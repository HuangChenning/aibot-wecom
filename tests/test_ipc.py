import asyncio
import hashlib
import json
import os
import stat
from pathlib import Path

from wecom_aibot.context_store import ContextStore
from wecom_aibot.delivery import DeliveryResult
from wecom_aibot.ipc import (
    MAX_REQUEST_BYTES,
    IpcServer,
    _delivery_response,
    _windows_bind_address,
    request,
)
from wecom_aibot.service import RelayService


class FakeClient:
    def __init__(self, result: DeliveryResult | None = None) -> None:
        self.result = result
        self.calls: list[tuple[object, str]] = []
        self.secret = "client-secret"

    async def reply(self, route: object, markdown: str) -> DeliveryResult:
        self.calls.append((route, markdown))
        if self.result is None:
            raise AssertionError("request must not call the SDK")
        return self.result


def socket_path(tmp_path) -> str:
    suffix = hashlib.sha256(str(tmp_path).encode()).hexdigest()[:16]
    project_root = Path(__file__).parent.parent
    return str(project_root / f".ipc-{suffix}")


async def start_test_server(
    tmp_path,
    token: str,
    client: FakeClient | None = None,
) -> IpcServer:
    service = RelayService(client or FakeClient(), ContextStore(60))
    server = IpcServer(service, token)
    await server.start(socket_path(tmp_path))
    return server


def test_reply_requires_startup_token(tmp_path):
    async def run() -> None:
        server = await start_test_server(tmp_path, token="local-token")
        try:
            response = await request(
                server.endpoint,
                "wrong",
                {"action": "status"},
            )
            assert response == {"status": "forbidden"}
        finally:
            await server.close()

    asyncio.run(run())


def test_reply_delivers_final_with_only_controlled_fields(tmp_path):
    async def run() -> None:
        route = object()
        client = FakeClient(DeliveryResult("delivered"))
        service = RelayService(client, ContextStore(60))
        context = await service.handle_text("event-1", "hello", route)
        server = IpcServer(service, "local-token")
        await server.start(socket_path(tmp_path))
        try:
            response = await request(
                server.endpoint,
                "local-token",
                {
                    "action": "reply",
                    "context": context,
                    "kind": "final",
                    "markdown": "**done**",
                },
            )
            assert response == {"status": "delivered"}
            assert client.calls == [(route, "**done**")]

            rejected = await request(
                server.endpoint,
                "local-token",
                {
                    "action": "reply",
                    "context": context,
                    "kind": "final",
                    "markdown": "done",
                    "route": "must-not-be-accepted",
                },
            )
            assert rejected == {
                "status": "invalid_request",
                "reason": "invalid reply fields",
            }
        finally:
            await server.close()

    asyncio.run(run())


def test_unknown_delivery_is_preserved(tmp_path):
    async def run() -> None:
        client = FakeClient(DeliveryResult("unknown", reason="confirmation_lost"))
        service = RelayService(client, ContextStore(60))
        context = await service.handle_text("event-1", "hello", object())
        server = IpcServer(service, "local-token")
        await server.start(socket_path(tmp_path))
        try:
            response = await request(
                server.endpoint,
                "local-token",
                {
                    "action": "reply",
                    "context": context,
                    "kind": "final",
                    "markdown": "done",
                },
            )
            assert response == {
                "status": "unknown",
                "reason": "confirmation_lost",
            }
        finally:
            await server.close()

    asyncio.run(run())


def test_status_response_is_redacted(tmp_path):
    async def run() -> None:
        server = await start_test_server(tmp_path, token="local-token")
        try:
            response = await request(
                server.endpoint,
                "local-token",
                {"action": "status"},
            )
            assert response == {"status": "running"}
            serialized = json.dumps(response)
            for forbidden in (
                "route",
                "replyContext",
                "Secret",
                "token",
                "local-token",
                "client-secret",
            ):
                assert forbidden not in serialized
        finally:
            await server.close()

    asyncio.run(run())


def test_stop_signals_and_safely_closes_server(tmp_path):
    async def run() -> None:
        server = await start_test_server(tmp_path, token="local-token")
        endpoint = server.endpoint
        token_path = server.token_path
        response = await request(
            endpoint,
            "local-token",
            {"action": "stop"},
        )
        assert response == {"status": "stopping"}
        await asyncio.wait_for(server.wait_stopped(), timeout=1)
        assert not os.path.exists(endpoint)
        assert not os.path.exists(token_path)

    asyncio.run(run())


def test_reply_rejects_wrong_kind_and_missing_fields(tmp_path):
    async def run() -> None:
        server = await start_test_server(tmp_path, token="local-token")
        try:
            progress = await request(
                server.endpoint,
                "local-token",
                {
                    "action": "reply",
                    "context": "context",
                    "kind": "progress",
                    "markdown": "working",
                },
            )
            missing = await request(
                server.endpoint,
                "local-token",
                {"action": "reply", "context": "context", "kind": "final"},
            )
            assert progress["status"] == "invalid_request"
            assert missing["status"] == "invalid_request"
        finally:
            await server.close()

    asyncio.run(run())


def test_unknown_action_and_invalid_json_are_rejected(tmp_path):
    async def run() -> None:
        server = await start_test_server(tmp_path, token="local-token")
        try:
            unknown = await request(
                server.endpoint,
                "local-token",
                {"action": "inspect"},
            )
            assert unknown == {
                "status": "invalid_request",
                "reason": "unknown action",
            }

            reader, writer = await asyncio.open_unix_connection(server.endpoint)
            writer.write(b"{invalid json}\n")
            await writer.drain()
            malformed = json.loads(await reader.readline())
            writer.close()
            await writer.wait_closed()
            assert malformed == {
                "status": "invalid_request",
                "reason": "invalid JSON",
            }
        finally:
            await server.close()

    asyncio.run(run())


def test_oversized_request_is_rejected(tmp_path):
    async def run() -> None:
        server = await start_test_server(tmp_path, token="local-token")
        try:
            reader, writer = await asyncio.open_unix_connection(server.endpoint)
            writer.write(b"x" * (MAX_REQUEST_BYTES + 1) + b"\n")
            await writer.drain()
            response = json.loads(await reader.readline())
            writer.close()
            await writer.wait_closed()
            assert response == {
                "status": "invalid_request",
                "reason": "request too large",
            }
        finally:
            await server.close()

    asyncio.run(run())


def test_socket_and_token_sidecar_are_owner_only_and_cleaned_up(tmp_path):
    async def run() -> None:
        server = await start_test_server(tmp_path, token="local-token")
        endpoint = server.endpoint
        token_path = server.token_path
        try:
            assert stat.S_IMODE(os.stat(endpoint).st_mode) == 0o600
            assert stat.S_IMODE(os.stat(token_path).st_mode) == 0o600
            assert Path(token_path).read_text(encoding="utf-8") == "local-token"
        finally:
            await server.close()
        assert not os.path.exists(endpoint)
        assert not os.path.exists(token_path)

    asyncio.run(run())


def test_platform_boundaries_keep_loopback_and_explicit_delivery_states():
    assert _windows_bind_address() == ("127.0.0.1", 0)
    assert _delivery_response(DeliveryResult("delivered")) == {
        "status": "delivered"
    }
    assert _delivery_response(
        DeliveryResult("not_delivered", reason="expired")
    ) == {"status": "not_delivered", "reason": "expired"}
    assert _delivery_response(DeliveryResult("unknown")) == {"status": "unknown"}
