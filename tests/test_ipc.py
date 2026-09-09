import asyncio
import hashlib
import json
import os
import socket
import stat
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

import pytest

from wecom_aibot.context_store import ContextStore
from wecom_aibot.delivery import DeliveryResult
from wecom_aibot.ipc import (
    _WINDOWS_TOKEN_SDDL,
    MAX_REQUEST_BYTES,
    IpcServer,
    _create_windows_listener,
    _delivery_response,
    _windows_bind_address,
    _write_token_file,
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


@pytest.fixture
def endpoint_path(tmp_path):
    suffix = hashlib.sha256(str(tmp_path).encode()).hexdigest()[:16]
    project_root = Path(__file__).parent.parent
    parent = project_root / f".it-{suffix[:8]}"
    parent.mkdir(mode=0o700)
    try:
        yield str(parent / "s")
    finally:
        parent.rmdir()


async def start_test_server(
    endpoint_path: str,
    token: str,
    client: FakeClient | None = None,
) -> IpcServer:
    service = RelayService(client or FakeClient(), ContextStore(60))
    server = IpcServer(service, token)
    await server.start(endpoint_path)
    return server


def test_reply_requires_startup_token(endpoint_path):
    async def run() -> None:
        server = await start_test_server(endpoint_path, token="local-token")
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


def test_reply_delivers_final_with_only_controlled_fields(endpoint_path):
    async def run() -> None:
        route = object()
        client = FakeClient(DeliveryResult("delivered"))
        service = RelayService(client, ContextStore(60))
        context = await service.handle_text("event-1", "hello", route)
        server = IpcServer(service, "local-token")
        await server.start(endpoint_path)
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


def test_unknown_delivery_is_preserved(endpoint_path):
    async def run() -> None:
        client = FakeClient(DeliveryResult("unknown", reason="confirmation_lost"))
        service = RelayService(client, ContextStore(60))
        context = await service.handle_text("event-1", "hello", object())
        server = IpcServer(service, "local-token")
        await server.start(endpoint_path)
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
                "reason": "delivery_unknown",
            }
        finally:
            await server.close()

    asyncio.run(run())


def test_status_response_is_redacted(endpoint_path):
    async def run() -> None:
        server = await start_test_server(endpoint_path, token="local-token")
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


def test_stop_signals_and_safely_closes_server(endpoint_path):
    async def run() -> None:
        server = await start_test_server(endpoint_path, token="local-token")
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


def test_reply_rejects_wrong_kind_and_missing_fields(endpoint_path):
    async def run() -> None:
        server = await start_test_server(endpoint_path, token="local-token")
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


def test_unknown_action_and_invalid_json_are_rejected(endpoint_path):
    async def run() -> None:
        server = await start_test_server(endpoint_path, token="local-token")
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


def test_oversized_request_is_rejected(endpoint_path):
    async def run() -> None:
        server = await start_test_server(endpoint_path, token="local-token")
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


def test_socket_and_token_sidecar_are_owner_only_and_cleaned_up(endpoint_path):
    async def run() -> None:
        server = await start_test_server(endpoint_path, token="local-token")
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
    assert _delivery_response(DeliveryResult("unknown")) == {
        "status": "unknown",
        "reason": "delivery_unknown",
    }


def test_stop_finishes_with_an_idle_connection(endpoint_path):
    async def run() -> None:
        server = await start_test_server(endpoint_path, token="local-token")
        idle_reader, idle_writer = await asyncio.open_unix_connection(
            server.endpoint
        )
        response = await request(
            server.endpoint,
            "local-token",
            {"action": "stop"},
        )
        assert response == {"status": "stopping"}
        await asyncio.wait_for(server.wait_stopped(), timeout=1)
        assert await asyncio.wait_for(idle_reader.read(), timeout=1) == b""
        idle_writer.close()
        await idle_writer.wait_closed()
        assert not Path(endpoint_path).exists()
        assert not Path(f"{endpoint_path}.token").exists()

    asyncio.run(run())


def test_deep_json_service_error_and_disconnect_do_not_leak(endpoint_path):
    async def run() -> None:
        class RaisingClient:
            async def reply(
                self,
                route: object,
                markdown: str,
            ) -> DeliveryResult:
                raise RuntimeError("sdk-secret-text")

        loop = asyncio.get_running_loop()
        leaked: list[dict[str, object]] = []
        loop.set_exception_handler(lambda _loop, context: leaked.append(context))
        service = RelayService(RaisingClient(), ContextStore(60))
        context = await service.handle_text("event-1", "hello", object())
        server = IpcServer(service, "local-token")
        await server.start(endpoint_path)
        try:
            reader, writer = await asyncio.open_unix_connection(server.endpoint)
            writer.write(("[" * 10000 + "]" * 10000 + "\n").encode())
            await writer.drain()
            deep_response = json.loads(await reader.readline())
            writer.close()
            await writer.wait_closed()
            assert deep_response == {
                "status": "invalid_request",
                "reason": "invalid JSON",
            }

            service_response = await request(
                server.endpoint,
                "local-token",
                {
                    "action": "reply",
                    "context": context,
                    "kind": "final",
                    "markdown": "done",
                },
            )
            assert service_response == {
                "status": "error",
                "reason": "internal_error",
            }
            assert "sdk-secret-text" not in json.dumps(service_response)

            _, disconnected = await asyncio.open_unix_connection(server.endpoint)
            disconnected.write(
                json.dumps(
                    {"token": "local-token", "action": "status"}
                ).encode()
                + b"\n"
            )
            await disconnected.drain()
            disconnected.transport.abort()
            await asyncio.sleep(0.05)
        finally:
            await server.close()
        await asyncio.sleep(0)
        assert leaked == []

    asyncio.run(run())


def test_unix_parent_directory_must_be_private(tmp_path):
    async def run() -> None:
        os.chmod(tmp_path, 0o755)
        endpoint = str(tmp_path / "relay.sock")
        server = IpcServer(
            RelayService(FakeClient(), ContextStore(60)),
            "local-token",
        )
        with pytest.raises(PermissionError, match="private"):
            await server.start(endpoint)
        assert not Path(endpoint).exists()
        assert not Path(f"{endpoint}.token").exists()

    asyncio.run(run())


def test_delivery_reason_is_mapped_to_stable_relay_code(endpoint_path):
    async def run() -> None:
        client = FakeClient(
            DeliveryResult(
                "not_delivered",
                reason="WECHAT_BOT_SECRET=must-not-cross-ipc",
            )
        )
        service = RelayService(client, ContextStore(60))
        context = await service.handle_text("event-1", "hello", object())
        server = IpcServer(service, "local-token")
        await server.start(endpoint_path)
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
                "status": "not_delivered",
                "reason": "delivery_failed",
            }
            assert "must-not-cross-ipc" not in json.dumps(response)
        finally:
            await server.close()

    asyncio.run(run())


async def start_http_test_server() -> IpcServer:
    server = IpcServer(
        RelayService(FakeClient(), ContextStore(60)),
        "local-token",
    )
    await server._start_http_listener(exclusive=False)
    return server


async def send_raw_http(endpoint: str, raw: bytes) -> dict[str, object]:
    parsed = urlsplit(endpoint)
    reader, writer = await asyncio.open_connection(parsed.hostname, parsed.port)
    writer.write(raw)
    await writer.drain()
    if writer.can_write_eof():
        writer.write_eof()
    status_line = await reader.readline()
    assert status_line == b"HTTP/1.1 200 OK\r\n"
    content_length = None
    while True:
        line = await reader.readline()
        if line == b"\r\n":
            break
        name, _, value = line.partition(b":")
        if name.lower() == b"content-length":
            content_length = int(value)
    assert content_length is not None
    body = await reader.readexactly(content_length)
    writer.close()
    await writer.wait_closed()
    return json.loads(body)


def test_http_loopback_server_and_client_end_to_end():
    async def run() -> None:
        server = await start_http_test_server()
        try:
            assert server.endpoint.startswith("http://127.0.0.1:")
            assert await request(
                server.endpoint,
                "local-token",
                {"action": "status"},
            ) == {"status": "running"}
        finally:
            await server.close()

    asyncio.run(run())


@pytest.mark.parametrize(
    "raw",
    [
        (
            b"GET /ipc HTTP/1.1\r\nContent-Type: application/json\r\n"
            b"Content-Length: 0\r\n\r\n"
        ),
        (
            b"POST /wrong HTTP/1.1\r\nContent-Type: application/json\r\n"
            b"Content-Length: 0\r\n\r\n"
        ),
        (
            b"POST /ipc HTTP/1.0\r\nContent-Type: application/json\r\n"
            b"Content-Length: 0\r\n\r\n"
        ),
        (
            b"POST /ipc HTTP/1.1\r\nContent-Type: application/json\r\n"
            b"Content-Length: 0\r\nContent-Length: 0\r\n\r\n"
        ),
        (
            b"POST /ipc HTTP/1.1\r\nContent-Type: application/json\r\n"
            b"Content-Length: +1\r\n\r\nx"
        ),
        (
            b"POST /ipc HTTP/1.1\r\nContent-Type: application/json\r\n"
            b"Content-Length: -1\r\n\r\n"
        ),
        (
            b"POST /ipc HTTP/1.1\r\nContent-Type: application/json\r\n"
            b"Content-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}"
        ),
        (
            b"POST /ipc HTTP/1.1\r\nContent-Type: text/plain\r\n"
            b"Content-Length: 2\r\n\r\n{}"
        ),
        (
            b"POST /ipc HTTP/1.1\r\nContent-Type: application/json\r\n"
            b"Content-Length: 2\r\n\r\n{}extra"
        ),
    ],
)
def test_http_rejects_ambiguous_or_invalid_requests(raw):
    async def run() -> None:
        server = await start_http_test_server()
        try:
            response = await send_raw_http(server.endpoint, raw)
            assert response == {
                "status": "invalid_request",
                "reason": "invalid HTTP request",
            }
        finally:
            await server.close()

    asyncio.run(run())


def test_start_failure_cleans_files_and_allows_retry(endpoint_path):
    async def run() -> None:
        server = IpcServer(
            RelayService(FakeClient(), ContextStore(60)),
            "local-token",
        )
        with (
            patch(
                "wecom_aibot.ipc.asyncio.start_unix_server",
                side_effect=RuntimeError("startup failed"),
            ),
            pytest.raises(RuntimeError, match="startup failed"),
        ):
            await server.start(endpoint_path)
        assert server.endpoint == ""
        assert server.token_path == ""
        assert not Path(endpoint_path).exists()
        assert not Path(f"{endpoint_path}.token").exists()

        await server.start(endpoint_path)
        await server.close()

    asyncio.run(run())


def test_start_does_not_delete_preexisting_token_sidecar(endpoint_path):
    async def run() -> None:
        token_path = Path(f"{endpoint_path}.token")
        token_path.write_text("existing", encoding="utf-8")
        os.chmod(token_path, 0o600)
        server = IpcServer(
            RelayService(FakeClient(), ContextStore(60)),
            "local-token",
        )
        with pytest.raises(FileExistsError):
            await server.start(endpoint_path)
        assert token_path.read_text(encoding="utf-8") == "existing"
        assert not Path(endpoint_path).exists()
        token_path.unlink()

    asyncio.run(run())


def test_windows_token_failure_is_closed_and_listener_is_exclusive(tmp_path):
    def fail_closed(path: str, token: str) -> None:
        raise OSError("ACL creation failed")

    token_path = str(tmp_path / "relay.token")
    with pytest.raises(OSError, match="ACL creation failed"):
        _write_token_file(
            token_path,
            "local-token",
            windows=True,
            windows_writer=fail_closed,
        )
    assert not Path(token_path).exists()
    assert _WINDOWS_TOKEN_SDDL == "D:P(A;;FA;;;OW)"

    class FakeSocket:
        def __init__(self) -> None:
            self.options: list[tuple[int, int, int]] = []
            self.bound = None

        def setsockopt(self, level: int, option: int, value: int) -> None:
            self.options.append((level, option, value))

        def bind(self, address) -> None:
            self.bound = address

        def listen(self) -> None:
            pass

        def setblocking(self, blocking: bool) -> None:
            assert blocking is False

        def close(self) -> None:
            pass

    fake_socket = FakeSocket()
    listener = _create_windows_listener(lambda *_args: fake_socket)
    assert listener is fake_socket
    assert fake_socket.bound == ("127.0.0.1", 0)
    assert fake_socket.options == [
        (socket.SOL_SOCKET, -5, 1),
    ]
