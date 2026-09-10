import asyncio
import hashlib
from pathlib import Path

from wecom_aibot.context_store import ContextStore
from wecom_aibot.delivery import DeliveryResult
from wecom_aibot.ipc import IpcServer, request
from wecom_aibot.service import RelayService


class FakeSdkClient:
    def __init__(self, result: str = "delivered") -> None:
        self.result = result
        self.calls: list[tuple[object, str]] = []

    async def reply(self, route: object, markdown: str) -> DeliveryResult:
        self.calls.append((route, markdown))
        return DeliveryResult(self.result)


class FakeRelay:
    def __init__(
        self,
        service: RelayService,
        server: IpcServer,
        client: FakeSdkClient,
        token: str,
        parent: Path,
    ) -> None:
        self.service = service
        self.server = server
        self.client = client
        self.token = token
        self.endpoint = server.endpoint
        self._parent = parent

    async def close(self) -> None:
        await self.server.close()
        self._parent.joinpath("s").unlink(missing_ok=True)
        self._parent.joinpath("s.token").unlink(missing_ok=True)
        try:
            self._parent.rmdir()
        except OSError:
            pass


async def start_relay_with_fake_sdk(
    tmp_path: Path,
    *,
    result: str = "delivered",
) -> FakeRelay:
    suffix = hashlib.sha256(str(tmp_path).encode()).hexdigest()[:16]
    parent = Path(__file__).resolve().parent.parent / f".it-{suffix[:8]}"
    parent.mkdir(mode=0o700, exist_ok=True)
    token = "e2e-token"
    client = FakeSdkClient(result)
    service = RelayService(client, ContextStore(60))
    server = IpcServer(service, token)
    await server.start(str(parent / "s"))
    return FakeRelay(service, server, client, token, parent)


def test_text_event_can_be_replied_to_through_ipc(tmp_path):
    async def run() -> None:
        relay = await start_relay_with_fake_sdk(tmp_path)
        try:
            context = await relay.service.handle_text("event-1", "question", object())
            response = await request(
                relay.endpoint,
                relay.token,
                {
                    "action": "reply",
                    "context": context,
                    "kind": "final",
                    "markdown": "answer",
                },
            )
            assert response["status"] == "delivered"
        finally:
            await relay.close()

    asyncio.run(run())


def test_duplicate_final_reply_does_not_call_sdk_twice(tmp_path):
    async def run() -> None:
        relay = await start_relay_with_fake_sdk(tmp_path)
        try:
            context = await relay.service.handle_text("event-1", "question", object())
            first = await request(
                relay.endpoint,
                relay.token,
                {
                    "action": "reply",
                    "context": context,
                    "kind": "final",
                    "markdown": "answer",
                },
            )
            second = await request(
                relay.endpoint,
                relay.token,
                {
                    "action": "reply",
                    "context": context,
                    "kind": "final",
                    "markdown": "answer again",
                },
            )
            assert first["status"] == "delivered"
            assert second["status"] == "delivered"
            assert len(relay.client.calls) == 1
        finally:
            await relay.close()

    asyncio.run(run())


def test_unknown_terminal_state_is_not_resent(tmp_path):
    async def run() -> None:
        relay = await start_relay_with_fake_sdk(tmp_path, result="unknown")
        try:
            context = await relay.service.handle_text("event-1", "question", object())
            first = await request(
                relay.endpoint,
                relay.token,
                {
                    "action": "reply",
                    "context": context,
                    "kind": "final",
                    "markdown": "answer",
                },
            )
            second = await request(
                relay.endpoint,
                relay.token,
                {
                    "action": "reply",
                    "context": context,
                    "kind": "final",
                    "markdown": "retry",
                },
            )
            assert first["status"] == "unknown"
            assert second["status"] == "unknown"
            assert len(relay.client.calls) == 1
        finally:
            await relay.close()

    asyncio.run(run())
