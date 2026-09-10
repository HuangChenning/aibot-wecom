import asyncio
from collections.abc import Iterable
from unittest.mock import AsyncMock

from wecom_aibot.context_store import ContextStore
from wecom_aibot.delivery import DeliveryResult
from wecom_aibot.service import RelayService


class FakeClient:
    def __init__(self, results: Iterable[DeliveryResult]) -> None:
        self._results = iter(results)
        self.calls: list[tuple[object, str]] = []

    async def reply(self, route: object, markdown: str) -> DeliveryResult:
        self.calls.append((route, markdown))
        return next(self._results)


def test_duplicate_event_reuses_context_and_original_route():
    async def run() -> None:
        original_route = object()
        client = FakeClient([DeliveryResult("delivered")])
        service = RelayService(client, ContextStore(60), now=lambda: 100.0)

        first = await service.handle_text("event-1", "hello", original_route)
        second = await service.handle_text("event-1", "again", object())

        assert first == second
        assert (await service.reply(second, "done")).status == "delivered"
        assert client.calls == [(original_route, "done")]

    asyncio.run(run())


def test_duplicate_final_reply_does_not_call_sdk_twice():
    async def run() -> None:
        client = FakeClient([DeliveryResult("delivered")])
        service = RelayService(client, ContextStore(60), now=lambda: 100.0)
        context = await service.handle_text("event-1", "hello", route=object())

        assert (await service.reply(context, "done")).status == "delivered"
        assert (await service.reply(context, "done again")).status == "delivered"
        assert len(client.calls) == 1

    asyncio.run(run())


def test_expired_and_missing_contexts_do_not_call_sdk():
    async def run() -> None:
        current_time = 100.0
        client = FakeClient([])
        service = RelayService(
            client,
            ContextStore(60),
            now=lambda: current_time,
        )
        context = await service.handle_text("event-1", "hello", route=object())
        current_time = 160.0

        expired = await service.reply(context, "too late")
        missing = await service.reply("missing", "not found")

        assert expired == DeliveryResult(
            "not_delivered", retryable=False, reason="expired"
        )
        assert missing == DeliveryResult(
            "not_delivered", retryable=False, reason="missing"
        )
        assert client.calls == []

    asyncio.run(run())


def test_retryable_failure_eventually_delivers_and_marks_context():
    async def run() -> None:
        route = object()
        client = FakeClient(
            [
                DeliveryResult("not_delivered", retryable=True),
                DeliveryResult("delivered"),
            ]
        )
        sleep = AsyncMock()
        service = RelayService(
            client,
            ContextStore(60),
            now=lambda: 100.0,
            sleep=sleep,
        )
        context = await service.handle_text("event-1", "hello", route)

        assert (await service.reply(context, "done")).status == "delivered"
        assert (await service.reply(context, "again")).status == "delivered"
        assert client.calls == [(route, "done"), (route, "done")]
        sleep.assert_awaited_once()

    asyncio.run(run())


def test_unknown_result_is_terminal_and_sdk_is_not_called_again():
    async def run() -> None:
        route = object()
        client = FakeClient([DeliveryResult("unknown")])
        sleep = AsyncMock()
        service = RelayService(
            client,
            ContextStore(60),
            now=lambda: 100.0,
            sleep=sleep,
        )
        context = await service.handle_text("event-1", "hello", route)

        assert (await service.reply(context, "first")).status == "unknown"
        assert (await service.reply(context, "second")).status == "unknown"
        assert client.calls == [(route, "first")]
        sleep.assert_not_awaited()

    asyncio.run(run())


def test_delivery_confirmed_after_expiry_is_remembered():
    async def run() -> None:
        current_time = 100.0

        class ExpiringClient:
            def __init__(self) -> None:
                self.calls = 0

            async def reply(
                self, route: object, markdown: str
            ) -> DeliveryResult:
                nonlocal current_time
                self.calls += 1
                current_time = 160.0
                return DeliveryResult("delivered")

        client = ExpiringClient()
        service = RelayService(
            client,
            ContextStore(60),
            now=lambda: current_time,
        )
        context = await service.handle_text("event-1", "hello", object())

        assert (await service.reply(context, "first")).status == "delivered"
        assert (await service.reply(context, "second")).status == "delivered"
        assert client.calls == 1

    asyncio.run(run())


def test_concurrent_final_replies_call_sdk_once():
    async def run() -> None:
        class BlockingClient:
            def __init__(self) -> None:
                self.calls = 0
                self.started = asyncio.Event()
                self.release = asyncio.Event()

            async def reply(
                self, route: object, markdown: str
            ) -> DeliveryResult:
                self.calls += 1
                self.started.set()
                await self.release.wait()
                return DeliveryResult("delivered")

        route = object()
        client = BlockingClient()
        service = RelayService(client, ContextStore(60), now=lambda: 100.0)
        context = await service.handle_text("event-1", "hello", route)

        first = asyncio.create_task(service.reply(context, "first"))
        await client.started.wait()
        second = asyncio.create_task(service.reply(context, "second"))
        await asyncio.sleep(0)
        client.release.set()
        results = await asyncio.gather(first, second)

        assert [result.status for result in results] == ["delivered", "delivered"]
        assert client.calls == 1

    asyncio.run(run())


def test_sdk_exception_marks_context_unknown_and_is_not_sent_again():
    async def run() -> None:
        class RaisingClient:
            def __init__(self) -> None:
                self.calls = 0

            async def reply(
                self,
                route: object,
                markdown: str,
            ) -> DeliveryResult:
                self.calls += 1
                raise RuntimeError("sdk failure")

        client = RaisingClient()
        service = RelayService(client, ContextStore(60), now=lambda: 100.0)
        context = await service.handle_text("event-1", "hello", object())

        assert (await service.reply(context, "first")).status == "unknown"
        assert (await service.reply(context, "second")).status == "unknown"
        assert client.calls == 1

    asyncio.run(run())


def test_cancelled_sdk_send_marks_context_unknown_before_reraising():
    async def run() -> None:
        class BlockingClient:
            def __init__(self) -> None:
                self.calls = 0
                self.started = asyncio.Event()

            async def reply(
                self,
                route: object,
                markdown: str,
            ) -> DeliveryResult:
                self.calls += 1
                if self.calls > 1:
                    return DeliveryResult("delivered")
                self.started.set()
                await asyncio.Event().wait()
                return DeliveryResult("delivered")

        client = BlockingClient()
        service = RelayService(client, ContextStore(60), now=lambda: 100.0)
        context = await service.handle_text("event-1", "hello", object())
        reply_task = asyncio.create_task(service.reply(context, "first"))
        await client.started.wait()
        reply_task.cancel()

        try:
            await reply_task
        except asyncio.CancelledError:
            pass
        else:
            raise AssertionError("CancelledError must be re-raised")

        assert (await service.reply(context, "second")).status == "unknown"
        assert client.calls == 1

    asyncio.run(run())


def test_different_contexts_can_send_concurrently():
    async def run() -> None:
        class PerRouteClient:
            def __init__(self) -> None:
                self.slow_started = asyncio.Event()
                self.release_slow = asyncio.Event()
                self.calls: list[str] = []

            async def reply(
                self,
                route: object,
                markdown: str,
            ) -> DeliveryResult:
                assert isinstance(route, str)
                self.calls.append(route)
                if route == "slow-route":
                    self.slow_started.set()
                    await self.release_slow.wait()
                return DeliveryResult("delivered")

        client = PerRouteClient()
        service = RelayService(client, ContextStore(60), now=lambda: 100.0)
        slow_context = await service.handle_text(
            "slow-event",
            "slow",
            "slow-route",
        )
        fast_context = await service.handle_text(
            "fast-event",
            "fast",
            "fast-route",
        )

        slow_reply = asyncio.create_task(service.reply(slow_context, "slow"))
        await client.slow_started.wait()
        try:
            fast_result = await asyncio.wait_for(
                service.reply(fast_context, "fast"),
                timeout=0.1,
            )
            assert fast_result.status == "delivered"
            assert client.calls == ["slow-route", "fast-route"]
        finally:
            client.release_slow.set()
            await slow_reply

    asyncio.run(run())
