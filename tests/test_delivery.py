import asyncio
from unittest.mock import AsyncMock

from wecom_aibot.delivery import (
    RETRY_BASE_DELAYS,
    RETRY_JITTER_MAX,
    DeliveryResult,
    deliver_with_retry,
)


def test_retryable_failure_is_sent_three_times_total():
    async def run() -> None:
        attempts = 0

        async def send() -> DeliveryResult:
            nonlocal attempts
            attempts += 1
            if attempts == 3:
                return DeliveryResult("delivered")
            return DeliveryResult("not_delivered", retryable=True)

        result = await deliver_with_retry(send, AsyncMock())
        assert (result.status, attempts) == ("delivered", 3)

    asyncio.run(run())


def test_unknown_result_is_not_retried():
    async def run() -> None:
        send = AsyncMock(return_value=DeliveryResult("unknown"))
        assert (await deliver_with_retry(send, AsyncMock())).status == "unknown"
        send.assert_awaited_once()

    asyncio.run(run())


def test_non_retryable_failure_is_not_retried():
    async def run() -> None:
        send = AsyncMock(return_value=DeliveryResult("not_delivered", retryable=False))
        result = await deliver_with_retry(send, AsyncMock())
        assert result.status == "not_delivered"
        send.assert_awaited_once()

    asyncio.run(run())


def test_retry_delays_use_base_plus_bounded_jitter():
    async def run() -> None:
        sleep = AsyncMock()
        attempts = 0

        async def send() -> DeliveryResult:
            nonlocal attempts
            attempts += 1
            if attempts == 3:
                return DeliveryResult("delivered")
            return DeliveryResult("not_delivered", retryable=True)

        await deliver_with_retry(send, sleep)
        assert sleep.await_count == len(RETRY_BASE_DELAYS)
        for call, base_delay in zip(sleep.await_args_list, RETRY_BASE_DELAYS, strict=True):
            delay = call.args[0]
            assert base_delay <= delay <= base_delay + RETRY_JITTER_MAX

    asyncio.run(run())
