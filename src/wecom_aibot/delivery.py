from __future__ import annotations

import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal

DeliveryStatus = Literal["delivered", "not_delivered", "unknown"]

RETRY_BASE_DELAYS = (0.5, 1.0)
RETRY_JITTER_MAX = 0.1


@dataclass(frozen=True)
class DeliveryResult:
    status: DeliveryStatus
    retryable: bool = False
    reason: str = ""


async def deliver_with_retry(
    send: Callable[[], Awaitable[DeliveryResult]],
    sleep: Callable[[float], Awaitable[None]],
) -> DeliveryResult:
    result = await send()

    for base_delay in RETRY_BASE_DELAYS:
        if result.status == "delivered":
            return result
        if result.status != "not_delivered" or not result.retryable:
            return result
        delay = base_delay + random.uniform(0, RETRY_JITTER_MAX)
        await sleep(delay)
        result = await send()

    return result
