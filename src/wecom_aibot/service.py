from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable

from wecom_aibot.context_store import ContextStore
from wecom_aibot.delivery import DeliveryResult, deliver_with_retry
from wecom_aibot.sdk import WeComClient


class RelayService:
    def __init__(
        self,
        client: WeComClient,
        context_store: ContextStore,
        *,
        now: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._client = client
        self._context_store = context_store
        self._now = now
        self._sleep = sleep
        self._final_lock = asyncio.Lock()

    async def handle_text(self, event_id: str, text: str, route: object) -> str:
        return self._context_store.issue(event_id, route, self._now())

    async def reply(self, context: str, markdown: str) -> DeliveryResult:
        async with self._final_lock:
            now = self._now()
            claim = self._context_store.claim_final(context, now)
            if claim.status == "delivered":
                return DeliveryResult("delivered")
            if claim.status != "ready":
                return DeliveryResult(
                    "not_delivered",
                    retryable=False,
                    reason=claim.status,
                )

            route = self._context_store.route_for_relay(context, now)
            if route is None:
                return DeliveryResult(
                    "not_delivered",
                    retryable=False,
                    reason="expired",
                )

            result = await deliver_with_retry(
                lambda: self._client.reply(route, markdown),
                self._sleep,
            )
            if result.status == "delivered":
                self._context_store.mark_delivered(context, self._now())
            return result
