from typing import Protocol

from wecom_aibot.delivery import DeliveryResult


class WeComClient(Protocol):
    async def reply(self, route: object, markdown: str) -> DeliveryResult: ...
