from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from aibot import WSClient, WSClientOptions
from aibot.utils import generate_req_id

from wecom_aibot.delivery import DeliveryResult

REPLY_TIMEOUT_SECONDS = 15.0
ACQUIRE_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_CONCURRENT_REPLIES = 1
STREAM_ID_PREFIX = "stream"

# The installed SDK reports platform outcomes only through exception messages
# raised by aibot.ws.WsConnectionManager, so they are matched exactly here.
_ACK_ERROR_PATTERN = re.compile(r"\AReply ack error: errcode=(-?\d+)")
_QUEUE_FULL_PATTERN = re.compile(r"\AReply queue for reqId .+ exceeds max size")
_NOT_CONNECTED_MESSAGE = "WebSocket not connected, unable to send data"

# Only codes with documented rate-limit semantics are retried. Everything else,
# including the platform's generic "system busy" -1, stays non-retryable until
# real platform evidence justifies otherwise.
_RETRYABLE_ERRCODES = frozenset({45009})
_ERRCODE_REASONS = {
    40001: "auth_rejected",
    40014: "auth_rejected",
    41001: "auth_rejected",
    42001: "auth_rejected",
    48002: "permission_rejected",
    60011: "permission_rejected",
    301002: "permission_rejected",
    40008: "content_rejected",
    44004: "content_rejected",
    45002: "content_rejected",
}


class WeComClient(Protocol):
    async def reply(self, route: object, markdown: str) -> DeliveryResult: ...


class SdkClient(Protocol):
    """The subset of ``aibot.WSClient`` the relay depends on."""

    async def reply_stream(
        self,
        frame: dict[str, Any],
        stream_id: str,
        content: str,
        finish: bool = False,
    ) -> dict[str, Any]: ...


@dataclass(frozen=True)
class ReplyRoute:
    """Relay-internal routing data extracted from a platform frame."""

    req_id: str
    stream_id: str


@dataclass(frozen=True)
class TextEvent:
    event_id: str
    text: str
    route: ReplyRoute


class _SilentLogger:
    """Drops SDK logs, which include raw frames, req_ids and error payloads."""

    def debug(self, message: str, *args: object) -> None:
        return

    def info(self, message: str, *args: object) -> None:
        return

    def warn(self, message: str, *args: object) -> None:
        return

    def error(self, message: str, *args: object) -> None:
        return


def parse_text_event(
    frame: object,
    *,
    stream_id_factory: Callable[[str], str] = generate_req_id,
) -> TextEvent | None:
    """Extract the relay's view of a text callback, or ``None`` if unusable."""
    if not isinstance(frame, dict):
        return None
    headers = frame.get("headers")
    body = frame.get("body")
    if not isinstance(headers, dict) or not isinstance(body, dict):
        return None

    req_id = headers.get("req_id")
    if not isinstance(req_id, str) or not req_id:
        return None

    text_field = body.get("text")
    text = text_field.get("content") if isinstance(text_field, dict) else None
    if not isinstance(text, str) or not text:
        return None

    msgid = body.get("msgid")
    event_id = msgid if isinstance(msgid, str) and msgid else req_id
    return TextEvent(
        event_id=event_id,
        text=text,
        route=ReplyRoute(
            req_id=req_id,
            stream_id=stream_id_factory(STREAM_ID_PREFIX),
        ),
    )


def classify_reply_failure(error: BaseException) -> DeliveryResult | None:
    """Map an SDK error to a definite outcome, or ``None`` when undetermined."""
    if not isinstance(error, RuntimeError):
        return None

    message = str(error)
    if message == _NOT_CONNECTED_MESSAGE:
        return DeliveryResult("not_delivered", retryable=True, reason="not_connected")
    if _QUEUE_FULL_PATTERN.match(message):
        return DeliveryResult(
            "not_delivered",
            retryable=False,
            reason="sdk_queue_full",
        )

    ack_error = _ACK_ERROR_PATTERN.match(message)
    if ack_error is None:
        return None

    errcode = int(ack_error.group(1))
    if errcode in _RETRYABLE_ERRCODES:
        return DeliveryResult("not_delivered", retryable=True, reason="platform_busy")
    return DeliveryResult(
        "not_delivered",
        retryable=False,
        reason=_ERRCODE_REASONS.get(errcode, "platform_rejected"),
    )


class WeComSdkAdapter:
    """Narrow boundary around the official SDK's reply path."""

    def __init__(
        self,
        client: SdkClient,
        *,
        max_concurrent_replies: int = DEFAULT_MAX_CONCURRENT_REPLIES,
        reply_timeout: float = REPLY_TIMEOUT_SECONDS,
        acquire_timeout: float = ACQUIRE_TIMEOUT_SECONDS,
    ) -> None:
        if max_concurrent_replies < 1:
            raise ValueError("max_concurrent_replies must be at least 1")
        self._client = client
        self._reply_timeout = reply_timeout
        self._acquire_timeout = acquire_timeout
        self._permits = asyncio.Semaphore(max_concurrent_replies)
        self._inbound_enabled = True

    async def reply(self, route: object, markdown: str) -> DeliveryResult:
        if not isinstance(route, ReplyRoute):
            return DeliveryResult(
                "not_delivered",
                retryable=False,
                reason="invalid_route",
            )

        try:
            await asyncio.wait_for(self._permits.acquire(), self._acquire_timeout)
        except asyncio.TimeoutError:
            return DeliveryResult(
                "not_delivered",
                retryable=False,
                reason="relay_busy",
            )

        try:
            await asyncio.wait_for(
                self._client.reply_stream(
                    {"headers": {"req_id": route.req_id}},
                    route.stream_id,
                    markdown,
                    finish=True,
                ),
                self._reply_timeout,
            )
        except asyncio.CancelledError:
            raise
        except Exception as error:
            result = classify_reply_failure(error)
            if result is None:
                raise
            return result
        finally:
            self._permits.release()
        return DeliveryResult("delivered")

    def on_text(self, callback: Callable[[TextEvent], None]) -> None:
        client = self._client

        def handle(frame: dict[str, Any]) -> None:
            if not self._inbound_enabled:
                return
            event = parse_text_event(frame)
            if event is not None:
                callback(event)

        client.on("message.text", handle)  # type: ignore[attr-defined]

    def stop_inbound(self) -> None:
        """Drop further inbound events while in-flight replies stay allowed."""
        self._inbound_enabled = False

    async def connect(self) -> None:
        await self._client.connect()  # type: ignore[attr-defined]

    def disconnect(self) -> None:
        self._client.disconnect()  # type: ignore[attr-defined]


def create_sdk_client(bot_id: str, secret: str) -> WeComSdkAdapter:
    """Build the adapter over a real WebSocket client for the given credentials."""
    return WeComSdkAdapter(
        WSClient(
            WSClientOptions(
                bot_id=bot_id,
                secret=secret,
                logger=_SilentLogger(),
            )
        )
    )
