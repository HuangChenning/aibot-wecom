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
AUTH_TIMEOUT_SECONDS = 15.0
DEFAULT_MAX_CONCURRENT_REPLIES = 1
STREAM_ID_PREFIX = "stream"


class SdkConnectError(Exception):
    """Raised when the official SDK socket is up but subscribe never succeeds."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code

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


def _content_from_text_field(value: object) -> str | None:
    if not isinstance(value, dict):
        return None
    content = value.get("content")
    if isinstance(content, str) and content:
        return content
    return None


def _text_from_body(body: dict[str, Any]) -> str | None:
    """Pull user-visible text from text, mixed, or voice callbacks."""
    direct = _content_from_text_field(body.get("text"))
    if direct is not None:
        return direct

    voice = body.get("voice")
    if isinstance(voice, dict):
        transcript = _content_from_text_field(voice) or (
            voice.get("content") if isinstance(voice.get("content"), str) else None
        )
        if isinstance(transcript, str) and transcript:
            return transcript

    mixed = body.get("mixed")
    if not isinstance(mixed, dict):
        return None
    items = mixed.get("msg_item")
    if not isinstance(items, list):
        return None
    parts: list[str] = []
    for item in items:
        if not isinstance(item, dict) or item.get("msgtype") != "text":
            continue
        piece = _content_from_text_field(item.get("text"))
        if piece is not None:
            parts.append(piece)
    if not parts:
        return None
    return "\n".join(parts)


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

    text = _text_from_body(body)
    if text is None:
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


def describe_inbound_frame(frame: object) -> dict[str, object]:
    """Describe a callback frame without copying secrets or message text."""
    if not isinstance(frame, dict):
        return {
            "event": "inbound_frame",
            "cmd": "",
            "msgtype": "",
            "eventtype": "",
            "parsed": False,
            "reason": "non_object",
            "body_keys": [],
        }

    body = frame.get("body")
    headers = frame.get("headers")
    cmd = frame.get("cmd")
    msgtype = body.get("msgtype") if isinstance(body, dict) else None
    eventtype = None
    if isinstance(body, dict):
        nested = body.get("event")
        if isinstance(nested, dict):
            eventtype = nested.get("eventtype")

    parsed = parse_text_event(frame) is not None
    reason = ""
    if not parsed:
        if not isinstance(headers, dict) or not isinstance(headers.get("req_id"), str) or not headers.get("req_id"):
            reason = "missing_req_id"
        elif not isinstance(body, dict):
            reason = "missing_body"
        else:
            reason = "unusable_text"

    body_keys = (
        sorted(key for key in body if isinstance(key, str))[:20]
        if isinstance(body, dict)
        else []
    )
    return {
        "event": "inbound_frame",
        "cmd": cmd if isinstance(cmd, str) else "",
        "msgtype": msgtype if isinstance(msgtype, str) else "",
        "eventtype": eventtype if isinstance(eventtype, str) else "",
        "parsed": parsed,
        "reason": reason,
        "body_keys": body_keys,
    }


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
        auth_timeout: float = AUTH_TIMEOUT_SECONDS,
        on_notice: Callable[[dict[str, object]], None] | None = None,
    ) -> None:
        if max_concurrent_replies < 1:
            raise ValueError("max_concurrent_replies must be at least 1")
        self._client = client
        self._reply_timeout = reply_timeout
        self._acquire_timeout = acquire_timeout
        self._auth_timeout = auth_timeout
        self._on_notice = on_notice
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

    def _notice(self, event: dict[str, object]) -> None:
        if self._on_notice is not None:
            self._on_notice(event)

    def on_text(self, callback: Callable[[TextEvent], None]) -> None:
        client = self._client
        manager = getattr(client, "_ws_manager", None)
        previous = getattr(manager, "on_message", None) if manager is not None else None

        def report_and_forward(frame: dict[str, Any]) -> None:
            meta = describe_inbound_frame(frame)
            self._notice(meta)
            # A newer subscribe won this Bot. Reconnecting would immediately
            # kick that winner and loop; the official SDK does not stop itself.
            if meta.get("eventtype") == "disconnected_event" and manager is not None:
                manager._is_manual_close = True
                self._notice({"event": "sdk_replaced"})
            if previous is not None:
                previous(frame)

        if manager is not None:
            manager.on_message = report_and_forward

        def handle(frame: dict[str, Any]) -> None:
            if not self._inbound_enabled:
                return
            event = parse_text_event(frame)
            if event is not None:
                callback(event)

        # Official SDK emits `message` for every callback, then a more specific
        # `message.text` / `message.mixed` / `message.voice`. Subscribe to the
        # generic event so mixed/voice text is not dropped.
        client.on("message", handle)  # type: ignore[attr-defined]

    def stop_inbound(self) -> None:
        """Drop further inbound events while in-flight replies stay allowed."""
        self._inbound_enabled = False

    async def connect(self) -> None:
        """Open the SDK socket and wait until subscribe/auth actually succeeds."""
        client = self._client
        loop = asyncio.get_running_loop()
        finished: asyncio.Future[None] = loop.create_future()

        def on_authenticated() -> None:
            if not finished.done():
                finished.set_result(None)

        def on_error(_error: object) -> None:
            if not finished.done():
                finished.set_exception(SdkConnectError("sdk_auth_failed"))

        client.on("authenticated", on_authenticated)  # type: ignore[attr-defined]
        client.on("error", on_error)  # type: ignore[attr-defined]

        def on_disconnected(reason: object) -> None:
            self._notice(
                {
                    "event": "sdk_disconnected",
                    "reason_len": len(str(reason)),
                }
            )

        def on_reconnecting(attempt: object) -> None:
            self._notice(
                {
                    "event": "sdk_reconnecting",
                    "attempt": attempt if isinstance(attempt, int) else 0,
                }
            )

        client.on("disconnected", on_disconnected)  # type: ignore[attr-defined]
        client.on("reconnecting", on_reconnecting)  # type: ignore[attr-defined]
        await client.connect()  # type: ignore[attr-defined]
        try:
            await asyncio.wait_for(asyncio.shield(finished), self._auth_timeout)
        except asyncio.TimeoutError as error:
            raise SdkConnectError("sdk_auth_timeout") from error

    def disconnect(self) -> None:
        self._client.disconnect()  # type: ignore[attr-defined]


def create_sdk_client(
    bot_id: str,
    secret: str,
    *,
    on_notice: Callable[[dict[str, object]], None] | None = None,
) -> WeComSdkAdapter:
    """Build the adapter over a real WebSocket client for the given credentials."""
    return WeComSdkAdapter(
        WSClient(
            WSClientOptions(
                bot_id=bot_id,
                secret=secret,
                logger=_SilentLogger(),
            )
        ),
        on_notice=on_notice,
    )
