import asyncio
from typing import Any

import pytest

from wecom_aibot.delivery import RETRY_BASE_DELAYS, RETRY_JITTER_MAX
from wecom_aibot.ipc import DELIVERY_RESPONSE_TIMEOUT_SECONDS
from wecom_aibot.sdk import (
    ACQUIRE_TIMEOUT_SECONDS,
    REPLY_TIMEOUT_SECONDS,
    ReplyRoute,
    WeComSdkAdapter,
    parse_text_event,
)


class FakeSdkClient:
    """Mimics the observable behavior of ``aibot.WSClient`` for replies."""

    def __init__(self, outcomes: list[object] | None = None) -> None:
        self.calls: list[tuple[dict[str, Any], str, str, bool]] = []
        self._outcomes = list(outcomes or [])
        self.started = asyncio.Event()
        self.release: asyncio.Event | None = None

    async def reply_stream(
        self,
        frame: dict[str, Any],
        stream_id: str,
        content: str,
        finish: bool = False,
    ) -> dict[str, Any]:
        self.calls.append((frame, stream_id, content, finish))
        self.started.set()
        if self.release is not None:
            await self.release.wait()
        if self._outcomes:
            outcome = self._outcomes.pop(0)
            if isinstance(outcome, BaseException):
                raise outcome
        return {"errcode": 0, "headers": {"req_id": frame["headers"]["req_id"]}}


def _route() -> ReplyRoute:
    return ReplyRoute(req_id="req-1", stream_id="stream-1")


def test_successful_reply_uses_original_req_id_and_finishes_stream():
    async def run() -> None:
        client = FakeSdkClient()
        adapter = WeComSdkAdapter(client)

        result = await adapter.reply(_route(), "answer")

        assert result.status == "delivered"
        assert client.calls == [
            ({"headers": {"req_id": "req-1"}}, "stream-1", "answer", True)
        ]

    asyncio.run(run())


@pytest.mark.parametrize(
    ("errcode", "reason"),
    [
        (40001, "auth_rejected"),
        (48002, "permission_rejected"),
        (44004, "content_rejected"),
        (99999, "platform_rejected"),
    ],
)
def test_explicit_platform_rejections_are_not_delivered_and_not_retryable(
    errcode: int,
    reason: str,
):
    async def run() -> None:
        error = RuntimeError(f"Reply ack error: errcode={errcode}, errmsg=denied")
        adapter = WeComSdkAdapter(FakeSdkClient([error]))

        result = await adapter.reply(_route(), "answer")

        assert result.status == "not_delivered"
        assert result.retryable is False
        assert result.reason == reason

    asyncio.run(run())


def test_platform_rate_limit_is_not_delivered_but_retryable():
    async def run() -> None:
        error = RuntimeError("Reply ack error: errcode=45009, errmsg=freq limit")
        adapter = WeComSdkAdapter(FakeSdkClient([error]))

        result = await adapter.reply(_route(), "answer")

        assert result.status == "not_delivered"
        assert result.retryable is True
        assert result.reason == "platform_busy"

    asyncio.run(run())


def test_disconnected_send_is_reported_as_definitely_not_delivered():
    async def run() -> None:
        error = RuntimeError("WebSocket not connected, unable to send data")
        adapter = WeComSdkAdapter(FakeSdkClient([error]))

        result = await adapter.reply(_route(), "answer")

        assert result.status == "not_delivered"
        assert result.retryable is True
        assert result.reason == "not_connected"

    asyncio.run(run())


def test_full_sdk_reply_queue_is_reported_as_not_delivered():
    async def run() -> None:
        error = RuntimeError(
            "Reply queue for reqId req-1 exceeds max size (100)"
        )
        adapter = WeComSdkAdapter(FakeSdkClient([error]))

        result = await adapter.reply(_route(), "answer")

        assert result.status == "not_delivered"
        assert result.retryable is False
        assert result.reason == "sdk_queue_full"

    asyncio.run(run())


def test_ack_timeout_from_sdk_is_raised_so_relay_records_unknown():
    async def run() -> None:
        error = TimeoutError("Reply ack timeout (5.0s) for reqId: req-1")
        adapter = WeComSdkAdapter(FakeSdkClient([error]))

        with pytest.raises(TimeoutError):
            await adapter.reply(_route(), "answer")

    asyncio.run(run())


def test_unexpected_transport_error_is_raised_so_relay_records_unknown():
    async def run() -> None:
        adapter = WeComSdkAdapter(FakeSdkClient([ConnectionResetError("reset")]))

        with pytest.raises(ConnectionResetError):
            await adapter.reply(_route(), "answer")

    asyncio.run(run())


def test_reply_call_timeout_is_raised_so_relay_records_unknown():
    async def run() -> None:
        client = FakeSdkClient()
        client.release = asyncio.Event()
        adapter = WeComSdkAdapter(client, reply_timeout=0.01)

        with pytest.raises(asyncio.TimeoutError):
            await adapter.reply(_route(), "answer")

        client.release.set()

    asyncio.run(run())


def test_backpressure_serializes_calls_and_timeout_starts_after_permit():
    async def run() -> None:
        client = FakeSdkClient()
        client.release = asyncio.Event()
        adapter = WeComSdkAdapter(
            client,
            max_concurrent_replies=1,
            acquire_timeout=0.01,
            reply_timeout=5,
        )

        first = asyncio.create_task(adapter.reply(_route(), "first"))
        await client.started.wait()
        second = await adapter.reply(
            ReplyRoute(req_id="req-2", stream_id="stream-2"),
            "second",
        )

        assert second.status == "not_delivered"
        assert second.retryable is False
        assert second.reason == "relay_busy"
        assert len(client.calls) == 1

        client.release.set()
        assert (await first).status == "delivered"

    asyncio.run(run())


def test_worst_case_reply_budget_stays_inside_the_ipc_deadline():
    attempts = len(RETRY_BASE_DELAYS) + 1
    worst_case = attempts * (ACQUIRE_TIMEOUT_SECONDS + REPLY_TIMEOUT_SECONDS) + sum(
        delay + RETRY_JITTER_MAX for delay in RETRY_BASE_DELAYS
    )

    assert worst_case < DELIVERY_RESPONSE_TIMEOUT_SECONDS


def test_reply_rejects_routes_it_did_not_issue():
    async def run() -> None:
        client = FakeSdkClient()
        adapter = WeComSdkAdapter(client)

        result = await adapter.reply({"req_id": "req-1"}, "answer")

        assert result.status == "not_delivered"
        assert result.retryable is False
        assert result.reason == "invalid_route"
        assert client.calls == []

    asyncio.run(run())


def test_text_frame_is_parsed_into_dedupable_event():
    frame = {
        "cmd": "aibot_msg_callback",
        "headers": {"req_id": "req-1"},
        "body": {
            "msgid": "msg-1",
            "msgtype": "text",
            "text": {"content": "hello robot"},
        },
    }

    event = parse_text_event(frame, stream_id_factory=lambda prefix: f"{prefix}-1")

    assert event is not None
    assert event.event_id == "msg-1"
    assert event.text == "hello robot"
    assert event.route == ReplyRoute(req_id="req-1", stream_id="stream-1")


def test_text_frame_without_msgid_falls_back_to_req_id():
    frame = {
        "headers": {"req_id": "req-1"},
        "body": {"msgtype": "text", "text": {"content": "hello"}},
    }

    event = parse_text_event(frame, stream_id_factory=lambda prefix: prefix)

    assert event is not None
    assert event.event_id == "req-1"


@pytest.mark.parametrize(
    "frame",
    [
        {},
        {"headers": {}, "body": {"text": {"content": "hello"}}},
        {"headers": {"req_id": "req-1"}, "body": {"text": {"content": ""}}},
        {"headers": {"req_id": "req-1"}, "body": {"msgtype": "image"}},
    ],
)
def test_unusable_frames_are_ignored(frame: dict[str, Any]):
    assert parse_text_event(frame, stream_id_factory=lambda prefix: prefix) is None
