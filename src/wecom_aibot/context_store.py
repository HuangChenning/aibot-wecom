from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Literal

ClaimStatus = Literal["ready", "delivered", "unknown", "expired", "missing"]
FinalState = Literal["pending", "delivered", "unknown"]


@dataclass(frozen=True)
class Claim:
    status: ClaimStatus


@dataclass
class _ContextRecord:
    event_id: str
    route: object
    expires_at: float
    final_state: FinalState = "pending"


class ContextStore:
    def __init__(self, ttl_seconds: float) -> None:
        self._ttl_seconds = ttl_seconds
        self._by_token: dict[str, _ContextRecord] = {}
        self._token_by_event_id: dict[str, str] = {}

    def issue(self, event_id: str, route: object, now: float) -> str:
        existing = self._token_by_event_id.get(event_id)
        if existing is not None:
            return existing

        token = secrets.token_urlsafe(32)
        self._by_token[token] = _ContextRecord(
            event_id=event_id,
            route=route,
            expires_at=now + self._ttl_seconds,
        )
        self._token_by_event_id[event_id] = token
        return token

    def claim_final(self, token: str, now: float) -> Claim:
        record = self._by_token.get(token)
        if record is None:
            return Claim(status="missing")
        if record.final_state == "delivered":
            return Claim(status="delivered")
        if record.final_state == "unknown":
            return Claim(status="unknown")
        if now >= record.expires_at:
            return Claim(status="expired")
        return Claim(status="ready")

    def route_for_relay(self, token: str, now: float) -> object | None:
        """Return an active route for relay-internal delivery only."""
        record = self._by_token.get(token)
        if record is None or now >= record.expires_at:
            return None
        return record.route

    def mark_delivered(self, token: str, now: float) -> None:
        record = self._by_token.get(token)
        if record is None:
            return
        record.final_state = "delivered"

    def mark_unknown(self, token: str) -> None:
        """Record an unknown delivery result as a relay-internal terminal state."""
        record = self._by_token.get(token)
        if record is None:
            return
        record.final_state = "unknown"
