from wecom_aibot.context_store import ContextStore


def test_same_event_reuses_context_token():
    store = ContextStore(ttl_seconds=60)
    assert store.issue("event-1", object(), 100.0) == store.issue("event-1", object(), 101.0)


def test_expired_context_is_rejected():
    store = ContextStore(ttl_seconds=60)
    token = store.issue("event-1", object(), 100.0)
    assert store.claim_final(token, 161.0).status == "expired"


def test_context_expires_at_exact_deadline():
    store = ContextStore(ttl_seconds=60)
    token = store.issue("event-1", object(), 100.0)
    assert store.claim_final(token, 160.0).status == "expired"


def test_final_claim_is_idempotent_after_delivery():
    store = ContextStore(ttl_seconds=60)
    token = store.issue("event-1", object(), 100.0)
    assert store.claim_final(token, 100.0).status == "ready"
    store.mark_delivered(token, 100.0)
    assert store.claim_final(token, 100.0).status == "delivered"


def test_missing_context_is_rejected():
    store = ContextStore(ttl_seconds=60)
    assert store.claim_final("unknown-token", 100.0).status == "missing"
