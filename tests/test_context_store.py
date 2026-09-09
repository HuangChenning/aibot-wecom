from wecom_aibot.context_store import ContextStore


def test_same_event_reuses_context_token():
    store = ContextStore(ttl_seconds=60)
    assert store.issue("event-1", object(), 100.0) == store.issue("event-1", object(), 101.0)


def test_expired_context_is_rejected():
    store = ContextStore(ttl_seconds=60)
    token = store.issue("event-1", object(), 100.0)
    assert store.claim_final(token, 161.0).status == "expired"
