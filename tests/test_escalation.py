import os
import pytest
import tempfile
import asyncio
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from server.store.db import (
    init_db,
    create_delegation_record,
    get_delegation,
    get_pending_briefings_for_recipient,
    get_audit_events_for_delegation,
    get_db,
)
from server.vault.crypto import encrypt_payload, hash_codeword
from server.scheduler.engine import DelegationScheduler

@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    init_db(db_path)
    # Point global DB_PATH to this temporary db for the test
    import server.store.db as db_mod
    orig_path = db_mod.DB_PATH
    db_mod.DB_PATH = db_path
    yield db_path
    db_mod.DB_PATH = orig_path
    if os.path.exists(db_path):
        os.remove(db_path)

@pytest.mark.asyncio
async def test_scheduler_escalation_on_missed_deadline(temp_db):
    facts = [{"label": "server pass", "value": "secret123"}]
    enc = encrypt_payload(facts)
    cw_hash = hash_codeword("falcon")

    # Created with expiry in the past
    past_time = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
    create_delegation_record(
        delegation_id="del-expired-test",
        owner="userA",
        recipient="userB",
        topic_desc="server access",
        payload_enc=enc,
        fact_labels=["server pass"],
        codeword_hash=cw_hash,
        max_uses=1,
        expires_at=past_time,
    )

    scheduler = DelegationScheduler()
    # Execute one tick
    await scheduler.tick()

    # Verify delegation is now expired
    d = get_delegation("del-expired-test")
    assert d["status"] == "expired"

    # Verify pending briefing created for userB
    briefings = get_pending_briefings_for_recipient("userB")
    assert len(briefings) >= 1
    assert "server access" in briefings[0]["message"]

    # Verify audit event for escalation
    events = get_audit_events_for_delegation("del-expired-test")
    actions = [e["action"] for e in events]
    assert "escalated" in actions

@pytest.mark.asyncio
async def test_fast_forward_debug_endpoint(temp_db):
    from server.main import app
    client = TestClient(app)

    facts = [{"label": "key", "value": "under mat"}]
    enc = encrypt_payload(facts)
    future_time = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()

    create_delegation_record(
        delegation_id="del-ff-test",
        owner="userA",
        recipient="userB",
        topic_desc="key info",
        payload_enc=enc,
        fact_labels=["key"],
        codeword_hash=hash_codeword("testpass"),
        max_uses=1,
        expires_at=future_time,
    )

    # Call fast forward endpoint
    resp = client.post("/api/debug/fast-forward/del-ff-test")
    assert resp.status_code == 200
    assert resp.json()["status"] == "fast_forwarded"

    # Delegation should now be expired and escalated
    d = get_delegation("del-ff-test")
    assert d["status"] == "expired"
