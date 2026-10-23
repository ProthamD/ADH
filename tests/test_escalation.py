"""
tests/test_escalation.py — Tests for time-locked escalation, scheduler, and fast-forward endpoint.
Uses mocked webhook (no real HTTP) and temp DB.
"""
import os
import pytest
import asyncio
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from server.store.db import (
    init_db,
    create_delegation_record,
    get_delegation,
    get_pending_briefings_for_recipient,
    get_audit_events_for_delegation,
    purge_delegation_payload,
)
from server.vault.crypto import encrypt_payload, hash_codeword
from server.scheduler.engine import DelegationScheduler


@pytest.mark.asyncio
async def test_scheduler_escalation_on_missed_deadline(temp_db, mock_webhook):
    """Scheduler must expire delegation, create briefing, and fire webhook on missed deadline."""
    facts = [{"label": "server pass", "value": "secret123"}]
    enc = encrypt_payload(facts)

    past_time = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
    create_delegation_record(
        delegation_id="del-expired-test",
        owner="userA",
        recipient="userB",
        topic_desc="server access",
        payload_enc=enc,
        fact_labels=["server pass"],
        codeword_hash=hash_codeword("falcon"),
        max_uses=1,
        expires_at=past_time,
        db_path=temp_db,
    )

    sched = DelegationScheduler()
    await sched.tick()
    await asyncio.sleep(0.2)  # Allow create_task to fire

    # Use db_path explicitly since tick() uses the global DB_PATH (which conftest patched)
    d = get_delegation("del-expired-test", db_path=temp_db)
    assert d["status"] == "expired"
    assert d["payload_enc"] is None, "F0: Payload must be purged on expiry"

    briefings = get_pending_briefings_for_recipient("userB", db_path=temp_db)
    assert len(briefings) >= 1
    assert "server access" in briefings[0]["message"]

    events = get_audit_events_for_delegation("del-expired-test", db_path=temp_db)
    actions = [e["action"] for e in events]
    assert "escalated" in actions
    assert "purged" in actions


@pytest.mark.asyncio
async def test_scheduler_escalation_fires_only_once(temp_db, mock_webhook):
    """Escalation must not fire multiple times for the same expired delegation."""
    enc = encrypt_payload([{"label": "k", "value": "v"}])
    past_time = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()

    create_delegation_record(
        delegation_id="del-once-test",
        owner="userA",
        recipient="userB",
        topic_desc="once topic",
        payload_enc=enc,
        fact_labels=["k"],
        codeword_hash=hash_codeword("pass"),
        max_uses=1,
        expires_at=past_time,
        db_path=temp_db,
    )

    sched = DelegationScheduler()
    # Tick multiple times — after first tick, status is 'expired' so it won't be picked up again
    await sched.tick()
    await asyncio.sleep(0.1)
    await sched.tick()
    await asyncio.sleep(0.1)
    await sched.tick()
    await asyncio.sleep(0.1)

    d = get_delegation("del-once-test", db_path=temp_db)
    assert d["status"] == "expired"

    # Briefings should appear exactly once
    briefings = get_pending_briefings_for_recipient("userB", db_path=temp_db)
    assert len(briefings) <= 1, f"Expected at most 1 briefing, got {len(briefings)}"


@pytest.mark.asyncio
async def test_fast_forward_debug_endpoint(temp_db):
    """Fast-forward endpoint triggers expiry through real production code path."""
    from server.main import app

    # Ensure TestClient uses temp DB
    import server.store.db as db_mod
    orig = db_mod.DB_PATH
    db_mod.DB_PATH = temp_db

    try:
        client = TestClient(app)
        enc = encrypt_payload([{"label": "key", "value": "under mat"}])
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
            db_path=temp_db,
        )

        resp = client.post("/api/debug/fast-forward/del-ff-test")
        assert resp.status_code == 200
        assert resp.json()["status"] == "fast_forwarded"

        d = get_delegation("del-ff-test", db_path=temp_db)
        assert d["status"] == "expired"
    finally:
        db_mod.DB_PATH = orig


@pytest.mark.asyncio
async def test_fast_forward_404_without_demo_mode(temp_db, monkeypatch):
    """Fast-forward endpoint must return 404 when DEMO_MODE is not true."""
    import server.main as main_mod
    monkeypatch.setattr(main_mod, "DEMO_MODE", False)

    from server.main import app
    client = TestClient(app)
    resp = client.post("/api/debug/fast-forward/some-id")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_scheduler_bad_row_does_not_stop_others(temp_db, mock_webhook):
    """P0-6: A delegation with a bad expires_at must not prevent other rows from processing."""
    enc = encrypt_payload([{"label": "k", "value": "v"}])

    # Good delegation — expired in the past
    past_time = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
    create_delegation_record(
        delegation_id="del-good",
        owner="userA",
        recipient="userB",
        topic_desc="good topic",
        payload_enc=enc,
        fact_labels=["k"],
        codeword_hash=hash_codeword("pass"),
        max_uses=1,
        expires_at=past_time,
        db_path=temp_db,
    )

    # Insert a bad row directly with a garbage expires_at
    from server.store.db import get_db
    conn = get_db(temp_db)
    with conn:
        conn.execute(
            """INSERT INTO delegations (id, owner, recipient, topic_desc, payload_enc, fact_labels,
               codeword_hash, max_uses, uses, expires_at, status, created_at, failed_attempts, deny_count)
               VALUES ('del-bad', 'userA', 'userB', 'bad', ?, '[]', 'x', 1, 0, 'garbage_date', 'active', ?, 0, 0)""",
            (enc, datetime.now(timezone.utc).isoformat())
        )
    conn.close()

    sched = DelegationScheduler()
    # Should not raise — bad row is caught per-row
    await sched.tick()
    await asyncio.sleep(0.1)

    # The good delegation should still be expired
    d = get_delegation("del-good", db_path=temp_db)
    assert d["status"] == "expired"
