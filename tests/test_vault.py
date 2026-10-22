import os
import pytest
import tempfile
import json
from server.store.db import (
    init_db,
    create_delegation_record,
    get_delegation,
    increment_delegation_uses,
    increment_failed_attempts,
    reset_failed_attempts,
    log_audit_event,
    get_audit_events_for_delegation,
    get_db,
)
from server.vault.crypto import (
    normalize_codeword,
    hash_codeword,
    verify_codeword,
    encrypt_payload,
    decrypt_payload,
    slice_facts,
)

@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    init_db(db_path)
    yield db_path
    if os.path.exists(db_path):
        os.remove(db_path)

def test_codeword_normalization():
    assert normalize_codeword("Solaris") == "solaris"
    assert normalize_codeword("solaris.") == "solaris"
    assert normalize_codeword(" SOLARIS! ") == "solaris"
    assert normalize_codeword("solaris?") == "solaris"
    assert normalize_codeword("  solaris,  ") == "solaris"

def test_codeword_hashing_and_verification():
    h = hash_codeword("solaris")
    # Voice transcripts with capitalization, spaces, or periods must all match
    assert verify_codeword("Solaris", h)
    assert verify_codeword("solaris.", h)
    assert verify_codeword("  SOLARIS  ", h)
    assert not verify_codeword("luna", h)
    assert not verify_codeword("", h)

def test_payload_encryption_and_decryption():
    facts = [
        {"label": "key location", "value": "under blue pot"},
        {"label": "alarm code", "value": "4821"},
    ]
    encrypted = encrypt_payload(facts)
    assert isinstance(encrypted, bytes)
    assert b"under blue pot" not in encrypted
    assert b"4821" not in encrypted

    decrypted = decrypt_payload(encrypted)
    assert decrypted == facts

def test_semantic_slicing():
    all_facts = [
        {"label": "spare key location", "value": "under blue pot"},
        {"label": "alarm code", "value": "4821"},
        {"label": "wifi password", "value": "supersecret"},
    ]
    # Inquire about key location only
    sliced = slice_facts(all_facts, ["spare key location"])
    assert len(sliced) == 1
    assert sliced[0]["label"] == "spare key location"
    assert sliced[0]["value"] == "under blue pot"
    # Ensure unrequested facts are NOT present
    labels_in_slice = [f["label"] for f in sliced]
    assert "alarm code" not in labels_in_slice
    assert "wifi password" not in labels_in_slice

def test_lockout_after_three_failed_attempts(temp_db):
    facts = [{"label": "secret note", "value": "classified"}]
    enc = encrypt_payload(facts)
    cw_hash = hash_codeword("falcon")

    d = create_delegation_record(
        delegation_id="del-test-1",
        owner="userA",
        recipient="userB",
        topic_desc="server credentials",
        payload_enc=enc,
        fact_labels=["secret note"],
        codeword_hash=cw_hash,
        max_uses=1,
        expires_at="2099-01-01T00:00:00Z",
        db_path=temp_db,
    )

    # 1st failure
    att1 = increment_failed_attempts("del-test-1", max_allowed=3, db_path=temp_db)
    assert att1 == 1
    assert get_delegation("del-test-1", db_path=temp_db)["status"] == "active"

    # 2nd failure
    att2 = increment_failed_attempts("del-test-1", max_allowed=3, db_path=temp_db)
    assert att2 == 2
    assert get_delegation("del-test-1", db_path=temp_db)["status"] == "active"

    # 3rd failure -> Lockout!
    att3 = increment_failed_attempts("del-test-1", max_allowed=3, db_path=temp_db)
    assert att3 == 3
    assert get_delegation("del-test-1", db_path=temp_db)["status"] == "locked"

def test_audit_log_never_contains_secret_payload(temp_db):
    secret_value = "ULTRA_CONFIDENTIAL_12345"
    facts = [{"label": "passcode", "value": secret_value}]
    enc = encrypt_payload(facts)
    cw_hash = hash_codeword("falcon")

    create_delegation_record(
        delegation_id="del-audit-test",
        owner="userA",
        recipient="userB",
        topic_desc="confidential topic",
        payload_enc=enc,
        fact_labels=["passcode"],
        codeword_hash=cw_hash,
        max_uses=1,
        expires_at="2099-01-01T00:00:00Z",
        db_path=temp_db,
    )

    log_audit_event(
        actor="userA",
        action="created",
        delegation_id="del-audit-test",
        note="Created delegation with 1 labeled fact",
        db_path=temp_db,
    )
    log_audit_event(
        actor="userB",
        action="asked",
        delegation_id="del-audit-test",
        question="What is the passcode?",
        gate_decision="ALLOW",
        gate_confidence=0.95,
        note="Released 1 fact to userB",
        db_path=temp_db,
    )

    # Assert on database contents: raw secret must never appear anywhere in audit_events table
    conn = get_db(temp_db)
    cur = conn.cursor()
    cur.execute("SELECT * FROM audit_events WHERE delegation_id = 'del-audit-test'")
    rows = cur.fetchall()
    conn.close()

    for r in rows:
        row_dict = dict(r)
        row_str = json.dumps(row_dict)
        assert secret_value not in row_str
