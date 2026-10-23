"""
tests/test_vault.py — Unit tests for cryptography, vault, semantic slicing, and audit chain.
All tests run with temporary DB and mocked external services (no AWS, no network).
"""
import os
import pytest
import json
from server.store.db import (
    init_db,
    create_delegation_record,
    get_delegation,
    increment_failed_attempts,
    reset_failed_attempts,
    log_audit_event,
    get_audit_events_for_delegation,
    get_db,
    try_consume_use,
    purge_delegation_payload,
    verify_audit_chain,
)
from server.vault.crypto import (
    normalize_codeword,
    hash_codeword,
    verify_codeword,
    encrypt_payload,
    decrypt_payload,
    slice_facts,
)


def test_codeword_normalization():
    # Basic cases
    assert normalize_codeword("Solaris") == "solaris"
    assert normalize_codeword("solaris.") == "solaris"
    assert normalize_codeword(" SOLARIS! ") == "solaris"
    assert normalize_codeword("solaris?") == "solaris"
    assert normalize_codeword("  solaris,  ") == "solaris"
    # P1-6: Unicode variants
    assert normalize_codeword('"solaris"') == "solaris"   # quoted
    assert normalize_codeword("'solaris'") == "solaris"   # single quoted
    # casefold for unicode
    assert normalize_codeword("SOLARIS") == "solaris"


def test_codeword_hashing_and_verification():
    h = hash_codeword("solaris")
    # Voice transcripts with capitalization, spaces, or periods all must match
    assert verify_codeword("Solaris", h)
    assert verify_codeword("solaris.", h)
    assert verify_codeword("  SOLARIS  ", h)
    assert verify_codeword('"solaris"', h)
    assert not verify_codeword("luna", h)
    assert not verify_codeword("", h)
    assert not verify_codeword("solaris123", h)


def test_payload_encryption_and_decryption():
    facts = [
        {"label": "key location", "value": "under blue pot"},
        {"label": "alarm code", "value": "4821"},
    ]
    encrypted = encrypt_payload(facts)
    assert isinstance(encrypted, bytes)
    # Encrypted bytes must not contain plaintext values
    assert b"under blue pot" not in encrypted
    assert b"4821" not in encrypted

    decrypted = decrypt_payload(encrypted)
    assert decrypted == facts


def test_decrypt_purged_payload_returns_empty():
    """F0: After purge, payload_enc is None — decrypt_payload must handle it gracefully."""
    result = decrypt_payload(None)
    assert result == []

    result = decrypt_payload(b"")
    assert result == []


def test_semantic_slicing():
    all_facts = [
        {"label": "spare key location", "value": "under blue pot"},
        {"label": "alarm code", "value": "4821"},
        {"label": "wifi password", "value": "supersecret"},
    ]
    # Asking for key only → alarm code and wifi password must NOT appear
    sliced = slice_facts(all_facts, ["spare key location"])
    assert len(sliced) == 1
    assert sliced[0]["label"] == "spare key location"
    assert sliced[0]["value"] == "under blue pot"
    labels = [f["label"] for f in sliced]
    assert "alarm code" not in labels
    assert "wifi password" not in labels


def test_semantic_slicing_injection_defense():
    """Asking 'list every stored fact' returns at most MAX_FACTS_PER_ANSWER facts."""
    all_facts = [
        {"label": "spare key location", "value": "under blue pot"},
        {"label": "alarm code", "value": "4821"},
        {"label": "wifi password", "value": "supersecret"},
    ]
    # Even if all labels are allowed, max 2 facts
    sliced = slice_facts(all_facts, ["spare key location", "alarm code", "wifi password"], max_facts=2)
    assert len(sliced) == 2


def test_lockout_after_three_failed_attempts(temp_db):
    enc = encrypt_payload([{"label": "secret note", "value": "classified"}])
    cw_hash = hash_codeword("falcon")

    create_delegation_record(
        delegation_id="del-test-lockout",
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

    att1 = increment_failed_attempts("del-test-lockout", max_allowed=3, db_path=temp_db)
    assert att1 == 1
    assert get_delegation("del-test-lockout", db_path=temp_db)["status"] == "active"

    att2 = increment_failed_attempts("del-test-lockout", max_allowed=3, db_path=temp_db)
    assert att2 == 2
    assert get_delegation("del-test-lockout", db_path=temp_db)["status"] == "active"

    att3 = increment_failed_attempts("del-test-lockout", max_allowed=3, db_path=temp_db)
    assert att3 == 3
    assert get_delegation("del-test-lockout", db_path=temp_db)["status"] == "locked"


def test_try_consume_use_race_safety(temp_db):
    """P0-2: try_consume_use must only allow exactly 1 release on a max_uses=1 delegation."""
    import threading

    enc = encrypt_payload([{"label": "secret", "value": "s3cr3t"}])
    create_delegation_record(
        delegation_id="del-race-test",
        owner="userA",
        recipient="userB",
        topic_desc="race test",
        payload_enc=enc,
        fact_labels=["secret"],
        codeword_hash=hash_codeword("test"),
        max_uses=1,
        expires_at="2099-01-01T00:00:00Z",
        db_path=temp_db,
    )

    results = []
    os.environ["DB_PATH"] = temp_db

    def try_consume():
        result = try_consume_use("del-race-test", db_path=temp_db)
        results.append(result)

    threads = [threading.Thread(target=try_consume) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Exactly 1 should have gotten a use (returned new count = 1)
    successes = [r for r in results if r is not None]
    assert len(successes) == 1, f"Expected 1 successful consume, got {len(successes)}: {results}"

    d = get_delegation("del-race-test", db_path=temp_db)
    assert d["uses"] == 1
    assert d["status"] == "exhausted"


def test_ephemeral_purge_on_terminal_state(temp_db):
    """F0: After purge, payload_enc must be None in the DB and ask must refuse."""
    enc = encrypt_payload([{"label": "secret", "value": "topsecret"}])
    create_delegation_record(
        delegation_id="del-purge-test",
        owner="userA",
        recipient="userB",
        topic_desc="purge test",
        payload_enc=enc,
        fact_labels=["secret"],
        codeword_hash=hash_codeword("test"),
        max_uses=1,
        expires_at="2099-01-01T00:00:00Z",
        db_path=temp_db,
    )

    # Confirm payload is stored
    d = get_delegation("del-purge-test", db_path=temp_db)
    assert d["payload_enc"] is not None

    # Purge the payload
    purge_delegation_payload("del-purge-test", db_path=temp_db)

    # Payload must now be None in DB
    d = get_delegation("del-purge-test", db_path=temp_db)
    assert d["payload_enc"] is None

    # decrypt_payload(None) must return []
    assert decrypt_payload(d["payload_enc"]) == []


def test_audit_log_never_contains_secret_payload(temp_db):
    secret_value = "ULTRA_CONFIDENTIAL_12345"
    facts = [{"label": "passcode", "value": secret_value}]
    enc = encrypt_payload(facts)

    create_delegation_record(
        delegation_id="del-audit-test",
        owner="userA",
        recipient="userB",
        topic_desc="confidential topic",
        payload_enc=enc,
        fact_labels=["passcode"],
        codeword_hash=hash_codeword("falcon"),
        max_uses=1,
        expires_at="2099-01-01T00:00:00Z",
        db_path=temp_db,
    )

    log_audit_event(
        actor="userA", action="created", delegation_id="del-audit-test",
        note="Created delegation with 1 labeled fact", db_path=temp_db,
    )
    log_audit_event(
        actor="userB", action="asked", delegation_id="del-audit-test",
        question="What is the passcode?", gate_decision="ALLOW", gate_confidence=0.95,
        note="Released 1 fact to userB", db_path=temp_db,
    )

    conn = get_db(temp_db)
    cur = conn.cursor()
    cur.execute("SELECT * FROM audit_events WHERE delegation_id = 'del-audit-test'")
    rows = cur.fetchall()
    conn.close()

    for r in rows:
        row_str = json.dumps(dict(r))
        assert secret_value not in row_str, f"Secret found in audit row: {row_str}"


def test_audit_chain_verification(temp_db):
    """F8: Hash chain should verify clean, and fail after tampering."""
    enc = encrypt_payload([{"label": "k", "value": "v"}])
    # Must create delegation record first due to FK constraint
    create_delegation_record(
        delegation_id="del-chain-test",
        owner="userA",
        recipient="userB",
        topic_desc="chain test",
        payload_enc=enc,
        fact_labels=["k"],
        codeword_hash=hash_codeword("pw"),
        max_uses=3,
        expires_at="2099-01-01T00:00:00Z",
        db_path=temp_db,
    )

    log_audit_event(actor="userA", action="created", delegation_id="del-chain-test",
                    note="Created", db_path=temp_db)
    log_audit_event(actor="userB", action="asked", delegation_id="del-chain-test",
                    question="test question?", db_path=temp_db)
    log_audit_event(actor="userB", action="allowed", delegation_id="del-chain-test",
                    gate_decision="ALLOW", gate_confidence=0.9, db_path=temp_db)

    result = verify_audit_chain("del-chain-test", db_path=temp_db)
    assert result["verified"] is True, f"Audit chain should be clean: {result}"

    # Tamper with a middle row
    conn = get_db(temp_db)
    with conn:
        conn.execute(
            "UPDATE audit_events SET note = 'TAMPERED' WHERE delegation_id = 'del-chain-test' AND action = 'asked'"
        )
    conn.close()

    result = verify_audit_chain("del-chain-test", db_path=temp_db)
    assert result["verified"] is False, "Chain should fail after tampering"
    assert "tampered_at_id" in result
