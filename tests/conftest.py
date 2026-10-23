"""
tests/conftest.py — Shared pytest fixtures for the Alexa+ Delegation Broker test suite.

All tests run against a temporary SQLite DB and with mocked external dependencies
(Bedrock, webhook) so no AWS credentials or network access are required.
"""
import os
import tempfile
import pytest
from cryptography.fernet import Fernet
import hmac as _hmac
import hashlib

# --- Generate stable test keys (in-memory, never committed) ---
TEST_FERNET_KEY = Fernet.generate_key().decode()
TEST_HMAC_SECRET = "test_hmac_secret_for_unit_tests_only_32chars!!"


@pytest.fixture(autouse=True, scope="session")
def set_test_env():
    """
    Set all required environment variables before any imports.
    This ensures startup validation passes and crypto uses deterministic test keys.
    """
    os.environ["ENCRYPTION_KEY"] = TEST_FERNET_KEY
    os.environ["HMAC_SECRET"] = TEST_HMAC_SECRET
    os.environ["DEMO_MODE"] = "true"
    os.environ["ALLOW_DIRECT_FALLBACK"] = "true"
    os.environ["ESCALATION_WEBHOOK_URL"] = ""  # Disabled by default in tests
    os.environ["BEDROCK_MODEL_ID"] = "amazon.nova-micro-v1:0"
    os.environ["AWS_REGION"] = "us-east-1"
    yield


@pytest.fixture
def temp_db(tmp_path, set_test_env):
    """
    Provides a fresh temporary SQLite DB path for each test.
    Also sets DB_PATH env var so all server.store.db functions use it.
    """
    db_file = str(tmp_path / "test_delegation_broker.db")
    os.environ["DB_PATH"] = db_file
    # Also patch the module-level DB_PATH in db.py
    import server.store.db as db_mod
    orig_path = db_mod.DB_PATH
    db_mod.DB_PATH = db_file
    from server.store.db import init_db
    init_db(db_path=db_file)
    yield db_file
    # Restore original DB_PATH
    db_mod.DB_PATH = orig_path
    os.environ["DB_PATH"] = orig_path
    # Try to delete temp file (may fail on Windows due to file handles)
    try:
        if os.path.exists(db_file):
            import gc
            gc.collect()  # Close any lingering connections
            os.remove(db_file)
    except PermissionError:
        pass  # Windows: file still open, pytest will clean up tmp_path later


@pytest.fixture
def mock_gate_allow(monkeypatch):
    """Mocks the gatekeeper to always return ALLOW with full labels."""
    from server.gate import bedrock_gate
    from server.gate.bedrock_gate import GatekeeperResult

    def _mock_classify(question, topic_desc, fact_labels, confidence_threshold=0.75, max_retries=1):
        return GatekeeperResult(
            decision="ALLOW",
            confidence=0.95,
            allowed_labels=fact_labels[:2],  # Return up to first 2 labels
            reasoning="Mocked ALLOW for testing",
        )

    monkeypatch.setattr(bedrock_gate, "classify_question", _mock_classify)
    from server.tools import delegation_tools
    monkeypatch.setattr(delegation_tools, "classify_question", _mock_classify)


@pytest.fixture
def mock_gate_deny(monkeypatch):
    """Mocks the gatekeeper to always return DENY."""
    from server.gate import bedrock_gate
    from server.gate.bedrock_gate import GatekeeperResult

    def _mock_classify(question, topic_desc, fact_labels, confidence_threshold=0.75, max_retries=1):
        return GatekeeperResult(
            decision="DENY",
            confidence=0.99,
            allowed_labels=[],
            reasoning="Mocked DENY for testing",
        )

    monkeypatch.setattr(bedrock_gate, "classify_question", _mock_classify)
    from server.tools import delegation_tools
    monkeypatch.setattr(delegation_tools, "classify_question", _mock_classify)


@pytest.fixture
def mock_speech_rewriter(monkeypatch):
    """Mocks speech rewriter to return a simple deterministic template."""
    from server.gate import speech_rewriter

    def _mock_rewrite(facts):
        if not facts:
            return "I found no relevant details."
        parts = [f"{f.get('label')}: {f.get('value')}" for f in facts]
        return "Here is what was shared with you: " + "; ".join(parts) + "."

    monkeypatch.setattr(speech_rewriter, "rewrite_facts_for_speech", _mock_rewrite)
    from server.tools import delegation_tools
    monkeypatch.setattr(delegation_tools, "rewrite_facts_for_speech", _mock_rewrite)


@pytest.fixture
def mock_webhook(monkeypatch):
    """Mocks the escalation webhook to avoid real HTTP calls."""
    calls = []
    from server.notify import webhook

    async def _mock_send(delegation_id, recipient, topic_desc, target_url=None):
        calls.append({
            "delegation_id": delegation_id,
            "recipient": recipient,
            "topic_desc": topic_desc,
            "target_url": target_url,
        })
        return True

    monkeypatch.setattr(webhook, "send_escalation_webhook", _mock_send)
    from server.scheduler import engine
    monkeypatch.setattr(engine, "send_escalation_webhook", _mock_send)
    return calls
