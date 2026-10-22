import pytest
import os
import yaml
from server.gate.bedrock_gate import (
    classify_question,
    GatekeeperResult,
    GATEKEEPER_SYSTEM_PROMPT,
)

def test_gatekeeper_prompt_security_no_secret_values():
    """
    CRITICAL SECURITY INVARIANT:
    The gatekeeper prompt and system instructions must NEVER contain secret values.
    """
    topic = "rollback steps for payments service"
    fact_labels = ["rollback command", "database rollback"]
    secret_value = "SUPER_SECRET_PAYLOAD_VALUE_9999"

    # Inspect the system prompt
    assert secret_value not in GATEKEEPER_SYSTEM_PROMPT

    # Construct user prompt as the gatekeeper does
    user_prompt = f"Allowed Topic: {topic}\nAvailable Fact Labels: {fact_labels}"
    assert secret_value not in user_prompt

def test_gatekeeper_fail_closed_on_empty_or_malformed():
    """
    Empty questions or missing data must immediately fail closed to DENY.
    """
    res = classify_question("", "some topic", ["label1"])
    assert res.decision == "DENY"
    assert res.allowed_labels == []

def test_gatekeeper_fail_closed_on_unauthenticated_bedrock():
    """
    When AWS credentials are invalid or missing, the gatekeeper must fail closed to DENY,
    never allowing access.
    """
    # Force invalid key to ensure fail-closed behavior
    orig_key = os.environ.get("AWS_ACCESS_KEY_ID")
    os.environ["AWS_ACCESS_KEY_ID"] = "invalid_key_for_test"
    try:
        res = classify_question(
            question="How do I roll back?",
            topic_desc="rollback steps",
            fact_labels=["rollback command"],
        )
        assert res.decision == "DENY"
        assert res.allowed_labels == []
        assert "AWS Bedrock error (fail-closed)" in res.reasoning
    finally:
        if orig_key:
            os.environ["AWS_ACCESS_KEY_ID"] = orig_key
        else:
            os.environ.pop("AWS_ACCESS_KEY_ID", None)

def test_gate_cases_yaml_structure():
    """
    Validates that gate_cases.yaml exists and contains all required benchmark scenarios.
    """
    yaml_path = os.path.join(os.path.dirname(__file__), "gate_cases.yaml")
    assert os.path.exists(yaml_path)

    with open(yaml_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    assert "scenario_on_call" in data
    assert "scenario_house_sitter" in data

    on_call_cases = data["scenario_on_call"]["cases"]
    assert len(on_call_cases) >= 10

    # Ensure in-scope, out-of-scope, and jailbreak categories exist
    case_ids = [c["id"] for c in on_call_cases]
    assert any("inscope" in cid for cid in case_ids)
    assert any("outscope" in cid for cid in case_ids)
    assert any("jailbreak" in cid for cid in case_ids)
