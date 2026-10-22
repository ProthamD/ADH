import uuid
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from server.store.db import (
    create_delegation_record,
    get_delegation,
    find_active_delegation_by_owner_or_recipient,
    update_delegation_status,
    increment_delegation_uses,
    increment_failed_attempts,
    reset_failed_attempts,
    log_audit_event,
    get_audit_events_for_delegation,
    parse_iso,
    now,
)
from server.vault.crypto import (
    hash_codeword,
    verify_codeword,
    encrypt_payload,
    decrypt_payload,
    slice_facts,
)
from server.gate.bedrock_gate import classify_question
from server.gate.speech_rewriter import rewrite_facts_for_speech

logger = logging.getLogger(__name__)

def handle_create_delegation(
    recipient: str,
    topic_desc: str,
    facts: List[Dict[str, str]],
    codeword: str,
    max_uses: int = 1,
    expires_at: Optional[str] = None,
    escalate_to: Optional[str] = None,
    owner: str = "userA",
) -> Dict[str, Any]:
    """
    Creates a new time-locked, scoped, encrypted delegation.
    """
    if not recipient or not topic_desc or not facts or not codeword:
        return {"error": "Missing required fields (recipient, topic_desc, facts, codeword)."}

    # Default expires_at to 1 hour from now if not provided
    if not expires_at:
        from datetime import timedelta
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

    delegation_id = str(uuid.uuid4())
    fact_labels = [f.get("label", "").strip() for f in facts if f.get("label")]
    if not fact_labels:
        return {"error": "At least one labeled fact is required."}

    # Encrypt raw secret payload and hash codeword
    payload_enc = encrypt_payload(facts)
    cw_hash = hash_codeword(codeword)

    record = create_delegation_record(
        delegation_id=delegation_id,
        owner=owner,
        recipient=recipient,
        topic_desc=topic_desc,
        payload_enc=payload_enc,
        fact_labels=fact_labels,
        codeword_hash=cw_hash,
        max_uses=int(max_uses),
        expires_at=expires_at,
        escalate_to=escalate_to,
    )

    log_audit_event(
        actor=owner,
        action="created",
        delegation_id=delegation_id,
        note=f"Delegation created for {recipient} with {len(fact_labels)} labeled facts. Expires {expires_at}.",
    )

    return {
        "status": "created",
        "delegation_id": delegation_id,
        "owner": owner,
        "recipient": recipient,
        "topic_desc": topic_desc,
        "fact_labels": fact_labels,
        "max_uses": max_uses,
        "expires_at": expires_at,
        "message": f"Successfully created delegation '{topic_desc}' for {recipient}.",
    }

def handle_ask_delegation(
    delegation_id_or_name: str,
    question: str,
    codeword: str,
    caller: str = "userB",
) -> Dict[str, Any]:
    """
    Processes an Alexa+ question through Stage 1 Gatekeeper and Stage 2 Vault.
    """
    cleaned_question = (question or "").strip()
    if not cleaned_question:
        return {"status": "denied", "message": "Please provide a valid question."}

    # Locate delegation
    d = get_delegation(delegation_id_or_name)
    if not d:
        d = find_active_delegation_by_owner_or_recipient(delegation_id_or_name)

    if not d:
        log_audit_event(
            actor=caller,
            action="denied",
            question=cleaned_question,
            note="Refused: No matching delegation found.",
        )
        return {"status": "denied", "message": "I'm sorry, no active delegation was found matching your request."}

    delegation_id = d["id"]
    status = d["status"]

    # Check status
    if status != "active":
        log_audit_event(
            actor=caller,
            action="denied",
            delegation_id=delegation_id,
            question=cleaned_question,
            note=f"Refused: Delegation status is '{status}'.",
        )
        return {"status": "denied", "message": f"This delegation is currently {status} and cannot be accessed."}

    # Check expiration
    expires_at = parse_iso(d["expires_at"])
    if datetime.now(timezone.utc) >= expires_at:
        update_delegation_status(delegation_id, "expired")
        log_audit_event(
            actor=caller,
            action="denied",
            delegation_id=delegation_id,
            question=cleaned_question,
            note="Refused: Delegation deadline has passed.",
        )
        return {"status": "expired", "message": "This delegation has expired."}

    # Check lockout
    if d.get("failed_attempts", 0) >= 3:
        update_delegation_status(delegation_id, "locked")
        log_audit_event(
            actor=caller,
            action="locked",
            delegation_id=delegation_id,
            question=cleaned_question,
            note="Refused: Delegation locked due to 3 failed attempts.",
        )
        return {"status": "locked", "message": "Access is locked due to multiple incorrect codeword attempts."}

    # -------------------------------------------------------------
    # STAGE 1: Blind Gatekeeper (Bedrock)
    # Sees ONLY question, topic_desc, and fact_labels (NEVER values)
    # -------------------------------------------------------------
    log_audit_event(
        actor=caller,
        action="asked",
        delegation_id=delegation_id,
        question=cleaned_question,
        note="Stage 1 Gatekeeper evaluation initiated.",
    )

    gate_result = classify_question(
        question=cleaned_question,
        topic_desc=d["topic_desc"],
        fact_labels=d["fact_labels"],
    )

    if gate_result.decision == "DENY":
        log_audit_event(
            actor=caller,
            action="denied",
            delegation_id=delegation_id,
            question=cleaned_question,
            gate_decision="DENY",
            gate_confidence=gate_result.confidence,
            note=f"Gatekeeper blocked: {gate_result.reasoning}",
        )
        return {
            "status": "denied",
            "decision": "DENY",
            "confidence": gate_result.confidence,
            "message": "I cannot provide that information. Your question is outside the authorized scope.",
        }

    if gate_result.decision == "BORDERLINE":
        log_audit_event(
            actor=caller,
            action="borderline",
            delegation_id=delegation_id,
            question=cleaned_question,
            gate_decision="BORDERLINE",
            gate_confidence=gate_result.confidence,
            note=f"Gatekeeper borderline: {gate_result.reasoning}",
        )
        return {
            "status": "borderline",
            "decision": "BORDERLINE",
            "confidence": gate_result.confidence,
            "message": f"I cannot verify that question with high confidence. I will check with {d['owner']}.",
        }

    # -------------------------------------------------------------
    # STAGE 2: Deterministic Vault Retrieval (Plain Code)
    # -------------------------------------------------------------
    # 1. Verify Codeword
    if not verify_codeword(codeword, d["codeword_hash"]):
        failed_count = increment_failed_attempts(delegation_id)
        if failed_count >= 3:
            log_audit_event(
                actor=caller,
                action="locked",
                delegation_id=delegation_id,
                question=cleaned_question,
                note=f"Lockout triggered: 3 failed codeword attempts.",
            )
            return {
                "status": "locked",
                "message": "Incorrect codeword. Maximum attempts reached. Delegation is now locked.",
            }
        remaining = 3 - failed_count
        log_audit_event(
            actor=caller,
            action="denied",
            delegation_id=delegation_id,
            question=cleaned_question,
            note=f"Authentication failure: incorrect codeword ({failed_count}/3).",
        )
        return {
            "status": "auth_failed",
            "message": f"Incorrect codeword. Voice authentication failed ({remaining} attempts remaining).",
        }

    # Codeword verified! Reset failed attempts
    reset_failed_attempts(delegation_id)

    # 2. Check limits & increment use count
    new_uses = increment_delegation_uses(delegation_id)
    new_status = "exhausted" if new_uses >= d["max_uses"] else "active"

    # 3. Decrypt facts and apply semantic slicing
    all_facts = decrypt_payload(d["payload_enc"])
    sliced_facts = slice_facts(all_facts, gate_result.allowed_labels)

    if not sliced_facts:
        log_audit_event(
            actor=caller,
            action="denied",
            delegation_id=delegation_id,
            question=cleaned_question,
            note="Zero facts matched allowed labels during slicing.",
        )
        return {
            "status": "denied",
            "message": "Authorization succeeded, but no specific facts were matched to your question.",
        }

    # 4. Speech rewrite for conversational Alexa+ experience
    spoken_answer = rewrite_facts_for_speech(sliced_facts)

    log_audit_event(
        actor=caller,
        action="allowed",
        delegation_id=delegation_id,
        question=cleaned_question,
        gate_decision="ALLOW",
        gate_confidence=gate_result.confidence,
        note=f"Access granted. Released {len(sliced_facts)} fact(s). Uses now: {new_uses}/{d['max_uses']}.",
    )

    return {
        "status": "allowed",
        "decision": "ALLOW",
        "confidence": gate_result.confidence,
        "answer": spoken_answer,
        "facts_released": len(sliced_facts),
        "uses": new_uses,
        "max_uses": d["max_uses"],
        "delegation_status": new_status,
        "message": spoken_answer,
    }

def handle_audit_log(
    delegation_id_or_name: str,
    caller: str = "userA",
) -> Dict[str, Any]:
    """
    Returns sanitized audit events for a delegation.
    Only the owner (userA) may call this.
    """
    d = get_delegation(delegation_id_or_name)
    if not d:
        d = find_active_delegation_by_owner_or_recipient(delegation_id_or_name)

    if not d:
        return {"error": "Delegation not found."}

    if caller != d["owner"]:
        return {"error": "Unauthorized: Only the delegation owner may inspect audit logs."}

    events = get_audit_events_for_delegation(d["id"])

    # Natural summary for voice query ("Did Sarah check yet?")
    has_accessed = any(e["action"] == "allowed" for e in events)
    is_exhausted = d["status"] == "exhausted"
    is_revoked = d["status"] == "revoked"
    is_expired = d["status"] == "expired"
    is_locked = d["status"] == "locked"

    if has_accessed:
        summary = f"{d['recipient']} has checked in and successfully received the answer (Uses: {d['uses']}/{d['max_uses']})."
    elif is_locked:
        summary = f"Access was locked after repeated failed codeword attempts by {d['recipient']}."
    elif is_revoked:
        summary = f"This delegation was revoked by {d['owner']}."
    elif is_expired:
        summary = f"The deadline passed without {d['recipient']} checking in. Escalation was triggered."
    else:
        summary = f"{d['recipient']} has not checked in yet. The delegation remains active until {d['expires_at']}."

    return {
        "delegation_id": d["id"],
        "owner": d["owner"],
        "recipient": d["recipient"],
        "topic_desc": d["topic_desc"],
        "status": d["status"],
        "uses": d["uses"],
        "max_uses": d["max_uses"],
        "summary": summary,
        "events": events,
    }

def handle_revoke_delegation(
    delegation_id: str,
    caller: str = "userA",
) -> Dict[str, Any]:
    """
    Immediately revokes an active delegation.
    Only the owner (userA) may call this.
    """
    d = get_delegation(delegation_id)
    if not d:
        return {"error": "Delegation not found."}

    if caller != d["owner"]:
        return {"error": "Unauthorized: Only the delegation owner may revoke access."}

    update_delegation_status(delegation_id, "revoked")
    log_audit_event(
        actor=caller,
        action="revoked",
        delegation_id=delegation_id,
        note=f"Delegation explicitly revoked by owner {caller}.",
    )

    return {
        "status": "revoked",
        "delegation_id": delegation_id,
        "message": f"Delegation '{d['topic_desc']}' for {d['recipient']} has been revoked immediately.",
    }

def handle_check_scam_message(text: str) -> Dict[str, Any]:
    """
    Evaluates suspicious voice or text messages for potential scams using Bedrock.
    """
    from server.gate.bedrock_gate import get_bedrock_client, BEDROCK_MODEL_ID
    prompt = f"""You are an Alexa+ Security Assistant. Analyze the following user-submitted message for potential phishing, impersonation, or scam indicators.
Message to analyze:
\"\"\"{text}\"\"\"

Provide your evaluation as JSON with:
- verdict: 'likely_scam' | 'suspicious' | 'looks_ok'
- reasons: list of strings
- suggested_action: string advising the user what to do safely
"""
    try:
        client = get_bedrock_client()
        resp = client.converse(
            modelId=BEDROCK_MODEL_ID,
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig={"maxTokens": 200, "temperature": 0.0},
        )
        content = resp["output"]["message"]["content"][0]["text"]
        # Basic JSON parsing
        import re
        match = re.search(r"\{.*\}", content, re.DOTALL)
        if match:
            return json.loads(match.group(0))
        return {
            "verdict": "suspicious",
            "reasons": ["Automated classification completed"],
            "suggested_action": "Do not share passwords or click unexpected links.",
            "raw": content,
        }
    except Exception as e:
        return {
            "verdict": "suspicious",
            "reasons": [f"Analysis fallback due to: {str(e)}"],
            "suggested_action": "Be cautious and verify the sender through a known trusted channel.",
        }
