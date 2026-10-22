# Alexa+ Delegation Broker (MCP Server & Simulator)

> **"Don't share the secret, delegate the answer."**

An auditable, time-locked, semantically sliced delegation broker built for **Alexa+** as a self-hosted **Model Context Protocol (MCP)** server over **Streamable HTTP** (spec 2025-11-25+), paired with the **AWS Builder mini-challenge** powered by **Amazon Bedrock**.

[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![MCP Spec](https://img.shields.io/badge/MCP-2025--11--25+-00caff.svg)](https://modelcontextprotocol.io/)
[![AWS Bedrock](https://img.shields.io/badge/AWS-Bedrock_Runtime-orange.svg)](https://aws.amazon.com/bedrock/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 1. Hackathon Context & Highlights

- **Primary Track:** Alexa+ (Self-Hosted Streamable HTTP MCP Server running on `/mcp`).
- **Mini Challenge:** AWS Builder (Amazon Bedrock Runtime `converse` API for Stage 1 Blind Gatekeeper & Speech Rewriting).
- **Judging Bonus:** Up to 10% bonus captured in [`FRICTION_LOG.md`](FRICTION_LOG.md) tracking MCP 2.x migration, Streamable HTTP transport, and Bedrock model lifecycle nuances.
- **Auditable Security:** Two-stage air-gapped pipeline. Stage 1 never sees secrets; Stage 2 deterministic vault performs semantic slicing in pure code.

---

## 2. Why Not Just Share a Note?

| Problem with Sharing a Note | Alexa+ Delegation Broker Solution |
|---|---|
| **Custody Loss:** The recipient sees everything at once and can retain it forever. | **Semantic Slicing:** User B only receives the specific fact needed to answer their approved question. |
| **No Expiration:** Notes sent over Slack/SMS linger forever. | **Time-Locked & Ephemeral:** Expires automatically at a deadline or after N uses. |
| **Blind Access:** Sender never knows if, when, or what was read. | **Live Audit:** User A asks *"Alexa, did Sarah check the server steps yet?"* and receives an auditable log. |
| **Silent Failures:** If teammate never checks in during an outage, silence. | **Time-Locked Escalation:** Missed deadline fires an out-of-band webhook (Slack/Discord) and queues an urgent briefing. |

---

## 3. Architecture & Two-Stage Security Model

```
+------------------+        +-------------------------------+        +------------------+
|  User A column   |        |      MCP SERVER  (/mcp)       |        |  User B column   |
|  (Alexa+ sim)    | <----> |  Streamable HTTP, spec        | <----> |  (Alexa+ sim)    |
|  create / audit  |  MCP   |  2025-11-25+                  |  MCP   |  ask / codeword  |
|  / revoke        |  calls |                               |  calls |                  |
+------------------+        |  tools:                       |        +------------------+
                            |   create_delegation           |
   center panel:            |   ask_delegation              |
   live audit + timers  <---|   audit_log                   |
   JSON-RPC trace           |   revoke_delegation           |
                            |   check_scam_message          |
                            |                               |
                            |  +-------------------------+  |
                            |  | Stage 1: Blind Gatekeeper| |
                            |  | Bedrock LLM. Sees ONLY   | |
                            |  | question + topic desc.   | |
                            |  | Zero secret values.      | |
                            |  +------------+------------+  |
                            |               | ALLOW         |
                            |  +------------v------------+  |
                            |  | Stage 2: Vault Retrieval | |
                            |  | HMAC codeword, limits,   | |
                            |  | decrypt & semantic slice | |
                            |  +------------+------------+  |
                            |               |               |
                            |  +------------v------------+  |
                            |  | SQLite Store & Scheduler | |
                            |  | Background Expiry Loop   | |
                            |  +-------------------------+  |
                            +---------------+---------------+
                                            |
                                  Escalation Webhook
                               (Slack / Discord / SMS)
```

### Stage 1: Blind Gatekeeper (Bedrock)
- Prompt contains **only** the allowed topic description and fact labels (e.g. `"rollback command"`, `"database rollback"`).
- Untrusted user question is enclosed in `<untrusted_user_question>` delimiters.
- Forced tool schema (`record_gate_decision`) outputs enum `ALLOW | DENY | BORDERLINE`, numeric confidence, and matched `allowed_labels`.
- **Fail-Closed:** Malformed output, timeouts, or low confidence (< 0.75) immediately default to `DENY`.

### Stage 2: Vault Retrieval (Deterministic Code)
- Voice codeword normalization (`strip().lower().rstrip(".!,?")`) prevents speech recognition punctuation mismatch.
- Keyed HMAC-SHA256 hash comparison using constant-time `secrets.compare_digest`.
- 3 failed attempts triggers automatic delegation lockout.
- Decrypts Fernet payload and slices **only** the allowed fact labels (capped at max 2 facts).
- Bedrock speech rewriter formats sliced facts into a natural 1-2 sentence spoken Alexa+ output.

---

## 4. MCP Tools Contract

All tools are registered on the official `MCPServer` instance and exposed over Streamable HTTP at `/mcp`:

1. `create_delegation`: Owner delegates a topic, secret facts (`[{label, value}]`), voice codeword, max uses, expiry, and escalation target.
2. `ask_delegation`: Recipient inquires via Alexa+. Passes through Stage 1 Gatekeeper and Stage 2 Vault.
3. `audit_log`: Owner query returning chronological audit events (guaranteed zero secret leaks).
4. `revoke_delegation`: Owner terminates active delegation immediately.
5. `check_scam_message`: Auxiliary voice tool analyzing suspicious incoming messages for phishing.

---

## 5. Quickstart & How to Run

### Prerequisites
- Python 3.11+
- Dependencies installed via `pip`:
  ```bash
  pip install -r requirements.txt
  ```

### Configuration
Copy `.env.example` to `.env` and fill in your settings:
```bash
cp .env.example .env
```
Key variables:
- `AWS_REGION=us-east-1`
- `BEDROCK_MODEL_ID=amazon.nova-micro-v1:0` (or `anthropic.claude-3-5-haiku-20241022-v1:0`)
- `DEMO_MODE=true`
- `ESCALATION_WEBHOOK_URL=https://httpbin.org/post`

### Launch the Unified Server
Run the unified server (serves MCP at `/mcp`, REST bridge at `/api`, and the Web Simulator at `/`):
```bash
python -m uvicorn server.main:app --port 8000
```
Open your browser at:
👉 **`http://localhost:8000`**

---

## 6. Running the Test Suite

Run all automated unit, integration, and security invariant tests:
```bash
python -m pytest tests/ -v
```

Tests include:
- `test_vault.py`: Fernet encryption, codeword normalization, constant-time verification, 3-attempt lockout, and audit log secret exclusion assertions.
- `test_mcp_protocol.py`: Real MCP client Streamable HTTP connection to `/mcp`, tool discovery, and tool call execution.
- `test_escalation.py`: Missed deadline escalation, webhook delivery, queued briefing creation, and fast-forward debug route.
- `test_gatekeeper_benchmark.py`: Air-gapped prompt security and fail-closed defense tests.

---

## 7. Demo Video Walkthrough (Under 3 Minutes)

1. **0:00 - 0:25 (The Pitch):** Show the problem of sharing raw notes vs delegating answers with custody intact.
2. **0:25 - 0:50 (User A Console):** Click the **"🚀 On-Call"** scenario preset in Column 1. Form populates with rollback steps, codeword `"solaris"`, 1 use, and 10-minute expiry. Click **"🔒 Delegate to Alexa+"**.
3. **0:50 - 1:30 (The 3 Test Cases in Column 3):**
   - Click **"Case 2: Out-Of-Scope"**: Asks for company finances -> Blocked by Stage 1 Gatekeeper.
   - Click **"Case 3: Jailbreak"**: Attempt to dump secrets -> Blocked by Gatekeeper, and the center log confirms the gatekeeper prompt had zero secrets.
   - Click **"Case 1: In-Scope"**: Asks for rollback command with codeword `" Solaris. "` -> Authorized, 1 fact released with semantic slicing, and Alexa+ speaks the concise answer.
4. **1:30 - 2:00 (Audit & Revoke):** User A clicks **"🔍 Check Audit"** -> Alexa+ answers *"userB has checked in and successfully received the answer (Uses: 1/1)"*. Show instant revocation on an active delegation.
5. **2:00 - 2:30 (Time-Locked Escalation):** Create another delegation. In the center hub, click **"⏩ Fast-Forward (Escalate)"**. The countdown reaches zero, the out-of-band webhook fires, and Column 3 immediately displays an **Urgent Alexa+ Priority Briefing**!
6. **2:30 - 3:00 (Wrap-up):** Show the Raw MCP JSON-RPC Inspector demonstrating real Streamable HTTP traffic against `/mcp`.
