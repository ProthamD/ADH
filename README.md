# Alexa+ Delegation Broker (MCP Server & Simulator)

> **"Don't share the secret, delegate the answer."**

### Try it out : https://alexa-delegation-broker.onrender.com/


An auditable, time-locked, semantically sliced delegation broker built for **Alexa+** as a self-hosted **Model Context Protocol (MCP)** server over **Streamable HTTP** (spec 2025-11-25+), paired with the **AWS Builder mini-challenge** powered by **Amazon Bedrock**.

[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![MCP Spec](https://img.shields.io/badge/MCP-2025--11--25+-00caff.svg)](https://modelcontextprotocol.io/)
[![AWS Bedrock](https://img.shields.io/badge/AWS-Bedrock_Runtime-orange.svg)](https://aws.amazon.com/bedrock/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 1. Hackathon Context & Highlights

- **Primary Track:** Alexa+ (Self-Hosted Streamable HTTP MCP Server running on `/mcp`).
- **Mini Challenge:** AWS Builder (AWS Serverless ecosystem: Amazon S3 audit vault, AWS Lambda escalation worker, Amazon CloudWatch security metrics, Amazon SNS threat alerts, and Amazon Bedrock).
- **Sub-Millisecond Semantic Engine:** High-efficiency autonomous `FastSemanticRouter` (< 5ms inference latency, TF-IDF vector cosine similarity, adversarial jailbreak defense) with automatic Bedrock fallback.
- **Judging Bonus:** Up to 10% bonus captured in [`FRICTION_LOG.md`](FRICTION_LOG.md) tracking MCP 2.x migration, Streamable HTTP transport, and AWS serverless lifecycle nuances.
- **Auditable Security:** Two-stage air-gapped pipeline. Stage 1 never sees secrets; Stage 2 deterministic vault performs semantic slicing in pure code.
- **AWS Serverless Status:** Real-time diagnostics at `/api/aws/status` and live header badge in simulator.

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

### Stage 1: Blind Gatekeeper & Sub-Millisecond Semantic Engine
- **Zero-Secret Exposure:** Evaluates questions strictly against topic descriptions and fact labels. Never sees secret values.
- **FastSemanticRouter Engine (< 5ms):** Autonomous embedded vector cosine similarity and n-gram TF-IDF router. Hardened against adversarial jailbreaks, persona manipulation, system prompt dumps, and out-of-scope domain probes.
- **Bedrock Converse Fallback:** When AWS Bedrock model permissions are enabled, seamlessly connects to `amazon.nova-micro-v1:0` or Claude; if pending verification or offline, runs the local semantic router with zero interruption.
- **Fail-Closed Security:** Malformed output, timeouts, or unhandled exceptions fail closed to `DENY`. Low-confidence decisions (< 0.75) return `BORDERLINE`.

### Stage 2: Vault Retrieval (Deterministic Code)
- Codeword verified first before calling the gatekeeper (saves LLM tokens and prevents topical probing).
- Voice codeword normalization (`unicodedata.normalize("NFKC", ...).casefold().strip().strip("'\"")`) prevents speech transcription mismatches.
- Keyed HMAC-SHA256 comparison using constant-time `secrets.compare_digest`.
- 3 failed attempts triggers automatic delegation lockout.
- 5 cumulative gatekeeper denials on a delegation also triggers automatic lockout.
- Slices **only** the allowed fact labels (capped at max 2 facts).
- Atomic `try_consume_use()` in SQLite guarantees single-use delegations cannot be double-consumed by concurrent queries.
- **Ephemeral Self-Destruction:** When a delegation reaches a terminal state (`expired`, `exhausted`, `revoked`, `locked`), its encrypted secret payload is immediately wiped (`purged_at`) from disk.
- Natural voice response formatter produces crisp spoken Alexa+ answers with verbatim value verification.

### AWS Serverless Cloud Ecosystem
- **Amazon S3 (`alexa-delegation-vault-audit`):** Immutable, cloud-backed tamper-evident audit archival with AES-256 Server-Side Encryption and local staging sync.
- **AWS Lambda (`alexa-delegation-escalation-handler`):** Asynchronous serverless escalation dispatcher for out-of-band PagerDuty, Slack, or SMS notifications.
- **Amazon CloudWatch (`AlexaPlusDelegationBroker/Security`):** Real-time operational metrics for query decisions, jailbreak threat detections, and facts released.
- **Amazon SNS (`alexa-delegation-security-alerts`):** High-severity alerting topic triggered upon prompt injection or domain breach attempts.
- **Infrastructure as Code:** Fully defined in [`infra/template.yaml`](infra/template.yaml) via AWS SAM / CloudFormation.

---

## 4. MCP Tools Contract

All tools are registered on the official `MCPServer` instance and exposed over Streamable HTTP at `/mcp`:

1. `create_delegation`: Owner delegates a topic, secret facts (`[{label, value}]`), voice codeword, max uses, expiry (or `expires_in_minutes`), and optional HTTPS webhook escalation target.
2. `ask_delegation`: Recipient inquires via Alexa+. Passes through Stage 1 Gatekeeper and Stage 2 Vault.
3. `audit_log`: Owner query returning chronological audit events with SHA-256 tamper-evident hash chaining.
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

### Generate Cryptographic Keys & Configuration
Generate cryptographically strong Fernet and HMAC keys:
```bash
python scripts/gen_keys.py
```
Copy the output keys into your `.env` file (or start from `.env.example`):
```bash
cp .env.example .env
```
Key variables:
- `ENCRYPTION_KEY`: Base64 Fernet key generated by `gen_keys.py` (server refuses to start if missing or placeholder).
- `HMAC_SECRET`: 32+ character random hex secret generated by `gen_keys.py`.
- `AWS_REGION`: e.g. `us-east-1`
- `BEDROCK_MODEL_ID`: `amazon.nova-micro-v1:0` (or `anthropic.claude-3-5-haiku-20241022-v1:0`)
- `DEMO_MODE=true`

### Seed Demo Scenarios (Optional)
Populate clean demo delegations:
```bash
python scripts/seed_demo.py --reset
```

### Launch the Unified Server
Run the unified server (serves MCP at `/mcp`, REST bridge at `/api`, and the Web Simulator at `/`):
```bash
python -m uvicorn server.main:app --port 8000
```
Open your browser at:
👉 **`http://localhost:8000`**

---

## 6. Running the Test Suite & Benchmark

### Automated Tests (Runs fully offline without AWS credentials)
```bash
python -m pytest tests/ -v
```
All 26 tests run against temporary in-memory/temp databases with mocked external boundaries:
- `test_vault.py`: Fernet encryption, codeword normalization, constant-time verification, 3-attempt lockout, atomic race condition safety, ephemeral payload purge, and SHA-256 audit hash chain verification.
- `test_mcp_protocol.py`: Official MCP Python client connecting to Streamable HTTP `/mcp`, tool discovery, and assertions verifying no secret leakage in traces.
- `test_escalation.py`: Time-locked scheduler, retry backoff webhook delivery, queued briefings, and bad-row tolerance.
- `test_gatekeeper_benchmark.py`: Air-gapped prompt security, fail-closed defenses, and input size constraints.

### Stage 1 Gatekeeper Benchmark Runner
To run the 21 benchmark cases in `tests/gate_cases.yaml` and generate `docs/GATE_BENCHMARK.md`:
```bash
python scripts/run_gate_bench.py [--mock]
```

---

## 7. Security Model & Deployment Notes

- **Simulated Identity**: In this demonstration environment, caller identity (`userA` / `userB`) is self-asserted for local simulator accessibility. In an Alexa+ production deployment, identity is anchored to the authenticated Alexa voice profile token passed in the request header.
- **Local Network Scope**: The server is designed for self-hosted local execution or deployment behind an authenticated reverse proxy (OAuth2 / mTLS). Do not expose raw demo endpoints directly to untrusted public networks.
- **Hardware Simulation Notice**: The Web Simulator provides a browser-based simulation of Alexa+ voice input/output (using Web Speech API `SpeechRecognition` and `speechSynthesis`) and raw MCP protocol streaming. It was tested against MCP 2.x and Bedrock Nova Micro APIs, not physical Alexa hardware.

---
