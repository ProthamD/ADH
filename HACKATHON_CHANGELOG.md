# Hackathon Changelog: Alexa+ Delegation Broker

All features and files documented below were created from scratch during the hackathon window.

## [Initial Release] - 2026-10-22

### Architecture & Protocol
- **Streamable HTTP MCP Server**: Implemented `/mcp` endpoint adhering to MCP spec (2025-11-25+) using Python `mcp` 2.3.0 `MCPServer`.
- **Alexa+ Tools Registered**:
  - `create_delegation`: Owner defines scoped topic, labeled facts, codeword, limits, and escalation.
  - `ask_delegation`: Two-stage gated execution (Bedrock gatekeeper + deterministic vault retrieval).
  - `audit_log`: Owner audit query returning sanitized historical actions.
  - `revoke_delegation`: Immediate access termination and timer cancellation.
  - `check_scam_message`: Auxiliary voice security assessment for suspicious messages.

### Security & Guardrails
- **Stage 1 Blind Gatekeeper**: AWS Bedrock Runtime `converse` API evaluating untrusted questions against topic descriptions and fact labels. Secret values are never passed to the model.
- **Stage 2 Vault**: Pure code. Voice codeword normalization (`strip().lower().rstrip(".!,?")`), HMAC-SHA256 keyed hashing, constant-time comparison, 3-attempt lockout, and Fernet encryption at rest.
- **Semantic Slicing**: Decrypts and releases only the specific facts deemed relevant by the gatekeeper (maximum 2 facts per response).
- **Speech Rewriting**: Bedrock runtime formatting of released facts into natural 1-2 sentence spoken Alexa+ answers.

### Escalation & Timers
- **Multi-channel Time-Locked Escalation**: In-process background scheduler monitoring delegation expiration; triggers external webhooks (Slack/Discord) if no check-in occurs.
- **Queued Briefing**: Automatically stages urgent `pending_briefing` greetings delivered to User B upon their next Alexa+ turn.
- **Fast-Forward Debug Route**: `POST /api/debug/fast-forward/{delegation_id}` for live demo clock acceleration under `DEMO_MODE=true`.

### Frontend Simulator
- **Unified 3-Column Alexa+ Console**:
  - Column 1: User A voice console with scenario presets ("On-Call Rollback", "House Sitter Key", "Caretaker Meds").
  - Column 2: Live Countdown Timers, Real-Time Audit Feed, and Live MCP JSON-RPC protocol inspector.
  - Column 3: User B voice console with pending briefing alerts, question & codeword inputs, and instant test triggers.
