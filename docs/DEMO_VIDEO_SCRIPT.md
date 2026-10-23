# Alexa+ Delegation Broker (ADH) — 3-Minute Demo Video Script

> **Target Video Runtime**: 2 minutes 48 seconds (Safety buffer: 12 seconds under the 3:00 hard cutoff)  
> **Total Word Count**: ~390 words  
> **Speech Rate**: ~140 words per minute (optimal for natural AI TTS models like ElevenLabs / OpenAI "alloy" / Amazon Polly)  
> **Target Audience**: Amazon Developer Hackathon Judges (Alexa+ Track & AWS Builder Mini-Challenge)

---

## Pre-Recording Checklist (Setup Before You Record)
1. **Open Tab 1**: Web Simulator at `http://localhost:8000/` (clean full-screen 1080p browser window, zoom at 100%).
2. **Open Tab 2**: OAuth 2.1 Consent Screen at:  
   `http://localhost:8000/oauth/authorize?client_id=alexa-simulator&redirect_uri=http://localhost:8000/oauth/callback&response_type=code&code_challenge=xyz&code_challenge_method=S256`
3. **Open Tab 3**: GitHub Repository at `https://github.com/ProthamD/ADH`.
4. **Audio**: Ensure your screen recorder captures system audio if you want the Alexa text-to-speech voice playback heard.

---

## Full Video Script & Visual Directions

---

### [0:00 – 0:25] Scene 1: The Hook & The Problem
* **Duration**: 25 seconds (Target word count: ~60 words)
* **On-Screen Navigation**: 
  - Start on the **Web Simulator** at `http://localhost:8000/`.
  - Slowly pan / point your cursor to the header: `"Alexa+ Delegation Broker"` and the live `"Streamable HTTP: /mcp"` badge.

#### 🎙️ Spoken Script:
> *"Today’s voice assistants face an all-or-nothing dilemma. If Alexa is unlocked in a shared home or office, anyone in earshot can ask for alarm codes, smart lock pins, or company secrets. There is no zero-trust delegation. We built the Alexa Plus Delegation Broker to solve this—bringing ephemeral, time-locked, and cryptographically verified delegations to multi-user Alexa Plus environments."*

---

### [0:25 – 0:55] Scene 2: Architecture & Two-Device OAuth 2.1
* **Duration**: 30 seconds (Target word count: ~70 words)
* **On-Screen Navigation**:
  - Switch briefly to **Tab 2** (the OAuth 2.1 login screen). Point cursor at the **Owner (User A)** and **Recipient (User B)** role buttons.
  - Switch back to **Tab 1** (Simulator). Point cursor to the left column: **Active Delegations** showing `blue falcon`, `copper pine`, and `silver lake`.

#### 🎙️ Spoken Script:
> *"Our project implements the official MCP Streamable HTTP specification and an RFC-compliant OAuth 2.1 authorization server. Two distinct Alexa devices connect simultaneously: User A, the owner who creates time-bounded delegations with access limits, and User B, the recipient—like an on-call engineer, house sitter, or caretaker. Each request is authenticated via Bearer tokens, eliminating self-asserted caller spoofing."*

---

### [0:55 – 1:30] Scene 3: Live Demo — The Authorized Request & Semantic Slicing
* **Duration**: 35 seconds (Target word count: ~82 words)
* **On-Screen Navigation**:
  - Under **Scenario Presets**, click the **"On-Call"** preset button.
  - Notice the question fills: *"What is the deployment procedure?"* and codeword fills: *"blue falcon"*.
  - Click the cyan button: **"Ask Alexa as User B"**.
  - Highlight the green **ALLOWED** result box, the spoken audio response, and the badge: `"Semantic Slicing: 1 fact(s) released"`.

#### 🎙️ Spoken Script:
> *"Let's test an on-call DevOps scenario. User A granted access to deployment steps under the phonetic codeword 'blue falcon'. User B asks: 'What is the deployment procedure?'. Amazon Bedrock evaluates the query against the topic scope, verifies the codeword, and our Semantic Slicer releases only the single relevant fact: the helm deploy command. The rest of the payload remains encrypted in the AES vault."*

---

### [1:30 – 2:05] Scene 4: Defense-in-Depth — Guardrail & Codeword Rejections
* **Duration**: 35 seconds (Target word count: ~82 words)
* **On-Screen Navigation**:
  - In the question box, delete the text and type: *"What is the home alarm code and master password?"*.
  - Click **"Ask Alexa as User B"**.
  - Show the red **DENIED** alert: `"Scope mismatch: question outside delegation boundaries"`.
  - Next, change the codeword to *"wrong secret"* and ask the deploy question again. Show the immediate red denial: `"Codeword did not match"`.

#### 🎙️ Spoken Script:
> *"Now let's test a privilege escalation attack. User B tries asking for the home alarm code and master password. Bedrock's blind gatekeeper analyzes the query intent without ever exposing decrypted vault keys and instantly denies it. Furthermore, if a user speaks an invalid codeword, access is immediately blocked, incrementing failed attempts and triggering automatic escalation webhooks before brute-force attacks can succeed."*

---

### [2:05 – 2:33] Scene 5: Cryptographic Audit Trail & AWS Serverless
* **Duration**: 28 seconds (Target word count: ~68 words)
* **On-Screen Navigation**:
  - Move the cursor to the right column: **Live Protocol Trace & Observability**.
  - Scroll through the raw JSON-RPC stream showing the `POST /mcp` requests.
  - Click on the green top-right badge: **"HASH CHAIN INTACT"**.
  - Point to the AWS badges at the bottom: **Amazon Bedrock**, **S3 Vault**, and **CloudWatch**.

#### 🎙️ Spoken Script:
> *"Every single interaction is recorded into a tamper-evident SHA-256 Merkle-like hash chain. Clicking verification confirms genesis-to-leaf integrity with zero breaks. On the right, the terminal inspects live JSON-RPC Streamable HTTP events in real-time. For enterprise durability, audit events stage directly to AWS S3, telemetry streams to CloudWatch, and critical escalations dispatch through AWS Lambda and SNS."*

---

### [2:33 – 2:48] Scene 6: Closing & Submission Summary
* **Duration**: 15 seconds (Target word count: ~30 words)
* **On-Screen Navigation**:
  - Switch to **Tab 3**: the GitHub repository at `https://github.com/ProthamD/ADH`.
  - Scroll past the README badge and the 28 passing pytest test suites.

#### 🎙️ Spoken Script:
> *"With twenty-eight passing automated test suites, complete Streamable HTTP compliance, and zero-trust security, ADH makes Alexa Plus safe for real-world shared environments. Thank you for watching."*

---

## Quick Reference Table for Video Production

| Timestamp | Visual Screen Target | Spoken Topic | Word Count |
| :---: | :--- | :--- | :---: |
| **0:00 – 0:25** | Simulator Home (`http://localhost:8000`) | The Hook & Voice Security Problem | 60 |
| **0:25 – 0:55** | OAuth Screen & Active Delegations | Dual-Device Architecture & MCP Spec | 70 |
| **0:55 – 1:30** | Preset Click + Allowed Query Response | Happy Path Demo & Semantic Slicing | 82 |
| **1:30 – 2:05** | Prompt Injection & Wrong Codeword Rejection | Bedrock Guardrail & Security Rejection | 82 |
| **2:05 – 2:33** | Protocol Trace Terminal & Hash Chain Badge | Observability, Audit Trail & AWS Staging | 68 |
| **2:33 – 2:48** | GitHub Repo (`ProthamD/ADH`) & Test Suite | Wrap-up & Hackathon Submission | 30 |
| **Total** | **2:48 Run Time** (Buffer: 12 seconds under 3:00) | **Zero-Trust Alexa+ Broker** | **~392 words** |
