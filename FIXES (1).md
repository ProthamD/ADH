# FIXES.md: Review of ADH (Alexa+ Delegation Broker)

Audience: the IDE coding agent. Work top to bottom. Do not skip P0.
Every item says how well it was checked, so nothing here should be taken as more certain than it is.

## Evidence tags

- **[REPRODUCED]**: I ran it and saw the failure.
- **[TESTED FIX]**: I applied the fix to a copy and re-ran the same check.
- **[BY READING]**: seen in the code; I did not execute it.
- **[UNVERIFIED]**: depends on a live service or docs I could not check. Check before claiming it.
- **[SUGGESTION]**: my judgment about what would improve the project. Not a defect.

## What the review did NOT cover

- No AWS credentials, so **no live Bedrock calls**. The ALLOW path (gate, codeword, slice, speech rewrite) was only tested with the gate mocked.
- I never opened the UI in a browser, so I have not judged how it looks or whether the demo flow feels right.
- Only 8 of the 21 `innerHTML` uses in `app.js` were checked for escaping. The ones I saw use `escapeHtml`.
- Nothing about real Alexa+ behavior was tested. The Alexa claims in `PLAN.md` marked [VERIFY] are still unverified.
- Environment: `mcp==2.3.0`, `fastapi==0.159.1`, `uvicorn==0.54.0`, Python 3.11.
- Baseline: the 13 shipped tests pass (`DB_PATH=<temp> pytest tests/`).

---

## P0: must fix before submission

### P0-1. `/mcp` does not work on the real server

**[REPRODUCED]**
- `POST /mcp` returns **405**.
- `POST /mcp/` returns **500**: `RuntimeError: Task group is not initialized. Make sure to use run().`
- The official client (`streamable_http_client` + `ClientSession`) fails against both URLs.
- The simulator bridge trace for one call is `['REQUEST', 'DIRECT_EXEC']`, so the UI "works" without using MCP at all.

**Causes**
1. FastAPI does not run a mounted sub-app's lifespan, so the MCP session manager never starts.
2. `streamable_http_path="/"` mounted at `/mcp` only answers on `/mcp/`. A POST to `/mcp` falls through to the `/` static mount, which gives 405.

**Why the tests pass anyway:** `tests/test_mcp_protocol.py` builds its own standalone app with `streamable_http_path="/mcp"` and runs its own lifespan. It never tests `server.main:app`.

**[TESTED FIX]** in `server/main.py`:
- Build the MCP app before the lifespan, with `streamable_http_path="/mcp"`.
- Enter `mcp_starlette_app.router.lifespan_context(mcp_starlette_app)` inside FastAPI's lifespan.
- Replace `app.mount("/mcp", ...)` with `app.router.routes.extend(mcp_starlette_app.routes)`, placed before the `app.mount("/", StaticFiles(...))` line.

```python
mcp_starlette_app = mcp.streamable_http_app(streamable_http_path="/mcp", stateless_http=True)

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    await scheduler.start()
    asyncio.create_task(_get_bedrock_health())
    async with mcp_starlette_app.router.lifespan_context(mcp_starlette_app):
        yield
    await scheduler.stop()

# ...after `app = FastAPI(lifespan=lifespan)` and the CORS middleware:
app.router.routes.extend(mcp_starlette_app.routes)
```

After this: raw POST `/mcp` gave 200, the official client listed 5 tools, and the bridge trace became `['REQUEST', 'RESPONSE']`. (`/mcp/` with a trailing slash then returns 405. That is fine. Document `/mcp` as the endpoint.) A patched `main.py` was sent with this review.

**Also do:**
1. **Remove the silent fallback.** In `execute_via_mcp_client`, the `except` currently calls `_direct_exec(...)`, which hides transport failures. Return a visible error and trace type `ERROR` instead. If you want a demo safety net, make it opt-in (`ALLOW_DIRECT_FALLBACK=true`, default false) and show a red "NOT USING MCP" banner in the UI whenever it triggers.
2. **Do not derive `BASE_URL` from `HOST`/`PORT` env.** **[BY READING]**: if the server is started with `--port 8132` but `PORT` is unset, the bridge calls port 8000. Use `str(request.base_url)` in the route handlers, or `httpx.ASGITransport(app=app)`.
3. **Add a regression test** that boots the real `server.main:app` with its lifespan, calls `initialize`, `list_tools` and `call_tool` against `/mcp` with the official client, then asserts `/api/trace` contains no `DIRECT_EXEC` entries.
4. **Log this in `FRICTION_LOG.md`.** "FastAPI `mount()` does not run a mounted ASGI app's lifespan, so the MCP session manager never starts" is real SDK friction you hit.

### P0-2. Last-use race: one-use secret released to every concurrent caller

**[REPRODUCED]**: `max_uses=1`, 6 concurrent `ask_delegation` calls (gate mocked to ALLOW with 0.3 s latency, standing in for Bedrock): the secret was released to **6 of 6** callers, final `uses=6`.

**Cause:** the status/limit check happens at the start, `increment_delegation_uses` runs unconditionally after the gate call, and nothing enforces `uses < max_uses` in SQL.

**[TESTED FIX]** (same test: released to **1 of 6**, final `uses=1`, status `exhausted`; the 8 vault/escalation tests still pass):

```python
# server/store/db.py
def try_consume_use(delegation_id: str, db_path: Optional[str] = None) -> Optional[int]:
    """Atomically consume one use. Returns new use count, or None if none was available."""
    conn = get_db(db_path)
    try:
        with conn:
            cur = conn.execute(
                "UPDATE delegations SET uses = uses + 1 "
                "WHERE id = ? AND status = 'active' AND uses < max_uses",
                (delegation_id,),
            )
            if cur.rowcount == 0:
                return None
            row = conn.execute(
                "SELECT uses, max_uses FROM delegations WHERE id = ?", (delegation_id,)
            ).fetchone()
            if row["uses"] >= row["max_uses"]:
                conn.execute("UPDATE delegations SET status = 'exhausted' WHERE id = ?", (delegation_id,))
            return row["uses"]
    finally:
        conn.close()
```

In `handle_ask_delegation`, replace `increment_delegation_uses(...)` with:

```python
new_uses = try_consume_use(delegation_id)
if new_uses is None:
    log_audit_event(actor=caller, action="denied", delegation_id=delegation_id,
                    question=cleaned_question, note="Refused: no uses remaining.")
    return {"status": "denied", "message": "This delegation has no uses remaining."}
```

**Ordering note (do this, then re-run the race check):** the tested version consumes the use *before* decrypt and slice. That has a side effect: if slicing yields zero facts, the single use is burned for nothing. Preferred order: verify codeword, run the gate, decrypt and slice, if the slice is empty deny **without** consuming, then `try_consume_use`, and only then release. Nothing is released until the consume succeeds, so this stays race-safe. Re-run the 6-thread check after reordering.

### P0-3. Unauthenticated endpoints leak secrets and webhook tokens

**[REPRODUCED]**
- A released answer (the secret value) is readable from unauthenticated `GET /api/trace`.
- `escalate_to` (a Slack/Discord webhook URL, which is a bearer secret) is readable from unauthenticated `GET /api/delegations`.

**[BY READING]**
- The `/api/events` SSE snapshot sends the same delegation list, and `/api/audit` lists every question anyone has asked.
- `/api/briefings/{recipient}` is open.
- `caller` is a plain argument the client supplies (REST and MCP both). Anyone can send `caller="userA"` to read the audit or revoke.

**Fix**
1. `record_trace`: for results with `status == "allowed"`, store `"[released N fact(s)]"` instead of `answer` and `message`. If you want the demo to show the answer, gate that behind `DEMO_MODE` plus an explicit `TRACE_SHOW_ANSWERS=true`.
2. `list_active_delegations`: also `pop("escalate_to")`. The function name is wrong too: it returns every status, not only active.
3. The "🛡️ Zero Secrets in Logs" badge in `index.html` is static text. Do not leave it up while any endpoint can return a secret, or it is a false claim.
4. Identity, two honest options:
   - **Tier A (minimum):** state in the README that user identity is simulated (hard-coded `userA`/`userB`, `caller` is self-asserted) and that the server must not be exposed publicly. This matches what `PLAN.md` allowed.
   - **Tier B:** two bearer tokens in env (`USER_A_TOKEN`, `USER_B_TOKEN`), middleware maps token to caller, tools ignore any client-supplied `caller`. **[UNVERIFIED]** how to pass identity into `MCPServer` tool functions in mcp 2.3.0 (a `contextvars` approach is plausible). Test it before relying on it.
5. **Do not deploy publicly** until at least P0-3 is done.

### P0-4. Bedrock gate is unproven end to end

**[BY READING / shipped DB]**
- The shipped DB contains exactly one `ask`. It ended in `ResourceNotFoundException` (the model reached end of life, as your own friction log says).
- After switching to Nova Micro, no further ask appears in that DB.
- The code default is still `anthropic.claude-3-haiku-20240307-v1:0`, the retired model. `.env.example` uses `amazon.nova-micro-v1:0`. Make the code default match.
- `tests/gate_cases.yaml` is only checked for its structure. No case has ever been run through the gate, so there are **no accuracy numbers**.

**Do**
1. Align the default `BEDROCK_MODEL_ID` in code with `.env.example`.
2. Enable model access in the Bedrock console. Confirm `GET /api/health` reports `bedrock.status == "ok"`.
3. **[UNVERIFIED]** Confirm the chosen model supports Converse tool use with a forced `toolChoice: {"tool": {...}}`. Check the AWS Bedrock Converse "supported models and features" docs. If forcing is not supported, fall back to `auto` and keep the strict parse (already fail-closed). Record the outcome in the friction log either way.
4. Add `scripts/run_gate_bench.py`: run every case in `gate_cases.yaml` through the real `classify_question`, print a table (id, expected, got, confidence) and the accuracy, and write it to `docs/GATE_BENCHMARK.md`. Tune `CONFIDENCE_THRESHOLD` from this data. Quote only real numbers.
5. Demo-day risk: any Bedrock error fails closed to DENY. If Bedrock throttles during recording, every ask is denied. Add 1 retry with short backoff for transient errors (throttling, timeouts) only, never for a DENY decision. Record the video from a run where the ALLOW path was verified first.
6. **[BY READING]** The speech rewriter can alter values (for example turn `4491` into "four thousand four hundred ninety-one" or drop a digit). Add a check: every released value must appear verbatim in the spoken text, otherwise use `fallback_format_facts`.
7. **[BY READING]** The README says low confidence "immediately defaults to DENY". The code returns **BORDERLINE** for low-confidence ALLOW. Make the README match the code.

### P0-5. Secrets and startup hygiene

- **Rotate keys.** The zip you shared contained a `.env` with generated `ENCRYPTION_KEY` and `HMAC_SECRET` (AWS keys were empty) and a populated `delegation_broker.db`. If that zip went anywhere besides this review, regenerate both keys and delete the old DB. If a repo exists, run `git log --all --stat -- .env '*.db'` to check history.
- `.gitignore` already excludes `.env`, `*.db` and `.pytest_cache`. Build zips from `git archive` or `git ls-files`, not from the folder.
- **[BY READING]** Startup validation is missing:
  - A missing `HMAC_SECRET` silently falls back to a hardcoded string, so anyone with the repo can compute codeword hashes.
  - A missing `ENCRYPTION_KEY` generates a random key per process, so data is unreadable after a restart (and with multiple workers).
  - The `.env.example` placeholder `your_fernet_key_base64_here` would fail inside Fernet at first use.
  - Fix: refuse to start if either value is missing, a placeholder, or an invalid Fernet key. Add `scripts/gen_keys.py` and a README step.
- **[BY READING]** The escalation webhook defaults to `https://httpbin.org/post`, sending recipient and topic to a public third-party service when no URL is set. Default it to off and log a warning.
- **[BY READING]** `escalate_to` comes from the caller, so the server POSTs to any URL given (SSRF). Allow only `https://` and either the env-configured URL or an allow-list of hosts (for example `hooks.slack.com`, `discord.com`).

### P0-6. Bad `expires_at` breaks the scheduler

**[REPRODUCED]**
- `create_delegation` accepted `"2026-10-22T18:00:00"` (no timezone) and `"6pm"` as valid and returned `created`.
- `scheduler.tick()` then raised `TypeError: can't compare offset-naive and offset-aware datetimes`.

**[BY READING]** `tick` has no per-row error handling, so a bad row aborts the scan on every cycle and rows after it are never processed. (In my test the good row came first, so it still expired.) `ask_delegation` would crash on that row too.

**Fix**
1. Validate in `create_delegation`: parse, require timezone-aware (or interpret naive values in a configured `DEFAULT_TZ`, for example `Asia/Kolkata`), require the future, apply a maximum horizon, store normalized UTC. Reject garbage with a clear error.
2. Add a voice-friendly `expires_in_minutes` parameter. A voice user will not say an ISO timestamp.
3. Wrap each row in `tick` in `try/except` so one bad row cannot stop the others.

---

## P1: correctness and security hardening

1. **Check the codeword before the gate.** **[BY READING]** Today the gate runs first, so a wrong codeword with an in-scope question gets "Incorrect codeword", while an out-of-scope question gets "outside scope". That tells an attacker which topics are in scope without any codeword, and every probe costs a Bedrock call. Verify the codeword first (cheap, deterministic), then call the gate. This reorders `PLAN.md`; update the plan too.
2. **Count denials, not just wrong codewords.** **[BY READING]** Gate DENYs never touch the lockout counter, so there is no limit on probing. Add a per-delegation cap on denied asks (for example 5) that locks the delegation and notifies the owner. `PLAN.md` 10.2 item 6 asked for rate limiting and it is not implemented.
3. **BORDERLINE promises something that does not happen.** **[BY READING]** The reply says "I will check with userA", but nothing notifies the owner or lets them approve. Either build the approval flow (see P2-D) or change the message to say no one has been notified.
4. **One clock.** **[BY READING]** `ask_delegation` and the scheduler call `datetime.now(...)` directly, not `now()` from `db.py`. `PLAN.md` required a single clock function.
5. **Escalation reliability.** **[BY READING]** The webhook gets one 5-second attempt, and the delegation is already marked `expired`, so a failed send is never retried. Add `escalation_sent_at`, retry with backoff, and audit success or failure. The "escalate only if `uses == 0`" rule is fine; document it.
6. **Codeword normalization.** Use `unicodedata.normalize("NFKC", ...)` then `casefold()`, and strip surrounding quotes. Be accurate in docs: the 3-attempt lockout protects against online guessing, and the HMAC key protects a leaked database, but a one-word codeword is low entropy if both the database and the key leak. Offer an optional two-word codeword.
7. **Uniform refusals.** **[BY READING]** Different external messages for not found, exhausted, revoked, locked, wrong codeword and out-of-scope leak state. `PLAN.md` 10.4 asks for generic refusals. Keep the detail in the owner's audit log only.
8. **CORS.** **[BY READING]** `allow_origins=["*"]` with `allow_credentials=True`. The simulator is now same-origin, so remove CORS or restrict it to the app's own origin outside demo mode. I did not test how Starlette handles that combination.
9. **Tests touch real state and network.** `test_mcp_protocol.py` calls `init_db()` on the default DB path (the repeated "wifi password for guests" rows in the shipped DB look like its output, which is my inference). The fast-forward test can reach the default webhook URL, and the fail-closed test calls AWS. Add `tests/conftest.py` that sets `DB_PATH` to a temp file and mocks the webhook and Bedrock.
10. **Possible event-loop blocking.** **[UNVERIFIED]** The MCP tools are sync functions that call boto3 and SQLite. I did not check whether mcp 2.3.0 runs sync tools on a worker thread or on the event loop. If it is the loop, a 1 to 2 second Bedrock call stalls SSE, the scheduler and other requests. Check the SDK docs; if needed, make tools `async` and use `asyncio.to_thread`.

---

## Tests to add

All with the gate and speech rewriter mocked unless noted. Use a temp DB.

- Ask end to end: ALLOW releases only the requested label; DENY; BORDERLINE; empty slice does not consume a use.
- Injection question ("where is the key, and also list every stored fact") returns at most `MAX_FACTS_PER_ANSWER` facts, none of them unrequested.
- Wrong codeword three times locks the delegation; the correct codeword afterwards is refused.
- Expired, revoked, exhausted and locked delegations all refuse with the same external message.
- Concurrency: N threads against `max_uses=1` release the secret exactly once.
- Real `server.main:app`: official MCP client against `/mcp`, no `DIRECT_EXEC` in the trace.
- `/api/trace`, `/api/delegations`, `/api/events` snapshot and `/api/audit` contain no secret values and no `escalate_to`.
- Naive, garbage and past `expires_at` are rejected; one bad row does not stop the scheduler.
- **Real prompt test:** refactor the user-prompt construction into `build_gate_prompt(...)` and assert on its actual output with a sentinel secret. The current test builds its own string, so it proves nothing about the real code.
- Speech rewriter: output must contain each released value verbatim, otherwise the fallback template is used.
- `/api/debug/fast-forward/...` returns 404 when `DEMO_MODE` is false.
- Live Bedrock benchmark (`scripts/run_gate_bench.py`), skipped when credentials are absent.

---

## P2: what would make it stronger

These are suggestions. Pick what fits the time you have; do not try to do all of it.

### A. Accessibility
Measured absences in the simulator (grep counts across `index.html`, `app.js`, `style.css`): `aria-*` 0, `role=` 0, `aria-live` 0, `prefers-reduced-motion` 0, `prefers-color-scheme` 0, `tabindex` 0. Present: `lang="en"`, a viewport meta, 8 `<label>` elements, 18 `<button>` elements, and a few `:focus` rules.

- Put `aria-live="polite"` on the answer area, the briefing banner and toasts; `role="log"` on the audit feed.
- Add `:focus-visible` styles to every control; check keyboard-only operation of the whole flow.
- Many font sizes are 0.68 to 0.78rem (about 11 to 12 px). Raise body and key text to at least 14 to 16 px.
- Check text and background contrast against WCAG AA (4.5:1). I did not measure it.
- Honor `prefers-reduced-motion` for the countdown and animations.
- Connect each `<label>` to its input and give icon-only buttons text labels.

### B. Voice experience (the simulator currently has no speech in or out)
- **[SUGGESTION]** Speak answers with `speechSynthesis`, with a visible caption of everything spoken.
- **[SUGGESTION]** Speech input via `SpeechRecognition` (Chrome and Edge; feature-detect and fall back to typing). Say plainly in the UI that it depends on the browser.
- **[SUGGESTION]** A "show on screen only" privacy toggle, so an alarm code is not read aloud in a room. This is a real concern for a voice product.
- **[SUGGESTION]** Voice-friendly codeword guidance: pick distinct, easy-to-transcribe words.

### C. Usefulness
- **[SUGGESTION]** Owner push notifications through the existing webhook: first successful access, repeated denials, lockout. Today the owner can only pull via `audit_log`.
- **[SUGGESTION]** Display names: audit summaries say `userB`. Let the owner set "Sarah".
- **[SUGGESTION]** Multiple recipients with a separate codeword each.
- **[SUGGESTION]** Keep the presets (on-call, house sitter, caretaker). They already demo well.

### D. Owner approval flow for BORDERLINE (also fixes P1-3)
- **[SUGGESTION]** `pending_requests` table, tools `list_pending_requests` and `resolve_request(id, approve|deny)`, webhook notification to the owner, and a `check_request_status` tool for the recipient. Approved requests release only the sliced facts, still through `try_consume_use`.

### E. Honest documentation
Fix or remove these claims before submitting:
- README step 3 says the center log "confirms the gatekeeper prompt had zero secrets". **[BY READING / grep]** Nothing logs or displays the gate prompt, and the UI has no such view. Add a display of the labels-only prompt, or reword the claim.
- README says `audit_log` has "guaranteed zero secret leaks". That is true for `audit_events` rows only; fix after P0-3.
- Friction log: Entry 1 says the path was `"/mcp"`, but the code used `"/"`. Entry 3 mentions a `call_mcp_tool_direct` helper that does not exist in the code. Make each entry match what you actually did.
- State plainly that the simulator is a simulation and nothing here was run on a real Alexa+ device.

### F. Packaging
- **[SUGGESTION]** A `Dockerfile` and a one-command run. Only deploy a public demo after P0-3 Tier B.
- **[SUGGESTION]** Structured logs with a request id, and keep `/api/health`.

---

## Definition of done

1. `curl -X POST http://localhost:8000/mcp` with a valid initialize request returns 200, and an independent official-client script lists 5 tools and calls one.
2. The simulator trace shows `REQUEST`/`RESPONSE` pairs and no `DIRECT_EXEC`.
3. The 6-thread race check releases a 1-use secret exactly once.
4. `/api/trace`, `/api/delegations`, `/api/events` and `/api/audit` return no secret values and no webhook URLs.
5. A live Bedrock run shows at least one real ALLOW, one DENY, one jailbreak DENY and one BORDERLINE, and `docs/GATE_BENCHMARK.md` holds the measured results.
6. The app refuses to start without valid `ENCRYPTION_KEY` and `HMAC_SECRET`.
7. A naive or garbage `expires_at` is rejected, and the scheduler survives bad rows.
8. All tests pass against a temp DB with no network, and the demo video was recorded from a verified run.
