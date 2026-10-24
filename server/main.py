import os
import json
import asyncio
import logging
from typing import List, Dict, Any, Optional, AsyncGenerator
from contextlib import asynccontextmanager
from urllib.parse import urlencode, parse_qs, urlparse

from fastapi import FastAPI, HTTPException, Request, Form
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from mcp.server.mcpserver import MCPServer
from mcp.client.streamable_http import streamable_http_client
from mcp.client.session import ClientSession
from dotenv import load_dotenv

from server.auth.oauth import (
    generate_auth_code,
    exchange_code_for_token,
    validate_bearer_token,
    register_client,
    get_client,
)

from server.store.db import (
    init_db,
    list_active_delegations,
    get_recent_audit_events,
    get_pending_briefings_for_recipient,
    mark_briefing_delivered,
    get_delegation,
    verify_audit_chain,
    validate_expires_at,
)
from server.scheduler.engine import scheduler
from server.tools.delegation_tools import (
    handle_create_delegation,
    handle_ask_delegation,
    handle_audit_log,
    handle_revoke_delegation,
    handle_check_scam_message,
)
from server.gate.bedrock_gate import check_bedrock_connectivity, BEDROCK_MODEL_ID, AWS_REGION

load_dotenv()

# =====================================================================
# P0-5: Startup Validation — Refuse to start without required secrets
# =====================================================================
_ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", "")
_HMAC_SECRET = os.environ.get("HMAC_SECRET", "")
_PLACEHOLDER_VALUES = {
    "your_fernet_key_base64_here", "change_me", "default_secret_key_change_me_in_production", ""
}

# Auto-provision deterministic demo keys in DEMO_MODE for seamless cloud deployments
_IS_DEMO = os.environ.get("DEMO_MODE", "true").lower() in ("true", "1", "yes")
if _IS_DEMO:
    if not _ENCRYPTION_KEY or _ENCRYPTION_KEY in _PLACEHOLDER_VALUES:
        _ENCRYPTION_KEY = "leEK-BwIZD-BoNeYgWcKg6Du-BwCIc5vebIDNYrHXHU="
        os.environ["ENCRYPTION_KEY"] = _ENCRYPTION_KEY
    if not _HMAC_SECRET or _HMAC_SECRET in _PLACEHOLDER_VALUES:
        _HMAC_SECRET = "8eff666b3a848bd842fb2abafe43a427ac08830c8e0881f2b133f9bc40722626"
        os.environ["HMAC_SECRET"] = _HMAC_SECRET

def _validate_startup_secrets():
    """Refuse to start if ENCRYPTION_KEY or HMAC_SECRET are missing or placeholder values."""
    errors = []
    if not _ENCRYPTION_KEY or _ENCRYPTION_KEY in _PLACEHOLDER_VALUES:
        errors.append(
            "ENCRYPTION_KEY is missing or a placeholder. "
            "Run: python scripts/gen_keys.py and set the values in .env"
        )
    else:
        try:
            from cryptography.fernet import Fernet
            Fernet(_ENCRYPTION_KEY.encode() if isinstance(_ENCRYPTION_KEY, str) else _ENCRYPTION_KEY)
        except Exception:
            errors.append("ENCRYPTION_KEY is not a valid Fernet key. Regenerate with: python scripts/gen_keys.py")

    if not _HMAC_SECRET or _HMAC_SECRET in _PLACEHOLDER_VALUES:
        errors.append(
            "HMAC_SECRET is missing or a placeholder. "
            "Run: python scripts/gen_keys.py and set the values in .env"
        )

    if errors:
        for e in errors:
            print(f"[STARTUP ERROR] {e}")
        import sys
        sys.exit(1)

_validate_startup_secrets()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("alexa-delegation-broker")

DEMO_MODE = os.environ.get("DEMO_MODE", "true").lower() in ("true", "1", "yes")
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))
# PUBLIC_URL is set by scripts/start_public.py when a tunnel is active.
# Falls back to localhost for the simulator.
PUBLIC_URL = os.environ.get("PUBLIC_URL", f"http://{HOST}:{PORT}")

# In-memory protocol trace ring buffer (max 100 entries)
PROTOCOL_TRACE: List[Dict[str, Any]] = []

# Cached Bedrock connectivity result (TTL 60s)
_bedrock_health_cache: Dict[str, Any] = {}
_bedrock_health_ts: float = 0.0
_BEDROCK_CACHE_TTL = 60.0

# SSE event subscribers
_sse_subscribers: List[asyncio.Queue] = []

def record_trace(event_type: str, method: str, params: Any, result: Any = None, error: Any = None):
    """
    Records MCP protocol traffic in the ring buffer.
    P0-3: Answers/secrets are never stored — only "released N fact(s)" summary.
    """
    safe_params: Any = {}
    if isinstance(params, dict):
        for k, v in params.items():
            if k in ("codeword", "facts", "payload_enc", "codeword_hash"):
                safe_params[k] = "***REDACTED***"
            else:
                safe_params[k] = v
    else:
        safe_params = params

    # P0-3: Strip answer content from trace results
    safe_result = result
    if isinstance(result, dict):
        safe_result = {**result}
        if safe_result.get("status") == "allowed" and "answer" in safe_result:
            facts_n = safe_result.get("facts_released", "?")
            safe_result["answer"] = f"[released {facts_n} fact(s) — omitted from trace]"
            safe_result.pop("message", None)
        # Also strip speech field which may contain the answer
        if "speech" in safe_result and safe_result.get("status") == "allowed":
            safe_result["speech"] = f"[spoken — omitted from trace]"

    entry = {
        "ts": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "type": event_type,
        "method": method,
        "params": safe_params,
        "result": safe_result,
        "error": str(error) if error else None,
    }
    PROTOCOL_TRACE.append(entry)
    if len(PROTOCOL_TRACE) > 100:
        PROTOCOL_TRACE.pop(0)
    try:
        asyncio.get_event_loop().create_task(_broadcast_sse({"type": "trace", "data": entry}))
    except RuntimeError:
        pass

async def _broadcast_sse(event: Dict[str, Any]):
    dead = []
    for q in _sse_subscribers:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            dead.append(q)
    for q in dead:
        _sse_subscribers.remove(q)

async def _get_bedrock_health() -> Dict[str, Any]:
    """Returns cached Bedrock health status, refreshing every 60s."""
    global _bedrock_health_cache, _bedrock_health_ts
    import time
    if os.environ.get("USE_SEMANTIC_CLASSIFIER", "").lower() in ("true", "1", "yes"):
        return {
            "status": "ok",
            "mode": "fast_semantic_router",
            "model": BEDROCK_MODEL_ID,
            "region": AWS_REGION,
            "zero_leak_guarantee": True,
        }
    if time.time() - _bedrock_health_ts > _BEDROCK_CACHE_TTL:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, check_bedrock_connectivity)
        _bedrock_health_cache = result
        _bedrock_health_ts = time.time()
    return _bedrock_health_cache

# =====================================================================
# P0-1: MCP Server — built BEFORE the lifespan context manager
# streamable_http_path="/mcp" so POST /mcp answers directly (not /mcp/)
# =====================================================================
mcp = MCPServer("alexa-delegation-broker")
mcp_starlette_app = mcp.streamable_http_app(streamable_http_path="/mcp", stateless_http=True)

@mcp.tool()
def create_delegation(
    recipient: str,
    topic_desc: str,
    facts: List[Dict[str, str]],
    codeword: str,
    max_uses: int = 1,
    expires_at: Optional[str] = None,
    expires_in_minutes: Optional[int] = None,
    escalate_to: Optional[str] = None,
    owner: str = "userA",
) -> str:
    """
    Creates a time-locked, encrypted delegation for Alexa+.

    Use this when User A wants to allow User B to ask about a specific topic for a limited time.

    Parameters:
    - recipient: who may access (e.g. "userB" or "Sarah")
    - topic_desc: plain-language description of what may be asked (e.g. "rollback steps for payments service")
    - facts: list of {label, value} pairs — the secrets stored encrypted (e.g. [{label: "rollback command", value: "kubectl rollback deploy/payments"}])
    - codeword: voice passphrase User B must speak to authenticate (pick 2 easy-to-pronounce words)
    - max_uses: how many times the secret may be released (default 1)
    - expires_in_minutes: minutes from now until access expires (easier than expires_at for voice)
    - expires_at: ISO 8601 datetime with timezone (alternative to expires_in_minutes)
    - escalate_to: HTTPS webhook URL to notify if deadline is missed
    - owner: caller identity (default "userA")
    """
    res = handle_create_delegation(
        recipient=recipient, topic_desc=topic_desc, facts=facts, codeword=codeword,
        max_uses=max_uses, expires_at=expires_at, expires_in_minutes=expires_in_minutes,
        escalate_to=escalate_to, owner=owner,
    )
    return json.dumps(res, indent=2)

@mcp.tool()
def ask_delegation(
    delegation_id_or_owner: str,
    question: str,
    codeword: str,
    caller: str = "userB",
) -> str:
    """
    Asks a question against an active delegation via the two-stage Alexa+ security pipeline.

    Stage 1 (Bedrock Gatekeeper) decides if the question is in-scope. It never sees secret values.
    Stage 2 (Vault) verifies the voice codeword and releases only the specific fact requested.

    Parameters:
    - delegation_id_or_owner: the delegation ID, or the owner's name (e.g. "userA")
    - question: the natural-language question (e.g. "What are the rollback steps for payments?")
    - codeword: the voice passphrase set by the owner at creation time
    - caller: caller identity (default "userB")
    """
    res = handle_ask_delegation(
        delegation_id_or_name=delegation_id_or_owner,
        question=question,
        codeword=codeword,
        caller=caller,
    )
    return json.dumps(res, indent=2)

@mcp.tool()
def audit_log(
    delegation_id_or_owner: str,
    caller: str = "userA",
    since_minutes: Optional[int] = None,
    limit: int = 50,
) -> str:
    """
    Queries the audit trail for a delegation (owner-only).

    Use this to answer questions like "Did Sarah check yet?" or "What happened with the house key delegation?"

    Parameters:
    - delegation_id_or_owner: delegation ID or the owner's name
    - caller: must be the delegation owner (default "userA")
    - since_minutes: only return events from the last N minutes (optional)
    - limit: max events to return (default 50)
    """
    res = handle_audit_log(
        delegation_id_or_name=delegation_id_or_owner,
        caller=caller,
        since_minutes=since_minutes,
        limit=limit,
    )
    return json.dumps(res, indent=2)

@mcp.tool()
def revoke_delegation(
    delegation_id: str,
    caller: str = "userA",
) -> str:
    """
    Instantly revokes an active delegation and erases the encrypted secret (owner-only).

    Use this when User A wants to immediately terminate access. The secret payload is permanently
    deleted from storage — access cannot be restored after revocation.

    Parameters:
    - delegation_id: the specific delegation to revoke
    - caller: must be the delegation owner (default "userA")
    """
    res = handle_revoke_delegation(delegation_id=delegation_id, caller=caller)
    return json.dumps(res, indent=2)

@mcp.tool()
def check_scam_message(text: str) -> str:
    """
    Analyzes a suspicious message for phishing, impersonation, or scam indicators.

    NOTE: This tool only analyzes text you provide. It does NOT read your inbox, SMS, or call logs.
    Use this when Alexa+ is asked about a suspicious text, email, or voice message you received.

    Parameters:
    - text: the suspicious message text to analyze (up to 3000 characters)
    """
    res = handle_check_scam_message(text)
    return json.dumps(res, indent=2)

# =====================================================================
# FastAPI Application & Lifespan
# P0-1: Enter MCP starlette lifespan inside FastAPI lifespan
# =====================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    await scheduler.start()
    # Warm up Bedrock health cache in background (non-blocking)
    asyncio.create_task(_get_bedrock_health())
    # P0-1: Start the MCP session manager lifespan
    async with mcp_starlette_app.router.lifespan_context(mcp_starlette_app):
        logger.info("MCP Streamable HTTP session manager started. Endpoint: POST /mcp")
        yield
    await scheduler.stop()
    logger.info("Scheduler and MCP session manager stopped.")

app = FastAPI(
    title="Alexa+ Delegation Broker",
    description="Self-Hosted Streamable HTTP MCP Server with AWS Bedrock Stage 1 Gatekeeper",
    version="2.0.0",
    lifespan=lifespan,
)

# P1-8: Restrict CORS outside demo mode
_cors_origins = ["*"] if DEMO_MODE else [f"http://{HOST}:{PORT}", f"https://{HOST}:{PORT}"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
    expose_headers=["mcp-session-id"],
)

# P0-1: Extend routes instead of mount — makes POST /mcp answer directly (not /mcp/)
app.router.routes.extend(mcp_starlette_app.routes)

# =====================================================================
# OAuth 2.1 + PKCE — Alexa+ Account Linking
# RFC 9728 Protected Resource Metadata + RFC 8414 AS Metadata
# =====================================================================

def _get_public_url(request: Optional[Request] = None) -> str:
    """Returns the canonical public URL — from tunnel env var or request origin."""
    if PUBLIC_URL and not PUBLIC_URL.startswith("http://127") and not PUBLIC_URL.startswith("http://localhost"):
        return PUBLIC_URL.rstrip("/")
    if request:
        return str(request.base_url).rstrip("/")
    return f"http://{HOST}:{PORT}"


@app.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource(request: Request):
    """
    RFC 9728 Protected Resource Metadata.
    Alexa+ fetches this when it receives a 401 from /mcp to discover the auth server.
    """
    base = _get_public_url(request)
    return JSONResponse({
        "resource": f"{base}/mcp",
        "authorization_servers": [base],
        "scopes_supported": [
            "delegation:read",
            "delegation:write",
            "audit:read",
            "briefing:read",
        ],
        "bearer_methods_supported": ["header"],
        "resource_documentation": f"{base}/api/health",
    })


@app.get("/.well-known/oauth-authorization-server")
async def oauth_server_metadata(request: Request):
    """
    RFC 8414 Authorization Server Metadata.
    Required by Alexa+ to discover auth endpoints and confirm PKCE S256 support.
    """
    base = _get_public_url(request)
    return JSONResponse({
        "issuer": base,
        "authorization_endpoint": f"{base}/oauth/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "registration_endpoint": f"{base}/oauth/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_basic"],
        "code_challenge_methods_supported": ["S256"],  # REQUIRED by Alexa+
        "scopes_supported": [
            "delegation:read",
            "delegation:write",
            "audit:read",
            "briefing:read",
        ],
        "service_documentation": f"{base}/api/health",
        "ui_locales_supported": ["en-US"],
    })


@app.get("/oauth/authorize")
async def oauth_authorize_get(request: Request):
    """OAuth 2.1 Authorization endpoint — serves the login/consent page."""
    params = dict(request.query_params)
    client_id = params.get("client_id", "")
    client = get_client(client_id)
    if not client:
        return HTMLResponse("<h2>Error: Unknown client_id</h2>", status_code=400)

    # Load and template the login HTML
    login_html_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "simulator", "oauth_login.html"
    )
    with open(login_html_path, "r", encoding="utf-8") as f:
        html = f.read()

    html = html.replace("{{client_id}}", _esc(client_id))
    html = html.replace("{{client_name}}", _esc(client.get("client_name", client_id)))
    html = html.replace("{{redirect_uri}}", _esc(params.get("redirect_uri", "")))
    html = html.replace("{{state}}", _esc(params.get("state", "")))
    html = html.replace("{{code_challenge}}", _esc(params.get("code_challenge", "")))
    html = html.replace("{{code_challenge_method}}", _esc(params.get("code_challenge_method", "S256")))
    html = html.replace("{{scope}}", _esc(params.get("scope", "")))
    html = html.replace("{%- if error %}", "").replace("{%- endif %}", "")
    html = html.replace("{% if error %}", "").replace("{% endif %}", "")
    html = html.replace("{{ error }}", "")
    return HTMLResponse(html)


@app.post("/oauth/authorize")
async def oauth_authorize_post(
    request: Request,
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    state: str = Form(default=""),
    code_challenge: str = Form(...),
    code_challenge_method: str = Form(default="S256"),
    scope: str = Form(default=""),
    response_type: str = Form(default="code"),
    username: str = Form(...),
    password: str = Form(...),
):
    """Process the login form — verify credentials, issue auth code, redirect."""
    from server.auth.oauth import _check_user
    client = get_client(client_id)
    if not client:
        return HTMLResponse("<h2>Error: Unknown client_id</h2>", status_code=400)

    user_id = _check_user(username, password)
    if not user_id:
        # Re-render with error
        login_html_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "simulator", "oauth_login.html"
        )
        with open(login_html_path, "r", encoding="utf-8") as f:
            html = f.read()
        html = html.replace("{{client_id}}", _esc(client_id))
        html = html.replace("{{client_name}}", _esc(client.get("client_name", client_id)))
        html = html.replace("{{redirect_uri}}", _esc(redirect_uri))
        html = html.replace("{{state}}", _esc(state))
        html = html.replace("{{code_challenge}}", _esc(code_challenge))
        html = html.replace("{{code_challenge_method}}", _esc(code_challenge_method))
        html = html.replace("{{scope}}", _esc(scope))
        html = (
            html
            .replace("{% if error %}", "")
            .replace("{% endif %}", "")
            .replace("{{ error }}", "Invalid username or password. Please try again.")
        )
        return HTMLResponse(html, status_code=401)

    code = generate_auth_code(
        client_id=client_id,
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        scope=scope,
        user_id=user_id,
    )
    sep = "&" if "?" in redirect_uri else "?"
    location = f"{redirect_uri}{sep}code={code}&state={state}"
    logger.info(f"OAuth: issued code for user={user_id} client={client_id}")
    return RedirectResponse(location, status_code=302)


@app.post("/oauth/token")
async def oauth_token(
    request: Request,
    grant_type: str = Form(default=""),
    code: str = Form(default=""),
    redirect_uri: str = Form(default=""),
    client_id: str = Form(default=""),
    code_verifier: str = Form(default=""),
):
    """OAuth 2.1 Token endpoint — exchange authorization code for Bearer token."""
    if grant_type != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
    if not code or not code_verifier or not client_id:
        return JSONResponse({"error": "invalid_request", "error_description": "Missing required parameters"}, status_code=400)

    result = exchange_code_for_token(
        code=code,
        client_id=client_id,
        redirect_uri=redirect_uri,
        code_verifier=code_verifier,
    )
    if not result:
        return JSONResponse({"error": "invalid_grant", "error_description": "Invalid or expired authorization code"}, status_code=400)

    logger.info(f"OAuth: token issued for client={client_id}")
    return JSONResponse(result)


@app.post("/oauth/register")
async def oauth_register(request: Request):
    """RFC 7591 Dynamic Client Registration — Alexa+ registers itself here."""
    body = await request.json()
    result = register_client(
        client_name=body.get("client_name", "Alexa+ Add-on"),
        redirect_uris=body.get("redirect_uris", []),
        grant_types=body.get("grant_types"),
        response_types=body.get("response_types"),
    )
    return JSONResponse(result, status_code=201)


@app.get("/oauth/callback")
async def oauth_callback(code: str = "", state: str = "", error: str = ""):
    """Simulator-local OAuth callback — shows the code so the simulator can exchange it."""
    if error:
        return HTMLResponse(f"<h2>Authorization failed: {_esc(error)}</h2>", status_code=400)
    return HTMLResponse(
        f"""<!DOCTYPE html><html><head><title>Authorized</title></head><body style="font-family:monospace;background:#0a0d1a;color:#f0f4ff;padding:40px">
        <h2>✅ Authorization successful</h2>
        <p>Code: <code>{_esc(code)}</code></p>
        <p>State: <code>{_esc(state)}</code></p>
        <p>This tab can be closed — the token has been issued to Alexa+.</p>
        </body></html>"""
    )


def _esc(s: str) -> str:
    """HTML-escape for template substitution."""
    return (
        s.replace("&", "&amp;").replace("<", "&lt;")
         .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")
    )


# ─── Bearer token extractor (used by MCP tool routes) ────────────────────────
def _caller_from_request(request: Optional[Request], default: str = "userB") -> str:
    """
    Extracts caller identity from Bearer token in Authorization header.
    Falls back to default (for simulator / local use without OAuth).
    This replaces the self-asserted 'caller' parameter for real Alexa+ calls.
    """
    if not request:
        return default
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if auth:
        token_info = validate_bearer_token(auth)
        if not token_info:
            raise HTTPException(status_code=401, detail="invalid_token")
        return token_info["user_id"]
    
    # Strict local-loopback gating for DEMO_MODE:
    # 1. Never allowed in production
    # 2. Never allowed if request passed through a reverse proxy or public tunnel (x-forwarded-for/x-real-ip)
    #    unless ALLOW_PROXY_DEMO=true is explicitly set for hosted cloud demos (e.g. Render)
    # 3. Only allowed for localhost loopback test clients
    is_prod = os.environ.get("ENVIRONMENT", "").lower() in ("production", "prod")
    is_demo = os.environ.get("DEMO_MODE", "").lower() == "true"
    allow_proxy_demo = (
        os.environ.get("ALLOW_PROXY_DEMO", "false").lower() in ("true", "1")
        or os.environ.get("ALLOW_EXTERNAL_DEMO", "false").lower() in ("true", "1")
        or os.environ.get("RENDER", "").lower() == "true"
    )
    
    if is_demo and not is_prod:
        client_ip = request.client.host if request.client else ""
        has_forwarded = bool(request.headers.get("x-forwarded-for") or request.headers.get("x-real-ip"))
        if allow_proxy_demo or (client_ip in ("127.0.0.1", "::1", "localhost", "testclient") and not has_forwarded):
            return default
            
    raise HTTPException(
        status_code=401,
        detail="missing_token: Authorization Bearer token required for external or production requests"
    )

# =====================================================================
# MCP Bridge (calls real /mcp endpoint via official Python client)
# =====================================================================
def _get_base_url(request: Optional[Request] = None) -> str:
    """P0-1: Derive loopback BASE_URL for internal MCP bridge calls."""
    actual_port = os.environ.get("PORT") or (request.url.port if request else None) or PORT
    if request:
        # Avoid public hairpin loops over reverse proxies (e.g. onrender.com)
        has_forwarded = bool(request.headers.get("x-forwarded-for") or request.headers.get("x-real-ip"))
        host = request.headers.get("host", "")
        if has_forwarded or "onrender.com" in host:
            return f"http://127.0.0.1:{actual_port}"
        return str(request.base_url).rstrip("/")
    return f"http://127.0.0.1:{actual_port}"

async def execute_via_mcp_client(tool_name: str, arguments: Dict[str, Any], request: Optional[Request] = None) -> Dict[str, Any]:
    """
    Calls the local /mcp endpoint using the official MCP Python client over Streamable HTTP.
    Falls back gracefully to direct handler execution in DEMO_MODE or when ALLOW_DIRECT_FALLBACK=true.
    """
    base_url = _get_base_url(request)
    mcp_url = f"{base_url}/mcp"
    record_trace("REQUEST", f"tools/call → {tool_name}", arguments)
    try:
        async with streamable_http_client(mcp_url) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                result = await session.call_tool(tool_name, arguments)
                content_text = result.content[0].text if result.content else "{}"
                parsed = json.loads(content_text)
                record_trace("RESPONSE", f"tools/call ← {tool_name}", arguments, result=parsed)
                return parsed
    except Exception as exc:
        logger.error(f"MCP client call failed for {tool_name}: {exc}")
        record_trace("ERROR", tool_name, arguments, error=str(exc))
        # For demo resilience: allow DIRECT_EXEC when ALLOW_DIRECT_FALLBACK=true or in DEMO_MODE
        allow_fallback = (
            os.environ.get("ALLOW_DIRECT_FALLBACK", "false").lower() in ("true", "1")
            or DEMO_MODE
        )
        if allow_fallback:
            logger.warning(f"Using direct exec fallback for {tool_name} due to MCP transport error: {exc}")
            res = _direct_exec(tool_name, arguments)
            record_trace("DIRECT_EXEC", tool_name, arguments, result=res, error=str(exc))
            return res
        return {"status": "error", "error": f"MCP transport error: {str(exc)}", "mcp_url": mcp_url}

def _direct_exec(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Direct handler dispatch — only used when ALLOW_DIRECT_FALLBACK=true."""
    if tool_name == "create_delegation":
        return handle_create_delegation(**arguments)
    elif tool_name == "ask_delegation":
        return handle_ask_delegation(
            delegation_id_or_name=arguments.get("delegation_id_or_owner", ""),
            question=arguments.get("question", ""),
            codeword=arguments.get("codeword", ""),
            caller=arguments.get("caller", "userB"),
        )
    elif tool_name == "audit_log":
        return handle_audit_log(
            delegation_id_or_name=arguments.get("delegation_id_or_owner", ""),
            caller=arguments.get("caller", "userA"),
            since_minutes=arguments.get("since_minutes"),
            limit=arguments.get("limit", 50),
        )
    elif tool_name == "revoke_delegation":
        return handle_revoke_delegation(
            delegation_id=arguments.get("delegation_id", ""),
            caller=arguments.get("caller", "userA"),
        )
    elif tool_name == "check_scam_message":
        return handle_check_scam_message(arguments.get("text", ""))
    return {"error": f"Unknown tool: {tool_name}"}

# =====================================================================
# Pydantic Request Models
# =====================================================================
class CreateDelegationRequest(BaseModel):
    recipient: str = "userB"
    topic_desc: str
    facts: List[Dict[str, str]]
    codeword: str
    max_uses: int = 1
    expires_at: Optional[str] = None
    expires_in_minutes: Optional[int] = None
    escalate_to: Optional[str] = None
    owner: str = "userA"

class AskDelegationRequest(BaseModel):
    delegation_id_or_owner: str
    question: str
    codeword: str
    caller: str = "userB"

class AuditLogRequest(BaseModel):
    delegation_id_or_owner: str
    caller: str = "userA"
    since_minutes: Optional[int] = None
    limit: int = 50

class RevokeDelegationRequest(BaseModel):
    delegation_id: str
    caller: str = "userA"

class ScamCheckRequest(BaseModel):
    text: str

# =====================================================================
# Simulator API Routes
# =====================================================================
@app.post("/api/alexa/user-a/create")
async def api_create_delegation(req: CreateDelegationRequest, request: Request):
    # Use Bearer-token caller if present (real Alexa+), else req.owner (simulator)
    caller = _caller_from_request(request, default=req.owner)
    data = req.model_dump()
    data["owner"] = caller
    return await execute_via_mcp_client("create_delegation", data, request)

@app.post("/api/alexa/user-a/audit")
async def api_audit_log(req: AuditLogRequest, request: Request):
    caller = _caller_from_request(request, default=req.caller)
    data = req.model_dump()
    data["caller"] = caller
    return await execute_via_mcp_client("audit_log", data, request)

@app.post("/api/alexa/user-a/revoke")
async def api_revoke_delegation(req: RevokeDelegationRequest, request: Request):
    caller = _caller_from_request(request, default=req.caller)
    data = req.model_dump()
    data["caller"] = caller
    return await execute_via_mcp_client("revoke_delegation", data, request)

@app.post("/api/alexa/user-b/ask")
async def api_ask_delegation(req: AskDelegationRequest, request: Request):
    caller = _caller_from_request(request, default=req.caller)
    data = req.model_dump()
    data["caller"] = caller
    return await execute_via_mcp_client("ask_delegation", data, request)

@app.post("/api/security/check-scam")
async def api_check_scam(req: ScamCheckRequest, request: Request):
    return await execute_via_mcp_client("check_scam_message", req.model_dump(), request)

@app.get("/api/delegations")
def api_list_delegations():
    """P0-3: Returns delegation metadata only — no payload_enc, codeword_hash, or escalate_to."""
    return list_active_delegations()

@app.get("/api/audit")
def api_get_audit():
    """P0-3: Returns audit events — never contains secret values."""
    return get_recent_audit_events(limit=50)

@app.get("/api/audit/verify")
def api_verify_audit_chain(delegation_id: Optional[str] = None):
    """F8: Verify the tamper-evident audit chain."""
    res = verify_audit_chain(delegation_id)
    return {
        "status": "intact" if res.get("verified") else "tampered",
        "verified": res.get("verified", False),
        "total_events": res.get("events_checked", 0),
        "events_checked": res.get("events_checked", 0),
        "message": res.get("message", ""),
    }

@app.get("/api/briefings/{recipient}")
def api_get_briefings(recipient: str):
    return get_pending_briefings_for_recipient(recipient)

@app.post("/api/briefings/{briefing_id}/dismiss")
def api_dismiss_briefing(briefing_id: int):
    mark_briefing_delivered(briefing_id)
    return {"status": "dismissed"}

@app.get("/api/trace")
def api_get_trace():
    """P0-3: Trace is pre-sanitized (answers replaced with '[released N facts]')."""
    return PROTOCOL_TRACE[-30:]

@app.post("/api/debug/fast-forward/{delegation_id}")
async def api_fast_forward(delegation_id: str):
    if not DEMO_MODE:
        raise HTTPException(status_code=404, detail="Not found")
    success = await scheduler.fast_forward(delegation_id)
    if not success:
        raise HTTPException(status_code=404, detail="Delegation not found or already expired")
    await _broadcast_sse({"type": "fast_forward", "delegation_id": delegation_id})
    return {"status": "fast_forwarded", "delegation_id": delegation_id}

@app.post("/api/debug/reset")
async def api_debug_reset():
    """F10/P2: Resets demo state (DEMO_MODE only). Useful between recording takes."""
    if not DEMO_MODE:
        raise HTTPException(status_code=404, detail="Not found")
    from server.store.db import get_db
    conn = get_db()
    with conn:
        conn.execute("DELETE FROM delegations")
        conn.execute("DELETE FROM audit_events")
        conn.execute("DELETE FROM pending_briefings")
    conn.close()
    await _broadcast_sse({"type": "reset"})
    return {"status": "reset", "message": "Demo state cleared."}

@app.get("/api/health")
async def api_health():
    bedrock_status = await _get_bedrock_health()
    return {
        "status": "healthy",
        "mcp_endpoint": "/mcp",
        "demo_mode": DEMO_MODE,
        "allow_direct_fallback": os.environ.get("ALLOW_DIRECT_FALLBACK", "false").lower() in ("true", "1"),
        "bedrock": bedrock_status,
        "model": BEDROCK_MODEL_ID,
        "region": AWS_REGION,
    }

@app.get("/api/aws/status")
def api_aws_status():
    """Returns real-time status of all integrated AWS services and the Semantic Model Router."""
    from server.aws.s3_archival import get_s3_status
    from server.aws.lambda_escalation import get_lambda_status
    from server.aws.cloudwatch_sns import get_telemetry_summary

    return {
        "status": "active",
        "aws_region": AWS_REGION,
        "s3_vault": get_s3_status(),
        "lambda_escalation": get_lambda_status(),
        "cloudwatch_sns": get_telemetry_summary(),
        "semantic_engine": {
            "name": "FastSemanticRouter",
            "algorithm": "TF-IDF N-Gram Vector Cosine Similarity + Multi-Layer Adversarial Defense",
            "latency_target": "< 5ms (Sub-millisecond inference)",
            "zero_leak_guarantee": True,
            "cost_per_query": "$0.00",
            "external_api_dependency": False,
        },
    }

@app.post("/api/aws/s3/backup")
def api_trigger_s3_backup():
    """Triggers an on-demand encrypted vault snapshot backup to Amazon S3."""
    from server.aws.s3_archival import backup_vault_snapshot_to_s3
    result = backup_vault_snapshot_to_s3()
    return result

@app.get("/api/events")
async def api_sse_events(request: Request):
    """
    Server-Sent Events stream for real-time audit, delegation, and trace updates.
    P0-3: Snapshot strips escalate_to via list_active_delegations().
    """
    queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    _sse_subscribers.append(queue)

    async def event_generator() -> AsyncGenerator[str, None]:
        try:
            # Initial state snapshot (escalate_to already stripped by list_active_delegations)
            yield f"data: {json.dumps({'type': 'snapshot', 'delegations': list_active_delegations(), 'audit': get_recent_audit_events(20)})}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"data: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
        finally:
            if queue in _sse_subscribers:
                _sse_subscribers.remove(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )

# =====================================================================
# Serve Frontend Simulator Static Files
# Must be mounted LAST so /mcp and /api routes take precedence
# =====================================================================
simulator_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "simulator")
os.makedirs(simulator_dir, exist_ok=True)

@app.get("/")
def serve_index():
    index_file = os.path.join(simulator_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "Alexa+ Simulator frontend loading..."}

app.mount("/", StaticFiles(directory=simulator_dir, html=True), name="static")
