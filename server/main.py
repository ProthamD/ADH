import os
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from mcp.server.mcpserver import MCPServer
from mcp.client.streamable_http import streamable_http_client
from mcp.client.session import ClientSession
from dotenv import load_dotenv

from server.store.db import (
    init_db,
    list_active_delegations,
    get_recent_audit_events,
    get_pending_briefings_for_recipient,
    mark_briefing_delivered,
    get_delegation,
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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("alexa-delegation-broker")

DEMO_MODE = os.environ.get("DEMO_MODE", "true").lower() in ("true", "1", "yes")
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))
BASE_URL = f"http://{HOST}:{PORT}"

# In-memory protocol trace ring buffer for the simulator's live JSON-RPC trace inspector
PROTOCOL_TRACE: List[Dict[str, Any]] = []

def record_trace(event_type: str, method: str, params: Any, result: Any = None, error: Any = None):
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "type": event_type,
        "method": method,
        "params": params,
        "result": result,
        "error": str(error) if error else None,
    }
    PROTOCOL_TRACE.append(entry)
    if len(PROTOCOL_TRACE) > 100:
        PROTOCOL_TRACE.pop(0)

# =====================================================================
# MCP Server Definition (Streamable HTTP, spec 2025-11-25+)
# =====================================================================
mcp = MCPServer("alexa-delegation-broker")

@mcp.tool()
def create_delegation(
    recipient: str,
    topic_desc: str,
    facts: List[Dict[str, str]],
    codeword: str,
    max_uses: int = 1,
    expires_at: Optional[str] = None,
    escalate_to: Optional[str] = None,
    owner: str = "userA",
) -> str:
    """
    Creates an encrypted, time-locked delegation. User A specifies what User B
    may ask about, labeled facts (secrets), a voice codeword, and expiry.
    """
    res = handle_create_delegation(
        recipient=recipient,
        topic_desc=topic_desc,
        facts=facts,
        codeword=codeword,
        max_uses=max_uses,
        expires_at=expires_at,
        escalate_to=escalate_to,
        owner=owner,
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
    Inquires against an active delegation. Evaluated via Stage 1 Blind Gatekeeper
    (Bedrock) and Stage 2 Vault with voice-normalized codeword verification and semantic slicing.
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
) -> str:
    """
    Queries the chronological audit trail for a delegation.
    Strictly authorized to the delegation owner only. Never reveals secrets.
    """
    res = handle_audit_log(
        delegation_id_or_name=delegation_id_or_owner,
        caller=caller,
    )
    return json.dumps(res, indent=2)

@mcp.tool()
def revoke_delegation(
    delegation_id: str,
    caller: str = "userA",
) -> str:
    """
    Instantly revokes an active delegation. Strictly owner authorized.
    """
    res = handle_revoke_delegation(
        delegation_id=delegation_id,
        caller=caller,
    )
    return json.dumps(res, indent=2)

@mcp.tool()
def check_scam_message(
    text: str,
) -> str:
    """
    Alexa+ voice security tool: evaluates suspicious incoming text or voice transcripts
    for scam/phishing indicators using Amazon Bedrock.
    """
    res = handle_check_scam_message(text)
    return json.dumps(res, indent=2)

# =====================================================================
# FastAPI Application & Lifespan
# =====================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialize database and start scheduler
    init_db()
    await scheduler.start()
    logger.info("Database initialized and scheduler loop active.")
    yield
    # Shutdown: stop scheduler
    await scheduler.stop()
    logger.info("Scheduler loop terminated.")

app = FastAPI(
    title="Alexa+ Delegation Broker",
    description="Self-Hosted Streamable HTTP MCP Server with AWS Bedrock Stage 1 Gatekeeper",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["mcp-session-id"],
)

# Mount MCP Starlette Streamable HTTP app at /mcp
mcp_starlette_app = mcp.streamable_http_app(streamable_http_path="/", stateless_http=True)
app.mount("/mcp", mcp_starlette_app)

# =====================================================================
# Client-side MCP Protocol Bridge
# =====================================================================
async def execute_via_mcp_client(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calls the local /mcp endpoint using the official MCP Python client over Streamable HTTP,
    capturing JSON-RPC traffic into the trace inspector.
    """
    mcp_url = f"{BASE_URL}/mcp"
    record_trace("REQUEST", f"tools/call -> {tool_name}", arguments)
    try:
        async with streamable_http_client(mcp_url) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                result = await session.call_tool(tool_name, arguments)
                content_text = result.content[0].text if result.content else "{}"
                parsed = json.loads(content_text)
                record_trace("RESPONSE", f"tools/call -> {tool_name}", arguments, result=parsed)
                return parsed
    except Exception as exc:
        logger.warning(f"MCP client call over HTTP encountered: {exc}. Executing direct tool handler fallback.")
        # Direct execution fallback ensures demo and simulator remain robust under local port bindings
        if tool_name == "create_delegation":
            res = handle_create_delegation(**arguments)
        elif tool_name == "ask_delegation":
            res = handle_ask_delegation(
                delegation_id_or_name=arguments.get("delegation_id_or_owner", ""),
                question=arguments.get("question", ""),
                codeword=arguments.get("codeword", ""),
                caller=arguments.get("caller", "userB"),
            )
        elif tool_name == "audit_log":
            res = handle_audit_log(
                delegation_id_or_name=arguments.get("delegation_id_or_owner", ""),
                caller=arguments.get("caller", "userA"),
            )
        elif tool_name == "revoke_delegation":
            res = handle_revoke_delegation(
                delegation_id=arguments.get("delegation_id", ""),
                caller=arguments.get("caller", "userA"),
            )
        elif tool_name == "check_scam_message":
            res = handle_check_scam_message(arguments.get("text", ""))
        else:
            res = {"error": f"Unknown tool: {tool_name}"}
        record_trace("DIRECT_EXEC", f"{tool_name}", arguments, result=res, error=str(exc))
        return res

# =====================================================================
# Pydantic Request Models for API Bridge
# =====================================================================
class CreateDelegationRequest(BaseModel):
    recipient: str = "userB"
    topic_desc: str
    facts: List[Dict[str, str]]
    codeword: str
    max_uses: int = 1
    expires_at: Optional[str] = None
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

class RevokeDelegationRequest(BaseModel):
    delegation_id: str
    caller: str = "userA"

class ScamCheckRequest(BaseModel):
    text: str

# =====================================================================
# Simulator API Routes
# =====================================================================
@app.post("/api/alexa/user-a/create")
async def api_create_delegation(req: CreateDelegationRequest):
    return await execute_via_mcp_client("create_delegation", req.model_dump())

@app.post("/api/alexa/user-a/audit")
async def api_audit_log(req: AuditLogRequest):
    return await execute_via_mcp_client("audit_log", req.model_dump())

@app.post("/api/alexa/user-a/revoke")
async def api_revoke_delegation(req: RevokeDelegationRequest):
    return await execute_via_mcp_client("revoke_delegation", req.model_dump())

@app.post("/api/alexa/user-b/ask")
async def api_ask_delegation(req: AskDelegationRequest):
    return await execute_via_mcp_client("ask_delegation", req.model_dump())

@app.post("/api/security/check-scam")
async def api_check_scam(req: ScamCheckRequest):
    return await execute_via_mcp_client("check_scam_message", req.model_dump())

@app.get("/api/delegations")
def api_list_delegations():
    return list_active_delegations()

@app.get("/api/audit")
def api_get_audit():
    return get_recent_audit_events(limit=50)

@app.get("/api/briefings/{recipient}")
def api_get_briefings(recipient: str):
    return get_pending_briefings_for_recipient(recipient)

@app.post("/api/briefings/{briefing_id}/dismiss")
def api_dismiss_briefing(briefing_id: int):
    mark_briefing_delivered(briefing_id)
    return {"status": "dismissed"}

@app.get("/api/trace")
def api_get_trace():
    return PROTOCOL_TRACE[-30:]

@app.post("/api/debug/fast-forward/{delegation_id}")
async def api_fast_forward(delegation_id: str):
    if not DEMO_MODE:
        raise HTTPException(status_code=404, detail="Fast-forward endpoint disabled when DEMO_MODE=false")
    success = await scheduler.fast_forward(delegation_id)
    if not success:
        raise HTTPException(status_code=404, detail="Delegation not found")
    return {"status": "fast_forwarded", "delegation_id": delegation_id}

@app.get("/api/health")
def api_health():
    bedrock_status = check_bedrock_connectivity()
    return {
        "status": "healthy",
        "mcp_endpoint": "/mcp",
        "demo_mode": DEMO_MODE,
        "bedrock": bedrock_status,
        "model": BEDROCK_MODEL_ID,
        "region": AWS_REGION,
    }

# =====================================================================
# Serve Frontend Simulator Static Files
# =====================================================================
simulator_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "simulator")
if not os.path.exists(simulator_dir):
    os.makedirs(simulator_dir, exist_ok=True)

@app.get("/")
def serve_index():
    index_file = os.path.join(simulator_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "Alexa+ Simulator frontend building..."}

app.mount("/", StaticFiles(directory=simulator_dir, html=True), name="static")
