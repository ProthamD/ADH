import os
import pytest
import uvicorn
import threading
import time
import json
from mcp.server.mcpserver import MCPServer
from mcp.client.streamable_http import streamable_http_client
from mcp.client.session import ClientSession
from server.main import mcp

@pytest.fixture(scope="module")
def running_mcp_server():
    from server.store.db import init_db
    init_db()
    app = mcp.streamable_http_app(streamable_http_path="/mcp", stateless_http=True)
    port = 8995
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    time.sleep(1.2) # Allow uvicorn to bind socket
    yield f"http://127.0.0.1:{port}/mcp"
    server.should_exit = True

@pytest.mark.asyncio
async def test_mcp_streamable_http_tools_discovery_and_call(running_mcp_server):
    url = running_mcp_server
    async with streamable_http_client(url) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            init_res = await session.initialize()
            assert init_res.server_info.name == "alexa-delegation-broker"

            # Discover tools
            tools_list = await session.list_tools()
            tool_names = [t.name for t in tools_list.tools]
            assert "create_delegation" in tool_names
            assert "ask_delegation" in tool_names
            assert "audit_log" in tool_names
            assert "revoke_delegation" in tool_names
            assert "check_scam_message" in tool_names

            # Test create_delegation tool call
            create_args = {
                "recipient": "userB",
                "topic_desc": "wifi password for guests",
                "facts": [{"label": "wifi code", "value": "Guest1234"}],
                "codeword": "starlight",
                "max_uses": 1,
            }
            res = await session.call_tool("create_delegation", create_args)
            content_text = res.content[0].text
            parsed = json.loads(content_text)
            assert parsed["status"] == "created"
            assert parsed["recipient"] == "userB"
            assert "delegation_id" in parsed
            del_id = parsed["delegation_id"]

            # Test revoke_delegation tool call
            revoke_res = await session.call_tool(
                "revoke_delegation",
                {"delegation_id": del_id, "caller": "userA"},
            )
            parsed_revoke = json.loads(revoke_res.content[0].text)
            assert parsed_revoke["status"] == "revoked"
