# Friction Log: Alexa+ Delegation Broker (MCP Server)

> **Hackathon Judging Note:** This log tracks concrete developer friction, SDK deprecations, breaking changes, and workarounds encountered while building the Alexa+ MCP Server and Streamable HTTP broker.

---

### Entry 1: MCP 2.x Python SDK Breaking Rename (`FastMCP` -> `MCPServer`)
- **Date & Timestamp:** 2026-10-22T08:52:00Z
- **Component / Tool:** `mcp` Python SDK (v2.3.0)
- **Task:** Creating an MCP server instance with Streamable HTTP support at `/mcp`.
- **Steps Taken:**
  1. Attempted `from mcp.server.fastmcp import FastMCP` as cited in legacy MCP tutorials and pre-2.0 documentation.
- **Expected:** `FastMCP` class available for initialization.
- **Actual:** `ModuleNotFoundError: No module named 'mcp.server.fastmcp'. This is mcp 2.x, where FastMCP was renamed to MCPServer (from mcp.server.mcpserver import MCPServer) and other APIs changed`.
- **Severity:** Medium (Blocking if following older tutorials).
- **Workaround:**
  Imported `from mcp.server.mcpserver import MCPServer`. Initialized server with `mcp = MCPServer("alexa-delegation-broker")` and used `mcp.streamable_http_app(streamable_http_path="/mcp")`.
- **Suggestion for SDK Maintainers:**
  Provide backward-compatibility alias or a deprecation warning instead of an immediate hard import error during major version transitions.

---

### Entry 2: Pydantic CamelCase vs SnakeCase in `InitializeResult`
- **Date & Timestamp:** 2026-10-22T08:54:15Z
- **Component / Tool:** `mcp.client.session.ClientSession` (v2.3.0)
- **Task:** Connecting to the Streamable HTTP endpoint using the official Python client.
- **Steps Taken:**
  1. Initialized client with `init_res = await session.initialize()`.
  2. Attempted to read server info via `init_res.serverInfo.name` matching the JSON-RPC spec field name.
- **Expected:** `init_res.serverInfo` attribute resolves or aliases the model field.
- **Actual:** `AttributeError: 'InitializeResult' object has no attribute 'serverInfo'. Did you mean: 'server_info'?`.
- **Severity:** Low.
- **Workaround:**
  Accessed `init_res.server_info.name` using Pythonic snake_case.
- **Suggestion for SDK Maintainers:**
  Add `__getattr__` mapping or `@property` aliases for camelCase JSON-RPC protocol keys to make client code intuitive across languages.

---

### Entry 3: Streamable HTTP Client Async TaskGroup Cleanup
- **Date & Timestamp:** 2026-10-22T08:56:30Z
- **Component / Tool:** `mcp.client.streamable_http.streamable_http_client`
- **Task:** Executing short-lived tool calls over Streamable HTTP from backend bridge routes.
- **Steps Taken:**
  1. Opened `async with streamable_http_client(url) as (read_stream, write_stream):`.
  2. Nested `async with ClientSession(read_stream, write_stream) as session:`.
- **Expected:** Seamless exit upon completing tool invocation.
- **Actual:** Anyio TaskGroup propagates internal termination notifications if session closure is not awaited gracefully before terminating the transport stream.
- **Severity:** Medium.
- **Workaround:**
  Structured helper `call_mcp_tool_direct` to cleanly manage the dual context managers and properly suppress normal session disconnection teardown signals.
- **Suggestion for SDK Maintainers:**
  Provide a high-level helper `execute_mcp_tool(url, tool_name, arguments)` that wraps session lifecycle and cleanup in one function.

---

### Entry 4: Bedrock Converse API Tool Specification Format
- **Date & Timestamp:** 2026-10-22T09:00:00Z
- **Component / Tool:** `boto3.client('bedrock-runtime').converse`
- **Task:** Forcing structured tool output for Stage 1 Blind Gatekeeper classification (`ALLOW` | `DENY` | `BORDERLINE`).
- **Steps Taken:**
  1. Configured `toolConfig` in `converse` with `toolChoice={"tool": {"name": "record_gate_decision"}}`.
- **Expected:** Standard JSON Schema supported directly.
- **Actual:** Bedrock runtime requires an exact nesting structure: `{"tools": [{"toolSpec": {"name": "...", "description": "...", "inputSchema": {"json": {...}}}}]}`, which differs from both Anthropic native format and OpenAI function schema.
- **Severity:** Medium.
- **Workaround:**
  Built a dedicated schema serializer adhering strictly to the `toolSpec.inputSchema.json` layout.
- **Suggestion for AWS / Bedrock:**
  Standardize tool calling parameter shapes across Bedrock SDKs or provide Pydantic model converters out of the box in boto3.

---

### Entry 5: Bedrock Model Version Deprecations & IAM Policy Enforcement
- **Date & Timestamp:** 2026-10-22T09:35:00Z
- **Component / Tool:** Amazon Bedrock Runtime (`converse` API)
- **Task:** Executing Stage 1 Blind Gatekeeper classification using standard baseline model IDs.
- **Steps Taken:**
  1. Configured `BEDROCK_MODEL_ID=anthropic.claude-3-haiku-20240307-v1:0` as originally documented in legacy guides.
  2. Invoked `client.converse(...)`.
- **Expected:** Converse API returns structured tool call output.
- **Actual:** `ResourceNotFoundException: This model version has reached the end of its life. Please refer to the AWS documentation for more details.`
- **Severity:** High (Breaking change in Bedrock foundation model lifecycle).
- **Workaround:**
  1. Migrated default model ID to `amazon.nova-micro-v1:0` (Amazon Nova family), which is active and supports fast, cost-effective inference and tool execution.
  2. Verified fail-closed security: when IAM permissions (`bedrock:InvokeModel`) are pending or missing, the Stage 1 Gatekeeper gracefully fails closed (returns `DENY` with full audit trace), preventing any authorization leaks.
- **Suggestion for AWS / Bedrock:**
  Provide automatic alias redirection (e.g. `anthropic.claude-haiku-latest` or `amazon.nova-micro-default`) so applications do not break abruptly when pinned minor model date snapshots reach retirement.
