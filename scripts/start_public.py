#!/usr/bin/env python3
"""
scripts/start_public.py — Start the Delegation Broker with a public HTTPS tunnel
================================================================================
Required by Alexa+ MCP Add-on: the server must be reachable via a public URL.

Usage:
    python scripts/start_public.py [--port 8000] [--ngrok-token YOUR_TOKEN]

What it does:
1. Starts the FastAPI/uvicorn server on localhost
2. Opens a cloudflared (preferred) or ngrok tunnel to get a public HTTPS URL
3. Prints the Alexa+ Add-on registration URLs and curl commands
4. Writes the public URL to .env as PUBLIC_URL so the OAuth endpoints use it

Prerequisites (choose one):
  A) cloudflared (free, no account needed for quick tunnels):
       winget install Cloudflare.cloudflared
       or download from https://github.com/cloudflare/cloudflared/releases

  B) ngrok (free account needed):
       pip install pyngrok
       Set NGROK_AUTHTOKEN in .env or pass --ngrok-token

Alexa+ Add-on Registration:
  After running this script, visit:
    https://developer.amazon.com/alexa/console  → Add-ons → New Add-on
  And use the URLs printed below.
"""

import os
import sys
import time
import signal
import subprocess
import threading
import argparse
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv, set_key
load_dotenv(PROJECT_ROOT / ".env")


def _start_uvicorn(port: int) -> subprocess.Popen:
    """Start uvicorn in a subprocess."""
    cmd = [
        sys.executable, "-m", "uvicorn",
        "server.main:app",
        "--host", "127.0.0.1",
        "--port", str(port),
        "--log-level", "info",
    ]
    print(f"  [server] Starting uvicorn on port {port}...")
    proc = subprocess.Popen(cmd, cwd=str(PROJECT_ROOT))
    time.sleep(2.5)  # wait for startup
    return proc


def _try_cloudflared(port: int):
    """Try to open a cloudflared quick tunnel. Returns public URL or None."""
    try:
        import re
        proc = subprocess.Popen(
            ["cloudflared", "tunnel", "--url", f"http://localhost:{port}", "--no-autoupdate"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        # Cloudflared prints the URL to stderr within ~5s
        for _ in range(30):
            line = proc.stdout.readline()
            if not line:
                time.sleep(0.3)
                continue
            match = re.search(r"https://[a-z0-9\-]+\.trycloudflare\.com", line)
            if match:
                return match.group(0), proc
        proc.terminate()
        return None, None
    except FileNotFoundError:
        return None, None


def _try_ngrok(port: int, token: str = None):
    """Try pyngrok. Returns public URL or None."""
    try:
        from pyngrok import ngrok, conf
        if token:
            conf.get_default().auth_token = token
        elif os.environ.get("NGROK_AUTHTOKEN"):
            conf.get_default().auth_token = os.environ["NGROK_AUTHTOKEN"]
        tunnel = ngrok.connect(port, "http")
        public_url = tunnel.public_url.replace("http://", "https://")
        return public_url, None  # pyngrok manages its own process
    except Exception as e:
        print(f"  [ngrok] Failed: {e}")
        return None, None


def _print_banner(public_url: str, port: int):
    """Print registration instructions."""
    sep = "=" * 72

    print(f"\n{sep}")
    print("  🚀  ALEXA+ DELEGATION BROKER — PUBLIC ENDPOINT ACTIVE")
    print(sep)
    print(f"\n  Public MCP URL:      {public_url}/mcp")
    print(f"  Simulator (local):   http://localhost:{port}")
    print(f"\n  OAuth 2.1 Endpoints:")
    print(f"    Authorization:     {public_url}/oauth/authorize")
    print(f"    Token:             {public_url}/oauth/token")
    print(f"    Client Register:   {public_url}/oauth/register")
    print(f"    PRM (RFC 9728):    {public_url}/.well-known/oauth-protected-resource")
    print(f"    AS Metadata:       {public_url}/.well-known/oauth-authorization-server")
    print(f"\n{sep}")
    print("  📋  Alexa+ Add-on Registration Steps:")
    print(f"  1. Go to: https://developer.amazon.com/alexa/console → Add-ons")
    print(f"  2. Click 'New Add-on' → select 'MCP Server'")
    print(f"  3. MCP Server URL:   {public_url}/mcp")
    print(f"  4. Auth Type:        OAuth 2.1")
    print(f"  5. Auth URL:         {public_url}/oauth/authorize")
    print(f"  6. Token URL:        {public_url}/oauth/token")
    print(f"  7. Client ID:        alexa-simulator")
    print(f"  8. Register Two Alexa+ connections:")
    print(f"     • Owner role:     log in as userA  (creates delegations)")
    print(f"     • Recipient role: log in as userB  (asks questions)")
    print(f"\n  🔑  Default credentials (change in .env):")
    print(f"     userA password:   {os.environ.get('OWNER_PASSWORD', 'owner-alexa-pass')}")
    print(f"     userB password:   {os.environ.get('RECIPIENT_PASSWORD', 'recipient-alexa-pass')}")
    print(f"\n  🧪  Quick MCP test:")
    print(f"     curl -X POST {public_url}/mcp \\")
    print(f'       -H "Content-Type: application/json" \\')
    print(f'       -d \'{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2024-11-05","capabilities":{{}},"clientInfo":{{"name":"test","version":"1"}}}}}}\' ')
    print(f"\n{sep}\n")

    # Write to .env
    env_path = PROJECT_ROOT / ".env"
    set_key(str(env_path), "PUBLIC_URL", public_url)
    print(f"  ✅  PUBLIC_URL written to .env → {public_url}")
    print(f"\n  Press Ctrl+C to stop the server and tunnel.\n")

    # Also write an add-on manifest JSON for convenience
    manifest = {
        "name": "Alexa+ Delegation Broker",
        "description": "Secure, time-limited secret delegation via Streamable HTTP MCP",
        "mcp_server_url": f"{public_url}/mcp",
        "auth": {
            "type": "oauth2_pkce",
            "authorization_endpoint": f"{public_url}/oauth/authorize",
            "token_endpoint": f"{public_url}/oauth/token",
            "client_id": "alexa-simulator",
            "scopes": ["delegation:read", "delegation:write", "audit:read"],
            "pkce_required": True,
            "code_challenge_methods_supported": ["S256"],
        },
        "roles": {
            "owner": {"user": "userA", "description": "Creates time-locked delegations"},
            "recipient": {"user": "userB", "description": "Asks questions via voice codeword"},
        },
    }
    manifest_path = PROJECT_ROOT / "docs" / "alexa_addon_manifest.json"
    manifest_path.parent.mkdir(exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"  📄  Add-on manifest saved → docs/alexa_addon_manifest.json")


def main():
    parser = argparse.ArgumentParser(description="Start Delegation Broker with public tunnel")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--ngrok-token", type=str, default=None)
    parser.add_argument("--no-seed", action="store_true", help="Skip seeding demo data")
    args = parser.parse_args()

    port = args.port
    server_proc = None
    tunnel_proc = None

    def _cleanup(sig=None, frame=None):
        print("\n  [shutdown] Stopping server and tunnel...")
        if server_proc:
            server_proc.terminate()
        if tunnel_proc:
            tunnel_proc.terminate()
        try:
            from pyngrok import ngrok
            ngrok.kill()
        except Exception:
            pass
        sys.exit(0)

    signal.signal(signal.SIGINT, _cleanup)
    signal.signal(signal.SIGTERM, _cleanup)

    print("\n  [setup] Seeding demo data...")
    if not args.no_seed:
        subprocess.run([sys.executable, "scripts/seed_demo.py", "--reset"], cwd=str(PROJECT_ROOT))

    server_proc = _start_uvicorn(port)

    print("  [tunnel] Trying cloudflared...")
    public_url, tunnel_proc = _try_cloudflared(port)

    if not public_url:
        print("  [tunnel] cloudflared not found, trying ngrok...")
        public_url, tunnel_proc = _try_ngrok(port, args.ngrok_token)

    if not public_url:
        print("\n  ❌  No tunnel available. Install cloudflared or configure ngrok.")
        print("     cloudflared: winget install Cloudflare.cloudflared")
        print("     ngrok:       pip install pyngrok  +  set NGROK_AUTHTOKEN in .env")
        print(f"\n  ℹ️  Server running locally at http://localhost:{port}")
        print("     MCP endpoint (local only): http://localhost:{port}/mcp\n")
        server_proc.wait()
        return

    _print_banner(public_url, port)
    server_proc.wait()


if __name__ == "__main__":
    main()
