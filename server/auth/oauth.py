"""
server/auth/oauth.py — Embedded OAuth 2.1 + PKCE Authorization Server
=======================================================================
Implements the OAuth 2.1 Authorization Code + PKCE flow required by
Alexa+ to connect to a third-party MCP server.

Architecture:
  - TWO pre-configured user accounts:
      • userA  (owner)    — creates delegations, reads audit
      • userB  (recipient) — asks questions, reads briefings
  - Alexa+ connects TWICE (once per role) via account linking
  - Each role gets a Bearer token stored in memory
  - The /mcp endpoint validates the Bearer token → maps to caller

Endpoints added to FastAPI:
  GET  /.well-known/oauth-protected-resource   RFC 9728 PRM
  GET  /.well-known/oauth-authorization-server RFC 8414 AS metadata
  GET  /oauth/authorize                        Consent / login page
  POST /oauth/token                            Token exchange
  POST /oauth/register                         Dynamic client registration

Token lifecycle:
  - Access tokens are short-lived (1 hour)
  - Identified by opaque random string
  - Stored in-memory (sufficient for hackathon / single-process demo)
"""

import os
import json
import time
import hashlib
import base64
import secrets
import logging
from typing import Optional, Dict, Any
from urllib.parse import urlencode, urlparse, parse_qs

logger = logging.getLogger("alexa-delegation-broker.auth")

# ─── In-memory stores ──────────────────────────────────────────────────────────
# { code: {client_id, redirect_uri, code_challenge, code_challenge_method,
#           scope, user_id, expires_at} }
_auth_codes: Dict[str, Dict] = {}

# { token: {user_id, scope, client_id, expires_at} }
_access_tokens: Dict[str, Dict] = {}

# { client_id: {client_secret, redirect_uris, client_name} }
_registered_clients: Dict[str, Dict] = {}

# Token TTL in seconds
TOKEN_TTL = 3600  # 1 hour
CODE_TTL = 120    # 2 minutes

# ─── User credentials ──────────────────────────────────────────────────────────
# In a real deployment these would be in a proper user store with hashed passwords.
# For the hackathon demo two fixed accounts map to the two Alexa+ roles.
_USERS = {
    "userA": {
        "password": os.environ.get("OWNER_PASSWORD", "owner-alexa-pass"),
        "role": "owner",
        "display_name": "User A (Owner)",
    },
    "userB": {
        "password": os.environ.get("RECIPIENT_PASSWORD", "recipient-alexa-pass"),
        "role": "recipient",
        "display_name": "User B (Recipient)",
    },
}

# ─── Helpers ───────────────────────────────────────────────────────────────────

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    """Verify S256 or plain PKCE code verifier against stored challenge."""
    if method == "S256":
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        expected = _b64url(digest)
        return secrets.compare_digest(expected, code_challenge)
    elif method == "plain":
        return secrets.compare_digest(code_verifier, code_challenge)
    return False


def _check_user(username: str, password: str) -> Optional[str]:
    """Returns user_id if credentials are valid, else None."""
    user = _USERS.get(username)
    if user and secrets.compare_digest(user["password"], password):
        return username
    return None


def generate_auth_code(
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    code_challenge_method: str,
    scope: str,
    user_id: str,
) -> str:
    """Create a short-lived authorization code."""
    code = secrets.token_urlsafe(32)
    _auth_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "scope": scope,
        "user_id": user_id,
        "expires_at": time.time() + CODE_TTL,
    }
    return code


def exchange_code_for_token(
    code: str,
    client_id: str,
    redirect_uri: str,
    code_verifier: str,
) -> Optional[Dict[str, Any]]:
    """Exchange auth code for access token. Returns token dict or None on failure."""
    entry = _auth_codes.get(code)
    if not entry:
        logger.warning("Token exchange: unknown code")
        return None
    if time.time() > entry["expires_at"]:
        del _auth_codes[code]
        logger.warning("Token exchange: code expired")
        return None
    if entry["client_id"] != client_id:
        logger.warning("Token exchange: client_id mismatch")
        return None
    if entry["redirect_uri"] != redirect_uri:
        logger.warning("Token exchange: redirect_uri mismatch")
        return None
    if not _verify_pkce(code_verifier, entry["code_challenge"], entry["code_challenge_method"]):
        logger.warning("Token exchange: PKCE verification failed")
        return None

    # Consume the code
    del _auth_codes[code]

    # Issue token
    token = secrets.token_urlsafe(40)
    _access_tokens[token] = {
        "user_id": entry["user_id"],
        "scope": entry["scope"],
        "client_id": client_id,
        "expires_at": time.time() + TOKEN_TTL,
    }
    logger.info(f"Issued access token for user={entry['user_id']} client={client_id}")
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL,
        "scope": entry["scope"],
    }


def validate_bearer_token(authorization_header: Optional[str]) -> Optional[Dict[str, Any]]:
    """
    Validates a Bearer token from the Authorization header.
    Returns {user_id, scope, role} if valid, None if invalid/expired.
    """
    if not authorization_header:
        return None
    parts = authorization_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    entry = _access_tokens.get(token)
    if not entry:
        return None
    if time.time() > entry["expires_at"]:
        del _access_tokens[token]
        return None
    user = _USERS.get(entry["user_id"], {})
    return {
        "user_id": entry["user_id"],
        "scope": entry["scope"],
        "role": user.get("role", "unknown"),
        "display_name": user.get("display_name", entry["user_id"]),
    }


def register_client(
    client_name: str,
    redirect_uris: list,
    grant_types: Optional[list] = None,
    response_types: Optional[list] = None,
) -> Dict[str, Any]:
    """Dynamic client registration (RFC 7591)."""
    client_id = f"alexa-{secrets.token_urlsafe(16)}"
    client_secret = secrets.token_urlsafe(32)
    _registered_clients[client_id] = {
        "client_secret": client_secret,
        "redirect_uris": redirect_uris,
        "client_name": client_name,
        "grant_types": grant_types or ["authorization_code"],
        "response_types": response_types or ["code"],
    }
    logger.info(f"Registered dynamic client: {client_name} → {client_id}")
    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "client_name": client_name,
        "redirect_uris": redirect_uris,
        "grant_types": grant_types or ["authorization_code"],
        "response_types": response_types or ["code"],
    }


def get_client(client_id: str) -> Optional[Dict]:
    """Returns registered client info or None."""
    # Also accept the built-in simulator client
    if client_id == "alexa-simulator":
        return {
            "client_secret": None,  # public client
            "redirect_uris": ["http://localhost:8000/oauth/callback", "https://layla.amazon.com/api/skill/link/ALEXA_ADDON"],
            "client_name": "Alexa+ Simulator",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
        }
    return _registered_clients.get(client_id)
