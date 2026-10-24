"""
tests/test_oauth_dual_alexa.py — Test OAuth 2.1 + PKCE Dual Alexa+ Integration
Validates:
- RFC 9728 Protected Resource Metadata endpoint
- RFC 8414 Authorization Server Metadata endpoint
- RFC 7591 Dynamic Client Registration
- PKCE S256 code challenge and token exchange
- Separate tokens for Owner (userA) and Recipient (userB)
- Bearer token authentication mapping to caller identity
"""
import base64
import hashlib
import secrets
from fastapi.testclient import TestClient
from server.main import app

def _pkce_pair():
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge

def test_prm_and_as_metadata():
    client = TestClient(app)
    # RFC 9728 PRM
    prm_res = client.get("/.well-known/oauth-protected-resource")
    assert prm_res.status_code == 200
    prm_data = prm_res.json()
    assert "delegation:read" in prm_data.get("scopes_supported", [])
    assert "authorization_servers" in prm_data

    # RFC 8414 AS
    as_res = client.get("/.well-known/oauth-authorization-server")
    assert as_res.status_code == 200
    as_data = as_res.json()
    assert "S256" in as_data.get("code_challenge_methods_supported", [])
    assert as_data.get("token_endpoint").endswith("/oauth/token")

def test_dual_alexa_oauth_flow(temp_db):
    import server.store.db as db_mod
    orig = db_mod.DB_PATH
    db_mod.DB_PATH = temp_db

    try:
        client = TestClient(app)

        # 0. Test RFC 7591 Dynamic Client Registration for both Alexa instances
        reg_a = client.post("/oauth/register", json={
            "client_name": "Alexa Owner Device",
            "redirect_uris": ["http://localhost:8000/oauth/callback"],
        })
        assert reg_a.status_code == 201
        client_a_id = reg_a.json()["client_id"]

        reg_b = client.post("/oauth/register", json={
            "client_name": "Alexa Recipient Device",
            "redirect_uris": ["http://localhost:8000/oauth/callback"],
        })
        assert reg_b.status_code == 201
        client_b_id = reg_b.json()["client_id"]

        # 1. User A (Owner) OAuth 2.1 Flow
        v_a, c_a = _pkce_pair()
        auth_a = client.post("/oauth/authorize", data={
            "client_id": client_a_id,
            "redirect_uri": "http://localhost:8000/oauth/callback",
            "state": "state_a",
            "code_challenge": c_a,
            "code_challenge_method": "S256",
            "scope": "delegation:write",
            "response_type": "code",
            "username": "userA",
            "password": "owner-alexa-pass",
        }, follow_redirects=False)
        assert auth_a.status_code == 302
        code_a = auth_a.headers["location"].split("code=")[1].split("&")[0]

        token_a_res = client.post("/oauth/token", data={
            "grant_type": "authorization_code",
            "code": code_a,
            "redirect_uri": "http://localhost:8000/oauth/callback",
            "client_id": client_a_id,
            "code_verifier": v_a,
        })
        assert token_a_res.status_code == 200
        token_a = token_a_res.json()["access_token"]

        # 2. User B (Recipient) OAuth 2.1 Flow
        v_b, c_b = _pkce_pair()
        auth_b = client.post("/oauth/authorize", data={
            "client_id": client_b_id,
            "redirect_uri": "http://localhost:8000/oauth/callback",
            "state": "state_b",
            "code_challenge": c_b,
            "code_challenge_method": "S256",
            "scope": "delegation:read",
            "response_type": "code",
            "username": "userB",
            "password": "recipient-alexa-pass",
        }, follow_redirects=False)
        assert auth_b.status_code == 302
        code_b = auth_b.headers["location"].split("code=")[1].split("&")[0]

        token_b_res = client.post("/oauth/token", data={
            "grant_type": "authorization_code",
            "code": code_b,
            "redirect_uri": "http://localhost:8000/oauth/callback",
            "client_id": client_b_id,
            "code_verifier": v_b,
        })
        assert token_b_res.status_code == 200
        token_b = token_b_res.json()["access_token"]

        # 3. User A creates delegation via Bearer token
        del_res = client.post(
            "/api/alexa/user-a/create",
            headers={"Authorization": f"Bearer {token_a}"},
            json={
                "recipient": "userB",
                "topic_desc": "deployment keys and procedure",
                "facts": [
                    {"label": "deploy command", "value": "helm upgrade prod-v2 ./chart"}
                ],
                "codeword": "blue falcon",
                "max_uses": 2,
                "expires_in_minutes": 60,
            }
        )
        assert del_res.status_code == 200
        del_data = del_res.json()
        assert "delegation_id" in del_data
        delegation_id = del_data["delegation_id"]

        # 4. User B queries delegation via Bearer token
        query_res = client.post(
            "/api/alexa/user-b/ask",
            headers={"Authorization": f"Bearer {token_b}"},
            json={
                "delegation_id_or_owner": delegation_id,
                "question": "What is the deploy command?",
                "codeword": "blue falcon",
            }
        )
        assert query_res.status_code == 200
        query_data = query_res.json()
        assert query_data["status"] == "allowed"
        assert "helm upgrade" in query_data["speech"]

    finally:
        db_mod.DB_PATH = orig


def test_proxy_demo_gating(monkeypatch):
    """Verifies that reverse-proxied requests require tokens unless ALLOW_PROXY_DEMO=true."""
    client = TestClient(app)
    
    # 1. Proxied request without ALLOW_PROXY_DEMO -> 401 missing_token
    monkeypatch.delenv("ALLOW_PROXY_DEMO", raising=False)
    monkeypatch.setenv("DEMO_MODE", "true")
    res = client.post(
        "/api/alexa/user-b/ask",
        headers={"X-Forwarded-For": "203.0.113.195"},
        json={"delegation_id_or_owner": "userB", "question": "test", "codeword": "none"}
    )
    assert res.status_code == 401
    assert "missing_token" in res.json()["detail"]

    # 2. Proxied request WITH ALLOW_PROXY_DEMO=true -> passes auth gating (does not return 401)
    monkeypatch.setenv("ALLOW_PROXY_DEMO", "true")
    res2 = client.post(
        "/api/alexa/user-b/ask",
        headers={"X-Forwarded-For": "203.0.113.195"},
        json={"delegation_id_or_owner": "nonexistent_id", "question": "test", "codeword": "none"}
    )
    assert res2.status_code != 401
