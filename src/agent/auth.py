"""OAuth browser sign-in for OpenAI and Anthropic.

Supports:
    - OpenAI Codex OAuth (PKCE) — sign in with ChatGPT subscription
    - Anthropic setup-token — paste token from `claude setup-token`
    - API key fallback — manual key entry

Tokens are stored in ~/.crowdsentinel/auth.json and auto-refreshed.
"""

import base64
import hashlib
import http.server
import json
import logging
import os
import secrets
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

logger = logging.getLogger("crowdsentinel.agent.auth")

AUTH_FILE = Path.home() / ".crowdsentinel" / "auth.json"

# OpenAI Codex OAuth configuration
OPENAI_AUTH_URL = "https://auth.openai.com/oauth/authorize"
OPENAI_TOKEN_URL = "https://auth.openai.com/oauth/token"
OPENAI_CALLBACK_PORT = 1455
OPENAI_CALLBACK_URL = f"http://127.0.0.1:{OPENAI_CALLBACK_PORT}/auth/callback"
# Public client ID used by Codex CLI tools
OPENAI_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"


def _generate_pkce() -> tuple:
    """Generate PKCE code verifier and challenge."""
    verifier = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def _save_auth(data: Dict[str, Any]) -> None:
    """Save auth tokens to ~/.crowdsentinel/auth.json."""
    AUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
    AUTH_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    AUTH_FILE.chmod(0o600)  # Owner-only read/write
    logger.info("Auth tokens saved to %s", AUTH_FILE)


def load_auth() -> Optional[Dict[str, Any]]:
    """Load auth tokens from ~/.crowdsentinel/auth.json."""
    if not AUTH_FILE.is_file():
        return None
    try:
        data = json.loads(AUTH_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) and "provider" in data else None
    except (json.JSONDecodeError, OSError):
        return None


def remove_auth() -> bool:
    """Remove stored auth tokens."""
    if AUTH_FILE.is_file():
        AUTH_FILE.unlink()
        return True
    return False


def get_auth_status() -> Dict[str, Any]:
    """Check authentication status."""
    auth = load_auth()
    if not auth:
        # Check env vars
        if os.environ.get("ANTHROPIC_API_KEY"):
            return {"authenticated": True, "method": "env:ANTHROPIC_API_KEY", "provider": "anthropic"}
        if os.environ.get("OPENAI_API_KEY"):
            return {"authenticated": True, "method": "env:OPENAI_API_KEY", "provider": "openai"}
        return {"authenticated": False, "method": None}

    provider = auth.get("provider", "unknown")
    expires_at = auth.get("expires_at", 0)
    expired = expires_at > 0 and time.time() > expires_at

    return {
        "authenticated": True,
        "method": f"oauth:{provider}",
        "provider": provider,
        "expired": expired,
        "expires_at": expires_at,
        "token_file": str(AUTH_FILE),
    }


def refresh_token_if_needed(auth: Dict[str, Any]) -> Dict[str, Any]:
    """Refresh OAuth token if expired. Returns updated auth dict."""
    if auth.get("provider") != "openai":
        return auth  # Anthropic tokens don't auto-refresh

    expires_at = auth.get("expires_at", 0)
    if expires_at > 0 and time.time() < expires_at - 60:
        return auth  # Still valid (with 60s buffer)

    refresh_token = auth.get("refresh_token")
    if not refresh_token:
        return auth  # No refresh token available

    try:
        resp = httpx.post(
            OPENAI_TOKEN_URL,
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": OPENAI_CLIENT_ID,
            },
            timeout=60,
        )
        resp.raise_for_status()
        tokens = resp.json()

        auth["access_token"] = tokens["access_token"]
        if "refresh_token" in tokens:
            auth["refresh_token"] = tokens["refresh_token"]
        auth["expires_at"] = int(time.time()) + tokens.get("expires_in", 3600)

        _save_auth(auth)
        logger.info("OpenAI token refreshed successfully")
    except Exception as exc:
        logger.warning("Token refresh failed: %s", exc)

    return auth


def get_access_token() -> Optional[tuple]:
    """Get a valid access token. Returns (token, provider) or None.

    Resolution order:
        1. Stored OAuth token (auto-refreshed if expired)
        2. ANTHROPIC_API_KEY env var
        3. OPENAI_API_KEY env var
    """
    auth = load_auth()
    if auth:
        auth = refresh_token_if_needed(auth)
        token = auth.get("access_token")
        if token:
            return token, auth["provider"]

    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    if anthropic_key:
        return anthropic_key, "anthropic"

    openai_key = os.environ.get("OPENAI_API_KEY")
    if openai_key:
        return openai_key, "openai"

    return None


# ---------------------------------------------------------------------------
# OpenAI Codex OAuth (PKCE browser flow)
# ---------------------------------------------------------------------------

class _OAuthCallbackHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler to capture the OAuth callback."""

    auth_code = None
    state = None

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/auth/callback":
            params = parse_qs(parsed.query)
            _OAuthCallbackHandler.auth_code = params.get("code", [None])[0]
            _OAuthCallbackHandler.state = params.get("state", [None])[0]

            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<html><body><h2>Authentication successful!</h2>"
                b"<p>You can close this window and return to the terminal.</p>"
                b"</body></html>"
            )
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress server logs


def login_openai() -> bool:
    """Run the OpenAI Codex OAuth PKCE flow."""
    verifier, challenge = _generate_pkce()
    state = secrets.token_urlsafe(16)

    params = {
        "client_id": OPENAI_CLIENT_ID,
        "redirect_uri": OPENAI_CALLBACK_URL,
        "response_type": "code",
        "scope": "openid profile email offline_access",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
    }

    auth_url = f"{OPENAI_AUTH_URL}?{urlencode(params)}"

    # Start local callback server
    server = http.server.HTTPServer(("127.0.0.1", OPENAI_CALLBACK_PORT), _OAuthCallbackHandler)
    server_thread = threading.Thread(target=server.handle_request, daemon=True)
    server_thread.start()

    print(f"Opening browser for OpenAI sign-in...")
    print(f"If the browser doesn't open, visit:\n  {auth_url}\n")
    webbrowser.open(auth_url)

    # Wait for callback
    print("Waiting for authentication...")
    server_thread.join(timeout=120)
    server.server_close()

    code = _OAuthCallbackHandler.auth_code
    returned_state = _OAuthCallbackHandler.state

    # Reset class variables for next use
    _OAuthCallbackHandler.auth_code = None
    _OAuthCallbackHandler.state = None

    if not code:
        # Fallback: ask user to paste the redirect URL manually
        print("\nBrowser callback not received.")
        print("After signing in, copy the URL from your browser and paste it here:")
        redirect_url = input("Paste URL: ").strip()
        if redirect_url:
            parsed = parse_qs(urlparse(redirect_url).query)
            code = parsed.get("code", [None])[0]
            returned_state = parsed.get("state", [None])[0]

    if not code:
        print("Authentication failed: no authorization code received.", file=sys.stderr)
        return False

    if returned_state != state:
        print("Authentication failed: state mismatch (possible CSRF).", file=sys.stderr)
        return False

    # Exchange code for tokens
    try:
        resp = httpx.post(
            OPENAI_TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "client_id": OPENAI_CLIENT_ID,
                "code": code,
                "redirect_uri": OPENAI_CALLBACK_URL,
                "code_verifier": verifier,
            },
            timeout=60,
        )
        resp.raise_for_status()
        tokens = resp.json()
    except Exception as exc:
        print(f"Token exchange failed: {exc}", file=sys.stderr)
        return False

    auth_data = {
        "provider": "openai",
        "access_token": tokens["access_token"],
        "refresh_token": tokens.get("refresh_token", ""),
        "expires_at": int(time.time()) + tokens.get("expires_in", 3600),
    }

    _save_auth(auth_data)
    print("OpenAI authentication successful! Token stored.")
    return True


# ---------------------------------------------------------------------------
# Anthropic (setup-token or API key paste)
# ---------------------------------------------------------------------------

def login_anthropic() -> bool:
    """Authenticate with Anthropic via setup-token or API key."""
    print("Anthropic authentication options:\n")
    print("  1. Paste a setup-token (from `claude setup-token`)")
    print("  2. Paste an API key (from https://console.anthropic.com/settings/keys)")
    print("  3. Open Anthropic Console in browser to create a key\n")

    choice = input("Choose [1/2/3]: ").strip()

    if choice == "3":
        webbrowser.open("https://console.anthropic.com/settings/keys")
        print("\nAfter creating your key, paste it below:")
        choice = "2"

    if choice == "1":
        token = input("Paste setup-token: ").strip()
        if not token:
            print("No token provided.", file=sys.stderr)
            return False

        auth_data = {
            "provider": "anthropic",
            "access_token": token,
            "refresh_token": "",
            "expires_at": 0,  # Setup tokens don't have a fixed expiry
        }
        _save_auth(auth_data)
        print("Anthropic authentication successful! Token stored.")
        return True

    elif choice == "2":
        key = input("Paste API key: ").strip()
        if not key:
            print("No key provided.", file=sys.stderr)
            return False

        auth_data = {
            "provider": "anthropic",
            "access_token": key,
            "refresh_token": "",
            "expires_at": 0,
        }
        _save_auth(auth_data)
        print("Anthropic API key stored.")
        return True

    else:
        print("Invalid choice.", file=sys.stderr)
        return False
