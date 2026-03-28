"""OpenAI PKCE OAuth flow for ChatGPT subscription authentication.

Uses the standard Authorization Code + PKCE flow via auth.openai.com.
A temporary local HTTP server captures the callback.

This flow does NOT use Device Code auth, which can cause ChatGPT
browser session invalidation.
"""

import base64
import hashlib
import secrets
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

# OpenAI OAuth endpoints
OPENAI_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
OPENAI_AUTH_BASE = "https://auth.openai.com"
OPENAI_AUTHORIZE_URL = f"{OPENAI_AUTH_BASE}/oauth/authorize"
OPENAI_TOKEN_URL = f"{OPENAI_AUTH_BASE}/oauth/token"
CALLBACK_HOST = "127.0.0.1"
CALLBACK_PORT = 1455
CALLBACK_URI = f"http://{CALLBACK_HOST}:{CALLBACK_PORT}/auth/callback"

# Refresh 5 minutes before expiry
REFRESH_BUFFER_SECONDS = 300


# ---------------------------------------------------------------------------
# PKCE helpers
# ---------------------------------------------------------------------------


def generate_code_verifier() -> str:
    """Generate a random PKCE code verifier (96 chars, base64url-safe)."""
    return secrets.token_urlsafe(64)[:96]


def generate_code_challenge(verifier: str) -> str:
    """Derive the S256 code challenge from a verifier.

    Returns ``base64url(SHA-256(verifier))`` with padding stripped.
    """
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def generate_state() -> str:
    """Generate a random state parameter (43 chars, base64url-safe)."""
    return secrets.token_urlsafe(32)[:43]


def build_authorize_url(code_challenge: str, state: str) -> str:
    """Build the full OpenAI authorization URL with PKCE parameters."""
    params = {
        "client_id": OPENAI_CLIENT_ID,
        "redirect_uri": CALLBACK_URI,
        "response_type": "code",
        "scope": "openai.public",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "audience": "https://api.openai.com/v1",
    }
    return f"{OPENAI_AUTHORIZE_URL}?{urlencode(params)}"


def parse_callback(url: str) -> tuple[str, str]:
    """Extract ``(code, state)`` from a callback URL.

    Raises :class:`ValueError` when the callback carries an error or is
    missing the ``code`` parameter.
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)

    error = qs.get("error", [None])[0]
    if error:
        description = qs.get("error_description", [""])[0]
        detail = f"{error}: {description}" if description else error
        raise ValueError(f"OAuth callback error: {detail}")

    codes = qs.get("code")
    if not codes:
        raise ValueError("OAuth callback missing 'code' parameter")

    states = qs.get("state", [""])
    return codes[0], states[0]


# ---------------------------------------------------------------------------
# Token exchange
# ---------------------------------------------------------------------------


def exchange_code(code: str, code_verifier: str) -> dict[str, Any]:
    """Exchange an authorization code for tokens via the OpenAI token endpoint.

    Returns the raw JSON response dict which typically includes
    ``access_token``, ``refresh_token``, ``expires_in``, and ``token_type``.
    """
    payload = {
        "grant_type": "authorization_code",
        "client_id": OPENAI_CLIENT_ID,
        "code": code,
        "redirect_uri": CALLBACK_URI,
        "code_verifier": code_verifier,
    }
    resp = httpx.post(OPENAI_TOKEN_URL, data=payload, timeout=30)
    resp.raise_for_status()
    return resp.json()


def refresh_access_token(refresh_token: str) -> dict[str, Any]:
    """Use a refresh token to obtain a new access token.

    Returns the raw JSON response dict from the token endpoint.
    """
    payload = {
        "grant_type": "refresh_token",
        "client_id": OPENAI_CLIENT_ID,
        "refresh_token": refresh_token,
    }
    resp = httpx.post(OPENAI_TOKEN_URL, data=payload, timeout=30)
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Expiry check
# ---------------------------------------------------------------------------


def is_token_expired(expires_ms: int) -> bool:
    """Check whether a token is expired or within the refresh buffer.

    *expires_ms* is the expiry timestamp in **milliseconds** since epoch.
    Returns ``False`` for values ``<= 0`` (API keys and setup-tokens that
    never expire).
    """
    if expires_ms <= 0:
        return False
    now_ms = int(time.time() * 1000)
    buffer_ms = REFRESH_BUFFER_SECONDS * 1000
    return now_ms >= (expires_ms - buffer_ms)


# ---------------------------------------------------------------------------
# Local callback server
# ---------------------------------------------------------------------------


class _CallbackHandler(BaseHTTPRequestHandler):
    """HTTP request handler that captures the OAuth callback parameters."""

    # Class-level state — reset before each flow
    auth_code: str | None = None
    auth_state: str | None = None
    error: str | None = None

    def do_GET(self) -> None:  # noqa: N802
        """Handle the GET redirect from OpenAI's authorization server."""
        try:
            full_url = f"http://{CALLBACK_HOST}:{CALLBACK_PORT}{self.path}"
            code, state = parse_callback(full_url)
            _CallbackHandler.auth_code = code
            _CallbackHandler.auth_state = state
        except ValueError as exc:
            _CallbackHandler.error = str(exc)

        # Always respond with a simple HTML page
        body = (
            "<html><body><h2>Authentication complete.</h2>"
            "<p>You can close this tab and return to the terminal.</p>"
            "</body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Suppress default stderr logging."""


# ---------------------------------------------------------------------------
# Full PKCE flow
# ---------------------------------------------------------------------------


def run_pkce_flow() -> dict[str, Any]:
    """Execute the full PKCE authorization code flow.

    1. Generate verifier, challenge, and state.
    2. Start a temporary local HTTP server for the callback.
    3. Open the browser to the OpenAI authorization URL.
    4. Wait for the callback (up to 300 seconds).
    5. Validate state and exchange the code for tokens.

    Returns the token response dict from OpenAI.

    Raises :class:`RuntimeError` on timeout, state mismatch, or callback error.
    """
    verifier = generate_code_verifier()
    challenge = generate_code_challenge(verifier)
    state = generate_state()

    # Reset handler state
    _CallbackHandler.auth_code = None
    _CallbackHandler.auth_state = None
    _CallbackHandler.error = None

    server = HTTPServer((CALLBACK_HOST, CALLBACK_PORT), _CallbackHandler)

    def _serve() -> None:
        while _CallbackHandler.auth_code is None and _CallbackHandler.error is None:
            server.handle_request()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()

    authorize_url = build_authorize_url(challenge, state)
    webbrowser.open(authorize_url)

    thread.join(timeout=300)

    server.server_close()

    if _CallbackHandler.error:
        raise RuntimeError(f"PKCE flow failed: {_CallbackHandler.error}")

    if _CallbackHandler.auth_code is None:
        raise RuntimeError("PKCE flow timed out — no callback received within 300 seconds")

    # Validate state BEFORE exchanging the code — prevents auth code injection
    if _CallbackHandler.auth_state != state:
        raise RuntimeError(
            f"PKCE flow failed: state mismatch (expected {state!r}, got {_CallbackHandler.auth_state!r})"
        )

    return exchange_code(_CallbackHandler.auth_code, verifier)
