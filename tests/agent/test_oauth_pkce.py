"""Tests for PKCE OAuth helpers (pure functions only).

The browser-based ``run_pkce_flow()`` and HTTP token exchange functions
are not tested here — they require a live OpenAI authorization server.
"""

import base64
import hashlib
import re
import time

import pytest

from src.agent.oauth_pkce import (
    REFRESH_BUFFER_SECONDS,
    build_authorize_url,
    generate_code_challenge,
    generate_code_verifier,
    generate_state,
    is_token_expired,
    parse_callback,
)


# ---------------------------------------------------------------------------
# PKCE helper tests
# ---------------------------------------------------------------------------

class TestPKCEHelpers:
    def test_generate_code_verifier_length(self):
        verifier = generate_code_verifier()
        assert 43 <= len(verifier) <= 128

    def test_generate_code_verifier_charset(self):
        verifier = generate_code_verifier()
        assert re.fullmatch(r"[A-Za-z0-9\-._~]+", verifier), (
            f"verifier contains invalid characters: {verifier!r}"
        )

    def test_generate_code_challenge(self):
        verifier = "test-verifier-for-challenge"
        expected_digest = hashlib.sha256(verifier.encode("ascii")).digest()
        expected = base64.urlsafe_b64encode(expected_digest).rstrip(b"=").decode("ascii")
        assert generate_code_challenge(verifier) == expected

    def test_generate_state(self):
        state = generate_state()
        assert len(state) >= 32

    def test_build_authorize_url(self):
        url = build_authorize_url(code_challenge="challenge123", state="state456")
        assert "client_id=" in url
        assert "redirect_uri=" in url
        assert "response_type=code" in url
        assert "code_challenge=challenge123" in url
        assert "code_challenge_method=S256" in url
        assert "state=state456" in url
        assert "scope=openai.public" in url
        assert url.startswith("https://auth.openai.com/oauth/authorize?")

    def test_parse_callback_url(self):
        url = "http://127.0.0.1:1455/auth/callback?code=abc123&state=xyz789"
        code, state = parse_callback(url)
        assert code == "abc123"
        assert state == "xyz789"

    def test_parse_callback_error(self):
        url = "http://127.0.0.1:1455/auth/callback?error=access_denied"
        with pytest.raises(ValueError, match="OAuth callback error"):
            parse_callback(url)

    def test_parse_missing_code(self):
        url = "http://127.0.0.1:1455/auth/callback?state=xyz789"
        with pytest.raises(ValueError, match="missing 'code' parameter"):
            parse_callback(url)

    def test_parse_error_with_description(self):
        url = (
            "http://127.0.0.1:1455/auth/callback"
            "?error=access_denied&error_description=User+cancelled"
        )
        with pytest.raises(ValueError, match="access_denied: User cancelled"):
            parse_callback(url)


# ---------------------------------------------------------------------------
# Token expiry tests
# ---------------------------------------------------------------------------

class TestTokenExpiry:
    def test_not_expired_token(self):
        # 1 hour from now in milliseconds
        future_ms = int((time.time() + 3600) * 1000)
        assert is_token_expired(future_ms) is False

    def test_expired_token(self):
        # 1 hour ago in milliseconds
        past_ms = int((time.time() - 3600) * 1000)
        assert is_token_expired(past_ms) is True

    def test_token_within_buffer_is_expired(self):
        # 2 minutes from now — within the 5-minute REFRESH_BUFFER_SECONDS
        soon_ms = int((time.time() + 120) * 1000)
        assert REFRESH_BUFFER_SECONDS == 300, "sanity check on buffer"
        assert is_token_expired(soon_ms) is True

    def test_zero_expiry_never_expires(self):
        assert is_token_expired(0) is False

    def test_negative_expiry_never_expires(self):
        assert is_token_expired(-1) is False
