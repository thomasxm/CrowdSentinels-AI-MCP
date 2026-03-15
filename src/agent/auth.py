"""OAuth authentication for OpenAI and Anthropic.

Supports:
    - OpenAI Device Code flow — sign in with ChatGPT subscription (works headless)
    - Anthropic — setup-token from `claude setup-token` or API key
    - API key fallback — env vars

Tokens stored in ~/.crowdsentinel/auth.json and auto-refreshed.
"""

import json
import logging
import os
import sys
import time
import webbrowser
from pathlib import Path
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger("crowdsentinel.agent.auth")

AUTH_FILE = Path.home() / ".crowdsentinel" / "auth.json"

# OpenAI Codex OAuth configuration (same as Codex CLI / OpenClaw)
OPENAI_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
OPENAI_AUTH_BASE = "https://auth.openai.com"
OPENAI_DEVICE_USERCODE_URL = f"{OPENAI_AUTH_BASE}/api/accounts/deviceauth/usercode"
OPENAI_DEVICE_TOKEN_URL = f"{OPENAI_AUTH_BASE}/api/accounts/deviceauth/token"
OPENAI_TOKEN_URL = f"{OPENAI_AUTH_BASE}/oauth/token"
OPENAI_DEVICE_CALLBACK_URI = f"{OPENAI_AUTH_BASE}/deviceauth/callback"
OPENAI_DEVICE_AUTH_PAGE = "https://auth.openai.com/codex/device"


def _save_auth(data: Dict[str, Any]) -> None:
    """Save auth tokens to ~/.crowdsentinel/auth.json."""
    AUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
    AUTH_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    AUTH_FILE.chmod(0o600)
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
    """Refresh OAuth token if expired."""
    if auth.get("provider") != "openai":
        return auth

    expires_at = auth.get("expires_at", 0)
    if expires_at > 0 and time.time() < expires_at - 60:
        return auth

    refresh_token = auth.get("refresh_token")
    if not refresh_token:
        return auth

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
        logger.info("OpenAI token refreshed")
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
# OpenAI Device Code Flow
# ---------------------------------------------------------------------------

def login_openai() -> bool:
    """Authenticate with OpenAI using the Device Code flow.

    This is the same flow used by Codex CLI and OpenClaw:
    1. Request a device code from OpenAI
    2. User opens a URL and enters the code
    3. CLI polls until the user authorises
    4. Exchange the authorisation code for tokens
    """
    client = httpx.Client(timeout=30)

    # Step 1: Request device code
    print("Requesting device code from OpenAI...")
    try:
        resp = client.post(
            OPENAI_DEVICE_USERCODE_URL,
            json={"client_id": OPENAI_CLIENT_ID},
            headers={
                "Content-Type": "application/json",
                "User-Agent": "crowdsentinel-mcp-server/1.0",
                "Accept": "application/json",
            },
        )
        resp.raise_for_status()
        device_data = resp.json()
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            print(
                "Device code login is not enabled for your account.\n"
                "Enable it at: https://chatgpt.com/settings/security\n"
                "Look for 'Device Code Login' and turn it on.",
                file=sys.stderr,
            )
        else:
            print(f"Failed to request device code: {exc}", file=sys.stderr)
        return False
    except Exception as exc:
        print(f"Failed to request device code: {exc}", file=sys.stderr)
        return False

    device_auth_id = device_data.get("device_auth_id")
    user_code = device_data.get("user_code") or device_data.get("usercode")
    interval = int(device_data.get("interval", 5))

    if not device_auth_id or not user_code:
        print(f"Unexpected response: {device_data}", file=sys.stderr)
        return False

    # Step 2: Show code and open browser
    print(f"\n  Your code: {user_code}\n")
    print(f"  Open this URL and enter the code above:")
    print(f"  {OPENAI_DEVICE_AUTH_PAGE}\n")

    try:
        webbrowser.open(OPENAI_DEVICE_AUTH_PAGE)
    except Exception:
        pass  # Browser may not be available (headless)

    # Step 3: Poll for authorisation
    print("Waiting for authorisation", end="", flush=True)
    max_wait = 15 * 60  # 15 minutes
    start = time.time()

    auth_code = None
    code_verifier = None

    while time.time() - start < max_wait:
        time.sleep(interval)
        print(".", end="", flush=True)

        try:
            resp = client.post(
                OPENAI_DEVICE_TOKEN_URL,
                json={
                    "device_auth_id": device_auth_id,
                    "user_code": user_code,
                },
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "crowdsentinel-mcp-server/1.0",
                    "Accept": "application/json",
                },
            )

            if resp.status_code == 200:
                token_data = resp.json()
                auth_code = token_data.get("authorization_code")
                code_verifier = token_data.get("code_verifier")
                print(" Authorised!")
                break
            elif resp.status_code in (403, 404):
                continue  # Still pending
            else:
                print(f"\nPolling error: {resp.status_code} {resp.text}", file=sys.stderr)
                return False
        except Exception:
            print("!", end="", flush=True)
            continue

    if not auth_code:
        print("\nAuthorisation timed out after 15 minutes.", file=sys.stderr)
        return False

    # Step 4: Exchange code for tokens
    print("Exchanging code for tokens...")
    try:
        exchange_data = {
            "grant_type": "authorization_code",
            "client_id": OPENAI_CLIENT_ID,
            "code": auth_code,
            "redirect_uri": OPENAI_DEVICE_CALLBACK_URI,
        }
        if code_verifier:
            exchange_data["code_verifier"] = code_verifier

        resp = client.post(
            OPENAI_TOKEN_URL,
            data=exchange_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
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
    print("OpenAI authentication successful! Token stored in ~/.crowdsentinel/auth.json")
    return True


# ---------------------------------------------------------------------------
# Anthropic (setup-token or API key)
# ---------------------------------------------------------------------------

def login_anthropic() -> bool:
    """Authenticate with Anthropic via setup-token or API key.

    For subscription auth (Pro/Max), use `claude setup-token` to generate
    a token, then paste it here. For API key auth, paste the key from
    https://console.anthropic.com/settings/keys.
    """
    print("Anthropic authentication\n")
    print("  Option 1: Run `claude setup-token` in another terminal, then paste the token here")
    print("  Option 2: Paste an API key from https://console.anthropic.com/settings/keys")
    print("  Option 3: Open Anthropic Console in browser to create a key\n")

    choice = input("Choose [1/2/3]: ").strip()

    if choice == "3":
        webbrowser.open("https://console.anthropic.com/settings/keys")
        print("\nAfter creating your key, paste it below:")
        choice = "2"

    if choice == "1":
        print("\nRun this in another terminal:")
        print("  claude setup-token\n")
        token = input("Paste the setup-token: ").strip()
        if not token:
            print("No token provided.", file=sys.stderr)
            return False

        _save_auth({
            "provider": "anthropic",
            "access_token": token,
            "refresh_token": "",
            "expires_at": 0,
        })
        print("Anthropic setup-token stored in ~/.crowdsentinel/auth.json")
        return True

    elif choice == "2":
        key = input("Paste API key (sk-ant-...): ").strip()
        if not key:
            print("No key provided.", file=sys.stderr)
            return False

        _save_auth({
            "provider": "anthropic",
            "access_token": key,
            "refresh_token": "",
            "expires_at": 0,
        })
        print("Anthropic API key stored in ~/.crowdsentinel/auth.json")
        return True

    else:
        print("Invalid choice.", file=sys.stderr)
        return False
