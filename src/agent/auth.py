"""Authentication for Anthropic and OpenAI.

Supports:
    - Anthropic -- setup-token from `claude setup-token` or API key
    - OpenAI -- API key
    - API key fallback -- env vars

Multi-profile storage in ~/.crowdsentinel/auth-profiles.json.
Legacy single-profile auth.json is auto-migrated on first access.
"""

import json
import logging
import os
import sys
import time
import webbrowser
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger("crowdsentinel.agent.auth")

AUTH_PROFILES_FILE = Path.home() / ".crowdsentinel" / "auth-profiles.json"
LEGACY_AUTH_FILE = Path.home() / ".crowdsentinel" / "auth.json"

# Backward-compat alias used by tests (e.g. test_cli_agent.py imports AUTH_FILE)
AUTH_FILE = AUTH_PROFILES_FILE


# ---------------------------------------------------------------------------
# Multi-profile storage
# ---------------------------------------------------------------------------

def load_profiles() -> dict[str, dict]:
    """Read auth-profiles.json and return the ``profiles`` dict.

    Returns an empty dict if the file is missing or corrupted.
    """
    if not AUTH_PROFILES_FILE.is_file():
        return {}
    try:
        data = json.loads(AUTH_PROFILES_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("profiles"), dict):
            return data["profiles"]
        return {}
    except (json.JSONDecodeError, OSError):
        return {}


def save_profile(profile_id: str, profile: dict) -> None:
    """Upsert a single profile into auth-profiles.json.

    Creates the file (with ``version: 1`` wrapper) if it does not exist.
    File permissions are set to ``0o600``.
    """
    profiles = load_profiles()
    profiles[profile_id] = profile

    AUTH_PROFILES_FILE.parent.mkdir(parents=True, exist_ok=True)
    AUTH_PROFILES_FILE.write_text(
        json.dumps({"version": 1, "profiles": profiles}, indent=2),
        encoding="utf-8",
    )
    AUTH_PROFILES_FILE.chmod(0o600)
    logger.info("Profile '%s' saved to %s", profile_id, AUTH_PROFILES_FILE)


def remove_profile(profile_id: str) -> bool:
    """Remove a single profile.  Returns *True* if it existed."""
    profiles = load_profiles()
    if profile_id not in profiles:
        return False
    del profiles[profile_id]

    AUTH_PROFILES_FILE.write_text(
        json.dumps({"version": 1, "profiles": profiles}, indent=2),
        encoding="utf-8",
    )
    AUTH_PROFILES_FILE.chmod(0o600)
    return True


def get_profile_for_provider(provider: str) -> dict | None:
    """Return the best profile matching *provider*.

    Priority: ``oauth`` / ``token`` types are preferred over ``api_key``.
    """
    profiles = load_profiles()
    api_key_match: dict | None = None

    for _pid, prof in profiles.items():
        if prof.get("provider") != provider:
            continue
        ptype = prof.get("type", "")
        if ptype in ("oauth", "token"):
            return prof
        if ptype == "api_key" and api_key_match is None:
            api_key_match = prof

    return api_key_match


# ---------------------------------------------------------------------------
# Legacy migration
# ---------------------------------------------------------------------------

def _migrate_legacy_auth() -> None:
    """One-time migration from ``auth.json`` to ``auth-profiles.json``.

    If ``auth-profiles.json`` already exists the migration is skipped.
    After migration the old file is renamed to ``.json.bak``.
    """
    if AUTH_PROFILES_FILE.is_file():
        return
    if not LEGACY_AUTH_FILE.is_file():
        return

    try:
        data = json.loads(LEGACY_AUTH_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return

    if not isinstance(data, dict) or "provider" not in data:
        return

    provider = data["provider"]
    token = data.get("access_token", "")

    # Determine profile id and shape based on the stored token
    if provider == "anthropic":
        if token.startswith("sk-ant-oat01-"):
            pid = "anthropic:subscription"
            profile = {
                "type": "token",
                "provider": "anthropic",
                "access": token,
                "expires": data.get("expires_at", 0),
            }
        else:
            pid = "anthropic:default"
            profile = {
                "type": "api_key",
                "provider": "anthropic",
                "key": token,
            }
    elif provider == "openai":
        pid = "openai:default"
        profile = {
            "type": "api_key",
            "provider": "openai",
            "key": token,
        }
    else:
        pid = f"{provider}:default"
        profile = {
            "type": "api_key",
            "provider": provider,
            "key": token,
        }

    save_profile(pid, profile)
    try:
        LEGACY_AUTH_FILE.rename(LEGACY_AUTH_FILE.with_suffix(".json.bak"))
        logger.info("Legacy auth.json migrated and renamed to .json.bak")
    except OSError:
        logger.warning("Could not rename legacy auth.json after migration")


# ---------------------------------------------------------------------------
# Existing public API (updated to delegate to profiles)
# ---------------------------------------------------------------------------

def _save_auth(data: dict[str, Any]) -> None:
    """Save auth tokens.  *Deprecated* -- delegates to :func:`save_profile`."""
    provider = data.get("provider", "unknown")
    token = data.get("access_token", "")

    if provider == "anthropic" and token.startswith("sk-ant-oat01-"):
        pid = "anthropic:subscription"
        profile = {
            "type": "token",
            "provider": "anthropic",
            "access": token,
            "expires": data.get("expires_at", 0),
        }
    elif provider == "anthropic":
        pid = "anthropic:default"
        profile = {"type": "api_key", "provider": "anthropic", "key": token}
    elif provider == "openai":
        pid = "openai:default"
        profile = {"type": "api_key", "provider": "openai", "key": token}
    else:
        pid = f"{provider}:default"
        profile = {"type": "api_key", "provider": provider, "key": token}

    save_profile(pid, profile)


def load_auth() -> dict[str, Any] | None:
    """Load auth tokens.  Delegates to the profile store.

    Returns the legacy-shaped dict ``{provider, access_token, ...}`` so
    callers that haven't been updated yet keep working.
    """
    _migrate_legacy_auth()
    profiles = load_profiles()
    if not profiles:
        return None

    # Pick best profile: prefer anthropic, then openai
    for provider in ("anthropic", "openai"):
        prof = get_profile_for_provider(provider)
        if prof:
            token = prof.get("access") or prof.get("key") or ""
            return {
                "provider": prof["provider"],
                "access_token": token,
                "refresh_token": prof.get("refresh", ""),
                "expires_at": prof.get("expires", 0),
            }

    # Fallback: return any first profile
    first = next(iter(profiles.values()))
    token = first.get("access") or first.get("key") or ""
    return {
        "provider": first.get("provider", "unknown"),
        "access_token": token,
        "refresh_token": first.get("refresh", ""),
        "expires_at": first.get("expires", 0),
    }


def remove_auth() -> bool:
    """Remove stored auth tokens (deletes auth-profiles.json)."""
    if AUTH_PROFILES_FILE.is_file():
        AUTH_PROFILES_FILE.unlink()
        return True
    return False


def get_auth_status() -> dict[str, Any]:
    """Check authentication status."""
    _migrate_legacy_auth()
    profiles = load_profiles()

    if profiles:
        # Summarise first matching profile
        for provider in ("anthropic", "openai"):
            prof = get_profile_for_provider(provider)
            if prof:
                expires_at = prof.get("expires", 0)
                expired = expires_at > 0 and time.time() > expires_at
                return {
                    "authenticated": True,
                    "method": f"{prof.get('type', 'unknown')}:{provider}",
                    "provider": provider,
                    "expired": expired,
                    "expires_at": expires_at,
                    "token_file": str(AUTH_PROFILES_FILE),
                    "profile_count": len(profiles),
                }

    # Env-var fallback
    if os.environ.get("ANTHROPIC_API_KEY"):
        return {"authenticated": True, "method": "env:ANTHROPIC_API_KEY", "provider": "anthropic"}
    if os.environ.get("OPENAI_API_KEY"):
        return {"authenticated": True, "method": "env:OPENAI_API_KEY", "provider": "openai"}

    return {"authenticated": False, "method": None}


def get_access_token() -> tuple | None:
    """Get a valid access token.  Returns ``(token, provider)`` or *None*.

    Resolution order:
        1. Stored profiles (~/.crowdsentinel/auth-profiles.json) -- anthropic first
        2. ANTHROPIC_API_KEY env var
        3. OPENAI_API_KEY env var
    """
    _migrate_legacy_auth()
    profiles = load_profiles()

    for provider in ("anthropic", "openai"):
        prof = get_profile_for_provider(provider)
        if prof:
            token = prof.get("access") or prof.get("key") or ""
            if token:
                return token, provider

    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    if anthropic_key:
        return anthropic_key, "anthropic"

    openai_key = os.environ.get("OPENAI_API_KEY")
    if openai_key:
        return openai_key, "openai"

    return None


# ---------------------------------------------------------------------------
# OpenAI (API key only)
# ---------------------------------------------------------------------------

def login_openai() -> bool:
    """Authenticate with OpenAI via API key."""
    print("OpenAI authentication (API key)\n")
    print("  Get your key from: https://platform.openai.com/api-keys\n")

    try:
        webbrowser.open("https://platform.openai.com/api-keys")
    except Exception:
        pass

    print("  1. Sign in to your OpenAI account")
    print("  2. Click 'Create new secret key'")
    print("  3. Copy and paste below\n")

    key = input("Paste API key (sk-...): ").strip()
    if not key:
        print("No key provided.", file=sys.stderr)
        return False

    print("Validating key...")
    try:
        resp = httpx.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {key}"},
            timeout=15,
        )
        if resp.status_code == 200:
            print("Key validated!")
        elif resp.status_code == 401:
            print("Warning: key returned 401.", file=sys.stderr)
            if input("Store anyway? [y/N]: ").strip().lower() != "y":
                return False
    except Exception as exc:
        print(f"Warning: could not validate ({exc}).")

    save_profile("openai:default", {
        "type": "api_key",
        "provider": "openai",
        "key": key,
    })
    print(f"OpenAI API key stored in {AUTH_PROFILES_FILE}")
    return True


# ---------------------------------------------------------------------------
# Anthropic (setup-token or API key)
# ---------------------------------------------------------------------------

def login_anthropic() -> bool:
    """Authenticate with Anthropic -- setup-token (subscription) or API key."""
    print("Anthropic authentication\n")
    print("  1. Paste a setup-token (from `claude setup-token` -- uses your subscription)")
    print("  2. Paste an API key (from console.anthropic.com -- usage-based billing)\n")

    choice = input("Choose [1/2]: ").strip()

    if choice == "1":
        return _login_anthropic_setup_token()
    if choice == "2":
        return _login_anthropic_api_key()
    print("Invalid choice.", file=sys.stderr)
    return False


def _login_anthropic_setup_token() -> bool:
    """Anthropic setup-token auth (Claude subscription)."""
    print("\nRun this in another terminal:")
    print("  claude setup-token\n")
    print("It will open a browser for sign-in and output a token.\n")

    token = input("Paste the setup-token (sk-ant-oat01-...): ").strip()
    if not token:
        print("No token provided.", file=sys.stderr)
        return False

    # Validate with OAuth beta headers
    print("Validating token...")
    try:
        resp = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": token,
                "anthropic-version": "2023-06-01",
                "anthropic-beta": "claude-code-20250219,oauth-2025-04-20",
                "Content-Type": "application/json",
            },
            json={
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 10,
                "messages": [{"role": "user", "content": "hi"}],
            },
            timeout=30,
        )
        if resp.status_code == 200:
            print("Token validated successfully!")
        elif resp.status_code == 401:
            print("Warning: token returned 401 -- it may be expired. Run `claude setup-token` again.", file=sys.stderr)
            if input("Store anyway? [y/N]: ").strip().lower() != "y":
                return False
        else:
            print(f"Warning: validation returned {resp.status_code}. Storing anyway.")
    except Exception as exc:
        print(f"Warning: could not validate ({exc}). Storing anyway.")

    save_profile("anthropic:subscription", {
        "type": "token",
        "provider": "anthropic",
        "access": token,
        "expires": 0,
    })
    print(f"Anthropic setup-token stored in {AUTH_PROFILES_FILE}")
    return True


def _login_anthropic_api_key() -> bool:
    """Anthropic API key auth."""
    print("\nOpening Anthropic Console...\n")
    webbrowser.open("https://console.anthropic.com/settings/keys")

    print("  1. Sign in to your Anthropic account")
    print("  2. Click 'Create Key'")
    print("  3. Copy and paste below\n")

    key = input("Paste API key (sk-ant-api03-...): ").strip()
    if not key:
        print("No key provided.", file=sys.stderr)
        return False

    print("Validating key...")
    try:
        resp = httpx.get(
            "https://api.anthropic.com/v1/models",
            headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
            timeout=15,
        )
        if resp.status_code == 200:
            print("Key validated!")
        elif resp.status_code == 401:
            print("Warning: key returned 401.", file=sys.stderr)
            if input("Store anyway? [y/N]: ").strip().lower() != "y":
                return False
    except Exception as exc:
        print(f"Warning: could not validate ({exc}).")

    save_profile("anthropic:default", {
        "type": "api_key",
        "provider": "anthropic",
        "key": key,
    })
    print(f"Anthropic API key stored in {AUTH_PROFILES_FILE}")
    return True
