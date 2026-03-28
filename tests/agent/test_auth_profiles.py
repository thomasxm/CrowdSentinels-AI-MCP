"""Tests for multi-profile auth storage and legacy migration.

All file I/O is isolated via tmp_path fixtures and monkeypatching of the
module-level path constants so the real ~/.crowdsentinel/ is never touched.
"""

import json
import os
import stat

import pytest

from src.agent import auth

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_auth_paths(tmp_path, monkeypatch):
    """Redirect AUTH_PROFILES_FILE and LEGACY_AUTH_FILE to tmp_path."""
    profiles = tmp_path / "auth-profiles.json"
    legacy = tmp_path / "auth.json"

    monkeypatch.setattr(auth, "AUTH_PROFILES_FILE", profiles)
    monkeypatch.setattr(auth, "LEGACY_AUTH_FILE", legacy)
    monkeypatch.setattr(auth, "AUTH_FILE", profiles)


# ---------------------------------------------------------------------------
# save_profile / load_profiles round-trip
# ---------------------------------------------------------------------------


class TestSaveLoadProfiles:
    def test_roundtrip_api_key(self):
        profile = {"type": "api_key", "provider": "anthropic", "key": "sk-ant-api03-test"}
        auth.save_profile("anthropic:default", profile)
        loaded = auth.load_profiles()
        assert loaded["anthropic:default"] == profile

    def test_roundtrip_oauth(self):
        profile = {
            "type": "oauth",
            "provider": "openai-codex",
            "access": "eyJtoken",
            "refresh": "rt_refresh",
            "expires": 1772274693664,
        }
        auth.save_profile("openai-codex:default", profile)
        loaded = auth.load_profiles()
        assert loaded["openai-codex:default"] == profile

    def test_roundtrip_token(self):
        profile = {
            "type": "token",
            "provider": "anthropic",
            "access": "sk-ant-oat01-testtoken",
            "expires": 0,
        }
        auth.save_profile("anthropic:subscription", profile)
        loaded = auth.load_profiles()
        assert loaded["anthropic:subscription"] == profile

    def test_upsert_preserves_other_profiles(self):
        auth.save_profile("a:one", {"type": "api_key", "provider": "a", "key": "k1"})
        auth.save_profile("b:two", {"type": "api_key", "provider": "b", "key": "k2"})
        profiles = auth.load_profiles()
        assert "a:one" in profiles
        assert "b:two" in profiles

    def test_upsert_overwrites_existing(self):
        auth.save_profile("a:one", {"type": "api_key", "provider": "a", "key": "old"})
        auth.save_profile("a:one", {"type": "api_key", "provider": "a", "key": "new"})
        assert auth.load_profiles()["a:one"]["key"] == "new"

    def test_version_wrapper(self):
        auth.save_profile("x:y", {"type": "api_key", "provider": "x", "key": "k"})
        raw = json.loads(auth.AUTH_PROFILES_FILE.read_text(encoding="utf-8"))
        assert raw["version"] == 1
        assert "profiles" in raw


# ---------------------------------------------------------------------------
# File permissions
# ---------------------------------------------------------------------------


class TestFilePermissions:
    def test_save_profile_sets_0600(self):
        auth.save_profile("test:p", {"type": "api_key", "provider": "test", "key": "k"})
        mode = stat.S_IMODE(os.stat(auth.AUTH_PROFILES_FILE).st_mode)
        assert mode == 0o600


# ---------------------------------------------------------------------------
# remove_profile
# ---------------------------------------------------------------------------


class TestRemoveProfile:
    def test_remove_existing(self):
        auth.save_profile("a:one", {"type": "api_key", "provider": "a", "key": "k"})
        result = auth.remove_profile("a:one")
        assert result is True
        assert "a:one" not in auth.load_profiles()

    def test_remove_nonexistent(self):
        assert auth.remove_profile("does:not:exist") is False

    def test_remove_leaves_others(self):
        auth.save_profile("a:one", {"type": "api_key", "provider": "a", "key": "k1"})
        auth.save_profile("b:two", {"type": "api_key", "provider": "b", "key": "k2"})
        auth.remove_profile("a:one")
        profiles = auth.load_profiles()
        assert "a:one" not in profiles
        assert "b:two" in profiles


# ---------------------------------------------------------------------------
# get_profile_for_provider
# ---------------------------------------------------------------------------


class TestGetProfileForProvider:
    def test_matching_api_key(self):
        auth.save_profile("openai:default", {"type": "api_key", "provider": "openai", "key": "sk-test"})
        prof = auth.get_profile_for_provider("openai")
        assert prof is not None
        assert prof["key"] == "sk-test"

    def test_no_match_returns_none(self):
        auth.save_profile("openai:default", {"type": "api_key", "provider": "openai", "key": "sk-test"})
        assert auth.get_profile_for_provider("anthropic") is None

    def test_empty_profiles_returns_none(self):
        assert auth.get_profile_for_provider("anthropic") is None

    def test_oauth_preferred_over_api_key(self):
        auth.save_profile(
            "anthropic:default",
            {
                "type": "api_key",
                "provider": "anthropic",
                "key": "sk-api",
            },
        )
        auth.save_profile(
            "anthropic:subscription",
            {
                "type": "token",
                "provider": "anthropic",
                "access": "sk-oat-token",
                "expires": 0,
            },
        )
        prof = auth.get_profile_for_provider("anthropic")
        assert prof["type"] == "token"
        assert prof["access"] == "sk-oat-token"

    def test_token_preferred_over_api_key(self):
        auth.save_profile(
            "anthropic:default",
            {
                "type": "api_key",
                "provider": "anthropic",
                "key": "sk-api",
            },
        )
        auth.save_profile(
            "anthropic:oauth",
            {
                "type": "oauth",
                "provider": "anthropic",
                "access": "eyJ",
                "refresh": "rt_",
                "expires": 999,
            },
        )
        prof = auth.get_profile_for_provider("anthropic")
        assert prof["type"] == "oauth"

    def test_api_key_returned_when_no_oauth(self):
        auth.save_profile(
            "openai:default",
            {
                "type": "api_key",
                "provider": "openai",
                "key": "sk-proj-test",
            },
        )
        prof = auth.get_profile_for_provider("openai")
        assert prof["type"] == "api_key"


# ---------------------------------------------------------------------------
# Legacy migration
# ---------------------------------------------------------------------------


class TestMigrateLegacyAuth:
    def test_migrate_anthropic_api_key(self):
        legacy = {
            "provider": "anthropic",
            "access_token": "sk-ant-api03-testkey",
            "refresh_token": "",
            "expires_at": 0,
        }
        auth.LEGACY_AUTH_FILE.write_text(json.dumps(legacy), encoding="utf-8")

        auth._migrate_legacy_auth()

        profiles = auth.load_profiles()
        assert "anthropic:default" in profiles
        assert profiles["anthropic:default"]["type"] == "api_key"
        assert profiles["anthropic:default"]["key"] == "sk-ant-api03-testkey"

        # Legacy file renamed
        assert not auth.LEGACY_AUTH_FILE.exists()
        assert auth.LEGACY_AUTH_FILE.with_suffix(".json.bak").exists()

    def test_migrate_anthropic_setup_token(self):
        legacy = {
            "provider": "anthropic",
            "access_token": "sk-ant-oat01-subscriptiontoken",
            "refresh_token": "",
            "expires_at": 0,
        }
        auth.LEGACY_AUTH_FILE.write_text(json.dumps(legacy), encoding="utf-8")

        auth._migrate_legacy_auth()

        profiles = auth.load_profiles()
        assert "anthropic:subscription" in profiles
        assert profiles["anthropic:subscription"]["type"] == "token"
        assert profiles["anthropic:subscription"]["access"] == "sk-ant-oat01-subscriptiontoken"

    def test_migrate_openai_api_key(self):
        legacy = {
            "provider": "openai",
            "access_token": "sk-proj-testkey",
            "refresh_token": "",
            "expires_at": 0,
        }
        auth.LEGACY_AUTH_FILE.write_text(json.dumps(legacy), encoding="utf-8")

        auth._migrate_legacy_auth()

        profiles = auth.load_profiles()
        assert "openai:default" in profiles
        assert profiles["openai:default"]["type"] == "api_key"
        assert profiles["openai:default"]["key"] == "sk-proj-testkey"

    def test_migration_skipped_if_profiles_exist(self):
        # Pre-existing profiles file
        auth.save_profile("existing:profile", {"type": "api_key", "provider": "x", "key": "k"})

        # Legacy file with different data
        legacy = {
            "provider": "anthropic",
            "access_token": "sk-ant-api03-should-not-appear",
            "refresh_token": "",
            "expires_at": 0,
        }
        auth.LEGACY_AUTH_FILE.write_text(json.dumps(legacy), encoding="utf-8")

        auth._migrate_legacy_auth()

        profiles = auth.load_profiles()
        assert "anthropic:default" not in profiles
        assert "existing:profile" in profiles
        # Legacy file should NOT be renamed
        assert auth.LEGACY_AUTH_FILE.exists()

    def test_migration_skipped_if_no_legacy_file(self):
        auth._migrate_legacy_auth()
        assert not auth.AUTH_PROFILES_FILE.exists()

    def test_corrupted_legacy_file_does_not_crash(self):
        auth.LEGACY_AUTH_FILE.write_text("not valid json{{{", encoding="utf-8")
        auth._migrate_legacy_auth()
        assert not auth.AUTH_PROFILES_FILE.exists()


# ---------------------------------------------------------------------------
# Corrupted profiles file
# ---------------------------------------------------------------------------


class TestCorruptedProfiles:
    def test_corrupted_json_returns_empty(self):
        auth.AUTH_PROFILES_FILE.parent.mkdir(parents=True, exist_ok=True)
        auth.AUTH_PROFILES_FILE.write_text("{bad json", encoding="utf-8")
        assert auth.load_profiles() == {}

    def test_missing_profiles_key_returns_empty(self):
        auth.AUTH_PROFILES_FILE.parent.mkdir(parents=True, exist_ok=True)
        auth.AUTH_PROFILES_FILE.write_text(json.dumps({"version": 1}), encoding="utf-8")
        assert auth.load_profiles() == {}

    def test_profiles_not_dict_returns_empty(self):
        auth.AUTH_PROFILES_FILE.parent.mkdir(parents=True, exist_ok=True)
        auth.AUTH_PROFILES_FILE.write_text(
            json.dumps({"version": 1, "profiles": "string"}),
            encoding="utf-8",
        )
        assert auth.load_profiles() == {}


# ---------------------------------------------------------------------------
# Backward-compat: load_auth / _save_auth delegates
# ---------------------------------------------------------------------------


class TestBackwardCompat:
    def test_save_auth_delegates_to_save_profile(self):
        auth._save_auth(
            {
                "provider": "openai",
                "access_token": "sk-proj-compat",
                "refresh_token": "",
                "expires_at": 0,
            }
        )
        profiles = auth.load_profiles()
        assert "openai:default" in profiles
        assert profiles["openai:default"]["key"] == "sk-proj-compat"

    def test_load_auth_returns_legacy_shape(self):
        auth.save_profile(
            "anthropic:default",
            {
                "type": "api_key",
                "provider": "anthropic",
                "key": "sk-ant-api03-x",
            },
        )
        result = auth.load_auth()
        assert result is not None
        assert result["provider"] == "anthropic"
        assert result["access_token"] == "sk-ant-api03-x"
        assert "refresh_token" in result
        assert "expires_at" in result

    def test_load_auth_empty_when_no_profiles(self):
        assert auth.load_auth() is None

    def test_load_auth_triggers_migration(self):
        legacy = {
            "provider": "anthropic",
            "access_token": "sk-ant-api03-migrated",
            "refresh_token": "",
            "expires_at": 0,
        }
        auth.LEGACY_AUTH_FILE.write_text(json.dumps(legacy), encoding="utf-8")

        result = auth.load_auth()
        assert result is not None
        assert result["access_token"] == "sk-ant-api03-migrated"


# ---------------------------------------------------------------------------
# remove_auth
# ---------------------------------------------------------------------------


class TestRemoveAuth:
    def test_remove_auth_deletes_profiles_file(self):
        auth.save_profile("a:b", {"type": "api_key", "provider": "a", "key": "k"})
        assert auth.remove_auth() is True
        assert not auth.AUTH_PROFILES_FILE.exists()

    def test_remove_auth_returns_false_when_missing(self):
        assert auth.remove_auth() is False


# ---------------------------------------------------------------------------
# get_auth_status
# ---------------------------------------------------------------------------


class TestGetAuthStatus:
    def test_status_with_profile(self):
        auth.save_profile(
            "anthropic:default",
            {
                "type": "api_key",
                "provider": "anthropic",
                "key": "sk-ant-api03-x",
            },
        )
        status = auth.get_auth_status()
        assert status["authenticated"] is True
        assert status["provider"] == "anthropic"
        assert "profile_count" in status

    def test_status_env_var_fallback(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-env")
        status = auth.get_auth_status()
        assert status["authenticated"] is True
        assert status["method"] == "env:ANTHROPIC_API_KEY"

    def test_status_no_auth(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        status = auth.get_auth_status()
        assert status["authenticated"] is False


# ---------------------------------------------------------------------------
# get_access_token
# ---------------------------------------------------------------------------


class TestGetAccessToken:
    def test_token_from_profile(self):
        auth.save_profile(
            "anthropic:default",
            {
                "type": "api_key",
                "provider": "anthropic",
                "key": "sk-ant-api03-stored",
            },
        )
        result = auth.get_access_token()
        assert result == ("sk-ant-api03-stored", "anthropic")

    def test_token_from_env(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-env")
        result = auth.get_access_token()
        assert result == ("sk-ant-api03-env", "anthropic")

    def test_no_token_returns_none(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        assert auth.get_access_token() is None

    def test_profile_preferred_over_env(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-env")
        auth.save_profile(
            "anthropic:default",
            {
                "type": "api_key",
                "provider": "anthropic",
                "key": "sk-stored",
            },
        )
        result = auth.get_access_token()
        assert result == ("sk-stored", "anthropic")

    def test_token_triggers_migration(self):
        legacy = {
            "provider": "openai",
            "access_token": "sk-proj-legacy",
            "refresh_token": "",
            "expires_at": 0,
        }
        auth.LEGACY_AUTH_FILE.write_text(json.dumps(legacy), encoding="utf-8")
        result = auth.get_access_token()
        assert result == ("sk-proj-legacy", "openai")


# ---------------------------------------------------------------------------
# AUTH_FILE alias
# ---------------------------------------------------------------------------


class TestAuthFileAlias:
    def test_auth_file_equals_profiles_file(self):
        """Ensure AUTH_FILE is the same object as AUTH_PROFILES_FILE for backward compat."""
        assert auth.AUTH_FILE is auth.AUTH_PROFILES_FILE
