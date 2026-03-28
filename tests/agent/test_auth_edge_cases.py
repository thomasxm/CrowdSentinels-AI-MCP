"""Edge case tests for auth system robustness."""

import json
from unittest.mock import patch

import pytest


@pytest.fixture
def isolated_auth(tmp_path):
    pf = tmp_path / "auth-profiles.json"
    legacy = tmp_path / "auth.json"
    return pf, legacy


class TestEdgeCases:
    def test_concurrent_profile_writes(self, isolated_auth):
        """Two rapid writes should not corrupt the file."""
        pf, _ = isolated_auth
        from src.agent.auth import load_profiles, save_profile

        with patch("src.agent.auth.AUTH_PROFILES_FILE", pf):
            save_profile("a:default", {"type": "api_key", "provider": "a", "key": "k1"})
            save_profile("b:default", {"type": "api_key", "provider": "b", "key": "k2"})
            profiles = load_profiles()
            assert len(profiles) == 2

    def test_auth_file_deleted_mid_session(self, isolated_auth):
        pf, _ = isolated_auth
        from src.agent.auth import load_profiles, save_profile

        with patch("src.agent.auth.AUTH_PROFILES_FILE", pf):
            save_profile("x:default", {"type": "api_key", "provider": "x", "key": "k"})
            pf.unlink()
            assert load_profiles() == {}

    def test_get_access_token_anthropic_wins(self, isolated_auth, monkeypatch):
        """With both providers, anthropic should be preferred."""
        pf, legacy = isolated_auth
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        from src.agent.auth import get_access_token, save_profile

        with patch("src.agent.auth.AUTH_PROFILES_FILE", pf), patch("src.agent.auth.LEGACY_AUTH_FILE", legacy):
            save_profile(
                "anthropic:default",
                {
                    "type": "api_key",
                    "provider": "anthropic",
                    "key": "sk-ant-test",
                },
            )
            save_profile(
                "openai:default",
                {
                    "type": "api_key",
                    "provider": "openai",
                    "key": "sk-proj-test",
                },
            )
            token, provider = get_access_token()
            assert provider == "anthropic"
            assert token == "sk-ant-test"

    def test_get_access_token_env_var_fallback(self, isolated_auth, monkeypatch):
        pf, legacy = isolated_auth
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.setenv("OPENAI_API_KEY", "sk-env")
        with patch("src.agent.auth.AUTH_PROFILES_FILE", pf), patch("src.agent.auth.LEGACY_AUTH_FILE", legacy):
            from src.agent.auth import get_access_token

            token, provider = get_access_token()
            assert provider == "openai"

    def test_remove_auth_clears_all_profiles(self, isolated_auth):
        pf, _ = isolated_auth
        from src.agent.auth import load_profiles, remove_auth, save_profile

        with patch("src.agent.auth.AUTH_PROFILES_FILE", pf):
            save_profile("a:1", {"type": "api_key", "provider": "a", "key": "k"})
            save_profile("b:2", {"type": "api_key", "provider": "b", "key": "k"})
            assert remove_auth() is True
            assert load_profiles() == {}

    def test_oauth_empty_access_skipped(self, isolated_auth, monkeypatch):
        """OAuth profile with empty access token should be skipped."""
        pf, legacy = isolated_auth
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        from src.agent.auth import get_access_token, save_profile

        with patch("src.agent.auth.AUTH_PROFILES_FILE", pf), patch("src.agent.auth.LEGACY_AUTH_FILE", legacy):
            save_profile(
                "openai-codex:default",
                {
                    "type": "oauth",
                    "provider": "openai-codex",
                    "access": "",
                    "refresh": "rt",
                    "expires": 0,
                },
            )
            result = get_access_token()
            assert result is None


class TestSecurityEdgeCases:
    def test_profiles_file_permissions(self, isolated_auth):
        pf, _ = isolated_auth
        from src.agent.auth import save_profile

        with patch("src.agent.auth.AUTH_PROFILES_FILE", pf):
            save_profile("x:default", {"type": "api_key", "provider": "x", "key": "secret"})
            mode = oct(pf.stat().st_mode & 0o777)
            assert mode == "0o600"

    def test_legacy_backup_preserves_content(self, isolated_auth):
        pf, legacy = isolated_auth
        legacy.parent.mkdir(parents=True, exist_ok=True)
        original = {
            "provider": "anthropic",
            "access_token": "sk-ant-oat01-orig",
            "refresh_token": "",
            "expires_at": 0,
        }
        legacy.write_text(json.dumps(original))
        from src.agent.auth import _migrate_legacy_auth

        with patch("src.agent.auth.AUTH_PROFILES_FILE", pf), patch("src.agent.auth.LEGACY_AUTH_FILE", legacy):
            _migrate_legacy_auth()
            bak = legacy.with_suffix(".json.bak")
            assert bak.exists()
            assert json.loads(bak.read_text())["access_token"] == "sk-ant-oat01-orig"


class TestMigrationEdgeCases:
    def test_migration_of_openai_legacy_token(self, isolated_auth):
        """Legacy OpenAI tokens should migrate as api_key type."""
        pf, legacy = isolated_auth
        legacy.parent.mkdir(parents=True, exist_ok=True)
        legacy.write_text(
            json.dumps(
                {
                    "provider": "openai",
                    "access_token": "sk-proj-legacykey123",
                    "refresh_token": "",
                    "expires_at": 0,
                }
            )
        )
        from src.agent.auth import _migrate_legacy_auth, load_profiles

        with patch("src.agent.auth.AUTH_PROFILES_FILE", pf), patch("src.agent.auth.LEGACY_AUTH_FILE", legacy):
            _migrate_legacy_auth()
            profiles = load_profiles()
            assert profiles["openai:default"]["type"] == "api_key"
            assert profiles["openai:default"]["key"] == "sk-proj-legacykey123"

    def test_migration_of_anthropic_setup_token(self, isolated_auth):
        """Legacy Anthropic setup-tokens (sk-ant-oat01-*) should migrate as token type."""
        pf, legacy = isolated_auth
        legacy.parent.mkdir(parents=True, exist_ok=True)
        legacy.write_text(
            json.dumps(
                {
                    "provider": "anthropic",
                    "access_token": "sk-ant-oat01-setuptoken",
                    "refresh_token": "",
                    "expires_at": 0,
                }
            )
        )
        from src.agent.auth import _migrate_legacy_auth, load_profiles

        with patch("src.agent.auth.AUTH_PROFILES_FILE", pf), patch("src.agent.auth.LEGACY_AUTH_FILE", legacy):
            _migrate_legacy_auth()
            profiles = load_profiles()
            assert profiles["anthropic:subscription"]["type"] == "token"
            assert profiles["anthropic:subscription"]["access"] == "sk-ant-oat01-setuptoken"

    def test_migration_skipped_when_profiles_exist(self, isolated_auth):
        """Migration should not run when auth-profiles.json already exists."""
        pf, legacy = isolated_auth
        from src.agent.auth import _migrate_legacy_auth, load_profiles, save_profile

        with patch("src.agent.auth.AUTH_PROFILES_FILE", pf), patch("src.agent.auth.LEGACY_AUTH_FILE", legacy):
            # Create profiles file first
            save_profile(
                "existing:one",
                {
                    "type": "api_key",
                    "provider": "existing",
                    "key": "k",
                },
            )
            # Create legacy file with different data
            legacy.parent.mkdir(parents=True, exist_ok=True)
            legacy.write_text(
                json.dumps(
                    {
                        "provider": "anthropic",
                        "access_token": "sk-ant-api03-shouldnotmigrate",
                        "refresh_token": "",
                        "expires_at": 0,
                    }
                )
            )
            _migrate_legacy_auth()
            profiles = load_profiles()
            assert "anthropic:default" not in profiles
            assert "existing:one" in profiles

    def test_migration_of_unknown_provider(self, isolated_auth):
        """Unknown providers should migrate with a generic profile id."""
        pf, legacy = isolated_auth
        legacy.parent.mkdir(parents=True, exist_ok=True)
        legacy.write_text(
            json.dumps(
                {
                    "provider": "custom-llm",
                    "access_token": "custom-token-123",
                    "refresh_token": "",
                    "expires_at": 0,
                }
            )
        )
        from src.agent.auth import _migrate_legacy_auth, load_profiles

        with patch("src.agent.auth.AUTH_PROFILES_FILE", pf), patch("src.agent.auth.LEGACY_AUTH_FILE", legacy):
            _migrate_legacy_auth()
            profiles = load_profiles()
            assert "custom-llm:default" in profiles
            assert profiles["custom-llm:default"]["type"] == "api_key"
            assert profiles["custom-llm:default"]["key"] == "custom-token-123"
