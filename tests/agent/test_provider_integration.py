"""Integration tests: auth profiles -> create_provider() -> correct provider type."""
import json
import time

import pytest
from unittest.mock import patch


@pytest.fixture
def isolated_auth(tmp_path, monkeypatch):
    """Isolate auth from real ~/.crowdsentinel and env vars."""
    profiles_file = tmp_path / "auth-profiles.json"
    legacy_file = tmp_path / "auth.json"
    monkeypatch.setattr("src.agent.auth.AUTH_PROFILES_FILE", profiles_file)
    monkeypatch.setattr("src.agent.auth.LEGACY_AUTH_FILE", legacy_file)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("CROWDSENTINEL_MODEL", raising=False)
    monkeypatch.delenv("CROWDSENTINEL_MODEL_URL", raising=False)
    return profiles_file, legacy_file


class TestProviderFromProfiles:
    def test_anthropic_api_key_profile(self, isolated_auth):
        from src.agent.auth import save_profile
        from src.agent.providers import create_provider, AnthropicProvider

        save_profile("anthropic:default", {
            "type": "api_key", "provider": "anthropic", "key": "sk-ant-api03-test",
        })
        with patch("anthropic.Anthropic"):
            provider = create_provider()
            assert isinstance(provider, AnthropicProvider)

    def test_anthropic_setup_token_profile(self, isolated_auth):
        from src.agent.auth import save_profile
        from src.agent.providers import create_provider, AnthropicProvider

        save_profile("anthropic:subscription", {
            "type": "token", "provider": "anthropic",
            "access": "sk-ant-oat01-test", "expires": 0,
        })
        with patch("anthropic.Anthropic"):
            provider = create_provider()
            assert isinstance(provider, AnthropicProvider)

    def test_openai_api_key_profile(self, isolated_auth):
        from src.agent.auth import save_profile
        from src.agent.providers import create_provider, OpenAICompatibleProvider

        save_profile("openai:default", {
            "type": "api_key", "provider": "openai", "key": "sk-proj-test",
        })
        provider = create_provider()
        assert isinstance(provider, OpenAICompatibleProvider)

    def test_openai_oauth_profile_with_valid_token(self, isolated_auth):
        from src.agent.auth import save_profile
        from src.agent.providers import create_provider, OpenAICompatibleProvider

        future_ms = int((time.time() + 3600) * 1000)
        save_profile("openai-codex:default", {
            "type": "oauth", "provider": "openai-codex",
            "access": "eyJvalid", "refresh": "rt_test", "expires": future_ms,
        })
        provider = create_provider()
        assert isinstance(provider, OpenAICompatibleProvider)

    def test_env_var_fallback_anthropic(self, isolated_auth, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-env")
        from src.agent.providers import create_provider, AnthropicProvider

        with patch("anthropic.Anthropic"):
            provider = create_provider()
            assert isinstance(provider, AnthropicProvider)

    def test_env_var_fallback_openai(self, isolated_auth, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-env")
        from src.agent.providers import create_provider, OpenAICompatibleProvider

        provider = create_provider()
        assert isinstance(provider, OpenAICompatibleProvider)

    def test_no_auth_raises_runtime_error(self, isolated_auth):
        from src.agent.providers import create_provider

        with pytest.raises(RuntimeError, match="No LLM"):
            create_provider()

    def test_model_url_creates_openai_provider(self, isolated_auth, monkeypatch):
        from src.agent.auth import save_profile
        from src.agent.providers import create_provider, OpenAICompatibleProvider

        # Even with anthropic profile, model_url should force OpenAI-compatible
        save_profile("anthropic:default", {
            "type": "api_key", "provider": "anthropic", "key": "sk-ant-test",
        })
        provider = create_provider(model_url="http://localhost:11434/v1")
        assert isinstance(provider, OpenAICompatibleProvider)

    def test_profile_preferred_over_env_var(self, isolated_auth, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-env")
        from src.agent.auth import save_profile
        from src.agent.providers import create_provider, AnthropicProvider

        save_profile("anthropic:default", {
            "type": "api_key", "provider": "anthropic", "key": "sk-ant-profile",
        })
        with patch("anthropic.Anthropic"):
            provider = create_provider()
            assert isinstance(provider, AnthropicProvider)

    def test_legacy_migration_works_with_create_provider(self, isolated_auth):
        """Old auth.json auto-migrates and create_provider works."""
        _pf, legacy = isolated_auth
        legacy.parent.mkdir(parents=True, exist_ok=True)
        legacy.write_text(json.dumps({
            "provider": "openai", "access_token": "sk-proj-legacy",
            "refresh_token": "", "expires_at": 0,
        }))
        from src.agent.providers import create_provider, OpenAICompatibleProvider

        provider = create_provider()
        assert isinstance(provider, OpenAICompatibleProvider)


class TestOAuthRefreshInProvider:
    def test_expired_oauth_triggers_refresh(self, isolated_auth):
        """create_provider should lazy-refresh expired OAuth tokens."""
        from src.agent.auth import save_profile
        from src.agent.providers import create_provider, OpenAICompatibleProvider

        expired_ms = int((time.time() - 60) * 1000)
        save_profile("openai-codex:default", {
            "type": "oauth", "provider": "openai-codex",
            "access": "eyJold", "refresh": "rt_test", "expires": expired_ms,
        })
        new_tokens = {
            "access_token": "eyJnew",
            "refresh_token": "rt_new",
            "expires_in": 3600,
        }
        with patch("src.agent.oauth_pkce.refresh_access_token", return_value=new_tokens):
            provider = create_provider()
            assert isinstance(provider, OpenAICompatibleProvider)

    def test_refresh_failure_still_creates_provider(self, isolated_auth):
        """If refresh fails, use stale token rather than crash."""
        from src.agent.auth import save_profile
        from src.agent.providers import create_provider, OpenAICompatibleProvider

        expired_ms = int((time.time() - 60) * 1000)
        save_profile("openai-codex:default", {
            "type": "oauth", "provider": "openai-codex",
            "access": "eyJstale", "refresh": "rt_test", "expires": expired_ms,
        })
        with patch("src.agent.oauth_pkce.refresh_access_token", side_effect=Exception("network")):
            provider = create_provider()
            assert isinstance(provider, OpenAICompatibleProvider)
