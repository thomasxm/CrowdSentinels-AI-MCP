"""Tests for lazy token refresh with file locking."""
import time
import pytest
from unittest.mock import patch


@pytest.fixture
def tmp_profiles(tmp_path):
    return tmp_path / "auth-profiles.json"


class TestLazyRefresh:
    def test_no_refresh_for_api_key(self, tmp_profiles):
        """API key profiles should never be refreshed."""
        from src.agent.auth import save_profile, refresh_if_needed
        with patch("src.agent.auth.AUTH_PROFILES_FILE", tmp_profiles):
            save_profile("openai:default", {
                "type": "api_key", "provider": "openai", "key": "sk-test"
            })
            result = refresh_if_needed("openai:default")
            assert result["type"] == "api_key"

    def test_no_refresh_for_non_expired_oauth(self, tmp_profiles):
        """OAuth tokens not near expiry should not be refreshed."""
        from src.agent.auth import save_profile, refresh_if_needed
        future_ms = int((time.time() + 3600) * 1000)
        with patch("src.agent.auth.AUTH_PROFILES_FILE", tmp_profiles):
            save_profile("openai-codex:default", {
                "type": "oauth", "provider": "openai-codex",
                "access": "eyJvalid", "refresh": "rt_test",
                "expires": future_ms,
            })
            with patch("src.agent.oauth_pkce.refresh_access_token") as mock_refresh:
                result = refresh_if_needed("openai-codex:default")
                mock_refresh.assert_not_called()
                assert result["access"] == "eyJvalid"

    def test_refresh_for_expired_oauth(self, tmp_profiles):
        """OAuth tokens near expiry should be refreshed."""
        from src.agent.auth import save_profile, refresh_if_needed
        expired_ms = int((time.time() - 60) * 1000)
        with patch("src.agent.auth.AUTH_PROFILES_FILE", tmp_profiles):
            save_profile("openai-codex:default", {
                "type": "oauth", "provider": "openai-codex",
                "access": "eyJold", "refresh": "rt_old",
                "expires": expired_ms,
            })
            new_tokens = {
                "access_token": "eyJnew",
                "refresh_token": "rt_new",
                "expires_in": 3600,
            }
            with patch("src.agent.oauth_pkce.refresh_access_token", return_value=new_tokens):
                result = refresh_if_needed("openai-codex:default")
                assert result["access"] == "eyJnew"
                assert result["refresh"] == "rt_new"

    def test_no_refresh_for_setup_token(self, tmp_profiles):
        """Anthropic setup-tokens (type: token) should not be refreshed via OAuth."""
        from src.agent.auth import save_profile, refresh_if_needed
        with patch("src.agent.auth.AUTH_PROFILES_FILE", tmp_profiles):
            save_profile("anthropic:subscription", {
                "type": "token", "provider": "anthropic",
                "access": "sk-ant-oat01-test", "expires": 0,
            })
            result = refresh_if_needed("anthropic:subscription")
            assert result["access"] == "sk-ant-oat01-test"

    def test_refresh_failure_returns_existing(self, tmp_profiles):
        """If refresh fails, return existing profile (don't crash)."""
        from src.agent.auth import save_profile, refresh_if_needed
        expired_ms = int((time.time() - 60) * 1000)
        with patch("src.agent.auth.AUTH_PROFILES_FILE", tmp_profiles):
            save_profile("openai-codex:default", {
                "type": "oauth", "provider": "openai-codex",
                "access": "eyJold", "refresh": "rt_old",
                "expires": expired_ms,
            })
            with patch("src.agent.oauth_pkce.refresh_access_token",
                       side_effect=Exception("network error")):
                result = refresh_if_needed("openai-codex:default")
                assert result["access"] == "eyJold"

    def test_refresh_updates_file_on_disk(self, tmp_profiles):
        """After refresh, re-reading the file should show new tokens."""
        from src.agent.auth import save_profile, refresh_if_needed, load_profiles
        expired_ms = int((time.time() - 60) * 1000)
        with patch("src.agent.auth.AUTH_PROFILES_FILE", tmp_profiles):
            save_profile("openai-codex:default", {
                "type": "oauth", "provider": "openai-codex",
                "access": "eyJold", "refresh": "rt_old", "expires": expired_ms,
            })
            new_tokens = {
                "access_token": "eyJpersisted",
                "refresh_token": "rt_persisted",
                "expires_in": 7200,
            }
            with patch("src.agent.oauth_pkce.refresh_access_token", return_value=new_tokens):
                refresh_if_needed("openai-codex:default")
                profiles = load_profiles()
                assert profiles["openai-codex:default"]["access"] == "eyJpersisted"

    def test_refresh_nonexistent_profile_returns_empty(self, tmp_profiles):
        from src.agent.auth import refresh_if_needed
        with patch("src.agent.auth.AUTH_PROFILES_FILE", tmp_profiles):
            assert refresh_if_needed("nonexistent:profile") == {}

    def test_refresh_oauth_without_refresh_token(self, tmp_profiles):
        """OAuth profile missing refresh token should not attempt refresh."""
        from src.agent.auth import save_profile, refresh_if_needed
        expired_ms = int((time.time() - 60) * 1000)
        with patch("src.agent.auth.AUTH_PROFILES_FILE", tmp_profiles):
            save_profile("openai-codex:default", {
                "type": "oauth", "provider": "openai-codex",
                "access": "eyJold", "refresh": "", "expires": expired_ms,
            })
            with patch("src.agent.oauth_pkce.refresh_access_token") as mock:
                result = refresh_if_needed("openai-codex:default")
                mock.assert_not_called()
                assert result["access"] == "eyJold"
