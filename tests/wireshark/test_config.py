# tests/wireshark/test_config.py
"""Tests for Wireshark module configuration."""


class TestWiresharkConfig:
    """Test configuration management."""

    def test_default_config_has_required_fields(self):
        """Default config should have all required fields."""
        from src.wireshark.config import WiresharkConfig, get_default_config

        config = get_default_config()

        assert isinstance(config, WiresharkConfig)
        assert config.tshark_path is not None
        assert config.auto_capture.enabled is True
        assert config.auto_capture.min_confidence >= 1
        assert config.auto_capture.min_confidence <= 10

    def test_config_storage_path_created(self):
        """Config should create storage directory if missing."""
        from src.wireshark.config import get_storage_path

        path = get_storage_path()

        assert path.exists()
        assert path.is_dir()

    def test_auto_capture_thresholds_valid(self):
        """Auto-capture thresholds should be within valid ranges."""
        from src.wireshark.config import get_default_config

        config = get_default_config()

        assert 1 <= config.auto_capture.min_confidence <= 10
        assert config.auto_capture.min_occurrences >= 1
        assert 1 <= config.auto_capture.min_pyramid_priority <= 6
