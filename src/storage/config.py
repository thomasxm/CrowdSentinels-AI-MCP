"""Storage configuration for investigation state management."""

import os
import json
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field, asdict


@dataclass
class StorageSettings:
    """Storage limit and management settings."""
    max_size_gb: float = 8.0
    compact_after_days: int = 7
    max_investigations: int = 100
    max_iocs_per_investigation: int = 1000


@dataclass
class ExtractionSettings:
    """Smart extraction settings for token efficiency."""
    max_events_to_keep: int = 100
    max_timeline_entries: int = 50
    max_iocs_in_summary: int = 20
    compress_after_days: int = 3


@dataclass
class ProgressiveDisclosureSettings:
    """Progressive disclosure settings for session start."""
    enabled: bool = True
    max_investigations_shown: int = 10
    show_on_session_start: bool = True


@dataclass
class StorageConfig:
    """Main storage configuration."""

    # Base storage path
    base_path: Path = field(default_factory=lambda: Path.home() / ".crowdsentinel")

    # Sub-settings
    storage: StorageSettings = field(default_factory=StorageSettings)
    extraction: ExtractionSettings = field(default_factory=ExtractionSettings)
    progressive_disclosure: ProgressiveDisclosureSettings = field(
        default_factory=ProgressiveDisclosureSettings
    )

    # Computed paths
    @property
    def investigations_path(self) -> Path:
        """Path to investigations directory."""
        return self.base_path / "investigations"

    @property
    def config_file_path(self) -> Path:
        """Path to config.json file."""
        return self.base_path / "config.json"

    @property
    def index_file_path(self) -> Path:
        """Path to master index.json file."""
        return self.investigations_path / "index.json"

    @property
    def storage_stats_path(self) -> Path:
        """Path to storage_stats.json file."""
        return self.base_path / "storage_stats.json"

    @property
    def max_size_bytes(self) -> int:
        """Maximum storage size in bytes."""
        return int(self.storage.max_size_gb * 1024 * 1024 * 1024)

    def ensure_directories(self) -> None:
        """Create required directories if they don't exist."""
        self.base_path.mkdir(parents=True, exist_ok=True)
        self.investigations_path.mkdir(parents=True, exist_ok=True)

    def save(self) -> None:
        """Save configuration to config.json."""
        self.ensure_directories()
        config_dict = {
            "storage": asdict(self.storage),
            "extraction": asdict(self.extraction),
            "progressive_disclosure": asdict(self.progressive_disclosure),
        }
        self.config_file_path.write_text(json.dumps(config_dict, indent=2))

    @classmethod
    def load(cls, base_path: Optional[Path] = None) -> "StorageConfig":
        """Load configuration from environment and config file."""
        # Determine base path
        env_path = os.environ.get("CROWDSENTINEL_STORAGE_PATH")
        if env_path:
            base_path = Path(env_path)
        elif base_path is None:
            base_path = Path.home() / ".crowdsentinel"

        config = cls(base_path=base_path)

        # Load from environment variables
        if os.environ.get("CROWDSENTINEL_MAX_STORAGE_GB"):
            config.storage.max_size_gb = float(
                os.environ["CROWDSENTINEL_MAX_STORAGE_GB"]
            )

        if os.environ.get("CROWDSENTINEL_COMPACT_AFTER_DAYS"):
            config.storage.compact_after_days = int(
                os.environ["CROWDSENTINEL_COMPACT_AFTER_DAYS"]
            )

        if os.environ.get("CROWDSENTINEL_MAX_IOCS"):
            config.storage.max_iocs_per_investigation = int(
                os.environ["CROWDSENTINEL_MAX_IOCS"]
            )

        if os.environ.get("CROWDSENTINEL_PROGRESSIVE_DISCLOSURE"):
            config.progressive_disclosure.enabled = (
                os.environ["CROWDSENTINEL_PROGRESSIVE_DISCLOSURE"].lower() == "true"
            )

        # Load from config file if exists
        if config.config_file_path.exists():
            try:
                file_config = json.loads(config.config_file_path.read_text())

                if "storage" in file_config:
                    for key, value in file_config["storage"].items():
                        if hasattr(config.storage, key):
                            setattr(config.storage, key, value)

                if "extraction" in file_config:
                    for key, value in file_config["extraction"].items():
                        if hasattr(config.extraction, key):
                            setattr(config.extraction, key, value)

                if "progressive_disclosure" in file_config:
                    for key, value in file_config["progressive_disclosure"].items():
                        if hasattr(config.progressive_disclosure, key):
                            setattr(config.progressive_disclosure, key, value)
            except (json.JSONDecodeError, KeyError):
                pass  # Use defaults if config file is invalid

        return config


# Global default config instance
_default_config: Optional[StorageConfig] = None


def get_config() -> StorageConfig:
    """Get the global storage configuration."""
    global _default_config
    if _default_config is None:
        _default_config = StorageConfig.load()
    return _default_config


def set_config(config: StorageConfig) -> None:
    """Set the global storage configuration."""
    global _default_config
    _default_config = config
