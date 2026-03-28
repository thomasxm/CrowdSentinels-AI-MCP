# src/wireshark/config.py
"""Wireshark module configuration."""

import json
import shutil
from pathlib import Path

from pydantic import BaseModel, Field


class AutoCaptureConfig(BaseModel):
    """Configuration for automatic IoC capture."""

    enabled: bool = True
    min_confidence: int = Field(default=7, ge=1, le=10)
    min_occurrences: int = Field(default=3, ge=1)
    auto_capture_types: list[str] = Field(default=["ip", "domain", "hash", "user", "process"])
    skip_internal_ips: bool = True
    min_pyramid_priority: int = Field(default=2, ge=1, le=6)
    ignore_domains: list[str] = Field(default=["microsoft.com", "windows.com", "google.com", "googleapis.com"])
    ignore_ports: list[int] = Field(default=[80, 443, 53])


class ArtifactStorageConfig(BaseModel):
    """Configuration for extracted artifact storage."""

    store_locally: bool = False
    prompted: bool = False


class WiresharkConfig(BaseModel):
    """Main Wireshark module configuration."""

    tshark_path: str = Field(default_factory=lambda: shutil.which("tshark") or "/usr/bin/tshark")
    auto_capture: AutoCaptureConfig = Field(default_factory=AutoCaptureConfig)
    artifact_storage: ArtifactStorageConfig = Field(default_factory=ArtifactStorageConfig)
    active_baseline: str | None = None


def get_storage_path() -> Path:
    """Get the Wireshark module storage path, creating if needed."""
    path = Path.home() / ".crowdsentinel" / "wireshark"
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_baselines_path() -> Path:
    """Get the baselines storage path."""
    path = get_storage_path() / "baselines"
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_config_file_path() -> Path:
    """Get path to config file."""
    return get_storage_path() / "config.json"


def get_default_config() -> WiresharkConfig:
    """Get default configuration."""
    return WiresharkConfig()


def load_config() -> WiresharkConfig:
    """Load configuration from file or return defaults."""
    config_path = get_config_file_path()
    if config_path.exists():
        try:
            data = json.loads(config_path.read_text())
            return WiresharkConfig(**data)
        except (json.JSONDecodeError, ValueError):
            pass
    return get_default_config()


def save_config(config: WiresharkConfig) -> None:
    """Save configuration to file."""
    config_path = get_config_file_path()
    config_path.write_text(config.model_dump_json(indent=2))
