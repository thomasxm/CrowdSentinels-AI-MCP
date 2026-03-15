# src/wireshark/baseline/baseline_store.py
"""Baseline storage and persistence."""
import json
import logging
from pathlib import Path
from typing import Any

from src.wireshark.config import get_baselines_path

logger = logging.getLogger(__name__)


class BaselineStore:
    """Store and retrieve baselines."""

    def __init__(self, baselines_dir: Path | None = None):
        """Initialize store with directory path."""
        self.baselines_dir = baselines_dir or get_baselines_path()
        self.baselines_dir.mkdir(parents=True, exist_ok=True)

    def _get_baseline_path(self, name: str) -> Path:
        """Get path for a baseline file."""
        # Sanitize name for filesystem
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)
        return self.baselines_dir / f"{safe_name}.json"

    def save(self, name: str, baseline: dict[str, Any]) -> Path:
        """Save baseline to file.

        Args:
            name: Baseline name
            baseline: Baseline dictionary

        Returns:
            Path to saved file
        """
        path = self._get_baseline_path(name)

        # Ensure name is in baseline
        baseline["name"] = name

        path.write_text(json.dumps(baseline, indent=2, default=str))
        logger.info(f"Saved baseline '{name}' to {path}")

        return path

    def load(self, name: str) -> dict[str, Any] | None:
        """Load baseline from file.

        Args:
            name: Baseline name

        Returns:
            Baseline dictionary or None if not found
        """
        path = self._get_baseline_path(name)

        if not path.exists():
            logger.warning(f"Baseline '{name}' not found at {path}")
            return None

        try:
            return json.loads(path.read_text())
        except json.JSONDecodeError as e:
            logger.error(f"Failed to load baseline '{name}': {e}")
            return None

    def list_baselines(self) -> list[str]:
        """List all saved baselines.

        Returns:
            List of baseline names
        """
        baselines = []
        for path in self.baselines_dir.glob("*.json"):
            baselines.append(path.stem)
        return sorted(baselines)

    def delete(self, name: str) -> bool:
        """Delete a baseline.

        Args:
            name: Baseline name

        Returns:
            True if deleted, False if not found
        """
        path = self._get_baseline_path(name)

        if path.exists():
            path.unlink()
            logger.info(f"Deleted baseline '{name}'")
            return True

        return False

    def get_default_baseline(self) -> dict[str, Any] | None:
        """Get the default baseline if it exists."""
        return self.load("default")

    def set_default_baseline(self, name: str) -> bool:
        """Set a baseline as the default.

        Args:
            name: Name of baseline to set as default

        Returns:
            True if successful
        """
        baseline = self.load(name)
        if baseline is None:
            return False

        self.save("default", baseline)
        return True
