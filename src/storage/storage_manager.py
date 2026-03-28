"""Storage manager for FIFO and size management of investigations."""

import json
import logging
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from src.storage.config import StorageConfig, get_config
from src.storage.models import (
    IndexEntry,
    InvestigationManifest,
    InvestigationStatus,
    MasterIndex,
)

logger = logging.getLogger(__name__)


class StorageManager:
    """Manages investigation storage with FIFO and size limits."""

    def __init__(self, config: StorageConfig | None = None):
        """Initialize the storage manager."""
        self.config = config or get_config()
        self.config.ensure_directories()
        self._index: MasterIndex | None = None

    @property
    def investigations_path(self) -> Path:
        """Get the investigations directory path."""
        return self.config.investigations_path

    @property
    def index(self) -> MasterIndex:
        """Get or load the master index."""
        if self._index is None:
            self._index = self._load_index()
        return self._index

    def _load_index(self) -> MasterIndex:
        """Load the master index from disk."""
        index_path = self.config.index_file_path

        if index_path.exists():
            try:
                data = json.loads(index_path.read_text())
                return MasterIndex.model_validate(data)
            except (json.JSONDecodeError, Exception) as e:
                logger.warning(f"Failed to load index, creating new: {e}")

        # Create new index
        index = MasterIndex(max_size_bytes=self.config.max_size_bytes)
        self._save_index(index)
        return index

    def _save_index(self, index: MasterIndex | None = None) -> None:
        """Save the master index to disk."""
        index = index or self._index
        if index is None:
            return

        self.config.ensure_directories()
        index_path = self.config.index_file_path
        index_path.write_text(index.model_dump_json(indent=2))

    def calculate_usage(self) -> int:
        """Calculate total storage used in bytes."""
        total = 0
        if not self.investigations_path.exists():
            return 0

        for item in self.investigations_path.iterdir():
            if item.is_dir():
                total += self._get_dir_size(item)
            elif item.is_file():
                total += item.stat().st_size

        return total

    def _get_dir_size(self, path: Path) -> int:
        """Calculate the size of a directory recursively."""
        total = 0
        try:
            for item in path.rglob("*"):
                if item.is_file():
                    total += item.stat().st_size
        except (PermissionError, OSError) as e:
            logger.warning(f"Error calculating size for {path}: {e}")
        return total

    def get_investigation_size(self, investigation_id: str) -> int:
        """Get the size of a specific investigation in bytes."""
        inv_path = self.investigations_path / investigation_id
        if not inv_path.exists():
            return 0
        return self._get_dir_size(inv_path)

    def get_investigation_path(self, investigation_id: str) -> Path:
        """Get the path to an investigation directory."""
        return self.investigations_path / investigation_id

    def investigation_exists(self, investigation_id: str) -> bool:
        """Check if an investigation exists."""
        return self.get_investigation_path(investigation_id).exists()

    def create_investigation_dir(self, investigation_id: str) -> Path:
        """Create directory structure for a new investigation."""
        inv_path = self.investigations_path / investigation_id

        # Create main directory and subdirectories
        inv_path.mkdir(parents=True, exist_ok=True)
        (inv_path / "iocs").mkdir(exist_ok=True)
        (inv_path / "timeline").mkdir(exist_ok=True)
        (inv_path / "sources").mkdir(exist_ok=True)
        (inv_path / "artifacts").mkdir(exist_ok=True)

        return inv_path

    def delete_investigation(self, investigation_id: str) -> bool:
        """Delete an investigation and remove from index."""
        inv_path = self.get_investigation_path(investigation_id)

        if inv_path.exists():
            try:
                shutil.rmtree(inv_path)
                logger.info(f"Deleted investigation: {investigation_id}")
            except (PermissionError, OSError) as e:
                logger.error(f"Failed to delete investigation {investigation_id}: {e}")
                return False

        # Remove from index
        self.index.remove_investigation(investigation_id)
        self._save_index()
        return True

    def enforce_limit(self) -> list[str]:
        """
        Enforce storage limit using FIFO.

        Returns:
            List of deleted investigation IDs
        """
        deleted = []
        current_size = self.calculate_usage()
        max_size = self.config.max_size_bytes

        while current_size > max_size:
            # Get oldest investigation
            oldest = self.index.get_oldest()
            if not oldest:
                break

            # Skip if it's the only active investigation
            active_count = len([inv for inv in self.index.investigations if inv.status == InvestigationStatus.ACTIVE])
            if active_count <= 1 and oldest.status == InvestigationStatus.ACTIVE:
                logger.warning("Cannot delete: only one active investigation remaining")
                break

            # Delete oldest
            if self.delete_investigation(oldest.id):
                deleted.append(oldest.id)
                logger.info(f"FIFO: Deleted oldest investigation {oldest.id}")

            # Recalculate
            current_size = self.calculate_usage()

        return deleted

    def prune_oldest(self, count: int = 1) -> list[str]:
        """
        Delete the N oldest investigations.

        Args:
            count: Number of investigations to delete

        Returns:
            List of deleted investigation IDs
        """
        deleted = []

        # Sort by updated_at ascending
        sorted_inv = sorted(self.index.investigations, key=lambda x: x.updated_at)

        for entry in sorted_inv[:count]:
            if self.delete_investigation(entry.id):
                deleted.append(entry.id)

        return deleted

    def compact_investigation(self, investigation_id: str) -> int:
        """
        Compact an investigation to save space.

        Removes detailed event data, keeps only summaries and IoCs.

        Args:
            investigation_id: Investigation to compact

        Returns:
            Bytes saved
        """
        inv_path = self.get_investigation_path(investigation_id)
        if not inv_path.exists():
            return 0

        original_size = self._get_dir_size(inv_path)

        # Compact timeline - keep only first/last 10 events
        timeline_path = inv_path / "timeline" / "events.json"
        if timeline_path.exists():
            try:
                events = json.loads(timeline_path.read_text())
                if isinstance(events, dict) and "events" in events:
                    all_events = events.get("events", [])
                    compacted = {
                        "total_events": len(all_events),
                        "first_events": all_events[:10],
                        "last_events": all_events[-10:] if len(all_events) > 10 else [],
                        "compacted": True,
                        "compacted_at": datetime.utcnow().isoformat(),
                    }
                    timeline_path.write_text(json.dumps(compacted, indent=2))
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning(f"Failed to compact timeline: {e}")

        # Compact source findings - remove raw data
        sources_path = inv_path / "sources"
        if sources_path.exists():
            for source_file in sources_path.glob("*.json"):
                try:
                    data = json.loads(source_file.read_text())
                    # Keep only summary, remove detailed events
                    if "events" in data:
                        data["events_count"] = len(data["events"])
                        data["events"] = []
                    if "raw_results" in data:
                        del data["raw_results"]
                    data["compacted"] = True
                    source_file.write_text(json.dumps(data, indent=2))
                except (json.JSONDecodeError, KeyError) as e:
                    logger.warning(f"Failed to compact {source_file}: {e}")

        new_size = self._get_dir_size(inv_path)
        bytes_saved = original_size - new_size

        logger.info(f"Compacted {investigation_id}: saved {bytes_saved} bytes")
        return bytes_saved

    def compact_old_investigations(self) -> dict[str, int]:
        """
        Compact investigations older than compact_after_days.

        Returns:
            Dict mapping investigation_id to bytes saved
        """
        results = {}
        cutoff_date = datetime.utcnow() - timedelta(days=self.config.storage.compact_after_days)

        for entry in self.index.investigations:
            if entry.updated_at < cutoff_date:
                bytes_saved = self.compact_investigation(entry.id)
                if bytes_saved > 0:
                    results[entry.id] = bytes_saved

        return results

    def get_storage_stats(self) -> dict[str, Any]:
        """Get current storage statistics."""
        current_usage = self.calculate_usage()
        max_size = self.config.max_size_bytes

        return {
            "current_usage_bytes": current_usage,
            "current_usage_gb": round(current_usage / (1024**3), 2),
            "max_size_bytes": max_size,
            "max_size_gb": round(max_size / (1024**3), 2),
            "usage_percent": round((current_usage / max_size) * 100, 1) if max_size > 0 else 0,
            "total_investigations": self.index.total_investigations,
            "active_investigations": len(
                [inv for inv in self.index.investigations if inv.status == InvestigationStatus.ACTIVE]
            ),
            "storage_path": str(self.config.base_path),
        }

    def update_investigation_size(self, investigation_id: str) -> int:
        """Update the size of an investigation in the index."""
        size = self.get_investigation_size(investigation_id)

        for entry in self.index.investigations:
            if entry.id == investigation_id:
                entry.size_bytes = size
                break

        self.index._update_totals()
        self._save_index()
        return size

    def list_investigations(
        self, limit: int = 10, status: InvestigationStatus | None = None, include_size: bool = False
    ) -> list[IndexEntry]:
        """
        List investigations with optional filtering.

        Args:
            limit: Maximum number to return
            status: Filter by status
            include_size: Recalculate sizes (slower but accurate)

        Returns:
            List of index entries
        """
        if include_size:
            # Update sizes for all investigations
            for entry in self.index.investigations:
                entry.size_bytes = self.get_investigation_size(entry.id)
            self._save_index()

        return self.index.get_recent(limit=limit, status=status)

    def cleanup(self, keep_count: int = 10, force: bool = False) -> dict[str, Any]:
        """
        Manual cleanup: enforce limits and compact old investigations.

        Args:
            keep_count: Minimum investigations to keep
            force: Force cleanup even if under limit

        Returns:
            Cleanup results
        """
        results = {
            "deleted": [],
            "compacted": {},
            "bytes_freed": 0,
            "initial_size": self.calculate_usage(),
        }

        # First, compact old investigations
        results["compacted"] = self.compact_old_investigations()

        # Then enforce limits
        if force or self.calculate_usage() > self.config.max_size_bytes:
            results["deleted"] = self.enforce_limit()

        # Calculate bytes freed
        results["final_size"] = self.calculate_usage()
        results["bytes_freed"] = results["initial_size"] - results["final_size"]

        return results

    def refresh_index(self) -> MasterIndex:
        """
        Refresh the index by scanning the filesystem.

        Useful for recovering from index corruption.
        """
        self._index = MasterIndex(max_size_bytes=self.config.max_size_bytes)

        if not self.investigations_path.exists():
            self._save_index()
            return self._index

        for inv_dir in self.investigations_path.iterdir():
            if not inv_dir.is_dir():
                continue

            manifest_path = inv_dir / "manifest.json"
            if not manifest_path.exists():
                continue

            try:
                manifest_data = json.loads(manifest_path.read_text())
                manifest = InvestigationManifest.model_validate(manifest_data)
                manifest.size_bytes = self._get_dir_size(inv_dir)
                self._index.add_investigation(manifest)
            except (json.JSONDecodeError, Exception) as e:
                logger.warning(f"Failed to load manifest for {inv_dir.name}: {e}")

        self._save_index()
        return self._index
