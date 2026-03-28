"""Asset Discovery Client for extracting and storing index metadata."""

import json
from datetime import datetime

from src.clients.base import SearchClientBase
from src.paths import get_assets_dir


class AssetDiscoveryClient(SearchClientBase):
    """Client for discovering and managing Elasticsearch assets (indices, mappings, etc.)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.assets_dir = get_assets_dir()

    def discover_all_assets(self) -> dict:
        """
        Discover all assets in the Elasticsearch cluster including indices,
        data streams, and their metadata.

        Returns:
            Dictionary containing all discovered assets
        """
        assets = {
            "discovery_timestamp": datetime.utcnow().isoformat(),
            "cluster_name": self._get_cluster_name(),
            "indices": self._discover_indices(),
            "data_streams": self._discover_data_streams(),
            "index_patterns": self._analyze_index_patterns(),
        }

        # Save to file
        self._save_assets(assets)

        return assets

    def _get_cluster_name(self) -> str:
        """Get cluster name."""
        try:
            cluster_info = self.client.info()
            return cluster_info.get("cluster_name", "unknown")
        except Exception:
            return "unknown"

    def _discover_indices(self) -> list[dict]:
        """Discover all indices and their metadata."""
        try:
            # Get all indices with detailed info
            indices_raw = self.client.cat.indices(format="json", h="index,health,status,pri,rep,docs.count,store.size")

            indices = []
            for idx in indices_raw:
                index_name = idx.get("index")

                # Skip system indices
                if index_name.startswith("."):
                    continue

                # Get detailed index information
                try:
                    index_info = self.client.indices.get(index=index_name)
                    mappings = index_info.get(index_name, {}).get("mappings", {})
                    settings = index_info.get(index_name, {}).get("settings", {})

                    # Analyze the index to determine metadata
                    metadata = self._analyze_index_metadata(index_name, mappings, settings)

                    indices.append(
                        {
                            "name": index_name,
                            "health": idx.get("health"),
                            "status": idx.get("status"),
                            "doc_count": idx.get("docs.count"),
                            "size": idx.get("store.size"),
                            "primary_shards": idx.get("pri"),
                            "replica_shards": idx.get("rep"),
                            "metadata": metadata,
                            "mappings": mappings,
                            "settings": settings,
                        }
                    )
                except Exception as e:
                    self.logger.warning(f"Failed to get details for index {index_name}: {e}")
                    continue

            return indices
        except Exception as e:
            self.logger.error(f"Failed to discover indices: {e}")
            return []

    def _discover_data_streams(self) -> list[dict]:
        """Discover all data streams."""
        try:
            data_streams = self.client.indices.get_data_stream(name="*")
            return data_streams.get("data_streams", [])
        except Exception as e:
            self.logger.warning(f"Failed to discover data streams: {e}")
            return []

    def _analyze_index_metadata(self, index_name: str, mappings: dict, settings: dict) -> dict:
        """
        Analyze index to extract metadata like OS type, log source, etc.

        Args:
            index_name: Name of the index
            mappings: Index mappings
            settings: Index settings

        Returns:
            Metadata dictionary
        """
        metadata = {
            "os_type": "unknown",
            "log_source": "unknown",
            "log_type": "unknown",
            "beat_type": None,
            "has_ecs": False,
            "fields": [],
        }

        # Determine beat type from index name
        if "winlogbeat" in index_name.lower():
            metadata["beat_type"] = "winlogbeat"
            metadata["os_type"] = "windows"
            metadata["log_source"] = "Windows Event Logs"
        elif "filebeat" in index_name.lower():
            metadata["beat_type"] = "filebeat"
            metadata["log_source"] = "File Logs"
        elif "metricbeat" in index_name.lower():
            metadata["beat_type"] = "metricbeat"
            metadata["log_source"] = "System Metrics"
        elif "packetbeat" in index_name.lower():
            metadata["beat_type"] = "packetbeat"
            metadata["log_source"] = "Network Traffic"
        elif "auditbeat" in index_name.lower():
            metadata["beat_type"] = "auditbeat"
            metadata["log_source"] = "Audit Logs"
        elif "syslog" in index_name.lower():
            metadata["log_source"] = "Syslog"
            metadata["os_type"] = "linux"

        # Extract fields from mappings
        properties = mappings.get("properties", {})
        metadata["fields"] = list(properties.keys())

        # Check for ECS compliance
        if "ecs" in properties or "@timestamp" in properties:
            metadata["has_ecs"] = True

        # Determine OS type from field names if not already set
        if metadata["os_type"] == "unknown":
            if "winlog" in properties or "event.code" in str(properties):
                metadata["os_type"] = "windows"
            elif "system" in properties or "process" in properties:
                if "winlog" not in str(properties):
                    metadata["os_type"] = "linux"

        # Determine log type from event codes or field structure
        if "event.code" in str(properties) or "event_id" in str(properties):
            metadata["log_type"] = "security_events"
        elif "message" in properties:
            metadata["log_type"] = "application_logs"

        # Detect specific Windows log channels
        if metadata["os_type"] == "windows":
            # Check for common Windows event log types
            field_str = str(properties).lower()
            if "security" in field_str or "4624" in field_str or "4688" in field_str:
                metadata["log_type"] = "Windows Security Logs"
            elif "sysmon" in field_str:
                metadata["log_type"] = "Sysmon Logs"
            elif "application" in field_str:
                metadata["log_type"] = "Windows Application Logs"
            elif "system" in field_str:
                metadata["log_type"] = "Windows System Logs"

        return metadata

    def _analyze_index_patterns(self) -> dict:
        """Analyze indices to identify common patterns."""
        try:
            indices = self.client.cat.indices(format="json", h="index")
            patterns = {
                "windows_security": [],
                "windows_sysmon": [],
                "linux_syslog": [],
                "application_logs": [],
                "network_logs": [],
                "metrics": [],
            }

            for idx in indices:
                index_name = idx.get("index", "")

                # Skip system indices
                if index_name.startswith("."):
                    continue

                # Categorize by pattern
                if "winlogbeat" in index_name.lower():
                    patterns["windows_security"].append(index_name)
                elif "sysmon" in index_name.lower():
                    patterns["windows_sysmon"].append(index_name)
                elif "syslog" in index_name.lower() or "auditbeat" in index_name.lower():
                    patterns["linux_syslog"].append(index_name)
                elif "filebeat" in index_name.lower():
                    patterns["application_logs"].append(index_name)
                elif "packetbeat" in index_name.lower():
                    patterns["network_logs"].append(index_name)
                elif "metricbeat" in index_name.lower():
                    patterns["metrics"].append(index_name)

            return patterns
        except Exception as e:
            self.logger.error(f"Failed to analyze index patterns: {e}")
            return {}

    def _save_assets(self, assets: dict) -> None:
        """Save assets to JSON file."""
        try:
            assets_file = self.assets_dir / "discovered_assets.json"
            with open(assets_file, "w") as f:
                json.dump(assets, f, indent=2)
            self.logger.info(f"Assets saved to {assets_file}")
        except Exception as e:
            self.logger.error(f"Failed to save assets: {e}")

    def get_saved_assets(self) -> dict | None:
        """Load previously discovered assets from file."""
        try:
            assets_file = self.assets_dir / "discovered_assets.json"
            if assets_file.exists():
                with open(assets_file) as f:
                    return json.load(f)
            return None
        except Exception as e:
            self.logger.error(f"Failed to load assets: {e}")
            return None

    def get_indices_by_type(self, log_type: str) -> list[str]:
        """
        Get indices matching a specific log type.

        Args:
            log_type: Type of logs (windows, linux, sysmon, security, etc.)

        Returns:
            List of matching index names
        """
        assets = self.get_saved_assets()
        if not assets:
            return []

        matching_indices = []
        for idx in assets.get("indices", []):
            metadata = idx.get("metadata", {})

            # Match by OS type
            if log_type.lower() in ["windows", "win"]:
                if metadata.get("os_type") == "windows":
                    matching_indices.append(idx["name"])
            elif log_type.lower() in ["linux", "nix", "unix"]:
                if metadata.get("os_type") == "linux":
                    matching_indices.append(idx["name"])

            # Match by log source
            elif (
                log_type.lower() in metadata.get("log_source", "").lower()
                or log_type.lower() in str(metadata.get("beat_type", "")).lower()
            ):
                matching_indices.append(idx["name"])

        return matching_indices

    def get_index_metadata(self, index_pattern: str) -> dict | None:
        """Get metadata for a specific index pattern."""
        assets = self.get_saved_assets()
        if not assets:
            return None

        for idx in assets.get("indices", []):
            if index_pattern in idx["name"] or idx["name"] in index_pattern:
                return idx.get("metadata")

        return None
