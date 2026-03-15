"""Cluster health and information operations."""

from src.clients.base import SearchClientBase


class ClusterClient(SearchClientBase):
    def get_cluster_health(self) -> dict:
        """Get cluster health information from OpenSearch."""
        return self.client.cluster.health()

    def get_cluster_stats(self) -> dict:
        """Get cluster statistics from OpenSearch."""
        return self.client.cluster.stats()
