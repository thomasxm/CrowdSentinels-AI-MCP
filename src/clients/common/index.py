"""Index management and introspection operations."""

from src.clients.base import SearchClientBase


class IndexClient(SearchClientBase):
    def list_indices(self) -> dict:
        """List all indices."""
        return self.client.cat.indices()

    def get_index(self, index: str) -> dict:
        """Returns information (mappings, settings, aliases) about one or more indices."""
        return self.client.indices.get(index=index)

    def create_index(self, index: str, body: dict | None = None) -> dict:
        """Creates an index with optional settings and mappings."""
        return self.client.indices.create(index=index, body=body)

    def delete_index(self, index: str) -> dict:
        """Delete an index."""
        return self.client.indices.delete(index=index)
