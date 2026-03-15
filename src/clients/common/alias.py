"""Alias management operations for Elasticsearch and OpenSearch."""

from src.clients.base import SearchClientBase


class AliasClient(SearchClientBase):
    def list_aliases(self) -> dict:
        """Get all aliases."""
        return self.client.cat.aliases()

    def get_alias(self, index: str) -> dict:
        """Get aliases for the specified index."""
        return self.client.indices.get_alias(index=index)

    def put_alias(self, index: str, name: str, body: dict) -> dict:
        """Creates or updates an alias."""
        return self.client.indices.put_alias(index=index, name=name, body=body)

    def delete_alias(self, index: str, name: str) -> dict:
        """Delete an alias for the specified index."""
        return self.client.indices.delete_alias(index=index, name=name)
