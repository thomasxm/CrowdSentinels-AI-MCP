"""Data stream management operations."""

from src.clients.base import SearchClientBase


class DataStreamClient(SearchClientBase):
    def create_data_stream(self, name: str) -> dict:
        """Create a new data stream."""
        return self.client.indices.create_data_stream(name=name)

    def get_data_stream(self, name: str | None = None) -> dict:
        """Get information about one or more data streams."""
        if name:
            return self.client.indices.get_data_stream(name=name)
        return self.client.indices.get_data_stream()

    def delete_data_stream(self, name: str) -> dict:
        """Delete one or more data streams."""
        return self.client.indices.delete_data_stream(name=name)
