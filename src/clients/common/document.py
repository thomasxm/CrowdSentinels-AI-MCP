from typing import Dict, Optional
import logging

from src.clients.base import SearchClientBase
from src.utils import limit_response_size, summarize_search_response

logger = logging.getLogger(__name__)

class DocumentClient(SearchClientBase):
    def search_documents(
        self,
        index: str,
        body: Dict,
        raw: bool = False
    ) -> Dict:
        """
        Search for documents in the index.

        Args:
            index: Index pattern to search
            body: Elasticsearch query body
            raw: If True, return raw response without size limiting.
                 Use when caller handles size management (e.g., via _source filtering).

        Returns:
            Search results (wrapped with metadata if raw=False, dict if raw=True)
        """
        # Execute search
        response = self.client.search(index=index, body=body)

        # Convert ObjectApiResponse to dict if needed
        if hasattr(response, 'body'):
            response = response.body

        # If raw mode requested, return without size limiting
        # Used by internal tools that manage their own response size via _source filtering
        if raw:
            return response

        # Check if size parameter was specified
        requested_size = body.get("size", 10)

        # If requesting more than 100 hits, automatically summarize
        if requested_size > 100:
            logger.info(f"Large search result requested ({requested_size} hits), applying summarization")
            summarized = summarize_search_response(response, max_hits=100)
            return limit_response_size(summarized)

        # Always apply size limiting to prevent token overflow
        return limit_response_size(response)
    
    def index_document(self, index: str, document: Dict, id: Optional[str] = None) -> Dict:
        """Creates a new document in the index."""
        # Handle parameter name differences between Elasticsearch and OpenSearch
        if self.engine_type == "elasticsearch":
            # For Elasticsearch: index(index, document, id=None, ...)
            if id is not None:
                return self.client.index(index=index, document=document, id=id)
            else:
                return self.client.index(index=index, document=document)
        else:
            # For OpenSearch: index(index, body, id=None, ...)
            if id is not None:
                return self.client.index(index=index, body=document, id=id)
            else:
                return self.client.index(index=index, body=document)
    
    def get_document(self, index: str, id: str) -> Dict:
        """Get a document by ID."""
        return self.client.get(index=index, id=id)
    
    def delete_document(self, index: str, id: str) -> Dict:
        """Removes a document from the index."""
        return self.client.delete(index=index, id=id)

    def delete_by_query(self, index: str, body: Dict) -> Dict:
        """Deletes documents matching the provided query."""
        return self.client.delete_by_query(index=index, body=body)

