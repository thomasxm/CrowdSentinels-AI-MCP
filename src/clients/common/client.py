from typing import Dict

from src.clients.common.alias import AliasClient
from src.clients.common.cluster import ClusterClient
from src.clients.common.data_stream import DataStreamClient
from src.clients.common.document import DocumentClient
from src.clients.common.general import GeneralClient
from src.clients.common.index import IndexClient
from src.clients.common.asset_discovery import AssetDiscoveryClient
from src.clients.common.eql_query import EQLQueryClient
from src.clients.common.threat_hunting import ThreatHuntingClient
from src.clients.common.ioc_analysis import IoCAnalysisClient

class SearchClient(IndexClient, DocumentClient, ClusterClient, AliasClient, DataStreamClient, GeneralClient, AssetDiscoveryClient, EQLQueryClient, ThreatHuntingClient, IoCAnalysisClient):
    """
    Unified search client that combines all search functionality.
    
    This class uses multiple inheritance to combine all specialized client implementations
    (index, document, cluster, alias) into a single unified client.
    """
    
    def __init__(self, config: Dict, engine_type: str):
        """
        Initialize the search client.
        
        Args:
            config: Configuration dictionary with connection parameters
            engine_type: Type of search engine to use ("elasticsearch" or "opensearch")
        """
        super().__init__(config, engine_type)
        self.logger.info(f"Initialised the {engine_type} client")
