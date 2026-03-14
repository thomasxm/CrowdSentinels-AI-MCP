"""Investigation State Storage Package.

Provides persistent storage for investigation state, IoCs, and findings
shared across Elasticsearch, Chainsaw, Wireshark, and future threat hunting tools.
"""

from src.storage.config import StorageConfig
from src.storage.models import (
    Investigation,
    InvestigationManifest,
    MasterIndex,
    IoC,
    IoCCollection,
    TimelineEvent,
    SourceFindings,
)
from src.storage.storage_manager import StorageManager
from src.storage.smart_extractor import SmartExtractor
from src.storage.investigation_state import InvestigationStateClient
from src.storage.auto_capture import (
    auto_capture_elasticsearch_results,
    auto_capture_chainsaw_results,
    auto_capture_wireshark_results,
    has_active_investigation,
    get_active_investigation_summary,
)

__all__ = [
    "StorageConfig",
    "Investigation",
    "InvestigationManifest",
    "MasterIndex",
    "IoC",
    "IoCCollection",
    "TimelineEvent",
    "SourceFindings",
    "StorageManager",
    "SmartExtractor",
    "InvestigationStateClient",
    "auto_capture_elasticsearch_results",
    "auto_capture_chainsaw_results",
    "auto_capture_wireshark_results",
    "has_active_investigation",
    "get_active_investigation_summary",
]
