"""Auto-capture helper for integrating investigation state with threat hunting tools.

This module provides automatic IoC extraction and storage for threat hunting
results from Elasticsearch, Chainsaw, and other tools.
"""

import logging
from typing import Any

from src.storage.investigation_state import InvestigationStateClient
from src.storage.models import SourceType

logger = logging.getLogger(__name__)

# Global client instance
_client: InvestigationStateClient | None = None


def get_client() -> InvestigationStateClient:
    """Get or create the investigation state client."""
    global _client
    if _client is None:
        _client = InvestigationStateClient()
    return _client


def auto_capture_elasticsearch_results(
    results: dict[str, Any],
    tool_name: str,
    query_description: str = "",
    extract_timeline: bool = False,
) -> dict[str, Any]:
    """
    Automatically capture IoCs from Elasticsearch results.

    This function should be called after any Elasticsearch threat hunting
    query to automatically extract and store IoCs to the active investigation.

    Args:
        results: Elasticsearch query results
        tool_name: Name of the tool that generated results
        query_description: Description of the query
        extract_timeline: Whether to extract timeline events

    Returns:
        Updated results dict with capture_summary added
    """
    client = get_client()

    # Check if there's an active investigation
    if client.active_investigation is None:
        # No active investigation - return results unchanged
        results["capture_info"] = {
            "captured": False,
            "reason": "No active investigation. Use create_investigation() first."
        }
        return results

    try:
        # Add findings to the active investigation
        summary = client.add_findings(
            source_type=SourceType.ELASTICSEARCH,
            source_tool=tool_name,
            results=results,
            query_description=query_description,
            extract_timeline=extract_timeline,
        )

        # Add capture info to results
        results["capture_info"] = {
            "captured": True,
            "investigation_id": client.active_investigation_id,
            "investigation_name": client.active_investigation.manifest.name,
            "iocs_added": summary.get("iocs_added", 0),
            "timeline_events_added": summary.get("timeline_events_added", 0),
            "total_iocs": client.active_investigation.iocs.total_count,
        }

        logger.info(
            f"Auto-captured {summary.get('iocs_added', 0)} IoCs from {tool_name} "
            f"to investigation {client.active_investigation_id}"
        )

    except Exception as e:
        logger.warning(f"Failed to auto-capture IoCs: {e}")
        results["capture_info"] = {
            "captured": False,
            "reason": f"Error: {str(e)}"
        }

    return results


def auto_capture_chainsaw_results(
    results: dict[str, Any],
    tool_name: str,
    query_description: str = "",
    extract_timeline: bool = True,
) -> dict[str, Any]:
    """
    Automatically capture IoCs from Chainsaw results.

    This function should be called after any Chainsaw threat hunting
    query to automatically extract and store IoCs to the active investigation.

    Args:
        results: Chainsaw query results
        tool_name: Name of the tool that generated results
        query_description: Description of the query
        extract_timeline: Whether to extract timeline events

    Returns:
        Updated results dict with capture_summary added
    """
    client = get_client()

    # Check if there's an active investigation
    if client.active_investigation is None:
        results["capture_info"] = {
            "captured": False,
            "reason": "No active investigation. Use create_investigation() first."
        }
        return results

    try:
        # Add findings to the active investigation
        summary = client.add_findings(
            source_type=SourceType.CHAINSAW,
            source_tool=tool_name,
            results=results,
            query_description=query_description,
            extract_timeline=extract_timeline,
        )

        # Add capture info to results
        results["capture_info"] = {
            "captured": True,
            "investigation_id": client.active_investigation_id,
            "investigation_name": client.active_investigation.manifest.name,
            "iocs_added": summary.get("iocs_added", 0),
            "timeline_events_added": summary.get("timeline_events_added", 0),
            "total_iocs": client.active_investigation.iocs.total_count,
        }

        logger.info(
            f"Auto-captured {summary.get('iocs_added', 0)} IoCs from {tool_name} "
            f"to investigation {client.active_investigation_id}"
        )

    except Exception as e:
        logger.warning(f"Failed to auto-capture IoCs: {e}")
        results["capture_info"] = {
            "captured": False,
            "reason": f"Error: {str(e)}"
        }

    return results


def auto_capture_wireshark_results(
    results: dict[str, Any],
    tool_name: str,
    query_description: str = "",
) -> dict[str, Any]:
    """
    Automatically capture IoCs from Wireshark/tshark results.

    Args:
        results: Wireshark query results
        tool_name: Name of the tool that generated results
        query_description: Description of the query

    Returns:
        Updated results dict with capture_summary added
    """
    client = get_client()

    # Check if there's an active investigation
    if client.active_investigation is None:
        results["capture_info"] = {
            "captured": False,
            "reason": "No active investigation. Use create_investigation() first."
        }
        return results

    try:
        # Add findings to the active investigation
        summary = client.add_findings(
            source_type=SourceType.WIRESHARK,
            source_tool=tool_name,
            results=results,
            query_description=query_description,
            extract_timeline=False,
        )

        # Add capture info to results
        results["capture_info"] = {
            "captured": True,
            "investigation_id": client.active_investigation_id,
            "investigation_name": client.active_investigation.manifest.name,
            "iocs_added": summary.get("iocs_added", 0),
            "total_iocs": client.active_investigation.iocs.total_count,
        }

        logger.info(
            f"Auto-captured {summary.get('iocs_added', 0)} IoCs from {tool_name} "
            f"to investigation {client.active_investigation_id}"
        )

    except Exception as e:
        logger.warning(f"Failed to auto-capture IoCs: {e}")
        results["capture_info"] = {
            "captured": False,
            "reason": f"Error: {str(e)}"
        }

    return results


def has_active_investigation() -> bool:
    """Check if there's an active investigation."""
    client = get_client()
    return client.active_investigation is not None


def get_active_investigation_summary() -> dict[str, Any] | None:
    """Get summary of the active investigation, if any."""
    client = get_client()
    if client.active_investigation is None:
        return None

    return {
        "id": client.active_investigation_id,
        "name": client.active_investigation.manifest.name,
        "iocs_count": client.active_investigation.iocs.total_count,
        "sources_used": client.active_investigation.manifest.sources_used,
    }
