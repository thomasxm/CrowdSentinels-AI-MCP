"""
Response handling utilities for MCP tool outputs.
Handles large responses with automatic truncation and summarization.
"""

import json
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

# Maximum tokens for MCP responses (conservative estimate: 1 token ≈ 4 characters)
MAX_RESPONSE_TOKENS = 8000  # ~32KB of text
MAX_RESPONSE_CHARS = MAX_RESPONSE_TOKENS * 4

# Maximum number of hits to return in search results
MAX_HITS_DEFAULT = 100
MAX_HITS_ABSOLUTE = 1000


def estimate_tokens(text: str) -> int:
    """Estimate token count for text (rough approximation)."""
    return len(text) // 4


def truncate_text(text: str, max_chars: int) -> str:
    """Truncate text to maximum characters with ellipsis."""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n\n... [TRUNCATED - Response too large]"


def summarize_hits(hits: List[Dict], max_hits: int = MAX_HITS_DEFAULT) -> Dict:
    """
    Summarize search hits to reduce response size.

    Args:
        hits: List of Elasticsearch hits
        max_hits: Maximum number of hits to include

    Returns:
        Summarized hits with metadata
    """
    total_hits = len(hits)

    if total_hits <= max_hits:
        return {
            "total_returned": total_hits,
            "hits": hits,
            "truncated": False
        }

    return {
        "total_returned": max_hits,
        "total_available": total_hits,
        "hits": hits[:max_hits],
        "truncated": True,
        "message": f"Response truncated: showing {max_hits} of {total_hits} hits. Use pagination or more specific queries to see more results."
    }


def summarize_search_response(response: Dict, max_hits: int = MAX_HITS_DEFAULT) -> Dict:
    """
    Summarize Elasticsearch search response.

    Args:
        response: Raw Elasticsearch search response
        max_hits: Maximum number of hits to return

    Returns:
        Summarized response
    """
    if not isinstance(response, dict):
        return response

    result = {
        "took": response.get("took"),
        "timed_out": response.get("timed_out"),
        "_shards": response.get("_shards"),
        "hits": {}
    }

    # Handle hits
    if "hits" in response:
        hits_data = response["hits"]
        total = hits_data.get("total", {})

        result["hits"]["total"] = total
        result["hits"]["max_score"] = hits_data.get("max_score")

        # Summarize actual hits
        hits_list = hits_data.get("hits", [])
        summarized = summarize_hits(hits_list, max_hits)
        result["hits"].update(summarized)

    # Keep aggregations (usually much smaller)
    if "aggregations" in response:
        result["aggregations"] = response["aggregations"]

    return result


def slim_event(event: Dict) -> Dict:
    """
    Extract only essential fields from an event for IoC extraction.
    This dramatically reduces event size while preserving huntable data.
    """
    if not isinstance(event, dict):
        return event

    # Get source data (handle both wrapped and unwrapped formats)
    source = event.get("_source", event)

    # Essential fields for threat hunting and IoC extraction
    slim = {
        "_index": event.get("_index"),
        "_id": event.get("_id"),
    }

    # Flatten important fields from _source
    essential_fields = {
        # Timestamps
        "@timestamp": source.get("@timestamp"),
        # Event info
        "event.code": source.get("event", {}).get("code"),
        "event.action": source.get("event", {}).get("action"),
        # User info
        "user.name": source.get("user", {}).get("name"),
        "user.domain": source.get("user", {}).get("domain"),
        # Host info
        "host.name": source.get("host", {}).get("name") or source.get("host", {}).get("hostname"),
        "host.ip": source.get("host", {}).get("ip"),
        # Network
        "source.ip": source.get("source", {}).get("ip"),
        "destination.ip": source.get("destination", {}).get("ip"),
        # Process
        "process.name": source.get("process", {}).get("name"),
        "process.command_line": source.get("process", {}).get("command_line"),
        # Winlog specifics
        "winlog.event_id": source.get("winlog", {}).get("event_id"),
        "winlog.computer_name": source.get("winlog", {}).get("computer_name"),
    }

    # Add winlog.event_data fields (these contain valuable IoCs)
    event_data = source.get("winlog", {}).get("event_data", {})
    if event_data:
        for key in ["TargetUserName", "SubjectUserName", "IpAddress", "CommandLine",
                    "Image", "ParentImage", "TargetFilename", "User"]:
            if key in event_data:
                essential_fields[f"winlog.event_data.{key}"] = event_data[key]

    # Add related fields (ECS format)
    related = source.get("related", {})
    if related:
        essential_fields["related.user"] = related.get("user")
        essential_fields["related.ip"] = related.get("ip")

    # Filter out None values
    slim["_source"] = {k: v for k, v in essential_fields.items() if v is not None}

    return slim


def summarize_events_response(response: Dict, max_events: int = MAX_HITS_DEFAULT) -> Dict:
    """
    Summarize MCP tool response that uses 'events' format.

    Args:
        response: MCP tool response with events
        max_events: Maximum number of events to return

    Returns:
        Summarized response preserving dict structure
    """
    if not isinstance(response, dict):
        return response

    result = {}

    # Copy metadata fields
    for key in ["lucene_query", "total_hits", "query", "index", "timeframe"]:
        if key in response:
            result[key] = response[key]

    # Summarize events
    if "events" in response:
        events = response["events"]
        total = len(events)

        # Slim down each event to essential fields
        slimmed_events = [slim_event(e) for e in events[:max_events]]

        result["events"] = slimmed_events
        result["events_truncated"] = total > max_events
        if total > max_events:
            result["total_events"] = total
            result["message"] = f"Response truncated: showing {max_events} of {total} events"

    # Copy other fields (skip large ones)
    skip_keys = {"events", "hits", "aggregations"}
    for key, value in response.items():
        if key not in result and key not in skip_keys:
            result[key] = value

    return result


def limit_response_size(response: Any, max_chars: int = MAX_RESPONSE_CHARS) -> Dict:
    """
    Limit response size with automatic truncation and summarization.

    Args:
        response: Response object (dict, string, etc.)
        max_chars: Maximum characters allowed

    Returns:
        Size-limited response with metadata
    """
    # Convert to JSON string to check size
    try:
        response_str = json.dumps(response, default=str, indent=2)
        estimated_tokens = estimate_tokens(response_str)

        # If within limits, return as-is
        if len(response_str) <= max_chars:
            return {
                "response": response,
                "metadata": {
                    "size_bytes": len(response_str),
                    "estimated_tokens": estimated_tokens,
                    "truncated": False
                }
            }

        # Response too large - try to summarize
        logger.warning(f"Response size {len(response_str)} chars exceeds limit {max_chars}")

        # If it's a search response, try intelligent summarization
        if isinstance(response, dict) and "hits" in response:
            summarized = summarize_search_response(response, max_hits=50)
            summarized_str = json.dumps(summarized, default=str, indent=2)

            # Check if summarization was enough
            if len(summarized_str) <= max_chars:
                return {
                    "response": summarized,
                    "metadata": {
                        "size_bytes": len(summarized_str),
                        "estimated_tokens": estimate_tokens(summarized_str),
                        "truncated": True,
                        "original_size_bytes": len(response_str),
                        "message": "Response automatically summarized due to size"
                    }
                }

            # Still too large - truncate further
            response_str = summarized_str

        # Handle MCP tool format with "events" array
        elif isinstance(response, dict) and "events" in response:
            summarized = summarize_events_response(response, max_events=50)
            summarized_str = json.dumps(summarized, default=str, indent=2)

            # Check if summarization was enough
            if len(summarized_str) <= max_chars:
                return {
                    "response": summarized,
                    "metadata": {
                        "size_bytes": len(summarized_str),
                        "estimated_tokens": estimate_tokens(summarized_str),
                        "truncated": True,
                        "original_size_bytes": len(response_str),
                        "message": "Response automatically summarized due to size"
                    }
                }

            # Still too large - truncate further
            response_str = summarized_str

        # Last resort: hard truncate
        truncated = truncate_text(response_str, max_chars)

        return {
            "response": truncated,
            "metadata": {
                "size_bytes": len(truncated),
                "estimated_tokens": estimate_tokens(truncated),
                "truncated": True,
                "original_size_bytes": len(response_str),
                "message": "Response truncated due to size limit. Use more specific queries or pagination."
            }
        }

    except Exception as e:
        logger.error(f"Error limiting response size: {e}")
        # Return truncated string representation as fallback
        response_str = str(response)
        return {
            "response": truncate_text(response_str, max_chars),
            "metadata": {
                "truncated": True,
                "error": str(e),
                "message": "Error processing response, returned truncated string representation"
            }
        }


def limit_response_size_if_needed(response: Any, max_chars: int = MAX_RESPONSE_CHARS) -> Any:
    """
    Return the original response when it's within limits, otherwise apply size limiting.
    """
    try:
        response_str = json.dumps(response, default=str, indent=2)
    except Exception:
        response_str = str(response)

    if len(response_str) <= max_chars:
        return response

    return limit_response_size(response, max_chars=max_chars)


def chunk_large_list(items: List, chunk_size: int = 100) -> List[List]:
    """Split large list into chunks."""
    return [items[i:i + chunk_size] for i in range(0, len(items), chunk_size)]


def summarize_aggregation(agg_result: Dict) -> Dict:
    """
    Summarize aggregation results to reduce size.
    Keep only top buckets and add truncation info.
    """
    if not isinstance(agg_result, dict):
        return agg_result

    summarized = {}

    for key, value in agg_result.items():
        if isinstance(value, dict):
            if "buckets" in value and isinstance(value["buckets"], list):
                # Limit buckets to top 50
                buckets = value["buckets"]
                if len(buckets) > 50:
                    summarized[key] = {
                        **value,
                        "buckets": buckets[:50],
                        "truncated": True,
                        "total_buckets": len(buckets),
                        "showing": 50
                    }
                else:
                    summarized[key] = value
            else:
                # Recursively summarize nested aggregations
                summarized[key] = summarize_aggregation(value)
        else:
            summarized[key] = value

    return summarized
