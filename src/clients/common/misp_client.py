"""MISP integration — offline-first event creation with optional live push.

Builds MISPEvent objects from CrowdSentinel IoCs. Works without a MISP
server (JSON export). If MISP_URL and MISP_API_KEY are set, can push
events to a live instance.
"""

import logging
import os
from typing import Any

logger = logging.getLogger("crowdsentinel.misp")

# IoC type → MISP attribute type mapping
IOC_TYPE_TO_MISP = {
    "ip": "ip-dst",
    "domain": "domain",
    "hostname": "hostname",
    "url": "url",
    "email": "email-src",
    "user": "target-user",
    "process": "filename",
    "commandline": "text",
    "file_path": "filename",
    "registry_key": "regkey",
    "service": "text",
    "scheduled_task": "text",
    "other": "text",
}

# Hash length → MISP hash type
HASH_LENGTH_TO_TYPE = {
    32: "md5",
    40: "sha1",
    64: "sha256",
    128: "sha512",
}

# IoC type → MISP category
IOC_TYPE_TO_CATEGORY = {
    "ip": "Network activity",
    "domain": "Network activity",
    "hostname": "Network activity",
    "url": "Network activity",
    "hash": "Payload delivery",
    "email": "Payload delivery",
    "user": "Attribution",
    "process": "Payload installation",
    "commandline": "Payload installation",
    "file_path": "Payload delivery",
    "registry_key": "Persistence mechanism",
    "service": "Persistence mechanism",
    "scheduled_task": "Persistence mechanism",
    "other": "Other",
}


def build_misp_event(
    investigation_name: str,
    investigation_id: str,
    iocs: list[Any],
    severity: str = "medium",
    tags: list[str] | None = None,
) -> dict[str, Any]:
    """Build a MISP event dict from CrowdSentinel IoCs.

    Returns a dict that is valid MISP JSON, importable by any MISP instance.
    Uses pymisp for correct structure, but does not require a MISP server.
    """
    try:
        from pymisp import MISPEvent
    except ImportError:
        return {"error": "pymisp library not installed. Run: pip install pymisp"}

    threat_level_map = {
        "critical": 1,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
        "unknown": 4,
    }

    event = MISPEvent()
    event.info = f"CrowdSentinel: {investigation_name} [{investigation_id}]"
    event.distribution = 0  # Organisation only
    event.threat_level_id = threat_level_map.get(severity, 2)
    event.analysis = 1  # Ongoing

    # Add tags
    event.add_tag("crowdsentinel:auto-export")
    event.add_tag(f"crowdsentinel:investigation-id={investigation_id}")
    for tag in tags or []:
        event.add_tag(tag)

    # Add IoCs as attributes
    for ioc in iocs:
        ioc_type = ioc.type.value if hasattr(ioc.type, "value") else str(ioc.type)
        ioc_value = ioc.value

        # Determine MISP attribute type
        if ioc_type == "hash":
            misp_type = HASH_LENGTH_TO_TYPE.get(len(ioc_value), "sha256")
        else:
            misp_type = IOC_TYPE_TO_MISP.get(ioc_type, "text")

        category = IOC_TYPE_TO_CATEGORY.get(ioc_type, "Other")

        # Build comment from enrichment context
        comment_parts = []
        if ioc.is_malicious is True:
            comment_parts.append("verdict: malicious")
        elif ioc.is_malicious is False:
            comment_parts.append("verdict: clean")
        comment_parts.append(f"priority: {ioc.pyramid_priority}/6")
        comment_parts.append(f"seen: {ioc.total_occurrences}x")
        comment = ", ".join(comment_parts)

        # to_ids = True for high-priority IoCs with malicious verdict
        to_ids = ioc.pyramid_priority >= 3 and ioc.is_malicious is not False

        attr = event.add_attribute(
            type=misp_type,
            value=ioc_value,
            category=category,
            to_ids=to_ids,
            comment=comment,
        )

        # Add IoC-level tags
        for tag in ioc.tags[:5]:
            attr.add_tag(tag)

        # Add MITRE ATT&CK tags
        for technique in ioc.mitre_techniques[:3]:
            attr.add_tag(f"mitre-attack:{technique}")

    return event.to_dict()


def push_to_misp(event_dict: dict[str, Any]) -> dict[str, Any]:
    """Push a MISP event to a live instance. Returns result or error.

    Requires MISP_URL and MISP_API_KEY environment variables.
    """
    url = os.environ.get("MISP_URL", "")
    key = os.environ.get("MISP_API_KEY", "")

    if not url or not key:
        return {
            "pushed": False,
            "reason": "MISP_URL and MISP_API_KEY not configured",
        }

    try:
        from pymisp import MISPEvent, PyMISP
    except ImportError:
        return {"pushed": False, "reason": "pymisp not installed"}

    ssl_verify: bool | str = os.environ.get("MISP_SSL_VERIFY", "true").lower() != "false"
    ca_path = os.environ.get("MISP_CA_BUNDLE")
    if ca_path:
        ssl_verify = ca_path

    try:
        misp = PyMISP(url=url, key=key, ssl=ssl_verify, timeout=30)

        event = MISPEvent()
        event.from_dict(**event_dict)

        result = misp.add_event(event)

        if hasattr(result, "id") and result.id:
            return {
                "pushed": True,
                "event_id": result.id,
                "event_uuid": str(result.uuid),
                "url": f"{url.rstrip('/')}/events/view/{result.id}",
            }

        # PyMISP may return a dict with errors
        if isinstance(result, dict) and "errors" in result:
            return {"pushed": False, "reason": str(result["errors"])}

        return {"pushed": True, "event_id": getattr(result, "id", None)}

    except Exception as exc:
        logger.warning("Failed to push to MISP: %s", exc)
        return {"pushed": False, "reason": str(exc)}


def search_misp_iocs(
    ioc_value: str,
    ioc_type: str | None = None,
) -> list[dict[str, Any]]:
    """Search a live MISP instance for matching IoCs.

    Returns list of matching attributes with event context.
    Requires MISP_URL and MISP_API_KEY environment variables.
    """
    url = os.environ.get("MISP_URL", "")
    key = os.environ.get("MISP_API_KEY", "")

    if not url or not key:
        return []

    try:
        from pymisp import PyMISP
    except ImportError:
        return []

    ssl_verify: bool | str = os.environ.get("MISP_SSL_VERIFY", "true").lower() != "false"
    ca_path = os.environ.get("MISP_CA_BUNDLE")
    if ca_path:
        ssl_verify = ca_path

    try:
        misp = PyMISP(url=url, key=key, ssl=ssl_verify, timeout=15)

        search_kwargs: dict[str, Any] = {
            "controller": "attributes",
            "value": ioc_value,
            "pythonify": True,
            "limit": 50,
        }

        if ioc_type:
            misp_type = IOC_TYPE_TO_MISP.get(ioc_type)
            if ioc_type == "hash":
                misp_type = HASH_LENGTH_TO_TYPE.get(len(ioc_value), "sha256")
            if misp_type:
                search_kwargs["type_attribute"] = misp_type

        results = misp.search(**search_kwargs)

        matches = []
        for attr in results:
            matches.append(
                {
                    "type": attr.type,
                    "value": attr.value,
                    "event_id": attr.event_id,
                    "category": attr.category,
                    "to_ids": attr.to_ids,
                    "comment": attr.comment or "",
                    "tags": [t.name for t in getattr(attr, "Tag", [])],
                }
            )
        return matches

    except Exception as exc:
        logger.warning("MISP search failed: %s", exc)
        return []
