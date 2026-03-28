"""Threat intelligence enrichment and sharing MCP tools.

Provides IoC enrichment via Shodan InternetDB, AbuseIPDB, VirusTotal,
and ThreatFox. MISP integration for IoC sharing (offline JSON export
or live push). Works with or without an active investigation.
"""

import logging
import os
from typing import Any

from fastmcp import FastMCP

from src.clients.common.threat_intel import (
    IOC_TYPE_PROVIDERS,
    aggregate_verdicts,
    enrich_single_ioc,
    get_configured_providers,
)
from src.storage.auto_capture import get_client as get_investigation_client
from src.storage.models import IoCSource, IoCType, SourceType

logger = logging.getLogger("crowdsentinel.tools.threat_intel")


class ThreatIntelTools:
    """MCP tools for threat intelligence enrichment."""

    def register_tools(self, mcp: FastMCP):
        """Register threat intelligence MCP tools."""

        @mcp.tool()
        def enrich_iocs(
            investigation_id: str | None = None,
            ioc_types: list[str] | None = None,
            min_priority: int = 2,
            providers: list[str] | None = None,
            max_iocs: int = 20,
        ) -> dict[str, Any]:
            """
            Enrich IoCs from the active investigation with external threat intelligence.

            Queries configured providers (Shodan, AbuseIPDB, VirusTotal, ThreatFox)
            and updates each IoC with verdict (malicious/clean/unknown), confidence
            score, and enrichment context.

            Shodan InternetDB works without any API key. Other providers require
            environment variables (VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, THREATFOX_API_KEY).

            Note: VirusTotal free tier allows 4 requests/minute. Enriching many IoCs
            with VT enabled may take several minutes (15s delay per lookup).

            Args:
                investigation_id: Target investigation (defaults to active)
                ioc_types: Filter by IoC types (e.g. ["ip", "hash"])
                min_priority: Minimum Pyramid of Pain priority (default: 2)
                providers: Specific providers to use (default: all configured)
                max_iocs: Maximum IoCs to enrich (default: 50)

            Returns:
                Enrichment summary with verdicts and provider statistics

            Example:
                enrich_iocs(ioc_types=["ip", "hash"], min_priority=3)
            """
            return self._enrich_iocs(investigation_id, ioc_types, min_priority, providers, max_iocs)

        @mcp.tool()
        def lookup_ioc(
            ioc_type: str,
            ioc_value: str,
            providers: list[str] | None = None,
        ) -> dict[str, Any]:
            """
            Look up a single IoC across all configured threat intelligence providers.

            Works independently of any investigation — use for ad-hoc lookups.

            Args:
                ioc_type: Type of indicator (ip, domain, hash, url)
                ioc_value: The indicator value
                providers: Specific providers (default: all applicable)

            Returns:
                Aggregated verdict with per-provider details

            Example:
                lookup_ioc(ioc_type="ip", ioc_value="1.2.3.4")
                lookup_ioc(ioc_type="hash", ioc_value="abc123...")
            """
            return self._lookup_ioc(ioc_type, ioc_value, providers)

        @mcp.tool()
        def get_enrichment_status() -> dict[str, Any]:
            """
            Check which threat intelligence providers are configured.

            Reports API key status for each provider and recommends
            which keys to set for better coverage.

            Returns:
                Provider configuration status and recommendations
            """
            return self._get_enrichment_status()

        @mcp.tool()
        def export_to_misp(
            investigation_id: str | None = None,
            min_priority: int = 2,
            push: bool = False,
            tags: list[str] | None = None,
        ) -> dict[str, Any]:
            """
            Export investigation IoCs as a MISP event.

            Always produces a MISP JSON event (offline, no server needed).
            If push=True and MISP_URL + MISP_API_KEY are configured, also
            pushes the event to the live MISP instance.

            Args:
                investigation_id: Target investigation (defaults to active)
                min_priority: Minimum Pyramid of Pain priority (default: 2)
                push: Whether to push to a live MISP instance (default: False)
                tags: Additional tags for the MISP event

            Returns:
                MISP event dict, optionally with push result

            Example:
                export_to_misp(push=True, tags=["tlp:amber"])
            """
            return self._export_to_misp(investigation_id, min_priority, push, tags)

        @mcp.tool()
        def search_misp(
            ioc_value: str,
            ioc_type: str | None = None,
        ) -> dict[str, Any]:
            """
            Search a live MISP instance for a specific IoC.

            Requires MISP_URL and MISP_API_KEY environment variables.
            Returns matching attributes with event context.

            Args:
                ioc_value: The indicator value to search for
                ioc_type: Optional IoC type hint (ip, domain, hash, url)

            Returns:
                List of matching MISP attributes with event metadata

            Example:
                search_misp(ioc_value="203.0.113.42", ioc_type="ip")
            """
            return self._search_misp(ioc_value, ioc_type)

    # ------------------------------------------------------------------
    # Internal implementations
    # ------------------------------------------------------------------

    def _enrich_iocs(
        self,
        investigation_id: str | None,
        ioc_types: list[str] | None,
        min_priority: int,
        providers: list[str] | None,
        max_iocs: int,
    ) -> dict[str, Any]:
        """Enrich IoCs from an investigation."""
        client = get_investigation_client()
        investigation = client._get_investigation(investigation_id)
        if not investigation:
            return {"error": "No investigation found. Create one first with create_investigation()."}

        # Filter IoCs
        iocs = investigation.iocs.get_by_priority(max(1, min_priority))
        if ioc_types:
            valid_types = {e.value for e in IoCType}
            type_filter = {t for t in ioc_types if t in valid_types}
            iocs = [i for i in iocs if i.type.value in type_filter]

        # Hard cap to prevent runaway enrichment (VT rate limit: 4/min)
        hard_limit = min(max_iocs, 200)
        iocs = iocs[:hard_limit]

        if not iocs:
            return {
                "enriched_count": 0,
                "message": "No IoCs matched the filters",
                "filters": {"ioc_types": ioc_types, "min_priority": min_priority},
            }

        # Enrich each IoC
        enriched_iocs = []
        provider_stats: dict[str, dict[str, int]] = {}
        verdicts_summary = {"malicious": 0, "clean": 0, "suspicious": 0, "unknown": 0}

        for ioc in iocs:
            ioc_type_str = ioc.type.value if isinstance(ioc.type, IoCType) else str(ioc.type)

            results = enrich_single_ioc(ioc_type_str, ioc.value, providers)

            # Track provider stats
            for r in results:
                stats = provider_stats.setdefault(r.provider, {"queried": 0, "found": 0, "errors": 0})
                stats["queried"] += 1
                if r.error:
                    stats["errors"] += 1
                elif r.is_malicious is not None or r.context:
                    stats["found"] += 1

            # Aggregate verdict
            is_malicious, confidence = aggregate_verdicts(results)

            # Update the IoC in the investigation
            ioc.is_malicious = is_malicious
            ioc.confidence = confidence
            for r in results:
                if r.context:
                    ioc.context[r.provider] = r.context
                ioc.tags = list(set(ioc.tags + r.tags))
                ioc.mitre_techniques = list(set(ioc.mitre_techniques + r.mitre_techniques))

            # Add threat_intel source
            has_ti_source = any(s.source_type == SourceType.THREAT_INTEL for s in ioc.sources)
            if not has_ti_source and results:
                ioc.sources.append(
                    IoCSource(
                        tool="threat_intel_enrichment",
                        source_type=SourceType.THREAT_INTEL,
                        investigation_id=investigation.manifest.id,
                        query_context=",".join(r.provider for r in results if not r.error),
                    )
                )

            # Classify verdict
            if is_malicious is True and confidence >= 0.7:
                verdicts_summary["malicious"] += 1
                verdict_label = "malicious"
            elif is_malicious is True:
                verdicts_summary["suspicious"] += 1
                verdict_label = "suspicious"
            elif is_malicious is False:
                verdicts_summary["clean"] += 1
                verdict_label = "clean"
            else:
                verdicts_summary["unknown"] += 1
                verdict_label = "unknown"

            enriched_iocs.append(
                {
                    "type": ioc_type_str,
                    "value": ioc.value,
                    "verdict": verdict_label,
                    "confidence": confidence,
                    "providers": {r.provider: r.context for r in results if not r.error and r.context},
                }
            )

        # Update statistics and save
        investigation.manifest.statistics.total_iocs = investigation.iocs.total_count
        investigation.manifest.update_timestamp()
        client.save_state()

        return {
            "investigation_id": investigation.manifest.id,
            "enriched_count": len(enriched_iocs),
            "verdicts": verdicts_summary,
            "provider_stats": provider_stats,
            "enriched_iocs": enriched_iocs,
            "workflow_hint": {
                "next_step": "export_iocs",
                "description": "Export enriched IoCs in STIX 2.1 or CSV format for sharing",
            },
        }

    def _lookup_ioc(
        self,
        ioc_type: str,
        ioc_value: str,
        providers: list[str] | None,
    ) -> dict[str, Any]:
        """Look up a single IoC across all providers."""
        if ioc_type not in IOC_TYPE_PROVIDERS:
            return {
                "error": f"Unsupported IoC type: {ioc_type}",
                "supported_types": list(IOC_TYPE_PROVIDERS.keys()),
            }

        applicable = IOC_TYPE_PROVIDERS.get(ioc_type, [])
        if not applicable:
            return {
                "ioc": {"type": ioc_type, "value": ioc_value},
                "verdict": "unknown",
                "confidence": 0.0,
                "message": f"No providers support IoC type '{ioc_type}'",
            }

        results = enrich_single_ioc(ioc_type, ioc_value, providers)
        is_malicious, confidence = aggregate_verdicts(results)

        if is_malicious is True and confidence >= 0.7:
            verdict_label = "malicious"
        elif is_malicious is True:
            verdict_label = "suspicious"
        elif is_malicious is False:
            verdict_label = "clean"
        else:
            verdict_label = "unknown"

        return {
            "ioc": {"type": ioc_type, "value": ioc_value},
            "verdict": verdict_label,
            "confidence": confidence,
            "details": {
                r.provider: {
                    "is_malicious": r.is_malicious,
                    "confidence": r.confidence,
                    "context": r.context,
                    "tags": r.tags,
                    "error": r.error,
                }
                for r in results
            },
        }

    def _get_enrichment_status(self) -> dict[str, Any]:
        """Report provider configuration status."""
        providers = get_configured_providers()
        total_configured = sum(1 for p in providers.values() if p["configured"])

        recommendations = []
        if not providers["virustotal"]["key_set"]:
            recommendations.append(
                "Set VIRUSTOTAL_API_KEY for hash, URL, domain, and IP enrichment "
                "(free: 500 lookups/day — https://www.virustotal.com/gui/join-us)"
            )
        if not providers["abuseipdb"]["key_set"]:
            recommendations.append(
                "Set ABUSEIPDB_API_KEY for IP reputation scoring "
                "(free: 1,000 lookups/day — https://www.abuseipdb.com/account/api)"
            )
        if not providers["threatfox"]["key_set"]:
            recommendations.append(
                "Set THREATFOX_API_KEY for IoC-to-malware-family mapping (free, unlimited — https://auth.abuse.ch/)"
            )

        return {
            "providers": providers,
            "total_configured": total_configured,
            "total_available": len(providers),
            "misp_configured": bool(os.environ.get("MISP_URL") and os.environ.get("MISP_API_KEY")),
            "recommendations": recommendations if recommendations else ["All providers configured."],
        }

    def _export_to_misp(
        self,
        investigation_id: str | None,
        min_priority: int,
        push: bool,
        tags: list[str] | None,
    ) -> dict[str, Any]:
        """Export investigation IoCs as a MISP event."""
        from src.clients.common.misp_client import build_misp_event, push_to_misp

        client = get_investigation_client()
        investigation = client._get_investigation(investigation_id)
        if not investigation:
            return {"error": "No investigation found. Create one first with create_investigation()."}

        iocs = investigation.iocs.get_by_priority(max(1, min_priority))
        if not iocs:
            return {"error": "No IoCs to export", "investigation_id": investigation.manifest.id}

        severity = (
            investigation.manifest.severity.value if hasattr(investigation.manifest.severity, "value") else "medium"
        )

        event_dict = build_misp_event(
            investigation_name=investigation.manifest.name,
            investigation_id=investigation.manifest.id,
            iocs=iocs,
            severity=severity,
            tags=tags,
        )

        if isinstance(event_dict, dict) and "error" in event_dict:
            return event_dict

        result: dict[str, Any] = {
            "investigation_id": investigation.manifest.id,
            "total_iocs": len(iocs),
            "event": event_dict,
        }

        if push:
            push_result = push_to_misp(event_dict)
            result["push_result"] = push_result
        else:
            result["push_result"] = {
                "pushed": False,
                "reason": "push=False (set push=True to push to live MISP instance)",
            }

        result["workflow_hint"] = {
            "next_step": "generate_investigation_report" if not push else "close_investigation",
            "description": "Generate a final investigation report" if not push else "Close the investigation",
        }

        return result

    def _search_misp(self, ioc_value: str, ioc_type: str | None) -> dict[str, Any]:
        """Search a live MISP instance for an IoC."""
        from src.clients.common.misp_client import search_misp_iocs

        misp_url = os.environ.get("MISP_URL", "")
        if not misp_url:
            return {
                "error": "MISP not configured. Set MISP_URL and MISP_API_KEY environment variables.",
                "searched": False,
            }

        matches = search_misp_iocs(ioc_value, ioc_type)

        return {
            "searched": True,
            "ioc": {"type": ioc_type, "value": ioc_value},
            "matches": matches,
            "total_matches": len(matches),
            "misp_instance": misp_url,
        }
