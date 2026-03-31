"""Smart Search Tools - Token-efficient search with automatic summarization."""

from fastmcp import FastMCP

from src.storage.auto_capture import auto_capture_elasticsearch_results


class SmartSearchTools:
    """Tools that combine search with automatic summarization and IoC extraction."""

    # Default fields to extract for different index types
    DEFAULT_FIELDS = {
        "winlogbeat": [
            "@timestamp",
            "event.code",
            "host.name",
            "user.name",
            "source.ip",
            "winlog.event_data.CommandLine",
            "message",
        ],
        "auditbeat": ["@timestamp", "event.action", "host.name", "user.name", "source.ip", "process.name", "message"],
        "filebeat": ["@timestamp", "event.module", "host.name", "source.ip", "message"],
        "cef": ["@timestamp", "name", "severity", "sourceAddress", "destinationAddress", "deviceAddress", "message"],
        "default": ["@timestamp", "host.name", "message", "event.action"],
    }

    def __init__(self, search_client):
        self.search_client = search_client

    def _get_index_time_range(self, index: str) -> tuple[str, str] | None:
        """
        Get the actual timestamp range of data in an index.

        Returns:
            Tuple of (min_timestamp, max_timestamp) or None if unable to determine
        """
        try:
            # Use aggregations to efficiently get min/max timestamps
            agg_query = {
                "size": 0,
                "aggs": {"min_time": {"min": {"field": "@timestamp"}}, "max_time": {"max": {"field": "@timestamp"}}},
            }
            result = self.search_client.search_documents(index=index, body=agg_query, raw=True)
            aggs = result.get("aggregations", {})

            min_time = aggs.get("min_time", {}).get("value_as_string")
            max_time = aggs.get("max_time", {}).get("value_as_string")

            if min_time and max_time:
                return (min_time, max_time)
        except Exception:
            pass
        return None

    def _build_adaptive_time_filter(
        self, index: str, timeframe_minutes: int | None, query: str = "*"
    ) -> tuple[dict | None, str | None]:
        """
        Build time filter that adapts to actual data range if needed.

        Args:
            index: Index pattern to search
            timeframe_minutes: User-specified timeframe (None for auto-detect)
            query: Query string to check if results exist

        Returns:
            Tuple of (time_filter_dict, info_message)
        """
        # If no timeframe specified, auto-detect from index
        if timeframe_minutes is None:
            time_range = self._get_index_time_range(index)
            if time_range:
                min_time, max_time = time_range
                return (
                    {"range": {"@timestamp": {"gte": min_time, "lte": max_time}}},
                    f"Auto-detected time range: {min_time} to {max_time}",
                )
            return (None, "No time filter applied - unable to detect data range")

        # User specified a timeframe - first try it
        time_filter = {"range": {"@timestamp": {"gte": f"now-{timeframe_minutes}m", "lte": "now"}}}

        # Quick check if this timeframe has data
        check_query = {
            "size": 0,
            "query": {"bool": {"must": [{"query_string": {"query": query}}], "filter": [time_filter]}},
        }

        try:
            result = self.search_client.search_documents(index=index, body=check_query, raw=True)
            total = result.get("hits", {}).get("total", {})
            if isinstance(total, dict):
                total = total.get("value", 0)

            if total > 0:
                return (time_filter, f"Using specified timeframe: last {timeframe_minutes} minutes")

            # No results with user's timeframe - fall back to auto-detect
            time_range = self._get_index_time_range(index)
            if time_range:
                min_time, max_time = time_range
                return (
                    {"range": {"@timestamp": {"gte": min_time, "lte": max_time}}},
                    f"No data in last {timeframe_minutes}m. Auto-detected range: {min_time} to {max_time}",
                )

        except Exception:
            pass

        # Fall back to user's timeframe even if we couldn't check
        return (time_filter, f"Using specified timeframe: last {timeframe_minutes} minutes")

    def register_tools(self, mcp: FastMCP):
        @mcp.tool()
        def smart_search(
            index: str,
            query: str,
            fields: list[str] | None = None,
            max_results: int = 20,
            offset: int = 0,
            timeframe_minutes: int | None = None,
            search_after: list | None = None,
        ) -> dict:
            """
            Token-efficient search with automatic summarization and PAGINATION.

            Returns a compact summary instead of raw Elasticsearch JSON.
            Use this instead of search_documents for general queries to save tokens.

            PAGINATION: Use offset or search_after to page through large result sets.
            - offset: Skip first N results (simple but inefficient for deep paging)
            - search_after: Use sort values from previous page (efficient for large sets)

            Args:
                index: Index pattern to search (e.g., "winlogbeat-*", "cef-ssh-*")
                query: Simple query string (e.g., "failed login", "powershell")
                fields: Fields to return (auto-detected from index type if None)
                max_results: Maximum hits to return (default: 20, max: 100)
                offset: Skip first N results for pagination (default: 0)
                timeframe_minutes: Limit to last N minutes (optional)
                search_after: Sort values from previous page for efficient pagination

            Returns:
                Compact summary with:
                - total_hits: Total matching documents
                - returned: Number of hits in response
                - offset: Current offset position
                - has_more: Whether more results exist
                - next_search_after: Sort values for next page (use with search_after)
                - time_range: First and last timestamps
                - top_values: Most common values per key field
                - hits: Simplified hit list with requested fields only

            Token savings: ~85% compared to search_documents

            Example (pagination):
                # Page 1
                result = smart_search(index="winlogbeat-*", query="event.code:4625", max_results=20)
                # Page 2 using search_after (efficient)
                result = smart_search(..., search_after=result["next_search_after"])
                # Or using offset (simple)
                result = smart_search(..., offset=20)
            """
            result = self._execute_smart_search(
                index=index,
                query=query,
                fields=fields,
                max_results=max_results,
                offset=offset,
                timeframe_minutes=timeframe_minutes,
                search_after=search_after,
            )
            # Add events key for auto-capture (add_findings checks "events" for non-nested formats)
            # Preserve original "hits" key to honour the documented return contract
            if "hits" in result and isinstance(result["hits"], list):
                result["events"] = result["hits"]
            return auto_capture_elasticsearch_results(
                result, "smart_search", f"smart_search: {query} in {index}", extract_timeline=True
            )

        @mcp.tool()
        def threat_hunt_search(
            index: str,
            query: str,
            timeframe_minutes: int | None = 60,
            extract_iocs: bool = True,
            map_mitre: bool = True,
            max_sample_events: int = 5,
            analysis_size: int = 50,
            offset: int = 0,
            search_after: list | None = None,
            agg_bucket_size: int = 20,
        ) -> dict:
            """
            IR-focused search with automatic IoC extraction, MITRE mapping, and PAGINATION.

            Combines search_documents + analyze_search_results into a single call.
            Returns extracted IoCs, MITRE techniques, and recommended follow-ups.

            PAGINATION: For large investigations, use offset/search_after to page through
            events. Store discovered IoCs to investigation state for comprehensive coverage.

            Args:
                index: Index pattern to search (e.g., "winlogbeat-*")
                query: Query string for threat hunting
                timeframe_minutes: Time window to search (default: 60)
                extract_iocs: Extract IPs, users, processes, commands (default: True)
                map_mitre: Map events to MITRE ATT&CK (default: True)
                max_sample_events: Number of sample events to include (default: 5)
                analysis_size: Number of events to fetch for analysis (default: 50, max: 200)
                offset: Skip first N results for pagination (default: 0)
                search_after: Sort values from previous page for efficient pagination
                agg_bucket_size: Size of aggregation buckets for IoC extraction (default: 20)

            Returns:
                IR-focused summary with:
                - summary: Hit count, severity, confidence, coverage percentage
                - pagination: offset, has_more, next_search_after for continuation
                - iocs: Extracted indicators grouped by type (from aggregations + samples)
                - mitre_techniques: Mapped ATT&CK techniques
                - recommended_followups: Next investigation steps
                - sample_events: Representative events (limited)

            CRITICAL for large result sets:
                When total_hits >> analysis_size, use pagination and store IoCs
                to investigation state to ensure complete coverage:
                1. Call create_investigation() to start tracking
                2. Call threat_hunt_search() to get first page of IoCs
                3. Call add_iocs_to_investigation() to persist discovered IoCs
                4. Use search_after to get next page
                5. Repeat until has_more=False

            Token savings: ~80% compared to search_documents

            Example (paginated investigation):
                # Page 1
                result = threat_hunt_search(index="winlogbeat-*", query="event.code:4625")
                # Store IoCs from page 1
                add_iocs_to_investigation(iocs=result["iocs"])
                # Page 2
                result = threat_hunt_search(..., search_after=result["pagination"]["next_search_after"])
            """
            result = self._execute_threat_hunt_search(
                index=index,
                query=query,
                timeframe_minutes=timeframe_minutes,
                extract_iocs=extract_iocs,
                map_mitre=map_mitre,
                max_sample_events=max_sample_events,
                analysis_size=analysis_size,
                offset=offset,
                search_after=search_after,
                agg_bucket_size=agg_bucket_size,
            )
            # Add events key for auto-capture, preserve original keys
            if "sample_events" in result and isinstance(result["sample_events"], list):
                result["events"] = result["sample_events"]
            return auto_capture_elasticsearch_results(
                result, "threat_hunt_search", f"threat_hunt_search: {query} in {index}", extract_timeline=True
            )

        @mcp.tool()
        def quick_count(
            index: str, group_by: str, query: str = "*", timeframe_minutes: int = 60, top_n: int = 10
        ) -> dict:
            """
            Fast triage aggregation - counts without returning documents.

            Use for quick assessment of activity volume and distribution.

            Args:
                index: Index pattern to search
                group_by: Field to aggregate (e.g., "source.ip", "user.name", "event.code")
                query: Filter query (default: "*" for all)
                timeframe_minutes: Time window (default: 60)
                top_n: Number of top values to return (default: 10)

            Returns:
                Aggregation summary with:
                - total: Total matching documents
                - groups: Top N values with counts
                - timeframe: Time window searched

            Token savings: ~95% compared to search_documents

            Example:
                quick_count(
                    index="winlogbeat-*",
                    group_by="source.ip",
                    query="event.code:4625",
                    timeframe_minutes=1440
                )
            """
            return self._execute_quick_count(
                index=index, group_by=group_by, query=query, timeframe_minutes=timeframe_minutes, top_n=top_n
            )

    def _detect_index_type(self, index: str) -> str:
        """Detect index type from pattern."""
        index_lower = index.lower()
        if "winlog" in index_lower:
            return "winlogbeat"
        if "audit" in index_lower:
            return "auditbeat"
        if "file" in index_lower:
            return "filebeat"
        if "cef" in index_lower:
            return "cef"
        return "default"

    def _get_default_fields(self, index: str) -> list[str]:
        """Get default fields based on index type."""
        index_type = self._detect_index_type(index)
        return self.DEFAULT_FIELDS.get(index_type, self.DEFAULT_FIELDS["default"])

    def _build_time_filter(self, timeframe_minutes: int | None) -> dict | None:
        """Build time range filter."""
        if not timeframe_minutes:
            return None
        return {"range": {"@timestamp": {"gte": f"now-{timeframe_minutes}m", "lte": "now"}}}

    def _extract_field_value(self, source: dict, field: str):
        """Extract nested field value using dot notation."""
        keys = field.split(".")
        value = source
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None
        return value

    def _simplify_hit(self, hit: dict, fields: list[str]) -> dict:
        """Extract only requested fields from a hit."""
        source = hit.get("_source", {})
        simplified = {}
        for field in fields:
            value = self._extract_field_value(source, field)
            if value is not None:
                # Use short field name (last part after dot)
                short_name = field.split(".")[-1]
                simplified[short_name] = value
        return simplified

    def _calculate_top_values(self, hits: list[dict], fields: list[str], top_n: int = 5) -> dict:
        """Calculate most common values for each field."""
        field_values = {field: {} for field in fields}

        for hit in hits:
            source = hit.get("_source", {})
            for field in fields:
                value = self._extract_field_value(source, field)
                if value and not isinstance(value, (dict, list)):
                    value_str = str(value)
                    # Skip long values (like command lines)
                    if len(value_str) < 100:
                        field_values[field][value_str] = field_values[field].get(value_str, 0) + 1

        # Get top values for each field
        top_values = {}
        for field, values in field_values.items():
            if values:
                sorted_values = sorted(values.items(), key=lambda x: x[1], reverse=True)[:top_n]
                short_name = field.split(".")[-1]
                top_values[short_name] = [{"value": v, "count": c} for v, c in sorted_values]

        return top_values

    def _get_time_range(self, hits: list[dict]) -> dict:
        """Extract time range from hits."""
        timestamps = []
        for hit in hits:
            ts = hit.get("_source", {}).get("@timestamp")
            if ts:
                timestamps.append(ts)

        if timestamps:
            timestamps.sort()
            return {"earliest": timestamps[0], "latest": timestamps[-1]}
        return {}

    def _execute_smart_search(
        self,
        index: str,
        query: str,
        fields: list[str] | None,
        max_results: int,
        offset: int,
        timeframe_minutes: int | None,
        search_after: list | None,
    ) -> dict:
        """Execute smart search with summarization and PAGINATION support."""
        # Determine fields to extract
        if not fields:
            fields = self._get_default_fields(index)

        # Build query
        es_query = {
            "size": min(max_results, 100),  # Cap at 100 for performance
            "query": {"bool": {"must": [{"query_string": {"query": query}}]}},
            "_source": fields,
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],  # Simple sort for pagination
        }

        # Add pagination - search_after takes precedence over offset
        if search_after:
            es_query["search_after"] = search_after
        elif offset > 0:
            es_query["from"] = offset

        # Add time filter if specified
        time_filter = self._build_time_filter(timeframe_minutes)
        if time_filter:
            es_query["query"]["bool"]["filter"] = [time_filter]

        # Execute search with raw=True (we handle size management via _source filtering)
        try:
            result = self.search_client.search_documents(index=index, body=es_query, raw=True)
        except Exception as e:
            return {"error": str(e), "query_used": es_query}

        # Extract results
        total_hits = result.get("hits", {}).get("total", {})
        if isinstance(total_hits, dict):
            total_hits = total_hits.get("value", 0)

        hits = result.get("hits", {}).get("hits", [])

        # Calculate pagination info
        current_offset = offset if not search_after else None
        has_more = (
            (offset + len(hits) < total_hits)
            if not search_after
            else (len(hits) == max_results and total_hits > len(hits))
        )

        # Extract sort values from last hit for search_after pagination
        next_search_after = None
        if hits and has_more:
            next_search_after = hits[-1].get("sort")

        # Build compact response with pagination metadata
        response = {
            "summary": {
                "total_hits": total_hits,
                "returned": len(hits),
                "time_range": self._get_time_range(hits),
                "top_values": self._calculate_top_values(hits, fields),
            },
            "pagination": {"offset": current_offset, "has_more": has_more, "next_search_after": next_search_after},
            "hits": [self._simplify_hit(hit, fields) for hit in hits],
            "query_used": es_query,
        }

        # Add guidance for large result sets
        if total_hits > 100:
            response["pagination"]["guidance"] = (
                f"Large result set ({total_hits} total). Use pagination to investigate all events. "
                f"Store IoCs to investigation state using create_investigation/add_iocs_to_investigation."
            )

        # WORKFLOW HINT: Guide the AI to use analysis tools
        response["workflow_hint"] = {
            "next_step": "analyze_search_results",
            "instruction": (
                "MANDATORY: Use analyze_search_results() on these results to extract IoCs, "
                "map MITRE ATT&CK techniques, and get follow-up recommendations. "
                "Do NOT manually summarize - use the analysis tools."
            ),
            "after_analysis": "Use analyze_kill_chain_stage() to position attack in kill chain",
        }

        return response

    # IR-relevant fields for threat hunting analysis
    THREAT_HUNT_FIELDS = [
        "@timestamp",
        "event.code",
        "event.action",
        "event.category",
        "host.name",
        "host.hostname",
        "user.name",
        "user.domain",
        "source.ip",
        "source.port",
        "destination.ip",
        "destination.port",
        "process.name",
        "process.executable",
        "process.command_line",
        "process.parent.name",
        "process.parent.command_line",
        "file.name",
        "file.path",
        "file.hash.sha256",
        "registry.key",
        "registry.value",
        "winlog.event_id",
        "winlog.event_data.CommandLine",
        "winlog.event_data.TargetUserName",
        "winlog.event_data.IpAddress",
        "message",
        "name",
        "severity",
        "sourceAddress",
        "destinationAddress",
    ]

    def _execute_threat_hunt_search(
        self,
        index: str,
        query: str,
        timeframe_minutes: int,
        extract_iocs: bool,
        map_mitre: bool,
        max_sample_events: int,
        analysis_size: int = 50,
        offset: int = 0,
        search_after: list | None = None,
        agg_bucket_size: int = 20,
    ) -> dict:
        """Execute threat hunting search with automatic analysis and PAGINATION."""
        # Clamp analysis_size to reasonable range
        analysis_size = min(max(analysis_size, 10), 200)

        # Build adaptive time filter (auto-detects if no recent data)
        time_filter, time_info = self._build_adaptive_time_filter(
            index=index, timeframe_minutes=timeframe_minutes, query=query
        )

        # Build comprehensive query with _source filtering to avoid truncation
        es_query = {
            "size": analysis_size,  # Configurable analysis size
            "_source": self.THREAT_HUNT_FIELDS,  # Only fetch IR-relevant fields
            "query": {"bool": {"must": [{"query_string": {"query": query}}]}},
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],  # Simple sort for pagination
            # Add aggregations for complete IoC coverage - configurable bucket size
            "aggs": {
                "top_ips": {"terms": {"field": "source.ip", "size": agg_bucket_size}},
                "top_dest_ips": {"terms": {"field": "destination.ip", "size": agg_bucket_size}},
                "top_users": {"terms": {"field": "user.name.keyword", "size": agg_bucket_size, "missing": "N/A"}},
                "top_hosts": {"terms": {"field": "host.name.keyword", "size": agg_bucket_size}},
                "top_events": {"terms": {"field": "event.code", "size": agg_bucket_size}},
                "top_processes": {
                    "terms": {"field": "process.name.keyword", "size": agg_bucket_size, "missing": "N/A"}
                },
                "top_commands": {
                    "terms": {"field": "process.command_line.keyword", "size": agg_bucket_size, "missing": "N/A"}
                },
            },
        }

        # Add adaptive time filter if available
        if time_filter:
            es_query["query"]["bool"]["filter"] = [time_filter]

        # Add pagination - search_after takes precedence over offset
        if search_after:
            es_query["search_after"] = search_after
        elif offset > 0:
            es_query["from"] = offset

        # Execute search with raw=True (we handle size management via _source filtering)
        try:
            result = self.search_client.search_documents(index=index, body=es_query, raw=True)
        except Exception as e:
            return {"error": str(e), "query_used": es_query}

        # Get analysis using existing analyze_search_results
        analysis = self.search_client.analyze_search_results(search_results=result, context=f"Threat hunt: {query}")

        # Extract total hits
        total_hits = result.get("hits", {}).get("total", {})
        if isinstance(total_hits, dict):
            total_hits = total_hits.get("value", 0)

        hits = result.get("hits", {}).get("hits", [])

        # Calculate pagination info
        current_offset = offset if not search_after else None
        has_more = (
            (offset + len(hits) < total_hits)
            if not search_after
            else (len(hits) == analysis_size and total_hits > len(hits))
        )

        # Extract sort values from last hit for search_after pagination
        next_search_after = None
        if hits and has_more:
            next_search_after = hits[-1].get("sort")

        # Build compact IR-focused response
        # CRITICAL: Add coverage warning if sample is small relative to total
        coverage_pct = (len(hits) / total_hits * 100) if total_hits > 0 else 100
        coverage_warning = None
        if coverage_pct < 10 and total_hits > 100:
            coverage_warning = (
                f"WARNING: Only analyzed {len(hits)} of {total_hits} events ({coverage_pct:.1f}%). "
                f"IoCs may be INCOMPLETE. Use pagination (search_after) to analyze all events, "
                f"and store IoCs using add_iocs_to_investigation() for comprehensive coverage."
            )

        response = {
            "summary": {
                "total_hits": total_hits,
                "analyzed": len(hits),
                "coverage_percent": round(coverage_pct, 1),
                "severity": analysis.get("severity_assessment", "unknown"),
                "timeframe": time_info or f"last {timeframe_minutes} minutes",
            },
            "pagination": {"offset": current_offset, "has_more": has_more, "next_search_after": next_search_after},
        }

        if coverage_warning:
            response["coverage_warning"] = coverage_warning

        # Add guidance for using investigation state
        if has_more:
            response["pagination"]["guidance"] = (
                f"More events available ({total_hits - len(hits) - offset} remaining). "
                f"Use search_after={next_search_after} for next page. "
                f"IMPORTANT: Store IoCs to investigation state to preserve findings across pages."
            )

        # Add IoCs if requested - combine analysis + aggregation for complete coverage
        if extract_iocs:
            iocs = analysis.get("iocs_found", [])
            # Group by type for readability
            grouped_iocs = {}
            for ioc in iocs:
                ioc_type = ioc.get("type", "unknown")
                if ioc_type not in grouped_iocs:
                    grouped_iocs[ioc_type] = []
                grouped_iocs[ioc_type].append({"value": ioc.get("value"), "priority": ioc.get("pyramid_priority", 0)})

            # Enrich with aggregation data (covers ALL events, not just samples)
            aggs = result.get("aggregations", {})
            if aggs:
                # Add source IPs from aggregations
                for bucket in aggs.get("top_ips", {}).get("buckets", []):
                    ip = bucket.get("key")
                    if ip and (
                        "ip" not in grouped_iocs or not any(i["value"] == ip for i in grouped_iocs.get("ip", []))
                    ):
                        if "ip" not in grouped_iocs:
                            grouped_iocs["ip"] = []
                        grouped_iocs["ip"].append(
                            {"value": ip, "count": bucket.get("doc_count"), "priority": 2, "type": "source"}
                        )

                # Add destination IPs from aggregations
                for bucket in aggs.get("top_dest_ips", {}).get("buckets", []):
                    ip = bucket.get("key")
                    if ip and (
                        "ip" not in grouped_iocs or not any(i["value"] == ip for i in grouped_iocs.get("ip", []))
                    ):
                        if "ip" not in grouped_iocs:
                            grouped_iocs["ip"] = []
                        grouped_iocs["ip"].append(
                            {"value": ip, "count": bucket.get("doc_count"), "priority": 2, "type": "destination"}
                        )

                # Add users from aggregations
                for bucket in aggs.get("top_users", {}).get("buckets", []):
                    user = bucket.get("key")
                    if (
                        user
                        and user != "N/A"
                        and (
                            "user" not in grouped_iocs
                            or not any(i["value"] == user for i in grouped_iocs.get("user", []))
                        )
                    ):
                        if "user" not in grouped_iocs:
                            grouped_iocs["user"] = []
                        grouped_iocs["user"].append({"value": user, "count": bucket.get("doc_count"), "priority": 4})

                # Add hosts from aggregations
                for bucket in aggs.get("top_hosts", {}).get("buckets", []):
                    host = bucket.get("key")
                    if host and (
                        "hostname" not in grouped_iocs
                        or not any(i["value"] == host for i in grouped_iocs.get("hostname", []))
                    ):
                        if "hostname" not in grouped_iocs:
                            grouped_iocs["hostname"] = []
                        grouped_iocs["hostname"].append(
                            {"value": host, "count": bucket.get("doc_count"), "priority": 4}
                        )

                # Add processes from aggregations
                for bucket in aggs.get("top_processes", {}).get("buckets", []):
                    proc = bucket.get("key")
                    if (
                        proc
                        and proc != "N/A"
                        and (
                            "process" not in grouped_iocs
                            or not any(i["value"] == proc for i in grouped_iocs.get("process", []))
                        )
                    ):
                        if "process" not in grouped_iocs:
                            grouped_iocs["process"] = []
                        grouped_iocs["process"].append({"value": proc, "count": bucket.get("doc_count"), "priority": 5})

                # Add command lines from aggregations (TTPs - highest value IoCs)
                for bucket in aggs.get("top_commands", {}).get("buckets", []):
                    cmd = bucket.get("key")
                    if cmd and cmd != "N/A" and len(cmd) < 500:  # Skip very long commands
                        if "command_line" not in grouped_iocs:
                            grouped_iocs["command_line"] = []
                        if not any(i["value"] == cmd for i in grouped_iocs.get("command_line", [])):
                            grouped_iocs["command_line"].append(
                                {"value": cmd, "count": bucket.get("doc_count"), "priority": 6}
                            )

            response["iocs"] = grouped_iocs
            response["ioc_source"] = "aggregations + sample analysis" if aggs else "sample analysis only"
            response["ioc_bucket_size"] = agg_bucket_size  # So user knows if they need larger buckets

        # Add MITRE mapping if requested
        if map_mitre:
            response["mitre_techniques"] = analysis.get("mitre_attack_techniques", [])

        # Add insights
        response["insights"] = analysis.get("raw_insights", [])

        # Add recommendations
        response["recommended_followups"] = [
            {"action": r.get("reason"), "tool": r.get("tool"), "priority": r.get("priority")}
            for r in analysis.get("recommended_followup", [])[:5]
        ]

        # Add limited sample events
        if max_sample_events > 0:
            response["sample_events"] = [
                self._simplify_hit(hit, self._get_default_fields(index)) for hit in hits[:max_sample_events]
            ]

        # WORKFLOW HINT: Guide the AI to use kill chain analysis
        # (analyze_search_results already called internally above)
        response["workflow_hint"] = {
            "previous_step_completed": "analyze_search_results (already called internally)",
            "next_step": "analyze_kill_chain_stage",
            "instruction": (
                "Use analyze_kill_chain_stage() with the IoCs above to position this activity "
                "in the Cyber Kill Chain and get hunting suggestions for previous/next stages."
            ),
            "final_step": "Use generate_investigation_report() before presenting findings",
        }

        return response

    def _execute_quick_count(self, index: str, group_by: str, query: str, timeframe_minutes: int, top_n: int) -> dict:
        """Execute quick count aggregation."""
        # Build adaptive time filter (auto-detects if no recent data)
        time_filter, time_info = self._build_adaptive_time_filter(
            index=index, timeframe_minutes=timeframe_minutes, query=query
        )

        es_query = {
            "size": 0,  # No documents, just aggregations
            "query": {"bool": {"must": [{"query_string": {"query": query}}]}},
            "aggs": {
                "top_values": {
                    "terms": {
                        "field": group_by,  # Try without .keyword first
                        "size": top_n,
                    }
                }
            },
        }

        # Add adaptive time filter if available
        if time_filter:
            es_query["query"]["bool"]["filter"] = [time_filter]

        # Execute search with raw=True (aggregation-only query is small)
        try:
            result = self.search_client.search_documents(index=index, body=es_query, raw=True)
            buckets = result.get("aggregations", {}).get("top_values", {}).get("buckets", [])

            # If no buckets and field doesn't have .keyword, try with .keyword suffix
            # (text fields need .keyword for aggregations)
            if not buckets and not group_by.endswith(".keyword"):
                es_query["aggs"]["top_values"]["terms"]["field"] = f"{group_by}.keyword"
                result = self.search_client.search_documents(index=index, body=es_query, raw=True)
                buckets = result.get("aggregations", {}).get("top_values", {}).get("buckets", [])

        except Exception as e:
            # If aggregation failed, try the other field format
            error_str = str(e).lower()
            if "illegal_argument_exception" in error_str or "fielddata" in error_str:
                try:
                    # Toggle .keyword suffix
                    if group_by.endswith(".keyword"):
                        es_query["aggs"]["top_values"]["terms"]["field"] = group_by[:-8]  # Remove .keyword
                    else:
                        es_query["aggs"]["top_values"]["terms"]["field"] = f"{group_by}.keyword"
                    result = self.search_client.search_documents(index=index, body=es_query, raw=True)
                    buckets = result.get("aggregations", {}).get("top_values", {}).get("buckets", [])
                except Exception as e2:
                    return {"error": str(e2), "query_used": es_query}
            else:
                return {"error": str(e), "query_used": es_query}

        # Extract total
        total_hits = result.get("hits", {}).get("total", {})
        if isinstance(total_hits, dict):
            total_hits = total_hits.get("value", 0)

        return {
            "total": total_hits,
            "grouped_by": group_by,
            "timeframe": time_info or f"last {timeframe_minutes} minutes",
            "groups": [{"key": b.get("key"), "count": b.get("doc_count")} for b in buckets],
        }
