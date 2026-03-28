"""MCP Tools for ES|QL Hunting Queries."""

import logging

from fastmcp import FastMCP

from ..clients.common.schemas import (
    SYSMON_SCHEMA,
    LogSourceSchema,
    detect_schema_from_index,
    get_schema,
)
from ..clients.common.schemas.query_builder import SchemaAwareQueryBuilder

logger = logging.getLogger(__name__)


class ESQLHuntingTools:
    """Tools for executing ES|QL hunting queries from detection-rules/hunting/.

    Provides access to 121 curated ES|QL hunting queries designed for
    hypothesis-driven threat hunting with aggregations, thresholds, and
    anomaly detection.

    Requires Elasticsearch 8.11+ for ES|QL support.
    """

    def __init__(self, hunting_loader, esql_client):
        """
        Initialize ES|QL hunting tools.

        Args:
            hunting_loader: HuntingRuleLoader instance with loaded ES|QL rules
            esql_client: ESQLClient instance for query execution
        """
        self.hunting_loader = hunting_loader
        self.esql_client = esql_client

    def register_tools(self, mcp: FastMCP):
        @mcp.tool()
        def list_esql_hunts(
            platform: str | None = None, mitre_technique: str | None = None, keyword: str | None = None, limit: int = 50
        ) -> dict:
            """
            List available ES|QL hunting queries from the curated rule library.

            ES|QL hunting queries are hypothesis-driven searches with aggregations,
            thresholds, and anomaly detection - designed to find *patterns* not just
            *matches*.

            Args:
                platform: Filter by platform (linux, windows, macos, aws, azure, okta, llm, cross-platform)
                mitre_technique: Filter by MITRE technique (e.g., "T1053", "T1059.001")
                keyword: Search in rule name and description
                limit: Maximum number of results (default: 50)

            Returns:
                Dictionary containing:
                - total_found: Number of matching rules
                - rules: List of rule summaries with uuid, name, platform, mitre
                - platforms: Available platforms in the library
                - statistics: Overall library statistics

            Examples:
                # List all Windows hunting rules
                list_esql_hunts(platform="windows")

                # Find persistence-related hunts
                list_esql_hunts(mitre_technique="T1053")

                # Search for cron job hunting
                list_esql_hunts(keyword="cron")
            """
            # Search for matching rules
            rules = self.hunting_loader.search_rules(
                platform=platform, mitre=mitre_technique, keyword=keyword, limit=limit
            )

            # Get statistics
            stats = self.hunting_loader.get_statistics()

            # Format rules for display
            rule_summaries = []
            for rule in rules:
                rule_summaries.append(
                    {
                        "uuid": rule.uuid,
                        "name": rule.name,
                        "description": rule.short_description,
                        "platform": rule.platform,
                        "mitre": rule.mitre,
                        "integration": rule.integration,
                        "query_count": len(rule.esql_queries),
                    }
                )

            return {
                "total_found": len(rules),
                "showing": len(rule_summaries),
                "rules": rule_summaries,
                "platforms": self.hunting_loader.get_platforms(),
                "statistics": stats,
            }

        @mcp.tool()
        def get_esql_hunt_details(rule_id: str) -> dict:
            """
            Get detailed information about a specific ES|QL hunting rule.

            Args:
                rule_id: The unique rule identifier (UUID from list_esql_hunts)

            Returns:
                Dictionary with complete rule details including queries and notes

            Example:
                get_esql_hunt_details("2e583d3c-7ad6-4544-a0db-c685b2066493")
            """
            rule = self.hunting_loader.get_rule(rule_id)

            if not rule:
                return {
                    "error": f"Hunting rule not found: {rule_id}",
                    "suggestion": "Use list_esql_hunts() to find available rules",
                }

            return {
                "uuid": rule.uuid,
                "name": rule.name,
                "description": rule.description,
                "platform": rule.platform,
                "integration": rule.integration,
                "mitre": rule.mitre,
                "notes": rule.notes,
                "esql_queries": rule.esql_queries,
                "query_count": len(rule.esql_queries),
                "file_path": rule.file_path,
            }

        @mcp.tool()
        def execute_esql_hunt(
            rule_id: str,
            index: str | None = None,
            timeframe_days: int | None = None,
            query_index: int = 0,
            lean: bool = False,
        ) -> dict:
            """
            Execute a curated ES|QL hunting query from the rule library.

            ES|QL queries run directly against Elasticsearch (requires 8.11+).

            **Adaptive Index Resolution:**
            - If `index` is provided, uses that index directly
            - If not provided, tries the rule's default index first
            - If default index not found, auto-discovers compatible indices
              based on query field requirements and executes against the best match

            Args:
                rule_id: The unique rule identifier (UUID from list_esql_hunts)
                index: Override index pattern (e.g., "winlogbeat-*", "logs-*")
                       If not provided, uses adaptive index discovery
                timeframe_days: Override the rule's hardcoded timeframe (e.g., 7 for last 7 days)
                query_index: Which query to execute if rule has multiple (default: 0)
                lean: If True, return token-efficient summarized results

            Returns:
                Dictionary containing:
                - rule_info: Rule metadata (includes MITRE and hunting_guidance only if hits found)
                - index_resolution: Details about which index was used
                - hits_count: Number of results
                - tokens_used: Estimated token count
                - columns: Column names from ES|QL result
                - results: Query results (full or summarised based on lean)
                - investigation_context: When hits found, includes:
                    - mitre_techniques: ATT&CK technique IDs
                    - hunting_tips: Investigation guidance from the rule
                    - next_steps: Recommended follow-up actions

            Examples:
                # Execute with adaptive index discovery (recommended)
                execute_esql_hunt("2e583d3c-7ad6-4544-a0db-c685b2066493")

                # Override to use winlogbeat index
                execute_esql_hunt("2e583d3c-7ad6-4544-a0db-c685b2066493", index="winlogbeat-*")

                # Override timeframe to last 7 days
                execute_esql_hunt("2e583d3c-7ad6-4544-a0db-c685b2066493", timeframe_days=7)

                # Get token-efficient results
                execute_esql_hunt("2e583d3c-7ad6-4544-a0db-c685b2066493", lean=True)
            """
            # Get the rule
            rule = self.hunting_loader.get_rule(rule_id)

            if not rule:
                return {
                    "error": f"Hunting rule not found: {rule_id}",
                    "suggestion": "Use list_esql_hunts() to find available rules",
                }

            # Validate query index
            if query_index >= len(rule.esql_queries):
                return {
                    "error": f"Query index {query_index} out of range",
                    "available_queries": len(rule.esql_queries),
                    "suggestion": f"Use query_index 0-{len(rule.esql_queries) - 1}",
                }

            # Get the query
            query = rule.esql_queries[query_index]

            # Apply timeframe override if specified
            if timeframe_days:
                query = self.esql_client.substitute_timeframe(query, timeframe_days)

            # Execute with adaptive index resolution
            result = self.esql_client.execute_with_auto_discovery(query=query, index=index, lean=lean, rule_id=rule_id)

            # Add rule metadata - base info always included
            result["rule_info"] = {
                "uuid": rule.uuid,
                "name": rule.name,
                "platform": rule.platform,
            }

            # Check if we have actual hits (true positives)
            hits_count = result.get("hits_count", 0)
            has_results = hits_count > 0

            if has_results:
                # Include full investigation guidance when there are findings
                result["rule_info"]["mitre"] = rule.mitre
                result["rule_info"]["hunting_guidance"] = rule.notes

                # Add actionable context for the analyst
                result["investigation_context"] = {
                    "findings_detected": True,
                    "hits_count": hits_count,
                    "mitre_techniques": rule.mitre,
                    "hunting_tips": rule.notes,
                    "next_steps": [
                        "Review the results for true positives vs false positives",
                        "Correlate findings with other log sources",
                        "Check affected hosts for additional indicators",
                        f"Research MITRE techniques: {', '.join(rule.mitre)}" if rule.mitre else None,
                    ],
                }
                # Filter out None values from next_steps
                result["investigation_context"]["next_steps"] = [
                    s for s in result["investigation_context"]["next_steps"] if s
                ]
            else:
                # No hits - minimal output
                result["investigation_context"] = {
                    "findings_detected": False,
                    "message": "No matches found for this hunting query in the specified timeframe",
                }

            return result

        @mcp.tool()
        def esql_query(query: str, auto_discover: bool = True, lean: bool = False) -> dict:
            """
            Execute a raw ES|QL query for ad-hoc threat hunting.

            ES|QL is Elasticsearch's piped query language (8.11+) designed for
            data exploration with aggregations, transformations, and enrichment.

            Args:
                query: The ES|QL query string (must start with FROM)
                auto_discover: If True and index not found, auto-discover compatible indices
                lean: If True, return token-efficient summarized results

            Returns:
                Dictionary containing:
                - hits_count: Number of results
                - tokens_used: Estimated token count
                - execution_time_ms: Query execution time
                - columns: Column names from result
                - results: Query results (full or summarized)
                - index_resolution: Details about which index was used (if auto_discover=True)

            Examples:
                # Simple query with auto-discovery
                esql_query("FROM logs-endpoint.events.process-* | LIMIT 10")

                # Aggregation query
                esql_query('''
                    FROM logs-endpoint.events.process-*
                    | WHERE host.os.type == "windows"
                    | STATS count = COUNT(*) BY process.name
                    | SORT count DESC
                    | LIMIT 20
                ''')

                # Disable auto-discovery (fail if index not found)
                esql_query("FROM logs-* | LIMIT 10", auto_discover=False)

                # Token-efficient mode
                esql_query("FROM logs-* | LIMIT 100", lean=True)
            """
            if auto_discover:
                result = self.esql_client.execute_with_auto_discovery(query=query, lean=lean)
            else:
                result = self.esql_client.execute(query=query, lean=lean)

            return result

        @mcp.tool()
        def discover_esql_indices(fields: list[str] | None = None, data_type: str | None = None) -> dict:
            """
            Discover available indices for ES|QL hunting.

            Use this to find indices compatible with your hunting queries, especially
            when the default index patterns (e.g., logs-endpoint.*) don't exist in
            your environment.

            Args:
                fields: List of field names to search for (e.g., ["process.name", "user.name"])
                        If not provided, shows all non-empty indices
                data_type: Optional hint for data type (windows, linux, network)

            Returns:
                Dictionary containing:
                - indices: List of matching indices with doc counts and match scores
                - total_indices: Total number of non-empty indices
                - field_aliases: Common field name mappings for reference

            Examples:
                # Find all available indices
                discover_esql_indices()

                # Find indices with process execution data
                discover_esql_indices(fields=["process.name", "process.command_line"])

                # Find indices with network data
                discover_esql_indices(fields=["destination.ip", "source.ip"])
            """
            try:
                # Get all indices
                indices_info = self.esql_client.client.cat.indices(format="json", h="index,docs.count,store.size")

                all_indices = []
                for idx_info in indices_info:
                    index_name = idx_info.get("index", "")
                    doc_count = int(idx_info.get("docs.count", 0) or 0)

                    # Skip system indices and empty indices
                    if index_name.startswith(".") or doc_count == 0:
                        continue

                    all_indices.append(
                        {"index": index_name, "doc_count": doc_count, "size": idx_info.get("store.size", "unknown")}
                    )

                # Sort by doc count
                all_indices.sort(key=lambda x: -x["doc_count"])

                # If fields specified, filter by field compatibility
                if fields:
                    compatible = self.esql_client.discover_compatible_indices(fields, data_type)
                    return {
                        "compatible_indices": compatible,
                        "total_checked": len(all_indices),
                        "required_fields": fields,
                        "field_aliases": self.esql_client.FIELD_ALIASES,
                        "suggestion": (
                            f"Found {len(compatible)} indices with matching fields. "
                            f"Use the top match in your FROM clause or override with index parameter."
                        ),
                    }
                return {
                    "indices": all_indices[:20],  # Top 20 by doc count
                    "total_indices": len(all_indices),
                    "field_aliases": self.esql_client.FIELD_ALIASES,
                    "suggestion": (
                        "Use discover_esql_indices(fields=['process.name', ...]) to find "
                        "indices compatible with specific queries."
                    ),
                }

            except Exception as e:
                return {"error": f"Failed to discover indices: {str(e)}", "indices": []}

        @mcp.tool()
        def get_esql_execution_history() -> dict:
            """
            Get ES|QL query execution history for token usage analysis.

            Returns recent query executions with their token counts, hit counts,
            and execution times. Useful for optimizing query efficiency.

            Returns:
                Dictionary containing:
                - executions: List of recent executions with metrics
                - summary: Aggregate statistics

            Example:
                get_esql_execution_history()
            """
            history = self.esql_client.get_execution_history()

            if not history:
                return {
                    "executions": [],
                    "summary": {"total_executions": 0, "total_tokens_used": 0, "avg_tokens_per_query": 0},
                }

            total_tokens = sum(e["result_tokens"] for e in history)
            avg_tokens = total_tokens // len(history) if history else 0

            return {
                "executions": history[-20:],  # Last 20 executions
                "summary": {
                    "total_executions": len(history),
                    "total_tokens_used": total_tokens,
                    "avg_tokens_per_query": avg_tokens,
                    "avg_execution_time_ms": sum(e["execution_time_ms"] for e in history) // len(history)
                    if history
                    else 0,
                },
            }

        @mcp.tool()
        def check_esql_support() -> dict:
            """
            Check if the connected Elasticsearch cluster supports ES|QL.

            ES|QL requires Elasticsearch 8.11 or later. This tool checks the
            cluster version and confirms ES|QL availability.

            Returns:
                Dictionary containing:
                - supported: Whether ES|QL is supported
                - es_version: Detected Elasticsearch version
                - min_required: Minimum required version

            Example:
                check_esql_support()
            """
            try:
                self.esql_client.check_version()
                return {
                    "supported": True,
                    "es_version": self.esql_client.es_version,
                    "min_required": "8.11",
                    "status": "ES|QL is available and ready to use",
                }
            except Exception as e:
                return {
                    "supported": False,
                    "es_version": self.esql_client.es_version,
                    "min_required": "8.11",
                    "error": str(e),
                    "status": "ES|QL is not available on this cluster",
                }

        @mcp.tool()
        def hunt_suspicious_process_activity(
            process_name: str,
            index: str | None = None,
            timeframe_days: int = 7,
            include_network: bool = True,
            include_files: bool = True,
            include_child_processes: bool = True,
            include_registry: bool = True,
            include_process_access: bool = True,
            include_remote_threads: bool = True,
            include_dns: bool = True,
            schema_hint: str | None = None,
            max_results: int = 100,
        ) -> dict:
            """
            Hunt for all activity associated with a suspicious process.

            This is a multi-stage ES|QL hunt that:
            1. Finds when the suspicious process started and stopped (time bounds)
            2. Identifies the host(s) where it ran
            3. Queries for child processes spawned during that window
            4. Queries for files created/modified during that window
            5. Queries for outbound network connections during that window
            6. Queries for process access events (credential dumping indicator)
            7. Queries for remote thread creation (injection indicator)
            8. Queries for DNS queries made by the process
            9. Queries for registry modifications

            **Schema-Aware Queries:**
            This tool automatically adapts to different log source schemas:
            - sysmon: Winlogbeat with Sysmon events (winlog.event_data.* fields)
            - ecs: Elastic Common Schema (process.*, file.*, etc.)
            - windows_security: Windows Security events (Event IDs 4688, etc.)

            Use `schema_hint` to explicitly specify the schema, or let the tool
            auto-detect based on index patterns.

            Use this tool when:
            - A previous hunt identified a suspicious process name (from IoCs)
            - User wants to investigate a known-bad process
            - You need to understand the full scope of process activity

            Args:
                process_name: Name of the suspicious process (e.g., "maze.exe", "mimikatz.exe")
                index: Base index pattern (default: auto-discovers auditbeat-*, winlogbeat-*, logs-*)
                timeframe_days: Initial search window in days (default: 7)
                include_network: Include outbound network connections (default: True)
                include_files: Include file operations (default: True)
                include_child_processes: Include child process spawns (default: True)
                include_registry: Include registry modifications (default: True)
                include_process_access: Include Event ID 10 ProcessAccess (default: True)
                include_remote_threads: Include Event ID 8 CreateRemoteThread (default: True)
                include_dns: Include DNS queries (default: True)
                schema_hint: Log source schema - "sysmon", "ecs", "windows_security" (auto-detected if not specified)
                max_results: Maximum results per category (default: 100)

            Returns:
                Dictionary containing:
                - schema_used: The schema used for query generation
                - process_bounds: Start/stop times and affected hosts
                - child_processes: Processes spawned by the suspicious process
                - file_operations: Files created/modified during execution
                - network_connections: Outbound connections made
                - process_access: Process access events (LSASS access indicator)
                - remote_threads: Remote thread creation events (injection indicator)
                - dns_queries: DNS queries made by the process
                - registry_operations: Registry modifications
                - timeline: Chronological view of all activity
                - iocs: Extracted indicators for further hunting

            Example:
                # Hunt for ransomware activity with Sysmon data
                hunt_suspicious_process_activity(
                    process_name="maze.exe",
                    schema_hint="sysmon"
                )

                # Hunt for credential dumping tool
                hunt_suspicious_process_activity(
                    process_name="mimikatz.exe",
                    include_process_access=True,
                    include_remote_threads=True
                )

            MITRE ATT&CK Coverage:
                - T1059: Command and Scripting Interpreter
                - T1055: Process Injection (remote threads)
                - T1003: OS Credential Dumping (process access)
                - T1083: File and Directory Discovery
                - T1071: Application Layer Protocol (network)
                - T1112: Modify Registry
            """
            results = {
                "process_name": process_name,
                "hunt_parameters": {
                    "timeframe_days": timeframe_days,
                    "include_network": include_network,
                    "include_files": include_files,
                    "include_child_processes": include_child_processes,
                    "include_registry": include_registry,
                    "include_process_access": include_process_access,
                    "include_remote_threads": include_remote_threads,
                    "include_dns": include_dns,
                    "schema_hint": schema_hint,
                },
                "stages": [],
                "schema_used": None,
                "process_bounds": None,
                "child_processes": [],
                "file_operations": [],
                "network_connections": [],
                "process_access": [],
                "remote_threads": [],
                "dns_queries": [],
                "registry_operations": [],
                "timeline": [],
                "iocs": {"processes": [], "files": [], "ips": [], "hostnames": [], "registry_keys": [], "domains": []},
                "errors": [],
            }

            # Determine index patterns to search
            process_index = index or "winlogbeat-*,auditbeat-*,logs-endpoint.events.process-*"
            file_index = index or "winlogbeat-*,auditbeat-*,logs-endpoint.events.file-*"
            network_index = index or "winlogbeat-*,auditbeat-*,logs-endpoint.events.network-*"

            # Resolve schema - explicit hint > auto-detect from index > default to sysmon
            schema: LogSourceSchema | None = None
            if schema_hint:
                schema = get_schema(schema_hint)
                if not schema:
                    results["errors"].append(
                        f"Unknown schema '{schema_hint}'. Available: sysmon, ecs, windows_security"
                    )
            if not schema:
                schema = detect_schema_from_index(process_index)
            if not schema:
                # Default to Sysmon for winlogbeat indices
                schema = SYSMON_SCHEMA
                logger.info(f"Using default Sysmon schema for index '{process_index}'")

            results["schema_used"] = {
                "schema_id": schema.schema_id,
                "name": schema.name,
                "field_prefix": schema.field_prefix,
                "index": process_index,
            }

            # Create query builder for schema-aware queries
            query_builder = SchemaAwareQueryBuilder(schema=schema, index=process_index, max_results=max_results)

            # =====================================================================
            # Stage 1: Find process execution bounds (start/stop times and hosts)
            # =====================================================================
            try:
                stage1_query_result = query_builder.build_process_bounds_query(process_name)
                stage1_query = stage1_query_result.query

                stage1_result = self.esql_client.execute(stage1_query, lean=False)
                results["stages"].append(
                    {
                        "stage": 1,
                        "name": "Process Bounds Discovery",
                        "query": stage1_query.strip(),
                        "schema_fields": stage1_query_result.fields_used,
                        "event_code": stage1_query_result.event_code,
                        "status": "success",
                        "hits": stage1_result.get("hits_count", 0),
                    }
                )

                # Extract bounds from results
                if stage1_result.get("hits_count", 0) > 0:
                    rows = stage1_result.get("results", [])
                    if rows:
                        row = rows[0] if isinstance(rows, list) else rows
                        start_time = row.get("start_time")
                        end_time = row.get("end_time")
                        hosts = row.get("hosts", [])
                        count = row.get("count", 0)

                        # Ensure hosts is a list
                        if isinstance(hosts, str):
                            hosts = [hosts]

                        results["process_bounds"] = {
                            "start_time": start_time,
                            "end_time": end_time,
                            "hosts": hosts,
                            "event_count": count,
                            "duration_info": "Time window for subsequent queries",
                        }

                        # Add to IoCs
                        results["iocs"]["hostnames"].extend(hosts if hosts else [])

                        # Use first host for subsequent queries
                        target_host = hosts[0] if hosts else None

                        stage_num = 2  # Track stage number for dynamic stages

                        # =====================================================================
                        # Stage 2: Child Processes (spawned by suspicious process)
                        # =====================================================================
                        if include_child_processes and start_time and end_time and target_host:
                            try:
                                stage2_query_result = query_builder.build_child_processes_query(
                                    parent_process_name=process_name,
                                    host=target_host,
                                    start_time=start_time,
                                    end_time=end_time,
                                )
                                stage2_query = stage2_query_result.query

                                stage2_result = self.esql_client.execute(stage2_query, lean=False)
                                results["stages"].append(
                                    {
                                        "stage": stage_num,
                                        "name": "Child Process Discovery",
                                        "query": stage2_query.strip(),
                                        "schema_fields": stage2_query_result.fields_used,
                                        "event_code": stage2_query_result.event_code,
                                        "status": "success",
                                        "hits": stage2_result.get("hits_count", 0),
                                    }
                                )

                                child_procs = stage2_result.get("results", [])
                                results["child_processes"] = child_procs

                                # Add to timeline and IoCs
                                for proc in child_procs if isinstance(child_procs, list) else []:
                                    timestamp_field = schema.timestamp_field
                                    process_field = schema.get_field("source_process", "process_create")

                                    results["timeline"].append(
                                        {
                                            "timestamp": proc.get(timestamp_field),
                                            "type": "child_process",
                                            "details": proc,
                                        }
                                    )
                                    if process_field and proc.get(process_field):
                                        results["iocs"]["processes"].append(proc.get(process_field))

                            except ValueError as e:
                                # Schema doesn't support this event type
                                results["stages"].append(
                                    {
                                        "stage": stage_num,
                                        "name": "Child Process Discovery",
                                        "status": "skipped",
                                        "reason": str(e),
                                    }
                                )
                            except Exception as e:
                                results["stages"].append(
                                    {
                                        "stage": stage_num,
                                        "name": "Child Process Discovery",
                                        "status": "error",
                                        "error": str(e),
                                    }
                                )
                                results["errors"].append(f"Stage {stage_num} (child processes): {str(e)}")

                            stage_num += 1

                        # =====================================================================
                        # Stage 3: File Operations (created/modified during execution)
                        # =====================================================================
                        if include_files and start_time and end_time and target_host:
                            try:
                                stage3_query_result = query_builder.build_file_operations_query(
                                    process_name=process_name,
                                    host=target_host,
                                    start_time=start_time,
                                    end_time=end_time,
                                )
                                stage3_query = stage3_query_result.query

                                stage3_result = self.esql_client.execute(stage3_query, lean=False)
                                results["stages"].append(
                                    {
                                        "stage": stage_num,
                                        "name": "File Operations Discovery",
                                        "query": stage3_query.strip(),
                                        "schema_fields": stage3_query_result.fields_used,
                                        "event_code": stage3_query_result.event_code,
                                        "status": "success",
                                        "hits": stage3_result.get("hits_count", 0),
                                    }
                                )

                                file_ops = stage3_result.get("results", [])
                                results["file_operations"] = file_ops

                                # Add to timeline and IoCs
                                timestamp_field = schema.timestamp_field
                                target_file_field = schema.get_field("target_filename", "file_create")

                                for file_op in file_ops if isinstance(file_ops, list) else []:
                                    results["timeline"].append(
                                        {
                                            "timestamp": file_op.get(timestamp_field),
                                            "type": "file_operation",
                                            "details": file_op,
                                        }
                                    )
                                    if target_file_field and file_op.get(target_file_field):
                                        results["iocs"]["files"].append(file_op.get(target_file_field))

                            except ValueError as e:
                                results["stages"].append(
                                    {
                                        "stage": stage_num,
                                        "name": "File Operations Discovery",
                                        "status": "skipped",
                                        "reason": str(e),
                                    }
                                )
                            except Exception as e:
                                results["stages"].append(
                                    {
                                        "stage": stage_num,
                                        "name": "File Operations Discovery",
                                        "status": "error",
                                        "error": str(e),
                                    }
                                )
                                results["errors"].append(f"Stage {stage_num} (file operations): {str(e)}")

                            stage_num += 1

                        # =====================================================================
                        # Stage 4: Network Connections (outbound during execution)
                        # =====================================================================
                        if include_network and start_time and end_time and target_host:
                            try:
                                stage4_query_result = query_builder.build_network_connections_query(
                                    process_name=process_name,
                                    host=target_host,
                                    start_time=start_time,
                                    end_time=end_time,
                                )
                                stage4_query = stage4_query_result.query

                                stage4_result = self.esql_client.execute(stage4_query, lean=False)
                                results["stages"].append(
                                    {
                                        "stage": stage_num,
                                        "name": "Network Connections Discovery",
                                        "query": stage4_query.strip(),
                                        "schema_fields": stage4_query_result.fields_used,
                                        "event_code": stage4_query_result.event_code,
                                        "status": "success",
                                        "hits": stage4_result.get("hits_count", 0),
                                    }
                                )

                                net_conns = stage4_result.get("results", [])
                                results["network_connections"] = net_conns

                                # Add to timeline and IoCs
                                timestamp_field = schema.timestamp_field
                                dest_ip_field = schema.get_field("destination_ip", "network_connection")

                                for conn in net_conns if isinstance(net_conns, list) else []:
                                    results["timeline"].append(
                                        {
                                            "timestamp": conn.get(timestamp_field),
                                            "type": "network_connection",
                                            "details": conn,
                                        }
                                    )
                                    if dest_ip_field and conn.get(dest_ip_field):
                                        results["iocs"]["ips"].append(conn.get(dest_ip_field))

                            except ValueError as e:
                                results["stages"].append(
                                    {
                                        "stage": stage_num,
                                        "name": "Network Connections Discovery",
                                        "status": "skipped",
                                        "reason": str(e),
                                    }
                                )
                            except Exception as e:
                                results["stages"].append(
                                    {
                                        "stage": stage_num,
                                        "name": "Network Connections Discovery",
                                        "status": "error",
                                        "error": str(e),
                                    }
                                )
                                results["errors"].append(f"Stage {stage_num} (network connections): {str(e)}")

                            stage_num += 1

                        # =====================================================================
                        # Stage 5: Registry Operations (persistence indicators)
                        # =====================================================================
                        if include_registry and start_time and end_time and target_host:
                            try:
                                stage5_query_result = query_builder.build_registry_operations_query(
                                    process_name=process_name,
                                    host=target_host,
                                    start_time=start_time,
                                    end_time=end_time,
                                )
                                stage5_query = stage5_query_result.query

                                stage5_result = self.esql_client.execute(stage5_query, lean=False)
                                results["stages"].append(
                                    {
                                        "stage": stage_num,
                                        "name": "Registry Operations Discovery",
                                        "query": stage5_query.strip(),
                                        "schema_fields": stage5_query_result.fields_used,
                                        "event_code": stage5_query_result.event_code,
                                        "status": "success",
                                        "hits": stage5_result.get("hits_count", 0),
                                    }
                                )

                                reg_ops = stage5_result.get("results", [])
                                results["registry_operations"] = reg_ops

                                # Add to timeline and IoCs
                                timestamp_field = schema.timestamp_field
                                target_object_field = schema.get_field("target_object", "registry_value_set")

                                for reg_op in reg_ops if isinstance(reg_ops, list) else []:
                                    results["timeline"].append(
                                        {
                                            "timestamp": reg_op.get(timestamp_field),
                                            "type": "registry_operation",
                                            "details": reg_op,
                                        }
                                    )
                                    if target_object_field and reg_op.get(target_object_field):
                                        results["iocs"]["registry_keys"].append(reg_op.get(target_object_field))

                            except ValueError as e:
                                results["stages"].append(
                                    {
                                        "stage": stage_num,
                                        "name": "Registry Operations Discovery",
                                        "status": "skipped",
                                        "reason": str(e),
                                    }
                                )
                            except Exception as e:
                                results["stages"].append(
                                    {
                                        "stage": stage_num,
                                        "name": "Registry Operations Discovery",
                                        "status": "error",
                                        "error": str(e),
                                    }
                                )
                                results["errors"].append(f"Stage {stage_num} (registry operations): {str(e)}")

                            stage_num += 1

                        # =====================================================================
                        # Stage 6: Process Access (credential dumping detection)
                        # =====================================================================
                        if include_process_access and start_time and end_time and target_host:
                            try:
                                stage6_query_result = query_builder.build_process_access_query(
                                    process_name=process_name,
                                    host=target_host,
                                    start_time=start_time,
                                    end_time=end_time,
                                    as_source=True,
                                    as_target=True,
                                )
                                stage6_query = stage6_query_result.query

                                stage6_result = self.esql_client.execute(stage6_query, lean=False)
                                results["stages"].append(
                                    {
                                        "stage": stage_num,
                                        "name": "Process Access Discovery (Credential Dumping)",
                                        "query": stage6_query.strip(),
                                        "schema_fields": stage6_query_result.fields_used,
                                        "event_code": stage6_query_result.event_code,
                                        "status": "success",
                                        "hits": stage6_result.get("hits_count", 0),
                                    }
                                )

                                proc_access = stage6_result.get("results", [])
                                results["process_access"] = proc_access

                                # Add to timeline
                                timestamp_field = schema.timestamp_field
                                for access in proc_access if isinstance(proc_access, list) else []:
                                    results["timeline"].append(
                                        {
                                            "timestamp": access.get(timestamp_field),
                                            "type": "process_access",
                                            "details": access,
                                        }
                                    )

                            except ValueError as e:
                                results["stages"].append(
                                    {
                                        "stage": stage_num,
                                        "name": "Process Access Discovery",
                                        "status": "skipped",
                                        "reason": str(e),
                                    }
                                )
                            except Exception as e:
                                results["stages"].append(
                                    {
                                        "stage": stage_num,
                                        "name": "Process Access Discovery",
                                        "status": "error",
                                        "error": str(e),
                                    }
                                )
                                results["errors"].append(f"Stage {stage_num} (process access): {str(e)}")

                            stage_num += 1

                        # =====================================================================
                        # Stage 7: Remote Thread Creation (process injection detection)
                        # =====================================================================
                        if include_remote_threads and start_time and end_time and target_host:
                            try:
                                stage7_query_result = query_builder.build_remote_thread_query(
                                    process_name=process_name,
                                    host=target_host,
                                    start_time=start_time,
                                    end_time=end_time,
                                    as_source=True,
                                    as_target=True,
                                )
                                stage7_query = stage7_query_result.query

                                stage7_result = self.esql_client.execute(stage7_query, lean=False)
                                results["stages"].append(
                                    {
                                        "stage": stage_num,
                                        "name": "Remote Thread Discovery (Process Injection)",
                                        "query": stage7_query.strip(),
                                        "schema_fields": stage7_query_result.fields_used,
                                        "event_code": stage7_query_result.event_code,
                                        "status": "success",
                                        "hits": stage7_result.get("hits_count", 0),
                                    }
                                )

                                remote_threads = stage7_result.get("results", [])
                                results["remote_threads"] = remote_threads

                                # Add to timeline
                                timestamp_field = schema.timestamp_field
                                for thread in remote_threads if isinstance(remote_threads, list) else []:
                                    results["timeline"].append(
                                        {
                                            "timestamp": thread.get(timestamp_field),
                                            "type": "remote_thread",
                                            "details": thread,
                                        }
                                    )

                            except ValueError as e:
                                results["stages"].append(
                                    {
                                        "stage": stage_num,
                                        "name": "Remote Thread Discovery",
                                        "status": "skipped",
                                        "reason": str(e),
                                    }
                                )
                            except Exception as e:
                                results["stages"].append(
                                    {
                                        "stage": stage_num,
                                        "name": "Remote Thread Discovery",
                                        "status": "error",
                                        "error": str(e),
                                    }
                                )
                                results["errors"].append(f"Stage {stage_num} (remote threads): {str(e)}")

                            stage_num += 1

                        # =====================================================================
                        # Stage 8: DNS Queries (C2 communication detection)
                        # =====================================================================
                        if include_dns and start_time and end_time and target_host:
                            try:
                                stage8_query_result = query_builder.build_dns_query(
                                    process_name=process_name,
                                    host=target_host,
                                    start_time=start_time,
                                    end_time=end_time,
                                )
                                stage8_query = stage8_query_result.query

                                stage8_result = self.esql_client.execute(stage8_query, lean=False)
                                results["stages"].append(
                                    {
                                        "stage": stage_num,
                                        "name": "DNS Query Discovery (C2 Detection)",
                                        "query": stage8_query.strip(),
                                        "schema_fields": stage8_query_result.fields_used,
                                        "event_code": stage8_query_result.event_code,
                                        "status": "success",
                                        "hits": stage8_result.get("hits_count", 0),
                                    }
                                )

                                dns_queries = stage8_result.get("results", [])
                                results["dns_queries"] = dns_queries

                                # Add to timeline and IoCs
                                timestamp_field = schema.timestamp_field
                                query_name_field = schema.get_field("query_name", "dns_query")

                                for dns_q in dns_queries if isinstance(dns_queries, list) else []:
                                    results["timeline"].append(
                                        {"timestamp": dns_q.get(timestamp_field), "type": "dns_query", "details": dns_q}
                                    )
                                    if query_name_field and dns_q.get(query_name_field):
                                        results["iocs"]["domains"].append(dns_q.get(query_name_field))

                            except ValueError as e:
                                results["stages"].append(
                                    {
                                        "stage": stage_num,
                                        "name": "DNS Query Discovery",
                                        "status": "skipped",
                                        "reason": str(e),
                                    }
                                )
                            except Exception as e:
                                results["stages"].append(
                                    {
                                        "stage": stage_num,
                                        "name": "DNS Query Discovery",
                                        "status": "error",
                                        "error": str(e),
                                    }
                                )
                                results["errors"].append(f"Stage {stage_num} (DNS queries): {str(e)}")

                        # Sort timeline chronologically
                        results["timeline"].sort(key=lambda x: x.get("timestamp", ""))

                else:
                    results["stages"][0]["message"] = (
                        f"No execution of '{process_name}' found in the last {timeframe_days} days"
                    )

            except ValueError as e:
                # Schema doesn't support required event types
                results["stages"].append(
                    {"stage": 1, "name": "Process Bounds Discovery", "status": "skipped", "reason": str(e)}
                )
                results["errors"].append(f"Schema limitation: {str(e)}")
            except Exception as e:
                results["stages"].append(
                    {"stage": 1, "name": "Process Bounds Discovery", "status": "error", "error": str(e)}
                )
                results["errors"].append(f"Stage 1 (process bounds): {str(e)}")

            # Deduplicate IoCs
            results["iocs"]["processes"] = list(set(results["iocs"]["processes"]))
            results["iocs"]["files"] = list(set(results["iocs"]["files"]))
            results["iocs"]["ips"] = list(set(results["iocs"]["ips"]))
            results["iocs"]["hostnames"] = list(set(results["iocs"]["hostnames"]))
            results["iocs"]["registry_keys"] = list(set(results["iocs"]["registry_keys"]))
            results["iocs"]["domains"] = list(set(results["iocs"]["domains"]))

            # Summary
            results["summary"] = {
                "process_found": results["process_bounds"] is not None,
                "schema_used": schema.schema_id if schema else None,
                "hosts_affected": len(results["iocs"]["hostnames"]),
                "child_processes_count": len(results["child_processes"]),
                "file_operations_count": len(results["file_operations"]),
                "network_connections_count": len(results["network_connections"]),
                "registry_operations_count": len(results["registry_operations"]),
                "process_access_count": len(results["process_access"]),
                "remote_threads_count": len(results["remote_threads"]),
                "dns_queries_count": len(results["dns_queries"]),
                "total_timeline_events": len(results["timeline"]),
                "total_iocs_extracted": (
                    len(results["iocs"]["processes"])
                    + len(results["iocs"]["files"])
                    + len(results["iocs"]["ips"])
                    + len(results["iocs"]["hostnames"])
                    + len(results["iocs"]["registry_keys"])
                    + len(results["iocs"]["domains"])
                ),
                "mitre_techniques": [
                    "T1059",  # Command and Scripting Interpreter
                    "T1055",  # Process Injection
                    "T1083",  # File and Directory Discovery
                    "T1071",  # Application Layer Protocol
                    "T1003",  # OS Credential Dumping
                    "T1547",  # Boot or Logon Autostart Execution
                    "T1112",  # Modify Registry
                ],
            }

            return results
