"""MCP Tools for Detection Rule Management."""
from typing import Dict, List, Optional
from fastmcp import FastMCP


class RuleManagementTools:
    """Tools for managing and executing detection rules."""

    def _execute_single_rule(self, rule_id: str, index: str,
                             timeframe_minutes: int = 15, size: int = 100) -> Dict:
        """Execute a single detection rule (internal, no MCP wrapper)."""
        rule = self.rule_loader.get_rule(rule_id)
        if not rule:
            return {"error": f"Rule not found: {rule_id}"}

        try:
            if rule.rule_type == "lucene":
                result = self.search_client.search_with_lucene(
                    index=index,
                    lucene_query=rule.query,
                    timeframe_minutes=timeframe_minutes if timeframe_minutes > 0 else None,
                    size=min(size, 1000),
                )
            elif rule.rule_type == "eql":
                result = self.search_client.eql_search(
                    index=index,
                    query=rule.query,
                    start_time=f"now-{timeframe_minutes}m" if timeframe_minutes > 0 else None,
                    size=min(size, 1000),
                )
            else:
                return {"error": f"Unsupported rule type: {rule.rule_type}"}

            result["rule_info"] = {
                "rule_id": rule.rule_id,
                "name": rule.display_name,
                "platform": rule.platform,
                "log_source": rule.log_source,
                "type": rule.rule_type,
                "mitre_tactics": list(rule.mitre_tactics),
            }
            return result
        except Exception as e:
            return {"error": f"Failed to execute rule {rule_id}: {e}"}

    def __init__(self, rule_loader, search_client):
        """
        Initialize rule management tools.

        Args:
            rule_loader: RuleLoader instance with loaded rules
            search_client: Elasticsearch client for executing rules
        """
        self.rule_loader = rule_loader
        self.search_client = search_client

    def register_tools(self, mcp: FastMCP):
        @mcp.tool()
        def list_detection_rules(
            platform: Optional[str] = None,
            log_source: Optional[str] = None,
            rule_type: Optional[str] = None,
            search_term: Optional[str] = None,
            mitre_tactic: Optional[str] = None,
            limit: int = 50
        ) -> Dict:
            """
            List available detection rules with optional filtering.

            This tool provides access to the comprehensive rule library
            containing 5000+ community detection rules for threat hunting.

            Args:
                platform: Filter by platform (windows, linux, macos, application, cloud, network)
                log_source: Filter by log source (powershell, process_creation, builtin, audit, etc.)
                rule_type: Filter by rule type (lucene, eql)
                search_term: Search in rule names, tags, and descriptions
                mitre_tactic: Filter by MITRE ATT&CK tactic
                    (execution, persistence, privilege_escalation, defense_evasion,
                     credential_access, discovery, lateral_movement, collection,
                     command_and_control, exfiltration, impact)
                limit: Maximum number of results (default: 50, max: 200)

            Returns:
                Dictionary containing:
                - total_found: Number of matching rules
                - rules: List of rule summaries
                - platforms: Available platforms
                - log_sources: Available log sources

            Examples:
                # List Windows PowerShell rules
                list_detection_rules(platform="windows", log_source="powershell")

                # Find credential access rules
                list_detection_rules(mitre_tactic="credential_access")

                # Search for mimikatz-related rules
                list_detection_rules(search_term="mimikatz")

                # Get all EQL rules for Linux
                list_detection_rules(platform="linux", rule_type="eql")
            """
            # Limit the maximum results
            limit = min(limit, 200)

            # Search for matching rules
            rules = self.rule_loader.search_rules(
                platform=platform,
                log_source=log_source,
                rule_type=rule_type,
                search_term=search_term,
                mitre_tactic=mitre_tactic,
                limit=limit
            )

            # Get statistics for context
            stats = self.rule_loader.get_statistics()

            # Format rules for display
            rule_summaries = []
            for rule in rules:
                rule_summaries.append({
                    "rule_id": rule.rule_id,
                    "name": rule.display_name,
                    "platform": rule.platform,
                    "log_source": rule.log_source,
                    "type": rule.rule_type,
                    "category": rule.category,
                    "mitre_tactics": list(rule.mitre_tactics),
                    "tags": list(rule.tags)[:10]  # Limit tags displayed
                })

            return {
                "total_found": len(rules),
                "showing": len(rule_summaries),
                "rules": rule_summaries,
                "available_platforms": stats["platforms"],
                "available_log_sources": list(stats["by_log_source"].keys())[:20],
                "statistics": {
                    "total_rules_loaded": stats["total_rules"],
                    "by_platform": stats["by_platform"],
                    "by_type": stats["by_type"]
                }
            }

        @mcp.tool()
        def get_rule_details(rule_id: str) -> Dict:
            """
            Get detailed information about a specific detection rule.

            Args:
                rule_id: The unique rule identifier

            Returns:
                Dictionary with complete rule details including query

            Example:
                get_rule_details("windows_powershell_posh_ps_potential_invoke_mimikatz_eql")
            """
            rule = self.rule_loader.get_rule(rule_id)

            if not rule:
                return {
                    "error": f"Rule not found: {rule_id}",
                    "suggestion": "Use list_detection_rules() to find available rules"
                }

            return {
                "rule_id": rule.rule_id,
                "name": rule.display_name,
                "platform": rule.platform,
                "log_source": rule.log_source,
                "category": rule.category,
                "type": rule.rule_type,
                "query": rule.query,
                "mitre_tactics": list(rule.mitre_tactics),
                "tags": list(rule.tags),
                "file_path": rule.file_path
            }

        @mcp.tool()
        def execute_detection_rule(
            rule_id: str,
            index: str,
            timeframe_minutes: Optional[int] = 15,
            size: int = 100
        ) -> Dict:
            """
            Execute a specific detection rule against Elasticsearch.

            This tool runs a detection rule and returns matching events.

            Args:
                rule_id: The unique rule identifier (from list_detection_rules)
                index: Index pattern to search (e.g., "winlogbeat-*", "auditbeat-*")
                timeframe_minutes: Time window in minutes (default: 15, use 0 for no time filter)
                size: Maximum number of results to return (default: 100, max: 1000)

            Returns:
                Dictionary containing:
                - rule_info: Rule metadata
                - total_hits: Number of matching events
                - events: List of matching events
                - execution_time_ms: Query execution time

            Example:
                execute_detection_rule(
                    rule_id="windows_powershell_posh_ps_potential_invoke_mimikatz_eql",
                    index="winlogbeat-*",
                    timeframe_minutes=60
                )
            """
            # Get the rule
            rule = self.rule_loader.get_rule(rule_id)

            if not rule:
                return {
                    "error": f"Rule not found: {rule_id}",
                    "suggestion": "Use list_detection_rules() to find available rules"
                }

            # Execute based on rule type
            try:
                if rule.rule_type == "lucene":
                    # Execute as Lucene query
                    result = self.search_client.search_with_lucene(
                        index=index,
                        lucene_query=rule.query,
                        timeframe_minutes=timeframe_minutes if timeframe_minutes > 0 else None,
                        size=min(size, 1000)
                    )
                elif rule.rule_type == "eql":
                    # Execute as EQL query
                    result = self.search_client.eql_search(
                        index=index,
                        query=rule.query,
                        start_time=f"now-{timeframe_minutes}m" if timeframe_minutes > 0 else None,
                        size=min(size, 1000)
                    )
                else:
                    return {"error": f"Unsupported rule type: {rule.rule_type}"}

                # Add rule metadata to result
                result["rule_info"] = {
                    "rule_id": rule.rule_id,
                    "name": rule.display_name,
                    "platform": rule.platform,
                    "log_source": rule.log_source,
                    "type": rule.rule_type,
                    "mitre_tactics": list(rule.mitre_tactics)
                }

                return result

            except Exception as e:
                error_msg = str(e)
                # Provide more specific error messages based on error type
                if "timeout" in error_msg.lower() or "timed out" in error_msg.lower():
                    return {
                        "error": f"Query timed out: The rule query may be too complex or the index too large",
                        "rule_id": rule_id,
                        "rule_type": rule.rule_type,
                        "query_preview": rule.query[:200] + "..." if len(rule.query) > 200 else rule.query,
                        "suggestions": [
                            "Try using a smaller timeframe (e.g., timeframe_minutes=5)",
                            "Use a more specific index pattern",
                            "Try search_with_lucene() with a simplified version of the query",
                            "Increase REQUEST_TIMEOUT environment variable"
                        ]
                    }
                elif "parse" in error_msg.lower() or "syntax" in error_msg.lower():
                    return {
                        "error": f"Query parsing error: {error_msg}",
                        "rule_id": rule_id,
                        "rule_type": rule.rule_type,
                        "query": rule.query,
                        "suggestion": "The rule query may have syntax errors or use unsupported features"
                    }
                else:
                    return {
                        "error": f"Failed to execute rule: {error_msg}",
                        "rule_id": rule_id,
                        "rule_type": rule.rule_type,
                        "query_preview": rule.query[:200] + "..." if len(rule.query) > 200 else rule.query
                    }

        @mcp.tool()
        def execute_multiple_rules(
            rule_ids: List[str],
            index: str,
            timeframe_minutes: Optional[int] = 15,
            max_results_per_rule: int = 50
        ) -> Dict:
            """
            Execute multiple detection rules in batch.

            This tool runs multiple rules and aggregates the results,
            useful for comprehensive threat hunting campaigns.

            Args:
                rule_ids: List of rule IDs to execute
                index: Index pattern to search
                timeframe_minutes: Time window in minutes (default: 15)
                max_results_per_rule: Maximum results per rule (default: 50, max: 200)

            Returns:
                Dictionary with results for each rule and summary statistics

            Example:
                execute_multiple_rules(
                    rule_ids=[
                        "windows_powershell_posh_ps_potential_invoke_mimikatz_eql",
                        "windows_process_creation_proc_creation_win_reg_screensaver_lucene"
                    ],
                    index="winlogbeat-*",
                    timeframe_minutes=60
                )
            """
            if len(rule_ids) > 50:
                return {
                    "error": "Too many rules requested",
                    "limit": 50,
                    "requested": len(rule_ids)
                }

            results = {
                "total_rules_executed": 0,
                "total_hits": 0,
                "rules_with_findings": 0,
                "failed_rules": 0,
                "results_by_rule": {}
            }

            for rule_id in rule_ids:
                # Execute each rule via internal method (not MCP wrapper)
                rule_result = self._execute_single_rule(
                    rule_id=rule_id,
                    index=index,
                    timeframe_minutes=timeframe_minutes,
                    size=max_results_per_rule,
                )

                results["total_rules_executed"] += 1

                if "error" in rule_result:
                    results["failed_rules"] += 1
                    results["results_by_rule"][rule_id] = {
                        "error": rule_result["error"],
                        "hits": 0
                    }
                else:
                    hit_count = rule_result.get("total_hits", 0)
                    results["total_hits"] += hit_count

                    if hit_count > 0:
                        results["rules_with_findings"] += 1

                    results["results_by_rule"][rule_id] = {
                        "rule_name": rule_result.get("rule_info", {}).get("name", rule_id),
                        "hits": hit_count,
                        "events": rule_result.get("events", [])[:max_results_per_rule],
                        "mitre_tactics": rule_result.get("rule_info", {}).get("mitre_tactics", [])
                    }

            return results

        @mcp.tool()
        def search_rules_by_mitre_attack(
            tactic: str,
            platform: Optional[str] = None,
            limit: int = 50
        ) -> Dict:
            """
            Search detection rules by MITRE ATT&CK tactic.

            This tool helps find rules mapped to specific attack techniques.

            Args:
                tactic: MITRE ATT&CK tactic (e.g., "credential_access", "lateral_movement")
                    Valid tactics:
                    - execution
                    - persistence
                    - privilege_escalation
                    - defense_evasion
                    - credential_access
                    - discovery
                    - lateral_movement
                    - collection
                    - command_and_control
                    - exfiltration
                    - impact
                platform: Optional platform filter (windows, linux, macos)
                limit: Maximum number of results (default: 50)

            Returns:
                Dictionary with rules matching the MITRE tactic

            Example:
                search_rules_by_mitre_attack(
                    tactic="credential_access",
                    platform="windows"
                )
            """
            # Get rules by MITRE tactic
            rules = self.rule_loader.get_rules_by_mitre_tactic(tactic)

            # Apply platform filter if specified
            if platform:
                rules = [r for r in rules if r.platform.lower() == platform.lower()]

            # Limit results
            rules = rules[:limit]

            # Format results
            rule_summaries = []
            for rule in rules:
                rule_summaries.append({
                    "rule_id": rule.rule_id,
                    "name": rule.display_name,
                    "platform": rule.platform,
                    "log_source": rule.log_source,
                    "type": rule.rule_type,
                    "mitre_tactics": list(rule.mitre_tactics)
                })

            return {
                "tactic": tactic,
                "platform_filter": platform,
                "total_found": len(rule_summaries),
                "rules": rule_summaries
            }

        @mcp.tool()
        def get_rule_statistics() -> Dict:
            """
            Get comprehensive statistics about the detection rule library.

            Returns:
                Dictionary with statistics about loaded rules

            Example:
                get_rule_statistics()
            """
            return self.rule_loader.get_statistics()

        @mcp.tool()
        def hunt_with_rule_category(
            platform: str,
            category: str,
            index: str,
            timeframe_minutes: int = 15,
            max_rules: int = 10
        ) -> Dict:
            """
            Execute all rules in a specific category for comprehensive hunting.

            This tool runs all rules matching a category/log source for
            thorough threat detection.

            Args:
                platform: Target platform (windows, linux, macos)
                category: Rule category or log source
                    (e.g., "powershell", "process_creation", "audit")
                index: Index pattern to search
                timeframe_minutes: Time window in minutes (default: 15)
                max_rules: Maximum number of rules to execute (default: 10, max: 25)

            Returns:
                Aggregated results from all matching rules

            Example:
                hunt_with_rule_category(
                    platform="windows",
                    category="powershell",
                    index="winlogbeat-*",
                    timeframe_minutes=60
                )
            """
            # Find matching rules
            rules = self.rule_loader.search_rules(
                platform=platform,
                log_source=category,
                limit=min(max_rules, 25)
            )

            if not rules:
                return {
                    "error": f"No rules found for platform={platform}, category={category}",
                    "suggestion": "Use get_rule_statistics() to see available platforms and categories"
                }

            # Execute all rules
            rule_ids = [rule.rule_id for rule in rules]

            # Call internal method directly (not MCP wrapper)
            all_results = {"total_rules_executed": 0, "total_detections": 0, "results_by_rule": {}}
            for rid in rule_ids:
                r = self._execute_single_rule(rule_id=rid, index=index, timeframe_minutes=timeframe_minutes, size=20)
                all_results["total_rules_executed"] += 1
                if "error" not in r:
                    hits = r.get("response", {}).get("total_hits", 0)
                    if hits > 0:
                        all_results["total_detections"] += hits
                        all_results["results_by_rule"][rid] = r
            return all_results

        @mcp.tool()
        def validate_rule_for_data(
            rule_id: str,
            index: str,
            sample_size: int = 10
        ) -> Dict:
            """
            Validate if a detection rule is applicable to your data.

            This tool analyzes your data to check if it contains the log sources
            and fields that the rule expects. Use this before executing rules
            to understand if they will work with your data.

            Args:
                rule_id: The unique rule identifier
                index: Index pattern to analyze (e.g., "winlogbeat-*")
                sample_size: Number of sample events to analyze (default: 10)

            Returns:
                Dictionary containing:
                - rule_info: Basic rule information
                - compatibility: Whether rule is likely compatible
                - data_analysis: Analysis of your data structure
                - recommendations: Suggestions if not compatible

            Example:
                validate_rule_for_data(
                    rule_id="windows_builtin_win_security_petitpotam_network_share_lucene",
                    index="winlogbeat-*"
                )
            """
            # Get the rule
            rule = self.rule_loader.get_rule(rule_id)

            if not rule:
                return {
                    "error": f"Rule not found: {rule_id}",
                    "suggestion": "Use list_detection_rules() to find available rules"
                }

            # Analyze the rule query to extract expected fields/values
            query = rule.query
            expected_log_sources = []
            expected_event_codes = []
            expected_channels = []

            # Parse common patterns from Lucene queries
            if "winlog.channel:" in query.lower():
                import re
                channels = re.findall(r'winlog\.channel[:\s]+([^\s\)]+)', query, re.IGNORECASE)
                expected_channels.extend(channels)

            if "event.code:" in query.lower():
                import re
                codes = re.findall(r'event\.code[:\s]+(\d+)', query, re.IGNORECASE)
                expected_event_codes.extend(codes)

            if "EventLog:" in query:
                import re
                logs = re.findall(r'EventLog[:\s]+([^\s\)]+)', query, re.IGNORECASE)
                expected_log_sources.extend(logs)

            # Sample data from the index to check compatibility
            try:
                sample_result = self.search_client.search_with_lucene(
                    index=index,
                    lucene_query="*",
                    size=sample_size
                )

                data_channels = set()
                data_event_codes = set()
                data_providers = set()

                events = sample_result.get("response", {}).get("events", [])
                if not events:
                    events = sample_result.get("events", [])

                for event in events:
                    source = event.get("_source", {})

                    # Extract winlog channel
                    winlog = source.get("winlog", {})
                    if winlog.get("channel"):
                        data_channels.add(winlog["channel"])

                    # Extract event code
                    event_data = source.get("event", {})
                    if event_data.get("code"):
                        data_event_codes.add(str(event_data["code"]))

                    # Extract provider
                    if event_data.get("provider"):
                        data_providers.add(event_data["provider"])

                # Determine compatibility
                compatibility_issues = []

                if expected_channels:
                    matching_channels = set(expected_channels) & data_channels
                    if not matching_channels:
                        compatibility_issues.append({
                            "issue": "Channel mismatch",
                            "rule_expects": expected_channels,
                            "data_has": list(data_channels)
                        })

                if expected_event_codes:
                    matching_codes = set(expected_event_codes) & data_event_codes
                    if not matching_codes:
                        compatibility_issues.append({
                            "issue": "Event code mismatch",
                            "rule_expects": expected_event_codes,
                            "data_has": list(data_event_codes)
                        })

                if expected_log_sources:
                    # Check if any expected log source is in data providers
                    if not any(ls.lower() in str(data_providers).lower() for ls in expected_log_sources):
                        compatibility_issues.append({
                            "issue": "Log source mismatch",
                            "rule_expects": expected_log_sources,
                            "data_providers": list(data_providers)
                        })

                is_compatible = len(compatibility_issues) == 0

                return {
                    "rule_info": {
                        "rule_id": rule.rule_id,
                        "name": rule.display_name,
                        "platform": rule.platform,
                        "log_source": rule.log_source,
                        "type": rule.rule_type
                    },
                    "compatibility": {
                        "likely_compatible": is_compatible,
                        "issues": compatibility_issues if compatibility_issues else None
                    },
                    "data_analysis": {
                        "sample_size": len(events),
                        "channels_found": list(data_channels),
                        "event_codes_found": list(data_event_codes),
                        "providers_found": list(data_providers)
                    },
                    "rule_requirements": {
                        "expected_channels": expected_channels if expected_channels else None,
                        "expected_event_codes": expected_event_codes if expected_event_codes else None,
                        "expected_log_sources": expected_log_sources if expected_log_sources else None
                    },
                    "recommendations": [
                        "Ensure your data contains the required event types",
                        "Check if the log source matches your ingestion pipeline",
                        f"For this rule, you may need: {rule.log_source} logs"
                    ] if not is_compatible else ["Rule appears compatible with your data"]
                }

            except Exception as e:
                return {
                    "error": f"Failed to analyze data: {str(e)}",
                    "rule_info": {
                        "rule_id": rule.rule_id,
                        "name": rule.display_name,
                        "log_source": rule.log_source
                    }
                }

        @mcp.tool()
        def suggest_rules_for_data(
            index: str,
            sample_size: int = 100
        ) -> Dict:
            """
            Analyze your data and suggest applicable detection rules.

            This tool samples your data to identify what log sources and event
            types are present, then recommends detection rules that are likely
            to work with your data.

            Args:
                index: Index pattern to analyze (e.g., "winlogbeat-*")
                sample_size: Number of events to sample (default: 100)

            Returns:
                Dictionary containing:
                - data_profile: Summary of your data characteristics
                - suggested_rules: Rules likely to work with your data
                - coverage: MITRE ATT&CK tactics covered by suggested rules

            Example:
                suggest_rules_for_data(index="winlogbeat-*")
            """
            try:
                # Sample data to understand its structure
                sample_result = self.search_client.search_with_lucene(
                    index=index,
                    lucene_query="*",
                    size=sample_size
                )

                events = sample_result.get("response", {}).get("events", [])
                if not events:
                    events = sample_result.get("events", [])

                if not events:
                    return {
                        "error": "No data found in the specified index",
                        "suggestion": "Check if the index pattern is correct"
                    }

                # Analyze data characteristics
                channels = {}
                event_codes = {}
                providers = {}
                platforms = set()

                for event in events:
                    source = event.get("_source", {})

                    # Count channels
                    winlog = source.get("winlog", {})
                    channel = winlog.get("channel", "unknown")
                    channels[channel] = channels.get(channel, 0) + 1

                    # Count event codes
                    event_data = source.get("event", {})
                    code = str(event_data.get("code", "unknown"))
                    event_codes[code] = event_codes.get(code, 0) + 1

                    # Count providers
                    provider = event_data.get("provider", "unknown")
                    providers[provider] = providers.get(provider, 0) + 1

                    # Detect platform
                    host = source.get("host", {})
                    os_info = host.get("os", {})
                    if os_info.get("platform"):
                        platforms.add(os_info["platform"])

                # Determine primary platform
                platform = "windows" if "windows" in platforms else list(platforms)[0] if platforms else "unknown"

                # Map channels/providers to rule log sources
                log_source_mapping = {
                    "Security": "builtin",
                    "Microsoft-Windows-PowerShell/Operational": "powershell",
                    "Microsoft-Windows-Sysmon/Operational": "sysmon",
                    "System": "builtin",
                    "Application": "builtin",
                    "Microsoft-Windows-RPC": "rpc_firewall"
                }

                suggested_log_sources = set()
                for channel in channels.keys():
                    if channel in log_source_mapping:
                        suggested_log_sources.add(log_source_mapping[channel])
                for provider in providers.keys():
                    if provider in log_source_mapping:
                        suggested_log_sources.add(log_source_mapping[provider])

                # Get rules for suggested log sources
                suggested_rules = []
                for log_source in suggested_log_sources:
                    rules = self.rule_loader.search_rules(
                        platform=platform,
                        log_source=log_source,
                        limit=5
                    )
                    for rule in rules:
                        suggested_rules.append({
                            "rule_id": rule.rule_id,
                            "name": rule.display_name,
                            "log_source": rule.log_source,
                            "mitre_tactics": list(rule.mitre_tactics)
                        })

                # Get MITRE coverage
                mitre_coverage = set()
                for rule in suggested_rules:
                    mitre_coverage.update(rule.get("mitre_tactics", []))

                return {
                    "data_profile": {
                        "total_sampled": len(events),
                        "platform": platform,
                        "channels": dict(sorted(channels.items(), key=lambda x: -x[1])[:10]),
                        "event_codes": dict(sorted(event_codes.items(), key=lambda x: -x[1])[:10]),
                        "providers": dict(sorted(providers.items(), key=lambda x: -x[1])[:10])
                    },
                    "suggested_log_sources": list(suggested_log_sources),
                    "suggested_rules": suggested_rules[:20],
                    "mitre_coverage": list(mitre_coverage),
                    "total_applicable_rules": len(suggested_rules),
                    "tips": [
                        f"Your data appears to be from {platform} systems",
                        f"Found {len(channels)} different log channels",
                        f"Suggested rules cover {len(mitre_coverage)} MITRE ATT&CK tactics"
                    ]
                }

            except Exception as e:
                return {
                    "error": f"Failed to analyze data: {str(e)}",
                    "suggestion": "Check if the index exists and contains data"
                }
