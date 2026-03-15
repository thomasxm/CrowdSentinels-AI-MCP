"""Threat Hunting Tools for incident response and threat detection."""

from fastmcp import FastMCP

from src.storage.auto_capture import auto_capture_elasticsearch_results


class ThreatHuntingTools:
    def __init__(self, search_client):
        self.search_client = search_client

    def register_tools(self, mcp: FastMCP):
        @mcp.tool()
        def hunt_by_timeframe(index: str, attack_types: list[str],
                             start_time: str, end_time: str | None = None,
                             host: str | None = None) -> dict:
            """
            Hunt for specific attack patterns within a timeframe.
            This tool automatically searches for common attack indicators based on
            predefined patterns.

            IoCs are automatically captured to the active investigation if one exists.

            Args:
                index: Index pattern to search (e.g., "winlogbeat-*")
                attack_types: List of attack types to hunt for. Options:
                    - "brute_force": Brute force authentication attempts
                    - "privilege_escalation": Privilege escalation attempts
                    - "lateral_movement": Lateral movement indicators
                    - "persistence": Persistence mechanisms
                    - "suspicious_process": Suspicious process execution
                    - "encoded_commands": Encoded PowerShell commands
                    - "credential_access": Credential dumping attempts
                    - "port_scan": Port scanning activity
                start_time: Start time (e.g., "now-15m", "2024-01-01T00:00:00")
                end_time: End time (optional, defaults to "now")
                host: Specific host to investigate (optional)

            Returns:
                Dictionary with findings for each attack type

            Example:
                hunt_by_timeframe(
                    index="winlogbeat-*",
                    attack_types=["brute_force", "suspicious_process"],
                    start_time="now-15m",
                    host="agent-001"
                )
            """
            result = self.search_client.hunt_by_timeframe(
                index=index,
                attack_types=attack_types,
                start_time=start_time,
                end_time=end_time,
                host=host
            )

            # Auto-capture IoCs to active investigation
            return auto_capture_elasticsearch_results(
                results=result,
                tool_name="hunt_by_timeframe",
                query_description=f"Hunt for {', '.join(attack_types)} in {index}",
            )

        @mcp.tool()
        def analyze_failed_logins(index: str, timeframe_minutes: int = 15,
                                  threshold: int = 5) -> dict:
            """
            Analyze failed login attempts to detect potential brute force attacks.
            This tool aggregates failed login events (Event ID 4625) and identifies
            suspicious patterns.

            IoCs are automatically captured to the active investigation if one exists.

            Args:
                index: Index pattern (e.g., "winlogbeat-*")
                timeframe_minutes: Time window to analyze (default: 15 minutes)
                threshold: Minimum failed attempts to report (default: 5)

            Returns:
                Analysis results with suspicious accounts and hosts

            Use case:
                Detect brute force attacks by finding accounts with multiple
                failed login attempts from various source IPs.
            """
            result = self.search_client.analyze_failed_logins(
                index=index,
                timeframe_minutes=timeframe_minutes,
                threshold=threshold
            )

            # Auto-capture IoCs to active investigation
            return auto_capture_elasticsearch_results(
                results=result,
                tool_name="analyze_failed_logins",
                query_description=f"Analyze failed logins in {index} (last {timeframe_minutes}m)",
            )

        @mcp.tool()
        def analyze_process_creation(index: str, timeframe_minutes: int = 60,
                                    process_filter: list[str] | None = None) -> dict:
            """
            Analyze process creation events (Event ID 4688) for suspicious activity.
            This is crucial for detecting malicious process execution and LOLBins usage.

            Args:
                index: Index pattern (e.g., "winlogbeat-*")
                timeframe_minutes: Time window to analyze (default: 60 minutes)
                process_filter: List of process names to filter (optional)
                    Examples: ["powershell.exe", "cmd.exe", "mshta.exe"]

            Returns:
                Process creation analysis with command lines and parent processes

            Use case:
                Detect suspicious processes like encoded PowerShell, LOLBins
                (Living Off the Land Binaries), or unusual process hierarchies.
            """
            result = self.search_client.analyze_process_creation(
                index=index,
                timeframe_minutes=timeframe_minutes,
                process_filter=process_filter
            )

            # Auto-capture IoCs to active investigation
            return auto_capture_elasticsearch_results(
                results=result,
                tool_name="analyze_process_creation",
                query_description=f"Analyze process creation in {index} (last {timeframe_minutes}m)",
            )

        @mcp.tool()
        def hunt_for_ioc(index: str, ioc: str, ioc_type: str,
                        timeframe_minutes: int | None = None) -> dict:
            """
            Hunt for a specific Indicator of Compromise (IoC) across logs.
            This tool searches multiple fields based on the IoC type.

            Args:
                index: Index pattern to search
                ioc: The IoC value (IP, domain, hash, filename, etc.)
                ioc_type: Type of IoC. Options:
                    - "ip": IP addresses (searches source.ip, destination.ip, etc.)
                    - "domain": Domain names (searches dns.question.name, url.domain, etc.)
                    - "hash": File hashes (MD5, SHA1, SHA256)
                    - "filename": File names or paths
                    - "process": Process names
                    - "user": User names
                timeframe_minutes: Optional time window (searches all time if not specified)

            Returns:
                IoC hunting results with matching events

            Example:
                hunt_for_ioc(
                    index="winlogbeat-*",
                    ioc="malicious.exe",
                    ioc_type="filename",
                    timeframe_minutes=1440  # Last 24 hours
                )

            Based on Pyramid of Pain:
                - Hash values (hard to change for attackers)
                - IP addresses (easy to change)
                - Domain names (medium difficulty)
                - Network/host artifacts (medium-hard)
            """
            result = self.search_client.hunt_for_ioc(
                index=index,
                ioc=ioc,
                ioc_type=ioc_type,
                timeframe_minutes=timeframe_minutes
            )

            # Auto-capture IoCs to active investigation
            return auto_capture_elasticsearch_results(
                results=result,
                tool_name="hunt_for_ioc",
                query_description=f"Hunt for {ioc_type} IoC: {ioc}",
            )

        @mcp.tool()
        def get_host_activity_timeline(index: str, hostname: str,
                                       start_time: str, end_time: str | None = None) -> dict:
            """
            Get a complete timeline of all activity for a specific host.
            This is essential for forensic analysis and incident investigation.

            Args:
                index: Index pattern (e.g., "winlogbeat-*")
                hostname: Hostname to investigate
                start_time: Start time (e.g., "now-1h", "2024-01-01T00:00:00")
                end_time: End time (optional, defaults to "now")

            Returns:
                Timeline of events sorted chronologically with event details

            Use case:
                Perform forensic timeline analysis to understand the full scope
                of a compromise on a specific host. Shows logons, process creation,
                network connections, and other security events.
            """
            result = self.search_client.get_host_activity_timeline(
                index=index,
                hostname=hostname,
                start_time=start_time,
                end_time=end_time
            )

            # Auto-capture IoCs to active investigation (with timeline extraction)
            return auto_capture_elasticsearch_results(
                results=result,
                tool_name="get_host_activity_timeline",
                query_description=f"Host activity timeline for {hostname}",
                extract_timeline=True,
            )

        @mcp.tool()
        def search_with_lucene(index: str, lucene_query: str,
                              timeframe_minutes: int | None = None,
                              size: int = 100) -> dict:
            """
            Execute a Lucene query string search for flexible threat hunting.
            Use this for custom queries that don't fit predefined patterns.

            Args:
                index: Index pattern to search
                lucene_query: Lucene query string syntax
                timeframe_minutes: Optional time window
                size: Number of results (default: 100)

            Returns:
                Search results matching the Lucene query

            Lucene Query Examples:
                1. Search for specific event:
                   'event.code:4688 AND winlog.event_data.CommandLine:*powershell*'

                2. Boolean operators:
                   'event.code:(4624 OR 4625) AND user.name:admin'

                3. Wildcards and ranges:
                   'process.name:*.exe AND @timestamp:[now-1h TO now]'

                4. Field existence:
                   '_exists_:winlog.event_data.CommandLine'

            Use case:
                Execute custom hunting queries based on specific hypotheses
                or follow-up investigations.
            """
            result = self.search_client.search_with_lucene(
                index=index,
                lucene_query=lucene_query,
                timeframe_minutes=timeframe_minutes,
                size=size
            )

            # Auto-capture IoCs to active investigation
            return auto_capture_elasticsearch_results(
                results=result,
                tool_name="search_with_lucene",
                query_description=f"Lucene search: {lucene_query[:100]}",
            )

        @mcp.tool()
        def hunt_by_kill_chain_stage(index: str, stage: str,
                                     timeframe_minutes: int = 60,
                                     host: str | None = None,
                                     size: int = 100) -> dict:
            """
            Hunt for indicators of a specific Cyber Kill Chain stage.

            This tool executes targeted hunting queries designed to find evidence
            of activity at a specific stage of the Lockheed Martin Cyber Kill Chain.
            Each stage has multiple specialized queries that look for stage-specific indicators.

            **The 7 Cyber Kill Chain Stages:**
            1. RECONNAISSANCE - Port scans, DNS enumeration, web scanning
            2. WEAPONIZATION - (Typically not visible in victim logs)
            3. DELIVERY - Phishing emails, malicious downloads, exploit delivery
            4. EXPLOITATION - Exploit execution, vulnerability exploitation
            5. INSTALLATION - Malware installation, persistence creation
            6. COMMAND_AND_CONTROL - C2 beaconing, tunneling, callbacks
            7. ACTIONS_ON_OBJECTIVES - Data exfiltration, lateral movement, ransomware

            Args:
                index: Index pattern to search (e.g., "winlogbeat-*", "auditbeat-*")
                stage: Kill chain stage name (case-insensitive)
                    Options: "RECONNAISSANCE", "DELIVERY", "EXPLOITATION",
                            "INSTALLATION", "COMMAND_AND_CONTROL", "ACTIONS_ON_OBJECTIVES"
                timeframe_minutes: Time window to hunt in (default: 60)
                host: Optional specific hostname to investigate
                size: Max results per query (default: 100)

            Returns:
                Comprehensive hunting results including:
                - Stage information
                - Results from all stage-specific queries
                - Total hits found
                - Indicators discovered
                - Recommended next steps

            Example workflows:

                1. Hunt for Installation stage (persistence):
                   hunt_by_kill_chain_stage(
                       index="winlogbeat-*",
                       stage="INSTALLATION",
                       timeframe_minutes=240
                   )
                   # Finds: Services created, scheduled tasks, registry Run keys, etc.

                2. Hunt for C2 activity:
                   hunt_by_kill_chain_stage(
                       index="packetbeat-*",
                       stage="COMMAND_AND_CONTROL",
                       timeframe_minutes=1440,
                       host="suspicious-workstation"
                   )
                   # Finds: Beaconing, DNS tunneling, unusual connections

                3. Hunt for Actions on Objectives:
                   hunt_by_kill_chain_stage(
                       index="winlogbeat-*",
                       stage="ACTIONS_ON_OBJECTIVES",
                       timeframe_minutes=60
                   )
                   # Finds: Lateral movement, credential dumping, data exfiltration

            Use cases:
                - You detected Installation stage → Hunt for C2 stage (what comes next?)
                - You detected C2 activity → Hunt backwards for Installation (how did they persist?)
                - Comprehensive stage-by-stage threat hunt
                - Validating detection gaps at specific stages
            """
            from src.clients.common.cyber_kill_chain import (
                CyberKillChainClient,
                KillChainStage,
            )

            # Find the matching stage
            stage_upper = stage.upper().replace(' ', '_')
            kill_chain_stage = None

            for kc_stage in KillChainStage:
                if kc_stage.name == stage_upper:
                    kill_chain_stage = kc_stage
                    break

            if not kill_chain_stage:
                return {
                    "error": f"Invalid stage: {stage}",
                    "valid_stages": [s.name for s in KillChainStage],
                    "tip": "Use get_kill_chain_overview() to see all valid stages"
                }

            # Get hunting queries for this stage
            hunting_queries = CyberKillChainClient.get_hunting_queries_for_stage(kill_chain_stage)
            stage_info = CyberKillChainClient.get_stage_info(kill_chain_stage)

            if not hunting_queries:
                return {
                    "stage": stage_info.name,
                    "message": f"No hunting queries available for {stage_info.name} stage",
                    "description": stage_info.description,
                    "indicators": stage_info.indicators
                }

            # Execute each hunting query for this stage
            results = {
                "kill_chain_stage": {
                    "number": kill_chain_stage.value,
                    "name": stage_info.name,
                    "description": stage_info.description
                },
                "timeframe_minutes": timeframe_minutes,
                "index": index,
                "host_filter": host,
                "hunting_results": {},
                "total_hits": 0,
                "queries_executed": len(hunting_queries)
            }

            for query_name, lucene_query in hunting_queries.items():
                try:
                    # Modify query to add host filter if specified
                    final_query = lucene_query
                    if host:
                        final_query = f"({lucene_query}) AND host.name:{host}"

                    # Execute the query
                    query_result = self.search_client.search_with_lucene(
                        index=index,
                        lucene_query=final_query,
                        timeframe_minutes=timeframe_minutes,
                        size=size
                    )

                    results["hunting_results"][query_name] = {
                        "query": final_query,
                        "total_hits": query_result.get("total_hits", 0),
                        "events": query_result.get("events", [])[:10]  # Limit to 10 events
                    }

                    results["total_hits"] += query_result.get("total_hits", 0)

                except Exception as e:
                    results["hunting_results"][query_name] = {
                        "query": final_query,
                        "error": str(e)
                    }

            # Add recommendations
            if results["total_hits"] > 0:
                results["assessment"] = f"⚠ Found {results['total_hits']} potential indicators of {stage_info.name} stage"
                results["recommendation"] = "Review findings and hunt for adjacent stages using hunt_adjacent_stages()"
            else:
                results["assessment"] = f"✓ No indicators of {stage_info.name} found in this timeframe"
                results["recommendation"] = "Consider expanding timeframe or hunting for other stages"

            # Auto-capture IoCs to active investigation
            return auto_capture_elasticsearch_results(
                results=results,
                tool_name="hunt_by_kill_chain_stage",
                query_description=f"Kill chain hunt: {stage} stage in {index}",
            )

        def _hunt_stage(index: str, stage: str, timeframe_minutes: int = 60,
                        host: str | None = None, size: int = 100) -> dict:
            """Internal helper: execute kill chain stage hunt without MCP wrapper."""
            from src.clients.common.cyber_kill_chain import (
                CyberKillChainClient,
                KillChainStage,
            )
            stage_upper = stage.upper().replace(' ', '_')
            kill_chain_stage = None
            for kc_stage in KillChainStage:
                if kc_stage.name == stage_upper:
                    kill_chain_stage = kc_stage
                    break
            if not kill_chain_stage:
                return {"error": f"Invalid stage: {stage}"}

            hunting_queries = CyberKillChainClient.get_hunting_queries_for_stage(kill_chain_stage)
            stage_info = CyberKillChainClient.get_stage_info(kill_chain_stage)

            if not hunting_queries:
                return {"stage": stage_info.name, "total_hits": 0}

            results = {
                "kill_chain_stage": {"name": stage_info.name},
                "hunting_results": {},
                "total_hits": 0,
            }
            for query_name, lucene_query in hunting_queries.items():
                try:
                    final_query = f"({lucene_query}) AND host.name:{host}" if host else lucene_query
                    qr = self.search_client.search_with_lucene(
                        index=index, lucene_query=final_query,
                        timeframe_minutes=timeframe_minutes, size=size,
                    )
                    hits = qr.get("total_hits", 0)
                    results["hunting_results"][query_name] = {"total_hits": hits}
                    results["total_hits"] += hits
                except Exception as e:
                    results["hunting_results"][query_name] = {"error": str(e)}

            if results["total_hits"] > 0:
                results["assessment"] = f"Found {results['total_hits']} indicators of {stage_info.name}"
            else:
                results["assessment"] = f"No indicators of {stage_info.name} found"
            return results

        @mcp.tool()
        def hunt_adjacent_stages(index: str, current_stage: str,
                                timeframe_minutes: int = 120,
                                hunt_previous: bool = True,
                                hunt_next: bool = True,
                                host: str | None = None) -> dict:
            """
            Hunt for IoCs in stages adjacent to the current attack stage.

            When you identify activity at one stage of the kill chain, this tool
            automatically hunts for evidence of the previous stage (to understand
            how they got there) and the next stage (to predict their next move).

            **Kill Chain Progression:**
            Reconnaissance → Weaponization → Delivery → Exploitation →
            Installation → Command & Control → Actions on Objectives

            Args:
                index: Index pattern to search
                current_stage: The stage you've currently identified
                    Options: "RECONNAISSANCE", "DELIVERY", "EXPLOITATION",
                            "INSTALLATION", "COMMAND_AND_CONTROL", "ACTIONS_ON_OBJECTIVES"
                timeframe_minutes: Time window to hunt (default: 120)
                hunt_previous: Hunt for previous stage (default: True)
                hunt_next: Hunt for next stage (default: True)
                host: Optional specific hostname

            Returns:
                Complete hunting results including:
                - Current stage information
                - Previous stage hunting results (if hunted)
                - Next stage hunting results (if hunted)
                - Attack progression analysis
                - Recommended actions

            Example workflows:

                1. You detected C2 beaconing:
                   hunt_adjacent_stages(
                       index="winlogbeat-*",
                       current_stage="COMMAND_AND_CONTROL",
                       timeframe_minutes=240
                   )
                   # Hunts backwards for: Installation (persistence)
                   # Hunts forward for: Actions on Objectives (exfiltration, lateral movement)

                2. You detected malware installation:
                   hunt_adjacent_stages(
                       index="winlogbeat-*",
                       current_stage="INSTALLATION",
                       hunt_previous=True,  # Find how it got delivered
                       hunt_next=True,      # Find if C2 was established
                       timeframe_minutes=360
                   )

                3. Focus only on preventing next stage:
                   hunt_adjacent_stages(
                       index="winlogbeat-*",
                       current_stage="EXPLOITATION",
                       hunt_previous=False,  # Don't care how they got in
                       hunt_next=True,       # Stop them from installing
                       timeframe_minutes=60,
                       host="compromised-host"
                   )

            Use cases:
                - Complete incident timeline reconstruction
                - Predictive threat hunting (stop next stage before it happens)
                - Root cause analysis (trace back to initial access)
                - Comprehensive compromise assessment
            """
            from src.clients.common.cyber_kill_chain import (
                CyberKillChainClient,
                KillChainStage,
            )

            # Find the matching stage
            stage_upper = current_stage.upper().replace(' ', '_')
            kill_chain_stage = None

            for kc_stage in KillChainStage:
                if kc_stage.name == stage_upper:
                    kill_chain_stage = kc_stage
                    break

            if not kill_chain_stage:
                return {
                    "error": f"Invalid stage: {current_stage}",
                    "valid_stages": [s.name for s in KillChainStage]
                }

            # Get adjacent stages
            adjacent = CyberKillChainClient.get_adjacent_stages(kill_chain_stage)
            current_info = CyberKillChainClient.get_stage_info(kill_chain_stage)

            results = {
                "current_stage": {
                    "number": kill_chain_stage.value,
                    "name": current_info.name,
                    "description": current_info.description
                },
                "timeframe_minutes": timeframe_minutes,
                "index": index,
                "host_filter": host,
                "previous_stage_hunt": None,
                "next_stage_hunt": None,
                "attack_progression_analysis": {}
            }

            # Hunt for previous stage (how did they get to current stage?)
            # Use _hunt_stage helper to avoid calling the MCP-decorated wrapper
            if hunt_previous and adjacent['previous']:
                prev_stage_name = adjacent['previous'].name
                print(f"Hunting for previous stage: {prev_stage_name}")

                prev_hunt = _hunt_stage(
                    index=index,
                    stage=prev_stage_name,
                    timeframe_minutes=timeframe_minutes,
                    host=host,
                )

                results["previous_stage_hunt"] = {
                    "stage": prev_hunt.get("kill_chain_stage"),
                    "total_hits": prev_hunt.get("total_hits", 0),
                    "assessment": prev_hunt.get("assessment"),
                    "hunting_results": prev_hunt.get("hunting_results", {})
                }

            # Hunt for next stage (what are they doing next?)
            # Use _hunt_stage helper to avoid calling the MCP-decorated wrapper
            if hunt_next and adjacent['next']:
                next_stage_name = adjacent['next'].name
                print(f"Hunting for next stage: {next_stage_name}")

                next_hunt = _hunt_stage(
                    index=index,
                    stage=next_stage_name,
                    timeframe_minutes=timeframe_minutes,
                    host=host,
                )

                results["next_stage_hunt"] = {
                    "stage": next_hunt.get("kill_chain_stage"),
                    "total_hits": next_hunt.get("total_hits", 0),
                    "assessment": next_hunt.get("assessment"),
                    "hunting_results": next_hunt.get("hunting_results", {})
                }

            # Analyze attack progression
            stages_with_activity = []

            if results.get("previous_stage_hunt") and results["previous_stage_hunt"]["total_hits"] > 0:
                stages_with_activity.append(results["previous_stage_hunt"]["stage"]["name"])

            stages_with_activity.append(current_info.name)  # Current stage assumed to have activity

            if results.get("next_stage_hunt") and results["next_stage_hunt"]["total_hits"] > 0:
                stages_with_activity.append(results["next_stage_hunt"]["stage"]["name"])

            results["attack_progression_analysis"] = {
                "stages_with_activity": stages_with_activity,
                "progression_complete": len(stages_with_activity) >= 2,
                "attack_maturity": f"{len(stages_with_activity)}/3 adjacent stages show activity"
            }

            # Provide recommendations
            recommendations = []

            if results.get("previous_stage_hunt"):
                if results["previous_stage_hunt"]["total_hits"] > 0:
                    recommendations.append(f"✓ Previous stage ({results['previous_stage_hunt']['stage']['name']}) shows activity - initial access vector identified")
                else:
                    recommendations.append(f"⚠ No evidence of {results['previous_stage_hunt']['stage']['name']} - hunt further back or expand timeframe")

            if results.get("next_stage_hunt"):
                if results["next_stage_hunt"]["total_hits"] > 0:
                    recommendations.append(f"🚨 CRITICAL: Next stage ({results['next_stage_hunt']['stage']['name']}) shows activity - attack has progressed!")
                    recommendations.append("Immediate action required to prevent further progression")
                else:
                    recommendations.append(f"✓ No evidence of {results['next_stage_hunt']['stage']['name']} yet - opportunity to prevent progression")
                    recommendations.append("Implement preventive controls before they advance")

            results["recommendations"] = recommendations

            # Auto-capture IoCs to active investigation
            return auto_capture_elasticsearch_results(
                results=results,
                tool_name="hunt_adjacent_stages",
                query_description=f"Hunt adjacent stages to {current_stage} in {index}",
            )
