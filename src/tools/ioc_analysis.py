"""IoC Analysis and Decision-Making Tools for incident response."""
from typing import Dict, List, Optional
from fastmcp import FastMCP


class IoCAnalysisTools:
    def __init__(self, search_client):
        self.search_client = search_client

    def register_tools(self, mcp: FastMCP):
        @mcp.tool()
        def analyze_search_results(search_results: Dict, context: str = "") -> Dict:
            """
            Analyze search results and provide intelligent insights with follow-up recommendations.
            This is a critical tool for incident response - it acts like an experienced analyst
            by extracting IoCs, mapping to MITRE ATT&CK, assessing severity, and recommending
            next steps.

            Args:
                search_results: Results from any search query (from search_documents, hunt_for_ioc, etc.)
                context: Context about what was searched for (e.g., "investigating failed logins on agent-001")

            Returns:
                Comprehensive analysis including:
                - Summary of findings
                - Extracted IoCs (IPs, users, processes, command lines) prioritized by Pyramid of Pain
                - MITRE ATT&CK technique mapping
                - Severity assessment (critical/high/medium/low)
                - Human-readable insights
                - Recommended follow-up queries and investigations

            Use case:
                After running any threat hunting query, use this tool to:
                1. Understand what was found
                2. Identify the most important IoCs to investigate
                3. Get specific recommendations for next steps
                4. Map activity to MITRE ATT&CK framework

            Example workflow:
                1. Run: hunt_for_ioc(index="winlogbeat-*", ioc="malicious.exe", ioc_type="process")
                2. Analyze: analyze_search_results(search_results=<results>, context="hunting for malicious.exe")
                3. Follow recommended queries based on the analysis

            Pyramid of Pain Priority:
                - Hash values (priority 1 - trivial for attackers to change)
                - IP addresses (priority 2 - easy to change)
                - Domain names (priority 3 - simple to change)
                - Network artifacts (priority 4 - annoying to change)
                - Tools (priority 5 - challenging to change)
                - TTPs/Behaviors (priority 6 - tough to change) ← Focus here!
            """
            return self.search_client.analyze_search_results(
                search_results=search_results,
                context=context
            )

        @mcp.tool()
        def generate_investigation_report(analysis_results: List[Dict],
                                          investigation_context: str) -> Dict:
            """
            Generate a comprehensive investigation report from multiple analyses.
            This tool aggregates results from multiple queries and analyses to create
            a complete incident response report.

            Args:
                analysis_results: List of analysis results from analyze_search_results tool
                investigation_context: Overall context of the investigation
                    (e.g., "Suspected ransomware on finance department workstations")

            Returns:
                Comprehensive investigation report including:
                - Report ID and timestamp
                - Executive summary
                - All discovered IoCs aggregated
                - All MITRE ATT&CK techniques identified
                - List of affected hosts and users
                - Overall severity assessment
                - Consolidated recommendations

            Use case:
                At the end of an investigation after running multiple queries:
                1. Run various threat hunting queries
                2. Analyze each with analyze_search_results
                3. Aggregate all analyses with this tool
                4. Present a complete report to stakeholders

            Example workflow:
                # Step 1: Hunt for suspicious activity
                result1 = hunt_by_timeframe(...)
                analysis1 = analyze_search_results(result1, "hunting for brute force")

                # Step 2: Investigate specific IoC
                result2 = hunt_for_ioc(...)
                analysis2 = analyze_search_results(result2, "tracking suspicious user")

                # Step 3: Generate final report
                report = generate_investigation_report(
                    analysis_results=[analysis1, analysis2],
                    investigation_context="Investigating potential data exfiltration incident"
                )
            """
            return self.search_client.generate_investigation_report(
                analysis_results=analysis_results,
                investigation_context=investigation_context
            )

        @mcp.tool()
        def analyze_kill_chain_stage(iocs: List[Dict], include_hunting_suggestions: bool = True) -> Dict:
            """
            Analyze IoCs to identify which Cyber Kill Chain stage(s) an attack is in.

            This tool maps Indicators of Compromise to the Lockheed Martin Cyber Kill Chain,
            helping analysts understand where in the attack lifecycle the adversary currently is,
            and suggesting where to hunt for evidence of previous or next stages.

            **The 7 Cyber Kill Chain Stages:**
            1. Reconnaissance - Adversary gathers information
            2. Weaponization - Adversary creates malicious payload
            3. Delivery - Adversary delivers payload to target
            4. Exploitation - Adversary exploits vulnerability
            5. Installation - Adversary installs malware/persistence
            6. Command & Control - Adversary establishes C2 channel
            7. Actions on Objectives - Adversary achieves their goal

            Args:
                iocs: List of IoC dictionaries with 'type' and 'value' keys
                    Supported types: ip, domain, url, file_hash, file_path, registry_key,
                                   service_name, scheduled_task, user_account, email,
                                   cve, port_scan, dns_query, credential, lateral_movement,
                                   c2_domain, user_agent, ransomware, data_exfil
                include_hunting_suggestions: Include suggestions for hunting adjacent stages

            Returns:
                Comprehensive kill chain analysis including:
                - Identified stages with confidence scores
                - Most likely current stage
                - Matching IoCs for each stage
                - Hunting suggestions for previous/next stages (if enabled)
                - Recommended log sources to check
                - Specific hunting queries to run

            Example IoC formats:
                [
                    {"type": "ip", "value": "203.0.113.42"},
                    {"type": "file_hash", "value": "abc123def456..."},
                    {"type": "registry_key", "value": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
                    {"type": "c2_domain", "value": "malicious-c2.evil"}
                ]

            Use cases:
                1. After detecting suspicious activity: Determine attack stage
                2. During investigation: Understand attack progression
                3. For threat hunting: Find evidence of adjacent stages
                4. For reporting: Map incident to kill chain framework

            Example workflow:
                # Step 1: Extract IoCs from investigation
                iocs = [
                    {"type": "ip", "value": "192.0.2.100"},
                    {"type": "file_hash", "value": "sha256:abc123..."},
                    {"type": "c2_domain", "value": "evil.com"}
                ]

                # Step 2: Analyze kill chain stage
                kill_chain_analysis = analyze_kill_chain_stage(iocs=iocs)

                # Step 3: Follow hunting suggestions
                # If current stage is "C2", hunt for:
                #   - Previous stage (Installation) - how did malware get installed?
                #   - Next stage (Actions on Objectives) - what are they doing?
            """
            from src.clients.common.cyber_kill_chain import CyberKillChainClient

            # Identify stages from IoCs
            stage_analysis = CyberKillChainClient.identify_stage_from_iocs(iocs)

            result = {
                "kill_chain_analysis": stage_analysis,
                "framework": "Lockheed Martin Cyber Kill Chain"
            }

            # Add hunting suggestions if requested and we identified a stage
            if include_hunting_suggestions and stage_analysis.get('most_likely_stage'):
                from src.clients.common.cyber_kill_chain import KillChainStage

                # Get the most likely stage
                stage_name = stage_analysis['most_likely_stage']

                # Find the KillChainStage enum value
                current_stage = None
                for stage in KillChainStage:
                    if stage.name == stage_name:
                        current_stage = stage
                        break

                if current_stage:
                    hunting_suggestions = CyberKillChainClient.suggest_next_hunting_actions(current_stage)
                    result['hunting_suggestions'] = hunting_suggestions

            return result

        @mcp.tool()
        def get_kill_chain_overview() -> Dict:
            """
            Get a complete overview of the Cyber Kill Chain framework.

            This tool provides comprehensive information about all 7 stages of the
            Lockheed Martin Cyber Kill Chain, including what to look for at each stage
            and how many hunting queries are available.

            Returns:
                Complete kill chain overview including:
                - Framework description
                - All 7 stages with descriptions
                - Indicators for each stage
                - Typical IoCs for each stage
                - Log sources to check
                - MITRE ATT&CK tactic mappings
                - Number of hunting queries available per stage

            Use cases:
                - Understanding the kill chain framework
                - Training and reference
                - Planning comprehensive threat hunts
                - Mapping detections to framework stages

            Example:
                # Get overview to understand what to hunt for
                overview = get_kill_chain_overview()

                # Review stage 5 (Installation) to understand persistence mechanisms
                installation_stage = overview['stages']['INSTALLATION']
                print(installation_stage['indicators'])
            """
            from src.clients.common.cyber_kill_chain import CyberKillChainClient

            return CyberKillChainClient.get_full_kill_chain_overview()

        @mcp.tool()
        def map_events_to_kill_chain(events: List[Dict]) -> Dict:
            """
            Map Elasticsearch events to Cyber Kill Chain stages.

            This tool analyzes raw Elasticsearch events and determines which kill chain
            stage(s) they belong to based on event codes, actions, and content.

            Args:
                events: List of Elasticsearch event documents (from any search query)

            Returns:
                Mapping of events to kill chain stages including:
                - Event count per stage
                - List of events for each identified stage
                - Stage distribution summary
                - Timeline of stages (if events have timestamps)

            Use cases:
                - Analyze results from threat hunting queries
                - Map incident timeline to kill chain
                - Understand attack progression over time
                - Identify gaps in visibility (missing stages)

            Example:
                # Step 1: Run threat hunting query
                results = hunt_by_timeframe(
                    index="winlogbeat-*",
                    timeframe_minutes=60,
                    attack_patterns=["all"]
                )

                # Step 2: Map events to kill chain
                kill_chain_mapping = map_events_to_kill_chain(
                    events=results['events']
                )

                # Step 3: Analyze stage progression
                # Shows: Reconnaissance → Delivery → Exploitation → Installation → C2
            """
            from src.clients.common.cyber_kill_chain import CyberKillChainClient

            stage_events = {}
            stage_counts = {}

            for event in events:
                # Get the _source field if this is an Elasticsearch hit
                event_data = event.get('_source', event)

                # Map event to stages
                stages = CyberKillChainClient.map_event_to_stage(event_data)

                for stage in stages:
                    stage_name = stage.name

                    if stage_name not in stage_events:
                        stage_events[stage_name] = []
                        stage_counts[stage_name] = 0

                    stage_events[stage_name].append(event_data)
                    stage_counts[stage_name] += 1

            # Sort stages by stage number
            from src.clients.common.cyber_kill_chain import KillChainStage
            sorted_stages = sorted(
                stage_counts.keys(),
                key=lambda name: KillChainStage[name].value
            )

            return {
                "total_events_analyzed": len(events),
                "stages_identified": len(stage_counts),
                "stage_distribution": {
                    stage: {
                        "event_count": stage_counts[stage],
                        "percentage": round((stage_counts[stage] / len(events)) * 100, 2) if events else 0,
                        "stage_number": KillChainStage[stage].value
                    }
                    for stage in sorted_stages
                },
                "events_by_stage": {
                    stage: stage_events[stage][:10]  # Limit to 10 events per stage
                    for stage in sorted_stages
                },
                "attack_progression": [
                    {
                        "stage_number": KillChainStage[stage].value,
                        "stage_name": stage,
                        "event_count": stage_counts[stage]
                    }
                    for stage in sorted_stages
                ]
            }
