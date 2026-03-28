"""Chainsaw Log Hunting Tools with Pyramid of Pain and Diamond Model integration."""

from fastmcp import FastMCP

from src.storage.auto_capture import auto_capture_chainsaw_results


class ChainsawHuntingTools:
    """
    Tools for hunting with Chainsaw log analyser.

    Default paths (installed by setup.sh):
        - Chainsaw binary: chainsaw/chainsaw
        - Sigma rules: chainsaw/sigma/
        - EVTX samples: chainsaw/EVTX-ATTACK-SAMPLES/
    """

    def __init__(self):
        """Initialise Chainsaw hunting tools."""
        from src.clients.common.chainsaw_client import ChainsawClient

        self.chainsaw = ChainsawClient()

    def register_tools(self, mcp: FastMCP):
        # Store reference to self for use in closures
        tools_instance = self

        @mcp.tool()
        def hunt_with_sigma_rules(
            evtx_path: str,
            sigma_rules_path: str | None = None,
            mapping_path: str | None = None,
            from_time: str | None = None,
            to_time: str | None = None,
            prioritize_by_pyramid: bool = True,
        ) -> dict:
            """
            Hunt for threats in EVTX logs using Sigma rules.

            This tool uses Chainsaw to hunt through Windows Event Logs (EVTX) with Sigma rules,
            automatically prioritising findings by the Pyramid of Pain and suggesting follow-up hunts.

            **Default Paths (installed by setup.sh):**
                - EVTX samples: chainsaw/EVTX-ATTACK-SAMPLES/
                - Sigma rules: chainsaw/sigma/
                - Mappings: chainsaw/mappings/

            Args:
                evtx_path: Path to EVTX files or directory
                    - Use "chainsaw/EVTX-ATTACK-SAMPLES" for bundled samples
                    - Or provide absolute path: /path/to/evtx/files
                sigma_rules_path: Path to Sigma rules directory (default: chainsaw/sigma/)
                mapping_path: Path to mapping YAML file (default: chainsaw/mappings/sigma-event-logs-all.yml)
                from_time: Start timestamp for filtering (ISO format: "2019-03-17T19:09:39")
                to_time: End timestamp for filtering (ISO format)
                prioritize_by_pyramid: Prioritise results by Pyramid of Pain (default: True)

            Returns:
                Hunt results with:
                - Total detections found
                - Detections grouped by Pyramid of Pain level
                - Diamond Model mapping for each detection
                - Suggested follow-up hunts
                - Summary of findings

            Examples:
                # Hunt using bundled EVTX samples (recommended for testing)
                hunt_with_sigma_rules(evtx_path="chainsaw/EVTX-ATTACK-SAMPLES")

                # Hunt with time filtering
                hunt_with_sigma_rules(
                    evtx_path="chainsaw/EVTX-ATTACK-SAMPLES",
                    from_time="2019-03-17T19:09:39",
                    to_time="2019-03-17T19:09:50"
                )

                # Hunt specific Sigma rule category
                hunt_with_sigma_rules(
                    evtx_path="chainsaw/EVTX-ATTACK-SAMPLES",
                    sigma_rules_path="chainsaw/sigma/rules/windows/process_access"
                )

            Workflow:
                1. Executes Sigma rules against EVTX logs
                2. Categorises findings by Pyramid of Pain
                3. Maps findings to Diamond Model
                4. Suggests follow-up hunts for discovered IoCs
            """
            # Execute hunt
            hunt_result = tools_instance.chainsaw.hunt(
                evtx_path=evtx_path,
                sigma_path=sigma_rules_path,
                mapping_path=mapping_path,
                from_time=from_time,
                to_time=to_time,
                output_format="json",
                skip_errors=True,
            )

            if "error" in hunt_result:
                return hunt_result

            detections = hunt_result.get("detections", [])

            if not detections:
                return {"message": "No threats detected", "total_detections": 0, "command": hunt_result.get("command")}

            # Categorize by Pyramid of Pain and Diamond Model
            categorized = tools_instance._categorize_and_analyze_detections(detections, prioritize_by_pyramid)

            # Generate summary and follow-up suggestions
            summary = tools_instance._generate_hunt_summary(categorized, evtx_path)

            result = {
                "total_detections": len(detections),
                "summary": summary,
                "detections_by_pyramid_level": categorized["by_pyramid"],
                "diamond_model_analysis": categorized["diamond_summary"],
                "follow_up_hunts": categorized["follow_ups"],
                "command_executed": hunt_result.get("command"),
                "raw_detections": detections[:10],  # Include first 10 for reference
            }

            # Auto-capture IoCs to active investigation
            return auto_capture_chainsaw_results(
                results=result,
                tool_name="hunt_with_sigma_rules",
                query_description=f"Sigma rule hunt on {evtx_path}",
            )

        @mcp.tool()
        def search_ioc_in_evtx(
            evtx_path: str,
            ioc: str,
            ioc_type: str,
            case_insensitive: bool = True,
            event_id: int | None = None,
            use_regex: bool = False,
        ) -> dict:
            """
            Search for a specific IoC in EVTX logs.

            This tool searches for IPs, domains, process names, hashes, or other indicators
            in Windows Event Logs, following the Pyramid of Pain prioritisation strategy.

            **Default Paths (installed by setup.sh):**
                - EVTX samples: chainsaw/EVTX-ATTACK-SAMPLES/
                - Chainsaw binary: chainsaw/chainsaw

            Args:
                evtx_path: Path to EVTX files or directory
                    - Use "chainsaw/EVTX-ATTACK-SAMPLES" for bundled samples
                    - Or provide absolute path: /path/to/evtx/files
                ioc: The indicator to search for (IP address, domain, process name, hash, etc.)
                ioc_type: Type of IoC
                    Options: "ip", "domain", "url", "process_name", "hash", "user_agent",
                            "registry_key", "file_path", "tool", "ttp"
                case_insensitive: Case-insensitive search (default: True)
                event_id: Filter by specific Windows Event ID (e.g., 21 for Sysmon DNS)
                use_regex: Treat IoC as regex pattern (e.g., "^admi.*")

            Returns:
                Search results with:
                - Total matches found
                - Pyramid of Pain categorization
                - Matches with context
                - Suggested follow-up searches
                - Diamond Model mapping

            Examples:
                # Search for IP address using bundled samples
                search_ioc_in_evtx(
                    evtx_path="chainsaw/EVTX-ATTACK-SAMPLES",
                    ioc="192.168.1.100",
                    ioc_type="ip"
                )

                # Search for mimikatz
                search_ioc_in_evtx(
                    evtx_path="chainsaw/EVTX-ATTACK-SAMPLES",
                    ioc="mimikatz",
                    ioc_type="tool",
                    case_insensitive=True
                )

                # Search in specific event ID
                search_ioc_in_evtx(
                    evtx_path="chainsaw/EVTX-ATTACK-SAMPLES",
                    ioc="evil.com",
                    ioc_type="domain",
                    event_id=21  # Sysmon DNS query
                )

                # Regex search
                search_ioc_in_evtx(
                    evtx_path="chainsaw/EVTX-ATTACK-SAMPLES",
                    ioc="^admi.*",
                    ioc_type="user",
                    use_regex=True
                )

            Pyramid of Pain Priority:
                - Hash (Level 1): Trivial to change
                - IP (Level 2): Easy to change → START HERE
                - Domain (Level 3): Simple to change → THEN THIS
                - Artifacts (Level 4): Annoying to change
                - Tools (Level 5): Challenging to change
                - TTPs (Level 6): Tough to change
            """
            # Categorize IoC by Pyramid of Pain
            pyramid_info = tools_instance.chainsaw.categorize_ioc_by_pyramid(ioc_type, ioc)

            # Execute search
            search_result = tools_instance.chainsaw.search(
                evtx_path=evtx_path,
                search_term=ioc,
                case_insensitive=case_insensitive,
                event_id=event_id,
                regex=use_regex,
                output_format="json",
            )

            if "error" in search_result:
                return search_result

            matches = search_result.get("matches", [])

            # Analyze matches
            analysis = {
                "ioc_searched": ioc,
                "ioc_type": ioc_type,
                "pyramid_of_pain": pyramid_info,
                "total_matches": len(matches),
                "matches": matches[:20],  # Limit to 20 matches
                "summary": tools_instance._generate_search_summary(ioc, ioc_type, matches),
                "follow_up_searches": tools_instance._suggest_follow_up_searches(ioc, ioc_type, matches),
                "diamond_model": tools_instance._extract_diamond_model_from_matches(matches),
                "command_executed": search_result.get("command"),
            }

            # Auto-capture IoCs to active investigation
            return auto_capture_chainsaw_results(
                results=analysis,
                tool_name="search_ioc_in_evtx",
                query_description=f"Search for {ioc_type}: {ioc} in {evtx_path}",
            )

        @mcp.tool()
        def iterative_hunt(
            evtx_path: str,
            initial_ioc: str,
            initial_ioc_type: str,
            max_iterations: int = 3,
            follow_pyramid: bool = True,
        ) -> dict:
            """
            Perform iterative threat hunting starting from an initial IoC.

            This tool performs multi-stage hunting, automatically discovering related IoCs
            and pivoting through the Pyramid of Pain levels for comprehensive investigation.

            **Default Paths (installed by setup.sh):**
                - EVTX samples: chainsaw/EVTX-ATTACK-SAMPLES/
                - Chainsaw binary: chainsaw/chainsaw

            **Hunting Strategy:**
            1. Start with easy-to-track IoCs (IPs, domains, process names)
            2. Each iteration discovers new IoCs from results
            3. Follow up on high-priority indicators
            4. Build complete attack picture using Diamond Model

            Args:
                evtx_path: Path to EVTX files or directory
                    - Use "chainsaw/EVTX-ATTACK-SAMPLES" for bundled samples
                    - Or provide absolute path: /path/to/evtx/files
                initial_ioc: Starting indicator (IP, domain, process name, etc.)
                initial_ioc_type: Type of initial IoC
                max_iterations: Maximum hunting iterations (default: 3)
                follow_pyramid: Follow Pyramid of Pain prioritisation (default: True)

            Returns:
                Complete hunting results with:
                - All iterations with findings
                - IoC discovery timeline
                - Complete Diamond Model analysis
                - Attack reconstruction
                - Final recommendations

            Example workflow:
                # Start with suspicious IP using bundled samples
                iterative_hunt(
                    evtx_path="chainsaw/EVTX-ATTACK-SAMPLES",
                    initial_ioc="203.0.113.42",
                    initial_ioc_type="ip",
                    max_iterations=3
                )

                # Iteration 1: Search for IP
                #   → Finds: Process "powershell.exe" connected to IP
                #   → Finds: User "admin" made connection
                #   → Finds: Hostname "DESKTOP-ABC123"
                #
                # Iteration 2: Search for process "powershell.exe"
                #   → Finds: Encoded commands
                #   → Finds: Persistence via scheduled task
                #   → Finds: Additional IPs contacted
                #
                # Iteration 3: Search for scheduled task indicators
                #   → Finds: Task name "WindowsUpdate" (suspicious)
                #   → Finds: TTPs for persistence
                #   → Builds complete attack timeline

            Diamond Model Integration:
                - Adversary: Identified from TTPs
                - Capability: Tools and techniques discovered
                - Infrastructure: IPs, domains from iterations
                - Victim: Affected hosts and users
            """
            iterations = []
            discovered_iocs = set()
            discovered_iocs.add(f"{initial_ioc_type}:{initial_ioc}")

            current_ioc = initial_ioc
            current_ioc_type = initial_ioc_type

            for iteration in range(max_iterations):
                # Search for current IoC
                # Call chainsaw search directly (not via MCP wrapper)
                search_result = tools_instance.chainsaw.search(
                    evtx_path=evtx_path,
                    search_term=current_ioc,
                    case_insensitive=True,
                    output_format="json",
                )
                if "error" in search_result:
                    result = search_result
                else:
                    matches = search_result.get("matches", [])
                    from src.clients.common.chainsaw_client import (
                        ChainsawClient as _ChainsawClient,
                    )

                    pyramid_info = _ChainsawClient.categorize_ioc_by_pyramid(current_ioc_type, current_ioc)
                    result = {
                        "ioc_searched": current_ioc,
                        "ioc_type": current_ioc_type,
                        "pyramid_of_pain": pyramid_info,
                        "total_matches": len(matches),
                        "matches": matches[:20],
                    }

                if "error" in result:
                    iterations.append(
                        {
                            "iteration": iteration + 1,
                            "ioc": current_ioc,
                            "ioc_type": current_ioc_type,
                            "error": result["error"],
                        }
                    )
                    break

                # Extract new IoCs from results
                new_iocs = tools_instance._extract_iocs_from_matches(result.get("matches", []))

                # Add to discovered set
                for ioc_entry in new_iocs:
                    discovered_iocs.add(f"{ioc_entry['type']}:{ioc_entry['value']}")

                iteration_result = {
                    "iteration": iteration + 1,
                    "searched_ioc": current_ioc,
                    "searched_ioc_type": current_ioc_type,
                    "pyramid_level": result.get("pyramid_of_pain", {}).get("pyramid_level"),
                    "matches_found": result.get("total_matches", 0),
                    "new_iocs_discovered": len(new_iocs),
                    "summary": result.get("summary"),
                    "follow_up_suggestions": result.get("follow_up_searches", []),
                    "sample_matches": result.get("matches", [])[:5],
                }

                iterations.append(iteration_result)

                # Select next IoC to hunt
                if new_iocs and iteration < max_iterations - 1:
                    if follow_pyramid:
                        # Pick highest priority IoC not yet searched
                        next_ioc = tools_instance._select_next_ioc_by_pyramid(new_iocs, discovered_iocs)
                    else:
                        # Pick first new IoC
                        next_ioc = new_iocs[0] if new_iocs else None

                    if next_ioc:
                        current_ioc = next_ioc["value"]
                        current_ioc_type = next_ioc["type"]
                    else:
                        break
                else:
                    break

            # Build complete analysis
            complete_analysis = {
                "initial_ioc": f"{initial_ioc_type}:{initial_ioc}",
                "total_iterations": len(iterations),
                "total_iocs_discovered": len(discovered_iocs),
                "iterations": iterations,
                "discovered_iocs_list": sorted(list(discovered_iocs)),
                "diamond_model_complete": tools_instance._build_complete_diamond_model(iterations),
                "attack_reconstruction": tools_instance._reconstruct_attack_timeline(iterations),
                "final_recommendations": tools_instance._generate_final_recommendations(iterations),
            }

            # Auto-capture IoCs to active investigation
            return auto_capture_chainsaw_results(
                results=complete_analysis,
                tool_name="iterative_hunt",
                query_description=f"Iterative hunt starting from {initial_ioc_type}: {initial_ioc}",
            )

        @mcp.tool()
        def get_pyramid_of_pain_guide() -> dict:
            """
            Get the Pyramid of Pain framework guide for IoC prioritization.

            Returns complete information about the Pyramid of Pain levels and how to use them
            for effective threat hunting, starting with easy-to-track indicators and moving
            to harder-to-change TTPs.

            Returns:
                Complete Pyramid of Pain framework with:
                - All 6 levels with descriptions
                - Hunting strategy recommendations
                - Examples for each level
                - Integration with Diamond Model

            Use this to understand:
                - Which IoCs to hunt first
                - How attackers adapt to detection
                - Most effective hunting strategies
            """
            from src.clients.common.chainsaw_client import ChainsawClient

            # Convert dataclass objects to dicts for JSON serialization
            levels_dict = {}
            for level, info in ChainsawClient.PYRAMID_OF_PAIN.items():
                levels_dict[level] = {
                    "level": info.level,
                    "name": info.name,
                    "description": info.description,
                    "difficulty_to_change": info.difficulty_to_change,
                    "examples": info.examples,
                }

            return {
                "framework": "Pyramid of Pain",
                "description": "Bianco's Pyramid of Pain shows the pain inflicted on attackers when defenders detect and block their indicators",
                "hunting_strategy": "Start at Level 2-3 (IPs, Domains) for quick wins, then move up to Level 5-6 (Tools, TTPs) for lasting impact",
                "levels": levels_dict,
                "recommended_hunting_order": [
                    {"step": 1, "level": 2, "focus": "IP Addresses", "reason": "Easy to find, provides quick context"},
                    {"step": 2, "level": 3, "focus": "Domain Names", "reason": "Shows attacker infrastructure"},
                    {"step": 3, "level": 5, "focus": "Tools", "reason": "Identifies specific malware/tools used"},
                    {
                        "step": 4,
                        "level": 6,
                        "focus": "TTPs",
                        "reason": "Most valuable - attackers can't easily change behavior",
                    },
                ],
                "integration_with_diamond_model": {
                    "Infrastructure": "Levels 2-3 (IPs, Domains)",
                    "Capability": "Levels 5-6 (Tools, TTPs)",
                    "Victim": "Identified from all levels",
                    "Adversary": "Inferred from Level 6 (TTPs)",
                },
            }

        @mcp.tool()
        def get_diamond_model_guide() -> dict:
            """
            Get the Diamond Model of Intrusion Analysis guide.

            Returns complete information about the Diamond Model and how to use it
            for comprehensive threat analysis during hunting operations.

            Returns:
                Complete Diamond Model framework with:
                - All 4 vertices (Adversary, Capability, Infrastructure, Victim)
                - How to populate each vertex from hunt results
                - Integration with Pyramid of Pain
                - Example analysis

            Use this to:
                - Understand the complete attack picture
                - Connect different pieces of evidence
                - Identify gaps in your analysis
            """
            from src.clients.common.chainsaw_client import ChainsawClient

            # Convert dataclass objects to dicts for JSON serialization
            vertices_dict = {}
            for name, info in ChainsawClient.DIAMOND_MODEL.items():
                vertices_dict[name] = {
                    "vertex": info.vertex,
                    "description": info.description,
                    "elements": info.elements,
                }

            return {
                "framework": "Diamond Model of Intrusion Analysis",
                "description": "The Diamond Model represents intrusion analysis as relationships between four core features",
                "vertices": vertices_dict,
                "relationships": {
                    "adversary_to_infrastructure": "Adversary uses Infrastructure",
                    "adversary_to_capability": "Adversary deploys Capability",
                    "capability_to_infrastructure": "Capability targets Infrastructure",
                    "infrastructure_to_victim": "Infrastructure affects Victim",
                    "capability_to_victim": "Capability impacts Victim",
                },
                "hunting_application": {
                    "step_1": "Identify Victim (affected hosts/users) - easiest to find",
                    "step_2": "Discover Infrastructure (IPs, domains) from victim logs",
                    "step_3": "Extract Capability (tools, techniques) from events",
                    "step_4": "Infer Adversary from TTPs and infrastructure patterns",
                },
                "integration_with_pyramid": {
                    "note": "Use Pyramid of Pain to prioritize which vertex to investigate first",
                    "strategy": "Start with Infrastructure (Levels 2-3) to quickly populate the model, then focus on Capability (Levels 5-6) for attribution",
                },
            }

    # Helper methods - now proper class methods
    def _categorize_and_analyze_detections(self, detections: list[dict], prioritize: bool) -> dict:
        """Categorize detections by Pyramid of Pain and analyze with Diamond Model."""
        by_pyramid = {i: [] for i in range(1, 7)}
        diamond_summary = {
            "adversary_elements": set(),
            "capability_elements": set(),
            "infrastructure_elements": set(),
            "victim_elements": set(),
        }
        follow_ups = []

        for detection in detections:
            # Skip if detection is not a dict (defensive coding)
            if not isinstance(detection, dict):
                continue
            # Extract IoC type and categorize
            rule_name = detection.get("name", "")

            # Simple categorization based on rule name
            if any(keyword in rule_name.lower() for keyword in ["hash", "md5", "sha"]):
                level = 1
            elif any(keyword in rule_name.lower() for keyword in ["ip", "network"]):
                level = 2
            elif any(keyword in rule_name.lower() for keyword in ["domain", "dns"]):
                level = 3
            elif any(keyword in rule_name.lower() for keyword in ["registry", "artifact"]):
                level = 4
            elif any(keyword in rule_name.lower() for keyword in ["mimikatz", "psexec", "tool"]):
                level = 5
            else:
                level = 6  # TTPs

            by_pyramid[level].append(detection)

            # Diamond Model mapping
            diamond = self.chainsaw.map_to_diamond_model(detection)
            for vertex, data in diamond.items():
                if data["identified"]:
                    for element in data["elements"]:
                        diamond_summary[f"{vertex}_elements"].add(f"{element['type']}:{element['value']}")

        # Convert sets to lists for JSON serialization
        for key in diamond_summary:
            diamond_summary[key] = list(diamond_summary[key])

        # Generate follow-up suggestions
        if prioritize:
            # Suggest hunting for higher pyramid levels
            if by_pyramid[2] or by_pyramid[3]:  # Found IPs/domains
                follow_ups.append(
                    {
                        "priority": "HIGH",
                        "action": "Search for tools/malware associated with discovered IPs/domains",
                        "pyramid_level": 5,
                    }
                )
            if by_pyramid[5]:  # Found tools
                follow_ups.append(
                    {
                        "priority": "CRITICAL",
                        "action": "Analyze TTPs and behavior patterns to understand adversary methodology",
                        "pyramid_level": 6,
                    }
                )

        return {"by_pyramid": by_pyramid, "diamond_summary": diamond_summary, "follow_ups": follow_ups}

    def _generate_hunt_summary(self, categorized: dict, evtx_path: str) -> str:
        """Generate human-readable summary of hunt results."""
        total = sum(len(categorized["by_pyramid"][i]) for i in range(1, 7))

        summary_parts = [f"Analyzed EVTX files at: {evtx_path}"]
        summary_parts.append(f"Total detections: {total}")

        pyramid_summary = []
        for level in range(6, 0, -1):  # Reverse order for priority
            count = len(categorized["by_pyramid"][level])
            if count > 0:
                from src.clients.common.chainsaw_client import ChainsawClient

                level_info = ChainsawClient.PYRAMID_OF_PAIN[level]
                pyramid_summary.append(f"  Level {level} ({level_info.name}): {count} detections")

        if pyramid_summary:
            summary_parts.append("\nDetections by Pyramid of Pain:")
            summary_parts.extend(pyramid_summary)

        # Diamond Model summary
        diamond = categorized["diamond_summary"]
        summary_parts.append("\nDiamond Model Analysis:")
        summary_parts.append(f"  Infrastructure: {len(diamond['infrastructure_elements'])} elements")
        summary_parts.append(f"  Capability: {len(diamond['capability_elements'])} elements")
        summary_parts.append(f"  Victim: {len(diamond['victim_elements'])} elements")

        return "\n".join(summary_parts)

    def _generate_search_summary(self, ioc: str, ioc_type: str, matches: list[dict]) -> str:
        """Generate summary of search results."""
        if not matches:
            return f"No matches found for {ioc_type}: {ioc}"

        summary = f"Found {len(matches)} matches for {ioc_type}: {ioc}\n"

        # Extract common patterns
        event_ids = set()
        computers = set()
        for match in matches[:20]:
            if "Event" in match and "System" in match["Event"]:
                event_id = match["Event"]["System"].get("EventID")
                if event_id:
                    event_ids.add(str(event_id))
                computer = match["Event"]["System"].get("Computer")
                if computer:
                    computers.add(computer)

        if event_ids:
            summary += f"Event IDs: {', '.join(sorted(event_ids))}\n"
        if computers:
            summary += f"Affected hosts: {', '.join(sorted(list(computers)[:5]))}"
            if len(computers) > 5:
                summary += f" and {len(computers) - 5} more"

        return summary

    def _suggest_follow_up_searches(self, ioc: str, ioc_type: str, matches: list[dict]) -> list[dict]:
        """Suggest follow-up searches based on results."""
        suggestions = []

        # Extract potential follow-up IoCs
        if matches:
            # Suggest searching for related processes
            suggestions.append(
                {
                    "suggestion": f"Search for processes that interacted with {ioc}",
                    "ioc_type": "process_name",
                    "priority": "HIGH",
                }
            )

            # Suggest timeline analysis
            suggestions.append(
                {
                    "suggestion": f"Analyze events before and after {ioc} activity",
                    "action": "time_correlation",
                    "priority": "MEDIUM",
                }
            )

        return suggestions

    def _extract_diamond_model_from_matches(self, matches: list[dict]) -> dict:
        """Extract Diamond Model elements from search matches."""
        diamond = {"infrastructure": [], "capability": [], "victim": []}

        for match in matches[:10]:
            if not isinstance(match, dict):
                continue
            if "Event" in match:
                event_data = match["Event"].get("EventData", {})

                # Extract infrastructure
                if "IpAddress" in event_data:
                    diamond["infrastructure"].append(event_data["IpAddress"])

                # Extract capability
                if "Image" in event_data:
                    diamond["capability"].append(event_data["Image"])

                # Extract victim
                system = match["Event"].get("System", {})
                if "Computer" in system:
                    diamond["victim"].append(system["Computer"])

        # Deduplicate
        for key in diamond:
            diamond[key] = list(set(diamond[key]))[:5]

        return diamond

    def _extract_iocs_from_matches(self, matches: list[dict]) -> list[dict]:
        """Extract IoCs from search matches for iterative hunting."""
        iocs = []
        seen = set()

        for match in matches[:20]:
            if not isinstance(match, dict):
                continue
            if "Event" in match:
                event_data = match["Event"].get("EventData", {})

                # Extract IPs
                for field in ["IpAddress", "SourceAddress", "DestAddress"]:
                    if field in event_data:
                        ip = event_data[field]
                        if ip and ip not in seen:
                            iocs.append({"type": "ip", "value": ip})
                            seen.add(ip)

                # Extract processes
                for field in ["Image", "ProcessName", "TargetImage"]:
                    if field in event_data:
                        process = event_data[field]
                        if process and process not in seen:
                            iocs.append({"type": "process_name", "value": process})
                            seen.add(process)

                # Extract domains
                if "QueryName" in event_data:
                    domain = event_data["QueryName"]
                    if domain and domain not in seen:
                        iocs.append({"type": "domain", "value": domain})
                        seen.add(domain)

        return iocs

    def _select_next_ioc_by_pyramid(self, new_iocs: list[dict], discovered: set) -> dict | None:
        """Select next IoC to hunt based on Pyramid of Pain priority."""
        # Prioritize by pyramid level (prefer higher levels)
        prioritized = []

        for ioc in new_iocs:
            ioc_key = f"{ioc['type']}:{ioc['value']}"
            if ioc_key not in discovered:
                pyramid_info = self.chainsaw.categorize_ioc_by_pyramid(ioc["type"], ioc["value"])
                prioritized.append({"ioc": ioc, "priority": pyramid_info["priority"]})

        if not prioritized:
            return None

        # Sort by priority (higher is better)
        prioritized.sort(key=lambda x: x["priority"], reverse=True)
        return prioritized[0]["ioc"]

    def _build_complete_diamond_model(self, iterations: list[dict]) -> dict:
        """Build complete Diamond Model from all iterations."""
        complete = {
            "adversary": {"elements": [], "confidence": "LOW"},
            "capability": {"elements": [], "confidence": "MEDIUM"},
            "infrastructure": {"elements": [], "confidence": "HIGH"},
            "victim": {"elements": [], "confidence": "HIGH"},
        }

        # This would analyze all iterations to build complete picture
        # Simplified version here

        return complete

    def _reconstruct_attack_timeline(self, iterations: list[dict]) -> list[dict]:
        """Reconstruct attack timeline from iterations."""
        timeline = []

        for iteration in iterations:
            timeline.append(
                {
                    "step": iteration["iteration"],
                    "action": f"Searched for {iteration['searched_ioc']} ({iteration['searched_ioc_type']})",
                    "findings": iteration["matches_found"],
                    "new_iocs": iteration["new_iocs_discovered"],
                }
            )

        return timeline

    def _generate_final_recommendations(self, iterations: list[dict]) -> list[str]:
        """Generate final recommendations based on all iterations."""
        recommendations = []

        total_matches = sum(it.get("matches_found", 0) for it in iterations)
        total_iocs = sum(it.get("new_iocs_discovered", 0) for it in iterations)

        if total_matches > 50:
            recommendations.append("HIGH SEVERITY: Significant malicious activity detected across multiple indicators")
            recommendations.append("Immediate incident response recommended")

        if total_iocs > 20:
            recommendations.append("Complex attack detected with multiple IoCs")
            recommendations.append("Perform full compromise assessment on affected systems")

        recommendations.append("Review all discovered IoCs and add to threat intelligence")
        recommendations.append("Implement detection rules for discovered TTPs")

        return recommendations
