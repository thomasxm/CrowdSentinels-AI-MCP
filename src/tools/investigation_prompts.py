"""MCP Tools for Investigation Prompts - Triage Questions for SIEM/SOAR."""
from fastmcp import FastMCP


class InvestigationPromptsTools:
    """Tools for displaying and executing investigation triage prompts."""

    def __init__(self, search_client):
        """
        Initialize investigation prompts tools.

        Args:
            search_client: Elasticsearch client with investigation prompts capability
        """
        self.search_client = search_client

    def register_tools(self, mcp: FastMCP):
        @mcp.tool()
        def show_investigation_prompts(
            platform: str | None = None,
            show_details: bool = False
        ) -> dict:
            """
            Display investigation triage questions for SIEM/SOAR.

            This tool shows the "fast triage spine" questions that every
            security analyst should ask when investigating a potential incident.
            These are the first questions to slam into your SIEM/SOAR.

            The 10 questions cover: identity → execution → persistence → network → privilege

            Args:
                platform: Filter by platform ("linux" or "windows", None for both)
                show_details: Show detailed information including log sources and fields

            Returns:
                Investigation prompts with questions and metadata

            Examples:
                # Show all investigation prompts
                show_investigation_prompts()

                # Show only Windows prompts
                show_investigation_prompts(platform="windows")

                # Show with full details
                show_investigation_prompts(platform="linux", show_details=True)
            """
            from src.clients.common.investigation_prompts import (
                InvestigationPromptsClient,
            )

            prompts = InvestigationPromptsClient.get_all_prompts(platform=platform)

            # Format prompts for display
            formatted_prompts = {}

            for prompt_id, prompt in prompts.items():
                if show_details:
                    formatted_prompts[prompt_id] = {
                        "priority": prompt.priority,
                        "platform": prompt.platform.upper(),
                        "question": prompt.question,
                        "description": prompt.description,
                        "focus_areas": prompt.focus_areas,
                        "log_sources": prompt.log_sources,
                        "elasticsearch_fields": prompt.elasticsearch_fields,
                        "mitre_tactics": prompt.mitre_tactics
                    }
                else:
                    formatted_prompts[prompt_id] = {
                        "priority": prompt.priority,
                        "platform": prompt.platform.upper(),
                        "question": prompt.question,
                        "description": prompt.description
                    }

            # Group by platform
            linux_prompts = {k: v for k, v in formatted_prompts.items() if "LINUX" in v["platform"]}
            windows_prompts = {k: v for k, v in formatted_prompts.items() if "WINDOWS" in v["platform"]}

            return {
                "message": "🔍 Investigation Triage Spine - First Questions for SIEM/SOAR",
                "description": "These 10 questions are the fast 'triage spine': identity → execution → persistence → network → privilege",
                "total_prompts": len(formatted_prompts),
                "linux_prompts": linux_prompts,
                "windows_prompts": windows_prompts,
                "usage_tip": "Use start_guided_investigation() to begin investigating with these prompts",
                "execution_tip": "Use investigate_with_prompt() to execute a specific prompt against your logs"
            }

        @mcp.tool()
        def start_guided_investigation(
            platform: str,
            index: str,
            timeframe_minutes: int = 60,
            host: str | None = None
        ) -> dict:
            """
            Start a guided investigation with all triage prompts for a platform.

            This tool presents all investigation questions for the selected platform
            and allows you to systematically investigate using the triage spine.

            Args:
                platform: Target platform ("linux" or "windows")
                index: Index pattern to search (e.g., "winlogbeat-*", "auditbeat-*")
                timeframe_minutes: Investigation time window in minutes (default: 60)
                host: Optional hostname to filter results

            Returns:
                Guided investigation results for all prompts

            Examples:
                # Investigate Windows endpoint
                start_guided_investigation(
                    platform="windows",
                    index="winlogbeat-*",
                    timeframe_minutes=120,
                    host="DESKTOP-ABC123"
                )

                # Investigate Linux server
                start_guided_investigation(
                    platform="linux",
                    index="auditbeat-*",
                    timeframe_minutes=60,
                    host="web-server-01"
                )
            """
            from src.clients.common.investigation_prompts import (
                InvestigationPromptsClient,
            )

            # Get prompts for platform (sorted by priority)
            prompts = InvestigationPromptsClient.get_prompts_by_priority(platform=platform)

            if not prompts:
                return {
                    "error": f"No prompts found for platform: {platform}",
                    "available_platforms": ["linux", "windows"]
                }

            # Build additional filters
            additional_filters = {}
            if host:
                additional_filters["host.name"] = host

            # Execute each prompt
            results = {
                "platform": platform.upper(),
                "index": index,
                "timeframe_minutes": timeframe_minutes,
                "host_filter": host,
                "total_prompts": len(prompts),
                "investigation_results": []
            }

            total_findings = 0

            for prompt in prompts:
                result = self.search_client.execute_investigation_prompt(
                    prompt_id=prompt.id,
                    index=index,
                    timeframe_minutes=timeframe_minutes,
                    size=50,  # Limit to 50 events per prompt
                    additional_filters=additional_filters
                )

                if "error" not in result:
                    total_findings += result.get("total_hits", 0)

                results["investigation_results"].append(result)

            results["total_findings"] = total_findings

            # Add summary
            if total_findings == 0:
                results["summary"] = "✓ No suspicious findings detected during this timeframe"
            else:
                results["summary"] = f"⚠ Found {total_findings} events requiring investigation"

            return results

        @mcp.tool()
        def investigate_with_prompt(
            prompt_id: str,
            index: str,
            timeframe_minutes: int = 60,
            size: int = 100,
            host: str | None = None,
            username: str | None = None,
            source_ip: str | None = None
        ) -> dict:
            """
            Execute a specific investigation prompt against Elasticsearch.

            Run a single triage question from the investigation spine.
            This allows focused investigation on specific areas.

            Args:
                prompt_id: Investigation prompt ID (from show_investigation_prompts)
                    Linux: linux_auth_1, linux_privilege_2, linux_processes_3,
                           linux_persistence_4, linux_network_5
                    Windows: windows_logon_1, windows_processes_2, windows_powershell_3,
                             windows_persistence_4, windows_privilege_5
                index: Index pattern to search
                timeframe_minutes: Time window in minutes (default: 60)
                size: Maximum number of results (default: 100, max: 500)
                host: Filter by specific hostname
                username: Filter by specific username
                source_ip: Filter by specific source IP

            Returns:
                Investigation results with matching events

            Examples:
                # Investigate Windows logons
                investigate_with_prompt(
                    prompt_id="windows_logon_1",
                    index="winlogbeat-*",
                    timeframe_minutes=120,
                    host="WEB-SERVER-01"
                )

                # Investigate Linux privilege escalation
                investigate_with_prompt(
                    prompt_id="linux_privilege_2",
                    index="auditbeat-*",
                    username="admin",
                    timeframe_minutes=60
                )

                # Investigate PowerShell execution
                investigate_with_prompt(
                    prompt_id="windows_powershell_3",
                    index="winlogbeat-*",
                    timeframe_minutes=240
                )
            """
            # Build additional filters
            additional_filters = {}
            if host:
                additional_filters["host.name"] = host
            if username:
                additional_filters["user.name"] = username
            if source_ip:
                additional_filters["source.ip"] = source_ip

            # Execute the investigation
            result = self.search_client.execute_investigation_prompt(
                prompt_id=prompt_id,
                index=index,
                timeframe_minutes=timeframe_minutes,
                size=min(size, 500),
                additional_filters=additional_filters
            )

            return result

        @mcp.tool()
        def get_investigation_query(prompt_id: str) -> dict:
            """
            Get the Elasticsearch query for an investigation prompt.

            This tool shows you the actual query that will be executed,
            along with the log sources and fields to check.

            Useful for:
            - Understanding what the prompt is looking for
            - Customizing queries for your environment
            - Verifying log source availability

            Args:
                prompt_id: Investigation prompt ID

            Returns:
                Query template and metadata

            Example:
                get_investigation_query("windows_logon_1")
            """
            from src.clients.common.investigation_prompts import (
                InvestigationPromptsClient,
            )

            prompt = InvestigationPromptsClient.get_prompt_by_id(prompt_id)

            if not prompt:
                return {
                    "error": f"Prompt not found: {prompt_id}",
                    "tip": "Use show_investigation_prompts() to see available prompts"
                }

            return {
                "prompt_id": prompt.id,
                "platform": prompt.platform.upper(),
                "priority": prompt.priority,
                "question": prompt.question,
                "description": prompt.description,
                "query_template": prompt.query_template,
                "log_sources_required": prompt.log_sources,
                "elasticsearch_fields": prompt.elasticsearch_fields,
                "focus_areas": prompt.focus_areas,
                "mitre_tactics": prompt.mitre_tactics,
                "usage": f"investigate_with_prompt(prompt_id='{prompt.id}', index='your-index-*')"
            }

        @mcp.tool()
        def quick_triage(
            platform: str,
            index: str,
            host: str,
            timeframe_minutes: int = 60,
            top_n_prompts: int = 3
        ) -> dict:
            """
            Quick triage: Run top N priority prompts for fast initial assessment.

            This is the fastest way to get initial triage results.
            Runs only the highest priority questions to quickly identify issues.

            Args:
                platform: Target platform ("linux" or "windows")
                index: Index pattern to search
                host: Hostname to investigate
                timeframe_minutes: Investigation window (default: 60 minutes)
                top_n_prompts: Number of prompts to run (default: 3, max: 5)

            Returns:
                Quick triage results

            Examples:
                # Quick Windows triage
                quick_triage(
                    platform="windows",
                    index="winlogbeat-*",
                    host="DESKTOP-ABC123",
                    timeframe_minutes=120
                )

                # Quick Linux triage
                quick_triage(
                    platform="linux",
                    index="auditbeat-*",
                    host="web-server-01",
                    top_n_prompts=5
                )
            """
            from src.clients.common.investigation_prompts import (
                InvestigationPromptsClient,
            )

            # Get top priority prompts
            prompts = InvestigationPromptsClient.get_prompts_by_priority(
                platform=platform,
                max_priority=min(top_n_prompts, 5)
            )

            if not prompts:
                return {
                    "error": f"No prompts found for platform: {platform}"
                }

            results = {
                "triage_type": "QUICK TRIAGE",
                "platform": platform.upper(),
                "host": host,
                "timeframe_minutes": timeframe_minutes,
                "prompts_executed": len(prompts),
                "findings": []
            }

            total_hits = 0

            for prompt in prompts:
                result = self.search_client.execute_investigation_prompt(
                    prompt_id=prompt.id,
                    index=index,
                    timeframe_minutes=timeframe_minutes,
                    size=20,  # Quick triage - limited results
                    additional_filters={"host.name": host}
                )

                if "error" not in result:
                    hits = result.get("total_hits", 0)
                    total_hits += hits

                    if hits > 0:
                        results["findings"].append({
                            "priority": prompt.priority,
                            "question": prompt.question,
                            "hits": hits,
                            "top_events": result.get("events", [])[:5],  # Show top 5
                            "prompt_id": prompt.id
                        })

            results["total_findings"] = total_hits

            if total_hits == 0:
                results["assessment"] = "✓ CLEAR - No immediate threats detected"
                results["recommendation"] = "Host appears clean for this timeframe. Consider running full investigation if suspicious activity suspected."
            else:
                results["assessment"] = f"⚠ ALERT - {total_hits} suspicious events found"
                results["recommendation"] = "Review findings and run start_guided_investigation() for comprehensive analysis."

            return results
