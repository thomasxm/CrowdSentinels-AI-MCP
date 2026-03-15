"""MCP Resources and Prompts for Investigation Workflow Guidance.

This module provides workflow guidance through MCP primitives (resources and prompts)
so that ANY AI agent connecting to the MCP server knows how to use the tools properly.

Unlike CLAUDE.md or skills which are local to specific environments, these MCP
primitives are exposed by the server itself and accessible to all connected clients.
"""
from fastmcp import FastMCP

INVESTIGATION_WORKFLOW = """
# CrowdSentinel Investigation Workflow

## The Iron Law

```
NO INVESTIGATION IS COMPLETE WITHOUT ANALYSIS TOOLS
```

If you have collected data but haven't used analysis tools, the investigation is INCOMPLETE.

## Mandatory Workflow

### Phase 1: Data Collection
Use hunting tools to gather evidence:

| Tool | Use Case |
|------|----------|
| `threat_hunt_search` | IR-focused search with auto IoC extraction (PREFERRED) |
| `smart_search` | Token-efficient search with summarization |
| `execute_detection_rule` | Run EQL/Lucene detection rules |
| `execute_esql_hunt` | Run ES|QL hunting queries |
| `esql_query` | Ad-hoc ES|QL queries |
| `eql_search` | Ad-hoc EQL queries |

### Phase 2: Analysis (MANDATORY - DO NOT SKIP)

After EVERY search/hunt query, you MUST analyze the results:

1. **analyze_search_results(results, context)**
   - Extracts IoCs, maps MITRE ATT&CK, assesses severity
   - Provides recommended follow-up queries

2. **analyze_kill_chain_stage(iocs, include_hunting_suggestions)**
   - Positions attack in Cyber Kill Chain
   - Suggests previous/next stage hunting

3. **map_events_to_kill_chain(events)**
   - Maps event timeline to kill chain stages
   - Shows attack progression

### Phase 3: Investigation State (Multi-Query Investigations)

1. `create_investigation(name, description, severity)` - Start tracking
2. `add_iocs_to_investigation(iocs)` - Store discovered IoCs
3. `get_shared_iocs()` - Retrieve for cross-correlation
4. `get_investigation_summary()` - Check current state

### Phase 4: Reporting (Before Concluding)

Before presenting findings to user:

```
generate_investigation_report(
    analysis_results=[analysis1, analysis2, ...],
    investigation_context="Description of what was investigated"
)
```

Returns: Executive summary, aggregated IoCs, MITRE techniques, severity, recommendations.

## Correct vs Incorrect Workflow

```
❌ WRONG: Run queries → manually summarize → present to user
✅ RIGHT: Run queries → analyze_search_results → analyze_kill_chain_stage
          → generate_investigation_report → present to user
```

## Verification Checklist

Before presenting findings, verify:
- [ ] Used `analyze_search_results` on query results
- [ ] Used `analyze_kill_chain_stage` on extracted IoCs
- [ ] MITRE ATT&CK techniques identified
- [ ] Kill chain position determined
- [ ] `generate_investigation_report` called (for formal investigations)
- [ ] Recommendations included in response
"""

RECOMMENDED_NEXT_STEPS = {
    # Data collection tools → Analysis
    "search_documents": {
        "next_step": "analyze_search_results",
        "hint": "Use analyze_search_results() to extract IoCs and map to MITRE ATT&CK"
    },
    "smart_search": {
        "next_step": "analyze_search_results",
        "hint": "Use analyze_search_results() to extract IoCs and assess severity"
    },
    "threat_hunt_search": {
        "next_step": "analyze_kill_chain_stage",
        "hint": "IoCs already extracted. Use analyze_kill_chain_stage() to position in kill chain"
    },
    "execute_detection_rule": {
        "next_step": "analyze_search_results",
        "hint": "Use analyze_search_results() to analyze detection hits"
    },
    "execute_esql_hunt": {
        "next_step": "analyze_search_results",
        "hint": "Use analyze_search_results() to analyze hunting results"
    },
    "esql_query": {
        "next_step": "analyze_search_results",
        "hint": "Use analyze_search_results() to extract insights from query results"
    },
    "eql_search": {
        "next_step": "analyze_search_results",
        "hint": "Use analyze_search_results() to analyze EQL matches"
    },
    "hunt_by_timeframe": {
        "next_step": "analyze_search_results",
        "hint": "Use analyze_search_results() for comprehensive analysis"
    },
    "hunt_for_ioc": {
        "next_step": "analyze_search_results",
        "hint": "Use analyze_search_results() to assess IoC matches"
    },

    # Analysis tools → More analysis or reporting
    "analyze_search_results": {
        "next_step": "analyze_kill_chain_stage",
        "hint": "Use analyze_kill_chain_stage() with extracted IoCs to position in kill chain"
    },
    "analyze_kill_chain_stage": {
        "next_step": "generate_investigation_report",
        "hint": "Use generate_investigation_report() to create final report, or follow hunting suggestions"
    },

    # Kill chain hunting → Analysis
    "hunt_by_kill_chain_stage": {
        "next_step": "analyze_search_results",
        "hint": "Use analyze_search_results() to analyze stage-specific findings"
    },
    "hunt_adjacent_stages": {
        "next_step": "analyze_search_results",
        "hint": "Use analyze_search_results() on each stage's results"
    },
}


class WorkflowGuidanceTools:
    """MCP resources and prompts for investigation workflow guidance."""

    def register_tools(self, mcp: FastMCP):
        """Register workflow guidance as MCP resources and prompts."""

        # Register MCP Resource: Investigation Workflow Documentation
        @mcp.resource("crowdsentinel://investigation-workflow")
        def get_investigation_workflow_resource():
            """
            Complete investigation workflow documentation for CrowdSentinel.

            Read this resource to understand the mandatory workflow for
            conducting threat hunting and incident response investigations.

            IMPORTANT: This workflow is MANDATORY. Every investigation must
            follow these phases and use the analysis tools.
            """
            return INVESTIGATION_WORKFLOW

        # Register MCP Resource: Tool Recommendations
        @mcp.resource("crowdsentinel://tool-recommendations")
        def get_tool_recommendations_resource():
            """
            Recommended next steps after using each tool.

            This resource maps each CrowdSentinel tool to its recommended
            follow-up action, ensuring complete investigations.
            """
            return RECOMMENDED_NEXT_STEPS

        # Register MCP Prompt: Investigation Starter
        @mcp.prompt("start-investigation")
        def start_investigation_prompt(
            description: str = "Describe the incident or threat to investigate"
        ):
            """
            Use this prompt to start a new investigation with proper workflow.

            This ensures the investigation follows the mandatory workflow:
            1. Data Collection (hunting/search)
            2. Analysis (analyze_search_results, analyze_kill_chain_stage)
            3. State Management (create_investigation, add_iocs)
            4. Reporting (generate_investigation_report)
            """
            return f"""You are conducting a security investigation using CrowdSentinel.

## Investigation Context
{description}

## MANDATORY Workflow (DO NOT SKIP)

### Before You Start
1. Read the investigation workflow: Use `crowdsentinel://investigation-workflow` resource

### Phase 1: Data Collection
- Use `threat_hunt_search` (preferred) or other hunting tools
- Start with `create_investigation()` to track IoCs across queries

### Phase 2: Analysis (REQUIRED)
After EVERY search query, you MUST use:
- `analyze_search_results()` - Extract IoCs, map MITRE ATT&CK
- `analyze_kill_chain_stage()` - Position attack in kill chain

### Phase 3: Reporting
Before concluding, use:
- `generate_investigation_report()` - Create comprehensive report

## Anti-Pattern Warning
```
❌ WRONG: Run queries → manually summarize → present to user
✅ RIGHT: Run queries → analyze_search_results → analyze_kill_chain_stage
          → generate_investigation_report → present to user
```

Begin your investigation now, following this workflow strictly.
"""

        # Register a tool for workflow guidance
        @mcp.tool()
        def get_investigation_workflow() -> dict:
            """
            Get the mandatory investigation workflow for CrowdSentinel.

            Call this tool at the START of any investigation to understand
            the required workflow phases and tools.

            The workflow ensures comprehensive analysis by requiring:
            1. Data collection using hunting/search tools
            2. Analysis using analyze_search_results and analyze_kill_chain_stage
            3. Reporting using generate_investigation_report

            Returns:
                Complete workflow documentation with tool recommendations

            Example:
                # First thing to do when starting an investigation
                workflow = get_investigation_workflow()
                # Follow the phases described
            """
            return {
                "workflow": INVESTIGATION_WORKFLOW,
                "tool_recommendations": RECOMMENDED_NEXT_STEPS,
                "critical_reminder": (
                    "NEVER skip the analysis phase. After every search/hunt query, "
                    "you MUST use analyze_search_results() and analyze_kill_chain_stage(). "
                    "Before concluding, use generate_investigation_report()."
                )
            }

        @mcp.tool()
        def get_next_step(tool_name: str) -> dict:
            """
            Get the recommended next step after using a specific tool.

            Call this after any search/hunting tool to know what analysis
            tool to use next.

            Args:
                tool_name: The name of the tool you just used (e.g., "smart_search")

            Returns:
                Recommended next tool and explanation

            Example:
                # After running smart_search
                next_action = get_next_step("smart_search")
                # Returns: {"next_step": "analyze_search_results", "hint": "..."}
            """
            if tool_name in RECOMMENDED_NEXT_STEPS:
                return {
                    "previous_tool": tool_name,
                    **RECOMMENDED_NEXT_STEPS[tool_name],
                    "workflow_phase": self._get_phase(tool_name)
                }
            return {
                "previous_tool": tool_name,
                "next_step": "analyze_search_results",
                "hint": "If this tool returned search results, analyze them with analyze_search_results()",
                "workflow_phase": "unknown"
            }

    def _get_phase(self, tool_name: str) -> str:
        """Determine which workflow phase a tool belongs to."""
        collection_tools = {
            "search_documents", "smart_search", "threat_hunt_search",
            "execute_detection_rule", "execute_esql_hunt", "esql_query",
            "eql_search", "hunt_by_timeframe", "hunt_for_ioc",
            "hunt_by_kill_chain_stage", "hunt_adjacent_stages"
        }
        analysis_tools = {
            "analyze_search_results", "analyze_kill_chain_stage",
            "map_events_to_kill_chain"
        }
        reporting_tools = {"generate_investigation_report"}

        if tool_name in collection_tools:
            return "Phase 1: Data Collection"
        if tool_name in analysis_tools:
            return "Phase 2: Analysis"
        if tool_name in reporting_tools:
            return "Phase 4: Reporting"
        return "Unknown"
