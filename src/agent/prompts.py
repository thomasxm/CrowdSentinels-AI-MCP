"""Build system and user prompts for the investigation agent."""

import json
from typing import Any, Dict, List


SYSTEM_PROMPT = """You are CrowdSentinel, an expert security analyst performing an investigation using MCP tools.

## Investigation Methodology

Follow this 4-phase workflow:

### Phase 1: Data Collection
- Review the provided hunt data (events, IoCs, MITRE techniques)
- Use threat_hunt_search, hunt_by_timeframe, or search_documents to gather additional context
- Use hunt_for_ioc to check specific indicators across indices

### Phase 2: Analysis
- Use analyze_search_results to extract IoCs and map MITRE ATT&CK techniques
- Use analyze_kill_chain_stage to position findings in the Cyber Kill Chain
- Use map_events_to_kill_chain for comprehensive stage mapping
- Correlate findings across multiple data sources

### Phase 3: Correlation
- Use hunt_adjacent_stages to discover related activity before and after the detected stage
- Use detect_lateral_movement, detect_beaconing if network data is available
- Cross-reference IoCs across Elasticsearch, EVTX (Chainsaw), and PCAP (Wireshark) if available

### Phase 4: Reporting
- Synthesise all findings into a structured response

## Output Format

Your FINAL response must be valid JSON with this structure:
```json
{
  "severity_assessment": "critical|high|medium|low",
  "summary": {
    "total_events": <number>,
    "key_finding": "<one sentence>"
  },
  "mitre_attack_techniques": [
    {"technique_id": "T1234", "technique_name": "Name", "tactic": "Tactic", "evidence": "What you found"}
  ],
  "iocs_found": [
    {"type": "ip|domain|hash|hostname|commandline", "value": "...", "context": "Where/how it was found"}
  ],
  "kill_chain_stage": "<stage name>",
  "insights": ["<key finding 1>", "<key finding 2>"],
  "recommended_followup": ["<next investigation step 1>", "<next investigation step 2>"]
}
```

## Rules
- Use tools to verify hypotheses, do not guess
- If a tool call fails, note the error and continue with other tools
- Focus on the user's investigation context
- Be concise — findings over filler
"""


def build_system_prompt(tool_names_by_server: Dict[str, List[str]]) -> str:
    """Build the system prompt with available tool inventory."""
    tools_section = "\n## Available Tools\n"
    for server, names in tool_names_by_server.items():
        tools_section += f"\n**{server}** ({len(names)} tools):\n"
        # Group in rows of 4 for readability
        for i in range(0, len(names), 4):
            chunk = names[i:i + 4]
            tools_section += "  " + ", ".join(chunk) + "\n"

    return SYSTEM_PROMPT + tools_section


def build_user_message(hunt_data: Dict[str, Any], context: str) -> str:
    """Build the user message from piped hunt data and investigation context."""
    parts = [f"## Investigation Context\n{context}\n"]

    # Include the hunt data
    parts.append("## Hunt Data\n```json")
    parts.append(json.dumps(hunt_data, indent=2, default=str))
    parts.append("```\n")

    # Highlight key findings if present
    summary = hunt_data.get("summary", {})
    if isinstance(summary, dict) and summary:
        parts.append(f"**Hits:** {summary.get('total_hits', 'unknown')}")
        parts.append(f"**Severity:** {summary.get('severity', 'unknown')}")

    iocs = hunt_data.get("iocs", {})
    if isinstance(iocs, dict) and iocs:
        total = sum(len(v) for v in iocs.values() if isinstance(v, list))
        parts.append(f"**IoCs found:** {total}")

    mitre = hunt_data.get("mitre_techniques", [])
    if isinstance(mitre, list) and mitre:
        tids = [t.get("technique_id", "?") for t in mitre if isinstance(t, dict)]
        parts.append(f"**MITRE techniques:** {', '.join(tids)}")

    parts.append("\nInvestigate this data using the available tools. Follow the 4-phase methodology. Return your findings as the JSON structure specified in your instructions.")

    return "\n".join(parts)
