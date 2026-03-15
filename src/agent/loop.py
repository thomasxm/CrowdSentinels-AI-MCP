"""Agent tool-use loop for autonomous investigation.

Orchestrates an LLM + MCP tools to investigate security events following
the 4-phase IR methodology. Provider-agnostic — works with any LLMProvider.
"""

import json
import logging
import sys
import time
from typing import Any

from src.agent.mcp_bridge import MCPBridge
from src.agent.prompts import build_system_prompt, build_user_message
from src.agent.providers import LLMProvider

logger = logging.getLogger("crowdsentinel.agent.loop")


def _stderr(msg: str) -> None:
    """Write progress to stderr so it doesn't pollute stdout output."""
    sys.stderr.write(f"{msg}\n")
    sys.stderr.flush()


def _parse_structured_output(text: str) -> dict[str, Any]:
    """Extract structured JSON from the agent's final response.

    The agent is instructed to return JSON, but it may wrap it in
    markdown code fences or add commentary.
    """
    # Try direct parse first
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        pass

    # Try extracting from code fences
    if "```json" in text:
        start = text.index("```json") + 7
        end = text.index("```", start)
        try:
            return json.loads(text[start:end].strip())
        except (json.JSONDecodeError, ValueError):
            pass
    elif "```" in text:
        start = text.index("```") + 3
        end = text.index("```", start)
        try:
            return json.loads(text[start:end].strip())
        except (json.JSONDecodeError, ValueError):
            pass

    # Try finding JSON object in text
    for i, ch in enumerate(text):
        if ch == "{":
            depth = 0
            for j in range(i, len(text)):
                if text[j] == "{":
                    depth += 1
                elif text[j] == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(text[i:j + 1])
                        except json.JSONDecodeError:
                            break
            break

    # Fallback: wrap raw text
    return {"raw_analysis": text, "severity_assessment": "unknown"}


def run_agent(
    provider: LLMProvider,
    bridge: MCPBridge,
    hunt_data: dict[str, Any],
    context: str,
    max_steps: int = 30,
    timeout: int = 300,
) -> dict[str, Any]:
    """Run the agent investigation loop.

    Args:
        provider: LLM provider (Anthropic, OpenAI-compatible, etc.)
        bridge: MCP bridge with tool access
        hunt_data: Piped hunt data from stdin
        context: User-provided investigation context (-c flag)
        max_steps: Maximum tool calls before stopping
        timeout: Maximum seconds for the entire run

    Returns:
        Structured investigation results compatible with -o json/table/summary
    """
    start_time = time.time()
    total_tokens = {"input": 0, "output": 0}

    # Build tool inventory grouped by server
    tool_names_by_server: dict[str, list[str]] = {}
    for schema in bridge.list_tools():
        # Determine server from registry
        name = schema["name"]
        server_name = "crowdsentinel"
        if name in bridge._tool_registry:
            server_name = bridge._tool_registry[name][0]
        tool_names_by_server.setdefault(server_name, []).append(name)

    # Build prompts
    system_prompt = build_system_prompt(tool_names_by_server)
    user_message = build_user_message(hunt_data, context)

    # Convert tool schemas to provider format
    tools = [provider.convert_tool_schema(s) for s in bridge.list_tools()]

    # Conversation history
    messages: list[dict[str, Any]] = [
        {"role": "user", "content": user_message},
    ]

    tool_count = len(bridge.list_tools())
    _stderr(f"[agent] Starting investigation with {tool_count} tools available")
    _stderr(f"[agent] Model: {provider.model} | Max steps: {max_steps} | Timeout: {timeout}s")

    step = 0
    while step < max_steps:
        elapsed = time.time() - start_time
        if elapsed >= timeout:
            _stderr(f"[agent] Timeout reached ({timeout}s) after {step} steps")
            return {
                "severity_assessment": "unknown",
                "summary": {"status": f"Timeout after {step} tool calls ({elapsed:.0f}s)"},
                "mitre_attack_techniques": [],
                "iocs_found": [],
                "insights": ["Investigation timed out — partial results only"],
                "recommended_followup": ["Re-run with --timeout to allow more time"],
                "agent_metadata": {"steps": step, "elapsed_seconds": elapsed, **total_tokens},
            }

        # Call LLM
        response = provider.create_message(
            system=system_prompt,
            messages=messages,
            tools=tools,
        )

        total_tokens["input"] += response.usage.get("input_tokens", 0)
        total_tokens["output"] += response.usage.get("output_tokens", 0)

        # If done (no tool calls), extract final response
        if response.is_done:
            elapsed = time.time() - start_time
            _stderr(f"[agent] Investigation complete ({step} tool calls, {elapsed:.1f}s)")
            result = _parse_structured_output(response.text)
            result["agent_metadata"] = {
                "steps": step,
                "elapsed_seconds": round(elapsed, 1),
                **total_tokens,
            }
            return result

        # Process tool calls
        # Build assistant message content (for conversation history)
        assistant_content = []
        if response.text:
            assistant_content.append({"type": "text", "text": response.text})
        for tc in response.tool_calls:
            assistant_content.append({
                "type": "tool_use",
                "id": tc.id,
                "name": tc.name,
                "input": tc.arguments,
            })

        messages.append({"role": "assistant", "content": assistant_content})

        # Execute tools and collect results
        tool_results = []
        for tc in response.tool_calls:
            step += 1
            _stderr(f"[step {step}/{max_steps}] Calling {tc.name}...")

            try:
                result_text = bridge.execute_tool(tc.name, tc.arguments)
                # Truncate very large results to avoid context overflow
                if len(result_text) > 50000:
                    result_text = result_text[:50000] + "\n... (truncated)"
            except Exception as exc:
                result_text = json.dumps({"error": str(exc)})
                _stderr(f"[step {step}/{max_steps}] Error: {exc}")

            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tc.id,
                "content": [{"type": "text", "text": result_text}],
            })

        messages.append({"role": "user", "content": tool_results})

    # Max steps reached — try to extract useful results from the last tool outputs
    elapsed = time.time() - start_time
    _stderr(f"[agent] Max steps reached ({max_steps}) after {elapsed:.1f}s")

    # Scan tool results for investigation reports or analysis results
    last_report = None
    for msg in reversed(messages):
        content = msg.get("content", [])
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict):
                continue
            text = ""
            if block.get("type") == "tool_result":
                inner = block.get("content", [])
                if isinstance(inner, list):
                    text = " ".join(b.get("text", "") for b in inner if isinstance(b, dict))
                elif isinstance(inner, str):
                    text = inner
            if text:
                try:
                    parsed = json.loads(text)
                    if isinstance(parsed, dict) and parsed.get("severity"):
                        last_report = parsed
                        break
                except (json.JSONDecodeError, TypeError):
                    continue
        if last_report:
            break

    if last_report:
        _stderr("[agent] Extracted results from last tool output")
        result = {
            "severity_assessment": last_report.get("severity", "unknown"),
            "summary": last_report.get("summary", {"status": f"Partial — {max_steps} tool calls"}),
            "mitre_attack_techniques": last_report.get("mitre_attack_techniques", last_report.get("techniques", [])),
            "iocs_found": last_report.get("iocs_found", last_report.get("iocs", [])),
            "insights": last_report.get("insights", last_report.get("raw_insights", [])),
            "recommended_followup": last_report.get("recommended_followup", last_report.get("recommendations", [])),
            "agent_metadata": {"steps": max_steps, "elapsed_seconds": round(elapsed, 1), **total_tokens},
        }
        return result

    return {
        "severity_assessment": "unknown",
        "summary": {"status": f"Max steps reached ({max_steps} tool calls)"},
        "mitre_attack_techniques": [],
        "iocs_found": [],
        "insights": ["Investigation hit step limit — partial results only"],
        "recommended_followup": ["Re-run with --max-steps to allow more tool calls"],
        "agent_metadata": {"steps": max_steps, "elapsed_seconds": round(elapsed, 1), **total_tokens},
    }
