"""Agent mode tests with mock LLM provider.

Tests the agent loop, MCP bridge, and structured output without
requiring a real LLM API key or live Elasticsearch.
"""

import json
import os

import pytest

from src.agent.providers import LLMProvider, LLMResponse, ToolCall


class MockProvider(LLMProvider):
    """Mock LLM provider that returns scripted responses."""

    def __init__(self, responses):
        super().__init__("mock-model")
        self.responses = list(responses)
        self.call_count = 0

    def convert_tool_schema(self, mcp_tool):
        return {
            "name": mcp_tool["name"],
            "description": mcp_tool.get("description", ""),
            "input_schema": mcp_tool.get("inputSchema", {}),
        }

    def create_message(self, system, messages, tools, max_tokens=8192):
        self.call_count += 1
        if self.responses:
            return self.responses.pop(0)
        # Default: return final response
        return LLMResponse(
            text=json.dumps(
                {
                    "severity_assessment": "high",
                    "summary": {"total_events": 1, "key_finding": "Mock finding"},
                    "mitre_attack_techniques": [],
                    "iocs_found": [],
                    "insights": ["Mock insight"],
                    "recommended_followup": [],
                }
            ),
            tool_calls=[],
            stop_reason="end_turn",
            usage={"input_tokens": 100, "output_tokens": 50},
        )


class TestAgentLoop:
    def test_agent_completes_with_no_tools(self):
        """Agent returns immediately when LLM doesn't call tools."""
        from src.agent.loop import run_agent
        from src.agent.mcp_bridge import MCPBridge

        provider = MockProvider(
            [
                LLMResponse(
                    text=json.dumps(
                        {
                            "severity_assessment": "low",
                            "summary": {"total_events": 0},
                            "mitre_attack_techniques": [],
                            "iocs_found": [],
                            "insights": ["Nothing found"],
                            "recommended_followup": [],
                        }
                    ),
                    tool_calls=[],
                    stop_reason="end_turn",
                    usage={"input_tokens": 50, "output_tokens": 30},
                )
            ]
        )

        # Create a minimal bridge with no tools
        bridge = MCPBridge.__new__(MCPBridge)
        bridge._tool_registry = {}
        bridge._tool_schemas = []
        bridge._started = True

        result = run_agent(
            provider=provider,
            bridge=bridge,
            hunt_data={"summary": {"total_hits": 0}, "sample_events": []},
            context="empty test",
            max_steps=5,
            timeout=10,
        )

        assert result["severity_assessment"] == "low"
        assert "agent_metadata" in result
        assert result["agent_metadata"]["steps"] == 0

    def test_agent_respects_max_steps(self):
        """Agent stops after max_steps tool calls."""
        from src.agent.loop import run_agent
        from src.agent.mcp_bridge import MCPBridge

        # Provider that always returns tool calls (infinite loop)
        infinite_responses = [
            LLMResponse(
                text="Calling tool",
                tool_calls=[ToolCall(id=f"tc{i}", name="nonexistent_tool", arguments={})],
                stop_reason="tool_use",
                usage={"input_tokens": 10, "output_tokens": 10},
            )
            for i in range(20)
        ]
        provider = MockProvider(infinite_responses)

        bridge = MCPBridge.__new__(MCPBridge)
        bridge._tool_registry = {}
        bridge._tool_schemas = []
        bridge._started = True

        result = run_agent(
            provider=provider,
            bridge=bridge,
            hunt_data={"summary": {"total_hits": 1}},
            context="test",
            max_steps=3,
            timeout=60,
        )

        assert "Max steps" in result.get("summary", {}).get("status", "")
        assert result["agent_metadata"]["steps"] == 3

    def test_agent_timeout(self):
        """Agent stops on timeout."""
        import time

        from src.agent.loop import run_agent
        from src.agent.mcp_bridge import MCPBridge

        class SlowProvider(LLMProvider):
            def __init__(self):
                super().__init__("slow-model")
                self.call_count = 0

            def convert_tool_schema(self, mcp_tool):
                return mcp_tool

            def create_message(self, system, messages, tools, max_tokens=8192):
                self.call_count += 1
                time.sleep(2)  # Slow response
                return LLMResponse(
                    text="still thinking",
                    tool_calls=[ToolCall(id="tc1", name="fake", arguments={})],
                    stop_reason="tool_use",
                    usage={"input_tokens": 10, "output_tokens": 10},
                )

        bridge = MCPBridge.__new__(MCPBridge)
        bridge._tool_registry = {}
        bridge._tool_schemas = []
        bridge._started = True

        result = run_agent(
            provider=SlowProvider(),
            bridge=bridge,
            hunt_data={"summary": {"total_hits": 1}},
            context="test",
            max_steps=100,
            timeout=3,  # 3 second timeout
        )

        assert "Timeout" in result.get("summary", {}).get("status", "")


class TestStructuredOutputParsing:
    def test_parse_json(self):
        from src.agent.loop import _parse_structured_output

        result = _parse_structured_output('{"severity_assessment": "high"}')
        assert result["severity_assessment"] == "high"

    def test_parse_json_in_code_fence(self):
        from src.agent.loop import _parse_structured_output

        text = 'Here is my analysis:\n```json\n{"severity_assessment": "critical"}\n```\nDone.'
        result = _parse_structured_output(text)
        assert result["severity_assessment"] == "critical"

    def test_parse_json_embedded_in_text(self):
        from src.agent.loop import _parse_structured_output

        text = 'Analysis complete. {"severity_assessment": "medium", "insights": ["test"]} End.'
        result = _parse_structured_output(text)
        assert result["severity_assessment"] == "medium"

    def test_parse_raw_text_fallback(self):
        from src.agent.loop import _parse_structured_output

        result = _parse_structured_output("No JSON here, just analysis text.")
        assert "raw_analysis" in result
        assert result["severity_assessment"] == "unknown"


class TestProviderAutoDetection:
    def test_no_keys_raises(self):
        from src.agent.providers import create_provider

        env = os.environ.copy()
        env.pop("ANTHROPIC_API_KEY", None)
        env.pop("OPENAI_API_KEY", None)

        # Temporarily clear env
        orig_anthropic = os.environ.pop("ANTHROPIC_API_KEY", None)
        orig_openai = os.environ.pop("OPENAI_API_KEY", None)

        # Also remove stored auth
        from src.agent.auth import AUTH_FILE

        auth_existed = AUTH_FILE.exists()
        if auth_existed:
            auth_backup = AUTH_FILE.read_text()
            AUTH_FILE.unlink()

        try:
            with pytest.raises(RuntimeError, match="No LLM"):
                create_provider()
        finally:
            if orig_anthropic:
                os.environ["ANTHROPIC_API_KEY"] = orig_anthropic
            if orig_openai:
                os.environ["OPENAI_API_KEY"] = orig_openai
            if auth_existed:
                AUTH_FILE.write_text(auth_backup)


class TestMCPConfig:
    def test_parse_cli_servers(self):
        from src.agent.config import _parse_cli_servers

        servers = _parse_cli_servers(
            [
                "vt:uvx virustotal-mcp-server",
                "shodan:uvx shodan-mcp --api-key test",
            ]
        )
        assert "vt" in servers
        assert servers["vt"].command == "uvx"
        assert servers["vt"].args == ["virustotal-mcp-server"]
        assert "shodan" in servers
        assert servers["shodan"].args == ["shodan-mcp", "--api-key", "test"]

    def test_parse_invalid_format(self):
        from src.agent.config import _parse_cli_servers

        servers = _parse_cli_servers(["no-colon-here"])
        assert len(servers) == 0

    def test_load_empty(self):
        from src.agent.config import load_mcp_config

        result = load_mcp_config(cli_add=None, cli_exclude=None)
        # Should not crash, returns list (may be empty or have config file entries)
        assert isinstance(result, list)
