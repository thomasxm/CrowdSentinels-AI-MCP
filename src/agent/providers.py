"""LLM provider abstraction for agent tool-use loops.

Supports Anthropic (native) and OpenAI-compatible endpoints (GPT, Ollama, vLLM, etc.).
Provider is auto-detected from environment variables or explicitly set via CLI flags.
"""

import json
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("crowdsentinel.agent.providers")


@dataclass
class ToolCall:
    """A tool call extracted from an LLM response."""
    id: str
    name: str
    arguments: Dict[str, Any]


@dataclass
class LLMResponse:
    """Normalised response from any LLM provider."""
    text: str = ""
    tool_calls: List[ToolCall] = field(default_factory=list)
    stop_reason: str = ""
    usage: Dict[str, int] = field(default_factory=dict)

    @property
    def is_done(self) -> bool:
        return len(self.tool_calls) == 0


class LLMProvider(ABC):
    """Abstract base for LLM providers that support tool use."""

    def __init__(self, model: str):
        self.model = model

    @abstractmethod
    def create_message(
        self,
        system: str,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        max_tokens: int = 8192,
    ) -> LLMResponse:
        """Send a message with tool definitions and return a normalised response."""

    @abstractmethod
    def convert_tool_schema(self, mcp_tool: Dict[str, Any]) -> Dict[str, Any]:
        """Convert an MCP tool schema to the provider's native format."""


class AnthropicProvider(LLMProvider):
    """Anthropic Claude provider using the official SDK."""

    def __init__(self, model: str, api_key: Optional[str] = None):
        super().__init__(model)
        import anthropic
        self.client = anthropic.Anthropic(api_key=api_key or os.environ["ANTHROPIC_API_KEY"])

    def convert_tool_schema(self, mcp_tool: Dict[str, Any]) -> Dict[str, Any]:
        """MCP tool → Anthropic tool format (nearly 1:1)."""
        input_schema = mcp_tool.get("inputSchema", mcp_tool.get("parameters", {}))
        return {
            "name": mcp_tool["name"],
            "description": mcp_tool.get("description", ""),
            "input_schema": input_schema,
        }

    def create_message(
        self,
        system: str,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        max_tokens: int = 8192,
    ) -> LLMResponse:
        kwargs = {
            "model": self.model,
            "system": system,
            "messages": messages,
            "max_tokens": max_tokens,
        }
        if tools:
            kwargs["tools"] = tools

        response = self.client.messages.create(**kwargs)

        text_parts = []
        tool_calls = []

        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_calls.append(ToolCall(
                    id=block.id,
                    name=block.name,
                    arguments=block.input,
                ))

        return LLMResponse(
            text="\n".join(text_parts),
            tool_calls=tool_calls,
            stop_reason=response.stop_reason,
            usage={
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            },
        )


class OpenAICompatibleProvider(LLMProvider):
    """Provider for OpenAI-compatible APIs (OpenAI, Ollama, vLLM, LM Studio)."""

    def __init__(self, model: str, api_key: Optional[str] = None, base_url: Optional[str] = None):
        super().__init__(model)
        import httpx
        self.base_url = (base_url or os.environ.get("CROWDSENTINEL_MODEL_URL", "https://api.openai.com/v1")).rstrip("/")
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.http = httpx.Client(timeout=300)

    def convert_tool_schema(self, mcp_tool: Dict[str, Any]) -> Dict[str, Any]:
        """MCP tool → OpenAI function-calling format."""
        input_schema = mcp_tool.get("inputSchema", mcp_tool.get("parameters", {}))
        return {
            "type": "function",
            "function": {
                "name": mcp_tool["name"],
                "description": mcp_tool.get("description", ""),
                "parameters": input_schema,
            },
        }

    def create_message(
        self,
        system: str,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        max_tokens: int = 8192,
    ) -> LLMResponse:
        # Build OpenAI-format messages with system as first message
        oai_messages = [{"role": "system", "content": system}]

        for msg in messages:
            role = msg["role"]
            content = msg["content"]

            if role == "assistant" and isinstance(content, list):
                # Convert Anthropic-style content blocks to OpenAI format
                text_parts = []
                oai_tool_calls = []
                for block in content:
                    if hasattr(block, "type"):
                        if block.type == "text":
                            text_parts.append(block.text)
                        elif block.type == "tool_use":
                            oai_tool_calls.append({
                                "id": block.id,
                                "type": "function",
                                "function": {
                                    "name": block.name,
                                    "arguments": json.dumps(block.input),
                                },
                            })
                    elif isinstance(block, dict):
                        if block.get("type") == "text":
                            text_parts.append(block.get("text", ""))
                        elif block.get("type") == "tool_use":
                            oai_tool_calls.append({
                                "id": block["id"],
                                "type": "function",
                                "function": {
                                    "name": block["name"],
                                    "arguments": json.dumps(block.get("input", {})),
                                },
                            })

                oai_msg = {"role": "assistant", "content": "\n".join(text_parts) or None}
                if oai_tool_calls:
                    oai_msg["tool_calls"] = oai_tool_calls
                oai_messages.append(oai_msg)

            elif role == "user" and isinstance(content, list):
                # Tool results
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "tool_result":
                        result_content = block.get("content", "")
                        if isinstance(result_content, list):
                            result_content = "\n".join(
                                b.get("text", "") for b in result_content if isinstance(b, dict)
                            )
                        oai_messages.append({
                            "role": "tool",
                            "tool_call_id": block.get("tool_use_id", ""),
                            "content": str(result_content),
                        })
            else:
                oai_messages.append({"role": role, "content": str(content) if content else ""})

        body = {
            "model": self.model,
            "messages": oai_messages,
            "max_tokens": max_tokens,
        }
        if tools:
            body["tools"] = tools

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        resp = self.http.post(
            f"{self.base_url}/chat/completions",
            json=body,
            headers=headers,
        )
        resp.raise_for_status()
        data = resp.json()

        choice = data["choices"][0]
        message = choice["message"]

        tool_calls = []
        for tc in message.get("tool_calls", []):
            func = tc["function"]
            try:
                args = json.loads(func["arguments"])
            except (json.JSONDecodeError, TypeError):
                args = {}
            tool_calls.append(ToolCall(
                id=tc["id"],
                name=func["name"],
                arguments=args,
            ))

        usage = data.get("usage", {})

        return LLMResponse(
            text=message.get("content", "") or "",
            tool_calls=tool_calls,
            stop_reason=choice.get("finish_reason", "stop"),
            usage={
                "input_tokens": usage.get("prompt_tokens", 0),
                "output_tokens": usage.get("completion_tokens", 0),
            },
        )


def create_provider(
    model: Optional[str] = None,
    model_url: Optional[str] = None,
) -> LLMProvider:
    """Create an LLM provider from environment variables and CLI overrides.

    Auto-detection order:
        1. If model_url is set → OpenAI-compatible (custom endpoint)
        2. If ANTHROPIC_API_KEY is set → Anthropic
        3. If OPENAI_API_KEY is set → OpenAI-compatible
        4. Error with instructions
    """
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    openai_key = os.environ.get("OPENAI_API_KEY")

    # Explicit model_url → OpenAI-compatible
    if model_url:
        return OpenAICompatibleProvider(
            model=model or os.environ.get("CROWDSENTINEL_MODEL", "gpt-4o"),
            base_url=model_url,
            api_key=openai_key,
        )

    # Anthropic
    if anthropic_key:
        return AnthropicProvider(
            model=model or os.environ.get("CROWDSENTINEL_MODEL", "claude-sonnet-4-20250514"),
            api_key=anthropic_key,
        )

    # OpenAI
    if openai_key:
        return OpenAICompatibleProvider(
            model=model or os.environ.get("CROWDSENTINEL_MODEL", "gpt-4o"),
            api_key=openai_key,
        )

    raise RuntimeError(
        "No LLM API key configured for agent mode.\n"
        "\n"
        "Set one of the following:\n"
        '  export ANTHROPIC_API_KEY="sk-ant-..."    # Claude (recommended)\n'
        '  export OPENAI_API_KEY="sk-..."           # GPT / OpenAI-compatible\n'
        "\n"
        "For local models (Ollama, vLLM, LM Studio):\n"
        '  export OPENAI_API_KEY="dummy"\n'
        "  crowdsentinel analyse --mcp --model-url http://localhost:11434/v1 --model llama3.1\n"
    )
