import functools
import logging
import os
import time
from collections.abc import Callable
from typing import Any, TypeVar

from fastmcp import FastMCP
from mcp.types import TextContent

from src.utils import limit_response_size_if_needed

T = TypeVar("T")

# Get the tool logger
_tool_logger = logging.getLogger("crowdsentinel.tools")

# ANSI colour codes for direct terminal output
_CYAN = "\033[36m"
_GREEN = "\033[32m"
_RED = "\033[31m"
_RESET = "\033[0m"
_BOLD = "\033[1m"


def _direct_terminal_write(message: str, colour: str = "") -> None:
    """
    Write directly to the terminal, bypassing all Python I/O layers.

    Uses os.write() to file descriptor 1 (stdout) which cannot be
    intercepted by uvicorn or any other framework.
    """
    try:
        # Format with colour if provided
        if colour:
            formatted = f"{colour}{message}{_RESET}\n"
        else:
            formatted = f"{message}\n"

        # Write directly to stdout file descriptor (1)
        os.write(1, formatted.encode("utf-8"))
    except Exception:
        # Silently fail if writing isn't possible
        pass


def _truncate_value(value: Any, max_length: int = 100) -> str:
    """Truncate a value for logging display."""
    str_value = str(value)
    if len(str_value) > max_length:
        return str_value[:max_length] + "..."
    return str_value


def _format_params(kwargs: dict[str, Any]) -> str:
    """Format parameters for logging, truncating large values."""
    if not kwargs:
        return ""

    parts = []
    for key, value in kwargs.items():
        if isinstance(value, (list, dict)):
            parts.append(f"{key}={_truncate_value(value, 50)}")
        elif isinstance(value, str) and len(value) > 50:
            parts.append(f"{key}='{value[:50]}...'")
        else:
            parts.append(f"{key}={value}")
    return " | ".join(parts)


def _extract_result_summary(result: Any) -> str:
    """Extract a detailed summary from tool results for logging."""
    if not isinstance(result, dict):
        return f"type={type(result).__name__}"

    parts = []

    # Hit counts - most important
    if "total_hits" in result:
        parts.append(f"hits={result['total_hits']}")
    elif "hits_count" in result:
        parts.append(f"hits={result['hits_count']}")
    elif "summary" in result and isinstance(result["summary"], dict):
        summary = result["summary"]
        if "total_hits" in summary:
            parts.append(f"hits={summary['total_hits']}")

    # Response metadata
    if "response" in result and isinstance(result["response"], dict):
        resp = result["response"]
        if "hits" in resp and isinstance(resp["hits"], dict):
            total = resp["hits"].get("total", {})
            if isinstance(total, dict):
                parts.append(f"hits={total.get('value', '?')}")
            elif isinstance(total, int):
                parts.append(f"hits={total}")

    # Events
    if "events" in result and isinstance(result["events"], list):
        parts.append(f"events={len(result['events'])}")
    elif "sample_events" in result and isinstance(result["sample_events"], list):
        parts.append(f"samples={len(result['sample_events'])}")

    # IoCs extracted
    if "iocs" in result and isinstance(result["iocs"], dict):
        total_iocs = sum(len(v) for v in result["iocs"].values() if isinstance(v, list))
        if total_iocs > 0:
            parts.append(f"iocs={total_iocs}")

    # MITRE ATT&CK mappings
    if "mitre_techniques" in result and isinstance(result["mitre_techniques"], list):
        if result["mitre_techniques"]:
            parts.append(f"mitre={len(result['mitre_techniques'])}")

    # Rules
    if "rules" in result and isinstance(result["rules"], list):
        parts.append(f"rules={len(result['rules'])}")

    # Indices
    if "indices" in result and isinstance(result["indices"], list):
        parts.append(f"indices={len(result['indices'])}")

    # Aggregations
    if "aggregations" in result or ("response" in result and "aggregations" in result.get("response", {})):
        parts.append("has_aggs")

    # Error handling
    if "error" in result:
        parts.append(f"error={_truncate_value(result['error'], 30)}")

    # Severity
    if "severity" in result:
        parts.append(f"severity={result['severity']}")

    return " | ".join(parts) if parts else "ok"


def handle_search_exceptions(func: Callable[..., T]) -> Callable[..., list[TextContent]]:
    """
    Decorator to handle exceptions in search client operations.
    Also logs tool invocation, timing, and results.

    Args:
        func: The function to decorate

    Returns:
        Decorated function that handles exceptions and logs calls
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        tool_name = func.__name__
        start_time = time.time()

        # Log tool invocation
        params_str = _format_params(kwargs)
        call_msg = f">>> CALL: {tool_name} | {params_str}"

        # Log via Python logging (goes to file)
        _tool_logger.info(call_msg)

        # Direct write to terminal using os.write() - bypasses all redirection
        _direct_terminal_write(call_msg, _CYAN)

        try:
            result = func(*args, **kwargs)
            elapsed = time.time() - start_time

            # Log success with detailed summary
            summary = _extract_result_summary(result)
            done_msg = f"<<< DONE: {tool_name} | {elapsed:.2f}s | {summary}"

            _tool_logger.info(done_msg)
            _direct_terminal_write(done_msg, _GREEN)

            return result
        except Exception as e:
            elapsed = time.time() - start_time
            fail_msg = f"!!! FAIL: {tool_name} | {elapsed:.2f}s | {type(e).__name__}: {e}"

            _tool_logger.error(fail_msg)
            _direct_terminal_write(fail_msg, _RED)

            return [TextContent(type="text", text=f"Unexpected error in {tool_name}: {str(e)}")]

    return wrapper


def _is_text_content_list(value: object) -> bool:
    if not isinstance(value, list) or not value:
        return False
    return all(isinstance(item, TextContent) for item in value)


def _is_response_limited(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    metadata = value.get("metadata")
    return isinstance(metadata, dict) and "truncated" in metadata and "response" in value


def limit_tool_response(func: Callable[..., T]) -> Callable[..., T]:
    """
    Apply response size limiting only when outputs exceed the configured limits.
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)

        if _is_text_content_list(result) or _is_response_limited(result):
            return result

        return limit_response_size_if_needed(result)

    return wrapper


def with_exception_handling(tool_instance: object, mcp: FastMCP) -> None:
    """
    Register tools from a tool instance with automatic exception handling applied to all tools.

    This function temporarily replaces mcp.tool with a wrapped version that automatically
    applies the handle_search_exceptions decorator to all registered tool methods.

    Args:
        tool_instance: The tool instance that has a register_tools method
        mcp: The FastMCP instance used for tool registration
    """
    # Save the original tool method
    original_tool = mcp.tool

    @functools.wraps(original_tool)
    def wrapped_tool(*args, **kwargs):
        # Get the original decorator
        decorator = original_tool(*args, **kwargs)

        # Return a new decorator that applies both the exception handler and original decorator
        def combined_decorator(func):
            # First apply response limiting, then exception handling
            wrapped_func = limit_tool_response(func)
            wrapped_func = handle_search_exceptions(wrapped_func)
            # Then apply the original mcp.tool decorator
            return decorator(wrapped_func)

        return combined_decorator

    try:
        # Temporarily replace mcp.tool with our wrapped version
        mcp.tool = wrapped_tool

        # Call the registration method on the tool instance
        tool_instance.register_tools(mcp)
    finally:
        # Restore the original mcp.tool to avoid affecting other code that might use mcp.tool
        # This ensures that our modification is isolated to just this tool registration
        # and prevents multiple nested decorators if register_all_tools is called multiple times
        mcp.tool = original_tool
