"""
Logging configuration for CrowdSentinel MCP Server.

Provides comprehensive logging with:
- Coloured output for terminal visibility
- File output for debugging (always viewable)
- Tool invocation logging with result summaries
- Works in both stdio and HTTP transport modes
"""

import functools
import logging
import os
import sys
import tempfile
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO

# Default log file location
DEFAULT_LOG_DIR = Path(tempfile.gettempdir()) / "crowdsentinel"
DEFAULT_LOG_FILE = DEFAULT_LOG_DIR / "mcp-server.log"

# Environment variable to override log location
LOG_FILE_ENV = "CROWDSENTINEL_LOG_FILE"
LOG_LEVEL_ENV = "CROWDSENTINEL_LOG_LEVEL"
LOG_TO_TTY_ENV = "CROWDSENTINEL_LOG_TO_TTY"  # Set to "false" to disable TTY logging


# ANSI Colour codes for terminal output
class Colours:
    """ANSI colour codes for terminal output."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Foreground colours
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Bright foreground colours
    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

    # Background colours
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"


def get_log_file_path() -> Path:
    """Get the log file path from environment or default."""
    env_path = os.environ.get(LOG_FILE_ENV)
    if env_path:
        return Path(env_path)
    return DEFAULT_LOG_FILE


def get_log_level() -> int:
    """Get log level from environment or default to INFO."""
    level_str = os.environ.get(LOG_LEVEL_ENV, "INFO").upper()
    return getattr(logging, level_str, logging.INFO)


def _get_tty_stream() -> TextIO | None:
    """
    Get a direct handle to the controlling terminal (TTY).

    This bypasses stdout/stderr capture by MCP clients, allowing logs
    to appear directly in the terminal where the server was started.

    Returns:
        File handle to /dev/tty if available, None otherwise.
    """
    # Check if TTY logging is disabled
    if os.environ.get(LOG_TO_TTY_ENV, "").lower() == "false":
        return None

    try:
        # /dev/tty is the controlling terminal - writes here go directly
        # to the terminal, bypassing any stdout/stderr redirection
        tty = open("/dev/tty", "w")
        return tty
    except OSError:
        # No controlling terminal (e.g., running in background, Docker, etc.)
        return None


class ColouredFormatter(logging.Formatter):
    """
    Custom formatter that adds colours to log messages.

    Different colours for:
    - Tool calls (cyan)
    - Tool results (green)
    - Errors (red)
    - Timestamps (dim)
    """

    def __init__(self, use_colours: bool = True):
        super().__init__()
        self.use_colours = use_colours

    def format(self, record: logging.LogRecord) -> str:
        # Get the timestamp
        timestamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")

        # Get the message
        message = record.getMessage()

        if not self.use_colours:
            return f"{timestamp} | {record.levelname:<8} | {message}"

        # Colour the timestamp (dim)
        coloured_time = f"{Colours.DIM}{timestamp}{Colours.RESET}"

        # Colour based on message type and level
        if record.levelno >= logging.ERROR:
            # Errors in red
            coloured_level = f"{Colours.BRIGHT_RED}{record.levelname:<8}{Colours.RESET}"
            coloured_msg = f"{Colours.RED}{message}{Colours.RESET}"
        elif record.levelno >= logging.WARNING:
            # Warnings in yellow
            coloured_level = f"{Colours.BRIGHT_YELLOW}{record.levelname:<8}{Colours.RESET}"
            coloured_msg = f"{Colours.YELLOW}{message}{Colours.RESET}"
        elif ">>> CALL:" in message or "TOOL CALL:" in message:
            # Tool calls in cyan with bold arrow
            coloured_level = f"{Colours.BRIGHT_CYAN}{record.levelname:<8}{Colours.RESET}"
            # Highlight the tool name
            if ">>> CALL:" in message:
                parts = message.split(">>> CALL:", 1)
                if len(parts) > 1:
                    tool_info = parts[1].strip()
                    coloured_msg = f"{Colours.BOLD}{Colours.CYAN}>>> CALL:{Colours.RESET} {Colours.BRIGHT_CYAN}{tool_info}{Colours.RESET}"
                else:
                    coloured_msg = f"{Colours.CYAN}{message}{Colours.RESET}"
            else:
                coloured_msg = f"{Colours.CYAN}{message}{Colours.RESET}"
        elif "<<< DONE:" in message or "TOOL DONE:" in message:
            # Tool results in green
            coloured_level = f"{Colours.BRIGHT_GREEN}{record.levelname:<8}{Colours.RESET}"
            if "<<< DONE:" in message:
                parts = message.split("<<< DONE:", 1)
                if len(parts) > 1:
                    tool_info = parts[1].strip()
                    coloured_msg = f"{Colours.BOLD}{Colours.GREEN}<<< DONE:{Colours.RESET} {Colours.BRIGHT_GREEN}{tool_info}{Colours.RESET}"
                else:
                    coloured_msg = f"{Colours.GREEN}{message}{Colours.RESET}"
            else:
                coloured_msg = f"{Colours.GREEN}{message}{Colours.RESET}"
        elif "!!! FAIL:" in message or "TOOL FAIL:" in message:
            # Tool failures in bright red
            coloured_level = f"{Colours.BRIGHT_RED}{record.levelname:<8}{Colours.RESET}"
            coloured_msg = f"{Colours.BOLD}{Colours.RED}{message}{Colours.RESET}"
        elif "hits=" in message or "events=" in message or "iocs=" in message:
            # Result summaries in bright green
            coloured_level = f"{Colours.GREEN}{record.levelname:<8}{Colours.RESET}"
            coloured_msg = f"{Colours.BRIGHT_GREEN}{message}{Colours.RESET}"
        else:
            # Default: white/normal
            coloured_level = f"{Colours.WHITE}{record.levelname:<8}{Colours.RESET}"
            coloured_msg = message

        return f"{coloured_time} | {coloured_level} | {coloured_msg}"


class TTYHandler(logging.StreamHandler):
    """
    Logging handler that writes directly to the controlling terminal.

    This bypasses MCP's stdio capture, so logs appear in the terminal
    where `uv run crowdsentinel-mcp-server` was executed.

    This handler is resilient to stream closure - if the TTY becomes
    unavailable (e.g., in async contexts), it silently ignores write errors.
    """

    def __init__(self, tty_stream: TextIO):
        super().__init__(tty_stream)
        self._tty = tty_stream
        self._closed = False

    def emit(self, record: logging.LogRecord):
        """
        Emit a record, silently handling closed stream errors.

        In async HTTP mode, the TTY stream may become unavailable.
        Rather than crash, we silently skip the log message.
        """
        if self._closed:
            return

        try:
            # Check if stream is still valid before writing
            if self._tty and not self._tty.closed:
                super().emit(record)
            else:
                self._closed = True
        except (ValueError, OSError):
            # Stream closed or unavailable - mark as closed and continue
            self._closed = True
        except Exception:
            # Any other error - don't crash the application
            self._closed = True

    def close(self):
        """Close the TTY handle."""
        self._closed = True
        try:
            if self._tty and not self._tty.closed:
                self._tty.close()
        except Exception:
            pass
        super().close()


class StderrHandler(logging.StreamHandler):
    """
    Logging handler that writes to stderr with immediate flushing.

    Used in HTTP mode where TTY is not available. Forces immediate
    flush to ensure logs appear in real-time alongside uvicorn output.
    """

    def __init__(self):
        # Use stdout for HTTP mode - uvicorn passes stdout through
        # while stderr may be redirected
        super().__init__(sys.stdout)

    def emit(self, record: logging.LogRecord):
        """Emit a record and immediately flush."""
        try:
            super().emit(record)
            self.flush()
        except (ValueError, OSError):
            # Stream closed or unavailable
            pass
        except Exception:
            # Any other error - don't crash
            pass


class DirectStdoutHandler(logging.Handler):
    """
    Logging handler that writes directly to file descriptor 1 (stdout).

    Uses os.write() to bypass ALL Python I/O layers and framework
    redirection. This works reliably in uvicorn's async context where
    sys.stdout and sys.__stdout__ may be captured.
    """

    def __init__(self):
        super().__init__()
        # Import os here to ensure it's available
        import os

        self._os = os

    def emit(self, record: logging.LogRecord):
        """Emit a record directly to stdout file descriptor."""
        try:
            msg = self.format(record)
            # Write directly to file descriptor 1 (stdout)
            # This cannot be intercepted by any Python framework
            self._os.write(1, (msg + "\n").encode("utf-8"))
        except Exception:
            # Don't crash on logging errors
            pass


def configure_logging(name: str = "crowdsentinel") -> logging.Logger:
    """
    Configure comprehensive logging for the MCP server.

    Logs are written to:
    1. TTY/stderr: Direct terminal output with colours
    2. File: <tmpdir>/crowdsentinel/mcp-server.log (always available)

    Args:
        name: Logger name (default: crowdsentinel)

    Returns:
        Configured logger instance

    Environment Variables:
        CROWDSENTINEL_LOG_FILE: Override log file path
        CROWDSENTINEL_LOG_LEVEL: Set log level (DEBUG, INFO, WARNING, ERROR)
        CROWDSENTINEL_LOG_TO_TTY: Set to "false" to disable terminal logging
    """
    log_file = get_log_file_path()
    log_level = get_log_level()

    # Ensure log directory exists
    log_file.parent.mkdir(parents=True, exist_ok=True)

    # Create formatters
    # File formatter - detailed without colours
    file_formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Coloured formatter for terminal
    coloured_formatter = ColouredFormatter(use_colours=True)

    # Plain formatter for terminal (no colours)
    plain_formatter = ColouredFormatter(use_colours=False)

    # Get root logger for the application
    root_logger = logging.getLogger(name)
    root_logger.setLevel(log_level)

    # Remove existing handlers to avoid duplicates
    root_logger.handlers.clear()

    # Ensure this logger doesn't propagate to Python's root logger
    # but child loggers (like crowdsentinel.tools) WILL propagate to us
    root_logger.propagate = False

    # Pre-create tool logger to ensure it inherits our settings
    # This ensures tool logging works even if exceptions.py is imported first
    tool_logger = logging.getLogger(f"{name}.tools")
    tool_logger.setLevel(log_level)
    # Don't add handlers to child - let it propagate to parent

    # File handler - always write to file for debugging
    file_handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)  # Capture everything in file
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)

    # Terminal handler - try TTY first, fall back to direct stdout for HTTP mode
    tty_stream = _get_tty_stream()
    if tty_stream:
        tty_handler = TTYHandler(tty_stream)
        tty_handler.setLevel(log_level)
        tty_handler.setFormatter(coloured_formatter)
        root_logger.addHandler(tty_handler)
        root_logger.info(f"Logging to terminal (TTY) and file: {log_file}")
    else:
        # Fall back to direct stdout for HTTP mode - bypasses any redirection
        stdout_handler = DirectStdoutHandler()
        stdout_handler.setLevel(log_level)
        stdout_handler.setFormatter(coloured_formatter)
        root_logger.addHandler(stdout_handler)
        root_logger.info(f"Logging to stdout and file: {log_file}")
        root_logger.info("Tool calls will appear here in real-time")

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a child logger under the crowdsentinel namespace.

    Args:
        name: Logger name (will be prefixed with 'crowdsentinel.')

    Returns:
        Logger instance
    """
    return logging.getLogger(f"crowdsentinel.{name}")


def truncate_value(value: Any, max_length: int = 200) -> str:
    """Truncate a value for logging display."""
    str_value = str(value)
    if len(str_value) > max_length:
        return str_value[:max_length] + "..."
    return str_value


def format_params_for_log(params: dict[str, Any]) -> str:
    """Format parameters for logging, truncating large values."""
    formatted = {}
    for key, value in params.items():
        if isinstance(value, (list, dict)):
            formatted[key] = truncate_value(value, 100)
        elif isinstance(value, str) and len(value) > 100:
            formatted[key] = value[:100] + "..."
        else:
            formatted[key] = value
    return str(formatted)


def log_tool_call(logger: logging.Logger):
    """
    Decorator to log MCP tool invocations.

    Logs:
    - Tool name and parameters
    - Execution time
    - Result summary (hit count, error status)

    Usage:
        @log_tool_call(logger)
        def my_tool(param1: str, param2: int) -> Dict:
            ...
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            tool_name = func.__name__
            start_time = time.time()

            # Log invocation
            params_str = format_params_for_log(kwargs) if kwargs else "(no params)"
            logger.info(f"TOOL CALL: {tool_name} | Params: {params_str}")

            try:
                result = func(*args, **kwargs)
                elapsed = time.time() - start_time

                # Extract summary from result
                summary = _extract_result_summary(result)
                logger.info(f"TOOL DONE: {tool_name} | {elapsed:.2f}s | {summary}")

                return result

            except Exception as e:
                elapsed = time.time() - start_time
                logger.error(f"TOOL FAIL: {tool_name} | {elapsed:.2f}s | Error: {e}")
                raise

        return wrapper

    return decorator


def _extract_result_summary(result: Any) -> str:
    """Extract a summary from tool results for logging."""
    if not isinstance(result, dict):
        return f"type={type(result).__name__}"

    parts = []

    # Common result fields
    if "total_hits" in result:
        parts.append(f"hits={result['total_hits']}")
    elif "hits_count" in result:
        parts.append(f"hits={result['hits_count']}")

    if "error" in result:
        parts.append(f"error={truncate_value(result['error'], 50)}")

    if "iocs" in result and isinstance(result["iocs"], dict):
        total_iocs = sum(len(v) for v in result["iocs"].values() if isinstance(v, list))
        parts.append(f"iocs={total_iocs}")

    if "events" in result and isinstance(result["events"], list):
        parts.append(f"events={len(result['events'])}")

    if "mitre_techniques" in result and isinstance(result["mitre_techniques"], list):
        parts.append(f"mitre={len(result['mitre_techniques'])}")

    if "severity" in result:
        parts.append(f"severity={result['severity']}")

    return " | ".join(parts) if parts else "ok"


def log_query(logger: logging.Logger, query_type: str, index: str, query: str, timeframe: int | None = None):
    """
    Log an Elasticsearch query execution.

    Args:
        logger: Logger instance
        query_type: Type of query (lucene, eql, esql)
        index: Index pattern
        query: Query string (will be truncated)
        timeframe: Optional timeframe in minutes
    """
    time_str = f" | timeframe={timeframe}m" if timeframe else ""
    query_preview = truncate_value(query, 150)
    logger.debug(f"QUERY: {query_type} | index={index}{time_str} | {query_preview}")


def log_es_response(logger: logging.Logger, took_ms: int, hits: int, timed_out: bool = False):
    """
    Log Elasticsearch response summary.

    Args:
        logger: Logger instance
        took_ms: Query execution time in ms
        hits: Number of hits
        timed_out: Whether query timed out
    """
    status = "TIMEOUT" if timed_out else "ok"
    logger.debug(f"ES RESPONSE: {took_ms}ms | hits={hits} | {status}")


class ToolLogger:
    """
    Helper class for logging within tools.

    Usage:
        tool_logger = ToolLogger("threat_hunting")
        tool_logger.tool_start("hunt_by_timeframe", index="winlogbeat-*")
        tool_logger.query("lucene", "event.code:4625", "winlogbeat-*")
        tool_logger.tool_end(hits=42)
    """

    def __init__(self, tool_category: str):
        self.logger = get_logger(f"tools.{tool_category}")
        self._current_tool: str | None = None
        self._start_time: float | None = None

    def tool_start(self, tool_name: str, **params):
        """Log tool invocation start."""
        self._current_tool = tool_name
        self._start_time = time.time()
        params_str = format_params_for_log(params)
        self.logger.info(f">>> {tool_name} | {params_str}")

    def query(self, query_type: str, query: str, index: str, timeframe: int | None = None):
        """Log a query being executed."""
        log_query(self.logger, query_type, index, query, timeframe)

    def tool_end(self, **summary):
        """Log tool completion."""
        elapsed = time.time() - self._start_time if self._start_time else 0
        summary_str = " | ".join(f"{k}={v}" for k, v in summary.items())
        self.logger.info(f"<<< {self._current_tool} | {elapsed:.2f}s | {summary_str}")
        self._current_tool = None
        self._start_time = None

    def error(self, message: str, exc: Exception | None = None):
        """Log an error."""
        if exc:
            self.logger.error(f"!!! {self._current_tool} | {message}: {exc}")
        else:
            self.logger.error(f"!!! {self._current_tool} | {message}")


# Convenience function to view logs
def get_log_tail_command() -> str:
    """Get the command to tail the log file."""
    log_file = get_log_file_path()
    return f"tail -f {log_file}"
