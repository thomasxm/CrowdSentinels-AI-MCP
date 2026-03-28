"""ES|QL Query Client for Elasticsearch 8.11+."""

import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from src.clients.base import SearchClientBase
from src.clients.common.field_mapper import FieldMapper

logger = logging.getLogger(__name__)


class ESQLNotSupportedError(Exception):
    """Raised when Elasticsearch version does not support ES|QL (requires 8.11+)."""


@dataclass
class QueryExecution:
    """Tracks token usage and execution metrics for a query."""

    rule_id: str
    query: str
    result_tokens: int
    hits_count: int
    execution_time_ms: int
    timestamp: datetime


class ESQLClient(SearchClientBase):
    """Client for executing ES|QL queries with version checking and lean mode support."""

    # Minimum ES version for ES|QL support
    MIN_MAJOR_VERSION = 8
    MIN_MINOR_VERSION = 11

    # Common field patterns for security data
    SECURITY_FIELD_PATTERNS = {
        "process": ["process.name", "process.executable", "process.command_line", "process.args"],
        "user": ["user.name", "user.id", "user.domain"],
        "host": ["host.name", "host.hostname", "host.ip"],
        "event": ["event.code", "event.action", "event.category", "event.type"],
        "file": ["file.path", "file.name", "file.hash"],
        "network": ["destination.ip", "source.ip", "destination.port"],
        "registry": ["registry.path", "registry.key", "registry.value"],
    }

    # Winlogbeat field mappings (common alternative field names)
    FIELD_ALIASES = {
        "process.name": ["winlog.event_data.Image", "process.executable"],
        "process.command_line": ["winlog.event_data.CommandLine", "process.args"],
        "process.parent.name": ["winlog.event_data.ParentImage"],
        "user.name": ["winlog.event_data.User", "winlog.event_data.TargetUserName"],
        "host.name": ["host.hostname", "agent.hostname"],
        "file.path": ["winlog.event_data.TargetFilename", "file.target.path"],
        "registry.path": ["winlog.event_data.TargetObject"],
        "destination.ip": ["winlog.event_data.DestinationIp"],
        "source.ip": ["winlog.event_data.SourceIp"],
    }

    def __init__(self, config: dict, engine_type: str = "elasticsearch"):
        """
        Initialize the ES|QL client.

        Args:
            config: Configuration dictionary with connection parameters
            engine_type: Must be "elasticsearch" (ES|QL not available in OpenSearch)
        """
        if engine_type != "elasticsearch":
            raise ESQLNotSupportedError("ES|QL is only available in Elasticsearch, not OpenSearch")

        super().__init__(config, engine_type)
        self._version_checked = False
        self._esql_supported = False
        self._es_version = None
        self._execution_history: list[QueryExecution] = []
        self._index_cache: dict[str, list[str]] = {}  # Cache discovered indices

        # Initialise FieldMapper for field name substitution
        # Client reference set after connection is established
        self._field_mapper: FieldMapper | None = None

    @property
    def field_mapper(self) -> FieldMapper:
        """Get or create the FieldMapper instance with ES client reference."""
        if self._field_mapper is None:
            self._field_mapper = FieldMapper(client=self.client)
        return self._field_mapper

    def check_version(self) -> None:
        """
        Check if Elasticsearch version supports ES|QL (8.11+).

        Raises:
            ESQLNotSupportedError: If ES version is below 8.11
        """
        if self._version_checked:
            return

        try:
            info = self.client.info()
            version_str = info["version"]["number"]
            self._es_version = version_str

            # Parse version (e.g., "8.15.0" -> (8, 15))
            parts = version_str.split(".")
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0

            if major < self.MIN_MAJOR_VERSION or (major == self.MIN_MAJOR_VERSION and minor < self.MIN_MINOR_VERSION):
                raise ESQLNotSupportedError(
                    f"ES|QL requires Elasticsearch {self.MIN_MAJOR_VERSION}.{self.MIN_MINOR_VERSION}+. "
                    f"Current version: {version_str}"
                )

            self._esql_supported = True
            self._version_checked = True
            logger.info(f"ES|QL support confirmed for Elasticsearch {version_str}")

        except ESQLNotSupportedError:
            raise
        except Exception as e:
            raise ESQLNotSupportedError(f"Failed to check Elasticsearch version: {str(e)}")

    # =========================================================================
    # Adaptive Index Resolution
    # =========================================================================

    def extract_index_from_query(self, query: str) -> str | None:
        """
        Extract the index pattern from ES|QL FROM clause.

        Args:
            query: ES|QL query string

        Returns:
            Index pattern or None if not found

        Examples:
            "FROM logs-endpoint.events.process-*" -> "logs-endpoint.events.process-*"
            "from winlogbeat-* | WHERE..." -> "winlogbeat-*"
            "from idx1, idx2, idx3 | WHERE..." -> "idx1, idx2, idx3"
        """
        # Match FROM clause - capture everything until pipe, METADATA keyword, or newline
        # This handles multi-index patterns like "idx1, idx2, idx3"
        pattern = r"(?i)^\s*FROM\s+([^|\n]+?)(?:\s*(?:\||METADATA\s|$))"
        match = re.search(pattern, query.strip())
        if match:
            return match.group(1).strip().rstrip(",")
        return None

    def extract_fields_from_query(self, query: str) -> list[str]:
        """
        Extract field names referenced in an ES|QL query.

        Args:
            query: ES|QL query string

        Returns:
            List of field names found in the query
        """
        fields = set()

        # Common ES|QL patterns that reference fields
        # field.name == "value", field.name != "value"
        # BY field.name, field.name ASC/DESC
        # WHERE field.name LIKE/IN/IS
        # STATS ... BY field.name

        # Pattern for dotted field names (e.g., process.name, winlog.event_data.Image)
        field_pattern = r"\b([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)+)\b"

        # Exclude common ES|QL functions and keywords
        exclude_patterns = {
            "now.day",
            "now.hour",
            "count.by",
            "stats.by",
            "to.lower",
            "to.upper",
            "to.string",
            "to.int",
        }

        for match in re.finditer(field_pattern, query):
            field = match.group(1)
            # Skip if it looks like a function call or keyword
            if field.lower() not in exclude_patterns and not field.startswith("logs."):
                fields.add(field)

        return list(fields)

    def discover_compatible_indices(
        self, required_fields: list[str], data_type: str | None = None
    ) -> list[dict[str, Any]]:
        """
        Find indices and data streams that contain the required fields.

        Args:
            required_fields: List of field names the query needs
            data_type: Optional hint (windows, linux, network, etc.)

        Returns:
            List of compatible indices/data streams with match scores
        """
        compatible = []

        try:
            # Get regular indices
            indices = self.client.cat.indices(format="json", h="index,docs.count")

            for idx_info in indices:
                index_name = idx_info.get("index", "")
                doc_count = int(idx_info.get("docs.count", 0) or 0)

                # Skip system indices and empty indices
                if index_name.startswith(".") or doc_count == 0:
                    continue

                # Check if this index has the required fields
                try:
                    mapping = self.client.indices.get_mapping(index=index_name)
                    if index_name in mapping:
                        properties = self._extract_properties(mapping[index_name])
                        match_score = self._calculate_field_match_score(required_fields, properties)

                        if match_score > 0:
                            compatible.append(
                                {
                                    "index": index_name,
                                    "doc_count": doc_count,
                                    "match_score": match_score,
                                    "matched_fields": match_score,
                                    "total_fields": len(required_fields),
                                    "type": "index",
                                }
                            )
                except Exception:
                    continue

        except Exception as e:
            logger.warning(f"Failed to discover indices: {e}")

        try:
            # Also check data streams (like winlogbeat-*, filebeat-*, etc.)
            data_streams = self.client.indices.get_data_stream(name="*")

            for ds in data_streams.get("data_streams", []):
                ds_name = ds.get("name", "")

                # Skip system data streams
                if ds_name.startswith("."):
                    continue

                # Get the write index to check mapping
                backing_indices = ds.get("indices", [])
                if not backing_indices:
                    continue

                write_index = backing_indices[-1].get("index_name", "")

                try:
                    # Get doc count from backing indices
                    total_docs = 0
                    for bi in backing_indices:
                        bi_name = bi.get("index_name", "")
                        try:
                            stats = self.client.indices.stats(index=bi_name)
                            total_docs += stats.get("_all", {}).get("primaries", {}).get("docs", {}).get("count", 0)
                        except Exception:
                            pass

                    if total_docs == 0:
                        continue

                    # Check mapping from write index
                    mapping = self.client.indices.get_mapping(index=write_index)
                    if write_index in mapping:
                        properties = self._extract_properties(mapping[write_index])
                        match_score = self._calculate_field_match_score(required_fields, properties)

                        if match_score > 0:
                            compatible.append(
                                {
                                    "index": ds_name,  # Use data stream name for queries
                                    "doc_count": total_docs,
                                    "match_score": match_score,
                                    "matched_fields": match_score,
                                    "total_fields": len(required_fields),
                                    "type": "data_stream",
                                }
                            )
                except Exception:
                    continue

        except Exception as e:
            logger.warning(f"Failed to discover data streams: {e}")

        try:
            # Also check aliases (common in production environments)
            aliases = self.client.cat.aliases(format="json", h="alias,index")

            # Group by alias name
            alias_indices = {}
            for alias_info in aliases:
                alias_name = alias_info.get("alias", "")
                index_name = alias_info.get("index", "")

                # Skip system aliases
                if alias_name.startswith("."):
                    continue

                if alias_name not in alias_indices:
                    alias_indices[alias_name] = []
                alias_indices[alias_name].append(index_name)

            for alias_name, indices_list in alias_indices.items():
                # Skip if we already have this alias as an index or data stream
                if any(c["index"] == alias_name for c in compatible):
                    continue

                try:
                    # Get doc count from first index
                    sample_index = indices_list[0]
                    total_docs = 0

                    for idx in indices_list:
                        try:
                            stats = self.client.indices.stats(index=idx)
                            total_docs += stats.get("_all", {}).get("primaries", {}).get("docs", {}).get("count", 0)
                        except Exception:
                            pass

                    if total_docs == 0:
                        continue

                    # Check mapping from first index
                    mapping = self.client.indices.get_mapping(index=sample_index)
                    if sample_index in mapping:
                        properties = self._extract_properties(mapping[sample_index])
                        match_score = self._calculate_field_match_score(required_fields, properties)

                        if match_score > 0:
                            compatible.append(
                                {
                                    "index": alias_name,  # Use alias name for queries
                                    "doc_count": total_docs,
                                    "match_score": match_score,
                                    "matched_fields": match_score,
                                    "total_fields": len(required_fields),
                                    "type": "alias",
                                    "backing_indices": len(indices_list),
                                }
                            )
                except Exception:
                    continue

        except Exception as e:
            logger.warning(f"Failed to discover aliases: {e}")

        # Sort by match score (descending) then doc count (descending)
        compatible.sort(key=lambda x: (-x["match_score"], -x["doc_count"]))

        return compatible

    def _extract_properties(self, mapping: dict) -> set:
        """Extract all field names from an index mapping."""
        properties = set()

        def extract_recursive(obj: dict, prefix: str = ""):
            if "properties" in obj:
                for field_name, field_def in obj["properties"].items():
                    full_name = f"{prefix}{field_name}" if prefix else field_name
                    properties.add(full_name)
                    if isinstance(field_def, dict):
                        extract_recursive(field_def, f"{full_name}.")

        if "mappings" in mapping:
            extract_recursive(mapping["mappings"])
        else:
            extract_recursive(mapping)

        return properties

    def _calculate_field_match_score(self, required_fields: list[str], available_fields: set) -> int:
        """
        Calculate how many required fields are available in the index.

        Also checks field aliases for compatibility.
        """
        score = 0

        for field in required_fields:
            # Direct match
            if field in available_fields:
                score += 1
                continue

            # Check aliases
            if field in self.FIELD_ALIASES:
                for alias in self.FIELD_ALIASES[field]:
                    if alias in available_fields:
                        score += 1
                        break

        return score

    def substitute_index(self, query: str, new_index: str) -> str:
        """
        Replace the index pattern in an ES|QL query.

        Args:
            query: Original ES|QL query
            new_index: New index pattern to use

        Returns:
            Query with substituted index

        Examples:
            substitute_index("FROM idx1, idx2 | WHERE x", "new-idx")
            -> "FROM new-idx | WHERE x"
        """
        # Match FROM clause - capture everything until pipe, METADATA, or newline
        # This handles multi-index patterns like "FROM idx1, idx2, idx3"
        pattern = r"(?i)(^\s*FROM\s+)([^|\n]+?)(\s*(?:\||METADATA\s|$))"

        def replace_index(match):
            return f"{match.group(1)}{new_index}{match.group(3)}"

        return re.sub(pattern, replace_index, query.strip())

    def execute_with_auto_discovery(
        self,
        query: str,
        index: str | None = None,
        lean: bool = False,
        rule_id: str | None = None,
        field_substitution: bool = True,
    ) -> dict[str, Any]:
        """
        Execute ES|QL query with automatic index discovery and field substitution.

        If index is provided, uses it directly.
        If not, tries the query's original index first, then discovers alternatives.

        Field substitution automatically adapts ECS field names to the actual
        field names in the target index (e.g., process.name -> winlog.event_data.Image).

        Args:
            query: ES|QL query string
            index: Optional index override
            lean: If True, return summarized results
            rule_id: Optional rule ID for tracking
            field_substitution: If True, substitute ECS fields with index-specific fields

        Returns:
            Query results with index resolution metadata and field substitutions
        """
        # Check version on first execution
        if not self._version_checked:
            self.check_version()

        original_index = self.extract_index_from_query(query)
        used_index = index or original_index
        discovery_attempted = False
        discovered_indices = []
        field_substitutions = {}

        # If user provided index, substitute it
        if index:
            query = self.substitute_index(query, index)

        # Apply field substitution if enabled
        if field_substitution and used_index:
            available_fields = self.field_mapper.get_index_fields(used_index)
            if available_fields:
                # Get substitution report for transparency
                sub_report = self.field_mapper.get_substitution_report(query, available_fields)
                field_substitutions = sub_report.get("substitutions", {})

                # Apply substitutions
                query = self.field_mapper.substitute_fields_esql(query, available_fields)

        # Try execution
        result = self.execute(query, lean=lean, rule_id=rule_id)

        # If index not found and no override was provided, try auto-discovery
        if result.get("error") and "Index not found" in result.get("error", ""):
            if not index:  # Only auto-discover if user didn't specify
                discovery_attempted = True
                required_fields = self.extract_fields_from_query(query)

                logger.info(f"Index not found, attempting auto-discovery for fields: {required_fields}")

                discovered_indices = self.discover_compatible_indices(required_fields)

                # Try each discovered index until we get results
                for idx_info in discovered_indices[:3]:  # Try top 3 matches
                    alt_index = idx_info["index"]
                    alt_query = self.substitute_index(query, alt_index)

                    # Apply field substitution to the alternative query
                    if field_substitution:
                        alt_fields = self.field_mapper.get_index_fields(alt_index)
                        if alt_fields:
                            sub_report = self.field_mapper.get_substitution_report(alt_query, alt_fields)
                            field_substitutions = sub_report.get("substitutions", {})
                            alt_query = self.field_mapper.substitute_fields_esql(alt_query, alt_fields)

                    logger.info(f"Trying alternative index: {alt_index}")

                    alt_result = self.execute(alt_query, lean=lean, rule_id=rule_id)

                    if not alt_result.get("error"):
                        # Success! Return with discovery metadata
                        alt_result["index_resolution"] = {
                            "original_index": original_index,
                            "used_index": alt_index,
                            "auto_discovered": True,
                            "discovery_reason": f"Original index '{original_index}' not found",
                            "alternatives_checked": [i["index"] for i in discovered_indices[:3]],
                        }
                        # Add field substitution metadata
                        if field_substitutions:
                            alt_result["field_substitutions"] = {
                                "enabled": True,
                                "substitutions": field_substitutions,
                                "count": len(field_substitutions),
                            }
                        return alt_result

        # Add resolution metadata
        if "index_resolution" not in result:
            result["index_resolution"] = {
                "original_index": original_index,
                "used_index": used_index,
                "auto_discovered": discovery_attempted,
                "discovery_reason": None if not discovery_attempted else "No compatible index found",
                "alternatives_checked": [i["index"] for i in discovered_indices] if discovered_indices else [],
            }

        # Add field substitution metadata
        if field_substitutions:
            result["field_substitutions"] = {
                "enabled": True,
                "substitutions": field_substitutions,
                "count": len(field_substitutions),
            }
        elif field_substitution:
            result["field_substitutions"] = {
                "enabled": True,
                "substitutions": {},
                "count": 0,
                "note": "No field substitutions needed - fields already match",
            }

        return result

    def execute(self, query: str, lean: bool = False, rule_id: str | None = None) -> dict[str, Any]:
        """
        Execute an ES|QL query.

        Args:
            query: The ES|QL query string
            lean: If True, return token-efficient summarized results
            rule_id: Optional rule ID for tracking

        Returns:
            Dictionary with results, token count, and execution metrics
        """
        # Check version on first execution
        if not self._version_checked:
            self.check_version()

        import time

        start_time = time.time()

        try:
            # Clean up query (remove comments, normalize whitespace)
            cleaned_query = self._clean_query(query)

            # Execute ES|QL query
            response = self.client.esql.query(query=cleaned_query, format="json")

            execution_time_ms = int((time.time() - start_time) * 1000)

            # Parse response
            result = self._parse_response(response)
            result["execution_time_ms"] = execution_time_ms
            result["tokens_used"] = self._count_tokens(result)

            # Track execution
            if rule_id:
                self._track_execution(rule_id, cleaned_query, result)

            # Apply lean mode if requested
            if lean:
                result = self._summarize(result)

            return result

        except Exception as e:
            error_msg = str(e)

            # Handle specific error types
            if "Unknown index" in error_msg or "index_not_found" in error_msg.lower():
                return {
                    "error": "Index not found. Check if the required data source is available.",
                    "hits_count": 0,
                    "tokens_used": 0,
                    "results": [],
                }
            if "parsing_exception" in error_msg.lower() or "verification_exception" in error_msg.lower():
                return {"error": f"ES|QL syntax error: {error_msg}", "hits_count": 0, "tokens_used": 0, "results": []}
            return {"error": f"ES|QL execution failed: {error_msg}", "hits_count": 0, "tokens_used": 0, "results": []}

    def substitute_timeframe(self, query: str, days: int) -> str:
        """
        Replace hardcoded timeframe in ES|QL query.

        Args:
            query: The original ES|QL query
            days: Number of days for the new timeframe

        Returns:
            Query with substituted timeframe

        Examples:
            "@timestamp > now() - 30 day" -> "@timestamp > now() - 7 day"
        """
        # Pattern matches: @timestamp > now() - N day (with variations)
        pattern = r"@timestamp\s*>\s*now\(\)\s*-\s*\d+\s*day"
        replacement = f"@timestamp > now() - {days} day"

        return re.sub(pattern, replacement, query, flags=re.IGNORECASE)

    def _clean_query(self, query: str) -> str:
        """Clean ES|QL query by removing comments and normalizing whitespace."""
        # Remove single-line comments (// ...)
        query = re.sub(r"//.*", "", query)

        # Remove multi-line comments (/* ... */)
        query = re.sub(r"/\*.*?\*/", "", query, flags=re.DOTALL)

        # Normalize whitespace (but preserve newlines for readability in logs)
        query = re.sub(r"[ \t]+", " ", query)
        query = re.sub(r"\n\s*\n", "\n", query)

        return query.strip()

    def _parse_response(self, response) -> dict[str, Any]:
        """Parse ES|QL response into structured result."""
        # Handle both dict and response object
        if hasattr(response, "body"):
            data = response.body
        else:
            data = response

        columns = data.get("columns", [])
        values = data.get("values", [])

        # Convert to list of dicts for easier consumption
        column_names = [col.get("name", f"col_{i}") for i, col in enumerate(columns)]

        results = []
        for row in values:
            result_row = {}
            for i, value in enumerate(row):
                if i < len(column_names):
                    result_row[column_names[i]] = value
            results.append(result_row)

        return {"hits_count": len(results), "columns": column_names, "results": results}

    def _count_tokens(self, result: dict[str, Any]) -> int:
        """
        Estimate token count from result size.

        Uses rough estimate of ~4 characters per token.
        """
        try:
            json_str = json.dumps(result.get("results", []))
            return len(json_str) // 4
        except Exception:
            return 0

    def _summarize(self, result: dict[str, Any]) -> dict[str, Any]:
        """
        Create token-efficient summary of results.

        Reduces results to top values and sample rows.
        """
        results = result.get("results", [])
        columns = result.get("columns", [])

        if not results:
            return result

        # Build summary with top values per column
        summary = {}
        for col in columns:
            # Get value counts
            values = [r.get(col) for r in results if r.get(col) is not None]
            if values:
                # Count occurrences
                value_counts = {}
                for v in values:
                    v_str = str(v)
                    value_counts[v_str] = value_counts.get(v_str, 0) + 1

                # Get top 5 values with counts
                top_values = sorted(value_counts.items(), key=lambda x: -x[1])[:5]
                summary[f"top_{col}"] = [f"{v} ({c})" for v, c in top_values]

        # Keep only 3-5 sample results
        sample_results = results[:5]

        return {
            "hits_count": result.get("hits_count", 0),
            "tokens_used": result.get("tokens_used", 0) // 3,  # Lean mode uses ~1/3 tokens
            "execution_time_ms": result.get("execution_time_ms", 0),
            "summary": summary,
            "sample_results": sample_results,
        }

    def _track_execution(self, rule_id: str, query: str, result: dict[str, Any]) -> None:
        """Track query execution for token usage analysis."""
        execution = QueryExecution(
            rule_id=rule_id,
            query=query[:200],  # Truncate for storage
            result_tokens=result.get("tokens_used", 0),
            hits_count=result.get("hits_count", 0),
            execution_time_ms=result.get("execution_time_ms", 0),
            timestamp=datetime.utcnow(),
        )

        # Keep last 100 executions
        self._execution_history.append(execution)
        if len(self._execution_history) > 100:
            self._execution_history = self._execution_history[-100:]

    def get_execution_history(self) -> list[dict[str, Any]]:
        """Get execution history for token usage analysis."""
        return [
            {
                "rule_id": e.rule_id,
                "result_tokens": e.result_tokens,
                "hits_count": e.hits_count,
                "execution_time_ms": e.execution_time_ms,
                "timestamp": e.timestamp.isoformat(),
            }
            for e in self._execution_history
        ]

    @property
    def es_version(self) -> str | None:
        """Get the detected Elasticsearch version."""
        return self._es_version

    @property
    def is_supported(self) -> bool:
        """Check if ES|QL is supported (version check passed)."""
        return self._esql_supported
