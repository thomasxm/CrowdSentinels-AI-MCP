"""Hunting Rule Loader for ES|QL queries from detection-rules/hunting/."""
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

# Python 3.11+ has tomllib, earlier versions need tomli
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

logger = logging.getLogger(__name__)


@dataclass
class HuntingRule:
    """Represents an ES|QL hunting rule from the detection-rules/hunting/ directory."""

    uuid: str
    name: str
    description: str
    query: List[str]  # All queries (ES|QL, EQL, SQL, etc.)
    platform: str  # linux, windows, macos, aws, azure, okta, llm, cross-platform
    integration: List[str]  # Data sources: endpoint, windows, system, etc.
    mitre: List[str]  # MITRE techniques: T1053.003, AML.T0051, etc.
    notes: List[str]  # Hunting tips and guidance
    file_path: str

    # Computed fields - queries filtered by language
    esql_queries: List[str] = field(default_factory=list)

    @property
    def display_name(self) -> str:
        """Generate a human-readable display name."""
        return self.name

    @property
    def short_description(self) -> str:
        """Get truncated description for listings."""
        if len(self.description) > 200:
            return self.description[:197] + "..."
        return self.description


class HuntingRuleLoader:
    """Loads ES|QL hunting rules from detection-rules/hunting/ directory."""

    # Platforms based on directory structure
    PLATFORMS = {"linux", "windows", "macos", "aws", "azure", "okta", "llm", "cross-platform"}

    def __init__(self, hunting_directory: str):
        """
        Initialize the hunting rule loader.

        Args:
            hunting_directory: Path to the detection-rules/hunting/ directory
        """
        self.hunting_directory = Path(hunting_directory)
        self.rules: Dict[str, HuntingRule] = {}
        self.rules_by_platform: Dict[str, List[str]] = {}
        self.rules_by_mitre: Dict[str, List[str]] = {}

        self.logger = logging.getLogger(__name__)

        if self.hunting_directory.exists():
            self._load_rules()
        else:
            self.logger.warning(f"Hunting directory not found: {hunting_directory}")

    def _load_rules(self) -> None:
        """Load all TOML files and extract ES|QL queries."""
        loaded_count = 0
        esql_count = 0

        for toml_file in self.hunting_directory.rglob("*.toml"):
            try:
                rule = self._parse_toml(toml_file)
                if rule and rule.esql_queries:
                    self.rules[rule.uuid] = rule
                    loaded_count += 1
                    esql_count += len(rule.esql_queries)

                    # Index by platform
                    if rule.platform not in self.rules_by_platform:
                        self.rules_by_platform[rule.platform] = []
                    self.rules_by_platform[rule.platform].append(rule.uuid)

                    # Index by MITRE technique
                    for technique in rule.mitre:
                        if technique not in self.rules_by_mitre:
                            self.rules_by_mitre[technique] = []
                        self.rules_by_mitre[technique].append(rule.uuid)

            except Exception as e:
                self.logger.debug(f"Failed to load {toml_file}: {e}")

        self.logger.info(f"Loaded {loaded_count} ES|QL hunting rules with {esql_count} queries")

    def _parse_toml(self, toml_file: Path) -> Optional[HuntingRule]:
        """Parse a TOML hunting file into a HuntingRule."""
        try:
            with open(toml_file, "rb") as f:
                data = tomllib.load(f)

            hunt = data.get("hunt", {})
            if not hunt:
                return None

            # Required fields
            uuid = hunt.get("uuid")
            name = hunt.get("name")
            queries = hunt.get("query", [])

            if not uuid or not name or not queries:
                return None

            # Filter ES|QL queries
            esql_queries = [q for q in queries if self._is_esql(q)]

            if not esql_queries:
                return None

            # Detect platform from file path
            platform = self._detect_platform(toml_file)

            return HuntingRule(
                uuid=uuid,
                name=name,
                description=hunt.get("description", "").strip(),
                query=queries,
                platform=platform,
                integration=hunt.get("integration", []),
                mitre=hunt.get("mitre", []),
                notes=hunt.get("notes", []),
                file_path=str(toml_file),
                esql_queries=esql_queries
            )

        except Exception as e:
            self.logger.debug(f"Error parsing {toml_file}: {e}")
            return None

    def _is_esql(self, query: str) -> bool:
        """
        Detect if a query is ES|QL.

        ES|QL queries start with FROM, not to be confused with:
        - EQL: starts with event type (process, file, network, sequence, any)
        - SQL/OSQuery: starts with SELECT
        """
        q = query.strip().lower()
        return q.startswith("from ")

    def _detect_platform(self, toml_file: Path) -> str:
        """Detect platform from file path."""
        # Path structure: hunting/{platform}/queries/*.toml
        parts = toml_file.parts
        for part in parts:
            if part.lower() in self.PLATFORMS:
                return part.lower()
        return "unknown"

    def get_rule(self, rule_id: str) -> Optional[HuntingRule]:
        """Get a hunting rule by UUID."""
        return self.rules.get(rule_id)

    def search_rules(
        self,
        platform: Optional[str] = None,
        mitre: Optional[str] = None,
        keyword: Optional[str] = None,
        limit: int = 50
    ) -> List[HuntingRule]:
        """
        Search hunting rules with optional filters.

        Args:
            platform: Filter by platform (linux, windows, macos, aws, etc.)
            mitre: Filter by MITRE technique (T1053, T1059.001, etc.)
            keyword: Search in name and description
            limit: Maximum number of results

        Returns:
            List of matching HuntingRule objects
        """
        results = []

        for rule in self.rules.values():
            # Platform filter
            if platform and rule.platform.lower() != platform.lower():
                continue

            # MITRE filter
            if mitre:
                mitre_match = False
                for technique in rule.mitre:
                    if mitre.upper() in technique.upper():
                        mitre_match = True
                        break
                if not mitre_match:
                    continue

            # Keyword search
            if keyword:
                keyword_lower = keyword.lower()
                searchable = f"{rule.name} {rule.description}".lower()
                if keyword_lower not in searchable:
                    continue

            results.append(rule)
            if len(results) >= limit:
                break

        return results

    def get_statistics(self) -> Dict:
        """Get statistics about loaded hunting rules."""
        total_esql_queries = sum(len(r.esql_queries) for r in self.rules.values())

        return {
            "total_rules": len(self.rules),
            "total_esql_queries": total_esql_queries,
            "platforms": {p: len(uuids) for p, uuids in self.rules_by_platform.items()},
            "mitre_techniques_covered": len(self.rules_by_mitre)
        }

    def get_platforms(self) -> List[str]:
        """Get list of available platforms."""
        return sorted(self.rules_by_platform.keys())

    def get_mitre_techniques(self) -> List[str]:
        """Get list of MITRE techniques covered."""
        return sorted(self.rules_by_mitre.keys())
