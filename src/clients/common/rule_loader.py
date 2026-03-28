"""Rule Loader for Lucene and EQL Detection Rules."""

import logging
import sys

# Python 3.11+ has tomllib, earlier versions need tomli
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class DetectionRule:
    """Represents a single detection rule."""

    # Core identifiers
    rule_id: str
    name: str
    rule_type: str  # 'lucene' or 'eql'

    # Query content
    query: str

    # Metadata from filename
    platform: str  # windows, linux, macos, application, cloud, network
    log_source: str  # powershell, process_creation, builtin, audit, etc.
    category: str  # specific category from path

    # File information
    file_path: str

    # Tags for searching
    tags: set[str] = field(default_factory=set)

    # MITRE ATT&CK mapping (extracted from tags/name)
    mitre_tactics: set[str] = field(default_factory=set)
    mitre_techniques: set[str] = field(default_factory=set)

    # Hunting tips and guidance (from hunting rules)
    notes: list[str] = field(default_factory=list)

    # TOML rule metadata (from detection-rules/rules/)
    description: str = ""
    severity: str = ""
    risk_score: int = 0
    references: list[str] = field(default_factory=list)
    investigation_notes: str = ""

    @property
    def display_name(self) -> str:
        """Generate a human-readable display name."""
        # Convert underscores to spaces and title case
        return self.name.replace("_", " ").title()

    def matches_filter(
        self,
        platform: str | None = None,
        log_source: str | None = None,
        rule_type: str | None = None,
        search_term: str | None = None,
    ) -> bool:
        """Check if this rule matches the given filters."""
        if platform and self.platform.lower() != platform.lower():
            return False

        if log_source and self.log_source.lower() != log_source.lower():
            return False

        if rule_type and self.rule_type.lower() != rule_type.lower():
            return False

        if search_term:
            search_term = search_term.lower()
            # Search in name, tags, query, platform, log_source
            searchable = (
                self.name.lower()
                + " "
                + self.platform.lower()
                + " "
                + self.log_source.lower()
                + " "
                + self.category.lower()
                + " "
                + " ".join(self.tags).lower()
            )
            if search_term not in searchable:
                return False

        return True


class RuleLoader:
    """Loads and manages detection rules from the rules directory."""

    # Languages accepted from TOML detection rules
    TOML_ALLOWED_LANGUAGES = {"eql", "esql"}

    def __init__(
        self, rules_directory: str, hunting_directory: str | None = None, toml_rules_directory: str | None = None
    ):
        """
        Initialise the rule loader.

        Args:
            rules_directory: Path to the directory containing rule files
            hunting_directory: Optional path to detection-rules/hunting/ for EQL hunting rules
            toml_rules_directory: Optional path to detection-rules/rules/ for TOML detection rules
        """
        self.rules_directory = Path(rules_directory)
        self.hunting_directory = Path(hunting_directory) if hunting_directory else None
        self.toml_rules_directory = Path(toml_rules_directory) if toml_rules_directory else None
        self.rules: dict[str, DetectionRule] = {}
        self.rules_by_platform: dict[str, list[str]] = {}
        self.rules_by_type: dict[str, list[str]] = {}
        self.rules_by_log_source: dict[str, list[str]] = {}

        self.logger = logging.getLogger(__name__)

        # MITRE ATT&CK keyword mapping (simplified)
        self.mitre_keywords = {
            "execution": ["execution", "exec", "run", "launch"],
            "persistence": ["persistence", "scheduled", "service", "startup", "registry"],
            "privilege_escalation": ["escalation", "privilege", "admin", "sudo", "runas"],
            "defense_evasion": ["evasion", "obfuscation", "encoding", "bypass", "disable"],
            "credential_access": ["credential", "password", "mimikatz", "dump", "hash"],
            "discovery": ["discovery", "recon", "enumerate", "whoami", "netstat"],
            "lateral_movement": ["lateral", "remote", "psexec", "wmi", "rdp"],
            "collection": ["collection", "clipboard", "screenshot", "keylog"],
            "command_and_control": ["c2", "beacon", "callback", "tunnel"],
            "exfiltration": ["exfil", "upload", "transfer", "compress"],
            "impact": ["impact", "delete", "encrypt", "ransom", "wipe"],
        }

    def load_all_rules(self) -> int:
        """
        Load all rules from the rules directory.

        Returns:
            Number of rules successfully loaded
        """
        loaded_count = 0
        error_count = 0

        # Load Lucene + EQL rules from filesystem rules directory
        rules_dir_str = str(self.rules_directory)
        if rules_dir_str and self.rules_directory.exists() and self.rules_directory.is_dir():
            # Find all .lucene and .eql files
            lucene_files = list(self.rules_directory.glob("*.lucene"))
            eql_files = list(self.rules_directory.glob("*.eql"))

            self.logger.info(f"Found {len(lucene_files)} Lucene rules and {len(eql_files)} EQL rules")

            # Load Lucene rules
            for rule_file in lucene_files:
                try:
                    rule = self._load_rule_file(rule_file, "lucene")
                    if rule:
                        self._index_rule(rule)
                        loaded_count += 1
                except Exception as e:
                    self.logger.warning(f"Failed to load rule {rule_file.name}: {e}")
                    error_count += 1

            # Load EQL rules
            for rule_file in eql_files:
                try:
                    rule = self._load_rule_file(rule_file, "eql")
                    if rule:
                        self._index_rule(rule)
                        loaded_count += 1
                except Exception as e:
                    self.logger.warning(f"Failed to load rule {rule_file.name}: {e}")
                    error_count += 1

            self.logger.info(f"Loaded {loaded_count} Sigma rules successfully ({error_count} errors)")
        elif rules_dir_str:
            self.logger.warning(f"Rules directory not found: {self.rules_directory}")

        # Load hunting EQL rules if hunting directory is configured
        if self.hunting_directory and self.hunting_directory.exists():
            hunting_count = self._load_hunting_eql_rules()
            loaded_count += hunting_count

        # Load TOML detection rules if directory is configured
        if self.toml_rules_directory and self.toml_rules_directory.exists():
            toml_count = self._load_toml_detection_rules()
            loaded_count += toml_count

        return loaded_count

    def _load_hunting_eql_rules(self) -> int:
        """
        Load EQL queries from hunting TOML files.

        Returns:
            Number of EQL rules loaded from hunting directory
        """
        loaded_count = 0

        for toml_file in self.hunting_directory.rglob("*.toml"):
            try:
                rules = self._parse_hunting_toml(toml_file)
                for rule in rules:
                    self._index_rule(rule)
                    loaded_count += 1
            except Exception as e:
                self.logger.debug(f"Failed to load hunting file {toml_file}: {e}")

        self.logger.info(f"Loaded {loaded_count} EQL rules from hunting directory")
        return loaded_count

    def _parse_hunting_toml(self, toml_file: Path) -> list[DetectionRule]:
        """Parse a hunting TOML file and extract EQL queries as DetectionRules."""
        rules = []

        with open(toml_file, "rb") as f:
            data = tomllib.load(f)

        hunt = data.get("hunt", {})
        if not hunt:
            return rules

        uuid = hunt.get("uuid")
        name = hunt.get("name")
        queries = hunt.get("query", [])
        mitre = hunt.get("mitre", [])
        notes = hunt.get("notes", [])

        if not uuid or not name or not queries:
            return rules

        # Filter to EQL queries only
        eql_queries = [q for q in queries if self._is_eql(q)]

        if not eql_queries:
            return rules

        # Detect platform from file path
        platform = self._detect_hunting_platform(toml_file)

        # Create a DetectionRule for each EQL query
        for i, query in enumerate(eql_queries):
            rule_id = f"hunting_{uuid}_{i}" if len(eql_queries) > 1 else f"hunting_{uuid}"

            rule = DetectionRule(
                rule_id=rule_id,
                name=name,
                rule_type="eql",
                query=query.strip(),
                platform=platform,
                log_source="hunting",
                category="threat_hunting",
                file_path=str(toml_file),
                tags={"hunting", "elastic", platform},
                mitre_tactics=self._extract_tactics_from_mitre(mitre),
                mitre_techniques=set(mitre),
                notes=notes,
            )

            rules.append(rule)

        return rules

    def _is_eql(self, query: str) -> bool:
        """
        Detect if a query is EQL (not ES|QL, not SQL/OSQuery).

        EQL queries start with event types: process, file, network, registry, any, sequence
        ES|QL starts with: from
        SQL/OSQuery starts with: select
        """
        q = query.strip().lower()
        eql_prefixes = ("process ", "file ", "network ", "registry ", "any ", "sequence ")
        return q.startswith(eql_prefixes)

    def _detect_hunting_platform(self, toml_file: Path) -> str:
        """Detect platform from hunting file path."""
        platforms = {"linux", "windows", "macos", "aws", "azure", "okta", "llm", "cross-platform"}
        parts = toml_file.parts
        for part in parts:
            if part.lower() in platforms:
                return part.lower()
        return "unknown"

    def _extract_tactics_from_mitre(self, mitre_ids: list[str]) -> set[str]:
        """Extract MITRE tactics from technique IDs using keyword heuristics."""
        tactics = set()

        # Common technique to tactic mappings
        technique_tactics = {
            "T1053": "persistence",  # Scheduled Task
            "T1059": "execution",  # Command and Scripting Interpreter
            "T1071": "command_and_control",  # Application Layer Protocol
            "T1105": "command_and_control",  # Ingress Tool Transfer
            "T1547": "persistence",  # Boot or Logon Autostart Execution
            "T1543": "persistence",  # Create or Modify System Process
            "T1070": "defense_evasion",  # Indicator Removal
            "T1552": "credential_access",  # Unsecured Credentials
            "T1083": "discovery",  # File and Directory Discovery
            "T1204": "execution",  # User Execution
        }

        for technique in mitre_ids:
            # Get base technique (e.g., T1059 from T1059.001)
            base = technique.split(".")[0] if "." in technique else technique
            if base in technique_tactics:
                tactics.add(technique_tactics[base])

        return tactics

    def _load_toml_detection_rules(self) -> int:
        """Load EQL and ES|QL detection rules from TOML files in detection-rules/rules/."""
        loaded_count = 0

        for toml_file in self.toml_rules_directory.rglob("*.toml"):
            # Skip deprecated rules
            if "_deprecated" in toml_file.parts:
                continue
            try:
                rule = self._parse_toml_detection_rule(toml_file)
                if rule:
                    self._index_rule(rule)
                    loaded_count += 1
            except Exception as e:
                self.logger.debug(f"Failed to load TOML rule {toml_file}: {e}")

        self.logger.info(f"Loaded {loaded_count} TOML detection rules (EQL + ES|QL)")
        return loaded_count

    def _parse_toml_detection_rule(self, toml_file: Path) -> DetectionRule | None:
        """Parse a [rule]-format TOML detection rule file."""
        with open(toml_file, "rb") as f:
            data = tomllib.load(f)

        rule_data = data.get("rule", {})
        if not rule_data:
            return None

        # Filter: only EQL and ES|QL
        language = rule_data.get("language", "").lower()
        if language not in self.TOML_ALLOWED_LANGUAGES:
            return None

        query = rule_data.get("query", "").strip()
        if not query:
            return None

        uuid = rule_data.get("rule_id", "")
        name = rule_data.get("name", "")
        if not uuid or not name:
            return None

        # Map language to rule_type
        rule_type = language  # "eql" or "esql"

        # Detect platform from directory structure or tags
        platform = self._detect_toml_platform(toml_file, rule_data.get("tags", []))

        # Extract log source from integration metadata
        metadata = data.get("metadata", {})
        integrations = metadata.get("integration", [])
        log_source = integrations[0] if integrations else "elastic"

        # Extract MITRE from structured [[rule.threat]] sections
        mitre_tactics, mitre_techniques = self._extract_mitre_from_threat(rule_data.get("threat", []))

        # Build tags
        tags = set()
        tags.add(platform)
        tags.add(rule_type)
        tags.add(log_source)
        tags.add("elastic")
        tags.add("toml")
        for tag in rule_data.get("tags", []):
            if ":" in tag:
                tags.add(tag.split(":", 1)[1].strip().lower())
            else:
                tags.add(tag.lower())
        tags.update(mitre_tactics)

        return DetectionRule(
            rule_id=f"elastic_{uuid}",
            name=name,
            rule_type=rule_type,
            query=query,
            platform=platform,
            log_source=log_source,
            category=next(iter(mitre_tactics), ""),
            file_path=str(toml_file),
            tags=tags,
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_techniques,
            description=rule_data.get("description", "").strip(),
            severity=rule_data.get("severity", ""),
            risk_score=rule_data.get("risk_score", 0),
            references=rule_data.get("references", []),
            investigation_notes=rule_data.get("note", "").strip(),
        )

    def _detect_toml_platform(self, toml_file: Path, tags: list) -> str:
        """Detect platform from TOML rule directory structure or tags."""
        known_platforms = {
            "windows",
            "linux",
            "macos",
            "cross-platform",
            "network",
            "ml",
            "integrations",
        }
        for part in toml_file.parts:
            if part.lower() in known_platforms:
                return part.lower()

        for tag in tags:
            tag_lower = tag.lower()
            if "windows" in tag_lower:
                return "windows"
            if "linux" in tag_lower:
                return "linux"
            if "macos" in tag_lower:
                return "macos"

        return "cross-platform"

    def _extract_mitre_from_threat(self, threat_list: list) -> tuple:
        """Extract MITRE tactics and techniques from [[rule.threat]] TOML sections."""
        tactics = set()
        techniques = set()

        for threat_entry in threat_list:
            if not isinstance(threat_entry, dict):
                continue
            if threat_entry.get("framework") != "MITRE ATT&CK":
                continue

            tactic = threat_entry.get("tactic", {})
            if tactic.get("name"):
                tactics.add(tactic["name"].lower().replace(" ", "_"))

            for technique in threat_entry.get("technique", []):
                if technique.get("id"):
                    techniques.add(technique["id"])
                for sub in technique.get("subtechnique", []):
                    if sub.get("id"):
                        techniques.add(sub["id"])

        return tactics, techniques

    def _load_rule_file(self, file_path: Path, rule_type: str) -> DetectionRule | None:
        """Load a single rule file and parse its metadata."""
        # Read the rule query
        try:
            with open(file_path, encoding="utf-8") as f:
                query = f.read().strip()
        except Exception as e:
            self.logger.error(f"Failed to read {file_path}: {e}")
            return None

        if not query:
            self.logger.warning(f"Empty rule file: {file_path}")
            return None

        # Parse filename: platform__log_source__category__rule_name.type
        filename = file_path.stem  # Remove extension
        parts = filename.split("__")

        if len(parts) < 3:
            self.logger.warning(f"Invalid filename format: {file_path.name}")
            return None

        platform = parts[0]
        log_source = parts[1]

        # The rest is category + rule name
        if len(parts) == 3:
            category = ""
            rule_name = parts[2]
        else:
            # Multiple parts: category is middle parts, name is last part
            category = "__".join(parts[2:-1])
            rule_name = parts[-1]

        # Generate rule ID
        rule_id = f"{platform}_{log_source}_{rule_name}_{rule_type}"

        # Extract tags from various components
        tags = set()
        tags.add(platform)
        tags.add(log_source)
        tags.add(rule_type)
        if category:
            tags.add(category)

        # Extract additional tags from rule name
        # Common patterns: win_, lnx_, proc_, posh_, etc.
        name_parts = rule_name.split("_")
        for part in name_parts:
            if len(part) > 2:  # Skip very short parts
                tags.add(part)

        # Create the rule object
        rule = DetectionRule(
            rule_id=rule_id,
            name=rule_name,
            rule_type=rule_type,
            query=query,
            platform=platform,
            log_source=log_source,
            category=category,
            file_path=str(file_path),
            tags=tags,
        )

        # Map to MITRE ATT&CK tactics based on keywords
        self._map_mitre_tactics(rule)

        return rule

    def _map_mitre_tactics(self, rule: DetectionRule):
        """Map rule to MITRE ATT&CK tactics based on keywords."""
        rule_text = (rule.name + " " + rule.category).lower()

        for tactic, keywords in self.mitre_keywords.items():
            for keyword in keywords:
                if keyword in rule_text:
                    rule.mitre_tactics.add(tactic)
                    break  # Found match for this tactic

    def _index_rule(self, rule: DetectionRule):
        """Add rule to the index for fast lookups."""
        # Main index
        self.rules[rule.rule_id] = rule

        # Platform index
        if rule.platform not in self.rules_by_platform:
            self.rules_by_platform[rule.platform] = []
        self.rules_by_platform[rule.platform].append(rule.rule_id)

        # Type index
        if rule.rule_type not in self.rules_by_type:
            self.rules_by_type[rule.rule_type] = []
        self.rules_by_type[rule.rule_type].append(rule.rule_id)

        # Log source index
        if rule.log_source not in self.rules_by_log_source:
            self.rules_by_log_source[rule.log_source] = []
        self.rules_by_log_source[rule.log_source].append(rule.rule_id)

    def get_rule(self, rule_id: str) -> DetectionRule | None:
        """Get a specific rule by ID."""
        return self.rules.get(rule_id)

    def search_rules(
        self,
        platform: str | None = None,
        log_source: str | None = None,
        rule_type: str | None = None,
        search_term: str | None = None,
        mitre_tactic: str | None = None,
        limit: int = 100,
    ) -> list[DetectionRule]:
        """
        Search for rules matching the given criteria.

        Args:
            platform: Filter by platform (windows, linux, macos, etc.)
            log_source: Filter by log source (powershell, process_creation, etc.)
            rule_type: Filter by type (lucene, eql)
            search_term: Search in rule name, tags, and content
            mitre_tactic: Filter by MITRE ATT&CK tactic
            limit: Maximum number of results

        Returns:
            List of matching rules
        """
        results = []

        # Start with all rules or filtered by platform
        if platform and platform in self.rules_by_platform:
            candidate_ids = self.rules_by_platform[platform]
        else:
            candidate_ids = list(self.rules.keys())

        # Filter candidates
        for rule_id in candidate_ids:
            rule = self.rules[rule_id]

            # Apply filters
            if not rule.matches_filter(platform, log_source, rule_type, search_term):
                continue

            # MITRE tactic filter
            if mitre_tactic and mitre_tactic.lower() not in rule.mitre_tactics:
                continue

            results.append(rule)

            if len(results) >= limit:
                break

        return results

    def get_statistics(self) -> dict:
        """Get statistics about loaded rules."""
        return {
            "total_rules": len(self.rules),
            "by_platform": {platform: len(rule_ids) for platform, rule_ids in self.rules_by_platform.items()},
            "by_type": {rule_type: len(rule_ids) for rule_type, rule_ids in self.rules_by_type.items()},
            "by_log_source": {log_source: len(rule_ids) for log_source, rule_ids in self.rules_by_log_source.items()},
            "platforms": list(self.rules_by_platform.keys()),
            "log_sources": list(self.rules_by_log_source.keys()),
        }

    def get_rules_by_platform(self, platform: str) -> list[DetectionRule]:
        """Get all rules for a specific platform."""
        rule_ids = self.rules_by_platform.get(platform, [])
        return [self.rules[rid] for rid in rule_ids]

    def get_rules_by_mitre_tactic(self, tactic: str) -> list[DetectionRule]:
        """Get all rules mapped to a specific MITRE ATT&CK tactic."""
        return [rule for rule in self.rules.values() if tactic.lower() in rule.mitre_tactics]
