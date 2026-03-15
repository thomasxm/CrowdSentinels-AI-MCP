"""Chainsaw Log Analyzer Client for EVTX hunting and analysis."""
from typing import Dict, List, Optional, Any
import subprocess
import json
import logging
import os
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field

from src.paths import get_chainsaw_dir, get_binary_path

logger = logging.getLogger(__name__)

# Environment variable overrides
ENV_CHAINSAW_PATH = os.environ.get("CHAINSAW_PATH")
ENV_SIGMA_RULES_PATH = os.environ.get("CHAINSAW_SIGMA_PATH")
ENV_EVTX_SAMPLES_PATH = os.environ.get("CHAINSAW_EVTX_SAMPLES_PATH")


@dataclass
class PyramidOfPainLevel:
    """Pyramid of Pain priority levels for IoCs."""
    level: int
    name: str
    description: str
    difficulty_to_change: str
    examples: List[str]


@dataclass
class DiamondModelVertex:
    """Diamond Model of Intrusion Analysis vertex."""
    vertex: str
    description: str
    elements: List[str]


class ChainsawClient:
    """Client for executing Chainsaw log analyzer commands."""

    # Pyramid of Pain levels (from easiest to hardest for attackers to change)
    PYRAMID_OF_PAIN = {
        1: PyramidOfPainLevel(
            level=1,
            name="Hash Values",
            description="File hashes - trivial for attackers to change",
            difficulty_to_change="Trivial",
            examples=["MD5", "SHA1", "SHA256"]
        ),
        2: PyramidOfPainLevel(
            level=2,
            name="IP Addresses",
            description="IP addresses - easy for attackers to change",
            difficulty_to_change="Easy",
            examples=["192.0.2.100", "203.0.113.42"]
        ),
        3: PyramidOfPainLevel(
            level=3,
            name="Domain Names",
            description="Domain names - simple for attackers to change",
            difficulty_to_change="Simple",
            examples=["evil.com", "malicious.net"]
        ),
        4: PyramidOfPainLevel(
            level=4,
            name="Network/Host Artifacts",
            description="Network artifacts - annoying for attackers to change",
            difficulty_to_change="Annoying",
            examples=["User-Agent strings", "Registry keys", "File paths"]
        ),
        5: PyramidOfPainLevel(
            level=5,
            name="Tools",
            description="Attacker tools - challenging to change",
            difficulty_to_change="Challenging",
            examples=["mimikatz", "psexec", "cobalt strike"]
        ),
        6: PyramidOfPainLevel(
            level=6,
            name="TTPs",
            description="Tactics, Techniques, and Procedures - tough to change",
            difficulty_to_change="Tough",
            examples=["Credential dumping", "Lateral movement", "Persistence mechanisms"]
        )
    }

    # Diamond Model vertices
    DIAMOND_MODEL = {
        "adversary": DiamondModelVertex(
            vertex="Adversary",
            description="The attacker or threat actor",
            elements=["Threat actor identity", "Attribution", "Motivation", "Intent"]
        ),
        "capability": DiamondModelVertex(
            vertex="Capability",
            description="Tools and techniques used by adversary",
            elements=["Malware", "Exploits", "Tools", "TTPs", "Skills"]
        ),
        "infrastructure": DiamondModelVertex(
            vertex="Infrastructure",
            description="Physical/logical resources used in attack",
            elements=["IP addresses", "Domains", "Email addresses", "C2 servers"]
        ),
        "victim": DiamondModelVertex(
            vertex="Victim",
            description="Target of the attack",
            elements=["Target systems", "Affected hosts", "Users", "Assets"]
        )
    }

    def __init__(self, chainsaw_path: Optional[str] = None):
        """
        Initialise Chainsaw client.

        Args:
            chainsaw_path: Path to chainsaw binary. Resolution order:
                1. Explicit chainsaw_path argument
                2. CHAINSAW_PATH environment variable
                3. Resolved chainsaw directory (installed package or project root)
                4. Legacy fallback paths (from older setup.sh)
                5. System PATH via shutil.which
        """
        # Resolve the chainsaw root directory via the centralised path helper
        chainsaw_dir = get_chainsaw_dir()

        # Resolve chainsaw binary path (env var → project dir → legacy → system PATH)
        if chainsaw_path:
            self.chainsaw_path = Path(chainsaw_path)
        elif ENV_CHAINSAW_PATH:
            self.chainsaw_path = Path(ENV_CHAINSAW_PATH)
        elif chainsaw_dir is not None:
            default_binary = chainsaw_dir / "chainsaw"
            legacy_binary = chainsaw_dir / "chainsaw" / "chainsaw_binary"
            legacy_binary_2 = chainsaw_dir / "chainsaw" / "chainsaw_x86_64-unknown-linux-gnu"

            if default_binary.exists():
                self.chainsaw_path = default_binary
            elif legacy_binary.exists():
                logger.info(f"Using legacy Chainsaw path: {legacy_binary}")
                self.chainsaw_path = legacy_binary
            elif legacy_binary_2.exists():
                logger.info(f"Using legacy Chainsaw path: {legacy_binary_2}")
                self.chainsaw_path = legacy_binary_2
            else:
                self.chainsaw_path = default_binary
        else:
            # No project chainsaw directory — try system PATH
            system_binary = get_binary_path("chainsaw")
            self.chainsaw_path = system_binary or Path("chainsaw")

        # Validate chainsaw exists
        if not self.chainsaw_path.exists():
            logger.warning(f"Chainsaw binary not found at: {self.chainsaw_path}")
            logger.warning("Install chainsaw (https://github.com/WithSecureLabs/chainsaw) or run ./setup.sh")

        # Set default paths using the resolved chainsaw directory
        self.chainsaw_dir = chainsaw_dir
        if chainsaw_dir is not None:
            self.sigma_rules = Path(ENV_SIGMA_RULES_PATH) if ENV_SIGMA_RULES_PATH else chainsaw_dir / "sigma"
            self.custom_rules = chainsaw_dir / "rules"
            self.mappings = chainsaw_dir / "mappings"
            self.sample_evtx = Path(ENV_EVTX_SAMPLES_PATH) if ENV_EVTX_SAMPLES_PATH else chainsaw_dir / "EVTX-ATTACK-SAMPLES"
        else:
            # No chainsaw directory — use env vars or None
            self.sigma_rules = Path(ENV_SIGMA_RULES_PATH) if ENV_SIGMA_RULES_PATH else None
            self.custom_rules = None
            self.mappings = None
            self.sample_evtx = Path(ENV_EVTX_SAMPLES_PATH) if ENV_EVTX_SAMPLES_PATH else None

    def _resolve_evtx_path(self, evtx_path: str) -> str:
        """Resolve an EVTX path, trying multiple locations if relative.

        Resolution order:
            1. As given (absolute or relative to cwd)
            2. Under ~/.crowdsentinel/ (e.g., chainsaw/EVTX-ATTACK-SAMPLES)
            3. Under the chainsaw directory (e.g., EVTX-ATTACK-SAMPLES)
            4. Return as-is and let chainsaw report the error
        """
        p = Path(evtx_path)
        if p.exists():
            return str(p.resolve())

        from src.paths import get_user_data_dir
        user_dir = get_user_data_dir()

        # Try under ~/.crowdsentinel/
        candidate = user_dir / evtx_path
        if candidate.exists():
            logger.info("Resolved EVTX path: %s → %s", evtx_path, candidate)
            return str(candidate)

        # Try under chainsaw directory
        if self.chainsaw_dir:
            candidate = self.chainsaw_dir / evtx_path
            if candidate.exists():
                logger.info("Resolved EVTX path: %s → %s", evtx_path, candidate)
                return str(candidate)

            # Try just the basename under chainsaw dir
            candidate = self.chainsaw_dir / Path(evtx_path).name
            if candidate.exists():
                logger.info("Resolved EVTX path: %s → %s", evtx_path, candidate)
                return str(candidate)

        logger.warning("EVTX path not found: %s", evtx_path)
        return evtx_path

    def hunt(self,
             evtx_path: str,
             sigma_path: Optional[str] = None,
             mapping_path: Optional[str] = None,
             custom_rules: Optional[str] = None,
             from_time: Optional[str] = None,
             to_time: Optional[str] = None,
             output_format: str = "json",
             skip_errors: bool = True) -> Dict:
        """
        Hunt for threats using Sigma rules.

        Args:
            evtx_path: Path to EVTX files or directory
            sigma_path: Path to Sigma rules directory
            mapping_path: Path to mapping file
            custom_rules: Path to custom rules directory
            from_time: Start timestamp (ISO format: 2019-03-17T19:09:39)
            to_time: End timestamp (ISO format)
            output_format: Output format (json, csv)
            skip_errors: Skip errors during processing

        Returns:
            Dictionary with hunt results
        """
        if not self.chainsaw_path.exists():
            return {
                "error": "Chainsaw not installed",
                "message": "Run setup to install chainsaw",
                "install_command": "See CHAINSAW_GUIDE.md for installation"
            }

        # Resolve EVTX path (handles relative paths from LLM agent)
        resolved_evtx = self._resolve_evtx_path(evtx_path)

        # Build command
        cmd = [str(self.chainsaw_path), "hunt", resolved_evtx]

        # Add sigma rules path
        if sigma_path:
            cmd.extend(["-s", sigma_path])
        elif self.sigma_rules.exists():
            cmd.extend(["-s", str(self.sigma_rules)])

        # Add mapping
        if mapping_path:
            cmd.extend(["--mapping", mapping_path])
        elif self.mappings.exists():
            default_mapping = self.mappings / "sigma-event-logs-all.yml"
            if default_mapping.exists():
                cmd.extend(["--mapping", str(default_mapping)])

        # Add custom rules
        if custom_rules:
            cmd.extend(["-r", custom_rules])
        elif self.custom_rules.exists():
            cmd.extend(["-r", str(self.custom_rules)])

        # Add time filters
        if from_time:
            cmd.extend(["--from", from_time])
        if to_time:
            cmd.extend(["--to", to_time])

        # Add output format
        if output_format == "json":
            cmd.append("--json")
        elif output_format == "csv":
            cmd.append("--csv")

        # Skip errors
        if skip_errors:
            cmd.append("--skip-errors")

        # Add quiet mode for JSON
        if output_format == "json":
            cmd.append("-q")

        logger.info(f"Executing chainsaw hunt: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            if result.returncode != 0:
                return {
                    "error": "Chainsaw execution failed",
                    "stderr": result.stderr,
                    "returncode": result.returncode,
                    "command": ' '.join(cmd)
                }

            # Parse output based on format
            if output_format == "json":
                try:
                    # Chainsaw hunt with --json -q outputs a JSON array
                    output = result.stdout.strip()
                    if output.startswith('['):
                        # JSON array format
                        detections = json.loads(output)
                    else:
                        # Fallback: try newline-delimited JSON
                        lines = output.split('\n')
                        detections = []
                        for line in lines:
                            if line.strip():
                                detections.append(json.loads(line))

                    return {
                        "success": True,
                        "total_detections": len(detections),
                        "detections": detections,
                        "command": ' '.join(cmd)
                    }
                except json.JSONDecodeError as e:
                    return {
                        "error": "Failed to parse JSON output",
                        "details": str(e),
                        "raw_output": result.stdout[:1000]
                    }
            else:
                return {
                    "success": True,
                    "output": result.stdout,
                    "command": ' '.join(cmd)
                }

        except subprocess.TimeoutExpired:
            return {
                "error": "Chainsaw execution timed out",
                "timeout_seconds": 300,
                "command": ' '.join(cmd)
            }
        except Exception as e:
            return {
                "error": f"Chainsaw execution failed: {str(e)}",
                "command": ' '.join(cmd)
            }

    def search(self,
               evtx_path: str,
               search_term: str,
               case_insensitive: bool = True,
               event_id: Optional[int] = None,
               regex: bool = False,
               output_format: str = "json") -> Dict:
        """
        Search for specific terms in EVTX files.

        Args:
            evtx_path: Path to EVTX files or directory
            search_term: Term to search for (IP, URL, process name, etc.)
            case_insensitive: Case-insensitive search
            event_id: Filter by specific Windows Event ID (uses tau expression)
            regex: Treat search term as regex pattern (uses -e flag)
            output_format: Output format (json, jsonl)

        Returns:
            Dictionary with search results

        Command syntax: chainsaw search [OPTIONS] [PATTERN] [PATH]...
        """
        if not self.chainsaw_path.exists():
            return {
                "error": "Chainsaw not installed",
                "message": "Run setup to install chainsaw"
            }

        # Build command: chainsaw search [OPTIONS] [PATTERN] [PATH]...
        cmd = [str(self.chainsaw_path), "search"]

        # Add search pattern - either as regex (-e) or plain positional arg
        if regex:
            cmd.extend(["-e", search_term])
        else:
            cmd.append(search_term)

        # Add EVTX path as positional argument (resolve relative paths)
        cmd.append(self._resolve_evtx_path(evtx_path))

        # Case insensitive (-i or --ignore-case)
        if case_insensitive:
            cmd.append("-i")

        # Event ID filter using tau expression
        if event_id:
            cmd.extend(["-t", f"Event.System.EventID: ={event_id}"])

        # Output format
        if output_format == "json":
            cmd.append("--json")
        elif output_format == "jsonl":
            cmd.append("--jsonl")

        logger.info(f"Executing chainsaw search: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode != 0:
                return {
                    "error": "Chainsaw search failed",
                    "stderr": result.stderr,
                    "returncode": result.returncode,
                    "command": ' '.join(cmd)
                }

            # Parse JSON output
            if output_format == "json":
                try:
                    # Chainsaw search with --json outputs a JSON array
                    output = result.stdout.strip()
                    if output.startswith('['):
                        # JSON array format
                        matches = json.loads(output)
                    else:
                        # Fallback: try newline-delimited JSON
                        lines = output.split('\n')
                        matches = []
                        for line in lines:
                            if line.strip():
                                matches.append(json.loads(line))

                    return {
                        "success": True,
                        "search_term": search_term,
                        "total_matches": len(matches),
                        "matches": matches,
                        "command": ' '.join(cmd)
                    }
                except json.JSONDecodeError:
                    return {
                        "success": True,
                        "search_term": search_term,
                        "output": result.stdout,
                        "command": ' '.join(cmd)
                    }
            else:
                return {
                    "success": True,
                    "search_term": search_term,
                    "output": result.stdout,
                    "command": ' '.join(cmd)
                }

        except subprocess.TimeoutExpired:
            return {
                "error": "Chainsaw search timed out",
                "timeout_seconds": 300
            }
        except Exception as e:
            return {
                "error": f"Chainsaw search failed: {str(e)}"
            }

    @classmethod
    def categorize_ioc_by_pyramid(cls, ioc_type: str, ioc_value: str) -> Dict:
        """
        Categorize an IoC by Pyramid of Pain level.

        Args:
            ioc_type: Type of IoC (ip, domain, hash, tool, ttp, etc.)
            ioc_value: Value of the IoC

        Returns:
            Dictionary with pyramid level and information
        """
        ioc_type_lower = ioc_type.lower()

        # Map IoC types to pyramid levels
        if ioc_type_lower in ["hash", "md5", "sha1", "sha256", "file_hash"]:
            level = 1
        elif ioc_type_lower in ["ip", "ipv4", "ipv6", "ip_address"]:
            level = 2
        elif ioc_type_lower in ["domain", "url", "fqdn", "hostname"]:
            level = 3
        elif ioc_type_lower in ["user_agent", "registry", "file_path", "artifact"]:
            level = 4
        elif ioc_type_lower in ["tool", "malware", "process_name", "binary"]:
            level = 5
        elif ioc_type_lower in ["ttp", "technique", "tactic", "procedure", "behavior"]:
            level = 6
        else:
            # Default to level 3 for unknown types
            level = 3

        pyramid_level = cls.PYRAMID_OF_PAIN[level]

        return {
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "pyramid_level": level,
            "pyramid_name": pyramid_level.name,
            "description": pyramid_level.description,
            "difficulty_to_change": pyramid_level.difficulty_to_change,
            "priority": 7 - level  # Invert for priority (level 6 TTPs = priority 1)
        }

    @classmethod
    def map_to_diamond_model(cls, detection: Dict) -> Dict:
        """
        Map a detection to the Diamond Model of Intrusion Analysis.

        Args:
            detection: Detection result from chainsaw

        Returns:
            Dictionary with Diamond Model mapping
        """
        diamond_mapping = {
            "adversary": {
                "identified": False,
                "elements": []
            },
            "capability": {
                "identified": False,
                "elements": []
            },
            "infrastructure": {
                "identified": False,
                "elements": []
            },
            "victim": {
                "identified": False,
                "elements": []
            }
        }

        # Extract information from detection
        # Chainsaw detection structure: document.data.Event.System/EventData
        if not isinstance(detection, dict):
            return diamond_mapping

        if "document" in detection:
            doc = detection.get("document", {})
            if not isinstance(doc, dict):
                return diamond_mapping
            data = doc.get("data", {})

            # Handle Chainsaw's Event structure
            if not isinstance(data, dict):
                return diamond_mapping
            event = data.get("Event", {})
            if not isinstance(event, dict):
                return diamond_mapping
            system = event.get("System", {}) if isinstance(event.get("System"), dict) else {}
            event_data = event.get("EventData", {}) if isinstance(event.get("EventData"), dict) else {}

            # Victim identification - from System.Computer
            computer = system.get("Computer")
            if computer:
                diamond_mapping["victim"]["identified"] = True
                diamond_mapping["victim"]["elements"].append({
                    "type": "host",
                    "value": computer
                })

            # User from EventData
            target_user = event_data.get("TargetUserName") or event_data.get("SubjectUserName")
            if target_user:
                diamond_mapping["victim"]["identified"] = True
                diamond_mapping["victim"]["elements"].append({
                    "type": "user",
                    "value": target_user
                })

            # Infrastructure identification - from EventData
            ip_address = event_data.get("IpAddress") or event_data.get("SourceAddress") or event_data.get("DestAddress")
            if ip_address:
                diamond_mapping["infrastructure"]["identified"] = True
                diamond_mapping["infrastructure"]["elements"].append({
                    "type": "ip",
                    "value": ip_address
                })

            # Capability identification - from EventData
            image = event_data.get("Image") or event_data.get("SourceImage") or event_data.get("ProcessName")
            if image:
                diamond_mapping["capability"]["identified"] = True
                diamond_mapping["capability"]["elements"].append({
                    "type": "tool",
                    "value": image
                })

            command_line = event_data.get("CommandLine")
            if command_line:
                diamond_mapping["capability"]["identified"] = True
                diamond_mapping["capability"]["elements"].append({
                    "type": "technique",
                    "value": command_line
                })

        return diamond_mapping
