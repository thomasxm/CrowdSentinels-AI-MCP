"""Threat Hunting Client for incident response and threat detection."""
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
import json
import logging

from src.clients.base import SearchClientBase
from src.clients.common.field_mapper import FieldMapper
from src.utils import limit_response_size, summarize_search_response

logger = logging.getLogger(__name__)


class ThreatHuntingClient(SearchClientBase):
    """Client for threat hunting operations and incident response."""

    def __init__(self, config: Dict, engine_type: str = "elasticsearch"):
        """
        Initialise the threat hunting client.

        Args:
            config: Configuration dictionary with connection parameters
            engine_type: Backend type (elasticsearch or opensearch)
        """
        super().__init__(config, engine_type)
        # Initialise FieldMapper for field name substitution
        self._field_mapper: Optional[FieldMapper] = None

    @property
    def field_mapper(self) -> FieldMapper:
        """Get or create the FieldMapper instance with ES client reference."""
        if self._field_mapper is None:
            self._field_mapper = FieldMapper(client=self.client)
        return self._field_mapper

    # Windows Security Event IDs
    WINDOWS_EVENT_IDS = {
        "4624": "Successful Logon",
        "4625": "Failed Logon",
        "4672": "Special Privileges Assigned",
        "4688": "Process Creation",
        "4689": "Process Termination",
        "4697": "Service Installed",
        "4698": "Scheduled Task Created",
        "4699": "Scheduled Task Deleted",
        "4700": "Scheduled Task Enabled",
        "4701": "Scheduled Task Disabled",
        "4702": "Scheduled Task Updated",
        "4720": "User Account Created",
        "4722": "User Account Enabled",
        "4724": "Password Reset Attempt",
        "4725": "User Account Disabled",
        "4726": "User Account Deleted",
        "4732": "User Added to Security Group",
        "4733": "User Removed from Security Group",
        "4738": "User Account Changed",
        "4740": "User Account Locked",
        "4756": "Member Added to Global Security Group",
        "4768": "Kerberos TGT Requested",
        "4769": "Kerberos Service Ticket Requested",
        "4776": "Domain Controller Credential Validation",
        "5140": "Network Share Accessed",
        "5145": "Network Share Object Access",
    }

    # Common attack patterns
    ATTACK_PATTERNS = {
        "brute_force": {
            "description": "Brute force authentication attempts",
            "event_codes": ["4625", "4776"],
            "threshold": 5,
            "timeframe_minutes": 5
        },
        "privilege_escalation": {
            "description": "Privilege escalation attempts",
            "event_codes": ["4672", "4673", "4674"],
            "indicators": ["SeDebugPrivilege", "SeImpersonatePrivilege"]
        },
        "lateral_movement": {
            "description": "Lateral movement indicators",
            "event_codes": ["4624", "4648", "4672"],
            "logon_types": ["3", "10"]  # Network, Remote Interactive
        },
        "persistence": {
            "description": "Persistence mechanisms",
            "event_codes": ["4697", "4698", "4720", "4732"]
        },
        "suspicious_process": {
            "description": "Suspicious process execution",
            "event_codes": ["4688"],
            "processes": [
                "powershell.exe",
                "cmd.exe",
                "wscript.exe",
                "cscript.exe",
                "mshta.exe",
                "rundll32.exe",
                "regsvr32.exe",
                "certutil.exe",
                "bitsadmin.exe"
            ]
        },
        "encoded_commands": {
            "description": "Encoded PowerShell commands",
            "event_codes": ["4688"],
            "indicators": ["-EncodedCommand", "-enc", "-e ", "frombase64"]
        },
        "credential_access": {
            "description": "Credential dumping attempts",
            "event_codes": ["4688", "4656"],
            "processes": ["lsass.exe", "mimikatz", "procdump"]
        },
        "port_scan": {
            "description": "Port scanning activity",
            "threshold": 1000,
            "timeframe_minutes": 15
        }
    }

    def hunt_by_timeframe(self, index: str, attack_types: List[str],
                         start_time: str, end_time: Optional[str] = None,
                         host: Optional[str] = None) -> Dict:
        """
        Hunt for specific attack patterns within a timeframe.

        Args:
            index: Index pattern to search
            attack_types: List of attack types to hunt for
            start_time: Start time (e.g., "now-15m", "2024-01-01T00:00:00")
            end_time: End time (optional, defaults to "now")
            host: Specific host to investigate (optional)

        Returns:
            Dictionary with findings for each attack type
        """
        if end_time is None:
            end_time = "now"

        findings = {
            "search_timeframe": {"start": start_time, "end": end_time},
            "host_filter": host,
            "attack_patterns": {}
        }

        for attack_type in attack_types:
            if attack_type not in self.ATTACK_PATTERNS:
                self.logger.warning(f"Unknown attack type: {attack_type}")
                continue

            pattern = self.ATTACK_PATTERNS[attack_type]
            query = self._build_attack_query(pattern, start_time, end_time, host)

            try:
                result = self.client.search(index=index, body=query)
                findings["attack_patterns"][attack_type] = {
                    "description": pattern["description"],
                    "total_hits": result["hits"]["total"]["value"],
                    "events": result["hits"]["hits"][:50]  # Limit to 50 events per attack type
                }
            except Exception as e:
                self.logger.error(f"Failed to hunt for {attack_type}: {e}")
                findings["attack_patterns"][attack_type] = {
                    "error": str(e)
                }

        # Apply response size limiting to entire result
        return limit_response_size(findings)

    def _build_attack_query(self, pattern: Dict, start_time: str,
                           end_time: str, host: Optional[str] = None) -> Dict:
        """Build Elasticsearch query for attack pattern."""
        must_clauses = []
        should_clauses = []

        # Time range filter
        must_clauses.append({
            "range": {
                "@timestamp": {
                    "gte": start_time,
                    "lte": end_time
                }
            }
        })

        # Event code filter
        if "event_codes" in pattern:
            should_clauses.extend([
                {"term": {"event.code": code}}
                for code in pattern["event_codes"]
            ])

        # Host filter
        if host:
            must_clauses.append({
                "term": {"host.name.keyword": host}
            })

        # Process name filter
        if "processes" in pattern:
            process_clauses = []
            for proc in pattern["processes"]:
                process_clauses.append({
                    "wildcard": {
                        "winlog.event_data.NewProcessName": f"*{proc}*"
                    }
                })
            should_clauses.extend(process_clauses)

        # Command line indicators
        if "indicators" in pattern:
            for indicator in pattern["indicators"]:
                should_clauses.append({
                    "wildcard": {
                        "winlog.event_data.CommandLine": f"*{indicator}*"
                    }
                })

        query = {
            "query": {
                "bool": {
                    "must": must_clauses,
                    "should": should_clauses,
                    "minimum_should_match": 1 if should_clauses else 0
                }
            },
            "size": 100,
            "sort": [{"@timestamp": "desc"}]
        }

        return query

    def analyze_failed_logins(self, index: str, timeframe_minutes: int = 15,
                             threshold: int = 5) -> Dict:
        """
        Analyze failed login attempts (potential brute force).

        Args:
            index: Index pattern
            timeframe_minutes: Time window to analyze
            threshold: Minimum failed attempts to report

        Returns:
            Analysis results with suspicious accounts/hosts
        """
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"event.code": "4625"}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": f"now-{timeframe_minutes}m"
                                }
                            }
                        }
                    ]
                }
            },
            "size": 0,
            "aggs": {
                "by_user": {
                    "terms": {
                        "field": "user.name.keyword",
                        "size": 50,
                        "min_doc_count": threshold
                    },
                    "aggs": {
                        "by_host": {
                            "terms": {
                                "field": "host.name.keyword",
                                "size": 10
                            }
                        },
                        "by_source_ip": {
                            "terms": {
                                "field": "source.ip",
                                "size": 10
                            }
                        }
                    }
                },
                "by_host": {
                    "terms": {
                        "field": "host.name.keyword",
                        "size": 50,
                        "min_doc_count": threshold
                    }
                }
            }
        }

        try:
            result = self.client.search(index=index, body=query)
            return limit_response_size({
                "total_failed_logins": result["hits"]["total"]["value"],
                "suspicious_users": result["aggregations"]["by_user"]["buckets"][:20],  # Limit buckets
                "suspicious_hosts": result["aggregations"]["by_host"]["buckets"][:20],
                "timeframe_minutes": timeframe_minutes,
                "threshold": threshold
            })
        except Exception as e:
            self.logger.error(f"Failed to analyze failed logins: {e}")
            raise

    def analyze_process_creation(self, index: str, timeframe_minutes: int = 60,
                                process_filter: Optional[List[str]] = None) -> Dict:
        """
        Analyze process creation events for suspicious activity.

        Args:
            index: Index pattern
            timeframe_minutes: Time window
            process_filter: List of process names to filter (optional)

        Returns:
            Process creation analysis
        """
        must_clauses = [
            {"term": {"event.code": "4688"}},
            {
                "range": {
                    "@timestamp": {
                        "gte": f"now-{timeframe_minutes}m"
                    }
                }
            }
        ]

        # Add process filter if provided
        if process_filter:
            should_clauses = [
                {"wildcard": {"winlog.event_data.NewProcessName": f"*{proc}*"}}
                for proc in process_filter
            ]
            must_clauses.append({
                "bool": {
                    "should": should_clauses,
                    "minimum_should_match": 1
                }
            })

        query = {
            "query": {
                "bool": {
                    "must": must_clauses
                }
            },
            "size": 100,
            "sort": [{"@timestamp": "desc"}],
            "_source": [
                "@timestamp",
                "host.name",
                "user.name",
                "winlog.event_data.NewProcessName",
                "winlog.event_data.CommandLine",
                "winlog.event_data.ParentProcessName"
            ]
        }

        try:
            result = self.client.search(index=index, body=query)
            return {
                "total_processes": result["hits"]["total"]["value"],
                "processes": result["hits"]["hits"],
                "timeframe_minutes": timeframe_minutes
            }
        except Exception as e:
            self.logger.error(f"Failed to analyze process creation: {e}")
            raise

    def hunt_for_ioc(self, index: str, ioc: str, ioc_type: str,
                    timeframe_minutes: Optional[int] = None) -> Dict:
        """
        Hunt for a specific Indicator of Compromise (IoC).

        Args:
            index: Index pattern
            ioc: The IoC value (IP, domain, hash, filename, etc.)
            ioc_type: Type of IoC (ip, domain, hash, filename, process, user)
            timeframe_minutes: Optional time window

        Returns:
            IoC hunting results
        """
        # Map IoC type to field names
        field_mapping = {
            "ip": ["source.ip", "destination.ip", "client.ip", "server.ip"],
            "domain": ["dns.question.name", "url.domain", "destination.domain"],
            "hash": ["file.hash.md5", "file.hash.sha1", "file.hash.sha256"],
            "filename": ["file.name", "file.path", "winlog.event_data.TargetFilename"],
            "process": ["process.name", "winlog.event_data.NewProcessName"],
            "user": ["user.name", "winlog.event_data.TargetUserName"]
        }

        fields = field_mapping.get(ioc_type, [])
        if not fields:
            raise ValueError(f"Unknown IoC type: {ioc_type}")

        # Build query
        should_clauses = []
        for field in fields:
            # Try both exact match and wildcard
            should_clauses.append({"term": {f"{field}.keyword": ioc}})
            should_clauses.append({"wildcard": {field: f"*{ioc}*"}})

        must_clauses = [
            {
                "bool": {
                    "should": should_clauses,
                    "minimum_should_match": 1
                }
            }
        ]

        # Add time filter if specified
        if timeframe_minutes:
            must_clauses.append({
                "range": {
                    "@timestamp": {
                        "gte": f"now-{timeframe_minutes}m"
                    }
                }
            })

        query = {
            "query": {
                "bool": {
                    "must": must_clauses
                }
            },
            "size": 100,
            "sort": [{"@timestamp": "desc"}]
        }

        try:
            result = self.client.search(index=index, body=query)
            return {
                "ioc": ioc,
                "ioc_type": ioc_type,
                "total_hits": result["hits"]["total"]["value"],
                "events": result["hits"]["hits"]
            }
        except Exception as e:
            self.logger.error(f"Failed to hunt for IoC: {e}")
            raise

    def get_host_activity_timeline(self, index: str, hostname: str,
                                   start_time: str, end_time: Optional[str] = None) -> Dict:
        """
        Get a timeline of all activity for a specific host.

        Args:
            index: Index pattern
            hostname: Hostname to investigate
            start_time: Start time
            end_time: End time (optional)

        Returns:
            Timeline of events
        """
        if end_time is None:
            end_time = "now"

        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"host.name.keyword": hostname}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_time,
                                    "lte": end_time
                                }
                            }
                        }
                    ]
                }
            },
            "size": 1000,
            "sort": [{"@timestamp": "asc"}],
            "_source": [
                "@timestamp",
                "event.code",
                "event.action",
                "user.name",
                "process.name",
                "winlog.event_data.NewProcessName",
                "winlog.event_data.CommandLine"
            ]
        }

        try:
            result = self.client.search(index=index, body=query)
            return {
                "hostname": hostname,
                "timeframe": {"start": start_time, "end": end_time},
                "total_events": result["hits"]["total"]["value"],
                "timeline": result["hits"]["hits"]
            }
        except Exception as e:
            self.logger.error(f"Failed to get host timeline: {e}")
            raise

    def search_with_lucene(self, index: str, lucene_query: str,
                          timeframe_minutes: Optional[int] = None,
                          size: int = 100,
                          field_substitution: bool = True) -> Dict:
        """
        Execute a Lucene query string search with automatic field substitution.

        Field substitution automatically adapts ECS field names to the actual
        field names in the target index (e.g., process.name -> winlog.event_data.Image).

        Args:
            index: Index pattern
            lucene_query: Lucene query string
            timeframe_minutes: Optional time window
            size: Number of results
            field_substitution: If True, substitute ECS fields with index-specific fields

        Returns:
            Search results with field substitution metadata
        """
        field_substitutions = {}

        # Apply field substitution if enabled
        if field_substitution:
            available_fields = self.field_mapper.get_index_fields(index)
            if available_fields:
                # Get substitution report for transparency
                sub_report = self.field_mapper.get_substitution_report(lucene_query, available_fields)
                field_substitutions = sub_report.get("substitutions", {})

                # Apply substitutions to the query
                lucene_query = self.field_mapper.substitute_fields_lucene(lucene_query, available_fields)

        must_clauses = [
            {
                "query_string": {
                    "query": lucene_query
                }
            }
        ]

        if timeframe_minutes:
            must_clauses.append({
                "range": {
                    "@timestamp": {
                        "gte": f"now-{timeframe_minutes}m"
                    }
                }
            })

        query = {
            "query": {
                "bool": {
                    "must": must_clauses
                }
            },
            "size": size,
            "sort": [{"@timestamp": "desc"}]
        }

        try:
            result = self.client.search(index=index, body=query)

            # Limit size to prevent context overflow
            limited_result = limit_response_size({
                "lucene_query": lucene_query,
                "total_hits": result["hits"]["total"]["value"],
                "events": result["hits"]["hits"]
            })

            # Add field substitution metadata
            if field_substitutions:
                limited_result["field_substitutions"] = {
                    "enabled": True,
                    "substitutions": field_substitutions,
                    "count": len(field_substitutions)
                }
            elif field_substitution:
                limited_result["field_substitutions"] = {
                    "enabled": True,
                    "substitutions": {},
                    "count": 0,
                    "note": "No field substitutions needed - fields already match"
                }

            return limited_result
        except Exception as e:
            self.logger.error(f"Lucene search failed: {e}")
            raise

    def execute_investigation_prompt(self, prompt_id: str, index: str,
                                    timeframe_minutes: int = 60,
                                    size: int = 100,
                                    additional_filters: Optional[Dict] = None) -> Dict:
        """
        Execute an investigation prompt query.

        Args:
            prompt_id: Investigation prompt ID
            index: Index pattern to search
            timeframe_minutes: Time window in minutes
            size: Maximum number of results
            additional_filters: Additional field filters (e.g., {"host.name": "server01"})

        Returns:
            Investigation results with metadata
        """
        from src.clients.common.investigation_prompts import InvestigationPromptsClient

        # Get the prompt
        prompt = InvestigationPromptsClient.get_prompt_by_id(prompt_id)
        if not prompt:
            return {
                "error": f"Prompt not found: {prompt_id}",
                "tip": "Use show_investigation_prompts() to see available prompts"
            }

        # Build the query with filters
        must_clauses = []

        # Add the base query template
        if prompt.query_template.startswith("event.code"):
            # Parse Lucene-style query
            must_clauses.append({
                "query_string": {
                    "query": prompt.query_template
                }
            })
        else:
            # Treat as a generic query string
            must_clauses.append({
                "query_string": {
                    "query": prompt.query_template
                }
            })

        # Add time range filter
        must_clauses.append({
            "range": {
                "@timestamp": {
                    "gte": f"now-{timeframe_minutes}m"
                }
            }
        })

        # Add additional filters
        if additional_filters:
            for field, value in additional_filters.items():
                if isinstance(value, list):
                    must_clauses.append({
                        "terms": {f"{field}.keyword": value}
                    })
                else:
                    must_clauses.append({
                        "term": {f"{field}.keyword": value}
                    })

        query = {
            "query": {
                "bool": {
                    "must": must_clauses
                }
            },
            "size": size,
            "sort": [{"@timestamp": "desc"}]
        }

        try:
            result = self.client.search(index=index, body=query)

            return {
                "prompt_id": prompt.id,
                "platform": prompt.platform.upper(),
                "priority": prompt.priority,
                "question": prompt.question,
                "description": prompt.description,
                "total_hits": result["hits"]["total"]["value"],
                "events": result["hits"]["hits"],
                "focus_areas": prompt.focus_areas,
                "mitre_tactics": prompt.mitre_tactics,
                "timeframe_minutes": timeframe_minutes
            }
        except Exception as e:
            self.logger.error(f"Investigation prompt execution failed: {e}")
            return {
                "error": f"Execution failed: {str(e)}",
                "prompt_id": prompt_id
            }
