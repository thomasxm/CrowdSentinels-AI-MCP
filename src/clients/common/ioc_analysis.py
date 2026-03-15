"""IoC Analysis and Decision-Making Client for incident response."""
from typing import Dict, List, Optional, Tuple
import json
from datetime import datetime

from src.clients.base import SearchClientBase


class IoCAnalysisClient(SearchClientBase):
    """Client for analyzing IoCs and making incident response decisions."""

    # Pyramid of Pain - prioritize IoCs based on difficulty to change
    PYRAMID_OF_PAIN = {
        "hash": {"priority": 1, "difficulty": "Trivial", "description": "Easily changed by attackers"},
        "ip": {"priority": 2, "difficulty": "Easy", "description": "Can be changed quickly"},
        "domain": {"priority": 3, "difficulty": "Simple", "description": "Takes some effort to change"},
        "network_artifact": {"priority": 4, "difficulty": "Annoying", "description": "Requires infrastructure changes"},
        "tool": {"priority": 5, "difficulty": "Challenging", "description": "Requires tool development"},
        "ttps": {"priority": 6, "difficulty": "Tough", "description": "Fundamental behavior patterns"}
    }

    # MITRE ATT&CK mapping for common Windows events
    MITRE_ATTACK_MAPPING = {
        # Authentication
        "4624": {"technique": "T1078", "tactic": "Defense Evasion", "name": "Valid Accounts"},
        "4625": {"technique": "T1110", "tactic": "Credential Access", "name": "Brute Force"},
        "4648": {"technique": "T1078", "tactic": "Credential Access", "name": "Explicit Credential Logon"},
        "4672": {"technique": "T1078.002", "tactic": "Privilege Escalation", "name": "Admin Account"},
        # Process execution
        "1": {"technique": "T1059", "tactic": "Execution", "name": "Process Creation (Sysmon)"},
        "4688": {"technique": "T1059", "tactic": "Execution", "name": "Command and Scripting Interpreter"},
        # PowerShell
        "4103": {"technique": "T1059.001", "tactic": "Execution", "name": "PowerShell Module Logging"},
        "4104": {"technique": "T1059.001", "tactic": "Execution", "name": "PowerShell ScriptBlock Logging"},
        "40961": {"technique": "T1059.001", "tactic": "Execution", "name": "PowerShell Console Start"},
        "40962": {"technique": "T1059.001", "tactic": "Execution", "name": "PowerShell Console Ready"},
        "53504": {"technique": "T1059.001", "tactic": "Execution", "name": "PowerShell IPC Channel"},
        # Persistence
        "4697": {"technique": "T1543.003", "tactic": "Persistence", "name": "Windows Service"},
        "4698": {"technique": "T1053.005", "tactic": "Persistence", "name": "Scheduled Task"},
        "4720": {"technique": "T1136.001", "tactic": "Persistence", "name": "Create Account"},
        "4732": {"technique": "T1098", "tactic": "Persistence", "name": "Account Manipulation"},
        "7045": {"technique": "T1543.003", "tactic": "Persistence", "name": "Service Install"},
        # Discovery
        "4799": {"technique": "T1069.001", "tactic": "Discovery", "name": "Local Group Enumeration"},
        # Lateral movement
        "5140": {"technique": "T1021.002", "tactic": "Lateral Movement", "name": "SMB/Windows Admin Shares"},
        "5145": {"technique": "T1021.002", "tactic": "Lateral Movement", "name": "SMB Share Access"},
        # Credential access
        "10": {"technique": "T1003.001", "tactic": "Credential Access", "name": "LSASS Process Access (Sysmon)"},
        "4663": {"technique": "T1003.003", "tactic": "Credential Access", "name": "NTDS.dit Access"},
        # Defense evasion
        "1102": {"technique": "T1070.001", "tactic": "Defense Evasion", "name": "Security Log Cleared"},
        "4657": {"technique": "T1112", "tactic": "Defense Evasion", "name": "Registry Modification"},
        # Network
        "3": {"technique": "T1071", "tactic": "Command and Control", "name": "Network Connection (Sysmon)"},
        "5156": {"technique": "T1071", "tactic": "Command and Control", "name": "Windows Filtering Platform Connection"},
    }

    # Content-based patterns for MITRE mapping when event codes alone are insufficient.
    # Checked against event message/command_line content.
    MITRE_CONTENT_PATTERNS = {
        "MiniDumpWriteDump": {"technique": "T1003.001", "tactic": "Credential Access", "name": "LSASS Memory Dump"},
        "lsass": {"technique": "T1003.001", "tactic": "Credential Access", "name": "LSASS Access"},
        "mimikatz": {"technique": "T1003.001", "tactic": "Credential Access", "name": "Mimikatz"},
        "sekurlsa": {"technique": "T1003.001", "tactic": "Credential Access", "name": "Sekurlsa Module"},
        "Invoke-Mimikatz": {"technique": "T1003.001", "tactic": "Credential Access", "name": "Invoke-Mimikatz"},
        "-EncodedCommand": {"technique": "T1027", "tactic": "Defense Evasion", "name": "Encoded PowerShell"},
        "-enc ": {"technique": "T1027", "tactic": "Defense Evasion", "name": "Encoded PowerShell"},
        "FromBase64String": {"technique": "T1027", "tactic": "Defense Evasion", "name": "Base64 Decode"},
        "Net.WebClient": {"technique": "T1105", "tactic": "Command and Control", "name": "PowerShell Download"},
        "DownloadString": {"technique": "T1105", "tactic": "Command and Control", "name": "Remote Download"},
        "DownloadFile": {"technique": "T1105", "tactic": "Command and Control", "name": "Remote Download"},
        "Invoke-WebRequest": {"technique": "T1105", "tactic": "Command and Control", "name": "Web Request Download"},
        "psexec": {"technique": "T1021.002", "tactic": "Lateral Movement", "name": "PsExec"},
        "wmic": {"technique": "T1047", "tactic": "Execution", "name": "WMI Command"},
        "whoami": {"technique": "T1033", "tactic": "Discovery", "name": "System Owner Discovery"},
        "net user": {"technique": "T1087.001", "tactic": "Discovery", "name": "Local Account Discovery"},
        "reg save": {"technique": "T1003.002", "tactic": "Credential Access", "name": "SAM Registry Dump"},
        "ntdsutil": {"technique": "T1003.003", "tactic": "Credential Access", "name": "NTDS.dit Dump"},
        "vssadmin": {"technique": "T1003.003", "tactic": "Credential Access", "name": "Volume Shadow Copy"},
        "procdump": {"technique": "T1003.001", "tactic": "Credential Access", "name": "ProcDump LSASS"},
    }

    def analyze_search_results(self, search_results: Dict, context: str = "") -> Dict:
        """
        Analyze search results and provide insights with follow-up recommendations.

        Args:
            search_results: Results from a search query (supports multiple formats)
            context: Context about what was searched for

        Returns:
            Analysis with insights, IoCs, and recommended follow-up queries

        Supported formats:
            1. Standard ES: {"hits": {"hits": [...], "total": {"value": N}}}
            2. Simplified:  {"hits": [...], "total": N}
            3. Smart search: {"hits": [...], "total_hits": N}
        """
        analysis = {
            "timestamp": datetime.utcnow().isoformat(),
            "context": context,
            "summary": {},
            "iocs_found": [],
            "mitre_attack_techniques": [],
            "severity_assessment": "unknown",
            "recommended_followup": [],
            "raw_insights": []
        }

        # Extract total hits and events - handle multiple input formats:
        #   1. Standard ES:     {"hits": {"hits": [...], "total": {"value": N}}}
        #   2. Simplified:      {"hits": [...], "total": N}
        #   3. Smart search:    {"hits": [...], "total_hits": N}
        #   4. Hunt CLI output: {"sample_events": [...], "summary": {"total_hits": N}}
        hits_data = search_results.get("hits", {})

        # Check for hunt CLI output format first (sample_events + summary)
        if "sample_events" in search_results:
            events = search_results["sample_events"]
            summary_data = search_results.get("summary", {})
            total_hits = summary_data.get("total_hits", len(events)) if isinstance(summary_data, dict) else len(events)
            # Carry forward any IoCs and MITRE mappings already computed by hunt
            if search_results.get("iocs"):
                analysis["piped_iocs"] = search_results["iocs"]
            if search_results.get("mitre_techniques"):
                analysis["piped_mitre"] = search_results["mitre_techniques"]
        elif isinstance(hits_data, list):
            # Simplified format: {"hits": [...], "total": N}
            events = hits_data
            total_hits = search_results.get("total", search_results.get("total_hits", len(events)))
        elif isinstance(hits_data, dict):
            # Standard ES format: {"hits": {"hits": [...], "total": {"value": N}}}
            events = hits_data.get("hits", [])
            total_data = hits_data.get("total", {})
            if isinstance(total_data, dict):
                total_hits = total_data.get("value", 0)
            else:
                total_hits = total_data if isinstance(total_data, int) else 0
        else:
            events = []
            total_hits = 0

        analysis["summary"]["total_events"] = total_hits

        if total_hits == 0 and len(events) == 0:
            analysis["summary"]["status"] = "No suspicious activity detected"
            analysis["severity_assessment"] = "low"
            return analysis
        analysis["summary"]["events_analyzed"] = len(events)

        # Extract IoCs from events
        iocs = self._extract_iocs_from_events(events)
        analysis["iocs_found"] = iocs

        # Map to MITRE ATT&CK
        techniques = self._map_to_mitre_attack(events)
        analysis["mitre_attack_techniques"] = techniques

        # Assess severity
        severity = self._assess_severity(total_hits, iocs, techniques)
        analysis["severity_assessment"] = severity

        # Generate insights
        insights = self._generate_insights(events, iocs, techniques)
        analysis["raw_insights"] = insights

        # Recommend follow-up queries
        followup = self._recommend_followup_queries(iocs, events, context)
        analysis["recommended_followup"] = followup

        return analysis

    def _extract_iocs_from_events(self, events: List[Dict]) -> List[Dict]:
        """Extract IoCs from event data.

        Handles both standard ES format (with _source wrapper) and simplified format
        (direct documents).
        """
        iocs = []
        seen = set()

        for event in events:
            # Handle both formats: {"_source": {...}} or direct document
            source = event.get("_source", event) if isinstance(event, dict) else {}

            # Extract IPs
            for ip_field in ["source.ip", "destination.ip", "client.ip"]:
                ip = self._get_nested_value(source, ip_field)
                if ip and ip not in seen:
                    iocs.append({
                        "type": "ip",
                        "value": ip,
                        "pyramid_priority": self.PYRAMID_OF_PAIN["ip"]["priority"],
                        "field": ip_field
                    })
                    seen.add(ip)

            # Extract usernames
            user = self._get_nested_value(source, "user.name")
            if user and user not in seen and user != "SYSTEM":
                iocs.append({
                    "type": "user",
                    "value": user,
                    "pyramid_priority": 4,  # Network artifact level
                    "field": "user.name"
                })
                seen.add(user)

            # Extract process names
            process = self._get_nested_value(source, "winlog.event_data.NewProcessName")
            if process and process not in seen:
                iocs.append({
                    "type": "process",
                    "value": process,
                    "pyramid_priority": self.PYRAMID_OF_PAIN["tool"]["priority"],
                    "field": "winlog.event_data.NewProcessName"
                })
                seen.add(process)

            # Extract command lines (TTPs)
            cmdline = self._get_nested_value(source, "winlog.event_data.CommandLine")
            if cmdline and cmdline not in seen:
                iocs.append({
                    "type": "commandline",
                    "value": cmdline,
                    "pyramid_priority": self.PYRAMID_OF_PAIN["ttps"]["priority"],
                    "field": "winlog.event_data.CommandLine"
                })
                seen.add(cmdline)

            # Extract hostnames
            hostname = self._get_nested_value(source, "host.name")
            if hostname and hostname not in seen:
                iocs.append({
                    "type": "hostname",
                    "value": hostname,
                    "pyramid_priority": 3,
                    "field": "host.name"
                })
                seen.add(hostname)

        # Sort by pyramid priority (higher priority first)
        iocs.sort(key=lambda x: x["pyramid_priority"], reverse=True)

        return iocs

    def _map_to_mitre_attack(self, events: List[Dict]) -> List[Dict]:
        """Map events to MITRE ATT&CK techniques.

        Uses two detection methods:
        1. Event code mapping — known Windows event IDs to MITRE techniques
        2. Content pattern matching — scans message/command_line for known
           attack tool signatures (e.g., MiniDumpWriteDump, mimikatz, psexec)

        Handles both standard ES format (with _source wrapper) and simplified format.
        """
        techniques = []
        seen_techniques = set()

        def _add_technique(technique_id, mapping, event_code=None):
            if technique_id not in seen_techniques:
                techniques.append({
                    "technique_id": technique_id,
                    "technique_name": mapping["name"],
                    "tactic": mapping["tactic"],
                    "event_code": event_code or "content",
                    "count": 1
                })
                seen_techniques.add(technique_id)
            else:
                for t in techniques:
                    if t["technique_id"] == technique_id:
                        t["count"] += 1

        for event in events:
            # Handle both formats: {"_source": {...}} or direct document
            source = event.get("_source", event) if isinstance(event, dict) else {}

            # Try multiple field names for event code
            event_code = (
                self._get_nested_value(source, "event.code") or
                source.get("code") or
                self._get_nested_value(source, "winlog.event_id")
            )

            # 1. Event code mapping
            if event_code and str(event_code) in self.MITRE_ATTACK_MAPPING:
                mapping = self.MITRE_ATTACK_MAPPING[str(event_code)]
                _add_technique(mapping["technique"], mapping, event_code)

            # 2. Content pattern matching — scan message and command_line
            content = " ".join(filter(None, [
                source.get("message", ""),
                self._get_nested_value(source, "process.command_line") or "",
                self._get_nested_value(source, "winlog.event_data.CommandLine") or "",
                self._get_nested_value(source, "process.executable") or "",
            ]))
            if content.strip():
                for pattern, mapping in self.MITRE_CONTENT_PATTERNS.items():
                    if pattern.lower() in content.lower():
                        _add_technique(mapping["technique"], mapping)

        return techniques

    def _assess_severity(self, total_hits: int, iocs: List[Dict],
                        techniques: List[Dict]) -> str:
        """Assess severity based on findings.

        Severity is driven primarily by *what* was detected (technique
        criticality) and secondarily by volume.  A single LSASS dump is
        critical regardless of event count.
        """
        severity_score = 0

        # Factor 1: Volume of events (minor weight)
        if total_hits > 100:
            severity_score += 2
        elif total_hits > 10:
            severity_score += 1

        # Factor 2: High-priority IoCs (TTPs — Pyramid of Pain level 5+)
        high_priority_iocs = [ioc for ioc in iocs if ioc.get("pyramid_priority", 0) >= 5]
        severity_score += min(len(high_priority_iocs), 3)

        # Factor 3: MITRE ATT&CK techniques — weighted by criticality
        critical_tactics = {"Credential Access", "Privilege Escalation", "Lateral Movement"}
        high_tactics = {"Execution", "Defense Evasion", "Command and Control"}
        critical_techniques = {"T1003", "T1003.001", "T1003.002", "T1003.003"}  # Credential dumping

        for technique in techniques:
            tid = technique.get("technique_id", "")
            tactic = technique.get("tactic", "")

            # Credential dumping techniques are always critical
            if tid in critical_techniques or any(tid.startswith(ct) for ct in critical_techniques):
                severity_score += 5
            elif tactic in critical_tactics:
                severity_score += 3
            elif tactic in high_tactics:
                severity_score += 2
            else:
                severity_score += 1

        # Determine severity level
        if severity_score >= 7:
            return "critical"
        elif severity_score >= 4:
            return "high"
        elif severity_score >= 2:
            return "medium"
        else:
            return "low"

    def _generate_insights(self, events: List[Dict], iocs: List[Dict],
                          techniques: List[Dict]) -> List[str]:
        """Generate human-readable insights from the analysis."""
        insights = []

        # Event volume insights
        if len(events) > 50:
            insights.append(f"HIGH VOLUME: Detected {len(events)} security events, indicating significant activity")

        # IoC insights
        user_iocs = [ioc for ioc in iocs if ioc["type"] == "user"]
        if len(user_iocs) > 3:
            insights.append(f"MULTIPLE USERS: {len(user_iocs)} different user accounts involved")

        hostname_iocs = [ioc for ioc in iocs if ioc["type"] == "hostname"]
        if len(hostname_iocs) > 1:
            insights.append(f"LATERAL SPREAD: Activity detected across {len(hostname_iocs)} different hosts")

        # Command line insights
        cmdline_iocs = [ioc for ioc in iocs if ioc["type"] == "commandline"]
        suspicious_keywords = ["encoded", "bypass", "hidden", "download", "invoke"]
        for cmdline in cmdline_iocs:
            for keyword in suspicious_keywords:
                if keyword.lower() in cmdline["value"].lower():
                    insights.append(f"SUSPICIOUS COMMAND: Detected '{keyword}' in command line execution")
                    break

        # MITRE ATT&CK insights
        if techniques:
            tactics = set(t["tactic"] for t in techniques)
            insights.append(f"MITRE ATT&CK: Detected techniques from {len(tactics)} different tactics: {', '.join(tactics)}")

        # Specific technique insights
        for technique in techniques:
            if technique["count"] > 5:
                insights.append(f"REPEATED TECHNIQUE: {technique['technique_name']} ({technique['technique_id']}) occurred {technique['count']} times")

        return insights

    def _recommend_followup_queries(self, iocs: List[Dict], events: List[Dict],
                                   context: str) -> List[Dict]:
        """Recommend follow-up queries based on findings."""
        recommendations = []

        # Prioritize by Pyramid of Pain (investigate high-priority IoCs first)
        high_priority_iocs = [ioc for ioc in iocs if ioc["pyramid_priority"] >= 4]

        for ioc in high_priority_iocs[:5]:  # Top 5 high-priority IoCs
            if ioc["type"] == "user":
                recommendations.append({
                    "priority": "high",
                    "reason": f"Investigate all activity for user '{ioc['value']}'",
                    "tool": "get_host_activity_timeline",
                    "parameters": {
                        "search_scope": "all_indices",
                        "ioc": ioc["value"],
                        "ioc_type": "user"
                    },
                    "query_description": f"Search for all events involving user {ioc['value']} to understand scope"
                })

            elif ioc["type"] == "hostname":
                recommendations.append({
                    "priority": "high",
                    "reason": f"Perform forensic timeline analysis on host '{ioc['value']}'",
                    "tool": "get_host_activity_timeline",
                    "parameters": {
                        "hostname": ioc["value"],
                        "timeframe": "extended"
                    },
                    "query_description": f"Get complete activity timeline for {ioc['value']}"
                })

            elif ioc["type"] == "process":
                recommendations.append({
                    "priority": "medium",
                    "reason": f"Search for other instances of process '{ioc['value']}'",
                    "tool": "hunt_for_ioc",
                    "parameters": {
                        "ioc": ioc["value"],
                        "ioc_type": "process"
                    },
                    "query_description": f"Find all executions of {ioc['value']} across the environment"
                })

        # Recommend correlation queries
        if len(high_priority_iocs) > 1:
            recommendations.append({
                "priority": "high",
                "reason": "Correlate multiple IoCs to identify attack chain",
                "tool": "custom_correlation",
                "parameters": {
                    "iocs": [ioc["value"] for ioc in high_priority_iocs[:3]]
                },
                "query_description": "Build timeline showing relationship between identified IoCs"
            })

        return recommendations

    def _get_nested_value(self, data: Dict, path: str) -> Optional[str]:
        """Get value from nested dictionary using dot notation."""
        keys = path.split(".")
        value = data
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None
        return value

    def generate_investigation_report(self, analysis_results: List[Dict],
                                     investigation_context: str) -> Dict:
        """
        Generate a comprehensive investigation report from multiple analyses.

        Args:
            analysis_results: List of analysis results from multiple queries
            investigation_context: Context of the investigation

        Returns:
            Comprehensive investigation report
        """
        report = {
            "report_id": f"IR-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
            "generated_at": datetime.utcnow().isoformat(),
            "investigation_context": investigation_context,
            "executive_summary": "",
            "total_queries_executed": len(analysis_results),
            "all_iocs": [],
            "all_techniques": [],
            "affected_hosts": set(),
            "affected_users": set(),
            "timeline": [],
            "severity": "unknown",
            "recommendations": []
        }

        # Aggregate all IoCs
        for analysis in analysis_results:
            for ioc in analysis.get("iocs_found", []):
                # Handle both dict IoCs and simple values
                if isinstance(ioc, dict):
                    if ioc not in report["all_iocs"]:
                        report["all_iocs"].append(ioc)
                elif isinstance(ioc, str):
                    # Convert string IoC to dict format
                    ioc_dict = {"type": "unknown", "value": ioc}
                    if ioc_dict not in report["all_iocs"]:
                        report["all_iocs"].append(ioc_dict)

            # Collect affected hosts/users
            for ioc in analysis.get("iocs_found", []):
                if isinstance(ioc, dict):
                    if ioc.get("type") == "hostname":
                        report["affected_hosts"].add(ioc.get("value", ""))
                    elif ioc.get("type") == "user":
                        report["affected_users"].add(ioc.get("value", ""))

            # Aggregate MITRE techniques
            for technique in analysis.get("mitre_attack_techniques", []):
                # Handle both dict techniques and string technique IDs
                if isinstance(technique, str):
                    # Convert string to dict format
                    technique = {"technique_id": technique, "technique_name": technique, "tactic": "Unknown", "count": 1}

                if not isinstance(technique, dict):
                    continue

                technique_id = technique.get("technique_id", "")
                existing = next((t for t in report["all_techniques"]
                               if t.get("technique_id") == technique_id), None)
                if existing:
                    existing["count"] = existing.get("count", 0) + technique.get("count", 1)
                else:
                    # Safe copy - handle both dict and other types
                    if hasattr(technique, 'copy'):
                        report["all_techniques"].append(technique.copy())
                    else:
                        report["all_techniques"].append(dict(technique))

        # Convert sets to lists for JSON serialization
        report["affected_hosts"] = list(report["affected_hosts"])
        report["affected_users"] = list(report["affected_users"])

        # Determine overall severity
        severities = [a.get("severity_assessment", "low") for a in analysis_results]
        if "critical" in severities:
            report["severity"] = "critical"
        elif "high" in severities:
            report["severity"] = "high"
        elif "medium" in severities:
            report["severity"] = "medium"
        else:
            report["severity"] = "low"

        # Generate executive summary
        report["executive_summary"] = self._generate_executive_summary(report)

        # Aggregate recommendations
        for analysis in analysis_results:
            report["recommendations"].extend(analysis.get("recommended_followup", []))

        return report

    def _generate_executive_summary(self, report: Dict) -> str:
        """Generate executive summary for the report."""
        summary_parts = []

        # Severity statement
        summary_parts.append(f"SEVERITY: {report['severity'].upper()}")

        # Scope statement
        if report["affected_hosts"]:
            summary_parts.append(f"Affected {len(report['affected_hosts'])} host(s)")

        if report["affected_users"]:
            summary_parts.append(f"Involving {len(report['affected_users'])} user account(s)")

        # IoC summary
        if report["all_iocs"]:
            ioc_types = {}
            for ioc in report["all_iocs"]:
                ioc_types[ioc["type"]] = ioc_types.get(ioc["type"], 0) + 1

            ioc_summary = ", ".join([f"{count} {ioc_type}(s)" for ioc_type, count in ioc_types.items()])
            summary_parts.append(f"Identified: {ioc_summary}")

        # MITRE ATT&CK summary
        if report["all_techniques"]:
            tactics = set(t["tactic"] for t in report["all_techniques"])
            summary_parts.append(f"MITRE ATT&CK Tactics: {', '.join(tactics)}")

        return " | ".join(summary_parts)
