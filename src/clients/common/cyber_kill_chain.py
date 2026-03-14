"""Lockheed Martin Cyber Kill Chain implementation for threat analysis."""
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class KillChainStage(Enum):
    """Lockheed Martin Cyber Kill Chain stages."""
    RECONNAISSANCE = 1
    WEAPONIZATION = 2
    DELIVERY = 3
    EXPLOITATION = 4
    INSTALLATION = 5
    COMMAND_AND_CONTROL = 6
    ACTIONS_ON_OBJECTIVES = 7


@dataclass
class KillChainStageInfo:
    """Information about a Cyber Kill Chain stage."""
    stage: KillChainStage
    name: str
    description: str
    indicators: List[str]
    typical_iocs: List[str]
    log_sources: List[str]
    event_codes: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    hunting_queries: Dict[str, str] = field(default_factory=dict)


class CyberKillChainClient:
    """Client for Cyber Kill Chain analysis and threat hunting."""

    # Complete Kill Chain stage definitions
    KILL_CHAIN_STAGES = {
        KillChainStage.RECONNAISSANCE: KillChainStageInfo(
            stage=KillChainStage.RECONNAISSANCE,
            name="Reconnaissance",
            description="Adversary gathers information about the target through various means (OSINT, scanning, enumeration)",
            indicators=[
                "Port scanning activity",
                "DNS enumeration",
                "WHOIS lookups",
                "Social media profiling",
                "Employee enumeration",
                "Network mapping",
                "Vulnerability scanning",
                "Web application probing"
            ],
            typical_iocs=[
                "Multiple failed connection attempts",
                "Unusual DNS queries",
                "Port scan signatures",
                "Web crawler activity",
                "Unusual external IPs scanning your network",
                "OSINT data collection"
            ],
            log_sources=[
                "Firewall logs",
                "IDS/IPS logs",
                "DNS logs",
                "Web server logs",
                "Network flow data",
                "Proxy logs"
            ],
            event_codes=[],
            mitre_tactics=["reconnaissance"],
            hunting_queries={
                "port_scans": "destination.port:* AND (event.action:denied OR event.action:blocked) | stats count by source.ip",
                "dns_enumeration": "event.category:dns AND dns.question.type:ANY",
                "web_scanning": "url.path:(*admin* OR *login* OR *wp-* OR *.env OR *.git) AND http.response.status_code:(401 OR 403 OR 404)",
                "failed_connections": "event.outcome:failure AND network.protocol:* | stats count by source.ip, destination.port"
            }
        ),

        KillChainStage.WEAPONIZATION: KillChainStageInfo(
            stage=KillChainStage.WEAPONIZATION,
            name="Weaponization",
            description="Adversary creates malicious payload (malware, exploit, document with macro) to exploit vulnerabilities",
            indicators=[
                "Malware creation",
                "Exploit development",
                "Malicious document creation",
                "Payload encoding/obfuscation",
                "C2 infrastructure setup",
                "Exploit kit usage"
            ],
            typical_iocs=[
                "File hashes of malware",
                "Malicious document signatures",
                "Exploit kit indicators",
                "Packer/crypter signatures",
                "Obfuscated code patterns"
            ],
            log_sources=[
                "Threat intelligence feeds",
                "Sandbox analysis logs",
                "Email security logs",
                "File analysis logs"
            ],
            event_codes=[],
            mitre_tactics=["resource_development"],
            hunting_queries={
                # Weaponization is typically not visible in victim logs
                # These are preparation activities on attacker infrastructure
            }
        ),

        KillChainStage.DELIVERY: KillChainStageInfo(
            stage=KillChainStage.DELIVERY,
            name="Delivery",
            description="Adversary delivers the weaponized payload to the target (email, web, USB, etc.)",
            indicators=[
                "Phishing emails",
                "Malicious attachments",
                "Drive-by downloads",
                "Watering hole attacks",
                "USB drops",
                "Malicious links",
                "Compromised websites"
            ],
            typical_iocs=[
                "Phishing email sender addresses",
                "Malicious URLs",
                "Suspicious file attachments",
                "Compromised legitimate sites",
                "Exploit kit domains",
                "Malicious advertising (malvertising)"
            ],
            log_sources=[
                "Email gateway logs",
                "Web proxy logs",
                "DNS logs",
                "Endpoint detection logs",
                "Network traffic logs",
                "URL filtering logs"
            ],
            event_codes=[],
            mitre_tactics=["initial_access"],
            hunting_queries={
                "phishing_emails": 'event.category:email AND (email.subject:(*invoice* OR *payment* OR *urgent* OR *verify*) OR email.attachments.file.extension:(exe OR scr OR zip OR rar OR js OR vbs))',
                "suspicious_downloads": 'event.category:file AND file.extension:(exe OR scr OR dll OR bat OR ps1 OR vbs OR js) AND url.domain:*',
                "malicious_urls": 'url.domain:* AND (url.path:*.exe OR url.path:*.zip OR url.path:*.ps1)',
                "web_exploits": 'http.response.status_code:200 AND url.path:(*exploit* OR *shellcode* OR *payload*)'
            }
        ),

        KillChainStage.EXPLOITATION: KillChainStageInfo(
            stage=KillChainStage.EXPLOITATION,
            name="Exploitation",
            description="Adversary exploits vulnerability to execute code on target system",
            indicators=[
                "Exploit execution",
                "Vulnerability exploitation",
                "Code execution",
                "Memory corruption",
                "Privilege escalation attempts",
                "Browser exploits",
                "Application crashes"
            ],
            typical_iocs=[
                "CVE exploitation indicators",
                "Exploit kit signatures",
                "Abnormal process execution",
                "Memory injection",
                "Shellcode execution",
                "Application crashes before payload"
            ],
            log_sources=[
                "Sysmon",
                "Windows Security logs",
                "EDR logs",
                "Application logs",
                "IDS/IPS logs",
                "Crash dumps"
            ],
            event_codes=["4688", "4624"],  # Process creation, logon
            mitre_tactics=["execution", "privilege_escalation"],
            hunting_queries={
                "exploit_attempts": 'event.action:exploited OR event.action:vulnerability_exploited',
                "suspicious_process_execution": 'process.parent.name:(winword.exe OR excel.exe OR powerpnt.exe OR acrord32.exe OR chrome.exe OR firefox.exe OR iexplore.exe) AND process.name:(powershell.exe OR cmd.exe OR wscript.exe OR cscript.exe OR mshta.exe OR rundll32.exe)',
                "memory_injection": 'event.category:process AND event.action:created AND process.args:(*VirtualAlloc* OR *WriteProcessMemory* OR *CreateRemoteThread*)',
                "shellcode_execution": 'process.command_line:(*IEX* OR *Invoke-Expression* OR *DownloadString* OR *EncodedCommand*)'
            }
        ),

        KillChainStage.INSTALLATION: KillChainStageInfo(
            stage=KillChainStage.INSTALLATION,
            name="Installation",
            description="Adversary installs malware and establishes persistence on the target system",
            indicators=[
                "Malware installation",
                "Persistence mechanisms",
                "Backdoor installation",
                "Registry modifications",
                "Scheduled tasks creation",
                "Service creation",
                "Startup folder modifications",
                "DLL hijacking"
            ],
            typical_iocs=[
                "File hashes of installed malware",
                "Registry keys modified",
                "Scheduled task names",
                "Service names",
                "Startup locations",
                "DLL paths",
                "User account creation"
            ],
            log_sources=[
                "Sysmon",
                "Windows Security logs",
                "Windows System logs",
                "EDR logs",
                "File integrity monitoring"
            ],
            event_codes=["4688", "7045", "4698", "4720", "4732"],  # Process, service, task, user creation
            mitre_tactics=["persistence", "defense_evasion"],
            hunting_queries={
                "service_creation": 'event.code:7045 OR (event.category:process AND process.name:sc.exe AND process.args:create)',
                "scheduled_task_creation": 'event.code:(4698 OR 4702) OR (process.name:schtasks.exe AND process.args:create)',
                "registry_run_keys": 'registry.path:(*\\Run OR *\\RunOnce OR *\\RunServices OR *\\RunServicesOnce) AND event.action:modified',
                "startup_persistence": 'file.path:(*\\Startup\\* OR *\\AppData\\Roaming\\Microsoft\\Windows\\Start*) AND event.action:created',
                "new_user_creation": 'event.code:4720',
                "dll_hijacking": 'file.extension:dll AND file.path:(*\\System32\\* OR *\\SysWOW64\\*) AND event.action:created',
                "malware_installation": 'file.path:(*\\AppData\\* OR *\\Temp\\* OR *\\ProgramData\\*) AND file.extension:(exe OR dll OR sys OR bat OR ps1) AND event.action:created'
            }
        ),

        KillChainStage.COMMAND_AND_CONTROL: KillChainStageInfo(
            stage=KillChainStage.COMMAND_AND_CONTROL,
            name="Command and Control (C2)",
            description="Adversary establishes command channel to control compromised system",
            indicators=[
                "C2 beaconing",
                "Outbound connections to known C2",
                "Unusual network traffic patterns",
                "DNS tunneling",
                "Encrypted channels",
                "Non-standard ports",
                "Periodic callbacks"
            ],
            typical_iocs=[
                "C2 IP addresses",
                "C2 domain names",
                "User agents",
                "URL patterns",
                "JA3 fingerprints",
                "Certificate hashes",
                "Beacon intervals"
            ],
            log_sources=[
                "Firewall logs",
                "Proxy logs",
                "DNS logs",
                "Network flow data",
                "SSL/TLS inspection logs",
                "EDR network logs"
            ],
            event_codes=[],
            mitre_tactics=["command_and_control"],
            hunting_queries={
                "c2_beaconing": 'destination.ip:* AND network.protocol:* | stats count by destination.ip, destination.port | where count > 100',
                "dns_tunneling": 'dns.question.name:* AND dns.question.type:(TXT OR NULL) | stats count by dns.question.name',
                "suspicious_tls": 'tls.client.ja3:* OR tls.server.ja3s:* AND destination.port:443',
                "unusual_ports": 'destination.port:(8080 OR 8443 OR 8888 OR 4444 OR 5555 OR 6666 OR 7777) AND network.direction:outbound',
                "long_connections": 'network.duration:>3600 AND network.direction:outbound',
                "rare_domains": 'dns.question.name:* AND NOT dns.question.name:(*microsoft* OR *google* OR *amazon* OR *cloudflare*) | rare dns.question.name',
                "base64_http": 'http.request.body.content:*==* OR http.response.body.content:*==*'
            }
        ),

        KillChainStage.ACTIONS_ON_OBJECTIVES: KillChainStageInfo(
            stage=KillChainStage.ACTIONS_ON_OBJECTIVES,
            name="Actions on Objectives",
            description="Adversary achieves their goal (data theft, destruction, encryption, lateral movement)",
            indicators=[
                "Data exfiltration",
                "File encryption (ransomware)",
                "Data destruction",
                "Lateral movement",
                "Credential theft",
                "System manipulation",
                "Service disruption"
            ],
            typical_iocs=[
                "Large data transfers",
                "File extensions changed (.encrypted)",
                "Credential dumping tools",
                "Lateral movement tools",
                "Mass file deletion",
                "Database dumps",
                "Compression tools usage"
            ],
            log_sources=[
                "Windows Security logs",
                "Sysmon",
                "Firewall logs",
                "DLP logs",
                "Database logs",
                "File server logs",
                "EDR logs"
            ],
            event_codes=["4624", "4648", "4672", "4688"],  # Logon, explicit creds, special privileges, process
            mitre_tactics=["credential_access", "lateral_movement", "collection", "exfiltration", "impact"],
            hunting_queries={
                "data_exfiltration": 'network.bytes:>10000000 AND network.direction:outbound',
                "lateral_movement": 'event.code:4624 AND winlog.event_data.LogonType:(3 OR 10) AND NOT user.name:(*$ OR SYSTEM OR LOCAL SERVICE OR NETWORK SERVICE)',
                "credential_dumping": 'process.name:(mimikatz.exe OR procdump.exe OR pwdump*.exe) OR process.command_line:(*sekurlsa* OR *lsass* OR *sam*)',
                "ransomware": 'file.extension:(encrypted OR locked OR crypted OR crypt OR enc OR crinf) OR process.name:(*crypt* OR *locker* OR *ransom*)',
                "mass_file_deletion": 'event.action:deleted | stats count by host.name, user.name | where count > 100',
                "smb_lateral_movement": 'event.code:5140 AND winlog.event_data.ShareName:(\\ADMIN$ OR \\C$ OR \\IPC$)',
                "psexec_usage": 'process.name:psexec*.exe OR service.name:PSEXESVC',
                "wmi_lateral_movement": 'process.name:wmic.exe AND process.command_line:(*process* OR */node:*)',
                "large_uploads": 'http.request.body.bytes:>10000000 OR http.response.body.bytes:>10000000',
                "archive_before_exfil": 'process.name:(7z.exe OR winrar.exe OR zip.exe OR tar.exe) OR file.extension:(zip OR rar OR 7z OR tar OR gz)'
            }
        )
    }

    # Mapping of IoC types to Kill Chain stages
    IOC_TO_STAGES = {
        # Reconnaissance IoCs
        "port_scan": [KillChainStage.RECONNAISSANCE],
        "dns_query": [KillChainStage.RECONNAISSANCE],
        "web_scan": [KillChainStage.RECONNAISSANCE],

        # Delivery IoCs
        "email": [KillChainStage.DELIVERY],
        "url": [KillChainStage.DELIVERY, KillChainStage.COMMAND_AND_CONTROL],
        "domain": [KillChainStage.DELIVERY, KillChainStage.COMMAND_AND_CONTROL],
        "attachment": [KillChainStage.DELIVERY],

        # Exploitation IoCs
        "cve": [KillChainStage.EXPLOITATION],
        "exploit": [KillChainStage.EXPLOITATION],
        "shellcode": [KillChainStage.EXPLOITATION],

        # Installation IoCs
        "file_hash": [KillChainStage.INSTALLATION, KillChainStage.WEAPONIZATION],
        "file_path": [KillChainStage.INSTALLATION],
        "registry_key": [KillChainStage.INSTALLATION],
        "service_name": [KillChainStage.INSTALLATION],
        "scheduled_task": [KillChainStage.INSTALLATION],
        "user_account": [KillChainStage.INSTALLATION, KillChainStage.ACTIONS_ON_OBJECTIVES],

        # C2 IoCs
        "ip": [KillChainStage.COMMAND_AND_CONTROL, KillChainStage.RECONNAISSANCE],
        "c2_domain": [KillChainStage.COMMAND_AND_CONTROL],
        "user_agent": [KillChainStage.COMMAND_AND_CONTROL],
        "ja3": [KillChainStage.COMMAND_AND_CONTROL],
        "certificate": [KillChainStage.COMMAND_AND_CONTROL],

        # Actions on Objectives IoCs
        "credential": [KillChainStage.ACTIONS_ON_OBJECTIVES],
        "lateral_movement": [KillChainStage.ACTIONS_ON_OBJECTIVES],
        "data_exfil": [KillChainStage.ACTIONS_ON_OBJECTIVES],
        "ransomware": [KillChainStage.ACTIONS_ON_OBJECTIVES]
    }

    # Mapping of MITRE ATT&CK tactics to Kill Chain stages
    MITRE_TO_KILL_CHAIN = {
        "reconnaissance": [KillChainStage.RECONNAISSANCE],
        "resource_development": [KillChainStage.WEAPONIZATION],
        "initial_access": [KillChainStage.DELIVERY],
        "execution": [KillChainStage.EXPLOITATION],
        "persistence": [KillChainStage.INSTALLATION],
        "privilege_escalation": [KillChainStage.EXPLOITATION, KillChainStage.INSTALLATION],
        "defense_evasion": [KillChainStage.INSTALLATION],
        "credential_access": [KillChainStage.ACTIONS_ON_OBJECTIVES],
        "discovery": [KillChainStage.ACTIONS_ON_OBJECTIVES],
        "lateral_movement": [KillChainStage.ACTIONS_ON_OBJECTIVES],
        "collection": [KillChainStage.ACTIONS_ON_OBJECTIVES],
        "command_and_control": [KillChainStage.COMMAND_AND_CONTROL],
        "exfiltration": [KillChainStage.ACTIONS_ON_OBJECTIVES],
        "impact": [KillChainStage.ACTIONS_ON_OBJECTIVES]
    }

    @classmethod
    def get_stage_info(cls, stage: KillChainStage) -> KillChainStageInfo:
        """Get information about a specific Kill Chain stage."""
        return cls.KILL_CHAIN_STAGES.get(stage)

    @classmethod
    def identify_stage_from_iocs(cls, iocs: List[Dict]) -> Dict:
        """
        Identify Kill Chain stages from a list of IoCs.

        Args:
            iocs: List of IoC dictionaries with 'type' and 'value' keys

        Returns:
            Dictionary with identified stages and confidence scores
        """
        stage_counts = {}
        stage_iocs = {}

        for ioc in iocs:
            ioc_type = ioc.get('type', '').lower()
            ioc_value = ioc.get('value', '')

            # Find matching stages for this IoC type
            stages = cls.IOC_TO_STAGES.get(ioc_type, [])

            for stage in stages:
                if stage not in stage_counts:
                    stage_counts[stage] = 0
                    stage_iocs[stage] = []

                stage_counts[stage] += 1
                stage_iocs[stage].append({
                    'type': ioc_type,
                    'value': ioc_value
                })

        # Calculate confidence scores (percentage of IoCs pointing to each stage)
        total_iocs = len(iocs)
        stage_analysis = {}

        for stage, count in stage_counts.items():
            confidence = (count / total_iocs) * 100 if total_iocs > 0 else 0
            stage_info = cls.get_stage_info(stage)

            stage_analysis[stage.name] = {
                'stage_number': stage.value,
                'stage_name': stage_info.name,
                'description': stage_info.description,
                'confidence': round(confidence, 2),
                'ioc_count': count,
                'matching_iocs': stage_iocs[stage]
            }

        # Sort by confidence
        sorted_stages = sorted(
            stage_analysis.items(),
            key=lambda x: x[1]['confidence'],
            reverse=True
        )

        return {
            'identified_stages': dict(sorted_stages),
            'total_iocs_analyzed': total_iocs,
            'most_likely_stage': sorted_stages[0][0] if sorted_stages else None,
            'confidence': sorted_stages[0][1]['confidence'] if sorted_stages else 0
        }

    @classmethod
    def identify_stage_from_mitre_tactics(cls, tactics: List[str]) -> List[KillChainStage]:
        """
        Map MITRE ATT&CK tactics to Kill Chain stages.

        Args:
            tactics: List of MITRE ATT&CK tactic names

        Returns:
            List of corresponding Kill Chain stages
        """
        stages = set()

        for tactic in tactics:
            tactic_lower = tactic.lower().replace(' ', '_')
            mapped_stages = cls.MITRE_TO_KILL_CHAIN.get(tactic_lower, [])
            stages.update(mapped_stages)

        return sorted(list(stages), key=lambda s: s.value)

    @classmethod
    def get_adjacent_stages(cls, current_stage: KillChainStage) -> Dict[str, Optional[KillChainStage]]:
        """
        Get the previous and next stages in the Kill Chain.

        Args:
            current_stage: Current Kill Chain stage

        Returns:
            Dictionary with 'previous' and 'next' stages
        """
        stage_num = current_stage.value

        previous_stage = None
        next_stage = None

        if stage_num > 1:
            previous_stage = KillChainStage(stage_num - 1)

        if stage_num < 7:
            next_stage = KillChainStage(stage_num + 1)

        return {
            'previous': previous_stage,
            'next': next_stage,
            'current': current_stage
        }

    @classmethod
    def get_hunting_queries_for_stage(cls, stage: KillChainStage) -> Dict[str, str]:
        """
        Get hunting queries for a specific Kill Chain stage.

        Args:
            stage: Kill Chain stage

        Returns:
            Dictionary of query names and Lucene query strings
        """
        stage_info = cls.get_stage_info(stage)
        return stage_info.hunting_queries if stage_info else {}

    @classmethod
    def suggest_next_hunting_actions(cls, current_stage: KillChainStage) -> Dict:
        """
        Suggest hunting actions for adjacent stages.

        Args:
            current_stage: Current Kill Chain stage identified

        Returns:
            Dictionary with hunting suggestions for previous and next stages
        """
        adjacent = cls.get_adjacent_stages(current_stage)
        current_info = cls.get_stage_info(current_stage)

        suggestions = {
            'current_stage': {
                'name': current_info.name,
                'number': current_stage.value,
                'description': current_info.description
            },
            'hunt_previous_stage': None,
            'hunt_next_stage': None
        }

        # Suggest hunting for previous stage (how did they get here?)
        if adjacent['previous']:
            prev_info = cls.get_stage_info(adjacent['previous'])
            suggestions['hunt_previous_stage'] = {
                'stage_name': prev_info.name,
                'stage_number': adjacent['previous'].value,
                'description': prev_info.description,
                'reason': f"Hunt for {prev_info.name} to understand how the attacker reached {current_info.name}",
                'indicators_to_look_for': prev_info.indicators,
                'log_sources': prev_info.log_sources,
                'hunting_queries': prev_info.hunting_queries
            }

        # Suggest hunting for next stage (where are they going?)
        if adjacent['next']:
            next_info = cls.get_stage_info(adjacent['next'])
            suggestions['hunt_next_stage'] = {
                'stage_name': next_info.name,
                'stage_number': adjacent['next'].value,
                'description': next_info.description,
                'reason': f"Hunt for {next_info.name} to predict and prevent the attacker's next move",
                'indicators_to_look_for': next_info.indicators,
                'log_sources': next_info.log_sources,
                'hunting_queries': next_info.hunting_queries
            }

        return suggestions

    @classmethod
    def get_full_kill_chain_overview(cls) -> Dict:
        """
        Get a complete overview of the Cyber Kill Chain.

        Returns:
            Dictionary with all stages and their information
        """
        overview = {
            'name': 'Lockheed Martin Cyber Kill Chain',
            'description': 'Framework for understanding the stages of a cyberattack',
            'total_stages': 7,
            'stages': {}
        }

        for stage in KillChainStage:
            info = cls.get_stage_info(stage)
            overview['stages'][stage.name] = {
                'number': stage.value,
                'name': info.name,
                'description': info.description,
                'indicators': info.indicators,
                'typical_iocs': info.typical_iocs,
                'log_sources': info.log_sources,
                'mitre_tactics': info.mitre_tactics,
                'hunting_query_count': len(info.hunting_queries)
            }

        return overview

    @classmethod
    def map_event_to_stage(cls, event: Dict) -> List[KillChainStage]:
        """
        Map an Elasticsearch event to potential Kill Chain stages.

        Args:
            event: Elasticsearch event document

        Returns:
            List of potential Kill Chain stages
        """
        stages = set()

        # Check event code
        event_code = event.get('event', {}).get('code')
        if event_code:
            event_code_str = str(event_code)
            for stage, info in cls.KILL_CHAIN_STAGES.items():
                if event_code_str in info.event_codes:
                    stages.add(stage)

        # Check MITRE tactics if available
        mitre_tactics = event.get('mitre', {}).get('tactics', [])
        if mitre_tactics:
            for tactic in mitre_tactics:
                mapped_stages = cls.identify_stage_from_mitre_tactics([tactic])
                stages.update(mapped_stages)

        # Analyze event content for stage indicators
        event_action = event.get('event', {}).get('action', '').lower()

        # Reconnaissance indicators
        if any(keyword in event_action for keyword in ['scan', 'enumerate', 'probe', 'reconnaissance']):
            stages.add(KillChainStage.RECONNAISSANCE)

        # Delivery indicators
        if any(keyword in event_action for keyword in ['email', 'download', 'attachment']):
            stages.add(KillChainStage.DELIVERY)

        # Exploitation indicators
        if any(keyword in event_action for keyword in ['exploit', 'vulnerability', 'execute']):
            stages.add(KillChainStage.EXPLOITATION)

        # Installation indicators
        if any(keyword in event_action for keyword in ['install', 'persist', 'create', 'modify']):
            stages.add(KillChainStage.INSTALLATION)

        # C2 indicators
        if any(keyword in event_action for keyword in ['beacon', 'callback', 'connect', 'c2', 'command_and_control']):
            stages.add(KillChainStage.COMMAND_AND_CONTROL)

        # Actions on Objectives indicators
        if any(keyword in event_action for keyword in ['exfiltrate', 'encrypt', 'delete', 'lateral', 'credential']):
            stages.add(KillChainStage.ACTIONS_ON_OBJECTIVES)

        return sorted(list(stages), key=lambda s: s.value)
