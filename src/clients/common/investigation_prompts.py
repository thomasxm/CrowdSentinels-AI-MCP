"""Investigation Prompts for SIEM/SOAR Triage."""
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from src.clients.base import SearchClientBase


@dataclass
class InvestigationPrompt:
    """Represents a single investigation prompt/question."""

    id: str
    platform: str  # 'linux' or 'windows'
    priority: int  # 1-5, with 1 being highest priority
    question: str
    description: str
    focus_areas: List[str]
    log_sources: List[str]
    elasticsearch_fields: List[str]
    query_template: str
    mitre_tactics: List[str] = field(default_factory=list)

    @property
    def short_description(self) -> str:
        """Get a short version of the question."""
        return self.question.split('?')[0] + '?'


class InvestigationPromptsClient(SearchClientBase):
    """Client for managing investigation prompts and executing triage queries."""

    # Linux Investigation Prompts
    LINUX_PROMPTS = {
        "linux_auth_1": InvestigationPrompt(
            id="linux_auth_1",
            platform="linux",
            priority=1,
            question="Who authenticated to the box during the suspected window, from where, and how?",
            description="Investigate successful and failed SSH logins: usernames, source IPs, auth method/key fingerprint, geo/ASN, first-seen sources.",
            focus_areas=[
                "Successful SSH logins",
                "Failed SSH login attempts",
                "Source IP addresses and geolocation",
                "Authentication methods and key fingerprints",
                "First-time connection sources"
            ],
            log_sources=[
                "/var/log/auth.log",
                "/var/log/secure",
                "journald sshd",
                "EDR auth telemetry"
            ],
            elasticsearch_fields=[
                "system.auth.ssh.event",
                "event.action",
                "event.outcome",
                "source.ip",
                "source.geo.country_name",
                "user.name",
                "ssh.method",
                "process.name:sshd"
            ],
            query_template="""
(event.action:("ssh_login" OR "session_opened" OR "publickey" OR "password") OR
 process.name:sshd OR
 system.auth.ssh.event:*) AND
(event.outcome:("success" OR "failure"))
            """.strip(),
            mitre_tactics=["initial_access", "lateral_movement"]
        ),

        "linux_privilege_2": InvestigationPrompt(
            id="linux_privilege_2",
            platform="linux",
            priority=2,
            question="Did anyone gain root via sudo/su, and exactly what commands were run?",
            description="Correlate who → what command → tty/session → result. Track privilege escalation attempts.",
            focus_areas=[
                "sudo command execution",
                "su command usage",
                "Root privilege escalation",
                "Command execution with elevated privileges",
                "Session and TTY correlation"
            ],
            log_sources=[
                "sudo logs",
                "su logs",
                "auditd execve events",
                "EDR process telemetry"
            ],
            elasticsearch_fields=[
                "process.name:(sudo OR su)",
                "process.args",
                "user.name",
                "user.effective.name:root",
                "auditd.data.cmd",
                "process.working_directory"
            ],
            query_template="""
(process.name:(sudo OR su) OR
 event.action:"executed" AND user.effective.name:root OR
 auditd.data.syscall:"execve" AND user.effective.id:"0")
            """.strip(),
            mitre_tactics=["privilege_escalation"]
        ),

        "linux_processes_3": InvestigationPrompt(
            id="linux_processes_3",
            platform="linux",
            priority=3,
            question="What new or unusual processes executed (and from which paths), and what's the parent/command line?",
            description="Focus on suspicious paths: /tmp, /dev/shm, /var/tmp, user home, hidden dirs, new ELF in odd paths, unusual interpreter chains.",
            focus_areas=[
                "Processes from /tmp, /dev/shm, /var/tmp",
                "Hidden directories (starting with .)",
                "Unusual interpreter chains",
                "New ELF binaries in odd locations",
                "Parent-child process relationships"
            ],
            log_sources=[
                "auditd execve",
                "process accounting",
                "EDR process start",
                "Sysmon-for-Linux"
            ],
            elasticsearch_fields=[
                "process.executable",
                "process.args",
                "process.parent.executable",
                "process.parent.args",
                "process.working_directory",
                "file.path"
            ],
            query_template="""
(process.executable:(*\/tmp\/* OR *\/dev\/shm\/* OR *\/var\/tmp\/* OR *\/.* OR *\/home\/*) OR
 process.working_directory:(*\/tmp OR *\/dev\/shm OR *\/var\/tmp) OR
 process.name:(bash OR sh OR perl OR python OR ruby OR php) AND process.parent.name:(bash OR sh))
            """.strip(),
            mitre_tactics=["execution", "defense_evasion"]
        ),

        "linux_persistence_4": InvestigationPrompt(
            id="linux_persistence_4",
            platform="linux",
            priority=4,
            question="What persistence changed on the host, and who changed it?",
            description="Track changes to cron/systemd/init scripts, new timers/services, modified crontab, shell profiles.",
            focus_areas=[
                "Cron job modifications",
                "Systemd service changes",
                "Init script modifications",
                "Shell profile changes (.bashrc, .profile)",
                "Scheduled task creation",
                "/etc/rc.local modifications"
            ],
            log_sources=[
                "auditd file watches",
                "FIM (file integrity monitoring)",
                "package logs",
                "journald systemd unit changes"
            ],
            elasticsearch_fields=[
                "file.path:(*cron* OR *systemd* OR *rc.local OR *.bashrc OR *.profile)",
                "event.action:(created OR modified OR renamed)",
                "process.name:(crontab OR systemctl OR chkconfig)",
                "auditd.data.name"
            ],
            query_template="""
((file.path:(*\/etc\/cron* OR *\/etc\/systemd\/system\/* OR *\/etc\/rc.local OR *\/.bashrc OR *\/.profile OR *\/etc\/init.d\/*) AND
  event.action:(created OR modified OR renamed OR deleted)) OR
 process.name:(crontab OR systemctl OR "systemd-run") OR
 event.action:"systemd-unit-started")
            """.strip(),
            mitre_tactics=["persistence"]
        ),

        "linux_network_5": InvestigationPrompt(
            id="linux_network_5",
            platform="linux",
            priority=5,
            question="What outbound network connections did the host initiate, and which process/user owned them?",
            description="Track rare destinations, odd ports, first-time domains, long-lived beacons, DNS→connect correlation.",
            focus_areas=[
                "Outbound connections to rare destinations",
                "Unusual port usage",
                "First-time domain connections",
                "Beacon-like behavior (regular intervals)",
                "DNS query to connection correlation",
                "Process ownership of connections"
            ],
            log_sources=[
                "EDR network telemetry",
                "NetFlow/VPC Flow Logs",
                "DNS logs",
                "firewall logs",
                "conntrack/eBPF telemetry"
            ],
            elasticsearch_fields=[
                "destination.ip",
                "destination.port",
                "destination.domain",
                "network.direction:outbound",
                "process.name",
                "user.name",
                "dns.question.name"
            ],
            query_template="""
(network.direction:outbound OR
 event.category:network AND event.type:connection) AND
NOT (destination.port:(80 OR 443 OR 53) AND destination.ip:(10.* OR 172.16.* OR 192.168.*))
            """.strip(),
            mitre_tactics=["command_and_control", "exfiltration"]
        )
    }

    # Windows Investigation Prompts
    WINDOWS_PROMPTS = {
        "windows_logon_1": InvestigationPrompt(
            id="windows_logon_1",
            platform="windows",
            priority=1,
            question="Who logged on, from where, and using what logon type—and what changed vs baseline?",
            description="Analyze interactive vs RDP vs network vs service logins; new source hosts; unusual logon hours; admin logons.",
            focus_areas=[
                "Logon types (Interactive, RDP, Network, Service)",
                "Source workstation/IP addresses",
                "Unusual logon hours",
                "Administrator account logons",
                "Failed logon attempts",
                "Explicit credential usage"
            ],
            log_sources=[
                "Security 4624 (successful logon)",
                "Security 4625 (failed logon)",
                "Security 4634 (logoff)",
                "Security 4648 (explicit creds)",
                "RDP-related events",
                "EDR auth telemetry"
            ],
            elasticsearch_fields=[
                "event.code:(4624 OR 4625 OR 4634 OR 4648)",
                "winlog.event_data.LogonType",
                "source.ip",
                "user.name",
                "winlog.event_data.WorkstationName",
                "winlog.event_data.TargetUserName"
            ],
            query_template="""
winlog.channel:Security AND
event.code:(4624 OR 4625 OR 4648) AND
(winlog.event_data.LogonType:(2 OR 3 OR 10) OR
 winlog.event_data.TargetUserName:(*admin* OR *adm))
            """.strip(),
            mitre_tactics=["initial_access", "lateral_movement"]
        ),

        "windows_processes_2": InvestigationPrompt(
            id="windows_processes_2",
            platform="windows",
            priority=2,
            question="What processes spawned around the alert, with full command lines + parent/child chain?",
            description="Focus on LOLBINs: powershell.exe, cmd.exe, wscript, mshta, rundll32, regsvr32, schtasks, wmic, certutil, bitsadmin.",
            focus_areas=[
                "LOLBin execution (PowerShell, CMD, WScript, etc.)",
                "Process parent-child relationships",
                "Full command line arguments",
                "Suspicious process chains",
                "Encoded commands",
                "Download tools (certutil, bitsadmin, curl, wget)"
            ],
            log_sources=[
                "Sysmon Event ID 1 (process creation)",
                "Security 4688 (process creation)",
                "EDR process telemetry"
            ],
            elasticsearch_fields=[
                "event.code:(1 OR 4688)",
                "process.name",
                "process.command_line",
                "process.parent.name",
                "process.parent.command_line",
                "winlog.event_data.Image",
                "winlog.event_data.ParentImage"
            ],
            query_template="""
(event.code:(1 OR 4688) OR event.category:process) AND
process.name:(powershell.exe OR cmd.exe OR wscript.exe OR cscript.exe OR
             mshta.exe OR rundll32.exe OR regsvr32.exe OR schtasks.exe OR
             wmic.exe OR certutil.exe OR bitsadmin.exe OR curl.exe OR wget.exe)
            """.strip(),
            mitre_tactics=["execution", "defense_evasion"]
        ),

        "windows_powershell_3": InvestigationPrompt(
            id="windows_powershell_3",
            platform="windows",
            priority=3,
            question="Was PowerShell used, and was it doing anything sketchy (encoded, download cradle, AMSI hits)?",
            description="Look for -enc, IEX, Invoke-WebRequest, FromBase64String, Add-MpPreference, suspicious module loads.",
            focus_areas=[
                "Encoded PowerShell commands (-enc, -e)",
                "Download cradles (IEX, Invoke-WebRequest)",
                "Base64 encoding/decoding",
                "AMSI bypass attempts",
                "Defender exclusion additions",
                "Suspicious module loads",
                "Script block logging"
            ],
            log_sources=[
                "PowerShell 4104 (script block)",
                "PowerShell 4103 (module logging)",
                "Security 4688",
                "Sysmon 1",
                "AMSI/Defender alerts"
            ],
            elasticsearch_fields=[
                "event.code:(4104 OR 4103 OR 1 OR 4688)",
                "powershell.file.script_block_text",
                "process.command_line",
                "winlog.event_data.ScriptBlockText",
                "powershell.command.value"
            ],
            query_template="""
(event.code:(4104 OR 4103) OR
 (process.name:powershell.exe AND process.command_line:*)) AND
(process.command_line:(*-enc* OR *-e * OR *IEX* OR *Invoke-WebRequest* OR
                      *Invoke-Expression* OR *FromBase64String* OR
                      *Add-MpPreference* OR *Net.WebClient* OR *DownloadString*) OR
 powershell.file.script_block_text:(*IEX* OR *Invoke-WebRequest* OR *FromBase64String*))
            """.strip(),
            mitre_tactics=["execution", "defense_evasion"]
        ),

        "windows_persistence_4": InvestigationPrompt(
            id="windows_persistence_4",
            platform="windows",
            priority=4,
            question="What persistence was created or modified (services/tasks/Run keys/WMI/startup folders)?",
            description="Track new service installs, scheduled tasks, registry autoruns, WMI event subscriptions, startup shortcuts.",
            focus_areas=[
                "New service creation",
                "Scheduled task creation/modification",
                "Registry Run key modifications",
                "WMI event subscriptions",
                "Startup folder changes",
                "COM hijacking",
                "DLL search order hijacking"
            ],
            log_sources=[
                "System 7045 (service created)",
                "Security 4698 (task created)",
                "TaskScheduler operational logs",
                "Sysmon 12/13/14 (registry)",
                "Sysmon 19-21 (WMI)",
                "EDR persistence detections"
            ],
            elasticsearch_fields=[
                "event.code:(7045 OR 4698 OR 12 OR 13 OR 14 OR 19 OR 20 OR 21)",
                "winlog.event_data.ServiceName",
                "winlog.event_data.TaskName",
                "registry.path:(*Run* OR *RunOnce* OR *RunServices*)",
                "winlog.event_data.TargetObject",
                "file.path:(*Startup* OR *Start Menu*)"
            ],
            query_template="""
(event.code:(7045 OR 4698 OR 106) OR
 (event.code:(12 OR 13 OR 14) AND registry.path:(*\\\\Run* OR *\\\\RunOnce* OR *\\\\RunServices*)) OR
 event.code:(19 OR 20 OR 21) OR
 (event.category:file AND file.path:(*\\\\Startup\\\\* OR *\\\\Start Menu\\\\*) AND event.action:(created OR modified)))
            """.strip(),
            mitre_tactics=["persistence"]
        ),

        "windows_privilege_5": InvestigationPrompt(
            id="windows_privilege_5",
            platform="windows",
            priority=5,
            question="Any signs of privilege/credential access—and how far did it go?",
            description="Track special privileges assigned, new local admins, LSASS access/dumps, token manipulation, suspicious handle access.",
            focus_areas=[
                "Special privilege assignments",
                "Local admin group changes",
                "LSASS process access",
                "Memory dumping",
                "Token manipulation",
                "Credential dumping tools",
                "SAM/SECURITY hive access"
            ],
            log_sources=[
                "Security 4672 (special privileges)",
                "Security 4728/4732/4756 (group membership)",
                "Sysmon 10 (process access)",
                "EDR credential access alerts",
                "Defender/AV detections"
            ],
            elasticsearch_fields=[
                "event.code:(4672 OR 4728 OR 4732 OR 4756 OR 10)",
                "winlog.event_data.PrivilegeList",
                "winlog.event_data.TargetImage:*lsass.exe",
                "winlog.event_data.GrantedAccess",
                "winlog.event_data.MemberName",
                "process.name:(mimikatz* OR procdump* OR dumpert*)"
            ],
            query_template="""
(event.code:4672 AND winlog.event_data.PrivilegeList:*SeDebugPrivilege*) OR
event.code:(4728 OR 4732 OR 4756) OR
(event.code:10 AND winlog.event_data.TargetImage:*lsass.exe AND
 NOT winlog.event_data.SourceImage:(*svchost.exe OR *csrss.exe OR *wininit.exe)) OR
process.name:(mimikatz* OR procdump* OR dumpert* OR pwdump*)
            """.strip(),
            mitre_tactics=["privilege_escalation", "credential_access"]
        )
    }

    @classmethod
    def get_all_prompts(cls, platform: Optional[str] = None) -> Dict[str, InvestigationPrompt]:
        """Get all investigation prompts, optionally filtered by platform."""
        all_prompts = {**cls.LINUX_PROMPTS, **cls.WINDOWS_PROMPTS}

        if platform:
            return {k: v for k, v in all_prompts.items() if v.platform == platform.lower()}

        return all_prompts

    @classmethod
    def get_prompt_by_id(cls, prompt_id: str) -> Optional[InvestigationPrompt]:
        """Get a specific prompt by ID."""
        all_prompts = cls.get_all_prompts()
        return all_prompts.get(prompt_id)

    @classmethod
    def get_prompts_by_priority(cls, platform: str, max_priority: int = 5) -> List[InvestigationPrompt]:
        """Get prompts sorted by priority."""
        prompts = cls.get_all_prompts(platform=platform)
        sorted_prompts = sorted(prompts.values(), key=lambda p: p.priority)
        return [p for p in sorted_prompts if p.priority <= max_priority]

    def execute_investigation_prompt(self, prompt_id: str, index: str,
                                    timeframe_minutes: int = 60,
                                    size: int = 100,
                                    additional_filters: Optional[Dict] = None) -> Dict:
        """
        Execute an investigation prompt against Elasticsearch.

        Args:
            prompt_id: ID of the investigation prompt
            index: Index pattern to search
            timeframe_minutes: Time window in minutes
            size: Maximum number of results
            additional_filters: Additional filters to apply (e.g., host.name)

        Returns:
            Investigation results
        """
        prompt = self.get_prompt_by_id(prompt_id)

        if not prompt:
            return {
                "error": f"Investigation prompt not found: {prompt_id}",
                "available_prompts": list(self.get_all_prompts().keys())
            }

        # Build the query
        query = {
            "bool": {
                "must": [],
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": f"now-{timeframe_minutes}m",
                                "lte": "now"
                            }
                        }
                    }
                ]
            }
        }

        # Add the prompt query
        query["bool"]["must"].append({
            "query_string": {
                "query": prompt.query_template,
                "analyze_wildcard": True
            }
        })

        # Add additional filters if provided
        if additional_filters:
            for field, value in additional_filters.items():
                query["bool"]["filter"].append({
                    "term": {field: value}
                })

        # Execute the search
        try:
            response = self.client.search(
                index=index,
                body={
                    "query": query,
                    "size": size,
                    "sort": [{"@timestamp": {"order": "desc"}}]
                }
            )

            hits = response["hits"]["hits"]
            total_hits = response["hits"]["total"]["value"]

            return {
                "prompt_id": prompt_id,
                "prompt_question": prompt.question,
                "platform": prompt.platform,
                "priority": prompt.priority,
                "focus_areas": prompt.focus_areas,
                "total_hits": total_hits,
                "showing": len(hits),
                "events": hits,
                "log_sources_to_check": prompt.log_sources,
                "key_fields": prompt.elasticsearch_fields,
                "mitre_tactics": prompt.mitre_tactics,
                "execution_time_ms": response.get("took", 0)
            }

        except Exception as e:
            self.logger.error(f"Failed to execute investigation prompt {prompt_id}: {e}")
            return {
                "error": str(e),
                "prompt_id": prompt_id,
                "prompt_question": prompt.question
            }
