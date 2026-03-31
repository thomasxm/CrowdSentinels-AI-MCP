"""Velociraptor forensic artifact collection tools for CrowdSentinel MCP server.

Provides MCP tools for live endpoint forensics via Velociraptor, with
automatic IoC extraction and integration with the investigation state system.
"""

import asyncio
import logging
import os
from typing import Any

from fastmcp import FastMCP

from src.clients.velociraptor_client import (
    _sanitize_date,
    _sanitize_drive,
    _sanitize_regex,
)
from src.storage.auto_capture import auto_capture_velociraptor_results

logger = logging.getLogger(__name__)

VELOCIRAPTOR_GUIDE = """
# Velociraptor Endpoint Forensics Guide

## Prerequisites
- `VELOCIRAPTOR_API_CONFIG` env var must point to your `api_client.yaml`
- Target endpoint must have a Velociraptor agent installed and connected

## Workflow: Always Start with velociraptor_client_info
Every investigation starts by resolving a hostname to a `client_id`:
```
result = velociraptor_client_info(hostname="WORKSTATION01")
client_id = result["client_id"]  # e.g. "C.abc123def456"
```

## Artifact Reference

### Evidence of Execution
| Tool | Artifact | Forensic Question | Key IoCs | Reliability |
|------|----------|-------------------|----------|-------------|
| `velociraptor_prefetch` | Windows.Forensics.Prefetch | Was this program ever executed? | process, hash | High (run count + timestamps) |
| `velociraptor_amcache` | Windows.Detection.Amcache | SHA1 and metadata of executables? | hash, file_path | High (SHA1 + publisher) |
| `velociraptor_shimcache` | Windows.Registry.AppCompatCache | Was this file path seen by the OS? | file_path | Medium (no execution proof) |
| `velociraptor_userassist` | Windows.Registry.UserAssist | Did a user interactively launch this? | process, user | High (user-specific, with count) |
| `velociraptor_bam` | Windows.Forensics.Bam | Background execution evidence? | process, file_path | Medium (Win10+ only) |

### Persistence Mechanisms
| Tool | Artifact | Forensic Question | Key IoCs |
|------|----------|-------------------|----------|
| `velociraptor_services` | Windows.System.Services | Suspicious services installed? | service, hash, file_path |
| `velociraptor_scheduled_tasks` | Windows.System.TaskScheduler | Suspicious scheduled tasks? | commandline, file_path |

### Live State
| Tool | Artifact | Forensic Question | Key IoCs |
|------|----------|-------------------|----------|
| `velociraptor_pslist` | Windows/Linux.Sys.Pslist | What is currently running? | process, commandline, user |
| `velociraptor_netstat` | Windows/Linux.Network.NetstatEnriched | Active network connections? | ip, process |
| `velociraptor_users` | Windows/Linux.Sys.Users | What user accounts exist? | user |
| `velociraptor_groups` | Linux.Sys.Groups | What groups exist? | user |
| `velociraptor_mounts` | Linux.Mounts | What filesystems are mounted? | file_path |

### User Activity
| Tool | Artifact | Forensic Question | Key IoCs |
|------|----------|-------------------|----------|
| `velociraptor_shellbags` | Windows.Forensics.Shellbags | What folders did the user browse? | file_path, registry_key |
| `velociraptor_recentdocs` | Windows.Registry.RecentDocs | What documents were recently accessed? | file_path |
| `velociraptor_evidence_of_download` | Windows.Analysis.EvidenceOfDownload | What files were downloaded? | url, hash, file_path |

### Filesystem Forensics
| Tool | Artifact | Forensic Question | Key IoCs |
|------|----------|-------------------|----------|
| `velociraptor_ntfs_mft` | Windows.NTFS.MFT | Does this file exist? Timeline? Timestomped? | file_path, hash |

### Generic Collection
| Tool | Purpose |
|------|---------|
| `velociraptor_collect_artifact` | Start any artifact collection (returns flow_id) |
| `velociraptor_get_collection_results` | Retrieve results from async collection |
| `velociraptor_list_artifacts` | Discover all available artifacts for Windows/Linux |

---

## Decision Tree: "I found X in SIEM, what do I check on the endpoint?"

- **Suspicious process name** -> `velociraptor_pslist` (still running?), `velociraptor_prefetch` (executed before?), `velociraptor_amcache` (hash?)
- **Suspicious IP connection** -> `velociraptor_netstat` (active connection?), `velociraptor_evidence_of_download` (downloaded from that IP?)
- **Persistence alert** -> `velociraptor_services` + `velociraptor_scheduled_tasks`
- **User compromise** -> `velociraptor_userassist` (what they ran), `velociraptor_shellbags` (where they browsed), `velociraptor_recentdocs` (what they opened)
- **File on disk** -> `velociraptor_ntfs_mft` (exists? timestamps? timestomped?)
- **Unknown artifact needed** -> `velociraptor_list_artifacts` to discover, then `velociraptor_collect_artifact`

## SIEM Pivot Patterns (Endpoint -> SIEM)

After collecting endpoint data, pivot to SIEM for fleet-wide visibility:
- **SHA1 from Amcache** -> `hunt_for_ioc(ioc_type="hash")` — find same binary on other hosts
- **Binary name from Prefetch** -> `hunt_for_ioc(ioc_type="process")` — lateral movement detection
- **Remote IPs from Netstat** -> `hunt_for_ioc(ioc_type="ip")` — broader C2 activity
- **Download URLs** -> `hunt_for_ioc(ioc_type="domain")` — identify other victims
- **Service DLL hash** -> `hunt_for_ioc(ioc_type="hash")` — persistence across fleet
"""


class VelociraptorTools:
    """MCP tools for Velociraptor forensic artifact collection.

    Tools are registered conditionally — if VELOCIRAPTOR_API_CONFIG is not set,
    no tools are registered and CrowdSentinel functions normally without Velociraptor.
    """

    def __init__(self):
        """Initialize with lazy client creation."""
        self._client = None
        self.logger = logger

    def _get_client(self) -> "VelociraptorClient":  # noqa: F821
        """Lazily initialize the Velociraptor gRPC client."""
        if self._client is not None:
            return self._client

        config_path = os.environ.get("VELOCIRAPTOR_API_CONFIG")
        if not config_path:
            raise RuntimeError(
                "VELOCIRAPTOR_API_CONFIG environment variable not set. "
                "Set it to the path of your api_client.yaml file."
            )

        from src.clients.velociraptor_client import VelociraptorClient

        self._client = VelociraptorClient(config_path)
        return self._client

    def _wrap_results(self, results: list[dict[str, Any]], tool_name: str, description: str) -> dict[str, Any]:
        """Wrap raw Velociraptor results into a standard dict for auto-capture."""
        wrapped = {
            "events": results,
            "total_hits": len(results),
            "source": "velociraptor",
            "tool": tool_name,
        }
        return auto_capture_velociraptor_results(wrapped, tool_name, description, extract_timeline=True)

    def register_tools(self, mcp: FastMCP):
        tools_instance = self

        # MCP Resource: Velociraptor investigation guide
        @mcp.resource("crowdsentinel://velociraptor-guide")
        def get_velociraptor_guide():
            """
            Velociraptor endpoint forensics reference guide.

            Read this resource to understand which Velociraptor artifact
            answers which forensic question, how to pivot from SIEM findings
            to endpoint validation, and the decision tree for choosing
            the right artifact collection tool.
            """
            return VELOCIRAPTOR_GUIDE

        @mcp.tool()
        async def velociraptor_client_info(hostname: str) -> dict:
            """
            Find a Velociraptor endpoint by hostname or FQDN.

            Returns client metadata including client_id, OS type, agent version,
            and last-seen timestamp. The client_id is required for all other
            Velociraptor tools.

            Args:
                hostname: Hostname or FQDN of the target endpoint.

            Returns:
                Client metadata dict with client_id, or error message.
            """
            client = tools_instance._get_client()
            result = await client.find_client(hostname)
            if result is None:
                return {"error": f"No Velociraptor client found for hostname: {hostname}"}
            return result

        @mcp.tool()
        async def velociraptor_pslist(
            client_id: str,
            os_type: str = "windows",
            ProcessRegex: str = ".",
            Fields: str = "*",
        ) -> dict:
            """
            List running processes on an endpoint (Windows or Linux).

            Args:
                client_id: Velociraptor client ID (from velociraptor_client_info).
                os_type: Operating system — 'windows' or 'linux'.
                ProcessRegex: Case-insensitive regex to filter process names.
                Fields: Comma-separated fields to return, or '*' for all.

            Returns:
                Process list with auto-captured IoCs.
            """
            ProcessRegex = _sanitize_regex(ProcessRegex)
            client = tools_instance._get_client()

            if os_type.lower() == "linux":
                artifact = "Linux.Sys.Pslist"
            else:
                artifact = "Windows.System.Pslist"
                if Fields == "*":
                    Fields = "Pid,Ppid,TokenIsElevated,Name,Exe,CommandLine,Username,Authenticode.Trusted"

            parameters = f"ProcessRegex='{ProcessRegex}'"
            results = await client.collect_realtime(client_id, artifact, parameters, Fields)
            return tools_instance._wrap_results(results, "velociraptor_pslist", f"Process list ({os_type})")

        @mcp.tool()
        async def velociraptor_netstat(
            client_id: str,
            os_type: str = "windows",
            IPRegex: str = ".",
            PortRegex: str = ".",
            ProcessNameRegex: str = ".",
            ConnectionStatusRegex: str = "LISTEN|ESTAB",
            Fields: str = "*",
        ) -> dict:
            """
            List network connections with process metadata on an endpoint.

            Args:
                client_id: Velociraptor client ID.
                os_type: Operating system — 'windows' or 'linux'.
                IPRegex: Regex to filter IP addresses.
                PortRegex: Regex to filter ports (e.g., '^443$').
                ProcessNameRegex: Regex to filter process names.
                ConnectionStatusRegex: Regex to filter connection status.
                Fields: Comma-separated fields to return, or '*' for all.

            Returns:
                Network connection list with auto-captured IoCs.
            """
            IPRegex = _sanitize_regex(IPRegex)
            PortRegex = _sanitize_regex(PortRegex)
            ProcessNameRegex = _sanitize_regex(ProcessNameRegex)
            ConnectionStatusRegex = _sanitize_regex(ConnectionStatusRegex)
            client = tools_instance._get_client()

            if os_type.lower() == "linux":
                artifact = "Linux.Network.NetstatEnriched"
                result_scope = ""
                parameters = (
                    f"IPRegex='{IPRegex}',"
                    f"PortRegex='{PortRegex}',"
                    f"ProcessNameRegex='{ProcessNameRegex}',"
                    f"ConnectionStatusRegex='{ConnectionStatusRegex}'"
                )
            else:
                artifact = "Windows.Network.NetstatEnriched"
                result_scope = "/Netstat"
                if Fields == "*":
                    Fields = "Pid,Ppid,Name,Path,CommandLine,Username,Authenticode.Trusted,Type,Status,Laddr,Lport,Raddr,Rport"
                parameters = (
                    f"IPRegex='{IPRegex}',"
                    f"PortRegex='{PortRegex}',"
                    f"ProcessNameRegex='{ProcessNameRegex}',"
                    f"ConnectionStatusRegex='{ConnectionStatusRegex}'"
                )

            results = await client.collect_realtime(client_id, artifact, parameters, Fields, result_scope)
            return tools_instance._wrap_results(results, "velociraptor_netstat", f"Netstat ({os_type})")

        @mcp.tool()
        async def velociraptor_users(client_id: str, os_type: str = "windows", Fields: str = "*") -> dict:
            """
            List users on an endpoint.

            Args:
                client_id: Velociraptor client ID.
                os_type: Operating system — 'windows' or 'linux'.
                Fields: Comma-separated fields to return.

            Returns:
                User list with auto-captured IoCs.
            """
            client = tools_instance._get_client()
            artifact = "Linux.Sys.Users" if os_type.lower() == "linux" else "Windows.Sys.Users"
            results = await client.collect_realtime(client_id, artifact, "", Fields)
            return tools_instance._wrap_results(results, "velociraptor_users", f"Users ({os_type})")

        @mcp.tool()
        async def velociraptor_groups(client_id: str, Fields: str = "*") -> dict:
            """
            List groups on a Linux endpoint.

            Args:
                client_id: Velociraptor client ID.
                Fields: Comma-separated fields to return.

            Returns:
                Group list.
            """
            client = tools_instance._get_client()
            results = await client.collect_realtime(client_id, "Linux.Sys.Groups", "", Fields)
            return tools_instance._wrap_results(results, "velociraptor_groups", "Linux groups")

        @mcp.tool()
        async def velociraptor_mounts(client_id: str, Fields: str = "*") -> dict:
            """
            List mounted filesystems on a Linux endpoint.

            Args:
                client_id: Velociraptor client ID.
                Fields: Comma-separated fields to return.

            Returns:
                Mount list.
            """
            client = tools_instance._get_client()
            results = await client.collect_realtime(client_id, "Linux.Mounts", "", Fields)
            return tools_instance._wrap_results(results, "velociraptor_mounts", "Linux mounts")

        @mcp.tool()
        async def velociraptor_scheduled_tasks(
            client_id: str,
            Fields: str = "OSPath,Mtime,Command,ExpandedCommand,Arguments,ComHandler,UserId,StartBoundary,Authenticode",
        ) -> dict:
            """
            List scheduled tasks (persistence) on a Windows endpoint.

            Args:
                client_id: Velociraptor client ID.
                Fields: Comma-separated fields to return.

            Returns:
                Scheduled tasks with auto-captured IoCs.
            """
            client = tools_instance._get_client()
            results = await client.collect_realtime(client_id, "Windows.System.TaskScheduler", "", Fields, "/Analysis")
            return tools_instance._wrap_results(results, "velociraptor_scheduled_tasks", "Scheduled tasks")

        @mcp.tool()
        async def velociraptor_services(
            client_id: str,
            Fields: str = "UserAccount,Created,ServiceDll,FailureCommand,FailureActions,AbsoluteExePath,HashServiceExe,CertinfoServiceExe,HashServiceDll,CertinfoServiceDll",
        ) -> dict:
            """
            List services with metadata on a Windows endpoint.

            Args:
                client_id: Velociraptor client ID.
                Fields: Comma-separated fields to return.

            Returns:
                Services with auto-captured IoCs.
            """
            client = tools_instance._get_client()
            results = await client.collect_realtime(client_id, "Windows.System.Services", "", Fields)
            return tools_instance._wrap_results(results, "velociraptor_services", "Windows services")

        @mcp.tool()
        async def velociraptor_prefetch(
            client_id: str,
            Fields: str = "Binary,CreationTime,LastRunTimes,RunCount,Hash",
        ) -> dict:
            """
            Parse Prefetch files on a Windows endpoint to identify previously executed programs.

            Args:
                client_id: Velociraptor client ID.
                Fields: Comma-separated fields to return.

            Returns:
                Prefetch entries with auto-captured IoCs.
            """
            client = tools_instance._get_client()
            results = await client.collect_realtime(client_id, "Windows.Forensics.Prefetch", "", Fields)
            return tools_instance._wrap_results(results, "velociraptor_prefetch", "Prefetch execution evidence")

        @mcp.tool()
        async def velociraptor_shimcache(
            client_id: str,
            Fields: str = "Position,ModificationTime,Path,ExecutionFlag,ControlSet",
        ) -> dict:
            """
            Parse ShimCache (AppCompatCache) entries from the registry.

            Note: Presence in ShimCache may not indicate actual execution.

            Args:
                client_id: Velociraptor client ID.
                Fields: Comma-separated fields to return.

            Returns:
                ShimCache entries with auto-captured IoCs.
            """
            client = tools_instance._get_client()
            results = await client.collect_realtime(client_id, "Windows.Registry.AppCompatCache", "", Fields)
            return tools_instance._wrap_results(results, "velociraptor_shimcache", "ShimCache entries")

        @mcp.tool()
        async def velociraptor_amcache(
            client_id: str,
            Fields: str = "FullPath,SHA1,ProgramID,FileDescription,FileVersion,Publisher,CompileTime,LastModified,LastRunTime",
        ) -> dict:
            """
            Collect evidence of execution from Amcache on a Windows endpoint.

            Args:
                client_id: Velociraptor client ID.
                Fields: Comma-separated fields to return.

            Returns:
                Amcache entries with auto-captured IoCs.
            """
            client = tools_instance._get_client()
            results = await client.collect_realtime(client_id, "Windows.Detection.Amcache", "", Fields)
            return tools_instance._wrap_results(results, "velociraptor_amcache", "Amcache execution evidence")

        @mcp.tool()
        async def velociraptor_userassist(
            client_id: str,
            Fields: str = "Name,User,LastExecution,NumberOfExecutions",
        ) -> dict:
            """
            Extract evidence of execution from UserAssist registry keys.

            Args:
                client_id: Velociraptor client ID.
                Fields: Comma-separated fields to return.

            Returns:
                UserAssist entries with auto-captured IoCs.
            """
            client = tools_instance._get_client()
            results = await client.collect_realtime(client_id, "Windows.Registry.UserAssist", "", Fields)
            return tools_instance._wrap_results(results, "velociraptor_userassist", "UserAssist execution evidence")

        @mcp.tool()
        async def velociraptor_bam(client_id: str, Fields: str = "*") -> dict:
            """
            Extract evidence of execution from the BAM (Background Activity Moderator) registry key.

            Args:
                client_id: Velociraptor client ID.
                Fields: Comma-separated fields to return.

            Returns:
                BAM entries with auto-captured IoCs.
            """
            client = tools_instance._get_client()
            results = await client.collect_realtime(client_id, "Windows.Forensics.Bam", "", Fields)
            return tools_instance._wrap_results(results, "velociraptor_bam", "BAM execution evidence")

        @mcp.tool()
        async def velociraptor_shellbags(
            client_id: str,
            Fields: str = "ModTime,Name,_OSPath,Hive,KeyPath,Description,Path",
        ) -> dict:
            """
            Collect Shellbags from Registry on a Windows endpoint.

            Args:
                client_id: Velociraptor client ID.
                Fields: Comma-separated fields to return.

            Returns:
                Shellbag entries with auto-captured IoCs.
            """
            client = tools_instance._get_client()
            results = await client.collect_realtime(client_id, "Windows.Forensics.Shellbags", "", Fields)
            return tools_instance._wrap_results(results, "velociraptor_shellbags", "Shellbags user activity")

        @mcp.tool()
        async def velociraptor_recentdocs(
            client_id: str,
            Fields: str = "Username,LastWriteTime,Value,Key,MruEntries,HiveName",
        ) -> dict:
            """
            Collect RecentDocs from Registry on a Windows endpoint.

            Args:
                client_id: Velociraptor client ID.
                Fields: Comma-separated fields to return.

            Returns:
                RecentDocs entries with auto-captured IoCs.
            """
            client = tools_instance._get_client()
            results = await client.collect_realtime(client_id, "Windows.Registry.RecentDocs", "", Fields)
            return tools_instance._wrap_results(results, "velociraptor_recentdocs", "Recent documents")

        @mcp.tool()
        async def velociraptor_evidence_of_download(
            client_id: str,
            Fields: str = "DownloadedFilePath,_ZoneIdentifierContent,FileHash,HostUrl,ReferrerUrl",
        ) -> dict:
            """
            Collect evidence of file downloads on a Windows endpoint.

            Args:
                client_id: Velociraptor client ID.
                Fields: Comma-separated fields to return.

            Returns:
                Download evidence with auto-captured IoCs.
            """
            client = tools_instance._get_client()
            results = await client.collect_realtime(client_id, "Windows.Analysis.EvidenceOfDownload", "", Fields)
            return tools_instance._wrap_results(results, "velociraptor_evidence_of_download", "Evidence of download")

        @mcp.tool()
        async def velociraptor_ntfs_mft(
            client_id: str,
            FileRegex: str = ".",
            PathRegex: str = ".",
            MFTDrive: str = "C:",
            DateAfter: str = "",
            DateBefore: str = "",
            Fields: str = "*",
        ) -> dict:
            """
            Search the NTFS MFT for files by name or path on a Windows endpoint.

            This is a forensic-grade search. FileRegex is more performant than PathRegex.

            Args:
                client_id: Velociraptor client ID.
                FileRegex: Regex to match filenames.
                PathRegex: Regex to match file paths (more expensive).
                MFTDrive: Target drive letter (default: C:).
                DateAfter: Filter for files after this timestamp.
                DateBefore: Filter for files before this timestamp.
                Fields: Comma-separated fields to return.

            Returns:
                MFT entries with auto-captured IoCs.
            """
            FileRegex = _sanitize_regex(FileRegex)
            PathRegex = _sanitize_regex(PathRegex)
            MFTDrive = _sanitize_drive(MFTDrive)
            DateAfter = _sanitize_date(DateAfter)
            DateBefore = _sanitize_date(DateBefore)
            client = tools_instance._get_client()
            parameters = (
                f"MFTDrive='{MFTDrive}',"
                f"PathRegex='{PathRegex}',"
                f"FileRegex='{FileRegex}',"
                f"DateAfter='{DateAfter}',"
                f"DateBefore='{DateBefore}'"
            )
            results = await client.collect_realtime(client_id, "Windows.NTFS.MFT", parameters, Fields)
            return tools_instance._wrap_results(results, "velociraptor_ntfs_mft", f"MFT search: {FileRegex}")

        @mcp.tool()
        async def velociraptor_collect_artifact(
            client_id: str,
            artifact: str,
            parameters: str = "",
        ) -> dict:
            """
            Start a generic Velociraptor artifact collection.

            Use this for artifacts not covered by the specialized tools.
            Returns flow metadata — use velociraptor_get_collection_results to retrieve results.

            Args:
                client_id: Velociraptor client ID.
                artifact: Artifact name (e.g. 'Windows.KapeFiles.Targets').
                parameters: Comma-separated key='value' pairs for the artifact.

            Returns:
                Flow metadata including flow_id and artifact specs.
            """
            client = tools_instance._get_client()
            results = await client.start_collection(client_id, artifact, parameters)
            if not results:
                return {"error": f"Failed to start collection for {artifact}"}
            return results[0] if isinstance(results, list) else results

        @mcp.tool()
        async def velociraptor_get_collection_results(
            client_id: str,
            flow_id: str,
            artifact: str,
            fields: str = "*",
            max_retries: int = 10,
            retry_delay: int = 30,
        ) -> dict:
            """
            Retrieve results from a previously started Velociraptor collection.

            Polls for completion and returns results when the flow finishes.

            Args:
                client_id: Velociraptor client ID.
                flow_id: Flow ID from velociraptor_collect_artifact.
                artifact: Artifact name that was collected.
                fields: Comma-separated fields to return.
                max_retries: Number of retry attempts.
                retry_delay: Seconds between retries.

            Returns:
                Collection results with auto-captured IoCs.
            """
            client = tools_instance._get_client()

            for _ in range(max_retries):
                status = await client.get_flow_status(client_id, flow_id, artifact)
                if status == "FINISHED":
                    results = await client.get_flow_results(client_id, flow_id, artifact, fields)
                    return tools_instance._wrap_results(
                        results, "velociraptor_get_collection_results", f"Collection results: {artifact}"
                    )
                await asyncio.sleep(retry_delay)

            return {"error": "Collection did not finish within the timeout period."}

        @mcp.tool()
        async def velociraptor_list_artifacts(os_filter: str = "windows") -> dict:
            """
            List available Velociraptor artifacts for an OS.

            Args:
                os_filter: OS filter — 'windows' or 'linux'.

            Returns:
                List of artifacts with names, descriptions, and parameters.
            """
            client = tools_instance._get_client()
            results = await client.list_artifacts(os_filter)
            return {"artifacts": results, "total": len(results), "os_filter": os_filter}
