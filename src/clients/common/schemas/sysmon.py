"""Sysmon schema definition for Winlogbeat indices.

Field names verified against official Microsoft Sysmon documentation:
https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

This schema maps Sysmon event types (Event ID 1-29) to their field names
as stored in Winlogbeat indices under winlog.event_data.*.
"""

from .base import EventTypeDefinition, LogSourceSchema, LogSourceType

SYSMON_SCHEMA = LogSourceSchema(
    name="Sysmon (Winlogbeat)",
    schema_id="sysmon",
    source_type=LogSourceType.SYSMON,
    description="Windows Sysmon events collected via Winlogbeat. "
                "Fields are stored under winlog.event_data.* prefix.",
    index_patterns=[
        "winlogbeat-*",
        "logs-windows.sysmon*",
        "logs-windows.sysmon_operational-*",
    ],
    field_prefix="winlog.event_data.",
    common_fields={
        # These fields are at root level, not under winlog.event_data
        "hostname": "host.name",
        "agent_name": "agent.name",
        "timestamp": "@timestamp",
    },
    timestamp_field="@timestamp",
    host_field="host.name",
    event_code_field="event.code",
    event_code_alternatives=[
        "winlog.event_id",           # Winlogbeat native field
        "winlog.event_data.EventCode",  # Some Sysmon configurations
        "EventCode",                  # Raw/legacy field name
    ],
    event_types={
        # Event ID 1: Process Create
        "process_create": EventTypeDefinition(
            event_code="1",
            description="Process creation - logs when a new process is created",
            category="process",
            fields={
                "source_process": "Image",
                "process_guid": "ProcessGuid",
                "process_id": "ProcessId",
                "command_line": "CommandLine",
                "current_directory": "CurrentDirectory",
                "user": "User",
                "logon_guid": "LogonGuid",
                "logon_id": "LogonId",
                "terminal_session_id": "TerminalSessionId",
                "integrity_level": "IntegrityLevel",
                "hashes": "Hashes",
                "parent_process": "ParentImage",
                "parent_process_guid": "ParentProcessGuid",
                "parent_process_id": "ParentProcessId",
                "parent_command_line": "ParentCommandLine",
                "parent_user": "ParentUser",
                "rule_name": "RuleName",
                "utc_time": "UtcTime",
                "original_file_name": "OriginalFileName",
                "file_version": "FileVersion",
                "description": "Description",
                "product": "Product",
                "company": "Company",
            }
        ),

        # Event ID 2: File creation time changed
        "file_time_change": EventTypeDefinition(
            event_code="2",
            description="File creation time changed - timestomping detection",
            category="file",
            fields={
                "source_process": "Image",
                "process_guid": "ProcessGuid",
                "process_id": "ProcessId",
                "target_filename": "TargetFilename",
                "creation_utc_time": "CreationUtcTime",
                "previous_creation_utc_time": "PreviousCreationUtcTime",
                "user": "User",
                "utc_time": "UtcTime",
            }
        ),

        # Event ID 3: Network connection
        "network_connection": EventTypeDefinition(
            event_code="3",
            description="Network connection detected",
            category="network",
            fields={
                "source_process": "Image",
                "process_guid": "ProcessGuid",
                "process_id": "ProcessId",
                "user": "User",
                "protocol": "Protocol",
                "initiated": "Initiated",
                "source_is_ipv6": "SourceIsIpv6",
                "source_ip": "SourceIp",
                "source_hostname": "SourceHostname",
                "source_port": "SourcePort",
                "source_port_name": "SourcePortName",
                "destination_is_ipv6": "DestinationIsIpv6",
                "destination_ip": "DestinationIp",
                "destination_hostname": "DestinationHostname",
                "destination_port": "DestinationPort",
                "destination_port_name": "DestinationPortName",
                "utc_time": "UtcTime",
            }
        ),

        # Event ID 4: Sysmon service state changed
        "service_state_change": EventTypeDefinition(
            event_code="4",
            description="Sysmon service state changed",
            category="service",
            fields={
                "state": "State",
                "version": "Version",
                "schema_version": "SchemaVersion",
                "utc_time": "UtcTime",
            }
        ),

        # Event ID 5: Process terminated
        "process_terminate": EventTypeDefinition(
            event_code="5",
            description="Process terminated",
            category="process",
            fields={
                "source_process": "Image",
                "process_guid": "ProcessGuid",
                "process_id": "ProcessId",
                "user": "User",
                "utc_time": "UtcTime",
            }
        ),

        # Event ID 6: Driver loaded
        "driver_load": EventTypeDefinition(
            event_code="6",
            description="Driver loaded",
            category="driver",
            fields={
                "source_process": "ImageLoaded",
                "hashes": "Hashes",
                "signed": "Signed",
                "signature": "Signature",
                "signature_status": "SignatureStatus",
                "utc_time": "UtcTime",
            }
        ),

        # Event ID 7: Image loaded
        "image_load": EventTypeDefinition(
            event_code="7",
            description="Image loaded - DLL or executable loaded into process",
            category="process",
            fields={
                "source_process": "Image",
                "process_guid": "ProcessGuid",
                "process_id": "ProcessId",
                "image_loaded": "ImageLoaded",
                "file_version": "FileVersion",
                "description": "Description",
                "product": "Product",
                "company": "Company",
                "original_file_name": "OriginalFileName",
                "hashes": "Hashes",
                "signed": "Signed",
                "signature": "Signature",
                "signature_status": "SignatureStatus",
                "user": "User",
                "utc_time": "UtcTime",
            }
        ),

        # Event ID 8: CreateRemoteThread
        "remote_thread": EventTypeDefinition(
            event_code="8",
            description="CreateRemoteThread detected - process injection indicator",
            category="process",
            fields={
                "source_process": "SourceImage",
                "source_process_guid": "SourceProcessGuid",
                "source_process_id": "SourceProcessId",
                "source_user": "SourceUser",
                "target_process": "TargetImage",
                "target_process_guid": "TargetProcessGuid",
                "target_process_id": "TargetProcessId",
                "target_user": "TargetUser",
                "new_thread_id": "NewThreadId",
                "start_address": "StartAddress",
                "start_module": "StartModule",
                "start_function": "StartFunction",
                "utc_time": "UtcTime",
            }
        ),

        # Event ID 9: RawAccessRead
        "raw_access_read": EventTypeDefinition(
            event_code="9",
            description="RawAccessRead detected - direct disk access",
            category="file",
            fields={
                "source_process": "Image",
                "process_guid": "ProcessGuid",
                "process_id": "ProcessId",
                "device": "Device",
                "user": "User",
                "utc_time": "UtcTime",
            }
        ),

        # Event ID 10: ProcessAccess
        "process_access": EventTypeDefinition(
            event_code="10",
            description="Process accessed - credential dumping indicator",
            category="process",
            fields={
                "source_process": "SourceImage",
                "source_process_guid": "SourceProcessGUID",
                "source_process_id": "SourceProcessId",
                "source_thread_id": "SourceThreadId",
                "source_user": "SourceUser",
                "target_process": "TargetImage",
                "target_process_guid": "TargetProcessGUID",
                "target_process_id": "TargetProcessId",
                "target_user": "TargetUser",
                "granted_access": "GrantedAccess",
                "call_trace": "CallTrace",
                "utc_time": "UtcTime",
            }
        ),

        # Event ID 11: FileCreate
        "file_create": EventTypeDefinition(
            event_code="11",
            description="File created",
            category="file",
            fields={
                "source_process": "Image",
                "process_guid": "ProcessGuid",
                "process_id": "ProcessId",
                "target_filename": "TargetFilename",
                "creation_utc_time": "CreationUtcTime",
                "user": "User",
                "utc_time": "UtcTime",
            }
        ),

        # Event ID 12: RegistryEvent (Object create and delete)
        "registry_create_delete": EventTypeDefinition(
            event_code="12",
            description="Registry object added or deleted",
            category="registry",
            fields={
                "source_process": "Image",
                "process_guid": "ProcessGuid",
                "process_id": "ProcessId",
                "event_type": "EventType",
                "target_object": "TargetObject",
                "user": "User",
                "utc_time": "UtcTime",
            }
        ),

        # Event ID 13: RegistryEvent (Value Set)
        "registry_value_set": EventTypeDefinition(
            event_code="13",
            description="Registry value set",
            category="registry",
            fields={
                "source_process": "Image",
                "process_guid": "ProcessGuid",
                "process_id": "ProcessId",
                "event_type": "EventType",
                "target_object": "TargetObject",
                "details": "Details",
                "user": "User",
                "utc_time": "UtcTime",
            }
        ),

        # Event ID 14: RegistryEvent (Key and Value Rename)
        "registry_rename": EventTypeDefinition(
            event_code="14",
            description="Registry key and value renamed",
            category="registry",
            fields={
                "source_process": "Image",
                "process_guid": "ProcessGuid",
                "process_id": "ProcessId",
                "event_type": "EventType",
                "target_object": "TargetObject",
                "new_name": "NewName",
                "user": "User",
                "utc_time": "UtcTime",
            }
        ),

        # Event ID 15: FileCreateStreamHash
        "file_stream_create": EventTypeDefinition(
            event_code="15",
            description="File stream created - alternate data streams",
            category="file",
            fields={
                "source_process": "Image",
                "process_guid": "ProcessGuid",
                "process_id": "ProcessId",
                "target_filename": "TargetFilename",
                "creation_utc_time": "CreationUtcTime",
                "hash": "Hash",
                "contents": "Contents",
                "user": "User",
                "utc_time": "UtcTime",
            }
        ),

        # Event ID 16: Sysmon config state changed
        "config_change": EventTypeDefinition(
            event_code="16",
            description="Sysmon config state changed",
            category="service",
            fields={
                "configuration": "Configuration",
                "configuration_file_hash": "ConfigurationFileHash",
                "utc_time": "UtcTime",
            }
        ),

        # Event ID 17: PipeEvent (Pipe Created)
        "pipe_create": EventTypeDefinition(
            event_code="17",
            description="Named pipe created",
            category="pipe",
            fields={
                "source_process": "Image",
                "process_guid": "ProcessGuid",
                "process_id": "ProcessId",
                "pipe_name": "PipeName",
                "user": "User",
                "utc_time": "UtcTime",
            }
        ),

        # Event ID 18: PipeEvent (Pipe Connected)
        "pipe_connect": EventTypeDefinition(
            event_code="18",
            description="Named pipe connection made",
            category="pipe",
            fields={
                "source_process": "Image",
                "process_guid": "ProcessGuid",
                "process_id": "ProcessId",
                "pipe_name": "PipeName",
                "user": "User",
                "utc_time": "UtcTime",
            }
        ),

        # Event ID 19: WmiEvent (WmiEventFilter activity)
        "wmi_filter": EventTypeDefinition(
            event_code="19",
            description="WMI event filter registered",
            category="wmi",
            fields={
                "event_type": "EventType",
                "operation": "Operation",
                "user": "User",
                "event_namespace": "EventNamespace",
                "name": "Name",
                "query": "Query",
                "utc_time": "UtcTime",
            }
        ),

        # Event ID 20: WmiEvent (WmiEventConsumer activity)
        "wmi_consumer": EventTypeDefinition(
            event_code="20",
            description="WMI event consumer registered",
            category="wmi",
            fields={
                "event_type": "EventType",
                "operation": "Operation",
                "user": "User",
                "name": "Name",
                "type": "Type",
                "destination": "Destination",
                "utc_time": "UtcTime",
            }
        ),

        # Event ID 21: WmiEvent (WmiEventConsumerToFilter activity)
        "wmi_binding": EventTypeDefinition(
            event_code="21",
            description="WMI consumer to filter binding",
            category="wmi",
            fields={
                "event_type": "EventType",
                "operation": "Operation",
                "user": "User",
                "consumer": "Consumer",
                "filter": "Filter",
                "utc_time": "UtcTime",
            }
        ),

        # Event ID 22: DNSEvent
        "dns_query": EventTypeDefinition(
            event_code="22",
            description="DNS query",
            category="network",
            fields={
                "source_process": "Image",
                "process_guid": "ProcessGuid",
                "process_id": "ProcessId",
                "query_name": "QueryName",
                "query_status": "QueryStatus",
                "query_results": "QueryResults",
                "user": "User",
                "utc_time": "UtcTime",
            }
        ),

        # Event ID 23: FileDelete (archived)
        "file_delete_archived": EventTypeDefinition(
            event_code="23",
            description="File deleted with content archived",
            category="file",
            fields={
                "source_process": "Image",
                "process_guid": "ProcessGuid",
                "process_id": "ProcessId",
                "user": "User",
                "target_filename": "TargetFilename",
                "hashes": "Hashes",
                "is_executable": "IsExecutable",
                "archived": "Archived",
                "utc_time": "UtcTime",
            }
        ),

        # Event ID 24: ClipboardChange
        "clipboard_change": EventTypeDefinition(
            event_code="24",
            description="Clipboard content changed",
            category="clipboard",
            fields={
                "source_process": "Image",
                "process_guid": "ProcessGuid",
                "process_id": "ProcessId",
                "session": "Session",
                "client_info": "ClientInfo",
                "hashes": "Hashes",
                "archived": "Archived",
                "user": "User",
                "utc_time": "UtcTime",
            }
        ),

        # Event ID 25: ProcessTampering
        "process_tampering": EventTypeDefinition(
            event_code="25",
            description="Process image change detected - process hollowing",
            category="process",
            fields={
                "source_process": "Image",
                "process_guid": "ProcessGuid",
                "process_id": "ProcessId",
                "type": "Type",
                "user": "User",
                "utc_time": "UtcTime",
            }
        ),

        # Event ID 26: FileDeleteDetected
        "file_delete_logged": EventTypeDefinition(
            event_code="26",
            description="File deleted (logged, not archived)",
            category="file",
            fields={
                "source_process": "Image",
                "process_guid": "ProcessGuid",
                "process_id": "ProcessId",
                "user": "User",
                "target_filename": "TargetFilename",
                "hashes": "Hashes",
                "is_executable": "IsExecutable",
                "utc_time": "UtcTime",
            }
        ),

        # Event ID 27: FileBlockExecutable
        "file_block_executable": EventTypeDefinition(
            event_code="27",
            description="File block executable",
            category="file",
            fields={
                "source_process": "Image",
                "process_guid": "ProcessGuid",
                "process_id": "ProcessId",
                "user": "User",
                "target_filename": "TargetFilename",
                "hashes": "Hashes",
                "utc_time": "UtcTime",
            }
        ),

        # Event ID 28: FileBlockShredding
        "file_block_shredding": EventTypeDefinition(
            event_code="28",
            description="File block shredding",
            category="file",
            fields={
                "source_process": "Image",
                "process_guid": "ProcessGuid",
                "process_id": "ProcessId",
                "user": "User",
                "target_filename": "TargetFilename",
                "hashes": "Hashes",
                "is_executable": "IsExecutable",
                "utc_time": "UtcTime",
            }
        ),

        # Event ID 29: FileExecutableDetected
        "file_executable_detected": EventTypeDefinition(
            event_code="29",
            description="File executable detected",
            category="file",
            fields={
                "source_process": "Image",
                "process_guid": "ProcessGuid",
                "process_id": "ProcessId",
                "user": "User",
                "target_filename": "TargetFilename",
                "hashes": "Hashes",
                "utc_time": "UtcTime",
            }
        ),
    }
)
