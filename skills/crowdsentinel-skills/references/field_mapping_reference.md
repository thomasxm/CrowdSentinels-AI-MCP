# Field Mapping Reference

## Overview

This reference documents common field mappings across different Elasticsearch data schemas. Use this when detection rules fail due to field name mismatches between ECS (Elastic Common Schema) and native log formats.

## Schema Types

| Schema | Index Patterns | Source |
|--------|---------------|--------|
| ECS | `logs-endpoint.*`, `logs-*` | Elastic Agent, Endpoint Security |
| Sysmon | `winlogbeat-*` (with Sysmon) | Winlogbeat + Sysmon |
| Windows Security | `winlogbeat-*` (Security logs) | Winlogbeat + Windows Security |

## Process Fields

| Semantic Field | ECS | Sysmon | Windows Security |
|----------------|-----|--------|------------------|
| Process name | `process.name` | `winlog.event_data.Image` | `winlog.event_data.NewProcessName` |
| Process executable | `process.executable` | `winlog.event_data.Image` | `winlog.event_data.NewProcessName` |
| Process ID | `process.pid` | `winlog.event_data.ProcessId` | `winlog.event_data.NewProcessId` |
| Command line | `process.command_line` | `winlog.event_data.CommandLine` | `winlog.event_data.CommandLine` |
| Parent process | `process.parent.name` | `winlog.event_data.ParentImage` | `winlog.event_data.ParentProcessName` |
| Parent PID | `process.parent.pid` | `winlog.event_data.ParentProcessId` | `winlog.event_data.ProcessId` |
| Parent command line | `process.parent.command_line` | `winlog.event_data.ParentCommandLine` | N/A |
| Working directory | `process.working_directory` | `winlog.event_data.CurrentDirectory` | N/A |
| Process hash (SHA256) | `process.hash.sha256` | `winlog.event_data.Hashes` | N/A |
| Original filename | `process.pe.original_file_name` | `winlog.event_data.OriginalFileName` | N/A |

## User Fields

| Semantic Field | ECS | Sysmon | Windows Security |
|----------------|-----|--------|------------------|
| Username | `user.name` | `winlog.event_data.User` | `winlog.event_data.TargetUserName` |
| User domain | `user.domain` | N/A | `winlog.event_data.TargetDomainName` |
| User SID | `user.id` | N/A | `winlog.event_data.TargetUserSid` |
| Logon ID | `winlog.logon.id` | `winlog.event_data.LogonId` | `winlog.event_data.TargetLogonId` |

## Network Fields

| Semantic Field | ECS | Sysmon | Windows Security |
|----------------|-----|--------|------------------|
| Source IP | `source.ip` | `winlog.event_data.SourceIp` | `winlog.event_data.IpAddress` |
| Source port | `source.port` | `winlog.event_data.SourcePort` | `winlog.event_data.IpPort` |
| Destination IP | `destination.ip` | `winlog.event_data.DestinationIp` | N/A |
| Destination port | `destination.port` | `winlog.event_data.DestinationPort` | N/A |
| Destination hostname | `destination.domain` | `winlog.event_data.DestinationHostname` | N/A |
| Protocol | `network.protocol` | `winlog.event_data.Protocol` | N/A |

## DNS Fields

| Semantic Field | ECS | Sysmon | Windows Security |
|----------------|-----|--------|------------------|
| Query name | `dns.question.name` | `winlog.event_data.QueryName` | N/A |
| Query type | `dns.question.type` | `winlog.event_data.QueryType` | N/A |
| Query results | `dns.answers` | `winlog.event_data.QueryResults` | N/A |

## File Fields

| Semantic Field | ECS | Sysmon | Windows Security |
|----------------|-----|--------|------------------|
| File path | `file.path` | `winlog.event_data.TargetFilename` | `winlog.event_data.ObjectName` |
| File name | `file.name` | `winlog.event_data.TargetFilename` | `winlog.event_data.ObjectName` |
| File hash | `file.hash.sha256` | `winlog.event_data.Hash` | N/A |
| File creation time | `file.created` | `winlog.event_data.CreationUtcTime` | N/A |

## Registry Fields

| Semantic Field | ECS | Sysmon | Windows Security |
|----------------|-----|--------|------------------|
| Registry path | `registry.path` | `winlog.event_data.TargetObject` | `winlog.event_data.ObjectName` |
| Registry value | `registry.value` | `winlog.event_data.Details` | N/A |
| Registry data | `registry.data.strings` | `winlog.event_data.Details` | N/A |

## Host Fields

| Semantic Field | ECS | Sysmon | Windows Security |
|----------------|-----|--------|------------------|
| Hostname | `host.name` | `host.name` | `winlog.computer_name` |
| Host ID | `host.id` | `host.id` | N/A |
| OS | `host.os.name` | `host.os.name` | N/A |

## Event Fields

| Semantic Field | ECS | Sysmon | Windows Security |
|----------------|-----|--------|------------------|
| Event ID | `event.code` | `winlog.event_id` | `winlog.event_id` |
| Event action | `event.action` | `winlog.event_data.RuleName` | N/A |
| Event category | `event.category` | N/A | N/A |
| Event type | `event.type` | N/A | N/A |
| Timestamp | `@timestamp` | `@timestamp` | `@timestamp` |

## Sysmon Event IDs

| Event ID | Description | Key Fields |
|----------|-------------|------------|
| 1 | Process Create | Image, CommandLine, ParentImage |
| 2 | File Creation Time Changed | TargetFilename, CreationUtcTime |
| 3 | Network Connection | SourceIp, DestinationIp, DestinationPort |
| 5 | Process Terminated | Image, ProcessId |
| 6 | Driver Loaded | ImageLoaded, Signature |
| 7 | Image Loaded | ImageLoaded, Image |
| 8 | CreateRemoteThread | SourceImage, TargetImage |
| 9 | RawAccessRead | Image, Device |
| 10 | ProcessAccess | SourceImage, TargetImage, GrantedAccess |
| 11 | FileCreate | TargetFilename, Image |
| 12 | Registry Create/Delete | TargetObject, Image |
| 13 | Registry Value Set | TargetObject, Details, Image |
| 14 | Registry Rename | TargetObject, NewName |
| 15 | FileCreateStreamHash | TargetFilename, Hash |
| 17 | Pipe Created | PipeName, Image |
| 18 | Pipe Connected | PipeName, Image |
| 19 | WMI Event Filter | EventNamespace, Name, Query |
| 20 | WMI Event Consumer | Destination, Name, Type |
| 21 | WMI Consumer Binding | Consumer, Filter |
| 22 | DNS Query | QueryName, QueryResults, Image |
| 23 | File Delete | TargetFilename, Image |
| 24 | Clipboard Change | Image, Session |
| 25 | Process Tampering | Image, Type |
| 26 | File Delete Detected | TargetFilename, Image |

## Windows Security Event IDs

| Event ID | Description | Key Fields |
|----------|-------------|------------|
| 4624 | Successful Logon | TargetUserName, LogonType, IpAddress |
| 4625 | Failed Logon | TargetUserName, LogonType, IpAddress |
| 4627 | Group Membership | TargetUserName, GroupMembership |
| 4634 | Logoff | TargetUserName, LogonType |
| 4648 | Explicit Credential Logon | SubjectUserName, TargetUserName |
| 4656 | Object Access Requested | ObjectName, ObjectType, AccessMask |
| 4663 | Object Access Attempt | ObjectName, ProcessName, AccessMask |
| 4688 | Process Created | NewProcessName, CommandLine, ParentProcessName |
| 4689 | Process Exited | ProcessName, ExitStatus |
| 4697 | Service Installed | ServiceName, ServiceFileName |
| 4698 | Scheduled Task Created | TaskName, TaskContent |
| 4699 | Scheduled Task Deleted | TaskName |
| 4700 | Scheduled Task Enabled | TaskName |
| 4701 | Scheduled Task Disabled | TaskName |
| 4702 | Scheduled Task Updated | TaskName, TaskContent |
| 4720 | User Account Created | TargetUserName, SubjectUserName |
| 4722 | User Account Enabled | TargetUserName |
| 4723 | Password Change Attempt | TargetUserName |
| 4724 | Password Reset Attempt | TargetUserName, SubjectUserName |
| 4725 | User Account Disabled | TargetUserName |
| 4726 | User Account Deleted | TargetUserName |
| 4728 | Member Added to Security Group | MemberName, TargetUserName |
| 4729 | Member Removed from Security Group | MemberName, TargetUserName |
| 4732 | Member Added to Local Group | MemberName, TargetUserName |
| 4733 | Member Removed from Local Group | MemberName, TargetUserName |
| 4768 | Kerberos TGT Requested | TargetUserName, ServiceName |
| 4769 | Kerberos Service Ticket Requested | TargetUserName, ServiceName |
| 4770 | Kerberos Service Ticket Renewed | TargetUserName, ServiceName |
| 4771 | Kerberos Pre-Auth Failed | TargetUserName, IpAddress |
| 4776 | NTLM Authentication | TargetUserName, Workstation |

## Query Examples by Schema

### ECS Query
```
process where process.name == "powershell.exe" and process.command_line like "*-enc*"
```

### Sysmon Query
```
process where winlog.event_data.Image : "*\\powershell.exe" and winlog.event_data.CommandLine : "*-enc*"
```

### Windows Security Query (Lucene)
```
winlog.event_id:4688 AND winlog.event_data.NewProcessName:*powershell.exe AND winlog.event_data.CommandLine:*-enc*
```

## CrowdSentinel Tools for Field Mapping

```python
# Detect schema in your data
detect_schema_for_index(index_pattern="winlogbeat-*")

# Get field mapping for specific field
get_field_mapping(
    semantic_field="process.name",
    event_type="process_create",
    schema_id="sysmon"
)

# List all available schemas
list_available_schemas()

# Get all fields for event type
get_event_type_fields(event_type="process_create")
```
