"""Windows Security Event Log schema definition.

Field names based on Windows Security Event Log documentation:
https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/

This schema covers Windows Security events (Event IDs 4624, 4625, 4688, etc.)
as collected by Winlogbeat.
"""

from .base import EventTypeDefinition, LogSourceSchema, LogSourceType

WINDOWS_SECURITY_SCHEMA = LogSourceSchema(
    name="Windows Security Events",
    schema_id="windows_security",
    source_type=LogSourceType.WINDOWS_SECURITY,
    description="Windows Security event log events collected via Winlogbeat. "
    "Covers authentication, process creation, service installation, etc.",
    index_patterns=[
        "winlogbeat-*",
        "logs-windows.security*",
        "logs-windows.forwarded*",
    ],
    field_prefix="winlog.event_data.",
    common_fields={
        "hostname": "host.name",
        "timestamp": "@timestamp",
        "channel": "winlog.channel",
        "provider_name": "winlog.provider_name",
        "record_id": "winlog.record_id",
    },
    timestamp_field="@timestamp",
    host_field="host.name",
    event_code_field="event.code",
    event_types={
        # Event ID 4624: Successful logon
        "logon_success": EventTypeDefinition(
            event_code="4624",
            description="An account was successfully logged on",
            category="authentication",
            fields={
                "user": "TargetUserName",
                "user_domain": "TargetDomainName",
                "user_sid": "TargetUserSid",
                "logon_type": "LogonType",
                "logon_process": "LogonProcessName",
                "authentication_package": "AuthenticationPackageName",
                "source_ip": "IpAddress",
                "source_port": "IpPort",
                "workstation_name": "WorkstationName",
                "logon_id": "TargetLogonId",
                "logon_guid": "LogonGuid",
                "subject_user": "SubjectUserName",
                "subject_domain": "SubjectDomainName",
                "subject_logon_id": "SubjectLogonId",
                "elevated_token": "ElevatedToken",
                "impersonation_level": "ImpersonationLevel",
                "restricted_admin_mode": "RestrictedAdminMode",
                "virtual_account": "VirtualAccount",
            },
        ),
        # Event ID 4625: Failed logon
        "logon_failure": EventTypeDefinition(
            event_code="4625",
            description="An account failed to log on",
            category="authentication",
            fields={
                "user": "TargetUserName",
                "user_domain": "TargetDomainName",
                "user_sid": "TargetUserSid",
                "logon_type": "LogonType",
                "logon_process": "LogonProcessName",
                "authentication_package": "AuthenticationPackageName",
                "source_ip": "IpAddress",
                "source_port": "IpPort",
                "workstation_name": "WorkstationName",
                "failure_reason": "FailureReason",
                "status": "Status",
                "sub_status": "SubStatus",
                "subject_user": "SubjectUserName",
                "subject_domain": "SubjectDomainName",
                "subject_logon_id": "SubjectLogonId",
            },
        ),
        # Event ID 4634: Logoff
        "logoff": EventTypeDefinition(
            event_code="4634",
            description="An account was logged off",
            category="authentication",
            fields={
                "user": "TargetUserName",
                "user_domain": "TargetDomainName",
                "user_sid": "TargetUserSid",
                "logon_id": "TargetLogonId",
                "logon_type": "LogonType",
            },
        ),
        # Event ID 4648: Explicit credential logon
        "explicit_credential_logon": EventTypeDefinition(
            event_code="4648",
            description="A logon was attempted using explicit credentials",
            category="authentication",
            fields={
                "subject_user": "SubjectUserName",
                "subject_domain": "SubjectDomainName",
                "subject_logon_id": "SubjectLogonId",
                "user": "TargetUserName",
                "user_domain": "TargetDomainName",
                "target_server": "TargetServerName",
                "target_info": "TargetInfo",
                "process_id": "ProcessId",
                "source_process": "ProcessName",
                "source_ip": "IpAddress",
                "source_port": "IpPort",
            },
        ),
        # Event ID 4672: Special privileges assigned
        "special_privileges": EventTypeDefinition(
            event_code="4672",
            description="Special privileges assigned to new logon",
            category="privilege",
            fields={
                "user": "SubjectUserName",
                "user_domain": "SubjectDomainName",
                "user_sid": "SubjectUserSid",
                "logon_id": "SubjectLogonId",
                "privileges": "PrivilegeList",
            },
        ),
        # Event ID 4688: Process creation
        "process_create": EventTypeDefinition(
            event_code="4688",
            description="A new process has been created",
            category="process",
            fields={
                "source_process": "NewProcessName",
                "new_process_id": "NewProcessId",
                "command_line": "CommandLine",
                "creator_process": "CreatorProcessName",
                "parent_process": "ParentProcessName",
                "parent_process_id": "ProcessId",
                "token_elevation_type": "TokenElevationType",
                "mandatory_label": "MandatoryLabel",
                "subject_user": "SubjectUserName",
                "subject_domain": "SubjectDomainName",
                "subject_logon_id": "SubjectLogonId",
                "target_user": "TargetUserName",
                "target_domain": "TargetDomainName",
                "target_logon_id": "TargetLogonId",
            },
        ),
        # Event ID 4689: Process termination
        "process_terminate": EventTypeDefinition(
            event_code="4689",
            description="A process has exited",
            category="process",
            fields={
                "source_process": "ProcessName",
                "process_id": "ProcessId",
                "exit_status": "Status",
                "subject_user": "SubjectUserName",
                "subject_domain": "SubjectDomainName",
                "subject_logon_id": "SubjectLogonId",
            },
        ),
        # Event ID 4697: Service installed
        "service_install": EventTypeDefinition(
            event_code="4697",
            description="A service was installed in the system",
            category="service",
            fields={
                "service_name": "ServiceName",
                "service_file_name": "ServiceFileName",
                "service_type": "ServiceType",
                "service_start_type": "ServiceStartType",
                "service_account": "ServiceAccount",
                "subject_user": "SubjectUserName",
                "subject_domain": "SubjectDomainName",
                "subject_logon_id": "SubjectLogonId",
            },
        ),
        # Event ID 4698: Scheduled task created
        "scheduled_task_create": EventTypeDefinition(
            event_code="4698",
            description="A scheduled task was created",
            category="scheduled_task",
            fields={
                "task_name": "TaskName",
                "task_content": "TaskContent",
                "subject_user": "SubjectUserName",
                "subject_domain": "SubjectDomainName",
                "subject_logon_id": "SubjectLogonId",
            },
        ),
        # Event ID 4699: Scheduled task deleted
        "scheduled_task_delete": EventTypeDefinition(
            event_code="4699",
            description="A scheduled task was deleted",
            category="scheduled_task",
            fields={
                "task_name": "TaskName",
                "subject_user": "SubjectUserName",
                "subject_domain": "SubjectDomainName",
                "subject_logon_id": "SubjectLogonId",
            },
        ),
        # Event ID 4700: Scheduled task enabled
        "scheduled_task_enable": EventTypeDefinition(
            event_code="4700",
            description="A scheduled task was enabled",
            category="scheduled_task",
            fields={
                "task_name": "TaskName",
                "subject_user": "SubjectUserName",
                "subject_domain": "SubjectDomainName",
                "subject_logon_id": "SubjectLogonId",
            },
        ),
        # Event ID 4701: Scheduled task disabled
        "scheduled_task_disable": EventTypeDefinition(
            event_code="4701",
            description="A scheduled task was disabled",
            category="scheduled_task",
            fields={
                "task_name": "TaskName",
                "subject_user": "SubjectUserName",
                "subject_domain": "SubjectDomainName",
                "subject_logon_id": "SubjectLogonId",
            },
        ),
        # Event ID 4702: Scheduled task updated
        "scheduled_task_update": EventTypeDefinition(
            event_code="4702",
            description="A scheduled task was updated",
            category="scheduled_task",
            fields={
                "task_name": "TaskName",
                "task_content": "TaskContent",
                "subject_user": "SubjectUserName",
                "subject_domain": "SubjectDomainName",
                "subject_logon_id": "SubjectLogonId",
            },
        ),
        # Event ID 4720: User account created
        "user_account_create": EventTypeDefinition(
            event_code="4720",
            description="A user account was created",
            category="account",
            fields={
                "target_user": "TargetUserName",
                "target_domain": "TargetDomainName",
                "target_sid": "TargetSid",
                "subject_user": "SubjectUserName",
                "subject_domain": "SubjectDomainName",
                "subject_logon_id": "SubjectLogonId",
                "sam_account_name": "SamAccountName",
                "display_name": "DisplayName",
                "user_principal_name": "UserPrincipalName",
                "home_directory": "HomeDirectory",
                "home_path": "HomePath",
                "script_path": "ScriptPath",
                "profile_path": "ProfilePath",
                "user_workstations": "UserWorkstations",
                "password_last_set": "PasswordLastSet",
                "account_expires": "AccountExpires",
                "primary_group_id": "PrimaryGroupId",
                "allowed_to_delegate_to": "AllowedToDelegateTo",
                "old_uac_value": "OldUacValue",
                "new_uac_value": "NewUacValue",
                "user_account_control": "UserAccountControl",
                "user_parameters": "UserParameters",
                "sid_history": "SidHistory",
                "logon_hours": "LogonHours",
            },
        ),
        # Event ID 4722: User account enabled
        "user_account_enable": EventTypeDefinition(
            event_code="4722",
            description="A user account was enabled",
            category="account",
            fields={
                "target_user": "TargetUserName",
                "target_domain": "TargetDomainName",
                "target_sid": "TargetSid",
                "subject_user": "SubjectUserName",
                "subject_domain": "SubjectDomainName",
                "subject_logon_id": "SubjectLogonId",
            },
        ),
        # Event ID 4723: Password change attempt
        "password_change_attempt": EventTypeDefinition(
            event_code="4723",
            description="An attempt was made to change an account's password",
            category="account",
            fields={
                "target_user": "TargetUserName",
                "target_domain": "TargetDomainName",
                "target_sid": "TargetSid",
                "subject_user": "SubjectUserName",
                "subject_domain": "SubjectDomainName",
                "subject_logon_id": "SubjectLogonId",
            },
        ),
        # Event ID 4724: Password reset attempt
        "password_reset_attempt": EventTypeDefinition(
            event_code="4724",
            description="An attempt was made to reset an account's password",
            category="account",
            fields={
                "target_user": "TargetUserName",
                "target_domain": "TargetDomainName",
                "target_sid": "TargetSid",
                "subject_user": "SubjectUserName",
                "subject_domain": "SubjectDomainName",
                "subject_logon_id": "SubjectLogonId",
            },
        ),
        # Event ID 4728: Member added to security-enabled global group
        "group_member_add_global": EventTypeDefinition(
            event_code="4728",
            description="A member was added to a security-enabled global group",
            category="group",
            fields={
                "target_user": "MemberName",
                "member_sid": "MemberSid",
                "target_group": "TargetUserName",
                "target_domain": "TargetDomainName",
                "target_sid": "TargetSid",
                "subject_user": "SubjectUserName",
                "subject_domain": "SubjectDomainName",
                "subject_logon_id": "SubjectLogonId",
            },
        ),
        # Event ID 4732: Member added to security-enabled local group
        "group_member_add_local": EventTypeDefinition(
            event_code="4732",
            description="A member was added to a security-enabled local group",
            category="group",
            fields={
                "target_user": "MemberName",
                "member_sid": "MemberSid",
                "target_group": "TargetUserName",
                "target_domain": "TargetDomainName",
                "target_sid": "TargetSid",
                "subject_user": "SubjectUserName",
                "subject_domain": "SubjectDomainName",
                "subject_logon_id": "SubjectLogonId",
            },
        ),
        # Event ID 4768: Kerberos TGT request
        "kerberos_tgt_request": EventTypeDefinition(
            event_code="4768",
            description="A Kerberos authentication ticket (TGT) was requested",
            category="authentication",
            fields={
                "user": "TargetUserName",
                "user_domain": "TargetDomainName",
                "user_sid": "TargetSid",
                "service_name": "ServiceName",
                "service_sid": "ServiceSid",
                "ticket_options": "TicketOptions",
                "result_code": "Status",
                "ticket_encryption_type": "TicketEncryptionType",
                "pre_auth_type": "PreAuthType",
                "source_ip": "IpAddress",
                "source_port": "IpPort",
                "cert_issuer_name": "CertIssuerName",
                "cert_serial_number": "CertSerialNumber",
                "cert_thumbprint": "CertThumbprint",
            },
        ),
        # Event ID 4769: Kerberos service ticket request
        "kerberos_service_ticket": EventTypeDefinition(
            event_code="4769",
            description="A Kerberos service ticket was requested",
            category="authentication",
            fields={
                "user": "TargetUserName",
                "user_domain": "TargetDomainName",
                "service_name": "ServiceName",
                "service_sid": "ServiceSid",
                "ticket_options": "TicketOptions",
                "result_code": "Status",
                "ticket_encryption_type": "TicketEncryptionType",
                "failure_code": "FailureCode",
                "source_ip": "IpAddress",
                "source_port": "IpPort",
                "logon_guid": "LogonGuid",
                "transited_services": "TransitedServices",
            },
        ),
        # Event ID 4776: Credential validation
        "credential_validation": EventTypeDefinition(
            event_code="4776",
            description="The domain controller attempted to validate credentials",
            category="authentication",
            fields={
                "user": "TargetUserName",
                "workstation": "Workstation",
                "result_code": "Status",
                "logon_account": "LogonAccount",
                "source_workstation": "SourceWorkstation",
            },
        ),
        # Event ID 5140: Network share access
        "network_share_access": EventTypeDefinition(
            event_code="5140",
            description="A network share object was accessed",
            category="network",
            fields={
                "subject_user": "SubjectUserName",
                "subject_domain": "SubjectDomainName",
                "subject_logon_id": "SubjectLogonId",
                "share_name": "ShareName",
                "share_path": "ShareLocalPath",
                "access_mask": "AccessMask",
                "source_ip": "IpAddress",
                "source_port": "IpPort",
            },
        ),
        # Event ID 5145: Network share check
        "network_share_check": EventTypeDefinition(
            event_code="5145",
            description="A network share object was checked for access",
            category="network",
            fields={
                "subject_user": "SubjectUserName",
                "subject_domain": "SubjectDomainName",
                "subject_logon_id": "SubjectLogonId",
                "share_name": "ShareName",
                "share_path": "ShareLocalPath",
                "relative_target": "RelativeTargetName",
                "access_mask": "AccessMask",
                "access_list": "AccessList",
                "source_ip": "IpAddress",
                "source_port": "IpPort",
            },
        ),
    },
)
