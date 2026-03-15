"""Elastic Common Schema (ECS) definition.

Field names based on the Elastic Common Schema reference:
https://www.elastic.co/guide/en/ecs/current/index.html

ECS provides a common set of fields for normalised event data across
different log sources. This schema is used for Elastic Agent, Endpoint
Security, and other ECS-compliant data sources.
"""

from .base import EventTypeDefinition, LogSourceSchema, LogSourceType

ECS_SCHEMA = LogSourceSchema(
    name="Elastic Common Schema",
    schema_id="ecs",
    source_type=LogSourceType.ECS,
    description="Elastic Common Schema compliant logs from Elastic Agent, "
                "Endpoint Security, or other ECS-normalised sources.",
    index_patterns=[
        "logs-endpoint.*",
        "logs-endpoint.events.*",
        "logs-endpoint.events.process-*",
        "logs-endpoint.events.network-*",
        "logs-endpoint.events.file-*",
        "logs-*",
        ".ds-logs-*",
    ],
    field_prefix="",  # ECS fields are at root level
    common_fields={
        "hostname": "host.name",
        "timestamp": "@timestamp",
        "user": "user.name",
        "user_domain": "user.domain",
        "agent_id": "agent.id",
        "agent_name": "agent.name",
        "event_action": "event.action",
        "event_category": "event.category",
        "event_type": "event.type",
        "event_outcome": "event.outcome",
    },
    timestamp_field="@timestamp",
    host_field="host.name",
    event_code_field="event.action",  # ECS uses event.action instead of numeric codes
    event_types={
        # Process events
        "process_create": EventTypeDefinition(
            event_code="start",
            description="Process started",
            category="process",
            fields={
                "source_process": "process.executable",
                "process_name": "process.name",
                "process_id": "process.pid",
                "process_entity_id": "process.entity_id",
                "command_line": "process.command_line",
                "args": "process.args",
                "working_directory": "process.working_directory",
                "user": "user.name",
                "user_id": "user.id",
                "parent_process": "process.parent.executable",
                "parent_process_name": "process.parent.name",
                "parent_process_id": "process.parent.pid",
                "parent_entity_id": "process.parent.entity_id",
                "parent_command_line": "process.parent.command_line",
                "hash_sha256": "process.hash.sha256",
                "hash_sha1": "process.hash.sha1",
                "hash_md5": "process.hash.md5",
                "code_signature_subject_name": "process.code_signature.subject_name",
                "code_signature_status": "process.code_signature.status",
            }
        ),

        "process_terminate": EventTypeDefinition(
            event_code="end",
            description="Process ended",
            category="process",
            fields={
                "source_process": "process.executable",
                "process_name": "process.name",
                "process_id": "process.pid",
                "process_entity_id": "process.entity_id",
                "exit_code": "process.exit_code",
                "user": "user.name",
            }
        ),

        # Network events
        "network_connection": EventTypeDefinition(
            event_code="connection",
            description="Network connection",
            category="network",
            fields={
                "source_process": "process.executable",
                "process_name": "process.name",
                "process_id": "process.pid",
                "source_ip": "source.ip",
                "source_port": "source.port",
                "source_bytes": "source.bytes",
                "destination_ip": "destination.ip",
                "destination_port": "destination.port",
                "destination_bytes": "destination.bytes",
                "destination_domain": "destination.domain",
                "network_direction": "network.direction",
                "network_transport": "network.transport",
                "network_protocol": "network.protocol",
                "user": "user.name",
            }
        ),

        # DNS events
        "dns_query": EventTypeDefinition(
            event_code="lookup",
            description="DNS query",
            category="network",
            fields={
                "source_process": "process.executable",
                "process_name": "process.name",
                "process_id": "process.pid",
                "query_name": "dns.question.name",
                "query_type": "dns.question.type",
                "resolved_ip": "dns.resolved_ip",
                "answers": "dns.answers",
                "response_code": "dns.response_code",
            }
        ),

        # File events
        "file_create": EventTypeDefinition(
            event_code="creation",
            description="File created",
            category="file",
            fields={
                "source_process": "process.executable",
                "process_name": "process.name",
                "process_id": "process.pid",
                "target_filename": "file.path",
                "file_name": "file.name",
                "file_extension": "file.extension",
                "file_size": "file.size",
                "file_hash_sha256": "file.hash.sha256",
                "user": "user.name",
            }
        ),

        "file_modify": EventTypeDefinition(
            event_code="modification",
            description="File modified",
            category="file",
            fields={
                "source_process": "process.executable",
                "process_name": "process.name",
                "process_id": "process.pid",
                "target_filename": "file.path",
                "file_name": "file.name",
                "previous_hash": "file.hash.sha256",
                "user": "user.name",
            }
        ),

        "file_delete": EventTypeDefinition(
            event_code="deletion",
            description="File deleted",
            category="file",
            fields={
                "source_process": "process.executable",
                "process_name": "process.name",
                "process_id": "process.pid",
                "target_filename": "file.path",
                "file_name": "file.name",
                "user": "user.name",
            }
        ),

        # Registry events (Windows)
        "registry_modification": EventTypeDefinition(
            event_code="modification",
            description="Registry modification",
            category="registry",
            fields={
                "source_process": "process.executable",
                "process_name": "process.name",
                "process_id": "process.pid",
                "target_object": "registry.path",
                "registry_key": "registry.key",
                "registry_value": "registry.value",
                "registry_data": "registry.data.strings",
                "user": "user.name",
            }
        ),

        # Authentication events
        "authentication_success": EventTypeDefinition(
            event_code="authentication_success",
            description="Successful authentication",
            category="authentication",
            fields={
                "user": "user.name",
                "user_domain": "user.domain",
                "user_id": "user.id",
                "source_ip": "source.ip",
                "source_port": "source.port",
            }
        ),

        "authentication_failure": EventTypeDefinition(
            event_code="authentication_failure",
            description="Failed authentication",
            category="authentication",
            fields={
                "user": "user.name",
                "user_domain": "user.domain",
                "source_ip": "source.ip",
                "failure_reason": "event.reason",
            }
        ),

        # Library/module loading
        "library_load": EventTypeDefinition(
            event_code="library_loaded",
            description="Library loaded into process",
            category="process",
            fields={
                "source_process": "process.executable",
                "process_name": "process.name",
                "process_id": "process.pid",
                "image_loaded": "dll.path",
                "dll_name": "dll.name",
                "hash_sha256": "dll.hash.sha256",
                "code_signature_subject": "dll.code_signature.subject_name",
                "user": "user.name",
            }
        ),
    }
)
