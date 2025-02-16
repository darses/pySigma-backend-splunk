from sigma.pipelines.common import (
    logsource_windows,
    logsource_windows_process_creation,
    logsource_windows_registry_add,
    logsource_windows_registry_delete,
    logsource_windows_registry_event,
    logsource_windows_registry_set,
    logsource_windows_file_event,
    logsource_linux_process_creation,
    generate_windows_logsource_items,
)
from sigma.processing.transformations import (
    AddConditionTransformation,
    FieldMappingTransformation,
    DetectionItemFailureTransformation,
    RuleFailureTransformation,
    SetStateTransformation,
)
from sigma.processing.conditions import (
    LogsourceCondition,
    ExcludeFieldCondition,
    RuleProcessingItemAppliedCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from typing import Dict, List, FrozenSet

windows_sysmon_acceleration_keywords = {  # Map Sysmon event sources and keywords that are added to search for Sysmon optimization pipeline
    "process_creation": "ParentProcessGuid",
    "file_event": "TargetFilename",
}

splunk_sysmon_process_creation_cim_mapping: Dict[str, str | List[str]] = {
    "CommandLine": "Processes.process",
    "Computer": "Processes.dest",
    "CurrentDirectory": "Processes.process_current_directory",
    "Image": "Processes.process_path",
    "IntegrityLevel": "Processes.process_integrity_level",
    "OriginalFileName": "Processes.original_file_name",
    "ParentCommandLine": "Processes.parent_process",
    "ParentImage": "Processes.parent_process_path",
    "ParentProcessGuid": "Processes.parent_process_guid",
    "ParentProcessId": "Processes.parent_process_id",
    "ProcessGuid": "Processes.process_guid",
    "ProcessId": "Processes.process_id",
    "User": "Processes.user",
    "LogonId": "Processes.logon_id",
    "LogonGuid": "Processes.logon_guid",
    "Session": "Processes.session_id",
    "Status": "Processes.status"
}

splunk_windows_registry_cim_mapping: Dict[str, str | List[str]] = {
    "Computer": "Registry.dest",
    "Details": "Registry.registry_value_data",
    "EventType": "Registry.action",
    "Image": "Registry.process_path",
    "ProcessGuid": "Registry.process_guid",
    "ProcessId": "Registry.process_id",
    "TargetObject": "Registry.registry_key_name",
    "User": "Registry.user",
    "Status": "Registry.status",
    "Type": "Registry.registry_value_type"
}

splunk_windows_file_event_cim_mapping: Dict[str, str | List[str]] = {
    "Computer": "Filesystem.dest",
    "CreationUtcTime": "Filesystem.file_create_time",
    "Image": "Filesystem.process_path",
    "ProcessGuid": "Filesystem.process_guid",
    "ProcessId": "Filesystem.process_id",
    "TargetFilename": "Filesystem.file_path",
    "User": "Filesystem.user",
    "FileHash": "Filesystem.file_hash",
    "FileSize": "Filesystem.file_size",
    "FileType": "Filesystem.file_type",
    "Action": "Filesystem.action"
}

splunk_web_proxy_cim_mapping: Dict[str, str | List[str]] = {
    "c-uri": "Web.url",
    "c-uri-query": "Web.uri_query",
    "c-uri-stem": "Web.uri_path",
    "c-useragent": "Web.http_user_agent",
    "cs-method": "Web.http_method",
    "cs-host": "Web.dest",
    "cs-referrer": "Web.http_referrer",
    "src_ip": "Web.src",
    "dst_ip": "Web.dest_ip",
    "status": "Web.status",
    "bytes": "Web.bytes",
    "bytes_in": "Web.bytes_in",
    "bytes_out": "Web.bytes_out",
    "user": "Web.user"
}

splunk_dns_cim_mapping: Dict[str, str | List[str]] = {
    "query": "DNS.query",
    "answer": "DNS.answer",
    "record_type": "DNS.record_type",
    "parent_domain": "DNS.parent_domain",
    "query_type": "DNS.query_type",
    "src_ip": "DNS.src",
    "dst_ip": "DNS.dest",
    "src_port": "DNS.src_port",
    "dest_port": "DNS.dest_port",
    "transport": "DNS.transport",
    "answer_count": "DNS.answer_count",
    "ttl": "DNS.ttl"
}

splunk_network_traffic_cim_mapping: Dict[str, str | List[str]] = {
    "src_ip": "Network_Traffic.src",
    "dst_ip": "Network_Traffic.dest",
    "src_port": "Network_Traffic.src_port",
    "dst_port": "Network_Traffic.dest_port",
    "protocol": "Network_Traffic.protocol",
    "bytes_in": "Network_Traffic.bytes_in",
    "bytes_out": "Network_Traffic.bytes_out",
    "app": "Network_Traffic.app", 
    "dest_host": "Network_Traffic.dest_host",
    "transport": "Network_Traffic.transport",
    "duration": "Network_Traffic.duration",
    "user": "Network_Traffic.user"
}

splunk_authentication_cim_mapping: Dict[str, str | List[str]] = {
    "user": "Authentication.user",
    "app": "Authentication.app",
    "src": "Authentication.src",
    "src_ip": "Authentication.src_ip", 
    "dest": "Authentication.dest",
    "dest_ip": "Authentication.dest_ip",
    "signature": "Authentication.signature",
    "action": "Authentication.action",
    "status": "Authentication.status"
}

splunk_ids_cim_mapping: Dict[str, str | List[str]] = {
    "src_ip": "IDS.src",
    "dst_ip": "IDS.dest", 
    "src_port": "IDS.src_port",
    "dst_port": "IDS.dest_port",
    "signature": "IDS.signature",
    "signature_id": "IDS.signature_id",
    "severity": "IDS.severity",
    "category": "IDS.category",
    "transport": "IDS.transport"
}

splunk_email_cim_mapping: Dict[str, str | List[str]] = {
    "src_user": "Email.src_user",
    "src_ip": "Email.src_ip",
    "dest_user": "Email.dest_user",
    "dest_ip": "Email.dest_ip",
    "subject": "Email.subject",
    "message_id": "Email.message_id",
    "attachment_name": "Email.file_name",
    "attachment_size": "Email.file_size",
    "direction": "Email.direction"
}

def splunk_windows_pipeline():
    return ProcessingPipeline(
        name="Splunk Windows log source conditions",
        allowed_backends=frozenset(["splunk"]),
        priority=20,
        items=generate_windows_logsource_items("source", "WinEventLog:{source}")
        + [
            ProcessingItem(  # Field mappings
                identifier="splunk_windows_field_mapping",
                transformation=FieldMappingTransformation(
                    {
                        "EventID": "EventCode",
                    }
                ),
            )
        ],
    )


def splunk_windows_sysmon_acceleration_keywords():
    return ProcessingPipeline(
        name="Splunk Windows Sysmon search acceleration keywords",
        allowed_backends=frozenset(["splunk"]),
        priority=25,
        items=[
            ProcessingItem(  # Some optimizations searching for characteristic keyword for specific log sources
                identifier="splunk_windows_sysmon_process_creation",
                transformation=AddConditionTransformation(
                    {
                        "": keyword,
                    }
                ),
                rule_conditions=[
                    LogsourceCondition(
                        category=sysmon_category,
                        product="windows",
                        service="sysmon",
                    )
                ],
            )
            for sysmon_category, keyword in windows_sysmon_acceleration_keywords.items()
        ],
    )


def splunk_cim_data_model():
    return ProcessingPipeline(
        name="Splunk CIM Data Model Mapping",
        allowed_backends=frozenset(["splunk"]),
        priority=20,
        items=[
            ProcessingItem(
                identifier="splunk_dm_mapping_sysmon_process_creation_unsupported_fields",
                transformation=DetectionItemFailureTransformation(
                    "The Splunk Data Model Sigma backend supports only the following fields for process_creation log source: "
                    + ",".join(list(splunk_sysmon_process_creation_cim_mapping.keys()))
                ),
                rule_conditions=[
                    logsource_windows_process_creation(),
                    logsource_linux_process_creation(),
                ],
                rule_condition_linking=any,
                field_name_conditions=[
                    ExcludeFieldCondition(
                        fields=list(splunk_sysmon_process_creation_cim_mapping.keys())
                    )
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_mapping_sysmon_process_creation",
                transformation=FieldMappingTransformation(
                    splunk_sysmon_process_creation_cim_mapping
                ),
                rule_conditions=[
                    logsource_windows_process_creation(),
                    logsource_linux_process_creation(),
                ],
                rule_condition_linking=any,
            ),
            ProcessingItem(
                identifier="splunk_dm_fields_sysmon_process_creation",
                transformation=SetStateTransformation(
                    "fields", splunk_sysmon_process_creation_cim_mapping.values()
                ),
                rule_conditions=[
                    logsource_windows_process_creation(),
                    logsource_linux_process_creation(),
                ],
                rule_condition_linking=any,
            ),
            ProcessingItem(
                identifier="splunk_dm_sysmon_process_creation_data_model_set",
                transformation=SetStateTransformation(
                    "data_model_set", "Endpoint.Processes"
                ),
                rule_conditions=[
                    logsource_windows_process_creation(),
                    logsource_linux_process_creation(),
                ],
                rule_condition_linking=any,
            ),
            ProcessingItem(
                identifier="splunk_dm_mapping_sysmon_registry_unsupported_fields",
                transformation=DetectionItemFailureTransformation(
                    "The Splunk Data Model Sigma backend supports only the following fields for registry log source: "
                    + ",".join(list(splunk_windows_registry_cim_mapping.keys()))
                ),
                rule_conditions=[
                    logsource_windows_registry_add(),
                    logsource_windows_registry_delete(),
                    logsource_windows_registry_event(),
                    logsource_windows_registry_set(),
                ],
                rule_condition_linking=any,
                field_name_conditions=[
                    ExcludeFieldCondition(
                        fields=list(splunk_windows_registry_cim_mapping.keys())
                    )
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_mapping_sysmon_registry",
                transformation=FieldMappingTransformation(
                    splunk_windows_registry_cim_mapping
                ),
                rule_conditions=[
                    logsource_windows_registry_add(),
                    logsource_windows_registry_delete(),
                    logsource_windows_registry_event(),
                    logsource_windows_registry_set(),
                ],
                rule_condition_linking=any,
            ),
            ProcessingItem(
                identifier="splunk_dm_fields_sysmon_registry",
                transformation=SetStateTransformation(
                    "fields", splunk_windows_registry_cim_mapping.values()
                ),
                rule_conditions=[
                    logsource_windows_registry_add(),
                    logsource_windows_registry_delete(),
                    logsource_windows_registry_event(),
                    logsource_windows_registry_set(),
                ],
                rule_condition_linking=any,
            ),
            ProcessingItem(
                identifier="splunk_dm_sysmon_registry_data_model_set",
                transformation=SetStateTransformation(
                    "data_model_set", "Endpoint.Registry"
                ),
                rule_conditions=[
                    logsource_windows_registry_add(),
                    logsource_windows_registry_delete(),
                    logsource_windows_registry_event(),
                    logsource_windows_registry_set(),
                ],
                rule_condition_linking=any,
            ),
            ProcessingItem(
                identifier="splunk_dm_mapping_sysmon_file_event_unsupported_fields",
                transformation=DetectionItemFailureTransformation(
                    "The Splunk Data Model Sigma backend supports only the following fields for file_event log source: "
                    + ",".join(list(splunk_windows_file_event_cim_mapping.keys()))
                ),
                rule_conditions=[
                    logsource_windows_file_event(),
                ],
                field_name_conditions=[
                    ExcludeFieldCondition(
                        fields=list(splunk_windows_file_event_cim_mapping.keys())
                    )
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_mapping_sysmon_file_event",
                transformation=FieldMappingTransformation(
                    splunk_windows_file_event_cim_mapping
                ),
                rule_conditions=[
                    logsource_windows_file_event(),
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_fields_sysmon_file_event",
                transformation=SetStateTransformation(
                    "fields", splunk_windows_file_event_cim_mapping.values()
                ),
                rule_conditions=[
                    logsource_windows_file_event(),
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_mapping_sysmon_file_event_data_model_set",
                transformation=SetStateTransformation(
                    "data_model_set", "Endpoint.Filesystem"
                ),
                rule_conditions=[
                    logsource_windows_file_event(),
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_mapping_web_proxy_unsupported_fields",
                transformation=DetectionItemFailureTransformation(
                    "The Splunk Data Model Sigma backend supports only the following fields for web proxy log source: "
                    + ",".join(list(splunk_web_proxy_cim_mapping.keys()))
                ),
                rule_conditions=[
                    LogsourceCondition(category="proxy"),
                ],
                field_name_conditions=[
                    ExcludeFieldCondition(
                        fields=list(splunk_web_proxy_cim_mapping.keys())
                    )
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_mapping_web_proxy",
                transformation=FieldMappingTransformation(
                    splunk_web_proxy_cim_mapping
                ),
                rule_conditions=[
                    LogsourceCondition(category="proxy"),
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_fields_web_proxy",
                transformation=SetStateTransformation(
                    "fields", splunk_web_proxy_cim_mapping.values()
                ),
                rule_conditions=[
                    LogsourceCondition(category="proxy"),
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_mapping_web_proxy_data_model_set",
                transformation=SetStateTransformation(
                    "data_model_set", "Web.Proxy"
                ),
                rule_conditions=[
                    LogsourceCondition(category="proxy"),
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_mapping_dns_unsupported_fields",
                transformation=DetectionItemFailureTransformation(
                    "The Splunk Data Model Sigma backend supports only the following fields for DNS log source: "
                    + ",".join(list(splunk_dns_cim_mapping.keys()))
                ),
                rule_conditions=[
                    LogsourceCondition(category="dns"),
                ],
                field_name_conditions=[
                    ExcludeFieldCondition(
                        fields=list(splunk_dns_cim_mapping.keys())
                    )
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_mapping_dns",
                transformation=FieldMappingTransformation(
                    splunk_dns_cim_mapping
                ),
                rule_conditions=[
                    LogsourceCondition(category="dns"),
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_fields_dns",
                transformation=SetStateTransformation(
                    "fields", splunk_dns_cim_mapping.values()
                ),
                rule_conditions=[
                    LogsourceCondition(category="dns"),
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_mapping_dns_data_model_set",
                transformation=SetStateTransformation(
                    "data_model_set", "Network_Resolution.DNS"
                ),
                rule_conditions=[
                    LogsourceCondition(category="dns"),
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_mapping_network_traffic_unsupported_fields",
                transformation=DetectionItemFailureTransformation(
                    "The Splunk Data Model Sigma backend supports only the following fields for network traffic: "
                    + ",".join(list(splunk_network_traffic_cim_mapping.keys()))
                ),
                rule_conditions=[
                    LogsourceCondition(category="network_connection"),
                ],
                field_name_conditions=[
                    ExcludeFieldCondition(
                        fields=list(splunk_network_traffic_cim_mapping.keys())
                    )
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_mapping_network_traffic",
                transformation=FieldMappingTransformation(
                    splunk_network_traffic_cim_mapping
                ),
                rule_conditions=[
                    LogsourceCondition(category="network_connection"),
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_fields_network_traffic",
                transformation=SetStateTransformation(
                    "fields", splunk_network_traffic_cim_mapping.values()
                ),
                rule_conditions=[
                    LogsourceCondition(category="network_connection"),
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_mapping_network_traffic_data_model_set",
                transformation=SetStateTransformation(
                    "data_model_set", "Network_Traffic"
                ),
                rule_conditions=[
                    LogsourceCondition(category="network_connection"),
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_mapping_authentication_unsupported_fields",
                transformation=DetectionItemFailureTransformation(
                    "The Splunk Data Model Sigma backend supports only the following fields for authentication log source: "
                    + ",".join(list(splunk_authentication_cim_mapping.keys()))
                ),
                rule_conditions=[
                    LogsourceCondition(category="authentication"),
                ],
                field_name_conditions=[
                    ExcludeFieldCondition(
                        fields=list(splunk_authentication_cim_mapping.keys())
                    )
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_mapping_authentication",
                transformation=FieldMappingTransformation(
                    splunk_authentication_cim_mapping
                ),
                rule_conditions=[
                    LogsourceCondition(category="authentication"),
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_fields_authentication",
                transformation=SetStateTransformation(
                    "fields", splunk_authentication_cim_mapping.values()
                ),
                rule_conditions=[
                    LogsourceCondition(category="authentication"),
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_mapping_authentication_data_model_set",
                transformation=SetStateTransformation(
                    "data_model_set", "Authentication"
                ),
                rule_conditions=[
                    LogsourceCondition(category="authentication"),
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_mapping_ids_unsupported_fields",
                transformation=DetectionItemFailureTransformation(
                    "The Splunk Data Model Sigma backend supports only the following fields for IDS log source: "
                    + ",".join(list(splunk_ids_cim_mapping.keys()))
                ),
                rule_conditions=[
                    LogsourceCondition(category="ids"),
                ],
                field_name_conditions=[
                    ExcludeFieldCondition(
                        fields=list(splunk_ids_cim_mapping.keys())
                    )
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_mapping_ids",
                transformation=FieldMappingTransformation(
                    splunk_ids_cim_mapping
                ),
                rule_conditions=[
                    LogsourceCondition(category="ids"),
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_fields_ids",
                transformation=SetStateTransformation(
                    "fields", splunk_ids_cim_mapping.values()
                ),
                rule_conditions=[
                    LogsourceCondition(category="ids"),
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_mapping_ids_data_model_set",
                transformation=SetStateTransformation(
                    "data_model_set", "Network.IDS"
                ),
                rule_conditions=[
                    LogsourceCondition(category="ids"),
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_mapping_email_unsupported_fields",
                transformation=DetectionItemFailureTransformation(
                    "The Splunk Data Model Sigma backend supports only the following fields for email log source: "
                    + ",".join(list(splunk_email_cim_mapping.keys()))
                ),
                rule_conditions=[
                    LogsourceCondition(category="email"),
                ],
                field_name_conditions=[
                    ExcludeFieldCondition(
                        fields=list(splunk_email_cim_mapping.keys())
                    )
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_mapping_email",
                transformation=FieldMappingTransformation(
                    splunk_email_cim_mapping
                ),
                rule_conditions=[
                    LogsourceCondition(category="email"),
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_fields_email",
                transformation=SetStateTransformation(
                    "fields", splunk_email_cim_mapping.values()
                ),
                rule_conditions=[
                    LogsourceCondition(category="email"),
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_mapping_email_data_model_set",
                transformation=SetStateTransformation(
                    "data_model_set", "Email"
                ),
                rule_conditions=[
                    LogsourceCondition(category="email"),
                ],
            ),
            ProcessingItem(
                identifier="splunk_dm_mapping_log_source_not_supported",
                rule_condition_linking=any,
                transformation=RuleFailureTransformation(
                    "Rule type not yet supported by the Splunk data model CIM pipeline!"
                ),
                rule_condition_negation=True,
                rule_conditions=[
                    RuleProcessingItemAppliedCondition(
                        "splunk_dm_mapping_sysmon_process_creation"
                    ),
                    RuleProcessingItemAppliedCondition(
                        "splunk_dm_mapping_sysmon_registry"
                    ),
                    RuleProcessingItemAppliedCondition(
                        "splunk_dm_mapping_sysmon_file_event"
                    ),
                    RuleProcessingItemAppliedCondition(
                        "splunk_dm_mapping_web_proxy"
                    ),
                    RuleProcessingItemAppliedCondition(
                        "splunk_dm_mapping_dns"
                    ),
                    RuleProcessingItemAppliedCondition(
                        "splunk_dm_mapping_network_traffic"
                    ),
                    RuleProcessingItemAppliedCondition(
                        "splunk_dm_mapping_authentication"
                    ),
                    RuleProcessingItemAppliedCondition(
                        "splunk_dm_mapping_ids"
                    ),
                    RuleProcessingItemAppliedCondition(
                        "splunk_dm_mapping_email"
                    ),
                ],
            ),
        ],
    )
