//! Compares host catalog columns with the pinned giganto-client records.

use giganto_client::{RawEventKind, ingest::sysmon};
use rulec::{FieldStatus, catalog_fields, field_status};

#[test]
fn sysmon_catalog_columns_are_exactly_the_record_columns_except_endpoint() {
    fn check(kind: RawEventKind, record: impl serde::Serialize) {
        let value = serde_json::to_value(record).unwrap();
        let object = value.as_object().unwrap();
        let mut expected: Vec<_> = object
            .keys()
            .map(String::as_str)
            .filter(|name| *name != "endpoint")
            .collect();
        let mut actual = catalog_fields(kind).unwrap().to_vec();
        expected.sort_unstable();
        actual.sort_unstable();
        assert_eq!(actual, expected, "{kind:?}");
        for name in actual {
            assert_eq!(field_status(kind, name), FieldStatus::Known);
        }
        assert_eq!(field_status(kind, "endpoint"), FieldStatus::NotInKind);
        assert_eq!(
            field_status(kind, "nonexistent_column"),
            FieldStatus::NotInKind
        );
    }
    check(
        RawEventKind::ProcessCreate,
        sysmon::ProcessCreate {
            agent_name: Default::default(),
            agent_id: Default::default(),
            process_guid: Default::default(),
            process_id: Default::default(),
            image: Default::default(),
            file_version: Default::default(),
            description: Default::default(),
            product: Default::default(),
            company: Default::default(),
            original_file_name: Default::default(),
            command_line: Default::default(),
            current_directory: Default::default(),
            user: Default::default(),
            logon_guid: Default::default(),
            logon_id: Default::default(),
            terminal_session_id: Default::default(),
            integrity_level: Default::default(),
            hashes: Default::default(),
            parent_process_guid: Default::default(),
            parent_process_id: Default::default(),
            parent_image: Default::default(),
            parent_command_line: Default::default(),
            parent_user: Default::default(),
            endpoint: Default::default(),
            logon_id_full: Default::default(),
        },
    );
    check(
        RawEventKind::FileCreateTime,
        sysmon::FileCreationTimeChanged {
            agent_name: Default::default(),
            agent_id: Default::default(),
            process_guid: Default::default(),
            process_id: Default::default(),
            image: Default::default(),
            target_filename: Default::default(),
            creation_utc_time: Default::default(),
            previous_creation_utc_time: Default::default(),
            user: Default::default(),
            endpoint: Default::default(),
        },
    );
    check(
        RawEventKind::NetworkConnect,
        sysmon::NetworkConnection {
            agent_name: Default::default(),
            agent_id: Default::default(),
            process_guid: Default::default(),
            process_id: Default::default(),
            image: Default::default(),
            user: Default::default(),
            protocol: Default::default(),
            initiated: Default::default(),
            source_is_ipv6: Default::default(),
            source_ip: "192.0.2.1".parse().unwrap(),
            source_hostname: Default::default(),
            source_port: Default::default(),
            source_port_name: Default::default(),
            destination_is_ipv6: Default::default(),
            destination_ip: "192.0.2.1".parse().unwrap(),
            destination_hostname: Default::default(),
            destination_port: Default::default(),
            destination_port_name: Default::default(),
            endpoint: Default::default(),
        },
    );
    check(
        RawEventKind::ProcessTerminate,
        sysmon::ProcessTerminated {
            agent_name: Default::default(),
            agent_id: Default::default(),
            process_guid: Default::default(),
            process_id: Default::default(),
            image: Default::default(),
            user: Default::default(),
            endpoint: Default::default(),
        },
    );
    check(
        RawEventKind::ImageLoad,
        sysmon::ImageLoaded {
            agent_name: Default::default(),
            agent_id: Default::default(),
            process_guid: Default::default(),
            process_id: Default::default(),
            image: Default::default(),
            image_loaded: Default::default(),
            file_version: Default::default(),
            description: Default::default(),
            product: Default::default(),
            company: Default::default(),
            original_file_name: Default::default(),
            hashes: Default::default(),
            signed: Default::default(),
            signature: Default::default(),
            signature_status: Default::default(),
            user: Default::default(),
            endpoint: Default::default(),
        },
    );
    check(
        RawEventKind::FileCreate,
        sysmon::FileCreate {
            agent_name: Default::default(),
            agent_id: Default::default(),
            process_guid: Default::default(),
            process_id: Default::default(),
            image: Default::default(),
            target_filename: Default::default(),
            creation_utc_time: Default::default(),
            user: Default::default(),
            endpoint: Default::default(),
        },
    );
    check(
        RawEventKind::RegistryValueSet,
        sysmon::RegistryValueSet {
            agent_name: Default::default(),
            agent_id: Default::default(),
            event_type: Default::default(),
            process_guid: Default::default(),
            process_id: Default::default(),
            image: Default::default(),
            target_object: Default::default(),
            details: Default::default(),
            user: Default::default(),
            endpoint: Default::default(),
        },
    );
    check(
        RawEventKind::RegistryKeyRename,
        sysmon::RegistryKeyValueRename {
            agent_name: Default::default(),
            agent_id: Default::default(),
            event_type: Default::default(),
            process_guid: Default::default(),
            process_id: Default::default(),
            image: Default::default(),
            target_object: Default::default(),
            new_name: Default::default(),
            user: Default::default(),
            endpoint: Default::default(),
        },
    );
    check(
        RawEventKind::FileCreateStreamHash,
        sysmon::FileCreateStreamHash {
            agent_name: Default::default(),
            agent_id: Default::default(),
            process_guid: Default::default(),
            process_id: Default::default(),
            image: Default::default(),
            target_filename: Default::default(),
            creation_utc_time: Default::default(),
            hash: Default::default(),
            contents: Default::default(),
            user: Default::default(),
            endpoint: Default::default(),
        },
    );
    check(
        RawEventKind::PipeEvent,
        sysmon::PipeEvent {
            agent_name: Default::default(),
            agent_id: Default::default(),
            event_type: Default::default(),
            process_guid: Default::default(),
            process_id: Default::default(),
            pipe_name: Default::default(),
            image: Default::default(),
            user: Default::default(),
            endpoint: Default::default(),
        },
    );
    check(
        RawEventKind::DnsQuery,
        sysmon::DnsEvent {
            agent_name: Default::default(),
            agent_id: Default::default(),
            process_guid: Default::default(),
            process_id: Default::default(),
            query_name: Default::default(),
            query_status: Default::default(),
            query_results: Default::default(),
            image: Default::default(),
            user: Default::default(),
            endpoint: Default::default(),
        },
    );
    check(
        RawEventKind::FileDelete,
        sysmon::FileDelete {
            agent_name: Default::default(),
            agent_id: Default::default(),
            process_guid: Default::default(),
            process_id: Default::default(),
            user: Default::default(),
            image: Default::default(),
            target_filename: Default::default(),
            hashes: Default::default(),
            is_executable: Default::default(),
            archived: Default::default(),
            endpoint: Default::default(),
        },
    );
    check(
        RawEventKind::ProcessTamper,
        sysmon::ProcessTampering {
            agent_name: Default::default(),
            agent_id: Default::default(),
            process_guid: Default::default(),
            process_id: Default::default(),
            image: Default::default(),
            tamper_type: Default::default(),
            user: Default::default(),
            endpoint: Default::default(),
        },
    );
    check(
        RawEventKind::FileDeleteDetected,
        sysmon::FileDeleteDetected {
            agent_name: Default::default(),
            agent_id: Default::default(),
            process_guid: Default::default(),
            process_id: Default::default(),
            user: Default::default(),
            image: Default::default(),
            target_filename: Default::default(),
            hashes: Default::default(),
            is_executable: Default::default(),
            endpoint: Default::default(),
        },
    );
    check(
        RawEventKind::DriverLoad,
        sysmon::DriverLoad {
            agent_name: Default::default(),
            agent_id: Default::default(),
            image_loaded: Default::default(),
            hashes: Default::default(),
            signed: Default::default(),
            signature: Default::default(),
            signature_status: Default::default(),
            endpoint: Default::default(),
        },
    );
    check(
        RawEventKind::CreateRemoteThread,
        sysmon::CreateRemoteThread {
            agent_name: Default::default(),
            agent_id: Default::default(),
            source_process_guid: Default::default(),
            source_process_id: Default::default(),
            source_image: Default::default(),
            target_process_guid: Default::default(),
            target_process_id: Default::default(),
            target_image: Default::default(),
            new_thread_id: Default::default(),
            start_address: Default::default(),
            start_module: Default::default(),
            start_function: Default::default(),
            source_user: Default::default(),
            target_user: Default::default(),
            endpoint: Default::default(),
        },
    );
    check(
        RawEventKind::RawAccessRead,
        sysmon::RawAccessRead {
            agent_name: Default::default(),
            agent_id: Default::default(),
            process_guid: Default::default(),
            process_id: Default::default(),
            image: Default::default(),
            device: Default::default(),
            user: Default::default(),
            endpoint: Default::default(),
        },
    );
    check(
        RawEventKind::ProcessAccess,
        sysmon::ProcessAccess {
            agent_name: Default::default(),
            agent_id: Default::default(),
            source_process_guid: Default::default(),
            source_process_id: Default::default(),
            source_thread_id: Default::default(),
            source_image: Default::default(),
            target_process_guid: Default::default(),
            target_process_id: Default::default(),
            target_image: Default::default(),
            granted_access: Default::default(),
            call_trace: Default::default(),
            source_user: Default::default(),
            target_user: Default::default(),
            endpoint: Default::default(),
        },
    );
    check(
        RawEventKind::RegistryObjectAddDel,
        sysmon::RegistryObjectAddDel {
            agent_name: Default::default(),
            agent_id: Default::default(),
            event_type: Default::default(),
            process_guid: Default::default(),
            process_id: Default::default(),
            image: Default::default(),
            target_object: Default::default(),
            user: Default::default(),
            endpoint: Default::default(),
        },
    );
}
