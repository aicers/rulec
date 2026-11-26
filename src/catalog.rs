//! The field catalog: names supplied by the network [`Event`](crate::Event)
//! implementations and specified for future host implementations.

use giganto_client::RawEventKind;

use crate::rule::Rule;

/// The connection fields every network record has.
macro_rules! connection_fields {
    ($($rest:literal),* $(,)?) => {
        &[
            "orig_addr",
            "orig_port",
            "resp_addr",
            "resp_port",
            "proto",
            "start_time",
            "duration",
            "orig_pkts",
            "resp_pkts",
            "orig_l2_bytes",
            "resp_l2_bytes",
            $($rest),*
        ]
    };
}

/// The fields of a `Conn` record.
const CONN: &[&str] = connection_fields!["conn_state", "service", "orig_bytes", "resp_bytes",];

/// The fields of a `Dns` record.
const DNS: &[&str] = connection_fields![
    "query", "answer", "trans_id", "rtt", "qclass", "qtype", "rcode", "aa_flag", "tc_flag",
    "rd_flag", "ra_flag", "ttl",
];

/// The fields of an `Http` record, then its derived fields.
const HTTP: &[&str] = connection_fields![
    "method",
    "host",
    "uri",
    "referer",
    "version",
    "user_agent",
    "request_len",
    "response_len",
    "status_code",
    "status_msg",
    "username",
    "password",
    "cookie",
    "content_encoding",
    "content_type",
    "cache_control",
    "filenames",
    "mime_types",
    "body",
    "state",
    "request_header_names",
    "accept",
    "connection",
    "accept_encoding",
    "accept_language",
    "pragma",
    "uri.normalized",
    "host.normalized",
    "body.request",
    "body.response",
    "header_names.joined",
    "header_block",
];

/// The fields of a `Tls` record, then its derived fields.
const TLS: &[&str] = connection_fields![
    "server_name",
    "alpn_protocol",
    "ja3",
    "version",
    "client_cipher_suites",
    "client_extensions",
    "cipher",
    "extensions",
    "ja3s",
    "serial",
    "subject_country",
    "subject_org_name",
    "subject_common_name",
    "validity_not_before",
    "validity_not_after",
    "subject_alt_name",
    "issuer_country",
    "issuer_org_name",
    "issuer_org_unit_name",
    "issuer_common_name",
    "last_alert",
    "subject.joined",
    "issuer.joined",
];

/// The fields of an `Ssh` record, then its derived fields.
const SSH: &[&str] = connection_fields![
    "client",
    "server",
    "cipher_alg",
    "mac_alg",
    "compression_alg",
    "kex_alg",
    "host_key_alg",
    "hassh_algorithms",
    "hassh",
    "hassh_server_algorithms",
    "hassh_server",
    "client_shka",
    "server_shka",
    "client.proto",
    "client.software",
    "server.proto",
    "server.software",
];

const PROCESS_CREATE: &[&str] = &[
    "agent_name",
    "agent_id",
    "process_guid",
    "process_id",
    "image",
    "file_version",
    "description",
    "product",
    "company",
    "original_file_name",
    "command_line",
    "current_directory",
    "user",
    "logon_guid",
    "logon_id",
    "terminal_session_id",
    "integrity_level",
    "hashes",
    "parent_process_guid",
    "parent_process_id",
    "parent_image",
    "parent_command_line",
    "parent_user",
    "logon_id_full",
];

const FILE_CREATION_TIME_CHANGED: &[&str] = &[
    "agent_name",
    "agent_id",
    "process_guid",
    "process_id",
    "image",
    "target_filename",
    "creation_utc_time",
    "previous_creation_utc_time",
    "user",
];

const NETWORK_CONNECTION: &[&str] = &[
    "agent_name",
    "agent_id",
    "process_guid",
    "process_id",
    "image",
    "user",
    "protocol",
    "initiated",
    "source_is_ipv6",
    "source_ip",
    "source_hostname",
    "source_port",
    "source_port_name",
    "destination_is_ipv6",
    "destination_ip",
    "destination_hostname",
    "destination_port",
    "destination_port_name",
];

const PROCESS_TERMINATED: &[&str] = &[
    "agent_name",
    "agent_id",
    "process_guid",
    "process_id",
    "image",
    "user",
];

const IMAGE_LOADED: &[&str] = &[
    "agent_name",
    "agent_id",
    "process_guid",
    "process_id",
    "image",
    "image_loaded",
    "file_version",
    "description",
    "product",
    "company",
    "original_file_name",
    "hashes",
    "signed",
    "signature",
    "signature_status",
    "user",
];

const FILE_CREATE: &[&str] = &[
    "agent_name",
    "agent_id",
    "process_guid",
    "process_id",
    "image",
    "target_filename",
    "creation_utc_time",
    "user",
];

const REGISTRY_VALUE_SET: &[&str] = &[
    "agent_name",
    "agent_id",
    "event_type",
    "process_guid",
    "process_id",
    "image",
    "target_object",
    "details",
    "user",
];

const REGISTRY_KEY_VALUE_RENAME: &[&str] = &[
    "agent_name",
    "agent_id",
    "event_type",
    "process_guid",
    "process_id",
    "image",
    "target_object",
    "new_name",
    "user",
];

const FILE_CREATE_STREAM_HASH: &[&str] = &[
    "agent_name",
    "agent_id",
    "process_guid",
    "process_id",
    "image",
    "target_filename",
    "creation_utc_time",
    "hash",
    "contents",
    "user",
];

const PIPE_EVENT: &[&str] = &[
    "agent_name",
    "agent_id",
    "event_type",
    "process_guid",
    "process_id",
    "pipe_name",
    "image",
    "user",
];

const DNS_EVENT: &[&str] = &[
    "agent_name",
    "agent_id",
    "process_guid",
    "process_id",
    "query_name",
    "query_status",
    "query_results",
    "image",
    "user",
];

const FILE_DELETE: &[&str] = &[
    "agent_name",
    "agent_id",
    "process_guid",
    "process_id",
    "user",
    "image",
    "target_filename",
    "hashes",
    "is_executable",
    "archived",
];

const PROCESS_TAMPERING: &[&str] = &[
    "agent_name",
    "agent_id",
    "process_guid",
    "process_id",
    "image",
    "tamper_type",
    "user",
];

const FILE_DELETE_DETECTED: &[&str] = &[
    "agent_name",
    "agent_id",
    "process_guid",
    "process_id",
    "user",
    "image",
    "target_filename",
    "hashes",
    "is_executable",
];

const DRIVER_LOAD: &[&str] = &[
    "agent_name",
    "agent_id",
    "image_loaded",
    "hashes",
    "signed",
    "signature",
    "signature_status",
];

const CREATE_REMOTE_THREAD: &[&str] = &[
    "agent_name",
    "agent_id",
    "source_process_guid",
    "source_process_id",
    "source_image",
    "target_process_guid",
    "target_process_id",
    "target_image",
    "new_thread_id",
    "start_address",
    "start_module",
    "start_function",
    "source_user",
    "target_user",
];

const RAW_ACCESS_READ: &[&str] = &[
    "agent_name",
    "agent_id",
    "process_guid",
    "process_id",
    "image",
    "device",
    "user",
];

const PROCESS_ACCESS: &[&str] = &[
    "agent_name",
    "agent_id",
    "source_process_guid",
    "source_process_id",
    "source_thread_id",
    "source_image",
    "target_process_guid",
    "target_process_id",
    "target_image",
    "granted_access",
    "call_trace",
    "source_user",
    "target_user",
];

const REGISTRY_OBJECT_ADD_DEL: &[&str] = &[
    "agent_name",
    "agent_id",
    "event_type",
    "process_guid",
    "process_id",
    "image",
    "target_object",
    "user",
];

const WINDOWS_EVENT_LOG: &[&str] = &[
    "channel",
    "provider",
    "event_id",
    "version",
    "level",
    "task",
    "opcode",
    "keywords",
    "record_id",
    "computer",
    "user_sid",
    "user_data_xml",
];

/// Returns the field names of `kind` in the catalog, or `None` if the
/// catalog has no entry for the kind.
///
/// The names are the record's column names, then its derived fields, in
/// that order. The catalog covers the five network kinds, every Sysmon
/// kind, Windows event logs, journald and auditd. Dynamic names are
/// described by [`catalog_field_prefixes`].
#[must_use]
pub fn catalog_fields(kind: RawEventKind) -> Option<&'static [&'static str]> {
    match kind {
        RawEventKind::Conn => Some(CONN),
        RawEventKind::Dns => Some(DNS),
        RawEventKind::Http => Some(HTTP),
        RawEventKind::Tls => Some(TLS),
        RawEventKind::Ssh => Some(SSH),
        RawEventKind::ProcessCreate => Some(PROCESS_CREATE),
        RawEventKind::FileCreateTime => Some(FILE_CREATION_TIME_CHANGED),
        RawEventKind::NetworkConnect => Some(NETWORK_CONNECTION),
        RawEventKind::ProcessTerminate => Some(PROCESS_TERMINATED),
        RawEventKind::ImageLoad => Some(IMAGE_LOADED),
        RawEventKind::FileCreate => Some(FILE_CREATE),
        RawEventKind::RegistryValueSet => Some(REGISTRY_VALUE_SET),
        RawEventKind::RegistryKeyRename => Some(REGISTRY_KEY_VALUE_RENAME),
        RawEventKind::FileCreateStreamHash => Some(FILE_CREATE_STREAM_HASH),
        RawEventKind::PipeEvent => Some(PIPE_EVENT),
        RawEventKind::DnsQuery => Some(DNS_EVENT),
        RawEventKind::FileDelete => Some(FILE_DELETE),
        RawEventKind::ProcessTamper => Some(PROCESS_TAMPERING),
        RawEventKind::FileDeleteDetected => Some(FILE_DELETE_DETECTED),
        RawEventKind::DriverLoad => Some(DRIVER_LOAD),
        RawEventKind::CreateRemoteThread => Some(CREATE_REMOTE_THREAD),
        RawEventKind::RawAccessRead => Some(RAW_ACCESS_READ),
        RawEventKind::ProcessAccess => Some(PROCESS_ACCESS),
        RawEventKind::RegistryObjectAddDel => Some(REGISTRY_OBJECT_ADD_DEL),
        RawEventKind::WindowsEventLog => Some(WINDOWS_EVENT_LOG),
        RawEventKind::Journald => Some(&[]),
        RawEventKind::Auditd => Some(&["serial", "record_type"]),
        _ => None,
    }
}

/// Returns the prefixes of dynamic field names for `kind`.
///
/// A prefix must be followed by a nonempty, case-preserved source name.
#[must_use]
pub fn catalog_field_prefixes(kind: RawEventKind) -> &'static [&'static str] {
    match kind {
        RawEventKind::WindowsEventLog => &["event_data."],
        RawEventKind::Journald | RawEventKind::Auditd => &["fields."],
        _ => &[],
    }
}

/// What the catalog says about a field name of a kind of raw event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FieldStatus {
    /// The kind has the field.
    Known,
    /// The kind is in the catalog and does not have the field.
    NotInKind,
    /// The catalog has no entry for the kind.
    KindNotCataloged,
}

/// Returns whether events of `kind` have the field `name`.
#[must_use]
pub fn field_status(kind: RawEventKind, name: &str) -> FieldStatus {
    match catalog_fields(kind) {
        Some(fields)
            if fields.contains(&name)
                || catalog_field_prefixes(kind).iter().any(|prefix| {
                    name.strip_prefix(prefix)
                        .is_some_and(|suffix| !suffix.is_empty())
                }) =>
        {
            FieldStatus::Known
        }
        Some(_) => FieldStatus::NotInKind,
        None => FieldStatus::KindNotCataloged,
    }
}

/// The error of [`unknown_fields`]: the catalog has no entry for the kind
/// of the rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the field catalog has no entry for {0:?}")]
pub struct KindNotCataloged(pub RawEventKind);

/// Returns the field names a rule uses that its kind of raw event does
/// not have, sorted and without repeats; empty if the kind has them all.
///
/// The names a rule uses are the fields of all its field conditions and
/// the fields `fieldref` refers to, in every search identifier of its
/// `detection`, including one its `condition` does not use. Whether to drop the rule, and under
/// which reason, is the caller's decision.
///
/// # Errors
///
/// Returns [`KindNotCataloged`] if the catalog has no entry for the
/// rule's kind ([`Rule::kind`]).
pub fn unknown_fields(rule: &Rule) -> Result<Vec<&str>, KindNotCataloged> {
    let kind = rule.kind();
    catalog_fields(kind).ok_or(KindNotCataloged(kind))?;
    Ok(rule
        .fields
        .iter()
        .map(String::as_str)
        .filter(|name| field_status(kind, name) != FieldStatus::Known)
        .collect())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn names_are_unique() {
        for kind in [
            RawEventKind::Conn,
            RawEventKind::Dns,
            RawEventKind::Http,
            RawEventKind::Tls,
            RawEventKind::Ssh,
        ] {
            let fields = catalog_fields(kind).unwrap();
            let unique: BTreeSet<_> = fields.iter().collect();
            assert_eq!(unique.len(), fields.len(), "{kind:?}");
        }
    }
}
