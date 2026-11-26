//! The field catalog: which field names the [`Event`](crate::Event)
//! implementations of each kind of raw event answer.

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

/// Returns the field names of `kind` in the catalog, or `None` if the
/// catalog has no entry for the kind.
///
/// The names are the record's column names, then its derived fields, in
/// that order. The catalog covers `conn`, `dns`, `http`, `tls` and `ssh`.
#[must_use]
pub fn catalog_fields(kind: RawEventKind) -> Option<&'static [&'static str]> {
    match kind {
        RawEventKind::Conn => Some(CONN),
        RawEventKind::Dns => Some(DNS),
        RawEventKind::Http => Some(HTTP),
        RawEventKind::Tls => Some(TLS),
        RawEventKind::Ssh => Some(SSH),
        _ => None,
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
        Some(fields) if fields.contains(&name) => FieldStatus::Known,
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
    let fields = catalog_fields(kind).ok_or(KindNotCataloged(kind))?;
    Ok(rule
        .fields
        .iter()
        .map(String::as_str)
        .filter(|name| !fields.contains(name))
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
