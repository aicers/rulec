//! The [`Event`] trait for `giganto-client`'s network records: `Conn`,
//! `Dns`, `Http`, `Tls` and `Ssh`.

use std::{borrow::Cow, net::IpAddr};

use giganto_client::{
    RawEventKind,
    ingest::{
        endpoint::OsFamily,
        network::{Conn, Dns, Http, Ssh, Tls},
    },
};

use crate::{
    body::decode_body,
    derived::{
        HEADER_BLOCK_HEADERS, header_block, join_cert_name, join_header_names, split_ssh_banner,
    },
    event::{Event, FieldValue},
    normalize::{normalize_host, normalize_uri},
};

/// One string value.
fn text(value: &str) -> Vec<FieldValue<'_>> {
    vec![FieldValue::Bytes(Cow::Borrowed(value.as_bytes()))]
}

/// One byte value.
fn bytes(value: &[u8]) -> Vec<FieldValue<'_>> {
    vec![FieldValue::Bytes(Cow::Borrowed(value))]
}

/// One integer value of a type that fits in `i64`.
fn int<'a>(value: impl Into<i64>) -> Vec<FieldValue<'a>> {
    vec![FieldValue::Int(value.into())]
}

/// One integer value of a type that may not fit in `i64`: its decimal
/// text if it does not.
fn wide<'a, T>(value: T) -> Vec<FieldValue<'a>>
where
    T: Copy + TryInto<i64> + ToString,
{
    vec![match value.try_into() {
        Ok(v) => FieldValue::Int(v),
        Err(_) => FieldValue::Bytes(Cow::Owned(value.to_string().into_bytes())),
    }]
}

/// One `true` or `false` value.
fn flag<'a>(value: bool) -> Vec<FieldValue<'a>> {
    let text: &'static [u8] = if value { b"true" } else { b"false" };
    vec![FieldValue::Bytes(Cow::Borrowed(text))]
}

/// One address value.
fn addr<'a>(value: IpAddr) -> Vec<FieldValue<'a>> {
    vec![FieldValue::Addr(value)]
}

/// One value per string of a list, in order.
fn texts(values: &[String]) -> Vec<FieldValue<'_>> {
    values
        .iter()
        .map(|v| FieldValue::Bytes(Cow::Borrowed(v.as_bytes())))
        .collect()
}

/// One value per integer of a list, in order.
fn ints<'a, T: Copy + Into<i64>>(values: &[T]) -> Vec<FieldValue<'a>> {
    values.iter().map(|&v| FieldValue::Int(v.into())).collect()
}

/// One derived value, or none.
fn derived<'a>(value: Option<Vec<u8>>) -> Vec<FieldValue<'a>> {
    value
        .map(|v| vec![FieldValue::Bytes(Cow::Owned(v))])
        .unwrap_or_default()
}

/// Returns the values of a connection field every network record has, or
/// `None` if `$name` is not one.
macro_rules! connection_field {
    ($record:expr, $name:expr) => {
        match $name {
            "orig_addr" => Some(addr($record.orig_addr)),
            "orig_port" => Some(int($record.orig_port)),
            "resp_addr" => Some(addr($record.resp_addr)),
            "resp_port" => Some(int($record.resp_port)),
            "proto" => Some(int($record.proto)),
            "start_time" => Some(int($record.start_time)),
            "duration" => Some(int($record.duration)),
            "orig_pkts" => Some(wide($record.orig_pkts)),
            "resp_pkts" => Some(wide($record.resp_pkts)),
            "orig_l2_bytes" => Some(wide($record.orig_l2_bytes)),
            "resp_l2_bytes" => Some(wide($record.resp_l2_bytes)),
            _ => None,
        }
    };
}

impl Event for Conn {
    fn kind(&self) -> RawEventKind {
        RawEventKind::Conn
    }

    fn field(&self, name: &str) -> Vec<FieldValue<'_>> {
        if let Some(values) = connection_field!(self, name) {
            return values;
        }
        match name {
            "conn_state" => text(&self.conn_state),
            "service" => text(&self.service),
            "orig_bytes" => wide(self.orig_bytes),
            "resp_bytes" => wide(self.resp_bytes),
            _ => Vec::new(),
        }
    }

    fn os_family(&self) -> Option<&OsFamily> {
        None
    }
}

impl Event for Dns {
    fn kind(&self) -> RawEventKind {
        RawEventKind::Dns
    }

    fn field(&self, name: &str) -> Vec<FieldValue<'_>> {
        if let Some(values) = connection_field!(self, name) {
            return values;
        }
        match name {
            "query" => text(&self.query),
            "answer" => texts(&self.answer),
            "trans_id" => int(self.trans_id),
            "rtt" => int(self.rtt),
            "qclass" => int(self.qclass),
            "qtype" => int(self.qtype),
            "rcode" => int(self.rcode),
            "aa_flag" => flag(self.aa_flag),
            "tc_flag" => flag(self.tc_flag),
            "rd_flag" => flag(self.rd_flag),
            "ra_flag" => flag(self.ra_flag),
            "ttl" => ints(&self.ttl),
            _ => Vec::new(),
        }
    }

    fn os_family(&self) -> Option<&OsFamily> {
        None
    }
}

/// Returns the values an `Http` record holds for the headers of
/// [`HEADER_BLOCK_HEADERS`], in that order.
fn http_header_values(http: &Http) -> [(&'static str, &[u8]); 11] {
    let [
        host,
        user_agent,
        referer,
        content_type,
        content_encoding,
        cache_control,
        accept,
        connection,
        accept_encoding,
        accept_language,
        pragma,
    ] = HEADER_BLOCK_HEADERS;
    [
        (host, http.host.as_bytes()),
        (user_agent, http.user_agent.as_bytes()),
        (referer, http.referer.as_bytes()),
        (content_type, http.content_type.as_bytes()),
        (content_encoding, http.content_encoding.as_bytes()),
        (cache_control, http.cache_control.as_bytes()),
        (accept, http.accept.as_bytes()),
        (connection, http.connection.as_bytes()),
        (accept_encoding, http.accept_encoding.as_bytes()),
        (accept_language, http.accept_language.as_bytes()),
        (pragma, http.pragma.as_bytes()),
    ]
}

/// Returns the unpacked body of an `Http` record if its method is
/// `method`, byte for byte, and it has a body.
fn body_for<'a>(http: &'a Http, method: &str) -> Vec<FieldValue<'a>> {
    if http.method != method || http.body.is_empty() {
        return Vec::new();
    }
    vec![FieldValue::Bytes(decode_body(&http.body))]
}

impl Event for Http {
    fn kind(&self) -> RawEventKind {
        RawEventKind::Http
    }

    fn field(&self, name: &str) -> Vec<FieldValue<'_>> {
        if let Some(values) = connection_field!(self, name) {
            return values;
        }
        match name {
            "method" => text(&self.method),
            "host" => text(&self.host),
            "uri" => text(&self.uri),
            "referer" => text(&self.referer),
            "version" => text(&self.version),
            "user_agent" => text(&self.user_agent),
            "request_len" => wide(self.request_len),
            "response_len" => wide(self.response_len),
            "status_code" => int(self.status_code),
            "status_msg" => text(&self.status_msg),
            "username" => text(&self.username),
            "password" => text(&self.password),
            "cookie" => text(&self.cookie),
            "content_encoding" => text(&self.content_encoding),
            "content_type" => text(&self.content_type),
            "cache_control" => text(&self.cache_control),
            "filenames" => texts(&self.filenames),
            "mime_types" => texts(&self.mime_types),
            "body" => bytes(&self.body),
            "state" => text(&self.state),
            "request_header_names" => texts(&self.request_header_names),
            "accept" => text(&self.accept),
            "connection" => text(&self.connection),
            "accept_encoding" => text(&self.accept_encoding),
            "accept_language" => text(&self.accept_language),
            "pragma" => text(&self.pragma),
            "uri.normalized" => {
                derived((!self.uri.is_empty()).then(|| normalize_uri(self.uri.as_bytes())))
            }
            "host.normalized" => {
                derived((!self.host.is_empty()).then(|| normalize_host(self.host.as_bytes())))
            }
            "body.request" => body_for(self, "POST"),
            "body.response" => body_for(self, "GET"),
            "header_names.joined" => derived(join_header_names(&self.request_header_names)),
            "header_block" => derived(header_block(
                &self.request_header_names,
                &http_header_values(self),
            )),
            _ => Vec::new(),
        }
    }

    fn os_family(&self) -> Option<&OsFamily> {
        None
    }
}

impl Event for Tls {
    fn kind(&self) -> RawEventKind {
        RawEventKind::Tls
    }

    fn field(&self, name: &str) -> Vec<FieldValue<'_>> {
        if let Some(values) = connection_field!(self, name) {
            return values;
        }
        match name {
            "server_name" => text(&self.server_name),
            "alpn_protocol" => text(&self.alpn_protocol),
            "ja3" => text(&self.ja3),
            "version" => text(&self.version),
            "client_cipher_suites" => ints(&self.client_cipher_suites),
            "client_extensions" => ints(&self.client_extensions),
            "cipher" => int(self.cipher),
            "extensions" => ints(&self.extensions),
            "ja3s" => text(&self.ja3s),
            "serial" => text(&self.serial),
            "subject_country" => text(&self.subject_country),
            "subject_org_name" => text(&self.subject_org_name),
            "subject_common_name" => text(&self.subject_common_name),
            "validity_not_before" => int(self.validity_not_before),
            "validity_not_after" => int(self.validity_not_after),
            "subject_alt_name" => text(&self.subject_alt_name),
            "issuer_country" => text(&self.issuer_country),
            "issuer_org_name" => text(&self.issuer_org_name),
            "issuer_org_unit_name" => text(&self.issuer_org_unit_name),
            "issuer_common_name" => text(&self.issuer_common_name),
            "last_alert" => int(self.last_alert),
            "subject.joined" => derived(join_cert_name(
                self.subject_country.as_bytes(),
                self.subject_org_name.as_bytes(),
                b"",
                self.subject_common_name.as_bytes(),
            )),
            "issuer.joined" => derived(join_cert_name(
                self.issuer_country.as_bytes(),
                self.issuer_org_name.as_bytes(),
                self.issuer_org_unit_name.as_bytes(),
                self.issuer_common_name.as_bytes(),
            )),
            _ => Vec::new(),
        }
    }

    fn os_family(&self) -> Option<&OsFamily> {
        None
    }
}

/// Which part of an SSH banner a derived field holds.
#[derive(Clone, Copy)]
enum BannerPart {
    Proto,
    Software,
}

/// Returns one part of an SSH banner, or no value if the banner does not
/// split or lacks the part.
fn banner_part(banner: &str, part: BannerPart) -> Vec<FieldValue<'_>> {
    split_ssh_banner(banner.as_bytes())
        .and_then(|split| match part {
            BannerPart::Proto => Some(split.proto()),
            BannerPart::Software => split.software(),
        })
        .map(bytes)
        .unwrap_or_default()
}

impl Event for Ssh {
    fn kind(&self) -> RawEventKind {
        RawEventKind::Ssh
    }

    fn field(&self, name: &str) -> Vec<FieldValue<'_>> {
        if let Some(values) = connection_field!(self, name) {
            return values;
        }
        match name {
            "client" => text(&self.client),
            "server" => text(&self.server),
            "cipher_alg" => text(&self.cipher_alg),
            "mac_alg" => text(&self.mac_alg),
            "compression_alg" => text(&self.compression_alg),
            "kex_alg" => text(&self.kex_alg),
            "host_key_alg" => text(&self.host_key_alg),
            "hassh_algorithms" => text(&self.hassh_algorithms),
            "hassh" => text(&self.hassh),
            "hassh_server_algorithms" => text(&self.hassh_server_algorithms),
            "hassh_server" => text(&self.hassh_server),
            "client_shka" => text(&self.client_shka),
            "server_shka" => text(&self.server_shka),
            "client.proto" => banner_part(&self.client, BannerPart::Proto),
            "client.software" => banner_part(&self.client, BannerPart::Software),
            "server.proto" => banner_part(&self.server, BannerPart::Proto),
            "server.software" => banner_part(&self.server, BannerPart::Software),
            _ => Vec::new(),
        }
    }

    fn os_family(&self) -> Option<&OsFamily> {
        None
    }
}
