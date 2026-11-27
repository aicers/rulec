use std::collections::BTreeSet;

use giganto_client::{
    RawEventKind,
    ingest::network::{Conn, Dns, Http, Ssh, Tls},
};
use rulec::{Event, catalog_fields};
use serde_json::{Value, json};

use super::Result;

pub(super) struct Record {
    pub value: Box<dyn Event>,
    pub missing: BTreeSet<String>,
}

fn number_field(name: &str) -> bool {
    matches!(
        name,
        "orig_port"
            | "resp_port"
            | "proto"
            | "start_time"
            | "duration"
            | "orig_pkts"
            | "resp_pkts"
            | "orig_l2_bytes"
            | "resp_l2_bytes"
            | "orig_bytes"
            | "resp_bytes"
            | "request_len"
            | "response_len"
            | "status_code"
            | "trans_id"
            | "rtt"
            | "qclass"
            | "qtype"
            | "rcode"
            | "cipher"
            | "validity_not_before"
            | "validity_not_after"
            | "last_alert"
    )
}

fn array_field(name: &str) -> bool {
    matches!(
        name,
        "answer"
            | "ttl"
            | "filenames"
            | "mime_types"
            | "body"
            | "request_header_names"
            | "client_cipher_suites"
            | "client_extensions"
            | "extensions"
    )
}

pub(super) fn kind(name: &str) -> Option<RawEventKind> {
    match name {
        "flow" | "Conn" => Some(RawEventKind::Conn),
        "http" | "Http" => Some(RawEventKind::Http),
        "dns" | "Dns" => Some(RawEventKind::Dns),
        "tls" | "Tls" => Some(RawEventKind::Tls),
        "ssh" | "Ssh" => Some(RawEventKind::Ssh),
        _ => None,
    }
}

fn dns_number(value: &str) -> Option<u16> {
    Some(match value {
        "A" | "NOERROR" => 1,
        "NS" | "SERVFAIL" => 2,
        "NXDOMAIN" => 3,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "ANY" => 255,
        _ => return value.parse().ok(),
    })
}

pub(super) fn make(eve: &Value, flow: &Value) -> Result<Option<Record>> {
    let Some(kind) = eve["event_type"].as_str().and_then(kind) else {
        return Ok(None);
    };
    let mut data = serde_json::Map::new();
    let mut missing = BTreeSet::new();
    let mut incomplete_fields = Vec::new();
    for &field in catalog_fields(kind).ok_or("missing network catalog")? {
        let default = if matches!(field, "orig_addr" | "resp_addr") {
            json!("0.0.0.0")
        } else if number_field(field) {
            json!(0)
        } else if array_field(field) {
            json!([])
        } else if field.ends_with("_flag") {
            json!(false)
        } else {
            json!("")
        };
        data.insert(field.into(), default);
        missing.insert(field.to_owned());
    }
    let mut set = |field: &str, value: Value| {
        if !value.is_null() {
            data.insert(field.into(), value);
            missing.remove(field);
        }
    };
    for (field, source) in [
        ("orig_addr", "src_ip"),
        ("resp_addr", "dest_ip"),
        ("orig_port", "src_port"),
        ("resp_port", "dest_port"),
    ] {
        set(field, flow[source].clone());
    }
    match flow["proto"].as_str() {
        Some("TCP") => set("proto", json!(6)),
        Some("UDP") => set("proto", json!(17)),
        Some("ICMP") => set("proto", json!(1)),
        Some("IPv6-ICMP") => set("proto", json!(58)),
        _ => {}
    }
    if let Some(stamp) = flow["flow"]["start"]
        .as_str()
        .and_then(|s| s.parse::<jiff::Timestamp>().ok())
    {
        if let Ok(nanos) = i64::try_from(stamp.as_nanosecond()) {
            set("start_time", json!(nanos));
        }
        if let Some(end) = flow["flow"]["end"]
            .as_str()
            .and_then(|s| s.parse::<jiff::Timestamp>().ok())
            && let Ok(nanos) = i64::try_from(end.as_nanosecond() - stamp.as_nanosecond())
        {
            set("duration", json!(nanos));
        }
    }
    for (field, source) in [
        ("orig_pkts", "pkts_toserver"),
        ("resp_pkts", "pkts_toclient"),
    ] {
        set(field, flow["flow"][source].clone());
    }
    match kind {
        RawEventKind::Conn => {
            set("service", eve["app_proto"].clone());
        }
        RawEventKind::Http => {
            let http = &eve["http"];
            for (field, source) in [
                ("method", "http_method"),
                ("host", "hostname"),
                ("uri", "url"),
                ("referer", "http_refer"),
                ("version", "protocol"),
                ("user_agent", "http_user_agent"),
            ] {
                set(field, http[source].clone());
            }
            set("status_code", http["status"].clone());
            if let Some(length) = http["length"]
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
            {
                set("response_len", json!(length));
            }
            // Dumped request headers preserve names, order and request-side values.
            // A complete list also proves that an absent header has an empty value.
            if let Some(headers) = http["request_headers"].as_array() {
                let names: Vec<_> = headers.iter().filter_map(|h| h["name"].as_str()).collect();
                set("request_header_names", json!(names));
                if names.len() != headers.len() {
                    incomplete_fields.extend(
                        [
                            "request_header_names",
                            "header_names.joined",
                            "header_block",
                        ]
                        .map(str::to_owned),
                    );
                }
                for (field, name) in [
                    ("host", "Host"),
                    ("user_agent", "User-Agent"),
                    ("referer", "Referer"),
                    ("cookie", "Cookie"),
                    ("content_type", "Content-Type"),
                    ("content_encoding", "Content-Encoding"),
                    ("cache_control", "Cache-Control"),
                    ("accept", "Accept"),
                    ("connection", "Connection"),
                    ("accept_encoding", "Accept-Encoding"),
                    ("accept_language", "Accept-Language"),
                    ("pragma", "Pragma"),
                ] {
                    let values: Vec<_> = headers
                        .iter()
                        .filter(|h| {
                            h["name"]
                                .as_str()
                                .is_some_and(|n| n.eq_ignore_ascii_case(name))
                        })
                        .collect();
                    match values.as_slice() {
                        [] if names.len() == headers.len() => set(field, json!("")),
                        [header] if header["value"].is_string() => {
                            set(field, header["value"].clone());
                        }
                        _ => {
                            // A scalar record cannot preserve distinct duplicate values.
                            incomplete_fields.push(field.to_owned());
                            if name != "Cookie" {
                                incomplete_fields.push("header_block".to_owned());
                            }
                        }
                    }
                }
            }
        }
        RawEventKind::Dns => {
            let dns = &eve["dns"];
            set("query", dns["rrname"].clone());
            set("trans_id", dns["id"].clone());
            if let Some(queries) = dns["queries"].as_array().and_then(|q| q.first()) {
                set("query", queries["rrname"].clone());
            }
            let rrtype = dns["rrtype"]
                .as_str()
                .or_else(|| dns["queries"].as_array()?.first()?["rrtype"].as_str());
            if let Some(code) = rrtype.and_then(dns_number) {
                set("qtype", json!(code));
            }
            if let Some(rcode) = dns["rcode"].as_str() {
                if rcode == "NOERROR" {
                    set("rcode", json!(0));
                } else if let Some(code) = dns_number(rcode) {
                    set("rcode", json!(code));
                }
            }
            if let Some(answers) = dns["answers"].as_array() {
                let values: Vec<_> = answers.iter().filter_map(|a| a["rdata"].as_str()).collect();
                let ttls: Vec<_> = answers
                    .iter()
                    .filter_map(|a| a["ttl"].as_i64())
                    .filter_map(|t| i32::try_from(t).ok())
                    .collect();
                for (field, complete) in [
                    ("answer", values.len() == answers.len()),
                    ("ttl", ttls.len() == answers.len()),
                ] {
                    if !complete {
                        incomplete_fields.push(field.to_owned());
                    }
                }
                set("answer", json!(values));
                set("ttl", json!(ttls));
            }
        }
        RawEventKind::Tls => {
            let tls = &eve["tls"];
            for (field, source) in [
                ("server_name", "sni"),
                ("version", "version"),
                ("serial", "serial"),
            ] {
                set(field, tls[source].clone());
            }
            set("ja3", tls["ja3"]["hash"].clone());
            set("ja3s", tls["ja3s"]["hash"].clone());
            // Parse only unambiguous comma-separated RDNs; escaped or multivalued
            // DNs stay empty instead of inventing a certificate identity.
            for (source, prefix) in [("subject", "subject"), ("issuerdn", "issuer")] {
                if let Some(dn) = tls[source].as_str().filter(|s| !s.contains(['\\', '+'])) {
                    let representable = if prefix == "subject" {
                        &["C", "O", "CN"][..]
                    } else {
                        &["C", "O", "OU", "CN"][..]
                    };
                    if dn.split(", ").any(|part| {
                        part.split_once('=')
                            .is_none_or(|(key, _)| !representable.contains(&key))
                    }) {
                        incomplete_fields.push(format!("{prefix}.joined"));
                    }
                    for (key, suffix) in
                        [("C", "country"), ("O", "org_name"), ("CN", "common_name")]
                    {
                        let parts: Vec<_> = dn
                            .split(", ")
                            .filter_map(|part| part.strip_prefix(&format!("{key}=")))
                            .collect();
                        if let [value] = parts.as_slice() {
                            set(&format!("{prefix}_{suffix}"), json!(value));
                        }
                    }
                    if prefix == "issuer" {
                        let values: Vec<_> = dn
                            .split(", ")
                            .filter_map(|part| part.strip_prefix("OU="))
                            .collect();
                        if let [value] = values.as_slice() {
                            set("issuer_org_unit_name", json!(value));
                        }
                    }
                }
            }
            for (source, field) in [
                ("notbefore", "validity_not_before"),
                ("notafter", "validity_not_after"),
            ] {
                if let Some(text) = tls[source].as_str() {
                    // EVE certificate dates without an offset are UTC.
                    let timestamp = if text.len() == 19 {
                        format!("{text}Z")
                    } else {
                        text.to_owned()
                    };
                    if let Ok(stamp) = timestamp.parse::<jiff::Timestamp>() {
                        set(field, json!(stamp.as_second()));
                    }
                }
            }
        }
        RawEventKind::Ssh => {
            for side in ["client", "server"] {
                if let (Some(proto), Some(software)) = (
                    eve["ssh"][side]["proto_version"].as_str(),
                    eve["ssh"][side]["software_version"].as_str(),
                ) {
                    set(side, json!(format!("SSH-{proto}-{software}")));
                }
            }
        }
        _ => return Ok(None),
    }
    // Derived values depend on these raw fields. Preserve missingness separately
    // from giganto's unavoidable empty/zero representation.
    missing.extend(incomplete_fields.iter().cloned());
    for (derived, dependencies) in [
        ("uri.normalized", &["uri"][..]),
        ("host.normalized", &["host"][..]),
        ("body.request", &["body"][..]),
        ("body.response", &["body"][..]),
        ("header_names.joined", &["request_header_names"][..]),
        (
            "header_block",
            &[
                "request_header_names",
                "host",
                "user_agent",
                "referer",
                "content_type",
                "content_encoding",
                "cache_control",
                "accept",
                "connection",
                "accept_encoding",
                "accept_language",
                "pragma",
            ][..],
        ),
        (
            "subject.joined",
            &["subject_country", "subject_org_name", "subject_common_name"][..],
        ),
        (
            "issuer.joined",
            &[
                "issuer_country",
                "issuer_org_name",
                "issuer_org_unit_name",
                "issuer_common_name",
            ][..],
        ),
        ("client.proto", &["client"][..]),
        ("client.software", &["client"][..]),
        ("server.proto", &["server"][..]),
        ("server.software", &["server"][..]),
    ] {
        if !dependencies.iter().any(|d| missing.contains(*d))
            && !incomplete_fields.iter().any(|field| field == derived)
        {
            missing.remove(derived);
        }
    }
    let data = Value::Object(data);
    let value: Box<dyn Event> = match kind {
        RawEventKind::Conn => Box::new(serde_json::from_value::<Conn>(data)?),
        RawEventKind::Http => Box::new(serde_json::from_value::<Http>(data)?),
        RawEventKind::Dns => Box::new(serde_json::from_value::<Dns>(data)?),
        RawEventKind::Tls => Box::new(serde_json::from_value::<Tls>(data)?),
        RawEventKind::Ssh => Box::new(serde_json::from_value::<Ssh>(data)?),
        _ => return Ok(None),
    };
    Ok(Some(Record { value, missing }))
}

#[cfg(test)]
mod tests {
    use rulec::FieldValue;

    use super::*;

    fn flow() -> Value {
        json!({"src_ip":"10.0.0.1","dest_ip":"1.2.3.4","src_port":1234,"dest_port":80,"proto":"TCP","flow":{"start":"2026-01-01T00:00:00.000000+0000","end":"2026-01-01T00:00:01.000000+0000","pkts_toserver":3,"pkts_toclient":2}})
    }

    #[test]
    fn maps_all_five_kinds_and_preserves_empty_fields() {
        for (event, field, expected) in [
            (
                json!({"event_type":"http","http":{"http_method":"GET","url":"/a","status":404}}),
                "uri",
                "/a",
            ),
            (
                json!({"event_type":"dns","dns":{"rrname":"test.invalid","rrtype":"A","id":42}}),
                "query",
                "test.invalid",
            ),
            (
                json!({"event_type":"tls","tls":{"sni":"test.invalid","subject":"CN=test.invalid"}}),
                "subject_common_name",
                "test.invalid",
            ),
            (
                json!({"event_type":"ssh","ssh":{"server":{"proto_version":"2.0","software_version":"OpenSSH_8.0"}}}),
                "server.software",
                "OpenSSH_8.0",
            ),
            (
                json!({"event_type":"flow","app_proto":"http"}),
                "service",
                "http",
            ),
        ] {
            let record = make(&event, &flow()).unwrap().unwrap();
            let values = record.value.field(field);
            assert!(
                matches!(values.first(), Some(FieldValue::Bytes(bytes)) if bytes.as_ref() == expected.as_bytes()),
                "{field}"
            );
            assert!(!record.missing.contains(field));
            assert!(record.missing.contains("orig_l2_bytes"));
            assert!(matches!(
                record.value.field("orig_port").first(),
                Some(FieldValue::Int(1234))
            ));
        }
        let record = make(&json!({"event_type":"http","http":{}}), &flow())
            .unwrap()
            .unwrap();
        assert!(record.missing.contains("body.response"));
        assert!(record.value.field("body.response").is_empty());
    }
    #[test]
    fn http_request_headers_preserve_values_names_and_absence() {
        let event = json!({"event_type":"http", "http":{
            "hostname":"example.invalid", "http_content_type":"response/type", "length":42,
            "request_headers":[
                {"name":"Host", "value":"example.invalid:8080"},
                {"name":"aCcEpT", "value":"text/plain"},
                {"name":"Cookie", "value":"session=public"},
                {"name":"Content-Type", "value":"request/type"},
                {"name":"Content-Encoding", "value":"gzip"},
                {"name":"Cache-Control", "value":"no-cache"},
                {"name":"Connection", "value":"close"},
                {"name":"Accept-Encoding", "value":"gzip, deflate"},
                {"name":"Accept-Language", "value":"en"},
                {"name":"Pragma", "value":"no-cache"}
            ]
        }});
        let record = make(&event, &flow()).unwrap().unwrap();
        for (field, expected) in [
            ("host", "example.invalid:8080"),
            ("accept", "text/plain"),
            ("cookie", "session=public"),
            ("content_type", "request/type"),
            ("content_encoding", "gzip"),
            ("cache_control", "no-cache"),
            ("connection", "close"),
            ("accept_encoding", "gzip, deflate"),
            ("accept_language", "en"),
            ("pragma", "no-cache"),
        ] {
            assert!(!record.missing.contains(field), "{field}");
            assert!(
                matches!(record.value.field(field).first(),
                Some(FieldValue::Bytes(bytes)) if bytes.as_ref() == expected.as_bytes()),
                "{field}"
            );
        }
        for field in [
            "user_agent",
            "referer",
            "request_header_names",
            "header_names.joined",
            "header_block",
            "response_len",
        ] {
            assert!(!record.missing.contains(field), "{field}");
        }
        assert!(record.missing.contains("request_len"));
        assert!(matches!(
            record.value.field("response_len").first(),
            Some(FieldValue::Int(42))
        ));
        assert!(matches!(record.value.field("header_names.joined").first(),
            Some(FieldValue::Bytes(bytes)) if bytes.starts_with(b"\r\nHost\r\naCcEpT\r\nCookie\r\n")));
        assert!(matches!(record.value.field("header_block").first(),
            Some(FieldValue::Bytes(bytes)) if bytes.starts_with(b"Host: example.invalid:8080\r\naCcEpT: text/plain\r\nContent-Type: request/type\r\n")));
    }

    #[test]
    fn http_unavailable_and_incomplete_headers_keep_input_limits() {
        for http in [json!({}), json!({"request_headers":null})] {
            let record = make(&json!({"event_type":"http", "http":http}), &flow())
                .unwrap()
                .unwrap();
            assert!(record.missing.contains("request_header_names"));
            assert!(record.missing.contains("header_block"));
        }
        for headers in [
            json!([{"value":"lost name"}]),
            json!([{"name":"Accept"}]),
            json!([{"name":"Accept","value":"a"},{"name":"accept","value":"b"}]),
        ] {
            let record = make(
                &json!({"event_type":"http", "http":{"request_headers":headers}}),
                &flow(),
            )
            .unwrap()
            .unwrap();
            assert!(record.missing.contains("accept"));
            assert!(record.missing.contains("header_block"));
        }
        let record = make(
            &json!({"event_type":"http", "http":{"request_headers":[]}}),
            &flow(),
        )
        .unwrap()
        .unwrap();
        for field in [
            "request_header_names",
            "header_names.joined",
            "header_block",
            "accept",
        ] {
            assert!(!record.missing.contains(field), "{field}");
        }
    }

    #[test]
    fn tls_dates_and_ambiguous_names_have_documented_provenance() {
        let event = json!({"event_type":"tls", "tls":{
            "subject":"C=US, O=Example, CN=example.invalid",
            "issuerdn":"C=US, O=Example CA, OU=Testing, CN=CA",
            "notbefore":"2024-01-01T00:00:00", "notafter":"2025-01-01T00:00:00"
        }});
        let record = make(&event, &flow()).unwrap().unwrap();
        assert!(!record.missing.contains("subject.joined"));
        assert!(!record.missing.contains("issuer.joined"));
        assert!(matches!(
            record.value.field("validity_not_before").first(),
            Some(FieldValue::Int(1704067200))
        ));
        let event = json!({"event_type":"tls", "tls":{"subject":"CN=first+CN=second"}});
        let record = make(&event, &flow()).unwrap().unwrap();
        assert!(record.missing.contains("subject_common_name"));
        assert!(record.missing.contains("subject.joined"));
    }

    #[test]
    fn unrepresented_certificate_attributes_mark_joined_names_incomplete() {
        let event = json!({"event_type":"tls", "tls":{
            "subject":"C=US, O=Example, OU=Lost, CN=example.invalid",
            "issuerdn":"C=US, O=Example CA, OU=Testing, L=Lost, CN=CA"
        }});
        let record = make(&event, &flow()).unwrap().unwrap();
        // All representable components are available; the omitted RDNs still
        // make a rule using the joined buffer subject to an input limit.
        for field in ["subject.joined", "issuer.joined"] {
            assert!(record.missing.contains(field), "{field}");
            assert!(!record.value.field(field).is_empty());
        }
        assert!(!record.missing.contains("subject_common_name"));
        assert!(!record.missing.contains("issuer_org_unit_name"));
    }

    #[test]
    fn dns_response_preserves_query_answers_ttls_and_zero_rcode() {
        let event = json!({"event_type":"dns", "dns":{
            "type":"answer", "id":42, "rcode":"NOERROR",
            "queries":[{"rrname":"example.invalid", "rrtype":"AAAA"}],
            "answers":[
                {"rdata":"2001:db8::1", "ttl":60},
                {"rdata":"2001:db8::2", "ttl":120}
            ]
        }});
        let record = make(&event, &flow()).unwrap().unwrap();
        assert!(matches!(
            record.value.field("query").first(),
            Some(FieldValue::Bytes(bytes)) if bytes.as_ref() == b"example.invalid"
        ));
        assert_eq!(record.value.field("answer").len(), 2);
        for (field, expected) in [("trans_id", 42), ("qtype", 28), ("rcode", 0)] {
            assert!(matches!(
                record.value.field(field).first(),
                Some(FieldValue::Int(value)) if *value == expected
            ));
            assert!(!record.missing.contains(field), "{field}");
        }
        assert!(matches!(
            record.value.field("ttl").as_slice(),
            [FieldValue::Int(60), FieldValue::Int(120)]
        ));
        for field in ["query", "answer", "ttl"] {
            assert!(!record.missing.contains(field), "{field}");
        }
        for field in ["qclass", "rtt", "aa_flag", "rd_flag"] {
            assert!(record.missing.contains(field), "{field}");
        }
    }

    #[test]
    fn incomplete_dns_answer_arrays_remain_marked_as_input_limits() {
        for (second, incomplete) in [
            (json!({"ttl":4294967295_u64}), vec!["answer", "ttl"]),
            (json!({}), vec!["answer", "ttl"]),
            (
                json!({"rdata":"other.invalid", "ttl":4294967295_u64}),
                vec!["ttl"],
            ),
            (json!({"ttl":120}), vec!["answer"]),
        ] {
            let event = json!({"event_type":"dns", "dns":{
                "answers":[{"rdata":"example.invalid", "ttl":60}, second]
            }});
            let record = make(&event, &flow()).unwrap().unwrap();
            for field in ["answer", "ttl"] {
                let missing = incomplete.contains(&field);
                assert_eq!(record.value.field(field).len(), if missing { 1 } else { 2 });
                assert_eq!(record.missing.contains(field), missing, "{field}");
            }
        }
        // A supplied empty answer set is complete, unlike an unavailable set.
        let record = make(&json!({"event_type":"dns", "dns":{"answers":[]}}), &flow())
            .unwrap()
            .unwrap();
        for field in ["answer", "ttl"] {
            assert!(!record.missing.contains(field), "{field}");
        }
    }
    #[test]
    fn unrepresentable_values_stay_empty_and_marked_missing() {
        let mut connection = flow();
        connection["proto"] = json!("SCTP");
        connection["flow"]["start"] = json!("2500-01-01T00:00:00Z");
        connection["flow"]["end"] = json!("invalid");
        let record = make(
            &json!({"event_type":"tls", "tls":{"notbefore":"invalid"}}),
            &connection,
        )
        .unwrap()
        .unwrap();
        for field in ["proto", "start_time", "duration", "validity_not_before"] {
            assert!(record.missing.contains(field));
            assert!(matches!(
                record.value.field(field).first(),
                Some(FieldValue::Int(0))
            ));
        }
    }
}
