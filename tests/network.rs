//! Reading fields out of `giganto-client`'s network records, the field
//! catalog, and rules matched against those records.

mod common;

use std::{
    borrow::Cow,
    collections::BTreeSet,
    io::Write,
    net::{IpAddr, Ipv4Addr},
};

use common::rule_text_with;
use flate2::{Compression, write::GzEncoder};
use giganto_client::{
    RawEventKind,
    ingest::network::{Conn, Dns, Http, Ssh, Tls},
};
use rulec::{
    Cidr, Event, FieldStatus, FieldValue, KindNotCataloged, ReadError, Rule, catalog_fields,
    compile, decode_body, field_status, header_block, join_cert_name, join_header_names,
    normalize_host, normalize_uri, reason, split_ssh_banner, unknown_fields,
};

const KINDS: [RawEventKind; 5] = [
    RawEventKind::Conn,
    RawEventKind::Dns,
    RawEventKind::Http,
    RawEventKind::Tls,
    RawEventKind::Ssh,
];

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn conn() -> Conn {
    Conn {
        orig_addr: v4(10, 1, 2, 3),
        orig_port: 49152,
        resp_addr: "2001:db8::1".parse().unwrap(),
        resp_port: 443,
        proto: 6,
        conn_state: "SF".to_string(),
        start_time: 1_700_000_000_000_000_000,
        duration: 1_500_000_000,
        service: "http".to_string(),
        orig_bytes: 1200,
        resp_bytes: u64::MAX,
        orig_pkts: 10,
        resp_pkts: 12,
        orig_l2_bytes: 1500,
        resp_l2_bytes: 1_600,
    }
}

fn dns() -> Dns {
    Dns {
        orig_addr: v4(10, 0, 0, 5),
        orig_port: 53_000,
        resp_addr: v4(8, 8, 8, 8),
        resp_port: 53,
        proto: 17,
        start_time: 1,
        duration: 2,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 80,
        resp_l2_bytes: 120,
        query: "evil.example.com".to_string(),
        answer: vec!["192.0.2.1".to_string(), "192.0.2.2".to_string()],
        trans_id: 4660,
        rtt: 15,
        qclass: 1,
        qtype: 1,
        rcode: 0,
        aa_flag: true,
        tc_flag: false,
        rd_flag: true,
        ra_flag: false,
        ttl: vec![300, -1],
    }
}

fn http() -> Http {
    Http {
        orig_addr: v4(192, 168, 1, 10),
        orig_port: 50_000,
        resp_addr: v4(203, 0, 113, 7),
        resp_port: 8080,
        proto: 6,
        start_time: 3,
        duration: 4,
        orig_pkts: 5,
        resp_pkts: 6,
        orig_l2_bytes: 700,
        resp_l2_bytes: 800,
        method: "POST".to_string(),
        host: "Example.COM:8080".to_string(),
        uri: "/a/./b/../c//%41dmin.php?x=%2e%2e".to_string(),
        referer: "http://ref.example/".to_string(),
        version: "1.1".to_string(),
        user_agent: "Mozilla/5.0 (rulec)".to_string(),
        request_len: 512,
        response_len: usize::MAX,
        status_code: 200,
        status_msg: "OK".to_string(),
        username: "alice".to_string(),
        password: "secret".to_string(),
        cookie: "session=1".to_string(),
        content_encoding: "gzip".to_string(),
        content_type: "application/x-www-form-urlencoded".to_string(),
        cache_control: "no-cache".to_string(),
        filenames: vec!["a.txt".to_string(), "b.exe".to_string()],
        mime_types: vec!["text/plain".to_string()],
        body: gzip(b"cmd=whoami&token=abc"),
        state: "done".to_string(),
        request_header_names: vec![
            "Host".to_string(),
            "user-agent".to_string(),
            "Cookie".to_string(),
            "X-Custom".to_string(),
            "Accept".to_string(),
            "Connection".to_string(),
            "Accept-Encoding".to_string(),
            "Accept-Language".to_string(),
            "Pragma".to_string(),
            "Referer".to_string(),
            "Content-Type".to_string(),
            "Content-Encoding".to_string(),
            "Cache-Control".to_string(),
            "HOST".to_string(),
        ],
        accept: "*/*".to_string(),
        connection: "keep-alive".to_string(),
        accept_encoding: "gzip, deflate".to_string(),
        accept_language: "en-US".to_string(),
        pragma: "no-cache".to_string(),
    }
}

fn tls() -> Tls {
    Tls {
        orig_addr: v4(10, 0, 0, 1),
        orig_port: 51_000,
        resp_addr: v4(198, 51, 100, 2),
        resp_port: 443,
        proto: 6,
        start_time: 7,
        duration: 8,
        orig_pkts: 9,
        resp_pkts: 10,
        orig_l2_bytes: 11,
        resp_l2_bytes: 12,
        server_name: "www.example.com".to_string(),
        alpn_protocol: "h2".to_string(),
        ja3: "771,4865-4866,0-23,29,0".to_string(),
        version: "TLSv1.3".to_string(),
        client_cipher_suites: vec![4865, 4866],
        client_extensions: vec![0, 23],
        cipher: 4865,
        extensions: vec![43, 51],
        ja3s: "771,4865,43-51".to_string(),
        serial: "01AB".to_string(),
        subject_country: "US".to_string(),
        subject_org_name: "Example Org".to_string(),
        subject_common_name: "www.example.com".to_string(),
        validity_not_before: 1_600_000_000,
        validity_not_after: 1_900_000_000,
        subject_alt_name: "www.example.com".to_string(),
        issuer_country: "US".to_string(),
        issuer_org_name: "Example CA".to_string(),
        issuer_org_unit_name: "Issuing".to_string(),
        issuer_common_name: "Example CA R1".to_string(),
        last_alert: 0,
    }
}

fn ssh() -> Ssh {
    Ssh {
        orig_addr: v4(10, 0, 0, 9),
        orig_port: 52_000,
        resp_addr: v4(10, 0, 0, 22),
        resp_port: 22,
        proto: 6,
        start_time: 13,
        duration: 14,
        orig_pkts: 15,
        resp_pkts: 16,
        orig_l2_bytes: 17,
        resp_l2_bytes: 18,
        client: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3".to_string(),
        server: "SSH-1.99-Cisco-1.25".to_string(),
        cipher_alg: "aes128-ctr".to_string(),
        mac_alg: "hmac-sha2-256".to_string(),
        compression_alg: "none".to_string(),
        kex_alg: "curve25519-sha256".to_string(),
        host_key_alg: "ssh-ed25519".to_string(),
        hassh_algorithms: "curve25519-sha256;aes128-ctr;hmac-sha2-256;none".to_string(),
        hassh: "ec7378c1a92f5a8dde7e8b7a1ddf33d1".to_string(),
        hassh_server_algorithms: "curve25519-sha256;aes128-ctr;hmac-sha2-256;none".to_string(),
        hassh_server: "b12d2871a1189eff20364cf5333619ee".to_string(),
        client_shka: "ssh-ed25519".to_string(),
        server_shka: "ssh-ed25519".to_string(),
    }
}

fn b(value: &str) -> FieldValue<'static> {
    FieldValue::Bytes(Cow::Owned(value.as_bytes().to_vec()))
}

fn i(value: i64) -> FieldValue<'static> {
    FieldValue::Int(value)
}

fn owned(values: Vec<FieldValue<'_>>) -> Vec<FieldValue<'static>> {
    values
        .into_iter()
        .map(|v| match v {
            FieldValue::Bytes(bytes) => FieldValue::Bytes(Cow::Owned(bytes.into_owned())),
            FieldValue::Addr(a) => FieldValue::Addr(a),
            FieldValue::Int(n) => FieldValue::Int(n),
        })
        .collect()
}

/// Returns the column names of a record, as serde writes them.
fn columns<T: serde::Serialize>(record: &T) -> Vec<String> {
    let serde_json::Value::Object(map) = serde_json::to_value(record).unwrap() else {
        panic!("a record is not a JSON object");
    };
    map.keys().cloned().collect()
}

/// Checks that every column of the record is in the catalog, every name
/// in the catalog but those in `no_value` gives a value for the filled
/// record, and the catalog holds exactly the columns and the given
/// derived fields.
fn check_catalog<E: Event + serde::Serialize>(record: &E, derived: &[&str], no_value: &[&str]) {
    let kind = record.kind();
    let fields = catalog_fields(kind).unwrap();
    let mut expected: BTreeSet<String> = columns(record).into_iter().collect();
    expected.extend(derived.iter().map(ToString::to_string));
    let catalog: BTreeSet<String> = fields.iter().map(ToString::to_string).collect();
    assert_eq!(catalog, expected, "{kind:?}");
    for name in fields {
        assert_eq!(
            record.field(name).is_empty(),
            no_value.contains(name),
            "{kind:?} {name}"
        );
        assert_eq!(field_status(kind, name), FieldStatus::Known);
    }
    for name in ["no_such_field", "", "URI", "uri.raw", "endpoint"] {
        assert!(record.field(name).is_empty(), "{kind:?} {name}");
        assert_eq!(field_status(kind, name), FieldStatus::NotInKind);
    }
    assert_eq!(record.os_family(), None);
}

#[test]
fn catalog_covers_every_column() {
    check_catalog(&conn(), &[], &[]);
    check_catalog(&dns(), &[], &[]);
    // This record is a POST, so `body.response` has no value.
    check_catalog(
        &http(),
        &[
            "uri.normalized",
            "host.normalized",
            "body.request",
            "body.response",
            "header_names.joined",
            "header_block",
        ],
        &["body.response"],
    );
    let mut get = http();
    get.method = "GET".to_string();
    assert!(!get.field("body.response").is_empty());
    check_catalog(&tls(), &["subject.joined", "issuer.joined"], &[]);
    check_catalog(
        &ssh(),
        &[
            "client.proto",
            "client.software",
            "server.proto",
            "server.software",
        ],
        &[],
    );
}

#[test]
fn kinds_and_catalog_answers() {
    assert_eq!(conn().kind(), RawEventKind::Conn);
    assert_eq!(dns().kind(), RawEventKind::Dns);
    assert_eq!(http().kind(), RawEventKind::Http);
    assert_eq!(tls().kind(), RawEventKind::Tls);
    assert_eq!(ssh().kind(), RawEventKind::Ssh);
    for kind in KINDS {
        assert!(catalog_fields(kind).is_some());
        assert_eq!(field_status(kind, "orig_addr"), FieldStatus::Known);
    }
    assert_eq!(
        field_status(RawEventKind::Http, "query"),
        FieldStatus::NotInKind
    );
    assert_eq!(
        field_status(RawEventKind::Conn, "uri.normalized"),
        FieldStatus::NotInKind
    );
    for kind in [RawEventKind::Smb, RawEventKind::Smtp, RawEventKind::Log] {
        assert_eq!(catalog_fields(kind), None);
        assert_eq!(
            field_status(kind, "orig_addr"),
            FieldStatus::KindNotCataloged
        );
    }
}

#[test]
fn value_shapes() {
    let c = conn();
    assert_eq!(
        c.field("orig_addr"),
        vec![FieldValue::Addr(v4(10, 1, 2, 3))]
    );
    assert_eq!(
        c.field("resp_addr"),
        vec![FieldValue::Addr("2001:db8::1".parse().unwrap())]
    );
    assert_eq!(c.field("orig_port"), vec![i(49152)]);
    assert_eq!(c.field("resp_port"), vec![i(443)]);
    assert_eq!(c.field("proto"), vec![i(6)]);
    assert_eq!(c.field("conn_state"), vec![b("SF")]);
    assert_eq!(c.field("service"), vec![b("http")]);
    assert_eq!(c.field("orig_bytes"), vec![i(1200)]);
    assert_eq!(c.field("start_time"), vec![i(1_700_000_000_000_000_000)]);
    // A `u64` past `i64::MAX` is its decimal text.
    assert_eq!(c.field("resp_bytes"), vec![b("18446744073709551615")]);
    let mut c = conn();
    c.resp_bytes = u64::try_from(i64::MAX).unwrap();
    assert_eq!(c.field("resp_bytes"), vec![i(i64::MAX)]);

    let d = dns();
    assert_eq!(d.field("query"), vec![b("evil.example.com")]);
    assert_eq!(d.field("answer"), vec![b("192.0.2.1"), b("192.0.2.2")]);
    assert_eq!(d.field("ttl"), vec![i(300), i(-1)]);
    assert_eq!(d.field("qtype"), vec![i(1)]);
    assert_eq!(d.field("aa_flag"), vec![b("true")]);
    assert_eq!(d.field("tc_flag"), vec![b("false")]);
    let mut d = dns();
    d.answer.clear();
    d.ttl.clear();
    d.query.clear();
    assert!(d.field("answer").is_empty());
    assert!(d.field("ttl").is_empty());
    assert_eq!(d.field("query"), vec![b("")]);

    let h = http();
    assert_eq!(h.field("status_code"), vec![i(200)]);
    assert_eq!(h.field("status_code")[0].as_bytes().as_ref(), b"200");
    assert_eq!(h.field("request_len"), vec![i(512)]);
    assert_eq!(h.field("response_len"), vec![b(&usize::MAX.to_string())]);
    assert_eq!(h.field("filenames"), vec![b("a.txt"), b("b.exe")]);
    assert_eq!(
        h.field("body"),
        vec![FieldValue::Bytes(Cow::Owned(h.body.clone()))]
    );
    assert_eq!(h.field("accept"), vec![b("*/*")]);
    assert_eq!(h.field("pragma"), vec![b("no-cache")]);
    assert_eq!(h.field("request_header_names").len(), 14);
    let mut h = http();
    h.body.clear();
    h.filenames.clear();
    h.request_header_names.clear();
    h.accept.clear();
    assert_eq!(h.field("body"), vec![b("")]);
    assert!(h.field("filenames").is_empty());
    assert!(h.field("request_header_names").is_empty());
    assert_eq!(h.field("accept"), vec![b("")]);

    let t = tls();
    assert_eq!(t.field("client_cipher_suites"), vec![i(4865), i(4866)]);
    assert_eq!(t.field("cipher"), vec![i(4865)]);
    assert_eq!(t.field("last_alert"), vec![i(0)]);
    assert_eq!(t.field("validity_not_after"), vec![i(1_900_000_000)]);
}

#[test]
fn http_derived_fields() {
    let h = http();
    assert_eq!(h.field("uri.normalized"), vec![b("/a/c/Admin.php?x=..")]);
    assert_eq!(h.field("host.normalized"), vec![b("example.com")]);
    assert_eq!(h.field("body.request"), vec![b("cmd=whoami&token=abc")]);
    assert!(h.field("body.response").is_empty());
    let names = owned(h.field("header_names.joined"));
    assert_eq!(names.len(), 1);
    assert!(
        names[0]
            .as_bytes()
            .starts_with(b"\r\nHost\r\nuser-agent\r\nCookie\r\n")
    );
    assert!(names[0].as_bytes().ends_with(b"\r\nHOST\r\n\r\n"));
    assert_eq!(
        h.field("header_block"),
        vec![b("Host: Example.COM:8080\r\n\
             user-agent: Mozilla/5.0 (rulec)\r\n\
             X-Custom: \r\n\
             Accept: */*\r\n\
             Connection: keep-alive\r\n\
             Accept-Encoding: gzip, deflate\r\n\
             Accept-Language: en-US\r\n\
             Pragma: no-cache\r\n\
             Referer: http://ref.example/\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Encoding: gzip\r\n\
             Cache-Control: no-cache\r\n\
             HOST: Example.COM:8080\r\n")]
    );

    let mut get = http();
    get.method = "GET".to_string();
    assert!(get.field("body.request").is_empty());
    assert_eq!(get.field("body.response"), vec![b("cmd=whoami&token=abc")]);
    for method in ["post", "HEAD", "get", "PUT", ""] {
        let mut other = http();
        other.method = method.to_string();
        assert!(other.field("body.request").is_empty(), "{method}");
        assert!(other.field("body.response").is_empty(), "{method}");
    }
    let mut empty = http();
    empty.body.clear();
    empty.uri.clear();
    empty.host.clear();
    empty.request_header_names.clear();
    for name in [
        "body.request",
        "uri.normalized",
        "host.normalized",
        "header_names.joined",
        "header_block",
    ] {
        assert!(empty.field(name).is_empty(), "{name}");
    }
    // A plain body is returned as it is.
    let mut plain = http();
    plain.body = b"{\"a\": [1, 2]}".to_vec();
    assert_eq!(plain.field("body.request"), vec![b("{\"a\": [1, 2]}")]);
}

#[test]
fn tls_and_ssh_derived_fields() {
    let t = tls();
    assert_eq!(
        t.field("subject.joined"),
        vec![b("C=US, O=Example Org, CN=www.example.com")]
    );
    assert_eq!(
        t.field("issuer.joined"),
        vec![b("C=US, O=Example CA, OU=Issuing, CN=Example CA R1")]
    );
    let mut t = tls();
    t.subject_country.clear();
    t.subject_org_name.clear();
    t.issuer_org_unit_name.clear();
    t.issuer_country.clear();
    assert_eq!(t.field("subject.joined"), vec![b("CN=www.example.com")]);
    assert_eq!(
        t.field("issuer.joined"),
        vec![b("O=Example CA, CN=Example CA R1")]
    );
    t.subject_common_name.clear();
    t.issuer_org_name.clear();
    t.issuer_common_name.clear();
    assert!(t.field("subject.joined").is_empty());
    assert!(t.field("issuer.joined").is_empty());

    let s = ssh();
    assert_eq!(s.field("client.proto"), vec![b("2.0")]);
    assert_eq!(s.field("client.software"), vec![b("OpenSSH_8.9p1")]);
    assert_eq!(s.field("server.proto"), vec![b("1.99")]);
    assert_eq!(s.field("server.software"), vec![b("Cisco-1.25")]);
    let mut s = ssh();
    s.client = "OpenSSH_8.9".to_string();
    s.server = "SSH-2.0-".to_string();
    assert!(s.field("client.proto").is_empty());
    assert!(s.field("client.software").is_empty());
    assert_eq!(s.field("server.proto"), vec![b("2.0")]);
    assert!(s.field("server.software").is_empty());
}

/// The derived values of a record are what the public functions give for
/// the record's columns.
#[test]
fn derived_fields_use_the_public_functions() {
    fn one(values: Vec<FieldValue<'_>>) -> Vec<u8> {
        assert_eq!(values.len(), 1);
        values[0].as_bytes().into_owned()
    }

    let mut h = http();
    h.uri = "/x/%u002e%u002e/y\\z%c0%af?q=%41+#f%u0041".to_string();
    h.host = "[2001:DB8::1]:443".to_string();
    assert_eq!(
        one(h.field("uri.normalized")),
        normalize_uri(h.uri.as_bytes())
    );
    assert_eq!(
        one(h.field("host.normalized")),
        normalize_host(h.host.as_bytes())
    );
    assert_eq!(one(h.field("body.request")), &*decode_body(&h.body));
    assert_eq!(
        one(h.field("header_names.joined")),
        join_header_names(&h.request_header_names).unwrap()
    );
    let values: [(&str, &[u8]); 11] = [
        ("Host", h.host.as_bytes()),
        ("User-Agent", h.user_agent.as_bytes()),
        ("Referer", h.referer.as_bytes()),
        ("Content-Type", h.content_type.as_bytes()),
        ("Content-Encoding", h.content_encoding.as_bytes()),
        ("Cache-Control", h.cache_control.as_bytes()),
        ("Accept", h.accept.as_bytes()),
        ("Connection", h.connection.as_bytes()),
        ("Accept-Encoding", h.accept_encoding.as_bytes()),
        ("Accept-Language", h.accept_language.as_bytes()),
        ("Pragma", h.pragma.as_bytes()),
    ];
    assert_eq!(
        values.map(|(name, _)| name),
        rulec::HEADER_BLOCK_HEADERS,
        "the header list"
    );
    assert_eq!(
        one(h.field("header_block")),
        header_block(&h.request_header_names, &values).unwrap()
    );
    h.method = "GET".to_string();
    assert_eq!(one(h.field("body.response")), &*decode_body(&h.body));

    let t = tls();
    assert_eq!(
        one(t.field("subject.joined")),
        join_cert_name(
            t.subject_country.as_bytes(),
            t.subject_org_name.as_bytes(),
            b"",
            t.subject_common_name.as_bytes()
        )
        .unwrap()
    );
    assert_eq!(
        one(t.field("issuer.joined")),
        join_cert_name(
            t.issuer_country.as_bytes(),
            t.issuer_org_name.as_bytes(),
            t.issuer_org_unit_name.as_bytes(),
            t.issuer_common_name.as_bytes()
        )
        .unwrap()
    );

    let s = ssh();
    let client = split_ssh_banner(s.client.as_bytes()).unwrap();
    let server = split_ssh_banner(s.server.as_bytes()).unwrap();
    assert_eq!(one(s.field("client.proto")), client.proto());
    assert_eq!(one(s.field("client.software")), client.software().unwrap());
    assert_eq!(one(s.field("server.proto")), server.proto());
    assert_eq!(one(s.field("server.software")), server.software().unwrap());
}

fn rule(id: &str, kind: &str, detection: &str) -> Rule {
    Rule::from_yaml(&rule_text_with(id, kind, "", detection))
        .unwrap_or_else(|e| panic!("rule {id} does not read: {e}"))
}

#[test]
fn rules_naming_unknown_fields() {
    let r = rule(
        "r",
        "http",
        "    sel:\n        uri.normalized|contains: '/admin'\n        zeta: x\n        alpha|fieldref: host\n    other:\n        zeta|neq: y\n        status_code|gte: 200\n        cookie|fieldref|neq: missing_ref\n    condition: sel or not other\n",
    );
    assert_eq!(
        unknown_fields(&r).unwrap(),
        vec!["alpha", "missing_ref", "zeta"]
    );
    let ok = rule(
        "ok",
        "conn",
        "    sel:\n        orig_addr|cidr: 10.0.0.0/8\n        service|fieldref: conn_state\n    condition: sel\n",
    );
    assert!(unknown_fields(&ok).unwrap().is_empty());
    // A search identifier the condition does not use still counts.
    let unused = rule(
        "unused",
        "http",
        "    sel:\n        uri: /a\n    unused:\n        missing|fieldref: missing_ref\n    condition: sel\n",
    );
    assert_eq!(
        unknown_fields(&unused).unwrap(),
        vec!["missing", "missing_ref"]
    );
    let uncataloged = rule(
        "uncataloged",
        "smb",
        "    sel:\n        Image|endswith: '\\cmd.exe'\n    condition: sel\n",
    );
    assert_eq!(
        unknown_fields(&uncataloged),
        Err(KindNotCataloged(RawEventKind::Smb))
    );
}

#[test]
fn timeseries_is_not_a_kind() {
    let detection = "    sel:\n        x: 1\n    condition: sel\n";
    let err = Rule::from_yaml(&rule_text_with("t", "timeseries", "", detection)).unwrap_err();
    assert!(matches!(err, ReadError::Format(_)), "{err:?}");
    assert_eq!(err.reason(), reason::FORMAT_ERROR);
    let read =
        Rule::from_yaml(&rule_text_with("p", "periodic_time_series", "", detection)).unwrap();
    assert_eq!(read.kind(), RawEventKind::PeriodicTimeSeries);
}

fn sel(selection: &str) -> String {
    format!("    sel:\n{selection}    condition: sel\n")
}

/// Compiles the rules and returns the ids `event` matches.
fn ids<E: Event>(rules: &[Rule], event: &E, home_net: &[Cidr]) -> Vec<String> {
    let compiled = compile(rules.to_vec()).unwrap();
    assert!(compiled.stats().excluded().is_empty());
    compiled
        .matcher()
        .matches(event, home_net)
        .unwrap()
        .iter()
        .map(|m| m.rule().source_rule_id().to_string())
        .collect()
}

#[test]
fn rules_match_conn_records() {
    let rules = vec![
        rule("cidr", "conn", &sel("        orig_addr|cidr: 10.0.0.0/8\n")),
        rule(
            "cidr6",
            "conn",
            &sel("        resp_addr|cidr: 2001:db8::/32\n"),
        ),
        rule(
            "fields",
            "conn",
            &sel(
                "        proto: 6\n        service: http\n        conn_state: SF\n        resp_port: 443\n",
            ),
        ),
        rule("big", "conn", &sel("        resp_bytes|gte: 1\n")),
        rule(
            "home",
            "conn",
            &sel("        orig_addr|expand|cidr: '%home_net%'\n"),
        ),
        rule(
            "miss_cidr",
            "conn",
            &sel("        orig_addr|cidr: 192.168.0.0/16\n"),
        ),
        rule("miss_port", "conn", &sel("        orig_port|lt: 1024\n")),
        rule("miss_service", "conn", &sel("        service: dns\n")),
    ];
    let home = ["10.1.0.0/16".parse::<Cidr>().unwrap()];
    // `resp_bytes` is past `i64::MAX`, so the numeric comparison is false.
    assert_eq!(
        ids(&rules, &conn(), &home),
        vec!["cidr", "cidr6", "fields", "home"]
    );
}

#[test]
fn rules_match_dns_records() {
    let rules = vec![
        rule(
            "query",
            "dns",
            &sel("        query|endswith: '.example.com'\n"),
        ),
        rule("answer", "dns", &sel("        answer|cidr: 192.0.2.0/24\n")),
        rule("ttl", "dns", &sel("        ttl|lt: 0\n")),
        rule(
            "flag",
            "dns",
            &sel("        aa_flag: 'true'\n        qtype: 1\n"),
        ),
        rule("miss_flag", "dns", &sel("        tc_flag: 'true'\n")),
        rule(
            "miss_query",
            "dns",
            &sel("        query|startswith: good\n"),
        ),
    ];
    assert_eq!(
        ids(&rules, &dns(), &[]),
        vec!["query", "answer", "ttl", "flag"]
    );
}

#[test]
fn rules_match_http_records() {
    let rules = vec![
        rule("status_gte", "http", &sel("        status_code|gte: 200\n")),
        rule("status_text", "http", &sel("        status_code: '200'\n")),
        rule(
            "uri_norm",
            "http",
            &sel("        uri.normalized|contains: '/c/admin.php'\n"),
        ),
        rule(
            "uri_raw_miss",
            "http",
            &sel("        uri|contains: '/c/admin.php'\n"),
        ),
        rule(
            "host_norm",
            "http",
            &sel("        host.normalized|cased: example.com\n"),
        ),
        rule(
            "body_req",
            "http",
            &sel("        body.request|contains: 'cmd=whoami'\n"),
        ),
        rule(
            "body_resp_miss",
            "http",
            &sel("        body.response|contains: 'cmd='\n"),
        ),
        rule(
            "names",
            "http",
            &sel("        header_names.joined|contains: \"\\r\\nX-Custom\\r\\n\"\n"),
        ),
        rule(
            "block",
            "http",
            &sel("        header_block|contains: \"\\r\\nAccept: */*\\r\\n\"\n"),
        ),
        rule(
            "block_cookie_miss",
            "http",
            &sel("        header_block|contains: 'Cookie:'\n"),
        ),
        rule(
            "resp_addr",
            "http",
            &sel("        resp_addr|cidr: 203.0.113.0/24\n        resp_port: 8080\n"),
        ),
        rule(
            "status_miss",
            "http",
            &sel("        status_code|gte: 400\n"),
        ),
        rule(
            "filename",
            "http",
            &sel("        filenames|endswith: '.exe'\n"),
        ),
    ];
    assert_eq!(
        ids(&rules, &http(), &[]),
        vec![
            "status_gte",
            "status_text",
            "uri_norm",
            "host_norm",
            "body_req",
            "names",
            "block",
            "resp_addr",
            "filename"
        ]
    );
}

#[test]
fn rules_match_tls_and_ssh_records() {
    let tls_rules = vec![
        rule(
            "subject",
            "tls",
            &sel("        subject.joined: 'C=US, O=Example Org, CN=www.example.com'\n"),
        ),
        rule(
            "issuer",
            "tls",
            &sel("        issuer.joined|contains: 'OU=Issuing'\n"),
        ),
        rule(
            "sni",
            "tls",
            &sel("        server_name|endswith: example.com\n        cipher: 4865\n"),
        ),
        rule(
            "miss_issuer",
            "tls",
            &sel("        issuer.joined|contains: 'OU=Other'\n"),
        ),
    ];
    assert_eq!(
        ids(&tls_rules, &tls(), &[]),
        vec!["subject", "issuer", "sni"]
    );
    let ssh_rules = vec![
        rule(
            "software",
            "ssh",
            &sel("        client.software|startswith: OpenSSH_8\n"),
        ),
        rule("proto", "ssh", &sel("        server.proto: '1.99'\n")),
        rule(
            "hassh",
            "ssh",
            &sel("        hassh: ec7378c1a92f5a8dde7e8b7a1ddf33d1\n"),
        ),
        rule("miss_proto", "ssh", &sel("        client.proto: '1.99'\n")),
        // A rule of another kind is not checked against the record.
        rule("other_kind", "tls", &sel("        resp_port: 22\n")),
    ];
    assert_eq!(
        ids(&ssh_rules, &ssh(), &[]),
        vec!["software", "proto", "hassh"]
    );
}
