//! Hand-written synthetic Suricata rules only; no third-party rule fixtures.

mod common;

use std::io::Write as _;

use common::{TestEvent, matched_ids};
use flate2::{Compression, write::GzEncoder};
use giganto_client::{
    RawEventKind,
    ingest::network::{Conn, Dns, Http, Ssh, Tls},
};
use jiff::civil::date;
use rulec::{
    Blocklist, Cidr, Conversion, EtOpenError, Model, RuleBundle, Source, VERSION, compile,
    content_digest, convert_et_open, read_et_open_version, reason, unknown_fields,
};
use sha2::{Digest, Sha256};

fn archive(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    for (path, bytes) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(u64::try_from(bytes.len()).unwrap());
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, path, *bytes).unwrap();
    }
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(&tar.into_inner().unwrap()).unwrap();
    gz.finish().unwrap()
}

fn rule(id: u64, header: &str, options: &str) -> String {
    format!(
        "alert {header} (msg:\"synthetic {id}\"; {options} sid:{id}; rev:2; metadata:updated_at 2026_11_25;)\n"
    )
}

fn convert(text: &str) -> Conversion {
    let bundle = archive(&[("rules/emerging-malware.rules", text.as_bytes())]);
    convert_et_open(&bundle, Some(11342), &Blocklist::default()).unwrap()
}

fn one(options: &str) -> Conversion {
    convert(&rule(90001, "http any any -> any any", options))
}

fn accepted(options: &str) -> Conversion {
    let converted = one(options);
    assert_eq!(converted.rules.len(), 1, "{:?}", converted.summary.dropped);
    assert!(converted.summary.dropped.is_empty());
    converted
}

fn matches(options: &str, field: &str, bytes: &[u8]) -> bool {
    let converted = accepted(options);
    let compiled = compile(converted.rules).unwrap();
    !matched_ids(&compiled, &TestEvent::http().bytes(field, bytes), &[]).is_empty()
}

fn dropped(header: &str, options: &str, expected: &str) {
    let converted = convert(&rule(90001, header, options));
    assert!(converted.rules.is_empty(), "{header} {options}");
    assert_eq!(
        converted.summary.dropped.len(),
        1,
        "{:?}",
        converted.summary
    );
    assert_eq!(converted.summary.dropped.get(expected).unwrap(), &["90001"]);
}

#[test]
fn files_versions_digest_and_continuations() {
    let r1 = rule(
        90001,
        "dns any any -> any any",
        "dns.query; content:\"abc\";",
    );
    let r2 = rule(90002, "tcp any any -> any any", "").replace("2026_11_25", "2026_11_26");
    let continued = r1.replace("dns.query;", "dns.query; \\\n");
    let included = format!(
        "\n # {}\n{continued}",
        r2.replace("2026_11_26", "2029_12_31").trim()
    );
    let excluded = [
        "emerging-retired.rules",
        "botcc.rules",
        "botcc.portgrouped.rules",
        "ciarmy.rules",
        "compromised.rules",
        "drop.rules",
        "dshield.rules",
        "tor.rules",
        "threatview.rules",
        "threatview-extra.rules",
        "README.txt",
    ];
    let mut files = vec![
        (
            "./rules/emerging-dns.rules".to_string(),
            included.as_bytes(),
        ),
        ("rules/emerging-info.rules".into(), r2.as_bytes()),
        ("elsewhere/emerging-dns.rules".into(), r1.as_bytes()),
        ("rules/nested/a.rules".into(), r1.as_bytes()),
    ];
    for name in excluded {
        files.push((format!("rules/{name}"), r1.as_bytes()));
    }
    let files: Vec<_> = files.iter().map(|(p, b)| (p.as_str(), *b)).collect();
    let bytes = archive(&files);
    for number in [Some(11342), None] {
        let converted = convert_et_open(&bytes, number, &Blocklist::default()).unwrap();
        assert_eq!(converted.rules.len(), 2);
        assert!(converted.summary.dropped.is_empty());
        let version = read_et_open_version(&bytes, number).unwrap();
        assert_eq!(version, converted.summary.source_version);
        assert_eq!(version.order_key.date, date(2026, 11, 26));
        assert_eq!(version.order_key.number, number);
        assert_eq!(version.release_name, None);
        assert_eq!(
            version.content_digest,
            content_digest([
                ("emerging-dns.rules", included.as_bytes()),
                ("emerging-info.rules", r2.as_bytes())
            ])
        );
        if number.is_some() {
            assert_eq!(version.version, "11342");
        } else {
            assert_eq!(
                version.version,
                format!(
                    "upd-2026-11-26-{}",
                    Sha256::digest(&bytes)
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                )
                .get(..27)
                .unwrap()
            );
        }
    }
    let base = archive(&[("rules/emerging-dns.rules", r1.as_bytes())]);
    let extra = archive(&[
        ("rules/emerging-dns.rules", r1.as_bytes()),
        ("rules/tor.rules", b"changed"),
    ]);
    assert_eq!(
        read_et_open_version(&base, None).unwrap().content_digest,
        read_et_open_version(&extra, None).unwrap().content_digest
    );
    let changed = archive(&[(
        "rules/emerging-dns.rules",
        format!("{r1}# comment\n").as_bytes(),
    )]);
    assert_ne!(
        read_et_open_version(&base, None).unwrap().content_digest,
        read_et_open_version(&changed, None).unwrap().content_digest
    );
}

#[test]
fn bundle_errors_have_the_same_precedence_for_both_apis() {
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(&[42; 2048]).unwrap();
    let bad_tar = gz.finish().unwrap();
    let no_files = archive(&[("rules/tor.rules", b"nonsense")]);
    let no_version = archive(&[(
        "rules/emerging-dns.rules",
        b"alert dns any any -> any any (msg:\"x\"; sid:9;)\n",
    )]);
    for (bytes, variant) in [
        (b"not gzip".as_slice(), 0),
        (&bad_tar, 0),
        (&no_files, 1),
        (&no_version, 2),
    ] {
        for result in [
            read_et_open_version(bytes, None),
            convert_et_open(bytes, None, &Blocklist::default()).map(|c| c.summary.source_version),
        ] {
            let error = result.unwrap_err();
            assert!(matches!(
                (variant, error),
                (0, EtOpenError::NotATarGz(_))
                    | (1, EtOpenError::NoRuleFiles)
                    | (2, EtOpenError::NoVersionInfo)
            ));
        }
    }
    let mut corrupt = archive(&[("rules/emerging-dns.rules", b"")]);
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert!(matches!(
        read_et_open_version(&corrupt, None),
        Err(EtOpenError::NotATarGz(_))
    ));
    for value in ["2026_02_30", "2026_13_01", "2026_1_01", "2026-11-25"] {
        let text = rule(1, "ip any any -> any any", "").replace("2026_11_25", value);
        assert!(matches!(
            read_et_open_version(
                &archive(&[("rules/emerging-info.rules", text.as_bytes())]),
                Some(1)
            ),
            Err(EtOpenError::NoVersionInfo)
        ));
    }
}

#[test]
fn categories_and_gpl_are_not_filtered() {
    let threat = [
        "malware",
        "web_specific_apps",
        "exploit_kit",
        "phishing",
        "mobile_malware",
        "exploit",
        "web_server",
        "web_client",
        "scan",
        "user_agents",
        "ja3",
        "coinminer",
        "current_events",
        "attack_response",
        "dos",
        "worm",
        "scada",
        "activex",
        "dns",
    ];
    let policy = [
        "dyn_dns",
        "info",
        "hunting",
        "file_sharing",
        "ta_abused_services",
        "remote_access",
        "p2p",
        "games",
        "chat",
        "inappropriate",
        "adware_pup",
    ];
    let text = rule(90001, "ip any any -> any any", "").replace("synthetic 90001", "GPL synthetic");
    for (categories, model) in [
        (threat.as_slice(), Model::EtSignature),
        (policy.as_slice(), Model::EtPolicySignature),
    ] {
        for category in categories {
            let converted = convert_et_open(
                &archive(&[(&format!("rules/emerging-{category}.rules"), text.as_bytes())]),
                None,
                &Blocklist::default(),
            )
            .unwrap();
            assert_eq!(converted.rules[0].model(), model);
            assert_eq!(converted.rules[0].license(), Some("GPL-2.0"));
        }
    }
    for name in ["emerging-unknown.rules", "custom.rules"] {
        let converted = convert_et_open(
            &archive(&[(&format!("rules/{name}"), text.as_bytes())]),
            None,
            &Blocklist::default(),
        )
        .unwrap();
        assert_eq!(converted.summary.dropped_count(reason::UNCATEGORIZED), 1);
    }
}

#[test]
fn every_buffer_maps_to_a_catalog_field() {
    let buffers = [
        ("http.method", "http", "method"),
        ("http.uri", "http", "uri.normalized"),
        ("http.uri.raw", "http", "uri"),
        ("http.host", "http", "host.normalized"),
        ("http.host.raw", "http", "host"),
        ("http.user_agent", "http", "user_agent"),
        ("http.referer", "http", "referer"),
        ("http.cookie", "http", "cookie"),
        ("http.content_type", "http", "content_type"),
        ("http.protocol", "http", "version"),
        ("http.stat_code", "http", "status_code"),
        ("http.stat_msg", "http", "status_msg"),
        ("http.request_body", "http", "body.request"),
        ("http.response_body", "http", "body.response"),
        ("file.data", "http", "body.request"),
        ("http.header_names", "http", "header_names.joined"),
        ("http.accept", "http", "accept"),
        ("http.accept_enc", "http", "accept_encoding"),
        ("http.accept_lang", "http", "accept_language"),
        ("http.connection", "http", "connection"),
        ("http.header", "http", "header_block"),
        ("dns.query", "dns", "query"),
        ("tls.sni", "tls", "server_name"),
        ("tls.cert_subject", "tls", "subject.joined"),
        ("tls.cert_issuer", "tls", "issuer.joined"),
        ("tls.cert_serial", "tls", "serial"),
        ("ja3.hash", "tls", "ja3"),
        ("ja3s.hash", "tls", "ja3s"),
        ("ssh.proto", "ssh", "client.proto"),
        ("ssh.software", "ssh", "client.software"),
        ("ssh.hassh", "ssh", "hassh"),
        ("ssh.hassh.server", "ssh", "hassh_server"),
    ];
    for (buffer, kind, field) in buffers {
        let converted = convert(&rule(
            90001,
            &format!("{kind} any any -> any any"),
            &format!("{buffer}; content:\"needle\";"),
        ));
        assert_eq!(
            converted.rules.len(),
            1,
            "{buffer}: {:?}",
            converted.summary.dropped
        );
        let rule = &converted.rules[0];
        assert!(unknown_fields(rule).unwrap().is_empty());
        let json = serde_json::to_value(rule).unwrap();
        assert!(
            json["fields"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!(field)),
            "{json}"
        );
        assert!(json.to_string().contains("\"cased\":true"));
        assert!(!json.to_string().contains("AnyChar"));
        assert!(
            compile(converted.rules)
                .unwrap()
                .stats()
                .excluded()
                .is_empty()
        );
    }
    for options in [
        "content:\"a\"; http_uri;",
        "http_content_type; content:\"a\";",
        "content:\"a\"; http_header;",
        "content:\"a\"; http_raw_uri;",
    ] {
        assert_eq!(one(options).rules.len(), 1, "{options}");
    }
}

#[test]
fn legacy_body_modifiers_attach_to_the_preceding_content() {
    assert!(matches(
        r#"content:"needle"; http_client_body;"#,
        "body.request",
        b"needle"
    ));
    let converted = accepted(r#"content:"Needle"; pcre:"/GET/M"; http_client_body; nocase;"#);
    let event = TestEvent::http()
        .text("method", &["GET"])
        .bytes("body.request", b"NEEDLE");
    assert_eq!(
        matched_ids(&compile(converted.rules).unwrap(), &event, &[]),
        ["90001"]
    );
    dropped(
        "http any any -> any any",
        r#"pcre:"/abc/M"; http_client_body;"#,
        reason::FORMAT_ERROR,
    );
    dropped(
        "http any any -> any any",
        r#"http.uri; content:"abc"; startswith; offset:1;"#,
        reason::FORMAT_ERROR,
    );
}

#[test]
fn literals_normalization_case_bytes_and_prefilter() {
    assert!(matches(
        "http.uri; content:\"%41\";",
        "uri.normalized",
        b"A"
    ));
    assert!(!matches(
        "http.uri; content:\"%41\";",
        "uri.normalized",
        b"%41"
    ));
    assert!(matches(
        "http.host; content:\"Example.COM\";",
        "host.normalized",
        b"example.com"
    ));
    assert!(matches("http.uri.raw; content:\"%41\";", "uri", b"%41"));
    assert!(!matches("http.uri.raw; content:\"%41\";", "uri", b"A"));
    assert!(matches(
        "http.uri.raw; content:\"a*b?c%\";",
        "uri",
        b"a*b?c%"
    ));
    assert!(!matches(
        "http.uri.raw; content:\"a*b?c%\";",
        "uri",
        b"aXXbYc%"
    ));
    assert!(matches(
        r#"http.uri.raw; content:"a\\b|00 FF|";"#,
        "uri",
        b"a\\b\0\xff"
    ));
    assert!(!matches("http.uri.raw; content:\"a\";", "uri", b"A"));
    assert!(matches("http.uri.raw; content:\"a\"; nocase;", "uri", b"A"));
    assert!(matches("http.uri.raw; content:!\"bad\";", "uri", b"good"));
    assert!(!matches("http.uri.raw; content:!\"bad\";", "uri", b"bad"));
    let converted = accepted(
        "http.host; content:\"Example.COM\"; fast_pattern; content:\"longer-unselected-content\";",
    );
    assert_eq!(
        converted.rules[0].prefilter(),
        Some(b"example.com".as_slice())
    );
    assert_eq!(
        accepted("http.uri; content:\"%41\";").rules[0].prefilter(),
        Some(b"A".as_slice())
    );
    assert_eq!(
        accepted("http.uri; pcre:\"/abc/\";").rules[0].prefilter(),
        None
    );
}

#[test]
fn continuations_preserve_literal_bytes_and_keyword_spelling() {
    for (source, expected) in [
        ("ab\\\ncd", b"abcd".as_slice()),
        ("ab\\\n  cd", b"ab  cd"),
        ("ab\\\n#cd", b"ab#cd"),
        ("ab\\ \t\r\ncd", b"abcd"),
    ] {
        let converted = accepted(&format!("http.uri.raw; content:\"{source}\";"));
        assert_eq!(converted.rules[0].prefilter(), Some(expected));
        let compiled = compile(converted.rules).unwrap();
        assert_eq!(
            matched_ids(&compiled, &TestEvent::http().bytes("uri", expected), &[]),
            ["90001"]
        );
    }
    let converted = accepted("http.uri.raw; con\\\ntent:\"abcd\";");
    assert_eq!(converted.rules[0].prefilter(), Some(b"abcd".as_slice()));

    let first = rule(
        90001,
        "http any any -> any any",
        "http.uri.raw; content:\"ab\\\n\n",
    );
    let second = "alert http any any -> any any (msg:\"missing sid\"; http.uri.raw; content:\"x\"; metadata:updated_at 2026_11_25;)\n";
    let converted = convert(&format!("# ignored\n{first}{second}"));
    assert_eq!(
        converted
            .summary
            .dropped
            .get(reason::MISSING_ATTRIBUTE)
            .unwrap(),
        &["emerging-malware.rules:5"]
    );
    assert_eq!(
        converted.summary.dropped.get(reason::FORMAT_ERROR).unwrap(),
        &["emerging-malware.rules:2", "emerging-malware.rules:4"]
    );
}

#[test]
fn negated_patterns_require_a_present_buffer() {
    for (header, buffer, field) in [
        ("http", "flow:to_server; file.data", "body.request"),
        ("http", "http.uri", "uri.normalized"),
        ("http", "http.host", "host.normalized"),
        ("http", "http.header_names", "header_names.joined"),
        ("tls", "tls.cert_subject", "subject.joined"),
        ("ssh", "flow:to_server; ssh.software", "client.software"),
        ("ssh", "flow:to_client; ssh.software", "server.software"),
    ] {
        for pattern in [
            r#"content:!"x";"#,
            r#"content:!"x"; startswith;"#,
            r#"content:!"x"; endswith;"#,
            r#"pcre:!"/x/";"#,
            r#"pcre:!"/x/i";"#,
        ] {
            let converted = convert(&rule(
                90001,
                &format!("{header} any any -> any any"),
                &format!("{buffer}; {pattern}"),
            ));
            assert_eq!(converted.rules.len(), 1, "{:?}", converted.summary);
            let kind = converted.rules[0].kind();
            let compiled = compile(converted.rules).unwrap();
            assert!(matched_ids(&compiled, &TestEvent::new(kind), &[]).is_empty());
            for (value, matches) in [(b"".as_slice(), true), (b"good", true), (b"x", false)] {
                assert_eq!(
                    !matched_ids(&compiled, &TestEvent::new(kind).bytes(field, value), &[])
                        .is_empty(),
                    matches,
                    "{buffer}; {pattern}, {value:?}"
                );
            }
        }
    }
}

#[test]
fn negated_neutral_buffers_keep_presence_with_direction_and_endpoints() {
    for pattern in [r#"content:!"x";"#, r#"pcre:!"/x/";"#] {
        let converted = convert(&rule(
            90001,
            "ssh 10.0.0.0/8 50000 -> 198.51.100.0/24 80",
            &format!("ssh.software; {pattern}"),
        ));
        let compiled = compile(converted.rules).unwrap();
        for reverse in [false, true] {
            let event = network_event(RawEventKind::Ssh, reverse);
            assert!(matched_ids(&compiled, &event, &[]).is_empty());
            let (field, other) = if reverse {
                ("server.software", "client.software")
            } else {
                ("client.software", "server.software")
            };
            assert_eq!(
                matched_ids(&compiled, &event.clone().bytes(field, b"good"), &[]),
                ["90001"]
            );
            assert!(matched_ids(&compiled, &event.clone().bytes(other, b"good"), &[]).is_empty());
            assert!(matched_ids(&compiled, &event.bytes(field, b"x"), &[]).is_empty());
        }
    }
}

#[test]
fn anchors_lengths_and_regex_chains() {
    for option in ["startswith;", "offset:0; depth:3;"] {
        let options = format!("http.uri.raw; content:\"abc\"; {option}");
        assert!(matches(&options, "uri", b"abcx"));
        assert!(!matches(&options, "uri", b"xabc"));
    }
    for option in ["endswith;", "isdataat:!1,relative;"] {
        let options = format!("http.uri.raw; content:\"abc\"; {option}");
        assert!(matches(&options, "uri", b"xabc"));
        assert!(!matches(&options, "uri", b"abcx"));
    }
    let chain = "http.uri.raw; content:\"Ab\"; nocase; offset:1; depth:4; pcre:\"/Cd/R\"; content:\"eF\"; distance:1; within:3;";
    assert!(matches(chain, "uri", b"xAbCdx eF"));
    assert!(!matches(chain, "uri", b"xAbCdx  eF"));
    for gap in [b'\n', 0, 255] {
        let bytes = [b'x', b'a', b'B', b'C', b'd', gap, b'e', b'F'];
        assert!(matches(chain, "uri", &bytes), "{bytes:?}");
    }
    assert!(!matches(chain, "uri", b"xABcd\neF"));
    assert!(!matches(chain, "uri", b"xABCd----eF"));
    assert!(!matches(chain, "uri", b"xxxxABCd-eF"));
    assert!(matches(
        "http.uri; content:\"%41\"; offset:0; depth:1; content:\"B\"; distance:1; within:2;",
        "uri.normalized",
        b"A\nB"
    ));
    let mixed =
        "http.uri.raw; content:\"ABC\"; pcre:\"/d.e/imsR\"; content:\"F\"; distance:0; within:1;";
    assert!(matches(mixed, "uri", b"ABCD\nEF"));
    assert!(!matches(mixed, "uri", b"abcD\nEF"));
    assert!(!matches(mixed, "uri", b"ABCD\nEf"));
    assert!(matches(
        "http.uri.raw; pcre:\"/^abc$/imO\";",
        "uri",
        b"x\nABC\ny"
    ));
    assert!(matches("http.uri.raw; bsize:5<>10;", "uri", b"123456"));
    assert!(!matches("http.uri.raw; bsize:5<>10;", "uri", b"12345"));
    assert!(!matches("http.uri.raw; bsize:5<>10;", "uri", b"1234567890"));
    assert!(matches("urilen:>3;", "uri.normalized", b"abcd"));
    assert!(matches("urilen:3,raw;", "uri", b"abc"));
}

#[test]
fn relative_pcre_preserves_its_subject_and_committed_cursor() {
    // A sticky buffer starts with cursor zero even without a preceding match.
    assert!(matches(r#"http.uri.raw; pcre:"/abc/R";"#, "uri", b"xabc"));
    assert!(!matches(r#"http.uri.raw; pcre:"/^abc/R";"#, "uri", b"xabc"));

    // R gives PCRE a new subject beginning at the previous match's end.
    // Anchors and word boundaries cannot be left unchanged in a combined RE.
    for expression in [r"^b", r"\Ab", r"\bb", r"\Bb", r"(?m:^b)"] {
        dropped(
            "http any any -> any any",
            &format!(r#"http.uri.raw; content:"a"; pcre:"/{expression}/R";"#),
            reason::UNSUPPORTED_REGEX,
        );
    }
    // PCRE commits to its chosen end before evaluating the following keyword.
    // A combined RE would backtrack a+ to a, incorrectly accepting "aa".
    for expression in ["a+", "a+?", "a|aa", "(a+)", "a{1,2}"] {
        dropped(
            "http any any -> any any",
            &format!(r#"http.uri.raw; pcre:"/{expression}/"; content:"a"; distance:0; within:1;"#),
            reason::UNSUPPORTED_REGEX,
        );
    }
    dropped(
        "http any any -> any any",
        r#"http.uri.raw; pcre:"/^a+?/"; isdataat:!1,relative;"#,
        reason::UNSUPPORTED_REGEX,
    );
    dropped(
        "http any any -> any any",
        r#"http.uri.raw; pcre:!"/a/"; isdataat:!1,relative;"#,
        reason::UNSUPPORTED_REGEX,
    );
    // These operators remain supported when no later test uses the cursor.
    assert!(matches(r#"http.uri.raw; pcre:"/a+/";"#, "uri", b"aa"));
    assert!(matches(
        r#"http.uri.raw; content:"a"; pcre:"/[b-d].\x65/R"; content:"f"; distance:0; within:1;"#,
        "uri",
        b"abcef"
    ));
    assert!(matches(
        r#"http.uri.raw; content:"a"; pcre:"/\^b\+/R"; content:"c"; distance:0; within:1;"#,
        "uri",
        b"a^b+c"
    ));
    assert!(matches(
        r#"http.uri.raw; content:"a"; pcre:"/[^b]+/R";"#,
        "uri",
        b"accc"
    ));
    assert!(matches(
        r#"http.uri.raw; pcre:"/[^^]/"; content:"b"; distance:0; within:1;"#,
        "uri",
        b"ab"
    ));
}

#[test]
fn relative_start_cursor_and_expanded_list_exclusions() {
    let options = r#"http.uri.raw; content:"b"; distance:2; within:2;"#;
    assert!(matches(options, "uri", b"xxb"));
    assert!(matches(options, "uri", b"xxxb"));
    assert!(!matches(options, "uri", b"xxxxb"));
    assert!(!matches(options, "uri", b"xb"));
    let converted = convert(&rule(
        90001,
        "http any any -> any [80:90,$SHELLCODE_PORTS]",
        r#"http.method; content:"GET";"#,
    ));
    let compiled = compile(converted.rules).unwrap();
    for (port, yes) in [
        (79, false),
        (80, false),
        (81, true),
        (90, true),
        (91, false),
    ] {
        let event = TestEvent::http()
            .int("resp_port", port)
            .text("method", &["GET"]);
        assert_eq!(!matched_ids(&compiled, &event, &[]).is_empty(), yes);
    }
    dropped(
        "http any any -> any any",
        "flowbits:isset,x; http.uri; bsize:bad;",
        reason::FORMAT_ERROR,
    );
}

#[test]
fn length_comparisons_and_hex_separators() {
    assert!(matches(
        r#"http.uri.raw; content:"|00,FF|";"#,
        "uri",
        b"\0\xff"
    ));
    assert!(matches("http.uri.raw; bsize:1kb;", "uri", &[b'x'; 1024]));
    assert!(matches("http.uri.raw; bsize:1-4;", "uri", b"ab"));
    assert!(!matches("http.uri.raw; bsize:1-4;", "uri", b"abcd"));
    assert!(matches("http.uri.raw; bsize:!=3;", "uri", b"ab"));
    assert!(!matches("http.uri.raw; bsize:!=3;", "uri", b"abc"));
}

#[test]
fn rejected_rules_cover_every_reason_and_precedence() {
    let any = "http any any -> any any";
    for (header, options, reason) in [
        (
            any,
            "flowbits:isset,x; http.header.raw;",
            reason::NEEDS_STATE,
        ),
        (
            any,
            "byte_test:1,=,1,0;",
            reason::PAYLOAD_OR_PACKET_CONDITION,
        ),
        (any, "isdataat:3;", reason::PAYLOAD_OR_PACKET_CONDITION),
        (any, "tcp.flags:S;", reason::PAYLOAD_OR_PACKET_CONDITION),
        (any, "unknown:first;", "unsupported_keyword:unknown"),
        (any, "bad keyword:value;", reason::FORMAT_ERROR),
        (any, "tls.version:1.2;", "unsupported_keyword:tls.version"),
        (
            any,
            "http.header.raw; content:\"a\";",
            "unsupported_buffer:http.header.raw",
        ),
        (any, "content:\"a\";", reason::RAW_PAYLOAD),
        (
            "tcp any any -> any any",
            "http.uri; content:\"a\"; dns.query; content:\"b\";",
            reason::MIXED_KINDS,
        ),
        (
            "dns any any -> any any",
            "http.uri; content:\"a\";",
            reason::MIXED_KINDS,
        ),
        (
            any,
            "http.uri; content:\"a\"; http.stat_code; content:\"b\";",
            reason::MIXED_DIRECTIONS,
        ),
        (
            any,
            "flow:to_client; http.header; content:\"a\";",
            reason::NO_RESPONSE_VALUE,
        ),
        (
            any,
            "flow:to_client; http.uri; content:\"a\";",
            reason::DIRECTION_MISMATCH,
        ),
        (
            "http $UNKNOWN any -> any any",
            "http.uri; content:\"a\";",
            reason::PLACEHOLDER_VALUE_MISSING,
        ),
        (
            any,
            "http.uri; content:\"a\"; content:!\"b\"; distance:0;",
            reason::UNSUPPORTED_REGEX,
        ),
        (
            any,
            "http.uri; pcre:\"/(a)\\1/\";",
            reason::UNSUPPORTED_REGEX,
        ),
        (
            any,
            "http.uri; pcre:\"/(?=a)a/\";",
            reason::UNSUPPORTED_REGEX,
        ),
        (any, "http.uri; content:\"|zz|\";", reason::FORMAT_ERROR),
        (any, "unknown:a; another:b;", "unsupported_keyword:unknown"),
        (
            any,
            "http.header.raw; tls.random;",
            "unsupported_buffer:http.header.raw",
        ),
        (
            any,
            "flowbits:isset,x; unknown:foo; http.header.raw;",
            reason::NEEDS_STATE,
        ),
    ] {
        dropped(header, options, reason);
    }
    for buffer in [
        "http.header",
        "http.header_names",
        "http.cookie",
        "http.content_type",
        "http.protocol",
        "http.connection",
    ] {
        dropped(
            any,
            &format!("flow:to_client; {buffer}; content:\"a\";"),
            reason::NO_RESPONSE_VALUE,
        );
    }
    for flag in ["A", "E", "G", "x"] {
        dropped(
            any,
            &format!("http.uri; pcre:\"/abc/{flag}\";"),
            reason::UNSUPPORTED_REGEX,
        );
    }
    dropped(
        any,
        "pcre:\"/abc/D\";",
        "unsupported_buffer:http.header.raw",
    );
    dropped(
        any,
        "content:\"a\"; http_raw_header;",
        "unsupported_buffer:http.header.raw",
    );
    let text = rule(90001, any, "flowbits:isset,x;");
    let bytes = archive(&[("rules/emerging-malware.rules", text.as_bytes())]);
    let converted =
        convert_et_open(&bytes, None, &Blocklist::parse("et_open 90001").unwrap()).unwrap();
    assert_eq!(
        converted.summary.dropped.get(reason::BLOCKLIST).unwrap(),
        &["90001"]
    );
    let missing_msg = rule(90001, any, "").replace("msg:\"synthetic 90001\";", "");
    assert_eq!(
        convert(&missing_msg)
            .summary
            .dropped
            .get(reason::MISSING_ATTRIBUTE)
            .unwrap(),
        &["90001"]
    );
    let no_sid = rule(90001, any, "").replace("sid:90001;", "");
    let mut bad_utf8 = rule(90002, any, "http.uri; content:\"x\";").into_bytes();
    bad_utf8.insert(8, 255);
    let mut lines = format!("# comment\n\n{no_sid}bad syntax\n").into_bytes();
    lines.extend_from_slice(&bad_utf8);
    let converted = convert_et_open(
        &archive(&[("rules/emerging-malware.rules", &lines)]),
        None,
        &Blocklist::default(),
    )
    .unwrap();
    assert_eq!(
        converted
            .summary
            .dropped
            .get(reason::MISSING_ATTRIBUTE)
            .unwrap(),
        &["emerging-malware.rules:3"]
    );
    assert_eq!(
        converted.summary.dropped.get(reason::FORMAT_ERROR).unwrap(),
        &["emerging-malware.rules:4", "90002"]
    );
}

fn network_event(kind: RawEventKind, reverse: bool) -> TestEvent {
    let (orig, resp, orig_port, resp_port) = if reverse {
        ("198.51.100.2", "10.0.0.1", 80, 50000)
    } else {
        ("10.0.0.1", "198.51.100.2", 50000, 80)
    };
    TestEvent::new(kind)
        .addr("orig_addr", orig)
        .addr("resp_addr", resp)
        .int("orig_port", orig_port)
        .int("resp_port", resp_port)
}

#[test]
fn response_and_neutral_directions_keep_endpoints_with_their_fields() {
    let home: Vec<Cidr> = vec!["10.0.0.0/8".parse().unwrap()];
    let converted = convert(&rule(
        90001,
        "http $EXTERNAL_NET any -> $HOME_NET any",
        "flow:established,to_client; file.data; content:\"payload\";",
    ));
    assert_eq!(converted.rules.len(), 1, "{:?}", converted.summary);
    let compiled = compile(converted.rules).unwrap();
    assert_eq!(
        matched_ids(
            &compiled,
            &network_event(RawEventKind::Http, false).bytes("body.response", b"payload"),
            &home
        ),
        ["90001"]
    );
    assert!(
        matched_ids(
            &compiled,
            &network_event(RawEventKind::Http, true).bytes("body.response", b"payload"),
            &home
        )
        .is_empty()
    );
    assert!(
        matched_ids(
            &compiled,
            &network_event(RawEventKind::Http, false).bytes("body.request", b"payload"),
            &home
        )
        .is_empty()
    );
    for flow in [
        "",
        "flow:established;",
        "flow:to_client;",
        "flow:from_server;",
    ] {
        let text = rule(
            90001,
            "ssh 10.0.0.0/8 50000 -> 198.51.100.0/24 80",
            &format!("{flow} ssh.software; content:\"ServerProbe\";"),
        );
        let converted = convert(&text);
        assert_eq!(converted.rules.len(), 1, "{:?}", converted.summary);
        let compiled = compile(converted.rules).unwrap();
        let response = flow.contains("to_client") || flow.contains("from_server");
        let client =
            network_event(RawEventKind::Ssh, false).text("client.software", &["ServerProbe"]);
        let server =
            network_event(RawEventKind::Ssh, true).text("server.software", &["ServerProbe"]);
        assert_eq!(!matched_ids(&compiled, &client, &[]).is_empty(), !response);
        assert_eq!(matched_ids(&compiled, &server, &[]), ["90001"]);
        assert!(
            matched_ids(
                &compiled,
                &network_event(RawEventKind::Ssh, false).text("server.software", &["ServerProbe"]),
                &[]
            )
            .is_empty()
        );
        assert!(
            matched_ids(
                &compiled,
                &network_event(RawEventKind::Ssh, true).text("client.software", &["ServerProbe"]),
                &[]
            )
            .is_empty()
        );
    }
    for (kind, options, field) in [
        (
            RawEventKind::Tls,
            "tls.cert_subject; content:\"CN=Subject\";",
            "subject.joined",
        ),
        (
            RawEventKind::Ssh,
            "ssh.software; content:\"OpenSSH\";",
            "server.software",
        ),
        (
            RawEventKind::Ssh,
            "ssh.hassh.server; content:\"hash\";",
            "hassh_server",
        ),
    ] {
        let protocol = if kind == RawEventKind::Tls {
            "tls"
        } else {
            "ssh"
        };
        let converted = convert(&rule(
            90001,
            &format!("{protocol} any any -> any any"),
            &format!("flow:established,to_client; {options}"),
        ));
        assert_eq!(converted.rules.len(), 1, "{:?}", converted.summary);
        let bytes = if kind == RawEventKind::Tls {
            "CN=Subject"
        } else if field == "server.software" {
            "OpenSSH"
        } else {
            "hash"
        };
        assert_eq!(
            matched_ids(
                &compile(converted.rules).unwrap(),
                &TestEvent::new(kind).text(field, &[bytes]),
                &[]
            ),
            ["90001"]
        );
    }
}

#[test]
fn connection_protocols_and_header_directions() {
    for (protocol, number) in [
        ("ip", None),
        ("tcp", Some(6)),
        ("udp", Some(17)),
        ("icmp", Some(1)),
    ] {
        for arrow in ["->", "<>"] {
            let converted = convert(&rule(
                90001,
                &format!("{protocol} 10.0.0.0/8 50000 {arrow} 198.51.100.2 80"),
                "",
            ));
            assert_eq!(converted.rules.len(), 1, "{:?}", converted.summary);
            assert_eq!(converted.rules[0].kind(), RawEventKind::Conn);
            let compiled = compile(converted.rules).unwrap();
            for reverse in [false, true] {
                for proto in [1, 6, 17, 99] {
                    let event = network_event(RawEventKind::Conn, reverse).int("proto", proto);
                    assert_eq!(
                        !matched_ids(&compiled, &event, &[]).is_empty(),
                        number.is_none_or(|n| n == proto)
                    );
                }
            }
        }
    }
    dropped("http any any -> any any", "", reason::MIXED_KINDS);
    // A unidirectional application-buffer rule does not swap addresses unless <>.
    for arrow in ["->", "<>"] {
        let converted = convert(&rule(
            90001,
            &format!("http 10.0.0.0/8 50000 {arrow} 198.51.100.2 80"),
            "http.method; content:\"GET\";",
        ));
        let compiled = compile(converted.rules).unwrap();
        assert_eq!(
            matched_ids(
                &compiled,
                &network_event(RawEventKind::Http, false).text("method", &["GET"]),
                &[]
            ),
            ["90001"]
        );
        assert_eq!(
            !matched_ids(
                &compiled,
                &network_event(RawEventKind::Http, true).text("method", &["GET"]),
                &[]
            )
            .is_empty(),
            arrow == "<>"
        );
    }
}

#[test]
fn transport_headers_keep_protocol_checks_on_buffer_rules() {
    for (protocol, number) in [
        ("ip", None),
        ("tcp", Some(6)),
        ("udp", Some(17)),
        ("tcp-pkt", Some(6)),
        ("tcp-stream", Some(6)),
    ] {
        let converted = convert(&rule(
            90001,
            &format!("{protocol} any any -> any any"),
            r#"dns.query; content:"needle";"#,
        ));
        assert_eq!(converted.rules.len(), 1, "{:?}", converted.summary);
        let compiled = compile(converted.rules).unwrap();
        for proto in [6, 17, 99] {
            let event = TestEvent::new(RawEventKind::Dns)
                .text("query", &["needle"])
                .int("proto", proto);
            assert_eq!(
                !matched_ids(&compiled, &event, &[]).is_empty(),
                number.is_none_or(|n| n == proto)
            );
        }
    }
}

#[test]
fn addresses_lists_negations_ranges_and_default_variables() {
    let text = rule(
        90001,
        "http $HTTP_SERVERS [50000:,!50001] -> $AIM_SERVERS $HTTP_PORTS",
        "http.method; content:\"GET\";",
    );
    let converted = convert(&text);
    assert_eq!(converted.rules.len(), 1, "{:?}", converted.summary);
    let compiled = compile(converted.rules).unwrap();
    let event = network_event(RawEventKind::Http, false).text("method", &["GET"]);
    assert!(matched_ids(&compiled, &event, &[]).is_empty());
    let home: Vec<Cidr> = vec!["10.0.0.0/8".parse().unwrap()];
    assert_eq!(matched_ids(&compiled, &event, &home), ["90001"]);
    assert!(matched_ids(&compiled, &event, &["198.51.100.0/24".parse().unwrap()]).is_empty());
    assert!(matched_ids(&compiled, &event.clone().int("orig_port", 50001), &home).is_empty());
    for (port, values) in [
        ("$FILE_DATA_PORTS", vec![80, 110, 143]),
        ("$SHELLCODE_PORTS", vec![1, 79, 81, 65535]),
        (":80", vec![0, 80]),
        ("80:", vec![80, 65535]),
    ] {
        let converted = convert(&rule(
            90001,
            &format!("http any any -> any {port}"),
            "http.method; content:\"GET\";",
        ));
        assert_eq!(converted.rules.len(), 1, "{:?}", converted.summary);
        let compiled = compile(converted.rules).unwrap();
        for p in values {
            assert_eq!(
                matched_ids(
                    &compiled,
                    &TestEvent::http()
                        .int("resp_port", p)
                        .text("method", &["GET"]),
                    &[]
                ),
                ["90001"]
            );
        }
    }
    let converted = convert(&rule(
        90001,
        "http [10.0.0.0/8,!10.1.0.0/16,2001:db8::/32] any -> !192.0.2.0/24 any",
        "http.method; content:\"GET\";",
    ));
    let compiled = compile(converted.rules).unwrap();
    for (src, dst, yes) in [
        ("10.0.0.1", "198.51.100.1", true),
        ("10.1.0.1", "198.51.100.1", false),
        ("2001:db8::1", "198.51.100.1", true),
        ("10.0.0.1", "192.0.2.1", false),
    ] {
        let event = TestEvent::http()
            .addr("orig_addr", src)
            .addr("resp_addr", dst)
            .text("method", &["GET"]);
        assert_eq!(!matched_ids(&compiled, &event, &[]).is_empty(), yes);
    }
}

#[test]
fn nested_header_lists_keep_global_exclusions() {
    let converted = convert(&rule(
        90001,
        "http [10.0.0.0/8,[192.0.2.0/24,!10.1.0.0/16]] any -> any [80:100,[443,!90]]",
        r#"http.method; content:"GET";"#,
    ));
    assert_eq!(converted.rules.len(), 1, "{:?}", converted.summary);
    let compiled = compile(converted.rules).unwrap();
    for (address, port, yes) in [
        ("10.2.0.1", 80, true),
        ("10.1.0.1", 80, false),
        ("192.0.2.1", 443, true),
        ("10.2.0.1", 90, false),
    ] {
        let event = TestEvent::http()
            .addr("orig_addr", address)
            .int("resp_port", port)
            .text("method", &["GET"]);
        assert_eq!(!matched_ids(&compiled, &event, &[]).is_empty(), yes);
    }
}

#[test]
fn attributes_references_licenses_headers_and_summary() {
    let text = rule(
        90001,
        "http any any -> any any",
        "http.header; content:\"X-Foo|3a 20|bar\"; classtype:trojan-activity; reference:url,www.example.com/a; reference:cve,2021-44228; reference:private,value; metadata:signature_severity Major,mitre_tactic_id TA0001,mitre_tactic_id bad,mitre_technique_id T1059_001,mitre_technique_id T1190,mitre_technique_id T99;",
    );
    let converted = convert(&text);
    assert_eq!(converted.rules.len(), 1, "{:?}", converted.summary);
    let converted_rule = &converted.rules[0];
    assert_eq!(converted_rule.source(), Source::EtOpen);
    assert_eq!(converted_rule.source_rule_id(), "90001");
    assert_eq!(converted_rule.source_rule_rev(), Some(2));
    assert_eq!(converted_rule.title(), "synthetic 90001");
    assert_eq!(converted_rule.classification(), Some("trojan-activity"));
    assert_eq!(converted_rule.severity(), Some("Major"));
    assert_eq!(converted_rule.tactics(), ["TA0001"]);
    assert_eq!(converted_rule.techniques(), ["T1059.001", "T1190"]);
    assert_eq!(
        converted_rule.references(),
        [
            "http://www.example.com/a",
            "http://cve.mitre.org/cgi-bin/cvename.cgi?name=2021-44228",
            "private,value"
        ]
    );
    assert_eq!(converted_rule.license(), Some("BSD"));
    assert_eq!(converted_rule.os(), None);
    assert_eq!(converted_rule.author(), None);
    assert_eq!(converted.summary.header_values_partly_missing, 1);
    assert_eq!(
        converted.summary.accepted.get(&Model::EtSignature),
        Some(&1)
    );
    assert_eq!(converted.summary.rulec_version, VERSION);
    assert_eq!(converted.summary.partly_never_true, 0);
    assert_eq!(converted.summary.partly_never_true_under_not, 0);
    assert!(converted.summary.unmapped_fields.is_empty());
    assert!(converted.summary.db_size > 0);
    assert!(!converted.summary.compile_time.is_zero());
    assert!(converted.summary.always_check.is_empty());
    assert!(
        serde_json::to_value(&converted.summary)
            .unwrap()
            .is_object()
    );
    for (content, count) in [
        ("X-Foo|3a 20|bar", 1),
        ("Cookie|3a 20|a", 1),
        ("User-Agent|3a 20|x", 0),
        ("X-Foo|3a|", 0),
        ("uSeR-AgEnT|3a 20|x", 0),
    ] {
        assert_eq!(
            accepted(&format!("http.header; content:\"{content}\";"))
                .summary
                .header_values_partly_missing,
            count
        );
    }
    let converted = accepted(
        "http.header; content:\"X-Foo|3a 20|bar\"; offset:0; depth:30; content:\"end\"; distance:0;",
    );
    assert_eq!(converted.summary.header_values_partly_missing, 1);
    for (sid, license) in [
        (1, "GPL-2.0"),
        (3464, "GPL-2.0"),
        (3465, "BSD"),
        (100_000_000, "GPL-2.0"),
        (100_000_908, "GPL-2.0"),
        (100_000_909, "BSD"),
    ] {
        assert_eq!(
            convert(&rule(sid, "ip any any -> any any", "")).rules[0].license(),
            Some(license)
        );
    }
    let converted = convert(&rule(90001, "tcp any any -> any any", ""));
    assert_eq!(converted.summary.always_check[0].kind, RawEventKind::Conn);
    assert_eq!(converted.summary.always_check[0].count, 1);
    let bundle = RuleBundle::new(Source::EtOpen, converted.rules.clone()).unwrap();
    assert_eq!(
        RuleBundle::from_bytes(&bundle.to_bytes().unwrap())
            .unwrap()
            .into_rules(),
        converted.rules
    );
}

#[test]
fn pcre_buffer_flags_and_regex_compile_exclusions() {
    for (flag, field) in [
        ("U", "uri.normalized"),
        ("I", "uri"),
        ("H", "header_block"),
        ("C", "cookie"),
        ("M", "method"),
        ("P", "body.request"),
        ("Q", "body.response"),
        ("S", "status_code"),
        ("Y", "status_msg"),
        ("V", "user_agent"),
        ("W", "host.normalized"),
        ("Z", "host"),
    ] {
        assert!(
            matches(&format!("pcre:\"/needle/{flag}\";"), field, b"needle"),
            "{flag}"
        );
    }

    let body_chain = r#"flow:to_client; file.data; content:"A"; pcre:"/B/QR"; content:"C"; distance:0; within:1;"#;
    assert!(matches(body_chain, "body.response", b"A\nBC"));
    assert!(!matches(body_chain, "body.response", b"ABxC"));
    dropped(
        "http any any -> any any",
        r#"http.uri; content:"a"; byte_extract:1,0,n; content:"b"; within:n;"#,
        reason::PAYLOAD_OR_PACKET_CONDITION,
    );
    dropped(
        "http any any -> any any",
        r#"flowbits:isset,x; http.uri; content:"a"; byte_extract:1,0,n; content:"b"; within:n;"#,
        reason::NEEDS_STATE,
    );
    let text = format!(
        "{}{}{}",
        rule(
            90001,
            "http any any -> any any",
            "http.header; content:\"X-Foo|3a 20|x\"; pcre:\"/(a)\\1/\";"
        ),
        rule(
            90001,
            "http any any -> any any",
            "http.uri; content:\"ok\";"
        ),
        rule(90002, "http any any -> any any", "http.uri; pcre:\"/a*/\";")
    );
    let converted = convert(&text);
    assert_eq!(converted.rules.len(), 1);
    assert_eq!(converted.rules[0].source_rule_id(), "90001");
    assert_eq!(
        converted
            .summary
            .dropped
            .get(reason::UNSUPPORTED_REGEX)
            .unwrap(),
        &["90001", "90002"]
    );
    assert_eq!(converted.summary.header_values_partly_missing, 0);
    assert!(
        compile(converted.rules)
            .unwrap()
            .stats()
            .excluded()
            .is_empty()
    );
}

fn record<T: serde::de::DeserializeOwned>(extra: serde_json::Value) -> T {
    let mut fields = serde_json::json!({
        "orig_addr":"10.0.0.1", "orig_port":50000, "resp_addr":"198.51.100.2", "resp_port":80,
        "proto":6,"start_time":1,"duration":1,"orig_pkts":1,"resp_pkts":1,"orig_l2_bytes":1,"resp_l2_bytes":1
    });
    fields
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    serde_json::from_value(fields).unwrap()
}

fn http_record(method: &str, body: &[u8]) -> Http {
    record(
        serde_json::json!({"method":method,"host":"Example.COM","uri":"/%41","referer":"","version":"1.1","user_agent":"","request_len":0,"response_len":0,"status_code":200,"status_msg":"OK","username":"","password":"","cookie":"","content_encoding":"","content_type":"","cache_control":"","filenames":[],"mime_types":[],"body":body,"state":"","request_header_names":[],"accept":"","connection":"","accept_encoding":"","accept_language":"","pragma":""}),
    )
}

#[test]
fn negated_request_body_does_not_match_records_without_request_data() {
    for pattern in [r#"content:!"x";"#, r#"pcre:!"/x/";"#] {
        let converted = accepted(&format!("flow:to_server; file.data; {pattern}"));
        let compiled = compile(converted.rules).unwrap();
        let mut matcher = compiled.matcher();
        for (method, body, matches) in [
            ("GET", b"".as_slice(), false),
            ("GET", b"good", false),
            ("POST", b"", false),
            ("POST", b"good", true),
            ("POST", b"x", false),
        ] {
            assert_eq!(
                !matcher
                    .matches(&http_record(method, body), &[])
                    .unwrap()
                    .is_empty(),
                matches,
                "{method}, {body:?}, {pattern}"
            );
        }
    }
}

#[test]
fn converted_rules_match_all_five_giganto_record_kinds() {
    let text = [
        rule(90001, "http $HOME_NET any -> $EXTERNAL_NET any", "http.uri; content:\"/%41\"; http.host; content:\"Example.COM\";"),
        rule(90002, "dns any any -> any any", "dns.query; content:\"probe.example\";"),
        rule(90003, "tls any any -> any any", "flow:to_client; tls.cert_subject; content:\"CN=Subject\"; tls.cert_issuer; content:\"CN=Issuer\";"),
        rule(90004, "ssh any any -> any any", "flow:to_client; ssh.software; content:\"OpenSSH\";"),
        rule(90005, "tcp any any -> any any", ""),
        rule(90006, "http $EXTERNAL_NET any -> $HOME_NET any", r#"flow:to_client; file.data; content:"payload";"#),
    ].concat();
    let converted = convert(&text);
    assert_eq!(converted.rules.len(), 6, "{:?}", converted.summary);
    let compiled = compile(converted.rules).unwrap();
    let home = ["10.0.0.0/8".parse::<Cidr>().unwrap()];
    let mut matcher = compiled.matcher();
    let http = http_record("GET", b"payload");
    assert_eq!(
        matcher
            .matches(&http, &home)
            .unwrap()
            .iter()
            .map(|m| m.rule().source_rule_id())
            .collect::<Vec<_>>(),
        ["90001", "90006"]
    );
    let dns: Dns = record(
        serde_json::json!({"query":"probe.example","answer":[],"trans_id":1,"rtt":0,"qclass":1,"qtype":1,"rcode":0,"aa_flag":false,"tc_flag":false,"rd_flag":true,"ra_flag":false,"ttl":[]}),
    );
    assert_eq!(
        matcher.matches(&dns, &home).unwrap()[0]
            .rule()
            .source_rule_id(),
        "90002"
    );
    let tls: Tls = record(
        serde_json::json!({"server_name":"","alpn_protocol":"","ja3":"","version":"","client_cipher_suites":[],"client_extensions":[],"cipher":0,"extensions":[],"ja3s":"","serial":"","subject_country":"","subject_org_name":"","subject_common_name":"Subject","validity_not_before":0,"validity_not_after":0,"subject_alt_name":"","issuer_country":"","issuer_org_name":"","issuer_org_unit_name":"","issuer_common_name":"Issuer","last_alert":0}),
    );
    assert_eq!(
        matcher.matches(&tls, &home).unwrap()[0]
            .rule()
            .source_rule_id(),
        "90003"
    );
    let ssh: Ssh = record(
        serde_json::json!({"client":"SSH-2.0-Other","server":"SSH-2.0-OpenSSH","cipher_alg":"","mac_alg":"","compression_alg":"","kex_alg":"","host_key_alg":"","host_key":"","hassh_algorithms":"","hassh":"","hassh_server_algorithms":"","hassh_server":"","client_shka":"","server_shka":""}),
    );
    assert_eq!(
        matcher.matches(&ssh, &home).unwrap()[0]
            .rule()
            .source_rule_id(),
        "90004"
    );
    let conn: Conn =
        record(serde_json::json!({"conn_state":"SF","service":"","orig_bytes":0,"resp_bytes":0}));
    assert_eq!(
        matcher.matches(&conn, &home).unwrap()[0]
            .rule()
            .source_rule_id(),
        "90005"
    );
}
