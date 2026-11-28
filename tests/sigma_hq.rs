//! Synthetic source rules and zip files; no upstream rule text is stored here.

mod common;

use std::{
    io::{Cursor, Write},
    net::{IpAddr, Ipv4Addr},
};

use common::{TestEvent, matched_ids};
use giganto_client::{
    RawEventKind,
    ingest::{
        endpoint::OsFamily,
        network::{Conn, Dns, Http, Tls},
    },
};
use jiff::civil::date;
use rulec::{
    Blocklist, Conversion, FieldStatus, Model, Os, SigmaHqError, Source, VERSION,
    catalog_field_prefixes, catalog_fields, compile, content_digest, convert_sigma_hq,
    convert_sigma_hq_emerging, field_status, read_sigma_hq_emerging_version, read_sigma_hq_version,
    reason, unknown_fields,
};
use zip::{ZipWriter, write::FullFileOptions};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const VERSION_TEXT: &str =
    "Release Date: 2026-07-09\nLabel: r2026-04-01-50-g552f3fee4\nCommit-Hash: ignored\n";
const MTIME: u32 = 1_783_598_400; // A timestamp on 2026-07-09 UTC.

fn archive(files: &[(&str, &[u8])], comment: &str, mtimes: &[Option<u32>]) -> Vec<u8> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    zip.set_comment(comment).unwrap();
    for (index, (name, bytes)) in files.iter().enumerate() {
        let mut options = FullFileOptions::default();
        if let Some(seconds) = mtimes.get(index).copied().flatten() {
            let mut extra = vec![1];
            extra.extend_from_slice(&seconds.to_le_bytes());
            options
                .add_extra_field(0x5455, extra.into_boxed_slice(), false)
                .unwrap();
        }
        zip.start_file(*name, options).unwrap();
        zip.write_all(bytes).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

fn release(files: &[(&str, &str)]) -> Vec<u8> {
    let mut files: Vec<_> = files.iter().map(|(p, t)| (*p, t.as_bytes())).collect();
    files.push(("version.txt", VERSION_TEXT.as_bytes()));
    archive(&files, "", &[])
}

fn source_rule(id: &str, logsource: &str, detection: &str) -> String {
    format!("id: {id}\ntitle: synthetic {id}\nlogsource: {logsource}\ndetection:\n{detection}")
}

fn simple(id: &str, logsource: &str, fields: &str, condition: &str) -> String {
    source_rule(
        id,
        logsource,
        &format!("  selection: {fields}\n  condition: {condition}\n"),
    )
}

fn convert_one(text: &str) -> Conversion {
    convert_sigma_hq(
        &release(&[("rules/synthetic.yml", text)]),
        None,
        &Blocklist::default(),
    )
    .unwrap()
}

fn assert_accepted(conversion: &Conversion, expected: usize) {
    assert_eq!(
        conversion.rules.len(),
        expected,
        "{:?}",
        conversion.summary.dropped
    );
    for rule in &conversion.rules {
        assert!(unknown_fields(rule).unwrap().is_empty());
    }
    let compiled = compile(conversion.rules.clone()).unwrap();
    assert!(compiled.stats().excluded().is_empty());
}

#[test]
fn scope_status_wrapper_digest_and_version_only_parity() {
    let rule = simple("r", "{category: proxy}", "{c-uri: /example}", "selection");
    let deprecated = format!("{rule}status: deprecated\n");
    let unsupported = format!("{rule}status: unsupported\n");
    let files = [
        ("rules/network/a.yml", rule.as_str()),
        ("rules/network/b.yaml", deprecated.as_str()),
        ("rules/c.yml", unsupported.as_str()),
        ("rules/deprecated/x.yml", "invalid"),
        ("rules/windows/deprecated/x.yml", "invalid"),
        ("deprecated/x.yml", "invalid"),
        ("rules-threat-hunting/x.yml", "invalid"),
        ("rules-placeholder/x.yml", "invalid"),
        ("rules-compliance/x.yml", "invalid"),
        ("rules-emerging-threats/x.yml", "invalid"),
        ("rules/x.txt", "invalid"),
    ];
    let bytes = release(&files);
    let converted = convert_sigma_hq(&bytes, Some("r2026-07-01"), &Blocklist::default()).unwrap();
    assert_accepted(&converted, 1);
    assert!(converted.summary.dropped.is_empty());
    let v = read_sigma_hq_version(&bytes, Some("r2026-07-01")).unwrap();
    assert_eq!(converted.summary.source_version, v);
    assert_eq!(v.version, "r2026-04-01-50-g552f3fee4 (2026-07-09)");
    assert_eq!(v.release_name.as_deref(), Some("r2026-07-01"));
    assert_eq!(v.order_key.date, date(2026, 7, 9));
    assert_eq!(v.order_key.number, None);
    assert_eq!(
        v.content_digest,
        content_digest([
            ("network/a.yml", rule.as_bytes()),
            ("network/b.yaml", deprecated.as_bytes()),
            ("c.yml", unsupported.as_bytes())
        ])
    );
    let wrapped: Vec<_> = files
        .iter()
        .map(|(p, t)| (format!("sigma-any/{p}"), t.as_bytes()))
        .chain(std::iter::once((
            "sigma-any/version.txt".into(),
            VERSION_TEXT.as_bytes(),
        )))
        .collect();
    let refs: Vec<_> = wrapped.iter().map(|(p, t)| (p.as_str(), *t)).collect();
    let bytes = archive(&refs, "", &[]);
    let wrapped = convert_sigma_hq(&bytes, None, &Blocklist::default()).unwrap();
    assert_eq!(wrapped.rules, converted.rules);
    assert_eq!(
        wrapped.summary.source_version.content_digest,
        v.content_digest
    );
    assert_eq!(wrapped.summary.source_version.release_name, None);
}

#[test]
fn emerging_uses_comment_and_utc_timestamp_and_hashes_only_its_subtree() {
    let rule = simple(
        "r",
        "{category: dns}",
        "{query: example.invalid}",
        "selection",
    );
    let make = |root: &str, contents: &str, outside: &str| {
        let a = format!("{root}rules-emerging-threats/test/a.yaml");
        let b = format!("{root}rules/outside.yml");
        archive(
            &[(&a, contents.as_bytes()), (&b, outside.as_bytes())],
            SHA,
            &[Some(MTIME), Some(MTIME)],
        )
    };
    let a = make("sigma-master/", &rule, "outside");
    let b = make("sigma-sha/", &rule, "changed outside");
    let c = make("", &rule, "outside");
    let v = read_sigma_hq_emerging_version(&a).unwrap();
    assert_eq!(v.version, "master@0123456 (2026-07-09)");
    assert_eq!(v.order_key.date, date(2026, 7, 9));
    assert_eq!(v.order_key.number, None);
    assert_eq!(v.release_name, None);
    assert_eq!(v, read_sigma_hq_emerging_version(&b).unwrap());
    assert_eq!(v, read_sigma_hq_emerging_version(&c).unwrap());
    let converted = convert_sigma_hq_emerging(&a, &Blocklist::default()).unwrap();
    assert_eq!(converted.summary.source_version, v);
    assert_eq!(converted.summary.source, Source::SigmaHqEmerging);
    assert_eq!(converted.rules[0].source(), Source::SigmaHqEmerging);
    assert_accepted(&converted, 1);
    assert_ne!(
        v.content_digest,
        read_sigma_hq_emerging_version(&make("", &format!("{rule}# changed\n"), "outside"))
            .unwrap()
            .content_digest
    );
}

fn same_archive_error(bytes: &[u8], emerging: bool) -> String {
    let (version, conversion) = if emerging {
        (
            read_sigma_hq_emerging_version(bytes),
            convert_sigma_hq_emerging(bytes, &Blocklist::default()),
        )
    } else {
        (
            read_sigma_hq_version(bytes, None),
            convert_sigma_hq(bytes, None, &Blocklist::default()),
        )
    };
    let a = version.unwrap_err();
    let b = conversion.unwrap_err();
    assert_eq!(std::mem::discriminant(&a), std::mem::discriminant(&b));
    assert_eq!(a.to_string(), b.to_string());
    a.to_string()
}

#[test]
fn emerging_rejects_timestamps_without_the_central_mtime_flag() {
    let original = archive(
        &[("rules-emerging-threats/a.yml", b"bad rule")],
        SHA,
        &[Some(MTIME)],
    );
    assert!(read_sigma_hq_emerging_version(&original).is_ok());
    let mut timestamp = vec![0x55, 0x54, 5, 0, 1];
    timestamp.extend_from_slice(&MTIME.to_le_bytes());
    let offsets: Vec<_> = original
        .windows(timestamp.len())
        .enumerate()
        .filter_map(|(offset, bytes)| (bytes == timestamp).then_some(offset + 4))
        .collect();
    assert_eq!(offsets.len(), 2);
    for flags in [0, 2] {
        // The central header is authoritative even with a valid local mtime.
        for local_flags in [1, flags] {
            let mut bytes = original.clone();
            *bytes.get_mut(*offsets.first().unwrap()).unwrap() = local_flags;
            *bytes.get_mut(*offsets.last().unwrap()).unwrap() = flags;
            assert!(matches!(
                read_sigma_hq_emerging_version(&bytes),
                Err(SigmaHqError::NoCommitInfo)
            ));
            assert!(matches!(
                convert_sigma_hq_emerging(&bytes, &Blocklist::default()),
                Err(SigmaHqError::NoCommitInfo)
            ));
        }
    }
}

#[test]
fn oversized_selected_members_fail_both_apis_but_outside_members_are_ignored() {
    let oversized = vec![b'x'; 8 * 1024 * 1024 + 1];
    for (path, emerging) in [
        ("rules/large.yml", false),
        ("version.txt", false),
        ("rules-emerging-threats/large.yml", true),
    ] {
        let bytes = archive(
            &[("rules/a.yml", b"x"), (path, &oversized)],
            SHA,
            &[Some(MTIME); 2],
        );
        let message = same_archive_error(&bytes, emerging);
        assert!(message.contains("uncompressed data exceeds"), "{message}");
        assert!(message.contains(path), "{message}");
    }
    let rule = simple("r", "{category: proxy}", "{c-uri: /example}", "selection");
    let bytes = archive(
        &[
            ("rules/a.yml", rule.as_bytes()),
            ("version.txt", VERSION_TEXT.as_bytes()),
            ("outside.yml", &oversized),
        ],
        "",
        &[],
    );
    let conversion = convert_sigma_hq(&bytes, None, &Blocklist::default()).unwrap();
    assert_accepted(&conversion, 1);
    assert_eq!(
        read_sigma_hq_version(&bytes, None).unwrap(),
        conversion.summary.source_version
    );
}

#[test]
fn archive_errors_follow_required_priority_for_both_apis() {
    for emerging in [false, true] {
        assert!(same_archive_error(b"not a zip", emerging).contains("cannot read the zip"));
        assert!(
            same_archive_error(&archive(&[("outside.yml", b"x")], "", &[]), emerging)
                .contains("no rule files")
        );
    }
    let path = "rules/a.yml";
    for version in [
        None,
        Some("Label: label"),
        Some("Release Date: 2026-07-09"),
        Some("Label: label\nRelease Date: 2026-7-9"),
        Some("Label: label\nRelease Date: 2026-02-30"),
    ] {
        let mut files = vec![(path, b"bad rule".as_slice())];
        if let Some(text) = version {
            files.push(("version.txt", text.as_bytes()));
        }
        assert!(
            same_archive_error(&archive(&files, "", &[]), false).contains("no version information")
        );
    }
    let files = [
        (
            "sigma-master/rules-emerging-threats/a.yml",
            b"bad rule".as_slice(),
        ),
        ("sigma-master/README", b"x".as_slice()),
    ];
    for (comment, times) in [
        ("", vec![Some(MTIME); 2]),
        ("01234", vec![Some(MTIME); 2]),
        (
            "z123456789abcdef0123456789abcdef01234567",
            vec![Some(MTIME); 2],
        ),
        (SHA, vec![Some(MTIME), Some(MTIME + 1)]),
        (SHA, vec![Some(MTIME), None]),
    ] {
        assert!(
            same_archive_error(&archive(&files, comment, &times), true)
                .contains("exactly as downloaded from GitHub, unmodified")
        );
    }
    assert!(matches!(
        read_sigma_hq_emerging_version(&release(&[
            ("rules/a.yml", "bad"),
            ("rules-emerging-threats/a.yml", "bad")
        ])),
        Err(SigmaHqError::NoCommitInfo)
    ));
}

#[test]
fn fieldref_both_sides_map_and_unmapped_reference_is_never() {
    let good = simple(
        "ref",
        "{product: windows, category: process_creation}",
        "{Image|fieldref: ParentImage}",
        "selection",
    );
    let c = convert_one(&good);
    assert_accepted(&c, 1);
    let compiled = compile(c.rules).unwrap();
    let event = TestEvent::new(RawEventKind::ProcessCreate)
        .os(OsFamily::Windows)
        .text("image", &["same"])
        .text("parent_image", &["SAME"]);
    assert_eq!(matched_ids(&compiled, &event, &[]), ["ref"]);
    let event = TestEvent::new(RawEventKind::ProcessCreate)
        .os(OsFamily::Windows)
        .text("image", &["same"])
        .text("parent_image", &["different"]);
    assert!(matched_ids(&compiled, &event, &[]).is_empty());
    let c = convert_one(&good.replace("ParentImage", "NoSuchField"));
    assert_accepted(&c, 1);
    assert_eq!(c.summary.partly_never_true, 1);
    assert_eq!(c.summary.unmapped_fields.get("NoSuchField"), Some(&1));
    assert!(matched_ids(&compile(c.rules).unwrap(), &event, &[]).is_empty());
}

#[test]
fn added_conditions_guard_ps_channels_event_ids_and_registry_types() {
    for (category, id) in [("ps_module", 4103), ("ps_script", 4104)] {
        for condition in [
            "1 of them",
            "all of them",
            "1 of sel*",
            "selection",
            "[selection, '1 of sel*']",
        ] {
            let rule = simple(
                "ps",
                &format!("{{product: windows, category: {category}}}"),
                "{ScriptBlockText|contains: needle}",
                condition,
            );
            let c = convert_one(&rule);
            assert_accepted(&c, 1);
            let compiled = compile(c.rules).unwrap();
            for channel in [
                "Microsoft-Windows-PowerShell/Operational",
                "PowerShellCore/Operational",
                "Other",
            ] {
                for event_id in [id, 1] {
                    for value in ["needle", "other"] {
                        let event = TestEvent::new(RawEventKind::WindowsEventLog)
                            .os(OsFamily::Windows)
                            .text("channel", &[channel])
                            .int("event_id", event_id)
                            .text("event_data.ScriptBlockText", &[value]);
                        assert_eq!(
                            !matched_ids(&compiled, &event, &[]).is_empty(),
                            channel != "Other" && event_id == id && value == "needle",
                            "{category} {condition} {channel} {event_id} {value}"
                        );
                    }
                }
            }
        }
    }
    for (category, allowed) in [
        ("registry_add", vec!["CreateKey"]),
        ("registry_delete", vec!["DeleteKey", "DeleteValue"]),
    ] {
        let c = convert_one(&simple(
            "reg",
            &format!("{{product: windows, category: {category}}}"),
            "{TargetObject: target}",
            "1 of them",
        ));
        assert_accepted(&c, 1);
        let compiled = compile(c.rules).unwrap();
        for event_type in ["CreateKey", "DeleteKey", "DeleteValue", "SetValue"] {
            let event = TestEvent::new(RawEventKind::RegistryObjectAddDel)
                .os(OsFamily::Windows)
                .text("event_type", &[event_type])
                .text("target_object", &["target"]);
            assert_eq!(
                !matched_ids(&compiled, &event, &[]).is_empty(),
                allowed.contains(&event_type)
            );
        }
    }
}

#[test]
fn added_conditions_preserve_them_exclusions_and_explicit_auxiliary_references() {
    for (condition, expected) in [
        ("1 of them", [true, true, true, false, false, true]),
        ("all of them", [false, false, true, false, false, true]),
        (
            "[all of them, _aux]",
            [false, true, true, false, true, true],
        ),
        ("all of *", [false, false, false, false, false, true]),
        ("all of _*", [false, true, false, false, true, true]),
        ("_aux", [false, true, false, false, true, true]),
    ] {
        for (logsource, kind, field, guarded) in [
            (
                "{product: windows, category: process_creation}",
                RawEventKind::ProcessCreate,
                "command_line",
                false,
            ),
            (
                "{product: windows, service: security}",
                RawEventKind::WindowsEventLog,
                "event_data.CommandLine",
                true,
            ),
        ] {
            let rule = source_rule(
                "aux",
                logsource,
                &format!(
                    "  selection: {{CommandLine|contains: needle}}\n  _aux: {{CommandLine|contains: other}}\n  secondary: {{CommandLine|contains: second}}\n  condition: {condition}\n"
                ),
            );
            let conversion = convert_one(&rule);
            assert_accepted(&conversion, 1);
            let compiled = compile(conversion.rules).unwrap();
            for (value, matches) in [
                "needle",
                "needle other",
                "needle second",
                "neither",
                "other",
                "needle other second",
            ]
            .into_iter()
            .zip(expected)
            {
                for channel in ["Security", "System"] {
                    let event = TestEvent::new(kind)
                        .os(OsFamily::Windows)
                        .text(field, &[value])
                        .text("channel", &[channel]);
                    assert_eq!(
                        !matched_ids(&compiled, &event, &[]).is_empty(),
                        matches && (!guarded || channel == "Security"),
                        "{logsource} {condition} {value} {channel}"
                    );
                }
            }
        }
    }
}

#[test]
fn never_counts_follow_referenced_identifiers_and_not_parity() {
    let logsource = "{product: windows, category: process_creation}";
    for (condition, partly, under_not) in [
        ("selection", 0, 0),
        ("selection and not filter", 1, 1),
        ("selection and not not filter", 1, 0),
        ("selection or filter or not filter", 1, 1),
        ("selection and (1 of filter*)", 1, 0),
    ] {
        let rule = source_rule(
            "r",
            logsource,
            &format!(
                "  selection: {{Image: image}}\n  filter: {{NoSuchField: first, NoSuchField|contains: second}}\n  condition: {condition}\n"
            ),
        );
        let c = convert_one(&rule);
        assert_accepted(&c, 1);
        assert_eq!(c.summary.partly_never_true, partly, "{condition}");
        assert_eq!(
            c.summary.partly_never_true_under_not, under_not,
            "{condition}"
        );
        assert_eq!(c.summary.unmapped_fields.get("NoSuchField"), Some(&1));
        let event = TestEvent::new(RawEventKind::ProcessCreate)
            .os(OsFamily::Windows)
            .text("image", &["image"]);
        let compiled = compile(c.rules).unwrap();
        assert_eq!(
            !matched_ids(&compiled, &event, &[]).is_empty(),
            under_not == 1 || partly == 0
        );
        for m in compiled.matcher().matches(&event, &[]).unwrap() {
            assert!(!m.fields().contains(&"NoSuchField"));
        }
    }
    let list = source_rule(
        "list",
        logsource,
        "  selection:\n    - NoSuchField: x\n    - Image: image\n  condition: selection\n",
    );
    let c = convert_one(&list);
    assert_eq!(c.summary.partly_never_true, 1);
    assert_eq!(c.summary.partly_never_true_under_not, 0);
    assert_accepted(&c, 1);
}

#[test]
fn journald_keywords_and_named_fields_and_audit_prefixes() {
    let keywords = source_rule(
        "keywords",
        "{product: linux, service: auth}",
        "  selection: ['failed login', 'bad password']\n  condition: selection\n",
    );
    let c = convert_one(&keywords);
    assert_accepted(&c, 1);
    assert_eq!(c.rules[0].os(), Some(Os::Linux));
    let compiled = compile(c.rules).unwrap();
    for facility in ["4", "10", "9"] {
        let event = TestEvent::new(RawEventKind::Journald)
            .os(OsFamily::Linux)
            .text("fields.MESSAGE", &["a FAILED LOGIN attempt"])
            .text("fields.SYSLOG_FACILITY", &[facility]);
        assert_eq!(
            !matched_ids(&compiled, &event, &[]).is_empty(),
            facility != "9"
        );
    }
    for (logsource, fields, expected) in [
        ("{product: linux}", "{MESSAGE: x}", None),
        (
            "{product: linux, service: auditd}",
            "{type: EXECVE, a0: command}",
            Some(vec!["record_type", "fields.a0"]),
        ),
        (
            "{product: windows, service: security}",
            "{EventID: 1, Channel: Security, Provider_Name: P, Computer: C, Level: 2, Task: 3, Opcode: 4, Version: 5, EventRecordID: 6, CommandLine: x}",
            Some(vec![
                "event_id",
                "channel",
                "provider",
                "computer",
                "level",
                "task",
                "opcode",
                "version",
                "record_id",
                "event_data.CommandLine",
            ]),
        ),
    ] {
        let c = convert_one(&simple("r", logsource, fields, "selection"));
        assert_accepted(&c, 1);
        let json = serde_json::to_string(&c.rules[0]).unwrap();
        if let Some(fields) = expected {
            for field in fields {
                assert!(json.contains(&format!("\"{field}\"")), "{json}");
            }
        } else {
            assert_eq!(c.summary.unmapped_fields.get("MESSAGE"), Some(&1));
        }
    }
}

#[test]
fn dropped_reasons_ids_paths_and_priority() {
    let mut cases = vec![
        (
            "blocked",
            simple("blocked", "{product: macos}", "{x|minute: 1}", "selection"),
            reason::BLOCKLIST,
        ),
        (
            "format",
            "id: format\ntitle: x\nlogsource: {category: proxy}\ndetection: bad\n".into(),
            reason::FORMAT_ERROR,
        ),
        (
            "correlation",
            "id: correlation\ntitle: x\ncorrelation: {type: event_count}\n".into(),
            reason::CORRELATION_RULE,
        ),
        (
            "mac",
            simple("mac", "{product: macos}", "{x|minute: 1}", "selection"),
            reason::NO_INPUT_KIND_MACOS,
        ),
        (
            "kube",
            simple(
                "kube",
                "{product: kubernetes, service: audit}",
                "{x: y}",
                "selection",
            ),
            reason::NO_INPUT_KIND,
        ),
        (
            "registry",
            simple(
                "registry",
                "{product: windows, category: registry_event}",
                "{x: y}",
                "selection",
            ),
            reason::NO_INPUT_KIND,
        ),
        (
            "modifier",
            simple(
                "modifier",
                "{category: proxy}",
                "{Unknown|minute: 1}",
                "selection",
            ),
            "unsupported_modifier:minute",
        ),
        (
            "placeholder",
            simple(
                "placeholder",
                "{category: proxy}",
                "{c-uri|expand: '%missing%'}",
                "selection",
            ),
            reason::PLACEHOLDER_VALUE_MISSING,
        ),
        (
            "keywords",
            source_rule(
                "keywords",
                "{category: webserver}",
                "  selection: [keyword]\n  condition: selection\n",
            ),
            reason::KEYWORDS_WITHOUT_FIELD,
        ),
        (
            "regex",
            simple(
                "regex",
                "{category: proxy}",
                "{c-uri|re: '(x)\\1'}",
                "selection",
            ),
            reason::UNSUPPORTED_REGEX,
        ),
        (
            "missing-title",
            "id: missing-title\n".into(),
            reason::MISSING_ATTRIBUTE,
        ),
    ];
    // The first unsupported name in document order wins; it also wins over placeholders.
    cases.push((
        "first-mod",
        simple(
            "first-mod",
            "{category: proxy}",
            "{c-uri|expand: '%missing%', Unknown|minute: 1, Other|hour: 2}",
            "selection",
        ),
        "unsupported_modifier:minute",
    ));
    cases.push((
        "bad-and-mac",
        simple("bad-and-mac", "{product: macos}", "{x: []}", "selection"),
        reason::FORMAT_ERROR,
    ));
    let mut files: Vec<_> = cases
        .iter()
        .map(|(name, body, _)| (format!("rules/{name}.yml"), body.clone()))
        .collect();
    files.push(("rules/no-id.yml".into(), "title: no id\n".into()));
    files.push(("rules/bad-yaml.yml".into(), "id: [unterminated".into()));
    files.push((
        "rules/multi.yml".into(),
        "id: multi\n---\nid: another\n".into(),
    ));
    let refs: Vec<_> = files
        .iter()
        .map(|(p, t)| (p.as_str(), t.as_str()))
        .collect();
    let c = convert_sigma_hq(
        &release(&refs),
        None,
        &Blocklist::parse("sigma_hq blocked\n").unwrap(),
    )
    .unwrap();
    assert_accepted(&c, 0);
    for (id, _, why) in cases {
        assert!(
            c.summary
                .dropped
                .get(why)
                .is_some_and(|ids| ids.iter().any(|actual| actual == id)),
            "{id}: {why} {:?}",
            c.summary.dropped
        );
    }
    for (why, path) in [
        (reason::MISSING_ATTRIBUTE, "no-id.yml"),
        (reason::FORMAT_ERROR, "bad-yaml.yml"),
        (reason::FORMAT_ERROR, "multi.yml"),
    ] {
        assert!(
            c.summary
                .dropped
                .get(why)
                .unwrap()
                .iter()
                .any(|id| id == path)
        );
    }
    let invalid_utf8 = archive(
        &[
            ("rules/bad.yml", &[0xff]),
            ("version.txt", VERSION_TEXT.as_bytes()),
        ],
        "",
        &[],
    );
    let c = convert_sigma_hq(&invalid_utf8, None, &Blocklist::default()).unwrap();
    assert_eq!(
        c.summary.dropped.get(reason::FORMAT_ERROR).unwrap(),
        &["bad.yml"]
    );
}

#[test]
fn attributes_tactics_techniques_prefilter_and_summary_json() {
    let mut rule = simple(
        "attrs",
        "{product: windows, category: process_creation}",
        "{CommandLine|contains: ['a*longest\\?literal?tail', 'equalLengthHere'], Image|re: 'ignored.*expression', ProcessId: 123}",
        "selection",
    );
    rule.push_str("author: author\nlevel: critical\nreferences: [https://example.invalid]\ntags: [attack.initial-access, attack.initial_access, attack.t1059, attack.t1059.001, other.tag]\n");
    let c = convert_one(&rule);
    assert_accepted(&c, 1);
    let r = &c.rules[0];
    assert_eq!(r.source(), Source::SigmaHq);
    assert_eq!(r.source_rule_id(), "attrs");
    assert_eq!(r.model(), Model::SigmaSignature);
    assert_eq!(r.title(), "synthetic attrs");
    assert_eq!(r.author(), Some("author"));
    assert_eq!(r.severity(), Some("critical"));
    assert_eq!(r.references(), ["https://example.invalid"]);
    assert_eq!(r.techniques(), ["T1059", "T1059.001"]);
    assert_eq!(r.tactics(), ["TA0001"]);
    assert_eq!(r.license(), Some("DRL-1.1"));
    assert_eq!(r.os(), Some(Os::Windows));
    assert_eq!(r.source_rule_rev(), None);
    assert_eq!(r.classification(), None);
    assert_eq!(r.prefilter(), Some(b"longest?literal".as_slice()));
    assert_eq!(c.summary.accepted.get(&Model::SigmaSignature), Some(&1));
    assert_eq!(c.summary.rulec_version, VERSION);
    assert_eq!(c.summary.header_values_partly_missing, 0);
    assert!(c.summary.db_size > 0);
    assert!(!c.summary.compile_time.is_zero());
    serde_json::to_string(&c.summary).unwrap();
}

#[test]
fn host_catalog_dynamic_names_and_fixed_columns() {
    for (kind, fixed, prefix, dynamic) in [
        (
            RawEventKind::WindowsEventLog,
            vec![
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
            ],
            "event_data.",
            "event_data.CommandLine",
        ),
        (RawEventKind::Journald, vec![], "fields.", "fields.MESSAGE"),
        (
            RawEventKind::Auditd,
            vec!["serial", "record_type"],
            "fields.",
            "fields.a0",
        ),
    ] {
        assert_eq!(catalog_fields(kind).unwrap(), fixed);
        assert_eq!(catalog_field_prefixes(kind), &[prefix]);
        for field in fixed.iter().copied().chain([dynamic]) {
            assert_eq!(field_status(kind, field), FieldStatus::Known);
        }
        for field in [prefix, "unknown"] {
            assert_eq!(field_status(kind, field), FieldStatus::NotInKind);
        }
    }
    for kind in [
        RawEventKind::Conn,
        RawEventKind::Dns,
        RawEventKind::Http,
        RawEventKind::Tls,
        RawEventKind::Ssh,
        RawEventKind::Log,
    ] {
        assert!(catalog_field_prefixes(kind).is_empty());
    }
    assert_eq!(
        field_status(RawEventKind::Log, "x"),
        FieldStatus::KindNotCataloged
    );
    assert_eq!(
        field_status(RawEventKind::ProcessCreate, "logon_id_full"),
        FieldStatus::Known
    );
    assert_eq!(
        field_status(RawEventKind::ProcessCreate, "endpoint"),
        FieldStatus::NotInKind
    );
}

#[test]
fn converted_network_rules_match_giganto_records() {
    let specs = [
        (
            "http",
            "{category: proxy}",
            "{c-uri|contains: /a, cs-host: example.com}",
        ),
        ("dns", "{category: dns}", "{query: evil.example.com}"),
        (
            "tls",
            "{product: zeek, service: ssl}",
            "{server_name: example.com}",
        ),
        ("conn", "{product: zeek, service: conn}", "{service: http}"),
    ];
    let texts: Vec<_> = specs
        .iter()
        .map(|(id, logsource, fields)| {
            (
                format!("rules/{id}.yml"),
                simple(id, logsource, fields, "selection"),
            )
        })
        .collect();
    let refs: Vec<_> = texts
        .iter()
        .map(|(p, t)| (p.as_str(), t.as_str()))
        .collect();
    let c = convert_sigma_hq(&release(&refs), None, &Blocklist::default()).unwrap();
    assert_accepted(&c, 4);
    let compiled = compile(c.rules).unwrap();
    let mut http = http();
    http.uri = "/a/unchanged%2fraw".into();
    http.host = "example.com".into();
    let dns = dns();
    let mut tls = tls();
    tls.server_name = "example.com".into();
    let conn = conn();
    let mut matcher = compiled.matcher();
    for (event, id) in [
        (&http as &dyn rulec::Event, "http"),
        (&dns, "dns"),
        (&tls, "tls"),
        (&conn, "conn"),
    ] {
        let matched = matcher.matches(event, &[]).unwrap();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].rule().source_rule_id(), id);
    }
}
fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
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

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn single_wrapper_allows_root_files_but_two_wrappers_are_not_selected() {
    let rule = simple("r", "{category: proxy}", "{c-uri: /x}", "selection");
    let files = [
        ("sigma-master/rules/a.yml", rule.as_bytes()),
        ("sigma-master/version.txt", VERSION_TEXT.as_bytes()),
        ("README", b"outside".as_slice()),
    ];
    let c = convert_sigma_hq(&archive(&files, "", &[]), None, &Blocklist::default()).unwrap();
    assert_accepted(&c, 1);
    let files = [
        ("one/rules/a.yml", rule.as_bytes()),
        ("two/README", b"outside".as_slice()),
    ];
    assert!(matches!(
        read_sigma_hq_version(&archive(&files, "", &[]), None),
        Err(SigmaHqError::NoRuleFiles)
    ));
}

#[test]
fn emerging_status_and_source_specific_blocklist() {
    let rule = simple("shared", "{category: proxy}", "{c-uri: /x}", "selection");
    let skipped = format!("{rule}status: unsupported\n");
    let paths = [
        (
            "rules-emerging-threats/deprecated/kept.yaml",
            rule.as_bytes(),
        ),
        ("rules-emerging-threats/skipped.yml", skipped.as_bytes()),
        ("rules/a.yml", rule.as_bytes()),
    ];
    let bytes = archive(&paths, SHA, &[Some(MTIME); 3]);
    let blocklist = Blocklist::parse("sigma_hq shared\n").unwrap();
    let c = convert_sigma_hq_emerging(&bytes, &blocklist).unwrap();
    assert_accepted(&c, 1);
    assert!(c.summary.dropped.is_empty());
    let blocked = Blocklist::parse("sigma_hq_emerging shared\n").unwrap();
    let c = convert_sigma_hq_emerging(&bytes, &blocked).unwrap();
    assert_accepted(&c, 0);
    assert_eq!(
        c.summary.dropped.get(reason::BLOCKLIST).unwrap(),
        &["shared"]
    );
    assert_eq!(
        c.summary.source_version.content_digest,
        content_digest([
            ("deprecated/kept.yaml", rule.as_bytes()),
            ("skipped.yml", skipped.as_bytes())
        ])
    );
}

#[test]
fn version_inspection_does_not_parse_malformed_rules() {
    let bytes = release(&[("rules/a.yml", "not: [valid")]);
    let version = read_sigma_hq_version(&bytes, None).unwrap();
    let conversion = convert_sigma_hq(&bytes, None, &Blocklist::default()).unwrap();
    assert_eq!(version, conversion.summary.source_version);
    assert_eq!(
        conversion
            .summary
            .dropped
            .get(reason::FORMAT_ERROR)
            .unwrap(),
        &["a.yml"]
    );
}

#[test]
fn blocklist_matches_only_source_ids_not_fallback_paths() {
    let missing = "title: missing id\n";
    let invalid = "id: [not, a, string]\ntitle: invalid id\n";
    let blocked = "id: blocked\n";
    let bytes = release(&[
        ("rules/missing.yml", missing),
        ("rules/invalid.yml", invalid),
        ("rules/blocked.yml", blocked),
    ]);
    let blocklist =
        Blocklist::parse("sigma_hq missing.yml\nsigma_hq invalid.yml\nsigma_hq blocked\n").unwrap();
    let conversion = convert_sigma_hq(&bytes, None, &blocklist).unwrap();
    assert_accepted(&conversion, 0);
    assert_eq!(
        conversion.summary.dropped.get(reason::BLOCKLIST).unwrap(),
        &["blocked"]
    );
    assert_eq!(
        conversion
            .summary
            .dropped
            .get(reason::MISSING_ATTRIBUTE)
            .unwrap(),
        &["missing.yml"]
    );
    assert_eq!(
        conversion
            .summary
            .dropped
            .get(reason::FORMAT_ERROR)
            .unwrap(),
        &["invalid.yml"]
    );
}

#[test]
fn added_conditions_rename_operator_names_used_as_pattern_targets() {
    for name in ["and", "or", "not", "of", "all", "1"] {
        for quantifier in ["1", "all"] {
            let rule = source_rule(
                "guarded",
                "{product: windows, service: security}",
                &format!(
                    "  {name}: {{CommandLine: needle}}\n  condition: {quantifier} of {name} or {quantifier} of {name}\n"
                ),
            );
            let converted = convert_one(&rule);
            assert_accepted(&converted, 1);
            let compiled = compile(converted.rules).unwrap();
            for channel in ["Security", "System"] {
                for command in ["needle", "other"] {
                    let event = TestEvent::new(RawEventKind::WindowsEventLog)
                        .os(OsFamily::Windows)
                        .text("channel", &[channel])
                        .text("event_data.CommandLine", &[command]);
                    assert_eq!(
                        !matched_ids(&compiled, &event, &[]).is_empty(),
                        channel == "Security" && command == "needle",
                        "{quantifier} of {name}, {channel}, {command}"
                    );
                }
            }
        }
    }
}

#[test]
fn excluded_members_do_not_need_a_supported_compression_method() {
    let rule = simple("r", "{category: proxy}", "{c-uri: /x}", "selection");
    for emerging in [false, true] {
        let path = if emerging {
            "rules-emerging-threats/a.yml"
        } else {
            "rules/a.yml"
        };
        let mut bytes = archive(
            &[
                ("outside.bin", b"not decoded"),
                (path, rule.as_bytes()),
                ("version.txt", VERSION_TEXT.as_bytes()),
            ],
            SHA,
            &[Some(MTIME); 3],
        );
        // Only the excluded first member uses BZip2, a disabled codec.
        // Its payload is deliberately opaque to both inspection APIs.
        for (signature, method_offset) in [(b"PK\x03\x04", 8), (b"PK\x01\x02", 10)] {
            let header = bytes.windows(4).position(|s| s == signature).unwrap();
            bytes[header + method_offset..header + method_offset + 2]
                .copy_from_slice(&12_u16.to_le_bytes());
        }
        let conversion = if emerging {
            convert_sigma_hq_emerging(&bytes, &Blocklist::default()).unwrap()
        } else {
            convert_sigma_hq(&bytes, None, &Blocklist::default()).unwrap()
        };
        assert_accepted(&conversion, 1);
        let version = if emerging {
            read_sigma_hq_emerging_version(&bytes).unwrap()
        } else {
            read_sigma_hq_version(&bytes, None).unwrap()
        };
        assert_eq!(version, conversion.summary.source_version);
    }
}

#[test]
fn utf8_and_cp437_member_names_preserve_rules_and_source_versions() {
    let rule = simple("r", "{category: proxy}", "{c-uri: /x}", "selection");
    for emerging in [false, true] {
        let directory = if emerging {
            "rules-emerging-threats"
        } else {
            "rules"
        };
        let make = |name: &str| {
            archive(
                &[
                    (name, rule.as_bytes()),
                    ("sigma/version.txt", VERSION_TEXT.as_bytes()),
                ],
                SHA,
                &[Some(MTIME); 2],
            )
        };
        let utf8 = make(&format!("sigma/{directory}/café.yml"));
        let mut cp437 = make(&format!("sigma/{directory}/cafe.yml"));
        // Replace the ASCII name in both headers with CP437 é (0x82).
        let offsets: Vec<_> = cp437
            .windows(b"/cafe.yml".len())
            .enumerate()
            .filter_map(|(offset, bytes)| (bytes == b"/cafe.yml").then_some(offset + 4))
            .collect();
        assert_eq!(offsets.len(), 2);
        for offset in offsets {
            *cp437.get_mut(offset).unwrap() = 0x82;
        }
        let convert = |bytes: &[u8]| {
            if emerging {
                convert_sigma_hq_emerging(bytes, &Blocklist::default()).unwrap()
            } else {
                convert_sigma_hq(bytes, None, &Blocklist::default()).unwrap()
            }
        };
        let expected = convert(&utf8);
        let actual = convert(&cp437);
        assert_accepted(&actual, 1);
        assert_eq!(actual.rules, expected.rules);
        assert_eq!(
            actual.summary.source_version,
            expected.summary.source_version
        );
        let version = if emerging {
            read_sigma_hq_emerging_version(&cp437).unwrap()
        } else {
            read_sigma_hq_version(&cp437, None).unwrap()
        };
        assert_eq!(version, actual.summary.source_version);
        assert_eq!(
            version.content_digest,
            content_digest([("café.yml", rule.as_bytes())])
        );
    }
}

#[test]
fn selected_members_with_bad_crc_fail_both_apis_as_invalid_zip() {
    for (path, emerging) in [
        ("rules/a.yml", false),
        ("version.txt", false),
        ("rules-emerging-threats/a.yml", true),
    ] {
        let mut bytes = archive(&[(path, b"corrupt member")], SHA, &[Some(MTIME)]);
        // Keep the local and central headers consistent, but make their CRC
        // disagree with the decoded payload to exercise the member read error.
        for (signature, crc_offset) in [(b"PK\x03\x04", 14), (b"PK\x01\x02", 16)] {
            let header = bytes.windows(4).position(|s| s == signature).unwrap();
            *bytes.get_mut(header + crc_offset).unwrap() ^= 1;
        }
        let message = same_archive_error(&bytes, emerging);
        assert!(message.starts_with("cannot read the zip:"), "{message}");
        assert!(message.contains(&format!("reading {path}:")), "{message}");
    }
}
