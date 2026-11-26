//! Rule bundles, the version constant, and what conversions record.

mod common;

use std::{cmp::Ordering, time::Duration};

use common::{rule_text, rule_text_with};
use giganto_client::RawEventKind;
use jiff::civil::date;
use rulec::{
    Blocklist, BundleError, ConversionSummary, KindCount, Model, OrderKey, Rule, RuleBundle,
    Source, SourceVersion, VERSION, compile, content_digest, reason,
};

fn sample_rules() -> Vec<Rule> {
    vec![
        Rule::from_yaml(&rule_text_with(
            "a",
            "http",
            "author: someone\ntechniques: [T1190]\nos: linux\nreferences: [https://example.com]\n",
            "    sel:\n        uri|contains|all:\n            - '/x'\n            - !bytes '\\x00\\xff'\n        resp_addr|expand|cidr: '%home_net%'\n    condition: sel\n",
        ))
        .unwrap(),
        Rule::from_yaml(&rule_text(
            "b",
            "    sel:\n        uri|re|i: '^/a.+'\n        status|gt: 3\n    filter:\n        ua|windash|base64offset|contains: '-x'\n    condition: sel and not filter\n",
        ))
        .unwrap(),
    ]
}

fn source_version() -> SourceVersion {
    SourceVersion {
        version: "r1234".to_string(),
        release_name: Some("November".to_string()),
        order_key: OrderKey {
            date: date(2026, 11, 27),
            number: Some(3),
        },
        content_digest: content_digest([("a", "b")]),
    }
}

/// Returns the bytes of a bundle with its version string replaced.
fn with_version(bytes: &[u8], version: &str) -> Vec<u8> {
    let len = usize::from(u16::from_le_bytes([bytes[8], bytes[9]]));
    let mut out = bytes[..8].to_vec();
    out.extend_from_slice(&u16::try_from(version.len()).unwrap().to_le_bytes());
    out.extend_from_slice(version.as_bytes());
    out.extend_from_slice(&bytes[10 + len..]);
    out
}

#[test]
fn version_is_cargos() {
    let manifest = include_str!("../Cargo.toml");
    let version = manifest
        .lines()
        .find_map(|line| line.strip_prefix("version = \""))
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap();
    assert_eq!(VERSION, version);
}

#[test]
fn bundle_round_trip() {
    let rules = sample_rules();
    let bundle = RuleBundle::new(Source::SigmaHq, rules.clone()).unwrap();
    let bytes = bundle.to_bytes().unwrap();
    assert!(bytes.starts_with(b"RULECBDL"));
    assert_eq!(&bytes[10..10 + VERSION.len()], VERSION.as_bytes());
    let read = RuleBundle::from_bytes(&bytes).unwrap();
    assert_eq!(read, bundle);
    assert_eq!(read.source(), Source::SigmaHq);
    assert_eq!(read.into_rules(), rules);

    let empty = RuleBundle::new(Source::EtOpen, Vec::new()).unwrap();
    assert_eq!(
        RuleBundle::from_bytes(&empty.to_bytes().unwrap()).unwrap(),
        empty
    );
}

#[test]
fn bundle_of_another_version_is_rejected() {
    let bytes = RuleBundle::new(Source::SigmaHq, sample_rules())
        .unwrap()
        .to_bytes()
        .unwrap();
    let other = with_version(&bytes, "0.0.1-other");
    match RuleBundle::from_bytes(&other) {
        Err(e @ BundleError::VersionMismatch { .. }) => {
            let message = e.to_string();
            assert!(message.contains("0.0.1-other"), "{message}");
            assert!(message.contains(VERSION), "{message}");
        }
        other => panic!("expected a version mismatch, got {other:?}"),
    }
}

#[test]
fn bundle_source_must_match() {
    assert!(matches!(
        RuleBundle::new(Source::EtOpen, sample_rules()),
        Err(BundleError::SourceMismatch { .. })
    ));
}

#[test]
fn broken_bundles_are_errors() {
    let bundle = RuleBundle::new(Source::SigmaHq, sample_rules()).unwrap();
    let bytes = bundle.to_bytes().unwrap();
    for len in 0..bytes.len() {
        assert!(
            RuleBundle::from_bytes(&bytes[..len]).is_err(),
            "cut at {len}"
        );
    }
    let header = 10 + VERSION.len();
    // A flipped byte is an error, except in the gzip header fields the
    // checksum does not cover (its time stamp, say), where the rules read
    // the same.
    let mut errors = 0;
    for i in header..bytes.len() {
        let mut broken = bytes.clone();
        broken[i] ^= 0x5a;
        match RuleBundle::from_bytes(&broken) {
            Err(_) => errors += 1,
            Ok(read) => assert_eq!(read, bundle, "flipped byte {i}"),
        }
    }
    assert!(errors > bytes.len() - header - 10);
    assert!(matches!(
        RuleBundle::from_bytes(b"not a bundle at all"),
        Err(BundleError::NotABundle)
    ));
    let mut garbage = bytes[..header].to_vec();
    garbage.extend_from_slice(&[0xff; 64]);
    assert!(RuleBundle::from_bytes(&garbage).is_err());
}

#[test]
fn content_digest_is_fixed_and_order_free() {
    let entries = [
        ("rules/b.rules", "beta\n"),
        ("rules/a.rules", "alpha\n"),
        ("README", ""),
    ];
    let expected = "ba708a5ed863fc60d4dca819028e7420a86a8ec8c6f19954aafe192d4ab34ea1";
    assert_eq!(content_digest(entries), expected);
    let mut reversed = entries;
    reversed.reverse();
    assert_eq!(content_digest(reversed), expected);
    assert_ne!(
        content_digest([
            ("rules/b.rules", "beta\n"),
            ("rules/a.rules", "alpha!\n"),
            ("README", "")
        ]),
        expected
    );
    assert_ne!(
        content_digest([
            ("rules/c.rules", "beta\n"),
            ("rules/a.rules", "alpha\n"),
            ("README", "")
        ]),
        expected
    );
    assert_eq!(
        content_digest([(b"p".as_slice(), b"\xff".as_slice())]),
        content_digest([(b"p".to_vec(), vec![0xff_u8])])
    );
}

#[test]
fn order_keys_compare() {
    let key = |d: i8, number: Option<u64>| OrderKey {
        date: date(2026, 11, d),
        number,
    };
    assert_eq!(key(1, None).compare(&key(2, None)), Ordering::Less);
    assert_eq!(key(3, Some(1)).compare(&key(2, Some(9))), Ordering::Greater);
    assert_eq!(key(2, Some(1)).compare(&key(2, Some(2))), Ordering::Less);
    assert_eq!(key(2, Some(2)).compare(&key(2, Some(1))), Ordering::Greater);
    assert_eq!(key(2, Some(2)).compare(&key(2, Some(2))), Ordering::Equal);
    assert_eq!(key(2, None).compare(&key(2, Some(1))), Ordering::Equal);
    assert_eq!(key(2, None).compare(&key(2, Some(2))), Ordering::Equal);
    assert_eq!(key(2, Some(1)).compare(&key(2, None)), Ordering::Equal);
    assert_eq!(key(2, None).compare(&key(2, None)), Ordering::Equal);
    assert_ne!(key(2, None), key(2, Some(1)));
}

#[test]
fn blocklist_drops_rules() {
    assert!(Blocklist::builtin().unwrap().is_empty());
    let list = Blocklist::parse("# test list\n\nsigma_hq b\net_open 2001\n").unwrap();
    assert_eq!(list.len(), 2);
    assert!(list.contains(Source::SigmaHq, "b"));
    assert!(!list.contains(Source::SigmaHqEmerging, "b"));
    let mut summary = ConversionSummary::new(Source::SigmaHq, source_version());
    let kept = list.apply(sample_rules(), &mut summary);
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].source_rule_id(), "a");
    assert_eq!(summary.dropped_count(reason::BLOCKLIST), 1);
    assert_eq!(summary.dropped[reason::BLOCKLIST], vec!["b".to_string()]);

    assert!(Blocklist::parse("sigma_hq\n").is_err());
    assert!(Blocklist::parse("nowhere 1\n").is_err());
    assert!(Blocklist::parse("et_open 1 2\n").is_err());
}

#[test]
fn summary_takes_compile_stats() {
    let mut rules = sample_rules();
    rules.push(
        Rule::from_yaml(&rule_text(
            "bad",
            "    sel:\n        uri|re: '(a)\\1'\n    condition: sel\n",
        ))
        .unwrap(),
    );
    rules.push(
        Rule::from_yaml(&rule_text(
            "port",
            "    sel:\n        resp_port: 2\n    condition: sel\n",
        ))
        .unwrap(),
    );
    rules.push(
        Rule::from_yaml(
            &rule_text("et", "    sel:\n        resp_port: 1\n    condition: sel\n")
                .replace("source: sigma_hq", "source: et_open")
                .replace("model: SigmaSignature", "model: EtSignature"),
        )
        .unwrap(),
    );
    let compiled = compile(rules).unwrap();
    let mut summary = ConversionSummary::new(Source::SigmaHq, source_version());
    summary.apply_compile_stats(compiled.stats());
    assert_eq!(summary.rulec_version, VERSION);
    assert_eq!(
        summary.accepted.into_iter().collect::<Vec<_>>(),
        vec![(Model::SigmaSignature, 3)]
    );
    assert_eq!(
        summary.dropped[reason::UNSUPPORTED_REGEX],
        vec!["bad".to_string()]
    );
    // Only "port" is always checked among the SigmaHQ rules; the ET Open
    // rule is not counted here.
    assert_eq!(
        summary.always_check,
        vec![KindCount {
            kind: RawEventKind::Http,
            count: 1
        }]
    );
    assert_eq!(compiled.stats().always_check()[0].count, 2);
    assert_eq!(summary.db_size, compiled.stats().db_size());
    assert!(summary.db_size > 0);
    assert_eq!(summary.compile_time, compiled.stats().compile_time());
}

#[test]
fn records_round_trip_through_json() {
    let version = source_version();
    let json = serde_json::to_string(&version).unwrap();
    assert_eq!(
        serde_json::from_str::<SourceVersion>(&json).unwrap(),
        version
    );

    let key = version.order_key;
    let json = serde_json::to_string(&key).unwrap();
    assert_eq!(json, r#"{"date":"2026-11-27","number":3}"#);
    assert_eq!(serde_json::from_str::<OrderKey>(&json).unwrap(), key);

    let mut summary = ConversionSummary::new(Source::SigmaHqEmerging, version);
    summary.accepted.insert(Model::SigmaSignature, 7);
    summary.record_dropped(reason::BLOCKLIST, "x");
    summary.record_dropped("unmapped_logsource", "y");
    summary.record_dropped("unmapped_logsource", "z");
    summary.partly_never_true = 3;
    summary.partly_never_true_under_not = 1;
    summary.header_values_partly_missing = 2;
    summary.unmapped_fields.insert("Hashes".to_string(), 4);
    summary.always_check = vec![KindCount {
        kind: RawEventKind::Dns,
        count: 5,
    }];
    summary.compile_time = Duration::from_millis(1234);
    summary.db_size = 4096;
    let json = serde_json::to_string(&summary).unwrap();
    assert_eq!(
        serde_json::from_str::<ConversionSummary>(&json).unwrap(),
        summary
    );
}
