//! Reading rules: attributes, rejections and their kinds, byte values and
//! the `%home_net%` notation.

mod common;

use common::{TestEvent, rule_text, rule_text_with, selection_matches};
use giganto_client::RawEventKind;
use rulec::{Model, Os, ReadError, Rule, Source, read_rules, reason};

fn read_selection(selection: &str) -> Result<Rule, ReadError> {
    Rule::from_yaml(&rule_text(
        "r",
        &format!("    selection:\n{selection}    condition: selection\n"),
    ))
}

fn assert_format_error(result: Result<Rule, ReadError>) {
    match result {
        Err(ReadError::Format(_)) => {}
        other => panic!("expected a format error, got {other:?}"),
    }
}

const FULL_RULE: &str = "\
title: Full rule
source: et_open
source_rule_id: 2001219
source_rule_rev: 20
model: EtPolicySignature
license: MIT
severity: '2'
classification: policy-violation
techniques: [T1059, T1059.001]
tactics: [TA0002]
author: someone
os: windows
prefilter: !bytes 'ab\\x00'
references:
    - https://example.com/a
description: ignored
logsource:
    category: process_create
detection:
    selection:
        image|endswith: '\\cmd.exe'
    condition: selection
";

#[test]
fn reads_every_attribute() {
    let rule = Rule::from_yaml(FULL_RULE).unwrap();
    assert_eq!(rule.title(), "Full rule");
    assert_eq!(rule.source(), Source::EtOpen);
    assert_eq!(rule.source_rule_id(), "2001219");
    assert_eq!(rule.source_rule_rev(), Some(20));
    assert_eq!(rule.model(), Model::EtPolicySignature);
    assert_eq!(rule.license(), Some("MIT"));
    assert_eq!(rule.severity(), Some("2"));
    assert_eq!(rule.classification(), Some("policy-violation"));
    assert_eq!(rule.techniques(), ["T1059", "T1059.001"]);
    assert_eq!(rule.tactics(), ["TA0002"]);
    assert_eq!(rule.author(), Some("someone"));
    assert_eq!(rule.os(), Some(Os::Windows));
    assert_eq!(rule.prefilter(), Some(&b"ab\x00"[..]));
    assert_eq!(rule.references(), ["https://example.com/a"]);
    assert_eq!(rule.kind(), RawEventKind::ProcessCreate);
}

#[test]
fn rejects_placeholders_other_than_home_net() {
    let result = read_selection("        user|expand: '%Administrators%'\n");
    assert_eq!(
        result,
        Err(ReadError::PlaceholderValueMissing(
            "Administrators".to_string()
        ))
    );
    assert_eq!(
        result.unwrap_err().reason(),
        reason::PLACEHOLDER_VALUE_MISSING
    );
    assert_eq!(
        read_selection("        resp_addr|expand|cidr: '%servers%'\n"),
        Err(ReadError::PlaceholderValueMissing("servers".to_string()))
    );
    // Without `expand` a percent sign is a plain character.
    assert!(read_selection("        user: '%Administrators%'\n").is_ok());
    // The placeholder decides the reason, whatever else is wrong with the
    // rule, wherever it stands in `detection`.
    assert_eq!(
        Rule::from_yaml(&rule_text(
            "r",
            "    a:\n        uri|bogus: x\n    b:\n        - user|expand: '%Domain%'\n    \
             condition: a or b\n",
        )),
        Err(ReadError::PlaceholderValueMissing("Domain".to_string()))
    );
}

#[test]
fn home_net_notation() {
    assert!(read_selection("        resp_addr|expand|cidr: '%home_net%'\n").is_ok());
    assert!(
        read_selection(
            "        resp_addr|expand|cidr:\n            - '%home_net%'\n            - 192.0.2.0/24\n"
        )
        .is_ok()
    );
    assert_format_error(read_selection(
        "        resp_addr|cidr|expand: '%home_net%'\n",
    ));
    assert_format_error(read_selection("        resp_addr|expand: '%home_net%'\n"));
    assert_format_error(read_selection("        resp_addr|cidr: '%home_net%'\n"));
    assert_format_error(read_selection(
        "        resp_addr|expand|cidr|neq: '%home_net%'\n",
    ));
    assert_format_error(read_selection(
        "        resp_addr|expand|cidr: 'x%home_net%'\n",
    ));
}

#[test]
fn rejects_correlation_rules() {
    let text = "\
title: correlation
source: sigma_hq
source_rule_id: c1
model: SigmaSignature
correlation:
    type: event_count
    rules: [a]
    timespan: 1h
    condition:
        gte: 10
";
    let result = Rule::from_yaml(text);
    assert_eq!(result, Err(ReadError::CorrelationRule));
    assert_eq!(result.unwrap_err().reason(), reason::CORRELATION_RULE);
}

#[test]
fn rejects_missing_attributes_without_blocking_others() {
    let good = rule_text("good", "    sel:\n        uri: a\n    condition: sel\n");
    let mut texts = vec![good.clone()];
    for key in ["source", "source_rule_id", "model", "title"] {
        let text: String = good
            .lines()
            .filter(|line| !line.starts_with(&format!("{key}:")))
            .map(|line| format!("{line}\n"))
            .collect();
        texts.push(text);
    }
    texts.push(good.clone());
    let results = read_rules(texts.iter().map(String::as_str));
    assert_eq!(results.len(), 6);
    assert!(results[0].is_ok());
    for (result, key) in results[1..5]
        .iter()
        .zip(["source", "source_rule_id", "model", "title"])
    {
        assert_eq!(result, &Err(ReadError::MissingAttribute(key.to_string())));
    }
    assert!(results[5].is_ok());
}

#[test]
fn rejects_unsupported_modifiers() {
    for name in ["minute", "hour", "day", "week", "month", "year", "unknown"] {
        let result = read_selection(&format!("        time|{name}: 3\n"));
        assert_eq!(
            result,
            Err(ReadError::UnsupportedModifier(name.to_string()))
        );
        assert_eq!(result.unwrap_err().reason(), reason::UNSUPPORTED_MODIFIER);
    }
}

#[test]
fn rejects_format_errors() {
    // Keyword searches.
    assert_format_error(Rule::from_yaml(&rule_text(
        "r",
        "    keywords:\n        - 'evil'\n    condition: keywords\n",
    )));
    assert_format_error(read_selection(
        "        '|all':\n            - a\n            - b\n",
    ));
    // A position modifier before a Base64 encoding hands it a wildcard.
    for key in [
        "body|contains|base64",
        "body|startswith|base64",
        "body|endswith|base64offset",
    ] {
        assert_format_error(read_selection(&format!("        {key}: 'abc'\n")));
    }
    assert!(read_selection("        body|base64|contains: 'abc'\n").is_ok());
    // `logsource` with `product` or `service`.
    for extra in ["    product: windows\n", "    service: sshd\n"] {
        let text = rule_text("r", "    sel:\n        uri: a\n    condition: sel\n").replace(
            "    category: http\n",
            &format!("    category: http\n{extra}"),
        );
        assert_format_error(Rule::from_yaml(&text));
    }
    // An unknown event kind.
    assert_format_error(Rule::from_yaml(&rule_text_with(
        "r",
        "process_creation",
        "",
        "    sel:\n        uri: a\n    condition: sel\n",
    )));
    // Model and source that do not pair, and unknown names.
    let base = rule_text("r", "    sel:\n        uri: a\n    condition: sel\n");
    for (from, to) in [
        ("model: SigmaSignature", "model: EtSignature"),
        ("source: sigma_hq", "source: et_open"),
        ("source: sigma_hq", "source: sigmahq"),
        ("model: SigmaSignature", "model: Sigma"),
    ] {
        assert_format_error(Rule::from_yaml(&base.replace(from, to)));
    }
    // Malformed `techniques`, `tactics` and `os`.
    for extra in [
        "techniques: [T59]\n",
        "techniques: [T1059.1]\n",
        "techniques: T1059\n",
        "tactics: [T0001]\n",
        "os: bsd\n",
    ] {
        assert_format_error(Rule::from_yaml(&rule_text_with(
            "r",
            "http",
            extra,
            "    sel:\n        uri: a\n    condition: sel\n",
        )));
    }
    // Bad YAML and bad Sigma syntax.
    assert_format_error(Rule::from_yaml("title: [unclosed\n"));
    for selection in [
        "        uri|i: 'a'\n",
        "        uri|contains|contains: 'a'\n",
        "        uri|contains|startswith: 'a'\n",
        "        uri|all: 'a'\n",
        "        uri|re|contains: 'a'\n",
        "        uri|gt: 'a'\n",
        "        uri|cidr: 'a'\n",
        "        uri|exists: 'yes'\n",
        "        uri|neq|all:\n            - a\n            - b\n",
        "        uri|base64|contains: 'a*b'\n",
        "        uri|contains: null\n",
        "        uri:\n            - a\n            - null\n",
        "        uri: []\n",
        "        uri|utf16le: !bytes 'a'\n",
        "        uri|windash: !bytes 'a-b'\n",
    ] {
        assert_format_error(read_selection(selection));
    }
    assert_format_error(Rule::from_yaml(&rule_text(
        "r",
        "    sel:\n        uri: a\n    condition: sel and other\n",
    )));
    assert_format_error(Rule::from_yaml(&rule_text(
        "r",
        "    sel:\n        uri: a\n",
    )));
}

#[test]
fn rejects_deeply_nested_yaml() {
    // A list nested far deeper than any rule needs, under a key reading
    // ignores: rejected as malformed rather than overflowing the stack.
    let deep = format!("ignored:\n  {}x\n", "- ".repeat(100_000));
    let text = rule_text_with(
        "deep",
        "http",
        &deep,
        "    sel:\n        uri: a\n    condition: sel\n",
    );
    assert_format_error(Rule::from_yaml(&text));

    // Nesting a rule actually uses still reads.
    let shallow = format!("ignored:\n  {}x\n", "- ".repeat(32));
    let text = rule_text_with(
        "shallow",
        "http",
        &shallow,
        "    sel:\n        uri: a\n    condition: sel\n",
    );
    assert!(Rule::from_yaml(&text).is_ok());
}

#[test]
fn reads_non_utf8_bytes() {
    let sel = "        payload|contains: !bytes '\\xff\\xfeA'\n";
    let rule = read_selection(sel).unwrap();
    assert_eq!(rule.source_rule_id(), "r");
    assert!(selection_matches(
        sel,
        &TestEvent::http().bytes("payload", b"\x00\xff\xfeA\x80")
    ));
    assert!(selection_matches(
        sel,
        &TestEvent::http().bytes("payload", b"\xff\xfea")
    ));
    assert!(!selection_matches(
        sel,
        &TestEvent::http().bytes("payload", b"\xff\xfd")
    ));
    // A `!bytes` value is literal: `*` is a plain byte.
    let star = "        payload: !bytes 'a*'\n";
    assert!(selection_matches(
        star,
        &TestEvent::http().bytes("payload", b"a*")
    ));
    assert!(!selection_matches(
        star,
        &TestEvent::http().bytes("payload", b"ab")
    ));
}

#[test]
fn nul_bytes_compile_and_match() {
    let sel = "        payload|contains: !bytes 'a\\x00b'\n";
    assert!(selection_matches(
        sel,
        &TestEvent::http().bytes("payload", b"xa\x00by")
    ));
    assert!(!selection_matches(
        sel,
        &TestEvent::http().bytes("payload", b"xa by")
    ));
    let exact = "        payload: !bytes '\\x00'\n";
    assert!(selection_matches(
        exact,
        &TestEvent::http().bytes("payload", b"\x00")
    ));
    // A NUL in a regular expression is the character it stands for.
    let re = "        payload|re: \"a\\0b\"\n";
    assert!(selection_matches(
        re,
        &TestEvent::http().bytes("payload", b"a\x00b")
    ));
}
