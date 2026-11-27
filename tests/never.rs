//! The explicit impossible field condition, independent of conversion.

mod common;

use common::{TestEvent, matched_ids, rule_text};
use rulec::{ReadError, Rule, RuleBundle, Source, compile, unknown_fields};

#[test]
fn never_is_false_has_no_fields_and_survives_bundling() {
    let positive = Rule::from_yaml(&rule_text(
        "never",
        "    sel:\n        f|not_a_modifier: !never ''\n    condition: sel\n",
    ))
    .unwrap();
    assert!(unknown_fields(&positive).unwrap().is_empty());
    let negative = Rule::from_yaml(&rule_text(
        "not",
        "    sel:\n        f: !never ''\n    condition: not sel\n",
    ))
    .unwrap();
    let impossible_and = Rule::from_yaml(&rule_text("and", "    sel:\n        f: !never ''\n        orig_addr|cidr: 192.0.2.0/24\n    condition: sel\n")).unwrap();
    let list = Rule::from_yaml(&rule_text(
        "list",
        "    sel:\n        - f: !never ''\n        - uri: yes\n    condition: sel\n",
    ))
    .unwrap();
    let rules = vec![positive, negative, impossible_and, list];
    let bundle = RuleBundle::new(Source::SigmaHq, rules.clone()).unwrap();
    assert_eq!(
        RuleBundle::from_bytes(&bundle.to_bytes().unwrap())
            .unwrap()
            .into_rules(),
        rules
    );
    let compiled = compile(rules).unwrap();
    assert_eq!(
        compiled
            .stats()
            .always_check_for(Source::SigmaHq)
            .iter()
            .map(|k| k.count)
            .sum::<usize>(),
        1
    );
    let event = TestEvent::http()
        .text("uri", &["yes"])
        .text("f", &[""])
        .addr("orig_addr", "192.0.2.1");
    assert_eq!(matched_ids(&compiled, &event, &[]), ["not", "list"]);
    let mut matcher = compiled.matcher();
    let matches = matcher.matches(&event, &[]).unwrap();
    assert!(matches.iter().all(|m| !m.fields().contains(&"f")));
    assert!(
        matches
            .iter()
            .find(|m| m.rule().source_rule_id() == "not")
            .unwrap()
            .fields()
            .is_empty()
    );
}

#[test]
fn never_requires_empty_string_in_a_direct_field_value() {
    for detection in [
        "    sel: {f: !never 'x'}\n    condition: sel\n",
        "    sel: {f: [!never '']}\n    condition: sel\n",
        "    sel: !never ''\n    condition: sel\n",
        "    sel: [!never '']\n    condition: sel\n",
        "    sel: {f: x}\n    condition: !never ''\n",
    ] {
        assert!(
            matches!(
                Rule::from_yaml(&rule_text("r", detection)),
                Err(ReadError::Format(_))
            ),
            "{detection}"
        );
    }
    let invalid = format!(
        "{}extra: !never ''\n",
        rule_text("r", "    sel: {uri: x}\n    condition: sel\n")
    );
    assert!(matches!(
        Rule::from_yaml(&invalid),
        Err(ReadError::Format(_))
    ));
}
