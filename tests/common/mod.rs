//! Helpers shared by the integration tests: synthetic events and
//! hand-written rules.

#![allow(dead_code)] // Each test crate uses a different part of the helpers.

use std::{borrow::Cow, collections::HashMap, net::IpAddr};

use giganto_client::{RawEventKind, ingest::endpoint::OsFamily};
use rulec::{Cidr, CompiledRules, Event, FieldValue, Rule, compile};

/// A synthetic raw event.
#[derive(Clone, Debug)]
pub struct TestEvent {
    kind: RawEventKind,
    fields: HashMap<String, Vec<FieldValue<'static>>>,
    os: Option<OsFamily>,
}

impl TestEvent {
    pub fn new(kind: RawEventKind) -> Self {
        Self {
            kind,
            fields: HashMap::new(),
            os: None,
        }
    }

    pub fn http() -> Self {
        Self::new(RawEventKind::Http)
    }

    /// Adds text values to a field.
    pub fn text(mut self, name: &str, values: &[&str]) -> Self {
        let entry = self.fields.entry(name.to_string()).or_default();
        for v in values {
            entry.push(FieldValue::Bytes(Cow::Owned(v.as_bytes().to_vec())));
        }
        self
    }

    /// Adds a byte value to a field.
    pub fn bytes(mut self, name: &str, value: &[u8]) -> Self {
        self.fields
            .entry(name.to_string())
            .or_default()
            .push(FieldValue::Bytes(Cow::Owned(value.to_vec())));
        self
    }

    /// Adds an address value to a field.
    pub fn addr(mut self, name: &str, value: &str) -> Self {
        let addr: IpAddr = value.parse().unwrap();
        self.fields
            .entry(name.to_string())
            .or_default()
            .push(FieldValue::Addr(addr));
        self
    }

    /// Adds an integer value to a field.
    pub fn int(mut self, name: &str, value: i64) -> Self {
        self.fields
            .entry(name.to_string())
            .or_default()
            .push(FieldValue::Int(value));
        self
    }

    pub fn os(mut self, os: OsFamily) -> Self {
        self.os = Some(os);
        self
    }
}

impl Event for TestEvent {
    fn kind(&self) -> RawEventKind {
        self.kind
    }

    fn field(&self, name: &str) -> Vec<FieldValue<'_>> {
        self.fields.get(name).cloned().unwrap_or_default()
    }

    fn os_family(&self) -> Option<&OsFamily> {
        self.os.as_ref()
    }
}

/// Returns the text of a SigmaHQ rule with the given id, event kind, extra
/// top-level lines and detection (indented by four spaces).
pub fn rule_text_with(id: &str, kind: &str, extra: &str, detection: &str) -> String {
    format!(
        "title: rule {id}\nsource: sigma_hq\nsource_rule_id: '{id}'\nmodel: SigmaSignature\n\
         {extra}logsource:\n    category: {kind}\ndetection:\n{detection}"
    )
}

/// Returns the text of an HTTP rule with the given id and detection.
pub fn rule_text(id: &str, detection: &str) -> String {
    rule_text_with(id, "http", "", detection)
}

/// Reads one HTTP rule whose detection is `selection` and the given body
/// of `selection`, indented by eight spaces.
pub fn selection_rule(id: &str, selection: &str) -> Rule {
    let detection = format!("    selection:\n{selection}    condition: selection\n");
    Rule::from_yaml(&rule_text(id, &detection))
        .unwrap_or_else(|e| panic!("rule {id} does not read: {e}"))
}

/// Compiles rules from their texts, all of which must read.
pub fn compile_texts(texts: &[String]) -> CompiledRules {
    let rules: Vec<Rule> = texts
        .iter()
        .map(|t| Rule::from_yaml(t).unwrap_or_else(|e| panic!("{e}\n{t}")))
        .collect();
    compile(rules).unwrap()
}

/// Returns the ids of the rules `event` matches.
pub fn matched_ids(compiled: &CompiledRules, event: &TestEvent, home_net: &[Cidr]) -> Vec<String> {
    compiled
        .matcher()
        .matches(event, home_net)
        .unwrap()
        .iter()
        .map(|m| m.rule().source_rule_id().to_string())
        .collect()
}

/// Returns whether a rule with the given `selection` body matches `event`.
pub fn selection_matches(selection: &str, event: &TestEvent) -> bool {
    let compiled = compile(vec![selection_rule("r", selection)]).unwrap();
    assert!(
        compiled.stats().excluded().is_empty(),
        "the rule was left out: {:?}",
        compiled.stats().excluded()
    );
    !matched_ids(&compiled, event, &[]).is_empty()
}
