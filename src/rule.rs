//! Clumit Sigma rules and how they are read.

use std::str::FromStr;

use giganto_client::RawEventKind;
use serde::{Deserialize, Serialize};

use crate::{
    attrs::{Model, Os, Source},
    detection,
    expr::Expr,
    reason,
    yaml::{self, Node},
};

/// A Clumit Sigma rule: its attributes, the kind of raw event it applies
/// to, and its detection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    source: Source,
    source_rule_id: String,
    model: Model,
    title: String,
    source_rule_rev: Option<u64>,
    license: Option<String>,
    severity: Option<String>,
    classification: Option<String>,
    techniques: Vec<String>,
    tactics: Vec<String>,
    author: Option<String>,
    os: Option<Os>,
    prefilter: Option<Vec<u8>>,
    references: Vec<String>,
    kind: RawEventKind,
    pub(crate) detection: Expr,
    /// Every field name the search identifiers of the detection use,
    /// sorted and without repeats, including those of identifiers the
    /// condition leaves out of [`Rule::detection`].
    pub(crate) fields: Vec<String>,
}

/// Why a rule could not be read.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReadError {
    /// The rule uses a placeholder other than `%home_net%`, which has no
    /// value.
    #[error("no value for placeholder `%{0}%`")]
    PlaceholderValueMissing(String),
    /// The rule is a Sigma correlation rule.
    #[error("correlation rules are not supported")]
    CorrelationRule,
    /// A required attribute is missing; this holds its key.
    #[error("required attribute `{0}` is missing")]
    MissingAttribute(String),
    /// The rule uses a modifier Clumit Sigma does not accept; this holds
    /// its name.
    #[error("modifier `{0}` is not supported")]
    UnsupportedModifier(String),
    /// The rule is malformed: bad YAML, a Sigma syntax error, or a bad
    /// attribute value.
    #[error("{0}")]
    Format(String),
}

impl ReadError {
    /// Returns the name of the reason a conversion summary records a rule
    /// rejected for this error under.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::PlaceholderValueMissing(_) => reason::PLACEHOLDER_VALUE_MISSING,
            Self::CorrelationRule => reason::CORRELATION_RULE,
            Self::MissingAttribute(_) => reason::MISSING_ATTRIBUTE,
            Self::UnsupportedModifier(_) => reason::UNSUPPORTED_MODIFIER,
            Self::Format(_) => reason::FORMAT_ERROR,
        }
    }
}

fn attr_err(key: &str, message: impl std::fmt::Display) -> ReadError {
    ReadError::Format(format!("attribute `{key}`: {message}"))
}

/// Reads each text as one Clumit Sigma rule.
///
/// Each text gives its own result; a text that fails to read does not keep
/// the others from being read.
#[must_use]
pub fn read_rules<'a, I>(texts: I) -> Vec<Result<Rule, ReadError>>
where
    I: IntoIterator<Item = &'a str>,
{
    texts.into_iter().map(Rule::from_yaml).collect()
}

impl Rule {
    /// Reads one rule from its YAML text, which must hold one document.
    ///
    /// # Errors
    ///
    /// Returns the reason the rule cannot be read: see [`ReadError`].
    pub fn from_yaml(text: &str) -> Result<Self, ReadError> {
        let node = yaml::load(text).map_err(|e| ReadError::Format(format!("YAML: {e}")))?;
        Self::from_node(node)
    }

    pub(crate) fn from_node(node: Node) -> Result<Self, ReadError> {
        validate_never(&node, NeverPosition::Root)?;
        let Node::Map(entries) = node else {
            return Err(ReadError::Format(
                "the rule is not a YAML mapping".to_string(),
            ));
        };
        let get = |key: &str| {
            entries
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v)
                .filter(|v| !matches!(v, Node::Null))
        };
        if entries.iter().any(|(k, _)| k == "correlation") {
            return Err(ReadError::CorrelationRule);
        }

        let required = |key: &str| get(key).ok_or_else(|| ReadError::MissingAttribute(key.into()));
        let source_node = required("source")?;
        let source_rule_id_node = required("source_rule_id")?;
        let model_node = required("model")?;
        let title_node = required("title")?;

        let source: Source = text_attr("source", source_node)?
            .parse()
            .map_err(|e| attr_err("source", e))?;
        let model: Model = text_attr("model", model_node)?
            .parse()
            .map_err(|e| attr_err("model", e))?;
        if !model.pairs_with(source) {
            return Err(attr_err(
                "model",
                format!("model `{model}` does not come from source `{source}`"),
            ));
        }
        let source_rule_id = scalar_attr("source_rule_id", source_rule_id_node)?;
        if source_rule_id.is_empty() {
            return Err(attr_err("source_rule_id", "is empty"));
        }
        let title = scalar_attr("title", title_node)?;

        let source_rule_rev = match get("source_rule_rev") {
            None => None,
            Some(Node::Int(n)) => {
                Some(u64::try_from(*n).map_err(|_| attr_err("source_rule_rev", "is negative"))?)
            }
            Some(other) => {
                return Err(attr_err(
                    "source_rule_rev",
                    format!("is {}, not an integer", other.type_name()),
                ));
            }
        };
        let optional = |key: &str| get(key).map(|v| scalar_attr(key, v)).transpose();
        let license = optional("license")?;
        let severity = optional("severity")?;
        let classification = optional("classification")?;
        let author = optional("author")?;
        let techniques = list_attr("techniques", get("techniques"))?;
        if let Some(bad) = techniques.iter().find(|t| !is_technique(t)) {
            return Err(attr_err(
                "techniques",
                format!("{bad:?} is not a technique id like `T1059` or `T1059.001`"),
            ));
        }
        let tactics = list_attr("tactics", get("tactics"))?;
        if let Some(bad) = tactics.iter().find(|t| !is_tactic(t)) {
            return Err(attr_err(
                "tactics",
                format!("{bad:?} is not a tactic id like `TA0001`"),
            ));
        }
        let os = get("os")
            .map(|v| {
                text_attr("os", v)?
                    .parse::<Os>()
                    .map_err(|e| attr_err("os", e))
            })
            .transpose()?;
        let prefilter = match get("prefilter") {
            None => None,
            Some(Node::Bytes(bytes)) => Some(bytes.clone()),
            Some(other) => Some(scalar_attr("prefilter", other)?.into_bytes()),
        };
        let references = list_attr("references", get("references"))?;

        let kind = logsource(get("logsource"))?;
        let detection = get("detection")
            .ok_or_else(|| ReadError::Format("the rule has no `detection`".to_string()))?;
        let (detection, fields) = detection::parse(detection)?;

        Ok(Self {
            source,
            source_rule_id,
            model,
            title,
            source_rule_rev,
            license,
            severity,
            classification,
            techniques,
            tactics,
            author,
            os,
            prefilter,
            references,
            kind,
            detection,
            fields,
        })
    }

    /// Returns the source the rule comes from.
    #[must_use]
    pub fn source(&self) -> Source {
        self.source
    }

    /// Returns the id of the rule in its source (an ET `sid`, a Sigma
    /// `id`).
    #[must_use]
    pub fn source_rule_id(&self) -> &str {
        &self.source_rule_id
    }

    /// Returns the detection model the rule belongs to.
    #[must_use]
    pub fn model(&self) -> Model {
        self.model
    }

    /// Returns the title.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the revision of the rule in its source (an ET `rev`).
    #[must_use]
    pub fn source_rule_rev(&self) -> Option<u64> {
        self.source_rule_rev
    }

    /// Returns the license of the rule.
    #[must_use]
    pub fn license(&self) -> Option<&str> {
        self.license.as_deref()
    }

    /// Returns the severity as the source rule gives it.
    #[must_use]
    pub fn severity(&self) -> Option<&str> {
        self.severity.as_deref()
    }

    /// Returns the classification (an ET classtype).
    #[must_use]
    pub fn classification(&self) -> Option<&str> {
        self.classification.as_deref()
    }

    /// Returns the MITRE ATT&CK technique ids.
    #[must_use]
    pub fn techniques(&self) -> &[String] {
        &self.techniques
    }

    /// Returns the MITRE ATT&CK tactic ids.
    #[must_use]
    pub fn tactics(&self) -> &[String] {
        &self.tactics
    }

    /// Returns the author.
    #[must_use]
    pub fn author(&self) -> Option<&str> {
        self.author.as_deref()
    }

    /// Returns the OS the rule applies to; a rule without one applies to
    /// every event.
    #[must_use]
    pub fn os(&self) -> Option<Os> {
        self.os
    }

    /// Returns the prefilter literal, which the engine does not use.
    #[must_use]
    pub fn prefilter(&self) -> Option<&[u8]> {
        self.prefilter.as_deref()
    }

    /// Returns the reference URLs.
    #[must_use]
    pub fn references(&self) -> &[String] {
        &self.references
    }

    /// Returns every field used by the search identifiers, sorted without repeats.
    ///
    /// Includes field references and identifiers the condition does not select.
    #[must_use]
    pub fn fields(&self) -> &[String] {
        &self.fields
    }

    /// Returns the kind of raw event the rule applies to.
    #[must_use]
    pub fn kind(&self) -> RawEventKind {
        self.kind
    }
}

/// Positions in which a `!never` scalar may occur. Only a field map's
/// direct value is allowed, including maps in an OR list.
#[derive(Clone, Copy)]
enum NeverPosition {
    Root,
    Detection,
    Search,
    FieldValue,
    Forbidden,
}

fn validate_never(node: &Node, position: NeverPosition) -> Result<(), ReadError> {
    match node {
        Node::Never if !matches!(position, NeverPosition::FieldValue) => {
            return Err(ReadError::Format(
                "`!never` is only a field condition value".into(),
            ));
        }
        Node::Map(entries) => {
            for (key, value) in entries {
                let next = match position {
                    NeverPosition::Root if key == "detection" => NeverPosition::Detection,
                    NeverPosition::Detection if key != "condition" => NeverPosition::Search,
                    NeverPosition::Search => NeverPosition::FieldValue,
                    _ => NeverPosition::Forbidden,
                };
                validate_never(value, next)?;
            }
        }
        Node::Seq(items) => {
            for item in items {
                let next =
                    if matches!(position, NeverPosition::Search) && matches!(item, Node::Map(_)) {
                        NeverPosition::Search
                    } else {
                        NeverPosition::Forbidden
                    };
                validate_never(item, next)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Reads a string attribute.
fn text_attr<'n>(key: &str, node: &'n Node) -> Result<&'n str, ReadError> {
    match node {
        Node::Str(s) => Ok(s),
        other => Err(attr_err(
            key,
            format!("is {}, not a string", other.type_name()),
        )),
    }
}

/// Reads an attribute written as any scalar, as text.
fn scalar_attr(key: &str, node: &Node) -> Result<String, ReadError> {
    match node {
        Node::Str(s) | Node::Float(s) => Ok(s.clone()),
        Node::Int(i) => Ok(i.to_string()),
        Node::Bool(b) => Ok(b.to_string()),
        other => Err(attr_err(
            key,
            format!("is {}, not a string", other.type_name()),
        )),
    }
}

/// Reads an optional list-of-strings attribute.
fn list_attr(key: &str, node: Option<&Node>) -> Result<Vec<String>, ReadError> {
    match node {
        None => Ok(Vec::new()),
        Some(Node::Seq(items)) => items.iter().map(|item| scalar_attr(key, item)).collect(),
        Some(other) => Err(attr_err(
            key,
            format!("is {}, not a list", other.type_name()),
        )),
    }
}

fn is_digits(s: &str, n: usize) -> bool {
    s.len() == n && s.bytes().all(|b| b.is_ascii_digit())
}

/// Returns whether `s` looks like `T1059` or `T1059.001`.
fn is_technique(s: &str) -> bool {
    let Some(rest) = s.strip_prefix('T') else {
        return false;
    };
    match rest.split_once('.') {
        Some((main, sub)) => is_digits(main, 4) && is_digits(sub, 3),
        None => is_digits(rest, 4),
    }
}

/// Returns whether `s` looks like `TA0001`.
fn is_tactic(s: &str) -> bool {
    s.strip_prefix("TA").is_some_and(|rest| is_digits(rest, 4))
}

/// Reads `logsource`, whose `category` names the kind of raw event.
fn logsource(node: Option<&Node>) -> Result<RawEventKind, ReadError> {
    let Some(Node::Map(entries)) = node else {
        return Err(ReadError::Format(
            "`logsource` is missing or not a mapping".to_string(),
        ));
    };
    for (key, _) in entries {
        if key == "product" || key == "service" {
            return Err(ReadError::Format(format!(
                "`logsource` has `{key}`; Clumit Sigma names the event kind in `category` alone"
            )));
        }
    }
    let category = entries
        .iter()
        .find(|(k, _)| k == "category")
        .map(|(_, v)| v);
    let Some(Node::Str(category)) = category else {
        return Err(ReadError::Format(
            "`logsource` has no `category` string".to_string(),
        ));
    };
    RawEventKind::from_str(category).map_err(|_| {
        ReadError::Format(format!(
            "`logsource` category {category:?} is not a raw event kind"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn technique_and_tactic_shapes() {
        assert!(is_technique("T1059"));
        assert!(is_technique("T1059.001"));
        assert!(!is_technique("T105"));
        assert!(!is_technique("T1059.1"));
        assert!(!is_technique("t1059"));
        assert!(!is_technique("TA0001"));
        assert!(is_tactic("TA0001"));
        assert!(!is_tactic("TA001"));
        assert!(!is_tactic("T0001"));
    }
}
