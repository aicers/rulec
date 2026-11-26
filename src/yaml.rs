//! A YAML loader that keeps what Clumit Sigma needs from a document.
//!
//! `yaml-rust2`'s own loader drops tags, and the `!bytes` tag carries
//! values that are not text, so this module builds its own tree from the
//! parser's events.

use std::collections::HashMap;

use yaml_rust2::{
    Yaml,
    parser::{Event, Parser, Tag},
    scanner::TScalarStyle,
};

/// The local tag that marks a value written as bytes.
const BYTES_TAG: &str = "bytes";
/// The handle of the tags the YAML core schema defines (`!!str`, ...).
const CORE_TAG_HANDLE: &str = "tag:yaml.org,2002:";
/// The most weight (see [`Node::weight`]) the aliases of one document may
/// copy in all. An alias copies the node its anchor names, so a chain of
/// anchors each referring to the one before several times grows a short
/// text into a tree exponentially large; this bounds that growth.
const MAX_ALIAS_WEIGHT: usize = 1 << 20;
/// The most sequences and mappings a document may nest. A Sigma rule
/// needs a handful; the bound keeps every function that walks a [`Node`]
/// recursively, `Drop` included, from running out of stack.
const MAX_COLLECTION_DEPTH: usize = 64;

/// One node of a YAML document.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Node {
    Null,
    Bool(bool),
    Int(i64),
    /// A floating-point number, kept as written.
    Float(String),
    Str(String),
    /// A scalar tagged `!bytes`, decoded.
    Bytes(Vec<u8>),
    Seq(Vec<Node>),
    /// A mapping whose keys are the text of scalar keys, in document order.
    Map(Vec<(String, Node)>),
}

impl Node {
    /// Returns a measure of the memory the node takes: one for each node,
    /// plus the bytes of its text — scalars and mapping keys.
    fn weight(&self) -> usize {
        match self {
            Self::Null | Self::Bool(_) | Self::Int(_) => 1,
            Self::Float(s) | Self::Str(s) => 1 + s.len(),
            Self::Bytes(b) => 1 + b.len(),
            Self::Seq(items) => items
                .iter()
                .fold(1_usize, |sum, item| sum.saturating_add(item.weight())),
            Self::Map(entries) => entries.iter().fold(1_usize, |sum, (key, value)| {
                sum.saturating_add(key.len()).saturating_add(value.weight())
            }),
        }
    }

    /// Returns a short name of the node's type, for error messages.
    pub(crate) fn type_name(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool(_) => "a boolean",
            Self::Int(_) => "an integer",
            Self::Float(_) => "a float",
            Self::Str(_) => "a string",
            Self::Bytes(_) => "bytes",
            Self::Seq(_) => "a list",
            Self::Map(_) => "a mapping",
        }
    }
}

/// Parses `text` as exactly one YAML document.
pub(crate) fn load(text: &str) -> Result<Node, String> {
    let mut builder = Builder::default();
    let mut parser = Parser::new_from_str(text);
    // `Parser::load` recurses once per nested collection, so a deeply
    // nested document would overflow the stack before the builder could
    // refuse it. Pulling the events one by one keeps reading iterative and
    // stops it at the builder's first error.
    loop {
        let (event, _mark) = parser.next_token().map_err(|e| e.to_string())?;
        let end = event == Event::StreamEnd;
        builder.on_event(event);
        if end || builder.error.is_some() {
            break;
        }
    }
    if let Some(error) = builder.error {
        return Err(error);
    }
    let mut docs = builder.docs;
    match docs.len() {
        0 => Err("the text holds no YAML document".to_string()),
        1 => docs
            .pop()
            .ok_or_else(|| "the text holds no YAML document".to_string()),
        n => Err(format!("the text holds {n} YAML documents, not one")),
    }
}

/// Decodes the scalar of a `!bytes` value: `\xHH` is one byte, `\\` is a
/// backslash, and every other character stands for its UTF-8 encoding.
pub(crate) fn decode_bytes(text: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            let mut buf = [0_u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            continue;
        }
        match chars.next() {
            Some('\\') => out.push(b'\\'),
            Some('x') => {
                let hi = chars.next().and_then(|c| c.to_digit(16));
                let lo = chars.next().and_then(|c| c.to_digit(16));
                let (Some(hi), Some(lo)) = (hi, lo) else {
                    return Err(format!(
                        "`!bytes` value {text:?} has a `\\x` escape without two hex digits"
                    ));
                };
                let byte = u8::try_from(hi * 16 + lo)
                    .map_err(|_| format!("`!bytes` value {text:?} has a bad escape"))?;
                out.push(byte);
            }
            Some(other) => {
                return Err(format!(
                    "`!bytes` value {text:?} has an unknown escape `\\{other}`"
                ));
            }
            None => return Err(format!("`!bytes` value {text:?} ends in a lone backslash")),
        }
    }
    Ok(out)
}

/// A collection being built.
enum Frame {
    Seq {
        items: Vec<Node>,
        anchor: usize,
    },
    Map {
        entries: Vec<(String, Node)>,
        key: Option<String>,
        anchor: usize,
    },
}

/// Receives parser events and builds [`Node`] trees.
#[derive(Default)]
struct Builder {
    docs: Vec<Node>,
    stack: Vec<Frame>,
    /// The anchored nodes, with their weight.
    anchors: HashMap<usize, (Node, usize)>,
    /// The weight the aliases have copied so far.
    alias_weight: usize,
    error: Option<String>,
}

impl Builder {
    fn fail(&mut self, message: String) {
        if self.error.is_none() {
            self.error = Some(message);
        }
    }

    fn scalar(value: String, style: TScalarStyle, tag: Option<&Tag>) -> Result<Node, String> {
        if let Some(tag) = tag {
            if tag.handle == "!" && tag.suffix == BYTES_TAG {
                return decode_bytes(&value).map(Node::Bytes);
            }
            if tag.handle == CORE_TAG_HANDLE {
                return match tag.suffix.as_str() {
                    "str" => Ok(Node::Str(value)),
                    "null" | "bool" | "int" | "float" => {
                        let node = Self::resolve_plain(&value);
                        let fits = matches!(
                            (tag.suffix.as_str(), &node),
                            ("null", Node::Null)
                                | ("bool", Node::Bool(_))
                                | ("int", Node::Int(_))
                                | ("float", Node::Float(_) | Node::Int(_))
                        );
                        if fits {
                            Ok(node)
                        } else {
                            Err(format!("{value:?} is not a valid `!!{}`", tag.suffix))
                        }
                    }
                    other => Err(format!("unsupported YAML tag `!!{other}`")),
                };
            }
            return Err(format!(
                "unsupported YAML tag `{}{}`",
                tag.handle, tag.suffix
            ));
        }
        if style == TScalarStyle::Plain {
            Ok(Self::resolve_plain(&value))
        } else {
            Ok(Node::Str(value))
        }
    }

    /// Resolves a plain scalar by the YAML 1.2 core schema.
    fn resolve_plain(value: &str) -> Node {
        match Yaml::from_str(value) {
            Yaml::Null => Node::Null,
            Yaml::Boolean(b) => Node::Bool(b),
            Yaml::Integer(i) => Node::Int(i),
            Yaml::Real(r) => Node::Float(r),
            _ => Node::Str(value.to_string()),
        }
    }

    fn check_collection_tag(tag: Option<&Tag>, expected: &str) -> Result<(), String> {
        match tag {
            None => Ok(()),
            Some(tag) if tag.handle == CORE_TAG_HANDLE && tag.suffix == expected => Ok(()),
            Some(tag) => Err(format!(
                "unsupported YAML tag `{}{}`",
                tag.handle, tag.suffix
            )),
        }
    }

    fn insert(&mut self, node: Node, anchor: usize) {
        if anchor > 0 {
            let weight = node.weight();
            self.anchors.insert(anchor, (node.clone(), weight));
        }
        let error = match self.stack.last_mut() {
            None => {
                self.docs.push(node);
                None
            }
            Some(Frame::Seq { items, .. }) => {
                items.push(node);
                None
            }
            Some(Frame::Map { entries, key, .. }) => match key.take() {
                Some(k) => {
                    if entries.iter().any(|(existing, _)| *existing == k) {
                        Some(format!("duplicate key `{k}` in a mapping"))
                    } else {
                        entries.push((k, node));
                        None
                    }
                }
                None => match node {
                    Node::Null => {
                        *key = Some(String::new());
                        None
                    }
                    Node::Bool(b) => {
                        *key = Some(b.to_string());
                        None
                    }
                    Node::Int(i) => {
                        *key = Some(i.to_string());
                        None
                    }
                    Node::Float(s) | Node::Str(s) => {
                        *key = Some(s);
                        None
                    }
                    Node::Bytes(_) | Node::Seq(_) | Node::Map(_) => {
                        Some("a mapping key is not a text scalar".to_string())
                    }
                },
            },
        };
        if let Some(error) = error {
            self.fail(error);
        }
    }
}

impl Builder {
    fn on_event(&mut self, ev: Event) {
        if self.error.is_some() {
            return;
        }
        match ev {
            Event::Nothing
            | Event::StreamStart
            | Event::StreamEnd
            | Event::DocumentStart
            | Event::DocumentEnd => {}
            Event::Alias(id) => match self.anchors.get(&id) {
                Some((node, weight)) => {
                    let total = self.alias_weight.saturating_add(*weight);
                    if total > MAX_ALIAS_WEIGHT {
                        self.fail(format!(
                            "aliases expand the document past {MAX_ALIAS_WEIGHT} units \
                             (nodes and text bytes)"
                        ));
                    } else {
                        self.alias_weight = total;
                        let node = node.clone();
                        self.insert(node, 0);
                    }
                }
                None => self.fail("an alias refers to an unknown anchor".to_string()),
            },
            Event::Scalar(value, style, anchor, tag) => {
                match Self::scalar(value, style, tag.as_ref()) {
                    Ok(node) => self.insert(node, anchor),
                    Err(e) => self.fail(e),
                }
            }
            Event::SequenceStart(..) | Event::MappingStart(..)
                if self.stack.len() >= MAX_COLLECTION_DEPTH =>
            {
                self.fail(format!(
                    "sequences and mappings nest more than {MAX_COLLECTION_DEPTH} deep"
                ));
            }
            Event::SequenceStart(anchor, tag) => {
                if let Err(e) = Self::check_collection_tag(tag.as_ref(), "seq") {
                    self.fail(e);
                }
                self.stack.push(Frame::Seq {
                    items: Vec::new(),
                    anchor,
                });
            }
            Event::MappingStart(anchor, tag) => {
                if let Err(e) = Self::check_collection_tag(tag.as_ref(), "map") {
                    self.fail(e);
                }
                self.stack.push(Frame::Map {
                    entries: Vec::new(),
                    key: None,
                    anchor,
                });
            }
            Event::SequenceEnd | Event::MappingEnd => match self.stack.pop() {
                Some(Frame::Seq { items, anchor }) => self.insert(Node::Seq(items), anchor),
                Some(Frame::Map {
                    entries, anchor, ..
                }) => self.insert(Node::Map(entries), anchor),
                None => self.fail("unbalanced YAML collection".to_string()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_scalars_by_core_schema() {
        let node = load("a: 1\nb: '1'\nc: ~\nd: true\ne: 1.5\nf: x\ng: ''\n").unwrap();
        assert_eq!(
            node,
            Node::Map(vec![
                ("a".to_string(), Node::Int(1)),
                ("b".to_string(), Node::Str("1".to_string())),
                ("c".to_string(), Node::Null),
                ("d".to_string(), Node::Bool(true)),
                ("e".to_string(), Node::Float("1.5".to_string())),
                ("f".to_string(), Node::Str("x".to_string())),
                ("g".to_string(), Node::Str(String::new())),
            ])
        );
    }

    #[test]
    fn aliases_expand_within_a_budget() {
        let node = load("a: &x [1, 2]\nb: *x\n").unwrap();
        let pair = Node::Seq(vec![Node::Int(1), Node::Int(2)]);
        assert_eq!(
            node,
            Node::Map(vec![
                ("a".to_string(), pair.clone()),
                ("b".to_string(), pair)
            ])
        );

        // Each level refers to the one before ten times: 10^9 leaves.
        let mut text = "l0: &l0 [x, x, x, x, x, x, x, x, x, x]\n".to_string();
        for level in 1..=9 {
            let prev = level - 1;
            let refs = vec![format!("*l{prev}"); 10].join(", ");
            text.push_str(&format!("l{level}: &l{level} [{refs}]\n"));
        }
        let error = load(&text).unwrap_err();
        assert!(error.contains("aliases expand"), "{error}");
    }

    #[test]
    fn loads_bytes_tag() {
        let node = load("v: !bytes 'a\\x00\\xFFb\\\\'\n").unwrap();
        assert_eq!(
            node,
            Node::Map(vec![(
                "v".to_string(),
                Node::Bytes(vec![b'a', 0, 0xff, b'b', b'\\'])
            )])
        );
        assert!(load("v: !bytes '\\x0'\n").is_err());
        assert!(load("v: !bytes '\\n'\n").is_err());
        assert!(load("v: !other x\n").is_err());
    }

    #[test]
    fn rejects_duplicates_and_many_documents() {
        assert!(load("a: 1\na: 2\n").is_err());
        assert!(load("a: 1\n---\nb: 2\n").is_err());
        assert!(load("a: [1\n").is_err());
        assert!(load("").is_err());
    }

    #[test]
    fn nesting_is_bounded() {
        let block = |depth: usize| format!("v:\n  {}x\n", "- ".repeat(depth));
        let flow = |depth: usize| format!("v: {}x{}\n", "[".repeat(depth), "]".repeat(depth));
        // The document's own mapping is one level.
        assert!(load(&block(MAX_COLLECTION_DEPTH - 1)).is_ok());
        assert!(load(&flow(MAX_COLLECTION_DEPTH - 1)).is_ok());
        let error = load(&block(MAX_COLLECTION_DEPTH)).unwrap_err();
        assert!(error.contains("nest more than"), "{error}");
        assert!(load(&flow(MAX_COLLECTION_DEPTH)).is_err());

        // Deep enough to overflow the stack of a recursive reader.
        let error = load(&block(100_000)).unwrap_err();
        assert!(error.contains("nest more than"), "{error}");
        // The scanner refuses deep flow collections before the builder.
        assert!(load(&flow(100_000)).is_err());
    }

    #[test]
    fn resolves_aliases() {
        let node = load("a: &x [1, 2]\nb: *x\n").unwrap();
        let Node::Map(entries) = node else { panic!() };
        assert_eq!(entries[0].1, entries[1].1);
    }
}
