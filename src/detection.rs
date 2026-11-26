//! Reads the `detection` section of a rule: search identifiers, field
//! conditions with their modifiers, and the condition.

use crate::{
    cidr::Cidr,
    condition,
    expr::{Cmp, Expr, Leaf, Piece, RegexPattern, StrPattern, Test},
    rule::ReadError,
    yaml::Node,
};

/// The only placeholder `expand` accepts.
const HOME_NET: &str = "home_net";
/// The most values one field condition may expand into, through
/// `windash` before an encoding or through `base64offset`.
const MAX_EXPANSION: usize = 1024;
/// The characters `windash` makes interchangeable.
const WINDASH: [char; 5] = ['-', '/', '\u{2013}', '\u{2014}', '\u{2015}'];
/// The Base64 alphabet.
const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn format_err(message: impl Into<String>) -> ReadError {
    ReadError::Format(message.into())
}

/// Reads the `detection` mapping into one expression.
pub(crate) fn parse(detection: &Node) -> Result<Expr, ReadError> {
    let Node::Map(entries) = detection else {
        return Err(format_err("`detection` is not a mapping"));
    };
    check_placeholders(entries)?;
    let mut searches = Vec::new();
    let mut conditions = None;
    for (name, body) in entries {
        if name == "condition" {
            conditions = Some(body);
        } else {
            let expr = search(name, body)?;
            searches.push((name.as_str(), expr));
        }
    }
    let Some(conditions) = conditions else {
        return Err(format_err("`detection` has no `condition`"));
    };
    let texts: Vec<&str> = match conditions {
        Node::Str(text) => vec![text.as_str()],
        Node::Seq(items) if !items.is_empty() => items
            .iter()
            .map(|item| match item {
                Node::Str(text) => Ok(text.as_str()),
                other => Err(format_err(format!(
                    "a `condition` item is {}, not a string",
                    other.type_name()
                ))),
            })
            .collect::<Result<_, _>>()?,
        other => {
            return Err(format_err(format!(
                "`condition` is {}, not a string or a list of strings",
                other.type_name()
            )));
        }
    };
    let exprs = texts
        .into_iter()
        .map(|text| condition::parse(text, &searches))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Expr::or(exprs))
}

/// Rejects a detection whose `expand` values name a placeholder other than
/// `%home_net%`, before anything else in it is checked: such a rule is
/// rejected for that, whatever else is wrong with it.
fn check_placeholders(entries: &[(String, Node)]) -> Result<(), ReadError> {
    for (name, body) in entries {
        if name == "condition" {
            continue;
        }
        let maps = match body {
            Node::Seq(items) => items.as_slice(),
            other => std::slice::from_ref(other),
        };
        for map in maps {
            let Node::Map(conditions) = map else {
                continue;
            };
            for (key, value) in conditions {
                if !key.split('|').skip(1).any(|m| m == "expand") {
                    continue;
                }
                let values = match value {
                    Node::Seq(items) => items.as_slice(),
                    other => std::slice::from_ref(other),
                };
                for v in values {
                    let Node::Str(text) = v else {
                        continue;
                    };
                    if let Some(name) = placeholders(text).into_iter().find(|n| n != HOME_NET) {
                        return Err(ReadError::PlaceholderValueMissing(name));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Reads one search identifier: a mapping is the AND of its field
/// conditions, and a list of mappings the OR of the mappings.
fn search(name: &str, body: &Node) -> Result<Expr, ReadError> {
    match body {
        Node::Map(entries) => map_search(name, entries),
        Node::Seq(items) if !items.is_empty() => {
            let mut exprs = Vec::with_capacity(items.len());
            for item in items {
                let Node::Map(entries) = item else {
                    return Err(format_err(format!(
                        "search identifier `{name}` lists {} — keyword searches are not \
                         supported; name the field",
                        item.type_name()
                    )));
                };
                exprs.push(map_search(name, entries)?);
            }
            Ok(Expr::or(exprs))
        }
        other => Err(format_err(format!(
            "search identifier `{name}` is {}, not a mapping or a list of mappings",
            other.type_name()
        ))),
    }
}

fn map_search(name: &str, entries: &[(String, Node)]) -> Result<Expr, ReadError> {
    if entries.is_empty() {
        return Err(format_err(format!(
            "search identifier `{name}` has an empty mapping"
        )));
    }
    let exprs = entries
        .iter()
        .map(|(key, value)| field_condition(key, value))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Expr::and(exprs))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Modifier {
    Contains,
    StartsWith,
    EndsWith,
    All,
    Exists,
    Cased,
    Neq,
    Windash,
    Re,
    ReI,
    ReM,
    ReS,
    Base64,
    Base64Offset,
    Utf16Le,
    Utf16Be,
    Utf16,
    Wide,
    Lt,
    Lte,
    Gt,
    Gte,
    Cidr,
    Expand,
    FieldRef,
    Len,
}

impl Modifier {
    fn parse(name: &str, after_re: bool) -> Result<Self, ReadError> {
        let modifier = match name {
            "contains" => Self::Contains,
            "startswith" => Self::StartsWith,
            "endswith" => Self::EndsWith,
            "all" => Self::All,
            "exists" => Self::Exists,
            "cased" => Self::Cased,
            "neq" => Self::Neq,
            "windash" => Self::Windash,
            "re" => Self::Re,
            "i" | "m" | "s" if !after_re => {
                return Err(format_err(format!(
                    "modifier `{name}` is a sub-modifier of `re` and must follow it"
                )));
            }
            "i" => Self::ReI,
            "m" => Self::ReM,
            "s" => Self::ReS,
            "base64" => Self::Base64,
            "base64offset" => Self::Base64Offset,
            "utf16le" => Self::Utf16Le,
            "utf16be" => Self::Utf16Be,
            "utf16" => Self::Utf16,
            "wide" => Self::Wide,
            "lt" => Self::Lt,
            "lte" => Self::Lte,
            "gt" => Self::Gt,
            "gte" => Self::Gte,
            "cidr" => Self::Cidr,
            "expand" => Self::Expand,
            "fieldref" => Self::FieldRef,
            "len" => Self::Len,
            "" => return Err(format_err("an empty modifier name")),
            other => return Err(ReadError::UnsupportedModifier(other.to_string())),
        };
        Ok(modifier)
    }

    fn cmp(self) -> Option<Cmp> {
        match self {
            Self::Lt => Some(Cmp::Lt),
            Self::Lte => Some(Cmp::Lte),
            Self::Gt => Some(Cmp::Gt),
            Self::Gte => Some(Cmp::Gte),
            _ => None,
        }
    }

    fn is_encoding(self) -> bool {
        matches!(
            self,
            Self::Windash
                | Self::Base64
                | Self::Base64Offset
                | Self::Utf16Le
                | Self::Utf16Be
                | Self::Utf16
                | Self::Wide
        )
    }

    fn is_position(self) -> bool {
        matches!(self, Self::Contains | Self::StartsWith | Self::EndsWith)
    }
}

/// What a field condition compares, as its modifiers decide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Exists,
    FieldRef,
    Cidr,
    Re,
    Len(Cmp),
    Num(Cmp),
    /// A string, or a plain value whose type decides.
    Plain,
}

/// Reads one `field|modifiers: value` entry.
fn field_condition(key: &str, value: &Node) -> Result<Expr, ReadError> {
    let mut parts = key.split('|');
    let field = parts.next().unwrap_or_default();
    if field.is_empty() {
        return Err(format_err(format!(
            "`{key}` names no field — keyword searches are not supported"
        )));
    }
    let mut mods: Vec<Modifier> = Vec::new();
    for name in parts {
        let modifier = Modifier::parse(name, mods.contains(&Modifier::Re))?;
        if mods.contains(&modifier) {
            return Err(format_err(format!("`{key}` repeats modifier `{name}`")));
        }
        mods.push(modifier);
    }
    let has = |m: Modifier| mods.contains(&m);

    let is_list = matches!(value, Node::Seq(_));
    let values: Vec<&Node> = match value {
        Node::Seq(items) => {
            if items.is_empty() {
                return Err(format_err(format!("`{key}` has an empty list of values")));
            }
            items.iter().collect()
        }
        Node::Map(_) => {
            return Err(format_err(format!("the value of `{key}` is a mapping")));
        }
        other => vec![other],
    };
    for v in &values {
        if matches!(v, Node::Seq(_) | Node::Map(_)) {
            return Err(format_err(format!(
                "`{key}` lists {}, not a value",
                v.type_name()
            )));
        }
        if is_list && matches!(v, Node::Null) {
            return Err(format_err(format!(
                "`{key}` lists `null`; a `null` value must stand alone"
            )));
        }
    }

    // `check_placeholders` has rejected every placeholder but `%home_net%`
    // already; this checks how `%home_net%` is written.
    if has(Modifier::Expand) {
        let mut home_net = false;
        for v in &values {
            if let Node::Str(text) = v {
                for name in placeholders(text) {
                    if name != HOME_NET {
                        return Err(ReadError::PlaceholderValueMissing(name));
                    }
                    home_net = true;
                    if *text != format!("%{HOME_NET}%") {
                        return Err(format_err(format!(
                            "`{key}`: `%{HOME_NET}%` must be a whole value"
                        )));
                    }
                }
            }
        }
        if home_net && mods != [Modifier::Expand, Modifier::Cidr] {
            return Err(format_err(format!(
                "`{key}`: `%{HOME_NET}%` is written only as `field|expand|cidr`"
            )));
        }
    }

    let all = has(Modifier::All);
    let neq = has(Modifier::Neq);
    let cased = has(Modifier::Cased);
    if all && !is_list {
        return Err(format_err(format!(
            "`{key}`: modifier `all` needs a list of values"
        )));
    }
    if all && neq {
        return Err(format_err(format!(
            "`{key}`: modifiers `all` and `neq` do not combine"
        )));
    }

    let kind = kind_of(key, &mods)?;
    let mut per_value: Vec<Vec<Test>> = Vec::with_capacity(values.len());
    for v in &values {
        per_value.push(value_tests(key, kind, &mods, cased, v)?);
    }

    if neq {
        let tests: Vec<Test> = per_value.into_iter().flatten().collect();
        if tests
            .iter()
            .any(|t| matches!(t, Test::Null | Test::Exists(_)))
        {
            return Err(format_err(format!(
                "`{key}`: modifier `neq` does not combine with `null`"
            )));
        }
        return Ok(Expr::Leaf(Leaf {
            field: field.to_string(),
            test: Test::Neq(tests),
        }));
    }
    let leaf = |test| {
        Expr::Leaf(Leaf {
            field: field.to_string(),
            test,
        })
    };
    let nodes: Vec<Expr> = per_value
        .into_iter()
        .map(|tests| Expr::or(tests.into_iter().map(leaf).collect()))
        .collect();
    Ok(if all {
        Expr::and(nodes)
    } else {
        Expr::or(nodes)
    })
}

/// Decides what the field condition compares, and rejects modifiers that
/// do not combine with it.
fn kind_of(key: &str, mods: &[Modifier]) -> Result<Kind, ReadError> {
    let has = |m: Modifier| mods.contains(&m);
    let cmps: Vec<Cmp> = mods.iter().filter_map(|m| m.cmp()).collect();
    if cmps.len() > 1 {
        return Err(format_err(format!(
            "`{key}` has more than one numeric comparison"
        )));
    }
    let cmp = cmps.first().copied();
    let positions = mods.iter().filter(|m| m.is_position()).count();
    if positions > 1 {
        return Err(format_err(format!(
            "`{key}` combines more than one of `contains`, `startswith` and `endswith`"
        )));
    }

    let (kind, allowed): (Kind, &[Modifier]) = if has(Modifier::Exists) {
        (Kind::Exists, &[Modifier::Exists])
    } else if has(Modifier::FieldRef) {
        (
            Kind::FieldRef,
            &[
                Modifier::FieldRef,
                Modifier::Neq,
                Modifier::Cased,
                Modifier::All,
            ],
        )
    } else if has(Modifier::Cidr) {
        (
            Kind::Cidr,
            &[
                Modifier::Cidr,
                Modifier::Expand,
                Modifier::Neq,
                Modifier::Cased,
                Modifier::All,
            ],
        )
    } else if has(Modifier::Re) {
        (
            Kind::Re,
            &[
                Modifier::Re,
                Modifier::ReI,
                Modifier::ReM,
                Modifier::ReS,
                Modifier::Neq,
                Modifier::Cased,
                Modifier::All,
            ],
        )
    } else if has(Modifier::Len) {
        (
            Kind::Len(cmp.unwrap_or(Cmp::Eq)),
            &[
                Modifier::Len,
                Modifier::Lt,
                Modifier::Lte,
                Modifier::Gt,
                Modifier::Gte,
                Modifier::Neq,
                Modifier::Cased,
                Modifier::All,
            ],
        )
    } else if let Some(cmp) = cmp {
        (
            Kind::Num(cmp),
            &[
                Modifier::Lt,
                Modifier::Lte,
                Modifier::Gt,
                Modifier::Gte,
                Modifier::Cased,
                Modifier::All,
            ],
        )
    } else {
        (
            Kind::Plain,
            &[
                Modifier::Contains,
                Modifier::StartsWith,
                Modifier::EndsWith,
                Modifier::Windash,
                Modifier::Base64,
                Modifier::Base64Offset,
                Modifier::Utf16Le,
                Modifier::Utf16Be,
                Modifier::Utf16,
                Modifier::Wide,
                Modifier::Expand,
                Modifier::Cased,
                Modifier::All,
                Modifier::Neq,
            ],
        )
    };
    if let Some(bad) = mods.iter().find(|m| !allowed.contains(m)) {
        return Err(format_err(format!(
            "`{key}`: modifier `{}` does not combine with the others",
            modifier_name(*bad)
        )));
    }
    Ok(kind)
}

fn modifier_name(m: Modifier) -> &'static str {
    match m {
        Modifier::Contains => "contains",
        Modifier::StartsWith => "startswith",
        Modifier::EndsWith => "endswith",
        Modifier::All => "all",
        Modifier::Exists => "exists",
        Modifier::Cased => "cased",
        Modifier::Neq => "neq",
        Modifier::Windash => "windash",
        Modifier::Re => "re",
        Modifier::ReI => "i",
        Modifier::ReM => "m",
        Modifier::ReS => "s",
        Modifier::Base64 => "base64",
        Modifier::Base64Offset => "base64offset",
        Modifier::Utf16Le => "utf16le",
        Modifier::Utf16Be => "utf16be",
        Modifier::Utf16 => "utf16",
        Modifier::Wide => "wide",
        Modifier::Lt => "lt",
        Modifier::Lte => "lte",
        Modifier::Gt => "gt",
        Modifier::Gte => "gte",
        Modifier::Cidr => "cidr",
        Modifier::Expand => "expand",
        Modifier::FieldRef => "fieldref",
        Modifier::Len => "len",
    }
}

/// Returns the text of a scalar a string condition reads, or `None` for
/// bytes and null.
fn scalar_text(value: &Node) -> Option<String> {
    match value {
        Node::Str(s) | Node::Float(s) => Some(s.clone()),
        Node::Int(i) => Some(i.to_string()),
        Node::Bool(b) => Some(b.to_string()),
        Node::Null | Node::Bytes(_) | Node::Seq(_) | Node::Map(_) => None,
    }
}

/// Builds the tests of one value; a value may expand into several, any of
/// which holding makes the value hold.
fn value_tests(
    key: &str,
    kind: Kind,
    mods: &[Modifier],
    cased: bool,
    value: &Node,
) -> Result<Vec<Test>, ReadError> {
    let wrong = |what: &str| format_err(format!("`{key}` takes {what}, not {}", value.type_name()));
    let test = match kind {
        Kind::Exists => match value {
            Node::Bool(b) => Test::Exists(*b),
            _ => return Err(wrong("`true` or `false`")),
        },
        Kind::FieldRef => match value {
            Node::Str(other) if !other.is_empty() => Test::FieldRef {
                other: other.clone(),
                cased,
            },
            _ => return Err(wrong("a field name")),
        },
        Kind::Cidr => match value {
            Node::Str(text)
                if mods.contains(&Modifier::Expand) && *text == format!("%{HOME_NET}%") =>
            {
                Test::HomeNet
            }
            Node::Str(text) => Test::Cidr(
                text.parse::<Cidr>()
                    .map_err(|e| format_err(format!("`{key}`: {e}")))?,
            ),
            _ => return Err(wrong("an address range")),
        },
        Kind::Re => {
            let Some(expr) = scalar_text(value) else {
                return Err(wrong("a regular expression"));
            };
            Test::Regex(RegexPattern {
                expr,
                caseless: mods.contains(&Modifier::ReI),
                multiline: mods.contains(&Modifier::ReM),
                dotall: mods.contains(&Modifier::ReS),
            })
        }
        Kind::Len(cmp) => match value {
            Node::Int(n) => Test::Len(
                cmp,
                u64::try_from(*n)
                    .map_err(|_| format_err(format!("`{key}`: a length cannot be negative")))?,
            ),
            _ => return Err(wrong("an integer")),
        },
        Kind::Num(cmp) => match value {
            Node::Int(n) => Test::Num(cmp, *n),
            _ => return Err(wrong("an integer")),
        },
        Kind::Plain => return plain_tests(key, mods, cased, value),
    };
    Ok(vec![test])
}

/// Builds the tests of a value under string modifiers, or of a plain value.
fn plain_tests(
    key: &str,
    mods: &[Modifier],
    cased: bool,
    value: &Node,
) -> Result<Vec<Test>, ReadError> {
    let transforms = mods.iter().any(|m| m.is_encoding() || m.is_position());
    let expand = mods.contains(&Modifier::Expand);
    let pieces = match value {
        Node::Null => {
            if !mods.is_empty() {
                return Err(format_err(format!(
                    "`{key}`: a `null` value takes no modifiers"
                )));
            }
            return Ok(vec![Test::Null]);
        }
        Node::Int(n) if !transforms => return Ok(vec![Test::Num(Cmp::Eq, *n)]),
        Node::Bytes(bytes) => vec![Piece::Lit(bytes.clone())],
        Node::Str(text) => sigma_string(text, expand),
        other => match scalar_text(other) {
            Some(text) => vec![Piece::Lit(text.into_bytes())],
            None => {
                return Err(format_err(format!(
                    "`{key}` takes a value, not {}",
                    other.type_name()
                )));
            }
        },
    };
    let is_bytes = matches!(value, Node::Bytes(_));

    let mut alternatives = vec![pieces];
    for m in mods {
        alternatives = match m {
            Modifier::Windash => {
                if is_bytes {
                    return Err(format_err(format!(
                        "`{key}`: a `!bytes` value takes no `windash`"
                    )));
                }
                alternatives.into_iter().map(windash).collect()
            }
            Modifier::Base64 => expand_literals(key, alternatives)?
                .into_iter()
                .map(|bytes| vec![Piece::Lit(base64(&bytes))])
                .collect(),
            Modifier::Base64Offset => {
                let mut out = Vec::new();
                for bytes in expand_literals(key, alternatives)? {
                    out.extend(
                        base64_offsets(&bytes)
                            .into_iter()
                            .map(|b| vec![Piece::Lit(b)]),
                    );
                }
                if out.len() > MAX_EXPANSION {
                    return Err(too_many(key));
                }
                out
            }
            Modifier::Utf16Le | Modifier::Wide | Modifier::Utf16Be | Modifier::Utf16 => {
                if is_bytes {
                    return Err(format_err(format!(
                        "`{key}`: a `!bytes` value is not text to encode in UTF-16"
                    )));
                }
                alternatives
                    .into_iter()
                    .map(|pieces| utf16(key, &pieces, *m))
                    .collect::<Result<_, _>>()?
            }
            Modifier::Contains | Modifier::StartsWith | Modifier::EndsWith => alternatives
                .into_iter()
                .map(|mut pieces| {
                    if *m != Modifier::StartsWith {
                        pieces.insert(0, Piece::AnyStr);
                    }
                    if *m != Modifier::EndsWith {
                        pieces.push(Piece::AnyStr);
                    }
                    pieces
                })
                .collect(),
            _ => alternatives,
        };
    }

    Ok(alternatives
        .into_iter()
        .map(|pieces| finish(pieces, cased))
        .collect())
}

fn too_many(key: &str) -> ReadError {
    format_err(format!(
        "`{key}` expands into more than {MAX_EXPANSION} values"
    ))
}

/// Normalizes the pieces and turns patterns that can match an empty value
/// into the tests that check them without vectorscan.
fn finish(pieces: Vec<Piece>, cased: bool) -> Test {
    let mut out: Vec<Piece> = Vec::with_capacity(pieces.len());
    for piece in pieces {
        match (out.last_mut(), piece) {
            (_, Piece::Lit(bytes)) if bytes.is_empty() => {}
            (Some(Piece::Lit(prev)), Piece::Lit(bytes)) => prev.extend_from_slice(&bytes),
            (Some(Piece::AnyStr), Piece::AnyStr) => {}
            (_, piece) => out.push(piece),
        }
    }
    if out.is_empty() {
        Test::Empty
    } else if out.iter().all(|p| *p == Piece::AnyStr) {
        Test::Any
    } else {
        Test::Str(StrPattern { pieces: out, cased })
    }
}

/// Reads a Sigma string: `*` and `?` are wildcards, and a backslash escapes
/// a wildcard, a backslash, or — under `expand` — a percent sign.
fn sigma_string(text: &str, expand: bool) -> Vec<Piece> {
    let mut pieces = Vec::new();
    let mut lit = Vec::new();
    let mut chars = text.chars().peekable();
    let push_char = |lit: &mut Vec<u8>, c: char| {
        let mut buf = [0_u8; 4];
        lit.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    };
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.peek() {
                Some(&next @ ('*' | '?' | '\\')) => {
                    push_char(&mut lit, next);
                    chars.next();
                }
                Some('%') if expand => {
                    push_char(&mut lit, '%');
                    chars.next();
                }
                _ => push_char(&mut lit, '\\'),
            },
            '*' | '?' => {
                if !lit.is_empty() {
                    pieces.push(Piece::Lit(std::mem::take(&mut lit)));
                }
                pieces.push(if c == '*' {
                    Piece::AnyStr
                } else {
                    Piece::AnyChar
                });
            }
            c => push_char(&mut lit, c),
        }
    }
    if !lit.is_empty() {
        pieces.push(Piece::Lit(lit));
    }
    pieces
}

/// Returns the names of the placeholders (`%name%`) in a value under
/// `expand`. A backslash escapes a percent sign or a backslash.
fn placeholders(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut chars = text.chars();
    let mut current: Option<String> = None;
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let next = chars.next();
                if let (Some(name), Some(next)) = (current.as_mut(), next) {
                    name.push('\\');
                    name.push(next);
                }
            }
            '%' => match current.take() {
                Some(name) => names.push(name),
                None => current = Some(String::new()),
            },
            c => {
                if let Some(name) = current.as_mut() {
                    name.push(c);
                }
            }
        }
    }
    names
}

/// Makes every dash in the literal pieces stand for any of the `windash`
/// characters.
fn windash(pieces: Vec<Piece>) -> Vec<Piece> {
    let alternatives: Vec<Vec<u8>> = WINDASH.iter().map(|c| c.to_string().into_bytes()).collect();
    let mut out = Vec::new();
    for piece in pieces {
        let Piece::Lit(bytes) = piece else {
            out.push(piece);
            continue;
        };
        let mut lit = Vec::new();
        let mut rest = bytes.as_slice();
        while !rest.is_empty() {
            if let Some(dash) = alternatives.iter().find(|d| rest.starts_with(d)) {
                if !lit.is_empty() {
                    out.push(Piece::Lit(std::mem::take(&mut lit)));
                }
                out.push(Piece::Alt(alternatives.clone()));
                rest = rest.get(dash.len()..).unwrap_or_default();
            } else if let Some((first, tail)) = rest.split_first() {
                lit.push(*first);
                rest = tail;
            }
        }
        if !lit.is_empty() {
            out.push(Piece::Lit(lit));
        }
    }
    out
}

/// Expands values of literal pieces and alternatives into byte strings,
/// for an encoding that needs the bytes. Wildcards cannot be encoded.
fn expand_literals(key: &str, values: Vec<Vec<Piece>>) -> Result<Vec<Vec<u8>>, ReadError> {
    let mut out = Vec::new();
    for pieces in values {
        let mut partial: Vec<Vec<u8>> = vec![Vec::new()];
        for piece in pieces {
            match piece {
                Piece::Lit(bytes) => {
                    for p in &mut partial {
                        p.extend_from_slice(&bytes);
                    }
                }
                Piece::Alt(choices) => {
                    if partial.len().saturating_mul(choices.len()) > MAX_EXPANSION {
                        return Err(too_many(key));
                    }
                    partial = partial
                        .iter()
                        .flat_map(|p| {
                            choices.iter().map(move |c| {
                                let mut next = p.clone();
                                next.extend_from_slice(c);
                                next
                            })
                        })
                        .collect();
                }
                Piece::AnyStr | Piece::AnyChar => {
                    return Err(format_err(format!(
                        "`{key}`: a value with wildcards cannot be Base64-encoded \
                         (a `contains`, `startswith` or `endswith` before the encoding \
                         adds one)"
                    )));
                }
            }
        }
        out.extend(partial);
        if out.len() > MAX_EXPANSION {
            return Err(too_many(key));
        }
    }
    Ok(out)
}

/// Encodes bytes in standard Base64 with padding.
pub(crate) fn base64(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len().div_ceil(3) * 4);
    let symbol = |index: u32| -> u8 {
        // Masking with 0x3f keeps the index below 64.
        let i = usize::try_from(index & 0x3f).unwrap_or_default();
        BASE64_ALPHABET.get(i).copied().unwrap_or(b'=')
    };
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk.first().copied().unwrap_or_default());
        let b1 = u32::from(chunk.get(1).copied().unwrap_or_default());
        let b2 = u32::from(chunk.get(2).copied().unwrap_or_default());
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(symbol(n >> 18));
        out.push(symbol(n >> 12));
        out.push(if chunk.len() > 1 {
            symbol(n >> 6)
        } else {
            b'='
        });
        out.push(if chunk.len() > 2 { symbol(n) } else { b'=' });
    }
    out
}

/// Returns the three `base64offset` forms of `bytes`: the part of its
/// Base64 encoding that stays the same at each offset modulo 3 within a
/// longer encoded string, as pySigma computes it.
fn base64_offsets(bytes: &[u8]) -> Vec<Vec<u8>> {
    const START: [usize; 3] = [0, 2, 3];
    // How many characters to drop from the end, by `(len + shift) % 3`.
    const END_DROP: [usize; 3] = [0, 3, 2];
    let mut out = Vec::with_capacity(3);
    for (shift, start) in START.iter().enumerate() {
        let mut padded = vec![b' '; shift];
        padded.extend_from_slice(bytes);
        let encoded = base64(&padded);
        let drop = END_DROP
            .get((bytes.len() + shift) % 3)
            .copied()
            .unwrap_or_default();
        let end = encoded.len().saturating_sub(drop);
        out.push(encoded.get(*start..end).unwrap_or_default().to_vec());
    }
    out
}

/// Encodes the text pieces of a value in UTF-16.
fn utf16(key: &str, pieces: &[Piece], m: Modifier) -> Result<Vec<Piece>, ReadError> {
    let big_endian = m == Modifier::Utf16Be;
    let encode = |bytes: &[u8]| -> Result<Vec<u8>, ReadError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| format_err(format!("`{key}`: the value is not UTF-8 text to encode")))?;
        Ok(text
            .encode_utf16()
            .flat_map(|unit| {
                if big_endian {
                    unit.to_be_bytes()
                } else {
                    unit.to_le_bytes()
                }
            })
            .collect())
    };
    let mut out = Vec::with_capacity(pieces.len() + 1);
    if m == Modifier::Utf16 {
        out.push(Piece::Lit(vec![0xff, 0xfe]));
    }
    for piece in pieces {
        out.push(match piece {
            Piece::Lit(bytes) => Piece::Lit(encode(bytes)?),
            Piece::Alt(choices) => Piece::Alt(
                choices
                    .iter()
                    .map(|c| encode(c))
                    .collect::<Result<_, _>>()?,
            ),
            Piece::AnyStr => Piece::AnyStr,
            Piece::AnyChar => {
                return Err(format_err(format!(
                    "`{key}`: the wildcard `?` cannot be encoded in UTF-16"
                )));
            }
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_reference() {
        assert_eq!(base64(b""), b"");
        assert_eq!(base64(b"f"), b"Zg==");
        assert_eq!(base64(b"fo"), b"Zm8=");
        assert_eq!(base64(b"foo"), b"Zm9v");
        assert_eq!(base64(b"foob"), b"Zm9vYg==");
        assert_eq!(base64(&[0xff, 0xfe, 0x00]), b"//4A");
    }

    #[test]
    fn base64_offsets_match_pysigma() {
        // pySigma's `base64offset` of `/bin/bash`.
        let forms = base64_offsets(b"/bin/bash");
        assert_eq!(
            forms,
            vec![
                b"L2Jpbi9iYXNo".to_vec(),
                b"9iaW4vYmFza".to_vec(),
                b"vYmluL2Jhc2".to_vec()
            ]
        );
    }

    #[test]
    fn sigma_string_escapes() {
        assert_eq!(
            sigma_string(r"a*b?c\*d\?e\\f\g", false),
            vec![
                Piece::Lit(b"a".to_vec()),
                Piece::AnyStr,
                Piece::Lit(b"b".to_vec()),
                Piece::AnyChar,
                Piece::Lit(br"c*d?e\f\g".to_vec()),
            ]
        );
        assert_eq!(
            sigma_string(r"\\*", false),
            vec![Piece::Lit(br"\".to_vec()), Piece::AnyStr]
        );
        assert_eq!(sigma_string(r"\%x", true), vec![Piece::Lit(b"%x".to_vec())]);
        assert_eq!(
            sigma_string(r"\%x", false),
            vec![Piece::Lit(br"\%x".to_vec())]
        );
    }

    #[test]
    fn finds_placeholders() {
        assert_eq!(placeholders("%home_net%"), vec!["home_net"]);
        assert_eq!(placeholders(r"\%a%b%"), vec!["b"]);
        assert!(placeholders("100%").is_empty());
    }
}
