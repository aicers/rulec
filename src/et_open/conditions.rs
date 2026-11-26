//! Clumit Sigma generation and exact byte-position chains.

use std::{collections::BTreeMap, fmt::Write as _};

use super::{
    data::{self, Direction},
    parse::{Header, Pattern, Value},
};
use crate::{Cidr, HEADER_BLOCK_HEADERS, normalize_host, normalize_uri, reason};

const ANY_BYTE: &str = r"[\x00-\xff]";

#[derive(Default)]
pub(super) struct Detection {
    pub yaml: String,
    next: usize,
    truth: Option<String>,
}

pub(super) fn quote(value: &str) -> String {
    // JSON double-quoted strings are also YAML double-quoted scalars.
    serde_json::to_string(value).expect("serializing a string cannot fail")
}

pub(super) fn byte_value(bytes: &[u8]) -> String {
    let mut value = String::from("!bytes '");
    for byte in bytes {
        let _ = write!(value, "\\x{byte:02x}");
    }
    value.push('\'');
    value
}

impl Detection {
    fn leaf(&mut self, field: &str, modifier: &str, value: &str) -> String {
        let id = format!("s{}", self.next);
        self.next += 1;
        let _ = writeln!(self.yaml, "  {id}:\n    {field}{modifier}: {value}");
        id
    }

    fn truth(&mut self) -> String {
        if let Some(value) = &self.truth {
            return value.clone();
        }
        let yes = self.leaf("orig_addr", "|exists", "true");
        let no = self.leaf("orig_addr", "|exists", "false");
        let value = or(vec![yes, no]);
        self.truth = Some(value.clone());
        value
    }
}

fn and(mut items: Vec<String>) -> String {
    if items.len() == 1
        && let Some(item) = items.pop()
    {
        return item;
    }
    format!("({})", items.join(" and "))
}

fn or(mut items: Vec<String>) -> String {
    if items.len() == 1
        && let Some(item) = items.pop()
    {
        return item;
    }
    format!("({})", items.join(" or "))
}

fn not(item: String) -> String {
    format!("not ({item})")
}

fn error(reason: &str) -> String {
    reason.to_string()
}

fn list_items(value: &str) -> Result<Vec<&str>, String> {
    let mut start = 0;
    let mut depth = 0_u32;
    let mut items = Vec::new();
    for (i, ch) in value.char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| error(reason::FORMAT_ERROR))?
            }
            ',' if depth == 0 => {
                items.push(value.get(start..i).unwrap_or_default().trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    items.push(value.get(start..).unwrap_or_default().trim());
    if depth != 0 || items.iter().any(|s| s.is_empty()) {
        return Err(error(reason::FORMAT_ERROR));
    }
    Ok(items)
}

// Expanding a variable can introduce a negation. Resolve it before partitioning
// a list into inclusions and exclusions, rather than OR-ing a negated variable
// with positive ranges (which would silently widen the list).
fn resolve(value: &str, port: bool) -> Result<(bool, String), String> {
    let mut value = value.trim().to_string();
    let mut negated = false;
    for _ in 0..24 {
        if let Some(rest) = value.strip_prefix('!') {
            negated = !negated;
            value = rest.trim().to_string();
        } else if let Some(name) = value.strip_prefix('$') {
            if name == "HOME_NET" && !port {
                return Ok((negated, value));
            }
            value = data::variable(name, port)
                .ok_or_else(|| error(reason::PLACEHOLDER_VALUE_MISSING))?
                .to_string();
        } else {
            return Ok((negated, value));
        }
    }
    Err(error(reason::FORMAT_ERROR))
}

fn address_or_port(
    detection: &mut Detection,
    field: &str,
    value: &str,
    port: bool,
    depth: usize,
) -> Result<String, String> {
    if depth > 24 {
        return Err(error(reason::FORMAT_ERROR));
    }
    let (negated, value) = resolve(value, port)?;
    let value = value.as_str();
    if negated {
        return Ok(not(address_or_port(
            detection,
            field,
            value,
            port,
            depth + 1,
        )?));
    }
    if let Some(list) = value.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        let mut positive = Vec::new();
        let mut negative = Vec::new();
        let mut errors = Vec::new();
        // Positive nested lists share the outer list's exclusions in
        // Suricata; treating them as an independent OR would widen the set.
        let mut pending: Vec<_> = list_items(list)?
            .into_iter()
            .rev()
            .map(|item| (item.to_string(), depth + 1))
            .collect();
        while let Some((item, item_depth)) = pending.pop() {
            if item_depth > 24 {
                errors.push(error(reason::FORMAT_ERROR));
                continue;
            }
            let (is_negative, rest) = match resolve(&item, port) {
                Ok(value) => value,
                Err(e) => {
                    errors.push(e);
                    continue;
                }
            };
            if !is_negative
                && let Some(inner) = rest.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
            {
                match list_items(inner) {
                    Ok(items) => pending.extend(
                        items
                            .into_iter()
                            .rev()
                            .map(|item| (item.to_string(), item_depth + 1)),
                    ),
                    Err(e) => errors.push(e),
                }
                continue;
            }
            match address_or_port(detection, field, &rest, port, item_depth) {
                Ok(expr) => {
                    if is_negative {
                        negative.push(not(expr));
                    } else {
                        positive.push(expr);
                    }
                }
                Err(e) => errors.push(e),
            }
        }
        if let Some(e) = errors
            .iter()
            .find(|e| *e == reason::FORMAT_ERROR)
            .or(errors.first())
        {
            return Err(e.clone());
        }
        if !positive.is_empty() {
            negative.insert(0, or(positive));
        }
        return Ok(if negative.is_empty() {
            detection.truth()
        } else {
            and(negative)
        });
    }
    if value == "any" {
        return Ok(detection.truth());
    }
    if let Some(name) = value.strip_prefix('$') {
        if name == "HOME_NET" && !port {
            return Ok(detection.leaf(field, "|expand|cidr", "'%home_net%'"));
        }
        let value =
            data::variable(name, port).ok_or_else(|| error(reason::PLACEHOLDER_VALUE_MISSING))?;
        return address_or_port(detection, field, value, port, depth + 1);
    }
    if port {
        if let Some((low, high)) = value.split_once(':') {
            let parse = |s: &str, default: u16| {
                if s.is_empty() {
                    Ok(default)
                } else {
                    s.parse::<u16>().map_err(|_| error(reason::FORMAT_ERROR))
                }
            };
            let low = parse(low, 0)?;
            let high = parse(high, u16::MAX)?;
            if low > high {
                return Err(error(reason::FORMAT_ERROR));
            }
            Ok(and(vec![
                detection.leaf(field, "|gte", &low.to_string()),
                detection.leaf(field, "|lte", &high.to_string()),
            ]))
        } else {
            let n = value
                .parse::<u16>()
                .map_err(|_| error(reason::FORMAT_ERROR))?;
            Ok(detection.leaf(field, "", &n.to_string()))
        }
    } else {
        let cidr = value
            .parse::<Cidr>()
            .map_err(|_| error(reason::FORMAT_ERROR))?;
        Ok(detection.leaf(field, "|cidr", &quote(&cidr.to_string())))
    }
}

fn endpoints(
    detection: &mut Detection,
    header: &Header<'_>,
    response: bool,
    swapped: bool,
) -> Result<String, String> {
    let orig = if response ^ swapped { "resp" } else { "orig" };
    let resp = if response ^ swapped { "orig" } else { "resp" };
    let values = [
        (format!("{orig}_addr"), header.src_addr, false),
        (format!("{orig}_port"), header.src_port, true),
        (format!("{resp}_addr"), header.dst_addr, false),
        (format!("{resp}_port"), header.dst_port, true),
    ];
    let mut parts = Vec::new();
    let mut errors = Vec::new();
    for (field, value, port) in values {
        if value == "any" {
            continue;
        }
        match address_or_port(detection, &field, value, port, 0) {
            Ok(expr) => parts.push(expr),
            Err(e) => errors.push(e),
        }
    }
    if let Some(e) = errors
        .iter()
        .find(|e| *e == reason::FORMAT_ERROR)
        .or(errors.first())
    {
        return Err(e.clone());
    }
    Ok(if parts.is_empty() {
        detection.truth()
    } else {
        and(parts)
    })
}

pub(super) fn build(
    detection: &mut Detection,
    header: &Header<'_>,
    patterns: &[Pattern],
    sizes: &[(String, String)],
    direction: Direction,
    kind: &str,
) -> Result<String, String> {
    let directions: &[bool] = match direction {
        Direction::Request => &[false],
        Direction::Response => &[true],
        Direction::Both | Direction::None => &[false, true],
    };
    let mut branches = Vec::new();
    for &response in directions {
        let mut addresses = vec![endpoints(detection, header, response, false)?];
        if header.bidirectional {
            addresses.push(endpoints(detection, header, response, true)?);
        }
        let mut branch = vec![or(addresses)];
        // Only after endpoints: unresolved variables must beat unsupported regex.
        branch.extend(buffer_conditions(detection, patterns, sizes, response)?);
        let proto = match header.protocol {
            "tcp" | "tcp-pkt" | "tcp-stream" => Some(6),
            "udp" => Some(17),
            "icmp" if kind == "conn" => Some(1),
            _ => None,
        };
        if let Some(proto) = proto {
            branch.push(detection.leaf("proto", "", &proto.to_string()));
        }
        branches.push(and(branch));
    }
    Ok(or(branches))
}

fn normalized(buffer: Option<&str>, bytes: &[u8]) -> Vec<u8> {
    match buffer {
        Some("http.uri") => normalize_uri(bytes),
        Some("http.host") => normalize_host(bytes),
        _ => bytes.to_vec(),
    }
}

pub(super) fn prefilter(patterns: &[Pattern]) -> Option<Vec<u8>> {
    let literals: Vec<_> = patterns
        .iter()
        .filter_map(|p| {
            if let Value::Content(bytes) = &p.value {
                Some((p.fast, normalized(p.buffer.as_deref(), bytes)))
            } else {
                None
            }
        })
        .collect();
    literals
        .iter()
        .find(|(fast, _)| *fast)
        .or_else(|| literals.iter().max_by_key(|(_, b)| b.len()))
        .map(|(_, bytes)| bytes.clone())
}

fn buffer_conditions(
    detection: &mut Detection,
    patterns: &[Pattern],
    sizes: &[(String, String)],
    response: bool,
) -> Result<Vec<String>, String> {
    let mut by_buffer: BTreeMap<&str, Vec<&Pattern>> = BTreeMap::new();
    for pattern in patterns {
        if let Some(buffer) = pattern
            .buffer
            .as_deref()
            .and_then(|name| data::lookup(name, response))
        {
            // file.data and the legacy PCRE Q flag select the same response
            // body. Group by the resolved field so relative cursors agree.
            by_buffer.entry(buffer.field).or_default().push(pattern);
        }
    }
    let mut conditions = Vec::new();
    for (field, patterns) in by_buffer {
        // Each independent match starts a new chain. Relative matches retain the
        // previous match's cursor in this buffer, even across buffer switches.
        let mut chains: Vec<Vec<&Pattern>> = Vec::new();
        for pattern in patterns {
            if pattern.relative() {
                if let Some(chain) = chains.last_mut() {
                    chain.push(pattern);
                } else if matches!(pattern.value, Value::Content(_)) {
                    chains.push(vec![pattern]);
                } else {
                    return Err(error(reason::UNSUPPORTED_REGEX));
                }
            } else {
                chains.push(vec![pattern]);
            }
        }
        for chain in chains {
            conditions.push(chain_condition(detection, field, &chain)?);
        }
    }
    for (name, size) in sizes {
        if let Some(buffer) = data::lookup(name, response) {
            conditions.extend(length(detection, buffer.field, size)?);
        }
    }
    Ok(conditions)
}

fn length(detection: &mut Detection, field: &str, size: &str) -> Result<Vec<String>, String> {
    Ok(length_parts(size)?
        .into_iter()
        .map(|(modifier, n)| detection.leaf(field, modifier, &n.to_string()))
        .collect())
}

pub(super) fn length_parts(size: &str) -> Result<Vec<(&'static str, u64)>, String> {
    if let Some((low, high)) = size.split_once("<>").or_else(|| size.split_once('-')) {
        let low = low
            .trim()
            .parse::<u64>()
            .map_err(|_| error(reason::FORMAT_ERROR))?;
        let high = high
            .trim()
            .parse::<u64>()
            .map_err(|_| error(reason::FORMAT_ERROR))?;
        if high.checked_sub(low).is_none_or(|distance| distance < 2) {
            return Err(error(reason::FORMAT_ERROR));
        }
        return Ok(vec![("|len|gt", low), ("|len|lt", high)]);
    }
    let (modifier, value) = [
        (">=", "|len|gte"),
        ("<=", "|len|lte"),
        (">", "|len|gt"),
        ("<", "|len|lt"),
        ("!=", "|len|neq"),
        ("!", "|len|neq"),
        ("=", "|len"),
    ]
    .into_iter()
    .find_map(|(prefix, modifier)| size.strip_prefix(prefix).map(|value| (modifier, value)))
    .unwrap_or(("|len", size));
    let value = value.trim();
    let mut digits = value;
    let mut scale = 1_u64;
    if modifier == "|len" {
        for (suffix, multiplier) in [("kb", 1_024), ("mb", 1_048_576), ("gb", 1_073_741_824)] {
            if value.to_ascii_lowercase().ends_with(suffix) {
                digits = value.get(..value.len() - suffix.len()).unwrap_or_default();
                scale = multiplier;
                break;
            }
        }
    }
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(error(reason::FORMAT_ERROR));
    }
    let value = digits
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(scale))
        .ok_or_else(|| error(reason::FORMAT_ERROR))?;
    Ok(vec![(modifier, value)])
}

fn chain_condition(
    detection: &mut Detection,
    field: &str,
    chain: &[&Pattern],
) -> Result<String, String> {
    let Some(first) = chain.first() else {
        return Err(error(reason::UNSUPPORTED_REGEX));
    };
    if chain.len() == 1
        && let Value::Content(bytes) = &first.value
    {
        let bytes = normalized(first.buffer.as_deref(), bytes);
        let byte_len = u64::try_from(bytes.len()).map_err(|_| error(reason::UNSUPPORTED_REGEX))?;
        let starts = first.start || (first.offset == Some(0) && first.depth == Some(byte_len));
        let plain =
            !first.relative() && (first.offset.is_none() && first.depth.is_none() || starts);
        if plain && !(starts && first.end) {
            let modifier = if starts {
                "|startswith"
            } else if first.end {
                "|endswith"
            } else {
                "|contains"
            };
            let modifier = format!("{modifier}{}", if first.nocase { "" } else { "|cased" });
            let expr = detection.leaf(field, &modifier, &byte_value(&bytes));
            return Ok(if first.negated { not(expr) } else { expr });
        }
    }
    if chain.iter().any(|p| p.negated) {
        // Independent negative PCRE is a negated regex condition; positional
        // negative content and any negation inside a cursor chain need lookaround.
        if chain.len() == 1
            && let Value::Pcre { expression, flags } = &first.value
        {
            let (expression, caseless) = pcre_fragment(expression, flags, true)?;
            return Ok(not(detection.leaf(
                field,
                if caseless { "|re|i" } else { "|re" },
                &quote(&expression),
            )));
        }
        return Err(error(reason::UNSUPPORTED_REGEX));
    }
    // Suricata 7.0.3 detect-engine-content-inspection.c measures `within`
    // from the cursor after adding `distance`, not from the old cursor.
    let mut regex = String::new();
    let mut caseless = false;
    for (index, pattern) in chain.iter().enumerate() {
        if pattern.start && index != 0 || pattern.end && index + 1 != chain.len() {
            return Err(error(reason::UNSUPPORTED_REGEX));
        }
        match &pattern.value {
            Value::Content(bytes) => {
                let bytes = normalized(pattern.buffer.as_deref(), bytes);
                let len =
                    u64::try_from(bytes.len()).map_err(|_| error(reason::UNSUPPORTED_REGEX))?;
                let min;
                let max;
                if index == 0 {
                    if pattern.relative() {
                        if pattern.offset.is_some() || pattern.depth.is_some() {
                            return Err(error(reason::UNSUPPORTED_REGEX));
                        }
                        min = u64::try_from(pattern.distance.unwrap_or(0))
                            .map_err(|_| error(reason::UNSUPPORTED_REGEX))?;
                        max = pattern
                            .within
                            .map(|n| n.checked_sub(len).and_then(|v| min.checked_add(v)))
                            .transpose_option()?;
                        regex.push_str(r"\A");
                        regex.push_str(&gap(min, max)?);
                    } else {
                        min = pattern.offset.unwrap_or(0);
                        max = pattern
                            .depth
                            .map(|n| n.checked_sub(len).and_then(|v| min.checked_add(v)))
                            .transpose_option()?;
                        if pattern.start || pattern.offset.is_some() || pattern.depth.is_some() {
                            regex.push_str(r"\A");
                        }
                        if pattern.start {
                            if min != 0 {
                                return Err(error(reason::UNSUPPORTED_REGEX));
                            }
                        } else if pattern.offset.is_some() || pattern.depth.is_some() {
                            regex.push_str(&gap(min, max)?);
                        }
                    }
                } else {
                    if pattern.offset.is_some() || pattern.depth.is_some() {
                        return Err(error(reason::UNSUPPORTED_REGEX));
                    }
                    min = u64::try_from(pattern.distance.unwrap_or(0))
                        .map_err(|_| error(reason::UNSUPPORTED_REGEX))?;
                    max = pattern
                        .within
                        .map(|n| n.checked_sub(len).and_then(|v| min.checked_add(v)))
                        .transpose_option()?;
                    regex.push_str(&gap(min, max)?);
                }
                let only = chain.len() == 1 && pattern.nocase;
                caseless |= only;
                for byte in bytes {
                    if pattern.nocase && !only && byte.is_ascii_alphabetic() {
                        let _ = write!(
                            regex,
                            "[{}{}]",
                            char::from(byte.to_ascii_lowercase()),
                            char::from(byte.to_ascii_uppercase())
                        );
                    } else {
                        let _ = write!(regex, "\\x{byte:02x}");
                    }
                }
            }
            Value::Pcre { expression, flags } => {
                if index > 0 {
                    regex.push_str(&gap(0, None)?);
                }
                let (fragment, ignore_case) = pcre_fragment(expression, flags, chain.len() == 1)?;
                caseless |= ignore_case;
                regex.push_str(&fragment);
            }
        }
        if pattern.end {
            regex.push_str(r"\z");
        }
    }
    Ok(detection.leaf(
        field,
        if caseless { "|re|i" } else { "|re" },
        &quote(&regex),
    ))
}

// Distinguishes an absent upper bound from an arithmetic underflow.
trait TransposeOption {
    fn transpose_option(self) -> Result<Option<u64>, String>;
}
impl TransposeOption for Option<Option<u64>> {
    fn transpose_option(self) -> Result<Option<u64>, String> {
        match self {
            None => Ok(None),
            Some(Some(n)) => Ok(Some(n)),
            Some(None) => Err(error(reason::UNSUPPORTED_REGEX)),
        }
    }
}

fn gap(min: u64, max: Option<u64>) -> Result<String, String> {
    if max.is_some_and(|max| max < min) {
        return Err(error(reason::UNSUPPORTED_REGEX));
    }
    Ok(match max {
        Some(0) if min == 0 => String::new(),
        Some(max) if max == min => format!("{ANY_BYTE}{{{min}}}"),
        Some(max) => format!("{ANY_BYTE}{{{min},{max}}}"),
        None => format!("{ANY_BYTE}{{{min},}}"),
    })
}

fn pcre_fragment(expr: &str, flags: &str, only: bool) -> Result<(String, bool), String> {
    if flags
        .chars()
        .any(|c| !matches!(c, 'i' | 'm' | 's' | 'R' | 'O') && data::pcre_buffer(c).is_none())
    {
        return Err(error(reason::UNSUPPORTED_REGEX));
    }
    // vectorscan rejects backreferences, lookaround and unsupported inline
    // constructs. Preserve the expression and let the common compiler decide.
    let mut scope = String::new();
    if flags.contains('i') && !only {
        scope.push('i');
    }
    if flags.contains('m') {
        scope.push('m');
    }
    if flags.contains('s') {
        scope.push('s');
    }
    let fragment = if scope.is_empty() {
        format!("(?:{expr})")
    } else {
        format!("(?{scope}:{expr})")
    };
    Ok((fragment, only && flags.contains('i')))
}

pub(super) fn partial_header(bytes: &[u8]) -> bool {
    bytes.iter().enumerate().any(|(i, &b)| {
        if b != b':' || i + 1 == bytes.len() {
            return false;
        }
        let before = bytes.get(..i).unwrap_or_default();
        let start = before
            .iter()
            .rposition(|b| b.is_ascii_whitespace() || *b == b':')
            .map_or(0, |p| p + 1);
        let name = before.get(start..).unwrap_or_default();
        !name.is_empty()
            && !HEADER_BLOCK_HEADERS
                .iter()
                .any(|known| name.eq_ignore_ascii_case(known.as_bytes()))
    })
}
