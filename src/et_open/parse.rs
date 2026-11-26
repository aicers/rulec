//! A conservative Suricata rule parser. No Suricata implementation is copied.

use super::{
    conditions,
    data::{self, Direction},
};
use crate::{Model, Rule, reason};

#[derive(Clone, Debug)]
pub(super) enum Value {
    Content(Vec<u8>),
    Pcre { expression: String, flags: String },
}

#[derive(Clone, Debug)]
pub(super) struct Pattern {
    pub buffer: Option<String>,
    pub value: Value,
    pub negated: bool,
    pub nocase: bool,
    pub start: bool,
    pub end: bool,
    pub offset: Option<u64>,
    pub depth: Option<u64>,
    pub distance: Option<i64>,
    pub within: Option<u64>,
    pub fast: bool,
}

impl Pattern {
    fn new(buffer: Option<String>, value: Value, negated: bool) -> Self {
        Self {
            buffer,
            value,
            negated,
            nocase: false,
            start: false,
            end: false,
            offset: None,
            depth: None,
            distance: None,
            within: None,
            fast: false,
        }
    }

    pub(super) fn relative(&self) -> bool {
        self.distance.is_some()
            || self.within.is_some()
            || matches!(&self.value, Value::Pcre { flags, .. } if flags.contains('R'))
    }
}

pub(super) struct Header<'a> {
    pub protocol: &'a str,
    pub src_addr: &'a str,
    pub src_port: &'a str,
    pub bidirectional: bool,
    pub dst_addr: &'a str,
    pub dst_port: &'a str,
}

#[derive(Default)]
struct Problems(Vec<String>);

impl Problems {
    fn add(&mut self, reason: &str) {
        self.0.push(reason.to_string());
    }

    fn named(&mut self, reason: &str, name: &str) {
        self.0.push(format!("{reason}:{name}"));
    }

    fn first(&self) -> Option<&str> {
        self.0.iter().min_by_key(|r| rank(r)).map(String::as_str)
    }
}

fn position_error(value: &str) -> &'static str {
    // byte_extract variables are valid Suricata position arguments. Their
    // value needs packet inspection; do not let parsing one as an integer
    // incorrectly outrank the rule's needs_state or packet-condition reason.
    if value
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphabetic)
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        reason::UNSUPPORTED_REGEX
    } else {
        reason::FORMAT_ERROR
    }
}

fn rank(value: &str) -> usize {
    let base = value.split(':').next().unwrap_or(value);
    [
        reason::FORMAT_ERROR,
        reason::MISSING_ATTRIBUTE,
        reason::NEEDS_STATE,
        reason::PAYLOAD_OR_PACKET_CONDITION,
        reason::UNSUPPORTED_KEYWORD,
        reason::UNSUPPORTED_BUFFER,
        reason::RAW_PAYLOAD,
        reason::MIXED_KINDS,
        reason::MIXED_DIRECTIONS,
        reason::NO_RESPONSE_VALUE,
        reason::DIRECTION_MISMATCH,
        reason::PLACEHOLDER_VALUE_MISSING,
        reason::UNSUPPORTED_REGEX,
    ]
    .iter()
    .position(|r| *r == base)
    .unwrap_or(usize::MAX)
}

/// Joins physical lines and preserves the first physical line number.
pub(super) fn lines(bytes: &[u8]) -> Vec<(usize, Vec<u8>)> {
    let mut result = Vec::new();
    let mut pending = Vec::new();
    let mut first = 0;
    for (index, line) in bytes.split(|b| *b == b'\n').enumerate() {
        let line = line.trim_ascii();
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }
        if pending.is_empty() {
            first = index + 1;
        }
        if let Some(part) = line.strip_suffix(b"\\") {
            pending.extend_from_slice(part);
            pending.push(b' ');
        } else {
            pending.extend_from_slice(line);
            result.push((first, std::mem::take(&mut pending)));
        }
    }
    if !pending.is_empty() {
        result.push((first, pending));
    }
    result
}

fn options(text: &str) -> (Vec<(&str, &str)>, bool) {
    let mut quoted = false;
    let mut escaped = false;
    let mut start = 0;
    let mut result = Vec::new();
    for (index, ch) in text.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => quoted = !quoted,
            ';' if !quoted => {
                let option = text.get(start..index).unwrap_or_default().trim();
                if !option.is_empty() {
                    result.push(
                        option
                            .split_once(':')
                            .map_or((option, ""), |(k, v)| (k.trim(), v.trim())),
                    );
                }
                start = index + 1;
            }
            _ => {}
        }
    }
    (
        result,
        !quoted && !escaped && text.get(start..).unwrap_or_default().trim().is_empty(),
    )
}

fn rule_options(text: &str) -> (Vec<(&str, &str)>, bool) {
    let Some((_, rest)) = text.split_once('(') else {
        return (Vec::new(), false);
    };
    let (body, closed) = rest
        .trim_end()
        .strip_suffix(')')
        .map_or((rest, false), |s| (s, true));
    let (options, valid) = options(body);
    (options, closed && valid)
}

pub(super) fn sid(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    rule_options(&text)
        .0
        .iter()
        .find(|(k, _)| *k == "sid")
        .and_then(|(_, v)| v.parse::<u64>().ok())
        .map(|n| n.to_string())
}

pub(super) fn updated_at(bytes: &[u8]) -> Option<jiff::civil::Date> {
    let text = String::from_utf8_lossy(bytes);
    rule_options(&text)
        .0
        .iter()
        .filter(|(k, _)| *k == "metadata")
        .flat_map(|(_, value)| value.split(','))
        .filter_map(|item| {
            let mut words = item.split_whitespace();
            match (words.next(), words.next(), words.next()) {
                (Some("updated_at"), Some(value), None) => super::date(value),
                _ => None,
            }
        })
        .max()
}

fn header(text: &str) -> Option<Header<'_>> {
    let text = text.split_once('(')?.0;
    let mut words = Vec::new();
    let mut depth = 0_u32;
    let mut start = None;
    for (index, ch) in text.char_indices() {
        if !ch.is_whitespace() && start.is_none() {
            start = Some(index);
        }
        match ch {
            '[' => depth += 1,
            ']' => depth = depth.checked_sub(1)?,
            _ => {}
        }
        if ch.is_whitespace()
            && depth == 0
            && let Some(begin) = start.take()
        {
            words.push(text.get(begin..index)?);
        }
    }
    if let Some(begin) = start {
        words.push(text.get(begin..)?);
    }
    let [
        action,
        protocol,
        src_addr,
        src_port,
        arrow,
        dst_addr,
        dst_port,
    ] = words.as_slice()
    else {
        return None;
    };
    if depth != 0
        || !matches!(
            *action,
            "alert" | "drop" | "pass" | "reject" | "rejectsrc" | "rejectdst" | "rejectboth"
        )
        || !matches!(*arrow, "->" | "<>")
    {
        return None;
    }
    Some(Header {
        protocol,
        src_addr,
        src_port,
        bidirectional: *arrow == "<>",
        dst_addr,
        dst_port,
    })
}

fn quoted(value: &str) -> Option<&str> {
    value.strip_prefix('"')?.strip_suffix('"')
}

fn unescape(value: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = quoted(value)?.chars();
    while let Some(ch) = chars.next() {
        out.push(if ch == '\\' { chars.next()? } else { ch });
    }
    Some(out)
}

fn content(value: &str) -> Option<(Vec<u8>, bool)> {
    let (value, negated) = value
        .strip_prefix('!')
        .map_or((value, false), |v| (v.trim(), true));
    let text = quoted(value)?;
    let mut bytes = Vec::new();
    let mut input = text.as_bytes().iter().copied();
    while let Some(b) = input.next() {
        match b {
            b'|' => {
                let mut hex = String::new();
                loop {
                    let b = input.next()?;
                    if b == b'|' {
                        break;
                    }
                    if !b.is_ascii_whitespace() && b != b',' {
                        hex.push(char::from(b));
                    }
                }
                if hex.is_empty() || !hex.len().is_multiple_of(2) {
                    return None;
                }
                for pair in hex.as_bytes().as_chunks::<2>().0 {
                    let pair = std::str::from_utf8(pair).ok()?;
                    bytes.push(u8::from_str_radix(pair, 16).ok()?);
                }
            }
            b'\\' => {
                let b = input.next()?;
                if !matches!(b, b'\\' | b'"' | b';' | b':') {
                    return None;
                }
                bytes.push(b);
            }
            b'"' => return None,
            _ => bytes.push(b),
        }
    }
    if bytes.is_empty() {
        return None;
    }
    Some((bytes, negated))
}

fn pcre(value: &str) -> Option<(Value, bool)> {
    let (value, negated) = value
        .strip_prefix('!')
        .map_or((value, false), |v| (v.trim(), true));
    let text = quoted(value)?.strip_prefix('/')?;
    let (expr, flags) = text.rsplit_once('/')?;
    if !flags.bytes().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    Some((
        Value::Pcre {
            expression: expr.replace("\\\"", "\""),
            flags: flags.to_string(),
        },
        negated,
    ))
}

fn metadata(options: &[(&str, &str)], key: &str) -> Vec<String> {
    options
        .iter()
        .filter(|(k, _)| *k == "metadata")
        .flat_map(|(_, value)| value.split(','))
        .filter_map(|item| {
            let (k, v) = item.trim().split_once(char::is_whitespace)?;
            (k == key).then(|| v.trim().to_string())
        })
        .collect()
}

pub(super) fn convert(bytes: &[u8], model: Model) -> Result<(Rule, bool), String> {
    let text = std::str::from_utf8(bytes).map_err(|_| reason::FORMAT_ERROR.to_string())?;
    let header = header(text).ok_or_else(|| reason::FORMAT_ERROR.to_string())?;
    let (options, valid) = rule_options(text);
    let mut problems = Problems::default();
    if !valid
        || options.iter().any(|(key, _)| {
            !key.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
                || !key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
        })
    {
        problems.add(reason::FORMAT_ERROR);
    }
    let get = |key: &str| options.iter().find(|(k, _)| *k == key).map(|(_, v)| *v);
    for key in ["sid", "msg", "rev"] {
        if options.iter().filter(|(k, _)| *k == key).count() > 1 {
            problems.add(reason::FORMAT_ERROR);
        }
    }
    let title = get("msg").and_then(unescape);
    if get("msg").is_some() && title.is_none() {
        problems.add(reason::FORMAT_ERROR);
    }
    let sid = get("sid").and_then(|v| v.parse::<u64>().ok());
    if get("sid").is_some() && sid.is_none() {
        problems.add(reason::FORMAT_ERROR);
    }
    if get("rev").is_some_and(|v| v.parse::<u64>().is_err()) {
        problems.add(reason::FORMAT_ERROR);
    }
    if title.is_none() || sid.is_none() {
        problems.add(reason::MISSING_ATTRIBUTE);
    }
    let mut patterns: Vec<Pattern> = Vec::new();
    let mut buffers = Vec::new();
    let mut sizes: Vec<(String, String)> = Vec::new();
    let mut sticky: Option<String> = None;
    let mut request = false;
    let mut response = false;
    for &(key, value) in &options {
        if let Some((name, modifier)) = data::buffer(key).filter(|_| {
            !matches!(
                key,
                "tcp.mss" | "tcp.flags" | "tcp.hdr" | "ipv4.hdr" | "ipv6.hdr"
            )
        }) {
            // Dotted names also occur on non-buffer keywords (tls.version,
            // for example). An unknown name with an argument is not a known
            // no-argument buffer selector, so report it as an unknown keyword.
            if data::lookup(name, false).is_none() && !value.is_empty() {
                problems.named(reason::UNSUPPORTED_KEYWORD, key);
                continue;
            }
            buffers.push(name.to_string());
            if !value.is_empty() {
                problems.add(reason::FORMAT_ERROR);
            }
            if modifier {
                if let Some(last) = patterns
                    .iter_mut()
                    .rev()
                    .find(|p| matches!(p.value, Value::Content(_)))
                {
                    if last.buffer.is_some() {
                        problems.add(reason::FORMAT_ERROR);
                    }
                    last.buffer = Some(name.to_string());
                } else {
                    problems.add(reason::FORMAT_ERROR);
                }
            } else {
                sticky = Some(name.to_string());
            }
            continue;
        }
        match key {
            "content" => match content(value) {
                Some((bytes, negated)) => {
                    patterns.push(Pattern::new(sticky.clone(), Value::Content(bytes), negated))
                }
                None => problems.add(reason::FORMAT_ERROR),
            },
            "pcre" => match pcre(value) {
                Some((parsed, negated)) => {
                    let mut buffer = sticky.clone();
                    if let Value::Pcre { flags, .. } = &parsed {
                        let mut flag_buffer = None;
                        for flag in flags.chars() {
                            if let Some(name) = data::pcre_buffer(flag) {
                                buffers.push(name.to_string());
                                if flag_buffer.is_some_and(|b| b != name)
                                    || sticky.as_deref().is_some_and(|b| {
                                        b != name && !(b == "file.data" && flag == 'Q')
                                    })
                                {
                                    problems.add(reason::FORMAT_ERROR);
                                }
                                flag_buffer = Some(name);
                                buffer = Some(name.to_string());
                            } else if !matches!(flag, 'i' | 'm' | 's' | 'R' | 'O') {
                                problems.add(reason::UNSUPPORTED_REGEX);
                            }
                        }
                    }
                    patterns.push(Pattern::new(buffer, parsed, negated));
                }
                None => problems.add(reason::FORMAT_ERROR),
            },
            "nocase" | "startswith" | "endswith" | "fast_pattern" | "offset" | "depth"
            | "distance" | "within" => {
                let Some(last) = patterns
                    .iter_mut()
                    .rev()
                    .find(|p| matches!(p.value, Value::Content(_)))
                else {
                    problems.add(reason::FORMAT_ERROR);
                    continue;
                };
                if matches!(key, "nocase" | "startswith" | "endswith") && !value.is_empty() {
                    problems.add(reason::FORMAT_ERROR);
                }
                match key {
                    "nocase" => last.nocase = true,
                    "startswith" => last.start = true,
                    "endswith" => last.end = true,
                    "fast_pattern" => last.fast = true,
                    "distance" => match value.parse() {
                        Ok(n) => last.distance = Some(n),
                        Err(_) => problems.add(position_error(value)),
                    },
                    _ => {
                        if let Ok(n) = value.parse() {
                            match key {
                                "offset" => last.offset = Some(n),
                                "depth" => last.depth = Some(n),
                                "within" => last.within = Some(n),
                                _ => {}
                            }
                        } else {
                            problems.add(position_error(value));
                        }
                    }
                }
            }
            "isdataat" => {
                if value.split(',').map(str::trim).collect::<Vec<_>>() == ["!1", "relative"] {
                    if let Some(last) = patterns.last_mut() {
                        last.end = true;
                    } else {
                        problems.add(reason::FORMAT_ERROR);
                    }
                } else {
                    problems.add(reason::PAYLOAD_OR_PACKET_CONDITION);
                }
            }
            "bsize" => {
                if conditions::length_parts(value).is_err() {
                    problems.add(reason::FORMAT_ERROR);
                }
                if let Some(buffer) = &sticky {
                    sizes.push((buffer.clone(), value.to_string()));
                } else {
                    problems.add(reason::RAW_PAYLOAD);
                }
            }
            "urilen" => {
                let mut args = value.split(',').map(str::trim);
                let size = args.next().unwrap_or_default();
                if conditions::length_parts(size).is_err() {
                    problems.add(reason::FORMAT_ERROR);
                }
                let buffer = match args.next() {
                    None | Some("norm") => "http.uri",
                    Some("raw") => "http.uri.raw",
                    _ => {
                        problems.add(reason::FORMAT_ERROR);
                        "http.uri"
                    }
                };
                if args.next().is_some() {
                    problems.add(reason::FORMAT_ERROR);
                }
                buffers.push(buffer.to_string());
                sizes.push((buffer.to_string(), size.to_string()));
            }
            "flow" => {
                for word in value.split(',').map(str::trim) {
                    match word {
                        "to_server" | "from_client" => request = true,
                        "to_client" | "from_server" => response = true,
                        "established" | "not_established" | "stateless" | "only_stream"
                        | "no_stream" | "only_frag" | "no_frag" => {}
                        _ => problems.add(reason::FORMAT_ERROR),
                    }
                }
            }
            "pkt_data" => {
                sticky = None;
            }
            "flowbits" | "flowint" | "xbits" => problems.add(reason::NEEDS_STATE),
            "byte_test" | "byte_jump" | "byte_extract" | "byte_math" | "dsize"
            | "base64_decode" | "base64_data" | "asn1" | "stream_size" | "ttl" | "flags"
            | "ip_proto" | "itype" | "icode" | "window" | "seq" | "ack" | "fragbits"
            | "fragoffset" | "id" | "sameip" | "ipopts" | "geoip" | "tcp.mss" | "tcp.flags"
            | "tcp.hdr" | "ipv4.hdr" | "ipv6.hdr" | "icmp_id" | "icmp_seq" => {
                problems.add(reason::PAYLOAD_OR_PACKET_CONDITION)
            }
            "threshold" | "detection_filter" | "msg" | "sid" | "rev" | "gid" | "classtype"
            | "reference" | "metadata" | "priority" | "target" | "tag" => {}
            _ => problems.named(reason::UNSUPPORTED_KEYWORD, key),
        }
    }
    for pattern in &patterns {
        if pattern.start
            && (pattern.offset.is_some() || pattern.depth.is_some() || pattern.relative())
        {
            problems.add(reason::FORMAT_ERROR);
        }
        if pattern.relative() && (pattern.offset.is_some() || pattern.depth.is_some()) {
            problems.add(reason::FORMAT_ERROR);
        }
    }
    let mut kind = None;
    let mut buffer_request = false;
    let mut buffer_response = false;
    for name in &buffers {
        if let Some(buffer) = data::lookup(name, false) {
            if kind.is_some_and(|kind| kind != buffer.kind) {
                problems.add(reason::MIXED_KINDS);
            }
            kind = Some(buffer.kind);
            buffer_request |= buffer.direction == Direction::Request;
            buffer_response |= buffer.direction == Direction::Response;
        } else {
            problems.named(reason::UNSUPPORTED_BUFFER, name);
        }
    }
    if patterns.iter().any(|p| p.buffer.is_none()) {
        problems.add(reason::RAW_PAYLOAD);
    }
    let kind = kind.unwrap_or("conn");
    let protocol_matches = if buffers.is_empty() {
        matches!(header.protocol, "ip" | "tcp" | "udp" | "icmp")
    } else {
        matches!(
            header.protocol,
            "ip" | "tcp" | "udp" | "tcp-pkt" | "tcp-stream"
        ) || header.protocol == kind
            || (header.protocol == "http1" && kind == "http")
    };
    if !protocol_matches {
        problems.add(reason::MIXED_KINDS);
    }
    let direction = if request && response {
        problems.add(reason::MIXED_DIRECTIONS);
        Direction::Request
    } else if request {
        Direction::Request
    } else if response {
        Direction::Response
    } else if buffer_request && buffer_response {
        problems.add(reason::MIXED_DIRECTIONS);
        Direction::Request
    } else if buffer_request {
        Direction::Request
    } else if buffer_response {
        Direction::Response
    } else if buffers.is_empty() {
        Direction::None
    } else {
        Direction::Both
    };
    for name in &buffers {
        if let Some(buffer) = data::lookup(name, false) {
            if direction == Direction::Response && buffer.request_value_only {
                problems.add(reason::NO_RESPONSE_VALUE);
            } else if matches!(
                (direction, buffer.direction),
                (Direction::Request, Direction::Response)
                    | (Direction::Response, Direction::Request)
            ) {
                problems.add(reason::DIRECTION_MISMATCH);
            }
        }
    }
    // Header syntax and missing placeholders are checked even when an earlier
    // buffer problem exists, so a malformed address still wins by precedence.
    let mut detection = conditions::Detection::default();
    let condition = conditions::build(&mut detection, &header, &patterns, &sizes, direction, kind);
    if let Err(error) = &condition {
        problems.add(error);
    }
    if let Some(problem) = problems.first() {
        return Err(problem.to_string());
    }
    let condition = condition?;
    let sid = sid.ok_or_else(|| reason::MISSING_ATTRIBUTE.to_string())?;
    let title = title.ok_or_else(|| reason::MISSING_ATTRIBUTE.to_string())?;
    let license = if title.starts_with("GPL")
        || (1..=3464).contains(&sid)
        || (100_000_000..=100_000_908).contains(&sid)
    {
        "GPL-2.0"
    } else {
        "BSD"
    };
    let mut yaml = format!(
        "title: {}\nsource: et_open\nsource_rule_id: '{sid}'\nmodel: {}\nlicense: '{license}'\n",
        conditions::quote(&title),
        model.as_str()
    );
    if let Some(rev) = get("rev") {
        yaml.push_str(&format!("source_rule_rev: {rev}\n"));
    }
    if let Some(class) = get("classtype") {
        yaml.push_str(&format!("classification: {}\n", conditions::quote(class)));
    }
    if let Some(severity) = metadata(&options, "signature_severity").first() {
        yaml.push_str(&format!("severity: {}\n", conditions::quote(severity)));
    }
    let tactics: Vec<_> = metadata(&options, "mitre_tactic_id")
        .into_iter()
        .filter(|v| {
            v.strip_prefix("TA")
                .is_some_and(|n| n.len() == 4 && n.bytes().all(|b| b.is_ascii_digit()))
        })
        .collect();
    let techniques: Vec<_> = metadata(&options, "mitre_technique_id")
        .into_iter()
        .map(|v| v.replace('_', "."))
        .filter(|v| {
            let Some(rest) = v.strip_prefix('T') else {
                return false;
            };
            let (main, sub) = rest
                .split_once('.')
                .map_or((rest, None), |(m, s)| (m, Some(s)));
            main.len() == 4
                && main.bytes().all(|b| b.is_ascii_digit())
                && sub.is_none_or(|s| s.len() == 3 && s.bytes().all(|b| b.is_ascii_digit()))
        })
        .collect();
    for (key, values) in [("tactics", tactics), ("techniques", techniques)] {
        if !values.is_empty() {
            yaml.push_str(&format!(
                "{key}: [{}]\n",
                values
                    .iter()
                    .map(|s| conditions::quote(s))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    let references: Vec<_> = options
        .iter()
        .filter(|(k, _)| *k == "reference")
        .map(|(_, value)| {
            if let Some((kind, suffix)) = value.split_once(',')
                && let Some(prefix) = data::reference(kind.trim())
            {
                format!("{prefix}{}", suffix.trim())
            } else {
                value.to_string()
            }
        })
        .collect();
    if !references.is_empty() {
        yaml.push_str(&format!(
            "references: [{}]\n",
            references
                .iter()
                .map(|s| conditions::quote(s))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if let Some(bytes) = conditions::prefilter(&patterns) {
        yaml.push_str(&format!("prefilter: {}\n", conditions::byte_value(&bytes)));
    }
    yaml.push_str(&format!(
        "logsource:\n  category: {kind}\ndetection:\n{}  condition: {condition}\n",
        detection.yaml
    ));
    let rule = Rule::from_yaml(&yaml).map_err(|error| error.reason().to_string())?;
    let partial_header = patterns.iter().any(|p| {
        p.buffer.as_deref() == Some("http.header")
            && matches!(&p.value, Value::Content(bytes) if conditions::partial_header(bytes))
    });
    Ok((rule, partial_header))
}
