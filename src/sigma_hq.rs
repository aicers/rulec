//! Converts the two SigmaHQ archive sources without accessing the network.

use std::{
    collections::BTreeSet,
    io::{Cursor, Read},
};

use jiff::civil::Date;
use zip::ZipArchive;

use crate::{
    Blocklist, CompileError, Conversion, ConversionSummary, OrderKey, ReadError, Rule, Source,
    SourceVersion, compile, content_digest, detection,
    expr::{Expr, Piece},
    reason,
    sigma_hq_mapping::{MAPPINGS, Mapping, get, text},
    yaml::{self, Node},
};

/// An archive-level error converting or inspecting a SigmaHQ source.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SigmaHqError {
    /// The bytes or an archive member cannot be read as a zip.
    #[error("cannot read the zip: {0}")]
    NotAZip(String),
    /// The selected source directory contains no rule files.
    #[error("the zip contains no rule files")]
    NoRuleFiles,
    /// The release has no complete, valid `version.txt`.
    #[error("the zip carries no version information")]
    NoVersionInfo,
    /// The GitHub archive does not identify one commit and timestamp.
    #[error(
        "the zip carries no commit information; upload the zip exactly as downloaded from GitHub, unmodified"
    )]
    NoCommitInfo,
    /// A whole vectorscan field database failed to compile.
    #[error(transparent)]
    Compile(#[from] CompileError),
}

/// Converts the `rules/` files in a SigmaHQ release zip.
///
/// `release_name` is the caller's GitHub `tag_name`, if known.
///
/// # Errors
///
/// Returns an archive/version error or a whole-database compilation error.
/// Individual rule failures are recorded in the returned summary.
pub fn convert_sigma_hq(
    zip: &[u8],
    release_name: Option<&str>,
    blocklist: &Blocklist,
) -> Result<Conversion, SigmaHqError> {
    let archive = unpack(zip, Source::SigmaHq, release_name)?;
    convert(archive, Source::SigmaHq, blocklist)
}

/// Reads a SigmaHQ release's version and content digest without converting rules.
///
/// # Errors
///
/// Returns the same archive/version errors as [`convert_sigma_hq`].
pub fn read_sigma_hq_version(
    zip: &[u8],
    release_name: Option<&str>,
) -> Result<SourceVersion, SigmaHqError> {
    Ok(unpack(zip, Source::SigmaHq, release_name)?.version)
}

/// Converts `rules-emerging-threats/` in an unmodified GitHub source zip.
///
/// # Errors
///
/// Returns an archive/commit error or a whole-database compilation error.
/// Individual rule failures are recorded in the returned summary.
pub fn convert_sigma_hq_emerging(
    zip: &[u8],
    blocklist: &Blocklist,
) -> Result<Conversion, SigmaHqError> {
    let archive = unpack(zip, Source::SigmaHqEmerging, None)?;
    convert(archive, Source::SigmaHqEmerging, blocklist)
}

/// Reads a GitHub source zip's commit version and digest without converting rules.
///
/// # Errors
///
/// Returns the same archive/commit errors as [`convert_sigma_hq_emerging`].
pub fn read_sigma_hq_emerging_version(zip: &[u8]) -> Result<SourceVersion, SigmaHqError> {
    Ok(unpack(zip, Source::SigmaHqEmerging, None)?.version)
}

struct Archive {
    files: Vec<(String, Vec<u8>)>,
    version: SourceVersion,
}

fn bad_zip(error: impl std::fmt::Display) -> SigmaHqError {
    SigmaHqError::NotAZip(error.to_string())
}

fn unpack(
    bytes: &[u8],
    source: Source,
    release_name: Option<&str>,
) -> Result<Archive, SigmaHqError> {
    let mut zip = ZipArchive::new(Cursor::new(bytes)).map_err(bad_zip)?;
    let directory = if source == Source::SigmaHq {
        "rules/"
    } else {
        "rules-emerging-threats/"
    };
    let names: Vec<_> = zip.file_names().collect();
    let roots: BTreeSet<_> = names
        .iter()
        .filter_map(|name| name.split_once('/').map(|(root, _)| root))
        .collect();
    let prefix = if names.iter().any(|name| name.starts_with(directory)) {
        String::new()
    } else if roots.len() == 1 {
        format!("{}/", roots.first().copied().unwrap_or_default())
    } else {
        String::new()
    };
    let selected = format!("{prefix}{directory}");
    let version_path = format!("{prefix}version.txt");
    let comment = zip.comment().to_vec();
    let mut timestamps = BTreeSet::new();
    let mut missing_time = false;
    let mut files = Vec::new();
    let mut version_text = None;
    for index in 0..zip.len() {
        // Excluded members need no decoder, even if their codec is disabled.
        let file = zip.by_index_raw(index).map_err(bad_zip)?;
        if source == Source::SigmaHqEmerging {
            match utc_mtime(file.extra_data().unwrap_or_default()) {
                Some(seconds) => {
                    timestamps.insert(seconds);
                }
                None => missing_time = true,
            }
        }
        if file.is_dir() {
            continue;
        }
        let relative = file
            .name()
            .strip_prefix(&selected)
            .filter(|path| {
                let mut parts = path.split('/').peekable();
                while let Some(part) = parts.next() {
                    if part.is_empty()
                        || part == "."
                        || part == ".."
                        || part.contains('\\')
                        || (source == Source::SigmaHq
                            && part == "deprecated"
                            && parts.peek().is_some())
                    {
                        return false;
                    }
                }
                path.ends_with(".yml") || path.ends_with(".yaml")
            })
            .map(str::to_string);
        let is_version = source == Source::SigmaHq && file.name() == version_path;
        if relative.is_none() && !is_version {
            continue;
        }
        drop(file);
        let mut file = zip.by_index(index).map_err(bad_zip)?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)
            .map_err(|e| bad_zip(format!("reading {}: {e}", file.name())))?;
        if is_version {
            version_text = String::from_utf8(contents).ok()
        } else if let Some(path) = relative {
            files.push((path, contents))
        }
    }
    if files.is_empty() {
        return Err(SigmaHqError::NoRuleFiles);
    }
    files.sort_unstable_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let (version, date) = if source == Source::SigmaHq {
        let contents = version_text.ok_or(SigmaHqError::NoVersionInfo)?;
        let line = |key: &str| {
            contents
                .lines()
                .find_map(|line| line.strip_prefix(key))
                .map(str::trim)
                .filter(|s| !s.is_empty())
        };
        let label = line("Label:").ok_or(SigmaHqError::NoVersionInfo)?;
        let date_text = line("Release Date:").ok_or(SigmaHqError::NoVersionInfo)?;
        let date = strict_date(date_text).ok_or(SigmaHqError::NoVersionInfo)?;
        (format!("{label} ({date})"), date)
    } else {
        let sha = std::str::from_utf8(&comment).map_err(|_| SigmaHqError::NoCommitInfo)?;
        if sha.len() != 40
            || !sha.bytes().all(|b| b.is_ascii_hexdigit())
            || missing_time
            || timestamps.len() != 1
        {
            return Err(SigmaHqError::NoCommitInfo);
        }
        let seconds = timestamps
            .first()
            .copied()
            .ok_or(SigmaHqError::NoCommitInfo)?;
        let date = jiff::Timestamp::from_second(i64::from(seconds))
            .map_err(|_| SigmaHqError::NoCommitInfo)?
            .to_zoned_datetime(jiff::tz::TimeZone::UTC)
            .date();
        (
            format!(
                "master@{} ({date})",
                sha.get(..7).ok_or(SigmaHqError::NoCommitInfo)?
            ),
            date,
        )
    };
    let version = SourceVersion {
        version,
        release_name: release_name.map(str::to_string),
        order_key: OrderKey { date, number: None },
        content_digest: content_digest(files.iter().map(|(p, b)| (p, b))),
    };
    Ok(Archive { files, version })
}

fn strict_date(text: &str) -> Option<Date> {
    let date: Date = text.parse().ok()?;
    (date.to_string() == text && text.len() == 10).then_some(date)
}

/// Reads the extended timestamp's UTC mtime, never the timezone-less DOS time.
/// The actual r2026-07-01 release has no extras (it uses version.txt).
/// Both archive/876eb7b8cfbcce4d690dff8c3439ecdc7dc8175f.zip and the
/// master zip observed on 2026-11-27 carry 0x5455, flags=1, on every
/// entry, all with the same mtime. No DOS fallback is needed or guessed.
fn utc_mtime(mut extra: &[u8]) -> Option<u32> {
    let mut mtime = None;
    while !extra.is_empty() {
        let header = extra.get(..4)?;
        let tag = u16::from_le_bytes(header.get(..2)?.try_into().ok()?);
        let size = usize::from(u16::from_le_bytes(header.get(2..4)?.try_into().ok()?));
        let payload = extra.get(4..4 + size)?;
        extra = extra.get(4 + size..)?;
        if tag == 0x5455 {
            if mtime.is_some() || payload.first()? & 1 == 0 {
                return None;
            }
            mtime = Some(u32::from_le_bytes(payload.get(1..5)?.try_into().ok()?));
        }
    }
    mtime
}

fn convert(
    archive: Archive,
    source: Source,
    blocklist: &Blocklist,
) -> Result<Conversion, SigmaHqError> {
    let mut summary = ConversionSummary::new(source, archive.version);
    let mut rules = Vec::new();
    for (path, contents) in archive.files {
        let node = std::str::from_utf8(&contents)
            .map_err(|e| e.to_string())
            .and_then(yaml::load);
        let node = match node {
            Ok(node) => node,
            Err(_) => {
                summary.record_dropped(reason::FORMAT_ERROR, &path);
                continue;
            }
        };
        if matches!(
            get(&node, "status").and_then(text),
            Some("deprecated" | "unsupported")
        ) {
            continue;
        }
        let source_id = get(&node, "id").and_then(text).filter(|s| !s.is_empty());
        let id = source_id.unwrap_or(&path);
        if source_id.is_some_and(|id| blocklist.contains(source, id)) {
            summary.record_dropped(reason::BLOCKLIST, id);
            continue;
        }
        match convert_rule(&node, source) {
            Ok((rule, unmapped)) => {
                let (some, under_not) = never_usage(&rule.detection, false);
                summary.partly_never_true += usize::from(some);
                summary.partly_never_true_under_not += usize::from(under_not);
                for name in unmapped {
                    *summary.unmapped_fields.entry(name).or_default() += 1;
                }
                rules.push(rule);
            }
            Err(why) => summary.record_dropped(&why, id),
        }
    }
    let compiled = compile(rules)?;
    summary.apply_compile_stats(compiled.stats());
    let rules = compiled.rules().cloned().collect();
    Ok(Conversion { rules, summary })
}

fn read_reason(error: ReadError) -> String {
    if let ReadError::UnsupportedModifier(name) = error {
        format!("{}:{name}", reason::UNSUPPORTED_MODIFIER)
    } else {
        error.reason().to_string()
    }
}

fn never_usage(expr: &Expr, negated: bool) -> (bool, bool) {
    match expr {
        Expr::Never => (true, negated),
        Expr::Leaf(_) => (false, false),
        Expr::Not(inner) => never_usage(inner, !negated),
        Expr::And(items) | Expr::Or(items) => items
            .iter()
            .map(|e| never_usage(e, negated))
            .fold((false, false), |(a, b), (c, d)| (a || c, b || d)),
    }
}

fn convert_rule(node: &Node, source: Source) -> Result<(Rule, BTreeSet<String>), String> {
    let Node::Map(_) = node else {
        return Err(reason::FORMAT_ERROR.into());
    };
    for key in ["id", "title"] {
        if get(node, key).is_none_or(|n| matches!(n, Node::Null)) {
            return Err(reason::MISSING_ATTRIBUTE.into());
        }
        if get(node, key)
            .and_then(text)
            .is_none_or(|s| key == "id" && s.is_empty())
        {
            return Err(reason::FORMAT_ERROR.into());
        }
    }
    let mut attributes = attributes(node, source)?;
    if get(node, "correlation").is_some() {
        return Err(reason::CORRELATION_RULE.into());
    }
    let detection = get(node, "detection").ok_or(reason::FORMAT_ERROR)?;
    // Validate source grammar before selecting an input kind. Unsupported
    // modifiers and placeholders are deferred to their specified priority.
    let deferred = preflight(detection)?;
    let logsource = get(node, "logsource").ok_or(reason::FORMAT_ERROR)?;
    let Node::Map(keys) = logsource else {
        return Err(reason::FORMAT_ERROR.into());
    };
    if keys.iter().any(|(key, value)| {
        ["product", "category", "service"].contains(&key.as_str()) && text(value).is_none()
    }) {
        return Err(reason::FORMAT_ERROR.into());
    }
    if get(logsource, "product").and_then(text) == Some("macos") {
        return Err(reason::NO_INPUT_KIND_MACOS.into());
    }
    let mapping = MAPPINGS
        .iter()
        .find(|mapping| mapping.matches(logsource))
        .ok_or(reason::NO_INPUT_KIND)?;
    if let Some(why) = deferred {
        return Err(why);
    }
    let mut converted = detection.clone();
    let mut unmapped = BTreeSet::new();
    transform_detection(&mut converted, mapping, &mut unmapped)?;
    let prefilter = prefilter(&converted);
    if let Some(bytes) = prefilter {
        attributes.push(("prefilter".into(), Node::Bytes(bytes)))
    }
    if let Some(os) = &mapping.os {
        attributes.push(("os".into(), Node::Str(os.clone())))
    }
    if let Some(add) = &mapping.add {
        add_logsource(&mut converted, add)?
    }
    attributes.push((
        "logsource".into(),
        Node::Map(vec![(
            "category".into(),
            Node::Str(mapping.kind_name.clone()),
        )]),
    ));
    attributes.push(("detection".into(), converted));
    let rule = Rule::from_node(Node::Map(attributes)).map_err(read_reason)?;
    debug_assert!(crate::unknown_fields(&rule).is_ok_and(|fields| fields.is_empty()));
    Ok((rule, unmapped))
}

/// Checks grammar with safe stand-ins for values, then checks each actual
/// field condition independently so a later format error beats an earlier
/// unsupported modifier. Keyword lists are valid Sigma source grammar.
fn preflight(node: &Node) -> Result<Option<String>, String> {
    let Node::Map(entries) = node else {
        return Err(reason::FORMAT_ERROR.into());
    };
    let mut safe = node.clone();
    let Node::Map(safe_entries) = &mut safe else {
        return Err(reason::FORMAT_ERROR.into());
    };
    let mut unsupported = None;
    let mut placeholder = None;
    for ((name, body), (_, safe_body)) in entries.iter().zip(safe_entries) {
        if name == "condition" {
            continue;
        }
        let maps = match body {
            Node::Seq(items) if !items.is_empty() => items.as_slice(),
            Node::Map(_) => std::slice::from_ref(body),
            _ => return Err(reason::FORMAT_ERROR.into()),
        };
        if maps.iter().all(|item| matches!(item, Node::Str(_))) {
            *safe_body = Node::Map(vec![("keyword".into(), Node::Str("x".into()))]);
            continue;
        }
        let mut safe_maps = Vec::new();
        for map in maps {
            let Node::Map(conditions) = map else {
                return Err(reason::FORMAT_ERROR.into());
            };
            if conditions.is_empty() {
                return Err(reason::FORMAT_ERROR.into());
            }
            for (key, value) in conditions {
                // Structural Sigma errors do not depend on knowing a
                // modifier's meaning, so they precede unsupported names.
                if !matches!(value, Node::Never) {
                    let mut parts = key.split('|');
                    if parts.next().is_none_or(str::is_empty) {
                        return Err(reason::FORMAT_ERROR.into());
                    }
                    let mut modifiers = BTreeSet::new();
                    if parts.any(|name| name.is_empty() || !modifiers.insert(name)) {
                        return Err(reason::FORMAT_ERROR.into());
                    }
                    match value {
                        Node::Map(_) => return Err(reason::FORMAT_ERROR.into()),
                        Node::Seq(values)
                            if values.is_empty()
                                || values.iter().any(|value| {
                                    matches!(
                                        value,
                                        Node::Null | Node::Never | Node::Map(_) | Node::Seq(_)
                                    )
                                }) =>
                        {
                            return Err(reason::FORMAT_ERROR.into());
                        }
                        _ => {}
                    }
                }
                match detection::field_condition(key, value) {
                    Ok(_) => {}
                    Err(ReadError::UnsupportedModifier(name)) => {
                        if unsupported.is_none() {
                            unsupported = Some(format!("{}:{name}", reason::UNSUPPORTED_MODIFIER));
                        }
                    }
                    Err(ReadError::PlaceholderValueMissing(_)) => {
                        if placeholder.is_none() {
                            placeholder = Some(reason::PLACEHOLDER_VALUE_MISSING.to_string());
                        }
                    }
                    Err(_) => return Err(reason::FORMAT_ERROR.into()),
                }
            }
            safe_maps.push(Node::Map(vec![("field".into(), Node::Str("x".into()))]));
        }
        *safe_body = if matches!(body, Node::Seq(_)) {
            Node::Seq(safe_maps)
        } else {
            safe_maps.pop().ok_or(reason::FORMAT_ERROR)?
        };
    }
    detection::parse(&safe).map_err(read_reason)?;
    Ok(unsupported.or(placeholder))
}

fn transform_detection(
    node: &mut Node,
    mapping: &Mapping,
    unmapped: &mut BTreeSet<String>,
) -> Result<(), String> {
    let Node::Map(entries) = node else {
        return Err(reason::FORMAT_ERROR.into());
    };
    for (name, body) in entries {
        if name == "condition" {
            continue;
        }
        if let Node::Seq(items) = body
            && items.iter().all(|item| matches!(item, Node::Str(_)))
        {
            let field = mapping
                .keywords
                .as_ref()
                .ok_or(reason::KEYWORDS_WITHOUT_FIELD)?;
            *body = Node::Map(vec![(
                format!("{field}|contains"),
                Node::Seq(std::mem::take(items)),
            )]);
            continue;
        }
        match body {
            Node::Map(fields) => transform_fields(fields, mapping, unmapped),
            Node::Seq(maps) => {
                for map in maps {
                    if let Node::Map(fields) = map {
                        transform_fields(fields, mapping, unmapped);
                    }
                }
            }
            _ => return Err(reason::FORMAT_ERROR.into()),
        }
    }
    Ok(())
}

fn transform_fields(
    fields: &mut [(String, Node)],
    mapping: &Mapping,
    unmapped: &mut BTreeSet<String>,
) {
    for (key, value) in fields {
        let name = key.split('|').next().unwrap_or_default();
        let mapped = mapping.field(name);
        if mapped.is_none() {
            unmapped.insert(name.to_string());
        }
        let mut reference_missing = false;
        if key.split('|').skip(1).any(|m| m == "fieldref") {
            let values = match &mut *value {
                Node::Seq(items) => items.as_mut_slice(),
                other => std::slice::from_mut(other),
            };
            for value in values {
                if let Node::Str(other) = value {
                    if let Some(target) = mapping.field(other) {
                        *other = target
                    } else {
                        unmapped.insert(other.clone());
                        reference_missing = true;
                    }
                }
            }
        }
        if reference_missing || mapped.is_none() {
            *value = Node::Never;
        } else if let Some(target) = mapped {
            let suffix = key.find('|').and_then(|i| key.get(i..)).unwrap_or_default();
            *key = format!("{target}{suffix}");
        }
    }
}

fn add_logsource(detection: &mut Node, add: &Node) -> Result<(), String> {
    let Node::Map(entries) = detection else {
        return Err(reason::FORMAT_ERROR.into());
    };
    for (name, body) in entries.iter_mut() {
        if name != "condition" {
            *name = format!("s_{name}");
            continue;
        }
        match body {
            Node::Str(condition) => *condition = guarded_condition(condition),
            Node::Seq(conditions) => {
                for condition in conditions {
                    if let Node::Str(text) = condition {
                        *text = guarded_condition(text);
                    } else {
                        return Err(reason::FORMAT_ERROR.into());
                    }
                }
            }
            _ => return Err(reason::FORMAT_ERROR.into()),
        }
    }
    entries.push(("rulec_logsource".into(), add.clone()));
    Ok(())
}

fn guarded_condition(original: &str) -> String {
    // Keep whitespace and parentheses as tokens too, so only identifier
    // words change. `all` and `1` may themselves be identifier names when
    // they are not followed by `of`.
    let mut tokens = Vec::new();
    let mut start = 0;
    for (index, c) in original.char_indices() {
        if c.is_whitespace() || c == '(' || c == ')' {
            if let Some(word) = original.get(start..index).filter(|word| !word.is_empty()) {
                tokens.push(word);
            }
            if let Some(separator) = original.get(index..index + c.len_utf8()) {
                tokens.push(separator);
            }
            start = index + c.len_utf8();
        }
    }
    if let Some(word) = original.get(start..).filter(|word| !word.is_empty()) {
        tokens.push(word);
    }
    let mut out = String::from("(");
    let mut pattern_target = false;
    for (index, token) in tokens.iter().enumerate() {
        if token.chars().all(char::is_whitespace) {
            out.push_str(token);
            continue;
        }
        // After `of`, even an operator's spelling is an identifier
        // pattern. Consume it before looking for the next operator.
        if pattern_target {
            out.push_str("s_");
            out.push_str(if *token == "them" { "*" } else { token });
            pattern_target = false;
            continue;
        }
        let next = tokens
            .iter()
            .skip(index + 1)
            .find(|t| !t.chars().all(char::is_whitespace));
        match *token {
            "of" => {
                out.push_str(token);
                pattern_target = true;
            }
            "and" | "or" | "not" | "(" | ")" => out.push_str(token),
            "1" | "all" if next == Some(&"of") => out.push_str(token),
            _ => {
                out.push_str("s_");
                out.push_str(token);
            }
        }
    }
    out.push_str(") and rulec_logsource");
    out
}

fn prefilter(detection: &Node) -> Option<Vec<u8>> {
    fn visit(node: &Node, longest: &mut Vec<u8>) {
        match node {
            Node::Map(fields) => {
                for (key, value) in fields {
                    if key == "condition"
                        || key.split('|').skip(1).any(|m| {
                            matches!(
                                m,
                                "re" | "cidr" | "fieldref" | "lt" | "lte" | "gt" | "gte" | "len"
                            )
                        })
                    {
                        continue;
                    }
                    let values = match value {
                        Node::Seq(items) => items.as_slice(),
                        other => std::slice::from_ref(other),
                    };
                    for value in values {
                        if let Node::Str(s) = value {
                            for piece in
                                detection::sigma_string(s, key.split('|').any(|m| m == "expand"))
                            {
                                if let Piece::Lit(bytes) = piece
                                    && bytes.len() > longest.len()
                                {
                                    *longest = bytes;
                                }
                            }
                        } else if matches!(value, Node::Map(_)) {
                            visit(value, longest)
                        }
                    }
                }
            }
            Node::Seq(items) => {
                for item in items {
                    visit(item, longest)
                }
            }
            _ => {}
        }
    }
    // The outer mapping holds identifiers, not field keys.
    let mut longest = Vec::new();
    if let Node::Map(entries) = detection {
        for (name, body) in entries {
            if name != "condition" {
                visit(body, &mut longest)
            }
        }
    }
    (!longest.is_empty()).then_some(longest)
}

const TACTICS: &[(&str, &str)] = &[
    ("reconnaissance", "TA0043"),
    ("resource-development", "TA0042"),
    ("initial-access", "TA0001"),
    ("execution", "TA0002"),
    ("persistence", "TA0003"),
    ("privilege-escalation", "TA0004"),
    ("defense-evasion", "TA0005"),
    ("credential-access", "TA0006"),
    ("discovery", "TA0007"),
    ("lateral-movement", "TA0008"),
    ("collection", "TA0009"),
    ("command-and-control", "TA0011"),
    ("exfiltration", "TA0010"),
    ("impact", "TA0040"),
];

fn attributes(node: &Node, source: Source) -> Result<Vec<(String, Node)>, String> {
    let mut entries = vec![
        ("source".into(), Node::Str(source.to_string())),
        (
            "source_rule_id".into(),
            get(node, "id").cloned().ok_or(reason::MISSING_ATTRIBUTE)?,
        ),
        ("model".into(), Node::Str("SigmaSignature".into())),
        ("license".into(), Node::Str("DRL-1.1".into())),
    ];
    for key in ["title", "author", "references"] {
        if let Some(value) = get(node, key) {
            entries.push((key.into(), value.clone()));
        }
    }
    if let Some(level) = get(node, "level") {
        entries.push(("severity".into(), level.clone()));
    }
    let mut techniques = Vec::new();
    let mut tactics = Vec::new();
    if let Some(tags) = get(node, "tags") {
        let Node::Seq(tags) = tags else {
            return Err(reason::FORMAT_ERROR.into());
        };
        for tag in tags {
            let tag = text(tag).ok_or(reason::FORMAT_ERROR)?;
            if let Some(name) = tag.strip_prefix("attack.") {
                let normalized = name.replace('_', "-");
                if let Some((_, id)) = TACTICS.iter().find(|(tactic, _)| *tactic == normalized) {
                    let value = Node::Str((*id).into());
                    if !tactics.contains(&value) {
                        tactics.push(value);
                    }
                } else if let Some(technique) = name.strip_prefix('t') {
                    let valid = |s: &str, n| s.len() == n && s.bytes().all(|c| c.is_ascii_digit());
                    if technique
                        .split_once('.')
                        .map_or_else(|| valid(technique, 4), |(a, b)| valid(a, 4) && valid(b, 3))
                    {
                        let value = Node::Str(format!("T{technique}"));
                        if !techniques.contains(&value) {
                            techniques.push(value);
                        }
                    }
                }
            }
        }
    }
    entries.push(("techniques".into(), Node::Seq(techniques)));
    entries.push(("tactics".into(), Node::Seq(tactics)));
    // Reuse the format reader to check copied attributes before logsource
    // and modifier failures. This synthetic detection has no source values.
    let mut check = entries.clone();
    check.push((
        "logsource".into(),
        Node::Map(vec![("category".into(), Node::Str("http".into()))]),
    ));
    check.push((
        "detection".into(),
        Node::Map(vec![
            (
                "selection".into(),
                Node::Map(vec![("uri".into(), Node::Str("x".into()))]),
            ),
            ("condition".into(), Node::Str("selection".into())),
        ]),
    ));
    Rule::from_node(Node::Map(check)).map_err(read_reason)?;
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_mapping_converts_to_its_kind_os_and_added_expression() {
        for mapping in MAPPINGS.iter() {
            let detection = Node::Map(vec![
                (
                    "selection".into(),
                    Node::Map(vec![(
                        "RulecUnknownField|contains".into(),
                        Node::Str("value".into()),
                    )]),
                ),
                ("condition".into(), Node::Str("not selection".into())),
            ]);
            let node = Node::Map(vec![
                ("id".into(), Node::Str("synthetic".into())),
                ("title".into(), Node::Str("synthetic".into())),
                ("logsource".into(), mapping.logsource.clone()),
                ("detection".into(), detection),
            ]);
            let (rule, unmapped) = convert_rule(&node, Source::SigmaHq).unwrap();
            assert_eq!(rule.kind(), mapping.kind);
            assert_eq!(rule.os().map(|os| os.to_string()), mapping.os);
            let expected = if let Some(add) = &mapping.add {
                let added = Node::Map(vec![
                    ("guard".into(), add.clone()),
                    ("condition".into(), Node::Str("guard".into())),
                ]);
                Expr::And(vec![
                    Expr::Not(Box::new(Expr::Never)),
                    detection::parse(&added).unwrap().0,
                ])
            } else {
                Expr::Not(Box::new(Expr::Never))
            };
            // Windows event log and auditd prefix rules map arbitrary names.
            if unmapped.contains("RulecUnknownField") {
                assert_eq!(rule.detection, expected);
            }
            assert!(crate::unknown_fields(&rule).unwrap().is_empty());
            let compiled = compile(vec![rule]).unwrap();
            assert!(compiled.stats().excluded().is_empty());
        }
    }

    #[test]
    fn condition_renaming_is_token_based_and_keeps_no_guard_unchanged() {
        assert_eq!(
            guarded_condition("(selection and not filter) or 1 of sel*"),
            "((s_selection and not s_filter) or 1 of s_sel*) and rulec_logsource"
        );
        assert_eq!(
            guarded_condition("all of them"),
            "(all of s_*) and rulec_logsource"
        );
        assert_eq!(
            guarded_condition("1 and all"),
            "(s_1 and s_all) and rulec_logsource"
        );
        let original = "selection";
        let node = yaml::load("id: x\ntitle: x\nlogsource: {category: proxy}\ndetection:\n  selection: {c-uri: /x}\n  condition: selection").unwrap();
        let rule = convert_rule(&node, Source::SigmaHq).unwrap().0;
        assert_eq!(
            rule.detection,
            detection::parse(
                &yaml::load(&format!("selection: {{uri: /x}}\ncondition: {original}")).unwrap()
            )
            .unwrap()
            .0
        );
    }

    #[test]
    fn extended_timestamp_parser_rejects_missing_duplicate_and_truncated_fields() {
        assert_eq!(utc_mtime(&[0x55, 0x54, 5, 0, 1, 0, 0, 0, 0]), Some(0));
        for bad in [
            vec![],
            vec![0x55, 0x54, 5, 0, 0, 0, 0, 0, 0],
            vec![0x55, 0x54, 5, 0, 1, 0],
            vec![
                0x55, 0x54, 5, 0, 1, 0, 0, 0, 0, 0x55, 0x54, 5, 0, 1, 0, 0, 0, 0,
            ],
        ] {
            assert_eq!(utc_mtime(&bad), None);
        }
        let seconds = 1_783_641_599_u32; // 2026-07-09 23:59:59 UTC.
        let date = jiff::Timestamp::from_second(i64::from(seconds))
            .unwrap()
            .to_zoned_datetime(jiff::tz::TimeZone::UTC)
            .date();
        assert_eq!(date, jiff::civil::date(2026, 7, 9));
    }

    #[test]
    fn structural_errors_precede_unknown_modifiers() {
        for field in [
            "Unknown|minute: []",
            "Unknown|minute: [null]",
            "Unknown|minute: {nested: value}",
            "Unknown|minute|minute: x",
            "Unknown|minute|: x",
        ] {
            let node = yaml::load(&format!("id: x\ntitle: x\nlogsource: {{product: macos}}\ndetection:\n  selection: {{{field}}}\n  condition: selection")).unwrap();
            assert_eq!(
                convert_rule(&node, Source::SigmaHq).unwrap_err(),
                reason::FORMAT_ERROR
            );
        }
    }

    #[test]
    fn all_enterprise_tactics_accept_hyphens_and_underscores_without_duplicates() {
        let mut tags = Vec::new();
        for (name, _) in TACTICS {
            tags.push(Node::Str(format!("attack.{name}")));
            tags.push(Node::Str(format!("attack.{}", name.replace('-', "_"))));
        }
        let node = Node::Map(vec![
            ("id".into(), Node::Str("x".into())),
            ("title".into(), Node::Str("x".into())),
            ("tags".into(), Node::Seq(tags)),
        ]);
        let attrs = Node::Map(attributes(&node, Source::SigmaHq).unwrap());
        assert_eq!(
            get(&attrs, "tactics"),
            Some(&Node::Seq(
                TACTICS
                    .iter()
                    .map(|(_, id)| Node::Str((*id).into()))
                    .collect()
            ))
        );
    }

    #[test]
    fn prefilter_excludes_special_tests_escapes_wildcards_and_keeps_first_tie() {
        let detection = yaml::load("selection:\n  f: ['first?second', 'third']\n  g|re: 'ignored_regex'\n  h|fieldref: ignored_reference\n  j|cidr: 192.0.2.0/24\n  k|gt: 123456789\n  m: !never ''\ncondition: selection").unwrap();
        assert_eq!(prefilter(&detection), Some(b"second".to_vec()));
        let detection =
            yaml::load("selection: {f: ['first*third', 'other']}\ncondition: selection").unwrap();
        assert_eq!(prefilter(&detection), Some(b"first".to_vec()));
    }
}
