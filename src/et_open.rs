//! ET Open bundle reading and conversion, without network access.

use std::{collections::HashMap, fmt::Write as _, io::Read};

use flate2::read::MultiGzDecoder;
use jiff::civil::Date;
use sha2::{Digest, Sha256};

use crate::{
    Blocklist, CompileError, Conversion, ConversionSummary, OrderKey, Source, SourceVersion,
    compile, content_digest, reason, unknown_fields,
};

mod conditions;
mod data;
mod parse;

/// An error reading or compiling an ET Open bundle.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EtOpenError {
    /// The input is not readable gzip-compressed tar data.
    #[error("not a tar.gz bundle: {0}")]
    NotATarGz(String),
    /// The archive has no included rule files.
    #[error("the bundle contains no rule files")]
    NoRuleFiles,
    /// No active rule in an included file has a readable `updated_at`.
    #[error("the bundle has no version information")]
    NoVersionInfo,
    /// Building a field database failed after individual rule checks.
    #[error("compiling ET Open rules: {0}")]
    Compile(#[from] CompileError),
}

struct RuleFile {
    path: String,
    bytes: Vec<u8>,
}

struct Bundle {
    files: Vec<RuleFile>,
    version: SourceVersion,
}

fn archive_error(error: impl std::fmt::Display) -> EtOpenError {
    EtOpenError::NotATarGz(error.to_string())
}

fn included(path: &str) -> Option<&str> {
    let path = path.trim_start_matches("./").strip_prefix("rules/")?;
    if path.contains('/') || !path.ends_with(".rules") {
        return None;
    }
    if matches!(
        path,
        "emerging-retired.rules"
            | "botcc.rules"
            | "botcc.portgrouped.rules"
            | "ciarmy.rules"
            | "compromised.rules"
            | "drop.rules"
            | "dshield.rules"
            | "tor.rules"
    ) || path.starts_with("threatview")
    {
        return None;
    }
    Some(path)
}

fn read_bundle(bytes: &[u8], number: Option<u64>) -> Result<Bundle, EtOpenError> {
    // Read through the gzip trailer even if tar has already reached its end.
    // Otherwise a damaged CRC or a truncated final member could go unnoticed.
    let mut decoded = Vec::new();
    MultiGzDecoder::new(bytes)
        .read_to_end(&mut decoded)
        .map_err(archive_error)?;
    if decoded.len() < 512 {
        return Err(archive_error("missing tar header"));
    }
    let mut archive = tar::Archive::new(decoded.as_slice());
    let mut files = Vec::new();
    for entry in archive.entries().map_err(archive_error)? {
        let mut entry = entry.map_err(archive_error)?;
        let path = entry.path_bytes();
        let Some(path) = std::str::from_utf8(&path).ok().and_then(included) else {
            continue;
        };
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = path.to_string();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).map_err(archive_error)?;
        files.push(RuleFile { path, bytes });
    }
    if files.is_empty() {
        return Err(EtOpenError::NoRuleFiles);
    }
    // Stable output independent of tar entry order, including duplicate paths.
    files.sort_unstable_by(|a, b| (&a.path, &a.bytes).cmp(&(&b.path, &b.bytes)));
    let date = files
        .iter()
        .flat_map(|f| parse::lines(&f.bytes))
        .filter_map(|(_, line)| parse::updated_at(&line))
        .max()
        .ok_or(EtOpenError::NoVersionInfo)?;
    let version = match number {
        Some(number) => number.to_string(),
        None => {
            let mut hex = String::new();
            for byte in Sha256::digest(bytes).iter().take(6) {
                let _ = write!(hex, "{byte:02x}");
            }
            format!("upd-{date}-{hex}")
        }
    };
    let version = SourceVersion {
        version,
        release_name: None,
        order_key: OrderKey { date, number },
        content_digest: content_digest(files.iter().map(|f| (&f.path, &f.bytes))),
    };
    Ok(Bundle { files, version })
}

/// Reads an ET Open source version without converting or compiling rules.
///
/// `version_number` is the optional number from the adjacent `version.txt`,
/// supplied by the caller. No network requests or filesystem writes occur.
///
/// # Errors
///
/// Returns [`EtOpenError::NotATarGz`], [`EtOpenError::NoRuleFiles`], or
/// [`EtOpenError::NoVersionInfo`], in that precedence order, exactly as
/// [`convert_et_open`] does. Never returns [`EtOpenError::Compile`].
pub fn read_et_open_version(
    bundle: &[u8],
    version_number: Option<u64>,
) -> Result<SourceVersion, EtOpenError> {
    Ok(read_bundle(bundle, version_number)?.version)
}

/// Converts an ET Open Suricata 7.0.3 bundle into checked Clumit Sigma rules.
///
/// Accepts the compressed bundle bytes, an optional external version number,
/// and the blocklist to apply (usually [`Blocklist::builtin`]). The source
/// version is in [`Conversion::summary`]. See the crate's ET Open conversion
/// documentation for exclusions and the order of rejection reasons.
///
/// # Errors
///
/// Returns a bundle error in the same order as [`read_et_open_version`], or
/// [`EtOpenError::Compile`] if building a field database fails. Unsupported
/// individual rules are recorded in the summary instead of failing the bundle.
pub fn convert_et_open(
    bundle: &[u8],
    version_number: Option<u64>,
    blocklist: &Blocklist,
) -> Result<Conversion, EtOpenError> {
    let bundle = read_bundle(bundle, version_number)?;
    let mut summary = ConversionSummary::new(Source::EtOpen, bundle.version);
    let mut rules = Vec::new();
    let mut partial_headers: HashMap<String, Vec<_>> = HashMap::new();
    for file in bundle.files {
        for (line_number, line) in parse::lines(&file.bytes) {
            let sid = parse::sid(&line);
            let id = sid
                .as_deref()
                .map_or_else(|| format!("{}:{line_number}", file.path), str::to_string);
            let model = data::model(&file.path);
            let result = if sid
                .as_deref()
                .is_some_and(|id| blocklist.contains(Source::EtOpen, id))
            {
                Err(reason::BLOCKLIST.to_string())
            } else if let Some(model) = model {
                parse::convert(&line, model)
            } else {
                Err(reason::UNCATEGORIZED.to_string())
            };
            match result {
                Ok((rule, partial_header)) => {
                    // Every generated field is chosen from the static buffer map.
                    // A failure here is an implementation defect, not source syntax.
                    assert!(
                        unknown_fields(&rule).is_ok_and(|fields| fields.is_empty()),
                        "ET Open conversion chooses every field from the static catalog"
                    );
                    if partial_header {
                        partial_headers
                            .entry(rule.source_rule_id().to_string())
                            .or_default()
                            .push(rule.clone());
                    }
                    rules.push(rule);
                }
                Err(reason) => summary.record_dropped(&reason, &id),
            }
        }
    }
    let compiled = compile(rules)?;
    summary.apply_compile_stats(compiled.stats());
    // Exclusions identify source ids, which need not be unique. Use the actual
    // accepted rules rather than removing every occurrence of an excluded id.
    let rules: Vec<_> = compiled.rules().cloned().collect();
    summary.header_values_partly_missing = rules
        .iter()
        .filter(|r| {
            partial_headers
                .get(r.source_rule_id())
                .is_some_and(|candidates| candidates.contains(r))
        })
        .count();
    Ok(Conversion { rules, summary })
}

fn date(value: &str) -> Option<Date> {
    if value.len() != 10
        || !value.bytes().enumerate().all(|(i, b)| {
            if i == 4 || i == 7 {
                b == b'_'
            } else {
                b.is_ascii_digit()
            }
        })
    {
        return None;
    }
    value.replace('_', "-").parse().ok()
}

/// Per-rule ET Open diagnostics used to explain differential results.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EtOpenDiagnostics {
    /// Whether this rule meets the documented partial-header counter definition.
    pub header_values_partly_missing: bool,
    /// Whether conversion ignores a threshold or detection filter in this rule.
    pub ignores_threshold: bool,
}

/// A rejection reason encountered while inspecting one ET Open rule.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("inspecting ET Open rule: {reason}")]
pub struct EtOpenInspectionError {
    reason: String,
}

impl EtOpenInspectionError {
    /// Returns the converter's rejection reason key.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// Inspects an ET Open rule using the converter's parser and header definition.
///
/// Supply the accepted rule's model and its original logical source line.
/// This does not compile patterns, access the network, or change conversion.
///
/// # Errors
///
/// Returns the parser's rejection reason if the line cannot be converted
/// into a rule. Pattern compilation errors are outside this inspection.
pub fn inspect_et_open_rule(
    line: &[u8],
    model: crate::Model,
) -> Result<EtOpenDiagnostics, EtOpenInspectionError> {
    let (_, header_values_partly_missing) =
        parse::convert(line, model).map_err(|reason| EtOpenInspectionError { reason })?;
    Ok(EtOpenDiagnostics {
        header_values_partly_missing,
        ignores_threshold: parse::has_threshold(line),
    })
}
