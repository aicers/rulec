//! What a conversion records: the version of the source it converted and a
//! summary of the result, plus the blocklist it applies.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashSet},
    fmt::Write as _,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    VERSION,
    attrs::{Model, Source},
    compile::{CompileStats, KindCount},
    reason,
    rule::Rule,
};

/// The blocklist built into the crate.
const BUILTIN_BLOCKLIST: &str = include_str!("../data/blocklist.txt");

/// A version of a source's rule set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceVersion {
    /// The version string, for display.
    pub version: String,
    /// The release name, for display, if the source has one.
    pub release_name: Option<String>,
    /// The key that orders the versions of the source.
    pub order_key: OrderKey,
    /// The digest of the contents, from [`content_digest`].
    pub content_digest: String,
}

/// The key that orders the versions of one source: a UTC date, and a
/// number that orders versions of the same date.
///
/// Compare keys with [`OrderKey::compare`], and only keys of the same
/// source. Its sameness is not transitive — a key without a number is the
/// same as a key with number 1 and one with number 2 — so the type does
/// not implement `Ord`. `PartialEq` compares the fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderKey {
    /// The UTC date of the version.
    pub date: jiff::civil::Date,
    /// A number ordering versions of the same date.
    pub number: Option<u64>,
}

impl OrderKey {
    /// Compares two keys of the same source: by date, then, on the same
    /// date, by number if both have one. Keys that are not told apart are
    /// the same.
    #[must_use]
    pub fn compare(&self, other: &Self) -> Ordering {
        self.date
            .cmp(&other.date)
            .then_with(|| match (self.number, other.number) {
                (Some(a), Some(b)) => a.cmp(&b),
                _ => Ordering::Equal,
            })
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for b in digest.iter() {
        // Writing to a `String` cannot fail.
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// Returns the digest of a rule set's contents: the lowercase hex SHA-256
/// of the entries sorted by path as bytes, each written as
/// `<path>\0<lowercase hex SHA-256 of the contents>\n`.
///
/// Paths are taken as given. Entries with the same path are ordered by the
/// digest of their contents. This definition does not change between
/// `rulec` versions, so digests from different versions compare.
#[must_use]
pub fn content_digest<I, P, C>(entries: I) -> String
where
    I: IntoIterator<Item = (P, C)>,
    P: AsRef<[u8]>,
    C: AsRef<[u8]>,
{
    let mut lines: Vec<(Vec<u8>, String)> = entries
        .into_iter()
        .map(|(path, contents)| (path.as_ref().to_vec(), sha256_hex(contents.as_ref())))
        .collect();
    lines.sort_unstable();
    let mut text = Vec::new();
    for (path, digest) in lines {
        text.extend_from_slice(&path);
        text.push(0);
        text.extend_from_slice(digest.as_bytes());
        text.push(b'\n');
    }
    sha256_hex(&text)
}

/// The summary of converting one version of one source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ConversionSummary {
    /// The source converted.
    pub source: Source,
    /// The version of the source converted.
    pub source_version: SourceVersion,
    /// The version of `rulec` that converted it ([`VERSION`]).
    pub rulec_version: String,
    /// The number of rules accepted, by model.
    pub accepted: BTreeMap<Model, usize>,
    /// The ids of the rules dropped, by reason name. See [`reason`] for
    /// the names `rulec` defines.
    pub dropped: BTreeMap<String, Vec<String>>,
    /// The number of rules some of whose conditions are always false.
    pub partly_never_true: usize,
    /// How many of `partly_never_true` have such a condition under `not`.
    pub partly_never_true_under_not: usize,
    /// The number of rules some of whose header values are missing.
    pub header_values_partly_missing: usize,
    /// The number of rules that used each source field with no
    /// counterpart, by field name.
    pub unmapped_fields: BTreeMap<String, usize>,
    /// The number of always-checked rules, by kind of raw event.
    pub always_check: Vec<KindCount>,
    /// How long compilation took.
    pub compile_time: Duration,
    /// The total size of the vectorscan databases in bytes.
    pub db_size: usize,
}

impl ConversionSummary {
    /// Creates an empty summary for `source` at `source_version`, stamped
    /// with this version of `rulec`.
    #[must_use]
    pub fn new(source: Source, source_version: SourceVersion) -> Self {
        Self {
            source,
            source_version,
            rulec_version: VERSION.to_string(),
            accepted: BTreeMap::new(),
            dropped: BTreeMap::new(),
            partly_never_true: 0,
            partly_never_true_under_not: 0,
            header_values_partly_missing: 0,
            unmapped_fields: BTreeMap::new(),
            always_check: Vec::new(),
            compile_time: Duration::ZERO,
            db_size: 0,
        }
    }

    /// Records a rule dropped for `reason`.
    pub fn record_dropped(&mut self, reason: &str, source_rule_id: &str) {
        self.dropped
            .entry(reason.to_string())
            .or_default()
            .push(source_rule_id.to_string());
    }

    /// Returns the number of rules dropped for `reason`.
    #[must_use]
    pub fn dropped_count(&self, reason: &str) -> usize {
        self.dropped.get(reason).map_or(0, Vec::len)
    }

    /// Fills the fields compilation decides from its statistics: the rules
    /// of this source accepted, by model; the rules of this source left out,
    /// as dropped for [`reason::UNSUPPORTED_REGEX`]; the always-checked
    /// rules of this source, by kind; and the compile time and database
    /// size, which are those of the whole compilation.
    pub fn apply_compile_stats(&mut self, stats: &CompileStats) {
        self.accepted = stats.accepted_for(self.source);
        for excluded in stats.excluded() {
            if excluded.source == self.source {
                self.record_dropped(reason::UNSUPPORTED_REGEX, &excluded.source_rule_id);
            }
        }
        self.always_check = stats.always_check_for(self.source);
        self.compile_time = stats.compile_time();
        self.db_size = stats.db_size();
    }
}

/// An error reading a blocklist.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("blocklist line {line}: {message}")]
pub struct BlocklistError {
    line: usize,
    message: String,
}

/// Rules to drop at conversion, by source and id in the source.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Blocklist {
    entries: HashSet<(Source, String)>,
}

impl Blocklist {
    /// Returns the blocklist built into the crate.
    ///
    /// # Errors
    ///
    /// Returns an error if the built-in list is malformed.
    pub fn builtin() -> Result<Self, BlocklistError> {
        Self::parse(BUILTIN_BLOCKLIST)
    }

    /// Reads a blocklist: one rule per line, its source and its id in the
    /// source separated by whitespace. Blank lines and lines starting with
    /// `#` are skipped.
    ///
    /// # Errors
    ///
    /// Returns an error naming the line of an entry that is not a known
    /// source followed by one id.
    pub fn parse(text: &str) -> Result<Self, BlocklistError> {
        let mut entries = HashSet::new();
        for (number, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let error = |message: String| BlocklistError {
                line: number + 1,
                message,
            };
            let mut words = line.split_whitespace();
            let (Some(source), Some(id), None) = (words.next(), words.next(), words.next()) else {
                return Err(error("expected a source and one rule id".to_string()));
            };
            let source: Source = source.parse().map_err(|e| error(format!("{e}")))?;
            entries.insert((source, id.to_string()));
        }
        Ok(Self { entries })
    }

    /// Returns whether the rule with `source_rule_id` from `source` is on
    /// the list.
    #[must_use]
    pub fn contains(&self, source: Source, source_rule_id: &str) -> bool {
        self.entries.contains(&(source, source_rule_id.to_string()))
    }

    /// Returns the number of rules on the list.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Drops the rules on the list, recording each in `summary` as dropped
    /// for [`reason::BLOCKLIST`], and returns the rest.
    #[must_use]
    pub fn apply(&self, rules: Vec<Rule>, summary: &mut ConversionSummary) -> Vec<Rule> {
        rules
            .into_iter()
            .filter(|rule| {
                let blocked = self.contains(rule.source(), rule.source_rule_id());
                if blocked {
                    summary.record_dropped(reason::BLOCKLIST, rule.source_rule_id());
                }
                !blocked
            })
            .collect()
    }
}
