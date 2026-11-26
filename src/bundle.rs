//! Rule bundles: one source's rules as bytes.
//!
//! A bundle is the magic `RULECBDL`, the length of the `rulec` version that
//! wrote it (two bytes, little-endian), that version, and then the rules
//! as gzip-compressed JSON. Only the version that wrote a bundle reads it.

use std::io::Read;

use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use serde::{Deserialize, Serialize};

use crate::{VERSION, attrs::Source, rule::Rule};

const MAGIC: &[u8; 8] = b"RULECBDL";

/// One source's rules, to store and read back as bytes.
///
/// The bytes carry the version of `rulec` that wrote them ([`VERSION`]),
/// uncompressed, followed by the rules as gzip-compressed JSON. Only the
/// same version reads them back: a server keeping bundles converts its
/// rules again when `VERSION` changes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleBundle {
    source: Source,
    rules: Vec<Rule>,
}

/// An error writing or reading a [`RuleBundle`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BundleError {
    /// A rule is not from the bundle's source.
    #[error("rule {source_rule_id:?} is from {rule_source}, not {bundle_source}")]
    SourceMismatch {
        /// The bundle's source.
        bundle_source: Source,
        /// The rule's source.
        rule_source: Source,
        /// The rule's id in its source.
        source_rule_id: String,
    },
    /// The bytes do not start like a bundle.
    #[error("the bytes are not a rule bundle")]
    NotABundle,
    /// The bytes end before the bundle does.
    #[error("the rule bundle is truncated")]
    Truncated,
    /// The bundle was written by another version of `rulec`.
    #[error(
        "the rule bundle was written by rulec {bundle_version}, and this is rulec {rulec_version}"
    )]
    VersionMismatch {
        /// The version that wrote the bundle.
        bundle_version: String,
        /// This version.
        rulec_version: String,
    },
    /// The bundle's contents cannot be read.
    #[error("the rule bundle is corrupt: {0}")]
    Corrupt(String),
    /// The rules could not be serialized.
    #[error("serializing the rule bundle: {0}")]
    Serialize(String),
}

impl RuleBundle {
    /// Creates a bundle of `rules`, all from `source`.
    ///
    /// # Errors
    ///
    /// Returns [`BundleError::SourceMismatch`] if a rule is from another
    /// source.
    pub fn new(source: Source, rules: Vec<Rule>) -> Result<Self, BundleError> {
        if let Some(rule) = rules.iter().find(|r| r.source() != source) {
            return Err(BundleError::SourceMismatch {
                bundle_source: source,
                rule_source: rule.source(),
                source_rule_id: rule.source_rule_id().to_string(),
            });
        }
        Ok(Self { source, rules })
    }

    /// Returns the source of the rules.
    #[must_use]
    pub fn source(&self) -> Source {
        self.source
    }

    /// Returns the rules.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Returns the rules, consuming the bundle.
    #[must_use]
    pub fn into_rules(self) -> Vec<Rule> {
        self.rules
    }

    /// Serializes the bundle, stamped with this version of `rulec`.
    ///
    /// # Errors
    ///
    /// Returns an error if the rules cannot be serialized or compressed.
    pub fn to_bytes(&self) -> Result<Vec<u8>, BundleError> {
        self.to_bytes_as(VERSION)
    }

    pub(crate) fn to_bytes_as(&self, version: &str) -> Result<Vec<u8>, BundleError> {
        let version_len = u16::try_from(version.len())
            .map_err(|_| BundleError::Serialize("the version is too long".to_string()))?;
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&version_len.to_le_bytes());
        out.extend_from_slice(version.as_bytes());
        let mut encoder = GzEncoder::new(out, Compression::default());
        serde_json::to_writer(&mut encoder, self)
            .map_err(|e| BundleError::Serialize(e.to_string()))?;
        encoder
            .finish()
            .map_err(|e| BundleError::Serialize(e.to_string()))
    }

    /// Reads a bundle written by this version of `rulec`.
    ///
    /// # Errors
    ///
    /// Returns [`BundleError::VersionMismatch`], naming both versions, if
    /// another version wrote the bundle, and another error if the bytes
    /// are not a bundle, are truncated, or are corrupt.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BundleError> {
        let Some(rest) = bytes.strip_prefix(MAGIC.as_slice()) else {
            return Err(if MAGIC.starts_with(bytes) {
                BundleError::Truncated
            } else {
                BundleError::NotABundle
            });
        };
        let (Some(&lo), Some(&hi)) = (rest.first(), rest.get(1)) else {
            return Err(BundleError::Truncated);
        };
        let version_len = usize::from(u16::from_le_bytes([lo, hi]));
        let rest = rest.get(2..).unwrap_or_default();
        let (Some(version), Some(payload)) = (rest.get(..version_len), rest.get(version_len..))
        else {
            return Err(BundleError::Truncated);
        };
        let version = String::from_utf8_lossy(version);
        if version != VERSION {
            return Err(BundleError::VersionMismatch {
                bundle_version: version.into_owned(),
                rulec_version: VERSION.to_string(),
            });
        }
        let mut json = Vec::new();
        GzDecoder::new(payload)
            .read_to_end(&mut json)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::UnexpectedEof => BundleError::Truncated,
                _ => BundleError::Corrupt(e.to_string()),
            })?;
        let bundle: Self =
            serde_json::from_slice(&json).map_err(|e| BundleError::Corrupt(e.to_string()))?;
        Self::new(bundle.source, bundle.rules).map_err(|e| BundleError::Corrupt(e.to_string()))
    }
}
