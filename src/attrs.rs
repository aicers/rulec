//! The enumerated attributes of a rule.

use std::{fmt, str::FromStr};

use giganto_client::ingest::endpoint::OsFamily;
use serde::{Deserialize, Serialize};

/// The public rule set a rule comes from.
///
/// More sources may be added, so a `match` on it needs a wildcard arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Source {
    /// ET Open (`et_open`).
    EtOpen,
    /// The SigmaHQ rule set (`sigma_hq`).
    SigmaHq,
    /// The emerging-threats rules of SigmaHQ (`sigma_hq_emerging`).
    SigmaHqEmerging,
}

impl Source {
    /// Returns the name of the source as a rule writes it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EtOpen => "et_open",
            Self::SigmaHq => "sigma_hq",
            Self::SigmaHqEmerging => "sigma_hq_emerging",
        }
    }
}

/// The detection model a rule belongs to.
///
/// More models may be added, so a `match` on it needs a wildcard arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Model {
    /// An ET Open signature (`EtSignature`).
    EtSignature,
    /// An ET Open policy signature (`EtPolicySignature`).
    EtPolicySignature,
    /// A Sigma signature (`SigmaSignature`).
    SigmaSignature,
}

impl Model {
    /// Returns the name of the model as a rule writes it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EtSignature => "EtSignature",
            Self::EtPolicySignature => "EtPolicySignature",
            Self::SigmaSignature => "SigmaSignature",
        }
    }

    /// Returns whether a rule of this model may come from `source`.
    #[must_use]
    pub fn pairs_with(self, source: Source) -> bool {
        match self {
            Self::EtSignature | Self::EtPolicySignature => source == Source::EtOpen,
            Self::SigmaSignature => {
                matches!(source, Source::SigmaHq | Source::SigmaHqEmerging)
            }
        }
    }
}

/// The OS a rule applies to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Os {
    /// Windows (`windows`).
    Windows,
    /// Linux (`linux`).
    Linux,
    /// macOS (`macos`).
    Macos,
}

impl Os {
    /// Returns the name of the OS as a rule writes it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Linux => "linux",
            Self::Macos => "macos",
        }
    }

    /// Returns whether `family` is this OS. [`OsFamily::Other`] is no OS a
    /// rule names.
    #[must_use]
    pub fn is(self, family: &OsFamily) -> bool {
        matches!(
            (self, family),
            (Self::Windows, OsFamily::Windows)
                | (Self::Linux, OsFamily::Linux)
                | (Self::Macos, OsFamily::Macos)
        )
    }
}

/// An error parsing a [`Source`], [`Model`] or [`Os`] from its name.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unknown {what} {name:?}")]
pub struct UnknownName {
    what: &'static str,
    name: String,
}

macro_rules! name_impls {
    ($ty:ident, $what:literal, [$($variant:ident),+]) => {
        impl FromStr for $ty {
            type Err = UnknownName;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                $(
                    if s == Self::$variant.as_str() {
                        return Ok(Self::$variant);
                    }
                )+
                Err(UnknownName { what: $what, name: s.to_string() })
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

name_impls!(Source, "source", [EtOpen, SigmaHq, SigmaHqEmerging]);
name_impls!(
    Model,
    "model",
    [EtSignature, EtPolicySignature, SigmaSignature]
);
name_impls!(Os, "OS", [Windows, Linux, Macos]);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for s in [Source::EtOpen, Source::SigmaHq, Source::SigmaHqEmerging] {
            assert_eq!(s.as_str().parse::<Source>().unwrap(), s);
            assert_eq!(
                serde_json::to_string(&s).unwrap(),
                format!("\"{}\"", s.as_str())
            );
        }
        for m in [
            Model::EtSignature,
            Model::EtPolicySignature,
            Model::SigmaSignature,
        ] {
            assert_eq!(m.as_str().parse::<Model>().unwrap(), m);
            assert_eq!(
                serde_json::to_string(&m).unwrap(),
                format!("\"{}\"", m.as_str())
            );
        }
        for o in [Os::Windows, Os::Linux, Os::Macos] {
            assert_eq!(o.as_str().parse::<Os>().unwrap(), o);
        }
        assert!("ET_OPEN".parse::<Source>().is_err());
        assert!("bsd".parse::<Os>().is_err());
    }

    #[test]
    fn pairs() {
        assert!(Model::EtSignature.pairs_with(Source::EtOpen));
        assert!(Model::EtPolicySignature.pairs_with(Source::EtOpen));
        assert!(!Model::EtSignature.pairs_with(Source::SigmaHq));
        assert!(Model::SigmaSignature.pairs_with(Source::SigmaHq));
        assert!(Model::SigmaSignature.pairs_with(Source::SigmaHqEmerging));
        assert!(!Model::SigmaSignature.pairs_with(Source::EtOpen));
    }
}
