//! The names of the reasons a conversion summary records dropped rules
//! under.
//!
//! These are the reasons `rulec` itself defines. A converter adds its own
//! names beside them.

/// vectorscan rejected a pattern of the rule, so compilation left it out.
pub const UNSUPPORTED_REGEX: &str = "unsupported_regex";
/// The rule is on the blocklist.
pub const BLOCKLIST: &str = "blocklist";
/// The rule uses a placeholder with no value
/// ([`ReadError::PlaceholderValueMissing`](crate::ReadError::PlaceholderValueMissing)).
pub const PLACEHOLDER_VALUE_MISSING: &str = "placeholder_value_missing";
/// The rule is a correlation rule
/// ([`ReadError::CorrelationRule`](crate::ReadError::CorrelationRule)).
pub const CORRELATION_RULE: &str = "correlation_rule";
/// A required attribute is missing
/// ([`ReadError::MissingAttribute`](crate::ReadError::MissingAttribute)).
pub const MISSING_ATTRIBUTE: &str = "missing_attribute";
/// The rule uses a modifier Clumit Sigma does not accept
/// ([`ReadError::UnsupportedModifier`](crate::ReadError::UnsupportedModifier)).
pub const UNSUPPORTED_MODIFIER: &str = "unsupported_modifier";
/// The rule is malformed ([`ReadError::Format`](crate::ReadError::Format)).
pub const FORMAT_ERROR: &str = "format_error";
