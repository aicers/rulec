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

/// The rule's file has no category assigned to a detection model.
pub const UNCATEGORIZED: &str = "uncategorized";
/// The rule requires state shared between packets or rules.
pub const NEEDS_STATE: &str = "needs_state";
/// The rule tests raw payload or packet properties unavailable in records.
pub const PAYLOAD_OR_PACKET_CONDITION: &str = "payload_or_packet_condition";
/// An unsupported keyword; the summary key is `unsupported_keyword:<name>`.
pub const UNSUPPORTED_KEYWORD: &str = "unsupported_keyword";
/// An unsupported buffer; the summary key is `unsupported_buffer:<name>`,
/// with the Suricata 7.0.3 dotted buffer name.
pub const UNSUPPORTED_BUFFER: &str = "unsupported_buffer";
/// The rule inspects payload without an application buffer.
pub const RAW_PAYLOAD: &str = "raw_payload";
/// The buffers or header protocol do not describe one event kind.
pub const MIXED_KINDS: &str = "mixed_kinds";
/// The rule combines request and response directions.
pub const MIXED_DIRECTIONS: &str = "mixed_directions";
/// A response buffer has only a request-side value in the event.
pub const NO_RESPONSE_VALUE: &str = "no_response_value";
/// The rule's direction contradicts a buffer's direction.
pub const DIRECTION_MISMATCH: &str = "direction_mismatch";
