//! The result shared by source converters.

use crate::{ConversionSummary, Rule};

/// The accepted rules of one source and the summary of their conversion.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Conversion {
    /// The converted rules, checked against the field catalog and compiled.
    pub rules: Vec<Rule>,
    /// The source version and the outcome of conversion and compilation.
    pub summary: ConversionSummary,
}
