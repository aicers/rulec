//! A rule compiler for public signature rules.
//!
//! `rulec` turns public signature rules (ET Open, SigmaHQ) into one rule
//! format, **Clumit Sigma**, compiles rules in that format with vectorscan,
//! and matches them against raw events of `giganto-client`. The server that
//! keeps converted rules uses this crate to convert and compile them, which
//! checks them; the engine that matches events uses the same crate to
//! compile and match. Both run the same code, so a rule that passes the
//! check runs the same way in the engine.
//!
//! This version reads the format ([`Rule::from_yaml`], [`read_rules`]),
//! stores one source's rules as bytes ([`RuleBundle`]), compiles rules
//! ([`compile`]) and matches events ([`Matcher`]) through the [`Event`]
//! trait, and defines what converters record ([`ConversionSummary`],
//! [`SourceVersion`], [`content_digest`], [`Blocklist`]). Reading fields out
//! of `giganto-client` records and the converters themselves are not here
//! yet.
//!
//! # Clumit Sigma
//!
//! A Clumit Sigma rule is a YAML document in the rule syntax of the
//! [Sigma specification 2.1][sigma]: search identifiers under `detection`
//! (a mapping is the AND of its field conditions, a list of mappings the OR
//! of the mappings), values with wildcards `*` and `?` and the backslash
//! escape, `null`, and a `condition` with `and`, `or`, `not`, parentheses,
//! `1 of` and `all of` over an identifier pattern or `them`. A list of
//! conditions is their OR. A list of values without a field name (a
//! keyword search) is rejected: a converter decides which field such a
//! value searches and writes it as a field condition. YAML aliases are
//! read, up to a bound on what they copy in all (2^20 nodes and text
//! bytes); a rule past it is rejected as malformed.
//!
//! `logsource` names one kind of raw event: its `category` is the name
//! `giganto-client`'s `RawEventKind` parses (`http`, `tls`,
//! `process_create`, ...), and it has no `product` or `service`. Field names
//! are those of the [`Event`] trait. Correlation rules are rejected.
//!
//! ## Attributes
//!
//! Each rule carries these top-level keys besides Sigma's own:
//!
//! | Key | Meaning | Required |
//! | --- | --- | --- |
//! | `source` | `et_open`, `sigma_hq` or `sigma_hq_emerging` ([`Source`]) | yes |
//! | `source_rule_id` | the rule's id in the source (ET `sid`, Sigma `id`) | yes |
//! | `model` | `EtSignature`, `EtPolicySignature` or `SigmaSignature` ([`Model`]) | yes |
//! | `title` | the title | yes |
//! | `source_rule_rev` | ET `rev` | no |
//! | `license` | the rule's license | no |
//! | `severity` | the source rule's severity, as text | no |
//! | `classification` | ET classtype | no |
//! | `techniques` | MITRE ATT&CK technique ids (`T1059`, `T1059.001`) | no |
//! | `tactics` | MITRE ATT&CK tactic ids (`TA0001`) | no |
//! | `author` | the author | no |
//! | `os` | `windows`, `linux` or `macos` ([`Os`]) | no |
//! | `prefilter` | a prefilter literal, kept for information only | no |
//! | `references` | reference URLs | no |
//!
//! The ET models pair only with `et_open`, and `SigmaSignature` only with
//! the two SigmaHQ sources. Other top-level keys are ignored.
//!
//! ## Modifiers
//!
//! The modifiers of Sigma 2.1 are accepted with their meaning there:
//! `contains`, `startswith`, `endswith`, `all`, `exists`, `cased`, `neq`,
//! `windash`, `re` (with `i`, `m` and `s`), `base64`, `base64offset`,
//! `utf16le`, `utf16be`, `utf16`, `wide`, `lt`, `lte`, `gt`, `gte`, `cidr`,
//! `expand` and `fieldref`. Any other modifier, the time modifiers
//! (`minute`, `hour`, `day`, `week`, `month`, `year`) included, is
//! rejected.
//!
//! Clumit Sigma adds one: **`len`** compares the length of a field's value
//! in bytes. Alone it tests equality; with `lt`, `lte`, `gt` or `gte` it
//! makes that comparison: `uri|len|gt: 100`.
//!
//! Some combinations are pinned down:
//!
//! - A field condition names each modifier at most once, and takes at most
//!   one numeric comparison (`lt`, `lte`, `gt`, `gte`) and at most one of
//!   `contains`, `startswith` and `endswith`. `i`, `m` and `s` follow `re`.
//! - The modifiers that transform a value — `contains`, `startswith`,
//!   `endswith` and the encodings — apply in the order written, as Sigma
//!   2.1 defines. `contains`, `startswith` and `endswith` add a `*`, so
//!   `utf16|contains` finds the encoded value with its BOM anywhere, and
//!   `contains|utf16` finds it anywhere after a BOM at the start. A value
//!   with wildcards cannot be Base64-encoded — `contains|base64` is
//!   rejected, `base64|contains` is not — and `?` cannot be encoded in
//!   UTF-16.
//! - `all` needs a list of values and does not combine with `neq`.
//! - `neq` holds when the field has a value that none of the listed values
//!   matches. Where a listed value compares a number, for an integer, or
//!   an address, for `cidr|neq`, a field value must read as one to count:
//!   a value that does not read makes `neq` false, as it does the
//!   comparison `neq` negates.
//! - What a condition compares decides which modifiers it takes beside the
//!   one that names it; any other modifier is rejected:
//!   - `exists` stands alone.
//!   - `fieldref` takes `neq`, `cased` and `all`.
//!   - `cidr` takes `expand`, `neq`, `cased` and `all`; a `%home_net%`
//!     value is written only as `field|expand|cidr`, with no other
//!     modifier (see below).
//!   - `re` takes `i`, `m`, `s`, `neq`, `cased` and `all`.
//!   - `len` takes one numeric comparison, `neq`, `cased` and `all`.
//!   - A numeric comparison without `len` takes only `cased` and `all`, so
//!     `status|gt|neq` is rejected.
//!   - A string condition takes `contains`, `startswith`, `endswith`,
//!     `windash`, `base64`, `base64offset`, `utf16le`, `utf16be`, `utf16`,
//!     `wide`, `expand`, `cased`, `all` and `neq`.
//!
//!   Each list is still subject to the rules for `all` and `neq` above.
//! - `null` takes no modifier and is not listed with other values.
//! - A Base64 encoding spells out the `windash` alternatives of a value,
//!   and `base64offset` makes three forms of each. Each value — the
//!   scalar, or each member of a list on its own — expands into at most
//!   1024 values that way; a rule with a value past that is rejected as
//!   malformed. The ceiling is neither shared by the members of a list nor
//!   a limit on how many members a list has:
//!   `f|windash|base64: ['a----', 'b----']` expands each member into 625
//!   values, 1250 in all, and is read.
//! - A detection nests `and`, `or` and `not` at most 32 deep, counting
//!   those a search identifier's mappings and lists stand for, and a
//!   `condition` nests `not` and parentheses at most 64 deep; a rule past
//!   either is rejected as malformed. The first bound keeps every rule a
//!   rule bundle stores readable from it.
//! - A rule's YAML nests sequences and mappings at most 64 deep, the
//!   rule's own top-level mapping included and every collection an alias
//!   copies in counted where it lands; a rule past that is rejected as
//!   malformed.
//!
//! ## Case
//!
//! A string condition that is not a regular expression — a plain value,
//! `contains`, `startswith`, `endswith`, a wildcard value, and the values
//! the encoding modifiers produce — ignores case unless `cased` is given.
//! A `re` condition is case-sensitive unless `re|i` is given. Ignoring case
//! applies to ASCII letters only, as vectorscan's `CASELESS` does.
//!
//! ## Regular expressions
//!
//! A `re` value is not held to the metacharacters of Sigma 2.1: it is taken
//! in the PCRE syntax vectorscan accepts. A rule with an expression
//! vectorscan rejects — a back-reference, say, or one that matches an empty
//! value, as vectorscan compiles without `ALLOWEMPTY` — is read, then left
//! out when compiled (see [`CompileStats::excluded`]).
//!
//! ## Bytes
//!
//! A value tagged `!bytes` is a byte string: `\xHH` is the byte with hex
//! value `HH`, `\\` is a backslash, and every other character is its UTF-8
//! encoding. Such a value is literal — `*`, `?` and `%` are plain bytes —
//! and it takes the string modifiers except `windash` and the UTF-16 ones:
//!
//! ```yaml
//! payload|contains: !bytes 'GET \x00\xff /'
//! ```
//!
//! A plain Sigma string never carries a tag, so the two cannot be confused.
//! Without the tag, a backslash keeps its Sigma meaning.
//!
//! ## `%home_net%`
//!
//! `expand` accepts one placeholder, `%home_net%`, standing for the ranges
//! the caller passes when matching. It is written only as a whole value of
//! `field|expand|cidr`, with `expand` and `cidr` in that order and no other
//! modifier; the list may hold plain ranges beside it:
//!
//! ```yaml
//! resp_addr|expand|cidr:
//!     - '%home_net%'
//!     - 192.0.2.0/24
//! ```
//!
//! Any other placeholder is rejected as having no value
//! ([`ReadError::PlaceholderValueMissing`]).
//!
//! ## Values
//!
//! - **Fields with several values.** A condition on a field holds if it
//!   holds for one of the field's values. `all` is the AND of the rule's
//!   values, each of which holds if it holds for one of the field's values.
//! - **Fields with no value.** Only `null` and `exists: false` hold; every
//!   other condition, `neq` included, is false. An empty value is a value:
//!   it matches `''`, and not `null`. `fieldref` is false if either field
//!   has no value.
//! - **Numbers.** A numeric comparison, and a plain integer value, read the
//!   event's value as a decimal integer (`i64`); a value that does not read
//!   as one makes them false.
//! - **Addresses.** `cidr` takes an address value as it is and reads a byte
//!   value as an IP address; a value that does not read as one makes it
//!   false. An IPv4 range also holds the IPv4-mapped IPv6 form
//!   (`::ffff:a.b.c.d`) of its addresses; an IPv6 range compares an IPv6
//!   address as it is, and holds no IPv4 address.
//! - **Conditions that match an empty value.** A plain, `contains`,
//!   `startswith` or `endswith` condition whose value is `''` or only `*`
//!   is checked without vectorscan, as Sigma defines it.
//! - **`?`** matches one UTF-8 encoded character, or one byte where no
//!   character starts. A character is a well-formed encoding by RFC 3629
//!   (as Rust's `str` reads UTF-8): no overlong encoding, no surrogate,
//!   nothing above U+10FFFF. What `?` takes depends only on the bytes where
//!   it starts: the whole character if one starts there, else that one
//!   byte — a continuation byte, a byte that starts no character, or a lead
//!   byte whose character is cut short or followed by a byte out of range,
//!   whose following bytes each count as one byte. So `??` matches the
//!   bytes `E3 81` and `?A` the bytes `E3 41`, while `?` alone matches
//!   neither, nor the overlong `C0 80`. An empty value matches no `?`.
//! - Rules with the same source and id are all compiled and matched.
//!
//! [sigma]: https://github.com/SigmaHQ/sigma-specification/tree/v2.1.0

mod attrs;
mod bundle;
mod cidr;
mod compile;
mod condition;
mod detection;
mod event;
mod expr;
mod matcher;
pub mod reason;
mod rule;
mod summary;
mod wildcard;
mod yaml;

pub use attrs::{Model, Os, Source, UnknownName};
pub use bundle::{BundleError, RuleBundle};
pub use cidr::{Cidr, CidrParseError};
pub use compile::{CompileError, CompileStats, CompiledRules, ExcludedRule, KindCount, compile};
pub use event::{Event, FieldValue};
pub use matcher::{MatchError, Matcher, RuleMatch};
pub use rule::{ReadError, Rule, read_rules};
pub use summary::{
    Blocklist, BlocklistError, ConversionSummary, OrderKey, SourceVersion, content_digest,
};

/// The version of `rulec`, as Cargo gives it. Rule bundles and conversion
/// summaries carry it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use vectorscan_rs::{BlockDatabase, Flag, Pattern, Scan};

    /// Compiles one pattern with vectorscan and scans one input with it,
    /// which fails to build or run unless vectorscan is linked.
    #[test]
    fn vectorscan_compiles_and_scans() {
        const PATTERN_ID: u32 = 7;

        let pattern = Pattern::new(b"rule[0-9]+c".to_vec(), Flag::empty(), Some(PATTERN_ID));
        let db = BlockDatabase::new(vec![pattern]).expect("compile the pattern");
        let mut scanner = db.create_scanner().expect("allocate scratch space");

        let mut matches = Vec::new();
        scanner
            .scan(b"a rule42c match", |id, _from, to, _flags| {
                matches.push((id, to));
                Scan::Continue
            })
            .expect("scan the input");
        assert_eq!(matches, vec![(PATTERN_ID, 9)]);

        let mut misses = 0_usize;
        scanner
            .scan(b"no hit here", |_, _, _, _| {
                misses += 1;
                Scan::Continue
            })
            .expect("scan the input");
        assert_eq!(misses, 0);
    }
}
