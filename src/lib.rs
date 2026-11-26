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
//! [`SourceVersion`], [`content_digest`], [`Blocklist`]). It reads fields out
//! of `giganto-client`'s network records, which implement [`Event`] (see
//! [Network records](#network-records)), keeps the catalog of their fields
//! ([`catalog_fields`], [`field_status`], [`unknown_fields`]), and provides
//! the normalization functions converters apply to patterns and the records
//! to values ([`normalize_uri`], [`normalize_host`], [`decode_body`],
//! [`join_cert_name`], [`join_header_names`], [`header_block`],
//! [`split_ssh_banner`]). The converters themselves are not here yet.
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
//! # Network records
//!
//! `giganto-client`'s `Conn`, `Dns`, `Http`, `Tls` and `Ssh` records
//! (`giganto_client::ingest::network`) implement [`Event`] as they are, so
//! a record is passed to [`Matcher::matches`] directly. Their kinds are
//! `conn`, `dns`, `http`, `tls` and `ssh`, and none has a host header, so
//! [`Event::os_family`] is `None` for all of them.
//!
//! ## Fields
//!
//! Each record answers every one of its columns by the column's name, and
//! the derived fields below. [`catalog_fields`] lists them for each kind,
//! [`field_status`] says whether a kind has a field, and [`unknown_fields`]
//! names the fields a rule uses that its kind lacks. A name not in the
//! catalog has no value.
//!
//! | Kind | Columns | Derived fields |
//! | --- | --- | --- |
//! | all five | `orig_addr`, `orig_port`, `resp_addr`, `resp_port`, `proto`, `start_time`, `duration`, `orig_pkts`, `resp_pkts`, `orig_l2_bytes`, `resp_l2_bytes` | |
//! | `conn` | `conn_state`, `service`, `orig_bytes`, `resp_bytes` | |
//! | `dns` | `query`, `answer`, `trans_id`, `rtt`, `qclass`, `qtype`, `rcode`, `aa_flag`, `tc_flag`, `rd_flag`, `ra_flag`, `ttl` | |
//! | `http` | `method`, `host`, `uri`, `referer`, `version`, `user_agent`, `request_len`, `response_len`, `status_code`, `status_msg`, `username`, `password`, `cookie`, `content_encoding`, `content_type`, `cache_control`, `filenames`, `mime_types`, `body`, `state`, `request_header_names`, `accept`, `connection`, `accept_encoding`, `accept_language`, `pragma` | `uri.normalized`, `host.normalized`, `body.request`, `body.response`, `header_names.joined`, `header_block` |
//! | `tls` | `server_name`, `alpn_protocol`, `ja3`, `version`, `client_cipher_suites`, `client_extensions`, `cipher`, `extensions`, `ja3s`, `serial`, `subject_country`, `subject_org_name`, `subject_common_name`, `validity_not_before`, `validity_not_after`, `subject_alt_name`, `issuer_country`, `issuer_org_name`, `issuer_org_unit_name`, `issuer_common_name`, `last_alert` | `subject.joined`, `issuer.joined` |
//! | `ssh` | `client`, `server`, `cipher_alg`, `mac_alg`, `compression_alg`, `kex_alg`, `host_key_alg`, `hassh_algorithms`, `hassh`, `hassh_server_algorithms`, `hassh_server`, `client_shka`, `server_shka` | `client.proto`, `client.software`, `server.proto`, `server.software` |
//!
//! ## Value forms
//!
//! | Column type | Values |
//! | --- | --- |
//! | `String` | one byte value, its UTF-8 bytes; an empty string is one empty value, not no value |
//! | `Vec<u8>` (`Http::body`) | one byte value, the bytes as they are; an empty body is one empty value |
//! | integer (`u8`, `u16`, `i32`, `i64`, `u64`, `usize`) | one [`FieldValue::Int`]; a `u64` or `usize` past `i64::MAX` is one byte value, its decimal text |
//! | `bool` | one byte value, `true` or `false` |
//! | `IpAddr` | one [`FieldValue::Addr`] |
//! | `Vec<String>`, `Vec<u16>`, `Vec<i32>` | one value per element, as above, in stored order; an empty list is no value |
//!
//! So `status_code` 200 is `Int(200)`, which both `status_code|gte: 200`
//! and `status_code: '200'` match, and a negative `ttl` is a negative
//! integer.
//!
//! ## Derived fields
//!
//! Each is one byte value made by the public function named, from the
//! record's columns, or no value where said:
//!
//! - `uri.normalized`: [`normalize_uri`] of `uri`, as Suricata 7.0.3 builds
//!   `http.uri` — escapes decoded, dot segments and repeated `/` removed.
//!   No value if `uri` is empty.
//! - `host.normalized`: [`normalize_host`] of `host` — lowercased, port
//!   dropped. No value if `host` is empty.
//! - `body.request`: [`decode_body`] of `body` if `method` is `POST`, byte
//!   for byte; `body.response` the same if `method` is `GET`. No value for
//!   any other method (`post` and `HEAD` included) or an empty body.
//! - `header_names.joined`: [`join_header_names`] of
//!   `request_header_names` — `\r\nHost\r\nUser-Agent\r\n\r\n`. No value
//!   if the list is empty.
//! - `header_block`: [`header_block`] of `request_header_names`, a
//!   `<name>: <value>\r\n` line per name in order, the values of the headers
//!   in [`HEADER_BLOCK_HEADERS`] filled in from the record (matching names
//!   without regard to ASCII case) and every other header's value empty.
//!   `Cookie` gets no line, as in Suricata's `http.header`. No value if no
//!   line is written.
//! - `subject.joined` and `issuer.joined`: [`join_cert_name`] —
//!   `C=…, O=…, OU=…, CN=…`, empty parts skipped; the subject has no `OU`.
//!   No value if every part is empty.
//! - `client.proto`, `client.software`, `server.proto`, `server.software`:
//!   [`split_ssh_banner`] of `client` or `server`, as Suricata 7.0.3 splits
//!   the banner. No value if the banner is not `SSH-<proto>-<software>…`,
//!   and no software value if the banner has none.
//!
//! ## Bodies
//!
//! [`decode_body`] unpacks the chunked transfer coding, then one layer of
//! gzip, zlib or raw deflate, recognizing each from the bytes, since a
//! record holds no response headers and may hold only the start of a
//! body. A body cut short gives what it unpacks to up to the cut; a body
//! it cannot unpack is returned as it is. Raw deflate is used only when
//! the whole body is one complete stream, or when inflating it reaches
//! [`MAX_DECODED_BODY_LEN`] before the stream ends, so a plain body is
//! not misread as one. Unpacked output is cut at [`MAX_DECODED_BODY_LEN`]
//! (1 MiB), and unpacking stops there. Its documentation has the rules in
//! full.
//!
//! [sigma]: https://github.com/SigmaHQ/sigma-specification/tree/v2.1.0

mod attrs;
mod bestfit;
mod body;
mod bundle;
mod catalog;
mod cidr;
mod compile;
mod condition;
mod derived;
mod detection;
mod event;
mod expr;
mod matcher;
mod network;
mod normalize;
pub mod reason;
mod rule;
mod summary;
mod wildcard;
mod yaml;

pub use attrs::{Model, Os, Source, UnknownName};
pub use body::{MAX_DECODED_BODY_LEN, decode_body};
pub use bundle::{BundleError, RuleBundle};
pub use catalog::{FieldStatus, KindNotCataloged, catalog_fields, field_status, unknown_fields};
pub use cidr::{Cidr, CidrParseError};
pub use compile::{CompileError, CompileStats, CompiledRules, ExcludedRule, KindCount, compile};
pub use derived::{
    HEADER_BLOCK_HEADERS, SshBanner, header_block, join_cert_name, join_header_names,
    split_ssh_banner,
};
pub use event::{Event, FieldValue};
pub use matcher::{MatchError, Matcher, RuleMatch};
pub use normalize::{normalize_host, normalize_uri};
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
