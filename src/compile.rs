//! Compiles rules into vectorscan databases, one per field of each event
//! kind, and the residual conditions checked without vectorscan.

use std::{
    collections::{BTreeMap, HashMap},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use giganto_client::RawEventKind;
use serde::{Deserialize, Serialize};
use vectorscan_rs::{BlockDatabase, Flag, Pattern};

use crate::{
    attrs::{Model, Source},
    cidr::Cidr,
    expr::{Cmp, Expr, Piece, RegexPattern, StrPattern, Test},
    rule::Rule,
};

/// One byte, or one well-formed multi-byte UTF-8 character: what the
/// wildcard `?` is scanned as.
///
/// It accepts everything `?` matches and more: `?` takes a lead byte on its
/// own only where no well-formed character starts there, which depends on
/// the bytes after it, and a vectorscan expression cannot look at them
/// without consuming them. So a value this expression matches is checked
/// again in Rust ([`StrPattern::matches`]), which decides.
const ANY_CHAR: &[u8] = br"(?:[\x00-\xff]|[\xc2-\xdf][\x80-\xbf]|\xe0[\xa0-\xbf][\x80-\xbf]|[\xe1-\xec\xee\xef][\x80-\xbf]{2}|\xed[\x80-\x9f][\x80-\xbf]|\xf0[\x90-\xbf][\x80-\xbf]{2}|[\xf1-\xf3][\x80-\xbf]{3}|\xf4[\x80-\x8f][\x80-\xbf]{2})";

/// A count of rules for one kind of raw event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KindCount {
    /// The kind of raw event.
    pub kind: RawEventKind,
    /// The number of rules.
    pub count: usize,
}

/// A rule left out of compilation because vectorscan rejected one of its
/// patterns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExcludedRule {
    /// The source of the rule.
    pub source: Source,
    /// The id of the rule in its source.
    pub source_rule_id: String,
    /// The detection model of the rule.
    pub model: Model,
    /// vectorscan's message.
    pub message: String,
}

/// Statistics of one compilation.
#[derive(Clone, Debug, Default)]
pub struct CompileStats {
    accepted: BTreeMap<(Source, Model), usize>,
    excluded: Vec<ExcludedRule>,
    always_check: BTreeMap<(Source, u32), KindCount>,
    compile_time: Duration,
    db_size: usize,
}

impl CompileStats {
    /// Returns the number of rules compiled.
    #[must_use]
    pub fn accepted(&self) -> usize {
        self.accepted.values().sum()
    }

    /// Returns the number of rules of `source` compiled, by model.
    #[must_use]
    pub fn accepted_for(&self, source: Source) -> BTreeMap<Model, usize> {
        self.accepted
            .iter()
            .filter(|((s, _), _)| *s == source)
            .map(|((_, m), n)| (*m, *n))
            .collect()
    }

    /// Returns the rules left out, with vectorscan's message for each.
    #[must_use]
    pub fn excluded(&self) -> &[ExcludedRule] {
        &self.excluded
    }

    /// Returns the number of always-checked rules for each kind of raw
    /// event, in the order of the kinds' numbers.
    #[must_use]
    pub fn always_check(&self) -> Vec<KindCount> {
        self.always_check_where(|_| true)
    }

    /// Returns the number of always-checked rules of `source` for each kind
    /// of raw event, in the order of the kinds' numbers.
    #[must_use]
    pub fn always_check_for(&self, source: Source) -> Vec<KindCount> {
        self.always_check_where(|s| s == source)
    }

    fn always_check_where(&self, keep: impl Fn(Source) -> bool) -> Vec<KindCount> {
        let mut by_kind: BTreeMap<u32, KindCount> = BTreeMap::new();
        for ((source, number), count) in &self.always_check {
            if keep(*source) {
                by_kind
                    .entry(*number)
                    .and_modify(|c| c.count += count.count)
                    .or_insert(*count);
            }
        }
        by_kind.into_values().collect()
    }

    /// Returns how long the compilation took.
    #[must_use]
    pub fn compile_time(&self) -> Duration {
        self.compile_time
    }

    /// Returns the total size of the vectorscan databases in bytes.
    #[must_use]
    pub fn db_size(&self) -> usize {
        self.db_size
    }
}

/// An error building the vectorscan databases.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CompileError {
    /// vectorscan failed to build the database of one field, although
    /// each rule's patterns compiled on their own.
    #[error("building the vectorscan database of field `{field}` of {kind:?}: {message}")]
    Database {
        /// The kind of raw event.
        kind: RawEventKind,
        /// The field.
        field: String,
        /// vectorscan's message.
        message: String,
    },
    /// One field has more distinct patterns than vectorscan has ids.
    #[error("field `{field}` of {kind:?} has more patterns than vectorscan can number")]
    TooManyPatterns {
        /// The kind of raw event.
        kind: RawEventKind,
        /// The field.
        field: String,
    },
}

/// A test with its patterns resolved to database entries.
#[derive(Debug)]
pub(crate) enum CTest {
    /// A pattern scanned by vectorscan: the condition holds for a value it
    /// matched, if `check` is `None` or also matches the value. `check` is
    /// the string pattern of a condition with a `?`, which vectorscan
    /// matches more widely than it means.
    Pattern {
        db: usize,
        id: u32,
        check: Option<StrPattern>,
    },
    Empty,
    Any,
    Null,
    Exists(bool),
    Num(Cmp, i64),
    Len(Cmp, u64),
    Cidr(Cidr),
    HomeNet,
    FieldRef {
        other: String,
        cased: bool,
    },
    Neq(Vec<CTest>),
}

/// An expression with its patterns resolved to database entries.
#[derive(Debug)]
pub(crate) enum CExpr {
    Never,
    And(Vec<CExpr>),
    Or(Vec<CExpr>),
    Not(Box<CExpr>),
    Leaf { field: String, test: CTest },
}

#[derive(Debug)]
pub(crate) struct CompiledRule {
    pub(crate) rule: Rule,
    pub(crate) expr: CExpr,
    /// The fields the rule reads, including the fields `fieldref` names.
    pub(crate) fields: Vec<String>,
}

/// The vectorscan database of one field of one kind of raw event.
#[derive(Debug)]
pub(crate) struct FieldDb {
    pub(crate) field: String,
    pub(crate) db: BlockDatabase,
    /// The rules that own each pattern, by pattern id.
    pub(crate) owners: Vec<Vec<u32>>,
}

/// What matching needs for one kind of raw event.
#[derive(Debug, Default)]
pub(crate) struct KindIndex {
    /// The databases of the kind's fields, as indices into `dbs`.
    pub(crate) dbs: Vec<usize>,
    /// The rules checked for every event of the kind.
    pub(crate) always: Vec<u32>,
    /// Counts the events skipped by rules with an OS, if the kind has such
    /// rules.
    pub(crate) skipped_os: Option<AtomicU64>,
}

/// Rules compiled for matching.
///
/// It is `Send + Sync`: threads share one and match with a
/// [`Matcher`](crate::Matcher) each.
#[derive(Debug)]
pub struct CompiledRules {
    pub(crate) rules: Vec<CompiledRule>,
    pub(crate) dbs: Vec<FieldDb>,
    pub(crate) kinds: HashMap<RawEventKind, KindIndex>,
    stats: CompileStats,
}

impl CompiledRules {
    /// Returns the statistics of the compilation.
    #[must_use]
    pub fn stats(&self) -> &CompileStats {
        &self.stats
    }

    /// Returns the number of events of `kind` that had no host header, so
    /// rules with an `os` were not checked against them.
    #[must_use]
    pub fn skipped_os_events(&self, kind: RawEventKind) -> u64 {
        self.kinds
            .get(&kind)
            .and_then(|k| k.skipped_os.as_ref())
            .map_or(0, |n| n.load(Ordering::Relaxed))
    }

    /// Returns the rules compiled, in input order.
    pub fn rules(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter().map(|r| &r.rule)
    }
}

/// Collects the distinct patterns of one database.
struct DbBuilder {
    kind: RawEventKind,
    field: String,
    patterns: Vec<Pattern>,
    ids: HashMap<(Vec<u8>, u32), u32>,
    owners: Vec<Vec<u32>>,
}

/// Returns the vectorscan expression and flags of a string pattern. Every
/// literal byte is escaped as `\xHH`, so no byte, NUL included, keeps the
/// pattern from compiling.
pub(crate) fn str_expression(pattern: &StrPattern) -> (Vec<u8>, Flag) {
    let mut pieces = pattern.pieces.as_slice();
    let mut expr = Vec::new();
    if pieces.first() == Some(&Piece::AnyStr) {
        pieces = pieces.get(1..).unwrap_or_default();
    } else {
        expr.extend_from_slice(br"\A");
    }
    let open_end = pieces.last() == Some(&Piece::AnyStr);
    if open_end {
        pieces = pieces.get(..pieces.len() - 1).unwrap_or_default();
    }
    let escape = |expr: &mut Vec<u8>, bytes: &[u8]| {
        for b in bytes {
            expr.extend_from_slice(format!("\\x{b:02x}").as_bytes());
        }
    };
    for piece in pieces {
        match piece {
            Piece::Lit(bytes) => escape(&mut expr, bytes),
            Piece::AnyStr => expr.extend_from_slice(b".*"),
            Piece::AnyChar => expr.extend_from_slice(ANY_CHAR),
            Piece::Alt(choices) => {
                expr.extend_from_slice(b"(?:");
                for (i, choice) in choices.iter().enumerate() {
                    if i > 0 {
                        expr.push(b'|');
                    }
                    escape(&mut expr, choice);
                }
                expr.push(b')');
            }
        }
    }
    if !open_end {
        expr.extend_from_slice(br"\z");
    }
    let mut flags = Flag::DOTALL | Flag::SINGLEMATCH;
    if !pattern.cased {
        flags |= Flag::CASELESS;
    }
    (expr, flags)
}

/// Returns the vectorscan expression and flags of a regular expression.
/// A NUL character, which vectorscan cannot take in an expression, is
/// written as the escape `\x00` it stands for.
pub(crate) fn regex_expression(pattern: &RegexPattern) -> (Vec<u8>, Flag) {
    let mut expr = Vec::with_capacity(pattern.expr.len());
    let mut backslashes = 0_usize;
    for &b in pattern.expr.as_bytes() {
        if b == 0 {
            // After an odd run of backslashes the NUL is escaped already,
            // and `x00` completes the escape.
            if backslashes.is_multiple_of(2) {
                expr.push(b'\\');
            }
            expr.extend_from_slice(b"x00");
            backslashes = 0;
            continue;
        }
        backslashes = if b == b'\\' { backslashes + 1 } else { 0 };
        expr.push(b);
    }
    let mut flags = Flag::SINGLEMATCH;
    if pattern.caseless {
        flags |= Flag::CASELESS;
    }
    if pattern.multiline {
        flags |= Flag::MULTILINE;
    }
    if pattern.dotall {
        flags |= Flag::DOTALL;
    }
    (expr, flags)
}

/// Returns the vectorscan expression and flags of a test, if it is matched
/// by vectorscan.
fn expression(test: &Test) -> Option<(Vec<u8>, Flag)> {
    match test {
        Test::Str(p) => Some(str_expression(p)),
        Test::Regex(r) => Some(regex_expression(r)),
        _ => None,
    }
}

/// Collects every vectorscan expression of a rule.
fn rule_expressions(expr: &Expr) -> Vec<(Vec<u8>, Flag)> {
    let mut out = Vec::new();
    expr.for_each_leaf(&mut |leaf| match &leaf.test {
        Test::Neq(inner) => out.extend(inner.iter().filter_map(expression)),
        test => out.extend(expression(test)),
    });
    out
}

fn compile_message(error: vectorscan_rs::Error) -> String {
    match error {
        vectorscan_rs::Error::HyperscanCompile(message, _) => message,
        other => other.to_string(),
    }
}

/// Compiles rules, from any number of sources, for matching.
///
/// Each rule's patterns are compiled on their own first; a rule vectorscan
/// rejects is left out and reported in [`CompileStats::excluded`], and the
/// rest are compiled. Rules with the same source and id are all compiled.
///
/// # Errors
///
/// Returns an error if vectorscan fails to build a field's database from
/// patterns it accepted rule by rule, or a field has more than `u32::MAX`
/// distinct patterns.
pub fn compile<I>(rules: I) -> Result<CompiledRules, CompileError>
where
    I: IntoIterator<Item = Rule>,
{
    let start = Instant::now();
    let mut stats = CompileStats::default();
    let mut accepted = Vec::new();
    for rule in rules {
        let patterns: Vec<Pattern> = rule_expressions(&rule.detection)
            .into_iter()
            .map(|(expr, flags)| Pattern::new(expr, flags, None))
            .collect();
        if !patterns.is_empty()
            && let Err(e) = BlockDatabase::new(patterns)
        {
            stats.excluded.push(ExcludedRule {
                source: rule.source(),
                source_rule_id: rule.source_rule_id().to_string(),
                model: rule.model(),
                message: compile_message(e),
            });
            continue;
        }
        accepted.push(rule);
    }

    let mut builders: Vec<DbBuilder> = Vec::new();
    let mut builder_index: HashMap<(RawEventKind, String), usize> = HashMap::new();
    let mut kinds: HashMap<RawEventKind, KindIndex> = HashMap::new();
    let mut compiled = Vec::with_capacity(accepted.len());
    for (index, rule) in accepted.into_iter().enumerate() {
        let rule_index = u32::try_from(index).map_err(|_| CompileError::TooManyPatterns {
            kind: rule.kind(),
            field: String::new(),
        })?;
        let mut cx = ExprCompiler {
            kind: rule.kind(),
            rule: rule_index,
            builders: &mut builders,
            builder_index: &mut builder_index,
            fields: Vec::new(),
        };
        let expr = cx.expr(&rule.detection)?;
        let mut fields = cx.fields;
        fields.sort_unstable();
        fields.dedup();

        let entry = kinds.entry(rule.kind()).or_default();
        if rule.os().is_some() && entry.skipped_os.is_none() {
            entry.skipped_os = Some(AtomicU64::new(0));
        }
        if always_check(&expr) != Tri::False {
            entry.always.push(rule_index);
            stats
                .always_check
                .entry((rule.source(), u32::from(rule.kind())))
                .or_insert(KindCount {
                    kind: rule.kind(),
                    count: 0,
                })
                .count += 1;
        }
        *stats
            .accepted
            .entry((rule.source(), rule.model()))
            .or_default() += 1;
        compiled.push(CompiledRule { rule, expr, fields });
    }

    let mut dbs = Vec::with_capacity(builders.len());
    for (index, builder) in builders.into_iter().enumerate() {
        let db = BlockDatabase::new(builder.patterns).map_err(|e| CompileError::Database {
            kind: builder.kind,
            field: builder.field.clone(),
            message: compile_message(e),
        })?;
        stats.db_size += db.size().map_err(|e| CompileError::Database {
            kind: builder.kind,
            field: builder.field.clone(),
            message: compile_message(e),
        })?;
        kinds.entry(builder.kind).or_default().dbs.push(index);
        dbs.push(FieldDb {
            field: builder.field,
            db,
            owners: builder.owners,
        });
    }
    stats.compile_time = start.elapsed();
    Ok(CompiledRules {
        rules: compiled,
        dbs,
        kinds,
        stats,
    })
}

struct ExprCompiler<'b> {
    kind: RawEventKind,
    rule: u32,
    builders: &'b mut Vec<DbBuilder>,
    builder_index: &'b mut HashMap<(RawEventKind, String), usize>,
    fields: Vec<String>,
}

impl ExprCompiler<'_> {
    fn expr(&mut self, expr: &Expr) -> Result<CExpr, CompileError> {
        Ok(match expr {
            Expr::Never => CExpr::Never,
            Expr::And(items) => CExpr::And(self.exprs(items)?),
            Expr::Or(items) => CExpr::Or(self.exprs(items)?),
            Expr::Not(item) => CExpr::Not(Box::new(self.expr(item)?)),
            Expr::Leaf(leaf) => {
                self.fields.push(leaf.field.clone());
                CExpr::Leaf {
                    field: leaf.field.clone(),
                    test: self.test(&leaf.field, &leaf.test)?,
                }
            }
        })
    }

    fn exprs(&mut self, items: &[Expr]) -> Result<Vec<CExpr>, CompileError> {
        items.iter().map(|item| self.expr(item)).collect()
    }

    fn test(&mut self, field: &str, test: &Test) -> Result<CTest, CompileError> {
        Ok(match test {
            Test::Str(p) => {
                let (expr, flags) = str_expression(p);
                let check = p.has_any_char().then(|| p.clone());
                self.pattern(field, expr, flags, check)?
            }
            Test::Regex(r) => {
                let (expr, flags) = regex_expression(r);
                self.pattern(field, expr, flags, None)?
            }
            Test::Empty => CTest::Empty,
            Test::Any => CTest::Any,
            Test::Null => CTest::Null,
            Test::Exists(b) => CTest::Exists(*b),
            Test::Num(cmp, n) => CTest::Num(*cmp, *n),
            Test::Len(cmp, n) => CTest::Len(*cmp, *n),
            Test::Cidr(net) => CTest::Cidr(*net),
            Test::HomeNet => CTest::HomeNet,
            Test::FieldRef { other, cased } => {
                self.fields.push(other.clone());
                CTest::FieldRef {
                    other: other.clone(),
                    cased: *cased,
                }
            }
            Test::Neq(inner) => CTest::Neq(
                inner
                    .iter()
                    .map(|t| self.test(field, t))
                    .collect::<Result<_, _>>()?,
            ),
        })
    }

    fn pattern(
        &mut self,
        field: &str,
        expr: Vec<u8>,
        flags: Flag,
        check: Option<StrPattern>,
    ) -> Result<CTest, CompileError> {
        let key = (self.kind, field.to_string());
        let db = match self.builder_index.get(&key) {
            Some(db) => *db,
            None => {
                let db = self.builders.len();
                self.builders.push(DbBuilder {
                    kind: self.kind,
                    field: field.to_string(),
                    patterns: Vec::new(),
                    ids: HashMap::new(),
                    owners: Vec::new(),
                });
                self.builder_index.insert(key, db);
                db
            }
        };
        let too_many = || CompileError::TooManyPatterns {
            kind: self.kind,
            field: field.to_string(),
        };
        let builder = self.builders.get_mut(db).ok_or_else(too_many)?;
        let id = match builder.ids.get(&(expr.clone(), flags.bits())) {
            Some(id) => *id,
            None => {
                let id = u32::try_from(builder.patterns.len()).map_err(|_| too_many())?;
                builder
                    .patterns
                    .push(Pattern::new(expr.clone(), flags, Some(id)));
                builder.ids.insert((expr, flags.bits()), id);
                builder.owners.push(Vec::new());
                id
            }
        };
        if let Some(owners) = usize::try_from(id)
            .ok()
            .and_then(|i| builder.owners.get_mut(i))
            && owners.last() != Some(&self.rule)
        {
            owners.push(self.rule);
        }
        Ok(CTest::Pattern { db, id, check })
    }
}

/// A value of three-valued logic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tri {
    True,
    False,
    Unknown,
}

/// Evaluates an expression with every vectorscan pattern false and every
/// other condition unknown. A rule whose result is not false can match an
/// event no pattern matched, so it is checked for every event.
fn always_check(expr: &CExpr) -> Tri {
    match expr {
        CExpr::Never => Tri::False,
        CExpr::And(items) => {
            let mut result = Tri::True;
            for item in items {
                match always_check(item) {
                    Tri::False => return Tri::False,
                    Tri::Unknown => result = Tri::Unknown,
                    Tri::True => {}
                }
            }
            result
        }
        CExpr::Or(items) => {
            let mut result = Tri::False;
            for item in items {
                match always_check(item) {
                    Tri::True => return Tri::True,
                    Tri::Unknown => result = Tri::Unknown,
                    Tri::False => {}
                }
            }
            result
        }
        CExpr::Not(item) => match always_check(item) {
            Tri::True => Tri::False,
            Tri::False => Tri::True,
            Tri::Unknown => Tri::Unknown,
        },
        CExpr::Leaf { test, .. } => match test {
            CTest::Pattern { .. } => Tri::False,
            _ => Tri::Unknown,
        },
    }
}
