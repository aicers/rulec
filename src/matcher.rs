//! Matches raw events against compiled rules.

use std::collections::{HashMap, HashSet};

use giganto_client::ingest::endpoint::OsFamily;
use vectorscan_rs::{BlockScanner, Scan};

use crate::{
    cidr::Cidr,
    compile::{CExpr, CTest, CompiledRules},
    event::{Event, FieldValue},
    rule::Rule,
};

/// A rule an event matched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleMatch<'a> {
    rule: &'a Rule,
    fields: Vec<&'a str>,
}

impl<'a> RuleMatch<'a> {
    /// Returns the rule.
    #[must_use]
    pub fn rule(&self) -> &'a Rule {
        self.rule
    }

    /// Returns the names of the fields whose conditions made the rule
    /// match, sorted and without repeats.
    #[must_use]
    pub fn fields(&self) -> &[&'a str] {
        &self.fields
    }
}

/// An error matching an event.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MatchError {
    /// vectorscan failed to allocate scratch space or to scan.
    #[error("scanning field `{field}`: {message}")]
    Scan {
        /// The field being scanned.
        field: String,
        /// vectorscan's message.
        message: String,
    },
    /// A value is longer than vectorscan can scan in one call (4 GiB).
    #[error("a value of field `{field}` is too long to scan")]
    ValueTooLong {
        /// The field.
        field: String,
    },
}

/// Matches events against one [`CompiledRules`].
///
/// A matcher holds vectorscan scratch space, so each thread uses its own;
/// all of them may share one `CompiledRules`.
pub struct Matcher<'a> {
    compiled: &'a CompiledRules,
    scanners: Vec<Option<BlockScanner<'a>>>,
}

impl CompiledRules {
    /// Returns a matcher for these rules. Scratch space for each database
    /// is allocated the first time it is scanned.
    #[must_use]
    pub fn matcher(&self) -> Matcher<'_> {
        Matcher {
            compiled: self,
            scanners: self.dbs.iter().map(|_| None).collect(),
        }
    }
}

impl<'a> Matcher<'a> {
    /// Matches one event and returns the rules it matched, in the order the
    /// rules were compiled.
    ///
    /// `home_net` is the value of `%home_net%`: the ranges a
    /// `field|expand|cidr: '%home_net%'` condition tests. With no ranges
    /// that condition is false.
    ///
    /// A rule with an `os` is checked only against an event whose host
    /// header has that OS. An event without a host header is counted in
    /// [`CompiledRules::skipped_os_events`] when its kind has such rules.
    ///
    /// # Errors
    ///
    /// Returns an error if vectorscan cannot allocate scratch space or
    /// scan, or a value is too long to scan.
    pub fn matches<'e, E>(
        &mut self,
        event: &'e E,
        home_net: &'e [Cidr],
    ) -> Result<Vec<RuleMatch<'a>>, MatchError>
    where
        E: Event + ?Sized,
    {
        let compiled = self.compiled;
        let Some(index) = compiled.kinds.get(&event.kind()) else {
            return Ok(Vec::new());
        };
        let mut cx = Context {
            values: HashMap::new(),
            hits: HashSet::new(),
            home_net,
        };
        let mut candidates: Vec<u32> = index.always.clone();

        for &db_index in &index.dbs {
            let Some(db) = compiled.dbs.get(db_index) else {
                continue;
            };
            let field = db.field.as_str();
            cx.load(event, field);
            let values = cx.values.get(field).map(Vec::as_slice).unwrap_or_default();
            if values.is_empty() {
                continue;
            }
            let scan_error = |e: vectorscan_rs::Error| MatchError::Scan {
                field: field.to_string(),
                message: e.to_string(),
            };
            let slot = self
                .scanners
                .get_mut(db_index)
                .ok_or_else(|| MatchError::Scan {
                    field: field.to_string(),
                    message: "no scanner for the database".to_string(),
                })?;
            let scanner = match slot {
                Some(scanner) => scanner,
                None => slot.insert(BlockScanner::new(&db.db).map_err(scan_error)?),
            };
            for (value_index, value) in values.iter().enumerate() {
                let bytes = value.as_bytes();
                if u32::try_from(bytes.len()).is_err() {
                    return Err(MatchError::ValueTooLong {
                        field: field.to_string(),
                    });
                }
                let hits = &mut cx.hits;
                scanner
                    .scan(&bytes, |id, _, _, _| {
                        hits.insert((db_index, id, value_index));
                        Scan::Continue
                    })
                    .map_err(scan_error)?;
            }
        }
        for (db_index, id, _) in &cx.hits {
            if let Some(owners) = compiled
                .dbs
                .get(*db_index)
                .and_then(|db| usize::try_from(*id).ok().and_then(|i| db.owners.get(i)))
            {
                candidates.extend_from_slice(owners);
            }
        }
        candidates.sort_unstable();
        candidates.dedup();

        let os = event.os_family();
        if os.is_none()
            && let Some(skipped) = &index.skipped_os
        {
            skipped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        let candidates: Vec<_> = candidates
            .into_iter()
            .filter_map(|i| usize::try_from(i).ok().and_then(|i| compiled.rules.get(i)))
            .filter(|c| match (c.rule.os(), os) {
                (None, _) => true,
                (Some(_), None | Some(OsFamily::Other(_))) => false,
                (Some(rule_os), Some(family)) => rule_os.is(family),
            })
            .collect();
        for candidate in &candidates {
            for field in &candidate.fields {
                cx.load(event, field);
            }
        }

        let mut matches = Vec::new();
        for candidate in candidates {
            if cx.eval(&candidate.expr) {
                let mut fields = Vec::new();
                cx.witness(&candidate.expr, true, &mut fields);
                fields.sort_unstable();
                fields.dedup();
                matches.push(RuleMatch {
                    rule: &candidate.rule,
                    fields,
                });
            }
        }
        Ok(matches)
    }
}

/// What matching knows about one event.
struct Context<'a, 'e> {
    values: HashMap<&'a str, Vec<FieldValue<'e>>>,
    /// (database, pattern id, value index) of every pattern match.
    hits: HashSet<(usize, u32, usize)>,
    home_net: &'e [Cidr],
}

impl<'a, 'e> Context<'a, 'e> {
    fn load<E: Event + ?Sized>(&mut self, event: &'e E, field: &'a str) {
        self.values
            .entry(field)
            .or_insert_with(|| event.field(field));
    }

    fn values(&self, field: &str) -> &[FieldValue<'e>] {
        self.values
            .get(field)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    fn eval(&self, expr: &CExpr) -> bool {
        match expr {
            CExpr::And(items) => items.iter().all(|item| self.eval(item)),
            CExpr::Or(items) => items.iter().any(|item| self.eval(item)),
            CExpr::Not(item) => !self.eval(item),
            CExpr::Leaf { field, test } => self.leaf(field, test),
        }
    }

    /// Collects the fields of the true conditions that make `expr`, whose
    /// value is `want`, evaluate to it. A false condition under `not` makes
    /// the rule match too, but it is not reported: its field's condition is
    /// not true.
    fn witness<'x>(&self, expr: &'x CExpr, want: bool, out: &mut Vec<&'x str>) {
        match expr {
            CExpr::Not(item) => self.witness(item, !want, out),
            CExpr::And(items) | CExpr::Or(items) => {
                // Every item decides an AND that is true or an OR that is
                // false; otherwise only the items with the wanted value do.
                let every = want == matches!(expr, CExpr::And(_));
                for item in items {
                    if every || self.eval(item) == want {
                        self.witness(item, want, out);
                    }
                }
            }
            // A condition reached here has the value `want`.
            CExpr::Leaf { field, .. } => {
                if want {
                    out.push(field);
                }
            }
        }
    }

    fn leaf(&self, field: &str, test: &CTest) -> bool {
        let values = self.values(field);
        match test {
            CTest::Null => values.is_empty(),
            CTest::Exists(exists) => values.is_empty() != *exists,
            CTest::Neq(inner) => {
                let other_missing = inner.iter().any(
                    |t| matches!(t, CTest::FieldRef { other, .. } if self.values(other).is_empty()),
                );
                // A value counts only if it reads as what every listed
                // value compares — a number, an address — for a value
                // that does not read is false to each of them, not unequal.
                !other_missing
                    && values.iter().enumerate().any(|(i, v)| {
                        inner.iter().all(|t| Self::reads_as(t, v))
                            && !inner.iter().any(|t| self.value_holds(t, i, v))
                    })
            }
            test => values
                .iter()
                .enumerate()
                .any(|(i, v)| self.value_holds(test, i, v)),
        }
    }

    /// Returns whether `value` reads as the type `test` compares; only a
    /// numeric or an address test needs one.
    fn reads_as(test: &CTest, value: &FieldValue<'_>) -> bool {
        match test {
            CTest::Num(..) => value.as_int().is_some(),
            CTest::Cidr(_) | CTest::HomeNet => value.as_addr().is_some(),
            _ => true,
        }
    }

    /// Returns whether `test` holds for the value at `index` of `field`.
    fn value_holds(&self, test: &CTest, index: usize, value: &FieldValue<'_>) -> bool {
        match test {
            CTest::Pattern { db, id } => self.hits.contains(&(*db, *id, index)),
            CTest::Empty => value.byte_len() == 0,
            CTest::Any => true,
            CTest::Num(cmp, n) => value.as_int().is_some_and(|v| cmp.holds(&v, n)),
            CTest::Len(cmp, n) => {
                u64::try_from(value.byte_len()).is_ok_and(|len| cmp.holds(&len, n))
            }
            CTest::Cidr(net) => value.as_addr().is_some_and(|a| net.contains(a)),
            CTest::HomeNet => value
                .as_addr()
                .is_some_and(|a| self.home_net.iter().any(|net| net.contains(a))),
            CTest::FieldRef { other, cased } => {
                let bytes = value.as_bytes();
                self.values(other).iter().any(|w| {
                    let w = w.as_bytes();
                    if *cased {
                        *bytes == *w
                    } else {
                        bytes.eq_ignore_ascii_case(&w)
                    }
                })
            }
            // These look at the whole field and never stand inside `neq`.
            CTest::Null | CTest::Exists(_) | CTest::Neq(_) => false,
        }
    }
}
