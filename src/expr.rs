//! The parsed form of a rule's detection: a boolean expression over field
//! conditions.

use serde::{Deserialize, Serialize};

use crate::cidr::Cidr;

/// A boolean expression over field conditions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Expr {
    And(Vec<Expr>),
    Or(Vec<Expr>),
    Not(Box<Expr>),
    Leaf(Leaf),
}

impl Expr {
    /// Returns an AND of `items`, or the item itself if there is one.
    pub(crate) fn and(mut items: Vec<Expr>) -> Expr {
        if items.len() == 1
            && let Some(item) = items.pop()
        {
            return item;
        }
        Expr::And(items)
    }

    /// Returns an OR of `items`, or the item itself if there is one.
    pub(crate) fn or(mut items: Vec<Expr>) -> Expr {
        if items.len() == 1
            && let Some(item) = items.pop()
        {
            return item;
        }
        Expr::Or(items)
    }

    /// Returns how many `And`, `Or` and `Not` nodes the deepest path from
    /// the root to a leaf passes through.
    pub(crate) fn depth(&self) -> usize {
        match self {
            Expr::And(items) | Expr::Or(items) => {
                1 + items.iter().map(Expr::depth).max().unwrap_or_default()
            }
            Expr::Not(item) => 1 + item.depth(),
            Expr::Leaf(_) => 0,
        }
    }

    /// Calls `f` on every leaf, in order.
    pub(crate) fn for_each_leaf<'a>(&'a self, f: &mut impl FnMut(&'a Leaf)) {
        match self {
            Expr::And(items) | Expr::Or(items) => {
                for item in items {
                    item.for_each_leaf(f);
                }
            }
            Expr::Not(item) => item.for_each_leaf(f),
            Expr::Leaf(leaf) => f(leaf),
        }
    }
}

/// A condition on one field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Leaf {
    pub(crate) field: String,
    pub(crate) test: Test,
}

/// What a field condition tests.
///
/// Every test but `Null`, `Exists` and `Neq` holds for a field if it holds
/// for one of the field's values; those three look at the field as a whole.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Test {
    /// A string pattern, matched by vectorscan.
    Str(StrPattern),
    /// A regular expression, matched by vectorscan.
    Regex(RegexPattern),
    /// The value is empty (`''`).
    Empty,
    /// Any value (`*`, or `contains: ''`).
    Any,
    /// The field has no value (`null`).
    Null,
    /// The field has a value, or has none (`exists`).
    Exists(bool),
    /// The value read as a decimal integer compares with the number.
    Num(Cmp, i64),
    /// The length of the value in bytes compares with the number (`len`).
    Len(Cmp, u64),
    /// The value is an address in the range (`cidr`).
    Cidr(Cidr),
    /// The value is an address in the ranges the caller passes for
    /// `%home_net%`.
    HomeNet,
    /// The value equals a value of another field (`fieldref`).
    FieldRef { other: String, cased: bool },
    /// The field has a value for which none of the tests holds (`neq`).
    Neq(Vec<Test>),
}

/// A comparison of a number taken from a value with a rule's number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Cmp {
    Eq,
    Lt,
    Lte,
    Gt,
    Gte,
}

impl Cmp {
    pub(crate) fn holds<T: Ord>(self, left: &T, right: &T) -> bool {
        match self {
            Cmp::Eq => left == right,
            Cmp::Lt => left < right,
            Cmp::Lte => left <= right,
            Cmp::Gt => left > right,
            Cmp::Gte => left >= right,
        }
    }
}

/// A piece of a string pattern.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Piece {
    /// Bytes that must appear as they are (up to ASCII case, when the
    /// pattern is caseless).
    Lit(Vec<u8>),
    /// Any run of bytes, including none (`*`).
    AnyStr,
    /// One character, or one byte where no character starts (`?`).
    AnyChar,
    /// One of the byte strings (the dash variants of `windash`).
    Alt(Vec<Vec<u8>>),
}

/// A pattern of literal bytes and wildcards matched against a whole value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StrPattern {
    pub(crate) pieces: Vec<Piece>,
    pub(crate) cased: bool,
}

/// A regular expression in the PCRE syntax vectorscan accepts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RegexPattern {
    pub(crate) expr: String,
    pub(crate) caseless: bool,
    pub(crate) multiline: bool,
    pub(crate) dotall: bool,
}
