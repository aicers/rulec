//! Parses a Sigma `condition` into an expression over the search
//! identifiers.
//!
//! Precedence, from least to most binding: `or`, `and`, `not`,
//! `1 of`/`all of`, parentheses.

use crate::{expr::Expr, rule::ReadError};

/// The most `not`s and parentheses that may enclose one another. This
/// bounds the parser's recursion; the expression it yields is held to a
/// tighter depth once the whole detection is read.
const MAX_NESTING: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token<'a> {
    Open,
    Close,
    Word(&'a str),
}

fn tokenize(text: &str) -> Vec<Token<'_>> {
    let mut tokens = Vec::new();
    let mut start = None;
    for (i, c) in text.char_indices() {
        if c.is_whitespace() || c == '(' || c == ')' {
            if let Some(s) = start.take()
                && let Some(word) = text.get(s..i)
            {
                tokens.push(Token::Word(word));
            }
            if c == '(' {
                tokens.push(Token::Open);
            } else if c == ')' {
                tokens.push(Token::Close);
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(s) = start
        && let Some(word) = text.get(s..)
    {
        tokens.push(Token::Word(word));
    }
    tokens
}

fn error(text: &str, message: &str) -> ReadError {
    ReadError::Format(format!("condition {text:?}: {message}"))
}

/// Parses `text` against the search identifiers, given with their
/// expressions in document order.
pub(crate) fn parse(text: &str, searches: &[(&str, Expr)]) -> Result<Expr, ReadError> {
    let tokens = tokenize(text);
    let mut parser = Parser {
        text,
        tokens: &tokens,
        pos: 0,
        nesting: 0,
        searches,
    };
    let expr = parser.or()?;
    if parser.pos != tokens.len() {
        return Err(error(text, "unexpected text after the expression"));
    }
    Ok(expr)
}

struct Parser<'t, 's> {
    text: &'t str,
    tokens: &'t [Token<'t>],
    pos: usize,
    nesting: usize,
    searches: &'s [(&'s str, Expr)],
}

impl Parser<'_, '_> {
    fn peek(&self) -> Option<&Token<'_>> {
        self.tokens.get(self.pos)
    }

    fn peek_word(&self, word: &str) -> bool {
        matches!(self.peek(), Some(Token::Word(w)) if *w == word)
    }

    /// Runs `parse` one level of nesting deeper, failing past
    /// [`MAX_NESTING`].
    fn nested(
        &mut self,
        parse: impl FnOnce(&mut Self) -> Result<Expr, ReadError>,
    ) -> Result<Expr, ReadError> {
        if self.nesting >= MAX_NESTING {
            return Err(error(
                self.text,
                &format!("`not` and parentheses nest more than {MAX_NESTING} deep"),
            ));
        }
        self.nesting += 1;
        let expr = parse(self);
        self.nesting -= 1;
        expr
    }

    fn or(&mut self) -> Result<Expr, ReadError> {
        let mut items = vec![self.and()?];
        while self.peek_word("or") {
            self.pos += 1;
            items.push(self.and()?);
        }
        Ok(Expr::or(items))
    }

    fn and(&mut self) -> Result<Expr, ReadError> {
        let mut items = vec![self.not()?];
        while self.peek_word("and") {
            self.pos += 1;
            items.push(self.not()?);
        }
        Ok(Expr::and(items))
    }

    fn not(&mut self) -> Result<Expr, ReadError> {
        if self.peek_word("not") {
            self.pos += 1;
            return Ok(Expr::Not(Box::new(self.nested(Self::not)?)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr, ReadError> {
        let text = self.text;
        match self.tokens.get(self.pos) {
            Some(Token::Open) => {
                self.pos += 1;
                let expr = self.nested(Self::or)?;
                if self.peek() != Some(&Token::Close) {
                    return Err(error(text, "a parenthesis is not closed"));
                }
                self.pos += 1;
                Ok(expr)
            }
            Some(Token::Close) => Err(error(text, "unexpected `)`")),
            Some(Token::Word(word)) => {
                let word = *word;
                self.pos += 1;
                if self.peek_word("of") {
                    self.pos += 1;
                    let all = match word {
                        "1" => false,
                        "all" => true,
                        _ => {
                            return Err(error(
                                text,
                                &format!("`{word} of` is not supported; use `1 of` or `all of`"),
                            ));
                        }
                    };
                    let Some(Token::Word(target)) = self.tokens.get(self.pos) else {
                        return Err(error(text, "`of` needs a pattern or `them`"));
                    };
                    self.pos += 1;
                    let exprs = self.select(target)?;
                    return Ok(if all {
                        Expr::and(exprs)
                    } else {
                        Expr::or(exprs)
                    });
                }
                if matches!(word, "and" | "or" | "not" | "of" | "them") {
                    return Err(error(text, &format!("unexpected `{word}`")));
                }
                self.searches
                    .iter()
                    .find(|(name, _)| *name == word)
                    .map(|(_, expr)| expr.clone())
                    .ok_or_else(|| error(text, &format!("unknown search identifier `{word}`")))
            }
            None => Err(error(text, "the expression ends early")),
        }
    }

    /// Returns the expressions of the search identifiers `target` selects:
    /// `them` selects those not starting with `_`, and a pattern those it
    /// matches, `*` standing for any run of characters.
    fn select(&self, target: &str) -> Result<Vec<Expr>, ReadError> {
        let exprs: Vec<Expr> = self
            .searches
            .iter()
            .filter(|(name, _)| {
                if target == "them" {
                    !name.starts_with('_')
                } else {
                    wildcard_match(target, name)
                }
            })
            .map(|(_, expr)| expr.clone())
            .collect();
        if exprs.is_empty() {
            return Err(error(
                self.text,
                &format!("`{target}` selects no search identifier"),
            ));
        }
        Ok(exprs)
    }
}

/// Returns whether `name` matches `pattern`, in which `*` stands for any
/// run of characters.
fn wildcard_match(pattern: &str, name: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or_default();
    let Some(mut rest) = name.strip_prefix(first) else {
        return false;
    };
    let parts: Vec<&str> = parts.collect();
    let Some((last, middle)) = parts.split_last() else {
        return rest.is_empty();
    };
    for part in middle {
        match rest.find(part) {
            Some(i) => rest = rest.get(i + part.len()..).unwrap_or_default(),
            None => return false,
        }
    }
    rest.ends_with(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expr::{Leaf, Test};

    fn leaf(name: &str) -> Expr {
        Expr::Leaf(Leaf {
            field: name.to_string(),
            test: Test::Any,
        })
    }

    #[test]
    fn wildcards() {
        assert!(wildcard_match("sel*", "selection"));
        assert!(wildcard_match("sel*", "sel"));
        assert!(wildcard_match("*tion", "selection"));
        assert!(wildcard_match("s*e*n", "selection"));
        assert!(!wildcard_match("s*x*n", "selection"));
        assert!(wildcard_match("selection", "selection"));
        assert!(!wildcard_match("selection", "selection2"));
        assert!(wildcard_match("*", "anything"));
    }

    #[test]
    fn precedence() {
        let searches = vec![("a", leaf("a")), ("b", leaf("b")), ("c", leaf("c"))];
        assert_eq!(
            parse("a or b and not c", &searches).unwrap(),
            Expr::Or(vec![
                leaf("a"),
                Expr::And(vec![leaf("b"), Expr::Not(Box::new(leaf("c")))])
            ])
        );
        assert_eq!(
            parse("(a or b) and c", &searches).unwrap(),
            Expr::And(vec![Expr::Or(vec![leaf("a"), leaf("b")]), leaf("c")])
        );
        for bad in ["a and", "(a", "a)", "x", "2 of them", "1 of z*", "a b", ""] {
            assert!(parse(bad, &searches).is_err(), "{bad}");
        }
    }

    #[test]
    fn nesting_is_bounded() {
        let searches = vec![("a", leaf("a"))];
        let nots = |n: usize| format!("{}a", "not ".repeat(n));
        let parens = |n: usize| format!("{}a{}", "(".repeat(n), ")".repeat(n));
        assert!(parse(&nots(MAX_NESTING), &searches).is_ok());
        assert!(parse(&parens(MAX_NESTING), &searches).is_ok());
        assert!(parse(&nots(MAX_NESTING + 1), &searches).is_err());
        assert!(parse(&parens(MAX_NESTING + 1), &searches).is_err());
        assert!(parse(&parens(100_000), &searches).is_err());
    }

    #[test]
    fn them_skips_underscore() {
        let searches = vec![("a", leaf("a")), ("_b", leaf("b"))];
        assert_eq!(parse("1 of them", &searches).unwrap(), leaf("a"));
        assert_eq!(
            parse("all of *", &searches).unwrap(),
            Expr::And(vec![leaf("a"), leaf("b")])
        );
    }
}
