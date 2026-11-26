//! Matches a string pattern against a value in Rust, for the patterns with
//! a `?`, whose meaning vectorscan cannot express exactly.
//!
//! What `?` consumes at a position depends on the bytes after it, which a
//! vectorscan expression cannot look at without consuming them, so the
//! expression vectorscan scans accepts more than `?` means and every value
//! it matches is checked here.

use crate::expr::{Piece, StrPattern};

impl StrPattern {
    /// Returns whether the pattern has a `?`, so a vectorscan match of it
    /// has to be confirmed with [`StrPattern::matches`].
    pub(crate) fn has_any_char(&self) -> bool {
        self.pieces.contains(&Piece::AnyChar)
    }

    /// Returns whether the pattern matches the whole of `value`.
    ///
    /// A leading or trailing `*` leaves that end of the value open, as the
    /// vectorscan expression does. Literals and `windash` alternatives
    /// ignore ASCII case unless the pattern is cased. It takes time
    /// proportional to the length of the value times the number of pieces
    /// and alternatives, plus the length of the pattern: it tracks the set
    /// of positions each piece can end at instead of backtracking, and
    /// finds every match of a literal in one pass over the value.
    pub(crate) fn matches(&self, value: &[u8]) -> bool {
        // `reach[p]`: the pieces so far can match `value[..p]`.
        let mut reach = vec![false; value.len() + 1];
        let mut next = vec![false; value.len() + 1];
        if let Some(start) = reach.first_mut() {
            *start = true;
        }
        for piece in &self.pieces {
            next.fill(false);
            match piece {
                Piece::Lit(bytes) => self.step_lit(value, &reach, &mut next, bytes),
                Piece::Alt(choices) => {
                    for choice in choices {
                        self.step_lit(value, &reach, &mut next, choice);
                    }
                }
                Piece::AnyStr => {
                    let mut seen = false;
                    for (r, n) in reach.iter().zip(next.iter_mut()) {
                        seen |= *r;
                        *n = seen;
                    }
                }
                Piece::AnyChar => {
                    for (p, _) in reach.iter().enumerate().filter(|(_, r)| **r) {
                        let Some(rest) = value.get(p..).filter(|rest| !rest.is_empty()) else {
                            continue;
                        };
                        if let Some(n) = next.get_mut(p + char_len(rest)) {
                            *n = true;
                        }
                    }
                }
            }
            std::mem::swap(&mut reach, &mut next);
            if !reach.contains(&true) {
                return false;
            }
        }
        reach.last().copied().unwrap_or_default()
    }

    /// Marks in `next` the end of every match of `lit` that starts at a
    /// position marked in `reach`.
    ///
    /// It finds the matches, overlapping ones included, with the
    /// Knuth-Morris-Pratt search, so a long literal is not compared again
    /// from every position it could start at.
    fn step_lit(&self, value: &[u8], reach: &[bool], next: &mut [bool], lit: &[u8]) {
        let fold = |byte: u8| {
            if self.cased {
                byte
            } else {
                byte.to_ascii_lowercase()
            }
        };
        let lit: Vec<u8> = lit.iter().map(|&byte| fold(byte)).collect();
        if lit.is_empty() {
            for (r, n) in reach.iter().zip(next.iter_mut()) {
                *n |= *r;
            }
            return;
        }
        let border = borders(&lit);
        // `matched`: the length of the longest prefix of `lit` that ends
        // at the current position of `value`.
        let mut matched = 0;
        for (end, &byte) in (1..).zip(value) {
            let byte = fold(byte);
            while matched > 0 && lit.get(matched) != Some(&byte) {
                matched = border.get(matched - 1).copied().unwrap_or_default();
            }
            if lit.get(matched) == Some(&byte) {
                matched += 1;
            }
            if matched == lit.len()
                && reach.get(end - matched).copied().unwrap_or_default()
                && let Some(n) = next.get_mut(end)
            {
                *n = true;
            }
        }
    }
}

/// Returns, for each prefix `lit[..=i]`, the length of its longest proper
/// prefix that is also its suffix: the failure function of the
/// Knuth-Morris-Pratt search.
fn borders(lit: &[u8]) -> Vec<usize> {
    let mut border = Vec::with_capacity(lit.len());
    border.push(0);
    let mut k = 0;
    for &byte in lit.iter().skip(1) {
        while k > 0 && lit.get(k) != Some(&byte) {
            k = border.get(k - 1).copied().unwrap_or_default();
        }
        if lit.get(k) == Some(&byte) {
            k += 1;
        }
        border.push(k);
    }
    border
}

/// Returns how many bytes a `?` consumes at the start of `rest`, which is
/// not empty: the whole well-formed UTF-8 character that starts there (by
/// RFC 3629, as `std::str::from_utf8` reads it: no overlong encoding, no
/// surrogate, nothing above U+10FFFF), or one byte where none starts. A
/// lead byte whose character is cut short or followed by a byte out of
/// range is one byte on its own; the continuation bytes after it are each
/// one byte too.
fn char_len(rest: &[u8]) -> usize {
    let head = rest.get(..4).unwrap_or(rest);
    head.utf8_chunks()
        .next()
        .and_then(|chunk| chunk.valid().chars().next())
        .map_or(1, char::len_utf8)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(pieces: Vec<Piece>, cased: bool) -> StrPattern {
        StrPattern { pieces, cased }
    }

    fn lit(bytes: &[u8]) -> Piece {
        Piece::Lit(bytes.to_vec())
    }

    #[test]
    fn char_len_takes_well_formed_characters_whole() {
        for bytes in [
            &b"A"[..],
            &[0x00],
            &[0x7f],
            &[0xc2, 0x80],
            &[0xdf, 0xbf],
            &[0xe0, 0xa0, 0x80],
            &[0xe3, 0x81, 0x82],
            &[0xed, 0x9f, 0xbf],
            &[0xee, 0x80, 0x80],
            &[0xef, 0xbf, 0xbf],
            &[0xf0, 0x90, 0x80, 0x80],
            &[0xf1, 0x80, 0x80, 0x80],
            &[0xf4, 0x8f, 0xbf, 0xbf],
        ] {
            assert_eq!(char_len(bytes), bytes.len(), "{bytes:02x?}");
            let mut longer = bytes.to_vec();
            longer.extend_from_slice(&[0x80, 0x41]);
            assert_eq!(char_len(&longer), bytes.len(), "{longer:02x?}");
        }
    }

    #[test]
    fn char_len_takes_one_byte_where_no_character_starts() {
        for bytes in [
            // Continuation bytes.
            &[0x80][..],
            &[0xbf, 0x80],
            // Bytes that start no well-formed encoding.
            &[0xc0, 0x80],
            &[0xc1, 0xbf],
            &[0xf5, 0x80, 0x80, 0x80],
            &[0xf8],
            &[0xff],
            // Lead bytes followed by a byte out of range.
            &[0xe3, 0x41],
            &[0xc2, 0xc0],
            &[0xe0, 0x80, 0x80],
            &[0xed, 0xa0, 0x80],
            &[0xf0, 0x80, 0x80, 0x80],
            &[0xf4, 0x90, 0x80, 0x80],
            // Cut-short encodings.
            &[0xe3],
            &[0xe3, 0x81],
            &[0xe3, 0x81, 0x41],
            &[0xf0, 0x9f, 0x98],
            &[0xf0, 0x9f, 0x98, 0x41],
        ] {
            assert_eq!(char_len(bytes), 1, "{bytes:02x?}");
        }
    }

    #[test]
    fn any_char_consumes_by_the_bytes_where_it_starts() {
        let any = pattern(vec![Piece::AnyChar], true);
        assert!(any.matches(&[0xe3, 0x81, 0x82]));
        assert!(any.matches(&[0xe3]));
        assert!(!any.matches(&[0xe3, 0x81]));
        assert!(!any.matches(&[0xe3, 0x41]));
        assert!(!any.matches(&[0xc0, 0x80]));
        assert!(!any.matches(b""));
        let two = pattern(vec![Piece::AnyChar, Piece::AnyChar], true);
        assert!(two.matches(&[0xe3, 0x81]));
        assert!(two.matches(&[0xe3, 0x41]));
        assert!(!two.matches(&[0xe3, 0x81, 0x82]));
        let three = pattern(vec![Piece::AnyChar; 3], true);
        assert!(!three.matches(&[0xe3, 0x81, 0x82]));
        assert!(three.matches(&[0xed, 0xa0, 0x80]));
        // `*` may stop anywhere, and the `?` after it starts from there.
        let tail = pattern(vec![Piece::AnyStr, Piece::AnyChar, Piece::AnyChar], true);
        assert!(tail.matches(&[0xe3, 0x81, 0x82]));
    }

    #[test]
    fn literals_and_alternatives_follow_cased() {
        let caseless = pattern(vec![Piece::AnyChar, lit(b"a")], false);
        assert!(caseless.matches(&[0xe3, b'A']));
        let cased = pattern(vec![Piece::AnyChar, lit(b"a")], true);
        assert!(!cased.matches(&[0xe3, b'A']));
        assert!(cased.matches(&[0xe3, b'a']));
        let alt = pattern(
            vec![
                Piece::Alt(vec![b"-x".to_vec(), b"/x".to_vec()]),
                Piece::AnyChar,
            ],
            false,
        );
        assert!(alt.matches(b"-Xy"));
        assert!(alt.matches(b"/x\xc3\xa9"));
        assert!(!alt.matches(b"+xy"));
        assert!(!alt.matches(b"-x"));
    }

    #[test]
    fn open_ends() {
        let contains = pattern(
            vec![Piece::AnyStr, Piece::AnyChar, lit(b"A"), Piece::AnyStr],
            false,
        );
        assert!(contains.matches(&[b'B', 0xe3, b'A', b'B']));
        assert!(!contains.matches(&[0xe3, 0x81, 0x82, b'B']));
        let starts = pattern(vec![Piece::AnyChar, lit(b"A"), Piece::AnyStr], false);
        assert!(starts.matches(&[0xe3, b'A', b'B']));
        assert!(!starts.matches(&[b'B', 0xe3, b'A']));
    }

    #[test]
    fn literals_match_where_they_overlap() {
        // The second match of `aa` in `aaa` overlaps the first.
        let p = pattern(vec![Piece::AnyStr, lit(b"aa"), Piece::AnyChar], true);
        assert!(p.matches(b"aaab"));
        assert!(!p.matches(b"baa"));
        let p = pattern(vec![Piece::AnyStr, lit(b"abab"), Piece::AnyChar], true);
        assert!(p.matches(b"ababab\xe3"));
        assert!(!p.matches(b"abaab\xe3"));
        let caseless = pattern(vec![Piece::AnyStr, lit(b"aB"), Piece::AnyChar], false);
        assert!(caseless.matches(b"AAbx"));
        // A match only counts where the pieces before it can end.
        let p = pattern(vec![Piece::AnyChar, lit(b"aa"), Piece::AnyStr], true);
        assert!(p.matches(b"\xe3aa"));
        assert!(!p.matches(b"\xe3baa"));
    }

    #[test]
    fn borders_are_the_failure_function() {
        assert_eq!(borders(b"a"), vec![0]);
        assert_eq!(borders(b"aaaa"), vec![0, 1, 2, 3]);
        assert_eq!(borders(b"abab"), vec![0, 0, 1, 2]);
        assert_eq!(borders(b"aabaaab"), vec![0, 1, 0, 1, 2, 2, 3]);
    }

    #[test]
    fn a_long_literal_with_a_repeated_prefix_finishes_quickly() {
        // `contains: '?aa…ab'` on `aa…ab`: every position the `*` and the
        // `?` can reach starts a long prefix of the literal, which a search
        // from each position would compare again in full.
        const LEN: usize = 50_000;
        let mut literal = vec![b'a'; LEN];
        literal.push(b'b');
        let p = pattern(
            vec![Piece::AnyStr, Piece::AnyChar, lit(&literal), Piece::AnyStr],
            false,
        );
        let mut value = vec![b'a'; 2 * LEN];
        let start = std::time::Instant::now();
        assert!(!p.matches(&value));
        value.push(b'b');
        assert!(p.matches(&value));
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn many_stars_on_a_long_value_finish_quickly() {
        let mut pieces = Vec::new();
        for _ in 0..100 {
            pieces.push(Piece::AnyStr);
            pieces.push(Piece::AnyChar);
            pieces.push(lit(b"a"));
        }
        pieces.push(lit(b"b"));
        let p = pattern(pieces, true);
        let value = vec![b'a'; 20_000];
        let start = std::time::Instant::now();
        assert!(!p.matches(&value));
        let mut value = value;
        value.push(b'b');
        assert!(p.matches(&value));
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "took {:?}",
            start.elapsed()
        );
    }
}
