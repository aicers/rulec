//! The wildcard `?` on byte values that are not well-formed UTF-8: it takes
//! a well-formed character whole, and one byte where none starts.

mod common;

use std::collections::HashSet;

use common::{TestEvent, compile_texts, matched_ids, rule_text, selection_matches};

/// Returns whether the condition `uri|<mods>: '<pattern>'` holds for a
/// `uri` with the one value `value`. `mods` is empty for an exact pattern.
fn holds(mods: &str, pattern: &str, value: &[u8]) -> bool {
    let key = if mods.is_empty() {
        "uri".to_string()
    } else {
        format!("uri|{mods}")
    };
    selection_matches(
        &format!("        {key}: '{pattern}'\n"),
        &TestEvent::http().bytes("uri", value),
    )
}

fn exact(pattern: &str, value: &[u8]) -> bool {
    holds("", pattern, value)
}

#[test]
fn well_formed_characters_are_one_char() {
    for value in [
        &[0xc2, 0x80][..],
        &[0xc3, 0xa9],
        &[0xe0, 0xa0, 0x80],
        &[0xed, 0x9f, 0xbf],
        &[0xe3, 0x81, 0x82],
        &[0xef, 0xbf, 0xbf],
        &[0xf0, 0x90, 0x80, 0x80],
        &[0xf0, 0x9f, 0x98, 0x80],
        &[0xf4, 0x8f, 0xbf, 0xbf],
    ] {
        assert!(exact("?", value), "`?` on {value:02x?}");
        assert!(!exact("??", value), "`??` on {value:02x?}");
    }
    assert!(!exact("???", &[0xe3, 0x81, 0x82]));
}

#[test]
fn lead_byte_followed_by_a_byte_out_of_range() {
    let value = [0xe3, 0x41];
    assert!(exact("?A", &value));
    assert!(exact("??", &value));
    assert!(!exact("?", &value));
    assert!(exact("?a", &value));
    assert!(!holds("cased", "?a", &value));
}

#[test]
fn cut_short_encodings() {
    assert!(exact("?", &[0xe3]));
    assert!(exact("A?", &[0x41, 0xe3]));
    assert!(holds("endswith", "?", &[0x41, 0xe3]));
    assert!(exact("??", &[0xe3, 0x81]));
    assert!(!exact("?", &[0xe3, 0x81]));
    assert!(exact("???", &[0xe3, 0x81, 0x41]));
    assert!(exact("??A", &[0xe3, 0x81, 0x41]));
    assert!(!exact("?", &[0xe3, 0x81, 0x41]));
    assert!(exact("A??", &[0x41, 0xe3, 0x81]));
    assert!(!exact("A?", &[0x41, 0xe3, 0x81]));
}

#[test]
fn bytes_that_start_no_character() {
    for byte in [0x80, 0xbf, 0xc0, 0xc1, 0xf5, 0xf8, 0xff] {
        assert!(exact("?", &[byte]), "{byte:02x}");
    }
}

#[test]
fn ill_formed_encodings_go_byte_by_byte() {
    assert!(exact("??", &[0xc0, 0x80]));
    assert!(!exact("?", &[0xc0, 0x80]));
    for value in [[0xe0, 0x80, 0x80], [0xed, 0xa0, 0x80]] {
        assert!(exact("???", &value), "{value:02x?}");
        assert!(!exact("?", &value), "{value:02x?}");
    }
    assert!(exact("????", &[0xf4, 0x90, 0x80, 0x80]));
    assert!(!exact("?", &[0xf4, 0x90, 0x80, 0x80]));
}

#[test]
fn any_char_after_a_star_starts_where_the_star_stops() {
    let value = [0xe3, 0x81, 0x82];
    assert!(holds("endswith", "??", &value));
    assert!(exact("*??", &value));
    assert!(holds("endswith", "?", &value));
}

#[test]
fn modifiers() {
    assert!(holds("startswith", "?A", &[0xe3, 0x41, 0x42]));
    assert!(holds("contains", "?A", &[0x42, 0xe3, 0x41, 0x42]));
    assert!(holds("neq", "?", &[0xc0, 0x80]));
    assert!(!holds("neq", "?", &[0xe3, 0x81, 0x82]));
}

#[test]
fn any_char_beside_literals_and_wildcards() {
    assert!(exact("a?b", &[b'A', 0xe3, 0x81, 0x82, b'B']));
    assert!(!holds("cased", "a?b", &[b'A', 0xe3, 0x81, 0x82, b'B']));
    assert!(holds("cased", "a?b", &[b'a', 0xe3, 0x81, 0x82, b'b']));
    assert!(!exact("a?b", &[b'a', 0xe3, 0x81, b'b']));
    assert!(exact("a??b", &[b'a', 0xe3, 0x81, b'b']));
    assert!(exact("a*?b", &[b'a', 0xe3, 0x81, b'b']));
    // The first `?` takes the whole character, and nothing is left for
    // the last one.
    assert!(!exact("?*?", &[0xe3, 0x81, 0x82]));
    assert!(exact("?*?", &[0xe3, 0x81, 0x82, b'A']));
    assert!(!exact("?*?", &[0xe3]));
    assert!(exact("?*?", &[0xe3, 0x81]));
}

#[test]
fn escaped_question_mark_is_one_byte() {
    let escaped = r"a\?";
    assert!(exact(escaped, b"a?"));
    assert!(exact(escaped, b"A?"));
    assert!(!exact(escaped, b"aX"));
    assert!(!exact(escaped, &[b'a', 0xe3]));
    assert!(!exact(escaped, &[b'a', 0xc3, 0xa9]));
}

#[test]
fn windash_with_any_char() {
    // `?` takes the lead byte alone where a dash follows it.
    assert!(holds("windash", "?-x", &[0xe3, b'/', b'x']));
    assert!(holds("windash", "?-x", &[0xe3, 0xe2, 0x80, 0x93, b'x']));
    // After an en dash, `?` takes a whole character but not a cut one.
    assert!(holds(
        "windash",
        "-?",
        &[0xe2, 0x80, 0x93, 0xe3, 0x81, 0x82]
    ));
    assert!(!holds("windash", "-?", &[b'-', 0xe2, 0x80]));
    assert!(holds("windash", "-??", &[b'-', 0xe2, 0x80]));
    assert!(holds(
        "windash|contains",
        "-?a",
        &[b'x', b'/', 0xff, b'A', b'y']
    ));
}

#[test]
fn empty_value_matches_no_any_char() {
    assert!(!exact("?", b""));
    assert!(!holds("contains", "?", b""));
    assert!(holds("neq", "?", b""));
}

/// Returns how many bytes `?` takes at the start of `value`, which is not
/// empty: the shortest prefix of at most four bytes that is UTF-8, or one
/// byte.
fn reference_char_len(value: &[u8]) -> usize {
    (1..=4)
        .find(|&n| {
            value
                .get(..n)
                .is_some_and(|head| std::str::from_utf8(head).is_ok())
        })
        .unwrap_or(1)
}

/// Matches a Sigma pattern of `*`, `?` and ASCII literals against the whole
/// of `value` by backtracking.
fn reference_match(pattern: &[u8], cased: bool, value: &[u8]) -> bool {
    match pattern.split_first() {
        None => value.is_empty(),
        Some((b'*', rest)) => (0..=value.len()).any(|i| reference_match(rest, cased, &value[i..])),
        Some((b'?', rest)) => {
            !value.is_empty() && reference_match(rest, cased, &value[reference_char_len(value)..])
        }
        Some((c, rest)) => {
            value.first().is_some_and(|d| {
                if cased {
                    c == d
                } else {
                    c.eq_ignore_ascii_case(d)
                }
            }) && reference_match(rest, cased, &value[1..])
        }
    }
}

struct Case {
    id: String,
    /// The pattern the condition means, with the open ends of `contains`,
    /// `startswith` and `endswith` written as `*`.
    pattern: String,
    cased: bool,
    neq: bool,
}

#[test]
fn every_short_value_agrees_with_a_reference() {
    const BYTES: [u8; 21] = [
        0x41, 0x61, 0x80, 0x81, 0x8f, 0x90, 0x9f, 0xa0, 0xbf, 0xc0, 0xc1, 0xc2, 0xdf, 0xe0, 0xe3,
        0xed, 0xef, 0xf0, 0xf4, 0xf5, 0xff,
    ];
    const PATTERNS: [&str; 9] = ["?", "??", "???", "?A", "A?", "?*", "*?", "*??", "?*?"];
    const POSITIONS: [&str; 4] = ["", "contains", "startswith", "endswith"];

    let mut cases = Vec::new();
    let mut texts = Vec::new();
    for pattern in PATTERNS {
        let casings: &[bool] = if pattern.contains('A') {
            &[false, true]
        } else {
            &[false]
        };
        for &cased in casings {
            for position in POSITIONS {
                for neq in [false, true] {
                    let mut mods: Vec<&str> = Vec::new();
                    if !position.is_empty() {
                        mods.push(position);
                    }
                    if neq {
                        mods.push("neq");
                    }
                    if cased {
                        mods.push("cased");
                    }
                    let key = std::iter::once("uri")
                        .chain(mods.iter().copied())
                        .collect::<Vec<_>>()
                        .join("|");
                    let id = format!("r{}", cases.len());
                    texts.push(rule_text(
                        &id,
                        &format!(
                            "    selection:\n        {key}: '{pattern}'\n    condition: selection\n"
                        ),
                    ));
                    let open_start = matches!(position, "contains" | "endswith");
                    let open_end = matches!(position, "contains" | "startswith");
                    cases.push(Case {
                        id,
                        pattern: format!(
                            "{}{pattern}{}",
                            if open_start { "*" } else { "" },
                            if open_end { "*" } else { "" }
                        ),
                        cased,
                        neq,
                    });
                }
            }
        }
    }
    let compiled = compile_texts(&texts);
    assert!(
        compiled.stats().excluded().is_empty(),
        "rules were left out: {:?}",
        compiled.stats().excluded()
    );
    assert_eq!(compiled.rules().count(), cases.len());

    let mut values: Vec<Vec<u8>> = vec![Vec::new()];
    let mut last = values.clone();
    for _ in 0..3 {
        last = last
            .iter()
            .flat_map(|v| {
                BYTES.iter().map(move |b| {
                    let mut next = v.clone();
                    next.push(*b);
                    next
                })
            })
            .collect();
        values.extend(last.iter().cloned());
    }
    assert_eq!(values.len(), 1 + 21 + 21 * 21 + 21 * 21 * 21);

    let mut checked = 0_usize;
    for value in &values {
        let event = TestEvent::http().bytes("uri", value);
        let matched: HashSet<String> = matched_ids(&compiled, &event, &[]).into_iter().collect();
        for case in &cases {
            let want = reference_match(case.pattern.as_bytes(), case.cased, value) != case.neq;
            assert_eq!(
                matched.contains(&case.id),
                want,
                "pattern {:?} (cased: {}, neq: {}) on {value:02x?}",
                case.pattern,
                case.cased,
                case.neq
            );
            checked += 1;
        }
    }
    assert_eq!(checked, values.len() * cases.len());
}
