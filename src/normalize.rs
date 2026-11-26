//! URI and host normalization, as Suricata 7.0.3 does it with its bundled
//! libhtp (0.5.46) in the default configuration.
//!
//! Suricata's default `libhtp` configuration (`suricata.yaml`) sets
//! `personality: IDS`, `double-decode-path: no` and `double-decode-query:
//! no`, and sets nothing else that touches URIs. What that amounts to was
//! read from these sources:
//!
//! - libhtp `htp/htp_config.c`, `htp_config_create`: the defaults for
//!   every decoder — an invalid `%` escape keeps its `%`
//!   (`HTP_URL_DECODE_PRESERVE_PERCENT`), neither a raw nor an encoded NUL
//!   ends the path, `%u` is not decoded, `+` becomes a space in
//!   URL-encoded data, and the best-fit map is code page 1252 with `?` as
//!   the replacement byte.
//! - libhtp `htp/htp_config.c`, `htp_config_set_server_personality`, case
//!   `HTP_SERVER_IDS`: for the path, backslashes become slashes, encoded
//!   separators (`%2f`, `%5c`) are decoded, runs of separators are
//!   compressed, `%uHHHH` is decoded, UTF-8 is turned into single bytes
//!   with the best-fit map, and the path is lowercased.
//! - Suricata `src/app-layer-htp.c`, `HTPConfigSetDefaultsPhase1` and
//!   `HTPConfigParseParameters`: it turns the lowercasing back off for the
//!   IDS personality ("Signatures do not expect this") and turns off `+`
//!   to space for URL-encoded data.
//! - Suricata `src/app-layer-htp-libhtp.c`, `SCHTPGenerateNormalizedUri`,
//!   with `uri-include-all: no`: the normalized URI is the normalized path,
//!   then `?` and the query URL-decoded once, then `#` and the fragment.
//!   Scheme, credentials, host and port are left out.
//! - libhtp `htp/htp_util.c`: `htp_parse_uri` (how the URI is split),
//!   `htp_normalize_parsed_uri` (which part gets which decoding),
//!   `htp_decode_path_inplace` (path escapes), `htp_utf8_decode_path_inplace`
//!   with `htp_utf8_decode_allow_overlong` in `htp/htp_utf8_decoder.c`
//!   (UTF-8), `htp_normalize_uri_path_inplace` (dot segments),
//!   `htp_urldecode_inplace_ex` (query and fragment) and
//!   `htp_parse_hostport` (the `Host` header).
//!
//! The functions below are written from that reading; no libhtp code is
//! carried over.

use crate::bestfit;

/// Normalizes a request URI the way Suricata 7.0.3 builds its `http.uri`
/// buffer with the default configuration.
///
/// It takes any bytes — a full request URI, or a piece of a rule's
/// pattern that need not start with `/`, be UTF-8 or hold whole `%`
/// escapes — and never fails. The steps, each as libhtp 0.5.46 takes them
/// for Suricata's IDS personality:
///
/// 1. **Splitting** (`htp_parse_uri`). Trailing spaces are dropped. A URI
///    that does not start with `/` and has a `:` has a scheme up to the
///    first `:`, wherever that colon is — `a.php?x=1:2` has the scheme
///    `a.php?x=1` and the path `2`. After a scheme, `//` followed by a
///    byte other than `/` starts an authority (credentials, host, port)
///    that runs to the next `/`, `?` or `#`. A URI without a colon is all
///    path. The path runs to the first `?` or `#`, the query from `?` to
///    the first `#`, and the fragment from `#` to the end. Scheme and
///    authority are dropped from the result, so an absolute URI
///    `http://host/a` normalizes to `/a`.
/// 2. **Path escapes** (`htp_decode_path_inplace`). `%HH` with two hex
///    digits (either case) is decoded, `%2f` and `%5c` included, and so is
///    a NUL. `%uHHHH` (`u` either case) is decoded to one byte: a code
///    point below U+0100 is that byte, anything else its best fit in code
///    page 1252 or `?`. A `%` that does not start a whole escape — not
///    followed by two hex digits, `%u` not followed by four, or fewer than
///    two bytes left — is kept as `%` and the bytes after it are read
///    normally. Every `\`, raw or decoded, becomes `/`, and a `/` right
///    after a `/` written to the output is dropped. Case is kept and `+`
///    stays `+`.
/// 3. **UTF-8** (`htp_utf8_decode_path_inplace`). The decoded path is read
///    as UTF-8 with overlong forms allowed: each complete character becomes
///    one byte — itself below U+0100 (so the overlong `%c0%af` becomes
///    `/`), its best fit or `?` above. A byte that cannot start a
///    character becomes `?`; a character broken off by a byte that cannot
///    continue it becomes one `?`, and that byte is read again as the start
///    of the next one. An incomplete character at the very end is dropped.
///    Surrogates (`\xed\xa0\x80` and up) and code points past U+10FFFF are
///    not characters.
/// 4. **Dot segments** (`htp_normalize_uri_path_inplace`), RFC 3986 section
///    5.2.4 with libhtp's quirks: a leading `./` or `../` is dropped, `/./`
///    becomes `/`, `/../` becomes `/` and removes the segment before it
///    (never going above the root), and a lone `.` or `..` is dropped. A
///    path ending in `/.` or `/..` loses the final `/` as well, so `/a/b/.`
///    is `/a/b` and `/a/b/..` is `/a`. Separators were compressed before
///    the UTF-8 step, so a `/` that step produces is not compressed:
///    `/a/%c0%af/b` is `/a///b`.
/// 5. **Query** (Suricata's `SCHTPGenerateNormalizedUri`, which decodes it
///    with libhtp's URL-encoded settings): `%HH` is decoded once, an
///    invalid `%` is kept, `%u` is not decoded, `+` stays `+`, and nothing
///    else changes — no separator handling, no UTF-8 step.
/// 6. **Fragment**: decoded like the query, except that `%uHHHH` is
///    decoded as in the path (libhtp decodes it with the path's settings).
#[must_use]
pub fn normalize_uri(uri: &[u8]) -> Vec<u8> {
    let parts = UriParts::split(uri);
    let mut out = normalize_path(parts.path);
    if let Some(query) = parts.query {
        out.push(b'?');
        url_decode(query, false, &mut out);
    }
    if let Some(fragment) = parts.fragment {
        out.push(b'#');
        url_decode(fragment, true, &mut out);
    }
    out
}

/// Normalizes the value of a `Host` header: drops the port and lowercases
/// ASCII letters.
///
/// It takes any bytes and never fails. Following libhtp 0.5.46
/// (`htp_parse_hostport`, which reads the `Host` header), leading and
/// trailing whitespace (space, tab, LF, VT, FF, CR) is dropped first.
/// Then:
///
/// - A value starting with `[` is an IPv6 literal: the host is everything
///   up to and including the first `]`, brackets kept, and what follows it
///   — a `:port` or anything else — is dropped (`[2001:DB8::1]:8080` →
///   `[2001:db8::1]`). Without a `]`, libhtp's `Host` header parser finds
///   no host at all; this takes the whole value instead, as libhtp's URI
///   parser (`htp_parse_uri`) does for an authority with no closing `]`.
/// - Otherwise the host runs to the first `:`, with whitespace before the
///   colon dropped (`Example.COM:8080` → `example.com`).
///
/// Trailing dots are kept: libhtp removes them only from a host named in
/// the request URI (`htp_normalize_hostname_inplace`), not from the `Host`
/// header. The result may be empty (`:80`).
#[must_use]
pub fn normalize_host(host: &[u8]) -> Vec<u8> {
    let host = trim_c_space(host);
    let host = if host.first() == Some(&b'[') {
        match host.iter().position(|&b| b == b']') {
            Some(end) => host.get(..=end).unwrap_or(host),
            None => host,
        }
    } else {
        match host.iter().position(|&b| b == b':') {
            Some(colon) => trim_c_space(host.get(..colon).unwrap_or_default()),
            None => host,
        }
    };
    host.to_ascii_lowercase()
}

/// Returns whether `b` is whitespace to C's `isspace` in the C locale.
fn is_c_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// Drops the C whitespace at both ends of `bytes`.
fn trim_c_space(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| !is_c_space(b));
    let end = bytes.iter().rposition(|&b| !is_c_space(b));
    match (start, end) {
        (Some(start), Some(end)) => bytes.get(start..=end).unwrap_or_default(),
        _ => &[],
    }
}

/// The parts of a request URI that make up the normalized URI.
struct UriParts<'a> {
    path: &'a [u8],
    query: Option<&'a [u8]>,
    fragment: Option<&'a [u8]>,
}

impl<'a> UriParts<'a> {
    /// Splits `uri` as libhtp's `htp_parse_uri` does, leaving out the
    /// scheme and the authority.
    fn split(uri: &'a [u8]) -> Self {
        let end = uri.iter().rposition(|&b| b != b' ').map_or(0, |i| i + 1);
        let uri = uri.get(..end).unwrap_or_default();

        let mut rest = uri;
        if uri.first().is_some_and(|&b| b != b'/')
            && let Some(colon) = uri.iter().position(|&b| b == b':')
        {
            let after_scheme = uri.get(colon + 1..).unwrap_or_default();
            rest = match after_scheme {
                [b'/', b'/', third, ..] if *third != b'/' => {
                    let authority = after_scheme.get(2..).unwrap_or_default();
                    let len = authority
                        .iter()
                        .position(|&b| matches!(b, b'/' | b'?' | b'#'))
                        .unwrap_or(authority.len());
                    authority.get(len..).unwrap_or_default()
                }
                _ => after_scheme,
            };
        }

        let path_len = rest
            .iter()
            .position(|&b| b == b'?' || b == b'#')
            .unwrap_or(rest.len());
        let (path, rest) = rest.split_at(path_len);
        let (query, rest) = match rest.split_first() {
            Some((b'?', after)) => {
                let len = after.iter().position(|&b| b == b'#').unwrap_or(after.len());
                let (query, rest) = after.split_at(len);
                (Some(query), rest)
            }
            _ => (None, rest),
        };
        let fragment = match rest.split_first() {
            Some((b'#', after)) => Some(after),
            _ => None,
        };
        Self {
            path,
            query,
            fragment,
        }
    }
}

/// Returns the value of an ASCII hex digit.
fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Reads the byte of a `%` escape at the start of `input`, which starts
/// with `%`. Returns the byte and how many input bytes it took; a `%` that
/// does not start a whole escape is itself, taking one byte.
///
/// `u_escapes` decodes `%uHHHH` to its best-fit byte. As in libhtp, the
/// escape is looked at only when at least two bytes follow the `%`, and a
/// `%u` that does not hold four hex digits is not read as `%HH` either.
fn decode_escape(input: &[u8], u_escapes: bool) -> (u8, usize) {
    const NOT_AN_ESCAPE: (u8, usize) = (b'%', 1);
    let (Some(&first), Some(&second)) = (input.get(1), input.get(2)) else {
        return NOT_AN_ESCAPE;
    };
    if u_escapes && (first == b'u' || first == b'U') {
        let digits = input.get(2..6).and_then(|digits| {
            digits.iter().try_fold(0_u32, |value, &d| {
                hex_value(d).map(|d| (value << 4) | u32::from(d))
            })
        });
        return match digits {
            Some(codepoint) => (bestfit::byte_for(codepoint), 6),
            None => NOT_AN_ESCAPE,
        };
    }
    match (hex_value(first), hex_value(second)) {
        (Some(high), Some(low)) => ((high << 4) | low, 3),
        _ => NOT_AN_ESCAPE,
    }
}

/// URL-decodes `input` into `out`: `%HH`, and `%uHHHH` if `u_escapes` is
/// set; any other byte, `+` included, is copied.
fn url_decode(input: &[u8], u_escapes: bool, out: &mut Vec<u8>) {
    let mut pos = 0;
    while let Some(&b) = input.get(pos) {
        if b == b'%' {
            let (byte, used) = decode_escape(input.get(pos..).unwrap_or_default(), u_escapes);
            out.push(byte);
            pos += used;
        } else {
            out.push(b);
            pos += 1;
        }
    }
}

/// Normalizes a URI path: escapes, separators, UTF-8 and dot segments.
fn normalize_path(path: &[u8]) -> Vec<u8> {
    let decoded = decode_path(path);
    let single_bytes = utf8_to_bestfit(&decoded);
    remove_dot_segments(&single_bytes)
}

/// Decodes the escapes of a path, turns backslashes into slashes and
/// compresses runs of slashes.
fn decode_path(path: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(path.len());
    let mut after_separator = false;
    let mut pos = 0;
    while let Some(&b) = path.get(pos) {
        let (mut byte, used) = if b == b'%' {
            decode_escape(path.get(pos..).unwrap_or_default(), true)
        } else {
            (b, 1)
        };
        pos += used;
        if byte == b'\\' {
            byte = b'/';
        }
        if byte == b'/' {
            if after_separator {
                continue;
            }
            after_separator = true;
        } else {
            after_separator = false;
        }
        out.push(byte);
    }
    out
}

/// Turns each UTF-8 character of `input`, overlong forms allowed, into one
/// byte by best fit, as `htp_utf8_decode_path_inplace` does.
fn utf8_to_bestfit(input: &[u8]) -> Vec<u8> {
    const CONTINUATION: std::ops::RangeInclusive<u8> = 0x80..=0xbf;

    let mut out = Vec::with_capacity(input.len());
    let mut pos = 0;
    while let Some(&lead) = input.get(pos) {
        if lead.is_ascii() {
            out.push(lead);
            pos += 1;
            continue;
        }
        // The number of continuation bytes, the range the first of them
        // must fall in, and the bits the lead byte carries.
        let (count, first_range, bits) = match lead {
            0xc0..=0xdf => (1, CONTINUATION, lead & 0x1f),
            0xe0..=0xec | 0xee..=0xef => (2, CONTINUATION, lead & 0x0f),
            // No surrogates.
            0xed => (2, 0x80..=0x9f, lead & 0x0f),
            0xf0..=0xf3 => (3, CONTINUATION, lead & 0x07),
            // Nothing past U+10FFFF.
            0xf4 => (3, 0x80..=0x8f, lead & 0x07),
            _ => {
                out.push(bestfit::REPLACEMENT);
                pos += 1;
                continue;
            }
        };
        let mut codepoint = u32::from(bits);
        let mut next = pos + 1;
        let mut complete = true;
        for index in 0..count {
            let Some(&b) = input.get(next) else {
                // The input ends inside the character, which is dropped.
                return out;
            };
            let range = if index == 0 {
                &first_range
            } else {
                &CONTINUATION
            };
            if !range.contains(&b) {
                complete = false;
                break;
            }
            codepoint = (codepoint << 6) | u32::from(b & 0x3f);
            next += 1;
        }
        out.push(if complete {
            bestfit::byte_for(codepoint)
        } else {
            bestfit::REPLACEMENT
        });
        // A byte that broke the character off is read again.
        pos = next;
    }
    out
}

/// Removes dot segments from a path as libhtp's
/// `htp_normalize_uri_path_inplace` does.
///
/// The input is read one segment at a time. `pending` holds a byte that
/// stands in for input already consumed: the `/` that a `/./` or `/../`
/// leaves behind. Like libhtp, the loop stops once the input is used up,
/// even with a `/` pending, which is why `/a/.` ends up as `/a`.
fn remove_dot_segments(input: &[u8]) -> Vec<u8> {
    /// Removes the last segment of `out` and the `/` before it.
    fn pop_segment(out: &mut Vec<u8>) {
        while out.last().is_some_and(|&b| b != b'/') {
            out.pop();
        }
        out.pop();
    }

    let mut out = Vec::with_capacity(input.len());
    let mut pos = 0;
    let mut pending: Option<u8> = None;
    while pos < input.len() {
        let byte = match pending.take() {
            Some(byte) => byte,
            None => {
                let Some(&byte) = input.get(pos) else { break };
                pos += 1;
                byte
            }
        };
        let rest = input.get(pos..).unwrap_or_default();
        if byte == b'.' {
            // A leading `../` or `./`.
            if rest.starts_with(b"./") {
                pos += 2;
                continue;
            }
            if rest.starts_with(b"/") {
                pos += 1;
                continue;
            }
            // A lone `.` or `..` at the end.
            if rest.is_empty() {
                break;
            }
            if rest == b"." {
                break;
            }
        }
        if byte == b'/' {
            if rest.starts_with(b"./") {
                pending = Some(b'/');
                pos += 2;
                continue;
            }
            if rest == b"." {
                pending = Some(b'/');
                pos += 1;
                continue;
            }
            if rest.starts_with(b"../") {
                pending = Some(b'/');
                pos += 3;
                pop_segment(&mut out);
                continue;
            }
            if rest == b".." {
                pending = Some(b'/');
                pos += 2;
                pop_segment(&mut out);
                continue;
            }
        }
        // Move the segment, with the byte before it, to the output.
        out.push(byte);
        let len = rest.iter().position(|&b| b == b'/').unwrap_or(rest.len());
        out.extend_from_slice(rest.get(..len).unwrap_or_default());
        pos += len;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(input: &[u8]) -> Vec<u8> {
        normalize_uri(input)
    }

    #[test]
    fn percent_escapes_in_the_path() {
        assert_eq!(uri(b"/%41%62c"), b"/Abc");
        // A NUL is decoded and does not end the path.
        assert_eq!(uri(b"/a%00b"), b"/a\x00b");
        // Invalid or broken-off escapes keep their `%`.
        assert_eq!(uri(b"/a%zz"), b"/a%zz");
        assert_eq!(uri(b"/a%4"), b"/a%4");
        assert_eq!(uri(b"/a%"), b"/a%");
        assert_eq!(uri(b"/%%41"), b"/%A");
        // `+` stays.
        assert_eq!(uri(b"/a+b"), b"/a+b");
    }

    #[test]
    fn u_escapes_in_the_path() {
        assert_eq!(uri(b"/%u0041"), b"/A");
        assert_eq!(uri(b"/%U0041"), b"/A");
        // Best fit: fullwidth solidus, a Latin letter, and one with no fit.
        assert_eq!(uri(b"/a%uff0fb"), b"/a/b");
        assert_eq!(uri(b"/%u0100"), b"/A");
        assert_eq!(uri(b"/%u4e00"), b"/?");
        // A `%u` without four hex digits keeps its `%` and is not `%HH`.
        assert_eq!(uri(b"/%u00"), b"/%u00");
        assert_eq!(uri(b"/%u00zz"), b"/%u00zz");
    }

    #[test]
    fn separators() {
        assert_eq!(uri(b"/a//b"), b"/a/b");
        assert_eq!(uri(b"///a"), b"/a");
        assert_eq!(uri(b"/a\\b"), b"/a/b");
        assert_eq!(uri(b"/a%2fb"), b"/a/b");
        assert_eq!(uri(b"/a%5Cb"), b"/a/b");
        assert_eq!(uri(b"/a/%2f/b"), b"/a/b");
    }

    #[test]
    fn dot_segments() {
        assert_eq!(uri(b"/a/./b"), b"/a/b");
        assert_eq!(uri(b"/a/../b"), b"/b");
        assert_eq!(uri(b"/a/b/../../../c"), b"/c");
        assert_eq!(uri(b"/../a"), b"/a");
        assert_eq!(uri(b"/a/%2e%2e/b"), b"/b");
        // libhtp drops the final `/` after a trailing dot segment.
        assert_eq!(uri(b"/a/b/."), b"/a/b");
        assert_eq!(uri(b"/a/b/.."), b"/a");
        assert_eq!(uri(b"/a/b/"), b"/a/b/");
        // A dot segment ends at `/`, not inside a name.
        assert_eq!(uri(b"/a/.b/..c"), b"/a/.b/..c");
        // Relative pieces.
        assert_eq!(uri(b"./a"), b"a");
        assert_eq!(uri(b"../a"), b"a");
        assert_eq!(uri(b"."), b"");
        assert_eq!(uri(b".."), b"");
        // Separators are compressed before dot segments are removed.
        assert_eq!(uri(b"/a/.//b"), b"/a/b");
    }

    #[test]
    fn utf8_in_the_path() {
        // A character below U+0100 is that byte.
        assert_eq!(uri("/é".as_bytes()), b"/\xe9");
        assert_eq!(uri(b"/%c3%a9"), b"/\xe9");
        // Best fit above it.
        assert_eq!(uri("/Ā".as_bytes()), b"/A");
        assert_eq!(uri("/\u{4e00}".as_bytes()), b"/?");
        // Overlong forms are decoded, and an overlong `/` is a separator
        // for dot segments.
        assert_eq!(uri(b"/%c0%af"), b"//");
        assert_eq!(uri(b"/a%c0%af..%c0%afb"), b"/b");
        // It comes after separators are compressed, so it is not.
        assert_eq!(uri(b"/a/%c0%af/b"), b"/a///b");
        // Invalid bytes become `?`; a broken-off character becomes one
        // `?` and the byte that broke it is read again.
        assert_eq!(uri(b"/\xff"), b"/?");
        assert_eq!(uri(b"/\xc3A"), b"/?A");
        assert_eq!(uri(b"/\xe4\xb8A"), b"/?A");
        assert_eq!(uri(b"/\xed\xa0\x80"), b"/???");
        assert_eq!(uri(b"/\xf4\x90\x80\x80"), b"/????");
        // An incomplete character at the end is dropped.
        assert_eq!(uri(b"/a\xe4\xb8"), b"/a");
        // Four-byte characters are past the map.
        assert_eq!(uri("/\u{1f600}".as_bytes()), b"/?");
    }

    #[test]
    fn query_and_fragment() {
        assert_eq!(uri(b"/a?b=%41&c=%u0041+d"), b"/a?b=A&c=%u0041+d");
        // No path handling in the query.
        assert_eq!(uri(b"/a?x=/../b//c\\d"), b"/a?x=/../b//c\\d");
        assert_eq!(uri(b"/a?x=%zz%4"), b"/a?x=%zz%4");
        assert_eq!(uri(b"/a?"), b"/a?");
        assert_eq!(uri(b"/a#f%41%u0042"), b"/a#fAB");
        assert_eq!(uri(b"/a?q#f"), b"/a?q#f");
        // `#` before `?`: everything after `#` is the fragment.
        assert_eq!(uri(b"/a#f?q"), b"/a#f?q");
        // The path ends at the first `?`.
        assert_eq!(uri(b"/a%3fb?c"), b"/a?b?c");
    }

    #[test]
    fn absolute_and_odd_uris() {
        assert_eq!(uri(b"http://Example.com:80/a/../b?c"), b"/b?c");
        assert_eq!(uri(b"http://user:pw@host"), b"");
        assert_eq!(uri(b"http://host?q"), b"?q");
        // `///` after the scheme is a path.
        assert_eq!(uri(b"http:///a"), b"/a");
        // A scheme reaches to the first colon, wherever it is.
        assert_eq!(uri(b"a.php?x=1:2"), b"2");
        assert_eq!(uri(b"mailto:x"), b"x");
        // No colon: all path.
        assert_eq!(uri(b"index.php?a=1"), b"index.php?a=1");
        // Trailing spaces are dropped, other ones kept.
        assert_eq!(uri(b"/a b  "), b"/a b");
        assert_eq!(uri(b""), b"");
        assert_eq!(uri(b"   "), b"");
    }

    #[test]
    fn pattern_pieces() {
        assert_eq!(uri(b"cmd.exe"), b"cmd.exe");
        assert_eq!(uri(b"\xff\xfe"), b"??");
        assert_eq!(uri(b"%4"), b"%4");
        assert_eq!(uri(b"a/%"), b"a/%");
    }

    #[test]
    fn hosts() {
        assert_eq!(normalize_host(b"Example.COM:8080"), b"example.com");
        assert_eq!(normalize_host(b"Example.COM"), b"example.com");
        assert_eq!(normalize_host(b" example.com :80 "), b"example.com");
        assert_eq!(normalize_host(b"example.com."), b"example.com.");
        assert_eq!(normalize_host(b"[2001:DB8::1]:8080"), b"[2001:db8::1]");
        assert_eq!(normalize_host(b"[2001:db8::1]"), b"[2001:db8::1]");
        assert_eq!(normalize_host(b"[2001:db8::1]junk"), b"[2001:db8::1]");
        assert_eq!(normalize_host(b"[2001:DB8::1"), b"[2001:db8::1");
        assert_eq!(normalize_host(b"2001:db8::1"), b"2001");
        assert_eq!(normalize_host(b":80"), b"");
        assert_eq!(normalize_host(b"\t\x0b"), b"");
        assert_eq!(normalize_host(b"H\xffST:1"), b"h\xffst");
    }
}
