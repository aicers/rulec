//! Unpacking an HTTP body: the chunked transfer coding, then one layer of
//! gzip, zlib or raw deflate.

use std::borrow::Cow;

use flate2::{Decompress, FlushDecompress, Status};

/// The most bytes [`decode_body`] returns from unpacking a body: 1 MiB.
///
/// Unpacking stops once the output reaches it, and the output is cut
/// there, so a compression bomb takes no longer than unpacking 1 MiB.
pub const MAX_DECODED_BODY_LEN: usize = 1 << 20;

/// How many bytes one call to the inflater may write.
const INFLATE_STEP: usize = 64 * 1024;

/// The gzip magic and the deflate compression method.
const GZIP_MAGIC: [u8; 3] = [0x1f, 0x8b, 0x08];
/// gzip header flags (RFC 1952, section 2.3.1).
const GZIP_FHCRC: u8 = 0x02;
const GZIP_FEXTRA: u8 = 0x04;
const GZIP_FNAME: u8 = 0x08;
const GZIP_FCOMMENT: u8 = 0x10;
/// The length of the fixed part of a gzip header.
const GZIP_FIXED_HEADER_LEN: usize = 10;

/// Unpacks an HTTP body.
///
/// A record holds no response headers, so the codings are recognized from
/// the bytes, and the body may be only the first part of the real one.
///
/// 1. **Chunked.** The body is chunked if it starts with a chunk-size line
///    — one or more hex digits, then optionally an extension starting with
///    `;`, ending in CRLF or LF — and the first chunk's data is followed by
///    CRLF or LF, or the input ends inside the first chunk. The chunks'
///    data is joined up to the last chunk (size `0`); its trailers are
///    dropped. If the input ends inside a chunk, or a later chunk-size line
///    or the line end after a later chunk's data is malformed, the data
///    joined so far (with that chunk's data, if it is there whole) is the
///    result.
/// 2. **Compression,** on the result of step 1 (or the body itself, if it
///    is not chunked):
///    - It starts with a gzip header (`1f 8b 08`) or a zlib header
///      (compression method 8, no preset dictionary, and `(CMF * 256 +
///      FLG) % 31 == 0`): it is inflated up to the end of the stream, the
///      end of the input or an error. If at least one byte came out, that
///      is the result; if none did, the bytes before inflating are. Only
///      the first gzip member is read, and checksums are not checked.
///    - Neither header: it is inflated as raw deflate, and that is the
///      result only if the whole input is one raw deflate stream ending in
///      its final block, with no byte left over. Otherwise the bytes before
///      inflating are the result. This keeps a plain body whose first byte
///      happens to read as a deflate block header (a JSON body starting
///      with `{`, say) from turning into garbage.
///
/// Neither chunked nor compressed, the body is returned as it is. Chunked
/// but not compressed, the joined chunks are.
///
/// Each step's output is cut at [`MAX_DECODED_BODY_LEN`], and unpacking
/// stops when it reaches that length; for raw deflate, an output that
/// reaches it is used without reading the rest of the stream.
#[must_use]
pub fn decode_body(body: &[u8]) -> Cow<'_, [u8]> {
    let dechunked = dechunk(body);
    let input = dechunked.as_deref().unwrap_or(body);
    if let Some(inflated) = decompress(input) {
        return Cow::Owned(inflated);
    }
    match dechunked {
        Some(joined) => Cow::Owned(joined),
        None => Cow::Borrowed(body),
    }
}

/// Reads a chunk-size line at the start of `input`: its size, and the
/// input after the line. `None` if `input` does not start with one, or
/// the size does not fit in 64 bits.
fn size_line(input: &[u8]) -> Option<(u64, &[u8])> {
    let digits = input.iter().take_while(|b| b.is_ascii_hexdigit()).count();
    if digits == 0 {
        return None;
    }
    let (hex, rest) = input.split_at(digits);
    let size = hex.iter().try_fold(0_u64, |size, &d| {
        let digit = char::from(d).to_digit(16)?;
        size.checked_mul(16)?.checked_add(u64::from(digit))
    })?;
    let line_end = rest.iter().position(|&b| b == b'\n')?;
    let (line, after) = rest.split_at(line_end);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if !line.is_empty() && line.first() != Some(&b';') {
        return None;
    }
    Some((size, after.get(1..).unwrap_or_default()))
}

/// Returns the input after a CRLF or LF at its start, if there is one.
fn line_end(input: &[u8]) -> Option<&[u8]> {
    input
        .strip_prefix(b"\r\n")
        .or_else(|| input.strip_prefix(b"\n"))
}

/// Appends `data` to `out`, up to [`MAX_DECODED_BODY_LEN`] in all.
/// Returns whether `out` reached that length.
fn push_capped(out: &mut Vec<u8>, data: &[u8]) -> bool {
    let room = MAX_DECODED_BODY_LEN.saturating_sub(out.len());
    out.extend_from_slice(data.get(..room).unwrap_or(data));
    out.len() >= MAX_DECODED_BODY_LEN
}

/// Joins the chunks of a chunked body, or returns `None` if the body is
/// not chunked.
fn dechunk(body: &[u8]) -> Option<Vec<u8>> {
    let (mut size, mut rest) = size_line(body)?;
    let mut out = Vec::new();
    let mut first = true;
    while size > 0 {
        let len = usize::try_from(size).unwrap_or(usize::MAX);
        let Some(data) = rest.get(..len) else {
            // The input ends inside the chunk.
            push_capped(&mut out, rest);
            break;
        };
        let after = rest.get(len..).unwrap_or_default();
        let Some(next) = line_end(after) else {
            // The input ends before the line end (or inside it, after a
            // CR), which is still inside the chunk; anything else breaks
            // the framing, and the first chunk must not be broken.
            if first && !(after.is_empty() || after == b"\r") {
                return None;
            }
            push_capped(&mut out, data);
            break;
        };
        if push_capped(&mut out, data) {
            break;
        }
        first = false;
        let Some((next_size, after_line)) = size_line(next) else {
            break;
        };
        size = next_size;
        rest = after_line;
    }
    // The last chunk can be the first: then the body is chunked if its
    // size line is followed by a line end, or nothing.
    if first && size == 0 && !(rest.is_empty() || rest == b"\r" || line_end(rest).is_some()) {
        return None;
    }
    Some(out)
}

/// How inflating ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ended {
    /// The stream ended, after taking this many input bytes.
    StreamEnd(u64),
    /// The output reached [`MAX_DECODED_BODY_LEN`].
    Capped,
    /// The input ran out or was not valid.
    Stopped,
}

/// Inflates `input`, a zlib stream if `zlib` is set and raw deflate
/// otherwise, into at most [`MAX_DECODED_BODY_LEN`] bytes.
fn inflate(input: &[u8], zlib: bool) -> (Vec<u8>, Ended) {
    let mut inflater = Decompress::new(zlib);
    let mut out = Vec::new();
    let mut buf = vec![0_u8; INFLATE_STEP];
    loop {
        let room = MAX_DECODED_BODY_LEN
            .saturating_sub(out.len())
            .min(buf.len());
        if room == 0 {
            return (out, Ended::Capped);
        }
        let taken = usize::try_from(inflater.total_in()).unwrap_or(usize::MAX);
        let remaining = input.get(taken..).unwrap_or_default();
        let before_in = inflater.total_in();
        let before_out = inflater.total_out();
        let result = inflater.decompress(
            remaining,
            buf.get_mut(..room).unwrap_or_default(),
            FlushDecompress::None,
        );
        let produced = usize::try_from(inflater.total_out() - before_out).unwrap_or(0);
        out.extend_from_slice(buf.get(..produced).unwrap_or_default());
        match result {
            Ok(Status::StreamEnd) => return (out, Ended::StreamEnd(inflater.total_in())),
            Ok(_) if produced == 0 && inflater.total_in() == before_in => {
                return (out, Ended::Stopped);
            }
            Ok(_) => {}
            Err(_) => return (out, Ended::Stopped),
        }
    }
}

/// Returns the deflate data of the first member of a gzip stream, which
/// starts with [`GZIP_MAGIC`], or `None` if its header is cut short.
fn gzip_deflate_data(input: &[u8]) -> Option<&[u8]> {
    let flags = *input.get(3)?;
    let mut rest = input.get(GZIP_FIXED_HEADER_LEN..)?;
    if flags & GZIP_FEXTRA != 0 {
        let len = usize::from(u16::from_le_bytes([*rest.first()?, *rest.get(1)?]));
        rest = rest.get(2 + len..)?;
    }
    for flag in [GZIP_FNAME, GZIP_FCOMMENT] {
        if flags & flag != 0 {
            let nul = rest.iter().position(|&b| b == 0)?;
            rest = rest.get(nul + 1..)?;
        }
    }
    if flags & GZIP_FHCRC != 0 {
        rest = rest.get(2..)?;
    }
    Some(rest)
}

/// Returns whether `input` starts with a zlib header using deflate and no
/// preset dictionary.
fn is_zlib_header(input: &[u8]) -> bool {
    const DEFLATE: u8 = 8;
    const FDICT: u8 = 0x20;
    match input {
        [cmf, flg, ..] => {
            cmf & 0x0f == DEFLATE
                && flg & FDICT == 0
                && (u16::from(*cmf) * 256 + u16::from(*flg)) % 31 == 0
        }
        _ => false,
    }
}

/// Inflates one layer of gzip, zlib or raw deflate, or returns `None` if
/// the input is none of them by the rules of [`decode_body`].
fn decompress(input: &[u8]) -> Option<Vec<u8>> {
    if input.starts_with(&GZIP_MAGIC) {
        let (out, _) = inflate(gzip_deflate_data(input)?, false);
        return (!out.is_empty()).then_some(out);
    }
    if is_zlib_header(input) {
        let (out, _) = inflate(input, true);
        return (!out.is_empty()).then_some(out);
    }
    let (out, ended) = inflate(input, false);
    let whole = match ended {
        Ended::StreamEnd(taken) => usize::try_from(taken).is_ok_and(|t| t == input.len()),
        Ended::Capped => true,
        Ended::Stopped => false,
    };
    whole.then_some(out)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::{
        Compression,
        write::{DeflateEncoder, GzEncoder, ZlibEncoder},
    };

    use super::*;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn deflate(data: &[u8]) -> Vec<u8> {
        let mut e = DeflateEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn chunk(data: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for d in data {
            out.extend_from_slice(format!("{:x}\r\n", d.len()).as_bytes());
            out.extend_from_slice(d);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"0\r\nX-Trailer: t\r\n\r\n");
        out
    }

    const TEXT: &[u8] = b"hello, world; hello, world; hello, world";

    #[test]
    fn plain_bodies_are_kept() {
        for body in [
            &b"just text"[..],
            b"{\"a\": 1}",
            b"[1, 2]",
            b"",
            b"\x00\x01",
            b"<html>",
        ] {
            assert!(matches!(decode_body(body), Cow::Borrowed(b) if b == body));
        }
    }

    #[test]
    fn chunked() {
        assert_eq!(
            &*decode_body(&chunk(&[b"hello, ", b"world"])),
            b"hello, world"
        );
        assert_eq!(&*decode_body(b"5;ext=1\r\nhello\r\n0\r\n\r\n"), b"hello");
        assert_eq!(&*decode_body(b"5\nhello\n6\n world\n0\n\n"), b"hello world");
        assert_eq!(
            &*decode_body(b"A\r\n0123456789\r\n0\r\n\r\n"),
            b"0123456789"
        );
        // Cut short inside a chunk, inside a line end, or with no last
        // chunk.
        assert_eq!(&*decode_body(b"5\r\nhello\r\na\r\nwor"), b"hellowor");
        assert_eq!(&*decode_body(b"5\r\nhel"), b"hel");
        assert_eq!(&*decode_body(b"5\r\nhello"), b"hello");
        assert_eq!(&*decode_body(b"5\r\nhello\r"), b"hello");
        assert_eq!(&*decode_body(b"5\r\nhello\r\n"), b"hello");
        // A later chunk is broken: the data so far.
        assert_eq!(&*decode_body(b"5\r\nhello\r\nzz\r\nmore"), b"hello");
        assert_eq!(&*decode_body(b"5\r\nhello\r\n3\r\nabcX"), b"helloabc");
        // An empty chunked body.
        assert_eq!(&*decode_body(b"0\r\n\r\n"), b"");
        // Not chunked: no line end, a broken first chunk, a space after
        // the size, an extension without `;`.
        for body in [
            &b"5"[..],
            b"5\r\nhelloX",
            b"5 \r\nhello\r\n",
            b"5x\r\nhello\r\n",
            b"0\r\nTrailer",
            b"cafe babe\n",
        ] {
            assert_eq!(&*decode_body(body), body);
        }
        // A size past 64 bits is not a size.
        let huge = b"10000000000000000\r\nx";
        assert_eq!(&*decode_body(huge), huge);
    }

    #[test]
    fn compressed() {
        assert_eq!(&*decode_body(&gzip(TEXT)), TEXT);
        assert_eq!(&*decode_body(&zlib(TEXT)), TEXT);
        assert_eq!(&*decode_body(&deflate(TEXT)), TEXT);
        let gz = gzip(TEXT);
        let (a, b) = gz.split_at(gz.len() / 2);
        assert_eq!(&*decode_body(&chunk(&[a, b])), TEXT);
        assert_eq!(&*decode_body(&chunk(&[&deflate(TEXT)])), TEXT);
    }

    #[test]
    fn gzip_header_fields() {
        let mut e = flate2::GzBuilder::new()
            .filename("f.txt")
            .comment("c")
            .extra(vec![1, 2, 3])
            .write(Vec::new(), Compression::default());
        e.write_all(TEXT).unwrap();
        let gz = e.finish().unwrap();
        assert_eq!(&*decode_body(&gz), TEXT);
        // The header itself cut short: nothing inflated.
        assert_eq!(&*decode_body(&gz[..12]), &gz[..12]);
    }

    #[test]
    fn truncated_streams() {
        let long: Vec<u8> = (0..20_000_u32)
            .flat_map(|i| format!("line {i}\n").into_bytes())
            .collect();
        let gz = gzip(&long);
        let part = &gz[..gz.len() / 2];
        let out = decode_body(part);
        assert!(!out.is_empty() && out.len() < long.len());
        assert!(long.starts_with(&out));
        let z = zlib(&long);
        let out = decode_body(&z[..z.len() / 2]);
        assert!(!out.is_empty() && long.starts_with(&out));
        // A truncated raw deflate stream is kept as it is.
        let d = deflate(&long);
        let part = &d[..d.len() / 2];
        assert_eq!(&*decode_body(part), part);
        // So is a complete one with bytes after it.
        let mut extra = deflate(TEXT);
        extra.push(b'x');
        assert_eq!(&*decode_body(&extra), &extra[..]);
        // A gzip stream with nothing inflated is kept.
        let empty = gzip(b"");
        assert_eq!(&*decode_body(&empty), &empty[..]);
        // A corrupt gzip payload after some output keeps that output.
        let mut bad = gzip(&long);
        let len = bad.len();
        for b in &mut bad[len / 2..] {
            *b = 0xff;
        }
        let out = decode_body(&bad);
        assert!(out.len() > 1000 && out.len() < long.len());
        assert_eq!(&out[..1000], &long[..1000]);
    }

    #[test]
    fn output_is_capped() {
        let big = vec![b'a'; MAX_DECODED_BODY_LEN * 3];
        for packed in [gzip(&big), zlib(&big), deflate(&big)] {
            let out = decode_body(&packed);
            assert_eq!(out.len(), MAX_DECODED_BODY_LEN);
            assert!(out.iter().all(|&b| b == b'a'));
        }
        let chunked = chunk(&[&big]);
        assert_eq!(decode_body(&chunked).len(), MAX_DECODED_BODY_LEN);
    }

    #[test]
    fn headers() {
        assert!(is_zlib_header(&[0x78, 0x9c]));
        assert!(is_zlib_header(&[0x78, 0x01]));
        assert!(!is_zlib_header(&[0x78, 0x9d]));
        assert!(!is_zlib_header(&[0x79, 0x9c]));
        assert!(!is_zlib_header(&[0x78]));
        // FDICT set.
        assert!(!is_zlib_header(&[0x78, 0xbb]));
    }
}
