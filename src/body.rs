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
///    CRLF or LF, or the input ends inside the first chunk. A size too
///    large to hold is read as the largest one, so a body with such a size
///    ends inside that chunk. The chunks'
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
/// The unpacked output is cut at [`MAX_DECODED_BODY_LEN`]: inflating stops
/// when its output reaches that length (for raw deflate, such an output is
/// used without reading the rest of the stream), and joined chunks that are
/// not compressed are cut there.
///
/// Chunks are joined only up to [`MAX_DECODED_BODY_LEN`] at first, so a
/// chunked body that is not compressed costs no more to unpack than its
/// first 1 MiB, however long it is. Compressed data has no cap of its own
/// going in: if what inflating makes of the first
/// [`MAX_DECODED_BODY_LEN`] bytes of the joined chunks could change with
/// the bytes after them, the chunks are joined whole, however long, and
/// the cap applies to what comes out of inflating. The joined chunks are
/// never longer than the body.
#[must_use]
pub fn decode_body(body: &[u8]) -> Cow<'_, [u8]> {
    let Some(chunks) = Chunks::new(body) else {
        return match decompress(body, false) {
            Decompressed::Inflated(out) => Cow::Owned(out),
            Decompressed::NotCompressed | Decompressed::NeedsMore => Cow::Borrowed(body),
        };
    };
    let head = join(chunks.clone(), MAX_DECODED_BODY_LEN);
    match decompress(&head.data, head.cut) {
        Decompressed::Inflated(out) => Cow::Owned(out),
        Decompressed::NotCompressed => Cow::Owned(head.data),
        Decompressed::NeedsMore => match decompress(&join(chunks, usize::MAX).data, false) {
            Decompressed::Inflated(out) => Cow::Owned(out),
            // Not compressed after all: the whole joined chunks cut at the
            // cap, which is what `head` holds.
            Decompressed::NotCompressed | Decompressed::NeedsMore => Cow::Owned(head.data),
        },
    }
}

/// Reads a chunk-size line at the start of `input`: its size, and the
/// input after the line. `None` if `input` does not start with one. A
/// size past `usize::MAX` saturates there: no chunk that long can be in
/// the input, so either way the input ends inside it.
fn size_line(input: &[u8]) -> Option<(usize, &[u8])> {
    const RADIX: u32 = 16;
    let digits = input.iter().take_while(|b| b.is_ascii_hexdigit()).count();
    if digits == 0 {
        return None;
    }
    let (hex, rest) = input.split_at(digits);
    let size = hex.iter().try_fold(0_usize, |size, &d| {
        let digit = usize::try_from(char::from(d).to_digit(RADIX)?).ok()?;
        Some(size.saturating_mul(16).saturating_add(digit))
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

/// The data of the chunks of a chunked body, one chunk at a time, up to
/// the last chunk (size `0`) or to where the input or the framing breaks
/// off. Nothing is copied.
#[derive(Clone, Debug)]
struct Chunks<'a> {
    /// The size of the chunk `rest` starts with; `0` once there is none.
    size: usize,
    /// The input after the chunk-size line of the current chunk.
    rest: &'a [u8],
}

impl<'a> Chunks<'a> {
    /// Reads the first chunk of `body`, or returns `None` if the body is
    /// not chunked.
    fn new(body: &'a [u8]) -> Option<Self> {
        let (size, rest) = size_line(body)?;
        // The first chunk's data, or the last chunk's size line if the
        // first chunk is the last, is followed by a line end, or the input
        // ends before one (or inside it, after a CR). Anything else breaks
        // the framing, and the first chunk must not be broken. Input
        // ending inside the first chunk's data is still inside the chunk.
        let after = if size == 0 {
            Some(rest)
        } else {
            rest.get(size..)
        };
        let framed = after
            .is_none_or(|after| after.is_empty() || after == b"\r" || line_end(after).is_some());
        framed.then_some(Self { size, rest })
    }
}

impl<'a> Iterator for Chunks<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        if self.size == 0 {
            return None;
        }
        let Some(data) = self.rest.get(..self.size) else {
            // The input ends inside the chunk.
            self.size = 0;
            return Some(self.rest);
        };
        let after = self.rest.get(self.size..).unwrap_or_default();
        // Without a line end and a chunk-size line after the data, the
        // input or the framing breaks off after this chunk.
        match line_end(after).and_then(size_line) {
            Some((size, rest)) => {
                self.size = size;
                self.rest = rest;
            }
            None => self.size = 0,
        }
        Some(data)
    }
}

/// Chunk data joined up to a limit.
#[derive(Debug)]
struct Joined {
    /// The joined data, no longer than the limit.
    data: Vec<u8>,
    /// Whether chunk data past the limit was left out.
    cut: bool,
}

/// Joins chunk data, copying at most `limit` bytes and reading no chunk
/// after the one that reaches it.
fn join(chunks: Chunks<'_>, limit: usize) -> Joined {
    // The chunks' data all lies in `rest`, so it never needs more room.
    let mut data = Vec::with_capacity(chunks.rest.len().min(limit));
    for piece in chunks {
        let room = limit.saturating_sub(data.len());
        if piece.len() > room {
            data.extend_from_slice(piece.get(..room).unwrap_or_default());
            return Joined { data, cut: true };
        }
        data.extend_from_slice(piece);
    }
    Joined { data, cut: false }
}

/// How inflating ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ended {
    /// The stream ended, after taking this many input bytes.
    StreamEnd(u64),
    /// The output reached [`MAX_DECODED_BODY_LEN`].
    Capped,
    /// Inflating made no progress without an error: the input ran out.
    Starved,
    /// The input was not valid.
    Invalid,
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
                return (out, Ended::Starved);
            }
            Ok(_) => {}
            Err(_) => return (out, Ended::Invalid),
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

/// What [`decompress`] made of its input.
#[derive(Debug)]
enum Decompressed {
    /// The input is compressed, and inflated to this.
    Inflated(Vec<u8>),
    /// The input is none of gzip, zlib or raw deflate by the rules of
    /// [`decode_body`].
    NotCompressed,
    /// The input is followed by more data, and what inflating makes of the
    /// input alone could change with that data.
    NeedsMore,
}

/// Inflates one layer of gzip, zlib or raw deflate by the rules of
/// [`decode_body`]. `more` says whether more data follows `input`, which
/// is then only its start.
fn decompress(input: &[u8], more: bool) -> Decompressed {
    let (out, ended) = if input.starts_with(&GZIP_MAGIC) {
        let Some(data) = gzip_deflate_data(input) else {
            return if more {
                Decompressed::NeedsMore
            } else {
                Decompressed::NotCompressed
            };
        };
        inflate(data, false)
    } else if is_zlib_header(input) {
        inflate(input, true)
    } else {
        let (out, ended) = inflate(input, false);
        let whole = match ended {
            // Whether bytes follow the stream, or the stream would have
            // ended exactly at the cap with bytes after it, only the data
            // after `input` tells.
            Ended::Starved | Ended::Capped if more => return Decompressed::NeedsMore,
            Ended::StreamEnd(taken) => {
                !more && usize::try_from(taken).is_ok_and(|t| t == input.len())
            }
            Ended::Capped => true,
            Ended::Starved | Ended::Invalid => false,
        };
        return if whole {
            Decompressed::Inflated(out)
        } else {
            Decompressed::NotCompressed
        };
    };
    if more && ended == Ended::Starved {
        Decompressed::NeedsMore
    } else if out.is_empty() {
        Decompressed::NotCompressed
    } else {
        Decompressed::Inflated(out)
    }
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
        // A size too large to hold saturates: the input ends inside the
        // chunk.
        assert_eq!(&*decode_body(b"10000000000000000\r\nhello"), b"hello");
        let huge = format!("{}\r\nhello", "f".repeat(64));
        assert_eq!(&*decode_body(huge.as_bytes()), b"hello");
        assert_eq!(
            &*decode_body(b"5\r\nhello\r\n10000000000000000\r\nworld"),
            b"helloworld"
        );
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
    fn chunked_compressed_data_is_not_capped_before_inflating() {
        // Stored, not compressed: the gzip stream is longer than the cap,
        // and what it inflates to fits in it exactly.
        let data: Vec<u8> = (0..MAX_DECODED_BODY_LEN)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let mut e = GzEncoder::new(Vec::new(), Compression::none());
        e.write_all(&data).unwrap();
        let gz = e.finish().unwrap();
        assert!(gz.len() > MAX_DECODED_BODY_LEN);
        assert_eq!(&*decode_body(&gz), &data[..]);
        let pieces: Vec<&[u8]> = gz.chunks(100_000).collect();
        assert_eq!(&*decode_body(&chunk(&pieces)), &data[..]);
        let mut e = DeflateEncoder::new(Vec::new(), Compression::none());
        e.write_all(&data).unwrap();
        let raw = e.finish().unwrap();
        assert_eq!(&*decode_body(&chunk(&[&raw])), &data[..]);
    }

    /// Plain text that is no compressed stream, `len` bytes of it.
    fn lines(len: usize) -> Vec<u8> {
        (0_u32..)
            .flat_map(|i| format!("line {i}\n").into_bytes())
            .take(len)
            .collect()
    }

    /// Bytes that do not compress, `len` of them.
    fn noise(len: usize) -> Vec<u8> {
        let mut state = 0x2545_f491_u32;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state.to_le_bytes()[0]
            })
            .collect()
    }

    #[test]
    fn dechunking_stops_at_the_cap() {
        let data = lines(2 * MAX_DECODED_BODY_LEN + 12_345);
        let pieces: Vec<&[u8]> = data.chunks(100_000).collect();
        let body = chunk(&pieces);
        let chunks = Chunks::new(&body).unwrap();
        let head = join(chunks.clone(), MAX_DECODED_BODY_LEN);
        // No byte past the cap is copied, and no room is made for one.
        assert!(head.cut);
        assert_eq!(head.data.len(), MAX_DECODED_BODY_LEN);
        assert!(head.data.capacity() <= MAX_DECODED_BODY_LEN);
        assert_eq!(head.data, data[..MAX_DECODED_BODY_LEN]);
        // Not compressed, so `decode_body` joins no more than that.
        assert!(matches!(
            decompress(&head.data, head.cut),
            Decompressed::NotCompressed
        ));
        assert_eq!(&*decode_body(&body), &data[..MAX_DECODED_BODY_LEN]);
        // Joined without a limit, the chunks give all the data.
        let whole = join(chunks, usize::MAX);
        assert!(!whole.cut);
        assert_eq!(whole.data, data);
    }

    #[test]
    fn chunks_ending_around_the_cap() {
        const CAP: usize = MAX_DECODED_BODY_LEN;
        // The trailer `chunk` ends with, after the last chunk's data.
        const AFTER_DATA: usize = b"\r\n0\r\nX-Trailer: t\r\n\r\n".len();
        let data = lines(CAP + 3);
        for sizes in [
            &[CAP - 1][..],
            &[CAP],
            &[CAP + 1],
            &[CAP - 1, 1],
            &[CAP - 1, 2],
            &[CAP, 1],
            &[CAP + 1, 1],
            &[1, CAP - 2, 1],
            &[1, CAP - 1, 1],
            &[1, CAP, 1],
        ] {
            let mut pieces = Vec::new();
            let mut len = 0;
            for &size in sizes {
                pieces.push(&data[len..len + size]);
                len += size;
            }
            let body = chunk(&pieces);
            // Whole, and cut short inside the last chunk's data.
            for (body, len) in [
                (&body[..], len),
                (&body[..body.len() - AFTER_DATA - 1], len - 1),
            ] {
                let expected = &data[..len.min(CAP)];
                assert_eq!(&*decode_body(body), expected, "{sizes:?}, {len}");
                let head = join(Chunks::new(body).unwrap(), CAP);
                assert_eq!(head.data, expected, "{sizes:?}, {len}");
                assert_eq!(head.cut, len > CAP, "{sizes:?}, {len}");
            }
        }
        // The framing of a first chunk longer than the cap is still read:
        // broken, the body is not chunked.
        let mut broken = format!("{:x}\r\n", CAP + 1).into_bytes();
        broken.extend_from_slice(&data[..CAP + 1]);
        broken.push(b'X');
        assert!(Chunks::new(&broken).is_none());
        assert!(matches!(decode_body(&broken), Cow::Borrowed(b) if b == &broken[..]));
    }

    #[test]
    fn chunked_compressed_bodies_past_the_cap() {
        // The first 1 MiB of the stream inflates past the cap.
        let mut data = vec![b'a'; 2 * MAX_DECODED_BODY_LEN];
        data.extend_from_slice(&noise(2 * MAX_DECODED_BODY_LEN));
        // The first 1 MiB of the stream does not reach the cap.
        let dense = noise(3 * MAX_DECODED_BODY_LEN);
        for data in [&data, &dense] {
            for packed in [gzip(data), zlib(data), deflate(data)] {
                assert!(packed.len() > MAX_DECODED_BODY_LEN);
                let pieces: Vec<&[u8]> = packed.chunks(100_000).collect();
                let body = chunk(&pieces);
                assert_eq!(&*decode_body(&body), &data[..MAX_DECODED_BODY_LEN]);
                // Cut short, the same.
                let cut = &body[..body.len() / 2];
                assert_eq!(&*decode_body(cut), &data[..MAX_DECODED_BODY_LEN]);
            }
        }
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
