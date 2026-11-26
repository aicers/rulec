//! Derived field values: certificate names, request header strings and
//! SSH banner parts.

/// The request headers whose values a [`header_block`] fills in from an
/// `Http` record, by the names Suricata's `http.header` buffer shows.
///
/// A header not in this list gets an empty value in the block. `Cookie` is
/// not here even though the record holds its value: Suricata leaves it out
/// of `http.header`, and so does [`header_block`].
pub const HEADER_BLOCK_HEADERS: [&str; 11] = [
    "Host",
    "User-Agent",
    "Referer",
    "Content-Type",
    "Content-Encoding",
    "Cache-Control",
    "Accept",
    "Connection",
    "Accept-Encoding",
    "Accept-Language",
    "Pragma",
];

/// The request header [`header_block`] leaves out, as Suricata 7.0.3 does.
const EXCLUDED_HEADER: &[u8] = b"cookie";

/// Joins the parts of a certificate's distinguished name as
/// `C=…, O=…, OU=…, CN=…`, in that order, skipping empty parts.
///
/// The values go in as they are, without escaping. Returns `None` if every
/// part is empty. A subject, which a `Tls` record holds no organizational
/// unit for, passes an empty `org_unit`.
#[must_use]
pub fn join_cert_name(
    country: &[u8],
    org: &[u8],
    org_unit: &[u8],
    common_name: &[u8],
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for (label, value) in [
        (&b"C="[..], country),
        (b"O=", org),
        (b"OU=", org_unit),
        (b"CN=", common_name),
    ] {
        if value.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.extend_from_slice(b", ");
        }
        out.extend_from_slice(label);
        out.extend_from_slice(value);
    }
    (!out.is_empty()).then_some(out)
}

/// Joins request header names as Suricata's `http.header_names` buffer
/// does: `\r\n`, the names separated by `\r\n`, then `\r\n\r\n`.
///
/// Returns `None` for no names.
#[must_use]
pub fn join_header_names<N: AsRef<[u8]>>(names: &[N]) -> Option<Vec<u8>> {
    if names.is_empty() {
        return None;
    }
    let mut out = b"\r\n".to_vec();
    for name in names {
        out.extend_from_slice(name.as_ref());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    Some(out)
}

/// Builds a request header block like Suricata 7.0.3's `http.header`
/// buffer: one `<name>: <value>\r\n` line for each name, in order.
///
/// Each name is written in the case `names` has it. Its value is that of
/// the first entry of `values` whose name equals it, ignoring ASCII case,
/// or empty if there is none; a name that appears more than once gets the
/// same value on each line. As Suricata does (`src/detect-http-header.c`,
/// `GetBufferForTX`), a `Cookie` header gets no line at all, and the block
/// ends with the last header's line, with no blank line after it. Returns
/// `None` if no line is written: for no names, or only `Cookie`, Suricata
/// has no buffer.
///
/// For an `Http` record, `values` holds the headers of
/// [`HEADER_BLOCK_HEADERS`] with the record's values.
#[must_use]
pub fn header_block<N: AsRef<[u8]>>(names: &[N], values: &[(&str, &[u8])]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for name in names {
        let name = name.as_ref();
        if name.eq_ignore_ascii_case(EXCLUDED_HEADER) {
            continue;
        }
        let value = values
            .iter()
            .find(|(known, _)| known.as_bytes().eq_ignore_ascii_case(name))
            .map_or(&[][..], |(_, value)| value);
        out.extend_from_slice(name);
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }
    (!out.is_empty()).then_some(out)
}

/// The protocol version and software version of an SSH banner
/// (`SSH-<proto>-<software>[ <comments>]`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SshBanner<'a> {
    proto: &'a [u8],
    software: Option<&'a [u8]>,
}

impl<'a> SshBanner<'a> {
    /// Returns the protocol version, such as `2.0`; never empty.
    #[must_use]
    pub fn proto(&self) -> &'a [u8] {
        self.proto
    }

    /// Returns the software version, such as `OpenSSH_8.9p1`, or `None` if
    /// the banner has none.
    #[must_use]
    pub fn software(&self) -> Option<&'a [u8]> {
        self.software
    }
}

/// Splits an SSH banner into its protocol and software versions as
/// Suricata 7.0.3 does (`rust/src/ssh/parser.rs`, `ssh_parse_banner`, on
/// the line `ssh_parse_line` frames).
///
/// The banner is read up to its first CR or LF. It must start with `SSH-`,
/// followed by the protocol version — one or more bytes up to the next
/// `-` — and that `-`. The software version is what follows up to the
/// first space. If what follows is empty or starts with a space, Suricata
/// takes all of it as the software version instead; empty, there is no
/// software version, as Suricata then keeps none. So
/// `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3` is `2.0` and `OpenSSH_8.9p1`, and
/// `SSH-2.0-` is `2.0` with no software version.
///
/// Returns `None` if the banner is not of that form.
#[must_use]
pub fn split_ssh_banner(banner: &[u8]) -> Option<SshBanner<'_>> {
    let line_len = banner
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(banner.len());
    let line = banner.get(..line_len).unwrap_or_default();
    let rest = line.strip_prefix(b"SSH-")?;
    let dash = rest.iter().position(|&b| b == b'-')?;
    if dash == 0 {
        return None;
    }
    let (proto, rest) = rest.split_at(dash);
    let rest = rest.get(1..).unwrap_or_default();
    let software = match rest.iter().position(|&b| b == b' ') {
        Some(0) | None => rest,
        Some(space) => rest.get(..space).unwrap_or(rest),
    };
    Some(SshBanner {
        proto,
        software: (!software.is_empty()).then_some(software),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_names() {
        assert_eq!(
            join_cert_name(b"US", b"Example Org", b"Unit", b"example.com").unwrap(),
            b"C=US, O=Example Org, OU=Unit, CN=example.com"
        );
        assert_eq!(
            join_cert_name(b"", b"Org, Inc.", b"", b"a=b").unwrap(),
            b"O=Org, Inc., CN=a=b"
        );
        assert_eq!(join_cert_name(b"KR", b"", b"", b"").unwrap(), b"C=KR");
        assert_eq!(join_cert_name(b"", b"", b"", b""), None);
    }

    #[test]
    fn header_names() {
        assert_eq!(
            join_header_names(&["Host", "User-Agent"]).unwrap(),
            b"\r\nHost\r\nUser-Agent\r\n\r\n"
        );
        assert_eq!(join_header_names::<&str>(&[]), None);
    }

    #[test]
    fn header_blocks() {
        let values: &[(&str, &[u8])] = &[("Host", b"example.com"), ("Accept", b"*/*")];
        assert_eq!(
            header_block(&["host", "X-Odd", "ACCEPT", "Host", "Cookie"], values).unwrap(),
            b"host: example.com\r\nX-Odd: \r\nACCEPT: */*\r\nHost: example.com\r\n"
        );
        assert_eq!(header_block(&["cookie", "COOKIE"], values), None);
        assert_eq!(header_block::<&str>(&[], values), None);
    }

    #[test]
    fn ssh_banners() {
        let split = |b: &'static [u8]| split_ssh_banner(b).map(|s| (s.proto(), s.software()));
        assert_eq!(
            split(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"),
            Some((&b"2.0"[..], Some(&b"OpenSSH_8.9p1"[..])))
        );
        assert_eq!(
            split(b"SSH-2.0-OpenSSH_8.9p1"),
            Some((&b"2.0"[..], Some(&b"OpenSSH_8.9p1"[..])))
        );
        assert_eq!(
            split(b"SSH-1.99-Cisco-1.25"),
            Some((&b"1.99"[..], Some(&b"Cisco-1.25"[..])))
        );
        assert_eq!(
            split(b"SSH-2.0-libssh\r\n"),
            Some((&b"2.0"[..], Some(&b"libssh"[..])))
        );
        assert_eq!(split(b"SSH-2.0-"), Some((&b"2.0"[..], None)));
        assert_eq!(
            split(b"SSH-2.0- comment"),
            Some((&b"2.0"[..], Some(&b" comment"[..])))
        );
        assert_eq!(split(b"SSH-Single-"), Some((&b"Single"[..], None)));
        for bad in [
            &b"OpenSSH_8.9"[..],
            b"ssh-2.0-x",
            b"SSH-",
            b"SSH--x",
            b"SSH-2.0",
            b"",
            b"\r\nSSH-2.0-x",
        ] {
            assert_eq!(split_ssh_banner(bad), None, "{bad:?}");
        }
    }
}
