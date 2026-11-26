//! What the engine reads from one raw event.

use std::{borrow::Cow, net::IpAddr};

use giganto_client::{RawEventKind, ingest::endpoint::OsFamily};

/// One raw event as the engine sees it.
///
/// The engine reads an event only through this trait. Field names are the
/// column names of the `giganto-client` record and the derived field names
/// the implementation defines (such as `uri.normalized`); the engine does
/// not interpret them and compares them with a rule's field names as they
/// are.
pub trait Event {
    /// Returns the kind of the raw event.
    fn kind(&self) -> RawEventKind;

    /// Returns the values of the field `name`.
    ///
    /// A field may have several values (a list of header names, say). A
    /// field the event does not have returns no values; an empty value is a
    /// value, and differs from no value. The connection fields `orig_addr`
    /// and `resp_addr` return [`FieldValue::Addr`], and `orig_port` and
    /// `resp_port` return [`FieldValue::Int`].
    fn field(&self, name: &str) -> Vec<FieldValue<'_>>;

    /// Returns the OS family in the event's host header, or `None` for a
    /// record without one (a network record, say).
    fn os_family(&self) -> Option<&OsFamily>;
}

/// One value of an event's field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldValue<'a> {
    /// A byte string.
    Bytes(Cow<'a, [u8]>),
    /// An IP address.
    Addr(IpAddr),
    /// An integer, such as a port.
    Int(i64),
}

impl FieldValue<'_> {
    /// Returns the value as bytes: a byte string as it is, an address or an
    /// integer as its text.
    #[must_use]
    pub fn as_bytes(&self) -> Cow<'_, [u8]> {
        match self {
            Self::Bytes(b) => Cow::Borrowed(b.as_ref()),
            Self::Addr(a) => Cow::Owned(a.to_string().into_bytes()),
            Self::Int(i) => Cow::Owned(i.to_string().into_bytes()),
        }
    }

    /// Returns the value read as a decimal integer, if it is one.
    pub(crate) fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(i) => Some(*i),
            Self::Bytes(b) => std::str::from_utf8(b).ok()?.parse().ok(),
            Self::Addr(_) => None,
        }
    }

    /// Returns the value read as an IP address, if it is one.
    pub(crate) fn as_addr(&self) -> Option<IpAddr> {
        match self {
            Self::Addr(a) => Some(*a),
            Self::Bytes(b) => std::str::from_utf8(b).ok()?.parse().ok(),
            Self::Int(_) => None,
        }
    }

    /// Returns the length of the value in bytes, as [`Self::as_bytes`]
    /// gives it.
    pub(crate) fn byte_len(&self) -> usize {
        match self {
            Self::Bytes(b) => b.len(),
            Self::Addr(_) | Self::Int(_) => self.as_bytes().len(),
        }
    }
}

impl<'a> From<&'a [u8]> for FieldValue<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self::Bytes(Cow::Borrowed(value))
    }
}

impl<'a> From<&'a str> for FieldValue<'a> {
    fn from(value: &'a str) -> Self {
        Self::Bytes(Cow::Borrowed(value.as_bytes()))
    }
}

impl From<Vec<u8>> for FieldValue<'_> {
    fn from(value: Vec<u8>) -> Self {
        Self::Bytes(Cow::Owned(value))
    }
}

impl From<IpAddr> for FieldValue<'_> {
    fn from(value: IpAddr) -> Self {
        Self::Addr(value)
    }
}

impl From<i64> for FieldValue<'_> {
    fn from(value: i64) -> Self {
        Self::Int(value)
    }
}
