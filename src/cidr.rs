//! IP address ranges in CIDR notation.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// An IP address range written in CIDR notation, such as `10.0.0.0/8` or
/// `2001:db8::/32`.
///
/// A bare address is a range of that one address. Host bits below the
/// prefix are cleared, so `10.1.2.3/8` is the same range as `10.0.0.0/8`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

/// An error parsing a [`Cidr`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} is not an IP address range in CIDR notation")]
pub struct CidrParseError(String);

impl Cidr {
    /// Creates a range from an address and a prefix length, clearing the
    /// host bits of the address.
    ///
    /// # Errors
    ///
    /// Returns an error if `prefix` is longer than the address (32 bits for
    /// IPv4, 128 for IPv6).
    pub fn new(addr: IpAddr, prefix: u8) -> Result<Self, CidrParseError> {
        let network = match addr {
            IpAddr::V4(v4) => {
                if prefix > 32 {
                    return Err(CidrParseError(format!("{addr}/{prefix}")));
                }
                let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
                IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask))
            }
            IpAddr::V6(v6) => {
                if prefix > 128 {
                    return Err(CidrParseError(format!("{addr}/{prefix}")));
                }
                let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
                IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
            }
        };
        Ok(Self { network, prefix })
    }

    /// Returns the first address of the range.
    #[must_use]
    pub fn network(&self) -> IpAddr {
        self.network
    }

    /// Returns the prefix length.
    #[must_use]
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Returns whether `addr` lies in the range.
    ///
    /// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is compared as the
    /// IPv4 address it maps.
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.network, addr.to_canonical()) {
            (IpAddr::V4(_), a @ IpAddr::V4(_)) | (IpAddr::V6(_), a @ IpAddr::V6(_)) => {
                Self::new(a, self.prefix).is_ok_and(|masked| masked.network == self.network)
            }
            _ => false,
        }
    }
}

impl FromStr for Cidr {
    type Err = CidrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || CidrParseError(s.to_string());
        let (addr, prefix) = match s.split_once('/') {
            Some((addr, prefix)) => {
                if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(err());
                }
                (addr, Some(prefix.parse::<u8>().map_err(|_| err())?))
            }
            None => (s, None),
        };
        let addr: IpAddr = addr.parse().map_err(|_| err())?;
        let prefix = prefix.unwrap_or(match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        });
        Self::new(addr, prefix).map_err(|_| err())
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

impl Serialize for Cidr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Cidr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_contains() {
        let net: Cidr = "10.1.2.3/8".parse().unwrap();
        assert_eq!(net.to_string(), "10.0.0.0/8");
        assert!(net.contains("10.200.0.1".parse().unwrap()));
        assert!(net.contains("::ffff:10.0.0.1".parse().unwrap()));
        assert!(!net.contains("11.0.0.1".parse().unwrap()));
        assert!(!net.contains("::1".parse().unwrap()));

        let host: Cidr = "192.168.0.1".parse().unwrap();
        assert_eq!(host.prefix(), 32);
        assert!(host.contains("192.168.0.1".parse().unwrap()));
        assert!(!host.contains("192.168.0.2".parse().unwrap()));

        let all: Cidr = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains("1.2.3.4".parse().unwrap()));

        let v6: Cidr = "2001:db8::/32".parse().unwrap();
        assert!(v6.contains("2001:db8:1::1".parse().unwrap()));
        assert!(!v6.contains("2001:db9::1".parse().unwrap()));

        for bad in [
            "10.0.0.0/33",
            "10.0.0.0/",
            "10.0.0.0/+8",
            "x/8",
            "",
            "::/129",
        ] {
            assert!(bad.parse::<Cidr>().is_err(), "{bad}");
        }
    }
}
