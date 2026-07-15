//! Address classification and network types (Section 4.2, 4.2.1 address detection).

use std::fmt;
use std::net::Ipv6Addr;

use data_encoding::BASE32_NOPAD;
use sha3::{Digest, Sha3_256};

/// The network type an address is classified into (Section 2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkType {
    Ipv4,
    Ipv6,
    Cjdns,
    OnionV2,
    OnionV3,
    I2p,
    Unknown,
}

impl NetworkType {
    /// The lowercase identifier used in outputs.
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkType::Ipv4 => "ipv4",
            NetworkType::Ipv6 => "ipv6",
            NetworkType::Cjdns => "cjdns",
            NetworkType::OnionV2 => "onion_v2",
            NetworkType::OnionV3 => "onion_v3",
            NetworkType::I2p => "i2p",
            NetworkType::Unknown => "unknown",
        }
    }

    /// The transport family that carries this network type (Section 3.5).
    pub fn transport(self) -> Transport {
        match self {
            NetworkType::Ipv4 | NetworkType::Ipv6 | NetworkType::Cjdns => Transport::Ip,
            NetworkType::OnionV2 | NetworkType::OnionV3 => Transport::Tor,
            NetworkType::I2p => Transport::I2p,
            NetworkType::Unknown => Transport::Ip, // never actually connected
        }
    }
}

impl fmt::Display for NetworkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A transport family with its own work queue and worker pool (Section 3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    Ip,
    Tor,
    I2p,
}

/// Classify a host string into a [`NetworkType`] (Section 4.2 address detection).
pub fn classify(host: &str) -> NetworkType {
    // IPv6-form (contains a colon): parse into an Ipv6Addr and test fc00::/8.
    if host.contains(':') {
        return match host.parse::<Ipv6Addr>() {
            Ok(addr) => {
                if addr.octets()[0] == 0xfc {
                    NetworkType::Cjdns
                } else {
                    NetworkType::Ipv6
                }
            }
            Err(_) => NetworkType::Unknown,
        };
    }

    if let Some(label) = host.strip_suffix(".onion") {
        if label.len() == 16 && decode_base32(label, 10).is_some() {
            return NetworkType::OnionV2;
        }
        if label.len() == 56 && valid_onion_v3(label) {
            return NetworkType::OnionV3;
        }
        return NetworkType::Unknown;
    }

    if let Some(label) = host.strip_suffix(".b32.i2p") {
        return if label.len() == 52 && decode_base32(label, 32).is_some() {
            NetworkType::I2p
        } else {
            NetworkType::Unknown
        };
    }

    // Four dotted octets each in [0, 256).
    if is_ipv4_dotted(host) {
        return NetworkType::Ipv4;
    }

    NetworkType::Unknown
}

fn decode_base32(label: &str, expected_len: usize) -> Option<Vec<u8>> {
    if label
        .bytes()
        .any(|b| !matches!(b, b'a'..=b'z' | b'2'..=b'7'))
    {
        return None;
    }
    let upper = label.to_ascii_uppercase();
    BASE32_NOPAD
        .decode(upper.as_bytes())
        .ok()
        .filter(|bytes| bytes.len() == expected_len)
}

fn valid_onion_v3(label: &str) -> bool {
    let Some(decoded) = decode_base32(label, 35) else {
        return false;
    };
    if decoded[34] != 3 {
        return false;
    }
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(&decoded[..32]);
    hasher.update([3]);
    let digest = hasher.finalize();
    decoded[32..34] == digest[..2]
}

fn is_ipv4_dotted(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| {
        !p.is_empty()
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u32>().map(|n| n < 256).unwrap_or(false)
    })
}

/// Render a host:port as a string, bracketing IPv6/CJDNS hosts (Section 4.2).
pub fn render_addr(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_ipv4() {
        assert_eq!(classify("192.0.2.5"), NetworkType::Ipv4);
        assert_eq!(classify("255.255.255.255"), NetworkType::Ipv4);
        assert_eq!(classify("256.0.0.1"), NetworkType::Unknown);
        assert_eq!(classify("1.2.3"), NetworkType::Unknown);
    }

    #[test]
    fn classifies_ipv6_and_cjdns() {
        assert_eq!(classify("2001:db8::1"), NetworkType::Ipv6);
        assert_eq!(classify("fc00::1"), NetworkType::Cjdns);
        // Uppercase / zero-compressed must still be detected via parsing.
        assert_eq!(classify("FC00::1"), NetworkType::Cjdns);
        assert_eq!(classify("not:valid:ipv6:::"), NetworkType::Unknown);
    }

    #[test]
    fn classifies_onion_and_i2p() {
        let invalid_v3 = format!("{}.onion", "a".repeat(56));
        assert_eq!(classify(&invalid_v3), NetworkType::Unknown);
        let v2 = format!("{}.onion", "a".repeat(16));
        assert_eq!(classify(&v2), NetworkType::OnionV2);
        let i2p = format!("{}.b32.i2p", "a".repeat(52));
        assert_eq!(classify(&i2p), NetworkType::I2p);
        assert_eq!(
            classify(&format!("{}.onion", "0".repeat(16))),
            NetworkType::Unknown
        );
        assert_eq!(
            classify(&format!("{}.b32.i2p", "!".repeat(52))),
            NetworkType::Unknown
        );
    }

    #[test]
    fn renders_bracketed() {
        assert_eq!(render_addr("2001:db8::1", 8333), "[2001:db8::1]:8333");
        assert_eq!(render_addr("192.0.2.5", 8333), "192.0.2.5:8333");
    }
}
