//! Bitcoin wire protocol: envelope, CompactSize, and message (de)serialization.
//! This section (spec Section 4) is the Bitcoin wire format and is implemented
//! exactly.

use crate::address::{classify, NetworkType};
use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};

/// Mainnet network magic (Section 4.1).
pub const MAGIC: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9];

/// Maximum accepted payload length: 4 MiB (Section 4.1).
pub const MAX_PROTOCOL_MESSAGE_LENGTH: u32 = 4 * 1024 * 1024;

/// Bitcoin Core's `MAX_ADDR_TO_SEND` (Section 3.3 early-exit).
pub const MAX_ADDR_TO_SEND: usize = 1000;

/// Protocol version advertised by the crawler (Section 4.3).
pub const PROTOCOL_VERSION: i32 = 70016;
/// User agent advertised by the crawler (Section 4.3).
pub const USER_AGENT: &str = "/Satoshi:27.0.0/";

/// Double-SHA256, returning the first 4 bytes (the envelope checksum).
pub fn checksum(payload: &[u8]) -> [u8; 4] {
    let first = Sha256::digest(payload);
    let second = Sha256::digest(first);
    [second[0], second[1], second[2], second[3]]
}

/// Serialize a full message envelope (header + payload) for `command`.
pub fn frame(command: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + payload.len());
    out.extend_from_slice(&MAGIC);
    let mut cmd = [0u8; 12];
    let bytes = command.as_bytes();
    cmd[..bytes.len()].copy_from_slice(bytes);
    out.extend_from_slice(&cmd);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&checksum(payload));
    out.extend_from_slice(payload);
    out
}

// ---------------------------------------------------------------------------
// CompactSize (Section 4.3.0)
// ---------------------------------------------------------------------------

/// Encode a value in minimal CompactSize form.
pub fn write_compact_size(out: &mut Vec<u8>, value: u64) {
    if value <= 0xFC {
        out.push(value as u8);
    } else if value <= 0xFFFF {
        out.push(0xFD);
        out.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0xFFFF_FFFF {
        out.push(0xFE);
        out.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        out.push(0xFF);
        out.extend_from_slice(&value.to_le_bytes());
    }
}

/// A cursor over a byte slice for defensive parsing; short reads yield `None`.
pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Some(slice)
    }

    pub fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    pub fn u16_le(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn u16_be(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32_le(&mut self) -> Option<u32> {
        let b = self.take(4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn i32_le(&mut self) -> Option<i32> {
        Some(self.u32_le()? as i32)
    }

    pub fn u64_le(&mut self) -> Option<u64> {
        let b = self.take(8)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(b);
        Some(u64::from_le_bytes(arr))
    }

    pub fn i64_le(&mut self) -> Option<i64> {
        Some(self.u64_le()? as i64)
    }

    /// Decode a CompactSize (minimality not enforced on decode, Section 4.3.0).
    pub fn compact_size(&mut self) -> Option<u64> {
        match self.u8()? {
            0xFF => self.u64_le(),
            0xFE => self.u32_le().map(|v| v as u64),
            0xFD => self.u16_le().map(|v| v as u64),
            n => Some(n as u64),
        }
    }
}

// ---------------------------------------------------------------------------
// version message (Section 4.3, 4.4)
// ---------------------------------------------------------------------------

/// Fields retained from a peer's `version` message (Section 4.4).
#[derive(Debug, Clone)]
pub struct VersionData {
    pub version: i32,
    pub services: u64,
    pub timestamp: i64,
    pub user_agent: String,
    pub latest_block: i32,
    pub relay: bool,
}

/// Serialize the crawler's own `version` payload (Section 4.3).
pub fn build_version(timestamp: i64, nonce: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes()); // version
    out.extend_from_slice(&0u64.to_le_bytes()); // services = 0
    out.extend_from_slice(&timestamp.to_le_bytes()); // timestamp
    // addr_recv: services(8) + IP(16 = ::ffff:0.0.0.0) + port(2 BE)
    write_zero_netaddr(&mut out);
    // addr_from: same
    write_zero_netaddr(&mut out);
    out.extend_from_slice(&nonce.to_le_bytes()); // nonce
    write_compact_size(&mut out, USER_AGENT.len() as u64);
    out.extend_from_slice(USER_AGENT.as_bytes());
    out.extend_from_slice(&0i32.to_le_bytes()); // start_height = 0
    out.push(0x00); // relay = false
    out
}

fn write_zero_netaddr(out: &mut Vec<u8>) {
    out.extend_from_slice(&0u64.to_le_bytes()); // services
    // ::ffff:0.0.0.0
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0]);
    out.extend_from_slice(&0u16.to_be_bytes()); // port
}

/// Parse a peer's `version` payload (Section 4.4). Returns `None` on truncation.
pub fn parse_version(payload: &[u8]) -> Option<VersionData> {
    let mut c = Cursor::new(payload);
    let version = c.i32_le()?;
    let services = c.u64_le()?;
    let timestamp = c.i64_le()?;
    // addr_recv (26 bytes): services(8) + IP(16) + port(2)
    c.take(26)?;

    let mut user_agent = String::new();
    let mut latest_block = 0i32;
    // Absent relay is recorded as true (Core convention, Section 4.3/4.4).
    let mut relay = true;

    // addr_from..user_agent..latest_block requires version >= 106.
    if version >= 106 {
        c.take(26)?; // addr_from
        c.take(8)?; // nonce
        let ua_len = c.compact_size()? as usize;
        let ua_bytes = c.take(ua_len)?;
        user_agent = match std::str::from_utf8(ua_bytes) {
            Ok(s) => s.to_string(),
            Err(_) => hex(ua_bytes),
        };
        latest_block = c.i32_le()?;

        // relay requires version >= 70001; absent => true.
        if version >= 70001 {
            if let Some(byte) = c.u8() {
                relay = byte != 0;
            }
        }
    }

    Some(VersionData {
        version,
        services,
        timestamp,
        user_agent,
        latest_block,
        relay,
    })
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---------------------------------------------------------------------------
// addr / addrv2 parsing (Section 4.3)
// ---------------------------------------------------------------------------

/// A single advertised address from an `addr`/`addrv2` response.
#[derive(Debug, Clone)]
pub struct AdvertisedAddr {
    pub host: String,
    pub port: u16,
    pub network: NetworkType,
    /// Literal last-seen timestamp from the response, zero-extended (Section 4.3).
    pub timestamp: i64,
}

/// Parse a legacy `addr` payload (Section 4.3). Defensive: returns what was
/// decoded before any truncation. A truncated count returns empty.
pub fn parse_addr(payload: &[u8]) -> Vec<AdvertisedAddr> {
    let mut c = Cursor::new(payload);
    let count = match c.compact_size() {
        Some(n) => n,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for _ in 0..count {
        let ts = match c.u32_le() {
            Some(t) => t as i64, // zero-extend (unsigned)
            None => break,
        };
        if c.take(8).is_none() {
            break;
        } // services, discarded
        let ip = match c.take(16) {
            Some(b) => b,
            None => break,
        };
        let port = match c.u16_be() {
            Some(p) => p,
            None => break,
        };
        let mut arr = [0u8; 16];
        arr.copy_from_slice(ip);
        let (host, network) = decode_ipv6_mapped(&arr);
        out.push(AdvertisedAddr {
            host,
            port,
            network,
            timestamp: ts,
        });
    }
    out
}

/// Parse a BIP155 `addrv2` payload (Section 4.3). Defensive: stops on truncation,
/// unknown net id, or length mismatch, returning what was decoded so far.
pub fn parse_addrv2(payload: &[u8]) -> Vec<AdvertisedAddr> {
    let mut c = Cursor::new(payload);
    let count = match c.compact_size() {
        Some(n) => n,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for _ in 0..count {
        let ts = match c.u32_le() {
            Some(t) => t as i64,
            None => break,
        };
        if c.compact_size().is_none() {
            break;
        } // services, discarded
        let net_id = match c.u8() {
            Some(n) => n,
            None => break,
        };
        let addr_len = match c.compact_size() {
            Some(l) => l as usize,
            None => break,
        };
        // Expected fixed length per net id (Section 4.3).
        let expected = match net_id {
            1 => 4,
            2 => 16,
            3 => 10,
            4 => 32,
            5 => 32,
            6 => 16,
            _ => {
                // Unknown net id: parsing stops (defensive).
                break;
            }
        };
        if addr_len != expected {
            break; // length mismatch: stop (defensive)
        }
        let addr_bytes = match c.take(addr_len) {
            Some(b) => b,
            None => break,
        };
        let port = match c.u16_be() {
            Some(p) => p,
            None => break,
        };
        let (host, network) = match decode_addrv2(net_id, addr_bytes) {
            Some(v) => v,
            None => break,
        };
        out.push(AdvertisedAddr {
            host,
            port,
            network,
            timestamp: ts,
        });
    }
    out
}

/// Decode a 16-byte IPv6 field, collapsing IPv4-mapped to dotted quad.
fn decode_ipv6_mapped(arr: &[u8; 16]) -> (String, NetworkType) {
    let addr = std::net::Ipv6Addr::from(*arr);
    if let Some(v4) = ipv4_mapped(&addr) {
        (v4.to_string(), NetworkType::Ipv4)
    } else if arr[0] == 0xfc {
        (compact_ipv6(&addr), NetworkType::Cjdns)
    } else {
        (compact_ipv6(&addr), NetworkType::Ipv6)
    }
}

fn ipv4_mapped(addr: &std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    let o = addr.octets();
    if o[..10].iter().all(|&b| b == 0) && o[10] == 0xff && o[11] == 0xff {
        Some(std::net::Ipv4Addr::new(o[12], o[13], o[14], o[15]))
    } else {
        None
    }
}

fn compact_ipv6(addr: &std::net::Ipv6Addr) -> String {
    addr.to_string()
}

fn decode_addrv2(net_id: u8, bytes: &[u8]) -> Option<(String, NetworkType)> {
    match net_id {
        1 => {
            let v4 = std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
            Some((v4.to_string(), NetworkType::Ipv4))
        }
        2 => {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(bytes);
            Some(decode_ipv6_mapped(&arr))
        }
        3 => {
            // torv2: base32(10 bytes) + .onion (defunct, kept for completeness)
            let label = BASE32_NOPAD.encode(bytes).to_lowercase();
            Some((format!("{label}.onion"), NetworkType::OnionV2))
        }
        4 => {
            // torv3: label = base32(pubkey || checksum || 0x03)
            let host = encode_onion_v3(bytes)?;
            Some((host, NetworkType::OnionV3))
        }
        5 => {
            // i2p: base32(32 bytes) => 56 chars, strip padding, + .b32.i2p
            let label = BASE32_NOPAD.encode(bytes).to_lowercase();
            Some((format!("{label}.b32.i2p"), NetworkType::I2p))
        }
        6 => {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(bytes);
            let addr = std::net::Ipv6Addr::from(arr);
            Some((compact_ipv6(&addr), NetworkType::Cjdns))
        }
        _ => None,
    }
}

/// Encode a torv3 ed25519 pubkey into its `.onion` address (Section 4.3).
fn encode_onion_v3(pubkey: &[u8]) -> Option<String> {
    if pubkey.len() != 32 {
        return None;
    }
    use sha3::Sha3_256;
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pubkey);
    hasher.update([0x03]);
    let digest = hasher.finalize();
    let checksum = &digest[..2];

    let mut data = Vec::with_capacity(35);
    data.extend_from_slice(pubkey);
    data.extend_from_slice(checksum);
    data.push(0x03);
    let label = BASE32_NOPAD.encode(&data).to_lowercase();
    // Sanity: classify() also verifies this is a 56-char label.
    debug_assert_eq!(label.len(), 56);
    let host = format!("{label}.onion");
    debug_assert_eq!(classify(&host), NetworkType::OnionV3);
    Some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_size_roundtrip() {
        for v in [0u64, 0xFC, 0xFD, 0xFFFF, 0x1_0000, 0xFFFF_FFFF, 0x1_0000_0000] {
            let mut buf = Vec::new();
            write_compact_size(&mut buf, v);
            let mut c = Cursor::new(&buf);
            assert_eq!(c.compact_size(), Some(v));
        }
    }

    #[test]
    fn version_roundtrip() {
        let payload = build_version(1_720_000_000, 0xdead_beef);
        let v = parse_version(&payload).unwrap();
        assert_eq!(v.version, PROTOCOL_VERSION);
        assert_eq!(v.services, 0);
        assert_eq!(v.user_agent, USER_AGENT);
        assert_eq!(v.latest_block, 0);
        assert!(!v.relay);
    }

    #[test]
    fn absent_relay_is_true() {
        // Build a version at exactly the boundary with no relay byte.
        let mut p = build_version(1, 2);
        p.pop(); // remove relay byte
        let v = parse_version(&p).unwrap();
        assert!(v.relay);
    }

    #[test]
    fn addr_timestamp_zero_extends() {
        // Build one addr record with a high-bit timestamp.
        let mut payload = Vec::new();
        write_compact_size(&mut payload, 1);
        payload.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // timestamp
        payload.extend_from_slice(&0u64.to_le_bytes()); // services
        payload.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 1, 2, 3, 4]);
        payload.extend_from_slice(&8333u16.to_be_bytes());
        let addrs = parse_addr(&payload);
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].timestamp, 0xFFFF_FFFF); // zero-extended, not -1
        assert_eq!(addrs[0].host, "1.2.3.4");
        assert_eq!(addrs[0].network, NetworkType::Ipv4);
    }

    #[test]
    fn addrv2_torv3_roundtrips_through_classify() {
        let pubkey = [7u8; 32];
        let mut payload = Vec::new();
        write_compact_size(&mut payload, 1);
        payload.extend_from_slice(&0u32.to_le_bytes()); // ts
        write_compact_size(&mut payload, 0); // services
        payload.push(4); // net id torv3
        write_compact_size(&mut payload, 32); // addr len
        payload.extend_from_slice(&pubkey);
        payload.extend_from_slice(&8333u16.to_be_bytes());
        let addrs = parse_addrv2(&payload);
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].network, NetworkType::OnionV3);
        assert_eq!(classify(&addrs[0].host), NetworkType::OnionV3);
    }

    #[test]
    fn addrv2_length_mismatch_stops() {
        let mut payload = Vec::new();
        write_compact_size(&mut payload, 1);
        payload.extend_from_slice(&0u32.to_le_bytes());
        write_compact_size(&mut payload, 0);
        payload.push(1); // ipv4
        write_compact_size(&mut payload, 16); // wrong length
        payload.extend_from_slice(&[0u8; 16]);
        payload.extend_from_slice(&8333u16.to_be_bytes());
        assert!(parse_addrv2(&payload).is_empty());
    }
}
