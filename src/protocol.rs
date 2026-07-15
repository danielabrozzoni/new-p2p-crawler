//! Bitcoin wire protocol: envelope, CompactSize, and message (de)serialization.
//! This section (spec Section 4) is the Bitcoin wire format and is implemented
//! exactly.

use crate::address::{classify, NetworkType};
use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};

/// Mainnet network magic (Section 4.1).
pub const MAGIC: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9];

/// Bitcoin Core's exact maximum protocol payload size.
pub const MAX_PROTOCOL_MESSAGE_LENGTH: u32 = 4_000_000;

/// Bitcoin Core's `MAX_ADDR_TO_SEND` (Section 3.3 early-exit).
pub const MAX_ADDR_TO_SEND: usize = 1000;

/// Protocol version advertised by the crawler (Section 4.3).
pub const PROTOCOL_VERSION: i32 = 70016;
/// User agent advertised by the crawler (Section 4.3).
pub const USER_AGENT: &str = "/new-p2p-crawler:0.1.0/";
/// Bitcoin Core's maximum accepted subversion/user-agent string length.
pub const MAX_SUBVERSION_LENGTH: usize = 256;

/// Double-SHA256, returning the first 4 bytes (the envelope checksum).
pub fn checksum(payload: &[u8]) -> [u8; 4] {
    let first = Sha256::digest(payload);
    let second = Sha256::digest(first);
    [second[0], second[1], second[2], second[3]]
}

/// Serialize a full message envelope (header + payload) for `command`.
pub fn frame(command: &str, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    validate_command(command)?;
    let payload_len: u32 = payload
        .len()
        .try_into()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "payload too large"))?;
    if payload_len > MAX_PROTOCOL_MESSAGE_LENGTH {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "payload exceeds protocol limit",
        ));
    }
    let mut out = Vec::with_capacity(24 + payload.len());
    out.extend_from_slice(&MAGIC);
    let mut cmd = [0u8; 12];
    let bytes = command.as_bytes();
    cmd[..bytes.len()].copy_from_slice(bytes);
    out.extend_from_slice(&cmd);
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(&checksum(payload));
    out.extend_from_slice(payload);
    Ok(out)
}

fn validate_command(command: &str) -> std::io::Result<()> {
    let bytes = command.as_bytes();
    if bytes.is_empty() || bytes.len() > 12 || bytes.iter().any(|b| !(0x20..=0x7e).contains(b)) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "command must be 1..=12 printable ASCII bytes",
        ));
    }
    Ok(())
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

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
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

    /// Decode CompactSize without imposing caller-specific minimality policy.
    pub fn compact_size(&mut self) -> Option<u64> {
        match self.u8()? {
            0xFF => self.u64_le(),
            0xFE => self.u32_le().map(|v| v as u64),
            0xFD => self.u16_le().map(|v| v as u64),
            n => Some(n as u64),
        }
    }

    pub fn compact_size_canonical(&mut self) -> Option<u64> {
        let prefix = self.u8()?;
        let value = match prefix {
            0xFF => self.u64_le()?,
            0xFE => self.u32_le()? as u64,
            0xFD => self.u16_le()? as u64,
            n => n as u64,
        };
        match prefix {
            0xFF if value <= 0xffff_ffff => None,
            0xFE if value <= 0xffff => None,
            0xFD if value < 0xfd => None,
            _ => Some(value),
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
    pub addr_recv: VersionNetAddr,
    pub addr_from: Option<VersionNetAddr>,
    pub nonce: Option<u64>,
}

/// A legacy network address claimed inside a peer's `version` message.
#[derive(Debug, Clone)]
pub struct VersionNetAddr {
    pub services: u64,
    pub host: String,
    pub port: u16,
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
    let addr_recv = parse_version_netaddr(&mut c)?;

    let mut user_agent = String::new();
    let mut latest_block = 0i32;
    // Absent relay is recorded as true (Core convention, Section 4.3/4.4).
    let mut relay = true;
    let mut addr_from = None;
    let mut nonce = None;

    // addr_from..user_agent..latest_block requires version >= 106.
    if version >= 106 {
        addr_from = Some(parse_version_netaddr(&mut c)?);
        nonce = Some(c.u64_le()?);
        let ua_len: usize = c.compact_size_canonical()?.try_into().ok()?;
        if ua_len > MAX_SUBVERSION_LENGTH {
            return None;
        }
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
        addr_recv,
        addr_from,
        nonce,
    })
}

fn parse_version_netaddr(c: &mut Cursor<'_>) -> Option<VersionNetAddr> {
    let services = c.u64_le()?;
    let ip = c.take(16)?;
    let port = c.u16_be()?;
    let mut octets = [0u8; 16];
    octets.copy_from_slice(ip);
    let (host, _) = decode_legacy_ip(&octets);
    Some(VersionNetAddr {
        services,
        host,
        port,
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
    pub services: u64,
    pub wire_network_id: u8,
}

#[derive(Debug, Clone)]
pub struct ParsedAddrMessage {
    pub declared_count: u64,
    pub addrs: Vec<AdvertisedAddr>,
    pub unknown_entries: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddrParseError {
    NonCanonicalOrTruncated,
    TooMany(u64),
    WrongLength { network_id: u8, length: usize },
    InvalidNetworkEncoding(u8),
    TrailingBytes(usize),
}

impl std::fmt::Display for AddrParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonCanonicalOrTruncated => {
                f.write_str("non-canonical or truncated address message")
            }
            Self::TooMany(n) => write!(f, "declared address count {n} exceeds {MAX_ADDR_TO_SEND}"),
            Self::WrongLength { network_id, length } => {
                write!(f, "wrong length {length} for BIP155 network {network_id}")
            }
            Self::InvalidNetworkEncoding(id) => {
                write!(f, "invalid encoding for BIP155 network {id}")
            }
            Self::TrailingBytes(n) => write!(f, "{n} trailing bytes after address vector"),
        }
    }
}

impl std::error::Error for AddrParseError {}

/// Parse a legacy `addr` payload atomically. No prefix is returned on error.
pub fn parse_addr(payload: &[u8]) -> Result<ParsedAddrMessage, AddrParseError> {
    let mut c = Cursor::new(payload);
    let count = c
        .compact_size_canonical()
        .ok_or(AddrParseError::NonCanonicalOrTruncated)?;
    check_addr_count(count)?;
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let ts = c.u32_le().ok_or(AddrParseError::NonCanonicalOrTruncated)? as i64;
        let services = c.u64_le().ok_or(AddrParseError::NonCanonicalOrTruncated)?;
        let ip = c.take(16).ok_or(AddrParseError::NonCanonicalOrTruncated)?;
        let port = c.u16_be().ok_or(AddrParseError::NonCanonicalOrTruncated)?;
        let mut arr = [0u8; 16];
        arr.copy_from_slice(ip);
        let (host, network) = decode_legacy_ip(&arr);
        out.push(AdvertisedAddr {
            host,
            port,
            network,
            timestamp: ts,
            services,
            wire_network_id: 2,
        });
    }
    finish_addr_parse(c, count, out, 0)
}

/// Parse BIP155 atomically. Unknown future ids are consumed and skipped.
pub fn parse_addrv2(payload: &[u8]) -> Result<ParsedAddrMessage, AddrParseError> {
    let mut c = Cursor::new(payload);
    let count = c
        .compact_size_canonical()
        .ok_or(AddrParseError::NonCanonicalOrTruncated)?;
    check_addr_count(count)?;
    let mut out = Vec::with_capacity(count as usize);
    let mut unknown_entries = 0;
    for _ in 0..count {
        let ts = c.u32_le().ok_or(AddrParseError::NonCanonicalOrTruncated)? as i64;
        let services = c
            .compact_size_canonical()
            .ok_or(AddrParseError::NonCanonicalOrTruncated)?;
        let net_id = c.u8().ok_or(AddrParseError::NonCanonicalOrTruncated)?;
        let addr_len_u64 = c
            .compact_size_canonical()
            .ok_or(AddrParseError::NonCanonicalOrTruncated)?;
        let addr_len: usize = addr_len_u64
            .try_into()
            .map_err(|_| AddrParseError::NonCanonicalOrTruncated)?;
        if addr_len > 512 {
            return Err(AddrParseError::WrongLength {
                network_id: net_id,
                length: addr_len,
            });
        }
        let expected = match net_id {
            1 => 4,
            2 => 16,
            3 => 10,
            4 => 32,
            5 => 32,
            6 => 16,
            _ => addr_len,
        };
        if addr_len != expected {
            return Err(AddrParseError::WrongLength {
                network_id: net_id,
                length: addr_len,
            });
        }
        let addr_bytes = c
            .take(addr_len)
            .ok_or(AddrParseError::NonCanonicalOrTruncated)?;
        let port = c.u16_be().ok_or(AddrParseError::NonCanonicalOrTruncated)?;
        let Some((host, network)) = decode_addrv2(net_id, addr_bytes)? else {
            unknown_entries += 1;
            continue;
        };
        out.push(AdvertisedAddr {
            host,
            port,
            network,
            timestamp: ts,
            services,
            wire_network_id: net_id,
        });
    }
    finish_addr_parse(c, count, out, unknown_entries)
}

fn check_addr_count(count: u64) -> Result<(), AddrParseError> {
    if count > MAX_ADDR_TO_SEND as u64 {
        Err(AddrParseError::TooMany(count))
    } else {
        Ok(())
    }
}

fn finish_addr_parse(
    c: Cursor<'_>,
    count: u64,
    addrs: Vec<AdvertisedAddr>,
    unknown_entries: u64,
) -> Result<ParsedAddrMessage, AddrParseError> {
    if c.remaining() != 0 {
        return Err(AddrParseError::TrailingBytes(c.remaining()));
    }
    Ok(ParsedAddrMessage {
        declared_count: count,
        addrs,
        unknown_entries,
    })
}

/// Decode a 16-byte IPv6 field, collapsing IPv4-mapped to dotted quad.
fn decode_legacy_ip(arr: &[u8; 16]) -> (String, NetworkType) {
    let addr = std::net::Ipv6Addr::from(*arr);
    if let Some(v4) = ipv4_mapped(&addr) {
        (v4.to_string(), NetworkType::Ipv4)
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

fn decode_addrv2(
    net_id: u8,
    bytes: &[u8],
) -> Result<Option<(String, NetworkType)>, AddrParseError> {
    match net_id {
        1 => {
            let v4 = std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
            Ok(Some((v4.to_string(), NetworkType::Ipv4)))
        }
        2 => {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(bytes);
            let addr = std::net::Ipv6Addr::from(arr);
            if ipv4_mapped(&addr).is_some() || arr[0] == 0xfc {
                return Err(AddrParseError::InvalidNetworkEncoding(net_id));
            }
            Ok(Some((compact_ipv6(&addr), NetworkType::Ipv6)))
        }
        3 => {
            // torv2: base32(10 bytes) + .onion (defunct, kept for completeness)
            let label = BASE32_NOPAD.encode(bytes).to_lowercase();
            Ok(Some((format!("{label}.onion"), NetworkType::OnionV2)))
        }
        4 => {
            // torv3: label = base32(pubkey || checksum || 0x03)
            let host =
                encode_onion_v3(bytes).ok_or(AddrParseError::InvalidNetworkEncoding(net_id))?;
            Ok(Some((host, NetworkType::OnionV3)))
        }
        5 => {
            // i2p: base32(32 bytes) => 56 chars, strip padding, + .b32.i2p
            let label = BASE32_NOPAD.encode(bytes).to_lowercase();
            Ok(Some((format!("{label}.b32.i2p"), NetworkType::I2p)))
        }
        6 => {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(bytes);
            if arr[0] != 0xfc {
                return Err(AddrParseError::InvalidNetworkEncoding(net_id));
            }
            let addr = std::net::Ipv6Addr::from(arr);
            Ok(Some((compact_ipv6(&addr), NetworkType::Cjdns)))
        }
        _ => Ok(None),
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
        for v in [
            0u64,
            0xFC,
            0xFD,
            0xFFFF,
            0x1_0000,
            0xFFFF_FFFF,
            0x1_0000_0000,
        ] {
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
    fn version_rejects_oversize_and_noncanonical_user_agents() {
        const USER_AGENT_OFFSET: usize = 80;
        let base = build_version(1, 2);

        let mut oversized = base[..USER_AGENT_OFFSET].to_vec();
        write_compact_size(&mut oversized, (MAX_SUBVERSION_LENGTH + 1) as u64);
        oversized.extend(std::iter::repeat_n(b'x', MAX_SUBVERSION_LENGTH + 1));
        oversized.extend_from_slice(&0i32.to_le_bytes());
        oversized.push(0);
        assert!(parse_version(&oversized).is_none());

        let mut noncanonical = base[..USER_AGENT_OFFSET].to_vec();
        noncanonical.extend_from_slice(&[0xfd, 1, 0]);
        noncanonical.push(b'x');
        noncanonical.extend_from_slice(&0i32.to_le_bytes());
        noncanonical.push(0);
        assert!(parse_version(&noncanonical).is_none());
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
        let parsed = parse_addr(&payload).unwrap();
        assert_eq!(parsed.addrs.len(), 1);
        assert_eq!(parsed.addrs[0].timestamp, 0xFFFF_FFFF); // zero-extended, not -1
        assert_eq!(parsed.addrs[0].host, "1.2.3.4");
        assert_eq!(parsed.addrs[0].network, NetworkType::Ipv4);
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
        let parsed = parse_addrv2(&payload).unwrap();
        assert_eq!(parsed.addrs.len(), 1);
        assert_eq!(parsed.addrs[0].network, NetworkType::OnionV3);
        assert_eq!(classify(&parsed.addrs[0].host), NetworkType::OnionV3);
    }

    #[test]
    fn addrv2_torv2_is_decoded_and_counted_as_known() {
        let mut payload = Vec::new();
        write_compact_size(&mut payload, 1);
        payload.extend_from_slice(&0u32.to_le_bytes());
        write_compact_size(&mut payload, 0);
        payload.push(3);
        write_compact_size(&mut payload, 10);
        payload.extend_from_slice(&[0u8; 10]);
        payload.extend_from_slice(&8333u16.to_be_bytes());

        let parsed = parse_addrv2(&payload).unwrap();
        assert_eq!(parsed.unknown_entries, 0);
        assert_eq!(parsed.addrs.len(), 1);
        assert_eq!(parsed.addrs[0].network, NetworkType::OnionV2);
        assert_eq!(classify(&parsed.addrs[0].host), NetworkType::OnionV2);
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
        assert_eq!(
            parse_addrv2(&payload).unwrap_err(),
            AddrParseError::WrongLength {
                network_id: 1,
                length: 16
            }
        );
    }

    #[test]
    fn address_vectors_reject_noncanonical_oversize_truncated_and_trailing() {
        assert_eq!(
            parse_addr(&[0xfd, 1, 0]).unwrap_err(),
            AddrParseError::NonCanonicalOrTruncated
        );
        let mut oversized = Vec::new();
        write_compact_size(&mut oversized, 1001);
        assert_eq!(
            parse_addr(&oversized).unwrap_err(),
            AddrParseError::TooMany(1001)
        );

        let mut truncated = vec![1];
        truncated.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            parse_addr(&truncated).unwrap_err(),
            AddrParseError::NonCanonicalOrTruncated
        );
        assert_eq!(
            parse_addr(&[0, 42]).unwrap_err(),
            AddrParseError::TrailingBytes(1)
        );
    }

    #[test]
    fn unknown_addrv2_network_is_consumed_before_later_valid_entry() {
        let mut payload = vec![2];
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.push(0); // services
        payload.push(99); // future network
        payload.push(3); // address length
        payload.extend_from_slice(&[1, 2, 3]);
        payload.extend_from_slice(&8333u16.to_be_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.push(0);
        payload.push(1); // IPv4
        payload.push(4);
        payload.extend_from_slice(&[1, 2, 3, 4]);
        payload.extend_from_slice(&8333u16.to_be_bytes());
        let parsed = parse_addrv2(&payload).unwrap();
        assert_eq!(parsed.declared_count, 2);
        assert_eq!(parsed.unknown_entries, 1);
        assert_eq!(parsed.addrs.len(), 1);
        assert_eq!(parsed.addrs[0].host, "1.2.3.4");
    }

    #[test]
    fn wire_network_pairing_is_enforced() {
        let mapped = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4];
        assert_eq!(
            decode_addrv2(2, &mapped).unwrap_err(),
            AddrParseError::InvalidNetworkEncoding(2)
        );
        assert_eq!(
            decode_addrv2(6, &[0x20; 16]).unwrap_err(),
            AddrParseError::InvalidNetworkEncoding(6)
        );
        let mut cjdns = [0u8; 16];
        cjdns[0] = 0xfc;
        assert_eq!(
            decode_addrv2(6, &cjdns).unwrap().unwrap().1,
            NetworkType::Cjdns
        );
    }

    #[test]
    fn legacy_fc_address_remains_ipv6() {
        let mut address = [0u8; 16];
        address[0] = 0xfc;
        assert_eq!(decode_legacy_ip(&address).1, NetworkType::Ipv6);
    }

    #[test]
    fn frame_validates_internal_commands_and_payload_limit() {
        assert!(frame("this-command-is-too-long", &[]).is_err());
        assert!(frame("bad\0command", &[]).is_err());
        assert!(frame("ping", &vec![0; MAX_PROTOCOL_MESSAGE_LENGTH as usize + 1]).is_err());
    }
}
