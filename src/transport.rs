//! Transport layer: TCP (IPv4/IPv6/CJDNS), SOCKS5 (Tor), SAM (I2P), plus the
//! framed envelope send/receive primitives (Section 4.1, 4.2).

use crate::protocol::{checksum, frame, MAGIC, MAX_PROTOCOL_MESSAGE_LENGTH};
use bytes::{Buf, BytesMut};
use std::io;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// A received message envelope (Section 4.1).
#[derive(Debug, Clone)]
pub struct Envelope {
    pub command: String,
    pub payload: Vec<u8>,
}

/// A live P2P connection over any transport (all collapse to a TCP stream).
pub struct Connection {
    stream: TcpStream,
    recv_buf: BytesMut,
    frame_started: Option<std::time::Instant>,
    socket_local: std::net::SocketAddr,
    socket_peer: std::net::SocketAddr,
}

impl Connection {
    pub fn new(stream: TcpStream) -> Self {
        let socket_local = stream
            .local_addr()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
        let socket_peer = stream
            .peer_addr()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
        Connection {
            stream,
            recv_buf: BytesMut::with_capacity(8192),
            frame_started: None,
            socket_local,
            socket_peer,
        }
    }

    pub fn socket_local(&self) -> std::net::SocketAddr {
        self.socket_local
    }

    pub fn socket_peer(&self) -> std::net::SocketAddr {
        self.socket_peer
    }

    pub fn has_partial_envelope(&self) -> bool {
        !self.recv_buf.is_empty()
    }

    /// Serialize + send a framed message.
    pub async fn send(&mut self, command: &str, payload: &[u8]) -> io::Result<()> {
        let bytes = frame(command, payload)?;
        self.stream.write_all(&bytes).await?;
        Ok(())
    }

    /// Read exactly one envelope, bounded by `per_timeout`.
    /// Returns `Ok(None)` on timeout, `Ok(Some(env))` on a message, and `Err`
    /// on any transport failure (EOF, magic/checksum mismatch, oversize length).
    pub async fn recv_one(&mut self, per_timeout: Duration) -> io::Result<Option<Envelope>> {
        const ENVELOPE_HARD_TIMEOUT: Duration = Duration::from_secs(120);
        let call_deadline = std::time::Instant::now() + per_timeout;
        loop {
            if let Some(env) = try_parse_envelope(&mut self.recv_buf)? {
                self.frame_started = if self.recv_buf.is_empty() {
                    None
                } else {
                    Some(std::time::Instant::now())
                };
                return Ok(Some(env));
            }
            let hard_remaining = self
                .frame_started
                .map(|start| ENVELOPE_HARD_TIMEOUT.saturating_sub(start.elapsed()))
                .unwrap_or(ENVELOPE_HARD_TIMEOUT);
            if hard_remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "incomplete envelope exceeded hard deadline",
                ));
            }
            let call_remaining = call_deadline.saturating_duration_since(std::time::Instant::now());
            if call_remaining.is_zero() {
                return Ok(None);
            }
            let mut chunk = [0u8; 8192];
            match timeout(
                call_remaining.min(hard_remaining),
                self.stream.read(&mut chunk),
            )
            .await
            {
                Err(_) => return Ok(None),
                Ok(Err(e)) => return Err(e),
                Ok(Ok(0)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "peer closed connection",
                    ))
                }
                Ok(Ok(n)) => {
                    if self.recv_buf.is_empty() {
                        self.frame_started = Some(std::time::Instant::now());
                    }
                    self.recv_buf.extend_from_slice(&chunk[..n]);
                    if self.recv_buf.len() > 24 + MAX_PROTOCOL_MESSAGE_LENGTH as usize {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "receive buffer limit exceeded",
                        ));
                    }
                }
            }
        }
    }

    /// Answer a `ping` by echoing its exact 8-byte nonce as a `pong` (Section 4.1).
    pub async fn answer_ping(
        &mut self,
        ping_payload: &[u8],
        protocol_version: i32,
    ) -> io::Result<()> {
        let expects_nonce = protocol_version > 60000;
        validate_ping_payload(ping_payload, expects_nonce)?;
        if expects_nonce {
            self.send("pong", ping_payload).await
        } else {
            Ok(())
        }
    }
}

fn validate_ping_payload(payload: &[u8], expects_nonce: bool) -> io::Result<()> {
    if (expects_nonce && payload.len() == 8) || (!expects_nonce && payload.is_empty()) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ping nonce must be exactly 8 bytes",
        ))
    }
}

/// Parse one complete envelope without consuming partial bytes.
fn try_parse_envelope(buf: &mut BytesMut) -> io::Result<Option<Envelope>> {
    if buf.len() < 24 {
        return Ok(None);
    }
    let header = &buf[..24];

    if header[0..4] != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "network magic mismatch (stream desynchronized)",
        ));
    }

    let command = parse_command(&header[4..16])?;
    let length = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);
    let expected_checksum = [header[20], header[21], header[22], header[23]];

    // Reject oversize payloads before any allocation (Section 4.1).
    if length > MAX_PROTOCOL_MESSAGE_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("payload length {length} exceeds 4,000,000 bytes"),
        ));
    }
    let frame_len = 24 + length as usize;
    if buf.len() < frame_len {
        return Ok(None);
    }
    let payload = buf[24..frame_len].to_vec();

    if checksum(&payload) != expected_checksum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "payload checksum mismatch",
        ));
    }

    buf.advance(frame_len);
    Ok(Some(Envelope { command, payload }))
}

fn parse_command(bytes: &[u8]) -> io::Result<String> {
    if bytes.len() != 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "command field is not 12 bytes",
        ));
    }
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    if end == 0
        || bytes[..end].iter().any(|b| !(0x20..=0x7e).contains(b))
        || bytes[end..].iter().any(|b| *b != 0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid command field",
        ));
    }
    Ok(std::str::from_utf8(&bytes[..end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-ASCII command"))?
        .to_string())
}

// ---------------------------------------------------------------------------
// TCP transport (IPv4/IPv6/CJDNS)
// ---------------------------------------------------------------------------

/// Connect a plain TCP stream to `host:port` (Section 4.2).
///
/// IPv4/IPv6/CJDNS hosts are always numeric literals, so parse straight to a
/// `SocketAddr` (no `getaddrinfo`) — this also avoids the unbracketed-IPv6
/// pitfall of `"host:port"` string parsing, which would otherwise force a DNS
/// lookup on every IPv6/CJDNS connect.
pub async fn connect_tcp(
    host: &str,
    port: u16,
    connect_timeout: Duration,
) -> io::Result<TcpStream> {
    let ip: std::net::IpAddr = host
        .parse()
        .map_err(|_| io::Error::other(format!("not a numeric IP address: {host}")))?;
    let addr = std::net::SocketAddr::new(ip, port);
    let stream = timeout(connect_timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tcp connect timed out"))??;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

// ---------------------------------------------------------------------------
// SOCKS5 transport (Tor) — RFC 1928, no auth, remote DNS (Section 4.2.1)
// ---------------------------------------------------------------------------

/// Connect to `host:port` through a SOCKS5 proxy using DOMAINNAME (remote DNS).
pub async fn connect_socks5(
    proxy_host: &str,
    proxy_port: u16,
    host: &str,
    port: u16,
    connect_timeout: Duration,
) -> io::Result<TcpStream> {
    timeout(connect_timeout, async {
        let proxy_addr = format!("{proxy_host}:{proxy_port}");
        let mut stream = TcpStream::connect(&proxy_addr).await?;
        let _ = stream.set_nodelay(true);

        socks5_greeting(&mut stream).await?;
        socks5_connect(&mut stream, host, port).await?;
        Ok::<_, io::Error>(stream)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "socks5 connect timed out"))?
}

/// Greeting + method selection: `05 01 00` -> `05 00`.
async fn socks5_greeting(stream: &mut TcpStream) -> io::Result<()> {
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply != [0x05, 0x00] {
        return Err(io::Error::other(format!(
            "socks5 method selection failed: {reply:02x?}"
        )));
    }
    Ok(())
}

/// CONNECT with ATYP=DOMAINNAME, then parse the reply.
async fn socks5_connect(stream: &mut TcpStream, host: &str, port: u16) -> io::Result<()> {
    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(io::Error::other("socks5 host too long"));
    }
    let mut req = Vec::with_capacity(7 + host_bytes.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03]); // VER, CMD=CONNECT, RSV, ATYP=DOMAIN
    req.push(host_bytes.len() as u8);
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&port.to_be_bytes()); // port big-endian
    stream.write_all(&req).await?;

    // Reply: VER REP RSV ATYP BND.ADDR BND.PORT
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        return Err(io::Error::other(format!(
            "socks5 connect failed: REP={:#04x}",
            head[1]
        )));
    }
    // Consume BND.ADDR based on ATYP, then 2-byte BND.PORT.
    let atyp = head[3];
    let addr_len = match atyp {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await?;
            l[0] as usize
        }
        other => {
            return Err(io::Error::other(format!(
                "socks5 reply unknown ATYP {other}"
            )))
        }
    };
    let mut scratch = vec![0u8; addr_len + 2];
    stream.read_exact(&mut scratch).await?;
    Ok(())
}

/// Complete only the SOCKS5 greeting (used by the Tor preflight, Section 2.5).
pub async fn socks5_probe(
    proxy_host: &str,
    proxy_port: u16,
    connect_timeout: Duration,
) -> io::Result<()> {
    timeout(connect_timeout, async {
        let proxy_addr = format!("{proxy_host}:{proxy_port}");
        let mut stream = TcpStream::connect(&proxy_addr).await?;
        socks5_greeting(&mut stream).await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "socks5 probe timed out"))?
}

// ---------------------------------------------------------------------------
// I2P SAM v3.1 transport (Section 4.2.2)
// ---------------------------------------------------------------------------

/// A shared SAM session: one control socket + a session id, reused by all
/// I2P connections (Section 4.2.2, 5).
pub struct SamSession {
    pub session_id: String,
    // The control socket is kept open for the session lifetime.
    _control: TcpStream,
    router_host: String,
    router_port: u16,
}

impl SamSession {
    /// Create the shared SAM session lazily (once).
    pub async fn create(
        router_host: &str,
        router_port: u16,
        connect_timeout: Duration,
    ) -> io::Result<Self> {
        timeout(connect_timeout, async {
            let addr = format!("{router_host}:{router_port}");
            let mut control = TcpStream::connect(&addr).await?;

            sam_hello(&mut control).await?;

            let session_id = format!("crawler{}", rand::random::<u32>());
            let cmd = format!(
                "SESSION CREATE STYLE=STREAM ID={session_id} DESTINATION=TRANSIENT SIGNATURE_TYPE=7\n"
            );
            control.write_all(cmd.as_bytes()).await?;
            let reply = sam_read_line(&mut control).await?;
            if !reply.contains("SESSION STATUS") || !reply.contains("RESULT=OK") {
                return Err(io::Error::other(format!("SAM session create failed: {}", reply.trim()),
                ));
            }
            Ok(SamSession {
                session_id,
                _control: control,
                router_host: router_host.to_string(),
                router_port,
            })
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SAM session create timed out"))?
    }

    /// Open a new stream to a `.b32.i2p` destination over this session.
    pub async fn connect(&self, host: &str, connect_timeout: Duration) -> io::Result<TcpStream> {
        timeout(connect_timeout, async {
            let addr = format!("{}:{}", self.router_host, self.router_port);
            let mut stream = TcpStream::connect(&addr).await?;
            sam_hello(&mut stream).await?;
            let cmd = format!(
                "STREAM CONNECT ID={} DESTINATION={host} SILENT=false\n",
                self.session_id
            );
            stream.write_all(cmd.as_bytes()).await?;
            let reply = sam_read_line(&mut stream).await?;
            if !reply.contains("STREAM STATUS") || !reply.contains("RESULT=OK") {
                return Err(io::Error::other(format!(
                    "SAM stream connect failed: {}",
                    reply.trim()
                )));
            }
            Ok::<_, io::Error>(stream)
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SAM stream connect timed out"))?
    }
}

async fn sam_hello(stream: &mut TcpStream) -> io::Result<()> {
    stream.write_all(b"HELLO VERSION MIN=3.0 MAX=3.1\n").await?;
    let reply = sam_read_line(stream).await?;
    if !reply.contains("HELLO REPLY") || !reply.contains("RESULT=OK") {
        return Err(io::Error::other(format!(
            "SAM HELLO failed: {}",
            reply.trim()
        )));
    }
    Ok(())
}

/// Read a single '\n'-terminated line from a SAM control/stream socket.
async fn sam_read_line(stream: &mut TcpStream) -> io::Result<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "SAM connection closed before newline",
            ));
        }
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
        if line.len() > 4096 {
            return Err(io::Error::other("SAM line too long"));
        }
    }
    Ok(String::from_utf8_lossy(&line).into_owned())
}

/// Complete only the SAM `HELLO VERSION` handshake (used by the I2P preflight).
pub async fn sam_probe(
    router_host: &str,
    router_port: u16,
    connect_timeout: Duration,
) -> io::Result<()> {
    timeout(connect_timeout, async {
        let addr = format!("{router_host}:{router_port}");
        let mut stream = TcpStream::connect(&addr).await?;
        sam_hello(&mut stream).await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SAM probe timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_command_field_rejects_suffix_and_non_ascii() {
        assert_eq!(parse_command(b"addr\0\0\0\0\0\0\0\0").unwrap(), "addr");
        assert!(parse_command(b"addr\0garbage").is_err());
        assert!(parse_command(&[0xff; 12]).is_err());
        assert!(parse_command(&[0; 12]).is_err());
    }

    #[test]
    fn parser_handles_multiple_buffered_envelopes() {
        let mut bytes = BytesMut::new();
        bytes.extend_from_slice(&frame("ping", &[1; 8]).unwrap());
        bytes.extend_from_slice(&frame("pong", &[2; 8]).unwrap());
        assert_eq!(
            try_parse_envelope(&mut bytes).unwrap().unwrap().command,
            "ping"
        );
        assert_eq!(
            try_parse_envelope(&mut bytes).unwrap().unwrap().command,
            "pong"
        );
        assert!(bytes.is_empty());
    }

    #[test]
    fn partial_frame_bytes_remain_buffered() {
        let framed = frame("ping", &[7; 8]).unwrap();
        for split in 0..framed.len() {
            let mut buffered = BytesMut::from(&framed[..split]);
            assert!(try_parse_envelope(&mut buffered).unwrap().is_none());
            assert_eq!(&buffered[..], &framed[..split]);
            buffered.extend_from_slice(&framed[split..]);
            let envelope = try_parse_envelope(&mut buffered).unwrap().unwrap();
            assert_eq!(envelope.command, "ping");
            assert_eq!(envelope.payload, vec![7; 8]);
        }
    }

    #[test]
    fn malformed_ping_is_not_fabricated() {
        assert_eq!(
            validate_ping_payload(&[1, 2], true).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(validate_ping_payload(&[0; 8], true).is_ok());
        assert!(validate_ping_payload(&[0; 9], true).is_err());
        assert!(validate_ping_payload(&[], false).is_ok());
        assert!(validate_ping_payload(&[0; 8], false).is_err());
    }
}
