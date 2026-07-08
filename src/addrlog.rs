//! Optional addr-response log (Section 7.6, 8.5): grouped plain-CSV blocks,
//! written incrementally as messages arrive.

use crate::protocol::AdvertisedAddr;
use crate::store::HandshakeData;
use std::io::{self, BufWriter, Write};
use tokio::sync::Mutex;

/// Metadata about the responding node for one addr-response block.
pub struct Responder<'a> {
    pub host: &'a str,
    pub port: u16,
    pub network: &'a str,
    pub received_at: i64,
    pub message_type: &'a str,
    pub handshake: &'a HandshakeData,
}

/// A thread-safe incremental writer for the grouped addr-response CSV.
pub struct AddrLog {
    inner: Mutex<BufWriter<std::fs::File>>,
}

impl AddrLog {
    pub fn create(path: &std::path::Path) -> io::Result<Self> {
        let file = std::fs::File::create(path)?;
        Ok(AddrLog {
            inner: Mutex::new(BufWriter::new(file)),
        })
    }

    /// Write one block: a `===NEW NODE===` line + one line per advertised addr.
    pub async fn write_block(&self, r: &Responder<'_>, addrs: &[AdvertisedAddr]) {
        let mut buf = String::new();
        // Node line (IPv6/CJDNS host written bracketless).
        let hd = r.handshake;
        buf.push_str("===NEW NODE===,");
        push_csv_fields(
            &mut buf,
            &[
                r.host,
                &r.port.to_string(),
                r.network,
                &r.received_at.to_string(),
                r.message_type,
                &hd.version.to_string(),
                &hd.services.to_string(),
                &hd.user_agent,
                &hd.latest_block.to_string(),
                &hd.relay.to_string(),
            ],
        );
        buf.push('\n');
        // Address lines.
        for a in addrs {
            push_csv_fields(
                &mut buf,
                &[
                    &a.host,
                    &a.port.to_string(),
                    a.network.as_str(),
                    &a.timestamp.to_string(),
                ],
            );
            buf.push('\n');
        }
        let mut w = self.inner.lock().await;
        let _ = w.write_all(buf.as_bytes());
    }

    pub async fn flush(&self) {
        let mut w = self.inner.lock().await;
        let _ = w.flush();
    }
}

/// Write comma-separated fields with RFC 4180 minimal quoting (Section 8).
fn push_csv_fields(out: &mut String, fields: &[&str]) {
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_csv_field(out, f);
    }
}

fn push_csv_field(out: &mut String, field: &str) {
    let needs_quote = field.contains(',')
        || field.contains('"')
        || field.contains('\r')
        || field.contains('\n');
    if needs_quote {
        out.push('"');
        for ch in field.chars() {
            if ch == '"' {
                out.push('"');
            }
            out.push(ch);
        }
        out.push('"');
    } else {
        out.push_str(field);
    }
}
