//! Bounded, single-writer address observation log.

use crate::protocol::{AddrParseError, ParsedAddrMessage};
use crate::store::{CollectionOutcome, HandshakeData};
use std::io::{self, BufWriter, Write};
use tokio::sync::{mpsc, oneshot, Mutex};

/// Metadata about the responding node for one addr-response block.
pub struct Responder<'a> {
    pub host: &'a str,
    pub port: u16,
    pub network: &'a str,
    pub received_at: i64,
    pub message_type: &'a str,
    pub handshake: &'a HandshakeData,
}

enum WriterCommand {
    Append {
        bytes: Vec<u8>,
        event_id: u64,
        reply: oneshot::Sender<io::Result<u64>>,
    },
    Flush {
        reply: oneshot::Sender<io::Result<u64>>,
    },
}

/// Producers send complete records through a bounded channel to one blocking
/// filesystem writer. Every acknowledged event has been written in order.
pub struct AddrLog {
    tx: mpsc::Sender<WriterCommand>,
    next_event_id: Mutex<u64>,
}

impl AddrLog {
    pub fn create(path: &std::path::Path) -> io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)?;
        let (tx, mut rx) = mpsc::channel::<WriterCommand>(1024);
        std::thread::Builder::new()
            .name("addr-observation-writer".to_string())
            .spawn(move || {
                let mut writer = BufWriter::new(file);
                let mut durable_event_id = 0;
                while let Some(command) = rx.blocking_recv() {
                    match command {
                        WriterCommand::Append {
                            bytes,
                            event_id,
                            reply,
                        } => {
                            let result = writer.write_all(&bytes).map(|()| {
                                durable_event_id = event_id;
                                event_id
                            });
                            let _ = reply.send(result);
                        }
                        WriterCommand::Flush { reply } => {
                            let result = writer
                                .flush()
                                .and_then(|()| writer.get_ref().sync_all())
                                .map(|()| durable_event_id);
                            let _ = reply.send(result);
                        }
                    }
                }
            })?;
        Ok(Self {
            tx,
            next_event_id: Mutex::new(1),
        })
    }

    pub async fn write_block(
        &self,
        r: &Responder<'_>,
        parsed: &ParsedAddrMessage,
    ) -> io::Result<u64> {
        let mut next_event_id = self.next_event_id.lock().await;
        let event_id = *next_event_id;
        *next_event_id += 1;
        let mut buf = String::new();
        let hd = r.handshake;
        buf.push_str("===NEW NODE===,");
        push_csv_fields(
            &mut buf,
            &[
                &event_id.to_string(),
                r.host,
                &r.port.to_string(),
                r.network,
                &r.received_at.to_string(),
                r.message_type,
                "complete",
                &parsed.declared_count.to_string(),
                &parsed.addrs.len().to_string(),
                &parsed.unknown_entries.to_string(),
                &hd.version.to_string(),
                &hd.services.to_string(),
                &hd.user_agent,
                &hd.latest_block.to_string(),
                &hd.relay.to_string(),
            ],
        );
        buf.push('\n');
        for a in &parsed.addrs {
            push_csv_fields(
                &mut buf,
                &[
                    &event_id.to_string(),
                    &a.host,
                    &a.port.to_string(),
                    a.network.as_str(),
                    &a.timestamp.to_string(),
                    &a.services.to_string(),
                    &a.wire_network_id.to_string(),
                ],
            );
            buf.push('\n');
        }
        self.append(event_id, buf.into_bytes()).await
    }

    pub async fn write_outcome(
        &self,
        host: &str,
        port: u16,
        outcome: CollectionOutcome,
    ) -> io::Result<u64> {
        let mut next_event_id = self.next_event_id.lock().await;
        let event_id = *next_event_id;
        *next_event_id += 1;
        let mut buf = String::from("===REQUEST OUTCOME===,");
        push_csv_fields(
            &mut buf,
            &[
                &event_id.to_string(),
                host,
                &port.to_string(),
                outcome.as_str(),
            ],
        );
        buf.push('\n');
        self.append(event_id, buf.into_bytes()).await
    }

    pub async fn write_malformed(
        &self,
        host: &str,
        port: u16,
        message_type: &str,
        error: &AddrParseError,
        payload: &[u8],
    ) -> io::Result<u64> {
        use sha2::{Digest, Sha256};
        let mut next_event_id = self.next_event_id.lock().await;
        let event_id = *next_event_id;
        *next_event_id += 1;
        let payload_hash: String = Sha256::digest(payload)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let mut buf = String::from("===MALFORMED RESPONSE===,");
        push_csv_fields(
            &mut buf,
            &[
                &event_id.to_string(),
                host,
                &port.to_string(),
                message_type,
                "malformed",
                &error.to_string(),
                &payload_hash,
            ],
        );
        buf.push('\n');
        self.append(event_id, buf.into_bytes()).await
    }

    async fn append(&self, event_id: u64, bytes: Vec<u8>) -> io::Result<u64> {
        let (reply, response) = oneshot::channel();
        self.tx
            .send(WriterCommand::Append {
                bytes,
                event_id,
                reply,
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "address writer stopped"))?;
        response.await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "address writer dropped acknowledgement",
            )
        })?
    }

    /// Flush buffered bytes and sync them to stable storage. Returns the last
    /// durable event id for snapshot manifests.
    pub async fn flush(&self) -> io::Result<u64> {
        // Serialize the barrier with producers so every event that reached this
        // writer before the checkpoint is included in the durable watermark.
        let _event_order = self.next_event_id.lock().await;
        let (reply, response) = oneshot::channel();
        self.tx
            .send(WriterCommand::Flush { reply })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "address writer stopped"))?;
        response.await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "address writer dropped acknowledgement",
            )
        })?
    }
}

fn push_csv_fields(out: &mut String, fields: &[&str]) {
    for (i, field) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_csv_field(out, field);
    }
}

fn push_csv_field(out: &mut String, field: &str) {
    let needs_quote =
        field.contains(',') || field.contains('"') || field.contains('\r') || field.contains('\n');
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
