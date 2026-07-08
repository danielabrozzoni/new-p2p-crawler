//! Result serialization: reachable / handshake-failed / unreachable CSVs and
//! the crawler-stats JSON (Sections 7, 8).

use crate::address::NetworkType;
use crate::settings::Settings;
use crate::store::{AddrKey, NetworkBreakdown, NodeEntry, NodeState, NodeStore};
use csv::{Terminator, WriterBuilder};
use serde::Serialize;
use serde_json::{Map, Value};
use std::io::Write;

/// Per-seed resolution result (Section 3.1 / 7.2).
pub struct SeedResult {
    pub seed: String,
    pub addrs: Vec<(AddrKey, NetworkType)>,
}

/// Build a CSV writer with the spec's dialect (Section 8): comma delimiter,
/// `\n` terminator, minimal quoting, `"` doubled.
fn csv_writer(path: &std::path::Path) -> anyhow::Result<csv::Writer<std::fs::File>> {
    let file = std::fs::File::create(path)?;
    Ok(WriterBuilder::new()
        .terminator(Terminator::Any(b'\n'))
        .quote_style(csv::QuoteStyle::Necessary)
        .from_writer(file))
}

/// Write all output files (Section 8).
pub fn write_all(
    store: &NodeStore,
    settings: &Settings,
    seeds: &[SeedResult],
    runtime_seconds: i64,
    num_processed: usize,
) -> anyhow::Result<()> {
    let snapshot = store.snapshot();

    write_reachable(&snapshot, settings)?;
    write_handshake_failed(&snapshot, settings)?;
    write_unreachable(&snapshot, settings)?;
    write_stats_json(
        &snapshot,
        store,
        settings,
        seeds,
        runtime_seconds,
        num_processed,
    )?;
    Ok(())
}

fn out_path(settings: &Settings, file: &str) -> std::path::PathBuf {
    settings.output_path(file)
}

fn write_reachable(
    snapshot: &[(AddrKey, NodeEntry)],
    settings: &Settings,
) -> anyhow::Result<()> {
    let mut rows: Vec<&(AddrKey, NodeEntry)> = snapshot
        .iter()
        .filter(|(_, e)| e.state == NodeState::Reachable)
        .collect();
    if rows.is_empty() {
        tracing::warn!("no reachable nodes; reachable CSV not written");
        return Ok(());
    }
    // Sorted ascending by handshake_timestamp (Section 8.1).
    rows.sort_by_key(|(_, e)| e.handshake.as_ref().map(|h| h.handshake_timestamp).unwrap_or(0));

    let path = out_path(settings, &settings.result_settings.reachable_nodes);
    let mut w = csv_writer(&path)?;
    w.write_record([
        "host",
        "port",
        "network",
        "handshake_timestamp",
        "time_connect",
        "handshake_attempts",
        "handshake_duration",
        "version",
        "services",
        "user_agent",
        "latest_block",
        "relay",
        "version_reply_timestamp_remote",
        "advertised_addrs_total",
        "advertised_addrs_ipv4",
        "advertised_addrs_ipv6",
        "advertised_addrs_onion_v2",
        "advertised_addrs_onion_v3",
        "advertised_addrs_i2p",
        "advertised_addrs_cjdns",
        "freshest_timestamp",
    ])?;
    for (key, e) in rows {
        let h = e.handshake.as_ref().expect("reachable has handshake");
        let s = &e.stats;
        w.write_record([
            key.host.as_str(),
            &key.port.to_string(),
            e.network.as_str(),
            &h.handshake_timestamp.to_string(),
            &s.time_connect_ms.map(|v| v.to_string()).unwrap_or_default(),
            &s.handshake_attempts.to_string(),
            &h.handshake_duration_ms.to_string(),
            &h.version.to_string(),
            &h.services.to_string(),
            &h.user_agent,
            &h.latest_block.to_string(),
            &h.relay.to_string(),
            &h.version_reply_timestamp_remote.to_string(),
            &s.advertised_total.to_string(),
            &s.advertised_ipv4.to_string(),
            &s.advertised_ipv6.to_string(),
            &s.advertised_onion_v2.to_string(),
            &s.advertised_onion_v3.to_string(),
            &s.advertised_i2p.to_string(),
            &s.advertised_cjdns.to_string(),
            &e.freshest_ts.to_string(),
        ])?;
    }
    w.flush()?;
    Ok(())
}

fn write_handshake_failed(
    snapshot: &[(AddrKey, NodeEntry)],
    settings: &Settings,
) -> anyhow::Result<()> {
    let mut rows: Vec<&(AddrKey, NodeEntry)> = snapshot
        .iter()
        .filter(|(_, e)| e.state == NodeState::HandshakeFailed)
        .collect();
    if rows.is_empty() {
        tracing::warn!("no handshake-failed nodes; CSV not written");
        return Ok(());
    }
    // Sorted ascending by handshake_timestamp (Section 8.2).
    rows.sort_by_key(|(_, e)| e.stats.first_version_send_ts.unwrap_or(0));

    let path = out_path(settings, &settings.result_settings.handshake_failed_nodes);
    let mut w = csv_writer(&path)?;
    w.write_record([
        "host",
        "port",
        "network",
        "handshake_timestamp",
        "time_connect",
        "handshake_attempts",
        "freshest_timestamp",
    ])?;
    for (key, e) in rows {
        let s = &e.stats;
        w.write_record([
            key.host.as_str(),
            &key.port.to_string(),
            e.network.as_str(),
            &s.first_version_send_ts.map(|v| v.to_string()).unwrap_or_default(),
            &s.time_connect_ms.map(|v| v.to_string()).unwrap_or_default(),
            &s.handshake_attempts.to_string(),
            &e.freshest_ts.to_string(),
        ])?;
    }
    w.flush()?;
    Ok(())
}

fn write_unreachable(
    snapshot: &[(AddrKey, NodeEntry)],
    settings: &Settings,
) -> anyhow::Result<()> {
    let mut rows: Vec<&(AddrKey, NodeEntry)> = snapshot
        .iter()
        .filter(|(_, e)| e.state == NodeState::Unreachable)
        .collect();
    if rows.is_empty() {
        tracing::warn!("no unreachable nodes; CSV not written");
        return Ok(());
    }
    // Sorted ascending by freshest_timestamp (Section 8.3).
    rows.sort_by_key(|(_, e)| e.freshest_ts);

    let path = out_path(settings, &settings.result_settings.unreachable_nodes);
    let mut w = csv_writer(&path)?;
    w.write_record(["host", "port", "network", "handshake_attempts", "freshest_timestamp"])?;
    for (key, e) in rows {
        w.write_record([
            key.host.as_str(),
            &key.port.to_string(),
            e.network.as_str(),
            &e.stats.handshake_attempts.to_string(),
            &e.freshest_ts.to_string(),
        ])?;
    }
    w.flush()?;
    Ok(())
}

/// Serializable per-network breakdown in the spec's key order (Section 8.4).
#[derive(Serialize)]
struct BreakdownJson {
    total: u64,
    unknown: u64,
    ipv4: u64,
    ipv6: u64,
    onion_v2: u64,
    onion_v3: u64,
    i2p: u64,
    cjdns: u64,
}

impl From<&NetworkBreakdown> for BreakdownJson {
    fn from(b: &NetworkBreakdown) -> Self {
        BreakdownJson {
            total: b.total,
            unknown: b.unknown,
            ipv4: b.ipv4,
            ipv6: b.ipv6,
            onion_v2: b.onion_v2,
            onion_v3: b.onion_v3,
            i2p: b.i2p,
            cjdns: b.cjdns,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn write_stats_json(
    snapshot: &[(AddrKey, NodeEntry)],
    store: &NodeStore,
    settings: &Settings,
    seeds: &[SeedResult],
    runtime_seconds: i64,
    num_processed: usize,
) -> anyhow::Result<()> {
    // Terminal-state breakdowns.
    let mut reachable = NetworkBreakdown::default();
    let mut handshake_failed = NetworkBreakdown::default();
    let mut unreachable = NetworkBreakdown::default();
    let mut list_reachable = Vec::new();
    let mut list_handshake_failed = Vec::new();
    let mut list_unreachable = Vec::new();

    for (key, e) in snapshot {
        match e.state {
            NodeState::Reachable => {
                reachable.add(e.network);
                list_reachable.push(key.render());
            }
            NodeState::HandshakeFailed => {
                handshake_failed.add(e.network);
                list_handshake_failed.push(key.render());
            }
            NodeState::Unreachable => {
                unreachable.add(e.network);
                list_unreachable.push(key.render());
            }
            _ => {}
        }
    }

    // Per-seed breakdowns and address lists (Section 7.2).
    let mut num_from_seed = Map::new();
    let mut list_from_seed = Map::new();
    for sr in seeds {
        let mut bd = NetworkBreakdown::default();
        let mut list = Vec::new();
        for (key, net) in &sr.addrs {
            bd.add(*net);
            list.push(key.render());
        }
        num_from_seed.insert(sr.seed.clone(), serde_json::to_value(BreakdownJson::from(&bd))?);
        list_from_seed.insert(sr.seed.clone(), serde_json::to_value(list)?);
    }

    // Assemble the ordered top-level object (Section 8.4).
    let mut root = Map::new();
    root.insert(
        "crawler_settings".to_string(),
        serde_json::to_value(settings)?,
    );
    root.insert(
        "time_started".to_string(),
        Value::String(settings.result_settings.timestamp.clone()),
    );
    root.insert("runtime_seconds".to_string(), Value::from(runtime_seconds));
    root.insert(
        "num_processed_nodes".to_string(),
        Value::from(num_processed),
    );
    root.insert(
        "num_reachable".to_string(),
        serde_json::to_value(BreakdownJson::from(&reachable))?,
    );
    root.insert(
        "num_handshake_failed".to_string(),
        serde_json::to_value(BreakdownJson::from(&handshake_failed))?,
    );
    root.insert(
        "num_unreachable".to_string(),
        serde_json::to_value(BreakdownJson::from(&unreachable))?,
    );
    root.insert("num_advertised".to_string(), Value::from(store.len()));
    root.insert("num_nodes_from_seed".to_string(), Value::Object(num_from_seed));
    root.insert("list_reachable".to_string(), serde_json::to_value(list_reachable)?);
    root.insert(
        "list_handshake_failed".to_string(),
        serde_json::to_value(list_handshake_failed)?,
    );
    root.insert(
        "list_unreachable".to_string(),
        serde_json::to_value(list_unreachable)?,
    );
    root.insert("list_nodes_from_seed".to_string(), Value::Object(list_from_seed));

    // Pretty-print with 4-space indent (Section 8.4).
    let path = out_path(settings, &settings.result_settings.crawler_stats);
    let file = std::fs::File::create(&path)?;
    let mut writer = std::io::BufWriter::new(file);
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut ser = serde_json::Serializer::with_formatter(&mut writer, formatter);
    Value::Object(root).serialize(&mut ser)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}
