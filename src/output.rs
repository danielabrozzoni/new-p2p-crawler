//! Result serialization: reachable / handshake-failed / unreachable CSVs and
//! the crawler-stats JSON (Sections 7, 8).

use crate::address::NetworkType;
use crate::settings::Settings;
use crate::store::{AddrKey, NetworkBreakdown, NodeEntry, NodeState, NodeStore};
use csv::{Terminator, WriterBuilder};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;

/// Per-seed resolution result (Section 3.1 / 7.2).
pub struct SeedResult {
    pub seed: String,
    pub addrs: Vec<(AddrKey, NetworkType)>,
}

#[derive(Debug, Clone, Copy)]
pub struct SnapshotMeta {
    pub runtime_seconds: i64,
    pub num_processed: usize,
    pub durable_addr_event_id: Option<u64>,
    pub consistent: bool,
    pub run_complete: bool,
}

/// Build a CSV writer with the spec's dialect (Section 8): comma delimiter,
/// `\n` terminator, minimal quoting, `"` doubled.
fn csv_writer(path: &std::path::Path) -> anyhow::Result<csv::Writer<std::fs::File>> {
    let file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?;
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
    meta: SnapshotMeta,
) -> anyhow::Result<()> {
    let snapshot = store.snapshot();
    write_snapshot(snapshot, store.budget_rejected(), settings, seeds, meta)
}

/// Serialize a snapshot that was captured by the caller. This lets checkpoint
/// coordination release its observation barrier before doing filesystem I/O.
pub fn write_snapshot(
    snapshot: Vec<(AddrKey, NodeEntry)>,
    budget_rejected: usize,
    settings: &Settings,
    seeds: &[SeedResult],
    meta: SnapshotMeta,
) -> anyhow::Result<()> {
    let run_dir = settings.run_dir();
    let snapshots = run_dir.join("snapshots");
    std::fs::create_dir_all(&snapshots)?;
    let generation = format!(
        "{}-{}",
        chrono::Utc::now().format("%Y%m%dT%H%M%S%.9fZ"),
        std::process::id()
    );
    let temp_dir = snapshots.join(format!(".tmp-{generation}"));
    let final_dir = snapshots.join(&generation);
    std::fs::create_dir(&temp_dir)?;

    write_reachable(&snapshot, settings, &temp_dir)?;
    write_handshake_failed(&snapshot, settings, &temp_dir)?;
    write_unreachable(&snapshot, settings, &temp_dir)?;
    write_stats_json(
        &snapshot,
        settings,
        seeds,
        meta.runtime_seconds,
        meta.num_processed,
        &temp_dir,
        meta.consistent,
        budget_rejected,
        meta.run_complete,
    )?;

    let files = [
        &settings.result_settings.reachable_nodes,
        &settings.result_settings.handshake_failed_nodes,
        &settings.result_settings.unreachable_nodes,
        &settings.result_settings.crawler_stats,
    ];
    let mut hashes = BTreeMap::new();
    for file in files {
        let path = temp_dir.join(file);
        std::fs::File::open(&path)?.sync_all()?;
        hashes.insert(file.clone(), sha256_file(&path)?);
    }
    sync_dir(&temp_dir)?;
    std::fs::rename(&temp_dir, &final_dir)?;
    sync_dir(&snapshots)?;

    let manifest = serde_json::json!({
        "schema_version": 1,
        "generation": generation,
        "snapshot_directory": format!("snapshots/{generation}"),
        "snapshot_consistency": if meta.consistent { "final_consistent" } else { "checkpoint_fuzzy" },
        "run_complete": meta.run_complete,
        "durable_addr_event_id": meta.durable_addr_event_id,
        "num_snapshot_entries": snapshot.len(),
        "files_sha256": hashes,
        "address_sample_semantics": "A getaddr response is a capped, partial, potentially 21-27-hour cached sample; it is not a complete live addrman view.",
    });
    publish_manifest(&run_dir, &manifest)?;
    Ok(())
}

fn out_path(dir: &std::path::Path, file: &str) -> std::path::PathBuf {
    dir.join(file)
}

fn write_reachable(
    snapshot: &[(AddrKey, NodeEntry)],
    settings: &Settings,
    dir: &std::path::Path,
) -> anyhow::Result<()> {
    let mut rows: Vec<&(AddrKey, NodeEntry)> = snapshot
        .iter()
        .filter(|(_, e)| e.state == NodeState::Reachable)
        .collect();
    // Sorted ascending by handshake_timestamp (Section 8.1).
    rows.sort_by_key(|(_, e)| {
        e.handshake
            .as_ref()
            .map(|h| h.handshake_timestamp)
            .unwrap_or(0)
    });

    let path = out_path(dir, &settings.result_settings.reachable_nodes);
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
        "collection_outcome",
        "valid_addr_messages",
        "malformed_addr_messages",
        "requested_endpoint",
        "transport_destination",
        "socket_local",
        "socket_peer",
        "version_addr_recv",
        "version_addr_recv_services",
        "version_addr_from",
        "version_addr_from_services",
        "version_nonce",
        "attempt_history_json",
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
            s.collection_outcome.as_str(),
            &s.valid_addr_messages.to_string(),
            &s.malformed_addr_messages.to_string(),
            &h.requested_endpoint,
            &h.transport_destination,
            &h.socket_local,
            &h.socket_peer,
            &h.version_addr_recv,
            &h.version_addr_recv_services.to_string(),
            h.version_addr_from.as_deref().unwrap_or(""),
            &h.version_addr_from_services
                .map(|v| v.to_string())
                .unwrap_or_default(),
            &h.version_nonce.map(|v| v.to_string()).unwrap_or_default(),
            &attempt_history_json(e)?,
        ])?;
    }
    w.flush()?;
    Ok(())
}

fn write_handshake_failed(
    snapshot: &[(AddrKey, NodeEntry)],
    settings: &Settings,
    dir: &std::path::Path,
) -> anyhow::Result<()> {
    let mut rows: Vec<&(AddrKey, NodeEntry)> = snapshot
        .iter()
        .filter(|(_, e)| e.state == NodeState::HandshakeFailed)
        .collect();
    // Sorted ascending by handshake_timestamp (Section 8.2).
    rows.sort_by_key(|(_, e)| e.stats.first_version_send_ts.unwrap_or(0));

    let path = out_path(dir, &settings.result_settings.handshake_failed_nodes);
    let mut w = csv_writer(&path)?;
    w.write_record([
        "host",
        "port",
        "network",
        "failure_reason",
        "handshake_timestamp",
        "time_connect",
        "handshake_attempts",
        "freshest_timestamp",
        "attempt_history_json",
    ])?;
    for (key, e) in rows {
        let s = &e.stats;
        w.write_record([
            key.host.as_str(),
            &key.port.to_string(),
            e.network.as_str(),
            e.failure.map(|f| f.as_str()).unwrap_or(""),
            &s.first_version_send_ts
                .map(|v| v.to_string())
                .unwrap_or_default(),
            &s.time_connect_ms.map(|v| v.to_string()).unwrap_or_default(),
            &s.handshake_attempts.to_string(),
            &e.freshest_ts.to_string(),
            &attempt_history_json(e)?,
        ])?;
    }
    w.flush()?;
    Ok(())
}

fn write_unreachable(
    snapshot: &[(AddrKey, NodeEntry)],
    settings: &Settings,
    dir: &std::path::Path,
) -> anyhow::Result<()> {
    let mut rows: Vec<&(AddrKey, NodeEntry)> = snapshot
        .iter()
        .filter(|(_, e)| e.state == NodeState::Unreachable)
        .collect();
    // Sorted ascending by freshest_timestamp (Section 8.3).
    rows.sort_by_key(|(_, e)| e.freshest_ts);

    let path = out_path(dir, &settings.result_settings.unreachable_nodes);
    let mut w = csv_writer(&path)?;
    w.write_record([
        "host",
        "port",
        "network",
        "failure_reason",
        "handshake_attempts",
        "freshest_timestamp",
        "attempt_history_json",
    ])?;
    for (key, e) in rows {
        w.write_record([
            key.host.as_str(),
            &key.port.to_string(),
            e.network.as_str(),
            e.failure.map(|f| f.as_str()).unwrap_or(""),
            &e.stats.handshake_attempts.to_string(),
            &e.freshest_ts.to_string(),
            &attempt_history_json(e)?,
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
    settings: &Settings,
    seeds: &[SeedResult],
    runtime_seconds: i64,
    num_processed: usize,
    dir: &std::path::Path,
    consistent: bool,
    budget_rejected: usize,
    run_complete: bool,
) -> anyhow::Result<()> {
    // Terminal-state breakdowns.
    let mut reachable = NetworkBreakdown::default();
    let mut handshake_failed = NetworkBreakdown::default();
    let mut unreachable = NetworkBreakdown::default();
    let mut list_reachable = Vec::new();
    let mut list_handshake_failed = Vec::new();
    let mut list_unreachable = Vec::new();
    // Failure-reason histograms (Section 7): why nodes failed, at a glance.
    let mut handshake_failed_reasons: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut unreachable_reasons: BTreeMap<&'static str, u64> = BTreeMap::new();

    for (key, e) in snapshot {
        match e.state {
            NodeState::Reachable => {
                reachable.add(e.network);
                list_reachable.push(key.render());
            }
            NodeState::HandshakeFailed => {
                handshake_failed.add(e.network);
                list_handshake_failed.push(key.render());
                let reason = e.failure.map(|f| f.as_str()).unwrap_or("unknown");
                *handshake_failed_reasons.entry(reason).or_insert(0) += 1;
            }
            NodeState::Unreachable => {
                unreachable.add(e.network);
                list_unreachable.push(key.render());
                let reason = e.failure.map(|f| f.as_str()).unwrap_or("unknown");
                *unreachable_reasons.entry(reason).or_insert(0) += 1;
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
        num_from_seed.insert(
            sr.seed.clone(),
            serde_json::to_value(BreakdownJson::from(&bd))?,
        );
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
    root.insert(
        "handshake_failed_reasons".to_string(),
        serde_json::to_value(&handshake_failed_reasons)?,
    );
    root.insert(
        "unreachable_reasons".to_string(),
        serde_json::to_value(&unreachable_reasons)?,
    );
    root.insert("num_advertised".to_string(), Value::from(snapshot.len()));
    root.insert(
        "num_budget_rejected_observations".to_string(),
        Value::from(budget_rejected),
    );
    root.insert(
        "snapshot_consistency".to_string(),
        Value::String(
            if consistent {
                "final_consistent"
            } else {
                "checkpoint_fuzzy"
            }
            .to_string(),
        ),
    );
    root.insert("run_complete".to_string(), Value::Bool(run_complete));
    root.insert(
        "getaddr_sample_semantics".to_string(),
        Value::String("capped partial sample which may be cached for roughly 21-27 hours; not a complete live addrman view".to_string()),
    );
    root.insert(
        "num_nodes_from_seed".to_string(),
        Value::Object(num_from_seed),
    );
    root.insert(
        "list_reachable".to_string(),
        serde_json::to_value(list_reachable)?,
    );
    root.insert(
        "list_handshake_failed".to_string(),
        serde_json::to_value(list_handshake_failed)?,
    );
    root.insert(
        "list_unreachable".to_string(),
        serde_json::to_value(list_unreachable)?,
    );
    root.insert(
        "list_nodes_from_seed".to_string(),
        Value::Object(list_from_seed),
    );

    // Pretty-print with 4-space indent (Section 8.4).
    let path = out_path(dir, &settings.result_settings.crawler_stats);
    let file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)?;
    let mut writer = std::io::BufWriter::new(file);
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut ser = serde_json::Serializer::with_formatter(&mut writer, formatter);
    Value::Object(root).serialize(&mut ser)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn attempt_history_json(entry: &NodeEntry) -> anyhow::Result<String> {
    let values: Vec<Value> = entry
        .attempts
        .iter()
        .map(|a| {
            serde_json::json!({
                "attempt": a.attempt,
                "connect_duration_ms": a.connect_duration_ms,
                "version_send_timestamp": a.version_send_timestamp,
                "outcome": a.outcome,
                "failure": a.failure.map(|f| f.as_str()),
            })
        })
        .collect();
    Ok(serde_json::to_string(&values)?)
}

fn sha256_file(path: &std::path::Path) -> anyhow::Result<String> {
    let bytes = std::fs::read(path)?;
    let digest = Sha256::digest(bytes);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn publish_manifest(run_dir: &std::path::Path, manifest: &Value) -> anyhow::Result<()> {
    let temp = run_dir.join(format!(
        ".manifest.tmp.{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let final_path = run_dir.join("snapshot_manifest.json");
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)?;
    serde_json::to_writer_pretty(&mut file, manifest)?;
    file.write_all(b"\n")?;
    file.flush()?;
    file.sync_all()?;
    std::fs::rename(temp, final_path)?;
    sync_dir(run_dir)
}

#[cfg(unix)]
fn sync_dir(path: &std::path::Path) -> anyhow::Result<()> {
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_dir(_path: &std::path::Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::Cli;
    use clap::Parser;

    #[test]
    fn publishes_header_only_categories_through_manifest() {
        let base = std::env::temp_dir().join(format!(
            "crawler-output-test-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let base_string = base.to_string_lossy().into_owned();
        let settings = Cli::try_parse_from([
            "crawler",
            "--result-path",
            &base_string,
            "--timestamp",
            "test-run",
            "--no-record-addr-responses",
        ])
        .unwrap()
        .into_settings()
        .unwrap();
        std::fs::create_dir_all(&base).unwrap();
        std::fs::create_dir(settings.run_dir()).unwrap();

        write_all(
            &NodeStore::new(),
            &settings,
            &[],
            SnapshotMeta {
                runtime_seconds: 0,
                num_processed: 0,
                durable_addr_event_id: None,
                consistent: true,
                run_complete: true,
            },
        )
        .unwrap();

        let manifest: Value = serde_json::from_slice(
            &std::fs::read(settings.run_dir().join("snapshot_manifest.json")).unwrap(),
        )
        .unwrap();
        let generation = settings.run_dir().join(
            manifest["snapshot_directory"]
                .as_str()
                .expect("snapshot directory in manifest"),
        );
        for file in [
            &settings.result_settings.reachable_nodes,
            &settings.result_settings.handshake_failed_nodes,
            &settings.result_settings.unreachable_nodes,
            &settings.result_settings.crawler_stats,
        ] {
            assert!(generation.join(file).is_file());
        }
        assert_eq!(manifest["run_complete"], true);
        assert_eq!(manifest["snapshot_consistency"], "final_consistent");

        std::fs::remove_dir_all(base).unwrap();
    }
}
