//! `probe` — connect to an explicit list of nodes and report the outcome of
//! each connect + version handshake, without crawling.
//!
//! Unlike the full crawler (`new-p2p-crawler`), this does not resolve DNS seeds
//! and never follows `addr`/`addrv2` responses: it processes exactly the nodes
//! you give it. It reuses the crawler's connect/handshake machinery (so all the
//! per-network timeouts, retries, Tor/I2P transports and result files behave
//! identically) with peer discovery switched off.
//!
//! Nodes come from positional arguments, `--nodes-file`, and/or stdin, one per
//! line. Accepted forms: `1.2.3.4`, `1.2.3.4:8333`, `[2001:db8::1]:8333`,
//! `2001:db8::1`, `<onion>.onion[:port]`, `<b32>.b32.i2p[:port]`. A host with no
//! port uses `--port` (default 8333). Blank lines and `#` comments are ignored.

use clap::Parser;
use new_p2p_crawler::address::{classify, NetworkType};
use new_p2p_crawler::crawler::{now_epoch, Crawler};
use new_p2p_crawler::settings::{CommonArgs, Settings};
use new_p2p_crawler::store::{AddrKey, NodeEntry, NodeState, NodeStore};
use new_p2p_crawler::{logging, output};
use std::collections::BTreeMap;
use std::process::ExitCode;
use std::sync::Arc;

const EXIT_CONFIG_ERROR: u8 = 2;

#[derive(Parser, Debug)]
#[command(
    name = "probe",
    about = "Directly connect to a list of Bitcoin nodes and report handshake outcomes"
)]
struct ProbeCli {
    #[command(flatten)]
    common: CommonArgs,

    /// Nodes to probe (host, host:port, or [ipv6]:port). Repeatable.
    #[arg(value_name = "NODE")]
    nodes: Vec<String>,

    /// File with one node per line (# comments and blank lines ignored)
    #[arg(long, value_name = "PATH", help_heading = "Nodes")]
    nodes_file: Option<String>,

    /// Default port for nodes given without one
    #[arg(long, default_value_t = 8333, help_heading = "Nodes")]
    port: u16,
}

fn main() -> ExitCode {
    let cli = ProbeCli::parse();

    // Collect and parse the target node list before touching anything else.
    let raw = match gather_raw_nodes(&cli) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cannot read nodes: {e}");
            return ExitCode::from(EXIT_CONFIG_ERROR);
        }
    };
    if raw.is_empty() {
        eprintln!(
            "no nodes given: pass them as arguments, via --nodes-file, or on stdin (one per line)"
        );
        return ExitCode::from(EXIT_CONFIG_ERROR);
    }

    let settings = match cli.common.into_settings(0, None, true) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("configuration error: {e}");
            return ExitCode::from(EXIT_CONFIG_ERROR);
        }
    };

    // Parse each node string; classify and drop the unusable ones up front.
    let mut targets: Vec<AddrKey> = Vec::new();
    for s in &raw {
        match parse_node(s, cli.port) {
            Some(key) if classify(&key.host) != NetworkType::Unknown => targets.push(key),
            Some(key) => eprintln!("skipping unrecognised address: {}", key.render()),
            None => eprintln!("skipping unparseable node: {s}"),
        }
    }
    if targets.is_empty() {
        eprintln!("no usable nodes after parsing");
        return ExitCode::from(EXIT_CONFIG_ERROR);
    }

    if let Err(e) = std::fs::create_dir_all(settings.run_dir()) {
        eprintln!(
            "cannot create results directory {}: {e}",
            settings.run_dir().display()
        );
        return ExitCode::from(EXIT_CONFIG_ERROR);
    }

    let _guard = logging::init(&settings);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    runtime.block_on(async_main(settings, targets))
}

async fn async_main(settings: Arc<Settings>, targets: Vec<AddrKey>) -> ExitCode {
    let store = Arc::new(NodeStore::new());
    // No addr-response log: probe mode never issues getaddr.
    let crawler = Arc::new(Crawler::new(Arc::clone(&store), Arc::clone(&settings), None));

    // Seed exactly the provided nodes (dedup handled by the store).
    let now = now_epoch();
    let mut seeded = 0usize;
    for key in targets {
        if crawler.store.observe_seed(key.clone(), now).newly_queued {
            crawler.enqueue_seed(key);
            seeded += 1;
        }
    }
    tracing::info!("probing {seeded} node(s)");

    Arc::clone(&crawler).run().await;

    let runtime_seconds = crawler.start_clock.elapsed().as_secs() as i64;
    let num_processed = crawler.num_processed();

    let reachable = store.count_state(NodeState::Reachable);
    let handshake_failed = store.count_state(NodeState::HandshakeFailed);
    let unreachable = store.count_state(NodeState::Unreachable);
    tracing::info!(
        "probe complete: processed={num_processed} reachable={reachable} handshake_failed={handshake_failed} unreachable={unreachable} runtime={runtime_seconds}s"
    );

    // Reuse the crawler's result files (no seeds → empty per-seed section).
    if let Err(e) = output::write_all(&store, &settings, &[], runtime_seconds, num_processed) {
        tracing::error!("failed to write output: {e}");
        return ExitCode::FAILURE;
    }

    print_report(&store);
    tracing::info!("result files written to {}", settings.run_dir().display());

    ExitCode::SUCCESS
}

/// Gather the raw node strings from args, `--nodes-file`, and — only if neither
/// supplied any — stdin.
fn gather_raw_nodes(cli: &ProbeCli) -> std::io::Result<Vec<String>> {
    let mut out: Vec<String> = cli.nodes.clone();

    if let Some(path) = &cli.nodes_file {
        let content = std::fs::read_to_string(path)?;
        out.extend(split_lines(&content));
    }

    if out.is_empty() && !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        out.extend(split_lines(&buf));
    }

    Ok(out)
}

/// Split file/stdin content into node tokens, dropping blanks and `#` comments.
fn split_lines(content: &str) -> Vec<String> {
    content
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect()
}

/// Parse one node string into an [`AddrKey`], applying `default_port` when the
/// address carries none. IPv6 addresses need brackets to include a port.
fn parse_node(s: &str, default_port: u16) -> Option<AddrKey> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    // Bracketed IPv6: `[host]` or `[host]:port`.
    if let Some(rest) = s.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if after.is_empty() => default_port,
            None => return None,
        };
        return Some(AddrKey::new(host, port));
    }

    // Bare IPv6 literal (no brackets, no port).
    if s.parse::<std::net::Ipv6Addr>().is_ok() {
        return Some(AddrKey::new(s, default_port));
    }

    // `host:port` for IPv4 / onion / i2p / hostnames; else host with default port.
    if let Some((host, port_str)) = s.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return Some(AddrKey::new(host, port));
        }
    }
    Some(AddrKey::new(s, default_port))
}

/// Print a human-readable per-node report and failure-reason histograms to
/// stdout — the "why did this fail" summary that motivates the probe.
fn print_report(store: &NodeStore) {
    let mut snapshot = store.snapshot();
    snapshot.sort_by_key(|(key, _)| key.render());

    let mut reason_hist: BTreeMap<&'static str, u64> = BTreeMap::new();

    println!("\n=== Probe results ===");
    for (key, e) in &snapshot {
        let line = describe_node(key, e);
        if let Some(f) = e.failure {
            *reason_hist.entry(f.as_str()).or_insert(0) += 1;
        }
        println!("{line}");
    }

    if !reason_hist.is_empty() {
        println!("\n=== Failure reasons ===");
        for (reason, count) in &reason_hist {
            println!("{count:>5}  {reason}");
        }
    }
}

/// One report line for a node: address, result, and the salient detail
/// (user agent for reachable, failure reason otherwise).
fn describe_node(key: &AddrKey, e: &NodeEntry) -> String {
    let addr = key.render();
    let net = e.network.as_str();
    let attempts = e.stats.handshake_attempts;
    match e.state {
        NodeState::Reachable => {
            let h = e.handshake.as_ref();
            let ua = h.map(|h| h.user_agent.as_str()).unwrap_or("");
            let connect = e
                .stats
                .time_connect_ms
                .map(|ms| format!("{ms}ms"))
                .unwrap_or_default();
            format!("REACHABLE         {addr}  ({net})  connect={connect}  ua={ua:?}")
        }
        NodeState::HandshakeFailed => {
            let reason = e.failure.map(|f| f.as_str()).unwrap_or("unknown");
            format!("HANDSHAKE_FAILED  {addr}  ({net})  reason={reason}  attempts={attempts}")
        }
        NodeState::Unreachable => {
            let reason = e.failure.map(|f| f.as_str()).unwrap_or("unknown");
            format!("UNREACHABLE       {addr}  ({net})  reason={reason}  attempts={attempts}")
        }
        other => format!("{other:?}          {addr}  ({net})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(host: &str, port: u16) -> AddrKey {
        AddrKey::new(host, port)
    }

    #[test]
    fn parses_ipv4_with_and_without_port() {
        assert_eq!(parse_node("1.2.3.4:8333", 8333), Some(key("1.2.3.4", 8333)));
        assert_eq!(parse_node("1.2.3.4", 8333), Some(key("1.2.3.4", 8333)));
        assert_eq!(parse_node("1.2.3.4:1234", 8333), Some(key("1.2.3.4", 1234)));
    }

    #[test]
    fn parses_bracketed_ipv6() {
        assert_eq!(
            parse_node("[2001:db8::1]:8333", 8333),
            Some(key("2001:db8::1", 8333))
        );
        assert_eq!(
            parse_node("[2001:db8::1]", 8333),
            Some(key("2001:db8::1", 8333))
        );
    }

    #[test]
    fn parses_bare_ipv6_with_default_port() {
        // Unbracketed IPv6 has no port; the trailing group is not mistaken for one.
        assert_eq!(
            parse_node("2001:db8::1", 8333),
            Some(key("2001:db8::1", 8333))
        );
        assert_eq!(parse_node("fc00::1", 8333), Some(key("fc00::1", 8333)));
    }

    #[test]
    fn parses_onion_and_i2p() {
        let onion = format!("{}.onion", "a".repeat(56));
        assert_eq!(
            parse_node(&format!("{onion}:8333"), 8333),
            Some(key(&onion, 8333))
        );
        let i2p = format!("{}.b32.i2p", "b".repeat(52));
        assert_eq!(parse_node(&i2p, 8333), Some(key(&i2p, 8333)));
    }

    #[test]
    fn split_lines_drops_comments_and_blanks() {
        let content = "1.2.3.4\n\n# a comment\n5.6.7.8:8333  # trailing\n";
        assert_eq!(split_lines(content), vec!["1.2.3.4", "5.6.7.8:8333"]);
    }
}
