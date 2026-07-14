//! Immutable settings tree built from CLI args + env (Section 2.2, 8.4, 9).

use clap::{Args, Parser};
use serde::Serialize;

pub const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Per-network timeout set (seconds), Section 6.1.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Timeouts {
    pub connect: u64,
    pub message: u64,
    pub getaddr: u64,
    pub getaddr_idle: u64,
}

/// Fully-resolved, immutable settings (Section 2.2).
#[derive(Debug, Clone, Serialize)]
pub struct Settings {
    pub version_info: VersionInfo,
    pub delay_start: u64,
    pub max_nodes: Option<usize>,
    pub enabled_networks: EnabledNetworks,
    pub strict_networks: bool,
    pub freshness_threshold: i64,
    pub record_addr_responses: bool,
    pub concurrency: Concurrency,
    pub node_settings: NodeSettings,
    pub result_settings: ResultSettings,
    #[serde(skip)]
    pub dry_run: bool,
    #[serde(skip)]
    pub log_level: String,
    #[serde(skip)]
    pub store_debug_log: bool,
    #[serde(skip)]
    pub retry_on_timeout: bool,
    /// Re-write the snapshot result files this often (seconds); 0 disables.
    #[serde(skip)]
    pub checkpoint_interval: i64,
    /// Direct-probe mode: process exactly the seeded nodes and skip peer
    /// discovery (getaddr), so no new addresses are ever enqueued. Set by the
    /// `probe` binary; always false for the full crawler.
    #[serde(skip)]
    pub probe_mode: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct VersionInfo {
    pub version: String,
    pub extra: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct EnabledNetworks {
    pub ipv4: bool,
    pub ipv6: bool,
    pub tor: bool,
    pub i2p: bool,
    pub cjdns: bool,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Concurrency {
    pub ip: usize,
    pub tor: usize,
    pub i2p: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeSettings {
    pub timeouts: TimeoutSettings,
    pub handshake_attempts: u32,
    pub network_settings: NetworkEndpoints,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct TimeoutSettings {
    pub ip: Timeouts,
    pub tor: Timeouts,
    pub i2p: Timeouts,
    pub cjdns: Timeouts,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkEndpoints {
    pub tor_proxy_host: String,
    pub tor_proxy_port: u16,
    pub i2p_sam_host: String,
    pub i2p_sam_port: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResultSettings {
    pub path: String,
    pub timestamp: String,
    pub reachable_nodes: String,
    pub handshake_failed_nodes: String,
    pub unreachable_nodes: String,
    pub crawler_stats: String,
    pub addr_responses: String,
}

impl Settings {
    /// The timeouts for a given network type.
    pub fn timeouts_for(&self, net: crate::address::NetworkType) -> Timeouts {
        use crate::address::NetworkType::*;
        match net {
            Ipv4 | Ipv6 => self.node_settings.timeouts.ip,
            Cjdns => self.node_settings.timeouts.cjdns,
            OnionV2 | OnionV3 => self.node_settings.timeouts.tor,
            I2p => self.node_settings.timeouts.i2p,
            Unknown => self.node_settings.timeouts.ip,
        }
    }

    /// Whether a network type is enabled for this run (Section 9).
    pub fn is_enabled(&self, net: crate::address::NetworkType) -> bool {
        use crate::address::NetworkType::*;
        match net {
            Ipv4 => self.enabled_networks.ipv4,
            Ipv6 => self.enabled_networks.ipv6,
            Cjdns => self.enabled_networks.cjdns,
            OnionV2 | OnionV3 => self.enabled_networks.tor,
            I2p => self.enabled_networks.i2p,
            Unknown => false,
        }
    }

    /// Per-run output directory: `<path>/<prefix>`. Each crawl gets its own
    /// directory named after the timestamp it started at, so runs are not
    /// mixed together.
    pub fn run_dir(&self) -> std::path::PathBuf {
        std::path::Path::new(&self.result_settings.path).join(self.prefix())
    }

    /// Full path of an output file under this run's output directory.
    pub fn output_path(&self, file: &str) -> std::path::PathBuf {
        self.run_dir().join(file)
    }

    pub fn prefix(&self) -> String {
        format!(
            "{}_v{}",
            self.result_settings.timestamp, self.version_info.version
        )
    }
}

/// Raw CLI definition (Section 9). Env-var fallbacks handled by clap.
#[derive(Parser, Debug)]
#[command(name = "new-p2p-crawler", about = "Bitcoin mainnet P2P network crawler")]
pub struct Cli {
    #[command(flatten)]
    pub common: CommonArgs,

    /// Stop after processing at most N nodes (testing cap; default unlimited)
    #[arg(long, value_name = "N", help_heading = "Crawl behavior")]
    max_nodes: Option<usize>,
    /// Skip addresses last-seen older than this; seconds or 2d/48h; 0 disables
    #[arg(long, default_value = "2d", help_heading = "Crawl behavior")]
    freshness_threshold: String,
    /// Disable the freshness filter (shorthand for --freshness-threshold 0)
    #[arg(long, help_heading = "Crawl behavior")]
    no_freshness_filter: bool,
}

/// Args shared by the crawler and the `probe` binary (timeouts, concurrency,
/// per-node behaviour, networks, endpoints, output). Flattened into each
/// binary's own [`Parser`] so defaults live in exactly one place.
#[derive(Args, Debug)]
pub struct CommonArgs {
    // ---- Timeouts (seconds). connect / message / getaddr / getaddr-idle ----
    /// IPv4/IPv6 TCP connect timeout (s)
    #[arg(long, default_value_t = 3, help_heading = "Timeouts (seconds)")]
    ip_connect_timeout: u64,
    /// IPv4/IPv6 wait for one reply, e.g. the peer's version (s)
    #[arg(long, default_value_t = 30, help_heading = "Timeouts (seconds)")]
    ip_message_timeout: u64,
    /// IPv4/IPv6 hard budget for the whole getaddr collection loop (s)
    #[arg(long, default_value_t = 70, help_heading = "Timeouts (seconds)")]
    ip_getaddr_timeout: u64,
    /// IPv4/IPv6 idle timeout per receive inside the getaddr loop (s)
    #[arg(long, default_value_t = 3, help_heading = "Timeouts (seconds)")]
    ip_getaddr_idle_timeout: u64,

    /// Tor connect timeout, incl. SOCKS5 negotiation (s)
    #[arg(long, default_value_t = 100, help_heading = "Timeouts (seconds)")]
    tor_connect_timeout: u64,
    /// Tor wait for one reply (s)
    #[arg(long, default_value_t = 40, help_heading = "Timeouts (seconds)")]
    tor_message_timeout: u64,
    /// Tor hard budget for the getaddr loop (s)
    #[arg(long, default_value_t = 90, help_heading = "Timeouts (seconds)")]
    tor_getaddr_timeout: u64,
    /// Tor idle timeout per getaddr receive (s)
    #[arg(long, default_value_t = 5, help_heading = "Timeouts (seconds)")]
    tor_getaddr_idle_timeout: u64,

    /// I2P connect timeout, incl. SAM stream setup (s)
    #[arg(long, default_value_t = 30, help_heading = "Timeouts (seconds)")]
    i2p_connect_timeout: u64,
    /// I2P wait for one reply (s)
    #[arg(long, default_value_t = 80, help_heading = "Timeouts (seconds)")]
    i2p_message_timeout: u64,
    /// I2P hard budget for the getaddr loop (s)
    #[arg(long, default_value_t = 170, help_heading = "Timeouts (seconds)")]
    i2p_getaddr_timeout: u64,
    /// I2P idle timeout per getaddr receive (s)
    #[arg(long, default_value_t = 8, help_heading = "Timeouts (seconds)")]
    i2p_getaddr_idle_timeout: u64,

    /// CJDNS TCP connect timeout (s)
    #[arg(long, default_value_t = 10, help_heading = "Timeouts (seconds)")]
    cjdns_connect_timeout: u64,
    /// CJDNS wait for one reply (s)
    #[arg(long, default_value_t = 30, help_heading = "Timeouts (seconds)")]
    cjdns_message_timeout: u64,
    /// CJDNS hard budget for the getaddr loop (s)
    #[arg(long, default_value_t = 70, help_heading = "Timeouts (seconds)")]
    cjdns_getaddr_timeout: u64,
    /// CJDNS idle timeout per getaddr receive (s)
    #[arg(long, default_value_t = 3, help_heading = "Timeouts (seconds)")]
    cjdns_getaddr_idle_timeout: u64,

    // ---- Concurrency ----
    /// Concurrent IPv4/IPv6/CJDNS workers
    #[arg(long, default_value_t = 512, help_heading = "Concurrency")]
    ip_concurrency: usize,
    /// Concurrent Tor workers
    #[arg(long, default_value_t = 64, help_heading = "Concurrency")]
    tor_concurrency: usize,
    /// Concurrent I2P workers
    #[arg(long, default_value_t = 32, help_heading = "Concurrency")]
    i2p_concurrency: usize,

    // ---- Crawl behavior ----
    /// Run network preflight probes, print the table, and exit without crawling
    #[arg(long, help_heading = "Crawl behavior")]
    dry_run: bool,
    /// Total version-handshake attempts per node before giving up
    #[arg(long, default_value_t = 3, help_heading = "Crawl behavior")]
    handshake_attempts: u32,
    /// Seconds to sleep before crawling (for Tor/I2P side-service warm-up)
    #[arg(long, default_value_t = 0, help_heading = "Crawl behavior")]
    delay_start: u64,
    /// Log every addr/addrv2 response to a CSV (on by default; largest output)
    #[arg(
        long,
        default_value_t = true,
        overrides_with = "no_record_addr_responses",
        help_heading = "Crawl behavior"
    )]
    record_addr_responses: bool,
    /// Do not record addr responses (disables the on-by-default recording)
    #[arg(long, help_heading = "Crawl behavior")]
    no_record_addr_responses: bool,
    /// Also retry a node that stayed silent for the whole handshake deadline
    #[arg(long, help_heading = "Crawl behavior")]
    retry_on_timeout: bool,

    // ---- Networks (each crawled by default; pass --no-<net> to disable) ----
    /// Crawl IPv4 (default on)
    #[arg(long, overrides_with = "no_ipv4", help_heading = "Networks")]
    ipv4: bool,
    /// Disable IPv4
    #[arg(long, overrides_with = "ipv4", help_heading = "Networks")]
    no_ipv4: bool,
    /// Crawl IPv6 (default on)
    #[arg(long, overrides_with = "no_ipv6", help_heading = "Networks")]
    ipv6: bool,
    /// Disable IPv6
    #[arg(long, overrides_with = "ipv6", help_heading = "Networks")]
    no_ipv6: bool,
    /// Crawl Tor onion v2/v3 — needs a SOCKS5 proxy (default on)
    #[arg(long, overrides_with = "no_tor", help_heading = "Networks")]
    tor: bool,
    /// Disable Tor
    #[arg(long, overrides_with = "tor", help_heading = "Networks")]
    no_tor: bool,
    /// Crawl I2P — needs a SAM router (default on)
    #[arg(long, overrides_with = "no_i2p", help_heading = "Networks")]
    i2p: bool,
    /// Disable I2P
    #[arg(long, overrides_with = "i2p", help_heading = "Networks")]
    no_i2p: bool,
    /// Crawl CJDNS — needs a local fc00::/8 interface (default on)
    #[arg(long, overrides_with = "no_cjdns", help_heading = "Networks")]
    cjdns: bool,
    /// Disable CJDNS
    #[arg(long, overrides_with = "cjdns", help_heading = "Networks")]
    no_cjdns: bool,
    /// Abort at startup if any enabled network fails its preflight probe
    #[arg(long, help_heading = "Networks")]
    strict_networks: bool,

    // ---- Endpoints ----
    /// SOCKS5 proxy host for Tor
    #[arg(long, default_value = "127.0.0.1", help_heading = "Endpoints")]
    tor_proxy_host: String,
    /// SOCKS5 proxy port for Tor
    #[arg(long, default_value_t = 9050, help_heading = "Endpoints")]
    tor_proxy_port: u16,
    /// SAM router host for I2P
    #[arg(long, default_value = "127.0.0.1", help_heading = "Endpoints")]
    i2p_sam_host: String,
    /// SAM router port for I2P
    #[arg(long, default_value_t = 7656, help_heading = "Endpoints")]
    i2p_sam_port: u16,

    // ---- Output & logging ----
    /// Directory for result files (created if missing)
    #[arg(long, default_value = "results", help_heading = "Output & logging")]
    result_path: String,
    /// Output filename prefix timestamp (default: crawl start, UTC)
    #[arg(long, help_heading = "Output & logging")]
    timestamp: Option<String>,
    /// Extra version string recorded in the stats JSON
    #[arg(long, help_heading = "Output & logging")]
    extra_version_info: Option<String>,
    /// Console log level: error, warn, info, debug, trace
    #[arg(long, default_value = "INFO", help_heading = "Output & logging")]
    log_level: String,
    /// Do not write the plain-text debug log file (written by default)
    #[arg(long, help_heading = "Output & logging")]
    no_store_debug_log: bool,
    /// Re-write result files this often as a checkpoint; seconds or 5m/1h; 0 disables
    #[arg(long, default_value = "10m", help_heading = "Output & logging")]
    checkpoint_interval: String,
}

impl Cli {
    /// Build the immutable [`Settings`] tree from the parsed crawler args.
    pub fn into_settings(self) -> anyhow::Result<Settings> {
        let freshness_threshold = if self.no_freshness_filter {
            0
        } else {
            parse_duration(&self.freshness_threshold)?
        };
        self.common
            .into_settings(freshness_threshold, self.max_nodes, false)
    }
}

impl CommonArgs {
    /// Build the immutable [`Settings`] tree from the shared args plus the
    /// caller-supplied crawl-only knobs. `probe_mode` is set by the `probe`
    /// binary to disable peer discovery (getaddr).
    pub fn into_settings(
        self,
        freshness_threshold: i64,
        max_nodes: Option<usize>,
        probe_mode: bool,
    ) -> anyhow::Result<Settings> {
        let timestamp = self.timestamp.unwrap_or_else(|| {
            chrono::Utc::now().format("%Y-%m-%dT%H-%M-%SZ").to_string()
        });

        let record_addr_responses = self.record_addr_responses && !self.no_record_addr_responses;

        let checkpoint_interval = parse_duration(&self.checkpoint_interval)?;

        // Networks are on by default; `--<net>`/`--no-<net>` override each other,
        // so the negative flag alone decides enablement.
        let enabled_networks = EnabledNetworks {
            ipv4: self.ipv4 || !self.no_ipv4,
            ipv6: self.ipv6 || !self.no_ipv6,
            tor: self.tor || !self.no_tor,
            i2p: self.i2p || !self.no_i2p,
            cjdns: self.cjdns || !self.no_cjdns,
        };

        Ok(Settings {
            version_info: VersionInfo {
                version: PKG_VERSION.to_string(),
                extra: self.extra_version_info,
            },
            delay_start: self.delay_start,
            max_nodes,
            enabled_networks,
            strict_networks: self.strict_networks,
            freshness_threshold,
            record_addr_responses,
            concurrency: Concurrency {
                ip: self.ip_concurrency,
                tor: self.tor_concurrency,
                i2p: self.i2p_concurrency,
            },
            node_settings: NodeSettings {
                timeouts: TimeoutSettings {
                    ip: Timeouts {
                        connect: self.ip_connect_timeout,
                        message: self.ip_message_timeout,
                        getaddr: self.ip_getaddr_timeout,
                        getaddr_idle: self.ip_getaddr_idle_timeout,
                    },
                    tor: Timeouts {
                        connect: self.tor_connect_timeout,
                        message: self.tor_message_timeout,
                        getaddr: self.tor_getaddr_timeout,
                        getaddr_idle: self.tor_getaddr_idle_timeout,
                    },
                    i2p: Timeouts {
                        connect: self.i2p_connect_timeout,
                        message: self.i2p_message_timeout,
                        getaddr: self.i2p_getaddr_timeout,
                        getaddr_idle: self.i2p_getaddr_idle_timeout,
                    },
                    cjdns: Timeouts {
                        connect: self.cjdns_connect_timeout,
                        message: self.cjdns_message_timeout,
                        getaddr: self.cjdns_getaddr_timeout,
                        getaddr_idle: self.cjdns_getaddr_idle_timeout,
                    },
                },
                handshake_attempts: self.handshake_attempts,
                network_settings: NetworkEndpoints {
                    tor_proxy_host: self.tor_proxy_host,
                    tor_proxy_port: self.tor_proxy_port,
                    i2p_sam_host: self.i2p_sam_host,
                    i2p_sam_port: self.i2p_sam_port,
                },
            },
            result_settings: ResultSettings {
                path: self.result_path,
                timestamp,
                reachable_nodes: "reachable_nodes.csv".to_string(),
                handshake_failed_nodes: "handshake_failed_nodes.csv".to_string(),
                unreachable_nodes: "unreachable_nodes.csv".to_string(),
                crawler_stats: "crawler_stats.json".to_string(),
                addr_responses: "addr_responses.csv".to_string(),
            },
            dry_run: self.dry_run,
            log_level: self.log_level,
            store_debug_log: !self.no_store_debug_log,
            retry_on_timeout: self.retry_on_timeout,
            checkpoint_interval,
            probe_mode,
        })
    }
}

/// Parse a duration in seconds or human form (`2d`, `48h`, `30m`, `10s`).
fn parse_duration(s: &str) -> anyhow::Result<i64> {
    let s = s.trim();
    if let Ok(n) = s.parse::<i64>() {
        return Ok(n);
    }
    let (num, unit) = s.split_at(
        s.find(|c: char| !c.is_ascii_digit())
            .ok_or_else(|| anyhow::anyhow!("invalid duration: {s}"))?,
    );
    let n: i64 = num
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid duration: {s}"))?;
    let mult = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => anyhow::bail!("unknown duration unit: {unit}"),
    };
    Ok(n * mult)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_parsing() {
        assert_eq!(parse_duration("172800").unwrap(), 172800);
        assert_eq!(parse_duration("2d").unwrap(), 172800);
        assert_eq!(parse_duration("48h").unwrap(), 172800);
        assert_eq!(parse_duration("0").unwrap(), 0);
        assert!(parse_duration("2x").is_err());
    }
}
