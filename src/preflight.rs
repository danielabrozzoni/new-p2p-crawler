//! Network preflight probes and the dry-run table (Section 2.5).

use crate::dns::{resolve_seed, ip_to_host, MAINNET_PORT, SEEDS};
use crate::settings::Settings;
use crate::transport::{connect_tcp, sam_probe, socks5_probe};
use std::time::Duration;

/// The result of one network's preflight probe.
#[derive(Debug, Clone)]
pub enum ProbeResult {
    Reachable,
    Unreachable(String),
    Skipped,
}

impl ProbeResult {
    fn is_ok(&self) -> bool {
        matches!(self, ProbeResult::Reachable)
    }

    fn render(&self) -> String {
        match self {
            ProbeResult::Reachable => "reachable".to_string(),
            ProbeResult::Unreachable(why) => format!("unreachable ({why})"),
            ProbeResult::Skipped => "skipped".to_string(),
        }
    }
}

/// One row of the preflight table.
pub struct PreflightRow {
    pub network: &'static str,
    pub enabled: bool,
    pub result: ProbeResult,
}

/// Run every enabled network's preflight probe (Section 2.5).
pub async fn run_preflight(settings: &Settings) -> Vec<PreflightRow> {
    let en = &settings.enabled_networks;
    let to = &settings.node_settings.timeouts;
    let ns = &settings.node_settings.network_settings;

    let mut rows = Vec::new();

    // ipv4
    rows.push(PreflightRow {
        network: "ipv4",
        enabled: en.ipv4,
        result: if en.ipv4 {
            probe_ip(false, Duration::from_secs(to.ip.connect)).await
        } else {
            ProbeResult::Skipped
        },
    });

    // ipv6
    rows.push(PreflightRow {
        network: "ipv6",
        enabled: en.ipv6,
        result: if en.ipv6 {
            probe_ip(true, Duration::from_secs(to.ip.connect)).await
        } else {
            ProbeResult::Skipped
        },
    });

    // tor
    rows.push(PreflightRow {
        network: "tor",
        enabled: en.tor,
        result: if en.tor {
            match socks5_probe(
                &ns.tor_proxy_host,
                ns.tor_proxy_port,
                Duration::from_secs(to.tor.connect),
            )
            .await
            {
                Ok(()) => ProbeResult::Reachable,
                Err(e) => ProbeResult::Unreachable(format!(
                    "SOCKS5 proxy {}:{}: {e}",
                    ns.tor_proxy_host, ns.tor_proxy_port
                )),
            }
        } else {
            ProbeResult::Skipped
        },
    });

    // i2p
    rows.push(PreflightRow {
        network: "i2p",
        enabled: en.i2p,
        result: if en.i2p {
            match sam_probe(
                &ns.i2p_sam_host,
                ns.i2p_sam_port,
                Duration::from_secs(to.i2p.connect),
            )
            .await
            {
                Ok(()) => ProbeResult::Reachable,
                Err(e) => ProbeResult::Unreachable(format!(
                    "SAM router {}:{}: {e}",
                    ns.i2p_sam_host, ns.i2p_sam_port
                )),
            }
        } else {
            ProbeResult::Skipped
        },
    });

    // cjdns
    rows.push(PreflightRow {
        network: "cjdns",
        enabled: en.cjdns,
        result: if en.cjdns {
            probe_cjdns()
        } else {
            ProbeResult::Skipped
        },
    });

    rows
}

/// Probe IPv4 or IPv6 by resolving seeds and trying up to a few node:8333.
async fn probe_ip(want_ipv6: bool, connect_timeout: Duration) -> ProbeResult {
    let mut tried = 0usize;
    for seed in SEEDS {
        if tried >= 5 {
            break;
        }
        let ips = resolve_seed(seed).await;
        for ip in ips {
            let is_v6 = ip.is_ipv6() && ip.to_string().contains(':');
            if is_v6 != want_ipv6 {
                continue;
            }
            tried += 1;
            let host = ip_to_host(ip);
            if connect_tcp(&host, MAINNET_PORT, connect_timeout).await.is_ok() {
                return ProbeResult::Reachable;
            }
            if tried >= 5 {
                break;
            }
        }
    }
    if tried == 0 {
        ProbeResult::Unreachable("no seed addresses resolved for this family".to_string())
    } else {
        ProbeResult::Unreachable("no resolved node accepted a connection".to_string())
    }
}

/// Best-effort check for a local `fc00::/8` interface address (Section 2.5).
fn probe_cjdns() -> ProbeResult {
    // Enumerate local interface addresses; look for one in fc00::/8.
    match local_ipv6_addrs() {
        Ok(addrs) => {
            if addrs.iter().any(|a| a.octets()[0] == 0xfc) {
                ProbeResult::Reachable
            } else {
                ProbeResult::Unreachable("no cjdns interface".to_string())
            }
        }
        Err(_) => ProbeResult::Unreachable("no cjdns interface".to_string()),
    }
}

/// Enumerate local IPv6 interface addresses via `getifaddrs`-style parsing.
/// Best-effort: reads `/proc/net/if_inet6` on Linux, empty elsewhere.
fn local_ipv6_addrs() -> std::io::Result<Vec<std::net::Ipv6Addr>> {
    let content = std::fs::read_to_string("/proc/net/if_inet6")?;
    let mut out = Vec::new();
    for line in content.lines() {
        // First field is 32 hex chars of the address.
        if let Some(hex) = line.split_whitespace().next() {
            if hex.len() == 32 {
                if let Ok(bytes) = decode_hex16(hex) {
                    out.push(std::net::Ipv6Addr::from(bytes));
                }
            }
        }
    }
    Ok(out)
}

fn decode_hex16(s: &str) -> Result<[u8; 16], ()> {
    if s.len() != 32 {
        return Err(());
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| ())?;
    }
    Ok(out)
}

/// Print the preflight table and return true iff every enabled network is reachable.
pub fn print_table(rows: &[PreflightRow]) -> bool {
    println!("Network  Enabled  Probe result");
    let mut all_ok = true;
    for row in rows {
        let enabled = if row.enabled { "yes" } else { "no" };
        println!("{:<8} {:<8} {}", row.network, enabled, row.result.render());
        if row.enabled && !row.result.is_ok() {
            all_ok = false;
        }
    }
    all_ok
}

/// Whether any enabled network failed its probe (for --strict-networks).
pub fn any_enabled_failed(rows: &[PreflightRow]) -> Vec<String> {
    rows.iter()
        .filter(|r| r.enabled && !r.result.is_ok())
        .map(|r| format!("{}: {}", r.network, r.result.render()))
        .collect()
}
