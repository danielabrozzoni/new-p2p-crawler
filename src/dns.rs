//! DNS seeds: resolve hardcoded seed hostnames into initial addresses (Section 3.1).

use std::collections::BTreeSet;
use std::net::IpAddr;
use tokio::net::lookup_host;

/// The hardcoded mainnet DNS seeds (Section 3.1), trailing-dot FQDN form.
pub const SEEDS: &[&str] = &[
    "seed.bitcoin.sipa.be.",
    "dnsseed.bluematt.me.",
    "seed.bitcoin.jonasschnelli.ch.",
    "seed.btc.petertodd.net.",
    "seed.bitcoin.sprovoost.nl.",
    "dnsseed.emzy.de.",
    "seed.bitcoin.wiz.biz.",
    "seed.mainnet.achownodes.xyz.",
];

/// The default mainnet P2P port.
pub const MAINNET_PORT: u16 = 8333;

/// Resolve one seed's A + AAAA records into unique IPs.
///
/// `lookup_host` uses getaddrinfo; we dedup so a host isn't returned once per
/// socktype (Section 3.1).
pub async fn resolve_seed(seed: &str) -> Vec<IpAddr> {
    // getaddrinfo does not want the trailing dot stripped, but strip it to be
    // safe across resolvers; a trailing dot is a valid FQDN either way.
    let host = seed.trim_end_matches('.');
    let query = format!("{host}:{MAINNET_PORT}");
    match lookup_host(query).await {
        Ok(iter) => {
            let mut set = BTreeSet::new();
            for sockaddr in iter {
                set.insert(sockaddr.ip());
            }
            set.into_iter().collect()
        }
        Err(e) => {
            tracing::warn!("DNS resolution failed for seed {seed}: {e}");
            Vec::new()
        }
    }
}

/// Render a resolved IP into the crawler's host-string form (Section 4.2).
pub fn ip_to_host(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            // Collapse IPv4-mapped to dotted quad for consistent classification.
            if let Some(v4) = v6.to_ipv4_mapped() {
                v4.to_string()
            } else {
                v6.to_string()
            }
        }
    }
}
