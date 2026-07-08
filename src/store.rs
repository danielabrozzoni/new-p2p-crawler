//! The node store — the central data structure (Section 2.1).

use crate::address::{classify, render_addr, NetworkType};
use crate::protocol::VersionData;
use dashmap::DashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Key identifying a distinct address; network type is derived from host.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AddrKey {
    pub host: String,
    pub port: u16,
}

impl AddrKey {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        AddrKey {
            host: host.into(),
            port,
        }
    }

    pub fn render(&self) -> String {
        render_addr(&self.host, self.port)
    }
}

/// Node lifecycle state (Section 2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    Queued,
    Processing,
    Reachable,
    HandshakeFailed,
    Unreachable,
    StaleDiscarded,
}

/// Peer metadata retained from a successful handshake (Section 4.4).
#[derive(Debug, Clone)]
pub struct HandshakeData {
    pub version: i32,
    pub services: u64,
    pub user_agent: String,
    pub latest_block: i32,
    pub relay: bool,
    pub version_reply_timestamp_remote: i64,
    /// epoch s when `version` was sent (Section 7.1).
    pub handshake_timestamp: i64,
    /// handshake duration in ms.
    pub handshake_duration_ms: u64,
}

impl HandshakeData {
    pub fn from_version(v: &VersionData, handshake_timestamp: i64, duration_ms: u64) -> Self {
        HandshakeData {
            version: v.version,
            services: v.services,
            user_agent: v.user_agent.clone(),
            latest_block: v.latest_block,
            relay: v.relay,
            version_reply_timestamp_remote: v.timestamp,
            handshake_timestamp,
            handshake_duration_ms: duration_ms,
        }
    }
}

/// Per-node timing / counters / advertised-addr breakdown (Section 2.1, 7).
#[derive(Debug, Clone, Default)]
pub struct NodeStats {
    /// TCP/SOCKS5/SAM connect time in ms (set once connected).
    pub time_connect_ms: Option<u64>,
    /// Number of processing iterations (connect / version-send attempts).
    pub handshake_attempts: u32,
    /// epoch s of the first `version` send (Section 7.4 handshake_timestamp).
    pub first_version_send_ts: Option<i64>,
    // Per-node advertised-address breakdown (Section 3.3 step 4).
    pub advertised_total: u64,
    pub advertised_ipv4: u64,
    pub advertised_ipv6: u64,
    pub advertised_onion_v2: u64,
    pub advertised_onion_v3: u64,
    pub advertised_i2p: u64,
    pub advertised_cjdns: u64,
    pub advertised_unknown: u64,
}

impl NodeStats {
    pub fn record_advertised(&mut self, net: NetworkType) {
        self.advertised_total += 1;
        match net {
            NetworkType::Ipv4 => self.advertised_ipv4 += 1,
            NetworkType::Ipv6 => self.advertised_ipv6 += 1,
            NetworkType::OnionV2 => self.advertised_onion_v2 += 1,
            NetworkType::OnionV3 => self.advertised_onion_v3 += 1,
            NetworkType::I2p => self.advertised_i2p += 1,
            NetworkType::Cjdns => self.advertised_cjdns += 1,
            NetworkType::Unknown => self.advertised_unknown += 1,
        }
    }
}

/// A stored node entry (Section 2.1).
#[derive(Debug, Clone)]
pub struct NodeEntry {
    pub network: NetworkType,
    pub freshest_ts: i64,
    pub state: NodeState,
    pub handshake: Option<HandshakeData>,
    pub stats: NodeStats,
}

impl NodeEntry {
    fn new(network: NetworkType, freshest_ts: i64, state: NodeState) -> Self {
        NodeEntry {
            network,
            freshest_ts,
            state,
            handshake: None,
            stats: NodeStats::default(),
        }
    }
}

/// The central node store: sharded map + the global outstanding counter.
pub struct NodeStore {
    map: DashMap<AddrKey, NodeEntry>,
    /// Every address in state Queued OR Processing (Section 3.5).
    outstanding: AtomicUsize,
}

impl NodeStore {
    pub fn new() -> Self {
        NodeStore {
            map: DashMap::new(),
            outstanding: AtomicUsize::new(0),
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn outstanding(&self) -> usize {
        self.outstanding.load(Ordering::SeqCst)
    }

    /// Increment outstanding at enqueue, before the item becomes visible (3.5).
    pub fn incr_outstanding(&self) {
        self.outstanding.fetch_add(1, Ordering::SeqCst);
    }

    /// Decrement outstanding when an address reaches a terminal state.
    /// Returns the prior value (`== 1` means it just went to 0).
    pub fn decr_outstanding(&self) -> usize {
        self.outstanding.fetch_sub(1, Ordering::SeqCst)
    }

    /// Access an entry mutably under its shard lock.
    pub fn with_entry<R>(&self, key: &AddrKey, f: impl FnOnce(&mut NodeEntry) -> R) -> Option<R> {
        self.map.get_mut(key).map(|mut e| f(e.value_mut()))
    }

    /// Iterate every entry (for output). Clones to avoid holding shard locks.
    pub fn snapshot(&self) -> Vec<(AddrKey, NodeEntry)> {
        self.map
            .iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect()
    }

    /// Count entries in a given state.
    pub fn count_state(&self, state: NodeState) -> usize {
        self.map.iter().filter(|e| e.value().state == state).count()
    }

    /// Seed observation (Section 3.1): create/refresh with freshest_ts = now.
    /// Returns true if this created a **new** entry that should be enqueued.
    pub fn observe_seed(&self, key: AddrKey, now: i64) -> SeedOutcome {
        let network = classify(&key.host);
        use dashmap::mapref::entry::Entry;
        match self.map.entry(key) {
            Entry::Occupied(mut o) => {
                let e = o.get_mut();
                e.freshest_ts = e.freshest_ts.max(now);
                SeedOutcome { newly_queued: false }
            }
            Entry::Vacant(v) => {
                v.insert(NodeEntry::new(network, now, NodeState::Queued));
                // outstanding incremented by caller's enqueue().
                SeedOutcome { newly_queued: true }
            }
        }
    }

    /// Frontier upsert (Section 3.4). Updates freshest_ts = max, creating the
    /// entry if new. Snapshots prior state under the shard lock and decides the
    /// action, so a brand-new address is not misread as already-known (3.4 note).
    pub fn frontier_upsert(
        &self,
        key: AddrKey,
        observed_ts: i64,
        network: NetworkType,
        freshness_threshold: i64,
        now: i64,
    ) -> FrontierOutcome {
        use dashmap::mapref::entry::Entry;
        match self.map.entry(key) {
            Entry::Occupied(mut o) => {
                let e = o.get_mut();
                e.freshest_ts = e.freshest_ts.max(observed_ts);
                // Known iff already existed in a non-StaleDiscarded state.
                if e.state != NodeState::StaleDiscarded {
                    return FrontierOutcome::Known;
                }
                // StaleDiscarded: reconsider with the updated freshest_ts.
                if freshness_threshold > 0 && e.freshest_ts < now - freshness_threshold {
                    return FrontierOutcome::StillStale;
                }
                e.state = NodeState::Queued;
                FrontierOutcome::Enqueue
            }
            Entry::Vacant(v) => {
                // Brand-new address.
                if freshness_threshold > 0 && observed_ts < now - freshness_threshold {
                    v.insert(NodeEntry::new(network, observed_ts, NodeState::StaleDiscarded));
                    FrontierOutcome::StaleNew
                } else {
                    v.insert(NodeEntry::new(network, observed_ts, NodeState::Queued));
                    FrontierOutcome::Enqueue
                }
            }
        }
    }
}

impl Default for NodeStore {
    fn default() -> Self {
        Self::new()
    }
}

pub struct SeedOutcome {
    pub newly_queued: bool,
}

/// The decision from a frontier upsert (Section 3.4).
#[derive(Debug, PartialEq, Eq)]
pub enum FrontierOutcome {
    /// Freshly queued (new or lifted from stale); caller must enqueue.
    Enqueue,
    /// Already known in a live state; do nothing.
    Known,
    /// New address that failed the freshness filter (StaleDiscarded).
    StaleNew,
    /// Was StaleDiscarded and still stale; do nothing.
    StillStale,
}

/// Per-network-type count breakdown (Section 7.2).
#[derive(Debug, Default, Clone)]
pub struct NetworkBreakdown {
    pub total: u64,
    pub unknown: u64,
    pub ipv4: u64,
    pub ipv6: u64,
    pub onion_v2: u64,
    pub onion_v3: u64,
    pub i2p: u64,
    pub cjdns: u64,
}

impl NetworkBreakdown {
    pub fn add(&mut self, net: NetworkType) {
        self.total += 1;
        match net {
            NetworkType::Ipv4 => self.ipv4 += 1,
            NetworkType::Ipv6 => self.ipv6 += 1,
            NetworkType::OnionV2 => self.onion_v2 += 1,
            NetworkType::OnionV3 => self.onion_v3 += 1,
            NetworkType::I2p => self.i2p += 1,
            NetworkType::Cjdns => self.cjdns += 1,
            NetworkType::Unknown => self.unknown += 1,
        }
    }
}
