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
    BudgetDiscarded,
}

/// Why a node ended up in a failure state — the reason recorded alongside a
/// terminal `Unreachable` / `HandshakeFailed`. Surfaced in the result CSVs and
/// aggregated into a histogram in the stats JSON so a run's failures can be
/// understood at a glance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailKind {
    // ---- Connect phase (terminal state = Unreachable) ----
    /// TCP/proxy actively refused the connection (nothing listening).
    ConnectRefused,
    /// The connect (incl. SOCKS5/SAM setup) exceeded its timeout.
    ConnectTimeout,
    /// Network/host unreachable (no route).
    ConnectUnreachable,
    /// Connection reset during connect.
    ConnectReset,
    /// The Tor SOCKS5 proxy negotiation failed (e.g. proxy down, REP != 0).
    ProxyError,
    /// The I2P SAM session/stream setup failed.
    SamError,
    /// Any other connect-phase error.
    ConnectOther,

    // ---- Handshake phase (terminal state = HandshakeFailed) ----
    /// Failed to write our `version` message.
    VersionSendFailed,
    NegotiationSendFailed,
    VerackSendFailed,
    PeerVerackTimeout,
    /// Peer stayed silent for the whole handshake deadline.
    HandshakeTimeout,
    /// Peer closed / reset the connection mid-handshake (EOF).
    ConnectionClosed,
    /// Peer sent a `version` we could not parse.
    MalformedVersion,
    /// Stream desynchronised: bad network magic, checksum, or oversize payload.
    ProtocolDesync,
    /// Any other handshake-phase error.
    HandshakeOther,
    WorkerFailed,
}

impl FailKind {
    /// The snake_case identifier used in output CSVs and the stats histogram.
    pub fn as_str(self) -> &'static str {
        match self {
            FailKind::ConnectRefused => "connect_refused",
            FailKind::ConnectTimeout => "connect_timeout",
            FailKind::ConnectUnreachable => "connect_unreachable",
            FailKind::ConnectReset => "connect_reset",
            FailKind::ProxyError => "proxy_error",
            FailKind::SamError => "sam_error",
            FailKind::ConnectOther => "connect_other",
            FailKind::VersionSendFailed => "version_send_failed",
            FailKind::NegotiationSendFailed => "negotiation_send_failed",
            FailKind::VerackSendFailed => "verack_send_failed",
            FailKind::PeerVerackTimeout => "peer_verack_timeout",
            FailKind::HandshakeTimeout => "handshake_timeout",
            FailKind::ConnectionClosed => "connection_closed",
            FailKind::MalformedVersion => "malformed_version",
            FailKind::ProtocolDesync => "protocol_desync",
            FailKind::HandshakeOther => "handshake_other",
            FailKind::WorkerFailed => "worker_failed",
        }
    }
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
    pub requested_endpoint: String,
    pub transport_destination: String,
    pub socket_local: String,
    pub socket_peer: String,
    pub version_addr_recv: String,
    pub version_addr_recv_services: u64,
    pub version_addr_from: Option<String>,
    pub version_addr_from_services: Option<u64>,
    pub version_nonce: Option<u64>,
}

impl HandshakeData {
    pub fn from_version(
        v: &VersionData,
        handshake_timestamp: i64,
        duration_ms: u64,
        requested_endpoint: String,
        transport_destination: String,
        socket_local: String,
        socket_peer: String,
    ) -> Self {
        HandshakeData {
            version: v.version,
            services: v.services,
            user_agent: v.user_agent.clone(),
            latest_block: v.latest_block,
            relay: v.relay,
            version_reply_timestamp_remote: v.timestamp,
            handshake_timestamp,
            handshake_duration_ms: duration_ms,
            requested_endpoint,
            transport_destination,
            socket_local,
            socket_peer,
            version_addr_recv: render_addr(&v.addr_recv.host, v.addr_recv.port),
            version_addr_recv_services: v.addr_recv.services,
            version_addr_from: v.addr_from.as_ref().map(|a| render_addr(&a.host, a.port)),
            version_addr_from_services: v.addr_from.as_ref().map(|a| a.services),
            version_nonce: v.nonce,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CollectionOutcome {
    #[default]
    NotRequested,
    CompleteQuiet,
    NoResponseTimeout,
    PartialHardTimeout,
    HardTimeout,
    SendFailed,
    MalformedResponse,
    PartialMalformedResponse,
    RemoteDisconnect,
    PartialRemoteDisconnect,
    IncompleteEnvelopeTimeout,
    PartialIncompleteEnvelopeTimeout,
    LogFailed,
}

impl CollectionOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotRequested => "not_requested",
            Self::CompleteQuiet => "complete_quiet",
            Self::NoResponseTimeout => "no_response_timeout",
            Self::PartialHardTimeout => "partial_hard_timeout",
            Self::HardTimeout => "hard_timeout",
            Self::SendFailed => "send_failed",
            Self::MalformedResponse => "malformed_response",
            Self::PartialMalformedResponse => "partial_malformed_response",
            Self::RemoteDisconnect => "remote_disconnect",
            Self::PartialRemoteDisconnect => "partial_remote_disconnect",
            Self::IncompleteEnvelopeTimeout => "incomplete_envelope_timeout",
            Self::PartialIncompleteEnvelopeTimeout => "partial_incomplete_envelope_timeout",
            Self::LogFailed => "log_failed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AttemptData {
    pub attempt: u32,
    pub connect_duration_ms: Option<u64>,
    pub version_send_timestamp: Option<i64>,
    pub outcome: String,
    pub failure: Option<FailKind>,
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
    pub collection_outcome: CollectionOutcome,
    pub valid_addr_messages: u64,
    pub malformed_addr_messages: u64,
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
    /// Why this node failed, when in a terminal failure state (Section 7).
    pub failure: Option<FailKind>,
    pub attempts: Vec<AttemptData>,
}

impl NodeEntry {
    fn new(network: NetworkType, freshest_ts: i64, state: NodeState) -> Self {
        NodeEntry {
            network,
            freshest_ts,
            state,
            handshake: None,
            stats: NodeStats::default(),
            failure: None,
            attempts: Vec::new(),
        }
    }
}

/// The central node store: sharded map + the global outstanding counter.
pub struct NodeStore {
    map: DashMap<AddrKey, NodeEntry>,
    /// Every address in state Queued OR Processing (Section 3.5).
    outstanding: AtomicUsize,
    entries: AtomicUsize,
    max_entries: usize,
    budget_rejected: AtomicUsize,
}

impl NodeStore {
    pub fn new() -> Self {
        Self::with_limit(1_000_000)
    }

    pub fn with_limit(max_entries: usize) -> Self {
        NodeStore {
            map: DashMap::new(),
            outstanding: AtomicUsize::new(0),
            entries: AtomicUsize::new(0),
            max_entries,
            budget_rejected: AtomicUsize::new(0),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.load(Ordering::SeqCst)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn budget_rejected(&self) -> usize {
        self.budget_rejected.load(Ordering::SeqCst)
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

    pub fn network_of(&self, key: &AddrKey) -> Option<NetworkType> {
        self.map.get(key).map(|entry| entry.network)
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
                SeedOutcome {
                    newly_queued: false,
                }
            }
            Entry::Vacant(v) => {
                if !self.reserve_entry() {
                    return SeedOutcome {
                        newly_queued: false,
                    };
                }
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
                if !self.reserve_entry() {
                    return FrontierOutcome::BudgetRejected;
                }
                // Brand-new address.
                if freshness_threshold > 0 && observed_ts < now - freshness_threshold {
                    v.insert(NodeEntry::new(
                        network,
                        observed_ts,
                        NodeState::StaleDiscarded,
                    ));
                    FrontierOutcome::StaleNew
                } else {
                    v.insert(NodeEntry::new(network, observed_ts, NodeState::Queued));
                    FrontierOutcome::Enqueue
                }
            }
        }
    }

    fn reserve_entry(&self) -> bool {
        let reserved = self
            .entries
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < self.max_entries).then_some(n + 1)
            })
            .is_ok();
        if !reserved {
            self.budget_rejected.fetch_add(1, Ordering::SeqCst);
        }
        reserved
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
    /// Crawl-wide unique-address budget exhausted; claim was not inserted.
    BudgetRejected,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_address_budget_is_strict_and_counted() {
        let store = NodeStore::with_limit(1);
        assert!(store.is_empty());
        assert!(
            store
                .observe_seed(AddrKey::new("1.2.3.4", 8333), 1)
                .newly_queued
        );
        assert!(
            !store
                .observe_seed(AddrKey::new("5.6.7.8", 8333), 1)
                .newly_queued
        );
        assert_eq!(store.len(), 1);
        assert_eq!(store.budget_rejected(), 1);
    }
}
