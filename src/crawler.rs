//! Crawler core: per-transport work queues + worker pools, the node worker
//! (connect → handshake → getaddr), and the status monitor (Sections 3.2–3.8).

use crate::address::{classify, NetworkType, Transport};
use crate::addrlog::{AddrLog, Responder};
use crate::protocol::{
    build_version, parse_addr, parse_addrv2, parse_version, AdvertisedAddr, ParsedAddrMessage,
    VersionData,
};
use crate::settings::Settings;
use crate::store::{
    AddrKey, AttemptData, CollectionOutcome, FailKind, FrontierOutcome, HandshakeData, NodeState,
    NodeStore,
};
use crate::transport::{connect_socks5, connect_tcp, Connection, SamSession};
use rand::seq::SliceRandom;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock, RwLockWriteGuard};

/// The set of per-transport queues (each an async MPMC channel, Section 3.5).
struct Queues {
    ip: (
        async_channel::Sender<AddrKey>,
        async_channel::Receiver<AddrKey>,
    ),
    tor: (
        async_channel::Sender<AddrKey>,
        async_channel::Receiver<AddrKey>,
    ),
    i2p: (
        async_channel::Sender<AddrKey>,
        async_channel::Receiver<AddrKey>,
    ),
}

impl Queues {
    fn new(capacity: usize) -> Self {
        Queues {
            ip: async_channel::bounded(capacity),
            tor: async_channel::bounded(capacity),
            i2p: async_channel::bounded(capacity),
        }
    }

    fn sender(&self, t: Transport) -> &async_channel::Sender<AddrKey> {
        match t {
            Transport::Ip => &self.ip.0,
            Transport::Tor => &self.tor.0,
            Transport::I2p => &self.i2p.0,
        }
    }

    fn receiver(&self, t: Transport) -> &async_channel::Receiver<AddrKey> {
        match t {
            Transport::Ip => &self.ip.1,
            Transport::Tor => &self.tor.1,
            Transport::I2p => &self.i2p.1,
        }
    }

    fn close_all(&self) {
        self.ip.0.close();
        self.tor.0.close();
        self.i2p.0.close();
    }
}

/// The crawler: owns the store, queues, counters, shared side-services.
pub struct Crawler {
    pub store: Arc<NodeStore>,
    settings: Arc<Settings>,
    queues: Queues,
    num_processed: AtomicUsize,
    /// Lazily-created shared I2P SAM session (Section 4.2.2, 5).
    sam: Mutex<Option<Arc<SamSession>>>,
    addr_log: Option<Arc<AddrLog>>,
    /// Crawl start clock (Section 3.8).
    pub start_clock: Instant,
    /// Set when a shutdown was requested (e.g. Ctrl+C): workers stop pulling new
    /// work after finishing their current node, so the crawl drains and exits.
    shutdown: AtomicBool,
    node_limit_reached: AtomicBool,
    worker_failed: AtomicBool,
    output_failed: AtomicBool,
    observation_barrier: RwLock<()>,
}

impl Crawler {
    pub fn new(
        store: Arc<NodeStore>,
        settings: Arc<Settings>,
        addr_log: Option<Arc<AddrLog>>,
    ) -> Self {
        let queue_capacity = settings.max_addresses;
        Crawler {
            store,
            settings,
            queues: Queues::new(queue_capacity),
            num_processed: AtomicUsize::new(0),
            sam: Mutex::new(None),
            addr_log,
            start_clock: Instant::now(),
            shutdown: AtomicBool::new(false),
            node_limit_reached: AtomicBool::new(false),
            worker_failed: AtomicBool::new(false),
            output_failed: AtomicBool::new(false),
            observation_barrier: RwLock::new(()),
        }
    }

    pub fn num_processed(&self) -> usize {
        self.num_processed.load(Ordering::SeqCst)
    }

    pub fn mark_output_failed(&self) {
        self.output_failed.store(true, Ordering::SeqCst);
    }

    pub fn terminated_early(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst) || self.node_limit_reached.load(Ordering::SeqCst)
    }

    pub async fn checkpoint_barrier(&self) -> RwLockWriteGuard<'_, ()> {
        self.observation_barrier.write().await
    }

    /// Enqueue a key already set to `Queued` in the store: count it in
    /// `outstanding` before it becomes visible, then push it (Section 3.5).
    fn enqueue(&self, key: AddrKey) {
        let transport = self
            .store
            .network_of(&key)
            .unwrap_or_else(|| classify(&key.host))
            .transport();
        self.store.incr_outstanding();
        // Unbounded channel: send completes immediately. If closed (crawl ending)
        // undo the outstanding increment so termination is not blocked.
        if self.queues.sender(transport).try_send(key.clone()).is_err() {
            self.store
                .with_entry(&key, |entry| entry.state = NodeState::BudgetDiscarded);
            self.store.decr_outstanding();
        }
    }

    /// Seed a brand-new address into its queue (Section 3.1).
    pub fn enqueue_seed(&self, key: AddrKey) {
        self.enqueue(key);
    }

    /// Move an address to a terminal state, recording the failure reason (if
    /// any); close all queues if it was the last outstanding work in the crawl
    /// (Section 3.5 `finish`).
    fn finish(&self, key: &AddrKey, terminal: NodeState, reason: Option<FailKind>) {
        let was_active = self
            .store
            .with_entry(key, |e| {
                let active = matches!(e.state, NodeState::Queued | NodeState::Processing);
                if active {
                    e.state = terminal;
                    e.failure = reason;
                }
                active
            })
            .unwrap_or(false);
        if was_active && self.store.decr_outstanding() == 1 {
            self.queues.close_all();
        }
    }

    /// Run the full crawl: spawn per-transport pools + monitor, await completion.
    pub async fn run(self: Arc<Self>) -> anyhow::Result<()> {
        // Nothing to crawl (e.g. all DNS seeds failed): close queues so workers
        // exit immediately instead of blocking on recv forever.
        if self.store.outstanding() == 0 {
            self.queues.close_all();
        }

        let mut workers = tokio::task::JoinSet::new();

        tracing::info!(
            ip = self.settings.concurrency.ip,
            tor = self.settings.concurrency.tor,
            i2p = self.settings.concurrency.i2p,
            total = self.settings.concurrency.ip
                + self.settings.concurrency.tor
                + self.settings.concurrency.i2p,
            "connection concurrency caps"
        );

        // One pool of `concurrency[T]` workers per transport (Section 3.5).
        for (transport, count) in [
            (Transport::Ip, self.settings.concurrency.ip),
            (Transport::Tor, self.settings.concurrency.tor),
            (Transport::I2p, self.settings.concurrency.i2p),
        ] {
            for _ in 0..count {
                let me = Arc::clone(&self);
                workers.spawn(async move {
                    me.worker_loop(transport).await;
                });
            }
        }

        // Status monitor (Section 3.8).
        let monitor = {
            let me = Arc::clone(&self);
            tokio::spawn(async move { me.monitor_loop().await })
        };

        // Ctrl+C handler: first press drains gracefully, second force-quits.
        let signals = {
            let me = Arc::clone(&self);
            tokio::spawn(async move { me.signal_loop().await })
        };

        while let Some(result) = workers.join_next().await {
            if let Err(e) = result {
                self.worker_failed.store(true, Ordering::SeqCst);
                self.shutdown.store(true, Ordering::SeqCst);
                self.queues.close_all();
                tracing::error!("worker task failed: {e}");
            }
        }
        // All workers have returned, so the crawl is definitively over. Under the
        // `--max-nodes` cap, `outstanding` can stay > 0 (queued-but-abandoned
        // addresses), so the monitor's outstanding==0 check would never fire —
        // stop it here. On natural termination the monitor has already exited and
        // this abort is a no-op.
        monitor.abort();
        let _ = monitor.await;
        signals.abort();
        let _ = signals.await;
        if self.worker_failed.load(Ordering::SeqCst) {
            anyhow::bail!("one or more worker tasks failed");
        }
        if self.output_failed.load(Ordering::SeqCst) {
            anyhow::bail!("address observation log failed");
        }
        Ok(())
    }

    /// Wait for Ctrl+C. The first one requests a graceful drain (workers finish
    /// their in-flight node, then stop); a second one force-quits immediately,
    /// abandoning in-flight work and any not-yet-written output.
    async fn signal_loop(self: &Arc<Self>) {
        if tokio::signal::ctrl_c().await.is_err() {
            return;
        }
        tracing::warn!(
            "Ctrl+C received: shutting down gracefully, draining in-flight nodes then writing output (press Ctrl+C again to force-quit)"
        );
        self.shutdown.store(true, Ordering::Relaxed);
        // Unblock workers idle on an empty queue so they observe the flag.
        self.queues.close_all();

        if tokio::signal::ctrl_c().await.is_err() {
            return;
        }
        tracing::warn!("second Ctrl+C received: force-quitting without writing output");
        std::process::exit(130);
    }

    /// A single worker's loop bound to transport `t` (Section 3.5 pseudocode).
    async fn worker_loop(self: &Arc<Self>, t: Transport) {
        let rx = self.queues.receiver(t).clone();
        loop {
            // Shutdown requested (Ctrl+C): stop after the current node, leaving
            // any still-queued addresses untouched.
            if self.shutdown.load(Ordering::Relaxed) {
                return;
            }
            let key = match rx.recv().await {
                Ok(k) => k,
                Err(_) => return, // queues closed & drained
            };
            if !self.reserve_node_slot() {
                self.finish(&key, NodeState::BudgetDiscarded, None);
                self.queues.close_all();
                continue;
            }
            self.store
                .with_entry(&key, |e| e.state = NodeState::Processing);
            let me = Arc::clone(self);
            let task_key = key.clone();
            let task = tokio::spawn(async move { me.process(&task_key, t).await });
            if let Err(e) = task.await {
                tracing::error!("worker panicked while processing {}: {e}", key.render());
                self.worker_failed.store(true, Ordering::SeqCst);
                self.shutdown.store(true, Ordering::SeqCst);
                self.finish(
                    &key,
                    NodeState::HandshakeFailed,
                    Some(FailKind::WorkerFailed),
                );
                self.queues.close_all();
                return;
            }
        }
    }

    fn reserve_node_slot(&self) -> bool {
        let reserved = match self.settings.max_nodes {
            None => {
                self.num_processed.fetch_add(1, Ordering::SeqCst);
                true
            }
            Some(max) => self
                .num_processed
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                    (n < max).then_some(n + 1)
                })
                .is_ok(),
        };
        if !reserved {
            self.node_limit_reached.store(true, Ordering::SeqCst);
        }
        reserved
    }

    /// Process one address: connect → handshake → getaddr, updating the store.
    async fn process(self: &Arc<Self>, key: &AddrKey, t: Transport) {
        let network = self
            .store
            .network_of(key)
            .unwrap_or_else(|| classify(&key.host));
        let timeouts = self.settings.timeouts_for(network);
        let max_attempts = self.settings.node_settings.handshake_attempts;

        // Count this processing iteration (Section 6.2 counter).
        let attempt = self
            .store
            .with_entry(key, |e| {
                e.stats.handshake_attempts += 1;
                e.attempts.push(AttemptData {
                    attempt: e.stats.handshake_attempts,
                    connect_duration_ms: None,
                    version_send_timestamp: None,
                    outcome: "started".to_string(),
                    failure: None,
                });
                e.stats.handshake_attempts
            })
            .unwrap_or(1);

        // 1. Connect (Section 3.2 step 1).
        let connect_start = Instant::now();
        let conn = match self
            .connect(key, network, t, Duration::from_secs(timeouts.connect))
            .await
        {
            Ok(c) => c,
            Err(e) => {
                let kind = classify_connect_error(&e, network);
                self.update_attempt(key, "connect_failed", Some(kind), None, None);
                tracing::debug!(
                    endpoint = %key.render(),
                    attempt,
                    max_attempts,
                    reason = kind.as_str(),
                    will_retry = attempt < max_attempts,
                    error = %e,
                    "connect attempt failed"
                );
                // Retry like any other transient failure (Section 6.2): a connect
                // timeout/refusal can be self-inflicted (e.g. a saturated worker
                // pool), not necessarily a dead peer. A node that connected on an
                // earlier attempt (time_connect_ms is set) has already proven it's
                // reachable, so exhausting attempts here means HandshakeFailed, not
                // Unreachable — the earlier evidence must not be discarded.
                let ever_connected = self
                    .store
                    .with_entry(key, |e| e.stats.time_connect_ms.is_some())
                    .unwrap_or(false);
                let terminal = if ever_connected {
                    NodeState::HandshakeFailed
                } else {
                    NodeState::Unreachable
                };
                self.retry_or_finish(key, t, attempt < max_attempts, terminal, Some(kind));
                return;
            }
        };
        let connect_ms = connect_start.elapsed().as_millis() as u64;
        self.store
            .with_entry(key, |e| e.stats.time_connect_ms = Some(connect_ms));
        self.update_attempt(key, "connected", None, Some(connect_ms), None);

        let mut conn = conn;

        // 2–5. Handshake (Section 3.2).
        match self.handshake(&mut conn, key, &timeouts, network).await {
            HandshakeResult::Version(v, sent_ts, duration_ms) => {
                let hd = HandshakeData::from_version(
                    &v,
                    sent_ts,
                    duration_ms,
                    key.render(),
                    key.render(),
                    conn.socket_local().to_string(),
                    conn.socket_peer().to_string(),
                );
                self.store.with_entry(key, |e| {
                    e.handshake = Some(hd.clone());
                });
                // 3.3 peer discovery — skipped in direct-probe mode so the run
                // never enqueues addresses beyond the seeded node list.
                if !self.settings.probe_mode {
                    let outcome = self.getaddr(&mut conn, key, &timeouts, network, &hd).await;
                    let _observation = self.observation_barrier.read().await;
                    self.store
                        .with_entry(key, |e| e.stats.collection_outcome = outcome);
                    if let Some(log) = &self.addr_log {
                        if let Err(e) = log.write_outcome(&key.host, key.port, outcome).await {
                            tracing::error!("address-log outcome write failed: {e}");
                            self.output_failed.store(true, Ordering::SeqCst);
                        }
                    }
                }
                self.update_attempt(key, "handshake_complete", None, None, Some(sent_ts));
                self.finish(key, NodeState::Reachable, None);
            }
            HandshakeResult::Timeout => {
                let should_retry = self.settings.retry_on_timeout && attempt < max_attempts;
                tracing::debug!(
                    endpoint = %key.render(),
                    attempt,
                    max_attempts,
                    reason = FailKind::HandshakeTimeout.as_str(),
                    will_retry = should_retry,
                    "handshake attempt failed: peer version was not received before the deadline"
                );
                self.update_attempt(
                    key,
                    "handshake_timeout",
                    Some(FailKind::HandshakeTimeout),
                    None,
                    None,
                );
                // Full-deadline silence: do not retry unless configured (6.2).
                self.retry_or_finish(
                    key,
                    t,
                    should_retry,
                    NodeState::HandshakeFailed,
                    Some(FailKind::HandshakeTimeout),
                );
            }
            HandshakeResult::Failed { kind, detail } => {
                let should_retry = attempt < max_attempts;
                tracing::debug!(
                    endpoint = %key.render(),
                    attempt,
                    max_attempts,
                    reason = kind.as_str(),
                    will_retry = should_retry,
                    detail = %detail,
                    "handshake attempt failed"
                );
                self.update_attempt(key, "handshake_failed", Some(kind), None, None);
                // Mid-handshake transport/protocol error: retry if attempts
                // remain (6.2), otherwise record the specific reason.
                self.retry_or_finish(key, t, should_retry, NodeState::HandshakeFailed, Some(kind));
            }
        }
        // Disconnect happens by dropping `conn`.
    }

    fn update_attempt(
        &self,
        key: &AddrKey,
        outcome: &str,
        failure: Option<FailKind>,
        connect_duration_ms: Option<u64>,
        version_send_timestamp: Option<i64>,
    ) {
        self.store.with_entry(key, |e| {
            if let Some(a) = e.attempts.last_mut() {
                a.outcome = outcome.to_string();
                if failure.is_some() {
                    a.failure = failure;
                }
                if connect_duration_ms.is_some() {
                    a.connect_duration_ms = connect_duration_ms;
                }
                if version_send_timestamp.is_some() {
                    a.version_send_timestamp = version_send_timestamp;
                }
            }
        });
    }

    /// Retry-or-give-up decision shared by the connect and handshake failure paths
    /// (Section 6.2): requeue if attempts remain, else finish with `terminal`.
    /// `terminal`/`reason` are also used as the fallback if the queue turns out to
    /// be closed (crawl ending mid-retry), so they must be the caller's correct
    /// terminal state for *this* failure — passing the wrong one mislabels a node
    /// that never reached this failure's stage.
    fn retry_or_finish(
        &self,
        key: &AddrKey,
        t: Transport,
        should_retry: bool,
        terminal: NodeState,
        reason: Option<FailKind>,
    ) {
        if should_retry {
            self.requeue(key, t, terminal, reason);
        } else {
            self.finish(key, terminal, reason);
        }
    }

    /// Lateral Processing → Queued move; does not change `outstanding` (3.5).
    /// `on_channel_closed`/`reason` are the terminal state and failure reason to
    /// record if the crawl ends before the retry can be re-sent (see
    /// `retry_or_finish`).
    fn requeue(
        &self,
        key: &AddrKey,
        t: Transport,
        on_channel_closed: NodeState,
        reason: Option<FailKind>,
    ) {
        self.store.with_entry(key, |e| e.state = NodeState::Queued);
        if self.queues.sender(t).try_send(key.clone()).is_err() {
            // Channel closed mid-crawl: treat as terminal to keep the counter sane.
            self.finish(key, on_channel_closed, reason);
        }
    }

    /// Establish a transport connection for `network` (Section 4.2).
    async fn connect(
        self: &Arc<Self>,
        key: &AddrKey,
        network: NetworkType,
        _t: Transport,
        connect_timeout: Duration,
    ) -> std::io::Result<Connection> {
        let ns = &self.settings.node_settings.network_settings;
        let stream = match network {
            NetworkType::Ipv4 | NetworkType::Ipv6 | NetworkType::Cjdns => {
                connect_tcp(&key.host, key.port, connect_timeout).await?
            }
            NetworkType::OnionV2 | NetworkType::OnionV3 => {
                connect_socks5(
                    &ns.tor_proxy_host,
                    ns.tor_proxy_port,
                    &key.host,
                    key.port,
                    connect_timeout,
                )
                .await?
            }
            NetworkType::I2p => {
                let session = self
                    .sam_session(connect_timeout)
                    .await
                    .ok_or_else(|| std::io::Error::other("no SAM session"))?;
                match session.connect(&key.host, connect_timeout).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        // A failed STREAM CONNECT normally describes only the
                        // requested destination (for example CANT_REACH_PEER or
                        // TIMEOUT). Keep the shared session in those cases;
                        // INVALID_ID specifically means the router no longer
                        // knows the cached session.
                        if e.to_string().contains("RESULT=INVALID_ID") {
                            let mut cached = self.sam.lock().await;
                            if cached.as_ref().is_some_and(|s| Arc::ptr_eq(s, &session)) {
                                *cached = None;
                            }
                        }
                        return Err(e);
                    }
                }
            }
            NetworkType::Unknown => {
                return Err(std::io::Error::other(
                    "unknown network type has no transport",
                ));
            }
        };
        Ok(Connection::new(stream))
    }

    /// Get (or lazily create) the shared SAM session (Section 4.2.2).
    async fn sam_session(&self, connect_timeout: Duration) -> Option<Arc<SamSession>> {
        let ns = &self.settings.node_settings.network_settings;
        let mut cached = self.sam.lock().await;
        if let Some(session) = cached.as_ref() {
            return Some(Arc::clone(session));
        }
        match SamSession::create(&ns.i2p_sam_host, ns.i2p_sam_port, connect_timeout).await {
            Ok(s) => {
                let session = Arc::new(s);
                *cached = Some(Arc::clone(&session));
                Some(session)
            }
            Err(e) => {
                tracing::warn!("failed to create SAM session (will retry): {e}");
                None
            }
        }
    }

    /// Perform the version handshake (Section 3.2 steps 2–5).
    async fn handshake(
        &self,
        conn: &mut Connection,
        key: &AddrKey,
        timeouts: &crate::settings::Timeouts,
        _network: NetworkType,
    ) -> HandshakeResult {
        let start = Instant::now();
        let sent_ts = now_epoch();
        // Send our version.
        let nonce = rand::random::<u64>();
        let payload = build_version(sent_ts, nonce);
        if let Err(e) = conn.send("version", &payload).await {
            return HandshakeResult::Failed {
                kind: FailKind::VersionSendFailed,
                detail: e.to_string(),
            };
        }
        // Record only a version message that was successfully written.
        self.store.with_entry(key, |e| {
            if e.stats.first_version_send_ts.is_none() {
                e.stats.first_version_send_ts = Some(sent_ts);
            }
        });
        self.update_attempt(key, "version_sent", None, None, Some(sent_ts));

        // Wait for the peer's version (Section 3.2 step 3, 4.1 receive loop).
        let deadline = start + Duration::from_secs(timeouts.message);
        let per = Duration::from_secs(timeouts.message);
        let peer_version = match self
            .recv_matching(conn, &["version"], deadline, per, None)
            .await
        {
            RecvResult::Message(env) => match parse_version(&env.payload) {
                Some(v) => v,
                None => {
                    return HandshakeResult::Failed {
                        kind: FailKind::MalformedVersion,
                        detail: "peer version payload could not be parsed".to_string(),
                    }
                }
            },
            RecvResult::Timeout => return HandshakeResult::Timeout,
            RecvResult::Transport(e) => {
                return HandshakeResult::Failed {
                    kind: classify_handshake_error(&e),
                    detail: e.to_string(),
                }
            }
        };

        // BIP155 negotiation must be between version and verack and only when
        // both sides support it.
        if peer_version.version.min(crate::protocol::PROTOCOL_VERSION) >= 70016 {
            if let Err(e) = conn.send("sendaddrv2", &[]).await {
                return HandshakeResult::Failed {
                    kind: FailKind::NegotiationSendFailed,
                    detail: e.to_string(),
                };
            }
        }
        if let Err(e) = conn.send("verack", &[]).await {
            return HandshakeResult::Failed {
                kind: FailKind::VerackSendFailed,
                detail: e.to_string(),
            };
        }

        match self
            .recv_matching(conn, &["verack"], deadline, per, Some(peer_version.version))
            .await
        {
            RecvResult::Message(_) => {}
            RecvResult::Timeout => {
                return HandshakeResult::Failed {
                    kind: FailKind::PeerVerackTimeout,
                    detail: "peer verack was not received before the handshake deadline"
                        .to_string(),
                }
            }
            RecvResult::Transport(e) => {
                return HandshakeResult::Failed {
                    kind: classify_handshake_error(&e),
                    detail: e.to_string(),
                };
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        HandshakeResult::Version(peer_version, sent_ts, duration_ms)
    }

    /// Receive loop bounded by a per-envelope timeout AND an overall deadline
    /// (Section 4.1). Answers pings, skips unmatched messages.
    async fn recv_matching(
        &self,
        conn: &mut Connection,
        expected: &[&str],
        deadline: Instant,
        per_timeout: Duration,
        ping_version: Option<i32>,
    ) -> RecvResult {
        loop {
            let now = Instant::now();
            if now >= deadline {
                return RecvResult::Timeout;
            }
            let wait = (deadline - now).min(per_timeout);
            match conn.recv_one(wait).await {
                Ok(Some(env)) => {
                    if expected.contains(&env.command.as_str()) {
                        return RecvResult::Message(env);
                    }
                    if env.command == "ping" {
                        if let Some(version) = ping_version {
                            if let Err(e) = conn.answer_ping(&env.payload, version).await {
                                return RecvResult::Transport(e);
                            }
                        }
                    }
                    // else: unmatched, skip and keep waiting.
                }
                Ok(None) => {
                    // Per-envelope timeout elapsed; loop re-checks the deadline.
                    continue;
                }
                Err(e) => return RecvResult::Transport(e),
            }
        }
    }

    /// Peer discovery: getaddr + collect addr/addrv2 replies (Section 3.3).
    async fn getaddr(
        &self,
        conn: &mut Connection,
        key: &AddrKey,
        timeouts: &crate::settings::Timeouts,
        _network: NetworkType,
        hd: &HandshakeData,
    ) -> CollectionOutcome {
        if conn.send("getaddr", &[]).await.is_err() {
            return CollectionOutcome::SendFailed;
        }
        let start = Instant::now();
        let hard_deadline = start + Duration::from_secs(timeouts.getaddr);
        let idle = Duration::from_secs(timeouts.getaddr_idle);
        let mut valid_messages = 0u64;

        loop {
            let now = Instant::now();
            if now >= hard_deadline {
                return if valid_messages == 0 {
                    CollectionOutcome::HardTimeout
                } else {
                    CollectionOutcome::PartialHardTimeout
                };
            }
            let wait = (hard_deadline - now).min(idle);
            match conn.recv_one(wait).await {
                Ok(Some(env)) => match env.command.as_str() {
                    "addr" | "addrv2" => {
                        let parsed = if env.command == "addr" {
                            parse_addr(&env.payload)
                        } else {
                            parse_addrv2(&env.payload)
                        };
                        let parsed = match parsed {
                            Ok(parsed) => parsed,
                            Err(e) => {
                                let _observation = self.observation_barrier.read().await;
                                tracing::debug!(
                                    "malformed {} from {}: {e}",
                                    env.command,
                                    key.render()
                                );
                                self.store.with_entry(key, |entry| {
                                    entry.stats.malformed_addr_messages += 1
                                });
                                if let Some(log) = &self.addr_log {
                                    if let Err(log_error) = log
                                        .write_malformed(
                                            &key.host,
                                            key.port,
                                            &env.command,
                                            &e,
                                            &env.payload,
                                        )
                                        .await
                                    {
                                        tracing::error!("failed to quarantine malformed address response: {log_error}");
                                        self.output_failed.store(true, Ordering::SeqCst);
                                        return CollectionOutcome::LogFailed;
                                    }
                                }
                                return if valid_messages == 0 {
                                    CollectionOutcome::MalformedResponse
                                } else {
                                    CollectionOutcome::PartialMalformedResponse
                                };
                            }
                        };
                        let address_count = parsed.addrs.len();
                        if self
                            .handle_addr_message(key, &env.command, &parsed, hd)
                            .await
                            .is_err()
                        {
                            self.output_failed.store(true, Ordering::SeqCst);
                            return CollectionOutcome::LogFailed;
                        }
                        valid_messages += 1;
                        self.store
                            .with_entry(key, |entry| entry.stats.valid_addr_messages += 1);
                        if is_getaddr_reply_complete(address_count) {
                            return CollectionOutcome::CompleteQuiet;
                        }
                    }
                    "ping" if conn.answer_ping(&env.payload, hd.version).await.is_err() => {
                        return if valid_messages == 0 {
                            CollectionOutcome::RemoteDisconnect
                        } else {
                            CollectionOutcome::PartialRemoteDisconnect
                        };
                    }
                    "ping" => {}
                    _ => { /* skip */ }
                },
                Ok(None) => {
                    if conn.has_partial_envelope() {
                        return if valid_messages == 0 {
                            CollectionOutcome::IncompleteEnvelopeTimeout
                        } else {
                            CollectionOutcome::PartialIncompleteEnvelopeTimeout
                        };
                    }
                    return if valid_messages == 0 {
                        CollectionOutcome::NoResponseTimeout
                    } else {
                        CollectionOutcome::CompleteQuiet
                    };
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::TimedOut {
                        return if valid_messages == 0 {
                            CollectionOutcome::IncompleteEnvelopeTimeout
                        } else {
                            CollectionOutcome::PartialIncompleteEnvelopeTimeout
                        };
                    }
                    return if valid_messages == 0 {
                        CollectionOutcome::RemoteDisconnect
                    } else {
                        CollectionOutcome::PartialRemoteDisconnect
                    };
                }
            }
        }
    }

    /// Process one addr/addrv2 message (Section 3.3 steps 3–6).
    async fn handle_addr_message(
        &self,
        responder: &AddrKey,
        message_type: &str,
        parsed: &ParsedAddrMessage,
        hd: &HandshakeData,
    ) -> std::io::Result<()> {
        // Checkpoints take the write side while flushing the observation log
        // and cloning aggregate state, preventing a provenance/aggregate split.
        let _observation = self.observation_barrier.read().await;
        let addrs = &parsed.addrs;
        let now = now_epoch();

        // Step 4: per-node breakdown counts ALL advertised addresses.
        self.store.with_entry(responder, |e| {
            for a in addrs {
                e.stats.record_advertised(a.network);
            }
            e.stats.advertised_total += parsed.unknown_entries;
            e.stats.advertised_unknown += parsed.unknown_entries;
        });

        // Step 5: addr-response log, recorded before dedup (Section 8.5).
        if let Some(log) = &self.addr_log {
            let responder_net = classify(&responder.host);
            let r = Responder {
                host: &responder.host,
                port: responder.port,
                network: responder_net.as_str(),
                received_at: now,
                message_type,
                handshake: hd,
            };
            log.write_block(&r, parsed).await?;
        }

        // Steps 0/3/6: feed enabled-network addresses into the frontier.
        // Politeness spread: shuffle the batch before enqueuing (Section 3.5).
        let mut enabled: Vec<&AdvertisedAddr> = addrs
            .iter()
            .filter(|a| self.settings.is_enabled(a.network))
            .collect();
        enabled.shuffle(&mut rand::thread_rng());

        for a in enabled {
            let akey = AddrKey::new(a.host.clone(), a.port);
            let outcome = self.store.frontier_upsert(
                akey.clone(),
                a.timestamp,
                a.network,
                self.settings.freshness_threshold,
                now,
            );
            if outcome == FrontierOutcome::Enqueue {
                self.enqueue(akey);
            } else if outcome == FrontierOutcome::BudgetRejected {
                tracing::debug!("frontier address budget rejected {}", akey.render());
            }
        }
        Ok(())
    }

    /// Status monitor loop (Section 3.8).
    async fn monitor_loop(self: &Arc<Self>) {
        let mut ticker = tokio::time::interval(Duration::from_secs(5));
        loop {
            ticker.tick().await;
            // Seeds are enqueued before the crawl starts, so `outstanding == 0`
            // here means the crawl has genuinely terminated (Section 3.6).
            if self.store.outstanding() == 0 {
                // Crawl has terminated.
                tracing::info!("[STATUS] No more nodes and no active workers: exiting");
                let runtime = self.start_clock.elapsed().as_secs();
                if runtime > 12 * 3600 {
                    tracing::warn!("[STATUS] crawl runtime exceeded 12h ({runtime}s)");
                }
                return;
            }
            let elapsed_h = self.start_clock.elapsed().as_secs_f64() / 3600.0;
            let r = self.store.count_state(NodeState::Reachable);
            let f = self.store.count_state(NodeState::HandshakeFailed);
            let u = self.store.count_state(NodeState::Unreachable);
            let q = self.store.count_state(NodeState::Queued);
            let p = self.store.count_state(NodeState::Processing);
            let completed = r + f + u;
            let remaining = self.store.outstanding();
            let elapsed = self.start_clock.elapsed();
            let (rate, eta) = match progress_estimate(elapsed, completed, remaining) {
                Some((nodes_per_second, duration)) => (
                    format!("{nodes_per_second:.2}nodes/s"),
                    format_eta(duration),
                ),
                None => ("calculating".to_string(), "calculating".to_string()),
            };
            tracing::info!(
                "[STATUS] Elapsed: {elapsed_h:.1}h  reachable={r} handshake_failed={f} unreachable={u} queued={q} processing={p} remaining={remaining} rate={rate} eta_current_frontier={eta}"
            );
        }
    }
}

enum HandshakeResult {
    /// Peer version parsed; carries (version, sent epoch, duration ms).
    Version(VersionData, i64, u64),
    /// Peer stayed silent for the whole handshake deadline.
    Timeout,
    /// A specific transport/protocol failure (carries the classified reason).
    Failed { kind: FailKind, detail: String },
}

enum RecvResult {
    Message(crate::transport::Envelope),
    Timeout,
    Transport(std::io::Error),
}

/// Average terminal-node throughput and the time needed to drain the work that
/// is outstanding right now. The frontier can still grow as peers advertise
/// addresses, so this is deliberately not presented as a fixed completion time.
fn progress_estimate(
    elapsed: Duration,
    completed: usize,
    remaining: usize,
) -> Option<(f64, Duration)> {
    if completed == 0 || elapsed.is_zero() {
        return None;
    }
    let elapsed_seconds = elapsed.as_secs_f64();
    let nodes_per_second = completed as f64 / elapsed_seconds;
    let eta_seconds = (remaining as f64 / nodes_per_second).ceil();
    if !nodes_per_second.is_finite() || nodes_per_second <= 0.0 || !eta_seconds.is_finite() {
        return None;
    }
    Some((
        nodes_per_second,
        Duration::from_secs(eta_seconds.min(u64::MAX as f64) as u64),
    ))
}

fn format_eta(duration: Duration) -> String {
    let total = duration.as_secs();
    let days = total / 86_400;
    let hours = (total % 86_400) / 3_600;
    let minutes = (total % 3_600) / 60;
    let seconds = total % 60;
    if days > 0 {
        format!("{days}d {hours}h {minutes}m")
    } else if hours > 0 {
        format!("{hours}h {minutes}m {seconds}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}

/// Classify a connect-phase `io::Error` into a [`FailKind`]. Uses the error
/// kind first, falling back to the transport (proxy vs SAM vs direct) for
/// otherwise-opaque errors so the reported reason still points at the right
/// subsystem.
fn classify_connect_error(e: &std::io::Error, network: NetworkType) -> FailKind {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::TimedOut => FailKind::ConnectTimeout,
        ErrorKind::ConnectionRefused => FailKind::ConnectRefused,
        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted => FailKind::ConnectReset,
        _ => {
            // Linux ENETUNREACH (101) / EHOSTUNREACH (113): no route to host.
            if matches!(e.raw_os_error(), Some(101) | Some(113)) {
                return FailKind::ConnectUnreachable;
            }
            match network {
                NetworkType::OnionV2 | NetworkType::OnionV3 => FailKind::ProxyError,
                NetworkType::I2p => FailKind::SamError,
                _ => FailKind::ConnectOther,
            }
        }
    }
}

/// Classify a handshake-phase `io::Error` (from the framed receive loop) into a
/// [`FailKind`].
fn classify_handshake_error(e: &std::io::Error) -> FailKind {
    use std::io::ErrorKind;
    match e.kind() {
        // read_envelope raises InvalidData on magic/checksum/oversize mismatch.
        ErrorKind::InvalidData => FailKind::ProtocolDesync,
        ErrorKind::UnexpectedEof
        | ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted
        | ErrorKind::BrokenPipe => FailKind::ConnectionClosed,
        _ => FailKind::HandshakeOther,
    }
}

/// A one-address message is normally the peer's self-announcement, not the
/// substantive getaddr reply. Keep listening after empty or singleton messages;
/// any valid block containing at least two addresses completes the response.
/// The parser separately enforces Bitcoin Core's 1000-address maximum.
fn is_getaddr_reply_complete(address_count: usize) -> bool {
    address_count > 1
}

/// Current UNIX epoch seconds.
pub fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::io::{Error, ErrorKind};

    #[test]
    fn connect_errors_classify_by_kind() {
        let refused = Error::from(ErrorKind::ConnectionRefused);
        assert_eq!(
            classify_connect_error(&refused, NetworkType::Ipv4),
            FailKind::ConnectRefused
        );
        let timeout = Error::new(ErrorKind::TimedOut, "tcp connect timed out");
        assert_eq!(
            classify_connect_error(&timeout, NetworkType::Ipv4),
            FailKind::ConnectTimeout
        );
    }

    #[test]
    fn opaque_connect_errors_fall_back_to_transport() {
        // SOCKS5/SAM failures surface as ErrorKind::Other; the transport decides.
        let other = Error::other("socks5 connect failed: REP=0x05");
        assert_eq!(
            classify_connect_error(&other, NetworkType::OnionV3),
            FailKind::ProxyError
        );
        assert_eq!(
            classify_connect_error(&other, NetworkType::I2p),
            FailKind::SamError
        );
        assert_eq!(
            classify_connect_error(&other, NetworkType::Ipv6),
            FailKind::ConnectOther
        );
    }

    #[test]
    fn unreachable_os_errors_are_detected() {
        // ENETUNREACH / EHOSTUNREACH on Linux.
        assert_eq!(
            classify_connect_error(&Error::from_raw_os_error(101), NetworkType::Ipv4),
            FailKind::ConnectUnreachable
        );
        assert_eq!(
            classify_connect_error(&Error::from_raw_os_error(113), NetworkType::Ipv4),
            FailKind::ConnectUnreachable
        );
    }

    #[test]
    fn handshake_errors_classify_by_kind() {
        let desync = Error::new(ErrorKind::InvalidData, "network magic mismatch");
        assert_eq!(classify_handshake_error(&desync), FailKind::ProtocolDesync);
        let eof = Error::from(ErrorKind::UnexpectedEof);
        assert_eq!(classify_handshake_error(&eof), FailKind::ConnectionClosed);
        let other = Error::other("weird");
        assert_eq!(classify_handshake_error(&other), FailKind::HandshakeOther);
    }

    #[test]
    fn getaddr_reply_completion_ignores_self_announcements() {
        assert!(!is_getaddr_reply_complete(0));
        assert!(!is_getaddr_reply_complete(1));
        assert!(is_getaddr_reply_complete(2));
        assert!(is_getaddr_reply_complete(
            crate::protocol::MAX_ADDR_TO_SEND - 1
        ));
        assert!(is_getaddr_reply_complete(crate::protocol::MAX_ADDR_TO_SEND));
    }

    #[test]
    fn progress_eta_uses_completed_rate_and_current_remaining_work() {
        let (rate, eta) = progress_estimate(Duration::from_secs(50), 100, 40).unwrap();
        assert_eq!(rate, 2.0);
        assert_eq!(eta, Duration::from_secs(20));
        assert!(progress_estimate(Duration::from_secs(50), 0, 40).is_none());
        assert!(progress_estimate(Duration::ZERO, 100, 40).is_none());
    }

    #[test]
    fn eta_is_formatted_for_humans() {
        assert_eq!(format_eta(Duration::from_secs(42)), "42s");
        assert_eq!(format_eta(Duration::from_secs(192)), "3m 12s");
        assert_eq!(format_eta(Duration::from_secs(7_445)), "2h 4m 5s");
        assert_eq!(format_eta(Duration::from_secs(93_720)), "1d 2h 2m");
    }

    #[test]
    fn node_limit_counts_every_processing_iteration() {
        let settings = crate::settings::Cli::try_parse_from([
            "crawler",
            "--max-nodes",
            "2",
            "--no-ipv4",
            "--no-ipv6",
            "--no-tor",
            "--no-i2p",
            "--no-cjdns",
        ])
        .unwrap()
        .into_settings()
        .unwrap();
        let crawler = Crawler::new(Arc::new(NodeStore::new()), Arc::new(settings), None);

        assert!(crawler.reserve_node_slot());
        assert!(crawler.reserve_node_slot());
        assert!(!crawler.reserve_node_slot());
        assert_eq!(crawler.num_processed(), 2);
        assert!(crawler.terminated_early());
    }
}
