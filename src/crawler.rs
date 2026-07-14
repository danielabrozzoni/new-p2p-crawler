//! Crawler core: per-transport work queues + worker pools, the node worker
//! (connect → handshake → getaddr), and the status monitor (Sections 3.2–3.8).

use crate::addrlog::{AddrLog, Responder};
use crate::address::{classify, NetworkType, Transport};
use crate::protocol::{
    build_version, parse_addr, parse_addrv2, parse_version, AdvertisedAddr, VersionData,
    MAX_ADDR_TO_SEND,
};
use crate::settings::Settings;
use crate::store::{AddrKey, FailKind, FrontierOutcome, HandshakeData, NodeState, NodeStore};
use crate::transport::{
    connect_socks5, connect_tcp, Connection, SamSession,
};
use rand::seq::SliceRandom;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::OnceCell;

/// The set of per-transport queues (each an async MPMC channel, Section 3.5).
struct Queues {
    ip: (async_channel::Sender<AddrKey>, async_channel::Receiver<AddrKey>),
    tor: (async_channel::Sender<AddrKey>, async_channel::Receiver<AddrKey>),
    i2p: (async_channel::Sender<AddrKey>, async_channel::Receiver<AddrKey>),
}

impl Queues {
    fn new() -> Self {
        Queues {
            ip: async_channel::unbounded(),
            tor: async_channel::unbounded(),
            i2p: async_channel::unbounded(),
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
    sam: OnceCell<Option<Arc<SamSession>>>,
    addr_log: Option<Arc<AddrLog>>,
    /// Crawl start clock (Section 3.8).
    pub start_clock: Instant,
    /// Set when a shutdown was requested (e.g. Ctrl+C): workers stop pulling new
    /// work after finishing their current node, so the crawl drains and exits.
    shutdown: AtomicBool,
}

impl Crawler {
    pub fn new(
        store: Arc<NodeStore>,
        settings: Arc<Settings>,
        addr_log: Option<Arc<AddrLog>>,
    ) -> Self {
        Crawler {
            store,
            settings,
            queues: Queues::new(),
            num_processed: AtomicUsize::new(0),
            sam: OnceCell::new(),
            addr_log,
            start_clock: Instant::now(),
            shutdown: AtomicBool::new(false),
        }
    }

    pub fn num_processed(&self) -> usize {
        self.num_processed.load(Ordering::SeqCst)
    }

    /// Enqueue a key already set to `Queued` in the store: count it in
    /// `outstanding` before it becomes visible, then push it (Section 3.5).
    fn enqueue(&self, key: AddrKey) {
        let transport = classify(&key.host).transport();
        self.store.incr_outstanding();
        // Unbounded channel: send completes immediately. If closed (crawl ending)
        // undo the outstanding increment so termination is not blocked.
        if self.queues.sender(transport).try_send(key).is_err() {
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
        self.store.with_entry(key, |e| {
            e.state = terminal;
            e.failure = reason;
        });
        if self.store.decr_outstanding() == 1 {
            self.queues.close_all();
        }
    }

    /// Run the full crawl: spawn per-transport pools + monitor, await completion.
    pub async fn run(self: Arc<Self>) {
        // Nothing to crawl (e.g. all DNS seeds failed): close queues so workers
        // exit immediately instead of blocking on recv forever.
        if self.store.outstanding() == 0 {
            self.queues.close_all();
        }

        let mut handles = Vec::new();

        // One pool of `concurrency[T]` workers per transport (Section 3.5).
        for (transport, count) in [
            (Transport::Ip, self.settings.concurrency.ip),
            (Transport::Tor, self.settings.concurrency.tor),
            (Transport::I2p, self.settings.concurrency.i2p),
        ] {
            for _ in 0..count {
                let me = Arc::clone(&self);
                handles.push(tokio::spawn(async move {
                    me.worker_loop(transport).await;
                }));
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

        for h in handles {
            let _ = h.await;
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
            // Test cap: stop taking work and wake everyone (Section 3.6).
            if let Some(max) = self.settings.max_nodes {
                if self.num_processed() >= max {
                    self.queues.close_all();
                    return;
                }
            }
            let key = match rx.recv().await {
                Ok(k) => k,
                Err(_) => return, // queues closed & drained
            };
            self.num_processed.fetch_add(1, Ordering::SeqCst);
            self.store.with_entry(&key, |e| e.state = NodeState::Processing);
            self.process(&key, t).await;
        }
    }

    /// Process one address: connect → handshake → getaddr, updating the store.
    async fn process(self: &Arc<Self>, key: &AddrKey, t: Transport) {
        let network = classify(&key.host);
        let timeouts = self.settings.timeouts_for(network);
        let max_attempts = self.settings.node_settings.handshake_attempts;

        // Count this processing iteration (Section 6.2 counter).
        let attempt = self
            .store
            .with_entry(key, |e| {
                e.stats.handshake_attempts += 1;
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
                tracing::debug!(
                    "connect failed for {} [{}]: {e}",
                    key.render(),
                    kind.as_str()
                );
                self.finish(key, NodeState::Unreachable, Some(kind));
                return;
            }
        };
        let connect_ms = connect_start.elapsed().as_millis() as u64;
        self.store
            .with_entry(key, |e| e.stats.time_connect_ms = Some(connect_ms));

        let mut conn = conn;

        // 2–5. Handshake (Section 3.2).
        match self
            .handshake(&mut conn, key, &timeouts, network)
            .await
        {
            HandshakeResult::Version(v, sent_ts, duration_ms) => {
                let hd = HandshakeData::from_version(&v, sent_ts, duration_ms);
                self.store.with_entry(key, |e| {
                    e.handshake = Some(hd.clone());
                });
                // 3.3 peer discovery — skipped in direct-probe mode so the run
                // never enqueues addresses beyond the seeded node list.
                if !self.settings.probe_mode {
                    self.getaddr(&mut conn, key, &timeouts, network, &hd).await;
                }
                self.finish(key, NodeState::Reachable, None);
            }
            HandshakeResult::Timeout => {
                // Full-deadline silence: do not retry unless configured (6.2).
                if self.settings.retry_on_timeout && attempt < max_attempts {
                    self.requeue(key, t);
                } else {
                    self.finish(key, NodeState::HandshakeFailed, Some(FailKind::HandshakeTimeout));
                }
            }
            HandshakeResult::Failed(kind) => {
                // Mid-handshake transport/protocol error: retry if attempts
                // remain (6.2), otherwise record the specific reason.
                if attempt < max_attempts {
                    self.requeue(key, t);
                } else {
                    self.finish(key, NodeState::HandshakeFailed, Some(kind));
                }
            }
        }
        // Disconnect happens by dropping `conn`.
    }

    /// Lateral Processing → Queued move; does not change `outstanding` (3.5).
    fn requeue(&self, key: &AddrKey, t: Transport) {
        self.store.with_entry(key, |e| e.state = NodeState::Queued);
        if self.queues.sender(t).try_send(key.clone()).is_err() {
            // Channel closed mid-crawl: treat as terminal to keep the counter sane.
            self.finish(key, NodeState::HandshakeFailed, Some(FailKind::HandshakeOther));
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
                session.connect(&key.host, connect_timeout).await?
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
        self.sam
            .get_or_init(|| async {
                match SamSession::create(&ns.i2p_sam_host, ns.i2p_sam_port, connect_timeout).await {
                    Ok(s) => Some(Arc::new(s)),
                    Err(e) => {
                        tracing::warn!("failed to create SAM session: {e}");
                        None
                    }
                }
            })
            .await
            .clone()
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
        // Record the first version-send timestamp (Section 7.4).
        self.store.with_entry(key, |e| {
            if e.stats.first_version_send_ts.is_none() {
                e.stats.first_version_send_ts = Some(sent_ts);
            }
        });

        // Send our version.
        let nonce = rand::random::<u64>();
        let payload = build_version(sent_ts, nonce);
        if conn.send("version", &payload).await.is_err() {
            return HandshakeResult::Failed(FailKind::VersionSendFailed);
        }

        // Wait for the peer's version (Section 3.2 step 3, 4.1 receive loop).
        let deadline = start + Duration::from_secs(timeouts.message);
        let per = Duration::from_secs(timeouts.message);
        let peer_version = match self.recv_matching(conn, &["version"], deadline, per).await {
            RecvResult::Message(env) => match parse_version(&env.payload) {
                Some(v) => v,
                None => return HandshakeResult::Failed(FailKind::MalformedVersion),
            },
            RecvResult::Timeout => return HandshakeResult::Timeout,
            RecvResult::Transport(e) => {
                return HandshakeResult::Failed(classify_handshake_error(&e))
            }
        };

        let duration_ms = start.elapsed().as_millis() as u64;

        // Step 4: send sendaddrv2 then verack.
        let _ = conn.send("sendaddrv2", &[]).await;
        let _ = conn.send("verack", &[]).await;

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
                        let _ = conn.answer_ping(&env.payload).await;
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
    ) {
        if conn.send("getaddr", &[]).await.is_err() {
            return;
        }
        let start = Instant::now();
        let deadline = start + Duration::from_secs(timeouts.getaddr);
        let idle = Duration::from_secs(timeouts.getaddr_idle);

        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let wait = (deadline - now).min(idle);
            match conn.recv_one(wait).await {
                Ok(Some(env)) => match env.command.as_str() {
                    "addr" => {
                        let addrs = parse_addr(&env.payload);
                        let n = addrs.len();
                        self.handle_addr_message(key, "addr", &addrs, hd).await;
                        if is_getaddr_reply_complete(n) {
                            break;
                        }
                    }
                    "addrv2" => {
                        let addrs = parse_addrv2(&env.payload);
                        let n = addrs.len();
                        self.handle_addr_message(key, "addrv2", &addrs, hd).await;
                        if is_getaddr_reply_complete(n) {
                            break;
                        }
                    }
                    "ping" => {
                        let _ = conn.answer_ping(&env.payload).await;
                    }
                    _ => { /* skip */ }
                },
                Ok(None) => break, // idle timeout: peer quiet, done
                Err(_) => break,   // transport error: done with what we collected
            }
        }
    }

    /// Process one addr/addrv2 message (Section 3.3 steps 3–6).
    async fn handle_addr_message(
        &self,
        responder: &AddrKey,
        message_type: &str,
        addrs: &[AdvertisedAddr],
        hd: &HandshakeData,
    ) {
        let now = now_epoch();

        // Step 4: per-node breakdown counts ALL advertised addresses.
        self.store.with_entry(responder, |e| {
            for a in addrs {
                e.stats.record_advertised(a.network);
            }
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
            log.write_block(&r, addrs).await;
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
            }
        }
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
                    tracing::warn!(
                        "[STATUS] crawl runtime exceeded 12h ({runtime}s)"
                    );
                }
                return;
            }
            let elapsed_h = self.start_clock.elapsed().as_secs_f64() / 3600.0;
            let r = self.store.count_state(NodeState::Reachable);
            let f = self.store.count_state(NodeState::HandshakeFailed);
            let u = self.store.count_state(NodeState::Unreachable);
            let q = self.store.count_state(NodeState::Queued);
            let p = self.store.count_state(NodeState::Processing);
            tracing::info!(
                "[STATUS] Elapsed: {elapsed_h:.1}h  reachable={r} handshake_failed={f} unreachable={u} queued={q} processing={p}"
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
    Failed(FailKind),
}

enum RecvResult {
    Message(crate::transport::Envelope),
    Timeout,
    Transport(std::io::Error),
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

/// Decide whether an addr/addrv2 message of length `n` completes the getaddr
/// reply, so the collection loop can stop early instead of waiting for the idle
/// timeout.
///
/// The discriminator is *substance*, not chunk size. Bitcoin Core sends its
/// self-announcement (the peer's own address) as its own standalone message of
/// exactly one address, right alongside the getaddr reply (net_processing.cpp
/// `MaybeSendAddr`). A length-based "sub-1000 means done" test would break on
/// that self-announcement and miss the real dump, so instead:
///   - `n >= MAX_ADDR_TO_SEND`: a full chunk; more may follow, keep reading.
///   - `1 < n < MAX_ADDR_TO_SEND`: the substantive final chunk, we are done.
///   - `n <= 1`: a self-announcement (or empty); ignore and keep waiting for the
///     real reply, falling back to the idle timeout if none arrives.
///
/// This mirrors Core's own AddrFetch completion rule (`vAddr.size() > 1`).
fn is_getaddr_reply_complete(n: usize) -> bool {
    n > 1 && n < MAX_ADDR_TO_SEND
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
    fn getaddr_reply_completion_ignores_self_announcements() {
        // Self-announcement (1 addr) or empty: not the dump, keep waiting.
        assert!(!is_getaddr_reply_complete(0));
        assert!(!is_getaddr_reply_complete(1));
        // Substantive, non-full chunk: the reply is complete.
        assert!(is_getaddr_reply_complete(2));
        assert!(is_getaddr_reply_complete(MAX_ADDR_TO_SEND - 1));
        // Full chunk: more may follow, keep reading.
        assert!(!is_getaddr_reply_complete(MAX_ADDR_TO_SEND));
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
}
