# Crawler review — fix plan

Detailed implementation plan for the accepted subset of review findings.
All facts below were verified against the vendored Bitcoin Core in `bitcoin/`.

## Scope

| ID | Fix | Files | Notes |
|----|-----|-------|-------|
| **C2** | Cancellation-safe framed receive (buffered `Connection`) | `transport.rs` | — |
| **H1** | Two-phase getaddr timeout (first-response vs inter-message idle) | `crawler.rs` | — |
| **H3** | Cap `addr`/`addrv2` decode at `MAX_ADDR_TO_SEND` | `protocol.rs` | — |
| **H4** | Flush `addr_responses.csv` at every checkpoint | `main.rs` | — |
| **M1** | Record a `parse_status` per addr block | `protocol.rs`, `crawler.rs`, `addrlog.rs` | — |
| **M3** | Stop mislabeling `fc00::/8` as CJDNS in the parse path | `protocol.rs` | confirmed — Core's `SetLegacyIPv6` never sets `NET_CJDNS`; CJDNS is assigned only from BIP155 net id 6 |
| **M5** | `num_processed` counts distinct nodes, not iterations | `crawler.rs` | — |
| **L1** | Remove `.expect("reachable has handshake")` | `output.rs` | — |
| **L2** | Stop swallowing send/write errors | `crawler.rs`, `addrlog.rs` | — |
| **L3** | Sync DNS seeds with Core | `dns.rs` | corrected — drop `seed.bitcoin.sipa.be` (stale); `bluematt`/`jonasschnelli` are still in Core's current mainnet list |

**Not fixed (explicitly declined):** C1 (routability filter), H2 (timestamp validation),
M2 (self-announcement provenance), M4 (onion/i2p label validation), L4 (version
addr_recv/addr_from capture), L5 (grouped-CSV → JSONL).

Sequencing matters: M1+H3+M3 change the signatures of `parse_addr`/`parse_addrv2`,
which ripple into `crawler.rs` and `addrlog.rs`. Do the modules in the order below.

---

## Step 1 — `transport.rs`: cancellation-safe `Connection` (C2)

**Problem:** `recv_one` = `timeout(per, read_exact(...))` over a bare `TcpStream`.
`read_exact` is not cancellation-safe; a timeout mid-payload consumes and discards
bytes → desync → the whole address response (and everything after) is lost, most
often on slow Tor/I2P links carrying a 1000-entry reply.

**Change:** give `Connection` a persistent buffer; read in chunks with the caller's
timeout (`AsyncReadExt::read` *is* cancellation-safe); parse complete envelopes out
of the buffer. A timeout now retains the partial bytes instead of dropping them.

```rust
pub struct Connection {
    stream: TcpStream,
    buf: Vec<u8>,          // unconsumed bytes carried across recv_one calls
}

impl Connection {
    pub fn new(stream: TcpStream) -> Self {
        Connection { stream, buf: Vec::with_capacity(64 * 1024) }
    }
    // send() and answer_ping() unchanged.

    pub async fn recv_one(&mut self, per_timeout: Duration) -> io::Result<Option<Envelope>> {
        loop {
            if let Some(env) = self.try_parse_buffered()? {
                return Ok(Some(env));
            }
            let mut chunk = [0u8; 16 * 1024];
            match timeout(per_timeout, self.stream.read(&mut chunk)).await {
                Err(_elapsed) => return Ok(None),                 // buffer RETAINED
                Ok(Ok(0))     => return Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof, "peer closed connection")),
                Ok(Ok(n))     => self.buf.extend_from_slice(&chunk[..n]),
                Ok(Err(e))    => return Err(e),
            }
        }
    }

    fn try_parse_buffered(&mut self) -> io::Result<Option<Envelope>> {
        if self.buf.len() < 24 { return Ok(None); }               // need full header
        if self.buf[0..4] != MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                "network magic mismatch (stream desynchronized)"));
        }
        let length = u32::from_le_bytes([self.buf[16], self.buf[17], self.buf[18], self.buf[19]]);
        if length > MAX_PROTOCOL_MESSAGE_LENGTH {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("payload length {length} exceeds 4 MiB")));
        }
        let total = 24 + length as usize;
        if self.buf.len() < total { return Ok(None); }            // payload incomplete
        let command  = parse_command(&self.buf[4..16]);
        let expected = [self.buf[20], self.buf[21], self.buf[22], self.buf[23]];
        let payload  = self.buf[24..total].to_vec();
        if checksum(&payload) != expected {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "payload checksum mismatch"));
        }
        self.buf.drain(0..total);
        Ok(Some(Envelope { command, payload }))
    }
}
```

- Delete the free `read_envelope`; keep `parse_command`, `MAGIC`, `checksum`,
  `MAX_PROTOCOL_MESSAGE_LENGTH`.
- Magic/oversize/checksum are still enforced *before* any large allocation. A magic
  mismatch now unambiguously means real desync (no cancellation artifact), so
  `Err(InvalidData)` is still correct and still maps to `ProtocolDesync` in
  `classify_handshake_error`.
- Multiple messages per read and split messages are both handled by the buffer loop.
- Optional: after `drain`, `if self.buf.is_empty() { self.buf.shrink_to(64 * 1024); }`
  to release the transient 4 MiB spike from an oversized message.

**Tests (new `transport.rs` mock-peer tests using `tokio::net::TcpListener`):**
- Payload written in two chunks with a delay > `per_timeout`: first `recv_one`
  returns `Ok(None)`, a later one returns the fully-parsed message (no desync).
  ← direct C2 regression.
- Two messages in one `write` → two successive `recv_one`s return both, in order.
- Header split across reads.
- Bad magic / oversize length / bad checksum → `Err(InvalidData)`.

---

## Step 2 — `protocol.rs`: parse status + receive cap + CJDNS fix (M1, H3, M3)

**M1/H3 — new return type.** Replace the `Vec<AdvertisedAddr>` return of
`parse_addr`/`parse_addrv2` with a struct carrying a status, and cap the loop.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseStatus { Complete, Truncated, UnknownNetId, LengthMismatch, Capped }

impl ParseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ParseStatus::Complete       => "complete",
            ParseStatus::Truncated      => "truncated",
            ParseStatus::UnknownNetId   => "unknown_netid",
            ParseStatus::LengthMismatch => "length_mismatch",
            ParseStatus::Capped         => "capped",
        }
    }
}

pub struct ParsedAddrs { pub addrs: Vec<AdvertisedAddr>, pub status: ParseStatus }
```

`parse_addr` — cap + status:
```rust
pub fn parse_addr(payload: &[u8]) -> ParsedAddrs {
    let mut c = Cursor::new(payload);
    let count = match c.compact_size() {
        Some(n) => n,
        None => return ParsedAddrs { addrs: Vec::new(), status: ParseStatus::Truncated },
    };
    let mut out = Vec::new();
    let mut status = ParseStatus::Complete;
    for _ in 0..count {
        if out.len() >= MAX_ADDR_TO_SEND { status = ParseStatus::Capped; break; }   // H3
        let ts = match c.u32_le() { Some(t) => t as i64, None => { status = ParseStatus::Truncated; break; } };
        if c.take(8).is_none() { status = ParseStatus::Truncated; break; }
        let ip = match c.take(16) { Some(b) => b, None => { status = ParseStatus::Truncated; break; } };
        let port = match c.u16_be() { Some(p) => p, None => { status = ParseStatus::Truncated; break; } };
        let mut arr = [0u8; 16]; arr.copy_from_slice(ip);
        let (host, network) = decode_ipv6_mapped(&arr);
        out.push(AdvertisedAddr { host, port, network, timestamp: ts });
    }
    ParsedAddrs { addrs: out, status }
}
```

`parse_addrv2` — same shape, but set `status = ParseStatus::Capped` on the cap,
`UnknownNetId` at the unknown-net-id break, `LengthMismatch` at the length break,
`Truncated` on any short read.

**M3 — remove the `0xfc → CJDNS` heuristic from the raw-16-byte decoder.** This path
is used by legacy `addr` and by `addrv2` net id 2 (IPv6); Core's `SetLegacyIPv6`
classifies these only as IPv4/IPv6/internal, never CJDNS. CJDNS stays produced *only*
by `decode_addrv2` net id 6 (unchanged).

```rust
fn decode_ipv6_mapped(arr: &[u8; 16]) -> (String, NetworkType) {
    let addr = std::net::Ipv6Addr::from(*arr);
    if let Some(v4) = ipv4_mapped(&addr) {
        (v4.to_string(), NetworkType::Ipv4)
    } else {
        (compact_ipv6(&addr), NetworkType::Ipv6)   // fc00::/8 -> IPv6, not CJDNS
    }
}
```
Leave `classify()` in `address.rs` unchanged — the spec (§4.2) mandates
`fc00::/8 → CJDNS` for host-string→transport selection, and a CJDNS host from net id
6 must still re-classify as CJDNS at connect time. The label now comes from the wire
net id, which is authoritative.

**Test updates (existing):** `addr_timestamp_zero_extends`,
`addrv2_torv3_roundtrips_through_classify`, `addrv2_length_mismatch_stops` now read
`.addrs` / assert `.status`.

**Tests (new):**
- Legacy `addr` with `fc00::…` → `NetworkType::Ipv6` (M3).
- `addrv2` net id 6 → `NetworkType::Cjdns` (unchanged path).
- `count = 2000` with 2000 records → `addrs.len() == 1000`, `status == Capped` (H3).
- Declared count larger than the bytes → `status == Truncated`.
- `addrv2` unknown net id → `status == UnknownNetId`; length mismatch → `LengthMismatch`.

---

## Step 3 — `addrlog.rs`: record parse status + surface write errors (M1, L2)

- Add `pub parse_status: &'a str` to `Responder`.
- Append it as the **last** field of the `===NEW NODE===` line (appending, not
  inserting, so existing column positions in `addr_responses.csv` don't shift):
  `===NEW NODE===, host, port, network, received_at, message_type, version, services, user_agent, latest_block, relay, parse_status`
- L2: replace the two `let _ = w.write_all(...)` / `let _ = w.flush()` with logged
  errors:
```rust
if let Err(e) = w.write_all(buf.as_bytes()) {
    tracing::warn!("addr-response log write failed: {e}");
}
```
(A persistent disk error would repeat the warning; acceptable since it's rare and
important. A one-shot `AtomicBool` guard is an optional refinement.)

---

## Step 4 — `crawler.rs`: getaddr timeout, parse wiring, distinct-node count, send errors (H1, M1, M5, L2)

**H1 — two-phase getaddr loop.** Reuse the existing per-network `message` timeout as
the *time-to-first-response* window (semantically "wait for one reply"); keep
`getaddr_idle` for the gap *after* the first response. No new CLI flag.

```rust
async fn getaddr(&self, conn: &mut Connection, key: &AddrKey,
                 timeouts: &crate::settings::Timeouts, _network: NetworkType, hd: &HandshakeData) {
    if conn.send("getaddr", &[]).await.is_err() { return; }
    let start = Instant::now();
    let deadline = start + Duration::from_secs(timeouts.getaddr);
    let idle           = Duration::from_secs(timeouts.getaddr_idle);
    let first_response = Duration::from_secs(timeouts.message);   // H1
    let mut got_first = false;

    loop {
        let now = Instant::now();
        if now >= deadline { break; }
        let window = if got_first { idle } else { first_response };
        let wait = (deadline - now).min(window);
        match conn.recv_one(wait).await {
            Ok(Some(env)) => match env.command.as_str() {
                "addr" => {
                    got_first = true;
                    let p = parse_addr(&env.payload);
                    let n = p.addrs.len();
                    self.handle_addr_message(key, "addr", &p.addrs, p.status, hd).await;
                    if is_getaddr_reply_complete(n) { break; }
                }
                "addrv2" => {
                    got_first = true;
                    let p = parse_addrv2(&env.payload);
                    let n = p.addrs.len();
                    self.handle_addr_message(key, "addrv2", &p.addrs, p.status, hd).await;
                    if is_getaddr_reply_complete(n) { break; }
                }
                "ping" => { let _ = conn.answer_ping(&env.payload).await; }
                _ => {}
            },
            Ok(None) => break,   // silence for the whole window (first_response, then idle)
            Err(_)   => break,
        }
    }
}
```
- `got_first` is set on any `addr`/`addrv2`, including a 1-entry self-announcement —
  the peer is answering address traffic, so switching to the short idle gap is
  correct and avoids a `message`-length wait for peers with a 1-address addrman.
- **Tradeoff to note:** a *reachable* peer that never answers `getaddr` now costs up
  to `message` (30 s IP) instead of 3 s. That set is a minority (Core always answers
  inbound `getaddr` unless already answered), and the cost is bounded by `getaddr`
  (70 s IP) and amortized across workers. If it proves material on `--max-nodes`
  runs, add a dedicated `getaddr_response` per-network timeout (4 CLI flags +
  `Timeouts` field) — deferred, not part of this change.

**M1 wiring:** `handle_addr_message` gains a `status: crate::protocol::ParseStatus`
parameter and sets `parse_status: status.as_str()` on the `Responder` it builds
(`crawler.rs:569`).

**M5 — distinct-node count.**
- Remove `self.num_processed.fetch_add(1, Ordering::SeqCst);` from `worker_loop`
  (line 219).
- In `process`, right after `attempt` is computed (line ~239), count only the first
  attempt:
```rust
if attempt == 1 {
    self.num_processed.fetch_add(1, Ordering::SeqCst);
}
```
`attempt == 1` iff this is the node's first processing (retries increment
`handshake_attempts` to ≥2). This makes both `--max-nodes` and the
`num_processed_nodes` stat mean *distinct nodes*, not iterations. The cap remains
approximate under concurrency (unchanged from today).

**L2 — handshake send errors** (`crawler.rs:458-459`): keep `Reachable` semantics
(peer's `version` received = success per spec §3.2) but log instead of discarding:
```rust
if let Err(e) = conn.send("sendaddrv2", &[]).await {
    tracing::debug!("{}: sendaddrv2 send failed: {e}", key.render());
}
if let Err(e) = conn.send("verack", &[]).await {
    tracing::debug!("{}: verack send failed: {e}", key.render());
}
```

**Tests (new, mock peer):**
- Peer that stays silent after `getaddr` for `> getaddr_idle` but `< message`, then
  sends a full reply → reply is collected (H1 regression; today it would be lost).
- Peer that never replies → loop ends after ~`message`, node `Reachable` with
  `advertised_total = 0`.
- A node forced through one retry → `num_processed` increments by 1, not 2 (M5).

---

## Step 5 — `output.rs`: remove latent panic (L1)

`write_reachable` (line ~98): replace `.expect(...)` with a skip-and-warn so a future
invariant break degrades gracefully:
```rust
for (key, e) in rows {
    let Some(h) = e.handshake.as_ref() else {
        tracing::warn!("reachable node {} missing handshake data; skipping", key.render());
        continue;
    };
    let s = &e.stats;
    // ... existing row write ...
}
```

---

## Step 6 — `main.rs`: flush the addr log at checkpoints (H4)

- Add a parameter to `spawn_checkpoint`: `addr_log: Option<Arc<AddrLog>>`, and pass
  `addr_log.clone()` from `async_main`.
- Inside the checkpoint loop, after a successful `write_all`, flush the buffered addr
  log so a hard kill can't leave `reachable_nodes.csv` referencing responders whose
  blocks are still in the 8 KB `BufWriter`:
```rust
match output::write_all(&store, &settings, &seeds, runtime, processed) {
    Ok(()) => {
        if let Some(log) = &addr_log { log.flush().await; }   // H4
        tracing::info!("checkpoint: result files written ({processed} processed)");
    }
    Err(e) => tracing::warn!("checkpoint write failed: {e}"),
}
```
The end-of-run `addr_log.flush()` in `async_main` stays. `probe` needs no change (no
checkpoint, no addr log).

---

## Step 7 — `dns.rs`: sync seeds with Core (L3)

Drop `seed.bitcoin.sipa.be.` (absent from the vendored Core's `chainparams.cpp`
lines 168–174); keep the rest. Final list matches Core exactly:
```rust
pub const SEEDS: &[&str] = &[
    "dnsseed.bluematt.me.",
    "seed.bitcoin.jonasschnelli.ch.",
    "seed.btc.petertodd.net.",
    "seed.bitcoin.sprovoost.nl.",
    "dnsseed.emzy.de.",
    "seed.bitcoin.wiz.biz.",
    "seed.mainnet.achownodes.xyz.",
];
```

---

## Step 8 — Documentation (`SPECIFICATION_v2.md`, `README.md`)

These changes deviate from the documented behavior; update the spec:
- **§3.3 / §6.1:** getaddr collection now uses `message` as the time-to-first-response
  bound; `getaddr_idle` applies only after the first `addr`/`addrv2` (H1).
- **§4.3:** `addr`/`addrv2` decode is capped at `MAX_ADDR_TO_SEND` (H3); legacy `addr`
  and `addrv2` net id 2 in `fc00::/8` classify as **IPv6**, CJDNS only via net id 6 (M3).
- **§8.5:** the `===NEW NODE===` line gains a trailing `parse_status` column (M1).
- **§3.1:** DNS seed list (drop `sipa.be`) (L3).
- **§7:** `num_processed_nodes` now counts distinct nodes (M5).

---

## Verification

1. `cargo test` — updated unit tests (protocol return-type/status/M3/cap) + new
   `transport.rs` and `crawler.rs` mock-peer tests (C2, H1, M5).
2. `cargo clippy --all-targets` — clean (watch for the `read_envelope` removal and
   the new `ParsedAddrs`).
3. Manual smoke: `probe <a few known-good mainnet nodes>` → reachable with non-zero
   advertised counts, exercising the buffered receive path against real peers.
4. Targeted C2 check: point `probe`/crawler at an I2P/Tor peer (or a throttled mock)
   returning a full 1000-entry `addrv2`; confirm `advertised_total ≈ 1000` (pre-fix
   this frequently recorded 0).
5. H4 check: run the crawler, `kill -9` mid-run, confirm `addr_responses.csv` tail is
   present up to the last checkpoint.

## Suggested commit slicing
1. `transport: buffer reads so a receive timeout can't desync the stream` (C2)
2. `protocol: cap addr/addrv2 decode and report a parse status; stop labeling fc00::/8 as CJDNS in the addr path` (H3, M1-core, M3)
3. `crawler: two-phase getaddr timeout, record parse status, count distinct nodes` (H1, M1-wiring, M5, L2)
4. `output/addrlog/main: durable addr log at checkpoints, no reachable panic, log write errors` (H4, L1, L2)
5. `dns: sync mainnet seeds with Bitcoin Core` (L3)
6. `docs: update spec for timeout model, parse_status, cap, seeds`
