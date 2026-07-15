# Bitcoin P2P crawler correctness review

Reviewed crawler commit: `5d2d1558d85234ef5fbbd711f7c20d93cd4969b8`  
Reference Bitcoin Core commit: `e3554bf361ff6979b09fdedfdcbebf687590cd1c`

Line numbers below refer to those revisions. Findings marked **Confirmed** follow
directly from the current implementation. Findings marked **Risk** need an
operational decision or additional evidence.

## Executive summary

The implementation is **not reliable enough for research data collection yet**.
Its basic mainnet envelope and common address encodings are mostly correct, and
per-peer connection objects avoid an obvious cross-task attribution race. However,
the crawler can silently discard a valid response after a receive timeout, accept
and persist a partially decoded malformed response as if complete, stop before
additional address messages, classify a version-only exchange as a completed
handshake, and overwrite or retain stale files when a run directory is reused.

The highest security concern is that an untrusted peer controls the crawl frontier.
Every decoded IP and port, including loopback, private, link-local, multicast,
unspecified, documentation ranges, and port zero, is queued for connection. This is
an SSRF/network-scanning primitive against the crawler host and its surrounding
network. Peer timestamps are also trusted when deciding freshness, so one malicious
response can keep poisoned destinations eligible indefinitely.

The current result schema records claims as facts. It does not preserve the actual
socket endpoint, the peer's `version.addr_from`/`addr_recv`, request timing, parser
status, declared versus decoded counts, or a collection outcome. Consequently a
zero-address row cannot distinguish no response, a failed `getaddr` write, malformed
input, a checksum failure, timeout, or disconnect. A partial response is
indistinguishable from a complete response.

What is already correct:

* Mainnet magic `f9beb4d9`, 24-byte v1 envelope layout, little-endian payload length,
  double-SHA256 checksum, and big-endian ports are implemented correctly.
* `version`, `sendaddrv2`, `verack`, and `getaddr` are written in TCP order; therefore
  a Core peer sees this crawler's `verack` before its `getaddr`.
* IPv4-mapped IPv6, native IPv6 formatting, Tor v3 checksum/encoding, I2P base32,
  and BIP155 fixed sizes for known networks are mostly correct.
* Each worker owns its `Connection` and passes its own immutable `AddrKey`; the
  address-log mutex serializes blocks. I found no confirmed one-peer-to-another
  closure-capture or shared-buffer attribution bug.
* Unknown unrelated commands are not treated as address responses; `ping` is the
  only unrelated command answered.
* `cargo test --all-targets` passes all 21 tests. This is weak coverage: there are no
  socket/parser lifecycle, persistence, concurrency, fuzz, or mock-peer tests.

## Critical issues

### C1. Untrusted gossip becomes an unrestricted connection target (Confirmed)

**Location:** `src/crawler.rs:580-599`; `src/address.rs:58-94`.

```rust
let mut enabled: Vec<&AdvertisedAddr> = addrs
    .iter()
    .filter(|a| self.settings.is_enabled(a.network))
    .collect();
// ...
let akey = AddrKey::new(a.host.clone(), a.port);
let outcome = self.store.frontier_upsert(/* ... */);
if outcome == FrontierOutcome::Enqueue {
    self.enqueue(akey);
}
```

**Why this is wrong:** `is_enabled` checks only the broad network type. It does not
reject `127.0.0.1`, `0.0.0.0`, RFC1918, link-local, multicast, documentation space,
IPv6 ULA, IPv6 scope-local addresses, or port zero. The parser also discards each
address's service flags, so crawl eligibility cannot require useful services.
Bitcoin Core applies validity/routability and reachability logic before adding
received addresses to addrman (`bitcoin/src/netaddress.cpp:424-464`,
`bitcoin/src/net_processing.cpp:5791-5814`). A Core CJDNS address is valid only with
the `fc00::/8` prefix (`netaddress.cpp:432-434`).

**Failure scenario:** a hostile reachable peer returns `127.0.0.1:22`,
`192.168.1.1:80`, cloud metadata addresses, and internal IPv6 targets with future
timestamps. Hundreds of workers then scan those destinations from the crawler's
network context. Successful non-Bitcoin TCP services are recorded as handshake
failures, while the malicious claims pollute raw and aggregate results.

**Exact correction:** retain every syntactically decodable entry in an immutable
raw-observation log, but run a separate `validate_for_frontier` policy before
enqueueing. Capture services. Reject port zero, invalid BIP155 combinations,
non-routable IPs, Onion v2, and networks disabled by policy. Make private/local
probing an explicit dangerous opt-in, never the default. Store a rejection reason
(`non_routable`, `zero_port`, `invalid_cjdns_prefix`, `unsupported_tor_v2`,
`insufficient_services`) rather than silently dropping the claim.

**Test:** a mock peer returns loopback, RFC1918, multicast, documentation, link-local,
unspecified, port-zero, invalid-CJDNS, valid public IPv4/IPv6, Tor v3, and I2P entries.
Assert all appear as raw claims, only eligible entries reach the frontier, and no
socket connect is attempted for rejected entries.

### C2. Receive timeouts cancel `read_exact` after consuming bytes (Confirmed)

**Location:** `src/transport.rs:35-42`, `55-89`.

```rust
match timeout(per_timeout, read_envelope(&mut self.stream)).await {
    Err(_elapsed) => Ok(None),
    Ok(res) => res.map(Some),
}
// read_envelope:
stream.read_exact(&mut header).await?;
// ...
stream.read_exact(&mut payload).await?;
```

**Why this is wrong:** Tokio's `read_exact` future is not cancellation-safe. If the
timeout expires after consuming part of the header or payload, those bytes are lost
from the local stack frame. The next `recv_one` starts a new header at the middle of
the old message and normally reports bad magic. This is not ordinary TCP
fragmentation; it is destructive cancellation at the timeout boundary.

**Failure scenario:** a Tor peer sends a valid 1000-entry `addrv2` response slowly.
Five seconds elapse after part of the payload is read. `recv_one` returns `None`, the
getaddr loop ends, and the peer is saved as reachable with zero addresses. During a
handshake the same sequence becomes a false `protocol_desync`.

**Exact correction:** make `Connection` own an unconsumed byte buffer. Use
cancel-safe `read`, append chunks, and parse only when a full 24-byte header and the
declared bounded payload are present. Retain partial bytes across idle timeouts.
Track a separate absolute deadline for completing one envelope so a slowloris cannot
hold a connection indefinitely. Validate magic, command bytes, length, and checksum
before yielding an envelope.

**Test:** split a valid envelope in the payload, wait longer than the per-read idle
timeout, assert the first call times out and a later call returns the intact message.
Also split every header boundary and test two envelopes in one write.

### C3. Malformed and oversized address messages are silently saved as partial data (Confirmed)

**Location:** `src/protocol.rs:236-335`; `src/crawler.rs:521-535`.

```rust
for _ in 0..count {
    let ts = match c.u32_le() { Some(t) => t as i64, None => break };
    // every parse failure breaks
    out.push(AdvertisedAddr { /* ... */ });
}
return out;
```

**Why this is wrong:** the return type cannot say whether decoding was complete.
Truncation, invalid known-network length, unknown network id, and a valid empty list
all collapse to a vector. The caller logs and enqueues the prefix, then may treat its
length as proof the response is complete. Counts over Core's
`MAX_ADDR_TO_SEND == 1000` are accepted. Non-canonical CompactSize values are also
accepted (`Cursor::compact_size`, lines 119-126), whereas Core's `ReadCompactSize`
rejects them (`bitcoin/src/serialize.h:333-360`). Core rejects an address vector over
1000 (`net_processing.cpp:5754-5758`).

For unknown BIP155 network ids, Core consumes that address and continues with later
entries (`netaddress.h:431-471`); this parser stops at the unknown id and loses all
subsequent valid entries. A wrong length for a founding BIP155 network is a malformed
message in Core (`netaddress.cpp:49-97`), not a valid partial response.

**Failure scenario:** a message declares three entries, encodes two valid public
nodes, and truncates the third. The crawler persists and enqueues two entries, ends
collection because `2 < 1000`, and provides no indication that the wire response was
malformed. Researchers count it as an accurate two-address response.

**Exact correction:** return `Result<ParsedAddrMessage, AddrParseError>` with
`declared_count`, `decoded_count`, per-entry raw network id/length/services,
`unknown_entries`, and `parse_status`. Reject non-canonical CompactSize, count >1000,
trailing bytes when the grammar is exhausted, truncated entries, and wrong lengths.
Unknown future network ids should be bounds-checked, retained as opaque bytes, skipped
for frontier use, and parsing should continue. Never enqueue any prefix from a
structurally malformed message; optionally preserve the raw payload hash and the
decoded prefix in a quarantine record explicitly marked invalid.

**Test:** cover count 1001, truncated final entry, non-canonical count/services/length,
wrong known-network length, unknown id followed by valid IPv4, and trailing garbage.
Assert no malformed prefix reaches the frontier.

### C4. Address collection has no trustworthy completion model (Confirmed)

**Location:** `src/crawler.rs:498-546`, `688-705`.

```rust
let wait = (deadline - now).min(idle);
match conn.recv_one(wait).await {
    // ...
    if is_getaddr_reply_complete(n) { break; }
    // ...
    Ok(None) => break,
    Err(_) => break,
}
// complete iff n > 1 && n < 1000
```

**Why this is wrong:** before the first response, the crawler waits only the 3/5/8s
idle interval, not the configured 70/90/170s collection budget. A valid delayed
response is lost. Conversely, each unrelated message starts a fresh idle wait, so
`ping` traffic moves the effective first-response deadline until the hard deadline.
After a 2..999 entry message it exits immediately, missing a following `addrv2` or
additional address message. It waits unnecessarily after exactly 1000 even though
Core caps the whole reply at 1000 and sends the queued vector in one message
(`net_processing.cpp:4925-4958`, `5496-5565`).

The cited Core AddrFetch rule (`vAddr.size() > 1`, lines 5824-5828) is a specialized
Core connection-disconnect policy, not a wire-level end-of-response marker. The
protocol has no request id or terminal message. Importing that heuristic cannot prove
the crawler has collected all messages attributable to `getaddr`.

**Failure scenario:** a loaded peer answers after four seconds; IP collection has
already ended. Another peer sends 40 `addr` entries followed 200ms later by 30
`addrv2` entries; only the first block is recorded.

**Exact correction:** use absolute phase deadlines: `first_addr_deadline` starts only
after `getaddr` is fully written and is not reset by unrelated traffic; after every
valid address message, set `quiet_deadline = received_at + inter_addr_idle`; retain a
hard total deadline. Complete only on quiet-after-first-response, hard deadline,
disconnect/error, or cancellation. Never infer completion from entry count. Persist
the completion reason and whether valid messages had already been collected.

**Test:** delayed first response; repeated pings before response; `addr` then
`addrv2`; two sub-1000 messages; exactly-1000 response; no response; response just
before each deadline.

### C5. A peer `version` alone is labeled as a completed handshake (Confirmed)

**Location:** `src/crawler.rs:441-461`, `284-295`.

```rust
let peer_version = self.recv_matching(conn, &["version"], /* ... */);
let _ = conn.send("sendaddrv2", &[]).await;
let _ = conn.send("verack", &[]).await;
HandshakeResult::Version(peer_version, sent_ts, duration_ms)
// caller sends getaddr and finishes Reachable
```

**Why this is wrong:** the crawler never observes the peer's `verack`, ignores both
feature-negotiation write failures, and still marks the node `Reachable`. Bitcoin
Core sets `fSuccessfullyConnected` only when it processes `VERACK`
(`bitcoin/src/net_processing.cpp:3862-3939`). BIP155 negotiation must occur between
`VERSION` and `VERACK` (Core lines 3994-4004). The crawler's TCP order does put its
own `verack` before `getaddr`, so Core interoperability is usually okay, but the
recorded claim “completed handshake” is false.

It also sends `sendaddrv2` to every version. Core sends it only when the common
version is at least 70016 as a compatibility courtesy (`net_processing.cpp:3755-3762`).
The parser accepts obsolete versions below Core's minimum 31800 and user agents over
Core's 256-byte limit (`net_processing.cpp:3660-3678`, `net.h:65-67`).

**Failure scenario:** a service sends a syntactically valid `version` then closes.
All subsequent writes fail, but the crawler records the endpoint as a reachable
Bitcoin node with a completed handshake and zero advertised addresses.

**Exact correction:** implement explicit states `TcpConnected -> VersionSent ->
PeerVersionReceived -> NegotiationSent -> OurVerackSent -> PeerVerackReceived ->
GetAddrSent -> Collecting -> Finalized`. Check every write. Send `sendaddrv2` only
after a valid peer version and before our `verack` (optionally conditioned on common
version >=70016). Then wait within the handshake deadline for peer `verack`, handling
`sendaddrv2`, `wtxidrelay`, `ping`, and other permitted pre-verack messages. Reject or
record duplicates/protocol-order violations. Only `PeerVerackReceived` is handshake
success.

**Test:** version without verack, verack then disconnect, verack delayed, Core-like
`version+sendaddrv2+verack` coalesced in one write, duplicate version/verack, and a
write failure after peer version.

### C6. Run reuse and non-transactional snapshots can mix stale and partial output (Confirmed)

**Location:** `src/settings.rs:130-146`, `357-359`; `src/main.rs:27-33`;
`src/output.rs:21-26`, `61-68`, `132-139`, `176-183`, `343-351`.

```rust
std::fs::create_dir_all(&run_dir)?;
let file = std::fs::File::create(path)?; // truncates in place
if rows.is_empty() {
    return Ok(()); // old file, if any, remains
}
```

**Why this is wrong:** run ids have one-second resolution and user-supplied
timestamps are allowed. Existing run directories are silently reused. Nonempty
snapshot files are truncated and rewritten, while a category with zero current rows
is not rewritten or removed. Thus an old `reachable_nodes.csv` can coexist with a
new stats file claiming zero reachable nodes. A crash during a checkpoint can leave
truncated CSV/JSON, and sequential replacement of four files can expose different
generations. `num_advertised` is read from live `store.len()` rather than the snapshot
(`output.rs:330`), so even a successful checkpoint can be internally inconsistent.

**Failure scenario:** two runs use `--timestamp experiment`. The second has no
reachable peers. It leaves the first run's `reachable_nodes.csv`, overwrites other
files, and reports success. A researcher later joins mutually inconsistent files as
one run.

**Exact correction:** create a collision-resistant `run_id` and fail if its directory
already exists/nonempty unless an explicit resume mode validates a manifest. Always
write every snapshot category, including header-only empty files. Write each
generation to temporary files, flush and `sync_all`, rename atomically, then atomically
publish a manifest containing generation id and hashes. Compute all counts from one
immutable snapshot. Keep the append log separate with a durable watermark.

**Test:** reuse an explicit timestamp; write nonempty then empty categories; inject a
failure after each file/temp write; verify old complete generation or new complete
generation is visible, never a mixture or invalid JSON/CSV.

### C7. Address-log I/O failures and crash loss are silent (Confirmed)

**Location:** `src/addrlog.rs:25-29`, `67-73`; `src/main.rs:135-137`, `150-179`.

```rust
let mut w = self.inner.lock().await;
let _ = w.write_all(buf.as_bytes());
// ... only at normal finalization:
let _ = w.flush();
```

**Why this is wrong:** the mutex prevents concurrent interleaving within this
process, but write and flush failures are discarded. The `BufWriter` is not flushed at
periodic checkpoints and is not synced to stable storage. A disk-full or I/O error
silently loses provenance while aggregate reachable rows still report advertised
counts. A process crash can lose the buffered tail; a partial block has no checksum or
record id by which to detect truncation.

**Failure scenario:** the disk fills after aggregate state is updated. Every later
address block is absent, no error reaches process exit, and `reachable_nodes.csv`
claims thousands of advertisements that cannot be audited back to their responders.

**Exact correction:** use a single bounded writer task. Encode one self-contained
JSONL response event into bytes, assign a monotonic sequence/event id, write through
one `write_all`, propagate errors to crawler health, and flush/sync at a documented
checkpoint policy. Final output must record the last durable event id. On persistent
write failure, stop accepting research results or mark the run failed/incomplete.

**Test:** an injectable writer that performs short writes and then errors; disk-full
simulation; concurrent producer load; crash/truncate every byte offset and verify a
reader accepts only complete newline/checksummed events and reports the lost tail.

### C8. Zero worker concurrency hangs the crawl forever (Confirmed)

**Location:** `src/settings.rs:229-238`, `375-390`; `src/crawler.rs:128-176`.

```rust
for (transport, count) in [/* CLI-provided counts */] {
    for _ in 0..count {
        handles.push(tokio::spawn(/* worker */));
    }
}
```

**Why this is wrong:** concurrency values are not validated. If IP concurrency is
zero, DNS seeds remain queued with `outstanding > 0`, no IP worker can finish them,
other transport workers wait on open empty queues, and the monitor never exits.

**Failure scenario:** `--ip-concurrency 0` with default IPv4/IPv6 enabled produces a
permanent hang rather than a configuration error.

**Exact correction:** validate at startup that every enabled transport has at least
one worker (and impose a sane maximum). A zero value may disable a transport only if
all corresponding networks are disabled and no address can be routed to its queue.

**Test:** all combinations of enabled networks and zero/nonzero pools; assert invalid
config fails immediately and valid config terminates.

## High-priority issues

1. **Envelope command validation is too permissive (Confirmed):**
   `src/transport.rs:92-95` truncates at the first NUL and uses lossy UTF-8. A wire
   command `addr\0garbage` is treated as `addr`. Core requires printable ASCII and all
   zeros after the first NUL (`bitcoin/src/protocol.cpp:26-42`). Reject malformed
   command fields before dispatch.

2. **The payload limit differs from Core (Confirmed):**
   `src/protocol.rs:12-13` uses `4 * 1024 * 1024`; Core uses `4 * 1000 * 1000`
   (`bitcoin/src/net.h:64-65`). The crawler accepts 194,304 bytes that Core rejects.

3. **Legacy/BIP155 network semantics are wrong (Confirmed):**
   `src/protocol.rs:337-346` labels every legacy `fc00::/8` as CJDNS. Core's
   `SetLegacyIPv6` does not (`bitcoin/src/netaddress.cpp:140-164`). Legacy OnionCat
   Tor v2 and internal prefixes are instead saved as ordinary IPv6. BIP155 network-id
   2 containing embedded IPv4 is accepted/collapsed although Core makes it invalid;
   network-id 6 without `fc00` is accepted; current Core silently ignores Tor v2.
   Network type must derive from both the wire encoding and validation rules.

4. **Peer timestamps are trusted for frontier freshness (Confirmed):**
   `src/store.rs:261-293` accepts any `u32` timestamp, including far future values.
   Core replaces timestamps <=100,000,000 or >now+10 minutes with now-5 days
   (`bitcoin/src/net_processing.cpp:5797-5799`). Store literal and normalized values
   separately; use only policy-normalized time for scheduling.

5. **Response/request outcomes are absent (Confirmed):** `getaddr` returns `()` and
   swallows send, receive, parse, disconnect, and timeout distinctions
   (`src/crawler.rs:499-546`). Reachable with zero results is therefore unauditable.
   Return a typed `CollectionOutcome` and persist it even when no address message
   arrives.

6. **Connection and version provenance is discarded (Confirmed):** `VersionData`
   drops `addr_recv`, `addr_from`, their services/ports, and nonce
   (`src/protocol.rs:170-211`); `Connection` exposes no `local_addr`/`peer_addr`.
   Record requested endpoint, actual TCP peer endpoint (noting proxy endpoints),
   local socket, transport destination, and both peer-claimed version netaddrs.

7. **Global dedup can destroy provenance when raw logging is disabled (Confirmed):**
   `AddrKey(host,port)` is the only global key and `frontier_upsert` collapses all
   sources. The optional raw log is the only source relationship. Provenance must be
   mandatory for research runs; dedup only the connection frontier, never observation
   events. Normalize before computing the frontier key.

8. **Unbounded queues/frontier permit memory exhaustion (Confirmed):** all three
   channels are unbounded (`src/crawler.rs:28-34`) and every accepted address gets a
   permanent DashMap entry. Use bounded queues, a crawl-wide unique-address budget,
   backpressure, and explicit `budget_rejected` observations.

9. **I2P initialization failure is cached forever (Confirmed):**
   `OnceCell<Option<Arc<SamSession>>>` stores `None` after one failed SAM creation
   (`src/crawler.rs:400-415`). A temporarily unavailable router biases every I2P
   result for the rest of the run. Cache only successful sessions or use bounded
   retry/backoff and recreate a dead session.

10. **Retries erase attempt history (Confirmed):** one `time_connect_ms`, one first
    send timestamp, and one final failure reason represent up to three attempts.
    Later connects overwrite timing. Persist an attempt event per connect/handshake;
    derive node summaries afterward.

11. **Worker task failures are ignored (Risk):** join errors at
    `src/crawler.rs:164-175` are discarded. A panic before `finish` can strand
    `outstanding` and hang remaining workers. Propagate join failures, use a per-item
    completion guard, and close/cancel the crawl on worker death.

12. **`max_nodes` is neither strict nor distinct-node based (Confirmed):** the check
    and increment are separate across workers and retries increment `num_processed`
    (`src/crawler.rs:208-220`). It can overshoot by the worker count and reports
    attempts as nodes. Reserve an atomic permit only on a node's first attempt.

## Medium and low-priority issues

* **Medium:** the current grouped CSV has heterogeneous row shapes, no header,
  schema version, event id, declared count, parser status, request id, or completion
  status (`src/addrlog.rs:32-66`). It is syntactically CSV but operationally fragile.
* **Medium:** `answer_ping` pads short payloads and truncates long ones
  (`src/transport.rs:45-51`). Validate the negotiated ping form and reject/ignore
  malformed payloads; do not fabricate a nonce.
* **Medium:** the addr logger performs blocking filesystem writes while holding a
  Tokio mutex on runtime threads. A bounded dedicated blocking writer provides
  backpressure and keeps network timers meaningful.
* **Medium:** checkpoints snapshot DashMap shards at different instants. This is
  acceptable only if the manifest labels them fuzzy/in-progress; final research
  output should be derived after workers stop or from an event log.
* **Medium:** current Core returns at most 23% and 1000 addresses and caches a
  per-requestor response for roughly 21-27 hours (`bitcoin/src/net_processing.cpp:188,
  4925-4958`; `bitcoin/src/net.cpp:3771-3806`). Output must not call one response a
  complete addrman view, and reconnect sampling can be cached/biased.
* **Low:** the hard-coded seed list includes stale `seed.bitcoin.sipa.be`
  (`src/dns.rs:8-17`), absent from this Core revision's mainnet list
  (`bitcoin/src/kernel/chainparams.cpp:168-174`). Record seed configuration and
  resolution time in the run manifest.
* **Low:** `frame` panics if an internal caller passes a command over 12 bytes
  (`src/protocol.rs:31-36`). Return `Result` and validate command syntax.
* **Low:** `write_reachable` uses an invariant `expect` (`src/output.rs:98`). Avoid a
  persistence-time panic; reject impossible state transitions earlier and surface a
  structured integrity error.
* **Low:** default user agent claims `/Satoshi:27.0.0/` although this is not Bitcoin
  Core (`src/protocol.rs:21`). Use a truthful crawler-specific agent; this also helps
  remote operators understand traffic.
* **Low:** `cargo clippy --all-targets -- -D warnings` fails only on
  `NodeStore::len` without `is_empty` (`src/store.rs:202`). This is not a correctness
  defect but shows the strict lint gate is not currently clean.

## Protocol flow trace

### Current successful path

1. DNS seed results become `AddrKey(host,8333)` and enter an unbounded transport
   queue. `outstanding` is incremented before enqueue.
2. A worker marks the entry `Processing`, increments attempt/processed counters, and
   opens direct TCP, SOCKS5, or SAM. Only the requested key is retained; socket and
   proxy endpoint metadata are not recorded.
3. The crawler sends `version` with mainnet framing, protocol 70016, services 0,
   zero netaddrs, random nonce, `/Satoshi:27.0.0/`, height 0, relay false.
4. It waits for the first command parsed as `version`, skipping other commands and
   answering pings. It parses selected fields only.
5. It writes `sendaddrv2`, then `verack`, ignores both errors, does not wait for peer
   `verack`, and stores handshake metadata.
6. It writes `getaddr`. TCP ordering means the peer receives this after our `verack`.
7. It waits at most `getaddr_idle` for the first message. Valid `addr`/`addrv2`
   prefixes are logged, counted, and inserted into the global store. A 2..999-entry
   block ends collection immediately; otherwise silence, error, or hard deadline
   ends it.
8. The node is finalized `Reachable` regardless of getaddr send/result status.
   `finish` decrements `outstanding`; the last item closes all queues.
9. Addr blocks remain buffered until normal final flush. Snapshot CSV/JSON files are
   rewritten in place at checkpoints and finalization.

### Failure paths

* **Handshake timeout:** no complete `version` by the absolute message deadline ->
  `HandshakeFailed(handshake_timeout)` after one attempt unless retry-on-timeout.
  A timeout after partial bytes can instead poison the next read and become
  `protocol_desync`.
* **No addr response:** first `getaddr_idle` silence ends collection; node is
  `Reachable` with zero advertised count. No “no response” record is persisted.
* **Partial response then timeout:** if the envelope is complete but its address
  payload is structurally truncated, the decoded prefix is saved and may end
  collection. If TCP payload bytes are partial, timeout discards them and saves no
  block. Neither case is marked partial.
* **Malformed response:** bad envelope checksum/magic/length ends collection and the
  node remains `Reachable`; malformed address grammar saves a prefix/empty block.
* **Remote disconnect:** during handshake it becomes a classified handshake failure;
  after getaddr it silently ends collection and remains `Reachable`.
* **Local cancellation:** first Ctrl+C closes queues but lets in-flight connections
  run through their timers. Queued entries and discoveries racing the closed queues
  can remain `Queued` and are absent from terminal CSVs. Second Ctrl+C calls
  `process::exit(130)` and skips final flush/output. No per-node cancellation outcome
  exists.

### Safe state assessment

The per-connection ownership path is sound: one worker holds one mutable connection,
one immutable responder key, and local parsed vectors. DashMap mutations are
synchronized, and the address log serializes complete in-memory blocks. Dedup makes
duplicate simultaneous processing of the same normalized key unlikely.

The lifecycle is not finalization-safe as a data model: `finish` is not guarded by a
compare-and-set terminal transition, late message handling has no finalized flag,
worker panics are not supervised, and shutdown leaves nonterminal entries. Today no
separate reader task can normally deliver a late message after `finish`, so I found
no confirmed late-message race; the architecture should nevertheless enforce
single-finalization before adding cancellation or split reader/timer tasks.

## Data schema review

### Current address-response record

```csv
===NEW NODE===,203.0.113.7,8333,ipv4,1720353600,addrv2,70016,1033,/Satoshi:25.0/,850000,false
198.51.100.9,8333,ipv4,1720350000
```

This says only that the requested `203.0.113.7:8333` connection produced a parsed
block. It does not identify the run/request/attempt, actual socket, peer-claimed
version addresses, send time, wire declared count, parse status, or collection
outcome. The advertised row can be mistaken for a verified live node.

### Recommended append-only JSONL response event

```json
{"schema_version":1,"run_id":"01J...","event_id":1842,"request_id":"01J...","attempt":1,"responder":{"requested_endpoint":{"host":"203.0.113.7","port":8333,"network":"ipv4"},"transport":"direct_tcp","socket_peer":"203.0.113.7:8333","socket_local":"192.0.2.10:49152","version_claim":{"addr_from":"198.51.100.4:8333","addr_recv":"192.0.2.10:49152","version":70016,"services":1033,"user_agent":"/Satoshi:25.0/"}},"timing":{"connected_at":"2026-07-14T12:00:00.123456Z","getaddr_sent_at":"2026-07-14T12:00:00.300123Z","received_at":"2026-07-14T12:00:01.912345Z"},"response":{"sequence":1,"command":"addrv2","checksum_valid":true,"declared_count":1,"decoded_count":1,"parse_status":"complete"},"addresses":[{"wire_network_id":1,"host":"198.51.100.9","port":8333,"services":1033,"peer_timestamp":1720350000,"normalized_timestamp":1720350000,"routability":"documentation","frontier_eligible":false,"rejection_reason":"non_routable"}],"observation_semantics":"remote_peer_claim"}
```

Write a separate final request event with
`outcome = complete_quiet | no_response_timeout | partial_timeout |
malformed_response | remote_disconnect | send_failed | cancelled` and counts of
valid, quarantined, duplicate-within-message, and frontier-eligible claims. Never use
`online`, `owned_by`, or equivalent language for gossip addresses. Direct reachability
is evidence only for the endpoint actually connected during that attempt.

## Recommended timeout model

| Timer | Suggested default | Starts | Resets | Ends/meaning |
|---|---:|---|---|---|
| TCP/proxy connect | IP 5s; Tor 60s; I2P 45s | before transport setup | never | success or `connect_timeout` |
| Handshake total | IP 30s; Tor 60s; I2P 90s | after TCP/proxy success, before `version` write | never | peer `verack` or handshake failure |
| Envelope progress idle | IP 5s; Tor 15s; I2P 20s | after first byte of an envelope | on newly read bytes | diagnostic/stall; partial bytes retained |
| Envelope hard | IP 30s; Tor 60s; I2P 90s | first byte of that envelope | never | reject slowloris/incomplete envelope |
| First addr response | IP 10s; Tor 30s; I2P 45s | successful `getaddr` write | never; pings/unrelated messages do not reset | first valid address block or `no_response_timeout` |
| Inter-address quiet | IP 2s; Tor 5s; I2P 8s | each valid `addr`/`addrv2` receipt | only another valid address block | quiet expiry means normal collection completion |
| Collection hard | IP 30s; Tor 60s; I2P 90s | successful `getaddr` write | never | complete/partial hard timeout |
| Crawl/run deadline | operator-defined | run start | never | initiate cancellation and persist incomplete states |

Exact values should be measured and included in the manifest. The important property
is timer ownership: unrelated traffic never extends response deadlines; byte progress
does not extend hard deadlines; only address responses reset inter-address quiet; and
collection never completes based on address count.

## Test plan

### P0 deterministic unit/integration tests

1. Buffered envelope parser: every fragmentation boundary, two/many messages in one
   read, timeout mid-header/payload, EOF at every byte, invalid magic/checksum/command,
   Core's exact 4,000,000 limit and one byte over.
2. Strict CompactSize: all canonical boundaries and every non-canonical form;
   overflow/range checks occur before allocation or loops.
3. Address fixtures: legacy IPv4/IPv6/OnionCat/internal; BIP155 IPv4, IPv6, Tor v3,
   I2P, CJDNS, Tor v2, unknown ids, wrong lengths, invalid CJDNS prefix, IPv4 embedded
   in IPv6, zero/invalid ports, and >1000 count.
4. Mock peer handshake: fragmented/coalesced version-verack, pre-handshake unrelated
   messages, missing/delayed/duplicate verack, sendaddrv2 order, invalid version and
   user-agent limits, cancellation at each state.
5. Collection: delayed response, no response, `addr` then `addrv2`, multiple blocks,
   pings while delayed, malformed block after a valid block, partial block then
   timeout, abrupt disconnect, late block after finalized timeout.
6. Frontier policy: all routability classes, timestamp normalization, services,
   duplicates within and across peers; raw provenance survives while connection dedup
   occurs exactly once.
7. Persistence fault injection: concurrent producers, short/error writes, checkpoint
   crash points, run-id collision, empty replacement category, final sync/manifest,
   and recovery from a truncated JSONL tail.
8. State/concurrency: finish exactly once, worker panic, zero worker config, bounded
   queue backpressure, strict max-nodes permit, shutdown with queued/in-flight/late
   messages, no task/socket leaks.

### P1 fuzz/property tests

* Fuzz envelope header/stream chunking and assert bounded memory, no panic, and parser
  equivalence independent of chunk boundaries.
* Fuzz `version`, `addr`, and `addrv2` payloads with allocation/iteration caps and a
  differential oracle built from Bitcoin Core serialization fixtures where practical.
* Property-test normalization/idempotence and `(network, bytes, port)` key uniqueness.
* Model-test the connection state machine and timer races with Tokio paused time.

### P2 live-network tests

* Small, rate-limited IPv4/IPv6/Tor/I2P samples after deterministic tests pass.
* Compare wire-event counts with pcap/debug logs; do not use live success as parser
  validation.
* Repeat from the same and different local sockets to measure Core's 21-27 hour
  response-cache bias. Record sample selection and network conditions.

## Patch suggestions

### 1. Cancellation-safe framed receiver

```rust
pub struct Connection {
    stream: TcpStream,
    buf: BytesMut,
    socket_local: SocketAddr,
    socket_peer: SocketAddr,
}

pub async fn recv_one(&mut self, idle: Duration, hard: Instant)
    -> io::Result<RecvOutcome>
{
    loop {
        if let Some(env) = try_parse_strict(&mut self.buf)? {
            return Ok(RecvOutcome::Message(env));
        }
        let wait = idle.min(hard.saturating_duration_since(Instant::now()));
        if wait.is_zero() { return Ok(RecvOutcome::HardTimeout); }
        let n = match timeout(wait, self.stream.read_buf(&mut self.buf)).await {
            Err(_) => return Ok(RecvOutcome::IdleTimeout),
            Ok(result) => result?,
        };
        if n == 0 { return Err(io::ErrorKind::UnexpectedEof.into()); }
        if self.buf.len() > 24 + MAX_PROTOCOL_MESSAGE_LENGTH as usize {
            return Err(invalid_data("receive buffer limit exceeded"));
        }
    }
}
```

`try_parse_strict` must use Core's 4,000,000-byte limit and validate all 12 command
bytes. Do not `drain` large vectors repeatedly; advance a `BytesMut` cursor.

### 2. Typed parser with raw claims and policy separation

```rust
pub struct ParsedAddrMessage {
    pub declared_count: u64,
    pub claims: Vec<AddressClaim>,
    pub unknown: Vec<OpaqueAddressClaim>,
}

pub fn parse_addrv2(payload: &[u8]) -> Result<ParsedAddrMessage, AddrParseError> {
    let count = read_canonical_compact_size(&mut c)?;
    if count > MAX_ADDR_TO_SEND as u64 { return Err(TooMany(count)); }
    // Decode exactly count entries. Unknown ids consume bounded opaque bytes and
    // continue. Known ids with wrong lengths fail the whole message.
    // Require c.remaining() == 0 before returning Complete.
}

fn frontier_decision(claim: &AddressClaim, now: i64) -> FrontierDecision {
    // Validate wire-network/address pairing, nonzero port, Core-like validity and
    // routability, useful services, enabled network, and normalized timestamp.
}
```

### 3. Handshake and collection state machine

```rust
send_version().await?;
let peer_version = wait_peer_version(handshake_deadline).await?;
if peer_version.version >= 70016 { send("sendaddrv2", &[]).await?; }
send("verack", &[]).await?;
wait_peer_verack(handshake_deadline).await?;
send("getaddr", &[]).await?;

let first_deadline = Instant::now() + first_response;
let hard_deadline = Instant::now() + collection_hard;
let mut quiet_deadline = None;
loop {
    let phase_deadline = quiet_deadline.unwrap_or(first_deadline).min(hard_deadline);
    match recv_until(phase_deadline).await? {
        Address(env) => {
            persist_validated_event(env).await?;
            quiet_deadline = Some(Instant::now() + inter_addr_quiet);
        }
        Ping(nonce) => send_valid_pong(nonce).await?,
        Unrelated(_) => {},
        Timeout if quiet_deadline.is_some() => break CompleteQuiet,
        Timeout => break NoResponseTimeout,
        Eof if quiet_deadline.is_some() => break PartialRemoteDisconnect,
        Eof => break RemoteDisconnect,
    }
}
```

### 4. Durable output publication

* Create a unique run directory with `create_dir`, not `create_dir_all` reuse.
* Make JSONL observation events the source of truth through one bounded writer.
* Flush/sync event batches and publish a durable sequence watermark.
* Generate CSV convenience views from durable events after the crawl.
* Write snapshots to `*.tmp.<generation>`, flush+sync, rename, sync the directory,
  and atomically publish `manifest.json` last.

## Assessment of `REVIEW_FIX_PLAN.md`

The plan is directionally useful but insufficient for the stated research goal.

Accepted recommendations I agree with:

* Its C2 buffered receive fix addresses a real critical bug.
* H3's 1000-entry cap, H4 checkpoint flush, M1 parse status, M3 legacy-CJDNS fix,
  M5 distinct-node accounting, surfaced write errors, and seed synchronization are
  worthwhile.

Changes needed to that plan:

* **Do not decline C1 routability filtering.** Keeping raw non-routable claims is
  useful; connecting to them by default is unsafe and methodologically wrong. Raw
  observation and frontier eligibility must be separate.
* **Do not decline H2 timestamp validation.** Preserve the literal peer timestamp,
  but never use an unchecked future/invalid value for scheduling.
* **Do not decline L4 version/socket provenance or L5 structured output** if the goal
  is auditable attribution. Grouped CSV cannot represent request outcomes safely.
* The proposed H1 loop still starts a fresh full first-response window after every
  unrelated message. Use an absolute `first_addr_deadline`; pings must not reset it.
* Its completion heuristic still stops on a 2..999-entry block. Remove the count
  heuristic and use quiet-after-first-response.
* A parse-status enum is not enough if malformed prefixes are still enqueued. Invalid
  messages should be quarantined atomically, not partially accepted.
* Logging failed `sendaddrv2`/`verack` while keeping `Reachable` semantics is not
  acceptable. A completed handshake requires successful writes and peer `verack`.
* Flushing the addr log at checkpoints improves visibility but is not durability.
  Errors must propagate and snapshot generations must be transactional.

In short: implement its buffered receive work first, but revise the timeout,
handshake, validation, and persistence portions before treating the plan as a
research-grade remediation.
