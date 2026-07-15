# Fix ledger for `FINDINGS_BY_REVIEWER.md`

This file records the changes made for the retained findings. The scope source was
`FINDINGS_BY_REVIEWER.md`; the older review documents were used only to understand
the retained items.

## Wire framing and protocol parsing

- **B2:** `Connection` now owns a persistent receive buffer. Timed-out reads retain
  partial header/payload bytes, reads use Tokio's cancellation-safe `read`, multiple
  buffered frames are parsed in order, and an incomplete envelope has a hard
  deadline (`src/transport.rs`).
- **B4, B5, C2:** `addr` and `addrv2` parsing now returns a typed atomic `Result`.
  It rejects counts above 1000, non-canonical CompactSize encodings, truncation,
  wrong known-network lengths, invalid known-network encodings, and trailing bytes.
  No decoded prefix is returned or enqueued after structural failure. Unknown future
  BIP155 ids are bounds-checked, consumed, counted, and skipped so later valid entries
  still parse (`src/protocol.rs`, `src/crawler.rs`, `src/addrlog.rs`).
- **C8, C9:** incoming command fields require printable ASCII followed only by NUL
  padding, and the payload ceiling is Core's exact 4,000,000 bytes
  (`src/transport.rs`, `src/protocol.rs`).
- **C17:** ping payloads are checked against the negotiated protocol form; the
  crawler no longer pads or truncates a nonce (`src/transport.rs`, `src/crawler.rs`).
- **C21:** outbound `frame` returns `Result`, validates command syntax/length, and
  checks the payload limit instead of being able to panic (`src/protocol.rs`).
- **C22:** the advertised user agent is now the truthful
  `/new-p2p-crawler:0.1.0/` (`src/protocol.rs`).

## Address identity and collection

- **B3, C3:** first-response and inter-address waits are separate absolute phases.
  Unrelated traffic does not restart either phase (`src/crawler.rs`).
- **C4:** entry-count completion was removed. Collection ends only on quiet after a
  valid address message, a first/hard deadline, disconnect/error, or cancellation;
  later `addr`/`addrv2` blocks are therefore not discarded merely because an earlier
  block contained 2..999 entries (`src/crawler.rs`).
- **B7, D1:** legacy `fc00::/8` remains legacy IPv6 rather than becoming CJDNS.
  BIP155 embedded IPv4-in-IPv6 and invalid CJDNS prefixes are rejected, Tor v2 wire
  entries are ignored, valid CJDNS is derived only from network id 6, and textual
  Onion/I2P labels are base32/checksum validated (`src/protocol.rs`, `src/address.rs`,
  `src/store.rs`, `src/crawler.rs`).
- **C10:** every requested collection stores a typed outcome, including successful
  quiet completion, no response, hard/partial/incomplete-frame timeout, malformed
  response, disconnect, send failure, and log failure. Empty valid responses remain
  distinguishable from malformed/no-response cases (`src/store.rs`, `src/crawler.rs`,
  `src/output.rs`, `src/addrlog.rs`).
- **C20:** manifests/statistics explicitly describe one `getaddr` result as capped,
  partial, and potentially cached for roughly 21-27 hours—not a complete live
  addrman view (`src/output.rs`, `README.md`).

## Handshake, endpoints, retries, and workers

- **C1, B11:** reachability now requires the peer's `verack`. `sendaddrv2` is sent
  only when negotiated, every version/negotiation/verack write is checked, and the
  crawler waits for peer `verack` inside the absolute handshake deadline
  (`src/crawler.rs`, `src/store.rs`).
- **B13, C11:** records now retain version `addr_recv`, `addr_from`, their services,
  nonce, the requested/transport destination, and actual local/peer TCP socket
  endpoints. For proxy transports this distinguishes the proxy socket from the
  requested Onion/I2P destination (`src/protocol.rs`, `src/transport.rs`,
  `src/store.rs`, `src/output.rs`).
- **B9, C16:** `num_processed_nodes` reserves one atomic permit only for a distinct
  node's first attempt. Retries do not increment it and concurrent workers cannot
  overshoot `max_nodes` (`src/crawler.rs`).
- **C14:** each connection/handshake attempt now has its own retained attempt number,
  connect duration, version-send time, outcome, and failure; CSV summaries include
  the full attempt history (`src/store.rs`, `src/crawler.rs`, `src/output.rs`).
- **C13:** only a successful SAM session is cached. Initialization failure is
  retried, and a failed cached stream invalidates the session (`src/crawler.rs`).
- **C15:** worker and per-item task join failures are no longer discarded. A per-item
  panic is terminalized exactly once, cancels/closes the crawl, and makes the run
  incomplete/failed instead of stranding termination accounting (`src/crawler.rs`,
  `src/main.rs`, `src/output.rs`).

## Bounds and configuration

- **C7:** startup rejects zero workers for any enabled transport and rejects
  concurrency above 4096. Zero remains valid when all networks routed to that
  transport are disabled (`src/settings.rs`).
- **C12:** all transport queues are bounded. `--max-addresses` (default 1,000,000)
  places a strict crawl-wide bound on unique retained frontier entries; rejected
  observations are counted in statistics (`src/settings.rs`, `src/crawler.rs`,
  `src/store.rs`, `src/output.rs`, `README.md`).
- **C23:** `NodeStore::is_empty` was added and the strict Clippy gate is clean
  (`src/store.rs`).
- **B12:** removed stale `seed.bitcoin.sipa.be` (`src/dns.rs`).

## Persistence and run isolation

- **C5:** default run ids use nanosecond resolution, and run directories are created
  with create-new semantics. Reusing an explicit run name fails rather than mixing
  old and current files (`src/settings.rs`, `src/main.rs`, `src/bin/probe.rs`).
- **C6, C19:** each checkpoint/final snapshot is written into a new generation,
  including header-only empty category files; files and the generation directory are
  synced, then an atomic manifest publishes the generation and hashes. All counts
  come from the same cloned snapshot. Checkpoints are labeled `checkpoint_fuzzy`,
  final post-worker snapshots `final_consistent`, and run completeness is separate
  (`src/output.rs`, `src/main.rs`, `README.md`).
- **B6, B11, C18:** address observations go through one bounded dedicated blocking
  writer thread, so filesystem work no longer blocks Tokio networking workers.
  Writes/flushes propagate errors, events have monotonic ids, and checkpoint/final
  flushes call `sync_all`; the manifest records the last durable event id. A log
  failure makes the run incomplete and returns failure (`src/addrlog.rs`,
  `src/crawler.rs`, `src/main.rs`, `src/output.rs`).

## Deliberately not changed

These issues appear in the older review files but are not retained as numbered
findings in `FINDINGS_BY_REVIEWER.md`, so this patch does not implement them:

- routability/private-address, port-zero, or useful-services frontier filtering;
- peer timestamp normalization/validation (literal timestamps still drive the
  existing freshness policy);
- mandatory provenance logging when `--no-record-addr-responses` is selected;
- special self-announcement provenance;
- converting the grouped observation CSV to JSONL;
- replacing `expect("reachable has handshake")` in the reachable writer.

## Verification

- `cargo test --all-targets` — 28 library tests and 5 probe tests pass.
- `cargo clippy --all-targets -- -D warnings` — passes.
- Both binaries' `--help` paths run successfully.
