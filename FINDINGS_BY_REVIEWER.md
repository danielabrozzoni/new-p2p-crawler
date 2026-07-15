# Consolidated crawler findings by reviewer

This document merges the findings present in:

* **Claude:** `REVIEW_FIX_PLAN.md`
* **Codex:** `CRAWLER_REVIEW.md`

The Claude artifact is a fix plan for an "accepted subset" of an earlier review,
not the complete original review. For declined Claude findings, only the short name
preserved at `REVIEW_FIX_PLAN.md:21-23` is available. This document does not invent
missing Claude rationale.

## Legend

* **Both:** both Claude and Codex independently identified the underlying issue.
* **Both, different scope:** the reviews overlap, but one review makes a broader or
  materially different claim.
* **Claude only:** present in Claude's artifact and not stated specifically by Codex.
* **Codex only:** first stated as a distinct finding in the Codex review.
* Claude IDs retain Claude's severity prefix: `C` critical, `H` high, `M` medium,
  `L` low.
* Codex severity is copied from `CRAWLER_REVIEW.md`.

## Summary

The sections below use mutually exclusive provenance categories. Some findings are
deliberately split. For example, both reviewers found the initial `getaddr` timeout
problem, while Codex separately found that unrelated messages reset that wait and
that the count-based completion heuristic drops later responses.

## Findings from both Claude and Codex

### B2. Cancellation-unsafe framed receiving

* **Found by:** Both
* **Claude:** C2, critical.
* **Codex:** C2, critical.
* **Files:** `src/transport.rs:35-89`.
* **Finding:** timing out a `read_exact` future can consume and discard partial TCP
  bytes, causing message loss or subsequent framing desynchronization.
* **Agreement:** both recommend a persistent per-connection buffer and cancel-safe
  chunk reads.

### B3. First `getaddr` response timeout is too short

* **Found by:** Both
* **Claude:** H1, high.
* **Codex:** part of C4, critical.
* **Files:** `src/crawler.rs:510-544`.
* **Finding:** `getaddr_idle` is used before any address response, so a valid response
  arriving after 3/5/8 seconds can be missed even though the total collection budget
  is much longer.
* **Difference:** Claude proposes two phases. Codex agrees with the phases but requires
  an absolute first-response deadline that unrelated messages cannot restart.

### B4. Address count is not capped at Core's 1000-entry limit

* **Found by:** Both
* **Claude:** H3, high.
* **Codex:** part of C3, critical.
* **Files:** `src/protocol.rs:238-335`.
* **Finding:** the parser accepts more than Bitcoin Core's `MAX_ADDR_TO_SEND == 1000`.
* **Difference:** Claude proposes returning the first 1000 with `Capped` status.
  Codex recommends treating an over-limit wire message as malformed and preventing
  every entry in that message from entering the frontier.

### B5. Address parse status is missing

* **Found by:** Both
* **Claude:** M1, medium.
* **Codex:** part of C3, critical.
* **Files:** `src/protocol.rs:236-335`, `src/crawler.rs:521-535`.
* **Finding:** a valid empty response, truncation, unknown network id, and invalid
  address length all collapse to a `Vec<AdvertisedAddr>` with no parse outcome.
* **Difference:** Claude adds a status while keeping decoded prefixes. Codex says a
  status alone is insufficient: structurally malformed prefixes must be quarantined,
  not enqueued as valid data.

### B6. Address-log data is not flushed at checkpoints

* **Found by:** Both
* **Claude:** H4, high.
* **Codex:** part of C7, critical.
* **Files:** `src/main.rs:135-179`, `src/addrlog.rs:67-73`.
* **Finding:** checkpoint CSV/JSON may reference advertisements whose provenance is
  still buffered in `addr_responses.csv` and is lost on a crash.
* **Difference:** Claude adds `flush()` at checkpoints. Codex says that improves
  visibility but does not provide durability without error propagation, stable event
  ids, and an explicit sync policy.

### B7. Legacy `fc00::/8` is mislabeled as CJDNS

* **Found by:** Both
* **Claude:** M3, medium.
* **Codex:** high-priority issue 3.
* **Files:** `src/protocol.rs:337-346`.
* **Finding:** the legacy `addr`/BIP155 IPv6 decoder assigns CJDNS based on the first
  byte. Bitcoin Core's legacy IPv6 deserializer does not; CJDNS comes from BIP155
  network id 6.
* **Difference:** Codex also covers OnionCat/internal legacy prefixes, embedded IPv4
  in BIP155 IPv6, and the required CJDNS prefix.

### B9. `num_processed` counts attempts instead of distinct nodes

* **Found by:** Both
* **Claude:** M5, medium.
* **Codex:** part of high-priority issue 12.
* **Files:** `src/crawler.rs:208-220`.
* **Finding:** retries increment `num_processed_nodes`, making the name and max-node
  behavior misleading.
* **Difference:** Codex additionally identifies a non-atomic max-node overshoot; that
  is listed separately as C14.

### B11. Send/write/flush errors are swallowed

* **Found by:** Both
* **Claude:** L2, low.
* **Codex:** parts of C5 and C7, critical.
* **Files:** `src/crawler.rs:457-459`, `src/addrlog.rs:67-73`.
* **Finding:** handshake feature writes and address-log writes/flushes discard errors.
* **Difference:** Claude proposes logging the errors and retaining current reachable
  semantics. Codex requires handshake send failures to fail the handshake and
  persistent output errors to fail or explicitly invalidate the research run.

### B12. DNS seed list is stale

* **Found by:** Both
* **Claude:** L3, low.
* **Codex:** low-priority seed-list finding.
* **File:** `src/dns.rs:8-17`.
* **Finding:** `seed.bitcoin.sipa.be` is absent from the vendored Core revision's
  current mainnet seed list.

### B13. `version.addr_recv` and `version.addr_from` are discarded

* **Found by:** Both
* **Claude:** L4, low, explicitly declined in the fix plan.
* **Codex:** high-priority issue 6.
* **Files:** `src/protocol.rs:170-211`, `src/transport.rs:18-25`.
* **Finding:** the stored record cannot distinguish the requested endpoint from the
  addresses claimed in the peer's `version` message.
* **Difference:** Codex also requires the actual TCP local/peer socket endpoints and
  proxy/transport destination to be recorded.
## Findings from both, but with materially different scope

### D1. Onion/I2P and BIP155 network validation

* **Found by:** Both, different scope
* **Claude:** M4, medium, "onion/i2p label validation", explicitly declined.
* **Codex:** high-priority issue 3.
* **Files:** `src/address.rs:73-87`, `src/protocol.rs:362-395`.
* **Claude scope:** validate Onion/I2P textual labels rather than classifying solely
  by suffix and length.
* **Codex scope:** validate wire-network/address pairing, including legacy OnionCat,
  BIP155 IPv4 embedded in IPv6, invalid CJDNS prefixes, and unsupported Tor v2.
* **Note:** the scopes overlap in address identity validation but are not identical.

## Findings only present in the Codex review

### C1. Peer `verack` is never required

* **Found by:** Codex only
* **Codex severity:** Critical (Codex C5).
* **Files:** `src/crawler.rs:441-461`, `src/crawler.rs:284-295`.
* **Finding:** receipt of a peer `version` is labeled as a completed handshake. The
  crawler never waits for peer `verack` and marks the node reachable even if later
  writes fail.

### C2. Structurally malformed messages are not rejected atomically

* **Found by:** Codex only as this stronger finding
* **Codex severity:** Critical (additional part of Codex C3).
* **Files:** `src/protocol.rs:236-335`, `src/crawler.rs:521-535`.
* **Finding:** non-canonical CompactSize, truncated entries, wrong known-network
  lengths, and trailing garbage can yield a decoded prefix that is logged/enqueued.
  Unknown future network ids stop parsing rather than being consumed and skipped.
* **Distinction from Claude:** Claude adds status/capping but still proposes returning
  partial prefixes.

### C3. Unrelated traffic restarts response waits

* **Found by:** Codex only
* **Codex severity:** Critical (part of Codex C4).
* **File:** `src/crawler.rs:514-544`.
* **Finding:** every unrelated message starts a new full `recv_one(wait)`, so pings or
  other traffic reset the effective silence window until the hard collection limit.
* **Claude-plan gap:** Claude's proposed two-phase loop retains this behavior.

### C4. Entry-count completion can drop later address messages

* **Found by:** Codex only
* **Codex severity:** Critical (part of Codex C4).
* **Files:** `src/crawler.rs:521-535`, `688-705`.
* **Finding:** a 2..999-entry block terminates collection immediately, so a following
  `addrv2` or second `addr` block is lost. Core's AddrFetch disconnect heuristic is
  not a protocol end marker.

### C5. Run-directory reuse mixes stale and current data

* **Found by:** Codex only
* **Codex severity:** Critical (Codex C6).
* **Files:** `src/settings.rs:130-146`, `src/main.rs:27-33`, `src/output.rs:21-50`.
* **Finding:** second-resolution or user-supplied run names are silently reused;
  empty current categories leave old files behind, while other files are overwritten.

### C6. Snapshot publication is non-transactional

* **Found by:** Codex only
* **Codex severity:** Critical (part of Codex C6).
* **File:** `src/output.rs:21-50`, `343-351`.
* **Finding:** checkpoint files are truncated and rewritten sequentially, so a crash
  can expose partial files or a mixture of generations. `num_advertised` is read from
  live state rather than the same snapshot.

### C7. Zero concurrency can hang forever

* **Found by:** Codex only
* **Codex severity:** Critical (Codex C8).
* **Files:** `src/settings.rs:229-238`, `src/crawler.rs:128-176`.
* **Finding:** an enabled transport with zero workers leaves queued/outstanding work
  that can never finish.

### C8. Envelope command syntax is not validated

* **Found by:** Codex only
* **Codex severity:** High.
* **File:** `src/transport.rs:92-95`.
* **Finding:** lossy UTF-8 and truncation at the first NUL can interpret malformed
  wire commands such as `addr\0garbage` as valid `addr`.

### C9. Payload limit does not match Bitcoin Core

* **Found by:** Codex only
* **Codex severity:** High.
* **File:** `src/protocol.rs:12-13`.
* **Finding:** the crawler permits `4 * 1024 * 1024`; Core permits
  `4 * 1000 * 1000`, a difference of 194,304 bytes.

### C10. Request/collection outcomes are not stored

* **Found by:** Codex only
* **Codex severity:** High.
* **File:** `src/crawler.rs:499-546`.
* **Finding:** no-response timeout, send failure, malformed response, disconnect,
  partial result, and successful empty response all collapse into reachable/zero or
  reachable/some-count summaries.

### C11. Actual socket and transport endpoints are not stored

* **Found by:** Codex only as an extension beyond Claude L4
* **Codex severity:** High.
* **Files:** `src/transport.rs:18-25`, `src/crawler.rs:361-398`.
* **Finding:** records omit TCP local/peer endpoints and cannot distinguish a proxy
  socket endpoint from the requested Tor/I2P destination.

### C12. Queues and frontier memory are unbounded

* **Found by:** Codex only
* **Codex severity:** High.
* **Files:** `src/crawler.rs:28-34`, `src/store.rs:187-204`.
* **Finding:** unbounded channels plus permanent DashMap entries permit memory growth
  controlled by remote gossip.

### C13. I2P session initialization failure is cached forever

* **Found by:** Codex only
* **Codex severity:** High.
* **File:** `src/crawler.rs:400-415`.
* **Finding:** `OnceCell<Option<...>>` permanently stores `None` after one transient
  SAM initialization failure, biasing all subsequent I2P results.

### C14. Retry history is overwritten

* **Found by:** Codex only
* **Codex severity:** High.
* **Files:** `src/store.rs:127-145`, `src/crawler.rs:231-318`.
* **Finding:** multiple attempts collapse into one connect duration, one first send
  timestamp, one handshake record, and one final failure reason.

### C15. Worker task failures are ignored

* **Found by:** Codex only
* **Codex severity:** High risk requiring evidence.
* **File:** `src/crawler.rs:164-175`.
* **Finding:** join errors are discarded. A worker panic before `finish` can strand
  the outstanding counter and prevent termination.

### C16. `max_nodes` check can overshoot under concurrency

* **Found by:** Codex only as distinct from attempt counting
* **Codex severity:** High.
* **File:** `src/crawler.rs:208-220`.
* **Finding:** checking the count and incrementing it are separate operations, so many
  workers may pass the cap concurrently.

### C17. Malformed ping payloads are fabricated into pong payloads

* **Found by:** Codex only
* **Codex severity:** Medium.
* **File:** `src/transport.rs:45-51`.
* **Finding:** short pings are zero-padded and long pings truncated instead of being
  validated against the negotiated ping form.

### C18. Blocking address-log writes run on Tokio worker threads

* **Found by:** Codex only
* **Codex severity:** Medium.
* **File:** `src/addrlog.rs:67-73`.
* **Finding:** synchronous filesystem I/O occurs while holding an async mutex, which
  can interfere with networking and timer fairness under load.

### C19. DashMap checkpoints are fuzzy snapshots

* **Found by:** Codex only
* **Codex severity:** Medium.
* **Files:** `src/store.rs:226-232`, `src/output.rs:30-49`.
* **Finding:** entries are cloned shard by shard while workers mutate the store. An
  in-progress checkpoint does not represent one logical instant and is not labeled as
  fuzzy/incomplete.

### C20. `getaddr` samples are partial and cached

* **Found by:** Codex only
* **Codex severity:** Medium methodology issue.
* **Reference:** Core returns at most 1000 and 23%, with per-requestor caches lasting
  roughly 21-27 hours.
* **Finding:** output must not imply one response is a complete live addrman view;
  reconnects from the same network/local socket can repeat cached, stale samples.

### C21. `frame` can panic on an overlong internal command

* **Found by:** Codex only
* **Codex severity:** Low.
* **File:** `src/protocol.rs:31-36`.
* **Finding:** slicing `cmd[..bytes.len()]` panics if an internal caller supplies a
  command longer than the 12-byte wire field. Return `Result` and validate syntax.

### C22. The advertised user agent falsely claims to be Bitcoin Core

* **Found by:** Codex only
* **Codex severity:** Low.
* **File:** `src/protocol.rs:21`.
* **Finding:** the crawler advertises `/Satoshi:27.0.0/`; it should use a truthful,
  crawler-specific identity.

### C23. The strict Clippy gate is not clean

* **Found by:** Codex only
* **Codex severity:** Low.
* **File:** `src/store.rs:202`.
* **Finding:** `cargo clippy --all-targets -- -D warnings` fails because `NodeStore`
  exposes `len` without `is_empty`. This is a quality-gate issue, not a data bug.

## Bottom line

Claude identified 16 named issues in the available artifact. Codex independently
confirmed most of the important ones, but disagreed with several proposed remedies
and found additional handshake, parser, collection, persistence, configuration,
resource, and methodology problems.

The most consequential disagreements are:

1. Claude declined routability filtering and timestamp validation; Codex considers
   both necessary for security and data integrity.
2. Claude's timeout patch still lets unrelated traffic restart the response window;
   Codex requires absolute phase deadlines.
3. Claude retains the count-based response-completion heuristic; Codex considers it
   invalid because the protocol has no terminal marker.
4. Claude proposes logging failed `sendaddrv2`/`verack` writes while still marking the
   peer reachable; Codex requires successful writes plus peer `verack` for a completed
   handshake.
5. Claude's parse-status approach retains malformed prefixes; Codex requires atomic
   quarantine and no frontier insertion from structurally malformed messages.
6. Claude's checkpoint flush improves buffering behavior; Codex additionally requires
   propagated writer failure and transactional snapshot publication.
