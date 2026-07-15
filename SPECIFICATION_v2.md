# Bitcoin P2P Network Crawler — Specification (Rust)

This is the specification for a Bitcoin mainnet P2P network crawler written in
**Rust**. It describes the behavior, algorithms, data flows, and design decisions
in enough detail to implement the crawler from scratch.

The wire format (Section 4) is Bitcoin's, so it is specified exactly and must be
implemented faithfully. Everything else is the crawler's own design, chosen for
correctness, speed, and simplicity.

---

## 1. Overview

The crawler maps the reachable Bitcoin **mainnet** P2P network. Starting from a
hardcoded list of DNS seeds, it connects to nodes, performs the Bitcoin P2P
`version` handshake, asks reachable nodes for their peers (`getaddr`), and
recursively repeats on newly discovered addresses until no new work remains. It
reaches **six network types** over **three transports**:

| Network type | Transport |
|--------------|-----------|
| IPv4         | plain TCP |
| IPv6         | plain TCP |
| CJDNS        | plain TCP (CJDNS addresses are ordinary IPv6 sockets in `fc00::/8`) |
| Tor onion v2 | SOCKS5 proxy |
| Tor onion v3 | SOCKS5 proxy |
| I2P          | I2P SAM session |

("Transport" = connection mechanism; "network type" = the address family the
crawler classifies and counts. They are not one-to-one.)

Each node processed ends in exactly one of three terminal outcomes (Section 3.7):

- **reachable** — connected **and** completed the `version` handshake;
- **handshake-failed** — connected (TCP/SOCKS5/SAM succeeded) but never completed
  the handshake after all attempts;
- **unreachable** — the connection could not be established at all.

The crawler performs exactly **one crawl run** and then writes results; it keeps
no state across runs. Outputs (all **plain, uncompressed** files):

- a CSV of every **reachable** node with its full metadata + freshest-seen
  timestamp;
- a CSV of every **handshake-failed** node (address, provenance, connect timing);
- a CSV of every **unreachable** node with its freshest-seen timestamp;
- a JSON of crawl-wide statistics and node lists;
- an optional plain-CSV log of every `addr`/`addrv2` response with responder
  identity and the advertised addresses;
- an optional plain-text debug log.

---

## 2. Architecture

### 2.1 The node store (central data structure)

A single map is the heart of the crawler:

```
NodeStore = HashMap<AddrKey, NodeEntry>
AddrKey   = (host: String, port: u16)          // network type is derived from host

struct NodeEntry {
    network:     NetworkType,     // ipv4 | ipv6 | cjdns | onion_v2 | onion_v3 | i2p | unknown
    freshest_ts: i64,             // max timestamp ever observed for this address
    state:       NodeState,
    handshake:   Option<HandshakeData>,   // Some once a version reply is parsed
    stats:       NodeStats,       // timing, attempt counters, advertised-addr counts
}

enum NodeState {
    Queued,          // in the work queue, waiting to be processed
    Processing,      // a worker holds it right now
    Reachable,       // terminal: connected + handshake completed
    HandshakeFailed, // terminal: connected, but no handshake after all attempts
    Unreachable,     // terminal: connection failed
    StaleDiscarded,  // known but not queued because it failed the freshness filter (3.4)
}
```

This one map is the whole crawl frontier and result set. Consequences:

- **Known check** (Section 3.4): `store.contains_key(&addr_key)` — O(1).
- **Freshest-seen map** (Section 3.4.1): `entry.freshest_ts`, updated to
  `max(existing, observed)` on every observation.
- **`num_advertised`** (Section 7.2): `store.len()` — one entry per distinct
  `(host, port)` ever seen.
- **Output sets**: iterate the map filtering by `state`.

The work queues (one per transport, Section 3.5) hold only `AddrKey`s (or
lightweight handles) whose entries are in state `Queued`; the map is the source of
truth.

### 2.2 Components

- **CLI / entry point**: parse args + env into an immutable settings tree, sanity-
  check, init logging, run the crawl, persist results.
- **Settings**: immutable config (per-network timeouts, node behavior, proxy
  hosts, result paths, logging).
- **DNS seeds**: resolve the hardcoded seed hostnames (A + AAAA) into the initial
  queued addresses.
- **Address / network type**: classify a host string into a `NetworkType`;
  equality/hashing by `(host, port)` only (timestamp excluded).
- **Node worker**: connect → handshake → optional `getaddr` → disconnect, updating
  the store.
- **Transport layer**: TCP (IPv4/IPv6/CJDNS), SOCKS5 (Tor), SAM (I2P). Frames,
  sends, receives, dispatches P2P messages; auto-answers `ping` with `pong`.
- **Protocol**: (de)serialize the Bitcoin wire format (Section 4).
- **Crawler core**: owns the node store, the per-transport work queues and worker
  pools (Section 3.5), and the status monitor.
- **Output**: serialize plain result files.

### 2.3 Data flow

```
   DNS seeds ──resolve──> initial addresses ──> node store (state=Queued)
                                                     │
                          ┌──────────────────────────┘
                          ▼
   [ per-transport worker pools, each draining its own transport's work queue ]
                          │
             connect ─────┤── fail ──> retry (re-Queue) or give up ──> state=Unreachable/HandshakeFailed
                          │
           handshake ─────┤── fail ──> retry (re-Queue) or give up ──> state=HandshakeFailed
                          │ success
           getaddr  ─────> addr/addrv2 replies ──> observed addresses
                          │                              │
                          │   update freshest_ts=max; if unknown AND fresh:
                          │                              ▼
                          │                enqueue (state=Queued)
                          ▼                     (stale-but-unknown -> StaleDiscarded)
                    state=Reachable
                          │
   when all queues are empty and nothing is in-flight (outstanding == 0):
                          ▼
          Output: reachable CSV + handshake-failed CSV + unreachable CSV
                  + stats JSON + (optional addr-response CSV) + (optional debug log)
```

### 2.4 Lifecycle

1. Parse args/env; build settings; sanity-check (create results dir if missing).
2. Init logging (UTC timestamps; console at chosen level, optional debug file).
3. If `delay_start > 0`, sleep that many seconds (only needed when local Tor/I2P
   side services still need warm-up time; default 0).
4. **Network preflight** (Section 2.5): probe each enabled network's transport
   prerequisite. In `--dry-run` mode, print the results table and **exit** without
   crawling. Otherwise, for any enabled network whose probe failed (e.g. an
   unreachable Tor proxy): **abort** with a config-error exit code if
   `--strict-networks` is set, else log a **warning** and continue.
5. Resolve DNS seeds into the initial `Queued` entries.
6. Start the per-transport worker pools (Section 3.5) and the status monitor.
   Record the crawl **start clock** here (Section 3.8).
7. Run until every queue drains and nothing is in-flight (`outstanding == 0`,
   Section 3.6).
8. Log a final summary (processed / reachable / handshake-failed / unreachable /
   runtime).
9. Persist output files locally.

### 2.5 Network preflight and dry run

Before crawling (and as the whole job in `--dry-run` mode), the crawler probes the
transport prerequisite of each **enabled** network with a cheap, bounded check:

| Network | Probe | "Reachable" means |
|---------|-------|-------------------|
| ipv4 | resolve a seed's A records, then TCP-connect to up to a few resolved node:8333 in turn (ip connect timeout each); reachable if any connects | outbound IPv4 works |
| ipv6 | same via AAAA records | outbound IPv6 works |
| tor | TCP-connect to the SOCKS5 proxy and complete the greeting/method-selection (`05 01 00` → `05 00`) | the Tor proxy is up and speaks SOCKS5 |
| i2p | TCP-connect to the SAM router and complete `HELLO VERSION` → `HELLO REPLY RESULT=OK` | the SAM router is up |
| cjdns | check for a local interface address in `fc00::/8` | the host has a CJDNS interface (best-effort) |

Each probe is bounded by that network's **connect** timeout (Section 6.1) and does
**no** Bitcoin handshake — it only establishes that the transport can be used. The
IPv4/IPv6 probes try a handful of resolved nodes and pass if **any** connects, so a
single offline node doesn't make the whole network read as unreachable.

- **`--dry-run`**: run every enabled network's probe, print a results table (below),
  and exit. No seeds are resolved beyond what a probe needs, no crawl runs, and no
  output files are written. Exit code is **0** iff every enabled network probed
  reachable, non-zero otherwise (so it doubles as a scriptable health check).
- **Normal run**: the same probes run at startup (lifecycle step 4). A failed probe
  for an enabled network is, by default, a non-fatal **warning** — the crawl
  proceeds and those nodes will simply come back unreachable. With
  `--strict-networks`, a failed probe for an enabled network instead **aborts** the
  run with a config-error exit code before any crawling begins. Disabled networks
  are skipped (shown as `skipped`) and never cause a strict abort.

Example table:

```
Network  Enabled  Probe result
ipv4     yes      reachable
ipv6     yes      reachable
tor      yes      unreachable (SOCKS5 proxy 127.0.0.1:9050: connection refused)
i2p      no       skipped
cjdns    yes      no cjdns interface
```

---

## 3. Crawling algorithm

### 3.1 Seed / bootstrap

The initial node set comes from **DNS seeds** — a hardcoded list of seed
hostnames (fully-qualified, trailing-dot form):

```
seed.bitcoin.sipa.be.
dnsseed.bluematt.me.
dnsseed.bitcoin.dashjr-list-of-p2p-nodes.us.
seed.bitcoinstats.com.
seed.bitcoin.jonasschnelli.ch.
seed.btc.petertodd.net.
seed.bitcoin.sprovoost.nl.
dnsseed.emzy.de.
seed.bitcoin.wiz.biz.
seed.mainnet.achownodes.xyz.
```

Resolve A and AAAA records for each hostname (a `getaddrinfo`-style call
constrained to return each IP once — e.g. constrain socktype so a host is not
returned once per socktype). Every returned IP becomes an address with the default
mainnet port **8333** and a last-seen timestamp of "now".

- Per-seed resolution results are recorded (for `num_nodes_from_seed`). The union
  of all seeds' addresses becomes the initial `Queued` entries.
- Resolution failure for a seed is a warning and yields nothing for that seed; the
  crawl continues.

Each seed observation also updates the store's `freshest_ts` for that address to
"now" (Section 3.4.1).

### 3.2 The Bitcoin P2P handshake

For each node pulled from the queue, a worker:

1. **Connects** using the transport for the address type (Section 4.2) with the
   per-network connect timeout. Connection failure ⇒ retry, then **Unreachable**
   (or **HandshakeFailed** if an earlier attempt connected; Sections 3.7, 6.2).
2. **Sends `version`**, recording the send timestamp and incrementing the
   handshake-attempt counter.
3. **Waits for the peer's `version`** via the receive loop (Section 4.1) with
   `deadline = handshake_start + message_timeout` and per-envelope timeout
   `message_timeout` (both per-network). While waiting, any `ping` is answered with a
   `pong` echoing that ping's exact 8-byte nonce, and any non-`version` message is
   skipped. Deadline reached or error ⇒ this attempt fails.
4. On receiving the peer's `version`: record success and handshake duration (ms),
   then **send `sendaddrv2`** and **send `verack`**.
5. **Extract and store** the peer's `version` fields (Section 4.4). The peer's
   `timestamp` field is stored as `version_reply_timestamp_remote`.

Deviations from a full Core handshake (intentional):

- Does **not** wait for the peer's `verack`; the peer's `version` is enough.
- Sends `sendaddrv2` without requiring the peer to; parses either `addr` or
  `addrv2` later.
- Own `version` advertises fixed protocol **70016**, services **0**, relay
  **false**, user agent **`/Satoshi:27.0.0/`** (Section 4.3).

### 3.3 Peer discovery (getaddr / addr / addrv2)

After a successful handshake, the worker always solicits peers:

1. **Send `getaddr`**.
2. **Receive address messages in a loop** bounded by two limits:
   - a **hard ceiling**: `deadline = loop_start + getaddr_budget` (per-network,
     Section 6.1);
   - a **short idle timeout** `getaddr_idle` (default 3 s): each receive waits at
     most `min(deadline − now, getaddr_idle)`.
   Both `addr` and `addrv2` replies are accepted. The loop ends when the deadline
   is reached, a receive times out (⇒ the peer has gone quiet — done), or a
   receive errors. A peer typically dumps its addresses within a second or two and
   then stays silent; the short idle timeout detects that quickly instead of
   blocking for the full message timeout.

   **Early exit:** Bitcoin Core answers `getaddr` with a single snapshot of at most
   **1000** addresses (`MAX_ADDR_TO_SEND`). A received `addr`/`addrv2` message
   carrying **fewer than 1000** addresses therefore almost always means the dump is
   complete, so the loop **ends on the first such sub-1000 message** instead of
   paying the trailing `getaddr_idle` wait. A message carrying a full 1000 means
   more may follow, so the loop keeps going under the idle/deadline bounds. This
   removes the fixed `getaddr_idle` tax on the common case.
3. **Update the freshest-seen timestamp** (Section 3.4.1) for every advertised
   address of an **enabled** network type (Section 9), before any dedup, to
   `max(existing, observed)`.
4. **Compute per-node address statistics**: total advertised + a per-network
   breakdown. This counts **all** addresses in the raw response, including disabled
   and unknown network types — it reflects what the peer advertised, independent of
   which networks this run crawls.
5. **Record the addr-response log** (Section 8.5) if enabled: one block per
   received `addr`/`addrv2` message with responder identity/metadata and the raw
   advertised list (with literal per-address timestamps), recorded **before**
   dedup.
6. **Feed advertised addresses into the frontier** (Section 3.4).

To bound cost during testing, use the `--max-nodes` cap (Section 3.6) rather than
sampling which nodes are asked for peers.

### 3.4 Feeding discovered addresses back (frontier update)

For each advertised address from a peer:

0. **Enabled-network filter** (Section 9): if the address's network type is
   **disabled** for this run (or is "unknown"), ignore it entirely — it is not
   stored, not queued, and not counted in `num_advertised` or the freshest-seen
   map. (It is still counted in the advertising node's per-node breakdown, Section
   3.3 step 4.) All remaining steps apply only to enabled-network addresses.
1. **Update `freshest_ts`** in the store to `max(existing, observed)` (this also
   *creates* the entry if the address is brand new — see 3.4.1).

   ⚠️ **Ordering:** because this upsert *creates* the entry, snapshot the address's
   prior existence/state **before** it, then do the upsert, then branch on the
   snapshot — e.g. `let was_known = matches!(store.get(k), Some(e) if e.state !=
   StaleDiscarded);`. If step 2 instead tests existence *after* the upsert, every
   brand-new address looks already-known and is never enqueued, and the crawl stops
   right after resolving the seeds. With a sharded map, take the snapshot and the
   upsert **under the same shard lock** so a racing response can't interleave.
2. Determine known-ness: the address is **known** iff its entry already existed in
   a non-`StaleDiscarded` state before this response (`Queued`, `Processing`,
   `Reachable`, `HandshakeFailed`, or `Unreachable`). Known ⇒ do nothing further
   (dedup by identity).
3. **Freshness filter** (configurable; default 2 days, disable with `0`): if
   enabled and the entry's (just-updated) `freshest_ts` is **older** than
   `now − freshness_threshold`, set the entry's state to `StaleDiscarded` and do
   **not** enqueue. A `StaleDiscarded` entry is reconsidered on every later
   advertisement: when a fresher timestamp lifts it over the threshold, transition
   it to `Queued` and enqueue it then. When the filter is disabled, this step is
   skipped and every previously-unqueued address is enqueued.
4. Otherwise set state to `Queued` and push it onto the work queue.
5. Log counts: added / total advertised / already-known / discarded-stale.

Deduplication is by `(host, port)` identity only. Because the store is a single
map, the "known" check is one lookup — there is no union-of-sets scan.

### 3.4.1 Freshest-seen timestamp

The store holds one `freshest_ts` per distinct `(host, port)`, updated on **every**
observation:

- when a seed resolves to an address (Section 3.1), with timestamp "now"; and
- for every **enabled-network** address in **every** `addr`/`addrv2` response,
  before dedup.

Each update sets `freshest_ts = max(existing, observed)`. This single value:

- **drives the freshness filter** (Section 3.4 step 3), so an address is enqueued
  exactly when its freshest-seen timestamp first clears the threshold; and
- is written as `freshest_timestamp` in the reachable, handshake-failed, and
  unreachable outputs (Sections 7.1, 7.4, 7.5).

The timestamp keeps updating even after a node is classified, so the recorded value
reflects the freshest advertisement seen across the whole run. (This differs from
the addr-response log, which records each response's **literal** timestamp —
Section 8.5.)

### 3.5 Traversal strategy

The crawl is an **order-independent parallel sweep**: every distinct address is
processed exactly once, and the only goal is to visit them all. Nothing about the
result depends on the order in which addresses are processed, so there is no BFS,
no wave structure, and no distance bookkeeping — just per-transport work queues
drained by concurrent workers.

- **Per-transport queues and pools** (the structure that keeps slow transports from
  starving fast ones). There is one work queue **per transport family** — `ip`
  (IPv4/IPv6/CJDNS), `tor` (onion v2/v3), `i2p` — each holding only `AddrKey`s in
  state `Queued`, and each drained by its **own pool of workers whose size *is* that
  transport's concurrency limit** (Section 5). A newly discovered address is routed
  to the queue for its transport. Because each pool pulls only from its own queue, a
  saturated Tor pool can never hold IP workers hostage nor leave IP addresses
  stranded behind Tor work — the head-of-line blocking a single shared queue with a
  mixed worker pool suffers when a worker blocks on a slow connect while fast work
  waits. The pool size bounds concurrency directly, so no separate per-transport
  semaphore is needed, and queued addresses simply wait in their queue until a
  worker of that transport is free (which also bounds memory — no task is spawned
  per queued address).
- **Order within a queue is irrelevant**, so any cheap concurrent structure works
  (async MPMC channel, or `Mutex<VecDeque>` + `Notify`; FIFO/LIFO/work-stealing —
  whichever is fastest for the chosen runtime).
- **Politeness spread (only reason order is touched at all)**: to avoid hammering
  one subnet when a single peer advertises a burst of neighbors, **shuffle each
  batch of newly-discovered addresses before enqueuing** (O(k) per response). This
  is a load-spreading nicety, not a correctness requirement.
- **Outstanding-work counter (drives termination, Section 3.6).** A single global
  `AtomicUsize` `outstanding` counts every address in state `Queued` **or**
  `Processing` — i.e. queued + in-flight. It is incremented **at enqueue, before the
  item is visible in a queue** (by `enqueue()` below, under the store lock), and
  decremented **only when an address reaches a terminal state**. A retry is a
  lateral `Processing → Queued` move and does **not** change it. Because the
  increment happens on the producer side (never in a gap after a dequeue), an
  address is at every instant either sitting in a queue or counted in `outstanding`
  — it is never briefly invisible, which is what would otherwise let the crawl
  declare itself done while a just-dequeued address is still in a worker's hands. A
  node in state `Processing` is never re-enqueued (the known check in 3.4 covers it).

```
// Move an address to a terminal state; if it was the last outstanding work in the
// whole crawl, close every queue to end the run (3.6). fetch_sub returns the prior
// value, so "== 1" means outstanding just went 1 -> 0.
fn finish(entry, terminal_state):
    entry.state = terminal_state
    if outstanding.fetch_sub(1) == 1:
        close all queues                 // wakes every worker's recv() with None

// Used by the seeds (3.1) and the frontier feed (3.4). Caller holds the store lock.
fn enqueue(key):
    entry.state = Queued
    outstanding.fetch_add(1)             // count BEFORE the item becomes visible
    queue[transport_of(key)].send(key)

// Worker loop — run `concurrency[T]` of these per transport T, each bound to queue[T]:
loop:
    if max_nodes is set and num_processed_nodes >= max_nodes:
        close all queues                 // cap reached: wake peers; in-flight drain, then end
        return
    key = queue[T].recv()                // returns None once queues are closed & drained
    if key is None: return
    num_processed_nodes += 1             // counts this processing iteration, incl. retries (3.6)
    entry.state = Processing             // still counted in `outstanding`
    if not connect(entry):
        // Connect failures retry too (6.2): a node that connected on an earlier
        // attempt already proved reachable, so exhaustion here means
        // HandshakeFailed, not Unreachable.
        terminal = HandshakeFailed if entry.stats.time_connect_ms is set else Unreachable
        if attempts_left(entry): entry.state = Queued; queue[T].send(key)
        else:                    finish(entry, terminal)
    else if not handshake(entry):
        if attempts_left(entry): entry.state = Queued; queue[T].send(key)   // retry: outstanding unchanged
        else:                    finish(entry, HandshakeFailed)
    else:
        getaddr(entry) -> feed frontier (3.4)   // enqueue() each fresh addr FIRST, so
        finish(entry, Reachable)                // outstanding never dips to 0 while new work exists
    disconnect(entry)
```

### 3.6 Termination

The crawl ends when **`outstanding == 0`** — no address is queued or in-flight in
any transport's queue — detected precisely, without polling. Concretely: the worker
that drives the last outstanding address to a terminal state observes
`outstanding.fetch_sub(1) == 1` (Section 3.5) and closes every queue, which wakes
each blocked `queue[T].recv()` with `None` so all workers return. The monitor then
records `runtime_seconds` and exits. (The producer-side increment is what guarantees
the last address is never briefly out of its queue yet uncounted — Section 3.5.)

There is exactly **one crawl phase**. `num_processed_nodes` counts total connect
attempts (once per processing iteration, including retries).

**Optional test cap (`--max-nodes N`)**: when set, a worker that sees
`num_processed_nodes >= N` stops taking new work **and closes every queue** so peers
blocked on `recv()` wake and return (otherwise queued-but-unprocessed addresses
would leave `outstanding > 0` and the run would hang). Any addresses already
in-flight finish first; then the crawl ends. A re-queued retry that is pulled again
counts as another processing iteration. Default is **unlimited** — no max node
count.

There is **no global time limit**. A soft warning is logged if total runtime
exceeds 12 hours; it does not stop the crawl.

### 3.7 Reachable / handshake-failed / unreachable classification

Every processed node reaches exactly one terminal state:

- **Reachable**: the connection **and** the `version` handshake both succeeded.
  Full peer metadata (Section 4.4) is recorded, plus any advertised-address
  statistics from `getaddr`.
- **HandshakeFailed**: the connection succeeded (TCP/SOCKS5/SAM), but no peer
  `version` arrived after exhausting all handshake attempts. Only address,
  provenance, and connect timing are known — no `version`-derived fields, and no
  `getaddr` was ever sent. Semantically this means "something accepts TCP on this
  host:port," not necessarily a Bitcoin node.
- **Unreachable**: the connection could not be established on any attempt. Only
  address, provenance, and attempt count are known. If a node connected
  successfully on an earlier attempt but then failed to connect on its last one,
  it is filed as `HandshakeFailed` instead (Section 6.2) — it *did* prove
  reachable at least once, so `Unreachable` would misrepresent it.

Related transitions:

- **Retry**: a node whose connect or handshake attempt failed but which still has
  attempts left is re-enqueued (`state = Queued`) rather than terminated; only
  after the last attempt does it become terminal. A connect failure on the last
  attempt becomes `Unreachable` normally, but `HandshakeFailed` if the node
  connected successfully on an earlier attempt (Section 6.2) — a prior successful
  connect is evidence "the connection could not be established at all" no longer
  holds, and that evidence must not be discarded just because the final attempt
  failed at an earlier stage. A handshake failure on the last attempt always
  becomes `HandshakeFailed`.
- **Stale**: when the freshness filter is enabled, an advertised address older than
  the threshold is set `StaleDiscarded` and not enqueued (reconsidered on later,
  fresher advertisements). When disabled, nothing is stale.

### 3.8 Status monitor

One monitor task runs alongside the workers. It:

- **Cadence**: loops every 5 s (this is only the status-print cadence; termination
  detection is event-driven, Section 3.6).
- **Logs** each iteration a single `INFO` line:

  ```
  [STATUS] Elapsed: <H.h>h  reachable=<R> handshake_failed=<F> unreachable=<U> queued=<P> processing=<X>
  ```

  where `<H.h> = (now − start_clock)/3600`, and `<R>`/`<F>`/`<U>`/`<P>`/`<X>` are
  the counts of entries in states `Reachable`/`HandshakeFailed`/`Unreachable`/
  `Queued`/`Processing`.
- **Clock**: `start_clock` is set at **crawl launch** (Section 2.4 step 5).
  `runtime_seconds = int(now − start_clock)` is recorded once, at termination.
- **Exit**: when the crawl terminates (Section 3.6), log
  `[STATUS] No more nodes and no active workers: exiting`, emit the >12 h soft
  warning if applicable, and return.

---

## 4. Network and protocol details

*(This section is the Bitcoin wire protocol and must be implemented exactly.)*

### 4.1 Message envelope and receive loop

Every message is a 24-byte header + variable payload:

| Field | Size | Encoding | Notes |
|-------|------|----------|-------|
| network magic | 4 | fixed | Mainnet `F9 BE B4 D9`. Mismatch on receive ⇒ the stream is desynchronized: log and **drop the connection** (transport failure). |
| command | 12 | ASCII, NUL-padded right | e.g. `version\0\0\0\0\0`. |
| payload length | 4 | uint32 LE | payload bytes following the checksum. |
| checksum | 4 | fixed | first 4 bytes of double-SHA256 of the payload. Mismatch ⇒ payload is corrupt: log and **drop the connection**; payload not used. |
| payload | *len* | — | message body. |

Sending serializes the body, wraps it (recomputing length + checksum), writes it.

**Read-exactly framing.** Parse an envelope as strict, ordered read-exactly ops:
4 magic, 12 command, 4 length, 4 checksum, then `length` payload bytes. Each step
loops until the exact count arrives (TCP delivers arbitrary chunks).

**EOF / partial reads.** If the stream ends or drops mid-read, raise an "incomplete
read" error that propagates as a **transport failure**: during handshake it fails
the attempt (3.2); in the getaddr loop it ends the loop with what was collected
(3.3). No resynchronization.

**Payload-length bound.** **Reject** any envelope whose advertised payload length
exceeds `MAX_PROTOCOL_MESSAGE_LENGTH` = **4 MiB (4 × 1024 × 1024)**: log and drop
the connection. This check happens **before** any allocation or payload read, so a
peer advertising `0xFFFFFFFF` can never drive a large read/allocation.

**Receive loop.** Read envelopes until one whose command matches an expected class
arrives. During the wait:
- Any `ping` is answered immediately with a `pong` **echoing that ping's exact
  8-byte nonce**.
- Any other unmatched message is silently skipped.

The wait is bounded by a caller-supplied budget: a **per-envelope timeout** *and*
an **overall deadline**. Each envelope-parse waits at most
`min(deadline − now, per_envelope_timeout)`, and once the deadline passes the loop
fails with a timeout. Bounding the aggregate (not only each envelope) stops a peer
that stays active — e.g. dripping `ping`s — without ever sending the expected
message from pinning the loop forever. The handshake wait uses
`deadline = start + message_timeout` with per-envelope `message_timeout`
(Section 3.2); the getaddr loop uses `deadline = start + getaddr` with per-receive
`getaddr_idle` (Section 3.3). Multi-byte counts/lengths inside
`addr`/`addrv2`/`version` payloads use **CompactSize** (Section 4.3.0).

### 4.2 Transports and network types

- **IPv4 / IPv6**: direct TCP.
- **CJDNS**: an IPv6 socket, connected directly over TCP (distinguished from IPv6
  only for typing/timeouts).
- **Onion v2 / v3**: SOCKS5 proxy (default `127.0.0.1:9050`) with remote DNS.
- **I2P**: SAM session (default router `127.0.0.1:7656`); one session created lazily
  and shared across all I2P connections.

Connection time (ms) is measured and stored as `time_connect`.

#### 4.2.1 SOCKS5 (Tor) — RFC 1928, no auth, remote DNS

Over a fresh TCP connection to the proxy `host:port`:

1. **Greeting** → proxy: `05 01 00` (VER 5, 1 method, `00` = no auth).
2. **Method selection** ← proxy: `05 00`. Anything else ⇒ failure.
3. **CONNECT** → proxy: `05 01 00 03 <LEN> <HOST…> <PORT>` — CMD `01`, ATYP `03`
   (DOMAINNAME ⇒ remote DNS), `<LEN>` 1-byte host length, `<HOST…>` ASCII `.onion`,
   `<PORT>` 2-byte **big-endian** (8333).
4. **Reply** ← proxy: `05 <REP> 00 <ATYP> <BND.ADDR…> <BND.PORT>`. `REP=00` ⇒
   success; non-zero ⇒ connection failure, handled like any other connect
   failure (retry-or-`Unreachable`, Section 6.2).
5. On success the tunnel is transparent; the raw P2P envelope stream flows over it.

The Tor **connect** timeout bounds the whole negotiation.

#### 4.2.2 I2P SAM v3.1

**Session creation (lazy, once, shared).** Over a TCP connection to the SAM router:

1. `HELLO VERSION MIN=3.0 MAX=3.1\n` → `HELLO REPLY RESULT=OK VERSION=3.1`.
2. `SESSION CREATE STYLE=STREAM ID=<session_id> DESTINATION=TRANSIENT SIGNATURE_TYPE=7\n`
   → `SESSION STATUS RESULT=OK …`. `<session_id>` is a random session name,
   `DESTINATION=TRANSIENT` a throwaway destination, `SIGNATURE_TYPE=7` =
   Ed25519. Keep this control socket open for the session lifetime.

**Per-connection stream setup.** Over a **new** TCP connection to the router:

1. `HELLO VERSION MIN=3.0 MAX=3.1\n` → `HELLO REPLY RESULT=OK`.
2. `STREAM CONNECT ID=<session_id> DESTINATION=<host> SILENT=false\n` where `<host>`
   is the `.b32.i2p` address (SAM does the naming lookup implicitly). Expect
   `STREAM STATUS RESULT=OK`; anything else ⇒ failure.
3. Afterwards the socket carries the raw P2P stream.

The I2P **connect** timeout bounds stream setup. (There is no mature Rust SAM
library; plan to hand-roll this ~20-line line-oriented exchange.)

**Address type detection** (from the host string):

- Contains `:` (IPv6-form) → parse into an IPv6 value (`Ipv6Addr` /
  `inet_pton(AF_INET6, …)`) and test **`first_octet == 0xfc`** ⇒ CJDNS
  (`fc00::/8`), else IPv6. **Do not** use a case-sensitive `"fc"` string prefix —
  uppercase, zero-compressed, or IPv4-mapped forms would be misclassified. If
  parsing fails, it is not a valid IPv6/CJDNS address ⇒ "unknown".
- Ends `.onion`, label length 16 → onion_v2.
- Ends `.onion`, label length 56 → onion_v3.
- Ends `.b32.i2p`, label length 52 → i2p.
- Four dotted octets each in `[0,256)` → ipv4.
- Otherwise → "unknown" (logged as an error).

IPv6/CJDNS hosts are rendered bracketed in string form (`[2001:db8::1]:8333`).

### 4.3 Messages sent and parsed

#### 4.3.0 CompactSize codec

Every wire count/length below (addr/addrv2 record counts, addrv2 per-record
`services` and address-length, `version` user-agent length) uses CompactSize:

| First byte | Total size | Value |
|------------|-----------|-------|
| `0x00`–`0xFC` | 1 | the byte itself (0–252) |
| `0xFD` | 3 | `0xFD` + uint16 LE |
| `0xFE` | 5 | `0xFE` + uint32 LE |
| `0xFF` | 9 | `0xFF` + uint64 LE |

Decode need not enforce minimality; encoders must emit minimal form.

**Sent by the crawler:**

- `version`: protocol **70016**, services **0**, current timestamp, zeroed
  receiver/sender address fields (IP `::ffff:0.0.0.0`, port 0), a **freshly drawn
  random 64-bit nonce and the current time per handshake**, user agent
  **`/Satoshi:27.0.0/`**, latest block **0**, relay **false**. On-wire layout (also
  the layout parsed from peers, Section 4.4):

  | Offset | Field | Size | Encoding |
  |--------|-------|------|----------|
  | 0  | version | 4 | int32 LE |
  | 4  | services | 8 | uint64 LE |
  | 12 | timestamp | 8 | int64 LE (epoch s) |
  | 20 | addr_recv services | 8 | uint64 LE |
  | 28 | addr_recv IP | 16 | 16-byte IPv6 (IPv4 as `::ffff:a.b.c.d`) |
  | 44 | addr_recv port | 2 | uint16 BE |
  | 46 | addr_from services | 8 | uint64 LE |
  | 54 | addr_from IP | 16 | 16-byte IPv6 |
  | 70 | addr_from port | 2 | uint16 BE |
  | 72 | nonce | 8 | uint64 LE |
  | 80 | user-agent length | var | CompactSize |
  | …  | user-agent | *len* | UTF-8 |
  | …  | start_height / latest_block | 4 | int32 LE |
  | …  | relay | 1 | bool (`00`/`01`) |

  The two 26-byte address sub-fields carry an 8-byte services prefix + 16-byte IP +
  2-byte port, **no** per-address timestamp; the crawler zeroes both when sending.
  On parsing, later fields are read only if the peer's version is high enough: the
  `addr_from…user_agent…latest_block` block requires version ≥ 106, `relay`
  requires ≥ 70001. **An absent `relay` is recorded as `true`** (Core convention:
  omitted ⇒ relay all), never `false`.
- `sendaddrv2`: empty payload; opts into BIP155 `addrv2`.
- `verack`: empty payload.
- `getaddr`: empty payload.
- `pong`: 8-byte nonce echoing a received `ping`.

**Parsed from peers:**

- `version` (fields per Section 4.4).
- `ping`: 8-byte nonce (used only to build the `pong`).
- `addr`: CompactSize count + that many records; each = 4-byte LE timestamp
  (**uint32, unsigned** — zero-extend into the `i64` `freshest_ts`, never
  sign-extend), 8-byte services (discarded), 16-byte IPv4-mapped IPv6, 2-byte BE
  port. IPv4-mapped ⇒ dotted IPv4. (Assumes version ≥ 31402; no pre-timestamp
  special case.)
- `addrv2` (BIP155): CompactSize count + records; each = 4-byte LE timestamp
  (uint32, unsigned — zero-extend, as in `addr`), CompactSize services (discarded),
  1-byte net id, CompactSize address length,
  address bytes, 2-byte BE port. Net ids and their **validated fixed** lengths:

  | net id | type | addr length |
  |--------|------|-------------|
  | 1 | ipv4 | 4 |
  | 2 | ipv6 | 16 |
  | 3 | torv2 | 10 |
  | 4 | torv3 | 32 |
  | 5 | i2p | 32 |
  | 6 | cjdns | 16 |

  If length ≠ expected, parsing stops (defensive). Decoding:
  - **ipv4** → dotted quad.
  - **ipv6** → IPv6 text; IPv4-mapped collapses to dotted IPv4.
  - **torv2** → base32(10 bytes), lowercase, + `.onion` (16-char label). (Onion v2
    is defunct network-wide; keep the parser for completeness but expect zero
    connects.)
  - **torv3** → the 32-byte ed25519 pubkey. `checksum = SHA3-256(".onion checksum"
    ‖ pubkey ‖ 0x03)[:2]`; `label = base32(pubkey ‖ checksum ‖ 0x03)` = 56 lower
    base32 chars, no padding; address = `label + ".onion"`.
  - **i2p** → base32(32 bytes) = 56 chars + `====`; lowercase; strip all `=`
    (→ 52 chars); + `.b32.i2p`.
  - **cjdns** → IPv6 text.

  Base32 = RFC 4648 (`A–Z2–7`), lowercased. Parsing is defensive: truncation,
  unknown net id, or length mismatch stops and returns what was decoded so far
  (logged). A truncated leading count returns empty rather than raising.

### 4.4 Node metadata collected from the peer `version`

The crawler sends fixed 70016 and does not negotiate. From the peer's `version` it
retains (version permitting):

- `version` (int), `services` (u64), `timestamp` (stored as
  `version_reply_timestamp_remote`).
- receiver + sender services/IP/port, and the nonce — **parsed then dropped** from
  output.
- `user_agent`: length-prefixed UTF-8; on UTF-8 decode failure store the raw bytes'
  hex.
- `latest_block`: peer's best height at handshake.
- `relay`: present only for version ≥ 70001; **absent ⇒ `true`**, never `false`.

---

## 5. Concurrency and performance

- **Model**: async tasks over a shared node store and per-transport work queues.
  Recommended runtime: `tokio`. Because there is real parallelism, the shared state
  **must** be synchronized:
  - the node store behind a **sharded / concurrent map** (recommended — e.g.
    `dashmap`, or `N` shards each a `Mutex<HashMap>` keyed by `hash(host,port) % N`),
    so the many per-address frontier updates from concurrent `addr` responses don't
    serialize on one lock. A single `Mutex<HashMap>`/`RwLock<HashMap>` is *correct*
    but at `ip`-concurrency in the hundreds the global lock becomes the throughput
    bottleneck; use it only for a simple first cut, then shard.
  - each transport's work queue an async MPMC channel (or `Mutex<VecDeque>` +
    `Notify`);
  - `outstanding` an `AtomicUsize` (Section 3.5); `num_processed_nodes` likewise.
  The invariant "each entry is in exactly one `NodeState`" is maintained by
  transitioning state **while holding the entry's shard lock**, and by moving an
  entry to `Processing` the instant it is dequeued.
- **Per-transport pools = the concurrency limit** (the key throughput lever): each
  transport family (`ip`, `tor`, `i2p`; CJDNS rides the `ip` TCP path) has its own
  work queue drained by a pool of exactly `concurrency[T]` workers (Section 3.5), so
  the pool size *is* the concurrency cap and no separate semaphore is needed.
  Suggested defaults: `ip` = 64, `tor` = 64, `i2p` = 32 (tune to host + side-service
  capacity).
- **No per-host or global socket cap beyond the pool sizes; no explicit rate
  limiting.** Pacing comes from timeouts + pool sizes.
- **Shared I2P SAM session**: one session id created on first I2P use, reused by
  all I2P connections (shared failure/identity point — accepted).

---

## 6. Timeouts, retries, error handling

### 6.1 Timeouts (seconds, per network)

Four values per network: **connect**, **message** (wait for one reply), **getaddr**
(hard budget ceiling for the collection loop), and **getaddr_idle** (idle timeout
per receive inside the loop).

| Network | connect | message | getaddr | getaddr_idle |
|---------|---------|---------|---------|--------------|
| IP (v4/v6) | 3 | 30 | 70 | 3 |
| Tor | 100 | 40 | 90 | 5 |
| I2P | 30 | 80 | 170 | 8 |
| CJDNS | 10 | 30 | 70 | 3 |

All overridable per network via flags/env. The getaddr loop uses per-receive
timeout `min(deadline − now, getaddr_idle)` and stops on the first idle timeout
(Section 3.3). `getaddr_idle` is the single most impactful knob for crawl speed.

### 6.2 Retries

- **Handshake attempts**: default 3 total (not 3 on top of an initial try). A
  per-node counter starts at 0 and is incremented **before** each `version` send.
  After a failure, retry iff `counter < handshake_attempts` (true at 1 and 2, false
  at 3). Sequence: attempt 1 fails → retry, 2 fails → retry, 3 fails → give up
  (`HandshakeFailed`). No backoff; the retry simply competes for selection later
  (re-enqueued).
- **Connect failures retry** like any other transient failure, up to
  `handshake_attempts`, then give up as `Unreachable` — or `HandshakeFailed` if
  an earlier attempt had connected successfully (Section 3.7). A connect
  timeout/refusal is not reliable evidence of a dead peer — it can be
  self-inflicted (e.g. a saturated worker pool causing legitimately-live peers to
  blow past the connect timeout), so a single failed attempt does not condemn the
  address. This applies uniformly to IP (TCP), Tor (SOCKS5), and I2P (SAM)
  connects. The tradeoff mirrors the one made for handshake silence below: a
  genuinely dead host can now cost up to `handshake_attempts × connect_timeout`
  of worker time instead of one `connect_timeout` — most visible for Tor
  (up to 3 × 100 s = 300 s per dead `.onion` by default) — which is accepted
  because a connect failure, unlike a full-deadline handshake silence, is not
  strong evidence the host is dead.
  The requeue fallback (used if the crawl is shutting down when a retry would be
  re-enqueued) always finishes with the *same* terminal state the exhausted-retry
  path would have used, so a connect-stage retry racing shutdown still resolves
  to `Unreachable`/`HandshakeFailed` correctly rather than being mislabeled as a
  handshake-stage failure.
- **Retry only transient failures past the connect stage** (default). A host that
  **connects but then stays silent for the whole handshake deadline** (Section 3.2
  step 3) is *not* retried:
  a full-deadline silence is strong evidence it won't speak Bitcoin, and retrying
  would burn another full `message_timeout` — up to `handshake_attempts ×
  message_timeout` of worker time on a single dead-but-listening host, a real
  crawl-wide cost since the open internet is full of TCP services that aren't nodes.
  Such an attempt goes **straight to `HandshakeFailed`**. Retries are reserved for
  **mid-handshake transport errors** (connection reset/dropped after some bytes, or
  a magic/checksum desync, Section 4.1) that plausibly differ on a second try. A
  flag/env can restore retry-on-timeout for networks where slow-but-live peers are
  expected.

### 6.3 Error handling

- Connect exceptions ⇒ retry like any other transient failure (Section 6.2);
  exhausting attempts ⇒ Unreachable, or HandshakeFailed if an earlier attempt
  had already connected successfully (Section 3.7).
- Disconnect exceptions ⇒ logged, ignored.
- Handshake receive errors/timeouts ⇒ attempt fails.
- Getaddr send/receive errors ⇒ loop ends with what was collected.
- Magic/checksum mismatch, or payload length > 4 MiB ⇒ log + drop connection
  (transport failure).
- Address-message parse errors ⇒ partial/empty result, no raise.
- Per-seed DNS failure ⇒ empty for that seed.

---

## 7. Data collected and statistics

### 7.1 Reachable-node fields (CSV column order)

For nodes that connected **and** completed the handshake:

`host`, `port`, `network`, `handshake_timestamp` (epoch s when `version` was sent),
`time_connect` (ms), `handshake_attempts`, `handshake_duration` (ms), `version`,
`services`, `user_agent`, `latest_block`, `relay`,
`version_reply_timestamp_remote`, `advertised_addrs_total`,
`advertised_addrs_ipv4`, `_ipv6`, `_onion_v2`, `_onion_v3`, `_i2p`, `_cjdns`,
`freshest_timestamp`.

(No `handshake_successful` column: membership in this file already means the
handshake succeeded. No `requested_addrs` column: every reachable node is asked for
peers, so it would always be true.)

`freshest_timestamp` = newest timestamp ever seen for this address (Section 3.4.1);
for a seed node never re-advertised it is the seed's "now".

Dropped deliberately: receiver/sender services/IP/port and the version nonce.

### 7.2 Crawl-wide statistics (JSON)

- Full serialized settings (Section 8.4 shape).
- `time_started` (UTC string), `runtime_seconds`, `num_processed_nodes` (total
  connect attempts including retries).
- `num_reachable`, `num_handshake_failed`, `num_unreachable`: each a breakdown
  `{ total, unknown, ipv4, ipv6, onion_v2, onion_v3, i2p, cjdns }`.
- `num_advertised`: number of **distinct** advertised addresses = `store.len()`
  (one entry per distinct `(host, port)` ever seen).
- `num_nodes_from_seed`: per-seed network-type breakdown of initial addresses.
- `list_reachable`, `list_handshake_failed`, `list_unreachable`: address-string
  lists.
- `list_nodes_from_seed`: per-seed address-string lists.

### 7.3 Final summary

One line at end: processed / reachable / handshake-failed / unreachable counts +
total runtime.

### 7.4 Handshake-failed-node fields (CSV column order)

For nodes that connected but never completed the handshake:

`host`, `port`, `network`, `handshake_timestamp` (epoch s when the first `version`
was sent), `time_connect` (ms), `handshake_attempts` (number of `version` sends
before giving up — equal to the max only when every attempt was a retryable
transport error; a full-deadline silence gives up after one, Section 6.2),
`freshest_timestamp`.

No `version`-derived fields and no advertised-address counts (a `version` was never
received and `getaddr` was never sent).

### 7.5 Unreachable-node fields (CSV column order)

For nodes the connection to which never succeeded:

`host`, `port`, `network`, `handshake_attempts` (connect attempts before giving
up), `freshest_timestamp`. No connect-timing or handshake fields (the connection
never succeeded).

### 7.6 Addr-response records

If enabled, one block per received `addr`/`addrv2` message (Section 8.5): responder
identity (`host`, `port`, `network`), responder metadata (`version`, `services`,
`user_agent`, `latest_block`, `relay`), receipt epoch, message type, and the raw
advertised list (each with `host`, `port`, `network`, **literal** `timestamp`),
recorded before dedup.

---

## 8. Output

All outputs are **plain, uncompressed** files under the results directory, prefixed
`<timestamp>_v<version>_`, `timestamp` defaulting to the crawl start time in
`%Y-%m-%dT%H-%M-%SZ` UTC.

**CSV dialect:** delimiter `,`; record terminator `\n`; quote char `"` escaped by
doubling; RFC 4180 **minimal quoting** — quote a field only if it contains `,`,
`"`, `\r`, or `\n` (matters for `user_agent`). One header row; UTF-8; no trailing
blank line.

### 8.1 Reachable nodes CSV

- File: `<prefix>_reachable_nodes.csv`.
- One row per reachable node, columns in Section 7.1 order.
- Rows sorted ascending by `handshake_timestamp`.
- If none, file not written (warning logged).

### 8.2 Handshake-failed nodes CSV

- File: `<prefix>_handshake_failed_nodes.csv`.
- One row per handshake-failed node, columns in Section 7.4 order.
- Rows sorted ascending by `handshake_timestamp`.
- If none, file not written (warning logged).

### 8.3 Unreachable nodes CSV

- File: `<prefix>_unreachable_nodes.csv`.
- One row per unreachable node, columns in Section 7.5 order.
- Rows sorted ascending by `freshest_timestamp`.
- If none, file not written (warning logged).

### 8.4 Crawler statistics JSON

- File: `<prefix>_crawler_stats.json`.
- Pretty-printed, 4-space indent, keys in insertion order (not sorted).
- Top-level shape (in order):

  ```jsonc
  {
    "crawler_settings": { … },
    "time_started": "YYYY-MM-DDTHH-MM-SSZ",
    "runtime_seconds": <int>,
    "num_processed_nodes": <int>,
    "num_reachable":        { "total": <int>, "unknown": <int>, "ipv4": <int>,
                              "ipv6": <int>, "onion_v2": <int>, "onion_v3": <int>,
                              "i2p": <int>, "cjdns": <int> },
    "num_handshake_failed": { …same shape… },
    "num_unreachable":      { …same shape… },
    "num_advertised": <int>,
    "num_nodes_from_seed": { "<seed>": { …num_reachable shape… }, … },
    "list_reachable":        [ "<addr>", … ],
    "list_handshake_failed": [ "<addr>", … ],
    "list_unreachable":      [ "<addr>", … ],
    "list_nodes_from_seed": { "<seed>": [ "<addr>", … ], … }
  }
  ```

- `crawler_settings`:

  ```jsonc
  {
    "version_info": { "version": "<pkg version>", "extra": <string|null> },
    "delay_start": <int>,
    "max_nodes": <int|null>,             // null = unlimited (test cap)
    "enabled_networks": { "ipv4": <bool>, "ipv6": <bool>, "tor": <bool>,
                          "i2p": <bool>, "cjdns": <bool> },
    "strict_networks": <bool>,
    "freshness_threshold": <int>,        // seconds; 0 = filter disabled
    "record_addr_responses": <bool>,
    "concurrency": { "ip": <int>, "tor": <int>, "i2p": <int> },
    "node_settings": {
      "timeouts": {
        "ip":    { "connect": <n>, "message": <n>, "getaddr": <n>, "getaddr_idle": <n> },
        "tor":   { … }, "i2p": { … }, "cjdns": { … }
      },
      "handshake_attempts": <int>,
      "network_settings": {
        "tor_proxy_host": "<str>", "tor_proxy_port": <int>,
        "i2p_sam_host": "<str>",   "i2p_sam_port": <int>
      }
    },
    "result_settings": {
      "path": "<str>", "timestamp": "<str>",
      "reachable_nodes": "<str>", "handshake_failed_nodes": "<str>",
      "unreachable_nodes": "<str>", "crawler_stats": "<str>", "addr_responses": "<str>"
    }
  }
  ```

### 8.5 Addr-response log (optional, plain CSV)

Enabled by `record_addr_responses`. Written incrementally as messages arrive.

- File: `<prefix>_addr_responses.csv` — plain.
- **Grouped layout**: a sequence of blocks, one per received `addr`/`addrv2`
  message (recorded before dedup). Each block = one **node line** + zero or more
  **address lines**. Rows are comma-separated, `\n`-terminated, RFC 4180 minimal
  quoting.
- **Node line** — first field the literal `===NEW NODE===`, then: `host`, `port`,
  `network`, `received_at` (epoch s), `message_type` (`addr`|`addrv2`), `version`,
  `services`, `user_agent`, `latest_block`, `relay`. (IPv6/CJDNS host written
  **bracketless**.)
- **Address line** — `host` (bracketless), `port`, `network`, `timestamp`
  (**literal** last-seen epoch s from this response — not the freshest-seen value).
- **Parsing rule**: a line whose first field is `===NEW NODE===` starts a block;
  every other line is an advertised address of the most recent node line. A node
  that advertised nothing is a node line with no following address lines.
- Blocks in receipt order. If no responses (or disabled), no file.

Example:

```
===NEW NODE===,203.0.113.7,8333,ipv4,1720353600,addrv2,70016,1033,/Satoshi:25.0/,850000,false
198.51.100.9,8333,ipv4,1720350000
2001:db8::1,8333,ipv6,1720349000
===NEW NODE===,5.6.7.8,8333,ipv4,1720353610,addr,70015,1037,/Satoshi:24.0/,849990,true
192.0.2.5,8333,ipv4,1720348000
```

### 8.6 Debug log (optional, plain text)

- File: `<prefix>_debug_log.txt` — plain (no compression).

---

## 9. Configuration

CLI flags, most with a matching env var default.

**Timeouts** (per network `IP`, `TOR`, `I2P`, `CJDNS`; each with
`connect`/`message`/`getaddr`/`getaddr-idle`): `--<net>-<op>-timeout`, env
`<NET>_<OP>_TIMEOUT`. Defaults in Section 6.1.

**Concurrency**: `--ip-concurrency` (default 64), `--tor-concurrency` (64),
`--i2p-concurrency` (32).

**Crawler behavior**:
- `--dry-run` (default off): run the network preflight (Section 2.5), print the
  reachability table, and exit without crawling. Exit code 0 iff every enabled
  network is reachable.
- `--max-nodes` (env `MAX_NODES`, default unset/unlimited): stop after processing
  at most `N` nodes (Section 3.6). A testing cap for quick partial crawls.
- `--handshake-attempts` (env `HANDSHAKE_ATTEMPTS`, default 3).
- `--delay-start` (env `DELAY_START`, default **0**): seconds to sleep before
  crawling. Raise it only if local Tor/I2P side services need warm-up time.
- `--freshness-threshold` (env `FRESHNESS_THRESHOLD`, default `2d`/172800). Accepts
  seconds or a human form (`2d`, `48h`). `0` disables the filter.
- `--no-freshness-filter`: convenience for `--freshness-threshold 0`.
- `--record-addr-responses` / `--no-record-addr-responses` (env
  `RECORD_ADDR_RESPONSES`, default **off** — it's the largest output and pure
  provenance data; opt in when you need it).

**Networks** (which network types to crawl; each defaults **on**). Disabling a
network means addresses of that type are never queued, connected to, or counted in
`num_advertised` (Section 3.4 step 0); it does not affect the per-node
advertised-address breakdown. One toggle per network:
- `--ipv4` / `--no-ipv4` (env `ENABLE_IPV4`).
- `--ipv6` / `--no-ipv6` (env `ENABLE_IPV6`).
- `--tor` / `--no-tor` (env `ENABLE_TOR`): covers both onion v2 and v3.
- `--i2p` / `--no-i2p` (env `ENABLE_I2P`).
- `--cjdns` / `--no-cjdns` (env `ENABLE_CJDNS`).
- `--strict-networks` (default off): abort at startup if any **enabled** network
  fails its preflight probe (Section 2.5), instead of warning and continuing.

**Networking** (proxy / router endpoints for the anonymity networks):
- `--tor-proxy-host` / `--tor-proxy-port` (`127.0.0.1` / `9050`): the SOCKS5 proxy
  for Tor.
- `--i2p-sam-host` / `--i2p-sam-port` (`127.0.0.1` / `7656`): the SAM router for I2P.

**Output / logging**:
- `--result-path` (env `RESULT_PATH`, default `results`).
- `--timestamp` (env `TIMESTAMP`, default current UTC formatted).
- `--extra-version-info` (default none).
- `--log-level` (env `LOG_LEVEL`, default `INFO`).
- `--store-debug-log` / `--no-store-debug-log` (env `STORE_DEBUG_LOG`, default on).

The crawler is a one-off command: each run performs a single crawl and writes plain
result files. Tor and I2P require locally-running side services (SOCKS5 proxy, SAM
router) at the configured hosts/ports if those networks are to be crawled.

---

## 10. Key design decisions

Rationale for the non-obvious choices; the mechanics live in the sections cited.

- **Single node store keyed by `(host, port)`** (Section 2.1): one map holds the
  frontier and all result sets, so the discovery-time "known?" check is a single O(1)
  lookup rather than a scan over separate sets, and `num_advertised` is just the map
  size.
- **Order-independent parallel sweep** (Section 3.5): the result depends only on
  *which* addresses are visited, never the order — hence no BFS, no waves, no distance
  bookkeeping, and termination is a precise event rather than a poll.
- **Per-transport queues and pools** (Section 3.5): isolating slow anonymity-network
  connects from the fast IP crawl keeps a stalled Tor worker from holding up IP work,
  so overall throughput tracks the IP network rather than Tor/I2P latency.
- **Short getaddr idle timeout** (Section 3.3): peers dump their addresses in a burst
  then go quiet, so ending the collection loop on a few seconds of silence — instead
  of the full message timeout — is the largest per-node wall-clock saving.
- **Advertise protocol 70016 + `sendaddrv2`**: BIP155 gates `addrv2` on protocol
  ≥ 70016, and `addrv2` is the only way to learn Tor v3, I2P, and CJDNS peers.
- **Three terminal outcomes in separate files** (Section 3.7): "accepts a TCP
  connection" and "is a working Bitcoin node" are different facts worth separating.
- **Fixed identity (zero services, Core-like user agent)**: presents as an
  unremarkable node to maximize peer responsiveness without claiming to serve data.

---

## 11. Assumptions and edge cases

- **Mainnet only** (magic + port 8333 hardcoded).
- **Modern peers assumed** (`addr` always carries a timestamp; pre-31402 nodes are
  extinct).
- **No verack confirmation**: handshake judged on the peer's `version` alone.
- **Handshake-failed ≠ Bitcoin node**: a handshake-failed entry means only that
  *something* accepted a TCP connection on that host:port.
- **CJDNS = plain TCP**: reachable only if the host has CJDNS routing; else the
  connect simply fails.
- **Onion v2 is defunct**: parser retained, connects will essentially never
  succeed.
- **Concurrent shared state**: the store/queue are synchronized (Section 5); the
  single-`NodeState` invariant is held under the store lock.
- **No global time limit**: only a soft >12 h warning (an optional `--max-nodes`
  cap can stop the crawl early for testing, Section 3.6).
- **Unknown address types**: labeled "unknown", logged, counted separately, and
  (having no transport) never connect.
</content>
