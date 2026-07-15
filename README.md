# new-p2p-crawler

Maps the reachable Bitcoin **mainnet** P2P network. Starts from DNS seeds,
handshakes each node, asks for peers (`getaddr`), and repeats until the frontier
drains. Reaches IPv4, IPv6, CJDNS, Tor (v2/v3), and I2P. One run, then writes
plain result files. See `SPECIFICATION_v2.md` for the full design.

## Build

```bash
cargo build --release
```

## Run

```bash
# Health check: probe each enabled network's transport, print a table, exit.
# Exit 0 iff every enabled network is reachable.
./target/release/new-p2p-crawler --dry-run

# IPv4-only, capped for a quick partial crawl.
./target/release/new-p2p-crawler --no-tor --no-i2p --no-ipv6 --no-cjdns \
    --max-nodes 200 --result-path ./results

# Full crawl. Tor/I2P need local side services running (see below).
./target/release/new-p2p-crawler
```

## Probe a specific node list

The `probe` binary connects to an explicit list of nodes and reports the
outcome of each connect + handshake **without crawling** — no DNS seeds, and it
never follows `addr`/`addrv2` responses, so it touches exactly the nodes you
give it. It reuses the crawler's transports, timeouts, retries, and result
files. Handy for debugging *why* a handshake fails against known peers.

```bash
# Nodes as arguments (host, host:port, or [ipv6]:port; bare host uses --port).
./target/release/probe 1.2.3.4:8333 '[2001:db8::1]:8333' abc…xyz.onion

# Or from a file / stdin (one per line; # comments and blanks ignored).
./target/release/probe --nodes-file nodes.txt
cat nodes.txt | ./target/release/probe
```

It prints a per-node report (`REACHABLE` / `HANDSHAKE_FAILED` / `UNREACHABLE`
with the failure reason) and a failure-reason histogram, and writes the same
result files as the crawler. All shared flags (`--*-timeout`, `--*-concurrency`,
`--tor-proxy-*`, `--i2p-sam-*`, `--result-path`, `--log-level`, …) apply.

## Requirements

- Tor: a SOCKS5 proxy at `127.0.0.1:9050` (`--tor-proxy-host/-port`).
- I2P: a SAM router at `127.0.0.1:7656` (`--i2p-sam-host/-port`).
- Missing a service? That network just comes back unreachable (or use
  `--no-tor` / `--no-i2p`). `--strict-networks` aborts instead of warning.

## Key flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--max-nodes N` | unlimited | strict cap on distinct nodes started (testing cap) |
| `--max-addresses N` | `1000000` | cap unique retained frontier addresses and bound queue memory |
| `--no-<net>` | — | disable a network (`ipv4`/`ipv6`/`tor`/`i2p`/`cjdns`) |
| `--freshness-threshold` | `2d` | skip addrs last-seen older than this (`0` = off) |
| `--no-record-addr-responses` | on | stop logging every `addr`/`addrv2` reply (recording is on by default) |
| `--ip/-tor/-i2p-concurrency` | 64/64/32 | workers per transport |
| `--result-path` | `results` | output directory |
| `--checkpoint-interval` | `10m` | re-write result files this often (`0` = off) |

Run `--help` for the full, sectioned list.

## Output

Each run creates a new, collision-resistant subdirectory of the result dir. An
explicit `--timestamp` that would reuse an existing run fails instead of mixing
data. The run directory contains:

- `snapshot_manifest.json` — the atomically published current generation,
  consistency/completeness labels, file hashes, and durable addr-log watermark
- `snapshots/<generation>/reachable_nodes.csv` — connected + peer-`verack`
  handshake completed, including socket/version provenance, collection outcome,
  and attempt history
- `snapshots/<generation>/handshake_failed_nodes.csv` — connected but handshake
  failed (including all retry attempts)
- `snapshots/<generation>/unreachable_nodes.csv` — never connected (including all
  retry attempts)
- `snapshots/<generation>/crawler_stats.json` — settings, snapshot-consistent
  counts, completeness, and node lists
- `addr_responses.csv` — on by default; disable with `--no-record-addr-responses`
- `debug_log.txt` — optional, on by default

Every failed connect or handshake attempt is written immediately to
`debug_log.txt` with the endpoint, attempt number, stable failure reason, retry
decision, and (when available) the underlying I/O error. The snapshot failure
CSVs retain the terminal reason and the complete attempt history, so failure
diagnostics remain available even when debug logging is disabled.

The concurrency flags are hard in-flight connection caps, not batch sizes. The
default IP cap is 64 (down from the old 512); the crawler keeps those workers busy
without opening more IP connections than the configured cap.

### Failure reasons

Failed nodes carry a `failure_reason` (also aggregated in the stats JSON):

| Phase | Reason | Meaning |
|-------|--------|---------|
| connect | `connect_refused` | nothing listening (RST) |
| connect | `connect_timeout` | connect/proxy/SAM setup timed out |
| connect | `connect_unreachable` | no route to host/network |
| connect | `connect_reset` | connection reset during connect |
| connect | `proxy_error` | Tor SOCKS5 negotiation failed (proxy down / REP ≠ 0) |
| connect | `sam_error` | I2P SAM session/stream setup failed |
| connect | `connect_other` | other connect-phase error |
| handshake | `version_send_failed` | could not send our `version` |
| handshake | `negotiation_send_failed` | could not send `sendaddrv2` |
| handshake | `verack_send_failed` | could not send our `verack` |
| handshake | `peer_verack_timeout` | peer did not complete the handshake with `verack` |
| handshake | `handshake_timeout` | peer stayed silent for the whole deadline |
| handshake | `connection_closed` | peer closed/reset mid-handshake (EOF) |
| handshake | `malformed_version` | peer's `version` did not parse |
| handshake | `protocol_desync` | bad magic/checksum or oversize payload |
| handshake | `handshake_other` | other handshake-phase error |

Snapshot generations are published when the crawl finishes and every
`--checkpoint-interval` while it runs. Checkpoints are explicitly labeled fuzzy;
the post-worker generation is labeled final. Every category is present even when it
contains only a header. `addr_responses.csv` uses monotonic event ids, records parser
and request outcomes, and is flushed and synced before a manifest advances its
durable watermark. A `getaddr` result is a capped, partial, potentially cached sample,
not a complete live addrman view. Pressing **Ctrl+C** starts a graceful shutdown: in-flight nodes are
allowed to finish, then the final output is written. A **second Ctrl+C**
force-quits immediately without writing.
