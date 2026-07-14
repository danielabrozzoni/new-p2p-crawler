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
| `--max-nodes N` | unlimited | stop after ~N processed nodes (testing cap) |
| `--no-<net>` | — | disable a network (`ipv4`/`ipv6`/`tor`/`i2p`/`cjdns`) |
| `--freshness-threshold` | `2d` | skip addrs last-seen older than this (`0` = off) |
| `--no-record-addr-responses` | on | stop logging every `addr`/`addrv2` reply (recording is on by default) |
| `--ip/-tor/-i2p-concurrency` | 512/64/32 | workers per transport |
| `--result-path` | `results` | output directory |
| `--checkpoint-interval` | `10m` | re-write result files this often (`0` = off) |

Run `--help` for the full, sectioned list.

## Output

Each run writes into its own subdirectory of the result dir, named
`<timestamp>_v<version>` (the time the run started), containing:

- `reachable_nodes.csv` — connected + handshake completed, full metadata
- `handshake_failed_nodes.csv` — connected but handshake failed (has a `failure_reason` column)
- `unreachable_nodes.csv` — never connected (has a `failure_reason` column)
- `crawler_stats.json` — settings + crawl-wide counts and node lists, including
  `handshake_failed_reasons` / `unreachable_reasons` histograms
- `addr_responses.csv` — on by default; disable with `--no-record-addr-responses`
- `debug_log.txt` — optional, on by default

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
| handshake | `handshake_timeout` | peer stayed silent for the whole deadline |
| handshake | `connection_closed` | peer closed/reset mid-handshake (EOF) |
| handshake | `malformed_version` | peer's `version` did not parse |
| handshake | `protocol_desync` | bad magic/checksum or oversize payload |
| handshake | `handshake_other` | other handshake-phase error |

The snapshot files (`reachable`/`handshake_failed`/`unreachable`/`crawler_stats`)
are written when the crawl finishes, and also re-written every
`--checkpoint-interval` while it runs, so a crash or hard kill still leaves recent
output. Pressing **Ctrl+C** starts a graceful shutdown: in-flight nodes are
allowed to finish, then the final output is written. A **second Ctrl+C**
force-quits immediately without writing.
