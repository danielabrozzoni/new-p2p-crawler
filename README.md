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
| `--record-addr-responses` | off | log every `addr`/`addrv2` reply |
| `--ip/-tor/-i2p-concurrency` | 512/64/32 | workers per transport |
| `--result-path` | `results` | output directory |

Run `--help` for the full, sectioned list.

## Output

Written to the result dir, prefixed `<timestamp>_v<version>_`:

- `reachable_nodes.csv` — connected + handshake completed, full metadata
- `handshake_failed_nodes.csv` — connected but no `version`
- `unreachable_nodes.csv` — never connected
- `crawler_stats.json` — settings + crawl-wide counts and node lists
- `addr_responses.csv` — optional, `--record-addr-responses`
- `debug_log.txt` — optional, on by default
