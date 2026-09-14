# naabu-tools

Random **public IP** generation + **open port scanning** powered by [naabu](https://github.com/projectdiscovery/naabu).

Three front-ends, one engine — all built in Rust, all stream scan results live and exclude reserved/private ranges (RFC 1918, loopback, CGNAT, link-local, multicast, etc.) from randomly generated targets.

| Component | Directory | What it is |
|---|---|---|
| `gui` | `gui/` | Native desktop app (egui/eframe) |
| `web` | `web/` | Web dashboard (axum + vanilla JS) |
| `cli` | `cli/` | Terminal app (clap) |

> **⚠ Authorized use only.** Port scanning other people's infrastructure without permission is illegal in most jurisdictions. Only scan hosts you own or have explicit authorization to test.

## Requirements

- [Rust](https://rustup.rs/) toolchain
- [naabu](https://github.com/projectdiscovery/naabu) on `PATH` — install with `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` (or via your package manager)

## CLI

```bash
cd cli
cargo build --release
./target/release/naabu-cli --help
```

Results go to **stdout** (pipe-friendly, one `ip:port  service` per line); status and progress go to stderr.

```bash
# 10 random public IPs
naabu-cli gen --count 10

# expand a CIDR
naabu-cli cidr 8.8.8.0/30

# scan 25 random public IPs on common web ports (live streaming)
naabu-cli scan --count 25 --ports 80,443,8080,8443

# scan explicit targets (comma list or @file)
naabu-cli scan --ips 1.2.3.4,5.6.7.8
naabu-cli scan --ips @targets.txt

# pipe a list in
cat targets.txt | naabu-cli scan --stdin --top-ports 100

# write results to a file (txt / csv / json)
naabu-cli scan --count 100 --output results.csv --format csv

# tune the scan
naabu-cli scan --count 50 --rate 2000 --threads 100 --timeout 3000 \
  --scan-type connect --verify
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--count N` | — | Generate N random public IPs as targets |
| `--ips LIST` / `@file` | — | Explicit targets |
| `--cidr x.x.x.x/xx` | — | Expand a CIDR as targets |
| `--stdin` | — | Read targets from stdin |
| `--ports P` | `80,443,8080,8443,22,21,25,53,110,143,993,995,3306,5432,6379,8000,8888,9090` | Ports to scan |
| `--top-ports N` | none | Scan naabu's top N ports instead |
| `--rate N` | `500` | Packets per second |
| `--threads N` | `25` | Concurrent threads |
| `--timeout MS` | `5000` | Per-port timeout |
| `--scan-type X` | `connect` | `connect` \| `syn` \| `auto` |
| `--verify` | off | Probe open ports to confirm |
| `--output FILE` | none | Write results to file |
| `--format X` | `txt` | `txt` \| `csv` \| `json` (with `--output`) |

## Web

```bash
cd web
cargo build --release
./target/release/naabu-web            # serves http://127.0.0.1:8080
PORT=9000 ./target/release/naabu-web  # custom port
```

Open http://127.0.0.1:8080. The dashboard has an IP generator (random + CIDR expand), scan settings with port presets, live result streaming (polled every ~1.2s), IP/service filtering, export (txt/csv/json), and a scan history panel.

### API

| Method | Path | Description |
|---|---|---|
| GET | `/` | Redirects to the UI |
| GET | `/api/naabu/check` | Is the `naabu` binary available? |
| GET | `/api/ipgen/random?count=N` | N random public IPs |
| POST | `/api/ipgen/cidr` | Expand `{"text": "8.8.8.0/30"}` |
| POST | `/api/ipgen/parse` | Parse a list of IPs/CIDRs |
| POST | `/api/scans` | Start a scan `{"ips": [...], "settings": {...}}` |
| GET | `/api/scans` | Job history |
| GET | `/api/scans/{id}` | Job detail (poll this for live results) |
| DELETE | `/api/scans/{id}` | Remove a job |
| GET | `/api/scans/{id}/export?format=txt|csv|json` | Download results |

Scan settings: `port_range`, `rate_limit`, `threads`, `timeout`, `scan_type` (`connect`/`syn`/`auto`), `verify`, `use_top_ports`, `top_ports_count`.

## GUI

```bash
cd gui
cargo build --release
./target/release/naabu-gui
```

Progress is streamed live while naabu runs (no waiting for the scan to finish), results appear in a filterable table, and scans can be exported to CSV. The IP generator and port presets mirror the CLI/web tools.

## How the IP generator works

`ipgen` picks candidate IPs in `1.0.0.0/8` – `223.255.255.0/8` and rejects anything inside the reserved ranges (private, loopback, CGNAT `100.64.0.0/10`, link-local, documentation ranges, multicast, broadcast). The same code lives in all three tools so behavior is identical.