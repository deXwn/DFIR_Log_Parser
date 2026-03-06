# DFIR Log Parser

A Rust + Axum DFIR service for high-volume plain-text log analysis.
It provides a web UI, APIs, rule-based detections, SQLite persistence,
CSV export, and IP summary workflows.

## Features

- Parallel log scanning with Rayon.
- Search filters:
  - include terms / exclude terms
  - status code
  - private/public IP scope
  - minimum `bytes_received`
  - sorting by `bytes_received`
- Streamed CSV export (no large in-memory accumulation).
- Parsed fields from each line:
  - timestamp
  - source IP
  - destination IP
  - status
  - bytes received
- Rule engine:
  - regex
  - field operators (`eq/ne/gt/gte/lt/lte/contains`)
  - threshold + time window
  - grouping (`global/src_ip/dst_ip/status`)
- Detection persistence in SQLite:
  - rules
  - detection runs
  - detection hits
  - false-positive labeling
- Cursor-based pagination for large detection result sets.
- Export directory fallback:
  - primary `exports/`
  - fallback `exports_local/` when needed

## Run

```bash
cargo run --release
```

UI:

```text
http://localhost:8800
```

Default bind address: `0.0.0.0:8800`

To change address/port:

```bash
BIND_ADDRESS=127.0.0.1:9000 cargo run
```

## Key Folders

- `log/`: sample logs to analyze.
- `exports/`: preferred export output location.
- `exports_local/`: fallback export location.
- `detections.sqlite`: detection data storage.

## Main APIs

- `POST /search`
- `POST /ip_summary`
- `POST /context`
- `POST /detections/run`
- `GET /detections/rules`
- `POST /detections/rules`
- `GET /detections/hits?page_size=20&sort_order=desc&cursor=...&run_id=...`
- `POST /detections/hits/:id/false_positive`

## Development

Run tests:

```bash
cargo test
```

Compile check:

```bash
cargo check
```
