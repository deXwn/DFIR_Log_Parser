# Event Log Parser & EVTX DFIR UI

Rust backend + Next.js frontend for high-speed Windows EVTX parsing, search, and DFIR reporting.

## Features
- Multi-threaded EVTX ingest with SQLite/FTS5 storage and WAL.
- REST API: ingest, events, search, timeline, stats, detections, custom reports.
- Frontend: ingest UI, event table, process tree, timeline, detections, and report builder with case file.
- Custom report generation (HTML/Markdown) from selected events and analyst notes.

## Quick Start
```bash
# backend + frontend together
./start.sh
# or run separately
EVTX_DB_PATH=events.db RUST_LOG=info cargo run --release
cd web && NEXT_PUBLIC_API_BASE=http://localhost:8080 npm run dev
```

- Running `./start.sh` prints the UI and API addresses in the console.

## Access URLs
- Frontend UI: `http://localhost:3000`
- Backend API: `http://localhost:8080` (example: `http://localhost:8080/events?limit=10`)
- API root check: `http://localhost:8080/` → `EventLogParser API is running. UI: http://localhost:3000`

## Troubleshooting
- Use `http://localhost:3000` in your browser for the UI.
- `http://localhost:8080` is the backend API port; the UI does not run on this port.
- Use `event_log` as the default ingest path (resolved relative to project root).
- If you get `path not found`, verify the absolute path; example valid path:
  `/absolute/path/to/EventLogParser/event_log`

## Cleaning Local Data
- Delete any local EVTX samples and generated databases before committing (e.g., `events.db`, `event_log/`, `*.evtx` test files).
- `target/`, `web/.next/`, and `web/node_modules/` are ignored by git.

## API Notes
- Custom report endpoints:
  - `POST /reports/custom` → Markdown.
  - `POST /reports/custom/html` → HTML (render/print to PDF in browser).
- Standard report: `POST /report`.
