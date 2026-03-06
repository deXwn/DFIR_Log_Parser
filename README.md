# DFIR Suite

Unified local workspace for two DFIR applications:

1. `Event Log Parser` (EVTX-focused workflow)
2. `Log Parser` (high-volume plain-text log workflow)

Both services can be started from a single launcher and accessed through a single landing page.

## Table Of Contents

1. Overview
2. Architecture
3. Repository Layout
4. Prerequisites
5. Quick Start
6. Runtime URLs
7. Configuration
8. Privacy And Data Hygiene
9. `.gitignore` Policy
10. Day-To-Day Workflow
11. Troubleshooting
12. Safe Sharing Checklist
13. Maintenance Commands

## Overview

This project is designed for local DFIR operations where analysts need:

- rapid startup,
- a predictable local environment,
- strict protection against accidental leakage of case data,
- and a single launch path for all components.

The suite includes:

- one launcher script: [`start.sh`](./start.sh)
- one landing UI: [`landing/index.html`](./landing/index.html)
- two app codebases inside `apps/`.

## Architecture

When you run `./start.sh`, the script starts four processes:

1. `EventLogParser backend` (Rust API, port `8080`)
2. `EventLogParser frontend` (Next.js, port `3000`)
3. `Log_parser backend + UI` (Rust/Axum, port `8800`)
4. `Landing page static server` (Python http.server, port `8899`)

Startup behavior:

- Performs port pre-checks (`3000`, `8080`, `8800`, `8899`)
- Waits for each endpoint to be healthy
- Prints `All services started.` only after all services are reachable
- On exit (`Ctrl+C`), attempts to clean all started child processes

## Repository Layout

```text
DFIR_suite/
  ├─ start.sh                  # Single launcher
  ├─ .gitignore                # Privacy-first ignore policy (suite scope)
  ├─ README.md                 # This document
  ├─ landing/
  │   └─ index.html            # Unified entry page
  ├─ logs/                     # Runtime logs (ignored)
  └─ apps/
      ├─ EventLogParser/       # EVTX parser app
      └─ Log_parser/           # Plain-text log parser app
```

## Prerequisites

Required:

- Linux shell (`bash`)
- Rust toolchain (`cargo`)
- Node.js + npm (for Event frontend)
- Python 3 (or Python) for landing static server
- `curl` (used by health checks in launcher)
- `ss` (from `iproute2`, used by port checks)

Optional but useful:

- `git`
- `rg` (ripgrep) for local searching

## Quick Start

From `DFIR_suite`:

```bash
./start.sh
```

If ports are already occupied and you want automatic cleanup:

```bash
AUTO_KILL_PORTS=1 ./start.sh
```

If first startup takes too long, increase timeout:

```bash
STARTUP_TIMEOUT_SECS=900 ./start.sh
```

## Runtime URLs

- Landing: `http://localhost:8899`
- Event Parser UI: `http://localhost:3000`
- Event Parser API: `http://localhost:8080`
- Log Parser UI/API: `http://localhost:8800`
- Log Parser health endpoint: `http://localhost:8800/healthz`

## Configuration

Key environment variables used by `start.sh`:

- `AUTO_KILL_PORTS`:
  - `0` (default) -> fail if a required port is busy
  - `1` -> stop existing listeners on required ports, then continue
- `STARTUP_TIMEOUT_SECS`:
  - startup readiness timeout window
- `RUST_LOG`:
  - Rust logging level (default `info`)
- `EVTX_DB_PATH`:
  - Event parser DB location (default `events.db`)
- `NEXT_PUBLIC_API_BASE`:
  - Event frontend API base URL (default `http://localhost:8080`)
- `BIND_ADDRESS`:
  - Log Parser bind address (default `0.0.0.0:8800`)

## Privacy And Data Hygiene

This repository is configured to avoid committing:

- investigation logs,
- SQLite databases,
- exported reports,
- raw incident evidence files (`.evtx`, `.pcap`, archives),
- local environment secrets (`.env`, keys/certs),
- and editor/system noise.

Primary controls:

1. root `.gitignore` (repository-wide safety net)
2. [`DFIR_suite/.gitignore`](./.gitignore) (suite-specific strict policy)

Important:

- `.gitignore` only affects untracked files.
- If a sensitive file was previously committed, remove it from index:

```bash
git rm --cached <path>
```

Then commit that removal.

## `.gitignore` Policy

Ignored categories include:

- runtime logs (`logs/`, `*.log`)
- databases (`*.db`, `*.sqlite`, sidecar files)
- exports and local evidence storage
- Node and Rust build artifacts
- case evidence formats (`.evtx`, `.pcap`, archives, dumps)
- secrets (`.env*`, private keys, cert bundles)
- OS/editor artifacts

Goal:

- no private machine paths,
- no investigation artifacts,
- no accidental credential leakage in commits.

## Day-To-Day Workflow

1. Start services:
```bash
./start.sh
```
2. Open landing page:
```text
http://localhost:8899
```
3. Choose parser based on dataset type:
  - EVTX -> Event Log Parser
  - Text logs -> Log Parser
4. Perform analysis/export locally.
5. Stop everything with `Ctrl+C`.

## Troubleshooting

### Ports already in use

Symptom:

- launcher exits with a port-in-use error

Fix:

```bash
AUTO_KILL_PORTS=1 ./start.sh
```

### One service fails during startup

Check the logs printed by launcher, or run:

```bash
tail -n 120 logs/event_backend.log
tail -n 120 logs/event_frontend.log
tail -n 120 logs/log_parser.log
tail -n 120 logs/landing.log
```

### Frontend dependency issue

From Event frontend directory:

```bash
cd apps/EventLogParser/web
npm ci
```

### Slow first startup

Expected behavior:

- first run compiles Rust binaries and installs Node dependencies

Mitigation:

- keep cache/toolchains installed
- increase timeout (`STARTUP_TIMEOUT_SECS`)

## Safe Sharing Checklist

Before pushing or sharing:

1. Run `git status --short` and inspect all staged/untracked entries.
2. Ensure no files from `logs/`, DBs, exports, evidence archives, or `.env*` are included.
3. Verify paths do not expose local usernames/hostnames.
4. If needed, remove any accidental staged sensitive file:
```bash
git restore --staged <path>
```
5. Re-check with `git status`.

## Maintenance Commands

Useful local cleanup commands:

```bash
# Remove suite runtime logs
rm -f logs/*.log

# Remove Event parser local DB artifacts
rm -f apps/EventLogParser/*.db apps/EventLogParser/*.db-* apps/EventLogParser/*.sqlite*

# Remove Log parser local DB artifacts
rm -f apps/Log_parser/*.sqlite apps/Log_parser/*.db apps/Log_parser/*.db-*

# Reinstall Event frontend dependencies
cd apps/EventLogParser/web && npm ci
```

---

If you want, the next step is adding a pre-commit hook that blocks commits containing
`*.db`, `*.log`, `*.env`, `.pem`, and evidence archive extensions even if accidentally staged.
