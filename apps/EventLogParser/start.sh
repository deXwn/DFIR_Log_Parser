#!/usr/bin/env bash
set -euo pipefail

# Combined launcher for backend + frontend
# Uses defaults but allows overrides via environment.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACK_LOG="${BACK_LOG:-/tmp/evtx-backend.log}"
FRONT_LOG="${FRONT_LOG:-/tmp/evtx-frontend.log}"

export EVTX_DB_PATH="${EVTX_DB_PATH:-events.db}"
export RUST_LOG="${RUST_LOG:-info}"
export NEXT_PUBLIC_API_BASE="${NEXT_PUBLIC_API_BASE:-http://localhost:8080}"

echo "Starting backend (cargo run --release) -> ${BACK_LOG}"
(
  cd "$ROOT_DIR"
  cargo run --release
) >"$BACK_LOG" 2>&1 &
BACK_PID=$!

echo "Starting frontend (npm run dev) -> ${FRONT_LOG}"
(
  cd "$ROOT_DIR/web"
  npm run dev
) >"$FRONT_LOG" 2>&1 &
FRONT_PID=$!

cleanup() {
  echo "Stopping processes..."
  kill "$BACK_PID" "$FRONT_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "Backend PID: $BACK_PID"
echo "Frontend PID: $FRONT_PID"
echo "Logs: backend=$BACK_LOG frontend=$FRONT_LOG"
echo "Frontend UI: http://localhost:3000"
echo "Backend API: http://localhost:8080 (example: /events?limit=10)"
echo "Press Ctrl+C to stop."

wait
