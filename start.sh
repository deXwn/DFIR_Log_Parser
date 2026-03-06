#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVENT_DIR="${ROOT_DIR}/apps/EventLogParser"
LOG_DIR="${ROOT_DIR}/apps/Log_parser"
LANDING_DIR="${ROOT_DIR}/landing"

require_command() {
  local cmd="$1"
  local hint="$2"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "Error: required command not found: ${cmd}" >&2
    echo "Hint: ${hint}" >&2
    echo "Run: ${ROOT_DIR}/setup.sh" >&2
    exit 1
  fi
}

if [[ ! -d "${EVENT_DIR}" ]]; then
  echo "Error: EventLogParser directory not found: ${EVENT_DIR}" >&2
  exit 1
fi

if [[ ! -d "${LOG_DIR}" ]]; then
  echo "Error: Log_parser directory not found: ${LOG_DIR}" >&2
  exit 1
fi

mkdir -p "${ROOT_DIR}/logs"

EVENT_BACK_LOG="${EVENT_BACK_LOG:-${ROOT_DIR}/logs/event_backend.log}"
EVENT_FRONT_LOG="${EVENT_FRONT_LOG:-${ROOT_DIR}/logs/event_frontend.log}"
LOG_PARSER_LOG="${LOG_PARSER_LOG:-${ROOT_DIR}/logs/log_parser.log}"
LANDING_LOG="${LANDING_LOG:-${ROOT_DIR}/logs/landing.log}"

export EVTX_DB_PATH="${EVTX_DB_PATH:-events.db}"
export RUST_LOG="${RUST_LOG:-info}"
export NEXT_PUBLIC_API_BASE="${NEXT_PUBLIC_API_BASE:-http://localhost:8080}"
export BIND_ADDRESS="${BIND_ADDRESS:-0.0.0.0:8800}"
STARTUP_TIMEOUT_SECS="${STARTUP_TIMEOUT_SECS:-600}"
AUTO_KILL_PORTS="${AUTO_KILL_PORTS:-0}"

require_command "bash" "Install bash from your package manager."
require_command "curl" "Install curl from your package manager."
require_command "ss" "Install iproute2 (provides ss)."
require_command "cargo" "Install Rust toolchain (cargo + rustc)."
require_command "npm" "Install Node.js + npm."

PIDS=()
STARTED_PID=""
CLEANED_UP=0

start_process() {
  local name="$1"
  local cmd="$2"
  local log_file="$3"

  echo "[start] ${name} -> ${log_file}" >&2
  : > "${log_file}"
  bash -lc "${cmd}" >"${log_file}" 2>&1 &
  local pid=$!
  PIDS+=("${pid}")
  echo "[pid] ${name}: ${pid}" >&2
  STARTED_PID="${pid}"
}

wait_for_http() {
  local name="$1"
  local url="$2"
  local pid="$3"
  local log_file="$4"
  local waited=0

  echo "[wait] Waiting for ${name}: ${url}"
  while (( waited < STARTUP_TIMEOUT_SECS )); do
    if ! kill -0 "${pid}" 2>/dev/null; then
      echo "[error] ${name} process exited early. Last logs:"
      tail -n 120 "${log_file}" || true
      return 1
    fi
    if curl -fsS --max-time 2 "${url}" >/dev/null 2>&1; then
      echo "[ok] ${name} is ready."
      return 0
    fi
    sleep 2
    waited=$((waited + 2))
  done

  echo "[error] ${name} was not ready within ${STARTUP_TIMEOUT_SECS}s. Last logs:"
  tail -n 120 "${log_file}" || true
  return 1
}

listeners_on_port() {
  local port="$1"
  ss -ltnp 2>/dev/null \
    | awk -v p=":${port}" '
        index($0, p) {
          while (match($0, /pid=[0-9]+/)) {
            print substr($0, RSTART + 4, RLENGTH - 4)
            $0 = substr($0, RSTART + RLENGTH)
          }
        }
      ' \
    | sort -u \
    | tr '\n' ' '
}

ensure_port_available() {
  local port="$1"
  local name="$2"
  local pids
  pids="$(listeners_on_port "${port}")"

  if [[ -z "${pids// /}" ]]; then
    return 0
  fi

  if [[ "${AUTO_KILL_PORTS}" == "1" ]]; then
    echo "[warn] Port ${port} is busy for ${name}. Stopping existing processes: ${pids}"
    # shellcheck disable=SC2086
    kill ${pids} 2>/dev/null || true
    sleep 1
    pids="$(listeners_on_port "${port}")"
    if [[ -z "${pids// /}" ]]; then
      return 0
    fi
  fi

  echo "[error] Port ${port} is already in use for ${name}: ${pids}" >&2
  echo "Stop these processes and try again:" >&2
  # shellcheck disable=SC2086
  ps -fp ${pids} >&2 || true
  echo "Alternative: AUTO_KILL_PORTS=1 ./start.sh" >&2
  exit 1
}

prepare_event_frontend() {
  local web_dir="${EVENT_DIR}/web"
  if [[ ! -f "${web_dir}/package.json" ]]; then
    echo "Error: package.json not found: ${web_dir}" >&2
    exit 1
  fi

  if [[ ! -x "${web_dir}/node_modules/.bin/next" ]]; then
    echo "[prep] Installing Event frontend dependencies (npm ci)..."
    (
      cd "${web_dir}"
      npm ci
    )
  fi
}

cleanup() {
  if [[ "${CLEANED_UP}" == "1" ]]; then
    return
  fi
  CLEANED_UP=1

  echo
  echo "[stop] Stopping services..."
  for pid in "${PIDS[@]:-}"; do
    if kill -0 "${pid}" 2>/dev/null; then
      local children
      children="$(pgrep -P "${pid}" 2>/dev/null || true)"
      if [[ -n "${children}" ]]; then
        # shellcheck disable=SC2086
        kill ${children} 2>/dev/null || true
      fi
      kill "${pid}" 2>/dev/null || true
    fi
  done

  sleep 1

  for port in 3000 8080 8800 8899; do
    local port_pids
    port_pids="$(listeners_on_port "${port}")"
    if [[ -n "${port_pids// /}" ]]; then
      # shellcheck disable=SC2086
      kill ${port_pids} 2>/dev/null || true
    fi
  done
}

trap cleanup EXIT INT TERM

ensure_port_available 3000 "Event Parser UI"
ensure_port_available 8080 "Event API"
ensure_port_available 8800 "Log Parser API"
ensure_port_available 8899 "Landing Page"

prepare_event_frontend

start_process \
  "EventLogParser Backend (8080)" \
  "cd '${EVENT_DIR}' && exec cargo run --release" \
  "${EVENT_BACK_LOG}"
EVENT_BACK_PID="${STARTED_PID}"

start_process \
  "EventLogParser Frontend (3000)" \
  "cd '${EVENT_DIR}/web' && exec npm run dev -- --port 3000" \
  "${EVENT_FRONT_LOG}"
EVENT_FRONT_PID="${STARTED_PID}"

start_process \
  "Log Parser (8800)" \
  "cd '${LOG_DIR}' && exec cargo run --release" \
  "${LOG_PARSER_LOG}"
LOG_PARSER_PID="${STARTED_PID}"

if command -v python3 >/dev/null 2>&1; then
  LANDING_CMD="cd '${LANDING_DIR}' && exec python3 -m http.server 8899"
elif command -v python >/dev/null 2>&1; then
  LANDING_CMD="cd '${LANDING_DIR}' && exec python -m http.server 8899"
else
  echo "Error: python/python3 not found for landing page server." >&2
  exit 1
fi

start_process \
  "Landing Page (8899)" \
  "${LANDING_CMD}" \
  "${LANDING_LOG}"
LANDING_PID="${STARTED_PID}"

wait_for_http "Landing Page" "http://127.0.0.1:8899/" "${LANDING_PID}" "${LANDING_LOG}"
wait_for_http "Event API" "http://127.0.0.1:8080/" "${EVENT_BACK_PID}" "${EVENT_BACK_LOG}"
wait_for_http "Log Parser API" "http://127.0.0.1:8800/healthz" "${LOG_PARSER_PID}" "${LOG_PARSER_LOG}"
wait_for_http "Event Parser UI" "http://127.0.0.1:3000/" "${EVENT_FRONT_PID}" "${EVENT_FRONT_LOG}"

echo

echo "All services started."
echo "Landing         : http://localhost:8899"
echo "Event Parser UI : http://localhost:3000"
echo "Event API       : http://localhost:8080"
echo "Log Parser UI   : http://localhost:8800"
echo
echo "Log files:"
echo "- ${EVENT_BACK_LOG}"
echo "- ${EVENT_FRONT_LOG}"
echo "- ${LOG_PARSER_LOG}"
echo "- ${LANDING_LOG}"
echo
echo "To inspect logs on error:"
echo "tail -n 120 ${EVENT_BACK_LOG}"
echo "tail -n 120 ${EVENT_FRONT_LOG}"
echo "tail -n 120 ${LOG_PARSER_LOG}"
echo "tail -n 120 ${LANDING_LOG}"
echo
echo "Press Ctrl+C to stop."

wait
