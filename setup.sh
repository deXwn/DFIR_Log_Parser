#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVENT_WEB_DIR="${ROOT_DIR}/apps/EventLogParser/web"
EVENT_DIR="${ROOT_DIR}/apps/EventLogParser"
LOG_DIR="${ROOT_DIR}/apps/Log_parser"

SUDO=""
PKG_MANAGER=""

info() {
  echo "[setup] $*"
}

warn() {
  echo "[setup][warn] $*" >&2
}

die() {
  echo "[setup][error] $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

require_sudo_if_needed() {
  if [[ "$(id -u)" -eq 0 ]]; then
    SUDO=""
    return
  fi

  if need_cmd sudo; then
    SUDO="sudo"
    return
  fi

  die "This script needs root privileges to install system packages. Install sudo or run as root."
}

detect_pkg_manager() {
  if need_cmd apt-get; then
    PKG_MANAGER="apt"
  elif need_cmd dnf; then
    PKG_MANAGER="dnf"
  elif need_cmd yum; then
    PKG_MANAGER="yum"
  elif need_cmd pacman; then
    PKG_MANAGER="pacman"
  elif need_cmd zypper; then
    PKG_MANAGER="zypper"
  else
    die "Unsupported Linux distribution (no apt, dnf, yum, pacman, zypper found)."
  fi
}

node_major_version() {
  if ! need_cmd node; then
    echo "0"
    return
  fi
  node -p "process.versions.node.split('.')[0]" 2>/dev/null || echo "0"
}

install_node_via_nodesource_apt() {
  info "Installing Node.js 20 LTS (NodeSource)..."
  ${SUDO} apt-get update -y
  ${SUDO} apt-get install -y ca-certificates curl gnupg
  curl -fsSL https://deb.nodesource.com/setup_20.x | ${SUDO} -E bash -
  ${SUDO} apt-get install -y nodejs
}

install_system_packages() {
  info "Detected package manager: ${PKG_MANAGER}"
  case "${PKG_MANAGER}" in
    apt)
      ${SUDO} apt-get update -y
      ${SUDO} apt-get install -y \
        curl ca-certificates git python3 iproute2 build-essential pkg-config
      if ! need_cmd node || [[ "$(node_major_version)" -lt 18 ]]; then
        install_node_via_nodesource_apt
      else
        ${SUDO} apt-get install -y npm || true
      fi
      ;;
    dnf)
      ${SUDO} dnf -y install \
        curl ca-certificates git python3 iproute \
        gcc gcc-c++ make pkgconf-pkg-config nodejs npm
      ;;
    yum)
      ${SUDO} yum -y install \
        curl ca-certificates git python3 iproute \
        gcc gcc-c++ make pkgconfig nodejs npm
      ;;
    pacman)
      ${SUDO} pacman -Sy --needed --noconfirm \
        curl ca-certificates git python iproute2 base-devel pkgconf nodejs npm
      ;;
    zypper)
      ${SUDO} zypper --non-interactive refresh
      ${SUDO} zypper --non-interactive install -y \
        curl ca-certificates git python3 iproute2 gcc gcc-c++ make pkg-config || true
      ${SUDO} zypper --non-interactive install -y nodejs20 npm20 \
        || ${SUDO} zypper --non-interactive install -y nodejs npm
      ;;
  esac
}

install_rust_toolchain() {
  if need_cmd cargo && need_cmd rustc; then
    info "Rust toolchain already installed."
    return
  fi

  info "Installing Rust toolchain with rustup..."
  curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal

  if [[ -f "${HOME}/.cargo/env" ]]; then
    # shellcheck disable=SC1090
    source "${HOME}/.cargo/env"
  fi

  export PATH="${HOME}/.cargo/bin:${PATH}"
}

verify_requirements() {
  local missing=()
  local cmd
  for cmd in bash curl ss cargo rustc node npm git; do
    if ! need_cmd "${cmd}"; then
      missing+=("${cmd}")
    fi
  done

  if ! need_cmd python3 && ! need_cmd python; then
    missing+=("python3/python")
  fi

  if [[ "${#missing[@]}" -gt 0 ]]; then
    die "Missing required tools after setup: ${missing[*]}"
  fi

  local node_major
  node_major="$(node_major_version)"
  if [[ "${node_major}" -lt 18 ]]; then
    die "Node.js >= 18 is required. Current version: $(node -v)"
  fi
}

install_project_dependencies() {
  if [[ ! -f "${EVENT_WEB_DIR}/package.json" ]]; then
    die "Event frontend package.json not found: ${EVENT_WEB_DIR}/package.json"
  fi

  info "Installing Event frontend npm dependencies..."
  (
    cd "${EVENT_WEB_DIR}"
    npm ci
  )

  info "Fetching Rust dependencies for EventLogParser..."
  (
    cd "${EVENT_DIR}"
    cargo fetch
  )

  info "Fetching Rust dependencies for Log_parser..."
  (
    cd "${LOG_DIR}"
    cargo fetch
  )
}

print_summary() {
  local py_version
  if need_cmd python3; then
    py_version="$(python3 --version)"
  else
    py_version="$(python --version)"
  fi

  echo
  info "Setup completed successfully."
  echo "Versions:"
  echo "- rustc:  $(rustc --version)"
  echo "- cargo:  $(cargo --version)"
  echo "- node:   $(node --version)"
  echo "- npm:    $(npm --version)"
  echo "- python: ${py_version}"
  echo
  echo "Next steps:"
  echo "1) cd ${ROOT_DIR}"
  echo "2) ./start.sh"
}

main() {
  info "Starting DFIR Suite setup..."
  require_sudo_if_needed
  detect_pkg_manager
  install_system_packages
  install_rust_toolchain
  verify_requirements
  install_project_dependencies
  print_summary
}

main "$@"
