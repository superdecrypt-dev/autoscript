#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd -P)"
EDGE_DIST_DIR="${ROOT_DIR}/opt/edge/dist"

log() {
  printf '[test-edge-dist] %s\n' "$*"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

assert_binary_strings() {
  local file="$1"
  shift
  local pattern="$1"
  if strings "${file}" | rg -n "${pattern}" >/dev/null; then
    printf '[test-edge-dist] FAIL: legacy marker matched in %s: %s\n' "${file}" "${pattern}" >&2
    return 1
  fi
}

assert_binary_contains() {
  local file="$1"
  shift
  local pattern="$1"
  if ! strings "${file}" | rg -n "${pattern}" >/dev/null; then
    printf '[test-edge-dist] FAIL: expected marker missing in %s: %s\n' "${file}" "${pattern}" >&2
    return 1
  fi
}

assert_binary_present() {
  local file="$1"
  [[ -s "${file}" ]] || {
    printf '[test-edge-dist] FAIL: missing binary %s\n' "${file}" >&2
    return 1
  }
}

main() {
  local -a targets=(
    "${EDGE_DIST_DIR}/edge-mux-linux-amd64"
    "${EDGE_DIST_DIR}/edge-mux-linux-arm64"
  )
  local file

  need_cmd strings || {
    printf '[test-edge-dist] FAIL: strings command not found\n' >&2
    exit 1
  }
  need_cmd rg || {
    printf '[test-edge-dist] FAIL: rg command not found\n' >&2
    exit 1
  }

  for file in "${targets[@]}"; do
    assert_binary_present "${file}"
    assert_binary_contains "${file}" 'EDGE_XRAY_VMESS_RAW_BACKEND'
    assert_binary_contains "${file}" 'default@vmess-tcp'
    assert_binary_contains "${file}" 'vmess-tcp'
    assert_binary_contains "${file}" 'vmess_fallback_timeout'
    assert_binary_contains "${file}" 'vmess_fallback_unknown'
    assert_binary_contains "${file}" 'ssh-direct-timeout'
    assert_binary_contains "${file}" 'ssh-direct-unknown'
    assert_binary_contains "${file}" 'tls-port:ssh-direct-timeout'
    assert_binary_contains "${file}" 'http-port:ssh-direct-unknown'
    assert_binary_contains "${file}" 'EDGE_SSH_QUOTA_ROOT'
    assert_binary_contains "${file}" 'EDGE_SSH_MANAGE_BIN'
    assert_binary_contains "${file}" '__sync-ssh-network-session-targets'
    assert_binary_contains "${file}" 'edge-mux quota resolve empty'
    assert_binary_contains "${file}" 'edge-mux quota updated user='
    assert_binary_contains "${file}" 'edge-mux quota enforcer failed'
    assert_binary_contains "${file}" 'edge-mux session write failed'
    assert_binary_contains "${file}" 'edge-mux speed policy load failed'
    assert_binary_strings "${file}" 'EDGE_XRAY_QUOTA_ROOT'
    assert_binary_strings "${file}" 'EDGE_XRAY_QAC_ENFORCER'
    assert_binary_strings "${file}" 'EDGE_XRAY_MANAGE_BIN'
    assert_binary_strings "${file}" 'EDGE_XRAY_SESSION_ROOT'
    assert_binary_strings "${file}" 'xray-edge-sessions'
    log "validated ${file}"
  done
}

main "$@"
