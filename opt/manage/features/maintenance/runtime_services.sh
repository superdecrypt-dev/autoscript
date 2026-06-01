#!/usr/bin/env bash
# shellcheck shell=bash

ssh_runtime_context_run() {
  local ctx="${1:-}"
  shift || true
  local prev="${SSH_RUNTIME_MENU_CONTEXT:-}"
  SSH_RUNTIME_MENU_CONTEXT="${ctx}"
  "$@"
  local rc=$?
  SSH_RUNTIME_MENU_CONTEXT="${prev}"
  return "${rc}"
}

ssh_runtime_menu_title() {
  local suffix="${1:-}"
  local base="11) Maintenance"
  case "${SSH_RUNTIME_MENU_CONTEXT:-}" in
    ssh-users) base="2) SSH Users" ;;
    ssh-network) base="6) SSH Network" ;;
    maintenance|"") base="11) Maintenance" ;;
  esac
  if [[ -n "${suffix}" ]]; then
    printf '%s > %s\n' "${base}" "${suffix}"
  else
    printf '%s\n' "${base}"
  fi
}

sshws_runtime_env_file() {
  printf '%s\n' "${SSHWS_RUNTIME_ENV_FILE:-/etc/default/sshws-runtime}"
}

sshws_runtime_env_value() {
  local key="${1:-}"
  local default_value="${2:-}"
  local env_file
  env_file="$(sshws_runtime_env_file)"
  [[ -n "${key}" ]] || {
    printf '%s\n' "${default_value}"
    return 0
  }
  if [[ -r "${env_file}" ]]; then
    local value
    value="$(awk -F= -v k="${key}" '$1==k {print substr($0, index($0, "=")+1); exit}' "${env_file}" | tr -d '\r' || true)"
    if [[ -n "${value}" ]]; then
      printf '%s\n' "${value}"
      return 0
    fi
  fi
  printf '%s\n' "${default_value}"
}

sshws_status_menu() {
  title
  if [[ "${SSH_RUNTIME_MENU_CONTEXT:-}" == "ssh-network" ]]; then
    echo "$(ssh_runtime_menu_title "Status")"
  else
    echo "$(ssh_runtime_menu_title "SSH WS Status")"
  fi
  hr

  local services=("${SSHWS_DROPBEAR_SERVICE}" "${SSHWS_STUNNEL_SERVICE}" "${SSHWS_PROXY_SERVICE}")
  local svc
  for svc in "${services[@]}"; do
    if svc_exists "${svc}"; then
      svc_status_line "${svc}"
    else
      warn "${svc}.service tidak terpasang"
    fi
  done

  hr
  if have_cmd ss; then
    if ss -lntp 2>/dev/null | grep -Eq '(^|[[:space:]])[^[:space:]]*:80([[:space:]]|$)'; then
      log "Port 80   : LISTENING ✅"
    else
      warn "Port 80   : NOT listening ❌"
    fi
    if ss -lntp 2>/dev/null | grep -Eq '(^|[[:space:]])[^[:space:]]*:443([[:space:]]|$)'; then
      log "Port 443  : LISTENING ✅"
    else
      warn "Port 443  : NOT listening ❌"
    fi
  else
    warn "ss tidak tersedia, skip cek port 80/443"
  fi

  hr
  local dropbear_port stunnel_port proxy_port
  local runtime_env runtime_stale_sec runtime_handshake_timeout
  dropbear_port="$(sshws_detect_dropbear_port)"
  stunnel_port="$(sshws_detect_stunnel_port)"
  proxy_port="$(sshws_detect_proxy_port)"
  runtime_env="$(sshws_runtime_env_file)"
  runtime_stale_sec="$(sshws_runtime_env_value "SSHWS_RUNTIME_SESSION_STALE_SEC" "90")"
  runtime_handshake_timeout="$(sshws_runtime_env_value "SSHWS_HANDSHAKE_TIMEOUT_SEC" "10")"
  echo "Internal ports (detected):"
  echo "  - dropbear local : 127.0.0.1:${dropbear_port}"
  echo "  - stunnel local  : 127.0.0.1:${stunnel_port}"
  echo "  - ws proxy local : 127.0.0.1:${proxy_port}"
  echo "Runtime env:"
  echo "  - env file       : ${runtime_env}"
  echo "  - stale sec      : ${runtime_stale_sec}"
  echo "  - handshake sec  : ${runtime_handshake_timeout}"
  hr
  pause
}

sshws_post_restart_health_check() {
  local dropbear_svc="${SSHWS_DROPBEAR_SERVICE}"
  local stunnel_svc="${SSHWS_STUNNEL_SERVICE}"
  local proxy_svc="${SSHWS_PROXY_SERVICE}"
  local -a failed=()
  local dropbear_port stunnel_port proxy_port dropbear_probe proxy_probe stunnel_probe

  dropbear_port="$(sshws_detect_dropbear_port)"
  stunnel_port="$(sshws_detect_stunnel_port)"
  proxy_port="$(sshws_detect_proxy_port)"
  if have_cmd ss; then
    if (svc_exists "${proxy_svc}" || svc_exists "${stunnel_svc}") && ! ss -lntp 2>/dev/null | grep -Eq '(^|[[:space:]])[^[:space:]]*:80([[:space:]]|$)'; then
      warn "Port 80 belum listening setelah restart SSH WS."
      failed+=("port-80")
    fi
    if (svc_exists "${proxy_svc}" || svc_exists "${stunnel_svc}") && ! ss -lntp 2>/dev/null | grep -Eq '(^|[[:space:]])[^[:space:]]*:443([[:space:]]|$)'; then
      warn "Port 443 belum listening setelah restart SSH WS."
      failed+=("port-443")
    fi
  fi
  if svc_exists "${dropbear_svc}"; then
    dropbear_probe="$(sshws_probe_tcp_endpoint "127.0.0.1" "${dropbear_port}" "tcp")"
    if ! sshws_probe_result_is_healthy "${dropbear_probe}"; then
      warn "Probe dropbear local gagal setelah restart SSH WS: $(sshws_probe_result_disp "${dropbear_probe}")"
      failed+=("dropbear")
    fi
  fi
  if svc_exists "${proxy_svc}"; then
    proxy_probe="$(sshws_probe_ws_endpoint "127.0.0.1" "${proxy_port}" "$(sshws_probe_path_pick)" "127.0.0.1:${proxy_port}" "off" "")"
    if ! sshws_probe_result_is_healthy "${proxy_probe}"; then
      warn "Probe ws proxy local gagal setelah restart SSH WS: $(sshws_probe_result_disp "${proxy_probe}")"
      failed+=("ws-proxy")
    fi
  fi
  if svc_exists "${stunnel_svc}"; then
    stunnel_probe="$(sshws_probe_tcp_endpoint "127.0.0.1" "${stunnel_port}" "tls")"
    if ! sshws_probe_result_is_healthy "${stunnel_probe}"; then
      warn "Probe stunnel local gagal setelah restart SSH WS: $(sshws_probe_result_disp "${stunnel_probe}")"
      failed+=("stunnel")
    fi
  fi
  if (( ${#failed[@]} > 0 )); then
    warn "Verifikasi pasca-restart SSH WS belum sehat: ${failed[*]}"
    return 1
  fi
  return 0
}

sshws_restart_services_checked() {
  local services=("$@")
  local svc restarted="false"
  local -a failed=()

  for svc in "${services[@]}"; do
    [[ -n "${svc}" ]] || continue
    if svc_exists "${svc}"; then
      if svc_restart_checked "${svc}" 60; then
        restarted="true"
      else
        failed+=("${svc}")
      fi
    else
      warn "${svc}.service tidak terpasang"
    fi
  done

  if [[ "${restarted}" != "true" ]]; then
    warn "Tidak ada service SSH WS yang bisa direstart."
    return 1
  fi
  if (( ${#failed[@]} > 0 )); then
    warn "Gagal restart service SSH WS: ${failed[*]}"
    return 1
  fi
  sshws_post_restart_health_check || return 1
  return 0
}

sshws_restart_menu() {
  title
  if [[ "${SSH_RUNTIME_MENU_CONTEXT:-}" == "ssh-network" ]]; then
    echo "$(ssh_runtime_menu_title "Restart SSH Transport")"
  else
    echo "$(ssh_runtime_menu_title "Restart SSH WS")"
  fi
  hr

  local confirm_rc=0
  confirm_yn_or_back "Restart semua service SSH WS sekarang?"
  confirm_rc=$?
  if (( confirm_rc != 0 )); then
    if (( confirm_rc == 2 )); then
      warn "Restart SSH WS dibatalkan (kembali)."
    else
      warn "Restart SSH WS dibatalkan."
    fi
    hr
    pause
    return 0
  fi

  if ! sshws_restart_services_checked "${SSHWS_DROPBEAR_SERVICE}" "${SSHWS_STUNNEL_SERVICE}" "${SSHWS_PROXY_SERVICE}"; then
    warn "Restart SSH WS gagal."
  fi
  hr
  pause
}

sshws_probe_tcp_endpoint() {
  # args: host port mode(tcp|tls)
  local host="${1:-127.0.0.1}"
  local port="${2:-0}"
  local mode="${3:-tcp}"
  need_python3
  python3 - <<'PY' "${host}" "${port}" "${mode}" 2>/dev/null || true
import socket
import ssl
import sys
import base64
import os

host, port_s, mode = sys.argv[1:4]
try:
  port = int(port_s)
except Exception:
  print("fail|invalid-port")
  raise SystemExit(0)

timeout = 2.0
sock = None
try:
  raw = socket.create_connection((host, port), timeout=timeout)
  if mode == "tls":
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = ctx.wrap_socket(raw, server_hostname=host or "localhost")
  else:
    sock = raw
  print("ok|connected")
except Exception as exc:
  msg = str(exc).strip().replace("\n", " ")
  print("fail|" + (msg or exc.__class__.__name__.lower()))
finally:
  try:
    if sock is not None:
      sock.close()
  except Exception:
    pass
PY
}

sshws_probe_ws_endpoint() {
  # args: host port path host_header tls_mode sni
  local host="${1:-127.0.0.1}"
  local port="${2:-0}"
  local path="${3:-/}"
  local host_header="${4:-127.0.0.1}"
  local tls_mode="${5:-off}"
  local sni="${6:-}"
  need_python3
  python3 - <<'PY' "${host}" "${port}" "${path}" "${host_header}" "${tls_mode}" "${sni}" 2>/dev/null || true
import base64
import os
import socket
import ssl
import sys

host, port_s, path, host_header, tls_mode, sni = sys.argv[1:7]
try:
  port = int(port_s)
except Exception:
  print("fail|invalid-port")
  raise SystemExit(0)

raw = None
sock = None
try:
  raw = socket.create_connection((host, port), timeout=3.0)
  raw.settimeout(3.0)
  if tls_mode == "on":
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = ctx.wrap_socket(raw, server_hostname=sni or host or "localhost")
  else:
    sock = raw
  req = (
    f"GET {path or '/'} HTTP/1.1\r\n"
    f"Host: {host_header or host}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    f"Sec-WebSocket-Key: {base64.b64encode(os.urandom(16)).decode()}\r\n"
    "User-Agent: autoscript-manage/sshws-diagnostics\r\n"
    "\r\n"
  ).encode("ascii", "ignore")
  sock.sendall(req)
  buf = b""
  while b"\r\n\r\n" not in buf and len(buf) < 16384:
    chunk = sock.recv(4096)
    if not chunk:
      break
    buf += chunk
  if not buf:
    print("fail|empty-response")
    raise SystemExit(0)
  line = buf.split(b"\r\n", 1)[0].decode("latin1", "replace").strip()
  parts = line.split(None, 2)
  if len(parts) >= 2 and parts[1].isdigit():
    code = int(parts[1])
    reason = parts[2] if len(parts) >= 3 else ""
    print(f"http|{code}|{reason}")
  else:
    print("fail|" + (line or "bad-response"))
except Exception as exc:
  msg = str(exc).strip().replace("\n", " ")
  print("fail|" + (msg or exc.__class__.__name__.lower()))
finally:
  try:
    if sock is not None:
      sock.close()
  except Exception:
    pass
  try:
    if raw is not None and raw is not sock:
      raw.close()
  except Exception:
    pass
PY
}

sshws_probe_result_disp() {
  local raw="${1:-}"
  local kind part1 part2
  IFS='|' read -r kind part1 part2 <<<"${raw}"
  case "${kind}" in
    ok)
      echo "OK (${part1:-connected})"
      ;;
    http)
      case "${part1:-0}" in
        101) echo "OK (HTTP 101 ${part2:-})" ;;
        301|302|307|308) echo "WARN (HTTP ${part1} ${part2:-redirect})" ;;
        401|403) echo "WARN (HTTP ${part1} ${part2:-probe-rejected})" ;;
        *) echo "FAIL (HTTP ${part1:-0} ${part2:-})" ;;
      esac
      ;;
    fail)
      echo "FAIL (${part1:-unknown})"
      ;;
    *)
      echo "FAIL (unknown)"
      ;;
  esac
}

sshws_probe_result_is_healthy() {
  local raw="${1:-}"
  local kind part1
  IFS='|' read -r kind part1 _ <<<"${raw}"
  case "${kind}" in
    ok) return 0 ;;
    http)
      case "${part1:-0}" in
        101|301|302|307|308) return 0 ;;
      esac
      ;;
  esac
  return 1
}

sshws_combined_logs_menu() {
  title
  if [[ "${SSH_RUNTIME_MENU_CONTEXT:-}" == "ssh-network" ]]; then
    echo "$(ssh_runtime_menu_title "Combined Logs")"
  else
    echo "$(ssh_runtime_menu_title "SSH WS Combined Logs")"
  fi
  hr

  local -a svc_args=()
  local svc
  for svc in "${SSHWS_DROPBEAR_SERVICE}" "${SSHWS_STUNNEL_SERVICE}" "${SSHWS_PROXY_SERVICE}"; do
    if svc_exists "${svc}"; then
      svc_args+=(-u "${svc}")
    fi
  done

  if (( ${#svc_args[@]} == 0 )); then
    warn "Belum ada service SSH WS yang terpasang."
    hr
    pause
    return 0
  fi

  journalctl "${svc_args[@]}" --no-pager -n 120 2>/dev/null || true
  hr
  pause
}

sshws_diagnostics_menu() {
  local choice=""
  while true; do
    title
    if [[ "${SSH_RUNTIME_MENU_CONTEXT:-}" == "ssh-network" ]]; then
      echo "$(ssh_runtime_menu_title "Diagnostics")"
    else
      echo "$(ssh_runtime_menu_title "SSH WS Diagnostics")"
    fi
    hr

    local dropbear_port stunnel_port proxy_port domain probe_path
    local proxy_probe tls443_probe http80_probe dropbear_probe stunnel_probe
    dropbear_port="$(sshws_detect_dropbear_port)"
    stunnel_port="$(sshws_detect_stunnel_port)"
    proxy_port="$(sshws_detect_proxy_port)"
    domain="$(detect_domain)"
    probe_path="$(sshws_probe_path_pick)"

    echo "Services:"
    if svc_exists "${SSHWS_DROPBEAR_SERVICE}"; then
      printf "  %-16s : %s\n" "${SSHWS_DROPBEAR_SERVICE}" "$(svc_status_line "${SSHWS_DROPBEAR_SERVICE}")"
    else
      printf "  %-16s : %s\n" "${SSHWS_DROPBEAR_SERVICE}" "NOT INSTALLED"
    fi
    if svc_exists "${SSHWS_STUNNEL_SERVICE}"; then
      printf "  %-16s : %s\n" "${SSHWS_STUNNEL_SERVICE}" "$(svc_status_line "${SSHWS_STUNNEL_SERVICE}")"
    else
      printf "  %-16s : %s\n" "${SSHWS_STUNNEL_SERVICE}" "OPTIONAL / NOT INSTALLED"
    fi
    if svc_exists "${SSHWS_PROXY_SERVICE}"; then
      printf "  %-16s : %s\n" "${SSHWS_PROXY_SERVICE}" "$(svc_status_line "${SSHWS_PROXY_SERVICE}")"
    else
      printf "  %-16s : %s\n" "${SSHWS_PROXY_SERVICE}" "NOT INSTALLED"
    fi

    hr
    echo "Internal Ports:"
    printf "  %-16s : 127.0.0.1:%s\n" "dropbear" "${dropbear_port}"
    printf "  %-16s : 127.0.0.1:%s\n" "stunnel" "${stunnel_port}"
    printf "  %-16s : 127.0.0.1:%s\n" "ws proxy" "${proxy_port}"
    printf "  %-16s : %s\n" "domain" "${domain:-"-"}"
    printf "  %-16s : %s\n" "probe path" "${probe_path}"

    hr
    echo "Local Probes:"
    dropbear_probe="$(sshws_probe_tcp_endpoint "127.0.0.1" "${dropbear_port}" "tcp")"
    printf "  %-16s : %s\n" "dropbear tcp" "$(sshws_probe_result_disp "${dropbear_probe}")"

    proxy_probe="$(sshws_probe_ws_endpoint "127.0.0.1" "${proxy_port}" "${probe_path}" "127.0.0.1:${proxy_port}" "off" "")"
    printf "  %-16s : %s\n" "proxy ws" "$(sshws_probe_result_disp "${proxy_probe}")"

    if svc_exists "${SSHWS_STUNNEL_SERVICE}"; then
      stunnel_probe="$(sshws_probe_tcp_endpoint "127.0.0.1" "${stunnel_port}" "tls")"
      printf "  %-16s : %s\n" "stunnel tls" "$(sshws_probe_result_disp "${stunnel_probe}")"
    else
      printf "  %-16s : %s\n" "stunnel tls" "SKIP (optional)"
    fi

    hr
    echo "Public Path Probes:"
    if have_cmd ss && ss -lntp 2>/dev/null | grep -Eq '(^|[[:space:]])[^[:space:]]*:80([[:space:]]|$)'; then
      http80_probe="$(sshws_probe_ws_endpoint "127.0.0.1" "80" "${probe_path}" "${domain:-127.0.0.1}" "off" "")"
      printf "  %-16s : %s\n" "nginx :80" "$(sshws_probe_result_disp "${http80_probe}")"
    else
      printf "  %-16s : %s\n" "nginx :80" "SKIP (not listening)"
    fi
    if [[ -n "${domain}" ]] && have_cmd ss && ss -lntp 2>/dev/null | grep -Eq '(^|[[:space:]])[^[:space:]]*:443([[:space:]]|$)'; then
      tls443_probe="$(sshws_probe_ws_endpoint "127.0.0.1" "443" "${probe_path}" "${domain}" "on" "${domain}")"
      printf "  %-16s : %s\n" "nginx :443" "$(sshws_probe_result_disp "${tls443_probe}")"
    else
      printf "  %-16s : %s\n" "nginx :443" "SKIP (domain/443 unavailable)"
    fi

    hr
    echo "Notes:"
    echo "  - HTTP 101 menandakan chain SSH WS sehat, termasuk probe path sintetis."
    echo "  - HTTP 502 biasanya berarti backend internal belum siap."
    echo "  - HTTP 301/308 pada port 80 normal jika force-HTTPS aktif."
    echo "  - HTTP 401/403 berarti probe sintetis mencapai gateway tetapi ditolak auth/path."
    hr
    echo "  1) Refresh"
    echo "  2) Combined SSH WS Logs"
    echo "  0) Back"
    hr
    if ! read -r -p "Pilih: " choice; then
      echo
      return 0
    fi
    case "${choice}" in
      1|refresh|r) ;;
      2|logs|log) sshws_combined_logs_menu ;;
      0|kembali|k|back|b) return 0 ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}
