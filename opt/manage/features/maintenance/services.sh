#!/usr/bin/env bash
# shellcheck shell=bash

# -------------------------
# Wireproxy helpers
# -------------------------
wireproxy_status_menu() {
  title
  echo "11) Maintenance > WARP Status"
  hr

  if ! svc_exists wireproxy; then
    warn "wireproxy.service tidak ditemukan. Pastikan setup.sh sudah dijalankan."
    hr
    pause
    return 0
  fi

  # Status service
  if svc_is_active wireproxy; then
    log "wireproxy : active ✅"
  else
    warn "wireproxy : INACTIVE ❌"
  fi

  # PID & uptime (best-effort)
  local pid uptime_str
  pid="$(systemctl show -p MainPID --value wireproxy 2>/dev/null || true)"
  if [[ -n "${pid}" && "${pid}" != "0" ]]; then
    log "PID       : ${pid}"
    uptime_str="$(process_uptime_pretty "${pid}" || true)"
    [[ -n "${uptime_str}" ]] && log "Uptime    : ${uptime_str}"
  fi

  # Cek SOCKS5 port 40000 (wireproxy bind address)
  hr
  if have_cmd ss; then
    if ss -lntp 2>/dev/null | grep -q ':40000'; then
      log "Port 40000 (SOCKS5) : LISTENING ✅"
    else
      warn "Port 40000 (SOCKS5) : NOT listening ❌"
    fi
  else
    warn "ss tidak tersedia, tidak bisa cek port 40000"
  fi

  # Cek konektivitas WARP via wireproxy (opsional, timeout singkat)
  hr
  log "Test koneksi via WARP proxy (curl --socks5 127.0.0.1:40000, timeout 5s)..."
  if have_cmd curl; then
    local warp_ip
    warp_ip="$(curl -fsSL --socks5 127.0.0.1:40000 --max-time 5 https://api.ipify.org 2>/dev/null || true)"
    if [[ -n "${warp_ip}" ]]; then
      log "WARP outbound IP : ${warp_ip} ✅"
    else
      warn "WARP outbound IP : gagal (wireproxy mungkin tidak terhubung ke WARP)"
    fi
  else
    warn "curl tidak tersedia, skip test koneksi WARP"
  fi

  hr
  echo "Konfigurasi : /etc/wireproxy/config.conf"
  echo "Info log    : disembunyikan agar tampilan ringkas"
  echo
  echo "  1) Lihat log wireproxy (20 baris)"
  echo "  0) Back"
  hr
  if ! read -r -p "Pilih: " c; then
    echo
    return 0
  fi
  case "${c}" in
    1) daemon_log_tail_show wireproxy 20 ;;
    0|kembali|k|back|b) : ;;
    *) warn "Pilihan tidak valid" ; sleep 1 ;;
  esac
}

wireproxy_restart_menu() {
  title
  echo "11) Maintenance > Restart WARP"
  hr

  local confirm_rc=0
  confirm_yn_or_back "Restart wireproxy sekarang?"
  confirm_rc=$?
  if (( confirm_rc != 0 )); then
    if (( confirm_rc == 2 )); then
      warn "Restart wireproxy dibatalkan (kembali)."
    else
      warn "Restart wireproxy dibatalkan."
    fi
    hr
    pause
    return 0
  fi

  local restart_failed="false"
  if ! svc_exists wireproxy; then
    warn "wireproxy.service tidak ditemukan."
    hr
    pause
    return 0
  fi

  if ! warp_wireproxy_post_restart_health_check; then
    warn "Restart wireproxy gagal."
    restart_failed="true"
  fi
  hr
  pause
  [[ "${restart_failed}" != "true" ]]
}

edge_runtime_env_file() {
  printf '%s\n' "/etc/default/edge-runtime"
}

badvpn_runtime_env_file() {
  printf '%s\n' "/etc/default/badvpn-udpgw"
}

badvpn_runtime_ports() {
  local ports_raw
  ports_raw="$(badvpn_runtime_get_env BADVPN_UDPGW_PORTS 2>/dev/null || echo "7300 7400 7500 7600 7700 7800 7900")"
  ports_raw="${ports_raw//,/ }"
  ports_raw="${ports_raw%\"}"
  ports_raw="${ports_raw#\"}"
  ports_raw="${ports_raw%\'}"
  ports_raw="${ports_raw#\'}"
  awk '
    {
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^[0-9]+$/ && !seen[$i]++) {
          ports[++count] = $i + 0
        }
      }
    }
    END {
      if (count > 0) {
        for (i = 1; i <= count; i++) {
          for (j = i + 1; j <= count; j++) {
            if (ports[j] < ports[i]) {
              tmp = ports[i]
              ports[i] = ports[j]
              ports[j] = tmp
            }
          }
        }
        for (i = 1; i <= count; i++) {
          out = out (out ? " " : "") ports[i]
        }
        print out
      }
    }
  ' <<< "${ports_raw}"
}

badvpn_public_port_label() {
  local ports
  ports="$(badvpn_runtime_ports)"
  if svc_exists badvpn-udpgw || [[ -r "$(badvpn_runtime_env_file)" ]]; then
    printf '%s\n' "${ports}" | sed 's/ /, /g'
  else
    printf '%s\n' "-"
  fi
}

badvpn_runtime_get_env() {
  local key="$1"
  local env_file
  env_file="$(badvpn_runtime_env_file)"
  [[ -r "${env_file}" ]] || return 1
  awk -F= -v key="${key}" '
    $1 == key {
      sub(/^[[:space:]]+/, "", $2)
      sub(/[[:space:]]+$/, "", $2)
      print $2
      exit
    }
  ' "${env_file}"
}

edge_runtime_get_env() {
  local key="$1"
  local env_file
  env_file="$(edge_runtime_env_file)"
  [[ -r "${env_file}" ]] || return 1
  awk -F= -v key="${key}" '
    $1 == key {
      sub(/^[[:space:]]+/, "", $2)
      sub(/[[:space:]]+$/, "", $2)
      print $2
      exit
    }
  ' "${env_file}"
}

edge_runtime_port_list() {
  local list_key="$1" single_key="$2" fallback_list="$3" fallback_single="$4"
  local raw
  raw="$(edge_runtime_get_env "${list_key}" 2>/dev/null || true)"
  if [[ -z "${raw}" ]]; then
    raw="$(edge_runtime_get_env "${single_key}" 2>/dev/null || true)"
  fi
  if [[ -z "${raw}" ]]; then
    raw="${fallback_list:-${fallback_single}}"
  fi
  awk '
    {
      gsub(/,/, " ")
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^[0-9]+$/ && !seen[$i]++) {
          out = out (out ? " " : "") $i
        }
      }
    }
    END { print out }
  ' <<< "${raw}"
}

edge_runtime_public_http_ports() {
  edge_runtime_port_list EDGE_PUBLIC_HTTP_PORTS EDGE_PUBLIC_HTTP_PORT "80 8080 8880 2052 2082 2086 2095" "80"
}

edge_runtime_public_tls_ports() {
  edge_runtime_port_list EDGE_PUBLIC_TLS_PORTS EDGE_PUBLIC_TLS_PORT "443 2053 2083 2087 2096 8443" "443"
}

edge_runtime_ports_label() {
  local ports="${1:-}"
  [[ -n "${ports}" ]] || {
    printf '%s\n' "-"
    return 0
  }
  printf '%s\n' "${ports}" | sed 's/ /, /g'
}

edge_runtime_service_name() {
  local provider
  provider="$(edge_runtime_get_env EDGE_PROVIDER 2>/dev/null || echo "none")"
  case "${provider}" in
    nginx-stream) printf '%s\n' "nginx" ;;
    go) printf '%s\n' "edge-mux.service" ;;
    *) printf '%s\n' "edge-mux.service" ;;
  esac
}

format_elapsed_seconds_pretty() {
  local total="${1:-0}"
  local days hours mins secs rem
  [[ "${total}" =~ ^[0-9]+$ ]] || return 1

  days=$(( total / 86400 ))
  rem=$(( total % 86400 ))
  hours=$(( rem / 3600 ))
  rem=$(( rem % 3600 ))
  mins=$(( rem / 60 ))
  secs=$(( rem % 60 ))

  if (( days > 0 )); then
    printf '%d-%02d:%02d:%02d\n' "${days}" "${hours}" "${mins}" "${secs}"
  else
    printf '%02d:%02d:%02d\n' "${hours}" "${mins}" "${secs}"
  fi
}

process_uptime_pretty() {
  local pid="${1:-}"
  local started_at now_ts start_ts elapsed
  [[ "${pid}" =~ ^[0-9]+$ ]] || return 1
  (( pid > 0 )) || return 1

  started_at="$(ps -o lstart= -p "${pid}" 2>/dev/null | sed -e 's/^[[:space:]]*//' || true)"
  [[ -n "${started_at}" ]] || return 1

  now_ts="$(date +%s 2>/dev/null || true)"
  start_ts="$(date -d "${started_at}" +%s 2>/dev/null || true)"
  [[ "${now_ts}" =~ ^[0-9]+$ && "${start_ts}" =~ ^[0-9]+$ ]] || return 1
  (( now_ts >= start_ts )) || return 1

  elapsed=$(( now_ts - start_ts ))
  format_elapsed_seconds_pretty "${elapsed}"
}

edge_runtime_tls_backend_required() {
  local provider="${1:-}"
  local active="${2:-false}"
  [[ "${active}" == "true" && "${provider}" == "nginx-stream" ]]
}

edge_runtime_metrics_addr() {
  edge_runtime_get_env EDGE_METRICS_LISTEN 2>/dev/null || echo "127.0.0.1:9910"
}

edge_runtime_print_observability_summary() {
  local addr="${1:-}"
  [[ -n "${addr}" ]] || addr="$(edge_runtime_metrics_addr)"

  if ! have_cmd curl; then
    warn "curl tidak tersedia, skip observability edge"
    return 0
  fi
  if ! have_cmd python3; then
    warn "python3 tidak tersedia, skip observability edge"
    return 0
  fi

  local status_tmp
  status_tmp="$(mktemp)"
  if ! curl -fsS --max-time 2 "http://${addr}/status" >"${status_tmp}" 2>/dev/null; then
    rm -f "${status_tmp}"
    warn "Status ${addr} : unavailable"
    return 0
  fi

  python3 - <<'PY' "${addr}" "${status_tmp}"
import json
import pathlib
import re
import sys

addr = sys.argv[1]
path = pathlib.Path(sys.argv[2])
try:
  data = json.loads(path.read_text(encoding="utf-8"))
except Exception:
  print(f"[manage][WARN] Status {addr} : invalid JSON")
  raise SystemExit(0)

def to_int(v, default=0):
  try:
    if v is None:
      return default
    if isinstance(v, bool):
      return int(v)
    if isinstance(v, (int, float)):
      return int(v)
    s = str(v).strip()
    if not s:
      return default
    return int(float(s))
  except Exception:
    return default

def yesno(v):
  return "up" if bool(v) else "down"

def join_map(mapping):
  if not isinstance(mapping, dict) or not mapping:
    return "-"
  parts = []
  for key in sorted(mapping):
    parts.append(f"{key}={mapping[key]}")
  return ", ".join(parts)

def join_abuse_blocks(until_map, reason_map, surface_map):
  if not isinstance(until_map, dict) or not until_map:
    return "-"
  parts = []
  for ip in sorted(until_map):
    reason = "-"
    surface = "-"
    if isinstance(reason_map, dict):
      reason = str(reason_map.get(ip) or "-").strip() or "-"
    if isinstance(surface_map, dict):
      surface = str(surface_map.get(ip) or "-").strip() or "-"
    parts.append(f"{ip}({reason}/{surface})")
  return ", ".join(parts) if parts else "-"

def backend_status_text(row):
  if not isinstance(row, dict):
    return "-"
  status = str(row.get("status") or "").strip().lower()
  healthy = bool(row.get("healthy"))
  if not status:
    status = "up" if healthy else "down"
  latency = to_int(row.get("latency_ms"), -1)
  reason = str(row.get("reason") or "").strip()
  address = str(row.get("address") or "-").strip() or "-"
  parts = [status]
  if latency >= 0 and status in ("up", "degraded"):
    parts.append(f"{latency}ms")
  if status in ("down", "disabled") and reason:
    parts.append(reason)
  parts.append(address)
  return " | ".join(parts)

surface = data.get("surface")
listeners = data.get("listener_up") if isinstance(data.get("listener_up"), dict) else {}
last_route = data.get("last_route") if isinstance(data.get("last_route"), dict) else {}
backend_health = data.get("backend_health") if isinstance(data.get("backend_health"), dict) else {}
abuse = data.get("abuse") if isinstance(data.get("abuse"), dict) else {}

print(f"[manage] Status {addr} : ok ✅")
print(f"Runtime OK  : {'true' if bool(data.get('ok')) else 'false'}")
print(f"Active conn : {to_int(data.get('active_connections_total'), 0)}")
print(
  "Listeners   : "
  f"http={yesno(listeners.get('http'))} "
  f"tls={yesno(listeners.get('tls'))} "
  f"metrics={yesno(listeners.get('metrics'))}"
)
if last_route:
  print(
    "Last route  : "
    f"{last_route.get('surface') or '-'} | "
    f"{last_route.get('route') or '-'} | "
    f"{last_route.get('backend') or '-'}"
  )

if backend_health:
  print("Backends:")
  for name in sorted(backend_health):
    print(f"  {name:<18} {backend_status_text(backend_health.get(name))}")

if abuse:
  print(
    "Abuse: "
    f"active_ip={to_int(abuse.get('active_ips'), 0)} "
    f"active_conn={to_int(abuse.get('active_connections'), 0)} "
    f"rate_tracked={to_int(abuse.get('rate_tracked_ips'), 0)} "
    f"reject_tracked={to_int(abuse.get('reject_tracked_ips'), 0)} "
    f"cooldown={to_int(abuse.get('cooldown_blocked_ips'), 0)}"
  )
  reject_reasons = join_map(abuse.get("reject_reasons"))
  reject_surfaces = join_map(abuse.get("reject_surfaces"))
  blocked = join_abuse_blocks(
    abuse.get("blocked_until_unix"),
    abuse.get("blocked_reason"),
    abuse.get("blocked_surface"),
  )
  print(f"  reasons            {reject_reasons}")
  print(f"  surfaces           {reject_surfaces}")
  print(f"  blocked            {blocked}")

if isinstance(surface, dict) and surface:
  print("Surface:")
  for name in sorted(surface):
    row = surface.get(name)
    if not isinstance(row, dict):
      continue
    active = to_int(row.get("active_connections"), 0)
    accepted = to_int(row.get("accepted_total"), 0)
    rejected = to_int(row.get("rejected_total"), 0)
    detect = join_map(row.get("detect_totals"))
    routes = join_map(row.get("route_totals"))
    print(
      f"  {name:<18} "
      f"act={active} acc={accepted} rej={rejected} "
      f"detect={detect} route={routes}"
    )
PY
  rm -f "${status_tmp}"
}

edge_runtime_status_menu() {
  title
  echo "11) Maintenance > Edge Gateway Status"
  hr

  local svc env_file provider active http_ports tls_ports http_backend http_tls_backend ssh_backend ssh_tls_backend detect_timeout tls80 tls_backend_required
  svc="$(edge_runtime_service_name)"
  env_file="$(edge_runtime_env_file)"
  provider="$(edge_runtime_get_env EDGE_PROVIDER 2>/dev/null || echo "none")"
  active="$(edge_runtime_get_env EDGE_ACTIVATE_RUNTIME 2>/dev/null || echo "false")"
  http_ports="$(edge_runtime_public_http_ports)"
  tls_ports="$(edge_runtime_public_tls_ports)"
  http_backend="$(edge_runtime_get_env EDGE_NGINX_HTTP_BACKEND 2>/dev/null || echo "127.0.0.1:18080")"
  http_tls_backend="$(edge_runtime_get_env EDGE_NGINX_TLS_BACKEND 2>/dev/null || echo "127.0.0.1:18443")"
  ssh_backend="$(edge_runtime_get_env EDGE_SSH_CLASSIC_BACKEND 2>/dev/null || echo "127.0.0.1:22022")"
  ssh_tls_backend="$(edge_runtime_get_env EDGE_SSH_TLS_BACKEND 2>/dev/null || echo "127.0.0.1:22443")"
  detect_timeout="$(edge_runtime_get_env EDGE_HTTP_DETECT_TIMEOUT_MS 2>/dev/null || echo "250")"
  tls80="$(edge_runtime_get_env EDGE_CLASSIC_TLS_ON_80 2>/dev/null || echo "true")"
  if edge_runtime_tls_backend_required "${provider}" "${active}"; then
    tls_backend_required="true"
  else
    tls_backend_required="false"
  fi

  echo "Runtime env : ${env_file}"
  echo "Provider    : ${provider}"
  echo "Activate    : ${active}"
  echo "HTTP ports  : $(edge_runtime_ports_label "${http_ports}")"
  echo "TLS ports   : $(edge_runtime_ports_label "${tls_ports}")"
  echo "HTTP backend: ${http_backend}"
  if [[ "${tls_backend_required}" == "true" ]]; then
    echo "HTTPS b/e   : ${http_tls_backend}"
  else
    echo "HTTPS b/e   : ${http_tls_backend} (unused)"
  fi
  echo "SSH backend : ${ssh_backend}"
  echo "SSH TLS b/e : ${ssh_tls_backend}"
  echo "Detect (ms) : ${detect_timeout}"
  echo "TLS on 80   : ${tls80}"
  hr

  if svc_exists "${svc}"; then
    svc_status_line "${svc}"
  else
    warn "${svc} tidak terpasang"
  fi

  if svc_exists nginx; then
    svc_status_line nginx
  fi

  hr
  if have_cmd ss; then
    local port missing_http=() missing_tls=()
    for port in ${http_ports}; do
      if ! ss -lnt 2>/dev/null | grep -Eq "(^|[[:space:]])[^[:space:]]*:${port}([[:space:]]|$)"; then
        missing_http+=("${port}")
      fi
    done
    if (( ${#missing_http[@]} == 0 )); then
      log "Public HTTP $(edge_runtime_ports_label "${http_ports}") : LISTENING ✅"
    else
      warn "Public HTTP $(edge_runtime_ports_label "${http_ports}") : missing ${missing_http[*]} ❌"
    fi
    for port in ${tls_ports}; do
      if ! ss -lnt 2>/dev/null | grep -Eq "(^|[[:space:]])[^[:space:]]*:${port}([[:space:]]|$)"; then
        missing_tls+=("${port}")
      fi
    done
    if (( ${#missing_tls[@]} == 0 )); then
      log "Public TLS  $(edge_runtime_ports_label "${tls_ports}") : LISTENING ✅"
    else
      warn "Public TLS  $(edge_runtime_ports_label "${tls_ports}") : missing ${missing_tls[*]} ❌"
    fi

    local backend_http_port backend_http_tls_port backend_ssh_port
    backend_http_port="${http_backend##*:}"
    backend_ssh_port="${ssh_backend##*:}"
    if ss -lnt 2>/dev/null | grep -Eq "(^|[[:space:]])[^[:space:]]*:${backend_http_port}([[:space:]]|$)"; then
      log "Backend HTTP ${http_backend} : LISTENING ✅"
    else
      warn "Backend HTTP ${http_backend} : NOT listening ❌"
    fi
    if [[ "${tls_backend_required}" == "true" ]]; then
      backend_http_tls_port="${http_tls_backend##*:}"
      if ss -lnt 2>/dev/null | grep -Eq "(^|[[:space:]])[^[:space:]]*:${backend_http_tls_port}([[:space:]]|$)"; then
        log "Backend HTTPS ${http_tls_backend} : LISTENING ✅"
      else
        warn "Backend HTTPS ${http_tls_backend} : NOT listening ❌"
      fi
    else
      log "Backend HTTPS ${http_tls_backend} : unused for provider ${provider} ✅"
    fi
    if ss -lnt 2>/dev/null | grep -Eq "(^|[[:space:]])[^[:space:]]*:${backend_ssh_port}([[:space:]]|$)"; then
      log "Backend SSH  ${ssh_backend} : LISTENING ✅"
    else
      warn "Backend SSH  ${ssh_backend} : NOT listening ❌"
    fi
  else
    warn "ss tidak tersedia, skip cek listener edge"
  fi

  hr
  edge_runtime_print_observability_summary "$(edge_runtime_metrics_addr)"
  hr
  pause
}

edge_runtime_socket_listening() {
  local port="${1:-0}"
  [[ "${port}" =~ ^[0-9]+$ ]] || return 1
  have_cmd ss || return 0
  ss -lnt 2>/dev/null | grep -Eq "(^|[[:space:]])[^[:space:]]*:${port}([[:space:]]|$)"
}

edge_runtime_wait_socket_listening() {
  local port="${1:-0}"
  local timeout="${2:-10}"
  local checks i
  [[ "${port}" =~ ^[0-9]+$ ]] || return 1
  have_cmd ss || return 0
  checks=$(( timeout * 2 ))
  if (( checks < 1 )); then
    checks=1
  fi
  for (( i = 0; i < checks; i++ )); do
    if edge_runtime_socket_listening "${port}"; then
      return 0
    fi
    sleep 0.5
  done
  edge_runtime_socket_listening "${port}"
}

edge_runtime_post_restart_health_check() {
  local svc provider active http_ports tls_ports http_backend http_tls_backend ssh_backend tls_backend_required
  local backend_http_port backend_http_tls_port backend_ssh_port
  svc="$(edge_runtime_service_name)"
  provider="$(edge_runtime_get_env EDGE_PROVIDER 2>/dev/null || echo "none")"
  active="$(edge_runtime_get_env EDGE_ACTIVATE_RUNTIME 2>/dev/null || echo "false")"
  http_ports="$(edge_runtime_public_http_ports)"
  tls_ports="$(edge_runtime_public_tls_ports)"
  http_backend="$(edge_runtime_get_env EDGE_NGINX_HTTP_BACKEND 2>/dev/null || echo "127.0.0.1:18080")"
  http_tls_backend="$(edge_runtime_get_env EDGE_NGINX_TLS_BACKEND 2>/dev/null || echo "127.0.0.1:18443")"
  ssh_backend="$(edge_runtime_get_env EDGE_SSH_CLASSIC_BACKEND 2>/dev/null || echo "127.0.0.1:22022")"
  if edge_runtime_tls_backend_required "${provider}" "${active}"; then
    tls_backend_required="true"
  else
    tls_backend_required="false"
  fi

  if ! svc_restart_checked "${svc}" 60; then
    warn "Restart ${svc} gagal."
    return 1
  fi

  backend_http_port="${http_backend##*:}"
  backend_http_tls_port="${http_tls_backend##*:}"
  backend_ssh_port="${ssh_backend##*:}"

  local port
  for port in ${http_ports}; do
    if ! edge_runtime_wait_socket_listening "${port}" 12; then
      warn "Port HTTP publik ${port} belum listening setelah restart edge."
      return 1
    fi
  done
  for port in ${tls_ports}; do
    if ! edge_runtime_wait_socket_listening "${port}" 12; then
      warn "Port TLS publik ${port} belum listening setelah restart edge."
      return 1
    fi
  done
  if ! edge_runtime_wait_socket_listening "${backend_http_port}" 12; then
    warn "Backend HTTP ${http_backend} belum listening setelah restart edge."
    return 1
  fi
  if [[ "${tls_backend_required}" == "true" ]] && ! edge_runtime_wait_socket_listening "${backend_http_tls_port}" 12; then
    warn "Backend HTTPS ${http_tls_backend} belum listening setelah restart edge."
    return 1
  fi
  if ! edge_runtime_wait_socket_listening "${backend_ssh_port}" 12; then
    warn "Backend SSH ${ssh_backend} belum listening setelah restart edge."
    return 1
  fi
  return 0
}

edge_runtime_restart_menu() {
  title
  echo "11) Maintenance > Restart Edge Gateway"
  hr

  local confirm_rc=0
  confirm_yn_or_back "Restart Edge Gateway sekarang?"
  confirm_rc=$?
  if (( confirm_rc != 0 )); then
    if (( confirm_rc == 2 )); then
      warn "Restart Edge Gateway dibatalkan (kembali)."
    else
      warn "Restart Edge Gateway dibatalkan."
    fi
    hr
    pause
    return 0
  fi

  local restart_failed="false"
  local svc
  svc="$(edge_runtime_service_name)"
  if ! svc_exists "${svc}"; then
    warn "${svc} tidak terpasang."
    hr
    pause
    return 0
  fi

  if ! edge_runtime_post_restart_health_check; then
    warn "Restart ${svc} gagal."
    restart_failed="true"
  fi
  hr
  pause
  [[ "${restart_failed}" != "true" ]]
}

edge_runtime_info_menu() {
  title
  echo "11) Maintenance > Edge Gateway Info"
  hr

  local provider active http_ports tls_ports http_backend http_tls_backend ssh_backend ssh_tls_backend detect_timeout tls80 cert_file key_file
  provider="$(edge_runtime_get_env EDGE_PROVIDER 2>/dev/null || echo "none")"
  active="$(edge_runtime_get_env EDGE_ACTIVATE_RUNTIME 2>/dev/null || echo "false")"
  http_ports="$(edge_runtime_public_http_ports)"
  tls_ports="$(edge_runtime_public_tls_ports)"
  http_backend="$(edge_runtime_get_env EDGE_NGINX_HTTP_BACKEND 2>/dev/null || echo "127.0.0.1:18080")"
  http_tls_backend="$(edge_runtime_get_env EDGE_NGINX_TLS_BACKEND 2>/dev/null || echo "127.0.0.1:18443")"
  ssh_backend="$(edge_runtime_get_env EDGE_SSH_CLASSIC_BACKEND 2>/dev/null || echo "127.0.0.1:22022")"
  ssh_tls_backend="$(edge_runtime_get_env EDGE_SSH_TLS_BACKEND 2>/dev/null || echo "127.0.0.1:22443")"
  detect_timeout="$(edge_runtime_get_env EDGE_HTTP_DETECT_TIMEOUT_MS 2>/dev/null || echo "250")"
  tls80="$(edge_runtime_get_env EDGE_CLASSIC_TLS_ON_80 2>/dev/null || echo "true")"
  cert_file="$(edge_runtime_get_env EDGE_TLS_CERT_FILE 2>/dev/null || echo "/opt/cert/fullchain.pem")"
  key_file="$(edge_runtime_get_env EDGE_TLS_KEY_FILE 2>/dev/null || echo "/opt/cert/privkey.pem")"
  echo "Provider        : ${provider}"
  echo "Runtime Active  : ${active}"
  echo "Public HTTP     : $(edge_runtime_ports_label "${http_ports}")"
  echo "Public TLS      : $(edge_runtime_ports_label "${tls_ports}")"
  echo "HTTP Backend    : ${http_backend}"
  echo "HTTPS Backend   : ${http_tls_backend}"
  echo "SSH Backend     : ${ssh_backend}"
  echo "SSH TLS Backend : ${ssh_tls_backend}"
  echo "Detect Timeout  : ${detect_timeout} ms"
  echo "Classic TLS :80 : ${tls80}"
  echo "TLS Cert        : ${cert_file}"
  echo "TLS Key         : ${key_file}"
  hr
  echo "Mode ringkas:"
  echo "  - HTTP / WebSocket -> backend HTTP (${http_backend})"
  if [[ "${provider}" == "nginx-stream" ]]; then
    echo "  - TLS + ALPN http/1.1,h2 -> backend HTTPS (${http_tls_backend})"
    echo "  - TLS tanpa ALPN HTTP -> backend SSH TLS (${ssh_tls_backend})"
  else
    echo "  - non-HTTP setelah TLS -> backend SSH klasik (${ssh_backend})"
  fi
  echo "  - edge gateway aktif pada seluruh port Cloudflare HTTP/HTTPS yang didukung"
  hr
  pause
}

badvpn_status_menu() {
  title
  echo "11) Maintenance > BadVPN UDPGW Status"
  hr

  local env_file ports_raw ports_label max_clients max_conn sndbuf svc
  svc="badvpn-udpgw.service"
  env_file="$(badvpn_runtime_env_file)"
  ports_raw="$(badvpn_runtime_ports)"
  ports_label="$(printf '%s\n' "${ports_raw}" | sed 's/ /, /g')"
  max_clients="$(badvpn_runtime_get_env BADVPN_UDPGW_MAX_CLIENTS 2>/dev/null || echo "512")"
  max_conn="$(badvpn_runtime_get_env BADVPN_UDPGW_MAX_CONNECTIONS_FOR_CLIENT 2>/dev/null || echo "8")"
  sndbuf="$(badvpn_runtime_get_env BADVPN_UDPGW_BUFFER_SIZE 2>/dev/null || echo "1048576")"

  echo "Runtime env : ${env_file}"
  echo "Listen port : 127.0.0.1:${ports_label}"
  echo "Max clients : ${max_clients}"
  echo "Max conn    : ${max_conn}"
  echo "Sock sndbuf : ${sndbuf}"
  hr

  if svc_exists "${svc}"; then
    svc_status_line "${svc}"
  else
    warn "${svc} tidak terpasang"
  fi

  hr
  if have_cmd ss; then
    local badvpn_missing="" port
    for port in ${ports_raw}; do
      if ! ss -lntH 2>/dev/null | grep -Eq "(^|[[:space:]])127\\.0\\.0\\.1:${port}([[:space:]]|$)"; then
        badvpn_missing="${badvpn_missing}${badvpn_missing:+, }${port}"
      fi
    done
    if [[ -z "${badvpn_missing}" ]]; then
      log "UDPGW 127.0.0.1:${ports_label} : LISTENING ✅"
    else
      warn "UDPGW 127.0.0.1:${ports_label} : MISSING ${badvpn_missing} ❌"
    fi
  else
    warn "ss tidak tersedia, skip cek port TCP UDPGW"
  fi

  hr
  pause
}

badvpn_post_restart_health_check() {
  local svc ports_raw port
  svc="badvpn-udpgw.service"
  if ! svc_restart_checked "${svc}" 60; then
    warn "Restart ${svc} gagal."
    return 1
  fi
  if ! have_cmd ss; then
    return 0
  fi
  ports_raw="$(badvpn_runtime_ports)"
  for port in ${ports_raw}; do
    if ! ss -lntH 2>/dev/null | grep -Eq "(^|[[:space:]])127\\.0\\.0\\.1:${port}([[:space:]]|$)"; then
      warn "Port UDPGW 127.0.0.1:${port} belum listening setelah restart."
      return 1
    fi
  done
  return 0
}

badvpn_restart_menu() {
  title
  echo "11) Maintenance > Restart BadVPN UDPGW"
  hr

  local confirm_rc=0
  confirm_yn_or_back "Restart BadVPN UDPGW sekarang?"
  confirm_rc=$?
  if (( confirm_rc != 0 )); then
    if (( confirm_rc == 2 )); then
      warn "Restart BadVPN UDPGW dibatalkan (kembali)."
    else
      warn "Restart BadVPN UDPGW dibatalkan."
    fi
    hr
    pause
    return 0
  fi

  local restart_failed="false"
  local svc
  svc="badvpn-udpgw.service"
  if ! svc_exists "${svc}"; then
    warn "${svc} tidak ditemukan."
    hr
    pause
    return 0
  fi

  if ! badvpn_post_restart_health_check; then
    warn "Restart ${svc} gagal."
    restart_failed="true"
  fi
  hr
  pause
  [[ "${restart_failed}" != "true" ]]
}

sshws_detect_dropbear_port() {
  local fallback="${SSHWS_DROPBEAR_PORT:-22022}"
  local unit_file="/etc/systemd/system/${SSHWS_DROPBEAR_SERVICE}.service"
  local value=""
  if [[ -r "${unit_file}" ]]; then
    value="$(grep -Eo -- '-p[[:space:]]+127\\.0\\.0\\.1:[0-9]+' "${unit_file}" 2>/dev/null | head -n1 | grep -Eo '[0-9]+$' | head -n1 || true)"
  fi
  if [[ "${value}" =~ ^[0-9]+$ ]] && (( value >= 1 && value <= 65535 )); then
    echo "${value}"
  else
    echo "${fallback}"
  fi
}

sshws_detect_stunnel_port() {
  local fallback="${SSHWS_STUNNEL_PORT:-22443}"
  local conf_file="/etc/stunnel/sshws.conf"
  local value=""
  if [[ -r "${conf_file}" ]]; then
    value="$(sed -nE 's/^[[:space:]]*accept[[:space:]]*=[[:space:]]*127\\.0\\.0\\.1:([0-9]+).*$/\1/p' "${conf_file}" | head -n1)"
  fi
  if [[ "${value}" =~ ^[0-9]+$ ]] && (( value >= 1 && value <= 65535 )); then
    echo "${value}"
  else
    echo "${fallback}"
  fi
}

sshws_detect_proxy_port() {
  local fallback="${SSHWS_PROXY_PORT:-10015}"
  local unit_file="/etc/systemd/system/${SSHWS_PROXY_SERVICE}.service"
  local value=""
  if [[ -r "${unit_file}" ]]; then
    value="$(grep -Eo -- '--listen-port[[:space:]]+[0-9]+' "${unit_file}" 2>/dev/null | head -n1 | grep -Eo '[0-9]+' | head -n1 || true)"
  fi
  if [[ "${value}" =~ ^[0-9]+$ ]] && (( value >= 1 && value <= 65535 )); then
    echo "${value}"
  else
    echo "${fallback}"
  fi
}


daemon_restart_confirm_one() {
  local svc="${1:-}"
  local label="${2:-${svc}}"
  [[ -n "${svc}" ]] || return 1
  if ! svc_exists "${svc}"; then
    warn "${label} tidak terpasang"
    return 1
  fi
  if ! confirm_menu_apply_now "Restart ${label} sekarang?"; then
    return 2
  fi
  if ! svc_restart "${svc}"; then
    warn "Restart ${label} gagal."
    return 1
  fi
  return 0
}

daemon_restart_confirm_many() {
  local prompt="${1:-}"
  local warn_msg="${2:-Sebagian service gagal direstart.}"
  shift 2 || true
  local svc restart_failed="false"

  if ! confirm_menu_apply_now "${prompt}"; then
    return 2
  fi

  for svc in "$@"; do
    if svc_exists "${svc}"; then
      if ! svc_restart "${svc}"; then
        restart_failed="true"
      fi
    else
      warn "${svc} tidak terpasang, skip"
    fi
  done
  if [[ "${restart_failed}" == "true" ]]; then
    warn "${warn_msg}"
    return 1
  fi
  return 0
}

xray_daemon_post_restart_health_check() {
  local svc
  if ! svc_exists xray || ! svc_is_active xray; then
    warn "xray belum active setelah restart daemon terkait."
    return 1
  fi
  for svc in "$@"; do
    [[ -n "${svc}" ]] || continue
    if svc_exists "${svc}" && ! svc_is_active "${svc}"; then
      warn "Daemon ${svc} belum active setelah restart."
      return 1
    fi
  done
  return 0
}

xray_daemon_restart_checked() {
  local svc restarted="false"
  local -a failed=()
  for svc in "$@"; do
    [[ -n "${svc}" ]] || continue
    if svc_exists "${svc}"; then
      if svc_restart_checked "${svc}" 60; then
        restarted="true"
      else
        failed+=("${svc}")
      fi
    else
      warn "${svc} tidak terpasang, skip"
    fi
  done
  if [[ "${restarted}" != "true" ]]; then
    warn "Tidak ada daemon Xray yang bisa direstart."
    return 1
  fi
  if (( ${#failed[@]} > 0 )); then
    warn "Gagal restart daemon Xray: ${failed[*]}"
    return 1
  fi
  xray_daemon_post_restart_health_check "$@" || return 1
  return 0
}

daemon_status_menu() {
  title
  echo "11) Maintenance > Xray Daemons"
  hr

  local sshws_dropbear_svc="${SSHWS_DROPBEAR_SERVICE:-sshws-dropbear}"
  local sshws_stunnel_svc="${SSHWS_STUNNEL_SERVICE:-sshws-stunnel}"
  local sshws_proxy_svc="${SSHWS_PROXY_SERVICE:-sshws-proxy}"
  local sshws_qac_timer="${SSHWS_QAC_ENFORCER_TIMER:-sshws-qac-enforcer.timer}"

  local daemons=(
    "xray" "nginx" "xray-expired" "xray-quota" "xray-limit-ip" "xray-speed" "wireproxy"
    "${sshws_dropbear_svc}" "${sshws_stunnel_svc}" "${sshws_proxy_svc}" "${sshws_qac_timer}"
  )
  local d
  for d in "${daemons[@]}"; do
    if svc_exists "${d}"; then
      svc_status_line "${d}"
    else
      echo "N/A  - ${d} (not installed)"
    fi
  done
  hr

  echo "Info: daemon logs disembunyikan agar ringkas."
  hr

  echo "  1) Restart xray-expired"
  echo "  2) Restart xray-quota"
  echo "  3) Restart xray-limit-ip"
  echo "  4) Restart xray-speed"
  echo "  5) Restart All Xray Daemons"
  echo "  6) xray-expired Logs"
  echo "  7) xray-quota Logs"
  echo "  8) xray-limit-ip Logs"
  echo "  9) xray-speed Logs"
  echo " 10) Restart ${sshws_dropbear_svc} only"
  echo " 11) Restart ${sshws_stunnel_svc}"
  echo " 12) Restart ${sshws_proxy_svc}"
  echo " 13) Restart All SSH WS"
  echo " 14) ${sshws_dropbear_svc} Logs"
  echo " 15) ${sshws_stunnel_svc} Logs"
  echo " 16) ${sshws_proxy_svc} Logs"
  echo "  0) Back"
  hr
  if ! read -r -p "Pilih: " c; then
    echo
    return 0
  fi
  case "${c}" in
    1)
      if confirm_menu_apply_now "Restart xray-expired sekarang?"; then
        xray_daemon_restart_checked xray-expired || true
      fi
      pause
      ;;
    2)
      if confirm_menu_apply_now "Restart xray-quota sekarang?"; then
        xray_daemon_restart_checked xray-quota || true
      fi
      pause
      ;;
    3)
      if confirm_menu_apply_now "Restart xray-limit-ip sekarang?"; then
        xray_daemon_restart_checked xray-limit-ip || true
      fi
      pause
      ;;
    4)
      if confirm_menu_apply_now "Restart xray-speed sekarang?"; then
        xray_daemon_restart_checked xray-speed || true
      fi
      pause
      ;;
    5)
      if confirm_menu_apply_now "Restart semua daemon Xray sekarang?"; then
        if ! xray_daemon_restart_checked xray-expired xray-quota xray-limit-ip xray-speed; then
          pause
          return 1
        fi
      fi
      pause
      ;;
    6) daemon_log_tail_show xray-expired 20 ;;
    7) daemon_log_tail_show xray-quota 20 ;;
    8) daemon_log_tail_show xray-limit-ip 20 ;;
    9) daemon_log_tail_show xray-speed 20 ;;
    10)
      if confirm_menu_apply_now "Restart ${sshws_dropbear_svc} saja sekarang?"; then
        if ! sshws_restart_after_dropbear "${sshws_dropbear_svc}" "${sshws_stunnel_svc}" "${sshws_proxy_svc}"; then
          warn "Restart SSH WS gagal."
        fi
      fi
      pause
      ;;
    11)
      if confirm_menu_apply_now "Restart ${sshws_stunnel_svc} sekarang?"; then
        if ! sshws_restart_services_checked "${sshws_stunnel_svc}"; then
          warn "Restart ${sshws_stunnel_svc} gagal."
        fi
      fi
      pause
      ;;
    12)
      if confirm_menu_apply_now "Restart ${sshws_proxy_svc} sekarang?"; then
        if ! sshws_restart_services_checked "${sshws_proxy_svc}"; then
          warn "Restart ${sshws_proxy_svc} gagal."
        fi
      fi
      pause
      ;;
    13)
      if confirm_menu_apply_now "Restart semua service SSH WS sekarang?"; then
        if ! sshws_restart_services_checked "${sshws_dropbear_svc}" "${sshws_stunnel_svc}" "${sshws_proxy_svc}"; then
          pause
          return 1
        fi
      fi
      pause
      ;;
    14) daemon_log_tail_show "${sshws_dropbear_svc}" 20 ;;
    15) daemon_log_tail_show "${sshws_stunnel_svc}" 20 ;;
    16) daemon_log_tail_show "${sshws_proxy_svc}" 20 ;;
    0|kembali|k|back|b) return 0 ;;
    *) warn "Pilihan tidak valid" ; sleep 1 ;;
  esac
}

# -------------------------
