#!/usr/bin/env bash

EDGE_RUNTIME_ENV_FILE="${EDGE_RUNTIME_ENV_FILE:-/etc/default/edge-runtime}"
EDGE_DIST_DIR="${SCRIPT_DIR}/opt/edge/dist"
EDGE_BIN="${EDGE_BIN:-/usr/local/bin/edge-mux}"
EDGE_SERVICE_NAME="${EDGE_SERVICE_NAME:-edge-mux.service}"
EDGE_DEFAULT_HTTP_PORTS="${EDGE_DEFAULT_HTTP_PORTS:-80,8080,8880,2052,2082,2086,2095}"
EDGE_DEFAULT_TLS_PORTS="${EDGE_DEFAULT_TLS_PORTS:-443,2053,2083,2087,2096,8443}"
EDGE_NGINX_TLS_BACKEND="${EDGE_NGINX_TLS_BACKEND:-127.0.0.1:18443}"
EDGE_NGINX_STREAM_CONF="${EDGE_NGINX_STREAM_CONF:-/etc/nginx/stream-conf.d/edge-stream.conf}"
EDGE_SSH_QUOTA_ROOT="${EDGE_SSH_QUOTA_ROOT:-/opt/quota/ssh}"
EDGE_SSH_DROPBEAR_UNIT="${EDGE_SSH_DROPBEAR_UNIT:-sshws-dropbear}"
EDGE_SSH_QAC_ENFORCER="${EDGE_SSH_QAC_ENFORCER:-/usr/local/bin/sshws-qac-enforcer}"
EDGE_TLS_HANDSHAKE_TIMEOUT_MS="${EDGE_TLS_HANDSHAKE_TIMEOUT_MS:-5000}"
EDGE_MAX_CONNS="${EDGE_MAX_CONNS:-4096}"
EDGE_MAX_CONNS_PER_IP="${EDGE_MAX_CONNS_PER_IP:-128}"
EDGE_ACCEPT_RATE_LIMIT_PER_IP="${EDGE_ACCEPT_RATE_LIMIT_PER_IP:-60}"
EDGE_ACCEPT_RATE_WINDOW_SEC="${EDGE_ACCEPT_RATE_WINDOW_SEC:-10}"
EDGE_ABUSE_COOLDOWN_TRIGGER_REJECTS="${EDGE_ABUSE_COOLDOWN_TRIGGER_REJECTS:-8}"
EDGE_ABUSE_COOLDOWN_WINDOW_SEC="${EDGE_ABUSE_COOLDOWN_WINDOW_SEC:-30}"
EDGE_ABUSE_COOLDOWN_SEC="${EDGE_ABUSE_COOLDOWN_SEC:-120}"
EDGE_METRICS_ENABLED="${EDGE_METRICS_ENABLED:-true}"
EDGE_METRICS_LISTEN="${EDGE_METRICS_LISTEN:-127.0.0.1:9910}"
EDGE_SSH_SESSION_ROOT="${EDGE_SSH_SESSION_ROOT:-/run/autoscript/sshws-sessions}"
EDGE_SSH_SESSION_HEARTBEAT_SEC="${EDGE_SSH_SESSION_HEARTBEAT_SEC:-15}"
EDGE_ACCEPT_PROXY_PROTOCOL="${EDGE_ACCEPT_PROXY_PROTOCOL:-false}"
EDGE_TRUSTED_PROXY_CIDRS="${EDGE_TRUSTED_PROXY_CIDRS:-127.0.0.1/32,::1/128}"
EDGE_SNI_ROUTES="${EDGE_SNI_ROUTES:-}"
EDGE_SNI_PASSTHROUGH="${EDGE_SNI_PASSTHROUGH:-}"
edge_runtime_env_file_trusted() {
  local file="${EDGE_RUNTIME_ENV_FILE}"
  [[ -f "${file}" && ! -L "${file}" && -r "${file}" ]] || return 1

  if [[ "$(id -u)" -ne 0 ]]; then
    return 0
  fi

  local owner mode
  owner="$(stat -c '%u' "${file}" 2>/dev/null || echo 1)"
  mode="$(stat -c '%A' "${file}" 2>/dev/null || echo '----------')"
  [[ "${owner}" == "0" ]] || return 1
  [[ "${mode:5:1}" != "w" && "${mode:8:1}" != "w" ]] || return 1
  return 0
}

edge_runtime_set_default_from_persisted() {
  local key="$1"
  local value="$2"
  if [[ -n "${!key+x}" ]]; then
    return 0
  fi
  declare -gx "${key}=${value}"
}

load_persisted_edge_runtime_env() {
  local key value
  edge_runtime_env_file_trusted || return 0

  while IFS='=' read -r key value; do
    case "${key}" in
      EDGE_PROVIDER|EDGE_ACTIVATE_RUNTIME|EDGE_PUBLIC_HTTP_PORT|EDGE_PUBLIC_TLS_PORT|EDGE_PUBLIC_HTTP_PORTS|EDGE_PUBLIC_TLS_PORTS|EDGE_METRICS_ENABLED|EDGE_METRICS_LISTEN|EDGE_NGINX_HTTP_BACKEND|EDGE_NGINX_TLS_BACKEND|EDGE_NGINX_STREAM_CONF|EDGE_SSH_CLASSIC_BACKEND|EDGE_SSH_TLS_BACKEND|EDGE_SSH_WS_BACKEND|EDGE_SSH_QUOTA_ROOT|EDGE_XRAY_VLESS_RAW_BACKEND|EDGE_XRAY_VMESS_RAW_BACKEND|EDGE_XRAY_TROJAN_RAW_BACKEND|EDGE_SSH_DROPBEAR_UNIT|EDGE_SSH_QAC_ENFORCER|EDGE_HTTP_DETECT_TIMEOUT_MS|EDGE_CLASSIC_TLS_ON_80|EDGE_TLS_CERT_FILE|EDGE_TLS_KEY_FILE|EDGE_TLS_HANDSHAKE_TIMEOUT_MS|EDGE_MAX_CONNS|EDGE_MAX_CONNS_PER_IP|EDGE_ACCEPT_RATE_LIMIT_PER_IP|EDGE_ACCEPT_RATE_WINDOW_SEC|EDGE_ABUSE_COOLDOWN_TRIGGER_REJECTS|EDGE_ABUSE_COOLDOWN_WINDOW_SEC|EDGE_ABUSE_COOLDOWN_SEC|EDGE_SSH_SESSION_ROOT|EDGE_SSH_SESSION_HEARTBEAT_SEC|EDGE_ACCEPT_PROXY_PROTOCOL|EDGE_TRUSTED_PROXY_CIDRS|EDGE_SNI_ROUTES|EDGE_SNI_PASSTHROUGH)
        value="${value%$'\r'}"
        edge_runtime_set_default_from_persisted "${key}" "${value}"
        ;;
    esac
  done < "${EDGE_RUNTIME_ENV_FILE}"
}

edge_runtime_activate_requested() {
  case "${EDGE_ACTIVATE_RUNTIME:-false}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

edge_runtime_should_take_public_ports() {
  edge_provider_enabled && edge_runtime_activate_requested
}

edge_provider_selected() {
  printf '%s\n' "${EDGE_PROVIDER:-none}"
}

edge_provider_supported() {
  case "$(edge_provider_selected)" in
    none|go|nginx-stream) return 0 ;;
    *) return 1 ;;
  esac
}

edge_provider_enabled() {
  [[ "$(edge_provider_selected)" != "none" ]]
}

edge_public_ports_normalize() {
  local raw="${1:-}"
  awk '
    {
      gsub(/,/, " ")
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^[0-9]+$/ && !seen[$i]++) {
          ports[++count] = $i
        }
      }
    }
    END {
      for (i = 1; i <= count; i++) {
        printf "%s%s", (i == 1 ? "" : ","), ports[i]
      }
    }
  ' <<< "${raw}"
}

edge_public_http_ports_csv() {
  local ports
  ports="$(edge_public_ports_normalize "${EDGE_PUBLIC_HTTP_PORTS:-${EDGE_PUBLIC_HTTP_PORT:-${EDGE_DEFAULT_HTTP_PORTS}}}")"
  [[ -n "${ports}" ]] || ports="$(edge_public_ports_normalize "${EDGE_DEFAULT_HTTP_PORTS}")"
  printf '%s\n' "${ports}"
}

edge_public_tls_ports_csv() {
  local ports
  ports="$(edge_public_ports_normalize "${EDGE_PUBLIC_TLS_PORTS:-${EDGE_PUBLIC_TLS_PORT:-${EDGE_DEFAULT_TLS_PORTS}}}")"
  [[ -n "${ports}" ]] || ports="$(edge_public_ports_normalize "${EDGE_DEFAULT_TLS_PORTS}")"
  printf '%s\n' "${ports}"
}

edge_primary_port_from_csv() {
  local csv="${1:-}" first
  first="${csv%%,*}"
  [[ "${first}" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "${first}"
}

edge_public_http_primary_port() {
  edge_primary_port_from_csv "$(edge_public_http_ports_csv)"
}

edge_public_tls_primary_port() {
  edge_primary_port_from_csv "$(edge_public_tls_ports_csv)"
}

edge_public_ports_words() {
  local csv="${1:-}"
  printf '%s\n' "${csv//,/ }"
}

edge_firewall_allow_public_tcp_ports() {
  command -v ufw >/dev/null 2>&1 || return 0
  ufw status 2>/dev/null | grep -qi '^Status:[[:space:]]*active' || return 0

  local port
  local -A seen=()
  for port in \
    $(edge_public_ports_words "$(edge_public_http_ports_csv)") \
    $(edge_public_ports_words "$(edge_public_tls_ports_csv)"); do
    [[ "${port}" =~ ^[0-9]+$ ]] || continue
    [[ -z "${seen["${port}"]+x}" ]] || continue
    seen["${port}"]=1
    ufw allow "${port}/tcp" >/dev/null 2>&1 || warn "Gagal membuka UFW untuk TCP ${port}."
  done
}

edge_render_nginx_stream_servers() {
  local ports_csv backend_var
  case "${1:-}" in
    http)
      ports_csv="$(edge_public_http_ports_csv)"
      backend_var='$edge_stream_http_backend'
      ;;
    tls)
      ports_csv="$(edge_public_tls_ports_csv)"
      backend_var='$edge_stream_tls_backend'
      ;;
    *)
      return 1
      ;;
  esac

  python3 - "${backend_var}" "${ports_csv}" <<'PY'
import sys

backend_var, ports_csv = sys.argv[1:]
ports = [port for port in ports_csv.split(",") if port]

for idx, port in enumerate(ports):
    if idx:
        print()
    print("server {")
    print(f"  listen {port};")
    print(f"  proxy_pass {backend_var};")
    print("  proxy_connect_timeout 10s;")
    print("  proxy_timeout 7d;")
    print("  ssl_preread on;")
    print("}")
PY
}

edge_provider_summary() {
  local provider
  provider="$(edge_provider_selected)"
  case "${provider}" in
    none) printf '%s\n' "disabled" ;;
    go) printf '%s\n' "go (active custom provider)" ;;
    nginx-stream) printf '%s\n' "nginx-stream (experimental provider)" ;;
    *) printf '%s\n' "invalid:${provider}" ;;
  esac
}

edge_provider_service_name() {
  case "$(edge_provider_selected)" in
    go) printf '%s\n' "${EDGE_SERVICE_NAME}" ;;
    nginx-stream) printf '%s\n' "nginx" ;;
    *) return 1 ;;
  esac
}

edge_conflicting_provider_services() {
  local target
  target="$(edge_provider_service_name 2>/dev/null || true)"
  [[ -n "${EDGE_SERVICE_NAME}" ]] || return 0
  if [[ -n "${target}" && "${EDGE_SERVICE_NAME}" == "${target}" ]]; then
    return 0
  fi
  printf '%s\n' "${EDGE_SERVICE_NAME}"
}

edge_go_arch_suffix() {
  local arch
  arch="$(uname -m 2>/dev/null || echo unknown)"
  case "${arch}" in
    x86_64|amd64) printf '%s\n' "amd64" ;;
    aarch64|arm64) printf '%s\n' "arm64" ;;
    *) return 1 ;;
  esac
}

edge_go_dist_binary_path() {
  local suffix
  suffix="$(edge_go_arch_suffix)" || return 1
  printf '%s\n' "${EDGE_DIST_DIR}/edge-mux-linux-${suffix}"
}

edge_go_binary_available() {
  local path
  path="$(edge_go_dist_binary_path)" || return 1
  [[ -f "${path}" && -s "${path}" ]]
}

edge_runtime_preflight_or_die() {
  if ! edge_provider_enabled; then
    return 0
  fi

  case "$(edge_provider_selected)" in
    go)
      edge_go_binary_available || die "Binary prebuilt edge-mux belum tersedia untuk provider go."
      ;;
    nginx-stream) ;;
  esac
}

write_edge_runtime_env() {
  if ! edge_provider_supported; then
    die "EDGE_PROVIDER tidak dikenal: $(edge_provider_selected)"
  fi

  local vless_raw_backend vmess_raw_backend trojan_raw_backend
  # Raw VLESS/VMess/Trojan backends are generated by the current Xray config, so a
  # setup rerun must refresh them instead of inheriting stale values from an
  # older /etc/default/edge-runtime file.
  if [[ -n "${P_VLESS_TCP:-}" ]]; then
    vless_raw_backend="127.0.0.1:${P_VLESS_TCP}"
  else
    vless_raw_backend="${EDGE_XRAY_VLESS_RAW_BACKEND:-127.0.0.1:28080}"
  fi
  if [[ -n "${P_VMESS_TCP:-}" ]]; then
    vmess_raw_backend="127.0.0.1:${P_VMESS_TCP}"
  else
    vmess_raw_backend="${EDGE_XRAY_VMESS_RAW_BACKEND:-127.0.0.1:28082}"
  fi
  if [[ -n "${P_TROJAN_TCP:-}" ]]; then
    trojan_raw_backend="127.0.0.1:${P_TROJAN_TCP}"
  else
    trojan_raw_backend="${EDGE_XRAY_TROJAN_RAW_BACKEND:-127.0.0.1:28081}"
  fi

  render_setup_template_or_die \
    "config/edge-runtime.env" \
    "${EDGE_RUNTIME_ENV_FILE}" \
    0644 \
    "EDGE_PROVIDER=$(edge_provider_selected)" \
    "EDGE_ACTIVATE_RUNTIME=${EDGE_ACTIVATE_RUNTIME:-false}" \
    "EDGE_PUBLIC_HTTP_PORT=$(edge_public_http_primary_port)" \
    "EDGE_PUBLIC_TLS_PORT=$(edge_public_tls_primary_port)" \
    "EDGE_PUBLIC_HTTP_PORTS=$(edge_public_http_ports_csv)" \
    "EDGE_PUBLIC_TLS_PORTS=$(edge_public_tls_ports_csv)" \
    "EDGE_METRICS_ENABLED=${EDGE_METRICS_ENABLED:-true}" \
    "EDGE_METRICS_LISTEN=${EDGE_METRICS_LISTEN:-127.0.0.1:9910}" \
    "EDGE_NGINX_HTTP_BACKEND=${EDGE_NGINX_HTTP_BACKEND:-127.0.0.1:18080}" \
    "EDGE_NGINX_TLS_BACKEND=${EDGE_NGINX_TLS_BACKEND:-127.0.0.1:18443}" \
    "EDGE_NGINX_STREAM_CONF=${EDGE_NGINX_STREAM_CONF}" \
    "EDGE_SSH_CLASSIC_BACKEND=${EDGE_SSH_CLASSIC_BACKEND:-127.0.0.1:22022}" \
    "EDGE_SSH_TLS_BACKEND=${EDGE_SSH_TLS_BACKEND:-127.0.0.1:22443}" \
    "EDGE_SSH_WS_BACKEND=${EDGE_SSH_WS_BACKEND:-127.0.0.1:${SSHWS_PROXY_PORT:-10015}}" \
    "EDGE_SSH_QUOTA_ROOT=${EDGE_SSH_QUOTA_ROOT:-/opt/quota/ssh}" \
    "EDGE_XRAY_VLESS_RAW_BACKEND=${vless_raw_backend}" \
    "EDGE_XRAY_VMESS_RAW_BACKEND=${vmess_raw_backend}" \
    "EDGE_XRAY_TROJAN_RAW_BACKEND=${trojan_raw_backend}" \
    "EDGE_SSH_DROPBEAR_UNIT=${EDGE_SSH_DROPBEAR_UNIT:-sshws-dropbear}" \
    "EDGE_SSH_QAC_ENFORCER=${EDGE_SSH_QAC_ENFORCER:-/usr/local/bin/sshws-qac-enforcer}" \
    "EDGE_HTTP_DETECT_TIMEOUT_MS=${EDGE_HTTP_DETECT_TIMEOUT_MS:-1500}" \
    "EDGE_CLASSIC_TLS_ON_80=${EDGE_CLASSIC_TLS_ON_80:-true}" \
    "EDGE_TLS_CERT_FILE=${EDGE_TLS_CERT_FILE:-/opt/cert/fullchain.pem}" \
    "EDGE_TLS_KEY_FILE=${EDGE_TLS_KEY_FILE:-/opt/cert/privkey.pem}" \
    "EDGE_TLS_HANDSHAKE_TIMEOUT_MS=${EDGE_TLS_HANDSHAKE_TIMEOUT_MS:-5000}" \
    "EDGE_MAX_CONNS=${EDGE_MAX_CONNS:-4096}" \
    "EDGE_MAX_CONNS_PER_IP=${EDGE_MAX_CONNS_PER_IP:-128}" \
    "EDGE_ACCEPT_RATE_LIMIT_PER_IP=${EDGE_ACCEPT_RATE_LIMIT_PER_IP:-60}" \
    "EDGE_ACCEPT_RATE_WINDOW_SEC=${EDGE_ACCEPT_RATE_WINDOW_SEC:-10}" \
    "EDGE_ABUSE_COOLDOWN_TRIGGER_REJECTS=${EDGE_ABUSE_COOLDOWN_TRIGGER_REJECTS:-8}" \
    "EDGE_ABUSE_COOLDOWN_WINDOW_SEC=${EDGE_ABUSE_COOLDOWN_WINDOW_SEC:-30}" \
    "EDGE_ABUSE_COOLDOWN_SEC=${EDGE_ABUSE_COOLDOWN_SEC:-120}" \
    "EDGE_SSH_SESSION_ROOT=${EDGE_SSH_SESSION_ROOT:-/run/autoscript/sshws-sessions}" \
    "EDGE_SSH_SESSION_HEARTBEAT_SEC=${EDGE_SSH_SESSION_HEARTBEAT_SEC:-15}" \
    "EDGE_ACCEPT_PROXY_PROTOCOL=${EDGE_ACCEPT_PROXY_PROTOCOL:-false}" \
    "EDGE_TRUSTED_PROXY_CIDRS=${EDGE_TRUSTED_PROXY_CIDRS:-127.0.0.1/32,::1/128}" \
    "EDGE_SNI_ROUTES=${EDGE_SNI_ROUTES:-}" \
    "EDGE_SNI_PASSTHROUGH=${EDGE_SNI_PASSTHROUGH:-}"
}

stage_edge_go_provider() {
  local src
  src="$(edge_go_dist_binary_path)" || die "Arsitektur host belum didukung untuk provider go."
  [[ -f "${src}" && -s "${src}" ]] || die "Binary prebuilt edge-mux belum tersedia: ${src}"

  install -d -m 755 "$(dirname "${EDGE_BIN}")"
  install -m 0755 "${src}" "${EDGE_BIN}"
  chown root:root "${EDGE_BIN}" 2>/dev/null || true

  render_setup_template_or_die \
    "systemd/edge-mux.service" \
    "/etc/systemd/system/${EDGE_SERVICE_NAME}" \
    0644

  systemctl daemon-reload >/dev/null 2>&1 || true
  warn "Provider go sudah di-stage ke ${EDGE_BIN}."
}

disable_edge_nginx_stream_provider() {
  rm -f "${EDGE_NGINX_STREAM_CONF}" >/dev/null 2>&1 || true
}

stage_edge_nginx_stream_provider() {
  command -v nginx >/dev/null 2>&1 || die "Binary nginx belum tersedia untuk provider nginx-stream."
  install -d -m 755 "$(dirname "${EDGE_NGINX_STREAM_CONF}")"

  render_setup_template_or_die \
    "nginx/stream-edge.conf" \
    "${EDGE_NGINX_STREAM_CONF}" \
    0644 \
    "EDGE_HTTP_STREAM_SERVERS=$(edge_render_nginx_stream_servers http)" \
    "EDGE_TLS_STREAM_SERVERS=$(edge_render_nginx_stream_servers tls)" \
    "EDGE_NGINX_HTTP_BACKEND=${EDGE_NGINX_HTTP_BACKEND:-127.0.0.1:18080}" \
    "EDGE_NGINX_TLS_BACKEND=${EDGE_NGINX_TLS_BACKEND:-127.0.0.1:18443}" \
    "EDGE_SSH_TLS_BACKEND=${EDGE_SSH_TLS_BACKEND:-127.0.0.1:22443}"

  nginx -t >/dev/null 2>&1 || die "Validasi nginx-stream gagal: ${EDGE_NGINX_STREAM_CONF}"
  warn "Provider nginx-stream sudah di-stage."
}

edge_runtime_port_busy() {
  local port="$1"
  ss -lnt 2>/dev/null | awk '{print $4}' | grep -Eq "(^|[:.])${port}$"
}

edge_runtime_port_owned_only_by_edge() {
  local port="$1"
  local lines
  lines="$(ss -lntpH "( sport = :${port} )" 2>/dev/null || true)"
  [[ -n "${lines}" ]] || return 1
  printf '%s\n' "${lines}" | grep -qvE 'users:\(\(("edge-mux"|"nginx")' && return 1
  return 0
}

edge_runtime_activation_preflight() {
  local port
  local http_ports tls_ports
  http_ports="$(edge_public_ports_words "$(edge_public_http_ports_csv)")"
  tls_ports="$(edge_public_ports_words "$(edge_public_tls_ports_csv)")"

  [[ -s "${EDGE_TLS_CERT_FILE:-/opt/cert/fullchain.pem}" ]] || die "TLS cert edge tidak ditemukan: ${EDGE_TLS_CERT_FILE:-/opt/cert/fullchain.pem}"
  [[ -s "${EDGE_TLS_KEY_FILE:-/opt/cert/privkey.pem}" ]] || die "TLS key edge tidak ditemukan: ${EDGE_TLS_KEY_FILE:-/opt/cert/privkey.pem}"

  case "$(edge_provider_selected)" in
    go)
      [[ -x "${EDGE_BIN}" ]] || die "Binary edge belum tersedia: ${EDGE_BIN}"
      ;;
    nginx-stream)
      command -v nginx >/dev/null 2>&1 || die "Binary nginx belum tersedia."
      [[ -s "${EDGE_NGINX_STREAM_CONF}" ]] || die "Config nginx-stream belum tersedia: ${EDGE_NGINX_STREAM_CONF}"
      nginx -t >/dev/null 2>&1 || die "Validasi nginx gagal untuk provider nginx-stream."
      ;;
  esac

  for port in ${http_ports}; do
    if edge_runtime_port_busy "${port}"; then
      edge_runtime_port_owned_only_by_edge "${port}" || die "Port edge HTTP ${port} sedang dipakai proses non-edge. Aktivasi runtime edge belum aman."
    fi
  done
  for port in ${tls_ports}; do
    if edge_runtime_port_busy "${port}"; then
      edge_runtime_port_owned_only_by_edge "${port}" || die "Port edge TLS ${port} sedang dipakai proses non-edge. Aktivasi runtime edge belum aman."
    fi
  done
}

activate_edge_provider_runtime() {
  local target_service svc
  local -a restore_services=()
  target_service="$(edge_provider_service_name)" || die "Provider edge tidak punya service runtime."
  edge_runtime_activation_preflight

  while IFS= read -r svc; do
    [[ -n "${svc}" ]] || continue
    if systemctl is-active --quiet "${svc}" 2>/dev/null; then
      restore_services+=("${svc}")
    fi
  done < <(edge_conflicting_provider_services)

  systemctl daemon-reload >/dev/null 2>&1 || true
  for svc in "${restore_services[@]}"; do
    systemctl disable --now "${svc}" >/dev/null 2>&1 || true
    systemctl stop "${svc}" >/dev/null 2>&1 || true
  done

  if ! systemctl enable "${target_service}" --now >/dev/null 2>&1; then
    warn "Aktivasi ${target_service} gagal; coba pulihkan provider lama."
    for svc in "${restore_services[@]}"; do
      systemctl enable "${svc}" --now >/dev/null 2>&1 || true
    done
    die "Gagal enable ${target_service}"
  fi
  if ! systemctl restart "${target_service}" >/dev/null 2>&1; then
    warn "Restart ${target_service} gagal; coba pulihkan provider lama."
    systemctl stop "${target_service}" >/dev/null 2>&1 || true
    for svc in "${restore_services[@]}"; do
      systemctl enable "${svc}" --now >/dev/null 2>&1 || true
    done
    die "Gagal restart ${target_service}"
  fi
  systemctl is-active --quiet "${target_service}" || die "${target_service} tidak aktif setelah start"
  ok "Edge aktif: ${target_service}"
}

install_edge_provider_stack() {
  if ! edge_provider_supported; then
    die "EDGE_PROVIDER tidak dikenal: $(edge_provider_selected)"
  fi

  write_edge_runtime_env

  if ! edge_provider_enabled; then
    ok "Edge: OFF"
    return 0
  fi

  case "$(edge_provider_selected)" in
    go)
      ok "Edge provider aktif: go"
      ;;
    nginx-stream)
      warn "Edge provider: $(edge_provider_summary)"
      warn "Lihat: /root/project/autoscript/EDGE_PROVIDER_DESIGN.md"
      ;;
  esac
  install_setup_bin_or_die "edge-provider-switch" "/usr/local/bin/edge-provider-switch" 0755
  case "$(edge_provider_selected)" in
    go)
      disable_edge_nginx_stream_provider
      stage_edge_go_provider
      if edge_runtime_activate_requested; then
        activate_edge_provider_runtime
      fi
      ;;
    nginx-stream)
      stage_edge_nginx_stream_provider
      if edge_runtime_activate_requested; then
        activate_edge_provider_runtime
      fi
      ;;
  esac
  if ! edge_runtime_activate_requested; then
    warn "Edge belum diaktifkan. Set EDGE_ACTIVATE_RUNTIME=true bila ingin mengaktifkan."
  fi
  edge_firewall_allow_public_tcp_ports
  return 0
}
