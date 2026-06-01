#!/usr/bin/env bash
# SSHWS install/runtime module for setup runtime.

SSHWS_PROXY_DIST_DIR="${SCRIPT_DIR}/opt/wsproxy/dist"

sshws_go_arch_suffix() {
  local arch
  arch="$(uname -m 2>/dev/null || echo unknown)"
  case "${arch}" in
    x86_64|amd64) printf '%s\n' "amd64" ;;
    aarch64|arm64) printf '%s\n' "arm64" ;;
    *) return 1 ;;
  esac
}

sshws_go_dist_binary_path() {
  local suffix
  suffix="$(sshws_go_arch_suffix)" || return 1
  printf '%s\n' "${SSHWS_PROXY_DIST_DIR}/ws-proxy-linux-${suffix}"
}

install_sshws_proxy_binary_or_die() {
  local src
  src="$(sshws_go_dist_binary_path)" || die "Arsitektur host belum didukung untuk Websocket Proxy (Go)."
  [[ -f "${src}" && -s "${src}" ]] || die "Binary prebuilt Websocket Proxy (Go) tidak ditemukan: ${src}"
  install -d -m 755 /usr/local/bin
  install -m 0755 "${src}" /usr/local/bin/ws-proxy
  ln -sfn /usr/local/bin/ws-proxy /usr/local/bin/sshws-proxy
  chown root:root /usr/local/bin/ws-proxy /usr/local/bin/sshws-proxy 2>/dev/null || true
}

validate_port_number() {
  local name="$1"
  local value="$2"
  [[ "${value}" =~ ^[0-9]+$ ]] || die "${name} harus angka 1..65535 (got: ${value})."
  if (( value < 1 || value > 65535 )); then
    die "${name} di luar range 1..65535 (got: ${value})."
  fi
}

validate_sshws_ports_config() {
  local stunnel_enabled="false"
  if command -v stunnel4 >/dev/null 2>&1 || command -v stunnel >/dev/null 2>&1; then
    stunnel_enabled="true"
  fi

  validate_port_number "SSHWS_DROPBEAR_PORT" "${SSHWS_DROPBEAR_PORT}"
  validate_port_number "SSHWS_PROXY_PORT" "${SSHWS_PROXY_PORT}"
  if [[ "${stunnel_enabled}" == "true" ]]; then
    validate_port_number "SSHWS_STUNNEL_PORT" "${SSHWS_STUNNEL_PORT}"
  fi

  if [[ "${SSHWS_DROPBEAR_PORT}" == "${SSHWS_PROXY_PORT}" ]]; then
    die "Port SSHWS tidak boleh duplikat (dropbear=${SSHWS_DROPBEAR_PORT}, proxy=${SSHWS_PROXY_PORT})."
  fi
  if [[ "${stunnel_enabled}" == "true" ]] && [[ "${SSHWS_DROPBEAR_PORT}" == "${SSHWS_STUNNEL_PORT}" \
     || "${SSHWS_STUNNEL_PORT}" == "${SSHWS_PROXY_PORT}" ]]; then
    die "Port SSHWS tidak boleh duplikat saat stunnel aktif (dropbear=${SSHWS_DROPBEAR_PORT}, stunnel=${SSHWS_STUNNEL_PORT}, proxy=${SSHWS_PROXY_PORT})."
  fi

  local -a ports=("${SSHWS_DROPBEAR_PORT}" "${SSHWS_PROXY_PORT}")
  local p
  if [[ "${stunnel_enabled}" == "true" ]]; then
    ports+=("${SSHWS_STUNNEL_PORT}")
  fi
  for p in "${ports[@]}"; do
    case "${p}" in
      80|443)
        die "Port SSHWS ${p} bentrok dengan port publik Nginx (80/443)."
        ;;
      10085)
        die "Port SSHWS ${p} bentrok dengan Xray API port (10085)."
        ;;
    esac
  done
  if [[ "${stunnel_enabled}" != "true" ]]; then
    warn "Cek port stunnel dilewati (opsional)."
  fi
}

sshws_runtime_session_stale_sec_value() {
  local value="${SSHWS_RUNTIME_SESSION_STALE_SEC:-90}"
  [[ "${value}" =~ ^[0-9]+$ ]] || die "SSHWS_RUNTIME_SESSION_STALE_SEC harus angka positif (got: ${value})."
  if (( value < 15 )); then
    die "SSHWS_RUNTIME_SESSION_STALE_SEC minimal 15 detik (got: ${value})."
  fi
  printf '%s\n' "${value}"
}

sshws_handshake_timeout_sec_value() {
  local value="${SSHWS_HANDSHAKE_TIMEOUT_SEC:-10}"
  [[ "${value}" =~ ^[0-9]+([.][0-9]+)?$ ]] || die "SSHWS_HANDSHAKE_TIMEOUT_SEC harus angka positif (got: ${value})."
  if ! python3 - <<'PY' "${value}"
import sys
try:
    value = float(sys.argv[1])
except Exception:
    raise SystemExit(1)
if value <= 0:
    raise SystemExit(1)
print(f"{value:g}")
PY
  then
    die "SSHWS_HANDSHAKE_TIMEOUT_SEC harus lebih besar dari 0 (got: ${value})."
  fi
}

write_sshws_runtime_env() {
  render_setup_template_or_die \
    "config/sshws-runtime.env" \
    "/etc/default/sshws-runtime" \
    0644 \
    "SSHWS_RUNTIME_SESSION_STALE_SEC=$(sshws_runtime_session_stale_sec_value)" \
    "SSHWS_HANDSHAKE_TIMEOUT_SEC=$(sshws_handshake_timeout_sec_value)"
}

install_sshws_stack() {
  ok "Pasang SSH WS stack..."
  command -v python3 >/dev/null 2>&1 || die "python3 tidak ditemukan untuk SSH WS control plane."
  [[ -x /usr/sbin/dropbear ]] || die "dropbear tidak ditemukan di /usr/sbin/dropbear."

  local stunnel_bin=""
  if command -v stunnel4 >/dev/null 2>&1; then
    stunnel_bin="$(command -v stunnel4)"
  elif command -v stunnel >/dev/null 2>&1; then
    stunnel_bin="$(command -v stunnel)"
  else
    warn "stunnel tidak ada. sshws-stunnel dilewati."
  fi

  install -d -m 755 /etc/systemd/system
  if [[ -n "${stunnel_bin}" ]]; then
    install -d -m 755 /etc/stunnel
    install -d -m 755 /run/stunnel
  fi

  systemctl disable --now xray-sshws-dropbear xray-sshws-stunnel xray-sshws-proxy >/dev/null 2>&1 || true
  systemctl disable --now sshws-dropbear sshws-stunnel sshws-proxy >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/xray-sshws-dropbear.service \
        /etc/systemd/system/xray-sshws-stunnel.service \
        /etc/systemd/system/xray-sshws-proxy.service >/dev/null 2>&1 || true
  rm -f /usr/local/bin/xray-sshws-proxy /etc/stunnel/xray-sshws.conf >/dev/null 2>&1 || true

  local -a required_ports=("${SSHWS_DROPBEAR_PORT}" "${SSHWS_PROXY_PORT}")
  local p
  if [[ -n "${stunnel_bin}" ]]; then
    required_ports+=("${SSHWS_STUNNEL_PORT}")
  fi
  for p in "${required_ports[@]}"; do
    if ! is_port_free "${p}"; then
      die "Port SSHWS ${p} sedang dipakai proses lain. Bebaskan port ini atau ubah SSHWS_*_PORT."
    fi
  done

  render_setup_template_or_die \
    "systemd/sshws-dropbear.service" \
    "/etc/systemd/system/sshws-dropbear.service" \
    0644 \
    "SSHWS_DROPBEAR_PORT=${SSHWS_DROPBEAR_PORT}"

  if [[ -n "${stunnel_bin}" ]]; then
    render_setup_template_or_die \
      "config/sshws-stunnel.conf" \
      "/etc/stunnel/sshws.conf" \
      0600 \
      "SSHWS_STUNNEL_PORT=${SSHWS_STUNNEL_PORT}" \
      "SSHWS_DROPBEAR_PORT=${SSHWS_DROPBEAR_PORT}" \
      "CERT_FULLCHAIN=${CERT_FULLCHAIN}" \
      "CERT_PRIVKEY=${CERT_PRIVKEY}"

    render_setup_template_or_die \
      "systemd/sshws-stunnel.service" \
      "/etc/systemd/system/sshws-stunnel.service" \
      0644 \
      "STUNNEL_BIN=${stunnel_bin}"
  else
    rm -f /etc/stunnel/sshws.conf /etc/systemd/system/sshws-stunnel.service >/dev/null 2>&1 || true
  fi

  install_sshws_proxy_binary_or_die
  install_setup_bin_or_die "sshws-control.py" "/usr/local/bin/sshws-control" 0755
  write_sshws_runtime_env

  render_setup_template_or_die \
    "systemd/sshws-proxy.service" \
    "/etc/systemd/system/sshws-proxy.service" \
    0644 \
    "SSHWS_PROXY_PORT=${SSHWS_PROXY_PORT}" \
    "SSHWS_DROPBEAR_PORT=${SSHWS_DROPBEAR_PORT}" \
    "SSHWS_HANDSHAKE_TIMEOUT_SEC=$(sshws_handshake_timeout_sec_value)"

  systemctl daemon-reload
  service_enable_restart_checked sshws-dropbear || die "Gagal mengaktifkan sshws-dropbear."
  if [[ -n "${stunnel_bin}" ]]; then
    if service_enable_restart_checked sshws-stunnel; then
      ok "sshws-stunnel aktif."
    else
      warn "sshws-stunnel gagal aktif. SSH WS utama tetap jalan."
      systemctl disable --now sshws-stunnel >/dev/null 2>&1 || true
    fi
  else
    ok "sshws-stunnel dilewati."
    systemctl disable --now sshws-stunnel >/dev/null 2>&1 || true
  fi
  service_enable_restart_checked sshws-proxy || die "Gagal mengaktifkan sshws-proxy."

  systemctl disable --now stunnel4 >/dev/null 2>&1 || true

  if systemctl is-active --quiet ssh >/dev/null 2>&1 || systemctl is-active --quiet sshd >/dev/null 2>&1; then
    systemctl disable dropbear >/dev/null 2>&1 || true
    ok "Dropbear distro dinonaktifkan."
  else
    warn "Dropbear distro dipertahankan agar SSH tetap aman."
  fi
  ok "SSH WS stack aktif."
}

install_sshws_qac_enforcer() {
  ok "Pasang SSH QAC enforcer..."
  command -v python3 >/dev/null 2>&1 || die "python3 tidak ditemukan untuk SSH QAC enforcer."
  install -d -m 755 /etc/systemd/system
  write_sshws_runtime_env

  install_setup_bin_or_die "sshws-qac-enforcer.py" "/usr/local/bin/sshws-qac-enforcer" 0755

  render_setup_template_or_die \
    "systemd/sshws-qac-enforcer.service" \
    "/etc/systemd/system/sshws-qac-enforcer.service" \
    0644

  render_setup_template_or_die \
    "systemd/sshws-qac-enforcer.timer" \
    "/etc/systemd/system/sshws-qac-enforcer.timer" \
    0644

  systemctl daemon-reload
  if systemctl enable --now sshws-qac-enforcer.timer >/dev/null 2>&1; then
    systemctl start sshws-qac-enforcer.service >/dev/null 2>&1 || true
    ok "SSH QAC enforcer aktif:"
    ok "  - binary: /usr/local/bin/sshws-qac-enforcer"
    ok "  - timer : sshws-qac-enforcer.timer (1 menit)"
  else
    warn "Gagal mengaktifkan sshws-qac-enforcer.timer. Cek: systemctl status sshws-qac-enforcer.timer --no-pager"
  fi
}

install_ssh_expired_cleaner() {
  ok "Pasang SSH expired cleaner..."
  command -v python3 >/dev/null 2>&1 || die "python3 tidak ditemukan untuk SSH expired cleaner."
  install -d -m 755 /etc/systemd/system

  install_setup_bin_or_die "ssh-expired-cleaner.py" "/usr/local/bin/ssh-expired-cleaner" 0755

  render_setup_template_or_die \
    "systemd/ssh-expired-cleaner.service" \
    "/etc/systemd/system/ssh-expired-cleaner.service" \
    0644

  render_setup_template_or_die \
    "systemd/ssh-expired-cleaner.timer" \
    "/etc/systemd/system/ssh-expired-cleaner.timer" \
    0644

  systemctl daemon-reload
  if systemctl enable --now ssh-expired-cleaner.timer >/dev/null 2>&1; then
    systemctl start ssh-expired-cleaner.service >/dev/null 2>&1 || true
    ok "SSH expired cleaner aktif:"
    ok "  - binary: /usr/local/bin/ssh-expired-cleaner"
    ok "  - timer : ssh-expired-cleaner.timer (harian)"
  else
    warn "Gagal mengaktifkan ssh-expired-cleaner.timer. Cek: systemctl status ssh-expired-cleaner.timer --no-pager"
  fi
}
