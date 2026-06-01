#!/usr/bin/env bash
set -euo pipefail

# Harden PATH untuk mencegah PATH hijacking saat script dijalankan sebagai root.
SAFE_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PATH="${SAFE_PATH}"
export PATH

manage_bootstrap_path_trusted() {
  local target="${1:-}" current owner mode
  [[ -n "${target}" && -e "${target}" ]] || return 1
  if [[ "$(id -u)" -ne 0 ]]; then
    return 0
  fi

  current="$(readlink -f -- "${target}" 2>/dev/null || true)"
  [[ -n "${current}" ]] || return 1
  while :; do
    [[ -e "${current}" ]] || return 1
    [[ -L "${current}" ]] && return 1
    owner="$(stat -c '%u' "${current}" 2>/dev/null || echo 1)"
    mode="$(stat -c '%A' "${current}" 2>/dev/null || echo '----------')"
    [[ "${owner}" == "0" ]] || return 1
    [[ "${mode:5:1}" != "w" && "${mode:8:1}" != "w" ]] || return 1
    [[ "${current}" == "/" ]] && break
    current="$(dirname -- "${current}")"
  done
  return 0
}

# ============================================================
# manage.sh - CLI Menu Manajemen (post-setup)
# - Tidak mengubah setup.sh
# - Fokus: operasi harian (status, user, quota, maintenance)
# ============================================================

# -------------------------
# Konstanta (samakan dengan setup.sh)
# -------------------------
MANAGE_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
MANAGE_ENV_FILE=""
# shellcheck source=opt/setup/core/env.sh
for MANAGE_ENV_CANDIDATE in \
  "${MANAGE_SCRIPT_DIR}/opt/setup/core/env.sh" \
  "/opt/setup/core/env.sh" \
  "/usr/local/lib/autoscript-setup/opt/setup/core/env.sh"
do
  if [[ -f "${MANAGE_ENV_CANDIDATE}" ]]; then
    MANAGE_ENV_FILE="${MANAGE_ENV_CANDIDATE}"
    break
  fi
done
if [[ -z "${MANAGE_ENV_FILE}" ]]; then
  echo "manage: env.sh tidak ditemukan; cari di source repo, /opt/setup, dan /usr/local/lib/autoscript-setup." >&2
  exit 1
fi
if ! manage_bootstrap_path_trusted "${MANAGE_ENV_FILE}"; then
  echo "manage: env.sh tidak trusted; pastikan owner root, bukan symlink, dan tidak writable oleh group/other: ${MANAGE_ENV_FILE}" >&2
  exit 1
fi
. "${MANAGE_ENV_FILE}"

# Entry-point specific constants (Keep as requested)
CLOUDFLARE_API_TOKEN="${CLOUDFLARE_API_TOKEN:-ZEbavEuJawHqX4-Jwj-L5Vj0nHOD-uPXtdxsMiAZ}"
PROVIDED_ROOT_DOMAINS=(
"vyxara1.web.id"
"vyxara2.web.id"
)

# Runtime state untuk Domain Control
DOMAIN=""
# (rest of runtime state variables follow ...)
ACME_CERT_MODE="${ACME_CERT_MODE:-standalone}"
ACME_ROOT_DOMAIN="${ACME_ROOT_DOMAIN:-}"
CF_ZONE_ID="${CF_ZONE_ID:-}"
CF_ACCOUNT_ID="${CF_ACCOUNT_ID:-}"
VPS_IPV4="${VPS_IPV4:-}"
CF_PROXIED="${CF_PROXIED:-false}"
declare -ag DOMAIN_CTRL_STOPPED_SERVICES=()
declare -ag DOMAIN_CTRL_STOP_FAILURES=()
declare -ag DOMAIN_CTRL_TLS_RUNTIME_ACTIVE_SERVICES=()
DOMAIN_CTRL_NGINX_WAS_ACTIVE="0"
DOMAIN_CTRL_TXN_ACTIVE="0"
DOMAIN_CTRL_TXN_CERT_SNAPSHOT=""
DOMAIN_CTRL_TXN_NGINX_BACKUP=""
DOMAIN_CTRL_TXN_COMPAT_SNAPSHOT=""
DOMAIN_CTRL_TXN_CF_SNAPSHOT=""
DOMAIN_CTRL_TXN_CF_PREPARED="0"
DOMAIN_CTRL_TXN_DOMAIN=""
DOMAIN_CTRL_TXN_CF_ZONE_ID=""
DOMAIN_CTRL_TXN_CF_IPV4=""

# Account store (read-only source for Menu 2)
# ACCOUNT_ROOT, ACCOUNT_PROTO_DIRS, etc are sourced from env.sh

# Quota metadata store (Menu 2 add/delete)
# QUOTA_ROOT, QUOTA_PROTO_DIRS are sourced from env.sh

# Speed policy store (fondasi dari setup.sh)
# SPEED_POLICY_ROOT, SPEED_POLICY_PROTO_DIRS etc are sourced from env.sh

# Direktori kerja untuk operasi aman (atomic write)
WORK_DIR="${WORK_DIR:-/var/lib/xray-manage}"
MUTATION_TXN_DIR="${WORK_DIR}/txn-journal"
CERT_RENEW_SERVICE_JOURNAL_FILE="${WORK_DIR}/cert-renew-stopped-services.list"
CERT_RENEW_CERT_JOURNAL_FILE="${WORK_DIR}/cert-renew-cert-recovery.env"
DOMAIN_CONTROL_CF_SYNC_PENDING_FILE="${WORK_DIR}/domain-control-cf-sync.pending"
DOMAIN_CONTROL_CF_SYNC_PENDING_DIR="${WORK_DIR}/domain-control-cf-sync.pending.d"
DOMAIN_CONTROL_CF_SYNC_PENDING_LAST_ERROR=""

# File lock bersama untuk sinkronisasi write ke routing config dengan daemon Python
# (xray-quota, limit-ip, user-block). Semua pihak harus acquire lock ini sebelum
# memodifikasi 30-routing.json untuk menghindari race condition last-write-wins.
ROUTING_LOCK_FILE="/run/autoscript/locks/xray-routing.lock"
DNS_LOCK_FILE="/run/autoscript/locks/xray-dns.lock"
WARP_LOCK_FILE="/run/autoscript/locks/xray-warp.lock"

# Direktori laporan/export
REPORT_DIR="/var/log/xray-manage"
WARP_MODE_STATE_KEY="warp_mode"
WARP_TIER_STATE_KEY="warp_tier_target"
WARP_PLUS_LICENSE_STATE_KEY="warp_plus_license_key"
WARP_ZEROTRUST_ROOT="${WARP_ZEROTRUST_ROOT:-/etc/autoscript/warp-zerotrust}"
WARP_ZEROTRUST_CONFIG_FILE="${WARP_ZEROTRUST_ROOT}/config.env"
WARP_ZEROTRUST_MDM_FILE="${WARP_ZEROTRUST_MDM_FILE:-/var/lib/cloudflare-warp/mdm.xml}"
WARP_ZEROTRUST_SERVICE="${WARP_ZEROTRUST_SERVICE:-warp-svc}"
WARP_ZEROTRUST_PROXY_PORT="${WARP_ZEROTRUST_PROXY_PORT:-40000}"
SSH_ACCOUNT_DIR="${ACCOUNT_ROOT}/ssh"
SSH_QUOTA_DIR="${QUOTA_ROOT}/ssh"
SSH_USERS_STATE_DIR="${SSH_QUOTA_DIR}"
SSHWS_DROPBEAR_SERVICE="sshws-dropbear"
SSHWS_STUNNEL_SERVICE="sshws-stunnel"
SSHWS_PROXY_SERVICE="sshws-proxy"
SSHWS_QAC_ENFORCER_SERVICE="sshws-qac-enforcer"
SSHWS_QAC_ENFORCER_TIMER="sshws-qac-enforcer.timer"
SSHWS_DROPBEAR_PORT="${SSHWS_DROPBEAR_PORT:-22022}"
SSHWS_STUNNEL_PORT="${SSHWS_STUNNEL_PORT:-22443}"
SSHWS_PROXY_PORT="${SSHWS_PROXY_PORT:-10015}"
SSH_DNS_ADBLOCK_ROOT="${SSH_DNS_ADBLOCK_ROOT:-/etc/autoscript/ssh-adblock}"
SSH_DNS_ADBLOCK_CONFIG_FILE="${SSH_DNS_ADBLOCK_ROOT}/config.env"
SSH_DNS_ADBLOCK_BLOCKLIST_FILE="${SSH_DNS_ADBLOCK_ROOT}/blocked.domains"
SSH_DNS_ADBLOCK_URLS_FILE="${SSH_DNS_ADBLOCK_ROOT}/source.urls"
SSH_DNS_ADBLOCK_RENDERED_FILE="${SSH_DNS_ADBLOCK_ROOT}/blocklist.generated.conf"
SSH_DNS_ADBLOCK_DNSMASQ_CONF="${SSH_DNS_ADBLOCK_ROOT}/dnsmasq.conf"
SSH_DNS_ADBLOCK_SERVICE="${SSH_DNS_ADBLOCK_SERVICE:-ssh-adblock-dns.service}"
SSH_DNS_ADBLOCK_SYNC_SERVICE="${SSH_DNS_ADBLOCK_SYNC_SERVICE:-adblock-sync.service}"
SSH_DNS_ADBLOCK_SYNC_BIN="${SSH_DNS_ADBLOCK_SYNC_BIN:-/usr/local/bin/adblock-sync}"
SSH_NETWORK_ROOT="${SSH_NETWORK_ROOT:-/etc/autoscript/ssh-network}"
SSH_NETWORK_CONFIG_FILE="${SSH_NETWORK_ROOT}/config.env"
SSH_NETWORK_NFT_TABLE="${SSH_NETWORK_NFT_TABLE:-autoscript_ssh_network}"
SSH_NETWORK_FWMARK="${SSH_NETWORK_FWMARK:-42042}"
SSH_NETWORK_ROUTE_TABLE="${SSH_NETWORK_ROUTE_TABLE:-42042}"
SSH_NETWORK_RULE_PREF="${SSH_NETWORK_RULE_PREF:-14200}"
SSH_NETWORK_WARP_BACKEND="${SSH_NETWORK_WARP_BACKEND:-auto}"
SSH_NETWORK_WARP_INTERFACE="${SSH_NETWORK_WARP_INTERFACE:-warp-ssh0}"
SSH_NETWORK_XRAY_REDIR_PORT="${SSH_NETWORK_XRAY_REDIR_PORT:-12345}"
SSH_NETWORK_XRAY_REDIR_PORT_V6="${SSH_NETWORK_XRAY_REDIR_PORT_V6:-12346}"
SSH_NETWORK_LOCK_FILE="${SSH_NETWORK_LOCK_FILE:-/run/autoscript/locks/ssh-network.lock}"
ADBLOCK_AUTO_UPDATE_SERVICE="${ADBLOCK_AUTO_UPDATE_SERVICE:-adblock-update.service}"
ADBLOCK_AUTO_UPDATE_TIMER="${ADBLOCK_AUTO_UPDATE_TIMER:-adblock-update.timer}"
# Nilai konstanta di atas dipakai lintas modul yang di-source dinamis dari /opt/manage.
# No-op berikut menandai variabel sebagai "used" agar shellcheck tidak false-positive.
: "${WIREPROXY_CONF}" "${WGCF_DIR}" "${CUSTOM_GEOSITE_DAT}" "${ADBLOCK_GEOSITE_ENTRY}" \
  "${WIREGUARD_DIR}" "${SSH_WARP_SYNC_BIN}" \
  "${WARP_MODE_STATE_KEY}" "${WARP_TIER_STATE_KEY}" "${WARP_PLUS_LICENSE_STATE_KEY}" "${WARP_LOCK_FILE}" \
  "${WARP_ZEROTRUST_ROOT}" "${WARP_ZEROTRUST_CONFIG_FILE}" "${WARP_ZEROTRUST_MDM_FILE}" \
  "${WARP_ZEROTRUST_SERVICE}" "${WARP_ZEROTRUST_PROXY_PORT}" \
  "${SSH_USERS_STATE_DIR}" "${SSH_ACCOUNT_DIR}" "${SSH_QUOTA_DIR}" \
  "${SSHWS_DROPBEAR_SERVICE}" "${SSHWS_STUNNEL_SERVICE}" "${SSHWS_PROXY_SERVICE}" \
  "${SSHWS_QAC_ENFORCER_SERVICE}" "${SSHWS_QAC_ENFORCER_TIMER}" \
  "${SSHWS_DROPBEAR_PORT}" "${SSHWS_STUNNEL_PORT}" "${SSHWS_PROXY_PORT}" \
  "${SSH_DNS_ADBLOCK_ROOT}" "${SSH_DNS_ADBLOCK_CONFIG_FILE}" \
  "${SSH_DNS_ADBLOCK_BLOCKLIST_FILE}" "${SSH_DNS_ADBLOCK_URLS_FILE}" "${SSH_DNS_ADBLOCK_RENDERED_FILE}" \
  "${SSH_DNS_ADBLOCK_DNSMASQ_CONF}" "${SSH_DNS_ADBLOCK_SERVICE}" \
  "${SSH_DNS_ADBLOCK_SYNC_SERVICE}" "${SSH_DNS_ADBLOCK_SYNC_BIN}" \
  "${SSH_NETWORK_ROOT}" "${SSH_NETWORK_CONFIG_FILE}" "${SSH_NETWORK_NFT_TABLE}" \
  "${SSH_NETWORK_FWMARK}" "${SSH_NETWORK_ROUTE_TABLE}" "${SSH_NETWORK_RULE_PREF}" \
  "${SSH_NETWORK_WARP_BACKEND}" "${SSH_NETWORK_WARP_INTERFACE}" \
  "${SSH_NETWORK_XRAY_REDIR_PORT}" "${SSH_NETWORK_XRAY_REDIR_PORT_V6}" \
  "${SSH_NETWORK_LOCK_FILE}" \
  "${ADBLOCK_AUTO_UPDATE_SERVICE}" "${ADBLOCK_AUTO_UPDATE_TIMER}"

# Main Menu header cache (best-effort, supaya render menu tetap cepat)
MAIN_INFO_CACHE_TTL=300
MAIN_INFO_CACHE_TS=0
MAIN_INFO_CACHE_OS="-"
MAIN_INFO_CACHE_RAM="-"
MAIN_INFO_CACHE_IP="-"
MAIN_INFO_CACHE_ISP="-"
MAIN_INFO_CACHE_COUNTRY="-"
MAIN_INFO_CACHE_DOMAIN="-"
MAIN_INFO_CACHE_LICENSE_STATUS="-"
MAIN_INFO_CACHE_LICENSE_DAYS="-"
MAIN_INFO_CACHE_INVALIDATION_FILE="${WORK_DIR}/main-info.cache.invalidate"
ACCOUNT_INFO_DOMAIN_SYNC_STATE_FILE="${WORK_DIR}/account-info-domain.state"
ACCOUNT_INFO_DOMAIN_SYNC_CHECK_TTL=15
ACCOUNT_INFO_DOMAIN_SYNC_LAST_CHECK_TS=0

# Cache metadata quota (proto:username -> "quota_gb|expired|created|ip_enabled|ip_limit")
declare -Ag QUOTA_FIELDS_CACHE=()

# -------------------------
# UI styling (subtle)
# -------------------------
if [[ -t 1 ]]; then
  UI_RESET='\033[0m'
  UI_BOLD='\033[1m'
  UI_ACCENT='\033[0;36m'
  UI_MUTED='\033[0;37m'
  UI_WARN='\033[1;33m'
  UI_ERR='\033[0;31m'
else
  UI_RESET=''
  UI_BOLD=''
  UI_ACCENT=''
  UI_MUTED=''
  UI_WARN=''
UI_ERR=''
fi

MAIN_INFO_REMOTE_LOOKUPS="${MAIN_INFO_REMOTE_LOOKUPS:-1}"

init_runtime_dirs() {
  mkdir -p "${WORK_DIR}"
  chmod 700 "${WORK_DIR}"
  mkdir -p "${SSH_ACCOUNT_DIR}"
  chmod 700 "${SSH_ACCOUNT_DIR}" || true
  mkdir -p "${SSH_USERS_STATE_DIR}"
  chmod 700 "${SSH_USERS_STATE_DIR}" || true
  mkdir -p "${SSH_NETWORK_ROOT}" 2>/dev/null || true
  chmod 700 "${SSH_NETWORK_ROOT}" 2>/dev/null || true

  local lock_dir
  for lock_dir in \
    "$(dirname "${ACCOUNT_INFO_LOCK_FILE}")" \
    "$(dirname "${DOMAIN_CONTROL_LOCK_FILE}")" \
    "$(dirname "${USER_DATA_MUTATION_LOCK_FILE}")" \
    "$(dirname "${ROUTING_LOCK_FILE}")" \
    "$(dirname "${DNS_LOCK_FILE}")" \
    "$(dirname "${WARP_LOCK_FILE}")" \
    "$(dirname "${SSH_NETWORK_LOCK_FILE}")"; do
    mkdir -p "${lock_dir}" 2>/dev/null || true
    chmod 700 "${lock_dir}" 2>/dev/null || true
  done

  mkdir -p "${REPORT_DIR}"
  chmod 700 "${REPORT_DIR}"
}

# Pastikan directory account/quota ada
ensure_account_quota_dirs() {
  local proto
  mkdir -p "${ACCOUNT_ROOT}"
  mkdir -p "${QUOTA_ROOT}"
  chmod 700 "${ACCOUNT_ROOT}" "${QUOTA_ROOT}" || true

  for proto in "${ACCOUNT_PROTO_DIRS[@]}"; do
    mkdir -p "${ACCOUNT_ROOT}/${proto}"
    chmod 700 "${ACCOUNT_ROOT}/${proto}" || true
  done

  for proto in "${QUOTA_PROTO_DIRS[@]}"; do
    mkdir -p "${QUOTA_ROOT}/${proto}"
    chmod 700 "${QUOTA_ROOT}/${proto}" || true
  done

  mkdir -p "${SSH_ACCOUNT_DIR}" "${SSH_QUOTA_DIR}"
  chmod 700 "${SSH_ACCOUNT_DIR}" "${SSH_QUOTA_DIR}" || true
}

ensure_speed_policy_dirs() {
  local proto
  mkdir -p "${SPEED_POLICY_ROOT}"
  chmod 700 "${SPEED_POLICY_ROOT}" || true
  for proto in "${SPEED_POLICY_PROTO_DIRS[@]}"; do
    mkdir -p "${SPEED_POLICY_ROOT}/${proto}"
    chmod 700 "${SPEED_POLICY_ROOT}/${proto}" || true
  done
}

speed_policy_lock_prepare() {
  mkdir -p "$(dirname "${SPEED_POLICY_LOCK_FILE}")" 2>/dev/null || true
}

speed_policy_run_locked() {
  local rc=0
  if [[ "${SPEED_POLICY_LOCK_HELD:-0}" == "1" ]]; then
    "$@"
    return $?
  fi
  speed_policy_lock_prepare
  if have_cmd flock; then
    if (
      flock -x 200 || exit 1
      SPEED_POLICY_LOCK_HELD=1 "$@"
    ) 200>"${SPEED_POLICY_LOCK_FILE}"; then
      return 0
    fi
    rc=$?
    return "${rc}"
  fi
  SPEED_POLICY_LOCK_HELD=1 "$@"
  rc=$?
  return "${rc}"
}

normalize_domain_token() {
  local domain="${1:-}"
  domain="$(printf '%s' "${domain}" | tr '[:upper:]' '[:lower:]' | tr -d '\r\n' | awk '{print $1}' | tr -d ';')"
  printf '%s\n' "${domain}"
}

normalize_ip_token() {
  local ip="${1:-}"
  ip="$(printf '%s' "${ip}" | tr -d '\r\n' | awk '{print $1}' | tr -d ';')"
  printf '%s\n' "${ip}"
}

ip_literal_normalize() {
  local raw="${1:-}"
  raw="$(normalize_ip_token "${raw}")"
  [[ -n "${raw}" ]] || return 1
  need_python3
  python3 - <<'PY' "${raw}"
import ipaddress
import sys

value = str(sys.argv[1]).strip()
try:
    addr = ipaddress.ip_address(value)
except Exception:
    raise SystemExit(1)
print(addr.compressed)
PY
}

date_ymd_is_past() {
  local value="${1:-}"
  local value_ts="" today_ts=""
  [[ -n "${value}" ]] || return 1
  value_ts="$(date -d "${value}" +%s 2>/dev/null || true)"
  [[ -n "${value_ts}" ]] || return 1
  today_ts="$(date -d "$(date '+%Y-%m-%d')" +%s 2>/dev/null || true)"
  [[ -n "${today_ts}" ]] || return 1
  (( value_ts < today_ts ))
}

preview_report_path_prepare() {
  local prefix="${1:-preview}"
  local base_dir="${REPORT_DIR}"
  local out=""

  mkdir -p "${base_dir}" 2>/dev/null || base_dir="${WORK_DIR}"
  out="$(mktemp "${base_dir}/${prefix}.XXXXXX.txt" 2>/dev/null || true)"
  if [[ -z "${out}" ]]; then
    out="${WORK_DIR}/${prefix}.$(date +%s).$$.txt"
    : > "${out}" 2>/dev/null || return 1
  fi
  printf '%s\n' "${out}"
}

preview_report_show_file() {
  local path="${1:-}"
  local total_lines=0
  [[ -f "${path}" ]] || return 1
  if have_cmd less; then
    less -R "${path}"
    return $?
  fi
  total_lines="$(wc -l < "${path}" 2>/dev/null || echo 0)"
  sed -n '1,400p' "${path}" || return 1
  if [[ "${total_lines}" =~ ^[0-9]+$ ]] && (( total_lines > 400 )); then
    echo
    echo "... output dipotong; buka file report untuk daftar lengkap:"
    echo "  ${path}"
  fi
  return 0
}

account_info_lock_prepare() {
  mkdir -p "$(dirname "${ACCOUNT_INFO_LOCK_FILE}")" 2>/dev/null || true
}

account_info_run_locked() {
  local rc=0
  if [[ "${ACCOUNT_INFO_LOCK_HELD:-0}" == "1" ]]; then
    "$@"
    return $?
  fi
  if ! have_cmd flock; then
    ACCOUNT_INFO_LOCK_HELD=1 "$@"
    return $?
  fi
  account_info_lock_prepare
  if (
    flock -x 200 || exit 1
    ACCOUNT_INFO_LOCK_HELD=1 "$@"
  ) 200>"${ACCOUNT_INFO_LOCK_FILE}"; then
    return 0
  fi
  rc=$?
  return "${rc}"
}

domain_control_lock_prepare() {
  mkdir -p "$(dirname "${DOMAIN_CONTROL_LOCK_FILE}")" 2>/dev/null || true
}

domain_control_run_locked() {
  local rc=0
  if [[ "${DOMAIN_CONTROL_LOCK_HELD:-0}" == "1" ]]; then
    "$@"
    return $?
  fi
  if ! have_cmd flock; then
    DOMAIN_CONTROL_LOCK_HELD=1 "$@"
    return $?
  fi
  domain_control_lock_prepare
  if (
    flock -x 200 || exit 1
    DOMAIN_CONTROL_LOCK_HELD=1 "$@"
  ) 200>"${DOMAIN_CONTROL_LOCK_FILE}"; then
    return 0
  fi
  rc=$?
  return "${rc}"
}

user_data_mutation_lock_prepare() {
  mkdir -p "$(dirname "${USER_DATA_MUTATION_LOCK_FILE}")" 2>/dev/null || true
}

user_data_mutation_run_locked() {
  local rc=0
  if [[ "${USER_DATA_MUTATION_LOCK_HELD:-0}" == "1" ]]; then
    "$@"
    return $?
  fi
  user_data_mutation_lock_prepare
  if have_cmd flock; then
    if (
      flock -x 200 || exit 1
      USER_DATA_MUTATION_LOCK_HELD=1 "$@"
    ) 200>"${USER_DATA_MUTATION_LOCK_FILE}"; then
      return 0
    fi
    rc=$?
    return "${rc}"
  fi
  USER_DATA_MUTATION_LOCK_HELD=1 "$@"
  rc=$?
  return "${rc}"
}

quota_lock_file_path() {
  local qf="${1:-}"
  printf '%s.lock\n' "${qf}"
}

quota_restore_file_locked() {
  # args: backup_file target_file
  local src="${1:-}"
  local dst="${2:-}"
  local lockf
  [[ -n "${src}" && -n "${dst}" ]] || return 1
  lockf="$(quota_lock_file_path "${dst}")"
  mkdir -p "$(dirname "${lockf}")" 2>/dev/null || true

  if have_cmd flock; then
    (
      flock -x 200 || exit 1
      cp -f -- "${src}" "${dst}" || exit 1
      chmod 600 "${dst}" 2>/dev/null || true
    ) 200>"${lockf}"
    return $?
  fi

  cp -f -- "${src}" "${dst}" || return 1
  chmod 600 "${dst}" 2>/dev/null || true
  return 0
}

account_info_restore_file_locked() {
  # args: backup_file target_file
  local src="${1:-}"
  local dst="${2:-}"
  local dir="" tmp="" dst_mode="600" dst_uid="0" dst_gid="0"
  [[ -n "${src}" && -n "${dst}" ]] || return 1
  if [[ "${ACCOUNT_INFO_LOCK_HELD:-0}" != "1" ]]; then
    account_info_run_locked account_info_restore_file_locked "${src}" "${dst}"
    return $?
  fi

  dir="$(dirname "${dst}")"
  mkdir -p "${dir}" 2>/dev/null || true
  if ! account_info_target_write_preflight "${dst}"; then
    return 1
  fi
  if [[ -e "${dst}" || -L "${dst}" ]]; then
    dst_mode="$(stat -c '%a' "${dst}" 2>/dev/null || echo '600')"
    dst_uid="$(stat -c '%u' "${dst}" 2>/dev/null || echo '0')"
    dst_gid="$(stat -c '%g' "${dst}" 2>/dev/null || echo '0')"
  fi
  tmp="$(mktemp "${dir}/.account-restore.XXXXXX" 2>/dev/null || true)"
  [[ -n "${tmp}" ]] || return 1
  if ! cp -f -- "${src}" "${tmp}"; then
    rm -f "${tmp}" >/dev/null 2>&1 || true
    return 1
  fi
  chmod "${dst_mode}" "${tmp}" 2>/dev/null || chmod 600 "${tmp}" 2>/dev/null || true
  chown "${dst_uid}:${dst_gid}" "${tmp}" 2>/dev/null || true
  if ! mv -f "${tmp}" "${dst}"; then
    if install -m 600 "${tmp}" "${dst}" >/dev/null 2>&1; then
      rm -f "${tmp}" >/dev/null 2>&1 || true
    elif cp -f -- "${tmp}" "${dst}" >/dev/null 2>&1; then
      chmod 600 "${dst}" 2>/dev/null || true
      rm -f "${tmp}" >/dev/null 2>&1 || true
    else
      rm -f "${tmp}" >/dev/null 2>&1 || true
      return 1
    fi
  fi
  chmod 600 "${dst}" 2>/dev/null || true
  return 0
}

account_info_target_write_preflight() {
  # args: target_file
  local dst="${1:-}"
  local dir="" tmp=""
  [[ -n "${dst}" ]] || return 1
  if [[ "${ACCOUNT_INFO_LOCK_HELD:-0}" != "1" ]]; then
    account_info_run_locked account_info_target_write_preflight "${dst}"
    return $?
  fi
  dir="$(dirname "${dst}")"
  mkdir -p "${dir}" 2>/dev/null || return 1
  tmp="$(mktemp "${dir}/.account-write-preflight.XXXXXX" 2>/dev/null || true)"
  [[ -n "${tmp}" ]] || return 1
  rm -f "${tmp}" >/dev/null 2>&1 || true
  return 0
}

speed_policy_restore_file_locked() {
  # args: backup_file target_file
  local src="${1:-}"
  local dst="${2:-}"
  [[ -n "${src}" && -n "${dst}" ]] || return 1
  if [[ "${SPEED_POLICY_LOCK_HELD:-0}" != "1" ]]; then
    speed_policy_run_locked speed_policy_restore_file_locked "${src}" "${dst}"
    return $?
  fi
  mkdir -p "$(dirname "${dst}")" 2>/dev/null || true
  cp -f -- "${src}" "${dst}" || return 1
  chmod 600 "${dst}" 2>/dev/null || true
  return 0
}

xray_expired_pause_if_active() {
  # args: out_var_name
  local __outvar="${1:-}"
  local was_active="false"
  if svc_exists xray-expired && svc_is_active xray-expired; then
    if ! svc_stop_checked xray-expired 20; then
      return 1
    fi
    was_active="true"
  fi
  [[ -n "${__outvar}" ]] && printf -v "${__outvar}" '%s' "${was_active}"
  return 0
}

xray_expired_resume_if_needed() {
  local was_active="${1:-false}"
  [[ "${was_active}" == "true" ]] || return 0
  svc_start_checked xray-expired 20
}

speed_policy_has_entries() {
  local proto
  for proto in "${SPEED_POLICY_PROTO_DIRS[@]}"; do
    if compgen -G "${SPEED_POLICY_ROOT}/${proto}/*.json" >/dev/null; then
      return 0
    fi
  done
  return 1
}

speed_policy_artifacts_present_in_xray() {
  # Cek apakah masih ada artefak speed policy di config Xray walau policy file kosong.
  # Ini penting untuk skenario "hapus policy terakhir tapi sync gagal".
  need_python3
  [[ -f "${XRAY_OUTBOUNDS_CONF}" && -f "${XRAY_ROUTING_CONF}" ]] || return 1

  python3 - <<'PY' \
    "${XRAY_OUTBOUNDS_CONF}" \
    "${XRAY_ROUTING_CONF}" \
    "${SPEED_OUTBOUND_TAG_PREFIX}" \
    "${SPEED_RULE_MARKER_PREFIX}"
import json
import sys

out_src, rt_src, out_prefix, marker_prefix = sys.argv[1:5]
bal_prefix = f"{out_prefix}bal-"

def load_json(path):
  with open(path, "r", encoding="utf-8") as f:
    return json.load(f)

try:
  out_cfg = load_json(out_src)
  rt_cfg = load_json(rt_src)
except Exception:
  # Konservatif: jika tidak bisa diparse, paksa jalur resync agar kondisi stale tidak terlewat.
  raise SystemExit(0)

for o in (out_cfg.get("outbounds") or []):
  if not isinstance(o, dict):
    continue
  tag = o.get("tag")
  if isinstance(tag, str) and tag.startswith(out_prefix):
    raise SystemExit(0)

routing = rt_cfg.get("routing") or {}

for r in (routing.get("rules") or []):
  if not isinstance(r, dict):
    continue
  if r.get("type") != "field":
    continue
  ot = r.get("outboundTag")
  if isinstance(ot, str) and ot.startswith(out_prefix):
    raise SystemExit(0)
  users = r.get("user")
  if isinstance(users, list):
    for u in users:
      if isinstance(u, str) and u.startswith(marker_prefix):
        raise SystemExit(0)

raise SystemExit(1)
PY
}

ssh_dns_adblock_runtime_refresh_if_available() {
  [[ -x "${SSH_DNS_ADBLOCK_SYNC_BIN}" ]] || return 0
  if declare -F adblock_run_locked >/dev/null 2>&1 && [[ "${ADBLOCK_LOCK_HELD:-0}" != "1" ]]; then
    adblock_run_locked ssh_dns_adblock_runtime_refresh_if_available
    return $?
  fi
  "${SSH_DNS_ADBLOCK_SYNC_BIN}" --apply >/dev/null 2>&1 || return 1
}

speed_policy_resync_after_warp_change() {
  # Perubahan WARP global mempengaruhi jalur dasar speed-mark outbounds.
  # Wajib sinkron ulang supaya speed user tidak memakai topology sebelumnya.
  # Walau policy kosong, tetap perlu sync bila artefak speed historis masih tertinggal.
  local need_sync="false"
  if speed_policy_has_entries; then
    need_sync="true"
  elif speed_policy_artifacts_present_in_xray; then
    need_sync="true"
  fi

  if [[ "${need_sync}" != "true" ]]; then
    return 0
  fi

  if ! speed_policy_sync_xray; then
    warn "Perubahan WARP global tersimpan, tetapi sinkronisasi speed policy gagal."
    return 1
  fi

  if ! speed_policy_apply_now >/dev/null 2>&1; then
    warn "Perubahan WARP global tersimpan, tetapi apply runtime speed policy gagal."
    return 1
  fi
  return 0
}

# -------------------------
# Util
# -------------------------
log() {
  echo -e "${UI_ACCENT}[manage]${UI_RESET} $*"
}

warn() {
  echo -e "${UI_WARN}[manage][WARN]${UI_RESET} $*" >&2
}

die() {
  echo -e "${UI_ERR}[manage][ERROR]${UI_RESET} $*" >&2
  exit 1
}

mutation_txn_prepare() {
  mkdir -p "${MUTATION_TXN_DIR}" 2>/dev/null || return 1
  chmod 700 "${MUTATION_TXN_DIR}" 2>/dev/null || true
  return 0
}

mutation_txn_dir_new() {
  local prefix="${1:-txn}"
  local dir=""
  mutation_txn_prepare || return 1
  dir="$(mktemp -d "${MUTATION_TXN_DIR}/${prefix}.XXXXXX" 2>/dev/null || true)"
  if [[ -z "${dir}" ]]; then
    dir="${MUTATION_TXN_DIR}/${prefix}.$$.$RANDOM"
    mkdir -p "${dir}" 2>/dev/null || return 1
  fi
  chmod 700 "${dir}" 2>/dev/null || true
  printf '%s\n' "${dir}"
}

mutation_txn_field_write() {
  local dir="${1:-}"
  local field="${2:-}"
  local value="${3:-}"
  [[ -n "${dir}" && -n "${field}" ]] || return 1
  mkdir -p "${dir}" 2>/dev/null || return 1
  if ! printf '%s' "${value}" > "${dir}/${field}"; then
    return 1
  fi
  chmod 600 "${dir}/${field}" 2>/dev/null || true
  return 0
}

mutation_txn_field_read() {
  local dir="${1:-}"
  local field="${2:-}"
  [[ -n "${dir}" && -n "${field}" ]] || return 1
  [[ -f "${dir}/${field}" ]] || return 1
  cat "${dir}/${field}" 2>/dev/null || return 1
}

mutation_txn_dir_remove() {
  local dir="${1:-}"
  [[ -n "${dir}" && -d "${dir}" ]] || return 0
  rm -rf "${dir}" >/dev/null 2>&1 || true
}

mutation_txn_list_dirs() {
  local pattern="${1:-*}"
  mutation_txn_prepare || return 0
  find "${MUTATION_TXN_DIR}" -maxdepth 1 -type d -name "${pattern}" 2>/dev/null | sort
}

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "Jalankan sebagai root: sudo ./manage.sh"
  fi
}

ensure_path_writable() {
  # args: file_path (existing)
  local path="$1"
  local dir probe tmp

  [[ -e "${path}" ]] || die "Path tidak ditemukan: ${path}"
  dir="$(dirname "${path}")"

  # Best-effort check: directory writable (detect read-only fs, weird perms)
  probe="$(mktemp "${dir}/.writetest.XXXXXX" 2>/dev/null || true)"
  if [[ -z "${probe}" ]]; then
    warn "Directory tidak bisa ditulis: ${dir}"
    die "Tidak dapat menulis ke ${dir} (kemungkinan filesystem read-only / permission khusus)."
  fi
  rm -f "${probe}" 2>/dev/null || true

  # Immutable attribute check (best-effort)
  if have_cmd lsattr; then
    if lsattr -d "${path}" 2>/dev/null | awk '{print $1}' | grep -q 'i'; then
      die "File immutable (chattr +i): ${path}. Jalankan: chattr -i '${path}'"
    fi
  fi

  # Temp file test (same dir) for atomic replace
  tmp="$(mktemp "${dir}/.tmp.$(basename "${path}").XXXXXX" 2>/dev/null || true)"
  if [[ -z "${tmp}" ]]; then
    die "Gagal membuat temp file di ${dir} untuk atomic replace. Cek permission/immutable."
  fi
  if ! cp -a "${path}" "${tmp}" 2>/dev/null; then
    rm -f "${tmp}" 2>/dev/null || true
    die "Gagal membuat temp file di ${dir} untuk atomic replace. Cek permission/immutable."
  fi
  rm -f "${tmp}" 2>/dev/null || true
}

restore_file_if_exists() {
  local src="$1"
  local dst="$2"
  if [[ -f "${src}" ]]; then
    cp -a "${src}" "${dst}" || true
  fi
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

now_ts() {
  date '+%Y-%m-%d %H:%M'
}

bytes_from_gb() {
  # GB (GiB) -> bytes
  local gb="${1:-0}"
  python3 - <<'PY' "${gb}"
import sys
try:
  gb=float(sys.argv[1])
except Exception:
  gb=0.0
b=int(gb*(1024**3))
if b < 0:
  b=0
print(b)
PY
}

quota_disp() {
  # Jika sudah ada unit (mis. "2.50 MB"), jangan tambahkan lagi.
  # Jika hanya angka (mis. "2.50"), tambahkan unit default.
  local v="${1:-}"
  local unit="${2:-GB}"
  if [[ -z "${v}" ]]; then
    echo "0 ${unit}"
    return 0
  fi
  if [[ "${v}" =~ [A-Za-z] ]]; then
    echo "${v}"
  else
    echo "${v} ${unit}"
  fi
}


normalize_gb_input() {
  # Accept "5" or "5GB" (case-insensitive). Returns numeric string or empty on invalid.
  local v="${1:-}"
  v="$(echo "${v}" | tr -d '[:space:]')"
  v="$(echo "${v}" | tr '[:lower:]' '[:upper:]')"
  if [[ "${v}" =~ ^([0-9]+([.][0-9]+)?)GB$ ]]; then
    echo "${BASH_REMATCH[1]}"
    return 0
  fi
  if [[ "${v}" =~ ^([0-9]+([.][0-9]+)?)$ ]]; then
    echo "${BASH_REMATCH[1]}"
    return 0
  fi
  echo ""
}

normalize_speed_mbit_input() {
  # Accept "10", "10mbit", "10mbps", "10m" (case-insensitive), return numeric string.
  local v="${1:-}"
  v="$(echo "${v}" | tr -d '[:space:]')"
  v="$(echo "${v}" | tr '[:upper:]' '[:lower:]')"

  if [[ "${v}" =~ ^([0-9]+([.][0-9]+)?)(mbit|mbps|m)?$ ]]; then
    echo "${BASH_REMATCH[1]}"
    return 0
  fi
  echo ""
}

speed_mbit_is_positive() {
  local n="${1:-}"
  [[ "${n}" =~ ^[0-9]+([.][0-9]+)?$ ]] || return 1
  awk "BEGIN { exit !(${n} > 0) }"
}

validate_username() {
  # Aman untuk dipakai sebagai nama file: mencegah path traversal
  # Aturan:
  # - tidak boleh kosong
  # - tidak boleh mengandung '/', '\\', spasi, '@', atau '..'
  # - hanya karakter: A-Z a-z 0-9 . _ -
  local u="$1"

  if [[ -z "${u}" ]]; then
    return 1
  fi
  if [[ "${u}" == *"/"* || "${u}" == *"\\"* || "${u}" == *" "* || "${u}" == *"@"* || "${u}" == *".."* ]]; then
    return 1
  fi
  if [[ ! "${u}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$ ]]; then
    return 1
  fi
  return 0
}

proto_uses_password() {
  local proto="${1:-}"
  case "${proto}" in
    trojan) return 0 ;;
    *) return 1 ;;
  esac
}

proto_list_menu_print() {
  echo "  1) vless"
  echo "  2) vmess"
  echo "  3) trojan"
}

proto_menu_pick_to_value() {
  # args: pick_number -> prints proto or empty
  local pick="${1:-}"
  case "${pick}" in
    1) echo "vless" ;;
    2) echo "vmess" ;;
    3) echo "trojan" ;;
    *) echo "" ;;
  esac
}

account_username_find_protos() {
  # args: username
  local username="$1"
  local protos=()
  local p
  for p in "${ACCOUNT_PROTO_DIRS[@]}"; do
    if [[ -f "${ACCOUNT_ROOT}/${p}/${username}@${p}.txt" ]]; then
      protos+=("${p}")
    fi
  done
  echo "${protos[*]:-}"
}

quota_username_find_protos() {
  # args: username
  local username="$1"
  local protos=()
  local p
  for p in "${QUOTA_PROTO_DIRS[@]}"; do
    if [[ -f "${QUOTA_ROOT}/${p}/${username}@${p}.json" ]]; then
      protos+=("${p}")
    fi
  done
  echo "${protos[*]:-}"
}

xray_username_find_protos() {
  # args: username
  local username="$1"
  need_python3
  [[ -f "${XRAY_INBOUNDS_CONF}" ]] || return 0
  python3 - <<'PY' "${XRAY_INBOUNDS_CONF}" "${username}" 2>/dev/null || true
import json, sys
src, username = sys.argv[1:3]
try:
  with open(src,'r',encoding='utf-8') as f:
    cfg=json.load(f)
except Exception:
  raise SystemExit(0)

protos=set()
for ib in (cfg.get('inbounds') or []):
  if not isinstance(ib, dict):
    continue
  proto=ib.get('protocol')
  st=(ib.get('settings') or {})
  clients=st.get('clients') or []
  if not isinstance(clients, list):
    continue
  for c in clients:
    if not isinstance(c, dict):
      continue
    em=c.get('email')
    if not isinstance(em, str) or '@' not in em:
      continue
    u,p = em.split('@', 1)
    if u == username and isinstance(p, str) and p:
      protos.add(p.strip())
print(" ".join(sorted([x for x in protos if x])))
PY
}

is_yes() {
  # accept: y/yes/1/on/true
  local v="${1:-}"
  v="$(echo "${v}" | tr '[:upper:]' '[:lower:]')"
  [[ "${v}" == "y" || "${v}" == "yes" || "${v}" == "1" || "${v}" == "on" || "${v}" == "true" ]]
}

read_required_on_off() {
  # args: out_var_name prompt
  local -n _out_ref="$1"
  local prompt="${2:-Input (on/off): }"
  local value
  while true; do
    if ! read -r -p "${prompt}" value; then
      echo
      return 1
    fi
    if is_back_choice "${value}"; then
      return 2
    fi
    value="${value,,}"
    case "${value}" in
      on|off)
        _out_ref="${value}"
        return 0
        ;;
      *)
        warn "Input wajib on/off. Silakan isi 'on' atau 'off'."
        ;;
    esac
  done
}

is_back_choice() {
  local v="${1:-}"
  v="$(echo "${v}" | tr '[:upper:]' '[:lower:]')"
  [[ "${v}" == "0" || "${v}" == "kembali" || "${v}" == "k" || "${v}" == "back" || "${v}" == "b" ]]
}

is_back_word_choice() {
  local v="${1:-}"
  v="$(echo "${v}" | tr '[:upper:]' '[:lower:]')"
  [[ "${v}" == "kembali" || "${v}" == "k" || "${v}" == "back" || "${v}" == "b" ]]
}

detect_domain() {
  # Try nginx conf server_name first, then compatibility file, then hostname -f.
  local dom=""
  if [[ -f "${NGINX_CONF}" ]]; then
    dom="$(grep -E '^[[:space:]]*server_name[[:space:]]+' "${NGINX_CONF}" 2>/dev/null | head -n1 | sed -E 's/^[[:space:]]*server_name[[:space:]]+//; s/;.*$//' || true)"
    dom="$(echo "${dom}" | awk '{print $1}' | tr -d ';')"
  fi
  if [[ -z "${dom}" ]]; then
    dom="$(head -n1 "${XRAY_DOMAIN_FILE}" 2>/dev/null | tr -d '\r' | awk '{print $1}' | tr -d ';' || true)"
  fi
  if [[ -z "${dom}" ]]; then
    dom="$(hostname -f 2>/dev/null || hostname)"
  fi
  echo "${dom}"
}

sync_xray_domain_file() {
  local domain="${1:-}"
  local normalized tmp
  if [[ -z "${domain}" ]]; then
    domain="$(detect_domain)"
  fi
  normalized="$(normalize_domain_token "${domain}")"
  [[ -n "${normalized}" ]] || return 1

  mkdir -p "$(dirname "${XRAY_DOMAIN_FILE}")" 2>/dev/null || return 1
  tmp="$(mktemp "${WORK_DIR}/xray-domain.XXXXXX")" || return 1
  if ! printf '%s\n' "${normalized}" > "${tmp}"; then
    rm -f "${tmp}" >/dev/null 2>&1 || true
    return 1
  fi
  if ! install -m 644 "${tmp}" "${XRAY_DOMAIN_FILE}"; then
    rm -f "${tmp}" >/dev/null 2>&1 || true
    return 1
  fi
  rm -f "${tmp}" >/dev/null 2>&1 || true
  return 0
}

detect_public_ip() {
  # Prefer route src (no internet needed), fallback hostname -I
  local ip=""
  if have_cmd ip; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  fi
  if [[ -z "${ip}" ]]; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  fi
  echo "${ip:-0.0.0.0}"
}

detect_public_ip_ipapi() {
  # Ambil public IP dari api.ipify.org (best-effort), fallback ke detect_public_ip
  local ip=""
  if have_cmd curl; then
    ip="$(curl -fsSL --max-time 5 "https://api.ipify.org" 2>/dev/null || true)"
  elif have_cmd wget; then
    ip="$(wget -qO- --timeout=5 "https://api.ipify.org" 2>/dev/null || true)"
  fi

  if [[ -z "${ip}" || ! "${ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    warn "Gagal fetch IP dari api.ipify.org, fallback ke deteksi lokal"
    ip="$(detect_public_ip)"
  fi
  echo "${ip}"
}

account_info_domain_sync_state_read() {
  local state=""
  if [[ -s "${ACCOUNT_INFO_DOMAIN_SYNC_STATE_FILE}" ]]; then
    state="$(head -n1 "${ACCOUNT_INFO_DOMAIN_SYNC_STATE_FILE}" 2>/dev/null | tr -d '\r')"
    state="$(echo "${state}" | awk '{print $1}' | tr -d ';')"
  fi
  echo "${state}"
}

account_info_domain_sync_state_write() {
  local domain="${1:-}"
  local tmp=""
  domain="$(normalize_domain_token "${domain}")"
  [[ -n "${domain}" ]] || domain="-"
  mkdir -p "${WORK_DIR}" 2>/dev/null || return 1
  tmp="$(mktemp "${WORK_DIR}/account-info-domain.XXXXXX" 2>/dev/null || true)"
  [[ -n "${tmp}" ]] || tmp="${WORK_DIR}/account-info-domain.$$"
  if ! printf '%s\n' "${domain}" > "${tmp}"; then
    rm -f "${tmp}" >/dev/null 2>&1 || true
    return 1
  fi
  if ! install -m 600 "${tmp}" "${ACCOUNT_INFO_DOMAIN_SYNC_STATE_FILE}" >/dev/null 2>&1; then
    rm -f "${tmp}" >/dev/null 2>&1 || true
    return 1
  fi
  rm -f "${tmp}" >/dev/null 2>&1 || true
  return 0
}

account_info_domain_sync_state_mark_pending() {
  account_info_domain_sync_state_write "-"
}

account_info_probe_domain_from_any_account_file() {
  local proto dir f dom
  for proto in "${ACCOUNT_PROTO_DIRS[@]}"; do
    dir="${ACCOUNT_ROOT}/${proto}"
    [[ -d "${dir}" ]] || continue
    f="$(find "${dir}" -maxdepth 1 -type f -name '*.txt' -print -quit 2>/dev/null || true)"
    [[ -n "${f}" ]] || continue
    dom="$(grep -E '^[[:space:]]*Domain[[:space:]]*:' "${f}" 2>/dev/null | head -n1 | sed -E 's/^[[:space:]]*Domain[[:space:]]*:[[:space:]]*//' || true)"
    dom="$(echo "${dom}" | awk '{print $1}' | tr -d ';')"
    if [[ -n "${dom}" ]]; then
      echo "${dom}"
      return 0
    fi
  done
  dir="${SSH_ACCOUNT_DIR}"
  if [[ -d "${dir}" ]]; then
    f="$(find "${dir}" -maxdepth 1 -type f -name '*.txt' -print -quit 2>/dev/null || true)"
    if [[ -n "${f}" ]]; then
      dom="$(grep -E '^[[:space:]]*Domain[[:space:]]*:' "${f}" 2>/dev/null | head -n1 | sed -E 's/^[[:space:]]*Domain[[:space:]]*:[[:space:]]*//' || true)"
      dom="$(echo "${dom}" | awk '{print $1}' | tr -d ';')"
      if [[ -n "${dom}" ]]; then
        echo "${dom}"
        return 0
      fi
    fi
  fi
  echo ""
}

ssh_account_info_compat_needs_refresh() {
  local state_file username acc_file acc_compat
  if declare -F ssh_state_dirs_prepare >/dev/null 2>&1; then
    ssh_state_dirs_prepare >/dev/null 2>&1 || true
  fi
  [[ -d "${SSH_USERS_STATE_DIR}" ]] || return 1

  while IFS= read -r -d '' state_file; do
    username="$(basename "${state_file}")"
    username="${username%@ssh.json}"
    username="${username%.json}"
    [[ -n "${username}" ]] || continue

    acc_file="${SSH_ACCOUNT_DIR}/${username}@ssh.txt"
    acc_compat="${SSH_ACCOUNT_DIR}/${username}.txt"
    if [[ ! -f "${acc_file}" && -f "${acc_compat}" ]]; then
      acc_file="${acc_compat}"
    fi

    if [[ ! -f "${acc_file}" ]]; then
      return 0
    fi
    if ! grep -Eq '^ISP[[:space:]]*:' "${acc_file}" 2>/dev/null; then
      return 0
    fi
    if ! grep -Eq '^Country[[:space:]]*:' "${acc_file}" 2>/dev/null; then
      return 0
    fi
    if ! grep -Eq '^SSH WS Path[[:space:]]*:[[:space:]]*/[A-Fa-f0-9]{10}[[:space:]]*$' "${acc_file}" 2>/dev/null; then
      return 0
    fi
    if ! grep -Eq '^SSH WS Path Alt[[:space:]]*:[[:space:]]*/<bebas>/[A-Fa-f0-9]{10}/<bebas>[[:space:]]*$' "${acc_file}" 2>/dev/null; then
      return 0
    fi
    if ! grep -Eq '^SSH Direct[[:space:]]+Port[[:space:]]*:' "${acc_file}" 2>/dev/null; then
      return 0
    fi
    if ! grep -Eq '^SSH SSL/TLS[[:space:]]+Port[[:space:]]*:' "${acc_file}" 2>/dev/null; then
      return 0
    fi
    if ! grep -Eq '^BadVPN UDPGW[[:space:]]*:' "${acc_file}" 2>/dev/null; then
      return 0
    fi
  done < <(find "${SSH_USERS_STATE_DIR}" -maxdepth 1 -type f -name '*.json' ! -name '.*' -print0 2>/dev/null | sort -z)

  return 1
}

ssh_account_info_refresh_all_from_state() {
  local state_file username updated=0 failed=0
  if ! declare -F ssh_account_info_refresh_from_state >/dev/null 2>&1; then
    printf '0|0\n'
    return 0
  fi
  if declare -F ssh_state_dirs_prepare >/dev/null 2>&1; then
    ssh_state_dirs_prepare >/dev/null 2>&1 || true
  fi

  [[ -d "${SSH_USERS_STATE_DIR}" ]] || {
    printf '0|0\n'
    return 0
  }

  while IFS= read -r -d '' state_file; do
    username="$(basename "${state_file}")"
    username="${username%@ssh.json}"
    username="${username%.json}"
    [[ -n "${username}" ]] || continue

    if ssh_account_info_refresh_from_state "${username}"; then
      updated=$((updated + 1))
    else
      failed=$((failed + 1))
    fi
  done < <(find "${SSH_USERS_STATE_DIR}" -maxdepth 1 -type f -name '*.json' ! -name '.*' -print0 2>/dev/null | sort -z)

  printf '%s|%s\n' "${updated}" "${failed}"
  (( failed == 0 ))
}

account_info_refresh_collect_ssh_users() {
  local -n _out_ref="$1"
  local username state_file
  local -A seen=()
  _out_ref=()

  if declare -F ssh_state_dirs_prepare >/dev/null 2>&1; then
    ssh_state_dirs_prepare >/dev/null 2>&1 || true
  fi

  if declare -F ssh_collect_candidate_users >/dev/null 2>&1; then
    while IFS= read -r username; do
      [[ -n "${username}" ]] || continue
      [[ -n "${seen["${username}"]+x}" ]] && continue
      seen["${username}"]=1
      _out_ref+=("${username}")
    done < <(ssh_collect_candidate_users false 2>/dev/null || true)
    return 0
  fi

  while IFS= read -r -d '' state_file; do
    username="$(basename "${state_file}")"
    username="${username%@ssh.json}"
    username="${username%.json}"
    [[ -n "${username}" ]] || continue
    [[ -n "${seen["${username}"]+x}" ]] && continue
    seen["${username}"]=1
    _out_ref+=("${username}")
  done < <(find "${SSH_USERS_STATE_DIR}" -maxdepth 1 -type f -name '*.json' ! -name '.*' -print0 2>/dev/null | sort -z)
}

account_info_refresh_targets_summary() {
  local scope="${1:-all}"
  local sample_limit="${2:-5}"
  local i proto username
  local xray_count=0 ssh_count=0
  local -A seen_xray=() seen_ssh=()
  local -a xray_preview_items=() ssh_preview_items=()
  local -a ssh_users=()
  local xray_preview="-" ssh_preview="-"

  [[ "${sample_limit}" =~ ^[0-9]+$ ]] || sample_limit=5

  ensure_account_quota_dirs
  if [[ "${scope}" == "all" || "${scope}" == "xray" ]]; then
    account_collect_files

    if (( ${#ACCOUNT_FILES[@]} > 0 )); then
      for i in "${!ACCOUNT_FILES[@]}"; do
        proto="${ACCOUNT_FILE_PROTOS[$i]}"
        username="$(account_parse_username_from_file "${ACCOUNT_FILES[$i]}" "${proto}")"
        [[ -n "${username}" ]] || continue
        if [[ -n "${seen_xray["${proto}|${username}"]+x}" ]]; then
          continue
        fi
        seen_xray["${proto}|${username}"]=1
        xray_count=$((xray_count + 1))
        if (( sample_limit > 0 && ${#xray_preview_items[@]} < sample_limit )); then
          xray_preview_items+=("${username}@${proto}")
        fi
      done
    fi
  fi

  if [[ "${scope}" == "all" || "${scope}" == "ssh" ]]; then
    account_info_refresh_collect_ssh_users ssh_users
    for username in "${ssh_users[@]}"; do
      [[ -n "${username}" ]] || continue
      if [[ -n "${seen_ssh["${username}"]+x}" ]]; then
        continue
      fi
      seen_ssh["${username}"]=1
      ssh_count=$((ssh_count + 1))
      if (( sample_limit > 0 && ${#ssh_preview_items[@]} < sample_limit )); then
        ssh_preview_items+=("${username}")
      fi
    done
  fi

  if (( ${#xray_preview_items[@]} > 0 )); then
    xray_preview="$(printf '%s, ' "${xray_preview_items[@]}")"
    xray_preview="${xray_preview%, }"
    if (( sample_limit > 0 && xray_count > sample_limit )); then
      xray_preview="${xray_preview}, ..."
    fi
  fi
  if (( ${#ssh_preview_items[@]} > 0 )); then
    ssh_preview="$(printf '%s, ' "${ssh_preview_items[@]}")"
    ssh_preview="${ssh_preview%, }"
    if (( sample_limit > 0 && ssh_count > sample_limit )); then
      ssh_preview="${ssh_preview}, ..."
    fi
  fi

  printf '%s|%s|%s|%s|%s\n' "${xray_count}" "${ssh_count}" "$((xray_count + ssh_count))" "${xray_preview}" "${ssh_preview}"
}

account_info_refresh_targets_report_write() {
  local scope="${1:-all}"
  local outfile="${2:-}"
  local i proto username
  local -A seen_xray=() seen_ssh=()
  local -a ssh_users=()

  [[ -n "${outfile}" ]] || return 1
  ensure_account_quota_dirs
  mkdir -p "$(dirname "${outfile}")" 2>/dev/null || true
  : > "${outfile}" || return 1

  {
    printf 'Scope: %s\n' "${scope}"
    printf 'Generated: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
    printf '\n'

    if [[ "${scope}" == "all" || "${scope}" == "xray" ]]; then
      printf '[XRAY]\n'
      account_collect_files
      if (( ${#ACCOUNT_FILES[@]} == 0 )); then
        printf '(tidak ada target)\n'
      else
        for i in "${!ACCOUNT_FILES[@]}"; do
          proto="${ACCOUNT_FILE_PROTOS[$i]}"
          username="$(account_parse_username_from_file "${ACCOUNT_FILES[$i]}" "${proto}")"
          [[ -n "${username}" ]] || continue
          if [[ -n "${seen_xray["${proto}|${username}"]+x}" ]]; then
            continue
          fi
          seen_xray["${proto}|${username}"]=1
          printf '%s\t%s\t%s\n' "${username}@${proto}" "${proto}" "$(account_info_refresh_target_file_for_user "${proto}" "${username}")"
        done
      fi
      printf '\n'
    fi

    if [[ "${scope}" == "all" || "${scope}" == "ssh" ]]; then
      printf '[SSH]\n'
      account_info_refresh_collect_ssh_users ssh_users
      if (( ${#ssh_users[@]} == 0 )); then
        printf '(tidak ada target)\n'
      else
        for username in "${ssh_users[@]}"; do
          [[ -n "${username}" ]] || continue
          if [[ -n "${seen_ssh["${username}"]+x}" ]]; then
            continue
          fi
          seen_ssh["${username}"]=1
          printf '%s\tssh\t%s\n' "${username}" "$(ssh_account_info_file "${username}")"
        done
        if (( ${#seen_ssh[@]} == 0 )); then
          printf '(tidak ada target)\n'
        fi
      fi
    fi
  } > "${outfile}" || return 1

  chmod 600 "${outfile}" 2>/dev/null || true
  return 0
}

account_info_refresh_dry_run_status_for_file() {
  local target_file="${1:-}"
  local candidate_file="${2:-}"
  local hint="${3:-}"

  if [[ -z "${target_file}" || ! -f "${target_file}" ]]; then
    printf '%s\n' "would-create${hint:+ (${hint})}"
    return 0
  fi
  if [[ -z "${candidate_file}" || ! -f "${candidate_file}" ]]; then
    printf '%s\n' "preview-unavailable${hint:+ (${hint})}"
    return 0
  fi
  if cmp -s -- "${target_file}" "${candidate_file}"; then
    printf '%s\n' "no-rendered-drift"
    return 0
  fi
  printf '%s\n' "would-refresh${hint:+ (${hint})}"
}

account_info_refresh_append_diff_to_report() {
  local report_file="${1:-}"
  local current_file="${2:-}"
  local candidate_file="${3:-}"
  local label="${4:-rendered diff}"
  [[ -n "${report_file}" ]] || return 1
  {
    printf -- '--- %s\n' "${label}"
    if [[ ! -f "${candidate_file}" ]]; then
      printf '(candidate render tidak tersedia)\n'
    elif [[ ! -f "${current_file}" ]]; then
      printf '[current missing]\n'
      cat "${candidate_file}"
      [[ -s "${candidate_file}" ]] || printf '(candidate kosong)\n'
    elif cmp -s -- "${current_file}" "${candidate_file}"; then
      printf '(tidak ada perbedaan konten)\n'
    else
      diff -u --label "current:${current_file}" --label "rendered:${candidate_file}" "${current_file}" "${candidate_file}" || true
    fi
    printf '\n'
  } >> "${report_file}" || return 1
}

account_info_refresh_dry_run_report_write() {
  local scope="${1:-all}"
  local outfile="${2:-}"
  local domain="${3:-}"
  local ip="${4:-}"
  local target_isp="${5:-}"
  local target_country="${6:-}"
  local i proto username status target_file
  local stage_dir="" candidate_file="" state_file="" hint=""
  local -A seen_xray=() seen_ssh=()
  local -a ssh_users=()

  [[ -n "${outfile}" ]] || return 1
  ensure_account_quota_dirs
  mkdir -p "$(dirname "${outfile}")" 2>/dev/null || true
  : > "${outfile}" || return 1

  {
    printf 'Scope: %s\n' "${scope}"
    printf 'Mode: dry-run rendered content diff (tanpa write)\n'
    printf 'Target domain: %s\n' "${domain:-"-"}"
    printf 'Target ip: %s\n' "${ip:-"-"}"
    printf 'Target isp: %s\n' "${target_isp:-"-"}"
    printf 'Target country: %s\n' "${target_country:-"-"}"
    printf 'Generated: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
    printf '\n'

    if [[ "${scope}" == "all" || "${scope}" == "xray" ]]; then
      printf '[XRAY dry-run]\n'
      account_collect_files
      if (( ${#ACCOUNT_FILES[@]} == 0 )); then
        printf '(tidak ada target)\n'
      else
        for i in "${!ACCOUNT_FILES[@]}"; do
          proto="${ACCOUNT_FILE_PROTOS[$i]}"
          username="$(account_parse_username_from_file "${ACCOUNT_FILES[$i]}" "${proto}")"
          [[ -n "${username}" ]] || continue
          if [[ -n "${seen_xray["${proto}|${username}"]+x}" ]]; then
            continue
          fi
          seen_xray["${proto}|${username}"]=1
          target_file="$(account_info_refresh_target_file_for_user "${proto}" "${username}")"
          stage_dir="$(mktemp -d "${WORK_DIR}/.account-dryrun.${username}.${proto}.XXXXXX" 2>/dev/null || true)"
          candidate_file=""
          if [[ -n "${stage_dir}" && -d "${stage_dir}" ]]; then
            candidate_file="${stage_dir}/candidate.txt"
            if ! account_info_refresh_for_user "${proto}" "${username}" "${domain}" "${ip}" "" "${candidate_file}" >/dev/null 2>&1; then
              candidate_file=""
            fi
          fi
          hint=""
          [[ -n "${target_isp}" && "${target_isp}" != "-" ]] && hint="target ISP=${target_isp}, Country=${target_country:-"-"}"
          status="$(account_info_refresh_dry_run_status_for_file "${target_file}" "${candidate_file}" "${hint}")"
          printf '%s\t%s\t%s\n' "${username}@${proto}" "${status}" "${target_file}"
          if [[ -n "${candidate_file}" ]]; then
            account_info_refresh_append_diff_to_report "${outfile}" "${target_file}" "${candidate_file}" "${username}@${proto}" || true
          fi
          [[ -n "${stage_dir}" ]] && rm -rf "${stage_dir}" >/dev/null 2>&1 || true
        done
      fi
      printf '\n'
    fi

    if [[ "${scope}" == "all" || "${scope}" == "ssh" ]]; then
      printf '[SSH dry-run]\n'
      account_info_refresh_collect_ssh_users ssh_users
      if (( ${#ssh_users[@]} == 0 )); then
        printf '(tidak ada target)\n'
      else
        for username in "${ssh_users[@]}"; do
          [[ -n "${username}" ]] || continue
          if [[ -n "${seen_ssh["${username}"]+x}" ]]; then
            continue
          fi
          seen_ssh["${username}"]=1
          target_file="$(ssh_account_info_file "${username}")"
          state_file="$(ssh_user_state_resolve_file "${username}")"
          stage_dir="$(mktemp -d "${WORK_DIR}/.ssh-account-dryrun.${username}.XXXXXX" 2>/dev/null || true)"
          candidate_file=""
          hint=""
          if [[ -n "${stage_dir}" && -d "${stage_dir}" ]]; then
            candidate_file="${stage_dir}/candidate.txt"
            if [[ -f "${state_file}" ]] && ssh_account_info_refresh_from_state "${username}" "" "${candidate_file}" >/dev/null 2>&1; then
              :
            else
              candidate_file=""
              if [[ ! -f "${state_file}" ]]; then
                hint="skip-missing-managed-state"
              fi
            fi
          fi
          status="$(account_info_refresh_dry_run_status_for_file "${target_file}" "${candidate_file}" "${hint}")"
          printf '%s\t%s\t%s\n' "${username}" "${status}" "${target_file}"
          if [[ -n "${candidate_file}" ]]; then
            account_info_refresh_append_diff_to_report "${outfile}" "${target_file}" "${candidate_file}" "${username}@ssh" || true
          fi
          [[ -n "${stage_dir}" ]] && rm -rf "${stage_dir}" >/dev/null 2>&1 || true
        done
        if (( ${#seen_ssh[@]} == 0 )); then
          printf '(tidak ada target)\n'
        fi
      fi
    fi
  } > "${outfile}" || return 1

  chmod 600 "${outfile}" 2>/dev/null || true
  return 0
}

account_info_sync_after_domain_change_if_needed() {
  # Deprecated on CLI: render/startup must not trigger bulk rewrites anymore.
  return 0
}

account_info_compat_needs_refresh() {
  # Return 0 jika ditemukan file account info format kompatibilitas yang perlu disegarkan.
  # Kriteria:
  # - nama file format kompatibilitas (username.txt, belum username@proto.txt)
  # - belum memiliki blok "Links Import" modern
  # - belum memiliki baris link gRPC
  # - belum memiliki field ISP/Country
  # - belum memiliki field Path/Path Alt/Port modern
  ensure_account_quota_dirs
  account_collect_files

  if ssh_account_info_compat_needs_refresh; then
    return 0
  fi

  if (( ${#ACCOUNT_FILES[@]} == 0 )); then
    return 1
  fi

  local i f proto base
  for i in "${!ACCOUNT_FILES[@]}"; do
    f="${ACCOUNT_FILES[$i]}"
    proto="${ACCOUNT_FILE_PROTOS[$i]}"
    base="$(basename "${f}")"

    if [[ "${base}" != *@${proto}.txt ]]; then
      return 0
    fi

    if ! grep -Eq '^[[:space:]]*(Links Import:|=== LINKS IMPORT ===)[[:space:]]*$' "${f}" 2>/dev/null; then
      return 0
    fi

    if ! grep -Eq '^[[:space:]]*gRPC[[:space:]]*:' "${f}" 2>/dev/null; then
      return 0
    fi

    if ! grep -Eq '^[[:space:]]*ISP[[:space:]]*:' "${f}" 2>/dev/null; then
      return 0
    fi

    if ! grep -Eq '^[[:space:]]*Country[[:space:]]*:' "${f}" 2>/dev/null; then
      return 0
    fi

    if ! grep -Eq '^[[:space:]]*[A-Za-z0-9]+(?:[[:space:]][A-Za-z0-9]+)?[[:space:]]+Path(?:[[:space:]]+(WS|HUP|Service))?[[:space:]]*:' "${f}" 2>/dev/null; then
      return 0
    fi

    if ! grep -Eq '^[[:space:]]*[A-Za-z0-9]+(?:[[:space:]][A-Za-z0-9]+)?[[:space:]]+Path(?:[[:space:]]+(WS|HUP|Service))?[[:space:]]+Alt[[:space:]]*:' "${f}" 2>/dev/null; then
      return 0
    fi

    if ! grep -Eq '^[[:space:]]*[A-Za-z0-9]+(?:[[:space:]][A-Za-z0-9+]+)?[[:space:]]+(?:WS|HUP|gRPC|TCP\+TLS[[:space:]]+Port|Port)[[:space:]]*:' "${f}" 2>/dev/null; then
      return 0
    fi
  done

  return 1
}

account_info_compat_refresh_if_needed() {
  # Deprecated on CLI: compatibility refresh must be triggered explicitly from menu.
  return 0
}

cert_snapshot_create() {
  # args: backup_dir
  local backup_dir="$1"
  mkdir -p "${backup_dir}" || return 1
  chmod 700 "${backup_dir}" 2>/dev/null || return 1

  if [[ -f "${CERT_FULLCHAIN}" ]]; then
    cp -a "${CERT_FULLCHAIN}" "${backup_dir}/fullchain.pem" 2>/dev/null || return 1
    echo "1" > "${backup_dir}/fullchain.exists"
  else
    echo "0" > "${backup_dir}/fullchain.exists"
  fi

  if [[ -f "${CERT_PRIVKEY}" ]]; then
    cp -a "${CERT_PRIVKEY}" "${backup_dir}/privkey.pem" 2>/dev/null || return 1
    echo "1" > "${backup_dir}/privkey.exists"
  else
    echo "0" > "${backup_dir}/privkey.exists"
  fi

  return 0
}

cert_snapshot_restore() {
  # args: backup_dir
  local backup_dir="$1"
  local fullchain_exists privkey_exists
  local failed=0
  [[ -d "${backup_dir}" ]] || return 0

  fullchain_exists="$(cat "${backup_dir}/fullchain.exists" 2>/dev/null || echo "0")"
  privkey_exists="$(cat "${backup_dir}/privkey.exists" 2>/dev/null || echo "0")"

  if [[ "${fullchain_exists}" == "1" && -f "${backup_dir}/fullchain.pem" ]]; then
    cp -a "${backup_dir}/fullchain.pem" "${CERT_FULLCHAIN}" 2>/dev/null || failed=1
  else
    if [[ -e "${CERT_FULLCHAIN}" ]] && ! rm -f "${CERT_FULLCHAIN}" 2>/dev/null; then
      failed=1
    fi
  fi

  if [[ "${privkey_exists}" == "1" && -f "${backup_dir}/privkey.pem" ]]; then
    cp -a "${backup_dir}/privkey.pem" "${CERT_PRIVKEY}" 2>/dev/null || failed=1
  else
    if [[ -e "${CERT_PRIVKEY}" ]] && ! rm -f "${CERT_PRIVKEY}" 2>/dev/null; then
      failed=1
    fi
  fi

  if [[ -e "${CERT_PRIVKEY}" ]] && ! chmod 600 "${CERT_PRIVKEY}" 2>/dev/null; then
    failed=1
  fi
  if [[ -e "${CERT_FULLCHAIN}" ]] && ! chmod 600 "${CERT_FULLCHAIN}" 2>/dev/null; then
    failed=1
  fi

  return "${failed}"
}

file_replace_from_source_atomic() {
  local src="$1"
  local dest="$2"
  local dir base tmp_target mode uid gid
  [[ -n "${src}" && -f "${src}" && -n "${dest}" ]] || return 1
  dir="$(dirname "${dest}")"
  base="$(basename "${dest}")"
  mkdir -p "${dir}" 2>/dev/null || return 1
  tmp_target="$(mktemp "${dir}/.${base}.new.XXXXXX" 2>/dev/null || true)"
  [[ -n "${tmp_target}" ]] || return 1
  mode="$(stat -c '%a' "${dest}" 2>/dev/null || echo '600')"
  uid="$(stat -c '%u' "${dest}" 2>/dev/null || echo '0')"
  gid="$(stat -c '%g' "${dest}" 2>/dev/null || echo '0')"
  if ! cp -f -- "${src}" "${tmp_target}" >/dev/null 2>&1; then
    rm -f "${tmp_target}" >/dev/null 2>&1 || true
    return 1
  fi
  chmod "${mode}" "${tmp_target}" >/dev/null 2>&1 || chmod 600 "${tmp_target}" >/dev/null 2>&1 || true
  chown "${uid}:${gid}" "${tmp_target}" >/dev/null 2>&1 || chown 0:0 "${tmp_target}" >/dev/null 2>&1 || true
  if ! mv -f "${tmp_target}" "${dest}" >/dev/null 2>&1; then
    rm -f "${tmp_target}" >/dev/null 2>&1 || true
    return 1
  fi
  return 0
}

cert_stage_install_to_live() {
  local staged_fullchain="${1:-}"
  local staged_privkey="${2:-}"
  [[ -n "${staged_fullchain}" && -f "${staged_fullchain}" ]] || return 1
  [[ -n "${staged_privkey}" && -f "${staged_privkey}" ]] || return 1
  if ! file_replace_from_source_atomic "${staged_fullchain}" "${CERT_FULLCHAIN}"; then
    return 1
  fi
  if ! file_replace_from_source_atomic "${staged_privkey}" "${CERT_PRIVKEY}"; then
    return 1
  fi
  chmod 600 "${CERT_PRIVKEY}" "${CERT_FULLCHAIN}" >/dev/null 2>&1 || true
  return 0
}

domain_control_optional_file_snapshot_create() {
  local path="$1"
  local backup_dir="$2"
  local key="$3"
  mkdir -p "${backup_dir}" 2>/dev/null || return 1
  if [[ -e "${path}" || -L "${path}" ]]; then
    cp -a "${path}" "${backup_dir}/${key}.snapshot" 2>/dev/null || return 1
    printf '1\n' > "${backup_dir}/${key}.exists"
  else
    printf '0\n' > "${backup_dir}/${key}.exists"
  fi
  return 0
}

domain_control_optional_file_snapshot_restore() {
  local path="$1"
  local backup_dir="$2"
  local key="$3"
  local exists_flag="0"
  exists_flag="$(cat "${backup_dir}/${key}.exists" 2>/dev/null || printf '0')"
  if [[ "${exists_flag}" == "1" && -e "${backup_dir}/${key}.snapshot" ]]; then
    mkdir -p "$(dirname "${path}")" 2>/dev/null || true
    cp -a "${backup_dir}/${key}.snapshot" "${path}" 2>/dev/null || return 1
    return 0
  fi
  if [[ -e "${path}" || -L "${path}" ]]; then
    rm -f -- "${path}" 2>/dev/null || return 1
  fi
  return 0
}

domain_control_txn_clear() {
  DOMAIN_CTRL_TXN_ACTIVE="0"
  DOMAIN_CTRL_TXN_CERT_SNAPSHOT=""
  DOMAIN_CTRL_TXN_NGINX_BACKUP=""
  DOMAIN_CTRL_TXN_COMPAT_SNAPSHOT=""
  DOMAIN_CTRL_TXN_CF_SNAPSHOT=""
  DOMAIN_CTRL_TXN_CF_PREPARED="0"
  DOMAIN_CTRL_TXN_DOMAIN=""
  DOMAIN_CTRL_TXN_CF_ZONE_ID=""
  DOMAIN_CTRL_TXN_CF_IPV4=""
}

domain_control_txn_begin() {
  local cert_snapshot="$1"
  local nginx_backup="$2"
  local compat_snapshot="$3"
  local domain="$4"
  DOMAIN_CTRL_TXN_ACTIVE="1"
  DOMAIN_CTRL_TXN_CERT_SNAPSHOT="${cert_snapshot}"
  DOMAIN_CTRL_TXN_NGINX_BACKUP="${nginx_backup}"
  DOMAIN_CTRL_TXN_COMPAT_SNAPSHOT="${compat_snapshot}"
  DOMAIN_CTRL_TXN_CF_SNAPSHOT=""
  DOMAIN_CTRL_TXN_CF_PREPARED="0"
  DOMAIN_CTRL_TXN_DOMAIN="${domain}"
  DOMAIN_CTRL_TXN_CF_ZONE_ID=""
  DOMAIN_CTRL_TXN_CF_IPV4=""
}

domain_control_txn_register_cf_snapshot() {
  local zone_id="$1"
  local domain="$2"
  local ipv4="$3"
  local snapshot="$4"
  DOMAIN_CTRL_TXN_CF_ZONE_ID="${zone_id}"
  DOMAIN_CTRL_TXN_DOMAIN="${domain}"
  DOMAIN_CTRL_TXN_CF_IPV4="${ipv4}"
  DOMAIN_CTRL_TXN_CF_SNAPSHOT="${snapshot}"
  DOMAIN_CTRL_TXN_CF_PREPARED="0"
}

domain_control_txn_mark_cf_prepared() {
  DOMAIN_CTRL_TXN_CF_PREPARED="1"
}

domain_control_txn_restore() {
  local notes_name="$1"
  local rc=0
  declare -n notes_ref="${notes_name}"

  if [[ -n "${DOMAIN_CTRL_TXN_CF_SNAPSHOT}" && -f "${DOMAIN_CTRL_TXN_CF_SNAPSHOT}" && "${DOMAIN_CTRL_TXN_CF_PREPARED:-0}" == "1" ]]; then
    if ! cf_restore_relevant_a_records_snapshot "${DOMAIN_CTRL_TXN_CF_ZONE_ID}" "${DOMAIN_CTRL_TXN_DOMAIN}" "${DOMAIN_CTRL_TXN_CF_IPV4}" "${DOMAIN_CTRL_TXN_CF_SNAPSHOT}"; then
      notes_ref+=("restore DNS Cloudflare gagal")
      rc=1
    fi
  fi

  if [[ -n "${DOMAIN_CTRL_TXN_COMPAT_SNAPSHOT}" && -d "${DOMAIN_CTRL_TXN_COMPAT_SNAPSHOT}" ]]; then
    if ! domain_control_optional_file_snapshot_restore "${XRAY_DOMAIN_FILE}" "${DOMAIN_CTRL_TXN_COMPAT_SNAPSHOT}" compat_domain; then
      notes_ref+=("restore compat domain gagal")
      rc=1
    fi
  fi

  if [[ -n "${DOMAIN_CTRL_TXN_NGINX_BACKUP}" && -f "${DOMAIN_CTRL_TXN_NGINX_BACKUP}" ]]; then
    if ! cp -a "${DOMAIN_CTRL_TXN_NGINX_BACKUP}" "${NGINX_CONF}" >/dev/null 2>&1; then
      notes_ref+=("restore nginx conf gagal")
      rc=1
    fi
  fi

  if [[ -n "${DOMAIN_CTRL_TXN_CERT_SNAPSHOT}" && -d "${DOMAIN_CTRL_TXN_CERT_SNAPSHOT}" ]]; then
    if ! cert_snapshot_restore "${DOMAIN_CTRL_TXN_CERT_SNAPSHOT}" >/dev/null 2>&1; then
      notes_ref+=("restore sertifikat gagal")
      rc=1
    fi
  fi

  domain_control_restore_cert_runtime_after_rollback notes_ref || rc=1
  if ! domain_control_restore_stopped_services; then
    notes_ref+=("restore service runtime TLS gagal")
    rc=1
  else
    domain_control_clear_stopped_services
  fi

  [[ -n "${DOMAIN_CTRL_TXN_CF_SNAPSHOT}" ]] && rm -f "${DOMAIN_CTRL_TXN_CF_SNAPSHOT}" >/dev/null 2>&1 || true
  [[ -n "${DOMAIN_CTRL_TXN_COMPAT_SNAPSHOT}" ]] && rm -rf "${DOMAIN_CTRL_TXN_COMPAT_SNAPSHOT}" >/dev/null 2>&1 || true
  [[ -n "${DOMAIN_CTRL_TXN_CERT_SNAPSHOT}" ]] && rm -rf "${DOMAIN_CTRL_TXN_CERT_SNAPSHOT}" >/dev/null 2>&1 || true
  [[ -n "${DOMAIN_CTRL_TXN_NGINX_BACKUP}" ]] && rm -f "${DOMAIN_CTRL_TXN_NGINX_BACKUP}" >/dev/null 2>&1 || true
  domain_control_txn_clear
  return "${rc}"
}

main_info_os_get() {
  local pretty=""
  if [[ -r /etc/os-release ]]; then
    pretty="$(awk -F= '/^PRETTY_NAME=/{print $2; exit}' /etc/os-release 2>/dev/null | sed -E 's/^"//; s/"$//')"
  fi
  [[ -n "${pretty}" ]] || pretty="$(uname -sr 2>/dev/null || true)"
  [[ -n "${pretty}" ]] || pretty="-"
  echo "${pretty}"
}

main_info_ram_get() {
  local kb
  kb="$(awk '/^MemTotal:[[:space:]]+[0-9]+/{print $2; exit}' /proc/meminfo 2>/dev/null || true)"
  if [[ -z "${kb}" || ! "${kb}" =~ ^[0-9]+$ ]]; then
    echo "-"
    return 0
  fi
  awk -v kb="${kb}" 'BEGIN{
    gib = kb / 1024 / 1024;
    if (gib >= 1) {
      printf "%.2f GiB", gib;
    } else {
      printf "%.0f MiB", kb / 1024;
    }
  }'
}

main_info_uptime_get() {
  local u
  if have_cmd uptime; then
    u="$(uptime -p 2>/dev/null | sed -E 's/^up[[:space:]]+//')"
    [[ -n "${u}" ]] && { echo "${u}"; return 0; }
  fi
  u="$(awk '{print int($1)}' /proc/uptime 2>/dev/null || true)"
  if [[ -n "${u}" && "${u}" =~ ^[0-9]+$ ]]; then
    local d h m r
    d=$((u / 86400))
    r=$((u % 86400))
    h=$((r / 3600))
    r=$((r % 3600))
    m=$((r / 60))
    if (( d > 0 )); then
      echo "${d}d ${h}h ${m}m"
    elif (( h > 0 )); then
      echo "${h}h ${m}m"
    else
      echo "${m}m"
    fi
    return 0
  fi
  echo "-"
}

main_info_ip_quiet_get() {
  local ip=""
  if [[ "${MAIN_INFO_REMOTE_LOOKUPS}" == "1" ]] && have_cmd curl && have_cmd jq; then
    local json
    json="$(curl -fsSL --max-time 6 "https://api.ipify.org?format=json" 2>/dev/null || true)"
    if [[ -n "${json}" ]]; then
      ip="$(echo "${json}" | jq -r '.ip // "-"' 2>/dev/null || true)"
    fi
  fi
  if [[ -z "${ip}" || "${ip}" == "-" || "${ip}" == "0.0.0.0" ]]; then
    ip="$(detect_public_ip)"
  fi
  if [[ "${MAIN_INFO_REMOTE_LOOKUPS}" == "1" ]] && [[ -z "${ip}" || "${ip}" == "0.0.0.0" || "${ip}" == "-" ]]; then
    if have_cmd curl; then
      ip="$(curl -4fsSL --max-time 4 "https://api.ipify.org" 2>/dev/null || true)"
    elif have_cmd wget; then
      ip="$(wget -qO- --timeout=4 "https://api.ipify.org" 2>/dev/null || true)"
    fi
  fi
  if [[ "${ip}" == "0.0.0.0" ]]; then
    ip="-"
  fi
  [[ -n "${ip}" ]] || ip="-"
  echo "${ip}"
}

main_info_geo_lookup() {
  # args: ip -> prints: ip|isp|country
  local ip="$1"
  local isp="-" country="-"
  local json

  case "${ip}" in
    ""|"-"|"0.0.0.0"|"127."*|"10."*|"192.168."*|"172.16."*|"172.17."*|"172.18."*|"172.19."*|"172.2"?.*|"172.30."*|"172.31."*)
      echo "${ip}|-|-"
      return 0
      ;;
  esac

  if [[ "${MAIN_INFO_REMOTE_LOOKUPS}" == "1" ]] && [[ "${ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && have_cmd curl && have_cmd jq; then
    json="$(curl -fsSL --max-time 6 "https://ipwho.is/${ip}" 2>/dev/null || true)"
    if [[ -n "${json}" ]]; then
      [[ -z "${country}" || "${country}" == "-" ]] && country="$(echo "${json}" | jq -r 'if .success == true then (.country // "-") else "-" end' 2>/dev/null || true)"
      [[ -z "${isp}" || "${isp}" == "-" ]] && isp="$(echo "${json}" | jq -r 'if .success == true then (.connection.isp // .isp // "-") else "-" end' 2>/dev/null || true)"
    fi
    if [[ -z "${isp}" || "${isp}" == "-" || -z "${country}" || "${country}" == "-" ]]; then
      json="$(curl -fsSL --max-time 6 "https://ipapi.co/${ip}/json/" 2>/dev/null || true)"
      if [[ -n "${json}" ]]; then
        [[ -z "${country}" || "${country}" == "-" ]] && country="$(echo "${json}" | jq -r '.country_name // "-"' 2>/dev/null || true)"
        [[ -z "${isp}" || "${isp}" == "-" ]] && isp="$(echo "${json}" | jq -r '.org // .asn_org // "-" ' 2>/dev/null || true)"
      fi
    fi
  fi

  [[ -n "${isp}" && "${isp}" != "null" ]] || isp="-"
  [[ -n "${country}" && "${country}" != "null" ]] || country="-"
  [[ -n "${ip}" && "${ip}" != "null" ]] || ip="-"
  echo "${ip}|${isp}|${country}"
}

main_info_tls_expired_get() {
  local days
  days="$(cert_expiry_days_left)"
  if [[ -z "${days}" ]]; then
    echo "-"
    return 0
  fi
  if (( days < 0 )); then
    echo "Expired"
  else
    echo "${days} days"
  fi
}

main_info_warp_status_get() {
  local target mode cli_state
  if declare -F warp_mode_state_get >/dev/null 2>&1; then
    mode="$(warp_mode_state_get 2>/dev/null || true)"
    if [[ "${mode}" == "zerotrust" ]]; then
      if ! svc_exists "${WARP_ZEROTRUST_SERVICE}"; then
        echo "Zero Trust Missing"
        return 0
      fi
      if ! svc_is_active "${WARP_ZEROTRUST_SERVICE}"; then
        echo "Zero Trust Inactive"
        return 0
      fi
      if declare -F warp_zero_trust_cli_status_line_get >/dev/null 2>&1; then
        cli_state="$(warp_zero_trust_cli_status_line_get 2>/dev/null || true)"
        case "$(printf '%s' "${cli_state}" | tr '[:upper:]' '[:lower:]')" in
          *connected*|*proxying*|*healthy*)
            echo "Active (Zero Trust)"
            return 0
            ;;
        esac
      fi
      echo "Zero Trust Ready"
      return 0
    fi
  fi
  if ! svc_exists wireproxy; then
    echo "Not Installed"
    return 0
  fi
  if ! svc_is_active wireproxy; then
    echo "Inactive"
    return 0
  fi
  if declare -F warp_tier_target_cached_get >/dev/null 2>&1; then
    target="$(warp_tier_target_cached_get 2>/dev/null || true)"
  elif declare -F warp_tier_target_effective_get >/dev/null 2>&1; then
    target="$(warp_tier_target_effective_get 2>/dev/null || true)"
  else
    target="$(warp_tier_state_target_get 2>/dev/null || true)"
  fi
  case "${target}" in
    plus) echo "Active (Plus)" ;;
    free) echo "Active (Free)" ;;
    *) echo "Active" ;;
  esac
}

main_info_license_state_status_get() {
  python3 - "${AUTOSCRIPT_LICENSE_STATE_FILE}" <<'PY' 2>/dev/null || true
import json, sys
path = sys.argv[1]
try:
    with open(path, 'r', encoding='utf-8') as fh:
        state = json.load(fh)
except Exception:
    print("-")
    raise SystemExit(0)
status = str(state.get("status") or "").strip().lower()
if status in {"allowed", "cache-allow"}:
    print("aktif")
elif status:
    print("nonaktif")
else:
    print("-")
PY
}

main_info_license_status_url_get() {
  local api_url=""
  if declare -F manage_license_public_status_url >/dev/null 2>&1; then
    manage_license_public_status_url
    return 0
  fi

  api_url="${AUTOSCRIPT_LICENSE_API_URL:-${AUTOSCRIPT_LICENSE_DEFAULT_API_URL:-https://autoscript-license.minidecrypt.workers.dev/api/v1/license/check}}"
  case "${api_url}" in
    */api/v1/license/check)
      printf '%s/api/public/license/status\n' "${api_url%/api/v1/license/check}"
      return 0
      ;;
  esac
  if [[ "${api_url}" =~ ^https?://[^/]+ ]]; then
    printf '%s/api/public/license/status\n' "${BASH_REMATCH[0]}"
    return 0
  fi
  printf '%s\n' "https://autoscript-license.minidecrypt.workers.dev/api/public/license/status"
}

main_info_license_summary_get() {
  local ip="${1:-}"
  local fallback_status="-"
  local status_url=""
  local summary=""

  fallback_status="$(main_info_license_state_status_get)"
  [[ -n "${fallback_status}" ]] || fallback_status="-"

  if [[ -z "${ip}" || "${ip}" == "-" ]]; then
    printf '%s|%s\n' "${fallback_status}" "-"
    return 0
  fi

  status_url="$(main_info_license_status_url_get)"

  summary="$(
    python3 - "${status_url}" "${ip}" "${fallback_status}" <<'PY' 2>/dev/null || true
import json, math, sys, urllib.request

url, ip, fallback_status = sys.argv[1:4]
payload = json.dumps({"ip": ip}).encode("utf-8")
req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json", "User-Agent": "autoscript-manage/1.0"})

status_text = fallback_status or "-"
days_text = "-"

try:
    with urllib.request.urlopen(req, timeout=8) as resp:
        data = json.loads(resp.read().decode("utf-8", "replace"))
except Exception:
    print(f"{status_text}|{days_text}")
    raise SystemExit(0)

remote_status = str(data.get("status") or "").strip().lower()
days_remaining = data.get("days_remaining")

if remote_status == "active":
    status_text = "aktif"
elif remote_status in {"expired", "revoked", "not_found"}:
    status_text = "nonaktif"

if isinstance(days_remaining, (int, float)):
    days_value = int(math.ceil(float(days_remaining)))
    if days_value < 0:
        days_value = 0
    if status_text == "aktif":
        days_text = f"{days_value} Hari lagi"
    else:
        days_text = "Tidak aktif"

if status_text == "nonaktif" and days_text == "-":
    days_text = "Tidak aktif"

print(f"{status_text}|{days_text}")
PY
  )"

  if [[ -z "${summary}" ]]; then
    printf '%s|%s\n' "${fallback_status}" "-"
    return 0
  fi

  printf '%s\n' "${summary}"
}

account_count_by_proto() {
  # args: proto -> prints number of unique usernames from /opt/account/<proto>/*.txt
  local proto="$1"
  local dir="${ACCOUNT_ROOT}/${proto}"
  local f base username
  declare -A seen=()

  [[ -d "${dir}" ]] || { echo "0"; return 0; }
  while IFS= read -r -d '' f; do
    base="$(basename "${f}")"
    base="${base%.txt}"
    username="${base%%@*}"
    [[ -n "${username}" ]] || continue
    seen["${username}"]=1
  done < <(find "${dir}" -maxdepth 1 -type f -name '*.txt' -print0 2>/dev/null)

  echo "${#seen[@]}"
}

main_info_cache_invalidated_at_get() {
  local ts="0"
  if [[ -s "${MAIN_INFO_CACHE_INVALIDATION_FILE}" ]]; then
    ts="$(head -n1 "${MAIN_INFO_CACHE_INVALIDATION_FILE}" 2>/dev/null | tr -d '\r' | awk '{print $1}' || true)"
  fi
  [[ "${ts}" =~ ^[0-9]+$ ]] || ts="0"
  printf '%s\n' "${ts}"
}

main_info_cache_invalidate() {
  local ts tmp
  ts="$(date +%s 2>/dev/null || echo 0)"
  MAIN_INFO_CACHE_TS=0
  mkdir -p "${WORK_DIR}" 2>/dev/null || true
  tmp="$(mktemp "${WORK_DIR}/main-info.invalidate.XXXXXX" 2>/dev/null || true)"
  [[ -n "${tmp}" ]] || tmp="${WORK_DIR}/main-info.invalidate.$$"
  if printf '%s\n' "${ts}" > "${tmp}"; then
    install -m 600 "${tmp}" "${MAIN_INFO_CACHE_INVALIDATION_FILE}" >/dev/null 2>&1 || true
  fi
  rm -f "${tmp}" >/dev/null 2>&1 || true
}

main_info_cache_refresh() {
  local now elapsed ip geo isp country invalidated_at
  now="$(date +%s 2>/dev/null || echo 0)"
  invalidated_at="$(main_info_cache_invalidated_at_get)"
  if [[ "${invalidated_at}" =~ ^[0-9]+$ ]] && (( invalidated_at > MAIN_INFO_CACHE_TS )); then
    MAIN_INFO_CACHE_TS=0
  fi
  elapsed=$(( now - MAIN_INFO_CACHE_TS ))
  if (( MAIN_INFO_CACHE_TS > 0 && elapsed >= 0 && elapsed < MAIN_INFO_CACHE_TTL )); then
    return 0
  fi

  MAIN_INFO_CACHE_OS="$(main_info_os_get)"
  MAIN_INFO_CACHE_RAM="$(main_info_ram_get)"
  MAIN_INFO_CACHE_DOMAIN="$(detect_domain)"
  MAIN_INFO_CACHE_IP="$(main_info_ip_quiet_get)"

  ip="${MAIN_INFO_CACHE_IP}"
  geo="$(main_info_geo_lookup "${ip}")"
  IFS='|' read -r ip isp country <<< "${geo}"
  [[ -n "${ip}" ]] || ip="-"
  [[ -n "${isp}" ]] || isp="-"
  [[ -n "${country}" ]] || country="-"
  MAIN_INFO_CACHE_IP="${ip}"
  MAIN_INFO_CACHE_ISP="${isp}"
  MAIN_INFO_CACHE_COUNTRY="${country}"
  local license_summary license_status license_days
  license_summary="$(main_info_license_summary_get "${ip}")"
  IFS='|' read -r license_status license_days <<< "${license_summary}"
  [[ -n "${license_status}" ]] || license_status="-"
  [[ -n "${license_days}" ]] || license_days="-"
  MAIN_INFO_CACHE_LICENSE_STATUS="${license_status}"
  MAIN_INFO_CACHE_LICENSE_DAYS="${license_days}"
  MAIN_INFO_CACHE_TS="${now}"
}

main_menu_info_header_print() {
  local os ram up ip isp country domain tls warp license_status license_days
  local vless_count vmess_count trojan_count ssh_count
  local edge_icon nginx_icon xray_icon ssh_icon
  local info_label_width=20

  main_info_cache_refresh

  os="${MAIN_INFO_CACHE_OS}"
  ram="${MAIN_INFO_CACHE_RAM}"
  up="$(main_info_uptime_get)"
  ip="${MAIN_INFO_CACHE_IP}"
  isp="${MAIN_INFO_CACHE_ISP}"
  country="${MAIN_INFO_CACHE_COUNTRY}"
  domain="${MAIN_INFO_CACHE_DOMAIN}"
  license_status="${MAIN_INFO_CACHE_LICENSE_STATUS}"
  license_days="${MAIN_INFO_CACHE_LICENSE_DAYS}"
  tls="$(main_info_tls_expired_get)"
  warp="$(main_info_warp_status_get)"
  vless_count="$(account_count_by_proto "vless")"
  vmess_count="$(account_count_by_proto "vmess")"
  trojan_count="$(account_count_by_proto "trojan")"
  ssh_count="$(ssh_account_count)"
  edge_icon="$(service_status_icon "$(main_menu_edge_service_name)")"
  nginx_icon="$(service_status_icon "nginx")"
  xray_icon="$(service_status_icon "xray")"
  ssh_icon="$(service_group_status_icon "${SSHWS_DROPBEAR_SERVICE}" "${SSHWS_STUNNEL_SERVICE}" "${SSHWS_PROXY_SERVICE}")"

  printf "%-*s : %s\n" "${info_label_width}" "System OS" "${os}"
  printf "%-*s : %s\n" "${info_label_width}" "RAM" "${ram}"
  printf "%-*s : %s\n" "${info_label_width}" "Uptime" "${up}"
  printf "%-*s : %s\n" "${info_label_width}" "IP VPS" "${ip}"
  printf "%-*s : %s\n" "${info_label_width}" "ISP" "${isp}"
  printf "%-*s : %s\n" "${info_label_width}" "Country" "${country}"
  printf "%-*s : %s\n" "${info_label_width}" "Domain" "${domain}"
  printf "%-*s : %s\n" "${info_label_width}" "Status Lisensi" "${license_status}"
  printf "%-*s : %s\n" "${info_label_width}" "Masa Aktif Lisensi" "${license_days}"
  printf "%-*s : %s\n" "${info_label_width}" "TLS Expired" "${tls}"
  printf "%-*s : %s\n" "${info_label_width}" "WARP Status" "${warp}"
  hr
  main_menu_center_line "ACCOUNTS"
  main_menu_center_segments \
    "VLESS ${vless_count}" \
    "VMESS ${vmess_count}" \
    "TROJAN ${trojan_count}" \
    "SSH ${ssh_count}"
  echo
  main_menu_center_line "SERVICES"
  main_menu_center_segments \
    "Edge Mux ${edge_icon}" \
    "Nginx ${nginx_icon}" \
    "Xray ${xray_icon}" \
    "SSH ${ssh_icon}"
  hr
}

download_file_or_die() {
  local url="$1"
  local out="$2"
  local _unused_hint="${3:-}"
  local label="${4:-${_unused_hint:-$url}}"

  if ! download_file_checked "${url}" "${out}" "${label}"; then
    die "Gagal download: ${label}"
  fi
}

download_file_checked() {
  local url="$1"
  local out="$2"
  local label="${3:-$url}"

  if ! curl -fsSL --connect-timeout 15 --max-time 120 "${url}" -o "${out}"; then
    rm -f "${out}" >/dev/null 2>&1 || true
    return 1
  fi
  if [[ ! -s "${out}" ]]; then
    warn "File hasil download kosong: ${label}"
    rm -f "${out}" >/dev/null 2>&1 || true
    return 1
  fi
  return 0
}

rand_str() {
  local n="${1:-16}"
  ( set +o pipefail; tr -dc 'a-z0-9' </dev/urandom | head -c "$n" )
}

rand_email() {
  local user part
  user="$(rand_str 10)"
  part="$(rand_str 6)"
  local domains=("gmail.com" "outlook.com" "proton.me" "icloud.com" "yahoo.com")
  local idx=$(( RANDOM % ${#domains[@]} ))
  echo "${user}.${part}@${domains[$idx]}"
}

confirm_yn() {
  local prompt="$1"
  local ans
  while true; do
    if ! read -r -p "${prompt} (y/n): " ans; then
      echo
      return 1
    fi
    case "${ans,,}" in
      y|yes) return 0 ;;
      n|no) return 1 ;;
      *) echo "Input tidak valid. Jawab y/n." ;;
    esac
  done
}

confirm_yn_or_back() {
  # return: 0=yes, 1=no, 2=back
  local prompt="$1"
  local ans
  while true; do
    if ! read -r -p "${prompt} (y/n/kembali): " ans; then
      echo
      return 2
    fi
    case "${ans,,}" in
      y|yes) return 0 ;;
      n|no) return 1 ;;
      0|kembali|k|back|b) return 2 ;;
      *) echo "Input tidak valid. Jawab y/n/kembali." ;;
    esac
  done
}

confirm_menu_apply_now() {
  local prompt="$1"
  local ask_rc=0
  if confirm_yn_or_back "${prompt}"; then
    return 0
  fi
  ask_rc=$?
  if (( ask_rc == 2 )); then
    warn "Aksi dibatalkan (kembali)."
    return 2
  fi
  warn "Aksi dibatalkan."
  return 1
}

need_python3() {
  have_cmd python3 || die "python3 tidak ditemukan. Install dulu: apt-get install -y python3"
}

gen_uuid() {
  if have_cmd uuidgen; then
    uuidgen
  else
    python3 - <<'PY'
import uuid
print(uuid.uuid4())
PY
  fi
}

pause() {
  read -r -p "Tekan ENTER untuk kembali..." _ || true
}

invalid_choice() {
  warn "Pilihan tidak valid"
  pause
}

run_action() {
  local label="$1"
  shift || true
  menu_run_isolated_report "${label}" "$@"
}

menu_run_isolated_report() {
  # Jalankan aksi dalam subshell supaya error tidak menutup script,
  # lalu kembalikan status ke caller dengan warning yang konsisten.
  # args: label cmd...
  local label="$1"
  shift || true
  local rc=0
  if _run_in_strict_subshell "$@"; then
    :
  else
    rc=$?
  fi

  if (( rc != 0 )); then
    warn "${label} gagal (rc=${rc}). Kembali ke menu sebelumnya."
  fi
  return "${rc}"
}

domain_control_restore_stopped_services_strict() {
  local attempts="${1:-2}"
  local attempt svc all_restored
  [[ "${attempts}" =~ ^[0-9]+$ ]] || attempts=2
  (( attempts > 0 )) || attempts=1

  for (( attempt=1; attempt<=attempts; attempt++ )); do
    domain_control_restore_stopped_services || true
    all_restored="true"
    for svc in "${DOMAIN_CTRL_STOPPED_SERVICES[@]}"; do
      if svc_exists "${svc}" && ! svc_is_active "${svc}"; then
        all_restored="false"
        break
      fi
    done
    if [[ "${all_restored}" == "true" ]]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

_run_in_strict_subshell() {
  local restore_opts rc=0
  restore_opts="$(set +o)"
  set +e
  ( set -euo pipefail; "$@" )
  rc=$?
  eval "${restore_opts}"
  return "${rc}"
}

menu_run_isolated() {
  _run_in_strict_subshell "$@"
}

hr() {
  local w="${COLUMNS:-80}"
  local line
  if [[ ! "${w}" =~ ^[0-9]+$ ]]; then
    w=80
  fi
  if (( w < 60 )); then
    w=60
  fi
  printf -v line '%*s' "${w}" ''
  line="${line// /-}"
  echo -e "${UI_MUTED}${line}${UI_RESET}"
}

ui_menu_terminal_width() {
  local width="${COLUMNS:-}"
  if [[ ! "${width}" =~ ^[0-9]+$ ]] || (( width < 40 )); then
    if command -v tput >/dev/null 2>&1; then
      width="$(tput cols 2>/dev/null || true)"
    fi
  fi
  if [[ ! "${width}" =~ ^[0-9]+$ ]] || (( width < 40 )); then
    width=80
  fi
  printf '%s\n' "${width}"
}

main_menu_center_line() {
  local text="$1"
  local w
  local pad
  w="$(ui_menu_terminal_width)"
  if (( w < 60 )); then
    w=60
  fi
  if (( ${#text} >= w )); then
    echo "${text}"
    return 0
  fi
  pad=$(( (w - ${#text}) / 2 ))
  printf '%*s%s\n' "${pad}" '' "${text}"
}

main_menu_center_segments() {
  local joined=""
  local sep="   "
  local segment
  for segment in "$@"; do
    [[ -n "${segment}" ]] || continue
    if [[ -n "${joined}" ]]; then
      joined+="${sep}"
    fi
    joined+="${segment}"
  done
  main_menu_center_line "${joined}"
}

ui_menu_screen_begin() {
  local title_text="$1"
  local subtitle="${2:-}"
  title
  main_menu_center_line "${title_text}"
  if [[ -n "${subtitle}" ]]; then
    echo -e "${UI_MUTED}${subtitle}${UI_RESET}"
  fi
  hr
}

ui_menu_render_single_column() {
  local ref_name="$1"
  local -n menu_items="${ref_name}"
  local item key label
  for item in "${menu_items[@]}"; do
    IFS='|' read -r key label <<<"${item}"
    printf "  %b%s)%b %s\n" "${UI_ACCENT}" "${key}" "${UI_RESET}" "${label}"
  done
}

ui_menu_render_two_columns() {
  local ref_name="$1"
  local -n menu_items="${ref_name}"
  local width split total left_count right_count
  local left_num_width=0 right_num_width=0 left_label_width=0 right_label_width=0
  local i left_key left_label right_key right_label
  width="$(ui_menu_terminal_width)"
  total="${#menu_items[@]}"
  split=$(( (total + 1) / 2 ))
  left_count="${split}"
  right_count=$(( total - split ))

  for (( i=0; i<left_count; i++ )); do
    IFS='|' read -r left_key left_label <<<"${menu_items[$i]}"
    (( ${#left_key} > left_num_width )) && left_num_width=${#left_key}
    (( ${#left_label} > left_label_width )) && left_label_width=${#left_label}
  done
  for (( i=0; i<right_count; i++ )); do
    IFS='|' read -r right_key right_label <<<"${menu_items[$((split + i))]}"
    (( ${#right_key} > right_num_width )) && right_num_width=${#right_key}
    (( ${#right_label} > right_label_width )) && right_label_width=${#right_label}
  done

  local min_width=$(( 2 + left_num_width + 2 + left_label_width + 4 ))
  if (( right_count > 0 )); then
    min_width=$(( min_width + right_num_width + 2 + right_label_width ))
  fi
  if (( width < min_width )); then
    ui_menu_render_single_column "${ref_name}"
    return 0
  fi

  for (( i=0; i<left_count; i++ )); do
    IFS='|' read -r left_key left_label <<<"${menu_items[$i]}"
    if (( i < right_count )); then
      IFS='|' read -r right_key right_label <<<"${menu_items[$((split + i))]}"
      printf "  %b%*s)%b %-*s  %b%*s)%b %s\n" \
        "${UI_ACCENT}" "${left_num_width}" "${left_key}" "${UI_RESET}" "${left_label_width}" "${left_label}" \
        "${UI_ACCENT}" "${right_num_width}" "${right_key}" "${UI_RESET}" "${right_label}"
    else
      printf "  %b%*s)%b %s\n" \
        "${UI_ACCENT}" "${left_num_width}" "${left_key}" "${UI_RESET}" "${left_label}"
    fi
  done
}

ui_menu_render_two_columns_fixed() {
  local ref_name="$1"
  local -n menu_items="${ref_name}"
  local split total left_count right_count
  local left_num_width=0 right_num_width=0 left_label_width=0 right_label_width=0
  local shared_label_width=0
  local i left_key left_label right_key right_label
  total="${#menu_items[@]}"
  split=$(( (total + 1) / 2 ))
  left_count="${split}"
  right_count=$(( total - split ))

  for (( i=0; i<left_count; i++ )); do
    IFS='|' read -r left_key left_label <<<"${menu_items[$i]}"
    (( ${#left_key} > left_num_width )) && left_num_width=${#left_key}
    (( ${#left_label} > left_label_width )) && left_label_width=${#left_label}
  done
  for (( i=0; i<right_count; i++ )); do
    IFS='|' read -r right_key right_label <<<"${menu_items[$((split + i))]}"
    (( ${#right_key} > right_num_width )) && right_num_width=${#right_key}
    (( ${#right_label} > right_label_width )) && right_label_width=${#right_label}
  done

  shared_label_width="${left_label_width}"
  (( right_label_width > shared_label_width )) && shared_label_width="${right_label_width}"
  shared_label_width=$(( shared_label_width + 2 ))

  for (( i=0; i<left_count; i++ )); do
    IFS='|' read -r left_key left_label <<<"${menu_items[$i]}"
    if (( i < right_count )); then
      IFS='|' read -r right_key right_label <<<"${menu_items[$((split + i))]}"
      printf "  %b%*s)%b %-*s  %b%*s)%b %s\n" \
        "${UI_ACCENT}" "${left_num_width}" "${left_key}" "${UI_RESET}" "${shared_label_width}" "${left_label}" \
        "${UI_ACCENT}" "${right_num_width}" "${right_key}" "${UI_RESET}" "${right_label}"
    else
      printf "  %b%*s)%b %s\n" \
        "${UI_ACCENT}" "${left_num_width}" "${left_key}" "${UI_RESET}" "${left_label}"
    fi
  done
}

ui_menu_render_options() {
  local ref_name="$1"
  local -n menu_items="${ref_name}"
  local threshold="${2:-72}"
  local width count
  width="$(ui_menu_terminal_width)"
  count="${#menu_items[@]}"
  if (( count >= 4 && width >= threshold )); then
    ui_menu_render_two_columns "${ref_name}"
  else
    ui_menu_render_single_column "${ref_name}"
  fi
}

ui_spinner_wait() {
  local pid="$1"
  local label="${2:-Memproses}"
  local start_ts now elapsed frame_idx rc
  local -a frames=('|' '/' '-' '\\')

  if [[ ! "${pid}" =~ ^[0-9]+$ ]]; then
    return 1
  fi
  if [[ ! -t 1 ]]; then
    wait "${pid}"
    return $?
  fi

  start_ts="$(date +%s 2>/dev/null || echo 0)"
  frame_idx=0
  while kill -0 "${pid}" 2>/dev/null; do
    now="$(date +%s 2>/dev/null || echo "${start_ts}")"
    elapsed=$(( now - start_ts ))
    printf '\r%b' "${frames[$frame_idx]} ${label} ${UI_MUTED}(${elapsed}s)${UI_RESET}"
    frame_idx=$(( (frame_idx + 1) % ${#frames[@]} ))
    sleep 0.12
  done

  wait "${pid}"
  rc=$?
  printf '\r\033[2K'
  return "${rc}"
}

ui_run_logged_command_with_spinner() {
  local __outvar="$1"
  local label="$2"
  shift 2 || true

  local spinner_log_dir spinner_log_file spinner_pid rc
  spinner_log_dir="${WORK_DIR:-/tmp}"
  mkdir -p "${spinner_log_dir}" >/dev/null 2>&1 || spinner_log_dir="/tmp"
  spinner_log_file="$(mktemp "${spinner_log_dir}/manage-spin.XXXXXX.log")" || return 1

  (
    "$@"
  ) >"${spinner_log_file}" 2>&1 &
  spinner_pid=$!

  set +e
  ui_spinner_wait "${spinner_pid}" "${label}"
  rc=$?
  set -e

  printf -v "${__outvar}" '%s' "${spinner_log_file}"
  return "${rc}"
}

title() {
  if [[ -t 1 ]] && command -v clear >/dev/null 2>&1; then
    clear || true
  fi
  echo -e "${UI_BOLD}${UI_ACCENT}Control Panel${UI_RESET}"
  echo -e "${UI_MUTED}Host: $(hostname) | Script: ${0##*/}${UI_RESET}"
  hr
}

# -------------------------
# Service helpers
# -------------------------
svc_state() {
  local svc="$1"
  systemctl is-active "${svc}" 2>/dev/null || true
}

svc_is_active() {
  local svc="$1"
  systemctl is-active --quiet "${svc}" >/dev/null 2>&1
}

svc_wait_active() {
  # args: service [timeout_seconds]
  local svc="$1"
  local timeout="${2:-20}"
  local checks i state

  if [[ ! "${timeout}" =~ ^[0-9]+$ ]] || (( timeout <= 0 )); then
    timeout=20
  fi
  checks=$(( timeout * 4 ))
  if (( checks < 1 )); then
    checks=1
  fi

  for (( i=0; i<checks; i++ )); do
    state="$(svc_state "${svc}")"
    if [[ "${state}" == "active" ]]; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

svc_wait_inactive() {
  # args: service [timeout_seconds]
  local svc="$1"
  local timeout="${2:-20}"
  local checks i state

  if [[ ! "${timeout}" =~ ^[0-9]+$ ]] || (( timeout <= 0 )); then
    timeout=20
  fi
  checks=$(( timeout * 4 ))
  if (( checks < 1 )); then
    checks=1
  fi

  for (( i=0; i<checks; i++ )); do
    state="$(svc_state "${svc}")"
    if [[ "${state}" == "inactive" ]]; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

svc_start_checked() {
  local svc="$1"
  local timeout="${2:-20}"

  if systemctl start "${svc}" >/dev/null 2>&1 && svc_wait_active "${svc}" "${timeout}"; then
    return 0
  fi
  return 1
}

svc_stop_checked() {
  local svc="$1"
  local timeout="${2:-20}"

  if systemctl stop "${svc}" >/dev/null 2>&1 && svc_wait_inactive "${svc}" "${timeout}"; then
    return 0
  fi
  return 1
}

svc_restart_checked() {
  local svc="$1"
  local timeout="${2:-20}"
  local state=""

  if systemctl restart "${svc}" >/dev/null 2>&1; then
    if svc_wait_active "${svc}" "${timeout}"; then
      return 0
    fi
  else
    state="$(svc_state "${svc}")"
    if [[ "${state}" == "active" ]]; then
      return 1
    fi
  fi

  state="$(svc_state "${svc}")"
  if [[ "${state}" == "failed" || "${state}" == "inactive" || "${state}" == "activating" || "${state}" == "deactivating" ]]; then
    systemctl reset-failed "${svc}" >/dev/null 2>&1 || true
    sleep 1
    if systemctl start "${svc}" >/dev/null 2>&1 && svc_wait_active "${svc}" "${timeout}"; then
      return 0
    fi
  fi

  return 1
}

xray_restart_checked() {
  local state=""

  if systemctl restart xray >/dev/null 2>&1; then
    if svc_wait_active xray 60; then
      return 0
    fi
  else
    state="$(svc_state xray)"
    if [[ "${state}" == "active" ]]; then
      return 1
    fi
  fi

  state="$(svc_state xray)"
  if [[ "${state}" == "failed" || "${state}" == "inactive" || "${state}" == "activating" || "${state}" == "deactivating" ]]; then
    systemctl reset-failed xray >/dev/null 2>&1 || true
    sleep 1
    if systemctl start xray >/dev/null 2>&1 && svc_wait_active xray 60; then
      return 0
    fi
  fi

  return 1
}

xray_restart_checked_with_preflight() {
  if ! xray_confdir_required_files_check; then
    warn "Preflight konfigurasi Xray gagal: file conf.d wajib belum lengkap."
    return 1
  fi

  if have_cmd xray && ! xray_confdir_syntax_test; then
    warn "Syntax confdir Xray tidak valid. Restart dibatalkan."
    return 1
  fi

  if ! xray_restart_checked; then
    warn "Restart xray gagal."
    return 1
  fi
  return 0
}

nginx_service_listener_health_check() {
  if ! svc_exists nginx || ! svc_is_active nginx; then
    warn "nginx tidak aktif setelah operasi."
    return 1
  fi
  if ! have_cmd ss; then
    return 0
  fi
  if ss -lntp 2>/dev/null | grep -F "nginx" >/dev/null 2>&1; then
    return 0
  fi
  warn "Listener nginx tidak terdeteksi setelah operasi."
  return 1
}

nginx_restart_checked_with_listener() {
  if have_cmd nginx && ! nginx -t >/dev/null 2>&1; then
    warn "nginx -t gagal. Restart nginx dibatalkan."
    return 1
  fi
  if ! svc_restart_checked nginx 60; then
    warn "Restart nginx gagal."
    return 1
  fi
  nginx_service_listener_health_check || return 1
  return 0
}

svc_exists() {
  local svc="$1"
  local load
  load="$(systemctl show -p LoadState --value "${svc}" 2>/dev/null || true)"
  [[ -n "${load}" && "${load}" != "not-found" ]]
}

service_status_icon() {
  local svc="${1:-}"
  if [[ -z "${svc}" ]]; then
    printf '⛔\n'
    return 0
  fi
  if svc_exists "${svc}" && svc_is_active "${svc}"; then
    printf '✅\n'
  else
    printf '⛔\n'
  fi
}

service_group_status_icon() {
  local svc
  if (( $# == 0 )); then
    printf '⛔\n'
    return 0
  fi
  for svc in "$@"; do
    if ! svc_exists "${svc}" || ! svc_is_active "${svc}"; then
      printf '⛔\n'
      return 0
    fi
  done
  printf '✅\n'
}

main_menu_edge_service_name() {
  local provider active
  provider="$(edge_runtime_get_env EDGE_PROVIDER 2>/dev/null || echo "none")"
  active="$(edge_runtime_get_env EDGE_ACTIVATE_RUNTIME 2>/dev/null || echo "false")"
  if [[ "${active}" != "true" ]]; then
    printf '%s\n' "edge-mux.service"
    return 0
  fi
  case "${provider}" in
    nginx-stream) printf '%s\n' "nginx" ;;
    go) printf '%s\n' "edge-mux.service" ;;
    *) printf '%s\n' "edge-mux.service" ;;
  esac
}

ssh_account_count() {
  local count="0"
  if declare -F ssh_state_dirs_prepare >/dev/null 2>&1; then
    ssh_state_dirs_prepare >/dev/null 2>&1 || true
  fi
  [[ -d "${SSH_USERS_STATE_DIR}" ]] || {
    printf '0\n'
    return 0
  }
  count="$(find "${SSH_USERS_STATE_DIR}" -maxdepth 1 -type f -name '*.json' ! -name '.*' 2>/dev/null | wc -l | tr -d '[:space:]')"
  [[ "${count}" =~ ^[0-9]+$ ]] || count="0"
  printf '%s\n' "${count}"
}

svc_status_line() {
  local svc="$1"
  if svc_is_active "${svc}"; then
    echo "OK   - ${svc} (active)"
  else
    echo "FAIL - ${svc} (inactive)"
  fi
}

svc_restart_now() {
  local svc="$1"
  local st
  if svc_restart_checked "${svc}" 20; then
    return 0
  fi

  st="$(svc_state "${svc}")"
  echo "Restart dilakukan, tapi status masih tidak aktif: ${svc} (state=${st:-unknown})" >&2
  return 1
}

svc_restart() {
  local svc="$1"
  local spin_log=""
  if ui_run_logged_command_with_spinner spin_log "Restart ${svc}" svc_restart_now "${svc}"; then
    log "Restart sukses: ${svc}"
    rm -f "${spin_log}" >/dev/null 2>&1 || true
    return 0
  fi

  warn "Restart gagal: ${svc}"
  if [[ -n "${spin_log}" && -s "${spin_log}" ]]; then
    hr
    tail -n 30 "${spin_log}" 2>/dev/null || true
    hr
  fi
  rm -f "${spin_log}" >/dev/null 2>&1 || true
  return 1
}

svc_restart_if_exists() {
  local svc="$1"
  if systemctl cat "${svc}" >/dev/null 2>&1; then
    if svc_restart_now "${svc}" >/dev/null 2>&1; then
      return 0
    fi
    return 1
  fi
  return 1
}

svc_restart_any() {
  # args: list of service names (with or without .service)
  local s
  for s in "$@"; do
    if svc_restart_if_exists "${s}"; then
      return 0
    fi
    if [[ "${s}" != *.service ]]; then
      if svc_restart_if_exists "${s}.service"; then
        return 0
      fi
    fi
  done
  return 1
}

# -------------------------
# Account helpers (read-only)
# -------------------------
ACCOUNT_FILES=()
ACCOUNT_FILE_PROTOS=()

xray_delete_txn_runtime_deleted_contains() {
  local proto="${1:-}"
  local username="${2:-}"
  local txn_dir="" deleted_flag="" previous_cred="" current_cred=""
  [[ -n "${proto}" && -n "${username}" ]] || return 1
  mutation_txn_prepare || return 1
  while IFS= read -r -d '' txn_dir; do
    [[ -n "${txn_dir}" ]] || continue
    deleted_flag="$(mutation_txn_field_read "${txn_dir}" runtime_deleted 2>/dev/null || true)"
    if [[ "${deleted_flag}" == "1" ]]; then
      previous_cred="$(mutation_txn_field_read "${txn_dir}" previous_cred 2>/dev/null || true)"
      current_cred="$(xray_user_current_credential_get "${proto}" "${username}" 2>/dev/null || true)"
      if [[ -n "${current_cred}" && -n "${previous_cred}" && "${current_cred}" != "${previous_cred}" ]]; then
        continue
      fi
      return 0
    fi
  done < <(find "${MUTATION_TXN_DIR}" -maxdepth 1 -type d -name "xray-delete.${proto}.${username}*" -print0 2>/dev/null | sort -z)
  return 1
}

xray_add_txn_runtime_pending_contains() {
  local proto="${1:-}"
  local username="${2:-}"
  local txn_dir="" runtime_created=""
  [[ -n "${proto}" && -n "${username}" ]] || return 1
  mutation_txn_prepare || return 1
  while IFS= read -r -d '' txn_dir; do
    [[ -n "${txn_dir}" ]] || continue
    runtime_created="$(mutation_txn_field_read "${txn_dir}" runtime_created 2>/dev/null || true)"
    if [[ "${runtime_created}" != "1" ]]; then
      return 0
    fi
  done < <(find "${MUTATION_TXN_DIR}" -maxdepth 1 -type d -name "xray-add.${proto}.${username}*" -print0 2>/dev/null | sort -z)
  return 1
}

quota_cache_rebuild() {
  QUOTA_FIELDS_CACHE=()
  need_python3

  local line key val
  while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    key="${line%%|*}"
    val="${line#*|}"
    [[ -n "${key}" ]] || continue
    QUOTA_FIELDS_CACHE["${key}"]="${val}"
  done < <(python3 - <<'PY' "${QUOTA_ROOT}" "${QUOTA_PROTO_DIRS[@]}" 2>/dev/null || true
import json
import os
import sys

quota_root = sys.argv[1]
protos = tuple(sys.argv[2:])

def to_int(v, default=0):
  try:
    if v is None:
      return default
    if isinstance(v, bool):
      return int(v)
    if isinstance(v, (int, float)):
      return int(v)
    s = str(v).strip()
    if s == "":
      return default
    return int(float(s))
  except Exception:
    return default

def fmt_gb(v):
  try:
    v = float(v)
  except Exception:
    return "0"
  if v <= 0:
    return "0"
  if abs(v - round(v)) < 1e-9:
    return str(int(round(v)))
  s = f"{v:.2f}"
  s = s.rstrip("0").rstrip(".")
  return s

for proto in protos:
  d = os.path.join(quota_root, proto)
  if not os.path.isdir(d):
    continue

  chosen = {}
  chosen_has_at = {}
  for name in sorted(os.listdir(d)):
    if not name.endswith(".json"):
      continue
    base = name[:-5]
    username = base.split("@", 1)[0] if "@" in base else base
    if not username:
      continue
    has_at = "@" in base
    prev = chosen.get(username)
    if prev is not None:
      # Prefer username@proto.json over compatibility-format username.json
      if has_at and not chosen_has_at.get(username, False):
        chosen[username] = os.path.join(d, name)
        chosen_has_at[username] = True
      continue
    chosen[username] = os.path.join(d, name)
    chosen_has_at[username] = has_at

  for username in sorted(chosen.keys()):
    qf = chosen[username]
    quota_gb = "0"
    expired = "-"
    created = "-"
    ip_enabled = "false"
    ip_limit = 0

    try:
      with open(qf, "r", encoding="utf-8") as f:
        data = json.load(f)
      if isinstance(data, dict):
        ql = to_int(data.get("quota_limit"), 0)
        unit = str(data.get("quota_unit") or "binary").strip().lower()
        bpg = 1000**3 if unit in ("decimal", "gb", "1000", "gigabyte") else 1024**3
        quota_gb = fmt_gb(ql / bpg) if ql else "0"
        expired = str(data.get("expired_at") or "-")
        created = str(data.get("created_at") or "-")
        st_raw = data.get("status")
        st = st_raw if isinstance(st_raw, dict) else {}
        ip_enabled = str(bool(st.get("ip_limit_enabled"))).lower()
        ip_limit = to_int(st.get("ip_limit"), 0)
    except Exception:
      pass

    print(f"{proto}:{username}|{quota_gb}|{expired}|{created}|{ip_enabled}|{ip_limit}")
PY
)
}

account_collect_files() {
  local proto_filter="${1:-}"
  ACCOUNT_FILES=()
  ACCOUNT_FILE_PROTOS=()

  local proto dir f base u key
  declare -A pos=()
  declare -A has_at=()

  for proto in "${ACCOUNT_PROTO_DIRS[@]}"; do
    if [[ -n "${proto_filter}" && "${proto}" != "${proto_filter}" ]]; then
      continue
    fi
    dir="${ACCOUNT_ROOT}/${proto}"
    [[ -d "${dir}" ]] || continue
    while IFS= read -r -d '' f; do
      base="$(basename "${f}")"
      base="${base%.txt}"
      if [[ "${base}" == *"@"* ]]; then
        u="${base%%@*}"
      else
        u="${base}"
      fi
      key="${proto}:${u}"
      if xray_add_txn_runtime_pending_contains "${proto}" "${u}"; then
        continue
      fi
      if xray_delete_txn_runtime_deleted_contains "${proto}" "${u}"; then
        continue
      fi

      # Prefer file "username@proto.txt" over compatibility-format "username.txt" if both exist.
      if [[ -n "${pos[${key}]:-}" ]]; then
        if [[ "${base}" == *"@"* && "${has_at[${key}]:-0}" != "1" ]]; then
          ACCOUNT_FILES[${pos[${key}]}]="${f}"
          ACCOUNT_FILE_PROTOS[${pos[${key}]}]="${proto}"
          has_at["${key}"]=1
        fi
        continue
      fi

      pos["${key}"]="${#ACCOUNT_FILES[@]}"
      if [[ "${base}" == *"@"* ]]; then
        has_at["${key}"]=1
      else
        has_at["${key}"]=0
      fi

      ACCOUNT_FILES+=("${f}")
      ACCOUNT_FILE_PROTOS+=("${proto}")
    done < <(find "${dir}" -maxdepth 1 -type f -name '*.txt' -print0 2>/dev/null | sort -z)
  done

  # Tambahkan target dari quota metadata bila file account belum ada,
  # agar flow refresh/delete/reset masih bisa menemukan akun yang drift.
  for proto in "${ACCOUNT_PROTO_DIRS[@]}"; do
    if [[ -n "${proto_filter}" && "${proto}" != "${proto_filter}" ]]; then
      continue
    fi
    dir="${QUOTA_ROOT}/${proto}"
    [[ -d "${dir}" ]] || continue
    while IFS= read -r -d '' f; do
      base="$(basename "${f}")"
      base="${base%.json}"
      if [[ "${base}" == *"@"* ]]; then
        u="${base%%@*}"
      else
        u="${base}"
      fi
      [[ -n "${u}" ]] || continue
      key="${proto}:${u}"
      if xray_add_txn_runtime_pending_contains "${proto}" "${u}"; then
        continue
      fi
      if xray_delete_txn_runtime_deleted_contains "${proto}" "${u}"; then
        continue
      fi
      if [[ -n "${pos[${key}]:-}" ]]; then
        continue
      fi
      pos["${key}"]="${#ACCOUNT_FILES[@]}"
      has_at["${key}"]=1
      ACCOUNT_FILES+=("${ACCOUNT_ROOT}/${proto}/${u}@${proto}.txt")
      ACCOUNT_FILE_PROTOS+=("${proto}")
    done < <(find "${dir}" -maxdepth 1 -type f -name '*.json' -print0 2>/dev/null | sort -z)
  done

  # Tambahkan target dari runtime inbounds agar akun live tanpa file/quota
  # tetap bisa terlihat dan dipulihkan dari menu.
  local email
  while IFS= read -r email; do
    [[ -n "${email}" && "${email}" == *"@"* ]] || continue
    u="${email%%@*}"
    proto="${email##*@}"
    case "${proto}" in
      vless|vmess|trojan) ;;
      *) continue ;;
    esac
    if [[ -n "${proto_filter}" && "${proto}" != "${proto_filter}" ]]; then
      continue
    fi
    key="${proto}:${u}"
    if xray_add_txn_runtime_pending_contains "${proto}" "${u}"; then
      continue
    fi
    if xray_delete_txn_runtime_deleted_contains "${proto}" "${u}"; then
      continue
    fi
    if [[ -n "${pos[${key}]:-}" ]]; then
      continue
    fi
    pos["${key}"]="${#ACCOUNT_FILES[@]}"
    has_at["${key}"]=1
    ACCOUNT_FILES+=("${ACCOUNT_ROOT}/${proto}/${u}@${proto}.txt")
    ACCOUNT_FILE_PROTOS+=("${proto}")
  done < <(xray_inbounds_all_client_emails_get 2>/dev/null || true)

  # Build metadata cache in one Python process to avoid N subprocesses per row.
  quota_cache_rebuild
}

ACCOUNT_PAGE_SIZE=10
ACCOUNT_PAGE=0

account_total_pages() {
  local total="${#ACCOUNT_FILES[@]}"
  if (( total == 0 )); then
    echo 0
    return 0
  fi
  echo $(( (total + ACCOUNT_PAGE_SIZE - 1) / ACCOUNT_PAGE_SIZE ))
}

account_parse_username_from_file() {
  # args: file_path proto -> prints username (tanpa suffix @proto jika ada)
  local f="$1"
  local proto="$2"
  local base user
  base="$(basename "${f}")"
  base="${base%.txt}"
  if [[ "${base}" == *"@"* ]]; then
    user="${base%%@*}"
  else
    user="${base}"
  fi
  echo "${user}"
}

quota_read_fields() {
  # args: proto username -> prints: quota_gb|expired_at|created_at|ip_enabled|ip_limit
  local proto="$1"
  local username="$2"
  local key="${proto}:${username}"
  local parsed

  if [[ -n "${QUOTA_FIELDS_CACHE["${key}"]+_}" ]]; then
    echo "${QUOTA_FIELDS_CACHE["${key}"]}"
    return 0
  fi

  local qf="${QUOTA_ROOT}/${proto}/${username}@${proto}.json"
  if [[ ! -f "${qf}" ]]; then
    qf="${QUOTA_ROOT}/${proto}/${username}.json"
  fi
  if [[ ! -f "${qf}" ]]; then
    echo "-|-|-|-|-"
    return 0
  fi

  parsed="$(python3 - <<'PY' "${qf}"
import json, sys
p=sys.argv[1]
try:
  d=json.load(open(p,'r',encoding='utf-8'))
except Exception:
  print("-|-|-|-|-")
  raise SystemExit(0)
if not isinstance(d, dict):
  print("-|-|-|-|-")
  raise SystemExit(0)

def to_int(v, default=0):
  try:
    if v is None:
      return default
    if isinstance(v, bool):
      return int(v)
    if isinstance(v, (int, float)):
      return int(v)
    s=str(v).strip()
    if s == "":
      return default
    return int(float(s))
  except Exception:
    return default

def fmt_gb(v):
  try:
    v=float(v)
  except Exception:
    return "0"
  if v <= 0:
    return "0"
  if abs(v - round(v)) < 1e-9:
    return str(int(round(v)))
  s=f"{v:.2f}"
  s=s.rstrip("0").rstrip(".")
  return s

ql=to_int(d.get("quota_limit"), 0)
# Hormati quota_unit yang ditulis saat create user
unit=str(d.get("quota_unit") or "binary").strip().lower()
bpg=1000**3 if unit in ("decimal","gb","1000","gigabyte") else 1024**3
quota_gb=fmt_gb(ql/bpg) if ql else "0"
expired=d.get("expired_at") or "-"
created=d.get("created_at") or "-"
st_raw=d.get("status")
st=st_raw if isinstance(st_raw, dict) else {}
ip_en=bool(st.get("ip_limit_enabled"))
ip_lim=to_int(st.get("ip_limit"), 0)
print(f"{quota_gb}|{expired}|{created}|{str(ip_en).lower()}|{ip_lim}")
PY
)"
  QUOTA_FIELDS_CACHE["${key}"]="${parsed}"
  echo "${parsed}"
}

account_print_table_page() {
  # args: page [proto_filter]
  local page="${1:-0}"
  local proto_filter="${2:-}"
  local total="${#ACCOUNT_FILES[@]}"
  local pages
  pages="$(account_total_pages)"

  if (( total == 0 )); then
    warn "Tidak ada target akun Xray terdeteksi dari account/quota/runtime."
    return 0
  fi

  if (( page < 0 )); then page=0; fi
  if (( pages > 0 && page >= pages )); then page=$((pages - 1)); fi

  local start end i f proto username fields quota_gb expired created ip_en ip_lim
  start=$((page * ACCOUNT_PAGE_SIZE))
  end=$((start + ACCOUNT_PAGE_SIZE))
  if (( end > total )); then end="${total}"; fi

  if [[ -n "${proto_filter}" ]]; then
    printf "%-4s %-18s %-10s %-19s %-7s\n" "NO" "USERNAME" "QUOTA" "VALID UNTIL" "IP"
    printf "%-4s %-18s %-10s %-19s %-7s\n" "----" "------------------" "----------" "-------------------" "-------"
  else
    printf "%-4s %-8s %-18s %-10s %-19s %-7s\n" "NO" "PROTO" "USERNAME" "QUOTA" "VALID UNTIL" "IP"
    printf "%-4s %-8s %-18s %-10s %-19s %-7s\n" "----" "--------" "------------------" "----------" "-------------------" "-------"
  fi

  for (( i=start; i<end; i++ )); do
    f="${ACCOUNT_FILES[$i]}"
    proto="${ACCOUNT_FILE_PROTOS[$i]}"
    username="$(account_parse_username_from_file "${f}" "${proto}")"
    fields="$(quota_read_fields "${proto}" "${username}")"
    quota_gb="${fields%%|*}"
    fields="${fields#*|}"
    expired="${fields%%|*}"
    fields="${fields#*|}"
    created="${fields%%|*}"
    fields="${fields#*|}"
    ip_en="${fields%%|*}"
    ip_lim="${fields##*|}"

    local ip_show="OFF"
    if [[ "${ip_en}" == "true" ]]; then
      ip_show="ON(${ip_lim})"
    fi

    # BUG-17 fix: display page-relative row number (i - start + 1) so that
    # page 2 starts at NO=1, not NO=11. This matches user expectation when
    # entering a row number to select.
    if [[ -n "${proto_filter}" ]]; then
      printf "%-4s %-18s %-10s %-19s %-7s\n" "$((i - start + 1))" "${username}" "${quota_gb} GB" "${expired}" "${ip_show}"
    else
      printf "%-4s %-8s %-18s %-10s %-19s %-7s\n" "$((i - start + 1))" "${proto}" "${username}" "${quota_gb} GB" "${expired}" "${ip_show}"
    fi
  done

  echo
  echo "Halaman: $((page + 1))/${pages}  | Total akun: ${total}"
  if (( pages > 1 )); then
    echo "Ketik: next / previous / kembali"
  fi
}

human_size() {
  # bytes -> human-ish (KiB/MiB/GiB)
  local bytes="${1:-0}"
  local kib mib gib
  kib=$((1024))
  mib=$((1024 * 1024))
  gib=$((1024 * 1024 * 1024))

  if (( bytes >= gib )); then
    printf "%.1fGiB" "$(awk "BEGIN {print ${bytes}/${gib}}")"
  elif (( bytes >= mib )); then
    printf "%.1fMiB" "$(awk "BEGIN {print ${bytes}/${mib}}")"
  elif (( bytes >= kib )); then
    printf "%.1fKiB" "$(awk "BEGIN {print ${bytes}/${kib}}")"
  else
    printf "%dB" "${bytes}"
  fi
}

account_print_table() {
  local i f proto base mtime size
  if (( ${#ACCOUNT_FILES[@]} == 0 )); then
    warn "Tidak ada file account di ${ACCOUNT_ROOT}/{vless,vmess,trojan}"
    echo "Pastikan directory berikut ada:"
    echo "  ${ACCOUNT_ROOT}/vless"
    echo "  ${ACCOUNT_ROOT}/vmess"
    echo "  ${ACCOUNT_ROOT}/trojan"
    return 0
  fi

  printf "%-4s %-8s %-34s %-19s %-8s\n" "NO" "PROTO" "FILE" "UPDATED" "SIZE"
  printf "%-4s %-8s %-34s %-19s %-8s\n" "----" "--------" "----------------------------------" "-------------------" "--------"

  for i in "${!ACCOUNT_FILES[@]}"; do
    f="${ACCOUNT_FILES[$i]}"
    proto="${ACCOUNT_FILE_PROTOS[$i]}"
    base="$(basename "${f}")"
    mtime="$(stat -c '%y' "${f}" 2>/dev/null | cut -d'.' -f1 || echo '-')"
    size="$(stat -c '%s' "${f}" 2>/dev/null || echo '0')"
    printf "%-4s %-8s %-34s %-19s %-8s\n" "$((i + 1))" "${proto}" "${base}" "${mtime}" "$(human_size "${size}")"
  done
}

account_view_flow() {
  if (( ${#ACCOUNT_FILES[@]} == 0 )); then
    warn "Tidak ada file untuk dilihat"
    pause
    return 0
  fi

  local n f total page pages start end rows idx
  if ! read -r -p "Masukkan NO untuk view (atau kembali): " n; then
    echo
    return 0
  fi
  if is_back_choice "${n}"; then
    return 0
  fi
  [[ "${n}" =~ ^[0-9]+$ ]] || { warn "Input bukan angka"; pause; return 0; }

  total="${#ACCOUNT_FILES[@]}"
  page="${ACCOUNT_PAGE:-0}"
  pages=$(( (total + ACCOUNT_PAGE_SIZE - 1) / ACCOUNT_PAGE_SIZE ))
  if (( page < 0 )); then page=0; fi
  if (( pages > 0 && page >= pages )); then page=$((pages - 1)); fi
  start=$((page * ACCOUNT_PAGE_SIZE))
  end=$((start + ACCOUNT_PAGE_SIZE))
  if (( end > total )); then end="${total}"; fi
  rows=$((end - start))

  if (( n < 1 || n > rows )); then
    warn "NO di luar range"
    pause
    return 0
  fi

  idx=$((start + n - 1))
  f="${ACCOUNT_FILES[$idx]}"
  title
  echo "View: ${f}"
  hr
  if have_cmd less; then
    less -R "${f}"
  else
    cat "${f}"
  fi
  hr
  pause
}

account_search_flow() {
  title
  echo "Xray Users > Search"
  hr
  if ! have_cmd grep; then
    warn "grep tidak tersedia"
    pause
    return 0
  fi

  echo "Cari keyword (case-sensitive, gunakan regex bila perlu)."
  if ! read -r -p "Query: " q; then
    echo
    return 0
  fi
  if is_back_choice "${q}"; then
    return 0
  fi
  if [[ -z "${q}" ]]; then
    warn "Query kosong"
    pause
    return 0
  fi

  local matches=() proto dir f
  for proto in "${ACCOUNT_PROTO_DIRS[@]}"; do
    dir="${ACCOUNT_ROOT}/${proto}"
    [[ -d "${dir}" ]] || continue
    while IFS= read -r f; do
      [[ -n "${f}" ]] && matches+=("${f}")
    done < <(grep -RIl -- "${q}" "${dir}" 2>/dev/null || true)
  done

  title
  echo "Hasil search: ${q}"
  hr
  if (( ${#matches[@]} == 0 )); then
    warn "Tidak ada hasil."
    hr
    pause
    return 0
  fi

  local i f proto base
  printf "%-4s %-8s %-34s %s\n" "NO" "PROTO" "FILE" "PATH"
  printf "%-4s %-8s %-34s %s\n" "----" "--------" "----------------------------------" "----"
  for i in "${!matches[@]}"; do
    f="${matches[$i]}"
    proto="$(basename "$(dirname "${f}")")"
    base="$(basename "${f}")"
    printf "%-4s %-8s %-34s %s\n" "$((i + 1))" "${proto}" "${base}" "${f}"
  done
  hr
  echo "  1) View salah satu hasil"
  echo "  0) Back"
  hr
  if ! read -r -p "Pilih: " c; then
    echo
    return 0
  fi
  case "${c}" in
    1)
      if ! read -r -p "Masukkan NO untuk view (atau kembali): " n; then
        echo
        return 0
      fi
      if is_back_choice "${n}"; then
        return 0
      fi
      [[ "${n}" =~ ^[0-9]+$ ]] || { warn "Input bukan angka"; pause; return 0; }
      if (( n < 1 || n > ${#matches[@]} )); then
        warn "NO di luar range"
        pause
        return 0
      fi
      f="${matches[$((n - 1))]}"
      title
      echo "View: ${f}"
      hr
      if have_cmd less; then
        less -R "${f}"
      else
        cat "${f}"
      fi
      hr
      pause
      ;;
    0|kembali|k|back|b) : ;;
    *) : ;;
  esac
}

# -------------------------
# Diagnostics
# -------------------------
check_files() {
  local ok=0
  [[ -d "${XRAY_CONFDIR}" ]] || { warn "Tidak ada: ${XRAY_CONFDIR}"; ok=1; }
  [[ -f "${NGINX_CONF}" ]] || { warn "Tidak ada: ${NGINX_CONF}"; ok=1; }
  [[ -f "${CERT_FULLCHAIN}" ]] || { warn "Tidak ada: ${CERT_FULLCHAIN}"; ok=1; }
  [[ -f "${CERT_PRIVKEY}" ]] || { warn "Tidak ada: ${CERT_PRIVKEY}"; ok=1; }
  return "${ok}"
}

check_nginx_config() {
  if ! have_cmd nginx; then
    warn "nginx tidak tersedia, lewati nginx -t"
    return 0
  fi

  local out rc
  out="$(nginx -t 2>&1 || true)"
  if echo "${out}" | grep -q "test is successful"; then
    log "nginx -t: OK"
    return 0
  fi

  # Beberapa environment (container/sandbox terbatas) memblokir akses pid/log
  # sehingga nginx -t false-negative. Dalam kasus ini jadikan warning agar menu
  # diagnostic tetap bisa lanjut.
  if echo "${out}" | grep -Eqi "Permission denied|/var/run/nginx.pid|could not open error log file"; then
    warn "nginx -t tidak bisa diverifikasi penuh di environment ini (permission restriction)."
    echo "${out}" >&2
    return 0
  fi

  warn "nginx -t: GAGAL"
  if [[ -n "${out}" ]]; then
    echo "${out}" >&2
  else
    warn "Tidak ada output dari nginx -t"
  fi
  return 1
}

check_xray_config_json() {
  if ! xray_confdir_required_files_check; then
    die "Konfigurasi Xray (conf.d) tidak lengkap."
  fi
  if ! xray_confdir_syntax_test; then
    die "Konfigurasi Xray (conf.d) tidak lolos xray -test."
  fi
  log "Xray conf.d syntax: OK"
}

xray_confdir_required_files_check() {
  local ok=1 f
  for f in \
    "${XRAY_LOG_CONF}" \
    "${XRAY_API_CONF}" \
    "${XRAY_DNS_CONF}" \
    "${XRAY_INBOUNDS_CONF}" \
    "${XRAY_OUTBOUNDS_CONF}" \
    "${XRAY_ROUTING_CONF}" \
    "${XRAY_POLICY_CONF}" \
    "${XRAY_STATS_CONF}"; do
    if [[ ! -f "${f}" ]]; then
      warn "Konfigurasi tidak ditemukan: ${f}"
      ok=0
    fi
  done
  (( ok == 1 ))
}

xray_confdir_syntax_test() {
  # Return 0 jika syntax confdir valid atau binary xray tidak tersedia.
  # Return non-zero jika xray tersedia namun test config gagal.
  if ! have_cmd xray; then
    return 0
  fi
  xray run -test -confdir "${XRAY_CONFDIR}" >/dev/null 2>&1
}

xray_confdir_syntax_test_with_override() {
  # args: live_target candidate_file
  # Validasi seluruh confdir dengan satu file dioverride dari candidate.
  local live_target="${1:-}"
  local candidate_file="${2:-}"
  local temp_confdir="" target_rel="" override_target=""

  [[ -n "${live_target}" && -n "${candidate_file}" ]] || return 1
  if ! have_cmd xray; then
    return 0
  fi
  [[ -d "${XRAY_CONFDIR}" ]] || return 1

  temp_confdir="$(mktemp -d "${WORK_DIR}/.xray-confdir-test.XXXXXX" 2>/dev/null || true)"
  [[ -n "${temp_confdir}" && -d "${temp_confdir}" ]] || return 1
  if ! cp -a "${XRAY_CONFDIR}/." "${temp_confdir}/" >/dev/null 2>&1; then
    rm -rf "${temp_confdir}" >/dev/null 2>&1 || true
    return 1
  fi

  target_rel="${live_target#${XRAY_CONFDIR}/}"
  if [[ "${target_rel}" == "${live_target}" ]]; then
    rm -rf "${temp_confdir}" >/dev/null 2>&1 || true
    return 1
  fi
  override_target="${temp_confdir}/${target_rel}"
  mkdir -p "$(dirname "${override_target}")" 2>/dev/null || true
  if ! cp -f -- "${candidate_file}" "${override_target}" >/dev/null 2>&1; then
    rm -rf "${temp_confdir}" >/dev/null 2>&1 || true
    return 1
  fi

  if xray run -test -confdir "${temp_confdir}" >/dev/null 2>&1; then
    rm -rf "${temp_confdir}" >/dev/null 2>&1 || true
    return 0
  fi
  rm -rf "${temp_confdir}" >/dev/null 2>&1 || true
  return 1
}

nginx_conf_test_with_override() {
  # args: live_target candidate_file
  # Best-effort preflight untuk nginx conf.d dengan satu file dioverride dari candidate.
  # Return 0=valid, 1=invalid, 2=preflight tidak tersedia/tidak bisa disiapkan.
  local live_target="${1:-}"
  local candidate_file="${2:-}"
  local temp_root="" temp_confdir="" temp_main="" temp_pid="" rc=2

  [[ -n "${live_target}" && -n "${candidate_file}" ]] || return 2
  [[ -f "${live_target}" && -f "${candidate_file}" && -f "${NGINX_MAIN_CONF}" ]] || return 2
  have_cmd nginx || return 2
  have_cmd python3 || return 2

  temp_root="$(mktemp -d "${WORK_DIR}/.nginx-conf-test.XXXXXX" 2>/dev/null || true)"
  [[ -n "${temp_root}" && -d "${temp_root}" ]] || return 2
  temp_confdir="${temp_root}/conf.d"
  temp_pid="${temp_root}/nginx.pid"
  mkdir -p "${temp_confdir}" >/dev/null 2>&1 || {
    rm -rf "${temp_root}" >/dev/null 2>&1 || true
    return 2
  }

  if ! cp -a "$(dirname "${live_target}")/." "${temp_confdir}/" >/dev/null 2>&1; then
    rm -rf "${temp_root}" >/dev/null 2>&1 || true
    return 2
  fi
  if ! cp -f -- "${candidate_file}" "${temp_confdir}/$(basename "${live_target}")" >/dev/null 2>&1; then
    rm -rf "${temp_root}" >/dev/null 2>&1 || true
    return 2
  fi

  temp_main="${temp_root}/nginx.conf"
  if ! python3 - <<'PY' "${NGINX_MAIN_CONF}" "${temp_main}" "$(dirname "${live_target}")" "${temp_confdir}" "${temp_pid}" >/dev/null 2>&1
import pathlib
import re
import sys

main_src = pathlib.Path(sys.argv[1])
main_dst = pathlib.Path(sys.argv[2])
live_dir = sys.argv[3].rstrip("/")
temp_dir = sys.argv[4].rstrip("/")
temp_pid = sys.argv[5]

try:
    text = main_src.read_text(encoding="utf-8")
except Exception:
    raise SystemExit(2)

pattern = re.compile(
    rf'(^\s*include\s+){re.escape(live_dir)}/\*\.conf(\s*;\s*$)',
    re.MULTILINE,
)
updated, count = pattern.subn(
    lambda m: f"{m.group(1)}{temp_dir}/*.conf{m.group(2)}",
    text,
)
if count == 0:
    raise SystemExit(3)

pid_pattern = re.compile(r'(^\s*pid\s+)[^;]+(\s*;\s*$)', re.MULTILINE)
updated, pid_count = pid_pattern.subn(
    lambda m: f"{m.group(1)}{temp_pid}{m.group(2)}",
    updated,
    count=1,
)
if pid_count == 0:
    updated = f"pid {temp_pid};\n" + updated

try:
    main_dst.write_text(updated, encoding="utf-8")
except Exception:
    raise SystemExit(2)
PY
  then
    rc=$?
    rm -rf "${temp_root}" >/dev/null 2>&1 || true
    if (( rc == 3 )); then
      return 2
    fi
    return 2
  fi

  if nginx -t -c "${temp_main}" >/dev/null 2>&1; then
    rc=0
  else
    rc=1
  fi
  rm -rf "${temp_root}" >/dev/null 2>&1 || true
  return "${rc}"
}

xray_confdir_syntax_test_pretty() {
  # Untuk menu Diagnostics:
  # - tampilkan error penting jika ada
  # - ringkas warning deprecation transport terdepresiasi agar tidak terlihat seperti fatal error
  if ! have_cmd xray; then
    warn "xray binary tidak ditemukan"
    return 127
  fi

  local out rc filtered deprec_count
  set +e
  out="$(xray run -test -confdir "${XRAY_CONFDIR}" 2>&1)"
  rc=$?
  set -e

  filtered="$(printf '%s\n' "${out}" | grep -Ev 'common/errors: The feature .* is deprecated' || true)"
  deprec_count="$(printf '%s\n' "${out}" | grep -Ec 'common/errors: The feature .* is deprecated' || true)"

  if [[ -n "${filtered//[[:space:]]/}" ]]; then
    printf '%s\n' "${filtered}"
  fi

  if (( deprec_count > 0 )); then
    warn "Ditemukan ${deprec_count} warning deprecation transport terdepresiasi (WS/HUP/gRPC/VMess/Trojan)."
    warn "Ini warning kompatibilitas upstream, bukan syntax error conf.d."
  fi

  return "${rc}"
}


check_tls_expiry() {
  if have_cmd openssl && [[ -f "${CERT_FULLCHAIN}" ]]; then
    local end
    end="$(openssl x509 -in "${CERT_FULLCHAIN}" -noout -enddate 2>/dev/null | sed -e 's/^notAfter=//' || true)"
    if [[ -n "${end}" ]]; then
      log "TLS notAfter: ${end}"
    else
      warn "Gagal baca expiry TLS"
    fi
  else
    warn "openssl/cert tidak tersedia, lewati cek TLS"
  fi
}

show_ports() {
  if have_cmd ss; then
    ss -lntp | sed -n '1,120p'
  else
    warn "ss tidak tersedia"
  fi
}

tail_logs() {
  local target="$1"
  local tail_lines="${2:-120}"
  if [[ "${target}" == "xray" ]]; then
    journalctl -u xray --no-pager -n "${tail_lines}"
  elif [[ "${target}" == "nginx" ]]; then
    journalctl -u nginx --no-pager -n "${tail_lines}"
  else
    die "Target log tidak dikenal: ${target}"
  fi
}


show_listeners_compact() {
  # Ringkas output listeners (80/443) tanpa users:(...)
  if ! have_cmd ss; then
    warn "ss tidak tersedia"
    return 0
  fi

  printf "%-6s %-22s %-8s %s\n" "PROTO" "LOCAL" "PORT" "PROC"
  printf "%-6s %-22s %-8s %s\n" "------" "----------------------" "--------" "----"

  ss -lntpH 2>/dev/null | awk '
    $1 == "LISTEN" {
      local=$4
      port=local
      sub(/.*:/,"",port)

      if (port ~ /^(80|443)$/) {
        proc="-"
        line=$0

        if (line ~ /users:\(\("/) {
          sub(/.*users:\(\("/, "", line)
          sub(/".*/, "", line)
          if (line != "") proc=line
        }

        printf "%-6s %-22s %-8s %s\n", "tcp", local, port, proc
      }
    }
  ' || true
}

sanity_check_now() {
  title
  echo "Sanity Check (core only)"
  hr
  svc_status_line xray
  svc_status_line nginx
  hr

  echo "Daemon Status:"
  svc_status_line xray-expired
  svc_status_line xray-quota
  svc_status_line xray-limit-ip
  hr

  check_files || true
  hr
  check_nginx_config || warn "Validasi nginx gagal (lanjut cek lain)."
  check_xray_config_json
  check_tls_expiry
  hr

  echo "Listeners (ringkas):"
  show_listeners_compact
  hr
  echo "[OK] Sanity check selesai (lihat WARN bila ada)."
  pause
}


trap 'domain_control_restore_on_exit' EXIT

# -------------------------

# -------------------------
# Modular load (stage-1 split)
# -------------------------
MANAGE_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
MANAGE_REQUIRED_MODULES=(
  "core/env.sh"
  "core/router.sh"
  "core/ui.sh"
  "core/license.sh"
  "features/users.sh"
  "features/domain.sh"
  "features/maintenance.sh"
  "features/network.sh"
  "features/analytics.sh"
  "features/backup.sh"
  "menus/user_menu.sh"
  "menus/network_menu.sh"
  "menus/domain_menu.sh"
  "menus/maintenance_menu.sh"
  "menus/main_menu.sh"
  "app/main.sh"
)

manage_path_chain_trusted() {
  local target="$1"
  local modules_dir="${2:-${MANAGE_MODULES_DIR:-}}"
  local modules_root target_path modules_real target_real current owner mode
  [[ -n "${modules_dir}" ]] || return 1
  [[ -e "${target}" ]] || return 1

  modules_root="${modules_dir%/}"
  target_path="${target%/}"
  [[ "${target_path}" == "${modules_root}" || "${target_path}" == "${modules_root}/"* ]] || return 1

  modules_real="$(readlink -f -- "${modules_dir}" 2>/dev/null || true)"
  target_real="$(readlink -f -- "${target}" 2>/dev/null || true)"
  [[ -n "${modules_real}" && -n "${target_real}" ]] || return 1
  [[ "${target_real}" == "${modules_real}" || "${target_real}" == "${modules_real}/"* ]] || return 1

  if [[ "$(id -u)" -ne 0 ]]; then
    return 0
  fi

  current="${target_path}"
  while :; do
    [[ -e "${current}" ]] || return 1
    [[ -L "${current}" ]] && return 1
    owner="$(stat -c '%u' "${current}" 2>/dev/null || echo 1)"
    mode="$(stat -c '%A' "${current}" 2>/dev/null || echo '----------')"
    [[ "${owner}" == "0" ]] || return 1
    [[ "${mode:5:1}" != "w" && "${mode:8:1}" != "w" ]] || return 1
    [[ "${current}" == "${modules_root}" ]] && break
    current="$(dirname -- "${current}")"
  done
  return 0
}

manage_modules_dir_trusted() {
  local dir="$1"
  [[ -d "${dir}" ]] || return 1

  manage_path_chain_trusted "${dir}" "${dir}"
}

manage_module_file_trusted() {
  local file="$1"
  local modules_dir="${2:-${MANAGE_MODULES_DIR:-}}"
  [[ -n "${modules_dir}" ]] || return 1
  [[ -f "${file}" && -r "${file}" ]] || return 1

  manage_path_chain_trusted "${file}" "${modules_dir}"
}

manage_modules_dir_ready() {
  local dir="$1"
  local rel file
  manage_modules_dir_trusted "${dir}" || return 1
  for rel in "${MANAGE_REQUIRED_MODULES[@]}"; do
    file="${dir}/${rel}"
    [[ -r "${file}" ]] || return 1
    manage_module_file_trusted "${file}" "${dir}" || return 1
  done
  return 0
}

resolve_manage_modules_dir() {
  local installed_modules="/usr/local/lib/autoscript-manage/opt/manage"
  local local_modules="${MANAGE_SCRIPT_DIR}/opt/manage"
  if [[ "${MANAGE_SCRIPT_DIR}" != "/usr/local/bin" ]] && manage_modules_dir_ready "${local_modules}"; then
    printf '%s\n' "${local_modules}"
    return 0
  fi
  if manage_modules_dir_ready "/opt/manage"; then
    printf '%s\n' "/opt/manage"
    return 0
  fi
  if manage_modules_dir_ready "${installed_modules}"; then
    printf '%s\n' "${installed_modules}"
    return 0
  fi
  if manage_modules_dir_ready "/opt/autoscript/opt/manage"; then
    printf '%s\n' "/opt/autoscript/opt/manage"
    return 0
  fi
  if manage_modules_dir_ready "${local_modules}"; then
    printf '%s\n' "${local_modules}"
    return 0
  fi
  return 1
}

if [[ -n "${MANAGE_MODULES_DIR:-}" ]]; then
  if ! manage_modules_dir_ready "${MANAGE_MODULES_DIR}"; then
    die "MANAGE_MODULES_DIR tidak valid/tidak lengkap/tidak trusted: ${MANAGE_MODULES_DIR}"
  fi
else
  MANAGE_MODULES_DIR="$(resolve_manage_modules_dir)" \
    || die "Direktori module manage tidak ditemukan atau tidak trusted (cek /opt/manage, /usr/local/lib/autoscript-manage/opt/manage, /opt/autoscript/opt/manage, atau ${MANAGE_SCRIPT_DIR}/opt/manage)."
fi

manage_source_relative() {
  local rel="$1"
  local file="${MANAGE_MODULES_DIR}/${rel}"
  [[ -r "${file}" ]] || die "Module wajib tidak ditemukan: ${file}. Jalankan setup.sh/run.sh terbaru untuk sinkronisasi /opt/manage."
  if ! manage_module_file_trusted "${file}"; then
    die "Module wajib tidak trusted/tidak valid: ${file}. Pastikan owner root dan tidak writable oleh group/other."
  fi
  # shellcheck disable=SC1090
  . "${file}"
}

manage_source_required() {
  manage_source_relative "$1"
}

# Stage-1 modules moved out from monolith manage.sh
for _mod in "${MANAGE_REQUIRED_MODULES[@]}"; do
  manage_source_required "${_mod}"
done
unset _mod

main "$@"
