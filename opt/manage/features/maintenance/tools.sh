#!/usr/bin/env bash
# shellcheck shell=bash

AUTOSCRIPT_PACKAGE_OWNERSHIP_DIR="${AUTOSCRIPT_PACKAGE_OWNERSHIP_DIR:-/etc/autoscript/package-ownership}"

tools_external_installer_require_cmd() {
  local installer_cmd="$1"
  local label="$2"

  if [[ ! -x "${installer_cmd}" ]]; then
    warn "Installer ${label} tidak ditemukan / tidak executable:"
    echo "  ${installer_cmd}"
    echo
    echo "Hint: jalankan ulang run.sh agar installer ikut dipasang."
    hr
    pause
    return 1
  fi
  if declare -F manage_bootstrap_path_trusted >/dev/null 2>&1 && ! manage_bootstrap_path_trusted "${installer_cmd}"; then
    warn "Installer ${label} tidak trusted:"
    echo "  ${installer_cmd}"
    echo
    echo "Hint: pastikan owner root, bukan symlink, dan tidak writable oleh group/other."
    hr
    pause
    return 1
  fi
  return 0
}

tools_external_installer_exec() {
  local menu_title="$1"
  local label="$2"
  local installer_cmd="$3"
  local confirm_prompt="${4:-}"
  shift 4 || true
  local -a cmd=( "${installer_cmd}" "$@" )

  ui_menu_screen_begin "${menu_title}"
  tools_external_installer_require_cmd "${installer_cmd}" "${label}" || return 0

  echo "Menjalankan command:"
  printf '  %q' "${cmd[@]}"
  printf '\n'
  echo "Boundary:"
  echo "  - kontrol akan diserahkan ke installer eksternal"
  echo "  - installer dapat mengubah file/env/service di luar menu manage ini"
  hr

  if [[ -n "${confirm_prompt}" ]]; then
    if ! confirm_menu_apply_now "${confirm_prompt}"; then
      pause
      return 0
    fi
  fi

  if ! "${cmd[@]}"; then
    warn "Installer ${label} keluar dengan status error."
  fi
  hr
  pause
  return 0
}

install_telegram_bot_menu() {
  local installer_cmd="/usr/local/bin/install-telegram-bot"
  tools_external_installer_exec \
    "13) Tools > Telegram Bot" \
    "bot Telegram" \
    "${installer_cmd}" \
    "Serahkan kontrol ke installer bot Telegram eksternal sekarang?" \
    "menu"
  return 0
}

autoscript_license_status_menu() {
  local license_bin="/usr/local/bin/autoscript-license-check"
  local trusted_default_api_url="https://autoscript-license.minidecrypt.workers.dev/api/v1/license/check"
  local config_file="/etc/autoscript/license/config.env"

  ui_menu_screen_begin "13) Tools > License Guard"
  if [[ ! -x "${license_bin}" ]]; then
    warn "Binary license guard tidak ditemukan / tidak executable:"
    echo "  ${license_bin}"
    echo
    echo "Hint: jalankan ulang run.sh atau setup.sh agar license guard ikut dipasang."
    hr
    pause
    return 0
  fi
  if declare -F manage_bootstrap_path_trusted >/dev/null 2>&1 && ! manage_bootstrap_path_trusted "${license_bin}"; then
    warn "Binary license guard tidak trusted:"
    echo "  ${license_bin}"
    echo
    echo "Hint: pastikan owner root, bukan symlink, dan tidak writable oleh group/other."
    hr
    pause
    return 0
  fi

  if ! AUTOSCRIPT_LICENSE_DEFAULT_API_URL="${trusted_default_api_url}" \
    AUTOSCRIPT_LICENSE_API_URL="${trusted_default_api_url}" \
    AUTOSCRIPT_LICENSE_CONFIG_FILE="${config_file}" \
    "${license_bin}" status; then
    warn "Gagal membaca status license guard."
  fi
  hr
  pause
  return 0
}

autoscript_uninstall_realpath() {
  local target="${1:-}"
  python3 - <<'PY' "${target}" 2>/dev/null || true
import os
import sys
target = sys.argv[1] if len(sys.argv) > 1 else ""
if not target:
    raise SystemExit(1)
print(os.path.realpath(target))
PY
}

autoscript_uninstall_assert_safe_delete_target() {
  local target="$1"
  local label="${2:-path}"
  local resolved=""

  [[ -n "${target}" ]] || die "Path ${label} kosong; batalkan uninstall."
  resolved="$(autoscript_uninstall_realpath "${target}")"
  [[ -n "${resolved}" ]] || die "Path ${label} tidak valid: ${target}"
  [[ "${resolved}" == /* ]] || die "Path ${label} harus absolut: ${resolved}"
  if [[ "${resolved}" == *$'\n'* || "${resolved}" == *$'\r'* ]]; then
    die "Path ${label} tidak valid (mengandung newline)."
  fi

  case "${resolved}" in
    "/"|"/."|"/.."|"/bin"|"/boot"|"/dev"|"/etc"|"/home"|"/lib"|"/lib64"|"/media"|"/mnt"|"/opt"|"/proc"|"/root"|"/run"|"/sbin"|"/srv"|"/sys"|"/tmp"|"/usr"|"/var")
      die "Path ${label} terlalu berbahaya untuk dihapus: ${resolved}"
      ;;
  esac
}

autoscript_uninstall_rm_rf() {
  local target="${1:-}"
  local label="${2:-${target}}"
  [[ -e "${target}" || -L "${target}" ]] || return 0
  autoscript_uninstall_assert_safe_delete_target "${target}" "${label}"
  rm -rf "${target}" >/dev/null 2>&1 || true
  if [[ -e "${target}" || -L "${target}" ]]; then
    warn "Gagal menghapus ${label}: ${target}"
    return 1
  fi
  return 0
}

autoscript_uninstall_rm_f() {
  local target="${1:-}"
  [[ -e "${target}" || -L "${target}" ]] || return 0
  rm -f "${target}" >/dev/null 2>&1 || true
  if [[ -e "${target}" || -L "${target}" ]]; then
    warn "Gagal menghapus file: ${target}"
    return 1
  fi
  return 0
}

autoscript_uninstall_stop_disable_unit() {
  local unit="${1:-}"
  [[ -n "${unit}" ]] || return 0
  systemctl disable --now "${unit}" >/dev/null 2>&1 || systemctl stop "${unit}" >/dev/null 2>&1 || true
  systemctl reset-failed "${unit}" >/dev/null 2>&1 || true
}

autoscript_uninstall_remove_unit_file() {
  local unit="${1:-}"
  [[ -n "${unit}" ]] || return 0
  autoscript_uninstall_rm_f "/etc/systemd/system/${unit}"
  autoscript_uninstall_rm_rf "/etc/systemd/system/${unit}.d" "${unit}.d"
}

autoscript_uninstall_managed_units() {
  cat <<'EOF'
account-portal.service
autoscript-license-enforcer.service
autoscript-license-enforcer.timer
badvpn-udpgw.service
bot-telegram-backend.service
bot-telegram-gateway.service
bot-telegram-monitor.service
bot-telegram-monitor.timer
edge-mux.service
ssh-adblock-dns.service
adblock-sync.service
adblock-update.service
adblock-update.timer
ssh-expired-cleaner.service
ssh-expired-cleaner.timer
ssh-network-restore.service
sshws-dropbear.service
sshws-proxy.service
sshws-qac-enforcer.service
sshws-qac-enforcer.timer
sshws-stunnel.service
warp-zt-socks-bridge.service
wireproxy.service
xray-domain-guard.service
xray-domain-guard.timer
xray-expired.service
xray-limit-ip.service
xray-quota.service
xray-session.service
xray-speed.service
xray-xhttp3-udphop.service
xray.service
xray@.service
zivpn.service
warp-svc.service
nginx.service
dropbear.service
EOF
}

autoscript_uninstall_collect_domain() {
  if [[ -s "${XRAY_DOMAIN_FILE}" ]]; then
    head -n1 "${XRAY_DOMAIN_FILE}" 2>/dev/null | tr -d '\r' | awk '{print $1}' | tr -d ';' || true
  fi
}

autoscript_uninstall_collect_ssh_users() {
  local -a inputs=()
  local f base name

  [[ -d "${SSH_USERS_STATE_DIR}" ]] && inputs+=("${SSH_USERS_STATE_DIR}")
  [[ -d "${SSH_ACCOUNT_DIR}" ]] && inputs+=("${SSH_ACCOUNT_DIR}")
  (( ${#inputs[@]} > 0 )) || return 0

  while IFS= read -r f; do
    base="$(basename "${f}")"
    name="${base%.json}"
    name="${name%.txt}"
    name="${name%.pass}"
    name="${name%@ssh}"
    [[ -n "${name}" ]] || continue
    printf '%s\n' "${name}"
  done < <(
    find "${inputs[@]}" -maxdepth 1 -type f \
      \( -name '*@ssh.json' -o -name '*.json' -o -name '*@ssh.txt' -o -name '*.txt' -o -name '*.pass' \) \
      -print 2>/dev/null | sort -u
  ) | awk 'NF && !seen[$0]++'
}

autoscript_uninstall_delete_linux_user() {
  local username="${1:-}"
  [[ -n "${username}" ]] || return 0
  if ! id "${username}" >/dev/null 2>&1; then
    return 0
  fi
  pkill -KILL -u "${username}" >/dev/null 2>&1 || true
  if ! userdel -r "${username}" >/dev/null 2>&1; then
    warn "Gagal menghapus user Linux '${username}'."
    return 1
  fi
  return 0
}

autoscript_uninstall_delete_service_user() {
  local username="${1:-}"
  [[ -n "${username}" ]] || return 0
  if id "${username}" >/dev/null 2>&1; then
    pkill -KILL -u "${username}" >/dev/null 2>&1 || true
    userdel -r "${username}" >/dev/null 2>&1 || userdel "${username}" >/dev/null 2>&1 || true
  fi
  if getent group "${username}" >/dev/null 2>&1; then
    groupdel "${username}" >/dev/null 2>&1 || true
  fi
}

autoscript_uninstall_cleanup_runtime_network() {
  local udphop_iface="" udphop_port="" udphop_ports=""
  local warp_iface="${SSH_NETWORK_WARP_INTERFACE:-warp-ssh0}"

  if [[ -x "/usr/local/bin/xray-speed" && -f "${SPEED_CONFIG_FILE:-/etc/xray-speed/config.json}" ]]; then
    /usr/local/bin/xray-speed flush --config "${SPEED_CONFIG_FILE:-/etc/xray-speed/config.json}" >/dev/null 2>&1 || true
  fi

  if [[ -x "${XRAY_XHTTP3_UDPHOP_BIN:-/usr/local/bin/xray-xhttp3-udphop-rules}" && -f "${XRAY_XHTTP3_UDPHOP_ENV_FILE:-/etc/default/xray-xhttp3-udphop}" ]]; then
    eval "$(
      python3 - <<'PY' "${XRAY_XHTTP3_UDPHOP_ENV_FILE:-/etc/default/xray-xhttp3-udphop}" 2>/dev/null || true
import sys
path = sys.argv[1]
data = {}
try:
    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            data[key.strip()] = value.strip().strip('"').strip("'")
except OSError:
    pass
for key in ("XRAY_XHTTP3_UDPHOP_IFACE", "XRAY_XHTTP3_UDPHOP_LISTEN_PORT", "XRAY_XHTTP3_UDPHOP_PORTS"):
    print(f'{key}={data.get(key, "")!r}')
PY
    )"
    udphop_iface="${XRAY_XHTTP3_UDPHOP_IFACE:-}"
    udphop_port="${XRAY_XHTTP3_UDPHOP_LISTEN_PORT:-443}"
    udphop_ports="${XRAY_XHTTP3_UDPHOP_PORTS:-}"
    if [[ -n "${udphop_iface}" && -n "${udphop_ports}" ]]; then
      "${XRAY_XHTTP3_UDPHOP_BIN:-/usr/local/bin/xray-xhttp3-udphop-rules}" delete --iface "${udphop_iface}" --port "${udphop_port}" --ports "${udphop_ports}" >/dev/null 2>&1 || true
    fi
  fi

  if have_cmd nft; then
    nft delete table inet "${SSH_NETWORK_NFT_TABLE:-autoscript_ssh_network}" >/dev/null 2>&1 || true
    nft delete table inet "${SSH_DNS_ADBLOCK_NFT_TABLE:-autoscript_ssh_adblock}" >/dev/null 2>&1 || true
    nft delete table inet xray_speed >/dev/null 2>&1 || true
  fi

  if have_cmd ip; then
    ip route flush table "${SSH_NETWORK_ROUTE_TABLE:-42042}" >/dev/null 2>&1 || true
    ip -6 route flush table "${SSH_NETWORK_ROUTE_TABLE:-42042}" >/dev/null 2>&1 || true
    ip rule del fwmark "${SSH_NETWORK_FWMARK:-42042}" table "${SSH_NETWORK_ROUTE_TABLE:-42042}" pref "${SSH_NETWORK_RULE_PREF:-14200}" >/dev/null 2>&1 || true
    ip -6 rule del fwmark "${SSH_NETWORK_FWMARK:-42042}" table "${SSH_NETWORK_ROUTE_TABLE:-42042}" pref "${SSH_NETWORK_RULE_PREF:-14200}" >/dev/null 2>&1 || true
    ip link del "${warp_iface}" >/dev/null 2>&1 || true
  fi

  if have_cmd wg-quick; then
    wg-quick down "${warp_iface}" >/dev/null 2>&1 || true
    wg-quick down warp-xray0 >/dev/null 2>&1 || true
  fi
}

autoscript_uninstall_remove_managed_users() {
  local username=""
  while IFS= read -r username; do
    [[ -n "${username}" ]] || continue
    autoscript_uninstall_delete_linux_user "${username}" || true
  done < <(autoscript_uninstall_collect_ssh_users)

  autoscript_uninstall_delete_service_user "xray"
  autoscript_uninstall_delete_service_user "bot-telegram-gateway"
}

autoscript_uninstall_stop_orphan_processes() {
  local self="$$" bash_pid="${BASHPID:-$$}" parent="${PPID:-0}"
  local pid="" proc_cmd="" killed=0

  while IFS= read -r line; do
    pid="${line%% *}"
    proc_cmd="${line#* }"
    [[ "${pid}" =~ ^[0-9]+$ ]] || continue
    case "${pid}" in
      "${self}"|"${bash_pid}"|"${parent}") continue ;;
    esac
    case "${proc_cmd}" in
      *"/autoscript/run.sh"*|*" autoscript/run.sh"*|*"/autoscript/setup.sh"*|*" autoscript/setup.sh"*|*"/usr/local/bin/install-telegram-bot"*|*"/opt/bot-telegram/"*)
        kill -TERM "${pid}" >/dev/null 2>&1 || true
        killed=$((killed + 1))
        ;;
    esac
  done < <(ps -eo pid=,args= 2>/dev/null | awk '{$1=$1; print}')

  if (( killed > 0 )); then
    sleep 1
    while IFS= read -r line; do
      pid="${line%% *}"
      proc_cmd="${line#* }"
      [[ "${pid}" =~ ^[0-9]+$ ]] || continue
      case "${pid}" in
        "${self}"|"${bash_pid}"|"${parent}") continue ;;
      esac
      case "${proc_cmd}" in
        *"/autoscript/run.sh"*|*" autoscript/run.sh"*|*"/autoscript/setup.sh"*|*" autoscript/setup.sh"*|*"/usr/local/bin/install-telegram-bot"*|*"/opt/bot-telegram/"*)
          kill -KILL "${pid}" >/dev/null 2>&1 || true
          ;;
      esac
    done < <(ps -eo pid=,args= 2>/dev/null | awk '{$1=$1; print}')
  fi
}

autoscript_uninstall_pkg_installed() {
  local pkg="${1:-}"
  [[ -n "${pkg}" ]] || return 1
  dpkg-query -W -f='${Status}' "${pkg}" 2>/dev/null | grep -q "install ok installed"
}

autoscript_uninstall_package_owned() {
  local pkg="${1:-}"
  [[ -n "${pkg}" ]] || return 1
  [[ -f "${AUTOSCRIPT_PACKAGE_OWNERSHIP_DIR}/${pkg}.owned" ]]
}

autoscript_uninstall_snapd_safe_to_purge() {
  local snap_name=""

  autoscript_uninstall_package_owned snapd || return 1
  if ! have_cmd snap; then
    return 0
  fi
  snap list >/dev/null 2>&1 || return 1

  while IFS= read -r snap_name; do
    [[ -n "${snap_name}" ]] || continue
    case "${snap_name}" in
      Name|bare|core|core[0-9]*|snapd|speedtest)
        continue
        ;;
      *)
        return 1
        ;;
    esac
  done < <(snap list 2>/dev/null | awk 'NR > 1 {print $1}')

  return 0
}

autoscript_uninstall_purge_packages() {
  local -a purge_pkgs=(
    nginx
    nginx-common
    nginx-core
    nginx-full
    dropbear
    dropbear-bin
    stunnel4
    stunnel
    cloudflare-warp
    dnsmasq-base
    wireguard-tools
    easy-rsa
    rclone
    fail2ban
    chrony
  )
  local -a installed=()
  local pkg=""

  export DEBIAN_FRONTEND=noninteractive
  if have_cmd snap; then
    snap remove speedtest >/dev/null 2>&1 || true
  fi

  for pkg in "${purge_pkgs[@]}"; do
    if autoscript_uninstall_pkg_installed "${pkg}"; then
      installed+=("${pkg}")
    fi
  done

  if autoscript_uninstall_package_owned nodejs && autoscript_uninstall_pkg_installed nodejs; then
    installed+=("nodejs")
  fi
  if autoscript_uninstall_snapd_safe_to_purge && autoscript_uninstall_pkg_installed snapd; then
    installed+=("snapd")
  fi

  if (( ${#installed[@]} > 0 )); then
    apt-get purge -y "${installed[@]}" >/dev/null 2>&1 || warn "Sebagian package autoscript gagal dipurge."
    apt-get autoremove -y >/dev/null 2>&1 || true
  fi
}

autoscript_uninstall_warning_screen() {
  local domain="${1:-}" purge_packages="${2:-false}"
  ui_menu_screen_begin "13) Tools > Uninstall > Full Hard Uninstall"
  warn "Mode ini akan menghapus stack autoscript secara keras dari host ini."
  echo
  echo "Yang akan dihapus:"
  echo "  - service/timer autoscript (Xray stack, SSH WS, BadVPN, edge, bot, portal)"
  echo "  - akun SSH/Xray, quota, account info, runtime state, log, backup config"
  echo "  - cert/domain lokal, ACME state lokal, token/env bot, WARP/WireGuard config"
  echo "  - binary helper /usr/local/bin dan unit /etc/systemd/system milik autoscript"
  echo
  echo "Yang TIDAK dihapus:"
  if [[ "${purge_packages}" == "true" ]]; then
    echo "  - package umum host seperti curl, git, nano, python3, jq, cron, iproute2"
  else
    echo "  - package sistem / apt / snap yang sudah terpasang"
    echo "  - tool umum host seperti curl, git, nano, nginx package, dropbear package, cloudflare-warp package"
  fi
  if [[ "${purge_packages}" == "true" ]]; then
    echo
    warn "Mode purge aktif: package add-on autoscript seperti nginx/dropbear/stunnel/cloudflare-warp akan dipurge."
    echo "Node.js/snapd hanya dipurge bila ditandai dipasang oleh autoscript dan aman dibersihkan."
  fi
  if [[ -n "${domain}" ]]; then
    echo
    echo "Domain aktif terdeteksi: ${domain}"
  fi
  hr
}

autoscript_full_hard_uninstall_apply() {
  local domain="${1:-}"
  local purge_packages="${2:-false}"
  local unit="" path="" failures=0
  local -a remove_paths=()
  local -a remove_files=()

  need_root
  autoscript_uninstall_stop_orphan_processes
  autoscript_uninstall_cleanup_runtime_network

  while IFS= read -r unit; do
    [[ -n "${unit}" ]] || continue
    autoscript_uninstall_stop_disable_unit "${unit}"
  done < <(autoscript_uninstall_managed_units)

  autoscript_uninstall_remove_managed_users

  remove_files=(
    "/etc/systemd/system/xray.service.d/10-confdir.conf"
    "/etc/default/edge-runtime"
    "/etc/default/sshws-runtime"
    "/etc/default/badvpn-udpgw"
    "/etc/default/xray-xhttp3-udphop"
    "/etc/nginx/conf.d/xray.conf"
    "/etc/nginx/conf.d/00-cloudflare-realip.conf"
    "/etc/nginx/stream-conf.d/edge-stream.conf"
    "/etc/stunnel/sshws.conf"
    "/etc/cron.d/xray-update-geodata"
    "/etc/apt/sources.list.d/cloudflare-client.list"
    "/etc/apt/sources.list.d/nginx.list"
    "/etc/apt/sources.list.d/nodesource.list"
    "/etc/apt/keyrings/nodesource.gpg"
    "/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg"
    "/usr/share/keyrings/nginx-archive-keyring.gpg"
    "/usr/local/bin/manage"
    "/usr/local/bin/install-telegram-bot"
    "/usr/local/bin/backup-manage"
    "/usr/local/bin/autoscript-license-check"
    "/usr/local/bin/adblock-sync"
    "/usr/local/bin/ssh-adblock-sync"
    "/usr/local/bin/ws-proxy"
    "/usr/local/bin/sshws-proxy"
    "/usr/local/bin/sshws-control"
    "/usr/local/bin/sshws-qac-enforcer"
    "/usr/local/bin/ssh-expired-cleaner"
    "/usr/local/bin/edge-mux"
    "/usr/local/bin/edge-provider-switch"
    "/usr/local/bin/xray-domain-guard"
    "/usr/local/bin/xray-expired"
    "/usr/local/bin/limit-ip"
    "/usr/local/bin/user-block"
    "/usr/local/bin/xray-quota"
    "/usr/local/bin/xray-session"
    "/usr/local/bin/xray-speed"
    "/usr/local/bin/xray-update-geodata"
    "/usr/local/bin/xray"
    "/usr/local/bin/warp-zt-socks-bridge"
    "/usr/local/bin/ssh-warp-sync"
    "/usr/local/bin/xray-warp-sync"
    "/usr/local/bin/xray-xhttp3-udphop-rules"
    "/usr/local/bin/zivpn-password-sync"
    "/usr/local/bin/badvpn-udpgw-launcher"
    "/usr/local/bin/badvpn-udpgw"
    "/usr/local/bin/wgcf"
    "/usr/local/bin/wireproxy"
    "/usr/local/bin/zivpn"
    "/etc/logrotate.d/xray-nginx"
    "/var/lib/systemd/timers/stamp-autoscript-license-enforcer.timer"
    "/var/lib/systemd/timers/stamp-bot-telegram-monitor.timer"
    "/var/lib/systemd/timers/stamp-sshws-qac-enforcer.timer"
    "/var/lib/systemd/timers/stamp-xray-domain-guard.timer"
    "${MANAGE_AUTO_OPEN_PROFILED_FILE:-/etc/profile.d/99-autoscript-manage.sh}"
    "/etc/wireguard/${SSH_NETWORK_WARP_INTERFACE:-warp-ssh0}.conf"
    "/etc/wireguard/warp-xray0.conf"
    "/run/lock/xray-backup-restore.lock"
    "/var/lock/xray-backup-restore.lock"
  )

  remove_paths=(
    "/etc/systemd/system/xray.service.d"
    "/opt/manage"
    "/usr/local/lib/autoscript-manage"
    "${MANAGE_FALLBACK_MODULES_DST_DIR:-/usr/local/lib/autoscript-manage/opt/manage}"
    "${SETUP_FALLBACK_ROOT:-/usr/local/lib/autoscript-setup}"
    "${ACCOUNT_PORTAL_ROOT:-/opt/account-portal}"
    "/opt/bot-telegram"
    "/etc/bot-telegram"
    "/var/lib/bot-telegram"
    "/var/log/bot-telegram"
    "${ACCOUNT_ROOT:-/opt/account}/ssh"
    "${QUOTA_ROOT:-/opt/quota}/ssh"
    "${ACCOUNT_ROOT:-/opt/account}"
    "${QUOTA_ROOT:-/opt/quota}"
    "${SPEED_POLICY_ROOT:-/opt/speed}"
    "${CERT_DIR:-/opt/cert}"
    "/etc/autoscript"
    "/etc/xray"
    "${XRAY_CONFDIR:-/usr/local/etc/xray/conf.d}"
    "/usr/local/etc/xray"
    "${XRAY_ASSET_DIR:-/usr/local/share/xray}"
    "${DOMAIN_GUARD_CONFIG_DIR:-/etc/xray-domain-guard}"
    "${SPEED_CONFIG_DIR:-/etc/xray-speed}"
    "${WORK_DIR:-/var/lib/xray-manage}"
    "${SPEED_STATE_DIR:-/var/lib/xray-speed}"
    "${AUTOSCRIPT_LICENSE_STATE_DIR:-/var/lib/autoscript-license}"
    "${DOMAIN_GUARD_LOG_DIR:-/var/log/xray-domain-guard}"
    "/var/log/autoscript"
    "/var/log/xray"
    "/var/log/xray-manage"
    "/run/autoscript"
    "${WARP_ZEROTRUST_ROOT:-/etc/autoscript/warp-zerotrust}"
    "/etc/wireproxy"
    "${WGCF_DIR:-/etc/wgcf}"
    "${WIREGUARD_DIR:-/etc/wireguard}"
    "/var/lib/cloudflare-warp"
    "/etc/zivpn"
    "/var/log/zivpn"
    "/root/.acme.sh"
    "/var/lib/autoscript-backup"
    "/var/lib/autoscript-run"
    "/root/.config/rclone"
    "/root/.cache/rclone"
    "/var/lib/xray"
  )

  while IFS= read -r unit; do
    [[ -n "${unit}" ]] || continue
    autoscript_uninstall_remove_unit_file "${unit}"
  done < <(autoscript_uninstall_managed_units)

  for path in "${remove_files[@]}"; do
    [[ -n "${path}" ]] || continue
    autoscript_uninstall_rm_f "${path}" || failures=$((failures + 1))
  done

  if [[ "${purge_packages}" == "true" ]]; then
    autoscript_uninstall_purge_packages
  fi

  for path in "${remove_paths[@]}"; do
    [[ -n "${path}" ]] || continue
    autoscript_uninstall_rm_rf "${path}" "${path}" || failures=$((failures + 1))
  done

  # Pastikan subtree SSH tidak tersisa walaupun root account/quota sempat
  # diregenerasi ulang oleh proses lain di sela uninstall.
  for path in "${ACCOUNT_ROOT:-/opt/account}/ssh" "${QUOTA_ROOT:-/opt/quota}/ssh" "${ACCOUNT_ROOT:-/opt/account}" "${QUOTA_ROOT:-/opt/quota}"; do
    [[ -n "${path}" ]] || continue
    if [[ -e "${path}" ]]; then
      autoscript_uninstall_rm_rf "${path}" "${path}" || failures=$((failures + 1))
    fi
  done

  if [[ -n "${domain}" ]]; then
    autoscript_uninstall_rm_rf "/root/.acme.sh/${domain}" "acme domain ${domain}" || failures=$((failures + 1))
    autoscript_uninstall_rm_rf "/root/.acme.sh/${domain}_ecc" "acme domain ${domain}_ecc" || failures=$((failures + 1))
  fi

  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl reset-failed >/dev/null 2>&1 || true

  title
  if (( failures > 0 )); then
    echo "Full hard uninstall selesai parsial ⚠"
    echo "Ada ${failures} target yang belum terhapus bersih. Cek warning di atas."
  else
    echo "Full hard uninstall selesai ✅"
    echo "Stack autoscript, akun, cert/domain lokal, secret, dan runtime state sudah dibersihkan."
    if [[ "${purge_packages}" == "true" ]]; then
      echo "Package add-on autoscript juga sudah dicoba purge secara konservatif."
    else
      echo "Package sistem tetap dibiarkan terpasang."
    fi
  fi
  hr
  pause
  # Keluar langsung dari sesi manage yang sedang berjalan agar bootstrap/menu
  # tidak sempat membuat ulang root account/quota kosong setelah uninstall.
  exit 0
}

autoscript_full_hard_uninstall_menu() {
  local domain="" ack="" purge_packages="${1:-false}"
  need_root
  domain="$(autoscript_uninstall_collect_domain 2>/dev/null || true)"
  autoscript_uninstall_warning_screen "${domain}" "${purge_packages}"

  if ! confirm_menu_apply_now "Lanjutkan ke tahap konfirmasi full hard uninstall sekarang?"; then
    pause
    return 0
  fi
  if [[ "${purge_packages}" == "true" ]]; then
    if ! confirm_menu_apply_now "Konfirmasi purge package add-on autoscript juga?"; then
      pause
      return 0
    fi
  fi
  if ! confirm_menu_apply_now "Konfirmasi final: uninstall akan menghapus akun, cert/domain lokal, secret, dan runtime state autoscript. Lanjutkan?"; then
    pause
    return 0
  fi
  if [[ "${purge_packages}" == "true" ]]; then
    read -r -p "Ketik persis 'UNINSTALL AUTOSCRIPT PURGE' untuk lanjut full hard uninstall + purge (atau kembali): " ack || true
    if [[ "${ack}" != "UNINSTALL AUTOSCRIPT PURGE" ]]; then
      warn "Batal uninstall."
      pause
      return 0
    fi
  else
    read -r -p "Ketik persis 'UNINSTALL AUTOSCRIPT' untuk lanjut full hard uninstall (atau kembali): " ack || true
    if [[ "${ack}" != "UNINSTALL AUTOSCRIPT" ]]; then
      warn "Batal uninstall."
      pause
      return 0
    fi
  fi

  autoscript_full_hard_uninstall_apply "${domain}" "${purge_packages}"
  # shellcheck disable=SC2317
  return 0
}

autoscript_uninstall_menu() {
  # shellcheck disable=SC2034
  local -a items=(
    "1|Uninstall"
    "0|Back"
  )
  while true; do
    ui_menu_screen_begin "13) Tools > Uninstall"
    ui_menu_render_options items 76
    hr
    if ! read -r -p "Pilih: " c; then
      echo
      break
    fi
    case "${c}" in
      1|uninstall|full|hard|purge|full-purge|hard-purge) autoscript_full_hard_uninstall_menu true ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
  return 0
}
