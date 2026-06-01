#!/usr/bin/env bash
# shellcheck shell=bash

ssh_username_valid() {
  local username="${1:-}"
  [[ "${username}" =~ ^[a-z_][a-z0-9_-]{1,31}$ ]]
}

ssh_username_duplicate_reason() {
  # prints reason if duplicate exists; return 0 if duplicate, 1 otherwise.
  local username="${1:-}"
  [[ -n "${username}" ]] || return 1

  # Cegah duplikat terhadap user Linux yang sudah ada.
  if id "${username}" >/dev/null 2>&1; then
    printf "User '%s' sudah ada di sistem Linux.\n" "${username}"
    return 0
  fi

  local qf accf qf_compat accf_compat
  qf="$(ssh_user_state_file "${username}")"
  accf="$(ssh_account_info_file "${username}")"
  qf_compat="${SSH_USERS_STATE_DIR}/${username}.json"
  accf_compat="${SSH_ACCOUNT_DIR}/${username}.txt"

  # Cegah duplikat terhadap metadata managed (format baru/kompatibilitas lama).
  if [[ -f "${qf}" || -f "${accf}" || -f "${qf_compat}" || -f "${accf_compat}" ]]; then
    printf "Username '%s' sudah terdaftar pada metadata SSH managed.\n" "${username}"
    return 0
  fi

  local listed=""
  listed="$(
    find "${SSH_USERS_STATE_DIR}" -maxdepth 1 -type f -name '*.json' -printf '%f\n' 2>/dev/null \
      | sed -E 's/@ssh\.json$//' \
      | sed -E 's/\.json$//' \
      | tr '[:upper:]' '[:lower:]' \
      | grep -Fx -- "${username}" \
      | head -n1 || true
  )"
  if [[ -n "${listed}" ]]; then
    printf "Username '%s' sudah ada pada daftar akun SSH managed.\n" "${username}"
    return 0
  fi

  return 1
}

ssh_username_from_key() {
  local raw="${1:-}"
  raw="${raw%@ssh}"
  if [[ "${raw}" == *"@"* ]]; then
    raw="${raw%%@*}"
  fi
  printf '%s\n' "${raw}"
}

ssh_qac_lock_file() {
  printf '%s\n' "${SSH_QAC_LOCK_FILE:-/run/autoscript/locks/sshws-qac.lock}"
}

ssh_qac_lock_prepare() {
  local lock_file
  local lock_dir
  lock_file="$(ssh_qac_lock_file)"
  lock_dir="$(dirname "${lock_file}")"
  mkdir -p "${lock_dir}" 2>/dev/null || true
  chmod 700 "${lock_dir}" 2>/dev/null || true
}

ssh_qac_run_locked() {
  local lock_file rc=0
  if [[ "${SSH_QAC_LOCK_HELD:-0}" == "1" ]]; then
    "$@"
    return $?
  fi
  ssh_qac_lock_prepare
  lock_file="$(ssh_qac_lock_file)"
  if have_cmd flock; then
    if (
      flock -x 200 || exit 1
      SSH_QAC_LOCK_HELD=1 "$@"
    ) 200>"${lock_file}"; then
      return 0
    fi
    return $?
  fi

  SSH_QAC_LOCK_HELD=1 "$@"
  rc=$?
  return "${rc}"
}

ssh_account_info_password_mode() {
  # User-facing policy: password SSH harus tampil apa adanya di CLI.
  # Variabel legacy dibiarkan ada demi kompatibilitas, tetapi tidak lagi
  # dipakai untuk memask password di SSH ACCOUNT INFO.
  echo "store"
}

ssh_state_dirs_prepare() {
  local compat_state_dir="/var/lib/xray-manage/ssh-users"
  mkdir -p "${SSH_USERS_STATE_DIR}" "${SSH_ACCOUNT_DIR}"
  chmod 700 "${SSH_USERS_STATE_DIR}" "${SSH_ACCOUNT_DIR}" || true

  if [[ -d "${compat_state_dir}" && "${compat_state_dir}" != "${SSH_USERS_STATE_DIR}" ]]; then
    local f base username dst
    while IFS= read -r -d '' f; do
      base="$(basename "${f}")"
      base="${base%.json}"
      username="$(ssh_username_from_key "${base}")"
      [[ -n "${username}" ]] || continue
      dst="$(ssh_user_state_file "${username}")"
      if [[ ! -f "${dst}" ]]; then
        cp -a "${f}" "${dst}" >/dev/null 2>&1 || true
        chmod 600 "${dst}" >/dev/null 2>&1 || true
      elif [[ "${f}" -nt "${dst}" ]]; then
        # Jika file kompatibilitas lebih baru, sinkronkan agar metadata terbaru tidak hilang.
        cp -f "${f}" "${dst}" >/dev/null 2>&1 || true
        chmod 600 "${dst}" >/dev/null 2>&1 || true
      fi
    done < <(find "${compat_state_dir}" -maxdepth 1 -type f -name '*.json' -print0 2>/dev/null)
  fi

  local f base username dst
  while IFS= read -r -d '' f; do
    base="$(basename "${f}")"
    base="${base%.json}"
    username="$(ssh_username_from_key "${base}")"
    [[ -n "${username}" ]] || continue
    dst="$(ssh_user_state_file "${username}")"
    if [[ "${f}" != "${dst}" ]]; then
      if [[ ! -f "${dst}" ]]; then
        mv -f "${f}" "${dst}" >/dev/null 2>&1 || true
        chmod 600 "${dst}" >/dev/null 2>&1 || true
      elif [[ "${f}" -nt "${dst}" ]]; then
        # Pilih versi paling baru ketika format kompatibilitas & format canonical sama-sama ada.
        mv -f "${f}" "${dst}" >/dev/null 2>&1 || true
        chmod 600 "${dst}" >/dev/null 2>&1 || true
      else
        # Duplikat format kompatibilitas tidak dibutuhkan lagi setelah format @ssh dipakai.
        rm -f "${f}" >/dev/null 2>&1 || true
      fi
    fi
  done < <(find "${SSH_USERS_STATE_DIR}" -maxdepth 1 -type f -name '*.json' -print0 2>/dev/null)
}



ssh_user_state_file() {
  local username="${1:-}"
  printf '%s/%s@ssh.json\n' "${SSH_USERS_STATE_DIR}" "${username}"
}

ssh_user_state_lock_file() {
  local username="${1:-}"
  quota_lock_file_path "$(ssh_user_state_file "${username}")"
}

ssh_user_state_compat_file() {
  local username="${1:-}"
  printf '%s/%s.json\n' "${SSH_USERS_STATE_DIR}" "${username}"
}

ssh_user_state_compat_lock_file() {
  local username="${1:-}"
  quota_lock_file_path "$(ssh_user_state_compat_file "${username}")"
}

ssh_user_state_resolve_file() {
  local username="${1:-}"
  local primary compat
  primary="$(ssh_user_state_file "${username}")"
  compat="$(ssh_user_state_compat_file "${username}")"
  if [[ -f "${primary}" ]]; then
    printf '%s\n' "${primary}"
  elif [[ -f "${compat}" ]]; then
    printf '%s\n' "${compat}"
  else
    printf '%s\n' "${primary}"
  fi
}

ssh_account_info_file() {
  local username="${1:-}"
  printf '%s/%s@ssh.txt\n' "${SSH_ACCOUNT_DIR}" "${username}"
}

ssh_user_artifacts_cleanup_unlocked() {
  local username="${1:-}"
  local f=""
  local -a failed=()
  for f in \
    "$(ssh_user_state_file "${username}")" \
    "$(ssh_user_state_lock_file "${username}")" \
    "${SSH_USERS_STATE_DIR}/${username}.json" \
    "$(ssh_user_state_compat_lock_file "${username}")" \
    "$(ssh_account_info_file "${username}")" \
    "${SSH_ACCOUNT_DIR}/${username}.txt"; do
    [[ -e "${f}" || -L "${f}" ]] || continue
    rm -f "${f}" >/dev/null 2>&1 || true
    if [[ -e "${f}" || -L "${f}" ]]; then
      failed+=("${f}")
    fi
  done
  if (( ${#failed[@]} > 0 )); then
    printf '%s\n' "${failed[*]}"
    return 1
  fi
  return 0
}

ssh_user_artifacts_cleanup_locked() {
  local username="${1:-}"
  ssh_qac_run_locked ssh_user_artifacts_cleanup_unlocked "${username}"
}

sshws_path_prefix() {
  printf '\n'
}

sshws_token_valid() {
  local token="${1:-}"
  [[ "${token}" =~ ^[A-Fa-f0-9]{10}$ ]]
}

portal_token_valid() {
  local token="${1:-}"
  [[ "${token}" =~ ^[A-Za-z0-9_-]{10,64}$ ]]
}

sshws_path_from_token() {
  local token="${1:-}"
  if ! sshws_token_valid "${token}"; then
    return 1
  fi
  local prefix
  prefix="$(sshws_path_prefix)"
  if [[ -n "${prefix}" ]]; then
    printf '%s/%s\n' "${prefix}" "${token}"
  else
    printf '/%s\n' "${token}"
  fi
}

sshws_alt_path_from_token() {
  local token="${1:-}"
  if ! sshws_token_valid "${token}"; then
    return 1
  fi
  printf '/bebas/%s/bebas\n' "${token,,}"
}

ssh_user_state_token_get() {
  local username="${1:-}"
  local state_file
  ssh_state_dirs_prepare
  state_file="$(ssh_user_state_resolve_file "${username}")"
  [[ -s "${state_file}" ]] || {
    echo ""
    return 0
  }
  need_python3
  python3 - <<'PY' "${state_file}" 2>/dev/null || true
import json
import re
import sys

path = sys.argv[1]
token = ""
try:
  with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)
  if isinstance(data, dict):
    token = str(data.get("sshws_token") or "").strip()
except Exception:
  token = ""

if re.fullmatch(r"[A-Fa-f0-9]{10}", token):
  print(token.lower())
else:
  print("")
PY
}

ssh_user_state_ensure_token() {
  local username="${1:-}"
  local state_file tmp lock_file
  ssh_state_dirs_prepare
  state_file="$(ssh_user_state_resolve_file "${username}")"
  [[ -f "${state_file}" ]] || return 1
  ssh_qac_lock_prepare
  lock_file="$(ssh_qac_lock_file)"
  need_python3

  if have_cmd flock; then
    (
      flock -x 200
      python3 - <<'PY' "${state_file}"
import json
import os
import re
import secrets
import sys
import tempfile

path = sys.argv[1]
try:
  with open(path, "r", encoding="utf-8") as f:
    payload = json.load(f)
  if not isinstance(payload, dict):
    payload = {}
except Exception:
  payload = {}

def pick_unique_token(root_dir, current_path, current_token):
  seen = set()
  current_real = os.path.realpath(current_path)
  try:
    names = sorted(os.listdir(root_dir), key=str.lower)
  except Exception:
    names = []
  for name in names:
    if name.startswith(".") or not name.endswith(".json"):
      continue
    entry = os.path.join(root_dir, name)
    if os.path.realpath(entry) == current_real:
      continue
    try:
      loaded = json.load(open(entry, "r", encoding="utf-8"))
      if not isinstance(loaded, dict):
        continue
    except Exception:
      continue
    tok = str(loaded.get("sshws_token") or "").strip().lower()
    if re.fullmatch(r"[a-f0-9]{10}", tok):
      seen.add(tok)
  tok = str(current_token or "").strip().lower()
  if re.fullmatch(r"[a-f0-9]{10}", tok) and tok not in seen:
    return tok
  for _ in range(256):
    tok = secrets.token_hex(5)
    if tok not in seen:
      return tok
  raise RuntimeError("failed to allocate unique sshws token")

token = pick_unique_token(os.path.dirname(path) or ".", path, payload.get("sshws_token"))
if token != str(payload.get("sshws_token") or "").strip().lower():
  payload["sshws_token"] = token
  dirn = os.path.dirname(path) or "."
  fd, tmp = tempfile.mkstemp(prefix=".tmp.", suffix=".json", dir=dirn)
  try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
      json.dump(payload, f, ensure_ascii=False, indent=2)
      f.write("\n")
      f.flush()
      os.fsync(f.fileno())
    os.replace(tmp, path)
    try:
      os.chmod(path, 0o600)
    except Exception:
      pass
  finally:
    try:
      if os.path.exists(tmp):
        os.remove(tmp)
    except Exception:
      pass

print(token)
PY
    ) 200>"${lock_file}"
    return $?
  fi

  python3 - <<'PY' "${state_file}"
import json
import os
import re
import secrets
import sys
import tempfile

path = sys.argv[1]
try:
  with open(path, "r", encoding="utf-8") as f:
    payload = json.load(f)
  if not isinstance(payload, dict):
    payload = {}
except Exception:
  payload = {}

def pick_unique_token(root_dir, current_path, current_token):
  seen = set()
  current_real = os.path.realpath(current_path)
  try:
    names = sorted(os.listdir(root_dir), key=str.lower)
  except Exception:
    names = []
  for name in names:
    if name.startswith(".") or not name.endswith(".json"):
      continue
    entry = os.path.join(root_dir, name)
    if os.path.realpath(entry) == current_real:
      continue
    try:
      loaded = json.load(open(entry, "r", encoding="utf-8"))
      if not isinstance(loaded, dict):
        continue
    except Exception:
      continue
    tok = str(loaded.get("sshws_token") or "").strip().lower()
    if re.fullmatch(r"[a-f0-9]{10}", tok):
      seen.add(tok)
  tok = str(current_token or "").strip().lower()
  if re.fullmatch(r"[a-f0-9]{10}", tok) and tok not in seen:
    return tok
  for _ in range(256):
    tok = secrets.token_hex(5)
    if tok not in seen:
      return tok
  raise RuntimeError("failed to allocate unique sshws token")

token = pick_unique_token(os.path.dirname(path) or ".", path, payload.get("sshws_token"))
if token != str(payload.get("sshws_token") or "").strip().lower():
  payload["sshws_token"] = token
  dirn = os.path.dirname(path) or "."
  fd, tmp = tempfile.mkstemp(prefix=".tmp.", suffix=".json", dir=dirn)
  try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
      json.dump(payload, f, ensure_ascii=False, indent=2)
      f.write("\n")
      f.flush()
      os.fsync(f.fileno())
    os.replace(tmp, path)
    try:
      os.chmod(path, 0o600)
    except Exception:
      pass
  finally:
    try:
      if os.path.exists(tmp):
        os.remove(tmp)
    except Exception:
      pass

print(token)
PY
}

ssh_user_state_portal_token_get() {
  local username="${1:-}"
  local state_file
  ssh_state_dirs_prepare
  state_file="$(ssh_user_state_resolve_file "${username}")"
  [[ -s "${state_file}" ]] || {
    echo ""
    return 0
  }
  need_python3
  python3 - <<'PY' "${state_file}" 2>/dev/null || true
import json
import re
import sys

path = sys.argv[1]
token = ""
try:
  with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)
  if isinstance(data, dict):
    token = str(data.get("portal_token") or "").strip()
except Exception:
  token = ""

if re.fullmatch(r"[A-Za-z0-9_-]{10,64}", token):
  print(token)
else:
  print("")
PY
}

ssh_user_state_ensure_portal_token() {
  local username="${1:-}"
  local state_file lock_file
  ssh_state_dirs_prepare
  state_file="$(ssh_user_state_resolve_file "${username}")"
  [[ -f "${state_file}" ]] || return 1
  ssh_qac_lock_prepare
  lock_file="$(ssh_qac_lock_file)"
  need_python3

  if have_cmd flock; then
    (
      flock -x 200
      python3 - <<'PY' "${state_file}"
import json
import os
import re
import secrets
import sys
import tempfile
from pathlib import Path

path = Path(sys.argv[1])
try:
  with open(path, "r", encoding="utf-8") as f:
    payload = json.load(f)
  if not isinstance(payload, dict):
    payload = {}
except Exception:
  payload = {}

used = set()
quota_root = path.parent.parent
try:
  for proto_dir in quota_root.iterdir():
    if not proto_dir.is_dir():
      continue
    for entry in sorted(proto_dir.glob("*.json")):
      try:
        if entry.resolve() == path.resolve():
          continue
      except Exception:
        pass
      try:
        loaded = json.load(open(entry, "r", encoding="utf-8"))
      except Exception:
        continue
      if not isinstance(loaded, dict):
        continue
      tok = str(loaded.get("portal_token") or "").strip()
      if re.fullmatch(r"[A-Za-z0-9_-]{10,64}", tok):
        used.add(tok)
except Exception:
  pass

token = str(payload.get("portal_token") or "").strip()
if not re.fullmatch(r"[A-Za-z0-9_-]{10,64}", token) or token in used:
  token = ""
for _ in range(256):
  if token:
    break
  candidate = secrets.token_urlsafe(12).rstrip("=")
  if candidate and re.fullmatch(r"[A-Za-z0-9_-]{10,64}", candidate) and candidate not in used:
    token = candidate
    break
if not token:
  raise SystemExit(1)

if token != str(payload.get("portal_token") or "").strip():
  payload["portal_token"] = token
  dirn = str(path.parent)
  fd, tmp = tempfile.mkstemp(prefix=".tmp.", suffix=".json", dir=dirn)
  try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
      json.dump(payload, f, ensure_ascii=False, indent=2)
      f.write("\n")
      f.flush()
      os.fsync(f.fileno())
    os.replace(tmp, path)
    try:
      os.chmod(path, 0o600)
    except Exception:
      pass
  finally:
    try:
      if os.path.exists(tmp):
        os.remove(tmp)
    except Exception:
      pass

print(token)
PY
    ) 200>"${lock_file}"
    return $?
  fi

  python3 - <<'PY' "${state_file}"
import json
import os
import re
import secrets
import sys
import tempfile
from pathlib import Path

path = Path(sys.argv[1])
try:
  with open(path, "r", encoding="utf-8") as f:
    payload = json.load(f)
  if not isinstance(payload, dict):
    payload = {}
except Exception:
  payload = {}

used = set()
quota_root = path.parent.parent
try:
  for proto_dir in quota_root.iterdir():
    if not proto_dir.is_dir():
      continue
    for entry in sorted(proto_dir.glob("*.json")):
      try:
        if entry.resolve() == path.resolve():
          continue
      except Exception:
        pass
      try:
        loaded = json.load(open(entry, "r", encoding="utf-8"))
      except Exception:
        continue
      if not isinstance(loaded, dict):
        continue
      tok = str(loaded.get("portal_token") or "").strip()
      if re.fullmatch(r"[A-Za-z0-9_-]{10,64}", tok):
        used.add(tok)
except Exception:
  pass

token = str(payload.get("portal_token") or "").strip()
if not re.fullmatch(r"[A-Za-z0-9_-]{10,64}", token) or token in used:
  token = ""
for _ in range(256):
  if token:
    break
  candidate = secrets.token_urlsafe(12).rstrip("=")
  if candidate and re.fullmatch(r"[A-Za-z0-9_-]{10,64}", candidate) and candidate not in used:
    token = candidate
    break
if not token:
  raise SystemExit(1)

if token != str(payload.get("portal_token") or "").strip():
  payload["portal_token"] = token
  dirn = str(path.parent)
  fd, tmp = tempfile.mkstemp(prefix=".tmp.", suffix=".json", dir=dirn)
  try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
      json.dump(payload, f, ensure_ascii=False, indent=2)
      f.write("\n")
      f.flush()
      os.fsync(f.fileno())
    os.replace(tmp, path)
    try:
      os.chmod(path, 0o600)
    except Exception:
      pass
  finally:
    try:
      if os.path.exists(tmp):
        os.remove(tmp)
    except Exception:
      pass

print(token)
PY
}

account_portal_public_host() {
  local host=""
  host="$(normalize_domain_token "$(detect_domain 2>/dev/null || true)")"
  [[ -n "${host}" ]] || host="$(main_info_ip_quiet_get 2>/dev/null || true)"
  [[ -n "${host}" ]] || host="$(detect_public_ip 2>/dev/null || true)"
  printf '%s\n' "${host:--}"
}

ssh_account_portal_link() {
  local username="${1:-}"
  local token host
  [[ -n "${username}" ]] || return 0
  token="$(ssh_user_state_portal_token_get "${username}")"
  if ! portal_token_valid "${token}"; then
    token="$(ssh_user_state_ensure_portal_token "${username}" 2>/dev/null || true)"
  fi
  portal_token_valid "${token}" || return 0
  host="$(account_portal_public_host)"
  [[ -n "${host}" && "${host}" != "-" ]] || return 0
  printf 'https://%s/account/%s\n' "${host}" "${token}"
}

sshws_probe_path_pick() {
  echo "/diagnostic-probe"
}

ssh_user_state_created_at_get() {
  local username="${1:-}"
  local state_file
  ssh_state_dirs_prepare
  state_file="$(ssh_user_state_resolve_file "${username}")"
  [[ -s "${state_file}" ]] || {
    echo ""
    return 0
  }
  need_python3
  python3 - <<'PY' "${state_file}" 2>/dev/null || true
import json, sys
path = sys.argv[1]
try:
  with open(path, "r", encoding="utf-8") as f:
    d = json.load(f)
  print(str(d.get("created_at") or "").strip())
except Exception:
  print("")
PY
}

ssh_user_state_write() {
  local username="${1:-}" created_at="${2:-}" expired_at="${3:-}"
  local state_file tmp
  ssh_state_dirs_prepare
  state_file="$(ssh_user_state_resolve_file "${username}")"
  ssh_qac_lock_prepare
  local lock_file
  lock_file="$(ssh_qac_lock_file)"

  if have_cmd flock; then
    (
      flock -x 200
      tmp="$(mktemp "${SSH_USERS_STATE_DIR}/.${username}.XXXXXX")" || exit 1
      need_python3
      if ! python3 - <<'PY' "${state_file}" "${username}" "${created_at}" "${expired_at}" > "${tmp}"; then
import datetime
import json
import os
import re
import secrets
import sys

state_file, username, created_at, expired_at = sys.argv[1:5]

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

def to_float(v, default=0.0):
  try:
    if v is None:
      return default
    if isinstance(v, bool):
      return float(int(v))
    if isinstance(v, (int, float)):
      return float(v)
    s = str(v).strip()
    if not s:
      return default
    return float(s)
  except Exception:
    return default

def to_bool(v):
  if isinstance(v, bool):
    return v
  if isinstance(v, (int, float)):
    return bool(v)
  s = str(v or "").strip().lower()
  return s in ("1", "true", "yes", "on", "y")

def norm_date(v):
  s = str(v or "").strip()
  if not s:
    return ""
  return s[:10]

def pick_unique_token(root_dir, current_path, current_token):
  seen = set()
  current_real = os.path.realpath(current_path)
  try:
    names = sorted(os.listdir(root_dir), key=str.lower)
  except Exception:
    names = []
  for name in names:
    if name.startswith(".") or not name.endswith(".json"):
      continue
    entry = os.path.join(root_dir, name)
    if os.path.realpath(entry) == current_real:
      continue
    try:
      loaded = json.load(open(entry, "r", encoding="utf-8"))
      if not isinstance(loaded, dict):
        continue
    except Exception:
      continue
    tok = str(loaded.get("sshws_token") or "").strip().lower()
    if re.fullmatch(r"[a-f0-9]{10}", tok):
      seen.add(tok)
  tok = str(current_token or "").strip().lower()
  if re.fullmatch(r"[a-f0-9]{10}", tok) and tok not in seen:
    return tok
  for _ in range(256):
    tok = secrets.token_hex(5)
    if tok not in seen:
      return tok
  raise RuntimeError("failed to allocate unique sshws token")

payload = {}
if os.path.isfile(state_file):
  try:
    loaded = json.load(open(state_file, "r", encoding="utf-8"))
    if isinstance(loaded, dict):
      payload = loaded
  except Exception:
    payload = {}

status_raw = payload.get("status")
status = status_raw if isinstance(status_raw, dict) else {}
network_raw = payload.get("network")
network = network_raw if isinstance(network_raw, dict) else {}
network_raw = payload.get("network")
network = network_raw if isinstance(network_raw, dict) else {}

quota_limit = to_int(payload.get("quota_limit"), 0)
if quota_limit < 0:
  quota_limit = 0

quota_used = to_int(payload.get("quota_used"), 0)
if quota_used < 0:
  quota_used = 0

speed_down = to_float(status.get("speed_down_mbit"), 0.0)
speed_up = to_float(status.get("speed_up_mbit"), 0.0)
if speed_down < 0:
  speed_down = 0.0
if speed_up < 0:
  speed_up = 0.0

ip_limit = to_int(status.get("ip_limit"), 0)
if ip_limit < 0:
  ip_limit = 0

unit = str(payload.get("quota_unit") or "binary").strip().lower()
if unit not in ("binary", "decimal"):
  unit = "binary"

created = str(created_at or "").strip() or str(payload.get("created_at") or "").strip()
if created:
  created = created[:10]
if not created:
  created = datetime.datetime.now().strftime("%Y-%m-%d")

expired = norm_date(expired_at) or norm_date(payload.get("expired_at")) or "-"
token = pick_unique_token(os.path.dirname(state_file) or ".", state_file, payload.get("sshws_token"))

payload["managed_by"] = "autoscript-manage"
payload["username"] = username
payload["protocol"] = "ssh"
payload["created_at"] = created
payload["expired_at"] = expired
payload["sshws_token"] = token
payload["quota_limit"] = quota_limit
payload["quota_unit"] = unit
payload["quota_used"] = quota_used
payload["status"] = {
  "manual_block": to_bool(status.get("manual_block")),
  "quota_exhausted": to_bool(status.get("quota_exhausted")),
  "ip_limit_enabled": to_bool(status.get("ip_limit_enabled")),
  "ip_limit": ip_limit,
  "ip_limit_locked": to_bool(status.get("ip_limit_locked")),
  "ip_limit_metric": to_int(status.get("ip_limit_metric"), 0),
  "distinct_ip_count": to_int(status.get("distinct_ip_count"), 0),
  "distinct_ips": status.get("distinct_ips") if isinstance(status.get("distinct_ips"), list) else [],
  "active_sessions_total": to_int(status.get("active_sessions_total"), 0),
  "active_sessions_runtime": to_int(status.get("active_sessions_runtime"), 0),
  "active_sessions_dropbear": to_int(status.get("active_sessions_dropbear"), 0),
  "speed_limit_enabled": to_bool(status.get("speed_limit_enabled")),
  "speed_down_mbit": speed_down,
  "speed_up_mbit": speed_up,
  "lock_reason": str(status.get("lock_reason") or "").strip().lower(),
  "account_locked": to_bool(status.get("account_locked")),
  "lock_owner": str(status.get("lock_owner") or "").strip(),
  "lock_shell_restore": str(status.get("lock_shell_restore") or "").strip(),
}
payload["bootstrap_review_needed"] = to_bool(payload.get("bootstrap_review_needed"))
payload["bootstrap_source"] = str(payload.get("bootstrap_source") or "").strip()

print(json.dumps(payload, ensure_ascii=False, indent=2))
PY
        rm -f "${tmp}" >/dev/null 2>&1 || true
        exit 1
      fi
      printf '\n' >> "${tmp}"
      install -m 600 "${tmp}" "${state_file}" || {
        rm -f "${tmp}" >/dev/null 2>&1 || true
        exit 1
      }
      rm -f "${tmp}" >/dev/null 2>&1 || true
      exit 0
    ) 200>"${lock_file}"
    return $?
  fi

  tmp="$(mktemp "${SSH_USERS_STATE_DIR}/.${username}.XXXXXX")" || return 1
  need_python3
  if ! python3 - <<'PY' "${state_file}" "${username}" "${created_at}" "${expired_at}" > "${tmp}"; then
import datetime
import json
import os
import re
import secrets
import sys

state_file, username, created_at, expired_at = sys.argv[1:5]

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

def to_float(v, default=0.0):
  try:
    if v is None:
      return default
    if isinstance(v, bool):
      return float(int(v))
    if isinstance(v, (int, float)):
      return float(v)
    s = str(v).strip()
    if not s:
      return default
    return float(s)
  except Exception:
    return default

def to_bool(v):
  if isinstance(v, bool):
    return v
  if isinstance(v, (int, float)):
    return bool(v)
  s = str(v or "").strip().lower()
  return s in ("1", "true", "yes", "on", "y")

def norm_date(v):
  s = str(v or "").strip()
  if not s:
    return ""
  return s[:10]

def pick_unique_token(root_dir, current_path, current_token):
  seen = set()
  current_real = os.path.realpath(current_path)
  try:
    names = sorted(os.listdir(root_dir), key=str.lower)
  except Exception:
    names = []
  for name in names:
    if name.startswith(".") or not name.endswith(".json"):
      continue
    entry = os.path.join(root_dir, name)
    if os.path.realpath(entry) == current_real:
      continue
    try:
      loaded = json.load(open(entry, "r", encoding="utf-8"))
      if not isinstance(loaded, dict):
        continue
    except Exception:
      continue
    tok = str(loaded.get("sshws_token") or "").strip().lower()
    if re.fullmatch(r"[a-f0-9]{10}", tok):
      seen.add(tok)
  tok = str(current_token or "").strip().lower()
  if re.fullmatch(r"[a-f0-9]{10}", tok) and tok not in seen:
    return tok
  for _ in range(256):
    tok = secrets.token_hex(5)
    if tok not in seen:
      return tok
  raise RuntimeError("failed to allocate unique sshws token")

payload = {}
if os.path.isfile(state_file):
  try:
    loaded = json.load(open(state_file, "r", encoding="utf-8"))
    if isinstance(loaded, dict):
      payload = loaded
  except Exception:
    payload = {}

status_raw = payload.get("status")
status = status_raw if isinstance(status_raw, dict) else {}
network_raw = payload.get("network")
network = network_raw if isinstance(network_raw, dict) else {}

quota_limit = to_int(payload.get("quota_limit"), 0)
if quota_limit < 0:
  quota_limit = 0

quota_used = to_int(payload.get("quota_used"), 0)
if quota_used < 0:
  quota_used = 0

speed_down = to_float(status.get("speed_down_mbit"), 0.0)
speed_up = to_float(status.get("speed_up_mbit"), 0.0)
if speed_down < 0:
  speed_down = 0.0
if speed_up < 0:
  speed_up = 0.0

ip_limit = to_int(status.get("ip_limit"), 0)
if ip_limit < 0:
  ip_limit = 0

unit = str(payload.get("quota_unit") or "binary").strip().lower()
if unit not in ("binary", "decimal"):
  unit = "binary"

created = str(created_at or "").strip() or str(payload.get("created_at") or "").strip()
if created:
  created = created[:10]
if not created:
  created = datetime.datetime.now().strftime("%Y-%m-%d")

expired = norm_date(expired_at) or norm_date(payload.get("expired_at")) or "-"
token = pick_unique_token(os.path.dirname(state_file) or ".", state_file, payload.get("sshws_token"))

payload["managed_by"] = "autoscript-manage"
payload["username"] = username
payload["protocol"] = "ssh"
payload["created_at"] = created
payload["expired_at"] = expired
payload["sshws_token"] = token
payload["quota_limit"] = quota_limit
payload["quota_unit"] = unit
payload["quota_used"] = quota_used
payload["status"] = {
  "manual_block": to_bool(status.get("manual_block")),
  "quota_exhausted": to_bool(status.get("quota_exhausted")),
  "ip_limit_enabled": to_bool(status.get("ip_limit_enabled")),
  "ip_limit": ip_limit,
  "ip_limit_locked": to_bool(status.get("ip_limit_locked")),
  "ip_limit_metric": to_int(status.get("ip_limit_metric"), 0),
  "distinct_ip_count": to_int(status.get("distinct_ip_count"), 0),
  "distinct_ips": status.get("distinct_ips") if isinstance(status.get("distinct_ips"), list) else [],
  "active_sessions_total": to_int(status.get("active_sessions_total"), 0),
  "active_sessions_runtime": to_int(status.get("active_sessions_runtime"), 0),
  "active_sessions_dropbear": to_int(status.get("active_sessions_dropbear"), 0),
  "speed_limit_enabled": to_bool(status.get("speed_limit_enabled")),
  "speed_down_mbit": speed_down,
  "speed_up_mbit": speed_up,
  "lock_reason": str(status.get("lock_reason") or "").strip().lower(),
  "account_locked": to_bool(status.get("account_locked")),
  "lock_owner": str(status.get("lock_owner") or "").strip(),
  "lock_shell_restore": str(status.get("lock_shell_restore") or "").strip(),
}
payload["bootstrap_review_needed"] = to_bool(payload.get("bootstrap_review_needed"))
payload["bootstrap_source"] = str(payload.get("bootstrap_source") or "").strip()

print(json.dumps(payload, ensure_ascii=False, indent=2))
PY
    rm -f "${tmp}" >/dev/null 2>&1 || true
    return 1
  fi
  printf '\n' >> "${tmp}"
  install -m 600 "${tmp}" "${state_file}" || {
    rm -f "${tmp}" >/dev/null 2>&1 || true
    return 1
  }
  rm -f "${tmp}" >/dev/null 2>&1 || true
  return 0
}

ssh_account_info_password_get() {
  local username="${1:-}"
  if [[ "$(ssh_account_info_password_mode)" != "store" ]]; then
    echo "-"
    return 0
  fi
  local acc_file
  acc_file="$(ssh_account_info_file "${username}")"
  [[ -f "${acc_file}" ]] || {
    echo "-"
    return 0
  }
  awk '/^Password[[:space:]]*:/{sub(/^Password[[:space:]]*:[[:space:]]*/, ""); print; found=1; exit} END{if(!found) print "-"}' "${acc_file}" 2>/dev/null
}

ssh_previous_password_get() {
  local username="${1:-}"
  ssh_account_info_password_get "${username}"
}

ssh_qac_traffic_enforcement_ready() {
  local proxy_svc="${SSHWS_PROXY_SERVICE:-sshws-proxy}"
  [[ -x /usr/local/bin/ws-proxy || -x /usr/local/bin/sshws-proxy ]] && return 0
  [[ -f "/etc/systemd/system/${proxy_svc}.service" ]] && return 0
  [[ -f "/lib/systemd/system/${proxy_svc}.service" ]] && return 0
  return 1
}

ssh_qac_traffic_scope_label() {
  if ssh_qac_traffic_enforcement_ready; then
    echo "Unified SSH QAC"
  else
    echo "Metadata only (SSH runtime not installed)"
  fi
}

ssh_qac_traffic_scope_line() {
  if ssh_qac_traffic_enforcement_ready; then
    local provider active
    provider="$(edge_runtime_get_env EDGE_PROVIDER 2>/dev/null || echo "none")"
    active="$(edge_runtime_get_env EDGE_ACTIVATE_RUNTIME 2>/dev/null || echo "false")"
    if [[ "${provider}" == "go" ]]; then
      echo "Quota, speed limit, dan IP/Login limit berlaku sebagai satu sistem SSH pada SSH WS, SSH SSL/TLS, dan SSH Direct selama transport melewati Edge Gateway aktif. Pada provider go, trafik SSH SSL/TLS publik mengikuti jalur backend SSH klasik setelah terminasi TLS, sedangkan SSH WS memakai limiter token-aware milik sshws-proxy. Native sshd port 22 tetap di luar scope traffic enforcement."
      return 0
    fi
    echo "Quota, speed limit, dan IP/Login limit berlaku sebagai satu sistem SSH pada SSH WS, SSH SSL/TLS, dan SSH Direct selama transport melewati Edge Gateway aktif. Native sshd port 22 tetap di luar scope traffic enforcement."
  else
    echo "SSH runtime belum terpasang; quota/IP-login/speed SSH masih metadata dan native sshd port 22 tidak dihitung atau di-throttle."
  fi
}

edge_runtime_enabled_for_public_ports() {
  local provider active
  provider="$(edge_runtime_get_env EDGE_PROVIDER 2>/dev/null || echo "none")"
  active="$(edge_runtime_get_env EDGE_ACTIVATE_RUNTIME 2>/dev/null || echo "false")"
  [[ "${provider}" != "none" ]] || return 1
  case "${active}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
  esac
  return 1
}

ssh_public_all_ports_label() {
  local tls_ports http_ports merged
  tls_ports="$(edge_runtime_public_tls_ports 2>/dev/null || echo "443 2053 2083 2087 2096 8443")"
  http_ports="$(edge_runtime_public_http_ports 2>/dev/null || echo "80 8080 8880 2052 2082 2086 2095")"
  merged="$(printf '%s %s\n' "${tls_ports}" "${http_ports}" | awk '
    {
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^[0-9]+$/ && !seen[$i]++) {
          out = out (out ? " " : "") $i
        }
      }
    }
    END { print out }
  ')"
  if [[ -n "${merged}" ]]; then
    printf '%s\n' "${merged}" | sed 's/ /, /g'
  else
    printf '%s\n' "-"
  fi
}

ssh_primary_public_ports_label() {
  local tls_ports http_ports primary="" port
  tls_ports="$(edge_runtime_public_tls_ports 2>/dev/null || echo "443 2053 2083 2087 2096 8443")"
  http_ports="$(edge_runtime_public_http_ports 2>/dev/null || echo "80 8080 8880 2052 2082 2086 2095")"
  for port in ${tls_ports}; do
    primary="${port}"
    break
  done
  for port in ${http_ports}; do
    if [[ -n "${primary}" && "${port}" != "${primary}" ]]; then
      primary+=" ${port}"
    elif [[ -z "${primary}" ]]; then
      primary="${port}"
    fi
    break
  done
  if [[ -n "${primary}" ]]; then
    printf '%s\n' "${primary}" | sed 's/ /, /g'
  else
    printf '%s\n' "-"
  fi
}

ssh_ws_public_ports_label() {
  if edge_runtime_enabled_for_public_ports; then
    ssh_public_all_ports_label
  else
    printf '%s\n' "-"
  fi
}

ssh_alt_tls_public_ports_label() {
  local tls_ports out=() port
  tls_ports="$(edge_runtime_public_tls_ports 2>/dev/null || echo "443 2053 2083 2087 2096 8443")"
  for port in ${tls_ports}; do
    [[ "${port}" == "443" ]] && continue
    out+=("${port}")
  done
  if (( ${#out[@]} > 0 )); then
    printf '%s\n' "${out[*]}" | sed 's/ /, /g'
  else
    printf '%s\n' "-"
  fi
}

ssh_alt_http_public_ports_label() {
  local http_ports out=() port
  http_ports="$(edge_runtime_public_http_ports 2>/dev/null || echo "80 8080 8880 2052 2082 2086 2095")"
  for port in ${http_ports}; do
    [[ "${port}" == "80" ]] && continue
    out+=("${port}")
  done
  if (( ${#out[@]} > 0 )); then
    printf '%s\n' "${out[*]}" | sed 's/ /, /g'
  else
    printf '%s\n' "-"
  fi
}

ssh_ssl_tls_public_ports_label() {
  if edge_runtime_enabled_for_public_ports; then
    ssh_ws_public_ports_label
  else
    printf '%s\n' "-"
  fi
}

ssh_direct_public_ports_label() {
  if edge_runtime_enabled_for_public_ports; then
    ssh_ws_public_ports_label
  else
    printf '%s\n' "-"
  fi
}

ssh_account_info_write() {
  # args: username password quota_bytes expired_at created_at ip_enabled ip_limit speed_enabled speed_down speed_up sshws_token [output_file_override] [domain_override] [ip_override] [isp_override] [country_override]
  local username="${1:-}"
  local password_raw="${2:-}"
  local password_out
  local quota_bytes="${3:-0}"
  local expired_at="${4:--}"
  local created_at="${5:-}"
  local ip_enabled="${6:-false}"
  local ip_limit="${7:-0}"
  local speed_enabled="${8:-false}"
  local speed_down="${9:-0}"
  local speed_up="${10:-0}"
  local sshws_token="${11:-}"
  local output_file_override="${12:-}"
  local domain_override="${13:-}"
  local ip_override="${14:-}"
  local isp_override="${15:-}"
  local country_override="${16:-}"

  ssh_state_dirs_prepare
  password_out="${password_raw:-"-"}"

  local acc_file domain ip geo_ip isp country quota_limit_disp expired_disp valid_until created_disp ip_disp speed_disp sshws_path sshws_alt_path sshws_main_disp sshws_ports_disp ssh_direct_ports_disp ssh_ssl_tls_ports_disp ssh_alt_tls_ports_disp ssh_alt_http_ports_disp badvpn_port_disp geo portal_ssh_link
  local running_label_width running_ssh_ws_path running_ssh_ws_alt running_ssh_ws_port running_ssh_direct running_ssh_ssl_tls running_ssh_alt_tls running_ssh_alt_http running_badvpn
  local -a account_info_labels
  acc_file="$(ssh_account_info_file "${username}")"
  [[ -n "${output_file_override}" ]] && acc_file="${output_file_override}"
  domain="$(normalize_domain_token "${domain_override}")"
  [[ -n "${domain}" ]] || domain="$(detect_domain)"
  ip="$(normalize_ip_token "${ip_override}")"
  if [[ -z "${ip}" ]]; then
    ip="$(main_info_ip_quiet_get)"
    [[ -n "${ip}" ]] || ip="$(detect_public_ip)"
  fi
  isp="${isp_override}"
  country="${country_override}"
  if [[ -z "${isp}" || -z "${country}" ]]; then
    geo="$(main_info_geo_lookup "${ip}")"
    IFS='|' read -r geo_ip isp_geo country_geo <<<"${geo}"
    [[ -n "${geo_ip}" && "${geo_ip}" != "-" ]] && ip="${geo_ip}"
    [[ -n "${isp}" ]] || isp="${isp_geo:-}"
    [[ -n "${country}" ]] || country="${country_geo:-}"
  fi
  [[ -n "${domain}" ]] || domain="-"
  [[ -n "${ip}" ]] || ip="-"
  [[ -n "${isp}" ]] || isp="-"
  [[ -n "${country}" ]] || country="-"
  [[ -n "${created_at}" ]] || created_at="$(date '+%Y-%m-%d')"
  [[ -n "${expired_at}" ]] || expired_at="-"

  quota_limit_disp="$(python3 - <<'PY' "${quota_bytes}"
import sys
def fmt(v):
  s=f"{v:.3f}".rstrip("0").rstrip(".")
  return s if s else "0"
try:
  b=int(float(sys.argv[1]))
except Exception:
  b=0
if b < 0:
  b = 0
print(f"{fmt(b/(1024**3))} GB")
PY
)"

  created_disp="$(python3 - <<'PY' "${created_at}"
import sys
from datetime import datetime
v = (sys.argv[1] or "").strip()
if not v:
  print(datetime.now().strftime("%Y-%m-%d"))
  raise SystemExit(0)
for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d", "%Y-%m-%d %H:%M:%S"):
  try:
    dt = datetime.strptime(v[:len(fmt)], fmt)
    print(dt.strftime("%Y-%m-%d"))
    raise SystemExit(0)
  except Exception:
    pass
if len(v) >= 10 and v[4:5] == "-" and v[7:8] == "-":
  print(v[:10])
else:
  print(v)
PY
)"

  valid_until="${expired_at}"
  expired_disp="$(python3 - <<'PY' "${expired_at}"
import sys
from datetime import datetime
v = (sys.argv[1] or "").strip()
if not v or v == "-":
  print("unlimited")
  raise SystemExit(0)
try:
  dt = datetime.strptime(v[:10], "%Y-%m-%d").date()
  today = datetime.now().date()
  days = (dt - today).days
  if days < 0:
    days = 0
  print(f"{days} days")
except Exception:
  print("unknown")
PY
)"

  if [[ "${ip_enabled}" == "true" ]]; then
    if [[ "${ip_limit}" =~ ^[0-9]+$ ]] && (( ip_limit > 0 )); then
      ip_disp="ON (${ip_limit})"
    else
      ip_disp="ON"
    fi
  else
    ip_disp="OFF"
  fi

  if [[ "${speed_enabled}" == "true" ]]; then
    speed_disp="ON (DOWN ${speed_down} Mbps | UP ${speed_up} Mbps)"
  else
    speed_disp="OFF"
  fi

  if sshws_token_valid "${sshws_token}"; then
    sshws_token="${sshws_token,,}"
    sshws_path="$(sshws_path_from_token "${sshws_token}")"
    sshws_alt_path="$(sshws_alt_path_from_token "${sshws_token}" 2>/dev/null || true)"
    sshws_main_disp="${sshws_path}"
  else
    sshws_path="-"
    sshws_alt_path="-"
    sshws_main_disp="-"
  fi
  if [[ "${sshws_alt_path}" == /bebas/*/bebas ]]; then
    sshws_alt_path="/<bebas>/${sshws_token}/<bebas>"
  fi
  portal_ssh_link="$(ssh_account_portal_link "${username}")"
  [[ -n "${portal_ssh_link}" ]] || portal_ssh_link="-"
  sshws_ports_disp="$(ssh_primary_public_ports_label)"
  ssh_direct_ports_disp="$(ssh_primary_public_ports_label)"
  ssh_ssl_tls_ports_disp="$(ssh_primary_public_ports_label)"
  ssh_alt_tls_ports_disp="$(ssh_alt_tls_public_ports_label)"
  ssh_alt_http_ports_disp="$(ssh_alt_http_public_ports_label)"
  badvpn_port_disp="$(badvpn_public_port_label)"
  account_info_labels=(
    "SSH WS Path"
    "SSH WS Path Alt"
    "SSH WS Port"
    "SSH Direct Port"
    "SSH SSL/TLS Port"
    "Alt Port SSL/TLS"
    "Alt Port HTTP"
    "BadVPN UDPGW"
    "Portal SSH"
  )
  running_label_width=0
  local label=""
  for label in "${account_info_labels[@]}"; do
    (( ${#label} > running_label_width )) && running_label_width=${#label}
  done
  printf -v running_ssh_ws_path '%-*s : %s' "${running_label_width}" "SSH WS Path" "${sshws_main_disp}"
  printf -v running_ssh_ws_alt '%-*s : %s' "${running_label_width}" "SSH WS Path Alt" "${sshws_alt_path}"
  printf -v running_ssh_ws_port '%-*s : %s' "${running_label_width}" "SSH WS Port" "${sshws_ports_disp}"
  printf -v running_ssh_direct '%-*s : %s' "${running_label_width}" "SSH Direct Port" "${ssh_direct_ports_disp}"
  printf -v running_ssh_ssl_tls '%-*s : %s' "${running_label_width}" "SSH SSL/TLS Port" "${ssh_ssl_tls_ports_disp}"
  printf -v running_ssh_alt_tls '%-*s : %s' "${running_label_width}" "Alt Port SSL/TLS" "${ssh_alt_tls_ports_disp}"
  printf -v running_ssh_alt_http '%-*s : %s' "${running_label_width}" "Alt Port HTTP" "${ssh_alt_http_ports_disp}"
  printf -v running_badvpn '%-*s : %s' "${running_label_width}" "BadVPN UDPGW" "${badvpn_port_disp}"
  local running_portal_ssh
  printf -v running_portal_ssh '%-*s : %s' "${running_label_width}" "Portal SSH" "${portal_ssh_link}"
  local tmp_acc_file=""
  mkdir -p "$(dirname "${acc_file}")" 2>/dev/null || return 1
  tmp_acc_file="$(mktemp "${acc_file}.tmp.XXXXXX" 2>/dev/null || true)"
  [[ -n "${tmp_acc_file}" ]] || tmp_acc_file="${acc_file}.tmp.$$"
  if ! cat > "${tmp_acc_file}" <<EOF
=== ACCOUNT INFO ===
Domain      : ${domain}
IP          : ${ip}
ISP         : ${isp}
Country     : ${country}
Username    : ${username}
Password    : ${password_out}
Quota Limit : ${quota_limit_disp}
Expired     : ${expired_disp}
Valid Until : ${valid_until}
Created     : ${created_disp}
IP Limit    : ${ip_disp}
Speed Limit : ${speed_disp}

=== SSH ===
${running_ssh_ws_path}
${running_ssh_ws_alt}
${running_ssh_ws_port}
${running_ssh_direct}
${running_ssh_ssl_tls}
${running_ssh_alt_tls}
${running_ssh_alt_http}
${running_badvpn}
${running_portal_ssh}
EOF
  then
    rm -f "${tmp_acc_file}" >/dev/null 2>&1 || true
    return 1
  fi
  chmod 600 "${tmp_acc_file}" >/dev/null 2>&1 || true
  if ! mv -f "${tmp_acc_file}" "${acc_file}" >/dev/null 2>&1; then
    rm -f "${tmp_acc_file}" >/dev/null 2>&1 || true
    return 1
  fi
  return 0
}

ssh_account_info_refresh_from_state() {
  # args: username [password_override] [output_file_override] [domain_override] [ip_override] [isp_override] [country_override]
  local username="${1:-}"
  local password_override="${2:-}"
  local output_file_override="${3:-}"
  local domain_override="${4:-}"
  local ip_override="${5:-}"
  local isp_override="${6:-}"
  local country_override="${7:-}"
  local qf
  qf="$(ssh_user_state_resolve_file "${username}")"
  [[ -f "${qf}" ]] || return 1

  local fields quota_bytes expired_at created_at ip_enabled ip_limit speed_enabled speed_down speed_up sshws_token password
  need_python3
  fields="$(python3 - <<'PY' "${qf}"
import json
import sys
p = sys.argv[1]
try:
  d = json.load(open(p, "r", encoding="utf-8"))
except Exception:
  d = {}
if not isinstance(d, dict):
  d = {}
s = d.get("status")
if not isinstance(s, dict):
  s = {}
def tb(v):
  if isinstance(v, bool):
    return "true" if v else "false"
  if isinstance(v, (int, float)):
    return "true" if bool(v) else "false"
  return "true" if str(v or "").strip().lower() in ("1", "true", "yes", "on", "y") else "false"
def ti(v, d=0):
  try:
    if v is None:
      return d
    if isinstance(v, bool):
      return int(v)
    if isinstance(v, (int, float)):
      return int(v)
    t = str(v).strip()
    if not t:
      return d
    return int(float(t))
  except Exception:
    return d
def tf(v, d=0.0):
  try:
    if v is None:
      return d
    if isinstance(v, bool):
      return float(int(v))
    if isinstance(v, (int, float)):
      return float(v)
    t = str(v).strip()
    if not t:
      return d
    return float(t)
  except Exception:
    return d
def fm(v):
  s = f"{float(v):.3f}".rstrip("0").rstrip(".")
  return s if s else "0"
print("|".join([
  str(max(0, ti(d.get("quota_limit"), 0))),
  str(d.get("expired_at") or "-")[:10] if str(d.get("expired_at") or "-").strip() else "-",
  str(d.get("created_at") or "-"),
  tb(s.get("ip_limit_enabled")),
  str(max(0, ti(s.get("ip_limit"), 0))),
  tb(s.get("speed_limit_enabled")),
  fm(max(0.0, tf(s.get("speed_down_mbit"), 0.0))),
  fm(max(0.0, tf(s.get("speed_up_mbit"), 0.0))),
  str(d.get("sshws_token") or "").strip().lower(),
]))
PY
)"
  IFS='|' read -r quota_bytes expired_at created_at ip_enabled ip_limit speed_enabled speed_down speed_up sshws_token <<<"${fields}"

  password="${password_override}"
  if [[ -z "${password}" ]]; then
    password="$(ssh_previous_password_get "${username}")"
  fi
  if [[ -z "${password}" || "${password}" == "-" ]]; then
    return 1
  fi

  if ! sshws_token_valid "${sshws_token}"; then
    sshws_token="$(ssh_user_state_ensure_token "${username}" 2>/dev/null || true)"
  fi

  ssh_account_info_write "${username}" "${password}" "${quota_bytes}" "${expired_at}" "${created_at}" "${ip_enabled}" "${ip_limit}" "${speed_enabled}" "${speed_down}" "${speed_up}" "${sshws_token}" "${output_file_override}" "${domain_override}" "${ip_override}" "${isp_override}" "${country_override}"
}

ssh_account_info_refresh_warn() {
  # args: username [password_override]
  local username="${1:-}"
  local password_override="${2:-}"
  if ! ssh_account_info_refresh_from_state "${username}" "${password_override}"; then
    warn "SSH ACCOUNT INFO belum sinkron untuk '${username}'."
    return 1
  fi
  return 0
}

ssh_linux_candidate_users_get() {
  need_python3
  python3 - <<'PY'
import pwd

SKIP_SHELL_SUFFIXES = ("nologin", "false")
for entry in pwd.getpwall():
  name = str(entry.pw_name or "").strip()
  shell = str(entry.pw_shell or "").strip()
  home = str(entry.pw_dir or "").strip()
  if not name or name == "root":
    continue
  if entry.pw_uid < 1000:
    continue
  if not shell or shell.endswith(SKIP_SHELL_SUFFIXES):
    continue
  if home and not home.startswith("/home/"):
    continue
  print(name)
PY
}

ssh_linux_account_expiry_get() {
  local username="${1:-}"
  local raw normalized
  [[ -n "${username}" ]] || return 1
  raw="$(chage -l "${username}" 2>/dev/null | awk -F': ' '/Account expires/{print $2; exit}' || true)"
  raw="$(printf '%s' "${raw}" | tr -d '\r' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' || true)"
  case "${raw,,}" in
    ""|never|never\ expires)
      printf '%s\n' "-"
      return 0
      ;;
  esac
  normalized="$(date -d "${raw}" '+%Y-%m-%d' 2>/dev/null || true)"
  if [[ -n "${normalized}" ]]; then
    printf '%s\n' "${normalized}"
  else
    printf '%s\n' "-"
  fi
}

ssh_qac_metadata_bootstrap_if_missing() {
  local username="${1:-}"
  local qf="${2:-}"
  local created_at
  [[ -n "${username}" && -n "${qf}" ]] || return 1
  [[ -f "${qf}" ]] && return 0

  created_at="$(date '+%Y-%m-%d')"
  if ! ssh_user_state_write "${username}" "${created_at}" "-"; then
    return 1
  fi
  if ! ssh_qac_atomic_update_file "${qf}" bootstrap_marker_set "minimal-placeholder" >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

ssh_qac_bootstrap_status_get() {
  local qf="${1:-}"
  [[ -n "${qf}" && -f "${qf}" ]] || {
    printf 'false|\n'
    return 0
  }
  need_python3
  python3 - <<'PY' "${qf}"
import json
import sys

try:
  data = json.load(open(sys.argv[1], "r", encoding="utf-8"))
except Exception:
  print("false|")
  raise SystemExit(0)

flag = data.get("bootstrap_review_needed")
source = str(data.get("bootstrap_source") or "").strip()
if isinstance(flag, bool):
  needed = flag
elif isinstance(flag, (int, float)):
  needed = bool(flag)
else:
  needed = str(flag or "").strip().lower() in ("1", "true", "yes", "on", "y")
print(("true" if needed else "false") + "|" + source)
PY
}

ssh_pending_login_shell_get() {
  local shell="/usr/sbin/nologin"
  if have_cmd nologin; then
    shell="$(command -v nologin 2>/dev/null || printf '/usr/sbin/nologin')"
  fi
  printf '%s\n' "${shell}"
}

ssh_add_txn_linux_pending_contains() {
  local username="${1:-}"
  local txn_dir="" linux_created=""
  [[ -n "${username}" ]] || return 1
  mutation_txn_prepare || return 1
  while IFS= read -r -d '' txn_dir; do
    [[ -n "${txn_dir}" ]] || continue
    linux_created="$(mutation_txn_field_read "${txn_dir}" linux_created 2>/dev/null || true)"
    if [[ "${linux_created}" != "true" ]]; then
      return 0
    fi
  done < <(find "${MUTATION_TXN_DIR}" -maxdepth 1 -type d -name "ssh-add.${username}*" -print0 2>/dev/null | sort -z)
  return 1
}

ssh_collect_candidate_users() {
  # args: [include_linux=true|false]
  local include_linux="${1:-true}"
  ssh_state_dirs_prepare

  local -A seen_users=()
  local username="" name=""

  while IFS= read -r username; do
    [[ -n "${username}" ]] || continue
    username="${username%@ssh.json}"
    username="${username%.json}"
    ssh_username_valid "${username}" || continue
    [[ -n "${username}" ]] || continue
    if ssh_add_txn_linux_pending_contains "${username}"; then
      continue
    fi
    if [[ -n "${seen_users["${username}"]+x}" ]]; then
      continue
    fi
    seen_users["${username}"]=1
    printf '%s\n' "${username}"
  done < <(find "${SSH_USERS_STATE_DIR}" -maxdepth 1 -type f -name '*.json' -printf '%f\n' 2>/dev/null | sort -u)

  while IFS= read -r name; do
    [[ -n "${name}" ]] || continue
    name="${name%@ssh.txt}"
    name="${name%.txt}"
    ssh_username_valid "${name}" || continue
    [[ -n "${name}" ]] || continue
    if ssh_add_txn_linux_pending_contains "${name}"; then
      continue
    fi
    if [[ -n "${seen_users["${name}"]+x}" ]]; then
      continue
    fi
    seen_users["${name}"]=1
    printf '%s\n' "${name}"
  done < <(find "${SSH_ACCOUNT_DIR}" -maxdepth 1 -type f -name '*.txt' -printf '%f\n' 2>/dev/null | sort -u)

  while IFS= read -r name; do
    [[ -n "${name}" ]] || continue
    name="${name%@ssh.pass}"
    name="${name%.pass}"
    ssh_username_valid "${name}" || continue
    [[ -n "${name}" ]] || continue
    if ssh_add_txn_linux_pending_contains "${name}"; then
      continue
    fi
    if [[ -n "${seen_users["${name}"]+x}" ]]; then
      continue
    fi
    seen_users["${name}"]=1
    printf '%s\n' "${name}"
  done < <(find "${SSH_ACCOUNT_DIR}" -maxdepth 1 -type f -name '*.pass' -printf '%f\n' 2>/dev/null | sort -u)

  if [[ "${include_linux}" == "true" ]]; then
    while IFS= read -r name; do
      [[ -n "${name}" ]] || continue
      ssh_username_valid "${name}" || continue
      if ssh_add_txn_linux_pending_contains "${name}"; then
        continue
      fi
      if [[ -n "${seen_users["${name}"]+x}" ]]; then
        continue
      fi
      seen_users["${name}"]=1
      printf '%s\n' "${name}"
    done < <(ssh_linux_candidate_users_get 2>/dev/null || true)
  fi
}

ssh_pick_managed_user() {
  local -n _out_ref="$1"
  _out_ref=""

  ssh_state_dirs_prepare

  local -a users=()
  local name=""
  while IFS= read -r name; do
    [[ -n "${name}" ]] || continue
    users+=("${name}")
  done < <(ssh_collect_candidate_users false)

  if (( ${#users[@]} > 1 )); then
    mapfile -t users < <(printf '%s\n' "${users[@]}" | sort -u)
  fi

  if (( ${#users[@]} == 0 )); then
    warn "Belum ada akun SSH managed yang bisa dipilih dari menu ini."
    return 1
  fi

  local i
  echo "Pilih akun SSH:"
  for i in "${!users[@]}"; do
    printf "  %d) %s\n" "$((i + 1))" "${users[$i]}"
  done

  local pick
  while true; do
    if ! read -r -p "Nomor akun (1-${#users[@]}/kembali): " pick; then
      echo
      return 2
    fi
    if is_back_choice "${pick}"; then
      return 2
    fi
    [[ "${pick}" =~ ^[0-9]+$ ]] || { warn "Input harus angka."; continue; }
    if (( pick < 1 || pick > ${#users[@]} )); then
      warn "Di luar range."
      continue
    fi
    _out_ref="${users[$((pick - 1))]}"
    return 0
  done
}

ssh_read_password_confirm() {
  local -n _out_ref="$1"
  _out_ref=""
  local p1="" p2=""
  local silent_flag="-s"
  if [[ ! -t 0 ]]; then
    silent_flag=""
  fi

  if [[ -n "${silent_flag}" ]]; then
    if ! read -r -s -p "Password SSH: " p1; then
      echo
      return 1
    fi
  elif ! read -r -p "Password SSH: " p1; then
    echo
    return 1
  fi
  [[ -z "${silent_flag}" ]] || echo
  if [[ -z "${p1}" || ${#p1} -lt 6 ]]; then
    warn "Password minimal 6 karakter."
    return 1
  fi
  if [[ -n "${silent_flag}" ]]; then
    if ! read -r -s -p "Ulangi password: " p2; then
      echo
      return 1
    fi
  elif ! read -r -p "Ulangi password: " p2; then
    echo
    return 1
  fi
  [[ -z "${silent_flag}" ]] || echo
  if [[ "${p1}" != "${p2}" ]]; then
    warn "Password tidak sama."
    return 1
  fi
  _out_ref="${p1}"
  return 0
}

ssh_apply_password() {
  local username="${1:-}"
  local password="${2:-}"
  printf '%s:%s\n' "${username}" "${password}" | chpasswd >/dev/null 2>&1
}

ssh_apply_expiry() {
  local username="${1:-}"
  local expiry="${2:-}"
  [[ -n "${username}" ]] || return 1
  case "${expiry}" in
    ""|"-"|never|Never|unlimited|Unlimited)
      chage -E -1 "${username}" >/dev/null 2>&1
      ;;
    *)
      chage -E "${expiry}" "${username}" >/dev/null 2>&1
      ;;
  esac
}

ssh_strict_date_ymd_normalize() {
  local raw="${1:-}"
  need_python3
  python3 - <<'PY' "${raw}"
import sys
from datetime import datetime

value = str(sys.argv[1] or "").strip()
try:
    dt = datetime.strptime(value, "%Y-%m-%d")
except Exception:
    raise SystemExit(1)
print(dt.strftime("%Y-%m-%d"))
PY
}

ssh_user_state_expired_at_get() {
  local username="${1:-}"
  local qf
  qf="$(ssh_user_state_resolve_file "${username}")"
  [[ -f "${qf}" ]] || return 1

  need_python3
  python3 - <<'PY' "${qf}"
import json
import sys

path = sys.argv[1]
try:
  data = json.load(open(path, "r", encoding="utf-8"))
except Exception:
  data = {}

if not isinstance(data, dict):
  data = {}

value = str(data.get("expired_at") or "").strip()
if not value or value == "-":
  print("-")
else:
  print(value[:10])
PY
}

ssh_optional_file_snapshot_create() {
  # args: path snap_dir out_mode_var out_backup_var
  local path="${1:-}"
  local snap_dir="${2:-}"
  local __mode_var="${3:-}"
  local __backup_var="${4:-}"
  local mode="absent"
  local backup=""

  if [[ -e "${path}" || -L "${path}" ]]; then
    backup="$(mktemp "${snap_dir}/snapshot.XXXXXX" 2>/dev/null || true)"
    [[ -n "${backup}" ]] || return 1
    if ! cp -a "${path}" "${backup}" 2>/dev/null; then
      rm -f -- "${backup}" >/dev/null 2>&1 || true
      return 1
    fi
    mode="file"
  fi

  [[ -n "${__mode_var}" ]] && printf -v "${__mode_var}" '%s' "${mode}"
  [[ -n "${__backup_var}" ]] && printf -v "${__backup_var}" '%s' "${backup}"
  return 0
}

ssh_optional_file_snapshot_restore() {
  # args: mode backup_file target_file [chmod_mode]
  local mode="${1:-absent}"
  local backup="${2:-}"
  local target="${3:-}"
  local chmod_mode="${4:-600}"
  [[ -n "${target}" ]] || return 1

  case "${mode}" in
    file)
      [[ -n "${backup}" && -e "${backup}" ]] || return 1
      mkdir -p "$(dirname "${target}")" 2>/dev/null || true
      cp -a "${backup}" "${target}" || return 1
      chmod "${chmod_mode}" "${target}" 2>/dev/null || true
      ;;
    absent)
      if [[ -e "${target}" || -L "${target}" ]]; then
        rm -f "${target}" || return 1
      fi
      ;;
    *)
      return 1
      ;;
  esac
  return 0
}

ssh_password_reset_rollback() {
  local username="${1:-}"
  local previous_password="${2:-}"
  local account_mode="${3:-absent}"
  local account_backup="${4:-}"
  local account_file="${5:-}"

  [[ -n "${username}" ]] || {
    echo "username rollback kosong"
    return 1
  }
  if [[ -z "${previous_password}" || "${previous_password}" == "-" ]]; then
    echo "password lama tidak tersedia untuk rollback"
    return 1
  fi
  if ! ssh_apply_password "${username}" "${previous_password}"; then
    echo "rollback Linux password gagal"
    return 1
  fi
  local rollback_notes=""
  if [[ -n "${account_file}" ]]; then
    if ! ssh_optional_file_snapshot_restore "${account_mode}" "${account_backup}" "${account_file}" 600; then
      rollback_notes="account info rollback gagal"
    fi
  elif ! ssh_account_info_refresh_from_state "${username}" "${previous_password}"; then
    rollback_notes="account info rollback gagal"
  fi


  if [[ -n "${rollback_notes}" ]]; then
    echo "password Linux dipulihkan, tetapi ${rollback_notes}"
    return 1
  fi
  echo "ok"
  return 0
}

ssh_expiry_update_rollback() {
  local username="${1:-}"
  local previous_expiry="${2:--}"
  [[ -n "${username}" ]] || {
    echo "username rollback kosong"
    return 1
  }
  if ! ssh_apply_expiry "${username}" "${previous_expiry}"; then
    echo "rollback expiry Linux gagal"
    return 1
  fi

  local created_at
  created_at="$(ssh_user_state_created_at_get "${username}")"
  if [[ -z "${created_at}" ]]; then
    created_at="$(date '+%Y-%m-%d')"
  fi
  if ! ssh_user_state_write "${username}" "${created_at}" "${previous_expiry}"; then
    echo "expiry Linux dipulihkan, tetapi metadata rollback gagal"
    return 1
  fi
  if ! ssh_account_info_refresh_from_state "${username}"; then
    echo "expiry Linux dipulihkan, tetapi SSH ACCOUNT INFO rollback gagal"
    return 1
  fi
  echo "ok"
  return 0
}

ssh_add_user_rollback() {
  # args: username qf acc_file reason raw_password linux_created
  local username="${1:-}"
  local qf="${2:-}"
  local acc_file="${3:-}"
  local reason="${4:-Gagal membuat akun SSH.}"
  local raw_password="${5:-}"
  local linux_created="${6:-false}"
  local deleted="false"
  local -a rollback_notes=()



  if [[ "${linux_created}" == "true" ]]; then
    if id "${username}" >/dev/null 2>&1; then
      if ssh_userdel_purge "${username}" >/dev/null 2>&1; then
        deleted="true"
      fi
    fi
  else
    deleted="true"
  fi

  if [[ "${deleted}" == "true" ]]; then
    local -a cleanup_notes=()
    local cleanup_failed=""
    cleanup_failed="$(ssh_user_artifacts_cleanup_locked "${username}" 2>/dev/null || true)"
    if [[ -n "${cleanup_failed}" ]]; then
      cleanup_notes+=("${cleanup_failed}")
    elif ! ssh_network_runtime_refresh_if_available; then
      cleanup_notes+=("refresh runtime SSH Network gagal")
    fi
    warn "${reason}"
    if (( ${#rollback_notes[@]} > 0 )); then
      warn "Rollback tambahan: $(IFS=' | '; echo "${rollback_notes[*]}")"
    fi
    if (( ${#cleanup_notes[@]} > 0 )); then
      warn "Cleanup artefak lokal gagal: ${cleanup_notes[*]}"
      return 1
    fi
    if (( ${#rollback_notes[@]} > 0 )); then
      return 1
    fi
    return 0
  fi

  # Hindari orphan-silent: saat userdel gagal, pertahankan metadata agar status masih terlihat.
  warn "${reason}"
  warn "Rollback parsial: gagal menghapus user Linux '${username}'."

  if (( ${#rollback_notes[@]} > 0 )); then
    warn "Rollback tambahan: $(IFS=' | '; echo "${rollback_notes[*]}")"
  fi
  warn "Artefak managed yang sudah ada dipertahankan. Jalankan manual: userdel '${username}'"
  return 1
}

ssh_add_user_fail_with_rollback() {
  # args: username qf acc_file reason raw_password linux_created txn_dir
  local username="${1:-}"
  local qf="${2:-}"
  local acc_file="${3:-}"
  local reason="${4:-Gagal membuat akun SSH.}"
  local raw_password="${5:-}"
  local linux_created="${6:-false}"
  local txn_dir="${7:-}"
  if ssh_add_user_rollback "${username}" "${qf}" "${acc_file}" "${reason}" "${raw_password}" "${linux_created}"; then
    ssh_add_txn_marker_clear "${username}" >/dev/null 2>&1 || true
    mutation_txn_dir_remove "${txn_dir}"
  else
    [[ -n "${txn_dir}" ]] && warn "Journal recovery add SSH dipertahankan di ${txn_dir}."
  fi
  return 1
}

ssh_add_txn_marker_file() {
  local username="${1:-}"
  printf '%s/ssh-add-markers/%s.txn\n' "${WORK_DIR}" "${username}"
}

ssh_add_txn_marker_write() {
  local username="${1:-}"
  local txn_id="${2:-}"
  local marker_file=""
  [[ -n "${username}" && -n "${txn_id}" ]] || return 1
  marker_file="$(ssh_add_txn_marker_file "${username}")"
  mkdir -p "$(dirname "${marker_file}")" 2>/dev/null || return 1
  if ! printf '%s' "${txn_id}" > "${marker_file}"; then
    return 1
  fi
  chmod 600 "${marker_file}" 2>/dev/null || true
  return 0
}

ssh_add_txn_marker_read() {
  local username="${1:-}"
  local marker_file=""
  [[ -n "${username}" ]] || return 1
  marker_file="$(ssh_add_txn_marker_file "${username}")"
  [[ -f "${marker_file}" ]] || return 1
  cat "${marker_file}" 2>/dev/null || return 1
}

ssh_add_txn_marker_clear() {
  local username="${1:-}"
  local marker_file=""
  [[ -n "${username}" ]] || return 0
  marker_file="$(ssh_add_txn_marker_file "${username}")"
  rm -f "${marker_file}" >/dev/null 2>&1 || true
}

ssh_user_home_dir_default() {
  local username="${1:-}"
  printf '/home/%s\n' "${username}"
}

ssh_user_home_dir_get() {
  local username="${1:-}"
  local home=""
  [[ -n "${username}" ]] || return 1
  home="$(getent passwd "${username}" 2>/dev/null | awk -F: '{print $6; exit}' || true)"
  [[ -n "${home}" ]] || home="$(ssh_user_home_dir_default "${username}")"
  printf '%s\n' "${home}"
}

ssh_user_home_dir_prepare() {
  local username="${1:-}"
  local home=""
  [[ -n "${username}" ]] || return 1
  home="$(ssh_user_home_dir_get "${username}")"
  [[ -n "${home}" ]] || return 1
  mkdir -p "${home}" 2>/dev/null || return 1
  chown "${username}:${username}" "${home}" 2>/dev/null || return 1
  chmod 700 "${home}" 2>/dev/null || true
}

ssh_password_hash_generate() {
  local password="${1:-}"
  [[ -n "${password}" ]] || return 1
  if have_cmd openssl; then
    openssl passwd -6 -stdin 2>/dev/null <<<"${password}" | tr -d '\r' || return 1
    return 0
  fi
  need_python3
  python3 -c '
import crypt
import secrets
import string
import sys

password = sys.stdin.read().rstrip("\n")
alphabet = string.ascii_letters + string.digits + "./"
salt = "".join(secrets.choice(alphabet) for _ in range(16))
print(crypt.crypt(password, f"$6${salt}$"))
' <<<"${password}"
}

ssh_home_snapshot_create() {
  local username="${1:-}"
  local snapshot_dir="${2:-}"
  local mode_var="${3:-}"
  local backup_var="${4:-}"
  local home_dir="" archive="" mode="absent" backup=""
  [[ -n "${mode_var}" && -n "${backup_var}" ]] || return 1
  home_dir="$(ssh_user_home_dir_get "${username}")"
  if [[ -n "${home_dir}" && -d "${home_dir}" ]]; then
    archive="${snapshot_dir}/home.tar"
    if tar -cpf "${archive}" -C "${home_dir}" . >/dev/null 2>&1; then
      mode="file"
      backup="${archive}"
    else
      return 1
    fi
  fi
  printf -v "${mode_var}" '%s' "${mode}"
  printf -v "${backup_var}" '%s' "${backup}"
}

ssh_home_snapshot_restore() {
  local username="${1:-}"
  local mode="${2:-absent}"
  local backup_file="${3:-}"
  local home_dir=""
  [[ -n "${username}" ]] || return 1
  home_dir="$(ssh_user_home_dir_get "${username}")"
  [[ -n "${home_dir}" ]] || return 1
  if [[ "${mode}" != "file" || -z "${backup_file}" || ! -f "${backup_file}" ]]; then
    ssh_user_home_dir_prepare "${username}"
    return $?
  fi
  mkdir -p "${home_dir}" 2>/dev/null || return 1
  if ! tar -xpf "${backup_file}" -C "${home_dir}" >/dev/null 2>&1; then
    return 1
  fi
  chown -R "${username}:${username}" "${home_dir}" 2>/dev/null || true
  chmod 700 "${home_dir}" 2>/dev/null || true
}

ssh_linux_account_snapshot_create() {
  local username="${1:-}"
  local snapshot_dir="${2:-}"
  local meta_var="${3:-}"
  local meta_file="" passwd_line="" uid="" gid="" home="" shell="" primary_group="" groups="" password_hash="" gecos=""
  [[ -n "${username}" && -n "${snapshot_dir}" && -n "${meta_var}" ]] || return 1
  passwd_line="$(getent passwd "${username}" 2>/dev/null || true)"
  [[ -n "${passwd_line}" ]] || {
    printf -v "${meta_var}" '%s' ""
    return 0
  }
  uid="$(printf '%s' "${passwd_line}" | awk -F: '{print $3}')"
  gid="$(printf '%s' "${passwd_line}" | awk -F: '{print $4}')"
  home="$(printf '%s' "${passwd_line}" | awk -F: '{print $6}')"
  shell="$(printf '%s' "${passwd_line}" | awk -F: '{print $7}')"
  gecos="$(printf '%s' "${passwd_line}" | awk -F: '{print $5}')"
  primary_group="$(id -gn "${username}" 2>/dev/null || true)"
  password_hash="$(getent shadow "${username}" 2>/dev/null | awk -F: '{print $2}' || true)"
  groups="$(id -Gn "${username}" 2>/dev/null | awk -v pg="${primary_group}" '
    {
      out=""
      for (i=1; i<=NF; i++) {
        if ($i == pg || $i == "") continue
        out = out (out=="" ? "" : ",") $i
      }
      print out
    }' || true)"
  meta_file="${snapshot_dir}/linux-account.meta"
  {
    printf 'uid=%s\n' "${uid}"
    printf 'gid=%s\n' "${gid}"
    printf 'home=%s\n' "${home}"
    printf 'shell=%s\n' "${shell}"
    printf 'gecos=%s\n' "${gecos}"
    printf 'primary_group=%s\n' "${primary_group}"
    printf 'supp_groups=%s\n' "${groups}"
    printf 'password_hash=%s\n' "${password_hash}"
  } > "${meta_file}" || return 1
  chmod 600 "${meta_file}" 2>/dev/null || true
  printf -v "${meta_var}" '%s' "${meta_file}"
}

ssh_linux_account_snapshot_field_get() {
  local meta_file="${1:-}"
  local key="${2:-}"
  [[ -n "${meta_file}" && -f "${meta_file}" && -n "${key}" ]] || return 1
  awk -F= -v want="${key}" '$1==want {print substr($0, index($0, "=")+1); exit}' "${meta_file}" 2>/dev/null
}

ssh_add_txn_recover_dir() {
  local txn_dir="${1:-}"
  local username qf acc_file password expired_at created_at quota_bytes ip_enabled ip_limit speed_enabled speed_down speed_up linux_created txn_id marker_id
  local password_file="" cleanup_failed=""
  local -a notes=()
  [[ -n "${txn_dir}" && -d "${txn_dir}" ]] || return 0

  username="$(mutation_txn_field_read "${txn_dir}" username 2>/dev/null || true)"
  qf="$(mutation_txn_field_read "${txn_dir}" qf 2>/dev/null || true)"
  acc_file="$(mutation_txn_field_read "${txn_dir}" acc_file 2>/dev/null || true)"
  expired_at="$(mutation_txn_field_read "${txn_dir}" expired_at 2>/dev/null || true)"
  created_at="$(mutation_txn_field_read "${txn_dir}" created_at 2>/dev/null || true)"
  quota_bytes="$(mutation_txn_field_read "${txn_dir}" quota_bytes 2>/dev/null || true)"
  ip_enabled="$(mutation_txn_field_read "${txn_dir}" ip_enabled 2>/dev/null || true)"
  ip_limit="$(mutation_txn_field_read "${txn_dir}" ip_limit 2>/dev/null || true)"
  speed_enabled="$(mutation_txn_field_read "${txn_dir}" speed_enabled 2>/dev/null || true)"
  speed_down="$(mutation_txn_field_read "${txn_dir}" speed_down 2>/dev/null || true)"
  speed_up="$(mutation_txn_field_read "${txn_dir}" speed_up 2>/dev/null || true)"
  linux_created="$(mutation_txn_field_read "${txn_dir}" linux_created 2>/dev/null || true)"
  txn_id="$(mutation_txn_field_read "${txn_dir}" txn_id 2>/dev/null || true)"
  password_file="${txn_dir}/password.secret"
  password="$(cat "${password_file}" 2>/dev/null || true)"

  if [[ -z "${username}" || -z "${qf}" || -z "${acc_file}" ]]; then
    mutation_txn_dir_remove "${txn_dir}"
    return 0
  fi
  if [[ "${linux_created}" != "true" ]]; then
    cleanup_failed="$(ssh_user_artifacts_cleanup_locked "${username}" 2>/dev/null || true)"
    if [[ -n "${cleanup_failed}" ]]; then
      warn "Recovery add SSH untuk '${username}' belum bersih: cleanup artefak pre-Linux gagal (${cleanup_failed})."
      return 1
    fi
    if ! ssh_network_runtime_refresh_if_available; then
      warn "Recovery add SSH untuk '${username}' belum bersih: refresh runtime SSH Network gagal."
      return 1
    fi
    marker_id="$(ssh_add_txn_marker_read "${username}" 2>/dev/null || true)"
    if [[ -n "${txn_id}" && -n "${marker_id}" && "${marker_id}" == "${txn_id}" ]]; then
      ssh_add_txn_marker_clear "${username}" >/dev/null 2>&1 || true
    fi
    mutation_txn_dir_remove "${txn_dir}"
    log "Recovery add SSH membersihkan metadata pre-Linux untuk '${username}'."
    return 0
  fi

  if ! id "${username}" >/dev/null 2>&1; then

    cleanup_failed="$(ssh_user_artifacts_cleanup_locked "${username}" 2>/dev/null || true)"
    if [[ -n "${cleanup_failed}" ]]; then
      warn "Recovery add SSH untuk '${username}' belum bersih: cleanup artefak gagal (${cleanup_failed})."
      return 1
    fi
    if ! ssh_network_runtime_refresh_if_available; then
      warn "Recovery add SSH untuk '${username}' belum bersih: refresh runtime SSH Network gagal."
      return 1
    fi
    marker_id="$(ssh_add_txn_marker_read "${username}" 2>/dev/null || true)"
    if [[ -n "${txn_id}" && -n "${marker_id}" && "${marker_id}" == "${txn_id}" ]]; then
      ssh_add_txn_marker_clear "${username}" >/dev/null 2>&1 || true
    fi
    mutation_txn_dir_remove "${txn_dir}"
    log "Recovery add SSH membuang journal yatim untuk '${username}' karena user Linux tidak ada."
    return 0
  fi

  marker_id="$(ssh_add_txn_marker_read "${username}" 2>/dev/null || true)"
  if [[ -z "${txn_id}" || -z "${marker_id}" || "${marker_id}" != "${txn_id}" ]]; then
    warn "Recovery add SSH untuk '${username}' ditahan: marker transaksi tidak cocok. Akun Linux mungkin sudah dipakai ulang."
    return 1
  fi

  if [[ -z "${password}" ]]; then
    warn "Recovery add SSH untuk '${username}' belum bisa dilanjutkan: password journal tidak tersedia."
    return 1
  fi

  if (( ${#notes[@]} == 0 )) && ! ssh_user_state_write "${username}" "${created_at}" "${expired_at}"; then
    notes+=("tulis metadata akun SSH gagal")
  fi
  if (( ${#notes[@]} == 0 )) && ! ssh_qac_atomic_update_file "${qf}" set_quota_limit "${quota_bytes}"; then
    notes+=("set quota metadata SSH gagal")
  fi
  if (( ${#notes[@]} == 0 )); then
    if [[ "${ip_enabled}" == "true" ]]; then
      if ! ssh_qac_atomic_update_file "${qf}" set_ip_limit "${ip_limit}"; then
        notes+=("set IP limit metadata SSH gagal")
      elif ! ssh_qac_atomic_update_file "${qf}" ip_limit_enabled_set on; then
        notes+=("aktifkan IP limit metadata SSH gagal")
      fi
    else
      if ! ssh_qac_atomic_update_file "${qf}" ip_limit_enabled_set off; then
        notes+=("nonaktifkan IP limit metadata SSH gagal")
      fi
    fi
  fi
  if (( ${#notes[@]} == 0 )); then
    if [[ "${speed_enabled}" == "true" ]]; then
      if ! ssh_qac_atomic_update_file "${qf}" set_speed_all_enable "${speed_down}" "${speed_up}"; then
        notes+=("set speed limit metadata SSH gagal")
      fi
    else
      if ! ssh_qac_atomic_update_file "${qf}" speed_limit_set off; then
        notes+=("nonaktifkan speed limit metadata SSH gagal")
      fi
    fi
  fi
  if (( ${#notes[@]} == 0 )) && ! ssh_account_info_refresh_from_state "${username}" "${password}" "${acc_file}"; then
    notes+=("refresh SSH account info gagal")
  fi

  if (( ${#notes[@]} == 0 )) && ! ssh_qac_enforce_now_warn "${username}"; then
    notes+=("enforcement awal SSH gagal")
  fi
  if (( ${#notes[@]} == 0 )) && ! ssh_dns_adblock_runtime_refresh_if_available; then
    notes+=("refresh runtime DNS Adblock SSH gagal")
  fi
  if (( ${#notes[@]} == 0 )) && ! ssh_network_runtime_refresh_if_available; then
    notes+=("refresh runtime SSH Network gagal")
  fi
  if (( ${#notes[@]} == 0 )) && ! ssh_user_home_dir_prepare "${username}"; then
    notes+=("menyiapkan home dir Linux gagal")
  fi
  if (( ${#notes[@]} == 0 )) && ! ssh_apply_password "${username}" "${password}"; then
    notes+=("set password Linux gagal")
  fi
  if (( ${#notes[@]} == 0 )) && ! ssh_apply_expiry "${username}" "${expired_at}"; then
    notes+=("set expiry Linux gagal")
  fi
  if (( ${#notes[@]} == 0 )) && ! usermod -U "${username}" >/dev/null 2>&1; then
    notes+=("membuka lock akun Linux gagal")
  fi
  if (( ${#notes[@]} == 0 )) && ! usermod -s /bin/bash "${username}" >/dev/null 2>&1; then
    notes+=("aktifkan shell login gagal")
  fi
  if (( ${#notes[@]} == 0 )) && ! ssh_account_info_refresh_from_state "${username}" "${password}" "${acc_file}"; then
    notes+=("refresh final SSH account info gagal")
  fi

  if (( ${#notes[@]} > 0 )); then
    warn "Recovery add SSH untuk '${username}' belum bersih: $(IFS=' | '; echo "${notes[*]}")."
    return 1
  fi

  ssh_add_txn_marker_clear "${username}" >/dev/null 2>&1 || true
  mutation_txn_dir_remove "${txn_dir}"
  log "Recovery add SSH selesai untuk '${username}'."
  return 0
}

ssh_add_txn_recover_pending_all() {
  local txn_dir=""
  mutation_txn_prepare || return 0
  while IFS= read -r -d '' txn_dir; do
    [[ -n "${txn_dir}" ]] || continue
    ssh_add_txn_recover_dir "${txn_dir}" || true
  done < <(find "${MUTATION_TXN_DIR}" -maxdepth 1 -type d -name 'ssh-add.*' -print0 2>/dev/null | sort -z)
}

ssh_userdel_purge() {
  local username="${1:-}"
  [[ -n "${username}" ]] || return 1
  if ! id "${username}" >/dev/null 2>&1; then
    return 0
  fi
  userdel -r "${username}" >/dev/null 2>&1
}

ssh_delete_user_cleanup_after_linux_delete() {
  local username="${1:-}"
  local cleanup_failed=""
  local -a notes=()

  [[ -n "${username}" ]] || return 1

  cleanup_failed="$(ssh_user_artifacts_cleanup_locked "${username}" 2>/dev/null || true)"
  if [[ -n "${cleanup_failed}" ]]; then
    notes+=("cleanup artefak lokal gagal: ${cleanup_failed}")
  elif ! ssh_dns_adblock_runtime_refresh_if_available; then
    notes+=("refresh runtime DNS adblock gagal")
  elif ! ssh_network_runtime_refresh_if_available; then
    notes+=("refresh runtime SSH Network gagal")
  fi

  if (( ${#notes[@]} > 0 )); then
    printf '%s\n' "$(IFS=' | '; echo "${notes[*]}")"
    return 1
  fi
  return 0
}

ssh_delete_txn_recover_dir() {
  local txn_dir="${1:-}"
  local username linux_deleted cleanup_failed=""
  local state_mode="absent" state_backup="" state_file=""
  local state_compat_mode="absent" state_compat_backup="" state_compat_file=""
  local account_mode="absent" account_backup="" account_file=""
  local account_compat_mode="absent" account_compat_backup="" account_compat_file=""
  local linux_meta_file=""
  local restore_msg=""
  [[ -n "${txn_dir}" && -d "${txn_dir}" ]] || return 0

  username="$(mutation_txn_field_read "${txn_dir}" username 2>/dev/null || true)"
  linux_deleted="$(mutation_txn_field_read "${txn_dir}" linux_deleted 2>/dev/null || true)"
  if [[ -z "${username}" ]]; then
    mutation_txn_dir_remove "${txn_dir}"
    return 0
  fi
  state_file="$(ssh_user_state_file "${username}")"
  state_compat_file="$(ssh_user_state_compat_file "${username}")"
  account_file="$(ssh_account_info_file "${username}")"
  account_compat_file="${SSH_ACCOUNT_DIR}/${username}.txt"
  [[ -f "${txn_dir}/state.path" ]] && state_mode="file" && state_backup="${txn_dir}/state.path"
  [[ -f "${txn_dir}/state_compat.path" ]] && state_compat_mode="file" && state_compat_backup="${txn_dir}/state_compat.path"
  [[ -f "${txn_dir}/account.path" ]] && account_mode="file" && account_backup="${txn_dir}/account.path"
  [[ -f "${txn_dir}/account_compat.path" ]] && account_compat_mode="file" && account_compat_backup="${txn_dir}/account_compat.path"
  linux_meta_file="${txn_dir}/linux-account.meta"
  if [[ "${linux_deleted}" != "1" ]]; then
    if id "${username}" >/dev/null 2>&1; then
      if ! ssh_delete_user_predelete_restore "${username}" "${linux_meta_file}" "${state_mode}" "${state_backup}"; then
        warn "Recovery delete SSH untuk '${username}' belum bersih: gagal memulihkan status akun Linux pra-delete."
        return 1
      fi
      restore_msg="$(ssh_delete_user_snapshot_restore \
        "${username}" \
        "${state_mode}" "${state_backup}" "${state_file}" \
        "${state_compat_mode}" "${state_compat_backup}" "${state_compat_file}" \
        "${account_mode}" "${account_backup}" "${account_file}" \
        "${account_compat_mode}" "${account_compat_backup}" "${account_compat_file}" 2>/dev/null || true)"
      if [[ -n "${restore_msg}" ]]; then
        warn "Recovery delete SSH untuk '${username}' belum bersih: ${restore_msg}"
        return 1
      fi
      mutation_txn_dir_remove "${txn_dir}"
      log "Recovery delete SSH memulihkan state pra-delete untuk '${username}'."
      return 0
    fi
    cleanup_failed="$(ssh_delete_user_cleanup_after_linux_delete "${username}" 2>/dev/null || true)"
    if [[ -n "${cleanup_failed}" ]]; then
      warn "Recovery delete SSH untuk '${username}' belum bersih: ${cleanup_failed}"
      return 1
    fi
    mutation_txn_dir_remove "${txn_dir}"
    log "Recovery delete SSH menyelesaikan cleanup pasca-delete untuk '${username}'."
    return 0
  fi
  if id "${username}" >/dev/null 2>&1; then
    warn "Recovery delete SSH untuk '${username}' tertahan: akun Linux masih ada."
    return 1
  fi

  mutation_txn_dir_remove "${txn_dir}"
  log "Recovery delete SSH selesai untuk '${username}'."
  return 0
}

ssh_delete_txn_recover_pending_all() {
  local txn_dir=""
  mutation_txn_prepare || return 0
  while IFS= read -r -d '' txn_dir; do
    [[ -n "${txn_dir}" ]] || continue
    ssh_delete_txn_recover_dir "${txn_dir}" || true
  done < <(find "${MUTATION_TXN_DIR}" -maxdepth 1 -type d -name 'ssh-delete.*' -print0 2>/dev/null | sort -z)
}

ssh_pending_recovery_count() {
  local count=0
  mutation_txn_prepare || {
    printf '0\n'
    return 0
  }
  count="$(find "${MUTATION_TXN_DIR}" -maxdepth 1 -type d \( -name 'ssh-add.*' -o -name 'ssh-delete.*' \) 2>/dev/null | wc -l | tr -d '[:space:]' || true)"
  [[ "${count}" =~ ^[0-9]+$ ]] || count=0
  printf '%s\n' "${count}"
}

ssh_pending_txn_dirs_by_kind() {
  local kind="${1:-all}"
  case "${kind}" in
    add) mutation_txn_list_dirs 'ssh-add.*' ;;
    delete) mutation_txn_list_dirs 'ssh-delete.*' ;;
    all)
      mutation_txn_list_dirs 'ssh-add.*'
      mutation_txn_list_dirs 'ssh-delete.*'
      ;;
    *) return 0 ;;
  esac
}

ssh_pending_txn_label() {
  local txn_dir="${1:-}"
  local base="" username="" created=""
  [[ -n "${txn_dir}" && -d "${txn_dir}" ]] || return 1
  base="$(basename "${txn_dir}")"
  username="$(mutation_txn_field_read "${txn_dir}" username 2>/dev/null || true)"
  created="$(date -r "${txn_dir}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || true)"
  case "${base}" in
    ssh-add.*) printf 'ADD    | %s | %s\n' "${username:-?}" "${created:-unknown}" ;;
    ssh-delete.*) printf 'DELETE | %s | %s\n' "${username:-?}" "${created:-unknown}" ;;
    *) printf '%s | %s\n' "${base}" "${created:-unknown}" ;;
  esac
}

ssh_recover_pending_txn_now() {
  local kind="${1:-all}"
  local txn_dir="${2:-}"
  if [[ -n "${txn_dir}" ]]; then
    case "${kind}" in
      add) ssh_add_txn_recover_dir "${txn_dir}" || true ;;
      delete) ssh_delete_txn_recover_dir "${txn_dir}" || true ;;
    esac
    return 0
  fi
  case "${kind}" in
    add) ssh_add_txn_recover_pending_all || true ;;
    delete) ssh_delete_txn_recover_pending_all || true ;;
    all|*)
      ssh_add_txn_recover_pending_all || true
      ssh_delete_txn_recover_pending_all || true
      ;;
  esac
}

ssh_recover_pending_txn_pick_dir() {
  local kind="${1:-}"
  local -n _out_ref="${2}"
  local -a dirs=()
  local txn_dir="" choice="" i
  _out_ref=""
  [[ "${kind}" == "add" || "${kind}" == "delete" ]] || return 1
  while IFS= read -r txn_dir; do
    [[ -n "${txn_dir}" ]] || continue
    dirs+=("${txn_dir}")
  done < <(ssh_pending_txn_dirs_by_kind "${kind}")
  if (( ${#dirs[@]} == 0 )); then
    return 1
  fi
  if (( ${#dirs[@]} == 1 )); then
    _out_ref="${dirs[0]}"
    return 0
  fi
  echo "Pilih journal recovery ${kind} SSH:"
  for i in "${!dirs[@]}"; do
    printf '  %d) %s\n' "$((i + 1))" "$(ssh_pending_txn_label "${dirs[$i]}")"
  done
  while true; do
    if ! read -r -p "Pilih journal (1-${#dirs[@]}/kembali): " choice; then
      echo
      return 1
    fi
    if is_back_choice "${choice}"; then
      return 1
    fi
    [[ "${choice}" =~ ^[0-9]+$ ]] || { warn "Pilihan tidak valid."; continue; }
    if (( choice < 1 || choice > ${#dirs[@]} )); then
      warn "Nomor di luar range."
      continue
    fi
    _out_ref="${dirs[$((choice - 1))]}"
    return 0
  done
}

ssh_recover_pending_txn_menu() {
  local pending_count=0
  local add_count=0
  local delete_count=0
  local choice=""
  local selected_dir=""
  local selected_label=""
  pending_count="$(ssh_pending_recovery_count)"
  add_count="$(find "${MUTATION_TXN_DIR}" -maxdepth 1 -type d -name 'ssh-add.*' 2>/dev/null | wc -l | tr -d '[:space:]' || true)"
  delete_count="$(find "${MUTATION_TXN_DIR}" -maxdepth 1 -type d -name 'ssh-delete.*' 2>/dev/null | wc -l | tr -d '[:space:]' || true)"
  [[ "${pending_count}" =~ ^[0-9]+$ ]] || pending_count=0
  [[ "${add_count}" =~ ^[0-9]+$ ]] || add_count=0
  [[ "${delete_count}" =~ ^[0-9]+$ ]] || delete_count=0

  title
  echo "SSH Users > Recover Pending Txn"
  hr
  echo "Pending journal : ${pending_count}"
  echo "  Add    : ${add_count}"
  echo "  Delete : ${delete_count}"
  if (( pending_count == 0 )); then
    log "Tidak ada journal recovery SSH yang tertunda."
    pause
    return 0
  fi
  echo "Catatan        : aksi ini bisa memodifikasi akun Linux dan metadata SSH untuk menyelesaikan transaksi lama."
  hr
  echo "  1) Recover journal Add"
  echo "  2) Recover journal Delete"
  echo "  0) Back"
  hr
  read -r -p "Pilih aksi: " choice
  case "${choice}" in
    1)
      (( add_count > 0 )) || { warn "Tidak ada journal add SSH."; pause; return 0; }
      ssh_recover_pending_txn_pick_dir add selected_dir || { pause; return 0; }
      selected_label="$(ssh_pending_txn_label "${selected_dir}")"
      echo "Journal terpilih : ${selected_label}"
      confirm_menu_apply_now "Lanjutkan recovery journal add SSH ini sekarang? (${selected_label})" || { pause; return 0; }
      user_data_mutation_run_locked ssh_recover_pending_txn_now add "${selected_dir}"
      ;;
    2)
      (( delete_count > 0 )) || { warn "Tidak ada journal delete SSH."; pause; return 0; }
      ssh_recover_pending_txn_pick_dir delete selected_dir || { pause; return 0; }
      selected_label="$(ssh_pending_txn_label "${selected_dir}")"
      echo "Journal terpilih : ${selected_label}"
      confirm_menu_apply_now "Lanjutkan recovery journal delete SSH ini sekarang? (${selected_label})" || { pause; return 0; }
      user_data_mutation_run_locked ssh_recover_pending_txn_now delete "${selected_dir}"
      ;;
    0|kembali|k|back|b)
      return 0
      ;;
    *)
      warn "Pilihan tidak valid."
      ;;
  esac
  pause
}

ssh_managed_users_lines() {
  ssh_state_dirs_prepare
  need_python3
  python3 - <<'PY' "${SSH_USERS_STATE_DIR}" "${MUTATION_TXN_DIR}" 2>/dev/null || true
import json
import glob
import os
import pwd
import re
import sys
from datetime import datetime

root = sys.argv[1]
txn_root = sys.argv[2] if len(sys.argv) > 2 else ""

def norm_created(v):
  s = str(v or "").strip()
  if not s or s == "-":
    return "-"
  s = s.replace("T", " ")
  if s.endswith("Z"):
    s = s[:-1]
  s = s.strip()
  if re.match(r"^\d{4}-\d{2}-\d{2}$", s):
    return s
  if len(s) >= 16 and re.match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}", s):
    return s[:10]
  candidates = [s]
  if re.match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$", s):
    candidates.append(s + ":00")
  for c in candidates:
    try:
      dt = datetime.fromisoformat(c)
      return dt.strftime("%Y-%m-%d")
    except Exception:
      pass
  m = re.search(r"\d{4}-\d{2}-\d{2}", s)
  if m:
    return m.group(0)
  return "-"

def norm_expired(v):
  s = str(v or "").strip()
  if not s or s == "-":
    return "-"
  m = re.search(r"\d{4}-\d{2}-\d{2}", s)
  return m.group(0) if m else "-"

rows = []
seen = set()
if os.path.isdir(root):
  for name in os.listdir(root):
    if not name.endswith(".json"):
      continue
    base = name[:-5]
    username = base[:-4] if base.endswith("@ssh") else base
    username = username.strip()
    if not username:
      continue
    path = os.path.join(root, name)
    created = "-"
    expired = "-"
    try:
      with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
      if isinstance(data, dict):
        meta_user = str(data.get("username") or "").strip()
        if meta_user.endswith("@ssh"):
          meta_user = meta_user[:-4]
        if meta_user:
          username = meta_user
        created = norm_created(data.get("created_at"))
        expired = norm_expired(data.get("expired_at"))
    except Exception:
      pass
    rows.append((username.lower(), username, created, expired))
    seen.add(username)

for entry in pwd.getpwall():
  username = str(entry.pw_name or "").strip()
  shell = str(entry.pw_shell or "").strip()
  home = str(entry.pw_dir or "").strip()
  if not username or username == "root":
    continue
  if entry.pw_uid < 1000:
    continue
  if not shell or shell.endswith(("nologin", "false")):
    continue
  if home and not home.startswith("/home/"):
    continue
  if os.path.isdir(txn_root):
    for pending_path in glob.glob(os.path.join(txn_root, f"ssh-add.{username}*")):
      try:
        with open(os.path.join(pending_path, "linux_created"), "r", encoding="utf-8") as f:
          if f.read().strip() != "true":
            username = ""
            break
      except Exception:
        username = ""
        break
  if not username:
    continue
  if username in seen:
    continue
  rows.append((username.lower(), username, "linux-only", "-"))

rows.sort(key=lambda x: x[0])
for _, username, created, expired in rows:
  print(f"{username}|{created}|{expired}")
PY
}

ssh_add_user_header_render() {
  local -n _page_ref="$1"
  local page_size=5
  local -a rows=()
  local row
  while IFS= read -r row; do
    [[ -n "${row}" ]] || continue
    rows+=("${row}")
  done < <(ssh_managed_users_lines)

  local total="${#rows[@]}"
  echo "Daftar akun SSH terdaftar (maks 5 baris):"
  if (( total == 0 )); then
    echo "  (Belum ada akun SSH terkelola)"
    echo "  Input username baru untuk lanjut."
    return 0
  fi

  local pages=$(( (total + page_size - 1) / page_size ))
  local page="${_page_ref:-0}"
  if (( page < 0 )); then
    page=0
  fi
  if (( page >= pages )); then
    page=$((pages - 1))
  fi
  _page_ref="${page}"

  local start=$((page * page_size))
  local end=$((start + page_size))
  if (( end > total )); then
    end="${total}"
  fi

  printf "%-4s %-20s %-16s %-10s\n" "No" "Username" "Created" "Expired"
  printf "%-4s %-20s %-16s %-10s\n" "----" "--------------------" "----------------" "----------"

  local i username created expired
  for ((i=start; i<end; i++)); do
    IFS='|' read -r username created expired <<<"${rows[$i]}"
    printf "%-4s %-20s %-16s %-10s\n" "$((i + 1))" "${username}" "${created}" "${expired}"
  done

  echo "Halaman: $((page + 1))/${pages} | Total: ${total}"
  if (( pages > 1 )); then
    echo "Navigasi: ketik next/previous sebelum input username."
  fi
}

ssh_add_user_apply_locked() {
  local rc=0
  (
    SSH_ADD_ABORT_ACTIVE="1"
    SSH_ADD_ABORT_USERNAME="$1"
    SSH_ADD_ABORT_QF="$2"
    SSH_ADD_ABORT_ACC="$3"
    SSH_ADD_ABORT_PASSWORD="$4"
    SSH_ADD_ABORT_LINUX_CREATED="false"
    trap '
      if [[ "${SSH_ADD_ABORT_ACTIVE:-0}" == "1" ]]; then
        ssh_add_user_rollback \
          "${SSH_ADD_ABORT_USERNAME}" \
          "${SSH_ADD_ABORT_QF}" \
          "${SSH_ADD_ABORT_ACC}" \
          "transaksi add user SSH terputus sebelum commit final" \
          "${SSH_ADD_ABORT_PASSWORD}" \
          "${SSH_ADD_ABORT_LINUX_CREATED:-false}" >/dev/null 2>&1 || true
      fi
    ' EXIT INT TERM HUP QUIT
    ssh_add_user_apply_locked_inner "$@"
    rc=$?
    trap - EXIT INT TERM HUP QUIT
    exit "${rc}"
  )
  rc=$?
  return "${rc}"
}

ssh_add_user_apply_locked_inner() {
  local username="$1"
  local qf="$2"
  local acc_file="$3"
  local password="$4"
  local expired_at="$5"
  local created_at="$6"
  local quota_bytes="$7"
  local ip_enabled="$8"
  local ip_limit="$9"
  local speed_enabled="${10}"
  local speed_down="${11}"
  local speed_up="${12}"
  local add_txn_dir="" add_txn_id="" pending_shell="/usr/sbin/nologin"
  local password_hash="" home_dir="" pending_expired_at="1970-01-02"
  local -a useradd_args=()

  add_txn_dir="$(mutation_txn_dir_new "ssh-add.${username}" 2>/dev/null || true)"
  if [[ -z "${add_txn_dir}" || ! -d "${add_txn_dir}" ]]; then
    warn "Gagal menyiapkan journal recovery add user SSH."
    pause
    return 1
  fi
  add_txn_id="$(basename "${add_txn_dir}")"
  pending_shell="$(ssh_pending_login_shell_get)"
  mutation_txn_field_write "${add_txn_dir}" username "${username}" >/dev/null 2>&1 || true
  mutation_txn_field_write "${add_txn_dir}" qf "${qf}" >/dev/null 2>&1 || true
  mutation_txn_field_write "${add_txn_dir}" acc_file "${acc_file}" >/dev/null 2>&1 || true
  mutation_txn_field_write "${add_txn_dir}" txn_id "${add_txn_id}" >/dev/null 2>&1 || true
  mutation_txn_field_write "${add_txn_dir}" expired_at "${expired_at}" >/dev/null 2>&1 || true
  mutation_txn_field_write "${add_txn_dir}" created_at "${created_at}" >/dev/null 2>&1 || true
  mutation_txn_field_write "${add_txn_dir}" quota_bytes "${quota_bytes}" >/dev/null 2>&1 || true
  mutation_txn_field_write "${add_txn_dir}" ip_enabled "${ip_enabled}" >/dev/null 2>&1 || true
  mutation_txn_field_write "${add_txn_dir}" ip_limit "${ip_limit}" >/dev/null 2>&1 || true
  mutation_txn_field_write "${add_txn_dir}" speed_enabled "${speed_enabled}" >/dev/null 2>&1 || true
  mutation_txn_field_write "${add_txn_dir}" speed_down "${speed_down}" >/dev/null 2>&1 || true
  mutation_txn_field_write "${add_txn_dir}" speed_up "${speed_up}" >/dev/null 2>&1 || true
  mutation_txn_field_write "${add_txn_dir}" linux_created "false" >/dev/null 2>&1 || true
  if ! printf '%s' "${password}" > "${add_txn_dir}/password.secret"; then
    mutation_txn_dir_remove "${add_txn_dir}"
    warn "Gagal menulis journal password recovery add user SSH."
    pause
    return 1
  fi
  chmod 600 "${add_txn_dir}/password.secret" 2>/dev/null || true

  if ! ssh_user_state_write "${username}" "${created_at}" "${expired_at}"; then
    ssh_add_user_fail_with_rollback "${username}" "${qf}" "${acc_file}" "Gagal menulis metadata akun SSH." "${password}" "false" "false" "${add_txn_dir}"
    pause
    return 1
  fi

  if ! ssh_qac_atomic_update_file "${qf}" set_quota_limit "${quota_bytes}"; then
    ssh_add_user_fail_with_rollback "${username}" "${qf}" "${acc_file}" "Gagal set quota metadata SSH." "${password}" "false" "false" "${add_txn_dir}"
    pause
    return 1
  fi

  local add_fail_msg=""
  if [[ "${ip_enabled}" == "true" ]]; then
    if ! ssh_qac_atomic_update_file "${qf}" set_ip_limit "${ip_limit}"; then
      add_fail_msg="Gagal set IP limit metadata SSH."
    elif ! ssh_qac_atomic_update_file "${qf}" ip_limit_enabled_set on; then
      add_fail_msg="Gagal mengaktifkan IP limit metadata SSH."
    fi
  else
    if ! ssh_qac_atomic_update_file "${qf}" ip_limit_enabled_set off; then
      add_fail_msg="Gagal menonaktifkan IP limit metadata SSH."
    fi
  fi

  if [[ -z "${add_fail_msg}" ]]; then
    if [[ "${speed_enabled}" == "true" ]]; then
      if ! ssh_qac_atomic_update_file "${qf}" set_speed_all_enable "${speed_down}" "${speed_up}"; then
        add_fail_msg="Gagal set speed limit metadata SSH."
      fi
    else
      if ! ssh_qac_atomic_update_file "${qf}" speed_limit_set off; then
        add_fail_msg="Gagal menonaktifkan speed limit metadata SSH."
      fi
    fi
  fi

  if [[ -n "${add_fail_msg}" ]]; then
    ssh_add_user_fail_with_rollback "${username}" "${qf}" "${acc_file}" "${add_fail_msg}" "${password}" "false" "false" "${add_txn_dir}"
    pause
    return 1
  fi

  if ! ssh_account_info_refresh_from_state "${username}" "${password}"; then
    ssh_add_user_fail_with_rollback "${username}" "${qf}" "${acc_file}" "Gagal menyiapkan SSH account info." "${password}" "false" "false" "${add_txn_dir}"
    pause
    return 1
  fi

  if ! ssh_add_txn_marker_write "${username}" "${add_txn_id}"; then
    ssh_add_user_fail_with_rollback "${username}" "${qf}" "${acc_file}" "Gagal menulis marker transaksi add SSH." "${password}" "false" "false" "${add_txn_dir}"
    pause
    return 1
  fi
  if ! ssh_dns_adblock_runtime_refresh_if_available; then
    ssh_add_user_fail_with_rollback "${username}" "${qf}" "${acc_file}" "Gagal refresh runtime DNS Adblock SSH sebelum commit user Linux." "${password}" "true" "false" "${add_txn_dir}"
    pause
    return 1
  fi

  if ! password_hash="$(ssh_password_hash_generate "${password}" 2>/dev/null)"; then
    ssh_add_user_fail_with_rollback "${username}" "${qf}" "${acc_file}" "Gagal menyiapkan hash password Linux sebelum commit user Linux." "${password}" "true" "false" "${add_txn_dir}"
    pause
    return 1
  fi
  home_dir="$(ssh_user_home_dir_default "${username}")"
  useradd_args=(-M -d "${home_dir}" -s "${pending_shell}" -p '!' -e "${pending_expired_at}")
  if ! useradd "${useradd_args[@]}" "${username}" >/dev/null 2>&1; then
    ssh_add_user_fail_with_rollback "${username}" "${qf}" "${acc_file}" "Gagal membuat user Linux '${username}'." "${password}" "true" "false" "${add_txn_dir}"
    pause
    return 1
  fi
  SSH_ADD_ABORT_LINUX_CREATED="true"
  mutation_txn_field_write "${add_txn_dir}" linux_created "true" >/dev/null 2>&1 || true

  if ! ssh_qac_enforce_now_warn "${username}"; then
    if [[ "${ip_enabled}" == "true" ]]; then
      ssh_add_user_fail_with_rollback "${username}" "${qf}" "${acc_file}" "Gagal enforcement awal SSH (IP/Login limit)." "${password}" "true" "true" "${add_txn_dir}"
    else
      ssh_add_user_fail_with_rollback "${username}" "${qf}" "${acc_file}" "Gagal enforcement awal SSH." "${password}" "true" "true" "${add_txn_dir}"
    fi
    pause
    return 1
  fi
  if ! ssh_user_home_dir_prepare "${username}"; then
    ssh_add_user_fail_with_rollback "${username}" "${qf}" "${acc_file}" "Gagal menyiapkan home dir user '${username}'." "${password}" "true" "true" "${add_txn_dir}"
    pause
    return 1
  fi
  if ! usermod -p "${password_hash}" "${username}" >/dev/null 2>&1; then
    ssh_add_user_fail_with_rollback "${username}" "${qf}" "${acc_file}" "Gagal menerapkan hash password final user '${username}'." "${password}" "true" "true" "${add_txn_dir}"
    pause
    return 1
  fi
  if ! ssh_apply_expiry "${username}" "${expired_at}"; then
    ssh_add_user_fail_with_rollback "${username}" "${qf}" "${acc_file}" "Gagal memulihkan expiry final user '${username}' setelah status pending." "${password}" "true" "true" "${add_txn_dir}"
    pause
    return 1
  fi
  if ! usermod -U "${username}" >/dev/null 2>&1; then
    ssh_add_user_fail_with_rollback "${username}" "${qf}" "${acc_file}" "Gagal membuka lock akun Linux '${username}' pada commit final." "${password}" "true" "true" "${add_txn_dir}"
    pause
    return 1
  fi
  if ! usermod -s /bin/bash "${username}" >/dev/null 2>&1; then
    ssh_add_user_fail_with_rollback "${username}" "${qf}" "${acc_file}" "Gagal mengaktifkan shell login user '${username}'." "${password}" "true" "true" "${add_txn_dir}"
    pause
    return 1
  fi
  if ! ssh_account_info_refresh_from_state "${username}" "${password}" "${acc_file}"; then
    ssh_add_user_fail_with_rollback "${username}" "${qf}" "${acc_file}" "Gagal refresh final SSH account info user '${username}'." "${password}" "true" "true" "${add_txn_dir}"
    pause
    return 1
  fi
  if ! ssh_network_runtime_refresh_if_available; then
    ssh_add_user_fail_with_rollback "${username}" "${qf}" "${acc_file}" "Gagal refresh runtime SSH Network setelah commit user Linux." "${password}" "true" "true" "${add_txn_dir}"
    pause
    return 1
  fi

  SSH_ADD_ABORT_ACTIVE="0"
  ssh_add_txn_marker_clear "${username}" >/dev/null 2>&1 || true
  mutation_txn_dir_remove "${add_txn_dir}"
  log "Akun SSH berhasil dibuat: ${username}"
  title
  echo "Add SSH user sukses ✅"
  hr
  echo "Account file:"
  echo "  ${acc_file}"
  echo "Metadata file:"
  echo "  ${qf}"
  hr
  echo "SSH ACCOUNT INFO:"
  if [[ -f "${acc_file}" ]]; then
    cat "${acc_file}"
  else
    echo "(SSH ACCOUNT INFO tidak ditemukan: ${acc_file})"
  fi
  hr
  pause
}

ssh_delete_user_snapshot_restore() {
  local username="$1"
  local state_mode="$2"
  local state_backup="$3"
  local state_file="$4"
  local state_compat_mode="$5"
  local state_compat_backup="$6"
  local state_compat_file="$7"
  local account_mode="$8"
  local account_backup="$9"
  local account_file="${10}"
  local account_compat_mode="${11}"
  local account_compat_backup="${12}"
  local account_compat_file="${13}"
  local -a notes=()

  if ! ssh_optional_file_snapshot_restore "${state_mode}" "${state_backup}" "${state_file}" 600; then
    notes+=("restore state SSH gagal")
  fi
  if ! ssh_optional_file_snapshot_restore "${state_compat_mode}" "${state_compat_backup}" "${state_compat_file}" 600; then
    notes+=("restore state SSH compat gagal")
  fi
  if ! ssh_optional_file_snapshot_restore "${account_mode}" "${account_backup}" "${account_file}" 600; then
    notes+=("restore SSH ACCOUNT INFO gagal")
  fi
  if ! ssh_optional_file_snapshot_restore "${account_compat_mode}" "${account_compat_backup}" "${account_compat_file}" 600; then
    notes+=("restore SSH ACCOUNT INFO compat gagal")
  fi

  if ! ssh_dns_adblock_runtime_refresh_if_available; then
    notes+=("refresh runtime DNS adblock rollback gagal")
  fi
  if ! ssh_network_runtime_refresh_if_available; then
    notes+=("refresh runtime SSH Network rollback gagal")
  fi

  if (( ${#notes[@]} > 0 )); then
    printf '%s\n' "$(IFS=' | '; echo "${notes[*]}")"
    return 1
  fi
  return 0
}

ssh_delete_user_quarantine_for_delete() {
  local username="${1:-}"
  local pending_shell=""
  [[ -n "${username}" ]] || return 1
  pending_shell="$(ssh_pending_login_shell_get)"
  if ! usermod -s "${pending_shell}" "${username}" >/dev/null 2>&1; then
    return 1
  fi
  if ! chage -E 0 "${username}" >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

ssh_delete_user_predelete_restore() {
  local username="${1:-}"
  local linux_meta_file="${2:-}"
  local state_mode="${3:-absent}"
  local state_backup="${4:-}"
  local shell="" expired_at="-"
  [[ -n "${username}" ]] || return 1
  if ! id "${username}" >/dev/null 2>&1; then
    return 1
  fi
  shell="$(ssh_linux_account_snapshot_field_get "${linux_meta_file}" shell 2>/dev/null || true)"
  [[ -n "${shell}" ]] || shell="/bin/bash"
  if ! usermod -s "${shell}" "${username}" >/dev/null 2>&1; then
    return 1
  fi
  expired_at="$(ssh_snapshot_expired_at_read "${state_mode}" "${state_backup}")"
  if ! ssh_apply_expiry "${username}" "${expired_at}"; then
    return 1
  fi
  return 0
}

ssh_snapshot_expired_at_read() {
  local mode="${1:-absent}"
  local backup_file="${2:-}"
  if [[ "${mode}" != "file" || -z "${backup_file}" || ! -f "${backup_file}" ]]; then
    printf '%s\n' "-"
    return 0
  fi
  need_python3
  python3 - <<'PY' "${backup_file}" 2>/dev/null || printf '%s\n' "-"
import json
import re
import sys

try:
  data = json.load(open(sys.argv[1], "r", encoding="utf-8"))
except Exception:
  print("-")
  raise SystemExit(0)

value = str((data or {}).get("expired_at") or "").strip()
match = re.search(r"\d{4}-\d{2}-\d{2}", value)
print(match.group(0) if match else "-")
PY
}

ssh_delete_user_os_rollback() {
  local username="${1:-}"
  local previous_password="${2:-}"
  local state_mode="${3:-absent}"
  local state_backup="${4:-}"
  local state_file="${5:-}"
  local state_compat_mode="${6:-absent}"
  local state_compat_backup="${7:-}"
  local state_compat_file="${8:-}"
  local account_mode="${9:-absent}"
  local account_backup="${10:-}"
  local account_file="${11}"
  local account_compat_mode="${12:-absent}"
  local account_compat_backup="${13:-}"
  local account_compat_file="${14}"
  local linux_meta_file="${18:-}"
  local home_mode="${19:-absent}"
  local home_backup="${20:-}"
  local expired_at="-"
  local restore_msg=""
  local home_dir="" shell="/bin/bash" primary_group="" supp_groups="" uid="" password_hash="" gecos=""
  local -a useradd_args=()

  [[ -n "${username}" ]] || {
    echo "username rollback kosong"
    return 1
  }
  if [[ -z "${previous_password}" || "${previous_password}" == "-" ]]; then
    echo "password lama tidak tersedia untuk rollback OS"
    return 1
  fi
  if id "${username}" >/dev/null 2>&1; then
    echo "akun Linux '${username}' sudah ada; rollback OS dibatalkan"
    return 1
  fi

  home_dir="$(ssh_linux_account_snapshot_field_get "${linux_meta_file}" home 2>/dev/null || true)"
  shell="$(ssh_linux_account_snapshot_field_get "${linux_meta_file}" shell 2>/dev/null || true)"
  gecos="$(ssh_linux_account_snapshot_field_get "${linux_meta_file}" gecos 2>/dev/null || true)"
  primary_group="$(ssh_linux_account_snapshot_field_get "${linux_meta_file}" primary_group 2>/dev/null || true)"
  supp_groups="$(ssh_linux_account_snapshot_field_get "${linux_meta_file}" supp_groups 2>/dev/null || true)"
  uid="$(ssh_linux_account_snapshot_field_get "${linux_meta_file}" uid 2>/dev/null || true)"
  password_hash="$(ssh_linux_account_snapshot_field_get "${linux_meta_file}" password_hash 2>/dev/null || true)"
  [[ -n "${home_dir}" ]] || home_dir="$(ssh_user_home_dir_default "${username}")"
  [[ -n "${shell}" ]] || shell="/bin/bash"
  useradd_args=(-M -d "${home_dir}" -s "${shell}")
  if [[ -n "${gecos}" ]]; then
    useradd_args+=(-c "${gecos}")
  fi
  if [[ -n "${uid}" && "${uid}" =~ ^[0-9]+$ ]] && ! getent passwd "${uid}" >/dev/null 2>&1; then
    useradd_args+=(-u "${uid}")
  fi
  if [[ -n "${primary_group}" ]] && getent group "${primary_group}" >/dev/null 2>&1; then
    useradd_args+=(-g "${primary_group}")
  fi
  if ! useradd "${useradd_args[@]}" "${username}" >/dev/null 2>&1; then
    echo "gagal membuat ulang user Linux"
    return 1
  fi
  if [[ -n "${password_hash}" && "${password_hash}" != "!" && "${password_hash}" != "*" ]]; then
    if ! usermod -p "${password_hash}" "${username}" >/dev/null 2>&1; then
      userdel -r "${username}" >/dev/null 2>&1 || true
      echo "gagal memulihkan hash password Linux"
      return 1
    fi
  else
    if ! printf '%s:%s\n' "${username}" "${previous_password}" | chpasswd >/dev/null 2>&1; then
      userdel -r "${username}" >/dev/null 2>&1 || true
      echo "gagal memulihkan password Linux"
      return 1
    fi
  fi
  expired_at="$(ssh_snapshot_expired_at_read "${state_mode}" "${state_backup}")"
  if ! ssh_apply_expiry "${username}" "${expired_at}"; then
    userdel -r "${username}" >/dev/null 2>&1 || true
    echo "gagal memulihkan expiry Linux"
    return 1
  fi
  if ! ssh_home_snapshot_restore "${username}" "${home_mode}" "${home_backup}"; then
    userdel -r "${username}" >/dev/null 2>&1 || true
    echo "gagal memulihkan home user Linux"
    return 1
  fi
  if [[ -n "${supp_groups}" ]]; then
    usermod -a -G "${supp_groups}" "${username}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${primary_group}" ]]; then
    chown -R "${username}:${primary_group}" "${home_dir}" >/dev/null 2>&1 || true
  fi

  restore_msg="$(ssh_delete_user_snapshot_restore \
    "${username}" \
    "${state_mode}" "${state_backup}" "${state_file}" \
    "${state_compat_mode}" "${state_compat_backup}" "${state_compat_file}" \
    "${account_mode}" "${account_backup}" "${account_file}" \
    "${account_compat_mode}" "${account_compat_backup}" "${account_compat_file}" 2>/dev/null || true)"
  if [[ -n "${restore_msg}" ]]; then
    echo "${restore_msg}"
    return 1
  fi
  echo "ok"
  return 0
}

ssh_delete_user_apply_locked() {
  local username="$1"
  local previous_password="$2"
  local linux_exists="$3"
  local cleanup_failed=""
  local delete_txn_dir=""
  local snapshot_dir="" state_mode="absent" state_backup="" state_file=""
  local state_compat_mode="absent" state_compat_backup="" state_compat_file=""
  local account_mode="absent" account_backup="" account_file=""
  local account_compat_mode="absent" account_compat_backup="" account_compat_file=""
  local linux_meta_file=""
  local home_mode="absent" home_backup=""
  local rollback_restored="false"
  local -a notes=()

  delete_txn_dir="$(mutation_txn_dir_new "ssh-delete.${username}" 2>/dev/null || true)"
  if [[ -z "${delete_txn_dir}" || ! -d "${delete_txn_dir}" ]]; then
    warn "Gagal menyiapkan journal recovery delete user SSH."
    pause
    return 1
  fi
  state_file="$(ssh_user_state_file "${username}")"
  state_compat_file="$(ssh_user_state_compat_file "${username}")"
  account_file="$(ssh_account_info_file "${username}")"
  account_compat_file="${SSH_ACCOUNT_DIR}/${username}.txt"
  snapshot_dir="${delete_txn_dir}"
  if ! ssh_optional_file_snapshot_create "${state_file}" "${snapshot_dir}" state_mode state_backup \
    || ! ssh_optional_file_snapshot_create "${state_compat_file}" "${snapshot_dir}" state_compat_mode state_compat_backup \
    || ! ssh_optional_file_snapshot_create "${account_file}" "${snapshot_dir}" account_mode account_backup \
    || ! ssh_optional_file_snapshot_create "${account_compat_file}" "${snapshot_dir}" account_compat_mode account_compat_backup; then
    mutation_txn_dir_remove "${delete_txn_dir}"
    warn "Gagal membuat snapshot artefak SSH sebelum delete."
    pause
    return 1
  fi

  if ! ssh_home_snapshot_create "${username}" "${snapshot_dir}" home_mode home_backup; then
    mutation_txn_dir_remove "${delete_txn_dir}"
    warn "Gagal membuat snapshot home user Linux sebelum delete."
    pause
    return 1
  fi
  if [[ "${linux_exists}" == "true" ]] && ! ssh_linux_account_snapshot_create "${username}" "${snapshot_dir}" linux_meta_file; then
    mutation_txn_dir_remove "${delete_txn_dir}"
    warn "Gagal membuat snapshot metadata akun Linux sebelum delete."
    pause
    return 1
  fi
  mutation_txn_field_write "${delete_txn_dir}" username "${username}" >/dev/null 2>&1 || true
  mutation_txn_field_write "${delete_txn_dir}" linux_deleted "0" >/dev/null 2>&1 || true


  if [[ "${linux_exists}" == "true" ]] && ! ssh_delete_user_quarantine_for_delete "${username}"; then
    local restore_msg=""
    restore_msg="$(ssh_delete_user_snapshot_restore \
      "${username}" \
      "${state_mode}" "${state_backup}" "${state_file}" \
      "${state_compat_mode}" "${state_compat_backup}" "${state_compat_file}" \
      "${account_mode}" "${account_backup}" "${account_file}" \
      "${account_compat_mode}" "${account_compat_backup}" "${account_compat_file}" \ 2>/dev/null || true)"
    mutation_txn_dir_remove "${delete_txn_dir}"
    warn "Gagal mengarantina akun Linux '${username}' sebelum delete."
    [[ -n "${restore_msg}" ]] && warn "Rollback snapshot belum sepenuhnya bersih: ${restore_msg}"
    pause
    return 1
  fi

  cleanup_failed="$(ssh_delete_user_cleanup_after_linux_delete "${username}" 2>/dev/null || true)"
  if [[ -n "${cleanup_failed}" ]]; then
    local rollback_msg=""
    rollback_msg="$(ssh_delete_user_predelete_restore "${username}" "${linux_meta_file}" "${state_mode}" "${state_backup}" 2>/dev/null || true)"
    if [[ -n "${rollback_msg}" ]]; then
      notes+=("${cleanup_failed}")
      notes+=("rollback status akun Linux gagal: ${rollback_msg}")
    else
      rollback_msg="$(ssh_delete_user_snapshot_restore \
        "${username}" \
        "${state_mode}" "${state_backup}" "${state_file}" \
        "${state_compat_mode}" "${state_compat_backup}" "${state_compat_file}" \
        "${account_mode}" "${account_backup}" "${account_file}" \
        "${account_compat_mode}" "${account_compat_backup}" "${account_compat_file}" \ 2>/dev/null || true)"
      if [[ -z "${rollback_msg}" ]]; then
        rollback_restored="true"
        cleanup_failed=""
        mutation_txn_dir_remove "${delete_txn_dir}"
      else
        notes+=("${cleanup_failed}")
        notes+=("rollback snapshot gagal: ${rollback_msg}")
      fi
    fi
  fi
  if [[ -z "${cleanup_failed}" && "${linux_exists}" == "true" ]] && ! ssh_userdel_purge "${username}" >/dev/null 2>&1; then
    local restore_msg=""
    restore_msg="$(ssh_delete_user_predelete_restore "${username}" "${linux_meta_file}" "${state_mode}" "${state_backup}" 2>/dev/null || true)"
    [[ -n "${restore_msg}" ]] && notes+=("rollback status akun Linux gagal: ${restore_msg}")
    restore_msg="$(ssh_delete_user_snapshot_restore \
      "${username}" \
      "${state_mode}" "${state_backup}" "${state_file}" \
      "${state_compat_mode}" "${state_compat_backup}" "${state_compat_file}" \
      "${account_mode}" "${account_backup}" "${account_file}" \
      "${account_compat_mode}" "${account_compat_backup}" "${account_compat_file}" \ 2>/dev/null || true)"
    [[ -n "${restore_msg}" ]] && notes+=("rollback snapshot gagal: ${restore_msg}")
    cleanup_failed="Gagal menghapus user Linux '${username}' setelah cleanup artefak selesai."
  elif [[ -z "${cleanup_failed}" ]]; then
    mutation_txn_field_write "${delete_txn_dir}" linux_deleted "1" >/dev/null 2>&1 || true
  fi

  title
  if [[ "${rollback_restored}" == "true" ]]; then
    echo "Delete SSH user dibatalkan ⚠"
    echo "Cleanup akhir gagal, tetapi akun Linux dan artefak managed berhasil dipulihkan."
    hr
    pause
    return 1
  fi
  if [[ -n "${cleanup_failed}" ]]; then
    local linux_state_msg=""
    if id "${username}" >/dev/null 2>&1; then
      linux_state_msg="Akun Linux masih ada dan kemungkinan berada dalam status karantina, sedangkan cleanup lanjutan belum sepenuhnya bersih."
    else
      linux_state_msg="Akun Linux sudah terhapus, tetapi cleanup lanjutan belum sepenuhnya bersih."
    fi
    echo "Delete SSH user selesai parsial ⚠"
    echo "${linux_state_msg}"
    if (( ${#notes[@]} > 0 )); then
      printf '%s\n' "$(IFS=' | '; echo "${notes[*]}")"
    fi
    warn "Journal recovery delete SSH dipertahankan di ${delete_txn_dir}."
    hr
    pause
    return 1
  fi

  mutation_txn_dir_remove "${delete_txn_dir}"
  echo "Delete SSH user selesai ✅"
  hr
  echo "Akun Linux dan artefak managed untuk '${username}' berhasil dihapus."
  hr
  pause
  return 0
}

ssh_extend_expiry_apply_locked() {
  local username="$1"
  local new_expiry="$2"
  local previous_expiry="$3"

  if ! ssh_apply_expiry "${username}" "${new_expiry}"; then
    warn "Gagal update expiry untuk '${username}'."
    pause
    return 1
  fi

  local created_at
  created_at="$(ssh_user_state_created_at_get "${username}")"
  if [[ -z "${created_at}" ]]; then
    created_at="$(date '+%Y-%m-%d')"
  fi
  if ! ssh_user_state_write "${username}" "${created_at}" "${new_expiry}"; then
    local rollback_msg=""
    rollback_msg="$(ssh_expiry_update_rollback "${username}" "${previous_expiry}" 2>/dev/null || true)"
    if [[ -n "${rollback_msg}" ]]; then
      warn "Metadata SSH gagal diperbarui untuk '${username}'. Rollback: ${rollback_msg}"
    else
      warn "Metadata SSH gagal diperbarui untuk '${username}'."
    fi
    pause
    return 1
  fi
  if ! ssh_account_info_refresh_from_state "${username}"; then
    local rollback_msg=""
    rollback_msg="$(ssh_expiry_update_rollback "${username}" "${previous_expiry}" 2>/dev/null || true)"
    if [[ -n "${rollback_msg}" ]]; then
      warn "SSH ACCOUNT INFO gagal disinkronkan untuk '${username}'. Rollback: ${rollback_msg}"
    else
      warn "SSH ACCOUNT INFO gagal disinkronkan untuk '${username}'."
    fi
    pause
    return 1
  fi

  log "Expiry akun '${username}' diperbarui ke ${new_expiry}."
  pause
}

ssh_reset_password_apply_locked() {
  local username="$1"
  local previous_password="$2"
  local password="$3"
  local snapshot_dir="" account_snapshot_mode="absent" account_snapshot_backup="" account_file=""

  account_file="$(ssh_account_info_file "${username}")"
  snapshot_dir="$(mktemp -d "${TMPDIR:-/tmp}/ssh-reset.${username}.XXXXXX" 2>/dev/null || true)"
  if [[ -z "${snapshot_dir}" || ! -d "${snapshot_dir}" ]]; then
    warn "Gagal menyiapkan snapshot rollback password SSH."
    pause
    return 1
  fi
  if ! ssh_optional_file_snapshot_create "${account_file}" "${snapshot_dir}" account_snapshot_mode account_snapshot_backup; then
    rm -rf "${snapshot_dir}" >/dev/null 2>&1 || true
    warn "Gagal membuat snapshot SSH ACCOUNT INFO sebelum reset password."
    pause
    return 1
  fi


  if ! ssh_apply_password "${username}" "${password}"; then
    rm -rf "${snapshot_dir}" >/dev/null 2>&1 || true
    warn "Gagal reset password user '${username}'."
    pause
    return 1
  fi

  if ! ssh_account_info_refresh_from_state "${username}" "${password}"; then
    local rollback_msg=""
    rollback_msg="$(ssh_password_reset_rollback "${username}" "${previous_password}" "${account_snapshot_mode}" "${account_snapshot_backup}" "${account_file}" 2>/dev/null || true)"
    rm -rf "${snapshot_dir}" >/dev/null 2>&1 || true
    if [[ -n "${rollback_msg}" ]]; then
      warn "SSH ACCOUNT INFO gagal disinkronkan untuk '${username}'. Rollback: ${rollback_msg}"
    else
      warn "SSH ACCOUNT INFO gagal disinkronkan untuk '${username}'."
    fi
    pause
    return 1
  fi
  if ! ssh_account_info_refresh_from_state "${username}" "${password}"; then
    local rollback_msg=""
    rollback_msg="$(ssh_password_reset_rollback "${username}" "${previous_password}" "${account_snapshot_mode}" "${account_snapshot_backup}" "${account_file}" 2>/dev/null || true)"
    rm -rf "${snapshot_dir}" >/dev/null 2>&1 || true
    if [[ -n "${rollback_msg}" ]]; then
      warn "Refresh final SSH ACCOUNT INFO gagal untuk '${username}'. Rollback: ${rollback_msg}"
    else
      warn "Refresh final SSH ACCOUNT INFO gagal untuk '${username}'."
    fi
    pause
    return 1
  fi
  rm -rf "${snapshot_dir}" >/dev/null 2>&1 || true

  log "Password akun '${username}' berhasil direset."
  pause
}

ssh_add_user_menu() {
  local username qf acc_file header_page=0
  while true; do
    title
  echo "2) SSH Users > Add User"
    hr
    ssh_add_user_header_render header_page
    hr

    if ! read -r -p "Username SSH (atau next/previous/kembali): " username; then
      echo
      return 0
    fi
    if is_back_choice "${username}"; then
      return 0
    fi
    case "${username,,}" in
      next|n)
        header_page=$((header_page + 1))
        continue
        ;;
      previous|prev|p)
        header_page=$((header_page - 1))
        continue
        ;;
    esac
    username="${username,,}"
    break
  done

  if ! ssh_username_valid "${username}"; then
    warn "Username tidak valid. Gunakan format Linux user (huruf kecil/angka/_/-)."
    pause
    return 0
  fi
  local dup_reason=""
  if dup_reason="$(ssh_username_duplicate_reason "${username}")"; then
    warn "${dup_reason}"
    pause
    return 0
  fi
  qf="$(ssh_user_state_file "${username}")"
  acc_file="$(ssh_account_info_file "${username}")"

  local password=""
  if ! ssh_read_password_confirm password; then
    pause
    return 0
  fi
  if [[ "${username,,}" == "${password,,}" ]]; then
    warn "Password SSH tidak boleh sama dengan username."
    pause
    return 0
  fi

  local active_days
  if ! read -r -p "Masa aktif (hari) (atau kembali): " active_days; then
    echo
    return 0
  fi
  if is_back_choice "${active_days}"; then
    return 0
  fi
  if [[ -z "${active_days}" || ! "${active_days}" =~ ^[0-9]+$ || "${active_days}" -le 0 ]]; then
    warn "Masa aktif harus angka hari > 0."
    pause
    return 0
  fi

  local quota_input quota_gb quota_bytes
  if ! read -r -p "Quota (GB) (atau kembali): " quota_input; then
    echo
    return 0
  fi
  if is_back_choice "${quota_input}"; then
    return 0
  fi
  quota_gb="$(normalize_gb_input "${quota_input}")"
  if [[ -z "${quota_gb}" ]]; then
    warn "Format quota tidak valid. Contoh: 5 atau 5GB."
    pause
    return 0
  fi
  quota_bytes="$(bytes_from_gb "${quota_gb}")"

  local ip_toggle ip_enabled="false" ip_limit="0"
  echo "Limit IP? (on/off)"
  if ! read_required_on_off ip_toggle "IP Limit (on/off) (atau kembali): "; then
    return 0
  fi
  case "${ip_toggle}" in
    on)
      ip_enabled="true"
      if ! read -r -p "Limit IP (angka) (atau kembali): " ip_limit; then
        echo
        return 0
      fi
      if is_back_word_choice "${ip_limit}"; then
        return 0
      fi
      if [[ -z "${ip_limit}" || ! "${ip_limit}" =~ ^[0-9]+$ || "${ip_limit}" -le 0 ]]; then
        warn "Limit IP harus angka > 0."
        pause
        return 0
      fi
      ;;
    off) ip_enabled="false" ; ip_limit="0" ;;
    *)
      warn "Pilihan Limit IP harus on/off."
      pause
      return 0
      ;;
  esac

  local speed_toggle speed_enabled="false" speed_down="0" speed_up="0"
  echo "Limit speed per user? (on/off)"
  if ! read_required_on_off speed_toggle "Speed Limit (on/off) (atau kembali): "; then
    return 0
  fi
  case "${speed_toggle}" in
    on)
      speed_enabled="true"
      if ! read -r -p "Speed Download Mbps (contoh: 20 atau 20mbit) (atau kembali): " speed_down; then
        echo
        return 0
      fi
      if is_back_word_choice "${speed_down}"; then
        return 0
      fi
      speed_down="$(normalize_speed_mbit_input "${speed_down}")"
      if [[ -z "${speed_down}" ]] || ! speed_mbit_is_positive "${speed_down}"; then
        warn "Speed download tidak valid. Gunakan angka > 0."
        pause
        return 0
      fi

      if ! read -r -p "Speed Upload Mbps (contoh: 10 atau 10mbit) (atau kembali): " speed_up; then
        echo
        return 0
      fi
      if is_back_word_choice "${speed_up}"; then
        return 0
      fi
      speed_up="$(normalize_speed_mbit_input "${speed_up}")"
      if [[ -z "${speed_up}" ]] || ! speed_mbit_is_positive "${speed_up}"; then
        warn "Speed upload tidak valid. Gunakan angka > 0."
        pause
        return 0
      fi
      ;;
    off)
      speed_enabled="false"
      speed_down="0"
      speed_up="0"
      ;;
    *)
      warn "Pilihan speed limit harus on/off."
      pause
      return 0
      ;;
  esac

  local expired_at created_at
  expired_at="$(date -d "+${active_days} days" '+%Y-%m-%d' 2>/dev/null || true)"
  if [[ -z "${expired_at}" ]]; then
    warn "Gagal menghitung tanggal expiry SSH."
    pause
    return 1
  fi
  created_at="$(date '+%Y-%m-%d')"

  hr
  echo "Ringkasan:"
  echo "  Username : ${username}"
  echo "  Expired  : ${active_days} hari (sampai ${expired_at})"
  echo "  Quota    : ${quota_gb} GB"
  echo "  IP Limit : ${ip_enabled} $( [[ "${ip_enabled}" == "true" ]] && echo "(${ip_limit})" )"
  if [[ "${speed_enabled}" == "true" ]]; then
    echo "  Speed    : true (DOWN ${speed_down} Mbps | UP ${speed_up} Mbps)"
  else
    echo "  Speed    : false"
  fi
  hr
  local create_confirm_rc=0
  if confirm_yn_or_back "Buat akun SSH ini sekarang?"; then
    :
  else
    create_confirm_rc=$?
    if (( create_confirm_rc == 2 )); then
      warn "Pembuatan akun SSH dibatalkan (kembali)."
      pause
      return 0
    fi
    warn "Pembuatan akun SSH dibatalkan."
    pause
    return 0
  fi

  if user_data_mutation_run_locked ssh_add_user_apply_locked "${username}" "${qf}" "${acc_file}" "${password}" "${expired_at}" "${created_at}" "${quota_bytes}" "${ip_enabled}" "${ip_limit}" "${speed_enabled}" "${speed_down}" "${speed_up}"; then
    password=""
    return 0
  fi
  password=""
  return 1
}

ssh_delete_user_menu() {
  title
  echo "2) SSH Users > Delete User"
  hr

  local username
  local pick_rc=0
  ssh_pick_managed_user username
  pick_rc=$?
  if (( pick_rc != 0 )); then
    if (( pick_rc == 2 )); then
      return 0
    fi
    pause
    return 0
  fi

  local ask_rc=0
  confirm_yn_or_back "Hapus akun SSH '${username}' sekarang?"
  ask_rc=$?
  if (( ask_rc != 0 )); then
    if (( ask_rc == 2 )); then
      return 0
    fi
    warn "Dibatalkan."
    pause
    return 0
  fi

  local previous_password
  previous_password="$(ssh_previous_password_get "${username}")"
  local linux_exists="false"
  if id "${username}" >/dev/null 2>&1; then
    linux_exists="true"
  fi
  user_data_mutation_run_locked ssh_delete_user_apply_locked "${username}" "${previous_password}" "${linux_exists}"
}

ssh_extend_expiry_menu() {
  title
  echo "2) SSH Users > Set Expiry"
  hr

  local username
  local pick_rc=0
  ssh_pick_managed_user username
  pick_rc=$?
  if (( pick_rc != 0 )); then
    if (( pick_rc == 2 )); then
      return 0
    fi
    pause
    return 0
  fi
  if ! id "${username}" >/dev/null 2>&1; then
    warn "User Linux '${username}' tidak ditemukan."
    pause
    return 0
  fi

  local current_exp
  current_exp="$(chage -l "${username}" 2>/dev/null | awk -F': ' '/Account expires/{print $2; exit}' || true)"
  [[ -n "${current_exp}" ]] || current_exp="-"
  echo "Expiry saat ini: ${current_exp}"
  hr
  echo "  1) Add days from today"
  echo "  2) Set date (YYYY-MM-DD)"
  echo "  0) Back"
  hr

  local mode
  if ! read -r -p "Pilih: " mode; then
    echo
    return 0
  fi
  if is_back_choice "${mode}"; then
    return 0
  fi

  local new_expiry=""
  case "${mode}" in
    1)
      local add_days
      if ! read -r -p "Tambah berapa hari: " add_days; then
        echo
        return 0
      fi
      if is_back_choice "${add_days}"; then
        return 0
      fi
      if [[ ! "${add_days}" =~ ^[0-9]+$ ]] || (( add_days < 1 || add_days > 3650 )); then
        warn "Input hari tidak valid."
        pause
        return 0
      fi
      new_expiry="$(date -d "+${add_days} days" '+%Y-%m-%d' 2>/dev/null || true)"
      ;;
    2)
      if ! read -r -p "Tanggal expiry baru (YYYY-MM-DD): " new_expiry; then
        echo
        return 0
      fi
      if is_back_choice "${new_expiry}"; then
        return 0
      fi
      if ! new_expiry="$(ssh_strict_date_ymd_normalize "${new_expiry}" 2>/dev/null)"; then
        warn "Format tanggal tidak valid."
        pause
        return 0
      fi
      ;;
    *)
      invalid_choice
      return 0
      ;;
  esac

  if [[ -z "${new_expiry}" ]]; then
    warn "Gagal menentukan expiry baru."
    pause
    return 0
  fi

  if date_ymd_is_past "${new_expiry}"; then
    warn "Tanggal expiry ${new_expiry} sudah lewat dan akan membuat akun segera expired."
    if ! confirm_menu_apply_now "Tetap terapkan expiry lampau ${new_expiry} untuk akun SSH ${username}?"; then
      pause
      return 0
    fi
  fi

  hr
  echo "Ringkasan perubahan:"
  echo "  Username : ${username}"
  echo "  Expiry baru : ${new_expiry}"
  hr
  local confirm_rc=0
  if confirm_yn_or_back "Update expiry akun SSH ini sekarang?"; then
    :
  else
    confirm_rc=$?
    if (( confirm_rc == 2 )); then
      warn "Update expiry SSH dibatalkan (kembali)."
      pause
      return 0
    fi
    warn "Update expiry SSH dibatalkan."
    pause
    return 0
  fi

  local previous_expiry
  previous_expiry="$(ssh_user_state_expired_at_get "${username}" 2>/dev/null || true)"
  [[ -n "${previous_expiry}" ]] || previous_expiry="-"
  user_data_mutation_run_locked ssh_extend_expiry_apply_locked "${username}" "${new_expiry}" "${previous_expiry}"
}

ssh_reset_password_menu() {
  title
  echo "2) SSH Users > Reset Password"
  hr

  local username
  local pick_rc=0
  ssh_pick_managed_user username
  pick_rc=$?
  if (( pick_rc != 0 )); then
    if (( pick_rc == 2 )); then
      return 0
    fi
    pause
    return 0
  fi
  if ! id "${username}" >/dev/null 2>&1; then
    warn "User Linux '${username}' tidak ditemukan."
    pause
    return 0
  fi

  local previous_password
  previous_password="$(ssh_previous_password_get "${username}")"
  if [[ -z "${previous_password}" || "${previous_password}" == "-" ]]; then
    warn "Password lama untuk '${username}' tidak tersedia, jadi rollback aman tidak bisa dijamin."
    pause
    return 0
  fi

  local password=""
  if ! ssh_read_password_confirm password; then
    pause
    return 0
  fi

  local reset_confirm_rc=0
  if confirm_yn_or_back "Reset password akun SSH ini sekarang?"; then
    :
  else
    reset_confirm_rc=$?
    if (( reset_confirm_rc == 2 )); then
      warn "Reset password SSH dibatalkan (kembali)."
      pause
      return 0
    fi
    warn "Reset password SSH dibatalkan."
    pause
    return 0
  fi

  if user_data_mutation_run_locked ssh_reset_password_apply_locked "${username}" "${previous_password}" "${password}"; then
    password=""
    return 0
  fi
  password=""
  return 1
}

ssh_list_users_menu() {
  local -a users=()
  local u

  ssh_state_dirs_prepare
  need_python3

  while IFS= read -r u; do
    [[ -n "${u}" ]] || continue
    if ssh_add_txn_linux_pending_contains "${u}"; then
      continue
    fi
    users+=("${u}")
  done < <(find "${SSH_USERS_STATE_DIR}" -maxdepth 1 -type f -name '*.json' -printf '%f\n' 2>/dev/null | sed -E 's/@ssh\.json$//' | sed -E 's/\.json$//' | sort -u)

  if (( ${#users[@]} == 0 )); then
    title
    echo "2) SSH Users > List Users"
    hr
    warn "Belum ada akun SSH terkelola."
    hr
    pause
    return 0
  fi

  while true; do
    title
    echo "2) SSH Users > List Users"
    hr
    printf "%-4s %-20s %-12s %-12s %-12s\n" "No" "Username" "Created" "Expired" "SystemUser"
    local i username qf fields meta_user created expired sys_user
    for i in "${!users[@]}"; do
      username="${users[$i]}"
      qf="$(ssh_user_state_file "${username}")"
      fields="$(python3 - <<'PY' "${qf}" 2>/dev/null || true
import json
import re
import sys
from datetime import datetime

path = sys.argv[1]
username = ""
created = "-"
expired = "-"

def norm_created(v):
  s = str(v or "").strip()
  if not s or s == "-":
    return "-"
  s = s.replace("T", " ").strip()
  if s.endswith("Z"):
    s = s[:-1]
  if len(s) >= 10 and re.match(r"^\d{4}-\d{2}-\d{2}$", s[:10]):
    return s[:10]
  try:
    dt = datetime.fromisoformat(s)
    return dt.strftime("%Y-%m-%d")
  except Exception:
    pass
  m = re.search(r"\d{4}-\d{2}-\d{2}", s)
  if m:
    return m.group(0)
  return "-"

def norm_expired(v):
  s = str(v or "").strip()
  if not s or s == "-":
    return "-"
  m = re.search(r"\d{4}-\d{2}-\d{2}", s)
  return m.group(0) if m else "-"

try:
  with open(path, "r", encoding="utf-8") as f:
    d = json.load(f)
  if isinstance(d, dict):
    username = str(d.get("username") or "").strip()
    created = norm_created(d.get("created_at"))
    expired = norm_expired(d.get("expired_at"))
except Exception:
  pass
print("|".join([username, created, expired]))
PY
)"
      IFS='|' read -r meta_user created expired <<<"${fields}"
      if [[ -n "${meta_user}" ]]; then
        meta_user="$(ssh_username_from_key "${meta_user}")"
        [[ -n "${meta_user}" ]] && username="${meta_user}"
      fi
      sys_user="present"
      if ! id "${username}" >/dev/null 2>&1; then
        sys_user="missing"
      fi
      printf "%-4s %-20s %-12s %-12s %-12s\n" "$((i + 1))" "${username}" "${created}" "${expired}" "${sys_user}"
    done
    hr
    echo "Ketik NO untuk lihat detail SSH ACCOUNT INFO."
    echo "0/back untuk kembali ke SSH Users."
    hr

    local pick
    if ! read -r -p "Pilih: " pick; then
      echo
      return 0
    fi
    if is_back_choice "${pick}"; then
      return 0
    fi
    if [[ ! "${pick}" =~ ^[0-9]+$ ]] || (( pick < 1 || pick > ${#users[@]} )); then
      warn "Pilihan tidak valid."
      sleep 1
      continue
    fi

    username="${users[$((pick - 1))]}"
    local acc_file password_info
    ssh_account_info_refresh_warn "${username}" || true
    acc_file="$(ssh_account_info_file "${username}")"

    title
    echo "2) SSH Users > SSH ACCOUNT INFO"
    hr
    echo "Username : ${username}"
    echo "File     : ${acc_file}"
    hr
    if [[ -f "${acc_file}" ]]; then
      cat "${acc_file}"
      password_info="$(grep -E '^Password[[:space:]]*:' "${acc_file}" 2>/dev/null | head -n1 | sed -E 's/^Password[[:space:]]*:[[:space:]]*//' || true)"
      if [[ "${password_info}" == "********" || "${password_info}" == "(hidden)" ]]; then
        hr
        warn "File account ini masih memakai format lama yang memask password."
        echo "Gunakan menu 4) Reset Password bila ingin menulis ulang SSH ACCOUNT INFO."
      fi
    else
      warn "SSH ACCOUNT INFO tidak ditemukan untuk '${username}'."
    fi
    hr
    pause
  done
}
