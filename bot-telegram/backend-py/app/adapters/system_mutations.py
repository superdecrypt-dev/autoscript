import base64
import copy
import grp
import ipaddress
import json
import os
import pwd
import random
import re
import secrets
import shutil
import string
import tarfile
import tempfile
import threading
import time
import urllib.parse
import urllib.error
import urllib.request
import uuid
import zlib
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from functools import wraps
from pathlib import Path, PurePosixPath
from typing import Any
from xml.sax.saxutils import escape as xml_escape

from ..utils.locks import file_lock

ACCOUNT_ROOT = Path("/opt/account")
QUOTA_ROOT = Path("/opt/quota")
SPEED_POLICY_ROOT = Path("/opt/speed")
SSH_PROTOCOL = "ssh"
XRAY_PROTOCOLS = ("vless", "vmess", "trojan")
USER_PROTOCOLS = XRAY_PROTOCOLS + (SSH_PROTOCOL,)
QAC_PROTOCOLS = XRAY_PROTOCOLS + (SSH_PROTOCOL,)
SSH_ACCOUNT_DIR = ACCOUNT_ROOT / SSH_PROTOCOL
SSH_QUOTA_DIR = QUOTA_ROOT / SSH_PROTOCOL
SSHWS_PROXY_BIN = Path("/usr/local/bin/ws-proxy")
SSHWS_QAC_ENFORCER_BIN = Path("/usr/local/bin/sshws-qac-enforcer")
SSHWS_RUNTIME_SESSION_DIR = Path("/run/autoscript/sshws-sessions")
SSHWS_LOCK_FILE = Path("/run/autoscript/locks/sshws-qac.lock")
SPEED_CONFIG_FILE = Path("/etc/xray-speed/config.json")
XRAY_CONFDIR = Path("/usr/local/etc/xray/conf.d")
XRAY_INBOUNDS_CONF = XRAY_CONFDIR / "10-inbounds.json"
XRAY_OUTBOUNDS_CONF = XRAY_CONFDIR / "20-outbounds.json"
XRAY_ROUTING_CONF = XRAY_CONFDIR / "30-routing.json"
XRAY_DNS_CONF = XRAY_CONFDIR / "02-dns.json"
NGINX_CONF = Path("/etc/nginx/conf.d/xray.conf")
WIREPROXY_CONF = Path("/etc/wireproxy/config.conf")
WGCF_DIR = Path("/etc/wgcf")
NETWORK_STATE_FILE = Path("/var/lib/xray-manage/network_state.json")
SSH_NETWORK_ENV_FILE = Path("/etc/autoscript/ssh-network/config.env")
SSH_NETWORK_LOCK_FILE = "/run/autoscript/locks/ssh-network.lock"
ADBLOCK_ENV_FILE = Path("/etc/autoscript/ssh-adblock/config.env")
ADBLOCK_SYNC_BIN = Path("/usr/local/bin/adblock-sync")
ADBLOCK_TIMER_DIR = Path("/etc/systemd/system")
ADBLOCK_LOCK_FILE = "/run/autoscript/locks/adblock.lock"
ADBLOCK_XRAY_RULE = "ext:custom.dat:adblock"
ADBLOCK_DEFAULT_BLOCKLIST = "/etc/autoscript/ssh-adblock/blocked.domains"
ADBLOCK_DEFAULT_URLS = "/etc/autoscript/ssh-adblock/source.urls"
ADBLOCK_DEFAULT_MERGED = "/etc/autoscript/ssh-adblock/merged.domains"
ADBLOCK_DEFAULT_RENDERED = "/etc/autoscript/ssh-adblock/blocklist.generated.conf"
ADBLOCK_DEFAULT_DNSMASQ_CONF = "/etc/autoscript/ssh-adblock/dnsmasq.conf"
ADBLOCK_DEFAULT_CUSTOM_DAT = "/usr/local/share/xray/custom.dat"
ADBLOCK_DEFAULT_DNS_SERVICE = "ssh-adblock-dns.service"
ADBLOCK_DEFAULT_SYNC_SERVICE = "adblock-sync.service"
ADBLOCK_DEFAULT_AUTO_UPDATE_SERVICE = "adblock-update.service"
ADBLOCK_DEFAULT_AUTO_UPDATE_TIMER = "adblock-update.timer"
XRAY_DOMAIN_FILE = Path("/etc/xray/domain")
CERT_DIR = Path("/opt/cert")
CERT_FULLCHAIN = CERT_DIR / "fullchain.pem"
CERT_PRIVKEY = CERT_DIR / "privkey.pem"
EDGE_RUNTIME_ENV_FILE = Path("/etc/default/edge-runtime")
WORK_DIR = Path(os.getenv("BOT_STATE_DIR", "/var/lib/bot-telegram")) / "tmp"
ROUTING_LOCK_FILE = "/run/autoscript/locks/xray-routing.lock"
SPEED_POLICY_LOCK_FILE = "/var/lock/xray-speed-policy.lock"
USER_DATA_MUTATION_LOCK_FILE = "/run/autoscript/locks/user-data-mutation.lock"
PROTOCOLS = XRAY_PROTOCOLS
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
SSH_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{1,31}$")
PORTAL_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{10,64}$")
_GEO_LOOKUP_CACHE: dict[str, tuple[str, str]] = {}
DOMAIN_RE = re.compile(r"^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$")
SPEED_OUTBOUND_TAG_PREFIX = "speed-mark-"
SPEED_RULE_MARKER_PREFIX = "dummy-speed-user-"
SPEED_MARK_MIN = 1000
SPEED_MARK_MAX = 59999
QUOTA_UNIT_DECIMAL = {"decimal", "gb", "1000", "gigabyte"}
DEFAULT_EGRESS_PORTS = {"1-65535", "0-65535"}
DNS_LOCK_FILE = "/run/autoscript/locks/xray-dns.lock"
WARP_LOCK_FILE = "/run/autoscript/locks/xray-warp.lock"
WARP_MODE_STATE_KEY = "warp_mode"
DNS_QUERY_STRATEGY_ALLOWED = {"UseIP", "UseIPv4", "UseIPv6", "PreferIPv4", "PreferIPv6"}
DNS_RESTART_TIMEOUT_SEC = 8
DNS_ROLLBACK_RESTART_TIMEOUT_SEC = 5
WARP_TIER_STATE_KEY = "warp_tier_target"
WARP_PLUS_LICENSE_STATE_KEY = "warp_plus_license_key"
WARP_ZEROTRUST_ROOT = Path("/etc/autoscript/warp-zerotrust")
WARP_ZEROTRUST_CONFIG_FILE = WARP_ZEROTRUST_ROOT / "config.env"
WARP_ZEROTRUST_MDM_FILE = Path("/var/lib/cloudflare-warp/mdm.xml")
WARP_ZEROTRUST_SERVICE = "warp-svc"
WARP_ZEROTRUST_PROXY_PORT = "40000"
MANAGE_SCRIPT_CANDIDATES = (
    Path("/usr/local/bin/manage"),
    Path("/opt/autoscript/manage.sh"),
    Path("/root/project/autoscript/manage.sh"),
)
WARP_TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
READONLY_GEOSITE_DOMAINS = {
    "geosite:apple",
    "geosite:meta",
    "geosite:google",
    "geosite:openai",
    "geosite:spotify",
    "geosite:netflix",
    "geosite:reddit",
}
CLOUDFLARE_API_TOKEN = os.getenv(
    "CLOUDFLARE_API_TOKEN",
    "ZEbavEuJawHqX4-Jwj-L5Vj0nHOD-uPXtdxsMiAZ",
).strip()
PROVIDED_ROOT_DOMAINS = (
    "vyxara1.web.id",
    "vyxara2.web.id",
)
ACME_SH_INSTALL_REF = os.getenv("ACME_SH_INSTALL_REF", "f39d066ced0271d87790dc426556c1e02a88c91b").strip()
ACME_SH_TARBALL_URL = f"https://codeload.github.com/acmesh-official/acme.sh/tar.gz/{ACME_SH_INSTALL_REF}"
ACME_SH_SCRIPT_URL = f"https://raw.githubusercontent.com/acmesh-official/acme.sh/{ACME_SH_INSTALL_REF}/acme.sh"
ACME_SH_DNS_CF_HOOK_URL = (
    f"https://raw.githubusercontent.com/acmesh-official/acme.sh/{ACME_SH_INSTALL_REF}/dnsapi/dns_cf.sh"
)

_USER_DATA_MUTATION_LOCK_STATE = threading.local()


@contextmanager
def _user_data_mutation_lock():
    depth = int(getattr(_USER_DATA_MUTATION_LOCK_STATE, "depth", 0) or 0)
    if depth > 0:
        _USER_DATA_MUTATION_LOCK_STATE.depth = depth + 1
        try:
            yield
        finally:
            _USER_DATA_MUTATION_LOCK_STATE.depth = depth
        return

    with file_lock(USER_DATA_MUTATION_LOCK_FILE):
        _USER_DATA_MUTATION_LOCK_STATE.depth = 1
        try:
            yield
        finally:
            _USER_DATA_MUTATION_LOCK_STATE.depth = 0


def _user_data_mutation_locked(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        with _user_data_mutation_lock():
            return func(*args, **kwargs)

    return wrapper


def _run_cmd(
    argv: list[str],
    timeout: int = 25,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
) -> tuple[bool, str]:
    try:
        proc = shutil.which(argv[0])
        if proc is None:
            return False, f"Command tidak ditemukan: {argv[0]}"
        import subprocess

        cp = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
            cwd=cwd,
        )
    except Exception as exc:
        return False, f"Gagal menjalankan {' '.join(argv)}: {exc}"

    out = ((cp.stdout or "") + ("\n" + cp.stderr if cp.stderr else "")).strip()
    if not out:
        out = "(no output)"
    if cp.returncode != 0:
        return False, f"[exit {cp.returncode}]\n{out}"
    return True, out


def _service_exists(name: str) -> bool:
    ok, _ = _run_cmd(["systemctl", "status", name], timeout=10)
    if ok:
        return True
    ok2, out2 = _run_cmd(["systemctl", "list-unit-files", f"{name}.service"], timeout=10)
    if not ok2:
        return False
    return f"{name}.service" in out2


def _service_is_active(name: str) -> bool:
    ok, out = _run_cmd(["systemctl", "is-active", name], timeout=10)
    if not ok:
        return False
    state = out.splitlines()[-1].strip() if out else ""
    return state == "active"


def _service_state(name: str) -> str:
    ok, out = _run_cmd(["systemctl", "is-active", name], timeout=10)
    if ok:
        return out.splitlines()[-1].strip() if out else ""
    if out:
        return out.splitlines()[-1].strip()
    return ""



def _managed_ssh_usernames() -> list[str]:
    names: set[str] = set()
    for directory, suffix in ((SSH_ACCOUNT_DIR, f"@{SSH_PROTOCOL}.txt"), (SSH_QUOTA_DIR, f"@{SSH_PROTOCOL}.json")):
        if not directory.exists():
            continue
        for path in sorted(directory.iterdir()):
            if not path.is_file():
                continue
            name = path.name
            if name.endswith(suffix):
                username = name[: -len(suffix)]
            elif "." in name:
                continue
            else:
                username = name
            username = str(username or "").strip()
            if username:
                names.add(username)
    return sorted(names)


def _edge_runtime_get_env(key: str) -> str:
    try:
        if not EDGE_RUNTIME_ENV_FILE.exists():
            return ""
        for line in EDGE_RUNTIME_ENV_FILE.read_text(encoding="utf-8").splitlines():
            text = line.strip()
            if not text or text.startswith("#") or "=" not in text:
                continue
            env_key, env_value = text.split("=", 1)
            if env_key.strip() == key:
                return env_value.strip()
    except Exception:
        return ""
    return ""


def _edge_runtime_ports(list_key: str, single_key: str, default_list: str, default_single: str) -> list[int]:
    raw = _edge_runtime_get_env(list_key).strip() or _edge_runtime_get_env(single_key).strip()
    if not raw:
        raw = default_list or default_single
    values: list[int] = []
    seen: set[int] = set()
    for token in re.split(r"[\s,]+", raw.strip()):
        if not token or not token.isdigit():
            continue
        port = int(token)
        if port in seen:
            continue
        seen.add(port)
        values.append(port)
    return values


def _edge_runtime_ports_label(ports: list[int]) -> str:
    if not ports:
        return "-"
    return ", ".join(str(port) for port in ports)


def _edge_runtime_http_ports_label() -> str:
    return _edge_runtime_ports_label(
        _edge_runtime_ports(
            "EDGE_PUBLIC_HTTP_PORTS",
            "EDGE_PUBLIC_HTTP_PORT",
            "80,8080,8880,2052,2082,2086,2095",
            "80",
        )
    )


def _edge_runtime_tls_ports_label() -> str:
    return _edge_runtime_ports_label(
        _edge_runtime_ports(
            "EDGE_PUBLIC_TLS_PORTS",
            "EDGE_PUBLIC_TLS_PORT",
            "443,2053,2083,2087,2096,8443",
            "443",
        )
    )


def _edge_runtime_ws_ports_label() -> str:
    return "443, 80"


def _edge_runtime_alt_tls_ports_label() -> str:
    ports = [
        port
        for port in _edge_runtime_ports(
            "EDGE_PUBLIC_TLS_PORTS",
            "EDGE_PUBLIC_TLS_PORT",
            "443,2053,2083,2087,2096,8443",
            "443",
        )
        if port != 443
    ]
    return _edge_runtime_ports_label(ports)


def _edge_runtime_alt_http_ports_label() -> str:
    ports = [
        port
        for port in _edge_runtime_ports(
            "EDGE_PUBLIC_HTTP_PORTS",
            "EDGE_PUBLIC_HTTP_PORT",
            "80,8080,8880,2052,2082,2086,2095",
            "80",
        )
        if port != 80
    ]
    return _edge_runtime_ports_label(ports)


def _edge_runtime_service_name() -> str:
    provider = _edge_runtime_get_env("EDGE_PROVIDER").strip().lower()
    if provider == "nginx-stream":
        return "nginx"
    if provider == "go":
        return "edge-mux.service"
    return ""


def _edge_runtime_uses_public_http_port_80() -> bool:
    provider = _edge_runtime_get_env("EDGE_PROVIDER").strip().lower()
    active = _edge_runtime_get_env("EDGE_ACTIVATE_RUNTIME").strip().lower()
    http_ports = _edge_runtime_ports(
        "EDGE_PUBLIC_HTTP_PORTS",
        "EDGE_PUBLIC_HTTP_PORT",
        "80,8080,8880,2052,2082,2086,2095",
        "80",
    )
    if provider in {"", "none"}:
        return False
    if active not in {"1", "true", "yes", "on", "y"}:
        return False
    return 80 in http_ports


def _restart_and_wait(name: str, timeout_sec: int = 20) -> bool:
    if not _service_exists(name):
        return False

    cmd_timeout = max(4, min(30, timeout_sec + 4))
    ok_restart, _ = _run_cmd(["systemctl", "restart", name], timeout=cmd_timeout)
    if ok_restart:
        end = time.time() + max(1, timeout_sec)
        while time.time() < end:
            if _service_is_active(name):
                return True
            time.sleep(0.5)
        if _service_is_active(name):
            return True
    else:
        state_after_restart = _service_state(name)
        if state_after_restart not in {"failed", "inactive", "activating", "deactivating"}:
            return False

    # Recovery path for restart failures or services that never came back up.
    state_now = _service_state(name)
    if state_now in {"failed", "inactive", "activating", "deactivating"}:
        _run_cmd(["systemctl", "reset-failed", name], timeout=10)
        ok_start, _ = _run_cmd(["systemctl", "start", name], timeout=cmd_timeout)
        if not ok_start:
            return False
        end2 = time.time() + max(1, timeout_sec)
        while time.time() < end2:
            if _service_is_active(name):
                return True
            time.sleep(0.5)
        return _service_is_active(name)

    return False


def _stop_and_wait_inactive(name: str, timeout_sec: int = 20) -> bool:
    if not _service_exists(name):
        return True

    cmd_timeout = max(4, min(30, timeout_sec + 4))
    ok_stop, _ = _run_cmd(["systemctl", "stop", name], timeout=cmd_timeout)
    if not ok_stop:
        return False

    end = time.time() + max(1, timeout_sec)
    while time.time() < end:
        if _service_state(name) == "inactive":
            return True
        time.sleep(0.5)
    return _service_state(name) == "inactive"


def _read_json(path: Path) -> tuple[bool, Any]:
    if not path.exists():
        return False, f"File tidak ditemukan: {path}"
    try:
        return True, json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, f"Gagal parse JSON {path}: {exc}"


def _write_json_atomic(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    previous = None
    try:
        previous = path.stat()
    except Exception:
        previous = None
    fd, tmp = tempfile.mkstemp(prefix=".tmp.", suffix=path.suffix or ".json", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as wf:
            json.dump(payload, wf, ensure_ascii=False, indent=2)
            wf.write("\n")
            wf.flush()
            os.fsync(wf.fileno())
        os.replace(tmp, path)
        if previous is not None:
            try:
                os.chmod(path, previous.st_mode & 0o777)
            except Exception:
                pass
            try:
                os.chown(path, previous.st_uid, previous.st_gid)
            except Exception:
                pass
        if path.parent == XRAY_CONFDIR:
            try:
                os.chmod(path, 0o640)
            except Exception:
                pass
            try:
                xray_gid = grp.getgrnam("xray").gr_gid
                os.chown(path, 0, xray_gid)
            except Exception:
                pass
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass


def _write_text_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    previous = None
    try:
        previous = path.stat()
    except Exception:
        previous = None
    fd, tmp = tempfile.mkstemp(prefix=".tmp.", suffix=path.suffix or ".txt", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as wf:
            wf.write(content)
            wf.flush()
            os.fsync(wf.fileno())
        os.replace(tmp, path)
        if previous is not None:
            try:
                os.chmod(path, previous.st_mode & 0o777)
            except Exception:
                pass
            try:
                os.chown(path, previous.st_uid, previous.st_gid)
            except Exception:
                pass
        if path.parent == XRAY_CONFDIR:
            try:
                os.chmod(path, 0o640)
            except Exception:
                pass
            try:
                xray_gid = grp.getgrnam("xray").gr_gid
                os.chown(path, 0, xray_gid)
            except Exception:
                pass
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass


def _write_bytes_atomic(path: Path, payload: bytes) -> tuple[bool, str]:
    path.parent.mkdir(parents=True, exist_ok=True)
    previous = None
    try:
        previous = path.stat()
    except Exception:
        previous = None
    fd, tmp = tempfile.mkstemp(prefix=".tmp.", suffix=path.suffix or ".bin", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as wf:
            wf.write(payload)
            wf.flush()
            os.fsync(wf.fileno())
        os.replace(tmp, path)
        if previous is not None:
            try:
                os.chmod(path, previous.st_mode & 0o777)
            except Exception:
                pass
            try:
                os.chown(path, previous.st_uid, previous.st_gid)
            except Exception:
                pass
        if path.parent == XRAY_CONFDIR:
            try:
                os.chmod(path, 0o640)
            except Exception:
                pass
            try:
                xray_gid = grp.getgrnam("xray").gr_gid
                os.chown(path, 0, xray_gid)
            except Exception:
                pass
    except Exception as exc:
        return False, f"Gagal menulis file {path}: {exc}"
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
    return True, "ok"


def _chmod_600(path: Path) -> None:
    try:
        path.chmod(0o600)
    except Exception:
        pass


def _ensure_runtime_dirs() -> None:
    for p in [
        ACCOUNT_ROOT / "vless",
        ACCOUNT_ROOT / "vmess",
        ACCOUNT_ROOT / "trojan",
        SSH_ACCOUNT_DIR,
        QUOTA_ROOT / "vless",
        QUOTA_ROOT / "vmess",
        QUOTA_ROOT / "trojan",
        SSH_QUOTA_DIR,
        SPEED_POLICY_ROOT / "vless",
        SPEED_POLICY_ROOT / "vmess",
        SPEED_POLICY_ROOT / "trojan",
        WORK_DIR,
    ]:
        p.mkdir(parents=True, exist_ok=True)


def _safe_extract_tarball(archive_path: Path, dest_dir: Path) -> tuple[bool, str]:
    dest_dir.mkdir(parents=True, exist_ok=True)
    base_real = dest_dir.resolve()
    try:
        with tarfile.open(archive_path, "r:gz") as tf:
            for member in tf.getmembers():
                raw_name = str(member.name or "")
                if "\x00" in raw_name:
                    return False, "Tar acme.sh mengandung path NUL byte."
                norm = PurePosixPath(raw_name)
                if norm.is_absolute() or ".." in norm.parts:
                    return False, f"Tar acme.sh mengandung path tidak aman: {raw_name}"
                if raw_name in {"", "."}:
                    continue
                target = (base_real / norm).resolve()
                if target != base_real and base_real not in target.parents:
                    return False, f"Tar acme.sh keluar dari direktori tujuan: {raw_name}"
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    return False, f"Tar acme.sh mengandung entry tidak didukung: {raw_name}"
                target.parent.mkdir(parents=True, exist_ok=True)
                extracted = tf.extractfile(member)
                if extracted is None:
                    return False, f"Gagal membaca entry tar acme.sh: {raw_name}"
                with extracted, open(target, "wb") as dst:
                    shutil.copyfileobj(extracted, dst)
        return True, "ok"
    except Exception as exc:
        return False, f"Gagal extract acme.sh tarball: {exc}"


def _to_int(v: Any, default: int = 0) -> int:
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


def _to_float(v: Any, default: float = 0.0) -> float:
    try:
        if v is None:
            return default
        if isinstance(v, bool):
            return float(int(v))
        if isinstance(v, (int, float)):
            return float(v)
        s = str(v).strip().lower().replace("mbit", "").replace("mbps", "")
        if not s:
            return default
        return float(s)
    except Exception:
        return default


def _fmt_number(v: float) -> str:
    if v <= 0:
        return "0"
    if abs(v - round(v)) < 1e-9:
        return str(int(round(v)))
    return f"{v:.3f}".rstrip("0").rstrip(".")


def _fmt_quota_gb_from_bytes(quota_bytes: int) -> str:
    if quota_bytes <= 0:
        return "0"
    return _fmt_number(quota_bytes / (1024**3))


def _is_valid_username(username: str) -> bool:
    return bool(USERNAME_RE.match(username or ""))


def _is_valid_ssh_username(username: str) -> bool:
    return bool(SSH_USERNAME_RE.match(username or ""))


def _email(proto: str, username: str) -> str:
    return f"{username}@{proto}"


def _detect_public_ipv4() -> str:
    ok, out = _run_cmd(["ip", "-4", "-o", "addr", "show", "scope", "global"], timeout=8)
    if ok:
        m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", out)
        if m:
            return m.group(1)
    return "0.0.0.0"


def _geo_lookup(ip: str) -> tuple[str, str]:
    ip_text = str(ip or "").strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip_text):
        return "-", "-"
    cached = _GEO_LOOKUP_CACHE.get(ip_text)
    if cached is not None:
        return cached

    def _fetch_json(url: str) -> dict[str, Any] | None:
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "autoscript-bot-telegram/1.0",
                    "Accept": "application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=6) as resp:
                raw = resp.read().decode("utf-8", errors="ignore")
            payload = json.loads(raw)
            return payload if isinstance(payload, dict) else None
        except Exception:
            return None

    payload = _fetch_json(f"http://ip-api.com/json/{ip_text}?fields=status,country,isp")
    if payload and str(payload.get("status") or "").strip().lower() == "success":
        result = (
            str(payload.get("isp") or "-").strip() or "-",
            str(payload.get("country") or "-").strip() or "-",
        )
        _GEO_LOOKUP_CACHE[ip_text] = result
        return result

    payload = _fetch_json(f"https://ipwho.is/{ip_text}")
    if payload and bool(payload.get("success")):
        result = (
            str(payload.get("connection", {}).get("isp") or payload.get("isp") or "-").strip() or "-",
            str(payload.get("country") or "-").strip() or "-",
        )
        _GEO_LOOKUP_CACHE[ip_text] = result
        return result

    payload = _fetch_json(f"https://ipapi.co/{ip_text}/json/")
    if payload and not payload.get("error"):
        result = (
            str(payload.get("org") or payload.get("asn_org") or "-").strip() or "-",
            str(payload.get("country_name") or payload.get("country") or "-").strip() or "-",
        )
        _GEO_LOOKUP_CACHE[ip_text] = result
        return result

    result = ("-", "-")
    _GEO_LOOKUP_CACHE[ip_text] = result
    return result


def _detect_domain() -> str:
    if NGINX_CONF.exists():
        for line in NGINX_CONF.read_text(encoding="utf-8", errors="ignore").splitlines():
            m = re.match(r"^\s*server_name\s+([^;]+);", line)
            if m:
                token = m.group(1).strip().split()[0]
                if token and token != "_":
                    return token
    ok, fqdn = _run_cmd(["hostname", "-f"], timeout=8)
    if ok and fqdn.strip():
        return fqdn.splitlines()[0].strip()
    ok2, host = _run_cmd(["hostname"], timeout=8)
    if ok2 and host.strip():
        return host.splitlines()[0].strip()
    return "-"


def _network_state_get(key: str) -> str:
    ok, payload = _read_json(NETWORK_STATE_FILE)
    if not ok or not isinstance(payload, dict):
        return ""
    value = payload.get(key)
    if value is None:
        return ""
    return str(value).strip()


def _network_state_set(key: str, value: str) -> None:
    _network_state_set_many({key: value})


def _network_state_set_many(values: dict[str, str]) -> None:
    _network_state_update_many(values)


def _network_state_update_many(values: dict[str, str | None]) -> None:
    payload: dict[str, Any] = {}
    ok, raw = _read_json(NETWORK_STATE_FILE)
    if ok and isinstance(raw, dict):
        payload = raw
    for key, value in values.items():
        key_n = str(key)
        if value is None:
            payload.pop(key_n, None)
        else:
            payload[key_n] = str(value)
    _write_json_atomic(NETWORK_STATE_FILE, payload)
    _chmod_600(NETWORK_STATE_FILE)


def _snapshot_optional_file(path: Path) -> dict[str, Any]:
    if not path.exists() or not path.is_file():
        return {"exists": False}
    try:
        st = path.stat()
        return {
            "exists": True,
            "payload": path.read_bytes(),
            "mode": int(st.st_mode & 0o777),
        }
    except Exception:
        return {"exists": False}


def _restore_optional_file(path: Path, snapshot: dict[str, Any]) -> tuple[bool, str]:
    try:
        if bool(snapshot.get("exists")):
            ok_write, msg_write = _write_bytes_atomic(path, bytes(snapshot.get("payload") or b""))
            if not ok_write:
                return False, msg_write
            mode = snapshot.get("mode")
            if isinstance(mode, int):
                try:
                    os.chmod(path, mode)
                except Exception:
                    pass
        elif path.exists():
            path.unlink()
    except Exception as exc:
        return False, f"Gagal restore file {path}: {exc}"
    return True, "ok"


def _capture_domain_runtime_snapshot() -> dict[str, Any]:
    edge_service = _edge_runtime_service_name().strip()
    if edge_service == "nginx":
        edge_service = ""
    return {
        "nginx_conf": _snapshot_optional_file(NGINX_CONF),
        "compat_domain": _snapshot_optional_file(XRAY_DOMAIN_FILE),
        "cert_fullchain": _snapshot_optional_file(CERT_FULLCHAIN),
        "cert_privkey": _snapshot_optional_file(CERT_PRIVKEY),
        "nginx_was_active": _service_exists("nginx") and _service_is_active("nginx"),
        "sshws_stunnel_was_active": _service_exists("sshws-stunnel") and _service_is_active("sshws-stunnel"),
        "edge_service_name": edge_service,
        "edge_service_was_active": bool(
            edge_service and _service_exists(edge_service) and _service_is_active(edge_service)
        ),
    }


def _domain_snapshot_active_domain(snapshot: dict[str, Any]) -> str:
    compat = snapshot.get("compat_domain")
    if isinstance(compat, dict) and compat.get("exists"):
        try:
            value = bytes(compat.get("payload") or b"").decode("utf-8", errors="ignore").strip()
        except Exception:
            value = ""
        if DOMAIN_RE.match(value):
            return value

    nginx_conf = snapshot.get("nginx_conf")
    if isinstance(nginx_conf, dict) and nginx_conf.get("exists"):
        try:
            text = bytes(nginx_conf.get("payload") or b"").decode("utf-8", errors="ignore")
        except Exception:
            text = ""
        for line in text.splitlines():
            m = re.match(r"^\s*server_name\s+([^;]+);", line)
            if not m:
                continue
            domain = m.group(1).strip().split()[0]
            if DOMAIN_RE.match(domain):
                return domain
    return ""


def _restore_domain_runtime_snapshot(
    snapshot: dict[str, Any],
    skipped_services: set[str] | None = None,
) -> tuple[bool, str]:
    failures: list[str] = []
    for path, key in (
        (CERT_FULLCHAIN, "cert_fullchain"),
        (CERT_PRIVKEY, "cert_privkey"),
        (XRAY_DOMAIN_FILE, "compat_domain"),
        (NGINX_CONF, "nginx_conf"),
    ):
        entry = snapshot.get(key)
        if not isinstance(entry, dict):
            continue
        ok_restore, msg_restore = _restore_optional_file(path, entry)
        if not ok_restore:
            failures.append(msg_restore)

    if failures:
        return False, " | ".join(failures)

    ok_test, out_test = _run_cmd(["nginx", "-t"], timeout=20)
    if not ok_test:
        return False, f"nginx -t gagal saat rollback domain:\n{out_test}"
    if bool(snapshot.get("nginx_was_active")):
        if not _restart_and_wait("nginx", timeout_sec=20):
            return False, "nginx gagal restart saat rollback domain."
    elif _service_exists("nginx") and _service_is_active("nginx"):
        if not _stop_and_wait_inactive("nginx", timeout_sec=20):
            return False, "nginx gagal dikembalikan ke state inactive saat rollback domain."
    ok_tls, msg_tls = _restore_tls_runtime_consumers_from_snapshot(snapshot, skipped_services or set())
    if not ok_tls:
        return False, f"Rollback domain selesai, tetapi restart consumer TLS gagal:\n{msg_tls}"
    return True, "ok"


def _capture_warp_runtime_snapshot() -> dict[str, Any]:
    wireproxy_exists = _service_exists("wireproxy")
    zerotrust_exists = _service_exists(WARP_ZEROTRUST_SERVICE)
    return {
        "account_file": _snapshot_optional_file(WGCF_DIR / "wgcf-account.toml"),
        "profile_file": _snapshot_optional_file(WGCF_DIR / "wgcf-profile.conf"),
        "wireproxy_conf": _snapshot_optional_file(WIREPROXY_CONF),
        "zerotrust_config": _snapshot_optional_file(WARP_ZEROTRUST_CONFIG_FILE),
        "zerotrust_mdm": _snapshot_optional_file(WARP_ZEROTRUST_MDM_FILE),
        "mode_target": _network_state_get(WARP_MODE_STATE_KEY) or None,
        "tier_target": _network_state_get(WARP_TIER_STATE_KEY) or None,
        "license_key": _network_state_get(WARP_PLUS_LICENSE_STATE_KEY) or None,
        "wireproxy_exists": wireproxy_exists,
        "wireproxy_was_active": _service_is_active("wireproxy") if wireproxy_exists else False,
        "zerotrust_exists": zerotrust_exists,
        "zerotrust_was_active": _service_is_active(WARP_ZEROTRUST_SERVICE) if zerotrust_exists else False,
    }


def _capture_xray_network_runtime_snapshot() -> dict[str, Any]:
    return {
        "routing": _snapshot_optional_file(XRAY_ROUTING_CONF),
        "outbounds": _snapshot_optional_file(XRAY_OUTBOUNDS_CONF),
    }


def _restore_xray_network_runtime_snapshot(snapshot: dict[str, Any]) -> tuple[bool, str]:
    failures: list[str] = []
    for path, key in (
        (XRAY_ROUTING_CONF, "routing"),
        (XRAY_OUTBOUNDS_CONF, "outbounds"),
    ):
        entry = snapshot.get(key)
        if not isinstance(entry, dict):
            continue
        ok_restore, msg_restore = _restore_optional_file(path, entry)
        if not ok_restore:
            failures.append(msg_restore)
    if failures:
        return False, " | ".join(failures)
    if not _restart_and_wait("xray", timeout_sec=20):
        return False, "xray gagal restart saat rollback network controls."
    if Path("/usr/local/bin/xray-speed").exists() or _service_exists("xray-speed"):
        if not _speed_policy_apply_now():
            return False, "xray rollback berhasil, tetapi refresh runtime speed policy gagal."
    return True, "ok"


def _restore_warp_runtime_snapshot(snapshot: dict[str, Any]) -> tuple[bool, str]:
    failures: list[str] = []
    for path, key in (
        (WGCF_DIR / "wgcf-account.toml", "account_file"),
        (WGCF_DIR / "wgcf-profile.conf", "profile_file"),
        (WIREPROXY_CONF, "wireproxy_conf"),
        (WARP_ZEROTRUST_CONFIG_FILE, "zerotrust_config"),
        (WARP_ZEROTRUST_MDM_FILE, "zerotrust_mdm"),
    ):
        entry = snapshot.get(key)
        if not isinstance(entry, dict):
            continue
        ok_restore, msg_restore = _restore_optional_file(path, entry)
        if not ok_restore:
            failures.append(msg_restore)

    try:
        _network_state_update_many(
            {
                WARP_MODE_STATE_KEY: snapshot.get("mode_target"),
                WARP_TIER_STATE_KEY: snapshot.get("tier_target"),
                WARP_PLUS_LICENSE_STATE_KEY: snapshot.get("license_key"),
            }
        )
    except Exception as exc:
        failures.append(f"Gagal restore network state WARP: {exc}")

    if bool(snapshot.get("wireproxy_exists")):
        if bool(snapshot.get("wireproxy_was_active")):
            if not _restart_and_wait("wireproxy", timeout_sec=30):
                failures.append("wireproxy gagal restart saat rollback WARP.")
        elif _service_is_active("wireproxy"):
            if not _stop_and_wait_inactive("wireproxy", timeout_sec=30):
                failures.append("wireproxy gagal dikembalikan ke state inactive saat rollback WARP.")

    if bool(snapshot.get("zerotrust_exists")):
        if bool(snapshot.get("zerotrust_was_active")):
            if not _restart_and_wait(WARP_ZEROTRUST_SERVICE, timeout_sec=30):
                failures.append(f"{WARP_ZEROTRUST_SERVICE} gagal restart saat rollback WARP.")
        elif _service_is_active(WARP_ZEROTRUST_SERVICE):
            if not _stop_and_wait_inactive(WARP_ZEROTRUST_SERVICE, timeout_sec=30):
                failures.append(f"{WARP_ZEROTRUST_SERVICE} gagal dikembalikan ke state inactive saat rollback WARP.")

    if not failures:
        ok_apply, msg_apply = _ssh_network_apply_runtime()
        if not ok_apply:
            failures.append(f"SSH Network gagal direkonsiliasi saat rollback WARP: {msg_apply}")
        else:
            with _user_data_mutation_lock():
                ok_refresh, refresh_msg = _ssh_refresh_all_account_info()
            if not ok_refresh:
                failures.append(f"SSH ACCOUNT INFO gagal direfresh saat rollback WARP: {refresh_msg}")

    if failures:
        return False, " | ".join(failures)
    return True, "ok"


def _manage_script_path() -> Path | None:
    for candidate in MANAGE_SCRIPT_CANDIDATES:
        if candidate.exists():
            return candidate
    return None


def _ssh_network_env_map() -> dict[str, str]:
    data: dict[str, str] = {}
    try:
        if not SSH_NETWORK_ENV_FILE.exists():
            return data
        for raw in SSH_NETWORK_ENV_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            data[key.strip()] = value.strip()
    except Exception:
        return {}
    return data


def _ssh_network_env_value(key: str, default: str = "") -> str:
    value = _ssh_network_env_map().get(key)
    return value if isinstance(value, str) and value.strip() else default


def _ssh_network_update_env_many(updates: dict[str, str]) -> tuple[bool, str]:
    lines: list[str] = []
    if SSH_NETWORK_ENV_FILE.exists():
        try:
            lines = SSH_NETWORK_ENV_FILE.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception as exc:
            return False, f"Gagal membaca config env SSH Network: {exc}"

    out: list[str] = []
    seen: set[str] = set()
    for raw in lines:
        line = str(raw or "")
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            out.append(line)
            continue
        key, _ = line.split("=", 1)
        key = key.strip()
        if key in updates:
            out.append(f"{key}={updates[key]}")
            seen.add(key)
            continue
        out.append(line)

    for key, value in updates.items():
        if key in seen:
            continue
        out.append(f"{key}={value}")

    try:
        SSH_NETWORK_ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
        _write_text_atomic(SSH_NETWORK_ENV_FILE, "\n".join(out).rstrip("\n") + "\n")
        os.chmod(SSH_NETWORK_ENV_FILE, 0o600)
    except Exception as exc:
        return False, f"Gagal menulis config env SSH Network: {exc}"
    return True, "ok"


def _ssh_network_global_mode_get() -> str:
    value = _ssh_network_env_value("SSH_NETWORK_ROUTE_GLOBAL", "direct").strip().lower()
    return value if value in {"direct", "warp"} else "direct"


def _ssh_network_backend_get() -> str:
    value = _ssh_network_env_value("SSH_NETWORK_WARP_BACKEND", "auto").strip().lower()
    return value if value in {"auto", "local-proxy", "interface"} else "auto"


def _ssh_network_backend_effective(configured: str | None = None) -> str:
    value = str(configured or _ssh_network_backend_get()).strip().lower()
    if value in {"local-proxy", "interface"}:
        return value
    if shutil.which("xray") and shutil.which("iptables"):
        return "local-proxy"
    return "interface"


def _ssh_network_effective_rows() -> list[dict[str, str]]:
    global_mode = _ssh_network_global_mode_get()
    rows: list[dict[str, str]] = []
    if not SSH_QUOTA_DIR.exists():
        return rows

    for quota_path in sorted(SSH_QUOTA_DIR.glob("*.json")):
        ok, payload = _read_json(quota_path)
        if not ok or not isinstance(payload, dict):
            continue

        username = str(payload.get("username") or quota_path.stem.split("@", 1)[0]).strip()
        if not username:
            continue

        network = payload.get("network")
        override = "inherit"
        if isinstance(network, dict):
            candidate = str(network.get("route_mode") or "").strip().lower()
            if candidate in {"inherit", "direct", "warp"}:
                override = candidate

        effective = global_mode if override == "inherit" else override
        rows.append(
            {
                "username": username,
                "override": override,
                "effective": effective,
            }
        )

    return rows


def _ssh_network_host_mode_state() -> str:
    value = _network_state_get(WARP_MODE_STATE_KEY).strip().lower()
    if value in {"consumer", "zerotrust"}:
        return value
    if _service_exists(WARP_ZEROTRUST_SERVICE) and _service_is_active(WARP_ZEROTRUST_SERVICE):
        return "zerotrust"
    return "consumer"


def _ssh_network_require_backend_compatible(backend: str) -> tuple[bool, str]:
    backend_n = str(backend or "").strip().lower()
    if backend_n == "interface" and _ssh_network_host_mode_state() == "zerotrust":
        return (
            False,
            "Dedicated Interface SSH tidak kompatibel saat host aktif di Zero Trust. "
            "Gunakan Local Proxy atau kembalikan host ke Free/Plus lebih dulu.",
        )
    return True, "ok"


def _warp_restart_target_service() -> tuple[bool, str, str, str]:
    zerotrust_exists = _service_exists(WARP_ZEROTRUST_SERVICE)
    zerotrust_active = zerotrust_exists and _service_is_active(WARP_ZEROTRUST_SERVICE)
    if zerotrust_active or _ssh_network_host_mode_state() == "zerotrust":
        if not zerotrust_exists:
            return False, "", "Zero Trust", f"{WARP_ZEROTRUST_SERVICE}.service tidak terdeteksi."
        return True, WARP_ZEROTRUST_SERVICE, "Zero Trust", "ok"

    if _service_exists("wireproxy"):
        return True, "wireproxy", "Free/Plus", "ok"

    return False, "", "Free/Plus", "wireproxy.service tidak terdeteksi."


def _ssh_network_apply_runtime(*, skip_network_lock: bool = False) -> tuple[bool, str]:
    manage_script = _manage_script_path()
    if manage_script is None:
        return False, "manage script tidak ditemukan untuk apply SSH Network."
    env = os.environ.copy()
    if skip_network_lock:
        env["SSH_NETWORK_LOCK_HELD"] = "1"
    return _run_cmd(["bash", str(manage_script), "__apply-ssh-network"], timeout=180, env=env)


def _ssh_network_snapshot() -> dict[str, Any]:
    return {
        "env": _snapshot_optional_file(SSH_NETWORK_ENV_FILE),
    }


def _ssh_network_restore_snapshot(snapshot: dict[str, Any]) -> tuple[bool, str]:
    entry = snapshot.get("env")
    if not isinstance(entry, dict):
        return True, "ok"
    return _restore_optional_file(SSH_NETWORK_ENV_FILE, entry)


def _normalize_ip_literal(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("kosong")
    return str(ipaddress.ip_address(raw))


def _listener_present(port: int) -> bool:
    if shutil.which("ss") is None:
        return False
    ok, out = _run_cmd(["ss", "-lnt"], timeout=8)
    if not ok:
        return False
    return bool(re.search(rf":{int(port)}(?:\s|$)", out))


def _adblock_dnsmasq_conf_path() -> Path:
    return _adblock_path_from_env("SSH_DNS_ADBLOCK_DNSMASQ_CONF", ADBLOCK_DEFAULT_DNSMASQ_CONF)


def _ssh_dns_resolver_runtime_conf_write() -> tuple[bool, str]:
    dns_port = str(_adblock_env_value("SSH_DNS_ADBLOCK_PORT", "5353")).strip()
    if not dns_port.isdigit():
        dns_port = "5353"
    try:
        primary = _normalize_ip_literal(_adblock_env_value("SSH_DNS_ADBLOCK_UPSTREAM_PRIMARY", "1.1.1.1"))
    except Exception:
        return False, "Primary DNS SSH di config tidak valid."
    try:
        secondary = _normalize_ip_literal(_adblock_env_value("SSH_DNS_ADBLOCK_UPSTREAM_SECONDARY", "8.8.8.8"))
    except Exception:
        return False, "Secondary DNS SSH di config tidak valid."
    rendered = _adblock_path_from_env("SSH_DNS_ADBLOCK_RENDERED_FILE", ADBLOCK_DEFAULT_RENDERED)
    dnsmasq_conf = _adblock_dnsmasq_conf_path()
    content = (
        "# SSH Adblock resolver\n"
        f"port={dns_port}\n"
        "listen-address=127.0.0.1\n"
        "bind-interfaces\n"
        "no-resolv\n"
        "no-hosts\n"
        "domain-needed\n"
        "bogus-priv\n"
        "cache-size=1000\n"
        f"server={primary}\n"
        f"server={secondary}\n"
        f"conf-file={rendered}\n"
    )
    try:
        dnsmasq_conf.parent.mkdir(parents=True, exist_ok=True)
        _write_text_atomic(dnsmasq_conf, content)
        os.chmod(dnsmasq_conf, 0o644)
    except Exception as exc:
        return False, f"Gagal menulis dnsmasq SSH Adblock: {exc}"
    return True, "ok"


def _ssh_dns_resolver_apply_now() -> tuple[bool, str]:
    ok_write, msg_write = _ssh_dns_resolver_runtime_conf_write()
    if not ok_write:
        return False, msg_write

    dns_service = _adblock_dns_service_name()
    if not _service_exists(dns_service):
        return False, f"Service DNS SSH tidak ditemukan: {dns_service}"
    if not _restart_and_wait(dns_service, timeout_sec=20):
        return False, f"Service DNS SSH gagal start/restart: {dns_service}"

    if not ADBLOCK_SYNC_BIN.exists():
        return False, "adblock-sync tidak ditemukan."
    ok_apply, out_apply = _run_cmd([str(ADBLOCK_SYNC_BIN), "--apply"], timeout=120)
    if not ok_apply:
        return False, out_apply
    return True, out_apply


def _ssh_dns_resolver_restore_dnsmasq_snapshot(snapshot: dict[str, Any]) -> tuple[bool, str]:
    ok_restore, msg_restore = _restore_optional_file(_adblock_dnsmasq_conf_path(), snapshot)
    if not ok_restore:
        return False, msg_restore
    dns_service = _adblock_dns_service_name()
    if not _service_exists(dns_service):
        return False, f"Service DNS SSH tidak ditemukan: {dns_service}"
    if not _restart_and_wait(dns_service, timeout_sec=20):
        return False, f"Service DNS SSH gagal start/restart: {dns_service}"
    return True, "ok"


def _ssh_network_user_route_mode_set(username: str, mode: str) -> tuple[bool, str]:
    username_n = str(username or "").strip()
    mode_n = str(mode or "").strip().lower()
    if not _is_valid_ssh_username(username_n):
        return False, "Username SSH tidak valid."
    if mode_n not in {"inherit", "direct", "warp"}:
        return False, "Mode routing SSH harus inherit/direct/warp."

    target = _resolve_existing(_quota_candidates(SSH_PROTOCOL, username_n))
    payload: dict[str, Any]
    if target is None:
        if not _linux_user_exists(username_n):
            return False, f"User Linux '{username_n}' belum ada."
        ok_state, target_or_err, payload_or_err = _ssh_load_state(
            username_n,
            create_missing=True,
            created_at=_local_now().strftime("%Y-%m-%d %H:%M"),
            expired_at="-",
        )
        if not ok_state:
            return False, str(target_or_err)
        assert isinstance(target_or_err, Path)
        assert isinstance(payload_or_err, dict)
        target = target_or_err
        payload = payload_or_err
    else:
        ok_raw, raw_payload = _read_json(target)
        if ok_raw and isinstance(raw_payload, dict):
            payload = raw_payload
        else:
            ok_state, _, payload_or_err = _ssh_load_state(username_n, create_missing=True)
            if not ok_state or not isinstance(payload_or_err, dict):
                return False, f"Gagal membaca metadata SSH untuk '{username_n}'."
            payload = payload_or_err

    network = payload.get("network")
    if not isinstance(network, dict):
        network = {}
    network["route_mode"] = mode_n
    payload["network"] = network

    try:
        _write_json_atomic(target, payload)
        _chmod_600(target)
    except Exception as exc:
        return False, f"Gagal menyimpan route_mode SSH untuk '{username_n}': {exc}"
    return True, "ok"


def _warp_zero_trust_env_map() -> dict[str, str]:
    data: dict[str, str] = {}
    try:
        if not WARP_ZEROTRUST_CONFIG_FILE.exists():
            return data
        for raw in WARP_ZEROTRUST_CONFIG_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            data[key.strip()] = value.strip()
    except Exception:
        return {}
    return data


def _warp_zero_trust_env_value(key: str, default: str = "") -> str:
    value = _warp_zero_trust_env_map().get(key)
    return value if isinstance(value, str) and value.strip() else default


def _warp_zero_trust_update_env_many(updates: dict[str, str]) -> tuple[bool, str]:
    lines: list[str] = []
    if WARP_ZEROTRUST_CONFIG_FILE.exists():
        try:
            lines = WARP_ZEROTRUST_CONFIG_FILE.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception as exc:
            return False, f"Gagal membaca config Zero Trust: {exc}"

    out: list[str] = []
    seen: set[str] = set()
    for raw in lines:
        line = str(raw or "")
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            out.append(line)
            continue
        key, _ = line.split("=", 1)
        key = key.strip()
        if key in updates:
            out.append(f"{key}={updates[key]}")
            seen.add(key)
            continue
        out.append(line)

    for key, value in updates.items():
        if key in seen:
            continue
        out.append(f"{key}={value}")

    try:
        WARP_ZEROTRUST_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        _write_text_atomic(WARP_ZEROTRUST_CONFIG_FILE, "\n".join(out).rstrip("\n") + "\n")
        os.chmod(WARP_ZEROTRUST_CONFIG_FILE, 0o600)
    except Exception as exc:
        return False, f"Gagal menulis config Zero Trust: {exc}"
    return True, "ok"


def _warp_zero_trust_proxy_port_get() -> str:
    port = str(_warp_zero_trust_env_value("WARP_ZEROTRUST_PROXY_PORT", WARP_ZEROTRUST_PROXY_PORT)).strip()
    return port if port.isdigit() else WARP_ZEROTRUST_PROXY_PORT


def _warp_zero_trust_cli_first_line(*args: str) -> str:
    if shutil.which("warp-cli") is None:
        return "unknown"
    ok, out = _run_cmd(["warp-cli", *args], timeout=20)
    if not ok:
        last = str(out).splitlines()[-1].strip() if str(out).splitlines() else str(out).strip()
        return last or "unknown"
    for raw in out.splitlines():
        line = str(raw or "").strip()
        if line:
            return line
    return "unknown"


def _warp_zero_trust_proxy_wait_connected(timeout_sec: int = 30) -> bool:
    try:
        port = int(_warp_zero_trust_proxy_port_get())
    except Exception:
        return False
    end = time.time() + max(1, timeout_sec)
    while time.time() < end:
        if shutil.which("warp-cli") is not None:
            _run_cmd(["warp-cli", "connect"], timeout=20)
        if _listener_present(port):
            return True
        time.sleep(1.0)
    return _listener_present(port)


def _warp_zero_trust_disconnect_backend() -> tuple[bool, str]:
    if shutil.which("warp-cli") is not None:
        _run_cmd(["warp-cli", "disconnect"], timeout=20)
    if _service_exists(WARP_ZEROTRUST_SERVICE) and _service_is_active(WARP_ZEROTRUST_SERVICE):
        if not _stop_and_wait_inactive(WARP_ZEROTRUST_SERVICE, timeout_sec=30):
            return False, f"Gagal menghentikan {WARP_ZEROTRUST_SERVICE}."
    return True, "ok"


def _warp_zero_trust_render_mdm_file() -> tuple[bool, str]:
    team = str(_warp_zero_trust_env_value("WARP_ZEROTRUST_TEAM", "")).strip().lower()
    client_id = str(_warp_zero_trust_env_value("WARP_ZEROTRUST_CLIENT_ID", "")).strip()
    client_secret = str(_warp_zero_trust_env_value("WARP_ZEROTRUST_CLIENT_SECRET", "")).strip()
    proxy_port = _warp_zero_trust_proxy_port_get()
    if not team or not client_id or not client_secret:
        return False, "Config Zero Trust belum lengkap."
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<dict>\n"
        "  <key>organization</key>\n"
        f"  <string>{xml_escape(team)}</string>\n"
        "  <key>display_name</key>\n"
        "  <string>Autoscript Zero Trust</string>\n"
        "  <key>auth_client_id</key>\n"
        f"  <string>{xml_escape(client_id)}</string>\n"
        "  <key>auth_client_secret</key>\n"
        f"  <string>{xml_escape(client_secret)}</string>\n"
        "  <key>onboarding</key>\n"
        "  <false/>\n"
        "  <key>auto_connect</key>\n"
        "  <integer>1</integer>\n"
        "  <key>service_mode</key>\n"
        "  <string>proxy</string>\n"
        "  <key>proxy_port</key>\n"
        f"  <integer>{proxy_port}</integer>\n"
        "</dict>\n"
    )
    try:
        WARP_ZEROTRUST_MDM_FILE.parent.mkdir(parents=True, exist_ok=True)
        _write_text_atomic(WARP_ZEROTRUST_MDM_FILE, xml)
        os.chmod(WARP_ZEROTRUST_MDM_FILE, 0o600)
    except Exception as exc:
        return False, f"Gagal menulis mdm.xml Zero Trust: {exc}"
    return True, "ok"


def _warp_zero_trust_ssh_guard() -> tuple[bool, str]:
    backend_effective = _ssh_network_backend_effective()
    effective_warp_users = sum(1 for row in _ssh_network_effective_rows() if row.get("effective") == "warp")
    if effective_warp_users > 0 and backend_effective != "local-proxy":
        return (
            False,
            "Zero Trust belum kompatibel dengan SSH Network yang effective WARP users-nya aktif di backend non-Local Proxy.",
        )
    return True, "ok"


def _restore_adblock_source_snapshot(path: Path, snapshot: dict[str, Any]) -> tuple[bool, str]:
    return _restore_optional_file(path, snapshot)


def _adblock_env_map() -> dict[str, str]:
    data: dict[str, str] = {}
    try:
        if not ADBLOCK_ENV_FILE.exists():
            return data
        for raw in ADBLOCK_ENV_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            data[key.strip()] = value.strip()
    except Exception:
        return {}
    return data


def _adblock_env_value(key: str, default: str = "") -> str:
    value = _adblock_env_map().get(key)
    return value if isinstance(value, str) and value.strip() else default


def _adblock_path_from_env(key: str, default: str) -> Path:
    return Path(_adblock_env_value(key, default))


def _adblock_sync_service_name() -> str:
    return _adblock_env_value("SSH_DNS_ADBLOCK_SYNC_SERVICE", ADBLOCK_DEFAULT_SYNC_SERVICE)


def _adblock_dns_service_name() -> str:
    return _adblock_env_value("SSH_DNS_ADBLOCK_SERVICE", ADBLOCK_DEFAULT_DNS_SERVICE)


def _adblock_auto_update_service_name() -> str:
    return _adblock_env_value("AUTOSCRIPT_ADBLOCK_AUTO_UPDATE_SERVICE", ADBLOCK_DEFAULT_AUTO_UPDATE_SERVICE)


def _adblock_auto_update_timer_name() -> str:
    return _adblock_env_value("AUTOSCRIPT_ADBLOCK_AUTO_UPDATE_TIMER", ADBLOCK_DEFAULT_AUTO_UPDATE_TIMER)


def _adblock_timer_path() -> Path:
    return ADBLOCK_TIMER_DIR / _adblock_auto_update_timer_name()


def _adblock_update_env_many(updates: dict[str, str]) -> tuple[bool, str]:
    lines: list[str] = []
    if ADBLOCK_ENV_FILE.exists():
        try:
            lines = ADBLOCK_ENV_FILE.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception as exc:
            return False, f"Gagal membaca config env adblock: {exc}"

    out: list[str] = []
    seen: set[str] = set()
    for raw in lines:
        line = str(raw or "")
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            out.append(line)
            continue
        key, _ = line.split("=", 1)
        key = key.strip()
        if key in updates:
            out.append(f"{key}={updates[key]}")
            seen.add(key)
            continue
        out.append(line)

    for key, value in updates.items():
        if key in seen:
            continue
        out.append(f"{key}={value}")

    try:
        _write_text_atomic(ADBLOCK_ENV_FILE, "\n".join(out).rstrip("\n") + "\n")
        os.chmod(ADBLOCK_ENV_FILE, 0o644)
    except Exception as exc:
        return False, f"Gagal menulis config env adblock: {exc}"
    return True, "ok"


def _adblock_enabled_flag() -> bool:
    return _adblock_env_value("SSH_DNS_ADBLOCK_ENABLED", "0").strip().lower() in {"1", "true", "yes", "on", "y"}


def _adblock_status_map() -> dict[str, str]:
    if not ADBLOCK_SYNC_BIN.exists():
        return {}
    ok, out = _run_cmd([str(ADBLOCK_SYNC_BIN), "--status"], timeout=30)
    if not ok:
        return {"error": out}
    status: dict[str, str] = {}
    for raw in out.splitlines():
        line = str(raw or "").strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        status[key.strip()] = value.strip()
    return status


def _adblock_manual_domain_normalize(raw: str) -> str:
    value = str(raw or "").strip().lower()
    if value.startswith("*."):
        value = value[2:]
    value = value.lstrip(".").rstrip(".")
    if not value or " " in value or "/" in value or ".." in value or "." not in value:
        return ""
    if not re.match(r"^[a-z0-9][a-z0-9._-]*\.[a-z0-9._-]+$", value):
        return ""
    return value


def _adblock_url_normalize(raw: str) -> str:
    value = str(raw or "").strip()
    if not value.startswith(("http://", "https://")):
        return ""
    return value


def _adblock_read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    try:
        return path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return []


def _adblock_write_unique_lines(path: Path, lines: list[str]) -> tuple[bool, str]:
    unique: list[str] = []
    seen: set[str] = set()
    for item in lines:
        text = str(item or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        unique.append(text)
    payload = ("\n".join(unique).rstrip("\n") + "\n") if unique else ""
    try:
        _write_text_atomic(path, payload)
        os.chmod(path, 0o644)
    except Exception as exc:
        return False, f"Gagal menulis file {path}: {exc}"
    return True, "ok"


def _adblock_xray_rule_state() -> dict[str, str | int]:
    if not XRAY_ROUTING_CONF.exists():
        return {"enabled": "0", "outbound": "-", "duplicates": 0, "domains": 0}
    ok, payload = _read_json(XRAY_ROUTING_CONF)
    if not ok or not isinstance(payload, dict):
        return {"enabled": "0", "outbound": "-", "duplicates": 0, "domains": 0}
    rules = ((payload.get("routing") or {}).get("rules") or [])
    targets: list[dict[str, Any]] = []
    if isinstance(rules, list):
        for item in rules:
            if not isinstance(item, dict):
                continue
            if item.get("type") != "field":
                continue
            domains = item.get("domain")
            if not isinstance(domains, list):
                continue
            if any(isinstance(val, str) and val.strip() == ADBLOCK_XRAY_RULE for val in domains):
                targets.append(item)
    if not targets:
        return {"enabled": "0", "outbound": "-", "duplicates": 0, "domains": 0}
    first = targets[0]
    domains = first.get("domain") if isinstance(first.get("domain"), list) else []
    outbound = str(first.get("outboundTag") or "-").strip() or "-"
    return {
        "enabled": "1",
        "outbound": outbound,
        "duplicates": max(0, len(targets) - 1),
        "domains": sum(1 for item in domains if isinstance(item, str) and item.strip()),
    }


def _is_default_egress_rule(rule: dict[str, Any]) -> bool:
    if not isinstance(rule, dict):
        return False
    if rule.get("type") != "field":
        return False
    port = str(rule.get("port") or "").strip()
    if port not in {"1-65535", "0-65535"}:
        return False
    if rule.get("user") or rule.get("domain") or rule.get("ip") or rule.get("protocol"):
        return False
    return True


def _adblock_set_xray_rule(mode: str) -> tuple[bool, str]:
    mode_n = str(mode or "").strip().lower()
    if mode_n not in {"blocked", "off"}:
        return False, "Mode adblock Xray harus blocked/off."
    ok, payload = _read_json(XRAY_ROUTING_CONF)
    if not ok or not isinstance(payload, dict):
        return False, str(payload)
    routing = payload.get("routing")
    if not isinstance(routing, dict):
        return False, "Format routing tidak valid."
    rules = routing.get("rules")
    if not isinstance(rules, list):
        return False, "Format routing.rules tidak valid."

    before = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    backup = json.loads(json.dumps(payload, ensure_ascii=False))

    filtered: list[Any] = []
    primary_rule: dict[str, Any] | None = None
    for item in rules:
        if not isinstance(item, dict):
            filtered.append(item)
            continue
        domains = item.get("domain")
        if item.get("type") != "field" or not isinstance(domains, list):
            filtered.append(item)
            continue
        contains = any(isinstance(val, str) and val.strip() == ADBLOCK_XRAY_RULE for val in domains)
        if not contains:
            filtered.append(item)
            continue
        if primary_rule is None:
            primary_rule = dict(item)

    if mode_n == "blocked":
        if primary_rule is None:
            primary_rule = {"type": "field", "domain": [ADBLOCK_XRAY_RULE], "outboundTag": "blocked"}
        domains = primary_rule.get("domain")
        if not isinstance(domains, list):
            domains = []
        cleaned = [ADBLOCK_XRAY_RULE]
        seen = {ADBLOCK_XRAY_RULE}
        for item in domains:
            if not isinstance(item, str):
                continue
            value = item.strip()
            if not value or value in seen:
                continue
            cleaned.append(value)
            seen.add(value)
        primary_rule["type"] = "field"
        primary_rule["domain"] = cleaned
        primary_rule["outboundTag"] = "blocked"

        insert_at = len(filtered)
        for idx, item in enumerate(filtered):
            if isinstance(item, dict) and _is_default_egress_rule(item):
                insert_at = idx
                break
        filtered.insert(insert_at, primary_rule)

    routing["rules"] = filtered
    payload["routing"] = routing
    after = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if after == before:
        return True, "Rule adblock Xray tidak berubah."

    try:
        _write_json_atomic(XRAY_ROUTING_CONF, payload)
    except Exception as exc:
        return False, f"Gagal menulis routing adblock Xray: {exc}"

    if not _restart_and_wait("xray", timeout_sec=240):
        try:
            _write_json_atomic(XRAY_ROUTING_CONF, backup)
        except Exception:
            pass
        _restart_and_wait("xray", timeout_sec=30)
        return False, "xray tidak aktif setelah update routing adblock. Config di-rollback."
    return True, "ok"


def _adblock_apply_now() -> tuple[bool, str]:
    if not ADBLOCK_SYNC_BIN.exists():
        return False, "adblock-sync tidak ditemukan."
    ok, out = _run_cmd([str(ADBLOCK_SYNC_BIN), "--apply"], timeout=120)
    if not ok:
        return False, out
    return True, out


def _adblock_update_now(reload_xray: bool = False) -> tuple[bool, str]:
    if not ADBLOCK_SYNC_BIN.exists():
        return False, "adblock-sync tidak ditemukan."
    argv = [str(ADBLOCK_SYNC_BIN), "--update"]
    if reload_xray:
        argv.append("--reload-xray")
    ok, out = _run_cmd(argv, timeout=300)
    if not ok:
        return False, out
    return True, out


def _adblock_mark_dirty() -> tuple[bool, str]:
    return _adblock_update_env_many({"AUTOSCRIPT_ADBLOCK_DIRTY": "1"})


def _adblock_auto_update_timer_write(days: int) -> tuple[bool, str]:
    if days < 1:
        return False, "Interval harus minimal 1 hari."
    timer_path = _adblock_timer_path()
    service_name = _adblock_auto_update_service_name()
    content = (
        "[Unit]\n"
        f"Description=Run Adblock update every {days} day(s)\n\n"
        "[Timer]\n"
        "OnBootSec=10min\n"
        f"OnUnitActiveSec={days}d\n"
        "AccuracySec=5min\n"
        f"Unit={service_name}\n"
        "Persistent=true\n\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )
    try:
        _write_text_atomic(timer_path, content)
        os.chmod(timer_path, 0o644)
    except Exception as exc:
        return False, f"Gagal menulis timer adblock: {exc}"
    ok_reload, out_reload = _run_cmd(["systemctl", "daemon-reload"], timeout=20)
    if not ok_reload:
        return False, out_reload
    return True, "ok"


def _adblock_timer_state_matches(timer_name: str, *, enabled: bool) -> tuple[bool, str]:
    ok_enabled, out_enabled = _run_cmd(["systemctl", "is-enabled", timer_name], timeout=10)
    enabled_state = out_enabled.splitlines()[-1].strip() if out_enabled else "-"
    ok_active, out_active = _run_cmd(["systemctl", "is-active", timer_name], timeout=10)
    active_state = out_active.splitlines()[-1].strip() if out_active else "-"

    if enabled:
        if enabled_state != "enabled":
            return False, f"{timer_name} belum enabled (state={enabled_state})."
        if active_state != "active":
            return False, f"{timer_name} belum active (state={active_state})."
        return True, "ok"

    if ok_enabled and enabled_state == "enabled":
        return False, f"{timer_name} masih enabled."
    if ok_active and active_state == "active":
        return False, f"{timer_name} masih active."
    return True, "ok"


def _adblock_timer_days_matches(expected_days: int | str) -> tuple[bool, str]:
    timer_path = _adblock_timer_path()
    if not timer_path.exists():
        return False, f"Timer auto update belum tersedia: {timer_path}"

    try:
        expected_text = f"{int(expected_days)}d"
    except Exception:
        return False, f"Interval rollback tidak valid: {expected_days}"

    try:
        for raw_line in timer_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw_line.strip()
            if not line.startswith("OnUnitActiveSec="):
                continue
            current_value = line.split("=", 1)[1].strip()
            if current_value == expected_text:
                return True, "ok"
            return False, f"OnUnitActiveSec saat ini {current_value}, expected {expected_text}."
    except Exception as exc:
        return False, f"Gagal membaca timer auto update: {exc}"
    return False, "OnUnitActiveSec tidak ditemukan di timer auto update."


def _adblock_timer_rollback_verify(
    timer_name: str,
    *,
    enabled: bool,
    expected_days: int | str | None = None,
) -> tuple[bool, str]:
    ok_state, msg_state = _adblock_timer_state_matches(timer_name, enabled=enabled)
    if not ok_state:
        return False, f"state timer rollback tidak sesuai: {msg_state}"
    if expected_days is not None:
        ok_days, msg_days = _adblock_timer_days_matches(expected_days)
        if not ok_days:
            return False, f"interval timer rollback tidak sesuai: {msg_days}"
    return True, "ok"


def _warp_mask_license(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "(kosong)"
    if len(raw) <= 8:
        return raw
    return f"{raw[:4]}****{raw[-4:]}"


def _wireproxy_socks_bind_address() -> str:
    if not WIREPROXY_CONF.exists():
        return "127.0.0.1:40000"
    section = ""
    try:
        lines = WIREPROXY_CONF.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return "127.0.0.1:40000"
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        if section not in {"socks", "socks5"}:
            continue
        if "=" not in line:
            continue
        key, value = [x.strip() for x in line.split("=", 1)]
        if key.lower() == "bindaddress" and value:
            return value
    return "127.0.0.1:40000"


def _wireproxy_socks_block() -> list[str]:
    if not WIREPROXY_CONF.exists():
        return ["[Socks5]", "BindAddress = 127.0.0.1:40000"]
    section = ""
    captured: list[str] = []
    found = False
    try:
        lines = WIREPROXY_CONF.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return ["[Socks5]", "BindAddress = 127.0.0.1:40000"]

    for raw in lines:
        line = raw.rstrip("\n")
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            name = stripped[1:-1].strip().lower()
            if name in {"socks", "socks5"}:
                section = name
                found = True
                captured = ["[Socks5]"]
            else:
                section = ""
            continue
        if section in {"socks", "socks5"}:
            captured.append(line)
    if found and captured:
        return captured
    return ["[Socks5]", "BindAddress = 127.0.0.1:40000"]


def _warp_wireproxy_apply_profile(profile_path: Path) -> tuple[bool, str]:
    if not profile_path.exists() or profile_path.stat().st_size <= 0:
        return False, f"Profile wgcf tidak ditemukan: {profile_path}"

    socks_block = _wireproxy_socks_block()
    try:
        raw_lines = profile_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception as exc:
        return False, f"Gagal membaca profile wgcf: {exc}"

    output: list[str] = []
    in_socks = False
    for raw in raw_lines:
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section_name = stripped[1:-1].strip().lower()
            in_socks = section_name in {"socks", "socks5"}
            if in_socks:
                continue
        if in_socks:
            continue
        output.append(raw.rstrip("\n"))

    output.extend(["", *socks_block, ""])
    try:
        if WIREPROXY_CONF.exists():
            backup = WIREPROXY_CONF.with_suffix(WIREPROXY_CONF.suffix + f".bak.{int(time.time())}")
            shutil.copy2(WIREPROXY_CONF, backup)
        _write_text_atomic(WIREPROXY_CONF, "\n".join(output))
        _chmod_600(WIREPROXY_CONF)
    except Exception as exc:
        return False, f"Gagal menulis wireproxy config: {exc}"
    return True, "wireproxy config updated"


def _warp_live_tier() -> str:
    if shutil.which("curl") is None:
        return "unknown"
    bind_addr = _wireproxy_socks_bind_address()
    ok, out = _run_cmd(
        [
            "curl",
            "-fsS",
            "--max-time",
            "8",
            "--socks5",
            bind_addr,
            WARP_TRACE_URL,
        ],
        timeout=12,
    )
    if not ok:
        return "unknown"
    warp_val = ""
    for raw in out.splitlines():
        line = raw.strip()
        if not line or "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k.strip() == "warp":
            warp_val = v.strip().lower()
            break
    if warp_val == "plus":
        return "plus"
    if warp_val == "on":
        return "free"
    if warp_val == "off":
        return "off"
    return "unknown"


def _warp_tier_target_get() -> str:
    raw = _network_state_get(WARP_TIER_STATE_KEY).strip().lower()
    if raw in {"free", "plus"}:
        return raw
    return "unknown"


def _warp_tier_reconnect_target_get() -> str:
    if _network_state_get(WARP_MODE_STATE_KEY).strip().lower() != "zerotrust":
        live = _warp_live_tier()
        if live in {"free", "plus"}:
            return live
    target = _warp_tier_target_get()
    if target in {"free", "plus"}:
        return target
    return "unknown"


def _warp_wait_live_tier(expected: str, timeout_sec: int = 20) -> bool:
    expected_n = str(expected or "").strip().lower()
    if expected_n not in {"free", "plus"}:
        return False
    end = time.time() + max(1, timeout_sec)
    while time.time() < end:
        if _warp_live_tier() == expected_n:
            return True
        time.sleep(1.0)
    return _warp_live_tier() == expected_n


def _warp_tier_status_message() -> str:
    target = _warp_tier_target_get()
    live = _warp_live_tier()
    license_masked = _warp_mask_license(_network_state_get(WARP_PLUS_LICENSE_STATE_KEY))
    wireproxy_state = "not-installed"
    if _service_exists("wireproxy"):
        wireproxy_state = "active" if _service_is_active("wireproxy") else "inactive"
    lines = [
        f"Target Tier   : {target}",
        f"Live Tier     : {live}",
        f"wireproxy     : {wireproxy_state}",
        f"WARP+ License : {license_masked}",
    ]
    return "\n".join(lines)


def _warp_zero_trust_status_message() -> str:
    team = _warp_zero_trust_env_value("WARP_ZEROTRUST_TEAM", "").strip().lower()
    client_id = _warp_zero_trust_env_value("WARP_ZEROTRUST_CLIENT_ID", "").strip()
    client_secret = _warp_zero_trust_env_value("WARP_ZEROTRUST_CLIENT_SECRET", "").strip()
    proxy_port = _warp_zero_trust_proxy_port_get()
    config_state = "complete" if team and client_id and client_secret else "incomplete"
    svc_state = "missing"
    if _service_exists(WARP_ZEROTRUST_SERVICE):
        svc_state = _service_state(WARP_ZEROTRUST_SERVICE)
    mdm_state = "present" if WARP_ZEROTRUST_MDM_FILE.exists() else "missing"
    cli_status = _warp_zero_trust_cli_first_line("status")
    reg_status = _warp_zero_trust_cli_first_line("registration", "show")
    proxy_state = "not-listening"
    try:
        if _listener_present(int(proxy_port)):
            proxy_state = "listening"
    except Exception:
        proxy_state = "unknown"
    lines = [
        f"Mode          : {'Zero Trust' if _network_state_get(WARP_MODE_STATE_KEY).strip().lower() == 'zerotrust' else 'Free/Plus'}",
        "Backend       : cloudflare-warp (Zero Trust proxy)",
        f"Team Name     : {team or '(kosong)'}",
        f"Client ID     : {_warp_mask_license(client_id)}",
        f"Client Secret : {_warp_mask_license(client_secret)}",
        f"Config State  : {config_state}",
        f"{WARP_ZEROTRUST_SERVICE:<14} : {svc_state}",
        f"MDM Policy    : {mdm_state}",
        f"Proxy Bind    : 127.0.0.1:{proxy_port}",
        f"Proxy State   : {proxy_state}",
        f"CLI Status    : {cli_status}",
        f"Registration  : {reg_status}",
    ]
    return "\n".join(lines)


def _warp_wgcf_register_noninteractive() -> tuple[bool, str]:
    WGCF_DIR.mkdir(parents=True, exist_ok=True)
    account_file = WGCF_DIR / "wgcf-account.toml"
    if account_file.exists():
        return True, "wgcf account exists"

    ok, out = _run_cmd(["bash", "-lc", "set -euo pipefail; yes | wgcf register"], timeout=240, cwd=str(WGCF_DIR))
    if account_file.exists():
        return True, "wgcf register ok"
    if ok and account_file.exists():
        return True, "wgcf register ok"
    return False, f"wgcf register gagal: {out}"


def _warp_wgcf_build_profile(tier: str, license_key: str = "") -> tuple[bool, str]:
    WGCF_DIR.mkdir(parents=True, exist_ok=True)
    tier_n = str(tier or "").strip().lower()
    if tier_n not in {"free", "plus"}:
        return False, "Tier harus free/plus."

    ok_reg, msg_reg = _warp_wgcf_register_noninteractive()
    if not ok_reg:
        return False, msg_reg

    if tier_n == "plus":
        key = str(license_key or "").strip()
        if not key:
            return False, "License key WARP+ kosong."
        ok_upd, out_upd = _run_cmd(
            ["wgcf", "update", "--license-key", key],
            timeout=180,
            cwd=str(WGCF_DIR),
        )
        if not ok_upd:
            return False, f"wgcf update --license-key gagal: {out_upd}"

    profile_path = WGCF_DIR / "wgcf-profile.conf"
    ok_gen, out_gen = _run_cmd(
        ["wgcf", "generate", "-p", str(profile_path)],
        timeout=180,
        cwd=str(WGCF_DIR),
    )
    if not ok_gen:
        return False, f"wgcf generate gagal: {out_gen}"
    if not profile_path.exists() or profile_path.stat().st_size <= 0:
        return False, "wgcf-profile.conf tidak ditemukan setelah generate."
    return True, str(profile_path)


def _routing_default_mode_pretty(rt_cfg: dict[str, Any]) -> str:
    routing = rt_cfg.get("routing")
    if not isinstance(routing, dict):
        return "unknown"
    rules = routing.get("rules")
    if not isinstance(rules, list):
        return "unknown"
    idx = _routing_default_rule_index(rules)
    if idx < 0:
        return "unknown"
    target = rules[idx] if idx < len(rules) else None
    if not isinstance(target, dict):
        return "unknown"
    ot = str(target.get("outboundTag") or "").strip().lower()
    if ot in {"direct", "warp"}:
        return ot
    return "unknown"


def _parse_date_only(raw: Any) -> date | None:
    s = str(raw or "").strip()[:10]
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except Exception:
        return None


def _status_lock_reason(status: dict[str, Any]) -> str:
    if bool(status.get("manual_block")):
        return "manual"
    if bool(status.get("quota_exhausted")):
        return "quota"
    if bool(status.get("ip_limit_locked")):
        return "ip_limit"
    return ""


def _status_apply_lock_fields(status: dict[str, Any]) -> None:
    reason = _status_lock_reason(status)
    status["lock_reason"] = reason
    if reason:
        status["locked_at"] = str(status.get("locked_at") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    else:
        status["locked_at"] = ""


def _xray_recompute_limit_lock_fields(payload: dict[str, Any]) -> dict[str, Any]:
    status = payload.get("status") if isinstance(payload.get("status"), dict) else {}
    quota_limit = max(0, _to_int(payload.get("quota_limit"), 0))
    quota_used = max(0, _to_int(payload.get("quota_used"), 0))
    status["quota_exhausted"] = bool(quota_limit > 0 and quota_used >= quota_limit)

    ip_enabled = bool(status.get("ip_limit_enabled"))
    ip_limit = max(0, _to_int(status.get("ip_limit"), 0))
    ip_metric = max(0, _to_int(status.get("ip_limit_metric"), 0))
    status["ip_limit_locked"] = bool(ip_enabled and ip_limit > 0 and ip_metric > ip_limit)

    _status_apply_lock_fields(status)
    payload["status"] = status
    return status


def _linux_user_exists(username: str) -> bool:
    try:
        pwd.getpwnam(str(username or "").strip())
        return True
    except KeyError:
        return False
    except Exception:
        return False


def _ssh_password_output(password_raw: str) -> str:
    return str(password_raw or "-")


def _ssh_password_from_account_info(username: str) -> str:
    account_file = _resolve_existing(_account_candidates(SSH_PROTOCOL, username))
    if account_file is None:
        return "-"
    fields = _read_account_fields(account_file)
    password = str(fields.get("Password") or "").strip()
    return password or "-"


def _ssh_previous_password(username: str) -> str:
    return _ssh_password_from_account_info(username)


def _ssh_collect_existing_tokens(state_dir: Path, current_path: Path | None = None) -> set[str]:
    tokens: set[str] = set()
    current_real = current_path.resolve() if current_path and current_path.exists() else None
    try:
        candidates = sorted(state_dir.glob("*.json"))
    except Exception:
        return tokens
    for candidate in candidates:
        try:
            if current_real is not None and candidate.resolve() == current_real:
                continue
        except Exception:
            pass
        ok, payload = _read_json(candidate)
        if not ok or not isinstance(payload, dict):
            continue
        token = str(payload.get("sshws_token") or "").strip().lower()
        if re.fullmatch(r"[a-f0-9]{10}", token or ""):
            tokens.add(token)
    return tokens


def _portal_collect_existing_tokens(current_path: Path | None = None) -> set[str]:
    tokens: set[str] = set()
    current_real = current_path.resolve() if current_path and current_path.exists() else None
    for proto in QAC_PROTOCOLS:
        state_dir = QUOTA_ROOT / proto
        try:
            candidates = sorted(state_dir.glob("*.json"))
        except Exception:
            continue
        for candidate in candidates:
            try:
                if current_real is not None and candidate.resolve() == current_real:
                    continue
            except Exception:
                pass
            ok, payload = _read_json(candidate)
            if not ok or not isinstance(payload, dict):
                continue
            token = str(payload.get("portal_token") or "").strip()
            if PORTAL_TOKEN_RE.fullmatch(token):
                tokens.add(token)
    return tokens


def _portal_ensure_token(payload: dict[str, Any], state_path: Path | None = None) -> str:
    candidate = str(payload.get("portal_token") or "").strip()
    used = _portal_collect_existing_tokens(current_path=state_path)
    if PORTAL_TOKEN_RE.fullmatch(candidate) and candidate not in used:
        return candidate
    for _ in range(128):
        token = secrets.token_urlsafe(12).rstrip("=")
        if token and token not in used and PORTAL_TOKEN_RE.fullmatch(token):
            return token
    raise RuntimeError("Gagal membuat portal_token unik.")


def _account_portal_url(token: str) -> str:
    token_n = str(token or "").strip()
    if not PORTAL_TOKEN_RE.fullmatch(token_n):
        return "-"
    host = str(_detect_domain() or "").strip() or str(_detect_public_ipv4() or "").strip()
    if not host:
        return "-"
    return f"https://{host}/account/{token_n}"


def _ssh_ensure_state_token(payload: dict[str, Any], state_path: Path | None = None) -> str:
    candidate = str(payload.get("sshws_token") or "").strip().lower()
    state_dir = state_path.parent if state_path is not None else SSH_QUOTA_DIR
    used = _ssh_collect_existing_tokens(state_dir, current_path=state_path)
    if re.fullmatch(r"[a-f0-9]{10}", candidate or "") and candidate not in used:
        return candidate
    for _ in range(128):
        token = secrets.token_hex(5)
        if token not in used:
            return token
    raise RuntimeError("Gagal membuat sshws_token unik.")


def _ssh_ws_public_ports_label() -> str:
    return _edge_runtime_ws_ports_label()


def _ssh_direct_public_ports_label() -> str:
    return _edge_runtime_ws_ports_label()


def _ssh_ssl_tls_public_ports_label() -> str:
    return _edge_runtime_ws_ports_label()


def _badvpn_public_port_label() -> str:
    return "7300, 7400, 7500, 7600, 7700, 7800, 7900"


def _path_alt_placeholder(path: str) -> str:
    raw = str(path or "").strip()
    if not raw:
        return "-"
    if not raw.startswith("/"):
        raw = "/" + raw
    return f"/<bebas>{raw}"


def _service_alt_placeholder(service: str) -> str:
    raw = str(service or "").strip()
    if not raw or raw == "-":
        return "-"
    return f"<bebas>/{raw}"


def _xray_ech_config_from_server_keys(server_keys: Any) -> str:
    raw = str(server_keys or "").strip()
    if not raw:
        return ""
    ok, out = _run_cmd(["xray", "tls", "ech", "-i", raw], timeout=10)
    if not ok:
        return ""
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    for idx, line in enumerate(lines):
        if line.lower().startswith("ech config list") and idx + 1 < len(lines):
            return lines[idx + 1]
    return ""


def _find_vless_xhttp3_inbound(cfg: Any) -> dict[str, Any] | None:
    if not isinstance(cfg, dict):
        return None
    for item in cfg.get("inbounds") or []:
        if isinstance(item, dict) and str(item.get("tag") or "").strip() == "default@vless-xhttp3":
            return item
    return None


def _build_vless_xhttp3_client_config(domain: str, cred: str, username: str, proto: str) -> dict[str, Any] | None:
    ok, cfg = _read_json(XRAY_INBOUNDS_CONF)
    if not ok:
        return None
    inbound = _find_vless_xhttp3_inbound(cfg)
    if not isinstance(inbound, dict):
        return None

    stream = inbound.get("streamSettings") or {}
    tls = stream.get("tlsSettings") or {}
    xhttp = stream.get("xhttpSettings") or {}
    finalmask = stream.get("finalmask") or {}
    udp_masks = finalmask.get("udp") if isinstance(finalmask, dict) else []
    quic_params = finalmask.get("quicParams") if isinstance(finalmask, dict) else {}

    out_stream: dict[str, Any] = {
        "network": "xhttp",
        "security": "tls",
        "tlsSettings": {
            "serverName": str(tls.get("serverName") or domain),
            "alpn": list(tls.get("alpn") or ["h3"]),
        },
        "xhttpSettings": {
            "path": str(xhttp.get("path") or "/vless-xhttp3"),
        },
    }
    user_agent = str((xhttp.get("headers") or {}).get("User-Agent") or "").strip()
    if user_agent:
        out_stream["xhttpSettings"]["headers"] = {"User-Agent": user_agent}

    ech_config = _xray_ech_config_from_server_keys(tls.get("echServerKeys"))
    if ech_config:
        out_stream["tlsSettings"]["echConfigList"] = ech_config

    udp_out: list[dict[str, Any]] = []
    if isinstance(udp_masks, list):
        for mask in udp_masks:
            if not isinstance(mask, dict):
                continue
            if str(mask.get("type") or "").strip() != "salamander":
                continue
            password = str(((mask.get("settings") or {}).get("password")) or "").strip()
            if password:
                udp_out.append({"type": "salamander", "settings": {"password": password}})
    if udp_out or (isinstance(quic_params, dict) and quic_params):
        out_stream["finalmask"] = {}
        if udp_out:
            out_stream["finalmask"]["udp"] = udp_out
        if isinstance(quic_params, dict) and quic_params:
            out_stream["finalmask"]["quicParams"] = quic_params

    email = f"{username}@{proto}"
    remark = f"VLESS XHTTP/3 Full - {email}"
    return {
        "remark": remark,
        "remarks": remark,
        "version": {"min": "26.3.27"},
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": {"udp": True},
            }
        ],
        "outbounds": [
            {
                "tag": "vless-xhttp3-out",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": domain,
                            "port": 443,
                            "users": [{"id": cred, "encryption": "none"}],
                        }
                    ]
                },
                "streamSettings": out_stream,
            }
        ],
        "routing": {
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["socks-in"],
                    "outboundTag": "vless-xhttp3-out",
                }
            ]
        },
    }


def _build_vless_xhttp3_link(domain: str, cred: str, username: str, proto: str) -> str:
    ok, cfg = _read_json(XRAY_INBOUNDS_CONF)
    if not ok:
        return ""
    inbound = _find_vless_xhttp3_inbound(cfg)
    if not isinstance(inbound, dict):
        return ""

    stream = inbound.get("streamSettings") or {}
    tls = stream.get("tlsSettings") or {}
    xhttp = stream.get("xhttpSettings") or {}
    finalmask = stream.get("finalmask") or {}
    headers = xhttp.get("headers") or {}
    user_agent = str(headers.get("User-Agent") or "").strip()
    ech_config = _xray_ech_config_from_server_keys(tls.get("echServerKeys"))

    query: dict[str, str] = {
        "alpn": "h3",
        "fp": user_agent or "firefox",
        "type": "xhttp",
        "sni": str(tls.get("serverName") or domain),
        "mode": str(xhttp.get("mode") or "auto"),
        "path": str(xhttp.get("path") or "/vless-xhttp3"),
        "security": "tls",
        "encryption": "none",
        "insecure": "0",
        "allowInsecure": "0",
    }
    if ech_config:
        query["ech"] = ech_config
    if isinstance(finalmask, dict) and finalmask:
        query["fm"] = json.dumps(finalmask, ensure_ascii=False, separators=(",", ":"))
    if isinstance(headers, dict) and headers:
        query["extra"] = json.dumps({"headers": headers}, ensure_ascii=False, separators=(",", ":"))
    return f"vless://{cred}@{domain}:443?{urllib.parse.urlencode(query)}#{urllib.parse.quote(username + '@' + proto)}"


def _proto_display_label(proto: str) -> str:
    mapping = {
        "vless": "Vless",
        "vmess": "Vmess",
        "trojan": "Trojan",
    }
    return mapping.get(str(proto or "").strip().lower(), str(proto or "").strip().title() or "Xray")


def _local_now() -> datetime:
    return datetime.now().astimezone()


def _local_today() -> date:
    return _local_now().date()


def _normalize_created_display(raw: Any, *, date_only: bool = False) -> str:
    value = str(raw or "").strip()
    if not value:
        return _local_now().strftime("%Y-%m-%d" if date_only else "%Y-%m-%d %H:%M")
    normalized = value.replace("T", " ").strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1]
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(normalized[: len(fmt)], fmt)
            if date_only:
                return dt.strftime("%Y-%m-%d")
            return dt.strftime("%Y-%m-%d" if fmt == "%Y-%m-%d" else "%Y-%m-%d %H:%M")
        except Exception:
            pass
    if len(normalized) >= 10 and normalized[4:5] == "-" and normalized[7:8] == "-":
        if date_only:
            return normalized[:10]
        return normalized[:16] if len(normalized) >= 16 and normalized[13:14] == ":" else normalized[:10]
    return _local_now().strftime("%Y-%m-%d" if date_only else "%Y-%m-%d %H:%M")


def _ssh_traffic_enforcement_ready() -> bool:
    return SSHWS_PROXY_BIN.exists() or _service_exists("sshws-proxy")


def _ssh_traffic_scope_label() -> str:
    if _ssh_traffic_enforcement_ready():
        return "Unified SSH QAC"
    return "Metadata only (SSH runtime not installed)"


def _ssh_traffic_scope_note() -> str:
    if _ssh_traffic_enforcement_ready():
        provider = _edge_runtime_get_env("EDGE_PROVIDER").strip().lower()
        if provider == "go":
            return (
                "Quota, speed limit, dan IP/Login limit berlaku sebagai satu sistem SSH pada SSH WS, "
                "SSH SSL/TLS, dan SSH Direct selama transport melewati Edge Gateway aktif. Pada provider go, "
                "trafik SSH SSL/TLS publik mengikuti jalur backend SSH klasik setelah terminasi TLS, sedangkan "
                "SSH WS memakai limiter token-aware milik sshws-proxy. Native sshd port 22 tetap di luar scope "
                "traffic enforcement."
            )
        return (
            "Quota, speed limit, dan IP/Login limit berlaku sebagai satu sistem SSH pada SSH WS, SSH SSL/TLS, "
            "dan SSH Direct selama transport melewati Edge Gateway aktif. Native sshd port 22 tetap di luar "
            "scope traffic enforcement."
        )
    return "SSH runtime belum terpasang; quota/IP-login/speed SSH masih metadata dan native sshd port 22 tidak dihitung atau di-throttle."


def _ssh_normalize_state_payload(
    username: str,
    payload: dict[str, Any] | None = None,
    *,
    created_at: str = "",
    expired_at: str = "",
    state_path: Path | None = None,
) -> dict[str, Any]:
    existing = payload if isinstance(payload, dict) else {}
    status_raw = existing.get("status") if isinstance(existing.get("status"), dict) else {}
    quota_limit = max(0, _to_int(existing.get("quota_limit"), 0))
    quota_used = max(0, _to_int(existing.get("quota_used"), 0))
    quota_unit = str(existing.get("quota_unit") or "binary").strip().lower()
    if quota_unit not in {"binary", "decimal"}:
        quota_unit = "binary"

    normalized: dict[str, Any] = {
        "managed_by": "autoscript-manage",
        "username": str(username or "").strip(),
        "protocol": SSH_PROTOCOL,
        "created_at": str(created_at or existing.get("created_at") or "").strip() or _local_now().strftime("%Y-%m-%d %H:%M"),
        "expired_at": (str(expired_at or existing.get("expired_at") or "-").strip() or "-")[:10],
        "quota_limit": quota_limit,
        "quota_unit": quota_unit,
        "quota_used": quota_used,
        "sshws_token": _ssh_ensure_state_token(existing, state_path=state_path),
        "portal_token": _portal_ensure_token(existing, state_path=state_path),
        "status": {
            "manual_block": bool(status_raw.get("manual_block")),
            "quota_exhausted": bool(status_raw.get("quota_exhausted")),
            "ip_limit_enabled": bool(status_raw.get("ip_limit_enabled")),
            "ip_limit": max(0, _to_int(status_raw.get("ip_limit"), 0)),
            "ip_limit_locked": bool(status_raw.get("ip_limit_locked")),
            "speed_limit_enabled": bool(status_raw.get("speed_limit_enabled")),
            "speed_down_mbit": max(0.0, _to_float(status_raw.get("speed_down_mbit"), 0.0)),
            "speed_up_mbit": max(0.0, _to_float(status_raw.get("speed_up_mbit"), 0.0)),
            "lock_reason": str(status_raw.get("lock_reason") or "").strip().lower(),
            "locked_at": str(status_raw.get("locked_at") or "").strip(),
            "account_locked": bool(status_raw.get("account_locked")),
            "lock_owner": str(status_raw.get("lock_owner") or "").strip(),
            "lock_shell_restore": str(status_raw.get("lock_shell_restore") or "").strip(),
        },
    }
    return normalized


def _ssh_load_state(
    username: str,
    *,
    create_missing: bool = False,
    created_at: str = "",
    expired_at: str = "",
) -> tuple[bool, Path | str, dict[str, Any] | str]:
    target = _resolve_existing(_quota_candidates(SSH_PROTOCOL, username))
    if target is None:
        if not create_missing:
            return False, f"File quota tidak ditemukan untuk {username} [{SSH_PROTOCOL}]", ""
        target = SSH_QUOTA_DIR / f"{username}@{SSH_PROTOCOL}.json"
        payload: dict[str, Any] = {}
    else:
        ok, raw = _read_json(target)
        if not ok:
            return False, str(raw), ""
        if not isinstance(raw, dict):
            return False, f"Format quota tidak valid: {target}", ""
        payload = raw

    normalized = _ssh_normalize_state_payload(
        username,
        payload,
        created_at=created_at,
        expired_at=expired_at,
        state_path=target,
    )
    return True, target, normalized


def _ssh_save_state(path: Path, payload: dict[str, Any]) -> None:
    normalized = _ssh_normalize_state_payload(
        str(payload.get("username") or ""),
        payload,
        created_at=str(payload.get("created_at") or ""),
        expired_at=str(payload.get("expired_at") or ""),
        state_path=path,
    )
    _write_json_atomic(path, normalized)
    _chmod_600(path)


def _ssh_quota_limit_display(quota_bytes: int) -> str:
    if quota_bytes <= 0:
        return "0 GB"
    return f"{_fmt_number(quota_bytes / (1024**3))} GB"


def _ssh_expired_display(expired_at: str) -> str:
    value = str(expired_at or "").strip()[:10]
    if not value or value == "-":
        return "unlimited"
    try:
        expiry = datetime.strptime(value, "%Y-%m-%d").date()
        days = max(0, (expiry - _local_today()).days)
        return f"{days} days"
    except Exception:
        return "unknown"


def _ssh_ip_limit_display(enabled: bool, limit: int) -> str:
    if not enabled:
        return "OFF"
    if limit > 0:
        return f"ON ({limit})"
    return "ON"


def _ssh_speed_limit_display(enabled: bool, down: float, up: float) -> str:
    if not enabled:
        return "OFF"
    return f"ON (DOWN {_fmt_number(down)} Mbps | UP {_fmt_number(up)} Mbps)"


def _ssh_route_mode_details(quota_payload: dict[str, Any]) -> tuple[str, str]:
    network = quota_payload.get("network") if isinstance(quota_payload.get("network"), dict) else {}
    override = str(network.get("route_mode") or "").strip().lower()
    if override not in {"inherit", "direct", "warp"}:
        override = "inherit"
    effective = _ssh_network_global_mode_get() if override == "inherit" else override
    if effective not in {"direct", "warp"}:
        effective = "direct"
    return override, effective


def _ssh_write_account_info(
    username: str,
    *,
    password: str,
    quota_payload: dict[str, Any],
) -> tuple[bool, str]:
    status = quota_payload.get("status") if isinstance(quota_payload.get("status"), dict) else {}
    account_file = SSH_ACCOUNT_DIR / f"{username}@{SSH_PROTOCOL}.txt"
    created_at = str(quota_payload.get("created_at") or "").strip() or _local_now().strftime("%Y-%m-%d %H:%M")
    created_disp = _normalize_created_display(created_at, date_only=True)
    expired_at = str(quota_payload.get("expired_at") or "-").strip()[:10] or "-"
    quota_limit = max(0, _to_int(quota_payload.get("quota_limit"), 0))
    ip_enabled = bool(status.get("ip_limit_enabled"))
    ip_limit = max(0, _to_int(status.get("ip_limit"), 0))
    speed_enabled = bool(status.get("speed_limit_enabled"))
    speed_down = max(0.0, _to_float(status.get("speed_down_mbit"), 0.0))
    speed_up = max(0.0, _to_float(status.get("speed_up_mbit"), 0.0))
    sshws_token = str(quota_payload.get("sshws_token") or "").strip().lower()
    portal_url = _account_portal_url(str(quota_payload.get("portal_token") or "").strip())
    if re.fullmatch(r"[a-f0-9]{10}", sshws_token or ""):
        sshws_path = f"/{sshws_token}"
        sshws_alt_path = f"/<bebas>/{sshws_token}/<bebas>"
        sshws_main = sshws_path
    else:
        sshws_path = "-"
        sshws_alt_path = "-"
        sshws_main = "-"
    domain = _detect_domain() or "-"
    ok_ip, public_ip = _get_public_ipv4()
    ip = (public_ip if ok_ip else (_detect_public_ipv4() or "-")).strip() or "-"
    isp, country = _geo_lookup(ip)

    account_info_labels = [
        "SSH WS Path",
        "SSH WS Path Alt",
        "SSH WS Port",
        "SSH Direct Port",
        "SSH SSL/TLS Port",
        "Alt Port SSL/TLS",
        "Alt Port HTTP",
        "BadVPN UDPGW",
    ]
    running_label_width = max(len(label) for label in account_info_labels)
    running_ssh_ws_path = f"{'SSH WS Path':<{running_label_width}} : {sshws_main}"
    running_ssh_ws_alt = f"{'SSH WS Path Alt':<{running_label_width}} : {sshws_alt_path}"
    running_ssh_ws_port = f"{'SSH WS Port':<{running_label_width}} : {_ssh_ws_public_ports_label()}"
    running_ssh_direct = f"{'SSH Direct Port':<{running_label_width}} : {_ssh_direct_public_ports_label()}"
    running_ssh_ssl_tls = f"{'SSH SSL/TLS Port':<{running_label_width}} : {_ssh_ssl_tls_public_ports_label()}"
    running_ssh_alt_tls = f"{'Alt Port SSL/TLS':<{running_label_width}} : {_edge_runtime_alt_tls_ports_label()}"
    running_ssh_alt_http = f"{'Alt Port HTTP':<{running_label_width}} : {_edge_runtime_alt_http_ports_label()}"
    running_badvpn = f"{'BadVPN UDPGW':<{running_label_width}} : {_badvpn_public_port_label()}"
    lines = [
        "=== ACCOUNT INFO ===",
        f"Domain      : {domain}",
        f"IP          : {ip}",
        f"ISP         : {isp}",
        f"Country     : {country}",
        f"Username    : {username}",
        f"Password    : {_ssh_password_output(password)}",
        f"Quota Limit : {_ssh_quota_limit_display(quota_limit)}",
        f"Expired     : {_ssh_expired_display(expired_at)}",
        f"Valid Until : {expired_at}",
        f"Created     : {created_disp}",
        f"IP Limit    : {_ssh_ip_limit_display(ip_enabled, ip_limit)}",
        f"Speed Limit : {_ssh_speed_limit_display(speed_enabled, speed_down, speed_up)}",
        f"Portal SSH  : {portal_url}",
        "",
        "=== SSH ===",
        running_ssh_ws_path,
        running_ssh_ws_alt,
        running_ssh_ws_port,
        running_ssh_direct,
        running_ssh_ssl_tls,
        running_ssh_alt_tls,
        running_ssh_alt_http,
        running_badvpn,
    ]
    content = "\n".join(lines) + "\n"
    try:
        _write_text_atomic(account_file, content)
        _chmod_600(account_file)
        return True, str(account_file)
    except Exception as exc:
        return False, f"Gagal menulis SSH account info: {exc}"


def _ssh_refresh_account_info(username: str, password_override: str = "") -> tuple[bool, str]:
    ok_state, state_path_or_err, payload_or_err = _ssh_load_state(username)
    if not ok_state:
        return False, str(state_path_or_err)
    state_path = state_path_or_err
    quota_payload = payload_or_err
    assert isinstance(state_path, Path)
    assert isinstance(quota_payload, dict)
    try:
        _ssh_save_state(state_path, quota_payload)
    except Exception as exc:
        return False, f"Gagal menyimpan state SSH: {exc}"
    password = str(password_override or "").strip() or _ssh_password_from_account_info(username)
    return _ssh_write_account_info(username, password=password, quota_payload=quota_payload)


def _ssh_account_info_paths_for_all_users() -> list[Path]:
    paths: list[Path] = []
    seen: set[str] = set()
    if not SSH_QUOTA_DIR.exists():
        return paths
    for quota_path in sorted(SSH_QUOTA_DIR.glob("*.json")):
        ok, payload = _read_json(quota_path)
        if not ok or not isinstance(payload, dict):
            continue
        username = str(payload.get("username") or quota_path.stem.split("@", 1)[0]).strip()
        if not _is_valid_ssh_username(username) or username in seen:
            continue
        seen.add(username)
        paths.append(SSH_ACCOUNT_DIR / f"{username}@{SSH_PROTOCOL}.txt")
    return paths


def _ssh_snapshot_account_info_files() -> dict[str, dict[str, Any]]:
    return {str(path): _snapshot_optional_file(path) for path in _ssh_account_info_paths_for_all_users()}


def _ssh_restore_account_info_snapshots(snapshots: dict[str, dict[str, Any]]) -> tuple[bool, str]:
    failures: list[str] = []
    for path_text, snapshot in snapshots.items():
        ok_restore, msg_restore = _restore_optional_file(Path(path_text), snapshot)
        if not ok_restore:
            failures.append(msg_restore)
    if failures:
        return False, " | ".join(failures)
    return True, "ok"


def _ssh_refresh_all_account_info() -> tuple[bool, str]:
    failures: list[str] = []
    if not SSH_QUOTA_DIR.exists():
        return True, "ok"
    for quota_path in sorted(SSH_QUOTA_DIR.glob("*.json")):
        ok, payload = _read_json(quota_path)
        if not ok or not isinstance(payload, dict):
            continue
        username = str(payload.get("username") or quota_path.stem.split("@", 1)[0]).strip()
        if not _is_valid_ssh_username(username):
            continue
        ok_refresh, refresh_msg = _ssh_refresh_account_info(username)
        if not ok_refresh:
            failures.append(f"{username}: {refresh_msg}")
    if failures:
        limited = failures[:5]
        if len(failures) > 5:
            limited.append(f"... total {len(failures)} user gagal")
        return False, " | ".join(limited)
    return True, "ok"


def _ssh_run_enforcer(*, username: str = "", require_available: bool = False) -> tuple[bool, str]:
    if not SSHWS_QAC_ENFORCER_BIN.exists():
        if require_available:
            return False, "sshws-qac-enforcer tidak tersedia"
        return True, "skip: sshws-qac-enforcer tidak tersedia"
    args = [str(SSHWS_QAC_ENFORCER_BIN), "--once"]
    target_user = str(username or "").strip()
    if target_user:
        args.extend(["--user", target_user])
    ok, out = _run_cmd(args, timeout=20)
    if ok:
        return True, "ok"
    return False, out


def _ssh_post_update_warnings(username: str, password_override: str = "") -> list[str]:
    warnings: list[str] = []
    ok_enforce, enforce_msg = _ssh_run_enforcer(username=username)
    if not ok_enforce:
        warnings.append(f"enforcer: {enforce_msg}")
    ok_refresh, refresh_msg = _ssh_refresh_account_info(username, password_override=password_override)
    if not ok_refresh:
        warnings.append(f"account-info: {refresh_msg}")
    return warnings


def _ssh_apply_state_update(
    username: str,
    path: Path,
    previous_payload: dict[str, Any],
    next_payload: dict[str, Any],
    *,
    password_override: str = "",
    require_enforcer: bool = False,
    require_account_info: bool = False,
) -> tuple[bool, list[str], str]:
    try:
        _ssh_save_state(path, next_payload)
    except Exception as exc:
        return False, [], f"Gagal menyimpan state SSH: {exc}"

    if not require_enforcer and not require_account_info:
        return True, _ssh_post_update_warnings(username, password_override=password_override), ""

    if not require_enforcer:
        ok_refresh, refresh_msg = _ssh_refresh_account_info(username, password_override=password_override)
        if ok_refresh:
            return True, [], ""
        rollback_notes: list[str] = []
        try:
            _ssh_save_state(path, previous_payload)
        except Exception as exc:
            rollback_notes.append(f"rollback-state: {exc}")
        else:
            ok_rollback_refresh, rollback_refresh_msg = _ssh_refresh_account_info(
                username,
                password_override=password_override,
            )
            if not ok_rollback_refresh:
                rollback_notes.append(f"rollback-account-info: {rollback_refresh_msg}")

        detail = f"account-info: {refresh_msg}"
        if rollback_notes:
            detail += " | " + " | ".join(rollback_notes)
        else:
            detail += " | state di-rollback"
        return False, [], detail

    ok_enforce, enforce_msg = _ssh_run_enforcer(username=username, require_available=True)
    if ok_enforce:
        ok_refresh, refresh_msg = _ssh_refresh_account_info(username, password_override=password_override)
        if ok_refresh:
            return True, [], ""

        rollback_notes: list[str] = []
        try:
            _ssh_save_state(path, previous_payload)
        except Exception as exc:
            rollback_notes.append(f"rollback-state: {exc}")
        else:
            ok_rollback_enforce, rollback_enforce_msg = _ssh_run_enforcer(
                username=username,
                require_available=True,
            )
            if not ok_rollback_enforce:
                rollback_notes.append(f"rollback-enforcer: {rollback_enforce_msg}")
            ok_rollback_refresh, rollback_refresh_msg = _ssh_refresh_account_info(
                username,
                password_override=password_override,
            )
            if not ok_rollback_refresh:
                rollback_notes.append(f"rollback-account-info: {rollback_refresh_msg}")

        detail = f"account-info: {refresh_msg}"
        if rollback_notes:
            detail += " | " + " | ".join(rollback_notes)
        else:
            detail += " | state di-rollback"
        return False, [], detail

    rollback_notes: list[str] = []
    try:
        _ssh_save_state(path, previous_payload)
    except Exception as exc:
        rollback_notes.append(f"rollback-state: {exc}")
    else:
        ok_rollback_enforce, rollback_enforce_msg = _ssh_run_enforcer(
            username=username,
            require_available=True,
        )
        if not ok_rollback_enforce:
            rollback_notes.append(f"rollback-enforcer: {rollback_enforce_msg}")
        ok_rollback_refresh, rollback_refresh_msg = _ssh_refresh_account_info(
            username,
            password_override=password_override,
        )
        if not ok_rollback_refresh:
            rollback_notes.append(f"rollback-account-info: {rollback_refresh_msg}")

    detail = f"enforcer: {enforce_msg}"
    if rollback_notes:
        detail += " | " + " | ".join(rollback_notes)
    else:
        detail += " | state di-rollback"
    return False, [], detail




def _ssh_restore_linux_password(username: str, password: str) -> tuple[bool, str]:
    return _run_cmd(
        ["bash", "-lc", 'printf "%s:%s\\n" "$0" "$1" | chpasswd', username, password],
        timeout=20,
    )


def _ssh_delete_linux_user(username: str) -> tuple[bool, str]:
    if not _linux_user_exists(username):
        return True, "skip"
    ok_del, out_del = _run_cmd(["userdel", "-r", username], timeout=20)
    if ok_del or not _linux_user_exists(username):
        return True, out_del
    ok_del2, out_del2 = _run_cmd(["userdel", username], timeout=20)
    if ok_del2 or not _linux_user_exists(username):
        return True, out_del2
    return False, out_del2


def _ssh_password_reset_rollback(username: str, previous_password: str) -> tuple[bool, str]:
    previous = str(previous_password or "").strip()
    if not previous or previous == "-":
        return False, "password lama tidak tersedia untuk rollback"
    ok_restore, restore_msg = _ssh_restore_linux_password(username, previous)
    if not ok_restore:
        return False, f"rollback Linux password gagal: {restore_msg}"
    rollback_notes: list[str] = []
    ok_refresh, refresh_msg = _ssh_refresh_account_info(username, password_override=previous)
    if not ok_refresh:
        rollback_notes.append(f"account info rollback gagal: {refresh_msg}")
    if rollback_notes:
        return False, "password Linux dipulihkan, tetapi " + " | ".join(rollback_notes)
    return True, "ok"



def _ssh_add_user_rollback(
    username: str,
    quota_path: Path | None,
    account_path: Path,
    *,
    raw_password: str,
    error_prefix: str,
) -> tuple[bool, str, str]:
    title = "User Management - Add User"
    ok_del, del_msg = _ssh_delete_linux_user(username)
    if not ok_del:
        rollback_note = ""
        return (
            False,
            title,
            (
                f"{error_prefix}\n"
                f"- Rollback user Linux gagal: {del_msg}\n"
                f"- Akun dipertahankan agar bisa dipulihkan/manual cleanup"
                f"{rollback_note}"
            ),
        )

    for path in (quota_path, account_path):
        if path is None:
            continue
        try:
            path.unlink(missing_ok=True)
        except Exception as exc:
            error_prefix += f"\n- Cleanup artefak gagal: {path} ({exc})"
            continue
        if path.exists() or path.is_symlink():
            error_prefix += f"\n- Cleanup artefak gagal: {path} masih ada"
    return False, title, error_prefix


def _ssh_apply_linux_expiry(username: str, expiry: str) -> tuple[bool, str]:
    expiry_n = str(expiry or "").strip()
    if not expiry_n or expiry_n == "-":
        return _run_cmd(["chage", "-E", "-1", username], timeout=20)
    return _run_cmd(["chage", "-E", expiry_n, username], timeout=20)


def _ssh_expiry_update_rollback(
    username: str,
    previous_expiry: str,
    quota_path: Path,
    previous_payload: dict[str, Any],
) -> tuple[bool, str]:
    notes: list[str] = []
    ok_expiry, expiry_msg = _ssh_apply_linux_expiry(username, previous_expiry)
    if not ok_expiry:
        notes.append(f"rollback-expiry: {expiry_msg}")
    try:
        _ssh_save_state(quota_path, previous_payload)
    except Exception as exc:
        notes.append(f"rollback-state: {exc}")
    ok_refresh, refresh_msg = _ssh_refresh_account_info(username)
    if not ok_refresh:
        notes.append(f"rollback-account-info: {refresh_msg}")
    if notes:
        return False, " | ".join(notes)
    return True, "ok"


def _account_candidates(proto: str, username: str) -> list[Path]:
    return [
        ACCOUNT_ROOT / proto / f"{username}@{proto}.txt",
        ACCOUNT_ROOT / proto / f"{username}.txt",
    ]


def _quota_candidates(proto: str, username: str) -> list[Path]:
    return [
        QUOTA_ROOT / proto / f"{username}@{proto}.json",
        QUOTA_ROOT / proto / f"{username}.json",
    ]


def _resolve_existing(candidates: list[Path]) -> Path | None:
    for p in candidates:
        if p.exists():
            return p
    return None


def _load_quota(proto: str, username: str) -> tuple[bool, Path | str, dict[str, Any] | str]:
    target = _resolve_existing(_quota_candidates(proto, username))
    if target is None:
        return False, f"File quota tidak ditemukan untuk {username} [{proto}]", ""
    ok, payload = _read_json(target)
    if not ok:
        return False, str(payload), ""
    if not isinstance(payload, dict):
        return False, f"Format quota tidak valid: {target}", ""
    return True, target, payload


def _save_quota(path: Path, payload: dict[str, Any]) -> None:
    if isinstance(payload, dict):
        payload["portal_token"] = _portal_ensure_token(payload, state_path=path)
    _write_json_atomic(path, payload)
    _chmod_600(path)


def _extract_username_from_file_name(path: Path, proto: str) -> str:
    stem = path.stem
    suffix = f"@{proto}"
    if stem.endswith(suffix):
        return stem[: -len(suffix)]
    return stem


def _username_exists_anywhere(username: str) -> tuple[bool, str]:
    needle = username.strip().lower()

    for proto in USER_PROTOCOLS:
        acc_dir = ACCOUNT_ROOT / proto
        if acc_dir.exists():
            for p in acc_dir.glob("*.txt"):
                if _extract_username_from_file_name(p, proto).lower() == needle:
                    return True, f"account:{proto}:{p.name}"
        q_dir = QUOTA_ROOT / proto
        if q_dir.exists():
            for p in q_dir.glob("*.json"):
                if _extract_username_from_file_name(p, proto).lower() == needle:
                    return True, f"quota:{proto}:{p.name}"

    ok, payload = _read_json(XRAY_INBOUNDS_CONF)
    if ok and isinstance(payload, dict):
        inbounds = payload.get("inbounds", [])
        if isinstance(inbounds, list):
            for ib in inbounds:
                if not isinstance(ib, dict):
                    continue
                proto = str(ib.get("protocol") or "")
                settings = ib.get("settings") or {}
                clients = settings.get("clients") if isinstance(settings, dict) else []
                if not isinstance(clients, list):
                    continue
                for c in clients:
                    if not isinstance(c, dict):
                        continue
                    email = str(c.get("email") or "").lower().strip()
                    user_part, _, proto_part = email.partition("@")
                    if user_part == needle and proto_part in PROTOCOLS:
                        return True, f"xray:{proto_part}:{email}"
    if _linux_user_exists(needle):
        return True, f"linux:{needle}"
    return False, ""


def _inbound_matches_proto(ib: Any, proto: str) -> bool:
    if not isinstance(ib, dict):
        return False
    ib_proto = str(ib.get("protocol") or "").strip().lower()
    return proto in {"vless", "vmess", "trojan"} and ib_proto == proto


def _generate_credential(proto: str) -> str:
    if proto == "trojan":
        return secrets.token_hex(16)
    return str(uuid.uuid4())


def _xray_add_client(proto: str, username: str, cred: str) -> tuple[bool, str]:
    if not XRAY_INBOUNDS_CONF.exists():
        return False, f"Config tidak ditemukan: {XRAY_INBOUNDS_CONF}"

    email = _email(proto, username)
    with file_lock(ROUTING_LOCK_FILE):
        ok, payload = _read_json(XRAY_INBOUNDS_CONF)
        if not ok:
            return False, str(payload)
        if not isinstance(payload, dict):
            return False, "Format inbounds tidak valid"

        original = json.loads(json.dumps(payload))
        inbounds = payload.get("inbounds")
        if not isinstance(inbounds, list):
            return False, "Format inbounds tidak valid: inbounds bukan list"

        for ib in inbounds:
            if not isinstance(ib, dict):
                continue
            if not _inbound_matches_proto(ib, proto):
                continue
            settings = ib.get("settings") or {}
            clients = settings.get("clients")
            if isinstance(clients, list):
                for c in clients:
                    if isinstance(c, dict) and str(c.get("email") or "") == email:
                        return False, f"User sudah ada di config: {email}"

        if proto == "vless":
            client = {"id": cred, "email": email}
        elif proto == "vmess":
            client = {"id": cred, "alterId": 0, "email": email}
        elif proto == "trojan":
            client = {"password": cred, "email": email}
        elif proto != "trojan":
            return False, f"Protocol tidak didukung: {proto}"
        else:
            client = {"password": cred, "email": email}

        updated = False
        for ib in inbounds:
            if not isinstance(ib, dict):
                continue
            if not _inbound_matches_proto(ib, proto):
                continue
            settings = ib.setdefault("settings", {})
            clients = settings.get("clients")
            if clients is None:
                settings["clients"] = []
                clients = settings["clients"]
            if not isinstance(clients, list):
                continue
            clients.append(client)
            updated = True

        if not updated:
            return False, f"Inbound protocol {proto} tidak ditemukan"

        try:
            _write_json_atomic(XRAY_INBOUNDS_CONF, payload)
            if not _restart_and_wait("xray", timeout_sec=20):
                _write_json_atomic(XRAY_INBOUNDS_CONF, original)
                _restart_and_wait("xray", timeout_sec=20)
                return False, "xray tidak aktif setelah add user (rollback)."
        except Exception as exc:
            try:
                _write_json_atomic(XRAY_INBOUNDS_CONF, original)
                _restart_and_wait("xray", timeout_sec=20)
            except Exception:
                pass
            return False, f"Gagal update inbounds: {exc}"

    return True, "ok"


def _xray_delete_client(proto: str, username: str) -> tuple[bool, str]:
    if not XRAY_INBOUNDS_CONF.exists():
        return False, f"Config tidak ditemukan: {XRAY_INBOUNDS_CONF}"
    if not XRAY_ROUTING_CONF.exists():
        return False, f"Config tidak ditemukan: {XRAY_ROUTING_CONF}"

    email = _email(proto, username)
    with file_lock(ROUTING_LOCK_FILE):
        ok_inb, inb_payload = _read_json(XRAY_INBOUNDS_CONF)
        if not ok_inb:
            return False, str(inb_payload)
        ok_rt, rt_payload = _read_json(XRAY_ROUTING_CONF)
        if not ok_rt:
            return False, str(rt_payload)
        if not isinstance(inb_payload, dict) or not isinstance(rt_payload, dict):
            return False, "Format config Xray tidak valid"

        inb_original = json.loads(json.dumps(inb_payload))
        rt_original = json.loads(json.dumps(rt_payload))

        inbounds = inb_payload.get("inbounds")
        if not isinstance(inbounds, list):
            return False, "Format inbounds tidak valid"

        removed = 0
        for ib in inbounds:
            if not isinstance(ib, dict):
                continue
            if not _inbound_matches_proto(ib, proto):
                continue
            settings = ib.get("settings") or {}
            clients = settings.get("clients")
            if not isinstance(clients, list):
                continue
            before = len(clients)
            settings["clients"] = [c for c in clients if not (isinstance(c, dict) and str(c.get("email") or "") == email)]
            removed += before - len(settings["clients"])
            ib["settings"] = settings

        if removed == 0:
            return False, f"User tidak ditemukan di inbounds: {email}"

        routing = rt_payload.get("routing") or {}
        rules = routing.get("rules") if isinstance(routing, dict) else None
        if isinstance(rules, list):
            markers = {"dummy-block-user", "dummy-quota-user", "dummy-limit-user", "dummy-warp-user", "dummy-direct-user"}
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                users = rule.get("user")
                if not isinstance(users, list):
                    continue
                has_marker = any(u in markers for u in users)
                if not has_marker:
                    has_marker = any(isinstance(u, str) and u.startswith(SPEED_RULE_MARKER_PREFIX) for u in users)
                if not has_marker:
                    continue
                rule["user"] = [u for u in users if u != email]
            routing["rules"] = rules
            rt_payload["routing"] = routing

        try:
            _write_json_atomic(XRAY_INBOUNDS_CONF, inb_payload)
            _write_json_atomic(XRAY_ROUTING_CONF, rt_payload)
            if not _restart_and_wait("xray", timeout_sec=20):
                _write_json_atomic(XRAY_INBOUNDS_CONF, inb_original)
                _write_json_atomic(XRAY_ROUTING_CONF, rt_original)
                _restart_and_wait("xray", timeout_sec=20)
                return False, "xray tidak aktif setelah delete user (rollback)."
        except Exception as exc:
            try:
                _write_json_atomic(XRAY_INBOUNDS_CONF, inb_original)
                _write_json_atomic(XRAY_ROUTING_CONF, rt_original)
                _restart_and_wait("xray", timeout_sec=20)
            except Exception:
                pass
            return False, f"Gagal update config saat delete user: {exc}"

    return True, "ok"


def _routing_set_user_in_marker(marker: str, email: str, state: str, outbound_tag: str = "blocked") -> tuple[bool, str]:
    if state not in {"on", "off"}:
        return False, "state harus on/off"
    if not XRAY_ROUTING_CONF.exists():
        return False, f"Config routing tidak ditemukan: {XRAY_ROUTING_CONF}"

    with file_lock(ROUTING_LOCK_FILE):
        ok, payload = _read_json(XRAY_ROUTING_CONF)
        if not ok:
            return False, str(payload)
        if not isinstance(payload, dict):
            return False, "Format routing tidak valid"

        original = json.loads(json.dumps(payload))
        routing = payload.get("routing") or {}
        rules = routing.get("rules") if isinstance(routing, dict) else None
        if not isinstance(rules, list):
            return False, "Format routing.rules tidak valid"

        target = None
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            if rule.get("type") != "field":
                continue
            if rule.get("outboundTag") != outbound_tag:
                continue
            users = rule.get("user")
            if not isinstance(users, list):
                continue
            if marker in users:
                target = rule
                break

        if target is None:
            return False, f"Marker {marker} pada outboundTag={outbound_tag} tidak ditemukan"

        users = target.get("user") or []
        if not isinstance(users, list):
            users = []

        if marker not in users:
            users.insert(0, marker)
        else:
            users = [marker] + [u for u in users if u != marker]

        changed = False
        if state == "on":
            if email not in users:
                users.append(email)
                changed = True
        else:
            new_users = [u for u in users if u != email]
            if new_users != users:
                users = new_users
                changed = True

        if not changed:
            return True, "noop"

        target["user"] = users
        routing["rules"] = rules
        payload["routing"] = routing

        try:
            _write_json_atomic(XRAY_ROUTING_CONF, payload)
            if not _restart_and_wait("xray", timeout_sec=20):
                _write_json_atomic(XRAY_ROUTING_CONF, original)
                _restart_and_wait("xray", timeout_sec=20)
                return False, "xray tidak aktif setelah update routing marker (rollback)."
        except Exception as exc:
            try:
                _write_json_atomic(XRAY_ROUTING_CONF, original)
                _restart_and_wait("xray", timeout_sec=20)
            except Exception:
                pass
            return False, f"Gagal update routing marker: {exc}"

    return True, "ok"


def _is_speed_outbound_tag(tag: str) -> bool:
    return bool(tag) and tag.startswith(SPEED_OUTBOUND_TAG_PREFIX)


def _routing_default_rule_index(rules: list[Any]) -> int:
    idx = -1
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        if rule.get("type") != "field":
            continue
        port = str(rule.get("port") or "").strip()
        if port not in DEFAULT_EGRESS_PORTS:
            continue
        if rule.get("user") or rule.get("domain") or rule.get("ip") or rule.get("protocol"):
            continue
        idx = i
    return idx


def _outbound_tags_from_cfg(out_cfg: dict[str, Any]) -> list[str]:
    tags: list[str] = []
    seen: set[str] = set()
    outbounds = out_cfg.get("outbounds")
    if not isinstance(outbounds, list):
        return tags
    for item in outbounds:
        if not isinstance(item, dict):
            continue
        tag = str(item.get("tag") or "").strip()
        if not tag or tag in seen:
            continue
        seen.add(tag)
        tags.append(tag)
    return tags


def _routing_set_default_warp_global_mode(rt_cfg: dict[str, Any], out_cfg: dict[str, Any], mode: str) -> tuple[bool, str]:
    mode_n = str(mode or "").strip().lower()
    if mode_n not in {"direct", "warp"}:
        return False, "Mode WARP global harus direct/warp."

    routing = rt_cfg.get("routing")
    if not isinstance(routing, dict):
        routing = {}
    rules = routing.get("rules")
    if not isinstance(rules, list):
        return False, "Invalid routing config: routing.rules bukan list"

    idx = _routing_default_rule_index(rules)
    if idx < 0:
        return False, "Default rule (port 1-65535 / 0-65535) tidak ditemukan."

    outbound_tags = _outbound_tags_from_cfg(out_cfg)
    if mode_n in {"direct", "warp"} and mode_n not in set(outbound_tags):
        return False, f"Outbound '{mode_n}' tidak ditemukan pada 20-outbounds.json."

    target = rules[idx]
    if not isinstance(target, dict):
        return False, "Default rule tidak valid."

    if mode_n in {"direct", "warp"}:
        target["outboundTag"] = mode_n
    rules[idx] = target
    routing["rules"] = rules
    rt_cfg["routing"] = routing
    return True, f"WARP global di-set ke {mode_n}."


def _routing_find_user_rule_index(rules: list[Any], marker: str, outbound: str) -> int:
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        if rule.get("type") != "field":
            continue
        if str(rule.get("outboundTag") or "") != outbound:
            continue
        users = rule.get("user")
        if not isinstance(users, list):
            continue
        # Rule per-user harus tidak mengandung inboundTag.
        if "inboundTag" in rule:
            continue
        if marker in users:
            return i
    return -1


def _routing_find_inbound_rule_index(rules: list[Any], marker: str, outbound: str) -> int:
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        if rule.get("type") != "field":
            continue
        if str(rule.get("outboundTag") or "") != outbound:
            continue
        tags = rule.get("inboundTag")
        if not isinstance(tags, list):
            continue
        if marker in tags:
            return i
    return -1


def _routing_list_marker_users(rules: list[Any], marker: str, outbound: str) -> list[str]:
    idx = _routing_find_user_rule_index(rules, marker, outbound)
    if idx < 0:
        return []
    rule = rules[idx]
    if not isinstance(rule, dict):
        return []
    users = rule.get("user")
    if not isinstance(users, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in users:
        if not isinstance(item, str):
            continue
        value = item.strip()
        if not value or value == marker or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _routing_list_marker_inbounds(rules: list[Any], marker: str, outbound: str) -> list[str]:
    idx = _routing_find_inbound_rule_index(rules, marker, outbound)
    if idx < 0:
        return []
    rule = rules[idx]
    if not isinstance(rule, dict):
        return []
    tags = rule.get("inboundTag")
    if not isinstance(tags, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in tags:
        if not isinstance(item, str):
            continue
        value = item.strip()
        if not value or value == marker or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _routing_find_domain_rule_index(rules: list[Any], marker: str, outbound: str) -> int:
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        if rule.get("type") != "field":
            continue
        if str(rule.get("outboundTag") or "") != outbound:
            continue
        domains = rule.get("domain")
        if not isinstance(domains, list):
            continue
        if marker in domains:
            return i
    return -1


def _routing_list_marker_domains(rules: list[Any], marker: str, outbound: str) -> list[str]:
    idx = _routing_find_domain_rule_index(rules, marker, outbound)
    if idx < 0:
        return []
    rule = rules[idx]
    if not isinstance(rule, dict):
        return []
    domains = rule.get("domain")
    if not isinstance(domains, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in domains:
        if not isinstance(item, str):
            continue
        value = item.strip()
        if not value or value == marker or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _routing_set_user_warp_mode(rt_cfg: dict[str, Any], email: str, mode: str) -> tuple[bool, str]:
    mode_n = str(mode or "").strip().lower()
    if mode_n not in {"direct", "warp", "off"}:
        return False, "Mode user harus direct/warp/off."

    routing = rt_cfg.get("routing")
    if not isinstance(routing, dict):
        routing = {}
    rules = routing.get("rules")
    if not isinstance(rules, list):
        return False, "Invalid routing config: routing.rules bukan list"

    default_idx = _routing_default_rule_index(rules)
    if default_idx < 0:
        return False, "Default rule (port 1-65535 / 0-65535) tidak ditemukan."

    def toggle_user_marker(marker: str, outbound: str, enable: bool) -> None:
        nonlocal default_idx
        idx = _routing_find_user_rule_index(rules, marker, outbound)
        if idx < 0 and not enable:
            return
        if idx < 0 and enable:
            rules.insert(default_idx, {"type": "field", "user": [marker], "outboundTag": outbound})
            idx = default_idx
            default_idx += 1

        rule = rules[idx]
        if not isinstance(rule, dict):
            rule = {"type": "field", "user": [marker], "outboundTag": outbound}
        users = rule.get("user")
        if not isinstance(users, list):
            users = []
        users = [u for u in users if u != marker and u != email]
        users.insert(0, marker)
        if enable and email not in users:
            users.append(email)
        rule["type"] = "field"
        rule["outboundTag"] = outbound
        rule["user"] = users
        rules[idx] = rule

    if mode_n == "direct":
        toggle_user_marker("dummy-warp-user", "warp", enable=False)
        toggle_user_marker("dummy-direct-user", "direct", enable=True)
    elif mode_n == "warp":
        toggle_user_marker("dummy-direct-user", "direct", enable=False)
        toggle_user_marker("dummy-warp-user", "warp", enable=True)
    else:
        toggle_user_marker("dummy-direct-user", "direct", enable=False)
        toggle_user_marker("dummy-warp-user", "warp", enable=False)

    routing["rules"] = rules
    rt_cfg["routing"] = routing
    return True, f"Override user di-set: {email} -> {mode_n}"


def _routing_set_inbound_warp_mode(rt_cfg: dict[str, Any], inbound_tag: str, mode: str) -> tuple[bool, str]:
    mode_n = str(mode or "").strip().lower()
    if mode_n not in {"direct", "warp", "off"}:
        return False, "Mode inbound harus direct/warp/off."

    routing = rt_cfg.get("routing")
    if not isinstance(routing, dict):
        routing = {}
    rules = routing.get("rules")
    if not isinstance(rules, list):
        return False, "Invalid routing config: routing.rules bukan list"

    default_idx = _routing_default_rule_index(rules)
    if default_idx < 0:
        return False, "Default rule (port 1-65535 / 0-65535) tidak ditemukan."

    def toggle_inbound_marker(marker: str, outbound: str, enable: bool) -> None:
        nonlocal default_idx
        idx = _routing_find_inbound_rule_index(rules, marker, outbound)
        if idx < 0 and not enable:
            return
        if idx < 0 and enable:
            rules.insert(default_idx, {"type": "field", "inboundTag": [marker], "outboundTag": outbound})
            idx = default_idx
            default_idx += 1

        rule = rules[idx]
        if not isinstance(rule, dict):
            rule = {"type": "field", "inboundTag": [marker], "outboundTag": outbound}
        tags = rule.get("inboundTag")
        if not isinstance(tags, list):
            tags = []
        tags = [t for t in tags if t != marker and t != inbound_tag]
        tags.insert(0, marker)
        if enable and inbound_tag not in tags:
            tags.append(inbound_tag)
        rule["type"] = "field"
        rule["outboundTag"] = outbound
        rule["inboundTag"] = tags
        rules[idx] = rule

    if mode_n == "direct":
        toggle_inbound_marker("dummy-warp-inbounds", "warp", enable=False)
        toggle_inbound_marker("dummy-direct-inbounds", "direct", enable=True)
    elif mode_n == "warp":
        toggle_inbound_marker("dummy-direct-inbounds", "direct", enable=False)
        toggle_inbound_marker("dummy-warp-inbounds", "warp", enable=True)
    else:
        toggle_inbound_marker("dummy-direct-inbounds", "direct", enable=False)
        toggle_inbound_marker("dummy-warp-inbounds", "warp", enable=False)

    routing["rules"] = rules
    rt_cfg["routing"] = routing
    return True, f"Override inbound di-set: {inbound_tag} -> {mode_n}"


def _routing_set_custom_domain_mode(rt_cfg: dict[str, Any], mode: str, entry: str) -> tuple[bool, str]:
    mode_n = str(mode or "").strip().lower()
    ent = str(entry or "").strip()
    if mode_n not in {"direct", "warp", "off"}:
        return False, "Mode domain harus direct/warp/off."
    if not ent:
        return False, "Entry domain/geosite tidak boleh kosong."
    if ent in {"regexp:^$", "regexp:^$WARP"}:
        return False, "Entry reserved tidak boleh dipakai."
    if ent in READONLY_GEOSITE_DOMAINS:
        return False, f"Readonly geosite tidak boleh diubah: {ent}"

    routing = rt_cfg.get("routing")
    if not isinstance(routing, dict):
        routing = {}
    rules = routing.get("rules")
    if not isinstance(rules, list):
        return False, "Invalid routing config: routing.rules bukan list"

    default_idx = _routing_default_rule_index(rules)
    if default_idx < 0:
        return False, "Default rule (port 1-65535 / 0-65535) tidak ditemukan."

    def find_template_direct_idx() -> int:
        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                continue
            if rule.get("type") != "field":
                continue
            if str(rule.get("outboundTag") or "") != "direct":
                continue
            domains = rule.get("domain")
            if not isinstance(domains, list):
                continue
            if "geosite:apple" in domains or "geosite:google" in domains:
                return i
        return -1

    def ensure_domain_rule(outbound: str, marker: str, insert_at: int) -> int:
        idx = _routing_find_domain_rule_index(rules, marker, outbound)
        if idx >= 0:
            return idx
        rules.insert(insert_at, {"type": "field", "domain": [marker], "outboundTag": outbound})
        return insert_at

    def normalize_rule(idx: int, marker: str, desired_present: bool) -> None:
        rule = rules[idx]
        if not isinstance(rule, dict):
            rule = {"type": "field", "domain": [marker]}
        domains = rule.get("domain")
        if not isinstance(domains, list):
            domains = []
        domains = [d for d in domains if d != marker and d != ent]
        domains.insert(0, marker)
        if desired_present:
            domains.append(ent)
        rule["type"] = "field"
        rule["domain"] = domains
        rules[idx] = rule

    tpl_idx = find_template_direct_idx()
    base = (tpl_idx + 1) if tpl_idx >= 0 else default_idx

    direct_marker = "regexp:^$"
    warp_marker = "regexp:^$WARP"
    direct_idx = _routing_find_domain_rule_index(rules, direct_marker, "direct")
    warp_idx = _routing_find_domain_rule_index(rules, warp_marker, "warp")

    if mode_n == "direct":
        if direct_idx < 0:
            direct_idx = ensure_domain_rule("direct", direct_marker, base)
            if direct_idx <= default_idx:
                default_idx += 1
        if warp_idx >= 0:
            normalize_rule(warp_idx, warp_marker, False)
        normalize_rule(direct_idx, direct_marker, True)
    elif mode_n == "warp":
        base_warp = (direct_idx + 1) if direct_idx >= 0 else base
        if warp_idx < 0:
            warp_idx = ensure_domain_rule("warp", warp_marker, base_warp)
            if warp_idx <= default_idx:
                default_idx += 1
        if direct_idx >= 0:
            normalize_rule(direct_idx, direct_marker, False)
        normalize_rule(warp_idx, warp_marker, True)
    else:
        if direct_idx >= 0:
            normalize_rule(direct_idx, direct_marker, False)
        if warp_idx >= 0:
            normalize_rule(warp_idx, warp_marker, False)

    for idx in range(len(rules) - 1, -1, -1):
        rule = rules[idx]
        if not isinstance(rule, dict):
            continue
        if rule.get("type") != "field":
            continue
        if str(rule.get("outboundTag") or "") not in {"direct", "warp"}:
            continue
        domains = rule.get("domain")
        if not isinstance(domains, list):
            continue
        normalized = [str(item).strip() for item in domains if str(item).strip()]
        if not normalized:
            continue
        real_domains = [item for item in normalized if item not in {direct_marker, warp_marker}]
        if real_domains:
            continue
        if direct_marker in normalized or warp_marker in normalized:
            rules.pop(idx)

    routing["rules"] = rules
    rt_cfg["routing"] = routing
    return True, f"Domain/geosite di-set {mode_n}: {ent}"


def _apply_routing_transaction(
    mutator: Any,
) -> tuple[bool, str]:
    if not XRAY_ROUTING_CONF.exists():
        return False, f"Config routing tidak ditemukan: {XRAY_ROUTING_CONF}"
    if not XRAY_OUTBOUNDS_CONF.exists():
        return False, f"Config outbounds tidak ditemukan: {XRAY_OUTBOUNDS_CONF}"

    with file_lock(ROUTING_LOCK_FILE):
        ok_rt, rt_cfg = _read_json(XRAY_ROUTING_CONF)
        if not ok_rt:
            return False, str(rt_cfg)
        ok_out, out_cfg = _read_json(XRAY_OUTBOUNDS_CONF)
        if not ok_out:
            return False, str(out_cfg)
        if not isinstance(rt_cfg, dict) or not isinstance(out_cfg, dict):
            return False, "Format config Xray tidak valid."

        rt_original = json.loads(json.dumps(rt_cfg))
        try:
            ok_mut, msg_mut = mutator(rt_cfg, out_cfg)
            if not ok_mut:
                return False, str(msg_mut)
            _write_json_atomic(XRAY_ROUTING_CONF, rt_cfg)
            if not _restart_and_wait("xray", timeout_sec=20):
                _write_json_atomic(XRAY_ROUTING_CONF, rt_original)
                _restart_and_wait("xray", timeout_sec=20)
                return False, "xray tidak aktif setelah update network controls (rollback)."
            return True, str(msg_mut)
        except Exception as exc:
            try:
                _write_json_atomic(XRAY_ROUTING_CONF, rt_original)
                _restart_and_wait("xray", timeout_sec=20)
            except Exception:
                pass
            return False, f"Gagal update routing network controls: {exc}"


def _normalize_dns_root(cfg: Any) -> dict[str, Any]:
    if not isinstance(cfg, dict):
        cfg = {}
    dns_obj = cfg.get("dns")
    if not isinstance(dns_obj, dict):
        dns_obj = {}
    cfg["dns"] = dns_obj
    return cfg


def _dns_servers_list(cfg: dict[str, Any]) -> list[Any]:
    dns_obj = cfg.get("dns")
    if not isinstance(dns_obj, dict):
        dns_obj = {}
        cfg["dns"] = dns_obj
    servers = dns_obj.get("servers")
    if not isinstance(servers, list):
        servers = []
    dns_obj["servers"] = servers
    return servers


def _dns_set_server_idx(cfg: dict[str, Any], idx: int, value: str) -> None:
    val = str(value or "").strip()
    if not val:
        return
    servers = _dns_servers_list(cfg)
    while len(servers) <= idx:
        servers.append("")
    if isinstance(servers[idx], dict):
        servers[idx]["address"] = val
    else:
        servers[idx] = val


def _is_valid_port_text(port_text: str) -> bool:
    if not port_text.isdigit():
        return False
    try:
        port = int(port_text)
    except Exception:
        return False
    return 1 <= port <= 65535


def _is_valid_dns_host(value: str) -> bool:
    host = str(value or "").strip().lower().strip(".")
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        pass
    return bool(DOMAIN_RE.match(host))


def _is_valid_dns_server_value(value: str) -> bool:
    val = str(value or "").strip()
    if not val:
        return False

    # Plain IP/FQDN.
    if _is_valid_dns_host(val):
        return True

    # IPv4 with explicit port.
    if ":" in val and val.count(":") == 1:
        host, port_text = val.rsplit(":", 1)
        if _is_valid_port_text(port_text) and _is_valid_dns_host(host):
            return True

    # Bracketed IPv6 with explicit port.
    m = re.match(r"^\[(.+)\]:(\d{1,5})$", val)
    if m:
        host = m.group(1)
        port_text = m.group(2)
        if _is_valid_port_text(port_text):
            try:
                ipaddress.ip_address(host)
                return True
            except Exception:
                return False

    # URI form (for DoH/DoT style values), e.g. https://dns.google/dns-query.
    parsed = urllib.parse.urlparse(val)
    if parsed.scheme and parsed.hostname and _is_valid_dns_host(str(parsed.hostname)):
        return True

    return False


def _apply_dns_transaction(mutator: Any) -> tuple[bool, str]:
    if not _service_exists("xray"):
        return False, "Service xray tidak tersedia; update DNS dibatalkan."

    with file_lock(DNS_LOCK_FILE):
        existed_before = XRAY_DNS_CONF.exists()
        raw_snapshot: bytes | None = None
        raw_mode: int | None = None
        if existed_before:
            try:
                raw_snapshot = XRAY_DNS_CONF.read_bytes()
                raw_mode = int(XRAY_DNS_CONF.stat().st_mode & 0o777)
            except Exception as exc:
                return False, f"Gagal membaca snapshot DNS asli: {exc}"

        cfg_original: dict[str, Any]
        if XRAY_DNS_CONF.exists():
            ok_read, raw_cfg = _read_json(XRAY_DNS_CONF)
            if not ok_read:
                return False, f"Config DNS tidak valid:\n{raw_cfg}"
            cfg_original = raw_cfg if isinstance(raw_cfg, dict) else {}
        else:
            cfg_original = {"dns": {}}

        cfg_work = json.loads(json.dumps(cfg_original))
        cfg_work = _normalize_dns_root(cfg_work)

        def restore_raw_snapshot() -> None:
            if existed_before:
                XRAY_DNS_CONF.parent.mkdir(parents=True, exist_ok=True)
                tmp = XRAY_DNS_CONF.parent / f".{XRAY_DNS_CONF.name}.rollback.{uuid.uuid4().hex}.tmp"
                tmp.write_bytes(raw_snapshot or b"")
                os.chmod(tmp, raw_mode if raw_mode is not None else 0o600)
                os.replace(tmp, XRAY_DNS_CONF)
                if raw_mode is not None:
                    os.chmod(XRAY_DNS_CONF, raw_mode)
                else:
                    _chmod_600(XRAY_DNS_CONF)
            else:
                try:
                    XRAY_DNS_CONF.unlink()
                except FileNotFoundError:
                    pass

        try:
            ok_mut, msg_mut = mutator(cfg_work)
            if not ok_mut:
                return False, str(msg_mut)

            _write_json_atomic(XRAY_DNS_CONF, cfg_work)
            if not _restart_and_wait("xray", timeout_sec=DNS_RESTART_TIMEOUT_SEC):
                restore_raw_snapshot()
                _restart_and_wait("xray", timeout_sec=DNS_ROLLBACK_RESTART_TIMEOUT_SEC)
                return False, "xray tidak aktif setelah update DNS (rollback)."
            return True, str(msg_mut)
        except Exception as exc:
            try:
                restore_raw_snapshot()
                _restart_and_wait("xray", timeout_sec=DNS_ROLLBACK_RESTART_TIMEOUT_SEC)
            except Exception:
                pass
            return False, f"Gagal update DNS: {exc}"


def _dns_set_primary(cfg: dict[str, Any], value: str) -> tuple[bool, str]:
    val = str(value or "").strip()
    if not val:
        return False, "Primary DNS tidak boleh kosong."
    if not _is_valid_dns_server_value(val):
        return False, "Primary DNS tidak valid. Gunakan IP/FQDN/URI DNS yang valid."
    _dns_set_server_idx(cfg, 0, val)
    return True, f"Primary DNS di-set ke {val}."


def _dns_set_secondary(cfg: dict[str, Any], value: str) -> tuple[bool, str]:
    val = str(value or "").strip()
    if not val:
        return False, "Secondary DNS tidak boleh kosong."
    if not _is_valid_dns_server_value(val):
        return False, "Secondary DNS tidak valid. Gunakan IP/FQDN/URI DNS yang valid."
    servers = _dns_servers_list(cfg)
    if len(servers) == 0:
        _dns_set_server_idx(cfg, 0, "1.1.1.1")
    _dns_set_server_idx(cfg, 1, val)
    return True, f"Secondary DNS di-set ke {val}."


def _dns_set_query_strategy(cfg: dict[str, Any], strategy: str) -> tuple[bool, str]:
    val = str(strategy or "").strip()
    dns_obj = cfg.get("dns")
    assert isinstance(dns_obj, dict)
    if val.lower() in {"default", "clear", "none", "unset", "reset", "off"}:
        dns_obj.pop("queryStrategy", None)
        return True, "Query strategy dikembalikan ke default."

    canonical = next((item for item in DNS_QUERY_STRATEGY_ALLOWED if item.lower() == val.lower()), "")
    if canonical not in DNS_QUERY_STRATEGY_ALLOWED:
        choices = ", ".join(sorted(DNS_QUERY_STRATEGY_ALLOWED))
        return False, f"Query strategy invalid. Pilihan: {choices}, atau default untuk reset."
    dns_obj["queryStrategy"] = canonical
    return True, f"Query strategy di-set ke {canonical}."


def _dns_toggle_cache(cfg: dict[str, Any]) -> tuple[bool, str]:
    dns_obj = cfg.get("dns")
    assert isinstance(dns_obj, dict)
    current = bool(dns_obj.get("disableCache"))
    if current:
        dns_obj.pop("disableCache", None)
        return True, "DNS cache sekarang: DEFAULT."
    dns_obj["disableCache"] = True
    # disableCache=true means cache OFF.
    return True, "DNS cache sekarang: OFF."


def _build_links(proto: str, username: str, cred: str, domain: str, tcp_tls_host: str) -> dict[str, str]:
    public_paths = {
        "vless": {"ws": "/vless-ws", "httpupgrade": "/vless-hup", "xhttp": "/vless-xhttp", "xhttp3": "/vless-xhttp3", "grpc": "vless-grpc"},
        "vmess": {"ws": "/vmess-ws", "httpupgrade": "/vmess-hup", "xhttp": "/vmess-xhttp", "grpc": "vmess-grpc"},
        "trojan": {"ws": "/trojan-ws", "httpupgrade": "/trojan-hup", "xhttp": "/trojan-xhttp", "grpc": "trojan-grpc"},
    }
    tcp_tls_protocols = {"vless", "vmess", "trojan"}

    def vless_link(net: str, val: str) -> str:
        if net == "xhttp3":
            full = _build_vless_xhttp3_link(domain, cred, username, proto)
            if full:
                return full
        q = {"encryption": "none", "security": "tls", "type": net, "sni": domain}
        if net in {"ws", "httpupgrade", "xhttp", "xhttp3"}:
            q["path"] = val or "/"
        if net == "xhttp3":
            q["type"] = "xhttp"
            q["alpn"] = "h3"
        elif net == "grpc" and val:
            q["serviceName"] = val
        host = tcp_tls_host if net == "tcp" else domain
        return f"vless://{cred}@{host}:443?{urllib.parse.urlencode(q)}#{urllib.parse.quote(username + '@' + proto)}"

    def trojan_link(net: str, val: str) -> str:
        q = {"security": "tls", "type": net, "sni": domain}
        if net in {"ws", "httpupgrade", "xhttp"}:
            q["path"] = val or "/"
        elif net == "grpc" and val:
            q["serviceName"] = val
        host = tcp_tls_host if net == "tcp" else domain
        return f"trojan://{cred}@{host}:443?{urllib.parse.urlencode(q)}#{urllib.parse.quote(username + '@' + proto)}"

    def vmess_link(net: str, val: str) -> str:
        obj = {
            "v": "2",
            "ps": username + "@" + proto,
            "add": domain,
            "port": "443",
            "id": cred,
            "aid": "0",
            "net": net,
            "type": "none",
            "host": domain,
            "tls": "tls",
            "sni": domain,
        }
        if net in {"ws", "httpupgrade", "xhttp"}:
            obj["path"] = val or "/"
        elif net == "grpc":
            obj["path"] = val or ""
            obj["type"] = "gun"
        raw = json.dumps(obj, separators=(",", ":"))
        return "vmess://" + base64.b64encode(raw.encode()).decode()

    links: dict[str, str] = {}
    p = public_paths.get(proto, {})
    nets = ["ws", "httpupgrade", "grpc"]
    if proto in tcp_tls_protocols:
        nets = ["tcp"] + nets
    nets = [net for net in nets if net != "grpc"] + ["xhttp", "grpc"]
    if proto == "vless":
        nets = [net for net in nets if net != "grpc"] + ["xhttp3", "grpc"]
    for net in nets:
        v = p.get(net, "")
        if proto == "vless":
            links[net] = vless_link(net, v)
        elif proto == "vmess":
            links[net] = vmess_link(net, v)
        else:
            links[net] = trojan_link(net, v)
    return links


def _build_account_text(
    proto: str,
    username: str,
    credential: str,
    domain: str,
    ip: str,
    quota_bytes: int,
    created_at: str,
    expired_at: str,
    days: int,
    ip_enabled: bool,
    ip_limit: int,
    speed_enabled: bool,
    speed_down: float,
    speed_up: float,
    portal_token: str,
) -> str:
    ok_ip, public_ip = _get_public_ipv4()
    ip = (public_ip if ok_ip else str(ip or "").strip() or _detect_public_ipv4() or "-").strip() or "-"
    tcp_tls_protocols = {"vless", "vmess", "trojan"}
    tcp_tls_host = domain
    links = _build_links(proto, username, credential, domain, tcp_tls_host)
    isp, country = _geo_lookup(ip)
    proto_disp = _proto_display_label(proto)
    portal_url = _account_portal_url(portal_token)
    public_paths = {
        "vless": {"ws": "/vless-ws", "httpupgrade": "/vless-hup", "xhttp": "/vless-xhttp", "xhttp3": "/vless-xhttp3", "grpc": "vless-grpc"},
        "vmess": {"ws": "/vmess-ws", "httpupgrade": "/vmess-hup", "xhttp": "/vmess-xhttp", "grpc": "vmess-grpc"},
        "trojan": {"ws": "/trojan-ws", "httpupgrade": "/trojan-hup", "xhttp": "/trojan-xhttp", "grpc": "trojan-grpc"},
    }
    public_proto = public_paths.get(proto, {})
    ws_path = public_proto.get("ws", "") or "/"
    ws_path_alt = _path_alt_placeholder(ws_path)
    hup_path = public_proto.get("httpupgrade", "") or "/"
    hup_path_alt = _path_alt_placeholder(hup_path)
    xhttp_path = public_proto.get("xhttp", "") or "/"
    xhttp_path_alt = _path_alt_placeholder(xhttp_path)
    xhttp3_path = public_proto.get("xhttp3", "") or "-"
    grpc_service = public_proto.get("grpc", "") or "-"
    grpc_service_alt = _service_alt_placeholder(grpc_service)
    created_disp = _normalize_created_display(created_at, date_only=True)
    running_labels = [
        f"{proto_disp} WS",
        f"{proto_disp} HUP",
        f"{proto_disp} XHTTP",
        f"{proto_disp} gRPC",
        f"{proto_disp} Path WS",
        f"{proto_disp} Path WS Alt",
        f"{proto_disp} Path HUP",
        f"{proto_disp} Path HUP Alt",
        f"{proto_disp} Path XHTTP",
        f"{proto_disp} Path XHTTP Alt",
        f"{proto_disp} Path Service",
        f"{proto_disp} Path Service Alt",
    ]
    if proto == "vless":
        running_labels.append(f"{proto_disp} Path XHTTP/3")
    if proto in tcp_tls_protocols:
        running_labels.append(f"{proto_disp} TCP+TLS Port")
    running_label_width = max(len(label) for label in running_labels)

    def section_line(label: str, value: str) -> str:
        return f"  {label:<{running_label_width}} : {value}"

    def append_link_block(lines: list[str], label: str, value: str) -> None:
        lines.append(f"    {label:<12}:")
        lines.append(str(value or "-"))

    lines = [
        "=== XRAY ACCOUNT INFO ===",
        f"  Domain      : {domain}",
        f"  IP          : {ip}",
        f"  ISP         : {isp}",
        f"  Country     : {country}",
        f"  Username    : {username}",
        f"  Protocol    : {proto}",
    ]
    if proto in {"vless", "vmess"}:
        lines.append(f"  UUID        : {credential}")
    else:
        lines.append(f"  Password    : {credential}")

    lines.extend(
        [
            f"  Quota Limit : {_fmt_quota_gb_from_bytes(max(0, quota_bytes))} GB",
            f"  Expired     : {max(0, days)} days",
            f"  Valid Until : {expired_at}",
            f"  Created     : {created_disp}",
            f"  IP Limit    : {'ON' if ip_enabled else 'OFF'}" + (f" ({ip_limit})" if ip_enabled and ip_limit > 0 else ""),
        ]
    )

    if speed_enabled and speed_down > 0 and speed_up > 0:
        lines.append(f"  Speed Limit : ON (DOWN {_fmt_number(speed_down)} Mbps | UP {_fmt_number(speed_up)} Mbps)")
    else:
        lines.append("  Speed Limit : OFF")
    lines.append(f"  Portal Info : {portal_url}")

    lines.extend(
        [
            "",
            "=== RUNNING ON PORT & PATH ===",
            section_line(f"{proto_disp} WS", _edge_runtime_ws_ports_label()),
            section_line(f"{proto_disp} HUP", _edge_runtime_ws_ports_label()),
        ]
    )
    lines.append(section_line(f"{proto_disp} XHTTP", _edge_runtime_ws_ports_label()))
    lines.extend(
        [
            section_line(f"{proto_disp} gRPC", _edge_runtime_ws_ports_label()),
        ]
    )
    if proto in tcp_tls_protocols:
        lines.append(section_line(f"{proto_disp} TCP+TLS Port", _edge_runtime_ws_ports_label()))
    lines.append(section_line("Alt Port SSL/TLS", _edge_runtime_alt_tls_ports_label()))
    lines.append(section_line("Alt Port HTTP", _edge_runtime_alt_http_ports_label()))
    lines.extend(
        [
            section_line(f"{proto_disp} Path WS", ws_path),
            section_line(f"{proto_disp} Path WS Alt", ws_path_alt),
            section_line(f"{proto_disp} Path HUP", hup_path),
            section_line(f"{proto_disp} Path HUP Alt", hup_path_alt),
            section_line(f"{proto_disp} Path XHTTP", xhttp_path),
            section_line(f"{proto_disp} Path XHTTP Alt", xhttp_path_alt),
            "",
        ]
    )
    if proto == "vless":
        lines.append(section_line(f"{proto_disp} Path XHTTP/3", xhttp3_path))
    lines.extend(
        [
            section_line(f"{proto_disp} Path Service", grpc_service),
            section_line(f"{proto_disp} Path Service Alt", grpc_service_alt),
            "",
            "=== LINKS IMPORT ===",
        ]
    )
    if "tcp" in links:
        append_link_block(lines, "TCP+TLS", links.get("tcp", "-"))
        lines.append("")
    append_link_block(lines, "WebSocket", links.get("ws", "-"))
    lines.append("")
    append_link_block(lines, "HTTPUpgrade", links.get("httpupgrade", "-"))
    lines.append("")
    if "xhttp" in links:
        append_link_block(lines, "XHTTP", links.get("xhttp", "-"))
        lines.append("")
    if "xhttp3" in links:
        append_link_block(lines, "VLESS XHTTP/3 (UDP/QUIC)", links.get("xhttp3", "-"))
        lines.append("")
    append_link_block(lines, "gRPC", links.get("grpc", "-"))
    lines.append("")
    return "\n".join(lines)


def _read_account_fields(path: Path) -> dict[str, str]:
    fields: dict[str, str] = {}
    if not path.exists():
        return fields
    try:
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if ":" not in raw:
                continue
            k, v = raw.split(":", 1)
            fields[k.strip()] = v.strip()
    except Exception:
        return {}
    return fields


def _find_credential_in_inbounds(proto: str, username: str) -> str:
    email = _email(proto, username)
    ok, payload = _read_json(XRAY_INBOUNDS_CONF)
    if not ok or not isinstance(payload, dict):
        return ""
    inbounds = payload.get("inbounds", [])
    if not isinstance(inbounds, list):
        return ""
    for ib in inbounds:
        if not _inbound_matches_proto(ib, proto):
            continue
        clients = (ib.get("settings") or {}).get("clients")
        if not isinstance(clients, list):
            continue
        for c in clients:
            if not isinstance(c, dict):
                continue
            if str(c.get("email") or "") != email:
                continue
            if proto == "trojan":
                return str(c.get("password") or "").strip()
            return str(c.get("id") or "").strip()
    return ""


def _xray_reset_client_credential(proto: str, username: str, credential: str) -> tuple[bool, str]:
    if not XRAY_INBOUNDS_CONF.exists():
        return False, f"Config tidak ditemukan: {XRAY_INBOUNDS_CONF}"

    email = _email(proto, username)
    with file_lock(ROUTING_LOCK_FILE):
        ok, payload = _read_json(XRAY_INBOUNDS_CONF)
        if not ok:
            return False, str(payload)
        if not isinstance(payload, dict):
            return False, "Format inbounds tidak valid"

        original = json.loads(json.dumps(payload))
        inbounds = payload.get("inbounds")
        if not isinstance(inbounds, list):
            return False, "Format inbounds tidak valid: inbounds bukan list"

        updated = 0
        for ib in inbounds:
            if not isinstance(ib, dict):
                continue
            if not _inbound_matches_proto(ib, proto):
                continue
            settings = ib.get("settings") or {}
            clients = settings.get("clients")
            if not isinstance(clients, list):
                continue
            for client in clients:
                if not isinstance(client, dict):
                    continue
                if str(client.get("email") or "") != email:
                    continue
                if proto == "trojan":
                    client["password"] = credential
                    client.pop("id", None)
                else:
                    client["id"] = credential
                    client.pop("password", None)
                    if proto == "vmess":
                        client["alterId"] = int(client.get("alterId") or 0)
                updated += 1

        if updated == 0:
            return False, f"User tidak ditemukan di inbounds: {email}"

        try:
            _write_json_atomic(XRAY_INBOUNDS_CONF, payload)
            if not _restart_and_wait("xray", timeout_sec=20):
                _write_json_atomic(XRAY_INBOUNDS_CONF, original)
                _restart_and_wait("xray", timeout_sec=20)
                return False, "xray tidak aktif setelah reset credential (rollback)."
        except Exception as exc:
            try:
                _write_json_atomic(XRAY_INBOUNDS_CONF, original)
                _restart_and_wait("xray", timeout_sec=20)
            except Exception:
                pass
            return False, f"Gagal update inbounds saat reset credential: {exc}"

    return True, "ok"


def _write_account_artifacts(
    proto: str,
    username: str,
    credential: str,
    quota_bytes: int,
    days: int,
    ip_enabled: bool,
    ip_limit: int,
    speed_enabled: bool,
    speed_down: float,
    speed_up: float,
) -> tuple[Path, Path]:
    _ensure_runtime_dirs()

    created_dt = _local_now()
    created_date = created_dt.date()
    expired_date = created_date + timedelta(days=max(1, int(days)))
    created_at = created_dt.strftime("%Y-%m-%d %H:%M")
    expired_at = expired_date.strftime("%Y-%m-%d")

    domain = _detect_domain()
    ip = _detect_public_ipv4()

    account_file = ACCOUNT_ROOT / proto / f"{username}@{proto}.txt"
    quota_file = QUOTA_ROOT / proto / f"{username}@{proto}.json"
    portal_token = _portal_ensure_token({}, state_path=quota_file)

    account_text = _build_account_text(
        proto=proto,
        username=username,
        credential=credential,
        domain=domain,
        ip=ip,
        quota_bytes=int(max(0, quota_bytes)),
        created_at=created_at,
        expired_at=expired_at,
        days=max(0, int(days)),
        ip_enabled=bool(ip_enabled),
        ip_limit=max(0, int(ip_limit)) if ip_enabled else 0,
        speed_enabled=bool(speed_enabled),
        speed_down=float(speed_down) if speed_enabled else 0.0,
        speed_up=float(speed_up) if speed_enabled else 0.0,
        portal_token=portal_token,
    )

    quota_payload: dict[str, Any] = {
        "username": _email(proto, username),
        "protocol": proto,
        "quota_limit": int(max(0, quota_bytes)),
        "quota_unit": "binary",
        "quota_used": 0,
        "portal_token": portal_token,
        "created_at": created_at,
        "expired_at": expired_at,
        "status": {
            "manual_block": False,
            "quota_exhausted": False,
            "ip_limit_enabled": bool(ip_enabled),
            "ip_limit": int(max(0, ip_limit)) if ip_enabled else 0,
            "speed_limit_enabled": bool(speed_enabled),
            "speed_down_mbit": float(speed_down) if speed_enabled else 0.0,
            "speed_up_mbit": float(speed_up) if speed_enabled else 0.0,
            "ip_limit_locked": False,
            "lock_reason": "",
            "locked_at": "",
        },
    }

    _write_text_atomic(account_file, account_text)
    if proto == "vless":
        xray_client_cfg = _build_vless_xhttp3_client_config(domain, credential, username, proto)
        if xray_client_cfg:
            _write_json_atomic(account_file.with_suffix(".xray.json"), xray_client_cfg)
    _write_json_atomic(quota_file, quota_payload)
    _chmod_600(account_file)
    _chmod_600(quota_file)
    return account_file, quota_file


def _refresh_account_info_for_user(proto: str, username: str, domain: str | None = None, ip: str | None = None) -> tuple[bool, str]:
    if proto not in USER_PROTOCOLS:
        return False, f"Proto tidak valid: {proto}"
    if proto == SSH_PROTOCOL:
        if not _is_valid_ssh_username(username):
            return False, "Username SSH tidak valid"
        return _ssh_refresh_account_info(username)
    if not _is_valid_username(username):
        return False, "Username tidak valid"

    _ensure_runtime_dirs()

    account_target = _resolve_existing(_account_candidates(proto, username))
    quota_target = _resolve_existing(_quota_candidates(proto, username))

    if account_target is None:
        account_target = ACCOUNT_ROOT / proto / f"{username}@{proto}.txt"

    account_fields = _read_account_fields(account_target)

    quota_data: dict[str, Any] = {}
    if quota_target is not None:
        ok, payload = _read_json(quota_target)
        if ok and isinstance(payload, dict):
            quota_data = payload

    status = quota_data.get("status") if isinstance(quota_data.get("status"), dict) else {}

    quota_limit = _to_int(quota_data.get("quota_limit"), 0)
    created_at = _normalize_created_display(
        quota_data.get("created_at") or account_fields.get("Created") or "",
        date_only=False,
    )

    expired_at = str(quota_data.get("expired_at") or account_fields.get("Valid Until") or "").strip()[:10]
    if not expired_at:
        expired_at = "-"

    d_expired = _parse_date_only(expired_at)
    if d_expired:
        days = max(0, (d_expired - _local_today()).days)
    else:
        days = 0

    ip_enabled = bool(status.get("ip_limit_enabled"))
    ip_limit = _to_int(status.get("ip_limit"), 0) if ip_enabled else 0

    speed_enabled = bool(status.get("speed_limit_enabled"))
    speed_down = _to_float(status.get("speed_down_mbit"), 0.0)
    speed_up = _to_float(status.get("speed_up_mbit"), 0.0)
    if speed_down <= 0 or speed_up <= 0:
        speed_enabled = False
        speed_down = 0.0
        speed_up = 0.0

    credential = _find_credential_in_inbounds(proto, username)
    if not credential:
        if proto == "trojan":
            credential = account_fields.get("Password", "").strip()
        else:
            credential = account_fields.get("UUID", "").strip()
    if not credential:
        return False, f"Credential tidak ditemukan untuk {username}@{proto}"

    domain_eff = str(domain or "").strip() or _detect_domain()
    ip_eff = str(ip or "").strip() or account_fields.get("IP", "").strip() or _detect_public_ipv4()
    portal_token = _portal_ensure_token(quota_data, state_path=quota_target)
    quota_data["portal_token"] = portal_token

    content = _build_account_text(
        proto=proto,
        username=username,
        credential=credential,
        domain=domain_eff,
        ip=ip_eff,
        quota_bytes=quota_limit,
        created_at=created_at,
        expired_at=expired_at,
        days=days,
        ip_enabled=ip_enabled,
        ip_limit=ip_limit,
        speed_enabled=speed_enabled,
        speed_down=speed_down,
        speed_up=speed_up,
        portal_token=portal_token,
    )

    _write_text_atomic(account_target, content)
    if proto == "vless":
        xray_client_cfg = _build_vless_xhttp3_client_config(domain_eff, credential, username, proto)
        if xray_client_cfg:
            _write_json_atomic(account_target.with_suffix(".xray.json"), xray_client_cfg)
    _chmod_600(account_target)
    if quota_target is not None:
        _save_quota(quota_target, quota_data)
    return True, "ok"


def _restore_account_info_snapshots(snapshots: dict[Path, dict[str, Any]]) -> list[str]:
    notes: list[str] = []
    for path, snapshot in snapshots.items():
        ok_restore, restore_msg = _restore_optional_file(path, snapshot)
        if not ok_restore:
            notes.append(restore_msg)
    return notes


@_user_data_mutation_locked
def _refresh_all_account_info(domain: str | None = None, ip: str | None = None) -> tuple[int, int, int]:
    _ensure_runtime_dirs()
    domain_eff = str(domain or "").strip() or _detect_domain()
    ip_eff = str(ip or "").strip() or _detect_public_ipv4()

    updated = 0
    failed = 0
    skipped = 0
    snapshots: dict[Path, dict[str, Any]] = {}

    for proto in USER_PROTOCOLS:
        d = ACCOUNT_ROOT / proto
        if not d.exists():
            continue
        selected: dict[str, Path] = {}
        selected_has_at: dict[str, bool] = {}
        for p in sorted(d.glob("*.txt")):
            username = _extract_username_from_file_name(p, proto)
            if not username:
                continue
            has_at = "@" in p.stem
            prev = selected.get(username)
            if prev is not None:
                if has_at and not selected_has_at.get(username, False):
                    selected[username] = p
                    selected_has_at[username] = True
                continue
            selected[username] = p
            selected_has_at[username] = has_at

        for username in sorted(selected.keys()):
            target = selected[username]
            if proto == SSH_PROTOCOL:
                quota_target = _resolve_existing(_quota_candidates(proto, username))
                if quota_target is None and not _linux_user_exists(username):
                    skipped += 1
                    continue
            if target not in snapshots:
                snapshots[target] = _snapshot_optional_file(target)
            ok, _ = _refresh_account_info_for_user(proto, username, domain=domain_eff, ip=ip_eff)
            if ok:
                updated += 1
            else:
                failed += 1

    if failed > 0:
        restore_notes = _restore_account_info_snapshots(snapshots)
        updated = 0
        if restore_notes:
            failed += len(restore_notes)
    return updated, failed, skipped


def _account_refresh_outcome(
    title: str,
    lines: list[str],
    *,
    updated: int,
    failed: int,
    partial_failure_hint: str,
) -> tuple[bool, str, str]:
    message_lines = list(lines)
    message_lines.append(f"- Refresh account info: updated={updated}, failed={failed}")
    if failed > 0:
        message_lines.append(partial_failure_hint)
        return False, title, "\n".join(message_lines)
    return True, title, "\n".join(message_lines)


def _account_info_has_display_mismatch(text: str) -> bool:
    fields: dict[str, str] = {}
    for raw in str(text or "").splitlines():
        if ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        fields[key.strip()] = value.strip()

    valid_until = str(fields.get("Valid Until") or "").strip()[:10]
    expired_raw = str(fields.get("Expired") or "").strip()
    if not valid_until or not expired_raw:
        return False

    d_expired = _parse_date_only(valid_until)
    if d_expired is None:
        return False

    match = re.search(r"(\d+)", expired_raw)
    if match is None:
        return False

    try:
        shown_days = max(0, int(match.group(1)))
    except Exception:
        return False

    expected_days = max(0, (d_expired - _local_today()).days)
    return shown_days != expected_days


def _account_info_needs_compat_refresh() -> bool:
    _ensure_runtime_dirs()
    for proto in USER_PROTOCOLS:
        d = ACCOUNT_ROOT / proto
        if not d.exists():
            continue
        for p in sorted(d.glob("*.txt")):
            stem = p.stem
            expected_suffix = f"@{proto}"
            is_noncanonical_name = not stem.endswith(expected_suffix)

            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                return True

            if _account_info_has_display_mismatch(text):
                return True

            if proto == SSH_PROTOCOL:
                if is_noncanonical_name:
                    return True
                continue

            has_links_block = bool(re.search(r"(?m)^Links Import:\s*$", text))
            has_grpc_line = bool(re.search(r"(?m)^\s*gRPC\s*:", text))
            if is_noncanonical_name or not has_links_block or not has_grpc_line:
                return True
    return False


@_user_data_mutation_locked
def op_account_info_compat_refresh_if_needed() -> tuple[bool, str, str]:
    title = "User Management - Account Info Compat Refresh"
    if not _account_info_needs_compat_refresh():
        return True, title, "Skip: format account info sudah kompatibel."

    domain = _detect_domain()
    ip_override: str | None = None
    ok_ip, ip_or_err = _get_public_ipv4()
    if ok_ip:
        ip_override = str(ip_or_err)

    updated, failed, skipped = _refresh_all_account_info(domain=domain, ip=ip_override)
    msg = f"Compat refresh selesai: updated={updated}, failed={failed}"
    if skipped > 0:
        msg += f", skipped={skipped}"
    if failed > 0:
        return False, title, msg
    return True, title, msg


def _speed_policy_file_path(proto: str, username: str) -> Path:
    return SPEED_POLICY_ROOT / proto / f"{username}@{proto}.json"


def _speed_policy_exists(proto: str, username: str) -> bool:
    return _speed_policy_file_path(proto, username).exists()


def _speed_policy_remove(proto: str, username: str) -> None:
    p = _speed_policy_file_path(proto, username)
    with file_lock(SPEED_POLICY_LOCK_FILE):
        try:
            if p.exists():
                p.unlink()
        except Exception:
            pass


def _speed_policy_remove_checked(proto: str, username: str) -> tuple[bool, str]:
    p = _speed_policy_file_path(proto, username)
    with file_lock(SPEED_POLICY_LOCK_FILE):
        if not p.exists():
            return True, "ok"
        try:
            p.unlink()
        except Exception as exc:
            return False, f"Gagal hapus speed policy: {exc}"
        if p.exists():
            return False, f"Speed policy masih ada setelah unlink: {p}"
    return True, "ok"


def _valid_mark(v: Any) -> bool:
    m = _to_int(v, -1)
    return SPEED_MARK_MIN <= m <= SPEED_MARK_MAX


def _collect_used_marks(exclude_path: Path | None = None) -> set[int]:
    used: set[int] = set()
    for proto in PROTOCOLS:
        d = SPEED_POLICY_ROOT / proto
        if not d.exists():
            continue
        for p in d.glob("*.json"):
            if exclude_path is not None and p.resolve() == exclude_path.resolve():
                continue
            ok, payload = _read_json(p)
            if not ok or not isinstance(payload, dict):
                continue
            m = _to_int(payload.get("mark"), -1)
            if _valid_mark(m):
                used.add(m)
    return used


def _speed_policy_upsert(proto: str, username: str, down_mbit: float, up_mbit: float) -> tuple[bool, int | str]:
    down = _to_float(down_mbit, 0.0)
    up = _to_float(up_mbit, 0.0)
    if down <= 0 or up <= 0:
        return False, "Speed harus > 0"

    _ensure_runtime_dirs()

    email = _email(proto, username)
    target = _speed_policy_file_path(proto, username)

    with file_lock(SPEED_POLICY_LOCK_FILE):
        existing_mark = None
        if target.exists():
            ok, payload = _read_json(target)
            if ok and isinstance(payload, dict) and _valid_mark(payload.get("mark")):
                existing_mark = _to_int(payload.get("mark"), -1)

        used = _collect_used_marks(exclude_path=target)

        mark: int
        if existing_mark is not None and existing_mark not in used:
            mark = existing_mark
        else:
            size = SPEED_MARK_MAX - SPEED_MARK_MIN + 1
            seed = zlib.crc32(email.encode("utf-8")) & 0xFFFFFFFF
            start = SPEED_MARK_MIN + (seed % size)
            mark = -1
            for i in range(size):
                cand = SPEED_MARK_MIN + ((start - SPEED_MARK_MIN + i) % size)
                if cand not in used:
                    mark = cand
                    break
            if mark < 0:
                return False, "Range mark speed policy habis"

        payload = {
            "enabled": True,
            "username": email,
            "protocol": proto,
            "mark": mark,
            "down_mbit": round(down, 3),
            "up_mbit": round(up, 3),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        _write_json_atomic(target, payload)
        _chmod_600(target)

    return True, mark


def _list_speed_mark_users() -> dict[int, list[str]]:
    mark_users: dict[int, set[str]] = {}
    for proto in PROTOCOLS:
        d = SPEED_POLICY_ROOT / proto
        if not d.exists():
            continue
        for p in sorted(d.glob("*.json")):
            ok, payload = _read_json(p)
            if not ok or not isinstance(payload, dict):
                continue
            enabled = payload.get("enabled", True)
            enabled_bool = bool(enabled) if isinstance(enabled, bool) else str(enabled).strip().lower() in {
                "1",
                "true",
                "yes",
                "on",
            }
            if not enabled_bool:
                continue
            mark = _to_int(payload.get("mark"), -1)
            if not _valid_mark(mark):
                continue
            down = _to_float(payload.get("down_mbit"), 0.0)
            up = _to_float(payload.get("up_mbit"), 0.0)
            if down <= 0 or up <= 0:
                continue
            email = str(payload.get("username") or payload.get("email") or p.stem).strip()
            if not email:
                continue
            mark_users.setdefault(mark, set()).add(email)
    return {k: sorted(v) for k, v in sorted(mark_users.items())}


def _speed_policy_sync_xray() -> tuple[bool, str]:
    if not XRAY_OUTBOUNDS_CONF.exists() or not XRAY_ROUTING_CONF.exists():
        return False, "File outbounds/routing tidak ditemukan"

    with file_lock(ROUTING_LOCK_FILE):
        ok_out, out_cfg = _read_json(XRAY_OUTBOUNDS_CONF)
        ok_rt, rt_cfg = _read_json(XRAY_ROUTING_CONF)
        if not ok_out:
            return False, str(out_cfg)
        if not ok_rt:
            return False, str(rt_cfg)
        if not isinstance(out_cfg, dict) or not isinstance(rt_cfg, dict):
            return False, "Format config Xray tidak valid"

        out_original = json.loads(json.dumps(out_cfg))
        rt_original = json.loads(json.dumps(rt_cfg))

        outbounds = out_cfg.get("outbounds")
        if not isinstance(outbounds, list):
            return False, "outbounds bukan list"

        routing = rt_cfg.get("routing") or {}
        rules = routing.get("rules") if isinstance(routing, dict) else None
        if not isinstance(rules, list):
            return False, "routing.rules bukan list"

        mark_users = _list_speed_mark_users()

        out_by_tag: dict[str, dict[str, Any]] = {}
        for out in outbounds:
            if isinstance(out, dict):
                tag = str(out.get("tag") or "").strip()
                if tag:
                    out_by_tag[tag] = out

        def is_default_rule(rule: Any) -> bool:
            if not isinstance(rule, dict):
                return False
            if rule.get("type") != "field":
                return False
            port = str(rule.get("port", "")).strip()
            if port not in {"1-65535", "0-65535"}:
                return False
            if rule.get("user") or rule.get("domain") or rule.get("ip") or rule.get("protocol"):
                return False
            return True

        default_rule = None
        for rule in rules:
            if is_default_rule(rule):
                default_rule = rule
                break

        base_selector: list[str] = []

        if isinstance(default_rule, dict):
            ot = str(default_rule.get("outboundTag") or "").strip()
            if ot:
                base_selector = [ot]

        if not base_selector:
            if "direct" in out_by_tag:
                base_selector = ["direct"]
            else:
                for tag in out_by_tag.keys():
                    if not tag.startswith(SPEED_OUTBOUND_TAG_PREFIX):
                        base_selector = [tag]
                        break

        if not base_selector:
            return False, "Outbound dasar untuk speed policy tidak ditemukan"

        effective_selector: list[str] = []
        seen: set[str] = set()
        for tag in base_selector:
            t = str(tag).strip()
            if not t or t in {"api", "blocked"} or t.startswith(SPEED_OUTBOUND_TAG_PREFIX):
                continue
            if t not in out_by_tag:
                continue
            if t in seen:
                continue
            seen.add(t)
            effective_selector.append(t)

        if not effective_selector:
            if "direct" in out_by_tag:
                effective_selector = ["direct"]
            else:
                for t in out_by_tag.keys():
                    if t in {"api", "blocked"} or t.startswith(SPEED_OUTBOUND_TAG_PREFIX):
                        continue
                    effective_selector = [t]
                    break

        if not effective_selector:
            return False, "Selector outbound dasar untuk speed policy kosong"

        def managed_user_override_set(marker: str, outbound: str) -> set[str]:
            result: set[str] = set()
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                if rule.get("type") != "field":
                    continue
                if str(rule.get("outboundTag") or "").strip() != outbound:
                    continue
                users = rule.get("user")
                if not isinstance(users, list) or "inboundTag" in rule:
                    continue
                if marker not in users:
                    continue
                for user in users:
                    if not isinstance(user, str):
                        continue
                    user = user.strip()
                    if not user or user == marker:
                        continue
                    result.add(user)
            return result

        selector_candidates: list[str] = []
        seen = set()
        for tag in list(effective_selector) + ["direct", "warp"]:
            t = str(tag).strip()
            if not t or t in {"api", "blocked"} or t.startswith(SPEED_OUTBOUND_TAG_PREFIX):
                continue
            if t not in out_by_tag:
                continue
            if t in seen:
                continue
            seen.add(t)
            selector_candidates.append(t)

        if not selector_candidates:
            return False, "Selector outbound kandidat speed policy kosong"

        direct_users = managed_user_override_set("dummy-direct-user", "direct")
        warp_users = managed_user_override_set("dummy-warp-user", "warp")

        def resolve_speed_base_tag(user: str) -> str:
            if user in direct_users:
                return "direct"
            if user in warp_users:
                return "warp"
            first_base = effective_selector[0] if effective_selector else ""
            return first_base or (selector_candidates[0] if selector_candidates else "")

        clean_outbounds: list[Any] = []
        for out in outbounds:
            if isinstance(out, dict):
                tag = str(out.get("tag") or "").strip()
                if tag.startswith(SPEED_OUTBOUND_TAG_PREFIX):
                    continue
            clean_outbounds.append(out)

        mark_out_tags: dict[int, dict[str, str]] = {}
        for mark in sorted(mark_users.keys()):
            per_mark: dict[str, str] = {}
            for base_tag in selector_candidates:
                src = out_by_tag.get(base_tag)
                if not isinstance(src, dict):
                    continue
                clone = json.loads(json.dumps(src))
                safe_base_tag = re.sub(r"[^A-Za-z0-9_.-]", "-", base_tag)
                clone_tag = f"{SPEED_OUTBOUND_TAG_PREFIX}{mark}-{safe_base_tag}"
                clone["tag"] = clone_tag
                ss = clone.get("streamSettings")
                if not isinstance(ss, dict):
                    ss = {}
                sock = ss.get("sockopt")
                if not isinstance(sock, dict):
                    sock = {}
                sock["mark"] = int(mark)
                ss["sockopt"] = sock
                clone["streamSettings"] = ss
                clean_outbounds.append(clone)
                per_mark[base_tag] = clone_tag
            mark_out_tags[mark] = per_mark

        out_cfg["outbounds"] = clean_outbounds

        def is_protected_rule(rule: Any) -> bool:
            if not isinstance(rule, dict):
                return False
            if rule.get("type") != "field":
                return False
            ot = str(rule.get("outboundTag") or "").strip()
            return ot in {"api", "blocked"}

        kept_rules: list[Any] = []
        for rule in rules:
            if not isinstance(rule, dict):
                kept_rules.append(rule)
                continue
            if rule.get("type") != "field":
                kept_rules.append(rule)
                continue
            users = rule.get("user")
            ot = str(rule.get("outboundTag") or "").strip()
            has_speed_marker = isinstance(users, list) and any(
                isinstance(u, str) and u.startswith(SPEED_RULE_MARKER_PREFIX) for u in users
            )
            if has_speed_marker and ot.startswith(SPEED_OUTBOUND_TAG_PREFIX):
                continue
            kept_rules.append(rule)

        insert_idx = len(kept_rules)
        for idx, rule in enumerate(kept_rules):
            if is_protected_rule(rule):
                continue
            insert_idx = idx
            break

        speed_rules: list[dict[str, Any]] = []
        for mark, users in sorted(mark_users.items()):
            grouped: dict[str, list[str]] = {}
            for user in users:
                base_tag = resolve_speed_base_tag(user)
                if not base_tag:
                    continue
                ot = mark_out_tags.get(mark, {}).get(base_tag, "")
                if not ot:
                    continue
                grouped.setdefault(base_tag, []).append(user)
            for base_tag, grouped_users in sorted(grouped.items()):
                ot = mark_out_tags.get(mark, {}).get(base_tag, "")
                if not ot:
                    continue
                speed_rules.append({
                    "type": "field",
                    "user": [f"{SPEED_RULE_MARKER_PREFIX}{mark}-{re.sub(r'[^A-Za-z0-9_.-]', '-', base_tag)}"] + grouped_users,
                    "outboundTag": ot,
                })

        merged_rules = kept_rules[:insert_idx] + speed_rules + kept_rules[insert_idx:]
        routing["rules"] = merged_rules
        rt_cfg["routing"] = routing

        try:
            _write_json_atomic(XRAY_OUTBOUNDS_CONF, out_cfg)
            _write_json_atomic(XRAY_ROUTING_CONF, rt_cfg)
            if not _restart_and_wait("xray", timeout_sec=20):
                _write_json_atomic(XRAY_OUTBOUNDS_CONF, out_original)
                _write_json_atomic(XRAY_ROUTING_CONF, rt_original)
                _restart_and_wait("xray", timeout_sec=20)
                return False, "xray tidak aktif setelah sinkronisasi speed policy (rollback)."
        except Exception as exc:
            try:
                _write_json_atomic(XRAY_OUTBOUNDS_CONF, out_original)
                _write_json_atomic(XRAY_ROUTING_CONF, rt_original)
                _restart_and_wait("xray", timeout_sec=20)
            except Exception:
                pass
            return False, f"Gagal sinkronisasi speed policy: {exc}"

    return True, "ok"


def _speed_policy_apply_now() -> bool:
    if Path("/usr/local/bin/xray-speed").exists() and SPEED_CONFIG_FILE.exists():
        ok, _ = _run_cmd(["/usr/local/bin/xray-speed", "once", "--config", str(SPEED_CONFIG_FILE)], timeout=30)
        if ok:
            return True
    if _service_exists("xray-speed"):
        return _restart_and_wait("xray-speed", timeout_sec=20)
    return False


def _quota_sync_speed_policy_for_user(proto: str, username: str, quota_data: dict[str, Any]) -> tuple[bool, str]:
    status = quota_data.get("status") if isinstance(quota_data.get("status"), dict) else {}
    speed_on = bool(status.get("speed_limit_enabled"))
    speed_down = _to_float(status.get("speed_down_mbit"), 0.0)
    speed_up = _to_float(status.get("speed_up_mbit"), 0.0)

    if speed_on:
        if speed_down <= 0 or speed_up <= 0:
            return False, "Speed limit aktif tapi nilai speed_down/speed_up belum valid (>0)."
        ok_upsert, mark_or_err = _speed_policy_upsert(proto, username, speed_down, speed_up)
        if not ok_upsert:
            return False, f"Gagal menyimpan speed policy: {mark_or_err}"
        ok_sync, sync_msg = _speed_policy_sync_xray()
        if not ok_sync:
            return False, sync_msg
        if not _speed_policy_apply_now():
            return False, "Speed policy tersimpan, tetapi apply runtime gagal (xray-speed)."
        return True, f"Speed policy aktif (mark={mark_or_err})."

    removed = _speed_policy_exists(proto, username)
    if removed:
        ok_remove, remove_msg = _speed_policy_remove_checked(proto, username)
        if not ok_remove:
            return False, remove_msg
        ok_sync, sync_msg = _speed_policy_sync_xray()
        if not ok_sync:
            return False, sync_msg
        if not _speed_policy_apply_now():
            return False, "Speed policy dimatikan, tetapi apply runtime gagal (xray-speed)."
        return True, "ok"
    if not _speed_policy_apply_now():
        return False, "Speed policy runtime gagal di-refresh (xray-speed)."
    return True, "ok"


def _delete_account_artifacts(proto: str, username: str) -> None:
    for p in [
        ACCOUNT_ROOT / proto / f"{username}@{proto}.txt",
        ACCOUNT_ROOT / proto / f"{username}.txt",
        QUOTA_ROOT / proto / f"{username}@{proto}.json",
        QUOTA_ROOT / proto / f"{username}.json",
    ]:
        try:
            if p.exists():
                p.unlink()
        except Exception:
            pass


def _delete_account_artifacts_checked(proto: str, username: str) -> list[str]:
    notes: list[str] = []
    for p in [
        ACCOUNT_ROOT / proto / f"{username}@{proto}.txt",
        ACCOUNT_ROOT / proto / f"{username}.txt",
        QUOTA_ROOT / proto / f"{username}@{proto}.json",
        QUOTA_ROOT / proto / f"{username}.json",
    ]:
        exists_before = p.exists() or p.is_symlink()
        if not exists_before:
            continue
        try:
            p.unlink(missing_ok=True)
        except Exception as exc:
            notes.append(f"{p}: {exc}")
            continue
        if p.exists() or p.is_symlink():
            notes.append(f"{p}: masih ada setelah unlink")
    return notes


def _run_limit_ip_restart_if_present() -> tuple[bool, str]:
    for name in ("xray-limit-ip", "xray-limit"):
        if _service_exists(name):
            if _restart_and_wait(name, timeout_sec=15):
                return True, "ok"
            return False, f"Service {name} gagal restart/apply"
    return True, "skip"


def _xray_refresh_account_info_required(
    title: str,
    proto: str,
    username: str,
    success_msg: str,
) -> tuple[bool, str, str]:
    ok_refresh, refresh_msg = _refresh_account_info_for_user(proto, username)
    if ok_refresh:
        return True, title, success_msg
    return (
        False,
        title,
        (
            f"{success_msg}\n"
            f"- Refresh XRAY ACCOUNT INFO gagal: {refresh_msg}\n"
            f"- Perubahan runtime/metadata sudah diterapkan, tetapi file account belum sinkron"
        ),
    )


def _xray_cleanup_new_user_after_failure(proto: str, username: str) -> tuple[bool, str]:
    notes: list[str] = []

    ok_del, del_msg = _xray_delete_client(proto, username)
    if not ok_del and "tidak ditemukan" not in del_msg.lower():
        notes.append(f"cleanup inbounds: {del_msg}")

    cleanup_notes = _delete_account_artifacts_checked(proto, username)
    for note in cleanup_notes:
        notes.append(f"cleanup artefak: {note}")

    ok_remove, remove_msg = _speed_policy_remove_checked(proto, username)
    if not ok_remove:
        notes.append(f"cleanup speed policy file: {remove_msg}")
    ok_sync, sync_msg = _speed_policy_sync_xray()
    if not ok_sync:
        notes.append(f"cleanup speed policy: {sync_msg}")
    elif not _speed_policy_apply_now():
        notes.append("cleanup speed policy: apply runtime gagal (xray-speed)")

    if notes:
        return False, "; ".join(notes)
    return True, "ok"


def _restore_account_artifacts_from_snapshots(
    proto: str,
    username: str,
    *,
    account_snapshot: str | None,
    quota_snapshot: dict[str, Any] | None,
) -> list[str]:
    notes: list[str] = []
    account_path = ACCOUNT_ROOT / proto / f"{username}@{proto}.txt"
    quota_path = QUOTA_ROOT / proto / f"{username}@{proto}.json"

    if quota_snapshot is not None:
        try:
            _save_quota(quota_path, copy.deepcopy(quota_snapshot))
        except Exception as exc:
            notes.append(f"restore quota: {exc}")
    if account_snapshot is not None:
        try:
            _write_text_atomic(account_path, account_snapshot)
            _chmod_600(account_path)
        except Exception as exc:
            notes.append(f"restore account: {exc}")
    return notes


def _xray_apply_runtime_from_quota(
    proto: str,
    username: str,
    quota_data: dict[str, Any],
    *,
    ensure_client_credential: str = "",
    restore_markers: bool = False,
    restart_limit_ip: bool = False,
    sync_speed: bool = False,
) -> tuple[bool, str]:
    if ensure_client_credential and not _user_exists_in_inbounds(proto, username):
        ok_add, add_msg = _xray_add_client(proto, username, ensure_client_credential)
        if not ok_add and "sudah ada" not in add_msg.lower():
            return False, f"restore inbounds: {add_msg}"

    status = quota_data.get("status") if isinstance(quota_data.get("status"), dict) else {}
    if restore_markers:
        marker_states = (
            ("dummy-quota-user", bool(status.get("quota_exhausted"))),
            ("dummy-block-user", bool(status.get("manual_block"))),
            ("dummy-limit-user", bool(status.get("ip_limit_locked"))),
        )
        for marker, enabled in marker_states:
            ok_marker, marker_msg = _routing_set_user_in_marker(
                marker,
                _email(proto, username),
                "on" if enabled else "off",
                outbound_tag="blocked",
            )
            if not ok_marker:
                return False, f"routing {marker}: {marker_msg}"

    if restart_limit_ip:
        ok_restart, restart_msg = _run_limit_ip_restart_if_present()
        if not ok_restart:
            return False, restart_msg

    if sync_speed:
        ok_speed, speed_msg = _quota_sync_speed_policy_for_user(proto, username, quota_data)
        if not ok_speed:
            return False, speed_msg

    return True, "ok"


def _xray_apply_quota_update(
    title: str,
    proto: str,
    username: str,
    quota_path: Path,
    previous_payload: dict[str, Any],
    next_payload: dict[str, Any],
    success_msg: str,
    *,
    ensure_client_credential: str = "",
    restore_markers: bool = False,
    restart_limit_ip: bool = False,
    sync_speed: bool = False,
) -> tuple[bool, str, str]:
    _save_quota(quota_path, next_payload)

    ok_runtime, runtime_msg = _xray_apply_runtime_from_quota(
        proto,
        username,
        next_payload,
        ensure_client_credential=ensure_client_credential,
        restore_markers=restore_markers,
        restart_limit_ip=restart_limit_ip,
        sync_speed=sync_speed,
    )
    if not ok_runtime:
        rollback_notes: list[str] = []
        try:
            _save_quota(quota_path, previous_payload)
        except Exception as exc:
            rollback_notes.append(f"rollback quota: {exc}")
        else:
            ok_restore, restore_msg = _xray_apply_runtime_from_quota(
                proto,
                username,
                previous_payload,
                ensure_client_credential=ensure_client_credential,
                restore_markers=restore_markers,
                restart_limit_ip=restart_limit_ip,
                sync_speed=sync_speed,
            )
            if not ok_restore:
                rollback_notes.append(f"rollback runtime: {restore_msg}")
            ok_refresh, refresh_msg = _refresh_account_info_for_user(proto, username)
            if not ok_refresh:
                rollback_notes.append(f"rollback account-info: {refresh_msg}")

        detail = runtime_msg
        if rollback_notes:
            detail += " | " + " | ".join(rollback_notes)
        else:
            detail += " | state di-rollback"
        return False, title, detail

    ok_refresh, refresh_msg = _refresh_account_info_for_user(proto, username)
    if ok_refresh:
        return True, title, success_msg

    rollback_notes: list[str] = [f"refresh account-info: {refresh_msg}"]
    try:
        _save_quota(quota_path, previous_payload)
    except Exception as exc:
        rollback_notes.append(f"rollback quota: {exc}")
    else:
        ok_restore, restore_msg = _xray_apply_runtime_from_quota(
            proto,
            username,
            previous_payload,
            ensure_client_credential=ensure_client_credential,
            restore_markers=restore_markers,
            restart_limit_ip=restart_limit_ip,
            sync_speed=sync_speed,
        )
        if not ok_restore:
            rollback_notes.append(f"rollback runtime: {restore_msg}")
        ok_rb_refresh, rb_refresh_msg = _refresh_account_info_for_user(proto, username)
        if not ok_rb_refresh:
            rollback_notes.append(f"rollback account-info: {rb_refresh_msg}")

    return False, title, f"{success_msg} | " + " | ".join(rollback_notes)


def _xray_restore_deleted_user(
    proto: str,
    username: str,
    *,
    credential: str,
    account_snapshot: str | None,
    quota_snapshot: dict[str, Any] | None,
) -> tuple[bool, str]:
    notes = _restore_account_artifacts_from_snapshots(
        proto,
        username,
        account_snapshot=account_snapshot,
        quota_snapshot=quota_snapshot,
    )

    ok_runtime, runtime_msg = _xray_apply_runtime_from_quota(
        proto,
        username,
        quota_snapshot or {},
        ensure_client_credential=credential,
        restore_markers=True,
        restart_limit_ip=True,
        sync_speed=True,
    )
    if not ok_runtime:
        notes.append(f"restore runtime: {runtime_msg}")

    ok_refresh, refresh_msg = _refresh_account_info_for_user(proto, username)
    if not ok_refresh:
        notes.append(f"restore account-info: {refresh_msg}")

    if notes:
        return False, " | ".join(notes)
    return True, "ok"


@_user_data_mutation_locked
def op_user_add(
    proto: str,
    username: str,
    days: int,
    quota_gb: float,
    ip_enabled: bool,
    ip_limit: int,
    speed_enabled: bool,
    speed_down_mbit: float,
    speed_up_mbit: float,
    password: str = "",
) -> tuple[bool, str, str]:
    if proto not in USER_PROTOCOLS:
        return False, "User Management - Add User", f"Proto tidak valid: {proto}"
    if proto == SSH_PROTOCOL:
        if not _is_valid_ssh_username(username):
            return False, "User Management - Add User", "Username SSH tidak valid. Gunakan huruf kecil/angka/_/-."
    elif not _is_valid_username(username):
        return False, "User Management - Add User", "Username tidak valid."
    if days <= 0:
        return False, "User Management - Add User", "Masa aktif harus > 0 hari."
    if quota_gb <= 0:
        return False, "User Management - Add User", "Quota harus > 0 GB."
    if ip_enabled and ip_limit <= 0:
        return False, "User Management - Add User", "IP limit harus > 0 jika IP limit aktif."

    speed_on = bool(speed_enabled)
    down = _to_float(speed_down_mbit, 0.0)
    up = _to_float(speed_up_mbit, 0.0)
    if speed_on and (down <= 0 or up <= 0):
        return False, "User Management - Add User", "Speed limit aktif, tapi speed download/upload belum valid (>0)."

    exists, where = _username_exists_anywhere(username)
    if exists:
        return False, "User Management - Add User", f"Username sudah ada: {username} ({where})"

    if proto == SSH_PROTOCOL:
        raw_password = str(password or "")
        if not raw_password.strip():
            return False, "User Management - Add User", "Password SSH wajib diisi."
        if username.strip().lower() == raw_password.strip().lower():
            return False, "User Management - Add User", "Password SSH tidak boleh sama dengan username."

        expiry = (_local_today() + timedelta(days=max(1, int(days)))).strftime("%Y-%m-%d")
        created_at = _local_now().strftime("%Y-%m-%d %H:%M")
        quota_bytes = int(round(quota_gb * (1024**3)))
        quota_path = SSH_QUOTA_DIR / f"{username}@{SSH_PROTOCOL}.json"
        account_path = SSH_ACCOUNT_DIR / f"{username}@{SSH_PROTOCOL}.txt"

        ok_add_user, out_add_user = _run_cmd(["useradd", "-m", "-s", "/bin/bash", username], timeout=20)
        if not ok_add_user:
            return False, "User Management - Add User", f"Gagal membuat user Linux '{username}': {out_add_user}"

        ok_passwd, out_passwd = _run_cmd(
            ["bash", "-lc", 'printf "%s:%s\\n" "$0" "$1" | chpasswd', username, raw_password],
            timeout=20,
        )
        if not ok_passwd:
            return _ssh_add_user_rollback(
                username,
                None,
                account_path,
                raw_password=raw_password,
                error_prefix=f"Gagal set password user '{username}': {out_passwd}",
            )

        ok_expiry, out_expiry = _ssh_apply_linux_expiry(username, expiry)
        if not ok_expiry:
            return _ssh_add_user_rollback(
                username,
                None,
                account_path,
                raw_password=raw_password,
                error_prefix=f"Gagal set expiry user '{username}': {out_expiry}",
            )

        try:
            with file_lock(str(SSHWS_LOCK_FILE)):
                ok_state, quota_path_or_err, payload_or_err = _ssh_load_state(
                    username,
                    create_missing=True,
                    created_at=created_at,
                    expired_at=expiry,
                )
                if not ok_state:
                    raise RuntimeError(str(quota_path_or_err))
                quota_path = quota_path_or_err
                quota_payload = payload_or_err
                assert isinstance(quota_path, Path)
                assert isinstance(quota_payload, dict)

                quota_payload["quota_limit"] = quota_bytes
                quota_payload["quota_used"] = 0
                quota_payload["created_at"] = created_at
                quota_payload["expired_at"] = expiry
                status = quota_payload.get("status") if isinstance(quota_payload.get("status"), dict) else {}
                status["manual_block"] = False
                status["quota_exhausted"] = False
                status["ip_limit_enabled"] = bool(ip_enabled)
                status["ip_limit"] = int(max(0, ip_limit)) if ip_enabled else 0
                status["ip_limit_locked"] = False
                status["speed_limit_enabled"] = bool(speed_on)
                status["speed_down_mbit"] = float(down) if speed_on else 0.0
                status["speed_up_mbit"] = float(up) if speed_on else 0.0
                status["account_locked"] = False
                status["lock_owner"] = ""
                status["lock_shell_restore"] = ""
                _status_apply_lock_fields(status)
                quota_payload["status"] = status
                _ssh_save_state(quota_path, quota_payload)
        except Exception as exc:
            return _ssh_add_user_rollback(
                username,
                quota_path if "quota_path" in locals() else None,
                account_path,
                raw_password=raw_password,
                error_prefix=f"Gagal menulis metadata SSH: {exc}",
            )

        if ip_enabled:
            ok_enforce, enforce_msg = _ssh_run_enforcer(
                username=username,
                require_available=True,
            )
            if not ok_enforce:
                return _ssh_add_user_rollback(
                    username,
                    quota_path,
                    account_path,
                    raw_password=raw_password,
                    error_prefix=f"Gagal enforcement awal SSH untuk '{username}': {enforce_msg}",
                    )

        ok_account, account_msg = _ssh_refresh_account_info(username, password_override=raw_password)
        if not ok_account:
            return _ssh_add_user_rollback(
                username,
                quota_path,
                account_path,
                raw_password=raw_password,
                error_prefix=str(account_msg),
            )


        ok_account, account_msg = _ssh_refresh_account_info(username, password_override=raw_password)
        if not ok_account:
            return _ssh_add_user_rollback(
                username,
                quota_path,
                account_path,
                raw_password=raw_password,
                error_prefix=f"Gagal refresh SSH ACCOUNT INFO final untuk '{username}': {account_msg}",
            )

        warnings = _ssh_post_update_warnings(username, password_override=raw_password)
        msg = (
            f"Add user SSH sukses.\n"
            f"- User: {username}@{proto}\n"
            f"- Account: {account_path}\n"
            f"- Quota: {quota_path}"
        )
        if warnings:
            msg += "\n- Warning: " + " | ".join(warnings)
        return True, "User Management - Add User", msg

    cred = _generate_credential(proto)
    quota_bytes = int(round(quota_gb * (1024**3)))

    ok_add, add_msg = _xray_add_client(proto, username, cred)
    if not ok_add:
        return False, "User Management - Add User", add_msg

    try:
        account_file, quota_file = _write_account_artifacts(
            proto=proto,
            username=username,
            credential=cred,
            quota_bytes=quota_bytes,
            days=days,
            ip_enabled=ip_enabled,
            ip_limit=ip_limit,
            speed_enabled=speed_on,
            speed_down=down,
            speed_up=up,
        )

        if speed_on:
            ok_sync, sync_msg = _quota_sync_speed_policy_for_user(
                proto,
                username,
                {
                    "status": {
                        "speed_limit_enabled": True,
                        "speed_down_mbit": down,
                        "speed_up_mbit": up,
                    }
                },
            )
            if not ok_sync:
                ok_cleanup, cleanup_msg = _xray_cleanup_new_user_after_failure(proto, username)
                suffix = (
                    f"\n- Cleanup rollback: {cleanup_msg}"
                    if ok_cleanup
                    else f"\n- Cleanup rollback gagal: {cleanup_msg}"
                )
                return (
                    False,
                    "User Management - Add User",
                    f"Rollback add user karena speed policy gagal: {sync_msg}{suffix}",
                )

        msg = (
            f"Add user sukses.\n"
            f"- User: {username}@{proto}\n"
            f"- Account: {account_file}\n"
            f"- Quota: {quota_file}"
        )
        return True, "User Management - Add User", msg
    except Exception as exc:
        ok_cleanup, cleanup_msg = _xray_cleanup_new_user_after_failure(proto, username)
        suffix = (
            f" Cleanup rollback: {cleanup_msg}."
            if ok_cleanup
            else f" Cleanup rollback gagal: {cleanup_msg}."
        )
        return False, "User Management - Add User", f"Gagal menyimpan artefak user: {exc}.{suffix}"


def op_user_account_file_download(proto: str, username: str) -> tuple[bool, dict[str, str] | str]:
    if proto not in USER_PROTOCOLS:
        return False, f"Proto tidak valid: {proto}"
    if proto == SSH_PROTOCOL:
        if not _is_valid_ssh_username(username):
            return False, "Username SSH tidak valid."
    elif not _is_valid_username(username):
        return False, "Username tidak valid."

    account_file = _resolve_existing(_account_candidates(proto, username))
    if account_file is None:
        return False, f"File account tidak ditemukan untuk {username}@{proto}."

    try:
        raw = account_file.read_bytes()
    except Exception as exc:
        return False, f"Gagal membaca file account: {exc}"

    if proto == SSH_PROTOCOL:
        try:
            text = raw.decode("utf-8", errors="ignore")
            raw = text.encode("utf-8")
        except Exception:
            pass
        return True, {
            "filename": f"{username}@{proto}.txt",
            "content_base64": base64.b64encode(raw).decode("ascii"),
            "content_type": "text/plain",
        }

    return True, {
        "filename": f"{username}@{proto}.txt",
        "content_base64": base64.b64encode(raw).decode("ascii"),
        "content_type": "text/plain",
    }


@_user_data_mutation_locked
def op_user_delete(proto: str, username: str) -> tuple[bool, str, str]:
    if proto not in USER_PROTOCOLS:
        return False, "User Management - Delete User", f"Proto tidak valid: {proto}"
    if proto == SSH_PROTOCOL:
        if not _is_valid_ssh_username(username):
            return False, "User Management - Delete User", "Username SSH tidak valid."
    elif not _is_valid_username(username):
        return False, "User Management - Delete User", "Username tidak valid."

    if proto == SSH_PROTOCOL:
        previous_password = _ssh_previous_password(username)
        linux_exists = _linux_user_exists(username)
        ok_del, del_msg = _ssh_delete_linux_user(username)
        if not ok_del:
            suffix = ""
            return (
                False,
                "User Management - Delete User",
                f"Gagal menghapus user Linux '{username}': {del_msg}.{suffix}",
            )
        cleanup_notes = _delete_account_artifacts_checked(proto, username)
        if cleanup_notes:
            return (
                False,
                "User Management - Delete User",
                (
                    f"User Linux '{username}' sudah dihapus, tetapi cleanup artefak lokal gagal.\n- "
                    + "\n- ".join(cleanup_notes)
                ),
            )
        return True, "User Management - Delete User", f"Delete user selesai: {username}@{proto}"

    previous_credential = _find_credential_in_inbounds(proto, username) or _find_credential_from_account(proto, username)
    account_snapshot: str | None = None
    account_target = _resolve_existing(_account_candidates(proto, username))
    if account_target is not None:
        try:
            account_snapshot = account_target.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            account_snapshot = None
    ok_q_prev, _, q_prev_or_msg = _load_quota(proto, username)
    previous_quota = copy.deepcopy(q_prev_or_msg) if ok_q_prev and isinstance(q_prev_or_msg, dict) else None

    ok_del, del_msg = _xray_delete_client(proto, username)
    if not ok_del:
        return False, "User Management - Delete User", del_msg

    cleanup_notes = _delete_account_artifacts_checked(proto, username)
    ok_remove, remove_msg = _speed_policy_remove_checked(proto, username)
    ok_sync, sync_msg = _speed_policy_sync_xray()
    apply_ok = ok_sync and _speed_policy_apply_now()
    notes: list[str] = []
    if cleanup_notes:
        notes.extend(f"cleanup artefak: {note}" for note in cleanup_notes)
    if not ok_remove:
        notes.append(f"cleanup speed policy file: {remove_msg}")
    if not ok_sync:
        notes.append(f"sync speed policy: {sync_msg}")
    elif not apply_ok:
        notes.append("apply speed policy runtime gagal (xray-speed)")
    if notes:
        if previous_credential:
            ok_restore, restore_msg = _xray_restore_deleted_user(
                proto,
                username,
                credential=previous_credential,
                account_snapshot=account_snapshot,
                quota_snapshot=previous_quota,
            )
            notes.append(f"rollback delete: {restore_msg}" if ok_restore else f"rollback delete gagal: {restore_msg}")
        return (
            False,
            "User Management - Delete User",
            (
                f"Delete user untuk {username}@{proto} selesai parsial.\n- "
                + "\n- ".join(notes)
            ),
        )

    return True, "User Management - Delete User", f"Delete user selesai: {username}@{proto}"


def _find_credential_from_account(proto: str, username: str) -> str:
    acc = _resolve_existing(_account_candidates(proto, username))
    if acc is None:
        return ""
    fields = _read_account_fields(acc)
    if proto == "trojan":
        return fields.get("Password", "").strip()
    return fields.get("UUID", "").strip()


def _user_exists_in_inbounds(proto: str, username: str) -> bool:
    email = _email(proto, username)
    ok, payload = _read_json(XRAY_INBOUNDS_CONF)
    if not ok or not isinstance(payload, dict):
        return False
    inbounds = payload.get("inbounds", [])
    if not isinstance(inbounds, list):
        return False
    for ib in inbounds:
        if not _inbound_matches_proto(ib, proto):
            continue
        clients = (ib.get("settings") or {}).get("clients")
        if not isinstance(clients, list):
            continue
        for c in clients:
            if isinstance(c, dict) and str(c.get("email") or "") == email:
                return True
    return False


@_user_data_mutation_locked
def op_user_extend_expiry(proto: str, username: str, mode: str, value: str) -> tuple[bool, str, str]:
    if proto not in USER_PROTOCOLS:
        return False, "User Management - Extend Expiry", f"Proto tidak valid: {proto}"
    if proto == SSH_PROTOCOL:
        if not _is_valid_ssh_username(username):
            return False, "User Management - Extend Expiry", "Username SSH tidak valid."
    elif not _is_valid_username(username):
        return False, "User Management - Extend Expiry", "Username tidak valid."

    if proto == SSH_PROTOCOL:
        if not _linux_user_exists(username):
            return False, "User Management - Extend Expiry", f"User Linux '{username}' tidak ditemukan."

        ok_state, q_path_or_msg, q_data_or_msg = _ssh_load_state(username)
        if not ok_state:
            return False, "User Management - Extend Expiry", str(q_path_or_msg)
        quota_path = q_path_or_msg
        quota_data = q_data_or_msg
        assert isinstance(quota_path, Path)
        assert isinstance(quota_data, dict)
        previous_payload = copy.deepcopy(quota_data)

        current_expiry = str(quota_data.get("expired_at") or "").strip()[:10]
        today = _local_today()
        mode_n = str(mode or "").strip().lower()
        if mode_n in {"extend", "tambah", "days", "1"}:
            add_days = _to_int(value, 0)
            if add_days <= 0:
                return False, "User Management - Extend Expiry", "Nilai extend harus angka hari > 0."
            base = _parse_date_only(current_expiry) or today
            if base < today:
                base = today
            new_expiry = (base + timedelta(days=add_days)).strftime("%Y-%m-%d")
        elif mode_n in {"set", "date", "2"}:
            d = _parse_date_only(value)
            if d is None:
                return False, "User Management - Extend Expiry", "Format tanggal harus YYYY-MM-DD."
            new_expiry = d.strftime("%Y-%m-%d")
        else:
            return False, "User Management - Extend Expiry", "Mode harus extend atau set."

        ok_expiry, out_expiry = _ssh_apply_linux_expiry(username, new_expiry)
        if not ok_expiry:
            return False, "User Management - Extend Expiry", f"Gagal update expiry untuk '{username}': {out_expiry}"

        quota_data["expired_at"] = new_expiry
        try:
            _ssh_save_state(quota_path, quota_data)
        except Exception as exc:
            ok_rollback, rollback_msg = _ssh_expiry_update_rollback(
                username,
                current_expiry,
                quota_path,
                previous_payload,
            )
            suffix = f" Rollback: {rollback_msg}" if ok_rollback else f" Rollback gagal: {rollback_msg}"
            return (
                False,
                "User Management - Extend Expiry",
                f"Gagal menyimpan metadata expiry untuk '{username}': {exc}.{suffix}",
            )
        ok_refresh, refresh_msg = _ssh_refresh_account_info(username)
        if not ok_refresh:
            ok_rollback, rollback_msg = _ssh_expiry_update_rollback(
                username,
                current_expiry,
                quota_path,
                previous_payload,
            )
            suffix = f" Rollback: {rollback_msg}" if ok_rollback else f" Rollback gagal: {rollback_msg}"
            return (
                False,
                "User Management - Extend Expiry",
                f"Gagal sinkron SSH ACCOUNT INFO untuk '{username}': {refresh_msg}.{suffix}",
            )
        return (
            True,
            "User Management - Extend Expiry",
            f"Expiry diperbarui: {username}@{proto}\n- Lama: {current_expiry or '-'}\n- Baru: {new_expiry}",
        )

    ok_q, q_path_or_msg, q_data_or_msg = _load_quota(proto, username)
    if not ok_q:
        return False, "User Management - Extend Expiry", str(q_path_or_msg)
    quota_path = q_path_or_msg
    quota_data = q_data_or_msg
    assert isinstance(quota_path, Path)
    assert isinstance(quota_data, dict)

    current_expiry = str(quota_data.get("expired_at") or "").strip()[:10]
    today = _local_today()

    mode_n = str(mode or "").strip().lower()
    if mode_n in {"extend", "tambah", "days", "1"}:
        add_days = _to_int(value, 0)
        if add_days <= 0:
            return False, "User Management - Extend Expiry", "Nilai extend harus angka hari > 0."
        base = _parse_date_only(current_expiry) or today
        if base < today:
            base = today
        new_expiry = (base + timedelta(days=add_days)).strftime("%Y-%m-%d")
    elif mode_n in {"set", "date", "2"}:
        d = _parse_date_only(value)
        if d is None:
            return False, "User Management - Extend Expiry", "Format tanggal harus YYYY-MM-DD."
        new_expiry = d.strftime("%Y-%m-%d")
    else:
        return False, "User Management - Extend Expiry", "Mode harus extend atau set."

    previous_payload = copy.deepcopy(quota_data)
    quota_data["expired_at"] = new_expiry
    status = quota_data.get("status") if isinstance(quota_data.get("status"), dict) else {}

    st_quota = bool(status.get("quota_exhausted"))
    st_manual = bool(status.get("manual_block"))
    st_iplocked = bool(status.get("ip_limit_locked"))

    if st_quota:
        status["quota_exhausted"] = False

    _status_apply_lock_fields(status)
    quota_data["status"] = status

    ensure_credential = ""
    if not _user_exists_in_inbounds(proto, username):
        ensure_credential = _find_credential_from_account(proto, username)
        if not ensure_credential:
            return False, "User Management - Extend Expiry", f"Credential tidak ditemukan untuk restore {username}@{proto}"

    return _xray_apply_quota_update(
        "User Management - Extend Expiry",
        proto,
        username,
        quota_path,
        previous_payload,
        quota_data,
        f"Expiry diperbarui: {username}@{proto}\n- Lama: {current_expiry or '-'}\n- Baru: {new_expiry}",
        ensure_client_credential=ensure_credential,
        restore_markers=True,
        restart_limit_ip=True,
    )


@_user_data_mutation_locked
def op_ssh_reset_password(username: str, password: str) -> tuple[bool, str, str]:
    title = "User Management - Reset Password"
    if not _is_valid_ssh_username(username):
        return False, title, "Username SSH tidak valid."
    raw_password = str(password or "")
    if not raw_password.strip():
        return False, title, "Password SSH wajib diisi."
    if username.strip().lower() == raw_password.strip().lower():
        return False, title, "Password SSH tidak boleh sama dengan username."
    if not _linux_user_exists(username):
        return False, title, f"User Linux '{username}' tidak ditemukan."
    previous_password = _ssh_previous_password(username)
    if not previous_password or previous_password == "-":
        return False, title, (
            f"Password lama untuk '{username}' tidak tersedia, jadi rollback aman tidak bisa dijamin."
        )

    ok_passwd, out_passwd = _run_cmd(
        ["bash", "-lc", 'printf "%s:%s\\n" "$0" "$1" | chpasswd', username, raw_password],
        timeout=20,
    )
    if not ok_passwd:
        return False, title, f"Gagal reset password user '{username}': {out_passwd}"

    ok_refresh, refresh_msg = _ssh_refresh_account_info(username, password_override=raw_password)
    if not ok_refresh:
        ok_rollback, rollback_msg = _ssh_password_reset_rollback(username, previous_password)
        suffix = f" Rollback: {rollback_msg}" if ok_rollback else f" Rollback gagal: {rollback_msg}"
        return False, title, f"Gagal sinkron SSH ACCOUNT INFO untuk '{username}': {refresh_msg}.{suffix}"


    ok_refresh, refresh_msg = _ssh_refresh_account_info(username, password_override=raw_password)
    if not ok_refresh:
        ok_rollback, rollback_msg = _ssh_password_reset_rollback(username, previous_password)
        suffix = f" Rollback: {rollback_msg}" if ok_rollback else f" Rollback gagal: {rollback_msg}"
        return False, title, f"Gagal refresh SSH ACCOUNT INFO final untuk '{username}': {refresh_msg}.{suffix}"

    warnings: list[str] = []
    ok_enforce, enforce_msg = _ssh_run_enforcer()
    if not ok_enforce:
        warnings.append(f"enforcer: {enforce_msg}")
    msg = f"Password berhasil direset untuk {username}@{SSH_PROTOCOL}"
    if warnings:
        msg += "\n- Warning: " + " | ".join(warnings)
    return True, title, msg


@_user_data_mutation_locked
def op_xray_reset_credential(proto: str, username: str) -> tuple[bool, str, str]:
    title = "User Management - Reset UUID/Password"
    if proto not in XRAY_PROTOCOLS:
        return False, title, f"Proto tidak valid: {proto}"
    if not _is_valid_username(username):
        return False, title, "Username tidak valid."

    if not _user_exists_in_inbounds(proto, username):
        return False, title, f"User tidak ditemukan di inbounds: {username}@{proto}"

    previous_credential = _find_credential_in_inbounds(proto, username) or _find_credential_from_account(proto, username)
    if not previous_credential:
        return False, title, f"Credential lama tidak ditemukan untuk {username}@{proto}"

    credential = _generate_credential(proto)
    ok_reset, reset_msg = _xray_reset_client_credential(proto, username, credential)
    if not ok_reset:
        return False, title, reset_msg

    ok_refresh, refresh_msg = _refresh_account_info_for_user(proto, username)
    label = "Password baru" if proto == "trojan" else "UUID baru"
    if not ok_refresh:
        ok_rollback, rollback_msg = _xray_reset_client_credential(proto, username, previous_credential)
        if ok_rollback:
            _refresh_account_info_for_user(proto, username)
            return (
                False,
                title,
                (
                    f"Reset {label.lower()} gagal dituntaskan untuk {username}@{proto}\n"
                    f"- Refresh account-info gagal: {refresh_msg}\n"
                    f"- Rollback berhasil: credential lama dipulihkan"
                ),
            )
        return (
            False,
            title,
            (
                f"Reset {label.lower()} gagal dituntaskan untuk {username}@{proto}\n"
                f"- Refresh account-info gagal: {refresh_msg}\n"
                f"- Rollback credential gagal: {rollback_msg}"
            ),
        )
    return True, title, "\n".join(
        [
            f"{label} berhasil direset untuk {username}@{proto}",
            f"{label} : {credential}",
        ]
    )


def op_quota_set_limit(proto: str, username: str, quota_gb: float) -> tuple[bool, str, str]:
    if proto not in QAC_PROTOCOLS:
        return False, "Quota - Set Limit", f"Proto tidak valid: {proto}"
    if proto == SSH_PROTOCOL:
        if not _is_valid_ssh_username(username):
            return False, "Quota - Set Limit", "Username SSH tidak valid"
    elif not _is_valid_username(username):
        return False, "Quota - Set Limit", "Username tidak valid"
    if quota_gb <= 0:
        return False, "Quota - Set Limit", "Quota harus > 0 GB"

    if proto == SSH_PROTOCOL:
        ok_q, q_path_or_msg, q_data_or_msg = _ssh_load_state(username)
        if not ok_q:
            return False, "Quota - Set Limit", str(q_path_or_msg)
        q_path = q_path_or_msg
        q_data = q_data_or_msg
        assert isinstance(q_path, Path)
        assert isinstance(q_data, dict)
        previous_payload = copy.deepcopy(q_data)

        q_data["quota_limit"] = int(round(quota_gb * (1024**3)))
        status = q_data.get("status") if isinstance(q_data.get("status"), dict) else {}
        _status_apply_lock_fields(status)
        q_data["status"] = status
        ok_apply, warnings, apply_error = _ssh_apply_state_update(
            username,
            q_path,
            previous_payload,
            q_data,
            require_enforcer=True,
        )
        if not ok_apply:
            return False, "Quota - Set Limit", (
                f"Quota limit gagal diterapkan untuk {username}@{proto}: {apply_error}"
            )
        msg = f"Quota limit diubah ke {_fmt_number(quota_gb)} GB untuk {username}@{proto}"
        if warnings:
            msg += "\n- Warning: " + " | ".join(warnings)
        return True, "Quota - Set Limit", msg

    ok_q, q_path_or_msg, q_data_or_msg = _load_quota(proto, username)
    if not ok_q:
        return False, "Quota - Set Limit", str(q_path_or_msg)
    q_path = q_path_or_msg
    q_data = q_data_or_msg
    assert isinstance(q_path, Path)
    assert isinstance(q_data, dict)

    previous_payload = copy.deepcopy(q_data)
    q_data["quota_limit"] = int(round(quota_gb * (1024**3)))
    _xray_recompute_limit_lock_fields(q_data)
    return _xray_apply_quota_update(
        "Quota - Set Limit",
        proto,
        username,
        q_path,
        previous_payload,
        q_data,
        f"Quota limit diubah ke {_fmt_number(quota_gb)} GB untuk {username}@{proto}",
        restore_markers=True,
    )


def op_quota_reset_used(proto: str, username: str) -> tuple[bool, str, str]:
    if proto == SSH_PROTOCOL:
        ok_q, q_path_or_msg, q_data_or_msg = _ssh_load_state(username)
        if not ok_q:
            return False, "Quota - Reset Used", str(q_path_or_msg)
        q_path = q_path_or_msg
        q_data = q_data_or_msg
        assert isinstance(q_path, Path)
        assert isinstance(q_data, dict)
        previous_payload = copy.deepcopy(q_data)

        q_data["quota_used"] = 0
        status = q_data.get("status") if isinstance(q_data.get("status"), dict) else {}
        status["quota_exhausted"] = False
        _status_apply_lock_fields(status)
        q_data["status"] = status
        ok_apply, warnings, apply_error = _ssh_apply_state_update(
            username,
            q_path,
            previous_payload,
            q_data,
            require_enforcer=True,
        )
        if not ok_apply:
            return False, "Quota - Reset Used", (
                f"Reset quota gagal diterapkan untuk {username}@{proto}: {apply_error}"
            )
        msg = f"Quota used di-reset untuk {username}@{proto}"
        if warnings:
            msg += "\n- Warning: " + " | ".join(warnings)
        return True, "Quota - Reset Used", msg

    ok_q, q_path_or_msg, q_data_or_msg = _load_quota(proto, username)
    if not ok_q:
        return False, "Quota - Reset Used", str(q_path_or_msg)
    q_path = q_path_or_msg
    q_data = q_data_or_msg
    assert isinstance(q_path, Path)
    assert isinstance(q_data, dict)

    previous_payload = copy.deepcopy(q_data)
    q_data["quota_used"] = 0
    st = q_data.get("status") if isinstance(q_data.get("status"), dict) else {}
    st["quota_exhausted"] = False
    _status_apply_lock_fields(st)
    q_data["status"] = st
    return _xray_apply_quota_update(
        "Quota - Reset Used",
        proto,
        username,
        q_path,
        previous_payload,
        q_data,
        f"Quota used di-reset untuk {username}@{proto}",
        restore_markers=True,
    )


def op_quota_manual_block(proto: str, username: str, enabled: bool) -> tuple[bool, str, str]:
    if proto == SSH_PROTOCOL:
        ok_q, q_path_or_msg, q_data_or_msg = _ssh_load_state(username)
        if not ok_q:
            return False, "Quota - Manual Block", str(q_path_or_msg)
        q_path = q_path_or_msg
        q_data = q_data_or_msg
        assert isinstance(q_path, Path)
        assert isinstance(q_data, dict)
        previous_payload = copy.deepcopy(q_data)

        status = q_data.get("status") if isinstance(q_data.get("status"), dict) else {}
        status["manual_block"] = bool(enabled)
        _status_apply_lock_fields(status)
        q_data["status"] = status
        ok_apply, warnings, apply_error = _ssh_apply_state_update(
            username,
            q_path,
            previous_payload,
            q_data,
            require_enforcer=True,
        )
        if not ok_apply:
            return False, "Quota - Manual Block", (
                f"Manual block {'ON' if enabled else 'OFF'} gagal diterapkan untuk "
                f"{username}@{proto}: {apply_error}"
            )
        msg = f"Manual block {'ON' if enabled else 'OFF'} untuk {username}@{proto}"
        if warnings:
            msg += "\n- Warning: " + " | ".join(warnings)
        return True, "Quota - Manual Block", msg

    ok_q, q_path_or_msg, q_data_or_msg = _load_quota(proto, username)
    if not ok_q:
        return False, "Quota - Manual Block", str(q_path_or_msg)
    q_path = q_path_or_msg
    q_data = q_data_or_msg
    assert isinstance(q_path, Path)
    assert isinstance(q_data, dict)

    previous_payload = copy.deepcopy(q_data)
    st = q_data.get("status") if isinstance(q_data.get("status"), dict) else {}
    st["manual_block"] = bool(enabled)
    _status_apply_lock_fields(st)
    q_data["status"] = st
    return _xray_apply_quota_update(
        "Quota - Manual Block",
        proto,
        username,
        q_path,
        previous_payload,
        q_data,
        f"Manual block {'ON' if enabled else 'OFF'} untuk {username}@{proto}",
        restore_markers=True,
    )


def op_quota_ip_limit_enable(proto: str, username: str, enabled: bool) -> tuple[bool, str, str]:
    if proto == SSH_PROTOCOL:
        ok_q, q_path_or_msg, q_data_or_msg = _ssh_load_state(username)
        if not ok_q:
            return False, "Quota - IP Limit", str(q_path_or_msg)
        q_path = q_path_or_msg
        q_data = q_data_or_msg
        assert isinstance(q_path, Path)
        assert isinstance(q_data, dict)
        previous_payload = copy.deepcopy(q_data)

        status = q_data.get("status") if isinstance(q_data.get("status"), dict) else {}
        status["ip_limit_enabled"] = bool(enabled)
        if not enabled:
            status["ip_limit_locked"] = False
        _status_apply_lock_fields(status)
        q_data["status"] = status
        ok_apply, warnings, apply_error = _ssh_apply_state_update(
            username,
            q_path,
            previous_payload,
            q_data,
            require_enforcer=True,
        )
        if not ok_apply:
            return False, "Quota - IP Limit", (
                f"IP/Login limit {'ON' if enabled else 'OFF'} gagal diterapkan untuk "
                f"{username}@{proto}: {apply_error}"
            )
        msg = f"IP/Login limit {'ON' if enabled else 'OFF'} untuk {username}@{proto}"
        if warnings:
            msg += "\n- Warning: " + " | ".join(warnings)
        return True, "Quota - IP Limit", msg

    ok_q, q_path_or_msg, q_data_or_msg = _load_quota(proto, username)
    if not ok_q:
        return False, "Quota - IP Limit", str(q_path_or_msg)
    q_path = q_path_or_msg
    q_data = q_data_or_msg
    assert isinstance(q_path, Path)
    assert isinstance(q_data, dict)

    previous_payload = copy.deepcopy(q_data)
    st = q_data.get("status") if isinstance(q_data.get("status"), dict) else {}
    st["ip_limit_enabled"] = bool(enabled)
    q_data["status"] = st
    _xray_recompute_limit_lock_fields(q_data)
    return _xray_apply_quota_update(
        "Quota - IP Limit",
        proto,
        username,
        q_path,
        previous_payload,
        q_data,
        f"IP limit {'ON' if enabled else 'OFF'} untuk {username}@{proto}",
        restore_markers=True,
        restart_limit_ip=True,
    )


def op_quota_set_ip_limit(proto: str, username: str, limit: int) -> tuple[bool, str, str]:
    if limit <= 0:
        return False, "Quota - Set IP Limit", "IP limit harus > 0"

    if proto == SSH_PROTOCOL:
        ok_q, q_path_or_msg, q_data_or_msg = _ssh_load_state(username)
        if not ok_q:
            return False, "Quota - Set IP Limit", str(q_path_or_msg)
        q_path = q_path_or_msg
        q_data = q_data_or_msg
        assert isinstance(q_path, Path)
        assert isinstance(q_data, dict)
        previous_payload = copy.deepcopy(q_data)

        status = q_data.get("status") if isinstance(q_data.get("status"), dict) else {}
        status["ip_limit"] = int(limit)
        q_data["status"] = status
        ok_apply, warnings, apply_error = _ssh_apply_state_update(
            username,
            q_path,
            previous_payload,
            q_data,
            require_enforcer=True,
        )
        if not ok_apply:
            return False, "Quota - Set IP Limit", (
                f"IP/Login limit gagal diterapkan untuk {username}@{proto}: {apply_error}"
            )
        msg = f"IP/Login limit diubah ke {limit} untuk {username}@{proto}"
        if warnings:
            msg += "\n- Warning: " + " | ".join(warnings)
        return True, "Quota - Set IP Limit", msg

    ok_q, q_path_or_msg, q_data_or_msg = _load_quota(proto, username)
    if not ok_q:
        return False, "Quota - Set IP Limit", str(q_path_or_msg)
    q_path = q_path_or_msg
    q_data = q_data_or_msg
    assert isinstance(q_path, Path)
    assert isinstance(q_data, dict)

    previous_payload = copy.deepcopy(q_data)
    st = q_data.get("status") if isinstance(q_data.get("status"), dict) else {}
    st["ip_limit"] = int(limit)
    q_data["status"] = st
    _xray_recompute_limit_lock_fields(q_data)
    return _xray_apply_quota_update(
        "Quota - Set IP Limit",
        proto,
        username,
        q_path,
        previous_payload,
        q_data,
        f"IP limit diubah ke {limit} untuk {username}@{proto}",
        restore_markers=True,
        restart_limit_ip=True,
    )


def op_quota_unlock_ip_lock(proto: str, username: str) -> tuple[bool, str, str]:
    if proto == SSH_PROTOCOL:
        ok_q, q_path_or_msg, q_data_or_msg = _ssh_load_state(username)
        if not ok_q:
            return False, "Quota - Unlock IP Lock", str(q_path_or_msg)
        q_path = q_path_or_msg
        q_data = q_data_or_msg
        assert isinstance(q_path, Path)
        assert isinstance(q_data, dict)
        previous_payload = copy.deepcopy(q_data)

        status = q_data.get("status") if isinstance(q_data.get("status"), dict) else {}
        status["ip_limit_locked"] = False
        _status_apply_lock_fields(status)
        q_data["status"] = status
        ok_apply, warnings, apply_error = _ssh_apply_state_update(
            username,
            q_path,
            previous_payload,
            q_data,
            require_enforcer=True,
        )
        if not ok_apply:
            return False, "Quota - Unlock IP Lock", (
                f"IP/Login unlock gagal diterapkan untuk {username}@{proto}: {apply_error}"
            )
        msg = f"IP/Login lock di-unlock untuk {username}@{proto}"
        if warnings:
            msg += "\n- Warning: " + " | ".join(warnings)
        return True, "Quota - Unlock IP Lock", msg

    ok_q, q_path_or_msg, q_data_or_msg = _load_quota(proto, username)
    if not ok_q:
        return False, "Quota - Unlock IP Lock", str(q_path_or_msg)
    q_path = q_path_or_msg
    q_data = q_data_or_msg
    assert isinstance(q_path, Path)
    assert isinstance(q_data, dict)

    previous_payload = copy.deepcopy(q_data)
    email = _email(proto, username)
    if Path("/usr/local/bin/limit-ip").exists():
        ok_unlock, unlock_msg = _run_cmd(["/usr/local/bin/limit-ip", "unlock", email], timeout=15)
        if not ok_unlock:
            return False, "Quota - Unlock IP Lock", unlock_msg

    st = q_data.get("status") if isinstance(q_data.get("status"), dict) else {}
    st["ip_limit_locked"] = False
    _status_apply_lock_fields(st)
    q_data["status"] = st
    return _xray_apply_quota_update(
        "Quota - Unlock IP Lock",
        proto,
        username,
        q_path,
        previous_payload,
        q_data,
        f"IP lock di-unlock untuk {username}@{proto}",
        restore_markers=True,
        restart_limit_ip=True,
    )


def op_quota_set_speed_down(proto: str, username: str, speed_down: float) -> tuple[bool, str, str]:
    if speed_down <= 0:
        return False, "Quota - Speed Download", "Speed download harus > 0"

    if proto == SSH_PROTOCOL:
        ok_q, q_path_or_msg, q_data_or_msg = _ssh_load_state(username)
        if not ok_q:
            return False, "Quota - Speed Download", str(q_path_or_msg)
        q_path = q_path_or_msg
        q_data = q_data_or_msg
        assert isinstance(q_path, Path)
        assert isinstance(q_data, dict)
        previous_payload = copy.deepcopy(q_data)

        status = q_data.get("status") if isinstance(q_data.get("status"), dict) else {}
        status["speed_down_mbit"] = float(speed_down)
        q_data["status"] = status
        ok_apply, warnings, apply_error = _ssh_apply_state_update(
            username,
            q_path,
            previous_payload,
            q_data,
            require_account_info=True,
        )
        if not ok_apply:
            return False, "Quota - Speed Download", (
                f"Speed download gagal diterapkan untuk {username}@{proto}: {apply_error}"
            )
        msg = f"Speed download diubah ke {_fmt_number(speed_down)} Mbps untuk {username}@{proto}"
        if warnings:
            msg += "\n- Warning: " + " | ".join(warnings)
        return True, "Quota - Speed Download", msg

    ok_q, q_path_or_msg, q_data_or_msg = _load_quota(proto, username)
    if not ok_q:
        return False, "Quota - Speed Download", str(q_path_or_msg)
    q_path = q_path_or_msg
    q_data = q_data_or_msg
    assert isinstance(q_path, Path)
    assert isinstance(q_data, dict)

    previous_payload = copy.deepcopy(q_data)
    st = q_data.get("status") if isinstance(q_data.get("status"), dict) else {}
    st["speed_down_mbit"] = float(speed_down)
    q_data["status"] = st
    return _xray_apply_quota_update(
        "Quota - Speed Download",
        proto,
        username,
        q_path,
        previous_payload,
        q_data,
        f"Speed download diubah ke {_fmt_number(speed_down)} Mbps untuk {username}@{proto}",
        sync_speed=bool(st.get("speed_limit_enabled")),
    )


def op_quota_set_speed_up(proto: str, username: str, speed_up: float) -> tuple[bool, str, str]:
    if speed_up <= 0:
        return False, "Quota - Speed Upload", "Speed upload harus > 0"

    if proto == SSH_PROTOCOL:
        ok_q, q_path_or_msg, q_data_or_msg = _ssh_load_state(username)
        if not ok_q:
            return False, "Quota - Speed Upload", str(q_path_or_msg)
        q_path = q_path_or_msg
        q_data = q_data_or_msg
        assert isinstance(q_path, Path)
        assert isinstance(q_data, dict)
        previous_payload = copy.deepcopy(q_data)

        status = q_data.get("status") if isinstance(q_data.get("status"), dict) else {}
        status["speed_up_mbit"] = float(speed_up)
        q_data["status"] = status
        ok_apply, warnings, apply_error = _ssh_apply_state_update(
            username,
            q_path,
            previous_payload,
            q_data,
            require_account_info=True,
        )
        if not ok_apply:
            return False, "Quota - Speed Upload", (
                f"Speed upload gagal diterapkan untuk {username}@{proto}: {apply_error}"
            )
        msg = f"Speed upload diubah ke {_fmt_number(speed_up)} Mbps untuk {username}@{proto}"
        if warnings:
            msg += "\n- Warning: " + " | ".join(warnings)
        return True, "Quota - Speed Upload", msg

    ok_q, q_path_or_msg, q_data_or_msg = _load_quota(proto, username)
    if not ok_q:
        return False, "Quota - Speed Upload", str(q_path_or_msg)
    q_path = q_path_or_msg
    q_data = q_data_or_msg
    assert isinstance(q_path, Path)
    assert isinstance(q_data, dict)

    previous_payload = copy.deepcopy(q_data)
    st = q_data.get("status") if isinstance(q_data.get("status"), dict) else {}
    st["speed_up_mbit"] = float(speed_up)
    q_data["status"] = st
    return _xray_apply_quota_update(
        "Quota - Speed Upload",
        proto,
        username,
        q_path,
        previous_payload,
        q_data,
        f"Speed upload diubah ke {_fmt_number(speed_up)} Mbps untuk {username}@{proto}",
        sync_speed=bool(st.get("speed_limit_enabled")),
    )


def op_quota_speed_limit(proto: str, username: str, enabled: bool) -> tuple[bool, str, str]:
    if proto == SSH_PROTOCOL:
        ok_q, q_path_or_msg, q_data_or_msg = _ssh_load_state(username)
        if not ok_q:
            return False, "Quota - Speed Limit", str(q_path_or_msg)
        q_path = q_path_or_msg
        q_data = q_data_or_msg
        assert isinstance(q_path, Path)
        assert isinstance(q_data, dict)
        previous_payload = copy.deepcopy(q_data)

        status = q_data.get("status") if isinstance(q_data.get("status"), dict) else {}
        status["speed_limit_enabled"] = bool(enabled)
        if enabled:
            down = _to_float(status.get("speed_down_mbit"), 0.0)
            up = _to_float(status.get("speed_up_mbit"), 0.0)
            if down <= 0 or up <= 0:
                return False, "Quota - Speed Limit", "Set speed download/upload > 0 dulu sebelum ON."
        q_data["status"] = status
        ok_apply, warnings, apply_error = _ssh_apply_state_update(
            username,
            q_path,
            previous_payload,
            q_data,
            require_account_info=True,
        )
        if not ok_apply:
            return False, "Quota - Speed Limit", (
                f"Speed limit {'ON' if enabled else 'OFF'} gagal diterapkan untuk "
                f"{username}@{proto}: {apply_error}"
            )
        msg = f"Speed limit {'ON' if enabled else 'OFF'} untuk {username}@{proto}"
        if warnings:
            msg += "\n- Warning: " + " | ".join(warnings)
        return True, "Quota - Speed Limit", msg

    ok_q, q_path_or_msg, q_data_or_msg = _load_quota(proto, username)
    if not ok_q:
        return False, "Quota - Speed Limit", str(q_path_or_msg)
    q_path = q_path_or_msg
    q_data = q_data_or_msg
    assert isinstance(q_path, Path)
    assert isinstance(q_data, dict)

    previous_payload = copy.deepcopy(q_data)
    st = q_data.get("status") if isinstance(q_data.get("status"), dict) else {}
    st["speed_limit_enabled"] = bool(enabled)

    if enabled:
        down = _to_float(st.get("speed_down_mbit"), 0.0)
        up = _to_float(st.get("speed_up_mbit"), 0.0)
        if down <= 0 or up <= 0:
            return False, "Quota - Speed Limit", "Set speed download/upload > 0 dulu sebelum ON."

    q_data["status"] = st
    return _xray_apply_quota_update(
        "Quota - Speed Limit",
        proto,
        username,
        q_path,
        previous_payload,
        q_data,
        f"Speed limit {'ON' if enabled else 'OFF'} untuk {username}@{proto}",
        sync_speed=True,
    )


def _normalize_domain(domain: str) -> str:
    return str(domain or "").strip().lower()


def _rollback_nginx_domain_change(original: str) -> tuple[bool, str]:
    notes: list[str] = []
    try:
        _write_text_atomic(NGINX_CONF, original)
    except Exception as exc:
        notes.append(f"restore config nginx gagal: {exc}")
    else:
        ok_test, out_test = _run_cmd(["nginx", "-t"], timeout=20)
        if not ok_test:
            notes.append(f"nginx -t gagal saat rollback domain:\n{out_test}")
        elif not _restart_and_wait("nginx", timeout_sec=20):
            notes.append("nginx gagal restart saat rollback domain.")
    if notes:
        return False, "\n".join(notes)
    return True, "ok"


def _apply_nginx_domain(domain: str) -> tuple[bool, str]:
    if not NGINX_CONF.exists():
        return False, f"Nginx conf tidak ditemukan: {NGINX_CONF}"

    original = NGINX_CONF.read_text(encoding="utf-8", errors="ignore")
    changed = False
    out_lines: list[str] = []

    for line in original.splitlines():
        if re.match(r"^\s*server_name\s+", line):
            indent = re.match(r"^(\s*)", line).group(1) if re.match(r"^(\s*)", line) else ""
            out_lines.append(f"{indent}server_name {domain};")
            changed = True
        else:
            out_lines.append(line)

    if not changed:
        return False, "Baris server_name tidak ditemukan di nginx config"

    candidate = "\n".join(out_lines) + "\n"

    try:
        _write_text_atomic(NGINX_CONF, candidate)
        ok_test, out_test = _run_cmd(["nginx", "-t"], timeout=20)
        if not ok_test:
            ok_rb, msg_rb = _rollback_nginx_domain_change(original)
            if ok_rb:
                return False, f"nginx -t gagal setelah ubah domain:\n{out_test}\nPerubahan nginx sudah di-rollback."
            return False, f"nginx -t gagal setelah ubah domain:\n{out_test}\nRollback nginx gagal:\n{msg_rb}"

        if not _restart_and_wait("nginx", timeout_sec=20):
            ok_rb, msg_rb = _rollback_nginx_domain_change(original)
            if ok_rb:
                return False, "nginx gagal restart setelah ubah domain. Perubahan nginx sudah di-rollback."
            return False, f"nginx gagal restart setelah ubah domain.\nRollback nginx gagal:\n{msg_rb}"
    except Exception as exc:
        ok_rb, msg_rb = _rollback_nginx_domain_change(original)
        if ok_rb:
            return False, f"Gagal apply domain ke nginx: {exc}\nPerubahan nginx sudah di-rollback."
        return False, f"Gagal apply domain ke nginx: {exc}\nRollback nginx gagal:\n{msg_rb}"

    # Keep compatibility with compatibility scripts that still read active domain from /etc/xray/domain.
    try:
        XRAY_DOMAIN_FILE.parent.mkdir(parents=True, exist_ok=True)
        _write_text_atomic(XRAY_DOMAIN_FILE, f"{domain}\n")
    except Exception as exc:
        ok_rb, msg_rb = _rollback_nginx_domain_change(original)
        if ok_rb:
            return False, (
                f"Gagal sinkron domain kompatibilitas ke {XRAY_DOMAIN_FILE}: {exc}\n"
                "Perubahan nginx sudah di-rollback."
            )
        return False, f"Gagal sinkron domain kompatibilitas ke {XRAY_DOMAIN_FILE}: {exc}\nRollback nginx gagal:\n{msg_rb}"

    return True, "ok"


def _parse_bool_text(raw: Any, default: bool = False) -> bool:
    if isinstance(raw, bool):
        return raw
    text = str(raw or "").strip().lower()
    if text in {"1", "true", "yes", "y", "on", "aktif", "enable", "enabled"}:
        return True
    if text in {"0", "false", "no", "n", "off", "nonaktif", "disable", "disabled"}:
        return False
    return default


def _download_file(url: str, dest: Path, timeout: int = 60) -> tuple[bool, str]:
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = resp.read()
        ok_write, msg_write = _write_bytes_atomic(dest, data)
        if not ok_write:
            return False, msg_write
        if url.endswith(".sh"):
            try:
                os.chmod(dest, 0o700)
            except Exception:
                pass
        return True, "ok"
    except Exception as exc:
        return False, f"Gagal download {url}: {exc}"


def _rand_email() -> str:
    return f"admin{random.randint(1000, 9999)}@gmail.com"


def _acme_path() -> Path:
    return Path("/root/.acme.sh/acme.sh")


def _ensure_acme_installed() -> tuple[bool, str]:
    acme = _acme_path()
    if acme.exists():
        _run_cmd([str(acme), "--set-default-ca", "--server", "letsencrypt"], timeout=30)
        return True, "ok"

    account_email = _rand_email()
    tmpdir = Path(tempfile.mkdtemp(prefix="acme-install-"))
    src_dir: Path | None = None
    try:
        tgz = tmpdir / "acme.tar.gz"
        ok_dl, _ = _download_file(
            ACME_SH_TARBALL_URL,
            tgz,
            timeout=120,
        )
        if ok_dl:
            ok_extract, msg_extract = _safe_extract_tarball(tgz, tmpdir)
            if not ok_extract:
                return False, msg_extract
            for d in tmpdir.iterdir():
                if d.is_dir() and d.name.startswith("acme.sh-"):
                    src_dir = d
                    break

        if src_dir is None:
            src_dir = tmpdir / "acme-single"
            src_dir.mkdir(parents=True, exist_ok=True)
            ok_script, msg_script = _download_file(
                ACME_SH_SCRIPT_URL,
                src_dir / "acme.sh",
                timeout=120,
            )
            if not ok_script:
                return False, msg_script

        script = src_dir / "acme.sh"
        if not script.exists():
            return False, "acme.sh script tidak ditemukan setelah download."
        try:
            os.chmod(script, 0o700)
        except Exception:
            pass

        ok_install, out_install = _run_cmd(
            ["bash", str(script), "--install", "--home", "/root/.acme.sh", "--accountemail", account_email],
            timeout=240,
            cwd=str(src_dir),
        )
        if not ok_install:
            return False, f"Install acme.sh gagal:\n{out_install}"

        if not acme.exists():
            return False, "acme.sh tidak ditemukan setelah install."

        _run_cmd([str(acme), "--set-default-ca", "--server", "letsencrypt"], timeout=30)
        return True, "ok"
    finally:
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass


def _ensure_dns_cf_hook() -> tuple[bool, str]:
    hook = Path("/root/.acme.sh/dnsapi/dns_cf.sh")
    if hook.exists() and hook.stat().st_size > 0:
        return True, "ok"
    hook.parent.mkdir(parents=True, exist_ok=True)
    ok_dl, msg_dl = _download_file(
        ACME_SH_DNS_CF_HOOK_URL,
        hook,
        timeout=120,
    )
    if not ok_dl:
        return False, msg_dl
    try:
        os.chmod(hook, 0o700)
    except Exception:
        pass
    if not hook.exists() or hook.stat().st_size <= 0:
        return False, "Hook dns_cf tetap tidak ditemukan setelah bootstrap."
    return True, "ok"


def _stop_conflicting_services() -> tuple[list[str], list[str]]:
    stopped: list[str] = []
    failures: list[str] = []
    for svc in ("nginx", "apache2", "caddy", "lighttpd"):
        if not (_service_exists(svc) and _service_is_active(svc)):
            continue
        ok_stop, out_stop = _run_cmd(["systemctl", "stop", svc], timeout=25)
        if not ok_stop:
            failures.append(f"{svc}: {out_stop}")
            continue
        if _service_is_active(svc):
            failures.append(f"{svc}: masih aktif setelah stop")
            continue
        stopped.append(svc)
    edge_svc = _edge_runtime_service_name()
    if (
        _edge_runtime_uses_public_http_port_80()
        and edge_svc
        and edge_svc != "nginx"
        and _service_exists(edge_svc)
        and _service_is_active(edge_svc)
    ):
        ok_stop, out_stop = _run_cmd(["systemctl", "stop", edge_svc], timeout=25)
        if not ok_stop:
            failures.append(f"{edge_svc}: {out_stop}")
        elif _service_is_active(edge_svc):
            failures.append(f"{edge_svc}: masih aktif setelah stop")
        else:
            stopped.append(edge_svc)
    return stopped, failures


def _restore_services(services: list[str]) -> list[str]:
    failures: list[str] = []
    for svc in services:
        if not _service_exists(svc):
            failures.append(f"{svc}: service tidak ditemukan saat restore")
            continue
        ok_start, out_start = _run_cmd(["systemctl", "start", svc], timeout=25)
        if not ok_start:
            failures.append(f"{svc}: {out_start}")
            continue
        if not _service_is_active(svc):
            failures.append(f"{svc}: inactive setelah start")
    return failures


def _restart_tls_runtime_consumers(skipped_services: set[str] | None = None) -> tuple[bool, str]:
    skipped = skipped_services or set()
    targets = ["sshws-stunnel"]
    edge_svc = _edge_runtime_service_name()
    if edge_svc and edge_svc != "nginx":
        targets.append(edge_svc)

    failures: list[str] = []
    for svc in targets:
        if svc in skipped:
            continue
        if not _service_exists(svc) or not _service_is_active(svc):
            continue
        ok_reload, out_reload = _run_cmd(["systemctl", "reload", svc], timeout=30)
        if not ok_reload:
            ok_reload, out_reload = _run_cmd(["systemctl", "restart", svc], timeout=30)
        if not ok_reload or not _service_is_active(svc):
            failures.append(f"{svc}: {out_reload}")
    if failures:
        return False, "\n".join(failures)
    return True, "ok"


def _restore_tls_runtime_consumers_from_snapshot(
    snapshot: dict[str, Any],
    skipped_services: set[str] | None = None,
) -> tuple[bool, str]:
    skipped = skipped_services or set()
    failures: list[str] = []
    targets: list[tuple[str, bool]] = [
        ("sshws-stunnel", bool(snapshot.get("sshws_stunnel_was_active"))),
    ]
    edge_service = str(snapshot.get("edge_service_name") or "").strip()
    if edge_service and edge_service not in {"nginx", "sshws-stunnel"}:
        targets.append((edge_service, bool(snapshot.get("edge_service_was_active"))))

    for svc, should_be_active in targets:
        if svc in skipped:
            continue
        if should_be_active:
            if not _service_exists(svc):
                failures.append(f"{svc}: service tidak ditemukan saat rollback")
                continue
            ok_reload, out_reload = _run_cmd(["systemctl", "reload", svc], timeout=30)
            if not ok_reload:
                ok_reload, out_reload = _run_cmd(["systemctl", "restart", svc], timeout=30)
            if not ok_reload or not _service_is_active(svc):
                failures.append(f"{svc}: {out_reload}")
        elif _service_exists(svc) and _service_is_active(svc):
            if not _stop_and_wait_inactive(svc, timeout_sec=30):
                failures.append(f"{svc}: gagal dikembalikan ke inactive")

    if failures:
        return False, "\n".join(failures)
    return True, "ok"


def _cf_api(method: str, endpoint: str, payload: dict[str, Any] | None = None) -> tuple[bool, dict[str, Any] | str]:
    token = CLOUDFLARE_API_TOKEN.strip()
    if not token:
        return False, "CLOUDFLARE_API_TOKEN belum di-set."

    url = f"https://api.cloudflare.com/client/v4{endpoint}"
    data_bytes = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(
        url,
        data=data_bytes,
        method=method.upper(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )

    body_text = ""
    status = 0
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            status = int(resp.getcode() or 0)
            body_text = resp.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as exc:
        status = int(exc.code or 0)
        try:
            body_text = exc.read().decode("utf-8", errors="ignore")
        except Exception:
            body_text = str(exc)
    except Exception as exc:
        return False, f"Gagal call Cloudflare API: {exc}"

    if not body_text.strip():
        return False, f"Cloudflare API empty response (HTTP {status or '?'}) for {endpoint}"

    try:
        parsed = json.loads(body_text)
    except Exception:
        return False, f"Cloudflare API non-JSON response (HTTP {status or '?'}) for {endpoint}:\n{body_text}"

    if not (200 <= status < 300):
        return False, f"Cloudflare API HTTP {status} for {endpoint}: {body_text}"

    if not bool(parsed.get("success", False)):
        errs = parsed.get("errors")
        if isinstance(errs, list) and errs:
            msg = "; ".join(str(e.get("message") or e) for e in errs if isinstance(e, dict) or isinstance(e, str))
            if msg:
                return False, f"Cloudflare API error: {msg}"
        return False, f"Cloudflare API success=false untuk endpoint {endpoint}"

    return True, parsed


def _cf_get_zone_id_by_name(zone_name: str) -> tuple[bool, str]:
    endpoint = f"/zones?name={urllib.parse.quote(zone_name)}&per_page=1"
    ok, res = _cf_api("GET", endpoint)
    if not ok:
        return False, str(res)
    payload = res if isinstance(res, dict) else {}
    result = payload.get("result")
    if not isinstance(result, list) or not result:
        return False, f"Zone Cloudflare tidak ditemukan: {zone_name}"
    zid = str((result[0] or {}).get("id") or "").strip()
    if not zid:
        return False, f"Zone id tidak ditemukan untuk: {zone_name}"
    return True, zid


def _cf_get_account_id_by_zone(zone_id: str) -> tuple[bool, str]:
    ok, res = _cf_api("GET", f"/zones/{zone_id}")
    if not ok:
        return False, str(res)
    payload = res if isinstance(res, dict) else {}
    account_id = str((((payload.get("result") or {}).get("account") or {}).get("id") or "")).strip()
    if not account_id:
        return False, f"CF account id tidak ditemukan untuk zone: {zone_id}"
    return True, account_id


def _cf_list_a_records_by_name(zone_id: str, fqdn: str) -> tuple[bool, list[dict[str, Any]] | str]:
    endpoint = f"/zones/{zone_id}/dns_records?type=A&name={urllib.parse.quote(fqdn)}&per_page=100"
    ok, res = _cf_api("GET", endpoint)
    if not ok:
        return False, str(res)
    payload = res if isinstance(res, dict) else {}
    result = payload.get("result")
    if not isinstance(result, list):
        return True, []
    out: list[dict[str, Any]] = []
    for item in result:
        if isinstance(item, dict):
            out.append(item)
    return True, out


def _cf_list_a_records_by_ip(zone_id: str, ip: str) -> tuple[bool, list[dict[str, Any]] | str]:
    endpoint = f"/zones/{zone_id}/dns_records?type=A&content={urllib.parse.quote(ip)}&per_page=100"
    ok, res = _cf_api("GET", endpoint)
    if not ok:
        return False, str(res)
    payload = res if isinstance(res, dict) else {}
    result = payload.get("result")
    if not isinstance(result, list):
        return True, []
    out: list[dict[str, Any]] = []
    for item in result:
        if isinstance(item, dict):
            out.append(item)
    return True, out


def _cf_delete_record(zone_id: str, record_id: str) -> tuple[bool, str]:
    ok, res = _cf_api("DELETE", f"/zones/{zone_id}/dns_records/{record_id}")
    if not ok:
        return False, str(res)
    return True, "ok"


def _cf_create_a_record_result(
    zone_id: str,
    name: str,
    ip: str,
    *,
    proxied: bool = False,
    ttl: int = 1,
) -> tuple[bool, dict[str, Any] | str]:
    ttl_value = 1 if proxied else max(1, int(ttl or 1))
    payload = {
        "type": "A",
        "name": name,
        "content": ip,
        "ttl": ttl_value,
        "proxied": bool(proxied),
    }
    ok, res = _cf_api("POST", f"/zones/{zone_id}/dns_records", payload=payload)
    if not ok:
        return False, str(res)
    parsed = res if isinstance(res, dict) else {}
    result = parsed.get("result")
    if not isinstance(result, dict):
        return False, "Cloudflare API tidak mengembalikan result record."
    return True, result


def _cf_create_a_record(zone_id: str, name: str, ip: str, proxied: bool = False) -> tuple[bool, str]:
    ok, res = _cf_create_a_record_result(zone_id, name, ip, proxied=proxied)
    if not ok:
        return False, str(res)
    return True, "ok"


def _cf_record_restore_spec(record: dict[str, Any]) -> dict[str, Any]:
    ttl_raw = record.get("ttl")
    try:
        ttl = int(ttl_raw or 1)
    except Exception:
        ttl = 1
    proxied = bool(record.get("proxied"))
    if ttl <= 0 or proxied:
        ttl = 1
    return {
        "name": str(record.get("name") or "").strip(),
        "content": str(record.get("content") or "").strip(),
        "proxied": proxied,
        "ttl": ttl,
    }


def _cf_restore_deleted_a_records(zone_id: str, deleted_records: list[dict[str, Any]]) -> tuple[bool, str]:
    failures: list[str] = []
    for spec in deleted_records:
        name = str(spec.get("name") or "").strip()
        content = str(spec.get("content") or "").strip()
        if not name or not content:
            continue
        ttl_raw = spec.get("ttl")
        try:
            ttl = int(ttl_raw or 1)
        except Exception:
            ttl = 1
        proxied = bool(spec.get("proxied"))
        ok_create, create_res = _cf_create_a_record_result(
            zone_id,
            name,
            content,
            proxied=proxied,
            ttl=ttl,
        )
        if not ok_create:
            failures.append(f"{name}: {create_res}")
    if failures:
        return False, " | ".join(failures)
    return True, "ok"


def _cf_rollback_prepared_subdomain_a_record(zone_id: str, rollback: dict[str, Any] | None) -> tuple[bool, str]:
    if not isinstance(rollback, dict) or not bool(rollback.get("changed")):
        return True, "ok"
    failures: list[str] = []
    created_record_id = str(rollback.get("created_record_id") or "").strip()
    if created_record_id:
        ok_del, del_msg = _cf_delete_record(zone_id, created_record_id)
        if not ok_del:
            failures.append(f"hapus record baru: {del_msg}")
    deleted_records = rollback.get("deleted_records")
    if isinstance(deleted_records, list) and deleted_records:
        ok_restore, restore_msg = _cf_restore_deleted_a_records(zone_id, deleted_records)
        if not ok_restore:
            failures.append(f"restore record lama: {restore_msg}")
    if failures:
        return False, " | ".join(failures)
    return True, "ok"


def _gen_subdomain_random() -> str:
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choice(chars) for _ in range(5))


def _validate_subdomain(subdomain: str) -> bool:
    s = str(subdomain or "").strip()
    if not s:
        return False
    if s != s.lower():
        return False
    if " " in s:
        return False
    return bool(re.match(r"^[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?$", s))


def _resolve_root_domain_input(raw: str) -> tuple[bool, str]:
    text = str(raw or "").strip().lower()
    if not text:
        return False, "Root domain wajib diisi."
    if text.isdigit():
        idx = int(text)
        if 1 <= idx <= len(PROVIDED_ROOT_DOMAINS):
            return True, PROVIDED_ROOT_DOMAINS[idx - 1]
        return False, f"Index root domain di luar range 1-{len(PROVIDED_ROOT_DOMAINS)}."
    for root in PROVIDED_ROOT_DOMAINS:
        if text == root.lower():
            return True, root
    return False, f"Root domain tidak dikenali: {raw}. Pilihan: {', '.join(PROVIDED_ROOT_DOMAINS)}"


def _cf_prepare_subdomain_a_record(
    zone_id: str,
    fqdn: str,
    ip: str,
    proxied: bool,
    allow_existing_same_ip: bool,
) -> tuple[bool, dict[str, Any] | str]:
    ok_name, name_records_or_err = _cf_list_a_records_by_name(zone_id, fqdn)
    if not ok_name:
        return False, str(name_records_or_err)
    name_records = name_records_or_err if isinstance(name_records_or_err, list) else []
    target_exists_same_ip = False

    rec_ips = [str(r.get("content") or "").strip() for r in name_records if isinstance(r, dict)]
    if rec_ips:
        any_same = any(v == ip for v in rec_ips)
        any_diff = any(v and v != ip for v in rec_ips)
        if any_diff:
            return False, f"Subdomain {fqdn} sudah ada di Cloudflare tapi IP berbeda: {', '.join(rec_ips)}"
        if any_same:
            if allow_existing_same_ip:
                target_exists_same_ip = True
            else:
                return False, f"A record {fqdn} -> {ip} sudah ada. Set allow_existing_same_ip=on untuk lanjut."

    ok_ip, same_ip_or_err = _cf_list_a_records_by_ip(zone_id, ip)
    if not ok_ip:
        return False, str(same_ip_or_err)
    same_ip_records = same_ip_or_err if isinstance(same_ip_or_err, list) else []
    deleted_records: list[dict[str, Any]] = []
    for rec in same_ip_records:
        rec_id = str(rec.get("id") or "").strip()
        rec_name = str(rec.get("name") or "").strip()
        if not rec_id or not rec_name:
            continue
        if rec_name == fqdn:
            continue
        deleted_records.append(_cf_record_restore_spec(rec))
        ok_del, del_msg = _cf_delete_record(zone_id, rec_id)
        if not ok_del:
            return False, f"Gagal hapus A record historis {rec_name}: {del_msg}"

    if target_exists_same_ip:
        return True, {
            "message": f"A record sudah ada dan sama: {fqdn} -> {ip}",
            "rollback": {
                "changed": bool(deleted_records),
                "created_record_id": "",
                "deleted_records": deleted_records,
            },
        }

    ok_create, create_res = _cf_create_a_record_result(zone_id, fqdn, ip, proxied=proxied)
    if not ok_create:
        if deleted_records:
            _cf_restore_deleted_a_records(zone_id, deleted_records)
        return False, str(create_res)
    created_record_id = str((create_res or {}).get("id") or "").strip() if isinstance(create_res, dict) else ""
    return True, {
        "message": f"DNS A record siap: {fqdn} -> {ip} (proxied={'true' if proxied else 'false'})",
        "rollback": {
            "changed": True,
            "created_record_id": created_record_id,
            "deleted_records": deleted_records,
        },
    }


def _issue_cert_dns_cf_wildcard(domain: str, root_domain: str, zone_id: str, account_id: str = "") -> tuple[bool, str]:
    ok_verify, verify_res = _cf_api("GET", "/user/tokens/verify")
    if not ok_verify:
        return False, (
            "Token Cloudflare tidak valid/kurang scope. "
            "Butuh minimal Zone:DNS Edit + Zone:Read.\n"
            f"{verify_res}"
        )

    ok_acme, acme_msg = _ensure_acme_installed()
    if not ok_acme:
        return False, acme_msg
    ok_hook, hook_msg = _ensure_dns_cf_hook()
    if not ok_hook:
        return False, hook_msg

    acme = _acme_path()
    env = os.environ.copy()
    env["CF_Token"] = CLOUDFLARE_API_TOKEN
    if account_id:
        env["CF_Account_ID"] = account_id
    if zone_id:
        env["CF_Zone_ID"] = zone_id

    ok_issue, out_issue = _run_cmd(
        [str(acme), "--issue", "--force", "--dns", "dns_cf", "-d", domain, "-d", f"*.{domain}"],
        timeout=360,
        env=env,
    )
    if not ok_issue:
        return False, f"Gagal issue sertifikat wildcard via dns_cf untuk {domain}:\n{out_issue}"

    ok_install, out_install = _run_cmd(
        [
            str(acme),
            "--install-cert",
            "-d",
            domain,
            "--key-file",
            str(CERT_PRIVKEY),
            "--fullchain-file",
            str(CERT_FULLCHAIN),
            "--reloadcmd",
            "/bin/true",
        ],
        timeout=180,
        env=env,
    )
    if not ok_install:
        return False, f"Gagal install sertifikat wildcard untuk {domain}:\n{out_install}"

    _chmod_600(CERT_PRIVKEY)
    _chmod_600(CERT_FULLCHAIN)
    return True, f"Sertifikat wildcard terpasang untuk {domain} (root: {root_domain})"


def _issue_cert_standalone(domain: str) -> tuple[bool, str]:
    ok_acme, acme_msg = _ensure_acme_installed()
    if not ok_acme:
        return False, acme_msg
    acme = _acme_path()

    CERT_DIR.mkdir(parents=True, exist_ok=True)

    ok_issue, out_issue = _run_cmd(
        [
            str(acme),
            "--issue",
            "--force",
            "--standalone",
            "-d",
            domain,
            "--httpport",
            "80",
        ],
        timeout=240,
    )
    if not ok_issue:
        return False, f"Issue cert gagal:\n{out_issue}"

    ok_install, out_install = _run_cmd(
        [
            str(acme),
            "--install-cert",
            "-d",
            domain,
            "--key-file",
            str(CERT_PRIVKEY),
            "--fullchain-file",
            str(CERT_FULLCHAIN),
            "--reloadcmd",
            "/bin/true",
        ],
        timeout=120,
    )
    if not ok_install:
        return False, f"Install cert gagal:\n{out_install}"

    _chmod_600(CERT_PRIVKEY)
    _chmod_600(CERT_FULLCHAIN)
    return True, "ok"


def _get_public_ipv4() -> tuple[bool, str]:
    for url in ("https://api.ipify.org", "https://ipv4.icanhazip.com"):
        try:
            with urllib.request.urlopen(url, timeout=6) as resp:
                text = resp.read().decode("utf-8", errors="ignore").strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", text):
                return True, text
        except Exception:
            continue
    fallback = _detect_public_ipv4()
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", fallback) and fallback != "0.0.0.0":
        return True, fallback
    return False, "Gagal mendapatkan public IPv4 VPS."


def _parse_subdomain_mode(raw: Any) -> str:
    text = str(raw or "").strip().lower()
    if not text:
        return "auto"
    if text in {"1", "auto", "acak", "random", "generate", "generated"}:
        return "auto"
    if text in {"2", "manual", "input", "custom"}:
        return "manual"
    return ""


def op_domain_cloudflare_root_list() -> tuple[bool, str, str]:
    lines = [f"{i + 1}. {root}" for i, root in enumerate(PROVIDED_ROOT_DOMAINS)]
    msg = "Root domain Cloudflare yang tersedia:\n" + "\n".join(lines)
    msg += "\n\nInput bisa nomor (contoh: 1) atau nama domain penuh."
    return True, "Domain Control - Root Domain List", msg


def list_provided_root_domains() -> list[str]:
    return [str(root).strip() for root in PROVIDED_ROOT_DOMAINS if str(root).strip()]


@_user_data_mutation_locked
def op_domain_setup_custom(domain: str) -> tuple[bool, str, str]:
    title = "Domain Control - Set Domain (Custom)"
    domain_n = _normalize_domain(domain)
    if not DOMAIN_RE.match(domain_n):
        return False, title, "Domain tidak valid."

    snapshot = _capture_domain_runtime_snapshot()
    previous_domain = _domain_snapshot_active_domain(snapshot)
    stopped_services, stop_failures = _stop_conflicting_services()
    completed = False
    error_msg: str | None = None
    if stop_failures:
        error_msg = "Gagal menghentikan service konflik:\n" + "\n".join(stop_failures)
    restore_failures: list[str] = []
    try:
        if error_msg is None:
            ok_cert, cert_msg = _issue_cert_standalone(domain_n)
            if not ok_cert:
                error_msg = cert_msg
            else:
                ok_ng, ng_msg = _apply_nginx_domain(domain_n)
                if not ok_ng:
                    error_msg = ng_msg
                else:
                    ok_tls, tls_msg = _restore_tls_runtime_consumers_from_snapshot(snapshot, set(stopped_services))
                    if not ok_tls:
                        error_msg = f"Restart consumer TLS gagal:\n{tls_msg}"
                    else:
                        completed = True
    except Exception as exc:
        error_msg = f"Setup domain custom gagal: {exc}"
    finally:
        # Success path: nginx sudah di-restart oleh _apply_nginx_domain, restore service lain
        # yang tadinya aktif agar state sistem kembali seperti sebelum wizard.
        if completed:
            restore_failures = _restore_services([svc for svc in stopped_services if svc != "nginx"])
        else:
            # Failure path: pastikan semua service yang sebelumnya aktif dipulihkan.
            restore_failures = _restore_services(stopped_services)
        if restore_failures:
            restore_msg = "Restore service yang sebelumnya aktif gagal:\n" + "\n".join(restore_failures)
            if error_msg:
                error_msg = f"{error_msg}\n{restore_msg}"
            else:
                error_msg = restore_msg

    if error_msg:
        ok_rb, msg_rb = _restore_domain_runtime_snapshot(snapshot)
        if ok_rb and previous_domain:
            _, rb_failed, _ = _refresh_all_account_info(domain=previous_domain)
            if rb_failed > 0:
                return False, title, (
                    f"{error_msg}\nRollback domain berhasil, tetapi {rb_failed} ACCOUNT INFO domain lama "
                    "gagal direfresh."
                )
        if ok_rb:
            return False, title, error_msg
        return False, title, f"{error_msg}\nRollback domain gagal:\n{msg_rb}"

    ip_override: str | None = None
    ok_ip, ip_or_err = _get_public_ipv4()
    if ok_ip:
        ip_override = str(ip_or_err)
    updated, failed, skipped = _refresh_all_account_info(domain=domain_n, ip=ip_override)
    lines = [
        f"Domain aktif sekarang: {domain_n}",
        "- Certificate mode : standalone",
        f"- ACCOUNT INFO updated: {updated}",
    ]
    if failed > 0:
        lines.append(
            f"- Warning: {failed} ACCOUNT INFO gagal direfresh. Domain aktif tetap dipertahankan; jalankan refresh eksplisit bila diperlukan."
    )
    if skipped > 0:
        lines.append(f"- Catatan: {skipped} entri account-info yatim dilewati otomatis.")
    return True, title, "\n".join(lines)


@_user_data_mutation_locked
def op_domain_setup_cloudflare(
    root_domain_input: str,
    subdomain_mode: str = "auto",
    subdomain: str = "",
    proxied: Any = False,
    allow_existing_same_ip: Any = False,
) -> tuple[bool, str, str]:
    title = "Domain Control - Set Domain (Cloudflare Wizard)"
    snapshot = _capture_domain_runtime_snapshot()
    previous_domain = _domain_snapshot_active_domain(snapshot)

    ok_root, root_or_err = _resolve_root_domain_input(root_domain_input)
    if not ok_root:
        return False, title, str(root_or_err)
    root_domain = str(root_or_err)

    ok_ip, ip_or_err = _get_public_ipv4()
    if not ok_ip:
        return False, title, str(ip_or_err)
    vps_ipv4 = str(ip_or_err)

    ok_zone, zone_or_err = _cf_get_zone_id_by_name(root_domain)
    if not ok_zone:
        return False, title, str(zone_or_err)
    zone_id = str(zone_or_err)

    account_id = ""
    ok_acc, acc_or_err = _cf_get_account_id_by_zone(zone_id)
    if ok_acc:
        account_id = str(acc_or_err)

    mode = _parse_subdomain_mode(subdomain_mode)
    if not mode:
        return (
            False,
            title,
            "subdomain_mode tidak valid. Gunakan: auto/manual (atau 1/2).",
        )

    if mode == "auto":
        sub = _gen_subdomain_random()
    else:
        sub = str(subdomain or "").strip().lower()
        if not _validate_subdomain(sub):
            return (
                False,
                title,
                "Subdomain tidak valid. Hanya huruf kecil, angka, titik, dan strip (-).",
            )

    domain_final = f"{sub}.{root_domain}".lower()
    proxied_b = _parse_bool_text(proxied, default=False)
    allow_same_b = _parse_bool_text(allow_existing_same_ip, default=False)

    ok_dns, dns_payload_or_err = _cf_prepare_subdomain_a_record(
        zone_id=zone_id,
        fqdn=domain_final,
        ip=vps_ipv4,
        proxied=proxied_b,
        allow_existing_same_ip=allow_same_b,
    )
    if not ok_dns:
        return False, title, str(dns_payload_or_err)
    dns_payload = dns_payload_or_err if isinstance(dns_payload_or_err, dict) else {}
    dns_msg = str(dns_payload.get("message") or "").strip() or "DNS A record siap."
    dns_rollback = dns_payload.get("rollback") if isinstance(dns_payload.get("rollback"), dict) else {"changed": False}

    stopped_services, stop_failures = _stop_conflicting_services()
    completed = False
    error_msg: str | None = None
    if stop_failures:
        error_msg = "Gagal menghentikan service konflik:\n" + "\n".join(stop_failures)
    restore_failures: list[str] = []
    try:
        if error_msg is None:
            ok_cert, cert_msg = _issue_cert_dns_cf_wildcard(
                domain=domain_final,
                root_domain=root_domain,
                zone_id=zone_id,
                account_id=account_id,
            )
            if not ok_cert:
                error_msg = cert_msg
            else:
                ok_ng, ng_msg = _apply_nginx_domain(domain_final)
                if not ok_ng:
                    error_msg = ng_msg
                else:
                    ok_tls, tls_msg = _restore_tls_runtime_consumers_from_snapshot(snapshot, set(stopped_services))
                    if not ok_tls:
                        error_msg = f"Restart consumer TLS gagal:\n{tls_msg}"
                    else:
                        completed = True
    except Exception as exc:
        error_msg = f"Setup Cloudflare wizard gagal: {exc}"
    finally:
        if completed:
            restore_failures = _restore_services([svc for svc in stopped_services if svc != "nginx"])
        else:
            restore_failures = _restore_services(stopped_services)
        if restore_failures:
            restore_msg = "Restore service yang sebelumnya aktif gagal:\n" + "\n".join(restore_failures)
            if error_msg:
                error_msg = f"{error_msg}\n{restore_msg}"
            else:
                error_msg = restore_msg

    if error_msg:
        ok_dns_rb, msg_dns_rb = _cf_rollback_prepared_subdomain_a_record(zone_id, dns_rollback)
        if not ok_dns_rb:
            error_msg = f"{error_msg}\nRollback DNS Cloudflare gagal:\n{msg_dns_rb}"
        ok_rb, msg_rb = _restore_domain_runtime_snapshot(snapshot)
        if ok_rb and previous_domain:
            _, rb_failed, _ = _refresh_all_account_info(domain=previous_domain, ip=vps_ipv4)
            if rb_failed > 0:
                return False, title, (
                    f"{error_msg}\nRollback domain berhasil, tetapi {rb_failed} ACCOUNT INFO domain lama "
                    "gagal direfresh."
                )
        if ok_rb:
            return False, title, error_msg
        return False, title, f"{error_msg}\nRollback domain gagal:\n{msg_rb}"

    updated, failed, skipped = _refresh_all_account_info(domain=domain_final, ip=vps_ipv4)
    lines = [
        f"Domain aktif sekarang: {domain_final}",
        f"- Root domain      : {root_domain}",
        f"- Cloudflare proxy : {'ON' if proxied_b else 'OFF'}",
        f"- DNS              : {dns_msg}",
        "- Certificate mode : dns_cf wildcard",
    ]
    if not ok_acc:
        lines.append(f"- Catatan: CF_ACCOUNT_ID tidak ditemukan ({acc_or_err})")
    if failed > 0:
        lines.append(
            f"- Warning: {failed} ACCOUNT INFO gagal direfresh. Domain/DNS/certificate aktif tetap dipertahankan; jalankan refresh eksplisit bila diperlukan."
    )
    if skipped > 0:
        lines.append(f"- Catatan: {skipped} entri account-info yatim dilewati otomatis.")
    lines.append(f"- ACCOUNT INFO updated: {updated}")
    return True, title, "\n".join(lines)


@_user_data_mutation_locked
def op_domain_set(domain: str, issue_cert: bool = False) -> tuple[bool, str, str]:
    title = "Domain Control - Set Domain"
    domain_n = _normalize_domain(domain)
    if not DOMAIN_RE.match(domain_n):
        return False, title, "Domain tidak valid."

    if issue_cert:
        ok_setup, _, msg_setup = op_domain_setup_custom(domain_n)
        if not ok_setup:
            return False, title, msg_setup
        return True, title, msg_setup

    ok_ng, ng_msg = _apply_nginx_domain(domain_n)
    if not ok_ng:
        return False, title, ng_msg

    updated, failed, skipped = _refresh_all_account_info(domain=domain_n)
    if failed > 0:
        return True, title, (
            f"Domain berhasil diubah ke: {domain_n}\n"
            f"- ACCOUNT INFO updated: {updated}\n"
            f"- Warning: {failed} ACCOUNT INFO gagal direfresh. Domain aktif tetap dipertahankan; jalankan refresh eksplisit bila diperlukan."
        )
    msg = f"Domain berhasil diubah ke: {domain_n}\n- ACCOUNT INFO updated: {updated}"
    if skipped > 0:
        msg += f"\n- Catatan: {skipped} entri account-info yatim dilewati otomatis."
    return True, title, msg


@_user_data_mutation_locked
def op_domain_refresh_accounts() -> tuple[bool, str, str]:
    updated, failed, skipped = _refresh_all_account_info()
    title = "Domain Control - Refresh Account Info"
    msg = f"Selesai: updated={updated}, failed={failed}"
    if skipped > 0:
        msg += f", skipped={skipped}"
    if failed > 0:
        msg += "\nSebagian ACCOUNT INFO gagal direfresh."
        return False, title, msg
    if skipped > 0:
        msg += "\nEntri account-info yatim dilewati otomatis."
    return True, title, msg


def op_security_renew_cert() -> tuple[bool, str, str]:
    title = "Security - Renew Certificate"
    domain = _normalize_domain(_detect_domain())
    if not DOMAIN_RE.match(domain):
        return False, title, "Domain aktif tidak terdeteksi atau tidak valid."

    ok_acme, acme_msg = _ensure_acme_installed()
    if not ok_acme:
        return False, title, acme_msg

    acme = _acme_path()
    renew_cmd = [str(acme), "--renew", "-d", domain, "--force"]
    notes: list[str] = [f"Domain aktif : {domain}"]
    snapshot = _capture_domain_runtime_snapshot()
    restore_failures: list[str] = []

    ok_renew, renew_out = _run_cmd(renew_cmd, timeout=360)
    port80_conflict = (not ok_renew) and bool(
        re.search(r"port 80 is already used|Please stop it first", renew_out, flags=re.IGNORECASE)
    )

    if not ok_renew and port80_conflict:
        stopped_services, stop_failures = _stop_conflicting_services()
        stop_error_msg = None
        if stop_failures:
            stop_error_msg = "Gagal menghentikan service konflik:\n" + "\n".join(stop_failures)
        try:
            if stop_error_msg is None:
                ok_renew, renew_out = _run_cmd(renew_cmd, timeout=360)
        finally:
            restore_failures = _restore_services(stopped_services)
        if stopped_services:
            notes.append("Retry renew dijalankan setelah menghentikan service yang memakai port 80.")
        if stop_error_msg is not None:
            if restore_failures:
                stop_error_msg += "\nRestore service yang sebelumnya aktif gagal:\n" + "\n".join(restore_failures)
            return False, title, stop_error_msg
        if restore_failures:
            ok_rb, msg_rb = _restore_domain_runtime_snapshot(snapshot)
            restore_msg = "Restore service yang sebelumnya aktif gagal:\n" + "\n".join(restore_failures)
            if ok_rb:
                return False, title, (
                    f"{restore_msg}\nPerubahan cert sudah di-rollback."
                )
            return False, title, f"{restore_msg}\nRollback cert gagal:\n{msg_rb}"

    if not ok_renew and not port80_conflict:
        ok_renew, renew_out = _run_cmd(renew_cmd, timeout=360)
        if ok_renew:
            notes.append("Renew berhasil pada percobaan ulang.")

    if not ok_renew:
        msg = "\n".join(notes + ["", "Renew certificate gagal:", renew_out])
        return False, title, msg

    if _service_exists("nginx") and _service_is_active("nginx"):
        ok_nginx_reload, nginx_reload_out = _run_cmd(["systemctl", "reload", "nginx"], timeout=30)
        if not ok_nginx_reload:
            ok_nginx_reload, nginx_reload_out = _run_cmd(["systemctl", "restart", "nginx"], timeout=30)
        if ok_nginx_reload and _service_is_active("nginx"):
            notes.append("nginx berhasil di-reload/restart untuk memuat cert terbaru.")
        else:
            ok_rb, msg_rb = _restore_domain_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, (
                    "Cert berhasil diperbarui, tetapi nginx gagal di-reload/restart. "
                    "Perubahan cert sudah di-rollback.\n"
                    f"{nginx_reload_out}"
                )
            return False, title, (
                "Cert berhasil diperbarui, tetapi nginx gagal di-reload/restart.\n"
                f"{nginx_reload_out}\nRollback cert gagal:\n{msg_rb}"
            )

    ok_tls, tls_msg = _restore_tls_runtime_consumers_from_snapshot(snapshot, set())
    if ok_tls:
        notes.append("TLS consumer aktif berhasil di-reload/restart.")
    else:
        ok_rb, msg_rb = _restore_domain_runtime_snapshot(snapshot)
        if ok_rb:
            return False, title, (
                "Cert berhasil diperbarui, tetapi restart consumer TLS tambahan gagal. "
                "Perubahan cert sudah di-rollback.\n"
                f"{tls_msg}"
            )
        return False, title, (
            "Cert berhasil diperbarui, tetapi restart consumer TLS tambahan gagal.\n"
            f"{tls_msg}\nRollback cert gagal:\n{msg_rb}"
        )

    msg = "\n".join(notes + ["", "Renew certificate selesai. Cek expiry untuk memastikan hasil terbaru."])
    return True, title, msg


def op_network_apply_warp_global_mode(mode: str) -> tuple[bool, str, str]:
    title = "Network Controls - WARP Global"
    mode_n = str(mode or "").strip().lower()
    snapshot = _capture_xray_network_runtime_snapshot()

    ok_apply, msg_apply = _apply_routing_transaction(
        lambda rt_cfg, out_cfg: _routing_set_default_warp_global_mode(rt_cfg, out_cfg, mode_n)
    )
    if not ok_apply:
        return False, title, msg_apply

    ok_sync, msg_sync = _speed_policy_sync_xray()
    if not ok_sync:
        ok_rb, msg_rb = _restore_xray_network_runtime_snapshot(snapshot)
        if ok_rb:
            return False, title, f"{msg_apply}\nCatatan sinkronisasi speed policy: {msg_sync}"
        return False, title, f"{msg_apply}\nCatatan sinkronisasi speed policy: {msg_sync}\nRollback network controls gagal:\n{msg_rb}"
    if not _speed_policy_apply_now():
        ok_rb, msg_rb = _restore_xray_network_runtime_snapshot(snapshot)
        if ok_rb:
            return False, title, f"{msg_apply}\nCatatan apply runtime speed policy gagal (xray-speed)."
        return False, title, f"{msg_apply}\nCatatan apply runtime speed policy gagal (xray-speed).\nRollback network controls gagal:\n{msg_rb}"
    return True, title, msg_apply


def op_network_warp_status_report() -> tuple[bool, str, str]:
    title = "Network Controls - WARP Status"

    ok_rt, rt_payload = _read_json(XRAY_ROUTING_CONF)
    if not ok_rt:
        return False, title, str(rt_payload)
    if not isinstance(rt_payload, dict):
        return False, title, "Format routing tidak valid."

    routing = rt_payload.get("routing")
    rules = routing.get("rules") if isinstance(routing, dict) else None
    if not isinstance(rules, list):
        return False, title, "Format routing.rules tidak valid."

    global_mode = _routing_default_mode_pretty(rt_payload)
    user_warp = _routing_list_marker_users(rules, "dummy-warp-user", "warp")
    user_direct = _routing_list_marker_users(rules, "dummy-direct-user", "direct")
    inb_warp = _routing_list_marker_inbounds(rules, "dummy-warp-inbounds", "warp")
    inb_direct = _routing_list_marker_inbounds(rules, "dummy-direct-inbounds", "direct")
    dom_direct = _routing_list_marker_domains(rules, "regexp:^$", "direct")
    dom_warp = _routing_list_marker_domains(rules, "regexp:^$WARP", "warp")

    wireproxy_state = "not-installed"
    if _service_exists("wireproxy"):
        wireproxy_state = "active" if _service_is_active("wireproxy") else "inactive"

    lines = [
        f"WARP Global   : {global_mode}",
        f"wireproxy     : {wireproxy_state}",
        f"User Override : warp={len(user_warp)}, direct={len(user_direct)}",
        f"Inbound Ovr   : warp={len(inb_warp)}, direct={len(inb_direct)}",
        f"Domain List   : direct={len(dom_direct)}, warp={len(dom_warp)}",
        "",
        "User warp (sample): " + (", ".join(user_warp[:8]) if user_warp else "-"),
        "User direct (sample): " + (", ".join(user_direct[:8]) if user_direct else "-"),
        "Inbound warp (sample): " + (", ".join(inb_warp[:8]) if inb_warp else "-"),
        "Inbound direct (sample): " + (", ".join(inb_direct[:8]) if inb_direct else "-"),
        "Domain direct (sample): " + (", ".join(dom_direct[:8]) if dom_direct else "-"),
        "Domain warp (sample): " + (", ".join(dom_warp[:8]) if dom_warp else "-"),
        "",
        _warp_tier_status_message(),
    ]
    return True, title, "\n".join(lines)


def op_network_warp_restart() -> tuple[bool, str, str]:
    title = "Network Controls - Restart WARP"
    ok_target, service_name, backend_label, msg_target = _warp_restart_target_service()
    if not ok_target:
        return False, title, msg_target
    if not _restart_and_wait(service_name, timeout_sec=40):
        return False, title, f"{service_name} tidak aktif setelah restart."
    return True, title, (
        f"Restart WARP mengikuti backend host: {backend_label} ({service_name}).\n"
        f"Status: {'active' if _service_is_active(service_name) else 'inactive'}"
    )


def op_network_warp_set_global_mode(mode: str) -> tuple[bool, str, str]:
    title = "Network Controls - WARP Global"
    mode_n = str(mode or "").strip().lower()
    if mode_n not in {"direct", "warp"}:
        return False, title, "Mode global harus direct/warp."
    ok_op, _, msg = op_network_apply_warp_global_mode(mode_n)
    if not ok_op:
        return False, title, msg
    return True, title, msg


def op_network_warp_set_user_mode(proto: str, username: str, mode: str) -> tuple[bool, str, str]:
    title = "Network Controls - WARP per-user"
    proto_n = str(proto or "").strip().lower()
    username_n = str(username or "").strip()
    mode_n = str(mode or "").strip().lower()

    if proto_n not in PROTOCOLS:
        return False, title, "Protocol harus vless/vmess/trojan."
    if not _is_valid_username(username_n):
        return False, title, "Username tidak valid."
    if mode_n not in {"direct", "warp", "off"}:
        return False, title, "Mode user harus direct/warp/off."

    email = _email(proto_n, username_n)
    if re.match(r"^default@(vless|vmess|trojan)-(ws|hup|grpc)$", email):
        return False, title, f"User default bersifat readonly: {email}"

    snapshot = _capture_xray_network_runtime_snapshot()
    ok_apply, msg_apply = _apply_routing_transaction(
        lambda rt_cfg, _out_cfg: _routing_set_user_warp_mode(rt_cfg, email, mode_n)
    )
    if not ok_apply:
        return False, title, msg_apply
    ok_sync, msg_sync = _speed_policy_sync_xray()
    if not ok_sync:
        ok_rb, msg_rb = _restore_xray_network_runtime_snapshot(snapshot)
        if ok_rb:
            return False, title, f"{msg_apply}\nCatatan sinkronisasi speed policy: {msg_sync}"
        return False, title, f"{msg_apply}\nCatatan sinkronisasi speed policy: {msg_sync}\nRollback network controls gagal:\n{msg_rb}"
    if not _speed_policy_apply_now():
        ok_rb, msg_rb = _restore_xray_network_runtime_snapshot(snapshot)
        if ok_rb:
            return False, title, f"{msg_apply}\nCatatan apply runtime speed policy gagal (xray-speed)."
        return False, title, f"{msg_apply}\nCatatan apply runtime speed policy gagal (xray-speed).\nRollback network controls gagal:\n{msg_rb}"
    return True, title, msg_apply


def op_network_warp_set_inbound_mode(inbound_tag: str, mode: str) -> tuple[bool, str, str]:
    title = "Network Controls - WARP per-inbound"
    tag = str(inbound_tag or "").strip()
    mode_n = str(mode or "").strip().lower()

    if not tag:
        return False, title, "Inbound tag tidak boleh kosong."
    if tag == "api":
        return False, title, "Inbound internal 'api' bersifat readonly."
    if mode_n not in {"direct", "warp", "off"}:
        return False, title, "Mode inbound harus direct/warp/off."

    ok_inb, inb_cfg = _read_json(XRAY_INBOUNDS_CONF)
    if not ok_inb:
        return False, title, str(inb_cfg)
    inbounds = inb_cfg.get("inbounds") if isinstance(inb_cfg, dict) else None
    known_tags = set()
    if isinstance(inbounds, list):
        for item in inbounds:
            if not isinstance(item, dict):
                continue
            t = str(item.get("tag") or "").strip()
            if t:
                known_tags.add(t)
    if tag not in known_tags:
        return False, title, f"Inbound tag tidak ditemukan: {tag}"

    snapshot = _capture_xray_network_runtime_snapshot()
    ok_apply, msg_apply = _apply_routing_transaction(
        lambda rt_cfg, _out_cfg: _routing_set_inbound_warp_mode(rt_cfg, tag, mode_n)
    )
    if not ok_apply:
        return False, title, msg_apply
    ok_sync, msg_sync = _speed_policy_sync_xray()
    if not ok_sync:
        ok_rb, msg_rb = _restore_xray_network_runtime_snapshot(snapshot)
        if ok_rb:
            return False, title, f"{msg_apply}\nCatatan sinkronisasi speed policy: {msg_sync}"
        return False, title, f"{msg_apply}\nCatatan sinkronisasi speed policy: {msg_sync}\nRollback network controls gagal:\n{msg_rb}"
    if not _speed_policy_apply_now():
        ok_rb, msg_rb = _restore_xray_network_runtime_snapshot(snapshot)
        if ok_rb:
            return False, title, f"{msg_apply}\nCatatan apply runtime speed policy gagal (xray-speed)."
        return False, title, f"{msg_apply}\nCatatan apply runtime speed policy gagal (xray-speed).\nRollback network controls gagal:\n{msg_rb}"
    return True, title, msg_apply


def op_network_warp_set_domain_mode(mode: str, entry: str) -> tuple[bool, str, str]:
    title = "Network Controls - WARP per-domain"
    mode_n = str(mode or "").strip().lower()
    entry_n = str(entry or "").strip()
    if mode_n not in {"direct", "warp", "off"}:
        return False, title, "Mode domain harus direct/warp/off."
    if not entry_n:
        return False, title, "Entry domain/geosite tidak boleh kosong."
    if entry_n in {"regexp:^$", "regexp:^$WARP"}:
        return False, title, "Entry reserved tidak valid."
    if entry_n in READONLY_GEOSITE_DOMAINS:
        return False, title, f"Readonly geosite tidak boleh diubah: {entry_n}"

    snapshot = _capture_xray_network_runtime_snapshot()
    ok_apply, msg_apply = _apply_routing_transaction(
        lambda rt_cfg, _out_cfg: _routing_set_custom_domain_mode(rt_cfg, mode_n, entry_n)
    )
    if not ok_apply:
        return False, title, msg_apply
    ok_sync, msg_sync = _speed_policy_sync_xray()
    if not ok_sync:
        ok_rb, msg_rb = _restore_xray_network_runtime_snapshot(snapshot)
        if ok_rb:
            return False, title, f"{msg_apply}\nCatatan sinkronisasi speed policy: {msg_sync}"
        return False, title, f"{msg_apply}\nCatatan sinkronisasi speed policy: {msg_sync}\nRollback network controls gagal:\n{msg_rb}"
    if not _speed_policy_apply_now():
        ok_rb, msg_rb = _restore_xray_network_runtime_snapshot(snapshot)
        if ok_rb:
            return False, title, f"{msg_apply}\nCatatan apply runtime speed policy gagal (xray-speed)."
        return False, title, f"{msg_apply}\nCatatan apply runtime speed policy gagal (xray-speed).\nRollback network controls gagal:\n{msg_rb}"
    return True, title, msg_apply


def op_network_warp_tier_status() -> tuple[bool, str, str]:
    title = "Network Controls - WARP Tier Status"
    return True, title, _warp_tier_status_message()


def op_network_warp_tier_switch_free() -> tuple[bool, str, str]:
    title = "Network Controls - WARP Tier Free"
    if shutil.which("wgcf") is None:
        return False, title, "wgcf tidak ditemukan. Jalankan setup.sh terlebih dulu."
    if shutil.which("wireproxy") is None:
        return False, title, "wireproxy tidak ditemukan. Jalankan setup.sh terlebih dulu."

    with file_lock(WARP_LOCK_FILE):
        snapshot = _capture_warp_runtime_snapshot()
        if snapshot.get("mode_target") == "zerotrust" or snapshot.get("zerotrust_was_active"):
            ok_stop_zt, msg_stop_zt = _warp_zero_trust_disconnect_backend()
            if not ok_stop_zt:
                ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
                if ok_rb:
                    return False, title, msg_stop_zt
                return False, title, f"{msg_stop_zt}\nRollback WARP gagal:\n{msg_rb}"
        WGCF_DIR.mkdir(parents=True, exist_ok=True)
        account_file = WGCF_DIR / "wgcf-account.toml"
        profile_file = WGCF_DIR / "wgcf-profile.conf"
        try:
            if account_file.exists():
                account_file.unlink()
            if profile_file.exists():
                profile_file.unlink()
        except Exception as exc:
            ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, f"Gagal membersihkan artefak wgcf lama: {exc}"
            return False, title, f"Gagal membersihkan artefak wgcf lama: {exc}\nRollback WARP gagal:\n{msg_rb}"

        ok_reg, msg_reg = _warp_wgcf_register_noninteractive()
        if not ok_reg:
            ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, msg_reg
            return False, title, f"{msg_reg}\nRollback WARP gagal:\n{msg_rb}"

        ok_build, profile_or_err = _warp_wgcf_build_profile("free")
        if not ok_build:
            ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, profile_or_err
            return False, title, f"{profile_or_err}\nRollback WARP gagal:\n{msg_rb}"

        ok_apply, msg_apply = _warp_wireproxy_apply_profile(Path(profile_or_err))
        if not ok_apply:
            ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, msg_apply
            return False, title, f"{msg_apply}\nRollback WARP gagal:\n{msg_rb}"

        if not _restart_and_wait("wireproxy", timeout_sec=30):
            ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, "wireproxy tidak aktif setelah apply profile free."
            return False, title, f"wireproxy tidak aktif setelah apply profile free.\nRollback WARP gagal:\n{msg_rb}"
        if not _warp_wait_live_tier("free", timeout_sec=20):
            ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, "Live WARP tier tidak sesuai target free setelah switch."
            return False, title, f"Live WARP tier tidak sesuai target free setelah switch.\nRollback WARP gagal:\n{msg_rb}"
        try:
            _network_state_update_many(
                {
                    WARP_MODE_STATE_KEY: "consumer",
                    WARP_TIER_STATE_KEY: "free",
                    WARP_PLUS_LICENSE_STATE_KEY: snapshot.get("license_key"),
                }
            )
        except Exception as exc:
            ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, f"Gagal menyimpan state target WARP free: {exc}"
            return False, title, f"Gagal menyimpan state target WARP free: {exc}\nRollback WARP gagal:\n{msg_rb}"

        ok_refresh, msg_refresh = _ssh_network_apply_runtime()
        if not ok_refresh:
            ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, f"Switch free berhasil, tetapi refresh SSH Network gagal:\n{msg_refresh}"
            return False, title, f"Switch free berhasil, tetapi refresh SSH Network gagal:\n{msg_refresh}\nRollback WARP gagal:\n{msg_rb}"

    msg = (
        "Switch tier ke free berhasil.\n"
        f"- Register: {msg_reg}\n"
        f"- Apply: {msg_apply}\n\n"
        + _warp_tier_status_message()
    )
    return True, title, msg


def op_network_warp_tier_switch_plus(license_key: str) -> tuple[bool, str, str]:
    title = "Network Controls - WARP Tier Plus"
    if shutil.which("wgcf") is None:
        return False, title, "wgcf tidak ditemukan. Jalankan setup.sh terlebih dulu."
    if shutil.which("wireproxy") is None:
        return False, title, "wireproxy tidak ditemukan. Jalankan setup.sh terlebih dulu."

    with file_lock(WARP_LOCK_FILE):
        key = str(license_key or "").strip()
        if not key:
            key = _network_state_get(WARP_PLUS_LICENSE_STATE_KEY).strip()
        if not key:
            return False, title, "License key WARP+ kosong."
        snapshot = _capture_warp_runtime_snapshot()
        if snapshot.get("mode_target") == "zerotrust" or snapshot.get("zerotrust_was_active"):
            ok_stop_zt, msg_stop_zt = _warp_zero_trust_disconnect_backend()
            if not ok_stop_zt:
                ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
                if ok_rb:
                    return False, title, msg_stop_zt
                return False, title, f"{msg_stop_zt}\nRollback WARP gagal:\n{msg_rb}"

        ok_build, profile_or_err = _warp_wgcf_build_profile("plus", key)
        if not ok_build:
            ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, profile_or_err
            return False, title, f"{profile_or_err}\nRollback WARP gagal:\n{msg_rb}"

        ok_apply, msg_apply = _warp_wireproxy_apply_profile(Path(profile_or_err))
        if not ok_apply:
            ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, msg_apply
            return False, title, f"{msg_apply}\nRollback WARP gagal:\n{msg_rb}"

        if not _restart_and_wait("wireproxy", timeout_sec=30):
            ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, "wireproxy tidak aktif setelah apply profile plus."
            return False, title, f"wireproxy tidak aktif setelah apply profile plus.\nRollback WARP gagal:\n{msg_rb}"
        if not _warp_wait_live_tier("plus", timeout_sec=20):
            ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, "Live WARP tier tidak sesuai target plus setelah switch."
            return False, title, f"Live WARP tier tidak sesuai target plus setelah switch.\nRollback WARP gagal:\n{msg_rb}"
        try:
            _network_state_update_many(
                {
                    WARP_MODE_STATE_KEY: "consumer",
                    WARP_TIER_STATE_KEY: "plus",
                    WARP_PLUS_LICENSE_STATE_KEY: key,
                }
            )
        except Exception as exc:
            ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, f"Gagal menyimpan state target WARP plus: {exc}"
            return False, title, f"Gagal menyimpan state target WARP plus: {exc}\nRollback WARP gagal:\n{msg_rb}"

        ok_refresh, msg_refresh = _ssh_network_apply_runtime()
        if not ok_refresh:
            ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, f"Switch plus berhasil, tetapi refresh SSH Network gagal:\n{msg_refresh}"
            return False, title, f"Switch plus berhasil, tetapi refresh SSH Network gagal:\n{msg_refresh}\nRollback WARP gagal:\n{msg_rb}"

    msg = (
        "Switch tier ke plus berhasil.\n"
        f"- Apply: {msg_apply}\n\n"
        + _warp_tier_status_message()
    )
    return True, title, msg


def op_network_warp_tier_reconnect() -> tuple[bool, str, str]:
    title = "Network Controls - WARP Reconnect/Regenerate"
    if shutil.which("wgcf") is None:
        return False, title, "wgcf tidak ditemukan. Jalankan setup.sh terlebih dulu."
    if shutil.which("wireproxy") is None:
        return False, title, "wireproxy tidak ditemukan. Jalankan setup.sh terlebih dulu."

    with file_lock(WARP_LOCK_FILE):
        snapshot = _capture_warp_runtime_snapshot()
        target = _warp_tier_reconnect_target_get()
        if target not in {"free", "plus"}:
            return (
                False,
                title,
                "Target reconnect Free/Plus belum diketahui. Gunakan Switch ke WARP Free atau Switch ke WARP Plus dulu agar target tersimpan jelas.",
            )
        if snapshot.get("mode_target") == "zerotrust" or snapshot.get("zerotrust_was_active"):
            ok_stop_zt, msg_stop_zt = _warp_zero_trust_disconnect_backend()
            if not ok_stop_zt:
                ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
                if ok_rb:
                    return False, title, msg_stop_zt
                return False, title, f"{msg_stop_zt}\nRollback WARP gagal:\n{msg_rb}"

        if target == "plus":
            key = _network_state_get(WARP_PLUS_LICENSE_STATE_KEY).strip()
            if not key:
                return False, title, "Target plus aktif, tetapi license key kosong."
            ok_build, profile_or_err = _warp_wgcf_build_profile("plus", key)
        else:
            ok_build, profile_or_err = _warp_wgcf_build_profile("free")

        if not ok_build:
            ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, profile_or_err
            return False, title, f"{profile_or_err}\nRollback WARP gagal:\n{msg_rb}"

        ok_apply, msg_apply = _warp_wireproxy_apply_profile(Path(profile_or_err))
        if not ok_apply:
            ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, msg_apply
            return False, title, f"{msg_apply}\nRollback WARP gagal:\n{msg_rb}"

        if not _restart_and_wait("wireproxy", timeout_sec=30):
            ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, "wireproxy tidak aktif setelah reconnect/regenerate."
            return False, title, f"wireproxy tidak aktif setelah reconnect/regenerate.\nRollback WARP gagal:\n{msg_rb}"
        if not _warp_wait_live_tier(target, timeout_sec=20):
            ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, f"Live WARP tier tidak sesuai target {target} setelah reconnect/regenerate."
            return False, title, f"Live WARP tier tidak sesuai target {target} setelah reconnect/regenerate.\nRollback WARP gagal:\n{msg_rb}"

        try:
            updates: dict[str, str | None] = {
                WARP_MODE_STATE_KEY: "consumer",
                WARP_TIER_STATE_KEY: target,
            }
            if target == "plus":
                updates[WARP_PLUS_LICENSE_STATE_KEY] = _network_state_get(WARP_PLUS_LICENSE_STATE_KEY).strip() or snapshot.get("license_key")
            _network_state_update_many(updates)
        except Exception as exc:
            ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, f"Gagal menyimpan state target WARP setelah reconnect: {exc}"
            return False, title, f"Gagal menyimpan state target WARP setelah reconnect: {exc}\nRollback WARP gagal:\n{msg_rb}"

        ok_refresh, msg_refresh = _ssh_network_apply_runtime()
        if not ok_refresh:
            ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, f"Reconnect WARP berhasil, tetapi refresh SSH Network gagal:\n{msg_refresh}"
            return False, title, f"Reconnect WARP berhasil, tetapi refresh SSH Network gagal:\n{msg_refresh}\nRollback WARP gagal:\n{msg_rb}"

    msg = f"Reconnect/regenerate selesai untuk target: {target}\n- Apply: {msg_apply}\n\n{_warp_tier_status_message()}"
    return True, title, msg


def op_network_warp_tier_zero_trust_set_team(team: str) -> tuple[bool, str, str]:
    title = "Network Controls - Zero Trust Set Team Name"
    team_n = str(team or "").strip().lower()
    if not team_n or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", team_n):
        return False, title, "Team name Zero Trust tidak valid."
    with file_lock(WARP_LOCK_FILE):
        current = _warp_zero_trust_env_value("WARP_ZEROTRUST_TEAM", "").strip().lower()
        if current == team_n:
            return True, title, f"Team name Zero Trust sudah {team_n}; config tidak diubah."
        ok_set, msg_set = _warp_zero_trust_update_env_many({"WARP_ZEROTRUST_TEAM": team_n})
        if not ok_set:
            return False, title, msg_set
    return True, title, f"Team name Zero Trust disimpan: {team_n}"


def op_network_warp_tier_zero_trust_set_client_id(client_id: str) -> tuple[bool, str, str]:
    title = "Network Controls - Zero Trust Set Client ID"
    value = str(client_id or "").strip()
    if not value:
        return False, title, "Client ID Zero Trust tidak boleh kosong."
    with file_lock(WARP_LOCK_FILE):
        current = _warp_zero_trust_env_value("WARP_ZEROTRUST_CLIENT_ID", "").strip()
        if current == value:
            return True, title, "Client ID Zero Trust sudah sama; config tidak diubah."
        ok_set, msg_set = _warp_zero_trust_update_env_many({"WARP_ZEROTRUST_CLIENT_ID": value})
        if not ok_set:
            return False, title, msg_set
    return True, title, "Client ID Zero Trust disimpan."


def op_network_warp_tier_zero_trust_set_client_secret(client_secret: str) -> tuple[bool, str, str]:
    title = "Network Controls - Zero Trust Set Client Secret"
    value = str(client_secret or "").strip()
    if not value:
        return False, title, "Client secret Zero Trust tidak boleh kosong."
    with file_lock(WARP_LOCK_FILE):
        current = _warp_zero_trust_env_value("WARP_ZEROTRUST_CLIENT_SECRET", "").strip()
        if current == value:
            return True, title, "Client secret Zero Trust sudah sama; config tidak diubah."
        ok_set, msg_set = _warp_zero_trust_update_env_many({"WARP_ZEROTRUST_CLIENT_SECRET": value})
        if not ok_set:
            return False, title, msg_set
    return True, title, "Client secret Zero Trust disimpan."


def op_network_warp_tier_zero_trust_setup_credentials(
    team: str,
    client_id: str,
    client_secret: str,
) -> tuple[bool, str, str]:
    title = "Network Controls - Zero Trust Setup Credentials"
    team_n = str(team or "").strip().lower()
    client_id_n = str(client_id or "").strip()
    client_secret_n = str(client_secret or "").strip()
    if not team_n or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", team_n):
        return False, title, "Team name Zero Trust tidak valid."
    if not client_id_n:
        return False, title, "Client ID Zero Trust tidak boleh kosong."
    if not client_secret_n:
        return False, title, "Client secret Zero Trust tidak boleh kosong."
    with file_lock(WARP_LOCK_FILE):
        current_team = _warp_zero_trust_env_value("WARP_ZEROTRUST_TEAM", "").strip().lower()
        current_client_id = _warp_zero_trust_env_value("WARP_ZEROTRUST_CLIENT_ID", "").strip()
        current_client_secret = _warp_zero_trust_env_value("WARP_ZEROTRUST_CLIENT_SECRET", "").strip()
        if (
            current_team == team_n
            and current_client_id == client_id_n
            and current_client_secret == client_secret_n
        ):
            return True, title, "Credential Zero Trust sudah sama; config tidak diubah."
        ok_set, msg_set = _warp_zero_trust_update_env_many(
            {
                "WARP_ZEROTRUST_TEAM": team_n,
                "WARP_ZEROTRUST_CLIENT_ID": client_id_n,
                "WARP_ZEROTRUST_CLIENT_SECRET": client_secret_n,
            }
        )
        if not ok_set:
            return False, title, msg_set
    return True, title, "Credential Zero Trust disimpan."


def op_network_warp_tier_zero_trust_apply() -> tuple[bool, str, str]:
    title = "Network Controls - Zero Trust Apply / Connect"
    if shutil.which("warp-cli") is None:
        return False, title, "warp-cli tidak ditemukan. Install Cloudflare WARP client dulu."
    if not _service_exists(WARP_ZEROTRUST_SERVICE):
        return False, title, f"Service {WARP_ZEROTRUST_SERVICE} tidak ditemukan."

    ok_guard, msg_guard = _warp_zero_trust_ssh_guard()
    if not ok_guard:
        return False, title, msg_guard

    with file_lock(WARP_LOCK_FILE):
        snapshot = _capture_warp_runtime_snapshot()

        ok_mdm, msg_mdm = _warp_zero_trust_render_mdm_file()
        if not ok_mdm:
            return False, title, msg_mdm

        if snapshot.get("wireproxy_exists") and snapshot.get("wireproxy_was_active"):
            if not _stop_and_wait_inactive("wireproxy", timeout_sec=30):
                ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
                if ok_rb:
                    return False, title, "Gagal menghentikan wireproxy sebelum aktivasi Zero Trust."
                return False, title, f"Gagal menghentikan wireproxy sebelum aktivasi Zero Trust.\nRollback WARP gagal:\n{msg_rb}"

        if not _restart_and_wait(WARP_ZEROTRUST_SERVICE, timeout_sec=30):
            ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, f"{WARP_ZEROTRUST_SERVICE} tidak sehat setelah restart."
            return False, title, f"{WARP_ZEROTRUST_SERVICE} tidak sehat setelah restart.\nRollback WARP gagal:\n{msg_rb}"
        if not _warp_zero_trust_proxy_wait_connected(timeout_sec=30):
            ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, "Proxy Zero Trust belum listening setelah connect."
            return False, title, f"Proxy Zero Trust belum listening setelah connect.\nRollback WARP gagal:\n{msg_rb}"

        try:
            _network_state_update_many({WARP_MODE_STATE_KEY: "zerotrust"})
        except Exception as exc:
            ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, f"Gagal menyimpan state Zero Trust: {exc}"
            return False, title, f"Gagal menyimpan state Zero Trust: {exc}\nRollback WARP gagal:\n{msg_rb}"

        ok_refresh, msg_refresh = _ssh_network_apply_runtime()
        if not ok_refresh:
            ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, f"Zero Trust aktif, tetapi refresh SSH Network gagal:\n{msg_refresh}"
            return False, title, f"Zero Trust aktif, tetapi refresh SSH Network gagal:\n{msg_refresh}\nRollback WARP gagal:\n{msg_rb}"

    return True, title, f"Zero Trust berhasil diaktifkan.\n\n{_warp_zero_trust_status_message()}"


def op_network_warp_tier_zero_trust_disconnect() -> tuple[bool, str, str]:
    title = "Network Controls - Zero Trust Disconnect"
    with file_lock(WARP_LOCK_FILE):
        ok_disc, msg_disc = _warp_zero_trust_disconnect_backend()
        if not ok_disc:
            return False, title, msg_disc
        try:
            _network_state_update_many({WARP_MODE_STATE_KEY: "zerotrust"})
        except Exception as exc:
            return False, title, f"Gagal mempertahankan state Zero Trust: {exc}"
    return True, title, f"Zero Trust diputuskan.\n\n{_warp_zero_trust_status_message()}"


def op_network_warp_tier_zero_trust_return_free_plus() -> tuple[bool, str, str]:
    title = "Network Controls - Zero Trust Return to Free/Plus"
    if not _service_exists("wireproxy"):
        return False, title, "wireproxy tidak ditemukan. Jalankan setup.sh terlebih dulu."

    with file_lock(WARP_LOCK_FILE):
        snapshot = _capture_warp_runtime_snapshot()
        target = _warp_tier_reconnect_target_get()
        if target not in {"free", "plus"}:
            return (
                False,
                title,
                "Target Free/Plus belum diketahui. Gunakan Switch ke WARP Free atau Switch ke WARP Plus dulu agar target consumer tersimpan jelas.",
            )
        ok_disc, msg_disc = _warp_zero_trust_disconnect_backend()
        if not ok_disc:
            ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, msg_disc
            return False, title, f"{msg_disc}\nRollback WARP gagal:\n{msg_rb}"

        if not _restart_and_wait("wireproxy", timeout_sec=30):
            ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, "wireproxy tidak sehat sesudah kembali ke Free/Plus."
            return False, title, f"wireproxy tidak sehat sesudah kembali ke Free/Plus.\nRollback WARP gagal:\n{msg_rb}"
        if not _warp_wait_live_tier(target, timeout_sec=20):
            ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, f"Live WARP tier tidak sesuai target {target} sesudah kembali ke Free/Plus."
            return False, title, f"Live WARP tier tidak sesuai target {target} sesudah kembali ke Free/Plus.\nRollback WARP gagal:\n{msg_rb}"

        try:
            _network_state_update_many({WARP_MODE_STATE_KEY: "consumer"})
        except Exception as exc:
            ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, f"Gagal menyimpan state Free/Plus: {exc}"
            return False, title, f"Gagal menyimpan state Free/Plus: {exc}\nRollback WARP gagal:\n{msg_rb}"

        ok_refresh, msg_refresh = _ssh_network_apply_runtime()
        if not ok_refresh:
            ok_rb, msg_rb = _restore_warp_runtime_snapshot(snapshot)
            if ok_rb:
                return False, title, f"Kembali ke Free/Plus berhasil, tetapi refresh SSH Network gagal:\n{msg_refresh}"
            return False, title, f"Kembali ke Free/Plus berhasil, tetapi refresh SSH Network gagal:\n{msg_refresh}\nRollback WARP gagal:\n{msg_rb}"

    return True, title, f"Host dikembalikan ke Free/Plus (target: {target}).\n\n{_warp_tier_status_message()}"


def op_ssh_network_dns_set_enabled(enabled: bool) -> tuple[bool, str, str]:
    title = "SSH Network - DNS for SSH"
    snapshot = {
        "env": _snapshot_optional_file(ADBLOCK_ENV_FILE),
        "dnsmasq": _snapshot_optional_file(_adblock_dnsmasq_conf_path()),
    }
    with file_lock(ADBLOCK_LOCK_FILE):
        ok_env, msg_env = _adblock_update_env_many({"SSH_DNS_ADBLOCK_ENABLED": "1" if enabled else "0"})
        if not ok_env:
            return False, title, msg_env
        ok_apply, msg_apply = _ssh_dns_resolver_apply_now()
        if not ok_apply:
            _restore_optional_file(ADBLOCK_ENV_FILE, snapshot["env"])
            _restore_optional_file(_adblock_dnsmasq_conf_path(), snapshot["dnsmasq"])
            _ssh_dns_resolver_apply_now()
            return False, title, msg_apply
    state = "diaktifkan" if enabled else "dinonaktifkan"
    return True, title, f"DNS steering SSH berhasil {state}."


def op_ssh_network_dns_set_primary(value: str) -> tuple[bool, str, str]:
    title = "SSH Network - Set Primary DNS"
    try:
        primary = _normalize_ip_literal(value)
    except Exception:
        return False, title, "Primary DNS SSH harus IPv4/IPv6 literal."
    secondary = _adblock_env_value("SSH_DNS_ADBLOCK_UPSTREAM_SECONDARY", "8.8.8.8")
    snapshot = {
        "env": _snapshot_optional_file(ADBLOCK_ENV_FILE),
        "dnsmasq": _snapshot_optional_file(_adblock_dnsmasq_conf_path()),
    }
    with file_lock(ADBLOCK_LOCK_FILE):
        ok_env, msg_env = _adblock_update_env_many(
            {
                "SSH_DNS_ADBLOCK_UPSTREAM_PRIMARY": primary,
                "SSH_DNS_ADBLOCK_UPSTREAM_SECONDARY": _normalize_ip_literal(secondary),
            }
        )
        if not ok_env:
            return False, title, msg_env
        ok_apply, msg_apply = _ssh_dns_resolver_apply_now()
        if not ok_apply:
            _restore_optional_file(ADBLOCK_ENV_FILE, snapshot["env"])
            _restore_optional_file(_adblock_dnsmasq_conf_path(), snapshot["dnsmasq"])
            _ssh_dns_resolver_apply_now()
            return False, title, msg_apply
    return True, title, f"Primary DNS SSH diubah ke {primary}."


def op_ssh_network_dns_set_secondary(value: str) -> tuple[bool, str, str]:
    title = "SSH Network - Set Secondary DNS"
    try:
        secondary = _normalize_ip_literal(value)
    except Exception:
        return False, title, "Secondary DNS SSH harus IPv4/IPv6 literal."
    primary = _adblock_env_value("SSH_DNS_ADBLOCK_UPSTREAM_PRIMARY", "1.1.1.1")
    snapshot = {
        "env": _snapshot_optional_file(ADBLOCK_ENV_FILE),
        "dnsmasq": _snapshot_optional_file(_adblock_dnsmasq_conf_path()),
    }
    with file_lock(ADBLOCK_LOCK_FILE):
        ok_env, msg_env = _adblock_update_env_many(
            {
                "SSH_DNS_ADBLOCK_UPSTREAM_PRIMARY": _normalize_ip_literal(primary),
                "SSH_DNS_ADBLOCK_UPSTREAM_SECONDARY": secondary,
            }
        )
        if not ok_env:
            return False, title, msg_env
        ok_apply, msg_apply = _ssh_dns_resolver_apply_now()
        if not ok_apply:
            _restore_optional_file(ADBLOCK_ENV_FILE, snapshot["env"])
            _restore_optional_file(_adblock_dnsmasq_conf_path(), snapshot["dnsmasq"])
            _ssh_dns_resolver_apply_now()
            return False, title, msg_apply
    return True, title, f"Secondary DNS SSH diubah ke {secondary}."


def op_ssh_network_dns_apply_runtime() -> tuple[bool, str, str]:
    title = "SSH Network - Apply DNS Runtime"
    snapshot = _snapshot_optional_file(_adblock_dnsmasq_conf_path())
    with file_lock(ADBLOCK_LOCK_FILE):
        ok_apply, msg_apply = _ssh_dns_resolver_apply_now()
        if not ok_apply:
            ok_rb, msg_rb = _ssh_dns_resolver_restore_dnsmasq_snapshot(snapshot)
            if ok_rb:
                return False, title, msg_apply
            return False, title, f"{msg_apply}\nRollback DNS SSH gagal:\n{msg_rb}"
    return True, title, "Runtime DNS SSH berhasil disinkronkan."


def op_ssh_network_set_global_mode(mode: str) -> tuple[bool, str, str]:
    title = "SSH Network - Routing SSH Global"
    mode_n = str(mode or "").strip().lower()
    if mode_n not in {"direct", "warp"}:
        return False, title, "Mode routing SSH harus direct/warp."
    with file_lock(SSH_NETWORK_LOCK_FILE):
        current_mode = _ssh_network_env_map().get("SSH_NETWORK_ROUTE_GLOBAL", "direct").strip().lower()
        if current_mode == mode_n:
            return True, title, f"Routing SSH global sudah {mode_n.upper()}; runtime tidak diubah."
        snapshot = _ssh_network_snapshot()
        account_snapshots = _ssh_snapshot_account_info_files()
        ok_env, msg_env = _ssh_network_update_env_many({"SSH_NETWORK_ROUTE_GLOBAL": mode_n})
        if not ok_env:
            return False, title, msg_env
        ok_apply, msg_apply = _ssh_network_apply_runtime(skip_network_lock=True)
        if not ok_apply:
            _ssh_network_restore_snapshot(snapshot)
            _ssh_network_apply_runtime(skip_network_lock=True)
            return False, title, msg_apply
        with _user_data_mutation_lock():
            ok_refresh, refresh_msg = _ssh_refresh_all_account_info()
        if not ok_refresh:
            _ssh_network_restore_snapshot(snapshot)
            ok_rb_apply, msg_rb_apply = _ssh_network_apply_runtime(skip_network_lock=True)
            ok_rb_files, msg_rb_files = _ssh_restore_account_info_snapshots(account_snapshots)
            notes: list[str] = [f"refresh account-info: {refresh_msg}"]
            if not ok_rb_apply:
                notes.append(f"rollback runtime: {msg_rb_apply}")
            if not ok_rb_files:
                notes.append(f"rollback account-info: {msg_rb_files}")
            return False, title, " | ".join(notes)
    return True, title, f"Routing SSH global diubah ke {mode_n.upper()}."


def op_ssh_network_set_backend(backend: str) -> tuple[bool, str, str]:
    title = "SSH Network - Save WARP Backend"
    backend_n = str(backend or "").strip().lower()
    if backend_n not in {"auto", "local-proxy", "interface"}:
        return False, title, "Backend WARP SSH harus auto/local-proxy/interface."
    ok_guard, msg_guard = _ssh_network_require_backend_compatible(backend_n)
    if not ok_guard:
        return False, title, msg_guard
    with file_lock(SSH_NETWORK_LOCK_FILE):
        current_backend = _ssh_network_backend_get()
        if current_backend == backend_n:
            return True, title, f"Backend WARP SSH sudah {backend_n}; config tidak diubah."
        ok_env, msg_env = _ssh_network_update_env_many({"SSH_NETWORK_WARP_BACKEND": backend_n})
        if not ok_env:
            return False, title, msg_env
    return True, title, (
        f"Backend WARP SSH disimpan: {backend_n}. "
        "Jalankan Apply Routing Runtime untuk merekonsiliasi runtime."
    )


def op_ssh_network_apply_runtime() -> tuple[bool, str, str]:
    title = "SSH Network - Apply Routing Runtime"
    ok_apply, msg_apply = _ssh_network_apply_runtime()
    if not ok_apply:
        return False, title, msg_apply
    with _user_data_mutation_lock():
        ok_refresh, refresh_msg = _ssh_refresh_all_account_info()
    if not ok_refresh:
        return False, title, f"Runtime routing SSH berhasil disinkronkan, tetapi refresh SSH ACCOUNT INFO gagal: {refresh_msg}"
    return True, title, "Runtime routing SSH berhasil disinkronkan."


def op_ssh_network_set_user_route_mode(username: str, mode: str) -> tuple[bool, str, str]:
    title = "SSH Network - Routing SSH Per-User"
    target_user = str(username or "").strip()
    mode_n = str(mode or "").strip().lower()
    target = _resolve_existing(_quota_candidates(SSH_PROTOCOL, target_user))
    snapshot = _snapshot_optional_file(target) if isinstance(target, Path) else {"exists": False}
    account_path = SSH_ACCOUNT_DIR / f"{target_user}@{SSH_PROTOCOL}.txt"
    account_snapshot = _snapshot_optional_file(account_path)
    with _user_data_mutation_lock():
        ok_set, msg_set = _ssh_network_user_route_mode_set(target_user, mode_n)
        if not ok_set:
            return False, title, msg_set
        ok_apply, msg_apply = _ssh_network_apply_runtime()
        if not ok_apply:
            restored_path = target or SSH_QUOTA_DIR / f"{target_user}@{SSH_PROTOCOL}.json"
            _restore_optional_file(restored_path, snapshot)
            _restore_optional_file(account_path, account_snapshot)
            _ssh_network_apply_runtime()
            return False, title, msg_apply
        ok_refresh, refresh_msg = _ssh_refresh_account_info(target_user)
        if not ok_refresh:
            restored_path = target or SSH_QUOTA_DIR / f"{target_user}@{SSH_PROTOCOL}.json"
            _restore_optional_file(restored_path, snapshot)
            _restore_optional_file(account_path, account_snapshot)
            _ssh_network_apply_runtime()
            return False, title, f"Gagal refresh SSH ACCOUNT INFO untuk '{target_user}': {refresh_msg}"
    return True, title, f"Routing SSH '{target_user}' diubah ke {mode_n}."


def op_ssh_network_set_warp_global(enabled: bool) -> tuple[bool, str, str]:
    return op_ssh_network_set_global_mode("warp" if enabled else "direct")


def op_ssh_network_set_warp_user_mode(username: str, mode: str) -> tuple[bool, str, str]:
    title = "SSH Network - WARP SSH Per-User"
    ok_op, _, msg = op_ssh_network_set_user_route_mode(username, mode)
    if not ok_op:
        return False, title, msg
    target_user = str(username or "").strip()
    if mode == "warp":
        return True, title, f"Mode WARP SSH '{target_user}' diubah ke warp."
    if mode == "direct":
        return True, title, f"Mode WARP SSH '{target_user}' diubah ke direct."
    return True, title, f"Mode WARP SSH '{target_user}' dikembalikan ke inherit."


def op_network_set_dns_primary(value: str) -> tuple[bool, str, str]:
    title = "Network Controls - Set Primary DNS"
    val = str(value or "").strip()
    ok_apply, msg_apply = _apply_dns_transaction(lambda cfg: _dns_set_primary(cfg, val))
    if not ok_apply:
        return False, title, msg_apply
    return True, title, msg_apply


def op_network_set_dns_secondary(value: str) -> tuple[bool, str, str]:
    title = "Network Controls - Set Secondary DNS"
    val = str(value or "").strip()
    ok_apply, msg_apply = _apply_dns_transaction(lambda cfg: _dns_set_secondary(cfg, val))
    if not ok_apply:
        return False, title, msg_apply
    return True, title, msg_apply


def op_network_set_dns_query_strategy(strategy: str) -> tuple[bool, str, str]:
    title = "Network Controls - Set DNS Query Strategy"
    strategy_n = str(strategy or "").strip()
    ok_apply, msg_apply = _apply_dns_transaction(lambda cfg: _dns_set_query_strategy(cfg, strategy_n))
    if not ok_apply:
        return False, title, msg_apply
    return True, title, msg_apply


def op_network_toggle_dns_cache() -> tuple[bool, str, str]:
    title = "Network Controls - Toggle DNS Cache"
    ok_apply, msg_apply = _apply_dns_transaction(_dns_toggle_cache)
    if not ok_apply:
        return False, title, msg_apply
    return True, title, msg_apply


def _adblock_restore_runtime_state(*, xray_enabled: bool, ssh_enabled: bool) -> tuple[bool, str]:
    notes: list[str] = []
    target_mode = "blocked" if xray_enabled else "off"
    ok_xray, msg_xray = _adblock_set_xray_rule(target_mode)
    if not ok_xray:
        notes.append(f"rollback Xray gagal: {msg_xray}")
    ok_env, msg_env = _adblock_update_env_many({"SSH_DNS_ADBLOCK_ENABLED": "1" if ssh_enabled else "0"})
    if not ok_env:
        notes.append(f"rollback config SSH gagal: {msg_env}")
    else:
        ok_apply, msg_apply = _adblock_apply_now()
        if not ok_apply:
            notes.append(f"rollback SSH apply gagal: {msg_apply}")
    if notes:
        return False, " | ".join(notes)
    return True, "ok"


def op_network_adblock_enable() -> tuple[bool, str, str]:
    title = "Network - Enable Adblock"
    with file_lock(ADBLOCK_LOCK_FILE):
        status = _adblock_status_map()
        dirty = status.get("dirty", "0") == "1"
        rendered_ready = status.get("rendered_file", "missing") == "ready"
        custom_ready = status.get("custom_dat", "missing") == "ready"
        xray_enabled = str(_adblock_xray_rule_state().get("enabled") or "0") == "1"

        if dirty or not rendered_ready or not custom_ready:
            ok_update, msg_update = _adblock_update_now(reload_xray=xray_enabled)
            if not ok_update:
                return False, title, f"Update Adblock gagal. Enable dibatalkan.\n{msg_update}"
            status = _adblock_status_map()
            if status.get("custom_dat", "missing") != "ready":
                return False, title, "custom.dat belum siap. Enable dibatalkan."

        ok_xray, msg_xray = _adblock_set_xray_rule("blocked")
        if not ok_xray:
            return False, title, msg_xray

        ok_env, msg_env = _adblock_update_env_many({"SSH_DNS_ADBLOCK_ENABLED": "1"})
        if not ok_env:
            ok_rb, msg_rb = _adblock_restore_runtime_state(xray_enabled=xray_enabled, ssh_enabled=False)
            if ok_rb:
                return False, title, msg_env
            return False, title, f"{msg_env}\nRollback gagal:\n{msg_rb}"

        ok_apply, msg_apply = _adblock_apply_now()
        if not ok_apply:
            ok_rb, msg_rb = _adblock_restore_runtime_state(xray_enabled=xray_enabled, ssh_enabled=False)
            if ok_rb:
                return False, title, f"DNS Adblock SSH gagal diterapkan.\n{msg_apply}"
            return False, title, f"DNS Adblock SSH gagal diterapkan.\n{msg_apply}\nRollback gagal:\n{msg_rb}"
    return True, title, "Adblock diaktifkan (shared source -> Xray + SSH)."


def op_network_adblock_disable() -> tuple[bool, str, str]:
    title = "Network - Disable Adblock"
    with file_lock(ADBLOCK_LOCK_FILE):
        previous_xray_enabled = str(_adblock_xray_rule_state().get("enabled") or "0") == "1"
        previous_ssh_enabled = _adblock_status_map().get("enabled", "0") == "1"
        ok_xray, msg_xray = _adblock_set_xray_rule("off")
        ok_env, msg_env = _adblock_update_env_many({"SSH_DNS_ADBLOCK_ENABLED": "0"})
        ok_apply, msg_apply = _adblock_apply_now()

    if ok_xray and ok_env and ok_apply:
        return True, title, "Adblock dinonaktifkan (Xray + SSH)."

    parts = []
    if not ok_xray:
        parts.append(f"Xray: {msg_xray}")
    if not ok_env:
        parts.append(f"Config: {msg_env}")
    if not ok_apply:
        parts.append(f"SSH: {msg_apply}")
    rollback_notes: list[str] = []
    ok_rb, msg_rb = _adblock_restore_runtime_state(
        xray_enabled=previous_xray_enabled,
        ssh_enabled=previous_ssh_enabled,
    )
    if not ok_rb:
        rollback_notes.append(msg_rb)
    if rollback_notes:
        parts.append("Rollback: " + " | ".join(rollback_notes))
    return False, title, "Adblock nonaktif sebagian.\n" + "\n".join(parts)


def op_network_adblock_add_domain(domain: str) -> tuple[bool, str, str]:
    title = "Network - Adblock Add Domain"
    normalized = _adblock_manual_domain_normalize(domain)
    if not normalized:
        return False, title, "Domain tidak valid."
    blocklist_path = _adblock_path_from_env("SSH_DNS_ADBLOCK_BLOCKLIST_FILE", ADBLOCK_DEFAULT_BLOCKLIST)
    with file_lock(ADBLOCK_LOCK_FILE):
        snapshot = _snapshot_optional_file(blocklist_path)
        current = []
        seen: set[str] = set()
        for raw in _adblock_read_lines(blocklist_path):
            item = _adblock_manual_domain_normalize(raw)
            if not item or item in seen:
                continue
            seen.add(item)
            current.append(item)
        if normalized in seen:
            return False, title, "Domain sudah ada."
        current.append(normalized)
        ok_write, msg_write = _adblock_write_unique_lines(blocklist_path, current)
        if not ok_write:
            return False, title, msg_write
        ok_dirty, msg_dirty = _adblock_mark_dirty()
        if not ok_dirty:
            ok_restore, msg_restore = _restore_adblock_source_snapshot(blocklist_path, snapshot)
            if not ok_restore:
                return False, title, f"{msg_dirty}\nRollback source gagal: {msg_restore}"
            return False, title, msg_dirty
    return True, title, f"Domain ditambahkan: {normalized}\nJalankan Update Adblock untuk build artifact baru."


def op_network_adblock_delete_domain(domain: str) -> tuple[bool, str, str]:
    title = "Network - Adblock Delete Domain"
    normalized = _adblock_manual_domain_normalize(domain)
    if not normalized:
        return False, title, "Domain tidak valid."
    blocklist_path = _adblock_path_from_env("SSH_DNS_ADBLOCK_BLOCKLIST_FILE", ADBLOCK_DEFAULT_BLOCKLIST)
    with file_lock(ADBLOCK_LOCK_FILE):
        snapshot = _snapshot_optional_file(blocklist_path)
        current = []
        found = False
        seen: set[str] = set()
        for raw in _adblock_read_lines(blocklist_path):
            item = _adblock_manual_domain_normalize(raw)
            if not item or item in seen:
                continue
            seen.add(item)
            if item == normalized:
                found = True
                continue
            current.append(item)
        if not found:
            return False, title, f"Domain tidak ditemukan: {normalized}"
        ok_write, msg_write = _adblock_write_unique_lines(blocklist_path, current)
        if not ok_write:
            return False, title, msg_write
        ok_dirty, msg_dirty = _adblock_mark_dirty()
        if not ok_dirty:
            ok_restore, msg_restore = _restore_adblock_source_snapshot(blocklist_path, snapshot)
            if not ok_restore:
                return False, title, f"{msg_dirty}\nRollback source gagal: {msg_restore}"
            return False, title, msg_dirty
    return True, title, f"Domain dihapus: {normalized}\nJalankan Update Adblock untuk build artifact baru."


def op_network_adblock_add_url_source(url: str) -> tuple[bool, str, str]:
    title = "Network - Adblock Add URL Source"
    normalized = _adblock_url_normalize(url)
    if not normalized:
        return False, title, "URL tidak valid."
    urls_path = _adblock_path_from_env("SSH_DNS_ADBLOCK_URLS_FILE", ADBLOCK_DEFAULT_URLS)
    with file_lock(ADBLOCK_LOCK_FILE):
        snapshot = _snapshot_optional_file(urls_path)
        current = []
        seen: set[str] = set()
        for raw in _adblock_read_lines(urls_path):
            item = _adblock_url_normalize(raw)
            if not item or item in seen:
                continue
            seen.add(item)
            current.append(item)
        if normalized in seen:
            return False, title, "URL source sudah ada."
        current.append(normalized)
        ok_write, msg_write = _adblock_write_unique_lines(urls_path, current)
        if not ok_write:
            return False, title, msg_write
        ok_dirty, msg_dirty = _adblock_mark_dirty()
        if not ok_dirty:
            ok_restore, msg_restore = _restore_adblock_source_snapshot(urls_path, snapshot)
            if not ok_restore:
                return False, title, f"{msg_dirty}\nRollback source gagal: {msg_restore}"
            return False, title, msg_dirty
    return True, title, f"URL source ditambahkan: {normalized}\nJalankan Update Adblock untuk build artifact baru."


def op_network_adblock_delete_url_source(url: str) -> tuple[bool, str, str]:
    title = "Network - Adblock Delete URL Source"
    normalized = _adblock_url_normalize(url)
    if not normalized:
        return False, title, "URL tidak valid."
    urls_path = _adblock_path_from_env("SSH_DNS_ADBLOCK_URLS_FILE", ADBLOCK_DEFAULT_URLS)
    with file_lock(ADBLOCK_LOCK_FILE):
        snapshot = _snapshot_optional_file(urls_path)
        current = []
        found = False
        seen: set[str] = set()
        for raw in _adblock_read_lines(urls_path):
            item = _adblock_url_normalize(raw)
            if not item or item in seen:
                continue
            seen.add(item)
            if item == normalized:
                found = True
                continue
            current.append(item)
        if not found:
            return False, title, f"URL source tidak ditemukan: {normalized}"
        ok_write, msg_write = _adblock_write_unique_lines(urls_path, current)
        if not ok_write:
            return False, title, msg_write
        ok_dirty, msg_dirty = _adblock_mark_dirty()
        if not ok_dirty:
            ok_restore, msg_restore = _restore_adblock_source_snapshot(urls_path, snapshot)
            if not ok_restore:
                return False, title, f"{msg_dirty}\nRollback source gagal: {msg_restore}"
            return False, title, msg_dirty
    return True, title, f"URL source dihapus: {normalized}\nJalankan Update Adblock untuk build artifact baru."


def op_network_adblock_update() -> tuple[bool, str, str]:
    title = "Network - Update Adblock"
    with file_lock(ADBLOCK_LOCK_FILE):
        xray_enabled = str(_adblock_xray_rule_state().get("enabled") or "0") == "1"
        ok_update, msg_update = _adblock_update_now(reload_xray=xray_enabled)
        if not ok_update:
            return False, title, msg_update
    return True, title, "Adblock sources diperbarui dan artifact runtime dibangun ulang."


def op_network_adblock_toggle_auto_update() -> tuple[bool, str, str]:
    title = "Network - Toggle Auto Update"
    with file_lock(ADBLOCK_LOCK_FILE):
        timer_name = _adblock_auto_update_timer_name()
        timer_path = _adblock_timer_path()
        if not timer_path.exists():
            return False, title, f"Timer auto update belum tersedia: {timer_path}"

        enabled = _adblock_status_map().get("auto_update_enabled", "0") == "1"
        target_value = "0" if enabled else "1"
        ok_env, msg_env = _adblock_update_env_many({"AUTOSCRIPT_ADBLOCK_AUTO_UPDATE_ENABLED": target_value})
        if not ok_env:
            return False, title, msg_env

        if target_value == "1":
            ok_cmd, out_cmd = _run_cmd(["systemctl", "enable", "--now", timer_name], timeout=30)
            if not ok_cmd:
                rollback_notes: list[str] = []
                ok_rb_env, msg_rb_env = _adblock_update_env_many({"AUTOSCRIPT_ADBLOCK_AUTO_UPDATE_ENABLED": "0"})
                if not ok_rb_env:
                    rollback_notes.append(f"restore env gagal: {msg_rb_env}")
                ok_rb_cmd, out_rb_cmd = _run_cmd(["systemctl", "disable", "--now", timer_name], timeout=30)
                if not ok_rb_cmd:
                    rollback_notes.append(f"disable timer rollback gagal: {out_rb_cmd}")
                ok_rb_state, msg_rb_state = _adblock_timer_rollback_verify(timer_name, enabled=False)
                if not ok_rb_state:
                    rollback_notes.append(msg_rb_state)
                if rollback_notes:
                    return False, title, f"{out_cmd}\nRollback gagal:\n" + "\n".join(rollback_notes)
                return False, title, out_cmd
            ok_state, msg_state = _adblock_timer_state_matches(timer_name, enabled=True)
            if not ok_state:
                rollback_notes = []
                ok_rb_env, msg_rb_env = _adblock_update_env_many({"AUTOSCRIPT_ADBLOCK_AUTO_UPDATE_ENABLED": "0"})
                if not ok_rb_env:
                    rollback_notes.append(f"restore env gagal: {msg_rb_env}")
                ok_rb_cmd, out_rb_cmd = _run_cmd(["systemctl", "disable", "--now", timer_name], timeout=30)
                if not ok_rb_cmd:
                    rollback_notes.append(f"disable timer rollback gagal: {out_rb_cmd}")
                ok_rb_state, msg_rb_state = _adblock_timer_rollback_verify(timer_name, enabled=False)
                if not ok_rb_state:
                    rollback_notes.append(msg_rb_state)
                if rollback_notes:
                    return False, title, f"{msg_state}\nRollback gagal:\n" + "\n".join(rollback_notes)
                return False, title, msg_state
            return True, title, "Auto Update Adblock diaktifkan."

        ok_cmd, out_cmd = _run_cmd(["systemctl", "disable", "--now", timer_name], timeout=30)
        if not ok_cmd:
            rollback_notes = []
            ok_rb_env, msg_rb_env = _adblock_update_env_many({"AUTOSCRIPT_ADBLOCK_AUTO_UPDATE_ENABLED": "1"})
            if not ok_rb_env:
                rollback_notes.append(f"restore env gagal: {msg_rb_env}")
            ok_rb_cmd, out_rb_cmd = _run_cmd(["systemctl", "enable", "--now", timer_name], timeout=30)
            if not ok_rb_cmd:
                rollback_notes.append(f"enable timer rollback gagal: {out_rb_cmd}")
            ok_rb_state, msg_rb_state = _adblock_timer_rollback_verify(timer_name, enabled=True)
            if not ok_rb_state:
                rollback_notes.append(msg_rb_state)
            if rollback_notes:
                return False, title, f"{out_cmd}\nRollback gagal:\n" + "\n".join(rollback_notes)
            return False, title, out_cmd
        ok_state, msg_state = _adblock_timer_state_matches(timer_name, enabled=False)
        if not ok_state:
            rollback_notes = []
            ok_rb_env, msg_rb_env = _adblock_update_env_many({"AUTOSCRIPT_ADBLOCK_AUTO_UPDATE_ENABLED": "1"})
            if not ok_rb_env:
                rollback_notes.append(f"restore env gagal: {msg_rb_env}")
            ok_rb_cmd, out_rb_cmd = _run_cmd(["systemctl", "enable", "--now", timer_name], timeout=30)
            if not ok_rb_cmd:
                rollback_notes.append(f"enable timer rollback gagal: {out_rb_cmd}")
            ok_rb_state, msg_rb_state = _adblock_timer_rollback_verify(timer_name, enabled=True)
            if not ok_rb_state:
                rollback_notes.append(msg_rb_state)
            if rollback_notes:
                return False, title, f"{msg_state}\nRollback gagal:\n" + "\n".join(rollback_notes)
            return False, title, msg_state
        return True, title, "Auto Update Adblock dinonaktifkan."


def op_network_adblock_set_auto_update_days(days: int) -> tuple[bool, str, str]:
    title = "Network - Set Auto Update Interval"
    if int(days) < 1:
        return False, title, "Interval harus berupa angka hari, minimal 1."
    with file_lock(ADBLOCK_LOCK_FILE):
        timer_name = _adblock_auto_update_timer_name()
        previous_days = _adblock_env_value("AUTOSCRIPT_ADBLOCK_AUTO_UPDATE_DAYS", "1")
        previous_days_int = int(previous_days) if str(previous_days).isdigit() else 1
        timer_was_enabled = _adblock_status_map().get("auto_update_enabled", "0") == "1"
        ok_env, msg_env = _adblock_update_env_many({"AUTOSCRIPT_ADBLOCK_AUTO_UPDATE_DAYS": str(int(days))})
        if not ok_env:
            return False, title, msg_env
        ok_timer, msg_timer = _adblock_auto_update_timer_write(int(days))
        if not ok_timer:
            rollback_notes: list[str] = []
            ok_rb_env, msg_rb_env = _adblock_update_env_many({"AUTOSCRIPT_ADBLOCK_AUTO_UPDATE_DAYS": previous_days})
            if not ok_rb_env:
                rollback_notes.append(f"restore env hari gagal: {msg_rb_env}")
            ok_rb_timer, msg_rb_timer = _adblock_auto_update_timer_write(previous_days_int)
            if not ok_rb_timer:
                rollback_notes.append(f"restore timer file gagal: {msg_rb_timer}")
            ok_rb_state, msg_rb_state = _adblock_timer_rollback_verify(
                timer_name,
                enabled=timer_was_enabled,
                expected_days=previous_days_int,
            )
            if not ok_rb_state:
                rollback_notes.append(msg_rb_state)
            if rollback_notes:
                return False, title, f"{msg_timer}\nRollback gagal:\n" + "\n".join(rollback_notes)
            return False, title, msg_timer
        if _adblock_status_map().get("auto_update_enabled", "0") == "1":
            ok_restart, out_restart = _run_cmd(["systemctl", "restart", timer_name], timeout=30)
            if not ok_restart:
                rollback_notes = []
                ok_rb_env, msg_rb_env = _adblock_update_env_many({"AUTOSCRIPT_ADBLOCK_AUTO_UPDATE_DAYS": previous_days})
                if not ok_rb_env:
                    rollback_notes.append(f"restore env hari gagal: {msg_rb_env}")
                ok_rb_timer, msg_rb_timer = _adblock_auto_update_timer_write(previous_days_int)
                if not ok_rb_timer:
                    rollback_notes.append(f"restore timer file gagal: {msg_rb_timer}")
                ok_rb_restart, out_rb_restart = _run_cmd(["systemctl", "restart", timer_name], timeout=30)
                if not ok_rb_restart:
                    rollback_notes.append(f"restart timer rollback gagal: {out_rb_restart}")
                ok_rb_state, msg_rb_state = _adblock_timer_rollback_verify(
                    timer_name,
                    enabled=timer_was_enabled,
                    expected_days=previous_days_int,
                )
                if not ok_rb_state:
                    rollback_notes.append(msg_rb_state)
                if rollback_notes:
                    return False, title, f"{out_restart}\nRollback gagal:\n" + "\n".join(rollback_notes)
                return False, title, out_restart
            ok_state, msg_state = _adblock_timer_state_matches(timer_name, enabled=True)
            ok_days, msg_days = _adblock_timer_days_matches(int(days))
            if not ok_state or not ok_days:
                rollback_notes = []
                ok_rb_env, msg_rb_env = _adblock_update_env_many({"AUTOSCRIPT_ADBLOCK_AUTO_UPDATE_DAYS": previous_days})
                if not ok_rb_env:
                    rollback_notes.append(f"restore env hari gagal: {msg_rb_env}")
                ok_rb_timer, msg_rb_timer = _adblock_auto_update_timer_write(previous_days_int)
                if not ok_rb_timer:
                    rollback_notes.append(f"restore timer file gagal: {msg_rb_timer}")
                ok_rb_restart, out_rb_restart = _run_cmd(["systemctl", "restart", timer_name], timeout=30)
                if not ok_rb_restart:
                    rollback_notes.append(f"restart timer rollback gagal: {out_rb_restart}")
                ok_rb_state, msg_rb_state = _adblock_timer_rollback_verify(
                    timer_name,
                    enabled=timer_was_enabled,
                    expected_days=previous_days_int,
                )
                if not ok_rb_state:
                    rollback_notes.append(msg_rb_state)
                failure_msg = msg_state if not ok_state else msg_days
                if rollback_notes:
                    return False, title, f"{failure_msg}\nRollback gagal:\n" + "\n".join(rollback_notes)
                return False, title, failure_msg
    return True, title, f"Interval Auto Update di-set setiap {int(days)} hari."
