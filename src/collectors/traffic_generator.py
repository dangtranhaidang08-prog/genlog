from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import http.cookiejar
from pathlib import Path
import random
import re
import socket
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
import json

import pandas as pd

try:
    import paramiko  # type: ignore
except ImportError:
    paramiko = None

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config import (  # noqa: E402
    PAYLOADS_ALL_CSV,
    RAW_LOG_FILE,
    RUNS_DATA_DIR,
    CLIENT_REQUESTS_CSV,
    TARGET_WEB_URL,
    REMOTE_SSH_HOST,
    REMOTE_SSH_PORT,
    REMOTE_SSH_USER,
    REMOTE_SSH_PASS,
    REMOTE_LOG_PATH
)


class CollectionStatus(str, Enum):
    SUCCESS_WITH_LINES = "SUCCESS_WITH_LINES"
    SUCCESS_EMPTY = "SUCCESS_EMPTY"
    FAILED_CONNECT = "FAILED_CONNECT"
    FAILED_AUTH = "FAILED_AUTH"
    FAILED_PERMISSION = "FAILED_PERMISSION"
    FAILED_PATH = "FAILED_PATH"
    FAILED_COMMAND = "FAILED_COMMAND"
    FAILED_ROTATION = "FAILED_ROTATION"
    DISABLED = "DISABLED"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"


class TrafficGeneratorError(Exception):
    pass


class ConfigurationError(TrafficGeneratorError):
    pass


class DatasetValidationError(TrafficGeneratorError):
    pass


class AuthenticationError(TrafficGeneratorError):
    pass


class CollectionError(TrafficGeneratorError):
    pass


@dataclass
class TrafficConfig:
    target_url: str = TARGET_WEB_URL
    ssh_host: Optional[str] = REMOTE_SSH_HOST
    ssh_port: int = REMOTE_SSH_PORT
    ssh_user: str = REMOTE_SSH_USER
    ssh_pass: Optional[str] = REMOTE_SSH_PASS
    ssh_key_path: Optional[str] = None
    ssh_known_hosts: Optional[str] = None
    remote_log_path: str = REMOTE_LOG_PATH
    workers: int = 5
    delay: float = 0.02
    rate_limit_rps: Optional[float] = None
    timeout_sec: float = 5.0
    count: Optional[int] = None
    dataset_path: Path = PAYLOADS_ALL_CSV
    runs_dir: Path = RUNS_DATA_DIR
    enable_ssh_collection: bool = True
    dvwa_user: str = "admin"
    dvwa_pass: str = "password"
    security_level: str = "low"
    run_id: str = field(
        default_factory=lambda: f"run_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{random.randint(1000, 9999)}"
    )

    def validate(self) -> None:
        if not self.target_url or not isinstance(self.target_url, str):
            raise ConfigurationError("Target web URL must be a non-empty string.")
        parsed = urllib.parse.urlparse(self.target_url)
        if parsed.scheme not in ("http", "https"):
            raise ConfigurationError(f"Target URL must use http or https scheme, got: {self.target_url}")
        if not parsed.netloc:
            raise ConfigurationError(f"Target URL has no valid hostname/netloc: {self.target_url}")
        if parsed.username or parsed.password:
            raise ConfigurationError("Target URL must not contain embedded user:pass credentials.")

        if self.enable_ssh_collection:
            if not self.ssh_host or not isinstance(self.ssh_host, str):
                raise ConfigurationError("REMOTE_SSH_HOST must be explicitly configured when SSH collection is enabled.")
            if not (1 <= self.ssh_port <= 65535):
                raise ConfigurationError(f"SSH port must be in range 1-65535, got: {self.ssh_port}")
            if not self.ssh_user:
                raise ConfigurationError("REMOTE_SSH_USER must be configured for SSH collection.")
            if not self.remote_log_path:
                raise ConfigurationError("REMOTE_LOG_PATH must be configured when SSH collection is enabled.")

        if not (1 <= self.workers <= 20):
            raise ConfigurationError(f"Worker concurrency must be between 1 and 20, got: {self.workers}")
        if self.delay < 0:
            raise ConfigurationError(f"Inter-request delay cannot be negative, got: {self.delay}")
        if self.timeout_sec <= 0:
            raise ConfigurationError(f"Request timeout must be positive, got: {self.timeout_sec}")

        if self.count is not None and self.count <= 0:
            raise DatasetValidationError(f"Sample count must be a positive integer or None (all samples), got: {self.count}")


@dataclass
class HTTPRequestSpec:
    method: str
    url: str
    path: str
    query: str
    body_bytes: Optional[bytes]
    headers: Dict[str, str]

    @property
    def body(self) -> str:
        if self.body_bytes is None:
            return ""
        try:
            return self.body_bytes.decode("utf-8", errors="replace")
        except Exception:
            return ""

    @property
    def content_type(self) -> str:
        return self.headers.get("Content-Type", "")

    def __iter__(self):
        yield self.method
        yield self.path
        yield self.query
        yield self.body
        yield self.content_type
        yield self.headers


@dataclass
class SSHLogCollectionResult:
    status: CollectionStatus
    lines_collected: int = 0
    error_message: Optional[str] = None
    start_line: int = 0
    end_line: int = 0
    output_path: Optional[Path] = None


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0"
]


def load_and_validate_dataset(
    csv_path: Path,
    count: Optional[int] = None,
    seed: int = 42
) -> pd.DataFrame:
    if not csv_path.exists():
        raise DatasetValidationError(f"Payload dataset CSV file not found: {csv_path}")

    try:
        df = pd.read_csv(csv_path).fillna("")
    except Exception as e:
        raise DatasetValidationError(f"Failed to read CSV dataset at {csv_path}: {e}")

    if len(df) == 0:
        raise DatasetValidationError(f"Dataset CSV file is empty: {csv_path}")

    required_cols = {"payload", "label"}
    missing = required_cols - set(df.columns)
    if missing:
        raise DatasetValidationError(f"Dataset missing required columns {missing}. Found: {list(df.columns)}")

    valid_labels = {0, 1, "0", "1", 0.0, 1.0}
    unique_labels = set(df["label"].unique())
    if not unique_labels.issubset(valid_labels):
        raise DatasetValidationError(f"Invalid label values detected: {unique_labels - valid_labels}. Expected binary labels (0/1).")

    if count is not None:
        if count <= 0:
            raise DatasetValidationError(f"Requested count must be a positive integer, got: {count}")
        if count > len(df):
            sample_df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
        else:
            sample_df = df.sample(n=count, random_state=seed).reset_index(drop=True)
    else:
        sample_df = df.reset_index(drop=True)

    return sample_df


def authenticate_dvwa(
    target_url: str,
    username: str = "admin",
    password: str = "password",
    security_level: str = "low",
    timeout: float = 6.0
) -> Tuple[http.cookiejar.CookieJar, str]:
    base_url = target_url.rstrip("/")
    login_url = f"{base_url}/login.php"
    security_url = f"{base_url}/security.php"

    cj = http.cookiejar.CookieJar()
    cookie_handler = urllib.request.HTTPCookieProcessor(cj)
    opener = urllib.request.build_opener(cookie_handler)

    try:
        req = urllib.request.Request(
            login_url,
            headers={"User-Agent": USER_AGENTS[0]}
        )
        with opener.open(req, timeout=timeout) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        raise AuthenticationError(f"Cannot reach DVWA login page at {login_url}: {e}")

    token_match = (
        re.search(r"name=['\"]user_token['\"]\s+value=['\"]([a-f0-9]{32})['\"]", html)
        or re.search(r"user_token'\s+value='([a-f0-9]{32})'", html)
    )
    user_token = token_match.group(1) if token_match else ""

    login_payload = {
        "username": username,
        "password": password,
        "Login": "Login"
    }
    if user_token:
        login_payload["user_token"] = user_token

    login_data = urllib.parse.urlencode(login_payload).encode("utf-8")
    login_req = urllib.request.Request(
        login_url,
        data=login_data,
        headers={
            "User-Agent": USER_AGENTS[0],
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": login_url
        }
    )

    try:
        with opener.open(login_req, timeout=timeout) as resp:
            login_resp_body = resp.read().decode("utf-8", errors="ignore")
            if "login failed" in login_resp_body.lower() or '<form action="login.php"' in login_resp_body:
                raise AuthenticationError("DVWA login failed: Invalid credentials or rejected login.")
    except Exception as e:
        if isinstance(e, AuthenticationError):
            raise
        raise AuthenticationError(f"DVWA POST login failed: {e}")

    cookie_dict = {c.name: c.value for c in cj}
    if "PHPSESSID" not in cookie_dict:
        raise AuthenticationError("No PHPSESSID session cookie received from DVWA after login.")

    sec_url_get = f"{security_url}?security={security_level}&seclev_submit=Submit"
    sec_req = urllib.request.Request(
        sec_url_get,
        headers={
            "User-Agent": USER_AGENTS[0],
            "Referer": security_url
        }
    )
    try:
        with opener.open(sec_req, timeout=timeout) as resp:
            resp.read()
    except Exception:
        pass

    probe_url = f"{base_url}/vulnerabilities/sqli/?id=1&Submit=Submit"
    probe_req = urllib.request.Request(
        probe_url,
        headers={"User-Agent": USER_AGENTS[0]}
    )
    try:
        with opener.open(probe_req, timeout=timeout) as resp:
            probe_html = resp.read().decode("utf-8", errors="ignore")
            if '<form action="login.php"' in probe_html or "Login :: Damn Vulnerable Web Application" in probe_html:
                raise AuthenticationError("DVWA probe redirected to login page. Session invalid or credentials rejected.")
            if resp.getcode() != 200:
                raise AuthenticationError(f"DVWA probe returned unexpected HTTP status {resp.getcode()}")
    except Exception as e:
        if isinstance(e, AuthenticationError):
            raise
        raise AuthenticationError(f"DVWA authentication verification failed on {probe_url}: {e}")

    cookie_items = [f"{c.name}={c.value}" for c in cj]
    cookie_header = "; ".join(cookie_items)
    if "security=" not in cookie_header:
        cookie_header += f"; security={security_level}"
    else:
        cookie_header = re.sub(r"security=[^;]+", f"security={security_level}", cookie_header)

    return cj, cookie_header


def convert_payload_to_http_request(
    payload: str,
    family_id: str = "",
    attack_type: str = "",
    label: int = 1,
    target_url: str = TARGET_WEB_URL,
    cookie_header: str = "",
    user_agent: str = USER_AGENTS[0],
    rng: Optional[random.Random] = None
) -> HTTPRequestSpec:
    base = target_url.rstrip("/")
    payload_str = str(payload).strip()
    headers = {
        "User-Agent": user_agent,
        "Cookie": cookie_header,
        "Referer": f"{base}/"
    }

    if label == 0:
        if payload_str.startswith("/") or payload_str.endswith((".css", ".png", ".jpg", ".js", ".ico", ".php")):
            path = payload_str if payload_str.startswith("/") else f"/{payload_str}"
            full_url = f"{base}{path}"
            return HTTPRequestSpec("GET", full_url, path, "", None, headers)

        if "=" in payload_str:
            path = "/vulnerabilities/sqli/"
            encoded_query = payload_str
            full_url = f"{base}{path}?{encoded_query}"
            return HTTPRequestSpec("GET", full_url, path, encoded_query, None, headers)

        r = rng.random() if rng else 0.5
        if r < 0.60:
            path = "/vulnerabilities/sqli/"
            params = [("id", payload_str), ("Submit", "Submit")]
            encoded_query = urllib.parse.urlencode(params, safe="()", quote_via=urllib.parse.quote)
            full_url = f"{base}{path}?{encoded_query}"
            return HTTPRequestSpec("GET", full_url, path, encoded_query, None, headers)
        elif r < 0.85:
            path = "/vulnerabilities/sqli_blind/"
            params = [("id", payload_str), ("Submit", "Submit")]
            encoded_query = urllib.parse.urlencode(params, safe="()", quote_via=urllib.parse.quote)
            full_url = f"{base}{path}?{encoded_query}"
            return HTTPRequestSpec("GET", full_url, path, encoded_query, None, headers)
        else:
            path = "/instructions.php"
            params = [("doc", payload_str)]
            encoded_query = urllib.parse.urlencode(params, safe="()", quote_via=urllib.parse.quote)
            full_url = f"{base}{path}?{encoded_query}"
            return HTTPRequestSpec("GET", full_url, path, encoded_query, None, headers)

    if family_id == "FAMILY_AUTH_BYPASS" or "login" in attack_type.lower():
        r = rng.random() if rng else 0.5
        if r < 0.50:
            path = "/login.php"
            form_params = [
                ("username", payload_str),
                ("password", "password"),
                ("Login", "Login")
            ]
            body_bytes = urllib.parse.urlencode(form_params, safe="()").encode("utf-8")
            post_headers = dict(headers)
            post_headers["Content-Type"] = "application/x-www-form-urlencoded"
            full_url = f"{base}{path}"
            return HTTPRequestSpec("POST", full_url, path, "", body_bytes, post_headers)
        else:
            path = "/vulnerabilities/sqli/"
            params = [("id", payload_str), ("Submit", "Submit")]
            encoded_query = urllib.parse.urlencode(params, safe="()", quote_via=urllib.parse.quote)
            full_url = f"{base}{path}?{encoded_query}"
            return HTTPRequestSpec("GET", full_url, path, encoded_query, None, headers)

    elif family_id in ["FAMILY_BLIND_TIME_SLEEP", "FAMILY_BLIND_BOOLEAN_SUBSTR"]:
        path = "/vulnerabilities/sqli_blind/"
        params = [("id", payload_str), ("Submit", "Submit")]
        encoded_query = urllib.parse.urlencode(params, safe="()", quote_via=urllib.parse.quote)
        full_url = f"{base}{path}?{encoded_query}"
        return HTTPRequestSpec("GET", full_url, path, encoded_query, None, headers)

    else:
        r = rng.random() if rng else 0.5
        path = "/vulnerabilities/sqli_blind/" if r < 0.20 else "/vulnerabilities/sqli/"
        params = [("id", payload_str), ("Submit", "Submit")]
        encoded_query = urllib.parse.urlencode(params, safe="()", quote_via=urllib.parse.quote)
        full_url = f"{base}{path}?{encoded_query}"
        return HTTPRequestSpec("GET", full_url, path, encoded_query, None, headers)


def send_single_live_request(
    spec: HTTPRequestSpec,
    task_meta: Dict[str, Any],
    timeout_sec: float = 5.0,
    delay: float = 0.0
) -> Dict[str, Any]:
    if delay > 0:
        time.sleep(delay)

    payload_lower = str(task_meta.get("payload", "")).lower()
    actual_timeout = timeout_sec
    if "sleep" in payload_lower or "benchmark" in payload_lower:
        sleep_match = re.search(r"sleep\s*\(\s*(\d+)\s*\)", payload_lower)
        if sleep_match:
            actual_timeout = max(timeout_sec, float(sleep_match.group(1)) + 3.0)
        else:
            actual_timeout = max(timeout_sec, 8.0)

    t_start = time.perf_counter()
    status_code: Optional[int] = None
    transport_error: Optional[str] = None
    request_success: bool = False
    resp_size = 0
    final_url: Optional[str] = None
    is_redirect = False

    try:
        req = urllib.request.Request(
            spec.url,
            data=spec.body_bytes,
            headers=spec.headers,
            method=spec.method
        )
        with urllib.request.urlopen(req, timeout=actual_timeout) as resp:
            status_code = resp.getcode()
            resp_bytes = resp.read()
            resp_size = len(resp_bytes)
            final_url = resp.geturl()
            request_success = True
            if final_url and "login.php" in final_url and spec.path != "/login.php":
                is_redirect = True

    except urllib.error.HTTPError as e:
        status_code = e.code
        request_success = True
        final_url = e.geturl() if hasattr(e, "geturl") else spec.url
        try:
            resp_size = len(e.read())
        except Exception:
            resp_size = 0

    except urllib.error.URLError as e:
        status_code = None
        request_success = False
        transport_error = f"URLError: {e.reason}"

    except (socket.timeout, TimeoutError):
        status_code = None
        request_success = False
        transport_error = f"TimeoutError (exceeded {actual_timeout}s)"

    except Exception as e:
        status_code = None
        request_success = False
        transport_error = f"{type(e).__name__}: {str(e)}"

    elapsed_ms = round((time.perf_counter() - t_start) * 1000.0, 2)
    timestamp_utc = datetime.now(timezone.utc).isoformat()

    return {
        "run_id": task_meta.get("run_id", ""),
        "sample_id": task_meta.get("sample_id", 0),
        "request_id": task_meta.get("request_id", ""),
        "timestamp_utc": timestamp_utc,
        "method": spec.method,
        "url": spec.url,
        "path": spec.path,
        "status_code": status_code,
        "transport_error": transport_error,
        "request_success": request_success,
        "response_time_ms": elapsed_ms,
        "response_size_bytes": resp_size,
        "final_url": final_url or spec.url,
        "is_redirect": is_redirect,
        "payload": task_meta.get("payload", ""),
        "expected_label": task_meta.get("label", 0),
        "family_id": task_meta.get("family_id", ""),
        "attack_type": task_meta.get("attack_type", "")
    }


def get_remote_apache_log_state(
    host: str,
    port: int,
    user: str,
    password: Optional[str],
    key_path: Optional[str],
    known_hosts: Optional[str],
    log_path: str
) -> Tuple[int, Optional[str], Optional[str]]:
    if paramiko is None:
        return 0, None, "paramiko is not installed"

    ssh = None
    try:
        ssh = paramiko.SSHClient()
        if known_hosts and Path(known_hosts).exists():
            ssh.load_host_keys(known_hosts)
            ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            ssh.load_system_host_keys()
            ssh.set_missing_host_key_policy(paramiko.WarningPolicy())

        connect_kwargs: Dict[str, Any] = {
            "hostname": host,
            "port": port,
            "username": user,
            "timeout": 6
        }
        if key_path and Path(key_path).exists():
            connect_kwargs["key_filename"] = key_path
        elif password:
            connect_kwargs["password"] = password

        ssh.connect(**connect_kwargs)

        cmd = f"wc -l {log_path} && stat -c %i {log_path}"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()

        if "No such file" in err:
            return 0, None, f"Remote log path not found: {log_path}"
        if "Permission denied" in err:
            return 0, None, f"Permission denied reading remote log: {log_path}"

        lines = out.splitlines()
        line_cnt = 0
        inode = None
        if lines:
            parts = lines[0].split()
            if parts and parts[0].isdigit():
                line_cnt = int(parts[0])
        if len(lines) > 1 and lines[1].strip().isdigit():
            inode = lines[1].strip()

        return line_cnt, inode, None

    except paramiko.AuthenticationException:
        return 0, None, f"SSH authentication failed for {user}@{host}"
    except Exception as e:
        return 0, None, f"SSH connection failed to {host}:{port}: {e}"
    finally:
        if ssh:
            ssh.close()


def fetch_incremental_apache_log(
    config: TrafficConfig,
    start_line: int,
    start_inode: Optional[str],
    run_dir: Path
) -> SSHLogCollectionResult:
    if not config.enable_ssh_collection:
        return SSHLogCollectionResult(status=CollectionStatus.DISABLED, lines_collected=0)

    if paramiko is None:
        return SSHLogCollectionResult(
            status=CollectionStatus.DISABLED,
            lines_collected=0,
            error_message="paramiko library not installed"
        )

    end_line, end_inode, err = get_remote_apache_log_state(
        host=config.ssh_host or "",
        port=config.ssh_port,
        user=config.ssh_user,
        password=config.ssh_pass,
        key_path=config.ssh_key_path,
        known_hosts=config.ssh_known_hosts,
        log_path=config.remote_log_path
    )

    if err:
        status = CollectionStatus.FAILED_CONNECT
        if "Permission denied" in err:
            status = CollectionStatus.FAILED_PERMISSION
        elif "No such file" in err:
            status = CollectionStatus.FAILED_PATH
        elif "authentication failed" in err:
            status = CollectionStatus.FAILED_AUTH

        return SSHLogCollectionResult(
            status=status,
            lines_collected=0,
            error_message=err,
            start_line=start_line,
            end_line=0
        )

    if start_inode and end_inode and start_inode != end_inode:
        return SSHLogCollectionResult(
            status=CollectionStatus.FAILED_ROTATION,
            lines_collected=0,
            error_message=f"Log file was rotated (inode changed from {start_inode} to {end_inode})",
            start_line=start_line,
            end_line=end_line
        )

    if end_line < start_line:
        return SSHLogCollectionResult(
            status=CollectionStatus.FAILED_ROTATION,
            lines_collected=0,
            error_message=f"Log file was truncated (start lines: {start_line}, end lines: {end_line})",
            start_line=start_line,
            end_line=end_line
        )

    if end_line == start_line:
        return SSHLogCollectionResult(
            status=CollectionStatus.SUCCESS_EMPTY,
            lines_collected=0,
            start_line=start_line,
            end_line=end_line
        )

    from_line = start_line + 1
    to_line = end_line
    ssh = None
    try:
        ssh = paramiko.SSHClient()
        if config.ssh_known_hosts and Path(config.ssh_known_hosts).exists():
            ssh.load_host_keys(config.ssh_known_hosts)
            ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            ssh.load_system_host_keys()
            ssh.set_missing_host_key_policy(paramiko.WarningPolicy())

        connect_kwargs: Dict[str, Any] = {
            "hostname": config.ssh_host,
            "port": config.ssh_port,
            "username": config.ssh_user,
            "timeout": 8
        }
        if config.ssh_key_path and Path(config.ssh_key_path).exists():
            connect_kwargs["key_filename"] = config.ssh_key_path
        elif config.ssh_pass:
            connect_kwargs["password"] = config.ssh_pass

        ssh.connect(**connect_kwargs)

        cmd = f"sed -n '{from_line},{to_line}p' {config.remote_log_path}"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        err_msg = stderr.read().decode().strip()
        raw_bytes = stdout.read()

        if "Permission denied" in err_msg:
            return SSHLogCollectionResult(
                status=CollectionStatus.FAILED_PERMISSION,
                lines_collected=0,
                error_message=err_msg,
                start_line=start_line,
                end_line=end_line
            )

        run_log_path = run_dir / "access.log"
        with open(run_log_path, "wb") as f:
            f.write(raw_bytes)

        RAW_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(RAW_LOG_FILE, "wb") as f:
            f.write(raw_bytes)

        lines_count = len(raw_bytes.decode("utf-8", errors="ignore").splitlines())
        return SSHLogCollectionResult(
            status=CollectionStatus.SUCCESS_WITH_LINES,
            lines_collected=lines_count,
            start_line=start_line,
            end_line=end_line,
            output_path=run_log_path
        )

    except Exception as e:
        return SSHLogCollectionResult(
            status=CollectionStatus.UNKNOWN_ERROR,
            lines_collected=0,
            error_message=f"Failed to extract log slice: {e}",
            start_line=start_line,
            end_line=end_line
        )
    finally:
        if ssh:
            ssh.close()


def run_traffic_pipeline(config: TrafficConfig) -> Dict[str, Any]:
    config.validate()

    start_time_utc = datetime.now(timezone.utc)
    run_dir = config.runs_dir / config.run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    df = load_and_validate_dataset(config.dataset_path, count=config.count)
    print(f"[*] Replaying {len(df):,} requests -> {config.target_url} (Workers: {config.workers}, Run: {config.run_id})...")

    _, cookie_header = authenticate_dvwa(
        target_url=config.target_url,
        username=config.dvwa_user,
        password=config.dvwa_pass,
        security_level=config.security_level,
        timeout=config.timeout_sec
    )

    start_lines = 0
    start_inode = None
    if config.enable_ssh_collection and config.ssh_host:
        start_lines, start_inode, _ = get_remote_apache_log_state(
            host=config.ssh_host,
            port=config.ssh_port,
            user=config.ssh_user,
            password=config.ssh_pass,
            key_path=config.ssh_key_path,
            known_hosts=config.ssh_known_hosts,
            log_path=config.remote_log_path
        )

    tasks = []
    for idx, row_dict in enumerate(df.to_dict(orient="records")):
        ua = random.choice(USER_AGENTS)
        task_meta = {
            "run_id": config.run_id,
            "sample_id": idx,
            "request_id": f"{config.run_id}_{idx:06d}",
            "payload": str(row_dict.get("payload", "")),
            "label": int(row_dict.get("label", 0)),
            "family_id": str(row_dict.get("family_id", "")),
            "attack_type": str(row_dict.get("attack_type", row_dict.get("category", "")))
        }
        spec = convert_payload_to_http_request(
            payload=task_meta["payload"],
            family_id=task_meta["family_id"],
            attack_type=task_meta["attack_type"],
            label=task_meta["label"],
            target_url=config.target_url,
            cookie_header=cookie_header,
            user_agent=ua,
            rng=random.Random(idx + 1337)
        )
        tasks.append((spec, task_meta, config.timeout_sec, config.delay))

    records: List[Dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=config.workers) as executor:
        futures = {executor.submit(send_single_live_request, *t): t[1]["sample_id"] for t in tasks}
        for future in as_completed(futures):
            try:
                rec = future.result()
                records.append(rec)
            except Exception as e:
                records.append({
                    "run_id": config.run_id,
                    "sample_id": -1,
                    "request_id": "error",
                    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                    "method": "UNKNOWN",
                    "url": config.target_url,
                    "path": "/",
                    "status_code": None,
                    "transport_error": f"WorkerException: {str(e)}",
                    "request_success": False,
                    "response_time_ms": 0.0,
                    "response_size_bytes": 0,
                    "is_redirect": False,
                    "payload": "",
                    "expected_label": -1,
                    "family_id": "",
                    "attack_type": ""
                })

    records.sort(key=lambda x: x["sample_id"])

    client_df = pd.DataFrame(records)
    run_client_path = run_dir / "client_requests.csv"
    client_df.to_csv(run_client_path, index=False, encoding="utf-8")

    CLIENT_REQUESTS_CSV.parent.mkdir(parents=True, exist_ok=True)
    client_df.to_csv(CLIENT_REQUESTS_CSV, index=False, encoding="utf-8")

    collection_result = SSHLogCollectionResult(status=CollectionStatus.DISABLED)
    if config.enable_ssh_collection and config.ssh_host:
        time.sleep(1.0)
        collection_result = fetch_incremental_apache_log(
            config=config,
            start_line=start_lines,
            start_inode=start_inode,
            run_dir=run_dir
        )

    end_time_utc = datetime.now(timezone.utc)
    duration_sec = round((end_time_utc - start_time_utc).total_seconds(), 2)

    responses_received = sum(1 for r in records if r["request_success"])
    transport_failures = len(records) - responses_received
    status_distribution = client_df["status_code"].value_counts(dropna=False).to_dict()
    status_distribution_clean = {
        str(k) if pd.notna(k) else "None": int(v)
        for k, v in status_distribution.items()
    }

    metadata = {
        "run_id": config.run_id,
        "start_time_utc": start_time_utc.isoformat(),
        "end_time_utc": end_time_utc.isoformat(),
        "duration_sec": duration_sec,
        "target_url": config.target_url,
        "ssh_host": config.ssh_host,
        "ssh_port": config.ssh_port,
        "remote_log_path": config.remote_log_path,
        "dataset_path": str(config.dataset_path),
        "client_telemetry_path": str(run_client_path),
        "apache_log_path": str(collection_result.output_path) if collection_result.output_path else None,
        "samples_requested": len(df),
        "requests_attempted": len(records),
        "responses_received": responses_received,
        "transport_failures": transport_failures,
        "status_distribution": status_distribution_clean,
        "apache_collection_status": collection_result.status.value,
        "apache_lines_collected": collection_result.lines_collected,
        "apache_collection_error": collection_result.error_message,
        "workers": config.workers,
        "delay": config.delay,
        "timeout_sec": config.timeout_sec
    }

    metadata_path = run_dir / "run_metadata.json"
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    apache_info = f"{collection_result.lines_collected:,} lines" if collection_result.status == CollectionStatus.SUCCESS_WITH_LINES else collection_result.status.value
    print(f"[+] Hoan thanh: {len(client_df):,} requests ({responses_received:,} ok, {transport_failures:,} err) | Apache: {apache_info} | Run: {run_dir.name}")

    return {
        **metadata,
        "client_telemetry_path": run_client_path,
        "metadata_path": metadata_path,
        "apache_log_path": collection_result.output_path
    }


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="DVWA Live Network Traffic Generator (Research-Grade)")
    parser.add_argument("--target", type=str, default=TARGET_WEB_URL, help="Target DVWA Base URL")
    parser.add_argument("--count", type=int, default=None, help="Number of payload samples to replay (0 or omit for all)")
    parser.add_argument("--workers", type=int, default=5, help="Number of concurrent worker threads (1-20)")
    parser.add_argument("--delay", type=float, default=0.02, help="Inter-request delay in seconds")
    parser.add_argument("--no-ssh", action="store_true", help="Disable remote Apache access log collection via SSH")

    args = parser.parse_args()
    sample_count = None if (args.count is None or args.count == 0) else args.count

    config = TrafficConfig(
        target_url=args.target,
        count=sample_count,
        workers=args.workers,
        delay=args.delay,
        enable_ssh_collection=not args.no_ssh
    )
    try:
        run_traffic_pipeline(config)
    except TrafficGeneratorError as e:
        print(f"\n[FATAL PIPELINE ERROR] {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
