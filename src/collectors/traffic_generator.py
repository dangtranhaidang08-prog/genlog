"""
Live HTTP Traffic Generator for DVWA Web Server.
Sends live HTTP requests to local/remote DVWA server and records access log entries for ML pipeline ingestion.
"""
import argparse
import random
import sys
import time
import urllib.parse
import urllib.request
import pandas as pd
from pathlib import Path
from typing import Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

try:
    from src.config import PAYLOADS_ALL_CSV, RAW_LOG_FILE, RAW_LOGS_DIR
except ImportError:
    from config import PAYLOADS_ALL_CSV, RAW_LOG_FILE, RAW_LOGS_DIR

def convert_payload_to_http_request(payload: str, attack_type: str = "", rng: random.Random = None) -> Tuple[str, str, str, str, str, str]:
    """
    Convert payload string into HTTP request components:
    returns (method, url, path, query, body, content_type)
    """
    payload_str = str(payload).strip()
    is_json = payload_str.startswith(("{", "[")) or "json" in attack_type.lower()

    if is_json:
        method = "POST"
        content_type = "application/json"
        api_paths = ["/api/v1/query", "/api/v1/search", "/api/v1/auth", "/api/v1/users", "/rest/items", "/api/v1/profile"]
        path = rng.choice(api_paths) if rng else "/api/v1/query"
        query = ""
        body = payload_str
        url = f"http://127.0.0.1{path}"
        return method, url, path, query, body, content_type

    # 25% of regular form payloads sent as POST form-urlencoded
    if rng and rng.random() < 0.25 and ("=" in payload_str or "auth" in attack_type.lower()):
        method = "POST"
        content_type = "application/x-www-form-urlencoded"
        form_paths = ["/login.php", "/vulnerabilities/sqli/", "/search.php", "/vulnerabilities/sqli_blind/"]
        path = rng.choice(form_paths)
        query = ""
        body = payload_str
        url = f"http://127.0.0.1{path}"
        return method, url, path, query, body, content_type

    # Standard GET request
    method = "GET"
    content_type = ""
    body = ""

    if payload_str.startswith("http://") or payload_str.startswith("https://"):
        url = payload_str
        parsed = urllib.parse.urlparse(url)
        path = parsed.path
        query = parsed.query
        return method, url, path, query, body, content_type

    unquoted = urllib.parse.unquote_plus(payload_str)

    if "?" in payload_str:
        parts = payload_str.split("?", 1)
        path = parts[0]
        query = parts[1]
        if not path.startswith("/"):
            path = "/" + path
        url = f"http://127.0.0.1{path}?{query}"
    elif "=" in unquoted:
        path = "/vulnerabilities/sqli/"
        query = payload_str
        url = f"http://127.0.0.1{path}?{query}"
    else:
        path = "/vulnerabilities/sqli/"
        query = f"id={payload_str}&Submit=Submit"
        url = f"http://127.0.0.1{path}?{query}"

    return method, url, path, query, body, content_type

def run_live_http_traffic(df: pd.DataFrame, target_url: str, delay: float = 0.05, count: int = 0, output_log_path: Path = RAW_LOG_FILE):
    """
    Send live HTTP requests to DVWA environment and record raw log entries.
    """
    if count and count > 0:
        sample_df = df.sample(n=min(count, len(df)), random_state=42)
    else:
        sample_df = df  # Lấy TẤT CẢ 100% payload từ tập dữ liệu sinh ra

    print(f"Sending ALL {len(sample_df)} live HTTP requests from payloads directory to {target_url} (delay: {delay}s)...")

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15"
    ]

    # Check target connectivity
    is_live = False
    try:
        test_req = urllib.request.Request(target_url, headers={"User-Agent": "DVWA-ML-TrafficGenerator/1.0"})
        with urllib.request.urlopen(test_req, timeout=1.0) as test_resp:
            if test_resp.getcode() in [200, 302]:
                is_live = True
    except Exception:
        is_live = False

    if is_live:
        print(f"Connected to live target {target_url}. Sending live HTTP traffic...")
    else:
        print(f"Target {target_url} is offline/unreachable. Running in Fast Offline Log Generator mode (no timeout lag)...")

    records = []
    success_cnt = 0
    fail_cnt = 0
    rng = random.Random(42)

    for idx, row in sample_df.iterrows():
        payload = str(row["payload"])
        attack_type = str(row["attack_type"])
        label = int(row["label"])

        method, _, path, query, body, content_type = convert_payload_to_http_request(payload, attack_type, rng)
        full_target = f"{target_url.rstrip('/')}{path}"
        if query:
            safe_query = urllib.parse.quote(query, safe="=&%+/:-_?#*()'\"")
            full_target += f"?{safe_query}"

        status_code = 200
        start_t = time.time()

        if is_live:
            try:
                headers = {"User-Agent": "DVWA-ML-TrafficGenerator/1.0"}
                data_bytes = None
                if method == "POST" and body:
                    data_bytes = body.encode("utf-8")
                    if content_type:
                        headers["Content-Type"] = content_type

                req = urllib.request.Request(
                    full_target,
                    data=data_bytes,
                    headers=headers,
                    method=method
                )
                with urllib.request.urlopen(req, timeout=3.0) as response:
                    status_code = response.getcode()
                success_cnt += 1
                if (idx + 1) % 100 == 0:
                    print(f"[{idx + 1}/{len(sample_df)}] Live request sent -> Status {status_code}")
            except Exception as e:
                fail_cnt += 1
                status_code = e.code if hasattr(e, 'code') else 502
        else:
            success_cnt += 1
            status_code = 200
            if (idx + 1) % 2000 == 0 or idx == len(sample_df) - 1:
                print(f"[{idx + 1}/{len(sample_df)}] Generated log entry for {method} {full_target[:45]}...")

        resp_time_us = int((time.time() - start_t) * 1000000)
        timestamp = time.strftime("%d/%b/%Y:%H:%M:%S +0700", time.localtime())
        ip = "192.168.145.135"
        size = rng.randint(500, 4500)
        ua = rng.choice(user_agents)
        referer = f"{target_url.rstrip('/')}/"

        req_line = f"{method} {path}"
        if query:
            req_line += f"?{query}"
        req_line += " HTTP/1.1"

        raw_log = f'{ip} - - [{timestamp}] "{req_line}" {status_code} {size} "{referer}" "{ua}" {resp_time_us}'

        records.append({
            "timestamp": timestamp,
            "source_ip": ip,
            "method": method,
            "path": path,
            "query": query,
            "body": body,
            "content_type": content_type,
            "status_code": status_code,
            "response_size": size,
            "response_time_us": resp_time_us,
            "user_agent": ua,
            "referer": referer,
            "payload": payload,
            "payload_type": attack_type,
            "label": label,
            "binary_label": label,
            "raw_log": raw_log
        })

        if delay > 0:
            time.sleep(delay)

    RAW_LOGS_DIR.mkdir(parents=True, exist_ok=True)
    log_df = pd.DataFrame(records)
    log_df.to_csv(output_log_path, index=False, encoding="utf-8")

    print(f"\nLive Traffic Execution Finished: {success_cnt} succeeded, {fail_cnt} failed.")
    print(f"Saved {len(log_df)} raw log entries to: {output_log_path}")

def main():
    parser = argparse.ArgumentParser(description="DVWA Live HTTP Traffic Generator & Access Log Collector")
    parser.add_argument("--dataset", type=str, default=str(PAYLOADS_ALL_CSV), help="Path to payload CSV file")
    parser.add_argument("--target", type=str, default="http://127.0.0.1/dvwa", help="Target URL (Default: http://127.0.0.1/dvwa)")
    parser.add_argument("--count", type=int, default=0, help="Number of samples to send (0 = send ALL payloads from directory, Default: 0)")
    parser.add_argument("--delay", type=float, default=0.01, help="Delay between live requests in seconds (Default: 0.01)")

    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        print(f"ERROR: Dataset CSV file {dataset_path} not found. Run `python src/collectors/dvwa_generator/payload_generator.py` first!")
        sys.exit(1)

    df = pd.read_csv(dataset_path)
    run_live_http_traffic(df, args.target, delay=args.delay, count=args.count)

if __name__ == "__main__":
    main()
