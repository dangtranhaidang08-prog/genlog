import json
import re
import urllib.parse
import sys
import pandas as pd
from pathlib import Path

# Add project root to sys.path if executed directly
file_path = Path(__file__).resolve()
project_root = file_path.parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

try:
    from src.config import RAW_LOG_FILE, PARSED_LOG_CSV, DATA_DIR
except ImportError:
    from config import RAW_LOG_FILE, PARSED_LOG_CSV, DATA_DIR

# Combined Log Format Regex Pattern (with optional response_time at the end)
LOG_PATTERN = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\d+|-)(?:\s+"([^"]*)"\s+"([^"]*)")?(?:\s+(\d+))?$'
)

def flatten_json_values(data) -> list:
    """Recursively extract all key and string/numeric values from nested JSON structures."""
    values = []
    if isinstance(data, dict):
        for k, v in data.items():
            values.append(str(k))
            values.extend(flatten_json_values(v))
    elif isinstance(data, list):
        for item in data:
            values.extend(flatten_json_values(item))
    elif data is not None:
        values.append(str(data))
    return values

def calculate_json_depth(data) -> int:
    """Calculate the maximum nesting depth of a JSON structure."""
    if isinstance(data, dict):
        return 1 + (max((calculate_json_depth(v) for v in data.values()), default=0) if data else 0)
    elif isinstance(data, list):
        return 1 + (max((calculate_json_depth(item) for item in data), default=0) if data else 0)
    return 0

def parse_request_string(request_str: str, body: str = "", content_type: str = ""):
    """
    Parse request line and request body (GET query + POST form / JSON) into components.
    """
    if not request_str or request_str == "-":
        return "", "", "", "", "", "", "", "", "", 0, 0, 0

    parts = request_str.strip().split()
    if len(parts) == 1:
        method, raw_url, protocol = parts[0], "", ""
    elif len(parts) == 2:
        method, raw_url, protocol = parts[0], parts[1], ""
    else:
        method = parts[0]
        protocol = parts[-1]
        raw_url = " ".join(parts[1:-1])

    parsed = urllib.parse.urlparse(raw_url)
    path = parsed.path
    query = parsed.query

    decoded_url = urllib.parse.unquote_plus(raw_url)
    decoded_path = urllib.parse.unquote_plus(path)
    decoded_query = urllib.parse.unquote_plus(query)

    # Parse Request Body (JSON or Form-urlencoded)
    decoded_body = ""
    is_json = 0
    json_depth = 0
    param_count_body = 0

    if body and str(body).strip():
        body_clean = str(body).strip()
        is_json_type = "json" in content_type.lower() or body_clean.startswith(("{", "["))
        if is_json_type:
            try:
                parsed_json = json.loads(body_clean)
                is_json = 1
                json_depth = calculate_json_depth(parsed_json)
                flat_vals = flatten_json_values(parsed_json)
                decoded_body = " ".join(flat_vals)
                param_count_body = len(parsed_json) if isinstance(parsed_json, (dict, list)) else len(flat_vals)
            except Exception:
                decoded_body = urllib.parse.unquote_plus(body_clean)
                is_json = 1
                json_depth = 1
                param_count_body = 1
        else:
            decoded_body = urllib.parse.unquote_plus(body_clean)
            is_json = 0
            json_depth = 0
            param_count_body = len(urllib.parse.parse_qs(body_clean))

    return (
        method, raw_url, path, query, protocol,
        decoded_url, decoded_query, body, decoded_body,
        is_json, json_depth, param_count_body
    )

def parse_raw_line(line: str, body: str = "", content_type: str = ""):
    """
    Parse a single raw Apache log line with optional body and content_type into a record dictionary.
    """
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None

    ip = match.group(1)
    timestamp = match.group(2)
    request_str = match.group(3)
    status = int(match.group(4))
    size = 0 if match.group(5) == "-" else int(match.group(5))
    referer = match.group(6) if match.group(6) else "-"
    user_agent = match.group(7) if match.group(7) else "-"
    response_time = int(match.group(8)) if match.group(8) else 0

    (
        method, url, path, query, protocol,
        decoded_url, decoded_query, raw_body, decoded_body,
        is_json, json_depth, param_count_body
    ) = parse_request_string(request_str, body=body, content_type=content_type)

    return {
        "ip": ip,
        "timestamp": timestamp,
        "method": method,
        "url": url,
        "path": path,
        "query": query,
        "protocol": protocol,
        "status": status,
        "size": size,
        "response_time": response_time,
        "referer": referer,
        "user_agent": user_agent,
        "decoded_url": decoded_url,
        "decoded_query": decoded_query,
        "body": raw_body,
        "decoded_body": decoded_body,
        "content_type": content_type,
        "is_json_payload": is_json,
        "json_depth": json_depth,
        "param_count_body": param_count_body
    }

def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not RAW_LOG_FILE.exists():
        print(f"ERROR: Log file not found at {RAW_LOG_FILE}")
        return

    # Check if raw_logs/access.log is a pre-formatted CSV file or standard Apache text log
    with open(RAW_LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        first_line = f.readline()

    parsed_records = []
    failed_lines = 0

    if "raw_log" in first_line or "response_time_us" in first_line:
        print(f"Detected CSV-formatted log file ({RAW_LOG_FILE}). Reading CSV dataset...")
        raw_df = pd.read_csv(RAW_LOG_FILE).fillna("")
        for idx, row in raw_df.iterrows():
            log_text = row.get("raw_log", "")
            body_val = str(row.get("body", ""))
            ct_val = str(row.get("content_type", ""))
            rec = parse_raw_line(log_text, body=body_val, content_type=ct_val)
            if rec:
                atk = row.get("payload_type", row.get("attack_type", row.get("attack", "normal")))
                lbl = row.get("binary_label", row.get("label", row.get("category", 0)))
                rec["attack_type"] = atk if str(atk).strip() != "" else "normal"
                rec["existing_label"] = int(lbl) if str(lbl).isdigit() else (0 if str(lbl).lower() == "normal" else 1)
                parsed_records.append(rec)
            else:
                failed_lines += 1
    else:
        print(f"Reading standard Apache text log file ({RAW_LOG_FILE})...")
        with open(RAW_LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if not line.strip():
                    continue
                rec = parse_raw_line(line)
                if rec:
                    rec["attack_type"] = "unknown"
                    rec["existing_label"] = -1
                    parsed_records.append(rec)
                else:
                    failed_lines += 1

    df = pd.DataFrame(parsed_records)
    df.to_csv(PARSED_LOG_CSV, index=False, encoding="utf-8")

    print("====================================")
    print("APACHE PARSER STATS")
    print("====================================")
    print(f"Total log lines: {len(parsed_records) + failed_lines}")
    print(f"Successfully parsed: {len(parsed_records)}")
    print(f"Failed: {failed_lines}")
    print(f"Output: {PARSED_LOG_CSV}")
    print("====================================")

    if not df.empty:
        print("DATA VALIDATION")
        print("====================================")
        print(f"Shape: {df.shape}")
        print(f"Columns: {list(df.columns)}")
        print("Missing values:\n", df.isnull().sum())
        print("\nFirst 3 rows preview:")
        print(df[["ip", "method", "path", "query", "status", "attack_type"]].head(3))
        print("====================================")

if __name__ == "__main__":
    main()
