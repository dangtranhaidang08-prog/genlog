import csv
import json
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Tuple, cast
import urllib.parse

import pandas as pd

file_path = Path(__file__).resolve()
project_root = file_path.parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.config import (  # noqa: E402
    DATA_DIR,
    PARSED_LOG_CSV,
    PAYLOADS_ALL_CSV,
    RAW_LOG_FILE,
    CLIENT_REQUESTS_CSV,
    REPORTS_DIR
)

LOG_PATTERN = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"((?:[^"\\]|\\.)*)"\s+(\d{3})\s+(\d+|-)'
    r'(?:\s+"((?:[^"\\]|\\.)*)"\s+"((?:[^"\\]|\\.)*)")?(?:\s+(\d+))?$'
)


def parse_request_string(
    request_str: str,
    body: str = "",
    content_type: str = ""
) -> Tuple[str, str, str, str, str, str, str, str, str, int]:
    if not request_str or request_str == "-":
        return "", "", "", "", "", "", "", "", "", 0

    parts = request_str.strip().split()
    if len(parts) == 1:
        method, raw_url, protocol = parts[0], "", ""
    elif len(parts) == 2:
        method, raw_url, protocol = parts[0], parts[1], ""
    else:
        method = parts[0]
        if re.match(r"^HTTP/\d(\.\d)?$", parts[-1], re.IGNORECASE):
            protocol = parts[-1]
            raw_url = " ".join(parts[1:-1])
        else:
            protocol = ""
            raw_url = " ".join(parts[1:])

    parsed = urllib.parse.urlparse(raw_url)
    path = parsed.path
    query = parsed.query

    decoded_path = urllib.parse.unquote(path)
    decoded_query = urllib.parse.unquote_plus(query)
    if "%25" in query:
        try:
            decoded_query = urllib.parse.unquote_plus(decoded_query)
        except Exception:
            pass

    decoded_url = f"{decoded_path}?{decoded_query}" if query else decoded_path

    decoded_body = ""
    param_count_body = 0

    if body and body.strip():
        body_clean = body.strip()
        decoded_body = urllib.parse.unquote_plus(body_clean)
        param_count_body = len(urllib.parse.parse_qs(body_clean))

    return (
        method, raw_url, path, query, protocol,
        decoded_url, decoded_query, body, decoded_body,
        param_count_body
    )


def parse_raw_line(
    line: str,
    body: str = "",
    content_type: str = ""
) -> Optional[Dict[str, Any]]:
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
        param_count_body
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
        "param_count_body": param_count_body
    }


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    if not RAW_LOG_FILE.exists():
        print(f"ERROR: Log file not found at {RAW_LOG_FILE}")
        return

    with open(RAW_LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        first_line = f.readline()

    parsed_records = []
    failed_lines = 0

    if "raw_log" in first_line or "response_time_us" in first_line:
        print(f"Detected CSV-formatted log file ({RAW_LOG_FILE}). Reading CSV dataset...")
        raw_df = pd.read_csv(RAW_LOG_FILE).fillna("")
        for idx, row in raw_df.iterrows():
            log_text = str(row.get("raw_log", ""))
            body_val = str(row.get("body", ""))
            ct_val = str(row.get("content_type", ""))
            rec = parse_raw_line(log_text, body=body_val, content_type=ct_val)
            if rec:
                atk = row.get("payload_type", row.get("attack_type", row.get("attack", "normal")))
                lbl = row.get("binary_label", row.get("label", row.get("category", 0)))
                rec["attack_type"] = atk if str(atk).strip() != "" else "normal"
                if str(lbl).isdigit():
                    rec["existing_label"] = int(str(lbl))
                else:
                    rec["existing_label"] = 0 if str(lbl).lower() == "normal" else 1
                parsed_records.append(rec)
            else:
                failed_lines += 1
    else:
        print(f"Reading standard Apache text log file ({RAW_LOG_FILE})...")

        post_client_records: List[Dict[str, Any]] = []
        if CLIENT_REQUESTS_CSV.exists():
            try:
                with open(CLIENT_REQUESTS_CSV, "r", encoding="utf-8", errors="ignore") as f_post:
                    reader = csv.DictReader(f_post)
                    post_client_records = [
                        dict(row) for row in reader if str(row.get("method", "")).upper() == "POST"
                    ]
            except Exception:
                post_client_records = []
        post_idx: int = 0

        payload_lookup = {}
        if PAYLOADS_ALL_CSV.exists():
            p_df = pd.read_csv(PAYLOADS_ALL_CSV)

            def add_lookup_key(k_val: str, k_lbl: int, k_atk: str):
                curr = k_val.strip()
                if not curr:
                    return
                for _ in range(3):
                    payload_lookup[curr] = (k_lbl, k_atk)
                    norm_k = re.sub(r'[\s\+]+', '', curr.lower())
                    payload_lookup[norm_k] = (k_lbl, k_atk)
                    nxt = urllib.parse.unquote_plus(curr)
                    if nxt == curr:
                        break
                    curr = nxt

            for _, p_row in p_df.iterrows():
                p_val = str(p_row.get("payload", "")).strip()
                p_atk = str(p_row.get("attack_type", "normal")).strip()
                p_lbl = int(str(p_row.get("label", 0)))

                add_lookup_key(p_val, p_lbl, p_atk)

                unq_val = urllib.parse.unquote_plus(urllib.parse.unquote_plus(p_val))
                token_pat = r'&(Submit=Submit|Login=Login|user_token=[a-f0-9]{32})'
                clean_p = re.sub(token_pat, '', unq_val)
                add_lookup_key(clean_p, p_lbl, p_atk)
                if clean_p.startswith('id='):
                    add_lookup_key(clean_p[3:], p_lbl, p_atk)
                if clean_p.startswith('username='):
                    add_lookup_key('id=' + clean_p, p_lbl, p_atk)
                if '#' in clean_p:
                    add_lookup_key(clean_p.split('#', 1)[0], p_lbl, p_atk)

        token_pat = r'&(Submit=Submit|Login=Login|user_token=[a-f0-9]{32})'
        with open(RAW_LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if not line.strip():
                    continue
                rec = parse_raw_line(line)
                if rec:
                    # Hydrate POST body from client telemetry if available
                    if rec["method"] == "POST" and not rec["body"] and post_idx < len(post_client_records):
                        c_rec: Dict[str, Any] = post_client_records[post_idx]
                        post_idx += 1
                        p_val: str = str(c_rec.get("payload", ""))
                        rec["body"] = f"username={urllib.parse.quote(p_val)}&password=password&Login=Login"
                        rec["decoded_body"] = f"username={p_val}&password=password&Login=Login"
                        rec["content_type"] = "application/x-www-form-urlencoded"
                        rec["param_count_body"] = 3
                        lbl_val = c_rec.get("expected_label")
                        if lbl_val is not None and str(lbl_val).strip() != "":
                            rec["existing_label"] = int(float(str(lbl_val)))
                        else:
                            rec["existing_label"] = 1 if "sqli" in str(c_rec.get("attack_type", "")).lower() else 0
                        rec["attack_type"] = str(c_rec.get("attack_type", "sqli" if rec["existing_label"] == 1 else "normal"))
                        parsed_records.append(rec)
                        continue
                    elif rec["method"] == "POST" and not rec["body"]:
                        rec["existing_label"] = -1
                        rec["attack_type"] = "unknown_post"
                        parsed_records.append(rec)
                        continue

                    dq = str(rec.get("decoded_query", "")).strip()

                    candidates = []
                    curr_q = dq
                    for _ in range(3):
                        candidates.append(curr_q)
                        nxt_q = urllib.parse.unquote_plus(curr_q)
                        if nxt_q == curr_q:
                            break
                        curr_q = nxt_q

                    clean_candidates = []
                    for c in candidates:
                        cl = re.sub(token_pat, '', c)
                        cl = re.sub(r'^(Submit=Submit&|Login=Login&)', '', cl)
                        clean_candidates.append(cl)
                        if cl.startswith('id=id='):
                            clean_candidates.extend([cl[6:], cl[3:]])
                        elif cl.startswith('id=username='):
                            clean_candidates.append(cl[3:])
                        elif cl.startswith('id='):
                            clean_candidates.append(cl[3:])
                        if '#' in cl:
                            clean_candidates.append(cl.split('#', 1)[0])

                    candidates.extend(clean_candidates)

                    matched_label = None
                    matched_atk = None
                    for c in candidates:
                        c_norm = re.sub(r'[\s\+]+', '', c.lower())
                        if c in payload_lookup:
                            matched_label, matched_atk = payload_lookup[c]
                            break
                        elif c_norm in payload_lookup:
                            matched_label, matched_atk = payload_lookup[c_norm]
                            break

                    if matched_label is not None:
                        rec["existing_label"] = matched_label
                        rec["attack_type"] = matched_atk
                    else:
                        sqli_pattern = (
                            r"(\bunion\b\s+(all\s+)?\bselect\b|"
                            r"\bselect\b.*\bfrom\b|"
                            r"'\s*(or|and)\s*'?\d|"
                            r"--\s*$|/\*.*\*/|"
                            r"\bsleep\s*\(\d+|"
                            r"\bbenchmark\s*\(\d+|"
                            r"0x[0-9a-fA-F]{4,}|"
                            r"\bwaitfor\b|\bdelay\b)"
                        )
                        sqli_sig = re.search(sqli_pattern, dq.lower())
                        if sqli_sig:
                            rec["existing_label"] = 1
                            rec["attack_type"] = "sqli"
                        else:
                            rec["existing_label"] = 0
                            rec["attack_type"] = "normal"

                    parsed_records.append(rec)
                else:
                    failed_lines += 1

    df = pd.DataFrame(parsed_records)
    df.to_csv(PARSED_LOG_CSV, index=False, encoding="utf-8")

    stats = {
        "total_records": len(parsed_records),
        "failed_lines": failed_lines,
        "output_file": str(PARSED_LOG_CSV)
    }
    with open(REPORTS_DIR / "parse_stats.json", "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)

    print(f"  [+] Hoan thanh: {len(parsed_records):,} dong log phan tich thanh cong (loi: {failed_lines}) -> {PARSED_LOG_CSV}")


if __name__ == "__main__":
    main()
