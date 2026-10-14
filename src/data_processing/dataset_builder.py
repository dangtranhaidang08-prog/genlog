import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Tuple

import pandas as pd

file_path = Path(__file__).resolve()
project_root = file_path.parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.config import (  # noqa: E402
    PARSED_LOG_CSV,
    DATASET_CSV,
    DATASET_REPORT_FILE,
    REPORTS_DIR
)


def mask_sensitive_tokens(query_str: str) -> str:
    masked = re.sub(r'user_token=[a-zA-Z0-9_\-]+', 'user_token=<TOKEN>', query_str)
    masked = re.sub(r'PHPSESSID=[a-zA-Z0-9_\-]+', 'PHPSESSID=<TOKEN>', masked)
    return masked


def compute_request_hash(method: str, path: str, query: str, body: str) -> str:
    clean_m = str(method).strip().upper()
    clean_p = str(path).strip().lower()

    def _normalize_param_str(s: str) -> str:
        s_clean = str(s).strip()
        if not s_clean:
            return ""
        masked = mask_sensitive_tokens(s_clean)
        tokens = [t.strip() for t in masked.split("&") if t.strip()]
        return "&".join(sorted(tokens))

    clean_q = _normalize_param_str(query)
    clean_b = _normalize_param_str(body)
    raw_sig = f"{clean_m}:{clean_p}?{clean_q}#{clean_b}"
    return hashlib.md5(raw_sig.encode("utf-8")).hexdigest()


def map_label(row) -> Tuple[int, str]:
    attack_type = str(row.get("attack_type", "")).strip().lower()
    existing_lbl = row.get("existing_label", -1)

    try:
        existing_lbl = int(existing_lbl)
    except (ValueError, TypeError):
        existing_lbl = -1

    if attack_type in ["normal", "clean", "benign"] or (existing_lbl == 0 and not attack_type.startswith("sqli")):
        return 0, "verified_normal"

    if attack_type.startswith("sqli") or "sql" in attack_type or (existing_lbl == 1 and attack_type not in ["normal", "clean", "benign"]):
        return 1, "verified_sqli"

    return -1, "unknown_unlabeled"


def main():
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if not PARSED_LOG_CSV.exists():
        print(f"ERROR: {PARSED_LOG_CSV} not found. Run apache_parser.py first!")
        return

    df = pd.read_csv(PARSED_LOG_CSV).fillna("")
    total_raw = len(df)

    df["method"] = df["method"].str.upper()
    df["path"] = df["path"].str.strip()
    df["decoded_query"] = df["decoded_query"].apply(mask_sensitive_tokens)
    if "decoded_body" in df.columns:
        df["decoded_body"] = df["decoded_body"].apply(mask_sensitive_tokens)
    else:
        df["decoded_body"] = ""

    labels_and_sources = df.apply(map_label, axis=1)
    df["label"] = [ls[0] for ls in labels_and_sources]
    df["label_source"] = [ls[1] for ls in labels_and_sources]

    df_clean = df[df["label"] != -1].copy()
    unknown_count = total_raw - len(df_clean)

    df_clean["request_hash"] = df_clean.apply(
        lambda r: compute_request_hash(r["method"], r["path"], r["decoded_query"], r.get("decoded_body", "")),
        axis=1
    )

    duplicate_count = len(df_clean) - int(pd.Series(df_clean["request_hash"]).nunique())

    df_clean.to_csv(DATASET_CSV, index=False, encoding="utf-8")

    normal_cnt = (df_clean["label"] == 0).sum()
    sqli_cnt = (df_clean["label"] == 1).sum()
    total_clean = len(df_clean)

    attack_counts = pd.Series(df_clean[df_clean["label"] == 1]["attack_type"]).value_counts().to_dict()

    failed_parse_count = 0
    parse_stats_file = REPORTS_DIR / "parse_stats.json"
    if parse_stats_file.exists():
        try:
            with open(parse_stats_file, "r", encoding="utf-8") as f:
                p_stats = json.load(f)
                failed_parse_count = int(p_stats.get("failed_lines", 0))
        except Exception:
            failed_parse_count = 0

    report_content = f"""====================================
DATASET REPORT
====================================
Raw samples: {total_raw}
Failed parse: {failed_parse_count}
Clean samples: {total_clean}
Duplicate requests: {duplicate_count}
Unknown/unlabeled: {unknown_count}

Normal: {normal_cnt} ({normal_cnt/total_clean*100:.2f}%)
SQLi: {sqli_cnt} ({sqli_cnt/total_clean*100:.2f}%)

Attack types:
"""
    for atk, cnt in attack_counts.items():
        report_content += f"  - {atk}: {cnt}\n"

    report_content += f"""
Unique IP: {pd.Series(df_clean['ip']).nunique()}
Unique path: {pd.Series(df_clean['path']).nunique()}
Unique query: {pd.Series(df_clean['decoded_query']).nunique()}
====================================
"""
    with open(DATASET_REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(report_content)

    print(f"  [OK] Hoan thanh: {total_clean:,} mau sach (Normal: {normal_cnt:,} | SQLi: {sqli_cnt:,}) -> {DATASET_CSV}")
    print(f"  [i] Báo cáo chi tiết: {DATASET_REPORT_FILE}")


if __name__ == "__main__":
    main()
