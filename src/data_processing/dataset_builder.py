import hashlib
import re
import urllib.parse
import sys
import pandas as pd
from pathlib import Path

file_path = Path(__file__).resolve()
project_root = file_path.parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

try:
    from src.config import PARSED_LOG_CSV, DATASET_CSV, DATASET_REPORT_FILE, REPORTS_DIR
except ImportError:
    from config import PARSED_LOG_CSV, DATASET_CSV, DATASET_REPORT_FILE, REPORTS_DIR

def compute_request_hash(path: str, query: str) -> str:
    """
    Tạo signature độc nhất cho request để phục vụ deduplication & grouped split.
    """
    clean_p = path.strip().lower()
    clean_q = re.sub(r'(user_token|PHPSESSID)=[a-zA-Z0-9]+', r'\1=<TOKEN>', query.strip())
    raw_sig = f"{clean_p}?{clean_q}"
    return hashlib.md5(raw_sig.encode("utf-8")).hexdigest()

def mask_sensitive_tokens(query_str: str) -> str:
    """
    Mask CSRF tokens and Session IDs to prevent ML from learning random hashes.
    """
    masked = re.sub(r'user_token=[a-zA-Z0-9]+', 'user_token=<TOKEN>', query_str)
    masked = re.sub(r'PHPSESSID=[a-zA-Z0-9]+', 'PHPSESSID=<TOKEN>', masked)
    return masked

def map_label(row) -> tuple[int, str]:
    """
    Map label strictly based on authoritative attack_type and existing_label.
    """
    attack_type = str(row.get("attack_type", "")).strip().lower()
    existing_lbl = row.get("existing_label", -1)

    try:
        existing_lbl = int(existing_lbl)
    except (ValueError, TypeError):
        existing_lbl = -1

    if existing_lbl == 0 or attack_type in ["normal", "clean", "benign"]:
        return 0, "existing_log_label"

    if existing_lbl == 1 or attack_type.startswith("sqli") or "sql" in attack_type:
        return 1, "existing_log_label"

    return 0, "default_normal"

def main():
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if not PARSED_LOG_CSV.exists():
        print(f"ERROR: {PARSED_LOG_CSV} not found. Run apache_parser.py first!")
        return

    df = pd.read_csv(PARSED_LOG_CSV).fillna("")
    total_raw = len(df)

    # Clean & Normalize
    df["method"] = df["method"].str.upper()
    df["path"] = df["path"].str.strip()
    df["decoded_query"] = df["decoded_query"].apply(mask_sensitive_tokens)
    if "decoded_body" in df.columns:
        df["decoded_body"] = df["decoded_body"].apply(mask_sensitive_tokens)
    else:
        df["decoded_body"] = ""

    # Label mapping
    labels_and_sources = df.apply(map_label, axis=1)
    df["label"] = [ls[0] for ls in labels_and_sources]
    df["label_source"] = [ls[1] for ls in labels_and_sources]

    # Filter out UNKNOWN labels for training
    df_clean = df[df["label"] != -1].copy()
    unknown_count = total_raw - len(df_clean)

    # Request Hash for Group Split & Deduplication check (URL + Query + Body)
    df_clean["request_hash"] = df_clean.apply(
        lambda r: compute_request_hash(r["path"], f"{r['decoded_query']} {r.get('decoded_body', '')}"), axis=1
    )

    duplicate_count = total_raw - df_clean["request_hash"].nunique()

    # Save Clean Dataset
    df_clean.to_csv(DATASET_CSV, index=False, encoding="utf-8")

    # Generate Dataset Report
    normal_cnt = (df_clean["label"] == 0).sum()
    sqli_cnt = (df_clean["label"] == 1).sum()
    total_clean = len(df_clean)

    attack_counts = df_clean[df_clean["label"] == 1]["attack_type"].value_counts().to_dict()

    report_content = f"""====================================
DATASET REPORT
====================================
Raw samples: {total_raw}
Failed parse: 0
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
Unique IP: {df_clean['ip'].nunique()}
Unique path: {df_clean['path'].nunique()}
Unique query: {df_clean['decoded_query'].nunique()}
====================================
"""
    with open(DATASET_REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(report_content)

    print(report_content)
    print(f"Dataset report saved to: {DATASET_REPORT_FILE}")

if __name__ == "__main__":
    main()
