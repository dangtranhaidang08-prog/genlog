import re
import urllib.parse
import sys
import pandas as pd
import numpy as np
from pathlib import Path

file_path = Path(__file__).resolve()
project_root = file_path.parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

try:
    from src.config import DATASET_CSV, FEATURES_CSV
except ImportError:
    from config import DATASET_CSV, FEATURES_CSV

SQL_KEYWORDS = [
    "select", "union", "from", "where", "or", "and", "insert", "update",
    "delete", "drop", "alter", "create", "table", "information_schema",
    "sleep", "benchmark", "version"
]

def extract_features_from_row(row: dict, ip_stats: dict = None) -> dict:
    """
    Extract comprehensive 81 features from a single HTTP request row.
    """
    url = str(row.get("url", ""))
    path = str(row.get("path", ""))
    query = str(row.get("query", ""))
    decoded_url = str(row.get("decoded_url", url))
    decoded_query = str(row.get("decoded_query", query))
    decoded_path = urllib.parse.unquote_plus(path)
    raw_body = str(row.get("body", ""))
    decoded_body = str(row.get("decoded_body", ""))
    content_type = str(row.get("content_type", "")).lower()

    # JSON & Body Meta
    is_json = int(row.get("is_json_payload", 1 if ("json" in content_type or raw_body.strip().startswith(("{", "["))) else 0))
    json_depth = int(row.get("json_depth", 0))
    param_count_body = int(row.get("param_count_body", 0))

    method = str(row.get("method", "GET")).upper()
    status = int(row.get("status", 200))
    response_size = int(row.get("size", 0))
    response_time = int(row.get("response_time", 0))
    ip = str(row.get("ip", "127.0.0.1"))

    feats = {}

    # A. URL & Body Length Features
    feats["url_length"] = len(url)
    feats["path_length"] = len(path)
    feats["query_length"] = len(query)
    feats["body_length"] = len(raw_body)
    feats["is_json_payload"] = is_json
    feats["json_depth"] = json_depth
    feats["param_count_body"] = param_count_body

    params = urllib.parse.parse_qs(query)
    feats["number_of_parameters"] = len(params)
    feats["parameter_name_count"] = sum(len(k) for k in params.keys()) if params else 0

    encoded_chars = re.findall(r'%[0-9a-fA-F]{2}', url)
    feats["encoded_character_count"] = len(encoded_chars)
    feats["percent_encoded_count"] = url.count("%")

    # B. Character Features (Calculated on decoded_path + decoded_query + decoded_body)
    target_str = f"{decoded_path} {decoded_query} {decoded_body}".strip()

    feats["single_quote_count"] = target_str.count("'")
    feats["double_quote_count"] = target_str.count('"')
    feats["semicolon_count"] = target_str.count(";")
    feats["comma_count"] = target_str.count(",")
    feats["parenthesis_count"] = target_str.count("(") + target_str.count(")")
    feats["dash_count"] = target_str.count("-")
    feats["hash_count"] = target_str.count("#")
    feats["asterisk_count"] = target_str.count("*")
    feats["slash_count"] = target_str.count("/")
    feats["equal_count"] = target_str.count("=")
    feats["plus_count"] = target_str.count("+")
    feats["whitespace_count"] = len(re.findall(r"\s", target_str))

    # C. SQL Keyword Frequency Features
    target_lower = target_str.lower()
    for kw in SQL_KEYWORDS:
        feats[f"keyword_{kw}"] = len(re.findall(rf"\b{kw}\b", target_lower))

    # D. SQLi Pattern Features
    feats["has_union_select"] = 1 if re.search(r"\bunion\s+(all\s+)?select\b", target_lower) else 0
    feats["has_tautology"] = 1 if re.search(r"\bor\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?", target_lower) or "1=1" in target_lower.replace(" ", "") else 0
    feats["has_sql_comment"] = 1 if re.search(r"(--|#|/\*)", target_str) else 0
    feats["has_quote"] = 1 if ("'" in target_str or '"' in target_str) else 0
    feats["has_subquery"] = 1 if re.search(r"\(\s*select\b", target_lower) else 0
    feats["has_information_schema"] = 1 if "information_schema" in target_lower else 0
    feats["has_sleep"] = 1 if re.search(r"\bsleep\s*\(", target_lower) else 0
    feats["has_benchmark"] = 1 if re.search(r"\bbenchmark\s*\(", target_lower) else 0
    feats["has_if_function"] = 1 if re.search(r"\bif\s*\(", target_lower) else 0
    feats["has_case_when"] = 1 if re.search(r"\bcase\b.*\bwhen\b", target_lower) else 0
    feats["has_exists"] = 1 if re.search(r"\bexists\s*\(", target_lower) else 0
    feats["has_substring"] = 1 if re.search(r"\b(substring|substr)\s*\(", target_lower) else 0
    feats["has_ascii"] = 1 if re.search(r"\bascii\s*\(", target_lower) else 0
    feats["has_length"] = 1 if re.search(r"\blength\s*\(", target_lower) else 0
    feats["has_database_function"] = 1 if re.search(r"\bdatabase\s*\(", target_lower) else 0
    feats["has_version_function"] = 1 if re.search(r"\bversion\s*\(", target_lower) else 0
    feats["has_system_variable"] = 1 if ("@@" in target_str or "@version" in target_lower) else 0
    feats["has_error_based_pattern"] = 1 if re.search(r"\b(extractvalue|updatexml|floor|rand)\b", target_lower) else 0

    # E. Blind SQLi Specific Features
    feats["has_error_condition"] = 1 if ("1/0" in target_lower.replace(" ", "") or "division" in target_lower) else 0
    feats["nested_select_count"] = target_lower.count("select")
    feats["sql_function_count"] = sum([
        feats["has_sleep"], feats["has_benchmark"], feats["has_if_function"],
        feats["has_substring"], feats["has_ascii"], feats["has_length"],
        feats["has_database_function"], feats["has_version_function"]
    ])
    feats["comparison_count"] = sum(target_str.count(c) for c in [">", "<", "="])
    feats["logical_operator_count"] = len(re.findall(r"\b(and|or|not)\b", target_lower))

    # F. HTTP Features
    feats["method_get"] = 1 if method == "GET" else 0
    feats["method_post"] = 1 if method == "POST" else 0
    feats["status_code"] = status
    feats["is_error_response"] = 1 if status >= 400 else 0
    feats["response_size"] = response_size
    feats["response_time"] = response_time

    # G. Context Statistics Features (derived per IP)
    if ip_stats and ip in ip_stats:
        feats["ip_request_count"] = ip_stats[ip]["count"]
        feats["ip_unique_path_count"] = ip_stats[ip]["unique_path"]
        feats["ip_unique_query_count"] = ip_stats[ip]["unique_query"]
    else:
        feats["ip_request_count"] = 1
        feats["ip_unique_path_count"] = 1
        feats["ip_unique_query_count"] = 1

    # Text for TF-IDF Vectorizer: Isolate to query + body text to prevent DVWA path shortcut learning
    combined_content = f"{decoded_query} {decoded_body}".strip()
    feats["text"] = combined_content if combined_content else decoded_path.strip()

    return feats

def main():
    if not DATASET_CSV.exists():
        print(f"ERROR: {DATASET_CSV} not found. Run dataset_builder.py first!")
        return

    df = pd.read_csv(DATASET_CSV).fillna("")

    # Pre-calculate IP Context Stats
    ip_stats = {}
    for ip, group in df.groupby("ip"):
        ip_stats[ip] = {
            "count": len(group),
            "unique_path": group["path"].nunique(),
            "unique_query": group["decoded_query"].nunique()
        }

    extracted_rows = []
    for _, row in df.iterrows():
        f_dict = extract_features_from_row(row.to_dict(), ip_stats)

        # Retain metadata & target labels
        f_dict["ip"] = row.get("ip", "")
        f_dict["timestamp"] = row.get("timestamp", "")
        f_dict["method"] = row.get("method", "")
        f_dict["url"] = row.get("url", "")
        f_dict["path"] = row.get("path", "")
        f_dict["query"] = row.get("query", "")
        f_dict["decoded_query"] = row.get("decoded_query", "")
        f_dict["attack_type"] = row.get("attack_type", "")
        f_dict["label"] = row.get("label", 0)
        f_dict["label_source"] = row.get("label_source", "")
        f_dict["request_hash"] = row.get("request_hash", "")

        extracted_rows.append(f_dict)

    feat_df = pd.DataFrame(extracted_rows)
    feat_df.to_csv(FEATURES_CSV, index=False, encoding="utf-8")

    print("====================================")
    print("FEATURE EXTRACTION COMPLETED")
    print("====================================")
    print(f"Total processed requests: {len(feat_df)}")
    print(f"Total extracted features: {len(feat_df.columns)}")
    print(f"Output saved to: {FEATURES_CSV}")
    print("====================================\n")

if __name__ == "__main__":
    main()
