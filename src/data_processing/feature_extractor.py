from pathlib import Path
import re
import sys
from typing import Any, Dict, Optional
import urllib.parse

import pandas as pd

file_path = Path(__file__).resolve()
project_root = file_path.parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.config import DATASET_CSV, FEATURES_CSV  # noqa: E402

SQL_KEYWORDS = [
    "select", "union", "from", "where", "or", "and", "insert", "update",
    "delete", "drop", "alter", "create", "table", "information_schema",
    "sleep", "benchmark", "version"
]

# Explicit schema whitelist of 64 pre-execution numerical features (deterministic order)
APPROVED_NUMERICAL_FEATURES = [
    # A. Length & Parameter Features (9)
    "url_length", "path_length", "query_length", "body_length", "param_count_body",
    "number_of_parameters", "parameter_name_count", "encoded_character_count", "percent_encoded_count",
    # B. Character Counts (12)
    "single_quote_count", "double_quote_count", "semicolon_count", "comma_count",
    "parenthesis_count", "dash_count", "hash_count", "asterisk_count",
    "slash_count", "equal_count", "plus_count", "whitespace_count",
    # C. SQL Keyword Frequencies (17)
    "keyword_select", "keyword_union", "keyword_from", "keyword_where",
    "keyword_or", "keyword_and", "keyword_insert", "keyword_update",
    "keyword_delete", "keyword_drop", "keyword_alter", "keyword_create",
    "keyword_table", "keyword_information_schema", "keyword_sleep",
    "keyword_benchmark", "keyword_version",
    # D. SQLi Pattern Signatures (19)
    "has_union_select", "has_tautology", "has_sql_comment", "has_quote",
    "has_subquery", "has_information_schema", "has_sleep", "has_benchmark",
    "has_if_function", "has_case_when", "has_exists", "has_substring",
    "has_ascii", "has_length", "has_database_function", "has_version_function",
    "has_system_variable", "has_error_based_pattern", "has_hex_literal",
    # E. Blind SQLi & Structural Primitives (5)
    "has_error_condition", "nested_select_count", "sql_function_count",
    "comparison_count", "logical_operator_count",
    # F. HTTP Method Flags (2)
    "method_get", "method_post"
]


def extract_features_from_row(row: dict, ip_stats: Optional[dict] = None) -> dict:
    """
    Extract 64 pre-execution numerical features and TF-IDF text for machine learning threat detection.
    """
    url = str(row.get("url", ""))
    path = str(row.get("path", ""))
    query = str(row.get("query", ""))
    decoded_query = str(row.get("decoded_query", query))
    decoded_path = urllib.parse.unquote(path)
    raw_body = str(row.get("body", ""))
    decoded_body = str(row.get("decoded_body", ""))

    param_count_body = int(row.get("param_count_body", 0))
    method = str(row.get("method", "GET")).upper()
    status = int(row.get("status", 200))
    response_size = int(row.get("size", 0))
    response_time = int(row.get("response_time", 0))
    ip = str(row.get("ip", "127.0.0.1"))

    feats: Dict[str, Any] = {}

    # A. URL & Body Length Features
    feats["url_length"] = len(url)
    feats["path_length"] = len(path)
    feats["query_length"] = len(query)
    feats["body_length"] = len(raw_body)
    feats["param_count_body"] = param_count_body

    query_params = urllib.parse.parse_qs(query) if query else {}
    body_params = urllib.parse.parse_qs(raw_body) if raw_body else {}
    all_params = {**query_params, **body_params}
    feats["number_of_parameters"] = len(all_params)
    feats["parameter_name_count"] = sum(len(k) for k in all_params.keys()) if all_params else 0

    full_raw_stream = f"{url} {raw_body}".strip()
    encoded_chars = re.findall(r'%[0-9a-fA-F]{2}', full_raw_stream)
    feats["encoded_character_count"] = len(encoded_chars)
    feats["percent_encoded_count"] = full_raw_stream.count("%")

    # B. Character Features
    raw_target_str = f"{decoded_path} {decoded_query} {decoded_body}".strip()

    def _decode_hex_stream(s: str) -> str:
        def _replace_hex(m):
            h_str = m.group(1)
            if len(h_str) % 2 != 0:
                h_str = "0" + h_str
            try:
                d = bytes.fromhex(h_str).decode("latin1", errors="ignore")
                return f" {d} " if all(32 <= ord(c) < 127 for c in d) else m.group(0)
            except Exception:
                return m.group(0)
        s = re.sub(r"[xX]'([0-9a-fA-F]+)'", r"0x\1", s)
        return re.sub(r'0x([0-9a-fA-F]{2,})', _replace_hex, s)

    target_str = _decode_hex_stream(raw_target_str)

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

    # D. SQLi Pattern Features (Hardened against comment evasion & false positives)
    clean_target = re.sub(r'/\*.*?\*/', ' ', target_lower)
    feats["has_union_select"] = 1 if re.search(r"\bunion\s+(all\s+)?select\b", clean_target) else 0
    feats["has_tautology"] = 1 if (
        re.search(r"\b(or|and)\b\s+['\"]?\w+['\"]?\s*(=|>|<|!=|<>)\s*['\"]?\w+['\"]?", target_lower)
        or "1=1" in target_lower.replace(" ", "")
        or "2>1" in target_lower.replace(" ", "")
    ) else 0
    feats["has_sql_comment"] = 1 if re.search(r"(--|#|/\*)", target_str) else 0
    feats["has_quote"] = 1 if ("'" in target_str or '"' in target_str) else 0
    feats["has_subquery"] = 1 if re.search(r"\(\s*select\b", target_lower) else 0
    feats["has_information_schema"] = 1 if "information_schema" in target_lower else 0
    feats["has_sleep"] = 1 if re.search(r"\bsleep\s*\(", target_lower) else 0
    feats["has_benchmark"] = 1 if re.search(r"\bbenchmark\s*\(", target_lower) else 0
    feats["has_if_function"] = 1 if re.search(r"\bif\s*\(", target_lower) else 0
    feats["has_case_when"] = 1 if re.search(r"\bcase\b\s+when\b|\bcase\b\s+\w+\s+when\b", target_lower) else 0
    feats["has_exists"] = 1 if re.search(r"\bexists\s*\(", target_lower) else 0
    feats["has_substring"] = 1 if re.search(r"\b(substring|substr)\s*\(", target_lower) else 0
    feats["has_ascii"] = 1 if re.search(r"\bascii\s*\(", target_lower) else 0
    feats["has_length"] = 1 if re.search(r"\blength\s*\(", target_lower) else 0
    feats["has_database_function"] = 1 if re.search(r"\bdatabase\s*\(", target_lower) else 0
    feats["has_version_function"] = 1 if re.search(r"\bversion\s*\(", target_lower) else 0
    feats["has_system_variable"] = 1 if ("@@" in target_str or "@version" in target_lower) else 0
    feats["has_error_based_pattern"] = 1 if re.search(r"\b(extractvalue|updatexml|floor|rand)\b", target_lower) else 0
    feats["has_hex_literal"] = 1 if re.search(r"0x[0-9a-fA-F]{2,}", target_str) else 0

    # E. Blind SQLi Specific Features
    feats["has_error_condition"] = 1 if (
        "1/0" in target_lower.replace(" ", "")
        or "/0" in target_lower.replace(" ", "")
        or re.search(r"\bdivision\s+by\s+zero\b", target_lower)
        or re.search(r"\bmod\s*\(\s*\d+\s*,\s*0\s*\)", target_lower)
    ) else 0
    feats["nested_select_count"] = target_lower.count("select")
    feats["sql_function_count"] = sum([
        feats["has_sleep"], feats["has_benchmark"], feats["has_if_function"],
        feats["has_substring"], feats["has_ascii"], feats["has_length"],
        feats["has_database_function"], feats["has_version_function"]
    ])
    comp_gt_lt = target_str.count(">") + target_str.count("<")
    comp_eq = max(0, target_str.count("=") - feats["number_of_parameters"])
    feats["comparison_count"] = comp_gt_lt + comp_eq
    feats["logical_operator_count"] = len(re.findall(r"\b(and|or|not)\b", target_lower))

    # F. HTTP Features
    feats["method_get"] = 1 if method == "GET" else 0
    feats["method_post"] = 1 if method == "POST" else 0
    feats["status_code"] = status
    feats["is_error_response"] = 1 if status >= 400 else 0
    feats["response_size"] = response_size
    feats["response_time"] = response_time

    # G. Context Statistics Features
    if ip_stats and ip in ip_stats:
        feats["ip_request_count"] = ip_stats[ip]["count"]
        feats["ip_unique_path_count"] = ip_stats[ip]["unique_path"]
        feats["ip_unique_query_count"] = ip_stats[ip]["unique_query"]
    else:
        feats["ip_request_count"] = 1
        feats["ip_unique_path_count"] = 1
        feats["ip_unique_query_count"] = 1

    # Text for TF-IDF Vectorizer (No path fallback to avoid shortcut learning)
    combined_content = f"{decoded_query} {decoded_body}".strip()
    inspected_text = _decode_hex_stream(combined_content)
    feats["text"] = inspected_text if inspected_text else ""

    return feats


def main():
    if not DATASET_CSV.exists():
        print(f"ERROR: {DATASET_CSV} not found. Run dataset_builder.py first!")
        return

    df = pd.read_csv(DATASET_CSV).fillna("")

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

    print(f"  [OK] Hoan thanh: Da trich xuat {len(feat_df.columns)} dac trung cho {len(feat_df):,} requests -> {FEATURES_CSV}")


if __name__ == "__main__":
    main()
