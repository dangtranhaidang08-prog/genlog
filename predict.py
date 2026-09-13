"""
Real-time CLI Predictor for Web Attack Detection (SQLi).
Evaluates individual HTTP requests against the trained AI Security model.
"""
import sys
import re
import urllib.parse
from pathlib import Path
import pandas as pd
import numpy as np
import scipy.sparse as sp
import joblib

# Ensure project root is in sys.path
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.config import MODEL_FILE, VEC_FILE, COLS_FILE
from src.data_processing.apache_parser import parse_raw_line, parse_request_string
from src.data_processing.feature_extractor import extract_features_from_row

def load_models():
    if not (MODEL_FILE.exists() and VEC_FILE.exists() and COLS_FILE.exists()):
        print(f"ERROR: Model artifacts missing in {MODEL_FILE.parent}. Run `python run_pipeline.py` first!")
        sys.exit(1)
    
    model = joblib.load(MODEL_FILE)
    vectorizer = joblib.load(VEC_FILE)
    feature_cols = joblib.load(COLS_FILE)
    return model, vectorizer, feature_cols

def detect_indicators(query_str: str):
    """
    Phát hiện các dấu hiệu vi phạm trong chuỗi query/URL để hiển thị giải thích.
    """
    decoded = urllib.parse.unquote_plus(query_str)
    indicators = []

    if "'" in decoded:
        indicators.append("Single quote (')")
    if '"' in decoded:
        indicators.append('Double quote (")')
    if re.search(r"\bor\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?", decoded, re.IGNORECASE) or "1=1" in decoded.replace(" ", ""):
        indicators.append("OR condition / Tautology")
    if re.search(r"\bunion\s+(all\s+)?select\b", decoded, re.IGNORECASE):
        indicators.append("UNION SELECT keyword sequence")
    if re.search(r"(--|#|/\*)", decoded):
        indicators.append("SQL comment (-- or # or /*)")
    if "information_schema" in decoded.lower():
        indicators.append("Information Schema metadata query")
    if "@@" in decoded or "@version" in decoded.lower():
        indicators.append("System variable query (@@version)")
    if re.search(r"\b(sleep|benchmark)\s*\(", decoded, re.IGNORECASE):
        indicators.append("Time-based Blind SQLi function (sleep/benchmark)")
    if re.search(r"\b(substring|substr|ascii|length)\s*\(", decoded, re.IGNORECASE):
        indicators.append("Boolean-based Blind SQLi function (substring/ascii/length)")
    if re.search(r"\bcase\b.*\bwhen\b", decoded, re.IGNORECASE) or "1/0" in decoded.replace(" ", ""):
        indicators.append("Error-based SQLi / Division by zero pattern")

    return indicators if indicators else ["Clean HTTP request"]

import argparse

def predict_request(
    request_str: str = "",
    method_in: str = "",
    url_in: str = "",
    body_in: str = "",
    content_type_in: str = "",
    model = None,
    vectorizer = None,
    feature_cols = None
):
    """
    Predict SQL Injection risk for an HTTP request (GET query or POST body / JSON).
    """
    if request_str and not url_in:
        req_line = request_str
    elif url_in:
        m = method_in.upper() if method_in else ("POST" if body_in else "GET")
        req_line = f"{m} {url_in} HTTP/1.1"
    else:
        req_line = "GET / HTTP/1.1"

    (
        method, url, path, query, protocol,
        decoded_url, decoded_query, raw_body, decoded_body,
        is_json, json_depth, param_count_body
    ) = parse_request_string(req_line, body=body_in, content_type=content_type_in)

    if method_in:
        method = method_in.upper()

    row_dict = {
        "ip": "127.0.0.1",
        "timestamp": "01/Jan/2026:00:00:00 +0000",
        "method": method if method else "GET",
        "url": url if url else req_line,
        "path": path,
        "query": query,
        "protocol": protocol if protocol else "HTTP/1.1",
        "status": 200,
        "size": 1000,
        "referer": "-",
        "user_agent": "CLI-Predictor/1.0",
        "decoded_url": decoded_url,
        "decoded_query": decoded_query,
        "body": raw_body,
        "decoded_body": decoded_body,
        "content_type": content_type_in,
        "is_json_payload": is_json,
        "json_depth": json_depth,
        "param_count_body": param_count_body
    }

    feat_dict = extract_features_from_row(row_dict)

    # 1. Numerical Matrix (Pre-execution Threat Detection features)
    num_vals = [feat_dict.get(c, 0) for c in feature_cols]
    X_num = np.array([num_vals], dtype=np.float32)

    # 2. Text Character TF-IDF Vector
    X_text = [feat_dict["text"]]
    X_tfidf = vectorizer.transform(X_text)

    # 3. Combine
    X_combined = sp.hstack([sp.csr_matrix(X_num), X_tfidf])

    # 4. Predict
    pred = int(model.predict(X_combined)[0])
    proba = model.predict_proba(X_combined)[0]
    sqli_prob = float(proba[1]) if len(proba) > 1 else (1.0 if pred == 1 else 0.0)
    normal_prob = 1.0 - sqli_prob

    label_str = "SQL Injection" if pred == 1 else "Normal"
    inspect_target = f"{decoded_query} {decoded_body}".strip() if (decoded_query or decoded_body) else decoded_url
    indicators = detect_indicators(inspect_target)

    print("====================================")
    print("SQL INJECTION PREDICTION")
    print("====================================")
    print(f"Request:      {req_line}")
    if raw_body:
        print(f"Body:         {raw_body[:120]}{'...' if len(raw_body) > 120 else ''}")
        print(f"Content-Type: {content_type_in if content_type_in else 'unspecified'}")
        print(f"Is JSON:      {bool(is_json)} (Depth: {json_depth})")
    print(f"Prediction:   {label_str}")
    print(f"Label:        {pred}")
    print("\nProbability:")
    print(f"  SQLi:       {sqli_prob:.4f}")
    print(f"  Normal:     {normal_prob:.4f}")
    print("\nDetected indicators:")
    for ind in indicators:
        print(f"- {ind}")
    print("====================================\n")
    return {"label": pred, "sqli_prob": sqli_prob, "normal_prob": normal_prob, "indicators": indicators}

def main():
    model, vectorizer, feature_cols = load_models()

    parser = argparse.ArgumentParser(description="Real-time CLI Predictor for Web Attack Detection (SQLi)")
    parser.add_argument("request", nargs="?", default="", help="HTTP Request string, e.g. 'GET /vulnerabilities/sqli/?id=1 HTTP/1.1'")
    parser.add_argument("--method", type=str, default="", help="HTTP Method (GET, POST, etc.)")
    parser.add_argument("--url", type=str, default="", help="Target URL or Path (e.g. /api/v1/auth)")
    parser.add_argument("--body", type=str, default="", help="Request Body content (JSON or form-urlencoded)")
    parser.add_argument("--content-type", type=str, default="", help="Content-Type header (e.g. application/json)")

    args = parser.parse_args()

    if args.request or args.url or args.body:
        predict_request(
            request_str=args.request,
            method_in=args.method,
            url_in=args.url,
            body_in=args.body,
            content_type_in=args.content_type,
            model=model,
            vectorizer=vectorizer,
            feature_cols=feature_cols
        )
    else:
        print("No input provided. Running comprehensive test suite (GET + POST JSON)...\n")
        test_samples = [
            # 1. NORMAL GET
            {"request": "GET /index.php HTTP/1.1"},
            {"request": "GET /vulnerabilities/sqli/?id=1&Submit=Submit HTTP/1.1"},

            # 2. SQLi GET (Boolean, Union, Blind Time, Blind Error)
            {"request": "GET /vulnerabilities/sqli/?id=1%27+OR+1%3D1%23&Submit=Submit HTTP/1.1"},
            {"request": "GET /vulnerabilities/sqli/?id=%27+UNION+SELECT+table_name+FROM+information_schema.tables%23 HTTP/1.1"},
            {"request": "GET /vulnerabilities/sqli_blind/?id=1%27+AND+IF%281%3D1%2CSLEEP%285%29%2C0%29--+- HTTP/1.1"},
            {"request": "GET /vulnerabilities/sqli_blind/?id=1%27+AND+CASE+WHEN+%281%3D1%29+THEN+1/0+ELSE+1+END--+- HTTP/1.1"},

            # 3. NORMAL POST JSON
            {
                "method": "POST",
                "url": "/api/v1/search",
                "body": '{"search": "laptop", "page": 1, "category": "electronics"}',
                "content_type": "application/json"
            },
            {
                "method": "POST",
                "url": "/api/v1/auth",
                "body": '{"username": "alice", "action": "login", "remember": true}',
                "content_type": "application/json"
            },

            # 4. SQLi POST JSON
            {
                "method": "POST",
                "url": "/api/v1/auth",
                "body": '{"username": "admin\' OR 1=1-- -", "password": "123"}',
                "content_type": "application/json"
            },
            {
                "method": "POST",
                "url": "/api/v1/query",
                "body": '{"query": "laptop\' UNION SELECT user,password FROM users--", "limit": 10}',
                "content_type": "application/json"
            },
            {
                "method": "POST",
                "url": "/api/v1/filter",
                "body": '{"filter": {"user_id": "1\' AND SLEEP(5)--", "status": "active"}}',
                "content_type": "application/json"
            }
        ]

        for s in test_samples:
            predict_request(
                request_str=s.get("request", ""),
                method_in=s.get("method", ""),
                url_in=s.get("url", ""),
                body_in=s.get("body", ""),
                content_type_in=s.get("content_type", ""),
                model=model,
                vectorizer=vectorizer,
                feature_cols=feature_cols
            )

if __name__ == "__main__":
    main()
