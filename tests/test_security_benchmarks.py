"""
AI Security Benchmarks: Adversarial Robustness, False Positive Evaluation, and Inference Latency.
"""
import time
import json
import re
import urllib.parse
from pathlib import Path
import numpy as np
import scipy.sparse as sp
import joblib

import sys
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
from src.config import MODEL_FILE, VEC_FILE, COLS_FILE, REPORTS_DIR
from src.data_processing.apache_parser import parse_request_string
from src.data_processing.feature_extractor import extract_features_from_row

def load_artifacts():
    model = joblib.load(MODEL_FILE)
    vec = joblib.load(VEC_FILE)
    cols = joblib.load(COLS_FILE)
    return model, vec, cols

def predict_single(request_str: str, model, vec, cols, body: str = "", content_type: str = ""):
    (
        method, url, path, query, protocol,
        decoded_url, decoded_query, raw_body, decoded_body,
        is_json, json_depth, param_count_body
    ) = parse_request_string(request_str, body=body, content_type=content_type)
    row_dict = {
        "ip": "127.0.0.1",
        "timestamp": "01/Jan/2026:00:00:00 +0000",
        "method": method if method else "GET",
        "url": url if url else request_str,
        "path": path,
        "query": query,
        "protocol": protocol if protocol else "HTTP/1.1",
        "status": 200,
        "size": 1000,
        "referer": "-",
        "user_agent": "Benchmark/1.0",
        "decoded_url": decoded_url,
        "decoded_query": decoded_query,
        "body": raw_body,
        "decoded_body": decoded_body,
        "content_type": content_type,
        "is_json_payload": is_json,
        "json_depth": json_depth,
        "param_count_body": param_count_body
    }
    feat_dict = extract_features_from_row(row_dict)
    num_vals = [feat_dict.get(c, 0) for c in cols]
    X_num = np.array([num_vals], dtype=np.float32)
    X_text = [feat_dict["text"]]
    X_tfidf = vec.transform(X_text)
    X_combined = sp.hstack([sp.csr_matrix(X_num), X_tfidf])

    proba = model.predict_proba(X_combined)[0]
    sqli_prob = float(proba[1]) if len(proba) > 1 else 0.0
    pred = 1 if sqli_prob >= 0.5 else 0
    return pred, sqli_prob

def run_adversarial_suite(model, vec, cols):
    print("\n==================================================")
    print("1. ADVERSARIAL ROBUSTNESS & EVASION EVALUATION")
    print("==================================================")

    evasion_samples = [
        # Benign watermarking / keyword padding
        ("GET /search.php?id=1' UNION SELECT user,password FROM users-- &category=books&author=john&sort=asc HTTP/1.1", "Watermarking (Padding benign tokens)"),
        ("GET /products?id=1' OR 1=1-- &name=laptop&brand=dell&price=500 HTTP/1.1", "Watermarking (Benign query parameters)"),
        # Inline comments & Obfuscation
        ("GET /item?id=1'/**/OR/**/1=1# HTTP/1.1", "Inline Comment Whitespace Obfuscation"),
        ("GET /item?id=1'/*!50000UNION*//*!50000SELECT*/1,2# HTTP/1.1", "MySQL Version Comment Obfuscation"),
        # Hex & Char Encoding
        ("GET /login?id=0x27204f5220313d31 HTTP/1.1", "Hex-encoded SQLi probe"),
        # Case variation
        ("GET /api/user?id=1' uNiOn SeLeCt null,null-- HTTP/1.1", "Mixed-case keyword evasion"),
        # Line feed / Tab whitespace
        ("GET /view?id=1'%0AOR%0A1=1-- HTTP/1.1", "URL-encoded Line-feed delimiter"),
        # Tautology variations
        ("GET /check?id=1' OR 'admin' LIKE 'admin'-- HTTP/1.1", "String Tautology with LIKE"),
        ("GET /check?id=1' OR 2>1-- HTTP/1.1", "Inequality Tautology 2>1"),
        # Nested expression
        ("GET /query?id=1' OR (((1=1)))-- HTTP/1.1", "Deeply Nested Parentheses Tautology"),
        # POST JSON Evasion
        ("POST /api/v1/auth HTTP/1.1", "JSON Body SQLi Auth Evasion", '{"username": "admin\' OR 1=1-- -", "password": "123"}', "application/json"),
        ("POST /api/v1/query HTTP/1.1", "Nested JSON Body UNION SELECT Evasion", '{"query": {"filter": "laptop\' UNION SELECT user,password FROM users--"}}', "application/json")
    ]

    evasion_results = []
    detected_cnt = 0

    for item in evasion_samples:
        req = item[0]
        desc = item[1]
        body = item[2] if len(item) > 2 else ""
        content_type = item[3] if len(item) > 3 else ""

        pred, prob = predict_single(req, model, vec, cols, body=body, content_type=content_type)
        is_detected = (pred == 1)
        if is_detected:
            detected_cnt += 1
        evasion_results.append({
            "description": desc,
            "request": req,
            "detected": is_detected,
            "sqli_prob": round(prob, 4)
        })
        status_tag = "[DETECTED]" if is_detected else "[BYPASSED]"
        print(f" {status_tag} {desc:<42} | Prob: {prob:.4f}")

    robustness_rate = (detected_cnt / len(evasion_samples)) * 100
    print(f"\nAdversarial Detection Rate: {detected_cnt}/{len(evasion_samples)} ({robustness_rate:.2f}%)")
    return evasion_results, robustness_rate

def run_false_positive_suite(model, vec, cols):
    print("\n==================================================")
    print("2. FALSE POSITIVE RATE (FPR) EVALUATION ON BENIGN CORNER CASES")
    print("==================================================")

    benign_corner_samples = [
        # Names with quotes
        ("GET /profile?user=O'Connor&role=developer HTTP/1.1", "Irish Name with single quote (O'Connor)"),
        ("GET /author?name=D'Angelo HTTP/1.1", "Italian Name with single quote (D'Angelo)"),
        # Search queries containing SQL-like terms
        ("GET /search?q=How+to+select+best+laptop HTTP/1.1", "Search query with word 'select'"),
        ("GET /forum?title=Update+on+version+2.0 HTTP/1.1", "Forum title with 'update' and 'version'"),
        ("GET /docs?topic=drop+shadow+in+css HTTP/1.1", "CSS documentation search with 'drop'"),
        # Arithmetic / Comparison filters
        ("GET /filter?price_min=10&price_max=100&rating_gte=4 HTTP/1.1", "Benign price/rating filters"),
        ("GET /math?calc=10+plus+20+equals+30 HTTP/1.1", "Benign math query"),
        # Standard web requests
        ("GET /index.php?page=home&lang=vi HTTP/1.1", "Standard homepage with page and lang"),
        ("GET /api/v1/items?limit=20&offset=40 HTTP/1.1", "REST API pagination"),
        ("GET /catalog?category=electronics&sort=newest HTTP/1.1", "Catalog category sort"),
        # POST JSON Benign Corner Cases
        ("POST /api/v1/search HTTP/1.1", "JSON Benign Search with pagination", '{"search": "laptop", "page": 1, "category": "electronics"}', "application/json"),
        ("POST /api/v1/feedback HTTP/1.1", "JSON Benign Feedback with quote", '{"author": "O\'Connor", "comment": "Great product select menu!"}', "application/json")
    ]

    fp_results = []
    fp_cnt = 0

    for item in benign_corner_samples:
        req = item[0]
        desc = item[1]
        body = item[2] if len(item) > 2 else ""
        content_type = item[3] if len(item) > 3 else ""

        pred, prob = predict_single(req, model, vec, cols, body=body, content_type=content_type)
        is_fp = (pred == 1)
        if is_fp:
            fp_cnt += 1
        fp_results.append({
            "description": desc,
            "request": req,
            "false_positive": is_fp,
            "sqli_prob": round(prob, 4)
        })
        status_tag = "[PASS - CLEAN]" if not is_fp else "[FALSE POSITIVE]"
        print(f" {status_tag:<18} {desc:<42} | Prob: {prob:.4f}")

    fpr = (fp_cnt / len(benign_corner_samples)) * 100
    print(f"\nFalse Positive Rate: {fp_cnt}/{len(benign_corner_samples)} ({fpr:.2f}%)")
    return fp_results, fpr

def run_latency_benchmark(model, vec, cols, iterations: int = 50):
    print("\n==================================================")
    print("3. INFERENCE LATENCY BENCHMARK (ms/request)")
    print("==================================================")

    sample_req = "GET /search.php?id=1%27+UNION+SELECT+null%2Ctable_name+FROM+information_schema.tables%23 HTTP/1.1"

    # Warmup
    for _ in range(10):
        predict_single(sample_req, model, vec, cols)

    t0 = time.perf_counter()
    for _ in range(iterations):
        predict_single(sample_req, model, vec, cols)
    total_time = time.perf_counter() - t0

    avg_latency_ms = (total_time / iterations) * 1000
    fps = iterations / total_time

    print(f"Total Iterations:        {iterations}")
    print(f"Average Latency:         {avg_latency_ms:.3f} ms / request")
    print(f"Throughput Capacity:     {fps:.1f} requests / sec (Single Thread)")

    # Breakdown Latency
    (
        method, url, path, query, protocol,
        decoded_url, decoded_query, raw_body, decoded_body,
        is_json, json_depth, param_count_body
    ) = parse_request_string(sample_req)
    row_dict = {
        "ip": "127.0.0.1", "timestamp": "01/Jan/2026:00:00:00 +0000",
        "method": method, "url": url, "path": path, "query": query, "protocol": protocol,
        "status": 200, "size": 1000, "referer": "-", "user_agent": "Benchmark/1.0",
        "decoded_url": decoded_url, "decoded_query": decoded_query,
        "body": raw_body, "decoded_body": decoded_body, "content_type": "",
        "is_json_payload": is_json, "json_depth": json_depth, "param_count_body": param_count_body
    }

    t_feat_start = time.perf_counter()
    for _ in range(iterations):
        feat_dict = extract_features_from_row(row_dict)
    t_feat_ms = ((time.perf_counter() - t_feat_start) / iterations) * 1000

    num_vals = [feat_dict.get(c, 0) for c in cols]
    X_num = np.array([num_vals], dtype=np.float32)
    X_text = [feat_dict["text"]]

    t_vec_start = time.perf_counter()
    for _ in range(iterations):
        X_tfidf = vec.transform(X_text)
    t_vec_ms = ((time.perf_counter() - t_vec_start) / iterations) * 1000

    X_combined = sp.hstack([sp.csr_matrix(X_num), X_tfidf])
    t_rf_start = time.perf_counter()
    for _ in range(iterations):
        model.predict_proba(X_combined)
    t_rf_ms = ((time.perf_counter() - t_rf_start) / iterations) * 1000

    print(f"\nLatency Breakdown:")
    print(f"  - Feature Extraction:  {t_feat_ms:.3f} ms ({t_feat_ms/avg_latency_ms*100:.1f}%)")
    print(f"  - Char TF-IDF Vector:  {t_vec_ms:.3f} ms ({t_vec_ms/avg_latency_ms*100:.1f}%)")
    print(f"  - Random Forest Model: {t_rf_ms:.3f} ms ({t_rf_ms/avg_latency_ms*100:.1f}%)")

    latency_dict = {
        "iterations": iterations,
        "avg_latency_ms": round(avg_latency_ms, 3),
        "throughput_rps": round(fps, 1),
        "breakdown": {
            "feature_extraction_ms": round(t_feat_ms, 3),
            "tfidf_transform_ms": round(t_vec_ms, 3),
            "rf_predict_ms": round(t_rf_ms, 3)
        }
    }
    return latency_dict

def main():
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    model, vec, cols = load_artifacts()

    evasion_results, robustness_rate = run_adversarial_suite(model, vec, cols)
    fp_results, fpr = run_false_positive_suite(model, vec, cols)
    latency_dict = run_latency_benchmark(model, vec, cols, iterations=50)

    report_data = {
        "adversarial_robustness_rate": round(robustness_rate, 2),
        "false_positive_rate": round(fpr, 2),
        "latency_benchmark": latency_dict,
        "evasion_details": evasion_results,
        "false_positive_details": fp_results
    }

    report_file = REPORTS_DIR / "security_benchmark_report.json"
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    print("\n==================================================")
    print(f"Security Benchmark Report saved to: {report_file}")
    print("==================================================\n")

if __name__ == "__main__":
    main()
