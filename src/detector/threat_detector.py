"""
AI-Driven SQL Injection Threat Detector & Real-Time Security Analyzer.
Inspects HTTP request parameters, URL paths, query strings, and POST bodies (JSON / Form),
and autonomously detects malicious SQL injection attacks using trained Machine Learning models.
"""
import html
import json
import re
import sys
import time
import uuid
import urllib.parse
from pathlib import Path
from typing import Dict, Tuple, Any, List

# Project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config import MODEL_FILE, VEC_FILE, COLS_FILE
from src.data_processing.apache_parser import parse_request_string
from src.data_processing.feature_extractor import extract_features_from_row

import joblib
import numpy as np
import scipy.sparse as sp

def detect_threat_indicators(text_to_inspect: str) -> List[str]:
    """Detect heuristic SQL injection threat indicators to provide explanatory diagnostics."""
    decoded = urllib.parse.unquote_plus(text_to_inspect)
    indicators = []

    if "'" in decoded:
        indicators.append("Single quote (') character detected")
    if '"' in decoded:
        indicators.append('Double quote (") character detected')
    if re.search(r"\bor\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+", decoded, re.IGNORECASE) or "1=1" in decoded.replace(" ", ""):
        indicators.append("Tautology / Boolean OR condition (e.g. 1=1 or 'a'='a')")
    if re.search(r"\bunion\s+(all\s+)?select\b", decoded, re.IGNORECASE):
        indicators.append("UNION SELECT multi-table extraction sequence")
    if re.search(r"(--|#|/\*)", decoded):
        indicators.append("SQL comment syntax (-- or # or /*)")
    if "information_schema" in decoded.lower():
        indicators.append("Information Schema schema enumeration attempt")
    if "@@" in decoded or "@version" in decoded.lower():
        indicators.append("Database system variable inspection (@@version)")
    if re.search(r"\b(sleep|benchmark)\s*\(", decoded, re.IGNORECASE):
        indicators.append("Time-based Blind SQLi primitive (sleep / benchmark)")
    if re.search(r"\b(substring|substr|ascii|length)\s*\(", decoded, re.IGNORECASE):
        indicators.append("Boolean-based Blind SQLi primitive (substr / ascii / length)")
    if re.search(r"\bcase\b.*\bwhen\b", decoded, re.IGNORECASE) or "1/0" in decoded.replace(" ", ""):
        indicators.append("Error-based SQLi / conditional division by zero")
    if re.search(r"\b(extractvalue|updatexml|floor|rand)\b", decoded, re.IGNORECASE):
        indicators.append("Error-based XML/Floor function injection pattern")

    return indicators if indicators else ["Clean HTTP payload structure"]

class ThreatDetector:
    """
    Production-grade AI Security Threat Inspector & Anomaly Detection Engine.
    """
    def __init__(
        self,
        model_path: Path = MODEL_FILE,
        vec_path: Path = VEC_FILE,
        cols_path: Path = COLS_FILE,
        threshold: float = 0.50,
        **kwargs
    ):
        self.threshold = threshold

        print(f"[AI-ENGINE] Initializing Threat Inspector (Threshold: {self.threshold:.2f})...")
        if not (model_path.exists() and vec_path.exists() and cols_path.exists()):
            raise FileNotFoundError(f"Model artifacts not found in {model_path.parent}. Retrain pipeline first!")

        self.model = joblib.load(model_path)
        self.vectorizer = joblib.load(vec_path)
        self.feature_cols = joblib.load(cols_path)
        print(f"[AI-DETECTOR] Model loaded with {len(self.feature_cols)} features & Char TF-IDF.")

        # Real-time Metrics
        self.total_inspected = 0
        self.total_threats = 0
        self.total_clean = 0
        self.latencies_ms: List[float] = []
        self.event_log: List[Dict[str, Any]] = []

    def inspect_request(
        self,
        method: str,
        path: str,
        query: str = "",
        body: str = "",
        content_type: str = "",
        client_ip: str = "127.0.0.1"
    ) -> Dict[str, Any]:
        """
        Extract pre-execution features, predict SQLi risk probability, and measure latency.
        """
        t_start = time.perf_counter()

        req_line = f"{method.upper()} {path}"
        if query:
            req_line += f"?{query}"
        req_line += " HTTP/1.1"

        (
            parsed_method, parsed_url, parsed_path, parsed_query, protocol,
            decoded_url, decoded_query, raw_body, decoded_body,
            is_json, json_depth, param_count_body
        ) = parse_request_string(req_line, body=body, content_type=content_type)

        row_dict = {
            "ip": client_ip,
            "timestamp": time.strftime("%d/%b/%Y:%H:%M:%S +0700", time.localtime()),
            "method": method.upper(),
            "url": parsed_url if parsed_url else req_line,
            "path": parsed_path,
            "query": parsed_query,
            "protocol": protocol if protocol else "HTTP/1.1",
            "status": 200,
            "size": 1024,
            "referer": "-",
            "user_agent": "AI-Threat-Detector/1.0",
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

        # 1. Align numerical features
        num_vals = [feat_dict.get(c, 0) for c in self.feature_cols]
        X_num = np.array([num_vals], dtype=np.float32)

        # 2. Vectorize text content (query + body)
        X_text = [feat_dict["text"]]
        X_tfidf = self.vectorizer.transform(X_text)

        # 3. Predict probability
        X_combined = sp.hstack([sp.csr_matrix(X_num), X_tfidf])
        proba = self.model.predict_proba(X_combined)[0]
        sqli_prob = float(proba[1]) if len(proba) > 1 else 0.0

        latency_ms = (time.perf_counter() - t_start) * 1000

        # Threat classification
        is_attack = sqli_prob >= self.threshold
        inspect_target = f"{decoded_query} {decoded_body}".strip() if (decoded_query or decoded_body) else decoded_url
        indicators = detect_threat_indicators(inspect_target)

        attack_type = "normal"
        if is_attack:
            t_low = inspect_target.lower()
            if "union" in t_low: attack_type = "sqli_union"
            elif "sleep" in t_low or "benchmark" in t_low: attack_type = "sqli_blind_time"
            elif "1/0" in t_low or "case" in t_low: attack_type = "sqli_blind_error"
            elif is_json: attack_type = "sqli_json"
            else: attack_type = "sqli_boolean"

        # Update operational metrics
        self.total_inspected += 1
        self.latencies_ms.append(latency_ms)
        if len(self.latencies_ms) > 1000:
            self.latencies_ms.pop(0)

        if is_attack:
            self.total_threats += 1
        else:
            self.total_clean += 1

        return {
            "is_attack": is_attack,
            "confidence": sqli_prob,
            "threshold": self.threshold,
            "attack_type": attack_type,
            "indicators": indicators,
            "latency_ms": round(latency_ms, 3),
            "is_json": bool(is_json),
            "json_depth": json_depth,
            "param_count_body": param_count_body,
            "body_length": len(raw_body),
            "request_line": req_line,
            "path": parsed_path,
            "query": parsed_query,
            "body": raw_body,
            "client_ip": client_ip
        }

    def get_stats(self) -> Dict[str, Any]:
        """Return real-time SOC threat monitoring metrics."""
        avg_lat = sum(self.latencies_ms) / len(self.latencies_ms) if self.latencies_ms else 0.0
        threat_rate = (self.total_threats / self.total_inspected * 100) if self.total_inspected > 0 else 0.0
        return {
            "total_inspected": self.total_inspected,
            "total_threats": self.total_threats,
            "total_clean": self.total_clean,
            "threat_rate_percent": round(threat_rate, 2),
            "avg_latency_ms": round(avg_lat, 2),
            "threshold": self.threshold
        }

    def set_config(self, threshold: float = None, **kwargs):
        """Update runtime detection threshold."""
        if threshold is not None and 0.0 <= threshold <= 1.0:
            self.threshold = threshold
