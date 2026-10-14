"""
AI-Driven SQL Injection Threat Detector & Real-Time Security Analyzer.
Inspects HTTP request parameters, URL paths, query strings, and POST bodies,
and autonomously detects malicious SQL injection attacks using trained Machine Learning models.
"""
import json
from collections import deque
import re
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Dict, Any, List, Optional

# Project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config import MODEL_FILE, VEC_FILE, COLS_FILE, MODEL_METADATA_FILE
from src.data_processing.feature_extractor import extract_features_from_row

import joblib
import numpy as np
import scipy.sparse as sp


def detect_threat_indicators(text_to_inspect: str) -> List[str]:
    """
    Detect heuristic SQL injection threat indicators to provide explanatory diagnostics (XAI).
    Returns an empty list if no heuristic signature matches.
    """
    if not text_to_inspect or not text_to_inspect.strip():
        return []

    decoded = urllib.parse.unquote_plus(text_to_inspect)
    indicators = []

    if "'" in decoded:
        indicators.append("Single quote (') character detected")
    if '"' in decoded:
        indicators.append('Double quote (") character detected')
    if (
        re.search(r"\b(or|and)\b\s+['\"]?\w+['\"]?\s*(=|>|<|!=|<>)\s*['\"]?\w+", decoded, re.IGNORECASE)
        or "1=1" in decoded.replace(" ", "")
        or "2>1" in decoded.replace(" ", "")
    ):
        indicators.append("Tautology / Boolean condition (e.g. 1=1 or 'a'='a')")
    if re.search(r"\bunion\s+(all\s+)?select\b", decoded, re.IGNORECASE):
        indicators.append("UNION SELECT multi-table extraction sequence")
    if re.search(r"(--|#|/\*)", decoded):
        indicators.append("SQL comment syntax (-- or # or /*)")
    if "information_schema" in decoded.lower():
        indicators.append("Information Schema enumeration attempt")
    if "@@" in decoded or "@version" in decoded.lower():
        indicators.append("Database system variable inspection (@@version)")
    if re.search(r"\b(sleep|benchmark)\s*\(", decoded, re.IGNORECASE):
        indicators.append("Time-based Blind SQLi primitive (sleep / benchmark)")
    if re.search(r"\b(substring|substr|ascii|length)\s*\(", decoded, re.IGNORECASE):
        indicators.append("Boolean-based Blind SQLi primitive (substr / ascii / length)")
    if (
        re.search(r"\bcase\b\s+when\b|\bcase\b\s+\w+\s+when\b", decoded, re.IGNORECASE)
        or "1/0" in decoded.replace(" ", "")
    ):
        indicators.append("Error-based SQLi / conditional division by zero")
    if re.search(r"\b(extractvalue|updatexml|floor|rand)\b", decoded, re.IGNORECASE):
        indicators.append("Error-based XML/Floor function injection pattern")

    return indicators


class ThreatDetector:
    """
    SQL injection threat inspection and real-time detection engine.
    Ensures schema integrity, dynamic class mapping, and dimension validation.
    """
    def __init__(
        self,
        model_path: Path = MODEL_FILE,
        vec_path: Path = VEC_FILE,
        cols_path: Path = COLS_FILE,
        metadata_path: Optional[Path] = MODEL_METADATA_FILE,
        threshold: Optional[float] = None,
        **kwargs
    ):
        # Resolve threshold: explicit argument > metadata.json > default 0.50
        if threshold is None:
            if metadata_path and metadata_path.exists():
                try:
                    with open(metadata_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                        threshold = float(meta.get("selected_threshold", meta.get("default_threshold", 0.50)))
                except Exception:
                    threshold = 0.50
            else:
                threshold = 0.50

        if not (0.0 <= threshold <= 1.0):
            raise ValueError(f"threshold must be between 0.0 and 1.0, got {threshold}")
        self.threshold = threshold

        if not (model_path.exists() and vec_path.exists() and cols_path.exists()):
            raise FileNotFoundError(f"Model artifacts not found in {model_path.parent}. Retrain pipeline first!")

        self.model = joblib.load(model_path)
        self.vectorizer = joblib.load(vec_path)
        self.feature_cols = joblib.load(cols_path)

        # Dynamic class resolution to prevent index assumption bugs
        classes = list(self.model.classes_)
        if 1 not in classes:
            raise ValueError(f"Model artifact lacks target SQLi class (label 1). Classes found: {classes}")
        self.sqli_class_idx = classes.index(1)

        # Dimension compatibility verification
        if hasattr(self.model, "n_features_in_"):
            tfidf_dim = len(self.vectorizer.get_feature_names_out())
            expected_total = len(self.feature_cols) + tfidf_dim
            if self.model.n_features_in_ != expected_total:
                raise ValueError(
                    f"Model dimension mismatch: model expects {self.model.n_features_in_} features, "
                    f"but {expected_total} were provided ({len(self.feature_cols)} num + {tfidf_dim} tfidf)."
                )

        # Real-time Metrics & In-Memory SOC Telemetry
        self.total_inspected = 0
        self.total_threats = 0
        self.total_clean = 0
        self.latencies_ms: deque = deque(maxlen=1000)
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
        Extract pre-execution features, predict SQLi risk probability, and measure end-to-end latency.
        """
        t_start = time.perf_counter()

        # 1. Robust URL & Query Normalization (avoid re-serialization artifacts)
        clean_path = path.strip() if path else "/"
        clean_query = query.strip() if query else ""
        if "?" in clean_path:
            path_part, query_part = clean_path.split("?", 1)
            clean_path = path_part
            clean_query = f"{query_part}&{clean_query}" if clean_query else query_part

        clean_query = clean_query.lstrip("?")
        decoded_path = urllib.parse.unquote(clean_path)
        decoded_query = urllib.parse.unquote_plus(clean_query)
        if "%25" in clean_query:
            try:
                decoded_query = urllib.parse.unquote_plus(decoded_query)
            except Exception:
                pass

        raw_body = body.strip() if body else ""
        decoded_body = urllib.parse.unquote_plus(raw_body) if raw_body else ""
        param_count_body = len(urllib.parse.parse_qs(raw_body)) if raw_body else 0

        parsed_url = f"{clean_path}?{clean_query}" if clean_query else clean_path
        decoded_url = f"{decoded_path}?{decoded_query}" if decoded_query else decoded_path
        req_line = f"{method.upper()} {parsed_url} HTTP/1.1"

        row_dict = {
            "ip": client_ip,
            "timestamp": time.strftime("%d/%b/%Y:%H:%M:%S +0700", time.localtime()),
            "method": method.upper(),
            "url": parsed_url,
            "path": clean_path,
            "query": clean_query,
            "protocol": "HTTP/1.1",
            "status": 200,
            "size": 1024,
            "referer": "-",
            "user_agent": "AI-Threat-Detector/1.0",
            "decoded_url": decoded_url,
            "decoded_query": decoded_query,
            "body": raw_body,
            "decoded_body": decoded_body,
            "content_type": content_type,
            "param_count_body": param_count_body
        }

        # 2. Extract Pre-execution Features
        feat_dict = extract_features_from_row(row_dict)

        # 3. Align Numerical Features with Schema Integrity Check
        missing_cols = [c for c in self.feature_cols if c not in feat_dict]
        if missing_cols and self.total_inspected == 0:
            print(f"[AI-DETECTOR][WARN] {len(missing_cols)} expected feature columns missing during inference: {missing_cols[:5]}...")

        num_vals = [feat_dict.get(c, 0.0) for c in self.feature_cols]
        X_num = np.array([num_vals], dtype=np.float32)

        # 4. Vectorize Text Content (Query + Body)
        X_text = [feat_dict.get("text", "")]
        X_tfidf = self.vectorizer.transform(X_text)

        # 5. Predict Probability with Exact Class Index
        X_combined = sp.hstack([sp.csr_matrix(X_num), X_tfidf]).tocsr()
        proba = self.model.predict_proba(X_combined)[0]
        sqli_prob = float(proba[self.sqli_class_idx]) if len(proba) > self.sqli_class_idx else 0.0

        # 6. Threat Classification & XAI Explanation Alignment
        is_attack = sqli_prob >= self.threshold
        inspect_target = f"{decoded_query} {decoded_body}".strip() if (decoded_query or decoded_body) else decoded_url
        raw_indicators = detect_threat_indicators(inspect_target)

        if raw_indicators:
            indicators = raw_indicators
        elif is_attack:
            indicators = ["ML anomaly detection flagged suspicious vector (No simple regex signature matched)"]
        else:
            indicators = ["Clean HTTP payload structure"]

        attack_type = "normal"
        if is_attack:
            t_low = inspect_target.lower()
            if re.search(r"\bunion\s+(all\s+)?select\b", t_low):
                attack_type = "sqli_union"
            elif re.search(r"\b(sleep|benchmark)\s*\(", t_low):
                attack_type = "sqli_blind_time"
            elif (
                re.search(r"\bcase\b\s+when\b", t_low)
                or "1/0" in t_low.replace(" ", "")
                or re.search(r"\b(extractvalue|updatexml|floor|rand)\b", t_low)
            ):
                attack_type = "sqli_blind_error"
            elif (
                re.search(r"\b(or|and)\b\s+['\"]?\w+['\"]?\s*(=|>|<|!=|<>)\s*['\"]?\w+", t_low)
                or "1=1" in t_low.replace(" ", "")
                or "2>1" in t_low.replace(" ", "")
                or re.search(r"\b(substring|substr|ascii|length)\s*\(", t_low)
            ):
                attack_type = "sqli_boolean"
            else:
                attack_type = "sqli_heuristic"

        # 7. End-to-End Latency Measurement (Includes ML + XAI Heuristics)
        latency_ms = (time.perf_counter() - t_start) * 1000

        # 8. Update Operational Metrics & Event Log
        self.total_inspected += 1
        self.latencies_ms.append(latency_ms)

        if is_attack:
            self.total_threats += 1
        else:
            self.total_clean += 1

        event_record = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "client_ip": client_ip,
            "method": method.upper(),
            "path": clean_path,
            "is_attack": is_attack,
            "confidence": round(sqli_prob, 4),
            "attack_type": attack_type,
            "latency_ms": round(latency_ms, 3)
        }
        self.event_log.append(event_record)
        if len(self.event_log) > 500:
            self.event_log.pop(0)

        return {
            "is_attack": is_attack,
            "confidence": sqli_prob,
            "threshold": self.threshold,
            "attack_type": attack_type,
            "indicators": indicators,
            "latency_ms": round(latency_ms, 3),
            "param_count_body": param_count_body,
            "body_length": len(raw_body),
            "request_line": req_line,
            "path": clean_path,
            "query": clean_query,
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
            "threshold": self.threshold,
            "recent_events_count": len(self.event_log)
        }

    def set_config(self, threshold: Optional[float] = None, **kwargs):
        """Update runtime detection threshold."""
        if threshold is not None:
            if not (0.0 <= threshold <= 1.0):
                raise ValueError(f"threshold must be between 0.0 and 1.0, got {threshold}")
            self.threshold = threshold

