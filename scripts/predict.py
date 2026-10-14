"""
Real-time CLI Predictor for Web Attack Detection (SQLi).
Evaluates individual HTTP requests using the centralized ThreatDetector engine.
"""
import argparse
from pathlib import Path
import sys
from typing import Any, Dict, Optional
import urllib.parse

# Ensure project root is in sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.detector.threat_detector import ThreatDetector

_DETECTOR: Optional[ThreatDetector] = None


def get_detector() -> ThreatDetector:
    global _DETECTOR
    if _DETECTOR is None:
        _DETECTOR = ThreatDetector()
    return _DETECTOR


def predict_request(
    request_str: str = "",
    method_in: str = "",
    url_in: str = "",
    body_in: str = "",
    content_type_in: str = "",
    detector: Optional[ThreatDetector] = None,
    **kwargs
) -> Dict[str, Any]:
    """
    Predict SQL Injection risk for an HTTP request using ThreatDetector.
    """
    det = detector if detector is not None else get_detector()

    if request_str and not url_in:
        parts = request_str.strip().split()
        if len(parts) >= 2:
            method = parts[0].upper()
            raw_url = parts[1]
        elif len(parts) == 1:
            method = "GET"
            raw_url = parts[0]
        else:
            method = "GET"
            raw_url = "/"
    elif url_in:
        method = method_in.upper() if method_in else ("POST" if body_in else "GET")
        raw_url = url_in
    else:
        method = "GET"
        raw_url = "/"

    if method_in:
        method = method_in.upper()

    parsed = urllib.parse.urlparse(raw_url)
    path = parsed.path if parsed.path else "/"
    query = parsed.query

    insp = det.inspect_request(
        method=method,
        path=path,
        query=query,
        body=body_in,
        content_type=content_type_in
    )

    pred = 1 if insp["is_attack"] else 0
    sqli_prob = insp["confidence"]
    normal_prob = round(1.0 - sqli_prob, 4)
    label_str = "SQL Injection" if insp["is_attack"] else "Normal"

    print("====================================")
    print("SQL INJECTION PREDICTION")
    print("====================================")
    print(f"Request:      {insp['request_line']}")
    if body_in:
        print(f"Body:         {body_in[:120]}{'...' if len(body_in) > 120 else ''}")
        print(f"Content-Type: {content_type_in if content_type_in else 'unspecified'}")
    print(f"Prediction:   {label_str}")
    print(f"Label:        {pred}")
    print("\nProbability:")
    print(f"  SQLi:       {sqli_prob:.4f}")
    print(f"  Normal:     {normal_prob:.4f}")
    print("\nDetected indicators:")
    for ind in insp["indicators"]:
        print(f"- {ind}")
    print("====================================\n")

    return {
        "label": pred,
        "sqli_prob": sqli_prob,
        "normal_prob": normal_prob,
        "indicators": insp["indicators"],
        "attack_type": insp["attack_type"]
    }


def main():
    detector = get_detector()

    parser = argparse.ArgumentParser(description="Real-time CLI Predictor for Web Attack Detection (SQLi)")
    parser.add_argument("request", nargs="?", default="", help="HTTP Request string, e.g. 'GET /vulnerabilities/sqli/?id=1 HTTP/1.1'")
    parser.add_argument("--method", type=str, default="", help="HTTP Method (GET, POST, etc.)")
    parser.add_argument("--url", type=str, default="", help="Target URL or Path (e.g. /vulnerabilities/sqli/ or /login.php)")
    parser.add_argument("--body", type=str, default="", help="Request Body content (form-urlencoded)")
    parser.add_argument("--content-type", type=str, default="", help="Content-Type header (e.g. application/x-www-form-urlencoded)")

    args = parser.parse_args()

    if args.request or args.url or args.body:
        predict_request(
            request_str=args.request,
            method_in=args.method,
            url_in=args.url,
            body_in=args.body,
            content_type_in=args.content_type,
            detector=detector
        )
    else:
        print("No input provided. Running comprehensive DVWA test suite (GET + POST Form)...\n")
        test_samples = [
            # 1. NORMAL GET
            {"request": "GET /index.php HTTP/1.1"},
            {"request": "GET /vulnerabilities/sqli/?id=1&Submit=Submit HTTP/1.1"},

            # 2. SQLi GET (Boolean, Union, Blind Time, Blind Error)
            {"request": "GET /vulnerabilities/sqli/?id=1%27+OR+1%3D1%23&Submit=Submit HTTP/1.1"},
            {"request": "GET /vulnerabilities/sqli/?id=%27+UNION+SELECT+table_name+FROM+information_schema.tables%23 HTTP/1.1"},
            {"request": "GET /vulnerabilities/sqli_blind/?id=1%27+AND+IF%281%3D1%2CSLEEP%285%29%2C0%29--+- HTTP/1.1"},
            {"request": "GET /vulnerabilities/sqli_blind/?id=1%27+AND+CASE+WHEN+%281%3D1%29+THEN+1/0+ELSE+1+END--+- HTTP/1.1"},

            # 3. NORMAL POST FORM
            {
                "method": "POST",
                "url": "/login.php",
                "body": "username=admin&password=password&Login=Login",
                "content_type": "application/x-www-form-urlencoded"
            },
            {
                "method": "POST",
                "url": "/vulnerabilities/sqli/",
                "body": "id=1&Submit=Submit",
                "content_type": "application/x-www-form-urlencoded"
            },

            # 4. SQLi POST FORM
            {
                "method": "POST",
                "url": "/login.php",
                "body": "username=admin' OR 1=1--&password=123&Login=Login",
                "content_type": "application/x-www-form-urlencoded"
            },
            {
                "method": "POST",
                "url": "/vulnerabilities/sqli/",
                "body": "id=1' UNION SELECT user,password FROM users--&Submit=Submit",
                "content_type": "application/x-www-form-urlencoded"
            },
            {
                "method": "POST",
                "url": "/vulnerabilities/sqli_blind/",
                "body": "id=1' AND SLEEP(5)--&Submit=Submit",
                "content_type": "application/x-www-form-urlencoded"
            }
        ]

        for s in test_samples:
            predict_request(
                request_str=s.get("request", ""),
                method_in=s.get("method", ""),
                url_in=s.get("url", ""),
                body_in=s.get("body", ""),
                content_type_in=s.get("content_type", ""),
                detector=detector
            )


if __name__ == "__main__":
    main()
