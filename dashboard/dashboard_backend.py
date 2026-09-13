"""
AI Threat Intelligence & Real-Time SOC Monitoring - Dashboard Web Backend Server.
Runs lightweight Python HTTP server on http://127.0.0.1:5000 serving:
1. Real-time SOC Monitoring Dashboard (GET /, /style.css, /app.js, /api/stream)
2. SOC Operational Management APIs (/api/stats, /api/predict, /api/simulate)
"""
import http.server
import socketserver
import json
import re
import sys
import time
import random
import urllib.parse
import threading
from pathlib import Path

# Add project root to sys.path
DASHBOARD_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = DASHBOARD_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config import MODEL_FILE, VEC_FILE, COLS_FILE, RAW_LOG_FILE
from src.data_processing.apache_parser import parse_raw_line
from src.detector.threat_detector import ThreatDetector, detect_threat_indicators

# Initialize Global AI Threat Inspector Engine
print("[DASHBOARD] Initializing AI Threat Inspector Engine...")
threat_detector = ThreatDetector(
    model_path=MODEL_FILE,
    vec_path=VEC_FILE,
    cols_path=COLS_FILE,
    threshold=0.50
)
print("[DASHBOARD] AI Threat Inspector Engine Ready (Threshold: 0.50).")

# Global Event Queue for Real-time Stream
STREAM_EVENT_QUEUE = []
LOCK = threading.Lock()

def enqueue_security_event(event_dict: dict):
    """Enqueue an event to stream to the SOC Web Dashboard."""
    with LOCK:
        STREAM_EVENT_QUEUE.append(event_dict)
        if len(STREAM_EVENT_QUEUE) > 500:
            STREAM_EVENT_QUEUE.pop(0)

# Background Log Tailer Thread (Local Log + SSH SFTP Remote Log from 192.168.145.135)
def start_log_tailer():
    remote_host = "192.168.145.135"
    remote_user = "kali"
    remote_pass = "kali"
    remote_log_path = "/var/log/apache2/access.log"

    last_remote_size = 0
    last_local_pos = 0

    print(f"[DASHBOARD] Starting Background Log Tailer (Local + SSH SFTP: {remote_user}@{remote_host})...")

    while True:
        # 1. Local Log File Check
        try:
            if RAW_LOG_FILE.exists():
                with open(RAW_LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
                    f.seek(last_local_pos)
                    lines = f.readlines()
                    last_local_pos = f.tell()
                    for line in lines:
                        if not line.strip() or line.startswith("timestamp,") or line.startswith("#"):
                            continue
                        rec = parse_raw_line(line)
                        if rec:
                            insp = threat_detector.inspect_request(
                                method=rec.get("method", "GET"),
                                path=rec.get("path", "/"),
                                query=rec.get("query", ""),
                                body=rec.get("body", ""),
                                content_type=rec.get("content_type", ""),
                                client_ip=rec.get("ip", "192.168.145.135")
                            )
                            evt = {
                                "timestamp": time.strftime("%H:%M:%S", time.localtime()),
                                "source_ip": insp["client_ip"],
                                "method": rec.get("method", "GET"),
                                "url": f"{rec.get('path', '/')}?{rec.get('query', '')}" if rec.get('query') else rec.get('path', '/'),
                                "path": insp["path"],
                                "query": insp["query"],
                                "body": insp["body"],
                                "label": 1 if insp["is_attack"] else 0,
                                "label_str": "SQL INJECTION" if insp["is_attack"] else "NORMAL",
                                "confidence": insp["confidence"],
                                "action": "CRITICAL THREAT" if insp["is_attack"] else "SAFE (NORMAL)",
                                "attack_type": insp["attack_type"],
                                "latency_ms": insp["latency_ms"],
                                "indicators": insp["indicators"],
                                "is_json": insp["is_json"]
                            }
                            enqueue_security_event(evt)
        except Exception:
            pass

        # 2. SSH SFTP Remote Log Tailer from Ubuntu Web VM (192.168.145.135)
        try:
            import paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(remote_host, port=22, username=remote_user, password=remote_pass, timeout=2)
            sftp = ssh.open_sftp()
            
            stat = sftp.stat(remote_log_path)
            curr_size = stat.st_size

            if last_remote_size == 0:
                last_remote_size = max(0, curr_size - 4096)

            if curr_size > last_remote_size:
                with sftp.open(remote_log_path, "r") as f:
                    f.seek(last_remote_size)
                    new_content = f.read()
                    last_remote_size = curr_size

                if new_content:
                    lines = new_content.decode("utf-8", errors="ignore").splitlines()
                    for line in lines:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        rec = parse_raw_line(line)
                        if rec:
                            insp = threat_detector.inspect_request(
                                method=rec.get("method", "GET"),
                                path=rec.get("path", "/"),
                                query=rec.get("query", ""),
                                body=rec.get("body", ""),
                                content_type=rec.get("content_type", ""),
                                client_ip=rec.get("ip", "192.168.145.135")
                            )
                            evt = {
                                "timestamp": time.strftime("%H:%M:%S", time.localtime()),
                                "source_ip": insp["client_ip"],
                                "method": rec.get("method", "GET"),
                                "url": f"{rec.get('path', '/')}?{rec.get('query', '')}" if rec.get('query') else rec.get('path', '/'),
                                "path": insp["path"],
                                "query": insp["query"],
                                "body": insp["body"],
                                "label": 1 if insp["is_attack"] else 0,
                                "label_str": "SQL INJECTION" if insp["is_attack"] else "NORMAL",
                                "confidence": insp["confidence"],
                                "action": "CRITICAL THREAT" if insp["is_attack"] else "SAFE (NORMAL)",
                                "attack_type": insp["attack_type"],
                                "latency_ms": insp["latency_ms"],
                                "indicators": insp["indicators"],
                                "is_json": insp["is_json"]
                            }
                            enqueue_security_event(evt)

            sftp.close()
            ssh.close()
        except Exception:
            pass

        time.sleep(1.0)

threading.Thread(target=start_log_tailer, daemon=True).start()

class DashboardRequestHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress periodic /api/stream and /api/stats polling noise from flooding the terminal
        if args and len(args) > 0:
            msg = str(args[0])
            if "/api/stream" in msg or "/api/stats" in msg or "/api/config" in msg:
                return
        super().log_message(format, *args)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ["/", "/index.html"]:
            self.serve_file(DASHBOARD_DIR / "index.html", "text/html")
        elif path == "/style.css":
            self.serve_file(DASHBOARD_DIR / "style.css", "text/css")
        elif path == "/app.js":
            self.serve_file(DASHBOARD_DIR / "app.js", "application/javascript")
        elif path == "/api/stream":
            self.handle_api_stream()
        elif path in ["/api/stats", "/api/detector/stats"]:
            self.handle_api_stats()
        else:
            super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""

        if path == "/api/predict":
            self.handle_api_predict(body)
        elif path == "/api/config":
            self.handle_api_config_update(body)
        else:
            self.send_response(404)
            self.end_headers()

    def serve_file(self, file_path: Path, content_type: str):
        if not file_path.exists():
            self.send_response(404)
            self.end_headers()
            return
        with open(file_path, "rb") as f:
            content = f.read()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def handle_api_stream(self):
        with LOCK:
            events = list(STREAM_EVENT_QUEUE)
            STREAM_EVENT_QUEUE.clear()

        resp_body = json.dumps({"events": events}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

    def handle_api_stats(self):
        stats = threat_detector.get_stats()
        resp_body = json.dumps(stats).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

    def handle_api_config_update(self, body_str: str):
        try:
            data = json.loads(body_str) if body_str else {}
            threshold = float(data.get("threshold")) if "threshold" in data else None
            threat_detector.set_config(threshold=threshold)

            stats = threat_detector.get_stats()
            resp_body = json.dumps({"status": "success", "config": stats}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
        except Exception as e:
            err_body = json.dumps({"status": "error", "message": str(e)}).encode("utf-8")
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(err_body)))
            self.end_headers()
            self.wfile.write(err_body)

    def handle_api_predict(self, body_str: str):
        try:
            data = json.loads(body_str) if body_str else {}
            req_str = data.get("request", "")
            method = data.get("method", "GET").upper()
            url_target = data.get("url", "/")
            raw_body = data.get("body", "")
            content_type = data.get("content_type", "")

            if req_str and not data.get("url"):
                parts = req_str.strip().split()
                method = parts[0] if len(parts) > 0 else "GET"
                url_target = parts[1] if len(parts) > 1 else "/"

            parsed = urllib.parse.urlparse(url_target)
            path = parsed.path if parsed.path else "/"
            query = parsed.query

            insp = threat_detector.inspect_request(
                method=method,
                path=path,
                query=query,
                body=raw_body,
                content_type=content_type,
                client_ip=self.client_address[0]
            )

            is_attack = insp["is_attack"]
            result = {
                "timestamp": time.strftime("%H:%M:%S", time.localtime()),
                "source_ip": self.client_address[0],
                "method": method,
                "url": url_target,
                "path": path,
                "query": query,
                "body": raw_body,
                "label": 1 if is_attack else 0,
                "label_str": "SQL INJECTION" if is_attack else "NORMAL",
                "confidence": insp["confidence"],
                "attack_type": insp["attack_type"],
                "latency_ms": insp["latency_ms"],
                "indicators": insp["indicators"],
                "is_json": insp["is_json"]
            }

            resp_body = json.dumps(result).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
        except Exception as e:
            self.send_response(500)
            self.end_headers()


def main():
    PORT = 5000
    print("==================================================")
    print("AI THREAT INTELLIGENCE & REAL-TIME SOC MONITORING")
    print("==================================================")
    print(f"SOC Dashboard Web UI:   http://127.0.0.1:{PORT}")
    print(f"Inspection Engine:      Random Forest (84 Features + TF-IDF)")
    print(f"Listening Address:      0.0.0.0:{PORT}")
    print("Press Ctrl+C to stop the server.")
    print("==================================================")

    socketserver.TCPServer.allow_reuse_address = True
    handler = DashboardRequestHandler
    with socketserver.TCPServer(("0.0.0.0", PORT), handler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down Dashboard server...")
            httpd.shutdown()

if __name__ == "__main__":
    main()
