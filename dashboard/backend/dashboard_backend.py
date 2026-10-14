"""
AI Threat Intelligence & Real-Time SOC Monitoring - Dashboard Web Server.
Orchestrates:
1. LogCollector (Tail logs via Local & Remote SSH/SFTP)
2. ThreatDetector (Machine Learning Inference Engine & XAI)
3. EventStore (Thread-safe event streaming queue)
4. DashboardRequestHandler (HTTP Static Server & SOC REST APIs)
"""
import http.server
import socketserver
import json
import sys
import time
import urllib.parse
from pathlib import Path

# Path setup
BACKEND_DIR = Path(__file__).resolve().parent
DASHBOARD_DIR = BACKEND_DIR.parent
FRONTEND_DIR = DASHBOARD_DIR / "frontend"
PROJECT_ROOT = DASHBOARD_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import (
    MODEL_FILE, VEC_FILE, COLS_FILE, RAW_LOG_FILE,
    REMOTE_SSH_HOST, REMOTE_SSH_PORT, REMOTE_SSH_USER, REMOTE_SSH_PASS, REMOTE_LOG_PATH,
    DASHBOARD_HOST, DASHBOARD_PORT, DETECTION_THRESHOLD
)
from src.data_processing.apache_parser import parse_raw_line
from src.detector.threat_detector import ThreatDetector
from dashboard.backend.store import EventStore
from dashboard.backend.collector import LogCollector


# 1. Initialize Event Store
event_store = EventStore(max_size=500)

# 2. Initialize Global AI Threat Inspector Engine
print(f"[DASHBOARD] Initializing AI Threat Inspector Engine (Threshold: {DETECTION_THRESHOLD:.2f})...")
threat_detector = ThreatDetector(
    model_path=MODEL_FILE,
    vec_path=VEC_FILE,
    cols_path=COLS_FILE,
    threshold=DETECTION_THRESHOLD
)
print(f"[DASHBOARD] AI Threat Inspector Engine Ready (Threshold: {threat_detector.threshold:.2f}).")

# 3. Log line handler connecting Collector -> ThreatDetector -> EventStore
def handle_incoming_log_line(line: str):
    rec = parse_raw_line(line)
    if not rec:
        return

    insp = threat_detector.inspect_request(
        method=rec.get("method", "GET"),
        path=rec.get("path", "/"),
        query=rec.get("query", ""),
        body=rec.get("body", ""),
        content_type=rec.get("content_type", ""),
        client_ip=rec.get("ip", "127.0.0.1")
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
        "indicators": insp["indicators"]
    }
    event_store.enqueue(evt)

# 4. Start Background Log Collector
log_collector = LogCollector(
    local_log_path=RAW_LOG_FILE,
    remote_host=REMOTE_SSH_HOST,
    remote_port=REMOTE_SSH_PORT,
    remote_user=REMOTE_SSH_USER,
    remote_pass=REMOTE_SSH_PASS,
    remote_log_path=REMOTE_LOG_PATH,
    on_log_line=handle_incoming_log_line,
    poll_interval=1.0
)
log_collector.start()

# 5. HTTP Request Handler
class DashboardRequestHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress periodic polling noise from terminal
        if args and len(args) > 0:
            msg = str(args[0])
            if "/api/stream" in msg or "/api/stats" in msg or "/api/config" in msg:
                return
        super().log_message(format, *args)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ["/", "/index.html"]:
            self.serve_file(FRONTEND_DIR / "index.html", "text/html")
        elif path in ["/css/style.css", "/style.css"]:
            self.serve_file(FRONTEND_DIR / "css" / "style.css", "text/css")
        elif path in ["/js/app.js", "/app.js"]:
            self.serve_file(FRONTEND_DIR / "js" / "app.js", "application/javascript")
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
        events = event_store.consume_stream_events()
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
            val = data.get("threshold")
            threshold = float(val) if val is not None else None
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
            method = data.get("method", "GET").upper()
            url_str = data.get("url", "/")
            parsed_u = urllib.parse.urlparse(url_str)
            path = parsed_u.path if parsed_u.path else "/"
            query = parsed_u.query if parsed_u.query else data.get("query", "")
            req_body = data.get("body", "")
            content_type = data.get("content_type", "")
            client_ip = data.get("client_ip", "127.0.0.1")

            insp = threat_detector.inspect_request(
                method=method,
                path=path,
                query=query,
                body=req_body,
                content_type=content_type,
                client_ip=client_ip
            )

            result = {
                "is_attack": insp["is_attack"],
                "prediction": "SQL INJECTION" if insp["is_attack"] else "NORMAL",
                "confidence": insp["confidence"],
                "attack_type": insp["attack_type"],
                "latency_ms": insp["latency_ms"],
                "indicators": insp["indicators"]
            }

            resp_body = json.dumps(result).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
        except Exception:
            self.send_response(500)
            self.end_headers()




def main():
    PORT = DASHBOARD_PORT
    HOST = DASHBOARD_HOST   
    print(f"Dashboard Web UI:   http://{HOST}:{PORT}")
    print(f"Listening Address:      {HOST}:{PORT}")
    print("Press Ctrl+C to stop the server.")

    socketserver.TCPServer.allow_reuse_address = True
    handler = DashboardRequestHandler
    with socketserver.TCPServer((HOST, PORT), handler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down Dashboard server...")
            httpd.shutdown()

if __name__ == "__main__":
    main()
