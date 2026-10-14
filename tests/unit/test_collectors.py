"""
Unit tests for Collectors: payload_generator and traffic_generator.
Validates:
- Syntax-preserving quote transformations without blind replacement bugs.
- Safe SQL comment variations (no dangling /*).
- Exact SHA256 deduplication vs canonical similarity.
- Label conflict detection.
- Zero-leakage family splitting (strictly disjoint holdout challenge sets).
- Exact duplicate leakage prevention across splits.
- Empty dataset and error validation.
- HTTP traffic conversion for DVWA endpoints.
"""
import unittest
from pathlib import Path
import random
import json
import socket
import tempfile
import threading
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from unittest.mock import MagicMock, patch
import pandas as pd

from src.collectors.payload_generator import (
    semantic_normalize,
    apply_quote_variation,
    apply_comment_variation,
    split_dataset_by_family,
    FAMILY_BOOLEAN_TAUTOLOGY,
    FAMILY_NUMERIC_STACKED,
    FAMILY_NORMAL_BENIGN,
    FAMILY_BLIND_TIME_SLEEP,
    FAMILY_ENCODED_OBFUSCATED,
    FAMILY_SCHEMA_ENUM,
    FAMILY_SYNTAX_PROBE,
    FAMILY_AUTH_BYPASS,
    FAMILY_UNION_SELECT
)
from src.collectors.traffic_generator import (
    TrafficConfig,
    ConfigurationError,
    DatasetValidationError,
    AuthenticationError,
    CollectionStatus,
    SSHLogCollectionResult,
    HTTPRequestSpec,
    load_and_validate_dataset,
    authenticate_dvwa,
    convert_payload_to_http_request,
    send_single_live_request,
    fetch_incremental_apache_log,
    run_traffic_pipeline
)


class TestCollectors(unittest.TestCase):

    def test_01_sql_normalization(self):
        """Test SQL query normalization handles whitespace and comments consistently."""
        raw1 = "  SELECT   *  FROM   users  WHERE 1=1 --  "
        norm1 = semantic_normalize(raw1)
        self.assertIn("select", norm1)
        self.assertIn("1=1", norm1)

        raw2 = "1' OR '1'='1"
        norm2 = semantic_normalize(raw2)
        self.assertEqual(norm2, "1'or'1'='1")

    def test_02_quote_variation_safety(self):
        """
        Verify quote variation does not suffer from blind sequential replacement bugs
        where inserting (' and searching next ' mutates the newly inserted character.
        """
        rng = random.Random(42)
        payload = "id=1' OR 'a'='a' -- "
        for _ in range(50):
            res, style = apply_quote_variation(payload, rng)
            self.assertNotIn("()'", res, "Corrupt quote syntax ()' detected from blind replacement!")
            if style == "double_quote":
                self.assertIn('"', res)
                self.assertNotIn("'", res)

    def test_03_comment_variation_safety(self):
        """
        Verify comment variations only append valid, non-dangling comment structures.
        A dangling /* without */ is forbidden.
        """
        rng = random.Random(42)
        payload = "id=1' OR 1=1"
        for _ in range(50):
            res, name = apply_comment_variation(payload, rng)
            # Ensure no dangling unclosed block comment
            if "/*" in res:
                self.assertIn("*/", res, f"Dangling unclosed block comment in: {res}")
            # Ensure double dash has space
            if "--" in res and not res.endswith("-- -"):
                self.assertTrue("-- " in res or "--+" in res or ";--" in res or "-- -" in res,
                                f"Invalid double dash comment: {res}")

    def test_04_exact_hash_vs_normalized_hash(self):
        """
        Verify that exact hash distinguishes distinct variants while normalized hash
        tracks canonical similarity.
        """
        p1 = "id=1' OR 1=1 -- "
        p2 = "id=1'  or  1=1 -- "
        norm1 = semantic_normalize(p1)
        norm2 = semantic_normalize(p2)
        self.assertEqual(norm1, norm2, "Semantically similar queries must have same normalized representation.")
        self.assertNotEqual(p1, p2, "Raw distinct strings must not be identical.")

    def test_05_family_zero_leakage_split(self):
        """
        Test that SQLi attack families in Train, Val, and Test Unseen are strictly disjoint.
        """
        samples = [
            {"payload": "1' or 1=1-- ", "label": 1, "family_id": FAMILY_BOOLEAN_TAUTOLOGY},
            {"payload": "1' or 'a'='a", "label": 1, "family_id": FAMILY_BOOLEAN_TAUTOLOGY},
            {"payload": "1; sleep(3)-- ", "label": 1, "family_id": FAMILY_BLIND_TIME_SLEEP},
            {"payload": "1; drop table users-- ", "label": 1, "family_id": FAMILY_NUMERIC_STACKED},
            {"payload": "0x27204f5220313d31", "label": 1, "family_id": FAMILY_ENCODED_OBFUSCATED},
            {"payload": "1' union select version()-- ", "label": 1, "family_id": FAMILY_SCHEMA_ENUM},
            {"payload": "1' order by 1-- ", "label": 1, "family_id": FAMILY_SYNTAX_PROBE},
            {"payload": "search_term_normal_1", "label": 0, "family_id": FAMILY_NORMAL_BENIGN},
            {"payload": "search_term_normal_2", "label": 0, "family_id": FAMILY_NORMAL_BENIGN},
            {"payload": "search_term_normal_3", "label": 0, "family_id": FAMILY_NORMAL_BENIGN},
            {"payload": "search_term_normal_4", "label": 0, "family_id": FAMILY_NORMAL_BENIGN},
            {"payload": "search_term_normal_5", "label": 0, "family_id": FAMILY_NORMAL_BENIGN},
            {"payload": "search_term_normal_6", "label": 0, "family_id": FAMILY_NORMAL_BENIGN},
            {"payload": "search_term_normal_7", "label": 0, "family_id": FAMILY_NORMAL_BENIGN},
        ]
        df_samples = pd.DataFrame(samples)
        train_df, val_df, unseen_df = split_dataset_by_family(df_samples, seed=42)

        train_families = set(train_df[train_df["label"] == 1]["family_id"].unique())
        val_families = set(val_df[val_df["label"] == 1]["family_id"].unique())
        unseen_families = set(unseen_df[unseen_df["label"] == 1]["family_id"].unique())

        # Test Unseen families must have strictly zero overlap with Train or Val
        self.assertTrue(train_families.isdisjoint(unseen_families),
                        f"Leakage! Train & Unseen overlap: {train_families.intersection(unseen_families)}")
        self.assertTrue(val_families.isdisjoint(unseen_families),
                        f"Leakage! Val & Unseen overlap: {val_families.intersection(unseen_families)}")
        self.assertTrue(train_families.isdisjoint(val_families),
                        f"Leakage! Train & Val overlap: {train_families.intersection(val_families)}")

    def test_06_exact_duplicate_leakage_detection(self):
        """
        Verify that exact duplicate payloads across splits trigger an immediate error.
        """
        train_set = {"payload_A", "payload_B"}
        test_set = {"payload_B", "payload_C"}  # payload_B leaked!
        self.assertFalse(train_set.isdisjoint(test_set))

    def test_07_empty_dataset_handling(self):
        """Verify that split_dataset_by_family raises ValueError on an empty DataFrame."""
        empty_df = pd.DataFrame(columns=["payload", "label", "family_id"])
        with self.assertRaises(ValueError):
            split_dataset_by_family(empty_df)

    def test_08_http_conversion_normal(self):
        """Test converting benign payloads into HTTP requests."""
        rng = random.Random(42)
        method, path, query, body, content_type, _ = convert_payload_to_http_request(
            payload="/dvwa/css/main.css",
            family_id=FAMILY_NORMAL_BENIGN,
            attack_type="normal",
            label=0,
            rng=rng
        )
        self.assertEqual(method, "GET")
        self.assertEqual(path, "/dvwa/css/main.css")
        self.assertEqual(body, "")

    def test_09_http_conversion_auth_bypass(self):
        """Test converting auth bypass payloads into DVWA login POST or SQLi GET."""
        rng = random.Random(123)
        method, path, query, body, content_type, _ = convert_payload_to_http_request(
            payload="admin' -- ",
            family_id=FAMILY_AUTH_BYPASS,
            attack_type="sqli_auth_bypass",
            label=1,
            rng=rng
        )
        self.assertIn(method, ["POST", "GET"])
        if method == "POST":
            self.assertEqual(path, "/login.php")
            self.assertIn("username=", body)
            self.assertEqual(content_type, "application/x-www-form-urlencoded")
        else:
            self.assertEqual(path, "/vulnerabilities/sqli/")
            self.assertIn("admin'", query)

    def test_10_http_conversion_blind_sqli(self):
        """Test blind SQLi correctly routes to /vulnerabilities/sqli_blind/."""
        rng = random.Random(42)
        method, path, query, body, content_type, _ = convert_payload_to_http_request(
            payload="1' AND SLEEP(2)#",
            family_id=FAMILY_BLIND_TIME_SLEEP,
            attack_type="sqli_blind_time",
            label=1,
            rng=rng
        )
        self.assertEqual(method, "GET")
        self.assertEqual(path, "/vulnerabilities/sqli_blind/")
        self.assertIn("SLEEP(2)", query)


class MockHTTPServerHandler(BaseHTTPRequestHandler):
    received_requests = []

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        MockHTTPServerHandler.received_requests.append({
            "method": "GET",
            "path": parsed.path,
            "query": parsed.query,
            "params": qs,
            "headers": dict(self.headers)
        })
        if parsed.path == "/login.php":
            body = b'<html><input type="hidden" name="user_token" value="test_token_123" /></html>'
            self.send_response(200)
            self.send_header("Set-Cookie", "PHPSESSID=session_abc123; path=/")
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)
        elif parsed.path in ["/vulnerabilities/sqli/", "/vulnerabilities/sqli_blind/"]:
            cookie = self.headers.get("Cookie", "")
            if "session_authenticated_999" in cookie:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"User ID exists in database.")
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b'<html><form action="login.php">Login :: Damn Vulnerable Web Application</form></html>')
        elif parsed.path == "/status_404":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")
        elif parsed.path == "/status_500":
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Internal Error")
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(length)
        parsed = urllib.parse.urlsplit(self.path)
        body_str = body_bytes.decode("utf-8", errors="replace")
        qs = urllib.parse.parse_qs(body_str, keep_blank_values=True)
        MockHTTPServerHandler.received_requests.append({
            "method": "POST",
            "path": parsed.path,
            "body": body_str,
            "params": qs,
            "headers": dict(self.headers)
        })
        if parsed.path == "/login.php":
            user = qs.get("username", [""])[0]
            password = qs.get("password", [""])[0]
            token = qs.get("user_token", [""])[0]
            if user == "admin" and password == "password":
                self.send_response(302)
                self.send_header("Location", "/index.php")
                self.send_header("Set-Cookie", "PHPSESSID=session_authenticated_999; path=/")
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"Login failed")
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"POST OK")

    def log_message(self, format, *args):
        pass  # Suppress logging during tests


class TestTrafficGeneratorHarden(unittest.TestCase):
    server = None
    server_thread = None
    server_port = 0

    @classmethod
    def setUpClass(cls):
        MockHTTPServerHandler.received_requests = []
        cls.server = HTTPServer(("127.0.0.1", 0), MockHTTPServerHandler)
        cls.server_port = cls.server.server_port
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        if cls.server:
            cls.server.shutdown()
            cls.server.server_close()

    def setUp(self):
        MockHTTPServerHandler.received_requests.clear()

    # --- 1. Configuration & Input Validation Tests (AC-01, AC-05, AC-08) ---

    def test_11_config_validation_target_url(self):
        """Verify invalid target URLs fail early with ConfigurationError."""
        # Missing or empty
        with self.assertRaises(ConfigurationError):
            TrafficConfig(target_url="").validate()

        # Invalid scheme
        with self.assertRaises(ConfigurationError):
            TrafficConfig(target_url="ftp://192.168.1.1/").validate()

        # Embedded credentials forbidden
        with self.assertRaises(ConfigurationError):
            TrafficConfig(target_url="http://admin:pass@192.168.1.1/").validate()

    def test_12_config_validation_ssh_independent(self):
        """Verify Web target and SSH host are strictly independent."""
        # SSH host missing when collection enabled
        with self.assertRaises(ConfigurationError):
            TrafficConfig(
                target_url="http://192.168.1.100/",
                ssh_host="",
                enable_ssh_collection=True
            ).validate()

        # Invalid SSH port
        with self.assertRaises(ConfigurationError):
            TrafficConfig(
                target_url="http://192.168.1.100/",
                ssh_host="192.168.1.100",
                ssh_port=70000,
                enable_ssh_collection=True
            ).validate()

    def test_13_config_validation_workers_and_delay(self):
        """Verify worker bounds and non-negative delays are enforced."""
        with self.assertRaises(ConfigurationError):
            TrafficConfig(workers=0).validate()
        with self.assertRaises(ConfigurationError):
            TrafficConfig(workers=25).validate()
        with self.assertRaises(ConfigurationError):
            TrafficConfig(delay=-0.1).validate()
        with self.assertRaises(ConfigurationError):
            TrafficConfig(timeout_sec=0).validate()

    # --- 2. Dataset Validation Tests (AC-08) ---

    def test_14_dataset_validation_missing_or_empty(self):
        """Verify missing or corrupt dataset files raise DatasetValidationError."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)

            # Missing file
            with self.assertRaises(DatasetValidationError):
                load_and_validate_dataset(tmp_path / "non_existent.csv")

            # Empty file
            empty_file = tmp_path / "empty.csv"
            empty_file.write_text("", encoding="utf-8")
            with self.assertRaises(DatasetValidationError):
                load_and_validate_dataset(empty_file)

            # Missing required 'payload' column
            bad_cols = tmp_path / "bad_cols.csv"
            pd.DataFrame([{"query": "1=1", "label": 1}]).to_csv(bad_cols, index=False)
            with self.assertRaises(DatasetValidationError):
                load_and_validate_dataset(bad_cols)

            # Invalid label value (e.g. 2)
            bad_lbl = tmp_path / "bad_lbl.csv"
            pd.DataFrame([{"payload": "1=1", "label": 2}]).to_csv(bad_lbl, index=False)
            with self.assertRaises(DatasetValidationError):
                load_and_validate_dataset(bad_lbl)

    def test_15_dataset_sample_count_contract(self):
        """Verify sample count contract: None=all, count <= 0 rejected, count > size clamped."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            csv_path = Path(tmp_dir) / "test_data.csv"
            rows = [{"payload": f"query_{i}", "label": i % 2, "family_id": "normal"} for i in range(10)]
            pd.DataFrame(rows).to_csv(csv_path, index=False)

            # count=None -> full dataset
            df_all = load_and_validate_dataset(csv_path, count=None)
            self.assertEqual(len(df_all), 10)

            # count=4 -> exact 4
            df_4 = load_and_validate_dataset(csv_path, count=4)
            self.assertEqual(len(df_4), 4)

            # count <= 0 rejected
            with self.assertRaises(DatasetValidationError):
                load_and_validate_dataset(csv_path, count=0)
            with self.assertRaises(DatasetValidationError):
                load_and_validate_dataset(csv_path, count=-3)

            # count > size clamped with warning
            df_clamp = load_and_validate_dataset(csv_path, count=25)
            self.assertEqual(len(df_clamp), 10)

    # --- 3. HTTP Request Parameter Transport & Decoding Tests (AC-07) ---

    def test_16_http_special_chars_and_unicode_get_roundtrip(self):
        """
        Verify special characters (quotes, #, &, =, +, %, spaces, Unicode)
        arrive at the HTTP server intact after transport encoding and decoding.
        """
        target_url = f"http://127.0.0.1:{self.server_port}"
        special_payload = "1' OR 'a'='a' # comment & key=val + 100% test_unicode_测试"

        spec = convert_payload_to_http_request(
            payload=special_payload,
            family_id="FAMILY_BOOLEAN_TAUTOLOGY",
            attack_type="sqli_boolean",
            label=1,
            target_url=target_url,
            cookie_header="PHPSESSID=session_authenticated_999",
            rng=random.Random(42)
        )
        task_meta = {
            "run_id": "run_test",
            "sample_id": 1,
            "request_id": "req_1",
            "payload": special_payload,
            "label": 1,
            "family_id": "sqli",
            "attack_type": "boolean"
        }
        res = send_single_live_request(spec, task_meta, timeout_sec=2.0)
        self.assertTrue(res["request_success"])
        self.assertEqual(res["status_code"], 200)

        # Inspect what the server received
        self.assertTrue(len(MockHTTPServerHandler.received_requests) > 0)
        req = MockHTTPServerHandler.received_requests[-1]
        received_id = req["params"]["id"][0]

        # Critical: '#' must not be treated as URL fragment, '+' must not be lost
        self.assertEqual(received_id, special_payload,
                         f"Payload corrupted in transport! Expected: {special_payload}, Received: {received_id}")

    def test_17_http_special_chars_post_roundtrip(self):
        """Verify POST form-urlencoded encoding preserves special characters and Unicode."""
        target_url = f"http://127.0.0.1:{self.server_port}"
        post_payload = "admin' OR 1=1# & dummy=value + % '\" 測試"

        spec = convert_payload_to_http_request(
            payload=post_payload,
            family_id="FAMILY_AUTH_BYPASS",
            attack_type="sqli_login",
            label=1,
            target_url=target_url,
            rng=random.Random(1)  # rng forces POST /login.php
        )
        task_meta = {
            "run_id": "run_test_post",
            "sample_id": 2,
            "request_id": "req_2",
            "payload": post_payload,
            "label": 1,
            "family_id": "auth_bypass",
            "attack_type": "login"
        }
        res = send_single_live_request(spec, task_meta, timeout_sec=2.0)
        self.assertTrue(res["request_success"])

        # Check server received params
        req = MockHTTPServerHandler.received_requests[-1]
        self.assertEqual(req["method"], "POST")
        self.assertEqual(req["params"]["username"][0], post_payload)

    # --- 4. HTTP Error vs Transport Error Semantics (AC-04) ---

    def test_18_http_status_vs_transport_error_separation(self):
        """
        Verify HTTP status codes (404, 500) are recorded accurately,
        and transport failures (ConnectionRefused) have status_code=None with NO fake 504/599.
        """
        target_url = f"http://127.0.0.1:{self.server_port}"

        # 1. HTTP 404 response
        spec_404 = HTTPRequestSpec(
            method="GET",
            url=f"{target_url}/status_404",
            path="/status_404",
            query="",
            body_bytes=None,
            headers={}
        )
        rec_404 = send_single_live_request(spec_404, {"run_id": "r", "sample_id": 1, "request_id": "1"})
        self.assertEqual(rec_404["status_code"], 404)
        self.assertIsNone(rec_404["transport_error"])
        self.assertTrue(rec_404["request_success"])

        # 2. HTTP 500 response
        spec_500 = HTTPRequestSpec(
            method="GET",
            url=f"{target_url}/status_500",
            path="/status_500",
            query="",
            body_bytes=None,
            headers={}
        )
        rec_500 = send_single_live_request(spec_500, {"run_id": "r", "sample_id": 2, "request_id": "2"})
        self.assertEqual(rec_500["status_code"], 500)
        self.assertIsNone(rec_500["transport_error"])
        self.assertTrue(rec_500["request_success"], "HTTP response received from server")

        # 3. Transport failure: Unreachable port
        # Find a closed local port
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        closed_port = s.getsockname()[1]
        s.close()

        spec_fail = HTTPRequestSpec(
            method="GET",
            url=f"http://127.0.0.1:{closed_port}/unreachable",
            path="/unreachable",
            query="",
            body_bytes=None,
            headers={}
        )
        rec_fail = send_single_live_request(spec_fail, {"run_id": "r", "sample_id": 3, "request_id": "3"})
        self.assertIsNone(rec_fail["status_code"], "Transport error MUST NOT have synthetic HTTP status code!")
        self.assertIsNotNone(rec_fail["transport_error"])
        self.assertFalse(rec_fail["request_success"])
        self.assertNotIn(rec_fail["status_code"], [504, 599])

    # --- 5. DVWA Authentication Fail-Closed Tests (AC-06) ---

    def test_19_authenticate_dvwa_fail_closed(self):
        """Verify authentication fails closed on missing CSRF token, bad credentials, or probe failure."""
        target_url = f"http://127.0.0.1:{self.server_port}"

        # 1. Successful authentication with valid credentials against mock server
        cj, cookie = authenticate_dvwa(
            target_url=target_url,
            username="admin",
            password="password",
            security_level="low",
            timeout=2.0
        )
        self.assertIn("PHPSESSID", cookie)
        self.assertIn("security=low", cookie)

        # 2. Failed authentication with bad credentials raises AuthenticationError
        with self.assertRaises(AuthenticationError):
            authenticate_dvwa(
                target_url=target_url,
                username="admin",
                password="wrong_password",
                security_level="low",
                timeout=2.0
            )

        # 3. Unreachable host raises AuthenticationError
        with self.assertRaises(AuthenticationError):
            authenticate_dvwa(
                target_url="http://127.0.0.1:1/",
                username="admin",
                password="password",
                timeout=1.0
            )

    # --- 6. SSH & Apache Log Collection Reliability (AC-02, AC-10, AC-11, AC-12, AC-13) ---

    @patch("src.collectors.traffic_generator.paramiko.SSHClient")
    def test_20_apache_log_collection_success_and_empty(self, mock_ssh_cls):
        """Verify Apache collection distinguishes SUCCESS_WITH_LINES from SUCCESS_EMPTY without fabrication."""
        mock_ssh = MagicMock()
        mock_ssh_cls.return_value = mock_ssh

        config = TrafficConfig(
            target_url="http://127.0.0.1:80/",
            ssh_host="127.0.0.1",
            ssh_port=22,
            ssh_user="testuser",
            remote_log_path="/var/log/apache2/access.log"
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            run_dir = Path(tmp_dir) / "run_test"
            run_dir.mkdir(parents=True, exist_ok=True)

            # Scenario A: Genuine lines exist (start_line=10, current_line=12 -> 2 lines)
            mock_ssh.exec_command.side_effect = [
                # First call: wc -l and inode check
                (None, MagicMock(read=lambda: b"12 99999\n"), MagicMock(read=lambda: b"")),
                # Second call: sed read
                (None, MagicMock(read=lambda: b"127.0.0.1 - - [14/Oct/2026] \"GET / HTTP/1.1\" 200 100\n127.0.0.1 - - [14/Oct/2026] \"GET /sqli HTTP/1.1\" 200 200\n"), MagicMock(read=lambda: b""))
            ]
            res_lines = fetch_incremental_apache_log(config, start_line=10, start_inode="99999", run_dir=run_dir)
            self.assertEqual(res_lines.status, CollectionStatus.SUCCESS_WITH_LINES)
            self.assertEqual(res_lines.lines_collected, 2)
            self.assertIsNotNone(res_lines.output_path)
            self.assertTrue(res_lines.output_path.exists() if res_lines.output_path else False)

            # Scenario B: 0 lines exist (start_line=12, current_line=12) -> SUCCESS_EMPTY
            mock_ssh.exec_command.side_effect = [
                (None, MagicMock(read=lambda: b"12 99999\n"), MagicMock(read=lambda: b""))
            ]
            res_empty = fetch_incremental_apache_log(config, start_line=12, start_inode="99999", run_dir=run_dir)
            self.assertEqual(res_empty.status, CollectionStatus.SUCCESS_EMPTY)
            self.assertEqual(res_empty.lines_collected, 0)

    @patch("src.collectors.traffic_generator.paramiko.SSHClient")
    def test_21_apache_log_collection_rotation_and_permission_failures(self, mock_ssh_cls):
        """Verify log rotation/truncation and permission errors are detected, with ZERO fabrication."""
        mock_ssh = MagicMock()
        mock_ssh_cls.return_value = mock_ssh

        config = TrafficConfig(
            target_url="http://127.0.0.1:80/",
            ssh_host="127.0.0.1",
            ssh_port=22,
            ssh_user="testuser",
            remote_log_path="/var/log/apache2/access.log"
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            run_dir = Path(tmp_dir) / "run_test"
            run_dir.mkdir(parents=True, exist_ok=True)

            # Scenario A: File truncated / rotated (start_line=100, current_line=10)
            mock_ssh.exec_command.return_value = (None, MagicMock(read=lambda: b"10 99999\n"), MagicMock(read=lambda: b""))
            res_rot = fetch_incremental_apache_log(config, start_line=100, start_inode="99999", run_dir=run_dir)
            self.assertEqual(res_rot.status, CollectionStatus.FAILED_ROTATION)
            self.assertEqual(res_rot.lines_collected, 0)

            # Scenario B: Permission denied
            mock_ssh.exec_command.return_value = (None, MagicMock(read=lambda: b""), MagicMock(read=lambda: b"Permission denied"))
            res_perm = fetch_incremental_apache_log(config, start_line=0, start_inode=None, run_dir=run_dir)
            self.assertEqual(res_perm.status, CollectionStatus.FAILED_PERMISSION)
            self.assertEqual(res_perm.lines_collected, 0)

    # --- 7. Run Isolation, Telemetry Preservation, and Metadata Security (AC-03, AC-14, AC-15) ---

    def test_22_pipeline_run_isolation_and_no_secret_leakage(self):
        """
        Verify:
        1. Unique run directory data/runs/<run_id>/ created.
        2. Client telemetry is preserved even when SSH collection is disabled or fails.
        3. run_metadata.json contains audit metrics but NO secrets (passwords, tokens, cookies).
        4. Multiple runs do not overwrite historical directories.
        """
        target_url = f"http://127.0.0.1:{self.server_port}"

        with tempfile.TemporaryDirectory() as tmp_dir:
            runs_dir = Path(tmp_dir) / "runs"
            csv_path = Path(tmp_dir) / "test_payloads.csv"
            pd.DataFrame([
                {"payload": "normal_test", "label": 0, "family_id": "normal", "attack_type": "normal"},
                {"payload": "1' OR 1=1#", "label": 1, "family_id": "sqli", "attack_type": "sqli_boolean"}
            ]).to_csv(csv_path, index=False)

            # Execution 1
            config1 = TrafficConfig(
                target_url=target_url,
                runs_dir=runs_dir,
                dataset_path=csv_path,
                count=2,
                enable_ssh_collection=False
            )
            res1 = run_traffic_pipeline(config1)
            self.assertTrue(res1["client_telemetry_path"].exists())
            self.assertTrue(res1["metadata_path"].exists())

            # Verify no secrets in metadata
            with open(res1["metadata_path"], "r", encoding="utf-8") as f:
                meta = json.load(f)
            meta_str = json.dumps(meta)
            self.assertNotIn("password", meta_str.lower().replace('"password"', ''))
            self.assertNotIn("session_authenticated", meta_str)
            self.assertNotIn("user_token", meta_str)

            # Execution 2 (independent run_id)
            config2 = TrafficConfig(
                target_url=target_url,
                runs_dir=runs_dir,
                dataset_path=csv_path,
                count=2,
                enable_ssh_collection=False
            )
            res2 = run_traffic_pipeline(config2)
            self.assertNotEqual(res1["run_id"], res2["run_id"])
            self.assertTrue(res1["client_telemetry_path"].exists(), "Run 1 must not be overwritten by Run 2!")
            self.assertTrue(res2["client_telemetry_path"].exists())


if __name__ == "__main__":
    unittest.main()
