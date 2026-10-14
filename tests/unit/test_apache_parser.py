"""
Unit Test Suite for Apache Log Parser.
Tests parsing of Apache Combined Log format, query parameters, POST form body, and URL decoding.
"""
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.data_processing.apache_parser import parse_raw_line, parse_request_string

class TestApacheParser(unittest.TestCase):
    def test_01_parse_standard_get_line(self):
        line = '192.168.1.100 - - [14/Oct/2026:10:00:00 +0700] "GET /index.php?id=1&name=test HTTP/1.1" 200 4500 "http://google.com" "Mozilla/5.0" 1200'
        rec = parse_raw_line(line)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["ip"], "192.168.1.100")
        self.assertEqual(rec["method"], "GET")
        self.assertEqual(rec["path"], "/index.php")
        self.assertEqual(rec["query"], "id=1&name=test")
        self.assertEqual(rec["status"], 200)

    def test_02_parse_encoded_sqli_query(self):
        req_line = "GET /vulnerabilities/sqli/?id=1%27%20OR%201%3D1%23 HTTP/1.1"
        (
            method, raw_url, path, query, protocol,
            decoded_url, decoded_query, raw_body, decoded_body,
            param_count_body
        ) = parse_request_string(req_line)

        self.assertEqual(method, "GET")
        self.assertEqual(path, "/vulnerabilities/sqli/")
        self.assertIn("'", decoded_query)
        self.assertIn("1=1", decoded_query)

    def test_03_parse_post_form_body(self):
        req_line = "POST /login.php HTTP/1.1"
        body_content = "username=admin' OR 1=1-- -&password=123&Login=Login"
        (
            method, raw_url, path, query, protocol,
            decoded_url, decoded_query, raw_body, decoded_body,
            param_count_body
        ) = parse_request_string(req_line, body=body_content, content_type="application/x-www-form-urlencoded")

        self.assertEqual(method, "POST")
        self.assertEqual(path, "/login.php")
        self.assertIn("admin' OR 1=1", decoded_body)
        self.assertGreater(param_count_body, 0)

    def test_04_empty_or_malformed_input(self):
        rec = parse_raw_line("")
        self.assertIsNone(rec)

        res = parse_request_string("-")
        self.assertEqual(res[0], "")

if __name__ == "__main__":
    unittest.main()
