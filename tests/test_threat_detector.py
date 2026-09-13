"""
Automated Test Suite for AI Threat Detection Engine.
Validates risk classification for benign requests, malicious SQLi detection,
JSON body inspection, dynamic threshold adjustments, and SOC metrics.
"""
import sys
import unittest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.detector.threat_detector import ThreatDetector

class TestThreatDetector(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.detector = ThreatDetector(threshold=0.50)

    def setUp(self):
        self.detector.set_config(threshold=0.50)

    def test_01_benign_get_request_allowed(self):
        """Test that normal GET request is classified as SAFE."""
        inspection = self.detector.inspect_request(
            method="GET",
            path="/index.php",
            query="id=1&Submit=Submit",
            client_ip="192.168.1.50"
        )
        self.assertFalse(inspection["is_attack"])
        self.assertLess(inspection["confidence"], 0.50)
        self.assertLess(inspection["latency_ms"], 100.0)
        print(f"[TEST 1 PASS] Normal GET classified safe -> Score: {inspection['confidence']:.4f}, Latency: {inspection['latency_ms']:.2f}ms")

    def test_02_sqli_get_request_detected(self):
        """Test that SQLi GET request is detected with high confidence."""
        inspection = self.detector.inspect_request(
            method="GET",
            path="/vulnerabilities/sqli/",
            query="id=1%27+OR+1%3D1%23&Submit=Submit",
            client_ip="10.0.0.99"
        )
        self.assertTrue(inspection["is_attack"])
        self.assertGreaterEqual(inspection["confidence"], 0.50)
        self.assertTrue(any("quote" in ind.lower() or "or" in ind.lower() or "comment" in ind.lower() for ind in inspection["indicators"]))
        print(f"[TEST 2 PASS] SQLi GET detected -> Score: {inspection['confidence']:.4f}, Indicators: {len(inspection['indicators'])}")

    def test_03_benign_post_json_allowed(self):
        """Test that safe REST API POST with JSON payload is classified as SAFE."""
        json_body = '{"search": "wireless headphones", "page": 1, "category": "electronics"}'
        inspection = self.detector.inspect_request(
            method="POST",
            path="/api/v1/search",
            body=json_body,
            content_type="application/json",
            client_ip="192.168.1.75"
        )
        self.assertFalse(inspection["is_attack"])
        self.assertTrue(inspection["is_json"])
        self.assertLess(inspection["confidence"], 0.50)
        print(f"[TEST 3 PASS] Safe POST JSON classified safe -> Score: {inspection['confidence']:.4f}")

    def test_04_sqli_post_json_detected(self):
        """Test that SQLi payload hidden inside a POST JSON body is detected."""
        malicious_json = '{"username": "admin\' OR 1=1-- -", "password": "anypassword"}'
        inspection = self.detector.inspect_request(
            method="POST",
            path="/api/v1/auth",
            body=malicious_json,
            content_type="application/json",
            client_ip="10.0.0.88"
        )
        self.assertTrue(inspection["is_attack"])
        self.assertTrue(inspection["is_json"])
        self.assertGreaterEqual(inspection["confidence"], 0.50)
        self.assertTrue("SQL" in inspection["attack_type"].upper())
        print(f"[TEST 4 PASS] Malicious POST JSON detected -> Score: {inspection['confidence']:.4f}")

    def test_05_threshold_adjustment(self):
        """Test dynamic adjustment of risk alert threshold."""
        query = "id=1%27%20OR%201=1--+&Submit=Submit"
        self.detector.set_config(threshold=0.50)
        res_50 = self.detector.inspect_request("GET", "/vulnerabilities/sqli/", query=query)
        self.assertTrue(res_50["is_attack"])

        self.detector.set_config(threshold=0.99)
        res_99 = self.detector.inspect_request("GET", "/vulnerabilities/sqli/", query=query)
        if res_99["confidence"] < 0.99:
            self.assertFalse(res_99["is_attack"])
        print(f"[TEST 5 PASS] Threshold sensitivity tested (0.50 -> 0.99)")

    def test_06_stats_and_metrics_calculation(self):
        """Test that SOC metrics and latency counters update accurately."""
        stats = self.detector.get_stats()
        self.assertGreater(stats["total_inspected"], 0)
        self.assertIn("total_threats", stats)
        self.assertIn("total_clean", stats)
        self.assertGreater(stats["avg_latency_ms"], 0.0)
        print(f"[TEST 6 PASS] SOC Monitoring Metrics: {stats}")

if __name__ == "__main__":
    unittest.main(verbosity=2)
