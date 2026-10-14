"""
Automated Test Suite for AI Threat Detection Engine.
Validates risk classification for benign requests, malicious SQLi detection,
JSON body inspection, dynamic threshold adjustments, and SOC metrics.
"""
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
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
        self.assertLess(inspection["latency_ms"], 500.0)


    def test_02_sqli_get_request_detected(self):
        """Test that SQLi GET request is classified as ATTACK."""
        inspection = self.detector.inspect_request(
            method="GET",
            path="/vulnerabilities/sqli/",
            query="id=1'%20OR%20'1'='1&Submit=Submit",
            client_ip="192.168.1.99"
        )
        self.assertTrue(inspection["is_attack"])
        self.assertGreaterEqual(inspection["confidence"], 0.50)
        self.assertIn("sqli", inspection["attack_type"])

    def test_03_sqli_post_json_body_detected(self):
        """Test inspection of raw payload/JSON body in POST request."""
        inspection = self.detector.inspect_request(
            method="POST",
            path="/api/v1/login",
            query="",
            body='{"user": "admin\' UNION SELECT 1,2,3--", "pass": "secret"}',
            client_ip="10.0.0.5"
        )
        self.assertTrue(inspection["is_attack"])
        self.assertGreaterEqual(inspection["confidence"], 0.50)

    def test_04_dynamic_threshold_adjustment(self):
        """Test dynamic config adjustment at runtime."""
        self.detector.set_config(threshold=0.99)
        self.assertEqual(self.detector.threshold, 0.99)

        # Revert back
        self.detector.set_config(threshold=0.50)
        self.assertEqual(self.detector.threshold, 0.50)

    def test_05_soc_metrics_aggregation(self):
        """Test SOC metrics retrieval."""
        metrics = self.detector.get_stats()
        self.assertIn("total_inspected", metrics)
        self.assertIn("total_threats", metrics)
        self.assertIn("avg_latency_ms", metrics)
        self.assertGreater(metrics["total_inspected"], 0)

    def test_06_invalid_threshold_raises_error(self):
        """Test threshold validation rejects out-of-range values."""
        with self.assertRaises(ValueError):
            self.detector.set_config(threshold=1.5)
        with self.assertRaises(ValueError):
            self.detector.set_config(threshold=-0.1)

    def test_07_url_with_query_in_path_normalized(self):
        """Test URL paths containing query strings are handled without duplicate question marks."""
        inspection = self.detector.inspect_request(
            method="GET",
            path="/vulnerabilities/sqli/?id=1",
            query="Submit=Submit",
            client_ip="10.0.0.9"
        )
        self.assertNotIn("??", inspection["request_line"])
        self.assertEqual(inspection["path"], "/vulnerabilities/sqli/")
        self.assertIn("id=1", inspection["query"])


if __name__ == "__main__":
    unittest.main()
