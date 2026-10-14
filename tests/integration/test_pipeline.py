"""
Integration Test Suite.
Validates the end-to-end integration between parser, feature extractor, and AI threat detector.
"""
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.detector.threat_detector import ThreatDetector

class TestPipelineIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.detector = ThreatDetector(threshold=0.50)

    def test_01_full_detection_flow_benign(self):
        result = self.detector.inspect_request(
            method="GET",
            path="/index.php",
            query="page=home",
            client_ip="192.168.1.10"
        )
        self.assertFalse(result["is_attack"])
        self.assertEqual(result["attack_type"], "normal")
        self.assertLess(result["confidence"], 0.50)

    def test_02_full_detection_flow_sqli(self):
        result = self.detector.inspect_request(
            method="GET",
            path="/vulnerabilities/sqli/",
            query="id=1%27%20UNION%20SELECT%20null,null%23",
            client_ip="10.0.0.1"
        )
        self.assertTrue(result["is_attack"])
        self.assertEqual(result["attack_type"], "sqli_union")
        self.assertGreaterEqual(result["confidence"], 0.50)
        self.assertGreater(len(result["indicators"]), 0)

if __name__ == "__main__":
    unittest.main()
