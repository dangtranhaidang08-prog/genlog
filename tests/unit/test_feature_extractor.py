"""
Unit Test Suite for Feature Extractor.
Validates extraction of handcrafted numerical features and Char TF-IDF input text.
"""
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.data_processing.feature_extractor import extract_features_from_row

class TestFeatureExtractor(unittest.TestCase):
    def test_01_extract_benign_features(self):
        row = {
            "method": "GET",
            "url": "GET /index.php?id=1 HTTP/1.1",
            "path": "/index.php",
            "query": "id=1",
            "decoded_query": "id=1",
            "body": "",
            "decoded_body": ""
        }
        feats = extract_features_from_row(row)
        self.assertEqual(feats["single_quote_count"], 0)
        self.assertEqual(feats["has_union_select"], 0)
        self.assertEqual(feats["has_tautology"], 0)
        self.assertEqual(feats["has_sleep"], 0)
        self.assertIn("text", feats)

    def test_02_extract_sqli_union_features(self):
        row = {
            "method": "GET",
            "url": "GET /vulnerabilities/sqli/?id=-1' UNION SELECT user,password FROM users# HTTP/1.1",
            "path": "/vulnerabilities/sqli/",
            "query": "id=-1'%20UNION%20SELECT%20user,password%20FROM%20users%23",
            "decoded_query": "id=-1' UNION SELECT user,password FROM users#",
            "body": "",
            "decoded_body": ""
        }
        feats = extract_features_from_row(row)
        self.assertGreater(feats["single_quote_count"], 0)
        self.assertEqual(feats["has_union_select"], 1)
        self.assertEqual(feats["has_sql_comment"], 1)
        self.assertGreater(feats["keyword_union"], 0)
        self.assertGreater(feats["keyword_select"], 0)

    def test_03_extract_blind_time_features(self):
        row = {
            "method": "GET",
            "url": "GET /vulnerabilities/sqli/?id=1' AND SLEEP(5)# HTTP/1.1",
            "path": "/vulnerabilities/sqli/",
            "query": "id=1' AND SLEEP(5)#",
            "decoded_query": "id=1' AND SLEEP(5)#",
            "body": "",
            "decoded_body": ""
        }
        feats = extract_features_from_row(row)
        self.assertEqual(feats["has_sleep"], 1)
        self.assertGreater(feats["parenthesis_count"], 0)

if __name__ == "__main__":
    unittest.main()
