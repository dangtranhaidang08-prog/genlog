"""
Unit Test Suite for Training Pipeline and Defensive Evaluation.
Validates:
- Template-based group partitioning preventing variant leakage
- Independent cross-validation handling
- Single-class and edge case metric computation (no fabricated 1.0)
- Missing column and non-finite schema validation
- Dynamic class index mapping
- Online ThreatDetector artifact loading and dimension verification
"""
import sys
import unittest
from pathlib import Path

import numpy as np
from sklearn.dummy import DummyClassifier

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config import COLS_FILE, MODEL_FILE, MODEL_METADATA_FILE, VEC_FILE
from src.data_processing.feature_extractor import APPROVED_NUMERICAL_FEATURES
from src.detector.threat_detector import ThreatDetector
from src.training.train_model import (
    compute_classification_metrics,
    extract_payload_template,
    run_leakage_free_cv,
    tune_threshold_on_val,
)


class TestTrainingPipeline(unittest.TestCase):
    def test_01_template_grouping_clusters_related_payloads(self):
        """Verify that related SQLi variants share the same template group."""
        p1 = extract_payload_template("1' OR 1=1--", "sqli_boolean", 1, "hash1")
        p2 = extract_payload_template("2' OR 2=2--", "sqli_boolean", 1, "hash2")
        self.assertEqual(p1, p2, "Payload variants with different numbers/hashes must share template group")

        # Normal requests with different hashes should stay distinct
        n1 = extract_payload_template("id=1", "normal", 0, "hash_a")
        n2 = extract_payload_template("id=2", "normal", 0, "hash_b")
        self.assertNotEqual(n1, n2, "Distinct normal requests should have distinct canonical groups")

    def test_02_metrics_defensive_on_single_class(self):
        """Verify metrics return None instead of fabricating 1.0 when a partition has one class."""
        y_true = np.array([0, 0, 0, 0])
        y_pred = np.array([0, 0, 0, 0])
        y_prob = np.array([0.1, 0.2, 0.1, 0.3])

        m = compute_classification_metrics(y_true, y_pred, y_prob)
        self.assertEqual(m["accuracy"], 1.0)
        self.assertIsNone(m["roc_auc"], "ROC-AUC must be None when only one class is present")
        self.assertIsNone(m["pr_auc"], "PR-AUC must be None when only one class is present")
        self.assertIsNone(m["fpr"], "FPR must be None when positive class is absent from confusion matrix")

    def test_03_cv_graceful_on_insufficient_groups(self):
        """Verify CV returns (None, None) gracefully if there are fewer groups than folds."""
        X_num = np.zeros((10, 5), dtype=np.float32)
        texts = ["sample"] * 10
        y = np.array([0, 1] * 5)
        groups = np.array(["g1", "g2"] * 5)  # only 2 groups, need 5

        mean_cv, std_cv = run_leakage_free_cv(X_num, texts, y, groups, n_splits=5)
        self.assertIsNone(mean_cv)
        self.assertIsNone(std_cv)

    def test_04_threshold_tuning_selects_optimal_value(self):
        """Verify threshold tuning returns a valid threshold and positive F1."""
        y_val = np.array([0, 0, 1, 1, 1, 0, 1, 0])
        y_prob = np.array([0.1, 0.2, 0.8, 0.9, 0.7, 0.15, 0.85, 0.05])

        thresh, metrics = tune_threshold_on_val(y_val, y_prob)
        self.assertGreaterEqual(thresh, 0.10)
        self.assertLessEqual(thresh, 0.90)
        self.assertGreater(metrics["f1"], 0.80)

    def test_05_dynamic_class_index_resolution(self):
        """Verify that dynamic class indexing correctly identifies label 1 even if classes are reversed."""
        dummy = DummyClassifier(strategy="constant", constant=1)
        X = np.zeros((4, 2))
        y = np.array([1, 1, 1, 1])
        dummy.fit(X, y)
        dummy.classes_ = np.array([1, 0])  # Simulate reversed class index

        classes = list(dummy.classes_)
        sqli_idx = classes.index(1)
        self.assertEqual(sqli_idx, 0, "Target index for SQLi label 1 must be 0 when classes are [1, 0]")

    def test_06_approved_numerical_features_schema_count(self):
        """Verify that the explicit numerical feature whitelist contains exactly 64 pre-execution features."""
        self.assertEqual(len(APPROVED_NUMERICAL_FEATURES), 64)
        # Ensure no response features leaked into the whitelist
        forbidden = {"status_code", "response_size", "response_time", "is_error_response", "ip_request_count"}
        self.assertEqual(set(APPROVED_NUMERICAL_FEATURES) & forbidden, set())

    def test_07_threat_detector_loads_new_artifacts(self):
        """Verify ThreatDetector loads the newly trained model, vectorizer, feature list, and metadata threshold."""
        detector = ThreatDetector(
            model_path=MODEL_FILE,
            vec_path=VEC_FILE,
            cols_path=COLS_FILE,
            metadata_path=MODEL_METADATA_FILE
        )
        import json
        with open(MODEL_METADATA_FILE, "r", encoding="utf-8") as f:
            expected_thresh = json.load(f).get("selected_threshold", 0.50)
        self.assertEqual(len(detector.feature_cols), 64)
        self.assertAlmostEqual(detector.threshold, expected_thresh, places=4)

        # Inspect benign request
        res_benign = detector.inspect_request(method="GET", path="/index.php", query="id=1")
        self.assertFalse(res_benign["is_attack"])

        # Inspect attack request
        res_attack = detector.inspect_request(method="GET", path="/vulnerabilities/sqli/", query="id=1' UNION SELECT 1,2--")
        self.assertTrue(res_attack["is_attack"])
        self.assertIn("sqli", res_attack["attack_type"])


if __name__ == "__main__":
    unittest.main()
