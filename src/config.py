"""
Central configuration for paths and constants in the AI Security Web Attack Detection project.
"""
from pathlib import Path

# Base directories
SRC_DIR = Path(__file__).resolve().parent
ROOT_DIR = SRC_DIR.parent

DATA_DIR = ROOT_DIR / "data"
RAW_LOGS_DIR = DATA_DIR / "raw_logs"
MODELS_DIR = ROOT_DIR / "models"
REPORTS_DIR = ROOT_DIR / "reports"
COLLECTORS_DIR = SRC_DIR / "collectors"

# File paths
RAW_LOG_FILE = RAW_LOGS_DIR / "access.log"
PARSED_LOG_CSV = DATA_DIR / "apache_logs.csv"
DATASET_CSV = DATA_DIR / "dataset.csv"
FEATURES_CSV = DATA_DIR / "features.csv"

# Model Artifacts
MODEL_FILE = MODELS_DIR / "sqli_rf_model.pkl"
VEC_FILE = MODELS_DIR / "tfidf_vectorizer.pkl"
COLS_FILE = MODELS_DIR / "feature_columns.pkl"

# Report Artifacts
DATASET_REPORT_FILE = REPORTS_DIR / "dataset_report.txt"
CLASSIFICATION_REPORT_FILE = REPORTS_DIR / "classification_report.txt"
METRICS_JSON_FILE = REPORTS_DIR / "metrics.json"
CONFUSION_MATRIX_FILE = REPORTS_DIR / "confusion_matrix.png"
FEATURE_IMPORTANCE_CSV = REPORTS_DIR / "feature_importance.csv"
FEATURE_IMPORTANCE_PNG = REPORTS_DIR / "feature_importance.png"
SECURITY_BENCHMARK_REPORT_FILE = REPORTS_DIR / "security_benchmark_report.json"

# Payload Generation File Paths
PAYLOADS_ALL_CSV = DATA_DIR / "payloads_all.csv"
PAYLOAD_GEN_REPORT_FILE = REPORTS_DIR / "payload_generation_report.txt"

# Ensure output directories exist
for folder in [RAW_LOGS_DIR, DATA_DIR, MODELS_DIR, REPORTS_DIR]:
    folder.mkdir(parents=True, exist_ok=True)
