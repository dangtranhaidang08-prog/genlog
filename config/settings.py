"""
Central Application Settings & Configuration.
Consolidates environment variables, directory paths, and runtime parameters.
"""
import os
import sys
from pathlib import Path

# Root directory of the repository
CONFIG_DIR = Path(__file__).resolve().parent
ROOT_DIR = CONFIG_DIR.parent
SRC_DIR = ROOT_DIR / "src"

# Add root and src to sys.path
for p in [ROOT_DIR, SRC_DIR]:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

# Load .env file
ENV_FILE = ROOT_DIR / ".env"
try:
    from dotenv import load_dotenv
    if ENV_FILE.exists():
        load_dotenv(dotenv_path=ENV_FILE)
except ImportError:
    pass

# 1. DIRECTORY STRUCTURE
DATA_DIR = ROOT_DIR / "data"
PAYLOADS_DATA_DIR = DATA_DIR / "payloads"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
FEATURES_DATA_DIR = DATA_DIR / "features"
RUNS_DATA_DIR = DATA_DIR / "runs"
RAW_LOGS_DIR = RAW_DATA_DIR  # Alias for backward compatibility

MODELS_DIR = ROOT_DIR / "models"
MODELS_CURRENT_DIR = MODELS_DIR / "current"
MODELS_ARCHIVE_DIR = MODELS_DIR / "archive"

REPORTS_DIR = ROOT_DIR / "reports"
SCRIPTS_DIR = ROOT_DIR / "scripts"
COLLECTORS_DIR = SRC_DIR / "collectors"

# 2. FILE ARTIFACT PATHS
RAW_LOG_FILE = RAW_DATA_DIR / "access.log"
PARSED_LOG_CSV = PROCESSED_DATA_DIR / "apache_logs.csv"
DATASET_CSV = PROCESSED_DATA_DIR / "dataset.csv"
FEATURES_CSV = FEATURES_DATA_DIR / "features.csv"
PAYLOADS_ALL_CSV = PAYLOADS_DATA_DIR / "payloads_all.csv"
PAYLOADS_TRAIN_CSV = PAYLOADS_DATA_DIR / "train.csv"
PAYLOADS_VAL_CSV = PAYLOADS_DATA_DIR / "val.csv"
PAYLOADS_TEST_UNSEEN_CSV = PAYLOADS_DATA_DIR / "test_unseen.csv"
CLIENT_REQUESTS_CSV = PROCESSED_DATA_DIR / "client_requests.csv"


# Model Artifacts (Managed under models/current/)
MODEL_FILE = MODELS_CURRENT_DIR / "sqli_rf_model.pkl"
VEC_FILE = MODELS_CURRENT_DIR / "tfidf_vectorizer.pkl"
COLS_FILE = MODELS_CURRENT_DIR / "feature_columns.pkl"
MODEL_METADATA_FILE = MODELS_CURRENT_DIR / "metadata.json"

# Report Artifacts
DATASET_REPORT_FILE = REPORTS_DIR / "dataset_report.txt"
CLASSIFICATION_REPORT_FILE = REPORTS_DIR / "classification_report.txt"
METRICS_JSON_FILE = REPORTS_DIR / "metrics.json"
CONFUSION_MATRIX_FILE = REPORTS_DIR / "confusion_matrix.png"
FEATURE_IMPORTANCE_CSV = REPORTS_DIR / "feature_importance.csv"
FEATURE_IMPORTANCE_PNG = REPORTS_DIR / "feature_importance.png"
SECURITY_BENCHMARK_REPORT_FILE = REPORTS_DIR / "security_benchmark_report.json"
PAYLOAD_GEN_REPORT_FILE = REPORTS_DIR / "payload_generation_report.txt"

# 3. NETWORK & SERVICE CONFIGURATION
TARGET_WEB_URL = os.environ.get("TARGET_WEB_URL", "http://127.0.0.1:80/")
REMOTE_SSH_HOST = os.environ.get("REMOTE_SSH_HOST", "127.0.0.1")
REMOTE_SSH_PORT = int(os.environ.get("REMOTE_SSH_PORT", "22"))
REMOTE_SSH_USER = os.environ.get("REMOTE_SSH_USER", "")
REMOTE_SSH_PASS = os.environ.get("REMOTE_SSH_PASS", "")
REMOTE_LOG_PATH = os.environ.get("REMOTE_LOG_PATH", "/var/log/apache2/access.log")

DASHBOARD_HOST = os.environ.get("DASHBOARD_HOST", "127.0.0.1")
DASHBOARD_PORT = int(os.environ.get("DASHBOARD_PORT", "5000"))
DETECTION_THRESHOLD = float(os.environ.get("DETECTION_THRESHOLD", "0.50"))



# Ensure essential output directories exist
for folder in [
    PAYLOADS_DATA_DIR, RAW_DATA_DIR, PROCESSED_DATA_DIR, FEATURES_DATA_DIR,
    MODELS_CURRENT_DIR, REPORTS_DIR
]:
    folder.mkdir(parents=True, exist_ok=True)

def validate_environment() -> bool:
    """Validate runtime environment and print health status."""
    missing = []
    for f in [MODEL_FILE, VEC_FILE, COLS_FILE]:
        if not f.exists():
            missing.append(f.name)
    if missing:
        print(f"[WARN] Missing model artifacts in {MODELS_CURRENT_DIR}: {missing}. Run scripts/run_pipeline.py first.")
        return False
    return True
