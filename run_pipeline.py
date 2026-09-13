"""
End-to-End Live Pipeline Execution Script for AI Web Attack Detection (SQLi)
Runs the entire workflow sequentially:
1. Generate Payloads
2. Send Live Traffic & Collect Access Log
3. AI/ML Pipeline (Parse Log -> Clean & Label -> Extract Features -> Train Model)
"""
import argparse
import subprocess
import sys
import io
from pathlib import Path

# Set UTF-8 encoding for stdout on Windows
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.data_processing.apache_parser import main as run_parser
from src.data_processing.dataset_builder import main as run_builder
from src.data_processing.feature_extractor import main as run_extractor
from src.training.train_model import main as run_trainer

def main():
    parser = argparse.ArgumentParser(description="End-to-End Live Machine Learning Attack Detection Pipeline")
    parser.add_argument("--skip-gen", action="store_true", help="Skip payload generation and traffic steps, run ML pipeline on existing log only.")
    parser.add_argument("--target", type=str, default="http://127.0.0.1/dvwa", help="Target DVWA URL for traffic (Default: http://127.0.0.1/dvwa)")
    parser.add_argument("--count", type=int, default=0, help="Number of payload samples (0 = send ALL generated payloads, Default: 0)")

    args = parser.parse_args()

    if not args.skip_gen:
        print("\n==================================================")
        print("PHASE 1: GENERATING SYNTHETIC PAYLOADS")
        print("==================================================")
        gen_script = ROOT_DIR / "src" / "collectors" / "dvwa_generator" / "payload_generator.py"
        if gen_script.exists():
            subprocess.run([sys.executable, str(gen_script), "--count", str(args.count)], check=True)

        print("\n==================================================")
        print("PHASE 2: COLLECTING APACHE ACCESS LOGS")
        print("==================================================")
        traffic_script = ROOT_DIR / "src" / "collectors" / "traffic_generator.py"
        if traffic_script.exists():
            subprocess.run([sys.executable, str(traffic_script), "--target", args.target, "--count", str(args.count)], check=True)

    print("\n==================================================")
    print("STEP 1: PARSING RAW APACHE ACCESS LOGS")
    print("==================================================")
    run_parser()

    print("\n==================================================")
    print("STEP 2: DATA CLEANING, TOKEN MASKING & LABELING")
    print("==================================================")
    run_builder()

    print("\n==================================================")
    print("STEP 3: FEATURE EXTRACTION (80 FEATURES + CHAR TF-IDF)")
    print("==================================================")
    run_extractor()

    print("\n==================================================")
    print("STEP 4: MODEL TRAINING & EVALUATION (RANDOM FOREST)")
    print("==================================================")
    run_trainer()

    print("\n==================================================")
    print("PIPELINE COMPLETED SUCCESSFULLY!")
    print("Run `python predict.py` to test individual HTTP requests.")
    print("==================================================\n")

if __name__ == "__main__":
    main()
