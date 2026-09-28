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

    print("\n" + "="*72)
    print("          AI WEB ATTACK DETECTION (SQLi) - PIPELINE RUNNER")
    print("="*72)

    if not args.skip_gen:
        print("\n[Giai đoạn 1/2] Sinh tập mẫu Payload & Tấn công mô phỏng...")
        gen_script = ROOT_DIR / "src" / "collectors" / "dvwa_generator" / "payload_generator.py"
        if gen_script.exists():
            subprocess.run([sys.executable, str(gen_script), "--count", str(args.count)], check=True)

        print("\n[Giai đoạn 2/2] Thu thập Access Log qua Traffic Generator...")
        traffic_script = ROOT_DIR / "src" / "collectors" / "traffic_generator.py"
        if traffic_script.exists():
            subprocess.run([sys.executable, str(traffic_script), "--target", args.target, "--count", str(args.count)], check=True)

    print("\n[Bước 1/4] Phân tích cú pháp Apache Access Log...")
    run_parser()

    print("\n[Bước 2/4] Tiền xử lý, che giấu token CSRF & gán nhãn...")
    run_builder()

    print("\n[Bước 3/4] Trích xuất vector đặc trưng (Numerical + Char TF-IDF)...")
    run_extractor()

    print("\n[Bước 4/4] Khởi tạo & Huấn luyện mô hình học máy...")
    run_trainer()

    print("="*72)
    print("  [✓] TOÀN BỘ PIPELINE ĐÃ HOÀN TẤT THÀNH CÔNG!")
    print("  Sử dụng `python predict.py` hoặc chạy dashboard để giám sát thời gian thực.")
    print("="*72 + "\n")

if __name__ == "__main__":
    main()
