"""
Test Runner Script.
Runs unit tests, integration tests, and security benchmark suites.
Usage:
    python scripts/run_tests.py
    python scripts/run_tests.py --suite unit
    python scripts/run_tests.py --suite security
"""
import sys
import unittest
import argparse
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

def main():
    parser = argparse.ArgumentParser(description="Run AI Attack Detection Test Suites")
    parser.add_argument(
        "--suite",
        choices=["all", "unit", "integration", "security"],
        default="all",
        help="Test suite to run (default: all)"
    )
    args = parser.parse_args()

    tests_dir = ROOT_DIR / "tests"
    loader = unittest.TestLoader()

    if args.suite == "all":
        pattern = "test_*.py"
        start_dir = str(tests_dir)
    else:
        pattern = "test_*.py"
        start_dir = str(tests_dir / args.suite)

    print(f"\n{'='*60}")
    print(f"RUNNING TEST SUITE: {args.suite.upper()} (Directory: {start_dir})")
    print(f"{'='*60}\n")

    suite = loader.discover(start_dir=start_dir, pattern=pattern)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    sys.exit(0 if result.wasSuccessful() else 1)

if __name__ == "__main__":
    main()
