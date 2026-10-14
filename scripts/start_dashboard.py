"""
Script to start the SOC Monitoring Dashboard server.
Usage:
    python scripts/start_dashboard.py
"""
import sys
import runpy
from pathlib import Path

TARGET = Path(__file__).resolve().parent.parent / "dashboard" / "backend" / "dashboard_backend.py"

if __name__ == "__main__":
    runpy.run_path(str(TARGET), run_name="__main__")
