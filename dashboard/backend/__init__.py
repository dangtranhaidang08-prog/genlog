"""Dashboard Backend Package"""
from dashboard.backend.store import EventStore
from dashboard.backend.collector import LogCollector

__all__ = ["EventStore", "LogCollector"]
