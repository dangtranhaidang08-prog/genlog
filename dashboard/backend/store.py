"""
Thread-safe In-Memory Event Store for Real-time SOC Monitoring.
"""
import threading
from typing import Dict, Any, List

class EventStore:
    def __init__(self, max_size: int = 500):
        self._max_size = max_size
        self._queue: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def enqueue(self, event: Dict[str, Any]):
        """Enqueue a detected security event."""
        with self._lock:
            self._queue.append(event)
            if len(self._queue) > self._max_size:
                self._queue.pop(0)

    def consume_stream_events(self) -> List[Dict[str, Any]]:
        """Retrieve all queued events and clear the queue for stream polling."""
        with self._lock:
            events = list(self._queue)
            self._queue.clear()
        return events
