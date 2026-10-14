"""
Real-time Log Collector Service.
Monitors local Apache access.log and remote Apache access.log via SSH/SFTP.
"""
import time
import threading
from pathlib import Path
from typing import Callable, Optional

try:
    import paramiko
except ImportError:
    paramiko = None

class LogCollector:
    def __init__(
        self,
        local_log_path: Path,
        remote_host: str,
        remote_port: int,
        remote_user: str,
        remote_pass: str,
        remote_log_path: str,
        on_log_line: Callable[[str], None],
        poll_interval: float = 1.0
    ):
        self.local_log_path = local_log_path
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.remote_user = remote_user
        self.remote_pass = remote_pass
        self.remote_log_path = remote_log_path
        self.on_log_line = on_log_line
        self.poll_interval = poll_interval
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        """Start the background log collector thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        print(f"[LOG-COLLECTOR] Active: Local ({self.local_log_path.name}) + SSH SFTP ({self.remote_user}@{self.remote_host}:{self.remote_port})")

    def stop(self):
        self._running = False

    def _run_loop(self):
        # Seek to end of file on startup so we only capture NEW events
        last_local_pos = self.local_log_path.stat().st_size if self.local_log_path.exists() else 0
        last_remote_size = 0

        while self._running:
            # 1. Local Log File Check
            try:
                if self.local_log_path.exists():
                    with open(self.local_log_path, "r", encoding="utf-8", errors="ignore") as f:
                        f.seek(last_local_pos)
                        lines = f.readlines()
                        last_local_pos = f.tell()
                        for line in lines:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                self.on_log_line(line)
            except Exception:
                pass

            # 2. Remote SSH SFTP Log Check
            if paramiko and self.remote_host:
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(
                        self.remote_host,
                        port=self.remote_port,
                        username=self.remote_user,
                        password=self.remote_pass,
                        timeout=2
                    )
                    sftp = ssh.open_sftp()
                    stat = sftp.stat(self.remote_log_path)
                    curr_size = int(stat.st_size) if stat.st_size is not None else 0

                    if last_remote_size == 0:
                        last_remote_size = max(0, curr_size - 4096)

                    if curr_size > last_remote_size:
                        with sftp.open(self.remote_log_path, "r") as f:
                            f.seek(last_remote_size)
                            new_content = f.read()
                            last_remote_size = curr_size
                        if new_content:
                            lines = new_content.decode("utf-8", errors="ignore").splitlines()
                            for line in lines:
                                line = line.strip()
                                if line and not line.startswith("#"):
                                    self.on_log_line(line)

                    sftp.close()
                    ssh.close()
                except Exception:
                    pass

            time.sleep(self.poll_interval)
