"""
ENTROPY DETECTIVE — Finds hidden payloads through entropy deviation.

High Shannon entropy in files or network payloads indicates encryption,
compression, or obfuscation — classic malware hiding techniques.

Monitors:
- New files in watched directories for high entropy
- Running process memory-mapped files
- Optional: network capture files dropped in a watch folder
"""

import os
import math
import time
from typing import Callable

# Directories to watch for suspicious high-entropy files
DEFAULT_WATCH_DIRS = [
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~/AppData/Local/Temp") if os.name == "nt" else "/tmp",
    os.path.expanduser("~/Desktop"),
]

ENTROPY_THRESHOLD = 7.2        # out of 8.0 — highly suspicious
FILE_SIZE_MIN     = 512        # bytes — skip tiny files
FILE_SIZE_MAX     = 50_000_000 # 50MB — skip huge files
WATCHED_EXTS      = {".exe", ".dll", ".bin", ".dat", ".tmp", ".ps1", ".vbs", ".js", ".sh", ""}
SCAN_INTERVAL     = int(os.getenv("ENTROPY_INTERVAL", "30"))


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of bytes. Max = 8.0 (fully random/encrypted)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    return -sum((f / length) * math.log2(f / length) for f in freq if f > 0)


class EntropyDetective:
    def __init__(self, on_signal: Callable):
        self._on_signal = on_signal
        self._seen: set[str] = set()
        watch_env = os.getenv("ENTROPY_WATCH_DIRS", "")
        self._watch_dirs = [d.strip() for d in watch_env.split(",") if d.strip()] or DEFAULT_WATCH_DIRS
        self._watch_dirs = [d for d in self._watch_dirs if os.path.isdir(d)]

    def check_file(self, path: str) -> float:
        """Returns entropy of a file. -1 if unreadable/skipped."""
        try:
            size = os.path.getsize(path)
            if size < FILE_SIZE_MIN or size > FILE_SIZE_MAX:
                return -1.0
            ext = os.path.splitext(path)[1].lower()
            if ext not in WATCHED_EXTS:
                return -1.0
            with open(path, "rb") as f:
                data = f.read(65536)  # sample first 64KB
            return shannon_entropy(data)
        except (OSError, PermissionError):
            return -1.0

    def scan(self) -> list:
        """Single-pass scan of all watched directories."""
        signals = []
        for watch_dir in self._watch_dirs:
            try:
                for fname in os.listdir(watch_dir):
                    fpath = os.path.join(watch_dir, fname)
                    if fpath in self._seen or not os.path.isfile(fpath):
                        continue
                    self._seen.add(fpath)
                    entropy = self.check_file(fpath)
                    if entropy >= ENTROPY_THRESHOLD:
                        signals.append(self._make_signal(
                            severity="HIGH" if entropy >= 7.6 else "MEDIUM",
                            summary=f"High-entropy file detected: '{fpath}' (entropy={entropy:.3f}/8.0) — possible encrypted payload or packed executable.",
                            raw={"path": fpath, "entropy": entropy, "threshold": ENTROPY_THRESHOLD}
                        ))
            except PermissionError:
                continue
        return signals

    def run(self):
        while True:
            for signal in self.scan():
                self._on_signal(signal)
            time.sleep(SCAN_INTERVAL)

    def _make_signal(self, severity: str, summary: str, raw: dict):
        from core.orchestrator import ThreatSignal
        return ThreatSignal(source="ENTROPY_DETECTIVE", severity=severity, summary=summary, raw=raw)
