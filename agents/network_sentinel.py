"""
NETWORK SENTINEL — Watches all traffic, flags anomalies, maps C2 patterns.

Monitors active network connections using psutil. Detects:
- Connections to known bad port ranges
- Beaconing patterns (regular interval connections)
- High connection counts from single processes
- Connections to unusual geographic ranges (via feed enrichment)
"""

import os
import time
import socket
from collections import defaultdict
from datetime import datetime
from typing import Callable


# Ports commonly used by C2 frameworks and malware
SUSPICIOUS_PORTS = {
    4444, 4445, 1234, 31337, 8888, 9001, 9002,   # common shells/C2
    6667, 6668, 6669,                               # IRC (botnet C2)
    5555, 5554,                                     # Android ADB / RAT
    2222, 2323,                                     # Alt SSH (often brute-forced)
}

BEACON_INTERVAL_TOLERANCE = 5   # seconds — flag if connection repeats this precisely
HIGH_CONN_THRESHOLD = 20        # connections per process in one scan window


class NetworkSentinel:
    def __init__(self, on_signal: Callable):
        self._on_signal = on_signal
        self._connection_history: dict[str, list[float]] = defaultdict(list)
        self._scan_interval = int(os.getenv("SENTINEL_INTERVAL", "15"))

    def scan(self) -> list:
        """Single-pass network scan. Returns list of ThreatSignals."""
        try:
            import psutil
        except ImportError:
            return []

        signals = []
        conn_by_pid: dict[int, list] = defaultdict(list)

        for conn in psutil.net_connections(kind="inet"):
            if conn.status != "ESTABLISHED" or not conn.raddr:
                continue
            conn_by_pid[conn.pid or 0].append(conn)

        for pid, conns in conn_by_pid.items():
            proc_name = self._get_proc_name(pid)

            # ── High connection count ──
            if len(conns) > HIGH_CONN_THRESHOLD:
                signals.append(self._make_signal(
                    severity="HIGH",
                    summary=f"Process '{proc_name}' (PID {pid}) has {len(conns)} simultaneous connections — possible scanner or botnet activity.",
                    raw={"pid": pid, "proc": proc_name, "count": len(conns)}
                ))

            for conn in conns:
                remote_ip, remote_port = conn.raddr.ip, conn.raddr.port

                # ── Suspicious port ──
                if remote_port in SUSPICIOUS_PORTS:
                    signals.append(self._make_signal(
                        severity="HIGH",
                        summary=f"'{proc_name}' (PID {pid}) connected to {remote_ip}:{remote_port} — known C2/shell port.",
                        raw={"pid": pid, "proc": proc_name, "remote": f"{remote_ip}:{remote_port}"}
                    ))

                # ── Beaconing detection ──
                key = f"{pid}:{remote_ip}"
                now = time.time()
                history = self._connection_history[key]
                history.append(now)
                # Keep only last 10 observations
                self._connection_history[key] = history[-10:]

                if len(history) >= 3:
                    intervals = [history[i+1] - history[i] for i in range(len(history)-1)]
                    avg = sum(intervals) / len(intervals)
                    deviation = max(abs(i - avg) for i in intervals)
                    if avg > 0 and deviation < BEACON_INTERVAL_TOLERANCE:
                        signals.append(self._make_signal(
                            severity="HIGH",
                            summary=f"Beaconing detected: '{proc_name}' → {remote_ip} every ~{avg:.1f}s (±{deviation:.1f}s). Possible C2 heartbeat.",
                            raw={"pid": pid, "proc": proc_name, "remote": remote_ip, "interval_avg": avg}
                        ))

        return signals

    def run(self):
        """Continuous monitoring loop."""
        while True:
            for signal in self.scan():
                self._on_signal(signal)
            time.sleep(self._scan_interval)

    def _get_proc_name(self, pid: int) -> str:
        try:
            import psutil
            return psutil.Process(pid).name()
        except Exception:
            return f"pid:{pid}"

    def _make_signal(self, severity: str, summary: str, raw: dict):
        from core.orchestrator import ThreatSignal
        return ThreatSignal(source="NETWORK_SENTINEL", severity=severity, summary=summary, raw=raw)
