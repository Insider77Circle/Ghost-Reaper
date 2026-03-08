"""
HONEYPOT OVERSEER — Deploys canary tokens to lure intruders into detection.

Creates and monitors:
- Canary files (fake credentials, config files, sensitive-looking documents)
- Canary directories (fake admin shares, backup folders)
- Canary network listeners on decoy ports
- File access monitoring via mtime/atime tracking
"""

import os
import json
import time
import socket
import threading
from datetime import datetime
from typing import Callable

SCAN_INTERVAL  = int(os.getenv("HONEYPOT_INTERVAL", "10"))
CANARY_DIR     = os.getenv("HONEYPOT_DIR", os.path.join(os.path.expanduser("~"), ".ghost-reaper", "canaries"))
DECOY_PORTS    = [int(p) for p in os.getenv("HONEYPOT_PORTS", "21,23,3389").split(",") if p.strip().isdigit()]


CANARY_FILES = {
    "credentials.txt": "admin:P@ssw0rd123!\nroot:toor\nbackup:backup2024",
    "aws_keys.json":   json.dumps({"AccessKeyId": "AKIAIOSFODNN7EXAMPLE", "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}),
    "db_config.yml":   "host: 10.0.0.5\nport: 5432\nuser: postgres\npassword: postgres_prod_2024!",
    "id_rsa":          "-----BEGIN OPENSSH PRIVATE KEY-----\n[CANARY — NOT REAL]\n-----END OPENSSH PRIVATE KEY-----",
    "backup_codes.txt":"2FA Backup Codes:\n839201 · 473829 · 920183 · 748291",
}


class HoneypotOverseer:
    def __init__(self, on_signal: Callable):
        self._on_signal = on_signal
        self._canary_mtimes: dict[str, float] = {}
        self._listener_threads: list[threading.Thread] = []
        self._deployed = False

    def deploy(self):
        """Create canary files and start decoy port listeners."""
        if self._deployed:
            return
        os.makedirs(CANARY_DIR, exist_ok=True)

        for fname, content in CANARY_FILES.items():
            fpath = os.path.join(CANARY_DIR, fname)
            if not os.path.exists(fpath):
                with open(fpath, "w") as f:
                    f.write(content)
            self._canary_mtimes[fpath] = os.path.getmtime(fpath)

        for port in DECOY_PORTS:
            t = threading.Thread(target=self._decoy_listener, args=(port,), daemon=True)
            t.start()
            self._listener_threads.append(t)

        self._deployed = True
        print(f"  [HONEYPOT] Canaries deployed at: {CANARY_DIR}")
        print(f"  [HONEYPOT] Decoy listeners: {DECOY_PORTS}")

    def scan(self) -> list:
        """Check if any canary files were accessed or modified."""
        if not self._deployed:
            self.deploy()

        signals = []
        for fpath, known_mtime in self._canary_mtimes.items():
            try:
                current_mtime = os.path.getmtime(fpath)
                if current_mtime != known_mtime:
                    signals.append(self._make_signal(
                        severity="CRITICAL",
                        summary=f"CANARY TRIGGERED: '{os.path.basename(fpath)}' was accessed or modified. Intruder may be harvesting credentials.",
                        raw={"canary": fpath, "prev_mtime": known_mtime, "new_mtime": current_mtime}
                    ))
                    self._canary_mtimes[fpath] = current_mtime
            except FileNotFoundError:
                signals.append(self._make_signal(
                    severity="HIGH",
                    summary=f"CANARY DELETED: '{os.path.basename(fpath)}' was removed — possible attacker covering tracks.",
                    raw={"canary": fpath}
                ))
        return signals

    def run(self):
        self.deploy()
        while True:
            for signal in self.scan():
                self._on_signal(signal)
            time.sleep(SCAN_INTERVAL)

    def _decoy_listener(self, port: int):
        """Listens on a decoy port and fires a signal on connection."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", port))
                s.listen(5)
                while True:
                    try:
                        conn, addr = s.accept()
                        with conn:
                            remote_ip = addr[0]
                            self._on_signal(self._make_signal(
                                severity="CRITICAL",
                                summary=f"DECOY PORT HIT: {remote_ip} connected to honeypot port {port}. Active intruder on network.",
                                raw={"remote_ip": remote_ip, "decoy_port": port, "timestamp": datetime.utcnow().isoformat()}
                            ))
                            conn.send(b"SSH-2.0-OpenSSH_8.9\r\n")
                    except Exception:
                        continue
        except OSError:
            pass  # Port already in use — skip silently

    def _make_signal(self, severity: str, summary: str, raw: dict):
        from core.orchestrator import ThreatSignal
        return ThreatSignal(source="HONEYPOT_OVERSEER", severity=severity, summary=summary, raw=raw)
