"""
BEHAVIORAL ANALYSIS AGENT — Tracks process lineage, detects lateral movement.

Monitors running processes for:
- Suspicious parent-child relationships (e.g. Word spawning cmd.exe)
- Processes masquerading as system processes (wrong path)
- New processes spawned from unusual locations
- Known LOLBin (Living-off-the-Land Binary) abuse
"""

import os
import time
from collections import defaultdict
from typing import Callable

SCAN_INTERVAL = int(os.getenv("BEHAVIOR_INTERVAL", "20"))

# Processes that should NEVER be children of office/browser apps
SUSPICIOUS_CHILD_PROCS = {
    "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
    "bitsadmin.exe", "wmic.exe", "msiexec.exe", "bash.exe",
}

# Common office/browser parents that should not spawn shells
SUSPICIOUS_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe",
    "acrobat.exe", "acrord32.exe",
}

# LOLBins commonly abused for code execution / persistence
LOLBINS = {
    "certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe",
    "rundll32.exe", "msiexec.exe", "wmic.exe", "cmstp.exe",
    "installutil.exe", "msbuild.exe", "csc.exe", "vbc.exe",
}

# Paths where system binaries should NOT be running from
SYSTEM_PROC_LEGIT_PATHS = {
    "svchost.exe":    r"c:\windows\system32",
    "lsass.exe":      r"c:\windows\system32",
    "csrss.exe":      r"c:\windows\system32",
    "winlogon.exe":   r"c:\windows\system32",
    "services.exe":   r"c:\windows\system32",
    "smss.exe":       r"c:\windows\system32",
    "explorer.exe":   r"c:\windows",
}


class BehavioralAnalysis:
    def __init__(self, on_signal: Callable):
        self._on_signal = on_signal
        self._seen_pids: set[int] = set()

    def scan(self) -> list:
        try:
            import psutil
        except ImportError:
            return []

        signals = []
        procs = {p.pid: p for p in psutil.process_iter(["pid", "name", "exe", "ppid", "cmdline"])}

        for pid, proc in procs.items():
            try:
                info = proc.info
                name = (info.get("name") or "").lower()
                exe  = (info.get("exe") or "").lower()
                ppid = info.get("ppid") or 0
                cmdline = " ".join(info.get("cmdline") or [])

                # ── Masquerading system process ──
                for legit_name, legit_path in SYSTEM_PROC_LEGIT_PATHS.items():
                    if name == legit_name and exe and legit_path not in exe:
                        signals.append(self._make_signal(
                            severity="CRITICAL",
                            summary=f"Process masquerading as '{legit_name}' from unexpected path: '{exe}' — possible process injection or rootkit.",
                            raw={"pid": pid, "name": name, "exe": exe}
                        ))

                # ── Suspicious parent-child chain ──
                parent = procs.get(ppid)
                if parent:
                    parent_name = (parent.info.get("name") or "").lower()
                    if parent_name in SUSPICIOUS_PARENTS and name in SUSPICIOUS_CHILD_PROCS:
                        signals.append(self._make_signal(
                            severity="HIGH",
                            summary=f"Suspicious process chain: '{parent_name}' → '{name}' (PID {pid}). Classic macro/script execution pattern.",
                            raw={"parent": parent_name, "child": name, "pid": pid, "cmdline": cmdline[:200]}
                        ))

                # ── LOLBin activity ──
                if name in LOLBINS and pid not in self._seen_pids:
                    signals.append(self._make_signal(
                        severity="MEDIUM",
                        summary=f"LOLBin execution: '{name}' (PID {pid}) — living-off-the-land binary commonly abused for code execution.",
                        raw={"pid": pid, "name": name, "cmdline": cmdline[:200]}
                    ))

                self._seen_pids.add(pid)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return signals

    def run(self):
        while True:
            for signal in self.scan():
                self._on_signal(signal)
            time.sleep(SCAN_INTERVAL)

    def _make_signal(self, severity: str, summary: str, raw: dict):
        from core.orchestrator import ThreatSignal
        return ThreatSignal(source="BEHAVIORAL_ANALYSIS", severity=severity, summary=summary, raw=raw)
