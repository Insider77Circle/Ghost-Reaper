"""
Ghost Reaper Orchestrator — coordinates all 5 agents in the cluster.

Flow:
  NETWORK SENTINEL → anomaly flags → ENTROPY DETECTIVE
  BEHAVIORAL ANALYSIS → process lineage → SYNTHESIS ORACLE
  HONEYPOT OVERSEER → trigger events → SYNTHESIS ORACLE
  SYNTHESIS ORACLE → unified verdict → [OPERATOR]
"""

import time
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

from core.llm_client import LLMClient
from core.feed_manager import FeedManager
from agents.network_sentinel import NetworkSentinel
from agents.entropy_detective import EntropyDetective
from agents.behavioral_analysis import BehavioralAnalysis
from agents.honeypot_overseer import HoneypotOverseer
from agents.synthesis_oracle import SynthesisOracle


@dataclass
class ThreatSignal:
    source: str
    severity: str          # LOW / MEDIUM / HIGH / CRITICAL
    summary: str
    raw: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class GhostReaper:
    """Master orchestrator for the Ghost Reaper threat detection cluster."""

    def __init__(self, on_verdict: Optional[Callable[[dict], None]] = None):
        print("[GHOST REAPER] Initializing cluster...")
        self.llm     = LLMClient()
        self.feeds   = FeedManager()
        self.signals: list[ThreatSignal] = []
        self._lock   = threading.Lock()
        self._on_verdict = on_verdict or self._default_verdict_handler

        self.sentinel  = NetworkSentinel(self._collect_signal)
        self.entropy   = EntropyDetective(self._collect_signal)
        self.behavior  = BehavioralAnalysis(self._collect_signal)
        self.honeypot  = HoneypotOverseer(self._collect_signal)
        self.oracle    = SynthesisOracle(self.llm, self.feeds)

        print(f"[GHOST REAPER] LLM: {self.llm.provider} / {self.llm.model}")
        print(f"[GHOST REAPER] Feeds loaded: {self.feeds.available_feeds or ['none']}")

    def _collect_signal(self, signal: ThreatSignal):
        with self._lock:
            self.signals.append(signal)
        if signal.severity in ("HIGH", "CRITICAL"):
            self._trigger_synthesis()

    def _trigger_synthesis(self):
        with self._lock:
            pending = list(self.signals)
            self.signals.clear()

        if not pending:
            return

        verdict = self.oracle.synthesize(pending)
        self._on_verdict(verdict)

    def _default_verdict_handler(self, verdict: dict):
        print("\n" + "═" * 60)
        print("  SYNTHESIS ORACLE — THREAT VERDICT")
        print("═" * 60)
        print(f"  Severity : {verdict.get('severity', 'UNKNOWN')}")
        print(f"  Verdict  : {verdict.get('verdict', '')}")
        print(f"  Sources  : {', '.join(verdict.get('sources', []))}")
        print("─" * 60)
        print(verdict.get("analysis", ""))
        print("═" * 60 + "\n")

    def start(self):
        """Start all agents. Blocks until keyboard interrupt."""
        print("[GHOST REAPER] Starting all agents...")
        threads = [
            threading.Thread(target=self.sentinel.run,  daemon=True, name="NetworkSentinel"),
            threading.Thread(target=self.entropy.run,   daemon=True, name="EntropyDetective"),
            threading.Thread(target=self.behavior.run,  daemon=True, name="BehavioralAnalysis"),
            threading.Thread(target=self.honeypot.run,  daemon=True, name="HoneypotOverseer"),
        ]
        for t in threads:
            t.start()
            print(f"  ▶ {t.name} online")

        print("[GHOST REAPER] All agents active. Monitoring...\n")
        try:
            while True:
                time.sleep(30)
                with self._lock:
                    if self.signals:
                        self._trigger_synthesis()
        except KeyboardInterrupt:
            print("\n[GHOST REAPER] Shutdown signal received. Stopping.")

    def scan_once(self) -> dict:
        """Run a single-pass scan across all agents and return a verdict."""
        signals = []
        signals.extend(self.sentinel.scan())
        signals.extend(self.entropy.scan())
        signals.extend(self.behavior.scan())
        signals.extend(self.honeypot.scan())

        if not signals:
            return {"severity": "CLEAN", "verdict": "No threats detected.", "sources": [], "analysis": ""}

        return self.oracle.synthesize(signals)
