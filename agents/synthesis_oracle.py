"""
SYNTHESIS ORACLE — Fuses all 4 signal streams into a unified threat verdict.

Takes raw ThreatSignals from the other 4 agents, enriches with feed data,
and uses the LLM to produce a structured, actionable threat verdict.
"""

import json
from datetime import datetime


ORACLE_SYSTEM = """You are the Synthesis Oracle, the final analysis layer of Ghost Reaper — an AI-powered threat detection cluster.

You receive threat signals from 4 specialized agents:
- NETWORK_SENTINEL: Network connection anomalies, C2 patterns, beaconing
- ENTROPY_DETECTIVE: High-entropy files indicating encryption/packing/obfuscation
- BEHAVIORAL_ANALYSIS: Suspicious process chains, LOLBin abuse, masquerading
- HONEYPOT_OVERSEER: Canary token triggers, decoy port connections

Your job: synthesize all signals into a single, authoritative threat verdict.

Output JSON with these exact fields:
{
  "severity": "CLEAN|LOW|MEDIUM|HIGH|CRITICAL",
  "verdict": "One sentence executive summary",
  "threat_type": "e.g. Ransomware, C2 Beaconing, Credential Harvesting, Lateral Movement, etc.",
  "confidence": "LOW|MEDIUM|HIGH",
  "sources": ["list of contributing agent names"],
  "analysis": "2-4 paragraph technical analysis. What happened, what it means, recommended immediate actions.",
  "iocs": ["list of indicators of compromise extracted from signals"],
  "recommended_actions": ["list of 3-5 concrete remediation steps"]
}

Be precise. No false positives. If signals are ambiguous, say so. Severity CRITICAL means act immediately."""


class SynthesisOracle:
    def __init__(self, llm, feeds):
        self.llm   = llm
        self.feeds = feeds

    def synthesize(self, signals: list) -> dict:
        """Synthesize a list of ThreatSignals into a unified verdict dict."""
        if not signals:
            return self._clean_verdict()

        # Build signal summary for the LLM
        signal_text = self._format_signals(signals)

        # Enrich with feed data for any IPs/hashes in signals
        enrichment = self._enrich(signals)

        prompt = f"""THREAT SIGNALS RECEIVED — {datetime.utcnow().isoformat()}Z

{signal_text}

FEED ENRICHMENT:
{json.dumps(enrichment, indent=2) if enrichment else "No external feed data available."}

Synthesize these signals into a threat verdict. Output valid JSON only."""

        try:
            response = self.llm.chat(
                messages=[{"role": "user", "content": prompt}],
                system=ORACLE_SYSTEM,
                max_tokens=1200,
                temperature=0.1,
            )
            # Extract JSON from response
            verdict = self._parse_json(response)
            verdict["raw_signal_count"] = len(signals)
            verdict["timestamp"] = datetime.utcnow().isoformat()
            return verdict
        except Exception as e:
            return {
                "severity": "UNKNOWN",
                "verdict": f"Oracle synthesis failed: {e}",
                "sources": list({s.source for s in signals}),
                "analysis": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }

    def _format_signals(self, signals: list) -> str:
        lines = []
        for i, s in enumerate(signals, 1):
            lines.append(f"Signal {i}: [{s.severity}] {s.source}")
            lines.append(f"  Summary: {s.summary}")
            lines.append(f"  Time: {s.timestamp}")
            if s.raw:
                lines.append(f"  Raw: {json.dumps(s.raw)}")
        return "\n".join(lines)

    def _enrich(self, signals: list) -> dict:
        if not self.feeds.available_feeds:
            return {}
        enrichment = {}
        for signal in signals:
            raw = signal.raw or {}
            for key in ("remote_ip", "remote", "path"):
                if key in raw:
                    indicator = str(raw[key]).split(":")[0]
                    if indicator and indicator not in enrichment:
                        enrichment[indicator] = self.feeds.query_all(indicator)
        return enrichment

    def _parse_json(self, text: str) -> dict:
        # Strip markdown code fences if present
        text = text.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        return json.loads(text.strip())

    def _clean_verdict(self) -> dict:
        return {
            "severity": "CLEAN",
            "verdict": "No threats detected in this scan window.",
            "threat_type": "None",
            "confidence": "HIGH",
            "sources": [],
            "analysis": "All agents reported clean. No anomalous behavior, high-entropy files, suspicious processes, or honeypot triggers.",
            "iocs": [],
            "recommended_actions": ["Continue monitoring."],
            "timestamp": datetime.utcnow().isoformat(),
        }
