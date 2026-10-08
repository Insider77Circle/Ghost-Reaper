# Ghost Reaper 👻

> *Hunt without footprint. Strike without origin.*

Five AI agents watch your machine — network connections, file entropy,
process behavior, honeypot tripwires — and one LLM synthesis layer fuses
it all into a single threat verdict. No alert spam. Passive by design:
it watches, never touches.

```bash
git clone https://github.com/Insider77Circle/Ghost-Reaper.git && cd Ghost-Reaper
pip install -r requirements.txt
cp .env.example .env   # set LLM_PROVIDER + LLM_API_KEY
python main.py --scan-once --json   # one snapshot, pipe it anywhere
```

**Full-Spectrum AI Threat Detection · 5-Agent Cluster**

[![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub Stars](https://img.shields.io/github/stars/Insider77Circle/Ghost-Reaper?style=social)](https://github.com/Insider77Circle/Ghost-Reaper)

> *"Hunt without footprint. Strike without origin."*

Ghost Reaper is a passive AI-powered threat detection system built on a 5-agent cluster architecture. Each agent monitors a distinct attack surface. All signals are fused by the Synthesis Oracle — an LLM-powered analysis layer that delivers structured, actionable threat verdicts with zero noise.

---

## Why Ghost Reaper?

Traditional detection tools generate floods of alerts with little context, forcing analysts to manually triage everything. Ghost Reaper takes a different approach:

- **Signal fusion over alert spam** — four detection agents feed one synthesis layer, which reasons across all signals simultaneously before issuing a verdict
- **LLM-powered analysis** — the Synthesis Oracle doesn't just flag threats, it explains them, identifies IOCs, and recommends remediation steps
- **Bring your own LLM** — works with any provider: OpenAI, DeepSeek, Groq, Anthropic, Mistral, Ollama, or any OpenAI-compatible endpoint
- **Passive by design** — monitors without interfering, leaves no network footprint
- **Pluggable intelligence feeds** — add AbuseIPDB, VirusTotal, Shodan, or your own custom feed with one Python file

---

## The Agent Cluster

Ghost Reaper runs five specialized agents in parallel. Each owns a detection domain.

### 👁️ Network Sentinel — *EYES*
Watches all active network connections using live system data.

**Detects:**
- **C2 beaconing** — analyzes connection intervals to identify regular-heartbeat patterns characteristic of command-and-control malware
- **Suspicious port activity** — flags connections to known C2/shell ports (4444, 31337, 9001, IRC ports, etc.)
- **High connection counts** — catches processes with abnormal simultaneous connection counts, indicating scanners or botnet activity
- **Process-to-connection mapping** — ties every suspicious connection back to the owning process

---

### 🔬 Entropy Detective — *HANDS*
Calculates Shannon entropy on files landing in watched directories.

**Detects:**
- **Packed executables** — malware commonly uses packers (UPX, custom) that produce near-random byte distributions
- **Encrypted payloads** — ransomware staging files, encrypted shellcode loaders, and exfiltration archives all score high entropy
- **Obfuscated scripts** — heavily encoded PowerShell, VBScript, and JavaScript frequently exceeds natural language entropy levels
- **Configurable thresholds and watch paths** — tune sensitivity and add directories via `.env`

Entropy is scored out of 8.0. Ghost Reaper flags at 7.2+ (suspicious) and 7.6+ (HIGH severity).

---

### 🧠 Behavioral Analysis — *SHADOW*
Tracks process creation chains and identifies known abuse patterns.

**Detects:**
- **Suspicious parent-child chains** — Office apps, browsers, and PDF readers that spawn `cmd.exe`, `powershell.exe`, `wscript.exe`, or other shell processes. Classic macro and drive-by exploit signatures
- **LOLBin (Living-off-the-Land Binary) abuse** — monitors execution of `certutil.exe`, `bitsadmin.exe`, `mshta.exe`, `regsvr32.exe`, `msbuild.exe`, and other commonly abused Windows binaries
- **Process masquerading** — catches malware running as `svchost.exe`, `lsass.exe`, or other system processes from unexpected filesystem paths (a common rootkit technique)
- **Lateral movement indicators** — correlates process activity across the system to identify unusual propagation patterns

---

### 🪤 Honeypot Overseer — *TRAP*
Deploys canary tokens and decoy listeners. Any access is a confirmed threat.

**Deploys:**
- **Canary credential files** — fake `credentials.txt`, `aws_keys.json`, `db_config.yml`, `id_rsa`, and backup codes placed in a configurable directory. Legitimate processes never touch these
- **Decoy network listeners** — opens configurable ports (default: 21, 23, 3389) that serve fake banners. Any connection is an active intruder, not a false positive
- **Mtime/atime monitoring** — detects file access, modification, or deletion of canary assets

Any honeypot trigger fires a **CRITICAL** severity signal immediately — bypassing the normal synthesis interval for instant escalation.

---

### ⚡ Synthesis Oracle — *BRAIN*
The intelligence layer that makes Ghost Reaper more than a collection of scanners.

**Process:**
1. Receives signals from all four agents
2. Enriches indicators (IPs, hashes) against configured threat feeds
3. Sends a structured prompt to your configured LLM
4. Returns a complete threat verdict

**Verdict includes:**
- **Severity** — CLEAN / LOW / MEDIUM / HIGH / CRITICAL
- **Threat type** — e.g. Ransomware Staging, C2 Beaconing, Credential Harvesting, Lateral Movement
- **Confidence level** — LOW / MEDIUM / HIGH
- **Contributing sources** — which agents triggered
- **Technical analysis** — multi-paragraph explanation of what happened and what it means
- **IOCs** — indicators of compromise extracted from the signals
- **Recommended actions** — concrete remediation steps, not generic advice

---

## Use Cases

| Scenario | How Ghost Reaper Helps |
|---|---|
| **SOC monitoring** | Run continuously alongside your SIEM. Ghost Reaper surfaces behavioral and entropy signals that signature-based tools miss |
| **Incident response** | `--scan-once --json` gives a rapid structured snapshot of current system state for IR triage |
| **Malware analysis lab** | Drop samples into watched directories, execute them in a VM — Entropy Detective and Behavioral Analysis capture the execution profile |
| **Red team detection gap assessment** | Run Ghost Reaper against your own infrastructure during an authorized engagement to see what it catches |
| **Developer security testing** | Monitor your dev environment for dependency confusion attacks, supply chain compromises, or rogue build scripts |
| **Honeypot research** | Customize canary files and decoy ports to study attacker behavior and tool signatures |

---

## LLM Provider Support

Ghost Reaper works with any LLM that exposes an OpenAI-compatible API, plus native Anthropic support.

| Provider | `LLM_PROVIDER` value | Notes |
|---|---|---|
| OpenAI | `openai` | GPT-4o, GPT-4o-mini, etc. |
| DeepSeek | `deepseek` | deepseek-chat, deepseek-reasoner |
| Groq | `groq` | Fast inference — Llama 3, Mixtral |
| Together AI | `together` | Wide model selection |
| Mistral | `mistral` | mistral-large, mistral-small |
| Anthropic | `anthropic` | Claude Sonnet, Haiku, Opus |
| Ollama | `ollama` | Local models — fully offline |
| Custom | `custom` | Set `LLM_BASE_URL` to any endpoint |

---

## Threat Intelligence Feeds

All feeds are optional. Ghost Reaper works without any feeds — they add enrichment context to the Synthesis Oracle's analysis.

| Feed | What it adds | Key required |
|---|---|---|
| **AbuseIPDB** | Abuse confidence score, report count, ISP, Tor flag | `ABUSEIPDB_API_KEY` |
| **VirusTotal** | Multi-AV scan results for IPs, domains, file hashes | `VIRUSTOTAL_API_KEY` |
| **Shodan** | Open ports, org, known CVEs, hostnames for IPs | `SHODAN_API_KEY` |
| **Custom** | Drop a Python file in `feeds/` with `FEED_NAME` and `query(indicator)` | Your own |

---

## Installation

```bash
# Clone
git clone https://github.com/Insider77Circle/Ghost-Reaper.git
cd Ghost-Reaper

# Install dependencies
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env — set LLM_PROVIDER, LLM_API_KEY, LLM_MODEL
# Optionally add feed API keys
```

---

## Configuration

All configuration lives in `.env`. Copy `.env.example` to get started.

```env
# Required
LLM_PROVIDER=openai          # or deepseek, groq, anthropic, mistral, ollama, custom
LLM_API_KEY=sk-...
LLM_MODEL=gpt-4o

# Optional feeds
ABUSEIPDB_API_KEY=
VIRUSTOTAL_API_KEY=
SHODAN_API_KEY=

# Optional tuning
SENTINEL_INTERVAL=15         # seconds between network scans
ENTROPY_INTERVAL=30          # seconds between entropy scans
BEHAVIOR_INTERVAL=20         # seconds between process scans
HONEYPOT_INTERVAL=10         # seconds between canary checks
ENTROPY_WATCH_DIRS=/tmp,/home/user/downloads   # extra dirs to watch
HONEYPOT_PORTS=21,23,3389   # decoy listener ports
```

---

## Usage

```bash
# Continuous monitoring — runs until Ctrl+C
python main.py

# Single-pass scan — useful for cron jobs or CI pipelines
python main.py --scan-once

# JSON output — pipe into SIEM, Slack webhook, alerting system
python main.py --scan-once --json
```

### Adding a Custom Feed

Create any Python file in `feeds/` with two things:

```python
FEED_NAME = "my_feed"

def query(indicator: str) -> dict:
    # indicator is an IP, domain, or file hash
    # return any dict — it gets passed to the Synthesis Oracle
    ...
```

Ghost Reaper auto-discovers and loads it on next startup. No registration required.

---

## Architecture

```
                    ┌─────────────────────┐
                    │   GhostReaper       │  ← Orchestrator
                    │   Orchestrator      │
                    └──────────┬──────────┘
                               │ spawns (threaded)
        ┌──────────────────────┼──────────────────────┐
        │                      │                      │
 ┌──────▼──────┐      ┌────────▼──────┐      ┌───────▼──────┐
 │  Network    │      │   Entropy     │      │  Behavioral  │
 │  Sentinel   │      │   Detective   │      │  Analysis    │
 └──────┬──────┘      └────────┬──────┘      └───────┬──────┘
        │                      │                      │
        └──────────────────────┼──────────────────────┘
                               │ ThreatSignals
                    ┌──────────▼──────────┐
                    │  Honeypot Overseer  │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Synthesis Oracle   │  ← LLM + Feeds
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │   Threat Verdict    │  → stdout / JSON
                    └─────────────────────┘
```

---

## Project Structure

```
Ghost-Reaper/
├── main.py                        # Entry point — CLI interface
├── requirements.txt
├── .env.example                   # Configuration template
├── agents/
│   ├── network_sentinel.py        # C2 detection, beaconing analysis
│   ├── entropy_detective.py       # Shannon entropy file scanning
│   ├── behavioral_analysis.py     # Process lineage, LOLBin detection
│   ├── honeypot_overseer.py       # Canary tokens, decoy listeners
│   └── synthesis_oracle.py       # LLM-powered threat fusion
├── core/
│   ├── orchestrator.py            # Agent coordination + signal routing
│   ├── llm_client.py              # Universal LLM client
│   └── feed_manager.py            # Auto-discovery feed loader
├── feeds/
│   └── examples/
│       ├── abuseipdb_feed.py
│       ├── virustotal_feed.py
│       └── shodan_feed.py
└── docs/
    └── index.html                 # GitHub Pages site
```

---

## Requirements

- Python 3.11+
- `psutil` — process and network monitoring
- `python-dotenv` — environment configuration
- Any LLM API key (see supported providers above)

---


---

## 🛡️ REDSTORM RESEARCH suite

Security for the agent layer, not the model layer. More from the lab:

| Repo | What it does |
|---|---|
| [Red-Agent](https://github.com/Insider77Circle/Red-Agent) | AI-powered proxy command center — natural-language red-team operations |
| [AI-PASSWORD-TESTING-AGENT](https://github.com/Insider77Circle/AI-PASSWORD-TESTING-AGENT) | AI-driven password strength testing and vulnerability research |
| [Ghost-Reaper](https://github.com/Insider77Circle/Ghost-Reaper) | AI-powered full-spectrum passive threat detection |
| [MIRAGE](https://github.com/Insider77Circle/MIRAGE) | AI cyber range & honeypot simulator for red-team practice |
| [SCAFFOLD-WATCH](https://github.com/Insider77Circle/SCAFFOLD-WATCH) | Silent guardian for Claude Code — real-time builder monitoring |
| [STEGANO](https://github.com/Insider77Circle/STEGANO) | Invisible-Unicode injection attacks against LLMs + detection PoC |
| [mcp-trust-registry](https://github.com/Insider77Circle/mcp-trust-registry) | Agent-pointable MCP registry with trust verification |
## License

MIT — free to use, modify, and distribute.

---

*Built by [Insider77Circle](https://github.com/Insider77Circle)*
