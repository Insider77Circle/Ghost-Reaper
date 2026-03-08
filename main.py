#!/usr/bin/env python3
"""
Ghost Reaper — AI-Powered Full-Spectrum Passive Threat Detection
Cluster: Network Sentinel · Entropy Detective · Behavioral Analysis · Honeypot Overseer · Synthesis Oracle

Usage:
    python main.py              # Continuous monitoring mode
    python main.py --scan-once  # Single-pass scan, print verdict, exit
    python main.py --help       # Show this help
"""

import sys
import os
import argparse
import json
from dotenv import load_dotenv

load_dotenv()


def check_env():
    missing = []
    if not os.getenv("LLM_API_KEY"):
        missing.append("LLM_API_KEY")
    if missing:
        print("╔══════════════════════════════════════════════════╗")
        print("║  Ghost Reaper — Missing Configuration            ║")
        print("╠══════════════════════════════════════════════════╣")
        for var in missing:
            print(f"║  ✗ {var:<46}║")
        print("╠══════════════════════════════════════════════════╣")
        print("║  Copy .env.example to .env and fill in values.  ║")
        print("╚══════════════════════════════════════════════════╝")
        sys.exit(1)


def print_banner():
    print("""
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║    ░██████╗░██╗  ██╗░█████╗░░██████╗████████╗           ║
║   ██╔════╝░██║  ██║██╔══██╗██╔════╝╚══██╔══╝           ║
║   ██║░░██╗░███████║██║░░██║╚█████╗░   ██║              ║
║   ██║░░╚██╗██╔══██║██║░░██║░╚═══██╗   ██║              ║
║   ╚██████╔╝██║  ██║╚█████╔╝██████╔╝   ██║              ║
║    ╚═════╝ ╚═╝  ╚═╝ ╚════╝ ╚═════╝    ╚═╝              ║
║                                                          ║
║    R E A P E R   ·   Threat Detection Cluster            ║
║    Hunt without footprint. Strike without origin.        ║
╚══════════════════════════════════════════════════════════╝
""")


def main():
    parser = argparse.ArgumentParser(description="Ghost Reaper — AI threat detection cluster")
    parser.add_argument("--scan-once", action="store_true", help="Single-pass scan and exit")
    parser.add_argument("--json", action="store_true", help="Output verdict as JSON (scan-once mode)")
    args = parser.parse_args()

    check_env()
    print_banner()

    from core.orchestrator import GhostReaper

    if args.scan_once:
        gr = GhostReaper()
        print("[*] Running single-pass scan...")
        verdict = gr.scan_once()
        if args.json:
            print(json.dumps(verdict, indent=2))
        else:
            print(f"\n  Severity : {verdict.get('severity', 'UNKNOWN')}")
            print(f"  Verdict  : {verdict.get('verdict', '')}")
            if verdict.get("threat_type"):
                print(f"  Type     : {verdict['threat_type']}")
            if verdict.get("analysis"):
                print(f"\n  Analysis:\n  {verdict['analysis']}")
            if verdict.get("recommended_actions"):
                print("\n  Recommended Actions:")
                for action in verdict["recommended_actions"]:
                    print(f"    · {action}")
    else:
        gr = GhostReaper()
        gr.start()


if __name__ == "__main__":
    main()
