"""
Command line entry point.

    python -m detection_engine --log data/auth.log
    python -m detection_engine --log data/auth.log --html reports/report.html --json reports/alerts.json
    python -m detection_engine --list-rules
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .engine import LEVELS, load_rules, run_all
from .parsers import load_events
from .report import write_html, write_json

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    parser = argparse.ArgumentParser(prog="detection_engine", description="Run detection rules over logs.")
    parser.add_argument("--log", type=Path, default=PROJECT_ROOT / "data" / "auth.log")
    parser.add_argument("--rules", type=Path, default=PROJECT_ROOT / "rules")
    parser.add_argument("--year", type=int, default=2026, help="Year for syslog timestamps (they have none)")
    parser.add_argument("--min-level", choices=LEVELS, default="low")
    parser.add_argument("--json", type=Path)
    parser.add_argument("--html", type=Path)
    parser.add_argument("--list-rules", action="store_true")
    args = parser.parse_args()

    rules = load_rules(args.rules)
    if args.list_rules:
        for r in rules:
            print(f"{r.id:8} {r.level:9} {', '.join(r.mitre):12} {r.title}")
        return 0

    if not args.log.exists():
        print(f"Log not found: {args.log}  (tip: python src/generate_auth_log.py)")
        return 2

    events = load_events(args.log, args.year)
    alerts = [a for a in run_all(rules, events) if LEVELS.index(a.level) >= LEVELS.index(args.min_level)]

    print(f"{len(events)} events, {len(rules)} rules, {len(alerts)} alerts\n")
    for a in alerts:
        group = " ".join(f"{k}={v}" for k, v in a.group.items())
        print(f"[{a.level.upper():8}] {a.rule_id:8} {a.title:38} {group:24} x{a.count:<3} {a.first_seen}")

    if args.json:
        write_json(alerts, args.json)
        print(f"\nJSON  -> {args.json}")
    if args.html:
        write_html(alerts, len(events), args.html, args.log.name)
        print(f"HTML  -> {args.html}")
    return 1 if any(a.level in {"high", "critical"} for a in alerts) else 0


if __name__ == "__main__":
    sys.exit(main())
