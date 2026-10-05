"""Write alerts as JSON (for other tools) and as a self-contained HTML report (for people)."""

from __future__ import annotations

import html
import json
from collections import Counter
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from .engine import Alert

COLOURS = {"critical": "#b71c1c", "high": "#e65100", "medium": "#f9a825", "low": "#2e7d32", "informational": "#546e7a"}


def write_json(alerts: list[Alert], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([asdict(a) for a in alerts], indent=2), encoding="utf-8")


def write_html(alerts: list[Alert], events_count: int, path: Path, source: str) -> None:
    by_level = Counter(a.level for a in alerts)
    techniques = Counter(t for a in alerts for t in a.mitre)
    cards = "".join(
        f'<div class="card" style="border-color:{COLOURS[l]}"><b>{by_level.get(l, 0)}</b><span>{l}</span></div>'
        for l in ["critical", "high", "medium", "low"]
    )
    rows = []
    for a in alerts:
        group = ", ".join(f"{k}={v}" for k, v in a.group.items()) or "-"
        evidence = "<br>".join(html.escape(e) for e in a.evidence)
        mitre = " ".join(
            f'<a href="https://attack.mitre.org/techniques/{t.replace(".", "/")}/">{t}</a>' for t in a.mitre)
        rows.append(
            f'<tr><td><span class="pill" style="background:{COLOURS[a.level]}">{a.level}</span></td>'
            f"<td>{html.escape(a.rule_id)}</td><td>{html.escape(a.title)}</td><td>{mitre}</td>"
            f"<td>{html.escape(group)}</td><td>{a.count}</td><td>{a.first_seen}<br>{a.last_seen}</td>"
            f"<td><details><summary>show</summary><code>{evidence}</code></details></td></tr>"
        )
    top = "".join(f"<li>{t} &times; {c}</li>" for t, c in techniques.most_common(8)) or "<li>none</li>"
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Detection Report</title>
<style>
body{{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:24px;color:#1a1a1a;background:#fafafa}}
h1{{margin:0 0 4px}} .meta{{color:#666;margin-bottom:20px}}
.cards{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}}
.card{{background:#fff;border-left:6px solid;padding:12px 18px;min-width:110px;box-shadow:0 1px 3px #0002}}
.card b{{font-size:28px;display:block}} .card span{{text-transform:capitalize;color:#555}}
table{{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 3px #0002}}
th,td{{padding:8px 10px;border-bottom:1px solid #eee;text-align:left;vertical-align:top;font-size:14px}}
th{{background:#263238;color:#fff}} .pill{{color:#fff;padding:2px 8px;border-radius:10px;font-size:12px}}
code{{font-size:12px}} a{{color:#1565c0}}
</style></head><body>
<h1>Detection Report</h1>
<div class="meta">Source: {html.escape(source)} &middot; {events_count} events &middot; {len(alerts)} alerts &middot;
generated {datetime.now():%Y-%m-%d %H:%M}</div>
<div class="cards">{cards}</div>
<h3>Most seen ATT&amp;CK techniques</h3><ul>{top}</ul>
<table><tr><th>Level</th><th>Rule</th><th>Title</th><th>ATT&amp;CK</th><th>Group</th><th>Count</th><th>Time</th><th>Evidence</th></tr>
{''.join(rows)}</table></body></html>"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(page, encoding="utf-8")
