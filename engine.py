"""
Rule engine.

Rules are YAML files in a simplified Sigma-like format:

    id: LDE-001
    title: SSH brute force
    level: high                     # informational | low | medium | high | critical
    mitre: [T1110.001]
    description: Many failed SSH logins from one source
    match:                          # every field must match (AND)
      event: ssh_failed
      user|in: [root, admin]        # modifiers: |contains |startswith |endswith |re |in |not
    threshold:                      # optional: alert only when enough events group together
      count: 5
      within: 5m                    # s / m / h
      group_by: [src_ip]
      distinct: user                # optional: count distinct values of this field instead
    followed_by:                    # optional: only alert if a matching event follows the burst
      event: ssh_success            # for the same group, within the same window

A rule without `threshold` fires once per matching event.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

import yaml

LEVELS = ["informational", "low", "medium", "high", "critical"]


@dataclass
class Rule:
    id: str
    title: str
    level: str
    match: dict
    mitre: list[str] = field(default_factory=list)
    description: str = ""
    threshold: dict | None = None
    followed_by: dict | None = None

    def __post_init__(self):
        if self.level not in LEVELS:
            raise ValueError(f"{self.id}: level must be one of {LEVELS}")


@dataclass
class Alert:
    rule_id: str
    title: str
    level: str
    mitre: list[str]
    first_seen: str
    last_seen: str
    count: int
    group: dict
    evidence: list[str]


def parse_duration(text: str) -> timedelta:
    found = re.fullmatch(r"(\d+)\s*([smh])", str(text).strip())
    if not found:
        raise ValueError(f"Bad duration '{text}' - use e.g. 30s, 5m, 2h")
    value, unit = int(found[1]), found[2]
    return {"s": timedelta(seconds=value), "m": timedelta(minutes=value), "h": timedelta(hours=value)}[unit]


def load_rules(folder: Path) -> list[Rule]:
    rules = []
    for path in sorted(folder.glob("*.y*ml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        rules.append(Rule(**data))
    ids = [r.id for r in rules]
    duplicates = {i for i in ids if ids.count(i) > 1}
    if duplicates:
        raise ValueError(f"Duplicate rule ids: {duplicates}")
    return rules


def field_matches(event: dict, key: str, expected) -> bool:
    name, _, modifier = key.partition("|")
    value = event.get(name)
    if modifier == "not":
        return value != expected
    if value is None:
        return False
    value = str(value)
    if modifier == "":
        return value == str(expected)
    if modifier == "in":
        return value in [str(x) for x in expected]
    if modifier == "contains":
        return str(expected).lower() in value.lower()
    if modifier == "startswith":
        return value.lower().startswith(str(expected).lower())
    if modifier == "endswith":
        return value.lower().endswith(str(expected).lower())
    if modifier == "re":
        return re.search(str(expected), value) is not None
    raise ValueError(f"Unknown modifier '{modifier}' in '{key}'")


def event_matches(event: dict, conditions: dict) -> bool:
    return all(field_matches(event, k, v) for k, v in conditions.items())


def _describe(event: dict) -> str:
    stamp = event.get("timestamp")
    when = stamp.strftime("%Y-%m-%d %H:%M:%S") if stamp else "?"
    return f"{when} {event.get('source_file', '')}:{event.get('line', '')} {event.get('message', event.get('event', ''))}"


def run_rule(rule: Rule, events: list[dict]) -> list[Alert]:
    matched = [e for e in events if event_matches(e, rule.match)]
    if not rule.threshold:
        return [Alert(rule.id, rule.title, rule.level, rule.mitre, _describe(e)[:19], _describe(e)[:19], 1,
                      {}, [_describe(e)]) for e in matched]

    count_needed = int(rule.threshold["count"])
    window = parse_duration(rule.threshold.get("within", "5m"))
    group_by = rule.threshold.get("group_by", [])
    distinct = rule.threshold.get("distinct")

    groups: dict[tuple, list[dict]] = defaultdict(list)
    for e in matched:
        groups[tuple(e.get(g) for g in group_by)].append(e)

    alerts = []
    for key, group_events in groups.items():
        recent: deque[dict] = deque()
        fired_until = None
        for e in group_events:
            recent.append(e)
            while e["timestamp"] - recent[0]["timestamp"] > window:
                recent.popleft()
            size = len({x.get(distinct) for x in recent}) if distinct else len(recent)
            if size >= count_needed and (fired_until is None or e["timestamp"] > fired_until):
                burst = list(recent)
                if rule.followed_by:
                    follow = next((x for x in events
                                   if burst[-1]["timestamp"] <= x["timestamp"] <= burst[-1]["timestamp"] + window
                                   and all(x.get(g) == e.get(g) for g in group_by)
                                   and event_matches(x, rule.followed_by)), None)
                    if follow is None:
                        continue
                    burst.append(follow)
                # report the whole burst, not just the events needed to cross the threshold
                end = burst[0]["timestamp"] + window
                in_window = [x for x in group_events if burst[0]["timestamp"] <= x["timestamp"] <= end]
                total = len({x.get(distinct) for x in in_window}) if distinct else len(in_window)
                alerts.append(Alert(
                    rule.id, rule.title, rule.level, rule.mitre,
                    burst[0]["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                    burst[-1]["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                    max(size, total), dict(zip(group_by, key)), [_describe(x) for x in burst[:10]],
                ))
                fired_until = e["timestamp"] + window  # suppress duplicates for one window
    return alerts


def run_all(rules: list[Rule], events: list[dict]) -> list[Alert]:
    alerts = [a for rule in rules for a in run_rule(rule, events)]
    return sorted(alerts, key=lambda a: (-LEVELS.index(a.level), a.first_seen))
