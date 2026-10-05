"""
Log parsers. Each parser turns raw log lines into normalised event dictionaries
with common field names, so detection rules do not care where the log came from.

Supported:
  * Linux auth.log / secure (sshd, sudo, useradd, su)
  * JSON lines (one JSON object per line), e.g. exported Windows events
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Iterator

SYSLOG_PREFIX = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s(?P<host>\S+)\s"
    r"(?P<process>[\w\-/.]+)(?:\[(?P<pid>\d+)\])?:\s(?P<message>.*)$"
)

AUTH_PATTERNS = [
    ("ssh_failed", re.compile(
        r"Failed (?P<method>password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>[\d.:a-fA-F]+) port (?P<src_port>\d+)")),
    ("ssh_success", re.compile(
        r"Accepted (?P<method>password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<src_ip>[\d.:a-fA-F]+) port (?P<src_port>\d+)")),
    ("ssh_invalid_user", re.compile(r"Invalid user (?P<user>\S+) from (?P<src_ip>[\d.:a-fA-F]+)")),
    ("sudo_command", re.compile(
        r"^\s*(?P<user>\S+) : (?:\d+ incorrect password attempts ; )?TTY=(?P<tty>\S+) ; PWD=(?P<pwd>\S+) ; USER=(?P<target_user>\S+) ; COMMAND=(?P<command>.+)$")),
    ("sudo_auth_failure", re.compile(r"pam_unix\(sudo:auth\): authentication failure;.*ruser=(?P<user>\S*)")),
    ("user_created", re.compile(r"new user: name=(?P<new_user>[^,]+), UID=(?P<uid>\d+)")),
    ("group_member_added", re.compile(r"add '(?P<new_user>[^']+)' to group '(?P<group>[^']+)'")),
    ("su_session", re.compile(r"pam_unix\(su(?:-l)?:session\): session opened for user (?P<target_user>\S+) by (?P<user>\S*)")),
]


def parse_auth_log(path: Path, year: int | None = None) -> Iterator[dict]:
    """Parse a Linux auth.log. Syslog lines have no year, so one is supplied."""
    year = year or datetime.now().year
    with path.open(encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, start=1):
            match = SYSLOG_PREFIX.match(line.rstrip("\n"))
            if not match:
                continue
            stamp = datetime.strptime(f"{year} {match['month']} {match['day']} {match['time']}", "%Y %b %d %H:%M:%S")
            base = {
                "timestamp": stamp,
                "host": match["host"],
                "process": match["process"],
                "message": match["message"],
                "source_file": path.name,
                "line": number,
                "event": "other",
            }
            for event_name, pattern in AUTH_PATTERNS:
                found = pattern.search(match["message"])
                if found:
                    base["event"] = event_name
                    base.update({k: v for k, v in found.groupdict().items() if v is not None})
                    break
            yield base


def parse_json_lines(path: Path) -> Iterator[dict]:
    """Parse JSON lines. A 'timestamp' field in ISO format is converted to datetime."""
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            event = json.loads(line)
            if "timestamp" in event:
                event["timestamp"] = datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00")).replace(tzinfo=None)
            event.setdefault("source_file", path.name)
            event.setdefault("line", number)
            yield event


def load_events(path: Path, year: int | None = None) -> list[dict]:
    if path.suffix in {".json", ".jsonl", ".ndjson"}:
        events = list(parse_json_lines(path))
    else:
        events = list(parse_auth_log(path, year))
    return sorted(events, key=lambda e: e.get("timestamp") or datetime.min)
