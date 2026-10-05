from datetime import datetime, timedelta
from pathlib import Path

import pytest

from detection_engine.engine import Rule, field_matches, load_rules, parse_duration, run_all, run_rule
from detection_engine.parsers import load_events, parse_auth_log

ROOT = Path(__file__).resolve().parent.parent
T0 = datetime(2026, 9, 22, 2, 0)


def ev(sec, event, **fields):
    return {"timestamp": T0 + timedelta(seconds=sec), "event": event, **fields}


def test_parser_extracts_fields(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(
        "Sep 22 02:11:01 host sshd[1]: Failed password for invalid user oracle from 203.0.113.5 port 5555 ssh2\n"
        "Sep 22 02:12:00 host sshd[2]: Accepted publickey for priya from 192.0.2.21 port 6000 ssh2\n"
        "Sep 22 02:13:00 host sudo[3]:    priya : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/usr/bin/id\n"
    )
    events = list(parse_auth_log(log, 2026))
    assert events[0]["event"] == "ssh_failed" and events[0]["user"] == "oracle" and events[0]["src_ip"] == "203.0.113.5"
    assert events[1]["event"] == "ssh_success" and events[1]["method"] == "publickey"
    assert events[2]["event"] == "sudo_command" and events[2]["command"] == "/usr/bin/id"


def test_modifiers():
    e = {"user": "Admin", "cmd": "wget http://x/y -O /tmp/a"}
    assert field_matches(e, "user|in", ["Admin", "root"])
    assert field_matches(e, "cmd|contains", "/TMP/")
    assert field_matches(e, "cmd|re", r"wget .* -O /tmp/")
    assert field_matches(e, "user|not", "root")
    with pytest.raises(ValueError):
        field_matches(e, "user|bogus", "x")


def test_threshold_and_window():
    rule = Rule("T", "t", "high", {"event": "ssh_failed"}, threshold={"count": 3, "within": "1m", "group_by": ["src_ip"]})
    slow = [ev(i * 120, "ssh_failed", src_ip="a") for i in range(5)]
    fast = [ev(i * 5, "ssh_failed", src_ip="b") for i in range(5)]
    alerts = run_rule(rule, slow + fast)
    assert len(alerts) == 1 and alerts[0].group == {"src_ip": "b"} and alerts[0].count == 5


def test_distinct_counting():
    rule = Rule("T", "t", "high", {"event": "ssh_failed"},
                threshold={"count": 3, "within": "10m", "group_by": ["src_ip"], "distinct": "user"})
    same_user = [ev(i, "ssh_failed", src_ip="a", user="bob") for i in range(6)]
    many_users = [ev(i, "ssh_failed", src_ip="b", user=u) for i, u in enumerate("xyz")]
    alerts = run_rule(rule, same_user + many_users)
    assert [a.group["src_ip"] for a in alerts] == ["b"]


def test_followed_by_requires_success():
    rule = Rule("T", "t", "critical", {"event": "ssh_failed"},
                threshold={"count": 3, "within": "5m", "group_by": ["src_ip"]},
                followed_by={"event": "ssh_success"})
    fails = [ev(i, "ssh_failed", src_ip="a") for i in range(3)]
    assert run_rule(rule, fails) == []
    assert len(run_rule(rule, fails + [ev(10, "ssh_success", src_ip="a")])) == 1
    assert run_rule(rule, fails + [ev(10, "ssh_success", src_ip="other")]) == []


def test_bad_level_rejected():
    with pytest.raises(ValueError):
        Rule("X", "x", "urgent", {})


def test_duration():
    assert parse_duration("90s") == timedelta(seconds=90) and parse_duration("2h") == timedelta(hours=2)


def test_every_planted_scenario_is_detected(tmp_path):
    import subprocess, sys
    log = tmp_path / "auth.log"
    subprocess.run([sys.executable, str(ROOT / "src" / "generate_auth_log.py"), "--out", str(log)], check=True)
    alerts = run_all(load_rules(ROOT / "rules"), load_events(log, 2026))
    fired = {a.rule_id for a in alerts}
    assert {"LDE-001", "LDE-002", "LDE-003", "LDE-004", "LDE-005", "LDE-006", "LDE-007", "LDE-008", "LDE-009"} <= fired
    # the admins' normal key logins and routine sudo must not raise high alerts
    assert not any(a.level in {"high", "critical"} and "192.0.2.2" in str(a.group) for a in alerts)
