# Log Detection Engine

![tests](https://github.com/prajwal-sharma-cyber/log-detection-engine/actions/workflows/tests.yml/badge.svg) ![python](https://img.shields.io/badge/python-3.10%2B-blue) ![license](https://img.shields.io/badge/license-MIT-green)

A small SIEM-style detection engine written in Python. It parses Linux `auth.log` files, runs **Sigma-style YAML detection rules** against them, and produces MITRE ATT&CK-mapped alerts as JSON and as an HTML report.

![HTML report](docs/images/report.png)

## Why this project

SOC analysts and detection engineers spend their days writing and tuning rules like these. Building the engine yourself shows you understand what a SIEM such as Splunk, Elastic or Wazuh does underneath: parsing, normalising fields, matching, counting inside time windows and correlating one event with the next.

## Features

- **Parser** for sshd, sudo, useradd, usermod and su lines, normalised to common fields (`event`, `user`, `src_ip`, `command`...)
- **YAML rules** with field modifiers: `|contains`, `|startswith`, `|endswith`, `|re`, `|in`, `|not`
- **Thresholds** over sliding time windows, grouped by any field, optionally counting *distinct* values (password spraying)
- **Correlation** with `followed_by` (for example, a brute force followed by a successful login from the same address)
- **9 ready-made rules** mapped to ATT&CK: T1110.001, T1110.003, T1078, T1078.003, T1136.001, T1098, T1548.003, T1059.004
- **Reports**: console summary, JSON for other tools, and a self-contained HTML report
- **Synthetic log generator** with five planted attack scenarios, plus **pytest** tests and GitHub Actions CI
- Exit code 1 when high or critical alerts fire, so it can be used in scripts and pipelines

## Quick start

```bash
git clone https://github.com/prajwal-sharma-cyber/log-detection-engine.git
cd log-detection-engine
pip install -r requirements.txt

python src/generate_auth_log.py                     # creates data/auth.log
python run.py                                       # run all rules
python run.py --html reports/report.html --json reports/alerts.json
python run.py --list-rules
```

Run it on a real Linux machine you own (needs read access to the log):

```bash
sudo python run.py --log /var/log/auth.log --year 2026 --html reports/my-server.html
```

## Sample output

```text
101 events, 9 rules, 14 alerts

[CRITICAL] LDE-003  SSH login succeeded after brute force  src_ip=203.0.113.45      x14  2026-09-22 02:11:01
[HIGH    ] LDE-001  SSH brute force                        src_ip=203.0.113.45      x14  2026-09-22 02:11:01
[HIGH    ] LDE-007  User added to an administrative group                           x1   2026-09-22 02:16:12
[HIGH    ] LDE-008  Suspicious command run with sudo                                x1   2026-09-22 02:18:11
[HIGH    ] LDE-002  SSH password spraying                  src_ip=198.51.100.77     x8   2026-09-22 13:40:01
[HIGH    ] LDE-005  Direct root login over SSH                                      x1   2026-09-23 22:48:00
[MEDIUM  ] LDE-006  New local user account created                                  x1   2026-09-22 02:15:12
[MEDIUM  ] LDE-004  Username enumeration over SSH          src_ip=203.0.113.200     x5   2026-09-23 04:02:00
[MEDIUM  ] LDE-009  Repeated sudo authentication failures  user=intern              x4   2026-09-23 15:30:00
```

The first alerts tell a complete story: brute force, a successful login, a new account added to `sudo`, then a script downloaded to `/tmp` and run as root.

## Writing a rule

```yaml
id: LDE-002
title: SSH password spraying
level: high
mitre: [T1110.003]
description: One source failing against four or more different accounts.
match:
  event: ssh_failed
threshold:
  count: 4
  within: 10m
  group_by: [src_ip]
  distinct: user
```

See [docs/writing-rules.md](docs/writing-rules.md) for every option.

## How it works

```text
auth.log ──> parsers.py ──> normalised events ──> engine.py ──> alerts ──> report.py ──> console / JSON / HTML
                                                      ^
                                               rules/*.yml
```

## Project structure

```text
log-detection-engine/
├── data/auth.log                 synthetic log (regenerate any time)
├── docs/writing-rules.md         rule syntax reference
├── rules/                        one YAML file per detection
├── src/
│   ├── detection_engine/
│   │   ├── parsers.py            raw lines -> events
│   │   ├── engine.py             matching, thresholds, correlation
│   │   ├── report.py             JSON + HTML output
│   │   └── __main__.py           command line
│   └── generate_auth_log.py      synthetic data with planted attacks
├── tests/test_engine.py
├── run.py                        beginner-friendly launcher
└── pyproject.toml                installs a `detect` command: pip install -e .
```

## Ideas to extend it

- Add a parser for Windows Security events exported as JSON (4624, 4625, 4720, 4732)
- Convert real rules from the public Sigma repository into this format
- Send critical alerts to a Discord or Slack webhook
- Add GeoIP enrichment for source addresses

## Disclaimer

All logs are synthetic and use RFC 5737 documentation IP addresses. Only analyse logs from systems you own or are authorised to monitor.
