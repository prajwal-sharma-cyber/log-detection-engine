# Writing detection rules

Each rule is one YAML file in `rules/`. The engine loads every `.yml` / `.yaml` file in that folder.

## Required fields

| Field | Meaning |
|---|---|
| `id` | Unique identifier, e.g. `LDE-010` |
| `title` | Short name shown in reports |
| `level` | `informational`, `low`, `medium`, `high` or `critical` |
| `match` | Field conditions. **All** must be true (logical AND) |

## Optional fields

| Field | Meaning |
|---|---|
| `mitre` | List of ATT&CK technique IDs, e.g. `[T1110.001]` |
| `description` | What the rule detects and how to triage it |
| `threshold` | Only alert when enough matching events occur together |
| `followed_by` | Only alert if a second kind of event follows the burst |

## Field modifiers

| Syntax | Matches when |
|---|---|
| `user: root` | value equals `root` |
| `user|in: [root, admin]` | value is one of the list |
| `command|contains: /tmp/` | value contains the text (case-insensitive) |
| `command|startswith: /usr/bin` | value starts with the text |
| `command|endswith: .sh` | value ends with the text |
| `command|re: 'curl .*\| *sh'` | regular expression matches |
| `method|not: publickey` | value is anything except this |

## Thresholds

```yaml
threshold:
  count: 5          # how many events are needed
  within: 5m        # time window: 30s, 5m, 2h
  group_by: [src_ip]  # count separately for each value
  distinct: user    # optional: count different users instead of events
```

After a threshold alert fires for a group, repeats inside the same window are suppressed, so one attack produces one alert.

## Correlation

```yaml
followed_by:
  event: ssh_success
```

The follow-up event must share the same `group_by` values and occur within the window after the burst.

## Event types produced by the auth.log parser

| `event` | Extra fields |
|---|---|
| `ssh_failed` | `user`, `src_ip`, `src_port`, `method` |
| `ssh_success` | `user`, `src_ip`, `src_port`, `method` |
| `ssh_invalid_user` | `user`, `src_ip` |
| `sudo_command` | `user`, `tty`, `pwd`, `target_user`, `command` |
| `sudo_auth_failure` | `user` |
| `user_created` | `new_user`, `uid` |
| `group_member_added` | `new_user`, `group` |
| `su_session` | `user`, `target_user` |
| `other` | anything not recognised (still has `message`) |

## Testing a new rule

1. Add a line to `src/generate_auth_log.py` that produces the behaviour.
2. Add an assertion in `tests/test_engine.py` that the rule fires.
3. Add one that it does **not** fire on normal activity - false positives matter as much as detections.
