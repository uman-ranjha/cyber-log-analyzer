#!/usr/bin/env python3
"""
generate_sample_log.py
======================
Builds a synthetic auth log with KNOWN attack ground truth so the
analyzer can be demoed and tested end-to-end.

Everything is clearly fake: all attacker IPs come from the TEST-NET
documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
reserved by RFC 5737, and usernames are generic.

Ground truth baked into the output:
  1. 203.0.113.7  - brute force: 12 failed attempts vs root/admin in ~6 min
  2. 203.0.113.7  - then SUCCEEDS as root  -> success-after-failure (critical)
  3. jdoe         - password spray from 5 distinct IPs within 40 minutes
  4. 203.0.113.44 - username enumeration: invalid-user probes (oracle/test/guest/...)
  5. uman          - off-hours accepted login at 03:12 from 198.51.100.99
  plus normal background traffic (uman's 09:xx logins from 198.51.100.23).

Deterministic: same output every run (fixed event list, no randomness).
"""

from datetime import datetime, timedelta
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_auth.log")
DAY = datetime(2026, 10, 23)

HOST = "lab-server"
SSHD_PID = 4821


def line(ts: datetime, msg: str) -> str:
    # Classic syslog stamp: month, space-padded day, zero-padded time.
    stamp = f"{ts.strftime('%b')} {ts.day:2d} {ts.strftime('%H:%M:%S')}"
    # sshd pid drifts a little for realism
    pid = SSHD_PID + (ts.minute % 7)
    return f"{stamp} {HOST} sshd[{pid}]: {msg}"


def failed(ts, user, ip, port, invalid=False):
    who = f"invalid user {user}" if invalid else user
    return line(ts, f"Failed password for {who} from {ip} port {port} ssh2")


def accepted(ts, user, ip, port, method="password"):
    return line(ts, f"Accepted {method} for {user} from {ip} port {port} ssh2")


def invalid_user(ts, user, ip, port):
    return line(ts, f"Invalid user {user} from {ip} port {port}")


def build() -> list[str]:
    events: list[str] = []
    t = lambda h, m, s=0: DAY.replace(hour=h, minute=m, second=s)

    # --- normal background traffic: uman's workday logins ------------------
    events.append(accepted(t(9, 2, 14), "uman", "198.51.100.23", 51234))
    events.append(accepted(t(9, 3, 2), "uman", "198.51.100.23", 51235, "publickey"))
    events.append(accepted(t(12, 41, 55), "uman", "198.51.100.23", 53310))
    events.append(line(t(13, 5, 1), "pam_unix(sshd:session): session opened for user uman"))

    # --- 1+2. brute force then success, 203.0.113.7 -------------------------
    brute_start = t(14, 2, 10)
    targets = ["root", "admin", "root", "admin", "root", "ubuntu",
               "root", "admin", "root", "test", "root", "admin"]
    for i, user in enumerate(targets):
        ts = brute_start + timedelta(seconds=i * 31)
        events.append(failed(ts, user, "203.0.113.7", 42000 + i))
    # ...and then it gets in:
    events.append(accepted(brute_start + timedelta(minutes=7, seconds=12),
                           "root", "203.0.113.7", 42013))

    # --- 3. password spray against jdoe from 5 IPs --------------------------
    spray_start = t(15, 10, 0)
    spray_ips = ["203.0.113.21", "203.0.113.22", "203.0.113.23",
                 "203.0.113.24", "203.0.113.25"]
    for i, ip in enumerate(spray_ips):
        ts = spray_start + timedelta(minutes=i * 9)
        events.append(failed(ts, "jdoe", ip, 33000 + i))

    # --- 4. username enumeration, 203.0.113.44 ------------------------------
    enum_start = t(16, 20, 0)
    for i, user in enumerate(["oracle", "test", "guest", "postgres",
                              "mysql", "nagios", "zabbix"]):
        ts = enum_start + timedelta(seconds=i * 45)
        events.append(invalid_user(ts, user, "203.0.113.44", 51000 + i))
        events.append(failed(ts + timedelta(seconds=2), user,
                             "203.0.113.44", 51000 + i, invalid=True))

    # --- 5. off-hours login --------------------------------------------------
    events.append(accepted(t(3, 12, 44), "uman", "198.51.100.99", 60112))

    # --- misc noise (closed connections, disconnects) -----------------------
    events.append(line(t(14, 9, 3),
                       "Connection closed by authenticating user root 203.0.113.7 port 42013 [preauth]"))
    events.append(line(t(18, 0, 12),
                       "Received disconnect from 198.51.100.23 port 53310:11: disconnected by user"))

    events.sort()
    return events


if __name__ == "__main__":
    lines = build()
    with open(OUT, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    print(f"Wrote {len(lines)} synthetic log lines to {OUT}")
