# Authentication Log Triage Report

- **Log file:** `samples/sample_auth.log`
- **Generated:** 2026-10-23 20:48
- **Events parsed:** 36 (5 accepted, 31 failed/invalid)
- **Findings:** 6

## Findings

### 1. Successful login from 203.0.113.7 after 12 failures — possible compromise

- **Severity:** CRITICAL
- **MITRE ATT&CK:** T1078 — Valid Accounts
- **Details:** User 'root' logged in successfully from 203.0.113.7, which had 12 failed attempts in the previous 60 minutes. Treat as a potential account compromise until verified.

<details>
<summary>Indicators</summary>

```json
{
  "source_ip": "203.0.113.7",
  "user": "root",
  "login_time": "2026-10-23T14:09:22",
  "prior_failures": 12,
  "targeted_users": [
    "admin",
    "root",
    "test",
    "ubuntu"
  ]
}
```
</details>

### 2. Possible brute-force attack from 203.0.113.7

- **Severity:** HIGH
- **MITRE ATT&CK:** T1110 — Brute Force
- **Details:** 12 failed login attempts from 203.0.113.7 within 10 minutes, targeting 4 username(s): admin, root, test, ubuntu.

<details>
<summary>Indicators</summary>

```json
{
  "source_ip": "203.0.113.7",
  "failed_attempts": 12,
  "window_minutes": 10,
  "targeted_users": [
    "admin",
    "root",
    "test",
    "ubuntu"
  ],
  "first_seen": "2026-10-23T14:02:10",
  "last_seen": "2026-10-23T14:07:51"
}
```
</details>

### 3. Possible brute-force attack from 203.0.113.44

- **Severity:** HIGH
- **MITRE ATT&CK:** T1110 — Brute Force
- **Details:** 14 failed login attempts from 203.0.113.44 within 10 minutes, targeting 7 username(s): guest, mysql, nagios, oracle, postgres.

<details>
<summary>Indicators</summary>

```json
{
  "source_ip": "203.0.113.44",
  "failed_attempts": 14,
  "window_minutes": 10,
  "targeted_users": [
    "guest",
    "mysql",
    "nagios",
    "oracle",
    "postgres",
    "test",
    "zabbix"
  ],
  "first_seen": "2026-10-23T16:20:00",
  "last_seen": "2026-10-23T16:24:32"
}
```
</details>

### 4. Possible password spraying against user 'jdoe'

- **Severity:** HIGH
- **MITRE ATT&CK:** T1110.003 — Brute Force: Password Spraying
- **Details:** User 'jdoe' saw failed logins from 5 distinct IPs within 60 minutes — a classic spray pattern that evades per-IP rate limits.

<details>
<summary>Indicators</summary>

```json
{
  "targeted_user": "jdoe",
  "source_ips": [
    "203.0.113.21",
    "203.0.113.22",
    "203.0.113.23",
    "203.0.113.24",
    "203.0.113.25"
  ],
  "failed_attempts": 5,
  "first_seen": "2026-10-23T15:10:00",
  "last_seen": "2026-10-23T15:46:00"
}
```
</details>

### 5. Username enumeration from 203.0.113.44

- **Severity:** MEDIUM
- **MITRE ATT&CK:** T1590 — Gather Victim Network Information
- **Details:** 7 attempts against non-existent usernames from 203.0.113.44 (guest, mysql, nagios, oracle, postgres). The attacker is mapping valid accounts for a later brute-force run.

<details>
<summary>Indicators</summary>

```json
{
  "source_ip": "203.0.113.44",
  "probed_usernames": [
    "guest",
    "mysql",
    "nagios",
    "oracle",
    "postgres",
    "test",
    "zabbix"
  ],
  "attempts": 7
}
```
</details>

### 6. Off-hours login: 'uman' from 198.51.100.99 at 03:12

- **Severity:** MEDIUM
- **MITRE ATT&CK:** T1078 — Valid Accounts
- **Details:** Successful login outside expected hours (00:00-05:00). Verify with the user whether this was legitimate.

<details>
<summary>Indicators</summary>

```json
{
  "user": "uman",
  "source_ip": "198.51.100.99",
  "login_time": "2026-10-23T03:12:44"
}
```
</details>

## Recommended next steps

1. Block or rate-limit the flagged source IPs at the firewall.
2. Force a password reset for any account with a successful login after failures.
3. Confirm off-hours logins directly with the affected users.
4. Review whether SSH password auth can be disabled in favor of key-only auth.
