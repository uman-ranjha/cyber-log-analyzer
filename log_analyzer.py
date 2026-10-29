#!/usr/bin/env python3
"""
cyber-log-analyzer
==================
A small security tool that reads SSH authentication logs and flags
suspicious login activity: brute-force attacks, password spraying,
successful logins that follow failures, username enumeration, and
off-hours access.

Detections are mapped to MITRE ATT&CK techniques so the output reads
like a real analyst triage report.

Usage:
    python log_analyzer.py --log /var/log/auth.log --report report.md
    python log_analyzer.py --log samples/sample_auth.log --json findings.json

Zero third-party dependencies: standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# Event model
# ---------------------------------------------------------------------------

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

_TS_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)
_FAILED_RE = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user |)(?P<user>\S+)"
    r" from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
_INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
_ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+)"
    r" from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


@dataclass
class AuthEvent:
    """One parsed authentication event from an auth log."""

    timestamp: datetime
    kind: str            # "failed" | "accepted" | "invalid_user"
    user: str
    ip: str
    raw: str = ""


def parse_line(line: str, year: int) -> AuthEvent | None:
    """Parse a single syslog auth line. Returns None if not an auth event."""
    ts_match = _TS_RE.match(line)
    if not ts_match:
        return None
    month = MONTHS.get(ts_match.group("mon"))
    if month is None:
        return None
    day = int(ts_match.group("day"))
    hour, minute, second = (int(p) for p in ts_match.group("time").split(":"))
    timestamp = datetime(year, month, day, hour, minute, second)

    for pattern, kind in (
        (_ACCEPTED_RE, "accepted"),
        (_FAILED_RE, "failed"),
        (_INVALID_USER_RE, "invalid_user"),
    ):
        match = pattern.search(line)
        if match:
            return AuthEvent(
                timestamp=timestamp,
                kind=kind,
                user=match.group("user"),
                ip=match.group("ip"),
                raw=line.rstrip("\n"),
            )
    return None


def parse_log(path: str, year: int | None = None) -> list[AuthEvent]:
    """Parse a whole auth log file into a time-sorted list of AuthEvents."""
    year = year or datetime.now().year
    events: list[AuthEvent] = []
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            event = parse_line(line, year)
            if event is not None:
                events.append(event)
    events.sort(key=lambda e: e.timestamp)
    return events


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """One suspicious pattern detected in the log."""

    title: str
    severity: str            # "critical" | "high" | "medium" | "low"
    technique: str            # MITRE ATT&CK technique ID
    technique_name: str
    description: str
    indicators: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "mitre_attack": {
                "technique_id": self.technique,
                "technique_name": self.technique_name,
            },
            "description": self.description,
            "indicators": self.indicators,
        }


def _windowed(events: list[AuthEvent], window: timedelta) -> list[list[AuthEvent]]:
    """Group consecutive events where each is within `window` of the first."""
    groups: list[list[AuthEvent]] = []
    current: list[AuthEvent] = []
    for event in events:
        if current and event.timestamp - current[0].timestamp > window:
            groups.append(current)
            current = []
        current.append(event)
    if current:
        groups.append(current)
    return groups


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------

def detect_brute_force(
    events: list[AuthEvent],
    threshold: int = 5,
    window_minutes: int = 10,
) -> list[Finding]:
    """
    T1110 - Brute Force: many failed logins from one IP inside a short window.
    """
    window = timedelta(minutes=window_minutes)
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.kind in ("failed", "invalid_user"):
            by_ip[event.ip].append(event)

    findings: list[Finding] = []
    for ip, ip_events in by_ip.items():
        for group in _windowed(ip_events, window):
            if len(group) >= threshold:
                users = sorted({e.user for e in group})
                findings.append(
                    Finding(
                        title=f"Possible brute-force attack from {ip}",
                        severity="high",
                        technique="T1110",
                        technique_name="Brute Force",
                        description=(
                            f"{len(group)} failed login attempts from {ip} "
                            f"within {window_minutes} minutes, targeting "
                            f"{len(users)} username(s): {', '.join(users[:5])}."
                        ),
                        indicators={
                            "source_ip": ip,
                            "failed_attempts": len(group),
                            "window_minutes": window_minutes,
                            "targeted_users": users,
                            "first_seen": group[0].timestamp.isoformat(),
                            "last_seen": group[-1].timestamp.isoformat(),
                        },
                    )
                )
                break  # one finding per attacking IP is enough for triage
    return findings


def detect_password_spray(
    events: list[AuthEvent],
    min_ips: int = 3,
    window_minutes: int = 60,
) -> list[Finding]:
    """
    T1110.003 - Password Spraying: one username tried from several source IPs.
    (Attackers distribute attempts to dodge per-IP lockouts.)
    """
    window = timedelta(minutes=window_minutes)
    by_user: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.kind == "failed":
            by_user[event.user].append(event)

    findings: list[Finding] = []
    for user, user_events in by_user.items():
        for group in _windowed(user_events, window):
            ips = sorted({e.ip for e in group})
            if len(ips) >= min_ips:
                findings.append(
                    Finding(
                        title=f"Possible password spraying against user '{user}'",
                        severity="high",
                        technique="T1110.003",
                        technique_name="Brute Force: Password Spraying",
                        description=(
                            f"User '{user}' saw failed logins from "
                            f"{len(ips)} distinct IPs within {window_minutes} "
                            f"minutes — a classic spray pattern that evades "
                            f"per-IP rate limits."
                        ),
                        indicators={
                            "targeted_user": user,
                            "source_ips": ips,
                            "failed_attempts": len(group),
                            "first_seen": group[0].timestamp.isoformat(),
                            "last_seen": group[-1].timestamp.isoformat(),
                        },
                    )
                )
                break
    return findings


def detect_success_after_failure(
    events: list[AuthEvent],
    failure_threshold: int = 5,
    window_minutes: int = 60,
) -> list[Finding]:
    """
    T1078 - Valid Accounts: a successful login from an IP that was failing
    just before. Either the attacker guessed right, or a legitimate user
    fat-fingered their password — both deserve a look.
    """
    window = timedelta(minutes=window_minutes)
    failures: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.kind in ("failed", "invalid_user"):
            failures[event.ip].append(event)

    findings: list[Finding] = []
    for event in events:
        if event.kind != "accepted":
            continue
        recent = [
            f for f in failures[event.ip]
            if timedelta(0) < event.timestamp - f.timestamp <= window
        ]
        if len(recent) >= failure_threshold:
            users = sorted({f.user for f in recent})
            findings.append(
                Finding(
                    title=(
                        f"Successful login from {event.ip} after "
                        f"{len(recent)} failures — possible compromise"
                    ),
                    severity="critical",
                    technique="T1078",
                    technique_name="Valid Accounts",
                    description=(
                        f"User '{event.user}' logged in successfully from "
                        f"{event.ip}, which had {len(recent)} failed attempts "
                        f"in the previous {window_minutes} minutes. Treat as "
                        f"a potential account compromise until verified."
                    ),
                    indicators={
                        "source_ip": event.ip,
                        "user": event.user,
                        "login_time": event.timestamp.isoformat(),
                        "prior_failures": len(recent),
                        "targeted_users": users,
                    },
                )
            )
    return findings


def detect_username_enumeration(
    events: list[AuthEvent],
    threshold: int = 5,
) -> list[Finding]:
    """
    T1083-adjacent recon: repeated 'invalid user' attempts show an attacker
    probing which usernames exist on the box.
    """
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.kind == "invalid_user":
            by_ip[event.ip].append(event)

    findings: list[Finding] = []
    for ip, ip_events in by_ip.items():
        if len(ip_events) >= threshold:
            users = sorted({e.user for e in ip_events})
            findings.append(
                Finding(
                    title=f"Username enumeration from {ip}",
                    severity="medium",
                    technique="T1590",
                    technique_name="Gather Victim Network Information",
                    description=(
                        f"{len(ip_events)} attempts against non-existent "
                        f"usernames from {ip} ({', '.join(users[:5])}). The "
                        f"attacker is mapping valid accounts for a later "
                        f"brute-force run."
                    ),
                    indicators={
                        "source_ip": ip,
                        "probed_usernames": users,
                        "attempts": len(ip_events),
                    },
                )
            )
    return findings


def detect_off_hours_login(
    events: list[AuthEvent],
    start_hour: int = 0,
    end_hour: int = 5,
) -> list[Finding]:
    """
    T1078-adjacent: successful logins during hours nobody should be working.
    Common in compromised-account and insider-threat cases.
    """
    findings: list[Finding] = []
    for event in events:
        if event.kind == "accepted" and start_hour <= event.timestamp.hour < end_hour:
            findings.append(
                Finding(
                    title=(
                        f"Off-hours login: '{event.user}' from {event.ip} "
                        f"at {event.timestamp.strftime('%H:%M')}"
                    ),
                    severity="medium",
                    technique="T1078",
                    technique_name="Valid Accounts",
                    description=(
                        f"Successful login outside expected hours "
                        f"({start_hour:02d}:00-{end_hour:02d}:00). Verify with "
                        f"the user whether this was legitimate."
                    ),
                    indicators={
                        "user": event.user,
                        "source_ip": event.ip,
                        "login_time": event.timestamp.isoformat(),
                    },
                )
            )
    return findings


def analyze(events: list[AuthEvent], **options) -> list[Finding]:
    """Run every detector and return findings ordered by severity."""
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings: list[Finding] = []
    findings += detect_brute_force(
        events,
        threshold=options.get("threshold", 5),
        window_minutes=options.get("window", 10),
    )
    findings += detect_password_spray(events)
    findings += detect_success_after_failure(events)
    findings += detect_username_enumeration(events)
    findings += detect_off_hours_login(events)
    findings.sort(key=lambda f: severity_rank.get(f.severity, 4))
    return findings


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

SEVERITY_BADGE = {
    "critical": "[CRITICAL]",
    "high": "[HIGH]    ",
    "medium": "[MEDIUM]  ",
    "low": "[LOW]     ",
}


def console_summary(events: list[AuthEvent], findings: list[Finding]) -> str:
    accepted = sum(1 for e in events if e.kind == "accepted")
    failed = sum(1 for e in events if e.kind in ("failed", "invalid_user"))
    ips = len({e.ip for e in events})
    lines = [
        "=== Log analysis summary ===",
        f"Events parsed : {len(events)} "
        f"({accepted} accepted, {failed} failed/invalid)",
        f"Unique IPs    : {ips}",
        f"Findings      : {len(findings)}",
        "",
    ]
    for finding in findings:
        badge = SEVERITY_BADGE.get(finding.severity, "[?]       ")
        lines.append(f"{badge} {finding.title}  ({finding.technique})")
    return "\n".join(lines)


def markdown_report(
    events: list[AuthEvent],
    findings: list[Finding],
    log_path: str,
) -> str:
    accepted = sum(1 for e in events if e.kind == "accepted")
    failed = sum(1 for e in events if e.kind in ("failed", "invalid_user"))
    when = datetime.now().strftime("%Y-%m-%d %H:%M")
    parts = [
        f"# Authentication Log Triage Report",
        f"",
        f"- **Log file:** `{log_path}`",
        f"- **Generated:** {when}",
        f"- **Events parsed:** {len(events)} "
        f"({accepted} accepted, {failed} failed/invalid)",
        f"- **Findings:** {len(findings)}",
        f"",
        f"## Findings",
        f"",
    ]
    if not findings:
        parts.append("_No suspicious activity detected._\n")
    for i, finding in enumerate(findings, 1):
        parts += [
            f"### {i}. {finding.title}",
            f"",
            f"- **Severity:** {finding.severity.upper()}",
            f"- **MITRE ATT&CK:** {finding.technique} — "
            f"{finding.technique_name}",
            f"- **Details:** {finding.description}",
            f"",
            f"<details>",
            f"<summary>Indicators</summary>",
            f"",
            f"```json",
            json.dumps(finding.indicators, indent=2),
            f"```",
            f"</details>",
            f"",
        ]
    parts += [
        "## Recommended next steps",
        "",
        "1. Block or rate-limit the flagged source IPs at the firewall.",
        "2. Force a password reset for any account with a successful "
        "login after failures.",
        "3. Confirm off-hours logins directly with the affected users.",
        "4. Review whether SSH password auth can be disabled in favor of "
        "key-only auth.",
        "",
    ]
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze SSH auth logs for brute force, password "
                    "spraying, and other suspicious login activity."
    )
    parser.add_argument("--log", required=True, help="Path to the auth log file")
    parser.add_argument("--report", help="Write a Markdown triage report here")
    parser.add_argument("--json", help="Write machine-readable findings here")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Failed attempts that trigger brute force (default: 5)")
    parser.add_argument("--window", type=int, default=10,
                        help="Brute-force window in minutes (default: 10)")
    parser.add_argument("--year", type=int, default=None,
                        help="Log year (syslog has no year; default: current)")
    parser.add_argument("--quiet", action="store_true",
                        help="Only print findings, skip the summary header")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        events = parse_log(args.log, year=args.year)
    except FileNotFoundError:
        print(f"error: log file not found: {args.log}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: could not read {args.log}: {exc}", file=sys.stderr)
        return 1

    findings = analyze(events, threshold=args.threshold, window=args.window)

    if not args.quiet:
        print(console_summary(events, findings))

    if args.report:
        with open(args.report, "w", encoding="utf-8") as handle:
            handle.write(markdown_report(events, findings, args.log))
        print(f"\nMarkdown report written to {args.report}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump([f.to_dict() for f in findings], handle, indent=2)
        print(f"JSON findings written to {args.json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
