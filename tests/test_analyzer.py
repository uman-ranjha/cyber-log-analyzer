#!/usr/bin/env python3
"""Unit + end-to-end tests for log_analyzer. Run: python -m unittest discover tests"""

import os
import sys
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from log_analyzer import (  # noqa: E402
    AuthEvent,
    analyze,
    detect_brute_force,
    detect_off_hours_login,
    detect_password_spray,
    detect_success_after_failure,
    detect_username_enumeration,
    parse_line,
    parse_log,
)


def ev(ts, kind, user, ip):
    return AuthEvent(timestamp=ts, kind=kind, user=user, ip=ip, raw="")


BASE = datetime(2026, 10, 23, 14, 0, 0)


class TestParsing(unittest.TestCase):
    def test_failed_password(self):
        line = ("Oct 23 14:02:10 lab-server sshd[4821]: Failed password for "
                "root from 203.0.113.7 port 42000 ssh2")
        e = parse_line(line, 2026)
        self.assertIsNotNone(e)
        self.assertEqual((e.kind, e.user, e.ip),
                         ("failed", "root", "203.0.113.7"))
        self.assertEqual(e.timestamp, BASE.replace(hour=14, minute=2, second=10))

    def test_failed_invalid_user(self):
        line = ("Oct 23 14:02:10 lab-server sshd[4821]: Failed password for "
                "invalid user admin from 203.0.113.7 port 42000 ssh2")
        e = parse_line(line, 2026)
        self.assertEqual((e.kind, e.user), ("failed", "admin"))

    def test_accepted(self):
        line = ("Oct 23 09:02:14 lab-server sshd[4821]: Accepted password for "
                "uman from 198.51.100.23 port 51234 ssh2")
        e = parse_line(line, 2026)
        self.assertEqual((e.kind, e.user), ("accepted", "uman"))

    def test_invalid_user_line(self):
        line = ("Oct 23 16:20:00 lab-server sshd[4821]: Invalid user oracle "
                "from 203.0.113.44 port 51000")
        e = parse_line(line, 2026)
        self.assertEqual((e.kind, e.user), ("invalid_user", "oracle"))

    def test_non_auth_line_ignored(self):
        line = ("Oct 23 13:05:01 lab-server sshd[4821]: "
                "pam_unix(sshd:session): session opened for user uman")
        self.assertIsNone(parse_line(line, 2026))

    def test_garbage_ignored(self):
        self.assertIsNone(parse_line("not a log line", 2026))


class TestDetectors(unittest.TestCase):
    def test_brute_force_detected(self):
        events = [ev(BASE + timedelta(seconds=i * 30), "failed", "root",
                     "203.0.113.7") for i in range(6)]
        findings = detect_brute_force(events, threshold=5, window_minutes=10)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].technique, "T1110")
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[0].indicators["source_ip"], "203.0.113.7")

    def test_brute_force_not_triggered_below_threshold(self):
        events = [ev(BASE + timedelta(seconds=i * 30), "failed", "root",
                     "203.0.113.7") for i in range(4)]
        self.assertEqual(detect_brute_force(events, threshold=5), [])

    def test_brute_force_window_resets(self):
        # 5 failures spread over an hour: never 5 inside 10 minutes
        events = [ev(BASE + timedelta(minutes=i * 15), "failed", "root",
                     "203.0.113.7") for i in range(5)]
        self.assertEqual(detect_brute_force(events, threshold=5,
                                            window_minutes=10), [])

    def test_password_spray_detected(self):
        events = [ev(BASE + timedelta(minutes=i * 9), "failed", "jdoe",
                     f"203.0.113.{20 + i}") for i in range(5)]
        findings = detect_password_spray(events, min_ips=3)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].technique, "T1110.003")

    def test_password_spray_single_ip_not_flagged(self):
        events = [ev(BASE + timedelta(minutes=i), "failed", "jdoe",
                     "203.0.113.20") for i in range(8)]
        self.assertEqual(detect_password_spray(events, min_ips=3), [])

    def test_success_after_failure_critical(self):
        events = [ev(BASE + timedelta(minutes=i), "failed", "root",
                     "203.0.113.7") for i in range(6)]
        events.append(ev(BASE + timedelta(minutes=20), "accepted", "root",
                         "203.0.113.7"))
        findings = detect_success_after_failure(events)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "critical")
        self.assertEqual(findings[0].technique, "T1078")

    def test_clean_login_not_flagged(self):
        events = [ev(BASE, "accepted", "uman", "198.51.100.23")]
        self.assertEqual(detect_success_after_failure(events), [])

    def test_username_enumeration(self):
        events = [ev(BASE + timedelta(seconds=i * 45), "invalid_user",
                     f"user{i}", "203.0.113.44") for i in range(6)]
        findings = detect_username_enumeration(events, threshold=5)
        self.assertEqual(len(findings), 1)
        self.assertEqual(len(findings[0].indicators["probed_usernames"]), 6)

    def test_off_hours_login(self):
        events = [ev(BASE.replace(hour=3, minute=12), "accepted", "uman",
                     "198.51.100.99")]
        findings = detect_off_hours_login(events)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "medium")

    def test_daytime_login_not_flagged(self):
        events = [ev(BASE.replace(hour=9, minute=2), "accepted", "uman",
                     "198.51.100.23")]
        self.assertEqual(detect_off_hours_login(events), [])

    def test_severity_ordering(self):
        events = [ev(BASE + timedelta(seconds=i * 30), "failed", "root",
                     "203.0.113.7") for i in range(6)]
        events.append(ev(BASE + timedelta(minutes=30), "accepted", "root",
                         "203.0.113.7"))
        findings = analyze(events)
        severities = [f.severity for f in findings]
        self.assertEqual(severities, sorted(
            severities, key={"critical": 0, "high": 1,
                             "medium": 2, "low": 3}.get))


class TestSampleLogEndToEnd(unittest.TestCase):
    """The synthetic sample log must produce exactly the 5 planted attacks."""

    @classmethod
    def setUpClass(cls):
        here = os.path.dirname(os.path.abspath(__file__))
        cls.log_path = os.path.join(here, "..", "samples", "sample_auth.log")

    def test_ground_truth(self):
        events = parse_log(self.log_path, year=2026)
        self.assertGreater(len(events), 20)
        findings = analyze(events)
        techniques = {f.technique for f in findings}
        # brute force, password spray, success-after-failure,
        # username enumeration, off-hours login
        self.assertIn("T1110", techniques)
        self.assertIn("T1110.003", techniques)
        self.assertIn("T1078", techniques)
        self.assertIn("T1590", techniques)
        critical = [f for f in findings if f.severity == "critical"]
        self.assertTrue(any("203.0.113.7" in f.title for f in critical))


if __name__ == "__main__":
    unittest.main()
