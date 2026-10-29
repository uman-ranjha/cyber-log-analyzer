# SSH Log Analyzer

I built this to practice the kind of log triage you do on a SOC team.
Instead of just reading about brute force and password spraying, I wanted
a tool that could take a real SSH auth log and tell me what looks wrong
in it, and why.

It reads SSH authentication logs and flags five patterns, then ranks
them by severity. The output is a short console summary, a Markdown
report, and a JSON file if you want to feed the findings somewhere else.

## What it flags

| Finding | What it means | MITRE ATT&CK | Severity |
|---|---|---|---|
| Brute force | A lot of failed logins from one IP in a short window | T1110 | High |
| Password spraying | One username tried from a lot of different IPs | T1110.003 | High |
| Success after failures | A login succeeds from an IP that was just failing over and over | T1078 | Critical |
| Username enumeration | Repeated attempts against usernames that don't exist | T1590 | Medium |
| Off-hours login | A successful login between 00:00 and 05:00 | T1078 | Medium |

The brute force check uses a sliding 10 minute window, not fixed clock
buckets. I did it that way so a slow attack spread across a boundary
still gets caught, but a couple of typos from one person don't.

## How to run it

```bash
# Try it on the bundled sample log first
python log_analyzer.py --log samples/sample_auth.log

# Point it at a real auth log
python log_analyzer.py --log /var/log/auth.log --report triage-report.md --json findings.json

# Change the sensitivity (default is 5 failures in 10 minutes)
python log_analyzer.py --log /var/log/auth.log --threshold 10 --window 15
```

Standard library only, so there is nothing to install.

Example output:

```
=== Log analysis summary ===
Events parsed : 36 (5 accepted, 31 failed/invalid)
Unique IPs    : 9
Findings      : 6

[CRITICAL] Successful login from 203.0.113.7 after 12 failures — possible compromise  (T1078)
[HIGH]     Possible brute-force attack from 203.0.113.7  (T1110)
[HIGH]     Possible brute-force attack from 203.0.113.44  (T1110)
[HIGH]     Possible password spraying against user 'jdoe'  (T1110.003)
[MEDIUM]   Username enumeration from 203.0.113.44  (T1590)
[MEDIUM]   Off-hours login: 'uman' from 198.51.100.99 at 03:12  (T1078)
```

## How it works

1. Parse: each syslog line is matched for `Failed`, `Accepted`, and
   `Invalid user` sshd events and turned into a timestamped event.
   Syslog leaves the year out, so it defaults to the current year.
2. Detect: five detectors run over those events, using the sliding
   window described above for brute force and spraying.
3. Report: findings are sorted critical to low and written to the
   console, Markdown, and JSON.

## Project structure

```
log_analyzer.py                 # parser, detectors, CLI, reporters
samples/
  generate_sample_log.py        # builds the synthetic demo log
  sample_auth.log               # synthetic log with 6 planted attacks
  EXAMPLE_REPORT.md             # example report output
  EXAMPLE_FINDINGS.json         # example JSON output
tests/
  test_analyzer.py              # 18 unit and end-to-end tests
```

## Testing

```bash
python -m unittest discover -s tests
```

All 18 tests pass. The end-to-end test replays the sample log and
checks that every planted attack is detected, so the demo doubles as
a regression test.

## About the sample data

`sample_auth.log` is 100% synthetic, built by
`generate_sample_log.py`. All the attacker IPs are from the RFC 5737
documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`), which are reserved and never route on the real
internet.

## What it doesn't do yet

- It only parses classic syslog sshd format. It doesn't handle journald
  JSON or cloud logs like CloudTrail yet.
- No IP reputation or GeoIP lookup.
- The thresholds are fixed. On a busy jump box you'd want baselines
  per host to cut down false positives, and that's the next thing
  I'd add.
