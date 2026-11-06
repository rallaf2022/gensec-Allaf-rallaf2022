# Homework 06.3 — Secure Offline Security-Log Analyzer

FAU ID: **rallaf2022**

A secure, offline Python command-line analyzer for JSON Lines login
events. It uses **only the Python standard library**, makes no network
calls, runs no shell commands, and never reads `.env` files, keys, or
any file other than the single log file explicitly named with `--file`.

## What it reports

- Total, valid, and rejected records
- Login failures per IP address (IPv4 and IPv6)
- Suspected brute force: by default, **at least 3 failures from one IP
  within 5 minutes** (configurable, see below)

Usernames are used only for validation and counting; they are **not**
printed in either report format.

## Input format

One JSON object per line (`.jsonl`), with exactly these fields:

```json
{"timestamp": "2026-01-01T09:00:00+00:00", "ip": "203.0.113.10", "username": "alice", "action": "login_failure"}
```

| Field       | Rule                                                                 |
|-------------|----------------------------------------------------------------------|
| `timestamp` | ISO 8601 string, at most 64 chars, **must include a timezone** (`Z` allowed) |
| `ip`        | Valid IPv4 or IPv6 address (parsed and canonicalized; zone IDs rejected) |
| `username`  | 1–64 chars: letters, digits, `.` `_` `-` `@` `+` only                |
| `action`    | Exactly `login_success` or `login_failure`                           |

## Run on Windows

Open PowerShell or Command Prompt in this `hw6` folder:

```powershell
py --version
py app.py --demo
py app.py --file sample_events.jsonl
py app.py --file sample_events.jsonl --json
py app.py --file sample_events.jsonl --threshold 5 --window-minutes 10
py app.py --file sample_events.jsonl --threshold 4 --window-seconds 120
py app.py --help
```

If `py` is unavailable, use `python` instead of `py`. No installation
and no `pip install` are needed (standard library only), and no API key
or `.env` file is used.

Exit codes: `0` = analysis completed (rejected records may still have
been counted), `2` = unsafe/unusable input or invalid option values.

## Run the tests

```powershell
py -m unittest discover -s tests -v
```

## Files

| File                  | Purpose                                             |
|-----------------------|-----------------------------------------------------|
| `app.py`              | The analyzer CLI (standard library only)            |
| `sample_events.jsonl` | Synthetic example input, including rejected lines   |
| `tests/test_app.py`   | `unittest` suite: validation, detection, paths, CLI |
| `prompts.txt`         | Prompt 1, saved as assigned                         |

In `sample_events.jsonl`, `203.0.113.10` is flagged (3 failures inside
5 minutes), `198.51.100.7` is not (failures 20 minutes apart), and the
last three lines are intentionally rejected (bad IP, timezone-less
timestamp, non-JSON).

## Security defenses

- **Bounded input:** file ≤ 5 MiB, ≤ 10,000 records, ≤ 4,096 characters
  per line; oversized lines are consumed as one rejected record.
- **Strict validation:** exact field set (missing/extra fields fail),
  duplicate JSON keys rejected, all fields must be strings within
  length limits, IPs parsed with `ipaddress`, timestamps parsed with
  `datetime.fromisoformat` and required to be timezone-aware, actions
  allow-listed.
- **Terminal safety:** control characters (including ESC) are rejected
  in every field and raw lines are never echoed; reports contain only
  canonical IPs, counts, and normalized UTC timestamps. Lines are
  validated as read — only the trailing CRLF/LF line ending is removed,
  so control characters are never stripped away and cleaned. Controls
  smuggled as JSON escapes (`\u001b`, `\n`, …) are rejected after
  decoding, and CLI arguments containing controls are refused with a
  fixed error message that does not echo them.
- **Parser robustness:** JSON nesting deeper than 32 containers is
  rejected before parsing, `RecursionError` is converted to a rejected
  record, timestamps whose UTC conversion would overflow the
  representable date range are rejected, and invalid UTF-8 input is
  refused — none of these produce a traceback.
- **No dangerous operations:** no `eval`/`exec`, no shell/subprocess,
  no network, no environment-variable or secret access.
- **File safety:** only the exact `--file` path is opened. Symlinks,
  directories, missing files, non-`.jsonl`/`.log`/`.txt` files, and
  secret-like names (`.env`, `*.key`, `*.pem`, `*.p12`, `*.pfx`,
  certificates, credential files) are refused. Log contents are treated
  as data only — never as paths, commands, or instructions.

## Limitations

- **File-path filtering is not an OS sandbox.** The name/extension and
  symlink checks are only a guardrail inside this program. Any readable
  `.jsonl`/`.log`/`.txt` file the user explicitly points `--file` at
  will be read — including one outside this folder, or a sensitive file
  that was renamed to an allowed extension. The checks also cannot stop
  another process from swapping the file after it is checked (a
  time-of-check/time-of-use race). Real isolation would require OS
  permissions, a dedicated low-privilege account, or a sandbox, none of
  which this script provides. Only pass log files you intend to analyze.
- **Capped reports may be incomplete.** A file over 5 MiB is refused
  with no report at all. At the 10,000-record cap, analysis stops, the
  remaining input is collapsed into a single extra rejected record, and
  later events (including possible attacks) are not counted — totals
  can therefore understate the real log. Oversized lines are likewise
  counted once as rejected without their contents being examined.
  Split larger logs and analyze them in parts if completeness matters.
- Detection is per-IP only: it does not correlate one account attacked
  from many IPs (distributed/password-spraying attacks), and many users
  behind one NAT address share one count.
- The window rule is a simple threshold heuristic; it does not score
  risk, check successful logins after failures, or use threat intel.
- Events are held in memory after validation, so the 5 MiB / 10,000
  record caps also bound memory use; larger logs must be split first.
- A file that is not valid UTF-8 is refused as a whole rather than
  analyzed line by line, so one bad byte sequence discards the report
  for that run.
- Timestamps are compared in UTC after conversion; events with equal
  timestamps are ordered as encountered within the same IP.
- Only the two login actions above are supported; other real-world log
  schemas need to be converted to this format before analysis.
- Rejected records are counted but, by design, their contents are not
  shown, so diagnosing bad input requires inspecting the source file
  separately in a safe text viewer.
