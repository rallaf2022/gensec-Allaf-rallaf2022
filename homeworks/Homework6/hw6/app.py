"""Secure offline security-log analyzer.

FAU ID: rallaf2022
Homework 06.3

Reads JSON Lines login events from one explicitly named file (or from
built-in synthetic demo data), reports login-failure counts per IP, and
flags suspected brute force: by default, at least 3 failures from one IP
within 5 minutes.

Security properties:
    * Python standard library only; fully offline.
    * No eval/exec, no shell, no network, and no environment/secret access.
    * Reads only the single file named by ``--file``. It never opens
      ``.env`` files, key/certificate files, directories, or symlinks,
      and it never follows paths or instructions inside log lines to
      other files.
    * Bounded file size, record count, and line length, so a hostile or
      corrupt file cannot exhaust memory.
    * Every record is strictly validated (exact fields, string types,
      length limits, parsed IP address, timezone-aware ISO 8601
      timestamp, allow-listed action and username characters) before use.
    * Terminal control characters are rejected in input (including
      JSON-escaped controls after decoding) and in CLI arguments, and
      are never echoed; usernames are not printed in reports at all.
    * Deeply nested JSON and timestamps whose UTC conversion would
      overflow are rejected as records, without tracebacks.

Example (Windows):
    py app.py --demo
    py app.py --file sample_events.jsonl
    py app.py --file sample_events.jsonl --json
    py app.py --file sample_events.jsonl --threshold 5 --window-minutes 10
"""

import argparse
import ipaddress
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Optional, Sequence

# --- Limits (bounds against malformed / adversarial input) ------------------

MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MiB total input.
MAX_RECORDS = 10_000  # Maximum lines considered before input is cut off.
MAX_LINE_CHARS = 4_096  # Maximum characters in one JSON Lines record.
MAX_TIMESTAMP_CHARS = 64
MAX_IP_CHARS = 45  # Longest textual IPv6 address.
MAX_USERNAME_CHARS = 64
MIN_USERNAME_CHARS = 1
MAX_JSON_DEPTH = 32  # Containers nested deeper than this are rejected.

DEFAULT_THRESHOLD = 3
DEFAULT_WINDOW_SECONDS = 5 * 60
MIN_THRESHOLD = 1
MAX_THRESHOLD = 1_000
MIN_WINDOW_SECONDS = 1
MAX_WINDOW_SECONDS = 24 * 60 * 60

ALLOWED_ACTIONS = frozenset({"login_success", "login_failure"})
REQUIRED_FIELDS = frozenset({"timestamp", "ip", "username", "action"})
ALLOWED_SUFFIXES = frozenset({".jsonl", ".log", ".txt"})
BLOCKED_SUFFIXES = frozenset(
    {".env", ".key", ".pem", ".p12", ".pfx", ".crt", ".cer", ".der"}
)
BLOCKED_NAMES = frozenset(
    {".env", "id_rsa", "id_ed25519", "credentials", "credentials.json"}
)
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._@+\-]+$")


class InputError(ValueError):
    """Raised when an input file or CLI value is unsafe or unusable."""


@dataclass(frozen=True)
class LogEvent:
    """One validated login event."""

    timestamp: datetime
    ip: str
    username: str
    action: str


@dataclass(frozen=True)
class SuspectedBruteForce:
    """One IP whose failures reach the threshold inside one window."""

    ip: str
    max_failures_in_window: int
    total_failures: int
    window_start: str
    window_end: str


@dataclass(frozen=True)
class AnalysisReport:
    """Aggregate result; contains no usernames or raw input lines."""

    total_records: int
    valid_records: int
    rejected_records: int
    failures_per_ip: dict[str, int]
    suspected_brute_force: list[SuspectedBruteForce]
    threshold: int
    window_seconds: int


# --- Validation ---------------------------------------------------------------


def has_control_character(value: str) -> bool:
    """Return True if `value` contains a C0, DEL, or C1 control character."""
    return any(
        ord(char) < 32 or 127 <= ord(char) <= 159 for char in value
    )


def parse_timestamp(value: str) -> datetime:
    """Parse an ISO 8601 timestamp that must carry a timezone."""
    if len(value) > MAX_TIMESTAMP_CHARS:
        raise InputError("timestamp is too long")
    candidate = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as error:
        raise InputError("timestamp is not valid ISO 8601") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise InputError("timestamp must include a timezone")
    try:
        return parsed.astimezone(timezone.utc)
    except (OverflowError, ValueError, OSError) as error:
        # E.g. year 0001 with a positive offset would become year 0 in UTC.
        raise InputError("timestamp is outside the representable UTC range") from error


def parse_ip(value: str) -> str:
    """Parse an IPv4/IPv6 address and return its canonical text form."""
    if len(value) > MAX_IP_CHARS or "%" in value:
        raise InputError("ip is too long or contains a zone id")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as error:
        raise InputError("ip is not a valid IPv4 or IPv6 address") from error


def validate_username(value: str) -> str:
    """Validate a bounded username with a conservative character set."""
    if not MIN_USERNAME_CHARS <= len(value) <= MAX_USERNAME_CHARS:
        raise InputError("username length is out of range")
    if USERNAME_PATTERN.fullmatch(value) is None:
        raise InputError("username contains unsupported characters")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Build a JSON object while rejecting duplicate keys."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise InputError("JSON object contains a duplicate key")
        result[key] = value
    return result


def has_excessive_json_depth(line: str) -> bool:
    """Return True if JSON containers nest deeper than MAX_JSON_DEPTH.

    A small iterative scan (string- and escape-aware) rejects deeply
    nested input before the recursive JSON parser ever sees it, so a
    hostile line cannot trigger RecursionError or exhaust the stack.
    """
    depth = 0
    is_in_string = False
    is_escaped = False
    for char in line:
        if is_in_string:
            if is_escaped:
                is_escaped = False
            elif char == "\\":
                is_escaped = True
            elif char == '"':
                is_in_string = False
            continue
        if char == '"':
            is_in_string = True
        elif char in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                return True
        elif char in "]}":
            depth -= 1
    return False


def parse_event(line: str) -> LogEvent:
    """Parse and strictly validate one JSON Lines record.

    Raises:
        InputError: If the line is oversized, is not a JSON object with
            exactly the required fields, or any field is invalid.
    """
    if len(line) > MAX_LINE_CHARS:
        raise InputError("line exceeds the maximum length")
    if has_control_character(line):
        raise InputError("line contains a control character")
    if has_excessive_json_depth(line):
        raise InputError("JSON is nested too deeply")
    try:
        raw = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
    except InputError:
        raise
    except RecursionError as error:
        # Defense in depth: the depth pre-scan should catch this first.
        raise InputError("JSON is nested too deeply") from error
    except (json.JSONDecodeError, ValueError, OverflowError) as error:
        raise InputError("line is not valid JSON") from error
    if not isinstance(raw, dict):
        raise InputError("record must be a JSON object")
    if frozenset(raw.keys()) != REQUIRED_FIELDS:
        raise InputError("record must contain exactly timestamp, ip, username, action")
    for field_name, field_value in raw.items():
        if not isinstance(field_value, str):
            raise InputError(f"{field_name} must be a string")
        if has_control_character(field_value):
            raise InputError(f"{field_name} contains a control character")
    action = raw["action"]
    if action not in ALLOWED_ACTIONS:
        raise InputError("action is not supported")
    return LogEvent(
        timestamp=parse_timestamp(raw["timestamp"]),
        ip=parse_ip(raw["ip"]),
        username=validate_username(raw["username"]),
        action=action,
    )


# --- Analysis -----------------------------------------------------------------


def find_suspected(
    failures: dict[str, list[datetime]], threshold: int, window_seconds: int
) -> list[SuspectedBruteForce]:
    """Flag IPs reaching `threshold` failures within any sliding window."""
    window = timedelta(seconds=window_seconds)
    suspected: list[SuspectedBruteForce] = []
    for ip in sorted(failures):
        times = sorted(failures[ip])
        left = 0
        best_count = 0
        best_start = times[0]
        best_end = times[0]
        for right, current in enumerate(times):
            while current - times[left] > window:
                left += 1
            count = right - left + 1
            if count > best_count:
                best_count, best_start, best_end = count, times[left], current
        if best_count >= threshold:
            suspected.append(
                SuspectedBruteForce(
                    ip=ip,
                    max_failures_in_window=best_count,
                    total_failures=len(times),
                    window_start=best_start.isoformat(),
                    window_end=best_end.isoformat(),
                )
            )
    return suspected


def remove_line_ending(line: str) -> str:
    """Remove only one trailing CRLF, LF, or CR record terminator.

    Nothing else is stripped: leading/trailing spaces and, crucially,
    terminal control characters stay in place so `parse_event` can
    reject them instead of silently cleaning hostile input.
    """
    if line.endswith("\r\n"):
        return line[:-2]
    if line.endswith(("\n", "\r")):
        return line[:-1]
    return line


def analyze_lines(
    lines: Iterable[str], threshold: int, window_seconds: int
) -> AnalysisReport:
    """Analyze raw lines, counting (never echoing) rejected records."""
    total = 0
    valid = 0
    failures_per_ip: Counter[str] = Counter()
    failure_times: dict[str, list[datetime]] = defaultdict(list)
    for line in lines:
        if total >= MAX_RECORDS:
            # Count one extra rejected record and stop consuming input.
            total += 1
            break
        total += 1
        content = remove_line_ending(line)
        if not content:
            # Blank lines count as rejected records.
            continue
        try:
            event = parse_event(content)
        except (InputError, RecursionError, OverflowError):
            # Malformed records are counted, never raised as tracebacks.
            continue
        valid += 1
        if event.action == "login_failure":
            failures_per_ip[event.ip] += 1
            failure_times[event.ip].append(event.timestamp)
    ordered_failures = dict(
        sorted(failures_per_ip.items(), key=lambda item: (-item[1], item[0]))
    )
    return AnalysisReport(
        total_records=total,
        valid_records=valid,
        rejected_records=total - valid,
        failures_per_ip=ordered_failures,
        suspected_brute_force=find_suspected(
            failure_times, threshold, window_seconds
        ),
        threshold=threshold,
        window_seconds=window_seconds,
    )


def analyze_events(
    events: Iterable[LogEvent], threshold: int, window_seconds: int
) -> AnalysisReport:
    """Analyze already-validated events (used for demo data and tests)."""
    materialized = list(events)
    failures_per_ip: Counter[str] = Counter()
    failure_times: dict[str, list[datetime]] = defaultdict(list)
    for event in materialized:
        if event.action == "login_failure":
            failures_per_ip[event.ip] += 1
            failure_times[event.ip].append(event.timestamp)
    ordered_failures = dict(
        sorted(failures_per_ip.items(), key=lambda item: (-item[1], item[0]))
    )
    return AnalysisReport(
        total_records=len(materialized),
        valid_records=len(materialized),
        rejected_records=0,
        failures_per_ip=ordered_failures,
        suspected_brute_force=find_suspected(
            failure_times, threshold, window_seconds
        ),
        threshold=threshold,
        window_seconds=window_seconds,
    )


# --- Input handling -----------------------------------------------------------


def validate_input_path(path: Path) -> None:
    """Reject secret-like, non-regular, symlink, or wrong-type inputs."""
    if path.name.lower() in BLOCKED_NAMES or path.suffix.lower() in BLOCKED_SUFFIXES:
        raise InputError("refusing to read a secret-like file")
    if path.suffix.lower() not in ALLOWED_SUFFIXES:
        raise InputError("input file must end in .jsonl, .log, or .txt")
    if path.is_symlink():
        raise InputError("refusing to read a symbolic link")
    if not path.is_file():
        raise InputError("input path is not an existing regular file")


def read_input_lines(path: Path) -> list[str]:
    """Read one validated file with byte, line, and record bounds.

    Only this exact path is opened. File contents are data only: they are
    never executed and never used as paths to other files.
    """
    validate_input_path(path)
    try:
        size = path.stat().st_size
    except OSError as error:
        raise InputError("input file cannot be inspected") from error
    if size > MAX_FILE_BYTES:
        raise InputError("input file exceeds the maximum size")
    lines: list[str] = []
    bytes_read = 0
    try:
        with path.open("rb") as handle:
            max_line_bytes = MAX_LINE_CHARS * 4
            while True:
                raw_line = handle.readline(max_line_bytes + 1)
                if not raw_line:
                    break
                bytes_read += len(raw_line)
                if bytes_read > MAX_FILE_BYTES:
                    raise InputError("input file exceeds the maximum size")
                if len(raw_line) > max_line_bytes and not raw_line.endswith(b"\n"):
                    # Consume the rest of this one oversized line so it is
                    # counted once (as rejected), not as many fake records.
                    while raw_line and not raw_line.endswith(b"\n"):
                        raw_line = handle.readline(max_line_bytes + 1)
                        bytes_read += len(raw_line)
                        if bytes_read > MAX_FILE_BYTES:
                            raise InputError("input file exceeds the maximum size")
                    raw_line = b"x" * (MAX_LINE_CHARS + 1) + b"\n"
                try:
                    lines.append(raw_line.decode("utf-8", errors="strict"))
                except UnicodeDecodeError as error:
                    raise InputError("input file is not valid UTF-8") from error
                if len(lines) > MAX_RECORDS:
                    # Keep one marker line so the record cap is reported.
                    break
    except OSError as error:
        raise InputError("input file cannot be read") from error
    return lines


def build_demo_events() -> list[LogEvent]:
    """Return fixed synthetic events; no real users, IPs, or secrets."""
    base = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)
    rows = [
        (0, "203.0.113.10", "alice", "login_failure"),
        (60, "203.0.113.10", "alice", "login_failure"),
        (120, "203.0.113.10", "alice", "login_failure"),
        (180, "203.0.113.10", "alice", "login_success"),
        (0, "198.51.100.7", "bob", "login_failure"),
        (600, "198.51.100.7", "bob", "login_failure"),
        (30, "2001:db8::1", "carol", "login_success"),
    ]
    return [
        LogEvent(base + timedelta(seconds=offset), ip, username, action)
        for offset, ip, username, action in rows
    ]


# --- Output / CLI ---------------------------------------------------------------


def build_report_dict(report: AnalysisReport) -> dict[str, object]:
    """Convert a report to plain JSON-serializable data."""
    return asdict(report)


def format_text_report(report: AnalysisReport) -> str:
    """Format a deterministic text report (IPs only; no usernames)."""
    lines = [
        "Security log analysis",
        f"Total records: {report.total_records}",
        f"Valid records: {report.valid_records}",
        f"Rejected records: {report.rejected_records}",
        f"Brute-force rule: >= {report.threshold} failures within "
        f"{report.window_seconds} seconds",
        "",
        "Failures per IP:",
    ]
    if report.failures_per_ip:
        lines.extend(
            f"  {ip}: {count}" for ip, count in report.failures_per_ip.items()
        )
    else:
        lines.append("  (none)")
    lines.append("")
    lines.append("Suspected brute force:")
    if report.suspected_brute_force:
        for item in report.suspected_brute_force:
            lines.append(
                f"  {item.ip}: {item.max_failures_in_window} failures in window "
                f"{item.window_start} .. {item.window_end} "
                f"(total failures: {item.total_failures})"
            )
    else:
        lines.append("  (none)")
    return "\n".join(lines)


def resolve_window_seconds(args: argparse.Namespace) -> int:
    """Resolve and bound the configured detection window."""
    if args.window_seconds is not None:
        seconds = args.window_seconds
    else:
        seconds = args.window_minutes * 60
    if not MIN_WINDOW_SECONDS <= seconds <= MAX_WINDOW_SECONDS:
        raise InputError("window is out of the allowed range")
    return seconds


def create_argument_parser() -> argparse.ArgumentParser:
    """Create the full argument parser."""
    parser = argparse.ArgumentParser(
        description="Offline security-log analyzer (JSON Lines login events)."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", type=Path, help="Path to one .jsonl/.log/.txt file.")
    source.add_argument(
        "--demo", action="store_true", help="Analyze built-in synthetic events."
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    parser.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_THRESHOLD,
        help=f"Failures needed to flag an IP (default: {DEFAULT_THRESHOLD}).",
    )
    parser.add_argument(
        "--window-minutes",
        type=int,
        default=DEFAULT_WINDOW_SECONDS // 60,
        help="Detection window in minutes (default: 5).",
    )
    parser.add_argument(
        "--window-seconds",
        type=int,
        default=None,
        help="Detection window in seconds; overrides --window-minutes.",
    )
    return parser


def execute(argv: Optional[Sequence[str]] = None) -> int:
    """Run the CLI and return a process exit code (0 ok, 2 input error)."""
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    # Reject control characters before argparse can echo an unsafe
    # argument back in a usage/error message. The message is fixed text.
    if any(
        not isinstance(argument, str) or has_control_character(argument)
        for argument in raw_argv
    ):
        print(
            "Error: command-line arguments contain control characters.",
            file=sys.stderr,
        )
        return 2
    parser = create_argument_parser()
    args = parser.parse_args(raw_argv)
    try:
        if args.file is not None and has_control_character(str(args.file)):
            raise InputError("the file path contains control characters")
        if not MIN_THRESHOLD <= args.threshold <= MAX_THRESHOLD:
            raise InputError("threshold is out of the allowed range")
        window_seconds = resolve_window_seconds(args)
        if args.demo:
            report = analyze_events(
                build_demo_events(), args.threshold, window_seconds
            )
        else:
            report = analyze_lines(
                read_input_lines(args.file), args.threshold, window_seconds
            )
    except InputError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(build_report_dict(report), indent=2, sort_keys=True))
    else:
        print(format_text_report(report))
    return 0


def main() -> None:
    """Console entry point."""
    raise SystemExit(execute())


if __name__ == "__main__":
    main()
