"""Unit tests for the secure offline security-log analyzer (Homework 06.3).

Run from the hw6 folder (see README.md):
    py -m unittest discover -s tests -v
"""

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app


def make_line(timestamp="2026-01-01T09:00:00+00:00", ip="203.0.113.10",
              username="alice", action="login_failure"):
    """Return one valid JSON Lines record as text."""
    return (
        '{"timestamp": "%s", "ip": "%s", "username": "%s", "action": "%s"}'
        % (timestamp, ip, username, action)
    )


class ParseEventTests(unittest.TestCase):
    """Strict per-record validation."""

    def test_valid_ipv4_event_is_parsed(self):
        # Arrange / Act
        event = app.parse_event(make_line())
        # Assert
        self.assertEqual(event.ip, "203.0.113.10")
        self.assertEqual(event.action, "login_failure")
        self.assertIsNotNone(event.timestamp.tzinfo)

    def test_valid_ipv6_event_is_canonicalized(self):
        event = app.parse_event(make_line(ip="2001:0DB8:0000::1"))
        self.assertEqual(event.ip, "2001:db8::1")

    def test_zulu_timestamp_is_accepted(self):
        event = app.parse_event(make_line(timestamp="2026-01-01T09:00:00Z"))
        self.assertEqual(event.timestamp.hour, 9)

    def test_naive_timestamp_is_rejected(self):
        with self.assertRaises(app.InputError):
            app.parse_event(make_line(timestamp="2026-01-01T09:00:00"))

    def test_invalid_ip_is_rejected(self):
        with self.assertRaises(app.InputError):
            app.parse_event(make_line(ip="999.1.1.1"))

    def test_unknown_action_is_rejected(self):
        with self.assertRaises(app.InputError):
            app.parse_event(make_line(action="delete_user"))

    def test_non_string_field_is_rejected(self):
        line = ('{"timestamp": "2026-01-01T09:00:00+00:00", "ip": 123, '
                '"username": "alice", "action": "login_failure"}')
        with self.assertRaises(app.InputError):
            app.parse_event(line)

    def test_missing_and_extra_fields_are_rejected(self):
        with self.assertRaises(app.InputError):
            app.parse_event('{"timestamp": "2026-01-01T09:00:00+00:00"}')
        with self.assertRaises(app.InputError):
            app.parse_event(make_line()[:-1] + ', "role": "admin"}')

    def test_duplicate_key_is_rejected(self):
        line = ('{"timestamp": "2026-01-01T09:00:00+00:00", '
                '"timestamp": "2026-01-01T09:00:00+00:00", '
                '"ip": "203.0.113.10", "username": "alice", '
                '"action": "login_failure"}')
        with self.assertRaises(app.InputError):
            app.parse_event(line)

    def test_control_character_is_rejected(self):
        with self.assertRaises(app.InputError):
            app.parse_event(make_line(username="al\x1b[31mice"))

    def test_oversized_line_is_rejected(self):
        with self.assertRaises(app.InputError):
            app.parse_event("x" * (app.MAX_LINE_CHARS + 1))

    def test_oversized_username_is_rejected(self):
        with self.assertRaises(app.InputError):
            app.parse_event(make_line(username="a" * (app.MAX_USERNAME_CHARS + 1)))

    def test_non_object_json_is_rejected(self):
        with self.assertRaises(app.InputError):
            app.parse_event('["not", "an", "object"]')


class AnalysisTests(unittest.TestCase):
    """Counting and sliding-window brute-force detection."""

    def test_counts_total_valid_and_rejected(self):
        lines = [make_line(), "not-json", make_line(action="login_success")]
        report = app.analyze_lines(lines, threshold=3, window_seconds=300)
        self.assertEqual(report.total_records, 3)
        self.assertEqual(report.valid_records, 2)
        self.assertEqual(report.rejected_records, 1)

    def test_blank_line_is_rejected(self):
        report = app.analyze_lines(["", make_line()], 3, 300)
        self.assertEqual((report.total_records, report.rejected_records), (2, 1))

    def test_three_failures_within_five_minutes_are_flagged(self):
        lines = [
            make_line(timestamp="2026-01-01T09:00:00+00:00"),
            make_line(timestamp="2026-01-01T09:02:00+00:00"),
            make_line(timestamp="2026-01-01T09:05:00+00:00"),
        ]
        report = app.analyze_lines(lines, threshold=3, window_seconds=300)
        self.assertEqual(len(report.suspected_brute_force), 1)
        self.assertEqual(report.suspected_brute_force[0].ip, "203.0.113.10")
        self.assertEqual(report.suspected_brute_force[0].max_failures_in_window, 3)

    def test_failures_spread_beyond_window_are_not_flagged(self):
        lines = [
            make_line(timestamp="2026-01-01T09:00:00+00:00"),
            make_line(timestamp="2026-01-01T09:04:00+00:00"),
            make_line(timestamp="2026-01-01T09:09:00+00:00"),
        ]
        report = app.analyze_lines(lines, threshold=3, window_seconds=300)
        self.assertEqual(report.suspected_brute_force, [])

    def test_configurable_threshold(self):
        lines = [make_line(), make_line(timestamp="2026-01-01T09:01:00+00:00")]
        flagged = app.analyze_lines(lines, threshold=2, window_seconds=300)
        not_flagged = app.analyze_lines(lines, threshold=3, window_seconds=300)
        self.assertEqual(len(flagged.suspected_brute_force), 1)
        self.assertEqual(not_flagged.suspected_brute_force, [])

    def test_failures_per_ip_counts_only_failures(self):
        lines = [
            make_line(),
            make_line(ip="198.51.100.7", username="bob"),
            make_line(action="login_success"),
        ]
        report = app.analyze_lines(lines, threshold=3, window_seconds=300)
        self.assertEqual(
            report.failures_per_ip,
            {"203.0.113.10": 1, "198.51.100.7": 1},
        )

    def test_unordered_timestamps_are_sorted_before_detection(self):
        lines = [
            make_line(timestamp="2026-01-01T09:02:00+00:00"),
            make_line(timestamp="2026-01-01T09:00:00+00:00"),
            make_line(timestamp="2026-01-01T09:01:00+00:00"),
        ]
        report = app.analyze_lines(lines, threshold=3, window_seconds=300)
        self.assertEqual(len(report.suspected_brute_force), 1)

    def test_demo_data_flags_synthetic_attacker(self):
        report = app.analyze_events(app.build_demo_events(), 3, 300)
        flagged_ips = [item.ip for item in report.suspected_brute_force]
        self.assertEqual(flagged_ips, ["203.0.113.10"])
        self.assertEqual(report.rejected_records, 0)


class InputPathTests(unittest.TestCase):
    """The analyzer must never read secrets or arbitrary related files."""

    def test_env_file_is_refused(self):
        with self.assertRaises(app.InputError):
            app.validate_input_path(Path(".env"))

    def test_key_and_certificate_files_are_refused(self):
        for name in ("server.key", "cert.pem", "bundle.p12"):
            with self.subTest(name=name):
                with self.assertRaises(app.InputError):
                    app.validate_input_path(Path(name))

    def test_unexpected_suffix_is_refused(self):
        with self.assertRaises(app.InputError):
            app.validate_input_path(Path("payload.exe"))

    def test_missing_file_is_refused(self):
        with self.assertRaises(app.InputError):
            app.validate_input_path(Path("does-not-exist.jsonl"))

    def test_named_jsonl_file_is_analyzed_end_to_end(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text(make_line() + "\n" + "bad\n", encoding="utf-8")
            report = app.analyze_lines(
                app.read_input_lines(path), threshold=3, window_seconds=300
            )
        self.assertEqual((report.valid_records, report.rejected_records), (1, 1))


class CliTests(unittest.TestCase):
    """CLI exit codes without invoking a shell."""

    def test_demo_cli_succeeds(self):
        self.assertEqual(app.execute(["--demo"]), 0)

    def test_demo_cli_json_succeeds(self):
        self.assertEqual(app.execute(["--demo", "--json"]), 0)

    def test_out_of_range_threshold_returns_exit_code_2(self):
        self.assertEqual(app.execute(["--demo", "--threshold", "0"]), 2)

    def test_missing_file_returns_exit_code_2(self):
        self.assertEqual(app.execute(["--file", "missing.jsonl"]), 2)


class RegressionHardeningTests(unittest.TestCase):
    """Regression tests for Prompt 2 fixes (errors found in a real run)."""

    def test_username_minimum_uses_consistent_constant_name(self):
        self.assertEqual(app.MIN_USERNAME_CHARS, 1)
        self.assertFalse(hasattr(app, "MAX_USERNAME_MIN"))
        self.assertEqual(app.validate_username("a"), "a")
        with self.assertRaises(app.InputError):
            app.validate_username("")

    def test_deeply_nested_json_is_rejected_without_recursion_error(self):
        nested = "[" * 200 + "]" * 200
        with self.assertRaises(app.InputError):
            app.parse_event(nested)
        nested_object = '{"a": ' * 100 + "1" + "}" * 100
        with self.assertRaises(app.InputError):
            app.parse_event(nested_object)

    def test_deeply_nested_json_counts_as_one_rejected_record(self):
        lines = ["[" * 200 + "]" * 200, make_line()]
        report = app.analyze_lines(lines, threshold=3, window_seconds=300)
        self.assertEqual((report.total_records, report.valid_records), (2, 1))
        self.assertEqual(report.rejected_records, 1)

    def test_timezone_normalization_overflow_is_rejected(self):
        for timestamp in (
            "0001-01-01T00:30:00+14:00",  # UTC conversion reaches year 0.
            "9999-12-31T23:30:00-14:00",  # UTC conversion reaches year 10000.
        ):
            with self.subTest(timestamp=timestamp):
                with self.assertRaises(app.InputError):
                    app.parse_event(make_line(timestamp=timestamp))

    def test_timezone_overflow_counts_as_rejected_not_traceback(self):
        lines = [make_line(timestamp="0001-01-01T00:30:00+14:00"), make_line()]
        report = app.analyze_lines(lines, threshold=3, window_seconds=300)
        self.assertEqual((report.valid_records, report.rejected_records), (1, 1))

    def test_valid_timezone_offsets_normalize_to_utc(self):
        cases = {
            "2026-01-01T09:00:00+05:30": (3, 30),
            "2026-01-01T09:00:00-05:00": (14, 0),
            "2026-01-01T01:00:00+05:30": (19, 30),  # Previous UTC day.
            "2026-01-01T09:00:00+00:00": (9, 0),
        }
        for timestamp, expected in cases.items():
            with self.subTest(timestamp=timestamp):
                event = app.parse_event(make_line(timestamp=timestamp))
                self.assertEqual(
                    (event.timestamp.hour, event.timestamp.minute), expected
                )

    def test_invalid_timezone_offsets_are_rejected(self):
        for timestamp in (
            "2026-01-01T09:00:00+24:00",
            "2026-01-01T09:00:00+99:99",
            "2026-01-01T09:00:00UTC",
        ):
            with self.subTest(timestamp=timestamp):
                with self.assertRaises(app.InputError):
                    app.parse_event(make_line(timestamp=timestamp))

    def test_controls_are_not_stripped_before_validation(self):
        valid = make_line()
        hostile_lines = [
            "\x0b" + valid + "\n",  # Vertical tab would be removed by strip().
            "\x0c" + valid + "\n",  # Form feed would be removed by strip().
            "\x1c" + valid,  # File separator.
            valid + "\x0b\n",  # Trailing control before the line ending.
            valid + "\x7f\n",
        ]
        report = app.analyze_lines(hostile_lines, threshold=3, window_seconds=300)
        self.assertEqual(report.valid_records, 0)
        self.assertEqual(report.rejected_records, len(hostile_lines))

    def test_only_the_line_ending_is_removed(self):
        lines = [make_line() + "\r\n", make_line() + "\n", make_line()]
        report = app.analyze_lines(lines, threshold=3, window_seconds=300)
        self.assertEqual(report.valid_records, 3)
        self.assertEqual(app.remove_line_ending("abc\r\n"), "abc")
        self.assertEqual(app.remove_line_ending("abc\x0b\n"), "abc\x0b")

    def test_json_escaped_controls_are_rejected_after_decoding(self):
        backslash = chr(92)
        for escape in ("u001b", "u0007", "u007f", "n", "t"):
            with self.subTest(escape=escape):
                username = "al" + backslash + escape + "ice"
                with self.assertRaises(app.InputError):
                    app.parse_event(make_line(username=username))

    def test_cli_control_characters_return_2_without_echoing_them(self):
        hostile_argv = (
            ["--demo\x1b[31m"],
            ["--file", "events\x1b.jsonl"],
            ["--demo", "--threshold", "3\x07"],
            ["--demo", "--window-minutes", "5\x85"],
        )
        for argv in hostile_argv:
            with self.subTest(argv=argv):
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    exit_code = app.execute(argv)
                self.assertEqual(exit_code, 2)
                self.assertNotIn("\x1b", stderr.getvalue())
                self.assertNotIn("\x07", stderr.getvalue())
                self.assertIn("control characters", stderr.getvalue())

    def test_invalid_utf8_file_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_bytes(b"\xff\xfe\x00not-utf8\n")
            with self.assertRaises(app.InputError):
                app.read_input_lines(path)

    def test_file_size_bound_is_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text(make_line() + "\n", encoding="utf-8")
            with mock.patch.object(app, "MAX_FILE_BYTES", 10):
                with self.assertRaises(app.InputError):
                    app.read_input_lines(path)

    def test_oversized_line_is_one_rejected_record_and_reading_continues(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text("x" * 5_000 + "\n" + make_line() + "\n", encoding="utf-8")
            report = app.analyze_lines(
                app.read_input_lines(path), threshold=3, window_seconds=300
            )
        self.assertEqual((report.total_records, report.valid_records), (2, 1))
        self.assertEqual(report.rejected_records, 1)

    def test_record_bound_caps_the_report(self):
        lines = [make_line() for _ in range(5)]
        with mock.patch.object(app, "MAX_RECORDS", 3):
            report = app.analyze_lines(lines, threshold=3, window_seconds=300)
        # Three analyzed records plus one marker for the capped remainder:
        # a capped report is therefore knowingly incomplete.
        self.assertEqual((report.total_records, report.valid_records), (4, 3))
        self.assertEqual(report.rejected_records, 1)


if __name__ == "__main__":
    unittest.main()
