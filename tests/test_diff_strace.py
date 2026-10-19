"""Tests for the G2 recall harness's parsers.

The harness itself needs root and a live kernel, so it cannot run here. Its
*parsers* are where the bugs are, and they can be tested exactly: strace's
output format has several shapes a simple workload never produces (a syscall
split across <unfinished>/<resumed>, an escaped quote inside a path, a path
with spaces), and each one would silently change the recall figure.

A silently wrong recall number is worse than no number, because it would be
quoted.
"""

import importlib.util
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)

_spec = importlib.util.spec_from_file_location(
    "diff_strace", os.path.join(ROOT, "tools", "diff_strace.py"))
ds = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ds)


def _write(text, suffix=".out"):
    fd, p = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    return p


class StraceParserTest(unittest.TestCase):
    def parse(self, text):
        p = _write(text)
        try:
            return ds.parse_strace(p)
        finally:
            os.unlink(p)

    def test_a_plain_exec_and_open_are_read(self):
        ev, pids, _ = self.parse(
            '100 execve("/bin/ls", ["ls"], 0x7f /* 20 vars */) = 0\n'
            '100 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3\n')
        self.assertEqual(ev, [(100, "EXEC", "/bin/ls", True),
                              (100, "OPEN", "/etc/passwd", True)])
        self.assertEqual(pids, {100})

    def test_the_path_is_the_first_QUOTED_arg_not_the_first_arg(self):
        # openat's first argument is AT_FDCWD, not the path. Taking argument
        # one would make every openat compare against the literal "AT_FDCWD".
        ev, _, _ = self.parse('7 openat(AT_FDCWD, "/tmp/x", O_RDONLY) = 3\n')
        self.assertEqual(ev[0][2], "/tmp/x")

    def test_a_failed_call_is_marked_failed(self):
        ev, _, _ = self.parse(
            '9 openat(AT_FDCWD, "/nope", O_RDONLY) = -1 ENOENT '
            '(No such file or directory)\n')
        self.assertEqual(ev, [(9, "OPEN", "/nope", False)])

    def test_execveat_counts_as_an_exec(self):
        ev, _, _ = self.parse('5 execveat(3, "", ["x"], 0x0, AT_EMPTY_PATH) = 0\n')
        self.assertEqual(ev[0][1], "EXEC")

    def test_a_split_syscall_is_counted_once_not_twice(self):
        # <unfinished>/<resumed> is one syscall in two lines. Counting the
        # resumed half as well would inflate the denominator and understate
        # recall -- a number that looks like a capture gap but is a parser bug.
        ev, _, st = self.parse(
            '11 openat(AT_FDCWD, "/etc/slow", O_RDONLY <unfinished ...>\n'
            '11 <... openat resumed>) = 3\n')
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0][2], "/etc/slow")
        self.assertEqual(st["unfinished_resumed"], 1)
        self.assertEqual(st["unfinished_at_exit"], 1)

    def test_a_path_with_spaces_survives(self):
        ev, _, _ = self.parse(
            '3 openat(AT_FDCWD, "/home/a/My Documents/f.txt", O_RDONLY) = 3\n')
        self.assertEqual(ev[0][2], "/home/a/My Documents/f.txt")

    def test_an_escaped_quote_inside_a_path_does_not_end_it_early(self):
        # A naive split on '"' truncates this to '/tmp/a\\'.
        ev, _, _ = self.parse(r'4 openat(AT_FDCWD, "/tmp/a\"b", O_RDONLY) = 3' + "\n")
        self.assertEqual(ev[0][2], '/tmp/a"b')

    def test_signal_and_exit_lines_are_ignored(self):
        ev, pids, _ = self.parse(
            "12 --- SIGCHLD {si_signo=SIGCHLD} ---\n"
            "12 +++ exited with 0 +++\n"
            '12 execve("/bin/sh", ["sh"], 0x0) = 0\n')
        self.assertEqual(len(ev), 1)
        self.assertEqual(pids, {12})

    def test_untraced_syscalls_are_ignored_but_their_pid_is_noted(self):
        # The pid set is used to tell "whole process missing" from "one
        # syscall missing", so a pid seen only on an untraced line still
        # counts as a pid strace saw.
        ev, pids, _ = self.parse('77 close(3) = 0\n')
        self.assertEqual(ev, [])
        self.assertEqual(pids, {77})

    def test_a_line_with_no_quoted_argument_is_skipped_not_crashed(self):
        ev, _, _ = self.parse("8 openat(AT_FDCWD, NULL, O_RDONLY) = -1 EFAULT\n")
        self.assertEqual(ev, [])

    def test_garbage_does_not_raise(self):
        ev, _, _ = self.parse("not a strace line at all\n\n\x00\n")
        self.assertEqual(ev, [])


class MonitorLogParserTest(unittest.TestCase):
    def parse(self, lines):
        p = _write("".join(json.dumps(l) + "\n" for l in lines), ".jsonl")
        try:
            return ds.parse_monitor(p)
        finally:
            os.unlink(p)

    def test_exec_and_open_are_read(self):
        seen, bad = self.parse([
            {"type": "EXEC", "pid": 100, "path": "/bin/ls"},
            {"type": "OPEN", "pid": 100, "path": "/etc/passwd"},
        ])
        self.assertEqual(seen, {(100, "EXEC", "/bin/ls"),
                                (100, "OPEN", "/etc/passwd")})
        self.assertEqual(bad, 0)

    def test_failed_variants_fold_into_the_same_kind(self):
        # strace reports a failed open with the same path, so "did the monitor
        # see this syscall" must not depend on the return value.
        seen, _ = self.parse([
            {"type": "EXEC_FAILED", "pid": 1, "path": "/nope"},
            {"type": "OPEN_FAILED", "pid": 1, "path": "/nope2"},
        ])
        self.assertEqual(seen, {(1, "EXEC", "/nope"), (1, "OPEN", "/nope2")})

    def test_other_event_types_are_ignored(self):
        seen, _ = self.parse([
            {"type": "CONNECT", "pid": 1, "endpoint": "net:1.2.3.4:80"},
            {"type": "EXIT", "pid": 1},
        ])
        self.assertEqual(seen, set())

    def test_a_malformed_line_is_counted_not_fatal(self):
        p = _write('{"type": "EXEC", "pid": 1, "path": "/a"}\nnot json\n', ".jsonl")
        try:
            seen, bad = ds.parse_monitor(p)
        finally:
            os.unlink(p)
        self.assertEqual(seen, {(1, "EXEC", "/a")})
        self.assertEqual(bad, 1)

    def test_the_requested_path_is_indexed_too(self):
        # A shell searching $PATH logs the path it ASKED for; strace reports
        # that same string, so both keys have to be present or every failed
        # path-search counts as a miss.
        seen, _ = self.parse([
            {"type": "EXEC", "pid": 2, "path": "/usr/bin/ls",
             "requested": "ls"},
        ])
        self.assertIn((2, "EXEC", "/usr/bin/ls"), seen)
        self.assertIn((2, "EXEC", "ls"), seen)


class ClassifierTest(unittest.TestCase):
    """Every bucket but 'unexplained' is a reason that is NOT a capture gap,
    so a bucket that swallows too much would hide the finding."""

    def test_the_instruments_are_excluded(self):
        self.assertEqual(
            ds.classify((50, "EXEC", "/usr/bin/strace", True), {1}, {50}, 50, 99),
            "the instruments themselves")

    def test_a_process_the_monitor_never_saw_is_its_own_bucket(self):
        # Not "one syscall lost" -- a whole process missing is a bigger claim.
        self.assertEqual(
            ds.classify((60, "EXEC", "/bin/x", True), {1, 2}, {60}, 9, 99),
            "process never seen by the monitor")

    def test_a_relative_open_is_not_comparable_by_string(self):
        self.assertEqual(
            ds.classify((1, "OPEN", "relative/file", True), {1}, {1}, 9, 99),
            "relative path, not comparable by string")

    def test_procfs_is_excluded(self):
        self.assertEqual(
            ds.classify((1, "OPEN", "/proc/self/stat", True), {1}, {1}, 9, 99),
            "procfs/sysfs (monitor reads these itself)")

    def test_a_real_gap_falls_through_to_unexplained(self):
        self.assertEqual(
            ds.classify((1, "OPEN", "/etc/shadow", True), {1}, {1}, 9, 99),
            "unexplained")

    def test_an_absolute_exec_the_monitor_saw_the_process_for_is_unexplained(self):
        # The case that matters: the monitor knew the process and still has no
        # record of the syscall.
        self.assertEqual(
            ds.classify((1, "EXEC", "/bin/sh", True), {1}, {1}, 9, 99),
            "unexplained")


class NegativeControlTest(unittest.TestCase):
    """The first real run of this harness reported 100.00 % recall (133 of
    133) with zero misses in every bucket. A figure that cannot come out any
    other way is not a measurement, so the tool now runs a second arm with
    the `open` hook deliberately detached: every openat must then be reported
    missing. These tests exercise that verdict, because an unexercised guard
    is how the project keeps finding silently-vacuous checks.
    """

    def arm(self, events, matched):
        return {"events": events, "matched": matched}

    def test_a_working_control_says_ok(self):
        # Opens all vanished when the hook was detached; execs survived.
        v, msg = ds.control_verdict(self.arm(
            events=[(1, "OPEN", "/a", True), (1, "OPEN", "/b", True),
                    (1, "EXEC", "/bin/sh", True)],
            matched=[(1, "EXEC", "/bin/sh", True)]))
        self.assertEqual(v, "ok")
        self.assertIn("0 of 2 opens", msg)

    def test_opens_still_matching_voids_the_measurement(self):
        # The failure this control exists to catch: the comparison matches
        # opens even with nothing capturing them, so it can never fail.
        v, msg = ds.control_verdict(self.arm(
            events=[(1, "OPEN", "/a", True), (1, "OPEN", "/b", True)],
            matched=[(1, "OPEN", "/a", True)]))
        self.assertEqual(v, "void")
        self.assertIn("void", msg)

    def test_a_workload_with_no_opens_is_inconclusive_not_ok(self):
        # Detaching a hook for a syscall nobody made proves nothing, and
        # must not be reported as a passing control.
        v, msg = ds.control_verdict(self.arm(
            events=[(1, "EXEC", "/bin/sh", True)],
            matched=[(1, "EXEC", "/bin/sh", True)]))
        self.assertEqual(v, "inconclusive")
        self.assertIn("no opens", msg)

    def test_everything_vanishing_is_void_not_ok(self):
        # If the execs disappeared too, the control arm captured nothing at
        # all -- a broken run, not a clean isolation of the open hook. Naively
        # checking only "0 opens matched" would call this OK.
        v, msg = ds.control_verdict(self.arm(
            events=[(1, "OPEN", "/a", True), (1, "EXEC", "/bin/sh", True)],
            matched=[]))
        self.assertEqual(v, "void")
        self.assertIn("0 of 1 execs", msg)


class ByKindTest(unittest.TestCase):
    def test_it_counts_per_kind(self):
        self.assertEqual(
            ds.by_kind([(1, "OPEN", "/a", True), (1, "OPEN", "/b", True),
                        (2, "EXEC", "/c", True)]),
            {"OPEN": 2, "EXEC": 1})

    def test_empty_is_empty(self):
        self.assertEqual(ds.by_kind([]), {})


if __name__ == "__main__":
    unittest.main()
