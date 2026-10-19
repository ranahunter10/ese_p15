"""Recording and replay: the determinism the rest of the testing rests on.

A recording is the kernel's own bytes, so replaying one exercises the whole
userspace stack -- decode, assemble, graph -- without a kernel, without root
and without BCC. Two things have to hold for that to be worth anything:

  1. The same recording must produce the same graph and the same log, every
     time. Otherwise a diff between two runs says nothing.
  2. It must reproduce what the LIVE run did, not merely something stable.
     The live loop expires a pending exec once it has waited
     PENDING_TIMEOUT_S on a real clock. A file is read in microseconds, so a
     real clock expires nothing during a replay and dumps everything into the
     final forced tick -- which reports a failed exec in the wrong causal
     position. `VirtualClock` is what prevents that, and
     ExecTimeoutHappensOnTheRecordingsTimelineTest is the named test that
     fails if it is reverted.
"""

import io
import json
import os
import struct
import sys
import time
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)

from hids import replay
from hids.events import (ARG_FLAG_END, Clock, EVENT_EXEC_ENTER, EVENT_EXEC_OK,
                         EVENT_OPEN, decode, encode_arg, encode_event)
from hids.graph import ProcessGraph
from hids.processor import EventProcessor

SEC = 10 ** 9


# ---- recording builders -----------------------------------------------------

def _enter(pid, ts, path, comm="bash"):
    return [
        encode_event(type=EVENT_EXEC_ENTER, pid=pid, tid=pid, ppid=1, uid=1000,
                     gid=1000, ts_ns=ts, start_ns=SEC, pstart_ns=SEC,
                     comm=comm, tcomm=comm, pcomm="systemd", filename=path),
        encode_arg(pid, 0, ts, path.rsplit("/", 1)[-1]),
        encode_arg(pid, 1, ts, "", ARG_FLAG_END),
    ]


def _ok(pid, ts, enter_ts, comm):
    return [encode_event(type=EVENT_EXEC_OK, pid=pid, tid=pid, ppid=1, uid=1000,
                         gid=1000, ts_ns=ts, start_ns=SEC, pstart_ns=SEC,
                         comm=comm, tcomm=comm, pcomm="systemd", aux_ns=enter_ts)]


def timeout_payloads():
    """A failed exec at 10 s, then completed execs at 20/30/40 s.

    The gap is the point: the failure can only be noticed by a timeout, and
    the records after it are what make "noticed late" visible as an ordering
    difference rather than just a different timestamp.
    """
    recs = list(_enter(500, 10 * SEC, "/usr/local/bin/nc"))
    for pid, t in ((501, 20), (502, 30), (503, 40)):
        recs += _enter(pid, t * SEC, "/bin/true")
        recs += _ok(pid, t * SEC + 1000, t * SEC, "true")
    return recs


def write_recording(path, payloads):
    r = replay.RawRecorder(path)
    for b in payloads:
        r.write(b)
    r.close()
    return r.count


def replay_once(path, use_virtual_clock=True):
    """Returns (snapshot_json, log_text) for one replay of `path`."""
    clock = Clock()
    clock.offset = 0.0              # as monitor.py pins it for replay
    vclock = replay.VirtualClock()
    log = io.StringIO()
    graph = ProcessGraph()
    proc = EventProcessor(graph, clock, log_file=log,
                          mono=vclock if use_virtual_clock else time.monotonic)
    replay.run(path, proc, vclock, decode)
    return json.dumps(graph.to_dict(), sort_keys=True), log.getvalue()


def log_order(text):
    return [(e["type"], e.get("pid")) for e in
            (json.loads(l) for l in text.splitlines())]


class _Recorded(unittest.TestCase):
    """Writes its recordings under a per-test temp dir."""

    def setUp(self):
        import tempfile
        self.dir = tempfile.mkdtemp(prefix="p15replay")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    def path(self, name="rec.p15raw"):
        return os.path.join(self.dir, name)


class RoundTripTest(_Recorded):
    def test_the_recorder_gives_back_exactly_the_bytes_it_was_given(self):
        # If the container format altered a payload, every later guarantee
        # would be about the container rather than about the monitor.
        payloads = timeout_payloads()
        p = self.path()
        self.assertEqual(write_recording(p, payloads), len(payloads))
        self.assertEqual(list(replay.read_records(p)), payloads)

    def test_a_recording_replays_with_no_undecodable_records(self):
        p = self.path()
        write_recording(p, timeout_payloads())
        _, log = replay_once(p)
        self.assertTrue(log.strip())


class DeterminismTest(_Recorded):
    """Claim: same recording in, same everything out."""

    def test_two_replays_of_one_recording_give_an_identical_graph(self):
        p = self.path()
        write_recording(p, timeout_payloads())
        a, _ = replay_once(p)
        b, _ = replay_once(p)
        self.assertEqual(a, b)

    def test_two_replays_of_one_recording_give_an_identical_log(self):
        # Clock.offset is sampled from the wall at construction, so without
        # pinning it the log TEXT differs between replays even when the graph
        # does not.
        p = self.path()
        write_recording(p, timeout_payloads())
        _, a = replay_once(p)
        _, b = replay_once(p)
        self.assertEqual(a, b)


class ExecTimeoutHappensOnTheRecordingsTimelineTest(_Recorded):
    """The named test for VirtualClock. Revert it and this fails.

    A real monotonic clock reads a whole recording in microseconds, so no
    pending exec ever reaches PENDING_TIMEOUT_S during the replay and all of
    them settle in the final forced tick. The failed exec is then reported
    AFTER events that really happened after it -- wrong causal order from a
    tool whose entire purpose is causal order.
    """

    def test_a_failed_exec_is_reported_before_the_events_that_followed_it(self):
        p = self.path()
        write_recording(p, timeout_payloads())
        _, log = replay_once(p, use_virtual_clock=True)
        order = [t for t, _pid in log_order(log)]
        self.assertEqual(order,
                         ["EXEC_FAILED", "EXEC", "EXEC", "EXEC"],
                         "the 10 s failure must precede the 20/30/40 s execs")

    def test_a_real_clock_reports_that_failure_last_which_is_the_bug(self):
        # Asserted explicitly so the difference is recorded as a property of
        # the clock rather than left as a claim in a comment.
        p = self.path()
        write_recording(p, timeout_payloads())
        _, log = replay_once(p, use_virtual_clock=False)
        order = [t for t, _pid in log_order(log)]
        self.assertEqual(order, ["EXEC", "EXEC", "EXEC", "EXEC_FAILED"])

    def test_the_two_clocks_actually_disagree(self):
        # Guards the pair above against going vacuous together: if some
        # future change made both orders equal, the mutation check would
        # silently stop testing anything.
        p = self.path()
        write_recording(p, timeout_payloads())
        _, virtual = replay_once(p, use_virtual_clock=True)
        _, real = replay_once(p, use_virtual_clock=False)
        self.assertNotEqual(log_order(virtual), log_order(real))


class AFrozenClockIsRefusedTest(_Recorded):
    """The post-condition for a bug this module actually shipped.

    `getattr(ev, "ts", 0)` was the first version of the timestamp lookup. No
    record type has a field called `ts`, so it returned 0 for every record
    and the virtual clock never advanced -- replay silently behaved as though
    it had no clock. The default value is what made it silent.
    """

    def test_a_decoder_that_yields_unstamped_records_raises(self):
        p = self.path()
        write_recording(p, timeout_payloads())

        class Unstamped(object):
            """Decodes to something with no ts_ns, as a renamed field would."""

        def blind_decode(payload, size):
            return Unstamped()

        clock = Clock()
        vclock = replay.VirtualClock()
        proc = EventProcessor(ProcessGraph(), clock, mono=vclock)
        with self.assertRaises(RuntimeError) as cm:
            replay.run(p, proc, vclock, blind_decode)
        self.assertIn("virtual clock never advanced", str(cm.exception))

    def test_an_empty_recording_does_not_raise(self):
        # Nothing decoded means nothing to stamp: that is not the bug.
        p = self.path()
        write_recording(p, [])
        clock = Clock()
        vclock = replay.VirtualClock()
        proc = EventProcessor(ProcessGraph(), clock, mono=vclock)
        self.assertEqual(replay.run(p, proc, vclock, decode), (0, 0))


class VirtualClockTest(unittest.TestCase):
    def test_it_starts_at_zero_and_advances(self):
        v = replay.VirtualClock()
        self.assertEqual(v(), 0.0)
        v.advance_to(5 * SEC)
        self.assertEqual(v(), 5.0)

    def test_it_never_runs_backwards(self):
        # perf delivers per-CPU, so records can arrive slightly out of order.
        # A clock that went back would re-arm timeouts that had elapsed.
        v = replay.VirtualClock()
        v.advance_to(10 * SEC)
        v.advance_to(4 * SEC)
        self.assertEqual(v(), 10.0)


class CorruptRecordingTest(_Recorded):
    """A recording is evidence. Anything unreadable is reported, never
    skipped -- skipping would silently shorten the event stream and make a
    damaged file look like a clean run with fewer events."""

    def _read(self, blob):
        p = self.path("bad.p15raw")
        with open(p, "wb") as f:
            f.write(blob)
        return list(replay.read_records(p))

    def test_a_foreign_file_is_refused(self):
        with self.assertRaises(ValueError) as cm:
            self._read(b"NOTP" + struct.pack("<I", 1))
        self.assertIn("not a P15 raw recording", str(cm.exception))

    def test_a_file_too_short_for_a_header_is_refused(self):
        with self.assertRaises(ValueError):
            self._read(b"P15")

    def test_a_future_format_version_is_refused(self):
        with self.assertRaises(ValueError) as cm:
            self._read(replay.MAGIC + struct.pack("<I", replay.FORMAT_VERSION + 1))
        self.assertIn("this build reads", str(cm.exception))

    def test_a_truncated_payload_is_refused(self):
        head = replay.MAGIC + struct.pack("<I", replay.FORMAT_VERSION)
        with self.assertRaises(ValueError) as cm:
            self._read(head + struct.pack("<I", 100) + b"only ten.")
        self.assertIn("truncated record", str(cm.exception))

    def test_an_implausible_record_size_is_refused_before_allocating(self):
        head = replay.MAGIC + struct.pack("<I", replay.FORMAT_VERSION)
        with self.assertRaises(ValueError) as cm:
            self._read(head + struct.pack("<I", replay.MAX_RECORD + 1))
        self.assertIn("implausible record size", str(cm.exception))

    def test_a_zero_length_record_is_refused(self):
        head = replay.MAGIC + struct.pack("<I", replay.FORMAT_VERSION)
        with self.assertRaises(ValueError):
            self._read(head + struct.pack("<I", 0))

    def test_a_truncated_length_prefix_names_how_far_it_got(self):
        head = replay.MAGIC + struct.pack("<I", replay.FORMAT_VERSION)
        with self.assertRaises(ValueError) as cm:
            self._read(head + b"\x01\x02")
        self.assertIn("truncated length prefix", str(cm.exception))


class BootstrapSidecarTest(_Recorded):
    """A 60 s recording of an idle desktop replayed to 8 processes while the
    live screen had shown 174: the other 166 were the /proc bootstrap, which
    replay deliberately does not redo (it would inject TODAY's processes into
    a replay of a past run). Carrying the snapshot beside the recording is
    what makes a replayed graph comparable to the live one.
    """

    def _procs(self, n):
        return [{"pid": i, "ppid": 1 if i > 1 else 0, "comm": "p%d" % i,
                 "uid": 0, "start_ns": i * 1000} for i in range(1, n + 1)]

    def test_it_round_trips(self):
        p = self.path()
        write_recording(p, timeout_payloads())
        replay.write_bootstrap(p, self._procs(20), 999)
        procs, ts = replay.read_bootstrap(p)
        self.assertEqual(len(procs), 20)
        self.assertEqual(ts, 999)

    def test_a_recording_without_a_sidecar_still_replays(self):
        # Backward compatibility: recordings made before the sidecar existed,
        # and --no-bootstrap runs, have none.
        p = self.path()
        write_recording(p, timeout_payloads())
        self.assertIsNone(replay.read_bootstrap(p))

    def test_a_malformed_sidecar_is_refused_not_ignored(self):
        p = self.path()
        write_recording(p, timeout_payloads())
        with open(replay.bootstrap_path(p), "w") as f:
            json.dump({"procs": "not a list", "ts_ns": 1}, f)
        with self.assertRaises(ValueError):
            replay.read_bootstrap(p)

    def test_the_sidecar_sits_next_to_the_recording(self):
        self.assertEqual(replay.bootstrap_path("/tmp/a.p15raw"),
                         "/tmp/a.p15raw.bootstrap.json")

    def test_seeding_does_not_cost_determinism(self):
        # It is read from a file, so two replays see identical input.
        p = self.path()
        write_recording(p, timeout_payloads())
        replay.write_bootstrap(p, self._procs(15), 500)
        out = []
        for _ in range(2):
            graph = ProcessGraph()
            procs, ts = replay.read_bootstrap(p)
            graph.bootstrap(procs, ts)
            clock = Clock()
            clock.offset = 0.0
            vclock = replay.VirtualClock()
            proc = EventProcessor(graph, clock, mono=vclock)
            replay.run(p, proc, vclock, decode)
            out.append(json.dumps(graph.to_dict(), sort_keys=True))
        self.assertEqual(out[0], out[1])

    def test_seeding_actually_adds_the_processes(self):
        p = self.path()
        write_recording(p, timeout_payloads())
        graph = ProcessGraph()
        before = graph.summary()["processes"]
        procs, ts = replay.write_bootstrap(p, self._procs(12), 500), None
        procs, ts = replay.read_bootstrap(p)
        graph.bootstrap(procs, ts)
        self.assertEqual(graph.summary()["processes"], before + 12)


class PeekHeaderTest(_Recorded):
    """The up-front check. Pointing --replay at the JSONL log is the easy
    mistake, and it must cost one line rather than a traceback after a graph
    and a log file have already been created."""

    def test_it_accepts_a_real_recording(self):
        p = self.path()
        write_recording(p, timeout_payloads())
        self.assertEqual(replay.peek_header(p), replay.FORMAT_VERSION)

    def test_it_names_the_jsonl_log_as_the_likely_mistake(self):
        p = self.path("run.jsonl")
        with open(p, "w") as f:
            f.write('{"type": "EXEC", "pid": 1}\n')
        with self.assertRaises(ValueError) as cm:
            replay.peek_header(p)
        self.assertIn("the JSONL log is not one", str(cm.exception))

    def test_a_missing_file_raises_oserror_not_valueerror(self):
        # monitor.py catches both, but they mean different things: one is a
        # typo, the other is a wrong file.
        with self.assertRaises(OSError):
            replay.peek_header(self.path("absent.p15raw"))


class ReplayRebuildsTheCausalChainTest(_Recorded):
    """End to end: a recording of an intrusion-shaped sequence must come back
    as the same lineage a live run would have built."""

    def test_lineage_survives_a_round_trip_through_the_recording(self):
        recs = []
        recs += _enter(900, 4 * SEC, "/usr/sbin/sshd", comm="systemd")
        recs += _ok(900, 4 * SEC + 1000, 4 * SEC, "sshd")
        recs.append(encode_event(type=EVENT_OPEN, pid=900, tid=900, ppid=1,
                                 uid=0, gid=0, ret=3, flags=0, ts_ns=5 * SEC,
                                 start_ns=SEC, pstart_ns=SEC, comm="sshd",
                                 tcomm="sshd", pcomm="systemd",
                                 filename="/etc/passwd", ino=131074,
                                 dev=2049, igen=1))
        p = self.path()
        write_recording(p, recs)
        snap, _ = replay_once(p)
        d = json.loads(snap)
        # Asserted through the snapshot, not the live graph object, so the
        # round trip covers serialisation too: a replay whose result cannot
        # be written out is no use to query_graph.py.
        sshd = [n for n in d["processes"] if n.get("comm") == "sshd"]
        self.assertEqual(len(sshd), 1,
                         "the exec'd process must be in the replayed graph")
        self.assertEqual(sshd[0]["ppid"], 1)
        opened = [f for f in d["files"] if "/etc/passwd" in json.dumps(f)]
        self.assertTrue(opened, "the file it opened must be in the graph too")


if __name__ == "__main__":
    unittest.main()
