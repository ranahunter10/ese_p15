"""EventProcessor + ExecAssembler: ordering, failures, filters, log format."""

import ctypes
import io
import itertools
import json
import os
import unittest

from helpers import SEC, FakeClock, World
from hids import events
from hids.events import (AF_UNIX, ARG_FLAG_END, ARG_FLAG_TRUNCATED, Arg, EVENT_EXEC_ENTER,
                         EVENT_EXEC_OK, MAXARG)
from hids.graph import ProcessGraph
from hids.processor import EventProcessor


def setup(**kw):
    w = World()
    w.spawn(1, 0, "systemd", 1 * SEC)
    w.spawn(1360, 1, "bash", 10 * SEC)
    w.spawn(1390, 1360, "bash", 20 * SEC)      # forked shell, about to exec cat
    clock = FakeClock()
    log = io.StringIO()
    g = ProcessGraph()
    # what procstat.scan() would report at startup
    g.bootstrap([{"pid": pid, "ppid": v["ppid"], "comm": v["comm"], "uid": 1000,
                  "start_ns": v["start"]} for pid, v in w.procs.items()], 0)
    p = EventProcessor(g, clock, log_file=log, mono=clock, **kw)
    return w, g, p, log, clock


def lines(log):
    return [json.loads(l) for l in log.getvalue().splitlines()]


class ExecAssemblyTest(unittest.TestCase):
    ARGV = ["cat", "/etc/hostname"]

    def records(self, w):
        return w.exec_records(1390, 20 * SEC + 100, 20 * SEC + 900,
                              "/usr/bin/cat", self.ARGV, "cat")

    def test_every_arrival_order_gives_the_same_result(self):
        # 5 records (enter, 2 args, END, ok) -> 120 orders. The kernel can
        # deliver any of them (per-CPU buffers + sched_exec migration).
        w0, *_ = setup()
        recs = self.records(w0)
        for order in itertools.permutations(recs):
            w, g, p, log, _ = setup()
            for r in order:
                p.handle(r)
            out = lines(log)
            self.assertEqual(len(out), 1, order)
            e = out[0]
            self.assertEqual(e["type"], "EXEC")
            self.assertEqual(e["argv"], self.ARGV, order)
            self.assertEqual(e["name"], "cat")              # rows 9/15 fixed
            self.assertEqual(e["previous_name"], "bash")
            self.assertEqual(e["path"], "/usr/bin/cat")
            self.assertEqual(g.get(1390).cmdline, "cat /etc/hostname")
            self.assertEqual(p.assembler.pending, {})

    def test_failed_exec_reported_after_timeout(self):
        w, g, p, log, clock = setup()
        p.handle(w.ev(EVENT_EXEC_ENTER, 1390, 20 * SEC, "/usr/local/bin/ls"))
        p.handle(Arg(1390, 0, 20 * SEC, "ls"))
        p.handle(Arg(1390, 1, 20 * SEC, "", ARG_FLAG_END))
        p.tick()
        self.assertEqual(lines(log), [])                    # not yet
        clock.now += 3
        p.tick()
        out = lines(log)
        self.assertEqual([e["type"] for e in out], ["EXEC_FAILED"])
        self.assertEqual(out[0]["path"], "/usr/local/bin/ls")
        self.assertEqual(g.get(1390).failed_execs, [(20 * SEC, "/usr/local/bin/ls")])

    def test_path_search_then_success(self):
        # A shell trying several directories: two failures, one success.
        w, g, p, log, clock = setup()
        for i, d in enumerate(["/usr/local/sbin", "/usr/local/bin"]):
            p.handle(w.ev(EVENT_EXEC_ENTER, 1390, 20 * SEC + i, d + "/cat"))
        for r in w.exec_records(1390, 20 * SEC + 5, 20 * SEC + 9, "/usr/bin/cat",
                                ["cat"], "cat"):
            p.handle(r)
        p.tick(force=True)
        self.assertEqual([e["type"] for e in lines(log)],
                         ["EXEC", "EXEC_FAILED", "EXEC_FAILED"])
        self.assertEqual(p.counts["EXEC"], 1)
        self.assertEqual(p.counts["EXEC_FAILED"], 2)

    def test_ok_without_matching_enter(self):
        w, g, p, log, _ = setup()
        w.procs[1390]["comm"] = "cat"
        p.handle(w.ev(EVENT_EXEC_OK, 1390, 21 * SEC, aux=0))
        e = lines(log)[0]
        self.assertEqual((e["type"], e["name"], e["enter_seen"]), ("EXEC", "cat", False))

    def test_ok_whose_enter_never_arrives(self):
        w, g, p, log, clock = setup()
        w.procs[1390]["comm"] = "cat"
        p.handle(w.ev(EVENT_EXEC_OK, 1390, 21 * SEC, aux=20 * SEC))
        self.assertEqual(lines(log), [])
        clock.now += 3
        p.tick()
        self.assertEqual(lines(log)[0]["enter_seen"], False)

    def test_waits_for_end_marker(self):
        w, g, p, log, _ = setup()
        enter, a0, a1, end, ok = self.records(w)
        for r in (enter, a0, ok):
            p.handle(r)
        self.assertEqual(lines(log), [])            # END not seen yet
        p.handle(a1)
        p.handle(end)
        self.assertEqual(lines(log)[0]["argv"], self.ARGV)

    def test_argument_after_timeout_commit_is_patched_in(self):
        w, g, p, log, clock = setup()
        enter, a0, a1, end, ok = self.records(w)
        for r in (enter, a0, ok):
            p.handle(r)
        clock.now += 3
        p.tick()                                     # settled without END
        self.assertEqual(lines(log)[0]["argv"], ["cat"])
        p.handle(a1)
        p.handle(end)
        self.assertEqual(g.get(1390).execs[0].argv, self.ARGV)
        self.assertEqual(p.assembler.late_args, 2)

    def test_truncation_marker(self):
        w, g, p, log, _ = setup()
        argv = ["x%d" % i for i in range(MAXARG)]
        recs = w.exec_records(1390, 20 * SEC, 20 * SEC + 1, "/bin/echo", argv, "echo")
        recs[-2] = Arg(1390, MAXARG, 20 * SEC, "", ARG_FLAG_END | ARG_FLAG_TRUNCATED)
        for r in recs:
            p.handle(r)
        e = lines(log)[0]
        self.assertTrue(e["argv_truncated"])
        self.assertEqual(len(e["argv"]), MAXARG)

    def test_two_execs_same_pid(self):
        # bash -c 'exec cat' : one process, two program images
        w, g, p, log, _ = setup()
        for r in w.exec_records(1390, 20 * SEC, 20 * SEC + 1, "/bin/sh", ["sh"], "sh"):
            p.handle(r)
        for r in w.exec_records(1390, 20 * SEC + 2, 20 * SEC + 3, "/bin/cat", ["cat"], "cat"):
            p.handle(r)
        node = g.get(1390)
        self.assertEqual([x.filename for x in node.execs], ["/bin/sh", "/bin/cat"])
        self.assertEqual(node.key, (1390, 0))


class OpenExitTest(unittest.TestCase):
    def test_open_modes_and_failures(self):
        w, g, p, log, _ = setup()
        p.handle(w.open(1390, 21 * SEC, "/etc/hostname", os.O_RDONLY, 3))
        p.handle(w.open(1390, 22 * SEC, "/tmp/o", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 4))
        p.handle(w.open(1390, 23 * SEC, "/etc/shadow", os.O_RDONLY, -13))
        p.handle(w.open(1390, 24 * SEC, "rel.txt", os.O_RDWR, 5))
        out = lines(log)
        self.assertEqual([(e["mode"], e["ret"]) for e in out],
                         [("R", 3), ("W", 4), ("R", -13), ("RW", 5)])
        self.assertEqual([e["relative"] for e in out], [False, False, False, True])
        node = g.get(1390)
        self.assertEqual((node.file_count, node.failed_opens), (3, 1))
        self.assertEqual((p.counts["OPEN"], p.counts["OPEN_FAILED"]), (3, 1))

    def test_exit_status_decoding(self):
        w, g, p, log, _ = setup()
        p.handle(w.exit(1390, 30 * SEC, status=2 << 8))       # exit(2)
        p.handle(w.exit(1360, 31 * SEC, status=9))             # killed by SIGKILL
        out = lines(log)
        self.assertEqual((out[0]["exit_code"], out[0]["signal"]), (2, 0))
        self.assertEqual((out[1]["exit_code"], out[1]["signal"]), (0, 9))
        self.assertFalse(g.get(1390).alive)

    def test_log_line_fields_and_lineage(self):
        w, g, p, log, _ = setup()
        p.handle(w.open(1390, 21 * SEC, "/etc/hostname"))
        e = lines(log)[0]
        for k in ("type", "time", "ts_ns", "pid", "gen", "tid", "ppid", "uid",
                  "gid", "name", "thread", "start_ns", "lineage", "path"):
            self.assertIn(k, e)
        self.assertEqual(e["lineage"], "systemd(1) → bash(1360) → bash(1390)")

    def test_thread_name_vs_process_name(self):
        # Journal row 10: a worker thread showed up as "Thread (pooled)".
        w, g, p, log, _ = setup()
        w.spawn(700, 1, "pcmanfm-qt", 5 * SEC)
        ev = w.open(700, 21 * SEC, "/x.png")._replace(tid=705, tcomm="Thread (pooled)")
        p.handle(ev)
        e = lines(log)[0]
        self.assertEqual((e["name"], e["thread"], e["tid"]),
                         ("pcmanfm-qt", "Thread (pooled)", 705))


class FilterTest(unittest.TestCase):
    def test_name_filter_uses_new_program_name(self):
        # Journal row 9: --filter bash used to match `ls` launched from bash.
        w, g, p, log, _ = setup(name_filter="bash")
        for r in w.exec_records(1390, 20 * SEC, 20 * SEC + 1, "/bin/ls", ["ls"], "ls"):
            p.handle(r)
        self.assertEqual(lines(log), [])
        self.assertEqual(g.get(1390).comm, "ls")       # graph still updated

    def test_type_filter(self):
        w, g, p, log, _ = setup(type_filter="exit")
        p.handle(w.open(1390, 21 * SEC, "/etc/hostname"))
        p.handle(w.exit(1390, 22 * SEC))
        self.assertEqual([e["type"] for e in lines(log)], ["EXIT"])
        self.assertEqual(g.get(1390).file_count, 1)


class DecodeAndStatsTest(unittest.TestCase):
    def test_decode_round_trip(self):
        raw = events.encode_event(type=events.EVENT_OPEN, pid=5, tid=6, ppid=1,
                                  ret=-2, flags=os.O_WRONLY, ts_ns=7, start_ns=8,
                                  pstart_ns=9, comm="cat", tcomm="cat",
                                  pcomm="bash", filename="/tmp/ü")
        buf = ctypes.create_string_buffer(raw, len(raw))
        ev = events.decode(buf, len(raw))
        self.assertEqual((ev.pid, ev.ret, ev.flags, ev.filename, ev.pcomm),
                         (5, -2, os.O_WRONLY, "/tmp/ü", "bash"))
        raw = events.encode_arg(5, 3, 7, "--verbose")
        a = events.decode(ctypes.create_string_buffer(raw, len(raw)), len(raw))
        self.assertEqual(a, Arg(5, 3, 7, "--verbose", 0))
        raw = events.encode_arg(5, 4, 7, "", ARG_FLAG_END)
        a = events.decode(ctypes.create_string_buffer(raw, len(raw)), len(raw))
        self.assertEqual(a.flags, ARG_FLAG_END)

    def test_decode_rejects_garbage(self):
        buf = ctypes.create_string_buffer(b"\x09\x00\x00\x00" + b"\x00" * 400, 404)
        self.assertIsNone(events.decode(buf, 404))            # unknown type
        buf = ctypes.create_string_buffer(b"\x01\x00\x00\x00", 4)
        self.assertIsNone(events.decode(buf, 4))              # too short

    def test_full_filename_is_kept(self):
        long = "/" + "a" * 254                                  # 255 chars + NUL
        raw = events.encode_event(type=events.EVENT_OPEN, filename=long)
        ev = events.decode(ctypes.create_string_buffer(raw, len(raw)), len(raw))
        self.assertEqual(ev.filename, long)

    def test_loss_accounting(self):
        w, g, p, log, _ = setup()
        for i in range(90):
            p.handle(w.open(1390, 21 * SEC + i, "/f%d" % i))
        p.handle_lost(6)
        p.handle_lost(4)
        s = p.stats()
        self.assertEqual((s["records_received"], s["lost"], s["lost_bursts"]), (90, 10, 2))
        self.assertAlmostEqual(s["loss_rate"], 0.10)

    def test_clock_offset(self):
        import time
        c = events.Clock()
        mono = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        self.assertAlmostEqual(c.wall(mono), time.time(), delta=0.05)


if __name__ == "__main__":
    unittest.main()


class RobustnessProcessorTest(unittest.TestCase):
    def test_kernel_path_and_inode_preferred(self):
        w, g, p, log, _ = setup()
        recs = w.exec_records(1390, 20 * SEC, 20 * SEC + 1, "cat", ["cat"], "cat",
                              kernel_path="/usr/bin/cat",
                              ok_extra={"ino": 99, "dev": 8, "igen": 1})
        for r in recs:
            p.handle(r)
        e = lines(log)[0]
        self.assertEqual((e["path"], e["requested_path"], e["file"]),
                         ("/usr/bin/cat", "cat", "inode:8:99:1"))
        self.assertFalse(e["exec_from_fd"])
        self.assertIn("inode:8:99:1", g.files)

    def test_fileless_exec_detected(self):
        # memfd_create + fexecve -> execveat(fd, "", ..., AT_EMPTY_PATH)
        from hids.events import AT_EMPTY_PATH
        w, g, p, log, _ = setup()
        recs = w.exec_records(1390, 20 * SEC, 20 * SEC + 1, "", ["p15mem"], "3",
                              kernel_path="/dev/fd/3",
                              enter_extra={"dfd": 3, "flags": AT_EMPTY_PATH})
        for r in recs:
            p.handle(r)
        e = lines(log)[0]
        self.assertTrue(e["exec_from_fd"])
        self.assertEqual((e["path"], e["requested_path"]), ("/dev/fd/3", "fd3:"))
        self.assertEqual(p.counts["EXEC_FROM_FD"], 1)
        self.assertTrue(g.get(1390).execs[0].from_fd)

    def test_fileless_detected_without_kernel_path(self):
        from hids.events import AT_EMPTY_PATH
        w, g, p, log, _ = setup()
        for r in w.exec_records(1390, 20 * SEC, 20 * SEC + 1, "", ["x"], "x",
                                enter_extra={"dfd": 4, "flags": AT_EMPTY_PATH}):
            p.handle(r)
        self.assertTrue(lines(log)[0]["exec_from_fd"])

    def test_execveat_relative_path_display(self):
        w, g, p, log, clock = setup()
        p.handle(w.ev(EVENT_EXEC_ENTER, 1390, 20 * SEC, "tool", dfd=5))
        clock.now += 3
        p.tick()
        self.assertEqual(lines(log)[0]["path"], "fd5:tool")

    def test_relative_open_logged_but_unresolved(self):
        w, g, p, log, _ = setup()
        p.handle(w.open(1390, 21 * SEC, "lib", os.O_RDONLY | os.O_DIRECTORY, 4, dfd=3))
        e = lines(log)[0]
        self.assertEqual((e["path"], e["relative"], e["file"]), ("fd3:lib", True, None))
        self.assertEqual(g.get(1390).unresolved_opens, 1)

    def test_bad_record_does_not_stop_stream(self):
        w, g, p, log, _ = setup()
        p.handle(w.open(1390, 21 * SEC, "/a"))
        p.handle(object())                       # has no .type
        p.handle(w.open(1390, 22 * SEC, "/b"))
        self.assertEqual(p.counts["errors"], 1)
        self.assertIn("AttributeError", p.first_error)
        self.assertEqual([e["path"] for e in lines(log)], ["/a", "/b"])
        self.assertEqual(p.stats()["records"]["errors"], 1)

    def test_no_output_means_no_formatting(self):
        w = World()
        w.spawn(1, 0, "systemd", 1)
        w.spawn(5, 1, "sh", 2)
        g = ProcessGraph()
        from helpers import FakeClock
        p = EventProcessor(g, FakeClock())
        calls = []
        g.lineage_str = lambda n: calls.append(n) or ""
        p.handle(w.open(5, 3, "/x"))
        self.assertEqual((calls, p.counts["logged"], p.counts["OPEN"]), ([], 0, 1))
        self.assertEqual(g.get(5).file_count, 1)

    def test_late_truncation_and_done_cap(self):
        w, g, p, log, clock = setup()
        p.assembler.keep_done = 1
        enter, a0, a1, end, ok = ExecAssemblyTest().records(w)
        for r in (enter, a0, ok):
            p.handle(r)
        clock.now += 3
        p.tick()
        p.handle(Arg(1390, 20, enter.ts_ns, "", ARG_FLAG_END | ARG_FLAG_TRUNCATED))
        self.assertTrue(g.get(1390).execs[0].truncated)
        w.spawn(1400, 1360, "bash", 30 * SEC)
        for r in w.exec_records(1400, 30 * SEC + 1, 30 * SEC + 2, "/bin/ls", ["ls"], "ls"):
            p.handle(r)
        self.assertEqual(len(p.assembler.done), 1)      # oldest dropped

    def test_pending_cap(self):
        import hids.processor as proc_mod
        w, g, p, log, _ = setup()
        old = proc_mod.MAX_PENDING
        proc_mod.MAX_PENDING = 5
        try:
            for i in range(8):     # enters with no success: all will fail
                p.handle(w.ev(EVENT_EXEC_ENTER, 1390, 20 * SEC + i, "/x%d" % i))
            self.assertEqual(len(p.assembler.pending), 5)
            self.assertEqual(p.assembler.forced, 3)
            self.assertEqual(p.counts["EXEC_FAILED"], 3)
        finally:
            proc_mod.MAX_PENDING = old

    def test_expire_stops_at_first_fresh_record(self):
        w, g, p, log, clock = setup()
        p.handle(w.ev(EVENT_EXEC_ENTER, 1390, 20 * SEC, "/old"))
        clock.now += 3
        p.handle(w.ev(EVENT_EXEC_ENTER, 1390, 21 * SEC, "/new"))
        p.tick()
        self.assertEqual([e["path"] for e in lines(log)], ["/old"])
        self.assertEqual(len(p.assembler.pending), 1)


class ConnectTest(unittest.TestCase):
    """connect() handling: who talked to whom, and how the attempt ended."""

    def test_successful_tcp_connect(self):
        w, g, p, log, _ = setup()
        p.handle(w.connect(1390, 21 * SEC, "203.0.113.5", 443))
        e = lines(log)[0]
        self.assertEqual(e["type"], "CONNECT")
        self.assertEqual(e["endpoint"], "net:203.0.113.5:443")
        self.assertEqual((e["address"], e["port"], e["family"]),
                         ("203.0.113.5", 443, "ipv4"))
        self.assertFalse(e["pending"])
        self.assertEqual(e["lineage"], "systemd(1) → bash(1360) → bash(1390)")
        self.assertEqual(p.counts["CONNECT"], 1)
        self.assertEqual(g.get(1390).conn_count, 1)
        self.assertIn("net:203.0.113.5:443", g.endpoints)

    def test_refused_connect_is_counted_apart_and_creates_no_causal_edge(self):
        # A refused connect is evidence (scanning), but nothing flowed:
        # it must not become a path a root-cause walk can follow.
        w, g, p, log, _ = setup()
        p.handle(w.connect(1390, 21 * SEC, "10.0.0.9", 22, ret=-111))
        self.assertEqual(p.counts["CONNECT_FAILED"], 1)
        self.assertEqual(p.counts["CONNECT"], 0)
        node = g.get(1390)
        self.assertEqual((node.conn_count, node.failed_conns), (1, 1))
        ep = g.endpoints["net:10.0.0.9:22"]
        self.assertEqual((ep.access_count, ep.failed_count), (1, 1))
        # the parent chain is still there; what must NOT appear is a
        # CONNECT edge to a peer that refused the connection
        self.assertEqual([k for _, k, _, _ in g.trace_back(node)], ["FORK", "FORK"])
        self.assertNotIn("CONNECT", [k for _, k, _, _ in g.trace_forward(node)])

    def test_nonblocking_connect_is_neither_success_nor_failure(self):
        w, g, p, log, _ = setup()
        p.handle(w.connect(1390, 21 * SEC, "203.0.113.5", 443, pending=True))
        e = lines(log)[0]
        self.assertTrue(e["pending"])
        self.assertEqual(e["ret"], -115)
        self.assertEqual(p.counts["CONNECT_PENDING"], 1)
        self.assertEqual((p.counts["CONNECT"], p.counts["CONNECT_FAILED"]), (0, 0))
        # in flight still counts as a relationship: the socket was opened
        self.assertEqual(g.get(1390).failed_conns, 0)
        self.assertIn("net:203.0.113.5:443", g.endpoints)

    def test_ipv6_and_unix_sockets(self):
        w, g, p, log, _ = setup()
        p.handle(w.connect(1390, 21 * SEC, "2001:db8::1", 80))
        p.handle(w.connect(1390, 22 * SEC, path="/run/docker.sock"))
        p.handle(w.connect(1390, 23 * SEC, path="\x00dbus-abstract"))
        out = lines(log)
        self.assertEqual([e["endpoint"] for e in out],
                         ["net:[2001:db8::1]:80", "unix:/run/docker.sock",
                          "unix:@dbus-abstract"])
        self.assertEqual([e["family"] for e in out], ["ipv6", "unix", "unix"])
        self.assertEqual(p.counts["CONNECT_UNIX"], 2)

    def test_unnamed_socket_is_counted_but_gets_no_node(self):
        # connect() on an unnamed unix socket identifies no peer; inventing a
        # node for it would merge unrelated connections.
        w, g, p, log, _ = setup()
        p.handle(w.connect(1390, 21 * SEC, path="", family=AF_UNIX))
        self.assertEqual(g.endpoints, {})
        self.assertEqual(g.get(1390).conn_count, 1)
        self.assertEqual(lines(log)[0]["endpoint"], None)

    def test_same_peer_from_two_processes_is_one_node(self):
        w, g, p, log, _ = setup()
        p.handle(w.connect(1390, 21 * SEC, "203.0.113.5", 443))
        p.handle(w.connect(1360, 22 * SEC, "203.0.113.5", 443))
        self.assertEqual(len(g.endpoints), 1)
        ep = g.endpoints["net:203.0.113.5:443"]
        self.assertEqual(ep.access_count, 2)
        self.assertEqual({k for _, k, _ in ep.accesses}, {(1390, 0), (1360, 0)})

    def test_port_distinguishes_endpoints(self):
        w, g, p, log, _ = setup()
        p.handle(w.connect(1390, 21 * SEC, "203.0.113.5", 443))
        p.handle(w.connect(1390, 22 * SEC, "203.0.113.5", 8080))
        self.assertEqual(sorted(g.endpoints),
                         ["net:203.0.113.5:443", "net:203.0.113.5:8080"])

    def test_type_filter_applies_to_connect(self):
        w, g, p, log, _ = setup(type_filter="connect")
        p.handle(w.open(1390, 21 * SEC, "/etc/hostname"))
        p.handle(w.connect(1390, 22 * SEC, "203.0.113.5", 443))
        self.assertEqual([e["type"] for e in lines(log)], ["CONNECT"])
        self.assertEqual(g.get(1390).file_count, 1)   # graph still updated


class AcceptTest(unittest.TestCase):
    """accept() handling: who reached in, on which socket."""

    def test_accepted_connection_is_recorded_as_inbound(self):
        w, g, p, log, _ = setup()
        p.handle(w.accept(1390, 21 * SEC, "10.0.0.9", peer_port=45192,
                          listen_fd=3, conn_fd=7))
        e = lines(log)[0]
        self.assertEqual(e["type"], "ACCEPT")
        self.assertEqual(e["endpoint"], "host:10.0.0.9")
        self.assertEqual((e["address"], e["family"]), ("10.0.0.9", "ipv4"))
        # the ephemeral source port is kept in the record for forensics even
        # though it is deliberately not part of the endpoint id
        self.assertEqual(e["peer_port"], 45192)
        self.assertEqual((e["listen_fd"], e["conn_fd"]), (3, 7))
        self.assertTrue(e["peer_known"])
        self.assertEqual(p.counts["ACCEPT"], 1)
        self.assertEqual(g.get(1390).accept_count, 1)

    def test_one_record_type_carries_both_directions(self):
        # Inbound and outbound arrive in the same struct, told apart by a
        # flag: a connect record must never be counted as an accept.
        w, g, p, _log, _ = setup()
        p.handle(w.connect(1390, 21 * SEC, "10.0.0.9", 443))
        p.handle(w.accept(1390, 22 * SEC, "10.0.0.9", peer_port=45192))
        self.assertEqual((p.counts["CONNECT"], p.counts["ACCEPT"]), (1, 1))
        node = g.get(1390)
        self.assertEqual((node.conn_count, node.accept_count), (1, 1))
        self.assertEqual(sorted(g.endpoints),
                         ["host:10.0.0.9", "net:10.0.0.9:443"])

    def test_accept_without_a_peer_name_says_so(self):
        # accept(fd, NULL, NULL): a real connection the kernel cannot name.
        w, g, p, log, _ = setup()
        p.handle(w.accept(1390, 21 * SEC, nopeer=True))
        e = lines(log)[0]
        self.assertFalse(e["peer_known"])
        self.assertIsNone(e["endpoint"])
        self.assertEqual(p.counts["ACCEPT_NOPEER"], 1)
        self.assertEqual(g.get(1390).nopeer_accepts, 1)
        self.assertEqual(g.endpoints, {})       # nothing invented

    def test_ipv6_inbound_id_is_bracketed_so_it_can_be_parsed_back(self):
        # `host:::1` is not splittable into scheme and address by anything —
        # a person typing it into a query, or us parsing it later. Brackets
        # are what the outbound id and every other tool use.
        w, g, p, log, _ = setup()
        p.handle(w.accept(1390, 21 * SEC, "::1", peer_port=45192))
        self.assertEqual(lines(log)[0]["endpoint"], "host:[::1]")
        self.assertIn("host:[::1]", g.endpoints)

    def test_unix_accept_is_counted_as_local_ipc(self):
        w, g, p, log, _ = setup()
        p.handle(w.accept(1390, 21 * SEC, path="/run/p15.sock"))
        e = lines(log)[0]
        self.assertEqual(e["endpoint"], "unix:/run/p15.sock")
        self.assertEqual(p.counts["ACCEPT_UNIX"], 1)

    def test_many_connections_from_one_host_make_one_endpoint(self):
        w, g, p, _log, _ = setup()
        for i, port in enumerate((45192, 45193, 51022, 60001)):
            p.handle(w.accept(1390, (21 + i) * SEC, "10.0.0.9", peer_port=port))
        self.assertEqual(list(g.endpoints), ["host:10.0.0.9"])
        self.assertEqual(p.counts["ACCEPT"], 4)
        self.assertEqual(g.summary()["inbound_hosts"], 1)

    def test_inbound_filter_selects_only_accepts(self):
        w, _g, p, log, _ = setup(type_filter="accept")
        p.handle(w.connect(1390, 21 * SEC, "10.0.0.9", 443))
        p.handle(w.accept(1390, 22 * SEC, "10.0.0.9", peer_port=45192))
        self.assertEqual([e["type"] for e in lines(log)], ["ACCEPT"])


class SocketTypeAndProbeTest(unittest.TestCase):
    """Telling a real connection apart from a name-resolution probe.

    glibc's getaddrinfo() connects a UDP socket to each candidate address
    with port 0 so the kernel picks a source address (RFC 3484 sorting).
    Verified with strace, and seen on the VM as Firefox 'connecting' to
    several addresses on port 0 right after a DNS lookup.
    """

    def test_udp_port_zero_is_counted_as_a_probe(self):
        w, g, p, log, _ = setup()
        p.handle(w.connect(1390, 21 * SEC, "180.149.52.211", 0,
                           sock_type=events.SOCK_DGRAM))
        e = lines(log)[0]
        self.assertTrue(e["probe"])
        self.assertEqual(e["socket"], "dgram")
        self.assertEqual(p.counts["CONNECT_PROBE"], 1)
        self.assertEqual(p.counts["CONNECT"], 1)   # still a real syscall

    def test_a_real_tcp_connection_is_not_a_probe(self):
        w, g, p, log, _ = setup()
        p.handle(w.connect(1390, 21 * SEC, "203.0.113.5", 443,
                           sock_type=events.SOCK_STREAM))
        e = lines(log)[0]
        self.assertFalse(e["probe"])
        self.assertEqual(e["socket"], "stream")
        self.assertEqual(p.counts["CONNECT_PROBE"], 0)

    def test_tcp_to_port_zero_is_not_called_a_probe(self):
        # port 0 on a STREAM socket is not the resolver pattern
        w, g, p, log, _ = setup()
        p.handle(w.connect(1390, 21 * SEC, "203.0.113.5", 0,
                           sock_type=events.SOCK_STREAM))
        self.assertFalse(lines(log)[0]["probe"])

    def test_unknown_socket_type_still_flags_the_pattern(self):
        # SOCKET_TYPE refused by the verifier: type is 0, so the port-0
        # pattern alone has to carry it, and the field stays empty rather
        # than being guessed.
        w, g, p, log, _ = setup()
        p.handle(w.connect(1390, 21 * SEC, "180.149.52.211", 0, sock_type=0))
        e = lines(log)[0]
        self.assertTrue(e["probe"])
        self.assertEqual(e["socket"], "")

    def test_unix_socket_is_never_a_probe(self):
        w, g, p, log, _ = setup()
        p.handle(w.connect(1390, 21 * SEC, path="/run/docker.sock",
                           sock_type=events.SOCK_STREAM))
        self.assertFalse(lines(log)[0]["probe"])
