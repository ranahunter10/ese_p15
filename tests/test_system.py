"""/proc parsing, the live view, the query CLI, and monitor.main() end to end
with a fake BCC module (everything except the real kernel)."""

import ctypes
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

from helpers import SEC, World
from hids import events, monitor, procstat, view
from hids.events import ARG_FLAG_END
from hids.graph import ProcessGraph
from hids.processor import EventProcessor
from hids.view import make_printer, render

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


class ProcStatTest(unittest.TestCase):
    def test_parse_awkward_comm(self):
        line = ("4242 (a) b (x)) S 1 4242 4242 0 -1 4194560 100 0 0 0 "
                "250 50 0 0 20 0 1 0 12345 1000000 321 18446744073709551615")
        st = procstat.parse_stat(line)
        self.assertEqual((st["pid"], st["comm"], st["state"], st["ppid"]),
                         (4242, "a) b (x)", "S", 1))
        self.assertEqual((st["utime"], st["stime"], st["starttime"], st["rss_pages"]),
                         (250, 50, 12345, 321))

    def test_scan_real_proc(self):
        me = [p for p in procstat.scan() if p["pid"] == os.getpid()]
        self.assertEqual(len(me), 1)
        self.assertEqual(me[0]["ppid"], os.getppid())
        self.assertEqual(me[0]["uid"], os.getuid())
        self.assertGreater(me[0]["start_ns"], 0)

    def test_scan_matches_parent_start(self):
        # our own start estimate must be later than our parent's
        procs = {p["pid"]: p for p in procstat.scan()}
        me, parent = procs[os.getpid()], procs.get(os.getppid())
        if parent:
            self.assertGreaterEqual(me["start_ns"], parent["start_ns"])

    def test_sampler_measures_busy_child(self):
        child = subprocess.Popen([sys.executable, "-c", "while True: pass"])
        try:
            g = ProcessGraph()
            node = g.process(child.pid, 1, 0, 0, "busy", "", 0, 1)
            s = procstat.ResourceSampler()
            s.sample([node])
            import time
            time.sleep(0.5)
            s.sample([node])
            self.assertGreater(node.cpu_percent, 30.0)
            self.assertGreater(node.rss_kb, 0)
        finally:
            child.kill()
            child.wait()

    def test_sampler_ignores_vanished_and_resets_on_reuse(self):
        g = ProcessGraph()
        node = g.process(os.getpid(), 1, 0, 0, "me", "", 0, 1)
        s = procstat.ResourceSampler()
        s.sample([node])
        key = node.key
        ticks, when, start = s.prev[key]
        s.prev[key] = (ticks, when, start + 1)      # pretend PID changed hands
        node.cpu_percent = 99.0
        s.sample([node])
        self.assertEqual(node.cpu_percent, 99.0)    # not computed from mixed data
        ghost = g.process(2 ** 22 + 7, 1, 0, 0, "ghost", "", 0, 1)
        s.sample([ghost])
        self.assertNotIn(ghost.key, s.prev)


class ViewTest(unittest.TestCase):
    def test_render_and_printer(self):
        w = World()
        w.spawn(1, 0, "systemd", 1 * SEC)
        w.spawn(10, 1, "bash", 2 * SEC)
        g = ProcessGraph()
        from helpers import FakeClock
        p = EventProcessor(g, FakeClock(), printer=None)
        for r in w.exec_records(10, 3 * SEC, 3 * SEC + 1, "/bin/sleep", ["sleep", "5"], "sleep"):
            p.handle(r)
        text = render(g, p.stats(), 4 * SEC, 2.0, color=False)
        self.assertIn("sleep 5", text)
        self.assertIn("  sleep(10)", text)
        self.assertIn("ESE-P15 HIDS monitor v3", text)
        out = io.StringIO()
        make_printer(color=False, stream=out)({
            "type": "EXEC", "time": "t", "name": "sleep", "pid": 10,
            "argv": ["sleep", "5"], "lineage": "systemd(1) → sleep(10)", "path": "/bin/sleep"})
        self.assertIn("sleep 5", out.getvalue())


def fake_bcc(script):
    """A stand-in for the bcc module that replays `script` (a list of raw
    byte records or ('lost', n)) through the same callbacks BCC would use."""
    mod = types.ModuleType("bcc")

    class Table:
        def open_perf_buffer(self, cb, page_cnt, lost_cb):
            FakeBPF.cb, FakeBPF.lost, FakeBPF.pages = cb, lost_cb, page_cnt

    class FakeBPF:
        text = None
        polls = 0

        def __init__(self, text):
            FakeBPF.text = text

        @staticmethod
        def tracepoint_exists(cat, ev):
            return True

        def __getitem__(self, name):
            assert name == "events"
            return Table()

        def perf_buffer_poll(self, timeout):
            FakeBPF.polls += 1
            if script:
                item = script.pop(0)
                if isinstance(item, tuple):
                    FakeBPF.lost(item[1])
                else:
                    buf = ctypes.create_string_buffer(item, len(item))
                    FakeBPF.cb(0, buf, len(item))
            else:
                monitor.shutdown_requested = True   # like pressing Ctrl+C

    mod.BPF = FakeBPF
    return mod, FakeBPF


class PrinterTest(unittest.TestCase):
    def test_every_event_type(self):
        from hids.view import describe
        base = {"time": "t", "name": "x", "pid": 1, "lineage": "l"}
        self.assertEqual(describe(dict(base, type="EXEC", argv=["ls", "-l"])), "ls -l")
        self.assertEqual(describe(dict(base, type="EXEC", argv=[], path="/bin/ls",
                                       exec_from_fd=True)), "/bin/ls   [EXEC FROM FD]")
        self.assertEqual(describe(dict(base, type="OPEN", mode="R", path="/a", ret=3)),
                         "R /a -> 3")
        self.assertEqual(describe(dict(base, type="EXIT", exit_code=2, signal=0)),
                         "code=2 signal=0")
        self.assertEqual(describe(dict(base, type="EXEC_FAILED", path="/nope")), "/nope")
        out = io.StringIO()
        make_printer(color=True, stream=out)(dict(base, type="EXIT", exit_code=0, signal=9))
        self.assertIn("\033[93mEXIT", out.getvalue())
        self.assertIn("code=0 signal=9", out.getvalue())


class MonitorEndToEndTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        monitor.shutdown_requested = False

    def tearDown(self):
        shutil.rmtree(self.dir)
        monitor.shutdown_requested = False

    def script(self):
        me = os.getpid()
        base = dict(ppid=os.getppid(), uid=0, gid=0, pstart_ns=1, pcomm="shell")
        s = [
            events.encode_event(type=events.EVENT_EXEC_ENTER, pid=me + 1, tid=me + 1,
                                ts_ns=100, start_ns=50, comm="bash", tcomm="bash",
                                filename="/usr/bin/cat", **base),
            events.encode_arg(me + 1, 0, 100, "cat"),
            events.encode_arg(me + 1, 1, 100, "/etc/hostname"),
            ("lost", 3),
            events.encode_arg(me + 1, 2, 100, "", ARG_FLAG_END),
            events.encode_event(type=events.EVENT_EXEC_OK, pid=me + 1, tid=me + 1,
                                ts_ns=150, start_ns=50, aux_ns=100, comm="cat",
                                tcomm="cat", **base),
            events.encode_event(type=events.EVENT_OPEN, pid=me + 1, tid=me + 1,
                                ts_ns=160, start_ns=50, comm="cat", tcomm="cat",
                                filename="/etc/hostname", ret=3, **base),
            events.encode_net(pid=me + 1, tid=me + 1, ts_ns=165, start_ns=50,
                              comm="cat", tcomm="cat", family=events.AF_INET,
                              daddr=socket.inet_aton("203.0.113.5"), dport=443,
                              fd=4, ret=0, **base),
            events.encode_net(pid=me + 1, tid=me + 1, ts_ns=166, start_ns=50,
                              comm="cat", tcomm="cat", family=events.AF_INET,
                              daddr=socket.inet_aton("10.0.0.9"), dport=22,
                              fd=5, ret=-111, **base),
            # an INBOUND connection, same struct, flagged: ret is the new
            # connection fd (7), dport is the peer's ephemeral source port
            events.encode_net(pid=me + 1, tid=me + 1, ts_ns=167, start_ns=50,
                              comm="cat", tcomm="cat", family=events.AF_INET,
                              daddr=socket.inet_aton("10.0.0.9"), dport=45192,
                              fd=6, ret=7,
                              nflags=events.NET_FLAG_INBOUND, **base),
            events.encode_event(type=events.EVENT_EXIT, pid=me + 1, tid=me + 1,
                                ts_ns=170, start_ns=50, comm="cat", tcomm="cat", **base),
            b"\x07\x00",                         # garbage
        ]
        return s

    def run_main(self, extra):
        mod, fake = fake_bcc(self.script())
        log = os.path.join(self.dir, "run.jsonl")
        stats = os.path.join(self.dir, "stats.json")
        snap = os.path.join(self.dir, "graph.json")
        argv = ["--mode", "quiet", "--logfile", log, "--stats-json", stats,
                "--snapshot", snap] + extra
        with mock.patch.dict(sys.modules, {"bcc": mod}), \
                mock.patch("os.geteuid", return_value=0), \
                mock.patch("sys.stdout", new=io.StringIO()):
            monitor.main(argv)
        with open(stats) as f:
            st = json.load(f)
        lines, g = [], None
        if os.path.exists(log):
            with open(log) as f:
                lines = [json.loads(l) for l in f]
        if os.path.exists(snap):
            with open(snap) as f:
                g = ProcessGraph.from_dict(json.load(f))
        return fake, st, lines, g

    def test_full_pipeline(self):
        fake, st, lines, g = self.run_main(["--pages", "128"])
        self.assertIn("#define SELF_TGID %d\n" % os.getpid(), fake.text)
        self.assertEqual(fake.pages, 128)
        self.assertEqual([l["type"] for l in lines],
                         ["EXEC", "OPEN", "CONNECT", "CONNECT", "ACCEPT", "EXIT"])
        conn = [l for l in lines if l["type"] == "CONNECT"]
        self.assertEqual([c["endpoint"] for c in conn],
                         ["net:203.0.113.5:443", "net:10.0.0.9:22"])
        self.assertEqual(st["records"]["CONNECT"], 1)
        self.assertEqual(st["records"]["CONNECT_FAILED"], 1)
        # the inbound record went through the same bytes, the same decode and
        # the same perf buffer, and came out the other side as an accept
        acc = [l for l in lines if l["type"] == "ACCEPT"][0]
        self.assertEqual(acc["endpoint"], "host:10.0.0.9")     # no port in the id
        self.assertEqual((acc["peer_port"], acc["conn_fd"]), (45192, 7))
        self.assertEqual(st["records"]["ACCEPT"], 1)
        self.assertEqual(st["graph"]["endpoints"], 3)
        self.assertEqual(st["graph"]["inbound_hosts"], 1)
        self.assertEqual(lines[0]["argv"], ["cat", "/etc/hostname"])
        self.assertEqual(st["lost"], 3)
        self.assertEqual(st["records"]["undecodable"], 1)
        self.assertEqual(st["records_received"], 11)
        self.assertAlmostEqual(st["loss_rate"], 3 / 14.0)
        for k in ("monitor_cpu_percent_of_one_core", "monitor_maxrss_kb",
                  "duration_s", "kernel", "bpf_compile_s"):
            self.assertIn(k, st)
        cat = g.get(os.getpid() + 1)
        self.assertEqual((cat.comm, cat.alive, cat.cmdline),
                         ("cat", False, "cat /etc/hostname"))
        # bootstrap ran: our own real parent chain is in the graph
        self.assertIsNotNone(g.get(os.getppid()))

    def test_no_bootstrap_and_duration(self):
        fake, st, lines, g = self.run_main(["--no-bootstrap", "--duration", "0.0001"])
        self.assertIsNone(g.get(1))
        self.assertLess(st["duration_s"], 5)

    def test_count_sink_and_batching(self):
        fake, st, lines, g = self.run_main(["--sink", "count", "--batch-ms", "1",
                                            "--hooks", "open,exit"])
        self.assertEqual(st["sink"], "count")
        self.assertEqual(st["hooks"], ["open", "exit"])
        self.assertEqual(st["records_received"], 11)  # all raw records, incl. garbage
        self.assertEqual(st["records"]["OPEN"], 0)    # nothing processed
        self.assertIn("#define HOOK_OPEN 1", fake.text)
        self.assertNotIn("#define HOOK_EXEC", fake.text)
        self.assertEqual(lines, [])                   # count implies no log
        self.assertIsNone(g)                          # ...and no snapshot

    def test_feature_fallback(self):
        mod, fake = fake_bcc(self.script())
        real_init = fake.__init__

        def picky(self_, text):
            if "#define KERNEL_EXEC_PATH" in text:
                raise Exception("bpf: Failed to load program: Permission denied")
            real_init(self_, text)
        fake.__init__ = picky
        stats = os.path.join(self.dir, "s.json")
        with mock.patch.dict(sys.modules, {"bcc": mod}), \
                mock.patch("os.geteuid", return_value=0), \
                mock.patch("sys.stdout", new=io.StringIO()):
            monitor.main(["--mode", "quiet", "--no-log", "--stats-json", stats])
        with open(stats) as f:
            st = json.load(f)
        self.assertEqual(st["features"], ["FILE_IDENTITY"])
        # every richer set is tried first, and each refusal is recorded with
        # the reason, so a run always says which feature it actually had
        self.assertEqual(st["features_refused"][0][0],
                         ["KERNEL_EXEC_PATH", "FILE_IDENTITY", "SOCKET_TYPE"])
        self.assertEqual(st["features_refused"][1][0],
                         ["KERNEL_EXEC_PATH", "FILE_IDENTITY"])
        self.assertIn("Permission denied", st["features_refused"][0][1])

    def test_nothing_loads(self):
        mod, fake = fake_bcc([])

        def never(self_, text):
            raise Exception("compile error")
        fake.__init__ = never
        with mock.patch.dict(sys.modules, {"bcc": mod}), \
                mock.patch("os.geteuid", return_value=0), \
                mock.patch("sys.stdout", new=io.StringIO()), \
                self.assertRaises(SystemExit) as cm:
            monitor.main(["--mode", "quiet", "--no-log"])
        self.assertIn("could not be loaded", str(cm.exception))

    def test_stats_written_even_if_loop_crashes(self):
        mod, fake = fake_bcc([])

        def boom(self_, timeout):
            raise RuntimeError("poll exploded")
        fake.perf_buffer_poll = boom
        stats = os.path.join(self.dir, "s.json")
        with mock.patch.dict(sys.modules, {"bcc": mod}), \
                mock.patch("os.geteuid", return_value=0), \
                mock.patch("sys.stdout", new=io.StringIO()), \
                self.assertRaises(RuntimeError):
            monitor.main(["--mode", "quiet", "--no-log", "--stats-json", stats])
        with open(stats) as f:
            self.assertIn("poll exploded", json.load(f)["crash"])

    def test_view_mode_draws(self):
        mod, fake = fake_bcc(self.script())
        screen = io.StringIO()
        screen.isatty = lambda: True
        with mock.patch.dict(sys.modules, {"bcc": mod}), \
                mock.patch("os.geteuid", return_value=0), \
                mock.patch("sys.stdout", new=screen):
            monitor.main(["--mode", "view", "--no-log", "--refresh", "0", "--no-color"])
        text = screen.getvalue()
        self.assertIn("ESE-P15 HIDS monitor v3", text)
        # The screen used to be blanked with \033[2J before every frame, which
        # flickers. It now takes the alternate screen once and repaints in
        # place: cursor home, erase each line as it is rewritten, erase what
        # is left below. Asserted end to end because getting this wrong is
        # invisible to a unit test of render().
        self.assertIn(view.ALT_ON, text)               # took the alternate screen
        self.assertIn(view.HIDE_CURSOR, text)
        self.assertIn(view.EOL, text)                  # per-line erase, not a blank
        self.assertNotIn("\033[2J", text)              # never blanks the display
        # And gave the terminal back. Without this the user is left on a
        # screen with no scrollback and no cursor.
        self.assertIn(view.SHOW_CURSOR, text)
        self.assertIn(view.ALT_OFF, text)
        # The summary has to land on the NORMAL screen, after the alternate
        # one is released, or it disappears with it.
        self.assertLess(text.index(view.ALT_OFF), text.index("Stopped after"))

    def test_bad_hooks_rejected(self):
        with self.assertRaises(SystemExit), mock.patch("sys.stderr", new=io.StringIO()):
            monitor.parse_args(["--hooks", "exec,sockets"])
        self.assertEqual(monitor.parse_args(["--hooks", "exit,exec"]).hooks, ("exec", "exit"))
        # hooks come back in a fixed order whatever order they were given,
        # so a run's stats and a cost comparison name the same set the same way
        self.assertEqual(monitor.parse_args(["--hooks", "net,exec"]).hooks, ("exec", "net"))
        self.assertEqual(monitor.parse_args([]).hooks, ("exec", "open", "exit", "net"))

    def test_walk_trace_runs_every_built_in_demo(self):
        """The study guide quotes this tool's output, so it has to run.

        Each demo is also a scenario the guide explains, so a demo that
        stopped producing the documented shape would leave the guide
        teaching something the code no longer does.
        """
        tool = os.path.join(ROOT, "tools", "walk_trace.py")
        sys.path.insert(0, os.path.join(ROOT, "tools"))
        import walk_trace
        for name in sorted(walk_trace.DEMOS):
            out = subprocess.check_output(
                [sys.executable, tool, "--demo", name]).decode()
            self.assertIn("START", out, name)
            self.assertIn("STOP", out, name)
            self.assertIn("result, as the caller sees it", out, name)
        # the two shapes the guide leans on hardest
        two = subprocess.check_output(
            [sys.executable, tool, "--demo", "two-reads-two-writers"]).decode()
        self.assertEqual(two.count("POP        /tmp/g"), 2)
        self.assertIn("1 of 2", two)
        fwd = subprocess.check_output(
            [sys.executable, tool, "--demo", "forward-time-bound"]).decode()
        self.assertIn("forked BEFORE the bound", fwd)

    def test_type_filter_offers_every_event_type_that_is_emitted(self):
        """A drift guard, not a behaviour test.

        `--type` filters the JSONL log by the event-type string the
        processor emits, so the two lists must stay in step. v3.4 added
        CONNECT events and forgot the choice, which made connections
        unfilterable with no error message anywhere (review, minor finding
        1). Comparing the two lists mechanically is the only way this stops
        happening every time a record type is added.
        """
        import re
        with open(os.path.join(ROOT, "hids", "processor.py")) as f:
            src = f.read()
        emitted = set(re.findall(r'self\._emit\(\s*"([A-Z_]+)"', src))
        with open(os.path.join(ROOT, "hids", "monitor.py")) as f:
            parser_src = f.read()
        m = re.search(r'"--type".*?choices=\[([^\]]*)\]', parser_src, re.S)
        choices = set(x.strip().strip('"').upper() for x in m.group(1).split(","))
        choices.discard("")                      # "" means "no filter"
        self.assertEqual(choices, emitted,
                         "--type choices and emitted event types have drifted")
        # and the filter actually works for the newest type
        self.assertEqual(monitor.parse_args(["-t", "connect"]).type, "connect")

    def test_bad_pages_rejected(self):
        with self.assertRaises(SystemExit), mock.patch("sys.stderr", new=io.StringIO()):
            monitor.parse_args(["--pages", "100"])

    def test_requires_root(self):
        with mock.patch("os.geteuid", return_value=1000), self.assertRaises(SystemExit) as cm:
            monitor.main(["--mode", "quiet"])
        self.assertIn("root", str(cm.exception))


STARTUP_PROBE = r"""
import os, sys, time, types
sys.path.insert(0, sys.argv[1])
console = sys.argv[2]
bcc = types.ModuleType("bcc")
class Table:
    def open_perf_buffer(self, cb, page_cnt, lost_cb): pass
class BPF:
    def __init__(self, text): pass
    @staticmethod
    def tracepoint_exists(c, e): return True
    def __getitem__(self, n): return Table()
    def perf_buffer_poll(self, timeout):
        # Like vm_validation.sh: wait until the console FILE shows the line.
        from hids import monitor
        deadline = time.time() + 5
        while time.time() < deadline:
            with open(console) as f:
                if "Hooks attached" in f.read():
                    monitor.shutdown_requested = True
                    return
            time.sleep(0.05)
        sys.exit(42)
bcc.BPF = BPF
sys.modules["bcc"] = bcc
os.geteuid = lambda: 0
from hids import monitor
monitor.main(["--mode", "quiet", "--no-log", "--no-bootstrap"])
"""


class StartupOutputTest(unittest.TestCase):
    def test_ready_line_reaches_a_redirected_stdout(self):
        # Regression: on the VM, stdout went to a file, "Hooks attached" sat
        # in Python's buffer, and vm_validation.sh gave up after 60 s.
        d = tempfile.mkdtemp()
        try:
            console = os.path.join(d, "console.txt")
            with open(console, "w") as out:
                env = dict(os.environ)
                env.pop("PYTHONUNBUFFERED", None)
                rc = subprocess.call([sys.executable, "-c", STARTUP_PROBE, ROOT, console],
                                     stdout=out, stderr=subprocess.STDOUT, env=env)
            with open(console) as f:
                output = f.read()
            self.assertEqual(rc, 0, output)
        finally:
            shutil.rmtree(d)


class QueryToolTest(unittest.TestCase):
    def test_cli(self):
        from test_graph import ProvenanceTest
        g, *_ = ProvenanceTest().build()
        d = tempfile.mkdtemp()
        try:
            snap = os.path.join(d, "g.json")
            with open(snap, "w") as f:
                json.dump(g.to_dict(), f)
            tool = os.path.join(ROOT, "tools", "query_graph.py")

            def q(*args):
                return subprocess.check_output([sys.executable, tool, snap] + list(args)).decode()
            self.assertIn("curl(100)", q("trace", "300"))
            self.assertIn("bash(300)", q("impact", "100"))
            self.assertIn("systemd(1) → curl(100)", q("writers", "/tmp/payload.sh"))
            self.assertIn("W  /tmp/payload.sh", q("files", "100"))
            self.assertIn('"processes": 5', q("summary"))
            self.assertIn("systemd(1)", q("tree"))
            self.assertIn("curl(100)", q("trace", "300", "--no-libs"))
            self.assertIn("gen=0", q("gens", "100"))

            # network commands, on a snapshot that has endpoints
            from test_graph import EndpointTest
            g2, _, _ = EndpointTest().build()
            scanner = g2.process(500, 50 * 10**9, 1, 1, "nmap", "systemd", 0, 50 * 10**9)
            for port in (22, 23, 445):
                g2.record_connect(scanner, 51 * 10**9, "net:10.0.0.9:%d" % port, False)
            snap2 = os.path.join(d, "g2.json")
            with open(snap2, "w") as f:
                json.dump(g2.to_dict(), f)

            def q2(*args):
                return subprocess.check_output(
                    [sys.executable, tool, snap2] + list(args)).decode()
            self.assertIn("net:203.0.113.5:443", q2("peers", "100"))
            self.assertIn("curl(100)", q2("talkers", "net:203.0.113.5:443"))
            self.assertIn("net:203.0.113.5:443", q2("endpoints"))
            scans = q2("scans")
            self.assertIn("nmap(500)", scans)
            self.assertIn("3 failed attempts", scans)
            self.assertIn("CONNECT", q2("trace", "200"))      # chain reaches the peer

            # inbound: a snapshot with accepted connections
            from test_graph import InboundTest
            g3, sshd, _ = InboundTest().build()
            g3.record_accept(sshd, 25 * 10**9, "host:10.0.0.9")
            snap3 = os.path.join(d, "g3.json")
            with open(snap3, "w") as f:
                json.dump(g3.to_dict(), f)

            def q3(*args):
                return subprocess.check_output(
                    [sys.executable, tool, snap3] + list(args)).decode()
            inbound = q3("inbound")
            self.assertIn("host:10.0.0.9", inbound)
            self.assertIn("2 connections, 1 process(es)", inbound)
            self.assertIn("systemd(1) → sshd(900)", inbound)
            self.assertIn("accepted   in   host:10.0.0.9", q3("peers", "900"))
            self.assertIn("in ", q3("endpoints"))        # direction column
            self.assertIn("no accepted inbound", q2("inbound"))   # none here

            # point-in-time questions, from the CLI: as of 150 s only the
            # first writer had touched the file (the API-only version of
            # this was the review's P1 item)
            at = q("trace", "300", "--at", "31")
            self.assertIn("as of 31.000s", at)
            self.assertIn("/home/u/.bashrc", at)
            self.assertNotIn("curl(100)", q("trace", "300", "--at", "21"))
            self.assertIn("curl(100)", q("trace", "300"))
            r = subprocess.run([sys.executable, tool, snap, "summary", "--at", "5"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(r.returncode, 2)      # --at is not a summary option
            r = subprocess.run([sys.executable, tool, snap2, "talkers", "net:0.0.0.0:1"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertNotEqual(r.returncode, 0)
            for bad in (["trace"], ["lineage", "abc"]):
                r = subprocess.run([sys.executable, tool, snap] + bad,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertEqual(r.returncode, 2)
                self.assertIn(b"needs", r.stderr)
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
