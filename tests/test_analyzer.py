"""tools/analyze_run.py on a synthetic validation folder built through the
real EventProcessor, so a broken analyzer can't put wrong numbers in a deck."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from helpers import SEC, FakeClock, World
from hids.events import AF_UNIX, EVENT_EXEC_ENTER
from hids.graph import ProcessGraph
from hids.processor import EventProcessor

TOOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools", "analyze_run.py")
MON = 4242


def run_scenario(d, name, story, stats_extra=None):
    w = World()
    w.spawn(1, 0, "systemd", 1)
    w.spawn(100, 1, "bash", 2)
    g = ProcessGraph()
    g.bootstrap([{"pid": 1, "ppid": 0, "comm": "systemd", "uid": 0, "start_ns": 1},
                 {"pid": 100, "ppid": 1, "comm": "bash", "uid": 0, "start_ns": 2}], 0)
    clock = FakeClock()
    with open(os.path.join(d, name + ".jsonl"), "w") as log:
        p = EventProcessor(g, clock, log_file=log, mono=clock)
        story(w, p)
        clock.now += 5
        p.tick(force=True)
    st = p.stats()
    st.update({"monitor_pid": MON, "cpus": 2, "records_per_s": 1.0,
               "monitor_cpu_percent_of_one_core": 3.0, "monitor_maxrss_kb": 90000,
               "bpf_compile_s": 4.0, "features": ["KERNEL_EXEC_PATH", "FILE_IDENTITY"],
               "features_refused": []})
    st.update(stats_extra or {})
    with open(os.path.join(d, name + ".stats.json"), "w") as f:
        json.dump(st, f)
    with open(os.path.join(d, name + ".graph.json"), "w") as f:
        json.dump(g.to_dict(), f)


NET_PORT = 38177
NET_CLOSED_PORT = 57743
NET_UNIX = "/tmp/p15net-test/p15.sock"
NET_PAYLOAD = "/tmp/p15net-test/p15_net_payload.sh"
NET_SERVER_PORT = 41003
PAYLOAD_PATH = "/tmp/p15work-test/payload.txt"
FORK_PATH = "/tmp/p15work-test/fork.txt"
NET_DEMO = {
    "ok": True, "port": NET_PORT, "closed_port": NET_CLOSED_PORT,
    "unix_path": NET_UNIX, "payload_path": NET_PAYLOAD,
    "endpoint": "net:127.0.0.1:%d" % NET_PORT,
    "refused_endpoint": "net:127.0.0.1:%d" % NET_CLOSED_PORT,
    "unix_endpoint": "unix:" + NET_UNIX,
    "server_port": NET_SERVER_PORT,
    "inbound_endpoint": "host:127.0.0.1",
    "server_tag": "p15srv",
}


def functional_story(w, p, break_it=False, legacy=False):
    """legacy=True reproduces a run made before paths.json existed."""
    payload = "/tmp/p15_payload.txt" if legacy else PAYLOAD_PATH
    fork_file = "/tmp/p15_fork.txt" if legacy else FORK_PATH
    ts = [10 * SEC]

    def nxt():
        ts[0] += 1000
        return ts[0]

    def child(pid, comm="bash"):
        w.spawn(pid, 100, comm, nxt())

    def run(pid, path, argv, new):
        e = nxt()
        for r in w.exec_records(pid, e, nxt(), path, argv, new):
            p.handle(r)

    child(201); run(201, "/usr/bin/cat", ["cat", "/etc/hostname"], "cat")
    child(202); run(202, "/bin/echo", ["/bin/echo", "alpha", "beta", "gamma"], "echo")
    child(203); run(203, "/bin/sh", ["sh", "-c", "echo secret > " + payload], "sh")
    p.handle(w.open(203, nxt(), payload, os.O_WRONLY | os.O_CREAT, 3))
    child(204); run(204, "/usr/bin/cat", ["cat", payload], "cat")
    p.handle(w.open(204, nxt(), payload, os.O_RDONLY, 3))
    child(205, "python3")
    if not break_it:
        p.handle(w.ev(EVENT_EXEC_ENTER, 205, nxt(), "/nonexistent_p15_binary"))
    child(206); run(206, "/bin/sh", ["sh", "-c", "exit 3"], "sh")
    p.handle(w.exit(206, nxt(), status=3 << 8))
    child(207)
    e = nxt()
    recs = w.exec_records(207, e, nxt(), "/bin/echo", ["/bin/echo"] + [str(i) for i in range(1, 20)], "echo")
    from hids.events import ARG_FLAG_END, ARG_FLAG_TRUNCATED, Arg
    recs[-2] = Arg(207, 20, e, "", ARG_FLAG_END | ARG_FLAG_TRUNCATED)
    for r in recs:
        p.handle(r)
    child(208)
    p.handle(w.open(208, nxt(), fork_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 3))
    child(209, "python3")
    p.handle(w.open(209, nxt(), "/etc/hostname")._replace(tid=210, tcomm="p15worker"))
    # fileless exec
    from hids.events import AT_EMPTY_PATH
    child(211, "python3")
    e = nxt()
    for r in w.exec_records(211, e, nxt(), "" if not break_it else "/usr/bin/p15mem",
                            ["p15mem"], "3",
                            kernel_path="/dev/fd/3" if not break_it else "/usr/bin/p15mem",
                            enter_extra={"dfd": 3, "flags": AT_EMPTY_PATH} if not break_it else None):
        p.handle(r)
    # relative write then relative read, same inode. The writer is the
    # reader's PARENT (a fork-only subshell), exactly like the VM's
    # `(cd $WORK && echo rel > p15_rel.txt && cat ./p15_rel.txt)`. With the
    # writer as a sibling, as it was until row 80, the analyzer's own
    # synthetic story could not reproduce the VM failure.
    child(212)
    p.handle(w.open(212, nxt(), "p15_rel.txt", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 3,
                    ino=77, dev=8))
    w.spawn(213, 212, "bash", nxt())
    run(213, "/usr/bin/cat", ["cat", "./p15_rel.txt"], "cat")
    p.handle(w.open(213, nxt(), "./p15_rel.txt", os.O_RDONLY, 3, ino=77, dev=8))
    # network: the four connect outcomes, then download -> write -> execute
    child(214, "python3")
    p.handle(w.connect(214, nxt(), "127.0.0.1", NET_PORT))
    child(215, "python3")
    p.handle(w.connect(215, nxt(), "127.0.0.1", NET_CLOSED_PORT, ret=-111))
    child(216, "python3")
    p.handle(w.connect(216, nxt(), path=NET_UNIX))
    child(217, "python3")
    p.handle(w.connect(217, nxt(), "127.0.0.1", NET_PORT, pending=True))
    child(218, "python3")
    if not break_it:
        p.handle(w.connect(218, nxt(), "127.0.0.1", NET_PORT))
    p.handle(w.open(218, nxt(), NET_PAYLOAD, os.O_WRONLY | os.O_CREAT, 3, ino=91, dev=8))
    child(219)
    run(219, "/bin/sh", ["/bin/sh", NET_PAYLOAD], "sh")
    p.handle(w.open(219, nxt(), NET_PAYLOAD, os.O_RDONLY, 3, ino=91, dev=8))
    # inbound: a server child accepts two connections from the same host,
    # arriving on DIFFERENT ephemeral source ports — the shape that proves
    # the endpoint id must not contain the peer's port. Plus a unix accept,
    # where the kernel has no peer name to report.
    child(220, "python3")
    if not break_it:
        # two connections from ONE host on different source ports
        p.handle(w.accept(220, nxt(), "127.0.0.1", peer_port=45192,
                          listen_fd=3, conn_fd=7))
        p.handle(w.accept(220, nxt(), "127.0.0.1", peer_port=51022,
                          listen_fd=3, conn_fd=8))
    p.handle(w.accept(220, nxt(), path="", nopeer=True, listen_fd=4, conn_fd=9,
                      family=AF_UNIX))


def burst_story(w, p):
    for i in range(200):
        pid = 1000 + i
        w.spawn(pid, 100, "bash", 20 * SEC + i * 10)
        for r in w.exec_records(pid, 20 * SEC + i * 10 + 1, 20 * SEC + i * 10 + 2,
                                "/bin/true", ["/bin/true"], "true"):
            p.handle(r)
        p.handle(w.exit(pid, 20 * SEC + i * 10 + 3))


class AnalyzerTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d)

    def analyze(self):
        out = subprocess.check_output([sys.executable, TOOL, self.d]).decode()
        with open(os.path.join(self.d, "results.json")) as f:
            return out, json.load(f)

    def write_paths(self):
        with open(os.path.join(self.d, "paths.json"), "w") as f:
            json.dump({"work": "/tmp/p15net-test", "payload": PAYLOAD_PATH,
                       "fork": FORK_PATH, "rel": "p15_rel.txt"}, f)

    def write_net_demo(self, ok=True):
        payload = dict(NET_DEMO) if ok else {"ok": False}
        with open(os.path.join(self.d, "net_demo.json"), "w") as f:
            json.dump(payload, f)

    def test_all_pass_on_good_run(self):
        run_scenario(self.d, "functional", functional_story)
        self.write_net_demo()
        self.write_paths()
        run_scenario(self.d, "burst", burst_story)
        for pages in (64, 256):
            run_scenario(self.d, "stress_p%d" % pages, lambda w, p: p.handle_lost(10))
        with open(os.path.join(self.d, "timings.csv"), "w") as f:
            f.write("base,exec,2.0\nbase,exec,2.2\nbase,exec,2.1\n"
                    "mon,exec,2.5\nmon,exec,2.6\nmon,exec,2.4\n"
                    "base,open,1.0\nmon,open,1.1\n")
        out, res = self.analyze()
        fails = [c for c in res["checks"] if c["result"] != "PASS"]
        self.assertEqual(fails, [], out)
        self.assertEqual(len(res["checks"]), 23)
        nums = {n["metric"]: n["value"] for n in res["numbers"]}
        self.assertEqual(nums["workload slowdown: 2000 x /bin/true"],
                         "+19.0% (2.10 s -> 2.50 s, median of 3)")
        self.assertIn("10 (100.00%", nums["records lost [p64]"])

    def test_detects_failures(self):
        run_scenario(self.d, "functional", lambda w, p: functional_story(w, p, break_it=True))
        self.write_net_demo()
        self.write_paths()
        # a self-event from the monitor sneaks in
        with open(os.path.join(self.d, "functional.jsonl"), "a") as f:
            f.write(json.dumps({"type": "OPEN", "pid": MON, "lineage": "?(4242)",
                                "name": "python3"}) + "\n")
            f.write("{broken json\n")
        out, res = self.analyze()
        failed = {c["check"] for c in res["checks"] if c["result"] == "FAIL"}
        self.assertIn("failed execve recorded as EXEC_FAILED", failed)
        self.assertIn("zero self-events from the monitor (in-kernel filter)", failed)
        self.assertIn("JSONL log: every line parses", failed)
        self.assertIn("no '?' in any lineage (row 12 regression)", failed)
        self.assertIn("exec burst: all 200 /bin/true captured", failed)
        # break_it drops the downloader's connect: the chain must break too
        self.assertIn("root-cause trace crosses the network boundary: "
                      "executed file <- writer process <- the peer it came from", failed)
        # break_it also drops the inbound connections: the accept checks
        # must fail rather than quietly pass on an empty set
        self.assertIn("inbound connection recorded, attributed to the "
                      "accepting process", failed)
        self.assertIn("inbound endpoint keyed by host, not by the peer's "
                      "ephemeral port", failed)

    def test_runs_recorded_before_paths_json_still_analyse(self):
        """Older runs wrote to fixed /tmp names and have no paths.json. They
        are the regression baseline, so the analyzer must still read them."""
        run_scenario(self.d, "functional", lambda w, p: functional_story(w, p, legacy=True))
        self.write_net_demo()
        out, res = self.analyze()
        names = {c["check"]: c["result"] for c in res["checks"]}
        self.assertEqual(names["fork-without-exec process tracked (bash subshell)"], "PASS", out)

    def test_missing_network_demo_is_reported_not_skipped(self):
        run_scenario(self.d, "functional", functional_story)
        self.write_net_demo(ok=False)
        self.write_paths()
        out, res = self.analyze()
        failed = {c["check"] for c in res["checks"] if c["result"] == "FAIL"}
        # the network checks must report a missing demo rather than quietly
        # passing or disappearing from the report
        self.assertIn("network demo ran", failed)
        self.assertNotIn("fileless exec (memfd + fexecve) flagged exec_from_fd", failed)


if __name__ == "__main__":
    unittest.main()
