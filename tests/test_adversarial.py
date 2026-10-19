"""Adversarial tests: the time laws a causal walk must never break.

Every test here reproduces a bug that was actually in the tree (v3.5
adversarial review, findings H1-H3) or guards an invariant those bugs
violated. They are kept together, and apart from test_graph.py, because
they are written from the attacker's side of the contract: not "does the
feature work" but "can I make the walk tell me something false".

The two laws, stated once:

  BACKWARDS  every edge a root-cause walk lists happened at or before the
             point being asked about. A cause cannot be in the future.
  FORWARDS   every edge an impact walk lists happened at or after that
             point. An effect cannot precede its cause.

Both were breakable before these fixes, and one of the three bugs made the
walk return a confidently WRONG writer rather than merely omitting one —
which is the worse failure for a provenance tool.
"""

import os
import re
import random
import time
import unittest

from helpers import SEC

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
from hids.graph import (ACCEPT, CONNECT, EXEC, FORK, READ, WRITE, ProcessGraph)


def add(g, pid, start, ppid, pstart, comm, pcomm="", ts=None):
    return g.process(pid, start, ppid, pstart, comm, pcomm, 1000,
                     ts if ts is not None else start)


class TimeBoundTest(unittest.TestCase):
    """H1: an effect cannot predate its cause."""

    def test_forward_walk_does_not_list_a_fork_that_predates_the_bound(self):
        # curl writes a file at 20 s; a victim shell reads it at 50 s. The
        # victim had already forked a child at 41 s — BEFORE the read — so
        # that child cannot be an effect of the file. The walk used to list
        # it, because the FORK branch was the one branch that never checked
        # the time bound.
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        curl = add(g, 100, 10 * SEC, 1, 1, "curl", "systemd")
        g.record_open(curl, 20 * SEC, "/tmp/f", "W", 3)
        victim = add(g, 200, 30 * SEC, 1, 1, "bash", "systemd")
        add(g, 300, 41 * SEC, 200, 30 * SEC, "early", "bash")
        add(g, 301, 60 * SEC, 200, 30 * SEC, "late", "bash")
        g.record_open(victim, 50 * SEC, "/tmp/f", "R", 3)
        f = g.file("path:/tmp/f")
        found = [(k, ts, d) for _, k, ts, d in g.trace_forward(f)]
        self.assertIn((READ, 50 * SEC, "bash(200)"), found)
        self.assertIn((FORK, 60 * SEC, "late(301)"), found)     # after: an effect
        self.assertNotIn("early(300)", [d for _, _, d in found])  # before: not
        for _k, ts, _d in found:
            self.assertGreaterEqual(ts, 50 * SEC)               # the forward law

    def test_forward_from_a_process_still_lists_all_its_children(self):
        # The fix must not throw away the ordinary case: a walk that starts
        # at the process itself begins at its own span, so every child
        # qualifies.
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        sh = add(g, 100, 10 * SEC, 1, 1, "bash", "systemd")
        add(g, 101, 11 * SEC, 100, 10 * SEC, "a", "bash")
        add(g, 102, 12 * SEC, 100, 10 * SEC, "b", "bash")
        kids = [d for _, k, _, d in g.trace_forward(sh) if k == FORK]
        self.assertEqual(sorted(kids), ["a(101)", "b(102)"])


class MultiBoundTest(unittest.TestCase):
    """H2: the same file read twice is two different questions."""

    def build(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        w1 = add(g, 101, 10 * SEC, 1, 1, "w1", "systemd")
        w2 = add(g, 102, 11 * SEC, 1, 1, "w2", "systemd")
        r = add(g, 200, 20 * SEC, 1, 1, "reader", "systemd")
        g.record_open(w1, 50 * SEC, "/tmp/g", "W", 3)
        g.record_open(r, 100 * SEC, "/tmp/g", "R", 3)     # reads w1's bytes
        g.record_open(w2, 200 * SEC, "/tmp/g", "W", 4)
        g.record_open(r, 296 * SEC, "/tmp/g", "R", 5)     # reads w2's bytes
        return g, r

    def test_each_read_gets_its_own_writer(self):
        """The bug this replaces was worse than a missing edge.

        Keying the visited set on the node alone meant the file was expanded
        once, at the FIRST bound to reach it. The second read then inherited
        the first read's writer: the walk reported w1 as the origin of bytes
        that came from w2 — a wrong answer stated confidently, which is the
        one failure mode a provenance tool must not have.
        """
        g, r = self.build()
        found = [(k, ts, d) for _, k, ts, d in g.trace_back(r)]
        self.assertIn((WRITE, 50 * SEC, "w1(101)"), found)
        self.assertIn((WRITE, 200 * SEC, "w2(102)"), found)

    def test_no_duplicate_edges_from_re_expansion(self):
        # Expanding a node once per bound must not print the same edge
        # twice: a single write seen under two bounds is still one fact.
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        w = add(g, 101, 10 * SEC, 1, 1, "w", "systemd")
        r = add(g, 200, 20 * SEC, 1, 1, "reader", "systemd")
        g.record_open(w, 50 * SEC, "/tmp/h", "W", 3)
        g.record_open(r, 100 * SEC, "/tmp/h", "R", 3)
        g.record_open(r, 150 * SEC, "/tmp/h", "R", 4)
        writes = [(k, ts, d) for _, k, ts, d in g.trace_back(r) if k == WRITE]
        self.assertEqual(writes, [(WRITE, 50 * SEC, "w(101)")])

    def test_point_in_time_question(self):
        # With at_ns the analyst can ask the question an alert timestamp
        # poses: as of 150 s, only w1 had written the file.
        g, r = self.build()
        early = [d for _, k, _, d in g.trace_back(r, at_ns=150 * SEC) if k == WRITE]
        self.assertEqual(early, ["w1(101)"])


class ArrivalOrderTest(unittest.TestCase):
    """H3: per-CPU buffers reorder records, and the graph must not care."""

    def test_an_earlier_event_arriving_late_lowers_first_ns(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        n = add(g, 100, 10 * SEC, 1, 1, "bash", "systemd", ts=500 * SEC)
        self.assertEqual(n.first_ns, 500 * SEC)
        g.record_open(n, 300 * SEC, "/tmp/x", "R", 3)       # older event, later
        self.assertEqual(n.first_ns, 300 * SEC)
        # and through process(), which is the path every event takes first
        add(g, 100, 10 * SEC, 1, 1, "bash", "systemd", ts=200 * SEC)
        self.assertEqual(n.first_ns, 200 * SEC)

    def test_the_fork_edge_carries_the_real_fork_time(self):
        """Not `first_ns` — which is an artefact of arrival order.

        The kernel gave us `task->start_time` on every record, in the same
        clock as the event timestamps, so the fork time is known exactly.
        The walk used to date the FORK edge at "when we first saw this
        process", which reordering can push arbitrarily late — the fuzzer
        found a cause dated 394 s after the point being asked about.
        """
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        n = add(g, 100, 10 * SEC, 1, 1, "bash", "systemd", ts=500 * SEC)
        g.record_open(n, 300 * SEC, "/tmp/x", "R", 3)
        forks = [(ts, k) for ts, k, _src in g._in_edges(n, 300 * SEC) if k == FORK]
        self.assertEqual(forks, [(10 * SEC, FORK)])        # the true fork time
        self.assertTrue(n.start_exact)

    def test_a_bound_is_never_exceeded_even_by_an_estimated_start(self):
        # A /proc-bootstrapped node has an ESTIMATED start time, which can
        # be wrong in either direction. The walk must still never report a
        # cause after the point asked about.
        g = ProcessGraph()
        g.bootstrap([{"pid": 1, "ppid": 0, "comm": "systemd", "uid": 0,
                      "start_ns": 1},
                     {"pid": 900, "ppid": 1, "comm": "sshd", "uid": 0,
                      "start_ns": 900 * SEC}], 100 * SEC)
        n = g.get(900)
        self.assertFalse(n.start_exact)
        for ts, _k, _src in g._in_edges(n, 50 * SEC):
            self.assertLessEqual(ts, 50 * SEC)

    def test_inferred_exit_uses_the_earliest_known_time(self):
        # When a PID is reused without an exit event, the old generation's
        # exit is stamped with the new one's first_ns. If that was inflated
        # by reordering, the generation boundary lands in the wrong place.
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        old = add(g, 500, 10 * SEC, 1, 1, "first", "systemd")
        new = add(g, 500, 400 * SEC, 1, 1, "second", "systemd", ts=900 * SEC)
        g.record_open(new, 410 * SEC, "/tmp/y", "R", 3)     # earlier, arrives late
        self.assertFalse(old.alive)
        self.assertTrue(old.exit_inferred)
        # the old generation cannot outlive the new one's fork, and that
        # bound is exact — not "when we first saw the new process", which
        # is both arrival-order dependent and lowered afterwards, leaving
        # the stamp stale. (This consequence of H3 was still open after the
        # review's three fixes; found by this test.)
        self.assertEqual(old.exit_ns, 400 * SEC)
        self.assertLessEqual(old.exit_ns, new.first_ns)
        self.assertEqual(new.first_ns, 410 * SEC)


class PidReuseIsolationTest(unittest.TestCase):
    """A reused PID is two processes. A walk must never mix them.

    This is the project's core identity claim, tested at the walk level
    rather than at the node level: it is not enough that two generations
    exist as separate nodes, the causal queries must refuse to carry
    history across the boundary. The v2 bug this descends from scoped file
    history to the PID *number*, so a reused PID inherited the previous
    holder's files — and any walk built on that is attributing one
    program's actions to another.
    """

    def build(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        first = add(g, 500, 10 * SEC, 1, 1, "victim", "systemd")
        g.record_open(first, 11 * SEC, "/tmp/gen0-secret", "R", 3)
        g.record_connect(first, 12 * SEC, "net:10.0.0.1:443", True)
        g.record_exit(first, 20 * SEC, 0)
        second = add(g, 500, 100 * SEC, 1, 1, "innocent", "systemd")
        g.record_open(second, 101 * SEC, "/tmp/gen1-file", "R", 4)
        g.record_accept(second, 102 * SEC, "host:10.0.0.2")
        return g, first, second

    def test_generations_are_separate_nodes_with_separate_history(self):
        g, first, second = self.build()
        self.assertNotEqual(first.key, second.key)
        self.assertEqual(g.stats["generations"], 1)
        self.assertEqual([f[1] for f in first.files], ["/tmp/gen0-secret"])
        self.assertEqual([f[1] for f in second.files], ["/tmp/gen1-file"])
        self.assertEqual(first.accepts, [])
        self.assertEqual(second.conns, [])

    def test_walks_do_not_cross_the_generation_boundary(self):
        g, first, second = self.build()
        back = [d for _, _, _, d in g.trace_back(second)]
        self.assertIn("/tmp/gen1-file", back)
        self.assertNotIn("/tmp/gen0-secret", back)     # not ours, different process
        self.assertNotIn("net:10.0.0.1:443", back)
        fwd = [d for _, _, _, d in g.trace_forward(first)]
        self.assertIn("net:10.0.0.1:443", fwd)
        self.assertNotIn("/tmp/gen1-file", fwd)        # happened after we died
        self.assertNotIn("host:10.0.0.2", fwd)

    def test_an_endpoint_shared_by_two_generations_keeps_them_apart(self):
        # The resource is legitimately shared; the attribution must not be.
        g, first, second = self.build()
        g.record_connect(second, 103 * SEC, "net:10.0.0.1:443", True)
        ep = g.endpoints["net:10.0.0.1:443"]
        who = sorted({k for _ts, k, _kind in ep.accesses})
        self.assertEqual(who, [first.key, second.key])
        self.assertEqual(len(who), 2)                  # two keys, one PID


class OutOfOrderWalkTest(unittest.TestCase):
    """H3 again, but asked of the walks rather than of the fields."""

    def test_a_child_seen_before_its_parent_still_walks_correctly(self):
        """The reverse-order case the placeholder machinery exists for.

        A child's first record can arrive before anything from its parent,
        because they ran on different CPUs. The parent is then a placeholder
        with an estimated start, and the FORK edge must still obey the time
        law — a placeholder's guessed start must never date a cause after
        the point being asked about.
        """
        g = ProcessGraph()
        child = add(g, 300, 50 * SEC, 200, 40 * SEC, "child", "parent",
                    ts=55 * SEC)
        g.record_open(child, 56 * SEC, "/tmp/c", "R", 3)
        parent = g.get(200)
        self.assertIsNotNone(parent)                   # placeholder created
        back = g.trace_back(child)
        self.assertIn("parent(200)", [d for _, _, _, d in back])
        for _d, _k, ts, _desc in back:
            self.assertLessEqual(ts, g._start_ts(child, True))
        # ...and once the real parent record arrives, the lineage sharpens
        # without the walk ever having lied: the placeholder gets linked to
        # its own parent. Its NAME stays as the kernel reported it at fork
        # time, because that record (41 s) is older than everything already
        # seen for the node and a late pre-exec event must not rename it
        # (Journal row 12) — the same guard that stopped "cat" turning back
        # into "bash".
        add(g, 200, 40 * SEC, 1, 1, "bash", "systemd", ts=41 * SEC)
        self.assertEqual(g.lineage_str(child),
                         "systemd(1) → parent(200) → child(300)")

    def test_a_walk_is_identical_whatever_order_the_records_arrived(self):
        """The strongest form of the invariant: order must not change answers.

        Two graphs, same five events, one fed in time order and one fed
        reversed. The causal answers must be the same set — not merely both
        "valid", but equal. Anything order-dependent in the walks shows up
        here as a diff.
        """
        events = [
            ("proc", 101, 10 * SEC), ("proc", 102, 20 * SEC),
            ("write", 101, 30 * SEC), ("read", 102, 40 * SEC),
            ("conn", 102, 50 * SEC),
        ]

        def build(order):
            g = ProcessGraph()
            add(g, 1, 1, 0, 0, "systemd")
            nodes = {}
            for kind, pid, ts in order:
                start = 10 * SEC if pid == 101 else 20 * SEC
                n = nodes.setdefault(
                    pid, add(g, pid, start, 1, 1, "p%d" % pid, "systemd", ts=ts))
                n = g.process(pid, start, 1, 1, "p%d" % pid, "systemd", 1000, ts)
                if kind == "write":
                    g.record_open(n, ts, "/tmp/shared", "W", 3)
                elif kind == "read":
                    g.record_open(n, ts, "/tmp/shared", "R", 3)
                elif kind == "conn":
                    g.record_connect(n, ts, "net:10.0.0.5:443", True)
            return g

        fwd, rev = build(events), build(list(reversed(events)))
        a = sorted((k, ts, d) for _, k, ts, d in fwd.trace_back(fwd.get(102)))
        b = sorted((k, ts, d) for _, k, ts, d in rev.trace_back(rev.get(102)))
        self.assertEqual(a, b)
        self.assertIn((WRITE, 30 * SEC, "p101(101)"), a)
        for node in (fwd.get(101), fwd.get(102)):
            other = rev.get(node.pid)
            self.assertEqual(node.first_ns, other.first_ns)
            self.assertEqual(node.last_ns, other.last_ns)


class FuzzTest(unittest.TestCase):
    """The laws, under fully shuffled record arrival.

    This is the test that found H3. A graph built from events delivered in
    a random order must satisfy exactly the same invariants as one built in
    order, because out-of-order delivery is the NORMAL condition with
    per-CPU perf buffers, not an edge case.
    """

    def build_shuffled(self, rnd):
        """A small random world, with every record delivered out of order."""
        events = []
        procs = {1: (1, 0, 0)}                  # pid -> (start, ppid, pstart)
        for pid in range(100, 112):
            start = rnd.randrange(10, 500) * SEC
            ppid = rnd.choice(sorted(procs))
            procs[pid] = (start, ppid, procs[ppid][0])
            # several events per process, at times after its start
            for _ in range(rnd.randrange(1, 5)):
                ts = start + rnd.randrange(1, 4000) * SEC
                kind = rnd.choice(["open_r", "open_w", "exec", "conn", "accept"])
                events.append((pid, ts, kind, rnd.randrange(0, 4)))
        rnd.shuffle(events)                     # <-- arrival order is arbitrary
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        seen_ts = {}
        for pid, ts, kind, which in events:
            start, ppid, pstart = procs[pid]
            node = g.process(pid, start, ppid, pstart, "p%d" % pid,
                             "p%d" % ppid, 1000, ts)
            seen_ts.setdefault(node.key, []).append(ts)
            if kind == "open_r":
                g.record_open(node, ts, "/tmp/f%d" % which, "R", 3)
            elif kind == "open_w":
                g.record_open(node, ts, "/tmp/f%d" % which, "W", 3)
            elif kind == "exec":
                g.record_exec(node, ts, "/bin/e%d" % which, ["e"], False,
                              "e%d" % which)
            elif kind == "conn":
                g.record_connect(node, ts, "net:10.0.0.%d:443" % which, True)
            else:
                g.record_accept(node, ts, "host:10.0.0.%d" % which)
        return g, seen_ts

    def test_time_laws_hold_under_any_arrival_order(self):
        for seed in range(5):
            rnd = random.Random(seed)
            for trial in range(15):
                g, seen_ts = self.build_shuffled(rnd)
                where = "seed=%d trial=%d" % (seed, trial)

                # invariant 1: first_ns is not later than any event we saw
                for key, times in seen_ts.items():
                    node = g.nodes[key]
                    self.assertLessEqual(node.first_ns, min(times), where)
                    self.assertGreaterEqual(node.last_ns, max(times), where)

                roots = (list(g.nodes.values()) + list(g.files.values())
                         + list(g.endpoints.values()))
                for root in roots[:20]:
                    # invariant 2: a cause is never in the future
                    start_back = g._start_ts(root, True)
                    for _d, kind, ts, desc in g.trace_back(root):
                        self.assertLessEqual(
                            ts, start_back,
                            "%s: backward edge %s %s at %d > bound %d"
                            % (where, kind, desc, ts, start_back))
                    # invariant 3: an effect never precedes its cause
                    start_fwd = g._start_ts(root, False)
                    for _d, kind, ts, desc in g.trace_forward(root):
                        self.assertGreaterEqual(
                            ts, start_fwd,
                            "%s: forward edge %s %s at %d < bound %d"
                            % (where, kind, desc, ts, start_fwd))


class TerminationTest(unittest.TestCase):
    """Expanding per bound must stay bounded in time as well as in output."""

    def test_pathological_reread_terminates_quickly(self):
        # One file, written and read alternately 400 times by the same two
        # processes: 400 distinct bounds for the same node, which is the
        # shape that makes per-bound expansion expensive. The walk must
        # finish promptly and obey its own caps.
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        w = add(g, 101, 1 * SEC, 1, 1, "w", "systemd")
        r = add(g, 102, 2 * SEC, 1, 1, "r", "systemd")
        for i in range(400):
            g.record_open(w, (10 + 2 * i) * SEC, "/tmp/busy", "W", 3)
            g.record_open(r, (11 + 2 * i) * SEC, "/tmp/busy", "R", 4)
        t0 = time.time()
        out = g.trace_back(r)
        elapsed = time.time() - t0
        self.assertLessEqual(len(out), 200)
        self.assertLess(elapsed, 2.0, "walk took %.2fs" % elapsed)
        # and the answers it does give are the right ones: each read's
        # writer is the write immediately before it
        for _d, kind, ts, desc in out:
            if kind == WRITE:
                self.assertEqual(desc, "w(101)")
                self.assertEqual(ts % (2 * SEC), 0)       # writes are even seconds

    def test_work_budget_is_honoured(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        w = add(g, 101, 1 * SEC, 1, 1, "w", "systemd")
        r = add(g, 102, 2 * SEC, 1, 1, "r", "systemd")
        for i in range(50):
            g.record_open(w, (10 + 2 * i) * SEC, "/tmp/busy", "W", 3)
            g.record_open(r, (11 + 2 * i) * SEC, "/tmp/busy", "R", 4)
        # a budget of 1 means: expand the start node only
        self.assertLessEqual(len(g.trace_back(r, max_visits=1)),
                             len(g.trace_back(r)))


class CapDefaultsTest(unittest.TestCase):
    """The caps are memory budgets, so the numbers are claims about memory.

    This used to pin the documented figures to literals — "~380 B",
    "~530 B" — which guarded them against drifting apart but not against
    both being wrong, and they were: no harness existed anywhere in the
    tree, an audit found that, and measuring gave ~356 B and ~747 B on the
    VM's interpreter. So the doc is now checked against a MEASUREMENT taken
    here, with the same `tracemalloc` method `tools/bench_nodes.py` uses.

    The tolerance is wide (35 %) on purpose. Object sizes differ between
    interpreters — 3.8 and 3.13 disagree by a few percent on these — and the
    point is to catch a figure that is wrong by a factor, not to re-measure
    the allocator on every run. A number that drifts inside 35 % still
    supports the same cap decision; one outside it does not.
    """

    @staticmethod
    def _measured(kind, accesses, nodes):
        import tracemalloc
        g = ProcessGraph(max_nodes=10 ** 9, max_files=10 ** 9,
                         max_endpoints=10 ** 9)
        g.bootstrap([{"pid": 1, "ppid": 0, "comm": "init", "uid": 0,
                      "start_ns": SEC}], 0)
        node = g.process(500, 2 * SEC, 1, SEC, "p", "init", 0, 2 * SEC)
        tracemalloc.start()
        base = tracemalloc.take_snapshot()
        for i in range(nodes):
            for a in range(accesses):
                ts = 3 * SEC + i * 1000 + a
                if kind == "file":
                    g.record_open(node, ts, "/tmp/f%d" % i, "R", 3,
                                  "inode:8:%d:0" % i)
                else:
                    g.record_connect(node, ts, "net:10.0.%d.%d:443"
                                     % (i // 256, i % 256), True)
        snap = tracemalloc.take_snapshot()
        tracemalloc.stop()
        held = sum(x.size_diff for x in snap.compare_to(base, "filename"))
        return held / float(nodes)

    def test_endpoint_default_matches_the_documented_budget(self):
        from hids import monitor
        self.assertEqual(monitor.parse_args([]).max_endpoints, 25000)
        with open(os.path.join(ROOT, "docs", "ARCHITECTURE.md")) as f:
            arch = f.read()
        self.assertIn("`max_endpoints` (LRU, default 25 000)", arch)

    def test_the_documented_node_costs_are_within_range_of_a_measurement(self):
        with open(os.path.join(ROOT, "docs", "ARCHITECTURE.md")) as f:
            arch = f.read()
        # The per-node figure depends on how many nodes were built: Python
        # over-allocates lists and grows dicts in steps, so 150 nodes gives a
        # visibly higher per-node cost than 400. The doc states its shape, and
        # this reads that number instead of assuming one — comparing against a
        # different count is not a tolerance problem, it is a different
        # measurement.
        shape = re.search(r"(\d+) nodes per cell", arch)
        self.assertIsNotNone(shape, "ARCHITECTURE.md no longer says how many "
                                    "nodes the cost table was measured over")
        nodes = int(shape.group(1))

        for kind, label in (("file", "FileNode"), ("endpoint", "EndpointNode")):
            m = re.search(r"\| %s \| ~(\d+) B \| ~([\d.]+) KB \|" % label, arch)
            self.assertIsNotNone(
                m, "ARCHITECTURE.md no longer states %s's cost; the cap "
                   "defaults rest on it" % label)
            documented_one = float(m.group(1))
            documented_hot = float(m.group(2)) * 1024
            for accesses, documented in ((1, documented_one),
                                         (20, documented_hot)):
                got = self._measured(kind, accesses, nodes)
                self.assertLess(
                    abs(got - documented) / documented, 0.35,
                    "%s with %d access: doc says %.0f B, measured %.0f B "
                    "(>35 %% apart). Re-run tools/bench_nodes.py and update "
                    "the table, or explain the gap."
                    % (label, accesses, documented, got))

    def test_walk_budget_is_not_the_limiting_factor(self):
        """`max_visits` is a backstop, and the measurement says so.

        On the pathological 3 000-touch file the walk takes ~3 ms at the
        default budget of 4 000 and ~5 ms at 100 000: `max_items` binds
        first, so the budget only matters as a guard against a shape we
        have not thought of. Asserting the SHAPE (raising it 25x changes
        nothing material) rather than a millisecond figure keeps this from
        becoming a flaky timing test.
        """
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        w = add(g, 101, 1 * SEC, 1, 1, "w", "systemd")
        r = add(g, 102, 2 * SEC, 1, 1, "r", "systemd")
        for i in range(1500):
            g.record_open(w, (10 + 2 * i) * SEC, "/tmp/busy", "W", 3)
            g.record_open(r, (11 + 2 * i) * SEC, "/tmp/busy", "R", 4)
        default = g.trace_back(r)
        generous = g.trace_back(r, max_visits=100000)
        self.assertEqual(len(default), len(generous))
        self.assertEqual(default, generous)


class TraceObserverTest(unittest.TestCase):
    """The dry-run hook must observe the walk without changing it.

    `tools/walk_trace.py` teaches the algorithm by passing a printing
    observer into the real walk rather than reimplementing it — a teaching
    copy would drift from the real one and then teach the wrong thing. That
    only holds if the observer is provably inert.
    """

    def build(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        w1 = add(g, 101, 10 * SEC, 1, 1, "w1", "systemd")
        w2 = add(g, 102, 11 * SEC, 1, 1, "w2", "systemd")
        r = add(g, 200, 20 * SEC, 1, 1, "reader", "systemd")
        g.record_open(w1, 50 * SEC, "/tmp/g", "W", 3)
        g.record_open(r, 100 * SEC, "/tmp/g", "R", 3)
        g.record_open(w2, 200 * SEC, "/tmp/g", "W", 4)
        g.record_open(r, 296 * SEC, "/tmp/g", "R", 5)
        return g, r

    def test_observing_does_not_change_the_result(self):
        g, r = self.build()
        plain = g.trace_back(r)
        events = []
        observed = g.trace_back(r, trace=lambda e, i: events.append((e, i)))
        self.assertEqual(plain, observed)
        plain_f = g.trace_forward(g.get(101))
        observed_f = g.trace_forward(g.get(101), trace=lambda e, i: None)
        self.assertEqual(plain_f, observed_f)

    def test_the_trace_reports_the_decisions_the_docs_describe(self):
        # The multi-bound case from docs/study/05_GRAPH.md §5.7: the same
        # file node is expanded twice, and each expansion chooses its own
        # writer. If this ever stops being true, the guide is wrong.
        g, r = self.build()
        events = []
        g.trace_back(r, trace=lambda e, i: events.append((e, i)))
        kinds = [e for e, _ in events]
        self.assertEqual(kinds[0], "start")
        self.assertEqual(kinds[-1], "stop")
        pops = [i["node"] for e, i in events if e == "pop"]
        self.assertEqual(pops.count("/tmp/g"), 2)       # once per bound
        chosen = [(i["node"], i["ts"]) for e, i in events if e == "choose"]
        self.assertEqual(chosen, [("w1(101)", 50 * SEC), ("w2(102)", 200 * SEC)])
        stop = events[-1][1]
        self.assertEqual(stop["why"], "queue empty")
        self.assertEqual(stop["edges"], len(g.trace_back(r)))

    def test_suppressions_are_visible_in_the_trace(self):
        # dedup and echo both have to be observable, because the guide
        # explains them from the trace output.
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        curl = add(g, 100, 10 * SEC, 1, 1, "curl", "systemd")
        g.record_connect(curl, 11 * SEC, "net:203.0.113.5:443", True)
        g.record_open(curl, 12 * SEC, "/tmp/p", "W", 3)
        sh = add(g, 200, 20 * SEC, 1, 1, "bash", "systemd")
        g.record_open(sh, 21 * SEC, "/tmp/p", "R", 3)
        events = []
        g.trace_back(sh, trace=lambda e, i: events.append((e, i)))
        self.assertIn("echo", [e for e, _ in events])


class EndpointCapTest(unittest.TestCase):
    """An inbound endpoint is created by whoever connects to us."""

    def test_endpoints_are_evicted_least_recently_used_first(self):
        """Without a cap, a remote party can grow the monitor's memory.

        Files have had an LRU cap since v3.2; endpoints did not, which was
        tolerable while only our own processes could create them. Inbound
        changes that: any host that can reach a listening socket can mint a
        `host:<addr>` node, so the bound has to exist on our side.
        """
        g = ProcessGraph(max_endpoints=10)
        add(g, 1, 1, 0, 0, "systemd")
        srv = add(g, 900, 1 * SEC, 1, 1, "sshd", "systemd")
        for i in range(50):
            g.record_accept(srv, (10 + i) * SEC, "host:10.0.0.%d" % i)
        self.assertEqual(len(g.endpoints), 10)
        self.assertEqual(g.stats["evicted_endpoints"], 40)
        self.assertIn("host:10.0.0.49", g.endpoints)      # newest kept
        self.assertNotIn("host:10.0.0.0", g.endpoints)    # oldest gone
        # the per-process count still records what happened, so the
        # eviction shows up as "more accepts than endpoints", not as a
        # silently smaller number
        self.assertEqual(srv.accept_count, 50)

    def test_no_cap_keeps_everything(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        srv = add(g, 900, 1 * SEC, 1, 1, "sshd", "systemd")
        for i in range(30):
            g.record_accept(srv, (10 + i) * SEC, "host:10.0.0.%d" % i)
        self.assertEqual(len(g.endpoints), 30)
        self.assertEqual(g.stats["evicted_endpoints"], 0)


if __name__ == "__main__":
    unittest.main()
