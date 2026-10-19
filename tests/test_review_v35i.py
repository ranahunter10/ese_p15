"""One test per finding of the v3.5i six-agent review, by its filed name.

The review (18 Oct 2026) filed 26 findings and reproduced all 26. This file
pins the ones v3.6 fixes, named after the finding so the mapping from report
to regression test is mechanical: `grep -n "def test_" tests/test_review_v35i.py`
is the fix list.

Findings deliberately NOT fixed in v3.6 are listed in docs/CHANGES_v3.6.md
with the reason, so a missing name here is a recorded decision rather than an
oversight.

Each test fails if its fix is reverted — the project's standard of proof.
"""

import contextlib
import errno
import io
import json
import os
import random
import struct
import re
import unittest

from helpers import FakeClock, SEC, World
from hids import events as E
from hids.graph import (FORK, MAX_EDGES_PER_RESOURCE, ProcessGraph,
                        ProcessNode)
from hids.monitor import parse_args
from hids.processor import EventProcessor


def add(g, pid, start, ppid, pstart, comm, pcomm="", ts=None):
    return g.process(pid, start, ppid, pstart, comm, pcomm, 1000,
                     ts if ts is not None else start)


def pipeline(**kw):
    """Processor over a real graph, with a sink we can break on demand."""
    w = World()
    w.spawn(1, 0, "systemd", 1 * SEC)
    w.spawn(1360, 1, "bash", 10 * SEC)
    w.spawn(1390, 1360, "bash", 20 * SEC)
    clock = FakeClock()
    g = ProcessGraph()
    g.bootstrap([{"pid": pid, "ppid": v["ppid"], "comm": v["comm"], "uid": 1000,
                  "start_ns": v["start"]} for pid, v in w.procs.items()], 0)
    p = EventProcessor(g, clock, mono=clock, **kw)
    return w, g, p, clock


class Sink(io.StringIO):
    """A log sink that starts failing when told to — a full disk."""

    def __init__(self):
        io.StringIO.__init__(self)
        self.fail = None

    def write(self, s):
        if self.fail is not None:
            raise self.fail
        return io.StringIO.write(self, s)


# ------------------------------------------------------------- w2: pipeline
class CommitAtomicityTest(unittest.TestCase):

    def test_w2_b1b_one_exec_is_never_both_a_success_and_a_failure(self):
        """The realistic variant: the sink fails part-way through a commit.

        record_exec has already appended to node.execs when the log write
        raises. Before v3.6 the key had been popped, so a later duplicate
        ENTER plus a forced tick settled the same exec through on_failed and
        the graph claimed it both succeeded AND failed.
        """
        sink = Sink()
        w, g, p, clock = pipeline(log_file=sink)
        recs = w.exec_records(1390, 21 * SEC, 22 * SEC, "/bin/cat", ["cat", "x"],
                              "cat")
        sink.fail = OSError(errno.ENOSPC, "No space left on device")
        for r in recs:
            p.handle(r)
        # the write failed, so it was counted, not raised
        self.assertGreaterEqual(p.counts["errors"], 1)
        # a duplicate ENTER for the same key, then force the expiry
        p.handle(recs[0])
        clock.now += 10.0
        p.tick(force=True)
        node = [n for n in g.nodes.values() if n.pid == 1390][0]
        self.assertEqual(len(node.failed_execs), 0,
                         "the same exec was recorded as a failure as well")
        self.assertLessEqual(len(node.execs), 1)

    def test_w2_b1_a_committed_key_is_not_resurrected_by_late_args(self):
        sink = Sink()
        w, g, p, clock = pipeline(log_file=sink)
        recs = w.exec_records(1390, 21 * SEC, 22 * SEC, "/bin/cat", ["cat"], "cat")
        for r in recs:
            p.handle(r)
        before = len(p.assembler.pending)
        for r in recs:                      # replay the whole exec
            p.handle(r)
        self.assertEqual(len(p.assembler.pending), before,
                         "a committed exec went back into pending")


class TickGuardTest(unittest.TestCase):

    def test_w2_b2_a_failing_sink_during_expiry_does_not_kill_the_monitor(self):
        sink = Sink()
        w, g, p, clock = pipeline(log_file=sink)
        p.handle(w.ev(E.EVENT_EXEC_ENTER, 1390, 21 * SEC, "/bin/cat"))
        sink.fail = OSError(errno.ENOSPC, "No space left on device")
        clock.now += 10.0
        p.tick(force=True)                  # must not raise
        self.assertGreaterEqual(p.counts["errors"], 1)

    def test_w2_b4_epipe_still_escapes_both_handle_and_tick(self):
        """A closed pipe is a shutdown signal, not a data error."""
        sink = Sink()
        w, g, p, clock = pipeline(log_file=sink)
        sink.fail = OSError(errno.EPIPE, "Broken pipe")
        with self.assertRaises(OSError) as cm:
            p.handle(w.open(1390, 21 * SEC, "/tmp/x"))
        self.assertEqual(cm.exception.errno, errno.EPIPE)

        sink2 = Sink()
        w2, g2, p2, clock2 = pipeline(log_file=sink2)
        p2.handle(w2.ev(E.EVENT_EXEC_ENTER, 1390, 21 * SEC, "/bin/cat"))
        sink2.fail = OSError(errno.EPIPE, "Broken pipe")
        clock2.now += 10.0
        with self.assertRaises(OSError):
            p2.tick(force=True)


class ArgIndexTest(unittest.TestCase):

    def test_w2_b3a_a_negative_index_cannot_rewrite_a_committed_argv(self):
        w, g, p, clock = pipeline()
        recs = w.exec_records(1390, 21 * SEC, 22 * SEC, "/bin/cat", ["a", "b"],
                              "cat")
        for r in recs:
            p.handle(r)
        node = [n for n in g.nodes.values() if n.pid == 1390][0]
        self.assertEqual(node.execs[0].argv, ["a", "b"])
        p.handle(E.Arg(1390, -1, 21 * SEC, "EVIL"))
        self.assertEqual(node.execs[0].argv, ["a", "b"])
        self.assertEqual(p.assembler.bad_args, 1)

    def test_w2_b3b_a_huge_index_cannot_bloat_a_committed_argv(self):
        w, g, p, clock = pipeline()
        recs = w.exec_records(1390, 21 * SEC, 22 * SEC, "/bin/cat", ["a"], "cat")
        for r in recs:
            p.handle(r)
        node = [n for n in g.nodes.values() if n.pid == 1390][0]
        p.handle(E.Arg(1390, 2_000_000, 21 * SEC, "x"))
        self.assertEqual(len(node.execs[0].argv), 1)
        self.assertEqual(p.assembler.bad_args, 1)

    def test_a_valid_index_is_still_accepted(self):
        """The bound must not be so tight that real argv records bounce."""
        w, g, p, clock = pipeline()
        recs = w.exec_records(1390, 21 * SEC, 22 * SEC, "/bin/cat",
                              ["a%d" % i for i in range(E.MAXARG)], "cat")
        for r in recs:
            p.handle(r)
        node = [n for n in g.nodes.values() if n.pid == 1390][0]
        self.assertEqual(len(node.execs[0].argv), E.MAXARG)
        self.assertEqual(p.assembler.bad_args, 0)


class CliCapTest(unittest.TestCase):

    def test_w2_b5_negative_caps_are_refused(self):
        for flag in ("--max-files", "--max-nodes", "--max-endpoints"):
            with self.assertRaises(SystemExit), \
                    contextlib.redirect_stderr(io.StringIO()):
                parse_args([flag, "-5"])

    def test_zero_still_means_unlimited(self):
        a = parse_args(["--max-files", "0", "--max-nodes", "0",
                        "--max-endpoints", "0"])
        self.assertEqual((a.max_files, a.max_nodes, a.max_endpoints), (0, 0, 0))


# ---------------------------------------------------------------- w1: graph
class GenerationIdentityTest(unittest.TestCase):

    def _reuse_newest_first(self):
        """PID 112 reused three times, spawn events arriving newest first."""
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        for start in (141 * SEC, 102 * SEC, 33 * SEC):
            add(g, 112, start, 1, 1, "nc", "systemd", ts=200 * SEC)
        return g

    def test_w1_f4a_gens_are_oldest_first_even_when_arrival_is_newest_first(self):
        g = self._reuse_newest_first()
        starts = [g.nodes[k].start_ns for k in g.gens[112]]
        self.assertEqual(starts, sorted(starts))
        self.assertEqual(len(set(g.gens[112])), 3, "a generation key collided")

    def test_w1_f4a_gens_are_still_oldest_first_across_a_snapshot(self):
        """The live path and the restore path each have their own sort, and
        only the live one was covered.

        `from_dict` appends keys in `(pid, gen)` order and then sorts by
        `(start_ns, gen)` to restore the documented oldest-first order. An
        independent mutation sweep deleted that final sort and **no test
        failed**: the existing round-trip fixture happens to have no PID whose
        generation order differs from its start-time order, which is precisely
        the W1-F4 case the sort exists for. Arrival newest-first produces one
        — gen 0 is the LATEST lifetime — so a round trip of this graph is what
        the restore path has to get right.
        """
        g = self._reuse_newest_first()
        by_gen = sorted(g.gens[112], key=lambda k: k[1])
        starts_by_gen = [g.nodes[k].start_ns for k in by_gen]
        self.assertNotEqual(starts_by_gen, sorted(starts_by_gen),
                            "generation order already matches start order; "
                            "this fixture cannot see the restore sort")

        back = ProcessGraph.from_dict(json.loads(json.dumps(g.to_dict())))
        starts = [back.nodes[k].start_ns for k in back.gens[112]]
        self.assertEqual(starts, sorted(starts),
                         "restored generations are not oldest-first: %s" % starts)
        self.assertEqual(len(back.gens[112]), 3)
        self.assertEqual([back.nodes[k].start_ns for k in back.gens[112]],
                         [g.nodes[k].start_ns for k in g.gens[112]],
                         "a round trip changed the order the live path built")

    def test_w1_f4b_a_superseded_generation_is_not_left_alive(self):
        g = self._reuse_newest_first()
        newest = max(g.gens[112], key=lambda k: g.nodes[k].start_ns)
        for k in g.gens[112]:
            n = g.nodes[k]
            if k == newest:
                self.assertTrue(n.alive)
            else:
                self.assertFalse(n.alive, "a dead generation is still alive")
                self.assertTrue(n.exit_inferred)
                self.assertIsNotNone(n.exit_ns)
        self.assertEqual(g.summary()["alive"], 2)      # systemd + newest nc

    def test_w1_f4b_a_superseded_generation_becomes_evictable(self):
        """Eviction only removes exited nodes, so a zombie leaks for ever."""
        g = ProcessGraph(max_nodes=3)
        add(g, 1, 1, 0, 0, "systemd")
        for start in (141 * SEC, 102 * SEC, 33 * SEC):
            add(g, 112, start, 1, 1, "nc", "systemd", ts=200 * SEC)
        for i in range(6):
            add(g, 500 + i, (300 + i) * SEC, 1, 1, "x", "systemd")
        self.assertGreater(g.stats["evicted"], 0)


class HealingTest(unittest.TestCase):

    def test_w1_f5_an_empty_name_is_filled_by_a_late_birth_record(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        # an accept record arrives first and carries no name
        node = g.process(130, 50 * SEC, 0, 0, "", "", 1000, 60 * SEC)
        self.assertEqual(node.comm, "")
        # the birth record arrives later in wall time but is older in event time
        g.process(130, 50 * SEC, 1, 1, "sshd", "systemd", 1000, 50 * SEC)
        self.assertEqual(node.comm, "sshd")
        self.assertEqual(node.ppid, 1)

    def test_a_late_pre_exec_event_still_cannot_revert_a_real_rename(self):
        """The guard this relaxes exists for a reason: keep it working."""
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        node = g.process(200, 10 * SEC, 1, 1, "bash", "systemd", 1000, 10 * SEC)
        g.process(200, 10 * SEC, 1, 1, "cat", "systemd", 1000, 20 * SEC)
        self.assertEqual(node.comm, "cat")
        g.process(200, 10 * SEC, 1, 1, "bash", "systemd", 1000, 15 * SEC)
        self.assertEqual(node.comm, "cat", "a late event reverted the rename")


class DeadNodeParentTest(unittest.TestCase):

    def test_w1_f9_a_dead_node_with_no_parent_still_learns_one(self):
        """The birth record is authoritative; dropping it loses a FORK edge."""
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        parent = add(g, 102, 10 * SEC, 1, 1, "bash", "systemd")
        child = g.process(103, 20 * SEC, 0, 0, "cat", "", 1000, 21 * SEC)
        g.record_exit(child, 22 * SEC, 0)
        self.assertEqual(child.ppid, 0)
        # the authoritative birth record arrives after the exit
        g.process(103, 20 * SEC, 102, 10 * SEC, "cat", "bash", 1000, 20 * SEC)
        self.assertEqual(child.ppid, 102)
        self.assertEqual(child.parent_key, parent.key)
        self.assertIn(FORK, [k for _, k, _, _ in g.trace_back(child)])

    def test_an_established_parent_of_a_dead_node_is_never_moved(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        a = add(g, 102, 10 * SEC, 1, 1, "bash", "systemd")
        b = add(g, 109, 11 * SEC, 1, 1, "sh", "systemd")
        child = add(g, 103, 20 * SEC, 102, 10 * SEC, "cat", "bash")
        g.record_exit(child, 22 * SEC, 0)
        g.process(103, 20 * SEC, 109, 11 * SEC, "cat", "sh", 1000, 23 * SEC)
        self.assertEqual(child.parent_key, a.key, "a dead node was reparented")
        self.assertNotEqual(child.parent_key, b.key)

    def test_pid_1_is_not_reparented_away_from_its_legitimate_ppid_0(self):
        g = ProcessGraph()
        init = add(g, 1, 1, 0, 0, "systemd")
        g.record_exit(init, 5 * SEC, 0)
        g.process(1, 1, 999, 1, "systemd", "x", 0, 6 * SEC)
        self.assertEqual(init.ppid, 0)


class PlaceholderSpanTest(unittest.TestCase):

    def test_w1_f10_adoption_does_not_leave_a_borrowed_last_ns(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        # a child event at 219 s mints a placeholder parent (200, 50 s)
        add(g, 201, 219 * SEC, 200, 50 * SEC, "child", "parent")
        ph = g.find(200, 50 * SEC)
        self.assertIsNotNone(ph)
        # the parent's own birth arrives at 50 s and adopts the placeholder
        node = g.process(200, 50 * SEC, 1, 1, "parent", "systemd", 1000, 50 * SEC)
        self.assertEqual(node.first_ns, 50 * SEC)
        self.assertEqual(node.last_ns, 50 * SEC,
                         "last_ns still carries another process's timestamp")
        g.record_open(node, 60 * SEC, "/tmp/x", "R", 3, "inode:8:1:0")
        self.assertEqual(node.last_ns, 60 * SEC)


class SnapshotValidationTest(unittest.TestCase):

    def _snap(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        n = add(g, 100, 10 * SEC, 1, 1, "sh", "systemd")
        g.record_open(n, 11 * SEC, "/tmp/x", "W", 3, "inode:8:1:0")
        return json.loads(json.dumps(g.to_dict()))

    def test_w1_f6_a_duplicate_generation_is_refused(self):
        d = self._snap()
        d["processes"].append(dict(d["processes"][-1]))
        with self.assertRaises(ValueError) as cm:
            ProcessGraph.from_dict(d)
        self.assertIn("duplicate", str(cm.exception))

    def test_w1_f6_a_missing_field_names_itself(self):
        d = self._snap()
        del d["processes"][0]["comm"]
        with self.assertRaises(ValueError) as cm:
            ProcessGraph.from_dict(d)
        self.assertIn("comm", str(cm.exception))

    def test_a_good_snapshot_still_round_trips(self):
        g = ProcessGraph.from_dict(self._snap())
        self.assertEqual(len(g.nodes), 2)
        for keys in g.gens.values():
            starts = [g.nodes[k].start_ns for k in keys]
            self.assertEqual(starts, sorted(starts))


# ------------------------------------------------------- tier 1: eviction
class EvictionCostTest(unittest.TestCase):

    def test_a_graph_with_nothing_evictable_does_not_rescan_every_node(self):
        """The cliff: O(N) per creation, evicting nothing, with N growing.

        Not asserted by timing — a wall-clock assertion would be flaky on a
        shared machine, and the mechanism is what broke. But the previous
        version of this test asserted only `evicted == 0` and `_dead == {}`,
        which hold under the quadratic scan as well: the name promised a
        property the body could not observe, and an audit of the tree caught
        it. `sorted` resolves through the module's globals, so the scan can
        be counted directly — which is what "does not rescan" means.
        """
        import hids.graph as G

        calls = []
        real = sorted

        def counting_sorted(it, **kw):
            calls.append(1)
            return real(it, **kw)

        G.sorted = counting_sorted
        self.addCleanup(lambda: delattr(G, "sorted"))

        g = ProcessGraph(max_nodes=50)
        add(g, 1, 1, 0, 0, "systemd")
        for i in range(400):               # all alive: nothing to evict
            add(g, 1000 + i, (10 + i) * SEC, 1, 1, "p", "systemd")
        self.assertEqual(g.stats["evicted"], 0)
        self.assertEqual(g._dead, {})      # the short-circuit the fix relies on
        self.assertEqual(calls, [], "the eviction pass sorted %d times with "
                                    "nothing evictable" % len(calls))

    def test_eviction_still_evicts_oldest_exit_first_and_bounds_the_graph(self):
        g = ProcessGraph(max_nodes=100)
        add(g, 1, 1, 0, 0, "systemd")
        for i in range(500):
            n = add(g, 1000 + i, (10 + i) * SEC, 1, 1, "p", "systemd")
            g.record_exit(n, (10 + i) * SEC + 1, 0)
        self.assertLessEqual(len(g.nodes), 100)
        self.assertGreater(g.stats["evicted"], 0)
        # the tracking set cannot outgrow the graph it describes
        self.assertLessEqual(len(g._dead), len(g.nodes))

    def test_dead_tracking_survives_a_snapshot_round_trip(self):
        g = ProcessGraph(max_nodes=0)
        add(g, 1, 1, 0, 0, "systemd")
        n = add(g, 100, 10 * SEC, 1, 1, "sh", "systemd")
        g.record_exit(n, 11 * SEC, 0)
        back = ProcessGraph.from_dict(json.loads(json.dumps(g.to_dict())))
        self.assertIn(n.key, back._dead)


# --------------------------------------------------------- tier 4: fid reuse
class FidSharingTest(unittest.TestCase):

    def test_the_same_file_yields_the_same_fid_object(self):
        E._FID_CACHE.clear()
        a = E.file_id("/tmp/x", 11, 8, 0)
        b = E.file_id("/tmp/other-name-same-inode", 11, 8, 0)
        self.assertEqual(a, b)
        self.assertIs(a, b, "fid strings are not shared")
        c = E.file_id("/tmp/p")
        self.assertIs(c, E.file_id("/tmp/p"))

    def test_the_cache_is_bounded_and_keeps_returning_correct_ids(self):
        E._FID_CACHE.clear()
        for i in range(E._FID_CACHE_MAX + 500):
            self.assertEqual(E.file_id("/x", i + 1, 8, 0), "inode:8:%d:0" % (i + 1))
        self.assertLessEqual(len(E._FID_CACHE), E._FID_CACHE_MAX)

    def test_a_relative_path_with_no_inode_is_still_unidentifiable(self):
        self.assertIsNone(E.file_id("relative/path"))


class PerResourceCapEquivalenceTest(unittest.TestCase):
    """v3.6 selects the top-k instead of sorting the whole bucket.

    That is a pure optimisation, so the thing to prove is that it changes
    NOTHING — including which edge wins a timestamp tie, because ties decide
    what a walk shows. The old implementation is the reference.
    """

    @staticmethod
    def _old(items, newest=True, limit=None):
        limit = MAX_EDGES_PER_RESOURCE if limit is None else limit
        groups = {}
        for item in items:
            groups.setdefault(item[1], []).append(item)
        keep = set()
        for bucket in groups.values():
            bucket.sort(key=lambda it: it[0], reverse=newest)
            keep.update(id(it) for it in bucket[:limit])
        return [it for it in items if id(it) in keep]

    def test_top_k_selection_matches_the_full_sort_including_ties(self):
        rnd = random.Random(20261018)
        checks = 0
        for _ in range(2000):
            # Deliberately few distinct timestamps: ties are the risk.
            items = [(rnd.randint(0, 3), rnd.choice("abc"), object())
                     for _ in range(rnd.randint(0, 40))]
            for newest in (True, False):
                for limit in (1, 2, MAX_EDGES_PER_RESOURCE):
                    want = self._old(list(items), newest=newest, limit=limit)
                    got = ProcessGraph._cap_per_resource(list(items),
                                                         newest=newest,
                                                         limit=limit)
                    self.assertEqual([id(x) for x in want], [id(x) for x in got])
                    checks += 1
        self.assertEqual(checks, 12000)


# ------------------------------------- holes found in v3.6's own fixes
#
# An independent reviewer, given only the v3.6 tree and a list of what had
# changed, reproduced four ways the fixes above were incomplete. These pin the
# second round. The lesson each one carries is noted, because all four are the
# same kind of mistake: a guard placed somewhere that can be evicted, or a
# field list written out by hand instead of derived.


class CommitGuardSurvivesDoneEvictionTest(unittest.TestCase):
    """Hole 1 — the W2-B1b guard lived in an LRU and expired.

    `_commit` claims a key by putting it in `done`, and enter()/ok()/_settle
    refuse a key found there. But `done` is capped at `keep_done` (4096 by
    default) and evicts FIFO, so with enough intervening execs the key is
    gone and the guard silently stops applying — the reviewer brought back
    `execs == 1` AND `failed_execs == 1` for one exec with 4100 fillers and
    nothing counted. The authority now lives on the node, which cannot be
    evicted out from under the invariant.
    """

    def _one_exec_then_duplicate(self, keep_done, fillers):
        w, g, p, clock = pipeline()
        p.assembler.keep_done = keep_done
        recs = w.exec_records(1390, 21 * SEC, 22 * SEC, "/bin/cat", ["cat"], "cat")
        for r in recs:
            p.handle(r)
        # unrelated execs by OTHER processes, to push the key out of `done`
        for i in range(fillers):
            w.spawn(4000 + i, 1360, "sh", (30 + i) * SEC)
            for r in w.exec_records(4000 + i, (31 + i) * SEC, (32 + i) * SEC,
                                    "/bin/sh", ["sh"], "sh"):
                p.handle(r)
        self.assertNotIn((1390, 21 * SEC), p.assembler.done,
                         "the fillers did not evict the key; test is vacuous")
        p.handle(recs[0])                      # duplicate EXEC_ENTER
        clock.now += 10.0
        p.tick(force=True)
        node = [n for n in g.nodes.values() if n.pid == 1390][0]
        return node

    def test_the_contradiction_does_not_return_once_done_has_evicted_the_key(self):
        node = self._one_exec_then_duplicate(keep_done=4, fillers=6)
        self.assertEqual((len(node.execs), len(node.failed_execs)), (1, 0))

    def test_the_same_holds_at_the_shipped_keep_done(self):
        node = self._one_exec_then_duplicate(keep_done=4096, fillers=4100)
        self.assertEqual((len(node.execs), len(node.failed_execs)), (1, 0))

    def test_a_late_ok_after_a_failed_settle_adds_no_second_outcome(self):
        """The reverse route, also beyond `done`'s reach."""
        w, g, p, clock = pipeline()
        p.assembler.keep_done = 2
        enter = w.ev(E.EVENT_EXEC_ENTER, 1390, 21 * SEC, "/bin/cat")
        p.handle(enter)
        clock.now += 10.0
        p.tick(force=True)                     # settles as EXEC_FAILED
        node = [n for n in g.nodes.values() if n.pid == 1390][0]
        self.assertEqual(len(node.failed_execs), 1)
        for i in range(4):                     # evict the key from `done`
            w.spawn(4100 + i, 1360, "sh", (40 + i) * SEC)
            for r in w.exec_records(4100 + i, (41 + i) * SEC, (42 + i) * SEC,
                                    "/bin/sh", ["sh"], "sh"):
                p.handle(r)
        ok = w.ev(E.EVENT_EXEC_OK, 1390, 23 * SEC, "/bin/cat", aux=21 * SEC)
        p.handle(ok)
        clock.now += 10.0
        p.tick(force=True)
        self.assertEqual((len(node.execs), len(node.failed_execs)), (0, 1))

    def test_a_genuine_second_exec_by_the_same_process_is_still_recorded(self):
        """The guard must key on the enter timestamp, not on the process."""
        w, g, p, clock = pipeline()
        for i, (enter_ts, ok_ts) in enumerate(((21 * SEC, 22 * SEC),
                                               (31 * SEC, 32 * SEC))):
            for r in w.exec_records(1390, enter_ts, ok_ts, "/bin/cat",
                                    ["cat", str(i)], "cat"):
                p.handle(r)
        node = [n for n in g.nodes.values() if n.pid == 1390][0]
        self.assertEqual(len(node.execs), 2)


class LateArgAtTheCountSlotTest(unittest.TestCase):
    """Residual — idx == MAXARG is a COUNT, which only an END record carries."""

    def test_a_late_non_end_arg_at_the_count_slot_is_refused(self):
        w, g, p, clock = pipeline()
        for r in w.exec_records(1390, 21 * SEC, 22 * SEC, "/bin/cat",
                                ["cat", "x"], "cat"):
            p.handle(r)
        node = [n for n in g.nodes.values() if n.pid == 1390][0]
        p.handle(E.Arg(1390, E.MAXARG, 21 * SEC, "EVIL"))
        self.assertEqual(node.execs[0].argv, ["cat", "x"])
        self.assertEqual(p.assembler.bad_args, 1)

    def test_an_end_record_at_the_count_slot_is_still_accepted(self):
        w, g, p, clock = pipeline()
        for r in w.exec_records(1390, 21 * SEC, 22 * SEC, "/bin/cat",
                                ["a%d" % i for i in range(E.MAXARG)], "cat"):
            p.handle(r)
        node = [n for n in g.nodes.values() if n.pid == 1390][0]
        self.assertEqual(len(node.execs[0].argv), E.MAXARG)
        self.assertEqual(p.assembler.bad_args, 0)


class SnapshotValidationIsDerivedTest(unittest.TestCase):
    """Hole 2 — the required-field list was written out by hand and covered
    14 of the 24 fields the loader reads, so ten still raised a bare
    KeyError. The regression test deleted one of the covered ones and passed.
    """

    def _snap(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        n = add(g, 100, 10 * SEC, 1, 1, "sh", "systemd")
        g.record_open(n, 11 * SEC, "/tmp/x", "W", 3, "inode:8:1:0")
        g.record_connect(n, 12 * SEC, "net:10.0.0.1:443", True)
        return json.loads(json.dumps(g.to_dict()))

    def test_every_process_field_the_loader_reads_is_required(self):
        """Required means "read with p[k]". Fields in _PLAIN_OPT are read
        with p.get() on purpose, because older v4 snapshots predate them —
        the inbound counters, for one — so they must stay optional."""
        base = self._snap()
        # Read with p.get() by the loader, each because a v4 snapshot older
        # than the feature that added it will not have the key: `conns` from
        # v3.4 (outbound), `accepts` from v3.5 (inbound), and everything in
        # _PLAIN_OPT alongside them.
        optional = set(ProcessNode._PLAIN_OPT) | {"conns", "accepts"}
        checked = 0
        for field in sorted(base["processes"][0]):
            if field in optional:
                d = self._snap()
                del d["processes"][0][field]
                ProcessGraph.from_dict(d)       # must still load
                continue
            d = self._snap()
            del d["processes"][0][field]
            with self.assertRaises(ValueError, msg="%s raised no ValueError" % field):
                ProcessGraph.from_dict(d)
            checked += 1
        self.assertGreaterEqual(checked, 20, "too few required fields; derive bug")

    def test_file_and_endpoint_entries_are_validated_too(self):
        # `writes` is deliberately optional: pre-v3.5d snapshots have no
        # separate causal list and the loader rebuilds it from accesses.
        optional = {"writes"}
        for section in ("files", "endpoints"):
            base = self._snap()
            self.assertTrue(base[section], "%s is empty; test is vacuous" % section)
            for field in sorted(base[section][0]):
                d = self._snap()
                del d[section][0][field]
                if field in optional:
                    ProcessGraph.from_dict(d)
                    continue
                with self.assertRaises(ValueError,
                                       msg="%s.%s raised no ValueError"
                                           % (section, field)):
                    ProcessGraph.from_dict(d)

    def test_a_non_integer_pid_is_refused_before_it_reaches_the_sort(self):
        d = self._snap()
        d["processes"][0]["pid"] = "x"
        with self.assertRaises(ValueError):
            ProcessGraph.from_dict(d)
        d = self._snap()
        d["processes"] = {"not": "a list"}
        with self.assertRaises(ValueError):
            ProcessGraph.from_dict(d)

    def test_a_good_snapshot_is_unaffected(self):
        g = ProcessGraph.from_dict(self._snap())
        self.assertEqual(len(g.nodes), 2)
        self.assertEqual(len(g.files), 1)
        self.assertEqual(len(g.endpoints), 1)


class PlaceholderWithNoOwnEventsTest(unittest.TestCase):
    """Hole 3 — the span fix only covered an ADOPTED placeholder.

    One that never gets its own event keeps the borrowed stamp, and because
    _start_ts read first_ns the forward walk began AFTER the fork it was
    supposed to report: "what did this influence?" answered nothing for a
    process whose only known effect is the child that created it, while
    render_tree showed the edge.
    """

    def test_a_never_adopted_placeholder_still_reports_its_child(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        child = add(g, 600, 215 * SEC, 500, 50 * SEC, "child", "parent",
                    ts=219 * SEC)
        ph = g.nodes[g.find(500, 50 * SEC)]
        self.assertFalse(ph.own_span, "the placeholder has its own span; vacuous")
        kinds = [k for _, k, _, _ in g.trace_forward(ph)]
        self.assertIn(FORK, kinds, "the child is invisible as an effect")
        self.assertIn("child(600)", g.render_tree())
        self.assertIn(child.key, ph.children)

    def test_no_bootstrapped_process_has_an_inverted_span(self):
        """"never" over one process was one case; a /proc scan supplies many,
        with start times on both sides of the scan stamp, which is where an
        inverted span came from. The walks are called on each: they read
        first_ns as a bound, so an inversion there plants a cause in the
        future rather than raising."""
        g = ProcessGraph()
        procs = [{"pid": p, "ppid": 1 if p != 1 else 0, "comm": "p%d" % p,
                  "uid": 0, "start_ns": start}
                 for p, start in ((1, 1), (7, 40 * SEC), (9, 0),
                                  (11, 120 * SEC), (13, 60 * SEC))]
        g.bootstrap(procs, 60 * SEC)
        self.assertEqual(len(g.nodes), len(procs))
        for n in g.nodes.values():
            self.assertLessEqual(n.first_ns, n.last_ns,
                                 "pid %d: span %s..%s is inverted"
                                 % (n.pid, n.first_ns, n.last_ns))
            for walk in (g.trace_back, g.trace_forward):
                for line in walk(n):
                    at = line.get("at_ns") if isinstance(line, dict) else None
                    if at is not None:
                        self.assertGreaterEqual(at, 0)


# ------------------------- findings from the adversarial regression hunt
#
# A second independent reviewer, given the v3.6 tree and a description of what
# had changed, attacked it with its own probes. It found a P1 that v3.6
# introduced and two P2s, all in the interaction between the new eviction
# tracking and the new reparent gate. Its own reproductions are reproduced
# here as tests.


class DeadNodeEvictedMidProcessTest(unittest.TestCase):
    """P1, introduced by v3.6 — the worst defect in the release.

    `process()` could hand back a node that no longer existed. Resolving a
    DEAD node and reparenting it reaches `_parent_key`, which creates a
    placeholder, and creating a node runs an eviction pass that is allowed to
    remove any dead node — including the one `process()` was holding. The
    caller's `record_exit` then filed that key in `_dead`, and from then on
    every eviction pass raised KeyError inside `_new_node`: the node cap
    stopped bounding anything, every later event was lost, and the monitor
    counted one error per record for the rest of the run.

    Before v3.6 a dead node was never reparented, so the sequence could not
    arise. Both halves — the reparent gate and `_dead` — are v3.6.
    """

    def _poison_sequence(self):
        g = ProcessGraph(max_nodes=2)
        # a child whose parent was never seen -> placeholder (100, 0), ppid 0
        g.process(200, 100, 100, 100, "child", "parent", 0, 100)
        # pid 100 reused: the placeholder's exit is inferred and it is tracked
        g.process(100, 500, 0, 0, "reused", "", 0, 500)
        # the placeholder's OWN late record, carrying a real ppid
        node = g.process(100, 100, 1, 1, "parent", "init", 0, 600)
        return g, node

    def test_process_never_returns_a_node_it_has_just_evicted(self):
        g, node = self._poison_sequence()
        self.assertIn(node.key, g.nodes,
                      "process() returned a node that is not in the graph")

    def test_the_dead_set_never_holds_a_key_the_graph_does_not(self):
        g, node = self._poison_sequence()
        g.record_exit(node, 600, 0)
        self.assertEqual(set(g._dead) - set(g.nodes), set())

    def test_eviction_does_not_break_for_the_rest_of_the_run(self):
        g, node = self._poison_sequence()
        g.record_exit(node, 600, 0)
        for i in range(50):
            g.process(300 + i, 700 + i, 0, 0, "n", "", 0, 700 + i)  # must not raise
        self.assertEqual(set(g._dead) - set(g.nodes), set())

    def test_note_dead_refuses_a_node_that_is_no_longer_in_the_graph(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        n = add(g, 100, 10 * SEC, 1, 1, "sh", "systemd")
        g._evict(n)
        g._note_dead(n)
        self.assertNotIn(n.key, g._dead)


class InferredExitRespectsTheSpanTest(unittest.TestCase):
    """P2 — the graph said a process exited before it was last seen.

    v3.6 changed the inferred exit to the newer generation's fork time, which
    is the honest bound. But a placeholder still carries a span borrowed from
    the CHILD event that created it, and that stamp can be LATER than the
    proven exit — so `to_dict` and `render_tree` showed an effect before its
    cause, which is one of the two laws the walks are built on.
    """

    def test_an_inferred_exit_is_never_earlier_than_the_last_event(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        # a child at 50 s mints a placeholder parent that started at 10 s
        add(g, 200, 50 * SEC, 100, 10 * SEC, "child", "parent")
        ph = g.nodes[g.find(100, 10 * SEC)]
        self.assertFalse(ph.own_span, "placeholder has its own span; vacuous")
        # pid 100 is reused by a process that forked at 30 s
        add(g, 100, 30 * SEC, 1, 1, "reused", "systemd")
        self.assertFalse(ph.alive)
        self.assertTrue(ph.exit_inferred)
        self.assertLessEqual(ph.last_ns, ph.exit_ns,
                             "exited at %s but last seen at %s"
                             % (ph.exit_ns, ph.last_ns))
        self.assertLessEqual(ph.first_ns, ph.last_ns)

    def test_a_node_with_its_own_span_keeps_it(self):
        """The clamp must not touch a span we actually observed."""
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        n = add(g, 100, 10 * SEC, 1, 1, "real", "systemd")
        g.record_open(n, 90 * SEC, "/tmp/x", "R", 3, "inode:8:1:0")
        self.assertTrue(n.own_span)
        add(g, 100, 30 * SEC, 1, 1, "reused", "systemd")
        self.assertEqual(n.last_ns, 90 * SEC)


class ArgOnlyKeyIsNotClaimedTest(unittest.TestCase):
    """P2 — v3.6 lost an execve that v3.5i recorded correctly.

    `_settle` claimed the key even when there was nothing to record and
    nothing was emitted: ARG records whose ENTER the perf buffer dropped. The
    real ENTER and OK, arriving after the 2 s timeout, were then both
    refused, and the execve produced no record at all.
    """

    def test_args_without_an_enter_do_not_swallow_the_real_exec(self):
        w, g, p, clock = pipeline()
        p.handle(E.Arg(1390, 0, 21 * SEC, "/bin/sh"))
        clock.now += 10.0
        p.tick(force=True)
        self.assertNotIn((1390, 21 * SEC), p.assembler.done,
                         "an ARG-only key was claimed")
        for r in w.exec_records(1390, 21 * SEC, 22 * SEC, "/bin/sh", ["sh"], "sh"):
            p.handle(r)
        node = [n for n in g.nodes.values() if n.pid == 1390][0]
        self.assertEqual(len(node.execs), 1, "the execve was lost")
        self.assertEqual(len(node.failed_execs), 0)


class GenerationNumbersAreNeverReusedTest(unittest.TestCase):
    """P2 (pre-existing, fixed here) — an evicted generation's number was
    handed out again, and `_evict` cleans neither `FileNode.accesses` nor the
    `parent_key` of survivors. A file write was then credited to a later
    process that inherited the number.
    """

    @staticmethod
    def _worlds(forget_watermark):
        reused = 0
        for seed in range(120):
            rnd = random.Random(seed)
            g = ProcessGraph(max_nodes=rnd.choice([3, 4, 5]))
            evicted, minted = set(), []
            real_evict, real_new = g._evict, g._new_node

            def ev(n):
                evicted.add(n.key)
                return real_evict(n)

            def new(pid, *a, **kw):
                if forget_watermark:
                    g._gen_hwm.pop(pid, None)
                node = real_new(pid, *a, **kw)
                if node.key in evicted:
                    minted.append(node.key)
                return node

            g._evict, g._new_node = ev, new
            g.bootstrap([{"pid": 1, "ppid": 0, "comm": "init", "uid": 0,
                          "start_ns": SEC}], 0)
            clock = 10 * SEC
            for _ in range(rnd.randrange(14, 34)):
                clock += rnd.randrange(1, 15) * SEC
                pid = rnd.choice(range(100, 106))
                n = g.process(pid, clock, 1, SEC, "p", "init", 1000, clock)
                g.record_open(n, clock + 1000, "/tmp/f%d" % (pid % 3), "W", 3,
                              "inode:8:%d:0" % (pid % 3))
                if rnd.random() < 0.6:
                    g.record_exit(n, clock + rnd.randrange(1, 9) * SEC, 0)
            reused += len(minted)
        return reused

    def test_no_evicted_generation_number_is_ever_minted_again(self):
        self.assertEqual(self._worlds(forget_watermark=False), 0)

    def test_the_search_can_find_the_bug_it_looks_for(self):
        """Without the watermark the same worlds reuse keys in bulk, so a
        zero above means the fix works rather than that nothing was tried."""
        self.assertGreater(self._worlds(forget_watermark=True), 100)

    def test_the_watermark_is_restored_from_a_snapshot(self):
        """The restored mark only earns its place once the last surviving
        generation of a pid is gone.

        While any generation survives, `_new_node` takes max()+1 over
        `gens[pid]` and reaches the same number with or without the mark — so
        a test that stops at "the new key differs from the existing ones"
        passes even with the restore deleted, which is what the mutation pass
        showed. When every generation of that pid has been evicted, `gens` is
        empty and the mark is the only memory that those numbers were used;
        the snapshot's file accesses still name them.
        """
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        for start in (10 * SEC, 20 * SEC, 30 * SEC):
            n = add(g, 100, start, 1, 1, "p", "systemd")
            g.record_open(n, start + 1000, "/tmp/x", "W", 3, "inode:8:1:0")
        back = ProcessGraph.from_dict(json.loads(json.dumps(g.to_dict())))
        used = {k[1] for k in back.gens[100]}
        self.assertEqual(used, {0, 1, 2})

        for key in list(back.gens[100]):
            back._evict(back.nodes[key])
        # _evict drops the pid's list entirely once it empties, so there is
        # no [] to compare against — asserting one raised KeyError here and
        # the error masked the behaviour this test exists to check.
        self.assertNotIn(100, back.gens)

        fresh = back.process(100, 90 * SEC, 1, SEC, "p", "systemd", 1000, 90 * SEC)
        self.assertNotIn(fresh.key[1], used,
                         "generation %d was already used before the snapshot; "
                         "the file accesses it still name would be credited "
                         "to this process" % fresh.key[1])


class OwnSpanSurvivesASnapshotTest(unittest.TestCase):
    """P3 — `own_span` was not persisted, so a restored placeholder reported
    own_span=True with a borrowed span still in place and never handed it
    back: the W1-F10 symptom returned across a round trip."""

    def test_a_restored_placeholder_still_hands_its_span_back(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        add(g, 201, 219 * SEC, 200, 50 * SEC, "child", "parent")
        back = ProcessGraph.from_dict(json.loads(json.dumps(g.to_dict())))
        ph = back.nodes[back.find(200, 50 * SEC)]
        self.assertFalse(ph.own_span, "own_span did not survive the snapshot")
        back.process(200, 50 * SEC, 1, 1, "parent", "systemd", 1000, 50 * SEC)
        self.assertEqual(ph.last_ns, 50 * SEC)

    def test_a_snapshot_from_a_build_without_the_field_still_loads(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        d = json.loads(json.dumps(g.to_dict()))
        for entry in d["processes"]:
            del entry["own_span"]
        back = ProcessGraph.from_dict(d)
        self.assertTrue(back.get(1).own_span)


class AcceptPeerNameNeedsTheKernelsLengthTest(unittest.TestCase):
    """Found on the VM, 2026-10-18, on the first live run of v3.6 — the one
    defect three rounds of review and 313 unit tests did not catch, because
    it lives in the BPF C and only exists against a real kernel.

    `accept_exit` read the fixed 110-byte `sockaddr_un` out of the caller's
    buffer regardless of how much the kernel had written there. For an
    accepted unix peer the kernel writes **2 bytes** — the family — because a
    client that merely `connect()`s never binds a name; the other 108 bytes
    are whatever the traced process happened to leave on its stack. The code
    then decided "is there a peer name?" by testing `path[0] != 0`.

    Measured with `tools/p15_accept_probe.py` on 5.4.0-216-generic: a marker
    planted in the buffer before `accept()` came out of the monitor as the
    peer identity (`unix:P15_LEAK_MARKER_XXXX...`); zeroing the same buffer
    in the same program on the same socket gave `peer unknown`. Identical
    syscall, identical kernel answer, output decided by 108 bytes the caller
    chose. `dbus-daemon` reproduced it unprompted as `unix:ub<junk>`.

    The fix reads `upeer_addrlen` and copies only what the kernel wrote.
    These two tests pin the USERSPACE half of that contract. They do not
    prove the BPF fix — only a VM re-run of the probe does, and the entry
    in the changelog says so.
    """

    def test_a_nopeer_record_mints_nothing_however_its_path_bytes_read(self):
        """The kernel's "no peer" must win over any bytes in the field.

        Defence in depth behind the BPF fix: if a record ever arrives with
        NOPEER set and junk in `path` — a kernel we have not seen, a future
        edit to the probe — userspace must not rescue the junk into an
        endpoint id. A node minted from a traced process's leftover memory
        is a false provenance fact, which is worse than a missing one.
        """
        w, g, p, _clock = pipeline()
        rec = w.accept(1390, 21 * SEC, path="P15_LEAK_MARKER_XXXX", nopeer=True)
        self.assertTrue(rec.path, "the fixture has no path bytes; test is vacuous")
        p.handle(rec)
        self.assertEqual(g.endpoints, {}, "an endpoint was minted from junk")
        node = [n for n in g.nodes.values() if n.pid == 1390][0]
        self.assertEqual(node.nopeer_accepts, 1)
        self.assertEqual(node.accept_count, 1)

    def test_an_abstract_peer_name_is_a_name_not_an_absence(self):
        """The second, quieter defect the length fix also closes.

        An abstract unix address legitimately begins with a NUL byte, so
        `path[0] == 0` was never a sound test for absence: a client that
        bound an abstract name before connecting would have been filed as
        having no peer at all. The kernel's length tells the two apart,
        because an abstract name makes klen > offsetof(sun_path) exactly as
        a filesystem name does.
        """
        w, g, p, _clock = pipeline()
        p.handle(w.accept(1390, 21 * SEC, path="\0p15abstract",
                          family=E.AF_UNIX, nopeer=False))
        self.assertEqual(sorted(g.endpoints), ["unix:@p15abstract"])

    def test_the_two_cases_are_distinguished_by_length_not_by_first_byte(self):
        """States the rule itself, at the one boundary a unit test can reach:
        both an unnamed peer and an abstract one have `path[0] == 0`, so the
        first byte cannot be what decides. Only the flag can."""
        w, _g, _p, _clock = pipeline()
        unnamed = w.accept(1390, 21 * SEC, path="", family=E.AF_UNIX, nopeer=True)
        abstract = w.accept(1390, 22 * SEC, path="\0p15abstract",
                            family=E.AF_UNIX, nopeer=False)
        self.assertEqual(unnamed.path[0:1], abstract.path[0:1])
        self.assertNotEqual(bool(unnamed.nflags & E.NET_FLAG_NOPEER),
                            bool(abstract.nflags & E.NET_FLAG_NOPEER))
        # The length is what decides, so it is what the call needs. Passing
        # the same path bytes with the two different lengths is the whole
        # point: identical bytes, opposite answers.
        self.assertIsNone(E.inbound_endpoint_id(E.AF_UNIX, b"", abstract.path,
                                                unnamed.addrlen))
        self.assertEqual(E.inbound_endpoint_id(E.AF_UNIX, b"", abstract.path,
                                               abstract.addrlen),
                         "unix:@p15abstract")


class TheObviousAlternativeIsWorseTest(unittest.TestCase):
    """Row 157 argues that "pop after `on_exec` returns" is worse than the
    bug it would fix, and that argument decided the shape of `_commit`. It
    was prose: an independent mutation sweep moved the claim to after the
    fallible call — the exact alternative the docstring rejects — and **no
    test failed**. My own mutation of that fix was cruder (removing the claim
    entirely), which the suite did catch, so the pass had reported the fix as
    covered when its central design argument was not.

    The difference only shows on the failing-sink path, which is why the
    existing sink test missed it: that test asserts the monitor survives, not
    that the exec is committed once.
    """

    def _pipeline_with_a_failing_sink(self):
        calls = []

        class Sink(object):
            """A full disk: the write is attempted and then fails."""

            def write(self, line):
                calls.append(line)
                raise IOError("no space left on device")

            def flush(self):
                pass

        w, g, p, clock = pipeline(log_file=Sink())
        return w, g, p, clock, calls

    def test_a_sink_failure_commits_the_exec_exactly_once(self):
        """Note what this does and does not discriminate. It passes under the
        claim-after mutation too, because `last_settled_exec` independently
        refuses the second graph write — which is how the probe established
        that row 157's stated consequence no longer holds. It is kept as the
        property that actually matters to an analyst (one exec, never also a
        failure); the ORDERING is pinned by the test below."""
        w, g, p, clock, calls = self._pipeline_with_a_failing_sink()
        for r in w.exec_records(1390, 21 * SEC, 22 * SEC, "/bin/sh", ["sh"], "sh"):
            p.handle(r)

        node = [n for n in g.nodes.values() if n.pid == 1390][0]
        self.assertEqual(len(node.execs), 1,
                         "the exec reached the graph %d times" % len(node.execs))
        self.assertTrue(calls, "the sink was never written to; test is vacuous")

        # and no later tick may settle it again, however long the run goes on
        for _ in range(5):
            clock.now += 10.0
            p.tick(force=True)
        self.assertEqual(len(node.execs), 1,
                         "a later tick re-committed the exec (%d now)"
                         % len(node.execs))
        self.assertEqual(len(node.failed_execs), 0,
                         "the exec is in the graph AND recorded as failed — "
                         "the self-contradiction W2-B1b was about")

    def test_the_key_stays_claimed_after_a_partway_commit(self):
        """The mechanism behind the test above, asserted directly: the key is
        claimed before the fallible work, so it is in `done` even though the
        commit never returned a record, and `pending` is empty."""
        w, g, p, clock, _calls = self._pipeline_with_a_failing_sink()
        for r in w.exec_records(1390, 21 * SEC, 22 * SEC, "/bin/sh", ["sh"], "sh"):
            p.handle(r)
        key = (1390, 21 * SEC)
        self.assertIn(key, p.assembler.done,
                      "the key was not claimed, so a later tick will re-settle it")
        self.assertIsNone(p.assembler.done[key],
                          "a commit that raised partway must leave no record")
        self.assertNotIn(key, p.assembler.pending)


class RefusalsAreCountedWhereTheyCanBeSeenTest(unittest.TestCase):
    """The v3.6 duplicate guards refuse records instead of dropping them
    quietly, and the changelog claims that makes the trade visible. It only
    does if the count leaves the process. Both counters were incremented in
    five places and exported from none, so `--stats-json` never carried them:
    an audit of the tree found the claim false. A refusal nobody can count is
    a silent drop with extra steps.
    """

    def test_refused_duplicates_reach_the_stats_json(self):
        w, g, p, clock = pipeline()
        w.spawn(1500, 1, "bash", 9 * SEC)
        for r in w.exec_records(1500, 10 * SEC, 11 * SEC, "/bin/sh", ["sh"], "sh"):
            p.handle(r)
        before = p.stats()["duplicates_refused"]
        # the same ENTER/OK pair again: refused, not recorded twice
        for r in w.exec_records(1500, 10 * SEC, 11 * SEC, "/bin/sh", ["sh"], "sh"):
            p.handle(r)
        after = p.stats()["duplicates_refused"]
        self.assertGreater(after, before,
                           "a refusal happened but no counter left the process")
        node = [n for n in g.nodes.values() if n.pid == 1500][0]
        self.assertEqual(len(node.execs), 1)

    def test_bad_argument_indexes_reach_the_stats_json(self):
        w, g, p, clock = pipeline()
        p.handle(E.Arg(1501, -1, 20 * SEC, "EVIL"))
        self.assertEqual(p.stats()["bad_arg_indexes"], 1)

    def test_both_counters_are_present_from_the_start(self):
        """Absent until non-zero would be worse than useless: a reader cannot
        tell a build that never refuses from one that cannot report it."""
        _w, _g, p, _clock = pipeline()
        s = p.stats()
        self.assertEqual(s["duplicates_refused"], 0)
        self.assertEqual(s["bad_arg_indexes"], 0)

    def test_the_documented_stats_keys_are_the_ones_emitted(self):
        """ARCHITECTURE.md lists the keys. A list nothing checks drifts."""
        _w, _g, p, _clock = pipeline()
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "..", "docs", "ARCHITECTURE.md")) as f:
            text = f.read()
        line = [l for l in text.splitlines() if l.startswith("- **Records:**")]
        self.assertEqual(len(line), 1, "the stats key list moved or was renamed")
        documented = set(re.findall(r"`([a-z_]+)`", line[0]))
        emitted = set(p.stats())
        missing = sorted(emitted - documented - {"records", "graph"})
        self.assertEqual(missing, [], "emitted but undocumented: %s" % missing)


class GuardsBehindGuardsTest(unittest.TestCase):
    """Two v3.6 guards sit behind other guards, so the mutation pass could not
    reach them: nothing in the suite called them directly. These do."""

    def test_place_refuses_a_negative_index(self):
        from hids.processor import _place
        argv = ["a", "b"]
        _place(argv, -1, "EVIL")
        self.assertEqual(argv, ["a", "b"])
        _place(argv, 2, "c")
        self.assertEqual(argv, ["a", "b", "c"])

    def test_touch_hands_a_borrowed_span_back_on_a_direct_record(self):
        """The third guard-behind-a-guard, found by the independent sweep.

        `_touch` has its own `own_span` handback, separate from the one in
        `process()`. Through the pipeline it can never fire: every event
        resolves its node through `process()` first, which hands the span back
        there, so by the time any `record_*` reaches `_touch` the flag is
        already True. Disabling the `_touch` branch therefore failed no test.

        It is still worth one test rather than a comment, because anything
        holding a node reference — a query tool, a replay, a future caller
        that resolves a node once and records several events — reaches
        `_touch` without passing `process()` again. A borrowed span must be
        REPLACED by the node's first own event, not widened to span both: the
        placeholder's stamp came from a child's event at a time this process
        may never have been running (W1-F10).
        """
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        add(g, 201, 219 * SEC, 200, 50 * SEC, "child", "parent")
        ph = g.nodes[g.find(200, 50 * SEC)]
        self.assertFalse(ph.own_span, "not a placeholder; test is vacuous")
        self.assertEqual((ph.first_ns, ph.last_ns), (219 * SEC, 219 * SEC))

        g.record_open(ph, 300 * SEC, "/tmp/x", "R", 3, "inode:8:1:0")

        self.assertTrue(ph.own_span)
        self.assertEqual(ph.first_ns, 300 * SEC,
                         "the borrowed start was widened, not handed back")
        self.assertEqual(ph.last_ns, 300 * SEC)

    def test_the_format_generator_refuses_a_code_table_that_lies(self):
        """The size check in `_struct_format` cannot fire today: padding is
        computed from each field's real offset, so the derived format always
        matches `ctypes.sizeof`. That made it the one guard the mutation pass
        could not reach — reverting it failed nothing.

        But it is not pointless, because what it guards is the CODE TABLE: a
        future entry whose struct code is a different width from its ctypes
        type (`c_long` is 8 bytes while `l` is 4 under `<`) would silently
        decode every following field from the wrong offset. Substituting such
        an entry is the reachable form of that mistake, and it is what this
        checks — so the guard now has a test, and reverting it fails here.
        """
        import ctypes

        class Two(ctypes.Structure):
            _fields_ = [("a", ctypes.c_uint32), ("b", ctypes.c_uint32)]

        fmt, names = E._struct_format(Two)
        self.assertEqual(struct.calcsize(fmt), ctypes.sizeof(Two))

        saved = dict(E._STRUCT_CODES)
        E._STRUCT_CODES[ctypes.c_uint32] = "H"      # 2 bytes, not 4
        try:
            with self.assertRaises(TypeError):
                E._struct_format(Two)
        finally:
            E._STRUCT_CODES.clear()
            E._STRUCT_CODES.update(saved)

        # and the real table is intact afterwards
        self.assertEqual(E._struct_format(Two), (fmt, names))

    def test_every_code_in_the_table_is_the_width_ctypes_says(self):
        """The same mistake, caught at the table rather than per struct."""
        import ctypes
        for ctype, code in E._STRUCT_CODES.items():
            self.assertEqual(struct.calcsize("<" + code), ctypes.sizeof(ctype),
                             "%s is %d bytes but code %r is %d"
                             % (ctype.__name__, ctypes.sizeof(ctype), code,
                                struct.calcsize("<" + code)))

    def test_the_format_generator_refuses_a_layout_it_cannot_describe(self):
        """It must fail loudly rather than decode from guessed offsets."""
        import ctypes

        class Inner(ctypes.Structure):
            _fields_ = [("a", ctypes.c_uint32)]

        class Nested(ctypes.Structure):
            _fields_ = [("x", ctypes.c_uint32), ("inner", Inner)]

        with self.assertRaises(TypeError):
            E._struct_format(Nested)

        class Floaty(ctypes.Structure):
            _fields_ = [("x", ctypes.c_uint32), ("f", ctypes.c_double)]

        with self.assertRaises(TypeError):
            E._struct_format(Floaty)


if __name__ == "__main__":
    unittest.main()
