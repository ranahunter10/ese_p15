"""Stage S1 gates (a)-(c) for layer3/export_pidsmaker.py.

Each gate is a named class below, and each was mutation-checked: the
exporter was broken on purpose and the named test had to fail
(layer3/tests/MUTANTS_S1.md, re-runnable with layer3/tests/mutate_s1.py).

  S1(a) ConservationGateTest   every graph edge exactly once (multiset
                               equality on a canonical key), entities are
                               exactly the referenced nodes, integrity both
                               ways, ids their loader will not skip
  S1(b) DeterminismGateTest    same recording -> byte-identical files across
                               fresh replays, across PYTHONHASHSEED, and
                               across arrival order of tied records
  S1(c) DirectionGateTest      READ/EXECUTE file->proc, WRITE proc->file,
                               CLONE parent->child, CONNECT per D24

Inputs are P15R recordings built from the kernel's byte layout (recgen.py)
and replayed through the real decode -> processor -> graph path. The
EXPECTED edges in S1(a) are derived from the resource side of the graph
(FileNode/EndpointNode.accesses, children lists); the exporter reads the
process side. They are different code paths in hids/graph.py, so they can
disagree when the exporter is wrong.
"""

import filecmp
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import recgen                                                    # noqa: E402
from recgen import HOSTILE_ARG, HOSTILE_PATH, HOSTILE_UNIX, SEC  # noqa: E402
from tsvread import ID_RE, canon_of, loader_view, their_index, their_ts_ns  # noqa: E402

from hids.graph import (ACCEPT, CONNECT, CONNECT_FAILED, EXEC, READ,  # noqa: E402
                        WRITE, ProcessGraph)
from layer3 import export_pidsmaker as ex                        # noqa: E402

EXPORTER = os.path.join(ROOT, "layer3", "export_pidsmaker.py")


def exact_ns(text):
    """Timestamp text -> int ns, with no float anywhere (unlike their loader)."""
    if "." in text:
        s, frac = text.split(".")
        assert len(frac) == 9, text
        return int(s) * ex.NS + int(frac)
    return int(text)


def expected_edges(graph, opts):
    """The edge multiset the graph contains, read from the RESOURCE side.

    Canonical key: (ts_ns, EVENT_TYPE, src canon, dst canon), where canon is
    what the graph itself calls the node. Plus the number of edges the
    options say must be dropped (so "dropped" is checked too, not trusted).
    """
    P = lambda k: "proc:%d:%d" % k                    # noqa: E731
    out = Counter()
    must_drop = Counter()
    # CLONE from the parent's children list, not from child.parent_key.
    # (No scenario here reparents, so clone_parent=original must equal the
    # default; asserted rather than assumed.)
    assert all(n.reparented_from is None for n in graph.nodes.values())
    for pkey, node in graph.nodes.items():
        for ck in node.children:
            child = graph.nodes.get(ck)
            if child is None:
                continue
            out[(ProcessGraph._fork_ts(child), "EVENT_CLONE", P(pkey), P(ck))] += 1
    for fid, f in graph.files.items():
        F = "file:" + fid
        # One RW open is recorded by the graph as a READ and a WRITE with the
        # same (ts, process). (Two separate R and W opens at the same
        # nanosecond would look the same; no scenario here has one.)
        reads, writes = Counter(), Counter()
        for ts, key, kind in f.accesses:
            if kind == READ:
                reads[(ts, key)] += 1
            elif kind == WRITE:
                writes[(ts, key)] += 1
        for ts, key, kind in f.accesses:
            if kind == EXEC:
                out[(ts, "EVENT_EXECUTE", F, P(key))] += 1
                continue
            both = reads[(ts, key)] > 0 and writes[(ts, key)] > 0
            if opts.open_as == "open":
                if kind == WRITE or not both:
                    out[(ts, "EVENT_OPEN", F, P(key))] += 1
            elif kind == READ:
                if opts.open_as == "rw-writeonly" and both:
                    must_drop["rw_open_read_collapsed"] += 1
                else:
                    out[(ts, "EVENT_READ", F, P(key))] += 1
            else:
                out[(ts, "EVENT_WRITE", P(key), F)] += 1
    for eid, e in graph.endpoints.items():
        S = "sock:" + eid
        for ts, key, kind in e.accesses:
            if eid.startswith("unix:") and opts.unix_endpoints == "drop":
                must_drop["unix_endpoint_edges"] += 1
                continue
            if kind == ACCEPT:
                t = "EVENT_CONNECT" if opts.accept_as == "connect" else "EVENT_ACCEPT"
                out[(ts, t, S, P(key))] += 1
                continue
            if opts.probe_endpoints == "drop" and eid.startswith("net:") \
                    and eid.endswith(":0"):
                must_drop["probe_endpoint_edges"] += 1
                continue
            if kind == CONNECT_FAILED and opts.failed_connects == "drop":
                must_drop["failed_connect"] += 1
                continue
            assert kind in (CONNECT, CONNECT_FAILED), kind
            out[(ts, "EVENT_CONNECT", P(key), S)] += 1
    return out, must_drop


def actual_edges(out_dir):
    ents, edges, _ = loader_view(out_dir)
    known = set(e[0] for e in ents)
    got = Counter()
    for s, t, d, ts in edges:
        if s not in known or d not in known:
            raise AssertionError("dangling edge endpoint: %r" % ((s, t, d),))
        got[(exact_ns(ts), t, canon_of(s), canon_of(d))] += 1
    return got


class _Tmp(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="p15s1")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def p(self, *names):
        return os.path.join(self.dir, *names)

    def record(self, rec, name="rec.p15raw"):
        path = self.p(name)
        rec.write(path)
        return path

    def replayed(self, rec, name="rec.p15raw"):
        """(recording path, graph) — the graph built by the exporter's own
        replay path, so tests check what the CLI would export."""
        path = self.record(rec, name)
        graph, info = ex.build_graph_from_recording(path)
        self.assertEqual(info["records_undecodable"], 0)
        self.assertEqual(info["processor_errors"], 0)
        return path, graph


# =============================================================================
# S1(a) — conservation
# =============================================================================
class ConservationGateTest(_Tmp):
    """S1(a). Counts alone can match with one edge dropped and another
    duplicated, so the comparison is MULTISET equality on a canonical key."""

    OPTION_SETS = [
        {},
        {"open_as": "open"},
        {"open_as": "rw-writeonly"},
        {"accept_as": "accept"},
        {"failed_connects": "connect"},
        {"unix_endpoints": "drop"},
        {"probe_endpoints": "drop"},
        {"clone_parent": "original"},
        {"ts": "int-ns", "wall_offset_ns": 1792400000 * SEC},
    ]

    def _check(self, graph, out_dir, opts):
        report = ex.export_graph(graph, out_dir, opts)
        want, must_drop = expected_edges(graph, opts)
        got = actual_edges(out_dir)
        if opts.wall_offset_ns:
            off = opts.wall_offset_ns
            got = Counter({(k[0] - off,) + k[1:]: n for k, n in got.items()})
        missing = want - got
        extra = got - want
        self.assertFalse(missing, "graph edges absent from edges.tsv: %r" % missing)
        self.assertFalse(extra, "edges.tsv rows the graph does not have: %r" % extra)
        self.assertEqual(sum(got.values()), report["edges"])
        # Every drop the options call for is reported, and nothing else is.
        self.assertEqual(dict(report["dropped"]), dict(must_drop))
        return report

    def test_every_graph_edge_appears_exactly_once_under_every_option_set(self):
        _rec, graph = self.replayed(recgen.full_scenario())
        for i, kw in enumerate(self.OPTION_SETS):
            with self.subTest(options=kw):
                self._check(graph, self.p("out%d" % i), ex.ExportOptions(**kw))

    def test_the_scenario_is_not_trivially_small(self):
        # Guards the gate against going vacuous: if the scenario stopped
        # producing some edge kind, conservation would still "pass".
        _rec, graph = self.replayed(recgen.full_scenario())
        report = self._check(graph, self.p("out"), ex.ExportOptions())
        self.assertEqual(report["edges_by_type"], {
            "EVENT_CLONE": 6, "EVENT_CONNECT": 8, "EVENT_EXECUTE": 3,
            "EVENT_READ": 7, "EVENT_WRITE": 3})
        self.assertEqual(report["edges"], 27)

    def test_entities_are_exactly_the_referenced_nodes(self):
        _rec, graph = self.replayed(recgen.full_scenario())
        out = self.p("out")
        report = ex.export_graph(graph, out)
        ents, edges, _ = loader_view(out)
        ids = [e[0] for e in ents]
        referenced = set()
        for s, _t, d, _ts in edges:
            referenced.update((s, d))
        # both directions of referential integrity
        self.assertEqual(set(ids), referenced)
        self.assertEqual(len(ids), len(set(ids)))
        # every graph node with an edge (resource-side view) is an entity
        want, _ = expected_edges(graph, ex.ExportOptions())
        nodes_with_edges = set()
        for _ts, _t, s, d in want:
            nodes_with_edges.update((s, d))
        self.assertEqual(set(canon_of(i) for i in ids), nodes_with_edges)
        # ...and nodes without one are counted, not vanished
        no_edge = report["graph_nodes_without_edges"]
        self.assertEqual(no_edge, {"PROC": 0, "FILE": 0, "SOCK": 1})
        self.assertEqual(len(graph.nodes) + len(graph.files) + len(graph.endpoints),
                         len(ids) + sum(no_edge.values()))

    def test_every_id_survives_their_index_parse(self):
        # Their loader takes int(id.rsplit("_", 1)[-1]) and SKIPS an entity
        # whose suffix is not an integer — so a bad id is data loss nobody
        # is told about. Indices must be unique, and here also dense.
        _rec, graph = self.replayed(recgen.full_scenario())
        out = self.p("out")
        ex.export_graph(graph, out)
        ents, _edges, _ = loader_view(out)
        for eid, etype, _text in ents:
            self.assertRegex(eid, ID_RE)
            self.assertIn(etype, ("PROC", "FILE", "SOCK"))
        idx = [their_index(e[0]) for e in ents]
        self.assertEqual(sorted(idx), list(range(len(ents))))

    def test_conservation_holds_through_the_cli_on_a_real_recording(self):
        # End to end through hids.replay.run, as `layer3/export_pidsmaker.py
        # rec out` would do it, then compared with an independently built
        # graph of the same recording.
        path = self.record(recgen.full_scenario())
        out = self.p("cli")
        rc = subprocess.call([sys.executable, EXPORTER, path, out],
                             stderr=subprocess.DEVNULL)
        self.assertEqual(rc, 0)
        graph, _ = ex.build_graph_from_recording(path)
        want, _ = expected_edges(graph, ex.ExportOptions())
        self.assertEqual(actual_edges(out), want)


class CloneParentOptionTest(_Tmp):
    """After an orphan is re-parented to init, the graph's parent_key names
    the REAPER; `clone_parent=original` uses the forker it remembers."""

    def test_reparented_child_clone_source_follows_the_option(self):
        rec = recgen.Rec()
        rec.spawn(40, 1, "sh", 2 * SEC)
        rec.open(40, 2 * SEC + 1, "/etc/hosts", ino=2, dev=1, igen=1)
        rec.spawn(50, 40, "daemon", 3 * SEC)
        rec.open(50, 3 * SEC + 1, "/etc/passwd", ino=1, dev=1, igen=1)
        rec.exit(40, 4 * SEC)
        rec.procs[50]["ppid"] = 1                 # orphaned, adopted by init
        rec.open(50, 5 * SEC, "/etc/passwd", ino=1, dev=1, igen=1)
        _p, graph = self.replayed(rec)
        child = graph.nodes[graph.current[50]]
        self.assertEqual(child.reparented_from[0], 40)       # precondition
        self.assertEqual(child.parent_key[0], 1)

        def clone_src(**kw):
            out = self.p("o%d" % len(os.listdir(self.dir)))
            ex.export_graph(graph, out, ex.ExportOptions(**kw))
            _e, edges, _ = loader_view(out)
            return [canon_of(s_) for s_, t, d, _ts in edges
                    if t == "EVENT_CLONE" and canon_of(d) == "proc:50:0"]
        self.assertEqual(clone_src(), ["proc:1:0"])
        self.assertEqual(clone_src(clone_parent="original"), ["proc:40:0"])


class FailureIsCountedNotSilentTest(_Tmp):
    """The exporter may drop things by option, but never quietly."""

    def test_a_failed_connect_is_dropped_by_default_and_counted(self):
        _rec, graph = self.replayed(recgen.full_scenario())
        r = ex.export_graph(graph, self.p("a"))
        self.assertEqual(r["dropped"], {"failed_connect": 1})
        r2 = ex.export_graph(graph, self.p("b"),
                             ex.ExportOptions(failed_connects="connect"))
        self.assertEqual(r2["dropped"], {})
        self.assertEqual(r2["edges"], r["edges"] + 1)
        self.assertEqual(r2["graph_nodes_without_edges"]["SOCK"], 0)

    def test_graph_side_non_edges_are_reported(self):
        _rec, graph = self.replayed(recgen.full_scenario())
        r = ex.export_graph(graph, self.p("a"))
        self.assertEqual(r["graph_non_edges"]["failed_opens"], 1)
        self.assertEqual(r["graph_non_edges"]["unresolved_opens"], 1)
        self.assertEqual(r["graph_non_edges"]["accept_without_peer"], 1)

    def test_an_evicted_parent_is_a_counted_drop(self):
        # max_nodes evicts exited processes; a child then names a parent the
        # graph no longer holds, and a CLONE to it would dangle.
        # (A parent evicted BEFORE its child is first seen comes back as a
        # placeholder, so the dangling case is a parent that exits and is
        # evicted while its child lives on.)
        rec = recgen.Rec()
        rec.spawn(10, 1, "sh", 2 * SEC)
        rec.open(10, 2 * SEC + 1, "/etc/hosts", ino=2, dev=1, igen=1)
        rec.spawn(500, 10, "child", 3 * SEC)
        rec.open(500, 3 * SEC + 1, "/etc/passwd", ino=1, dev=1, igen=1)
        rec.exit(10, 4 * SEC)                   # oldest exit -> evicted first
        for i in range(12):
            rec.spawn(100 + i, 1, "sh", (5 + i) * SEC)
            rec.exit(100 + i, (5 + i) * SEC + 10)
        rec.open(500, 30 * SEC, "/etc/passwd", ino=1, dev=1, igen=1)
        path = self.record(rec)
        graph, _ = ex.build_graph_from_recording(path, max_nodes=5)
        self.assertGreater(graph.stats["evicted"], 0)
        child = graph.nodes[graph.current[500]]
        self.assertNotIn(child.parent_key, graph.nodes)    # the case under test
        r = ex.export_graph(graph, self.p("o"))
        ents, edges, _ = loader_view(self.p("o"))
        known = set(e[0] for e in ents)
        self.assertTrue(all(s in known and d in known for s, _t, d, _ts in edges))
        self.assertEqual(r["dropped"].get("clone_parent_not_in_graph"), 1)
        # sh(10) read /etc/hosts and was then evicted: that edge is gone
        # from the graph's process side, and the export must say so.
        self.assertEqual(
            r["graph_history_capped"]["accesses_by_evicted_processes"], 1)

    def test_stderr_summary_names_drops_and_the_time_base(self):
        path = self.record(recgen.full_scenario())
        p = subprocess.run([sys.executable, EXPORTER, path, self.p("o")],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("DROPPED by exporter: failed_connect=1", p.stderr)
        self.assertIn("boot-relative CLOCK_MONOTONIC", p.stderr)


# =============================================================================
# S1(b) — determinism
# =============================================================================
class DeterminismGateTest(_Tmp):
    FILES = ("entities.tsv", "edges.tsv", "export_meta.json")

    def assertSameExport(self, a, b):
        for name in self.FILES:
            self.assertTrue(filecmp.cmp(os.path.join(a, name), os.path.join(b, name),
                                        shallow=False), name)

    def test_two_fresh_replays_export_byte_identical_files(self):
        path = self.record(recgen.full_scenario())
        ex.export_recording(path, self.p("one"))
        ex.export_recording(path, self.p("two"))
        self.assertSameExport(self.p("one"), self.p("two"))

    def test_hash_randomisation_does_not_reach_the_output(self):
        # Set and dict-of-str iteration order changes with PYTHONHASHSEED; it
        # is the usual way nondeterminism leaks into "sorted enough" output.
        path = self.record(recgen.full_scenario())
        outs = []
        for seed in ("0", "1", "4242"):
            out = self.p("seed" + seed)
            env = dict(os.environ, PYTHONHASHSEED=seed)
            rc = subprocess.call([sys.executable, EXPORTER, path, out],
                                 env=env, stderr=subprocess.DEVNULL)
            self.assertEqual(rc, 0)
            outs.append(out)
        self.assertSameExport(outs[0], outs[1])
        self.assertSameExport(outs[0], outs[2])

    def test_arrival_order_of_tied_records_does_not_change_the_export(self):
        # /etc/hosts and /etc/group are opened at the same nanosecond. Which
        # record the ring delivered first is an accident of per-CPU buffers;
        # the export must not encode it.
        rec = recgen.full_scenario()
        swapped = recgen.full_scenario()
        a, b = swapped.payloads[-3], swapped.payloads[-2]
        swapped.payloads[-3], swapped.payloads[-2] = b, a
        self.assertNotEqual(rec.payloads, swapped.payloads)
        ex.export_recording(self.record(rec, "a.p15raw"), self.p("a"))
        ex.export_recording(self.record(swapped, "b.p15raw"), self.p("b"))
        for name in ("entities.tsv", "edges.tsv"):
            self.assertTrue(filecmp.cmp(self.p("a", name), self.p("b", name),
                                        shallow=False), name)

    def test_edges_are_in_time_order_with_a_total_tiebreak(self):
        path = self.record(recgen.full_scenario())
        ex.export_recording(path, self.p("o"))
        _ents, edges, _ = loader_view(self.p("o"))
        keys = [(exact_ns(ts), t, s, d) for s, t, d, ts in edges]
        self.assertEqual([k[0] for k in keys], sorted(k[0] for k in keys))
        # No two rows are identical in (ts, type, src, dst) in this scenario,
        # so the order is fully determined by the key, never by arrival.
        self.assertEqual(len(set(keys)), len(keys))
        tied = [(t, canon_of(s), canon_of(d)) for ns, t, s, d in keys
                if ns == 25 * SEC]
        self.assertEqual(tied, [
            ("EVENT_READ", "file:inode:2049:131079:1", "proc:200:0"),
            ("EVENT_READ", "file:inode:2049:131080:1", "proc:200:0")])


# =============================================================================
# S1(c) — direction
# =============================================================================
class DirectionGateTest(_Tmp):
    """Information-flow direction, pinned on the smallest story that has one
    edge of every kind (recgen.direction_scenario)."""

    def export(self, **kw):
        path = self.record(recgen.direction_scenario())
        out = self.p("o")
        report = ex.export_recording(path, out, ex.ExportOptions(**kw))
        ents, edges, _ = loader_view(out)
        by_id = dict((e[0], e) for e in ents)

        def name(i):
            _id, kind, text = by_id[i]
            if kind == "SOCK":
                return kind, text
            if kind == "PROC":
                return kind, text.split(" ", 1)[0]
            return kind, text
        rows = [(t, name(s), name(d)) for s, t, d, _ts in edges]
        return rows, report

    def test_read_is_file_to_process(self):
        rows, _ = self.export()
        self.assertIn(("EVENT_READ", ("FILE", "/etc/passwd"), ("PROC", "/bin/cat")), rows)
        self.assertTrue(all(s[0] == "FILE" and d[0] == "PROC"
                            for t, s, d in rows if t == "EVENT_READ"))

    def test_execute_is_file_to_process(self):
        rows, _ = self.export()
        self.assertIn(("EVENT_EXECUTE", ("FILE", "/bin/cat"), ("PROC", "/bin/cat")), rows)
        self.assertTrue(all(s[0] == "FILE" and d[0] == "PROC"
                            for t, s, d in rows if t == "EVENT_EXECUTE"))

    def test_write_is_process_to_file(self):
        rows, _ = self.export()
        self.assertIn(("EVENT_WRITE", ("PROC", "/bin/cat"), ("FILE", "/tmp/out")), rows)
        self.assertTrue(all(s[0] == "PROC" and d[0] == "FILE"
                            for t, s, d in rows if t == "EVENT_WRITE"))

    def test_a_read_write_open_is_both_directions_by_default(self):
        rows, _ = self.export()
        self.assertIn(("EVENT_READ", ("FILE", "/tmp/both"), ("PROC", "/bin/cat")), rows)
        self.assertIn(("EVENT_WRITE", ("PROC", "/bin/cat"), ("FILE", "/tmp/both")), rows)

    def test_clone_is_parent_to_child(self):
        rows, _ = self.export()
        self.assertIn(("EVENT_CLONE", ("PROC", "nginx"), ("PROC", "/bin/cat")), rows)

    def test_outbound_connect_is_process_to_socket(self):
        rows, _ = self.export()
        self.assertIn(("EVENT_CONNECT", ("PROC", "/bin/cat"), ("SOCK", "NA NA 1.2.3.4 443")),
                      rows)

    def test_accept_is_socket_to_process_as_connect_by_default(self):
        rows, report = self.export()
        self.assertIn(("EVENT_CONNECT", ("SOCK", "5.6.7.8 NA NA NA"), ("PROC", "nginx")),
                      rows)
        self.assertEqual(report["out_of_vocabulary_types"], [])

    def test_accept_as_accept_keeps_the_direction_and_flags_the_vocabulary(self):
        rows, report = self.export(accept_as="accept")
        self.assertIn(("EVENT_ACCEPT", ("SOCK", "5.6.7.8 NA NA NA"), ("PROC", "nginx")),
                      rows)
        self.assertEqual(report["out_of_vocabulary_types"], ["EVENT_ACCEPT"])

    def test_open_as_open_is_one_file_to_process_edge_per_open(self):
        # file->process, as PIDSMaker's own possible_events has it (review).
        rows, report = self.export(open_as="open")
        opens = [r for r in rows if r[0] == "EVENT_OPEN"]
        self.assertEqual(sorted(s[1] for _t, s, _d in opens),
                         ["/etc/passwd", "/tmp/both", "/tmp/out"])
        self.assertTrue(all(d[0] == "PROC" for _t, _s, d in opens))
        self.assertFalse([r for r in rows if r[0] in ("EVENT_READ", "EVENT_WRITE")])
        self.assertEqual(report["open_modes"], {"R": 1, "RW": 1, "W": 1})

    def test_rw_writeonly_collapses_rw_to_write_and_counts_it(self):
        rows, report = self.export(open_as="rw-writeonly")
        self.assertNotIn(("EVENT_READ", ("FILE", "/tmp/both"), ("PROC", "/bin/cat")), rows)
        self.assertIn(("EVENT_WRITE", ("PROC", "/bin/cat"), ("FILE", "/tmp/both")), rows)
        self.assertEqual(report["dropped"], {"rw_open_read_collapsed": 1})

    def test_the_whole_direction_table(self):
        # One assertion over the complete edge list, so an edge that appears
        # with the wrong direction AND the right one cannot slip through.
        rows, _ = self.export()
        self.assertEqual(sorted(rows), sorted([
            ("EVENT_CLONE", ("PROC", "systemd"), ("PROC", "nginx")),
            ("EVENT_CONNECT", ("SOCK", "5.6.7.8 NA NA NA"), ("PROC", "nginx")),
            ("EVENT_CLONE", ("PROC", "nginx"), ("PROC", "/bin/cat")),
            ("EVENT_EXECUTE", ("FILE", "/bin/cat"), ("PROC", "/bin/cat")),
            ("EVENT_READ", ("FILE", "/etc/passwd"), ("PROC", "/bin/cat")),
            ("EVENT_WRITE", ("PROC", "/bin/cat"), ("FILE", "/tmp/out")),
            ("EVENT_READ", ("FILE", "/tmp/both"), ("PROC", "/bin/cat")),
            ("EVENT_WRITE", ("PROC", "/bin/cat"), ("FILE", "/tmp/both")),
            ("EVENT_CONNECT", ("PROC", "/bin/cat"), ("SOCK", "NA NA 1.2.3.4 443")),
        ]))


# =============================================================================
# Contract details: escaping, timestamps, entity text, meta
# =============================================================================
class HostileStringsTest(_Tmp):
    """Paths, argv and unix names are chosen by whoever runs the process. A
    tab shifts columns; a newline (or a bare CR, under universal newlines)
    ends the line and lets the remainder FORGE a row."""

    def test_a_hostile_path_cannot_add_lines_or_columns(self):
        path = self.record(recgen.full_scenario(with_hostile=True))
        out = self.p("o")
        report = ex.export_recording(path, out)
        ents, edges, (n_ent_lines, n_edge_lines) = loader_view(out)
        self.assertEqual(n_ent_lines, report["entities"] + 1)
        self.assertEqual(n_edge_lines, report["edges"] + 1)
        self.assertTrue(all(len(e) == 3 and e[1] in ("PROC", "FILE", "SOCK") for e in ents))
        self.assertTrue(all(len(e) == 4 for e in edges))
        for _s, t, _d, ts in edges:
            self.assertIn(t, ex.PIDSMAKER_VOCAB)
            exact_ns(ts)

    def test_the_hostile_strings_are_recoverable_exactly(self):
        path = self.record(recgen.full_scenario(with_hostile=True))
        out = self.p("o")
        ex.export_recording(path, out)
        ents, _edges, _ = loader_view(out)
        files = [ex.tsv_unescape(t) for _i, k, t in ents if k == "FILE"]
        self.assertIn(HOSTILE_PATH, files)
        procs = [t for _i, k, t in ents if k == "PROC"]
        payload = [t for t in procs if ex.tsv_unescape(t.split(" ", 1)[0]) == HOSTILE_PATH]
        self.assertEqual(len(payload), 1, "exe must be the whole first token")
        self.assertEqual(ex.tsv_unescape(payload[0].split(" ", 1)[1]),
                         "payload " + HOSTILE_ARG)
        socks = [t.split() for _i, k, t in ents if k == "SOCK"]
        self.assertTrue(all(len(s) == 4 for s in socks), socks)
        self.assertIn(HOSTILE_UNIX, [ex.tsv_unescape(s[2]) for s in socks])

    def test_escape_round_trips_every_awkward_character(self):
        samples = ["", "plain", "\\", "\\t", "\t", "\\\t", "a\\x41", "\x00\x1f\x7f",
                   "\x85  ", "é漢字", "\ud800", " sp ace "]
        samples += [chr(c) for c in range(0, 0x300)]
        samples += [c for c in map(chr, range(0x110000)) if c.isspace()]
        for s in samples:
            for space in (False, True):
                e = ex.tsv_escape(s, space=space)
                self.assertEqual(ex.tsv_unescape(e), s)
                for bad in "\t\n\r\x0b\x0c\x1c\x1d\x1e\x85  ":
                    self.assertNotIn(bad, e)       # str.splitlines() breaks on these
                e.encode("utf-8")                  # always encodable
                if space:
                    self.assertNotIn(" ", e)
                    # their SOCK parse is str.split(): ALL Unicode whitespace
                    self.assertEqual(len(e.split()), 1 if e else 0, repr(s))

    def test_escaping_is_injective_on_the_classic_collision(self):
        # backslash-t (two characters) and TAB must not export the same
        self.assertNotEqual(ex.tsv_escape("a\\tb"), ex.tsv_escape("a\tb"))


class TimestampTest(unittest.TestCase):
    """D23, and the time-base finding."""

    NS_EPOCH = 1792400000123456789     # 2026-10-19-ish, 9 significant ns digits

    def test_float_seconds_text_is_exact_on_our_side(self):
        self.assertEqual(ex.format_ts(self.NS_EPOCH, "float-s"), "1792400000.123456789")
        self.assertEqual(ex.format_ts(5, "float-s"), "0.000000005")
        self.assertEqual(ex.format_ts(0, "float-s"), "0.000000000")

    def test_their_float_parse_loses_exactly_21_ns_here(self):
        # Pinned so nobody later mistakes the float path for lossless: their
        # loader does int(float(text) * 1e9), and a double near 1.79e9 s
        # cannot hold nanoseconds.
        text = ex.format_ts(self.NS_EPOCH, "float-s")
        self.assertEqual(their_ts_ns(text), 1792400000123456768)
        self.assertEqual(their_ts_ns(text) - self.NS_EPOCH, -21)

    def test_their_float_parse_loses_up_to_a_few_hundred_ns_near_today(self):
        # A double's spacing at 1.79e9 is 2**-22 s = 238 ns; *1e9 and int()
        # add a little more. Measured worst over a fixed sample.
        import random
        r = random.Random(7)
        worst = 0
        for _ in range(20000):
            ns = 1792400000 * ex.NS + r.randrange(ex.NS)
            worst = max(worst, abs(their_ts_ns(ex.format_ts(ns, "float-s")) - ns))
        self.assertGreater(worst, 200)
        self.assertLess(worst, 300)

    def test_boot_relative_times_survive_their_float_parse_far_better(self):
        # The default export is boot-relative (see test below), and at
        # ~1e5 s a double still resolves ~15 ps, so their parse is within
        # 1 ns. This is a property of the default, not a reason for it.
        for ns in (10 * SEC + 1, 86399 * SEC + 999999999):
            self.assertLessEqual(abs(their_ts_ns(ex.format_ts(ns, "float-s")) - ns), 1)

    def test_int_ns_is_exact_but_needs_their_loader_patched(self):
        text = ex.format_ts(self.NS_EPOCH, "int-ns")
        self.assertEqual(text, "1792400000123456789")
        self.assertEqual(int(text), self.NS_EPOCH)
        # Unpatched, their loader would multiply integer ns by 1e9 again.
        self.assertNotEqual(their_ts_ns(text), self.NS_EPOCH)

    def test_negative_timestamps_are_refused(self):
        with self.assertRaises(ValueError):
            ex.format_ts(-1, "float-s")


class TimeBaseTest(_Tmp):
    """FINDING: a replayed graph carries CLOCK_MONOTONIC ns since boot. The
    BPF stamps bpf_ktime_get_ns(); Clock.offset is used only for log text
    and replay pins it to 0; the P15R header is magic+version; the bootstrap
    sidecar's ts_ns is monotonic too. No anchor to the wall clock exists in
    a recording, so the exporter takes one as an explicit input."""

    def test_default_export_is_boot_relative_and_says_so(self):
        path = self.record(recgen.direction_scenario())
        ex.export_recording(path, self.p("o"))
        _e, edges, _ = loader_view(self.p("o"))
        first = exact_ns(edges[0][3])
        self.assertEqual(first, 2 * SEC)          # the recording's own clock
        with open(self.p("o", "export_meta.json")) as f:
            meta = json.load(f)
        self.assertIn("NOT unix epoch", meta["time_base"])
        self.assertEqual(meta["options"]["wall_offset_ns"], 0)

    def test_wall_offset_shifts_every_timestamp_exactly(self):
        path = self.record(recgen.full_scenario())
        off = 1792400000 * SEC + 123456789
        ex.export_recording(path, self.p("a"))
        ex.export_recording(path, self.p("b"), ex.ExportOptions(wall_offset_ns=off))
        _ea, a, _ = loader_view(self.p("a"))
        _eb, b, _ = loader_view(self.p("b"))
        self.assertEqual([r[:3] for r in a], [r[:3] for r in b])
        self.assertEqual([exact_ns(r[3]) + off for r in a], [exact_ns(r[3]) for r in b])

    def test_a_negative_offset_is_refused(self):
        with self.assertRaises(ValueError):
            ex.ExportOptions(wall_offset_ns=-1)


class EntityTextTest(_Tmp):
    def test_proc_text_is_exe_then_cmdline_and_splits_like_theirs(self):
        path = self.record(recgen.full_scenario(with_hostile=False))
        ex.export_recording(path, self.p("o"))
        ents, _e, _ = loader_view(self.p("o"))
        procs = dict((canon_of(i), t) for i, k, t in ents if k == "PROC")
        self.assertEqual(procs["proc:201:0"],
                         "/usr/bin/curl curl -o /tmp/p http://198.51.100.5/p")
        # their split: path = text up to the first space
        self.assertEqual(procs["proc:201:0"].split(" ", 1)[0], "/usr/bin/curl")
        # a process that never exec'd falls back to its comm, and is counted
        self.assertEqual(procs["proc:300:0"], "bash")

    def test_sock_text_puts_the_peer_where_their_mapper_does(self):
        path = self.record(recgen.full_scenario(with_hostile=False))
        ex.export_recording(path, self.p("o"))
        ents, _e, _ = loader_view(self.p("o"))
        socks = dict((canon_of(i), t) for i, k, t in ents if k == "SOCK")
        self.assertEqual(socks["sock:net:198.51.100.5:80"], "NA NA 198.51.100.5 80")
        self.assertEqual(socks["sock:net:[2001:db8::1]:443"], "NA NA 2001:db8::1 443")
        self.assertEqual(socks["sock:host:203.0.113.9"], "203.0.113.9 NA NA NA")
        self.assertEqual(socks["sock:host:[2001:db8::7]"], "2001:db8::7 NA NA NA")
        self.assertEqual(socks["sock:unix:/run/sshd.sock"], "NA NA /run/sshd.sock NA")

    def test_a_reused_pid_is_two_entities(self):
        path = self.record(recgen.full_scenario(with_hostile=False))
        ex.export_recording(path, self.p("o"))
        ents, _e, _ = loader_view(self.p("o"))
        canon = set(canon_of(i) for i, _k, _t in ents)
        self.assertTrue({"proc:300:0", "proc:300:1"} <= canon)

    def test_a_placeholder_must_be_one_token(self):
        for bad in ("", "N A", "a\tb", "x\\y"):
            with self.assertRaises(ValueError):
                ex.ExportOptions(sock_placeholder=bad)
        ex.ExportOptions(sock_placeholder="-")

    def test_an_unknown_option_value_is_refused(self):
        with self.assertRaises(ValueError):
            ex.ExportOptions(open_as="read")
        with self.assertRaises(TypeError):
            ex.ExportOptions(nonsense=1)


class MetaTest(_Tmp):
    def test_meta_records_input_hash_options_and_counts(self):
        path = self.record(recgen.full_scenario())
        opts = ex.ExportOptions(open_as="open", accept_as="accept")
        report = ex.export_recording(path, self.p("o"), opts)
        with open(self.p("o", "export_meta.json")) as f:
            meta = json.load(f)
        with open(path, "rb") as f:
            self.assertEqual(meta["source"]["recording_sha256"],
                             hashlib.sha256(f.read()).hexdigest())
        self.assertEqual(meta["options"], dict(opts.as_dict()))
        self.assertEqual(meta["exporter_version"], ex.EXPORTER_VERSION)
        self.assertEqual(meta["report"]["edges"], report["edges"])
        self.assertEqual(sum(meta["report"]["edges_by_type"].values()), report["edges"])
        self.assertEqual(sum(meta["report"]["entities_by_type"].values()),
                         report["entities"])
        self.assertEqual(meta["report"]["out_of_vocabulary_types"], ["EVENT_ACCEPT"])
        self.assertIsNone(meta["source"]["bootstrap_sidecar_sha256"])

    def test_every_open_decision_is_a_cli_flag(self):
        # An option that exists only in the library would be a decision the
        # CLI user cannot see or change.
        a = ex.parse_args(["rec", "out"])
        for k in ex.ExportOptions.DEFAULTS:
            self.assertEqual(getattr(a, k), ex.ExportOptions.DEFAULTS[k], k)

    def test_the_bootstrap_sidecar_is_used_and_hashed(self):
        from hids import replay
        rec = recgen.direction_scenario()
        path = self.record(rec)
        replay.write_bootstrap(path, [{"pid": 1, "ppid": 0, "comm": "systemd",
                                       "uid": 0, "start_ns": 0}], SEC)
        ex.export_recording(path, self.p("o"))
        with open(self.p("o", "export_meta.json")) as f:
            meta = json.load(f)
        self.assertIsNotNone(meta["source"]["bootstrap_sidecar_sha256"])
        self.assertEqual(meta["source"]["replay"]["bootstrap_processes"], 1)

    def test_a_non_recording_is_an_error_not_an_empty_export(self):
        bad = self.p("x.jsonl")
        with open(bad, "w") as f:
            f.write('{"type": "EXEC"}\n')
        p = subprocess.run([sys.executable, EXPORTER, bad, self.p("o")],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True)
        self.assertEqual(p.returncode, 2)
        self.assertIn("not a P15 raw recording", p.stderr)
        self.assertFalse(os.path.exists(self.p("o")))


if __name__ == "__main__":
    unittest.main()
