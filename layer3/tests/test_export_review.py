"""Manager review of stage S1 — tests added after an independent mutation sweep.

The S1 author's own 20 mutants were all killed. A second, differently
imagined sweep (16 mutants) left six alive; one is equivalent (R12: swapping
the tiebreak's src/dst order is still a total, deterministic order). Each
test below kills one of the other five, named in its docstring, and the last
pins a limit of the S1(a) reference rather than a defect in the exporter.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
for p in (ROOT, HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

import recgen                                             # noqa: E402
from recgen import SEC                                    # noqa: E402
from tsvread import loader_view                           # noqa: E402

from hids import replay                                   # noqa: E402
from hids.graph import MAX_ACCESSES_PER_FILE, ProcessGraph  # noqa: E402
from layer3 import export_pidsmaker as ex                 # noqa: E402

EXPORTER = os.path.join(ROOT, "layer3", "export_pidsmaker.py")


class _Tmp(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="p15rev")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def p(self, *n):
        return os.path.join(self.dir, *n)

    def meta(self, out):
        with open(os.path.join(out, "export_meta.json")) as f:
            return json.load(f)


def _graph_with_child(start_exact=True):
    """parent(10) -> child(11), built through the graph's own API."""
    g = ProcessGraph()
    par = g.process(10, 2 * SEC, 1, SEC, "parent", "systemd", 0, 2 * SEC)
    child = g.process(11, 5 * SEC, 10, 2 * SEC, "child", "parent", 0, 5 * SEC)
    assert child.parent_key == par.key
    return g, par, child


class ReviewMutantsTest(_Tmp):

    def test_file_text_is_the_newest_name_the_graph_holds(self):
        """Kills R3 (FILE text taken from the OLDEST path). A renamed file
        keeps one inode identity and several names; the graph orders them
        oldest -> newest (FileNode.add_path), and the export must label the
        entity with the name it has now."""
        r = recgen.Rec()
        r.spawn(100, 1, "mv", 2 * SEC)
        r.open(100, 3 * SEC, "/tmp/stage1", ino=77, dev=2049, igen=1)
        r.open(100, 4 * SEC, "/tmp/stage2", ino=77, dev=2049, igen=1)
        path = self.p("r.p15raw")
        r.write(path)
        out = self.p("o")
        ex.export_recording(path, out)
        ents, _e, _ = loader_view(out)
        files = [e for e in ents if e[1] == "FILE"]
        self.assertEqual(len(files), 1, "one inode must be one entity")
        self.assertEqual(files[0][2], "/tmp/stage2")

    def test_clone_uses_the_graph_fork_time_for_an_estimated_start(self):
        """Kills R4 (CLONE stamped at node.start_ns). For a /proc-bootstrapped
        process the start is an estimate, and ProcessGraph._fork_ts uses the
        earlier of it and the first event so a fork never post-dates its own
        child's activity. The export must use that, not the raw estimate."""
        g, _par, child = _graph_with_child()
        child.start_exact = False          # what bootstrap produces
        child.first_ns = 3 * SEC           # an event seen before the estimate
        self.assertEqual(ProcessGraph._fork_ts(child), 3 * SEC)
        _ents, edges, _r = ex.collect(g, ex.ExportOptions(ts="int-ns"))
        # The parent has its own CLONE from the pid-1 placeholder; only the
        # edge INTO the child is under test.
        into_child = [e for e in edges if e[1] == "EVENT_CLONE"
                      and e[2].startswith("proc:11:")]
        self.assertEqual([c[3] for c in into_child], [str(3 * SEC)])

    def test_the_cli_uses_the_bootstrap_sidecar(self):
        """Kills R9 (CLI drops the sidecar). The library path was tested; the
        CLI is what is actually run on the VM, so it is tested too."""
        path = self.p("r.p15raw")
        recgen.direction_scenario().write(path)
        replay.write_bootstrap(path, [{"pid": 1, "ppid": 0, "comm": "systemd",
                                       "uid": 0, "start_ns": 0}], SEC)
        out = self.p("o")
        rc = subprocess.call([sys.executable, EXPORTER, path, out],
                             stderr=subprocess.DEVNULL)
        self.assertEqual(rc, 0)
        m = self.meta(out)
        self.assertEqual(m["source"]["replay"]["bootstrap_processes"], 1)
        self.assertIsNotNone(m["source"]["bootstrap_sidecar_sha256"])
        # ...and --no-bootstrap really turns it off
        out2 = self.p("o2")
        subprocess.call([sys.executable, EXPORTER, path, out2, "--no-bootstrap"],
                        stderr=subprocess.DEVNULL)
        self.assertEqual(self.meta(out2)["source"]["replay"]["bootstrap_processes"], 0)

    def test_an_unknown_endpoint_scheme_is_dropped_by_name(self):
        """Kills R13 (unknown scheme kept and laid out as if it were unix)."""
        g, par, _child = _graph_with_child()
        g.record_connect(par, 6 * SEC, "weird:abc", True)
        ents, edges, report = ex.collect(g)
        self.assertEqual(report["dropped"].get("unknown_endpoint_scheme"), 1)
        self.assertFalse([e for e in ents if e[1] == "SOCK"])
        self.assertFalse([e for e in edges if e[1] == "EVENT_CONNECT"])

    def test_meta_says_when_their_loader_must_be_patched(self):
        """Kills R16. `int-ns` text read by the UNPATCHED loader is multiplied
        by 1e9 again, so an int-ns export must announce it."""
        path = self.p("r.p15raw")
        recgen.direction_scenario().write(path)
        for ts, want in (("int-ns", True), ("float-s", False)):
            out = self.p(ts)
            ex.export_recording(path, out, ex.ExportOptions(ts=ts))
            self.assertIs(self.meta(out)["loader_patch_required"], want, ts)


class PidsmakerSchemaTest(_Tmp):
    """Every (src type, dst type, event) the export emits is checked against
    PIDSMaker's possible_events (spider @ 0a0f41d, dataset_utils.py:49-82),
    where an unlisted triplet is silently filed as triplet 0 if hetero
    features are on. Found in review by reading their source."""

    def _report(self, **kw):
        path = self.p("r.p15raw")
        if not os.path.exists(path):
            recgen.direction_scenario().write(path)
        return ex.export_recording(path, self.p("o" + str(len(kw))),
                                   ex.ExportOptions(**kw))

    def test_open_edges_are_in_their_schema(self):
        r = self._report(open_as="open")
        self.assertFalse([k for k in r["out_of_schema_triplets"] if "EVENT_OPEN" in k])

    def test_default_accept_mapping_is_reported_as_off_schema(self):
        # Their own audit mapper emits accept as EVENT_CONNECT sock->proc,
        # yet their schema has no (netflow, subject, EVENT_CONNECT). D24.
        r = self._report()
        self.assertEqual(r["out_of_schema_triplets"], {"SOCK->PROC EVENT_CONNECT": 1})

    def test_every_other_default_edge_is_in_their_schema(self):
        r = self._report()
        n_off = sum(r["out_of_schema_triplets"].values())
        self.assertEqual(n_off, 1)
        self.assertGreater(r["edges"], n_off)


class AccessCapLimitTest(_Tmp):
    """Not a mutant: a limit of the S1(a) REFERENCE, found in review.

    S1(a) rebuilds the expected edges from the resource side
    (FileNode.accesses), which the graph trims to MAX_ACCESSES_PER_FILE
    (2000). The exporter reads the process side (node.files, trimmed per
    process at 2000). One file opened more than 2000 times across several
    processes — /etc/ld.so.cache on any real host, within seconds — makes the
    two sides differ although the exporter is right. So S1(a) as written is
    exact only on graphs below every cap, and must not be run on a VM
    recording without a cap-aware reference. This test pins which side the
    export follows: all opens, not the trimmed resource list.
    """

    def test_the_export_is_not_truncated_by_the_per_file_access_cap(self):
        r = recgen.Rec()
        r.spawn(100, 1, "a", 2 * SEC)
        r.spawn(101, 1, "b", 2 * SEC)
        per_proc = 1500                       # below MAX_FILES_PER_PROC
        n = 0
        for _ in range(per_proc):
            for pid in (100, 101):
                r.open(pid, 3 * SEC + n * 1000, "/etc/ld.so.cache",
                       ino=42, dev=2049, igen=1)
                n += 1
        path = self.p("r.p15raw")
        r.write(path)
        g, _ = ex.build_graph_from_recording(path)
        f = next(iter(g.files.values()))
        self.assertEqual(len(f.accesses), MAX_ACCESSES_PER_FILE)
        self.assertEqual(f.access_count, 2 * per_proc)
        _ents, edges, _rep = ex.collect(g)
        self.assertEqual(Counter(e[1] for e in edges)["EVENT_READ"], 2 * per_proc)


if __name__ == "__main__":
    unittest.main()
