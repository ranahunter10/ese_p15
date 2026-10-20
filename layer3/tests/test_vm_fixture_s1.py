"""Stage S1 on a REAL VM recording (layer3/fixtures/s1_mixed).

Every other S1 test uses synthetic kernel records. This file runs the same
exporter on a 90 s recording Ashu made on the VM from locked v3.7, and checks
two things:

  S1(b-vm)  determinism: exporting the replay of this recording twice, in
            fresh processes with different hash seeds, gives byte-identical
            files;
  S1(m)     markers: each workload step Ashu timestamped appears in the
            export as the edges that step must produce, inside its own
            marker window.

The marker windows need the graph's boot-relative timestamps on the
markers' unix-epoch clock. The anchor comes from the JSONL log
(vmfixture.wall_offset_interval): a 641 ns window. Every edge checked here
is required to sit inside its step's window even at the worst end of that
window, so the anchor's uncertainty cannot move an edge across a boundary.

What the recording shows, in contrast to how the steps read in the workload
script:
  * EXEC_chain is TWO processes. `bash -c 'sh -c "..."'` execs sh in place
    (bash's single-command exec), so one process EXECUTEs /usr/bin/bash and
    then /usr/bin/sh; sh forks the child that EXECUTEs /usr/bin/cat.
  * FILE_flow is ONE process: the forked child opens exfil.txt for writing
    while still bash (the redirect), then execs cat, which reads drop.txt.
  * The accept on 127.0.0.1:8765 carries no port on the server's side: the
    graph keys an inbound peer by address only (events.inbound_endpoint_id)
    and does not record its own listening port. 8765 is visible on the
    CLIENT's connect. Both sides are checked.
  * "example.com" is not in the graph, which sees addresses, not names. The
    process connects to the stub resolver (127.0.0.53:53) and then to four
    port-80 addresses, one of them twice. Some of these are glibc's
    getaddrinfo() source-address probes, which carry the real port (open
    question D4 / gate G4). The export cannot tell probes from the real
    connection, and this test pins that rather than pretending otherwise.
"""

import filecmp
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

import vmfixture as vf                                    # noqa: E402
from tsvread import canon_of, loader_view                 # noqa: E402

from layer3 import export_pidsmaker as ex                 # noqa: E402

EXPORTER = os.path.join(ROOT, "layer3", "export_pidsmaker.py")
FILES = ("entities.tsv", "edges.tsv", "export_meta.json")


class _Fixture(unittest.TestCase):
    """Unpack once, replay once, export once (epoch-anchored, integer ns)."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="p15vm")
        cls.f = vf.extract(cls.dir)
        cls.lo, cls.hi = vf.wall_offset_interval(cls.f["s1_mixed.jsonl"])
        cls.marks = vf.markers(cls.f["s1_markers.txt"])
        cls.graph, cls.info = ex.build_graph_from_recording(cls.f["s1_mixed.p15r"])
        cls.out = os.path.join(cls.dir, "export")
        cls.report = ex.export_graph(cls.graph, cls.out,
                                     ex.ExportOptions(ts="int-ns", wall_offset_ns=cls.lo))
        ents, edges, _ = loader_view(cls.out)
        cls.text = {e[0]: e[2] for e in ents}
        # (epoch ns at the anchor's low end, type, src canon, src text, dst canon, dst text)
        cls.edges = [(int(ts), t, canon_of(s), cls.text[s], canon_of(d), cls.text[d])
                     for s, t, d, ts in edges]

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def window(self, step):
        names = [m[1] for m in self.marks]
        i = names.index(step)
        return self.marks[i][0], self.marks[i + 1][0]

    def in_step(self, step):
        """Edges that lie inside `step`'s window under EVERY offset in the
        anchor interval: at the low end ts >= start, and at the high end
        ts + width < next marker."""
        a, b = self.window(step)
        w = self.hi - self.lo
        return [e for e in self.edges if a <= e[0] and e[0] + w < b]

    @staticmethod
    def of(edges, etype, src=None, dst=None):
        """Filter by type and by a predicate on (canon, text) of each end."""
        return [e for e in edges if e[1] == etype
                and (src is None or src(e[2], e[3]))
                and (dst is None or dst(e[4], e[5]))]


def is_file(path):
    return lambda c, t: c.startswith("file:") and t == path


def is_proc(c=None):
    return lambda cc, t: cc.startswith("proc:") and (c is None or cc == c)


def is_sock(text):
    return lambda c, t: c.startswith("sock:") and t == text


class FixtureIntegrityTest(_Fixture):

    def test_bundle_hash_is_the_one_ashu_recorded(self):
        self.assertEqual(vf.sha256(vf.BUNDLE), vf.BUNDLE_SHA256)
        man = vf.manifest()
        self.assertEqual(man["s1_mixed_bundle.tgz"], vf.BUNDLE_SHA256)
        for name in vf.MEMBERS:
            self.assertEqual(vf.sha256(self.f[name]), man["bundle/" + name], name)

    def test_replay_matches_what_the_vm_reported(self):
        # The VM's own numbers (s1_mixed.stats.json): the container replay
        # must rebuild the same graph from the same bytes.
        import json
        with open(self.f["s1_mixed.stats.json"]) as fh:
            st = json.load(fh)
        self.assertEqual(st["lost"], 0)
        self.assertEqual(self.info["records_decoded"], st["records"]["raw"])   # 5553
        self.assertEqual(self.info["records_undecodable"], 0)
        self.assertEqual(self.info["processor_errors"], 0)
        self.assertEqual(len(self.graph.nodes), st["graph"]["processes"])     # 197
        self.assertEqual(len(self.graph.files), st["graph"]["files"])         # 1274
        self.assertEqual(len(self.graph.endpoints), st["graph"]["endpoints"])  # 12

    def test_the_clock_anchor_is_tight_and_puts_markers_inside_the_recording(self):
        self.assertLess(self.hi - self.lo, 1000)          # 641 ns; < 1 us
        first, last = self.edges[0][0], self.edges[-1][0]
        for ts, step in self.marks:
            self.assertTrue(first < ts < last, step)
        self.assertEqual([m[1] for m in self.marks][-1], "DONE")
        self.assertNotIn("NET_outbound_FAILED", [m[1] for m in self.marks])

    def test_the_graph_cap_loss_on_this_recording_is_reported(self):
        # Not an exporter defect: hids.graph trims each process's open
        # history at MAX_FILES_PER_PROC (2000). lxqt-panel opened
        # ~/.config/user-dirs.dirs 2,492 times in 90 s, so the graph kept
        # fewer opens than the kernel delivered. The export must say so.
        capped = self.report["graph_history_capped"]
        self.assertEqual(capped["opens_trimmed_by_graph_cap"], 605)


class ByteIdenticalExportTest(_Fixture):
    """S1(b-vm): the gate Ashu asked for, on the real recording."""

    def test_export_of_two_fresh_replays_is_byte_identical(self):
        outs = []
        for seed in ("0", "4242"):
            out = os.path.join(self.dir, "det" + seed)
            env = dict(os.environ, PYTHONHASHSEED=seed)
            rc = subprocess.call([sys.executable, EXPORTER, self.f["s1_mixed.p15r"], out,
                                  "--ts", "int-ns", "--wall-offset-ns", str(self.lo)],
                                 env=env, stderr=subprocess.DEVNULL)
            self.assertEqual(rc, 0)
            outs.append(out)
        for name in FILES:
            self.assertTrue(filecmp.cmp(os.path.join(outs[0], name),
                                        os.path.join(outs[1], name), shallow=False), name)
        # ...and the in-process export of this class's own replay is the same
        # bytes too, apart from the meta (which names the recording's path
        # as given; the graph-derived TSVs must match exactly).
        for name in ("entities.tsv", "edges.tsv"):
            self.assertTrue(filecmp.cmp(os.path.join(outs[0], name),
                                        os.path.join(self.out, name), shallow=False), name)


class MarkerStepsTest(_Fixture):
    """S1(m): each marker step appears as the edges it must produce."""

    def test_exec_chain_bash_sh_cat(self):
        e = self.in_step("EXEC_chain")
        bash = self.of(e, "EVENT_EXECUTE", src=is_file("/usr/bin/bash"), dst=is_proc())
        sh = self.of(e, "EVENT_EXECUTE", src=is_file("/usr/bin/sh"), dst=is_proc())
        self.assertEqual(len(bash), 1)
        self.assertEqual(len(sh), 1)
        p = bash[0][4]
        # one process: bash replaced itself with sh, after it
        self.assertEqual(sh[0][4], p)
        self.assertLess(bash[0][0], sh[0][0])
        # sh forked the child that became cat, and cat read /etc/hostname
        clone = self.of(e, "EVENT_CLONE", src=is_proc(p), dst=is_proc())
        self.assertEqual(len(clone), 1)
        c = clone[0][4]
        self.assertEqual(len(self.of(e, "EVENT_EXECUTE", src=is_file("/usr/bin/cat"),
                                     dst=is_proc(c))), 1)
        self.assertEqual(len(self.of(e, "EVENT_READ", src=is_file("/etc/hostname"),
                                     dst=is_proc(c))), 1)

    def test_file_flow_drop_to_cat_to_exfil(self):
        e = self.in_step("FILE_flow")
        made = self.of(e, "EVENT_WRITE", src=is_proc(), dst=is_file("/tmp/s1w/drop.txt"))
        read = self.of(e, "EVENT_READ", src=is_file("/tmp/s1w/drop.txt"), dst=is_proc())
        wrote = self.of(e, "EVENT_WRITE", src=is_proc(), dst=is_file("/tmp/s1w/exfil.txt"))
        self.assertEqual((len(made), len(read), len(wrote)), (1, 1, 1))
        c = read[0][4]
        self.assertEqual(wrote[0][2], c, "drop.txt and exfil.txt meet in one process")
        self.assertNotEqual(made[0][2], c, "drop.txt was written by someone else")
        self.assertLess(made[0][0], read[0][0])
        self.assertEqual(len(self.of(e, "EVENT_EXECUTE", src=is_file("/usr/bin/cat"),
                                     dst=is_proc(c))), 1)
        # the child came from a process that ran bash
        parent = self.of(e, "EVENT_CLONE", src=is_proc(), dst=is_proc(c))
        self.assertEqual(len(parent), 1)
        self.assertTrue(self.of(e, "EVENT_EXECUTE", src=is_file("/usr/bin/bash"),
                                dst=is_proc(parent[0][2])))
        # the flow is a path in the graph: drop.txt -> c -> exfil.txt
        self.assertEqual((read[0][4], wrote[0][2]), (c, c))

    def test_accept_on_127_0_0_1_port_8765(self):
        start = self.in_step("NET_local_server")
        srv = [x for x in self.of(start, "EVENT_EXECUTE", src=is_file("/usr/bin/python3"),
                                  dst=is_proc()) if "http.server 8765" in x[5]]
        self.assertEqual(len(srv), 1)
        s = srv[0][4]
        inbound = is_sock("127.0.0.1 NA NA NA")       # host:127.0.0.1, no port by design
        to_8765 = is_sock("NA NA 127.0.0.1 8765")      # net:127.0.0.1:8765
        for step in ("NET_local_fetch", "NET_local_fetch2"):
            e = self.in_step(step)
            acc = self.of(e, "EVENT_CONNECT", src=inbound, dst=is_proc(s))
            con = self.of(e, "EVENT_CONNECT", src=is_proc(), dst=to_8765)
            self.assertEqual((len(acc), len(con)), (1, 1), step)
            self.assertNotEqual(con[0][2], s, "the client is not the server")
        # exactly two accepts in the whole export, both into the server
        all_acc = self.of(self.edges, "EVENT_CONNECT", src=inbound)
        self.assertEqual([x[4] for x in all_acc], [s, s])

    def test_connect_to_example_com(self):
        e = self.in_step("NET_outbound")
        procs = [x for x in self.of(e, "EVENT_EXECUTE", src=is_file("/usr/bin/python3"),
                                    dst=is_proc()) if "example.com" in x[5]]
        self.assertEqual(len(procs), 1)
        o = procs[0][4]
        mine = self.of(e, "EVENT_CONNECT", src=is_proc(o), dst=lambda c, t: True)
        # name resolution goes to the local stub resolver first
        self.assertEqual(mine[0][5], "NA NA 127.0.0.53 53")
        port80 = [x for x in mine if x[5].endswith(" 80")]
        self.assertEqual(Counter(x[5] for x in port80), Counter({
            "NA NA 104.20.23.154 80": 2,
            "NA NA 172.66.147.243 80": 1,
            "NA NA 2606:4700:10::ac42:93f3 80": 1,
            "NA NA 2606:4700:10::6814:179a 80": 1,
        }))
        # The last connect is the one that fetched the page. The four before
        # it carry the same port 80, so in the export they are
        # indistinguishable from it (D4 / G4). Pinned, not filtered.
        self.assertEqual(port80[-1][5], "NA NA 104.20.23.154 80")
        self.assertEqual(mine[-1], port80[-1])


if __name__ == "__main__":
    unittest.main()
