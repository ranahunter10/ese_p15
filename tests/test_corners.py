"""Corner cases of the graph, organised as a taxonomy.

`test_graph.py` covers behaviour and `test_adversarial.py` covers the time
laws under attack. This file is the systematic sweep: for each part of the
model, the degenerate, saturated and contradictory inputs it can be handed.
Six of these tests were written after a probe found the code getting them
wrong (CHANGES_v3.5 §C4); the rest pin behaviour that was already right so
it stays that way.

The areas, and what "corner" means in each:

  A  identity      reuse chains, out-of-order generations, non-current parents
  B  files         path reuse, inode reuse, saturated access lists
  C  endpoints     one host both directions, saturation, no-peer
  D  walks         cycles, repetition, truncation, degenerate bounds
  E  eviction      a walk whose nodes are no longer there
  F  presentation  two nodes that would render identically
  G  snapshots     round-trip under every feature, version guard
"""

import json
import time
import unittest

from helpers import SEC
from hids.graph import (ACCEPT, CONNECT, EXEC, FORK, READ, WRITE,
                        MAX_ACCESSES_PER_FILE, MAX_EDGES_PER_RESOURCE,
                        MAX_WRITES_PER_FILE, ProcessGraph)


def add(g, pid, start, ppid, pstart, comm, pcomm="", ts=None):
    return g.process(pid, start, ppid, pstart, comm, pcomm, 1000,
                     ts if ts is not None else start)


# ---------------------------------------------------------------- A. identity
class IdentityCornersTest(unittest.TestCase):

    def test_three_generations_of_one_pid(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        keys = []
        for i, start in enumerate((10 * SEC, 100 * SEC, 200 * SEC)):
            n = add(g, 777, start, 1, 1, "p%d" % i, "systemd")
            g.record_open(n, start + SEC, "/tmp/g%d" % i, "W", 3)
            keys.append(n.key)
            g.record_exit(n, start + 2 * SEC, 0)
        self.assertEqual(keys, [(777, 0), (777, 1), (777, 2)])
        self.assertEqual(g.stats["generations"], 2)
        # each generation kept only its own file
        for i, key in enumerate(keys):
            self.assertEqual([f[1] for f in g.nodes[key].files], ["/tmp/g%d" % i])

    def test_the_same_event_twice_changes_nothing(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        a = add(g, 500, 10 * SEC, 1, 1, "p", "systemd")
        b = add(g, 500, 10 * SEC, 1, 1, "p", "systemd")
        self.assertIs(a, b)
        self.assertEqual(len(g.nodes), 2)
        self.assertEqual(g.stats["generations"], 0)

    def test_an_older_generation_arriving_after_a_newer_one(self):
        """Per-CPU delivery can present lifetimes out of order."""
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        new = add(g, 600, 200 * SEC, 1, 1, "new", "systemd", ts=201 * SEC)
        old = add(g, 600, 10 * SEC, 1, 1, "old", "systemd", ts=202 * SEC)
        self.assertNotEqual(new.key, old.key)
        # the NEWER lifetime stays the one new events attach to
        self.assertEqual(g.current[600], new.key)
        self.assertEqual(g.get(600).comm, "new")

    def test_a_child_naming_a_parent_generation_that_is_not_current(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        p_old = add(g, 500, 10 * SEC, 1, 1, "old", "systemd")
        g.record_exit(p_old, 11 * SEC, 0)
        p_new = add(g, 500, 100 * SEC, 1, 1, "new", "systemd")
        child = add(g, 600, 50 * SEC, 500, 10 * SEC, "child", "old", ts=50 * SEC)
        self.assertEqual(child.parent_key, p_old.key)
        self.assertNotEqual(child.parent_key, p_new.key)
        self.assertEqual(g.lineage_str(child), "systemd(1) → old(500#0) → child(600)")

    def test_a_placeholder_parent_is_upgraded_not_duplicated(self):
        g = ProcessGraph()
        child = add(g, 300, 50 * SEC, 200, 40 * SEC, "child", "parent", ts=55 * SEC)
        placeholder = g.get(200)
        self.assertIsNotNone(placeholder)
        # Its start time is EXACT even though we have never seen a record
        # from it: the child's record carried the kernel's value for the
        # parent's start_time. A placeholder is missing history, not
        # identity — which is why it can later be matched to the real
        # process rather than duplicated.
        self.assertTrue(placeholder.start_exact)
        self.assertEqual(placeholder.start_ns, 40 * SEC)
        self.assertEqual(placeholder.comm, "parent")   # named from pcomm
        real = add(g, 200, 40 * SEC, 1, 1, "bash", "systemd", ts=41 * SEC)
        self.assertIs(real, placeholder)
        self.assertTrue(real.start_exact)
        self.assertEqual(child.parent_key, real.key)
        # Two placeholders, not one: pid 200 from the child's record, and
        # then pid 1 from the parent's own record, because this graph never
        # saw systemd either. Placeholders chain upwards, which is what
        # keeps a lineage from ending in "?(pid)" (the v2 regression the
        # analyzer still checks for).
        self.assertEqual(g.stats["placeholders"], 2)
        # "parent", not "bash": the parent's own record (41 s) is older than
        # everything already seen for that node, and the rename guard keeps
        # a late pre-exec record from renaming it (Journal row 12). Same
        # rule that stops "cat" turning back into "bash".
        self.assertEqual(g.lineage_str(child),
                         "systemd(1) → parent(200) → child(300)")

    def test_kernel_threads_are_hidden_from_the_tree_not_dropped(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        add(g, 2, 1, 0, 0, "kthreadd")
        kworker = add(g, 50, 5 * SEC, 2, 1, "kworker/0:1", "kthreadd")
        self.assertIn(kworker.key, g.nodes)                  # recorded
        self.assertNotIn("kworker", g.render_tree())         # not displayed
        self.assertIn("kworker", g.render_tree(hide_kernel=False))


# ------------------------------------------------------------------- B. files
class FileCornersTest(unittest.TestCase):

    def test_one_inode_many_names_is_one_node(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        p = add(g, 100, SEC, 1, 1, "p", "systemd")
        for i, name in enumerate(["/tmp/a", "/tmp/b", "/tmp/c"]):
            g.record_open(p, (10 + i) * SEC, name, "W", 3, fid="inode:8:77:1")
        self.assertEqual(list(g.files), ["inode:8:77:1"])
        f = g.files["inode:8:77:1"]
        self.assertEqual(f.paths, ["/tmp/a", "/tmp/b", "/tmp/c"])
        self.assertEqual(f.label, "/tmp/c")                  # newest name
        # every name resolves to it
        for name in ["/tmp/a", "/tmp/b", "/tmp/c"]:
            self.assertEqual(g.file(name).fid, "inode:8:77:1")

    def test_one_name_two_inodes_is_two_nodes(self):
        """A file replaced at the same path. Different file, different node."""
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        p = add(g, 100, SEC, 1, 1, "p", "systemd")
        g.record_open(p, 10 * SEC, "/tmp/same", "W", 3, fid="inode:8:11:1")
        g.record_open(p, 20 * SEC, "/tmp/same", "W", 3, fid="inode:8:22:1")
        self.assertEqual(sorted(g.files), ["inode:8:11:1", "inode:8:22:1"])
        self.assertEqual(g.file("/tmp/same").fid, "inode:8:22:1")   # the latest

    def test_inode_reuse_with_a_new_generation_is_a_new_node(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        p = add(g, 100, SEC, 1, 1, "p", "systemd")
        g.record_open(p, 10 * SEC, "/tmp/x", "W", 3, fid="inode:8:77:1")
        g.record_open(p, 20 * SEC, "/tmp/y", "W", 3, fid="inode:8:77:2")
        self.assertEqual(len(g.files), 2)

    def test_a_failed_open_creates_nothing(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        p = add(g, 100, SEC, 1, 1, "p", "systemd")
        g.record_open(p, 10 * SEC, "/etc/shadow", "R", -13)
        self.assertEqual(g.files, {})
        self.assertEqual(p.failed_opens, 1)
        self.assertEqual(p.file_count, 0)

    def test_a_relative_path_with_no_inode_creates_nothing(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        p = add(g, 100, SEC, 1, 1, "p", "systemd")
        g.record_open(p, 10 * SEC, "lib", "R", 3)
        self.assertEqual(g.files, {})
        self.assertEqual(p.unresolved_opens, 1)

    def test_a_process_reading_what_it_wrote_itself(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        p = add(g, 100, SEC, 1, 1, "p", "systemd")
        g.record_open(p, 10 * SEC, "/tmp/self", "W", 3)
        g.record_open(p, 20 * SEC, "/tmp/self", "R", 4)
        found = [(k, d) for _, k, _, d in g.trace_back(p)]
        self.assertIn((READ, "/tmp/self"), found)
        self.assertIn((WRITE, "p(100)"), found)      # itself, and that is the truth

    def test_a_write_survives_a_flood_of_reads(self):
        """The bug this replaces made the walk find NO writer at all.

        Writes and reads shared one capped access list, so 2 000 reads
        evicted the single write and a root-cause walk then reported
        nothing — a silent, confident "nobody put these bytes here".
        Writes now live in their own list (CHANGES_v3.5 row 117).
        """
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        w = add(g, 101, SEC, 1, 1, "writer", "systemd")
        r = add(g, 102, 2 * SEC, 1, 1, "reader", "systemd")
        g.record_open(w, 10 * SEC, "/tmp/hot", "W", 3)
        for i in range(MAX_ACCESSES_PER_FILE + 50):
            g.record_open(r, (11 + i) * SEC, "/tmp/hot", "R", 4)
        f = g.file("path:/tmp/hot")
        self.assertEqual(len(f.accesses), MAX_ACCESSES_PER_FILE)   # log trimmed
        self.assertEqual(f.writes, [(10 * SEC, w.key)])            # cause kept
        self.assertNotIn(WRITE, [k for _, _, k in f.accesses])     # gone from the log
        found = [(k, d) for _, k, _, d in g.trace_back(r)]
        self.assertIn((WRITE, "writer(101)"), found)

    def test_the_write_list_is_itself_capped(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        w = add(g, 101, SEC, 1, 1, "writer", "systemd")
        for i in range(MAX_WRITES_PER_FILE + 20):
            g.record_open(w, (10 + i) * SEC, "/tmp/many", "W", 3)
        f = g.file("path:/tmp/many")
        self.assertEqual(len(f.writes), MAX_WRITES_PER_FILE)
        # the NEWEST writes are the ones kept, which is what last-write-wins needs
        self.assertEqual(f.writes[-1][0], (10 + MAX_WRITES_PER_FILE + 19) * SEC)


# --------------------------------------------------------------- C. endpoints
class EndpointCornersTest(unittest.TestCase):

    def test_failed_connects_only_leaves_a_node_with_no_causal_edge(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        p = add(g, 100, SEC, 1, 1, "nmap", "systemd")
        for port in (22, 23, 445):
            g.record_connect(p, 10 * SEC, "net:10.0.0.9:%d" % port, False)
        self.assertEqual(len(g.endpoints), 3)
        self.assertEqual(p.failed_conns, 3)
        self.assertNotIn(CONNECT, [k for _, k, _, _ in g.trace_forward(p)])

    def test_an_endpoint_saturated_with_contacts(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        p = add(g, 100, SEC, 1, 1, "p", "systemd")
        for i in range(2500):
            g.record_connect(p, (10 + i) * SEC, "net:10.0.0.9:443", True)
        e = g.endpoints["net:10.0.0.9:443"]
        self.assertEqual(e.access_count, 2500)          # counted in full
        self.assertLessEqual(len(e.accesses), 2000)     # log bounded
        # and the walk still answers, rather than drowning in repetitions
        found = [(k, d) for _, k, _, d in g.trace_forward(p)]
        self.assertIn((CONNECT, "net:10.0.0.9:443"), found)
        self.assertLessEqual(len(found), 20)

    def test_unix_abstract_and_filesystem_sockets_are_different_nodes(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        p = add(g, 100, SEC, 1, 1, "p", "systemd")
        g.record_connect(p, 10 * SEC, "unix:/run/p15.sock", True)
        g.record_connect(p, 11 * SEC, "unix:@p15abstract", True)
        self.assertEqual(len(g.endpoints), 2)


# ------------------------------------------------------------------- D. walks
class WalkCornersTest(unittest.TestCase):

    def test_a_cycle_through_two_files_terminates(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        a = add(g, 101, SEC, 1, 1, "A", "systemd")
        b = add(g, 102, 2 * SEC, 1, 1, "B", "systemd")
        for i in range(40):
            g.record_open(a, (10 + 4 * i) * SEC, "/tmp/F", "W", 3)
            g.record_open(b, (11 + 4 * i) * SEC, "/tmp/F", "R", 3)
            g.record_open(b, (12 + 4 * i) * SEC, "/tmp/G", "W", 4)
            g.record_open(a, (13 + 4 * i) * SEC, "/tmp/G", "R", 4)
        t0 = time.perf_counter()
        out = g.trace_back(a)
        self.assertLess(time.perf_counter() - t0, 1.0)
        self.assertLessEqual(len(out), 200)

    def test_one_relationship_repeated_cannot_crowd_out_the_rest(self):
        """The bug: 2 000 reads of one file filled max_items at depth 1.

        Every edge was formally correct and the walk never descended to the
        writer. Capped per resource now (CHANGES_v3.5 row 118).
        """
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        w = add(g, 101, SEC, 1, 1, "writer", "systemd")
        r = add(g, 102, 2 * SEC, 1, 1, "reader", "systemd")
        g.record_open(w, 10 * SEC, "/tmp/hot", "W", 3)
        for i in range(2050):
            g.record_open(r, (11 + i) * SEC, "/tmp/hot", "R", 4)
        out = g.trace_back(r)
        reads = [e for e in out if e[1] == READ]
        self.assertLessEqual(len(reads), MAX_EDGES_PER_RESOURCE)
        self.assertIn(WRITE, [k for _, k, _, _ in out])
        self.assertLess(len(out), 20)

    def test_at_ns_before_the_process_existed_answers_nothing(self):
        """And in particular does not report a fork that had not happened.

        The FORK edge used to be listed unconditionally with its timestamp
        clamped to the bound, so this returned a parent dated 0 for a
        process forked at 10 s (CHANGES_v3.5 row 119).
        """
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        p = add(g, 100, 10 * SEC, 1, 1, "p", "systemd")
        g.record_open(p, 20 * SEC, "/tmp/x", "R", 3)
        self.assertEqual(g.trace_back(p, at_ns=0), [])
        self.assertEqual(g.trace_back(p, at_ns=5 * SEC), [])
        self.assertIn(FORK, [k for _, k, _, _ in g.trace_back(p, at_ns=15 * SEC)])

    def test_at_ns_far_in_the_future_matches_the_default(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        p = add(g, 100, 10 * SEC, 1, 1, "p", "systemd")
        g.record_open(p, 20 * SEC, "/tmp/x", "R", 3)
        self.assertEqual([(k, d) for _, k, _, d in g.trace_back(p, at_ns=10 ** 15)],
                         [(k, d) for _, k, _, d in g.trace_back(p)])

    def test_max_depth_zero_and_one(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        a = add(g, 100, 10 * SEC, 1, 1, "a", "systemd")
        b = add(g, 101, 20 * SEC, 100, 10 * SEC, "b", "a")
        self.assertEqual(g.trace_back(b, max_depth=0), [])
        one = g.trace_back(b, max_depth=1)
        self.assertEqual([d for d, _, _, _ in one], [1])

    def test_max_items_truncates_without_crashing(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        parent = add(g, 100, 10 * SEC, 1, 1, "p", "systemd")
        for i in range(50):
            add(g, 200 + i, (20 + i) * SEC, 100, 10 * SEC, "c%d" % i, "p")
        out = g.trace_forward(parent, max_items=7)
        self.assertEqual(len(out), 7)

    def test_skip_filtering_everything_leaves_the_process_chain(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        p = add(g, 100, 10 * SEC, 1, 1, "p", "systemd")
        g.record_open(p, 11 * SEC, "/usr/lib/x86_64-linux-gnu/libc.so.6", "R", 3)
        found = g.trace_back(p, skip=lambda n: True)
        self.assertEqual([k for _, k, _, _ in found], [FORK])

    def test_walks_from_every_node_type_and_an_empty_graph(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        p = add(g, 100, 10 * SEC, 1, 1, "p", "systemd")
        g.record_open(p, 11 * SEC, "/tmp/f", "W", 3)
        g.record_connect(p, 12 * SEC, "net:10.0.0.1:443", True)
        for node in (p, g.file("path:/tmp/f"), g.endpoints["net:10.0.0.1:443"]):
            self.assertIsInstance(g.trace_back(node), list)
            self.assertIsInstance(g.trace_forward(node), list)
        lonely = ProcessGraph()
        solo = add(lonely, 1, 1, 0, 0, "systemd")
        self.assertEqual(lonely.trace_back(solo), [])
        self.assertEqual(lonely.trace_forward(solo), [])

    def test_an_exited_process_still_answers_both_directions(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        p = add(g, 100, 10 * SEC, 1, 1, "p", "systemd")
        g.record_open(p, 11 * SEC, "/tmp/left-behind", "W", 3)
        g.record_exit(p, 12 * SEC, 0)
        reader = add(g, 200, 20 * SEC, 1, 1, "r", "systemd")
        g.record_open(reader, 21 * SEC, "/tmp/left-behind", "R", 3)
        self.assertIn((WRITE, "p(100)"),
                      [(k, d) for _, k, _, d in g.trace_back(reader)])
        self.assertIn((READ, "r(200)"),
                      [(k, d) for _, k, _, d in g.trace_forward(p)])


# ---------------------------------------------------------------- E. eviction
class EvictionCornersTest(unittest.TestCase):

    def test_an_evicted_file_shortens_a_walk_without_crashing(self):
        g = ProcessGraph(max_files=2)
        add(g, 1, 1, 0, 0, "systemd")
        p = add(g, 100, SEC, 1, 1, "p", "systemd")
        for i in range(5):
            g.record_open(p, (10 + i) * SEC, "/tmp/f%d" % i, "W", 3,
                          fid="inode:8:%d:1" % i)
        self.assertEqual(len(g.files), 2)
        self.assertEqual(g.stats["evicted_files"], 3)
        self.assertEqual(len(p.files), 5)            # the process still remembers
        out = [(k, d) for _, k, _, d in g.trace_forward(p)]
        self.assertEqual(out, [(WRITE, "/tmp/f3"), (WRITE, "/tmp/f4")])

    def test_eviction_never_removes_a_live_process(self):
        g = ProcessGraph(max_nodes=2)
        add(g, 1, 1, 0, 0, "systemd")
        alive = add(g, 100, SEC, 1, 1, "alive", "systemd")
        for i in range(10):
            n = add(g, 200 + i, (10 + i) * SEC, 1, 1, "dead%d" % i, "systemd")
            g.record_exit(n, (11 + i) * SEC, 0)
        self.assertIn(alive.key, g.nodes)
        self.assertGreater(g.stats["evicted"], 0)

    def test_an_orphan_is_marked_not_drawn_as_a_root(self):
        """An evicted parent used to leave the child beside systemd, which
        reads as "started by nobody" (CHANGES_v3.5 row 120)."""
        g = ProcessGraph(max_nodes=2)
        add(g, 1, 1, 0, 0, "systemd")
        parent = add(g, 200, SEC, 1, 1, "parent", "systemd")
        g.record_exit(parent, 2 * SEC, 0)
        add(g, 201, 3 * SEC, 200, SEC, "child", "parent")
        for i in range(5):
            n = add(g, 300 + i, (10 + i) * SEC, 1, 1, "filler", "systemd")
            g.record_exit(n, (11 + i) * SEC, 0)
        tree = g.render_tree()
        self.assertNotIn(parent.key, g.nodes)
        self.assertIn("child(201) [parent 200 evicted]", tree)


# ------------------------------------------------------------ F. presentation
class PresentationCornersTest(unittest.TestCase):

    def test_two_generations_of_one_pid_do_not_render_identically(self):
        """Otherwise a walk cannot say WHICH process wrote the file, which
        defeats the point of having generations (CHANGES_v3.5 row 121)."""
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        old = add(g, 777, 10 * SEC, 1, 1, "nc", "systemd")
        g.record_open(old, 11 * SEC, "/tmp/x", "W", 3)
        g.record_exit(old, 12 * SEC, 0)
        new = add(g, 777, 20 * SEC, 1, 1, "nc", "systemd")
        g.record_open(new, 21 * SEC, "/tmp/x", "W", 3)
        reader = add(g, 800, 30 * SEC, 1, 1, "cat", "systemd")
        g.record_open(reader, 31 * SEC, "/tmp/x", "R", 3)
        self.assertEqual(old.label(), new.label())            # the node cannot tell
        descs = [d for _, _, _, d in g.trace_back(reader)]
        self.assertIn("nc(777#1)", descs)                     # the graph can
        self.assertNotIn("nc(777)", descs)

    def test_a_single_generation_still_renders_plainly(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        p = add(g, 100, 10 * SEC, 1, 1, "bash", "systemd")
        child = add(g, 101, 11 * SEC, 100, 10 * SEC, "cat", "bash")
        self.assertIn("bash(100)", [d for _, _, _, d in g.trace_back(child)])

    def test_a_superseded_file_at_the_same_path_is_distinguishable(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        w = add(g, 101, SEC, 1, 1, "w", "systemd")
        g.record_open(w, 10 * SEC, "/tmp/same", "W", 3, fid="inode:8:11:1")
        g.record_open(w, 20 * SEC, "/tmp/same", "W", 3, fid="inode:8:22:1")
        old_file = g.files["inode:8:11:1"]
        self.assertEqual(old_file.label, "/tmp/same")         # the node cannot tell
        # dev:ino:gen, not the inode number alone. The bare inode was
        # ambiguous in exactly the case the discriminator exists for — see
        # the companion test below (v3.5i report W1-F3).
        self.assertEqual(g._desc(old_file), "/tmp/same#8:11:1")
        self.assertEqual(g._desc(g.files["inode:8:22:1"]), "/tmp/same")

    def test_two_files_sharing_an_inode_number_across_devices_are_distinguishable(self):
        """The case the old discriminator could not tell apart.

        Low inode numbers recur on every filesystem, so one path holding two
        different files with the SAME inode number on DIFFERENT devices is
        realistic (bind mounts, remounts). Taking `fid.split(":")[2]` rendered
        both as `/tmp/x#5`, and the fuzzer in the v3.5i review produced
        byte-identical walk edges for genuinely different files.
        """
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        w = add(g, 101, SEC, 1, 1, "w", "systemd")
        g.record_open(w, 10 * SEC, "/tmp/x", "W", 3, fid="inode:1:5:0")
        g.record_open(w, 20 * SEC, "/tmp/x", "W", 3, fid="inode:2:5:1")
        a = g._desc(g.files["inode:1:5:0"])
        b = g._desc(g.files["inode:2:5:1"])
        self.assertNotEqual(a, b)
        self.assertEqual(a, "/tmp/x#1:5:0")

    def test_a_short_fid_does_not_crash_every_walk(self):
        """A snapshot can carry a fid the kernel would never produce.

        `fid.split(":")[2]` raised IndexError on anything with fewer than
        three parts, and _desc runs inside trace_back, trace_forward and
        lineage_str — so one poisoned record killed the whole query path
        (v3.5i report W1-F2). from_dict is a supported workflow used by
        query_graph.py and walk_trace.py.
        """
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        w = add(g, 101, SEC, 1, 1, "w", "systemd")
        g.record_open(w, 10 * SEC, "/tmp/x", "W", 3, fid="inode:9")
        g.record_open(w, 20 * SEC, "/tmp/x", "W", 3, fid="inode:8:22:1")
        reader = add(g, 800, 30 * SEC, 1, 1, "cat", "systemd")
        g.record_open(reader, 31 * SEC, "/tmp/x", "R", 3, fid="inode:8:22:1")
        self.assertEqual(g._desc(g.files["inode:9"]), "/tmp/x#inode:9")
        g.trace_back(reader)            # must not raise
        g.trace_forward(w)
        g.lineage_str(reader)

    def test_a_parent_cycle_never_hides_the_tree(self):
        """Bad data must not empty the live view (CHANGES_v3.5 row 122)."""
        g = ProcessGraph()
        a = add(g, 10, SEC, 0, 0, "a")
        b = add(g, 11, 2 * SEC, 10, SEC, "b", "a")
        a.parent_key = b.key                                  # force a cycle
        tree = g.render_tree()
        self.assertIn("a(10)", tree)
        self.assertIn("b(11)", tree)
        self.assertIn("unreachable", tree)
        self.assertEqual(g.lineage_str(a), "b(11) → a(10)")   # still terminates


# ------------------------------------------------------------------- H. noise
class NoiseFilterTest(unittest.TestCase):
    """`--no-libs` must hide the boring and keep the dangerous."""

    def build(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        p = add(g, 100, SEC, 1, 1, "python3", "systemd")
        # the four classes the 16-Oct VM run showed leaking through
        for i, path in enumerate([
                "/usr/share/zoneinfo/America/New_York",
                "/usr/local/lib/python3.8/dist-packages",
                "/usr/local/lib/python3.8/dist-packages/easy-install.pth",
                "/usr/lib/x86_64-linux-gnu/libc.so.6"]):
            g.record_open(p, (10 + i) * SEC, path, "R", 3, fid="inode:8:%d:1" % i)
        return g, p

    def test_startup_noise_is_skipped(self):
        from hids.graph import noisy
        g, p = self.build()
        kept = [d for _, _, _, d in g.trace_back(p, skip=noisy)]
        self.assertEqual([k for k in kept if k.startswith("/")], [])
        unfiltered = [d for _, _, _, d in g.trace_back(p)]
        self.assertEqual(len([d for d in unfiltered if d.startswith("/")]), 4)

    def test_a_common_file_that_someone_WROTE_is_never_noise(self):
        """The rule is "a common path nobody wrote", not "a common path".

        Appending an `import` line to a .pth file under dist-packages is a
        Python persistence technique, and hijacking a shared library is the
        classic one. Both live on paths the filter would otherwise hide, so
        filtering by path alone would conceal the single event worth
        seeing.
        """
        from hids.graph import noisy
        g, reader = self.build()
        attacker = add(g, 200, 2 * SEC, 1, 1, "evil", "systemd")
        g.record_open(attacker, 5 * SEC,
                      "/usr/local/lib/python3.8/dist-packages/easy-install.pth",
                      "W", 3, fid="inode:8:2:1")
        kept = [d for _, _, _, d in g.trace_back(reader, skip=noisy)]
        self.assertIn("/usr/local/lib/python3.8/dist-packages/easy-install.pth", kept)
        # ...and the walk reaches the process that wrote it
        self.assertIn("evil(200)", kept)
        # the files nobody wrote are still hidden
        self.assertNotIn("/usr/lib/x86_64-linux-gnu/libc.so.6", kept)


# --------------------------------------------------------------- G. snapshots
class SnapshotCornersTest(unittest.TestCase):

    def full_graph(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        curl = add(g, 100, 10 * SEC, 1, 1, "curl", "systemd")
        g.record_connect(curl, 11 * SEC, "net:203.0.113.5:443", True)
        g.record_connect(curl, 12 * SEC, "net:10.0.0.9:22", False)
        g.record_open(curl, 13 * SEC, "/tmp/payload", "W", 3, fid="inode:8:5:1")
        g.record_exit(curl, 14 * SEC, 0)
        sshd = add(g, 900, 20 * SEC, 1, 1, "sshd", "systemd")
        g.record_accept(sshd, 21 * SEC, "host:10.0.0.9")
        g.record_accept(sshd, 22 * SEC, None, has_peer=False)
        sh = add(g, 901, 23 * SEC, 900, 20 * SEC, "bash", "sshd")
        g.record_exec(sh, 24 * SEC, "/bin/sh", ["sh", "/tmp/payload"], False, "sh",
                      fid="inode:8:9:1")
        g.record_open(sh, 25 * SEC, "/tmp/payload", "R", 4, fid="inode:8:5:1")
        return g, sh

    def test_round_trip_preserves_every_feature(self):
        g, sh = self.full_graph()
        h = ProcessGraph.from_dict(json.loads(json.dumps(g.to_dict())))
        self.assertEqual(h.render_tree(), g.render_tree())
        self.assertEqual(h.summary(), g.summary())
        self.assertEqual([(k, d) for _, k, _, d in h.trace_back(h.get(901))],
                         [(k, d) for _, k, _, d in g.trace_back(sh)])
        self.assertEqual(h.files["inode:8:5:1"].writes,
                         g.files["inode:8:5:1"].writes)

    def test_a_snapshot_without_the_write_list_rebuilds_it(self):
        """Pre-v3.5d snapshots have no causal list; it comes back from the log."""
        g, sh = self.full_graph()
        d = g.to_dict()
        for f in d["files"]:
            f.pop("writes", None)
        h = ProcessGraph.from_dict(json.loads(json.dumps(d)))
        self.assertEqual(h.files["inode:8:5:1"].writes,
                         g.files["inode:8:5:1"].writes)
        self.assertIn((WRITE, "curl(100)"),
                      [(k, d2) for _, k, _, d2 in h.trace_back(h.get(901))])

    def test_a_snapshot_of_an_evicted_graph_loads(self):
        g = ProcessGraph(max_files=2, max_endpoints=2, max_nodes=2)
        add(g, 1, 1, 0, 0, "systemd")
        p = add(g, 100, SEC, 1, 1, "p", "systemd")
        for i in range(6):
            g.record_open(p, (10 + i) * SEC, "/tmp/f%d" % i, "W", 3,
                          fid="inode:8:%d:1" % i)
            g.record_connect(p, (10 + i) * SEC, "net:10.0.0.%d:443" % i, True)
        h = ProcessGraph.from_dict(json.loads(json.dumps(g.to_dict())))
        self.assertEqual(len(h.files), 2)
        self.assertEqual(len(h.endpoints), 2)
        self.assertIsInstance(h.trace_forward(h.get(100)), list)

    def test_an_unsupported_version_is_refused(self):
        g, _ = self.full_graph()
        d = g.to_dict()
        d["version"] = 99
        with self.assertRaises(ValueError):
            ProcessGraph.from_dict(d)
        del d["version"]
        with self.assertRaises(ValueError):
            ProcessGraph.from_dict(d)


if __name__ == "__main__":
    unittest.main()
