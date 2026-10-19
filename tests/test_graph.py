"""ProcessGraph behaviour, including every PID-reuse case found so far."""

import json
import unittest

from helpers import SEC
from hids.graph import ACCEPT, CONNECT, EXEC, FORK, READ, WRITE, ProcessGraph


def add(g, pid, start, ppid, pstart, comm, pcomm="", ts=None):
    return g.process(pid, start, ppid, pstart, comm, pcomm, 1000,
                     ts if ts is not None else start)


def small_tree():
    """systemd(1) -> bash(1360) -> {cat(1390), ls(1391)}"""
    g = ProcessGraph()
    add(g, 1, 1 * SEC, 0, 0, "systemd")
    add(g, 1360, 10 * SEC, 1, 1 * SEC, "bash", "systemd")
    cat = add(g, 1390, 20 * SEC, 1360, 10 * SEC, "cat", "bash")
    ls = add(g, 1391, 21 * SEC, 1360, 10 * SEC, "ls", "bash")
    return g, cat, ls


class TreeTest(unittest.TestCase):
    def test_parent_and_children(self):
        g, cat, ls = small_tree()
        bash = g.get(1360)
        self.assertEqual(bash.children, [cat.key, ls.key])
        self.assertEqual(g.get(1).children, [bash.key])
        self.assertEqual(g.lineage_str(cat), "systemd(1) → bash(1360) → cat(1390)")

    def test_no_phantom_pid0(self):
        # legacy on_exec(pid=1, ppid=0) created a node for pid 0 (audit)
        g, _, _ = small_tree()
        self.assertNotIn(0, g.gens)
        self.assertEqual([n.pid for n in g.roots()], [1])

    def test_same_event_twice_is_idempotent(self):
        g, cat, _ = small_tree()
        again = add(g, 1390, 20 * SEC, 1360, 10 * SEC, "cat", "bash", ts=22 * SEC)
        self.assertIs(again, cat)
        self.assertEqual(g.get(1360).children.count(cat.key), 1)

    def test_render_tree(self):
        g, _, _ = small_tree()
        self.assertEqual(g.render_tree(),
                         "systemd(1)\n  bash(1360)\n    cat(1390)\n    ls(1391)")


class ExitSurvivalTest(unittest.TestCase):
    """Advisor: 'process died but created a file' must survive."""

    def test_exit_keeps_node_and_files(self):
        g, cat, _ = small_tree()
        g.record_open(cat, 20 * SEC + 5, "/tmp/out", "W", 3)
        g.record_exit(cat, 25 * SEC, 0)
        self.assertFalse(cat.alive)
        self.assertIn(cat.key, g.nodes)
        self.assertEqual(cat.files[0][1], "/tmp/out")
        self.assertIn("cat(1390) [exited]  (1 files)", g.render_tree())


class PidReuseTest(unittest.TestCase):
    def reuse(self):
        g, cat, _ = small_tree()
        g.record_open(cat, 20 * SEC + 5, "/etc/hostname", "R", 3)
        g.record_exit(cat, 25 * SEC, 0)
        add(g, 9999, 30 * SEC, 1, 1 * SEC, "sshd", "systemd")
        evil = add(g, 1390, 40 * SEC, 9999, 30 * SEC, "malicious_proc", "sshd")
        return g, cat, evil

    def test_reuse_creates_new_generation(self):
        # Journal row 21
        g, cat, evil = self.reuse()
        self.assertIsNot(evil, cat)
        self.assertEqual(evil.key, (1390, 1))
        self.assertTrue(evil.alive)
        self.assertFalse(cat.alive)
        self.assertEqual(cat.comm, "cat")
        self.assertEqual(g.get(1390), evil)
        self.assertEqual(g.get(1390, 0), cat)

    def test_reuse_does_not_inherit_files(self):
        # Journal row 22 — was a documented open issue in v2
        _, cat, evil = self.reuse()
        self.assertEqual(evil.files, [])
        self.assertEqual(len(cat.files), 1)

    def test_old_parent_not_pointing_at_new_process(self):
        # Audit bug C: malicious_proc used to render under bash.
        # The "#1" is the generation, shown because PID 1390 has more than
        # one lifetime in this graph: without it the lineage reads exactly
        # like the lineage of the OTHER process that held 1390, which
        # defeats the point of having generations at all (row 121).
        g, cat, evil = self.reuse()
        self.assertEqual(g.get(1360).children, [cat.key, (1391, 0)])
        self.assertEqual(g.lineage_str(evil),
                         "systemd(1) → sshd(9999) → malicious_proc(1390#1)")
        self.assertNotIn("malicious_proc", g.render_tree(g.get(1360)))

    def test_reused_parent_name_is_correct(self):
        # Audit probe B: v2 printed 'cat(1390)' as the parent of a child of
        # the NEW occupant of PID 1390.
        g, cat, evil = self.reuse()
        child = add(g, 4000, 41 * SEC, 1390, 40 * SEC, "payload", "malicious_proc")
        self.assertEqual(g.lineage_str(child),
                         "systemd(1) → sshd(9999) → malicious_proc(1390#1) → payload(4000)")

    def test_late_event_from_old_lifetime(self):
        # Per-CPU reordering: an OPEN from the dead cat is read AFTER the
        # new process appeared. It must land on cat, not on the new node.
        g, cat, evil = self.reuse()
        late = add(g, 1390, 20 * SEC, 1360, 10 * SEC, "cat", "bash", ts=24 * SEC)
        self.assertIs(late, cat)
        self.assertIs(g.get(1390), evil)
        self.assertFalse(cat.alive)

    def test_lost_exit_is_inferred(self):
        g, cat, _ = small_tree()        # cat never gets an exit event
        new = add(g, 1390, 50 * SEC, 1, 1 * SEC, "nginx", "systemd")
        self.assertFalse(cat.alive)
        self.assertTrue(cat.exit_inferred)
        self.assertEqual(g.stats["inferred_exits"], 1)
        self.assertIn("[exited?]", g.render_tree())
        self.assertTrue(new.alive)

    def test_older_unknown_lifetime_does_not_become_current(self):
        g, cat, _ = small_tree()
        ghost = add(g, 1390, 5 * SEC, 1, 1 * SEC, "ghost", "systemd", ts=6 * SEC)
        self.assertIsNot(ghost, cat)
        self.assertIs(g.get(1390), cat)
        self.assertTrue(cat.alive)


class RobustnessTest(unittest.TestCase):
    def test_cycle_does_not_hang(self):
        # Audit bug D: force a parent cycle and make sure every walk ends.
        g, cat, ls = small_tree()
        bash = g.get(1360)
        bash.parent_key = cat.key
        cat.children.append(bash.key)
        self.assertEqual(len(g.lineage(cat)), 2)
        g.render_tree(bash)             # must return
        g.trace_back(cat)
        g.trace_forward(bash)

    def test_deep_chain_no_recursion_error(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "init")
        prev_pid, prev_start = 1, 1
        for i in range(3, 5001):      # skip pid 2: that's kthreadd, hidden by design
            add(g, i, i, prev_pid, prev_start, "p%d" % i)
            prev_pid, prev_start = i, i
        self.assertEqual(len(g.render_tree().splitlines()), 4999)
        self.assertEqual(len(g.lineage(g.get(5000))), 4999)

    def test_reparent_to_subreaper(self):
        g, cat, _ = small_tree()
        g.record_exit(g.get(1360), 22 * SEC, 0)
        # bash died; the kernel now reports systemd as cat's parent
        add(g, 1390, 20 * SEC, 1, 1 * SEC, "cat", "systemd", ts=23 * SEC)
        self.assertEqual(cat.parent_key, (1, 0))
        self.assertEqual(cat.reparented_from, (1360, 0))
        self.assertIn(cat.key, g.get(1).children)
        self.assertNotIn(cat.key, g.get(1360, 0).children)

    def test_unknown_parent_gets_placeholder(self):
        g = ProcessGraph()
        child = add(g, 500, 9 * SEC, 400, 8 * SEC, "child", "gone")
        parent = g.get(400)
        self.assertEqual(parent.comm, "gone")
        self.assertEqual(child.parent_key, parent.key)
        self.assertEqual(g.stats["placeholders"], 1)

    def test_late_pre_exec_event_does_not_rename(self):
        g, cat, _ = small_tree()
        g.record_exec(cat, 20 * SEC + 2, "/usr/bin/cat", ["cat"], False, "cat")
        add(g, 1390, 20 * SEC, 1360, 10 * SEC, "bash", "bash", ts=20 * SEC + 1)
        self.assertEqual(cat.comm, "cat")

    def test_eviction_only_removes_exited(self):
        g = ProcessGraph(max_nodes=50)
        add(g, 1, 1, 0, 0, "init")
        for i in range(2, 200):
            n = add(g, i, i, 1, 1, "p%d" % i)
            if i < 170:
                g.record_exit(n, i + 1, 0)
        self.assertLessEqual(len(g.nodes), 50)
        alive = [n.pid for n in g.nodes.values() if n.alive]
        self.assertEqual(alive, [1] + list(range(170, 200)))   # no live node evicted
        self.assertTrue(g.get(1).alive)
        self.assertGreater(g.stats["evicted"], 0)
        # queries still work with dangling references
        g.render_tree()
        for n in list(g.nodes.values()):
            g.lineage(n)


class BootstrapTest(unittest.TestCase):
    def snapshot(self):
        return [
            {"pid": 1, "ppid": 0, "comm": "systemd", "uid": 0, "start_ns": 100},
            {"pid": 800, "ppid": 1, "comm": "sshd", "uid": 0, "start_ns": 5 * SEC},
            {"pid": 900, "ppid": 800, "comm": "bash", "uid": 1000, "start_ns": 6 * SEC},
        ]

    def test_bootstrap_builds_tree(self):
        g = ProcessGraph()
        g.bootstrap(self.snapshot(), 100 * SEC)
        self.assertEqual(g.lineage_str(g.get(900)), "systemd(1) → sshd(800) → bash(900)")
        self.assertFalse(g.get(900).start_exact)

    def test_first_event_adopts_exact_start(self):
        g = ProcessGraph()
        g.bootstrap(self.snapshot(), 100 * SEC)
        exact = 6 * SEC + 1234567          # kernel's exact value differs slightly
        node = add(g, 900, exact, 800, 5 * SEC + 7, "bash", "sshd", ts=101 * SEC)
        self.assertEqual(node.key, (900, 0))
        self.assertTrue(node.start_exact)
        self.assertEqual(node.start_ns, exact)
        self.assertEqual(g.get(800).start_ns, 5 * SEC + 7)   # parent upgraded too
        child = add(g, 950, 102 * SEC, 900, exact, "vim", "bash")
        self.assertEqual(g.lineage_str(child),
                         "systemd(1) → sshd(800) → bash(900) → vim(950)")


class ProvenanceTest(unittest.TestCase):
    """The write-then-read causal chain described in the Phase I report."""

    def build(self):
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        curl = add(g, 100, 10 * SEC, 1, 1, "curl", "systemd")
        g.record_open(curl, 11 * SEC, "/tmp/payload.sh", "W", 3)
        g.record_exit(curl, 12 * SEC, 0)
        bash = add(g, 200, 20 * SEC, 1, 1, "bash", "systemd")
        g.record_open(bash, 21 * SEC, "/tmp/payload.sh", "R", 3)
        g.record_open(bash, 22 * SEC, "/home/u/.bashrc", "W", 4)
        victim = add(g, 300, 30 * SEC, 1, 1, "bash", "systemd")
        g.record_open(victim, 31 * SEC, "/home/u/.bashrc", "R", 3)
        # a reader BEFORE the write must not be linked to the writer
        early = add(g, 50, 5 * SEC, 1, 1, "early", "systemd")
        g.record_open(early, 6 * SEC, "/tmp/payload.sh", "R", 3)
        return g, curl, bash, victim, early

    def test_trace_back_finds_root_cause_across_processes(self):
        g, curl, bash, victim, _ = self.build()
        found = [(k, d) for _, k, _, d in g.trace_back(victim)]
        self.assertIn((READ, "/home/u/.bashrc"), found)
        self.assertIn((WRITE, "bash(200)"), found)
        self.assertIn((READ, "/tmp/payload.sh"), found)
        self.assertIn((WRITE, "curl(100)"), found)     # never met victim directly
        self.assertIn((FORK, "systemd(1)"), found)

    def test_trace_back_lists_write_when_writer_was_already_visited(self):
        # Regression for the 13-Oct VM run: a parent shell writes a file
        # (relative path, inode identity) and its child reads it back. The
        # walk visits the writer via FORK first; the WRITE edge must still
        # be listed — FORK and WRITE are different causal facts, and only
        # the deeper expansion is deduped. Before the fix the walk dropped
        # the write and the validation check
        # "relative path linked through inode (write -> read)" failed.
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        sh = add(g, 100, 10 * SEC, 1, 1, "bash", "systemd")
        fid = "inode:8:77:1"
        g.record_open(sh, 11 * SEC, "p15_rel.txt", "W", 3, fid=fid)
        cat = add(g, 101, 12 * SEC, 100, 10 * SEC, "bash", "bash")
        g.record_exec(cat, 13 * SEC, "/usr/bin/cat", ["cat", "./p15_rel.txt"],
                      False, "cat", old_comm="bash", fid="inode:8:99:1")
        g.record_open(cat, 14 * SEC, "./p15_rel.txt", "R", 4, fid=fid)
        found = [(k, d) for _, k, _, d in g.trace_back(cat)]
        self.assertIn((FORK, "bash(100)"), found)
        self.assertIn((WRITE, "bash(100)"), found)   # the write, not just the fork
        # exactly one WRITE edge: listed once, never duplicated, walk terminates
        self.assertEqual([(k, d) for _, k, _, d in g.trace_back(cat)
                          if k == WRITE], [(WRITE, "bash(100)")])

    def test_time_order_is_respected(self):
        g, curl, bash, victim, early = self.build()
        self.assertNotIn("curl(100)", [d for _, _, _, d in g.trace_back(early)])
        impact = [d for _, _, _, d in g.trace_forward(curl)]
        self.assertIn("bash(200)", impact)
        self.assertIn("bash(300)", impact)
        self.assertNotIn("early(50)", impact)

    def test_failed_open_creates_no_edge(self):
        g, curl, *_ = self.build()
        g.record_open(curl, 11 * SEC + 1, "/etc/shadow", "R", -13)
        self.assertNotIn("/etc/shadow", g.files)
        self.assertEqual(curl.failed_opens, 1)

    def test_exec_edge(self):
        g, curl, *_ = self.build()
        g.record_exec(curl, 10 * SEC + 1, "/usr/bin/curl", ["curl", "-o", "x"], False, "curl")
        self.assertIn((EXEC, "/usr/bin/curl"),
                      [(k, d) for _, k, _, d in g.trace_back(curl)])


class SnapshotTest(unittest.TestCase):
    def test_round_trip(self):
        g, curl, bash, victim, _ = ProvenanceTest().build()
        add(g, 100, 40 * SEC, 1, 1, "reused", "systemd")
        g.record_exec(victim, 30 * SEC + 1, "/bin/bash", ["bash", "-i"], True, "bash")
        d = json.loads(json.dumps(g.to_dict()))
        h = ProcessGraph.from_dict(d)
        self.assertEqual(h.render_tree(), g.render_tree())
        self.assertEqual(h.trace_back(h.get(300)), g.trace_back(g.get(300)))
        self.assertEqual(h.get(100).comm, "reused")
        self.assertEqual(h.get(100, 0).comm, "curl")
        self.assertEqual(h.get(300).cmdline, "bash -i")
        self.assertEqual(h.summary(), g.summary())


if __name__ == "__main__":
    unittest.main()


class FileIdentityTest(unittest.TestCase):
    def setUp(self):
        self.g, self.cat, self.ls = small_tree()

    def test_same_inode_different_names_is_one_file(self):
        g = self.g
        g.record_open(self.cat, 21 * SEC, "/tmp/a", "W", 3, fid="inode:8:42:1")
        g.record_open(self.ls, 22 * SEC, "/tmp/../tmp/a", "R", 3, fid="inode:8:42:1")
        self.assertEqual(len(g.files), 1)
        f = g.file("/tmp/a")
        self.assertEqual(f.paths, ["/tmp/a", "/tmp/../tmp/a"])
        self.assertIs(g.file("/tmp/../tmp/a"), f)
        self.assertIn((WRITE, "cat(1390)"),
                      [(k, d) for _, k, _, d in g.trace_back(self.ls)])

    def test_relative_paths_without_inode_make_no_edges(self):
        # Bug found in the audit: `find` opens "lib" relative to many
        # directories; keying by the bare name merged them into one node
        # and invented links between unrelated processes.
        g = self.g
        g.record_open(self.cat, 21 * SEC, "lib", "W", 3)
        g.record_open(self.ls, 22 * SEC, "lib", "R", 3)
        self.assertEqual(len(g.files), 0)
        self.assertEqual(self.cat.unresolved_opens, 1)
        self.assertNotIn("cat(1390)", [d for _, _, _, d in g.trace_back(self.ls)])

    def test_relative_path_with_inode_is_tracked(self):
        g = self.g
        g.record_open(self.cat, 21 * SEC, "lib", "W", 3, fid="inode:8:7:0")
        g.record_open(self.ls, 22 * SEC, "lib", "R", 3, fid="inode:8:9:0")
        self.assertEqual(len(g.files), 2)          # two different directories
        self.assertNotIn("cat(1390)", [d for _, _, _, d in g.trace_back(self.ls)])

    def test_file_lru_eviction(self):
        g = ProcessGraph(max_files=3)
        n = add(g, 10, 1, 0, 0, "p")
        for i in range(5):
            g.record_open(n, 10 + i, "/f%d" % i, "R", 3)
        g.record_open(n, 20, "/f2", "R", 3)                 # touch f2
        g.record_open(n, 21, "/f5", "R", 3)
        self.assertEqual(list(g.files), ["path:/f4", "path:/f2", "path:/f5"])
        self.assertIsNone(g.file("/f0"))
        self.assertNotIn("/f3", g.path_index)
        self.assertEqual(g.stats["evicted_files"], 3)
        g.trace_back(n)                                     # dangling fids are fine

    def test_skip_filter(self):
        g = self.g
        g.record_open(self.cat, 21 * SEC, "/lib/libc.so.6", "R", 3)
        g.record_open(self.cat, 22 * SEC, "/tmp/p", "R", 3)
        noisy = [d for _, _, _, d in g.trace_back(self.cat)]
        quiet = [d for _, _, _, d in g.trace_back(
            self.cat, skip=lambda f: f.label.startswith("/lib/"))]
        self.assertIn("/lib/libc.so.6", noisy)
        self.assertNotIn("/lib/libc.so.6", quiet)
        self.assertIn("/tmp/p", quiet)

    def test_alive_nodes(self):
        g = self.g
        g.record_exit(self.cat, 30 * SEC, 0)
        self.assertEqual(sorted(n.pid for n in g.alive_nodes()), [1, 1360, 1391])

    def test_names_move_to_newest(self):
        g = self.g
        for path in ("/a", "/b", "/a"):
            g.record_open(self.cat, 21 * SEC, path, "R", 3, fid="inode:1:1:0")
        self.assertEqual(g.file("inode:1:1:0").paths, ["/b", "/a"])

    def test_tree_shows_only_recent_exits(self):
        g = self.g
        g.record_exit(self.cat, 30 * SEC, 0)
        g.record_exit(self.ls, 39 * SEC, 0)
        text = g.render_tree(show_exited=False, recent_ns=5 * SEC, now_ns=40 * SEC)
        self.assertIn("ls(1391) [exited]", text)
        self.assertNotIn("cat(1390)", text)
        self.assertEqual(g.render_tree(max_lines=2).splitlines()[-1], "  ...")

    def test_snapshot_version_checked(self):
        with self.assertRaises(ValueError):
            ProcessGraph.from_dict({"version": 3})


class EndpointTest(unittest.TestCase):
    """Network peers as graph nodes, and the chain they complete."""

    def build(self):
        """The attack shape this layer exists for: a process downloads a
        payload, writes it to disk, and a second process runs it."""
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        curl = add(g, 100, 10 * SEC, 1, 1, "curl", "systemd")
        g.record_connect(curl, 11 * SEC, "net:203.0.113.5:443", True)
        g.record_open(curl, 12 * SEC, "/tmp/payload.sh", "W", 3)
        g.record_exit(curl, 13 * SEC, 0)
        bash = add(g, 200, 20 * SEC, 1, 1, "bash", "systemd")
        g.record_open(bash, 21 * SEC, "/tmp/payload.sh", "R", 3)
        return g, curl, bash

    def test_endpoint_node_created_once_per_peer(self):
        g, curl, _ = self.build()
        self.assertEqual(list(g.endpoints), ["net:203.0.113.5:443"])
        ep = g.endpoints["net:203.0.113.5:443"]
        self.assertEqual((ep.access_count, ep.failed_count), (1, 0))
        self.assertEqual(g.summary()["endpoints"], 1)

    def test_root_cause_reaches_the_network(self):
        # The question an analyst actually asks: where did this file come
        # from? Answer must cross process AND protocol boundaries.
        g, _, bash = self.build()
        found = [(k, d) for _, k, _, d in g.trace_back(bash)]
        self.assertIn(("READ", "/tmp/payload.sh"), found)
        self.assertIn(("WRITE", "curl(100)"), found)
        self.assertIn(("CONNECT", "net:203.0.113.5:443"), found)

    def test_impact_walk_reaches_the_processes_a_peer_fed(self):
        g, _, _ = self.build()
        ep = g.endpoints["net:203.0.113.5:443"]
        found = [(k, d) for _, k, _, d in g.trace_forward(ep)]
        self.assertIn(("CONNECT", "curl(100)"), found)
        self.assertIn(("WRITE", "/tmp/payload.sh"), found)
        self.assertIn(("READ", "bash(200)"), found)

    def test_time_order_is_respected_for_connections(self):
        # A connection opened AFTER a file was written cannot have supplied
        # its contents.
        g, curl, _ = self.build()
        late = add(g, 400, 40 * SEC, 1, 1, "wget", "systemd")
        g.record_open(late, 41 * SEC, "/tmp/other", "W", 3)
        g.record_connect(late, 42 * SEC, "net:198.51.100.7:80", True)
        f = g.file("/tmp/other")
        self.assertNotIn("net:198.51.100.7:80",
                         [d for _, _, _, d in g.trace_back(f)])

    def test_failed_connects_are_recorded_but_never_followed(self):
        g, _, _ = self.build()
        scanner = add(g, 500, 50 * SEC, 1, 1, "nmap", "systemd")
        for port in (22, 23, 445):
            g.record_connect(scanner, 51 * SEC, "net:10.0.0.9:%d" % port, False)
        self.assertEqual(scanner.failed_conns, 3)
        self.assertEqual(g.endpoints["net:10.0.0.9:22"].failed_count, 1)
        kinds = [k for _, k, _, _ in g.trace_forward(scanner)]
        self.assertNotIn("CONNECT", kinds)

    def test_unidentifiable_peer_is_counted_without_a_node(self):
        g, curl, _ = self.build()
        before = len(g.endpoints)
        g.record_connect(curl, 14 * SEC, None, True)
        self.assertEqual(len(g.endpoints), before)
        self.assertEqual(curl.conn_count, 2)

    def test_connection_history_survives_process_exit(self):
        # curl exited at 13s; its connection must still be attributable.
        g, curl, _ = self.build()
        self.assertFalse(curl.alive)
        ep = g.endpoints["net:203.0.113.5:443"]
        self.assertEqual([kind for _, _, kind in ep.accesses], ["CONNECT"])
        self.assertIn(curl.key, [k for _, k, _ in ep.accesses])

    def test_snapshot_round_trip_keeps_endpoints_and_chain(self):
        g, _, bash = self.build()
        h = ProcessGraph.from_dict(json.loads(json.dumps(g.to_dict())))
        self.assertEqual(list(h.endpoints), list(g.endpoints))
        self.assertEqual(h.trace_back(h.get(200)), g.trace_back(bash))
        self.assertEqual(h.get(100).conns, g.get(100).conns)
        self.assertEqual(h.summary(), g.summary())

    def test_endpoint_walk_terminates_on_a_connect_loop(self):
        # Two processes repeatedly reaching the same peer must not make the
        # walk cycle between them.
        g, curl, _ = self.build()
        other = add(g, 600, 60 * SEC, 1, 1, "nc", "systemd")
        for t in range(5):
            g.record_connect(other, (61 + t) * SEC, "net:203.0.113.5:443", True)
            g.record_connect(curl, (62 + t) * SEC, "net:203.0.113.5:443", True)
        ep = g.endpoints["net:203.0.113.5:443"]
        self.assertLessEqual(len(g.trace_forward(ep)), 200)
        self.assertLessEqual(len(g.trace_back(ep)), 200)


class SnapshotCompatibilityTest(unittest.TestCase):
    def test_snapshot_without_network_fields_still_loads(self):
        """Snapshots taken before v3.4 have no endpoints and no per-process
        conns. They must still load: the runs already recorded are the
        regression baseline, and silently refusing them would throw that
        away."""
        g, _, _ = small_tree()
        d = json.loads(json.dumps(g.to_dict()))
        d.pop("endpoints")
        for proc in d["processes"]:
            proc.pop("conns")
        h = ProcessGraph.from_dict(d)
        self.assertEqual(h.render_tree(), g.render_tree())
        self.assertEqual(h.endpoints, {})
        self.assertEqual(h.get(1390).conns, [])
        self.assertEqual(h.summary()["endpoints"], 0)


class InboundTest(unittest.TestCase):
    """Accepted connections: the other half of a lateral movement."""

    def build(self):
        """What arriving lateral movement looks like: something reaches our
        sshd, a shell is spawned under it, and that shell writes a file."""
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        sshd = add(g, 900, 10 * SEC, 1, 1, "sshd", "systemd")
        g.record_accept(sshd, 11 * SEC, "host:10.0.0.9")
        sh = add(g, 901, 12 * SEC, 900, 10 * SEC, "bash", "sshd")
        g.record_open(sh, 13 * SEC, "/tmp/dropped", "W", 3)
        return g, sshd, sh

    def test_one_node_per_host_however_many_connections(self):
        """The reason an inbound id carries no port.

        A peer's source port is ephemeral: a different number every
        connection (measured: 45192, then another). If it were part of the
        id, 500 connections from one host would be 500 endpoint nodes and
        "who keeps connecting to this box" would be unanswerable.
        """
        g, sshd, _ = self.build()
        for i, _port in enumerate((45192, 45193, 51022)):
            g.record_accept(sshd, (20 + i) * SEC, "host:10.0.0.9")
        self.assertEqual(list(g.endpoints), ["host:10.0.0.9"])
        ep = g.endpoints["host:10.0.0.9"]
        self.assertEqual(ep.access_count, 4)          # 1 from build() + 3
        self.assertEqual(sshd.accept_count, 4)
        self.assertEqual(g.summary()["inbound_hosts"], 1)

    def test_inbound_is_a_cause_in_a_root_cause_walk(self):
        # The question: this file appeared — what put it here? The answer
        # has to cross back out to the host that reached in.
        g, _, sh = self.build()
        found = [(k, d) for _, k, _, d in g.trace_back(sh)]
        self.assertIn((FORK, "sshd(900)"), found)
        self.assertIn((ACCEPT, "host:10.0.0.9"), found)

    def test_forward_from_the_peer_reaches_what_it_touched(self):
        # The mirror question, asked of an address from a threat feed:
        # what did this host get to? Processes, then their files.
        g, _, _ = self.build()
        ep = g.endpoints["host:10.0.0.9"]
        found = [(k, d) for _, k, _, d in g.trace_forward(ep)]
        self.assertIn((ACCEPT, "sshd(900)"), found)
        self.assertIn((FORK, "bash(901)"), found)
        self.assertIn((WRITE, "/tmp/dropped"), found)

    def test_inbound_and_outbound_to_the_same_host_stay_apart(self):
        """One host both called us and was called: two nodes, two labels.

        Keeping them as one node would read as a single relationship, and
        "it connected in" versus "we connected out" are opposite findings
        for a detector — arriving lateral movement versus exfiltration.
        """
        g, sshd, _ = self.build()
        g.record_connect(sshd, 30 * SEC, "net:10.0.0.9:443", True)
        self.assertEqual(sorted(g.endpoints),
                         ["host:10.0.0.9", "net:10.0.0.9:443"])
        kinds = {k for _, k, _, _ in g.trace_forward(sshd)}
        self.assertIn(CONNECT, kinds)

    def test_accept_with_no_peer_name_is_counted_not_invented(self):
        # accept(fd, NULL, NULL), or a unix client with no bound address:
        # a real connection, but the kernel has no identity to report.
        g, sshd, _ = self.build()
        g.record_accept(sshd, 40 * SEC, None, has_peer=False)
        self.assertEqual(sshd.accept_count, 2)
        self.assertEqual(sshd.nopeer_accepts, 1)
        self.assertEqual(len(g.endpoints), 1)          # no phantom node
        self.assertEqual(len(sshd.accepts), 1)

    def test_accepts_survive_a_snapshot(self):
        g, _, _ = self.build()
        h = ProcessGraph.from_dict(json.loads(json.dumps(g.to_dict())))
        self.assertEqual(h.get(900).accepts, [(11 * SEC, "host:10.0.0.9", True)])
        self.assertEqual(h.get(900).accept_count, 1)
        self.assertEqual(h.summary()["inbound_hosts"], 1)
        found = [(k, d) for _, k, _, d in h.trace_back(h.get(901))]
        self.assertIn((ACCEPT, "host:10.0.0.9"), found)

    def test_a_pre_inbound_snapshot_still_loads(self):
        # Same promise as v3.4 made for endpoints: the format version did
        # not change, so a snapshot written before accept existed loads
        # with the inbound fields simply empty.
        g, _, _ = self.build()
        d = g.to_dict()
        for p in d["processes"]:
            p.pop("accepts", None)
            p.pop("accept_count", None)
            p.pop("nopeer_accepts", None)
        # A v3.4 snapshot has no inbound anywhere, endpoints included: the
        # accept edge is recorded on BOTH sides, so a faithful old snapshot
        # drops it from the endpoint's access list too. (Which is also why
        # `inbound_hosts` is derived from the endpoint side: it survives a
        # process record being evicted.)
        for e in d["endpoints"]:
            e["accesses"] = [a for a in e["accesses"] if a[2] != ACCEPT]
        h = ProcessGraph.from_dict(json.loads(json.dumps(d)))
        self.assertEqual(h.get(900).accepts, [])
        self.assertEqual(h.get(900).accept_count, 0)
        self.assertEqual(h.summary()["inbound_hosts"], 0)


class WalkNoiseTest(unittest.TestCase):
    def test_a_process_is_not_listed_as_the_cause_of_its_own_connection(self):
        """Walking back from a process to an endpoint and then onward finds
        the process that opened the connection — usually the one we just came
        from. Naming it again explains nothing, so it is suppressed."""
        g, curl, bash = EndpointTest().build()
        found = g.trace_back(bash)
        labels = [d for _, _, _, d in found]
        self.assertEqual(labels.count("curl(100)"), 1)
        self.assertIn("net:203.0.113.5:443", labels)

    def test_a_second_distinct_process_is_still_reported(self):
        # suppression must not hide a genuinely different cause
        g, curl, bash = EndpointTest().build()
        other = add(g, 700, 5 * SEC, 1, 1, "wget", "systemd")
        g.record_connect(other, 6 * SEC, "net:203.0.113.5:443", True)
        ep = g.endpoints["net:203.0.113.5:443"]
        self.assertIn("curl(100)", [d for _, _, _, d in g.trace_back(ep)])


class ProbeNoiseTest(unittest.TestCase):
    """Resolver probes are recorded, but must not pollute causal walks."""

    def test_probe_endpoints_are_skippable(self):
        from hids.graph import noisy, probe_endpoint
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        ff = add(g, 100, 10 * SEC, 1, 1, "firefox", "systemd")
        # what getaddrinfo() does for every name a browser resolves
        for ip in ("180.149.52.211", "180.149.52.200"):
            g.record_connect(ff, 11 * SEC, "net:%s:0" % ip, True)
        g.record_connect(ff, 12 * SEC, "net:203.0.113.5:443", True)
        self.assertTrue(probe_endpoint(g.endpoints["net:180.149.52.211:0"]))
        self.assertFalse(probe_endpoint(g.endpoints["net:203.0.113.5:443"]))

        kept = [d for _, _, _, d in g.trace_forward(ff, skip=noisy)]
        self.assertIn("net:203.0.113.5:443", kept)
        self.assertNotIn("net:180.149.52.211:0", kept)
        # without the filter nothing is hidden: the probes are still recorded
        allof = [d for _, _, _, d in g.trace_forward(ff)]
        self.assertIn("net:180.149.52.211:0", allof)

    def test_unix_sockets_are_not_treated_as_probes(self):
        from hids.graph import probe_endpoint
        g = ProcessGraph()
        add(g, 1, 1, 0, 0, "systemd")
        n = add(g, 100, 10 * SEC, 1, 1, "app", "systemd")
        g.record_connect(n, 11 * SEC, "unix:/run/docker.sock", True)
        self.assertFalse(probe_endpoint(g.endpoints["unix:/run/docker.sock"]))
