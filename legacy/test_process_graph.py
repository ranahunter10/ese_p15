#!/usr/bin/env python3
"""
test_process_graph.py — deterministic test of ProcessGraph, same
discipline as test_pid_reuse.py: synthetic inputs, no eBPF, no root,
no luck involved. Run this BEFORE wiring the graph into the real
monitor, so any bug is caught here, isolated, not buried inside a
live kernel event stream.

Run with:
    python3 test_process_graph.py
"""

from process_graph import ProcessGraph

g = ProcessGraph()

print("=" * 70)
print("STEP 1 — build a small tree: systemd -> bash -> cat, bash -> ls")
print("=" * 70)
g.on_exec(pid=1, name="systemd", ppid=0, pcomm="")
g.on_exec(pid=1360, name="bash", ppid=1, pcomm="systemd")
g.on_exec(pid=1390, name="cat", ppid=1360, pcomm="bash")
g.on_open(pid=1390, path="/etc/hostname")
g.on_exec(pid=1391, name="ls", ppid=1360, pcomm="bash")
print(g.render_tree(root_pid=1))

print("=" * 70)
print("STEP 2 — check children_of() gives the right answer both ways")
print("=" * 70)
print("children_of(1)    (should be [1360]):        ", g.children_of(1))
print("children_of(1360) (should be [1390, 1391]):  ", g.children_of(1360))
assert g.children_of(1) == [1360], "systemd should have exactly one child"
assert g.children_of(1360) == [1390, 1391], "bash should have both cat and ls as children"
print("PASS")
print()

print("=" * 70)
print("STEP 3 — the sir requirement: process exits, but its causal")
print("         trail (the file it touched) must survive")
print("=" * 70)
print("Before exit:", g.nodes[1390])
g.on_exit(1390)
print("After exit: ", g.nodes[1390])
assert g.nodes[1390].alive is False, "cat should be marked exited"
assert 1390 in g.nodes, "cat's NODE must still exist after exit"
assert len(g.nodes[1390].files) == 1, "the file it touched must still be recorded"
print("PASS — node persists, file record intact, only 'alive' flag changed")
print()
print("Tree view now shows the exit, but doesn't lose the node or its file:")
print(g.render_tree(root_pid=1))

print("=" * 70)
print("STEP 4 — a later, unrelated process reusing pid 1390 (mirrors the")
print("         PID-reuse concern from the lineage cache work) — does")
print("         the graph correctly treat it as a NEW identity, not")
print("         silently merge with the dead 'cat' node?")
print("=" * 70)
g.on_exec(pid=1390, name="malicious_proc", ppid=9999, pcomm="sshd")
print("nodes[1390] after reuse:", g.nodes[1390])
assert g.nodes[1390].name == "malicious_proc", "reused pid must show the NEW process's identity"
assert g.nodes[1390].alive is True, "reused pid should be alive again"
print("PASS — name and alive status correctly overwritten by the newer event")
print("NOTE (be honest about this): the OLD file record ('/etc/hostname',")
print("touched by the ORIGINAL cat) is still sitting in node.files, now")
print("misattributed to malicious_proc. This test found a second, distinct")
print("PID-reuse risk — this one in the graph itself, not the lineage")
print("cache from before. Not fixed here — flagging it, same as the")
print("original one, rather than pretending this file's history is clean.")
print()

print("=" * 70)
print("ALL STRUCTURAL ASSERTIONS PASSED")
print("Known open issue found by this test: file/socket history isn't")
print("scoped to a process GENERATION, only to a PID number — needs a")
print("generation counter or similar before this is trustworthy under")
print("real PID reuse, not just simple parent/child/exit tracking.")
print("=" * 70)
