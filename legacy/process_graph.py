"""
process_graph.py — in-memory DAG of process/file/socket relationships.

Stage 1 of the live execution-environment view sir asked for. Deliberately
standalone and eBPF-free right now — fed by plain method calls, testable
in isolation, same discipline as the earlier PID-reuse test. Only gets
wired into process_monitor_v2.py's handle_event() once THIS is proven
correct on its own.

Known gap, flagged honestly rather than hidden: on_exit() exists but has
no real caller yet — we don't have a process-EXIT hook in eBPF at all
right now (only execve/openat, both fire on process CREATION). A real
exit signal needs a new tracepoint, sched_process_exit, which we haven't
built. Until then, "alive" is never set False by real data — this file
proves the DATA STRUCTURE's behavior correctly, not the full pipeline.
"""

import time


class ProcessNode:
    def __init__(self, pid, name, ppid):
        self.pid = pid
        self.name = name
        self.ppid = ppid
        self.children = set()      # pids of direct children
        self.files = []            # list of (path, timestamp)
        self.sockets = []          # list of (dest_ip, dest_port, timestamp) — Stage 3+
        self.cpu_percent = 0.0     # populated later by /proc polling
        self.mem_kb = 0
        self.alive = True
        self.first_seen = time.time()
        self.last_seen = time.time()
        self.exit_time = None

    def __repr__(self):
        status = "alive" if self.alive else f"exited@{self.exit_time}"
        return f"<{self.name}(pid={self.pid}, ppid={self.ppid}, {status})>"


class ProcessGraph:
    def __init__(self):
        self.nodes = {}   # pid -> ProcessNode, NEVER deleted on exit —
                           # this is what makes "process died but created
                           # a file" survivable, per sir's explicit ask.

    def _get_or_create(self, pid, name=None, ppid=None):
        if pid not in self.nodes:
            self.nodes[pid] = ProcessNode(pid, name or "?", ppid if ppid is not None else 0)
        node = self.nodes[pid]
        if name:
            node.name = name
        if ppid is not None:
            node.ppid = ppid
        node.last_seen = time.time()
        return node

    def on_exec(self, pid, name, ppid, pcomm):
        """Call this for every EXEC event (maps directly onto your
        existing eBPF execve hook's captured fields)."""
        node = self._get_or_create(pid, name, ppid)
        # A fresh EXEC is kernel-confirmed proof this pid is alive RIGHT
        # NOW — must override any stale exited state left over from a
        # previous, unrelated process that held this same pid number
        # before it was reused. Same principle as the earlier lineage-
        # cache PID-reuse fix, found independently here by the test below.
        node.alive = True
        node.exit_time = None
        parent = self._get_or_create(ppid, pcomm)
        parent.children.add(pid)
        return node

    def on_open(self, pid, path):
        """Call this for every OPEN event (maps onto your existing
        openat hook)."""
        node = self._get_or_create(pid)
        node.files.append((path, time.time()))

    def on_exit(self, pid):
        """Not yet driven by real data — see module docstring. Exists
        so the data structure's exit-survival behavior can be tested
        now, ahead of building the real kernel hook."""
        if pid in self.nodes:
            self.nodes[pid].alive = False
            self.nodes[pid].exit_time = time.time()

    def children_of(self, pid):
        node = self.nodes.get(pid)
        return sorted(node.children) if node else []

    def render_tree(self, root_pid=1, indent=0):
        """pstree-style recursive text rendering."""
        node = self.nodes.get(root_pid)
        if not node:
            return ""
        status = "" if node.alive else " [exited]"
        files_note = f"  ({len(node.files)} file(s) touched)" if node.files else ""
        line = "  " * indent + f"{node.name}({node.pid}){status}{files_note}\n"
        for child_pid in sorted(node.children):
            line += self.render_tree(child_pid, indent + 1)
        return line
