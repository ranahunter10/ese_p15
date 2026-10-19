#!/usr/bin/env python3
"""
walk_trace.py — dry-run a causal walk, step by step.

A teaching and debugging tool: it prints every decision the BFS makes —
what it popped, which bound it was carrying, what it listed, what it
suppressed and why — so a walk can be followed by hand and checked.

    python3 tools/walk_trace.py runs/graph.json trace  1390
    python3 tools/walk_trace.py runs/graph.json impact 1390 --no-libs
    python3 tools/walk_trace.py runs/graph.json trace  1390 --at 1234.5
    python3 tools/walk_trace.py --demo write-then-read

It does NOT reimplement the algorithm. It passes a printing observer into
`ProcessGraph.trace_back` / `trace_forward`, so what you see is the real
walk explaining itself; a second copy of the loop would eventually drift
from the first and then teach the wrong thing.

Events, and what each one means:

  start   the walk's root and its initial time bound
  pop     a node taken off the queue and expanded (counts towards max_visits)
  choose  the single-cause rule picking ONE edge out of several candidates
          (last write before the bound; last contact before the bound)
  emit    an edge listed in the result, and its source queued
  dedup   `listed` suppressed an edge already reported (same node, kind, ts)
  echo    `via` suppressed an edge that would restate the link we arrived on
  skip    `seen` (node + bound), max_depth, the skip() filter, or a forward
          edge that happened before the bound
  stop    why the loop ended, with the final state sizes
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from hids.graph import ProcessGraph, noisy  # noqa: E402

SEC = 10 ** 9


def secs(ts):
    return "%.3fs" % (ts / 1e9) if ts else "0.000s"


class Printer:
    """An observer that renders each step as one line."""

    def __init__(self, out=sys.stdout):
        self.out = out
        self.step = 0

    @staticmethod
    def _ident(ident):
        """("P", (101, 0)) -> "pid 101"; ("F", fid) / ("E", eid) -> the id."""
        kind, val = ident
        if kind == "P":
            return "pid %d%s" % (val[0], "" if val[1] == 0 else " gen %d" % val[1])
        return str(val)

    def __call__(self, event, info):
        w = self.out.write
        if event != "start":
            self.step += 1
        if event == "start":
            w("  0  START      %-26s bound=%s%s\n"
              % (info["node"], secs(info["bound"]),
                 "  (--at)" if info.get("at_ns") is not None else ""))
            return
        if event == "stop":
            w("     ----------------------------------------------------------\n")
            w("     STOP       %s: %d edges, %d nodes expanded, "
              "%d left queued\n" % (info["why"], info["edges"], info["visits"],
                                    info["queue_left"]))
            w("                state: seen=%d (node,bound) pairs, listed=%d edges\n"
              % (info["seen"], info["listed"]))
            return
        if event == "pop":
            via = info.get("via")
            w("%3d  POP        %-26s bound=%-9s depth=%d queue=%d%s\n"
              % (self.step, info["node"], secs(info["bound"]), info["depth"],
                 info["queue"],
                 "  via=%s from %s" % (via[1], self._ident(via[0])) if via else ""))
            return
        if event == "emit":
            w("%3d    emit     %-5s %-20s at %-9s depth=%d -> queued\n"
              % (self.step, info["kind"], info["node"], secs(info["ts"]),
                 info["depth"]))
            return
        if event == "choose":
            w("%3d    choose   %-5s %-20s at %-9s  (1 of %d: %s)\n"
              % (self.step, info["kind"], info["node"], secs(info["ts"]),
                 info["of"], info["why"]))
            return
        if event in ("dedup", "echo", "skip"):
            label = {"dedup": "DEDUP", "echo": "ECHO ", "skip": "SKIP "}[event]
            node = info.get("node", "?")
            when = info.get("ts", info.get("bound"))
            w("%3d    %s    %-5s %-20s at %-9s  %s\n"
              % (self.step, label, info.get("kind", ""), node, secs(when),
                 info.get("why", "already reported")))
            return
        w("%3d  %s %r\n" % (self.step, event, info))


# ---------------------------------------------------------------------
# Built-in scenarios, so the tool teaches without needing a VM capture.
# Each returns (graph, the node to walk from, a one-line description).
# ---------------------------------------------------------------------
def _add(g, pid, start, ppid, pstart, comm, pcomm="", ts=None):
    return g.process(pid, start, ppid, pstart, comm, pcomm, 1000,
                     ts if ts is not None else start)


def demo_download_write_execute():
    """The chain the whole layer exists for."""
    g = ProcessGraph()
    _add(g, 1, 1, 0, 0, "systemd")
    curl = _add(g, 100, 10 * SEC, 1, 1, "curl", "systemd")
    g.record_connect(curl, 11 * SEC, "net:203.0.113.5:443", True)
    g.record_open(curl, 12 * SEC, "/tmp/payload.sh", "W", 3)
    g.record_exit(curl, 13 * SEC, 0)
    sh = _add(g, 200, 20 * SEC, 1, 1, "bash", "systemd")
    g.record_open(sh, 21 * SEC, "/tmp/payload.sh", "R", 3)
    g.record_exec(sh, 22 * SEC, "/bin/sh", ["sh", "/tmp/payload.sh"], False, "sh")
    return g, sh, "downloaded -> written -> executed, across two processes"


def demo_write_then_read():
    """Parent writes, child reads: the v3.4 WRITE-edge bug's shape."""
    g = ProcessGraph()
    _add(g, 1, 1, 0, 0, "systemd")
    sh = _add(g, 100, 10 * SEC, 1, 1, "bash", "systemd")
    g.record_open(sh, 11 * SEC, "p15_rel.txt", "W", 3, fid="inode:8:77:1")
    cat = _add(g, 101, 12 * SEC, 100, 10 * SEC, "bash", "bash")
    g.record_exec(cat, 13 * SEC, "/usr/bin/cat", ["cat", "./p15_rel.txt"],
                  False, "cat", old_comm="bash", fid="inode:8:99:1")
    g.record_open(cat, 14 * SEC, "./p15_rel.txt", "R", 4, fid="inode:8:77:1")
    return g, cat, "parent writes a file its child reads (FORK and WRITE both)"


def demo_two_reads_two_writers():
    """One file, two reads, two writers: the H2 multi-bound case."""
    g = ProcessGraph()
    _add(g, 1, 1, 0, 0, "systemd")
    w1 = _add(g, 101, 10 * SEC, 1, 1, "w1", "systemd")
    w2 = _add(g, 102, 11 * SEC, 1, 1, "w2", "systemd")
    r = _add(g, 200, 20 * SEC, 1, 1, "reader", "systemd")
    g.record_open(w1, 50 * SEC, "/tmp/g", "W", 3)
    g.record_open(r, 100 * SEC, "/tmp/g", "R", 3)
    g.record_open(w2, 200 * SEC, "/tmp/g", "W", 4)
    g.record_open(r, 296 * SEC, "/tmp/g", "R", 5)
    return g, r, "two reads of one file, each with its own writer"


def demo_inbound():
    """Arriving lateral movement: a peer reaches sshd, a shell drops a file."""
    g = ProcessGraph()
    _add(g, 1, 1, 0, 0, "systemd")
    sshd = _add(g, 900, 10 * SEC, 1, 1, "sshd", "systemd")
    g.record_accept(sshd, 11 * SEC, "host:10.0.0.9")
    sh = _add(g, 901, 12 * SEC, 900, 10 * SEC, "bash", "sshd")
    g.record_open(sh, 13 * SEC, "/tmp/dropped", "W", 3)
    return g, sh, "inbound connection -> sshd -> shell -> file written"


def demo_forward_time_bound():
    """A child forked BEFORE the read cannot be an effect of it (H1)."""
    g = ProcessGraph()
    _add(g, 1, 1, 0, 0, "systemd")
    curl = _add(g, 100, 10 * SEC, 1, 1, "curl", "systemd")
    g.record_open(curl, 20 * SEC, "/tmp/f", "W", 3)
    victim = _add(g, 200, 30 * SEC, 1, 1, "bash", "systemd")
    _add(g, 300, 41 * SEC, 200, 30 * SEC, "early", "bash")
    _add(g, 301, 60 * SEC, 200, 30 * SEC, "late", "bash")
    g.record_open(victim, 50 * SEC, "/tmp/f", "R", 3)
    return g, g.file("path:/tmp/f"), "forward from a file: which children count"


DEMOS = {
    "download-write-execute": (demo_download_write_execute, "trace"),
    "write-then-read": (demo_write_then_read, "trace"),
    "two-reads-two-writers": (demo_two_reads_two_writers, "trace"),
    "inbound": (demo_inbound, "trace"),
    "forward-time-bound": (demo_forward_time_bound, "impact"),
}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("snapshot", nargs="?", help="a --snapshot JSON file")
    p.add_argument("command", nargs="?", choices=["trace", "impact"])
    p.add_argument("target", nargs="?", help="PID to walk from")
    p.add_argument("--gen", type=int)
    p.add_argument("--at", type=float, default=None, metavar="SECONDS")
    p.add_argument("--no-libs", action="store_true")
    p.add_argument("--max-depth", type=int, default=6)
    p.add_argument("--demo", choices=sorted(DEMOS),
                   help="run a built-in scenario instead of a snapshot")
    a = p.parse_args(argv)

    if a.demo:
        build, command = DEMOS[a.demo]
        g, node, what = build()
        print("demo: %s\n  %s\n" % (a.demo, what))
    else:
        if not (a.snapshot and a.command and a.target):
            p.error("need SNAPSHOT COMMAND TARGET, or --demo NAME")
        with open(a.snapshot) as f:
            g = ProcessGraph.from_dict(json.load(f))
        node = g.get(int(a.target), a.gen)
        if node is None:
            sys.exit("no process %s in snapshot" % a.target)
        command = a.command

    walk = g.trace_back if command == "trace" else g.trace_forward
    out = walk(node, skip=noisy if a.no_libs else None,
               max_depth=a.max_depth,
               at_ns=int(a.at * 1e9) if a.at is not None else None,
               trace=Printer())
    print("\nresult, as the caller sees it:")
    for depth, kind, ts, desc in out:
        print("  " + "  " * depth + "%-6s %-9s %s" % (kind, secs(ts), desc))
    if not out:
        print("  (no edges)")


if __name__ == "__main__":
    main()
