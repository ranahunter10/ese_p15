#!/usr/bin/env python3
"""What a graph node costs in memory, measured with `tracemalloc`.

`docs/ARCHITECTURE.md` derives the node caps from per-node costs and labelled
them "measured (tracemalloc, this build)". No harness existed: an audit of
this tree found the figures had no reproducible source, which makes them
assertions dressed as measurements. The caps are the only thing standing
between a file-heavy host and the monitor's RSS, so the numbers behind them
have to be re-runnable.

Object sizes are interpreter-dependent — dict and str layouts differ between
3.8 and 3.13 — so the interpreter is printed with the result and the VM
figure is the one that should size the caps, because the VM runs 3.8.10.

    python3 tools/bench_nodes.py
    python3.8 tools/bench_nodes.py      # the figures that size the caps
"""
from __future__ import annotations

import argparse
import os
import sys
import tracemalloc

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from hids.graph import ProcessGraph                            # noqa: E402

SEC = 1_000_000_000


def cost(kind, accesses, nodes):
    """Bytes retained per node, including its access history.

    Caps are raised out of the way: the point is what a node costs while it
    is held, not what eviction later reclaims. The process node and the
    bootstrap are created before the snapshot so only the per-node growth is
    attributed.
    """
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
                g.record_connect(node, ts,
                                 "net:10.0.%d.%d:443" % (i // 256, i % 256),
                                 True)
    snap = tracemalloc.take_snapshot()
    tracemalloc.stop()

    held = sum(s.size_diff for s in snap.compare_to(base, "filename"))
    count = len(g.files) if kind == "file" else len(g.endpoints)
    assert count >= nodes, "%d %s nodes expected, %d present" % (nodes, kind, count)
    return held / float(nodes)


def fid_sharing(procs, distinct_files):
    """What sharing file-id strings saves, measured both ways.

    `file_id()` returns one cached object per distinct id; before v3.6 it
    built a fresh equal string per event, and every `node.files` tuple keeps
    whatever it was handed. The unshared arm is reproduced by wrapping
    `file_id` to hand back a fresh copy, so both arms do the same work and
    differ only in identity.

    The saving scales with how FEW distinct files a workload touches, which
    is why the fixture states its shape instead of quoting a bare percentage.
    """
    from hids import events as E

    def measure(share):
        orig = E.file_id
        if not share:
            def unshared(path, ino=0, dev=0, igen=0):
                r = orig(path, ino, dev, igen)
                return (r + " ")[:-1] if r else r   # equal, not identical
            E.file_id = unshared
        try:
            E._FID_CACHE.clear()
            g = ProcessGraph(max_nodes=10 ** 9, max_files=10 ** 9)
            g.bootstrap([{"pid": 1, "ppid": 0, "comm": "init", "uid": 0,
                          "start_ns": SEC}], 0)
            tracemalloc.start()
            base = tracemalloc.take_snapshot()
            seen = set()
            for p in range(procs):
                node = g.process(1000 + p, (2 + p) * SEC, 1, SEC, "p", "init",
                                 0, (2 + p) * SEC)
                for f in range(distinct_files):
                    path = "/usr/lib/f%d.so" % f
                    fid = E.file_id(path, f, 8, 0)
                    seen.add(id(fid))
                    g.record_open(node, (2 + p) * SEC + f, path, "R", 3, fid)
            snap = tracemalloc.take_snapshot()
            tracemalloc.stop()
            held = sum(s.size_diff for s in snap.compare_to(base, "filename"))
            return len(seen), held / 1e6
        finally:
            E.file_id = orig

    print("\nfile-id sharing: %d processes x %d distinct files = %d opens"
          % (procs, distinct_files, procs * distinct_files))
    rows = {}
    for share in (False, True):
        objs, mb = measure(share)
        rows[share] = (objs, mb)
        print("  %-8s distinct fid objects %7d, retained %6.1f MB"
              % ("shared" if share else "unshared", objs, mb))
    before, after = rows[False][1], rows[True][1]
    if before:
        print("  saving %.1f MB (%.0f %%); it grows as distinct files fall"
              % (before - after, (before - after) / before * 100))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--nodes", type=int, default=400)
    ap.add_argument("--fid-procs", type=int, default=20000)
    ap.add_argument("--fid-files", type=int, default=6)
    args = ap.parse_args()

    print("bench_nodes: %d nodes per cell, python %s"
          % (args.nodes, sys.version.split()[0]))
    print("\n| node | 1 access | 20 accesses |")
    print("|---|---|---|")
    out = {}
    for kind, label in (("file", "FileNode"), ("endpoint", "EndpointNode")):
        one = cost(kind, 1, args.nodes)
        hot = cost(kind, 20, args.nodes)
        out[kind] = (one, hot)
        print("| %s | ~%.0f B | ~%.1f KB |" % (label, one, hot / 1024.0))

    # What the caps mean in megabytes, which is the reason these figures are
    # quoted at all. Defaults read from the parser so a changed default
    # cannot leave this arithmetic behind.
    from hids.monitor import parse_args
    d = parse_args(["--mode", "print"])
    for kind, flag, n in (("file", "--max-files", d.max_files),
                          ("endpoint", "--max-endpoints", d.max_endpoints)):
        one, hot = out[kind]
        print("\n%s (default %s %d): ~%.0f MB typical, ~%.0f MB if every one "
              "is hot" % (kind, flag, n, n * one / 1e6, n * hot / 1e6))
    fid_sharing(args.fid_procs, args.fid_files)

    print("\nInterpreter-dependent. The VM runs 3.8.10; size the caps from a "
          "3.8 run, not this one, unless they match.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
