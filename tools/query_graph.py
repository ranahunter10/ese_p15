#!/usr/bin/env python3
"""
query_graph.py — ask questions of a graph snapshot saved with --snapshot.

    python3 tools/query_graph.py runs/graph.json tree
    python3 tools/query_graph.py runs/graph.json lineage 1390
    python3 tools/query_graph.py runs/graph.json trace 1390      # root cause
    python3 tools/query_graph.py runs/graph.json impact 1390     # what it affected
    python3 tools/query_graph.py runs/graph.json files 1390
    python3 tools/query_graph.py runs/graph.json writers /tmp/x  # who wrote a file
    python3 tools/query_graph.py runs/graph.json fdexec          # programs run from an fd
    python3 tools/query_graph.py runs/graph.json gens 1390       # every lifetime of a PID
    python3 tools/query_graph.py runs/graph.json peers 1390      # who a process talked to
    python3 tools/query_graph.py runs/graph.json talkers net:1.2.3.4:443
    python3 tools/query_graph.py runs/graph.json endpoints       # every peer contacted
    python3 tools/query_graph.py runs/graph.json scans           # refused/unreachable attempts
    python3 tools/query_graph.py runs/graph.json inbound         # hosts that connected IN

A PID may have several lifetimes; add --gen N to pick one (default: newest).

trace/impact accept `--at <seconds>` to ask the point-in-time question:
"what had caused this as of T", or "what had it affected by T". T is the
monotonic second shown in the log's `ts_ns` field (divide by 1e9), because
that is the clock the graph stores; the JSONL log carries the wall-clock
`time` field beside it for translation.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from hids.graph import ProcessGraph, noisy  # noqa: E402


def pick(g, pid, gen):
    node = g.get(pid, gen)
    if node is None:
        sys.exit("no process %d%s in snapshot" % (pid, "" if gen is None else " gen %d" % gen))
    return node


def main():
    p = argparse.ArgumentParser()
    p.add_argument("snapshot")
    p.add_argument("command", choices=["tree", "lineage", "trace", "impact",
                                       "files", "writers", "gens", "summary",
                                       "fdexec", "peers", "talkers", "endpoints",
                                       "scans", "inbound"])
    p.add_argument("target", nargs="?")
    p.add_argument("--gen", type=int)
    p.add_argument("--no-libs", action="store_true",
                   help="trace/impact: skip shared libraries, locale files and "
                        "name-resolution probes (port-0 endpoints)")
    p.add_argument("--at", type=float, default=None, metavar="SECONDS",
                   help="trace/impact: answer as of this monotonic time "
                        "(ts_ns / 1e9 from the log) instead of the node's "
                        "own span — the question an alert timestamp poses")
    a = p.parse_args()
    needs_target = ("lineage", "trace", "impact", "files", "writers", "gens",
                    "peers", "talkers")
    if a.at is not None and a.command not in ("trace", "impact"):
        p.error("--at only applies to trace and impact")
    if a.command in needs_target and not a.target:
        p.error("'%s' needs a target (a PID, or a path for 'writers')" % a.command)
    if a.command in needs_target[:4] + ("gens", "peers") and not a.target.isdigit():
        p.error("'%s' needs a numeric PID" % a.command)
    with open(a.snapshot) as f:
        g = ProcessGraph.from_dict(json.load(f))

    if a.command == "summary":
        print(json.dumps(g.summary(), indent=2))
    elif a.command == "tree":
        root = pick(g, int(a.target), a.gen) if a.target else None
        print(g.render_tree(root))
    elif a.command == "gens":
        for key in g.gens.get(int(a.target), []):
            print(g.nodes[key], g.nodes[key].cmdline)
    elif a.command == "lineage":
        print(g.lineage_str(pick(g, int(a.target), a.gen)))
    elif a.command in ("trace", "impact"):
        node = pick(g, int(a.target), a.gen)
        walk = g.trace_back if a.command == "trace" else g.trace_forward
        at_ns = int(a.at * 1e9) if a.at is not None else None
        print(node.label(), "(%s%s)" % (a.command,
                                        " as of %.3fs" % a.at if a.at is not None else ""))
        for depth, kind, ts, desc in walk(node, skip=noisy if a.no_libs else None,
                                          at_ns=at_ns):
            print("  " * depth + "%-5s %-9.3fs %s" % (kind, ts / 1e9, desc))
    elif a.command == "files":
        node = pick(g, int(a.target), a.gen)
        for ts, path, mode, ret, fid in node.files:
            print("%-2s %-50s %s" % (mode, path, fid or "(unresolved)"))
        print("(%d successful opens, %d failed, %d unresolved)"
              % (node.file_count, node.failed_opens, node.unresolved_opens))
    elif a.command == "writers":
        f = g.file(a.target)
        if f is None:
            sys.exit("file not in snapshot")
        print("%s  names: %s" % (f.fid, ", ".join(f.paths)))
        for ts, key, kind in f.accesses:
            if kind == "WRITE" and key in g.nodes:
                print(g.lineage_str(g.nodes[key]))
    elif a.command == "peers":
        node = pick(g, int(a.target), a.gen)
        for ts, eid, ok in node.conns:
            print("%-10s out  %s" % ("connected" if ok else "FAILED", eid))
        for ts, eid, known in node.accepts:
            print("%-10s in   %s" % ("accepted", eid if known else "(peer unknown)"))
        print("(%d connect calls, %d failed; %d accepted, %d with no peer name)"
              % (node.conn_count, node.failed_conns, node.accept_count,
                 node.nopeer_accepts))
    elif a.command == "talkers":
        e = g.endpoints.get(a.target)
        if e is None:
            sys.exit("endpoint not in snapshot (try the 'endpoints' command)")
        print("%s  %d attempts, %d failed" % (e.eid, e.access_count, e.failed_count))
        for ts, key, kind in e.accesses:
            if key in g.nodes:
                print("%-15s %s" % (kind, g.lineage_str(g.nodes[key])))
    elif a.command == "endpoints":
        for e in g.endpoints.values():
            kinds = set(k for _ts, _key, k in e.accesses)
            where = "in" if kinds == {"ACCEPT"} else (
                "both" if "ACCEPT" in kinds else "out")
            print("%-40s %-5s %4d attempts  %4d failed"
                  % (e.eid, where, e.access_count, e.failed_count))
    elif a.command == "scans":
        # Refused or unreachable attempts, grouped by the process that made
        # them: one failure is noise, many from one process is a sweep.
        by_proc = {}
        for e in g.endpoints.values():
            for ts, key, kind in e.accesses:
                if kind == "CONNECT_FAILED" and key in g.nodes:
                    by_proc.setdefault(key, []).append(e.eid)
        for key, eids in sorted(by_proc.items(), key=lambda kv: -len(kv[1])):
            print("%s  %d failed attempts" % (g.lineage_str(g.nodes[key]), len(eids)))
            for eid in eids[:10]:
                print("    " + eid)
            if len(eids) > 10:
                print("    ... and %d more" % (len(eids) - 10))
    elif a.command == "inbound":
        # The other half of lateral movement. Grouped by peer host, because
        # one host opening many connections is one relationship, not many:
        # the source port differs every time and says nothing.
        by_host = {}
        for e in g.endpoints.values():
            for ts, key, kind in e.accesses:
                if kind == "ACCEPT" and key in g.nodes:
                    by_host.setdefault(e.eid, []).append(key)
        if not by_host:
            print("no accepted inbound connections in this snapshot")
        for eid, keys in sorted(by_host.items(), key=lambda kv: -len(kv[1])):
            uniq = sorted(set(keys))
            print("%-40s %d connections, %d process(es)"
                  % (eid, len(keys), len(uniq)))
            for key in uniq[:10]:
                print("    " + g.lineage_str(g.nodes[key]))
            if len(uniq) > 10:
                print("    ... and %d more" % (len(uniq) - 10))
    elif a.command == "fdexec":
        for n in g.nodes.values():
            for e in n.execs:
                if e.from_fd:
                    print("%s  %s  argv=%s" % (g.lineage_str(n), e.filename, " ".join(e.argv)))


if __name__ == "__main__":
    main()
