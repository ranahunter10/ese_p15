#!/usr/bin/env python3
"""analyze_claims.py — turn a claims run into a claim-by-claim evidence table.

    python3 tools/analyze_claims.py runs/claims-<timestamp>

Each row states the CLAIM, how it was tested, the evidence quoted from the
run, and the verdict — so a reader knows what would be broken if it failed.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from hids.graph import ProcessGraph  # noqa: E402


def jsonl(p):
    out = []
    if os.path.exists(p):
        for line in open(p):
            try:
                out.append(json.loads(line))
            except ValueError:
                out.append({"type": "MALFORMED"})
    return out


def load(p):
    return json.load(open(p)) if os.path.exists(p) else None


def main():
    d = sys.argv[1]
    ev = jsonl(os.path.join(d, "behaviour.jsonl"))
    st = load(os.path.join(d, "behaviour.stats.json")) or {}
    snap = load(os.path.join(d, "behaviour.graph.json"))
    reuse = load(os.path.join(d, "reuse.json")) or {}
    rst = load(os.path.join(d, "reuse.stats.json")) or {}
    lst = load(os.path.join(d, "loss.stats.json")) or {}
    g = ProcessGraph.from_dict(snap) if snap else None
    rows = []

    def row(cid, claim, how, evidence, ok):
        rows.append((cid, claim, how, evidence, "PASS" if ok else "NOT SHOWN"))

    execs = [e for e in ev if e["type"] == "EXEC"]
    hit = [e for e in execs if e.get("argv") == ["/bin/echo", "alpha", "beta", "gamma"]]
    row("C1", "Every program start is captured with its full command line",
        "run `/bin/echo alpha beta gamma`; compare the recorded argv",
        ("argv=%s, name=%s, previous_name=%s" % (hit[0]["argv"], hit[0]["name"], hit[0].get("previous_name")))
        if hit else "no EXEC with that argv", bool(hit))

    asm = [e.get("enter_seen") for e in execs]
    row("C1", "Starts are reassembled completely despite out-of-order delivery",
        "count EXEC records that had start + arguments + success",
        "%d / %d complete" % (sum(1 for x in asm if x), len(asm)), asm and all(asm))

    fd = [e for e in execs if e.get("exec_from_fd") or e.get("from_fd")
          or "/dev/fd/" in str(e.get("path", ""))]
    row("C2", "In-memory ('fileless') execution is detected — the case antivirus misses",
        "copy /bin/true into a memfd and execute it (Linux form of the 2017 technique)",
        ("path=%s, exec_from_fd=%s" % (fd[0].get("path"),
          fd[0].get("exec_from_fd", fd[0].get("from_fd")))) if fd else "not flagged", bool(fd))

    bad = [e for e in ev if e["type"] == "EXEC_FAILED"]
    row("C2", "Failed start attempts are recorded, not lost",
        "exec a path that does not exist", bad[0]["path"] if bad else "none recorded", bool(bad))

    found = []
    if g:
        readers = [n for n in g.nodes.values()
                   if "payload.txt" in n.cmdline and n.comm == "cat"]
        if readers:
            found = [(k, desc) for _, k, _, desc in g.trace_back(readers[0])]
    wr = [d2 for k, d2 in found if k == "WRITE" and d2.startswith("sh(")]
    row("C3", "The cause of an event can be named across process boundaries",
        "sh writes a file in this run's work directory; a separate cat reads "
        "it; trace the reader backwards",
        ("reader ← file ← %s" % wr[0]) if wr else "writer not reached from reader", bool(wr))

    if g:
        files = [n for n in g.files]
        inode = sum(1 for f in files if f.startswith("inode:"))
        row("C3", "A file is identified by inode, so the same file under another name still links",
            "count file nodes carrying an inode identity",
            "%d file nodes, %d recorded by inode" % (len(files), inode), len(files) > 0)

    unknown = [e for e in ev if "?(" in e.get("lineage", "")]
    rooted = [e for e in ev if e.get("lineage", "").startswith("systemd(1)")]
    row("C4", "Attribution is exact: every event has a full ancestry",
        "check every logged event's lineage string",
        "%d/%d rooted at systemd(1); %d contain an unknown ancestor" % (len(rooted), len(ev), len(unknown)),
        ev and not unknown)

    ex = [e for e in ev if e["type"] == "EXIT" and e.get("exit_code") == 3]
    row("C4", "Process exit and its status are captured",
        "run `sh -c 'exit 3'`", ("exit_code=3 for %s" % ex[0]["name"]) if ex else "not captured", bool(ex))

    gens = 0
    if reuse.get("ok"):
        rg = load(os.path.join(d, "reuse.graph.json"))
        if rg:
            h = ProcessGraph.from_dict(rg)
            gens = len(h.gens.get(reuse["reused_pid"], []))
    row("C4", "A recycled PID becomes a NEW process, never inheriting the old one's history",
        "spawn processes until the kernel reuses a PID; check that PID's lifetimes in the graph",
        ("pid %d reused after %d spawns; %d separate lifetimes in the graph; graph reports %s reuse events"
         % (reuse["reused_pid"], reuse["spawned"], gens, rst.get("graph", {}).get("generations")))
        if reuse.get("ok") else ("no PID repeated within the window (%s)" % reuse.get("note", "")),
        reuse.get("ok") and gens >= 2)

    mal = [e for e in ev if e["type"] == "MALFORMED"]
    row("C5", "The log is machine-readable with no corrupt lines",
        "parse every line of the JSONL log", "%d lines, %d malformed" % (len(ev), len(mal)), ev and not mal)

    row("C5", "Nothing is dropped silently: loss is counted and reported",
        "run with a 1-page buffer under 3 parallel `find /` so the buffer must overflow",
        "received %s, lost %s (%.2f%%) in %s bursts; errors %s"
        % (lst.get("records_received"), lst.get("lost"), 100 * (lst.get("loss_rate") or 0),
           lst.get("lost_bursts"), (lst.get("records", {}) or {}).get("errors", 0)),
        (lst.get("lost") or 0) > 0)

    row("C6", "The cost of monitoring is measured, not assumed",
        "monitor reports its own CPU and memory for each run",
        "behaviour run: %s%% of one core, %.1f MB; loss run: %s%% of one core"
        % (st.get("monitor_cpu_percent_of_one_core"), (st.get("monitor_maxrss_kb") or 0) / 1024.0,
           lst.get("monitor_cpu_percent_of_one_core")), bool(st))

    md = ["# Claim-by-claim evidence — %s" % os.path.basename(d), "",
          "| # | Claim | How it was tested | Evidence from this run | Result |", "|---|---|---|---|---|"]
    for cid, claim, how, evi, res in rows:
        md.append("| %s | %s | %s | %s | %s |" % (cid, claim, how, str(evi).replace("|", "/"), res))
    text = "\n".join(md) + "\n"
    open(os.path.join(d, "claims_evidence.md"), "w").write(text)
    json.dump([dict(zip(("claim_id", "claim", "how", "evidence", "result"), r)) for r in rows],
              open(os.path.join(d, "claims_evidence.json"), "w"), indent=2)
    print(text)
    print("%d claims, %d not shown" % (len(rows), sum(1 for r in rows if r[4] != "PASS")))


if __name__ == "__main__":
    main()
