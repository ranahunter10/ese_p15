#!/usr/bin/env python3
"""
analyze_run.py — turn a vm_validation.sh output folder into results.md/json.

    python3 tools/analyze_run.py runs/validation-YYYYmmdd-HHMMSS

Every check prints the evidence it used, so a FAIL can be investigated from
the log rather than argued about.
"""
import json
import os
import statistics
import sys
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from hids.graph import ProcessGraph, noisy  # noqa: E402


def load_jsonl(path):
    out = []
    if not os.path.exists(path):
        return out
    with open(path) as f:
        for n, line in enumerate(f, 1):
            try:
                out.append(json.loads(line))
            except ValueError:
                out.append({"type": "MALFORMED", "line": n})
    return out


def load_json(path):
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


class Report:
    def __init__(self):
        self.checks = []
        self.numbers = []

    def check(self, name, ok, evidence):
        self.checks.append({"check": name, "result": "PASS" if ok else "FAIL",
                            "evidence": evidence})

    def number(self, name, value, condition):
        self.numbers.append({"metric": name, "value": value, "condition": condition})


def functional(d, r):
    # Where this run put its scratch files. Runs made before the script used
    # a private directory wrote to fixed /tmp names, so those still analyse.
    paths = load_json(os.path.join(d, "paths.json")) or {
        "payload": "/tmp/p15_payload.txt", "fork": "/tmp/p15_fork.txt",
        "rel": "p15_rel.txt"}
    ev = load_jsonl(os.path.join(d, "functional.jsonl"))
    st = load_json(os.path.join(d, "functional.stats.json")) or {}
    snap = load_json(os.path.join(d, "functional.graph.json"))
    if not ev:
        r.check("functional run produced a log", False, "functional.jsonl missing/empty")
        return
    malformed = [e for e in ev if e["type"] == "MALFORMED"]
    r.check("JSONL log: every line parses", not malformed,
            "%d lines, %d malformed" % (len(ev), len(malformed)))
    # A broken line must fail only the check above, not crash the rest.
    ev = [e for e in ev if e["type"] != "MALFORMED"]
    execs = [e for e in ev if e["type"] == "EXEC"]

    hit = [e for e in execs if e.get("argv") == ["/bin/echo", "alpha", "beta", "gamma"]]
    r.check("argv captured (/bin/echo alpha beta gamma)", bool(hit),
            hit[0]["lineage"] if hit else "no EXEC with that argv")

    cats = [e for e in execs if e.get("path", "").endswith("/cat")]
    ok = any(e["name"] == "cat" and e.get("previous_name") in ("bash", "sudo", "sh")
             for e in cats)
    r.check("EXEC reports the NEW program name (Journal rows 9/15)", ok,
            "; ".join("%s <- %s" % (e["name"], e.get("previous_name")) for e in cats[:3])
            or "no cat EXEC")

    failed = [e for e in ev if e["type"] == "EXEC_FAILED"
              and "nonexistent_p15_binary" in e.get("path", "")]
    r.check("failed execve recorded as EXEC_FAILED", bool(failed),
            failed[0]["path"] if failed else "not found")

    ex = [e for e in ev if e["type"] == "EXIT" and e.get("exit_code") == 3]
    r.check("exit status captured (sh -c 'exit 3')", bool(ex),
            ex[0]["lineage"] if ex else "no EXIT with code 3")

    tr = [e for e in execs if e.get("argv_truncated") and e.get("path", "").endswith("echo")]
    r.check("argv truncation flagged (31 args > MAXARG=20)", bool(tr),
            "%d args kept" % len(tr[0]["argv"]) if tr else "not flagged")

    fk = [e for e in ev if e["type"] == "OPEN" and e.get("path") == paths["fork"]
          and e.get("mode") == "W"]
    r.check("fork-without-exec process tracked (bash subshell)", bool(fk),
            fk[0]["lineage"] if fk else "no write to " + paths["fork"])

    th = [e for e in ev if e["type"] == "OPEN" and e.get("thread") == "p15worker"]
    ok = any(e.get("name", "").startswith("python") and e.get("tid") != e.get("pid") for e in th)
    r.check("thread name kept separate from process name (row 10)", ok,
            "name=%s thread=%s pid=%s tid=%s" % (th[0]["name"], th[0]["thread"],
                                                th[0]["pid"], th[0]["tid"]) if th else "not found")

    mon_pid = st.get("monitor_pid")
    selfev = [e for e in ev if e.get("pid") == mon_pid]
    r.check("zero self-events from the monitor (in-kernel filter)", mon_pid and not selfev,
            "monitor pid %s, %d events from it" % (mon_pid, len(selfev)))

    unknown = [e for e in ev if "?(" in e.get("lineage", "")]
    rooted = [e for e in ev if e.get("lineage", "").startswith("systemd(1)")]
    r.check("no '?' in any lineage (row 12 regression)", not unknown,
            "%d/%d events have '?'; %d/%d rooted at systemd(1)"
            % (len(unknown), len(ev), len(rooted), len(ev)))

    feats = st.get("features", [])
    r.number("kernel features active", ", ".join(feats) or "none",
             "refused: %s" % (st.get("features_refused") or "none"))
    if st.get("records", {}).get("errors"):
        r.check("no processing errors", False, (st.get("first_error") or "")[-200:])
    else:
        r.check("no processing errors", True, "0 errors")

    fd = [e for e in execs if e.get("argv") == ["p15mem"]]
    ok = bool(fd) and all(e.get("exec_from_fd") for e in fd)
    r.check("fileless exec (memfd + fexecve) flagged exec_from_fd", ok,
            "path=%s requested=%s from_fd=%s" % (fd[0].get("path"), fd[0].get("requested_path"),
                                                 fd[0].get("exec_from_fd")) if fd else "no EXEC with argv [p15mem]")

    if snap:
        g = ProcessGraph.from_dict(snap)
        rel_reader = [n for n in g.nodes.values()
                      if n.cmdline == "cat ./" + paths["rel"]]
        if "FILE_IDENTITY" in feats:
            chain = [(k, d) for _, k, _, d in g.trace_back(rel_reader[0], skip=noisy)] if rel_reader else []
            ok = any(k == "WRITE" and d.startswith("bash(") for k, d in chain)
            r.check("relative path linked through inode (write -> read)", ok,
                    ", ".join("%s %s" % x for x in chain[:5]) or "reader not found")
        else:
            ok = bool(rel_reader) and rel_reader[0].unresolved_opens > 0
            r.check("relative path counted as unresolved (no inode feature)", ok,
                    "unresolved=%s" % (rel_reader[0].unresolved_opens if rel_reader else "?"))
        inode_files = sum(1 for fid in g.files if fid.startswith("inode:"))
        r.number("files identified by inode", "%d / %d" % (inode_files, len(g.files)),
                 "functional run")
        readers = [n for n in g.nodes.values()
                   if n.cmdline == "cat " + paths["payload"]]
        found = []
        if readers:
            found = [(k, desc) for _, k, _, desc in g.trace_back(readers[0], skip=noisy)]
        ok = any(k == "WRITE" and desc.startswith("sh(") for k, desc in found)
        r.check("root-cause trace: cat <- payload file <- sh that wrote it (libraries skipped)", ok,
                ", ".join("%s %s" % x for x in found[:6]) or "reader not found")
        r.number("graph size after functional run",
                 "%d processes, %d files, %d endpoints"
                 % (len(g.nodes), len(g.files), len(g.endpoints)),
                 "includes processes already running at startup")
        _network(d, r, ev, g)

    enter_seen = [e.get("enter_seen") for e in execs]
    if enter_seen:
        r.number("EXEC records fully assembled (enter+args+success)",
                 "%d / %d" % (sum(1 for x in enter_seen if x), len(enter_seen)),
                 "functional run")


def _network(d, r, ev, g):
    """The connect hook: attribution, failures, IPC, and the chain that
    crosses a protocol boundary. Everything is checked against the ports the
    demo actually chose (net_demo.json), not against hard-coded numbers."""
    demo = load_json(os.path.join(d, "net_demo.json")) or {}
    conns = [e for e in ev if e["type"] == "CONNECT"]
    if not demo.get("ok"):
        r.check("network demo ran", False,
                "net_demo.json missing or failed; %d CONNECT events seen" % len(conns))
        return

    hit = [e for e in conns if e.get("endpoint") == demo["endpoint"] and e.get("ret") == 0]
    r.check("outbound connection attributed to the process that made it", bool(hit),
            ("%s by %s" % (hit[0]["endpoint"], hit[0]["lineage"])) if hit
            else "no successful CONNECT to " + demo["endpoint"])

    refused = [e for e in conns if e.get("endpoint") == demo["refused_endpoint"]]
    r.check("refused connection recorded as an attempt, not a connection",
            bool(refused) and refused[0]["ret"] != 0,
            ("%s ret=%s" % (refused[0]["endpoint"], refused[0]["ret"])) if refused
            else "no CONNECT to the closed port")

    unix = [e for e in conns if e.get("family") == "unix"]
    r.check("unix-socket connection (local IPC) recorded", bool(unix),
            unix[0]["endpoint"] if unix else "no AF_UNIX CONNECT")

    pending = [e for e in conns if e.get("pending")]
    r.check("non-blocking connect flagged as in flight, not as a failure",
            bool(pending), ("%s ret=%s" % (pending[0]["endpoint"], pending[0]["ret"]))
            if pending else "no in-flight CONNECT seen")

    # The chain the whole layer exists for: a file executed on this host,
    # traced back through the process that wrote it to the peer it came from.
    runners = [n for n in g.nodes.values()
               if n.cmdline.startswith("/bin/sh " + demo["payload_path"])]
    found = []
    if runners:
        found = [(k, desc) for _, k, _, desc in
                 g.trace_back(runners[0], skip=noisy)]
    ok = any(k == "CONNECT" and desc == demo["endpoint"] for k, desc in found)
    r.check("root-cause trace crosses the network boundary: "
            "executed file <- writer process <- the peer it came from", ok,
            ", ".join("%s %s" % x for x in found[:8])
            or "the executing shell is not in the graph")

    typed = [e for e in conns if e.get("socket")]
    r.number("socket type resolved (SOCKET_TYPE feature)",
             "%d / %d connects" % (len(typed), len(conns)), "functional run")
    probes = [e for e in conns if e.get("probe")]
    r.number("name-resolution probes (getaddrinfo, port 0)",
             "%d of %d connects" % (len(probes), len(conns)),
             "glibc connects a UDP socket to each candidate address to pick a source address")

    # ---- inbound (accept) --------------------------------------------
    accepts = [e for e in ev if e["type"] == "ACCEPT"]
    server_side = [e for e in accepts
                   if e.get("endpoint") == demo.get("inbound_endpoint")]
    r.check("inbound connection recorded, attributed to the accepting process",
            bool(server_side),
            ("%s accepted by %s" % (server_side[0]["endpoint"],
                                    server_side[0]["lineage"]))
            if server_side else
            "no ACCEPT to %s (%d ACCEPT events seen)"
            % (demo.get("inbound_endpoint"), len(accepts)))

    # The design claim this check exists for: the peer's source port is
    # ephemeral, so it must NOT be part of the endpoint id. If it ever
    # creeps back in, repeated connections from one host fan out into one
    # node each and this check fails.
    ports = sorted({e.get("peer_port") for e in server_side})
    ids = sorted({e.get("endpoint") for e in server_side})
    # Must have something to judge: an empty set satisfies "all ids are the
    # same" trivially, and a check that passes on no data is not a check.
    r.check("inbound endpoint keyed by host, not by the peer's ephemeral port",
            bool(server_side) and len(ids) == 1,
            "%d connection(s) from %d distinct source port(s) -> %s"
            % (len(server_side), len(ports), ids or "no node")
            if server_side else "no inbound connections to judge")

    # A unix client normally has no bound address, so the kernel has no peer
    # name to give: the record must say so rather than invent one.
    nopeer = [e for e in accepts if not e.get("peer_known")]
    r.number("inbound connections with no peer name the kernel could give",
             "%d of %d accepts" % (len(nopeer), len(accepts)),
             "unix clients are usually unnamed; accept(fd, NULL, NULL) too")

    inbound_hosts = [e for e in g.endpoints.values()
                     if any(k == "ACCEPT" for _ts, _k, k in e.accesses)]
    r.number("hosts seen connecting IN", "%d" % len(inbound_hosts),
             "functional run")

    talkers = g.endpoints.get(demo["endpoint"])
    r.number("endpoint reuse: one node per peer",
             "%s contacted %d times by %d processes"
             % (demo["endpoint"], talkers.access_count,
                len({k for _, k, _ in talkers.accesses})) if talkers else "endpoint missing",
             "functional run")


def burst(d, r):
    ev = [e for e in load_jsonl(os.path.join(d, "burst.jsonl")) if e["type"] != "MALFORMED"]
    st = load_json(os.path.join(d, "burst.stats.json")) or {}
    trues = [e for e in ev if e["type"] == "EXEC" and e.get("argv") == ["/bin/true"]]
    good = [e for e in trues if e["lineage"].startswith("systemd(1)") and "?(" not in e["lineage"]]
    r.check("exec burst: all 200 /bin/true captured", len(trues) == 200,
            "%d captured, lost records: %s" % (len(trues), st.get("lost")))
    r.check("exec burst: full lineage on every one", trues and len(good) == len(trues),
            "%d/%d complete; e.g. %s" % (len(good), len(trues), trues[0]["lineage"] if trues else "-"))
    exits = [e for e in ev if e["type"] == "EXIT" and e["name"] == "true"]
    r.number("burst: EXEC / EXIT records for /bin/true", "%d / %d" % (len(trues), len(exits)),
             "200 x /bin/true in a shell loop")


def stress(d, r):
    for pages in (64, 256):
        st = load_json(os.path.join(d, "stress_p%d.stats.json" % pages))
        if not st:
            continue
        cond = "3x find / for 20 s, %d pages/CPU x %s CPUs" % (pages, st.get("cpus"))
        r.number("records received [p%d]" % pages, st["records_received"], cond)
        r.number("records lost [p%d]" % pages,
                 "%d (%.2f%%, %d bursts)" % (st["lost"], 100 * st["loss_rate"], st["lost_bursts"]), cond)
        r.number("throughput [p%d]" % pages, "%s records/s" % st["records_per_s"], cond)
        r.number("monitor CPU [p%d]" % pages,
                 "%s%% of one core" % st["monitor_cpu_percent_of_one_core"], cond)
        r.number("monitor peak RSS [p%d]" % pages,
                 "%.1f MB" % (st["monitor_maxrss_kb"] / 1024.0), cond)
        r.number("BCC compile+load time", "%.1f s" % st["bpf_compile_s"], "startup, one-off")


def overhead(d, r):
    path = os.path.join(d, "timings.csv")
    if not os.path.exists(path):
        return
    t = defaultdict(list)
    with open(path) as f:
        for line in f:
            mode, load, sec = line.strip().split(",")
            t[(mode, load)].append(float(sec))
    for load, desc in (("exec", "2000 x /bin/true"), ("open", "find /usr (cached)")):
        b, m = t.get(("base", load)), t.get(("mon", load))
        if not b or not m:
            continue
        mb, mm = statistics.median(b), statistics.median(m)
        r.number("workload slowdown: %s" % desc,
                 "%+.1f%% (%.2f s -> %.2f s, median of %d)" % (100 * (mm - mb) / mb, mb, mm, len(b)),
                 "with vs without monitor (quiet, no log)")


def main():
    d = sys.argv[1]
    r = Report()
    functional(d, r)
    burst(d, r)
    stress(d, r)
    overhead(d, r)
    env = open(os.path.join(d, "env.txt")).read() if os.path.exists(os.path.join(d, "env.txt")) else ""
    unit = ""
    up = os.path.join(d, "unit_tests.txt")
    if os.path.exists(up):
        unit = open(up).read().strip().splitlines()[-1]

    md = ["# ESE-P15 v3 validation — %s" % os.path.basename(d), "", "```", env.strip(),
          "unit tests: " + unit, "```", "", "## Checks", "",
          "| Result | Check | Evidence |", "|---|---|---|"]
    for c in r.checks:
        md.append("| %s | %s | %s |" % (c["result"], c["check"], c["evidence"].replace("|", "/")))
    md += ["", "## Measured numbers", "", "| Metric | Value | Condition |", "|---|---|---|"]
    for n in r.numbers:
        md.append("| %s | %s | %s |" % (n["metric"], n["value"], n["condition"]))
    text = "\n".join(md) + "\n"
    with open(os.path.join(d, "results.md"), "w") as f:
        f.write(text)
    with open(os.path.join(d, "results.json"), "w") as f:
        json.dump({"env": env, "unit_tests": unit, "checks": r.checks,
                   "numbers": r.numbers}, f, indent=2)
    print(text)
    fails = sum(1 for c in r.checks if c["result"] == "FAIL")
    print("%d checks, %d failed" % (len(r.checks), fails))


if __name__ == "__main__":
    main()
