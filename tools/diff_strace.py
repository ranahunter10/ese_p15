#!/usr/bin/env python3
"""Measure capture recall against strace, and classify every miss.

This is gate G2. "We handle every corner case" is not a provable claim about
a system that observes a kernel -- three code reviews and 313 tests all passed
while the accept() length bug was live. What IS provable is a number:

    of the M syscalls that provably occurred, the monitor recorded N,
    and here are the M-N, each with a reason.

**Why both must run at once.** Running the workload twice -- once under the
monitor, once under strace -- gives two different sets of PIDs, and then
nothing can be matched to anything. So the monitor runs system-wide while
strace follows one workload, and every (pid, syscall, path) strace reports is
looked for in the monitor's log for that same pid.

**The barrier, not a sleep.** The workload does not start until the monitor
prints "Hooks attached." A `sleep 5` here would be the same flakiness that
cost two VM rounds: too short and the first execs are missed, too long and
nothing says so.

**Scope, stated rather than implied.** v1 compares `execve`/`execveat` and
`open`/`openat` only. Those are the highest-volume paths and the ones process
lineage and file provenance rest on. `connect`/`accept` need sockaddr parsing
out of strace's text form and are deliberately not attempted here, so this
tool reports recall for exec and open, not for the whole capture layer.

**What strace is and is not.** strace uses ptrace, so it stops the traced
process twice per syscall and perturbs the workload it measures. It is good
enough to FIND gaps; it is not a certificate that none remain, and a recall
figure from it must be quoted with that caveat.

Usage (needs root, on the VM):

    sudo python3 tools/diff_strace.py
    sudo python3 tools/diff_strace.py --workload 'find /usr/share/doc -name "*.gz"'
    sudo python3 tools/diff_strace.py --keep /tmp/g2    # keep the raw artifacts
"""

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

# The syscalls this tool compares. Kept narrow on purpose: see the module
# docstring on scope.
TRACED = "execve,execveat,open,openat"

# strace -f -o FILE writes "<pid><spaces><syscall>(...". With --keep the raw
# file is left behind, so these patterns can be checked against real output
# rather than trusted.
_LINE = re.compile(r"^(\d+)\s+(\w+)\((.*)$")
_RESUMED = re.compile(r"^(\d+)\s+<\.\.\.\s+(\w+)\s+resumed>")
_RET = re.compile(r"=\s+(-?\d+)")

BARRIER = "Hooks attached."


def _first_string_arg(rest):
    """The first "..." argument, which is the path for all four syscalls.

    execve("/bin/ls", ...)       -> /bin/ls
    openat(AT_FDCWD, "/etc/x",)  -> /etc/x   (first quoted arg, not first arg)

    strace escapes the path, so a literal \\" inside one would break a naive
    split; it is scanned instead.
    """
    i = rest.find('"')
    if i < 0:
        return None
    out = []
    j = i + 1
    while j < len(rest):
        c = rest[j]
        if c == "\\" and j + 1 < len(rest):
            out.append(rest[j:j + 2])
            j += 2
            continue
        if c == '"':
            break
        out.append(c)
        j += 1
    return "".join(out).encode().decode("unicode_escape", "replace")


def parse_strace(path):
    """-> (events, pids, stats). An event is (pid, kind, path, ok)."""
    events, pids = [], set()
    unfinished = truncated = 0
    with open(path, errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            m = _LINE.match(line)
            if not m:
                if _RESUMED.match(line):
                    # The completion half of a split syscall. Its first string
                    # argument was on the <unfinished> half, which we already
                    # counted, so counting this too would double-count.
                    unfinished += 1
                continue
            pid, call, rest = int(m.group(1)), m.group(2), m.group(3)
            pids.add(pid)
            if call not in ("execve", "execveat", "open", "openat"):
                continue
            if "<unfinished" in rest:
                # Counted on the resumed half's behalf: we have the path here
                # but not the return value, so treat it as a success we cannot
                # confirm rather than dropping it silently.
                truncated += 1
            p = _first_string_arg(rest)
            if p is None:
                continue
            r = _RET.search(rest)
            ok = (int(r.group(1)) >= 0) if r else True
            kind = "EXEC" if call.startswith("exec") else "OPEN"
            events.append((pid, kind, p, ok))
    return events, pids, {"unfinished_resumed": unfinished,
                          "unfinished_at_exit": truncated}


def parse_monitor(path):
    """-> (set of (pid, kind, path), malformed_count).

    Only EXEC/OPEN, matching the tool's scope. EXEC_FAILED and OPEN_FAILED
    are folded in as the same (pid, kind, path) because strace's failed call
    carries the same path -- whether the monitor got the return value right is
    a separate question from whether it saw the syscall at all.
    """
    seen, malformed = set(), 0
    with open(path, errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except ValueError:
                malformed += 1
                continue
            t = e.get("type", "")
            if t in ("EXEC", "EXEC_FAILED"):
                kind = "EXEC"
            elif t in ("OPEN", "OPEN_FAILED"):
                kind = "OPEN"
            else:
                continue
            pid = e.get("pid")
            for key in ("path", "requested", "filename"):
                p = e.get(key)
                if p:
                    seen.add((pid, kind, p))
    return seen, malformed


def classify(miss, monitor_pids, workload_pids, strace_pid, monitor_pid):
    """Why a syscall strace saw is absent from the monitor's log.

    Every category here is a reason that is NOT a capture gap. Whatever falls
    through to "unexplained" is the finding.
    """
    pid, kind, p, _ok = miss
    if pid in (strace_pid, monitor_pid):
        return "the instruments themselves"
    if pid not in monitor_pids:
        # The monitor never saw this pid at all -- so the miss is not "one
        # syscall lost", it is a whole process missing, which is a bigger
        # claim and gets its own bucket.
        return "process never seen by the monitor"
    if kind == "OPEN" and not p.startswith("/"):
        # openat(dirfd, "relative") -- the monitor stores what the kernel's
        # tracepoint gave it, which may be resolved differently. A path
        # comparison cannot settle these, so they are excluded rather than
        # counted as gaps in either direction.
        return "relative path, not comparable by string"
    if kind == "OPEN" and ("/proc/" in p or "/sys/" in p):
        return "procfs/sysfs (monitor reads these itself)"
    return "unexplained"


def measure(hooks, workload, work, tag, timeout):
    """One arm: monitor up, workload under strace, monitor down, compare.

    Returns a dict of the arm's results. Called more than once, so the
    artifacts of each arm are kept apart by `tag`.
    """
    mon_log = os.path.join(work, "%s-monitor.jsonl" % tag)
    raw = os.path.join(work, "%s-capture.p15raw" % tag)
    st_out = os.path.join(work, "%s-strace.out" % tag)

    cmd = [sys.executable, "-m", "hids.monitor", "--mode", "quiet",
           "--hooks", hooks, "--logfile", mon_log, "--record-raw", raw,
           "--no-bootstrap"]
    print("[%s] monitor --hooks %s" % (tag, hooks))
    mon = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True, bufsize=1)

    # The barrier. Wait for the monitor to SAY it is attached -- not a sleep:
    # too short loses the first execs, too long and nothing tells you.
    attached = threading.Event()
    banner = []

    def watch():
        for line in mon.stdout:
            banner.append(line)
            if BARRIER in line:
                attached.set()

    t = threading.Thread(target=watch, daemon=True)
    t.start()
    if not attached.wait(timeout=timeout):
        mon.terminate()
        sys.exit("[ERROR] monitor never reported %r. Output:\n%s"
                 % (BARRIER, "".join(banner[-15:])))

    st = ["strace", "-f", "-qq", "-e", "trace=" + TRACED, "-o", st_out,
          "sh", "-c", workload]
    # The workload's own output goes to a file, not the terminal. A heavy
    # workload (`find /usr ...`) otherwise buries the report under thousands
    # of its own lines, which is what happened on the VM on 2026-10-19. Kept
    # as an artifact rather than sent to /dev/null: if a workload fails, its
    # stderr is the only thing that says why.
    wl_out = os.path.join(work, "%s-workload.out" % tag)
    t0 = time.time()
    with open(wl_out, "wb") as f:
        rc = subprocess.call(st, stdout=f, stderr=subprocess.STDOUT)
    workload_s = time.time() - t0

    # SIGINT, not SIGKILL: the log is flushed on the clean-shutdown path only.
    mon.send_signal(signal.SIGINT)
    try:
        mon.wait(timeout=30)
    except subprocess.TimeoutExpired:
        mon.terminate()
        mon.wait(timeout=10)
    t.join(timeout=5)

    ev, wl_pids, st_stats = parse_strace(st_out)
    seen, malformed = parse_monitor(mon_log)
    mon_pids = {pid for pid, _k, _p in seen}

    misses, matched = [], []
    for pid, kind, p, ok in ev:
        (matched if (pid, kind, p) in seen else misses).append((pid, kind, p, ok))

    buckets = {}
    for m in misses:
        buckets.setdefault(classify(m, mon_pids, wl_pids, None, mon.pid),
                           []).append(m)

    excluded = sum(len(v) for k, v in buckets.items()
                   if k in ("the instruments themselves",
                            "relative path, not comparable by string"))
    return {
        "tag": tag, "hooks": hooks, "events": ev, "matched": matched,
        "misses": misses, "buckets": buckets, "malformed": malformed,
        "strace_stats": st_stats, "pids": wl_pids, "rc": rc,
        "workload_s": workload_s, "comparable": len(ev) - excluded,
    }


def by_kind(rows):
    out = {}
    for r in rows:
        out[r[1]] = out.get(r[1], 0) + 1
    return out


def control_verdict(control):
    """-> (verdict, message) for the negative-control arm.

    Extracted from main() so it can be tested: this verdict is what protects
    every recall figure the tool will ever print, and a verdict nothing can
    exercise is the same kind of untested guard the project keeps finding.

    verdict is "ok", "void" or "inconclusive".
    """
    tot = by_kind(control["events"])
    got = by_kind(control["matched"])
    o_tot, o_got = tot.get("OPEN", 0), got.get("OPEN", 0)
    e_tot, e_got = tot.get("EXEC", 0), got.get("EXEC", 0)
    if o_tot == 0:
        return ("inconclusive",
                "CONTROL INCONCLUSIVE: the workload performed no opens, so "
                "detaching the hook proves nothing. Use a workload that "
                "opens files.")
    if o_got:
        return ("void",
                "CONTROL FAILED: %d of %d opens still 'matched' with the hook "
                "detached. The comparison is not measuring capture -- treat "
                "the recall figure above as void." % (o_got, o_tot))
    if e_tot and not e_got:
        # Everything vanished, not just the opens. That is a broken arm (the
        # monitor never attached, the log went elsewhere), not a clean control.
        return ("void",
                "CONTROL FAILED: with only the exec hook attached, 0 of %d "
                "execs were found either. Nothing was captured in the control "
                "arm, so it does not isolate the open hook." % e_tot)
    return ("ok",
            "CONTROL OK: with the hook detached, 0 of %d opens were found "
            "(and %d of %d execs still were), so the comparison does detect a "
            "real capture gap." % (o_tot, e_got, e_tot))


def report(arm):
    ev, matched = arm["events"], arm["matched"]
    tot_k, got_k = by_kind(ev), by_kind(matched)
    print("strace recorded            : %d syscalls across %d pids"
          % (len(ev), len(arm["pids"])))
    print("monitor logged (same key)  : %d" % len(matched))
    print("comparable syscalls        : %d  (excludes the instruments and "
          "relative paths)" % arm["comparable"])
    if arm["comparable"] > 0:
        print("RECALL                     : %.2f %%  (%d of %d)"
              % (100.0 * len(matched) / arm["comparable"], len(matched),
                 arm["comparable"]))
    for k in sorted(tot_k):
        n, d = got_k.get(k, 0), tot_k[k]
        print("  %-5s recall             : %6.2f %%  (%d of %d)"
              % (k, 100.0 * n / d if d else 0.0, n, d))
    print("monitor malformed log lines: %d" % arm["malformed"])
    for k, v in arm["strace_stats"].items():
        print("strace %-20s: %d" % (k, v))
    print()
    print("misses by reason:")
    if not arm["buckets"]:
        print("  (none)")
    for k in sorted(arm["buckets"], key=lambda k: -len(arm["buckets"][k])):
        print("  %-42s %d" % (k, len(arm["buckets"][k])))
    # Printed with the arm it belongs to. It used to be printed once at the
    # very end, AFTER the control arm's report -- so the control's 108
    # deliberate misses were followed by "No unexplained misses in this run",
    # which refers to the live arm. Two arms' verdicts must not be separated
    # from their numbers.
    unexplained = arm["buckets"].get("unexplained", [])
    print()
    if unexplained:
        print("UNEXPLAINED in the %s arm -- these are the finding. First 25:"
              % arm["tag"])
        for pid, kind, p, ok in unexplained[:25]:
            print("  pid %-7d %-5s %s%s" % (pid, kind, p, "" if ok else "  (failed)"))
    else:
        print("No unexplained misses in the %s arm." % arm["tag"])


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workload",
                    default="sh -c 'for i in 1 2 3 4 5 6 7 8 9 10; do "
                            "/bin/true; /bin/echo hi >/dev/null; done; "
                            "ls -l /etc >/dev/null; cat /etc/hostname >/dev/null'",
                    help="shell command to measure (default: a small fixed mix "
                         "of execs and opens)")
    ap.add_argument("--keep", default="",
                    help="directory to keep the raw strace/monitor artifacts in")
    ap.add_argument("--hooks", default="exec,open",
                    help="monitor hooks to attach (default exec,open: this tool "
                         "only compares exec and open). Valid names are "
                         "exec,open,exit,net")
    ap.add_argument("--no-control", action="store_true",
                    help="skip the negative-control arm (not recommended: "
                         "without it a 100 %% recall figure is unfalsifiable)")
    ap.add_argument("--timeout", type=float, default=120.0)
    a = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("[ERROR] needs root (the monitor does): sudo python3 "
                 "tools/diff_strace.py")
    if not shutil.which("strace"):
        sys.exit("[ERROR] strace not installed: sudo apt install strace")

    work = a.keep or tempfile.mkdtemp(prefix="p15g2")
    os.makedirs(work, exist_ok=True)

    live = measure(a.hooks, a.workload, work, "live", a.timeout)
    print("workload finished in %.2f s (strace rc=%d)"
          % (live["workload_s"], live["rc"]))

    print()
    print("=" * 72)
    print("CAPTURE RECALL vs strace  (execve/execveat + open/openat only)")
    print("=" * 72)
    report(live)

    # -- the negative control ------------------------------------------------
    # A recall figure of 100 % is only meaningful if this harness is CAPABLE
    # of reporting less. So run it again with the `open` hook deliberately
    # detached: every openat strace sees must now come back missing. If OPEN
    # recall stays high, the comparison cannot fail and the figure above
    # measures nothing -- the same reasoning as tax_paired.py's 0-tracepoint
    # control arm, which reads 1.00 by construction.
    control = None
    if not a.no_control and "open" in a.hooks:
        print()
        print("=" * 72)
        print("NEGATIVE CONTROL: same workload, `open` hook DETACHED")
        print("Every openat must now be reported missing. If it is not, this")
        print("instrument cannot fail and the figure above is void.")
        print("=" * 72)
        control_hooks = ",".join(h for h in a.hooks.split(",")
                                 if h.strip() != "open") or "exec"
        control = measure(control_hooks, a.workload, work, "control", a.timeout)
        report(control)

        verdict, message = control_verdict(control)
        print()
        print(message)

    unexplained = live["buckets"].get("unexplained", [])
    print()
    print("strace uses ptrace and stops the traced process twice per syscall.")
    print("Two consequences, both limits on what this tool can ever say:")
    print(" 1. It perturbs what it measures. This FINDS gaps; it does not")
    print("    certify that none remain.")
    print(" 2. It suppresses the event RATE, so the perf ring is never")
    print("    stressed here. Recall under load is NOT measurable this way --")
    print("    use the monitor's own kernel-reported `lost` counter in a")
    print("    stress run for that (gate G3), not a strace comparison.")
    print("artifacts: %s" % work)
    if not a.keep:
        print("(temporary -- pass --keep DIR to retain them)")
    # A void instrument is a worse outcome than a found gap, so it gets its
    # own exit code: 2 = the control failed and the figure means nothing,
    # 1 = real unexplained misses, 0 = clean.
    if control is not None and control_verdict(control)[0] == "void":
        return 2
    return 0 if not unexplained else 1


if __name__ == "__main__":
    sys.exit(main())
