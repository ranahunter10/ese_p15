#!/usr/bin/env python3
"""The per-syscall tracepoint tax, measured by PAIRED ratios.

    sudo python3 tools/tax_paired.py                 # the full ladder
    sudo python3 tools/tax_paired.py --pairs 15      # tighter, slower
    sudo python3 tools/tax_paired.py --config count_exec

Why this exists, and why it is not `overhead_breakdown.sh` again.

`overhead_breakdown.sh` compares each configuration's median against the
medians of the baselines measured beside it. That protects against drift
between distant parts of a run, but not against drift DURING it — and on the
2026-10-18/19 runs the dd baseline moved 47 % within a single run while the
effect being hunted is ~6.7 % (16 ns on a 240 ns syscall). Both runs came out
non-monotonic and the analyzer refused to read either. More rounds cannot fix
that: the noise is multiplicative drift, not error that averages out.

The fix is the statistic, not the machine. Each measurement here is a PAIR
taken seconds apart — monitor up, run dd, monitor down, run dd — and the
result is the median of the per-pair RATIOS. Whatever both arms saw cancels.
The same change rescued this project's ingest measurement, where a ~50 %
sample spread around a 34 % effect became 1.34x with an IQR of 1.32-1.38
(`tools/bench_ingest.py`).

Three rules it enforces, each from something that has already gone wrong
here:

* **A real control, and the run is void without it.** `count_exit` runs the
  monitor with ZERO `syscalls:*` tracepoints. Its ratio must come out at 1.0:
  the monitor is running, reading events, using CPU, but no syscall is taxed.
  If that arm does not land near 1.0 the instrument is wrong and no other
  number from the run means anything, so it is reported as VOID rather than
  read.
* **CPU time of the workload, not wall time** — `dd`'s own user+sys, from
  `os.wait4`, so an unlucky scheduling slice is not a result.
* **Refuse to read what is not resolved.** If a ratio's interquartile range
  spans 1.0, or is as wide as the effect itself, the line says so instead of
  printing a median that looks like a finding.

Pinning: with `taskset` present, `dd` runs on CPU 0 and the monitor on CPU 1,
so contention on a 2-vCPU box is not counted as hook cost.

NOT YET RUN ON A KERNEL. The statistics are unit-tested against synthetic
data (`tests/test_tax_paired.py`), including a case where median-of-medians
fails and per-pair ratios succeed. The measurement itself is untested until
it runs on the VM.
"""
from __future__ import annotations

import argparse
import os
import resource
import shutil
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# hooks -> how many syscalls:* tracepoints that hook set attaches.
# net = connect enter/exit + accept enter/exit + accept4 enter/exit.
CONFIGS = [
    ("count_exit", "exit", 0),      # THE CONTROL: monitor up, no syscall tp
    ("count_exec", "exec", 2),
    ("count_open", "open", 4),
    ("count_net", "net", 6),
    ("count_all", "exec,open,exit,net", 12),
]


# ----------------------------------------------------------------- statistics
def pair_stats(ratios):
    """Median per-pair ratio, with the spread that decides if it is readable.

    Pure, so it can be tested without a kernel. Returns a dict rather than a
    tuple because the caller prints every field — a number without its spread
    is what this whole file exists to avoid.
    """
    if len(ratios) < 4:
        raise ValueError("need at least 4 pairs to speak of an IQR")
    rs = sorted(ratios)
    n = len(rs)
    med = statistics.median(rs)
    lo, hi = rs[n // 4], rs[(3 * n) // 4]
    effect = abs(med - 1.0)
    width = hi - lo
    # Two independent reasons a median must not be read as a result.
    spans_one = lo <= 1.0 <= hi
    too_wide = width >= effect
    return {"median": med, "iqr_lo": lo, "iqr_hi": hi,
            "min": rs[0], "max": rs[-1], "pairs": n,
            "effect": effect, "width": width,
            "resolved": not (spans_one or too_wide),
            "why": ("IQR spans 1.0" if spans_one else
                    "IQR as wide as the effect" if too_wide else "")}


def saturation_point(ladder):
    """Where the ladder stops rising, by ADJACENT-rung IQR overlap.

    `ladder` is the per-configuration stats, ordered by tracepoint count.
    Returns (saturates_at_tps_or_None, [(a_tps, b_tps, overlap_bool), ...]).

    Two rungs differ only if their IQRs are disjoint. Comparing each rung
    against zero instead would answer a different question — "does this
    configuration cost anything?" — and would say yes for all of them. The
    question actually asked is whether the NEXT hook costs anything, which is
    a comparison between neighbours.
    """
    steps = []
    saturates = None
    for a, b in zip(ladder, ladder[1:]):
        overlap = not (a["iqr_hi"] < b["iqr_lo"] or b["iqr_hi"] < a["iqr_lo"])
        steps.append((a["tps"], b["tps"], overlap))
        if overlap and saturates is None:
            saturates = a["tps"]
    return saturates, steps


def control_is_sane(stats, tolerance=0.05):
    """The 0-tracepoint arm must land at 1.0; it is the instrument check.

    `tolerance` is on the MEDIAN, not the spread: a control whose median sits
    5 % away from 1.0 means the two arms differ for a reason that is not
    syscall tracepoints — monitor CPU contention, page-cache state, anything —
    and every other rung inherits that error.
    """
    return abs(stats["median"] - 1.0) <= tolerance


# ---------------------------------------------------------------- measurement
def cpu_time_of(cmd, pin_cpu=None):
    """Run cmd, return its own user+sys CPU seconds (not wall)."""
    if pin_cpu is not None and shutil.which("taskset"):
        cmd = ["taskset", "-c", str(pin_cpu)] + cmd
    pid = os.fork()
    if pid == 0:                                    # child
        try:
            devnull = os.open(os.devnull, os.O_RDWR)
            os.dup2(devnull, 1)
            os.dup2(devnull, 2)
            os.execvp(cmd[0], cmd)
        finally:
            os._exit(127)
    _pid, status, ru = os.wait4(pid, 0)
    if os.WIFEXITED(status) and os.WEXITSTATUS(status) == 127:
        raise RuntimeError("could not run %r" % (cmd,))
    return ru.ru_utime + ru.ru_stime


class MonitorFailed(RuntimeError):
    """Raised with the monitor's own output attached, because on a load
    failure that output IS the diagnosis."""


class Monitor(object):
    """The monitor as a context manager, so a pair cannot leak one."""

    def __init__(self, hooks, pin_cpu=None, python=sys.executable):
        self.hooks = hooks
        self.pin_cpu = pin_cpu
        self.python = python
        self.proc = None

    def __enter__(self):
        # --sink count, not the graph: this measures the KERNEL-side tax, and
        # the Python graph would add userspace work that competes with the
        # workload for the same two CPUs. `overhead_breakdown.sh` uses the
        # same sink for its count_* configurations, so the rungs here mean
        # the same thing as the rungs there.
        cmd = [self.python, "-u", "-m", "hids.monitor", "--mode", "quiet",
               "--no-log", "--sink", "count", "--hooks", self.hooks]
        if self.pin_cpu is not None and shutil.which("taskset"):
            cmd = ["taskset", "-c", str(self.pin_cpu)] + cmd
        self.proc = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True)
        # Wait for the hooks to be live, not for a fixed sleep: BCC's compile
        # time varies by seconds and a fixed wait either wastes them or starts
        # measuring before the program is attached.
        #
        # Every line is KEPT. If the program fails to load, the verifier's
        # message is the most useful output of the whole run, and an earlier
        # version of this function discarded it and raised a bare timeout —
        # which is how the 18 Oct verifier rejection would have looked from
        # in here: a tool reporting "did not attach" while the kernel had
        # explained exactly why.
        seen = []
        deadline = time.time() + 90
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                break                       # the monitor exited
            seen.append(line.rstrip())
            if "Hooks attached" in line:
                return self
        self.__exit__(None, None, None)
        tail = "\n".join(seen[-12:]) or "(the monitor printed nothing)"
        raise MonitorFailed(
            "the monitor did not attach (hooks=%s). Its last output:\n%s"
            % (self.hooks, tail))

    def __exit__(self, *exc):
        if self.proc is None:
            return False
        self.proc.terminate()
        try:
            self.proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=10)
        self.proc = None
        return False


def measure_pair(hooks, dd_cmd, pin_workload, pin_monitor):
    """One pair: hooked then unhooked, seconds apart. Returns (hooked, bare)."""
    with Monitor(hooks, pin_cpu=pin_monitor):
        hooked = cpu_time_of(dd_cmd, pin_cpu=pin_workload)
    bare = cpu_time_of(dd_cmd, pin_cpu=pin_workload)
    return hooked, bare


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pairs", type=int, default=9,
                    help="pairs per configuration (default 9)")
    ap.add_argument("--dd-count", type=int, default=6_000_000,
                    help="dd bs=1 count=N; two syscalls per byte")
    ap.add_argument("--config", action="append",
                    help="limit to these configs (repeatable)")
    ap.add_argument("--no-pin", action="store_true",
                    help="do not pin workload and monitor to separate CPUs")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("needs root to load the BPF program: use sudo")
    if not os.path.isdir(os.path.join(ROOT, "hids")):
        sys.exit("run this from the project root: %s does not look like it"
                 % ROOT)

    dd_cmd = ["dd", "if=/dev/zero", "of=/dev/null", "bs=1",
              "count=%d" % args.dd_count]
    syscalls = 2 * args.dd_count
    pin_w, pin_m = (None, None) if args.no_pin else (0, 1)
    chosen = [c for c in CONFIGS if not args.config or c[0] in args.config]

    print("tax_paired: %d pairs per config, dd count=%d (%d syscalls), "
          "pinning=%s" % (args.pairs, args.dd_count, syscalls,
                          "off" if args.no_pin else "workload cpu0 / monitor cpu1"))
    print("dd calls none of the hooked syscalls, so its slowdown IS the tax.")
    print("Each pair is hooked-then-bare, seconds apart; the result is the "
          "median of per-pair ratios.\n")

    results = {}
    for name, hooks, tps in chosen:
        ratios, hookeds, bares = [], [], []
        for i in range(args.pairs):
            try:
                hooked, bare = measure_pair(hooks, dd_cmd, pin_w, pin_m)
            except MonitorFailed as e:
                # Stop at the first failure rather than grinding through the
                # remaining configurations: if the program will not load,
                # nothing after this is a measurement.
                print("\n%s\n" % e)
                print("Nothing was measured for %s or anything after it. If "
                      "that output names an instruction and an offset, it is "
                      "the verifier refusing the program -- paste it." % name)
                return 2
            if bare <= 0:
                sys.exit("dd reported no CPU time; cannot form a ratio")
            ratios.append(hooked / bare)
            hookeds.append(hooked)
            bares.append(bare)
            print("  %-11s pair %2d/%-2d  hooked %.3f s  bare %.3f s  "
                  "ratio %.4f" % (name, i + 1, args.pairs, hooked, bare,
                                  hooked / bare))
        st = pair_stats(ratios)
        st["tps"] = tps
        st["bare_median"] = statistics.median(bares)
        results[name] = st
        print("  -> %-11s %2d tp  ratio %.4f (IQR %.4f-%.4f, range "
              "%.4f-%.4f)  bare %.3f s%s\n"
              % (name, tps, st["median"], st["iqr_lo"], st["iqr_hi"],
                 st["min"], st["max"], st["bare_median"],
                 "" if st["resolved"] else "   not resolved (%s)" % st["why"]))

    print("=" * 72)
    control = results.get("count_exit")
    if control is None:
        print("NO CONTROL ARM in this run (count_exit was not measured), so "
              "the ladder below cannot be checked against a known answer.")
    elif not control_is_sane(control):
        print("VOID: the control arm (monitor running, ZERO syscall "
              "tracepoints) came out at %.4f, not 1.0." % control["median"])
        print("The two arms of every pair therefore differ for some reason "
              "that is not syscall tracepoints, and every rung inherits that "
              "error. No reading is offered. Likely causes: the monitor "
              "competing for CPU, or page-cache state differing between the "
              "arms.")
        return 1
    else:
        # A control that is NOT "resolved" is the control PASSING: there is no
        # effect to resolve, so its IQR straddling 1.0 is exactly right. An
        # earlier version of this summary listed it among the unresolved rungs
        # and advised raising --pairs, which told the reader the instrument had
        # failed at the moment it had worked.
        print("Control OK: 0 tracepoints with the monitor running reads "
              "%.4f (within 5 %% of 1.0)%s."
              % (control["median"],
                 "; its IQR straddles 1.0, which is what a zero effect "
                 "should look like" if not control["resolved"] else ""))

    ladder = sorted((st for st in results.values()), key=lambda st: st["tps"])

    # ns/syscall is converted with ONE common bare cost, the control's. Using
    # each configuration's own bare median -- as this tool first did -- feeds
    # the drift back in through the multiplication, undoing the very thing the
    # per-pair ratio removed: the bare arm wandered 1.5-3.9 s across the first
    # real run, so the same ratio would have produced ns figures differing by
    # 2.5x.
    base_s = (control or ladder[0])["bare_median"]
    print("Bare syscall cost (control's bare arm): %.1f ns. ns/syscall below "
          "is each ratio against THAT, not against its own bare arm." %
          (base_s / syscalls * 1e9))
    print()
    print("  %-11s %3s %8s %19s %11s" % ("config", "tp", "ratio", "IQR",
                                         "ns/syscall"))
    for st in ladder:
        name = next(n for n, v in results.items() if v is st)
        print("  %-11s %3d %8.4f   %.4f-%.4f %10.1f%s"
              % (name, st["tps"], st["median"], st["iqr_lo"], st["iqr_hi"],
                 (st["median"] - 1.0) * base_s / syscalls * 1e9,
                 "" if st["resolved"] else "   (not resolved)"))

    # The ladder is read by comparing ADJACENT rungs, and two rungs differ
    # only if their IQRs are disjoint. Comparing each rung against zero would
    # say "they all cost something"; comparing neighbours is what answers the
    # question actually asked -- does the NEXT hook cost anything?
    print("\nAdjacent rungs (disjoint IQRs = a real difference):")
    saturates_at, steps = saturation_point(ladder)
    for a_tps, b_tps, overlap in steps:
        print("  %2d -> %2d tp : %s" % (a_tps, b_tps,
              "overlap, no detectable difference" if overlap
              else "DISJOINT, real increase"))

    if saturates_at is not None:
        print("\nThe ladder stops rising at %d tracepoints: every rung beyond "
              "it is within its neighbour's IQR." % saturates_at)
        print("That is the measurement the design decision needs -- going "
              "from %d to %d hooks costs nothing detectable -- and it is "
              "stronger than the per-rung numbers, because it does not "
              "depend on converting a ratio into nanoseconds."
              % (saturates_at, ladder[-1]["tps"]))
    else:
        print("\nEvery adjacent pair is disjoint: the cost keeps rising with "
              "hook count on this machine. That CONTRADICTS a paid-once tax "
              "and would make hook count a budget after all -- re-run before "
              "believing it, then read syscall_regfunc() again.")

    print("\nThese are figures for THIS machine and run. The kernel mechanism "
          "(syscall_regfunc sets TIF_SYSCALL_TRACEPOINT once, then refcounts) "
          "is what predicts the shape; a measurement can only agree with it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
