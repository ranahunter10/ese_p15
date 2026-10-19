#!/usr/bin/env python3
"""Find the event rate at which the monitor starts losing records (gate G3).

**Why this is not tools/diff_strace.py.** That tool compares the monitor
against strace and answers "did it see what happened". It cannot answer "does
it still see everything under load", because strace stops the traced process
twice per syscall and so SUPPRESSES the very rate the question is about. The
two gates need two instruments:

    G2  correctness of capture   -> diff_strace.py, at whatever rate strace allows
    G3  loss under load          -> this, using the KERNEL's own lost counter

The loss counter is the right oracle here. `perf_buffer_poll`'s lost callback
is driven by the kernel's own record of how many records it overwrote before
userspace read them -- it needs no second observer, and nothing can hide a
drop from it.

**The ladder.** K parallel workers drive the rate up; each rung reports
records/s and the loss the kernel admits to. The interesting output is the
rung where loss stops being zero.

**Two guards, both of which can void a run** -- the same discipline as
tools/tax_paired.py, whose 0-tracepoint control arm is the only reason its
numbers are trustworthy:

  CONTROL      K=1 must lose nothing. The project has measured 0 loss at
               ~5.6k records/s, so a single worker losing records means
               something is wrong with the machine or the build, not with
               the design -- and every higher rung is then uninterpretable.

  MONOTONICITY the rate must RISE with K. On a 2-vCPU VM the workers compete
               with each other and with the monitor (~36 % of one core), so
               past some K the generator saturates CPU and adding workers
               makes the rate FALL. Beyond that point the ladder is measuring
               contention, not capture, and a loss figure from it would be
               attributed to the wrong cause.

The advisor's Layer 4 flood threshold is ~5,000 packets/s, so 5,000 events/s
is the line this measurement exists to speak to: the system is specified to
act at that rate, and the measured ceiling so far is ~5.6k records/s with no
loss -- close enough that it has to be probed above, not assumed.

Usage (needs root, on the VM):

    sudo python3 tools/loss_ladder.py
    sudo python3 tools/loss_ladder.py --workers 1,2,4,8 --seconds 20
    sudo python3 tools/loss_ladder.py --pages 256 --keep runs/g3
"""

import argparse
import json
import os
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

BARRIER = "Hooks attached."

# `find` opens every directory it descends, which is what makes it a dense
# source of openat records rather than merely a busy process. This is the
# same shape as the project's existing stress workload (3x parallel find /).
DEFAULT_WORKLOAD = "find /usr -xdev >/dev/null 2>&1"


def run_rung(workers, seconds, pages, hooks, work, workload, timeout=120.0):
    """One rung: start the monitor, run K workers for `seconds`, stop, read
    the stats it wrote. Returns the stats dict plus what we drove."""
    stats_path = os.path.join(work, "k%02d-stats.json" % workers)
    cmd = [sys.executable, "-m", "hids.monitor", "--mode", "quiet",
           "--hooks", hooks, "--no-log", "--no-bootstrap",
           "--pages", str(pages), "--stats-json", stats_path]
    mon = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True, bufsize=1)

    # The barrier, not a sleep: start driving only once the hooks are live,
    # or the first rung measures an unhooked machine.
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

    devnull = open(os.devnull, "wb")
    procs = []
    t0 = time.time()
    deadline = t0 + seconds
    try:
        for _ in range(workers):
            procs.append(subprocess.Popen(["sh", "-c",
                                           "while :; do %s; done" % workload],
                                          stdout=devnull, stderr=devnull,
                                          preexec_fn=os.setsid))
        while time.time() < deadline:
            time.sleep(0.2)
    finally:
        for p in procs:
            try:
                # The workers are shell loops that spawn children, so the
                # whole process group has to go -- killing the shell alone
                # leaves a find running into the next rung and silently
                # inflates it.
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except OSError:
                pass
        for p in procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
        devnull.close()
    drove_s = time.time() - t0

    mon.send_signal(signal.SIGINT)
    try:
        mon.wait(timeout=60)
    except subprocess.TimeoutExpired:
        mon.terminate()
        mon.wait(timeout=10)
    t.join(timeout=5)

    try:
        with open(stats_path) as f:
            st = json.load(f)
    except (OSError, ValueError) as e:
        sys.exit("[ERROR] rung K=%d wrote no readable stats (%s). Monitor "
                 "output:\n%s" % (workers, e, "".join(banner[-15:])))
    st["workers"] = workers
    st["drove_s"] = round(drove_s, 2)
    return st


def rate_of(st):
    """Records per second the monitor actually DRAINED.

    Not the event rate. At a lossy rung the kernel produced more than this
    and overwrote the difference, so quoting this as "the rate at which loss
    begins" conflates the consumer's ceiling with the offered load -- which
    is exactly the mistake the first version of this tool made on the VM run
    of 2026-10-19 (it bracketed the knee as 9436-10190 rec/s by comparing a
    clean rung's drain rate against a saturated one's).
    """
    d = st.get("duration_s") or 0
    return (st["records_received"] / d) if d else 0.0


def offered_of(st):
    """Records per second the kernel PRODUCED: drained plus overwritten.

    This is the event rate the machine was actually generating, and it is the
    axis a capture ceiling has to be stated against.
    """
    d = st.get("duration_s") or 0
    return ((st["records_received"] + st["lost"]) / d) if d else 0.0


def cpu_of(st):
    return st.get("monitor_cpu_percent_of_one_core", 0.0)


# A rung has to beat the previous one by more than this to count as having
# driven the rate higher. Below it the generator has plateaued and extra
# workers are buying contention rather than load.
MATERIAL_RISE = 0.15


def verdicts(ladder):
    """-> (list of messages, void) for the two guards."""
    msgs, void = [], False
    first = ladder[0]
    if first["lost"] == 0:
        msgs.append("CONTROL OK: K=%d lost 0 records at %.0f rec/s."
                    % (first["workers"], rate_of(first)))
    else:
        void = True
        msgs.append(
            "CONTROL FAILED: the lowest rung (K=%d) already lost %d records "
            "(%.2f %%) at only %.0f rec/s. The project has measured 0 loss at "
            "~5.6k rec/s, so something is wrong with this machine or build -- "
            "every higher rung is uninterpretable."
            % (first["workers"], first["lost"], 100 * first["loss_rate"],
               rate_of(first)))

    # Measured on OFFERED rate, not drained: at a lossy rung the drained rate
    # is pinned at the consumer's ceiling, so a ladder of drain rates looks
    # flat exactly when the offered load is still climbing.
    rates = [offered_of(s) for s in ladder]
    peak = max(range(len(rates)), key=lambda i: rates[i])
    if peak != len(rates) - 1:
        msgs.append(
            "OFFERED RATE PEAKED at K=%d (%.0f ev/s) and FELL after it. Past "
            "that rung the workers compete for CPU with each other and with "
            "the monitor, so those rungs measure contention rather than "
            "capture: do not attribute their loss to the ring buffer."
            % (ladder[peak]["workers"], rates[peak]))
    else:
        # It rose to the end -- but by how much? A +9 % rung after a +400 %
        # one is a plateau, and calling that "the generator was still the
        # limit" is a false inference. The first version of this tool made
        # exactly that claim about a ladder that had flattened at K=2.
        flat = [(i, (rates[i] - rates[i - 1]) / rates[i - 1])
                for i in range(1, len(rates)) if rates[i - 1] > 0
                and (rates[i] - rates[i - 1]) / rates[i - 1] < MATERIAL_RISE]
        if flat:
            # Name the transitions, not a range. "Plateaued from K=4 onward"
            # would be false on a ladder that flattens once and then climbs
            # again -- which is what the VM produced: +400 %, +9 %, +108 %.
            where = ", ".join(
                "K=%d->%d only +%.0f %%"
                % (ladder[i - 1]["workers"], ladder[i]["workers"], 100 * g)
                for i, g in flat)
            msgs.append(
                "OFFERED RATE DID NOT RISE MATERIALLY AT EVERY RUNG (%s). "
                "Where the rate stalls, the generator is not what limits it "
                "-- most likely CPU on this machine -- so adding workers "
                "there buys contention, not load, and a ceiling read off "
                "such a rung belongs to the test rig rather than to the "
                "capture path." % where)
        else:
            msgs.append(
                "OFFERED RATE MONOTONIC: it rose materially at every rung, so "
                "the generator was still the limit at K=%d and more workers "
                "would probe further." % ladder[-1]["workers"])

    # A gain bigger than parallelism can explain means something other than
    # the worker count changed. Doubling workers can at most roughly double
    # the rate -- and on a 2-vCPU box, less than that. A 5x gain from 1 to 2
    # workers is physically impossible from parallelism, so it is a warm-up
    # artefact: the 2026-10-19 cold ladder gained +400 % from K=1 to K=2
    # purely because `find /usr` moved from disk-bound to cached, and that
    # made its K=1 rung uncomparable to any later run.
    for i in range(1, len(ladder)):
        prev, cur = ladder[i - 1], ladder[i]
        prev_k, k = prev["workers"], cur["workers"]
        if rates[i - 1] <= 0 or prev_k <= 0:
            continue
        got = rates[i] / rates[i - 1]
        allowed = (float(k) / prev_k) * 1.3        # generous: an upper bound
        if got <= allowed:
            continue
        # TWO causes produce a superlinear gain, and naming the wrong one
        # sends the reader to the wrong fix. The first version blamed the
        # page cache unconditionally, and then told a user who had already
        # passed --warmup to rerun with --warmup.
        if cur["loss_rate"] - prev["loss_rate"] > 0.05:
            msgs.append(
                "GAIN EXCEEDS PARALLELISM at K=%d->%d (%.2fx offered rate for "
                "%.2fx workers), AND loss rose from %.1f %% to %.1f %% across "
                "those rungs. That is the overflow feedback loop, not a cold "
                "cache: when the ring is full, bpf_perf_event_output returns "
                "without copying the record, and that copy is charged to the "
                "TRACED process -- so dropping makes every syscall cheaper, "
                "the workers speed up, and the offered rate climbs. Offered "
                "load is therefore NOT independent of loss, and these rungs "
                "cannot be compared with another configuration's rungs at the "
                "same K."
                % (prev_k, k, got, float(k) / prev_k,
                   100 * prev["loss_rate"], 100 * cur["loss_rate"]))
        else:
            msgs.append(
                "GAIN EXCEEDS PARALLELISM at K=%d->%d: the offered rate rose "
                "%.2fx while the worker count rose only %.2fx, with no rise "
                "in loss to explain it. Workers cannot produce that, so "
                "something else changed between the rungs -- on this workload "
                "most likely the page cache going warm. Rerun with --warmup "
                "so every rung starts warm; until then treat the low rungs as "
                "uncomparable to any other run."
                % (prev_k, k, got, float(k) / prev_k))
        break

    # The drain rate falling as load rises is the headline property, not a
    # footnote: a consumer merely AT its ceiling holds steady, so a consumer
    # that gets slower under pressure is losing a race rather than running
    # out of capacity -- and it means coverage degrades exactly when the
    # machine is busiest, which is a property an attacker can use.
    drains = [rate_of(s) for s in ladder]
    peak_i = max(range(len(drains)), key=lambda i: drains[i])
    if drains[peak_i] > 0 and drains[-1] < drains[peak_i] * 0.85:
        msgs.append(
            "DRAIN RATE DEGRADES UNDER LOAD: it peaked at %.0f rec/s (K=%d) "
            "and fell to %.0f rec/s (K=%d) -- %.0f %% of peak -- while the "
            "monitor's CPU share fell from %.1f %% to %.1f %% of one core. A "
            "consumer at its capacity would hold steady; one that slows down "
            "is being descheduled. Coverage therefore drops when the machine "
            "is busiest, which is reachable by anyone who can generate "
            "syscall load. Test the mitigation by giving the monitor "
            "scheduling priority (nice -n -20, or SCHED_FIFO) and re-running "
            "this ladder: if the ceiling then holds, the defect is priority, "
            "not throughput."
            % (drains[peak_i], ladder[peak_i]["workers"], drains[-1],
               ladder[-1]["workers"], 100 * drains[-1] / drains[peak_i],
               cpu_of(ladder[peak_i]), cpu_of(ladder[-1])))

    # The attribution check. If the monitor got LESS CPU at the lossy rung
    # than at a clean one, it was starved rather than outpaced: the kernel
    # overwrote records because the consumer was not scheduled, which is a
    # different defect from a ring too small for the rate. Getting this
    # backwards would send the next change to --pages instead of to the
    # ingest path.
    lossy = [s for s in ladder if s["lost"] > 0]
    clean = [s for s in ladder if s["lost"] == 0]
    if lossy and clean:
        worst, best_cpu = lossy[0], max(clean, key=cpu_of)
        if cpu_of(worst) < cpu_of(best_cpu):
            msgs.append(
                "STARVATION, NOT CAPACITY: at the first lossy rung (K=%d) the "
                "monitor got %.1f %% of one core, LESS than the %.1f %% it "
                "got at the clean K=%d rung while facing more load. It was "
                "not outpaced, it was descheduled -- so this loss is CPU "
                "contention on a %s-CPU box. Two hypotheses to separate: a "
                "ring too small for the rate (re-run at a larger --pages; if "
                "the knee does not move, it was never ring size) versus a "
                "consumer that loses the scheduler race (re-run with "
                "scheduling priority; if the ceiling then holds, it was "
                "priority)."
                % (worst["workers"], cpu_of(worst), cpu_of(best_cpu),
                   best_cpu["workers"], os.cpu_count() or "?"))
    return msgs, void


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workers", default="1,2,4,8",
                    help="comma list of parallel worker counts (default 1,2,4,8)")
    ap.add_argument("--seconds", type=float, default=20.0,
                    help="how long to drive each rung (default 20)")
    ap.add_argument("--pages", type=int, default=64,
                    help="perf ring pages per CPU (default 64)")
    ap.add_argument("--hooks", default="exec,open,exit,net")
    ap.add_argument("--workload", default=DEFAULT_WORKLOAD,
                    help="what each worker loops (default: find /usr -xdev)")
    ap.add_argument("--keep", default="", help="keep the per-rung stats here")
    ap.add_argument("--warmup", type=float, default=15.0,
                    help="run the workload this long before the first rung, "
                         "with no monitor, to warm the page cache (default 15; "
                         "0 disables, which makes the first rungs of a cold "
                         "run uncomparable to anything)")
    a = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("[ERROR] needs root (the monitor does): sudo python3 "
                 "tools/loss_ladder.py")
    try:
        ks = sorted({int(x) for x in a.workers.split(",") if x.strip()})
    except ValueError:
        sys.exit("[ERROR] --workers must be a comma list of integers")
    if not ks or ks[0] < 1:
        sys.exit("[ERROR] --workers must start at 1 or more")

    work = a.keep or tempfile.mkdtemp(prefix="p15g3")
    os.makedirs(work, exist_ok=True)

    print("loss_ladder: %d rungs, %.0f s each, %d pages/CPU, hooks %s"
          % (len(ks), a.seconds, a.pages, a.hooks))
    print("each worker loops: %s" % a.workload)
    print("the oracle is the KERNEL's lost counter, not a second observer.")
    print()

    # Warm the page cache BEFORE the first rung.
    #
    # Two ladders run back to back on 2026-10-19 differed by 3.52x at K=1
    # (1,733 vs 6,099 events/s) for an identical workload, because the first
    # one started on a cold cache and warmed it as it climbed. That made its
    # K=1 -> K=2 "gain" of +400 % a cache artefact rather than worker scaling,
    # and made the two ladders uncomparable at every rung. `find /usr` on a
    # cold VirtualBox disk is I/O-bound; warm, it is pure syscall -- and only
    # the warm case measures the capture path.
    if a.warmup > 0:
        print("warming the page cache for %.0f s (%d workers, no monitor) ..."
              % (a.warmup, max(ks)), end="", flush=True)
        devnull = open(os.devnull, "wb")
        warm = [subprocess.Popen(["sh", "-c", "while :; do %s; done" % a.workload],
                                 stdout=devnull, stderr=devnull,
                                 preexec_fn=os.setsid)
                for _ in range(max(ks))]
        time.sleep(a.warmup)
        for p in warm:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except OSError:
                pass
        for p in warm:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
        devnull.close()
        print(" done.")
        print()

    ladder = []
    for k in ks:
        print("  K=%-3d driving %.0f s ..." % (k, a.seconds), end="", flush=True)
        st = run_rung(k, a.seconds, a.pages, a.hooks, work, a.workload)
        ladder.append(st)
        print("  %8.0f rec/s   received %-9d lost %-7d (%.2f %%)"
              % (rate_of(st), st["records_received"], st["lost"],
                 100 * st["loss_rate"]))

    print()
    print("=" * 74)
    print("LOSS vs EVENT RATE   (%d pages/CPU)" % a.pages)
    print("=" * 74)
    # Both rates, side by side. They are equal until something is lost, and
    # the gap between them IS the loss -- so printing only one of them is how
    # a consumer's ceiling gets mistaken for an event rate.
    print("%5s %11s %11s %11s %9s %8s %8s"
          % ("K", "offered/s", "drained/s", "received", "lost", "loss %", "CPU %"))
    for st in ladder:
        print("%5d %11.0f %11.0f %11d %9d %7.2f %8.1f"
              % (st["workers"], offered_of(st), rate_of(st),
                 st["records_received"], st["lost"], 100 * st["loss_rate"],
                 cpu_of(st)))

    print()
    msgs, void = verdicts(ladder)
    for m in msgs:
        print(m)

    print()
    lossy = [s for s in ladder if s["lost"] > 0]
    if void:
        print("This run is VOID: fix the control before reading anything above.")
    elif not lossy:
        best = max(ladder, key=offered_of)
        print("NO LOSS AT ANY RUNG. The highest OFFERED load reached was "
              "%.0f events/s at K=%d with 0 records lost, so this ladder has "
              "not found the ceiling -- it has only raised the floor. Report "
              "it as a lower bound, never as 'no loss': the knee is "
              "ABOVE %.0f events/s on this machine, and where above it is "
              "unknown. Add workers or use a denser workload until loss "
              "appears."
              % (offered_of(best), best["workers"], offered_of(best)))
        print()
        print("COMPARING THIS TO ANOTHER CONFIGURATION (a different --pages, "
              "say) IS ONLY VALID AT MATCHED OFFERED LOAD, NOT MATCHED K.")
        print("K does not fix the offered rate: when the ring overflows, "
              "bpf_perf_event_output fails without copying the record, and "
              "that copy is charged to the TRACED process -- so a dropping "
              "monitor makes the workload cheaper per syscall, the workers "
              "speed up, and the offered rate RISES. A run that loses "
              "nothing is therefore offered less load at the same K than one "
              "that drops, and 'no loss at K=8' does not mean the "
              "configuration survives the load the other one saw at K=8.")
        print("This ladder was never offered more than %.0f events/s."
              % offered_of(best))
    else:
        knee = lossy[0]
        prev = ladder[ladder.index(knee) - 1] if ladder.index(knee) else None
        print("LOSS BEGINS at K=%d: %.0f events/s offered, %.0f/s drained, "
              "%d records lost (%.2f %%)."
              % (knee["workers"], offered_of(knee), rate_of(knee),
                 knee["lost"], 100 * knee["loss_rate"]))
        print("DRAIN CEILING on this machine: ~%.0f records/s. That is what "
              "the consumer sustains; beyond it the kernel overwrites."
              % max(rate_of(s) for s in ladder))
        if prev is not None:
            # Bracketed on OFFERED rate. Bracketing on drained rate gives a
            # falsely tight answer, because the drained rate at the lossy
            # rung is the ceiling rather than the load.
            print("The last clean rung offered %.0f events/s (K=%d), so the "
                  "knee lies somewhere between %.0f and %.0f events/s -- a "
                  "wide bracket, because the ladder doubles K each step. "
                  "Narrow it with --workers %d,%d,%d,%d."
                  % (offered_of(prev), prev["workers"], offered_of(prev),
                     offered_of(knee), prev["workers"], prev["workers"] + 1,
                     prev["workers"] + 2, knee["workers"]))
        print("Against the advisor's ~5,000 events/s figure: the last rung "
              "with NO loss offered %.0f events/s, which is %s that rate."
              % (offered_of(ladder[ladder.index(knee) - 1]) if ladder.index(knee)
                 else 0.0,
                 "ABOVE" if (ladder.index(knee) and
                             offered_of(ladder[ladder.index(knee) - 1]) > 5000)
                 else "AT OR BELOW"))

    print()
    print("One machine, one run. Rates here are specific to this 2-vCPU VM, "
          "and the monitor competes with the workers for CPU on it.")
    print("artifacts: %s" % work)
    if not a.keep:
        print("(temporary -- pass --keep DIR to retain them)")
    return 2 if void else 0


if __name__ == "__main__":
    sys.exit(main())
