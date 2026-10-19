#!/usr/bin/env python3
"""
analyze_overhead.py — tables + guarded readings for overhead_breakdown.sh.

    python3 tools/analyze_overhead.py runs/overhead-YYYYmmdd-HHMMSS

"Readings" are simple rules applied to the medians. They are hints for
where to look, each with the numbers behind it — not conclusions.
"""
import csv
import json
import os
import statistics
import sys
from collections import defaultdict

WORKLOADS = [("exec", "2000 x /bin/true"), ("open", "find /usr (cached)"),
             ("sys", "dd 300k 1-byte copies")]       # fallback labels only
ORDER = ["base", "bcc_execsnoop", "bcc_opensnoop", "count_exec", "count_open",
         "count_exit", "count_net", "count_all", "count_all_nofeat", "graph_all",
         "graph_all_batch20", "graph_all_log", "base_end"]

# How many syscalls:* tracepoints each configuration enables. Enabling ANY of
# them makes the kernel take the slower syscall path for every task, so the
# question is whether the cost is paid once or per hook. The dd workload runs
# none of the hooked syscalls, so its slowdown is that tax and nothing else.
# net = connect enter/exit + accept enter/exit + accept4 enter/exit.
SYSCALL_TRACEPOINTS = {"base": 0, "count_exit": 0, "count_exec": 2, "count_open": 4,
                       "count_net": 6, "count_all": 12, "count_all_nofeat": 12}
OPS = {"exec": 2000, "sys": 600000}      # defaults; the run's env.txt overrides
DRIFT_LIMIT = 0.10
NOISE = 0.10                             # changes below 10 % are treated as noise


def build():
    """Which build this analyzer belongs to, from the project's VERSION file.

    One source of truth, asserted against the README title by a drift guard.
    The report stamps it because on 16 Oct a corrected report was read out of
    an uncorrected analyzer in a stale tree, and nothing in the output said
    so -- the numbers looked like a result rather than like a stale tool.
    """
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "VERSION")
    try:
        with open(p) as f:
            return f.read().strip() or "unknown"
    except OSError:
        return "unknown"


def env(d):
    """The run's own parameters, from env.txt written by overhead_breakdown.sh."""
    out = {}
    p = os.path.join(d, "env.txt")
    if os.path.exists(p):
        with open(p) as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    out[k] = v
    return out


def ops(e):
    """How many operations each workload performs — the per-operation divisors.

    These were hardcoded at 2000 execs and 600_000 syscalls (dd count=300_000)
    until 16 Oct, when a run with P15_DD_COUNT=6000000 reported 0.63 µs of
    added cost per syscall. The divisor was 20x too small, so the figure was
    20x too large, and implausible on its face: the same arithmetic put the
    UNTRACED baseline at 2.55 µs per syscall for a /dev/zero -> /dev/null
    copy, which is roughly twenty times what a minimal syscall costs. Read
    from the run instead, and let the baseline sanity-check it.
    """
    o = dict(OPS)
    try:
        o["exec"] = int(e["exec_n"])
    except (KeyError, ValueError):
        pass
    try:
        o["sys"] = 2 * int(e["dd_count"])    # dd bs=1: one read + one write per byte
    except (KeyError, ValueError):
        pass
    return o


def workloads(e):
    """WORKLOADS with the labels this run's parameters actually describe."""
    if not e:
        return list(WORKLOADS)
    o = ops(e)
    n = o["sys"] // 2
    human = ("%gM" % (n / 1e6)) if n >= 10 ** 6 else ("%gk" % (n / 1e3)) if n >= 1000 else str(n)
    return [("exec", "%d x /bin/true" % o["exec"]),
            ("open", "find %s (cached)" % e.get("open_dir", "/usr")),
            ("sys", "dd %s 1-byte copies" % human)]


def load(d, metric="wall"):
    """Read timings.csv.

    Two formats are accepted. The original is
    `config,workload,round,wall_seconds`. Since 16 Oct it is
    `config,workload,round,wall,user,sys`, because wall time on a
    VirtualBox guest is not a stable measure: that run's baseline moved
    +195 % inside fifteen minutes. `metric="cpu"` uses the workload's own
    user+sys CPU time instead, which the hypervisor cannot inflate by
    taking the processor away.

    Returns the medians, the spreads, the skipped configs, and the ORDER
    configs appear in the file — the order matters because it is what lets
    a config be compared with the baseline measured next to it in time.
    """
    t = defaultdict(list)
    skipped = []
    order = []
    with open(os.path.join(d, "timings.csv")) as f:
        for row in csv.reader(f):
            if len(row) not in (4, 6):
                continue
            cfg, w, _r = row[0], row[1], row[2]
            if w == "skipped":
                skipped.append(cfg)
                continue
            if len(row) == 6 and metric == "cpu":
                val = float(row[4]) + float(row[5])
            else:
                val = float(row[3])
            if cfg not in order:
                order.append(cfg)
            t[(cfg, w)].append(val)
    med = {k: statistics.median(v) for k, v in t.items()}
    spread = {k: (max(v) - min(v)) / statistics.median(v) if statistics.median(v) else 0
              for k, v in t.items()}
    return med, spread, skipped, order


def has_cpu_times(d):
    with open(os.path.join(d, "timings.csv")) as f:
        return any(len(row) == 6 for row in csv.reader(f))


def local_base(med, order, cfg, w):
    """The baseline measured either side of `cfg`, not one taken minutes away.

    `base_after_<cfg>` rows are written between configurations by
    overhead_breakdown.sh. With a machine whose cost drifts during the run,
    a config compared against a 15-minute-old baseline measures the drift;
    compared against its neighbours it measures itself.
    """
    bases = [c for c in order if c.startswith("base")]
    if cfg not in order:
        return None
    i = order.index(cfg)
    before = [c for c in bases if order.index(c) < i]
    after = [c for c in bases if order.index(c) > i]
    vals = []
    for c in (before[-1:] + after[:1]) or bases:
        v = med.get((c, w))
        if v:
            vals.append(v)
    return statistics.mean(vals) if vals else None


def control(med, order, w):
    """Read every baseline run as though it were a configuration.

    A baseline has no tracer attached, so its true slowdown is zero by
    construction. Whatever the method reports for it is therefore the
    METHOD'S OWN ERROR — the only number in this report whose right answer
    is known before the run. A check that cannot fail is not a check: this
    one can, and it is what tells the reader which effects in the table are
    resolved and which are not.

    Returns (per-baseline readings, worst |reading|, mean |reading|).
    """
    out = []
    for cfg in order:
        if not cfg.startswith("base"):
            continue
        m, b = med.get((cfg, w)), local_base(med, order, cfg, w)
        if m and b:
            out.append((cfg, m / b - 1.0))
    errs = [abs(v) for _c, v in out]
    return out, (max(errs) if errs else 0.0), (statistics.mean(errs) if errs else 0.0)


def stats(d, cfg):
    p = os.path.join(d, cfg + ".stats.json")
    if not os.path.exists(p):
        return None
    with open(p) as f:
        return json.load(f)


def analyze(d):
    # CPU time when the run recorded it, wall time otherwise.
    metric = "cpu" if has_cpu_times(d) else "wall"
    med, spread, skipped, order = load(d, metric)
    e = env(d)
    WL = workloads(e)
    OP = ops(e)
    base = {}
    drift = {}
    for w, _ in WL:
        a, b = med.get(("base", w)), med.get(("base_end", w))
        vals = [x for x in (a, b) if x]
        base[w] = statistics.mean(vals) if vals else None
        if a and b:
            drift[w] = abs(a - b) / min(a, b)

    def slow(cfg, w):
        m = med.get((cfg, w))
        if m is None:
            return None
        b = local_base(med, order, cfg, w) or base.get(w)
        if not b:
            return None
        return m / b - 1.0

    lines = ["# Overhead breakdown — %s" % os.path.basename(d), "",
             "Measured by build **%s**, analyzed by build **%s**. If those differ, "
             "the numbers were read by a different tool than captured them; if the "
             "analyzing build is not the one you expect, you are running a stale "
             "tree." % (e.get("build", "unrecorded"), build()), ""]
    envpath = os.path.join(d, "env.txt")
    if os.path.exists(envpath):
        lines += ["```", open(envpath).read().strip(), "```", ""]
    interleaved = any(c.startswith("base_after_") for c in order)
    lines += ["Slowdown vs. no tracing, measured in **%s** (median of rounds; "
              "baseline = %s)." % (
                  "workload CPU time (user+sys)" if metric == "cpu" else "wall time",
                  "the runs measured immediately before and after each config"
                  if interleaved else "mean of the start and end runs"), "",
              "| Config | " + " | ".join(desc for _, desc in WL)
              + " | records/s | monitor CPU | features |",
              "|---|" + "---|" * (len(WL) + 3)]
    for cfg in ORDER:
        if not any((cfg, w) in med for w, _ in WL):
            continue
        cells = []
        for w, _ in WL:
            m, s = med.get((cfg, w)), slow(cfg, w)
            if m is None:
                cells.append("-")
            elif cfg in ("base", "base_end"):
                cells.append("%.2f s" % m)
            else:
                flag = " ±%d%%" % round(100 * spread[(cfg, w)]) if spread[(cfg, w)] > 0.2 else ""
                cells.append("%+.0f%% (%.2f s)%s" % (100 * s, m, flag))
        st = stats(d, cfg)
        rate = "%.0f" % st["records_per_s"] if st else "-"
        cpu = "%.1f%%" % st["monitor_cpu_percent_of_one_core"] if st else "-"
        feats = (",".join(st.get("features", [])) or "none") if st else "-"
        lines.append("| %s | %s | %s | %s | %s |" % (cfg, " | ".join(cells), rate, cpu, feats))
    if skipped:
        lines += ["", "Skipped (tracer failed to start): " + ", ".join(sorted(set(skipped)))]

    # ---- per-operation cost -------------------------------------------------
    # Divisors come from the run's parameters, and the baseline checks them:
    # a per-operation cost far above the cost of the bare operation itself
    # means the divisor is wrong, not that the hook is expensive.
    lines += ["", "## Added cost per operation", "",
              "Divisors from this run: %d execs; %s syscalls (dd bs=1 count=%s, one "
              "read and one write per byte). Baseline cost of one bare syscall here: "
              "%s. Each config is compared with the baselines measured beside it."
              % (OP["exec"], "{:,}".format(OP["sys"]),
                 "{:,}".format(OP["sys"] // 2),
                 ("%.0f ns" % (1e9 * med[("base", "sys")] / OP["sys"]))
                 if med.get(("base", "sys")) else "not measured"),
              "",
              "| Config | per exec | per syscall (sys workload) |", "|---|---|---|"]
    for cfg in ORDER[1:-1]:
        ex = med.get((cfg, "exec"))
        y = med.get((cfg, "sys"))
        if ex is None and y is None:
            continue
        be = local_base(med, order, cfg, "exec") or base.get("exec")
        by = local_base(med, order, cfg, "sys") or base.get("sys")
        pe = "%.2f ms" % ((ex - be) / OP["exec"] * 1e3) if ex and be else "-"
        py = "%.0f ns" % ((y - by) / OP["sys"] * 1e9) if y and by else "-"
        lines.append("| %s | %s | %s |" % (cfg, pe, py))

    # ---- guarded readings -------------------------------------------------------
    notes = []
    # The instrument's own error, measured, before any reading that depends on
    # it. With interleaved baselines, whole-run drift is no longer the noise
    # floor -- absorbing it is the entire point of the paired design -- so
    # quoting it as one would discard every real effect in the table. On the
    # 16-Oct run drift was 22 % while the method's residual error was 6 %.
    cread, cerr, cmean = control(med, order, "sys") if interleaved else ([], 0.0, 0.0)
    floor = max(NOISE, cerr)
    if cread:
        notes.append("**Instrument check (true answer is 0%%):** the %d baseline runs, "
                     "each read against its own neighbours, come out at %s. Worst "
                     "%.1f%%, mean %.1f%%. That is this run's noise floor: an effect "
                     "below it is not resolved, however plausible it looks."
                     % (len(cread),
                        ", ".join("%+.0f%%" % (100 * v) for _c, v in cread),
                        100 * cerr, 100 * cmean))
    for w, desc in WL:
        if drift.get(w, 0) > DRIFT_LIMIT and interleaved:
            notes.append("**Baseline drift:** base %s moved %.0f%% between the start and "
                         "the end of the run. It does not enter the comparisons above, "
                         "which use the baselines measured beside each config -- but it "
                         "is why two configs' wall times from different points in a run "
                         "cannot be compared, and why this run reports CPU time."
                         % (desc, 100 * drift[w]))
        elif drift.get(w, 0) > DRIFT_LIMIT:
            notes.append("**Drift:** base %s changed %.0f%% between start and end; "
                         "treat differences under that size as noise." % (desc, 100 * drift[w]))

    def pair(a, b, w):
        sa, sb = slow(a, w), slow(b, w)
        return (sa, sb) if sa is not None and sb is not None else None

    p = pair("count_exec", "bcc_execsnoop", "sys")
    if p and p[0] - p[1] > NOISE:
        notes.append("**Syscall-tracepoint cost:** with only our exec hooks, dd (which never "
                     "execs) slows %+.0f%%, against %+.0f%% under execsnoop. Both are "
                     "attached and neither fires on dd, so the difference is the "
                     "attachment mechanism: BCC's tools hang kprobes on the syscall "
                     "function, which costs nothing to a task that never calls it, while "
                     "a syscalls:* tracepoint taxes every syscall of every task. Confirm "
                     "the installed tools really use kprobes before quoting this: "
                     "grep -c attach_kprobe /usr/share/bcc/tools/execsnoop."
                     % (100 * p[0], 100 * p[1]))
    elif p and p[0] - p[1] > 0.6 * NOISE:
        # Suppressing a comparison silently is worse than either claiming or
        # dropping it: the reader cannot tell the difference between "no
        # effect" and "not commented on". On the 16-Oct run this one came to
        # 9.9 points against a 10-point threshold, so it is reported as what
        # it is -- suggestive, not established -- with the experiment that
        # would settle it.
        notes.append("**Syscall tracepoint versus kprobe — suggestive, under the "
                     "reporting threshold.** dd slows %+.0f%% with our exec hooks "
                     "(syscalls:* tracepoints) against %+.0f%% under execsnoop "
                     "(kprobes), a difference of %.1f points where this report only "
                     "comments above %.0f. The ladder below is the stronger evidence "
                     "for the same mechanism, since it compares our own hooks with "
                     "each other. To settle this comparison properly, attach OUR open "
                     "hook as a kprobe on do_sys_open in a measurement-only config: "
                     "same code, same userspace, only the attachment mechanism differs."
                     % (100 * p[0], 100 * p[1], 100 * (p[0] - p[1]), 100 * NOISE))
    p = pair("count_exit", "count_exec", "sys")
    if p and p[1] - p[0] > NOISE:
        notes.append("**Consistent:** the exit hook (sched tracepoint) costs dd %+.0f%%, the exec "
                     "hooks (syscall tracepoint) %+.0f%%." % (100 * p[0], 100 * p[1]))
    for w, desc in WL:
        p = pair("count_all", "count_all_nofeat", w)
        if p and p[0] - p[1] > NOISE:
            notes.append("**Inode/kernel-path reads** add %+.0f points on %s."
                         % (100 * (p[0] - p[1]), desc))
        p = pair("graph_all", "count_all", w)
        if p and p[0] - p[1] > NOISE:
            notes.append("**Python processing** adds %+.0f points on %s (graph vs count; same "
                         "kernel work, 2 vCPUs shared with the workload)." % (100 * (p[0] - p[1]), desc))
        p = pair("graph_all_batch20", "graph_all", w)
        if p and p[1] - p[0] > NOISE:
            notes.append("**Batching helps** on %s: %+.0f%% -> %+.0f%% with 20 ms polling "
                         "(fewer reader wakeups)." % (desc, 100 * p[1], 100 * p[0]))
        p = pair("graph_all_log", "graph_all", w)
        if p and p[0] - p[1] > NOISE:
            notes.append("**Logging** adds %+.0f points on %s." % (100 * (p[0] - p[1]), desc))
    for cfg in ORDER:
        st = stats(d, cfg)
        if st and st.get("lost"):
            notes.append("**Loss:** %s dropped %d records (%.2f%%) — its slowdown is "
                         "understated by that much work." % (cfg, st["lost"], 100 * st["loss_rate"]))
        if st and st.get("features_refused"):
            notes.append("**Features refused** in %s: %s" % (cfg, st["features_refused"]))
    # Does the per-syscall tax scale with the number of hooks, or is it paid
    # once? dd executes none of the hooked syscalls, so its slowdown isolates
    # the tax. A flat line means hooks are nearly free to add; a rising one
    # means hook count is a budget to spend carefully.
    ladder = []
    for cfg, n in sorted(SYSCALL_TRACEPOINTS.items(), key=lambda kv: kv[1]):
        v = slow(cfg, "sys")
        if v is not None:
            ladder.append((n, cfg, v))
    if len(ladder) >= 3:
        listing = ", ".join("%d tp %s %+.0f%%" % (n, cfg, 100 * v)
                            for n, cfg, v in ladder)
        # Before offering flat-vs-rising, check the data can tell them apart.
        # Three ways it cannot, all of which happened on the 16-Oct run:
        #   * the worst single-config spread exceeds the whole ladder's range,
        #   * the baseline drifted by more than the range,
        #   * the ladder is not monotonic in tracepoint count by more than noise.
        # Offering a reading anyway would invite whichever conclusion the
        # reader already believed, which is worse than no reading at all.
        vals = [v for _n, _cfg, v in ladder]
        rng = max(vals) - min(vals)
        bands = [spread[(cfg, "sys")] for _n, cfg, _v in ladder
                 if (cfg, "sys") in spread]
        worst = max(bands) if bands else 0.0
        dft = drift.get("sys", 0.0)
        drops = sum(1 for a, b in zip(ladder, ladder[1:]) if b[2] < a[2] - NOISE)
        why = []
        if worst >= rng:
            why.append("the worst single-config spread (±%.0f%%) is as large as the "
                       "whole ladder's range (%.0f points)" % (100 * worst, 100 * rng))
        if interleaved:
            # Paired baselines absorb whole-run drift, so the floor is the
            # instrument's measured residual error, not the drift.
            if rng <= floor:
                why.append("the whole ladder's range (%.0f points) is inside the "
                           "instrument's own error (%.0f%%, measured on the baselines)"
                           % (100 * rng, 100 * floor))
        elif dft >= rng:
            why.append("the baseline itself drifted %.0f%% between the first and last "
                       "run, which is the size of the effect being measured"
                       % (100 * dft))
        if drops:
            why.append("the ladder is not monotonic: %d rung(s) come in LOWER than a "
                       "configuration with fewer tracepoints, which no per-hook cost "
                       "model can produce" % drops)
        if why:
            notes.append("**Cost per added syscall tracepoint — INCONCLUSIVE, no reading "
                         "offered.** Measured: " + listing + ". This cannot be read as "
                         "flat or rising, because " + "; and ".join(why) + ". What would "
                         "resolve it: a dd workload long enough that one round takes "
                         "seconds rather than ~0.15 s (P15_DD_COUNT), more rounds "
                         "(P15_ROUNDS), and the workload and the monitor pinned to "
                         "different CPUs (P15_PIN=1) so that contention on a 2-vCPU box "
                         "is not counted as hook cost.")
        else:
            # Two competing models, each making a number this ladder can
            # check, rather than a flat-or-rising choice left to the reader:
            #   PAID ONCE   the top rung costs the same as the first
            #   PER HOOK    the top rung costs n_top/n_first times the first
            # Report both residuals and name the closer one. The models are
            # 5x apart here, so the verdict survives the noise floor even
            # though the individual rung-to-rung steps do not.
            zero = [v for n, _c, v in ladder if n == 0]
            rungs = [(n, c, v) for n, c, v in ladder if n > 0]
            extra = ""
            if zero and len(rungs) >= 2:
                z = statistics.mean(zero)
                n1, _c1, v1 = rungs[0]
                nN, _cN, vN = max(rungs, key=lambda r: r[0])
                step = v1 - z
                if nN > n1 and step > 0:
                    per_hook = (vN - v1) / (nN - n1)
                    pred = z + step * nN / float(n1)
                    flat_err, prop_err = abs(vN - v1), abs(vN - pred)
                    verdict = ("**paid once**, when the first syscalls:* tracepoint is "
                               "enabled — so hook count is not a budget, event rate is"
                               if flat_err < prop_err else
                               "**per hook** — so hook count is a budget to spend carefully")
                    extra = (" Reading: the step from %d to %d tracepoints is %+.0f points, "
                             "which clears the %.0f%% noise floor; each tracepoint after "
                             "that adds %+.1f points, which does not. If every hook cost "
                             "what the first %d did, %d would read %+.0f%% — measured "
                             "%+.0f%% (residual %.0f points, versus %.0f points for an "
                             "unchanging cost). The tax is therefore %s."
                             % (0, n1, 100 * step, 100 * floor, 100 * per_hook,
                                n1, nN, 100 * pred, 100 * vN,
                                100 * prop_err, 100 * flat_err, verdict))
            notes.append("**Cost per added syscall tracepoint (dd, which calls none of the "
                         "hooked syscalls):** " + listing + "." + extra)
        # The one comparison that IS clean here, whatever the ladder does:
        # count_net attaches 6 syscall tracepoints that fire zero times on
        # these workloads, so it isolates attachment from event handling.
        st_net = stats(d, "count_net")
        if st_net is not None and not st_net.get("records_per_s"):
            notes.append("**Attachment versus events:** count_net has 6 syscall "
                         "tracepoints attached and produced %s records/s on this "
                         "workload — nothing fired. Its cost is therefore the price of "
                         "ATTACHING hooks, with no record-keeping at all, which is the "
                         "cleanest tax probe in the table."
                         % int(st_net.get("records_per_s", 0)))
    notes.append("BCC tools print every event (to a file here), so their userspace cost is "
                 "not zero; compare them with our count_* configs for kernel-side cost.")
    lines += ["", "## Readings (automatic — check against the table)", ""]
    lines += ["- " + n for n in notes]
    text = "\n".join(lines) + "\n"
    with open(os.path.join(d, "overhead.md"), "w") as f:
        f.write(text)
    return text


if __name__ == "__main__":
    print(analyze(sys.argv[1]))
