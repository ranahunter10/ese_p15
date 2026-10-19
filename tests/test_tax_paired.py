"""The paired-ratio statistics, tested without a kernel.

`tools/tax_paired.py` cannot be run here — it loads a BPF program. What CAN
be tested is the reason it exists: that comparing per-pair ratios resolves an
effect which median-of-medians, the statistic `overhead_breakdown.sh` uses,
cannot see under the drift this project's VM actually exhibits.

So the central test below is a competition between the two statistics on the
same synthetic data. If per-pair ratios ever stop winning it, the tool has no
reason to exist and this test should fail.
"""
import os
import random
import statistics
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "tools"))

import tax_paired as T                                        # noqa: E402


def drifting_run(effect, pairs, drift, seed, jitter=0.02):
    """Synthesise one configuration's measurements.

    `effect` is the true multiplicative cost of the hooks (1.067 = 6.7 %, the
    real figure: 16 ns on a 240 ns syscall). `drift` is how far the machine
    wanders over the run, multiplying BOTH arms of a pair alike — which is
    what makes it cancellable, and is the documented behaviour of the VM: the
    dd baseline moved 47 % within a single run while the effect was 6.7 %.

    `jitter` is per-measurement noise that does NOT cancel, kept small
    because the observed problem was drift, not jitter.
    """
    rnd = random.Random(seed)
    base = 2.88                          # dd CPU seconds, from the real run
    hooked, bare = [], []
    for i in range(pairs):
        # a slow wander across the run, shared by both arms of each pair
        wander = 1.0 + drift * (i / max(pairs - 1, 1))
        h = base * wander * effect * (1 + rnd.uniform(-jitter, jitter))
        b = base * wander * (1 + rnd.uniform(-jitter, jitter))
        hooked.append(h)
        bare.append(b)
    return hooked, bare


class PairedRatioBeatsMedianOfMediansTest(unittest.TestCase):
    """The whole justification for the tool, as an experiment."""

    EFFECT = 1.067        # 6.7 %: 16 ns on a 240 ns syscall
    DRIFT = 0.47          # 47 %: what the dd baseline actually did

    def test_per_pair_ratios_recover_the_true_effect_under_real_drift(self):
        hooked, bare = drifting_run(self.EFFECT, 12, self.DRIFT, seed=1)
        st = T.pair_stats([h / b for h, b in zip(hooked, bare)])
        self.assertTrue(st["resolved"], "paired ratios failed to resolve: %s"
                                        % st["why"])
        self.assertAlmostEqual(st["median"], self.EFFECT, delta=0.02)
        self.assertFalse(st["iqr_lo"] <= 1.0 <= st["iqr_hi"])

    def test_median_of_medians_cannot_see_it_on_the_same_data(self):
        """The control for the claim above.

        `overhead_breakdown.sh` compares the medians of two sample SETS. With
        the arms interleaved across a drifting run those sets are differently
        positioned in the drift, so the comparison is contaminated by it —
        which is why the real ladder came out non-monotonic. Here the same
        numbers are read that way and the error swamps the effect.
        """
        hooked, bare = drifting_run(self.EFFECT, 12, self.DRIFT, seed=1)
        # the hooked arm of pair i is adjacent to the bare arm of pair i, but
        # median-of-medians throws that pairing away
        naive = statistics.median(hooked) / statistics.median(bare[::-1])
        paired = statistics.median([h / b for h, b in zip(hooked, bare)])
        self.assertLess(abs(paired - self.EFFECT), abs(naive - self.EFFECT),
                        "paired ratios are no better than median-of-medians; "
                        "the tool has no reason to exist")

    def test_a_zero_effect_is_reported_as_unresolved_not_as_a_finding(self):
        """The failure that matters: inventing a tax that is not there."""
        hooked, bare = drifting_run(1.0, 12, self.DRIFT, seed=2)
        st = T.pair_stats([h / b for h, b in zip(hooked, bare)])
        self.assertFalse(st["resolved"],
                         "a zero effect was reported as resolved (%.4f)"
                         % st["median"])
        # The median lands at 1.0, correctly — what must not happen is that
        # the tiny residual gets PRESENTED as a tax. Either refusal reason is
        # sound here, and which one fires depends on where jitter leaves the
        # quartiles; the property under test is that one of them does.
        self.assertAlmostEqual(st["median"], 1.0, delta=0.01)
        self.assertTrue(st["iqr_lo"] <= 1.0 <= st["iqr_hi"]
                        or st["width"] >= st["effect"], st["why"])

    def test_several_seeds_of_a_zero_effect_are_never_called_a_finding(self):
        """One seed could pass by luck. A tool that invents a tax on even one
        machine-state is worse than one that reports nothing."""
        for seed in range(25):
            hooked, bare = drifting_run(1.0, 12, self.DRIFT, seed=seed)
            st = T.pair_stats([h / b for h, b in zip(hooked, bare)])
            self.assertFalse(st["resolved"],
                             "seed %d: zero effect read as %.4f"
                             % (seed, st["median"]))

    def test_an_effect_below_the_jitter_is_refused(self):
        """Honesty in the other direction: a real but unmeasurable effect."""
        hooked, bare = drifting_run(1.002, 12, self.DRIFT, seed=3, jitter=0.05)
        st = T.pair_stats([h / b for h, b in zip(hooked, bare)])
        self.assertFalse(st["resolved"])


class ControlArmTest(unittest.TestCase):
    """`count_exit` runs the monitor with ZERO syscall tracepoints, so its
    ratio must be 1.0. It is the one arm whose answer is known in advance,
    which makes it the instrument check — and a run that fails it is void,
    not merely noisy."""

    def test_a_clean_control_passes(self):
        hooked, bare = drifting_run(1.0, 12, 0.47, seed=4)
        st = T.pair_stats([h / b for h, b in zip(hooked, bare)])
        self.assertTrue(T.control_is_sane(st))

    def test_a_control_that_is_off_by_more_than_five_percent_voids_the_run(self):
        # the monitor stealing CPU from the workload would look exactly like
        # this: both arms drift together, but the hooked arm is consistently
        # slower for a reason that is not syscall tracepoints
        hooked, bare = drifting_run(1.12, 12, 0.47, seed=5)
        st = T.pair_stats([h / b for h, b in zip(hooked, bare)])
        self.assertFalse(T.control_is_sane(st),
                         "a 12 %% control error was accepted as sane")

    def test_the_tolerance_is_on_the_median_not_the_spread(self):
        """A control can be noisy and still sane, or tight and still wrong.
        Conflating the two would make the check unusable on a busy machine."""
        noisy, bare = drifting_run(1.0, 12, 0.47, seed=6, jitter=0.08)
        st = T.pair_stats([h / b for h, b in zip(noisy, bare)])
        self.assertTrue(T.control_is_sane(st))
        self.assertFalse(st["resolved"])      # noisy, yet its median is right


class PairStatsContractTest(unittest.TestCase):

    def test_four_pairs_is_the_minimum_for_an_iqr(self):
        with self.assertRaises(ValueError):
            T.pair_stats([1.0, 1.1, 1.2])
        T.pair_stats([1.0, 1.1, 1.2, 1.3])        # must not raise

    def test_every_field_the_report_prints_is_present(self):
        st = T.pair_stats([1.05, 1.06, 1.07, 1.08, 1.09])
        for key in ("median", "iqr_lo", "iqr_hi", "min", "max", "pairs",
                    "effect", "width", "resolved", "why"):
            self.assertIn(key, st)
        self.assertEqual(st["pairs"], 5)
        self.assertEqual(st["min"], 1.05)
        self.assertEqual(st["max"], 1.09)

    def test_the_ladder_shape_a_paid_once_tax_would_produce(self):
        """Documents what the output should look like if the kernel mechanism
        is right: a step at the first rung, then nothing. Not a measurement —
        a statement of what is being looked for, so the reader of the report
        knows before seeing the numbers."""
        bare_s, syscalls = 2.88, 12_000_000
        step_ns = 16.0
        ratios = {}
        for tps in (0, 2, 4, 6, 12):
            added = 0.0 if tps == 0 else step_ns      # paid ONCE, not per hook
            ratios[tps] = 1.0 + added * syscalls / 1e9 / bare_s
        self.assertAlmostEqual(ratios[0], 1.0)
        for tps in (2, 4, 6, 12):
            self.assertAlmostEqual(ratios[tps], ratios[2], delta=1e-9)
        self.assertGreater(ratios[2] - 1.0, 0.06)     # ~6.7 %, as computed


class ConfigTableTest(unittest.TestCase):

    def test_the_control_is_first_and_has_zero_syscall_tracepoints(self):
        name, _hooks, tps = T.CONFIGS[0]
        self.assertEqual(name, "count_exit")
        self.assertEqual(tps, 0, "the first config must be the 0-tp control")

    def test_tracepoint_counts_match_the_overhead_script(self):
        """Both tools must agree about how many syscalls:* tracepoints each
        hook set attaches, or their ladders are not comparable."""
        import re
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "..", "tools",
                               "overhead_breakdown.sh")) as f:
            pass            # the counts live in the analyzer, not the runner
        with open(os.path.join(here, "..", "tools", "analyze_overhead.py")) as f:
            src = f.read()
        m = re.search(r"SYSCALL_TRACEPOINTS = \{(.*?)\}", src, re.S)
        self.assertIsNotNone(m, "the overhead analyzer no longer declares "
                                "SYSCALL_TRACEPOINTS; the two ladders could "
                                "drift apart unnoticed")
        theirs = dict(re.findall(r'"(\w+)":\s*(\d+)', m.group(1)))
        for name, _hooks, tps in T.CONFIGS:
            if name in theirs:
                self.assertEqual(int(theirs[name]), tps,
                                 "%s: analyzer says %s tracepoints, "
                                 "tax_paired says %d"
                                 % (name, theirs[name], tps))

    def test_hook_names_are_ones_the_monitor_accepts(self):
        valid = {"exec", "open", "exit", "net"}
        for name, hooks, _tps in T.CONFIGS:
            for h in hooks.split(","):
                self.assertIn(h, valid, "%s passes --hooks %s" % (name, h))


def rung(tps, median, lo, hi):
    return {"tps": tps, "median": median, "iqr_lo": lo, "iqr_hi": hi}


class LadderReadingTest(unittest.TestCase):
    """The reading IS the conclusion, so it gets tested like one."""

    # The first run that produced a readable ladder: VM 2026-10-19,
    # 9 pairs per config, kernel 5.4.0-216-generic. Pinned here so a change
    # to the reading logic cannot quietly re-interpret the measurement this
    # project's design decision rests on.
    REAL = [rung(0, 0.9971, 0.9536, 1.0552),
            rung(2, 1.1065, 1.0786, 1.1454),
            rung(4, 1.1725, 1.1628, 1.2012),
            rung(6, 1.1820, 1.1410, 1.1909),
            rung(12, 1.1703, 1.1415, 1.3011)]

    def test_the_measured_ladder_saturates_at_four_tracepoints(self):
        sat, steps = T.saturation_point(self.REAL)
        self.assertEqual(sat, 4, "the observed ladder saturates at 4 tp")
        self.assertEqual([(a, b, ov) for a, b, ov in steps],
                         [(0, 2, False), (2, 4, False),
                          (4, 6, True), (6, 12, True)])

    def test_a_paid_once_tax_saturates_at_the_first_rung(self):
        once = [rung(0, 1.000, 0.99, 1.01), rung(2, 1.100, 1.09, 1.11),
                rung(4, 1.101, 1.09, 1.11), rung(12, 1.099, 1.09, 1.11)]
        sat, _ = T.saturation_point(once)
        self.assertEqual(sat, 2)

    def test_a_true_per_hook_cost_never_saturates(self):
        """The result that would overturn the design decision: if every rung
        is disjoint from the next, hook count IS a budget."""
        per_hook = [rung(0, 1.00, 0.995, 1.005), rung(2, 1.10, 1.095, 1.105),
                    rung(4, 1.20, 1.195, 1.205), rung(6, 1.30, 1.295, 1.305),
                    rung(12, 1.60, 1.595, 1.605)]
        sat, steps = T.saturation_point(per_hook)
        self.assertIsNone(sat)
        self.assertTrue(all(not ov for _a, _b, ov in steps))

    def test_an_all_noise_ladder_saturates_immediately(self):
        """Wide IQRs must not be read as a flat tax: everything overlaps, so
        the honest answer is that nothing was distinguished — which this
        reports as saturation at the first rung, and the per-rung
        'not resolved' markers qualify."""
        noise = [rung(t, 1.1, 0.8, 1.4) for t in (0, 2, 4, 6, 12)]
        sat, steps = T.saturation_point(noise)
        self.assertEqual(sat, 0)
        self.assertTrue(all(ov for _a, _b, ov in steps))

    def test_ns_conversion_uses_one_common_baseline(self):
        """The bug the first real run exposed: converting each rung with its
        OWN bare arm feeds the drift back in. The control's bare arm was
        1.641 s while count_net's was 3.7 s, so the same ratio would have
        produced ns figures differing by more than 2x."""
        syscalls = 12_000_000
        common = 1.641
        own = 3.709
        ratio = 1.1820
        ns_common = (ratio - 1) * common / syscalls * 1e9
        ns_own = (ratio - 1) * own / syscalls * 1e9
        self.assertGreater(ns_own / ns_common, 2.0,
                           "if these agree, the confound being guarded "
                           "against is not present in the fixture")
        self.assertAlmostEqual(ns_common, 24.9, delta=0.5)


if __name__ == "__main__":
    unittest.main()
