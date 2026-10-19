"""Tests for the G3 ladder's reading logic.

The ladder itself needs root and a live kernel. Its *verdicts* are what decide
whether a run is readable at all, and they are pure functions of the rungs --
so they can be tested exactly, which matters because both of them exist to
stop a number being quoted.

The failure this guards against is specific and has happened on this project
twice: the tax measurement came out non-monotonic and the analyzer correctly
refused to read it. The same shape applies here -- past some worker count the
generator saturates CPU and the rate FALLS, and loss from those rungs would
be blamed on the ring buffer instead of on contention.
"""

import importlib.util
import os
import sys
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)

_spec = importlib.util.spec_from_file_location(
    "loss_ladder", os.path.join(ROOT, "tools", "loss_ladder.py"))
ll = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ll)


def rung(workers, received, lost, duration=20.0, cpu=30.0):
    total = received + lost
    return {"workers": workers, "records_received": received, "lost": lost,
            "duration_s": duration,
            "loss_rate": (lost / float(total)) if total else 0.0,
            "monitor_cpu_percent_of_one_core": cpu}


# The VM ladder of 2026-10-19, pinned verbatim. The first version of this
# tool read it as "MONOTONIC, the generator was still the limit" and
# bracketed the knee at 9436-10190 rec/s. Both were wrong: the offered rate
# stalled at K=4, and the drained rate at K=8 is the consumer's ceiling, not
# the load. Keeping the real numbers here means the reading logic cannot
# silently revert to that interpretation.
VM_LADDER = [
    rung(1, 34782, 0, 20.07, 15.2),
    rung(2, 173848, 0, 20.06, 42.4),
    rung(4, 189892, 0, 20.12, 34.0),
    rung(8, 205109, 190410, 20.13, 19.5),
]


class RateTest(unittest.TestCase):
    def test_rate_is_records_over_duration(self):
        self.assertAlmostEqual(ll.rate_of(rung(1, 2000, 0, 20.0)), 100.0)

    def test_a_zero_duration_does_not_divide_by_zero(self):
        self.assertEqual(ll.rate_of(rung(1, 10, 0, 0)), 0.0)


class ControlGuardTest(unittest.TestCase):
    """K=1 losing records means the machine or build is wrong, not that a
    ceiling was found -- and then no higher rung can be interpreted."""

    def test_a_clean_lowest_rung_passes(self):
        msgs, void = ll.verdicts([rung(1, 2000, 0), rung(2, 4000, 0)])
        self.assertFalse(void)
        self.assertTrue(any("CONTROL OK" in m for m in msgs))

    def test_loss_at_the_lowest_rung_voids_the_run(self):
        msgs, void = ll.verdicts([rung(1, 2000, 50), rung(2, 4000, 400)])
        self.assertTrue(void)
        self.assertTrue(any("CONTROL FAILED" in m for m in msgs))

    def test_the_control_message_names_the_rate_it_failed_at(self):
        msgs, _ = ll.verdicts([rung(1, 2000, 50), rung(2, 4000, 400)])
        self.assertTrue(any("100 rec/s" in m for m in msgs))


class RateDefinitionTest(unittest.TestCase):
    """Drained and offered are different numbers, and conflating them is how
    a consumer's ceiling gets quoted as an event rate."""

    def test_they_agree_when_nothing_is_lost(self):
        r = rung(1, 2000, 0, 20.0)
        self.assertAlmostEqual(ll.rate_of(r), ll.offered_of(r))

    def test_offered_includes_what_the_kernel_overwrote(self):
        r = rung(8, 2000, 2000, 20.0)
        self.assertAlmostEqual(ll.rate_of(r), 100.0)
        self.assertAlmostEqual(ll.offered_of(r), 200.0)

    def test_on_the_vm_ladder_they_diverge_only_at_the_lossy_rung(self):
        for s in VM_LADDER[:-1]:
            self.assertAlmostEqual(ll.rate_of(s), ll.offered_of(s))
        last = VM_LADDER[-1]
        self.assertLess(ll.rate_of(last), ll.offered_of(last) * 0.6)


class MonotonicityGuardTest(unittest.TestCase):
    """If the offered rate stops rising, extra workers are fighting for CPU
    and those rungs measure contention rather than capture."""

    def test_a_materially_rising_ladder_is_reported_monotonic(self):
        msgs, void = ll.verdicts([rung(1, 2000, 0), rung(2, 4000, 0),
                                  rung(4, 8000, 0)])
        self.assertFalse(void)
        self.assertTrue(any("MONOTONIC" in m for m in msgs))

    def test_a_ladder_that_peaks_early_says_so_and_names_the_rung(self):
        msgs, void = ll.verdicts([rung(1, 2000, 0), rung(2, 9000, 0),
                                  rung(4, 5000, 100), rung(8, 4000, 900)])
        # Not void -- the control still passed, and the early rungs are
        # readable. But the later ones must not be read as a capture ceiling.
        self.assertFalse(void)
        peaked = [m for m in msgs if "PEAKED" in m]
        self.assertEqual(len(peaked), 1)
        self.assertIn("K=2", peaked[0])
        self.assertIn("contention", peaked[0])

    def test_a_nine_percent_rise_is_not_monotonic(self):
        # The VM's K=2 -> K=4 step. "It rose at every rung" was technically
        # true and substantively false: +9 % after a +400 % step means the
        # generator had stopped being the limit.
        msgs, _ = ll.verdicts(VM_LADDER)
        self.assertFalse(any("MONOTONIC" in m for m in msgs))
        stalled = [m for m in msgs if "DID NOT RISE MATERIALLY" in m]
        self.assertEqual(len(stalled), 1)
        self.assertIn("K=2->4", stalled[0])

    def test_the_stall_message_names_transitions_not_a_range(self):
        # A ladder can stall once and then climb again (the VM did: +400 %,
        # +9 %, +108 %), so "plateaued from K=4 onward" would be false.
        msgs, _ = ll.verdicts(VM_LADDER)
        stalled = [m for m in msgs if "DID NOT RISE MATERIALLY" in m][0]
        self.assertNotIn("onward", stalled)

    def test_a_flat_ladder_counts_as_stalled_not_monotonic(self):
        msgs, _ = ll.verdicts([rung(1, 4000, 0), rung(2, 4000, 0)])
        self.assertFalse(any("MONOTONIC" in m for m in msgs))

    def test_a_single_rung_ladder_is_trivially_monotonic(self):
        msgs, void = ll.verdicts([rung(1, 2000, 0)])
        self.assertFalse(void)
        self.assertTrue(any("MONOTONIC" in m for m in msgs))


class GainExceedsParallelismTest(unittest.TestCase):
    """Doubling workers cannot more than roughly double the rate, and on a
    2-vCPU box not even that. A larger gain means something other than the
    worker count changed between rungs.

    On 2026-10-19 two ladders run back to back differed by 3.52x at K=1 for
    an identical workload, because the first started on a cold page cache and
    warmed it as it climbed. Its K=1 -> K=2 "+400 % gain" was the cache, not
    parallelism -- and it made every low rung uncomparable to the second run.
    """

    def test_the_cold_vm_ladder_is_flagged(self):
        msgs, _ = ll.verdicts(VM_LADDER)
        flagged = [m for m in msgs if "GAIN EXCEEDS PARALLELISM" in m]
        self.assertEqual(len(flagged), 1)
        self.assertIn("K=1->2", flagged[0])
        self.assertIn("5.00x", flagged[0])
        self.assertIn("--warmup", flagged[0])

    def test_the_warm_ladder_is_not_flagged(self):
        # The p256 run, which followed the cold one and so started warm:
        # K=1 -> K=2 gained only 1.44x, well inside what 2 workers explain.
        warm = [rung(1, 122337, 0, 20.06, 28.4),
                rung(2, 176126, 0, 20.08, 42.6),
                rung(4, 195051, 0, 20.11, 34.5),
                rung(8, 226118, 0, 20.14, 19.7)]
        msgs, _ = ll.verdicts(warm)
        self.assertFalse(any("GAIN EXCEEDS PARALLELISM" in m for m in msgs))

    def test_a_doubling_gain_from_a_doubling_of_workers_is_fine(self):
        msgs, _ = ll.verdicts([rung(1, 2000, 0), rung(2, 4000, 0)])
        self.assertFalse(any("GAIN EXCEEDS PARALLELISM" in m for m in msgs))

    def test_it_reports_only_the_first_offending_rung(self):
        # One message, not one per rung: the first is the diagnosis and the
        # rest are its consequence.
        msgs, _ = ll.verdicts([rung(1, 1000, 0), rung(2, 9000, 0),
                               rung(4, 90000, 0)])
        self.assertEqual(
            sum(1 for m in msgs if "GAIN EXCEEDS PARALLELISM" in m), 1)


# The two warm, matched-load ladders of 2026-10-19 that settled the --pages
# question. Loss first appears at K=12 in BOTH, and the drain ceiling is
# 9,395/s at 64 pages against 8,892/s at 256 -- four times the ring bought
# nothing. Pinned so the conclusion cannot be quietly re-derived the other way.
WARM_P64 = [
    rung(8, 188830, 0, 20.1, 19.6),
    rung(12, 188308, 259982, 20.1, 14.0),
    rung(16, 121767, 912141, 20.1, 10.3),
    rung(24, 86174, 1406752, 20.1, 6.8),
]
WARM_P256 = [
    rung(8, 165318, 0, 20.1, 19.2),
    rung(12, 178727, 81574, 20.1, 14.1),
    rung(16, 135143, 708462, 20.1, 10.8),
    rung(24, 111583, 975367, 20.1, 8.0),
]


class ThePagesQuestionTest(unittest.TestCase):
    """The pre-registered criterion was: knee does not move -> the binding
    constraint is the userspace drain rate, not ring capacity. It did not
    move. These assertions hold the data to that reading."""

    def test_loss_begins_at_the_same_rung_in_both_configurations(self):
        first_lossy = lambda lad: next(s["workers"] for s in lad if s["lost"])
        self.assertEqual(first_lossy(WARM_P64), 12)
        self.assertEqual(first_lossy(WARM_P256), 12)

    def test_four_times_the_ring_did_not_raise_the_drain_ceiling(self):
        c64 = max(ll.rate_of(s) for s in WARM_P64)
        c256 = max(ll.rate_of(s) for s in WARM_P256)
        self.assertGreater(c64, c256)          # 9,395 vs 8,892
        # And the gap is small enough that with one run each it is not an
        # improvement either way -- the claim is "no gain", not "64 is better".
        self.assertLess(abs(c64 - c256) / c64, 0.10)


class DrainDegradationTest(unittest.TestCase):
    """A consumer at its capacity holds steady. One that gets SLOWER as load
    rises is losing a scheduler race, and its coverage drops exactly when the
    machine is busiest -- reachable by anyone who can generate syscall load."""

    def test_the_warm_ladders_are_flagged(self):
        for lad in (WARM_P64, WARM_P256):
            msgs, _ = ll.verdicts(lad)
            flagged = [m for m in msgs if "DRAIN RATE DEGRADES" in m]
            self.assertEqual(len(flagged), 1)
            self.assertIn("scheduling priority", flagged[0])

    def test_it_reports_the_peak_and_the_collapse(self):
        msgs, _ = ll.verdicts(WARM_P64)
        m = [x for x in msgs if "DRAIN RATE DEGRADES" in x][0]
        self.assertIn("9395", m.replace(",", ""))
        self.assertIn("46 %", m)

    def test_a_steady_consumer_is_not_flagged(self):
        # Holding its rate while loss climbs IS running out of capacity, and
        # must not be reported as degradation.
        steady = [rung(8, 200000, 0, 20.0, 50.0),
                  rung(12, 199000, 100000, 20.0, 52.0),
                  rung(16, 198000, 400000, 20.0, 54.0)]
        msgs, _ = ll.verdicts(steady)
        self.assertFalse(any("DRAIN RATE DEGRADES" in m for m in msgs))


class OverflowFeedbackAttributionTest(unittest.TestCase):
    """A superlinear offered-rate gain has two possible causes, and naming
    the wrong one sends the reader to the wrong fix. The first version blamed
    the page cache unconditionally and then told a user who had already
    passed --warmup to rerun with --warmup."""

    def test_a_gain_alongside_rising_loss_is_called_overflow_feedback(self):
        msgs, _ = ll.verdicts(WARM_P64)
        m = [x for x in msgs if "GAIN EXCEEDS PARALLELISM" in x]
        self.assertEqual(len(m), 1)
        self.assertIn("overflow feedback loop", m[0])
        self.assertNotIn("Rerun with --warmup", m[0])

    def test_a_gain_with_no_loss_change_is_still_blamed_on_the_cache(self):
        msgs, _ = ll.verdicts(VM_LADDER[:3])     # cold, all rungs clean
        m = [x for x in msgs if "GAIN EXCEEDS PARALLELISM" in x]
        self.assertEqual(len(m), 1)
        self.assertIn("page cache", m[0])
        self.assertIn("--warmup", m[0])

    def test_the_overflow_message_warns_against_comparing_at_matched_k(self):
        msgs, _ = ll.verdicts(WARM_P256)
        m = [x for x in msgs if "GAIN EXCEEDS PARALLELISM" in x][0]
        self.assertIn("same K", m)


class StarvationAttributionTest(unittest.TestCase):
    """Loss because the consumer was descheduled is a different defect from
    loss because the ring was too small for the rate. Getting the attribution
    backwards would send the next change to --pages instead of to ingest."""

    def test_less_cpu_at_the_lossy_rung_is_called_starvation(self):
        msgs, _ = ll.verdicts(VM_LADDER)
        starved = [m for m in msgs if "STARVATION" in m]
        self.assertEqual(len(starved), 1)
        self.assertIn("19.5", starved[0])      # CPU at the lossy rung
        self.assertIn("42.4", starved[0])      # CPU at the best clean rung
        # Names BOTH discriminators. It used to prescribe "--pages 256",
        # which went stale the moment that experiment was run and answered;
        # the message now states the two hypotheses and how to tell them
        # apart instead of assuming which one is still open.
        self.assertIn("--pages", starved[0])
        self.assertIn("scheduling priority", starved[0])

    def test_more_cpu_at_the_lossy_rung_is_not_called_starvation(self):
        # Monitor working harder than ever and still losing: that IS being
        # outpaced, and must not be reported as contention.
        msgs, _ = ll.verdicts([rung(1, 2000, 0, 20.0, 20.0),
                               rung(2, 4000, 0, 20.0, 40.0),
                               rung(4, 9000, 5000, 20.0, 95.0)])
        self.assertFalse(any("STARVATION" in m for m in msgs))

    def test_no_starvation_verdict_when_nothing_was_lost(self):
        msgs, _ = ll.verdicts([rung(1, 2000, 0, 20.0, 15.0),
                               rung(2, 4000, 0, 20.0, 40.0)])
        self.assertFalse(any("STARVATION" in m for m in msgs))


class BothGuardsTest(unittest.TestCase):
    def test_a_void_control_and_a_peak_both_report(self):
        # The two guards are independent: a run can fail the control AND
        # have peaked, and the reader needs to be told both.
        msgs, void = ll.verdicts([rung(1, 2000, 10), rung(2, 9000, 0),
                                  rung(4, 3000, 500)])
        self.assertTrue(void)
        self.assertTrue(any("CONTROL FAILED" in m for m in msgs))
        self.assertTrue(any("RATE PEAKED" in m for m in msgs))

    def test_the_two_unconditional_guards_always_report(self):
        # Control and rate-shape fire on every ladder -- a silent guard is one
        # nobody notices has stopped firing. The starvation guard is the
        # exception: it needs both a lossy and a clean rung to compare, so it
        # is conditional by construction and the count is 2 or 3, never fewer.
        for ladder in ([rung(1, 1, 0)],
                       [rung(1, 2000, 0), rung(2, 4000, 0)],
                       [rung(1, 2000, 9), rung(2, 10, 9)],
                       VM_LADDER):
            msgs, _ = ll.verdicts(ladder)
            self.assertIn(len(msgs), (2, 3, 4), "ladder %r gave %d verdicts"
                          % ([s["workers"] for s in ladder], len(msgs)))
            self.assertEqual(
                sum(1 for m in msgs if m.startswith("CONTROL")), 1)
            self.assertEqual(
                sum(1 for m in msgs
                    if "OFFERED RATE" in m or "PEAKED" in m), 1)

    def test_the_vm_ladder_gets_all_four(self):
        # Control, rate shape, cold-cache gain, starvation attribution: that
        # cold lossy ladder trips every conditional guard there is.
        msgs, _ = ll.verdicts(VM_LADDER)
        self.assertEqual(len(msgs), 4)


if __name__ == "__main__":
    unittest.main()
