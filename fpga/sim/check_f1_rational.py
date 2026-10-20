#!/usr/bin/env python3
"""check_f1_rational.py -- independent oracle for the F1 directed tests.

Re-derives every hand-computed boundary answer in tb/tb_f1_unit.v with exact
rationals in packets and seconds (fractions.Fraction), NOT the RTL's scaled
integers, on the same stimuli. Written by the reviewer, not the RTL author,
so a shared misreading of the fixed-point scheme cannot hide here.

Model: tokens in packets; a never-seen source is full (B); refill over a gap
of g cycles is g*R/CLK packets, capped at B; a packet conforms when at least
1 packet is available and then costs 1; a flagged packet costs nothing.

Usage: python3 fpga/sim/check_f1_rational.py   (~12 s, exits 1 on mismatch)
"""
import sys
from fractions import Fraction as Q

CLK, R = 100_000_000, 5000
BAD = []


def chk(name, got, want):
    ok = got == want
    print("%-4s %-40s got %-24r want %r" % ("PASS" if ok else "FAIL", name, got, want))
    if not ok:
        BAD.append(name)


class Bucket:
    def __init__(self, burst, tok=None, last=None):
        self.b, self.tok, self.last = burst, tok, last
        self.flags = self.conf = 0
        self.first = -1
        self.i = 0

    def step(self, t):
        if self.tok is None:
            avail = Q(self.b)
        else:
            avail = min(Q(self.b), self.tok + Q((t - self.last) * R, CLK))
        if avail >= 1:
            self.tok = avail - 1
            self.conf += 1
        else:
            self.tok = avail
            self.flags += 1
            if self.first < 0:
                self.first = self.i
        self.last = t
        self.i += 1


def run(b, ts, **kw):
    x = Bucket(b, **kw)
    for t in ts:
        x.step(t)
    return x


def even(n, minus=0):
    return [((k + 1) * CLK) // n - minus for k in range(n)]


def main():
    r = run(500, [k * 19000 for k in range(10001)])
    chk("over_rate_5263pps_first_flag", r.first, 9981)

    x, k = Bucket(500), 0
    while x.first < 0:
        x.step((k * CLK) // 5001)
        k += 1
    chk("5001pps_from_full_first_flag", x.first, 2495500)
    chk("5001pps_first_flag_time_cycles", (x.first * CLK) // 5001, 49900019996)  # 499.00019996 s

    chk("R+1_in_[0,1s)_full_flags", run(500, even(5001, 1)).flags, 0)
    r = run(500, even(5001), tok=Q(0), last=0)
    chk("R+1_empty_flags", r.flags, 1)
    chk("R+1_empty_first_flag", r.first, 0)
    chk("R+1_empty_one_cycle_earlier_flags", run(500, even(5001, 1), tok=Q(0), last=0).flags, 2)
    chk("R+B-1=5499_full_flags", run(500, even(5499)).flags, 0)
    r = run(500, even(5500))
    chk("R+B=5500_full_flags", r.flags, 1)
    chk("R+B=5500_full_first_flag", r.first, 5490)

    ts = [90_000_000 + k * 2000 for k in range(10000)]
    r = run(500, ts)
    chk("straddle_per_window_counts", [sum(t < CLK for t in ts), sum(t >= CLK for t in ts)],
        [5000, 5000])
    chk("straddle_first_flag", r.first, 555)
    chk("straddle_flags", r.flags, 8501)

    r = run(500, list(range(100000)))
    chk("back_to_back_conforms", r.conf, 504)
    chk("back_to_back_flags", r.flags, 99496)

    chk("B1_exact_R_flags", run(1, even(5000)).flags, 0)
    r = run(1, even(5001))
    chk("B1_R+1_full_flags", r.flags, 2500)
    chk("B1_R+1_full_first_flag", r.first, 1)
    chk("B1_R+1_empty_flags", run(1, even(5001), tok=Q(0), last=0).flags, 2501)

    print("RATIONAL ORACLE: %d mismatches" % len(BAD))
    return 1 if BAD else 0


if __name__ == "__main__":
    sys.exit(main())
