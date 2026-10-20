# F1 — per-source token bucket: notes

Stage F1 of the FPGA thread (Layer 4). Status: **simulated in Icarus Verilog
12 only.** Not run in Vivado xsim, not synthesized, no timing. Everything
below about the hardware is design intent and arithmetic, not a measurement.

Gate: `sh fpga/sim/run_f1.sh` → `SUMMARY: 185 passed, 0 failed`.
Mutation check: `python3 fpga/sim/mutate_f1.py` (details in `tb/MUTANTS_F1.md`).

## Files

| File | What |
|---|---|
| `rtl/token_bucket_update.v` | stateless combinational step: (stored state, `now`, `pkt`) → (new state, `conform`, `flag`). F3 reuses it unchanged with a BRAM. |
| `rtl/token_bucket.v` | single-source wrapper: state registers + free-running `TS_W`-bit counter, 1-cycle registered decision. |
| `rtl/f1_clog2.vh` | `f1_bits()` constant function, included inside each module. |
| `tb/tb_f1.v` | gate top: 6 harness instances in sequence, one SUMMARY line, `$fatal` on failure. |
| `tb/tb_f1_unit.v` | update-unit harness: drives exact timestamps (no need to clock 10^8 cycles per second), directed + random tests. |
| `tb/tb_f1_wrap.v` | clocked wrapper harness: reset, counter, latency, write-back, wrap, random every-cycle compare. |
| `tb/f1_ref_model.vh` | **reference model, testbench only**: 64/128-bit integers, no derived widths, no clamp-before-multiply. |
| `sim/run_f1.sh` | compile + run from any cwd; `--vcd`, `--seed N`; exit 0 only on `0 failed`. |
| `sim/mutate_f1.py` | applies each mutant to a **copy** of `fpga/` and reports killing tests (never writes the tree). |

## Parameters and the representation

Parameters (all overridable): `CLK_HZ` (default 100,000,000), `RATE_PPS` = R
(default 5,000, the advisor's figure), `BURST` = B (default 500, **OPEN**),
`TS_W` (default 48).

Tokens are counted in units of 1/CLK_HZ of a packet:

- one packet costs `COST = CLK_HZ`
- capacity `CAP = B × CLK_HZ`
- refill per clock cycle `= R`, so refill over `e` cycles `= e × R`

`e × R` is the exact real refill `(e / CLK_HZ) s × R pkt/s` multiplied by
CLK_HZ. **The token arithmetic has no rounding error.** The only
quantisation in the design is time: a packet is timestamped to the clock
cycle it is presented in (10 ns at 100 MHz). Over one packet period at R
(20,000 cycles) that is 1/20,000 = 5×10⁻⁵ of the period, and it does not
accumulate: the bucket sees exactly the cycle timestamps it is given.

The only multiply is `el_sat × R`. `elapsed` is first clamped to
`T_FULL = ceil(CAP / R)` (the cycles needed to refill an empty bucket), so
the product is at most `T_FULL × R < CAP + R`. It can never overflow,
whatever the idle gap, and any gap ≥ `T_FULL` gives a full bucket. Clamping
before the multiply is exact: once `elapsed ≥ T_FULL` the bucket is full
whatever the stored tokens were. Then `min(CAP, tokens + refill)`.

### Widths at the defaults (each one is computed in the RTL by `f1_bits`)

| Quantity | Value | Bits | Why |
|---|---|---|---|
| CAP = B·CLK_HZ | 5×10¹⁰ | **TOK_W = 36** | 2³⁵ = 3.44×10¹⁰ < 5×10¹⁰ < 6.87×10¹⁰ = 2³⁶ |
| T_FULL = ceil(CAP/R) | 10,000,000 cycles (0.1 s) | **EL_W = 24** | 2²⁴ = 1.68×10⁷ |
| R | 5,000 | **R_W = 13** | 2¹³ = 8192 |
| product el_sat·R | ≤ 5×10¹⁰ | **PROD_W = 37** | full EL_W + R_W product, nothing truncated |
| tokens + refill | ≤ 10¹¹ | **SUM_W = 38** | max(36, 37) + 1 |
| timestamp | — | **TS_W = 48** | see wrap below |

The multiplier is 24 × 13 unsigned, which fits one DSP48E1 (25 × 18). That is
an estimate; it has not been synthesized.

Parameter checks at elaboration: R ≥ 1, B ≥ 1, R ≤ CLK_HZ, CAP < 2⁶²,
1 ≤ TS_W ≤ 64, EL_W ≤ TS_W. A violation instantiates an undefined module, so
elaboration fails (a portable Verilog-2001 static assert, checked with
`BURST=0`).

## Latency

- `token_bucket_update`: **0 cycles** (combinational), O(1) work per packet
  with no iteration.
- `token_bucket`: `pkt_in` is sampled at rising edge k with timestamp =
  the counter value in cycle k. `dec_valid`/`conform`/`flag` are registered
  at that edge, so the decision is visible **1 cycle** after `pkt_in`.
  Throughput is 1 packet per cycle (tested back-to-back).
- Unpipelined critical path: 48-bit subtract → compare → 24×13 multiply →
  38-bit add → compare → 36-bit compare → 36-bit subtract. **Whether this
  closes at 100 MHz on Artix-7 is not known** until synthesis. If it does
  not, adding one register after the multiply gives 2 cycles. In F3 the
  BRAM read adds 1–2 cycles, and same-source back-to-back packets will
  need a forwarding path. That is F3's problem.

## Counter wrap

`elapsed = (now − last) mod 2^TS_W`. With TS_W = 48 at 100 MHz:

- wrap period = 2⁴⁸ cycles = 2,814,749.8 s = **32.58 days**
- **max exactly-handled idle gap = 2⁴⁸ − 1 cycles (32.58 days)**. Tested:
  `idle_gap_max_2powTS_minus_1_is_full`, and a gap across the wrap
  (`wrap_elapsed_exact_across_wrap`, plus an exact-R stream across the
  wrap).
- beyond that, the unit sees `G mod 2⁴⁸`. If that residue is ≥ T_FULL
  (0.1 s), the result is still exact (a full bucket). This holds for all
  but a 3.6×10⁻⁸ fraction of long gaps and is tested in
  `wrap_alias_residue_ge_T_FULL_still_full`. If the residue is < T_FULL,
  the source is refilled **less** than it should be.
- **Error direction:** aliasing never grants more tokens than the true
  bucket, so it never lets extra traffic through. It **can**, however, make
  a quiet source look like a flood: a source that was nearly empty, went
  quiet for k × 32.58 days (± < 0.1 s), then sends will have its first
  packets flagged. This is pinned by
  `wrap_alias_gap_2powTS_plus_100_DOCUMENTED_flag` (unit) and
  `alias_idle_2powTS_plus_1_DOCUMENTED_2_conforms_not_3` (wrapper, TS_W=12).
  It is a documented limitation, not hidden. The fix belongs to F3: refresh
  each entry (a `pkt=0` call, which the unit already supports) at least once
  per wrap period, or age out the valid bit. With a scrubber, TS_W could
  shrink (32 bits = 42.9 s wrap) to save BRAM: **OPEN for F3**.

## Decisions taken in F1 (changeable, each covered by a test)

1. **Never-seen source = full bucket** (`st_valid = 0` ignores the stored
   word). Reset puts the wrapper's source back to never-seen. Tests:
   `init_never_seen_*`, `reset_*`, mutants M9/M10/M12.
2. **A non-conforming packet consumes no tokens** (standard policer).
   `flag_consumes_nothing`, `after_flag_one_cycle_refill_conforms`, M3.
3. Conform iff tokens ≥ one packet (`>=`). `tokens_eq_COST_conforms`, M4.
4. **Single port:** at most one packet per source per cycle. The wrapper
   has one `pkt_in` bit, so two packets in one cycle cannot be presented.
   The caller (F3's parser/arbiter) must serialise them.
5. F1 only **flags**. Flag-only vs auto-drop (O9) is not decided here.
6. `pkt = 0` is a "refresh" call: it brings the state up to `now`, consumes
   nothing and decides nothing (for an F3 scrubber).

## Decisions left OPEN for the user

- **O6: token bucket itself.** Proposed, not formally approved.
- **B.** Default 500 = 100 ms at R. This is a parameter, and it changes the
  answers below.
- R = 5,000 pps is the advisor's figure, used as given.
- TS_W for F3 (48 bits per BRAM entry vs a scrubber and fewer bits).

## SPEC FINDING for the interface doc (O6): "5,000 vs 5,001 packets in one second"

The plan's test "R packets in 1 s pass, R+1 flag" is **fixed-window
thinking and is false for a token bucket that starts full.** At R = 5,000,
B = 500, all of these are tested and exact:

| Stimulus | Token bucket | 1-s fixed window (reference model) |
|---|---|---|
| 5,001 packets evenly inside [0, 1 s), bucket **full** | **0 flags** | 1 flag |
| same 5,001 in (0, 1 s], bucket **empty** at t=0 | **exactly 1 flag** (the first packet) | — |
| same, shifted 1 cycle earlier, bucket empty | 2 flags (boundary exact to the cycle) | — |
| N evenly in (0, 1 s], full: N = 5,499 = R+B−1 | 0 flags | — |
| N = 5,500 = R+B | 1 flag, at packet index 5,490 | — |
| sustained 5,001 pps from full | first flag at packet **2,495,500** (t = 499.0002 s) | — |
| B = 1, 5,001 evenly in 1 s from full | **2,500 flags** (every other packet), not 1 | — |

So the correct statement for the interface doc is:

> A source sending at ≤ R pps sustained is never flagged. A source sending
> at r > R pps sustained, starting from a full bucket, is first flagged at
> packet `k* = floor((CAP − COST) / D) + 1`, where `D = COST − P·R` is the
> per-packet loss at period P cycles. That is after about
> (B − 1)·r/(r − R) packets. A burst of up to B packets at line rate after
> idle is always accepted. "5,000 vs 5,001 in one second" separates only
> from an **empty** bucket, i.e. a source that has already used its burst
> allowance.

What this means for the advisor's "flags a flood once a source exceeds
~5,000 pps": the bucket enforces 5,000 pps as a long-run rate with a
B-packet tolerance. Detection delay for a flood at rate r is about
(B − 1)/(r − R) seconds, e.g. 10 kpps → 0.1 s, 5,100 pps → 5 s,
5,001 pps → 499 s. If a 1-second-exact count is what the advisor wants,
that is a different algorithm (a sliding window), not a parameter choice.
**The user should raise this with the advisor (O6).**

### Test #4 (straddle) is now meaningful

10,000 packets at 50 kpps from t = 0.9 s to 1.1 s: exactly 5,000 in [0, 1 s)
and 5,000 in [1 s, 2 s). The fixed-window model on the **same stimulus**
sees at most R per window and flags **0**. The bucket flags 8,501 of
10,000, the first at index **555** (= floor(4.99×10¹⁰ / 9×10⁷) + 1).

## Derivations behind the directed tests (defaults unless noted)

- **Exact R from full**, period P = 20,000: before each packet,
  (CAP − COST) + P·R = CAP, so tokens return to exactly CAP − COST every
  packet. 50,000 packets (10 s): 0 flags, tokens 49,900,000,000.
- **Exact R from EMPTY** (zero slack, the strongest drift test), and for a
  non-integer period (U3: 125 MHz / 3,000 pps, P = 41,666.67) with
  t_k = ceil(k·CLK_HZ/R): before packet k, tokens = ceil(k·C/R)·R − (k−1)·C
  ≥ C, so every packet conforms. Tokens also stay < C + R ≤ 2C ≤ CAP for
  B ≥ 2, so the cap never interferes. 0 flags over 30,000 packets in every
  parameter set, plus a run across the counter wrap.
- **Over rate**, P = 19,000 (5,263 pps): D = 10⁸ − 19,000·5,000 = 5×10⁶;
  k* = floor(4.99×10¹⁰ / 5×10⁶) + 1 = **9,981**. The next packet conforms
  (the flag consumed nothing).
- **5,001 pps**, t_k = floor(k·10⁸/5001): the real-valued model gives
  k* = 5001·(B−1) + 1 = 2,495,500. At k* − 1 the timestamp is exact and
  tokens are exactly one packet. For smaller k the margin (≥ C/5001 ≈
  19,996 units) exceeds the floor loss (< R = 5,000 units), so no earlier
  flag. The reference model agrees.
- **Back-to-back every cycle**, 100,000 packets from full: conforms =
  B + floor(99,999·R/C) = 500 + 4 = **504**.
- **B+1 burst** (generic, any set with B·R < C): B conform, the (B+1)th
  flags, both from never-seen and after idling ≥ T_FULL.

## Test structure

185 named checks across 6 harness instances (parameter sweep):

| Inst | CLK_HZ | R | B | TS_W | Content |
|---|---|---|---|---|---|
| U1 | 100 M | 5000 | 500 | 48 | generic + full directed suite + random |
| U2 | 100 M | 5000 | 1 | 48 | generic + B=1 behaviour + random |
| U3 | 125 M | 3000 | 37 | 40 | generic (non-integer period) + random |
| U4 | 1 k | 100 | 3 | 12 | generic + random (aliases often: wraps every 4.1 s) |
| W1 | 1 k | 100 | 3 | 12 | clocked: reset, latency, b2b, wrap, alias, 200k-cycle random |
| W2 | 100 M | 5000 | 500 | 48 | clocked at full-scale widths: wiring, b2b, refill |

Every call/cycle in every harness is compared, output by output, with the
independent reference model. A directed check passes only if its
hand-derived value holds **and** the model agreed on every call in that
test. The random runs (≥ 100,000 packets per U instance, regime-switching
gap mix including saturating idles and aliasing gaps, 10% refresh calls)
print their seed. The default is 20261020. Seeds 1, 42, 777, 99999 and
123456789 also give 185/0.

## Verilog-2001 constructs relied on (for the xsim port)

Constant functions in `localparam` (`f1_bits`), `` `include `` inside a module
body, `generate if` without genvar, 64-bit ranged parameters, an untyped
string parameter (`NAME`) printed with `%0s`, tasks with outputs and 128-bit
locals, `$random(seed)`, `$value$plusargs`/`$test$plusargs`, integer
part-selects (`k[9:0]`). `$clog2` is **not** used. **`$fatal` is IEEE 1800,
not 1364-2001.** Icarus `-g2001` accepts it. It is guarded: compile with
`-DF1_NO_FATAL` if xvlog rejects it, and then rely on the SUMMARY line,
because `$finish(n)`'s argument is not an exit code.

## Running in Vivado xsim on the laptop — NOT YET RUN (no Vivado here)

From the repository's `fpga/` directory:

```
xvlog -i rtl -i tb rtl/token_bucket_update.v rtl/token_bucket.v \
      tb/tb_f1_unit.v tb/tb_f1_wrap.v tb/tb_f1.v
xelab -debug typical -top tb_f1 -snapshot tb_f1_sim
xsim tb_f1_sim -R -testplusarg seed=20261020 | tee xsim_f1.log
grep '^SUMMARY' xsim_f1.log        # must read: SUMMARY: 185 passed, 0 failed
```

Add `-d F1_NO_FATAL` to `xvlog` if it errors on `$fatal`. Add
`-testplusarg vcd` for the VCD of the W1 wrapper (≈ 48 MB). Expect a longer
runtime than Icarus (≈ 60 s here). Any difference from Icarus is a finding
to log.

## Resource estimate (ESTIMATE, not a synthesis result)

Wrapper: about 136 flip-flops (48 counter + 36 tokens + 48 timestamp + 4),
1 DSP48E1, a few hundred LUTs for the 48-bit subtract/compare and the
38/36-bit add/compare/subtract. F3 per-source state is 1 + 36 + 48 = 85 bits
× 256 = 21.8 kbit. The capacity fits one RAMB36, but the width (85) is more
than its widest port (72), so expect 2 BRAM tiles unless TS_W is reduced.
That is a guess for F3 to check.
