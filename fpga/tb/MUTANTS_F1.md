# F1 mutation check

Project rule: a test only counts if breaking the thing it guards makes it
FAIL. Each mutant below is one deliberate bug in the RTL. Reproduce with:

```
python3 fpga/sim/mutate_f1.py [OUT_DIR] [-j 2]
```

The script copies `fpga/{rtl,tb,sim}` to `OUT_DIR/<id>/` and applies the
exact text edit to the **copy** (each pattern must match exactly once). It
runs the copy's `run_f1.sh` and lists the named FAILs. **The working tree
is never modified; no mutant code exists in the repository.** A mutant
counts as killed only if the run reaches its SUMMARY line, at least one
named test FAILs, and the run exits nonzero. A compile error does not count
as a kill.

Run on 2026-10-20 with Icarus Verilog 12.0, seed 20261020. Result:
`MUTANTS: all killed`, exit 0. In the table, "direct" killers are tests
whose hand-derived value was wrong; the reference-model comparison also
failed for every mutant except M10.

| ID | File | Mutation | Result | Named tests that FAIL (direct killers first) |
|---|---|---|---|---|
| M1 | update | refill off by one cycle: `elapsed = now - st_last - 1` | KILLED, 145 FAIL | `U1/refill_one_cycle_exact`, `U1/refill_T_FULL_minus_1_exact`, `U1/exact_R_5000pps_10s_from_EMPTY_zero_flags`, `U1/rate_5001pps_from_full_first_flag_at_index_2495500`, `U1/back_to_back_100k_conforms_504`, `W1/random_clocked_vs_ref_model_every_cycle`, … |
| M2 | update | no saturation at B (`full = !st_valid` only; sum never capped) | KILLED, 42 FAIL | `U1/refill_from_nonzero_caps_at_CAP`, `U2/B1_R_plus_1_in_1s_FULL_2500_flags`, `U2/B1_R_plus_1_in_1s_EMPTY_2501_flags`, `U2/after_flag_tokens`, `U*/random_vs_ref_model_all_outputs_agree` |
| M3 | update | non-conforming packet consumes tokens (drains to 0) | KILLED, 84 FAIL | `U*/flag_consumes_nothing`, `U*/after_flag_one_cycle_refill_conforms`, `U1/over_rate_5263pps_packet_after_flag_conforms`, `U1/R_plus_1_in_1s_EMPTY_bucket_exactly_one_flag`, `U1/back_to_back_100k_conforms_504`, … |
| M4 | update | conform compare `>` instead of `>=` | KILLED, 60 FAIL | `U*/tokens_eq_COST_conforms`, `U*/exact_R_from_EMPTY_30000pkts_zero_flags`, `U1/exact_R_5000pps_10s_from_EMPTY_zero_flags`, `U1/exact_R_5000pps_10s_from_EMPTY_tokens_end_0`, … |
| M5 | update | elapsed without wrap handling (`now < last` → 0) | KILLED, 28 FAIL | `U*/wrap_elapsed_exact_across_wrap`, `U*/exact_R_from_EMPTY_across_counter_wrap_zero_flags`, `U*/random_vs_ref_model_all_outputs_agree`, `W1/random_clocked_vs_ref_model_every_cycle` |
| M6 | update | multiplier product truncated by 2 bits (`[PROD_W-3:0]`) | KILLED, 63 FAIL | `U1/refill_T_FULL_minus_1_exact`, `U*/refill_T_FULL_saturates_at_CAP`, `U*/idle_gap_max_2powTS_minus_1_is_full`, `U1/cap_then_burst_B_plus_1_first_flag_index_B`, … |
| M7 | update | no clamp before multiply (elapsed truncated to EL_W bits, wraps) | KILLED, 28 FAIL | `U*/idle_gap_2powEL_plus_5_is_full`, `U4/wrap_elapsed_exact_across_wrap`, `W1/gap_across_wrap_exact_full_burst_B_conforms`, `U*/random_vs_ref_model_all_outputs_agree`, `W1/random_clocked_vs_ref_model_every_cycle` |
| M8 | update | `T_FULL = floor(CAP/R)` instead of ceil | KILLED, 5 FAIL | **only U3** (CAP/R non-integer): `U3/refill_T_FULL_saturates_at_CAP`, `U3/idle_gap_2powEL_plus_5_is_full`, `U3/idle_gap_max_2powTS_minus_1_is_full`, `U3/long_idle_bucket_exactly_CAP`, `U3/wrap_alias_residue_ge_T_FULL_still_full` |
| M9 | update | never-seen source starts EMPTY (`tok_in = 0` and not forced full; 2 edits) | KILLED, 55 FAIL | `U*/init_never_seen_is_full_conform`, `U*/init_never_seen_tokens_CAP_minus_COST`, `U*/burst_B_from_full_no_flag`, `U1/exact_R_5000pps_10s_from_full_zero_flags`, … |
| M10 | update | drop the `(!st_valid)` term in `full` | **SURVIVED, expected: equivalent** | none (185/0). Proof: when `st_valid = 0`, `tok_in = CAP`, so `sum = CAP + refill ≥ CAP` and `full` is already 1. The term is redundant and kept as belt-and-braces. The driver *requires* this mutant to survive, so the proof stays honest. |
| M11 | wrapper | timestamp not written back (`st_last <= st_last`) | KILLED, 17 FAIL | `W1/b2b_conforms_in_40_cycles`, `W1/b2b_flags_in_40_cycles`, `W1/pre_wrap_burst_empties_bucket`, `W1/gap_across_wrap_exact_full_burst_B_conforms`, `W1/random_clocked_vs_ref_model_every_cycle`, … |
| M12 | wrapper | reset does not clear never-seen state (`st_valid <= st_valid`) | KILLED, 22 FAIL | `W*/reset_source_never_seen_shows_CAP` (got X), `W*/latency_1_cycle_dec_valid_pulse`, `W1/b2b_first_flag_index_3`, `W1/reset_midstream_restores_CAP`, … |
| M13 | wrapper | `dec_valid` stuck high | KILLED, 12 FAIL | `W*/latency_1_cycle_dec_valid_pulse`, `W1/random_clocked_vs_ref_model_every_cycle` |
| M14 | wrapper | counter steps by 2 | KILLED, 23 FAIL | `W1/counter_free_runs`, `W1/counter_reaches_top`, `W1/counter_wrapped_to_4`, `W1/b2b_conforms_in_40_cycles`, … |

`U*` / `W*` = the same test fails in several parameter instances. Full logs
are written by the script to `OUT_DIR/<id>/log.txt`.

## What the table shows

- **M8 is killed only by the parameter sweep.** At the defaults, CAP/R is an
  integer (5×10¹⁰ / 5000 = 10⁷), so floor and ceil agree and U1/U2/U4 cannot
  see the bug. Only U3 (125 MHz, R = 3000, B = 37: CAP/R = 1,541,666.67)
  catches it. The sweep is load-bearing, not decoration.
- M7 at full scale (U1) is caught by one directed test
  (`idle_gap_2powEL_plus_5_is_full`) and by the random comparison, but
  narrowly: only 14 mismatches in 10⁵ calls. In the small sets, where gaps
  routinely exceed 2^EL_W, it fails widely. Long idle gaps in the random
  mix exist for this reason.
- M13 is caught directly only by the latency test, so the wrapper's
  `dec_valid` contract rests on that one directed check plus the
  every-cycle model compare.
