# Line-by-line audit of v3.0 → v3.1

Scope: every file in `hids/`, `tools/`, `tests/`, plus the first VM
validation run (2026-09-16, kernel 5.4.0-216, 2 vCPUs, BCC 0.12.0,
Python 3.8.10). Each finding says how it was found, what changed, and what
proves the fix. "VM pending" = needs `vm_validation.sh` /
`overhead_breakdown.sh` on the VM to confirm in the kernel.

## A. Findings from the VM run

| # | Finding | Evidence | Action |
|---|---|---|---|
| A1 | Kernel side loads and works on 5.4 | 13/13 checks, 636 log lines, 0 malformed | recorded; v3.0 kernel items → *tested* |
| A2 | `vm_validation.sh` gave up: "did not attach" | console file empty; Python block-buffers stdout to files | `flush=True`, `python3 -u`, cleanup trap; regression test `StartupOutputTest` |
| A3 | Workload slowdown 2.8× (exec) / 6.4× (find) | timings.csv | cause unknown → `overhead_breakdown.sh` built to isolate it |
| A4 | `--no-log` still formatted every log entry + lineage | reading `_emit` after A3 | early return when there's no output; test `test_no_output_means_no_formatting` |
| A5 | 0 % loss is not comparable to v2's 7.2 % | slowed workload, quiet mode, 20 s cap | stated in the deck guidance; not claimed as an improvement |
| A6 | p64 vs p256 difference likely page cache | neither lost records; p256 ran second | cache warm-up added before both stress runs |
| A7 | Root-cause trace buried in library files | trace evidence listed `ld.so.cache`, `libc`, locale | `graph.common_file` + `skip=`; `--no-libs` in query tool |

## B. Kernel program (`monitor.bpf.c`)

| # | Finding | Severity | Fix | Proof |
|---|---|---|---|---|
| B1 | `execveat` not hooked — misses `fexecve`/memfd, the core fileless pattern | high | hook added, shares `exec_enter()` | type-check; VM check "fileless exec" (pending) |
| B2 | Exec path read from user memory only | medium | `KERNEL_EXEC_PATH`: `__data_loc` path from the tracepoint (naming verified in BCC 0.12 source) | type-check; VM pending |
| B3 | Files identified by path string: relative paths from different dirs merge; different names of one file split | high (false causal edges) | `FILE_IDENTITY`: inode via fd table / `mm->exe_file`; relative paths without inode get no node | `FileIdentityTest`; VM check "relative path linked through inode" (pending) |
| B4 | `dfd` stashed but never sent | low | `dfd` field; shown as `fd3:name` | `test_execveat_relative_path_display` |
| B5 | No way to enable hooks selectively (needed to attribute cost) | medium | `HOOK_EXEC/OPEN/EXIT` switches, `--hooks` | `test_every_hook_and_feature_combination_typechecks` |
| B6 | A feature the verifier rejects would stop the monitor | medium | `load_bpf` falls back through 4 feature sets, records refusals | `test_feature_fallback`, `test_nothing_loads` |
| B7 | `&argv[i]` relies on BCC's rewriter leaving `&x[i]` alone | low | integer slot arithmetic | type-check |
| B8 | Size comment said 384; real size 392 | doc | corrected, size pinned by test | `test_sizes_quoted_in_docs` |
| B9 | Nested-program safety of per-CPU scratch undocumented | doc | explained (`bpf_prog_active`) | — |
| B10 | Syscall tracepoints set `TIF_SYSCALL_TRACEPOINT` on all threads | perf hypothesis | measured by `count_exec` vs `bcc_execsnoop` on `dd` | VM pending |
| B11 | Perf wakeup per record (BCC 0.12 hardcodes `wakeup_events=1`, verified in source) | perf hypothesis | `--batch-ms` | VM pending |

## C. Userspace

| # | File | Finding | Fix | Proof |
|---|---|---|---|---|
| C1 | processor | one exception in a callback could spam or break processing | `handle()` catches, counts `errors`, keeps first traceback | `test_bad_record_does_not_stop_stream` |
| C2 | processor | pending execs unbounded if records are lost in bulk | `MAX_PENDING` + forced settle | `test_pending_cap` |
| C3 | processor | `expire()` scanned every pending entry | ordered dict, stops at first fresh | `test_expire_stops_at_first_fresh_record` |
| C4 | processor | no fileless flag, kernel path unused | `exec_from_fd`, `requested_path`, `file` fields | `test_fileless_exec_detected` (+ without kernel path) |
| C5 | graph | file table unbounded (`find /` = 100k+ paths) | LRU `max_files` (CLI default 200 000) | `test_file_lru_eviction` |
| C6 | graph | refresh iterated every lifetime ever seen | `alive_nodes()` iterates PIDs only | `test_alive_nodes` |
| C7 | graph | dead branch `if old is node` | removed | coverage |
| C8 | graph | snapshot had no version check | version 4 + check | `test_snapshot_version_checked` |
| C9 | monitor | stats/log lost if the loop crashed | `try/finally`, `crash` field | `test_stats_written_even_if_loop_crashes` |
| C10 | monitor | Ctrl+C during compile → traceback | handlers installed before compiling | — |
| C11 | monitor | refresh sampled all nodes | samples `alive_nodes()` | view test |
| C12 | monitor | no way to measure kernel cost alone | `--sink count` | `test_count_sink_and_batching` |
| C13 | view | fileless `if` split an `if/elif` chain (right result by accident) | `describe()` with one branch per type | `PrinterTest` |
| C14 | view | `stream=sys.stdout` default bound at import time | `stream=None`, resolved at call | `test_view_mode_draws` |
| C15 | query tool | missing/non-numeric target → raw traceback | argparse errors | `QueryToolTest` |
| C16 | analyzer | `a or b if c else d` precedence bug | parenthesised | `test_overhead` |
| C17 | events | positional `Event(...)` in helpers broke silently when fields were added | keyword construction, defaults | full suite |

## D. Tests

| # | Finding | Fix |
|---|---|---|
| D1 | BPF type-check passed *vacuously* once code moved under `#ifdef` | compiles 5 hook/feature combinations; negative test proves it can fail |
| D2 | fake BCC never ended zero-timeout polls → hang | fake stops whenever its script is empty |
| D3 | view loop, printer branches, recent-exit tree, late truncation, done-LRU untested | tests added (coverage 95 %+) |

## E. Journal corrections

- **Row 2:** `bpf_probe_read_kernel_str()` was added in kernel **5.5** (Nov 2019 commit; helper id 115), not 5.11.
- **Rows 19 and 22, and the v2 `test_pid_reuse.py` scope:** superseded by the start-time identity design (docs/CHANGES_v3.md rows 26–28).
- **Row 20:** userspace CPU is not the whole overhead; see A3/B10.

## F. v3.1 → v3.2: second VM run (17 Sep 2026)

| # | Finding | Evidence | Action | Proof |
|---|---|---|---|---|
| F1 | v3.1 kernel additions work on 5.4 | `vm_validation.sh`: 16/16 checks; KERNEL_EXEC_PATH + FILE_IDENTITY active, none refused; 470/470 files by inode; memfd exec flagged `exec_from_fd` | README status updated | VM |
| F2 | `overhead_breakdown.sh` hung at `bcc_execsnoop`; Ctrl+C did nothing | console stopped after "== bcc_execsnoop"; `^C^C` ignored | root cause below; `tools/lib.sh` | `test_scripts.py` |
| F3 | Root cause: background jobs of a non-interactive bash ignore SIGINT; BCC tools don't install a handler; `kill -INT` + `wait` (no deadline) never returned, and the EXIT trap repeated it | reproduced: `signal.getsignal(SIGINT) == SIG_IGN` in a `&` job; old pattern times out | `stop_bg`: SIGTERM → deadline → SIGKILL | `DiagnosisTest`, `test_stop_bg_*` |
| F4 | No Ctrl+C handling in either script | — | `trap on_interrupt INT TERM` → stop tracer, exit 130 | `test_ctrl_c_stops_everything` (SIGINT to the process group, as a terminal does) |
| F5 | The scripts themselves were never executed by any test | the analyzer was tested, the script was not | env overrides (`P15_*`) + full dry run with fake monitor and fake tracer | `test_full_dry_run_finishes` |
| F6 | Missing BCC tool would hang or fail obscurely | — | `command -v` check → recorded as skipped | dry run uses a nonexistent `opensnoop` |
| F7 | No progress output during long measurements | a slow step looked like a hang | per-round timing lines | dry run output |
| F8 | My first `lib.sh` comment claimed `kill -0` is fooled by zombies of our own jobs | test showed bash reaps its jobs itself | comment corrected; the zombie case is tested with a process bash did NOT start | `test_bash_reaps_its_background_jobs`, `test_is_running_is_false_for_a_real_zombie` |
| F9 | `find /usr` baseline 0.81 s (16 Sep) vs 0.26 s (17 Sep) | results.md of both runs | percentages across runs are not comparable; compare seconds within one run | README |

Mutation checks for this change: restoring `kill -INT` + `wait` in
`stop_bg`, and removing the INT trap, each make `test_ctrl_c_stops_everything` fail.

Process lesson (sandbox, while mutation-testing): `pkill -f PATTERN`
matches every command line containing PATTERN, including the shell that
runs the `pkill`. That killed the test shell *before* its restore step, which
left `lib.sh` mutated until a later `diff` caught it. Use `pgrep -af` to look
first, and never put a restore step after a `pkill -f` in the same command.

## G. v3.2 → v3.3 (17 Sep 2026)

| # | Finding | Evidence | Action | Proof |
|---|---|---|---|---|
| G1 | `test_wait_for_text_return_codes` timed out on the VM, passed in the sandbox | VM: TimeoutExpired after 40 s, twice | reproduced: where bash does NOT replace a subshell with its last command, `( ...; sleep 600 ) &` leaves an orphan that inherits the script's stdout and keeps the pipe open | fix verified against a forced-orphan case: 0.5 s instead of a hang |
| G2 | Any stray grandchild could hang ANY shell test | same mechanism | `bash()` test helper now reads output from a temp file, never a pipe; `_kill_group` removes orphans | `test_scripts.py` |
| G3 | Results were reported as "16 checks passed" — a reviewer cannot tell what was actually shown | — | `tools/claims_evidence.sh` + `analyze_claims.py`: six claims (C1–C6), each with how it was tested and the evidence quoted | dry-run test asserts every claim id appears and that unproven claims read NOT SHOWN |
| G4 | Three claims rested on unit tests only: real PID reuse, real event loss, queries on real data | — | forced PID reuse (`force_pid_reuse.py`), forced buffer overflow (`--pages 1`), query tool run on the real snapshot | pending the VM run |
| G5 | A PID-reuse experiment can silently prove nothing on a machine with a large `kernel.pid_max` | 24,649 spawns, no reuse, in the sandbox | pid_max recorded and printed; a negative result reads NOT SHOWN with the spawn count | analyzer |
