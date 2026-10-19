# v2 → v3: problems found and how each was fixed

Status labels follow the Engineering Journal legend. "Unit-tested" means
proven in the 64-test suite without a kernel; kernel-side items stay
**"Design applied — not yet tested"** until `tools/vm_validation.sh` runs on
the VM. Suggested Journal rows 23+. Also correct row 2: the `_kernel`/`_user` probe-read helpers arrived in kernel **5.5**, not 5.11.

| # | Problem in v2 | Why it happened | v3 fix | Status |
|---|---|---|---|---|
| 23 | **argv never captured**, though the Phase I report lists it | execve hook read only `filename` | kernel sends one ARG record per argument (max 20), then an END record; userspace assembles | kernel: not yet tested · assembly: unit-tested (all 120 arrival orders) |
| 24 | Failed execs logged as if they ran | `sys_enter_execve` fires before the kernel tries | `sched_process_exec` confirms success; unmatched attempts become `EXEC_FAILED` | kernel: not yet tested · logic: unit-tested |
| 25 | EXEC showed the caller's name; `--filter` matched the shell (rows 9, 15) | comm read at syscall entry | name taken from `sched_process_exec` (after the image swap); previous name kept | unit-tested |
| 26 | Lineage cache: hop 1 **could** go stale (audit probe B); row 19's scope was wrong | cached parent entry with a resolved ppid was never overwritten; kernel's pcomm discarded | `pid_cache` removed. Every event carries process + parent **start time**; lineage read from the graph | unit-tested |
| 27 | `test_pid_reuse.py` tested exited-process fallback, not reuse, and depended on whether PID 1390 existed | `_resolve` re-reads /proc when ppid is None | replaced by deterministic graph tests (no /proc dependence) | unit-tested |
| 28 | Reused PID inherited dead process's files (row 22) | history keyed by PID number | node key = (pid, generation); identity decided by kernel start time | unit-tested |
| 29 | Reused PID listed under the OLD parent (audit bug C) | children set held bare PIDs | children hold (pid, gen) keys | unit-tested |
| 30 | `render_tree` recursion: cycle → RecursionError; phantom pid-0 node (audit bug D) | recursive, no visited set; ppid 0 created a node | iterative walks with visited sets; no node for ppid 0; 5000-deep chain test | unit-tested |
| 31 | No process-exit data (`on_exit` had no caller) | no exit hook | `sched_process_exit` (leader only) with exit status; lost exits inferred on PID reuse | kernel: not yet tested · logic: unit-tested |
| 32 | Worker threads logged under the thread name ("Thread (pooled)", row 10) | `bpf_get_current_comm` returns the THREAD name | process name from `group_leader->comm`; thread name kept as `thread` | kernel: not yet tested |
| 33 | Failed opens logged like successful ones; no R/W distinction | only `sys_enter_openat` hooked | enter/exit pairing (LRU hash) gives return value; flags → R/W/RW; also hooks plain `open` | kernel: not yet tested · logic: unit-tested |
| 34 | Stale parent fields possible in reused scratch buffer | parent fields skipped when `real_parent` NULL | every field reset in `fill_common` | type-checked |
| 35 | Self-events dropped in Python after the kernel copied them | SELF_PID check in userspace | `SELF_TGID` compiled into the eBPF program, dropped in-kernel | kernel: not yet tested |
| 36 | Timestamps up to 1 s off, drift after suspend | `btime` (whole seconds, boot clock) + monotonic ns | offset measured directly between wall and monotonic clocks | unit-tested |
| 37 | Filters ran after lineage lookup | order of operations | graph updated always; formatting/logging only for matches | unit-tested |
| 38 | Log appended across runs (row 17) | `open(..., "a")` | new `runs/run-<time>.jsonl` per run, opened with "w" | unit-tested |
| 39 | Per-event coloured printing is the dominant userspace cost | design | default is a 1 s refreshed top+tree view; per-event printing optional | measure on VM |
| 40 | Overhead number measured only monitor CPU via `ps` (row 20 tooling problems) | eBPF cost is charged to traced processes | monitor reports its own CPU/RSS via `getrusage`; validation times workloads with/without monitor | pending VM run |
| 41 | `pid_cache` grew without bound | no eviction | optional `--max-nodes` evicts oldest EXITED nodes only; per-node/file history capped | unit-tested |
| 42 | Bugs found by the new tests themselves | — | `record_*` didn't advance `last_ns` (broke time-bounded trace and let a late pre-exec event rename `cat`); exec-created node lost its previous name; bootstrap parent not upgraded; analyzer crashed on one malformed line | unit-tested |

| 43 | First VM run (16 Sep 2026) stopped: "monitor did not attach in 60 s", console empty | Python block-buffers stdout when it goes to a file; the ready line stayed in memory. Missed by all tests because the dev sandbox set PYTHONUNBUFFERED=1 | `flush=True` on status lines; script runs `python3 -u`; `trap` always stops a background monitor; new test runs the monitor as a real process with output to a file and PYTHONUNBUFFERED removed (fails before fix, passes after) | unit-tested; VM re-run pending |

Process note, like row 13: while mutation-testing the layout check, a stale
`__pycache__` `.pyc` (same size and mtime as the restored source) kept the
planted bug alive. Clear `__pycache__` after restoring files from backup.

---

# v3.0 VM validation and v3.1 audit — suggested Journal rows 43+

| # | Date | Item | Result | Status |
|---|---|---|---|---|
| 43 | 2026-09-16 | First `vm_validation.sh` run | aborted: "monitor did not attach"; empty console | root cause: stdout block-buffered to file |
| 44 | 2026-09-16 | Fix for 43 (`flush=True`, `-u`, trap) + regression test | second run completed | Resolved — confirmed on VM |
| 45 | 2026-09-16 | Kernel side on 5.4.0-216 | 13/13 checks: argv, new name, failed exec, exit code, truncation, fork-only, thread name, self-filter, no '?', root-cause trace, 200/200 burst with lineage, 636 clean lines | Confirmed on VM |
| 46 | 2026-09-16 | Stress (3× find /, 20 s) | 91,855 rec @ p64, 112,170 @ p256, 0 lost; ~4–5k rec/s; monitor 23–27 % of one core; 104–109 MB RSS; ~55 µs userspace per record | Measured; loss not comparable to row 18 (see AUDIT A5) |
| 47 | 2026-09-16 | Workload slowdown | 2000×/bin/true 3.69→10.46 s (+184 %); find /usr 0.81→5.18 s (+541 %) | Measured; cause under investigation (row 50) |
| 48 | 2026-09-16 | v3.1 kernel changes | execveat hook, kernel exec path, inode identity, hook switches, feature fallback | Design applied — type-checked, VM pending |
| 49 | 2026-09-16 | v3.1 userspace changes | 17 findings (AUDIT_v3.1.md §C) | Unit-tested (96 tests, py3.8 + 3.12) |
| 50 | pending | `overhead_breakdown.sh` | 11 configs × 3 workloads | To run on VM |
| 51 | 2026-09-16 | Correction to row 2 | helper appeared in 5.5, not 5.11 | Verified (kernel commit, helper id 115) |
