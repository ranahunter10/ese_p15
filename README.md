# ESE-P15 — eBPF process / file / network provenance monitor (v3.7)

Ashish Rana · SR 26179 · M.Tech ESE, IISc · Advisor: Prof. Haresh Dagale

Layer 1 (kernel telemetry) and Layer 2 (in-memory provenance graph) of the
HIDS. Replaces `process_monitor_v2.py` + `process_graph.py` (kept unchanged
in `legacy/`).

## Where to start reading

| If you want to… | Read |
|---|---|
| understand how every piece fits together | `docs/ARCHITECTURE.md` |
| learn the OS / kernel / eBPF / C / Python ideas used | `docs/CONCEPTS.md` |
| see what was wrong in v2 and v3.0, and what fixed it | `docs/CHANGES_v3.md`, `docs/AUDIT_v3.1.md` |
| see the latest day's work, mechanism by mechanism, with its evidence ledger | `docs/WORKLOG_2026-10-13.md` |
| see what the v3.5i review found and what v3.6 did about it (and chose not to) | `docs/CHANGES_v3.6.md` |
| **read the whole system line by line and be able to defend it** | `docs/study/00_MASTER.md` |
| test a build on the VM, step by step, and know what each step proves | `docs/VM_TEST_RUNBOOK.md` |
| run it | below |

## Layout

```
hids/
  bpf/monitor.bpf.c   kernel side: 14 tracepoint programs (exec, open, exit, net)
  events.py           byte layouts (must match the C), decode, file ids, clocks
  processor.py        exec assembly (any arrival order), logging, statistics
  graph.py            provenance graph: process lifetimes, files, causal queries
  procstat.py         /proc: startup snapshot, CPU / memory sampling
  view.py             live top + pstree screen, per-event printer
  monitor.py          entry point: feature fallback, main loop, crash-safe stats
tools/
  vm_validation.sh    correctness checks + headline numbers  -> results.md
  overhead_breakdown.sh  where the slowdown comes from        -> overhead.md
  analyze_run.py, analyze_overhead.py   the analyzers behind those
  query_graph.py      tree / lineage / trace / impact / files / writers / fdexec
                      peers / talkers / endpoints / scans / inbound   (network)
  net_demo.py         deterministic connect scenario over loopback (no internet)
  walk_trace.py       dry-run a causal walk step by step (teaching + debugging)
  lib.sh              safe start/stop of background tracers (used by all scripts)
  claims_evidence.sh  ONE command -> claim-by-claim evidence table (claims_evidence.md)
  analyze_claims.py   builds that table; force_pid_reuse.py forces a real PID reuse
  bench_ingest.py     paired decode/ingest cost (the figures in CHANGES §C)
  bench_nodes.py      what a graph node costs (tracemalloc) -> the cap defaults
  package.sh          build the zip and run the suite FROM INSIDE it, every Python
  tax_paired.py       the per-syscall tax by PAIRED ratios (drift cancels);
                      count_exit is a 0-tracepoint control that voids a bad run
tests/                436 tests, no root (Python 3.8, 3.12, 3.13);
                      test_review_v35i.py names one test per fixed review
                      finding; test_adversarial.py
                      holds the time-law fuzz, test_corners.py the corner-case
                      taxonomy (A-G); test_scripts.py
                      runs the shell scripts for real with fake tracers
docs/                 ARCHITECTURE, CONCEPTS, CHANGES_v3, CHANGES_v3.4 (outbound),
                      CHANGES_v3.5 (inbound), AUDIT_v3.1 (F = v3.2, G = v3.3)
docs/study/           8-stage guide for reading every line, with dry runs
legacy/               v2, unchanged
```

## Run (Ubuntu 20.04 VM, kernel 5.4)

```bash
sudo apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r)   # once
cd ese_p15
./run_tests.sh                                     # no root needed
sudo python3 -m hids.monitor                       # live top + tree
sudo python3 -m hids.monitor --mode print -f cat   # per-event lines
sudo python3 -m hids.monitor --mode quiet --duration 60 \
     --stats-json runs/s.json --snapshot runs/g.json
python3 tools/query_graph.py runs/g.json trace <PID> --no-libs
python3 tools/query_graph.py runs/g.json fdexec    # programs run from memory/fd
python3 tools/query_graph.py runs/g.json peers <PID>          # who it talked to
python3 tools/query_graph.py runs/g.json talkers net:1.2.3.4:443
python3 tools/query_graph.py runs/g.json scans                # refused attempts
python3 tools/query_graph.py runs/g.json inbound              # who connected IN
python3 tools/query_graph.py runs/g.json trace <PID> --at 1234.5   # as of that time
sudo python3 -m hids.monitor --hooks net --mode print         # connections only
sudo bash tools/vm_validation.sh                   # ~5 min
sudo bash tools/overhead_breakdown.sh              # ~10-15 min
```

Run as `python3 -m hids.monitor` from the project root (it is a package).
Each run writes a new log under `runs/`. Close file managers showing the
project folder while measuring (Journal row 10).

## Status — what is proven where

| Part | Evidence |
|---|---|
| v3.0 kernel side (execve, open/openat, exit hooks) | **VM, 2026-09-16:** 13/13 functional checks, 200/200 burst, 0 malformed lines |
| v3.1 kernel additions (execveat / fileless exec, kernel exec path, inode identity) | **VM, 2026-09-17:** 16/16 checks; features active, none refused; 470/470 files identified by inode |
| v3.4 network hook (`connect`: IPv4, IPv6, unix sockets; endpoint nodes) | **VM, 2026-10-13:** Firefox and systemd-resolved captured with full lineage, 2,191 records, 0 lost, 0 errors; refused / unix / non-blocking connects and the download→write→execute chain all verified |
| v3.5 inbound hook + v3.5d graph fixes, **end to end on kernel 5.4** | **VM, 2026-10-16:** 23/23 functional checks, 229 unit tests OK, 0 lost, 0 errors; full feature set verified with none refused; inbound captured from `curl`, `sshd` over IPv6 and `ssh-agent` over unix; 4 ephemeral ports collapsing to one host node (`docs/CHANGES_v3.5.md` §v3.5e) |
| `SOCKET_TYPE` feature, resolver-probe detection, per-run work directory | added after that run (see `docs/CHANGES_v3.4.md`, v3.4a) — **VM run pending** |
| WRITE-edge fix in `trace_back` (the one real failure of the 13-Oct run) | regression-tested here, and the analyzer's own synthetic run now reproduces the VM failure when the bug is reintroduced (rows 80–84) — **VM re-run pending: `vm_validation.sh` should reach 23/23** |
| v3.5 inbound hook (`accept`/`accept4`, host-keyed inbound endpoints, ACCEPT edges) | syscall behaviour verified by `strace` and against the v5.4 kernel source (`docs/CHANGES_v3.5.md` §A); 15 new unit tests; gcc type-check in all 8 hook/feature combinations — **not yet tested on the VM** |
| v3.5a walk hardening (3 bugs from an adversarial review + 1 found here) | each bug reproduced before fixing, each fix mutation-checked, two time laws held under a 5×15-trial shuffled-arrival fuzz (`docs/CHANGES_v3.5.md` §C2) |
| v3.5d corner-case sweep of the graph (6 findings, 3 correctness) | probed first, then 37 tests across a 7-area taxonomy; each fix mutation-checked (`docs/CHANGES_v3.5.md` §C4) |
| Hook switches (`--hooks`), batching, count sink | type-checked; exercised by `overhead_breakdown.sh` (**VM run pending**) |
| Python pipeline, graph, queries, analyzers | unit tests, Python 3.8.20, 3.12 and 3.13 |
| Shell scripts (start/stop, Ctrl+C, full overhead dry run) | `tests/test_scripts.py`, with a fake tracer that ignores SIGINT like BCC's tools |
| C ↔ Python record layout | gcc-compiled offsets compared field by field |
| Overhead | VM 2026-10-16: exec loop 6.65 → 12.96 s, `find /usr` 0.73 → 7.41 s, monitor CPU 35.9 % of one core, peak RSS 121 MB. **Quote absolute seconds, never the percentage:** the same `find` slowdown has read +917 %, +1325 % and +3516 % across runs purely because the baseline moved (row 133) |
| v3.6 full validation (VM 2026-10-19) | **23/23 checks, 0 failed**, run `validation-20261018-151152`: 1351 log lines 0 malformed, 0 processing errors, 0/1351 lineages with a `?`. Stress (3× `find /`, 20 s): **0 records lost at both 64 and 256 pages/CPU** (119 117 / 127 231 received), CPU 36.6 % / 35.9 % of one core, peak RSS 137.4 / 141.9 MB. Slowdown: 2000 execs 3.08 → 5.49 s, `find /usr` 0.34 → 4.81 s. **The zero loss means the p64-vs-p256 comparison no longer measures anything** and needs a heavier workload; it is also not attributed to v3.6's ingest gain without a paired run |
| Where the overhead comes from | **Answered, VM 2026-10-16** (`CHANGES_v3.5.md` §D, §D.5): cost tracks the number of EVENTS, not the number of hooks (`count_open` 11.14 s vs `count_exec` 0.71 s on the same workload); `--batch-ms 20` roughly halves the slowdown but drops 2.96 % of records |
| The per-syscall tax: is hook count a budget? | **No. Measured on the VM 2026-10-19 by `tools/tax_paired.py`** — paired ratios, 9 pairs per config, with a 0-tracepoint control arm reading **0.9971** and **1.0319** across two independent runs. **The ladder saturates at 4 tracepoints, reproduced in both runs:** 0→2 and 2→4 are real increases (disjoint IQRs), 4→6 and 6→12 are indistinguishable, so tripling 4→12 hooks costs nothing detectable. Magnitude: **~15 ns at 2 tracepoints** (14.6 and 15.3 — reproduced to 0.7 ns), rising to ~22–30 ns by four and flat after, on a ~130 ns bare syscall (`CHANGES_v3.6.md` §J rows 195–197). **Cite the saturation before the nanoseconds:** it is what the design decision rests on and it needs no ratio-to-ns conversion. Mechanism: `syscall_regfunc()` sets `TIF_SYSCALL_TRACEPOINT` on every thread only on the *first* registration, then refcounts — which predicts a step, not a slope. **What the mechanism does NOT explain:** the 2→4 increment is real in both runs, so something per-syscall-number also costs and also saturates. Open question inside a settled conclusion. *History:* v3.5g run `overhead-20261015-193624` reported ~16 ns for the first hook and < 1 ns for each further one; that "paid once" phrasing is **superseded** — the first rung is most of the cost but not all of it. Two `overhead_breakdown.sh` runs before `tax_paired.py` came out INCONCLUSIVE (noise floors 16.2 % and 13.4 % against a 6.7 % effect) and the analyzer correctly refused to read them; the fix was the statistic, not the machine (§D.5 rows 149–151, §J row 194) |
| v3.6 fixes for the v3.5i six-agent review (26 findings filed, 26 reproduced) | 15 fixed, each **mutation-checked** — reverting the fix fails a named test in `tests/test_review_v35i.py`. The rest are in `CHANGES_v3.6.md` §D with the reason they were deferred. **VM-verified 2026-10-19** (359 tests, 23/23 validation checks) |
| v3.6 reviewed again, as v3.6 | Three reviewers attacked the **new** code and found a P1 it had introduced (`process()` could return a node it had just evicted, which then broke every later eviction pass), three P2s and a P3 — all fixed and reproduced as tests. `CHANGES_v3.6.md` §H |
| v3.6 on the VM (2026-10-18) | Steps 0–3 **pass**: program verifies, all 3 features used, none refused, 14 programs attached, 6865 records, **0 lost, 0 errors**; suite 317/317 on the VM's Python 3.8.10. Step 4 found a real defect — `accept()`'s peer name was read from the traced process's leftover buffer memory, because the probe ignored `upeer_addrlen` (`CHANGES_v3.6.md` §J, rows 187–189). Fixed, and **VM-verified 2026-10-19**: the controlled marker/zero pair both report `peer unknown`, dbus is clean, inbound TCP is still named (two ports, one id) and connect-side unix paths are intact. The *first* fix was rejected by the verifier (a byte-by-byte copy off the BPF stack), so the length is now carried in the record and trimmed in userspace, where it is mutation-checked — 6 mutants, all caught (rows 187–192) |
| v3.6 claims audited against the tree | A third reviewer checked the *prose* against the code and found 20 overstated or stale claims, including a retracted figure still live in a test and a "measured" node-cost table with no harness anywhere. All corrected; the benchmarks now ship and the numbers in four documents are checked by tests. `CHANGES_v3.6.md` §I |
| v3.6 ingest cost | Measured paired by `tools/bench_ingest.py` (old and new interleaved in one process and compared per pair, because unpaired runs on the test machine drift ~25 %): decode **1.85x** (3.82 → 2.07 µs, IQR 1.82–1.89), full ingest **1.34x** (9.30 → 6.99 µs, IQR 1.32–1.38), 108k → 143k events/s. Quote the ratios; the absolute µs move ~2x between runs with container load. `ctypes.cast` replaced by one `struct.unpack_from` over a zero-copy view of BCC's pointer. **Container measurement, not the VM** |
| v3.6 eviction cliff (found here, not in the review) | `_maybe_evict` rebuilt `sorted(all dead nodes)` on every node creation while over the cap, so with dead nodes scarce it scanned everything, freed nothing, and the count kept growing. Per node creation against an uncapped baseline: 0 % dead **32.07x → 1.15x**, 50 % dead 13.62x → 1.54x. Identical final node counts, so the same policy without the scan |
| v3.6 decode safety | The old `ctypes` path performed a *successful* out-of-bounds read on a short buffer (`decode(b"\x04\x00\x00\x00", 10**6)` returned a garbage record). `struct.unpack_from` cannot, so W2-B6 is closed by construction; proven against the v3.5i decoder over 3000 randomised records in `test_layout.py` |

## If a script seems stuck

Both scripts print progress and stop cleanly on Ctrl+C (since v3.2).
If something is still running afterwards, in another terminal:

```bash
pgrep -af 'hids.monitor|bpfcc'            # what is still running?
sudo pkill -TERM -f 'hids.monitor|bpfcc'  # ask them to stop
sleep 3; sudo pkill -KILL -f 'hids.monitor|bpfcc'   # only if still listed
```

A leftover tracer keeps its eBPF hooks attached and slows every later
measurement, so always check before re-running. The kernel removes a tool's
hooks when the process dies, even with SIGKILL.

## Known limitations

See `docs/ARCHITECTURE.md` §11. The main ones:
- open mode is intent, not proof of reads/writes;
- path strings come from user memory (the inode is trustworthy);
- a connection is attributed when `connect()` is called (outbound) or when
  `accept()` returns (inbound); our own local/service port is still not
  captured in either direction, and UDP traffic that never calls `connect()`
  is invisible;
- an inbound peer is identified by host, not host:port, because the port in
  an accepted address is the peer's ephemeral one (`docs/CHANGES_v3.5.md` B4);
- enabling any `syscalls:*` tracepoint costs every process on the machine
  about 16 ns per syscall, whether or not that process is of interest; this
  is a property of the kernel's syscall tracepoint path, not of our code,
  and it cannot be avoided while using tracepoints (`CHANGES_v3.5.md` §D.5).
