# Stage 7 — `tools/` (1,551 lines)

Almost no algorithms. This stage is about **measurement discipline**: how to
produce a number you are willing to defend, and how to stop yourself
believing one you should not. Read it as methodology. Budget 3–4 hours.

```bash
wc -l tools/*
```

| file | what it is |
|---|---|
| `vm_validation.sh` | 23 functional checks + burst + stress + slowdown → `results.md` |
| `overhead_breakdown.sh` | 12 configurations × 3 workloads → `overhead.md` |
| `analyze_run.py` / `analyze_overhead.py` | the analyzers behind those two |
| `lib.sh` | safe start/stop of background tracers |
| `net_demo.py` | the deterministic network scenario |
| `query_graph.py` | 13 query verbs over a snapshot |
| `walk_trace.py` | the dry-run tool from stage 5 |
| `claims_evidence.sh` / `analyze_claims.py` | one command → a claim-by-claim evidence table |
| `force_pid_reuse.py` | forces a real PID reuse, deterministically |

---

## 7.1 `lib.sh` — read the comment block first, it is a case study

The header documents a VM session that hung forever and could not be
Ctrl+C'd. Two shell facts combined:

1. A **non-interactive** bash starts background jobs with SIGINT and SIGQUIT
   set to *ignore* (POSIX, for shells without job control). Python inherits
   that unless the program installs its own handler. `hids.monitor` does;
   BCC's `execsnoop-bpfcc` does not — so it ignored every SIGINT, including
   Ctrl+C.
2. The script stopped tracers with `kill -INT pid; wait pid`, and `wait` has
   no timeout. An ignored signal meant waiting forever, and the cleanup trap
   repeated the same two commands.

The fix is the pattern every script now uses: **SIGTERM, wait with a
deadline, then SIGKILL** — and the note that the kernel detaches a BCC
tool's eBPF programs when the process dies, even on SIGKILL, because they
are tied to its file descriptors.

Also read the last paragraph of the `is_running` comment, where an earlier
version of the comment was *wrong* about `kill -0` and a test proved it.
That is the house style: when the documentation and the test disagree, the
test wins and the comment gets corrected in place rather than quietly
deleted.

## 7.2 `overhead_breakdown.sh` — a designed experiment

Read the header block. Twelve configurations, and the thing to understand is
that each one exists to **isolate a single variable**:

| comparison | isolates |
|---|---|
| `base` first **and** `base_end` last | drift: did the machine change during the run? |
| `bcc_execsnoop` vs `count_exec` | is exec tracing inherently this costly, or is it us? |
| `count_*` vs `graph_all` | the cost of our Python processing, same kernel work |
| `count_all` vs `count_all_nofeat` | the cost of the inode / kernel-path reads |
| `graph_all` vs `graph_all_batch20` | the cost of perf wakeups |
| `graph_all` vs `graph_all_log` | the cost of writing JSONL |
| the `count_*` ladder against the **dd** workload | the per-syscall tax of enabling syscall tracepoints at all |

That last row is the experiment the whole project is waiting on, and it is
worth being able to explain precisely:

> Enabling any `syscalls:*` tracepoint sets a per-thread flag
> (`TIF_SYSCALL_TRACEPOINT`) that forces **every** syscall on the box onto
> the kernel's slow path. If that is the dominant cost, it is paid once when
> the first such hook is enabled and extra hooks are nearly free. The dd
> workload calls none of the syscalls we hook, so any slowdown it shows is
> that tax and nothing else. The ladder — 0, 2, 4, 6, 12 syscall
> tracepoints — therefore reads **flat = paid once, rising = per hook**.

Two methodology details to carry into any measurement you ever run:

- **Medians of N rounds, and absolute seconds reported alongside
  percentages.** A percentage against a drifting baseline is a lie; the
  13-Oct note about the `find` baseline being 3× faster than a week earlier
  is why both are printed.
- **Every configuration runs the same three workloads** — exec-heavy,
  open-heavy, and syscall-heavy-but-unhooked — so a cost can be attributed
  to a mechanism rather than to "the monitor".

## 7.3 `analyze_run.py` — checks that can fail

The analyzer's own design rule, which is the single most transferable idea
in this directory:

> A check that cannot fail is not a check.

Read `analyze_run.py` and notice that every `r.check(...)` is a *claim with
its evidence string attached*, and that the thing being asserted is derived
from what the demo actually did (`net_demo.json`, `paths.json`) rather than
from hard-coded ports and paths. Then read its test:

```bash
grep -n "break_it" tests/test_analyzer.py | head
```

`functional_story(w, p, break_it=True)` deliberately damages the run — drops
the downloader's connect, removes the inbound records — and the test asserts
the corresponding checks **FAIL**. A new check is not finished until it has
been seen to fail.

The most recent example is in the file today: the inbound host-keyed
identity check originally passed on an *empty* set (no inbound connections
→ "all ids are the same" → true). That is the failure mode this rule exists
to catch, and `CHANGES_v3.5.md` row 96 records the fix.

Also note `r.number(...)` versus `r.check(...)`: numbers are reported, not
asserted. Throughput, loss, CPU and RSS are facts about a run, not
pass/fail criteria, and labelling them as numbers keeps the check list
meaningful.

## 7.4 `analyze_overhead.py` — readings labelled as hints

Read the `readings()` section. It applies rule-based interpretation to the
timings — "the exit hook costs dd +2 %, the exec hooks +140 %, so the tax
looks like a syscall-tracepoint effect" — and every line is **guarded**: it
only fires when the data supports it, and the output says the readings are
hints to check against the table rather than conclusions.

`NOISE = 0.10` is the honesty knob: changes below 10 % are not interpreted
at all, because on a 2-vCPU VM they are not distinguishable from noise.

`SYSCALL_TRACEPOINTS` is the ladder map, and it had to be updated when
`accept` was added (2 → 6 for the net group, 8 → 12 for all). A test asserts
the ladder reading mentions the right counts, which is what caught the stale
numbers.

## 7.5 `net_demo.py` — determinism on purpose

Five scenarios over loopback, no internet, no DNS: successful connect,
refused connect, unix socket, non-blocking connect, inbound
server-child/client-child, and the download → write → execute chain.

The design decisions worth noticing:

- **Each case runs in its own child process**, so attribution is
  unambiguous: if the record says the connect came from the child, it did.
- **Ports are chosen by the kernel** (`bind(('127.0.0.1', 0))`) and then
  *published* — written to `net_demo.json`, and for the inbound server
  written-then-renamed to a file the client polls. A hard-coded port is a
  flaky test on a shared machine.
- **The analyzer asserts against those published values**, not against
  constants. This is what made the v3.4a fix possible: the paths moved into
  a per-run `mktemp -d` directory and nothing else had to change.
- **The blocking-socket comment** records a real misdiagnosis:
  `socket.create_connection(addr, timeout)` sets the socket non-blocking, so
  the syscall returns `-EINPROGRESS` and a test looking for `ret == 0`
  failed while the monitor was right.

## 7.6 `query_graph.py` and `walk_trace.py`

`query_graph.py` is the analyst's interface: `tree`, `lineage`, `trace`,
`impact`, `files`, `writers`, `fdexec`, `gens`, `peers`, `talkers`,
`endpoints`, `scans`, `inbound`, plus `--no-libs`, `--gen` and `--at`.

Read how little it does: load a snapshot, pick a node, call one graph
method, print. All the logic is in `graph.py` where it is tested; the CLI is
a thin shell. That separation is why the same `trace_back` serves the live
view, the analyzer, the CLI and the dry-run tool.

`walk_trace.py` (stage 5) is the same idea taken further: rather than
reimplementing the walk to explain it, it passes a printing observer into
the real one. **A second copy of an algorithm written for teaching will
drift from the first and then teach the wrong thing** — worth remembering
whenever you are tempted to write a "simplified version".

## 7.7 `force_pid_reuse.py` and `claims_evidence.sh`

`force_pid_reuse.py` deliberately cycles PIDs until one is reused, so the
PID-generation code is exercised against a *real* reuse rather than a
synthetic one. Determinism beats luck: a test that passes because the event
did not happen is worthless.

`claims_evidence.sh` runs one command and produces a table of every claim
the project makes with the evidence for it — built for the deck, and the
reason a review can ask "where is that number from?" and get an answer in
one line.

---

## Experiments

`[VM]` The two runs that matter, in order:

```bash
sudo bash tools/vm_validation.sh          # ~5 min, expect 23/23
sudo bash tools/overhead_breakdown.sh     # ~10-15 min -> runs/overhead-*/overhead.md
```

`[laptop]` Run the shell scripts for real, with fake tracers:

```bash
python3 -m unittest tests.test_scripts -v 2>&1 | head -20
```

That suite runs the actual scripts end to end, substituting a fake tracer
that **ignores SIGINT exactly like BCC's tools do**, which is how the
hanging bug is kept fixed.

`[laptop]` Watch a check fail on purpose:

```bash
python3 -m unittest tests.test_analyzer.AnalyzerTest.test_detects_failures -v
```

---

## Self-check

1. Why does `lib.sh` stop tracers with SIGTERM rather than SIGINT?
2. Why does a SIGKILL'd BCC tool not leave its eBPF programs attached?
3. `base` runs first and `base_end` runs last. What question does that
   answer, and what mistake does it prevent?
4. Why does the overhead rig include BCC's own `execsnoop` and `opensnoop`?
5. The dd workload calls none of the syscalls we hook. Why is it in the
   experiment at all?
6. Flat ladder versus rising ladder — what does each imply for Phase 2?
7. What is the rule about checks, and what is the empty-set failure that
   motivated it most recently?
8. Why does `net_demo.py` publish its ports instead of hard-coding them?
9. Why does `walk_trace.py` use an observer instead of its own copy of the
   BFS?
10. Why force a real PID reuse rather than simulating one?

<details>
<summary>Answers</summary>

1. Because a non-interactive bash sets SIGINT to "ignore" for background
   jobs and BCC's tools inherit that, so SIGINT is silently discarded.
   SIGTERM is not ignored, and `hids.monitor` treats it exactly like Ctrl+C
   so the stats are still written.
2. Because a BPF program's lifetime is tied to the file descriptors holding
   it; when the process dies the kernel closes them and detaches the
   programs, whatever killed it.
3. Whether the machine drifted during the run — thermal state, page cache,
   another process. It prevents quoting a percentage against a baseline that
   has since moved, which is how the `find` numbers were briefly
   misinterpreted.
4. As a control: if BCC's own exec tracer costs about the same, the cost is
   inherent to exec tracing on this kernel rather than something our design
   introduced.
5. Precisely because it calls none of them. Any slowdown it shows cannot be
   the cost of our record-keeping, so it isolates the per-syscall tax of
   enabling syscall tracepoints at all.
6. Flat: the tax is paid once, so hook count is not worth optimising and
   the remaining target is the Python cost. Rising: each hook costs, hooks
   become a budget, and alternatives (sched/LSM/fentry, a newer kernel) move
   onto the table. Either answer decides the Phase-2 architecture.
7. A check that cannot fail is not a check — so every check is proven to
   FAIL on a deliberately damaged run. Most recently, the inbound
   host-keyed identity check passed vacuously when there were no inbound
   connections at all, because "all ids are the same" is trivially true of
   an empty set.
8. Because a hard-coded port can be in use on a shared machine, making the
   test flaky; and because the analyzer asserting against the published
   value means the demo can change its ports or paths without the analyzer
   changing at all.
9. Because a teaching copy of an algorithm drifts from the real one and then
   teaches the wrong thing. The observer guarantees the trace *is* the real
   walk.
10. Because a test that passes only because the event never happened is
    worthless. Forcing the reuse means the generation code is exercised
    against the real kernel behaviour rather than our model of it.

</details>

Next: `08_TESTS.md` — reading the suite as the specification it is.
