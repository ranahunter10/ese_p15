# ESE-P15 — study route

A guide for reading the whole system line by line and being able to defend
every line of it. It does not restate the code or the other docs; it tells
you **what to read, in what order, what to look for, and how to prove to
yourself that you understood it.**

## How to use this

Each stage has the same five parts:

1. **Read** — exactly which file and which block, found by symbol rather
   than by line number (line numbers go stale; `grep -n` does not).
2. **The mechanism** — what the machine actually does, including the parts
   the code cannot say out loud.
3. **Why this way** — the alternative that was rejected, and what it would
   have cost. This is the part an examiner probes.
4. **Experiments** — things to run. Marked `[laptop]` or `[VM]`: anything
   involving BPF needs the VM, everything else runs anywhere.
5. **Self-check** — questions to answer out loud, with answers at the end
   of each stage. If an answer needs the code open in front of you, you
   have not finished that stage.

Bring me questions as they come up — that is what this format is for. The
useful shape is "I read `<symbol>` in `<file>` and I expected X, but it
does Y" rather than "explain `graph.py`".

## Honest size and pace

| Layer | Lines | Expect |
|---|---|---|
| `hids/bpf/monitor.bpf.c` | 794 | 5–7 h. The hardest, because the rules are not C's rules |
| `hids/graph.py` | 1,017 | 5–7 h. The identity algorithm and the walks are the project's IP |
| `hids/processor.py` | 390 | 2–3 h. One state machine, several subtle invariants |
| `hids/events.py` | 376 | 2 h. A byte-exact contract with the kernel |
| `hids/monitor.py`, `procstat.py`, `view.py` | 574 | 2–3 h |
| `tools/` | 1,551 | 3–4 h. Mostly measurement discipline, not algorithms |
| `tests/` | 3,800 | 3–4 h, read as a specification rather than as code |

**~8,500 lines, 20–30 hours.** You wrote most of the decisions, so some of
it will read fast; `graph.py`'s walks and the kernel's exec assembly will
each take an afternoon on their own.

A workable pace is one stage per sitting, in order. The order follows the
data — kernel → bytes → assembly → graph → tools — because each stage
explains the next stage's inputs, and because that is the order you will
explain it in when someone asks "how do you know that number is true".

## The route

| Stage | File | Covers | Status |
|---|---|---|---|
| 1 | `01_FOUNDATIONS.md` | eBPF, tracepoints, the verifier, per-CPU perf buffers, clocks, the C and Python you need | **written** |
| 2 | `02_KERNEL_C.md` | all 794 lines of `monitor.bpf.c`, in three passes | **written** |
| 3 | `03_EVENTS.md` | `events.py`: the ABI contract, byte order, identity functions | **written** |
| 4 | `04_PROCESSOR.md` | `processor.py`: `ExecAssembler`, dispatch, counters, logging | **written** |
| 5 | `05_GRAPH.md` | `graph.py`: PID generations and the causal walks, with five dry runs | **written** |
| 6 | `06_RUNTIME.md` | `monitor.py`, `procstat.py`, `view.py`: the loop that holds it together | **written** |
| 7 | `07_TOOLS.md` | the measurement rig, the analyzers, the query CLI | **written** |
| 8 | `08_TESTS.md` | reading tests as the specification they are | **written** |

## The dry-run tool

Stage 5 is built around `tools/walk_trace.py`, which prints every decision a
causal walk makes — what it popped, which time bound it carried, what it
listed, what it suppressed and why:

```bash
python3 tools/walk_trace.py --demo write-then-read
python3 tools/walk_trace.py --demo two-reads-two-writers
python3 tools/walk_trace.py runs/g.json trace 1390 --no-libs
```

It does not reimplement the algorithm: it passes a printing observer into
the real `trace_back`/`trace_forward`, so a dry run cannot drift from the
code it is teaching.

## What you already have, and should not re-read as prose

- `docs/ARCHITECTURE.md` — the function-by-function walkthrough. The study
  guide **routes** you into it rather than repeating it.
- `docs/CONCEPTS.md` — the OS / eBPF / C / Python ideas, with the
  byte-order, sockets, clocks and `accept` sections written as teaching
  text already.
- `docs/CHANGES_v3*.md` + `docs/WORKLOG_2026-10-13.md` — *why* things are
  the way they are, including the bugs that forced each decision. When a
  line looks over-careful, the reason is usually in a numbered Journal row.

## The four questions to hold in your head

Every piece of this system is an answer to one of these. If you can say
which one a block of code serves, you understand it:

1. **Who did this?** — PID is not an identity (it gets reused), so what is?
2. **To what?** — a path is not a file (relative, renamed, symlinked), so
   what is?
3. **Can I trust this value?** — who wrote it: the kernel, or the process
   being watched?
4. **What did it cost?** — every hook taxes every syscall on the box, and
   an unmeasured cost is an unmade claim.

## Vocabulary you must be able to define without hedging

Keep a list as you go; by the end of stage 5 you should be able to define
all of these cold: *tracepoint, kprobe, verifier, per-CPU array, perf ring
buffer, `pid_tgid`, tgid vs pid vs tid, `task_struct`, `start_time`,
CLOCK_MONOTONIC vs CLOCK_REALTIME, fd table, `struct file`, inode,
`i_generation`, `s_dev`, `probe_read`, user vs kernel memory, PID
generation, placeholder node, inferred exit, reparenting, provenance graph,
BFS, time bound, last-write-wins, dependency explosion, ephemeral port,
TOCTOU.*
