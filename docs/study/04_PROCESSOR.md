# Stage 4 — `hids/processor.py` (390 lines)

One state machine and a dispatcher. The state machine exists for a single
reason — **records arrive in any order** — and understanding it properly is
the difference between believing that and designing for it. Budget 2–3
hours.

```bash
grep -n "^class \|^    def \|^def \|^PENDING\|^MAX_PENDING" hids/processor.py
```

---

## 4.1 The problem, stated precisely

One `execve` produces up to 23 records from two different probes (stage 2,
C.1). Those records are written to **per-CPU** ring buffers, and `execve`
*deliberately migrates the process*, so:

- `EXEC_OK` routinely arrives **before** its own `EXEC_ENTER`;
- `ARG` records can arrive after the exec they belong to was committed;
- any of them can be lost entirely if a ring overflows.

A design that assumed order would produce execs with no arguments, or
arguments attached to the wrong exec. So nothing in this file may depend on
arrival order — only on the content of the records.

**The join key is `(pid, enter_ts)`.** The enter probe stamps its own
timestamp into every `ARG` record's `enter_ts`, and `sched_process_exec`
carries the same value in `aux_ns` (looked up via `old_pid`). All four
record kinds therefore name the same exec attempt by a value that was
decided in the kernel, not by when userspace happened to see them.

---

## 4.2 `_Pending.complete()` — the whole correctness condition in one line

```python
return (self.enter is not None and self.ok is not None and self.ended
        and len(self.args) >= self.count)
```

Read it as four independent facts that must all have arrived:

| condition | what it proves |
|---|---|
| `enter is not None` | we know what was attempted (path, dfd, flags) |
| `ok is not None` | the exec **succeeded** (otherwise it is a failed exec) |
| `ended` | the END record arrived, so argv is known to be finished |
| `len(args) >= count` | and all `count` of those arguments are actually here |

This is why the kernel always emits an END record carrying the count
(stage 2). Without it, "all the arguments have arrived" is unknowable —
you cannot distinguish "argv had 3 entries" from "argv had 7 and 4 are
still in flight".

> `>=` rather than `==` is deliberate: a duplicate ARG (same index twice)
> must not stall the commit forever.

Each handler — `enter()`, `arg()`, `ok()` — does the same three things:
find or create the `_Pending` for that key, record its piece, and commit
**if and only if** the condition above now holds. Which record completed
the set is irrelevant, which is exactly the property we want.

---

## 4.3 The three awkward realities, and the mechanism for each

### `ok` with no `enter` (`aux_ns == 0`)

```python
if ev.aux_ns == 0:
    self.on_exec(None, ev, [], False)
    return
```

Happens when we attached mid-exec, when the LRU evicted the enter
timestamp, or for an exec path we do not hook. The choice: commit what we
know (a program ran, no argv) rather than discard it. **Partial truth,
labelled as partial** — the log entry carries `enter_seen: false`, which the
run analyzer counts.

### Late `ARG` after the exec was already committed

```python
rec = self.done.get(key)
if rec is not None:
    self.late_args += 1
    ...
    _place(rec.argv, a.idx, a.arg)
```

`done` is a bounded LRU (`keep_done=4096`) of recently committed
`ExecRecord`s. A late argument cannot change the log line — that is already
written — but it *can* still be patched into the graph's record, because
the graph holds the same object. So the forensic store gets the complete
command line even when the live log did not. `late_args` is counted so this
is visible rather than silent.

### Nothing ever completes

`expire()` settles anything older than `PENDING_TIMEOUT_S` (2 s):

```python
if p.ok is not None:  self._commit(key, p)   # succeeded, partial argv
else:                 self.on_failed(p.enter) # never succeeded: EXEC_FAILED
```

The absence of `ok` after two seconds is the *evidence* that the exec
failed. Note the `break` in the loop — `pending` is an `OrderedDict` in
insertion order, so once an entry is young enough, every later one is too.
That turns expiry from O(pending) into O(expired).

And `MAX_PENDING = 20000` with `self.forced` counting: if records are being
lost in bulk, pending entries would grow without bound, so the oldest is
force-settled. A monitor that OOMs under load is a monitor that stops
monitoring exactly when it matters.

---

## 4.4 `EventProcessor` — two invariants worth more than the code

### It never raises

```python
def handle(self, rec):
    self.counts["raw"] += 1
    try:
        self._dispatch(rec)
    except Exception:
        self.counts["errors"] += 1
        if self.first_error is None:
            self.first_error = traceback.format_exc()
```

One malformed record must not stop the stream — a monitor that dies on
surprising input is worse than one that counts surprises. Note what it does
*not* do: it does not swallow the error silently. The count is in the stats
and the **first** traceback is kept (the first, not the last, because the
first failure usually explains the rest).

Be ready to defend this, because "catching bare `Exception`" is a code
smell in most contexts. The defence: this is the boundary between untrusted
input and our logic, the failure is counted and reported, and the
alternative — a dead monitor — loses more evidence than the bad record
contained.

### The `--no-log` fast path

```python
def _emit(self, etype, ev, node, **extra):
    if not self.output:
        return
```

First line of the function, before any formatting. An audit found v3.1
building lineage strings for events nobody would ever read; in a run with
no log that was the single largest avoidable cost. Measure-then-fix, and
the `--sink count` mode exists to measure the remaining kernel-side cost
with userspace work removed entirely.

---

## 4.5 The handlers, and where interpretation lives

Read `_exec_done`, `_open`, `_exit`, `_connect`, `_accept`. Each one is
thin, and all of them follow the same shape: resolve the node, compute an
identity, record it in the graph, count it, emit a log line.

The thing to notice is **what the kernel did not decide**. The kernel
copies facts; every judgement is here, in testable Python:

| judgement | where | why not in the kernel |
|---|---|---|
| is this a read or a write? | `open_mode(flags)` | flag semantics (`O_TRUNC`) are policy, not data |
| did this connect succeed, fail, or is it in flight? | `_connect` | three-way split from `ret` + a flag |
| is this a DNS probe rather than a connection? | `_connect`'s `probe` rule | heuristic (port 0 + datagram), and heuristics belong where they can be tested and changed |
| is this inbound? | `_dispatch` on `NET_FLAG_INBOUND` | one record type, two meanings |
| which generation of this PID is this? | `graph.process()` | needs history the kernel does not keep |

This is the architectural decision the reviews keep praising, and you
should be able to state it in one sentence: *the kernel stays dumb so that
everything debatable is unit-testable.*

---

## 4.6 Dry run — the 120 orders test

The test that proves the whole design:

```bash
grep -n "permutation\|itertools" tests/test_processor.py | head
python3 -m unittest tests.test_processor -v 2>&1 | grep -i order
```

One exec emits five records (ENTER, ARG×2, ARG-END, OK). The test replays
**all 5! = 120 orderings** and asserts the committed result is identical
every time. That is not thoroughness for its own sake: per-CPU delivery
means several of those orders genuinely occur in production.

Trace two of them by hand before reading the test, and check your
prediction against `complete()`:

| arrival order | state after each record |
|---|---|
| ENTER, ARG0, ARG1, END, OK | pending grows; `complete()` false until OK; commit on OK |
| OK, END, ARG1, ARG0, ENTER | `_get` creates the pending on OK (keyed by `aux_ns`); `ended` set by END; args fill in; commit fires on ENTER — the *first* record is the last piece |

The second row is the one people get wrong when they first read this file,
and it is the common case in a real run.

---

## Experiments

`[laptop]` Watch a reordered exec assemble:

```bash
python3 -m unittest tests.test_processor -v 2>&1 | head -30
```

`[laptop]` Prove the timeout path:

```bash
python3 -c "
import sys; sys.path.insert(0,'tests'); sys.path.insert(0,'.')
from helpers import World, FakeClock, SEC
from hids.graph import ProcessGraph
from hids.processor import EventProcessor
import io
w = World(); w.spawn(1,0,'systemd',1*SEC); w.spawn(100,1,'bash',10*SEC)
clock = FakeClock(); log = io.StringIO(); g = ProcessGraph()
p = EventProcessor(g, clock, log_file=log, mono=clock)
recs = w.exec_records(100, 11*SEC, 12*SEC, '/bin/nope', ['nope'], 'nope')
p.handle(recs[0])              # ENTER only: no OK will ever come
print('pending before:', len(p.assembler.pending))
clock.now += 3.0; p.tick()     # past PENDING_TIMEOUT_S (FakeClock is callable)
print('pending after :', len(p.assembler.pending))
print('counts        :', {k:v for k,v in p.counts.items() if v})"
```

`[VM]` See `late_args` happen for real — a busy exec burst is the usual
trigger:

```bash
sudo python3 -m hids.monitor --mode quiet --duration 30 --stats-json /tmp/s.json &
for i in $(seq 1 500); do /bin/true; done
python3 -c "import json; s=json.load(open('/tmp/s.json')); print('late_args', s['late_args'], 'forced', s.get('forced_settles'))"
```

---

## Self-check

1. Why can `EXEC_OK` arrive before `EXEC_ENTER`, and why is that normal
   rather than exceptional?
2. What is the join key, and why is it decided in the kernel rather than in
   userspace?
3. Name the four conditions in `complete()` and what each one proves.
4. Why does the kernel need to send an END record when the count is already
   in `idx`?
5. `aux_ns == 0` — what happened, and what does the processor do?
6. An ARG arrives for an exec that was already committed. Where does it go,
   and what cannot be fixed at that point?
7. Why does `expire()` `break` out of its loop instead of scanning
   everything?
8. What is the evidence that an exec failed?
9. `handle()` catches bare `Exception`. Defend it.
10. Give three judgements that are made in this file and explain why none of
    them belongs in the kernel probe.

<details>
<summary>Answers</summary>

1. The two records come from different probes into per-CPU ring buffers,
   and `execve` migrates the process between CPUs, so they land in
   different rings with no ordering between them. Normal, not exceptional —
   which is why the design is order-free rather than order-tolerant.
2. `(pid, enter_ts)`. The enter probe's own `bpf_ktime_get_ns()` value is
   stamped into every ARG record and recovered by `sched_process_exec` via
   `old_pid`, so every piece names the attempt by a kernel-decided value.
   Userspace has no reliable way to group records it may receive backwards.
3. `enter` — what was attempted; `ok` — that it succeeded; `ended` — that
   argv is finished; `len(args) >= count` — that all the arguments arrived.
4. Because arrival order carries no information: you cannot tell "argv had
   3 entries" from "argv had 7 and 4 are still in flight". The END record
   states completeness explicitly, and carries the count and the truncation
   flag.
5. There was no matching enter in the kernel map — attached mid-exec, LRU
   eviction, or an unhooked exec path. The processor commits what it knows
   (program ran, no argv) with `enter_seen: false`, rather than dropping a
   real exec.
6. Into the `done` LRU's `ExecRecord`, which the graph also references, so
   the graph's command line becomes complete. The already-written log line
   cannot be fixed; `late_args` counts the occurrence.
7. `pending` is an `OrderedDict` in insertion order, so the first entry
   young enough to keep guarantees every later entry is younger. Expiry is
   then O(expired) rather than O(pending).
8. The *absence* of an `EXEC_OK` for more than `PENDING_TIMEOUT_S` (2 s)
   after the enter record. Failure is proven by a timeout, not by a
   record — there is no "exec failed" tracepoint.
9. This is the boundary between untrusted kernel-fed input and our logic. A
   malformed record must not kill the stream, because a dead monitor loses
   far more evidence than one bad record contains. It is not silent: the
   error is counted and the first traceback kept, so the failure is visible
   in the stats.
10. Read/write classification (flag semantics are policy — `O_TRUNC`),
    connect outcome three-way split, and the DNS-probe heuristic. None
    belongs in the kernel because each is a judgement that may be wrong and
    must therefore be unit-testable and changeable without touching
    verifier-constrained code.

</details>

Next: `05_GRAPH.md` — the identity algorithm and the walks, with dry runs
produced by the real code.
