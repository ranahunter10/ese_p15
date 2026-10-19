# Stage 8 — `tests/`, read as a specification

The suite is bigger than the code it tests, and that ratio is the point: it
is where the project's claims are written down in a form that fails when
they stop being true. Read it to learn *what the system promises*, not to
learn Python testing. Budget 3–4 hours.

| file | lines | tests | what it specifies |
|---|---|---|---|
| `test_graph.py` | 666 | 56 | identity, PID reuse, the walks, snapshots |
| `test_processor.py` | 590 | 50 | assembly in any order, classification, counters |
| `test_adversarial.py` | 518 | 21 | the time laws, under attack and under fuzz |
| `test_system.py` | 523 | 20 | the whole runtime against a fake kernel |
| `test_scripts.py` | 349 | 15 | the shell scripts, run for real |
| `test_layout.py` | 331 | 16 | the C↔Python ABI, compiled and compared |
| `test_analyzer.py` | 256 | 4 | that the analyzer's checks can fail |
| `test_overhead.py` | 426 | 11 | the readings the overhead analyzer draws, and that it refuses to draw one it cannot support |
| `test_process_run.py` | 54 | 1 | a real subprocess end to end |
| `helpers.py` | 117 | — | `World`, `FakeClock`: the vocabulary the tests speak |

```bash
./run_tests.sh                  # all of it, no root, ~50 s
python3 -m unittest tests.test_graph -v | head -40
```

---

## 8.1 `helpers.py` first — the vocabulary

Read this before any test file. `World` tracks fake processes so a test
reads like a story:

```python
w = World()
w.spawn(1, 0, "systemd", 1 * SEC)
w.spawn(100, 1, "bash", 10 * SEC)
p.handle(w.open(100, 11 * SEC, "/tmp/x", os.O_WRONLY, 3, ino=77, dev=8))
p.handle(w.accept(100, 12 * SEC, "10.0.0.9", peer_port=45192))
```

Every builder produces the **decoded form of a real record** — the same
namedtuple `decode()` would return from kernel bytes. So a test exercises
the real processor, the real graph and the real classification logic, with
only the kernel replaced.

`FakeClock` stands in for both `events.Clock` (formatting) and
`time.monotonic` (timeouts), so a test can advance time by three seconds
without sleeping. Note `clock.now += 3.0` — the clock is callable and its
state is a plain attribute, which is all a fake needs to be.

## 8.2 How to read a test as a specification

Take one and read it in four parts:

```python
def test_refused_connect_is_counted_apart_and_creates_no_causal_edge(self):
    # A refused connect is evidence (scanning), but nothing flowed:
    # it must not become a path a root-cause walk can follow.
    w, g, p, log, _ = setup()
    p.handle(w.connect(1390, 21 * SEC, "10.0.0.9", 22, ret=-111))
    self.assertEqual(p.counts["CONNECT_FAILED"], 1)
    ...
    self.assertEqual([k for _, k, _, _ in g.trace_back(node)], ["FORK", "FORK"])
```

1. **The name is the claim.** If you cannot state the promise from the name
   alone, the name is wrong — that is the standard in this suite.
2. **The comment is the reasoning**, usually the threat-model sentence that
   explains why the claim matters.
3. **The body is the smallest world** in which the claim is meaningful.
4. **The assertions include a negative.** This test does not only count the
   failure; it asserts the walk contains *no* CONNECT edge. Most real bugs
   are things that should not be there.

Spend your time on the names and comments: `grep -n "def test_"
tests/test_graph.py` is a readable specification of the graph, in about
sixty lines.

## 8.3 The five kinds of test here, and what each one is for

### Behaviour

Ordinary: given these events, this is the state. Most of
`test_graph.py` and `test_processor.py`.

### Property / fuzz

`test_adversarial.py::FuzzTest` builds a random world, **shuffles the
arrival order**, and asserts invariants rather than outcomes: no cause in
the future, no effect before its cause, `first_ns ≤ every event seen`. Five
seeds × fifteen trials, ~20 walk roots each.

This is the test that *found* a bug (H3) rather than confirming a fix.
Property tests earn their keep when the input space is too large to
enumerate — and 5! orderings of one exec is already too large to write by
hand, which is why `test_processor` enumerates those exhaustively instead.

### Differential / parity

`test_layout.py` compiles the real C structs with **gcc** and compares
every offset against `ctypes`. Two independent descriptions of the same
layout, checked against each other — the only way to be sure a mirror has
not drifted. This caught a documented-416-actually-392 error.

The same file also checks our minimal `sockaddr` copies against
`<netinet/in.h>` and `<sys/un.h>`, with the invariant stated honestly as
**"same offsets, never longer"** after the first version wrongly demanded
equal sizes (our `sa_in_t` is 8 bytes where the real one is 16, because we
never read the padding).

### Meta / drift guards

Tests about the project rather than the code:

- `FixedTmpPathTest` — scans every test and script for a shell redirect to
  a literal `/tmp` path. Three separate VM failures came from that pattern;
  it immediately found a fourth instance.
- `test_type_filter_offers_every_event_type_that_is_emitted` — extracts
  every `_emit("...")` type from `processor.py` and every `--type` choice
  from `monitor.py` and asserts the sets are equal. It caught the missing
  `--type accept` within an hour of being written.
- `test_sizes_quoted_in_docs` / `test_endpoint_default_matches_the_documented_budget`
  — the documentation is part of the contract, so numbers quoted in docs are
  asserted against the code.

A drift guard is cheap and catches a class of bug rather than an instance.
When you find yourself fixing the same *kind* of mistake twice, write one.

### Integration with a fake kernel

`test_system.py` replaces the `bcc` module with a fake that replays a
scripted byte stream, then calls `monitor.main()`. Argument parsing, feature
fallback, the poll loop, the stats block, the snapshot — all exercised
without root. `test_scripts.py` does the same for the shell scripts, with a
fake tracer that **ignores SIGINT exactly like BCC's tools do**, which is
how the hanging bug stays fixed.

## 8.4 Mutation testing, by hand

The project's rule: a fix is not proven by a passing test, it is proven by a
test that **fails when the fix is reverted**. Do this yourself — it is the
single most useful hour in this stage.

```bash
# 1. revert the v3.4 WRITE-edge fix: in graph.py, trace_back's file branch,
#    change  if (self._ident(w), WRITE) != via:
#    to      if self._ident(w) not in seen:
python3 -m unittest tests.test_graph tests.test_analyzer 2>&1 | tail -5
#    -> the regression test fails AND the analyzer's own "good run" fails,
#       with the same evidence string shape as the 13-Oct VM output

# 2. revert the H1 fix: drop the `if ts >= t:` guard on the forward FORK
python3 -m unittest tests.test_adversarial 2>&1 | tail -5
#    -> 2 tests fail, one of them the fuzz

# 3. revert the H3 fix: delete the `first_ns = min(...)` line in _touch
python3 -m unittest tests.test_adversarial 2>&1 | tail -5
#    -> 3 tests fail

# 4. break a struct: swap two fields in events._COMMON_FIELDS
python3 -m unittest tests.test_layout 2>&1 | tail -5
#    -> the offset comparison names the field that moved
```

Predict which tests will fail *before* running each one. Where your
prediction is wrong, you have found the part of the system you do not yet
understand — which is the whole purpose of this exercise.

## 8.5 What the suite deliberately does not do

Be able to say this, because it is the honest boundary of every claim in the
repo:

- **It does not run eBPF.** No verifier, no real kernel. `test_layout.py`
  type-checks the C with gcc in all six hook/feature combinations, which is
  not the same as the verifier accepting it. Only the VM proves that.
- **It does not measure overhead.** `test_overhead.py` checks that the
  *analyzer* reads timings correctly, not that any real number is true. Two
  of its tests feed it the recorded rows of actual VM runs — the 16-Oct
  ladder that had to be refused, and the v3.5g one that resolved it — so
  what is pinned there is the **reading**, not the measurement.
- **It does not test the device-specific**: 2-vCPU behaviour, loss at a
  given page count, glibc's choice of `accept` vs `accept4` on the VM's
  libc version.

Hence the status table in the README, and the rule that an item is "not yet
tested" until it has run on the VM, however many unit tests cover it.

## 8.6 Testing a measuring instrument, which is a different problem

`test_overhead.py` is the odd one out: the thing under test is not a feature
but a *claim about a number*. Three ideas there are worth being able to
explain, because the overhead chapter of the report rests on them.

**A control whose answer is known in advance.** `analyze_overhead.control()`
reads every baseline run as though it were a configuration. A baseline has
no tracer attached, so its true slowdown is zero *by construction* —
whatever the method reports for it is the method's own error. On the v3.5g
run that came to worst 6.3 %, mean 3.6 %, from 13 controls. Every effect in
the table is then either above that floor or not claimed. This is the same
"a check that cannot fail is not a check" rule as everywhere else in the
project, turned on the measuring device instead of the system.

**Making rival explanations predict numbers.** "Is the cost flat or rising?"
cannot be settled by looking at a column, because a reader finds the shape
they expected. So each model is made to predict the top rung from the bottom
one: an unchanging cost predicts that 12 hooks cost what 2 do (+11 %);
a per-hook cost predicts 6× (+82 %). Measured: +17 %. The models are 65
points apart and the noise floor is 6, so the verdict survives even though
the individual rung-to-rung steps do not. `test_a_genuinely_rising_ladder_is
_read_as_per_hook` feeds in data where the *other* model wins, because a
verdict that can only come out one way is not a verdict.

**A divisor is a claim too.** The per-operation figures were twenty times too
large for one run because the syscall count was hardcoded while the workload
size was a parameter. The guard that catches that class of error is printing
the *baseline* cost of the same operation next to the added cost: an untraced
syscall priced at 2.55 µs is visibly absurd, and 128 ns is visibly right.
When you quote a derived number, quote the thing it was divided by.

Exercise: break the control. Change one `base_after_*` value in a recorded
`timings.csv` by 30 % and re-run the analyzer. The instrument-check line
should report a worse floor, and the ladder should go INCONCLUSIVE once the
floor exceeds the ladder's range. Predict which happens before you run it.

---

## Self-check

1. Why is `World` built on decoded records rather than on direct graph
   calls?
2. What does a good test name in this suite look like, and why does it
   matter more than the assertions?
3. Why does `test_processor` enumerate all 120 orderings exhaustively while
   `test_adversarial` fuzzes instead?
4. What is a differential test, and which one in this suite caught a real
   error?
5. Why is the sockaddr invariant "same offsets, never longer" rather than
   "same size"?
6. Name two drift guards and the class of bug each prevents.
7. What is the project's standard of proof for a fix?
8. The suite is 239 tests and all pass. Name three things that proves
   nothing about.

<details>
<summary>Answers</summary>

1. Because building the decoded form exercises the real processor, graph and
   classification logic — only the kernel is replaced. Calling graph methods
   directly would skip the layer where most classification bugs live.
2. A sentence stating the promise: "refused connect is counted apart and
   creates no causal edge". It matters more because the name is what a
   future reader (or a reviewer) reads as the specification; the assertions
   are just the mechanism.
3. 5! = 120 is small enough to enumerate, so exhaustive is strictly better —
   it proves the property rather than sampling it. The graph's input space
   (arbitrary worlds, arbitrary orders) is unbounded, so there a seeded
   random search with invariant checks is the only option.
4. Two independent descriptions of the same thing, checked against each
   other. `test_layout.py` compiles the C with gcc and compares offsets
   against ctypes; it caught a struct documented as 416 bytes that was
   actually 392.
5. Because our copies deliberately omit trailing padding we never read: our
   `sa_in_t` is 8 bytes where the real `sockaddr_in` is 16. Demanding equal
   size failed on a correct implementation, so the invariant was restated to
   what actually matters — every field at the same offset, and never reading
   past the real struct.
6. `FixedTmpPathTest` (writes to a fixed path in a world-writable directory,
   which caused three VM failures) and the `--type` drift guard (a new
   record type added without its CLI filter choice). Each prevents a *kind*
   of mistake rather than one instance.
7. The test must fail when the fix is reverted. A passing test alone does
   not establish that it tests the fix.
8. That the eBPF program passes the verifier; that any overhead number is
   true; and that device-specific behaviour (loss at a given page count,
   which `accept` syscall the VM's glibc issues, 2-vCPU timing) is as
   assumed.

</details>

---

## You have finished the route

Two closing exercises, both worth doing before the next advisor meeting.

**1. Trace one event all the way through, out loud.** Pick
`cat /etc/hostname`. Name every file it touches, in order: which probes
fire, which records are produced, how they are joined, which identity
functions run, which nodes and edges appear, what the log line contains,
and what a `trace` query would return. If you can do that without notes,
you know the system.

**2. Answer the four questions from `00_MASTER.md` for the whole system.**
Who did this (and why a PID is not the answer); to what (and why a path is
not the answer); can I trust this value (and which values are kernel truth);
what did it cost (and why that one is still unanswered until the ladder
runs).

The last one is the honest gap, and saying so plainly is what has made every
review of this project land well.
