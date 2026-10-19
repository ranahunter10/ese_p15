# Stage 5 — `hids/graph.py` (1,017 lines)

The project's intellectual property. Two algorithms live here and they are
independent: **identity** (which process is this, really?) and **causal
walks** (what caused this, what did it affect?). Read them separately —
most confusion about this file comes from trying to hold both at once.

Budget 5–7 hours, split across two sittings. Every dry run below was
produced by the real code, not written by hand: `tools/walk_trace.py`
passes a printing observer into the actual walk, so what you read is the
algorithm explaining itself.

```bash
grep -n "^class \|^    def \|^FORK\|^CONNECT\|^ACCEPT\|^MAX_" hids/graph.py
```

---

# Part 1 — Identity

## 5.1 Why a PID is not an identity

A PID is a small integer the kernel reuses. On Linux the default ceiling is
32768 (`/proc/sys/kernel/pid_max`), so on a busy host PIDs wrap in minutes.
If the graph keyed on PID:

- a file written by the *previous* holder of PID 777 would be attributed to
  the current one;
- a causal walk would travel through a boundary where nothing flowed;
- and the error is invisible — both nodes look equally plausible.

The audit found exactly this in v2 (`test_pid_reuse.py` in the project
docs is the deterministic proof).

**The fix: identity is `(pid, start_time)`.** The kernel gives us
`task->start_time` on every record (stage 2, B.1) — monotonic nanoseconds,
set once at fork, unchanged by exec. Two processes can share a PID; they
cannot share a PID *and* a start time.

Internally the node key is `(pid, generation)` where generation counts
0, 1, 2… per PID, because a small integer is cheaper to carry around than a
64-bit timestamp — but the *decision* about which generation a record
belongs to is always made by comparing start times. Read `find()` and
`_new_node()` together to see that.

## 5.2 Dry run: `process()` across a PID reuse

Produced by replaying real events through the real graph. `~` marks an
estimated (`/proc`-derived) start time.

```
1. bootstrap from /proc (estimated starts)
   systemd(1) gen=0 start=0s~ alive ; bash(500) gen=0 start=5s~ alive
   current={1: gen 0, 500: gen 0}

2. first real event for pid 500 (exact start)
   systemd(1) gen=0 start=0s~ alive ; bash(500) gen=0 start=5s alive
   current={1: gen 0, 500: gen 0}
                           ^^^ same node, estimate REPLACED by the exact value

3. pid 777 forked by 500
   ... ; cat(777) gen=0 start=200s alive
   current={..., 777: gen 0}

4. 777 writes a file and exits
   ... ; cat(777) gen=0 start=200s exited@202s
   current={..., 777: gen 0}        <-- still here: history survives exit

5. pid 777 REUSED by a different process
   ... ; cat(777) gen=0 start=200s exited@202s ; nc(777) gen=1 start=900s alive
   current={..., 777: gen 1}        stats={generations: 1}
                           ^^^ a SECOND node for the same PID

6. a LATE record from the old 777 arrives
   ... unchanged ...
   current={..., 777: gen 1}        stats={generations: 1}
                           ^^^ the late record did NOT take over `current`
```

Five mechanisms, one per step. Find each in the code and be able to say why
it is there:

| step | mechanism | what breaks without it |
|---|---|---|
| 1 | `bootstrap()` creates nodes with `start_exact=False` | processes that existed before we attached have no lineage at all |
| 2 | **adopt-and-upgrade**: the first real event replaces the estimate in place | a second node for a process we already knew, splitting its history |
| 4 | the node survives `record_exit` | "the process died but created a file" — the advisor's own example — becomes unanswerable |
| 5 | **new generation** when a record's start time disagrees with the current node | the new process inherits the old one's files and connections |
| 6 | `_set_current_if_newer` — only a *newer* lifetime takes over `current` | a late record from the dead generation would redirect new events into it |

### Read, in this order

`find` → `_new_node` → `_parent_key` → `_set_current_if_newer` → `process`
→ `_reparent` / `_relink` → `bootstrap`.

Four more things in `process()` worth stopping on:

1. **The rename guard.** `if ts_ns >= node.last_ns:` before updating `comm`.
   A late pre-exec record must not turn `cat` back into `bash`
   (Journal row 12). You met this rule in stage 2's placeholder test.
2. **`first_ns` is lowered**, not only `last_ns` raised. The arrival-order
   bug (H3) lived here; see 5.9.
3. **Placeholders.** A child can be seen before its parent, so
   `_parent_key` creates a node with an estimated start rather than
   dropping the edge — and `lineage` therefore never contains `?(pid)`,
   which was a v2 regression the analyzer still checks for.
4. **Inferred exits.** When a PID's owner changes with no exit event, the
   old generation is marked exited at `_fork_ts(new)` — provable, because a
   PID is not reused until its previous holder is gone (`CHANGES_v3.5.md`
   row 103).

## 5.3 The node model

| node | key | why that key |
|---|---|---|
| `ProcessNode` | `(pid, generation)` | identity, 5.1 |
| `FileNode` | `inode:<dev>:<ino>:<gen>`, else `path:/abs` | a path is a name; the inode is the file |
| `EndpointNode` | `net:<addr>:<port>` / `host:<addr>` / `unix:<path>` | the peer is what a connection is *to* |

`FileNode` and `EndpointNode` are deliberately the same shape: both are
**passive resources** identified by what they are, holding an `accesses`
list of `(ts, process_key, kind)`. That symmetry is what makes "who else
touched this?" one query rather than two.

`FileNode` carries a **second** list, `writes`, and the reason is a bug:
reads and writes shared one capped list, so a file read 2 000 times after
being written once lost the write, and a backward walk then reported *no
writer at all*. Reads are floods and writes are rare, so the causal subset
gets its own smaller cap (`MAX_WRITES_PER_FILE`) and cannot be evicted by
activity. `CHANGES_v3.5.md` row 117.

`ProcessNode.__slots__` is worth a minute: with hundreds of thousands of
instances, suppressing per-instance `__dict__` is the difference between a
sane footprint and an absurd one (stage 1, §1.7). The measured cost per node
is in `ARCHITECTURE.md` §7.

---

# Part 2 — The walks

## 5.4 What a provenance walk is

The graph is a directed graph whose edges follow **information flow**:

```
FORK      parent  -> child         (the child exists because the parent forked)
READ      file    -> process       (bytes went from the file into the process)
WRITE     process -> file          (bytes went from the process into the file)
EXEC      file    -> process       (the process became that file's program)
CONNECT   process <-> endpoint     (a channel the process opened)
ACCEPT    endpoint <-> process     (a channel someone else opened to us)
```

`trace_back` answers *what caused this?* by walking against the arrows;
`trace_forward` answers *what did this affect?* by walking with them. Both
are **breadth-first**, which matters for presentation (nearer causes come
first) and for the depth cap meaning "hops away from the question".

### The two time laws

These are the invariants the fuzz test asserts, and the ones to quote:

> **Backwards:** every edge listed happened at or before the point being
> asked about. A cause cannot be in the future.
> **Forwards:** every edge listed happened at or after it. An effect cannot
> precede its cause.

Each queue entry therefore carries its own **bound** — the timestamp of the
edge that led to it — and every branch filters on it. Bounds shrink as a
backward walk goes deeper, which is also why the walk terminates naturally
on most graphs.

## 5.5 The three suppressions

This is the part that has cost the project a bug every time two of them
were collapsed into one. Memorise the distinction:

| rule | stops | keyed on | if you get it wrong |
|---|---|---|---|
| `seen` | a node being **expanded** twice | `(node, bound)` | keyed on node alone → the second read of a file inherits the first read's writer: a **wrong answer** (H2) |
| `listed` | the same edge being **printed** twice | `(source, kind, ts)` | duplicate lines when a node is expanded at several bounds |
| `via` | an edge that **echoes the link we arrived on** | `(node, kind)` of the incoming edge | the endpoint we just came from is listed as the cause of its own connection |

There is also a **per-resource edge cap** (`MAX_EDGES_PER_RESOURCE`, 8),
which is not a suppression rule but a bound on repetition: a process that
reads one file 2 000 times has 2 000 formal input edges, all describing the
same relationship, and uncapped they filled `max_items` at depth 1 so the
walk never reached the writer. Backward walks keep the newest few per
resource, forward walks the earliest. Dependency explosion by repetition
rather than by fan-out — `CHANGES_v3.5.md` row 118.

And the rule that is *not* there: an already-seen node reached by a
**different kind of edge** is always listed. A parent that writes a file its
child reads is both a FORK and a WRITE; those are two different causal
facts. Gating the listing on `seen` dropped the WRITE and was the v3.4 bug
(`CHANGES_v3.4.md` row 80).

## 5.6 Dry run 1 — parent writes, child reads

The shape of the v3.4 bug, and the clearest illustration of all three
rules. Run it yourself:

```bash
python3 tools/walk_trace.py --demo write-then-read
```

```
  0  START      cat(101)                   bound=14.000s
  1  POP        cat(101)                   bound=14.000s   depth=0 queue=0
  2    emit     FORK  bash(100)            at 12.000s   depth=1 -> queued
  3    emit     READ  inode:8:77:1         at 14.000s   depth=1 -> queued
  4    emit     EXEC  /usr/bin/cat         at 13.000s   depth=1 -> queued
  5  POP        bash(100)                  bound=12.000s   depth=1 queue=2  via=FORK from pid 101
  6    emit     FORK  systemd(1)           at 10.000s   depth=2 -> queued
  7  POP        inode:8:77:1               bound=14.000s   depth=1 queue=2  via=READ from pid 101
  8    choose   WRITE bash(100)            at 11.000s    (1 of 1: last write at or before the bound)
  9    emit     WRITE bash(100)            at 11.000s   depth=2 -> queued
 10  POP        /usr/bin/cat               bound=13.000s   depth=1 queue=2  via=EXEC from pid 101
 11  POP        systemd(1)                 bound=10.000s   depth=2 queue=1  via=FORK from pid 100
 12  POP        bash(100)                  bound=11.000s   depth=2 queue=0  via=WRITE from inode:8:77:1
 13    DEDUP    FORK  systemd(1)           at 10.000s    already reported
     STOP       queue empty: 5 edges, 6 nodes expanded, 0 left queued
                state: seen=6 (node,bound) pairs, listed=5 edges
```

Follow it line by line:

- **Step 1** starts at `cat(101)` with bound 14 s — its own latest activity.
- **Steps 2–4** list its three inputs. All three timestamps are ≤ 14 s: the
  backward law holds.
- **Step 5** pops `bash(100)` *as a parent*, carrying `via=FORK`. Note the
  bound is now 12 s, not 14 s: deeper means earlier.
- **Step 7** pops the file at bound 14 s, and **step 8** is the
  single-cause rule — "1 of 1" here, but see dry run 2.
- **Step 9** lists `WRITE bash(100)` **even though `bash(100)` was already
  expanded at step 5.** This is the line the v3.4 bug suppressed, and the
  entire reason the project's walk reports "who put these bytes here".
- **Step 12** pops `bash(100)` a *second* time, now with bound 11 s and
  `via=WRITE`. The `(node, bound)` key is what permits this.
- **Step 13** is `listed` doing its job: that second expansion found the
  same `FORK systemd(1)` edge at the same timestamp, so it is not printed
  twice.

> **Exercise.** Before reading further: at step 12, why is the bound 11 s
> rather than 12 s? And why does the re-expansion find nothing new?

## 5.7 Dry run 2 — two reads, two writers (the H2 case)

```bash
python3 tools/walk_trace.py --demo two-reads-two-writers
```

A file written at 50 s and 200 s, read at 100 s and 296 s:

```
  0  START      reader(200)                bound=296.000s
  1  POP        reader(200)                bound=296.000s  depth=0 queue=0
  2    emit     FORK  systemd(1)           at 20.000s   depth=1 -> queued
  3    emit     READ  /tmp/g               at 100.000s  depth=1 -> queued
  4    emit     READ  /tmp/g               at 296.000s  depth=1 -> queued
  5  POP        systemd(1)                 bound=20.000s   depth=1 queue=2
  6  POP        /tmp/g                     bound=100.000s  depth=1 queue=1  via=READ from pid 200
  7    choose   WRITE w1(101)              at 50.000s    (1 of 1: last write at or before the bound)
  8    emit     WRITE w1(101)              at 50.000s   depth=2 -> queued
  9  POP        /tmp/g                     bound=296.000s  depth=1 queue=1  via=READ from pid 200
 10    choose   WRITE w2(102)              at 200.000s   (1 of 2: last write at or before the bound)
 11    emit     WRITE w2(102)              at 200.000s  depth=2 -> queued
```

**The same file node is popped twice** — steps 6 and 9 — with bounds 100 s
and 296 s, and each expansion picks a *different* writer: "1 of 1" at the
earlier bound, "1 of 2" at the later one. Both answers are right, for
different questions.

With `seen` keyed on the node alone, step 9 would have been skipped and the
walk would have reported `w1` as the origin of bytes that came from `w2`.
Not a missing edge — a **confident falsehood**, which is the one failure
mode a provenance tool cannot have.

> **Why the obvious optimisation is wrong.** It is tempting to re-expand
> only when the new bound is *wider*, since a wider bound sees more
> history. That reasoning fails here: `max(writes ≤ bound)` changes with the
> bound, so a wider bound does not subsume a narrower one. Be able to say
> this; it is the sharpest question available about this code.

## 5.8 Dry run 3 — crossing the network boundary, and `via`

```bash
python3 tools/walk_trace.py --demo download-write-execute
```

```
 10  POP        curl(100)                  bound=12.000s   depth=2 queue=0  via=WRITE from path:/tmp/payload.sh
 11    emit     FORK  systemd(1)           at 10.000s   depth=3 -> queued
 12    emit     CONNECT net:203.0.113.5:443  at 11.000s   depth=3 -> queued
 13  POP        systemd(1)                 bound=10.000s   depth=3 queue=1
 14  POP        net:203.0.113.5:443        bound=11.000s   depth=3 queue=0  via=CONNECT from pid 100
 15    choose   CONNECT curl(100)            at 11.000s    (1 of 1: last contact at or before the bound)
 16    ECHO     CONNECT curl(100)            at 11.000s    would echo the link we came on
```

The chain `sh → /tmp/payload.sh → curl → net:203.0.113.5:443` is the thing
the whole layer exists to produce: *the file this host executed came from
that address*.

Steps 15–16 are `via`. Arriving at the endpoint through `CONNECT from pid
100`, the endpoint's own single-cause rule picks… `curl(100)`, the process
we just came from. Listing it would restate the step we just took, so it is
suppressed. Compare with step 9 of dry run 1, where re-listing an
already-visited process *was* correct — because that was a **different
kind** of edge.

`ACCEPT` behaves the same way (`--demo inbound`): the inbound chain
`bash(901) → sshd(900) → host:10.0.0.9` lists the peer as a cause of the
shell, then suppresses the echo back to `sshd`.

## 5.9 Dry run 4 — the forward time law

```bash
python3 tools/walk_trace.py --demo forward-time-bound
```

```
  1  POP        /tmp/f                     bound=20.000s   depth=0 queue=0
  2    emit     READ  bash(200)            at 50.000s   depth=1 -> queued
  3  POP        bash(200)                  bound=50.000s   depth=1 queue=0  via=READ from path:/tmp/f
  4    SKIP     FORK  early(300)           at 41.000s    forked BEFORE the bound — cannot be an effect of it
  5    emit     FORK  late(301)            at 60.000s   depth=2 -> queued
```

`bash(200)` forked two children, at 41 s and 60 s, and was reached through a
read at 50 s. Only the later child can be an effect of that read. Before
the H1 fix the FORK branch was the one branch that did not check the bound,
so `early(300)` was listed as an effect of something that happened nine
seconds after it was born.

## 5.10 `_fork_ts` — the timestamp question

An edge needs a time. For FORK, which time?

| candidate | problem |
|---|---|
| `first_ns` (when we first saw an event for the child) | depends on record **arrival order**, so it can be later than the bound — that was bug H3 |
| the walk's bound | never violates the law, but reports the bound as though it were a measurement |
| **`start_ns`** when `start_exact` | the kernel's own `task->start_time`: the actual fork moment, provably ≤ any event of that process |

`_fork_ts` takes the third, falls back to `min(start_ns, first_ns)` for a
`/proc`-estimated start, and clamps to the bound only as a last resort. The
same helper then dates inferred exits, because the new generation's fork
time is a provable upper bound on the old one's exit.

## 5.11 Dependency explosion, and the cheap cure

A file written 130 times has 130 formal causes. Reporting all of them makes
a walk useless — the literature calls this dependency explosion. Two cures:

- **File versioning** (Kairos, SLEUTH): every write makes a new version
  node, so a read points at exactly the version it read. Correct and
  expensive.
- **Last-write-wins** (ours): only the last write at or before the bound
  can have influenced this read. One line, illustrative effect "130 causes → 1"
  (v3.5 VM capture, no run id recorded — see the note in `graph.py`),
  documented as the cheap equivalent.

What we give up: if a reader read the file *between* two writes and we
mis-order them, we attribute to the wrong writer. The bound makes that
precise rather than approximate — which is exactly why `seen` must include
the bound (5.7).

The noise filters are the same idea at a different scale: `common_file`
(shared libraries, locales), `probe_endpoint` (port-0 resolver probes), and
`noisy` combining them, applied by `--no-libs`. A walk through `libc.so.6`
is formally correct and tells you nothing.

## 5.12 Eviction, snapshots, and bounds

- `_maybe_evict` — oldest **exited** processes only, never a live one.
- `_maybe_evict_files` / `_maybe_evict_endpoints` — LRU via `OrderedDict`.
  Read the endpoint one's docstring: inbound means a *remote party* can mint
  nodes, so the bound has to be on our side.
- `to_dict`/`from_dict` — snapshot version **4**, with new fields added as
  optional keys so older snapshots still load. The pattern matters: three
  rounds of features (endpoints, inbound, counters) were added without a
  version bump, and tests assert the old format still loads.

---

## Experiments

`[laptop]` Dry-run every built-in scenario, then your own:

```bash
for d in write-then-read two-reads-two-writers download-write-execute \
         inbound forward-time-bound; do
  echo "=== $d"; python3 tools/walk_trace.py --demo $d; done
```

`[laptop]` Break a rule and watch the dry run change. In a scratch copy,
key `seen` on the node alone (`(ident, t)` → `ident`), then:

```bash
python3 tools/walk_trace.py --demo two-reads-two-writers
python3 -m unittest tests.test_adversarial 2>&1 | tail -3
```

Step 9 disappears, `w2` is never found, and exactly one test fails. Do the
same with the `listed` set and with the `via` check, and predict which
test fires before you run it.

`[VM]` Dry-run a real capture:

```bash
sudo python3 -m hids.monitor --mode quiet --duration 60 --snapshot /tmp/g.json &
python3 tools/net_demo.py
python3 tools/walk_trace.py /tmp/g.json trace <PID-of-the-shell> --no-libs
python3 tools/walk_trace.py /tmp/g.json trace <PID> --at 1234.5
```

---

## Self-check

**Identity**

1. Why is `(pid, start_time)` an identity when `pid` is not?
2. What is adopt-and-upgrade, and what would a second node cost us?
3. A late record from a dead generation arrives. What must *not* happen?
4. A PID's owner changes with no exit event. What timestamp do we give the
   old generation's exit, and why is it provable rather than a guess?
5. Why does a node survive its process's exit?

**Walks**

6. State both time laws.
7. Name the three suppressions, what each is keyed on, and the bug that
   results from collapsing each into another.
8. In dry run 1, step 9 lists a process that was already expanded at step
   5. Why is that correct?
9. In dry run 2, the same file node is popped twice. Why is that necessary,
   and why would "only re-expand on a wider bound" be wrong?
10. In dry run 3, step 16 suppresses an edge. Which rule, and what would the
    output look like without it?
11. Why does a FORK edge carry `start_ns` rather than `first_ns`?
12. What is dependency explosion, how do Kairos and SLEUTH solve it, what do
    we do instead, and what do we give up?
13. `max_visits` exists even though termination is already guaranteed. What
    is it for, and what did measurement show about its default?

<details>
<summary>Answers</summary>

1. PIDs are reused — the kernel hands out a bounded integer. `start_time`
   is monotonic nanoseconds fixed at fork, so two processes can share a PID
   but not a PID and a start time.
2. The first record carrying an exact start time replaces a
   `/proc`-estimated start *in the existing node* rather than creating a new
   one. A second node would split one process's history in half, so neither
   half would show the full chain.
3. It must not take over `current[pid]`. `_set_current_if_newer` only lets a
   newer lifetime become the one new events attach to; otherwise subsequent
   events would be filed under a process that is already dead.
4. `_fork_ts(new_generation)` — the new process's fork time. Provable
   because the kernel does not reuse a PID until its previous holder is
   gone, so the old process must have exited before the new one forked.
5. Because "the process died but created a file" is the central forensic
   case — the advisor's own example. Discarding dead processes discards
   exactly the evidence an investigation needs.
6. Backwards: every listed edge is at or before the point asked about.
   Forwards: every listed edge is at or after it.
7. `seen` on `(node, bound)` — stops re-expansion; collapsing it to `node`
   gives a wrong writer (H2). `listed` on `(source, kind, ts)` — stops
   duplicate output from legitimate re-expansion. `via` on the incoming
   `(node, kind)` — stops an edge echoing the step we arrived on; without
   it an endpoint lists the process we came from as its own cause. Using
   `seen` for the listing job drops the WRITE edge (the v3.4 bug).
8. Because it is a different *kind* of edge. FORK ("that process forked
   me") and WRITE ("that process put these bytes here") are two distinct
   causal facts about the same process, and only the second answers the
   question the walk is asking.
9. Because under last-write-wins each bound has its own correct answer; the
   read at 296 s was caused by the write at 200 s, the read at 100 s by the
   write at 50 s. "Wider bound subsumes narrower" is false precisely
   because `max(writes ≤ bound)` changes with the bound.
10. `via`. Without it the output would contain
    `CONNECT net:203.0.113.5:443` followed by `CONNECT curl(100)` — the
    walk restating the hop it had just taken, which explains nothing.
11. `first_ns` is "when we first processed a record for this node", which
    depends on per-CPU arrival order and can be *later* than the walk's
    bound, putting a cause in the future (H3). `start_ns` with
    `start_exact` is the kernel's own fork time and is provably no later
    than any event of that process.
12. A resource with N writers has N formal causes, and reporting all of
    them makes the answer useless. Kairos/SLEUTH version each file so a
    read points at the exact version. We take the last write at or before
    the bound — illustratively 130 causes → 1. We give up correctness when
    writes are mis-ordered relative to a read, which is why the bound is
    part of the visited state.
13. It bounds the *work*, not the output: with deduped edges the queue can
    stay busy while the result does not grow. Measured, it is not the
    binding constraint — ~3 ms at the 4,000 default and ~5 ms at 100,000 on
    a 3,000-touch file, because `max_items` stops the walk first. It is a
    backstop against a shape nobody has thought of.

</details>

Next: `06_RUNTIME.md` — the loop that holds all of this together, and the
parts that only break on a real machine.
