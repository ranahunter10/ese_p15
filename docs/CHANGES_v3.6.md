# v3.6 — acting on the v3.5i six-agent review

Engineering Journal rows 157–178. Continues `CHANGES_v3.5.md`.

Input: **ESE-P15_v3.5i_Full_Analysis** (18 Oct 2026) — five specialist agents
plus an independent cross-checker, 26 findings filed and 26 reproduced, no
P0 surviving. Plus the independent investigation in
`claude/RESEARCH_state_of_the_art_capture.md` (Falco, Tracee and Tetragon
read from source; CPR and FD/SD compaction read from the papers).

Rule for this round, since the review's own value was in severity
calibration: a finding is fixed here only if the fix is **mutation-checked**
(reverting it fails a named test). Everything else is listed in §D with the
reason, so a missing fix is a recorded decision rather than an oversight.

---

## A. Integrity — findings that lose or corrupt data

| Row | Finding | Status |
|---|---|---|
| 157 | **W2-B1/B1b — one exec recorded as both a success and a failure.** `_commit` popped the pending entry before doing anything fallible. `record_exec` mutates the graph and *then* writes the log line, so a sink failure (a full disk is the realistic trigger) left the exec in the graph with the key gone; a duplicate ENTER plus the next expiry then settled the same exec through `on_failed`, and `node.execs == 1` and `node.failed_execs == 1` described one exec. The fix CLAIMS the key — out of `pending`, into `done` — before any fallible work, and `enter()`, `ok()` and `_settle` all refuse a key that is already finished. **The obvious fix is worse than the bug** — but by less than this row first claimed, and the correction is §I/A21: against v3.5i, "pop after `on_exec` returns" left the entry in `pending` so every later tick re-settled it and `record_exec` ran again each time; against v3.6 the node-level `last_settled_exec` guard refuses that second graph write, so the real cost is one wasted settle attempt (counted in `duplicates`) and a key claimed later than it should be. Measured both ways. The ordering is kept anyway, because correctness here must not DEPEND on a guard elsewhere being right — claiming first makes the commit idempotent on its own | fixed, 3 of 4 guards mutation-checked (see §G) |
| 158 | A deliberate trade inside row 157, recorded because it loses information: a late `EXEC_OK` arriving after its exec was settled as FAILED no longer upgrades it to a success. That upgrade produced exactly the success-AND-failure contradiction by another route. Consistency was chosen over the upgrade; the window is an OK more than `PENDING_TIMEOUT_S` (2 s) after its ENTER, and `assembler.duplicates` counts every instance. That counter was incremented in five places and exported from none, so `--stats-json` never carried it and "visible rather than silent" was false — found by an audit of this tree. `duplicates_refused` and `bad_arg_indexes` are now in the stats JSON, documented in `ARCHITECTURE.md` §Stats, and covered by `RefusalsAreCountedWhereTheyCanBeSeenTest`. A refusal nobody can count is a silent drop with extra steps | implemented, counted, exported |
| 159 | **W2-B2 — a full disk during routine expiry killed the monitor.** `tick()` runs every 0.5 s from the main loop and writes log lines through the expiry path, but only `handle()` had the never-raises guard; the exception reached the main loop, which records a crash and re-raises. `tick()` now counts errors the same way. It cannot spin on a persistently failing sink, because row 157's claim means a failed commit is never retried | fixed, mutation-checked |
| 160 | **W2-B3 — `Arg.idx` was never validated**, and `ExecRecord.argv` is held by reference in the graph. `idx=-1` silently rewrote `argv[-1]` of an already-committed record; `idx=2_000_000` padded that same list to two million entries, +16 MB persisted into the graph, the snapshot and every walk — both with zero errors counted. `MAXARG = 20` had existed in `events.py` since v3.0 and was never enforced. Now validated at both entry points (END records carry the argv COUNT in `idx`, so the bound is inclusive), refusals counted in `assembler.bad_args`, and `_place` refuses a negative index behind that | fixed, mutation-checked (2 mutants) |
| 161 | **W1-F9 — a dead node could never learn its parent**, the one finding in the review that loses a causal fact rather than mislabelling one. The birth record is authoritative, and the `alive` gate on `_reparent` dropped it: the process stayed a permanent false root and `trace_back` lost a real FORK edge. A dead node now accepts a parent *only if it never had one* (`ppid == 0`), an established link is never moved after death, and pid 1 keeps its legitimate `ppid 0` | fixed, mutation-checked |
| 162 | **W2-B4 — `EPIPE` was swallowed.** BCC's own callback wrapper turns `EPIPE` into `exit()`, which is the clean-shutdown convention for `--mode print \| head -5`; `handle()` counted it as a data error first, so the monitor polled a dead pipe for ever at one error per record. `EPIPE` now propagates from both `handle()` and `tick()`; every other `OSError` is still counted | fixed, mutation-checked |
| 163 | **W2-B5 — negative `--max-*` caps were accepted** and silently destroyed the history the monitor exists to collect: `--max-files -5` makes `len(files) > -5` permanently true, so every file node was dropped at creation, with no error. Validated in `parse_args` like `--pages` and `--batch-ms` already were; `0` still means unlimited | fixed, mutation-checked |

## B. Correctness and presentation

| Row | Finding | Status |
|---|---|---|
| 164 | **W1-F2/F3 — the file discriminator.** It was `fid.split(":")[2]`, which raises `IndexError` on any id with fewer than three parts: the kernel never makes one, but `from_dict` loads one, and `_desc` runs inside `trace_back`, `trace_forward` and `lineage_str` — so a single poisoned snapshot record crashed the whole query path. The same slice took the inode number ALONE, so `inode:1:5:0` and `inode:2:5:1` both rendered `/tmp/x#5` — ambiguous in exactly the case a discriminator exists for, and realistic because low inode numbers recur on every filesystem (bind mounts, remounts). Now `dev:ino:gen`, with a length guard. The test that pinned the ambiguous output was rewritten to pin the fix, and a companion test covers the same-inode/different-device case it could not tell apart | fixed, mutation-checked |
| 165 | **W1-F4 — generation identity under newest-first arrival.** Three parts. `gens[pid]` is documented "oldest first" but was in observation order, which diverges whenever per-CPU reordering delivers a reused PID's newest lifetime first; it is now sorted by `start_ns`, and new generations are numbered `max(gen)+1` rather than `keys[-1][1]+1`, which would collide once the list is sorted. The gen NUMBER stays observation order and is documented as such: it is the node's key and persists into snapshots, so renumbering it retroactively would invalidate stored references. Third and worst: a generation older than an exact-start current one was left `alive = True`, so it was counted in `summary()["alive"]`, rendered as a live process, and — because eviction only removes exited nodes — could never be evicted. It is now marked not-alive with an inferred exit bounded by the newer generation's fork time, the same provable bound the existing inferred-exit uses in the other direction | fixed, mutation-checked (3 mutants) |
| 166 | **W1-F5 — an empty process name was never healed.** A node first seen through an `accept` or `open` record has no `comm`; the later birth record healed its `ppid` and `uid` but the `ts >= last_ns` rename guard blocked the name, so it rendered as `?(130)` in every walk while its siblings showed real names. An empty name is now fillable, because empty→something can never revert a real rename. The guard itself is unchanged and still tested: a late pre-exec record cannot turn "cat" back into "bash" | fixed, mutation-checked |
| 167 | **W1-F6 — `from_dict` accepted corrupt snapshots.** A duplicated `(pid, gen)` loaded silently, leaving `gens[pid]` holding one key twice and producing a bogus discriminator; a missing field raised a bare `KeyError` from inside the loader. Required fields are now checked per entry and named in the error, duplicates are refused, and a restored graph's `gens` lists are sorted the way the live path maintains them | fixed, mutation-checked |
| 168 | **W1-F10 — a placeholder's span outlived its own events.** A placeholder parent is created by a CHILD's event, so its `first_ns`/`last_ns` were a borrowed stamp from a time that process may never have been running; adoption corrected `first_ns` and left `last_ns` at the borrowed value. The span is now handed back to the node's own events on its first own event | fixed, mutation-checked |
| 169 | **A bug the fix for row 168 introduced, caught by the existing suite.** Resetting the span set `last_ns = ts_ns`, which made `newest` true, which defeated the deliberate rename guard of Journal row 12 — `test_a_placeholder_parent_is_upgraded_not_duplicated` failed. "Is this the newest thing seen about this node" must be decided against EVERYTHING seen, including the borrowed stamp, and therefore BEFORE the span is handed back. Recorded because it is the second time in this project that a span fix has interacted with the rename guard | fixed; the test that caught it is unchanged |

## C. Performance, each measured paired

Unpaired measurements on the test machine drift ~25 %, which is the size of
some of these effects — the same lesson as the overhead ladder (§D.5). Every
figure below is old and new interleaved in one process against a shared
baseline.

| Row | Change | Measured |
|---|---|---|
| 170 | **The eviction cliff — found here, not in the review.** `_maybe_evict` rebuilt `sorted(all dead nodes)` on every call, and it is called on every node creation while over the cap. With dead nodes scarce each call scanned every node, freed nothing, and returned — and the count then kept growing, so the next scan was longer. Quadratic, while bounding nothing. Dead nodes are now tracked as they die, and a pass with nothing evictable returns in O(1). Per node creation, as a multiple of an uncapped baseline: **100 % dead 2.00x → 1.79x; 50 % 13.62x → 1.54x; 10 % 27.09x → 1.34x; 0 % dead 32.07x → 1.15x.** Final node counts are identical before and after at every fraction, so this is the same eviction policy reached without the scan. The review had measured ~25 % in its favourable regime (a flood of mostly-dead generations) and listed "max_nodes only evicts dead nodes" separately; they are one cliff | fixed, mutation-checked, paired measurement |
| 171 | **Decode without `ctypes.cast`.** `cast(data, POINTER(RawEvent)).contents` plus per-field attribute access became one `struct.unpack_from`, with **no copy**: BCC hands the callback a `c_void_p`, which arrives as an integer address that `(c_char * size).from_address()` wraps in place. **decode 3.82 → 2.07 µs (1.85x, IQR 1.82–1.89); full ingest 9.30 → 6.99 µs (1.34x, IQR 1.32–1.38), 108k → 143k events/s** — 21 interleaved pairs, `tools/bench_ingest.py`, raw output in `docs/evidence/bench_ingest_container_20261018.txt`. Read the ratios, not the microseconds: the ratios reproduce inside their IQR while the absolute per-record cost on this container moves by ~2x between runs with load. The harness ships because the earlier figures here (1.7x/1.4x) came from a scratch script nobody else could run, which an audit of this tree flagged. The format string is DERIVED from the ctypes definitions — padding from each field's real offset — so it cannot drift from the layout `test_layout.py` anchors to gcc, and `_struct_format` refuses to build one whose size ctypes disagrees with | fixed, mutation-checked, paired measurement |
| 172 | Proof for row 171, because a re-derivation of a binary layout can be subtly wrong and then every field is quietly off: the v3.5i decoder is kept in `test_layout.py` as a reference and the two are compared over **3000 randomised records** — every type, NUL-terminated and full-width string fields, invalid UTF-8 — through both the ctypes-array and the integer-address paths. Plus a field-by-field check of the generated format against ctypes' own offsets | unit-tested |
| 173 | **W2-B6 closed by construction rather than by a check.** `decode(b"\x04\x00\x00\x00", 10**6)` performed a *successful* out-of-bounds `ctypes` read and returned garbage as a record. `struct.unpack_from` cannot do that — it raises on a short buffer, for `bytes` and `memoryview` alike — so the performance change removes the memory-safety smell structurally. A bytes-like input is additionally length-checked; an integer address keeps trusting BCC's size, which is documented | fixed, mutation-checked |
| 174 | **File ids are shared instead of rebuilt per event.** `file_id()` built a fresh string on every open and every exec, and every `node.files` tuple keeps a reference to whatever it was handed — so one file's id existed once per event. The review measured **38.1 MB** of them retained after 1.05 M events, the second-largest consumer behind the tuples holding them. Measured by `tools/bench_nodes.py` on a 20 000-process × 6-distinct-file shape (120 000 opens, Python 3.8.20, evidence in `docs/evidence/bench_nodes_py38_20261018.txt`): **distinct fid objects 120 000 → 6, retained 58.5 → 43.0 MB (−27 %)**. The saving scales with how FEW distinct files a workload touches, so the shape is quoted with it rather than a bare percentage — an earlier figure here (→ 400, −11.6 %) came from a scratch script with a different file count and no way to re-run it. The cache is cleared wholesale when full rather than evicted one at a time; `sys.intern` would be wrong, because it never releases and path strings are attacker-influenced and unbounded in variety | fixed, mutation-checked, paired measurement |
| 175 | `_cap_per_resource` selects the top *k* instead of sorting a whole bucket to slice 8 off the front — a bucket can hold every access one process made to one resource. Being a pure optimisation, what needed proving is that it changes nothing: `heapq.nlargest`/`nsmallest` are compared against the old full sort over **2000 randomised buckets with deliberately few distinct timestamps, each re-checked under 6 configurations (12 000 comparisons)**, because ties decide which edge a walk shows. Zero mismatches | fixed, equivalence unit-tested |

## D. Deliberately not fixed in v3.6, with reasons

Each is a decision, not an omission.

Carried forward as the first item for the next round: **finish pass 3** —
an independently imagined mutation of the eleven guards it did not reach
(§G). Three of the first twenty-four it did reach were broken in ways I had
not thought of, so the remainder is not a formality.

- **W1-F1** (`listed`/`via` order-dependence under exact-nanosecond timestamp
  ties, demoted to P3). The fix changes the expansion dedup key in both
  walks, i.e. the core of `trace_back`/`trace_forward`. Neither answer
  fabricates or drops a causal fact — both connects are real and the echo is
  a real edge — so this is a display-order subtlety, and it wants its own
  round with its own fuzz rather than a seat in a release that already
  touches identity, spans and eviction.
- **W1-F7, W1-F8** (arrival-order-dependent `summary()` counters and
  `max_items` truncation subsets). Both are arguably working as designed —
  the counters count ingest events, and BFS+cap truncation follows insertion
  order. Documenting them is the right fix; canonicalising emission order by
  timestamp would change every truncated answer in the suite.
- **W3-M1** (`filename` truncation carries no flag, so two long paths sharing
  a 255-byte prefix can merge into one node via `path:` ids). Real but
  LOW-rate, and it is an ABI change — a bit stolen from the `pad` u32 in
  `event_t`. An ABI change should land with its own VM verification and not
  share a release with the decode rewrite.
- **W3-H1, W3-H2** (open-filename and argv TOCTOU). Not code defects: argv
  cannot be read at exit because the old address space is gone, and the
  filename's answer is already in the code — the inode is kernel truth.
  These need the trust levels stated as a contract, which belongs with the
  threat-model document §5 of the review asks for.
- **Lazy string fields in `decode`.** Deferred *with a number*, which is the
  change from the earlier plan. Inside the 2.18 µs decode of one EVENT
  record, measured cumulatively in one run of `tools/bench_ingest.py`: 0.32 µs
  to unpack the struct, +0.92 µs for the four C-string conversions, +0.94 µs
  to build the namedtuple. Decode is ~30 % of ingest, so the strings are
  ~13 % of decode-side work and making them lazy saves on the order of 4 % of
  ingest — for a change that turns `Event` from a namedtuple into something
  with lazy attributes, touching `World`, `encode_event`, every test and both
  query tools. (The figures here were 1.87 µs / 0.69 µs / 0.88 µs and "about
  7 %", taken from a different run than the one published in row 171; §I/A6
  is the correction. The conclusion does not change, and the arithmetic is
  now from a single run.)
- **REO / versioned nodes** (USENIX Sec 2018, FD/SD compaction) as a
  replacement for `MAX_EDGES_PER_RESOURCE = 8`. This is the genuine
  algorithmic upgrade — an arbitrary truncation that can drop a
  non-redundant edge, against one that drops only provably redundant ones
  and reports ~7x — but it requires versioned nodes, which is the identity
  model the two time laws and much of the suite are built on. Research-grade
  change, own round.

## E. Corrections against myself in this round

| Row | Correction |
|---|---|
| 176 | **The "17x faster decode" was wrong.** It compared a microbenchmark unpacking nine scalar fields against a FULL old decode — not the same work. Paired, the honest figures are 1.7x on decode and 1.4x on the ingest path. The code comment that claimed 17x was corrected in the same commit |
| 177 | **An eviction "regression" I reported did not exist.** After the fix I measured the all-dead case at 3.0 → 4.8 µs and blamed a redundant set rebuild. Removing the rebuild changed nothing, because the control itself had drifted 2.0 → 2.5 µs between runs. Paired, the all-dead case *improves* (2.00x → 1.79x). The rebuild was still removed, correctly, for a different reason: `_evict` is the only place a node leaves `self.nodes` and it discards its own key |
| 178 | **An optimisation dropped for having no win.** `_start_ts` builds a list over a node's whole access list to take a max/min, which looked worth replacing with incrementally maintained bounds. It is called **twice per walk, at the root only** — so there is no cost to recover. A latent correctness issue remains (max/min over a *capped* list can be wrong once arrival is out of order and the list has been trimmed, the same class as row H3) and is recorded for a later round rather than bundled as a behaviour change justified by a performance claim that does not hold |

## F. Housekeeping

- `hids/__init__.py` said `3.5g` in a tree stamped `v3.5i`. The review found
  it; the drift guard I had written could not, because it compared `VERSION`
  against the README title and nothing else. A guard that checks two of
  three places is worse than none — it reports agreement it did not verify.
  It now **discovers** the copies: any `__version__` anywhere under `hids/`
  or `tools/` is checked, and the guard fails if the package stops declaring
  one at all.
- `VERSION`, the README title and `hids/__init__.py` all read 3.6.

## H. A second review, of v3.6 itself — and what it found

The v3.5i review was of v3.5i. Fixing fifteen findings in one round changes
the shape of the code, and a fix is a new piece of code with no review
history of its own. So before packaging, three independent reviewers were
given the v3.6 tree, a description of what had changed, and no access to the
reasoning behind it, and asked to attack the new code rather than re-check
the old findings. They found a **P1 that v3.6 introduced**, three P2s and a P3 — five holes
in code that had just been written to fix fifteen other holes. Each is reproduced as a test in
`tests/test_review_v35i.py`.

| ID | Severity | What the reviewers found |
|---|---|---|
| R1 | **P1, introduced by v3.6** | `process()` could **return a node that no longer existed**. Resolving a DEAD node and reparenting it reaches `_parent_key`, which creates a placeholder, and creating a node runs an eviction pass that may remove *any* dead node — including the one `process()` was holding. The caller's `record_exit` then filed that key in `_dead`, and from then on **every** eviction pass raised `KeyError` inside `_new_node`: the node cap stopped bounding anything, every later event was lost, and the monitor counted one error per record for the rest of the run. Permanent, from a single ordinary sequence (orphan → PID reuse → the orphan's own late record). Both halves are v3.6 — the reparent gate (row 161, W1-F9) and the `_dead` tracking (row 170) — so this defect did not exist in v3.5i and would have shipped as a regression. Fixed with a `_protect` pin held across `_parent_key`/`_reparent`, plus a membership check in `_note_dead` and a defensive skip in `_maybe_evict`: the belt-and-braces is deliberate, because the consequence of being wrong once is a monitor that silently stops bounding memory. Two of the three are reproduced as tests; the `_maybe_evict` skip is not, because `_note_dead`'s check makes it unreachable — see §G |
| R2 | P2 | **The graph said a process exited before it was last seen.** Row 165 changed the inferred exit to the newer generation's fork time, which is the honest bound — but a placeholder carries a span *borrowed* from the child event that created it, and that stamp can be later than the proven exit. `to_dict` and `render_tree` then showed an effect before its cause, which is one of the two laws every walk is built on. Fixed by clamping the borrowed end down to the proven exit (and `first_ns` with it), while a span the node actually owns is left untouched |
| R3 | P2 | **v3.6 lost an execve that v3.5i recorded correctly.** `_settle` claimed the key even when there was nothing to record and nothing was emitted — ARG records whose ENTER the perf buffer dropped. The real ENTER and OK, arriving after the 2 s timeout, were then both refused and the execve produced no record at all. The claim was added for a good reason (row 157: `on_failed` mutates the graph before it emits) but applied one branch too wide. Fixed: the ARG-only case returns without claiming |
| R4 | P2, pre-existing | **An evicted generation's number was handed out again.** `max()+1` over the *surviving* keys (row 165) can re-mint a number that evicted nodes are still referenced by, because `_evict` cleans neither `FileNode.accesses` nor a survivor's `parent_key`. A reviewer demonstrated a file write credited to a later process that inherited the number. Fixed with a per-pid high-water mark — one int per pid, monotone for the run, restored from snapshots |
| R5 | P3 | `own_span` (row 168) was **not persisted**, so a restored placeholder claimed to own a span it had borrowed and never handed it back: the W1-F10 symptom returned across a snapshot round trip |

Two things about this round are worth recording as method rather than result.

**A reviewer's reproduction can be wrong while its finding is right.** R4's
detector predicted the next key with the *old* formula and reported the bug
still present after the fix. Taken at face value I would have reverted a
correct fix. Replacing the prediction with an observation — record what keys
eviction removed, record what keys are actually minted, compare — gave, over the 120
randomised worlds the shipped harness runs, **0** evicted keys re-minted with
the watermark and **1112** with it disabled. (An earlier note here said 400
worlds and 3485 — figures from a scratch script with different parameters,
which an audit of this tree caught. These are the numbers
`GenerationNumbersAreNeverReusedTest` actually produces.) Both halves are now in the suite, the second as a
test that the search can find the bug it looks for: a zero that no
experiment could have turned positive proves nothing.

**Three of the probes still reproduce and are not bugs.** They drive the
assembler directly and bypass `EventProcessor`, where the node-level
duplicate guard lives, so they describe a path no event can take. One of
them — an `aux_ns == 0` exec correlating against a zero timestamp — is a
genuine pre-existing contradiction in the data, and the only fixes available
are heuristic correlations that would guess. It is documented in §D rather
than papered over, because a wrong parent recorded confidently is worse than
a missing one recorded honestly.

## J. The VM run — one defect the three reviews could not reach

v3.6 was validated on the VM (Ubuntu 20.04, 5.4.0-216-generic, BCC 0.12,
Python 3.8.10, 2 vCPUs) on 2026-10-18. Steps 0–3 of the runbook passed
cleanly, which is the first real evidence for the decode rewrite: the full
program **verified** with all three features used and none refused, 14
tracepoint programs attached, and 6865 records read with **0 lost and 0
errors**. The suite ran 317/317 on the VM's own interpreter with nothing
skipped.

Then step 4 found a defect in the BPF C — the one layer no unit test and no
code review in §A–§I could reach, because it only misbehaves against a real
kernel.

| Row | Finding | Status |
|---|---|---|
| 187 | **`accept()`'s peer name was read out of the traced process's leftover memory.** `accept`'s sockaddr is an *output* buffer: `move_addr_to_user()` writes only `*upeer_addrlen` bytes and leaves the rest as the caller had it. An accepted unix peer almost never has a bound name, so the kernel writes **2 bytes** — the family — and `accept_exit` read the fixed 110-byte `sockaddr_un` anyway, then decided whether a peer name existed by testing `path[0] != 0`, i.e. by asking whether the caller's first leftover byte happened to be non-zero. On the live run `dbus-daemon` reported `unix:ub<junk>` while `systemd` and `ssh-agent` reported `peer unknown` from the identical syscall — the difference was their stack contents, nothing else. **For a provenance tool this is the worst class of bug: it manufactures a fact and attributes it to the kernel.** The node id is attacker-chosen (a process can plant any 107 bytes), fragments of the traced process's memory land in `runs/*.jsonl` and in every snapshot, and a loop over `accept()` with varying buffer contents can churn the 25 000-endpoint cap and evict real peers — an attack on the evidence, using the monitor's own bookkeeping. Fixed by stashing `upeer_addrlen` in `accept_args_t`, reading the length at exit, and copying only those bytes; `klen <= offsetof(sun_path)` now means NOPEER. The same gate is applied to AF_INET/AF_INET6, where the kernel always writes a full sockaddr — belt-and-braces, but it makes one rule instead of a special case: **never read more of a user buffer than the kernel said it wrote** | **fixed and VM-verified** 2026-10-19 (see below) |
| 188 | **A second, quieter defect the same fix closes.** An abstract unix address legitimately begins with a NUL byte, so `path[0] == 0` was never a sound test for absence — a client that bound an abstract name before connecting would have been filed as having no peer at all. The kernel's length tells the two apart, because an abstract name makes `klen > offsetof(sun_path)` exactly as a filesystem name does. Found by reasoning about the fix rather than by observation, so it is marked as untested in the field | fixed, unit-tested |
| 189 | **Method: the demonstration, not the diagnosis, is the evidence.** A single garbage line could be argued away as a strange dbus socket. `tools/p15_accept_probe.py` makes it a measurement: it plants a known marker in the buffer before calling `accept()`, and runs a zeroed control through the same program on the same socket. The kernel's answer is identical both times (`addrlen == 2`, printed by the probe itself); the monitor's output is not. Marker run → `unix:P15_LEAK_MARKER_XXXX...`; control → `peer unknown`. The probe ships, so the fix has a falsifiable acceptance test rather than an assurance | tool added |

| 190 | **The first fix did not load. The verifier rejected it, and that is the most instructive result of the round.** I truncated inside BPF with a constant-bound loop copying `sa.path[i]` byte by byte, citing the argv loop as precedent. The precedent was false: the argv loop reads USER memory through `bpf_probe_read` — one helper call per iteration, constant size, only the destination to check — while mine walked the **BPF stack**. clang partially unrolled it and the 5.4 verifier, which tracks every stack slot individually, refused the program: `invalid read from stack off -34+0 size 1` at instruction 842, after `processed 785 insns`. Not a safety problem in fact; a proof it could not construct, which amounts to the same thing. The monitor then **refused to run at all** rather than attach partially (`feature set [] refused` → `could not be loaded with any feature set`), which is the feature-degradation path behaving correctly under a real load failure | first attempt rejected by the kernel; reworked |
| 191 | **The rework is better than the thing that failed, which is the useful part.** The length is now carried in the record — in the `u16` that used to be `pad`, so `RawNet` is still 256 bytes and the layout tests are untouched — and the truncation happens in **userspace**, in `unix_path(raw, addrlen)`. Three consequences. The BPF side has no loops, no variable-size reads and no variable stack indexing: every new instruction is of a kind already present and verified in the same function. The truncation is now **unit-testable**, so what I had labelled "assertable only by grep" is mutation-checked (6 mutants, all caught). And `connect()` gets the same treatment for free, because `sys_enter_connect` carries `addrlen` as a direct value — closing the latent half of the bug in the path that was not yet misbehaving. The rule is unchanged and now stated in one place: **never read more of a sockaddr than its length claims is real** | reworked; 6 mutants caught; **VM-verified** 2026-10-19 |

**What is and is not proven.** The userspace half is mutation-checked: six
mutants — the entry probes dropping the length pointer, the length never
recorded, the NOPEER gate removed, `unix_path` ignoring the length, the id
builders dropping it, and userspace ignoring NOPEER — each fail a named
test. The BPF half **cannot** be: the suite compiles that C against a gcc
stub (which does declare `int *upeer_addrlen`, so the field is type-checked)
but cannot execute it, and row 190 is the proof that compiling is not
loading. `test_accept_reads_the_kernels_length_before_trusting_the_buffer`
asserts the mechanism is present in the source, including that no
stack-walking loop has come back. That is a weak form of test and the
strongest available for code only a kernel runs. **VM-verified on 2026-10-19**, kernel 5.4.0-216-generic, in one 75-second
run, against the four things that could each have gone wrong:

| check | result |
|---|---|
| the controlled pair — marker buffer vs zeroed buffer, same program, same socket | `peer unknown` **both times** (was `unix:P15_LEAK_MARKER_XXXX...` / `peer unknown`) |
| `dbus-daemon`, three forced session-bus accepts | `peer unknown` ×3, no garbage (was `unix:ub<junk>`) |
| inbound TCP still NAMED — the risk that the new length gate was too strict | two curls → ports 60608 and 60616, **one** id `host:127.0.0.1` |
| connect-side unix paths still render — the risk that tidying a working path broke it | `unix:/tmp/p15net-.../p15.sock`, `unix:/run/user/1000/bus`, `unix:/var/run/nscd/socket` all intact |

The probe still reports `addrlen: 2` with the marker physically present in the
buffer, so nothing about the leak's *source* changed — the monitor simply
stopped reading bytes the kernel never wrote. 533–715 records per run, 0 lost,
0 errors throughout.

One precision kept deliberately: the process originally observed garbling was
`dbus-daemon(456)`, the **system** bus; the forced accepts came from
`dbus-daemon(1092)`, the **session** bus. Same binary and same unnamed-unix
accept, so the mechanism is covered, but pid 456 was not itself re-observed.

| 192 | **`getaddrinfo`'s source-address probe forges outbound edges, and the existing probe filter only catches the harmless half.** Confirmed by strace: the resolver opens a SOCK_DGRAM socket and `connect()`s it to each candidate address carrying the requested port. `processor.py`'s filter keys on `dport == 0`, so it catches probes from service-less lookups but not from lookups WITH a service — and the latter land on the same endpoint node a real connection would, inflating its attempt count and making a merely-resolved address look contacted. The socket type is the available discriminator. See §J step 5 point 4 for the trace and the reasoning | **open question, not decided** — it changes what the graph asserts about every endpoint |

### Step 5 — full functional validation: 23/23, and three things it changed

`vm_validation.sh`, run `validation-20261018-151152`, kernel 5.4.0-216-generic,
Python 3.8.10, BCC 0.12.0, 2 vCPUs. **23 checks, 0 failed**, 1351 log lines
with 0 malformed, 0 processing errors, 0/1351 events with a `?` in their
lineage and 1332/1351 rooted at systemd(1). None of the 23 checks touch the
accept path, so this is independent of §J above rather than a re-test of it.

Supporting evidence for the accept fix came out of it anyway: *"inbound
connections with no peer name the kernel could give — **1 of 5 accepts**"*,
and *"inbound endpoint keyed by host, not by the peer's ephemeral port — 4
connections from 4 distinct source ports → ['host:127.0.0.1']"*. The one
unnamed accept is the unix client, reported as unnamed rather than as 108
bytes of its own buffer.

| Metric | p64 | p256 | condition |
|---|---|---|---|
| records received | 119 117 | 127 231 | 3× `find /`, 20 s |
| records lost | **0 (0.00 %)** | **0 (0.00 %)** | same |
| throughput | 5 354.6 /s | 5 651.8 /s | same |
| monitor CPU | 36.61 % of one core | 35.93 % | same |
| monitor peak RSS | 137.4 MB | 141.9 MB | same |

| Workload slowdown | with vs without monitor (quiet, no log) |
|---|---|
| 2000 × `/bin/true` | +78.0 % (3.08 s → 5.49 s, median of 3) |
| `find /usr` (cached) | +1295.1 % (0.34 s → 4.81 s, median of 3) |

**1. Event loss is gone, and that stops one experiment from measuring
anything.** The recorded ceiling was 7.2 % loss (Phase I monitor) and v3.5
noted `--batch-ms 20` dropping 2.96 %. This run lost **nothing at either page
count**. Better — but the p64-vs-p256 comparison exists to show whether more
ring pages reduce loss, and at zero versus zero it no longer answers that. It
needs a heavier workload to stay a measurement. And the improvement is **not
attributed to v3.6's 1.34× ingest gain**, because that would need a paired run
against v3.5i on this machine, which has not been done.

**2. The slowdown baseline moved by 2× between runs.** 2000 execs took 3.08 s
unmonitored today against 6.65 s on 16 Oct. The ratio moved +95 % → +78 %
while the baseline halved, which is row 133's lesson arriving again: quote
absolute seconds **with their run**, never a percentage on its own.

**3. A correction against myself, of a correction I made this round.**
§I/A11 "fixed" `ARCHITECTURE.md`'s peak-RSS figure by replacing ~135 MB with
the README's 121 MB, calling the latter authoritative. Those are different
workloads: 121 MB is the overhead run (exec loop + `find /usr`), while
~135 MB and today's 137–142 MB are the stress run (3× `find /`). I corrected
a figure by citing a measurement taken under other conditions — the exact
error the audit was convened to find, committed while committing it. The
section now carries both numbers with their conditions. The open question is
unaffected in substance: `--max-files 200000` permits 149–677 MB against a
heaviest observed RSS of ~142 MB, so the cap still allows roughly five times
the memory the monitor has ever used.

**4. A resolver artifact that forges outbound edges — settled by strace, and
worse than it first looked.** The print-mode run showed `net:[::]:8078` and
`net:0.0.0.0:8078` as `connected [dgram]` while `http.server` was *binding*.
I first called these `AI_ADDRCONFIG` probes without checking, which was a
story rather than a mechanism. Traced:

    socket(AF_INET6, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_IP) = -1 EAFNOSUPPORT
    socket(AF_INET,  SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_IP) = 3
    connect(3, {AF_INET, htons(8078), inet_addr("0.0.0.0")}, 16) = 0

`getaddrinfo` opens a **datagram** socket and `connect()`s it to each
candidate address **carrying the requested port**, as its source-address
selection for RFC 3484 sorting. `getaddrinfo(None, 8078, AI_PASSIVE)` returns
`0.0.0.0:8078` and `::8078` — exactly the two endpoints observed, one probe
each. (Verified on glibc 2.39; the VM runs 2.31 and the code path is
long-standing.)

The tree already knows about this class of record — `processor.py` sets
`probe = ev.dport == 0 and ev.sock_type in (0, SOCK_DGRAM)` and the run
reported `CONNECT_PROBE: 2`, catching the two **portless** probes
(`net:151.101.209.91:0`, `net:[2a04:4e42:31::347]:0`). The rule anticipated
only lookups with no service. It misses every probe from a lookup that had
one — and those are the damaging ones:

- A portless probe is visibly an artifact: port 0 is not a service.
- A **port-carrying** probe connects to the same address and port a real
  connection would, so it **collapses into the same endpoint node and
  inflates its attempt count**. In this run `net:34.107.243.93:443` shows
  "2 attempts, 0 failed"; one of those may be a probe for a connection that
  happened once. An address that was merely *resolved* can be presented as
  an address that was *contacted* — a false causal edge, not noise.

The discriminator is available: `SOCKET_TYPE` already resolves the socket
behind the fd, and a TCP service reached over a datagram socket is the
signature. **Not changed, because widening the rule changes what the graph
claims about every endpoint** — whether to drop such records, keep them with
a `probe` label, or keep them as edges with a flag is a decision about what
the tool asserts, which belongs in a meeting. Recorded as the open question
it is. (Row 192.)

### Step 7 — the overhead ladder: unreadable, and the tool said so

Run `overhead-20261018-153826`, measured by v3.6 and analyzed by v3.6. The
headline is that **the analyzer refused to offer a reading**, and that refusal
is the most valuable line in the report:

> *Cost per added syscall tracepoint — **INCONCLUSIVE, no reading offered.**
> Measured: 0 tp base −24 %, 0 tp count_exit −2 %, 2 tp count_exec −9 %,
> 4 tp count_open −17 %, 6 tp count_net +25 %, 12 tp count_all −8 %, 12 tp
> count_all_nofeat +98 %. This cannot be read as flat or rising, because the
> ladder is not monotonic: 1 rung(s) come in LOWER than a configuration with
> fewer tracepoints, which no per-hook cost model can produce.*

A monotonicity check is a cheap and strong falsifier: no per-hook cost model,
flat or rising, can put a 4-hook configuration *below* a 2-hook one. The
guard fired, named what would resolve it, and declined — which is what the
v3.5g instrument bugs (rows 149–151) were supposed to buy, and it worked.

| Row | Finding | Status |
|---|---|---|
| 193 | **The script's default dd count could not resolve the measurement the dd workload exists for.** `DD_COUNT` defaulted to 300 000, at which one round takes **~0.09 s** on the VM — so the per-syscall tax sits far below timing noise and the ladder is unreadable. The v3.5g run that *did* resolve it (~16 ns, paid once) passed `P15_DD_COUNT=6000000` by hand, and the runbook told the reader to run the script with no overrides at all. So the documented command could not answer the question it was for. Default raised to 6 000 000 (~+2 min per run), the runbook now spells out `P15_DD_COUNT`/`P15_ROUNDS`/`P15_PIN` with the reason for each, and `test_the_dd_workload_is_long_enough_to_resolve_the_tax` pins the floor in **both** places a reader could take a number from — the script default and the runbook command | fixed, unit-tested |

**What this run does and does not establish.** The control measured a **16.2 %
mean, 49.4 % worst** error against a true answer of 0 %, and the `/bin/true`
baseline drifted **117 %** between the start and end of the run (2.37 s →
5.13 s) — larger than most effects in the table. So only the large effects are
resolved:

| Resolved by this run | |
|---|---|
| Cost tracks EVENTS, not hooks | `count_open` +1050 % vs `count_exec` −15 % on the same `find /usr` workload — two orders of magnitude apart with the same number of hooks attached |
| Python processing dominates on open-heavy work | graph vs count: **+351 points** on `find /usr` |
| Batching roughly halves it | `find /usr` +1998 % → +1299 % with `--batch-ms 20` |
| Logging is not free | +43 points on `find /usr`, monitor CPU 21.6 % → 34.2 % |

**Not resolved: the per-syscall tax.** Every dd figure except one sits inside
the noise floor. This run therefore **neither confirms nor contradicts** the
v3.5g result (~16 ns, paid once, mechanism confirmed in the kernel source);
v3.5g remains the only resolved measurement of it, and §11 of
`ARCHITECTURE.md` still rests on that run rather than on this one. A re-run
with the corrected defaults is the open item.

One figure worth keeping for the thesis anyway: `count_net` attaches **6
syscall tracepoints and produced 0 records** on these workloads, so its cost
is the price of *attaching* hooks with no record-keeping at all — the cleanest
tax probe available. It read −0 % on exec and −3 % on `find /usr`. Consistent
with "paid once", not sufficient to establish it.

### Step 7, re-run with the corrected instrument — and the useful answer

Run `overhead-20261018-160512`: `P15_DD_COUNT=6000000` (dd baseline 2.88 s,
not 0.09 s), `P15_ROUNDS=5`, `P15_PIN=1`. Still **INCONCLUSIVE** — ladder
+34 %, +0 %, −3 %, +20 %, +4 %, +8 %, +17 %, non-monotonic in 2 rungs, with
the analyzer adding a second reason: *"the worst single-config spread (±48 %)
is as large as the whole ladder's range (37 points)."*

But with the instrument fixed, the failure becomes quantitative and that is
the result worth keeping:

| quantity | this run |
|---|---|
| cost of one bare syscall | **240 ns** |
| the effect being hunted (v3.5g) | **~16 ns = 6.7 %** |
| measured noise floor (control, true answer 0 %) | **13.4 % mean, 36.6 % worst** |
| baseline drift *within* the run | 86 % (exec), 47 % (dd), 45 % (find) |

**The effect is roughly half the instrument's resolution on this machine.**
More rounds cannot fix that: the noise is multiplicative drift between
neighbouring measurements, not a fixed error that averages out. The cause is
visible in the run's own preconditions — `uptime` read **0.69** before
starting, which on 2 vCPUs is ~35 % of a core already busy (lxqt desktop,
sddm, dbus, panel applets).

| Row | Finding | Status |
|---|---|---|
| 194 | **The per-syscall tax is at or below this instrument's noise floor, and that reframes how v3.5g should be cited.** v3.5g measured +14 points against a **6.3 %** floor — about 2× margin, marginally resolved. This run's floor is 13.4 %, so the same real effect is invisible; the two runs do not conflict, the later instrument is simply worse. The consequence for the thesis: the claim "~16 ns, paid once" should rest primarily on the **kernel mechanism** — `syscall_regfunc()` sets `TIF_SYSCALL_TRACEPOINT` on every thread only at the *first* registration and then refcounts, which predicts exactly a paid-once step with ~0 per-hook increment — with v3.5g as **consistent supporting measurement** rather than as the proof. A borderline number presented as the evidence is the weaker claim of the two, and it is the one a reviewer would attack | reframed; measurement open |

**What would actually resolve it**, in order of effect: stop the desktop
(`systemctl stop sddm` from a TTY) so the control floor drops toward v3.5g's
6.3 %; then more rounds. Failing that, a method change — counting cycles with
`perf stat` on a pinned core rather than timing a workload — measures the
same thing without depending on a quiet machine. Recorded as the open item;
the design consequence (**hook count is not a budget, event rate is**) does
not depend on it, because that conclusion comes from `count_open` +1079 % vs
`count_exec` −22 % on the same workload, a two-order-of-magnitude separation
that no noise floor threatens.

### Step 8 — row 86 confirmed on the VM's own glibc

```
accept4(3, {sa_family=AF_INET, sin_port=htons(53804), ...}, [16], SOCK_CLOEXEC) = 4
ldd (Ubuntu GLIBC 2.31-0ubuntu9.18) 2.31
```

Python's `socket.accept()` issues **`__NR_accept4`** on glibc 2.31. Row 86
had claimed this from a container with a newer libc, so it was an assumption
carried in from another machine; it is now measured here. This is the reason
both syscalls are hooked: hooking either one alone would make half the
servers on a box invisible, and which half would depend on their libc.

### A better instrument for the open measurement — `tools/tax_paired.py`

Written in response to §J row 194, and **not yet run on a kernel**. The
statistics are unit-tested (`tests/test_tax_paired.py`, 14 tests); the
measurement is untested until it runs on the VM, and the header of the file
says so.

The diagnosis in row 194 was that the effect (~6.7 %) is half this machine's
noise floor (13.4 %). The first instinct was a quieter machine — stop the
desktop — which is a workaround, and on the VM it went wrong in the ordinary
way: `systemctl stop sddm` killed the terminal the command list was running
in, so the measurement never happened and the command that would have
restored the desktop never ran either.

`perf` would not have helped either, and this is worth recording so nobody
tries it: hardware instruction counting needs a virtualised PMU, which
VirtualBox does not expose by default, so `perf` would fall back to software
events (`task-clock`, `page-faults`, `context-switches`) — none of which
count instructions.

**The fix is the statistic, and this project had already learned it once this
round.** When the ingest benchmark showed a ~50 % sample spread around a 34 %
effect, the answer was not a quieter machine but comparing the two variants
**per pair** and taking the median of those ratios — drift both arms see
cancels. That turned an unpublishable figure into 1.34x with an IQR of
1.32–1.38 (§C row 171). `overhead_breakdown.sh` does not do this: it compares
a configuration's median against its *neighbouring baselines'* medians, which
protects against drift between distant parts of a run but not against drift
during it — and the drift is during it (47 % on dd, within one run).

So each measurement here is a pair taken **seconds** apart: monitor up → dd →
monitor down → dd, and the result is the median of per-pair ratios. `--sink
count` is used, as `overhead_breakdown.sh` does for its `count_*` rungs, so
the two ladders mean the same thing.

Three things it enforces, each from something that has already gone wrong:

- **A control that can void the run.** `count_exit` runs the monitor with
  **zero** `syscalls:*` tracepoints: it is attached, reading events and using
  CPU, but no syscall is taxed, so its ratio must land at 1.0. If it does not,
  the two arms differ for a reason that is not tracepoints — monitor CPU
  contention, page-cache state — and every rung inherits that error. The run
  is then reported **VOID** rather than read.
- **Refusal over presentation.** A ratio whose IQR spans 1.0, or is as wide as
  the effect, is printed as NOT RESOLVED. 25 synthetic zero-effect runs under
  47 % drift are each required to come back unresolved, because a tool that
  invents a tax on even one machine-state is worse than one that reports
  nothing.
- **The monitor's own output on failure.** An earlier version raised a bare
  "did not attach" timeout and discarded what the monitor had printed — which
  is precisely how the 18 Oct verifier rejection would have looked from
  inside this tool: a timeout, while the kernel had explained exactly why.
  The failure now carries the last twelve lines, and stops the run instead of
  grinding through configurations that cannot load.

The central test is a competition between the two statistics on the same
synthetic data — 6.7 % effect under 47 % drift — and it asserts that per-pair
ratios land within 2 % of the truth **and** beat median-of-medians. If that
ever stops holding, the tool has no reason to exist and the test says so.

### The tax, measured — VM 2026-10-19

`tools/tax_paired.py`, first run on a kernel, **9 pairs per configuration,
desktop session left running**. Raw output in
`docs/evidence/tax_paired_vm_20261019.txt`.

| config | tp | ratio | IQR | ns/syscall* |
|---|---|---|---|---|
| `count_exit` | 0 | **0.9971** | 0.9536–1.0552 | −0.4 ← **control** |
| `count_exec` | 2 | 1.1065 | 1.0786–1.1454 | 14.6 |
| `count_open` | 4 | 1.1725 | 1.1628–1.2012 | 23.6 |
| `count_net` | 6 | 1.1820 | 1.1410–1.1909 | 24.9 |
| `count_all` | 12 | 1.1703 | 1.1415–1.3011 | 23.3 |

\* one common bare cost (the control's bare arm, 136.8 ns per bare syscall).

**The control reads 0.9971.** The monitor is attached, reading events and
burning CPU, with zero `syscalls:*` tracepoints — and the workload is
unaffected. That is the instrument check passing, on the same busy desktop
where `overhead_breakdown.sh` produced a 13.4 % noise floor and two
unreadable ladders. The statistic was the problem, not the machine.

**Read by adjacent rungs**, since the question is whether the NEXT hook costs
anything, not whether a configuration costs anything:

| step | verdict |
|---|---|
| 0 → 2 tp | **disjoint** — a real increase |
| 2 → 4 tp | **disjoint** — a real increase |
| 4 → 6 tp | overlap — nothing detectable |
| 6 → 12 tp | overlap — nothing detectable |

| Row | Finding | Status |
|---|---|---|
| 195 | **The per-syscall tracepoint tax saturates at 4 tracepoints, and tripling 4 → 12 costs nothing detectable.** First readable ladder this project has produced: the control arm lands at 0.9971, the first two rungs are disjoint from their neighbours, and 4/6/12 are mutually indistinguishable. The design decision is therefore **measured** rather than inferred — hook count is not a budget beyond the first few hooks. The absolute figure is ~15 ns at 2 tracepoints rising to ~24 ns and flat thereafter, on a 137 ns bare syscall | **measured on the VM** |
| 196 | **It refines v3.5g rather than confirming it.** v3.5g read ~16 ns and was described as "paid once at the first `syscalls:*` tracepoint". This run says the first rung is most of it but **not all**: 0 → 2 is real (~15 ns) and 2 → 4 is *also* real (~+9 ns), with saturation only from 4 onward. So the shape is "paid in the first few hooks and saturating", not a single step. `syscall_regfunc()` setting `TIF_SYSCALL_TRACEPOINT` once explains the step; it does not by itself explain a second increment, so there is a secondary per-syscall-number component that also saturates. Stated as an observation with a mechanism that is only partly accounted for, which is the honest position — and a better thesis sentence than a single number, because it says what is explained and what is not | measured; mechanism partly open |
| 197 | **Two bugs in the new tool, both exposed by its first real data.** (a) `ns/syscall` was converted using each configuration's **own** bare arm — which feeds the drift straight back in through the multiplication, exactly undoing what the per-pair ratio removed. The bare arms wandered 1.5–3.9 s across the run, so one ratio could have yielded ns figures 2.5× apart. Now converted with one common baseline, and a test asserts the two differ by >2× in the fixture so the guard cannot become vacuous. (b) The summary listed the **control** among the unresolved rungs and advised "raise `--pairs`" — telling the reader the instrument had failed at the moment it had worked. A control with no effect to resolve *should* have an IQR straddling 1.0 | fixed, unit-tested |

**What the reading logic is now, and why it is tested.** `saturation_point()`
is a pure function comparing adjacent IQRs, with 5 tests: the real observed
ladder (pinned, so a change to the logic cannot silently re-interpret the
measurement the design decision rests on), a synthetic paid-once ladder
(saturates at the first rung), a synthetic per-hook ladder (never saturates —
the result that would overturn the decision), and an all-noise ladder
(saturates immediately, which is the honest reading of "nothing was
distinguished"). 19 tests in all on this tool.

| Row | Finding | Status |
|---|---|---|
| 198 | **The result reproduces.** A second independent run on the same machine and settings: control 1.0319, and the adjacent-rung verdicts identical — 0→2 disjoint, 2→4 disjoint, 4→6 overlap, 6→12 overlap, **saturating at 4 tracepoints both times**. The 2-tracepoint cost is the most stable figure this project's overhead work has produced: **14.6 and 15.3 ns/syscall** across the two runs. The 4/6/12 absolutes wander (23.6/24.9/23.3 then 28.1/21.5/30.3) but are mutually indistinguishable *within* each run, which is exactly the claim being made. Note in run 2 the 6 tp rung came in **below** the 4 tp rung — their IQRs overlap, so that is consistent with "no difference" rather than a contradiction of it, and it is the reason the reading compares IQRs instead of point estimates | **measured and reproduced** |

**How to state it in the thesis.** Three independent legs, in descending
order of strength:

1. **Saturation, reproduced.** Beyond 4 syscall tracepoints the cost is not
   detectable — tripling 4 → 12 is free. Two runs, identical verdicts, on a
   machine noisy enough that the previous method could not read the ladder at
   all. This is the leg the design decision stands on, and it needs no
   nanosecond figure.
2. **The mechanism.** `syscall_regfunc()` sets `TIF_SYSCALL_TRACEPOINT` on
   every thread only at the first registration, then refcounts — which
   predicts a step, not a slope.
3. **The magnitude**, with its caveat: ~15 ns/syscall at the first two
   tracepoints (reproduced to within 0.7 ns), rising to roughly 22–30 ns by
   four and flat after, against a ~130 ns bare syscall. Quote the first
   figure; treat the second as a range, because that is what two runs support.

And the part the mechanism does **not** cover, which should be said rather
than smoothed over: the second increment (2 → 4 tracepoints) is real in both
runs and is not explained by a flag set once. Something per-syscall-number
also costs, and it too saturates. That is an open question, not a hole in the
conclusion.

**The lesson I would put in the thesis.** A green suite certifies exactly
what the suite can execute. 317 tests, three reviews and a gcc type-check
all passed on code the kernel then refused to load — and the thing that
caught it was running it. The reason the second attempt is sound is not that
I reasoned more carefully; it is that moving the logic to where it could be
tested made it testable.

**What this says about the review rounds.** Three independent reviews and 313
tests did not find this, and could not have: §H attacked the Python, §I
attacked the prose, and the unit suite cannot run eBPF. The defect sat in the
one layer whose only honest test is a kernel. That is an argument for the VM
step being a gate rather than a formality — and a caution about the
confidence a large green suite buys, which is exactly as much as the suite
can execute and no more.

## I. A third review — of the claims, not the code

The adversarial round in §H attacked the code. It did not read a single
sentence of prose. So a third reviewer was given the finished tree and one
instruction: find places where the project violates its own standing rule
that **nothing is claimed as working, fixed, measured or verified unless it
is, and anything untested is labelled untested**. Not bugs. Claims.

It found more than §H did, because by this point the code had been attacked
three times and the documentation had not been attacked once.

| ID | Severity | The claim | What was actually true |
|---|---|---|---|
| A1 | **P1** | A test docstring: "`events.decode` stopped using `ctypes.cast` in v3.6 — **3.42 µs per record became 0.199 µs**" | That is the 17x figure §E row 176 **retracts**, and row 176 says "the code comment that claimed 17x was corrected in the same commit". It was corrected in `hids/events.py` and not in `tests/test_layout.py`, so a retracted number sat in the suite and row 176's claim of having fixed it was itself false. Corrected, with the reason written into the docstring so the next reader knows why the paragraph exists |
| A2 | **P1** | §G: "Every row marked mutation-checked was verified… 22 mutants in all" | At the moment of the audit the suite did not pass — a test I had just strengthened errored — and a mutation pass means nothing without a green baseline. §G is now written from a pass over the **final** tree, and the count is stated with the uncaught mutants named rather than averaged away |
| A3 | **P1** | §H: "Each is reproduced as a test" (of R1–R5) | True of four. R4's snapshot half **errored before reaching its own assertion**: `_evict` deletes `gens[pid]` entirely when the list empties, and the test asserted `== []`. The fix was real, the proof was not. Both halves pass now, and the error taught the better test: the watermark only matters once the *last* generation of a pid is gone, so the test evicts them all first |
| A4 | P2 | Row 157: "mutation-checked (4 separate mutants)" | Instrumenting the four refusals over the whole suite shows `_settle`'s done-refusal is reached **0 times**: it is belt-and-braces behind `enter()`'s guard, as its own comment admits, so no test can fail when it is reverted. Restated as "3 of 4 guards mutation-checked", with the fourth named in §G |
| A5 | P2 | Row 158: `assembler.duplicates` "counts every instance so the trade is **visible rather than silent**" | The counter was incremented in five places and exported from **none** — not in `stats()`, so never in `--stats-json`. A refusal nobody can count is a silent drop with extra steps. `duplicates_refused` and `bad_arg_indexes` are now exported, documented, and covered by four tests, one of which checks the documented key list against the emitted one |
| A6 | P2 | A comment in `hids/events.py` breaking down a "**1.87 µs** decode" beside a published figure of 2.33 µs, deriving "29 % of ingest" from the unpublished one | Two measurements of one quantity, from different runs, in the same comment block. Both are now produced by one run of `tools/bench_ingest.py`, where the stages sum to the total because they must |
| A7 | P2 | A comment claiming the dead-node sort "**measured +2 µs per node creation**" | No harness, no run id, nothing in the tree supporting it — and the same magnitude as the drift that already invented one regression on this project (§E row 177). The figure is gone; the structural reason the code holds nodes rather than keys is given instead |
| A8 | P2 | `docs/ARCHITECTURE.md`: "**What a node costs, measured** (`tracemalloc`, this build)" | `grep -r tracemalloc` matched nothing outside that prose. The figures were assertions wearing the word "measured". Now measured by `tools/bench_nodes.py` on both interpreters, and they were **~40 % low**: FileNode ~746 B not ~530 B. Which makes the open question in that section sharper, not softer — `--max-files 200000` permits 149–677 MB against a peak RSS of 121 MB |
| A9 | P2 | `docs/VM_TEST_RUNBOOK.md` step 0: "Expect `version 3.5d`" | Three releases stale, in the step whose entire purpose is confirming the right build was unpacked. The runbook also told the reader to expect `OK` from a suite that was failing, and said "Nine steps" over ten |
| A10 | P2 | `README.md` and `ARCHITECTURE.md`: "gcc type-check in all **6** hook/feature combinations" | `COMBOS` has **8** and the test iterates all 8 |
| A11 | P2, **and my fix for it was also wrong** | `ARCHITECTURE.md`: "against a measured peak RSS of **~135 MB**" | I replaced it with the README's **121 MB**, calling that authoritative. The two describe different workloads — 121 MB is the overhead run, ~135 MB the stress run — and the 2026-10-19 validation measured **137.4–141.9 MB** under stress, so the original figure was closer to right for its condition than my replacement. Both now appear with their conditions. See §J step 5, point 3 |
| A12 | P2 | A test named `..._does_not_rescan_every_node` | It asserted `evicted == 0` and `_dead == {}`, both of which hold under the quadratic scan it was written to catch. The name promised what the body could not observe. `sorted` resolves through module globals, so the scan is now **counted**: the assertion is that it happens zero times |
| A13 | P2 | A test named `test_tracepoint_ladder_is_reported`, docstring: "the reading must say so with the numbers attached" | It asserted five labels were present and nothing about the verdict, so it passed whatever conclusion the report drew — including the opposite one. The whole hook-count design decision rests on that verdict, so it is now asserted, with the percentages beside it |
| A14 | P2 | `ARCHITECTURE.md` §11: "**Not hooked yet:** … `accept` (inbound connections)" and "Syscall tracepoints **may** tax all syscalls — *being measured*" | Both settled: `accept`/`accept4` were hooked in v3.5, and the tax was answered on the VM in v3.5g. Two sections had simply not been revisited while the README moved on. The roadmap's first three items were likewise already done |
| A15 | P3 | Row 175: "**12 000 randomised cases**" | 2000 buckets, each re-checked under 6 configurations — 12 000 comparisons. Restated |
| A16 | P3 | §H: "three independent reviewers… **two P2s**" | The table below it listed three P2s and a P3 |
| A17 | P3 | §H's five cross-references to the rows above (W1-F9 "row 165", `_dead` "row 173", …) | **Every one** pointed at the wrong row. All five corrected |
| A18 | P3 | A fixture comment: string fields filled "about a third of the time, so NUL handling is exercised both ways… embedded NUL, no NUL at all, invalid UTF-8", writing at offsets `(28, 44, 60)` | The string fields start at **48**. Two of three writes landed on `ts_ns` and `pstart_ns` and the third straddled `comm`, so all three claimed conditions arose only by luck of the random bytes. The offsets are now derived from ctypes, and a test asserts they overlap no scalar field |
| A19 | P3 | `test_sizes_quoted_in_docs`: "monitor.bpf.c **and docs/ARCHITECTURE.md** quote these numbers" | It read only the C source. Both are read now |
| A22 | P2 | §G implicitly: that the W1-F4 ordering fix was covered | `from_dict` has its own oldest-first sort, separate from the live path's, and **only the live one was tested**. The sweep deleted the restore sort and nothing failed: the round-trip fixture had no PID whose generation order differs from its start-time order — which is exactly the W1-F4 case the sort exists for. `test_w1_f4a_gens_are_still_oldest_first_across_a_snapshot` now round-trips a graph built newest-first, and asserts first that the fixture can actually see the difference |
| A23 | P3 | `_new_node`'s `max([hwm] + [k[1] for k in keys]) + 1` | The `keys` term is **dead given the watermark**: `hwm` is already ≥ every surviving generation, so a mutant dropping it computes the same number on every input — an equivalent mutant, uncatchable by any test rather than merely untested. Not a coverage hole, and not removed: simplifying to `hwm + 1` would make key uniqueness rest on one invariant with no backstop. Documented as redundant at the site, so the next reader does not mistake it for load-bearing |
| A24 | P2 | §G implicitly: that `own_span` was covered | `_touch` carries its own handback, separate from `process()`'s, and only `process()`'s was tested — disabling `_touch`'s failed nothing, because no event can reach `_touch` without `process()` having run first. Reachable by direct call, which is how a query tool or a replay would reach it, so `test_touch_hands_a_borrowed_span_back_on_a_direct_record` now calls it that way. Third of its kind in this release, after `_place` and `_struct_format` |
| A21 | **P1** | Row 157: "the obvious fix is worse than the bug… every later tick re-settles it and `record_exec` runs again on each one" | An independent mutation sweep applied exactly that alternative — claim *after* the fallible call — and **no test failed**, because my own mutation of that fix had been cruder (removing the claim entirely), which the suite did catch. So the pass had reported row 157 covered while its central design argument was untested. Probing it showed the stated consequence is also no longer true: `last_settled_exec` refuses the duplicate graph write, so `execs` stays 1 and the real cost is one wasted settle plus a late claim. The argument is now correctly stated in both the row and the docstring, and `TheObviousAlternativeIsWorseTest` fails if the ordering is reverted |
| A20 | P3 | Row 174's memory figures, and "Real data: 130 causes → 1", and "the v3.5i load test measured 38.1 MB" | Scratch-script figures, an unsourced illustration, and a figure from a document not in this tree. The first is now produced by `tools/bench_nodes.py` (and differs: → 6 objects, −27 %, because the file count differs); the second is labelled illustrative; the third is labelled as attributed, with the note that the change does not rest on it |

**Three things this round changed about how the project works, not just what it says.**

*Benchmarks ship.* Every performance figure in §C was produced by a script in
a scratch directory. `tools/bench_ingest.py` and `tools/bench_nodes.py` are
now in the tree with their evidence in `docs/evidence/`, and re-running them
changed three figures — including one by 40 %. A number nobody else can
produce is a claim, however carefully it was measured the first time.

*The right statistic was not the obvious one.* The ingest ratio looked
unpublishable: a spread of ~50 % around an effect of 34 %. But the medians
were stable across independent runs, which is the signature of a skewed
sample, not a noisy effect. Comparing the two variants **per pair** and
taking the spread of those ratios — rather than comparing medians of
separate sample sets — gives 1.34x with an IQR of 1.32–1.38. The harness
prints the spread beside every ratio and says `SPREAD >= EFFECT` when the
figure does not deserve to be quoted, because on this project a drifting
control has already invented both a regression and a speedup.

*Numbers in prose now fail builds.* Four documents quoted the suite size and
nothing checked them; so did the hook-combination count, the runbook's
expected version, and the node-cost table. Each is now read by a test, and
the node-cost table is checked against a live `tracemalloc` measurement at
the shape the document itself states. The guards are deliberately written to
cover **every** copy, because §F of this changelog already records what a
guard that checks two of three places is worth: it reports agreement it did
not verify.

## G. Suite

**436 tests** (195 added), Python 3.8.20, 3.11.17, 3.12.3 and 3.13.16, each
run **from inside the packaged zip** by `tools/package.sh` — the working tree
passing proves nothing about what ships, because a file left out of the
archive still passes in the tree it was never removed from. That script is
in the tree so this claim can be reproduced rather than taken on trust.
`tests/test_review_v35i.py` names one test per fixed finding, so
`grep -n "def test_" tests/test_review_v35i.py` is the fix list.

### Mutation accounting, in full

A finding is fixed here only if reverting the fix fails a **named** test.
That was checked in three passes, each by copying the tree and mutating the
copy. The second exists because the first could not have covered it — the
guards added in response to §H did not exist when pass 1 ran — and the third
because the first two were written by the same person who wrote the fixes.

| Pass | What it mutated | Mutants | Caught |
|---|---|---|---|
| 1 | the fifteen v3.5i fixes and the four performance changes (§A–§C) | 22 | 18 |
| 2 | the guards v3.6 itself added, on the final tree (§H and §I) | 15 | 15 |
| 3 | an independent sweep, built from a description of the guards rather than from my own mutant list | 37 planned, **24 run** | 20 caught, 3 genuine misses (all now closed), 1 equivalent mutant |

Pass 1's four misses, and what happened to each:

- **`_place`'s negative-index refusal** — genuinely untested: nothing called
  `_place` directly, because `arg()`'s validation stops a bad index first.
  Now called directly by `test_place_refuses_a_negative_index`. Caught.
- **`_maybe_evict`'s O(1) short-circuit** — the test named for it asserted
  `evicted == 0` and `_dead == {}`, which hold under the quadratic scan too
  (§I, A12). `sorted` resolves through module globals, so the scan is now
  counted and the assertion is that it runs zero times. Caught.
- **`_struct_format`'s refusals** — two separate guards. The unsupported-field
  refusal was simply untested and now is. The **size check** cannot fire
  today at all: padding is derived from each field's real offset, so the
  format always matches `ctypes.sizeof`. What it actually guards is the code
  TABLE — an entry whose struct code is a different width from its ctypes
  type would decode every later field from the wrong offset — and
  substituting such an entry is the reachable form of that mistake. Both
  caught.
- **`_settle`'s refusal of a key already in `done`** — **still uncaught, and
  it should be.** Instrumenting all four of row 157's refusals and running
  the whole suite shows this one is reached **0 times**: it sits behind
  `enter()`'s guard, as its own comment says. So no test can fail when it is
  reverted, and row 157 now claims 3 of 4 rather than 4. It is kept because
  the cost is one dict lookup and the failure it would catch is an exec
  recorded as both a success and a failure.

Pass 3 is the one that found things, and the reason is worth keeping:
**a mutant written by the author of a fix tends to break the fix the way the
author imagines breaking it.** Given only a description of each guard, an
independent sweep broke three of them in ways I had not:

- `_commit`'s claim moved **after** the fallible call — the alternative row
  157 argues against — where my own mutant had removed the claim outright.
  The crude one was caught, the subtle one was not, so the fix counted as
  covered while the argument for its shape was untested. Probing it then
  showed the row's stated consequence was itself stale (§I/A21).
- `from_dict`'s oldest-first sort deleted. The live path's sort was tested;
  the restore path's was not, and the round-trip fixture could not have seen
  the difference (§I/A22).
- `_touch`'s `own_span` handback disabled. A **third** guard behind a guard:
  through the pipeline it can never fire, because every event resolves its
  node through `process()` first, which hands the span back there. It still
  earned a test rather than a comment, because anything holding a node
  reference — a query tool, a replay, a caller that resolves once and records
  several events — reaches `_touch` without passing `process()` again
  (§I/A24).
- `max()+1`'s `keys` term dropped — which turned out to be an **equivalent
  mutant**, not a coverage hole: the watermark makes that term dead. Worth
  recording because "no test caught it" and "no test could" are different
  findings and only one of them is a gap (§I/A23).

All three real gaps are closed, each verified by re-applying the sweep's own
mutation to a copy of the finished tree and confirming the new test — and
only the new test — fails.

**Pass 3 stopped at 24 of its 37 mutants**, on a rate limit rather than a
result, and that is stated here rather than rounded up. What it did not reach
is not unexamined: mutants 18–28 of its list are the same guards pass 2
mutated on the final tree, where all 15 came back caught, and its 29a/29b
(the version and test-count guards) were then mutated separately — 29b once
per document, because the sweep's own mutation touched only the README and
the other three copies are exactly the hole that guard was widened to close.
Five mutants, five caught. What is genuinely missing is a *differently
imagined* mutation of those eleven guards, of the kind that found the three
gaps above. On the evidence of this round that is worth doing, and it is
recorded as the first item for the next one rather than quietly dropped.

So, counting the distinct guards rather than the mutants (passes overlap):
every fix in §A–§C and every guard in §H is caught by a named test, with
**two exceptions, both deliberate and both demonstrated rather than
asserted**: `_settle`'s done-refusal, which instrumentation shows is reached
0 times across the whole suite, and the `keys` term in `_new_node`, which is
an equivalent mutant.

Two further things are deliberately not mutation-checked and are not counted
above: the defensive `n.key not in self.nodes` skip in `_maybe_evict`, which
`_note_dead`'s membership check already makes unreachable (kept because
being wrong once cost a monitor that stops bounding memory), and the
benchmark harnesses, which measure rather than assert.

**Nothing in v3.6 has run on the VM.** The decode rewrite changes how every
record is read, so `vm_validation.sh` (23/23 expected) and a live
`--mode print` run are required before any v3.6 figure is quoted as
VM-verified.
