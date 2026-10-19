# v3.5 — inbound telemetry (the `accept` hook)

Journal-ready rows. Status wording follows the Journal legend: an item is
"not yet tested" until it has run on the VM, however many unit tests cover
it.

**What this closes:** until now the monitor could see this host reaching
out and was blind to anything reaching in. Lateral movement was visible on
one side only — we could watch a compromised host scan its neighbours, but
not watch it being reached. For a HIDS whose threat model names lateral
movement, that is half a sensor.

---

## A. What the kernel actually does, established before writing any code

Two facts decided the whole design, and neither was assumed.

**A1. Both `accept` and `accept4` are really used.** Under `strace`:
glibc's C `accept()` issues `__NR_accept`, while Python's
`socket.accept()` issues `__NR_accept4` with `SOCK_CLOEXEC`.

```
accept(3, {sa_family=AF_INET, sin_port=htons(59524), ...}, [16]) = 4   # C
accept4(3, {sa_family=AF_INET, sin_port=htons(45192), ...}, [16], SOCK_CLOEXEC) = 5   # Python
```

Hooking one of the two would make half the servers on a box invisible,
with nothing in the output to suggest anything was missing. Both are
hooked. (Measured in the dev container; the VM's glibc 2.31 should behave
the same way, and the VM run will confirm it rather than assume it.)

**A2. The peer address is written by the kernel, inside the syscall.** In
v5.4 `net/socket.c`, `__sys_accept4()` does:

```c
if (upeer_sockaddr) {
        len = newsock->ops->getname(newsock, (struct sockaddr *)&address, 2);
        if (len < 0) { err = -ECONNABORTED; goto out_fd; }
        err = move_addr_to_user(&address, len, upeer_sockaddr, upeer_addrlen);
        if (err < 0) goto out_fd;
}
/* File flags are not inherited via accept() unlike another OSes. */
fd_install(newfd, newfile);
err = newfd;
```

Three consequences, and all three are load-bearing:

1. The buffer holds nothing useful at syscall **entry** — so, unlike
   `connect`, the address must be read at **exit**.
2. On a successful return the copy is guaranteed to have happened: a
   failure in `move_addr_to_user` jumps to `out_fd` and the whole syscall
   fails. Reading the buffer only when `ret >= 0` can never read garbage.
3. **The writer is the kernel, not the process.** An accepted peer address
   therefore cannot be spoofed by the process being monitored, where a
   `connect` target always can be. This is the first value in the system
   with that property, and it is exactly the kind of value an enforcement
   layer should prefer to act on.

## B. Design decisions, and why

| # | Decision | Reasoning |
|---|---|---|
| B1 | Hook `accept` **and** `accept4`, enter and exit | A1 above. Four more tracepoints, which also widens the overhead ladder usefully (below). |
| B2 | Parse the peer at syscall **exit**, only when `ret >= 0` | A2 above. The mirror image of the connect hook, for a reason that is in the kernel source rather than in taste. |
| B3 | A failed accept is **dropped in the kernel** | `-EAGAIN` fires on every poll of a non-blocking listener and `-EINTR` on every signal: no peer exists, no buffer was written, nothing happened. Keeping them would flood the ring with the absence of events. This is the opposite of the connect rule, where a refusal is *the* signal — a refused connect is what a port scan looks like from inside the host. The asymmetry is in what the failure means. |
| B4 | An inbound endpoint is keyed `host:<addr>` — **no port** | The port in an accepted `sockaddr` is the peer's *ephemeral source* port: measured at 45192, then 51022, then 59524 for connections to the same service. On an outbound connect the port is the service (443, 22) and belongs in the identity; inbound it is noise that would mint a fresh node per connection and turn "who keeps connecting to this box" into thousands of singletons — the dependency-explosion problem in a new place. Which of *our* ports was reached is a property of the accepting process, and the kernel keeps the local port where `sock:inet_sock_set_state` can read it (next step). |
| B5 | Reuse `net_t` with a direction flag, not a fourth record type | "Who did this, when, on which socket, to which peer" is the same set of facts in both directions. The record layout, its size (256 bytes) and the decode path are unchanged; `NET_FLAG_INBOUND` picks the handler. |
| B6 | `accept` stashes live in their **own** LRU map | A listener can sit blocked inside `accept()` for hours. An LRU evicts the oldest entry, so sharing one map with `connect` would let ordinary outbound churn — 16 384 connects on a busy host — discard the stash of the one blocked accept that matters most, and that inbound connection would be missed entirely at exit. Separating them means only other accepts can evict an accept. Costs 256 KB of kernel memory. |
| B7 | `ACCEPT` is a distinct edge **kind**, traversed exactly like `CONNECT` | Separate kind, because "we called out" and "they called in" are opposite findings for a detector (exfiltration versus arriving lateral movement) and a label is the cheapest way to keep them apart. Same traversal, because a TCP connection is a two-way channel whichever side opened it: a bind shell accepts and then sends files out, an HTTP client connects out and reads a payload in. Restricting either kind to one direction of the walk would hide one of those. |
| B8 | No peer name → say so (`NET_FLAG_NOPEER`), never invent one | `accept(fd, NULL, NULL)` is legal and common, and a unix client normally has no bound address, so `getname()` returns only the family. The connection is counted; it simply has no peer identity. Reporting `0.0.0.0` would be a fact the kernel never stated. |
| B9 | Inbound and outbound to the same host are two nodes | `host:10.0.0.9` and `net:10.0.0.9:443` are different relationships with the same counterparty. Merging them would read as one. |

## C. Rows

| Row | Change | Status |
|---|---|---|
| 86 | `accept`/`accept4` syscall facts established by `strace` before writing the hook: glibc uses `__NR_accept`, Python uses `__NR_accept4`; a peer's source port differs on every connection | measured in the dev container · **to be reconfirmed on the VM's glibc** |
| 87 | The kernel-writes-the-buffer property read out of v5.4 `net/socket.c` and written into the code comments: read at exit, only on success, and the resulting value is not spoofable by the monitored process | source-verified (quoted in section A) |
| 88 | `sys_enter_accept` / `sys_exit_accept` / `sys_enter_accept4` / `sys_exit_accept4` added behind `HOOK_NET`; peer parsed for AF_INET, AF_INET6 and AF_UNIX | type-checked in all 6 hook/feature combinations by the gcc harness · **not yet tested on the VM** |
| 89 | The `net` hook group now enables 6 syscall tracepoints instead of 2, so the cost ladder widened from 0/2/2/4/8 to **0/2/4/6/12** | the ladder reading is tested on synthetic timings; the measurement itself is still the open question (CHANGES_v3.4 §C) |
| 90 | One record type carries both directions (`NET_FLAG_INBOUND`), record layout and size unchanged at 256 bytes; `NET_FLAG_NOPEER` marks a connection the kernel could not name | layout test unchanged and still passing; flags asserted to be distinct single bits, since an inbound record with no peer carries both |
| 91 | Graph: `record_accept()`, the `ACCEPT` edge, per-process `accepts`/`accept_count`/`nopeer_accepts`, and an `inbound_hosts` summary counted from the endpoint side so it survives a process record being evicted | unit-tested, including the arriving-lateral-movement chain (peer → sshd → shell → file written) in both directions |
| 92 | Inbound endpoints keyed by host (B4). A regression check asserts that several connections from one host on different source ports collapse to **one** node | unit-tested, and asserted on real demo data by the run analyzer |
| 93 | Separate `accept_args` LRU map (B6) | design applied, reasoned from how LRU eviction interacts with a blocked listener · **not yet tested under churn** |
| 94 | Queries: new `inbound` verb (hosts that connected in, grouped by host), `peers` now shows direction per connection, `endpoints` gained an in/out/both column | unit-tested through the CLI |
| 95 | `net_demo.py` scenario 5: a server child publishes its kernel-chosen port through a written-then-renamed file, a client child connects, so an accepted connection is attributed to a process that is **not** the one that connected | runs standalone here; wired into `vm_validation.sh` · **not yet run on the VM** |
| 96 | Two new analyzer checks (inbound attribution; host-keyed identity) and two new numbers (unnamed peers, hosts seen inbound). Check count 21 → 23 | the analyzer's own test proves both new checks FAIL when the inbound events are removed — the first version of the identity check passed on an empty set, which is not a check, and was fixed |
| 97 | Snapshot format still version 4: `accepts`, `accept_count` and `nopeer_accepts` are optional keys, so pre-v3.5 snapshots load with inbound simply empty | unit-tested, including the endpoint side |
| 98 | The `--type` drift guard added earlier the same day (row 85) caught the missing `--type accept` choice within the hour, before it could reach a VM run | the guard works as intended; this is the second class of bug it has prevented |

Suite after the feature work: **164 tests**, Python 3.8 and 3.12.

## C2. Hardening rows — the adversarial review of v3.5

Found by an independent break-it review of the pristine v3.5 tree
(`ESE-P15_v3.5_Adversarial_Review.docx`, findings H1–H3), all three
reproduced here before being fixed. None of them is in the inbound feature:
they are in the walk logic the feature was built on, and two of them predate
v3.5.

| Row | Change | Status |
|---|---|---|
| 99 | **H1 — an effect that predates its cause.** `trace_forward` listed FORK edges without checking the time bound, the only branch that did not. Reaching a process through a file read at 50 s then listed a child forked at 41 s as an effect of that read | reproduced, fixed (`ts >= t` on the FORK branch), regression-tested; mutation-checked |
| 100 | **H2 — the stale-writer bug, and it was worse than a missing edge.** `seen` was keyed on the node alone, so a file reached at two different times was expanded once, at whichever bound arrived first. A file read at 100 s and again at 296 s, written at 50 s and 200 s, reported the 296 s read as coming from the 50 s writer: a **confidently wrong** provenance answer, not an omission | reproduced, fixed: `seen` is now keyed `(node, bound)` because each distinct bound is a different causal question, with a `listed` set keyed `(source, kind, ts)` so re-expansion cannot duplicate output |
| 101 | **H3 — record arrival order inflated `first_ns`.** `_touch()` maintained only `last_ns`, so `first_ns` was "the first record *processed*", not the earliest event. Per-CPU perf buffers reorder across CPUs — the reason `ExecAssembler` exists — so this is the normal condition, not a corner case. A 300 s event arriving after a 500 s one left `first_ns` 200 s too late | reproduced, fixed in `_touch` **and** in `process()`, which updated `last_ns` inline and so had the same gap |
| 102 | The FORK edge now carries the **true fork time**, not a clamp. The review's fix was `min(first_ns, bound)`, which never violates the time law but reports the bound as if it were a timestamp. The kernel already gives us `task->start_time` on every record, in the same CLOCK_MONOTONIC as the event timestamps: when `start_exact` it *is* the fork moment and is provably no later than any event of that node. `_fork_ts()` returns it, falls back to `min(start_ns, first_ns)` for a /proc-estimated start, and clamps to the bound only as a last resort | fixed; the test asserts the edge reads 10 s (the real fork) where the old code said 500 s and the proposed fix would have said 300 s |
| 103 | **A fourth consequence of H3, still open after the review's three fixes.** An inferred exit stamped `old.exit_ns = node.first_ns` at the moment the new generation appeared — so lowering `first_ns` afterwards (row 101) left the stamp stale, and the old generation looked alive 490 s longer than possible. Now `old.exit_ns = _fork_ts(new)`: a PID is not reused until its previous holder is gone, so the new generation's fork time is a *provable* upper bound on the old one's exit | found by a test written for this round, fixed, mutation-checked |
| 104 | Per-bound expansion needs a work budget as well as an output cap: with deduped edges the queue can stay busy without the result growing. `max_visits=4000` bounds the work; termination itself does not depend on it (bounds come from a finite set of timestamps already in the graph) | tested on the pathological shape — one file written and read 400 times alternately — which completes in well under a second and still attributes every read to the write immediately before it |
| 105 | **Endpoint LRU cap** (`--max-endpoints`, default 200 000), the review's design note. Files have been capped since v3.2; endpoints were not, which was defensible while only our own processes could create them. Inbound changes who holds the pen: any host that can reach a listening socket can mint a `host:<addr>` node, so an uncapped map is memory growth driven by a remote party — in the monitor, which is the last place for it | implemented with the same LRU as files, counted in `stats["evicted_endpoints"]`, unit-tested both capped and uncapped |
| 106 | `at_ns` added to both walks, so "what had caused this as of time T" is answerable — the question an analyst holding an alert timestamp actually asks | implemented and tested. Correction to the review's framing: nothing was *removed* in v3.4. `before_ns` has always been an internal parameter of `_in_edges`; `trace_back` never exposed a time bound in v3.1, v3.3 or v3.4 (checked against the packaged builds). The suggestion was good, the history was not |
| 107 | `tests/test_adversarial.py` — 14 tests written from the attacker's side of the contract, including a **5-seed × 15-trial fuzz** that builds a graph from fully shuffled record arrival and asserts the two time laws (no cause in the future, no effect before its cause) plus the `first_ns` invariant on every node | all pass; each of the four fixes was mutation-checked by reverting it and confirming which test fires — the fuzz independently catches H1, H3 and the `_fork_ts` change |
| 108 | The review's own `p15_v35_hardening.patch` and its 17-test file were **not received** — only the document. The fixes here were written from the findings' descriptions after reproducing each bug locally, so the trees will differ: 178 tests here versus 181 reported there, and the H2 fix uses the same `(node, bound)` idea while H3 goes further (rows 102–103) | the patch should be merged and the test sets de-duplicated when it arrives; three of its 17 tests are unaccounted for here |

Suite after hardening: **178 tests**, Python 3.8 and 3.12.

**Carried note from the review, confirmed:** H3 is in the v3.4c line too —
same `_touch`. v3.5 supersedes it here, so nothing is left to patch, but any
copy of v3.4c elsewhere wants the one-line fix.

## C3. Rows from the v3.5a rating round

The rating (8.5/10 overall, 4/10 on overhead — unchanged, and correctly the
only number that matters until the VM runs) came with a P1/P2 catalog. The
P0 items are VM runs and cannot be closed here. The rest are closed below.

| Row | Change | Status |
|---|---|---|
| 109 | `--at SECONDS` on `query_graph.py trace` and `impact`: the point-in-time walk is now reachable by an analyst, not only from Python (P1). Timestamps are printed per edge so the answer can be checked against the log | unit-tested through the CLI, including that `--at` is rejected on commands where it has no meaning |
| 110 | **IPv6 inbound ids are bracketed**: `host:[::1]`, not `host:::1` (P2, filed as cosmetic — it is not). The unbracketed form cannot be split back into scheme and address by anything, a person typing it into a query included, and the outbound id has always used brackets | fixed, unit-tested |
| 111 | **`--max-endpoints` default lowered 200 000 → 25 000, from a measurement rather than a guess** (P1). `tracemalloc` on this build: an EndpointNode costs ~380 B with one access and ~2.4 KB with twenty; a FileNode ~530 B / ~2.6 KB. So 25 000 endpoints is ~9 MB typical, ~59 MB worst; at 200 000 it would have been 76–476 MB, larger than the whole monitor on the test VM. The figures and the reasoning are in `ARCHITECTURE.md` §7, and a test asserts the default still matches them | measured, documented, guarded by a test |
| 112 | **The same measurement raises a question about a default we did not touch:** `--max-files 200000` implies **106–516 MB** of graph memory against a measured peak RSS of ~135 MB. The cap is therefore not a safety bound at all — it is larger than the machine. Lowering it to ~50 000 (~26 MB typical) would make it one, at the cost of forensic history on a file-heavy host | **open question, deliberately not decided** — it changes what the tool remembers, so it belongs in a meeting, not in a commit. Written up in `ARCHITECTURE.md` §7 |
| 113 | `max_visits=4000` validated rather than left as a heuristic (P1): on the pathological 3 000-touch file the walk takes ~3 ms at the default and ~5 ms at 100 000, because `max_items` binds first. The budget is a backstop against a shape we have not thought of, not a performance lever. A test asserts the *shape* of that result (25× the budget changes nothing material) instead of a millisecond number, so it cannot become a flaky timing test | measured; tested as an invariant |
| 114 | Three test classes added for the gaps the rating named: PID-reuse isolation asked at the walk level (generations must not share history, and a walk must not cross the boundary even when both generations touched the same endpoint), a child seen before its parent (placeholder path), and an order-equivalence test — the same five events fed forwards and reversed must produce *equal* causal answers, not merely valid ones | all pass. One of them initially failed on my own wrong expectation about placeholder renaming; the code was right, and the rule it follows (a late pre-exec record must not rename a node, Journal row 12) is now written into the test |
| 115 | BPF `accept_enter` re-entry documented in the code: one stash per thread, so a signal handler calling `accept()` inside a blocked `accept()` loses the outer record. Shared with the connect path, left alone deliberately — the fix is a per-thread stash stack, which costs map space on every thread to cover a case that needs a signal handler doing socket I/O | documented, not changed |
| 116 | Not done, with reasons: the `emit()` closure is left per-call (a shared helper would need more parameters than the closure saves, and would mean touching both walks again for style); JSON snapshots remain the only persistence (DuckDB is the planned step, not a patch); UDP, the local port, and server-side unix attribution stay open as documented in §E | — |

> **Superseded (v3.6).** The per-node figures quoted in rows 111 and 112 (~380 B endpoint, ~530 B file, and the ~135 MB peak RSS they are weighed against) had no harness in the tree and were ~40 % low. Measured by `tools/bench_nodes.py`: FileNode ~746 B / ~3.3 KB, EndpointNode ~356 B / ~2.8 KB on Python 3.8.20, against the authoritative VM peak RSS of 121 MB. The open question in row 112 gets sharper, not softer: `--max-files 200000` permits 149–677 MB. See `CHANGES_v3.6.md` §I/A8 and A11. The rows above are left as written, because this file is a record of what was claimed at the time.


**One presentation limitation found while testing `--at`:** the walk returns
a flat list of `(depth, kind, ts, description)`, and the CLI indents by
depth. When a file is expanded at two different bounds (row 100), both
writers come back at the same depth, so they render under the *last* read
rather than each under its own. The data is right and the timestamps now
printed beside each edge disambiguate it, but the tree shape can mislead a
reader. Fixing it properly means carrying the parent edge in the result
tuple — an API change, not a patch, so it is recorded rather than rushed.

Suite after this round: **233 tests**, Python 3.8 and 3.12.

## C4. Corner-case sweep of the graph (16 Oct 2026)

A systematic sweep rather than a review response: for each part of the
model, the degenerate, saturated and contradictory inputs it can be handed.
Probed first, so the tests were written around behaviour that was actually
wrong rather than around guesses. **Six findings, three of them
correctness.** New file `tests/test_corners.py` (37 tests), organised as the
taxonomy A–G it sweeps.

| Row | Finding | Severity | Status |
|---|---|---|---|
| 117 | **A flood of reads evicted the write that caused them.** `FileNode` kept one capped `accesses` list for every kind, so a file read 2 000 times after being written once lost the write — and a backward walk then reported **no writer at all**. Silent, and the worst shape of wrong: a confident "nobody put these bytes here" | high | fixed: writes live in their own list (`MAX_WRITES_PER_FILE`, 256) that activity cannot evict; the walk reads that list, which is also ~8× shorter to scan. Snapshots rebuild it from the log when loading a pre-v3.5d capture |
| 118 | **One relationship, repeated, crowded out everything else.** The same scenario had a second cause: 2 050 reads produce 2 051 input edges, 200 of which fill `max_items` at depth 1, so the walk never descended to the writer. Every edge was formally correct and the answer was still useless — dependency explosion by *repetition* rather than by fan-out | high | fixed: `MAX_EDGES_PER_RESOURCE` (8) caps how many edges one resource contributes to a step — newest per resource going backwards, earliest going forwards, because the earliest effect reaches the widest downstream set. The pathological walk went from 200 uninformative edges to 11 informative ones |
| 119 | **The backward FORK edge ignored the time bound** — the mirror of H1, still present after that fix. It was listed unconditionally with its timestamp *clamped* to the bound, so `trace_back(p, at_ns=0)` reported p's parent dated 0 for a process forked at 10 s: a cause that had not happened yet, wearing a made-up timestamp | medium | fixed: the fork obeys the bound like every other edge kind. Asking what caused a process before it existed now answers nothing, which is the honest answer |
| 120 | An **evicted parent** left its child rendered beside `systemd` as a root — "started by nobody" — in the live tree | low | fixed: the line is marked `[parent 200 evicted]`. Eviction makes a walk incomplete; saying so beats implying a fact |
| 121 | **Two generations of one PID rendered identically** (`nc(777)`), so a walk result could not say which of two processes wrote a file. The whole purpose of generations is that they are different processes. Same class for a file replaced at one path: two inode nodes, one label | medium | fixed: `_desc()` adds a discriminator only when the graph can see the ambiguity — `nc(777#1)`, `/tmp/same#11`. `lineage_str` now goes through it too, so a lineage and a walk cannot contradict each other. Two existing tests pinned the old ambiguous strings and were updated deliberately |
| 122 | **A `parent_key` cycle made `render_tree` print nothing at all.** No node had a missing parent, so there were no roots, so the live view was empty — a monitor showing no processes is the worst failure mode available | medium | fixed: anything unreachable from a root is listed under "(unreachable — parent cycle or missing link)". `lineage()` was already cycle-safe |

**Confirmed correct, now pinned by tests rather than by belief:** cycles
through two files terminate (40-iteration cycle, <2 ms); a child naming a
*non-current* parent generation resolves to the right lifetime; a
placeholder parent has an *exact* start time (the child's record carried
the kernel's value) and is upgraded rather than duplicated; inode reuse
with a new generation is a new node; one inode under many names is one
node; `max_depth=0`, `max_items=7`, `skip`-everything and empty graphs all
return rather than crash; walks start from any node type; an exited process
answers in both directions; eviction never removes a live process; the
snapshot version guard refuses an unknown version *and* a missing one.

Each of the six fixes was mutation-checked: reverted one at a time,
confirming which tests fire (117 → 2, 118 → 2, 119 → 1, 121 → 4, 122 → 1).

Suite after the sweep: **233 tests**, Python 3.8 and 3.12.

---

# v3.5e — the 16 Oct VM run

The first time v3.5 met a kernel. **23/23 functional checks, 227 unit tests
OK on the VM, 0 records lost, 0 processing errors**, and the full feature
set verified — `KERNEL_EXEC_PATH, FILE_IDENTITY, SOCKET_TYPE`, nothing
refused. Run: `runs/validation-20261015-183437` (the VM clock runs ~4 h
behind UTC; the monotonic timestamps inside the run are unaffected).

## A. What the run settles

| Row | Claim | Evidence from this run |
|---|---|---|
| 123 | **The accept probes verify on 5.4.** gcc type-checking was never proof; the verifier is. All 14 tracepoint programs loaded, including the exit-side `probe_read` chain and the `fd → file → private_data → socket` walk | `features USED: ['KERNEL_EXEC_PATH', 'FILE_IDENTITY', 'SOCKET_TYPE']`, `features REFUSED: []`, compile 4.76 s |
| 124 | **Both accept syscalls are traceable here**, so hooking one would have been a silent gap | `sys_enter_accept`, `sys_enter_accept4`, `sys_exit_accept`, `sys_exit_accept4` all present in `/sys/kernel/debug/tracing/events/syscalls/` — the net group really is 6 syscall tracepoints |
| 125 | **`openat2` genuinely cannot be tested on this VM** — the claim in the roadmap is now evidenced rather than assumed | `grep -c openat2` over the tracepoint directory returns **0** |
| 126 | **The v3.4 WRITE-edge bug is fixed on real kernel data**, not just in a synthetic story | `relative path linked through inode (write -> read)` PASSED with `FORK bash(11443), READ inode:8388609:412878:478568002, EXEC /usr/bin/cat, FORK bash(6850), WRITE bash(11443)` — the same process listed as both FORK and WRITE, which is exactly the shape that silently dropped the write on 13 Oct |
| 127 | **Inbound host-keying holds on live traffic**, with more evidence than the demo was designed to produce | `4 connection(s) from 4 distinct source port(s) -> ['host:127.0.0.1']`; separately, two `curl`s showed source ports 55758 and 55772 collapsing to one node |
| 128 | **The IPv6 bracket fix (row 110) earned itself immediately.** An inbound SSH over IPv6 loopback was captured with full lineage; without the fix this id would have read the unsplittable `host:::1` | `ACCEPT sshd(736) host:[::1] inbound from port 50826 -> fd 5 [stream]`, lineage `systemd(1) → sshd(736)` |
| 129 | **`NET_FLAG_NOPEER` appeared on a case nobody wrote a test for**: `ssh-agent` accepting a unix client with no bound name. No endpoint node was invented | `ACCEPT ssh-agent(1159) peer unknown inbound from port 0 -> fd 4 [stream]`; `ACCEPT_UNIX: 1, ACCEPT_NOPEER: 1`, and `inbound_hosts` stayed at 2 rather than 3 |
| 130 | `SOCKET_TYPE` resolves the socket behind the fd through the verifier on 5.4 | `[stream]` on all four ACCEPT records; `socket type resolved: 6 / 6 connects` |
| 131 | The server-child scenario proves inbound **attribution**, not just capture | `inbound` query: `host:127.0.0.1  4 connections, 2 process(es)` — the demo's parent and its dedicated server child (11454), i.e. the accept is credited to a process that is not the connector |

Also: 504/504 files identified by inode, 200/200 exec burst with complete
lineage, 27/27 execs fully assembled, 0 `?` lineages out of 1,359 events,
zero self-events.

## B. What the run corrects — against us

| Row | Correction |
|---|---|
| 132 | **Row 76 does not reproduce, and the conclusion drawn from it was wrong.** It read "buffer size demonstrably matters" from a 13-Oct run that lost 20,765 records (18.43 %) at 64 pages/CPU and none at 256. This run lost **0 at both sizes** — 68,686 records at p64 (3,044 rec/s) and 74,163 at p256 (3,292 rec/s), same workload. So the variable is not the page count but the **burst rate**: at ~3 k records/s, 64 pages/CPU is sufficient, and the 13-Oct loss came from a heavier burst (4,076 rec/s *received*, with ~5,000/s actually produced). Row 76 is superseded: buffer size is a lever that matters *at high burst rates*, which is a narrower and defensible claim |
| 133 | **Percentage slowdown is not comparable across runs on this VM, and we should stop quoting it as if it were.** `find /usr` has now measured +917 % (0.73 → 7.41 s, today), +1325 % (13 Oct) and +3516 % (the review's run) — because the *baseline* moved from 0.26 s to 0.73 s between runs. The absolute pair is the only transferable figure. Today's quotable numbers: **exec loop 6.65 → 12.96 s (+94.7 %)**, **find /usr 0.73 → 7.41 s**, monitor CPU **35.9 % / 36.8 %** of one core at p64 / p256, peak RSS **121–124 MB** |
| 134 | **The noise filter missed two file classes**, found by reading the evidence string of a check that *passed*: four of the eight visible edges in the network-boundary chain were `/usr/share/zoneinfo/America/New_York` and Python package metadata under `/usr/local/lib/python3.8/dist-packages`. The prefix list had `/usr/lib/` but not `/usr/local/lib/`, and no zoneinfo | fixed, and the rule itself sharpened — see below |

## C. The noise rule, sharpened rather than extended

Adding `/usr/local/lib/` to the prefix list would also have hidden `.pth`
files, and appending an `import` line to a `.pth` under dist-packages is a
Python **persistence technique** (the interpreter executes those lines at
startup). Hiding it would have concealed the one event worth seeing.

So `noisy()` is now **"a common path that nobody wrote during this
capture"**, not "a common path":

```python
return common_file(node) and not node.writes
```

A library read at startup is noise; the same library *written* mid-capture
is a hijack. This also covers LD_PRELOAD drops and any other
boring-path-interesting-event case, and it is what makes it safe to list
interpreter package directories in the prefix list at all. Two tests, both
mutation-checked: reverting either the clause or the prefixes fails one.

Suite: **233 tests**.

### D.4 The re-run made it worse, and that is the finding

`runs/overhead-20261015-191157` — 40× the dd work, 7 rounds, CPU-pinned,
exactly as §D.3 prescribed. The ladder came back **less** readable:

```
base 1.58 s  ...  base_end 4.66 s      = +195 % baseline drift in one run
count_exit (6th config)  2.05 s
count_net  (7th config)  5.56 s        = 3.5 s apart, measured back to back
```

| Row | Finding | Status |
|---|---|---|
| 139 | **The platform, not the parameters, is the problem.** The machine's own cost nearly **tripled** during a 15-minute run, so a configuration's number is mostly a function of *when it ran*. `count_exit` and `count_net` ran consecutively and differ by 3.5 s, which no hook can cause. More rounds cannot fix this: a median smooths variation *within* a config, while the drift is *between* configs | diagnosed |
| 140 | **Wall-clock time is the wrong instrument on a VirtualBox guest.** When the hypervisor takes the CPU away, elapsed time grows and the workload's own CPU time does not. A hook that adds work to every syscall adds it to the workload's **system CPU time**, which is immune to that. The rig now records `wall`, `user` and `sys` per round (`timings.csv` gains two columns; the analyzer reads both the old 4-column and the new 6-column format) and the analyzer prefers **user+sys** whenever it is present | implemented, tested |
| 141 | **A baseline measured fifteen minutes away measures the drift, not the hook.** The rig now measures a short baseline **between every configuration** (`base_after_<config>`, `P15_INTERLEAVE=1` by default, `P15_BASE_ROUNDS=2`), and the analyzer compares each config with the baselines either side of it — a paired design rather than a block design | implemented, tested |
| 142 | Proof the two changes recover a real effect: a synthetic run whose wall time triples across the run while CPU time stays honest. Read with wall time and one distant baseline, the two configs' numbers differ by 1.5 s of drift; read with CPU time and adjacent baselines, both correctly report **+50 %**, and the ladder stops being INCONCLUSIVE | unit-tested |

**The command for the next attempt** (same cost, ~12 min):

```bash
sudo P15_WORKLOADS=sys P15_DD_COUNT=6000000 P15_ROUNDS=7 P15_PIN=1 \
     bash tools/overhead_breakdown.sh
```

Nothing new to pass — interleaving is on by default and CPU time is always
recorded now. The report will state which metric and which baseline method
it used in its header, so a reader can never mistake one run's method for
another's.

**If it is still inconclusive with CPU time and paired baselines**, the
honest conclusion is that the per-syscall tax is not measurable on a 2-vCPU
VirtualBox guest, and the remaining options are bare metal, a cloud VM with
dedicated CPU, or dropping wall-clock methods entirely in favour of
`perf stat -e raw_syscalls:sys_enter` style counting. That would be a result
worth writing down rather than a failure.

Suite: **233 tests**. The VM numbers above are from v3.5d; the noise fix
landed after the run and is **not yet re-tested on the VM** — it changes
presentation only, not capture.

### D.5 Resolved: the tax is real, paid once, and costs ~16 ns per syscall

`runs/overhead-20261015-193624` — **VM, 16 Oct 2026, v3.5g**, the first run
with CPU time and interleaved baselines. (The build is identifiable from the
data itself: 6-column `timings.csv` rows and `base_after_*` configs exist
only in v3.5g.) `P15_WORKLOADS=sys P15_DD_COUNT=6000000 P15_ROUNDS=7
P15_PIN=1`, so dd performs **12,000,000 syscalls**, none of them hooked.

The instrument's own error, measured rather than assumed, comes first,
because every number below is read against it:

```
13 baseline runs, each read against its neighbours (truth = 0 % by construction)
   -5 % -2 % +5 % -3 % +5 % -4 % +1 % -1 % -2 % +6 % -4 % -3 % +6 %
   worst 6.3 %, mean 3.6 %      <- this run's noise floor
whole-run drift 22 %            <- absorbed by the paired design, not a floor
```

And the ladder, in CPU time against adjacent baselines:

```
syscall tracepoints attached   0      0     2     4     6    12    12
config                        base  exit  exec  open   net   all  nofeat
dd slowdown                   -5 %  -1 % +11 % +15 % +16 % +17 %  +11 %
added cost per syscall          -     -2    16    22    24    25     16   ns
```

| Row | Finding | Status |
|---|---|---|
| 143 | **The instrument now states its own error.** Every baseline run is read as though it were a configuration; its true slowdown is zero by construction, so whatever comes out is the method's residual error. 13 controls, worst **6.3 %**, mean 3.6 %. This is the one number in the report whose right answer is known in advance — a check that *can* fail, applied to the measuring device rather than to the system | implemented, tested on the real run |
| 144 | **The per-syscall tax exists and is paid once.** Zero syscall tracepoints cost nothing (`count_exit`, a `sched_*` tracepoint, reads −1 %, inside the floor). The first two cost **+14 points**, which is more than twice the floor. Every tracepoint after that adds **+0.6 points**, which is inside it. The two competing models were made to predict numbers: if each hook cost what the first pair did, 12 hooks would read **+82 %**; measured **+17 %**. Proportional cost is refuted by 65 points, an unchanging cost missed by 6 | **measured on the VM** |
| 145 | **The kernel source predicts that exact shape**, which is why the result is believable rather than merely consistent. `syscall_regfunc()` in `kernel/tracepoint.c` sets `TIF_SYSCALL_TRACEPOINT` on **every thread of every process** — `for_each_process_thread(p, t) set_tsk_thread_flag(t, TIF_SYSCALL_TRACEPOINT)` — but only `if (!sys_tracepoint_refcount)`, i.e. on the *first* registration; later ones just increment the refcount. One step at the first hook, nothing afterwards. Verified against published kernel source, not recalled | web-verified |
| 146 | **The cost is attachment, not event handling.** `count_net` attaches 6 syscall tracepoints that fired **zero times** (0 records/s) and still costs +16 % / +24 ns per syscall. No record was created, decoded, or stored; the whole figure is the price of the hooks being *present* | **measured on the VM** |
| 147 | **The absolute figures.** A bare syscall on this guest costs **128 ns** (1.53 s of CPU for 12 M syscalls, which independently confirms the divisor). The tax is **16–25 ns**, i.e. 13–19 % of a minimal syscall and invisible against any syscall that does real work | **measured on the VM** |
| 148 | A prediction that could have failed, and did not: on dd, no hooked syscall fires, so the feature code *inside* those handlers cannot run, and `count_all` vs `count_all_nofeat` must be ≈ 0. Measured 6 points — inside the 6.3 % floor, so correctly not claimed by the analyzer | consistent |
| 149 | **Bug in our own analyzer, found while checking its arithmetic: the headline number was 20× too large.** `OPS["sys"]` was hardcoded at 600 000 syscalls (`dd count=300000`) while this run used `P15_DD_COUNT=6000000` → 12 M. Every "per syscall" figure was twenty times the truth: the first report said **0.63 µs** where the answer is **24 ns**. The baseline is what exposes it — the same arithmetic priced an *untraced* syscall at 2.55 µs, roughly twenty times what a minimal syscall can cost. Divisors are now read from the run's `env.txt`, printed in the report with `dd count=` beside them, and the bare-syscall cost is printed too so a wrong divisor is visible on sight. Unit changed µs → ns | fixed, mutation-checked |
| 150 | **Second bug: the per-operation table was still using the distant baseline** after every other comparison had moved to paired baselines — a 20 % error on this run. Now uses the adjacent baselines like the rest | fixed, mutation-checked |
| 151 | **A reporting contradiction that would have discredited the whole table.** The drift note said *"treat differences under 22 % as noise"* immediately above readings of 11–17 % — advice that discards every real effect in its own report. With baselines measured beside each config, whole-run drift does not enter the comparison at all; the floor is the measured control error. Drift is now reported as the *reason* the paired design and CPU time are used | fixed, mutation-checked |
| 152 | **Correction against ourselves.** The old guard would *not* have suppressed this run: ladder range 22.38 points against drift 22.22, clearing by **0.16 points**. So that fix was necessary in principle but is not what made this run readable — the run escaped the old rule by luck. A synthetic case that the old rule really does gag (50 % drift, every rung clean against its neighbours) was added, because a fix whose test passes either way is not tested | corrected in writing, now genuinely tested |
| 153 | **Near-threshold comparisons are now reported as such.** `count_exec` (+11 %, syscall tracepoints) against `bcc_execsnoop` (+1 %, kprobes) is 9.9 points, against a 10-point reporting threshold. Silently dropping it would read as "no effect", and claiming it would be reading a coin flip; it is printed as *suggestive, under the threshold*, with the experiment that would settle it | implemented, tested |
| 154 | BCC's tools really are kprobe-based — `opensnoop` attaches `attach_kprobe(event="do_sys_open")` plus a kretprobe, with no tracepoint — so the mechanism behind row 153 is right even though our measurement of it is marginal. A kprobe costs nothing to a task that never calls the probed function, which is why dd pays BCC almost nothing and pays us 16 ns | web-verified against BCC source; **confirm the installed 0.12 tools with `grep -c attach_kprobe /usr/share/bcc/tools/execsnoop` before quoting** |

### D.5a Two process failures found by running it on the VM (v3.5i)

Neither is a code defect; both are ways the work can mislead, which the
project treats as the same severity.

| Row | Finding | Status |
|---|---|---|
| 155 | **A corrected report was produced by an uncorrected analyzer.** The v3.5h zip had not replaced the tree on the VM, so `tools/analyze_overhead.py` was still the old one: the command succeeded, printed 40 lines of plausible report, and **nothing in the output said which tool wrote it**. The 0.63 µs figure and the self-contradicting drift note reappeared, looking like a result rather than a stale instrument. Fixed structurally: `env.txt` now records `build=` (the build that MEASURED the run) and the report's second line names both that and the build that READ it, with a sentence saying what a mismatch means. One source of truth in a `VERSION` file, read by both the shell script and the analyzer, drift-guarded against the README title — a stamp that can drift is worse than no stamp, because it misidentifies the tool with confidence | implemented, mutation-checked |
| 156 | **A tool path quoted from memory instead of from our own script.** The BCC verification command named `/usr/share/bcc/tools/execsnoop`, which does not exist on this VM; `bpfcc-tools` on Ubuntu 20.04 installs `execsnoop-bpfcc` and `opensnoop-bpfcc` on `PATH` (under `/usr/sbin`), which is exactly what `overhead_breakdown.sh` has always used via `P15_EXECSNOOP` / `P15_OPENSNOOP`. The authoritative answer was in our own repository and was not consulted. The correct check resolves the path rather than assuming it: `grep -c attach_kprobe "$(command -v execsnoop-bpfcc)"` | corrected; row 154 still unverified on this VM until it runs |

**The open question from the README is now answered: hook count is not a
budget, event rate is.** This also reconciles with §D's earlier finding that
cost tracks events rather than hooks (`count_open` 11.14 s vs `count_exec`
0.71 s) — that measured the *handling* cost of events, this measures the
*attachment* cost of hooks, and the two are separate terms:

```
cost  =  16 ns x every syscall the machine makes      (paid once, any hook)
      +  per-event handling x events our hooks see    (the dominant term)
```

Design consequence for Layer 1: adding the remaining hooks
(`inet_sock_set_state`, `openat2`) carries **no new per-syscall tax**, so the
only question for each is how many events it produces. That retires the
hook-budget worry entirely.

**Still open after this run:**

- the kprobe-vs-tracepoint A/B as a real experiment (row 153): attach *our*
  open hook as a kprobe on `do_sys_open` in a **measurement-only** config —
  same code, same userspace, only the attachment mechanism differs. Note the
  tension to decide before building it: the project is deliberately
  tracepoints-only for ABI stability, so this config would exist to price
  that decision, not to ship;
- `P15_WORKLOADS=sys` ran the ladder alone, so the `per exec` and `find /usr`
  columns are empty for v3.5g; the full-workload figures in the README are
  still v3.5d's;
- whether the 16 ns step is the `TIF` flag alone or the flag plus two
  registrations. The ladder bounds the per-registration part below 1 ns, so
  by elimination it is nearly all flag — but a 1-tracepoint config would
  measure it directly.

Suite: **239 tests** (6 added here), Python 3.8, 3.12 and 3.13. Every fix in rows
149–156 was mutation-checked: reverting it fails a named test.

## D. The overhead ladder: the experiment did not resolve the question

`runs/overhead-20261015-184631`. This is the measurement the project has
been waiting on since September, and the honest verdict is that **it
failed**, for reasons that are visible in its own output.

### D.1 Why no conclusion may be drawn from it

The dd workload exists to isolate the per-syscall tax: it calls none of the
hooked syscalls, so any slowdown is the price of having hooks attached.
Measured:

| config | syscall tracepoints | dd | spread |
|---|---|---|---|
| base | 0 | 0.15 s | — |
| `count_exit` | 0 (sched only) | 0.19 s | — |
| `count_exec` | 2 | 0.24 s | ±36 % |
| `count_open` | 4 | 0.29 s | ±41 % |
| `count_net` | 6 | **0.19 s** | ±74 % |
| `count_all` | 12 | 0.26 s | ±61 % |
| `base_end` | 0 | 0.12 s | — |

Three independent reasons this cannot be read as flat or rising:

1. **The error bar on one point exceeds the whole ladder.** The worst
   single-config spread is ±74 % of ~0.2 s ≈ ±0.15 s; the entire range from
   the cheapest to the most expensive rung is 0.14 s. One point's noise is
   106 % of the effect.
2. **The baseline drifted 22 %** between the first and last run (0.15 →
   0.12 s) — by itself the size of the thing being measured.
3. **The ladder is not monotonic.** 6 tracepoints (0.19 s) came in *below*
   2 (0.24 s) and 4 (0.29 s), and 12 (0.26 s) below 4. No per-hook cost
   model can produce that; it is noise.

Root cause: one round of dd takes **0.15 s**. Nothing on a 2-vCPU
VirtualBox guest is measurable at that scale, and `P15_DD_COUNT=300000`
was chosen when the baseline was slower.

| Row | Change | Status |
|---|---|---|
| 135 | **The analyzer now refuses to offer a reading it cannot support.** It tests whether the ladder is resolvable — worst spread vs range, drift vs range, monotonicity — and prints `INCONCLUSIVE, no reading offered` with the three reasons and the parameters that would fix the experiment. Previously it printed the numbers next to "flat = paid once, rising = per hook", which invites the reader to see whichever answer they already held: the worst failure mode available to an analysis tool | implemented, tested on the actual 16-Oct numbers (the test fails if the old wording returns) |
| 136 | `P15_WORKLOADS="sys"` runs the ladder alone — minutes instead of ~40 — which is what makes more rounds and a longer dd affordable | implemented, tested |
| 137 | `P15_PIN=1` pins the workload to cpu0 and the tracer to cpu1 via `taskset`. On 2 vCPUs the monitor's own polling competes with the workload for a core, and that contention is otherwise counted as hook cost — which is almost certainly what `count_exit`'s +27 % on dd is, since its hook never fires during dd | implemented, degrades gracefully without `taskset`, tested |
| 138 | One clean comparison the table *does* support, now called out explicitly: `count_net` attaches **6 syscall tracepoints that fired zero times** (0 records/s, 0.3 % CPU) on these workloads. It is the purest attachment-versus-events probe available, and it came out indistinguishable from `count_exit`, which attaches none | the analyzer prints it whenever a config produced no records |

### D.2 What the run does establish, above the noise

The `find /usr` and exec workloads are long enough to measure, and three
effects there are far larger than any spread:

| finding | evidence | reading |
|---|---|---|
| **Cost tracks the number of EVENTS, not the number of hooks** | `count_open` on find: 11.14 s. `count_exec` on the same workload: 0.71 s. Same two-syscall-tracepoint mechanism, 15× the cost, because `find` generates floods of opens and almost no execs | this is a better-supported explanation than the per-syscall-tax hypothesis, and it points the optimisation at per-event work rather than at hook count |
| **Our open path is not pathological — it is slightly cheaper than BCC's own tool** | `bcc_opensnoop` 13.41 s vs our `count_open` 11.14 s on find | the control worked: this is the cost of open tracing on this kernel, not a defect in our implementation |
| **Batching is the single biggest lever we have** | find: `graph_all` 10.06 s → `graph_all_batch20` 5.22 s; dd: 0.24 s → 0.13 s; monitor CPU 22.2 % → 9.0 % | `--batch-ms 20` roughly halves the slowdown. **But it lost 2.96 % of records**, so part of the gain is work not done — the comparison is not like-for-like and must not be quoted as a free win |
| **Logging costs CPU, not wall time** | `graph_all` → `graph_all_log`: 10.06 → 10.02 s on find, but monitor CPU 22.2 % → 34.2 % | the JSONL writer is a CPU cost absorbed off the workload's critical path on this box |
| **Python processing is secondary to kernel-side cost** | find: `count_all` 8.53 s → `graph_all` 10.06 s | ~1.5 s of Python on top of ~8.5 s of kernel work |

### D.3 The re-run that would settle it

```bash
sudo P15_WORKLOADS=sys P15_DD_COUNT=6000000 P15_ROUNDS=7 P15_PIN=1 \
     bash tools/overhead_breakdown.sh
```

40× the dd work (≈3 s per round instead of 0.15 s), 7 rounds instead of 3,
the tracer pinned off the workload's CPU, and the two expensive workloads
skipped — about 12 minutes. If the ladder is still non-monotonic at that
scale, the honest conclusion is that this hypothesis is not testable on a
2-vCPU VirtualBox guest and needs either bare metal or a different method
(e.g. `perf stat` on syscall entry paths).

Suite: **233 tests**.

## D. What the demo cannot cover, and what covers it instead

`accept(fd, NULL, NULL)` — the no-peer-name path — cannot be produced from
Python, because `socket.accept()` always passes a buffer. It is covered by
unit tests instead. The unix-socket accept in the demo does exercise the
same path on real data, because a unix client normally has no bound
address of its own.

## E. Still open after this change

- The **local** (service) port is still not captured: `accept` tells us who
  reached in, not which of our ports they reached. The accepting process
  implies the service in practice, but the kernel's own answer needs
  `sock:inet_sock_set_state` — which is the next step, and which would also
  settle a non-blocking connect's eventual fate and give kernel-truth
  addresses for outbound connections.
- `accept` on a unix socket identifies the server's own socket, not the
  client; combined with B8 that means local IPC inbound is counted but
  rarely attributed. The server-side path (`unix:<path>` of the listening
  socket) would need the fd walk that `SOCKET_TYPE` already does.
- UDP traffic that never calls `connect()` or `accept()` remains invisible.
- `recvfrom`/`sendto` are not hooked, so a UDP server's peers are unseen.
