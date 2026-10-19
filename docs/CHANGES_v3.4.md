# v3.4 — network telemetry (the `connect` hook)

Journal-ready rows. Status wording follows the Journal legend: an item is
"not yet tested" until it has run on the VM, however many unit tests cover it.

**What this closes:** objective O1 named "network connections" as part of the
telemetry, and Phase I shipped without them. It is also the piece Layer 4
needs: an FPGA rule table has to be programmed with an *address*, and before
this change nothing in the system produced one.

---

## A. Design decisions, and why

| # | Decision | Reasoning |
|---|---|---|
| A1 | Hook `syscalls:sys_enter_connect` + `sys_exit_connect`, not a kprobe on `tcp_v4_connect` | Tracepoints are a stable interface; kprobes bind to internal function names that change between kernels. The same choice as every other hook in this project, and the reason it runs unmodified on 5.4. |
| A2 | Parse the address at syscall **entry**, report at **exit** | Entry is where the address is still what the program passed. Reading it at exit (as the open hook must, since a path is long and the kernel keeps no copy we can reach) would let a second thread rewrite it after the kernel used it. This value is what an enforcement layer would act on, so the window matters more here than anywhere else. |
| A3 | Keep failed connects | A refused or unreachable connect is what port scanning and host discovery look like from inside the host. Most monitors that hook only the success path lose exactly this. |
| A4 | Treat `-EINPROGRESS` as neither success nor failure | A non-blocking connect returns immediately and may still succeed or fail later. Counting it as either would be wrong; the record carries an explicit flag rather than leaving `-115` to be interpreted downstream. |
| A5 | Record AF_INET, AF_INET6 **and** AF_UNIX; drop the rest in the kernel | A unix socket is local IPC — who talks to the docker socket or the system bus is as interesting as who opens a TCP connection, and objective O1 names IPC. AF_NETLINK is pure noise (NetworkManager alone would flood the buffer) and is not a process-to-host relationship. |
| A6 | Addresses and ports stay in network byte order in the record | The kernel has no `ntohs`; converting there would mean doing it per record for no reason. Userspace converts once, in one tested function. |
| A7 | A third record type (`net_t`) rather than overloading `event_t` | An address is not a filename. Overloading the path buffer would have saved a struct and cost every future reader an explanation. |
| A8 | One shared `COMMON_FIELDS` prefix across record types | "Who did this, and when" is identical for every record. One `fill_common()` now serves all of them through a cast, and the prefix assumption is proven by a test rather than trusted. |
| A9 | Endpoints are graph nodes keyed by address+port (or unix path) | The peer is what a connection is *to*, independent of which process opened it — the same role the inode plays for a file. Two processes reaching the same peer meet at one node, which is what makes "who else talked to this address" answerable. |
| A10 | Failed connects create a node and a record, but never a causal edge | Nothing flowed, so a root-cause walk must not be able to travel through a refused connection. |

## B. Rows

| Row | Change | Status |
|---|---|---|
| 62 | `sys_enter_connect` / `sys_exit_connect` hooks added behind `HOOK_NET`; IPv4, IPv6 and unix sockets parsed from the user-supplied `sockaddr` at syscall entry | type-checked in 6 hook/feature combinations · **not yet tested on the VM** |
| 63 | New `net_t` record type (256 bytes) through the existing perf buffer, tagged by the shared `type` field | layout compiled with gcc and compared field by field |
| 64 | Record layouts refactored to a shared `COMMON_FIELDS` prefix; `fill_common()` now fills any record type through a `struct common_t *` cast | pure refactor, byte-identical layout (still 392 bytes); a test compiles all three structs and asserts the prefix is at identical offsets |
| 65 | Our minimal `sockaddr_in` / `sockaddr_in6` / `sockaddr_un` copies are compiled against `<netinet/in.h>` and `<sys/un.h>` and every offset compared; `AF_*` values checked against `<sys/socket.h>` | unit-tested. Found: our `sa_in_t` is 8 bytes where the real `sockaddr_in` is 16 (trailing padding we never read). The invariant is therefore "same offsets, never longer", which is what the test asserts |
| 66 | Endpoint nodes and CONNECT edges in the graph; `trace_back` and `trace_forward` cross the network boundary | unit-tested, including the download → write → execute chain |
| 67 | **Bug found by the new tests:** a causal walk could only *start* at a process. Starting one at a file or an endpoint raised `AttributeError`, because only `ProcessNode` has `first_ns`/`last_ns`. No query exercised it, so it had never fired | fixed with `_start_ts()`: a resource's walk starts at its latest access going backwards, earliest going forwards |
| 68 | `peers`, `talkers`, `endpoints` and `scans` queries; connect counters in the live view and a CONNECT line in the per-event printer | unit-tested through the CLI |
| 69 | `tools/net_demo.py`: a deterministic connect scenario over loopback — successful, refused, unix, non-blocking, and the download → write → execute chain. No internet needed, so it reproduces anywhere | runs standalone; wired into `vm_validation.sh` |
| 70 | Six new functional checks in the run analyzer, asserted against the ports the demo actually chose rather than hard-coded numbers | the analyzer's own test proves each one can FAIL, not just pass |
| 71 | `count_net` added to the cost breakdown, and the `count_*` configurations documented as a tracepoint ladder (0, 2, 2, 4, 8 syscall tracepoints) | the reading is tested on synthetic timings |
| 72 | Snapshot format unchanged at version 4: endpoints and per-process connections are optional keys, so snapshots taken before this change still load | unit-tested |

## C. The measurement this enables

Our own overhead data showed something odd: hooking only `execve` slowed a
`dd` workload that never calls `execve`. The explanation is that enabling any
`syscalls:*` tracepoint sets a per-thread flag that forces **every** syscall
onto the kernel's slow path — the cost is not specific to the hooked call.
(LKML discussion of `syscall_regfunc`, where the flag is described as forcing
the slow path, and Rostedt argues for a syscall-table swap to avoid it.)

If that is right, the tax is paid once when the first syscall tracepoint is
enabled, and extra hooks are nearly free — which would mean the connect hook
costs almost nothing on the syscall path, and that hook count is not the thing
to optimise. The `count_*` ladder in `overhead_breakdown.sh` now measures this
directly: `count_exit` (0 syscall tracepoints), `count_exec` (2),
`count_open` (4), `count_net` (6 — connect plus accept plus accept4),
`count_all` (12), all measured against a workload that calls none of the
hooked syscalls. **Flat ladder = paid once. Rising ladder = each hook
costs.** Either answer is worth having; the point is that it is now a
measurement rather than an assumption.

(The counts above are the v3.5 ones. Adding the inbound hooks widened the
ladder from 0/2/2/4/8 to 0/2/4/6/12, which makes the reading sharper rather
than muddier: a per-hook cost now has twice the span to show up in.)

## D. Still open after this change

- The local address and port are not captured. Only the kernel knows them, and that needs a second hook (`sock:inet_sock_set_state`, available since 4.16) which would also confirm that a non-blocking connect actually established. Designed, not built.
- UDP traffic that never calls `connect()` is invisible.
- Inbound connections (`accept`) are not hooked, so only one side of a lateral movement is visible.
- The TOCTOU window is narrowed but not closed: the address is still read from user memory. The kernel-side hook above is the real fix.
- `connect()` to `0.0.0.0:0` (the idiom for dissolving a UDP association) creates an endpoint node like any other. Harmless, but it is noise rather than a relationship.


---

# v3.4a — what the first VM run taught us (13 Oct 2026)

The connect hook ran on kernel 5.4 and captured Firefox and systemd-resolved
with full lineage: **2,191 records, 0 lost, 0 errors**. Three validation
checks failed. None of them was the hook.

| Row | Finding | Evidence | Action |
|---|---|---|---|
| 73 | `getaddrinfo()` makes connections that are not connections | Firefox showed `net:180.149.52.211:0` and `net:[2600:140f:4::1736:5369]:0` immediately after a DNS lookup. glibc resolves a name by opening a **UDP** socket and `connect()`ing it to each candidate address — **with port 0** — purely so the kernel picks a source address for RFC 3484 sorting. Reproduced under strace: `getaddrinfo(host, None)` connects with port 0, `getaddrinfo(host, "http")` with port 80 | new optional feature `SOCKET_TYPE` reads the socket type behind the fd (fd → file → private_data → `struct socket`), so a stream connection is distinguishable from a datagram probe; probes are counted separately and skipped by causal walks under `--no-libs` |
| 74 | A "successful" connect in Python is not a blocking connect | the check "outbound connection attributed to the process that made it" failed looking for `ret == 0`, while the same endpoint showed `ret=-115`. `socket.create_connection(addr, timeout)` sets the socket non-blocking, so the syscall returns `-EINPROGRESS`. Confirmed under strace: with a timeout `-1 EINPROGRESS`, without one `= 0` | `net_demo.py` now uses a plain blocking socket for the success case, keeping a separate explicit non-blocking case. **The monitor was right; the test's expectation was wrong** — and this is exactly why the pending/failed split exists |
| 75 | `sh: cannot create /tmp/p15_payload.txt: Permission denied` broke two checks | fixed paths in a world-writable directory. The same class of bug as the `/tmp/p15_zpid` unit-test failure in row 51 | every run now gets its own `mktemp -d` directory and writes the paths to `paths.json`; the analyzer reads them instead of assuming. Runs recorded before this still analyse (tested) |
| 76 | Buffer size demonstrably matters now | p64: 91,898 records with **20,765 lost (18.43 %)**; p256: 93,900 records, **0 lost**, same workload. Earlier runs lost nothing at either size | the extra hook raises the record rate, so 64 pages/CPU is no longer enough. First real evidence for the `--pages` lever; the earlier "buffer size made no difference" note is superseded |
| 77 | The network chain works on real data | "root-cause trace crosses the network boundary" PASSED, and "endpoint reuse: one node per peer" showed `net:127.0.0.1:44259 contacted 3 times by 3 processes` | — |

| 78 | The unit failure under sudo was the same bug again | `test_is_running_is_false_for_a_real_zombie` failed with `/tmp/p15_zpid: Permission denied`. The file belonged to the normal user, `/tmp` belongs to root, and the caller was root: `fs.protected_regular` denies opening a file in a world-writable sticky directory whose owner is neither the caller nor the directory's owner — **root included**, so running with sudo is not a workaround | the test now creates its scratch file with `tempfile.mkstemp`. (The fix had been applied directly on the VM in September and never made it back into a packaged zip — a reminder that a fix only counts once it is in the source) |
| 79 | A guard so this cannot happen a fourth time | `FixedTmpPathTest` scans every test and script for a shell redirect to a literal `/tmp` path | it immediately found a fourth instance in `claims_evidence.sh`, which would have failed on the VM in the same way; that script now uses a per-run directory too |

**The general rule, now enforced by a test:** nothing writes to a fixed path
in a shared directory. Not the scripts, not the tests, not the demos. Three
separate failures came from ignoring it, each one costing a VM run.

---

# v3.4b-fixed — the WRITE-edge regression (13 Oct 2026)

Found by an independent source read of v3.4b against the 13-Oct VM output
(`ESE-P15_v3.4_Hardcore_Review.docx`, Finding 1), not by the test suite.

**Correction to v3.4a:** that section blamed all three VM failures on the
`/tmp` permission problem and the non-blocking connect. Re-reading the
evidence line by line shows that is wrong for one of them. Only
`root-cause trace: cat <- payload file <- sh that wrote it` was the
permission problem — the VM printed `sh: 1: cannot create
/tmp/p15_payload.txt: Permission denied`, so in that run no write happened
at all. The relative-path check failed for a completely different reason,
and it was ours:

```
FAIL | relative path linked through inode (write -> read)
     | FORK bash(14439), READ inode:8388609:419080:4054662292,
       EXEC /usr/bin/cat, FORK bash(9292), FORK sudo(9291)
```

The `READ inode:…` edge is right there, so the file *was* written and *was*
read, by inode, exactly as designed. What is missing is `WRITE bash(14439)`.

| Row | Change | Status |
|---|---|---|
| 80 | **Regression in v3.4, high severity for a provenance tool:** `trace_back` dropped the WRITE edge whenever the writer had already been visited through another edge. The walk is breadth-first, so in the ordinary shell shape `(cmd > file; cat file)` the writer is the reader's *parent*: it is listed via FORK at depth 1, and by the time the file node is expanded its identity is already in `seen`, so the write — "who put these bytes here", the whole question a provenance tool exists to answer — was silently suppressed. `seen` was doing two different jobs: stopping re-*expansion* (correct, and what guarantees termination) and stopping re-*listing* (wrong, because FORK and WRITE are different causal facts) | fixed; regression test fails on the old code and passes on the new |
| 81 | The fix is one rule instead of two guards: an edge is suppressed only when it would **echo the link the walk arrived on** (`via`, a `(node, edge_kind)` pair carried through the queue). Everything else is listed, including an already-seen node reached by a different kind of edge. Termination is unchanged — it never depended on the listing guard | `trace_back` and `trace_forward` now use the same rule; `trace_forward` previously echoed the incoming CONNECT, which the endpoint guard in `trace_back` existed to prevent |
| 82 | Why 147 tests missed it: the analyzer's synthetic "good run" made the writer and the reader **siblings** (both children of pid 100), while `vm_validation.sh` runs `(cd $WORK && echo rel > p15_rel.txt && cat ./p15_rel.txt)` — writer is **parent**. Siblings never trigger the suppression; parent/child always does | the synthetic story now spawns the reader as a child of the writer. With the bug reintroduced, the analyzer's own test now fails with `FORK bash(212), READ inode:8:77:0, EXEC /usr/bin/cat, FORK bash(100), FORK systemd(1)` — the same shape as the VM line above, reproduced on this laptop |
| 83 | The general lesson, and it is a bigger one than the bug: a synthetic scenario has to reproduce the validation script's **process topology**, not just its syscalls. Same syscalls in a different tree exercise different code | recorded here; no mechanical guard yet (what would one assert?) |
| 84 | Where it came from: v3.3 and earlier listed *every* write (checked against the packaged v3.1/v3.2/v3.3 zips). v3.4 added last-write-wins and the `seen` guard in the same edit; the guard was copied from the endpoint branch, where it *is* justified, without the comment that justified it | an edge-listing rule now has to say which link it suppresses and why, in the code |
| 85 | `--type connect` was missing from the CLI choices, so CONNECT events could not be filtered in the log and no error said so (review, minor finding 1) | fixed, plus a drift guard: a test extracts every `_emit("…")` type from `processor.py` and every `--type` choice from `monitor.py` and asserts the two sets are equal |

Suite: **149 tests**, Python 3.8 and 3.12. The three VM-side consequences
(`vm_validation.sh` should now reach 21/21) are **not yet tested on the VM**.

### Still open from the review

Phase-2 items, listed so they are not rediscovered: `openat2` is unhooked
(invisible on 5.6+, absent on the 5.4 VM); `accept` is unhooked, so lateral
movement is visible on one side only; JSONL logs carry argv verbatim and
need a redaction policy before any central storage; `lineage_str` is
O(depth) per logged event and could be cached per `(pid, gen)`;
`--max-nodes` eviction is unit-tested but not soak-tested; `read_fd_inode`
races a concurrent `close()` in another thread (documented, accepted).
