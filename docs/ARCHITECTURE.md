# ESE-P15 monitor v3.4 — architecture, end to end

Read this top to bottom once. Afterwards each section works as a reference
for one piece. Concepts (what a tracepoint *is*, what the verifier checks)
are in `CONCEPTS.md`; this file is about how *this* system uses them.

Contents
1. The big picture
2. Files and responsibilities
3. Kernel side, function by function
4. Userspace: from bytes to graph
5. Process identity — the core algorithm
6. The graph and its queries
7. The main loop: startup, running, shutdown
8. Measurement tools
9. What each test proves
10. Reference: CLI flags, log fields, stats fields
11. Limitations and next steps

---

## 1. The big picture

```
 ┌──────────── kernel ────────────┐     ┌──────────────── monitor (Python) ────────────────┐
 │ any process                     │     │                                                   │
 │  execve / openat / connect /    │     │  perf_buffer_poll()                                │
 │  exit  │                        │     │        │ one callback per record                   │
 │  tracepoints ──► eBPF programs ─┼──►──┤  events.decode()    bytes → Event / Arg / Net      │
 │                  monitor.bpf.c  │ per │        │                                          │
 │                   │  maps:       │ CPU │  EventProcessor       exec assembly, filters      │
 │                   │  scratch,    │ ring│        │         └──► JSONL log / printer        │
 │                   │  open_args,  │     │  ProcessGraph     processes, files, endpoints     │
 │                   │  exec_start, │     │        │         └──► snapshot JSON (queries)    │
 │                   │  net_args    │     │        │                                          │
 └─────────────────────────────────┘     │  view.render()        top + tree, 1 Hz           │
                                         └───────────────────────────────────────────────────┘
```

Two rules shape everything:

1. **The kernel side stays small and dumb.** It copies facts (who, when,
   which file, result). All interpretation happens in Python, where it can
   be unit-tested.
2. **Nothing assumes arrival order or PID uniqueness.** Records carry
   enough identity (start times, enter timestamps) to be put back together
   however they arrive.

## 2. Files and responsibilities

| File | Responsibility | Talks to |
|---|---|---|
| `hids/bpf/monitor.bpf.c` | 8 tracepoint programs; builds records | kernel only |
| `hids/events.py` | byte layouts, decode, file ids, clocks, open flags | everyone |
| `hids/processor.py` | ExecAssembler, EventProcessor, log, stats | graph, events |
| `hids/graph.py` | ProcessGraph: identity, edges, queries, snapshot | — |
| `hids/procstat.py` | /proc snapshot at startup, CPU/RSS sampling | graph nodes |
| `hids/view.py` | screen rendering, per-event printer | graph, stats |
| `hids/monitor.py` | CLI, BCC loading with fallback, main loop, stats file | all |
| `tools/vm_validation.sh` + `analyze_run.py` | correctness checks + headline numbers | monitor |
| `tools/overhead_breakdown.sh` + `analyze_overhead.py` | where slowdown comes from | monitor, BCC tools |
| `tools/query_graph.py` | questions on a saved snapshot | graph |

## 3. Kernel side, function by function

`monitor.py` prepends `#define` lines before compiling: `SELF_TGID`, one
`HOOK_*` per enabled hook group, and the optional features. Code under an
`#ifdef` that is not defined is simply not compiled.

### 3.1 Records

`struct event_t` — 392 bytes, used for everything except arguments:

| field | offset | size | meaning |
|---|---|---|---|
| type | 0 | 4 | EXEC_ENTER=0, OPEN=1, EXEC_OK=2, EXIT=3 |
| pid / tid / ppid | 4 / 8 / 12 | 4 each | process, thread, parent process |
| uid / gid | 16 / 20 | 4 each | credentials at event time |
| ret | 24 | 4 | OPEN: fd or −errno · EXIT: wait status |
| flags | 28 | 4 | OPEN: open flags · EXEC_ENTER: execveat flags |
| ts_ns | 32 | 8 | when (CLOCK_MONOTONIC) |
| start_ns / pstart_ns | 40 / 48 | 8 each | start time of process / parent — **identity** |
| aux_ns | 56 | 8 | EXEC_OK: ts_ns of its EXEC_ENTER |
| ino / dev / igen | 64 / 72 / 76 | 8, 4, 4 | file identity (FILE_IDENTITY) |
| dfd | 80 | 4 | directory fd for relative paths (−100 = cwd) |
| pad | 84 | 4 | alignment |
| comm / tcomm / pcomm | 88 / 104 / 120 | 16 each | process, thread, parent names |
| filename | 136 | 256 | path |

`struct arg_t` — 152 bytes: `type=4, pid, idx, flags, enter_ts, arg[128]`.
An END record (`flags & 1`) carries in `idx` how many arguments were sent.
`flags & 2` means argv was longer than 20.

### 3.2 Maps

| map | type | key → value | why |
|---|---|---|---|
| `events` | perf output | — | the channel to userspace, one ring per CPU |
| `ev_scratch`, `arg_scratch` | per-CPU array, 1 slot | 0 → record | records too big for the 512-byte stack |
| `open_args` | LRU hash | pid_tgid → {path ptr, flags, dfd} | carry open's arguments from enter to exit |
| `exec_start` | LRU hash | thread id → enter ts | link a successful exec to its attempt |

### 3.3 Helpers (all `always_inline`)

- **`is_self()`** — true for the monitor's own PID. Every probe checks it
  first, so the monitor's `/proc` reads never become events (the Journal
  row 5 feedback loop).
- **`fill_common(ev, type)`** — resets *every* field (the slot is reused),
  then fills who/when:
  `bpf_get_current_pid_tgid` → pid/tid;
  `bpf_get_current_comm` → thread name;
  `task->group_leader` → process name and start time;
  `task->real_parent->group_leader` → parent pid, start time, name.
- **`read_inode(ev, file)`** — `file->f_inode` → `i_ino`, `i_generation`,
  `i_sb->s_dev`. Any NULL along the way leaves zeros ("unknown").
- **`read_fd_inode(ev, fd)`** — `task->files->fdt`, bounds-checks `fd`
  against `max_fds`, reads slot `fd` of the `fd[]` array, then `read_inode`.
- **`read_exe_inode(ev)`** — `task->mm->exe_file` → `read_inode`.

### 3.4 Exec path (`HOOK_EXEC`)

```
sys_enter_execve ─┐
                  ├─► exec_enter(): EXEC_ENTER record, then ARG × n, then ARG(END)
sys_enter_execveat┘                 exec_start[tid] = ts
       … kernel loads the program; may fail here …
sched_process_exec ─► EXEC_OK record: aux_ns = exec_start[old_pid] (then delete)
                                      filename = kernel's path (KERNEL_EXEC_PATH)
                                      ino = new executable (FILE_IDENTITY)
```

- The argument loop reads `argv[i]` (a user pointer) for i < 20 and stops
  at NULL. The slot address is computed with plain integer arithmetic so
  BCC's source rewriter doesn't reinterpret it.
- **`execveat`** is hooked because `fexecve()` (running a program from a
  file descriptor, e.g. from `memfd_create`) uses it. That is the textbook
  fileless-execution path.
- **`old_pid`**: when a thread of a multithreaded process calls exec, it
  takes over the leader's id; `exec_start` was keyed by its old thread id.
- **Kernel path**: `sched_process_exec` carries the kernel's own path
  string as a `__data_loc` field; BCC 0.12 exposes it as
  `args->data_loc_filename` (checked in BCC's source), where the low 16
  bits are the offset inside the record.

### 3.5 Open path (`HOOK_OPEN`)

```
sys_enter_openat / sys_enter_open ─► stash_open(): open_args[pid_tgid] = {ptr, flags, dfd}
sys_exit_openat  / sys_exit_open  ─► emit_open():  lookup + delete, OPEN record with ret,
                                                   path read from the stashed user pointer,
                                                   inode of the new fd (if ret ≥ 0)
```

### 3.6 Exit path (`HOOK_EXIT`)

`sched_process_exit` fires per thread; only the leader (tgid == tid)
produces an EXIT record, with `task->exit_code` (a wait status).

### 3.7 Feature fallback

`monitor.load_bpf()` tries `[KERNEL_EXEC_PATH + FILE_IDENTITY]`, then each
alone, then none. If the compiler or verifier rejects a combination, the
next one is tried and the refusal message is saved in the stats
(`features`, `features_refused`).

### 3.8 Network, outbound: `sys_enter_connect` / `sys_exit_connect` (HOOK_NET)

The same enter/exit shape as `open`, with the parsing moved to the **entry**
side for a reason worth knowing.

**Entry.** Reads the family (two bytes) from the user-supplied `sockaddr`,
then reads exactly as much as that family defines: 8 bytes for IPv4, 28 for
IPv6, 110 for a unix socket. Anything else (AF_NETLINK, AF_PACKET …) returns
immediately: it is not a process-to-host relationship, and netlink alone would
flood the buffer. The parsed result is stashed in an LRU hash keyed by
`pid_tgid`.

Why parse here rather than at exit, when `open` does the opposite: the open
hook has no choice — a path is long, and at entry the result is unknown — but
the connect address is small and fixed-size, and it is *the value an
enforcement layer would act on*. Reading it after the syscall would leave a
window where a second thread could rewrite the address the kernel already
used. Parsing at entry narrows that window to the syscall itself.

**Exit.** Fills a `net_t` record with the stashed address plus the syscall's
return value, and flags `-EINPROGRESS` explicitly so userspace never has to
guess whether a non-blocking connect was a success or a failure.

Addresses and ports stay in **network byte order** in the record. The kernel
has no `ntohs`, and converting there would mean paying for it per record;
`events.decode()` converts once.

**What this hook does not see:** the local address and port (only the kernel
knows them — `sock:inet_sock_set_state` would supply them and confirm that an
in-flight connect established), and UDP traffic that never calls `connect()`.

### 3.9 Network, inbound: `accept` / `accept4` (HOOK_NET)

The mirror image of 3.8, and the mirror is not symmetric. Three differences,
each forced by what the kernel does rather than chosen:

**The address is read at EXIT.** At entry the caller's buffer holds nothing:
the kernel fills it *during* the syscall (`__sys_accept4` →
`newsock->ops->getname()` → `move_addr_to_user()`, before `fd_install`). So
the hook stashes the buffer *pointer* at entry and reads the address at exit,
and only when the syscall succeeded — a failed copy aborts the whole call, so
a successful return guarantees the bytes are there.

**The value is kernel truth.** Because the kernel is the writer, an accepted
peer address cannot be falsified by the process being monitored, where a
`connect` target always can be. It is the first value in this system with
that property, and the one an enforcement layer should prefer.

**A failed accept is dropped in the kernel.** `-EAGAIN` fires on every poll
of a non-blocking listener; it means no connection was waiting. That is an
absence, not an attempt, and it carries no peer. The opposite of the connect
rule, where a refusal is kept precisely because refusals are what scanning
looks like.

Both syscalls are hooked: glibc's `accept()` issues `__NR_accept`, Python's
`socket.accept()` issues `__NR_accept4`. The record is the same `net_t`,
tagged `NET_FLAG_INBOUND`; `NET_FLAG_NOPEER` marks a connection the kernel
had no name for (`accept(fd, NULL, NULL)`, or a unix client with no bound
address). Stashes use their own LRU map, because a listener can block inside
`accept()` for hours and outbound churn in a shared map would evict exactly
the entry that matters (`CHANGES_v3.5.md` B6).

**What this hook does not see:** which of *our* ports the peer reached. The
sockaddr the kernel fills describes the peer, and the peer's port in it is
ephemeral — see §5 for why that keeps it out of the endpoint identity.

## 4. Userspace: from bytes to graph

### 4.1 `events.decode(data, size)`

Reads the first 4 bytes. `4` → `Arg`, otherwise → `Event` (namedtuple).
Short or unknown records → `None`, which is counted as `undecodable`.

### 4.2 `EventProcessor.handle(record)`

Wrapped in `try/except`: an exception is counted (`errors`), the first
traceback is kept for the stats, and the stream continues.

| record | goes to |
|---|---|
| Arg | `ExecAssembler.arg` |
| EXEC_ENTER | `ExecAssembler.enter` |
| EXEC_OK | `ExecAssembler.ok` |
| OPEN | `_open` → `graph.process` + `graph.record_open` |
| EXIT | `_exit` → `graph.process` + `graph.record_exit` |

### 4.3 ExecAssembler — a small state machine

Pending entries are keyed `(pid, enter_ts)`: EXEC_ENTER uses its own `ts_ns`;
ARG uses `enter_ts`; EXEC_OK uses `aux_ns`.

```
             ┌──────── enter ────────┐
 (new) ──────┼──────── args, END ────┼──► complete? ──► commit → _exec_done
             └──────── ok ───────────┘         │
                                               └─ no, and older than 2 s ─► _settle:
                                                    ok seen    → commit partial
                                                    no ok      → EXEC_FAILED
```

- **complete** = enter + ok + END + all `count` arguments present.
- **Out-of-order safe**: the test replays all 120 orders of one exec's 5 records.
- **ok with `aux_ns = 0`** (the kernel had no enter record) → committed at once.
- **Late ARG after a timeout commit** → patched into the graph's `ExecRecord`
  via the `done` LRU (the log line is already written).
- **`MAX_PENDING`** = 20 000: past that, the oldest entry is settled early
  (`forced_exec_settles`). This protects memory when records are lost in bulk.
- `expire()` walks oldest-first and stops at the first fresh entry.

`_exec_done` then works out:
- **name before exec** — from the ENTER record;
- **path** — the kernel path if present, otherwise the requested one
  (shown as `fd3:name` when relative to a directory fd);
- **`exec_from_fd`** — true if execveat was called with an empty path and
  `AT_EMPTY_PATH`, or the kernel path is `/dev/fd/N`;
- **`file_id`** — for the executable.

### 4.4 Output

`_emit` returns immediately when there is no log and no printer. The first
VM run did the full formatting (including the lineage string) even with
`--no-log`, which was pure waste. Otherwise the filters are applied, then
one JSON object per line (fields in §10).

## 5. Process identity — the core algorithm

`graph.process(pid, start_ns, ppid, pstart_ns, comm, pcomm, uid, ts)`:

```
key = find(pid, start_ns)                 # exact lifetime already known?
if not found:
    cur = current[pid]
    if cur is a startup-snapshot node (start estimated) and alive:
        adopt: cur.start_ns = start_ns     # same process, better timestamp
        also resolve/upgrade its parent
    else:
        parent = _parent_key(ppid, pstart_ns)   # exact parent lifetime,
                                                # or upgrade estimate,
                                                # or placeholder node
        node = new generation (pid, gen+1)
        _set_current_if_newer(node):
            if node started after current[pid]:
                current[pid] = node
                if old lifetime still "alive": mark exited, exit_inferred=True
            (an OLDER lifetime arriving late never becomes current)
        return node
refresh: rename only if this event is the newest seen for the node
         reparent if ppid changed (orphan adopted by init/subreaper)
```

Why it works: the kernel sets `start_time` once, at fork. It survives
exec (`de_thread` even copies it for multithreaded exec) and differs for
every new process that later receives the same PID.

## 6. The graph and its queries

- **ProcessNode** fields: identity (`key`, `start_ns`, `start_exact`),
  tree (`parent_key`, `children`, `reparented_from`), history (`execs`,
  `failed_execs`, `files`, counters), state (`alive`, `exit_*`),
  resources (`cpu_percent`, `rss_kb`).
- **FileNode**: `fid`, `paths` (up to 8 names, newest last), `writes`
  (the causal subset: `(ts, process key)`, capped separately so a flood of
  reads cannot evict the evidence of who wrote the file), `accesses`
  (ts, process key, READ/WRITE/EXEC).
- **Endpoint identity, and why the two directions differ.** Outbound:
  `net:<addr>:<port>`, because the port is the *service* and half of what
  identifies the peer. Inbound: `host:<addr>`, with **no** port, because the
  port in an accepted sockaddr is the peer's *ephemeral source* port — a
  different number every connection (measured: 45192, 51022, 59524 to the
  same service). Keying on it would create one endpoint node per connection
  and make "who keeps connecting to this box" unanswerable. One host that
  both called us and was called appears as two nodes, which is right: those
  are two different relationships with the same counterparty.
- **ACCEPT edges** are a distinct kind traversed exactly like CONNECT: a TCP
  connection carries data both ways whichever side opened it, so both
  directions of a walk follow both kinds, and the *label* preserves which it
  was. The distinction is what separates exfiltration from arriving lateral
  movement in a report.
- **EndpointNode**: `eid` (`net:<addr>:<port>`, `host:<addr>` or
  `unix:<path>`), `accesses`
  (ts, process key, CONNECT/CONNECT_FAILED), `access_count`, `failed_count`.
  Deliberately shaped like FileNode: both are passive resources identified by
  what they are rather than by who touched them, which is what makes "who
  else reached this peer" a one-line query.
- **CONNECT edges** are followed by causal walks only when the connection
  succeeded or was still in flight. A refused connect is recorded against both
  the process and the endpoint, and never followed: nothing flowed through it.
- **Walk start times**: a process carries its own span (`first_ns`/`last_ns`),
  but a file or endpoint does not. `_start_ts()` supplies one — latest access
  going backwards, earliest going forwards — so a walk can begin at any node
  type. Before v3.4 a walk could only start at a process; starting at a file
  raised `AttributeError`, and no query had ever done it.
- **File id**: `inode:dev:ino:gen` when known, else `path:/abs`. A relative
  path with no inode → no FileNode, counted in `unresolved_opens`. The audit
  found that `find`'s relative `openat(dirfd, "lib")` calls had been
  merging unrelated directories into one node.
- **Bounds**: `max_nodes` (oldest exited processes), `max_files` (LRU,
  default 200 000 from the CLI), `max_endpoints` (LRU, default 25 000),
  2 000 entries per history list. An endpoint cap exists because inbound
  changed who can create nodes: any host that reaches a listening socket
  mints one, so the bound has to be on our side.

  **What a node costs, measured** by `tools/bench_nodes.py` (`tracemalloc`,
  400 nodes per cell, Python 3.8.20 — the VM's interpreter):

  | node | 1 access | 20 accesses |
  |---|---|---|
  | FileNode | ~746 B | ~3.3 KB |
  | EndpointNode | ~356 B | ~2.8 KB |

  Object sizes are interpreter-dependent, so the harness prints the
  interpreter with the result; 3.13.16 gives ~713 B / ~3.4 KB and
  ~332 B / ~2.7 KB, close enough that the caps can be sized from either.
  An earlier version of this table quoted ~530 B and ~380 B and called them
  "measured, this build" with no harness anywhere in the tree — an audit
  found that, and the real figures are about 40 % higher than the ones the
  arithmetic below used to rest on.

  So the caps are memory budgets in disguise: 25 000 endpoints is ~9 MB
  typical and ~71 MB if every one is hot, which is why the endpoint default
  is 25 000 and not the 200 000 the file cap uses.

  **Open question this measurement raises**, and the corrected figures make
  it sharper rather than softer. `--max-files 200000` implies **149–677 MB**
  of graph memory, against a heaviest measured peak RSS of **~142 MB** on the
  2 vCPU test VM: the cap permits roughly five times the memory the monitor
  has ever actually used, so it is not a safety bound in any useful sense.
  Lowering it to ~50 000 (~37 MB typical, ~166 MB hot) would make it one, at
  the cost of forensic history on a file-heavy host. That is a trade-off to
  decide deliberately, not silently — it has not been changed.

  **Peak RSS depends on the workload, so both figures belong here with their
  conditions** — quoting one without the other is how this paragraph got the
  number wrong twice, once by understating it and once by "correcting" it to
  a measurement of something else:

  | run | workload | peak RSS |
  |---|---|---|
  | VM 2026-10-16 | overhead run (exec loop + `find /usr`) | 121 MB |
  | VM 2026-10-19 | stress, 3× `find /`, 64 pages/CPU | 137.4 MB |
  | VM 2026-10-19 | stress, 3× `find /`, 256 pages/CPU | 141.9 MB |

  The arithmetic above is weighed against the heaviest of these, because
  heavy load is the condition the cap exists for.
  Note also that the cap bounds node *count*, while memory per node grows
  with its access list (up to `MAX_ACCESSES_PER_FILE`), so neither cap is a
  hard memory limit.
- **Naming in output**: a node's own `label()` is ambiguous in two cases the
  *graph* can detect, so `_desc()` disambiguates only then — `nc(777#1)`
  when a PID has more than one generation, and `/tmp/x#11` for a file whose
  path now belongs to a different inode. Lineages, trees and walks all go
  through it, so one report cannot contradict another.
- **`render_tree`** lists anything it could not reach from a root under
  "(unreachable — parent cycle or missing link)", and marks an orphan whose
  parent was evicted. A monitor whose live view silently shows nothing is
  the worst failure mode available, and a `parent_key` cycle used to do
  exactly that.
- **Edge caps in a walk**: `MAX_EDGES_PER_RESOURCE` (8) bounds how many
  edges one resource contributes to a single step, so repeated access to one
  file cannot crowd every other input out of `max_items`.
- **`lineage(node)`**: parent pointers up to the root, visited set.
- **`trace_back(node, skip=)`**: breadth-first, backwards in time. A
  process's inputs are its parent, the files it read and the files it
  executed *before* the current time bound. A file's inputs are the
  processes that wrote it before that bound. `skip=common_file` drops
  libraries and locales (dependency explosion).
- **Two suppressions in a walk, and they are not the same thing.** `seen`
  stops a node being **expanded** twice — that is what guarantees
  termination, and it is checked when a node is popped off the queue.
  `via`, the `(node, edge_kind)` link the walk arrived on, stops an edge
  being **listed** as its own cause (endpoint → the very process we reached
  it from). Nothing else is suppressed: an already-seen node reached by a
  *different* kind of edge is always listed, because a parent shell that
  writes a file its child reads is both a FORK and a WRITE and those are two
  different causal facts. v3.4 used `seen` for both jobs and lost exactly
  that write (`CHANGES_v3.4.md` rows 80–84).
- **`trace_forward`**: the mirror image (children, files written, their
  later readers), under the same two rules.
- **Snapshot**: `to_dict()` / `from_dict()` (version 4), used by `--snapshot`
  and `tools/query_graph.py`.

## 7. The main loop: startup, running, shutdown

Startup order, and why:
1. **Parse args, check root, import BCC, check tracepoints exist** — fail fast with a clear message.
2. **Install SIGINT/SIGTERM handlers** — Ctrl+C during the compile is then a clean stop.
3. **Open the log** — a new file per run.
4. **Compile and load with feature fallback** (§3.7).
5. **Open the perf buffer** (`--pages` per CPU; the callback is either decode→process or just count).
6. **Snapshot `/proc`** — *after* the hooks are live, so nothing slips between.
7. **Print "Hooks attached"** with `flush=True`, which scripts wait for.

Loop, until the flag, `--duration`, or an exception:
- **Poll:** `perf_buffer_poll(50 ms)`, or with `--batch-ms`: poll(0) then
  sleep. The kernel wakes the reader only while it sleeps inside poll, and
  BCC 0.12 fixes `wakeup_events = 1`, so batching is the only knob.
- **Every 0.5 s:** `proc.tick()` settles stale execs.
- **View mode, every `--refresh`:** sample CPU/RSS of live processes, redraw.

Shutdown (in `finally`, so it also runs after a crash):
- **Drain:** at most 20 non-blocking polls, never unbounded.
- **Settle:** all pending execs.
- **Stats:** compute them (§10), close the log, write the stats and snapshot.

## 8. Measurement tools

- **`vm_validation.sh`** (~5 min) — unit tests, then:
  - a functional script (cat, echo argv, write→read, failed exec, exit 3,
    31 args, fork-only subshell, named thread, memfd fileless exec,
    relative paths);
  - a 200-exec burst;
  - stress at 64 and 256 pages after a cache warm-up;
  - workload timing with/without monitor.

  `analyze_run.py` → `results.md`.
- **`overhead_breakdown.sh`** (~10–15 min) — 11 configurations × 3
  workloads × 3 rounds, with the baseline measured first and last to catch
  drift. `analyze_overhead.py` → `overhead.md`, containing the slowdown
  table, cost per exec / per syscall, and rule-based readings (syscall
  tracepoint tax, feature cost, Python cost, batching, logging, loss).
- **`lib.sh`** — shared by both scripts. `stop_bg` stops a background
  tracer with SIGTERM, waits at most a grace period, then SIGKILL.
  `is_running` reads the process state from `/proc` (a zombie counts as not
  running). `wait_for_text` waits for a ready line and returns 0 found /
  1 process died / 2 timeout. Both scripts trap INT/TERM, stop the tracer
  and exit 130.

  **Why SIGTERM and not SIGINT.** A non-interactive bash starts `cmd &`
  with SIGINT ignored. Python keeps that unless the program installs a
  handler. `hids.monitor` does; BCC's tools don't. So `kill -INT` did nothing
  to `execsnoop-bpfcc`, and `wait` with no deadline hung the script (VM,
  17 Sep 2026). SIGTERM is not ignored, and `hids.monitor` treats it like
  Ctrl+C, so stats are still written.
- **`query_graph.py`** — `summary`, `tree`, `lineage`, `trace`, `impact`,
  `files`, `writers`, `gens`, `fdexec`; `--no-libs` for traces.

## 9. What each test proves

| Test file | Proves |
|---|---|
| `test_layout.py` | C/ctypes offsets and sizes match (gcc); every record type starts with the same common prefix, which is what makes the `fill_common()` cast safe; our `sockaddr` copies match `<netinet/in.h>` and `<sys/un.h>` offset by offset and are never longer than the real struct; `AF_*` and `EINPROGRESS` match the system headers; the BPF source type-checks for 8 hook/feature combinations against a kernel stub; the check is not vacuous |
| `test_graph.py` | endpoint nodes, CONNECT edges, the download → write → execute chain across a protocol boundary, failed connects never followed, walks starting at a file or endpoint, pre-v3.4 snapshots still loading, tree building, exit survival, every PID-reuse case (rows 19/21/22, audit B/C/D), late events, lost exits, reparenting, placeholders, deep chains, eviction, bootstrap adoption, time-respecting root cause, inode identity, relative-path safety, file LRU, noise skipping, snapshot round trip |
| `test_processor.py` | connect outcomes kept apart (connected / in flight / refused), IPv4, IPv6, unix and abstract sockets, unidentifiable peers, one node per peer, all 120 exec record orders, failed execs, PATH search, missing/late pieces, truncation, END markers, open modes/failures, exit status, log fields, thread names, filters, decode, loss accounting, clock offset, kernel path/inode preference, fileless detection, error isolation, no-output fast path, pending cap |
| `test_system.py` | `/proc` parsing (awkward names), real `/proc` scan, CPU sampler on a busy child, printer, full `main()` with a fake BCC (quiet, view, count sink, batching, feature fallback, total load failure, crash still writes stats, flags), redirected-stdout readiness line, query CLI |
| `test_analyzer.py` | validation analyzer passes a good run and flags each broken case |
| `test_overhead.py` | overhead analyzer's tables, per-op costs, readings and drift guard |

Run: `./run_tests.sh` (no root). 436 tests; Python 3.8, 3.12 and 3.13.

## 10. Reference

**CLI**: `python3 -m hids.monitor --help`. Key flags: `--mode`, `--hooks`,
`--sink`, `--features`, `--pages`, `--batch-ms`, `--duration`,
`--stats-json`, `--snapshot`, `--max-nodes`, `--max-files`,
`--no-bootstrap`, `--filter`, `--type`.

**JSONL fields (every line)**: `type, time, ts_ns, pid, gen, tid, ppid,
uid, gid, name, thread, start_ns, lineage`. The rest depends on the type:

| type | extra fields |
|---|---|
| EXEC | `path, requested_path, argv, argv_truncated, previous_name, enter_seen, exec_from_fd, file` |
| EXEC_FAILED | `path` |
| OPEN | `path, mode (R/W/RW), ret, flags, relative, file` |
| EXIT | `exit_code, signal` |

**Stats JSON**:
- **Records:** `records{raw, EXEC, EXEC_FAILED, EXEC_FROM_FD, OPEN, OPEN_FAILED, EXIT, ARG, logged, undecodable, errors}`, `records_received`, `lost`, `lost_bursts`, `loss_rate`, `late_args`, `forced_exec_settles`, `duplicates_refused`, `bad_arg_indexes`, `first_error`, `crash`.
- **Graph:** `graph{processes, alive, exited, files, generations, inferred_exits, evicted, evicted_files, reparents, placeholders}`.
- **Run configuration:** `version, monitor_pid, kernel, cpus, hooks, sink, features, features_refused, pages_per_cpu, batch_ms`.
- **Cost:** `duration_s, bpf_compile_s, monitor_cpu_s, monitor_cpu_percent_of_one_core, monitor_maxrss_kb, records_per_s, log`.

## 11. Limitations and next steps

Known and deliberate:
- **Open ≠ read/write** — mode is intent from the flags.
- **Path strings come from user memory (TOCTOU)**, but the inode is the kernel's truth.
- **The fd-to-inode read races with a concurrent `close()`** in another thread.
- **Leader-thread exit is treated as process exit** (rare `pthread_exit` in main is misreported).
- **Files are not versioned** (cycles possible; queries are time-bounded instead).
- **Fork-only processes appear only once they do something we hook.**
- **Not hooked yet:** `creat`, `openat2` (5.6+ — a program using it is invisible to the file layer there; harmless on 5.4, where it does not exist), UDP without `connect()`, pipes, mmap. (`accept`/`accept4` **are** hooked, since v3.5 — this line still listed them as missing until an audit caught it.)
- **Network: the local port and the kernel's own view of the peer are not captured** — only what the program asked for. `sock:inet_sock_set_state` (4.16+) would supply both and confirm that a non-blocking connect established.
- **Syscall tracepoints tax all syscalls — answered, not open.** The tax is real, **paid once** at the first `syscalls:*` tracepoint and **~16 ns** per syscall machine-wide; each further hook adds **< 1 ns**. Measured on the VM, v3.5g run `overhead-20261015-193624`, mechanism confirmed in the 5.4 source (`TIF_SYSCALL_TRACEPOINT` refcounting in `syscall_regfunc`). The design consequence: **hook count is not a budget, event rate is.** See `claude/FINDING_syscall_tracepoint_tax.md`.

Next steps, in order:
1. ~~The `count_*` ladder, to decide whether hook count is a budget~~ — **done** (v3.5g, see §11: it is not; event rate is).
2. ~~`accept` (inbound), the other half of lateral movement~~ — **done** in v3.5.
3. Run `vm_validation.sh` and a live `--mode print` for **v3.6**: the decode rewrite changes how every record is read, so nothing in v3.6 is VM-verified yet.
4. `sock:inet_sock_set_state`: kernel-truth addresses, the local port, and confirmation that an in-flight connect established.
5. DuckDB-backed store (advisor's queryable-store request).
6. Detection layer (Isolation Forest baseline, with a simple baseline alongside any graph model — Bilot et al.).
