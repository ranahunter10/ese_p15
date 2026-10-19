# Stage 2 — `hids/bpf/monitor.bpf.c`, all 794 lines

Three passes. Do not read the file top to bottom on the first pass: read
the **shape** first, then one hook family at a time. Budget 5–7 hours
across two or three sittings.

Navigate by symbol, not line number:

```bash
cd ese_p15
grep -n "^#define\|^struct\|^BPF_\|^static inline\|^TRACEPOINT_PROBE\|^#ifdef\|^#endif" hids/bpf/monitor.bpf.c
```

That one command prints the map of the file. Keep it in a second terminal.

---

## Pass A — the shape (1 h)

### A.1 It is not a file the compiler ever sees on disk

`monitor.bpf.c` is read as **text** by `monitor.bpf_text()`, which prepends
`#define` lines and hands the string to BCC. BCC runs clang on it at
startup, loads the resulting bytecode, and the verifier checks it.

```bash
grep -n "def bpf_text" -A 8 hids/monitor.py
```

Two consequences worth stating precisely:

- **A refused feature means a different program was compiled.** When
  `FEATURE_SETS` falls back, we do not disable a branch at runtime — we
  recompile without `-DFILE_IDENTITY`, so the inode-reading code does not
  exist in the loaded program. That is why the stats record *which* feature
  set ran.
- **`SELF_TGID` is a compile-time constant**, our own PID baked into the
  program text. The monitor's own `/proc` reads therefore never become
  events, and the filtering costs one comparison in the kernel rather than
  a map lookup or a userspace check. This killed the self-observation
  feedback loop in v2.

### A.2 BCC's three magic constructs

These are not C. BCC rewrites them before clang sees them:

| you write | what it becomes |
|---|---|
| `TRACEPOINT_PROBE(syscalls, sys_enter_openat) { … }` | a function whose single argument is a generated struct matching that tracepoint's `format` file, named `args` |
| `BPF_PERF_OUTPUT(events)` | a perf-event map, plus `events.perf_submit(ctx, p, size)` → `bpf_perf_event_output(...)` |
| `BPF_TABLE("lru_hash", K, V, name, size)` / `BPF_PERCPU_ARRAY(...)` | a map definition, plus `.lookup()/.update()/.delete()` → the corresponding `bpf_map_*` helpers |

So `args->filename` works because BCC generated a struct field with that
name, from the kernel's own tracepoint declaration. **If the kernel's field
name differs, the program does not compile** — which is a feature: it fails
loudly rather than reading the wrong offset.

### A.3 Read the record layouts

```bash
sed -n '/---- Record layouts/,/^BPF_PERF_OUTPUT/p' hids/bpf/monitor.bpf.c
```

Four things to understand before moving on:

1. **`COMMON_FIELDS`** is a macro expanded into `common_t`, `event_t` and
   `net_t`, so all three begin with the identical prefix. That is what lets
   `fill_common((struct common_t *)ev, type)` fill any record through a
   cast. The assumption is *proved* by a test that compiles all three and
   compares offsets — not trusted.
2. **Three record types, one stream.** `event_t` (392 B) for exec/open/exit,
   `arg_t` (152 B) for argv fragments, `net_t` (256 B) for connect/accept.
   The reader tells them apart by the `type` field, which is why `type` is
   first in the prefix: `decode()` can read it before knowing the size.
3. **`u16 sock_type; u16 pad;`** — explicit padding. Never leave the
   compiler's padding implicit in a struct Python has to mirror.
4. **`net_args_t` / `accept_args_t` / `open_args_t`** are not records. They
   are *stash* structures held in maps between a syscall's entry and exit.

### Self-check for pass A

- Why is `type` the first field of every record?
- What exactly happens when `FILE_IDENTITY` is refused by the verifier?
- Why does `args->upeer_sockaddr` compile for `sys_enter_accept` but not
  for `sys_enter_connect`?

---

## Pass B — the common path (1.5 h)

Read these four functions, in this order, with `grep -n "<name>"` to find
them: `is_self`, `fill_common`, `fill_event`, then `read_fd_inode` →
`read_inode`.

### B.1 `fill_common` — answering "who did this?"

Every record starts here. Three mechanisms in twenty lines:

**`bpf_get_current_pid_tgid()` returns one u64 holding two numbers.** High
32 bits = tgid (what userspace calls the PID), low 32 = pid (what userspace
calls the thread id). Linux's internal naming is the reverse of the
userspace naming, which is a classic source of confusion:

| our field | from | userspace name |
|---|---|---|
| `c->pid` | `id >> 32` | the process id (tgid) |
| `c->tid` | `(u32)id` | the thread id |

**The group leader holds the process's identity.** A thread's own `comm`
can differ from its process's name (`tcomm` vs `comm` in our records — the
Journal has a row where a thread named `p15worker` would otherwise have
been reported as the process name). So we read `task->group_leader` and take
`comm` and `start_time` from it.

**`real_parent`, not `parent`.** `task->parent` is the process being told
about wait status, which under `ptrace` is the *debugger*. `real_parent` is
who actually forked us. Getting this wrong would make any process under
`gdb` or `strace` reparent itself to the tracer in our tree.

And the line that makes the entire identity algorithm possible:

```c
bpf_probe_read(&c->start_ns, sizeof(c->start_ns), &leader->start_time);
```

`task->start_time` is nanoseconds since boot, set once at fork, **unchanged
by exec**. Carried on every record together with the parent's start time,
it is what makes `(pid, start_time)` a real identity and PID reuse solvable
in userspace. Stage 5 builds on exactly this.

> Notice that every kernel-memory access is a checked `bpf_probe_read` with
> a NULL test after it. The verifier demands it, and it is also honest:
> `task_struct` internals could be anything if the read fails, so a failed
> read must leave the field at its reset value rather than garbage.

### B.2 `read_fd_inode` — answering "to what?"

The walk is `task → files → fdt → fd[n] → struct file → inode →
{i_ino, i_generation} , inode → i_sb → s_dev`.

Study four things:

1. **Every hop is a `probe_read` with a NULL check.** Six hops, six checks.
2. **The bounds check is not optional**: `if ((unsigned int)fd >= max_fds)
   return;` — reading past the fd array would be reading arbitrary kernel
   memory. The cast to `unsigned` also disposes of negative fds.
3. **The slot address is computed with plain integer arithmetic**
   (`(u64)fds + (u64)fd * sizeof(struct file *)`) specifically so BCC's
   source rewriter does not try to reinterpret a pointer dereference.
4. **`i_generation` is in the key.** Inode numbers are reused when a file
   is deleted and another created; the generation counter distinguishes
   them. This is the file-level analogue of PID generations — the same idea
   twice, one for processes and one for files.

**The documented race:** between the syscall returning and this walk, another
thread could `close()` that fd, so we would read NULL or a different file.
Accepted and written down (`ARCHITECTURE.md` §11). Be ready to say why it is
acceptable: the window is sub-microsecond, the alternative needs a kprobe on
an internal return path, and a wrong inode shows up as an unresolved file
rather than a false causal edge.

### Experiment `[VM]`

```bash
sudo python3 -m hids.monitor --mode print -f cat --duration 20 &
cat /etc/hostname
```

Look at one OPEN line: `path` came from user memory, `file` is the
`inode:dev:ino:gen` identity from this walk. Then:

```bash
sudo python3 -m hids.monitor --features none --mode print -f cat --duration 20
```

Same event, no `file` identity, and `unresolved_opens` climbing for
relative paths. That difference *is* `FILE_IDENTITY`.

### Self-check for pass B

- `pid_tgid >> 32` gives what, in userspace vocabulary?
- Why read `comm` from the group leader rather than with
  `bpf_get_current_comm()`?
- Why `real_parent` and not `parent`?
- What single field makes PID reuse solvable, and what property of it
  matters?
- Name the two reasons the `max_fds` bounds check exists.
- Why is `i_generation` part of a file's identity?

---

## Pass C — the hooks, one family at a time (3–4 h)

### C.1 Exec: one event, four records

This is the hardest part of the file and the part most worth understanding
completely. Read `exec_enter`, then the three probes after it.

**Why one exec produces up to 23 records:**

| record | when | carries |
|---|---|---|
| `EVENT_EXEC_ENTER` | `sys_enter_execve(at)` | the *attempt*: path from user memory, dfd, flags |
| `EVENT_ARG` × n | same probe, one per argv entry | `idx`, the string, `enter_ts` as the join key |
| `EVENT_ARG` (END) | same probe, always | `ARG_FLAG_END`, plus the count in `idx` |
| `EVENT_EXEC_OK` | `sched_process_exec` | *success*, the kernel's own path, the exe inode, `aux_ns` = the enter timestamp |

**Why the split exists at all** — the question to be able to answer in one
breath: `sys_enter_execve` fires *before* the kernel tries the exec. At that
moment the argv and path are readable and the caller's name is still in
`comm`, but the exec may still fail. `sched_process_exec` fires only after
the new image is in place, so it proves success and carries the kernel's own
path — but by then argv has been replaced and the old name is gone. Neither
probe alone can report "this program ran, with these arguments". So the two
halves are joined in userspace by `(pid, enter_ts)`.

**The join key, and `old_pid`:**

```c
u32 old = args->old_pid;
u64 *enter_ts = exec_start.lookup(&old);
if (enter_ts) {
    ev->aux_ns = *enter_ts;          // copy BEFORE delete invalidates it
    exec_start.delete(&old);
}
```

In a multithreaded exec the calling thread takes over the leader's id, so
its thread id *changes during the syscall*. `sched_process_exec` exposes the
pre-exec id as `old_pid`, which is the key the enter probe stored under.
Also note the comment: the value is copied out of the map before `delete`,
because the pointer is into map memory.

**The argv loop** — four details:

```c
for (i = 0; i < MAXARG; i++) {
    const char *argp = NULL;
    u64 slot = (u64)argv + (u64)i * sizeof(const char *);
    bpf_probe_read(&argp, sizeof(argp), (void *)slot);
    if (!argp) goto end;
    ...
}
```

1. `argv` is a user pointer to an array of user pointers. Two levels of
   `probe_read`: one for the pointer, one for the string.
2. The bound is the constant `MAXARG` (20) — provable by the verifier
   (see stage 1 on bounded loops) and usually unrolled by clang.
3. `ARG_FLAG_TRUNCATED` is set if the loop ran out rather than hitting a
   NULL, so userspace knows the command line is incomplete rather than
   guessing.
4. **An END record is always emitted**, carrying the count. Because records
   can arrive in any order, "I have all the args" cannot be inferred from
   arrival; it has to be stated. This is the single design decision that
   makes `ExecAssembler` possible (stage 4).

**`execveat` and fileless execution.** `execveat(fd, "", argv, envp,
AT_EMPTY_PATH)` runs the program behind an open fd — glibc's `fexecve()`,
and the standard way to run a program that exists only in memory
(`memfd_create`). Hooking it, plus `KERNEL_EXEC_PATH` reporting
`/dev/fd/3`, is what makes "fileless exec" visible. Our validation proves
it with an actual memfd+fexecve run.

**`__data_loc`** — the mechanism stage 1 warned you about:

```c
u16 off = args->data_loc_filename & 0xFFFF;
bpf_probe_read_str(&ev->filename, sizeof(ev->filename), (char *)args + off);
```

The tracepoint stores a variable-length string elsewhere in its own record
and gives you an int whose low 16 bits are the offset. You read from
`(char *)args + off`. This is the kernel's own copy of the path, so unlike
the enter probe's string it cannot be rewritten by the process.

### C.2 Open: the enter/exit pattern

Read `stash_open` and `emit_open`. The pattern is BCC's `opensnoop`: the
entry probe stashes the path pointer and flags keyed by `pid_tgid`, the exit
probe knows the result.

The sentence in `emit_open` to be able to defend:

> The path is read from USER memory: a hostile program could change it after
> the kernel used it (TOCTOU). The inode below is the kernel's truth about
> which file was actually opened.

So one record carries a *claim* (the path) and a *fact* (the inode). Our
graph keys on the fact and keeps the claim as a label. The same distinction
runs through the whole project — and recurs in C.3 with the opposite
answer.

Note also: `ret >= 0` gates the inode walk, because there is no fd to walk
on failure; and a failed open is still emitted, so "tried to read
/etc/shadow and was denied" is recorded.

### C.3 Net: the two asymmetries

Read `sys_enter_connect` / `sys_exit_connect`, then `accept_enter` /
`accept_exit`. They are mirror images, and the mirror is not symmetric —
this is the most examinable part of the network layer.

| | `connect` | `accept` |
|---|---|---|
| who supplies the address | the **process** | the **kernel** |
| when it is readable | at **entry**, before the kernel acts on it | at **exit**, after the kernel wrote it |
| why that moment | reading at exit would let another thread rewrite the address the kernel already used (TOCTOU) | the buffer holds nothing at entry; `__sys_accept4` fills it before `fd_install` |
| trustworthy? | only as far as the process is | **kernel truth** — unforgeable by the watched process |
| what a failure means | a refusal is **signal** (scanning), so it is kept | an `-EAGAIN` means nothing was waiting: **absence**, so it is dropped in-kernel |
| identity | `net:<addr>:<port>` — the port is the service | `host:<addr>` — the peer's port is ephemeral |

Then the family parse, shared by both: read two bytes for the family first,
and only then read exactly as much as that family defines (8 bytes IPv4, 28
IPv6, 110 unix). Reading a fixed size would both mis-parse and risk
faulting past the end of the caller's buffer. Other families
(`AF_NETLINK`, `AF_PACKET`) are dropped in-kernel: not process-to-host
relationships, and NetworkManager alone would flood the ring.

Two more things to find and explain:

- **`accept_args` is a separate map** from `net_args`, and the comment says
  why: an LRU evicts the oldest entry, a listener can block inside
  `accept()` for hours, and outbound churn in a shared map would evict
  exactly the blocked listener we care most about.
- **`NET_FLAG_INPROGRESS`** exists because a non-blocking connect returns
  `-EINPROGRESS` (−115) and may still succeed or fail later. The kernel side
  flags it explicitly rather than leaving `-115` to be interpreted
  downstream. The *reason this matters* is a real VM failure:
  `socket.create_connection(addr, timeout)` sets the socket non-blocking,
  so a test looking for `ret == 0` failed while the monitor was right
  (`CHANGES_v3.4.md` row 74).

### C.4 Exit: the one-line subtlety

```c
if ((u32)(id >> 32) != (u32)id)
    return 0;
```

`sched_process_exit` fires for **every thread**. A process has exited only
when its *group leader* exits, and the leader is the task whose tgid equals
its pid. Without this line, a 40-thread process would report 40 exits.

Then the exit code: `do_exit()` stores `exit_code` before this tracepoint
fires (validated on the VM with `sh -c 'exit 3'`), and the value is a wait
status, so `code >> 8` is the exit code and the low 7 bits are the killing
signal.

### Experiments `[VM]`

```bash
# 1. one exec, all four record types, in arrival order
sudo python3 -m hids.monitor --mode print --duration 15 &
/bin/echo alpha beta gamma

# 2. a failed exec is still recorded
/bin/nosuchprogram 2>/dev/null

# 3. hook groups really are separate programs
sudo python3 -m hids.monitor --hooks exit --mode print --duration 10
sudo python3 -m hids.monitor --hooks net  --mode print --duration 10

# 4. the full inbound/outbound scenario, deterministic, no internet
sudo python3 -m hids.monitor --mode quiet --duration 30 --snapshot /tmp/g.json &
python3 tools/net_demo.py
python3 tools/query_graph.py /tmp/g.json inbound
python3 tools/query_graph.py /tmp/g.json endpoints
```

### Experiment `[laptop]` — see the verifier say no

The fastest way to understand the stack limit is to hit it. In a scratch
copy (never the real file), add a big stack variable to a probe:

```c
char waste[600];
waste[0] = 0;
```

Load it on the VM and read the rejection. You will see the verifier's own
message about stack size, and the reason `ev_scratch` exists stops being
theoretical.

### Self-check for pass C

1. Why can't `sched_process_exec` alone report "this program ran with these
   arguments"?
2. What is `old_pid`, and why is it the right map key?
3. Why is an explicit END record needed for argv when the count is already
   in `idx`?
4. A program calls `execveat(3, "", argv, envp, AT_EMPTY_PATH)`. What does
   our record say, and why does that matter for the threat model?
5. `connect` parses at entry, `accept` at exit. Give the kernel-source
   reason for each, not just the rule.
6. Which of those two addresses can a compromised process lie about?
7. Why is a failed `connect` kept but a failed `accept` dropped?
8. Why does an inbound endpoint id contain no port?
9. What does the one-line check at the top of the exit probe prevent?
10. The open record contains both a path and an inode. Which is evidence,
    and which is a label?

<details>
<summary>Answers</summary>

1. Because by the time it fires the new program image is already in place:
   argv has been replaced and the caller's `comm` is gone. The enter probe
   has argv and the old name but cannot know whether the exec succeeded.
2. The pre-exec thread id. In a multithreaded exec the calling thread takes
   over the group leader's id during the syscall, so the id the enter probe
   stored under no longer exists by the time `sched_process_exec` runs;
   `old_pid` is that original id.
3. Because records arrive in any order, so "the last one" cannot be
   recognised by arrival. The END record is an explicit statement that the
   list is complete, and it also carries the count and the truncation flag.
4. `KERNEL_EXEC_PATH` reports the kernel's own path, `/dev/fd/3`, and
   `FILE_IDENTITY` reports the exe inode; the processor flags
   `exec_from_fd`. It matters because that is the fileless-execution path —
   a program that never existed as a file on disk, which file-scanning
   defences cannot see.
5. `connect`: the address is user-supplied, so at entry it is what the
   program passed and the kernel has not acted on it yet; reading it at exit
   would leave a window for another thread to rewrite it. `accept`: at
   entry the buffer is empty, because `__sys_accept4()` calls
   `getname()` + `move_addr_to_user()` during the syscall, before
   `fd_install`; and a failed copy aborts the call, so a successful return
   guarantees the bytes are there.
6. The `connect` target. The accepted peer address was written by the
   kernel, so the monitored process cannot forge it.
7. A refused connect is the signature of scanning or host discovery —
   evidence. A failed accept means no connection was waiting (`-EAGAIN` on
   every poll of a non-blocking listener), which is an absence, and keeping
   it would flood the ring with non-events.
8. Because that port is the peer's *ephemeral source* port — a different
   number every connection (45192, then 51022, measured). Including it
   would create one endpoint node per connection and make "who keeps
   connecting to this box" unanswerable.
9. `sched_process_exit` fires per thread; the check keeps only the group
   leader, so a 40-thread process reports one exit rather than 40.
10. The inode is evidence (the kernel's answer to "which file"); the path is
    a label read from user memory, which a hostile process could have
    changed after the kernel used it.

</details>

---

## Before you move on

You should now be able to take any line of `monitor.bpf.c` and say which of
the four questions from `00_MASTER.md` it serves, and what would break if it
were removed. Two specific checks:

- Point at the three lines that make PID reuse solvable.
- Point at the two lines that make a value kernel truth rather than a
  process's claim.

Next: `03_EVENTS.md` — the byte-exact contract that turns these records into
Python, where the mirror has to match the C or everything after it is
nonsense.
