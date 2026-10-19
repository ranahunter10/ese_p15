# Concepts behind v3.1 — a study guide tied to the code

Each section explains one idea, then points to the lines that use it. Try
the "check it yourself" commands on the VM; being able to reproduce them is
the best preparation for questions from the advisor.

---

## 1. Processes, threads and `task_struct`

The kernel has one structure for anything that can run: `struct task_struct`.
A **thread** is one task. A **process** is a *thread group*: tasks sharing
memory and file descriptors, led by a **group leader**.

The naming is confusing because the kernel and userspace use the words differently:

| userspace says | kernel field | meaning |
|---|---|---|
| PID (process id) | `task->tgid` | id of the thread group = leader's id |
| TID (thread id) | `task->pid` | id of this one task |

`bpf_get_current_pid_tgid()` returns both in one u64: `tgid << 32 | pid`.
So `id >> 32` is the userspace PID and `(u32)id` is the TID. A task is the
leader exactly when both halves are equal; `sched_process_exit` uses this to
ignore thread exits.

Other fields used here:
- `comm` — 16 bytes, max 15 visible chars (Journal row 3). **Per thread**:
  a program may name its threads (`prctl(PR_SET_NAME)`), so the thread's
  comm is not the program name. v3 reads the process name from
  `group_leader->comm` (Journal row 10's "Thread (pooled)").
- `real_parent` — the process that forked us (or the reaper after
  orphaning). `parent` can temporarily be a *debugger* under ptrace.
- `start_time` — nanoseconds on the monotonic clock when the task was
  created. **This is the identity key in v3** (section 7).

Check it yourself:
```bash
ps -eLo pid,tid,comm | grep -m5 firefox   # several TIDs under one PID
cat /proc/$$/status | grep -E 'Tgid|^Pid|PPid'
```

## 2. The process lifecycle: fork, exec, exit, wait

- **fork/clone** — copy the current process. Child gets a new PID and the
  same program. (A thread is also created with `clone`, with flags that share memory.)
- **execve** — replace the program image *inside the same process*. Same
  PID, same start time, new code and a new `comm`. One process can exec
  several times (`bash -c 'exec cat'`).
- **exit** — the process ends. It stays a **zombie** until its parent
  calls `wait()` and reads the **wait status**: `(status >> 8) & 0xff` is
  the exit code and `status & 0x7f` the killing signal (processor.py `_exit`).
- **orphans** — if a parent dies first, the child is **reparented** to
  PID 1 or to a *subreaper* (`systemd --user`). graph.py `_reparent`
  records this.

What a shell does for `cat file`: fork → (child) execve("/usr/bin/cat") →
exit → (shell) wait. That is why `sys_enter_execve` sees the *shell's* name:
the child is still a copy of bash until the exec finishes (rows 9/15).

## 3. System calls and their return values

A system call is the controlled doorway from user mode into the kernel.
C library functions are wrappers: glibc's `open()` actually issues the
`openat` syscall (row 7). Syscalls return a non-negative result on success
(e.g. a file descriptor) or **-errno** on failure (`-2` = ENOENT, `-13` =
EACCES). v3 records `ret` so failed opens are not mistaken for access.

`open` flags: the low 2 bits (`O_ACCMODE`) say read-only / write-only /
read-write; `O_CREAT`, `O_TRUNC` imply writing. events.py `open_mode`.

```bash
strace -e trace=openat,execve cat /etc/hostname
```

## 4. Tracepoints

A **tracepoint** is a hook compiled into the kernel source at a fixed
place, with a published record format:

```bash
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
sudo cat /sys/kernel/debug/tracing/events/sched/sched_process_exec/format
```

- `syscalls:sys_enter_X` / `sys_exit_X` — at the start/end of every syscall.
  Enter sees arguments; exit sees the result. Pair them to get both
  (monitor.bpf.c `stash_open` / `emit_open`, keyed by thread).
- `sched:sched_process_exec` — only after a *successful* exec. Has
  `old_pid` because in a multithreaded exec, the thread doing the exec takes
  over the leader's id.
- `sched:sched_process_exit` — every task exit.

Tracepoints are a stable interface. **kprobes** can hook almost any kernel
function but depend on internal names that change between versions.

**Cost difference that matters here.** Enabling *any* `syscalls:*`
tracepoint sets the flag `TIF_SYSCALL_TRACEPOINT` on **every thread in the
system** (`syscall_regfunc()` in `kernel/tracepoint.c`). With that flag set,
*every* system call of *every* process takes the slower traced entry/exit
path, even syscalls we never record. `sched:*` tracepoints and kprobes don't
do this. BCC 0.12's own `opensnoop`/`execsnoop` use kprobes, which is why
`overhead_breakdown.sh` compares them with our syscall-tracepoint hooks on
the `dd` workload (1-byte reads and writes we never record). The mechanism
is known; how much it costs on your VM is what that run measures.

**`__data_loc` fields.** Variable-length strings in a tracepoint record
are stored after the fixed fields. The fixed part holds a 32-bit number:
low 16 bits = offset from the start of the record, high 16 bits = length.
BCC 0.12 names that number `data_loc_<field>` (verified in its
`tp_frontend_action.cc`), so the kernel's own exec path is at
`(char *)args + (args->data_loc_filename & 0xFFFF)`.

## 5. eBPF

eBPF lets you load small programs into the running kernel, attached to
hooks. Safety comes from the **verifier**, which checks every possible
path *before* the program runs:

- **512-byte stack** → big records live in a per-CPU array map (row 6).
- **NULL checks** after every map lookup, or the program is rejected.
- **Bounded loops** only (accepted since 5.3; earlier kernels needed
  unrolled loops). The argv loop has a constant bound `MAXARG`.
- **Helpers** are the only way to call kernel functionality, and each
  appeared in a specific kernel version. `bpf_probe_read_kernel_str()`
  came in **5.5** (commit 6ae08ae, Nov 2019; helper id 115, the
  `unknown#115` in row 2), so on 5.4 you use `bpf_probe_read_str()`.
  *Journal row 2 says 5.11 — correct it to 5.5.*
- Programs cannot call arbitrary functions: helper C functions are
  `always_inline` so they are pasted into each probe.

**Maps** are kernel data structures shared between eBPF and userspace:

| map | used for |
|---|---|
| `BPF_PERF_OUTPUT` | stream records to userspace |
| `BPF_PERCPU_ARRAY` | scratch buffers, one per CPU, no locks |
| `lru_hash` | enter→exit state per thread; evicts oldest when full |

**BCC** compiles the C source with Clang/LLVM *at startup* (a few seconds;
also why RSS is ~90 MB). BCC also rewrites `task->field` accesses into
`bpf_probe_read` calls. The modern alternative is **libbpf + CO-RE**:
compile once, relocate field offsets using the kernel's BTF type info.
That's a good topic for "future work".

**Wakeups.** A perf ring has a `wakeup_events` setting: after that many
records the kernel wakes a reader sleeping in `poll()`. BCC 0.12 hardcodes
it to 1 (checked in `libbpf.c`), so a sleeping reader can be woken per
record. In a VM each wakeup can mean an inter-processor interrupt and a VM
exit. The kernel only wakes a reader that is actually sleeping in `poll`, so
`--batch-ms` makes the monitor sleep *outside* poll and then drain
everything at once. Newer BCC (and libbpf) let you set the threshold directly.

**Nested programs.** A tracing program can't run while another one is
already running on the same CPU: `trace_call_bpf()` checks a per-CPU
counter (`bpf_prog_active`) and silently skips the nested one. That is
what makes the per-CPU scratch slot safe to reuse. The price is that a
nested event (e.g. from an interrupt during a probe) is dropped without
being counted as lost.

**BCC's source rewriter.** BCC turns `task->group_leader->comm` into
`bpf_probe_read` calls for you. It is convenient, but it can misread
complex expressions. v3.1 writes every kernel read as an explicit
`bpf_probe_read` and computes array slot addresses with integer arithmetic
(`(u64)fds + fd * sizeof(ptr)`), leaving nothing to reinterpret.

**Perf buffer vs ring buffer.** The perf buffer (used here) has one ring
**per CPU**. That has two consequences:
1. When a ring fills, new records are dropped and counted (`lost_cb`, row 18).
   `--pages` sets the ring size per CPU.
2. Records from different CPUs are read **in no guaranteed order**. `execve`
   deliberately moves the process to another CPU (`sched_exec` load
   balancing), so the success record often arrives before the attempt.
   processor.py matches pieces by `(pid, enter timestamp)` instead; the
   test tries all 120 orders.

`BPF_MAP_TYPE_RINGBUF` (kernel 5.8+) is one shared, ordered buffer. It is
not available on 5.4, and eBPF-PATROL assumes 5.8+ for this reason.

## 6. Reading user memory safely, and TOCTOU

Syscall arguments like the path in `openat` are pointers into the *calling
process's* memory. `bpf_probe_read_str` copies from them without faulting.
v3 reads the path at syscall **exit**, and the pointer is still valid then.
But a malicious multithreaded program could change that memory between the
kernel's own read and ours. This is a **time-of-check-to-time-of-use**
(TOCTOU) gap every syscall-tracepoint monitor shares. The robust fix is
LSM hooks (they see the kernel's resolved copy), which is future work.

## 7. PID reuse and identity

PIDs are recycled after they reach `/proc/sys/kernel/pid_max`. A PID
number alone therefore doesn't identify a process over time; all four
PID-reuse bugs in the Journal and audit came from that assumption.

**(pid, start_time)** does identify a process. v3:
- sends the process's and the parent's `start_time` with every event;
- keys graph nodes by `(pid, generation)`, and a new start time for a known
  PID means a new generation;
- attaches late, out-of-order events to the *right* generation by start time;
- infers a lost exit when a PID shows up with a newer start time.

Startup snapshot subtlety: `/proc/<pid>/stat` field 22 is counted on the
**boot** clock in 10 ms ticks. The kernel's `start_time` uses the
**monotonic** clock (which pauses during suspend) in ns. So the startup
values are estimates (`start_exact=False`) that get replaced by the exact
value on the first event.

## 7b. Files: names vs. identity

A **path is a name**, and the same file can have many names: `/tmp/x`,
`./x` from `/tmp`, `/tmp/../tmp/x`, hard links, symlinks. The **inode** is
the file: a number unique within one filesystem (the **device**, `s_dev`).
Inode numbers are reused after a file is deleted, and `i_generation` helps
tell those apart on filesystems that set it (ext4 does).

v3.1 reads the inode of the file actually opened, from the kernel's own
structures:

```
current task ─► files (files_struct) ─► fdt (fdtable) ─► fd[ret] (struct file *)
            ─► f_inode ─► i_ino, i_generation, i_sb ─► s_dev
```

That gives three things:
1. `find`'s relative `openat(dirfd, "lib")` calls in different directories
   stay different files (v3.0 merged them, inventing causal links).
2. A write via one name and a read via another are linked correctly.
3. Even if a program changes the path string in its own memory (TOCTOU),
   the inode still says which file really opened.

Without the inode, a relative path cannot be identified, so v3.1 records
it on the process as *unresolved* instead of guessing.

## 7c. Fileless execution

"Fileless" malware avoids leaving a program file on disk. The classic
Linux pattern:

```c
int fd = memfd_create("x", 0);   // anonymous file living only in RAM
write(fd, elf_bytes, n);          // e.g. downloaded payload
fexecve(fd, argv, envp);          // glibc: execveat(fd, "", argv, envp, AT_EMPTY_PATH)
```

The kernel names such an exec `/dev/fd/<fd>` (and `comm` becomes the fd
number, e.g. `3`). v3.1 hooks `execveat` and flags `exec_from_fd` when the
request had an empty path + `AT_EMPTY_PATH`, or the kernel path is
`/dev/fd/N`. `vm_validation.sh` runs exactly this with Python's
`os.memfd_create` + `os.execve(fd, ...)`. Legitimate software does this
too (some sandboxes and runtimes), so it is a strong *signal*, not proof.

## 7d. Sockets, addresses, and what `connect()` really is

A **socket** is a file descriptor you can send bytes through. `socket()`
creates one; `connect()` names the peer it should talk to. That naming step
is the only moment the peer's address exists in the calling process's own
context — afterwards the traffic belongs to the socket, and by the time a
packet leaves the machine nothing in it says which program produced it. That
gap is exactly what Layer 4 has to bridge, and why the hook is on `connect`.

**The address is a tagged union.** `connect(fd, addr, addrlen)` takes a
pointer to a `struct sockaddr`, whose first two bytes are the **family**.
The family decides the real layout:

| family | value | layout | what it means |
|---|---|---|---|
| `AF_INET` | 2 | `sockaddr_in`: family, port (2B), IPv4 address (4B) | an IPv4 peer |
| `AF_INET6` | 10 | `sockaddr_in6`: family, port, flowinfo, address (16B), scope | an IPv6 peer |
| `AF_UNIX` | 1 | `sockaddr_un`: family, `sun_path[108]` | local IPC through a filesystem socket |

So the hook reads two bytes first, then reads the right number of bytes for
that family. Reading a fixed size would both mis-parse the address and risk
faulting past the end of the caller's buffer.

**Abstract unix sockets** are a Linux extra: if `sun_path` begins with a NUL
byte, the name is not a filesystem path at all but an entry in an abstract
namespace. `ss` and `netstat` print those with a leading `@`, and so do we.

**Network byte order.** Ports and IPv4 addresses travel big-endian ("network
order") regardless of the machine. x86 is little-endian, so a port read as a
raw `u16` looks wrong until converted: 443 is `0x01BB`, stored as `BB 01`, and
read naively as 48129. The kernel side has no `ntohs`, so the record carries
the raw value and `events.decode()` converts once, with `socket.ntohs`.

**What the return value means** — three outcomes, not two:

| return | meaning |
|---|---|
| `0` | connected |
| `-EINPROGRESS` (−115) | the socket is non-blocking: the attempt is in flight and may still succeed or fail. Neither a success nor a failure. |
| any other `-errno` | refused (`ECONNREFUSED`), unreachable, timed out — and *this is a signal*: a host sweep or port scan is a burst of these from one process |

**What `connect()` does NOT see.** UDP usually skips it entirely (`sendto`
carries the address per message), and inbound connections arrive through
`accept()`, which is the next section. One hook is one direction of one
protocol — worth saying out loud, because "we monitor the network" would be
a much bigger claim than the code makes.

## 7e. The other direction: `accept()`, and who writes the address

A server does `socket()` → `bind()` → `listen()` → `accept()`. The first
three set a socket up to receive; `accept()` blocks until someone connects,
then returns a **new** file descriptor for that one conversation while the
listening socket stays open for the next. So in an inbound record the
syscall's return value is a descriptor, not a status — a thing worth knowing
before reading `ret` as an error code.

**Who fills the address is the interesting part.** `connect(fd, addr, len)`
is given an address *by the program*. `accept(fd, peer, len)` is given an
empty buffer which the *kernel* fills in before returning:

```c
/* v5.4 net/socket.c, inside __sys_accept4() */
if (upeer_sockaddr) {
        len = newsock->ops->getname(newsock, (struct sockaddr *)&address, 2);
        err = move_addr_to_user(&address, len, upeer_sockaddr, upeer_addrlen);
}
fd_install(newfd, newfile);
```

Two things follow. First, the address can only be read *after* the syscall,
which is the opposite of the connect hook. Second — and this is the part
worth remembering — a process can lie about who it is connecting *to*, but
it cannot lie about who connected *to it*: that string came from the
kernel's own socket state. For a monitor, values the kernel wrote are
strictly better evidence than values a process passed in.

**Ephemeral ports.** When you connect somewhere, the kernel picks your
source port from a random high range. So the port inside an accepted peer
address is *theirs*, and it is different on every connection:

```
accept4(3, {sin_port=htons(45192), sin_addr="127.0.0.1"}, ...)   # connection 1
accept4(3, {sin_port=htons(51022), sin_addr="127.0.0.1"}, ...)   # connection 2
```

Both are the same peer. That is why an inbound endpoint in this system is
identified by host alone (`host:10.0.0.9`) while an outbound one keeps its
port (`net:10.0.0.9:443`) — there the port is the *service*, which is a
stable, meaningful part of the peer's identity.

**`accept(fd, NULL, NULL)`** is legal: a server that does not care who
called. Then no address is written anywhere, so no peer identity exists —
which the record states rather than filling in a plausible-looking
`0.0.0.0`. A unix-socket client usually has the same effect from the other
end, because it normally has no bound name of its own for `getname()` to
return.

## 8. Clocks

| clock | counts suspend? | used by |
|---|---|---|
| `CLOCK_REALTIME` (`time.time()`) | wall time, can jump | log timestamps |
| `CLOCK_MONOTONIC` | no | `bpf_ktime_get_ns()`, `task->start_time` |
| `CLOCK_BOOTTIME` | yes | `/proc` starttime, `btime` |

events.py `Clock` measures REALTIME − MONOTONIC once and adds it. That is
exact, unlike v2's whole-second `btime`.

## 9. /proc

`/proc/<pid>/stat` is generated text. Field 2 is `(comm)` and may contain
spaces and parentheses, so parse by cutting at the **last** `)`
(procstat.py `parse_stat`, with a test using the name `a) b (x)`). CPU
figures come in **clock ticks** (`getconf CLK_TCK`, usually 100/s):
CPU% = Δ(utime+stime) / CLK_TCK / Δwall × 100, which is what `top` shows.

## 10. Provenance graphs

- **Nodes**: process lifetimes, files, and endpoints (network peers and unix
  sockets). A file is identified by its inode, an endpoint by its address and
  port: in both cases by *what it is*, never by who touched it, which is what
  makes two processes meeting at the same resource visible as one node.
- **Edges** follow **information flow**: parent→child (FORK),
  file→process (READ, EXEC), process→file (WRITE),
  process↔endpoint (CONNECT — a connection carries data both ways, so the
  walk direction decides which meaning is in play).
- **Root cause** = walk edges backwards; **impact** = forwards.
- **Time matters.** A file written at t=12 cannot have influenced a read
  at t=6. `trace_back` only follows edges older than the point it came
  from. The test includes a reader *before* the write to prove this.
- **Cycles**: without file versions, "P reads F then writes F" is a
  cycle. Systems like Kairos version nodes to keep a true DAG. v3 uses the
  time bound plus visited sets instead, and says so.
- **Dependency explosion**: long-lived processes (shells, daemons) and
  common files (`libc.so.6`, `ld.so.cache`, locale data) connect everything
  to everything. The first VM root-cause trace listed three library files
  before the payload. `graph.common_file` + `skip=` hides the obvious ones.
  Doing this *well* is an open research problem, and one reason
  Kairos/R-CAID/FLASH exist.

## 11. C techniques in monitor.bpf.c

- **Fixed-width types** (`u32`, `u64`, `s32`) so sizes are identical in C
  and Python.
- **Struct layout**: the compiler inserts padding to align fields, so field
  order is chosen to leave none, and test_layout compiles the struct and
  compares every `offsetof` with ctypes. (The mutation test swapped two
  fields and was caught.)
- **Tagged union across sizes**: two record types share one buffer, and
  the first 4 bytes say which one it is.
- **`const char *const *argv`**: a pointer to an array of pointers to
  strings. Each level is a separate user-memory read.
- **`goto end`**: the usual C way to jump to shared cleanup/final code.
- **`#ifdef` feature switches**: the same source compiles into different
  programs depending on the `#define`s prepended at load time (hooks,
  optional features). The layout test compiles every combination.
- **Operator precedence**: `x = a || b ? c : d` in C and
  `a or b if c else d` in Python both group as `a or (b if c else d)`.
  One such line in `analyze_overhead.py` was caught during the audit; use
  parentheses.
- **Copy before delete**: `*enter_ts` is copied before `exec_start.delete`,
  because the map value pointer is invalid afterwards.

## 12. Python techniques

- **ctypes.Structure** — describes raw memory; `ctypes.cast(ptr,
  POINTER(T)).contents` views bytes as a struct. Copy values out
  immediately (`decode` builds namedtuples) because BCC's buffer is only
  valid during the callback.
- **namedtuple / `__slots__`** — small immutable records; `__slots__`
  removes the per-object dict (memory for thousands of nodes).
- **OrderedDict as an LRU** — `popitem(last=False)` drops the oldest.
- **Closures as callbacks** — `lambda cpu, data, size: proc.handle(...)`.
- **Signal handling** — the handler only sets a flag; the loop checks it
  (row 11). Python runs handlers between bytecodes, not inside C calls.
- **`try / finally`** — the stats file is written in `finally`, so a
  crash still leaves evidence (the `crash` field says what happened).
- **Output buffering** — to a terminal, `print` is line-buffered; to a
  file or pipe it is block-buffered, and text can sit in memory
  indefinitely. That made `vm_validation.sh` give up the first time.
  Fixes: `print(..., flush=True)`, `python3 -u`, or `PYTHONUNBUFFERED=1`.
- **Graceful degradation** — `load_bpf` tries the richest feature set
  first and falls back, recording what was refused, instead of failing.
- **Test doubles** — the fake `bcc` module replays scripted records. When
  the fake itself was wrong (it never "pressed Ctrl+C" for zero-timeout
  polls), a test hung. Fakes need the same care as real code.
- **`python3 -m package.module`** — run code inside a package so relative
  imports (`from .graph import ...`) work.
- **Testing**:
  - `unittest.mock.patch` replaces `os.geteuid` and the whole `bcc`
    module, so `main()` runs end to end without root.
  - **Mutation testing**: plant a bug and confirm a test fails. Done for the
    layout check, the BPF syntax check and the lost-events wiring.
  - **Buffered output**: `print()` to a terminal is line-buffered, to a file
    or pipe it is block-buffered (flushed every ~8 KB or at exit). A script
    waiting for a line in a log file needs `flush=True` or `python3 -u`.
    An environment with `PYTHONUNBUFFERED=1` hides this, which is how it
    slipped past the tests until the first VM run.
  - **`pkill -f pattern` matches its own caller**: if the pattern is in the
    command line of the shell running pkill, that shell is killed too.
    Prefer PID files (`$!`) or `pgrep -af` first.
  - **Bytecode cache pitfall**: `__pycache__/*.pyc` is reused when the
    source has the same size and mtime. Restoring a file with `cp` in the
    same second kept a planted bug alive until the cache was cleared.

## 13. Exercises on the VM

1. Run `sudo python3 -m hids.monitor --mode print -f cat`, then `cat
   /etc/hostname` in another terminal. Identify the EXEC, OPEN and EXIT lines.
2. Type a mistyped command path, e.g. `/usr/bin/catt`. Look for EXEC_FAILED.
3. `sudo python3 -m hids.monitor --pages 8 --mode quiet --stats-json s.json`
   while running `find /`. Compare `lost` to a run with `--pages 256`.
4. Save `--snapshot`, then `python3 tools/query_graph.py <snap> trace <pid>`
   on the `cat` that read a file another command wrote.
5. Read `sched_process_exec/format` and find `old_pid`; explain why it is needed.
6. `ls -i /tmp/p15_rel.txt`, then find that inode number in a snapshot's
   `files` (`python3 tools/query_graph.py <snap> writers /tmp/p15_rel.txt`).
7. Run the memfd snippet from §7c under `--mode print` and find `[EXEC FROM FD]`.
8. `sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_execveat/format`
   and match each field to `exec_enter()`'s arguments.
