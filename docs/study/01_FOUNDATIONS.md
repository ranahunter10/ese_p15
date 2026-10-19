# Stage 1 — Foundations

What you need before `monitor.bpf.c` can be read as anything other than
strange C. Budget 2–3 hours. Nothing here is specific to our code, but
every number in it constrains our code.

---

## 1.1 What eBPF actually is

A small virtual machine inside the kernel. You hand the kernel a program in
BPF bytecode; it checks the program can't crash or loop forever, JITs it to
native code, and runs it every time the event you attached it to fires.

The part people under-appreciate: **your program runs in the context of
whatever process triggered the event**, synchronously, inside that
syscall's execution. It is not a separate thread, not a reader of a queue.
That is why every microsecond spent in a probe is a microsecond added to
somebody's syscall, and why the whole overhead question exists.

Three properties follow, and all three shape our code:

| property | consequence here |
|---|---|
| runs in the triggering process's context | `bpf_get_current_pid_tgid()` tells us who, with no lookup |
| must be provably safe before it runs | the verifier's limits below are hard walls |
| cannot block, allocate, or call libc | every value is copied into fixed-size records |

### Read

`docs/CONCEPTS.md` §1–§3 (BPF basics, maps, the verifier) if you want the
project's own framing first. Then this file.

---

## 1.2 Tracepoints vs kprobes — and why we only use tracepoints

**A kprobe** patches an arbitrary kernel function's first instruction. You
can attach to almost anything, and you get whatever that function's
arguments happen to be *in that kernel version*. Function names and
signatures are not an interface: they change, get inlined, get renamed.

**A tracepoint** is a declared, stable hook that kernel developers placed
deliberately, with a documented set of fields. `syscalls:sys_enter_openat`
exists because someone wrote `SYSCALL_DEFINE` for `openat`, and the field
names come from that declaration.

We use tracepoints everywhere. The cost of that choice: there is no
tracepoint for most interesting internal functions, so some things (the
local port of a socket, for example) are simply unreachable until we add a
second mechanism. The benefit: the same `monitor.bpf.c` runs unmodified on
kernel 5.4 and would on 6.x.

> **The one thing to remember.** A tracepoint's *field names* are the ABI.
> `fd`, `upeer_sockaddr`, `upeer_addrlen` are not names we chose — they come
> from `SYSCALL_DEFINE3(accept, int, fd, struct sockaddr __user *,
> upeer_sockaddr, int __user *, upeer_addrlen)` in `net/socket.c`. That is
> why `docs/CHANGES_v3.5.md` §A quotes the kernel source: the field names
> had to be *verified*, not guessed.

### Experiment `[VM]`

```bash
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_accept4/format
sudo cat /sys/kernel/debug/tracing/events/sched/sched_process_exec/format
```

Read the second one carefully. `filename` is declared as
`__data_loc char[]` — a *variable-length* field stored elsewhere in the
record, with an offset packed into an int. That single oddity is why our
code does the `data_loc` dance instead of just reading a string, and why
`tests/test_layout.py` models the field as `int data_loc_filename`.

---

## 1.3 The verifier, with real numbers

The verifier walks every possible path through your program before it is
allowed to run. What it enforces (checked against the kernel's own
documentation — these are the numbers to quote, not remembered ones):

| limit | value | source |
|---|---|---|
| stack per program | **512 bytes**, all program types | kernel `bpf_design_QA.rst` |
| program size, user-visible | 4096 instructions (`BPF_MAXINSNS`) | same |
| instruction limit, raised | **1 million**, since Linux **5.2** | LWN 794934 |
| bounded loops | supported since Linux **5.3** | LWN 794934 |

Our VM is 5.4, so bounded loops and the 1M limit are both available.

> **An honest nuance to carry into a viva.** Code comments in this project
> talk about "constant loop bounds" as though loops were forbidden. On 5.4
> they are not — bounded loops landed in 5.3. The constant bounds are still
> right, for two different reasons: the verifier must be able to *prove* the
> bound (so the limit has to be a compile-time constant, not a runtime
> value), and every iteration is instructions the verifier has to explore
> inside its complexity budget. If someone asks "are loops banned in eBPF?",
> the correct answer is "unbounded ones are; since 5.3 a loop the verifier
> can bound is fine."

### The 512 bytes is the single most shaping constraint in our kernel code

`struct event_t` is 392 bytes. `struct arg_t` is 152. The exec-enter path
needs both at once: 544 > 512, and the program would be rejected.

That is the entire reason `BPF_PERCPU_ARRAY(ev_scratch, struct event_t, 1)`
exists. A per-CPU array is map memory, not stack, so the size limit does
not apply — and because there is exactly one slot per CPU, no locking is
needed either.

### Why a per-CPU slot is safe from being clobbered mid-use

The obvious worry: our probe fills the scratch slot, another event fires on
the same CPU, that probe uses the same slot, and our half-built record is
corrupted. It cannot happen, because the kernel keeps a per-CPU
`bpf_prog_active` counter and refuses to run a second tracing program on a
CPU while one is active — the nested event is dropped instead. The code
says this in a comment near the scratch definitions; make sure you can
explain it without reading it.

### Experiment `[laptop]`

Prove the sizes rather than trusting them:

```bash
cd ese_p15 && python3 -m unittest tests.test_layout -v 2>&1 | head -20
```

That suite compiles our structs with **gcc** and compares offsets field by
field against what Python's `ctypes` believes. It is also where a real
mistake was caught: a struct was documented as 416 bytes and was actually
392 (`CHANGES_v3.4.md` row 64).

---

## 1.4 Per-CPU perf buffers, and why ordering is not guaranteed

The kernel side writes records into a **perf ring buffer**, one ring per
CPU. Userspace polls the rings and drains them, CPU by CPU.

Consequences, and the second one is the source of a whole class of bugs:

1. **Loss is possible and must be counted.** If a ring fills before
   userspace drains it, records are dropped and the kernel tells us how
   many. `--pages` sizes those rings (64 pages/CPU default; the 13-Oct run
   showed 18.4 % loss at 64 and 0 % at 256 under the same workload).
2. **Order is not global.** Two records written on different CPUs can be
   read in either order. There is no sequence number. A process that
   migrates between CPUs mid-syscall — which `execve` deliberately does —
   can have its records arrive backwards.

Everything downstream is designed around point 2:

- `ExecAssembler` keys on `(pid, enter_ts)` and matches by timestamp, never
  by arrival order (stage 4).
- `_touch()` maintains `first_ns` with `min()` as well as `last_ns` with
  `max()`, because the first record *processed* is not the earliest record
  that *happened* — this was bug H3, found by a fuzzer, `WORKLOG` Part 3.
- The rename guard in `process()` only lets the newest-seen record change a
  process's name, so a late pre-exec record cannot turn `cat` back into
  `bash`.

> Note for later: Linux 5.8 added the **BPF ring buffer**, which is shared
> across CPUs and preserves ordering. We cannot use it on 5.4. That is one
> of several reasons the kernel-version question in `WORKLOG` §6 matters.

---

## 1.5 Clocks

Two clocks, and conflating them produces timestamps that look fine and are
wrong.

| clock | what it is | where it appears |
|---|---|---|
| `CLOCK_MONOTONIC` | nanoseconds since boot, never jumps, unaffected by NTP or timezone | `bpf_ktime_get_ns()`, `task->start_time`, every `ts_ns` in our records |
| `CLOCK_REALTIME` | wall-clock time, can jump forwards or backwards | what a human needs in a log line |

Everything in the graph is monotonic, because durations and ordering must
survive a clock adjustment. The JSONL log carries a wall-clock `time` field
*beside* `ts_ns`, converted once per run by measuring the offset between
the two clocks directly (`events.Clock`, stage 3).

The payoff shows up in two places you have already relied on: process
identity uses `task->start_time` (monotonic, set once at fork, survives
exec), and `--at` on `query_graph.py` takes monotonic seconds because that
is the clock the graph stores.

### Read

`docs/CONCEPTS.md` §8 for the project's own treatment, including why
`/proc/stat`'s `btime` was *not* used.

---

## 1.6 The C you need

You do not need deep C. You need these six things, precisely:

1. **Structs are layout.** Field order is memory order; the compiler
   inserts padding so each field sits on its natural alignment. Our records
   are structs shared with Python, so padding is part of the contract — get
   it wrong and every field after the mistake is garbage.
2. **`u8/u16/u32/u64`, `s32`** — fixed-width types. Never `int` in a record:
   its size is not guaranteed to match what Python expects.
3. **Pointers are addresses**, and an address is only meaningful in one
   address space. A pointer from a syscall argument points into *user*
   memory; a pointer inside `task_struct` points into *kernel* memory.
4. **`probe_read` and friends** are how BPF touches memory it does not own.
   Every call can fail (the page may not be present, the address may be
   garbage) and **every call's return value must be checked**. Unchecked
   reads are how a monitor invents data.
5. **`#ifdef`** — compile-time switches. Our feature flags (`FILE_IDENTITY`,
   `SOCKET_TYPE`, `KERNEL_EXEC_PATH`) are `#define`s prepended to the source
   at runtime by `monitor.bpf_text()`, so a refused feature means a
   *different program* was compiled, not a disabled branch.
6. **Macros as text substitution.** `COMMON_FIELDS` is a macro that expands
   into the same field list in three structs, which is how all three share a
   prefix that one function can fill through a cast.

### Experiment `[laptop]`

See padding bite, in six lines:

```bash
cat > /tmp/pad.c <<'EOF'
#include <stdio.h>
#include <stdint.h>
struct bad  { uint8_t a; uint64_t b; uint8_t c; };
struct good { uint64_t b; uint8_t a; uint8_t c; };
int main(void){ printf("bad=%zu good=%zu\n", sizeof(struct bad), sizeof(struct good)); }
EOF
gcc -o /tmp/pad /tmp/pad.c && /tmp/pad
```

24 versus 16 bytes, same three fields. Now look at `struct net_t` and ask
why `u16 sock_type; u16 pad;` sit where they do.

---

## 1.7 The Python you need

Six things again:

1. **`ctypes.Structure`** — Python's way of describing a C layout. Our
   `RawEvent`/`RawNet` are *mirrors*: if the C struct changes and the mirror
   does not, decoding silently produces nonsense. This is why a test
   compiles both and compares.
2. **`namedtuple`** — immutable, tuple-cheap records. We copy ctypes data
   into namedtuples immediately, because BCC's buffer is only valid during
   the callback.
3. **`__slots__`** — tells Python not to give each instance a `__dict__`.
   On `ProcessNode`, with hundreds of thousands of instances, this is the
   difference between a sane memory footprint and an absurd one.
4. **`OrderedDict` as an LRU** — `move_to_end()` on access,
   `popitem(last=False)` to evict the oldest. Both file and endpoint caps
   use exactly this.
5. **`collections.deque`** — O(1) pops from the left; the BFS queue in both
   walks.
6. **Closures** — the `emit()` helper inside each walk captures `result`,
   `listed` and `queue` from the enclosing scope. Note the
   `depth=depth` default argument: it binds the *current* depth at
   definition time rather than looking it up later. Know why that matters.

### Experiment `[laptop]`

```bash
python3 -c "
import ctypes
class A(ctypes.Structure): _fields_=[('a',ctypes.c_uint8),('b',ctypes.c_uint64)]
class B(ctypes.Structure): _fields_=[('b',ctypes.c_uint64),('a',ctypes.c_uint8)]
print(ctypes.sizeof(A), ctypes.sizeof(B), A.b.offset, B.a.offset)"
```

Same lesson as the C experiment, from the other side of the contract.

---

## Self-check

Answer out loud, then compare.

1. Why does our code use tracepoints rather than kprobes, and what do we
   lose by that choice?
2. Someone says "eBPF doesn't allow loops." What is the accurate answer for
   kernel 5.4?
3. `struct event_t` is 392 bytes and the stack limit is 512. Why can't the
   exec-enter path just use a stack variable?
4. What stops a second probe on the same CPU from corrupting our per-CPU
   scratch slot mid-use?
5. Two records are written by the same process microseconds apart. Can
   userspace read them out of order? Why?
6. Why is every timestamp in the graph monotonic rather than wall-clock, and
   where does wall-clock time enter the system?
7. A tracepoint field is declared `__data_loc char[]`. What does that mean
   and what does our code have to do about it?
8. Why must the return value of every `probe_read` be checked?

<details>
<summary>Answers</summary>

1. Tracepoints are a declared, stable ABI; kprobes bind to internal
   function names and signatures that change between kernels. We lose
   reach: anything without a tracepoint (a socket's local port, for
   instance) is unavailable until we add another mechanism. The gain is that
   the same source runs unmodified across kernel versions.
2. Unbounded loops are rejected. Bounded loops have been supported since
   5.3, so on 5.4 a loop whose bound the verifier can *prove* is fine. Our
   constant bounds serve that provability and the verifier's complexity
   budget, not a blanket ban.
3. Because the exec-enter path needs `event_t` (392) and `arg_t` (152)
   live at the same time: 544 > 512, so the verifier rejects the program.
   Per-CPU array memory is map memory, not stack, so it escapes the limit —
   and one slot per CPU needs no locking.
4. The kernel's per-CPU `bpf_prog_active` counter: it will not run a second
   tracing program on a CPU while one is active, so the nested event is
   dropped rather than interleaved.
5. Yes. There is one ring buffer per CPU and no global sequence number;
   if the process migrated between CPUs (which `execve` does deliberately),
   its records sit in different rings and can be drained in either order.
6. Monotonic time never jumps, so durations and ordering survive NTP steps
   and timezone changes — and `task->start_time`, which process identity
   depends on, is monotonic. Wall-clock appears only in the JSONL log's
   `time` field, converted once per run via a measured offset.
7. The field is variable-length and stored elsewhere in the record; the
   int holds an offset (and length) rather than the data. Our code has to
   decode that offset and read the string from there, which is why the test
   harness models it as `int data_loc_filename`.
8. Because the memory may not be readable — unmapped page, bad address,
   user memory paged out. An unchecked read leaves the destination
   untouched or partially filled, and the monitor would then report
   whatever was in that buffer as though the kernel had said it. That is
   how a monitor invents evidence.

</details>

---

Next: `02_KERNEL_C.md` — all 794 lines, in three passes.
