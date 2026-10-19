#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║       Process + File Event Monitor  —  ESE-P15 (v2)              ║
║   eBPF-based real-time process + file-access tracker              ║
║   Ashish Rana | Sr. No. 26179 | M.Tech ESE | IISc Bangalore       ║
╚══════════════════════════════════════════════════════════════════╝

v2 changes from your working v1:
  - Unified event schema with a "type" discriminator (EVENT_EXEC / EVENT_OPEN)
    instead of one struct per hook — this is the pattern that scales as you
    add more hooks (connect, mmap, ...) without multiplying perf buffers.
  - New hook: sys_enter_openat (file access), not sys_enter_open — see the
    comment above that hook for why.
  - Event struct now lives in a per-CPU BPF array ("scratch space") instead
    of on the eBPF stack — see the comment above BPF_PERCPU_ARRAY for why
    this matters as your struct grows.

Run exactly as before:
  sudo python3 process_monitor_v2.py
"""

import os
import sys
import signal
import ctypes
import json
import argparse
from datetime import datetime

try:
    from bcc import BPF
except ImportError:
    print("\n[ERROR] BCC (bpfcc) not installed.")
    print("  Run: sudo apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r)")
    sys.exit(1)

TASK_COMM_LEN = 16
MAX_FILENAME  = 256
LOG_FILE      = "process_monitor.log"
event_count   = 0

# Own PID, captured once at module load. Without this, every lineage
# lookup this script performs (open(f"/proc/{pid}/status")) is itself an
# openat() syscall, caught by our own hook, which triggers another
# lineage lookup, which triggers another event — an unbounded
# self-referential feedback loop. See Engineering Journal row 5.
SELF_PID = os.getpid()

RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
CYAN, YELLOW, GREEN, RED = "\033[96m", "\033[93m", "\033[92m", "\033[91m"

# Must match the #define values in the C code below — used to decide
# how to print/log an event once it reaches Python.
EVENT_EXEC = 0
EVENT_OPEN = 1
EVENT_NAMES = {EVENT_EXEC: "EXEC", EVENT_OPEN: "OPEN"}

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_FILENAME 256
#define EVENT_EXEC 0
#define EVENT_OPEN 1

// Same struct for every hook now. "type" tells Python which kind of
// event this is. Every hook fills the fields it can and leaves the
// rest zeroed — cheap, and keeps one perf buffer and one Python
// handler instead of one pair per hook.
struct event_t {
    u32  type;
    u32  pid;
    u32  ppid;
    u32  uid;
    u32  gid;
    u32  pad;
    u64  ts_ns;
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
    char filename[MAX_FILENAME];
};

BPF_PERF_OUTPUT(events);

// ── Scratch space ────────────────────────────────────────────────────
// eBPF programs get a hard 512-byte stack per program (verifier-enforced,
// not a suggestion). struct event_t above is already ~320 bytes; add a
// couple more fields later (source IP, port, flags for a future connect
// hook) and a stack-local "struct event_t ev = {};" starts getting risky
// — the verifier will reject the program outright if it doesn't fit.
//
// The standard fix, used throughout BCC/Cilium/Falco: put the struct in
// a one-element per-CPU array map instead of on the stack. "Per-CPU"
// means every CPU core gets its own private copy, so two cores handling
// two syscalls at once never trample each other's data — you get a safe
// scratch buffer without any locking.
BPF_PERCPU_ARRAY(scratch, struct event_t, 1);

static struct event_t *get_scratch() {
    u32 zero = 0;
    return scratch.lookup(&zero);
}

// Fills in the fields common to every event type: pid, uid/gid, parent
// info, timestamp, current process name. Every hook calls this first,
// then fills in whatever is specific to that syscall.
static void fill_common(struct event_t *ev) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->pid = pid_tgid >> 32;
    u64 uid_gid = bpf_get_current_uid_gid();
    ev->uid = uid_gid & 0xFFFFFFFF;
    ev->gid = uid_gid >> 32;
    ev->ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    struct task_struct *parent = NULL;
    bpf_probe_read(&parent, sizeof(parent), &task->real_parent);
    if (parent) {
        bpf_probe_read(&ev->ppid, sizeof(ev->ppid), &parent->tgid);
        bpf_probe_read_str(&ev->pcomm, sizeof(ev->pcomm), parent->comm);
    }
}

// Hook 1: process creation (unchanged behaviour from v1, rewritten to
// use the shared scratch struct and fill_common() helper).
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t *ev = get_scratch();
    if (!ev) return 0;               // verifier requires this null check
                                       // even though lookup() can't really
                                       // fail for a map we just declared

    ev->type = EVENT_EXEC;
    fill_common(ev);
    bpf_probe_read_str(&ev->filename, sizeof(ev->filename), (void *)args->filename);

    events.perf_submit(args, ev, sizeof(*ev));
    return 0;
}

// Hook 2: file access — NEW.
//
// Why openat and not open: glibc's open() wrapper has called the
// openat() syscall under the hood for years now (openat just adds a
// directory-fd argument; ordinary open() passes the special value
// AT_FDCWD, meaning "relative to current directory"). sys_enter_open
// simply never fires for most real programs on a modern system —
// hooking it would silently miss almost everything. This is exactly
// the kind of gap that only shows up once you actually test a hook
// against real traffic, which is why testing against Atomic Red Team
// next matters more than reading further docs right now.
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct event_t *ev = get_scratch();
    if (!ev) return 0;

    ev->type = EVENT_OPEN;
    fill_common(ev);
    // args->filename here is the *second* argument to openat(int dirfd,
    // const char *pathname, int flags, ...) — the tracepoint format
    // file (/sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format)
    // is where that field name comes from; every tracepoint publishes one
    // of these, worth a `cat` on your VM once to see for yourself.
    bpf_probe_read_str(&ev->filename, sizeof(ev->filename), (void *)args->filename);

    events.perf_submit(args, ev, sizeof(*ev));
    return 0;
}
"""

class Event(ctypes.Structure):
    _fields_ = [
        ("type",     ctypes.c_uint32),
        ("pid",      ctypes.c_uint32),
        ("ppid",     ctypes.c_uint32),
        ("uid",      ctypes.c_uint32),
        ("gid",      ctypes.c_uint32),
        ("pad",      ctypes.c_uint32),
        ("ts_ns",    ctypes.c_uint64),
        ("comm",     ctypes.c_char * TASK_COMM_LEN),
        ("pcomm",    ctypes.c_char * TASK_COMM_LEN),
        ("filename", ctypes.c_char * MAX_FILENAME),
    ]

def get_boot_epoch():
    try:
        with open("/proc/stat") as f:
            for line in f:
                if line.startswith("btime"):
                    return int(line.split()[1])
    except Exception:
        pass
    return 0

BOOT_EPOCH = get_boot_epoch()

def ns_to_timestamp(ts_ns):
    abs_sec = BOOT_EPOCH + (ts_ns / 1_000_000_000)
    return datetime.fromtimestamp(abs_sec).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

def get_proc_info(pid):
    try:
        with open(f"/proc/{pid}/status") as f:
            info = {}
            for line in f:
                if ":" in line:
                    k, v = line.split(":", 1)
                    info[k.strip()] = v.strip()
            return info.get("Name", "?"), int(info.get("PPid", 0))
    except (FileNotFoundError, PermissionError, ValueError):
        return "?", 0

# pid -> (comm, ppid). Populated two ways: (a) unconditionally, from
# kernel-captured event fields (comm/ppid/pcomm — atomic at syscall time,
# zero /proc calls, zero TOCTOU race), for hop 0 and hop 1 of every event
# we process; (b) opportunistically, from /proc, the first time we DO
# have to fall back to it for hop 2+. Long-lived ancestors (shell, sshd,
# systemd) get resolved once this way and reused for every later event
# under them, instead of re-walking /proc from scratch each time.
pid_cache = {}

def _resolve(pid):
    cached = pid_cache.get(pid)
    if cached and cached[1] is not None:
        return cached
    name, ppid = get_proc_info(pid)
    if name != "?":
        pid_cache[pid] = (name, ppid)
        return name, ppid
    # /proc lookup failed (process already exited). If we at least have a
    # cached name — even without a resolved parent — prefer it over a
    # flat "?": this is what eliminates the hop-0/hop-1 collapse from row
    # 12, since those two are always seeded before this function is ever
    # called for them.
    if cached:
        return cached[0], 0
    return "?", 0

def get_lineage(ev, comm, pcomm):
    """
    Build the ancestry chain for the process in `ev`. Unlike the original
    version (which took only a pid and walked /proc from scratch — see
    Engineering Journal row 12), this seeds the first two hops from data
    the kernel already gave us, then walks /proc (via the cache) for
    everything above that.
    """
    pid_cache[ev.pid] = (comm, ev.ppid)
    existing_parent = pid_cache.get(ev.ppid)
    if existing_parent is None or existing_parent[1] is None:
        pid_cache[ev.ppid] = (pcomm, existing_parent[1] if existing_parent else None)

    chain, current, visited = [], ev.pid, set()
    while current > 0 and current not in visited:
        visited.add(current)
        name, ppid = _resolve(current)
        chain.append((current, name))
        if current == 1:
            break
        current = ppid
    chain.reverse()
    return chain

def format_lineage_string(chain):
    if not chain:
        return "unknown"
    return " → ".join(f"{name}({p})" for p, name in chain)

def make_lost_handler():
    # BCC calls this automatically whenever the perf ring buffer overflows
    # — i.e. events arrived faster than Python could drain them, and some
    # were dropped before we ever saw them. Without this registered, event
    # loss is silent and invisible; with it, we get an exact count.
    # This directly tests whether missing events in a run were ever
    # generated and lost, vs. never generated at all.
    def handle_lost(count):
        print(f"{RED}[LOST EVENTS] {count} events dropped "
              f"— ring buffer overflowed before Python could read them.{RESET}")
    return handle_lost

def make_event_handler(log_file, name_filter, type_filter):
    global event_count
    log_f = open(log_file, "a", buffering=1)

    def handle_event(cpu, data, size):
        global event_count
        ev = ctypes.cast(data, ctypes.POINTER(Event)).contents

        # Drop our own syscalls before doing anything else — in particular
        # before the lineage lookup below, which is itself the source of
        # the self-referential events this check exists to prevent.
        if ev.pid == SELF_PID:
            return

        etype    = EVENT_NAMES.get(ev.type, "UNKNOWN")
        ts       = ns_to_timestamp(ev.ts_ns)
        comm     = ev.comm.decode("utf-8", errors="replace").strip("\x00")
        pcomm    = ev.pcomm.decode("utf-8", errors="replace").strip("\x00")
        filename = ev.filename.decode("utf-8", errors="replace").strip("\x00")
        lineage  = format_lineage_string(get_lineage(ev, comm, pcomm))

        if name_filter and name_filter.lower() not in comm.lower():
            return
        if type_filter and etype != type_filter.upper():
            return

        event_count += 1
        color = GREEN if etype == "EXEC" else CYAN

        print(f"\n{BOLD}{color}{'━' * 65}{RESET}")
        print(f"{BOLD}  EVENT #{event_count:<5}  [{etype}]  [{ts}]{RESET}")
        print(f"{color}{'━' * 65}{RESET}")
        print(f"  {YELLOW}Process  :{RESET}  {BOLD}{comm}{RESET}  (PID {ev.pid}, parent {pcomm}/{ev.ppid})")
        print(f"  {YELLOW}Path     :{RESET}  {filename}")
        print(f"  {YELLOW}Lineage  :{RESET}  {lineage}")

        entry = {
            "event_id": event_count, "type": etype, "timestamp": ts,
            "pid": ev.pid, "ppid": ev.ppid, "uid": ev.uid, "gid": ev.gid,
            "name": comm, "parent_name": pcomm, "path": filename,
            "lineage": lineage,
        }
        try:
            log_f.write(json.dumps(entry) + "\n")
        except ValueError:
            # Defensive only: with the new shutdown flow (close happens
            # after the poll loop truly exits, not from inside the signal
            # handler) this window shouldn't occur anymore, but it's cheap
            # insurance against a closed-file write during teardown.
            pass

    return handle_event, log_f

# Set by the signal handler, checked by the polling loop in main().
# This is the fix for the "Ctrl+C doesn't respond under load" issue
# (Engineering Journal row 11): perf_buffer_poll() only returns control
# to Python when it runs out of events to drain, so under a sustained
# flood it may never return at all within a single call. A plain
# sys.exit() inside the handler doesn't help, because the handler
# itself only runs when Python regains control — same problem either
# way. The real fix is to (a) shrink the poll timeout so Python gets
# control back more often even when the buffer is busy, and (b) check
# a flag every time we do get control, instead of trying to exit
# directly from inside the handler.
shutdown_requested = False

def setup_signal_handler():
    def on_signal(sig, frame):
        global shutdown_requested
        # Diagnostic only — tells us WHEN the handler actually ran relative
        # to when you pressed Ctrl+C, using the real wall clock (not the
        # kernel-boot-relative ts_ns used elsewhere in this file). Keep
        # this while you're still confirming the fix; safe to remove once
        # you've verified it prints immediately even under load.
        print(f"\n[DIAGNOSTIC] signal handler fired at {datetime.now().strftime('%H:%M:%S.%f')}")
        shutdown_requested = True
    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

def main():
    parser = argparse.ArgumentParser(description="eBPF Process+File Monitor v2 — ESE-P15")
    parser.add_argument("--filter", "-f", default="", help="filter by process name")
    parser.add_argument("--type", "-t", default="", choices=["", "exec", "open"], help="show only EXEC or OPEN events")
    parser.add_argument("--logfile", "-l", default=LOG_FILE)
    args = parser.parse_args()

    if os.geteuid() != 0:
        print(f"{RED}[ERROR]{RESET} needs root — run with sudo")
        sys.exit(1)

    print(f"{BOLD}{CYAN}Loading eBPF program (execve + openat hooks)...{RESET}")
    bpf = BPF(text=BPF_PROGRAM)

    handler, log_f = make_event_handler(args.logfile, args.filter, args.type)
    lost_handler = make_lost_handler()
    bpf["events"].open_perf_buffer(handler, page_cnt=64, lost_cb=lost_handler)
    setup_signal_handler()

    print(f"{GREEN}●{RESET} Hooked execve + openat. Log: {args.logfile}. Ctrl+C to stop.\n")
    # timeout=50 (was 100): halving the poll window means Python regains
    # control roughly twice as often even while the buffer stays busy,
    # so shutdown_requested gets checked sooner under sustained load.
    # It doesn't eliminate the worst case (a single very dense 50ms
    # window can still delay us a little) but it meaningfully shrinks it,
    # and combined with the flag check below, Ctrl+C during a normal
    # burst (thousands, not tens of thousands, of events/sec) now
    # responds within a poll cycle or two instead of hanging indefinitely.
    while not shutdown_requested:
        try:
            bpf.perf_buffer_poll(timeout=50)
        except KeyboardInterrupt:
            break

    log_f.close()
    print(f"\n\n{YELLOW}Stopped. {event_count} events captured. Logs: {args.logfile}{RESET}\n")

if __name__ == "__main__":
    main()
