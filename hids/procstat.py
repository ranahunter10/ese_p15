"""
procstat.py — everything that reads /proc.

/proc is a view the kernel generates on demand: reading /proc/<pid>/stat
runs kernel code that formats that task's fields as text. It is only used
here for two things the eBPF hooks cannot give us:

  1. a snapshot of processes that ALREADY existed when the monitor started
     (the hooks only see events from now on), and
  2. periodic CPU / memory figures for the top-style view.

Per-event lineage no longer touches /proc at all (that was the v2 race).
"""

import os
import time

CLK_TCK = os.sysconf("SC_CLK_TCK")          # scheduler ticks per second (usually 100)
PAGE_KB = os.sysconf("SC_PAGE_SIZE") // 1024


def parse_stat(text):
    """Parse /proc/<pid>/stat.

    The 2nd field is the command name in parentheses, and it may itself
    contain spaces or ')' — e.g. "(Web Content)" or "(a) b)". Splitting on
    spaces breaks on those; the robust way is to cut at the LAST ')'.
    Field numbers below follow `man 5 proc` (1-based).
    """
    lpar = text.index("(")
    rpar = text.rindex(")")
    pid = int(text[:lpar])
    comm = text[lpar + 1:rpar]
    rest = text[rpar + 2:].split()
    # rest[0] is field 3 (state), so field N is rest[N - 3]
    return {
        "pid": pid,
        "comm": comm,
        "state": rest[0],
        "ppid": int(rest[1]),
        "utime": int(rest[11]),       # field 14
        "stime": int(rest[12]),       # field 15
        "starttime": int(rest[19]),   # field 22, ticks after boot
        "rss_pages": int(rest[21]),   # field 24
    }


def read_stat(pid, root="/proc"):
    try:
        with open("%s/%d/stat" % (root, pid)) as f:
            return parse_stat(f.read())
    except (OSError, ValueError, IndexError):
        # Process vanished between listing and reading, or permissions.
        return None


def read_uid(pid, root="/proc"):
    try:
        return os.stat("%s/%d" % (root, pid)).st_uid
    except OSError:
        return None


def boot_minus_mono_ns():
    """CLOCK_BOOTTIME - CLOCK_MONOTONIC = total time spent suspended.

    /proc starttime is counted on the boot clock; the kernel's
    task->start_time (what the eBPF events carry) on the monotonic clock.
    """
    if not hasattr(time, "CLOCK_BOOTTIME"):
        return 0
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME) - \
        time.clock_gettime_ns(time.CLOCK_MONOTONIC)


def scan(root="/proc"):
    """Snapshot of every process visible right now.

    start_ns is an ESTIMATE on the monotonic clock: tick resolution (10 ms)
    and wrong by any suspend that happened after the process started. The
    graph marks these nodes start_exact=False and replaces the estimate with
    the kernel's exact value the first time that process produces an event.
    """
    offset = boot_minus_mono_ns() if root == "/proc" else 0
    out = []
    try:
        entries = os.listdir(root)
    except OSError:
        return out
    for name in entries:
        if not name.isdigit():
            continue
        st = read_stat(int(name), root)
        if st is None:
            continue
        start_ns = st["starttime"] * 1000000000 // CLK_TCK - offset
        out.append({
            "pid": st["pid"], "ppid": st["ppid"], "comm": st["comm"],
            "uid": read_uid(st["pid"], root), "start_ns": max(start_ns, 0),
        })
    return out


class ResourceSampler:
    """CPU% the way `top` computes it: ticks used / ticks elapsed.

    100% = one full core. Keyed by graph node key, so a reused PID never
    inherits the previous process's tick counter.
    """

    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.prev = {}   # node key -> (ticks, when, starttime)

    def sample(self, nodes, root="/proc"):
        now = self.clock()
        live = set()
        for node in nodes:
            if not node.alive:
                continue
            st = read_stat(node.pid, root)
            if st is None:
                continue
            live.add(node.key)
            ticks = st["utime"] + st["stime"]
            node.rss_kb = st["rss_pages"] * PAGE_KB
            prev = self.prev.get(node.key)
            if prev is not None and prev[2] != st["starttime"]:
                prev = None      # PID now belongs to a different process
            if prev is not None and now > prev[1]:
                dt = now - prev[1]
                node.cpu_percent = max(0.0, (ticks - prev[0]) / CLK_TCK / dt * 100.0)
            self.prev[node.key] = (ticks, now, st["starttime"])
        for key in list(self.prev):
            if key not in live:
                del self.prev[key]
