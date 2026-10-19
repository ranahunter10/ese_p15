#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║   ESE-P15 HIDS — process / file provenance monitor                ║
║   Ashish Rana | Sr. No. 26179 | M.Tech ESE | IISc Bangalore       ║
╚══════════════════════════════════════════════════════════════════╝

Run from the project root (it is a package):
    sudo python3 -m hids.monitor                       # live top + tree
    sudo python3 -m hids.monitor --mode print -f cat   # per-event lines
    sudo python3 -m hids.monitor --mode quiet --duration 30 \
         --stats-json runs/s.json --snapshot runs/g.json
    sudo python3 -m hids.monitor --hooks open --sink count --no-log   # cost probe

Pipeline (docs/ARCHITECTURE.md walks through every step):
    kernel hooks (bpf/monitor.bpf.c)
      -> per-CPU perf ring buffers
      -> events.decode()            raw bytes -> Event / Arg
      -> processor.EventProcessor   exec assembly, filters, JSONL log
      -> graph.ProcessGraph         in-memory provenance graph
      -> view.render()              top + pstree screen
"""

import argparse
import ctypes
import json
import os
import resource
import signal
import sys
import time

from . import __version__, procstat, replay as replay_mod
from .events import Clock, decode
from .graph import ProcessGraph
from .processor import EventProcessor
from .view import (draw, enter_fullscreen, leave_fullscreen, make_printer,
                   render, screen_rows)

HERE = os.path.dirname(os.path.abspath(__file__))
BPF_SOURCE = os.path.join(HERE, "bpf", "monitor.bpf.c")

HOOK_TRACEPOINTS = {
    "exec": [("syscalls", "sys_enter_execve"), ("syscalls", "sys_enter_execveat"),
             ("sched", "sched_process_exec")],
    "open": [("syscalls", "sys_enter_openat"), ("syscalls", "sys_exit_openat"),
             ("syscalls", "sys_enter_open"), ("syscalls", "sys_exit_open")],
    "exit": [("sched", "sched_process_exit")],
    # 6 syscall tracepoints: outbound connect, plus inbound accept AND
    # accept4 — glibc's accept() and Python's socket.accept() issue
    # different syscalls, so hooking one leaves half the servers invisible.
    "net": [("syscalls", "sys_enter_connect"), ("syscalls", "sys_exit_connect"),
            ("syscalls", "sys_enter_accept"), ("syscalls", "sys_exit_accept"),
            ("syscalls", "sys_enter_accept4"), ("syscalls", "sys_exit_accept4")],
}
ALL_HOOKS = ("exec", "open", "exit", "net")

# Optional features, most capable first. If the compiler or verifier refuses
# a combination, the next one is tried; the stats record which one ran.
FEATURE_SETS = [
    ("KERNEL_EXEC_PATH", "FILE_IDENTITY", "SOCKET_TYPE"),
    ("KERNEL_EXEC_PATH", "FILE_IDENTITY"),
    ("FILE_IDENTITY",),
    ("KERNEL_EXEC_PATH",),
    (),
]

shutdown_requested = False


def _on_signal(sig, frame):
    # Only set a flag; the main loop checks it between polls (Journal row 11).
    global shutdown_requested
    shutdown_requested = True


def bpf_text(self_tgid, hooks=ALL_HOOKS, features=()):
    head = ["#define SELF_TGID %d" % self_tgid]
    head += ["#define HOOK_%s 1" % h.upper() for h in hooks]
    head += ["#define %s 1" % f for f in features]
    with open(BPF_SOURCE) as f:
        return "\n".join(head) + "\n" + f.read()


def parse_hooks(text):
    hooks = tuple(h.strip() for h in text.split(",") if h.strip())
    bad = [h for h in hooks if h not in ALL_HOOKS]
    if bad or not hooks:
        raise argparse.ArgumentTypeError(
            "hooks must be a comma list of " + ",".join(ALL_HOOKS))
    return tuple(h for h in ALL_HOOKS if h in hooks)


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="ESE-P15 eBPF provenance monitor v%s" % __version__)
    p.add_argument("--mode", choices=["view", "print", "quiet"], default="view",
                   help="live screen, per-event lines, or nothing on screen")
    p.add_argument("--filter", "-f", default="", help="process name substring (log/print only)")
    p.add_argument("--type", "-t", default="",
                   choices=["", "exec", "exec_failed", "open", "exit", "connect", "accept"])
    p.add_argument("--logfile", "-l", default="",
                   help="JSONL log (default: runs/run-<timestamp>.jsonl, new file per run)")
    p.add_argument("--no-log", action="store_true")
    p.add_argument("--hooks", type=parse_hooks, default=ALL_HOOKS,
                   help="which hook groups to attach: exec,open,exit,net (default all)")
    p.add_argument("--sink", choices=["graph", "count"], default="graph",
                   help="count = only count records (measures kernel-side cost)")
    p.add_argument("--features", choices=["auto", "none"], default="auto",
                   help="auto = try kernel exec path + inode identity, fall back if refused")
    p.add_argument("--pages", type=int, default=64,
                   help="perf ring buffer pages PER CPU (power of two)")
    p.add_argument("--batch-ms", type=float, default=0,
                   help="sleep between polls so records batch up (fewer wakeups)")
    p.add_argument("--duration", type=float, default=0, help="stop after N seconds")
    p.add_argument("--stats-json", default="", help="write run statistics here on exit")
    p.add_argument("--snapshot", default="", help="write the graph as JSON on exit")
    p.add_argument("--max-nodes", type=int, default=0,
                   help="evict oldest EXITED processes beyond this many (0 = keep all)")
    p.add_argument("--max-files", type=int, default=200000,
                   help="evict least recently used files beyond this many (0 = keep all)")
    # 25 000, not the 200 000 the file cap uses, and the number is measured
    # rather than chosen: an EndpointNode costs ~380 bytes with one access
    # and ~2.4 KB once it has twenty, so 25 000 is ~9 MB typical and ~59 MB
    # worst case. At 200 000 it would be 76-476 MB, which on the 2 vCPU test
    # VM is larger than the whole monitor. See docs/ARCHITECTURE.md §7.
    p.add_argument("--max-endpoints", type=int, default=25000,
                   help="evict least recently used network peers beyond this many "
                        "(0 = keep all). Inbound peers are created by whoever "
                        "connects, so this bound is not under our control")
    p.add_argument("--refresh", type=float, default=1.0, help="screen refresh seconds")
    p.add_argument("--no-bootstrap", action="store_true",
                   help="don't snapshot already-running processes at startup")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--record-raw", default="",
                   help="also write every kernel record, byte for byte, to this "
                        "file (replayable with --replay)")
    p.add_argument("--replay", default="",
                   help="rebuild the graph from a --record-raw file instead of "
                        "the kernel: no BPF, no root, deterministic")
    a = p.parse_args(argv)
    if a.replay and a.record_raw:
        p.error("--replay reads a recording; --record-raw writes one. Pick one.")
    if a.replay and a.sink == "count":
        # --sink count exists to measure kernel-side cost by NOT building a
        # graph. Replaying into it would report a record count and discard
        # the only thing a replay produces.
        p.error("--replay needs --sink graph")
    if a.pages <= 0 or a.pages & (a.pages - 1):
        p.error("--pages must be a power of two")
    if a.batch_ms < 0 or a.batch_ms > 1000:
        p.error("--batch-ms must be between 0 and 1000")
    # A negative cap silently destroyed the history the monitor exists to
    # collect (v3.5i report W2-B5): `--max-files -5` makes the eviction
    # condition `len(files) > -5` permanently true, so every file node was
    # dropped the moment it was created, with no error and no warning. Zero
    # keeps everything, which is the documented meaning and stays valid.
    for flag, value in (("--max-nodes", a.max_nodes),
                        ("--max-files", a.max_files),
                        ("--max-endpoints", a.max_endpoints)):
        if value < 0:
            p.error("%s must be >= 0 (0 = unlimited)" % flag)
    if a.sink == "count":
        a.no_log, a.mode = True, "quiet"
    return a


def default_logfile():
    os.makedirs("runs", exist_ok=True)
    return os.path.join("runs", time.strftime("run-%Y%m%d-%H%M%S.jsonl"))


def cpu_seconds():
    r = resource.getrusage(resource.RUSAGE_SELF)
    return r.ru_utime + r.ru_stime


def load_bpf(BPF, hooks, features_mode, log):
    """Compile + load, falling back through FEATURE_SETS. Returns (bpf,
    features, [(features, error)...])."""
    sets = FEATURE_SETS if features_mode == "auto" else [()]
    failures = []
    for feats in sets:
        try:
            return BPF(text=bpf_text(os.getpid(), hooks, feats)), feats, failures
        except Exception as e:                      # noqa: BLE001
            msg = str(e).strip().splitlines()
            failures.append((feats, msg[-1] if msg else repr(e)))
            log("  feature set %s refused: %s" % (list(feats) or "[]", failures[-1][1]))
    raise SystemExit("[ERROR] eBPF program could not be loaded with any feature set")


def main(argv=None):
    global shutdown_requested
    args = parse_args(argv)
    # A replay reads a file. It attaches nothing, so it needs neither root nor
    # BCC nor the tracepoints the recording was made with -- which is what
    # lets the determinism test run unprivileged, and lets a recording from
    # the VM be replayed anywhere.
    BPF = None
    if args.replay:
        # Fail before anything is set up: pointing --replay at the JSONL log
        # is the easy mistake, and it should cost one line, not a traceback
        # after a graph and a log file have been created.
        try:
            replay_mod.peek_header(args.replay)
        except (OSError, ValueError) as e:
            sys.exit("[ERROR] %s" % e)
    if not args.replay:
        if os.geteuid() != 0:
            sys.exit("[ERROR] needs root: sudo python3 -m hids.monitor")
        try:
            from bcc import BPF
        except ImportError:
            sys.exit("[ERROR] BCC missing: sudo apt install bpfcc-tools python3-bpfcc "
                     "linux-headers-$(uname -r)")

    def say(msg):
        # flush: stdout may be a file (vm_validation.sh waits for these lines)
        print(msg, flush=True)

    if not args.replay:
        missing = [c + ":" + e for h in args.hooks for c, e in HOOK_TRACEPOINTS[h]
                   if not BPF.tracepoint_exists(c, e)]
        if missing:
            sys.exit("[ERROR] tracepoints not available on this kernel: "
                     + ", ".join(missing))

    # Handlers first, so Ctrl+C during the compile is a clean stop.
    shutdown_requested = False
    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    tty = sys.stdout.isatty()
    color = not args.no_color and tty
    mode = args.mode if (args.mode != "view" or tty) else "quiet"

    log_path = "" if args.no_log else (args.logfile or default_logfile())
    log_f = None
    if log_path:
        d = os.path.dirname(log_path)
        if d:
            os.makedirs(d, exist_ok=True)
        # "w": one run per file (Journal row 17)
        log_f = open(log_path, "w", buffering=1 if mode == "print" else 1 << 20)

    clock = Clock()
    # Replay has to be reproducible, and Clock.offset is sampled from the wall
    # at construction purely to label log lines. Pinning it makes the log text
    # of two replays of one recording identical, so a diff means a real
    # difference.
    vclock = replay_mod.VirtualClock() if args.replay else None
    if vclock is not None:
        clock.offset = 0.0
    graph = ProcessGraph(max_nodes=args.max_nodes or None,
                         max_files=args.max_files or None,
                         max_endpoints=args.max_endpoints or None)
    proc = EventProcessor(graph, clock, log_file=log_f,
                          printer=make_printer(color) if mode == "print" else None,
                          name_filter=args.filter, type_filter=args.type,
                          mono=vclock or time.monotonic)
    count = [0]

    bpf = recorder = None
    features, refused, compile_s = [], [], 0.0
    if args.replay:
        say("Replaying %s (no kernel, no BPF)..." % args.replay)
    else:
        say("Compiling and loading eBPF program (hooks: %s)..." % ",".join(args.hooks))
        t0 = time.monotonic()
        bpf, features, refused = load_bpf(BPF, args.hooks, args.features, say)
        compile_s = time.monotonic() - t0

        if args.record_raw:
            recorder = replay_mod.RawRecorder(args.record_raw)
        # The callback is chosen once, here, rather than branching per record:
        # recording copies the payload (string_at) and that copy costs more
        # than parsing it does, so it must not be in the path when recording
        # is off. Tracee and Falco likewise select their path at setup.
        if args.sink == "count":
            def on_record(cpu, data, size):
                count[0] += 1
        elif recorder is not None:
            def on_record(cpu, data, size):
                # Decode from the bytes that were written, not from the
                # kernel pointer, so the recording and the live graph are
                # provably built from the same bytes.
                payload = ctypes.string_at(data, size)
                recorder.write(payload)
                proc.handle(decode(payload, size))
        else:
            def on_record(cpu, data, size):
                proc.handle(decode(data, size))
        on_lost = proc.handle_lost
        bpf["events"].open_perf_buffer(on_record, page_cnt=args.pages, lost_cb=on_lost)

        # Snapshot AFTER hooks are live, so nothing falls in between. Never on
        # replay: it would inject THIS machine's current processes into a
        # replay of a past run.
        if not args.no_bootstrap and args.sink == "graph":
            procs = procstat.scan()
            boot_ts = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
            graph.bootstrap(procs, boot_ts)
            if recorder is not None:
                # Beside the recording, so a replay can start from the same
                # population the live run did instead of an almost empty tree.
                replay_mod.write_bootstrap(args.record_raw, procs, boot_ts)

    sampler = procstat.ResourceSampler()
    cpu0, wall0 = cpu_seconds(), time.monotonic()
    last_tick = last_draw = wall0
    batch_s = args.batch_ms / 1000.0
    replay_undecodable = 0
    if not args.replay:
        say("Hooks attached. features: %s  log: %s  mode: %s  Ctrl+C to stop."
            % (",".join(features) or "none", log_path or "off", mode))

    fullscreen = (mode == "view" and tty)
    if fullscreen:
        enter_fullscreen()

    crash = None
    try:
        if args.replay:
            # Same starting population as the live run, when the recording
            # carries it. Read from a file, so it does not cost determinism.
            if not args.no_bootstrap:
                try:
                    boot = replay_mod.read_bootstrap(args.replay)
                except ValueError as e:
                    sys.exit("[ERROR] %s" % e)
                if boot is not None:
                    graph.bootstrap(boot[0], boot[1])
                    say("Seeded %d processes from the recording's bootstrap."
                        % len(boot[0]))
            # replay_mod.run() does its own forced tick at the end, so the
            # live loop's drain has no counterpart here: there is no ring.
            try:
                n, replay_undecodable = replay_mod.run(args.replay, proc,
                                                       vclock, decode)
            except ValueError as e:
                # Damage found mid-file: still bad input, not a crash. The
                # finally block below keeps whatever was built up to here.
                sys.exit("[ERROR] %s" % e)
            say("Replayed %d records (%d undecodable)." % (n, replay_undecodable))
        else:
            while not shutdown_requested:
                if batch_s:
                    # Leave records in the ring for a while: the kernel only
                    # wakes a reader that is sleeping in poll(), so fewer polls
                    # mean fewer wakeups (BCC 0.12 fixes wakeup_events = 1).
                    bpf.perf_buffer_poll(timeout=0)
                    time.sleep(batch_s)
                else:
                    bpf.perf_buffer_poll(timeout=50)   # short: Ctrl+C stays responsive
                now = time.monotonic()
                if args.duration and now - wall0 >= args.duration:
                    break
                if now - last_tick >= 0.5:
                    proc.tick()
                    last_tick = now
                if mode == "view" and now - last_draw >= args.refresh:
                    sampler.sample(graph.alive_nodes())
                    # Re-read the height every frame: a terminal can be
                    # resized mid-run, and a frame sized for the old height
                    # scrolls.
                    draw(render(graph, proc.stats(),
                                time.clock_gettime_ns(time.CLOCK_MONOTONIC),
                                now - wall0, color=color,
                                height=screen_rows()))
                    last_draw = now
            # Bounded drain: take what is queued, never loop forever in a flood.
            for _ in range(20):
                bpf.perf_buffer_poll(timeout=0)
            proc.tick(force=True)
    except Exception as e:                          # noqa: BLE001
        crash = "%s: %s" % (type(e).__name__, e)
        raise
    finally:
        # Give the terminal back FIRST, and on every path including a crash:
        # the alternate screen has no scrollback and no cursor, so a monitor
        # that dies without restoring it leaves the user stranded. It also
        # has to happen before the summary is printed, or the summary is
        # written to a screen that is about to be discarded.
        if fullscreen:
            leave_fullscreen()
        # Whatever happened, keep the evidence.
        wall = time.monotonic() - wall0
        cpu = cpu_seconds() - cpu0
        stats = proc.stats()
        if args.sink == "count":
            stats["records_received"] = count[0]
            total = count[0] + proc.lost
            stats["loss_rate"] = proc.lost / float(total) if total else 0.0
        stats.update({
            "version": __version__,
            "crash": crash,
            "monitor_pid": os.getpid(),
            "kernel": os.uname().release,
            "cpus": os.cpu_count(),
            "hooks": list(args.hooks),
            "sink": args.sink,
            "features": list(features),
            "features_refused": [[list(f), m] for f, m in refused],
            "pages_per_cpu": args.pages,
            "batch_ms": args.batch_ms,
            # Set when the graph came from a recording rather than the kernel.
            # Anything reading records_per_s has to know which it is: on a
            # replay that figure is how fast the FILE was read, not the rate
            # the events originally occurred at.
            "replay": args.replay,
            "replay_undecodable": replay_undecodable,
            "record_raw": args.record_raw,
            "records_recorded": recorder.count if recorder else 0,
            "duration_s": round(wall, 3),
            "bpf_compile_s": round(compile_s, 3),
            # Userspace cost only: in-kernel eBPF time is charged to the
            # traced processes and shows up as THEIR slowdown instead.
            "monitor_cpu_s": round(cpu, 3),
            "monitor_cpu_percent_of_one_core": round(100.0 * cpu / wall, 2) if wall else 0,
            "monitor_maxrss_kb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "records_per_s": round(stats["records_received"] / wall, 1) if wall else 0,
            "log": log_path,
        })
        if log_f:
            log_f.close()
        if recorder:
            recorder.close()
        if args.stats_json:
            with open(args.stats_json, "w") as f:
                json.dump(stats, f, indent=2)
        if args.snapshot and args.sink == "graph":
            with open(args.snapshot, "w") as f:
                json.dump(graph.to_dict(), f)
        say("\nStopped after %.1fs. records %d, lost %d (%.2f%%), errors %d, "
            "processes %d, files %d"
            % (wall, stats["records_received"], stats["lost"], 100 * stats["loss_rate"],
               stats["records"]["errors"], stats["graph"]["processes"],
               stats["graph"]["files"]))


if __name__ == "__main__":
    main()
