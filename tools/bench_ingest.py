#!/usr/bin/env python3
"""Paired benchmark of the userspace ingest path: decode and graph.

Why this file exists. v3.6 published per-event figures — "decode 3.96 -> 2.33
µs", "112k -> 153k events/s" — in the changelog, the README and a comment in
`hids/events.py`, and the harness that produced them lived in a scratch
directory. A figure nobody else can re-run is a claim, not a measurement, and
an independent audit of the tree flagged exactly that. So the harness ships.

Two rules it enforces, both learned the hard way on this project:

* **Paired, interleaved.** Unpaired runs on the test machine drift ~25 %,
  which is larger than most of the effects being measured. Each variant is
  timed in the same process, alternating, and the medians are compared. An
  earlier "60 % eviction regression" turned out to be the control drifting
  2.0 -> 2.5 µs between runs.
* **CPU time, not wall time.** `time.process_time`, so an unlucky scheduling
  slice does not become a result.

The old decoder is kept here verbatim, not imported, because the point is to
compare against what v3.5i actually ran.

    python3 tools/bench_ingest.py              # the published figures
    python3 tools/bench_ingest.py --reps 9     # tighter medians, slower
"""
from __future__ import annotations

import argparse
import ctypes
import gc
import os
import random
import statistics
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from hids import events as E                                   # noqa: E402
from hids.graph import ProcessGraph                            # noqa: E402

SEC = 1_000_000_000


# ---------------------------------------------------------------- the old way
def _old_decode(data, size):
    """v3.5i's decode(), verbatim — including the type dispatch.

    `ctypes.cast` is a Python-level function and every field read crosses the
    ctypes boundary; that is what the rewrite removed. The dispatch is part
    of it: a comparison that decodes only one record type measures a path
    the monitor never takes. This is the same reference decoder
    `tests/test_layout.py` compares against over 3000 randomised records, so
    the two cannot drift apart unnoticed.
    """
    if size < 4:
        return None
    etype = ctypes.cast(data, E._U32P).contents.value
    if etype == E.EVENT_ARG:
        if size < E._ARG_SIZE:
            return None
        a = ctypes.cast(data, E._ARGP).contents
        return E.Arg(a.pid, a.idx, a.enter_ts, E._s(a.arg), a.flags)
    if etype == E.EVENT_NET:
        if size < E._NET_SIZE:
            return None
        n = ctypes.cast(data, E._NETP).contents
        return E.Net(
            n.type, n.pid, n.tid, n.ppid, n.uid, n.gid,
            n.ts_ns, n.start_ns, n.pstart_ns,
            E._s(n.comm), E._s(n.tcomm), E._s(n.pcomm),
            n.ret, n.fd, n.family,
            socket.ntohs(n.dport), socket.ntohs(n.sport), n.nflags,
            bytes(bytearray(n.daddr)), bytes(bytearray(n.saddr)),
            bytes(bytearray(n.path)), n.sock_type)
    if etype not in E.EVENT_NAMES or size < E._EVENT_SIZE:
        return None
    e = ctypes.cast(data, E._EVP).contents
    return E.Event(
        e.type, e.pid, e.tid, e.ppid, e.uid, e.gid, e.ret, e.flags,
        e.ts_ns, e.start_ns, e.pstart_ns, e.aux_ns,
        e.ino, e.dev, e.igen, e.dfd,
        E._s(e.comm), E._s(e.tcomm), E._s(e.pcomm), E._s(e.filename))


# ------------------------------------------------------------------- fixtures
# The mix matters more than the record count: the old decoder's cost scales
# with how many string fields a record has and how long its path is, so a
# fixture of nothing but long-path opens flatters the rewrite. These weights
# are the shape of a desktop/server workload as this project's own VM runs
# show it — opens dominate, execs come in ENTER/OK pairs with their argv,
# exits and sockets are comparatively rare. Change them and the speedup
# changes; that is a property of the workload, not of the decoder, which is
# why the mix is printed with the result.
MIX = ((E.EVENT_OPEN, 55), (E.EVENT_EXEC_ENTER, 12), (E.EVENT_EXEC_OK, 12),
       (E.EVENT_ARG, 11), (E.EVENT_EXIT, 6), (E.EVENT_NET, 4))

PATHS = ("/etc/passwd", "/proc/self/stat", "/tmp/t",
         "/usr/lib/x86_64-linux-gnu/libc.so.6",
         "/usr/lib/x86_64-linux-gnu/libpython3.8.so.1.0",
         "/home/user/.cache/pip/http/9/3/a/1/e/93a1e0c4f2b8",
         "/var/log/journal/3f2a/system@0005b1.journal")

COMMS = (b"bash", b"python3", b"dd", b"sshd", b"systemd-journal", b"cat")


def sample_buffers(n, seed=7):
    """A realistic record mix, in a deterministic order for a fair pairing."""
    rnd = random.Random(seed)
    efmt, _ = E._struct_format(E.RawEvent)
    afmt, _ = E._struct_format(E.RawArg)
    nfmt, _ = E._struct_format(E.RawNet)
    kinds = [k for k, w in MIX for _ in range(w)]
    out = []
    for i in range(n):
        etype = kinds[rnd.randrange(len(kinds))]
        comm, tcomm = rnd.choice(COMMS), rnd.choice(COMMS)
        ts = i * 1000 + SEC
        if etype == E.EVENT_ARG:
            raw = struct.pack(afmt, etype, 1000 + i, rnd.randrange(0, 6),
                              0, ts, rnd.choice(PATHS).encode())
            size = ctypes.sizeof(E.RawArg)
        elif etype == E.EVENT_NET:
            raw = struct.pack(
                nfmt, etype, 1000 + i, 1000 + i, 1, 0, 0,
                ts, SEC, SEC // 2, comm, tcomm, b"bash",
                0, 7, socket.AF_INET, socket.htons(443),
                socket.htons(51000 + (i % 1000)), 0,
                bytes([93, 184, 216, 34]) + bytes(12),
                bytes([10, 0, 2, 15]) + bytes(12), b"", 1, 0)
            size = ctypes.sizeof(E.RawNet)
        else:
            path = rnd.choice(PATHS) if etype != E.EVENT_EXIT else ""
            raw = struct.pack(
                efmt, etype, 1000 + i, 1000 + i, 1, 0, 0,
                ts, SEC, SEC // 2, comm, tcomm, b"bash",
                0 if etype != E.EVENT_EXIT else 3, 0,
                0, rnd.randrange(1 << 20), 8, 0, -100, 0,
                path.encode())
            size = ctypes.sizeof(E.RawEvent)
        assert len(raw) == size, (etype, len(raw), size)
        out.append((ctypes.create_string_buffer(raw, size), size))
    return out


def timed(fn, bufs, inner):
    """CPU time per record, with the collector held still.

    The ingest case allocates a graph that grows for the whole pass, so a
    generational collection landing inside one timed window and not the next
    moved the ingest ratio around by ~50 % — larger than the effect being
    measured. Collecting first and disabling the collector for the window
    makes the two variants see the same allocator conditions. Decode-only is
    unaffected either way; it is the graph that allocates.
    """
    gc.collect()
    gc.disable()
    try:
        t0 = time.process_time()
        for _ in range(inner):
            fn(bufs)
        return (time.process_time() - t0) / (inner * len(bufs))
    finally:
        gc.enable()


# ------------------------------------------------------------------ the cases
def case_decode_new(bufs):
    for buf, size in bufs:
        E.decode(buf, size)


def case_decode_old(bufs):
    for buf, size in bufs:
        _old_decode(buf, size)


def _ingest(decode, bufs):
    """Decode plus the graph work each record causes.

    Not every record type reaches the graph the same way — an ARG is held by
    the assembler, an EXIT closes a node — so this routes by type rather
    than pretending every record is an open. The point is the RATIO between
    the two decoders over the same work, and both see the same routing.
    """
    g = ProcessGraph(max_nodes=4096, max_files=4096, max_endpoints=4096)
    g.bootstrap([{"pid": 1, "ppid": 0, "comm": "init", "uid": 0,
                  "start_ns": SEC}], 0)
    for buf, size in bufs:
        ev = decode(buf, size)
        if ev is None or isinstance(ev, E.Arg):
            continue
        node = g.process(ev.pid, ev.start_ns, ev.ppid, ev.pstart_ns,
                         ev.comm, ev.pcomm, ev.uid, ev.ts_ns)
        if isinstance(ev, E.Net):
            eid = E.endpoint_id(ev.family, ev.daddr, ev.dport, ev.path)
            g.record_connect(node, ev.ts_ns, eid, ev.ret >= 0)
        elif ev.type == E.EVENT_EXIT:
            g.record_exit(node, ev.ts_ns, ev.ret)
        elif ev.type == E.EVENT_OPEN:
            g.record_open(node, ev.ts_ns, ev.filename, "R", ev.ret,
                          E.file_id(ev.filename, ev.ino, ev.dev, ev.igen))


def case_ingest_new(bufs):
    _ingest(E.decode, bufs)


def case_ingest_old(bufs):
    _ingest(_old_decode, bufs)


# ------------------------------------------------- where the new decode goes
def breakdown(bufs, inner):
    """Cumulative stages of the NEW decode, measured the same paired way.

    These must be read as cumulative, not as addends of a total measured
    elsewhere: the published per-record decode cost comes from
    `case_decode_new` in the same run and is printed beside them. A breakdown
    whose parts are timed under different conditions than the total will not
    sum to it, and a comment claiming otherwise was flagged by an audit of
    this tree.
    """
    fmt, names = E._struct_format(E.RawEvent)
    unpack = struct.Struct(fmt).unpack_from
    # Only the 392-byte EVENT records: the stages below unpack that layout
    # directly, so an ARG or NET buffer would be a different measurement (and
    # raises struct.error rather than reading past its end, which is one of
    # the reasons the rewrite uses unpack_from at all).
    bufs = [b for b in bufs if b[1] == ctypes.sizeof(E.RawEvent)]

    def unpack_only(bs):
        for buf, _size in bs:
            unpack(buf)

    def unpack_and_strings(bs):
        for buf, _size in bs:
            v = unpack(buf)
            for i in (9, 10, 11, 20):
                E._cs(v[i])

    stages = [("unpack the %d-byte struct" % ctypes.sizeof(E.RawEvent),
               unpack_only),
              ("+ the four C-string conversions", unpack_and_strings),
              ("+ build the namedtuple (= full decode)", case_decode_new)]
    return [(label, timed(fn, bufs, inner)) for label, fn in stages]


def pair(label, new, old, bufs, reps, inner):
    """Interleave the two variants and report the PER-PAIR ratio.

    Comparing the median of all new-side samples against the median of all
    old-side samples throws away the pairing. The samples on this machine are
    right-skewed — a few slow windows stretch the range to ~50 % while the
    medians stay put across independent runs — so max-minus-min over samples
    is a bad noise estimate and made a stable 1.34x look unpublishable.

    Timing the two back to back and taking old/new per pair cancels whatever
    both saw: the spread of those RATIOS is the honest noise figure, and it
    is the number that has to be small against the effect. The absolute
    microseconds are still printed, as medians, because the ratio alone
    hides whether the path got slower overall.
    """
    ratios, a, b = [], [], []
    for _ in range(reps):
        tn = timed(new, bufs, inner)
        to = timed(old, bufs, inner)
        a.append(tn)
        b.append(to)
        ratios.append(to / tn if tn else 0.0)
    mn, mo = statistics.median(a), statistics.median(b)
    r = statistics.median(ratios)
    # Interquartile, not min-max: on a 2-vCPU container a single pair that
    # lands beside another job swings the range (one run here gave ratios
    # 1.02-2.78 around a median of 1.84 while the machine was busy). The IQR
    # ignores one disturbed pair; the full range is still printed so a run
    # that was disturbed throughout cannot hide behind it.
    rs = sorted(ratios)
    lo, hi = rs[len(rs) // 4], rs[(3 * len(rs)) // 4]
    full = (min(rs), max(rs))
    # The effect is how far the ratio sits from 1; the noise is how far the
    # ratios sit from each other. If the second is not clearly smaller than
    # the first, the line says so rather than letting the median speak alone.
    note = ""
    if (hi - lo) >= abs(r - 1):
        note = "   <-- SPREAD >= EFFECT, not a result; raise --reps"
    print("  %-22s %6.2f -> %6.2f µs   %.2fx  "
          "(IQR %.2f-%.2f, range %.2f-%.2f, %d pairs)%s"
          % (label, mo * 1e6, mn * 1e6, r, lo, hi, full[0], full[1], reps, note))
    return mn, mo


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--records", type=int, default=2000)
    ap.add_argument("--reps", type=int, default=11,
                    help="interleaved repetitions; medians are compared")
    ap.add_argument("--inner", type=int, default=3)
    args = ap.parse_args()

    bufs = sample_buffers(args.records)
    print("bench_ingest: %d records, %d interleaved reps, %d inner passes"
          % (len(bufs), args.reps, args.inner))
    names = dict(E.EVENT_NAMES)
    names[E.EVENT_NET] = "NET"       # not in EVENT_NAMES; it is its own struct
    print("mix: %s" % ", ".join("%s %d%%" % (names[k], w) for k, w in MIX))
    print("python %s on %s" % (sys.version.split()[0], os.uname().machine))
    print("CPU time per record, old = v3.5i ctypes.cast decoder\n")

    print("paired:")
    dec_new, _dec_old = pair("decode alone", case_decode_new, case_decode_old,
                             bufs, args.reps, args.inner)
    ing_new, ing_old = pair("full ingest path", case_ingest_new,
                            case_ingest_old, bufs, args.reps, args.inner)
    print("    events/s (ingest)  %.0fk -> %.0fk"
          % (1 / ing_old / 1000, 1 / ing_new / 1000))

    print("\ninside the new decode of one %d-byte EVENT record "
          "(cumulative, same run):" % ctypes.sizeof(E.RawEvent))
    last = 0.0
    for label, t in breakdown(bufs, args.inner):
        print("  %-42s %5.2f µs  (+%.2f)" % (label, t * 1e6, (t - last) * 1e6))
        last = t
    print("  decode over the whole mix is %.0f %% of the ingest path"
          % (dec_new / ing_new * 100 if ing_new else 0))
    print("\nThese are container figures, not the 2 vCPU VM. Re-run there "
          "before quoting them as VM numbers.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
