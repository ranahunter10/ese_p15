"""Record the kernel's raw perf-buffer bytes, and replay them deterministically.

Two jobs, one format:

  --record-raw   writes every record the kernel delivered, byte for byte,
                 before anything interprets it.
  --replay       feeds those bytes back through the SAME decode -> process ->
                 graph path, with no kernel, no BPF and no root.

**Why raw bytes and not the JSONL log.** The log is the decoder's *output*, so
replaying it would exercise a second parser and leave the decoder untested --
and the decoder is exactly where the `accept()` length bug lived (Journal rows
187-191). Replaying the kernel's own bytes puts the whole userspace stack
under test, and makes the comparison byte-exact rather than
semantic-and-hopeful.

**Why determinism needs work at all.** Two wall-clock dependencies would
otherwise make the same file produce different graphs on different runs, and
both are removed here rather than tolerated:

  * `ExecAssembler` settles a pending exec once `now - seen` exceeds its
    timeout, reading a monotonic clock. A file is read far faster than the
    events originally happened, so a real clock settles nothing during the
    replay and then everything at once in the final forced tick -- which is
    not what the live run did. `VirtualClock`, advanced from each record's own
    `ts_ns`, reproduces the original spacing.
  * `Clock.offset` converts monotonic ns to wall time for log lines. Replay
    pins it to 0 so even the log text is reproducible.

What replay deliberately does NOT reproduce: the `/proc` bootstrap (it would
inject *this* machine's current processes into a replay of a past run) and the
CPU/RSS resource samples (there are no live processes to sample). So the
invariant under test is the **causal structure** -- nodes, edges, generations,
lineage -- not the resource columns.
"""

import json
import os
import struct

MAGIC = b"P15R"
FORMAT_VERSION = 1

_HDR = struct.Struct("<4sI")
_LEN = struct.Struct("<I")

# A perf record in this design is a few hundred bytes (RawEvent 392, RawNet
# 256). This bound is not a tuning knob: it is what separates a truncated or
# foreign file from a plausible one, so a corrupt length is reported instead
# of being handed to the allocator.
MAX_RECORD = 1 << 16

# Matches monitor.py's live tick cadence, so replay expires pending execs on
# the same schedule the real loop did -- in virtual time.
TICK_INTERVAL_S = 0.5


class RawRecorder:
    """Length-prefixed raw records: header, then (u32 length, payload)*."""

    def __init__(self, path):
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        self.f = open(path, "wb", buffering=1 << 20)
        self.f.write(_HDR.pack(MAGIC, FORMAT_VERSION))
        self.count = 0

    def write(self, payload):
        self.f.write(_LEN.pack(len(payload)))
        self.f.write(payload)
        self.count += 1

    def close(self):
        self.f.close()


def bootstrap_path(recording):
    return recording + ".bootstrap.json"


def write_bootstrap(recording, procs, ts_ns):
    """Save the /proc snapshot the live run started from, beside the recording.

    Without this a replay rebuilds only what the kernel reported during the
    run, so a 60 s recording of an idle desktop replays to a handful of
    processes while the live screen showed 174 -- the rest were the bootstrap.
    That makes replay useless for rehearsing a demo, and makes a replayed
    graph look like a capture failure when it is working exactly as designed.

    A sidecar rather than a new record type: the container format stays fixed,
    and a recording made without one still replays.
    """
    with open(bootstrap_path(recording), "w") as f:
        json.dump({"ts_ns": ts_ns, "procs": procs}, f)


def read_bootstrap(recording):
    """-> (procs, ts_ns), or None when the recording has no sidecar."""
    p = bootstrap_path(recording)
    if not os.path.exists(p):
        return None
    with open(p) as f:
        d = json.load(f)
    procs, ts = d.get("procs"), d.get("ts_ns")
    if not isinstance(procs, list) or not isinstance(ts, int):
        raise ValueError("%s: not a bootstrap sidecar (need 'procs' list and "
                         "integer 'ts_ns')" % p)
    return procs, ts


def peek_header(path):
    """Validate the header and return its format version.

    Called before the monitor sets anything up, so the common mistake --
    pointing --replay at the JSONL log, or at a file from another build --
    is reported in one line instead of after a graph and a log file have
    been created.
    """
    with open(path, "rb") as f:
        hdr = f.read(_HDR.size)
    if len(hdr) < _HDR.size:
        raise ValueError("%s: too short to be a P15 raw recording" % path)
    magic, ver = _HDR.unpack(hdr)
    if magic != MAGIC:
        raise ValueError("%s: not a P15 raw recording (magic %r). A --record-raw "
                         "file starts with %r; the JSONL log is not one."
                         % (path, magic, MAGIC))
    if ver != FORMAT_VERSION:
        raise ValueError("%s: recording format v%d, this build reads v%d"
                         % (path, ver, FORMAT_VERSION))
    return ver


def read_records(path):
    """Yield each recorded payload.

    Raises ValueError on anything this build cannot read. A recording is
    evidence, so a wrong magic, an unknown version or a truncated tail is
    reported -- never skipped quietly, which would silently shorten the
    event stream and make a replay look like a clean run with fewer events.
    """
    with open(path, "rb") as f:
        hdr = f.read(_HDR.size)
        if len(hdr) < _HDR.size:
            raise ValueError("%s: too short to be a P15 raw recording" % path)
        magic, ver = _HDR.unpack(hdr)
        if magic != MAGIC:
            raise ValueError("%s: not a P15 raw recording (magic %r)" % (path, magic))
        if ver != FORMAT_VERSION:
            raise ValueError("%s: recording format v%d, this build reads v%d"
                             % (path, ver, FORMAT_VERSION))
        n = 0
        while True:
            head = f.read(_LEN.size)
            if not head:
                return
            if len(head) < _LEN.size:
                raise ValueError("%s: truncated length prefix after %d records"
                                 % (path, n))
            (size,) = _LEN.unpack(head)
            if size == 0 or size > MAX_RECORD:
                raise ValueError("%s: implausible record size %d at record %d"
                                 % (path, size, n))
            payload = f.read(size)
            if len(payload) < size:
                raise ValueError("%s: truncated record %d (%d of %d bytes)"
                                 % (path, n, len(payload), size))
            n += 1
            yield payload


class VirtualClock:
    """Monotonic seconds in the recording's own time, not the wall's.

    Callable, so it drops into `EventProcessor(mono=...)` -- the seam the
    assembler's tests already use.
    """

    def __init__(self):
        self.now = 0.0

    def advance_to(self, ts_ns):
        t = ts_ns / 1e9
        # Never runs backwards: perf delivers per-CPU, so records can arrive
        # slightly out of order, and a clock that went back would re-arm
        # timeouts that had already elapsed.
        if t > self.now:
            self.now = t

    def __call__(self):
        return self.now


def run(path, proc, vclock, decode):
    """Feed a recording through `proc`. Returns (decoded, undecodable).

    `decode` is passed in rather than imported so this module stays free of
    a cycle with events.py and so a test can substitute one.
    """
    decoded = bad = advanced = 0
    next_tick = 0.0
    for payload in read_records(path):
        ev = decode(payload, len(payload))
        if ev is None:
            # Counted, not raised. The live path tolerates an undecodable
            # record; replay must agree with it or it is testing something
            # else.
            bad += 1
            continue
        # Event and Net carry `ts_ns`. Arg carries `enter_ts` -- its ENTER's
        # stamp, which is already behind the clock -- so an Arg deliberately
        # does not move it.
        #
        # This was `getattr(ev, "ts", 0)` first. No record type has a field
        # called `ts`, so it returned 0 for every record, the clock never
        # advanced, and replay silently behaved as though it had no clock at
        # all. The default is what hid it; the post-condition below is here
        # so the same mistake cannot be silent twice.
        ts = getattr(ev, "ts_ns", None)
        if ts is not None:
            # Before handle(), so a pending exec is stamped with its own
            # record's time rather than the previous record's.
            vclock.advance_to(ts)
            advanced += 1
        proc.handle(ev)
        decoded += 1
        if vclock.now >= next_tick:
            proc.tick()
            next_tick = vclock.now + TICK_INTERVAL_S
    proc.tick(force=True)
    if decoded and not advanced:
        raise RuntimeError(
            "replay read %d records and none carried a timestamp: the virtual "
            "clock never advanced, so pending execs cannot expire on the "
            "recording's own timeline. A renamed timestamp field would do "
            "exactly this." % decoded)
    return decoded, bad
