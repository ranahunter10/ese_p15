"""
events.py — the Python mirror of the records defined in bpf/monitor.bpf.c,
plus the small interpretation helpers every other module shares.

The kernel hands us raw bytes. ctypes.Structure says how to read them: the
field order, types and sizes here MUST match the C structs exactly, or every
field after the first mismatch is silently read from the wrong offset.
tests/test_layout.py compiles the real C struct with gcc and compares every
offset, so the two cannot drift apart unnoticed.
"""

import ctypes
import os
import socket
import struct
import time
from collections import namedtuple

TASK_COMM_LEN = 16
MAX_FILENAME = 256
ARG_LEN = 128
MAXARG = 20

UNIX_PATH_LEN = 108

EVENT_EXEC_ENTER = 0
EVENT_OPEN = 1
EVENT_EXEC_OK = 2
EVENT_EXIT = 3
EVENT_ARG = 4
EVENT_NET = 5

ARG_FLAG_END = 1
ARG_FLAG_TRUNCATED = 2

NET_FLAG_INPROGRESS = 1    # non-blocking connect still in flight
NET_FLAG_INBOUND = 2       # accept(): the peer connected to us
NET_FLAG_NOPEER = 4        # inbound, but the kernel had no peer name to give

# Address families, as the Linux ABI fixes them (socket.AF_* agree; the
# layout test asserts it rather than trusting that they do).
AF_UNIX = 1
AF_INET = 2
AF_INET6 = 10

EINPROGRESS = 115

# socket(2) types. 0 means the SOCKET_TYPE feature was off or the lookup
# failed; it is never guessed.
SOCK_STREAM = 1
SOCK_DGRAM = 2
SOCK_RAW = 3
SOCK_TYPE_NAMES = {0: "", SOCK_STREAM: "stream", SOCK_DGRAM: "dgram", SOCK_RAW: "raw"}

AT_FDCWD = -100            # "relative to the current directory"
AT_EMPTY_PATH = 0x1000     # execveat: run the file the fd itself refers to

EVENT_NAMES = {
    EVENT_EXEC_ENTER: "EXEC_ENTER",
    EVENT_OPEN: "OPEN",
    EVENT_EXEC_OK: "EXEC",
    EVENT_EXIT: "EXIT",
    EVENT_ARG: "ARG",
}


# "Who did this, and when" — identical in every record type, so declared
# once here and placed first in each, mirroring COMMON_FIELDS in the C
# source. test_layout.py checks each field's offset against the compiled C
# struct, and that the prefix is identical across the record types.
_COMMON_FIELDS = [
    ("type", ctypes.c_uint32),
    ("pid", ctypes.c_uint32),
    ("tid", ctypes.c_uint32),
    ("ppid", ctypes.c_uint32),
    ("uid", ctypes.c_uint32),
    ("gid", ctypes.c_uint32),
    ("ts_ns", ctypes.c_uint64),
    ("start_ns", ctypes.c_uint64),
    ("pstart_ns", ctypes.c_uint64),
    ("comm", ctypes.c_char * TASK_COMM_LEN),
    ("tcomm", ctypes.c_char * TASK_COMM_LEN),
    ("pcomm", ctypes.c_char * TASK_COMM_LEN),
]


class RawCommon(ctypes.Structure):
    _fields_ = list(_COMMON_FIELDS)


class RawEvent(ctypes.Structure):
    _fields_ = _COMMON_FIELDS + [
        ("ret", ctypes.c_int32),
        ("flags", ctypes.c_int32),
        ("aux_ns", ctypes.c_uint64),
        ("ino", ctypes.c_uint64),
        ("dev", ctypes.c_uint32),
        ("igen", ctypes.c_uint32),
        ("dfd", ctypes.c_int32),
        ("pad", ctypes.c_uint32),
        ("filename", ctypes.c_char * MAX_FILENAME),
    ]


class RawNet(ctypes.Structure):
    # Addresses and ports arrive in NETWORK byte order, exactly as the
    # program passed them to connect(); they are converted here, once, where
    # the conversion is obvious and testable.
    _fields_ = _COMMON_FIELDS + [
        ("ret", ctypes.c_int32),
        ("fd", ctypes.c_int32),
        ("family", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
        ("sport", ctypes.c_uint16),
        ("nflags", ctypes.c_uint16),
        ("daddr", ctypes.c_ubyte * 16),
        ("saddr", ctypes.c_ubyte * 16),
        ("path", ctypes.c_ubyte * UNIX_PATH_LEN),
        ("sock_type", ctypes.c_uint16),
        # How many bytes of the sockaddr are real: what the kernel wrote back
        # through upeer_addrlen on an accept, or what the caller passed on a
        # connect. Occupies the u16 that used to be `pad`, so the record is
        # still 256 bytes. Anything in `path` past it belongs to the traced
        # process, not to the kernel.
        ("addrlen", ctypes.c_uint16),
    ]


class RawArg(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint32),
        ("pid", ctypes.c_uint32),
        ("idx", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("enter_ts", ctypes.c_uint64),
        ("arg", ctypes.c_char * ARG_LEN),
    ]


# Immutable Python copies. BCC's buffer is only valid during the callback,
# so values are copied out immediately; nothing downstream touches ctypes.
Event = namedtuple(
    "Event",
    "type pid tid ppid uid gid ret flags ts_ns start_ns pstart_ns aux_ns "
    "ino dev igen dfd comm tcomm pcomm filename",
)
Event.__new__.__defaults__ = (0, 0, 0, AT_FDCWD, "", "", "", "")   # ino .. filename
Arg = namedtuple("Arg", "pid idx enter_ts arg flags")
Arg.__new__.__defaults__ = (0,)
Net = namedtuple(
    "Net",
    "type pid tid ppid uid gid ts_ns start_ns pstart_ns comm tcomm pcomm "
    "ret fd family dport sport nflags daddr saddr path sock_type addrlen",
)

_EVENT_SIZE = ctypes.sizeof(RawEvent)
_ARG_SIZE = ctypes.sizeof(RawArg)
_NET_SIZE = ctypes.sizeof(RawNet)
_U32P = ctypes.POINTER(ctypes.c_uint32)
_EVP = ctypes.POINTER(RawEvent)
_ARGP = ctypes.POINTER(RawArg)
_NETP = ctypes.POINTER(RawNet)


# ---------------------------------------------------------------------------
# Decoding
#
# The structures above stay the single description of the wire format — they
# are what test_layout.py compares against the gcc-compiled C, field by
# field. What changed in v3.6 is how a record is READ from them.
#
# `ctypes.cast(data, POINTER(RawEvent)).contents` plus attribute access per
# field was the old way, and `ctypes.cast` is itself a Python function in
# ctypes/__init__.py. One `struct.unpack_from` replaces it, with no copy:
# BCC hands the callback a `c_void_p`, which arrives as an integer address
# that `(c_char * size).from_address()` wraps in place.
#
# Measured by `tools/bench_ingest.py`, which ships so these numbers can be
# re-run rather than believed. Old and new are interleaved in one process and
# compared PER PAIR, because unpaired runs on the test machine drift enough to
# invent a result. 21 pairs, realistic record mix, container not VM:
#
#     decode alone      3.82 -> 2.07 µs   1.85x  (IQR 1.82-1.89)
#     full ingest path  9.30 -> 6.99 µs   1.34x  (IQR 1.32-1.38)
#     event rate                                 108k -> 143k events/s
#
# Read the RATIOS, not the microseconds: the ratios reproduce across runs
# inside their IQR, while the absolute per-record cost on this container
# varies by about 2x between runs depending on what else is scheduled. Quote
# an absolute only with the run that produced it
# (docs/evidence/bench_ingest_container_20261018.txt).
#
# Not the 17x an early microbenchmark suggested: that compared unpacking the
# nine scalar fields against a FULL old decode, which is not the same work.
# Inside one 392-byte EVENT decode, cumulative in the same run: 0.32 µs to
# unpack the struct, +0.92 µs for the four C-string conversions, +0.94 µs to
# build the namedtuple, 2.18 µs in total — which is the decode figure above,
# as it must be. An earlier version of this comment broke the breakdown out
# of a different run and it summed to 1.87 µs against a published 2.33 µs;
# an audit of this tree caught the contradiction. Decode is ~30 % of ingest
# and the graph is the rest, so this path is close to spent; making the
# string fields lazy would save about 7 % of ingest and is recorded as
# deferred rather than guessed at.
#
# The format string is DERIVED from the ctypes definition rather than written
# out, so it cannot drift from it: a field added, reordered or resized in
# _fields_ changes the format automatically, and _struct_format refuses to
# build one it cannot prove matches ctypes.sizeof().
# ---------------------------------------------------------------------------

_STRUCT_CODES = {
    ctypes.c_uint8: "B", ctypes.c_int8: "b",
    ctypes.c_uint16: "H", ctypes.c_int16: "h",
    ctypes.c_uint32: "I", ctypes.c_int32: "i",
    ctypes.c_uint64: "Q", ctypes.c_int64: "q",
}


def _struct_format(cls):
    """(format, field names) for a ctypes Structure, read off the Structure.

    Padding is emitted from each field's real offset, so the result describes
    the compiler's layout rather than a guess at it. Raises if the format it
    builds does not have the size ctypes reports — i.e. this can fail loudly
    at import, but it cannot silently decode fields from the wrong offsets.
    """
    out, names, pos = ["<"], [], 0
    for name, ftype in cls._fields_:
        off = getattr(cls, name).offset
        if off < pos:
            raise TypeError("%s.%s overlaps the previous field" % (cls.__name__, name))
        if off > pos:
            out.append("%dx" % (off - pos))
            pos = off
        if ftype in _STRUCT_CODES:
            out.append(_STRUCT_CODES[ftype])
            pos += ctypes.sizeof(ftype)
        elif issubclass(ftype, ctypes.Array) and ftype._type_ in (ctypes.c_char,
                                                                  ctypes.c_ubyte):
            out.append("%ds" % ftype._length_)
            pos += ftype._length_
        else:
            raise TypeError("no struct code for %s.%s (%r)"
                            % (cls.__name__, name, ftype))
        names.append(name)
    total = ctypes.sizeof(cls)
    if total > pos:
        out.append("%dx" % (total - pos))
    fmt = "".join(out)
    if struct.calcsize(fmt) != total:
        raise TypeError("%s: derived format %r is %d bytes, ctypes says %d"
                        % (cls.__name__, fmt, struct.calcsize(fmt), total))
    return fmt, tuple(names)


_EV_FMT, _EV_NAMES = _struct_format(RawEvent)
_NET_FMT, _NET_NAMES = _struct_format(RawNet)
_ARG_FMT, _ARG_NAMES = _struct_format(RawArg)

# Positions inside the unpacked tuples, resolved by NAME so that reordering
# _fields_ moves them correctly instead of silently mislabelling columns.
(_E_TYPE, _E_PID, _E_TID, _E_PPID, _E_UID, _E_GID, _E_TS, _E_START, _E_PSTART,
 _E_COMM, _E_TCOMM, _E_PCOMM, _E_RET, _E_FLAGS, _E_AUX, _E_INO, _E_DEV,
 _E_IGEN, _E_DFD, _E_FILE) = [
    _EV_NAMES.index(n) for n in
    ("type", "pid", "tid", "ppid", "uid", "gid", "ts_ns", "start_ns",
     "pstart_ns", "comm", "tcomm", "pcomm", "ret", "flags", "aux_ns", "ino",
     "dev", "igen", "dfd", "filename")]

(_N_TYPE, _N_PID, _N_TID, _N_PPID, _N_UID, _N_GID, _N_TS, _N_START, _N_PSTART,
 _N_COMM, _N_TCOMM, _N_PCOMM, _N_RET, _N_FD, _N_FAMILY, _N_DPORT, _N_SPORT,
 _N_NFLAGS, _N_DADDR, _N_SADDR, _N_PATH, _N_SOCKTYPE, _N_ADDRLEN) = [
    _NET_NAMES.index(n) for n in
    ("type", "pid", "tid", "ppid", "uid", "gid", "ts_ns", "start_ns",
     "pstart_ns", "comm", "tcomm", "pcomm", "ret", "fd", "family", "dport",
     "sport", "nflags", "daddr", "saddr", "path", "sock_type", "addrlen")]

(_A_PID, _A_IDX, _A_ENTER, _A_ARG, _A_FLAGS) = [
    _ARG_NAMES.index(n) for n in ("pid", "idx", "enter_ts", "arg", "flags")]

_TYPE_FMT = "<I"


def _s(raw):
    # c_char arrays already stop at the first NUL byte when read.
    return raw.decode("utf-8", errors="replace")


def _cs(raw):
    """Fixed-width C string -> str. struct gives the whole field including
    its NUL padding, where ctypes stopped at the first NUL for us."""
    i = raw.find(b"\0")
    if i >= 0:
        raw = raw[:i]
    return raw.decode("utf-8", errors="replace")


def decode(data, size):
    """One perf-buffer record -> Event, Arg, Net, or None if it isn't valid.

    `data` is either an integer address (what BCC passes: a `c_void_p`
    callback argument, whose `size` comes from the kernel and is trusted) or
    any bytes-like object (tests, replay, tools). For the bytes-like case the
    length is CHECKED against `size`: `ctypes.cast` would happily read past
    the end of a short buffer and return garbage as a record — a successful
    out-of-bounds read, reported as W2-B6 in the v3.5i review. `unpack_from`
    cannot do that; it raises, and a short buffer is reported as undecodable.
    """
    if size < 4:
        return None
    if isinstance(data, int):
        # BCC's pointer. Wrapped, not copied: valid for this callback only,
        # which is the same lifetime the ctypes cast relied on.
        buf = (ctypes.c_char * size).from_address(data)
    else:
        buf = data
        try:
            if len(buf) < size:
                return None
        except TypeError:
            pass                      # ctypes array or similar: trust `size`
    etype = struct.unpack_from(_TYPE_FMT, buf, 0)[0]
    if etype == EVENT_ARG:
        if size < _ARG_SIZE:
            return None
        v = struct.unpack_from(_ARG_FMT, buf, 0)
        return Arg(v[_A_PID], v[_A_IDX], v[_A_ENTER], _cs(v[_A_ARG]), v[_A_FLAGS])
    if etype == EVENT_NET:
        if size < _NET_SIZE:
            return None
        v = struct.unpack_from(_NET_FMT, buf, 0)
        return Net(
            v[_N_TYPE], v[_N_PID], v[_N_TID], v[_N_PPID], v[_N_UID], v[_N_GID],
            v[_N_TS], v[_N_START], v[_N_PSTART],
            _cs(v[_N_COMM]), _cs(v[_N_TCOMM]), _cs(v[_N_PCOMM]),
            v[_N_RET], v[_N_FD], v[_N_FAMILY],
            socket.ntohs(v[_N_DPORT]), socket.ntohs(v[_N_SPORT]), v[_N_NFLAGS],
            v[_N_DADDR], v[_N_SADDR], v[_N_PATH], v[_N_SOCKTYPE],
            v[_N_ADDRLEN],
        )
    if etype not in EVENT_NAMES or size < _EVENT_SIZE:
        return None
    v = struct.unpack_from(_EV_FMT, buf, 0)
    return Event(
        v[_E_TYPE], v[_E_PID], v[_E_TID], v[_E_PPID], v[_E_UID], v[_E_GID],
        v[_E_RET], v[_E_FLAGS], v[_E_TS], v[_E_START], v[_E_PSTART], v[_E_AUX],
        v[_E_INO], v[_E_DEV], v[_E_IGEN], v[_E_DFD],
        _cs(v[_E_COMM]), _cs(v[_E_TCOMM]), _cs(v[_E_PCOMM]), _cs(v[_E_FILE]),
    )


def encode_event(**fields):
    """The exact bytes the kernel would send (tests, replay)."""
    raw = RawEvent()
    raw.dfd = AT_FDCWD
    for k, v in fields.items():
        if isinstance(v, str):
            v = v.encode()
        setattr(raw, k, v)
    return bytes(raw)


def encode_arg(pid, idx, enter_ts, arg, flags=0):
    return bytes(RawArg(EVENT_ARG, pid, idx, flags, enter_ts, arg.encode()))


def encode_net(**fields):
    """The exact bytes the kernel would send for a connect (tests, replay).

    Ports are given in host order here and converted, so tests read the way
    a person thinks ("port 443"), not the way the wire carries it.
    """
    raw = RawNet()
    raw.type = EVENT_NET
    for k, v in fields.items():
        if k in ("dport", "sport"):
            v = socket.htons(v)
        elif isinstance(v, str):
            v = v.encode()
        if isinstance(v, bytes) and k in ("daddr", "saddr", "path"):
            field = dict(RawNet._fields_)[k]
            buf = (ctypes.c_ubyte * ctypes.sizeof(field))()
            for i, b in enumerate(v[:ctypes.sizeof(field)]):
                buf[i] = b
            v = buf
        setattr(raw, k, v)
    return bytes(raw)


# ---- Network endpoints ----------------------------------------------------
def addr_str(family, daddr):
    """Printable address, or '' when the family carries none."""
    try:
        if family == AF_INET:
            return socket.inet_ntop(socket.AF_INET, daddr[:4])
        if family == AF_INET6:
            return socket.inet_ntop(socket.AF_INET6, daddr[:16])
    except (ValueError, OSError):
        return ""
    return ""


def unix_path(raw, addrlen=0):
    """A unix socket's name, trimmed to the bytes that are actually a name.

    An abstract socket (Linux-only) starts with a NUL byte and is shown with
    a leading '@', the convention `ss` and `netstat` use. An all-zero name is
    an unnamed socket, e.g. one end of a socketpair.

    `addrlen` is the kernel's (or, on connect, the caller's) statement of how
    many bytes of the sockaddr are real, INCLUDING the 2-byte family. Bytes
    past it are whatever the traced process had in its buffer. Reading them
    is the bug found on the VM on 2026-10-18: an accepted unix peer has no
    name, the kernel writes 2 bytes, and the monitor reported 108 bytes of
    the caller's stack as the peer's identity — demonstrably, with a planted
    marker (`tools/p15_accept_probe.py`).

    Trimming matters even when a name IS present: a filesystem name is
    NUL-terminated inside addrlen, so splitting at the NUL would have been
    enough, but an ABSTRACT name is not terminated and would otherwise
    absorb the leftovers that follow it.

    addrlen=0 means "not reported" and is treated as no name at all, which
    is the safe reading: a record that cannot say how much of its buffer is
    real has no business naming a peer. Records from builds before the field
    existed carried 0 in the same u16, so they degrade to that too.
    """
    hdr = 2                                 # offsetof(struct sockaddr_un, sun_path)
    if not raw or addrlen <= hdr:
        return ""
    name = raw[:addrlen - hdr]
    if name[0:1] == b"\x00":
        name = name[1:].split(b"\x00")[0]
        if not name:
            return ""
        return "@" + name.decode("utf-8", errors="replace")
    return name.split(b"\x00")[0].decode("utf-8", errors="replace")


def endpoint_id(family, daddr, dport, path, addrlen=0):
    """Stable key for an endpoint node in the graph.

    An address and port identify the peer the same way an inode identifies a
    file: it is what the connection is *to*, independent of which process
    opened it or when. Returns None when there is nothing identifiable.
    """
    if family in (AF_INET, AF_INET6):
        a = addr_str(family, daddr)
        if not a:
            return None
        if family == AF_INET6:
            return "net:[%s]:%d" % (a, dport)
        return "net:%s:%d" % (a, dport)
    if family == AF_UNIX:
        p = unix_path(path, addrlen)
        return "unix:" + p if p else None
    return None


def inbound_endpoint_id(family, daddr, path, addrlen=0):
    """Stable key for the peer of an ACCEPTED connection.

    The port is deliberately left out, and that is not a shortcut. On an
    outbound connect the port is the *service* (443, 22): stable, and half
    of what identifies the peer. On an inbound accept the port in the
    sockaddr is the peer's EPHEMERAL source port, a different number on
    every connection — measured: a client connecting to our listening port
    34177 arrived with source port 45192, and the next one with another.
    Keying on it would mint a fresh endpoint node per connection and turn
    "who has been connecting to this box" into thousands of singleton
    nodes: the dependency-explosion problem again, in a new place.

    So an inbound peer is identified by host: `host:<addr>`. Which of our
    own ports it reached is a property of the accepting process (and will
    be filled from `sock:inet_sock_set_state`, which is where the kernel
    keeps the local port). A unix peer normally has no name at all, so it
    has no id — see NET_FLAG_NOPEER.
    """
    if family in (AF_INET, AF_INET6):
        a = addr_str(family, daddr)
        if not a:
            return None
        # IPv6 goes in brackets, as it does in an outbound id and as every
        # other tool writes it. Without them the id reads `host:::1`, which
        # cannot be split back into scheme and address by anything — a
        # person typing it into a query, or us parsing it later.
        return "host:[%s]" % a if family == AF_INET6 else "host:" + a
    if family == AF_UNIX:
        p = unix_path(path, addrlen)
        return "unix:" + p if p else None
    return None


# ---- File identity --------------------------------------------------------
_FID_CACHE = {}
_FID_CACHE_MAX = 1 << 16


def file_id(path, ino=0, dev=0, igen=0):
    """Stable string key for a file node in the graph.

    inode:<dev>:<ino>:<gen>  when the kernel told us the inode (best);
    path:<abs path>          when it didn't but the path is absolute;
    None                     for a relative path with no inode: we cannot
                             know which file it was, so no graph edge.

    The returned string is cached and shared. This is called once per open
    and once per exec, and every `node.files` tuple keeps a reference to
    whatever it was handed — so building a fresh string each time made the
    *same* file id exist once per event. The v3.5i review's load test reported
    38.1 MB of these retained after 1.05 M events, the second-largest
    consumer in the graph behind the tuples that hold them. That document is
    not in this tree, so the figure is attributed rather than reproducible
    here; the reason for the change does not rest on it — one object per
    distinct id instead of one per event is the point, whatever the total. Returning one shared object makes
    all of those references point at it.

    The cache is cleared wholesale when it fills rather than evicted
    one-at-a-time: it exists to collapse hot, repeated ids, and a hot id is
    re-cached on its next use. `sys.intern` would be wrong here — it never
    releases, and path strings are attacker-influenced and unbounded in
    variety.
    """
    if ino:
        key = (dev, ino, igen)
    elif path.startswith("/"):
        key = path
    else:
        return None
    fid = _FID_CACHE.get(key)
    if fid is None:
        fid = ("inode:%d:%d:%d" % key) if ino else ("path:" + path)
        if len(_FID_CACHE) >= _FID_CACHE_MAX:
            _FID_CACHE.clear()
        _FID_CACHE[key] = fid
    return fid


def display_path(path, dfd):
    """How to show a path the program passed, given the directory fd."""
    if path.startswith("/") or dfd == AT_FDCWD:
        return path
    return "fd%d:%s" % (dfd, path)


# ---- Clocks ---------------------------------------------------------------
# bpf_ktime_get_ns() is CLOCK_MONOTONIC (ns since boot, excluding suspend).
# The offset to the wall clock is measured directly, which is exact — v2
# added /proc/stat's whole-second, suspend-inclusive btime instead.
class Clock:
    def __init__(self):
        self.offset = time.time() - time.clock_gettime(time.CLOCK_MONOTONIC)

    def wall(self, mono_ns):
        return self.offset + mono_ns / 1e9

    def fmt(self, mono_ns):
        t = self.wall(mono_ns)
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) + (
            ".%03d" % int((t % 1) * 1000)
        )


# ---- open() flags -----------------------------------------------------------
O_ACCMODE = getattr(os, "O_ACCMODE", 3)


def open_mode(flags):
    """'R', 'W' or 'RW' — what the process ASKED for when opening.

    Opening for reading does not prove a read happened: this is the usual
    open-level over-approximation, stated so it is not mistaken for more.
    """
    acc = flags & O_ACCMODE
    if acc == os.O_RDONLY:
        # O_RDONLY|O_TRUNC truncates the file (undefined by POSIX, but Linux
        # does it), so it counts as a write.
        return "W" if flags & (os.O_CREAT | os.O_TRUNC) else "R"
    if acc == os.O_WRONLY:
        return "W"
    return "RW"
