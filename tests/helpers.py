"""Synthetic kernel records for tests — no root, no eBPF, fully deterministic."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import socket  # noqa: E402

from hids.events import (AF_INET, AF_INET6, AF_UNIX, ARG_FLAG_END, Arg,  # noqa: E402
                         EINPROGRESS, Event, EVENT_EXEC_ENTER, EVENT_EXEC_OK,
                         EVENT_EXIT, EVENT_NET, EVENT_OPEN, NET_FLAG_INBOUND,
                         NET_FLAG_INPROGRESS, NET_FLAG_NOPEER, Net)

SEC = 10**9


class FakeClock:
    """Stands in for events.Clock (formatting) and time.monotonic (timeouts)."""

    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def fmt(self, ns):
        return "t+%.3f" % (ns / 1e9)


def _addrlen(family, path):
    """What the kernel (or the caller) would report as the sockaddr length.

    Fixtures have to get this right or they test the wrong thing. The case
    that matters is AF_UNIX with no path: a real unnamed peer makes the
    kernel write **2 bytes** — the family and nothing else — which is the
    whole subject of the 2026-10-18 VM bug. An earlier version of this
    helper fell through to a 6-byte default there, which let 6 bytes of the
    path through and made a no-peer fixture look like a named one.
    """
    if family == AF_UNIX:
        return 2 + len(path.encode()) if path else 2
    if family == AF_INET6:
        return 28                       # sizeof(struct sockaddr_in6)
    return 16                           # sizeof(struct sockaddr_in)


class World:
    """Tracks fake processes so tests read like a story."""

    def __init__(self):
        self.procs = {}   # pid -> dict(start, ppid, comm)

    def spawn(self, pid, ppid, comm, start):
        self.procs[pid] = {"start": start, "ppid": ppid, "comm": comm}

    def ev(self, etype, pid, ts, filename="", ret=0, flags=0, aux=0, comm=None,
           tid=None, **extra):
        p = self.procs[pid]
        par = self.procs.get(p["ppid"], {"start": 0, "comm": ""})
        return Event(type=etype, pid=pid, tid=tid or pid, ppid=p["ppid"], uid=1000,
                     gid=1000, ret=ret, flags=flags, ts_ns=ts, start_ns=p["start"],
                     pstart_ns=par["start"], aux_ns=aux, comm=comm or p["comm"],
                     tcomm=comm or p["comm"], pcomm=par["comm"], filename=filename,
                     **extra)

    # convenience wrappers ------------------------------------------------
    def exec_records(self, pid, enter_ts, ok_ts, filename, argv, new_comm,
                     kernel_path="", enter_extra=None, ok_extra=None):
        """kernel_path: what sched_process_exec reports with KERNEL_EXEC_PATH
        ("" = feature off)."""
        old = self.procs[pid]["comm"]
        recs = [self.ev(EVENT_EXEC_ENTER, pid, enter_ts, filename, comm=old,
                        **(enter_extra or {}))]
        recs += [Arg(pid, i, enter_ts, a) for i, a in enumerate(argv)]
        recs.append(Arg(pid, len(argv), enter_ts, "", ARG_FLAG_END))
        self.procs[pid]["comm"] = new_comm
        recs.append(self.ev(EVENT_EXEC_OK, pid, ok_ts, kernel_path, aux=enter_ts,
                            **(ok_extra or {})))
        return recs

    def open(self, pid, ts, path, flags=os.O_RDONLY, ret=3, **extra):
        return self.ev(EVENT_OPEN, pid, ts, path, ret=ret, flags=flags, **extra)

    def exit(self, pid, ts, status=0):
        return self.ev(EVENT_EXIT, pid, ts, ret=status)

    def connect(self, pid, ts, addr=None, port=0, ret=0, path="", fd=3,
                family=None, pending=False, sock_type=1):
        """A connect() record as the kernel would send it, after decoding.

        addr "1.2.3.4" -> AF_INET, "::1" -> AF_INET6, path -> AF_UNIX.
        sock_type defaults to SOCK_STREAM (1); pass 2 for a UDP socket, or 0
        for "the SOCKET_TYPE feature was not active".
        ret: 0 connected, -errno failed; pending=True marks the
        non-blocking -EINPROGRESS case the hook flags explicitly.
        """
        p = self.procs[pid]
        par = self.procs.get(p["ppid"], {"start": 0, "comm": ""})
        if path:
            family, raw = AF_UNIX, b""
        elif addr is not None and ":" in addr:
            family = family or AF_INET6
            raw = socket.inet_pton(socket.AF_INET6, addr)
        elif addr is not None:
            family = family or AF_INET
            raw = socket.inet_pton(socket.AF_INET, addr) + b"\x00" * 12
        else:
            family, raw = family or AF_INET, b"\x00" * 16
        if pending:
            ret = -EINPROGRESS
        return Net(type=EVENT_NET, pid=pid, tid=pid, ppid=p["ppid"], uid=1000,
                   gid=1000, ts_ns=ts, start_ns=p["start"], pstart_ns=par["start"],
                   comm=p["comm"], tcomm=p["comm"], pcomm=par["comm"],
                   ret=ret, fd=fd, family=family, dport=port, sport=0,
                   nflags=NET_FLAG_INPROGRESS if pending else 0,
                   daddr=raw.ljust(16, b"\x00"), saddr=b"\x00" * 16,
                   path=path.encode().ljust(108, b"\x00") if path else b"\x00" * 108,
                   sock_type=sock_type,
                   # The kernel's (or caller's) statement of how many bytes of
                   # the sockaddr are real, family included. A fixture with a
                   # unix path has to declare it, because userspace trims the
                   # name to it — that trimming is the fix for the VM bug of
                   # 2026-10-18, where 108 bytes of the traced process's own
                   # buffer were reported as the peer's identity.
                   addrlen=_addrlen(family, path))

    def accept(self, pid, ts, addr=None, peer_port=0, path="", listen_fd=3,
               conn_fd=7, family=None, nopeer=False, sock_type=1):
        """An accepted inbound connection, as the kernel would report it.

        `peer_port` is the peer's EPHEMERAL source port, which is why it is
        not part of the endpoint id. `conn_fd` lands in `ret`: for an
        inbound record that field is the new connection's descriptor, not a
        status. nopeer=True is `accept(fd, NULL, NULL)` or a unix client
        with no bound name — accepted, but no peer identity exists.
        """
        rec = self.connect(pid, ts, addr=addr, port=peer_port, path=path,
                           fd=listen_fd, family=family, sock_type=sock_type)
        flags = NET_FLAG_INBOUND | (NET_FLAG_NOPEER if nopeer else 0)
        return rec._replace(ret=conn_fd, nflags=flags)
