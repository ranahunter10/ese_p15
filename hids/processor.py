"""
processor.py — turns decoded kernel records into graph updates and log lines.
No BCC dependency, so every path is unit-tested with synthetic records.

Ordering: the perf buffer is one ring PER CPU, drained one after another,
so records from different CPUs arrive in no guaranteed order. execve even
migrates the process on purpose (sched_exec), so EXEC_OK is often read
before the EXEC_ENTER/ARG records it belongs to. ExecAssembler matches the
pieces by (pid, enter timestamp) instead of arrival order.

Walkthrough: docs/ARCHITECTURE.md, section 4.
"""

import errno
import json
import time
import traceback
from collections import OrderedDict

from .events import (AF_INET, AF_INET6, AF_UNIX, ARG_FLAG_END,
                     ARG_FLAG_TRUNCATED, AT_EMPTY_PATH, AT_FDCWD, Arg,
                     EINPROGRESS, EVENT_EXEC_ENTER, EVENT_EXEC_OK, EVENT_EXIT,
                     EVENT_NET, EVENT_OPEN, MAXARG, NET_FLAG_INBOUND,
                     NET_FLAG_INPROGRESS, NET_FLAG_NOPEER, SOCK_DGRAM,
                     SOCK_TYPE_NAMES, addr_str,
                     display_path, endpoint_id, file_id, inbound_endpoint_id,
                     open_mode, unix_path)

PENDING_TIMEOUT_S = 2.0
MAX_PENDING = 20000        # hard cap if records are being lost in bulk


class _Pending:
    __slots__ = ("enter", "ok", "args", "truncated", "ended", "count", "seen")

    def __init__(self, seen):
        self.enter = None
        self.ok = None
        self.args = {}
        self.truncated = False
        self.ended = False
        self.count = 0          # END record says how many args were sent
        self.seen = seen

    def complete(self):
        return (self.enter is not None and self.ok is not None and self.ended
                and len(self.args) >= self.count)


class ExecAssembler:
    """EXEC_ENTER + ARG* + ARG(END) + EXEC_OK -> one exec, in any order.

    Committed as soon as every piece has arrived; anything still incomplete
    after PENDING_TIMEOUT_S is settled by expire().
    """

    def __init__(self, on_exec, on_failed, clock=time.monotonic, keep_done=4096):
        self.on_exec = on_exec          # (enter|None, ok, argv, truncated) -> ExecRecord
        self.on_failed = on_failed      # (enter) -> None
        self.clock = clock
        self.pending = OrderedDict()    # (pid, enter_ts) -> _Pending, oldest first
        self.done = OrderedDict()       # (pid, enter_ts) -> ExecRecord (late ARGs)
        self.keep_done = keep_done
        self.late_args = 0
        self.forced = 0
        self.bad_args = 0               # ARG records refused for a bad slot index
        self.duplicates = 0            # records for an exec already committed

    def _get(self, key):
        p = self.pending.get(key)
        if p is None:
            p = self.pending[key] = _Pending(self.clock())
            if len(self.pending) > MAX_PENDING:
                self._settle(*self.pending.popitem(last=False))
                self.forced += 1
        return p

    def enter(self, ev):
        key = (ev.pid, ev.ts_ns)
        if key in self.done:
            # This exec is finished. Letting a duplicate ENTER rebuild a
            # pending entry is what turned a failed commit into the
            # success-AND-failure contradiction of W2-B1b: the entry had
            # nothing but an enter record, so the next expiry settled it
            # through on_failed while the graph already held the exec.
            self.duplicates += 1
            return
        p = self._get(key)
        p.enter = ev
        if p.complete():
            self._commit(key, p)

    def arg(self, a):
        # An out-of-range slot index is refused before it can touch anything.
        # Unvalidated, it had two ways to do damage (v3.5i report W2-B3):
        # idx=-1 silently rewrote argv[-1] of an already-committed record
        # (which the graph holds BY REFERENCE), and idx=2_000_000 padded that
        # same list to two million entries, +16 MB persisted into the graph,
        # the snapshot and every walk — with zero errors counted either time.
        # MAXARG has existed in events.py since v3.0 and was never enforced.
        # END records carry the argv COUNT in idx, so the bound is inclusive.
        if not isinstance(a.idx, int) or isinstance(a.idx, bool) \
                or a.idx < 0 or a.idx > MAXARG \
                or (a.idx == MAXARG and not a.flags & ARG_FLAG_END):
            self.bad_args += 1
            return
        key = (a.pid, a.enter_ts)
        if key in self.done:
            # Only after a timeout commit: log line already written, but the
            # graph still gets the argument. A None value means the key was
            # claimed by _commit and the record was lost to an error — the
            # exec is still committed, so it must not be resurrected here.
            rec = self.done[key]
            self.late_args += 1
            if rec is None:
                return
            if a.flags & ARG_FLAG_TRUNCATED:
                rec.truncated = True
            if not a.flags & ARG_FLAG_END:
                _place(rec.argv, a.idx, a.arg)
            return
        p = self._get(key)
        if a.flags & ARG_FLAG_TRUNCATED:
            p.truncated = True
        if a.flags & ARG_FLAG_END:
            p.ended = True
            p.count = a.idx
        else:
            p.args[a.idx] = a.arg
        if p.complete():
            self._commit(key, p)

    def ok(self, ev):
        if ev.aux_ns == 0:
            # No matching enter in the kernel (attached mid-exec, LRU
            # eviction, or an exec path we don't hook): commit what we know.
            self.on_exec(None, ev, [], False)
            return
        key = (ev.pid, ev.aux_ns)
        if key in self.done:
            # Once an exec key is finished it is finished, in EITHER
            # direction. The alternative — letting a late EXEC_OK upgrade an
            # exec already settled as failed — records the same exec as both
            # a success and a failure, which is the W2-B1b contradiction
            # reached by a different route. Consistency wins over the
            # upgrade, and the count makes the trade visible rather than
            # silent.
            #
            # The window is an OK arriving after its ENTER was settled. That
            # is normally more than PENDING_TIMEOUT_S, but _get's MAX_PENDING
            # overflow force-settles the OLDEST pending entry regardless of
            # age, so with more than MAX_PENDING execs in flight it is not
            # bounded by time at all.
            self.duplicates += 1
            return
        p = self._get(key)
        p.ok = ev
        if p.complete():
            self._commit(key, p)

    def _remember(self, key, rec):
        """Record that `key` has been committed. `rec` is None when the commit
        raised partway: the key is still claimed, so it can never settle."""
        self.done[key] = rec
        if len(self.done) > self.keep_done:
            self.done.popitem(last=False)

    def _commit(self, key, p):
        """Commit an exec exactly once, whatever goes wrong.

        The ordering here is the fix for the v3.5i report's W2-B1/B1b. The
        key is CLAIMED — removed from `pending` and entered in `done` — before
        any fallible work runs, because `on_exec` mutates the graph and *then*
        writes the log line. If that write fails (a full disk is the realistic
        trigger) the exec is already in the graph, so the one thing that must
        not happen is for the same exec to be settled again as a failure:
        `node.execs == 1` and `node.failed_execs == 1` for a single exec is a
        graph that contradicts itself, and an analyst would read it at face
        value.

        The obvious alternative — "pop after on_exec returns" — is still
        wrong, but measure what it actually costs before repeating the
        argument. Against v3.5i it meant the entry stayed in `pending` and
        every later tick re-settled it, running `record_exec` again each
        time. Against v3.6 that no longer happens: the node-level
        `last_settled_exec` guard (added for a different finding) refuses the
        second graph write, so the real consequence is one wasted settle
        attempt, counted in `duplicates`, and a key that is claimed later
        than it should be. Measured both ways — `execs` stays 1 either way;
        under the alternative the key sits in `pending` after the failure and
        `duplicates` reaches 1.

        That is a weaker argument than the one this docstring used to make,
        and it is the true one. The ordering is kept because correctness here
        should not DEPEND on a guard somewhere else being right: claiming
        first makes this method idempotent on its own, and defence in depth
        is worth having precisely because each layer is assumed to be the
        only one.
        """
        self.pending.pop(key, None)
        self._remember(key, None)
        argv = []
        for idx in sorted(p.args):
            _place(argv, idx, p.args[idx])
        rec = self.on_exec(p.enter, p.ok, argv, p.truncated)
        if rec is not None:
            self._remember(key, rec)

    def _settle(self, key, p):
        """ok seen -> commit what we have; no ok -> the exec FAILED."""
        if p.ok is not None:
            self._commit(key, p)
        else:
            self.pending.pop(key, None)
            if key in self.done:
                # Belt and braces behind enter()'s guard: an exec that has
                # been committed is never ALSO recorded as a failure, however
                # its key found its way back into pending.
                self.duplicates += 1
                return
            if p.enter is None:
                # ARG records whose ENTER was lost by the perf buffer. There
                # is nothing to record and nothing is emitted, so the key
                # must NOT be claimed: claiming it made the real ENTER and OK
                # — arriving after the timeout — both refuse, and an execve
                # that v3.5i recorded correctly produced no record at all.
                # Found by an independent review of v3.6.
                return
            # Claimed for the same reason _commit claims: on_failed mutates
            # the graph before it emits, so a failure part-way through must
            # not leave the key available to be settled a second time.
            self._remember(key, None)
            self.on_failed(p.enter)

    def expire(self, force=False):
        now = self.clock()
        for key in list(self.pending):
            p = self.pending[key]
            if not force and now - p.seen < PENDING_TIMEOUT_S:
                break           # OrderedDict: everything after is newer
            self._settle(key, p)


_FAMILY_NAMES = {AF_INET: "ipv4", AF_INET6: "ipv6", AF_UNIX: "unix"}


def _place(argv, idx, value):
    # Defence in depth behind ExecAssembler.arg()'s validation: a negative
    # index would not grow the list, it would overwrite from the end.
    if idx < 0:
        return
    while len(argv) <= idx:
        argv.append("")
    argv[idx] = value


class EventProcessor:
    def __init__(self, graph, clock, log_file=None, printer=None,
                 name_filter="", type_filter="", mono=time.monotonic):
        self.graph = graph
        self.clock = clock
        self.log_file = log_file
        self.printer = printer
        self.output = log_file is not None or printer is not None
        self.name_filter = name_filter.lower()
        self.type_filter = type_filter.upper()
        self.assembler = ExecAssembler(self._exec_done, self._exec_failed, clock=mono)
        self.counts = {"raw": 0, "EXEC": 0, "EXEC_FAILED": 0, "EXEC_FROM_FD": 0,
                       "OPEN": 0, "OPEN_FAILED": 0, "EXIT": 0, "ARG": 0,
                       "CONNECT": 0, "CONNECT_FAILED": 0, "CONNECT_PENDING": 0,
                       "CONNECT_UNIX": 0, "CONNECT_PROBE": 0,
                       "ACCEPT": 0, "ACCEPT_UNIX": 0, "ACCEPT_NOPEER": 0,
                       "logged": 0, "undecodable": 0, "errors": 0}
        self.first_error = None
        self.lost = 0
        self.lost_bursts = 0

    # -- entry points ---------------------------------------------------
    def _count_error(self):
        self.counts["errors"] += 1
        if self.first_error is None:
            self.first_error = traceback.format_exc()

    def handle(self, rec):
        """Never raises — except on EPIPE: a bad record must not stop the
        stream, but a closed output is not a bad record.

        EPIPE is the exception because BCC's own callback wrapper turns it
        into `exit()`, which is the clean-shutdown convention for
        `--mode print | head -5`. Swallowing it (v3.5i report W2-B4) left the
        monitor polling a dead pipe forever, counting one error per record.
        """
        self.counts["raw"] += 1
        try:
            self._dispatch(rec)
        except OSError as e:
            if e.errno == errno.EPIPE:        # BrokenPipeError included
                raise
            self._count_error()
        except Exception:                     # noqa: BLE001 — counted, kept
            self._count_error()

    def _dispatch(self, rec):
        if rec is None:
            self.counts["undecodable"] += 1
            return
        if isinstance(rec, Arg):
            self.counts["ARG"] += 1
            self.assembler.arg(rec)
            return
        t = rec.type
        if t == EVENT_OPEN:
            self._open(rec)
        elif t == EVENT_EXEC_ENTER:
            self.assembler.enter(rec)
        elif t == EVENT_EXEC_OK:
            self.assembler.ok(rec)
        elif t == EVENT_EXIT:
            self._exit(rec)
        elif t == EVENT_NET:
            # One record type carries both directions, told apart by a flag
            # rather than by a second struct: "who, when, which socket,
            # which peer" is the same set of facts either way.
            if rec.nflags & NET_FLAG_INBOUND:
                self._accept(rec)
            else:
                self._connect(rec)

    def handle_lost(self, count):
        self.lost += count
        self.lost_bursts += 1

    def tick(self, force=False):
        """Never raises, on the same terms as handle().

        The main loop calls this every 0.5 s and once more at shutdown, and
        the expiry path it drives writes log lines — so the "a bad record
        must not stop the stream" guarantee stopped at handle()'s door
        (v3.5i report W2-B2). A full disk during routine expiry did not just
        lose log lines, it killed the monitor: the exception reached
        monitor.py's main loop, which records a crash and re-raises.

        Expiries whose keys were already claimed by _commit/_settle are not
        retried, so a persistently failing sink cannot spin here.
        """
        try:
            self.assembler.expire(force=force)
        except OSError as e:
            if e.errno == errno.EPIPE:
                raise
            self._count_error()
        except Exception:                     # noqa: BLE001 — counted, kept
            self._count_error()

    # -- helpers --------------------------------------------------------
    def _node(self, ev, comm=None):
        return self.graph.process(ev.pid, ev.start_ns, ev.ppid, ev.pstart_ns,
                                  ev.comm if comm is None else comm,
                                  ev.pcomm, ev.uid, ev.ts_ns)

    def _emit(self, etype, ev, node, **extra):
        # Nothing to write to -> build nothing. Formatting the entry and the
        # lineage string was the largest avoidable cost in --no-log runs.
        if not self.output:
            return
        if self.type_filter and etype != self.type_filter:
            return
        if self.name_filter and self.name_filter not in node.comm.lower():
            return
        self.counts["logged"] += 1
        entry = {
            "type": etype,
            "time": self.clock.fmt(ev.ts_ns),
            "ts_ns": ev.ts_ns,
            "pid": node.pid, "gen": node.key[1], "tid": ev.tid,
            "ppid": node.ppid, "uid": ev.uid, "gid": ev.gid,
            "name": node.comm, "thread": ev.tcomm,
            "start_ns": node.start_ns,
            "lineage": self.graph.lineage_str(node),
        }
        entry.update(extra)
        if self.log_file is not None:
            self.log_file.write(json.dumps(entry) + "\n")
        if self.printer is not None:
            self.printer(entry)

    # -- per type ---------------------------------------------------------
    def _exec_done(self, enter, ok, argv, truncated):
        node = self._node(ok, comm="")      # record_exec does the rename
        # The enter timestamp identifies the exec. When the ENTER record was
        # never assembled we still have it, because EXEC_OK carries it in
        # aux_ns — which is how the assembler keys the pair in the first
        # place. Taking it from `enter` alone left the "ENTER lost, OK
        # arrives late" route uncovered, and the contradiction came back
        # through it. aux_ns == 0 means the kernel had no matching enter at
        # all (exec_start LRU eviction, or a hook we do not have), and then
        # nothing can correlate the two records; see CHANGES_v3.6.md §H.
        enter_ts = enter.ts_ns if enter is not None else (ok.aux_ns or None)
        if enter_ts is not None and node.last_settled_exec == enter_ts:
            # This exec already has an outcome. The assembler's own guards
            # catch the common case, but they live in `done`, which is an LRU
            # capped at keep_done — so with enough intervening execs the key
            # is evicted and the guard silently stops applying. An
            # independent review of v3.6 demonstrated exactly that: 4100
            # unrelated execs between a commit and a duplicate EXEC_ENTER
            # brought back `node.execs == 1` AND `node.failed_execs == 1` for
            # one exec, with nothing counted. The node is the authority that
            # cannot be evicted out from under the invariant: one outcome per
            # (process, enter timestamp), first one wins.
            self.assembler.duplicates += 1
            return None
        requested = ""
        from_fd = False
        if enter is not None:
            requested = display_path(enter.filename, enter.dfd)
            from_fd = (enter.dfd != AT_FDCWD and not enter.filename
                       and bool(enter.flags & AT_EMPTY_PATH))
        # Prefer the kernel's own path (KERNEL_EXEC_PATH), else the request.
        path = ok.filename or requested
        if path.startswith("/dev/fd/") or path.startswith("/proc/self/fd/"):
            from_fd = True
        fid = file_id(path, ok.ino, ok.dev, ok.igen)
        rec = self.graph.record_exec(
            node, ok.ts_ns, path, argv, truncated, ok.comm,
            old_comm=enter.comm if enter is not None else None,
            requested=requested, fid=fid, from_fd=from_fd)
        self.counts["EXEC"] += 1
        if from_fd:
            self.counts["EXEC_FROM_FD"] += 1
        node.last_settled_exec = enter_ts
        self._emit("EXEC", ok, node, path=path, requested_path=requested,
                   argv=argv, argv_truncated=truncated,
                   previous_name=rec.old_comm, enter_seen=enter is not None,
                   exec_from_fd=from_fd, file=fid)
        return rec

    def _exec_failed(self, enter):
        node = self._node(enter)
        if node.last_settled_exec == enter.ts_ns:
            self.assembler.duplicates += 1
            return
        path = display_path(enter.filename, enter.dfd)
        node.last_settled_exec = enter.ts_ns
        self.graph.record_failed_exec(node, enter.ts_ns, path)
        self.counts["EXEC_FAILED"] += 1
        self._emit("EXEC_FAILED", enter, node, path=path)

    def _open(self, ev):
        node = self._node(ev)
        mode = open_mode(ev.flags)
        fid = file_id(ev.filename, ev.ino, ev.dev, ev.igen) if ev.ret >= 0 else None
        self.graph.record_open(node, ev.ts_ns, ev.filename, mode, ev.ret, fid)
        self.counts["OPEN" if ev.ret >= 0 else "OPEN_FAILED"] += 1
        self._emit("OPEN", ev, node, path=display_path(ev.filename, ev.dfd),
                   mode=mode, ret=ev.ret, flags=ev.flags,
                   relative=not ev.filename.startswith("/"), file=fid)

    def _exit(self, ev):
        node = self._node(ev)
        self.graph.record_exit(node, ev.ts_ns, ev.ret)
        self.counts["EXIT"] += 1
        self._emit("EXIT", ev, node, exit_code=(ev.ret >> 8) & 0xFF,
                   signal=ev.ret & 0x7F)

    def _connect(self, ev):
        """One connect() call: who asked to talk to whom, and what happened.

        Three outcomes, deliberately counted apart, because they mean
        different things to a detector:
          ret == 0            connected
          -EINPROGRESS        non-blocking, still in flight — an attempt,
                              neither success nor failure (the kernel-side
                              confirmation that settles it is future work)
          any other -errno    refused, unreachable, timed out: the signature
                              of port scanning and host discovery
        """
        node = self._node(ev)
        eid = endpoint_id(ev.family, ev.daddr, ev.dport, ev.path, ev.addrlen)
        pending = bool(ev.nflags & NET_FLAG_INPROGRESS) or ev.ret == -EINPROGRESS
        ok = ev.ret == 0 or pending
        if ev.family == AF_UNIX:
            peer = unix_path(ev.path)
            self.counts["CONNECT_UNIX"] += 1
        else:
            peer = addr_str(ev.family, ev.daddr)
        # glibc resolves a name by connect()ing a UDP socket to each
        # candidate address with port 0, purely to let the kernel choose a
        # source address (RFC 3484 sorting). Those are name resolutions, not
        # connections; counted separately so they can be told apart.
        probe = ev.dport == 0 and ev.sock_type in (0, SOCK_DGRAM) and \
            ev.family != AF_UNIX
        if probe:
            self.counts["CONNECT_PROBE"] += 1
        self.graph.record_connect(node, ev.ts_ns, eid, ok)
        if pending:
            self.counts["CONNECT_PENDING"] += 1
        elif ev.ret == 0:
            self.counts["CONNECT"] += 1
        else:
            self.counts["CONNECT_FAILED"] += 1
        self._emit("CONNECT", ev, node, endpoint=eid, family=_FAMILY_NAMES.get(
                   ev.family, str(ev.family)), address=peer, port=ev.dport,
                   fd=ev.fd, ret=ev.ret, pending=pending,
                   socket=SOCK_TYPE_NAMES.get(ev.sock_type, str(ev.sock_type)),
                   probe=probe)

    def _accept(self, ev):
        """One accepted inbound connection: who reached in, and to whom.

        Two things differ from `_connect`, and both come from the kernel
        rather than from taste:

        * The peer address was written by the KERNEL into the caller's
          buffer during the syscall, so it is not a claim the monitored
          process made. An accepted peer cannot be spoofed by the process
          being watched; a connect target can.
        * `ev.ret` is the NEW connection's file descriptor, not a status.
          Only successful accepts exist as records at all — a failed accept
          means nothing was waiting, which the kernel hook drops.
        """
        node = self._node(ev)
        has_peer = not (ev.nflags & NET_FLAG_NOPEER)
        eid = inbound_endpoint_id(ev.family, ev.daddr, ev.path,
                                  ev.addrlen) if has_peer else None
        if ev.family == AF_UNIX:
            peer = unix_path(ev.path)
            self.counts["ACCEPT_UNIX"] += 1
        else:
            peer = addr_str(ev.family, ev.daddr)
        self.graph.record_accept(node, ev.ts_ns, eid, has_peer)
        self.counts["ACCEPT"] += 1
        if not has_peer:
            self.counts["ACCEPT_NOPEER"] += 1
        self._emit("ACCEPT", ev, node, endpoint=eid, family=_FAMILY_NAMES.get(
                   ev.family, str(ev.family)), address=peer,
                   peer_port=ev.dport, listen_fd=ev.fd, conn_fd=ev.ret,
                   socket=SOCK_TYPE_NAMES.get(ev.sock_type, str(ev.sock_type)),
                   peer_known=has_peer)

    def stats(self):
        raw = self.counts["raw"]
        return {
            "records": dict(self.counts),
            "records_received": raw,
            "lost": self.lost,
            "lost_bursts": self.lost_bursts,
            # share of kernel records dropped before we could read them
            "loss_rate": (self.lost / float(raw + self.lost)) if (raw + self.lost) else 0.0,
            "late_args": self.assembler.late_args,
            "forced_exec_settles": self.assembler.forced,
            # The v3.6 duplicate guards REFUSE records rather than drop them
            # silently, and the changelog claims that makes the trade
            # visible. It only does if the count leaves this process: an
            # audit found both counters incremented in five places and
            # exported from none, so --stats-json never carried them and the
            # claim was false. A refusal that nobody can count is a silent
            # drop with extra steps.
            "duplicates_refused": self.assembler.duplicates,
            "bad_arg_indexes": self.assembler.bad_args,
            "first_error": self.first_error,
            "graph": self.graph.summary(),
        }
