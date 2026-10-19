"""
graph.py — in-memory provenance graph.

Nodes
  ProcessNode  one process LIFETIME, keyed (pid, gen). gen is the order in
               which we FIRST SAW each holder of this PID number, which is
               not necessarily the order they ran: per-CPU buffers can
               deliver a reused PID's newest lifetime first, and the number
               cannot be reassigned afterwards because it is the node's key
               and persists into snapshots. `gens[pid]` IS kept in
               chronological order, so read that for "which came first", not
               the number. Identity itself comes from the kernel start time
               on every event, never from the number.
  FileNode     one file, keyed by events.file_id(): the inode when the kernel
               gave it (so different names for one file are one node), else
               the absolute path. Relative paths without an inode get NO node:
               "lib" opened by find in /usr and in /var are different files,
               and merging them would invent causal links.
  EndpointNode one peer a process connected to, keyed by events.endpoint_id():
               "net:<addr>:<port>" or "unix:<path>". The peer is what the
               connection is *to*, independent of which process opened it —
               the same role the inode plays for a file.

Edges (direction = information flow, as in threaTrace / Kairos)
  FORK    parent -> child        READ  file -> process
  WRITE   process -> file        EXEC  file -> process
  CONNECT process <-> endpoint   (a TCP connection carries data both ways;
          the walk direction decides which meaning is in play)

A FAILED connect is recorded against both the process and the endpoint, but
is never followed by a causal walk: nothing flowed. It is kept because a
refused or unreachable connect is what scanning looks like from inside.

Exited processes are never deleted by default (the advisor's "process died
but created a file" case). Memory bounds: optional max_nodes evicts the
oldest EXITED processes; max_files evicts the least recently used files;
per-process and per-file histories are capped with totals still counted.

Files are not versioned, so the graph can contain cycles (P reads F, then
writes F). Causal walks follow edges strictly backwards/forwards in TIME
and keep visited sets, which makes them meaningful and terminating.

Walkthrough: docs/ARCHITECTURE.md, sections 5-6.
"""

import heapq
import operator
from collections import OrderedDict, deque

_first = operator.itemgetter(0)   # (ts, group_key, value) -> ts

FORK, READ, WRITE, EXEC = "FORK", "READ", "WRITE", "EXEC"
CONNECT, CONNECT_FAILED = "CONNECT", "CONNECT_FAILED"
# Inbound. A separate edge KIND, but traversed exactly like CONNECT, and
# that is a deliberate pair of decisions:
#   * separate kind, because "we called out to that host" and "that host
#     called in to us" are different events to a detector — exfiltration
#     versus lateral movement arriving — and a label is the cheapest way to
#     keep them apart without a second graph;
#   * same traversal, because a TCP connection is a two-way channel
#     whichever side opened it. A bind shell accepts a connection and then
#     sends files out of it; an HTTP client connects out and reads a payload
#     in. Restricting either kind to one direction of the walk would hide
#     one of those two, so the walks follow both and the label says which.
ACCEPT = "ACCEPT"

MAX_FILES_PER_PROC = 2000
MAX_ACCESSES_PER_FILE = 2000
# Writes are kept in their own, smaller list (see FileNode): they are the
# causal edges a backward walk needs, and they must not be evicted by a
# flood of reads. 256 distinct writers-with-timestamps per file is far more
# history than last-write-wins can use, at ~24 bytes an entry.
MAX_WRITES_PER_FILE = 256
# How many edges one resource may contribute to a single walk step. A
# process that reads the same file 2 000 times has 2 000 formal input
# edges, all describing ONE relationship ("P read F"); left uncapped they
# fill `max_items` at depth 1 and the walk never descends to the writer at
# all — dependency explosion again, this time by repetition rather than by
# fan-out. Keeping the most recent few per resource preserves the
# multi-bound behaviour that matters (a file read two or three times, each
# read with its own writer) while bounding the pathological case.
MAX_EDGES_PER_RESOURCE = 8
MAX_PATHS_PER_FILE = 8
MAX_CONNS_PER_PROC = 2000
MAX_ACCESSES_PER_ENDPOINT = 2000
KERNEL_THREADD = 2

# Files almost every process touches (loader cache, shared libraries,
# locales, time zones, interpreter package directories,
# pseudo-filesystems). Following them in a causal walk connects everything
# to everything — the "dependency explosion" problem — so queries can skip
# them with skip=common_file.
#
# `/usr/local/lib/` and `/usr/share/zoneinfo/` were added after the 16-Oct
# VM run, where four of the eight visible edges in a root-cause chain were
# a zoneinfo file and Python package metadata under
# /usr/local/lib/python3.8/dist-packages — paths the old prefix list did
# not cover (it had /usr/lib/ but not /usr/local/lib/).
COMMON_PREFIXES = ("/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/",
                   "/usr/local/lib/", "/etc/ld.so",
                   "/usr/share/locale/", "/usr/lib/locale/",
                   "/usr/share/zoneinfo/", "/usr/share/i18n/",
                   "/proc/", "/sys/", "/dev/")


def common_file(f):
    return any(p.startswith(COMMON_PREFIXES) for p in f.paths)


def probe_endpoint(e):
    """An address the program never actually talked to.

    glibc's getaddrinfo() connect()s a UDP socket to each candidate address
    with port 0 so the kernel picks a source address (RFC 3484 sorting).
    Every name a browser resolves therefore appears as a port-0 endpoint.
    They are real syscalls and stay in the record, but following them in a
    causal walk links a process to every address it ever looked up.
    """
    return e.eid.startswith("net:") and e.eid.endswith(":0")


def noisy(node):
    """Skip rule for causal walks: shared libraries and resolver probes.

    With one exception that matters more than the rest of the rule: a
    common file that something WROTE during this capture is not noise, it
    is the interesting case. Hijacking a shared library, dropping an
    LD_PRELOAD object, or appending an `import` line to a `.pth` file under
    dist-packages (Python executes those at interpreter startup) all look
    exactly like "a file on a boring path" until you notice somebody wrote
    it. Filtering by path alone would hide the one event worth seeing, so
    the rule is "a common path that nobody wrote", not "a common path".

    This is why the prefix list can safely include interpreter package
    directories: a `.pth` read at startup is noise, and the same `.pth`
    written mid-capture still appears.
    """
    if isinstance(node, FileNode):
        return common_file(node) and not node.writes
    if isinstance(node, EndpointNode):
        return probe_endpoint(node)
    return False


class ExecRecord:
    __slots__ = ("ts_ns", "filename", "requested", "argv", "truncated",
                 "old_comm", "new_comm", "fid", "from_fd")

    def __init__(self, ts_ns, filename, argv, truncated, old_comm, new_comm,
                 requested="", fid=None, from_fd=False):
        self.ts_ns = ts_ns
        self.filename = filename      # path the kernel executed (best known)
        self.requested = requested    # path the program asked for
        self.argv = argv              # list; late ARG records may patch it
        self.truncated = truncated
        self.old_comm = old_comm
        self.new_comm = new_comm
        self.fid = fid
        self.from_fd = from_fd        # ran from a file descriptor (fexecve)

    def to_dict(self):
        return {s: (list(getattr(self, s)) if s == "argv" else getattr(self, s))
                for s in self.__slots__}


class ProcessNode:
    __slots__ = (
        "key", "pid", "start_ns", "start_exact", "ppid", "parent_key",
        "comm", "uid", "children", "execs", "failed_execs", "files",
        "conns", "conn_count", "failed_conns",
        "accepts", "accept_count", "nopeer_accepts",
        "file_count", "failed_opens", "unresolved_opens", "alive", "exit_ns",
        "exit_status", "exit_inferred", "first_ns", "last_ns", "cpu_percent",
        "rss_kb", "reparented_from", "own_span", "last_settled_exec",
    )

    def __init__(self, key, start_ns, start_exact, ppid, parent_key, comm, uid, ts_ns):
        self.key = key
        self.pid = key[0]
        self.start_ns = start_ns
        self.start_exact = start_exact   # False = estimated from /proc at startup
        self.ppid = ppid
        self.parent_key = parent_key
        self.comm = comm
        self.uid = uid
        self.children = []               # child keys, in order seen
        self.execs = []                  # ExecRecord list
        self.failed_execs = []           # (ts_ns, path)
        self.files = []                  # (ts_ns, path, mode, ret, fid)
        self.conns = []                  # (ts_ns, eid, ok)
        self.conn_count = 0              # connect() calls, including capped ones
        self.failed_conns = 0
        self.accepts = []                # (ts_ns, eid, has_peer) — inbound
        self.accept_count = 0            # accept()/accept4() that returned an fd
        self.nopeer_accepts = 0          # accepted, but the kernel had no name
        self.file_count = 0              # successful opens, including capped ones
        self.failed_opens = 0
        self.unresolved_opens = 0        # relative path, identity unknown
        self.alive = True
        self.exit_ns = None
        self.exit_status = None
        self.exit_inferred = False       # exit event lost; deduced from PID reuse
        self.first_ns = ts_ns
        self.last_ns = ts_ns
        self.cpu_percent = 0.0
        self.rss_kb = 0
        self.reparented_from = None
        # False while first_ns/last_ns are only a borrowed stamp from the
        # event that forced this node into existence (a placeholder parent).
        self.own_span = True
        # enter-timestamp of the last exec settled for this process, either
        # way. The authority for "this exec already has an outcome"; see
        # EventProcessor._exec_done.
        self.last_settled_exec = None

    @property
    def cmdline(self):
        if self.execs and self.execs[-1].argv:
            return " ".join(self.execs[-1].argv)
        return ""

    @property
    def exe(self):
        return self.execs[-1].filename if self.execs else ""

    def label(self):
        return "%s(%d)" % (self.comm or "?", self.pid)

    def __repr__(self):
        return "<%s gen=%d %s>" % (self.label(), self.key[1],
                                    "alive" if self.alive else "exited")

    _PLAIN = ("pid", "start_ns", "start_exact", "ppid", "comm", "uid",
              "file_count", "failed_opens", "unresolved_opens",
              "conn_count", "failed_conns", "alive",
              "exit_ns", "exit_status", "exit_inferred", "first_ns", "last_ns")

    # Fields added after the snapshot format was first written. They are
    # read with a default so a snapshot taken by an older build still
    # loads, which is why the format version did not have to change.
    _PLAIN_OPT = ("accept_count", "nopeer_accepts", "own_span")

    def to_dict(self):
        d = {k: getattr(self, k) for k in self._PLAIN + self._PLAIN_OPT}
        d.update({
            "gen": self.key[1],
            "parent": list(self.parent_key) if self.parent_key else None,
            "children": [list(k) for k in self.children],
            "execs": [e.to_dict() for e in self.execs],
            "failed_execs": [list(x) for x in self.failed_execs],
            "files": [list(x) for x in self.files],
            "conns": [list(x) for x in self.conns],
            "accepts": [list(x) for x in self.accepts],
            "reparented_from": list(self.reparented_from) if self.reparented_from else None,
        })
        return d


class FileNode:
    """One file, identified by inode where possible.

    Two access lists, deliberately:

    * `accesses` is the activity log — every read, write and exec, capped at
      MAX_ACCESSES_PER_FILE and trimmed oldest-first.
    * `writes` is the *causal* list, capped separately and much smaller.

    They are separate because reads and writes are not interchangeable to a
    backward walk: a write is a cause, a read is not. With one shared list,
    a file read 2 000 times after being written once loses the write — and
    then a root-cause walk reports no writer at all, which is a silent,
    confident "nobody put these bytes here". Writes are rare and reads are
    floods, so the fix is to stop letting the flood evict the evidence.
    """
    __slots__ = ("fid", "paths", "accesses", "access_count", "writes")

    def __init__(self, fid):
        self.fid = fid
        self.paths = []          # names seen for this file, newest last
        self.accesses = []       # (ts_ns, proc_key, kind) — activity log
        self.writes = []         # (ts_ns, proc_key) — the causal subset
        self.access_count = 0

    @property
    def label(self):
        return self.paths[-1] if self.paths else self.fid

    def add_path(self, path):
        if path and (not self.paths or self.paths[-1] != path):
            if path in self.paths:
                self.paths.remove(path)
            self.paths.append(path)
            if len(self.paths) > MAX_PATHS_PER_FILE:
                del self.paths[0]


class EndpointNode:
    """One network or unix-socket peer. Mirrors FileNode deliberately: both
    are passive resources processes touch, and both are identified by what
    they are rather than by who touched them."""
    __slots__ = ("eid", "accesses", "access_count", "failed_count")

    def __init__(self, eid):
        self.eid = eid
        self.accesses = []       # (ts_ns, proc_key, kind)
        self.access_count = 0
        self.failed_count = 0

    @property
    def label(self):
        return self.eid


class ProcessGraph:
    def __init__(self, max_nodes=None, max_files=None, max_endpoints=None):
        self.nodes = {}              # (pid, gen) -> ProcessNode
        self.gens = {}               # pid -> [keys, oldest first by start_ns]
        self.current = {}            # pid -> key of the newest known lifetime
        self.files = OrderedDict()   # fid -> FileNode, least recently used first
        self.endpoints = OrderedDict()   # eid -> EndpointNode
        self.path_index = {}         # path -> fid last seen under that path
        self.max_nodes = max_nodes
        self.max_files = max_files
        self.max_endpoints = max_endpoints
        self.stats = {"generations": 0, "inferred_exits": 0, "evicted": 0,
                      "evicted_files": 0, "evicted_endpoints": 0,
                      "reparents": 0, "placeholders": 0}
        # Nodes known to have exited, so eviction never has to scan for
        # candidates. See _maybe_evict for what that scan cost.
        self._dead = {}              # key -> ProcessNode, exited
        self._protect = None         # key the caller is holding; never evict
        # Highest generation number ever minted per pid, so an evicted
        # generation's number is never handed out again.
        self._gen_hwm = {}

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------
    def find(self, pid, start_ns):
        """Key of the lifetime of `pid` that started at `start_ns`, or None."""
        for key in self.gens.get(pid, ()):
            if self.nodes[key].start_ns == start_ns:
                return key
        return None

    def _new_node(self, pid, start_ns, exact, ppid, parent_key, comm, uid, ts_ns,
                  own_span=True):
        keys = self.gens.setdefault(pid, [])
        # max(gen)+1, not keys[-1][1]+1. The list is kept in start_ns order
        # below — which is what `gens` is documented to hold — so its last
        # entry is not necessarily the highest-numbered one, and +1 on it
        # would mint a key that already exists (v3.5i report W1-F4).
        # Never reuse a generation number. _evict removes keys from
        # gens[pid] (and deletes the list when it empties), so max()+1 over
        # the SURVIVING keys hands out a number that evicted nodes are still
        # referenced by — FileNode.accesses and surviving parent_keys both
        # keep (pid, gen) tuples, and _evict cleans neither. An independent
        # review of v3.6 showed a file write being credited to a later
        # process that inherited the number. A per-pid high-water mark costs
        # one int per pid and makes the key monotone for the run.
        #
        # The `[k[1] for k in keys]` term is redundant GIVEN the watermark —
        # `_gen_hwm[pid]` is set on every mint below and restored from the
        # surviving keys by `from_dict`, so `hwm` is already >= every live
        # generation of this pid. An independent mutation sweep showed it: a
        # mutant that drops the term computes the same number on every input,
        # which no test can catch. It is kept rather than simplified to
        # `hwm + 1` because the alternative makes key uniqueness depend on a
        # single invariant with no backstop — a future mint path that forgets
        # to update the watermark would hand out a colliding key silently,
        # and the term costs one list comprehension per node creation.
        hwm = self._gen_hwm.get(pid, -1)
        gen = max([hwm] + [k[1] for k in keys]) + 1
        self._gen_hwm[pid] = gen
        key = (pid, gen)
        node = ProcessNode(key, start_ns, exact, ppid, parent_key, comm, uid, ts_ns)
        node.own_span = own_span
        self.nodes[key] = node
        keys.append(key)
        # Restore the documented "oldest first". Observation order and
        # chronological order diverge whenever per-CPU reordering delivers a
        # reused PID's NEWEST lifetime first, and callers read gens[pid][0]
        # as the oldest generation. The gen NUMBER stays observation order —
        # it is the node's key and persists into snapshots, so it cannot be
        # renumbered retroactively; see the class docstring.
        keys.sort(key=lambda k: (self.nodes[k].start_ns, k[1]))
        if gen > 0:
            self.stats["generations"] += 1
        if parent_key is not None and parent_key in self.nodes:
            self.nodes[parent_key].children.append(key)
        self._maybe_evict()
        return node

    def _parent_key(self, ppid, pstart_ns, pcomm, ts_ns):
        """Resolve a parent reference to an exact lifetime; create a
        placeholder if that parent was never seen (it forked and exited
        before we could observe it)."""
        if not ppid:
            return None
        key = self.find(ppid, pstart_ns)
        if key is not None:
            return key
        cur = self.current.get(ppid)
        if cur is not None:
            node = self.nodes[cur]
            if not node.start_exact and node.alive:
                node.start_ns = pstart_ns      # upgrade the /proc estimate
                node.start_exact = True
                return cur
        node = self._new_node(ppid, pstart_ns, True, 0, None, pcomm, None, ts_ns,
                              own_span=False)
        self.stats["placeholders"] += 1
        self._set_current_if_newer(node)
        return node.key

    def _set_current_if_newer(self, node):
        cur = self.current.get(node.pid)
        if cur is None or cur not in self.nodes:
            self.current[node.pid] = node.key
            return
        old = self.nodes[cur]
        # Newest lifetime wins. Per-CPU buffers deliver out of order, so a
        # LATE event from an older lifetime must not take over.
        if not old.start_exact or node.start_ns > old.start_ns:
            if old.alive:
                # Its PID now belongs to someone else, so it must have
                # exited; the exit event was lost.
                old.alive = False
                old.exit_inferred = True
                # The new generation's FORK time is the latest moment the
                # old one can still have been alive: a PID is not handed out
                # again until its previous holder is gone. That is a
                # provable bound, and kernel-exact when start_exact — where
                # `first_ns` was merely "when we happened to see the new
                # process", which record reordering can push arbitrarily
                # late AND which gets lowered afterwards, leaving this
                # stamp stale. Same helper, same proof, as the FORK edge.
                self._infer_exit(old, self._fork_ts(node))
            self.current[node.pid] = node.key
        elif node.alive:
            # The mirror case, and the one that was missing (v3.5i report
            # W1-F4). This lifetime is OLDER than an exact-start current one,
            # so its PID has already been handed on and it cannot still be
            # running. Left alive it was counted in summary()["alive"],
            # rendered as a live process, and — because eviction only removes
            # exited nodes — could never be evicted: a slow leak of ghosts.
            # The bound is the same provable one used above, in the other
            # direction: the newer generation's fork time.
            self._infer_exit(node, self._fork_ts(old))

    def _infer_exit(self, node, exit_ns):
        """Mark a lifetime ended at a time we can prove, not observe.

        The bound is the fork of the generation that took its PID: a PID is
        not handed out again until its previous holder is gone.

        The clamp matters for a node whose span is still borrowed. A
        placeholder parent carries a stamp from the CHILD event that created
        it, which can be LATER than the proven exit — so the graph said a
        process exited before it was last seen, breaking "no effect before
        its cause" in `to_dict` output and in `render_tree`. A proven exit
        beats a borrowed observation, so the borrowed end is pulled in.
        """
        node.alive = False
        node.exit_inferred = True
        node.exit_ns = exit_ns
        if not node.own_span and node.last_ns > exit_ns:
            node.last_ns = exit_ns
            if node.first_ns > node.last_ns:
                node.first_ns = node.last_ns
        self.stats["inferred_exits"] += 1
        self._note_dead(node)

    def process(self, pid, start_ns, ppid, pstart_ns, comm, pcomm, uid, ts_ns):
        """Node for this exact lifetime, created/updated as needed.
        Every event passes through here first."""
        key = self.find(pid, start_ns)
        node = self.nodes.get(key) if key else None

        if node is None:
            cur = self.current.get(pid)
            cnode = self.nodes.get(cur) if cur else None
            if cnode is not None and not cnode.start_exact and cnode.alive:
                # Process that existed at startup: adopt the exact time.
                cnode.start_ns = start_ns
                cnode.start_exact = True
                node = cnode
                if not node.own_span:
                    # A placeholder's span was borrowed from the event that
                    # forced it into existence — a CHILD's event, at a time
                    # this process may never have been running. Adoption used
                    # to correct first_ns and leave last_ns at that borrowed
                    # stamp (v3.5i report W1-F10), so the node claimed a span
                    # reaching past its own last event. Hand the span back to
                    # this node's own events, starting with this one.
                    node.first_ns = node.last_ns = ts_ns
                    node.own_span = True
                if ppid:
                    self._protect = node.key      # see the reparent below
                    try:
                        pk = self._parent_key(ppid, pstart_ns, pcomm, ts_ns)
                    finally:
                        self._protect = None
                    if pk != node.parent_key:
                        self._relink(node, pk, ppid)
            else:
                parent_key = self._parent_key(ppid, pstart_ns, pcomm, ts_ns)
                node = self._new_node(pid, start_ns, True, ppid, parent_key,
                                      comm, uid, ts_ns)
                self._set_current_if_newer(node)
                return node

        # "Is this the newest thing we have seen about this node" is decided
        # against EVERYTHING seen, including the borrowed stamp a placeholder
        # carries — that is what stops a late pre-exec record renaming the
        # node (Journal row 12). It must therefore be decided BEFORE the span
        # is handed back below; computing it afterwards made every
        # first-own-event look newest and broke the rename guard, which
        # test_a_placeholder_parent_is_upgraded_not_duplicated caught.
        newest = ts_ns >= node.last_ns
        if not node.own_span:
            # First event that genuinely belongs to this node. Until now its
            # span was a stamp borrowed from whatever forced it into
            # existence — a CHILD's event, for a placeholder parent — so the
            # node claimed a span reaching past its own last event
            # (v3.5i report W1-F10). Note this is the path that matters: a
            # placeholder is created with an exact start_ns, so find()
            # matches it and the adoption branch above is never reached.
            node.first_ns = node.last_ns = ts_ns
            node.own_span = True
        elif newest:
            node.last_ns = ts_ns
        # Only an event NEWER than everything seen may rename: a late
        # pre-exec event must not turn "cat" back into "bash". An EMPTY name
        # is the exception, because filling a blank can never revert a real
        # rename — and without it a node first seen through an accept or open
        # record kept rendering as `?(130)` in every walk while its siblings
        # showed real names, even though the later birth record healed its
        # ppid and uid (v3.5i report W1-F5).
        if comm and node.alive and (newest or not node.comm):
            node.comm = comm
        # ...and the other end of the span, for the same reason _touch does
        # it: this event can be OLDER than the first one we processed.
        if ts_ns < node.first_ns:
            node.first_ns = ts_ns
        if node.uid is None:
            node.uid = uid
        # A dead node may still learn its parent, but only if it never had
        # one. The birth record is authoritative; gating the reparent on
        # `alive` alone dropped it (v3.5i report W1-F9), leaving a permanent
        # false root and losing a real FORK edge from every backward walk —
        # the one finding in that report that loses a causal fact rather than
        # mislabelling one. An established link is never moved after death,
        # and pid 1 legitimately has ppid 0.
        if ppid and node.ppid != ppid and (
                node.alive or (node.ppid == 0 and node.pid != 1)):
            # Pinned across the reparent because it can create a placeholder
            # parent, and creating a node runs an eviction pass that is
            # allowed to remove any DEAD node — including this one, which the
            # caller is about to be handed. An independent review of v3.6
            # found exactly that: process() returned a node no longer in the
            # graph, record_exit then filed its key in _dead, and from then
            # on every eviction pass raised KeyError inside _new_node, so the
            # node cap stopped bounding anything and every later event was
            # lost, one counted error at a time. Before v3.6 a dead node was
            # never reparented, so this could not arise.
            self._protect = node.key
            try:
                self._reparent(node, ppid, pstart_ns, pcomm, ts_ns)
            finally:
                self._protect = None
        return node

    def _reparent(self, node, ppid, pstart_ns, pcomm, ts_ns):
        """Orphans are adopted by init or a subreaper: move the edge,
        remember where it came from."""
        new_parent = self._parent_key(ppid, pstart_ns, pcomm, ts_ns)
        if node.reparented_from is None:
            node.reparented_from = node.parent_key
        self._relink(node, new_parent, ppid)
        self.stats["reparents"] += 1

    def _relink(self, node, new_parent, ppid):
        if node.parent_key in self.nodes:
            siblings = self.nodes[node.parent_key].children
            if node.key in siblings:
                siblings.remove(node.key)
        node.parent_key = new_parent
        node.ppid = ppid
        if new_parent in self.nodes and node.key not in self.nodes[new_parent].children:
            self.nodes[new_parent].children.append(node.key)

    # ------------------------------------------------------------------
    # Event recording
    # ------------------------------------------------------------------
    @staticmethod
    def _touch(node, ts_ns):
        """Keep BOTH ends of a node's observed span.

        `first_ns` used to be set once, from the first record *processed* for
        this node — which is not the earliest record that happened. Per-CPU
        perf buffers deliver out of order (the whole reason ExecAssembler
        exists), so an event from 300 s can arrive after one from 500 s and
        leave `first_ns` three minutes too late. Two things then go wrong:
        a generation's inferred exit (`old.exit_ns = node.first_ns`) is
        stamped with the wrong time, and any walk using `first_ns` as a
        timestamp can place a cause in the future.
        """
        if not node.own_span:
            node.first_ns = node.last_ns = ts_ns
            node.own_span = True
            return
        if ts_ns > node.last_ns:
            node.last_ns = ts_ns
        if ts_ns < node.first_ns:
            node.first_ns = ts_ns

    def record_exec(self, node, ts_ns, filename, argv, truncated, new_comm,
                    old_comm=None, requested="", fid=None, from_fd=False):
        self._touch(node, ts_ns)
        if old_comm is None:
            old_comm = node.comm
        if fid is None and filename:
            fid = self._fid_for(filename, None)
        rec = ExecRecord(ts_ns, filename, argv, truncated, old_comm, new_comm,
                         requested, fid, from_fd)
        node.execs.append(rec)
        if new_comm:
            node.comm = new_comm
        if fid:
            self._file_access(fid, filename, node, EXEC, ts_ns)
        return rec

    def record_failed_exec(self, node, ts_ns, path):
        self._touch(node, ts_ns)
        node.failed_execs.append((ts_ns, path))
        if len(node.failed_execs) > 100:
            del node.failed_execs[0]

    def _fid_for(self, path, fid):
        if fid:
            return fid
        return "path:" + path if path.startswith("/") else None

    def record_open(self, node, ts_ns, path, mode, ret, fid=None):
        self._touch(node, ts_ns)
        if ret < 0:
            node.failed_opens += 1
            return
        fid = self._fid_for(path, fid)
        node.file_count += 1
        node.files.append((ts_ns, path, mode, ret, fid))
        if len(node.files) > MAX_FILES_PER_PROC:
            del node.files[0]
        if fid is None:
            node.unresolved_opens += 1
            return
        if "R" in mode:
            self._file_access(fid, path, node, READ, ts_ns)
        if "W" in mode:
            self._file_access(fid, path, node, WRITE, ts_ns)

    def _file_access(self, fid, path, node, kind, ts_ns):
        f = self.files.get(fid)
        if f is None:
            f = self.files[fid] = FileNode(fid)
            self._maybe_evict_files()
        else:
            self.files.move_to_end(fid)
        if path.startswith("/"):
            f.add_path(path)
            self.path_index[path] = fid
        f.access_count += 1
        f.accesses.append((ts_ns, node.key, kind))
        if len(f.accesses) > MAX_ACCESSES_PER_FILE:
            del f.accesses[0]
        if kind == WRITE:
            f.writes.append((ts_ns, node.key))
            if len(f.writes) > MAX_WRITES_PER_FILE:
                del f.writes[0]

    def record_connect(self, node, ts_ns, eid, ok):
        """One connect() attempt. `ok` means connected or still in flight;
        a failed attempt is counted but creates no causal edge."""
        self._touch(node, ts_ns)
        node.conn_count += 1
        if not ok:
            node.failed_conns += 1
        if eid is None:         # unnamed socket, or a family we do not model
            return
        node.conns.append((ts_ns, eid, ok))
        if len(node.conns) > MAX_CONNS_PER_PROC:
            del node.conns[0]
        e = self.endpoints.get(eid)
        if e is None:
            e = self.endpoints[eid] = EndpointNode(eid)
        else:
            self.endpoints.move_to_end(eid)
        e.access_count += 1
        if not ok:
            e.failed_count += 1
        e.accesses.append((ts_ns, node.key, CONNECT if ok else CONNECT_FAILED))
        if len(e.accesses) > MAX_ACCESSES_PER_ENDPOINT:
            del e.accesses[0]
        self._maybe_evict_endpoints()

    def record_accept(self, node, ts_ns, eid, has_peer=True):
        """One accepted inbound connection.

        There is no failure case to model: a failed accept means no
        connection was waiting (-EAGAIN on a polling listener, -EINTR on a
        signal), which is an absence rather than an attempt, and the kernel
        hook drops those before they reach us. Compare `record_connect`,
        where a refusal is kept precisely because that is what a port scan
        looks like from inside the host.

        `has_peer` is False when the kernel had no peer name to give — a
        server that called `accept(fd, NULL, NULL)`, or a unix client with
        no bound address. The connection is still counted; it just cannot
        be attributed to a peer, and saying so is better than inventing
        0.0.0.0.
        """
        self._touch(node, ts_ns)
        node.accept_count += 1
        if not has_peer:
            node.nopeer_accepts += 1
        if eid is None:
            return
        node.accepts.append((ts_ns, eid, has_peer))
        if len(node.accepts) > MAX_CONNS_PER_PROC:
            del node.accepts[0]
        e = self.endpoints.get(eid)
        if e is None:
            e = self.endpoints[eid] = EndpointNode(eid)
        else:
            self.endpoints.move_to_end(eid)
        e.access_count += 1
        e.accesses.append((ts_ns, node.key, ACCEPT))
        if len(e.accesses) > MAX_ACCESSES_PER_ENDPOINT:
            del e.accesses[0]
        self._maybe_evict_endpoints()

    def record_exit(self, node, ts_ns, status):
        node.alive = False
        node.exit_ns = ts_ns
        node.exit_status = status
        node.exit_inferred = False
        self._note_dead(node)
        self._touch(node, ts_ns)

    # ------------------------------------------------------------------
    # Startup snapshot
    # ------------------------------------------------------------------
    def bootstrap(self, procs, ts_ns):
        """Seed with processes that existed before the hooks attached.
        procs: dicts with pid, ppid, comm, uid, start_ns (an ESTIMATE)."""
        for p in sorted(procs, key=lambda p: p["start_ns"]):
            if p["pid"] in self.current:
                continue      # an event already described it: trust that
            parent_key = self.current.get(p["ppid"]) if p["ppid"] else None
            node = self._new_node(p["pid"], p["start_ns"], False, p["ppid"],
                                  parent_key, p["comm"], p.get("uid"), ts_ns)
            node.first_ns = p["start_ns"]
            # ...and keep the span the right way round. Setting only first_ns
            # left last_ns at the bootstrap timestamp, which is EARLIER
            # whenever the snapshot is taken before the clock passes the
            # estimated start, so _start_ts(backwards) read an inverted span.
            if node.last_ns < node.first_ns:
                node.last_ns = node.first_ns
            self.current[p["pid"]] = node.key

    # ------------------------------------------------------------------
    # Memory bounds
    # ------------------------------------------------------------------
    def _maybe_evict(self):
        """Evict exited processes down to 90 % of the cap.

        Only dead nodes are evictable — a live process still exists, so
        forgetting it would be a lie — which makes this a dead-node LRU and
        not a hard memory bound. That part is by design; what was not is how
        it behaved when dead nodes ran short.

        It used to rebuild `sorted(all dead nodes)` on EVERY call, and it is
        called on every node creation while over the cap. With plenty of dead
        nodes that is amortised fine, because one pass frees 10 % of the cap.
        With few, each call scanned every node, freed nothing, and returned —
        and since the count then kept growing, the next scan was longer, so
        the whole thing was quadratic while bounding nothing.

        Measured per node creation on a 2000-cap graph, as a multiple of an
        UNCAPPED baseline taken in the same round (unpaired runs on the test
        machine drift ~25 %, which is the size of some of these effects):

            dead nodes      before      after
              100 %          2.00x      1.79x
               50 %         13.62x      1.54x
               10 %         27.09x      1.34x
                0 %         32.07x      1.15x

        Final node counts are identical before and after at every fraction,
        so this is the same eviction policy, reached without the scan. Dead
        nodes are tracked as they die, and when nothing is evictable the pass
        returns in O(1) instead of re-proving it over every node.
        """
        if not self.max_nodes or len(self.nodes) <= self.max_nodes:
            return
        if not self._dead:
            return                      # nothing evictable; do not re-scan
        target = int(self.max_nodes * 0.9)
        # Oldest exit first, from the tracked NODES rather than their keys:
        # sorting keys would mean a dict lookup per element to reach exit_ns.
        # No figure is quoted for that: the one this comment used to carry
        # (+2 µs per node creation) had no harness behind it and sat at the
        # same magnitude as the run-to-run drift that already invented one
        # regression on this project (changelog §E row 177). The reason to
        # hold nodes is structural, not measured — _evict pops from here, and
        # it is the only place a node leaves self.nodes, so no membership
        # filtering is needed.
        for n in sorted(self._dead.values(), key=lambda n: n.exit_ns or 0):
            if len(self.nodes) <= target:
                break
            if n.key == self._protect:
                continue
            if n.key not in self.nodes:
                # Defence in depth. _note_dead refuses to file a node that is
                # not in the graph, so this should be unreachable — but the
                # consequence of being wrong was a KeyError on every later
                # node creation, for the rest of the run, so the pass drops
                # the entry instead of raising on it.
                self._dead.pop(n.key, None)
                continue
            self._evict(n)

    def _note_dead(self, node):
        """Called wherever a node stops being alive, so _maybe_evict never
        has to scan for candidates.

        A node that has already been evicted is NOT filed: it is no longer
        part of the graph, and filing it put a key in _dead that _evict would
        later fail to delete from self.nodes.
        """
        if node.key in self.nodes:
            self._dead[node.key] = node

    def _evict(self, node):
        del self.nodes[node.key]
        self._dead.pop(node.key, None)
        self.gens[node.pid].remove(node.key)
        if not self.gens[node.pid]:
            del self.gens[node.pid]
        if self.current.get(node.pid) == node.key:
            del self.current[node.pid]
        if node.parent_key in self.nodes:
            ch = self.nodes[node.parent_key].children
            if node.key in ch:
                ch.remove(node.key)
        self.stats["evicted"] += 1
        # Children keep a parent_key that no longer resolves; every query
        # treats a missing key as "lineage ends here".

    def _maybe_evict_files(self):
        if not self.max_files:
            return
        while len(self.files) > self.max_files:
            fid, f = self.files.popitem(last=False)
            for p in f.paths:
                if self.path_index.get(p) == fid:
                    del self.path_index[p]
            self.stats["evicted_files"] += 1

    def _maybe_evict_endpoints(self):
        """Endpoints need the same cap as files, and inbound is why.

        An outbound endpoint can only be created by a process on this host,
        so its growth is bounded by what the host does. An INBOUND one is
        created by whoever connects: any host on the network can mint a
        `host:<addr>` node by opening a socket, so without a cap the map is
        growable by a remote party — a resource-exhaustion path in the
        monitor itself, which is the last place one should be. LRU, same as
        files: least recently touched goes first.
        """
        if not self.max_endpoints:
            return
        while len(self.endpoints) > self.max_endpoints:
            self.endpoints.popitem(last=False)
            self.stats["evicted_endpoints"] += 1

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------
    def get(self, pid, gen=None):
        key = self.current.get(pid) if gen is None else (pid, gen)
        return self.nodes.get(key)

    def file(self, path_or_fid):
        f = self.files.get(path_or_fid)
        if f is None:
            fid = self.path_index.get(path_or_fid)
            f = self.files.get(fid) if fid else None
        return f

    def alive_nodes(self):
        """Newest lifetime of each PID that is still alive. O(PIDs), not
        O(all lifetimes ever seen) — used by the 1 s refresh."""
        out = []
        for key in self.current.values():
            n = self.nodes.get(key)
            if n is not None and n.alive:
                out.append(n)
        return out

    def lineage(self, node):
        """[root ... node], cycle-safe."""
        chain, seen = [], set()
        while node is not None and node.key not in seen:
            seen.add(node.key)
            chain.append(node)
            node = self.nodes.get(node.parent_key)
        chain.reverse()
        return chain

    def lineage_str(self, node):
        # _desc, not label(): a lineage and a walk must name the same node
        # the same way, or one report contradicts the other on a PID that
        # has been reused.
        return " → ".join(self._desc(n) for n in self.lineage(node))

    def roots(self):
        return [n for n in self.nodes.values()
                if n.parent_key is None or n.parent_key not in self.nodes]

    def render_tree(self, root=None, show_exited=True, hide_kernel=True,
                    max_lines=None, recent_ns=None, now_ns=None):
        """pstree-style text. Iterative with a visited set."""
        starts = [root] if root is not None else \
            sorted(self.roots(), key=lambda n: (n.pid, n.key[1]))
        lines, seen = [], set()
        stack = [(n, 0) for n in reversed(starts)]
        while stack:
            node, depth = stack.pop()
            if node.key in seen:
                continue
            seen.add(node.key)
            if hide_kernel and (node.pid == KERNEL_THREADD or node.ppid == KERNEL_THREADD):
                continue
            if not node.alive and not show_exited:
                recent = (recent_ns is not None and now_ns is not None
                          and node.exit_ns is not None
                          and now_ns - node.exit_ns <= recent_ns)
                if not recent:
                    continue
            mark = "" if node.alive else (" [exited?]" if node.exit_inferred else " [exited]")
            files = "  (%d files)" % node.file_count if node.file_count else ""
            # An orphan is not a root. If this node names a parent we no
            # longer hold (evicted), say so rather than drawing it beside
            # systemd as though it started by itself.
            if depth == 0 and node.parent_key is not None \
                    and node.parent_key not in self.nodes:
                mark += " [parent %d evicted]" % node.parent_key[0]
            lines.append("  " * depth + self._desc(node) + mark + files)
            if max_lines and len(lines) >= max_lines:
                lines.append("  ...")
                break
            kids = [self.nodes[k] for k in node.children if k in self.nodes]
            for child in sorted(kids, key=lambda n: (n.pid, n.key[1]), reverse=True):
                stack.append((child, depth + 1))
        # Nothing may be invisible. A parent_key cycle (bad data, or a
        # reparenting mistake) leaves nodes with no root to descend from,
        # and the tree then renders EMPTY — a live view that silently shows
        # no processes is the worst possible failure for a monitor, so
        # anything unreached is listed explicitly instead.
        if root is None and not (max_lines and len(lines) >= max_lines):
            orphaned = [n for k, n in self.nodes.items() if k not in seen
                        and not (hide_kernel and (n.pid == KERNEL_THREADD
                                                  or n.ppid == KERNEL_THREADD))]
            if orphaned:
                lines.append("(unreachable — parent cycle or missing link)")
                for n in sorted(orphaned, key=lambda n: (n.pid, n.key[1])):
                    lines.append("  " + self._desc(n))
        return "\n".join(lines)

    def top(self, n=10):
        alive = self.alive_nodes()
        alive.sort(key=lambda x: (x.cpu_percent, x.rss_kb), reverse=True)
        return alive[:n]

    @staticmethod
    def _fork_ts(node, bound=None):
        """When this process was forked — the honest timestamp for a FORK edge.

        Not `first_ns`: that is when we first *saw* an event for the node,
        which depends on record arrival order. The fork time is the process's
        start time, and when the kernel gave it to us exactly
        (`task->start_time`, same CLOCK_MONOTONIC as every event timestamp)
        it is both true and provably no later than any event of this node.
        A /proc-bootstrapped start is an estimate, so the earlier of the
        estimate and the first event is used instead.

        `bound` is a last-resort clamp: a walk must never report a cause
        dated after the point it is asking about, whatever the inputs look
        like.
        """
        ts = node.start_ns if node.start_exact else min(node.start_ns, node.first_ns)
        if bound is not None and ts > bound:
            return bound
        return ts

    @staticmethod
    def _cap_per_resource(items, newest=True, limit=None):
        """Keep at most `limit` edges per resource, newest (or earliest) first.

        `items` is [(ts, group_key, value)...]. Backward walks keep the
        NEWEST per resource, because the most recent access before the
        bound is the one that could have carried the current contents;
        forward walks keep the EARLIEST, because the earliest effect
        reaches the widest set of downstream nodes. Input order is
        preserved so the caller's sort still decides presentation.
        """
        limit = MAX_EDGES_PER_RESOURCE if limit is None else limit
        groups = {}
        for item in items:
            groups.setdefault(item[1], []).append(item)
        keep = set()
        # Selecting the top `limit` is O(n), where sorting the whole bucket to
        # slice `limit` off the front is O(n log n) — and a bucket can hold
        # every access one process made to one resource (up to
        # MAX_FILES_PER_PROC) to keep 8. heapq.nlargest/nsmallest resolve
        # equal keys exactly as sorted(reverse=...)[:n] does, which matters
        # because timestamp ties decide which edge a walk shows; there is a
        # test asserting that equivalence against the old implementation.
        pick = heapq.nlargest if newest else heapq.nsmallest
        for bucket in groups.values():
            if len(bucket) <= limit:
                keep.update(id(it) for it in bucket)
                continue
            keep.update(id(it) for it in pick(limit, bucket, key=_first))
        return [it for it in items if id(it) in keep]

    def _in_edges(self, node, before_ns):
        """Everything that could have influenced `node` before `before_ns`."""
        out = []
        parent = self.nodes.get(node.parent_key)
        if parent is not None:
            # The fork obeys the bound like every other edge kind. This was
            # the backward mirror of the H1 bug: the FORK branch used to be
            # listed unconditionally, with its timestamp CLAMPED to the
            # bound, so asking "what caused this as of t=0" reported a
            # parent dated 0 for a process forked at 10 s — a cause that had
            # not happened yet, wearing a made-up timestamp. If the fork is
            # after the point being asked about, the honest answer is that
            # this process did not exist yet, so nothing about it is a cause.
            fork_ts = self._fork_ts(node)
            if fork_ts <= before_ns:
                out.append((fork_ts, FORK, parent))
        # Reads, execs and connections are collected with the resource they
        # name, so repeated access to ONE resource cannot crowd out every
        # other input (see MAX_EDGES_PER_RESOURCE).
        grouped = []
        for ts, _path, mode, _ret, fid in node.files:
            if ts <= before_ns and "R" in mode and fid in self.files:
                grouped.append((ts, (READ, fid), self.files[fid]))
        for e in node.execs:
            if e.ts_ns <= before_ns and e.fid in self.files:
                grouped.append((e.ts_ns, (EXEC, e.fid), self.files[e.fid]))
        # A connection that succeeded before this point could have carried
        # data in — that is how "downloaded, then written to disk" becomes a
        # traceable chain. Failed attempts carried nothing, so they are not
        # causes.
        for ts, eid, ok in node.conns:
            if ok and ts <= before_ns and eid in self.endpoints:
                grouped.append((ts, (CONNECT, eid), self.endpoints[eid]))
        # An accepted connection is an input by construction: something
        # outside reached in. There is no "ok" to check — only successful
        # accepts are recorded at all.
        for ts, eid, _has_peer in node.accepts:
            if ts <= before_ns and eid in self.endpoints:
                grouped.append((ts, (ACCEPT, eid), self.endpoints[eid]))
        for ts, (kind, _rid), obj in self._cap_per_resource(grouped, newest=True):
            out.append((ts, kind, obj))
        return out

    def _start_ts(self, x, backwards):
        """Where in time a walk begins, for any node type.

        A process carries its own span. A file or an endpoint does not: the
        walk starts at its latest access going backwards (every earlier
        cause is in scope) and at its earliest going forwards (everything it
        later influenced is in scope). Before this existed, a walk could
        only start at a process, so "where did this file come from?" — asked
        of the file itself — raised AttributeError.
        """
        if isinstance(x, ProcessNode):
            if not x.own_span:
                # No event of this node's own has been seen, so first_ns and
                # last_ns are a stamp borrowed from whatever forced it into
                # existence — for a placeholder parent, a CHILD's event, at a
                # time later than its own fork. Starting a forward walk there
                # begins AFTER the fork it is supposed to report, so
                # trace_forward returned nothing for a process whose only
                # known effect is the child that created it, while
                # render_tree showed the edge (found by the independent
                # review of v3.6). Its birth is the one time we do know, and
                # for a node with no observed activity it is the right bound
                # in both directions: nothing else can be a cause or an
                # effect of a process we have never seen do anything.
                return self._fork_ts(x)
            return x.last_ns if backwards else x.first_ns
        times = [ts for ts, _k, _kind in x.accesses]
        if not times:
            return 0
        return max(times) if backwards else min(times)

    @staticmethod
    def _ident(x):
        if isinstance(x, ProcessNode):
            return ("P", x.key)
        if isinstance(x, EndpointNode):
            return ("E", x.eid)
        return ("F", x.fid)

    def _desc(self, x):
        """How a node is named in a walk's output.

        Plain labels are ambiguous in exactly two situations, and in both
        the graph — unlike the node — knows it:

        * two generations of one PID both render `nc(777)`, so a walk
          result cannot say WHICH process wrote the file. The whole point
          of generations is that they are different processes;
        * a path whose file was replaced: two inode nodes both render
          `/tmp/x`, and one of them is no longer the file at that path.

        The discriminator is added only when the ambiguity is real, so the
        common case reads exactly as before.
        """
        if isinstance(x, ProcessNode):
            if len(self.gens.get(x.pid, ())) > 1:
                return "%s(%d#%d)" % (x.comm or "?", x.pid, x.key[1])
            return x.label()
        if isinstance(x, FileNode) and x.paths:
            current = self.path_index.get(x.paths[-1])
            if current is not None and current != x.fid:
                return "%s#%s" % (x.paths[-1], self._disc(x.fid))
        return x.label

    @staticmethod
    def _disc(fid):
        """The part of a file id that tells two files at one path apart.

        Two corrections from the v3.5i report. W1-F2: this was
        `fid.split(":")[2]`, which raises IndexError on any id with fewer
        than three parts — the kernel never makes one, but `from_dict` will
        load one, and a single poisoned snapshot record then crashed every
        walk query. W1-F3: the slice took the inode number ALONE, so
        `inode:1:5:0` and `inode:2:5:1` both rendered `/tmp/x#5` — ambiguous
        in exactly the case the discriminator exists for. Low inode numbers
        recur on every filesystem, so same-ino/different-dev is realistic
        (bind mounts, remounts). Use dev:ino:gen.
        """
        if fid.startswith("inode:"):
            parts = fid.split(":")
            if len(parts) > 3:
                return ":".join(parts[1:])
        return fid

    def trace_back(self, node, max_depth=6, max_items=200, skip=None,
                   max_visits=4000, at_ns=None, trace=None):
        """Root-cause walk, BACKWARDS in time.

        From a process: its parent, and files it read/executed before the
        point of interest. From a file: processes that wrote it before it
        was read. `skip(file_node) -> bool` drops noisy files (shared
        libraries...) — the dependency-explosion problem.
        Returns [(depth, edge_kind, ts_ns, description)].

        Three suppressions, and the differences matter. Collapsing any two
        of them has already cost this project a bug each time.

        * `seen` stops a node being **expanded** twice *for the same time
          bound*. The bound is part of the state because a resource reached
          at two different times is two different questions: a file read at
          100 s and again at 296 s has, under last-write-wins, two
          different correct answers. Keying `seen` on the node alone made
          the second read inherit the first read's writer — a confidently
          WRONG answer, not merely a missing edge (CHANGES_v3.5 row 101).
        * `listed` stops the same (source, kind, timestamp) edge being
          printed twice, which re-expansion would otherwise cause. An edge
          already emitted leads to an identical sub-walk, so it is skipped
          entirely rather than merely hidden.
        * `via` — the (node, edge_kind) link we arrived on — stops an edge
          being **listed** as its own cause, which would just echo the step
          we came from (endpoint -> the process we reached it from).

        Nothing else is suppressed. In particular an already-seen node is
        still listed when reached by a *different* kind of edge: a parent
        shell that writes a file its child reads is both a FORK and a WRITE,
        and those are two different causal facts. Confusing the two rules is
        what broke the v3.4 walk (CHANGES_v3.4 row 80).

        Termination: a node expands at most once per distinct bound, and
        bounds come only from timestamps already in the graph, so the state
        space is finite. `max_visits` additionally bounds the WORK (not just
        the output) for the pathological shape — one file touched thousands
        of times — where deduped edges could otherwise keep the queue busy
        without growing the result.

        `trace(event, info)` is an optional observer, called at every step
        with event in {"start", "pop", "skip", "emit", "dedup", "echo",
        "stop"} and a dict of the state. It exists so the algorithm can
        explain itself — `tools/walk_trace.py` prints a step-by-step dry
        run with it — without a second copy of the loop that could drift
        from this one. It never changes what the walk returns.
        """
        result, seen, listed = [], set(), set()
        visits = 0
        # `at_ns` asks the point-in-time question: "what had caused this as
        # of time T", which is what an analyst looking at an alert
        # timestamp actually wants. Without it the walk starts at the
        # node's own latest activity, which is the right default but
        # cannot answer "...and what did we know at 14:32".
        start = self._start_ts(node, True) if at_ns is None else at_ns
        if trace:
            trace("start", {"node": self._desc(node), "bound": start,
                            "at_ns": at_ns})
        queue = deque([(node, start, 0, None)])
        while queue and len(result) < max_items and visits < max_visits:
            cur, t, depth, via = queue.popleft()
            ident = self._ident(cur)
            if depth >= max_depth or (ident, t) in seen:
                if trace:
                    trace("skip", {"node": self._desc(cur), "bound": t,
                                   "depth": depth, "queue": len(queue),
                                   "why": "max_depth" if depth >= max_depth
                                          else "seen (node, bound)"})
                continue
            seen.add((ident, t))
            visits += 1
            if trace:
                trace("pop", {"node": self._desc(cur), "bound": t,
                              "depth": depth, "visits": visits,
                              "queue": len(queue), "via": via})

            def emit(src, kind, ts, depth=depth):
                """List an edge and queue its source, once."""
                key = (self._ident(src), kind, ts)
                if key in listed:
                    if trace:
                        trace("dedup", {"node": self._desc(src), "kind": kind,
                                        "ts": ts, "depth": depth + 1})
                    return
                listed.add(key)
                result.append((depth + 1, kind, ts, self._desc(src)))
                queue.append((src, ts, depth + 1, (ident, kind)))
                if trace:
                    trace("emit", {"node": self._desc(src), "kind": kind,
                                   "ts": ts, "depth": depth + 1,
                                   "queue": len(queue)})

            if isinstance(cur, ProcessNode):
                for ts, kind, src in self._in_edges(cur, t):
                    if not isinstance(src, ProcessNode) and skip and skip(src):
                        if trace:
                            trace("skip", {"node": self._desc(src), "kind": kind,
                                           "ts": ts, "why": "skip() — noisy"})
                        continue
                    if (self._ident(src), kind) == via:
                        if trace:
                            trace("echo", {"node": self._desc(src), "kind": kind,
                                           "ts": ts,
                                           "why": "would echo the link we came on"})
                        continue
                    emit(src, kind, ts)
            elif isinstance(cur, EndpointNode):
                # Who opened this connection: the last process to reach this
                # peer before the point of interest. Same single-cause rule
                # as for files — every earlier contact is a separate episode,
                # not a cause of this one.
                conns = [(ts, key, kind) for ts, key, kind in cur.accesses
                         if kind in (CONNECT, ACCEPT) and ts <= t
                         and key in self.nodes]
                if conns:
                    ts, key, kind = max(conns)
                    pr = self.nodes[key]
                    if trace:
                        trace("choose", {"node": self._desc(pr), "kind": kind,
                                         "ts": ts, "of": len(conns),
                                         "why": "last contact at or before the bound"})
                    if (self._ident(pr), kind) != via:
                        emit(pr, kind, ts)
                    elif trace:
                        trace("echo", {"node": self._desc(pr), "kind": kind,
                                       "ts": ts,
                                       "why": "would echo the link we came on"})
            else:
                # Dependency explosion: a file written N times has N formal
                # causes, but only the LAST write before this read can have
                # influenced it — earlier contents were overwritten.
                # (Kairos/SLEUTH solve this with file versioning; this is the
                # cheap equivalent. On the v3.5 VM capture this took a
                # read with 130 candidate causes down to 1; no run id was
                # recorded with that figure, so treat it as illustrative of
                # the shape, not as a measurement to quote.)
                # From `writes`, not `accesses`: the causal list cannot be
                # flushed by reads, and it is ~8x shorter to scan.
                writes = [(ts, key) for ts, key in cur.writes
                          if ts <= t and key in self.nodes]
                if writes:
                    ts, key = max(writes)
                    w = self.nodes[key]
                    if trace:
                        trace("choose", {"node": self._desc(w), "kind": WRITE,
                                         "ts": ts, "of": len(writes),
                                         "why": "last write at or before the bound "
                                                "(earlier contents were overwritten)"})
                    if (self._ident(w), WRITE) != via:
                        emit(w, WRITE, ts)
                    elif trace:
                        trace("echo", {"node": self._desc(w), "kind": WRITE,
                                       "ts": ts,
                                       "why": "would echo the link we came on"})
        if trace:
            trace("stop", {"edges": len(result), "visits": visits,
                           "queue_left": len(queue), "seen": len(seen),
                           "listed": len(listed),
                           "why": "queue empty" if not queue else
                                  ("max_items" if len(result) >= max_items
                                   else "max_visits")})
        return result[:max_items]

    def trace_forward(self, node, max_depth=6, max_items=200, skip=None,
                      max_visits=4000, at_ns=None, trace=None):
        """Impact walk: what did this process influence AFTER it started?

        The mirror of `trace_back`, under the same three suppression rules
        (`seen` keyed by node AND bound, `listed`, `via`) and the same time
        law — nothing is listed as an effect unless it happened at or after
        the point being asked about. Every branch therefore tests
        `ts >= t`, FORK included: a child forked at 41 s is not an effect of
        a file read at 50 s, and listing it as one was a real bug
        (CHANGES_v3.5 row 100).
        """
        result, seen, listed = [], set(), set()
        visits = 0
        start = self._start_ts(node, False) if at_ns is None else at_ns
        if trace:
            trace("start", {"node": self._desc(node), "bound": start,
                            "at_ns": at_ns})
        queue = deque([(node, start, 0, None)])
        while queue and len(result) < max_items and visits < max_visits:
            cur, t, depth, via = queue.popleft()
            ident = self._ident(cur)
            if depth >= max_depth or (ident, t) in seen:
                if trace:
                    trace("skip", {"node": self._desc(cur), "bound": t,
                                   "depth": depth, "queue": len(queue),
                                   "why": "max_depth" if depth >= max_depth
                                          else "seen (node, bound)"})
                continue
            seen.add((ident, t))
            visits += 1
            if trace:
                trace("pop", {"node": self._desc(cur), "bound": t,
                              "depth": depth, "visits": visits,
                              "queue": len(queue), "via": via})

            def emit(dst, kind, ts, depth=depth):
                key = (self._ident(dst), kind, ts)
                if key in listed:
                    if trace:
                        trace("dedup", {"node": self._desc(dst), "kind": kind,
                                        "ts": ts, "depth": depth + 1})
                    return
                listed.add(key)
                result.append((depth + 1, kind, ts, self._desc(dst)))
                queue.append((dst, ts, depth + 1, (ident, kind)))
                if trace:
                    trace("emit", {"node": self._desc(dst), "kind": kind,
                                   "ts": ts, "depth": depth + 1,
                                   "queue": len(queue)})

            if isinstance(cur, ProcessNode):
                for k in cur.children:
                    child = self.nodes.get(k)
                    if child is None:
                        continue
                    ts = self._fork_ts(child)
                    if ts >= t:
                        emit(child, FORK, ts)
                    elif trace:
                        trace("skip", {"node": self._desc(child), "kind": FORK,
                                       "ts": ts,
                                       "why": "forked BEFORE the bound — cannot "
                                              "be an effect of it"})
                # Same per-resource cap as the backward walk, keeping the
                # EARLIEST effects: the first write to a file reaches every
                # later reader, so forward it is the one that matters.
                grouped = []
                for ts, _path, mode, _ret, fid in cur.files:
                    f = self.files.get(fid)
                    if "W" in mode and ts >= t and f is not None:
                        grouped.append((ts, (WRITE, fid), f))
                for ts, eid, ok in cur.conns:
                    e = self.endpoints.get(eid)
                    if ok and ts >= t and e is not None:
                        grouped.append((ts, (CONNECT, eid), e))
                for ts, eid, _has_peer in cur.accepts:
                    e = self.endpoints.get(eid)
                    if ts >= t and e is not None:
                        grouped.append((ts, (ACCEPT, eid), e))
                for ts, (kind, _rid), obj in self._cap_per_resource(grouped,
                                                                    newest=False):
                    if skip and skip(obj):
                        continue
                    if (self._ident(obj), kind) == via:
                        continue
                    emit(obj, kind, ts)
            elif isinstance(cur, EndpointNode):
                grouped = [(ts, (kind, key), self.nodes[key])
                           for ts, key, kind in cur.accesses
                           if kind in (CONNECT, ACCEPT) and ts >= t
                           and key in self.nodes]
                for ts, (kind, _rid), r in self._cap_per_resource(grouped,
                                                                  newest=False):
                    # same rule as trace_back: never echo the link we
                    # arrived on, list every other one
                    if (self._ident(r), kind) == via:
                        continue
                    emit(r, kind, ts)
            else:
                grouped = [(ts, (kind, key), self.nodes[key])
                           for ts, key, kind in cur.accesses
                           if kind in (READ, EXEC) and ts >= t
                           and key in self.nodes]
                for ts, (kind, _rid), r in self._cap_per_resource(grouped,
                                                                  newest=False):
                    if (self._ident(r), kind) == via:
                        if trace:
                            trace("echo", {"node": self._desc(r), "kind": kind,
                                           "ts": ts,
                                           "why": "would echo the link we came on"})
                        continue
                    emit(r, kind, ts)
        if trace:
            trace("stop", {"edges": len(result), "visits": visits,
                           "queue_left": len(queue), "seen": len(seen),
                           "listed": len(listed),
                           "why": "queue empty" if not queue else
                                  ("max_items" if len(result) >= max_items
                                   else "max_visits")})
        return result[:max_items]

    def summary(self):
        alive = sum(1 for n in self.nodes.values() if n.alive)
        out = {"processes": len(self.nodes), "alive": alive,
               "exited": len(self.nodes) - alive, "files": len(self.files),
               "endpoints": len(self.endpoints),
               # Hosts that reached IN, counted apart from endpoints we
               # reached out to: one is a service's clientele, the other is
               # this host's own behaviour, and a detector wants them apart.
               "inbound_hosts": sum(1 for e in self.endpoints.values()
                                    if any(k == ACCEPT for _ts, _key, k
                                           in e.accesses))}
        out.update(self.stats)
        return out

    # ------------------------------------------------------------------
    # Snapshot (JSON) — the queryable-store step before DuckDB/ClickHouse
    # ------------------------------------------------------------------
    def to_dict(self):
        return {
            "version": 4,
            "processes": [n.to_dict() for n in self.nodes.values()],
            "files": [{"fid": f.fid, "paths": f.paths, "access_count": f.access_count,
                       "accesses": [[ts, list(k), kind] for ts, k, kind in f.accesses],
                       "writes": [[ts, list(k)] for ts, k in f.writes]}
                      for f in self.files.values()],
            "endpoints": [{"eid": e.eid, "access_count": e.access_count,
                           "failed_count": e.failed_count,
                           "accesses": [[ts, list(k), kind] for ts, k, kind in e.accesses]}
                          for e in self.endpoints.values()],
            "current": [[pid, list(k)] for pid, k in self.current.items()],
            "stats": self.stats,
        }

    # Fields a v4 snapshot must carry for a process entry. Checked up front so
    # a malformed snapshot fails with its own name attached rather than a bare
    # KeyError from somewhere inside the loader (v3.5i report W1-F6).
    _REQUIRED_PROC = ("pid", "gen", "start_ns", "start_exact", "ppid", "parent",
                      "comm", "uid", "first_ns", "children", "execs",
                      "failed_execs", "files", "reparented_from")
    # The loader reads more than the list above: everything in _PLAIN is
    # fetched with p[k]. Listing the fields by hand covered 14 of 24, so ten
    # of them still raised a bare KeyError from inside the loop — and the
    # regression test happened to delete one of the covered ones, so it
    # passed while the fix was half done. Derive the set from what the loader
    # actually reads instead.
    _REQUIRED_FILE = ("fid", "paths", "access_count", "accesses")
    _REQUIRED_ENDPOINT = ("eid", "access_count", "failed_count", "accesses")

    @classmethod
    def from_dict(cls, d):
        if d.get("version") != 4:
            raise ValueError("snapshot version %r not supported (need 4)" % d.get("version"))
        for what in ("processes", "files", "current"):
            if what not in d:
                raise ValueError("snapshot is missing %r" % what)
        if not isinstance(d["processes"], list):
            raise ValueError("snapshot 'processes' is %s, not a list"
                             % type(d["processes"]).__name__)
        required = tuple(cls._REQUIRED_PROC) + tuple(ProcessNode._PLAIN)
        # Validated BEFORE the sort, because the sort key reads pid and gen
        # and would raise a bare KeyError first.
        for p in d["processes"]:
            if not isinstance(p, dict):
                raise ValueError("process entry is %s, not an object"
                                 % type(p).__name__)
            missing = [k for k in required if k not in p]
            if missing:
                raise ValueError("process entry %r is missing %s"
                                 % (p.get("pid", "?"), ", ".join(missing)))
            for k in ("pid", "gen"):
                if not isinstance(p[k], int) or isinstance(p[k], bool) or p[k] < 0:
                    raise ValueError("process %r has a bad %s: %r"
                                     % (p.get("pid", "?"), k, p[k]))
        g = cls()
        seen_keys = set()
        for p in sorted(d["processes"], key=lambda x: (x["pid"], x["gen"])):
            key = (p["pid"], p["gen"])
            if key in seen_keys:
                # Loaded silently before, which left gens[pid] holding the
                # same key twice and rendered a bogus discriminator.
                raise ValueError("duplicate process (pid %s, gen %s)" % key)
            seen_keys.add(key)
            n = ProcessNode(key, p["start_ns"], p["start_exact"], p["ppid"],
                            tuple(p["parent"]) if p["parent"] else None,
                            p["comm"], p["uid"], p["first_ns"])
            for k in ProcessNode._PLAIN:
                setattr(n, k, p[k])
            for k in ProcessNode._PLAIN_OPT:
                setattr(n, k, p.get(k, True if k == "own_span" else 0))
            n.children = [tuple(k) for k in p["children"]]
            n.execs = [ExecRecord(**e) for e in p["execs"]]
            n.failed_execs = [tuple(x) for x in p["failed_execs"]]
            n.files = [tuple(x) for x in p["files"]]
            n.conns = [tuple(x) for x in p.get("conns", [])]
            n.accepts = [tuple(x) for x in p.get("accepts", [])]
            n.reparented_from = tuple(p["reparented_from"]) if p["reparented_from"] else None
            g.nodes[key] = n
            g.gens.setdefault(key[0], []).append(key)
            if not n.alive:
                g._dead[key] = n
        for f in d["files"]:
            missing = [k for k in cls._REQUIRED_FILE if k not in f]
            if missing:
                raise ValueError("file entry %r is missing %s"
                                 % (f.get("fid", "?"), ", ".join(missing)))
            fn = FileNode(f["fid"])
            fn.paths = list(f["paths"])
            fn.access_count = f["access_count"]
            fn.accesses = [(ts, tuple(k), kind) for ts, k, kind in f["accesses"]]
            # Pre-v3.5d snapshots have no separate causal list: rebuild it
            # from the activity log so an old capture still answers
            # "who wrote this?" exactly as it did before.
            if "writes" in f:
                fn.writes = [(ts, tuple(k)) for ts, k in f["writes"]]
            else:
                fn.writes = [(ts, k) for ts, k, kind in fn.accesses if kind == WRITE]
            g.files[fn.fid] = fn
            for p in fn.paths:
                g.path_index[p] = fn.fid
        for e in d.get("endpoints", []):
            missing = [k for k in cls._REQUIRED_ENDPOINT if k not in e]
            if missing:
                raise ValueError("endpoint entry %r is missing %s"
                                 % (e.get("eid", "?"), ", ".join(missing)))
            en = EndpointNode(e["eid"])
            en.access_count = e["access_count"]
            en.failed_count = e["failed_count"]
            en.accesses = [(ts, tuple(k), kind) for ts, k, kind in e["accesses"]]
            g.endpoints[en.eid] = en
        g.current = {pid: tuple(k) for pid, k in d["current"]}
        g.stats.update(d.get("stats", {}))
        # Same oldest-first order the live path maintains, so a restored graph
        # and a freshly built one answer gens queries identically.
        for pid, keys in g.gens.items():
            keys.sort(key=lambda k: (g.nodes[k].start_ns, k[1]))
            g._gen_hwm[pid] = max(k[1] for k in keys)
        return g
