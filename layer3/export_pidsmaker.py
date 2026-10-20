"""export_pidsmaker.py — P15R recording -> PIDSMaker `entities.tsv` + `edges.tsv`.

Stage S1 of the detection track (LANDSCAPE plan §5.1). The target is the
loader in PIDSMaker `spider` @ 0a0f41d,
`scripts/provenance_capture/create_database_provenance_benign.py`. What that
loader does decides most of the rules below, so they are listed once here:

  entities.tsv   line 0 skipped; each line `rstrip("\\n").split("\\t", 2)`;
                 index_id = int(entity_id.rsplit("_", 1)[-1]), and an id that
                 fails that is SKIPPED WITHOUT A WORD. PROC text is split at
                 the first space into (path, cmd); SOCK text is split on
                 whitespace into src_addr src_port dst_addr dst_port.
  edges.tsv      line 0 skipped; `split("\\t")`; an edge whose src or dst id is
                 not an entity is skipped (counted on their side, not ours);
                 timestamp = int(float(text) * 1e9); event_uuid = line number.
                 The event type string is stored as-is, never validated.
  file reading   open(path, "r"): text mode, universal newlines, so a bare
                 "\\r" ends a line just as "\\n" does.

Three consequences drive the design:

  * Their loader fails SILENTLY (skips) on exactly the mistakes an exporter
    makes — a bad id suffix, a dangling edge endpoint, a tab inside a path.
    So this file never relies on their loader to complain: every such rule
    is asserted by a test here (layer3/tests/test_export_s1.py).
  * Paths, argv and unix socket names are ATTACKER-CONTROLLED strings. A
    path containing "\\t" or "\\n" would otherwise shift columns or forge a
    whole extra edge line. Everything written passes through `tsv_escape`.
  * Several mappings are open design decisions owned by the project, not by
    this file. Each one is an `ExportOptions` field with a stated
    provisional default, and every export writes the values it was made
    under into export_meta.json — an export always says which decisions it
    embodies.

Nothing is dropped silently. Anything the exporter declines to emit is
counted under `dropped` (stderr summary, return value, export_meta.json),
and things the GRAPH never turned into an edge (failed opens, relative paths
with no inode, ...) are counted under `graph_non_edges` so a reader can tell
"the exporter lost it" from "there was never an edge".

stdlib only; Python 3.8 (the VM runs 3.8.10).
"""

import argparse
import hashlib
import json
import os
import sys
from collections import Counter, OrderedDict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:          # so `python3 layer3/export_pidsmaker.py` works too
    sys.path.insert(0, ROOT)

from hids import __version__ as HIDS_VERSION          # noqa: E402
from hids import replay as replay_mod                  # noqa: E402
from hids.events import Clock, decode                  # noqa: E402
from hids.graph import MAX_CONNS_PER_PROC, ProcessGraph  # noqa: E402
from hids.processor import EventProcessor              # noqa: E402

EXPORTER_VERSION = "s1.0"

# PIDSMaker's `rel2id_darpa_tc` — the 10 relation types its models know.
# A type outside this set loads into Postgres (their loader stores the
# string unchanged) but has no relation id, so featurisation cannot use it.
PIDSMAKER_VOCAB = ("EVENT_CONNECT", "EVENT_EXECUTE", "EVENT_OPEN", "EVENT_READ",
                   "EVENT_RECVFROM", "EVENT_RECVMSG", "EVENT_SENDMSG",
                   "EVENT_SENDTO", "EVENT_WRITE", "EVENT_CLONE")

ENTITIES_HEADER = "entity_id\tentity_type\tentity_text"
EDGES_HEADER = "src_id\tevent_type\tdst_id\ttimestamp"

# Entity kinds, in the order their indices are handed out.
PROC, FILE, SOCK = "PROC", "FILE", "SOCK"
_RANK = {PROC: 0, FILE: 1, SOCK: 2}

NS = 10 ** 9


# ---------------------------------------------------------------------------
# Open decisions. Each is a field with a provisional default; the CLI exposes
# every one, and export_meta.json records the values used.
# ---------------------------------------------------------------------------
class ExportOptions(object):
    """The open design decisions, as values.

    ts               D23. "float-s": decimal unix-style seconds, which their
                     loader reads as-is. We write the EXACT ns value as
                     "<s>.<9 digits>"; the loss happens in THEIR float()
                     (up to a few hundred ns near today's epoch — pinned by a
                     test). "int-ns": integer ns, lossless, but their loader
                     line must be patched first (it would multiply by 1e9).
    wall_offset_ns   Time base. Graph timestamps are CLOCK_MONOTONIC ns since
                     boot — live AND replayed — and a P15R recording carries
                     no wall-clock anchor. This many ns are added to every
                     timestamp. 0 (default) exports boot-relative time, and
                     the meta says so.
    open_as          D9. The graph records open() with a mode R/W/RW; it
                     never sees read()/write(). "rw": R -> READ file->proc,
                     W -> WRITE proc->file, RW -> BOTH (exactly what
                     ProcessGraph.record_open itself records). "rw-writeonly":
                     like PIDSMaker's audit mapper, RW -> WRITE only.
                     "open": one EVENT_OPEN proc->file per open (D9); the
                     mode is not representable in the 4-column contract and
                     is only counted in the meta.
    accept_as        D24. "connect": an accepted connection becomes
                     EVENT_CONNECT sock->proc (their mapper; in vocabulary).
                     "accept": EVENT_ACCEPT sock->proc (D10) — OUTSIDE their
                     10-type vocabulary, flagged in the meta.
    failed_connects  The graph keeps refused connects but never treats them
                     as causal. "drop" (default, counted) or "connect" (emit
                     as EVENT_CONNECT proc->sock anyway).
    unix_endpoints   "sock" (default): unix-socket peers become SOCK entities
                     with the path in dst_addr. "drop": counted and omitted.
    sock_placeholder Token written into SOCK fields the graph does not know.
                     Must be one non-empty, whitespace-free token, or their
                     whitespace split would shift the fields.
    clone_parent     "graph" (default): CLONE comes from the node's current
                     parent_key, as the graph's own walks use it. After a
                     reparent that is the REAPER (init/subreaper), not the
                     process that forked. "original": use reparented_from
                     when the graph kept it.
    probe_endpoints  glibc's getaddrinfo() connect()s a UDP socket to port 0
                     per candidate address (hids.graph.probe_endpoint); the
                     graph keeps these as real connects but its walks skip
                     them as noise. "keep" (default: they are real syscalls,
                     and S1 conserves the graph) or "drop" (counted).
    """

    CHOICES = OrderedDict([
        ("ts", ("float-s", "int-ns")),
        ("open_as", ("rw", "rw-writeonly", "open")),
        ("accept_as", ("connect", "accept")),
        ("failed_connects", ("drop", "connect")),
        ("unix_endpoints", ("sock", "drop")),
        ("clone_parent", ("graph", "original")),
        ("probe_endpoints", ("keep", "drop")),
    ])
    DEFAULTS = OrderedDict([
        ("ts", "float-s"),
        ("wall_offset_ns", 0),
        ("open_as", "rw"),
        ("accept_as", "connect"),
        ("failed_connects", "drop"),
        ("unix_endpoints", "sock"),
        ("sock_placeholder", "NA"),
        ("clone_parent", "graph"),
        ("probe_endpoints", "keep"),
    ])

    def __init__(self, **kw):
        unknown = set(kw) - set(self.DEFAULTS)
        if unknown:
            raise TypeError("unknown export option(s): %s" % ", ".join(sorted(unknown)))
        for k, v in self.DEFAULTS.items():
            setattr(self, k, kw.get(k, v))
        for k, allowed in self.CHOICES.items():
            if getattr(self, k) not in allowed:
                raise ValueError("%s must be one of %s, not %r"
                                 % (k, "/".join(allowed), getattr(self, k)))
        if not isinstance(self.wall_offset_ns, int) or isinstance(self.wall_offset_ns, bool) \
                or self.wall_offset_ns < 0:
            # An epoch offset is "wall - monotonic", which is positive on any
            # real machine; a negative one could only produce negative times.
            raise ValueError("wall_offset_ns must be a non-negative integer")
        p = self.sock_placeholder
        if not isinstance(p, str) or not p or p != tsv_escape(p, space=True):
            raise ValueError("sock_placeholder must be one plain token, got %r" % (p,))

    def as_dict(self):
        return OrderedDict((k, getattr(self, k)) for k in self.DEFAULTS)


# ---------------------------------------------------------------------------
# Escaping. One reversible rule for every field we write.
# ---------------------------------------------------------------------------
# Characters that would break a TSV line or their loader's parse:
#   "\t"  shifts columns            "\n", "\r"  end the line (universal newlines)
#   "\\"  must itself be escaped, or "a\\tb" (backslash, t) and "a<TAB>b" would
#         both come out as "a\\tb" and the rule would not be reversible.
# Every other control character (and the Unicode line/paragraph separators,
# and lone surrogates, which UTF-8 cannot even encode) becomes \xHH / \uHHHH.
# With space=True any whitespace becomes \xHH/\uHHHH: used for fields the
# loader splits on whitespace (the exe part of PROC text, every SOCK token) and for ids, so
# an id is always one shell token.
_LETTER = {"\\": "\\\\", "\t": "\\t", "\n": "\\n", "\r": "\\r"}


def _needs_hex(o):
    return o < 0x20 or o == 0x7f or 0x80 <= o < 0xa0 or o in (0x2028, 0x2029) \
        or 0xd800 <= o <= 0xdfff


def tsv_escape(s, space=False):
    out = []
    for ch in s:
        if ch in _LETTER:
            out.append(_LETTER[ch])
            continue
        o = ord(ch)
        # str.isspace, not == " ": their SOCK parse is text.split(), which
        # splits on EVERY Unicode whitespace (NBSP, U+2000-U+200A, U+3000...).
        if (space and ch.isspace()) or _needs_hex(o):
            out.append("\\x%02x" % o if o < 0x100 else "\\u%04x" % o)
        else:
            out.append(ch)
    return "".join(out)


def tsv_unescape(s):
    """Inverse of tsv_escape (for readers and tests)."""
    out, i, n = [], 0, len(s)
    while i < n:
        ch = s[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        nxt = s[i + 1:i + 2]
        if nxt in ("\\", "t", "n", "r"):
            out.append({"\\": "\\", "t": "\t", "n": "\n", "r": "\r"}[nxt])
            i += 2
        elif nxt == "x":
            out.append(chr(int(s[i + 2:i + 4], 16)))
            i += 4
        elif nxt == "u":
            out.append(chr(int(s[i + 2:i + 6], 16)))
            i += 6
        else:
            raise ValueError("bad escape at %d in %r" % (i, s))
    return "".join(out)


def format_ts(ns, mode):
    """Exact text for an integer-ns timestamp. Never goes through a float:
    whatever precision is lost, it is lost in the reader, not here."""
    if ns < 0:
        raise ValueError("negative timestamp %d" % ns)
    if mode == "int-ns":
        return str(ns)
    s, frac = divmod(ns, NS)
    return "%d.%09d" % (s, frac)


# ---------------------------------------------------------------------------
# Canonical node identity. A node's canonical key is what the GRAPH calls it;
# the TSV id is that key, escaped, plus "_<index>".
# ---------------------------------------------------------------------------
def proc_key(key):
    return (PROC, (key[0], key[1]))


def file_key(fid):
    return (FILE, fid)


def sock_key(eid):
    return (SOCK, eid)


def canon_str(ck):
    kind, k = ck
    if kind == PROC:
        return "proc:%d:%d" % k          # (pid, gen): the graph's own key
    if kind == FILE:
        return "file:" + k               # inode:<dev>:<ino>:<gen> or path:<abs>
    return "sock:" + k                   # net:<a>:<p> | host:<a> | unix:<path>


def _sort_key(ck):
    # Rank first, so tuples of different kinds are never compared.
    return (_RANK[ck[0]], ck[1])


# ---------------------------------------------------------------------------
# Entity text
# ---------------------------------------------------------------------------
def _split_endpoint(eid):
    """eid -> (scheme, addr, port_or_None). See hids.events.endpoint_id."""
    scheme, _, rest = eid.partition(":")
    if scheme == "net":
        addr, _, port = rest.rpartition(":")
        return scheme, addr.strip("[]"), port
    if scheme == "host":
        return scheme, rest.strip("[]"), None
    if scheme == "unix":
        return scheme, rest, None
    return scheme, rest, None


def sock_text(eid, placeholder):
    """`src_addr src_port dst_addr dst_port`, as their mapper lays it out:
    the PEER goes in src_* for inbound and in dst_* for outbound.

      net:<a>:<p>  outbound peer   -> NA NA <a> <p>
      host:<a>     inbound peer    -> <a> NA NA NA
                   (no peer port: the graph deliberately drops the client's
                   ephemeral port, events.inbound_endpoint_id; our own local
                   port is not in the graph either)
      unix:<path>  named socket    -> NA NA <path> NA
                   (the graph uses ONE node for connects to and accepts from
                   a unix name, so it gets one layout: the name as dst)
    Our own local address/port is never in the graph, hence the placeholders.
    """
    scheme, addr, port = _split_endpoint(eid)
    P = placeholder
    e = lambda t: tsv_escape(t, space=True) or P          # noqa: E731
    if scheme == "net":
        return " ".join((P, P, e(addr), e(port)))
    if scheme == "host":
        return " ".join((e(addr), P, P, P))
    return " ".join((P, P, e(addr), P))


def proc_text(node):
    """`<exe> <cmdline>` from the node's LAST exec. Their loader splits at
    the first space, so spaces inside exe are escaped and the cmdline keeps
    its own. A process with no exec seen (a fork that never exec'd, a
    bootstrap or placeholder node) has no exe: its comm stands in, and the
    meta counts how often (`proc_text_from_comm`)."""
    exe = node.exe
    if not exe:
        return tsv_escape(node.comm or "?", space=True), True
    cmd = node.cmdline
    text = tsv_escape(exe, space=True)
    if cmd:
        text += " " + tsv_escape(cmd)
    return text, False


# ---------------------------------------------------------------------------
# Collect: graph -> (entities, edges, report). Pure; reads the graph only.
# ---------------------------------------------------------------------------
def collect(graph, opts=None):
    """Turn a ProcessGraph into rows. Returns (entities, edges, report).

    entities: [(entity_id, type, text)], sorted, ids dense 0..N-1
    edges:    [(src_id, EVENT_TYPE, dst_id, ts_text)], time-ordered
    report:   counts, dropped, graph_non_edges (see module docstring)

    Edges are read from the PROCESS side of the graph (node.files, .execs,
    .conns, .accepts, .parent_key): that is where each event's path and
    timestamp live, and it survives file/endpoint LRU eviction. The S1(a)
    test rebuilds the expected edge multiset from the RESOURCE side
    (FileNode/EndpointNode.accesses, children lists) — a different code path
    — so the two can disagree when the exporter is wrong.

    Under the graph's caps the two sides legitimately differ: a FILE or
    ENDPOINT evicted by LRU is still named by its readers' histories, so its
    edges are exported (the entity text then comes from the open record's
    own path); a PROCESS evicted after exiting takes its edges with it, and
    those are counted in report["graph_history_capped"]. With the monitor's
    default caps neither happens below 200 000 files / 25 000 endpoints,
    and processes are never evicted (max_nodes=0).
    """
    opts = opts or ExportOptions()
    dropped = Counter()
    non_edges = Counter()
    capped = Counter()
    raw = []                 # (ts_ns, EVENT, src_ck, dst_ck)
    file_paths = {}          # fid -> (ts, path) newest name seen in a record
    open_modes = Counter()

    def note_path(fid, ts, path):
        cur = file_paths.get(fid)
        if path and (cur is None or (ts, path) > cur):
            file_paths[fid] = (ts, path)

    for key, node in graph.nodes.items():
        P = proc_key(key)

        # CLONE parent -> child, at the graph's own honest fork time.
        parent = node.parent_key
        if opts.clone_parent == "original" and node.reparented_from is not None \
                and node.reparented_from in graph.nodes:
            parent = node.reparented_from
        if parent is not None:
            if parent in graph.nodes:
                raw.append((ProcessGraph._fork_ts(node), "EVENT_CLONE",
                            proc_key(parent), P))
            else:
                dropped["clone_parent_not_in_graph"] += 1   # evicted parent

        # open(): mode decides the edge(s). See ExportOptions.open_as.
        non_edges["failed_opens"] += node.failed_opens
        for ts, path, mode, _ret, fid in node.files:
            if fid is None:
                continue            # counted by the graph as unresolved_opens
            F = file_key(fid)
            note_path(fid, ts, path)
            open_modes[mode] += 1
            if opts.open_as == "open":
                raw.append((ts, "EVENT_OPEN", P, F))
                continue
            if "R" in mode:
                if opts.open_as == "rw-writeonly" and "W" in mode:
                    dropped["rw_open_read_collapsed"] += 1
                else:
                    raw.append((ts, "EVENT_READ", F, P))
            if "W" in mode:
                raw.append((ts, "EVENT_WRITE", P, F))
        non_edges["unresolved_opens"] += node.unresolved_opens
        # The graph caps per-process history (MAX_FILES_PER_PROC, oldest
        # first). Those opens were never available to export; say how many.
        capped["opens_trimmed_by_graph_cap"] += max(0, node.file_count - len(node.files))
        if len(node.conns) >= MAX_CONNS_PER_PROC:
            capped["procs_at_connect_cap"] += 1
        if len(node.accepts) >= MAX_CONNS_PER_PROC:
            capped["procs_at_accept_cap"] += 1

        # exec: the image flows INTO the process.
        for rec in node.execs:
            if rec.fid:
                note_path(rec.fid, rec.ts_ns, rec.filename)
                raw.append((rec.ts_ns, "EVENT_EXECUTE", file_key(rec.fid), P))
            else:
                non_edges["exec_without_file_id"] += 1
        non_edges["failed_execs"] += len(node.failed_execs)

        # outbound connect: actor -> peer.
        for ts, eid, ok in node.conns:
            if eid.startswith("unix:") and opts.unix_endpoints == "drop":
                dropped["unix_endpoint_edges"] += 1
                continue
            if opts.probe_endpoints == "drop" and eid.startswith("net:") \
                    and eid.endswith(":0"):
                dropped["probe_endpoint_edges"] += 1
                continue
            if not ok:
                if opts.failed_connects == "drop":
                    dropped["failed_connect"] += 1
                    continue
            raw.append((ts, "EVENT_CONNECT", P, sock_key(eid)))
        # inbound accept: the peer reached in, so peer -> process.
        etype = "EVENT_CONNECT" if opts.accept_as == "connect" else "EVENT_ACCEPT"
        for ts, eid, _has_peer in node.accepts:
            if eid.startswith("unix:") and opts.unix_endpoints == "drop":
                dropped["unix_endpoint_edges"] += 1
                continue
            raw.append((ts, etype, sock_key(eid), P))
        non_edges["accept_without_peer"] += node.nopeer_accepts
        # connect() calls with no endpoint id (unnamed unix socket, unknown
        # family) are counted by the graph but never stored; cap-trimmed
        # ones are folded in here too because the graph cannot tell them
        # apart.
        non_edges["connects_not_in_history"] += node.conn_count - len(node.conns)

    # Edges the graph lost to its OWN eviction (max_nodes / max_files /
    # max_endpoints). An evicted process takes its history with it, but the
    # files and endpoints it touched still list it; count those accesses so
    # an export from a capped graph says how much it is missing.
    for res in list(graph.files.values()) + list(graph.endpoints.values()):
        for _ts, k, _kind in res.accesses:
            if k not in graph.nodes:
                capped["accesses_by_evicted_processes"] += 1

    # Endpoint schemes we do not know how to lay out (only reachable from a
    # hand-edited snapshot) are dropped by name, never guessed at.
    kept = []
    for ts, et, s, d in raw:
        bad = [c for c in (s, d) if c[0] == SOCK
               and _split_endpoint(c[1])[0] not in ("net", "host", "unix")]
        if bad:
            dropped["unknown_endpoint_scheme"] += 1
            continue
        kept.append((ts, et, s, d))
    raw = kept

    # Entities = exactly the nodes some edge references (referential
    # integrity both ways). Index order is sorted canonical key, so it does
    # not depend on dict or set iteration order anywhere.
    referenced = set()
    for _ts, _et, s, d in raw:
        referenced.add(s)
        referenced.add(d)
    ordered = sorted(referenced, key=_sort_key)
    ids = {}
    entities = []
    from_comm = 0
    for idx, ck in enumerate(ordered):
        eid = "%s_%d" % (tsv_escape(canon_str(ck), space=True), idx)
        ids[ck] = eid
        kind, k = ck
        if kind == PROC:
            text, fallback = proc_text(graph.nodes[k])
            from_comm += fallback
        elif kind == FILE:
            f = graph.files.get(k)
            if f is not None and f.paths:
                name = f.paths[-1]
            elif k in file_paths:
                name = file_paths[k][1]
            else:
                name = k
            text = tsv_escape(name)
        else:
            text = sock_text(k, opts.sock_placeholder)
        entities.append((eid, kind, text))

    # Time order, with a total tiebreak on canonical keys — never on
    # iteration order.
    raw.sort(key=lambda r: (r[0], r[1], _sort_key(r[2]), _sort_key(r[3])))
    off = opts.wall_offset_ns
    edges = [(ids[s], et, ids[d], format_ts(ts + off, opts.ts))
             for ts, et, s, d in raw]

    nodes_by_type = Counter()
    nodes_by_type[PROC] = len(graph.nodes)
    nodes_by_type[FILE] = len(graph.files)
    nodes_by_type[SOCK] = len(graph.endpoints)
    ent_by_type = Counter(e[1] for e in entities)
    out_of_vocab = sorted(set(e[1] for e in edges) - set(PIDSMAKER_VOCAB))
    report = OrderedDict([
        ("edges", len(edges)),
        ("entities", len(entities)),
        ("edges_by_type", OrderedDict(sorted(Counter(e[1] for e in edges).items()))),
        ("entities_by_type", OrderedDict(sorted(ent_by_type.items()))),
        # Graph nodes with no exported edge are not written (entities are
        # exactly the referenced nodes); counted so nothing vanishes unseen.
        ("graph_nodes_without_edges", OrderedDict(
            (t, nodes_by_type[t] - ent_by_type.get(t, 0)) for t in (PROC, FILE, SOCK))),
        ("dropped", OrderedDict(sorted(dropped.items()))),
        ("graph_non_edges", OrderedDict(sorted((k, v) for k, v in non_edges.items()))),
        ("graph_history_capped", OrderedDict(
            (k, capped.get(k, 0)) for k in ("accesses_by_evicted_processes",
                                             "opens_trimmed_by_graph_cap",
                                             "procs_at_connect_cap",
                                             "procs_at_accept_cap"))),
        ("open_modes", OrderedDict(sorted(open_modes.items()))),
        ("proc_text_from_comm", from_comm),
        ("out_of_vocabulary_types", out_of_vocab),
        ("graph_stats", OrderedDict(sorted(graph.stats.items()))),
    ])
    return entities, edges, report


# ---------------------------------------------------------------------------
# Input: a recording, through the SAME replay wiring monitor.py uses.
# ---------------------------------------------------------------------------
def build_graph_from_recording(path, bootstrap=True, max_nodes=0,
                               max_files=200000, max_endpoints=25000):
    """Replay a P15R file into a fresh graph, as `hids.monitor --replay` does
    (monitor.py, the replay branch of main()): Clock.offset pinned to 0, a
    VirtualClock driving exec expiry, the bootstrap sidecar if present, and
    the monitor's default caps. Returns (graph, info)."""
    replay_mod.peek_header(path)
    clock = Clock()
    clock.offset = 0.0
    vclock = replay_mod.VirtualClock()
    graph = ProcessGraph(max_nodes=max_nodes or None, max_files=max_files or None,
                         max_endpoints=max_endpoints or None)
    proc = EventProcessor(graph, clock, mono=vclock)
    seeded = 0
    if bootstrap:
        boot = replay_mod.read_bootstrap(path)
        if boot is not None:
            graph.bootstrap(boot[0], boot[1])
            seeded = len(boot[0])
    decoded, bad = replay_mod.run(path, proc, vclock, decode)
    st = proc.stats()
    info = OrderedDict([
        ("records_decoded", decoded),
        ("records_undecodable", bad),
        ("processor_errors", st["records"]["errors"]),
        ("bootstrap_processes", seeded),
        ("caps", OrderedDict([("max_nodes", max_nodes), ("max_files", max_files),
                              ("max_endpoints", max_endpoints)])),
    ])
    return graph, info


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_export(out_dir, entities, edges, meta):
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    # newline="\n": the line terminator is part of the contract, not the
    # platform's choice. UTF-8 explicitly; escaping already removed anything
    # UTF-8 cannot encode.
    with open(os.path.join(out_dir, "entities.tsv"), "w", encoding="utf-8",
              newline="\n") as f:
        f.write(ENTITIES_HEADER + "\n")
        for row in entities:
            f.write("\t".join(row) + "\n")
    with open(os.path.join(out_dir, "edges.tsv"), "w", encoding="utf-8",
              newline="\n") as f:
        f.write(EDGES_HEADER + "\n")
        for row in edges:
            f.write("\t".join(row) + "\n")
    with open(os.path.join(out_dir, "export_meta.json"), "w", encoding="utf-8",
              newline="\n") as f:
        json.dump(meta, f, indent=2, sort_keys=True)
        f.write("\n")


def _meta(opts, report, source):
    time_base = ("monotonic-since-boot (wall_offset_ns=0): NOT unix epoch"
                 if opts.wall_offset_ns == 0 else
                 "monotonic + wall_offset_ns (caller-supplied anchor)")
    return OrderedDict([
        ("exporter", "layer3/export_pidsmaker.py"),
        ("exporter_version", EXPORTER_VERSION),
        ("hids_version", HIDS_VERSION),
        ("contract", "PIDSMaker spider@0a0f41d create_database_provenance_benign.py"),
        ("source", source),
        ("options", opts.as_dict()),
        ("time_base", time_base),
        ("loader_patch_required", opts.ts == "int-ns"),
        ("escaping", "backslash: \\\\ \\t \\n \\r, other controls \\xHH/\\uHHHH; "
                     "spaces also escaped (\\x20) in ids, PROC exe, SOCK tokens"),
        ("report", report),
    ])


def export_graph(graph, out_dir, opts=None, source=None):
    """Export an in-memory graph. Returns the report dict."""
    opts = opts or ExportOptions()
    entities, edges, report = collect(graph, opts)
    write_export(out_dir, entities, edges, _meta(opts, report, source or OrderedDict()))
    return report


def export_recording(path, out_dir, opts=None, bootstrap=True, **caps):
    """P15R file -> out_dir/{entities,edges}.tsv + export_meta.json.
    Returns the report dict (also written into the meta)."""
    opts = opts or ExportOptions()
    graph, info = build_graph_from_recording(path, bootstrap=bootstrap, **caps)
    source = OrderedDict([("recording", path), ("recording_sha256", sha256_file(path))])
    bp = replay_mod.bootstrap_path(path)
    used_boot = bootstrap and os.path.exists(bp)
    source["bootstrap_sidecar_sha256"] = sha256_file(bp) if used_boot else None
    source["replay"] = info
    return export_graph(graph, out_dir, opts, source)


def summarize(report, opts, out=sys.stderr):
    w = out.write
    w("export: %d edges, %d entities\n" % (report["edges"], report["entities"]))
    w("  edges:    %s\n" % ", ".join("%s=%d" % kv for kv in report["edges_by_type"].items()))
    w("  entities: %s\n" % ", ".join("%s=%d" % kv for kv in report["entities_by_type"].items()))
    if report["dropped"]:
        w("  DROPPED by exporter: %s\n" % ", ".join("%s=%d" % kv for kv in report["dropped"].items()))
    else:
        w("  dropped by exporter: none\n")
    cz = [(k, v) for k, v in report["graph_history_capped"].items() if v]
    if cz:
        w("  WARNING: lost to the graph's own caps: %s\n"
          % ", ".join("%s=%d" % kv for kv in cz))
    nz = [(k, v) for k, v in report["graph_non_edges"].items() if v]
    if nz:
        w("  never edges in the graph: %s\n" % ", ".join("%s=%d" % kv for kv in nz))
    if report["out_of_vocabulary_types"]:
        w("  WARNING: types outside PIDSMaker's 10: %s\n"
          % ", ".join(report["out_of_vocabulary_types"]))
    if opts.wall_offset_ns == 0:
        w("  WARNING: timestamps are boot-relative CLOCK_MONOTONIC, not unix "
          "epoch (no --wall-offset-ns given)\n")
    if opts.ts == "int-ns":
        w("  WARNING: --ts int-ns needs the PIDSMaker loader patched\n")


def parse_args(argv=None):
    d = ExportOptions.DEFAULTS
    p = argparse.ArgumentParser(
        description="P15R recording -> PIDSMaker entities.tsv/edges.tsv (stage S1)")
    p.add_argument("recording", help="a --record-raw file")
    p.add_argument("out_dir")
    p.add_argument("--ts", choices=ExportOptions.CHOICES["ts"], default=d["ts"],
                   help="D23 timestamp text (default %(default)s)")
    p.add_argument("--wall-offset-ns", type=int, default=d["wall_offset_ns"],
                   help="ns added to every (monotonic) timestamp; 0 = export "
                        "boot-relative time (default %(default)s)")
    p.add_argument("--open-as", choices=ExportOptions.CHOICES["open_as"],
                   default=d["open_as"], help="D9 open mapping (default %(default)s)")
    p.add_argument("--accept-as", choices=ExportOptions.CHOICES["accept_as"],
                   default=d["accept_as"], help="D24 accept mapping (default %(default)s)")
    p.add_argument("--failed-connects", choices=ExportOptions.CHOICES["failed_connects"],
                   default=d["failed_connects"])
    p.add_argument("--unix-endpoints", choices=ExportOptions.CHOICES["unix_endpoints"],
                   default=d["unix_endpoints"])
    p.add_argument("--sock-placeholder", default=d["sock_placeholder"])
    p.add_argument("--clone-parent", choices=ExportOptions.CHOICES["clone_parent"],
                   default=d["clone_parent"])
    p.add_argument("--probe-endpoints", choices=ExportOptions.CHOICES["probe_endpoints"],
                   default=d["probe_endpoints"])
    p.add_argument("--no-bootstrap", action="store_true",
                   help="ignore the recording's bootstrap sidecar")
    p.add_argument("--max-nodes", type=int, default=0)
    p.add_argument("--max-files", type=int, default=200000)
    p.add_argument("--max-endpoints", type=int, default=25000)
    return p.parse_args(argv)


def main(argv=None):
    a = parse_args(argv)
    try:
        opts = ExportOptions(ts=a.ts, wall_offset_ns=a.wall_offset_ns,
                             open_as=a.open_as, accept_as=a.accept_as,
                             failed_connects=a.failed_connects,
                             unix_endpoints=a.unix_endpoints,
                             sock_placeholder=a.sock_placeholder,
                             clone_parent=a.clone_parent,
                             probe_endpoints=a.probe_endpoints)
        report = export_recording(a.recording, a.out_dir, opts,
                                  bootstrap=not a.no_bootstrap,
                                  max_nodes=a.max_nodes, max_files=a.max_files,
                                  max_endpoints=a.max_endpoints)
    except (OSError, ValueError) as e:
        sys.stderr.write("[ERROR] %s\n" % e)
        return 2
    summarize(report, opts)
    return 0


if __name__ == "__main__":
    sys.exit(main())
