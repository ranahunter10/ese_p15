#!/usr/bin/env python3
"""Mutation check for the S1 gates. Proves each gate test can fail.

    python3 layer3/tests/mutate_s1.py          # all mutants
    python3 layer3/tests/mutate_s1.py B2 C1    # some

For every mutant: copy hids/ and layer3/ to a fresh temp dir, apply ONE
exact text replacement to the copy's export_pidsmaker.py, run the named
killing test(s) there, and require them to FAIL. The worktree is never
modified, so no mutant can be left behind. The unmutated copy is run
first and must pass, or every "kill" would be meaningless.

Not a test_*.py file on purpose: it runs the suite dozens of times, and
`layer3/run_tests.sh` must stay fast. Its output is recorded in
layer3/tests/MUTANTS_S1.md.
"""

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
TARGET = os.path.join("layer3", "export_pidsmaker.py")

T = "layer3.tests.test_export_s1."
CONS = T + "ConservationGateTest"
DET = T + "DeterminismGateTest"
DIR = T + "DirectionGateTest"

# (id, gate, what it breaks, old text, new text, killing tests)
MUTANTS = [
    ("A1", "S1(a)", "drop the last edge",
     "             for ts, et, s, d in raw]",
     "             for ts, et, s, d in raw[:-1]]",
     [CONS + ".test_every_graph_edge_appears_exactly_once_under_every_option_set"]),
    ("A2", "S1(a)", "emit the first edge twice",
     "             for ts, et, s, d in raw]",
     "             for ts, et, s, d in raw + raw[:1]]",
     [CONS + ".test_every_graph_edge_appears_exactly_once_under_every_option_set"]),
    ("A3", "S1(a)", "drop one edge AND duplicate another (count unchanged)",
     "             for ts, et, s, d in raw]",
     "             for ts, et, s, d in raw[1:] + raw[-1:]]",
     [CONS + ".test_every_graph_edge_appears_exactly_once_under_every_option_set"]),
    ("A4", "S1(a)", "non-unique _<int> suffix (idx // 2)",
     'eid = "%s_%d" % (tsv_escape(canon_str(ck), space=True), idx)',
     'eid = "%s_%d" % (tsv_escape(canon_str(ck), space=True), idx // 2)',
     [CONS + ".test_every_id_survives_their_index_parse"]),
    ("A5", "S1(a)", "id suffix their int() cannot parse ('-' separator)",
     'eid = "%s_%d" % (tsv_escape(canon_str(ck), space=True), idx)',
     'eid = "%s-%d" % (tsv_escape(canon_str(ck), space=True), idx)',
     [CONS + ".test_every_id_survives_their_index_parse"]),
    ("A6", "S1(a)", "one referenced entity not written (dangling edges)",
     "        entities.append((eid, kind, text))",
     "        if idx != 3:\n            entities.append((eid, kind, text))",
     [CONS + ".test_every_graph_edge_appears_exactly_once_under_every_option_set",
      CONS + ".test_entities_are_exactly_the_referenced_nodes"]),
    ("A7", "S1(a)", "drop failed connects WITHOUT counting them",
     '                    dropped["failed_connect"] += 1\n',
     "",
     [CONS + ".test_every_graph_edge_appears_exactly_once_under_every_option_set"]),
    ("B1", "S1(b)", "tiebreak by arrival order (sort on ts only, stable)",
     "    raw.sort(key=lambda r: (r[0], r[1], _sort_key(r[2]), _sort_key(r[3])))",
     "    raw.sort(key=lambda r: r[0])",
     [DET + ".test_arrival_order_of_tied_records_does_not_change_the_export"]),
    ("B2", "S1(b)", "entity index order = set iteration order",
     "    ordered = sorted(referenced, key=_sort_key)",
     "    ordered = list(referenced)",
     [DET + ".test_hash_randomisation_does_not_reach_the_output"]),
    ("B3", "S1(b)", "wall-clock time leaks into export_meta.json",
     '        ("exporter_version", EXPORTER_VERSION),',
     '        ("exporter_version", EXPORTER_VERSION),\n'
     '        ("exported_at", __import__("time").time()),',
     [DET + ".test_two_fresh_replays_export_byte_identical_files"]),
    ("C1", "S1(c)", "READ written process->file",
     '                    raw.append((ts, "EVENT_READ", F, P))',
     '                    raw.append((ts, "EVENT_READ", P, F))',
     [DIR + ".test_read_is_file_to_process"]),
    ("C2", "S1(c)", "EXECUTE written process->file",
     '                raw.append((rec.ts_ns, "EVENT_EXECUTE", file_key(rec.fid), P))',
     '                raw.append((rec.ts_ns, "EVENT_EXECUTE", P, file_key(rec.fid)))',
     [DIR + ".test_execute_is_file_to_process"]),
    ("C3", "S1(c)", "WRITE written file->process",
     '                raw.append((ts, "EVENT_WRITE", P, F))',
     '                raw.append((ts, "EVENT_WRITE", F, P))',
     [DIR + ".test_write_is_process_to_file"]),
    ("C4", "S1(c)", "CLONE written child->parent",
     "                            proc_key(parent), P))",
     "                            P, proc_key(parent)))",
     [DIR + ".test_clone_is_parent_to_child"]),
    ("C5", "S1(c)", "accept written process->socket",
     "            raw.append((ts, etype, sock_key(eid), P))",
     "            raw.append((ts, etype, P, sock_key(eid)))",
     [DIR + ".test_accept_is_socket_to_process_as_connect_by_default"]),
    ("C6", "S1(c)", "outbound connect written socket->process",
     '            raw.append((ts, "EVENT_CONNECT", P, sock_key(eid)))',
     '            raw.append((ts, "EVENT_CONNECT", sock_key(eid), P))',
     [DIR + ".test_outbound_connect_is_process_to_socket"]),
    ("C7", "S1(c)", "RW open emits READ only (WRITE lost)",
     '            if "W" in mode:\n                raw.append((ts, "EVENT_WRITE", P, F))',
     '            if mode == "W":\n                raw.append((ts, "EVENT_WRITE", P, F))',
     [DIR + ".test_a_read_write_open_is_both_directions_by_default"]),
    # Contract details guarded outside the three gates.
    # (Deleting "\n" from _LETTER alone is an EQUIVALENT mutant: _needs_hex
    # still escapes it as \x0a. Recorded in MUTANTS_S1.md, not run here.)
    ("E1", "escaping", "a raw newline passes through unescaped",
     "    for ch in s:\n        if ch in _LETTER:",
     "    for ch in s:\n        if ch == \"\\n\":\n            out.append(ch)\n"
     "            continue\n        if ch in _LETTER:",
     [T + "HostileStringsTest.test_a_hostile_path_cannot_add_lines_or_columns"]),
    ("E2", "escaping", "backslash no longer escaped (not reversible)",
     '_LETTER = {"\\\\": "\\\\\\\\", "\\t": "\\\\t", "\\n": "\\\\n", "\\r": "\\\\r"}',
     '_LETTER = {"\\t": "\\\\t", "\\n": "\\\\n", "\\r": "\\\\r"}',
     [T + "HostileStringsTest.test_escaping_is_injective_on_the_classic_collision"]),
    ("T1", "D23", "timestamp text formatted through a float",
     '    return "%d.%09d" % (s, frac)',
     '    return "%.9f" % (ns / 1e9)',
     [T + "TimestampTest.test_float_seconds_text_is_exact_on_our_side"]),
]


def _copy_tree(dst):
    for sub in ("hids", "layer3"):
        shutil.copytree(os.path.join(ROOT, sub), os.path.join(dst, sub),
                        ignore=shutil.ignore_patterns("__pycache__"))


def _run(tree, tests):
    p = subprocess.run([sys.executable, "-m", "unittest"] + tests, cwd=tree,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       universal_newlines=True)
    last = [l for l in p.stdout.splitlines() if l.startswith(("FAILED", "OK", "Ran"))]
    return p.returncode, " ".join(last)


def main(argv):
    want = set(argv)
    rows, bad = [], 0
    with tempfile.TemporaryDirectory(prefix="p15mut") as base:
        clean = os.path.join(base, "clean")
        _copy_tree(clean)
        every = sorted(set(t for m in MUTANTS for t in m[5]))
        rc, out = _run(clean, every)
        print("baseline (unmutated): rc=%d %s" % (rc, out))
        if rc != 0:
            print("BASELINE FAILS: kills below would mean nothing")
            return 2
        for mid, gate, what, old, new, tests in MUTANTS:
            if want and mid not in want:
                continue
            tree = os.path.join(base, mid)
            _copy_tree(tree)
            path = os.path.join(tree, TARGET)
            with open(path) as f:
                src = f.read()
            n = src.count(old)
            if n != 1:
                print("%s: target text found %d times — mutant not applied" % (mid, n))
                bad += 1
                continue
            with open(path, "w") as f:
                f.write(src.replace(old, new))
            rc, out = _run(tree, tests)
            killed = rc != 0
            bad += not killed
            rows.append((mid, gate, what, killed, tests, out))
            print("%s %-8s %-6s %s  [%s]" % (mid, "KILLED" if killed else "SURVIVED",
                                            gate, what, out))
    print("\n%d mutants, %d killed, %d not" % (len(rows), sum(r[3] for r in rows), bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
