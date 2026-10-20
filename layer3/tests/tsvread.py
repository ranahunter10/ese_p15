"""Read an export back the way PIDSMaker's loader does, plus strict checks.

`loader_view` copies the parse in create_database_provenance_benign.py
(spider @ 0a0f41d): open(path, "r") in text mode — universal newlines, so
"\\r" also ends a line — skip line 0, entities `rstrip("\\n").split("\\t", 2)`,
edges `rstrip("\\n").split("\\t")`, index = int(id.rsplit("_", 1)[-1]).
Tests use it to see what THEY would see, not what we meant to write.
"""

import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
if ROOT not in sys.path:
    sys.path.insert(0, os.path.abspath(ROOT))

from layer3.export_pidsmaker import tsv_unescape   # noqa: E402

ID_RE = re.compile(r"^.+_\d+$")


def loader_view(out_dir):
    """-> (entities [(id, type, text)], edges [(src, type, dst, ts)], raw
    line counts) as their loader would split them."""
    with open(os.path.join(out_dir, "entities.tsv"), "r") as f:
        ent_lines = f.readlines()
    with open(os.path.join(out_dir, "edges.tsv"), "r") as f:
        edge_lines = f.readlines()
    ents = [tuple(l.rstrip("\n").split("\t", 2)) for l in ent_lines[1:]]
    edges = [tuple(l.rstrip("\n").split("\t")) for l in edge_lines[1:]]
    return ents, edges, (len(ent_lines), len(edge_lines))


def their_index(entity_id):
    return int(entity_id.rsplit("_", 1)[-1])


def their_ts_ns(text):
    return int(float(text) * 1e9)


def canon_of(entity_id):
    """Entity id -> the canonical node string it was minted from."""
    return tsv_unescape(entity_id.rsplit("_", 1)[0])


def canonical_edges(out_dir):
    """Edges as (ts_text, type, src_canon, dst_canon), via the entity ids."""
    ents, edges, _ = loader_view(out_dir)
    known = set(e[0] for e in ents)
    out = []
    for s, t, d, ts in edges:
        assert s in known and d in known, (s, d)
        out.append((ts, t, canon_of(s), canon_of(d)))
    return out
