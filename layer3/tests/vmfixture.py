"""Helpers for the real-VM fixture (layer3/fixtures/s1_mixed).

Kept apart from the tests so the two things that need care, unpacking a
tarball and deriving the clock anchor, are each written once.
"""

import datetime
import hashlib
import json
import os
import tarfile

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE_DIR = os.path.join(os.path.dirname(HERE), "fixtures", "s1_mixed")
BUNDLE = os.path.join(FIXTURE_DIR, "s1_mixed_bundle.tgz")
BUNDLE_SHA256 = "2fb46b7235ec983049a4cef3df7901ac1edea2a24964af4ff1736a4a38e36149"
VM_UTC_OFFSET_HOURS = -4          # the VM's timezone (Ashu, 20 Oct 2026)
EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)

MEMBERS = ("s1_mixed.p15r", "s1_mixed.p15r.bootstrap.json", "s1_mixed.jsonl",
           "s1_mixed.stats.json", "s1_mixed.snapshot.json", "s1_markers.txt",
           "s1_workload.sh")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def manifest():
    """{relative path: sha256} from SHA256SUMS."""
    out = {}
    with open(os.path.join(FIXTURE_DIR, "SHA256SUMS")) as f:
        for line in f:
            digest, name = line.split(None, 1)
            out[name.strip()] = digest
    return out


def extract(dest):
    """Unpack the bundle into `dest` and return {member: path}.

    Refuses anything except the seven expected regular files with plain
    names. A tarball is untrusted input: a member called "../x" or a
    symlink would otherwise write outside `dest`. Python 3.8's tarfile has
    no extraction filter, so the check is done here, by hand, before
    anything is written.
    """
    if sha256(BUNDLE) != BUNDLE_SHA256:
        raise ValueError("fixture bundle hash mismatch: %s" % BUNDLE)
    with tarfile.open(BUNDLE, "r:gz") as t:
        members = t.getmembers()
        names = sorted(m.name for m in members)
        if names != sorted(MEMBERS) or not all(m.isfile() for m in members):
            raise ValueError("unexpected fixture contents: %r" % names)
        for m in members:
            src = t.extractfile(m)
            with open(os.path.join(dest, m.name), "wb") as out:
                out.write(src.read())
    return {n: os.path.join(dest, n) for n in MEMBERS}


def markers(path):
    """[(epoch_ns, step)] in file order."""
    with open(path) as f:
        return [(int(a), b) for a, b in (line.split() for line in f if line.strip())]


def wall_offset_interval(jsonl_path, utc_offset_hours=VM_UTC_OFFSET_HOURS):
    """(lo, hi): the true wall-minus-monotonic offset lies in [lo, hi).

    Each line's `time` is local wall time truncated to the millisecond
    (hids.events.Clock.fmt), so its true wall time lies in [time, time+1ms).
    Hence, per line, offset is in [time - ts_ns, time - ts_ns + 1 ms).
    Intersecting over every line gives the interval. An empty intersection
    (lo >= hi) would mean the log is inconsistent with one fixed offset,
    for example a suspend or a clock step, and is raised rather than
    averaged away.
    """
    tz = datetime.timezone(datetime.timedelta(hours=utc_offset_hours))
    lo = hi = None
    with open(jsonl_path) as f:
        for line in f:
            x = json.loads(line)
            t = datetime.datetime.strptime(x["time"], "%Y-%m-%d %H:%M:%S.%f")
            t = t.replace(tzinfo=tz)
            # Integer arithmetic only: whole seconds by floor division of
            # timedeltas, then the microseconds. No float near 1.8e9.
            secs = (t - EPOCH) // datetime.timedelta(seconds=1)
            wall = secs * 10 ** 9 + t.microsecond * 1000
            d = wall - x["ts_ns"]
            lo = d if lo is None else max(lo, d)
            hi = d + 10 ** 6 if hi is None else min(hi, d + 10 ** 6)
    if lo is None or lo >= hi:
        raise ValueError("no single wall offset fits %s" % jsonl_path)
    return lo, hi
