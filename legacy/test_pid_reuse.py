#!/usr/bin/env python3
"""
Deterministic test of a PID-reuse staleness risk in process_monitor_v2's
pid_cache — see Engineering Journal (bottleneck review, Aug 2026).

This does NOT need root and does NOT load any eBPF program — it imports
process_monitor_v2 as a plain Python module. That's safe because BPF()
is only ever called inside main(), which is guarded by
`if __name__ == "__main__":`. Importing just gives us access to the
get_lineage() / _resolve() / pid_cache functions and data to test
directly, without needing a real kernel event to trigger them.

Run with:
    python3 test_pid_reuse.py
(from the same folder as process_monitor_v2.py)
"""

from types import SimpleNamespace
import process_monitor_v2 as mon

print("=" * 70)
print("STEP 1 — a child process reports its parent as PID 1390 (\"cat\")")
print("=" * 70)
# This is the ONLY way pid_cache learns about 1390 in this test — not
# from 1390's own event, but from someone reporting it as their parent.
# That's realistic: we may never capture a short-lived process's own
# event directly, but still learn its identity as someone else's ppid.
child_event = SimpleNamespace(pid=2000, ppid=1390)
mon.get_lineage(child_event, "child_proc", "cat")
print(f"pid_cache[1390] after this = {mon.pid_cache.get(1390)}")
print()

print("=" * 70)
print("STEP 2 — later, ask _resolve(1390) directly, simulating a lookup")
print("         long after the original 'cat' process is gone")
print("=" * 70)
result = mon._resolve(1390)
print(f"_resolve(1390) returns: {result}")
print("(This will return the STALE cached ('cat', 1360) — there is no")
print(" mechanism that re-checks whether 1390 still means 'cat' by now.)")
print()

print("=" * 70)
print("STEP 3 — a THIRD, unrelated process's ancestor chain happens to")
print("         walk through PID 1390 (now reused by something else")
print("         on a real system) — but our cache has no idea")
print("=" * 70)
grandchild_event = SimpleNamespace(pid=3000, ppid=2000)
chain = mon.get_lineage(grandchild_event, "grandchild_proc", "child_proc")
print(f"Full resolved chain: {mon.format_lineage_string(chain)}")
print()

print("=" * 70)
print("VERDICT")
print("=" * 70)
if mon.pid_cache.get(1390, (None,))[0] == "cat":
    print("CONFIRMED: pid_cache never invalidates an ancestor entry once")
    print("cached. If PID 1390 is reused by a real, unrelated process on")
    print("the live system, any lineage chain walking through 1390 as an")
    print("ancestor will silently report 'cat' — a process that may have")
    print("exited long ago — instead of the process actually holding that")
    print("PID now. This is a real gap, demonstrated with controlled")
    print("inputs, not dependent on catching real PID reuse by chance.")
else:
    print("Cache did NOT show the expected staleness — investigate further")
    print("before concluding the risk is real or ruled out.")
