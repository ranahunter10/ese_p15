# Fixture `s1_mixed`: real VM recording for stage S1

This is test data, not code. The tests that use it are in
`layer3/tests/test_vm_fixture_s1.py`. Never edit the bundle: a new recording
is a new fixture directory.

| | |
|---|---|
| File | `s1_mixed_bundle.tgz`, sha256 `2fb46b7235ec983049a4cef3df7901ac1edea2a24964af4ff1736a4a38e36149` (checked on receipt and by `test_bundle_hash_is_the_one_ashu_recorded`) |
| Recorded by | Ashu, 20 Oct 2026, on the VM, from locked **v3.7** (GitHub `main`, `verify_locked.sh` passed on the VM) |
| Platform | kernel 5.4.0-216-generic, 2 vCPUs, hooks `exec,open,exit,net`, 64 pages/CPU |
| Size | 5,553 records, 0 lost, 0 lost bursts, 0 errors, 90.02 s; 197 processes, 1,274 files, 12 endpoints |
| **VM timezone** | **UTC−4.** The JSONL `time` field is VM local time. This matters for day-based splits |
| Checked on the VM (Ashu) | two replays byte-identical; the live snapshot is byte-identical to the replay snapshot (870,268 B) |

## Contents (per-file sha256 in `SHA256SUMS`)

| File | What it is |
|---|---|
| `s1_mixed.p15r` + `.bootstrap.json` | the raw recording (kernel bytes) and its `/proc` sidecar. This is what the exporter replays |
| `s1_mixed.jsonl` | the live JSONL log. It is the only place that pairs each event's `ts_ns` with a wall-clock time |
| `s1_mixed.stats.json`, `s1_mixed.snapshot.json` | live stats and the live graph snapshot |
| `s1_markers.txt` | one `date +%s%N` (unix epoch ns) per workload step |
| `s1_workload.sh` | the workload that produced the markers |

## Time base

Graph timestamps are `CLOCK_MONOTONIC` ns since boot. The markers are unix
epoch ns. Each JSONL line gives a wall time truncated to the millisecond,
together with `ts_ns`.

For every line, then, the true offset (wall − monotonic) lies in
`[time − ts_ns, time − ts_ns + 1 ms)`. Intersecting those intervals over all
5,379 lines leaves a **641 ns** window:
`[1792501388293371587, 1792501388293372228)`.

The UTC−4 reading is confirmed independently: under that offset, each marker
lands immediately before the processes its step started.
