# Stage 6 — the runtime: `monitor.py`, `procstat.py`, `view.py` (574 lines)

The least algorithmic stage and the one with the most lessons learned on a
real machine. Almost every odd-looking line here is a Journal row. Budget
2–3 hours.

```bash
grep -n "^def \|^HOOK_\|^FEATURE_SETS\|^ALL_HOOKS" hids/monitor.py
grep -n "^def \|^class " hids/procstat.py hids/view.py
```

---

## 6.1 `bpf_text()` — the program is assembled at runtime

```python
head = ["#define SELF_TGID %d" % self_tgid]
head += ["#define HOOK_%s 1" % h.upper() for h in hooks]
head += ["#define %s 1" % f for f in features]
return "\n".join(head) + "\n" + f.read()
```

Three lines that explain the whole feature system. The C file never changes;
what changes is the `#define` block prepended to it. So:

- `--hooks net` does not disable the exec probes at runtime — it compiles a
  program that **does not contain them**.
- `SELF_TGID` is our own PID, baked in as a constant.
- A feature is on or off at *compile* time, which is why a refused feature
  means falling back to a different program (6.2).

## 6.2 `load_bpf()` — graceful degradation, recorded

```python
for feats in sets:
    try:
        return BPF(text=bpf_text(os.getpid(), hooks, feats)), feats, failures
    except Exception as e:
        failures.append((feats, msg[-1] if msg else repr(e)))
```

`FEATURE_SETS` is ordered most-capable-first:

```
("KERNEL_EXEC_PATH", "FILE_IDENTITY", "SOCKET_TYPE")
("KERNEL_EXEC_PATH", "FILE_IDENTITY")
("FILE_IDENTITY",)
("KERNEL_EXEC_PATH",)
()
```

The monitor tries each until one compiles and verifies. **Why this exists:**
the struct offsets a feature needs (`task->files->fdt`, `file->private_data`)
are not guaranteed across kernels. On a kernel where the walk cannot be
verified, the choice is "run with less" or "do not run". The project chooses
less — *and records which*, in `features` and `features_refused` in the
stats. A run whose numbers came from a degraded feature set must not look
like a run that had everything.

> Compare `--features none`: the same mechanism used deliberately, to
> measure what the inode walk costs.

## 6.3 The main loop, decision by decision

Read `main()` top to bottom once, then study these five.

**1. Tracepoint existence is checked before anything else.**

```python
missing = [... if not BPF.tracepoint_exists(c, e)]
if missing: sys.exit("[ERROR] tracepoints not available on this kernel: ...")
```

A clean, named error instead of a BCC stack trace. This is also exactly how
`openat2` will be handled when we add it on a 5.4 VM where it does not
exist (`WORKLOG` §6).

**2. Signal handlers are installed before the compile.** BCC's clang
invocation takes seconds; a Ctrl+C during it should stop cleanly rather than
leave a half-attached program. And the handler only sets a flag — the loop
checks it between polls, because doing real work in a signal handler is how
v2 hung for 10–15 s under load (Journal row 11).

**SIGTERM is handled identically to SIGINT**, which is not decoration: a
non-interactive bash ignores SIGINT in background jobs, so
`vm_validation.sh` has to send SIGTERM and needs it to mean the same thing.

**3. The `/proc` snapshot happens AFTER the hooks are attached.**

```python
# Snapshot AFTER hooks are live, so nothing falls in between.
```

Order matters: snapshot-then-attach leaves a window where a process starts,
is missed by the snapshot, and is missed by the hooks. Attach-then-snapshot
can only *duplicate* information, and duplication is handled by
adopt-and-upgrade (stage 5, §5.2 step 2).

**4. The poll timeout is 50 ms, or batched.**

```python
if batch_s:
    bpf.perf_buffer_poll(timeout=0)
    time.sleep(batch_s)
else:
    bpf.perf_buffer_poll(timeout=50)
```

The comment is the mechanism: the kernel only wakes a reader that is
*sleeping in* `poll()`, and BCC 0.12 sets `wakeup_events = 1`, so every
record wakes us. `--batch-ms` deliberately leaves records in the ring and
sleeps instead, trading latency for fewer wakeups. The overhead breakdown
measured this as a real effect (graph_all +170 % → +130 % with 20 ms
batching).

**5. The bounded drain, and `finally`.**

```python
for _ in range(20):
    bpf.perf_buffer_poll(timeout=0)
proc.tick(force=True)
```

Twenty polls, not "until empty": under a flood, "until empty" never
terminates. Then `tick(force=True)` settles every pending exec so partial
records are committed rather than lost.

And everything that matters is written in `finally`, including on a crash
(`crash` is recorded in the stats). The rule the project follows: **evidence
survives failure.** A crashed run that wrote its stats is a data point; one
that wrote nothing is a wasted VM session.

## 6.4 The statistics block is the project's measurement contract

Read the `stats.update({...})` dict and notice what is recorded beyond the
counts: kernel release, CPU count, hooks, sink, features, features refused,
pages per CPU, batch ms, duration, compile time, monitor CPU, peak RSS,
records/s, log path, version, crash.

That list exists so a number can never be quoted without its conditions.
The comment on `monitor_cpu_s` is the subtle one:

> Userspace cost only: in-kernel eBPF time is charged to the traced
> processes and shows up as THEIR slowdown instead.

So "monitor CPU 21 %" is **not** the monitor's total cost — the kernel-side
cost appears as the workload's slowdown, which is what
`overhead_breakdown.sh` measures separately. Be ready for that question; it
is the most common way these numbers get misquoted.

## 6.5 `procstat.py` — the `/proc` reader

Two jobs: the startup snapshot (`scan()`) and periodic CPU/RSS sampling
(`ResourceSampler`).

Things to notice:

- **Every read is defensive.** A process can exit between listing `/proc`
  and reading its files, so `ENOENT` is normal and must not be an error.
- **`start_time` from `/proc/<pid>/stat` is in clock ticks since boot**, not
  nanoseconds, so it is an *estimate* of the monotonic start time — hence
  `start_exact=False` and adopt-and-upgrade.
- **Field 22 is not simply field 22.** `comm` in `/proc/<pid>/stat` is
  wrapped in parentheses and may itself contain spaces and parentheses, so
  the parse finds the last `)` rather than splitting on whitespace. A
  process named `foo bar) baz` is a real attack on naive parsers.
- CPU percent is computed from *deltas* between samples; a single reading
  of `utime+stime` is a total since boot and would report a number that
  only ever rises.

## 6.6 `view.py` — the live screen

`render()` builds the whole screen as one string and `draw()` writes it with
a clear-screen escape, which avoids flicker and partial frames. The process
table is `top`-like; the tree is `pstree`-like; the counters are the
stats block. This is the shape the advisor asked for — `top` + `pstree`
combined, not a scrolling log.

Two details worth knowing:

- `mode = args.mode if (args.mode != "view" or tty) else "quiet"` — asking
  for the live screen while redirecting to a file silently becomes `quiet`,
  because escape codes in a log file are noise.
- `make_printer` is the per-event line printer, and `describe()` is where
  each event type gets its one-line summary. Note how CONNECT renders the
  endpoint id first: that is the value an enforcement layer would be
  programmed with.

---

## Experiments

`[VM]` Watch feature fallback happen for real:

```bash
sudo python3 -m hids.monitor --mode quiet --duration 5 --stats-json /tmp/s.json
python3 -c "import json; s=json.load(open('/tmp/s.json'));
print('ran with:', s['features']); print('refused:', s['features_refused'])"
```

`[VM]` Prove the snapshot-after-attach ordering matters:

```bash
sudo python3 -m hids.monitor --no-bootstrap --mode quiet --duration 20 --snapshot /tmp/nb.json &
sleep 2; ls /etc >/dev/null
python3 tools/query_graph.py /tmp/nb.json tree | head
# pre-existing processes are missing, so lineages start mid-tree
```

`[VM]` See the batching trade-off:

```bash
for b in 0 20; do
  sudo python3 -m hids.monitor --mode quiet --duration 20 --batch-ms $b \
       --stats-json /tmp/b$b.json & sleep 1; find /usr -type f >/dev/null 2>&1; wait
  python3 -c "import json; s=json.load(open('/tmp/b$b.json'));
print('batch=$b', s['records_per_s'], 'rec/s,', s['monitor_cpu_percent_of_one_core'], '% CPU')"
done
```

`[laptop]` The whole runtime, with a fake kernel:

```bash
python3 -m unittest tests.test_system -v 2>&1 | head -25
```

That suite replaces `bcc` with a fake module that replays a scripted byte
stream, so `main()` — argument parsing, fallback, the loop, the stats, the
snapshot — is exercised without root.

---

## Self-check

1. `--hooks net` is passed. What is physically different about the loaded
   program?
2. Why does a refused feature mean a *different program*, not a disabled
   branch?
3. Why are `features_refused` recorded in the stats rather than just logged?
4. Why is the `/proc` snapshot taken after the hooks are attached, and what
   handles the duplication that causes?
5. Why is SIGTERM treated the same as SIGINT?
6. Why does the signal handler only set a flag?
7. What does `--batch-ms` trade, and which mechanism makes it work?
8. Why is the final drain bounded at 20 polls?
9. "Monitor CPU was 21 % of one core." Why is that not the monitor's total
   cost?
10. Why is `/proc/<pid>/stat` parsed by finding the last `)`?
11. Why is `start_exact` False for bootstrapped processes?

<details>
<summary>Answers</summary>

1. The source handed to clang has only `#define HOOK_NET 1`, so the exec,
   open and exit probes are not compiled at all — they do not exist in the
   loaded program rather than being skipped at runtime.
2. Features are `#ifdef` blocks, so they are included or excluded at
   compile time. A refusal means that program did not verify, and the
   fallback compiles a different source with fewer defines.
3. Because a run with a degraded feature set produces different numbers —
   fewer resolved inodes, no socket types — and any figure quoted from it
   must be traceable to the conditions it was measured under.
4. Snapshot-then-attach leaves a gap in which a process can start and be
   caught by neither. Attach-then-snapshot can only duplicate, and
   adopt-and-upgrade merges the duplicate into one node while replacing the
   estimated start with the exact one.
5. A non-interactive bash ignores SIGINT for background jobs, so the
   validation scripts must use SIGTERM — and it has to mean "stop cleanly",
   not "die".
6. Because real work in a handler runs at an arbitrary point in the
   program's execution; v2 did that and hung 10–15 s under load. The flag
   is checked between polls, where the state is consistent.
7. Latency for wakeups. The kernel only wakes a reader sleeping in
   `poll()`, and BCC 0.12 wakes on every record; polling with timeout 0 and
   sleeping instead leaves records in the ring and wakes far less often.
8. Because "poll until empty" never terminates while a flood continues, and
   shutdown has to finish. Twenty passes take what is queued.
9. Because in-kernel eBPF time is charged to whichever process triggered the
   probe, so it appears as the *workload's* slowdown, not in the monitor's
   CPU accounting. The two have to be measured separately.
10. `comm` is parenthesised and may itself contain spaces and parentheses, so
    whitespace splitting mis-parses a process named, say, `foo bar) baz`.
11. The start time there comes from `/proc` in clock ticks since boot, which
    is an estimate of the monotonic value the kernel gives us on a real
    record — so it is marked inexact until a real record upgrades it.

</details>

Next: `07_TOOLS.md` — the measurement rig, and why it is built the way it is.
