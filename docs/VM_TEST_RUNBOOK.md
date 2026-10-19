# VM test runbook — v3.6

Ten steps (0 through 9), in this order. The cheap checks that could invalidate the
expensive ones come first: if step 3 shows the verifier refusing the new
code, steps 5–7 would be measuring something other than what we think.

Total: about 25–30 minutes, most of it step 7 running unattended.

Paste back the blocks marked **PASTE**. Everything else is for you to see.

---

## Step 0 — unpack, and make sure nothing is left attached

A leftover tracer keeps its eBPF hooks attached and slows every later
measurement (Journal row 10).

```bash
cd ~                       # or wherever you keep it
pgrep -af 'hids.monitor|bpfcc'                      # should print nothing
sudo pkill -TERM -f 'hids.monitor|bpfcc' ; sleep 3
sudo pkill -KILL -f 'hids.monitor|bpfcc' 2>/dev/null
unzip -o ese_p15_v3.6.zip && cd ese_p15
python3 -c "import hids; print('version', hids.__version__)"
```

Expect `version 3.7`. Also close any file manager showing the project
folder — it generates opens that land in every measurement.

---

## Step 1 — environment facts (settles two open claims)

```bash
uname -r ; python3 -V ; dpkg -l | grep -c bpfcc
echo "--- net tracepoints this kernel has:"
sudo ls /sys/kernel/debug/tracing/events/syscalls/ | grep -E 'accept|connect'
echo "--- openat2 (expected: ABSENT on 5.4):"
sudo ls /sys/kernel/debug/tracing/events/syscalls/ | grep -c openat2
echo "--- accept4 field names (the ABI we coded against):"
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_accept4/format
```

**PASTE this whole block's output.** It confirms the four accept tracepoints
exist, that `openat2` genuinely cannot be tested here (which is why row 2 of
the roadmap is labelled untestable), and that the field names are
`fd`, `upeer_sockaddr`, `upeer_addrlen`, `flags` as the code assumes.

---

## Step 2 — unit tests, as your normal user (not sudo)

```bash
./run_tests.sh 2>&1 | tail -5
```

Expect `Ran 436 tests ... OK` with **nothing skipped**.

> If you see `OK (skipped=1)` you ran it as root. The one conditional test,
> `test_refuses_without_root_unless_bypassed`, skips *when* it is root,
> because what it checks is that the claims script refuses to run without
> root. This line previously said to expect `(skipped=1)` — that expectation
> was copied from a container that runs as root, so it was wrong for the one
> environment this runbook is written for. As a normal user you get the
> fuller run of the two.

Note for v3.6: this run matters more than a
routine re-validation, because v3.6 rewrote the decode path — every
record is now read by `struct.unpack_from` over a zero-copy view of
BCC's pointer instead of `ctypes.cast`. The unit suite proves the new
decoder agrees with the old one on 3000 randomised buffers, but only a
live attach proves it agrees with the kernel. If step 4 shows malformed
or zero-filled fields, suspect the decode path first. **PASTE the last 5 lines.**

> Run these *without* `sudo`. The suite needs no root, and running it as
> root is what exposed the `/tmp` ownership failure in row 78.

If anything fails, stop and paste the failure — the VM's Python 3.8 and
BCC 0.12 are the only environment the suite has not been run on since the
corner-case sweep.

---

## Step 3 — does the kernel actually accept the new program?

The one question nothing on my side can answer: gcc type-checks the C,
the **verifier** decides whether it runs.

```bash
sudo python3 -m hids.monitor --mode quiet --duration 10 \
     --stats-json /tmp/s0.json --no-log
python3 - <<'EOF'
import json; s=json.load(open('/tmp/s0.json'))
print("kernel        :", s["kernel"], "| version", s["version"], "| cpus", s["cpus"])
print("features USED :", s["features"])
print("features REFUSED:")
for feats, msg in s["features_refused"]:
    print("   ", feats, "->", msg)
print("hooks         :", s["hooks"])
print("compile time  :", s["bpf_compile_s"], "s")
print("records       :", s["records_received"], "| lost", s["lost"], "| errors", s["records"]["errors"])
print("crash         :", s["crash"])
EOF
```

**PASTE that output.** What it tells us:

| result | meaning |
|---|---|
| `features USED: ['KERNEL_EXEC_PATH', 'FILE_IDENTITY', 'SOCKET_TYPE']` and nothing refused | the full program verified, including the accept probes |
| any entry under REFUSED | the verifier rejected that combination — paste the message, it names the instruction and is the single most useful line of the whole run |
| `crash` not null | something failed after loading; the traceback is in the stats |

---

## Step 4 — the inbound hook, on real traffic

The headline feature of v3.5, which has never run on a kernel. Two
terminals, or background the monitor as shown.

```bash
sudo python3 -m hids.monitor --mode print -t accept --duration 45 &
sleep 8                                   # let it compile and attach

# (a) a local server accepting a real connection
python3 -m http.server 8077 >/dev/null 2>&1 &
sleep 2 ; curl -s http://127.0.0.1:8077/ >/dev/null ; curl -s http://127.0.0.1:8077/ >/dev/null
kill %2 2>/dev/null

# (b) sshd, if it is running — the case the threat model is about
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 localhost true 2>/dev/null || true

# (c) the deterministic scenario, including a unix-socket accept
python3 tools/net_demo.py
wait
```

**PASTE every `ACCEPT` line.** What to look for, and what each one proves:

- `host:127.0.0.1  inbound from port <ephemeral> -> fd N  [stream]` — the
  peer address came from the kernel, and the port in the *record* is the
  client's ephemeral one while the **id has no port at all** (the design
  decision from row B4). Two curls should show two different source ports
  and the **same** endpoint id.
- an ACCEPT attributed to `python3` (the http server) or `sshd`, with a
  full lineage — inbound attribution working.
- `peer unknown` on the unix-socket accept — the kernel had no peer name,
  and we say so instead of inventing `0.0.0.0`.
- `[stream]` means `SOCKET_TYPE` resolved the socket behind the fd.

---

## Step 5 — full functional validation (23 checks, ~5 min)

```bash
sudo bash tools/vm_validation.sh
```

**PASTE the results table and the numbers table** (it also writes
`runs/validation-*/results.md`). Expect **23/23**. If any check fails,
paste its evidence string too — that string is designed to be the
diagnosis, and it is what caught the real graph bug on the 13th.

---

## Step 6 — the new query and dry-run tools, on your own capture

```bash
sudo python3 -m hids.monitor --mode quiet --duration 60 \
     --snapshot /tmp/g.json --stats-json /tmp/s1.json &
sleep 8
python3 tools/net_demo.py
python3 -m http.server 8078 >/dev/null 2>&1 & sleep 2
curl -s http://127.0.0.1:8078/ >/dev/null ; kill %2 2>/dev/null
( cd /tmp && echo payload > p15_demo.txt && cat ./p15_demo.txt >/dev/null )
wait

python3 - <<'EOF'
import json; s=json.load(open('/tmp/s1.json')); g=s["graph"]
print("records:", {k:v for k,v in s["records"].items() if v})
print("graph  :", {k:v for k,v in g.items() if v})
print("loss   : %s (%.2f%%) | monitor CPU %.1f%% | RSS %.0f MB"
      % (s["lost"], 100*s["loss_rate"], s["monitor_cpu_percent_of_one_core"],
         s["monitor_maxrss_kb"]/1024))
EOF

python3 tools/query_graph.py /tmp/g.json summary
python3 tools/query_graph.py /tmp/g.json inbound
python3 tools/query_graph.py /tmp/g.json endpoints | head -20
python3 tools/query_graph.py /tmp/g.json scans | head
```

**PASTE all of that.** `inbound` is new in v3.5 and should group by host;
`endpoints` should show an `in`/`out`/`both` column.

Then the dry-run tool against the same snapshot — pick a PID from the
`inbound` output or from `tree`:

```bash
python3 tools/query_graph.py /tmp/g.json tree | head -30
python3 tools/walk_trace.py /tmp/g.json trace <PID> --no-libs | tail -40
python3 tools/walk_trace.py /tmp/g.json trace <PID> --no-libs --at <SECONDS>
```

**PASTE the walk_trace output for one process.** This is the first time the
dry run will have been produced from real kernel data rather than a demo,
and it is worth checking that the step sequence reads the way the study
guide says it should.

---

## Step 7 — overhead breakdown (~10–15 min, leave it alone)

The measurement that has been pending since September, and now the only
thing blocking an architecture decision. Nothing else should run on the VM
while this goes — no browser, no file manager, no other terminal work.

```bash
sudo P15_DD_COUNT=6000000 P15_ROUNDS=5 P15_PIN=1 \
     bash tools/overhead_breakdown.sh 2>&1 | tail -60
cat runs/overhead-*/overhead.md
```

The three overrides are what make the ladder readable, and the 18 Oct run is
why they are spelled out here rather than left to the defaults:

- `P15_DD_COUNT=6000000` — at the old default (300 000) a dd round took
  **0.09 s** and the per-syscall tax sat far below timing noise; the ladder
  came out non-monotonic and the analyzer refused to read it. The default is
  now 6 000 000, so this override is belt-and-braces.
- `P15_ROUNDS=5` — more rounds, because the 18 Oct control measured a **16 %
  mean / 49 % worst** error against a true answer of 0 %.
- `P15_PIN=1` — workload and tracer on different CPUs, so contention on a
  2-vCPU box is not counted as hook cost.

**Before starting, check the machine is actually quiet.** The 18 Oct run saw
the `/bin/true` baseline move **117 %** between the start and the end
(2.37 s → 5.13 s), which is larger than most of the effects being measured.
`uptime` should show a load average near zero, and nothing else should be
running — no browser, no file manager on this folder, no other terminal.

**PASTE the whole `overhead.md`.** The row I care most about is the
tracepoint ladder reading at the bottom — `0 tp`, `2 tp`, `4 tp`, `6 tp`,
`12 tp` against the **dd** workload, which calls none of the syscalls we
hook:

- **flat** → the syscall-tracepoint tax is paid once; hook count is not
  worth optimising, and the Python cost is the remaining target;
- **rising** → each hook costs, hooks become a budget, and the mechanism
  choice (sched/LSM/fentry, or a newer kernel) becomes a thesis decision.

---

## Step 8 — the glibc question row 86 left open

Row 86 claims glibc's `accept()` issues `__NR_accept` while Python's
`socket.accept()` issues `__NR_accept4`, measured in a container with a
newer libc. Confirm it on *this* glibc:

```bash
sudo apt install -y strace 2>/dev/null | tail -1
cat > /tmp/p15srv.py <<'EOF'
import socket, threading
s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(1)
port = s.getsockname()[1]
threading.Thread(target=lambda: socket.create_connection(("127.0.0.1", port)).close()).start()
c, a = s.accept(); print("python peer:", a); c.close(); s.close()
EOF
strace -f -e trace=accept,accept4 python3 /tmp/p15srv.py 2>&1 | grep -E 'accept'
ldd --version | head -1
```

**PASTE that.** If Python uses `accept4` here too, row 86 is confirmed on
the VM's glibc 2.31 and stops being an assumption carried from another
machine.

---

## Step 9 — leave the machine clean

```bash
pgrep -af 'hids.monitor|bpfcc|http.server'     # expect nothing
sudo pkill -TERM -f 'hids.monitor|bpfcc' 2>/dev/null
ls runs/
```

---

## What to paste, in one list

1. step 1 — environment + tracepoint listing + accept4 format
2. step 2 — last 5 lines of `run_tests.sh`
3. step 3 — the features/refused block
4. step 4 — every ACCEPT line
5. step 5 — the validation tables (or `results.md`)
6. step 6 — stats, the four queries, one `walk_trace` output
7. step 7 — the whole `overhead.md`
8. step 8 — the strace lines and glibc version

If something fails early, paste that and stop — a failure in step 2 or 3
changes what the later steps mean.
