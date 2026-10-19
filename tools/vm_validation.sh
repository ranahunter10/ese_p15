#!/usr/bin/env bash
# vm_validation.sh — run ON THE UBUNTU VM, from the project root:
#
#     sudo bash tools/vm_validation.sh
#
# Produces runs/validation-<timestamp>/results.md (+ results.json): the
# PASS/FAIL checks and measured numbers for the presentation. Takes ~5 min.
# For WHERE the overhead comes from, run tools/overhead_breakdown.sh.
# Close any file manager showing this folder first (Journal row 10).

set -u
cd "$(dirname "$0")/.."
. tools/lib.sh
if [ "$(id -u)" -ne 0 ]; then echo "run with sudo"; exit 1; fi

OUT="runs/validation-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
PY=python3
MON=""
# Never leave a monitor running if this script stops early for any reason
# (tools/lib.sh explains why SIGTERM + deadline, not SIGINT + wait).
cleanup() { stop_bg "$MON" 15; MON=""; }
on_interrupt() { echo; echo "== interrupted: stopping monitor"; cleanup; exit 130; }
trap cleanup EXIT
trap on_interrupt INT TERM
echo "== output: $OUT"

# ---------------------------------------------------------------- 0 preflight
{
  echo "kernel=$(uname -r)"; echo "cpus=$(nproc)"
  echo "python=$($PY -c 'import sys; print(sys.version.split()[0])')"
  echo "bcc=$($PY -c 'import bcc; print(getattr(bcc, "__version__", "unknown"))' 2>&1)"
} | tee "$OUT/env.txt"

echo "== unit tests"
$PY -m unittest discover -s tests -p 'test_*.py' > "$OUT/unit_tests.txt" 2>&1
tail -3 "$OUT/unit_tests.txt"

# Start the monitor in the background and wait until the hooks are live.
# (Started in the foreground shell with sudo already held, so no password
# prompt can stop it — the `sudo cmd &` trap from Journal row 20.)
start_monitor() {   # $1 = name, rest = extra args
  local name=$1; shift
  # -u = unbuffered output, so the "Hooks attached" line reaches the file
  # immediately (the 16 Sep run waited 60 s for a line stuck in a buffer).
  $PY -u -m hids.monitor --mode quiet --logfile "$OUT/$name.jsonl" \
      --stats-json "$OUT/$name.stats.json" --snapshot "$OUT/$name.graph.json" "$@" \
      > "$OUT/$name.console.txt" 2>&1 &
  MON=$!
  wait_for_text "$OUT/$name.console.txt" "Hooks attached" "$MON" 60
  case $? in
    0) return 0 ;;
    1) echo "monitor failed to start:" ;;
    *) echo "monitor did not attach in 60 s. console so far:" ;;
  esac
  cat "$OUT/$name.console.txt"; exit 1
}
stop_monitor() { sleep 1; stop_bg "$MON" 15; MON=""; }

# ------------------------------------------------------------- 1 functional
echo "== 1/4 functional checks"
# A private directory per run. Fixed /tmp names break as soon as two runs
# use different users, or the kernel's protected_regular rule applies to a
# leftover file someone else owns — the 13 Oct run failed exactly that way,
# and the same mistake once broke a unit test. The analyzer reads these
# paths from paths.json instead of assuming them.
WORK=$(mktemp -d "/tmp/p15work-XXXXXXXX")
chmod 755 "$WORK"
printf '{"work": "%s", "payload": "%s", "fork": "%s", "rel": "%s"}\n' \
  "$WORK" "$WORK/payload.txt" "$WORK/fork.txt" "p15_rel.txt" > "$OUT/paths.json"
start_monitor functional
cat /etc/hostname > /dev/null
/bin/echo alpha beta gamma > /dev/null
sh -c "echo secret > $WORK/payload.txt"
cat "$WORK/payload.txt" > /dev/null
$PY -c "import os; os.execv('/nonexistent_p15_binary', ['x'])" 2>/dev/null
sh -c 'exit 3'
/bin/echo $(seq 1 30) > /dev/null
bash -c "( : > $WORK/fork.txt )"
# fileless execution: program exists only in memory (memfd), run via fexecve
$PY -c "
import os
fd = os.memfd_create('p15mem')
with open('/bin/true', 'rb') as f:
    os.write(fd, f.read())
os.execve(fd, ['p15mem'], {})
"
# relative path: the same file reached as ./p15_rel.txt from its own dir
(cd "$WORK" && echo rel > p15_rel.txt && cat ./p15_rel.txt > /dev/null)
$PY - <<'PYEOF'
import ctypes, threading
def work():
    ctypes.CDLL(None).prctl(15, b"p15worker", 0, 0, 0)   # PR_SET_NAME
    open("/etc/hostname").read()
t = threading.Thread(target=work); t.start(); t.join()
PYEOF
# network: successful, refused, unix and non-blocking connects, plus the
# download -> write -> execute chain (loopback only, no internet needed)
$PY tools/net_demo.py > "$OUT/net_demo.json" 2>"$OUT/net_demo.err" || \
  echo "net_demo failed: $(head -3 "$OUT/net_demo.err")"
stop_monitor

# ------------------------------------------------------------ 2 exec burst
echo "== 2/4 exec burst (200 x /bin/true)"
start_monitor burst
for i in $(seq 1 200); do /bin/true; done
stop_monitor

# ------------------------------------------------------ 3 throughput limit
# Warm the page cache once, so the first stress run isn't slower just
# because the disk was cold (the p64 vs p256 confound in the first run).
timeout 30 find / > /dev/null 2>&1
for PAGES in 64 256; do
  echo "== 3/4 stress: 3x find / for 20 s, $PAGES pages/CPU"
  start_monitor "stress_p$PAGES" --pages "$PAGES" --no-log
  for j in 1 2 3; do timeout 20 find / > /dev/null 2>&1 & done
  sleep 21          # the three finds are stopped by `timeout` at 20 s
  stop_monitor
done

# --------------------------------------------------- 4 workload slowdown
# The eBPF programs run inside the traced processes' syscalls, so their
# cost shows up as the WORKLOAD getting slower. This is the number that is
# comparable (in kind) to eBPF-PATROL's throughput degradation.
echo "== 4/4 workload slowdown"
timeit() {   # prints wall seconds taken by "$@"
  local s e; s=$(date +%s.%N); "$@" > /dev/null 2>&1; e=$(date +%s.%N)
  $PY -c "print(round($e - $s, 4))"
}
exec_load() { for i in $(seq 1 2000); do /bin/true; done; }
open_load() { find /usr > /dev/null 2>&1; }
find /usr > /dev/null 2>&1    # warm the page cache first
: > "$OUT/timings.csv"
for round in 1 2 3; do
  echo "base,exec,$(timeit exec_load)" >> "$OUT/timings.csv"
  echo "base,open,$(timeit open_load)" >> "$OUT/timings.csv"
done
start_monitor overhead --no-log
for round in 1 2 3; do
  echo "mon,exec,$(timeit exec_load)" >> "$OUT/timings.csv"
  echo "mon,open,$(timeit open_load)" >> "$OUT/timings.csv"
done
stop_monitor

echo "== analysing"
$PY tools/analyze_run.py "$OUT"
