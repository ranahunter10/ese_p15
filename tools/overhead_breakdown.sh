#!/usr/bin/env bash
# overhead_breakdown.sh — WHERE does the workload slowdown come from?
# Run ON THE VM from the project root:   sudo bash tools/overhead_breakdown.sh
# Takes ~10-15 min. Writes runs/overhead-<timestamp>/overhead.md
# Ctrl+C at any point stops the running tracer and exits cleanly.
#
# Every configuration runs the same three workloads, ROUNDS times each:
#   exec  EXEC_N x /bin/true           (process creation)
#   open  find OPEN_DIR, cache warm    (file opens)
#   sys   dd, DD_COUNT 1-byte reads/writes (syscalls that we do NOT record)
#
# Configurations, and the question each one answers:
#   base               no tracing at all (run first AND last: drift check)
#   bcc_execsnoop      BCC's own exec tool: is exec tracing just this costly here?
#   bcc_opensnoop      BCC's own open tool: same question for opens
#   count_exec         our exec hooks only, Python only counts
#   count_open         our open hooks only, Python only counts
#   count_exit         our exit hook only (a sched tracepoint, not a syscall one)
#   count_net          our connect hooks only (2 syscall tracepoints)
#   count_all          all hooks, counting only   -> kernel-side cost of our design
#   count_all_nofeat   same without inode/kernel-path reads -> cost of those reads
#   graph_all          full processing, no log    -> adds our Python work
#   graph_all_batch20  same, polling every 20 ms  -> effect of perf wakeups
#   graph_all_log      full processing + JSONL log
#
# Environment overrides (used by tests/test_scripts.py for a fast dry run):
#   P15_PY, P15_MON, P15_EXECSNOOP, P15_OPENSNOOP, P15_ROUNDS, P15_EXEC_N,
#   P15_OPEN_DIR, P15_DD_COUNT, P15_OUT, P15_GRACE,
#   P15_WORKLOADS="sys"  (ladder-only run: minutes instead of ~40)
#   P15_PIN=1            (workload on cpu0, tracer on cpu1 — separates hook
#                         cost from CPU contention on a 2-vCPU box)
#   P15_INTERLEAVE=0     (do NOT measure a baseline between configs; only
#                         for comparison with pre-16-Oct runs)
#   P15_BASE_ROUNDS=2    (rounds per interleaved baseline)
#   P15_SKIP_ROOT_CHECK=1 (tests only: the fakes need no root)

set -u
cd "$(dirname "$0")/.."
. tools/lib.sh
if [ "$(id -u)" -ne 0 ] && [ "${P15_SKIP_ROOT_CHECK:-0}" != 1 ]; then
  echo "run with sudo"; exit 1
fi

PY=${P15_PY:-python3}
MON=${P15_MON:-"$PY -u -m hids.monitor --mode quiet"}
BUILD=$(cat VERSION 2>/dev/null || echo unknown)   # already cd'd to the project root
EXECSNOOP=${P15_EXECSNOOP:-execsnoop-bpfcc}
OPENSNOOP=${P15_OPENSNOOP:-opensnoop-bpfcc}
ROUNDS=${P15_ROUNDS:-3}
EXEC_N=${P15_EXEC_N:-2000}
OPEN_DIR=${P15_OPEN_DIR:-/usr}
# 6,000,000 and not 300,000: at 300k a dd round takes ~0.09 s on the test VM
# and the per-syscall tax -- the whole reason the dd workload exists -- sits
# far below timing noise. The 2026-10-18 run used the old default and the
# ladder came out NON-MONOTONIC (-24, -2, -9, -17, +25, -8, +98 %), which the
# analyzer correctly refused to read. The v3.5g run that did resolve it
# (~16 ns, paid once) passed P15_DD_COUNT=6000000 by hand. A default that
# cannot resolve the measurement the tool is for is a defect in the default.
# Cost of the change: roughly +2 minutes over the whole run.
DD_COUNT=${P15_DD_COUNT:-6000000}
GRACE=${P15_GRACE:-15}
# Which workloads to run. The default is all three; "sys" alone turns this
# into a focused tracepoint-ladder experiment that finishes in a few
# minutes instead of forty, which is what the 16-Oct run showed we need —
# that run could not resolve flat-vs-rising because one round of dd took
# 0.15 s and the noise exceeded the whole effect.
WORKLOADS=${P15_WORKLOADS:-"exec open sys"}
# Pin the workload and the monitor to DIFFERENT CPUs. On a 2-vCPU box the
# monitor's own polling competes with the workload for a core, and that
# contention is otherwise counted as hook cost: count_exit showed dd +27 %
# with a hook that never fires during dd. Requires taskset (util-linux).
PIN=${P15_PIN:-0}
# Measure a baseline between every configuration (see run_config).
INTERLEAVE=${P15_INTERLEAVE:-1}
BASE_ROUNDS=${P15_BASE_ROUNDS:-2}
if [ "$PIN" = 1 ] && command -v taskset > /dev/null 2>&1; then
  WORK_PIN="taskset -c 0"
  MON_PIN="taskset -c 1"
  echo "== CPU pinning ON: workload on cpu0, tracer on cpu1"
else
  WORK_PIN=""
  MON_PIN=""
  [ "$PIN" = 1 ] && echo "== P15_PIN=1 but taskset not found: continuing unpinned"
fi
OUT=${P15_OUT:-"runs/overhead-$(date +%Y%m%d-%H%M%S)"}
mkdir -p "$OUT"

BG=""
cleanup() { stop_bg "$BG" "$GRACE"; BG=""; }
on_interrupt() {
  echo; echo "== interrupted: stopping background tracer and exiting"
  cleanup
  exit 130
}
trap cleanup EXIT
trap on_interrupt INT TERM

# `build` records which build MEASURED this run, as the analyzer records which
# build read it. On 16 Oct a corrected report was read from an uncorrected
# analyzer in a stale tree, and nothing in the output said so.
{ echo "kernel=$(uname -r)"; echo "cpus=$(nproc)"; echo "rounds=$ROUNDS"
  echo "exec_n=$EXEC_N"; echo "open_dir=$OPEN_DIR"; echo "dd_count=$DD_COUNT"
  echo "workloads=$WORKLOADS"; echo "pinned=$PIN"
  echo "interleave=$INTERLEAVE"; echo "base_rounds=$BASE_ROUNDS"
  echo "build=$BUILD"; } > "$OUT/env.txt"
echo "== output: $OUT"
: > "$OUT/timings.csv"

ts() { date +%s.%N; }
exec_load() { local i; for i in $(seq 1 "$EXEC_N"); do $WORK_PIN /bin/true; done; }
open_load() { $WORK_PIN find "$OPEN_DIR" > /dev/null 2>&1; }
sys_load()  { $WORK_PIN dd if=/dev/zero of=/dev/null bs=1 count="$DD_COUNT" 2> /dev/null; }

# Wall time AND the workload's own CPU time (user + sys). Wall time on a
# VirtualBox guest is at the mercy of the host: the 16-Oct ladder run saw
# its baseline go 1.58 s -> 4.66 s (+195 %) inside one 15-minute run, which
# makes every wall-clock comparison between configs meaningless. A hook
# that adds work to each syscall adds it to the workload's SYSTEM CPU time,
# and CPU time does not grow when the hypervisor takes the processor away.
measure() {   # $1 = config name
  local cfg_name=$1
  local w r line wall user sys
  for r in $(seq 1 "$ROUNDS"); do
    for w in $WORKLOADS; do
      TIMEFORMAT='%R %U %S'
      line=$( { time "${w}_load" ; } 2>&1 1>/dev/null )
      set -- $line
      wall=$1; user=$2; sys=$3
      echo "$cfg_name,$w,$r,$wall,$user,$sys" >> "$OUT/timings.csv"
      printf '   round %s %-4s wall %7.2f s   cpu %6.2f s (sys %5.2f)\n' \
             "$r" "$w" "$wall" "$($PY -c "print(round($user + $sys, 3))")" "$sys"
    done
  done
}

run_config() {  # $1 = name, rest = command (runs in background)
  local name=$1; shift
  echo "== $name"
  if ! command -v "$1" > /dev/null 2>&1; then
    echo "   $1 not found: skipped"
    echo "$name,skipped,0,0" >> "$OUT/timings.csv"
    return
  fi
  PYTHONUNBUFFERED=1 $MON_PIN "$@" > "$OUT/$name.console.txt" 2>&1 &
  BG=$!
  local ready="Hooks attached" rc
  case "$name" in bcc_*) ready="" ;; esac   # BCC tools: first header line
  wait_for_text "$OUT/$name.console.txt" "$ready" "$BG" 60
  rc=$?
  if [ $rc -eq 0 ]; then
    sleep 1
    measure "$name"
  else
    [ $rc -eq 1 ] && echo "   tracer exited during startup:" || echo "   tracer not ready after 60 s:"
    tail -5 "$OUT/$name.console.txt" | sed 's/^/   | /'
    echo "$name,skipped,0,0" >> "$OUT/timings.csv"
  fi
  stop_bg "$BG" "$GRACE"; BG=""
  # A baseline measured NEXT TO this config in time. Block designs assume a
  # stable machine; this one is not stable, so each config is compared with
  # the baseline either side of it rather than with one taken 15 minutes
  # earlier.
  if [ "$INTERLEAVE" = 1 ]; then
    local saved=$ROUNDS
    ROUNDS=$BASE_ROUNDS
    measure "base_after_$name"
    ROUNDS=$saved
  fi
}

open_load                                   # warm the page cache
echo "== base (start)"; measure base
run_config bcc_execsnoop  $EXECSNOOP
run_config bcc_opensnoop  $OPENSNOOP
run_config count_exec     $MON --sink count --hooks exec --stats-json "$OUT/count_exec.stats.json"
run_config count_open     $MON --sink count --hooks open --stats-json "$OUT/count_open.stats.json"
run_config count_exit     $MON --sink count --hooks exit --stats-json "$OUT/count_exit.stats.json"
run_config count_net      $MON --sink count --hooks net --stats-json "$OUT/count_net.stats.json"
run_config count_all      $MON --sink count --stats-json "$OUT/count_all.stats.json"
run_config count_all_nofeat $MON --sink count --features none --stats-json "$OUT/count_all_nofeat.stats.json"
run_config graph_all      $MON --no-log --stats-json "$OUT/graph_all.stats.json"
run_config graph_all_batch20 $MON --no-log --batch-ms 20 --stats-json "$OUT/graph_all_batch20.stats.json"
run_config graph_all_log  $MON --logfile "$OUT/graph_all_log.jsonl" --stats-json "$OUT/graph_all_log.stats.json"
echo "== base (end)"; measure base_end

$PY tools/analyze_overhead.py "$OUT"
