#!/usr/bin/env bash
# claims_evidence.sh — evidence for the six claims, one command, one table.
#   sudo bash tools/claims_evidence.sh
# ~3 min. Writes runs/claims-<timestamp>/claims_evidence.md
#
# Closes the three gaps unit tests alone cannot: real PID reuse, real event
# loss, and the query tool on a real snapshot.
#
# Test overrides: P15_PY, P15_MON, P15_OUT, P15_GRACE, P15_REUSE_S,
#                 P15_LOSS_S, P15_SKIP_ROOT_CHECK
set -u
cd "$(dirname "$0")/.."
. tools/lib.sh
if [ "$(id -u)" -ne 0 ] && [ "${P15_SKIP_ROOT_CHECK:-0}" != 1 ]; then echo "run with sudo"; exit 1; fi
PY=${P15_PY:-python3}
MON=${P15_MON:-"$PY -u -m hids.monitor --mode quiet"}
GRACE=${P15_GRACE:-15}
REUSE_S=${P15_REUSE_S:-90}
LOSS_S=${P15_LOSS_S:-12}
OUT=${P15_OUT:-"runs/claims-$(date +%Y%m%d-%H%M%S)"}
mkdir -p "$OUT"
MON_PID=""
cleanup(){ stop_bg "$MON_PID" "$GRACE"; MON_PID=""; }
on_int(){ echo; echo "== interrupted"; cleanup; exit 130; }
trap cleanup EXIT; trap on_int INT TERM
echo "== output: $OUT"

start(){ # $1 name, rest args
  local name=$1; shift
  $MON --logfile "$OUT/$name.jsonl" --stats-json "$OUT/$name.stats.json" \
       --snapshot "$OUT/$name.graph.json" "$@" > "$OUT/$name.console.txt" 2>&1 &
  MON_PID=$!
  wait_for_text "$OUT/$name.console.txt" "Hooks attached" "$MON_PID" 60 || {
    echo "monitor did not start:"; cat "$OUT/$name.console.txt"; exit 1; }
}
stop(){ sleep 1; stop_bg "$MON_PID" "$GRACE"; MON_PID=""; }

echo "== 1/3 behaviour + queries (claims C1-C4)"
start behaviour
/bin/echo alpha beta gamma > /dev/null
# A private directory per run: a fixed /tmp name fails as soon as a
# leftover file belongs to another user (fs.protected_regular refuses even
# root). Same lesson as Journal rows 51 and 75.
WORK=$(mktemp -d "/tmp/p15claims-XXXXXXXX")
chmod 755 "$WORK"
echo "{\"payload\": \"$WORK/payload.txt\"}" > "$OUT/paths.json"
sh -c "echo secret > $WORK/payload.txt"
cat "$WORK/payload.txt" > /dev/null
$PY -c "import os; os.execv('/nonexistent_p15_binary',['x'])" 2>/dev/null
$PY - <<'PYEOF' 2>/dev/null
import os
fd = os.memfd_create("p15demo")
os.write(fd, open("/bin/true","rb").read())
os.execve(fd, ["p15demo"], {})
PYEOF
sh -c 'exit 3'
stop

echo "== 2/3 real PID reuse (claim C4) — up to ${REUSE_S}s (kernel.pid_max=$(cat /proc/sys/kernel/pid_max))"
start reuse
$PY tools/force_pid_reuse.py "$REUSE_S" > "$OUT/reuse.json"
cat "$OUT/reuse.json"
stop

echo "== 3/3 event loss is counted, not silent (claim C5) — tiny buffer"
start loss --pages 1
for i in 1 2 3; do timeout "$LOSS_S" find / > /dev/null 2>&1 & done
sleep $((LOSS_S + 1))
stop

echo "== queries on the real snapshot"
{ echo "### trace (root cause of the reader)"
  READER=$($PY - "$OUT/behaviour.jsonl" <<'PYEOF'
import json,sys
for l in open(sys.argv[1]):
    e=json.loads(l)
    if e.get("type")=="EXEC" and e.get("argv",[])[:1]==["cat"] and "payload.txt" in " ".join(e.get("argv",[])):
        print(e["pid"])
PYEOF
)
  READER=$(echo "$READER" | tail -1)
  echo "reader pid: ${READER:-not found}"
  [ -n "$READER" ] && $PY tools/query_graph.py "$OUT/behaviour.graph.json" trace "$READER" --no-libs
  echo; echo "### writers of $WORK/payload.txt"
  $PY tools/query_graph.py "$OUT/behaviour.graph.json" writers "$WORK/payload.txt"
  echo; echo "### fdexec (programs run from memory)"
  $PY tools/query_graph.py "$OUT/behaviour.graph.json" fdexec
} > "$OUT/queries.txt" 2>&1
tail -20 "$OUT/queries.txt"

$PY tools/analyze_claims.py "$OUT"
