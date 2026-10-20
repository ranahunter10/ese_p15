#!/bin/sh
# run_f1.sh -- compile and run the F1 gate (token bucket) with Icarus Verilog.
# Usage: sh fpga/sim/run_f1.sh [--vcd] [--seed N]       (works from any cwd)
# Exit status: 0 only if the testbench prints "SUMMARY: N passed, 0 failed".
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
FPGA=$(cd "$HERE/.." && pwd)
BUILD="$HERE/build"
mkdir -p "$BUILD"

PLUS=""
while [ $# -gt 0 ]; do
    case "$1" in
        --vcd)  PLUS="$PLUS +vcd" ;;
        --seed) shift; PLUS="$PLUS +seed=$1" ;;
        *) echo "run_f1.sh: unknown argument $1" >&2; exit 2 ;;
    esac
    shift
done

iverilog -g2001 -Wall -Wno-timescale -o "$BUILD/tb_f1.vvp" \
    -I "$FPGA/rtl" -I "$FPGA/tb" -s tb_f1 \
    "$FPGA/rtl/token_bucket_update.v" \
    "$FPGA/rtl/token_bucket.v" \
    "$FPGA/tb/tb_f1_unit.v" \
    "$FPGA/tb/tb_f1_wrap.v" \
    "$FPGA/tb/tb_f1.v"

LOG="$BUILD/tb_f1.log"
# vvp exits nonzero on $fatal; run inside BUILD so the VCD lands there.
set +e
( cd "$BUILD" && vvp -n tb_f1.vvp $PLUS ) | tee "$LOG"
set -e

if grep -q '^SUMMARY: [0-9]* passed, 0 failed$' "$LOG" && ! grep -q '^FAIL' "$LOG"; then
    exit 0
fi
echo "run_f1.sh: F1 gate FAILED" >&2
exit 1
