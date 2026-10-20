#!/usr/bin/env python3
"""mutate_f1.py -- mutation check for the F1 gate (fpga/sim/run_f1.sh).

For each mutant: copy fpga/{rtl,tb,sim} to OUT/<id>/, apply one mutation (one or
two exact text replacements, each pattern must occur exactly once) to the
COPY's RTL, run the
copy's run_f1.sh, and list the named tests that FAIL.  The working tree is
never written.  A mutant is KILLED only if >= 1 named test prints FAIL and
the run reaches its SUMMARY line (a compile error does not count as a kill).

Usage: python3 fpga/sim/mutate_f1.py [OUT_DIR] [-j N]
       (default OUT_DIR = fpga/sim/build/mut, -j 2)
Exit:  0 iff every mutant is KILLED, except those marked EQUIV (proved
       equivalent by argument in tb/MUTANTS_F1.md), which must SURVIVE.
"""
import os, re, shutil, subprocess, sys
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
FPGA = os.path.dirname(HERE)
U, W = "rtl/token_bucket_update.v", "rtl/token_bucket.v"

MUTANTS = [
 ("M1", U, "refill off by one cycle (elapsed - 1)",
  "wire [TS_W-1:0]   elapsed = now - st_last;",
  "wire [TS_W-1:0]   elapsed = now - st_last - 1'b1;"),
 ("M2", U, "no saturation at B (sum never capped)",
  "wire              full    = (!st_valid) || (sum >= CAP);",
  "wire              full    = (!st_valid);"),
 ("M3", U, "non-conforming packet consumes tokens (drains to 0)",
  "assign nx_tokens = conform ? (avail - COST_K) : avail;",
  "assign nx_tokens = conform ? (avail - COST_K) : (pkt ? {TOK_W{1'b0}} : avail);"),
 ("M4", U, "conform compare > instead of >=",
  "wire              enough  = (avail >= COST_K);",
  "wire              enough  = (avail > COST_K);"),
 ("M5", U, "elapsed without wrap handling (now < last -> 0)",
  "wire [TS_W-1:0]   elapsed = now - st_last;",
  "wire [TS_W-1:0]   elapsed = (now >= st_last) ? (now - st_last) : {TS_W{1'b0}};"),
 ("M6", U, "multiplier product truncated by 2 bits",
  "wire [PROD_W-1:0] refill  = el_sat * RATE_K;",
  "wire [PROD_W-3:0] refill  = el_sat * RATE_K;"),
 ("M7", U, "no clamp before multiply (elapsed truncated to EL_W bits, wraps)",
  "wire [EL_W-1:0]   el_sat  = el_big ? T_FULL_K : elapsed[EL_W-1:0];",
  "wire [EL_W-1:0]   el_sat  = elapsed[EL_W-1:0];"),
 ("M8", U, "T_FULL = floor(CAP/R) instead of ceil",
  "localparam [63:0] T_FULL = (CAP + RATE_PPS - 64'd1) / RATE_PPS;",
  "localparam [63:0] T_FULL = CAP / RATE_PPS;"),
 ("M9", U, "never-seen source starts EMPTY (tok_in = 0 and not forced full)",
  [("wire [TOK_W-1:0]  tok_in  = st_valid ? st_tokens : CAP_K;",
    "wire [TOK_W-1:0]  tok_in  = st_valid ? st_tokens : {TOK_W{1'b0}};"),
   ("wire              full    = (!st_valid) || (sum >= CAP);",
    "wire              full    = (sum >= CAP);")], None),
 ("M10", U, "EQUIV: drop the redundant (!st_valid) term in `full`",
  "wire              full    = (!st_valid) || (sum >= CAP);",
  "wire              full    = (sum >= CAP);"),
 ("M11", W, "wrapper: timestamp not written back",
  "                st_last   <= nx_last;",
  "                st_last   <= st_last;"),
 ("M12", W, "wrapper: reset does not clear never-seen state",
  "            st_valid  <= 1'b0;",
  "            st_valid  <= st_valid;"),
 ("M13", W, "wrapper: dec_valid stuck high",
  "            dec_valid <= pkt_in;",
  "            dec_valid <= 1'b1;"),
 ("M14", W, "wrapper: counter steps by 2",
  "            cnt       <= cnt + {{(TS_W-1){1'b0}}, 1'b1};",
  "            cnt       <= cnt + {{(TS_W-2){1'b0}}, 2'b10};"),
]

def run(m, out):
    mid, f, desc, orig, repl = m
    d = os.path.join(out, mid)
    shutil.rmtree(d, ignore_errors=True)
    for sub in ("rtl", "tb", "sim"):
        shutil.copytree(os.path.join(FPGA, sub), os.path.join(d, sub),
                        ignore=shutil.ignore_patterns("build"))
    p = os.path.join(d, f)
    s = open(p).read()
    edits = orig if isinstance(orig, list) else [(orig, repl)]
    for o, rp in edits:
        if s.count(o) != 1:
            return mid, desc, "APPLY-FAILED (pattern count %d)" % s.count(o), "", []
        s = s.replace(o, rp)
    open(p, "w").write(s)
    r = subprocess.run(["sh", os.path.join(d, "sim", "run_f1.sh")],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    log = r.stdout
    open(os.path.join(d, "log.txt"), "w").write(log)
    fails = [l[5:] for l in log.splitlines() if l.startswith("FAIL ")]
    summ = next((l for l in log.splitlines() if l.startswith("SUMMARY")), "")
    st = "KILLED" if (fails and summ and r.returncode != 0) else \
         ("NO-SUMMARY" if not summ else "SURVIVED")
    return mid, desc, st, summ, fails

def main():
    args = sys.argv[1:]
    j = 2
    if "-j" in args:
        i = args.index("-j"); j = int(args[i + 1]); del args[i:i + 2]
    out = os.path.abspath(args[0]) if args else os.path.join(HERE, "build", "mut")
    os.makedirs(out, exist_ok=True)
    ok = True
    with ThreadPoolExecutor(max_workers=j) as ex:
        for mid, desc, st, summ, fails in ex.map(lambda m: run(m, out), MUTANTS):
            if desc.startswith("EQUIV"):
                # expected-equivalent: must SURVIVE (documents the redundancy)
                ok &= (st == "SURVIVED")
                st = st + "(expected: equivalent)"
            else:
                ok &= (st == "KILLED")
            print("%-4s %-8s [%s] %s" % (mid, st, summ, desc))
            for l in fails[:6]:
                print("       FAIL " + l)
            if len(fails) > 6:
                print("       ... %d FAIL lines in total (%s/%s/log.txt)" % (len(fails), out, mid))
            sys.stdout.flush()
    print("MUTANTS: %s" % ("all killed" if ok else "NOT all killed"))
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
