"""Stand-in for execsnoop-bpfcc / opensnoop-bpfcc in script tests.

Like the real BCC tools (0.12) it installs NO signal handler, so when a
non-interactive bash starts it with `&` it inherits "ignore SIGINT" — the
exact condition that hung overhead_breakdown.sh on the VM (17 Sep 2026).
Writes its PID to $FAKE_SNOOP_PIDS so tests can check it was stopped.
"""
import os
import time

print("PCOMM            PID    PPID   RET ARGS", flush=True)
with open(os.environ["FAKE_SNOOP_PIDS"], "a") as f:
    f.write("%d\n" % os.getpid())
time.sleep(600)
