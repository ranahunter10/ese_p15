#!/usr/bin/env python3
"""Force a PID number to be reused, so the graph's generation handling can be
checked against REAL kernel data instead of only unit tests.

Spawns short-lived processes until the kernel hands out a PID it already used
in this run, then prints the PID and both command lines as JSON.
"""
import json
import subprocess
import sys
import time

def pid_max():
    try:
        return int(open("/proc/sys/kernel/pid_max").read())
    except OSError:
        return None

limit = int(sys.argv[1]) if len(sys.argv) > 1 else 60      # seconds
seen, deadline, n = {}, time.time() + limit, 0
while time.time() < deadline:
    tag = "p15gen%d" % n
    p = subprocess.Popen(["/bin/sh", "-c", ": %s" % tag])  # tag = unique argv
    p.wait()
    n += 1
    if p.pid in seen:
        print(json.dumps({"reused_pid": p.pid, "first_tag": seen[p.pid],
                          "second_tag": tag, "spawned": n, "pid_max": pid_max(),
                          "ok": True}))
        sys.exit(0)
    seen[p.pid] = tag
print(json.dumps({"ok": False, "spawned": n, "seconds": limit, "pid_max": pid_max(),
                  "note": "no PID repeated in this window; with a large "
                          "kernel.pid_max this needs far more spawns"}))
