# lib.sh — process-control helpers shared by vm_validation.sh and
# overhead_breakdown.sh.   Usage:  . "$(dirname "$0")/lib.sh"
#
# Why this file exists (VM run, 17 Sep 2026): overhead_breakdown.sh hung
# forever at "bcc_execsnoop" and Ctrl+C could not stop it. Two shell facts
# combined:
#
#  1. A NON-interactive bash starts background jobs (`cmd &`) with SIGINT
#     and SIGQUIT set to "ignore" (POSIX rule for shells without job
#     control). Python keeps an inherited "ignore" unless the program
#     installs its own handler. hids.monitor installs one; BCC's
#     execsnoop-bpfcc does not, so it silently ignored every SIGINT —
#     including the one from Ctrl+C, which reaches the whole process group.
#  2. The script stopped tracers with `kill -INT pid; wait pid`. `wait`
#     has no timeout, so an ignored signal meant waiting forever, and the
#     EXIT cleanup trap repeated the same two commands.
#
# Fix: stop with SIGTERM (not ignored, and hids.monitor treats it exactly
# like Ctrl+C, so stats are still written), wait with a deadline, then
# SIGKILL. The kernel detaches a BCC tool's eBPF programs when the process
# dies, even on SIGKILL, because they are tied to its file descriptors.

# is_running PID — true only if PID exists and is not a zombie.
# In bash, `kill -0` usually gives the same answer, because bash reaps
# finished background jobs by itself (SIGCHLD) and keeps their exit status.
# Reading the state from /proc is still stricter: it is also correct for
# processes this shell did not start, where a zombie would fool `kill -0`.
# (An earlier version of this comment claimed kill -0 was fooled for our own
# background jobs; tests/test_scripts.py showed that was wrong.)
is_running() {
  local pid=$1 state
  [ -n "$pid" ] || return 1
  [ -r "/proc/$pid/stat" ] || return 1
  # /proc/PID/stat is "pid (comm) STATE ..."; comm may contain spaces or
  # parentheses, so take the text after the LAST ") ".
  state=$(sed 's/.*) //' "/proc/$pid/stat" 2>/dev/null | cut -d' ' -f1)
  [ -n "$state" ] && [ "$state" != "Z" ] && [ "$state" != "X" ]
}

# stop_bg PID [GRACE_SECONDS]
# SIGTERM, wait up to GRACE (default 15 s), then SIGKILL. Always reaps the
# child. Never blocks longer than GRACE + ~1 s.
stop_bg() {
  local pid=$1 grace=${2:-15} i
  [ -n "$pid" ] || return 0
  if is_running "$pid"; then
    kill -TERM "$pid" 2>/dev/null
    for i in $(seq 1 $((grace * 5))); do
      is_running "$pid" || break
      sleep 0.2
    done
    if is_running "$pid"; then
      echo "  (pid $pid still running ${grace}s after SIGTERM: sending SIGKILL)"
      kill -KILL "$pid" 2>/dev/null
      for i in $(seq 1 10); do is_running "$pid" || break; sleep 0.1; done
    fi
  fi
  wait "$pid" 2>/dev/null
  return 0
}

# wait_for_text FILE TEXT PID [SECONDS]
# Wait until FILE contains TEXT ("" = any output at all).
# Returns 0 when found, 1 if PID died first, 2 on timeout.
wait_for_text() {
  local file=$1 text=$2 pid=$3 secs=${4:-60} i
  for i in $(seq 1 $((secs * 2))); do
    if [ -z "$text" ]; then
      [ -s "$file" ] && return 0
    else
      grep -q -- "$text" "$file" 2>/dev/null && return 0
    fi
    is_running "$pid" || return 1
    sleep 0.5
  done
  return 2
}
