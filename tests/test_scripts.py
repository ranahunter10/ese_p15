"""The shell scripts themselves, run for real.

Regression for the VM run of 17 Sep 2026: overhead_breakdown.sh hung at
"bcc_execsnoop" and Ctrl+C did nothing. A background job of a
non-interactive bash ignores SIGINT; BCC's tools keep that setting; the
script stopped them with `kill -INT` + an unbounded `wait`.
See tools/lib.sh for the full explanation.
"""

import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
LIB = os.path.join(ROOT, "tools", "lib.sh")
FAKE = os.path.join(HERE, "fakebcc")
SLEEPER = "%s -c 'import time; time.sleep(600)'" % sys.executable
# Ignores SIGTERM as well, to force the SIGKILL path.
STUBBORN = ("%s -c 'import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "print(\"ready\", flush=True); time.sleep(600)'" % sys.executable)


def alive(pid):
    """Same meaning as lib.sh is_running: exists and is not a zombie."""
    try:
        with open("/proc/%d/stat" % pid) as f:
            state = f.read().rsplit(") ", 1)[1].split()[0]
    except (OSError, IndexError):
        return False
    return state not in ("Z", "X")


def bash(script, timeout=30):
    """Run a bash snippet with lib.sh loaded, in its own process group.

    Output goes to a FILE, not a pipe. With a pipe, any stray grandchild
    that inherited the write end keeps communicate() blocked until the
    timeout even after the script itself has exited — which is exactly how
    this helper hung on the VM (bash 5.0 forks a subshell where newer bash
    replaces it with its last command, so a `( ...; sleep 600 ) &` left an
    orphan holding the pipe).
    """
    fd, path = tempfile.mkstemp()
    p = subprocess.Popen(["bash", "-c", ". %s\n%s" % (LIB, script)],
                         stdout=fd, stderr=subprocess.STDOUT,
                         start_new_session=True)
    try:
        p.wait(timeout=timeout)
    finally:
        _kill_group(p)
        os.close(fd)
        with open(path) as f:
            out = f.read()
        os.unlink(path)
    return p.returncode, out


def _kill_group(p):
    try:
        os.killpg(p.pid, signal.SIGKILL)   # also removes any orphaned children
    except OSError:
        pass
    p.wait()
    if p.stdout:
        p.stdout.close()


class DiagnosisTest(unittest.TestCase):
    """Reproduces the root cause, so the explanation in lib.sh stays true."""

    def test_background_job_ignores_sigint(self):
        code, out = bash(
            "%s -c 'import signal; print(signal.getsignal(signal.SIGINT) == signal.SIG_IGN)' &\n"
            "wait $!" % sys.executable)
        self.assertEqual(out.strip(), "True")

    def test_old_stop_pattern_never_returns(self):
        p = subprocess.Popen(
            ["bash", "-c", "%s & BG=$!; sleep 0.5; kill -INT $BG; wait $BG; echo returned" % SLEEPER],
            stdout=subprocess.PIPE, start_new_session=True)
        try:
            with self.assertRaises(subprocess.TimeoutExpired):
                p.communicate(timeout=3)
        finally:
            _kill_group(p)

    def test_bash_reaps_its_background_jobs(self):
        # Records real behaviour: bash reaps finished background jobs itself,
        # so kill -0 is NOT fooled here (a claim I first got wrong), and
        # `wait` still returns the saved exit status afterwards.
        code, out = bash(
            "(exit 7) & p=$!; sleep 0.5\n"
            "kill -0 $p 2>/dev/null && echo kill0=alive || echo kill0=dead\n"
            "is_running $p && echo is_running=alive || echo is_running=dead\n"
            "wait $p; echo status=$?")
        self.assertIn("kill0=dead", out)
        self.assertIn("is_running=dead", out)
        self.assertIn("status=7", out)

    def test_is_running_is_false_for_a_real_zombie(self):
        # A zombie we did not start as a bash job: python forks a child and
        # never waits for it. kill -0 IS fooled in this case; is_running is not.
        #
        # The scratch file is created by PYTHON, unique per run. An earlier
        # version used a fixed /tmp/p15_zpid, which passed as the normal user
        # and then failed under sudo: the kernel's fs.protected_regular rule
        # refuses to open a file in a world-writable sticky directory when
        # the file's owner is neither the caller nor the directory's owner —
        # and that refusal applies to root too. Observed on the VM twice.
        fd, zf = tempfile.mkstemp(prefix="p15zpid-")
        os.close(fd)
        try:
            code, out = bash(
                "%s -c 'import os, time\n"
                "pid = os.fork()\n"
                "if pid == 0: os._exit(0)\n"
                "print(pid, flush=True); time.sleep(600)' > %s & parent=$!\n"
                "sleep 1; z=$(cat %s)\n"
                "cut -d' ' -f3 /proc/$z/stat\n"
                "kill -0 $z 2>/dev/null && echo kill0=alive || echo kill0=dead\n"
                "is_running $z && echo is_running=alive || echo is_running=dead\n"
                "stop_bg $parent 2" % (sys.executable, zf, zf))
        finally:
            os.unlink(zf)
        self.assertIn("Z", out.split(), out)
        self.assertIn("kill0=alive", out)
        self.assertIn("is_running=dead", out)


class LibTest(unittest.TestCase):
    def test_stop_bg_stops_a_sigint_ignoring_tracer_fast(self):
        t0 = time.time()
        code, out = bash("%s & BG=$!; sleep 0.5; stop_bg $BG 10; "
                         "is_running $BG && echo still || echo gone" % SLEEPER)
        self.assertLess(time.time() - t0, 5)
        self.assertIn("gone", out)
        self.assertNotIn("SIGKILL", out)

    def test_stop_bg_escalates_to_sigkill(self):
        t0 = time.time()
        code, out = bash("%s & BG=$!; sleep 0.5; stop_bg $BG 1; "
                         "is_running $BG && echo still || echo gone" % STUBBORN)
        self.assertLess(time.time() - t0, 6)
        self.assertIn("sending SIGKILL", out)
        self.assertIn("gone", out)

    def test_stop_bg_on_exited_child_is_instant(self):
        t0 = time.time()
        code, out = bash("true & BG=$!; sleep 0.3; stop_bg $BG 10; echo done")
        self.assertLess(time.time() - t0, 2)
        self.assertIn("done", out)

    def test_stop_bg_empty_pid_is_noop(self):
        self.assertEqual(bash('stop_bg ""; echo ok')[1].strip(), "ok")

    def test_is_running_with_awkward_process_name(self):
        name = "x) y Z (w"
        code, out = bash(
            "%s -c 'import ctypes, time; ctypes.CDLL(None).prctl(15, b\"%s\", 0, 0, 0); "
            "time.sleep(600)' & p=$!; sleep 0.5\n"
            "cat /proc/$p/comm\n"
            "is_running $p && echo alive || echo dead\n"
            "stop_bg $p 2" % (sys.executable, name))
        self.assertIn(name, out)
        self.assertIn("alive", out)

    def test_wait_for_text_return_codes(self):
        code, out = bash(
            "f=$(mktemp)\n"
            # `exec` so the subshell BECOMES the sleep (one pid to stop, no
            # orphan), and output discarded so nothing can hold a handle open.
            "(sleep 0.5; echo 'Hooks attached' >> $f; exec sleep 600) > /dev/null 2>&1 & p=$!\n"
            "wait_for_text $f 'Hooks attached' $p 10; echo found=$?\n"
            "stop_bg $p 2\n"
            "g=$(mktemp); true & q=$!; sleep 0.3\n"
            "wait_for_text $g 'never' $q 10; echo died=$?\n"
            "wait $q\n"
            "h=$(mktemp); %s & r=$!\n"
            "wait_for_text $h 'never' $r 1; echo timeout=$?\n"
            "wait_for_text $h '' $r 1; echo empty=$?\n"
            "echo x > $h; wait_for_text $h '' $r 1; echo any=$?\n"
            "stop_bg $r 2\n" % SLEEPER, timeout=40)
        for want in ("found=0", "died=1", "timeout=2", "empty=2", "any=0"):
            self.assertIn(want, out)


class OverheadScriptTest(unittest.TestCase):
    """overhead_breakdown.sh end to end, with fakes and tiny workloads."""

    def env(self, out_dir, pidfile, **extra):
        env = dict(os.environ)
        env.update({
            "P15_SKIP_ROOT_CHECK": "1",
            "P15_PY": sys.executable,
            "P15_MON": "%s -u %s --mode quiet" % (sys.executable,
                                                  os.path.join(FAKE, "runmon.py")),
            "P15_EXECSNOOP": "%s %s" % (sys.executable, os.path.join(FAKE, "fake_snoop.py")),
            "P15_OPENSNOOP": "/nonexistent/opensnoop-bpfcc",
            "P15_ROUNDS": "1", "P15_EXEC_N": "5", "P15_OPEN_DIR": HERE,
            "P15_DD_COUNT": "100", "P15_GRACE": "3", "P15_OUT": out_dir,
            "PYTHONPATH": FAKE + os.pathsep + ROOT,
            "FAKE_SNOOP_PIDS": pidfile,
        })
        env.update(extra)
        return env

    def start(self, env):
        return subprocess.Popen(["bash", os.path.join(ROOT, "tools", "overhead_breakdown.sh")],
                                env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                start_new_session=True)

    def snoop_pids(self, pidfile):
        if not os.path.exists(pidfile):
            return []
        with open(pidfile) as f:
            return [int(x) for x in f.read().split()]

    def test_full_dry_run_finishes(self):
        with tempfile.TemporaryDirectory() as d:
            out_dir, pidfile = os.path.join(d, "out"), os.path.join(d, "pids")
            p = self.start(self.env(out_dir, pidfile))
            try:
                out, _ = p.communicate(timeout=180)
            finally:
                _kill_group(p)
            out = out.decode()
            self.assertEqual(p.returncode, 0, out)
            with open(os.path.join(out_dir, "timings.csv")) as f:
                rows = [l.split(",") for l in f.read().split()]
            configs = {r[0] for r in rows if r[1] != "skipped"}
            tracers = {"bcc_execsnoop", "count_exec", "count_open", "count_exit",
                       "count_net", "count_all", "count_all_nofeat", "graph_all",
                       "graph_all_batch20", "graph_all_log"}
            # Every config that ran is followed by a baseline measured next
            # to it in time (P15_INTERLEAVE, default on): the 16-Oct re-run
            # showed the machine's own cost moving +195 % during a single
            # run, which makes a distant baseline meaningless.
            self.assertEqual(configs,
                             {"base", "base_end"} | tracers
                             | {"base_after_" + c for c in tracers})
            # and each round now records wall AND cpu time
            self.assertTrue(all(len(r) == 6 for r in rows if r[1] != "skipped"),
                            rows[:3])
            self.assertIn(["bcc_opensnoop", "skipped", "0", "0"], rows)
            self.assertIn("not found: skipped", out)
            self.assertTrue(os.path.exists(os.path.join(out_dir, "overhead.md")))
            pids = self.snoop_pids(pidfile)
            self.assertEqual(len(pids), 1)
            self.assertFalse(any(alive(x) for x in pids), "fake execsnoop left running")
            self.assertNotIn("SIGKILL", out)    # SIGTERM was enough

    def test_workload_selection_makes_a_ladder_only_run(self):
        """`P15_WORKLOADS=sys` must run ONLY dd, in every config.

        The 16-Oct VM run could not resolve flat-vs-rising because one dd
        round took 0.15 s and the noise swamped it. Fixing that means more
        rounds and a longer dd, which is only affordable if the two
        expensive workloads can be left out — so the selector is part of
        the experiment, not a convenience.
        """
        with tempfile.TemporaryDirectory() as d:
            out_dir, pidfile = os.path.join(d, "out"), os.path.join(d, "pids")
            p = self.start(self.env(out_dir, pidfile, P15_WORKLOADS="sys"))
            try:
                out, _ = p.communicate(timeout=180)
            finally:
                _kill_group(p)
            self.assertEqual(p.returncode, 0, out.decode()[-2000:])
            with open(os.path.join(out_dir, "timings.csv")) as f:
                rows = [l.split(",") for l in f.read().split()]
            kinds = {r[1] for r in rows}
            self.assertEqual(kinds, {"sys", "skipped"})     # no exec, no open
            with open(os.path.join(out_dir, "env.txt")) as f:
                self.assertIn("workloads=sys", f.read())
            self.assertTrue(os.path.exists(os.path.join(out_dir, "overhead.md")))

    def test_pinning_is_recorded_and_degrades_gracefully(self):
        # P15_PIN=1 with taskset present pins; without it, the run still
        # completes and says so rather than failing.
        with tempfile.TemporaryDirectory() as d:
            out_dir, pidfile = os.path.join(d, "out"), os.path.join(d, "pids")
            p = self.start(self.env(out_dir, pidfile, P15_WORKLOADS="sys",
                                    P15_PIN="1"))
            try:
                out, _ = p.communicate(timeout=180)
            finally:
                _kill_group(p)
            text = out.decode()
            self.assertEqual(p.returncode, 0, text[-2000:])
            self.assertTrue("CPU pinning ON" in text
                            or "taskset not found" in text, text[-500:])
            with open(os.path.join(out_dir, "env.txt")) as f:
                self.assertIn("pinned=1", f.read())

    def test_ctrl_c_stops_everything(self):
        with tempfile.TemporaryDirectory() as d:
            out_dir, pidfile = os.path.join(d, "out"), os.path.join(d, "pids")
            # bigger exec load so Ctrl+C lands while the tracer is running
            p = self.start(self.env(out_dir, pidfile, P15_EXEC_N="3000"))
            try:
                deadline = time.time() + 60
                while not self.snoop_pids(pidfile) and time.time() < deadline:
                    time.sleep(0.2)
                self.assertTrue(self.snoop_pids(pidfile), "fake tracer never started")
                time.sleep(1)
                t0 = time.time()
                os.killpg(p.pid, signal.SIGINT)      # what Ctrl+C in a terminal does
                out, _ = p.communicate(timeout=30)
                elapsed = time.time() - t0
            finally:
                _kill_group(p)
            out = out.decode()
            self.assertEqual(p.returncode, 130, out)
            self.assertLess(elapsed, 10)
            self.assertIn("interrupted", out)
            self.assertFalse(any(alive(x) for x in self.snoop_pids(pidfile)),
                             "fake execsnoop survived Ctrl+C")
            self.assertNotIn("== count_exec", out)   # it really stopped

class ClaimsScriptTest(unittest.TestCase):
    """claims_evidence.sh end to end with the fake monitor (no kernel)."""

    def test_dry_run_finishes_and_writes_table(self):
        with tempfile.TemporaryDirectory() as d:
            out_dir = os.path.join(d, "out")
            env = dict(os.environ)
            env.update({
                "P15_SKIP_ROOT_CHECK": "1", "P15_PY": sys.executable,
                "P15_MON": "%s -u %s --mode quiet" % (sys.executable,
                                                      os.path.join(FAKE, "runmon.py")),
                "P15_OUT": out_dir, "P15_GRACE": "3", "P15_REUSE_S": "3",
                "P15_LOSS_S": "2",
                "PYTHONPATH": FAKE + os.pathsep + ROOT,
            })
            p = subprocess.Popen(["bash", os.path.join(ROOT, "tools", "claims_evidence.sh")],
                                 env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 start_new_session=True)
            try:
                out, _ = p.communicate(timeout=240)
            finally:
                _kill_group(p)
                if p.stdout:
                    p.stdout.close()
            out = out.decode()
            self.assertEqual(p.returncode, 0, out[-3000:])
            table = os.path.join(out_dir, "claims_evidence.md")
            self.assertTrue(os.path.exists(table), out[-2000:])
            with open(table) as f:
                text = f.read()
            for cid in ("C1", "C2", "C3", "C4", "C5", "C6"):
                self.assertIn("| %s |" % cid, text)
            # with the fake monitor no kernel events exist, so claims must
            # read NOT SHOWN rather than silently passing
            self.assertIn("NOT SHOWN", text)
            self.assertIn("claims,", out)

    def test_refuses_without_root_unless_bypassed(self):
        if os.geteuid() == 0:
            self.skipTest("running as root")
        r = subprocess.run(["bash", os.path.join(ROOT, "tools", "overhead_breakdown.sh")],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        self.assertIn("run with sudo", r.stdout.decode())


if __name__ == "__main__":
    unittest.main()


class FixedTmpPathTest(unittest.TestCase):
    """No test or script may write to a fixed path in a shared directory.

    This has now bitten three times: /tmp/p15_zpid in a unit test (twice,
    once as the user and once under sudo) and /tmp/p15_payload.txt in the
    validation script. The kernel's fs.protected_regular rule refuses to
    open a file in a world-writable sticky directory whose owner is neither
    the caller nor the directory's owner — and it refuses root as well, so
    'run it with sudo' is not a workaround. Unique names per run are.
    """

    REDIRECT = re.compile(r">>?\s*/tmp/[A-Za-z0-9_.-]+")

    def test_no_shell_redirect_to_a_fixed_tmp_path(self):
        root = os.path.dirname(os.path.abspath(__file__))
        offenders = []
        for folder in (root, os.path.join(root, "..", "tools")):
            for name in sorted(os.listdir(folder)):
                if not name.endswith((".py", ".sh")):
                    continue
                path = os.path.join(folder, name)
                with open(path) as f:
                    for lineno, line in enumerate(f, 1):
                        if self.REDIRECT.search(line) and "mktemp" not in line:
                            offenders.append("%s:%d: %s" % (name, lineno, line.strip()))
        self.assertEqual(offenders, [], "fixed /tmp paths:\n" + "\n".join(offenders))
