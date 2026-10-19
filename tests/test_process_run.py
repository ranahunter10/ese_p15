"""The monitor as a real OS process with output redirected to a FILE —
exactly how tools/vm_validation.sh runs it. Regression test for the VM run
of 16 Sep 2026, where "Hooks attached" stayed in Python's block buffer, the
script's grep never saw it, and validation stopped after 60 s.

PYTHONUNBUFFERED is removed from the environment on purpose: a sandbox that
sets it hid this bug from every other test."""

import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
FAKE = os.path.join(HERE, "fakebcc")


class RedirectedOutputTest(unittest.TestCase):
    def test_ready_line_visible_while_running_and_sigint_stops(self):
        env = dict(os.environ)
        env.pop("PYTHONUNBUFFERED", None)
        env["PYTHONPATH"] = FAKE + os.pathsep + ROOT
        with tempfile.TemporaryDirectory() as d:
            con = os.path.join(d, "console.txt")
            with open(con, "w") as out:
                proc = subprocess.Popen(
                    [sys.executable, os.path.join(FAKE, "runmon.py"),
                     "--mode", "quiet", "--no-log"],
                    stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                    env=env, cwd=d)
            try:
                seen = False
                deadline = time.time() + 15
                while time.time() < deadline and not seen:
                    time.sleep(0.2)
                    with open(con) as f:
                        seen = "Hooks attached" in f.read()
                self.assertTrue(seen, "ready line not flushed while monitor runs")
                proc.send_signal(signal.SIGINT)
                self.assertEqual(proc.wait(timeout=10), 0)
                with open(con) as f:
                    self.assertIn("Stopped after", f.read())
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()


if __name__ == "__main__":
    unittest.main()
