"""Run `python -m hids.monitor` with the fake bcc and without needing root."""
import os
import runpy
import sys

os.geteuid = lambda: 0
sys.argv = ["hids.monitor"] + sys.argv[1:]
runpy.run_module("hids.monitor", run_name="__main__")
