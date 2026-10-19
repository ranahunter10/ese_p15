"""tools/analyze_overhead.py on synthetic timings that encode each hypothesis."""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

import helpers  # sets sys.path
assert helpers

TOOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools",
                    "analyze_overhead.py")

# (exec, open, sys) seconds per config
TIMES = {
    "base": (3.7, 0.8, 0.50),
    "bcc_execsnoop": (5.0, 0.8, 0.52),
    "bcc_opensnoop": (3.9, 2.0, 0.51),
    "count_exec": (6.0, 1.5, 1.20),        # syscall-tracepoint tax on dd
    "count_open": (6.5, 3.0, 1.25),
    "count_exit": (4.0, 0.82, 0.51),
    "count_net": (3.8, 0.82, 1.21),        # 2 syscall tracepoints, like count_exec
    "count_all": (8.0, 3.5, 1.30),
    "count_all_nofeat": (7.0, 3.0, 1.30),
    "graph_all": (10.0, 5.0, 1.30),
    "graph_all_batch20": (8.5, 3.8, 1.30),
    "graph_all_log": (11.5, 5.2, 1.30),
    "base_end": (3.7, 0.8, 0.50),
}


class OverheadAnalyzerTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        with open(os.path.join(self.d, "timings.csv"), "w") as f:
            for cfg, vals in TIMES.items():
                for r in (1, 2, 3):
                    for w, v in zip(("exec", "open", "sys"), vals):
                        f.write("%s,%s,%d,%s\n" % (cfg, w, r, v * (1 + 0.01 * r)))
            f.write("bcc_broken,skipped,0,0\n")
        for cfg in TIMES:
            if cfg.startswith(("count", "graph")):
                with open(os.path.join(self.d, cfg + ".stats.json"), "w") as f:
                    json.dump({"records_per_s": 4000, "monitor_cpu_percent_of_one_core": 20,
                               "features": [] if "nofeat" in cfg else ["FILE_IDENTITY"],
                               "lost": 5 if cfg == "graph_all" else 0, "loss_rate": 0.001,
                               "features_refused": []}, f)

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_readings(self):
        out = subprocess.check_output([sys.executable, TOOL, self.d]).decode()
        self.assertIn("| count_exec | +62% (6.12 s)", out)
        self.assertIn("**Syscall-tracepoint cost:**", out)
        self.assertIn("**Consistent:**", out)
        self.assertIn("**Python processing**", out)
        self.assertIn("**Batching helps**", out)
        self.assertIn("**Logging**", out)
        self.assertIn("**Inode/kernel-path reads**", out)
        self.assertIn("**Loss:** graph_all", out)
        self.assertIn("Skipped (tracer failed to start): bcc_broken", out)
        self.assertNotIn("**Drift:**", out)
        # (6.12 - 3.774) s / 2000 execs;  (1.224 - 0.510) s / 600k syscalls
        self.assertIn("| count_exec | 1.17 ms | 1190 ns |", out)
        self.assertTrue(os.path.exists(os.path.join(self.d, "overhead.md")))

    def test_cpu_time_and_adjacent_baselines_survive_a_drifting_machine(self):
        """The 16-Oct re-run's actual failure mode, in synthetic form.

        Wall time triples across the run (the host taking the CPU away),
        while the workload's own CPU time is honest throughout. With wall
        time and one distant baseline, a config's number is mostly its
        position in the run; with CPU time and the baseline measured beside
        it, the real effect comes back.
        """
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        # wall drifts 1.5 -> 4.5 s over the run; cpu is steady at 1.0 s for
        # the baseline and 1.5 s under a hook that really costs 50 %.
        seq = [("base", 1.5, 1.0), ("count_exec", 2.0, 1.5),
               ("base_after_count_exec", 2.5, 1.0), ("count_open", 3.5, 1.5),
               ("base_after_count_open", 4.0, 1.0), ("base_end", 4.5, 1.0)]
        with open(os.path.join(d, "timings.csv"), "w") as f:
            for cfg, wall, cpu in seq:
                for r in (1, 2, 3):
                    f.write("%s,sys,%d,%.3f,%.3f,%.3f\n"
                            % (cfg, r, wall, cpu * 0.4, cpu * 0.6))
        for cfg in ("count_exec", "count_open"):
            with open(os.path.join(d, cfg + ".stats.json"), "w") as f:
                json.dump({"records_per_s": 10,
                           "monitor_cpu_percent_of_one_core": 1.0,
                           "lost": 0, "loss_rate": 0.0,
                           "features": [], "features_refused": []}, f)
        out = subprocess.check_output([sys.executable, TOOL, d]).decode()
        self.assertIn("workload CPU time (user+sys)", out)
        self.assertIn("immediately before and after each config", out)
        # 1.5 cpu vs a local baseline of 1.0 -> +50 %, for BOTH configs,
        # even though their wall times differ by 1.5 s. Check the TABLE
        # rows, not the whole document (the ladder reading repeats them).
        # the slowdown table, not the per-operation table below it
        table = out.split("## Added cost per operation")[0]
        rows = {l.split("|")[1].strip(): l for l in table.splitlines()
                if l.startswith("| count_")}
        self.assertEqual(sorted(rows), ["count_exec", "count_open"])
        for cfg, line in rows.items():
            self.assertIn("+50%", line, cfg)
        # and with the drift removed, the ladder becomes readable again
        self.assertNotIn("INCONCLUSIVE", out)

    def test_the_ladder_refuses_to_be_read_when_the_data_cannot_resolve_it(self):
        """The 16-Oct VM run produced a ladder nobody should read.

        Non-monotonic, with a single-config spread as wide as the whole
        range and a baseline that drifted 22 %. The analyzer used to print
        "flat = paid once, rising = per hook" beside those numbers, which
        invites the reader to see whichever answer they already believed.
        It must now say INCONCLUSIVE and name what would fix the
        experiment.
        """
        noisy = {                    # dd seconds per round, as measured
            "base":             [0.15, 0.15, 0.15],
            "count_exit":       [0.19, 0.19, 0.19],
            "count_exec":       [0.24, 0.17, 0.31],
            "count_open":       [0.29, 0.20, 0.41],
            "count_net":        [0.19, 0.09, 0.33],   # 6 tp, LOWER than 4 tp
            "count_all":        [0.26, 0.14, 0.40],
            "count_all_nofeat": [0.25, 0.18, 0.33],
            "base_end":         [0.12, 0.12, 0.12],
        }
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        with open(os.path.join(d, "timings.csv"), "w") as f:
            for cfg, vals in noisy.items():
                for r, v in enumerate(vals, 1):
                    f.write("%s,sys,%d,%s\n" % (cfg, r, v))
        for cfg in noisy:
            if cfg.startswith("count"):
                with open(os.path.join(d, cfg + ".stats.json"), "w") as f:
                    json.dump({"records_per_s": 0 if cfg == "count_net" else 1000,
                               "monitor_cpu_percent_of_one_core": 5.0,
                               "lost": 0, "loss_rate": 0.0,
                               "features": ["FILE_IDENTITY"],
                               "features_refused": []}, f)
        out = subprocess.check_output([sys.executable, TOOL, d]).decode()
        self.assertIn("INCONCLUSIVE", out)
        self.assertIn("not monotonic", out)
        self.assertIn("P15_PIN=1", out)
        self.assertNotIn("Flat across the ladder", out)
        # and the clean comparison is still offered
        self.assertIn("Attachment versus events", out)

    def test_tracepoint_ladder_is_reported_with_its_verdict(self):
        """The dd workload calls none of the hooked syscalls, so its slowdown
        isolates the per-syscall tax. The fixture encodes a FLAT ladder — 0 tp
        ~0 %, then ~+140 % at 2 hooks and barely more at 4, 6 and 12 — which
        is the signature of a tax paid once rather than per hook.

        This used to assert only that five labels appeared, so it passed
        whatever conclusion the report drew from them, including the opposite
        one. An audit flagged that; the labels are the cheap half. The
        verdict is the half that matters, because the whole design decision
        (hook count is not a budget, event rate is) rests on it.
        """
        out = subprocess.check_output([sys.executable, TOOL, self.d]).decode()
        self.assertIn("Cost per added syscall tracepoint", out)
        for frag in ("0 tp count_exit", "2 tp count_exec", "6 tp count_net",
                     "4 tp count_open", "12 tp count_all"):
            self.assertIn(frag, out)

        self.assertIn("paid once", out,
                      "the ladder is flat but the report does not say so:\n%s" % out)
        # and the percentages the reading rests on must be in it, so the
        # claim can be checked against the numbers without re-running
        ladder = out[out.index("Cost per added syscall tracepoint"):]
        self.assertTrue(re.search(r"\+1[0-9]{2}(\.\d+)?\s*%", ladder),
                        "no per-configuration percentage near the verdict:\n%s"
                        % ladder)

    def test_report_stamps_which_build_measured_and_which_analyzed(self):
        """A stale tree must be visible in its own output.

        On 16 Oct a corrected report was produced by an UNcorrected analyzer:
        the new zip had not replaced the old tree, the command ran happily,
        and nothing in the 40-line report said which tool wrote it. The
        numbers read as a result rather than as a stale instrument. The run
        now records the build that measured it and the report names the
        build that read it.
        """
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        with open(os.path.join(d, "timings.csv"), "w") as f:
            for cfg, v in (("base", 1.0), ("count_exec", 1.5), ("base_end", 1.0)):
                for r in (1, 2):
                    f.write("%s,sys,%d,%.3f,%.3f,%.3f\n" % (cfg, r, v, v * 0.4, v * 0.6))
        with open(os.path.join(d, "env.txt"), "w") as f:
            f.write("dd_count=6000000\nexec_n=2000\nbuild=v9.9z\n")
        out = subprocess.check_output([sys.executable, TOOL, d]).decode()
        self.assertIn("Measured by build **v9.9z**", out)
        self.assertIn("analyzed by build **%s**" % self.version(), out)
        # a run captured before the stamp existed must still say so plainly
        os.remove(os.path.join(d, "env.txt"))
        out = subprocess.check_output([sys.executable, TOOL, d]).decode()
        self.assertIn("Measured by build **unrecorded**", out)

    @staticmethod
    def version():
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "VERSION")
        with open(p) as f:
            return f.read().strip()

    def test_every_version_string_in_the_tree_matches_the_version_file(self):
        """One source of truth, and this guard covers ALL of its copies.

        The first version of this test compared VERSION against the README
        title and nothing else — so when `hids/__init__.py` still said 3.5g
        in a tree stamped v3.5i, the guard could not see it, and the v3.5i
        review found it instead. A drift guard that checks two of three
        places is worse than none: it reports agreement it did not verify.

        So this discovers the copies rather than listing them. Any new
        `__version__` anywhere under the package is picked up automatically,
        and a `(vX.Y)` in the README title is required to exist.
        """
        root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
        want = self.version().lstrip("v")
        found = {}

        with open(os.path.join(root, "README.md")) as f:
            title = f.readline()
        m = re.search(r"\((v[\d.]+[a-z]?)\)", title)
        self.assertIsNotNone(m, "README title carries no (vX.Y) version: %r" % title)
        found["README.md title"] = m.group(1).lstrip("v")

        for sub in ("hids", "tools"):
            for dirpath, _dirs, files in os.walk(os.path.join(root, sub)):
                for name in files:
                    if not name.endswith(".py"):
                        continue
                    path = os.path.join(dirpath, name)
                    with open(path) as f:
                        for line in f:
                            mv = re.match(r"""\s*__version__\s*=\s*["']([^"']+)["']""",
                                          line)
                            if mv:
                                rel = os.path.relpath(path, root)
                                found[rel] = mv.group(1).lstrip("v")

        self.assertIn("hids/__init__.py", found,
                      "the package no longer declares __version__; this guard "
                      "would then silently cover less than it claims")

        # A banner cannot interpolate __version__, so one that spells a
        # version out is a copy nothing updates: hids/monitor.py's banner
        # still read "(v3.1)" in a tree stamped 3.6, and this guard — which
        # only reads __version__ assignments — could not see it, exactly the
        # hole §F of the changelog says it closed. The version was removed
        # from the banner rather than corrected; this keeps it out.
        banner = os.path.join(root, "hids", "monitor.py")
        with open(banner) as f:
            head = f.read(1200)
        stale = re.findall(r"\(v\d+\.\d+[a-z]?\)", head)
        self.assertEqual(stale, [], "hids/monitor.py's banner spells out a "
                                    "version (%s); use --version, which reads "
                                    "VERSION" % stale)

        # The runbook's step 0 exists to confirm the right build was
        # unpacked, so its expected value has to be this build's. It read
        # "version 3.5d" in a tree stamped 3.6 — a check whose expected value
        # is three releases stale cannot catch the thing it is for.
        rb = os.path.join(root, "docs", "VM_TEST_RUNBOOK.md")
        with open(rb) as f:
            expects = re.findall(r"Expect `version ([^`]+)`", f.read())
        self.assertEqual(expects, [want],
                         "VM_TEST_RUNBOOK expects version %s, VERSION says %s"
                         % (expects or "nothing", want))
        wrong = {k: v for k, v in found.items() if v != want}
        self.assertEqual(wrong, {},
                         "VERSION says %r but these disagree: %s"
                         % (want, ", ".join("%s=%s" % kv for kv in sorted(wrong.items()))))

    def test_every_documented_test_count_matches_the_suite(self):
        """Three documents quote the size of this suite, and nothing checked
        them — so after v3.6 added tests they all said 272 while the suite ran
        298, and the VM runbook told the reader to expect the wrong line.

        A number in a document is a claim like any other. This counts the
        tests by the same discovery the runner uses and requires the
        documents to agree, so adding a test either updates them or fails
        here. The count excludes nothing: a skipped test is still collected.
        """
        root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
        loader = unittest.TestLoader()
        suite = loader.discover(os.path.join(root, "tests"), pattern="test_*.py")
        self.assertEqual(loader.errors, [],
                         "a test module failed to import: %r" % (loader.errors,))

        def count(s):
            n = 0
            for item in s:
                n += count(item) if isinstance(item, unittest.TestSuite) else 1
            return n

        total = count(suite)
        self.assertGreater(total, 100, "discovery collected almost nothing")

        # Each pattern must match the claim about the WHOLE suite and nothing
        # else. A looser `(\d+) tests` also matched "37 tests across a 7-area
        # taxonomy" in the README, which is a true statement about the v3.5d
        # sweep and must not be rewritten to today's total.
        claims = {
            "README.md": r"^tests/\s+(\d+) tests, no root",
            "docs/ARCHITECTURE.md": r"`\./run_tests\.sh`[^\n]*?(\d+) tests;",
            "docs/VM_TEST_RUNBOOK.md": r"Expect `Ran (\d+) tests",
            # The changelog was the one document this guard did not read, and
            # it was the one that was wrong: §G said 271 while the other three
            # said 299. A guard that checks three of four places reports
            # agreement it did not verify — the same failure §F describes for
            # the old version guard.
            "docs/CHANGES_v3.6.md": r"\*\*(\d+) tests\*\*",
        }
        quoted = {}
        for rel, pattern in claims.items():
            with open(os.path.join(root, rel)) as f:
                text = f.read()
            nums = [int(m) for m in re.findall(pattern, text, re.M)]
            self.assertTrue(nums, "%s no longer states the suite size where "
                                  "this guard looks (%s); the guard would then "
                                  "cover less than it claims" % (rel, pattern))
            quoted[rel] = nums

        wrong = {k: v for k, v in quoted.items() if any(n != total for n in v)}
        self.assertEqual(wrong, {},
                         "the suite has %d tests but these disagree: %s"
                         % (total, ", ".join("%s=%s" % kv
                                             for kv in sorted(wrong.items()))))

    def test_the_dd_workload_is_long_enough_to_resolve_the_tax(self):
        """A default that cannot resolve the measurement the tool exists for.

        The dd workload exists to isolate the per-syscall tracepoint tax: it
        calls none of the hooked syscalls, so its slowdown IS the tax. At the
        old default of 300 000 one round took ~0.09 s on the test VM, the
        effect sat far below timing noise, and the 2026-10-18 ladder came out
        non-monotonic (-24, -2, -9, -17, +25, -8, +98 %) — unreadable, and
        correctly refused by the analyzer. The run that did resolve it passed
        P15_DD_COUNT=6000000 by hand.

        So the floor is checked in both places a reader could take a number
        from: the script's default, and the command the runbook tells them to
        type. 2 000 000 is the floor, not the recommendation — it is where a
        round starts taking on the order of a second rather than a tenth.
        """
        root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
        FLOOR = 2_000_000

        with open(os.path.join(root, "tools", "overhead_breakdown.sh")) as f:
            script = f.read()
        m = re.search(r"DD_COUNT=\$\{P15_DD_COUNT:-(\d+)\}", script)
        self.assertIsNotNone(m, "the dd count is no longer a P15_DD_COUNT "
                                "default; this guard would cover nothing")
        self.assertGreaterEqual(
            int(m.group(1)), FLOOR,
            "the default dd count is %s, too short to resolve the per-syscall "
            "tax — that is how the 18 Oct ladder became unreadable" % m.group(1))

        with open(os.path.join(root, "docs", "VM_TEST_RUNBOOK.md")) as f:
            runbook = f.read()
        cmds = re.findall(r"P15_DD_COUNT=(\d+)[\s\S]{0,160}?overhead_breakdown",
                          runbook)
        self.assertTrue(cmds, "the runbook's overhead command no longer sets "
                              "P15_DD_COUNT; it would hand the reader the "
                              "unresolvable run again")
        for got in cmds:
            self.assertGreaterEqual(int(got), FLOOR,
                                    "runbook passes P15_DD_COUNT=%s" % got)

    def test_per_operation_divisors_come_from_the_run_not_a_constant(self):
        """A hardcoded divisor made the headline number 20x too large.

        OPS["sys"] was fixed at 600_000 syscalls (dd count=300_000). The
        16-Oct run used P15_DD_COUNT=6000000, so the real divisor was
        12,000,000 and every "per syscall" figure in overhead.md was twenty
        times the truth: 0.63 µs where the answer is 24 ns. The baseline is
        the check -- the same arithmetic claimed an UNTRACED syscall cost
        2.55 µs, which is absurd for /dev/zero -> /dev/null -- so the
        report now prints the divisor and the bare-syscall cost beside it.
        """
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        with open(os.path.join(d, "timings.csv"), "w") as f:
            for cfg, v in (("base", 1.50), ("count_exec", 1.74), ("base_end", 1.50)):
                for r in (1, 2, 3):
                    f.write("%s,sys,%d,%.3f,%.3f,%.3f\n" % (cfg, r, v, v * 0.4, v * 0.6))
        with open(os.path.join(d, "env.txt"), "w") as f:
            f.write("exec_n=2000\nopen_dir=/usr\ndd_count=6000000\nworkloads=sys\n")
        out = subprocess.check_output([sys.executable, TOOL, d]).decode()
        # 12M syscalls, not 600k, and the label follows the parameter too
        self.assertIn("12,000,000 syscalls", out)
        self.assertIn("count=6,000,000", out)
        self.assertIn("dd 6M 1-byte copies", out)
        # (1.74 - 1.50) s / 12e6 = 20 ns.  With the old constant: 400 ns.
        self.assertIn("| count_exec | - | 20 ns |", out)
        # and the bare syscall cost is printed so a wrong divisor is visible
        self.assertIn("Baseline cost of one bare syscall here: 125 ns", out)

    def test_interleaved_run_reports_its_own_error_and_is_not_gagged_by_drift(self):
        """The real v3.5g VM run (16 Oct), read by the fixed instrument.

        This is the run that settled the per-syscall tax, so its reading is
        pinned here. Two things had to change for it to be readable:

        * whole-run drift was 22 % while the effects were 11-17 %, and the
          old report told the reader to "treat differences under that size
          as noise" -- which would discard every real effect in its own
          table. With baselines measured beside each config, drift does not
          enter the comparison at all;
        * the noise floor is now MEASURED, by reading each baseline against
          its neighbours: truth is 0 % there by construction, so whatever
          comes out is the method's own error (worst 6 %).

        The effects that survive that floor: 0 syscall tracepoints costs
        nothing, the first 2 cost +14 points, and 12 cost no more than 2.
        """
        VM_G = {
            "base": [1.55, 1.55, 1.53, 1.50, 1.54, 1.51, 1.53],
            "bcc_execsnoop": [1.59, 1.59, 1.62, 1.58, 1.56, 1.55, 1.59],
            "base_after_bcc_execsnoop": [1.62, 1.61],
            "bcc_opensnoop": [1.62, 1.67, 1.67, 1.71, 1.80, 1.75, 1.86],
            "base_after_bcc_opensnoop": [1.77, 1.79],
            "count_exec": [1.81, 1.78, 1.91, 2.07, 2.03, 2.02, 1.97],
            "base_after_count_exec": [1.73, 1.81],
            "count_open": [2.01, 1.92, 2.06, 2.09, 2.20, 2.15, 2.08],
            "base_after_count_open": [1.85, 1.86],
            "count_exit": [1.66, 1.63, 1.67, 1.89, 1.81, 1.82, 1.78],
            "base_after_count_exit": [1.75, 1.75],
            "count_net": [2.00, 1.95, 1.92, 2.23, 2.07, 2.11, 2.05],
            "base_after_count_net": [1.78, 1.77],
            "count_all": [1.97, 1.97, 2.04, 2.09, 2.17, 2.15, 2.07],
            "base_after_count_all": [1.75, 1.77],
            "count_all_nofeat": [1.97, 1.95, 1.95, 1.93, 2.03, 2.09, 2.08],
            "base_after_count_all_nofeat": [1.74, 1.83],
            "graph_all": [2.00, 1.96, 2.03, 2.12, 2.07, 2.12, 2.08],
            "base_after_graph_all": [1.73, 2.04],
            "graph_all_batch20": [1.96, 2.01, 1.96, 2.03, 2.00, 2.01, 2.09],
            "base_after_graph_all_batch20": [1.74, 1.78],
            "graph_all_log": [2.01, 1.99, 2.00, 2.03, 2.11, 2.11, 2.07],
            "base_after_graph_all_log": [1.75, 1.78],
            "base_end": [1.82, 1.87, 1.90, 1.83, 1.97, 1.80, 1.87],
        }
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        with open(os.path.join(d, "timings.csv"), "w") as f:
            for cfg, vals in VM_G.items():          # cpu = user + sys
                for r, v in enumerate(vals, 1):
                    f.write("%s,sys,%d,%.3f,%.3f,%.3f\n" % (cfg, r, v, v * 0.3, v * 0.7))
        with open(os.path.join(d, "env.txt"), "w") as f:
            f.write("kernel=5.4.0-216-generic\ncpus=2\nrounds=7\nexec_n=2000\n"
                    "open_dir=/usr\ndd_count=6000000\nworkloads=sys\npinned=1\n"
                    "interleave=1\nbase_rounds=2\n")
        rates = {"count_exec": 23, "count_open": 46, "count_exit": 2, "count_net": 0,
                 "count_all": 69, "count_all_nofeat": 71, "graph_all": 71,
                 "graph_all_batch20": 73, "graph_all_log": 71}
        for cfg, rate in rates.items():
            with open(os.path.join(d, cfg + ".stats.json"), "w") as f:
                json.dump({"records_per_s": rate, "lost": 0, "loss_rate": 0.0,
                           "monitor_cpu_percent_of_one_core": 0.5,
                           "features": [] if "nofeat" in cfg else ["FILE_IDENTITY"],
                           "features_refused": []}, f)
        out = subprocess.check_output([sys.executable, TOOL, d]).decode()

        # the instrument states its own error, from a control whose answer is 0
        self.assertIn("**Instrument check (true answer is 0%):**", out)
        self.assertIn("Worst 6.3%", out)
        # drift is reported, but no longer used to gag the table
        self.assertIn("**Baseline drift:**", out)
        self.assertIn("moved 22%", out)
        self.assertNotIn("treat differences under that size as noise", out)
        # ... so the ladder is readable, and reads as a one-off tax
        self.assertNotIn("INCONCLUSIVE", out)
        self.assertIn("0 tp count_exit -1%", out)
        self.assertIn("2 tp count_exec +11%", out)
        self.assertIn("12 tp count_all +17%", out)
        self.assertIn("step from 0 to 2 tracepoints is +14 points", out)
        self.assertIn("12 would read +82%", out)
        self.assertIn("paid once", out)
        # the cleanest probe: 6 tracepoints attached, none firing, +24 ns
        self.assertIn("Attachment versus events", out)
        self.assertIn("| count_net | - | 24 ns |", out)
        # the kprobe comparison came to 9.9 points against a 10-point
        # threshold. Reported as suggestive, not claimed and not dropped:
        # silence would read as "no effect".
        self.assertIn("suggestive, under the reporting threshold", out)
        self.assertIn("a difference of 9.9 points", out)

    def test_whole_run_drift_cannot_gag_a_ladder_with_paired_baselines(self):
        """Drift is not the noise floor once baselines are interleaved.

        The guard that refuses to read the ladder used to do so whenever
        whole-run drift was as large as the ladder's range. That test is
        right for a run with one distant baseline and wrong for a paired
        one, where absorbing drift is the whole point of the design.

        Worth being exact about what this fixed: on the real 16-Oct run the
        old guard did NOT fire -- range 22.38 points against drift 22.22 --
        so it cleared by 0.16 points, which is luck, not margin. Hence this
        synthetic case, where a machine that gets 50 % slower across the run
        carries a ladder every rung of which is clean against its own
        neighbours. The old guard gags it; the measured floor does not.
        """
        # baselines ramp 1.00 -> 1.50 (50 % drift); each config sits a fixed
        # percentage above the mean of the baselines measured either side.
        bases = [("base", 1.00), ("base_after_count_exit", 1.10),
                 ("base_after_count_exec", 1.20), ("base_after_count_open", 1.30),
                 ("base_after_count_net", 1.40), ("base_after_count_all", 1.45),
                 ("base_after_count_all_nofeat", 1.48), ("base_end", 1.50)]
        effect = {"count_exit": 0.00, "count_exec": 0.10, "count_open": 0.15,
                  "count_net": 0.20, "count_all": 0.25, "count_all_nofeat": 0.25}
        seq = []
        for i, (cfg, _) in enumerate(effect.items()):
            lo, hi = bases[i][1], bases[i + 1][1]
            seq.append((bases[i][0], bases[i][1]))
            seq.append((cfg, (lo + hi) / 2 * (1 + effect[cfg])))
        seq.append(bases[-1])
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        with open(os.path.join(d, "timings.csv"), "w") as f:
            for cfg, v in seq:
                for r in (1, 2):
                    f.write("%s,sys,%d,%.4f,%.4f,%.4f\n" % (cfg, r, v, v * 0.4, v * 0.6))
        for cfg in effect:
            with open(os.path.join(d, cfg + ".stats.json"), "w") as f:
                json.dump({"records_per_s": 0 if cfg == "count_net" else 10,
                           "monitor_cpu_percent_of_one_core": 1.0, "lost": 0,
                           "loss_rate": 0.0, "features": [], "features_refused": []}, f)
        out = subprocess.check_output([sys.executable, TOOL, d]).decode()
        self.assertIn("**Baseline drift:**", out)
        self.assertIn("moved 50%", out)
        self.assertNotIn("INCONCLUSIVE", out)
        self.assertNotIn("which is the size of the effect being measured", out)
        for frag in ("2 tp count_exec +10%", "4 tp count_open +15%",
                     "6 tp count_net +20%", "12 tp count_all +25%"):
            self.assertIn(frag, out)

    def test_a_genuinely_rising_ladder_is_read_as_per_hook(self):
        """The model comparison must be able to reach the other verdict.

        A reading that can only come out one way is not a reading. Same
        analyzer, same shape of data, but a cost that really is proportional
        to the hook count: 2 tp +10 %, 12 tp +60 %. The proportional model
        predicts +60 % and an unchanging cost predicts +10 %, so the verdict
        must flip to per-hook -- and hook count becomes a budget.
        """
        rising = {"base": 1.00, "count_exit": 1.00, "count_exec": 1.10,
                  "count_open": 1.20, "count_net": 1.30, "count_all": 1.60,
                  "count_all_nofeat": 1.60, "base_end": 1.00}
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        with open(os.path.join(d, "timings.csv"), "w") as f:
            for cfg, v in rising.items():
                for r in (1, 2, 3):
                    f.write("%s,sys,%d,%.3f,%.3f,%.3f\n" % (cfg, r, v, v * 0.4, v * 0.6))
                if cfg not in ("base", "base_end"):
                    for r in (1, 2):
                        f.write("base_after_%s,sys,%d,1.000,0.400,0.600\n" % (cfg, r))
        for cfg in rising:
            if cfg.startswith("count"):
                with open(os.path.join(d, cfg + ".stats.json"), "w") as f:
                    json.dump({"records_per_s": 0 if cfg == "count_net" else 10,
                               "monitor_cpu_percent_of_one_core": 1.0,
                               "lost": 0, "loss_rate": 0.0, "features": [],
                               "features_refused": []}, f)
        out = subprocess.check_output([sys.executable, TOOL, d]).decode()
        self.assertNotIn("INCONCLUSIVE", out)
        self.assertIn("12 would read +60%", out)
        self.assertIn("per hook", out)
        self.assertIn("hook count is a budget", out)
        self.assertNotIn("paid once", out)

    def test_drift_flagged_and_no_false_readings(self):
        with open(os.path.join(self.d, "timings.csv"), "w") as f:
            for cfg in ("base", "count_exec", "bcc_execsnoop", "base_end"):
                for w in ("exec", "open", "sys"):
                    f.write("%s,%s,1,%s\n" % (cfg, w, 1.5 if cfg == "base_end" else 1.0))
        out = subprocess.check_output([sys.executable, TOOL, self.d]).decode()
        self.assertIn("**Drift:**", out)
        self.assertNotIn("**Syscall-tracepoint cost:**", out)
