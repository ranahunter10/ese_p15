"""The live screen must never scroll.

A frame taller than the terminal makes the terminal scroll, and a scrolling
dashboard is indistinguishable from the scrolling log it was built to replace
-- which is exactly what was observed on the VM on 2026-10-19: a fixed
~60-line frame (top_n=12, tree_lines=40) on a shorter terminal.

These tests check the RENDERED line count, not fit()'s arithmetic. fit()
agreeing with itself proves nothing; two heights (13 and 14) overflowed
because the minimum-size floors were applied after the budget was checked,
and only counting real output caught it.
"""

import os
import sys
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)

from hids import view
from hids.graph import ProcessGraph

SEC = 10 ** 9


def _graph(n_procs=40, depth=6):
    """A graph deep and wide enough that the tree would overflow any terminal
    if it were not clamped."""
    g = ProcessGraph()
    g.process(1, 1, 0, 0, "systemd", "", 0, 1)
    pid = 100
    for branch in range(n_procs):
        parent, pstart = 1, 1
        for d in range(depth):
            g.process(pid, pid * SEC, parent, pstart, "p%d" % pid, "x", 1000,
                      pid * SEC)
            parent, pstart = pid, pid * SEC
            pid += 1
    return g


def _stats(g):
    return {
        "graph": g.summary(),
        "records": {"EXEC": 10, "EXEC_FAILED": 0, "EXEC_FROM_FD": 0,
                    "OPEN": 20, "OPEN_FAILED": 0, "EXIT": 0, "errors": 0,
                    "CONNECT": 0, "CONNECT_PENDING": 0, "CONNECT_FAILED": 0,
                    "CONNECT_UNIX": 0, "CONNECT_PROBE": 0, "ACCEPT": 0,
                    "ACCEPT_UNIX": 0, "ACCEPT_NOPEER": 0},
        "records_received": 30, "lost": 0, "loss_rate": 0.0,
    }


class TheFrameNeverScrollsTest(unittest.TestCase):
    def test_no_height_from_8_to_200_overflows(self):
        g = _graph()
        st = _stats(g)
        bad = []
        for h in range(8, 201):
            out = view.render(g, st, 500 * SEC, 60.0, color=False, height=h)
            n = out.count("\n") + 1
            if n > h:
                bad.append((h, n))
        self.assertEqual(bad, [], "frames taller than the terminal: %r" % bad)

    def test_heights_13_and_14_specifically(self):
        # The two that the first version of fit() got wrong, kept as named
        # cases so a future rewrite cannot quietly reintroduce them.
        g = _graph()
        st = _stats(g)
        for h in (13, 14):
            out = view.render(g, st, 500 * SEC, 60.0, color=False, height=h)
            self.assertLessEqual(out.count("\n") + 1, h, "height %d" % h)

    def test_a_short_terminal_drops_the_tree_rather_than_overflowing(self):
        top_n, tree = view.fit(12)
        self.assertEqual(tree, 0)
        self.assertGreaterEqual(top_n, 1)
        g = _graph()
        out = view.render(g, _stats(g), 500 * SEC, 60.0, color=False, height=12)
        self.assertNotIn("process tree", out)

    def test_a_tall_terminal_shows_both(self):
        top_n, tree = view.fit(50)
        self.assertGreaterEqual(top_n, 3)
        self.assertGreaterEqual(tree, 3)
        g = _graph()
        out = view.render(g, _stats(g), 500 * SEC, 60.0, color=False, height=50)
        self.assertIn("process tree", out)

    def test_without_a_height_nothing_is_clamped(self):
        # Piped output, a file, a scheduled run with no tty: there is no
        # terminal to fit, so the caller's defaults stand.
        g = _graph()
        out = view.render(g, _stats(g), 500 * SEC, 60.0, color=False)
        self.assertIn("process tree", out)


class RepaintTest(unittest.TestCase):
    """draw() must overwrite in place. Blanking the screen first is what
    flickers, and the first version of this screen did exactly that."""

    class _Sink(object):
        def __init__(self):
            self.buf = []

        def write(self, s):
            self.buf.append(s)

        def flush(self):
            pass

        def text(self):
            return "".join(self.buf)

    def test_it_does_not_clear_the_whole_screen(self):
        s = self._Sink()
        view.draw("a\nb", stream=s)
        self.assertNotIn("\033[2J", s.text())

    def test_it_homes_the_cursor_and_erases_each_line(self):
        s = self._Sink()
        view.draw("a\nb", stream=s)
        out = s.text()
        self.assertTrue(out.startswith(view.HOME))
        self.assertEqual(out.count(view.EOL), 2)     # one per line

    def test_it_erases_whatever_is_left_below_the_frame(self):
        # Without this, a frame that shrinks leaves the previous frame's tail
        # on screen -- stale processes that look live.
        s = self._Sink()
        view.draw("a\nb", stream=s)
        self.assertTrue(s.text().endswith(view.EOS))


class FullscreenTest(unittest.TestCase):
    class _Sink(RepaintTest._Sink):
        pass

    def test_entering_takes_the_alternate_screen_and_hides_the_cursor(self):
        s = self._Sink()
        view.enter_fullscreen(stream=s)
        out = s.text()
        self.assertIn(view.ALT_ON, out)
        self.assertIn(view.HIDE_CURSOR, out)

    def test_leaving_restores_both(self):
        # Paired on every exit path including a crash: the alternate screen
        # has no scrollback and no cursor, so failing to restore it leaves
        # the user stranded in a dead terminal.
        s = self._Sink()
        view.leave_fullscreen(stream=s)
        out = s.text()
        self.assertIn(view.SHOW_CURSOR, out)
        self.assertIn(view.ALT_OFF, out)

    def test_screen_rows_returns_a_usable_number(self):
        self.assertGreater(view.screen_rows(), 0)
        self.assertEqual(view.screen_rows.__defaults__, (40,))


if __name__ == "__main__":
    unittest.main()
