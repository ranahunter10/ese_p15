"""
view.py — the live "top + pstree" screen the advisor asked for, replacing
v2's scrolling per-event output (printing every event is slow and hard to
follow).

render() is a pure function returning a string, so it is unit-tested; draw()
is the only part that touches the terminal. "from fd" counts programs run
from a file descriptor (fexecve / memfd) and is highlighted in red because
that is the classic fileless-execution pattern.
"""

import shutil
import sys

from . import __version__

RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
CYAN, YELLOW, GREEN, RED = "\033[96m", "\033[93m", "\033[92m", "\033[91m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"

# Terminal control, the way top(1) and htop(1) do it. The first version of
# this screen cleared the whole display every frame (`\033[2J\033[H`) and
# rendered a fixed ~60 lines, which on a shorter terminal OVERFLOWS and makes
# the terminal scroll -- so a live dashboard was indistinguishable from the
# scrolling log it was built to replace.
#
#   ALT_ON/ALT_OFF  the alternate screen buffer: the dashboard gets a screen
#                   of its own, the shell's scrollback is left untouched, and
#                   on exit the terminal is restored exactly as it was.
#   HIDE/SHOW       a blinking cursor wandering across a repainting frame
#                   reads as a broken program.
#   HOME + EOL + EOS  overwrite in place instead of blanking first: cursor to
#                   the top, erase each line as it is rewritten, then erase
#                   whatever is left below. Blanking the screen first is what
#                   causes the flicker.
ALT_ON, ALT_OFF = "\033[?1049h", "\033[?1049l"
HIDE_CURSOR, SHOW_CURSOR = "\033[?25l", "\033[?25h"
HOME = "\033[H"
EOL = "\033[K"            # erase from the cursor to end of line
EOS = "\033[J"            # erase from the cursor to end of screen

# Rows the frame spends on things that are neither table rows nor tree lines:
# four counter lines, a blank, the table header, plus one row left spare so
# the bottom line is never pushed off. The tree costs two more (a blank and
# its caption) and is only charged for when it is shown.
_BASE_ROWS = 7
_TREE_ROWS = 2
# Below these the section says nothing useful, so it is dropped rather than
# shrunk further.
_MIN_TABLE = 3
_MIN_TREE = 3


def _trim(s, n):
    return s if len(s) <= n else s[: n - 1] + "…"


def fit(height, top_n=12, tree_lines=40):
    """Split `height` rows between the process table and the tree.

    A frame that does not fit makes the terminal scroll, and a scrolling
    dashboard is indistinguishable from the log this screen replaced -- so
    fitting is the hard requirement, not a nicety.

    The table yields first, because a three-line tree says almost nothing
    while a shorter table still ranks the busiest processes. On a terminal
    too short for both, the tree is dropped entirely (tree_lines == 0) rather
    than allowed to overflow.
    """
    # The floors matter: a table and a tree both clamped to their minimum
    # still need _BASE_ROWS + _TREE_ROWS + 3 + 3 rows. Testing the budget
    # BEFORE applying the floors let heights 13 and 14 through, where
    # max(3, 1) silently spent rows the terminal did not have.
    if height < _BASE_ROWS + _TREE_ROWS + _MIN_TABLE + _MIN_TREE:
        return max(1, height - _BASE_ROWS), 0
    avail = height - _BASE_ROWS - _TREE_ROWS
    t = max(_MIN_TABLE, min(top_n, avail // 3))
    return t, max(_MIN_TREE, avail - t)


def render(graph, stats, now_ns, elapsed_s, top_n=12, tree_lines=40, color=True,
           height=None):
    b, r, y, c, rd = (BOLD, RESET, YELLOW, CYAN, RED) if color else ("",) * 5
    if height:
        top_n, tree_lines = fit(height, top_n, tree_lines)
    g = stats["graph"]
    rec = stats["records"]
    rate = stats["records_received"] / elapsed_s if elapsed_s > 0 else 0.0
    lines = [
        "%sESE-P15 HIDS monitor v%s%s   up %ds   %.0f rec/s   lost %s%d%s (%.2f%%)"
        % (b, __version__, r, elapsed_s, rate, rd if stats["lost"] else "", stats["lost"], r,
           100 * stats["loss_rate"]),
        "processes %d alive / %d exited   files %d   exec %d (+%d failed, %s%d from fd%s)   "
        "open %d (+%d failed)   exit %d   pid reuse %d   errors %d"
        % (g["alive"], g["exited"], g["files"], rec["EXEC"], rec["EXEC_FAILED"],
           rd if rec["EXEC_FROM_FD"] else "", rec["EXEC_FROM_FD"], r,
           rec["OPEN"], rec["OPEN_FAILED"], rec["EXIT"], g["generations"],
           rec["errors"]),
        "endpoints %d   connect %d (+%d pending, %s%d failed%s)   unix sockets %d   "
        "name-resolution probes %d"
        % (g.get("endpoints", 0), rec.get("CONNECT", 0), rec.get("CONNECT_PENDING", 0),
           rd if rec.get("CONNECT_FAILED") else "", rec.get("CONNECT_FAILED", 0), r,
           rec.get("CONNECT_UNIX", 0), rec.get("CONNECT_PROBE", 0)),
        "inbound accept %d (%d unix, %d peer unknown)   hosts seen inbound %d"
        % (rec.get("ACCEPT", 0), rec.get("ACCEPT_UNIX", 0),
           rec.get("ACCEPT_NOPEER", 0), g.get("inbound_hosts", 0)),
        "",
        "%s%7s %5s %6s %8s %6s %5s %5s  %-16s %s%s" % (
            y, "PID", "GEN", "CPU%", "RSS(MB)", "FILES", "OUT", "IN",
            "NAME", "COMMAND", r),
    ]
    for n in graph.top(top_n):
        lines.append("%7d %5d %6.1f %8.1f %6d %5d %5d  %-16s %s" % (
            n.pid, n.key[1], n.cpu_percent, n.rss_kb / 1024.0, n.file_count,
            n.conn_count, n.accept_count, _trim(n.comm, 16),
            _trim(n.cmdline or n.exe, 60)))
    # tree_lines == 0 means the terminal is too short for a table AND a tree;
    # fit() has already decided, and drawing it anyway would scroll.
    if tree_lines:
        lines += ["", "%sprocess tree%s (alive + exited in last 10 s)%s"
                  % (c, DIM if color else "", r)]
        lines.append(graph.render_tree(show_exited=False, recent_ns=10 * 10**9,
                                       now_ns=now_ns, max_lines=tree_lines))
    return "\n".join(lines)


def draw(text, stream=None):
    """Repaint the frame in place.

    Each line is rewritten and erased to end-of-line, then everything below
    the frame is erased. Nothing is blanked before the write, so there is no
    moment where the screen is empty -- which is what flickers.
    """
    stream = stream or sys.stdout
    out = [HOME]
    for line in text.split("\n"):
        out.append(line)
        out.append(EOL)
        out.append("\n")
    out.append(EOS)
    stream.write("".join(out))
    stream.flush()


def screen_rows(default=40):
    """Terminal height, or `default` when it cannot be determined (a pipe,
    a file, a scheduled run with no tty)."""
    try:
        return shutil.get_terminal_size().lines or default
    except Exception:                       # noqa: BLE001 — never fatal
        return default


def enter_fullscreen(stream=None):
    """Take the alternate screen. Must be paired with leave_fullscreen() on
    EVERY exit path, including a crash, or the user is left on a screen they
    cannot scroll with no cursor."""
    stream = stream or sys.stdout
    stream.write(ALT_ON + HIDE_CURSOR + HOME + EOS)
    stream.flush()


def leave_fullscreen(stream=None):
    stream = stream or sys.stdout
    stream.write(SHOW_CURSOR + ALT_OFF)
    stream.flush()


def describe(e):
    """One-line detail for a log entry, by event type."""
    t = e["type"]
    if t == "EXEC":
        detail = " ".join(e.get("argv") or []) or e.get("path", "")
        if e.get("exec_from_fd"):
            detail += "   [EXEC FROM FD]"
        return detail
    if t == "OPEN":
        return "%s %s -> %s" % (e["mode"], e["path"], e["ret"])
    if t == "EXIT":
        return "code=%d signal=%d" % (e["exit_code"], e["signal"])
    if t == "CONNECT":
        # The endpoint id is what a rule table would be programmed with, so
        # show that, then how the attempt ended.
        if e.get("pending"):
            how = "in flight"
        elif e.get("ret") == 0:
            how = "connected"
        else:
            how = "FAILED errno=%d" % -e.get("ret", 0)
        kind = e.get("socket") or ""
        if e.get("probe"):
            kind = (kind + " probe").strip()
        return "%s  %s%s" % (e.get("endpoint") or e.get("family", "?"), how,
                             "  [%s]" % kind if kind else "")
    if t == "ACCEPT":
        # No success/failure to report: only accepted connections exist as
        # records. What matters is who reached in, and on which socket.
        who = e.get("endpoint") or ("peer unknown" if not e.get("peer_known")
                                    else e.get("family", "?"))
        kind = e.get("socket") or ""
        return "%s  inbound from port %s -> fd %s%s" % (
            who, e.get("peer_port", 0), e.get("conn_fd", "?"),
            "  [%s]" % kind if kind else "")
    return e.get("path", "")          # EXEC_FAILED


def make_printer(color=True, stream=None):
    """Per-event printing (v2 style), for small, filtered runs."""
    colors = {"EXEC": GREEN, "EXEC_FAILED": RED, "OPEN": CYAN, "EXIT": YELLOW,
              "CONNECT": BLUE, "ACCEPT": MAGENTA}

    def printer(e):
        out = stream or sys.stdout
        col = colors.get(e["type"], "") if color else ""
        end = RESET if color else ""
        out.write("%s%-11s%s %s %s(%d) %s\n    %s\n" % (
            col, e["type"], end, e["time"], e["name"], e["pid"], describe(e), e["lineage"]))
    return printer
