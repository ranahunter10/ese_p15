"""
The C structs in bpf/monitor.bpf.c and the ctypes structs in events.py must
agree byte-for-byte. This test compiles the REAL struct text with gcc and
compares sizes and every field offset. It also type-checks the whole BPF
program against a small stub of the BCC/kernel API, which catches typos and
type errors before the program ever reaches a VM (it does NOT replace the
in-kernel verifier — tools/vm_validation.sh covers that).
"""

import ctypes
import os
import random
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import unittest

import helpers  # sets sys.path
assert helpers
from hids import events
from hids import events as E
from hids.monitor import BPF_SOURCE

SRC = open(BPF_SOURCE).read()
HAVE_GCC = shutil.which("gcc") is not None


def struct_text(name):
    m = re.search(r"struct %s \{.*?\n\};" % name, SRC, re.S)
    assert m, name
    return macro_text("COMMON_FIELDS") + "\n" + m.group(0)


def macro_text(name):
    """The multi-line #define, continuation backslashes and all."""
    m = re.search(r"#define %s(?:[^\n]*\\\n)*[^\n]*\n" % name, SRC)
    assert m, name
    return m.group(0)


def c_define(name):
    return int(re.search(r"#define %s\s+(-?\d+)" % name, SRC).group(1))


PRELUDE = """
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef int32_t s32; typedef uint64_t u64; typedef int64_t s64;
#define TASK_COMM_LEN 16
#define MAX_FILENAME %d
#define ARG_LEN %d
#define UNIX_PATH_LEN %d
""" % (events.MAX_FILENAME, events.ARG_LEN, events.UNIX_PATH_LEN)


def compile_and_run(code):
    d = tempfile.mkdtemp()
    try:
        c, exe = os.path.join(d, "t.c"), os.path.join(d, "t")
        with open(c, "w") as f:
            f.write(code)
        subprocess.check_call(["gcc", "-Wall", "-Werror", "-o", exe, c])
        return subprocess.check_output([exe]).decode()
    finally:
        shutil.rmtree(d)


@unittest.skipUnless(HAVE_GCC, "gcc not installed")
class LayoutTest(unittest.TestCase):
    def check(self, cname, pytype):
        lines = ['printf("size %%zu\\n", sizeof(struct %s));' % cname]
        for fname, _ in pytype._fields_:
            lines.append('printf("%s %%zu\\n", offsetof(struct %s, %s));'
                         % (fname, cname, fname))
        code = PRELUDE + struct_text(cname) + "\nint main(void){" + "".join(lines) + "return 0;}\n"
        got = dict(l.split() for l in compile_and_run(code).splitlines())
        self.assertEqual(int(got["size"]), ctypes.sizeof(pytype), "sizeof " + cname)
        for fname, _ in pytype._fields_:
            self.assertEqual(int(got[fname]), getattr(pytype, fname).offset,
                             "%s.%s offset" % (cname, fname))

    def test_event_layout(self):
        self.check("event_t", events.RawEvent)

    def test_arg_layout(self):
        self.check("arg_t", events.RawArg)

    def test_net_layout(self):
        self.check("net_t", events.RawNet)

    def test_sockaddr_copies_match_the_real_abi(self):
        """monitor.bpf.c parses connect()'s address with its own small
        structs. They are only correct if they match the kernel ABI, so
        compile them next to the system headers and compare every offset."""
        pairs = [("sa_in_t", "sockaddr_in", [("family", "sin_family"),
                                             ("port", "sin_port"),
                                             ("addr", "sin_addr")]),
                 ("sa_in6_t", "sockaddr_in6", [("family", "sin6_family"),
                                               ("port", "sin6_port"),
                                               ("addr", "sin6_addr")]),
                 ("sa_un_t", "sockaddr_un", [("family", "sun_family"),
                                             ("path", "sun_path")])]
        code = ["#include <stdio.h>\n#include <stddef.h>\n#include <stdint.h>",
                "#include <netinet/in.h>\n#include <sys/un.h>",
                "typedef uint8_t u8; typedef uint16_t u16;",
                "typedef uint32_t u32; typedef uint64_t u64;",
                "#define UNIX_PATH_LEN %d" % events.UNIX_PATH_LEN]
        for ours, _, _ in pairs:
            code.append(re.search(r"struct %s\s*\{.*?\};" % ours, SRC, re.S).group(0))
        body = []
        for ours, theirs, fields in pairs:
            body.append('printf("%s_size %%zu %%zu\\n", sizeof(struct %s), sizeof(struct %s));'
                        % (ours, ours, theirs))   # ours must not be LARGER
            for mine, real in fields:
                body.append('printf("%s_%s %%zu %%zu\\n", offsetof(struct %s, %s),'
                            ' offsetof(struct %s, %s));' % (ours, mine, ours, mine, theirs, real))
        body.append('printf("af %d %d %d\\n", AF_UNIX, AF_INET, AF_INET6);')
        code.append("#include <sys/socket.h>")
        out = compile_and_run("\n".join(code) + "\nint main(void){" + "".join(body) + "return 0;}\n")
        for line in out.splitlines():
            parts = line.split()
            if parts[0] == "af":
                self.assertEqual([int(x) for x in parts[1:]],
                                 [events.AF_UNIX, events.AF_INET, events.AF_INET6])
            elif parts[0].endswith("_size"):
                # Our copy may be SHORTER — sockaddr_in carries 8 bytes of
                # trailing padding we have no reason to read — but never
                # longer, or the hook would read past the real structure.
                self.assertLessEqual(int(parts[1]), int(parts[2]),
                                     "%s is larger than the real struct" % parts[0])
            else:
                self.assertEqual(parts[1], parts[2],
                                 "%s is at a different offset than the system header"
                                 % parts[0])

    def test_common_layout(self):
        self.check("common_t", events.RawCommon)

    def test_every_record_starts_with_the_same_common_prefix(self):
        """fill_common() writes through a cast to struct common_t *.

        That is only safe if every record type really does begin with the
        same fields at the same offsets, so this proves it in the compiled
        C rather than assuming it from the source reading the same way.
        """
        names = [f for f, _ in events.RawCommon._fields_]
        code = [PRELUDE, macro_text("COMMON_FIELDS")]
        for cname in ("common_t", "event_t", "net_t"):
            code.append(re.search(r"struct %s \{.*?\n\};" % cname, SRC, re.S).group(0))
        body = []
        for cname in ("common_t", "event_t", "net_t"):
            for f in names:
                body.append('printf("%s.%s %%zu\\n", offsetof(struct %s, %s));'
                            % (cname, f, cname, f))
        out = dict(l.split() for l in
                   compile_and_run("\n".join(code) + "\nint main(void){"
                                   + "".join(body) + "return 0;}\n").splitlines())
        for f in names:
            for cname, pytype in (("event_t", events.RawEvent), ("net_t", events.RawNet)):
                self.assertEqual(out["common_t." + f], out["%s.%s" % (cname, f)],
                                 "common field %r is at a different offset in %s"
                                 % (f, cname))
                self.assertEqual(int(out["common_t." + f]), getattr(pytype, f).offset,
                                 "Python copy of %r in %s disagrees" % (f, cname))

    def test_sizes_quoted_in_docs(self):
        # monitor.bpf.c and docs/ARCHITECTURE.md quote these numbers. The
        # doc copy used to be named here and not read, so only the C source
        # was guarded; an audit found that. Both are checked now, and the
        # doc is searched for each size rather than just one.
        sizes = {"RawEvent": (events.RawEvent, 392),
                 "RawArg": (events.RawArg, 152),
                 "RawNet": (events.RawNet, 256)}
        for name, (cls, want) in sizes.items():
            self.assertEqual(ctypes.sizeof(cls), want, name)
        self.assertIn("event_t is 392", SRC)

        root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
        with open(os.path.join(root, "docs", "ARCHITECTURE.md")) as f:
            doc = f.read()
        for name, (_cls, want) in sizes.items():
            self.assertIn(str(want), doc,
                          "ARCHITECTURE.md no longer quotes %s's size (%d); "
                          "this guard would then cover less than it claims"
                          % (name, want))

    def test_no_hidden_padding(self):
        # Explicit layout: the sum of field sizes equals the struct size.
        for t in (events.RawCommon, events.RawEvent, events.RawArg, events.RawNet):
            total = sum(ctypes.sizeof(ft) for _, ft in t._fields_)
            self.assertEqual(total, ctypes.sizeof(t), t.__name__)


class ConstantsTest(unittest.TestCase):
    def test_at_fdcwd_matches(self):
        self.assertEqual(c_define("AT_FDCWD_VAL"), events.AT_FDCWD)

    def test_constants_match(self):
        for name in ("EVENT_EXEC_ENTER", "EVENT_OPEN", "EVENT_EXEC_OK",
                     "EVENT_EXIT", "EVENT_ARG", "EVENT_NET",
                     "MAX_FILENAME", "ARG_LEN", "MAXARG", "UNIX_PATH_LEN",
                     "ARG_FLAG_END", "ARG_FLAG_TRUNCATED", "NET_FLAG_INPROGRESS",
                     "NET_FLAG_INBOUND", "NET_FLAG_NOPEER"):
            self.assertEqual(c_define(name), getattr(events, name), name)

    def test_address_families_match(self):
        # The kernel side spells them AF_*_V to avoid clashing with headers.
        for name in ("UNIX", "INET", "INET6"):
            self.assertEqual(c_define("AF_%s_V" % name), getattr(events, "AF_" + name), name)

    def test_net_flags_are_distinct_bits(self):
        # They are OR-ed together in one u16 field (an inbound record with no
        # peer name carries both), so overlapping values would silently
        # make "inbound" and "no peer" indistinguishable.
        bits = [events.NET_FLAG_INPROGRESS, events.NET_FLAG_INBOUND,
                events.NET_FLAG_NOPEER]
        for b in bits:
            self.assertEqual(b & (b - 1), 0, "%d is not a single bit" % b)
        self.assertEqual(len(set(bits)), len(bits))

    def test_both_accept_syscalls_are_hooked(self):
        # glibc's accept() issues __NR_accept and Python's socket.accept()
        # issues __NR_accept4 (verified under strace, Journal row 86), so
        # hooking one of the two leaves half the servers on a box invisible.
        for tp in ("sys_enter_accept", "sys_exit_accept",
                   "sys_enter_accept4", "sys_exit_accept4"):
            self.assertIn("TRACEPOINT_PROBE(syscalls, %s)" % tp, SRC, tp)

    def test_accept_reads_the_kernels_length_before_trusting_the_buffer(self):
        """The VM bug of 2026-10-18, pinned at the only level reachable here.

        `accept()`'s sockaddr is an OUTPUT buffer: the kernel writes only
        `*upeer_addrlen` bytes and leaves the rest as the caller had it. The
        probe used to read the fixed 110-byte struct and test `path[0]` to
        decide whether a peer name existed, so an unnamed unix peer was
        reported using the traced process's leftover stack — demonstrated on
        5.4.0-216-generic with `tools/p15_accept_probe.py`, where a planted
        marker came back out of the monitor as the peer identity.

        The gcc stub above declares `int *upeer_addrlen`, so the compile
        check type-checks the field — but it would pass just as happily if
        someone went back to ignoring it. This asserts the mechanism: both
        entry probes must forward the length pointer, and the exit path must
        read it and gate the copy on it. A grep over source is a weak form
        of test; it is the strongest one available for code only a kernel
        can run, and it is better than the alternative of nothing.
        """
        for tp in ("sys_enter_accept", "sys_enter_accept4"):
            body = SRC.split("TRACEPOINT_PROBE(syscalls, %s)" % tp, 1)[1][:260]
            self.assertIn("upeer_addrlen", body,
                          "%s does not forward upeer_addrlen, so the exit "
                          "path cannot know how much the kernel wrote" % tp)

        self.assertIn("u64  ulen;", SRC,
                      "accept_args_t no longer carries the length pointer")
        exit_body = SRC.split("int accept_exit(", 1)[1].split("\nTRACEPOINT_PROBE", 1)[0]
        self.assertIn("aa->ulen", exit_body, "the length pointer is never read")
        self.assertIn("klen <= SA_UN_HDR", exit_body,
                      "nothing rejects a length that stops at the family")
        self.assertIn("n->addrlen = (u16)klen", exit_body,
                      "the kernel's length is not carried in the record, so "
                      "userspace cannot trim the name to it")
        self.assertNotIn("if (n->path[0] == 0)", exit_body,
                         "the peer-name test is back to reading the first "
                         "leftover byte, which an abstract name also makes 0")
        # The truncation itself lives in userspace, where it can be tested
        # properly: the first attempt did it here with a byte-by-byte loop
        # over the BPF stack and the 5.4 verifier refused the program
        # ("invalid read from stack off -34+0 size 1").
        self.assertNotIn("for (int i = 0; i < UNIX_PATH_LEN", exit_body,
                         "a stack-walking loop is back in accept_exit; the "
                         "5.4 verifier rejects it")
        import inspect
        self.assertIn("addrlen", inspect.signature(events.unix_path).parameters,
                      "unix_path no longer takes the length, so nothing trims")

    def test_einprogress_value_is_the_one_the_kernel_hook_tests(self):
        # The hook compares against the literal -115; if that ever stops
        # being EINPROGRESS on Linux the pending/failed split breaks silently.
        import errno
        self.assertEqual(events.EINPROGRESS, errno.EINPROGRESS)
        self.assertIn("-115", SRC)


STUB = r"""
#include <stdint.h>
#include <stddef.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef int32_t s32; typedef uint64_t u64; typedef int64_t s64;
#define TASK_COMM_LEN 16
struct super_block { u32 s_dev; };
struct inode { unsigned long i_ino; u32 i_generation; struct super_block *i_sb; };
struct file { struct inode *f_inode; void *private_data; };
struct fdtable { unsigned int max_fds; struct file **fd; };
struct files_struct { struct fdtable *fdt; };
struct mm_struct { struct file *exe_file; };
struct socket { short type; };
struct task_struct { struct task_struct *group_leader, *real_parent;
                     u64 start_time; char comm[16]; int tgid; int exit_code;
                     struct files_struct *files; struct mm_struct *mm; };
static u64 bpf_get_current_pid_tgid(void) { return 0; }
static u64 bpf_get_current_uid_gid(void) { return 0; }
static u64 bpf_ktime_get_ns(void) { return 0; }
static u64 bpf_get_current_task(void) { return 0; }
static int bpf_get_current_comm(void *d, u32 n) { (void)d; (void)n; return 0; }
static int bpf_probe_read(void *d, u32 n, const void *s) { (void)d; (void)n; (void)s; return 0; }
static int bpf_probe_read_str(void *d, u32 n, const void *s) { (void)d; (void)n; (void)s; return 0; }
#define BPF_PERF_OUTPUT(n) struct { int (*perf_submit)(void *, void *, u64); } n
#define BPF_PERCPU_ARRAY(n, V, sz) struct { V *(*lookup)(u32 *); } n
#define BPF_TABLE(kind, K, V, n, sz) struct { V *(*lookup)(K *); \
    int (*update)(K *, V *); int (*delete)(K *); } n
/* field names/types as in /sys/kernel/debug/tracing/events/.../format on 5.4,
   with __data_loc turned into "int data_loc_<name>" exactly as BCC 0.12 does */
struct tp_sys_enter_execve { const char *filename; const char *const *argv; };
struct tp_sys_enter_execveat { int fd; const char *filename; const char *const *argv;
                               const char *const *envp; int flags; };
struct tp_sched_process_exec { int data_loc_filename; int pid; int old_pid; };
struct tp_sys_enter_openat { int dfd; const char *filename; int flags; };
struct tp_sys_exit_openat { long ret; };
struct tp_sys_enter_open { const char *filename; int flags; };
struct tp_sys_exit_open { long ret; };
struct tp_sched_process_exit { int pid; };
struct sockaddr;
struct tp_sys_enter_connect { int fd; struct sockaddr *uservaddr; int addrlen; };
struct tp_sys_exit_connect { long ret; };
/* accept/accept4 field names verified against v5.4 net/socket.c:
   SYSCALL_DEFINE3(accept, int fd, struct sockaddr __user *upeer_sockaddr,
                   int __user *upeer_addrlen) and SYSCALL_DEFINE4(accept4, ...)
   which adds int flags. */
struct tp_sys_enter_accept { int fd; struct sockaddr *upeer_sockaddr; int *upeer_addrlen; };
struct tp_sys_exit_accept { long ret; };
struct tp_sys_enter_accept4 { int fd; struct sockaddr *upeer_sockaddr;
                              int *upeer_addrlen; int flags; };
struct tp_sys_exit_accept4 { long ret; };
#define TRACEPOINT_PROBE(cat, ev) int tp_##cat##_##ev(struct tp_##ev *args)
"""

COMBOS = [
    (("exec", "open", "exit", "net"), ("KERNEL_EXEC_PATH", "FILE_IDENTITY", "SOCKET_TYPE")),
    (("exec", "open", "exit", "net"), ("KERNEL_EXEC_PATH", "FILE_IDENTITY")),
    (("exec", "open", "exit", "net"), ()),
    (("exec",), ("KERNEL_EXEC_PATH",)),
    (("open",), ("FILE_IDENTITY",)),
    (("exit",), ()),
    (("net",), ()),
    (("net",), ("SOCKET_TYPE",)),
]


@unittest.skipUnless(HAVE_GCC, "gcc not installed")
class BpfSyntaxTest(unittest.TestCase):
    def compile(self, hooks, feats):
        from hids.monitor import bpf_text
        text = bpf_text(1234, hooks, feats)
        body = re.sub(r"#include <[^>]+>\n", "", text)
        d = tempfile.mkdtemp()
        try:
            c = os.path.join(d, "bpf.c")
            with open(c, "w") as f:
                f.write(STUB + body)
            r = subprocess.run(["gcc", "-fsyntax-only", "-Wall", "-Werror",
                                "-Wno-unused-function", "-Wno-unused-variable", c],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            return r.returncode, r.stdout.decode()
        finally:
            shutil.rmtree(d)

    def test_every_hook_and_feature_combination_typechecks(self):
        for hooks, feats in COMBOS:
            rc, out = self.compile(hooks, feats)
            self.assertEqual(rc, 0, "%s %s\n%s" % (hooks, feats, out))

    def test_the_documented_combination_count_is_the_one_compiled(self):
        """Two documents quote this number and both said 6 while COMBOS held
        8 — found by an audit, not by the suite. A count in a document is a
        claim; adding a combination now either updates them or fails here."""
        root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
        for rel, pattern in (("README.md", r"gcc type-check in all (\d+) hook"),
                             ("docs/ARCHITECTURE.md",
                              r"type-checks for (\d+) hook/feature")):
            with open(os.path.join(root, rel)) as f:
                found = re.findall(pattern, f.read())
            self.assertEqual(found, [str(len(COMBOS))],
                             "%s says %s hook/feature combinations, COMBOS has "
                             "%d" % (rel, found or "nothing", len(COMBOS)))

    def test_hooks_really_compiled_in(self):
        # Guard against the vacuous pass: a probe name that doesn't exist in
        # the stub must fail once HOOK_OPEN is on.
        from hids.monitor import bpf_text
        text = bpf_text(1, ("open",), ())
        self.assertIn("#define HOOK_OPEN 1", text)
        self.assertNotIn("#define HOOK_EXEC", text)
        broken = STUB.replace("struct tp_sys_exit_openat { long ret; };", "")
        d = tempfile.mkdtemp()
        try:
            c = os.path.join(d, "bpf.c")
            with open(c, "w") as f:
                f.write(broken + re.sub(r"#include <[^>]+>\n", "", text))
            r = subprocess.run(["gcc", "-fsyntax-only", c],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.assertNotEqual(r.returncode, 0)
        finally:
            shutil.rmtree(d)


def _string_fields(etype):
    """(offset, width) of every fixed-width C string in that record's layout.

    Derived from ctypes so a field that moves cannot silently take the
    fixture's string cases with it.
    """
    cls = {E.EVENT_ARG: E.RawArg, E.EVENT_NET: E.RawNet}.get(etype, E.RawEvent)
    return [(getattr(cls, name).offset, ftype._length_)
            for name, ftype in cls._fields_
            if issubclass(ftype, ctypes.Array)]


class StringFixtureHitsTheStringsTest(unittest.TestCase):
    """The fixture above claims to exercise string handling. This checks the
    offsets it uses are string fields, which is what the literals it replaced
    were not."""

    def test_every_derived_offset_lands_on_a_string_field(self):
        for etype, cls in ((E.EVENT_ARG, E.RawArg), (E.EVENT_NET, E.RawNet),
                           (E.EVENT_OPEN, E.RawEvent)):
            want = [(getattr(cls, n).offset, t._length_)
                    for n, t in cls._fields_ if issubclass(t, ctypes.Array)]
            got = _string_fields(etype)
            self.assertEqual(got, want)
            self.assertTrue(got, "%s has no string fields" % cls.__name__)
            # The real check, and the one the stale literals failed: no
            # scalar field overlaps any range the fixture writes to. Comparing
            # the derived list against the same derivation would be
            # tautological, and a bare lower bound is wrong — RawArg's `arg`
            # starts at 24 because its prefix is shorter.
            scalars = [(getattr(cls, n).offset, ctypes.sizeof(t))
                       for n, t in cls._fields_
                       if not issubclass(t, ctypes.Array)]
            for off, width in got:
                self.assertLessEqual(off + width, ctypes.sizeof(cls))
                for soff, swidth in scalars:
                    self.assertFalse(off < soff + swidth and soff < off + width,
                                     "%s: fixture range %d..%d overlaps a "
                                     "scalar field at %d..%d"
                                     % (cls.__name__, off, off + width,
                                        soff, soff + swidth))

    def test_the_offsets_it_replaced_were_not_string_fields(self):
        """Keeps the reason on the record: (28, 44, 60) are integers."""
        strings = _string_fields(E.EVENT_OPEN)
        starts = {off for off, _w in strings}
        for stale in (28, 44, 60):
            self.assertNotIn(stale, starts)


class DecoderEquivalenceTest(unittest.TestCase):
    """The v3.6 struct decoder against the v3.5 ctypes one, byte for byte.

    `events.decode` stopped using `ctypes.cast` in v3.6. The honest figure is
    1.85x on decode and 1.34x on the ingest path, measured per pair by
    `tools/bench_ingest.py`. This docstring used to claim "3.42 µs became
    0.199 µs" — the 17x that §E of the changelog retracts, because it
    compared a nine-scalar microbenchmark against a FULL old decode. The
    retraction said the comment had been corrected; it had been corrected in
    `hids/events.py` and not here, and an audit of this tree found the
    discarded number still sitting in a test. Hence this paragraph.

    The risk in that change was never speed, it is that a re-derivation of
    the binary layout can be subtly wrong and then every field is quietly
    off. So the OLD implementation is kept here as the reference and the two
    are compared over randomised bytes: two independent descriptions of one
    layout, checked against each other, which is the same method test_layout
    uses against gcc.
    """

    @staticmethod
    def _old_decode(data, size):
        """v3.5i's decode(), verbatim apart from the names it reaches for."""
        if size < 4:
            return None
        etype = ctypes.cast(data, E._U32P).contents.value
        if etype == E.EVENT_ARG:
            if size < E._ARG_SIZE:
                return None
            a = ctypes.cast(data, E._ARGP).contents
            return E.Arg(a.pid, a.idx, a.enter_ts, E._s(a.arg), a.flags)
        if etype == E.EVENT_NET:
            if size < E._NET_SIZE:
                return None
            n = ctypes.cast(data, E._NETP).contents
            return E.Net(
                n.type, n.pid, n.tid, n.ppid, n.uid, n.gid,
                n.ts_ns, n.start_ns, n.pstart_ns,
                E._s(n.comm), E._s(n.tcomm), E._s(n.pcomm),
                n.ret, n.fd, n.family,
                socket.ntohs(n.dport), socket.ntohs(n.sport), n.nflags,
                bytes(bytearray(n.daddr)), bytes(bytearray(n.saddr)),
                bytes(bytearray(n.path)), n.sock_type,
                # `addrlen` replaced the trailing `pad` in v3.6's accept fix.
                # The reference decoder is v3.5i's logic, not v3.5i's ABI: its
                # job is to prove the two decoders extract the same fields
                # from the same layout, so it has to read whatever fields the
                # layout now has.
                n.addrlen,
            )
        if etype not in E.EVENT_NAMES or size < E._EVENT_SIZE:
            return None
        e = ctypes.cast(data, E._EVP).contents
        return E.Event(
            e.type, e.pid, e.tid, e.ppid, e.uid, e.gid, e.ret, e.flags,
            e.ts_ns, e.start_ns, e.pstart_ns, e.aux_ns,
            e.ino, e.dev, e.igen, e.dfd,
            E._s(e.comm), E._s(e.tcomm), E._s(e.pcomm), E._s(e.filename),
        )

    def test_random_records_decode_identically_to_the_ctypes_decoder(self):
        rnd = random.Random(20261018)
        sizes = {E.EVENT_ARG: E._ARG_SIZE, E.EVENT_NET: E._NET_SIZE}
        types = [E.EVENT_ARG, E.EVENT_NET] + sorted(E.EVENT_NAMES)
        checked = 0
        for _ in range(3000):
            etype = rnd.choice(types)
            size = sizes.get(etype, E._EVENT_SIZE)
            raw = bytearray(rnd.getrandbits(8) for _ in range(size))
            raw[0:4] = struct.pack("<I", etype)
            # Make the string fields look like real ones about a third of the
            # time, so NUL handling is exercised deliberately and not just by
            # luck of the random bytes: a NUL-terminated value, a full-width
            # value with no NUL at all, and invalid UTF-8.
            #
            # The offsets are DERIVED from ctypes, not written out. They used
            # to be the literals (28, 44, 60), which for every record type
            # here are `ts_ns`, `pstart_ns` and the middle of `comm` — the
            # string fields start at 48. So two of three writes landed on
            # integer fields and the third straddled two strings, and the
            # three conditions this comment claims arose only incidentally.
            # An audit of the tree found that; deriving the offsets means a
            # field moving cannot quietly empty the case again.
            if rnd.random() < 0.34:
                fills = (b"name\x00", b"X" * 1, b"\xff\xfe bad\x00")
                for i, (off, width) in enumerate(_string_fields(etype)):
                    fill = fills[i % len(fills)]
                    if i % 3 == 1:          # full width, no terminator
                        raw[off:off + width] = (fill * width)[:width]
                    else:
                        raw[off:off + width] = (fill + bytes(width))[:width]
            owner = (ctypes.c_char * size).from_buffer(raw)
            want = self._old_decode(owner, size)
            got = E.decode(owner, size)
            self.assertEqual(want, got, "type=%d raw=%s" % (etype, bytes(raw[:64]).hex()))
            # and through the integer-address path BCC actually uses
            self.assertEqual(want, E.decode(ctypes.addressof(owner), size))
            checked += 1
        self.assertEqual(checked, 3000)

    def test_derived_formats_match_the_ctypes_layout_field_by_field(self):
        """The format is generated, so this checks the generator, not a
        transcription: every field's struct offset against ctypes'."""
        for cls, fmt, names in ((E.RawEvent, E._EV_FMT, E._EV_NAMES),
                                (E.RawNet, E._NET_FMT, E._NET_NAMES),
                                (E.RawArg, E._ARG_FMT, E._ARG_NAMES)):
            self.assertEqual(struct.calcsize(fmt), ctypes.sizeof(cls), cls.__name__)
            self.assertEqual(names, tuple(n for n, _ in cls._fields_), cls.__name__)
            # Walk the format and check each value lands at the ctypes offset.
            off, idx = 0, 0
            for tok in re.findall(r"\d*[a-zA-Z]", fmt.lstrip("<")):
                n = int(tok[:-1]) if tok[:-1] else 1
                code = tok[-1]
                if code == "x":
                    off += n
                    continue
                want = getattr(cls, names[idx]).offset
                self.assertEqual(off, want,
                                 "%s.%s at %d, ctypes says %d"
                                 % (cls.__name__, names[idx], off, want))
                off += struct.calcsize("<" + tok)
                idx += 1
            self.assertEqual(idx, len(names), cls.__name__)

    def test_a_short_buffer_is_refused_instead_of_read_past(self):
        """W2-B6: the ctypes path performed a SUCCESSFUL out-of-bounds read."""
        self.assertIsNotNone(self._old_decode(b"\x04\x00\x00\x00", 10 ** 6))
        self.assertIsNone(E.decode(b"\x04\x00\x00\x00", 10 ** 6))
        self.assertIsNone(E.decode(bytearray(8), E._EVENT_SIZE))
        self.assertIsNone(E.decode(memoryview(bytes(8)), E._NET_SIZE))


if __name__ == "__main__":
    unittest.main()
