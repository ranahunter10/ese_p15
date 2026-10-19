# Stage 3 — `hids/events.py` (376 lines)

The contract. Everything upstream is bytes; everything downstream is Python
objects. If this file is wrong by one byte, every number after it is
confidently wrong — which is why a test compiles the real C and compares.
Budget 2 hours.

```bash
grep -n "^class \|^def \|^_COMMON\|^EVENT_\|^NET_FLAG\|^AF_\|^SOCK_\|^O_" hids/events.py
```

---

## 3.1 The mirrors (`RawEvent`, `RawArg`, `RawNet`)

A `ctypes.Structure` describes a C layout to Python: field order, field
widths, and therefore offsets. Our three mirrors must match the three C
structs exactly.

Read `_COMMON_FIELDS` first and compare it, field by field, with
`COMMON_FIELDS` in the C. Same names, same order, same widths. The macro in
C and the list in Python are the *same declaration written twice* — which is
a smell you cannot avoid here (Python cannot read a C macro) and must
therefore defend with a test.

**What the test does**, and why it is the most important test in the repo:

```bash
python3 -m unittest tests.test_layout -v 2>&1 | head -25
```

It writes a small C program that `printf`s `offsetof()` for every field,
compiles it with gcc, runs it, and compares against `ctypes`' view. A
mismatch means decoding would read the wrong bytes — and this test has
already caught a real error (a struct documented as 416 bytes was 392,
`CHANGES_v3.4.md` row 64).

**Why fixed-width types everywhere.** `u32`/`c_uint32`, never `int`/`c_int`.
C's `int` is "at least 16 bits, usually 32" — on the wire between two
languages, "usually" is not a contract.

---

## 3.2 `decode(data, size)` — one record in, one namedtuple out

Read it and notice the order of checks:

1. `size < 4` → `None`. Too small to even hold the type tag.
2. read `type` from the first 4 bytes — *before* knowing which struct this
   is. This is why `type` is the first field of all three records.
3. dispatch on the type, and for each one check `size < _XXX_SIZE` before
   casting.
4. anything unrecognised → `None`, counted as `undecodable` upstream.

Then the part that matters for correctness: **the values are copied out
immediately** into a `namedtuple`. BCC's buffer is only valid during the
callback; keeping the ctypes object would be a pointer into memory that is
about to be reused. `bytes(bytearray(n.daddr))` makes a real copy of the
address bytes rather than a view.

> A `namedtuple` is also immutable, which matters more than it looks: the
> graph keeps references to values derived from records for the lifetime of
> the run, and an accidental mutation would rewrite history.

### The byte-order conversion, in exactly one place

```python
socket.ntohs(n.dport), socket.ntohs(n.sport)
```

The kernel has no `ntohs`, and converting there would cost per record for
no reason, so the record carries network byte order and `decode()` converts
once. 443 is `0x01BB`; stored big-endian and read naively on x86 it is
48129. The project's own wrong-number story is in `CONCEPTS.md` §7d.

---

## 3.3 The identity functions

Three functions, and together they answer "to what?" for every resource
type. Read them as a set, and notice they all return **`None`** when they
cannot answer.

| function | returns | when it returns `None` |
|---|---|---|
| `file_id(path, ino, dev, igen)` | `inode:<dev>:<ino>:<gen>`, else `path:/abs` | relative path with no inode — identity unknown |
| `endpoint_id(family, daddr, dport, path)` | `net:<addr>:<port>`, `net:[<v6>]:<port>`, `unix:<path>` | unnamed socket, or a family we do not model |
| `inbound_endpoint_id(family, daddr, path)` | `host:<addr>`, `host:[<v6>]`, `unix:<path>` | no peer name at all |

**`None` is a design decision, not a shortcut.** The alternative is to
invent an identity — key the file by its relative path, or report
`0.0.0.0` for an unknown peer. v2 did the former and the audit found it
merging unrelated directories named `lib` into one node and inventing
causal edges between them. A node that might be wrong is worse than no
node, because a wrong edge is indistinguishable from a real one downstream.

Read `inbound_endpoint_id`'s docstring in full; it carries the measured
justification for dropping the ephemeral port (stage 2, C.3).

### `unix_path` and abstract sockets

A unix socket whose `sun_path` starts with a NUL byte is in the *abstract*
namespace — not a filesystem path at all. `ss` and `netstat` print those
with a leading `@`, and so do we. An all-zero name is an unnamed socket
(one end of a `socketpair`), which gets no identity.

---

## 3.4 `open_mode(flags)` — one honest over-approximation

```python
acc = flags & O_ACCMODE
if acc == os.O_RDONLY:
    return "W" if flags & (os.O_CREAT | os.O_TRUNC) else "R"
```

Two things to be able to say about this function:

1. **It reports intent, not action.** Opening a file for reading does not
   prove a read happened. The docstring says so, `ARCHITECTURE.md` §11 lists
   it as a known limitation, and a viva question about it should be answered
   with "yes, and here is where we wrote that down" rather than a defence.
2. **`O_RDONLY|O_TRUNC` counts as a write.** POSIX leaves it undefined;
   Linux truncates the file. So the mode bits alone would call a
   file-destroying open a read.

Then `display_path(filename, dfd)`: a relative path opened against a
directory fd is shown as `<dfd>/path` rather than pretending it is absolute.
Honest rendering of an incomplete fact again.

---

## 3.5 `Clock` — two clocks, one offset, measured once

```python
self.offset = time.time() - time.clock_gettime(time.CLOCK_MONOTONIC)
```

Every record's `ts_ns` is monotonic (stage 1). Humans need wall-clock. The
offset between the two is measured **directly, once per run**, rather than
derived from `/proc/stat`'s `btime`, which is a whole-second value and would
quantise every timestamp to the nearest second.

Where this shows up for you: `query_graph.py --at` takes *monotonic*
seconds, because the graph stores monotonic time; the JSONL log carries both
`ts_ns` and a formatted `time`, so a log line is the Rosetta stone between
the two clocks.

---

## 3.6 `encode_event` / `encode_arg` / `encode_net`

The inverse direction: build the exact bytes the kernel *would* have sent.
These exist only for tests, and they are what make the whole pipeline
testable without a kernel:

```bash
grep -n "encode_net" tests/*.py | head
```

A test can hand `decode()` the precise byte sequence of a non-blocking
IPv6 connect and assert what comes out. That is also why `tests/helpers.py`
can replay all 120 arrival orders of one exec's five records (stage 4)
without root, BCC, or a VM.

Note `encode_net` takes ports in *host* order and converts, so tests read
the way a person thinks ("port 443") rather than the way the wire carries
it.

---

## Experiments

`[laptop]` Prove the mirror matches the C, then break it on purpose:

```bash
python3 -m unittest tests.test_layout 2>&1 | tail -3
# now edit hids/events.py: swap two fields in _COMMON_FIELDS, re-run
# the test tells you which offset diverged, not just "it failed"
```

`[laptop]` Watch byte order bite:

```bash
python3 -c "
import socket
raw = socket.htons(443)
print('on the wire:', hex(raw), '| read naively:', raw, '| ntohs:', socket.ntohs(raw))"
```

`[laptop]` See `None` happen:

```bash
python3 -c "
from hids.events import file_id, endpoint_id, inbound_endpoint_id, AF_INET, AF_UNIX
print(file_id('rel.txt'))                 # relative, no inode -> None
print(file_id('rel.txt', ino=77, dev=8, igen=1))
print(endpoint_id(AF_UNIX, b'', 0, b''))  # unnamed socket -> None
print(inbound_endpoint_id(AF_INET, b'\x0a\x00\x00\x09'+b'\x00'*12, b''))"
```

---

## Self-check

1. Why is `type` the first field of every record, and what breaks if it
   moves?
2. Why are values copied out of the ctypes object immediately?
3. Where is network byte order converted, and why not in the kernel?
4. `file_id` returns `None` for a relative path with no inode. Why is that
   better than keying on the path?
5. What does `open_mode` actually measure, and what does it *not* prove?
6. Why does `O_RDONLY|O_TRUNC` return `"W"`?
7. Why is the wall-clock offset measured directly instead of read from
   `/proc/stat`?
8. What are the `encode_*` functions for, and what capability do they give
   the test suite?

<details>
<summary>Answers</summary>

1. `decode()` must read the type before it knows which struct — and
   therefore which size — the record is. If `type` moved, the dispatch
   would read whatever field now sits at offset 0 and mis-route every
   record.
2. BCC's perf buffer is only valid during the callback; the memory is
   reused afterwards. A retained ctypes object would be a pointer into
   recycled memory — the classic use-after-free, in Python.
3. In `decode()`, once, with `socket.ntohs`. The kernel has no `ntohs`
   helper and converting per record there would cost CPU inside the probe
   for no benefit.
4. Because a relative path does not identify a file: two processes with
   different working directories can open "lib" and mean different
   directories. v2 keyed on the path and the audit found it merging
   unrelated directories into one node and inventing causal edges. No node
   is better than a node that might be wrong.
5. It reports what the process *asked for* in the open flags. It does not
   prove any byte was read or written — a known, documented
   over-approximation.
6. POSIX leaves `O_RDONLY|O_TRUNC` undefined, but Linux truncates the file,
   so treating it as a read would classify a file-destroying open as
   harmless.
7. `btime` has one-second resolution, which would quantise every converted
   timestamp. Measuring `time.time() - clock_gettime(MONOTONIC)` once gives
   nanosecond-consistent conversion for the whole run.
8. They build the exact bytes the kernel would send, which lets tests drive
   `decode()` and the whole pipeline — including every arrival order of a
   split exec — with no kernel, no BCC and no root.

</details>

Next: `04_PROCESSOR.md` — the state machine that reassembles an exec from
records that may arrive in any order.
