#!/usr/bin/env python3
"""Prove what accept() actually writes into the peer-address buffer.

Run it twice: once with a marker pre-loaded into the buffer, once with the
buffer zeroed. The KERNEL's answer is identical both times. If the monitor's
output differs between the two runs, the monitor is reading bytes the kernel
never wrote.

    python3 p15_accept_probe.py marker
    python3 p15_accept_probe.py zero
"""
import ctypes
import os
import socket
import sys
import threading

PATH = "/tmp/p15_accept_probe.sock"
MARKER = b"P15_LEAK_MARKER_" + b"X" * 64

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.accept.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
libc.accept.restype = ctypes.c_int

mode = sys.argv[1] if len(sys.argv) > 1 else "marker"

try:
    os.unlink(PATH)
except OSError:
    pass

srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(PATH)
srv.listen(1)

# A sockaddr_un-sized buffer. sizeof(struct sockaddr_un) == 110 on Linux:
# 2 bytes of sa_family_t + 108 bytes of sun_path.
buf = ctypes.create_string_buffer(110)
if mode == "marker":
    # family = AF_UNIX (1), then a string that exists ONLY in this process.
    payload = b"\x01\x00" + MARKER
    ctypes.memmove(buf, payload, len(payload))
alen = ctypes.c_int(110)


def client():
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect(PATH)          # the client never binds, so it has NO name
    c.close()


threading.Thread(target=client).start()
fd = libc.accept(srv.fileno(), ctypes.cast(buf, ctypes.c_void_p),
                 ctypes.byref(alen))
if fd < 0:
    err = ctypes.get_errno()
    sys.exit("accept failed: %s" % os.strerror(err))

print("mode                : %s" % mode)
print("accept() returned fd: %d" % fd)
print("addrlen AFTER accept: %d  <-- how many bytes the kernel wrote" % alen.value)
print("family in buffer    : %d" % int.from_bytes(bytes(buf[0:2]), "little"))
print("bytes 2..42         : %r" % bytes(buf[2:42]))
print("-> the kernel wrote %d byte(s); everything past that is OURS, not its"
      % alen.value)

os.close(fd)
srv.close()
os.unlink(PATH)
