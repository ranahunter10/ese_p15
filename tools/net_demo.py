#!/usr/bin/env python3
"""
net_demo.py — a deterministic network scenario for the monitor to observe.

Run it while the monitor is attached (vm_validation.sh does this). It needs
no internet: everything happens over loopback, so the run is identical on any
machine and nothing depends on a DNS lookup or a reachable host.

It performs, each in its OWN process so attribution is unambiguous:

  1. a successful TCP connect to a local server       -> CONNECT, ret 0
  2. a refused TCP connect to a closed port           -> CONNECT, -ECONNREFUSED
  3. a connect to a unix socket                       -> CONNECT, AF_UNIX
  4. a non-blocking connect                           -> CONNECT, -EINPROGRESS
  5. an INBOUND connection, server and client in separate processes
        -> ACCEPT, attributed to the server, peer host as the endpoint
  6. the download-write-execute chain:
        downloader connects, receives a script, writes it to disk
        a separate shell then executes that file
     which is the chain a root-cause query has to reconstruct across a
     process boundary AND a protocol boundary.

Not covered here: accept(fd, NULL, NULL), the case where the kernel has no
peer name to report. Python's socket.accept() always passes a buffer, so
that path cannot be produced from Python and is covered by unit tests
instead (tests/test_processor.py::AcceptTest). The unix-socket accept below
does exercise the no-peer-name path on real data, because a unix client
normally has no bound address of its own.

Prints one JSON line describing what it did, so the analyzer asserts against
the actual ports and paths rather than hard-coded guesses.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

PAYLOAD = "#!/bin/sh\necho p15-net-demo-payload\n"


def serve_tcp(sock, payload, stop):
    sock.settimeout(0.5)
    while not stop.is_set():
        try:
            conn, _ = sock.accept()
        except socket.timeout:
            continue
        except OSError:
            return
        try:
            conn.sendall(payload.encode())
        finally:
            conn.close()


def serve_unix(sock, stop):
    sock.settimeout(0.5)
    while not stop.is_set():
        try:
            conn, _ = sock.accept()
        except socket.timeout:
            continue
        except OSError:
            return
        conn.close()


def run_python(code, *args):
    """A child process, so the connect is attributed to it and not to us."""
    return subprocess.call([sys.executable, "-c", code] + list(args))


# A server in its own process, so an accepted connection is attributed to a
# process that is NOT the one that connected. The port is chosen by the
# kernel and published through a file written-then-renamed, so the client
# never reads a half-written number.
SERVER_CODE = """
import os, socket, sys
tag, port_file = sys.argv[1], sys.argv[2]
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 0))
s.listen(4)
tmp = port_file + '.tmp'
open(tmp, 'w').write(str(s.getsockname()[1]))
os.rename(tmp, port_file)
s.settimeout(15)
try:
    conn, peer = s.accept()
    conn.close()
except Exception:
    pass
s.close()
"""


def inbound_demo(tmp):
    """Scenario 5: one process accepts, another connects."""
    port_file = os.path.join(tmp, "p15srv.port")
    srv = subprocess.Popen([sys.executable, "-c", SERVER_CODE,
                            "p15srv", port_file])
    port = 0
    for _ in range(100):                      # up to ~5 s
        if os.path.exists(port_file):
            try:
                port = int(open(port_file).read())
                break
            except ValueError:
                pass
        time.sleep(0.05)
    if port:
        run_python(
            "import socket,sys\n"
            "s=socket.socket()\n"
            "s.connect(('127.0.0.1', int(sys.argv[1])))\n"
            "s.close()", str(port))
    try:
        srv.wait(timeout=20)
    except Exception:
        srv.kill()
    return port


def main():
    out = {}
    tmp = tempfile.mkdtemp(prefix="p15net-")
    payload_path = os.path.join(tmp, "p15_net_payload.sh")
    unix_path = os.path.join(tmp, "p15.sock")
    stop = threading.Event()

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind(("127.0.0.1", 0))
    tcp.listen(16)
    port = tcp.getsockname()[1]

    un = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    un.bind(unix_path)
    un.listen(4)

    # A port nothing listens on: bind one, read its number, close it.
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    closed_port = probe.getsockname()[1]
    probe.close()

    threads = [threading.Thread(target=serve_tcp, args=(tcp, PAYLOAD, stop)),
               threading.Thread(target=serve_unix, args=(un, stop))]
    for t in threads:
        t.daemon = True
        t.start()
    time.sleep(0.2)

    try:
        # 1. plain successful connect.
        #    Deliberately NOT socket.create_connection(..., timeout): giving
        #    Python a timeout makes it set the socket non-blocking, so the
        #    connect syscall returns -EINPROGRESS and never 0. Verified with
        #    strace. Testing the blocking path needs a blocking socket.
        run_python(
            "import socket,sys\n"
            "s=socket.socket()\n"
            "s.connect(('127.0.0.1', int(sys.argv[1])))\n"
            "s.recv(256); s.close()", str(port))

        # 2. refused connect — what a port scan looks like from inside
        run_python(
            "import socket,sys\n"
            "s=socket.socket()\n"
            "try: s.connect(('127.0.0.1', int(sys.argv[1])))\n"
            "except OSError: pass\n"
            "s.close()", str(closed_port))

        # 3. unix socket (local IPC)
        run_python(
            "import socket,sys\n"
            "s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
            "try: s.connect(sys.argv[1])\n"
            "except OSError: pass\n"
            "s.close()", unix_path)

        # 4. non-blocking connect: returns EINPROGRESS, neither success nor
        #    failure at the moment the syscall returns
        run_python(
            "import socket,sys\n"
            "s=socket.socket(); s.setblocking(False)\n"
            "try: s.connect(('127.0.0.1', int(sys.argv[1])))\n"
            "except BlockingIOError: pass\n"
            "except OSError: pass\n"
            "import time; time.sleep(0.1); s.close()", str(port))

        # 5. inbound: the server child accepts, a client child connects
        server_port = inbound_demo(tmp)

        # 6. the chain: download in one process, execute from another
        run_python(
            "import socket,sys\n"
            "s=socket.socket()\n"
            "s.connect(('127.0.0.1', int(sys.argv[1])))\n"
            "data=s.recv(4096); s.close()\n"
            "open(sys.argv[2],'wb').write(data)", str(port), payload_path)
        os.chmod(payload_path, 0o755)
        subprocess.call(["/bin/sh", payload_path],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        out = {"ok": True, "port": port, "closed_port": closed_port,
               "unix_path": unix_path, "payload_path": payload_path,
               "endpoint": "net:127.0.0.1:%d" % port,
               "refused_endpoint": "net:127.0.0.1:%d" % closed_port,
               "unix_endpoint": "unix:" + unix_path,
               "server_port": server_port,
               # An inbound endpoint carries no port on purpose: the peer's
               # source port is ephemeral (see events.inbound_endpoint_id).
               "inbound_endpoint": "host:127.0.0.1",
               "server_tag": "p15srv"}
    finally:
        stop.set()
        tcp.close()
        un.close()
        for t in threads:
            t.join(timeout=2)
    print(json.dumps(out))


if __name__ == "__main__":
    main()
