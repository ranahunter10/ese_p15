// monitor.bpf.c — ESE-P15 kernel-side telemetry (BCC dialect, Linux 5.4+)
//
// This file is compiled by BCC (Clang/LLVM) when the monitor starts, then
// checked by the kernel's verifier and attached to tracepoints. monitor.py
// prepends a few #define lines before compiling it:
//
//   SELF_TGID          the monitor's own PID; its syscalls are ignored here
//   HOOK_EXEC          execve/execveat + sched_process_exec
//   HOOK_OPEN          open/openat enter+exit pairs
//   HOOK_EXIT          sched_process_exit
//   HOOK_NET           connect enter+exit pairs
//   KERNEL_EXEC_PATH   read the exec path from kernel memory (optional)
//   FILE_IDENTITY      read inode numbers of opened/executed files (optional)
//   SOCKET_TYPE        read the socket type behind connect()'s fd (optional)
//
// The two optional features are "try, fall back if the compiler/verifier
// refuses": monitor.py records which ones were active in the run stats.
//
// Walkthrough of every function: docs/ARCHITECTURE.md, section 3.

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/mm_types.h>
#include <linux/net.h>   // struct socket, for SOCKET_TYPE

#define MAX_FILENAME 256
#define ARG_LEN      128
#define MAXARG       20

#define UNIX_PATH_LEN 108

#define EVENT_EXEC_ENTER 0
#define EVENT_OPEN       1
#define EVENT_EXEC_OK    2
#define EVENT_EXIT       3
#define EVENT_ARG        4
#define EVENT_NET        5

// Address families we record. Everything else (AF_NETLINK, AF_PACKET, ...)
// is dropped in the kernel: it is not a process-to-process or
// process-to-host relationship, and NetworkManager alone would flood the
// buffer with netlink traffic. Values are the Linux ABI, fixed forever;
// tests/test_layout.py checks them against the system headers.
#define AF_UNIX_V   1
#define AF_INET_V   2
#define AF_INET6_V 10

#define NET_FLAG_INPROGRESS 1   // non-blocking connect still in flight
#define NET_FLAG_INBOUND    2   // accept(): the peer connected to US
#define NET_FLAG_NOPEER     4   // inbound, but the kernel had no peer name

#define ARG_FLAG_END       1   // last ARG record for this exec
#define ARG_FLAG_TRUNCATED 2   // argv had more than MAXARG entries

#define AT_FDCWD_VAL -100

// ---- Record layouts ---------------------------------------------------
// Every record type travels through the SAME perf buffer; the first 4 bytes
// (type) tell userspace which layout follows. Fields are ordered so the
// compiler adds no hidden padding (tests/test_layout.py verifies every
// offset against the Python copy in events.py).
//
// "Who did this, and when" is identical for every record type, so it is
// declared once as COMMON_FIELDS and placed FIRST in each struct. Each
// record type therefore begins with the same bytes in the same order, which
// is what lets one fill_common() serve all of them through a cast to
// struct common_t *. That prefix assumption is not taken on trust:
// test_layout.py compiles these structs and asserts every common field sits
// at the same offset in common_t, event_t and net_t.
#define COMMON_FIELDS                                                        \
    u32  type;                                                               \
    u32  pid;        /* process id  (kernel: tgid) */                        \
    u32  tid;        /* thread id   (kernel: pid)  */                        \
    u32  ppid;       /* parent process id */                                 \
    u32  uid;                                                                \
    u32  gid;                                                                \
    u64  ts_ns;      /* CLOCK_MONOTONIC when the event happened */           \
    u64  start_ns;   /* this process's start time (identity, ARCHITECTURE 4)*/\
    u64  pstart_ns;  /* parent process's start time */                       \
    char comm[TASK_COMM_LEN];   /* PROCESS name (group leader) */            \
    char tcomm[TASK_COMM_LEN];  /* THREAD name */                            \
    char pcomm[TASK_COMM_LEN];  /* parent process name */

struct common_t {
    COMMON_FIELDS
};

struct event_t {
    COMMON_FIELDS
    s32  ret;        // OPEN: fd or -errno   EXIT: wait status
    s32  flags;      // OPEN: open() flags   EXEC_ENTER: execveat flags
    u64  aux_ns;     // EXEC_OK: ts_ns of the matching EXEC_ENTER (0 = unknown)
    u64  ino;        // FILE_IDENTITY: inode number (0 = unknown)
    u32  dev;        // FILE_IDENTITY: device of the filesystem
    u32  igen;       // FILE_IDENTITY: inode generation
    s32  dfd;        // directory fd a relative path is relative to
    u32  pad;        // keeps the struct a multiple of 8 bytes
    char filename[MAX_FILENAME];
};

struct arg_t {
    u32  type;       // always EVENT_ARG
    u32  pid;
    u32  idx;        // position in argv (END record: number of args sent)
    u32  flags;      // ARG_FLAG_*
    u64  enter_ts;   // ts_ns of the EXEC_ENTER this belongs to
    char arg[ARG_LEN];
};

// One outbound connection attempt. Addresses and ports stay in NETWORK byte
// order exactly as the program supplied them; userspace converts (the kernel
// has no ntohs, and converting there would mean doing it per record for no
// reason).
struct net_t {
    COMMON_FIELDS
    s32  ret;        // 0 = connected, -errno otherwise (see NET_FLAG_INPROGRESS)
    s32  fd;         // the socket the program called connect() on
    u16  family;     // AF_INET_V / AF_INET6_V / AF_UNIX_V
    u16  dport;      // network byte order
    u16  sport;      // local port: only the kernel knows it (not filled yet)
    u16  nflags;     // NET_FLAG_*
    u8   daddr[16];  // IPv4 uses the first 4 bytes, IPv6 all 16
    u8   saddr[16];  // local address: not filled yet, see ARCHITECTURE
    char path[UNIX_PATH_LEN];   // AF_UNIX socket path ("@..." = abstract)
    u16  sock_type;  // SOCKET_TYPE: SOCK_STREAM / SOCK_DGRAM / ... (0 = unknown)
    // How many bytes of the sockaddr are REAL. On accept() this is what the
    // kernel wrote back through upeer_addrlen; on connect() it is the length
    // the caller passed. Everything in `path` past it is the caller's own
    // buffer contents, so userspace must trim to it before reading a name.
    // This occupies the u16 that used to be `pad`, so the record stays 256
    // bytes and the layout tests are unaffected.
    u16  addrlen;
};

struct open_args_t {
    const char *fname;   // USER-space pointer, read at syscall exit
    s32 flags;
    s32 dfd;
};

// What connect() was asked to do, parsed at syscall ENTRY and held until the
// result is known at exit. The sockaddr is copied out at entry on purpose:
// reading it at exit (as the open hook must, because a path is long and the
// kernel keeps no copy we can reach) would let a second thread rewrite the
// address after the kernel used it, and this value is what an enforcement
// layer would act on. Parsing at entry narrows that window to the syscall
// itself.
struct net_args_t {
    u8   daddr[16];
    char path[UNIX_PATH_LEN];
    s32  fd;
    u16  family;
    u16  dport;
    u16  addrlen;    // what the caller said the sockaddr holds
};

// What accept()/accept4() was asked to do. Only two numbers are needed,
// because for an inbound connection the address does not exist yet at
// entry: the KERNEL writes it into this buffer during the syscall
// (__sys_accept4 -> getname() -> move_addr_to_user(), v5.4 net/socket.c),
// before the new fd is installed. So the pointer is stashed here and the
// address is read at EXIT — the exact opposite of connect(), and the
// reason an accepted peer address is kernel truth rather than a claim made
// by the process being watched.
struct accept_args_t {
    u64  uaddr;      // where the kernel will put the peer address (may be 0)
    u64  ulen;       // where it will put HOW MANY bytes of it it wrote
    s32  fd;         // the LISTENING socket
    s32  pad;
};

// Why `ulen` is not optional. move_addr_to_user() does two things: it
// put_user()s the real length through this pointer, and then copies that
// many bytes. Everything past it is untouched, which for an output buffer
// means it is whatever the CALLER had there. So the length is not a detail
// of the address, it is the only thing that distinguishes the kernel's
// bytes from the traced process's leftovers.
//
// v3.6 read the fixed 110-byte sockaddr_un regardless and decided "is there
// a peer name?" by testing path[0] != 0 — i.e. by asking whether the
// caller's first leftover byte happened to be non-zero. Measured on
// 5.4.0-216-generic with tools/p15_accept_probe.py: a marker planted in the
// buffer BEFORE accept() came back out of the monitor as the peer identity
// (`unix:P15_LEAK_MARKER_XXXX...`), while zeroing the same buffer in the
// same program on the same socket gave `peer unknown`. Identical syscall,
// identical kernel answer (addrlen == 2 both times), different output.
// dbus-daemon showed the same thing unprompted, as `unix:ub<junk>`.
//
// Reading the length also fixes a second, quieter bug: an ABSTRACT unix
// address legitimately starts with a NUL byte, so path[0] == 0 was never a
// sound test for absence — a client that bound an abstract name before
// connecting would have been reported as having no peer at all. The length
// discriminates both cases correctly, because an abstract name makes
// klen > offsetof(sun_path) just as a filesystem name does.
#define SA_UN_HDR ((int)sizeof(u16))   // offsetof(struct sockaddr_un, sun_path)

// Minimal copies of the kernel's sockaddr layouts. Declared here rather than
// pulled from headers so the record parsing is readable in one place;
// tests/test_layout.py compiles these against <netinet/in.h> and <sys/un.h>
// and asserts every offset matches, so they cannot drift from the ABI.
struct sa_in_t  { u16 family; u16 port; u32 addr; };
struct sa_in6_t { u16 family; u16 port; u32 flowinfo; u8 addr[16]; u32 scope_id; };
struct sa_un_t  { u16 family; char path[UNIX_PATH_LEN]; };

BPF_PERF_OUTPUT(events);

// Per-CPU scratch: the eBPF stack is only 512 bytes; event_t is 392 and
// exec_enter() needs it together with the 152-byte arg_t (544 > 512), with
// no room left for growth (tests/test_layout.py pins both sizes).
// One private slot per CPU needs no locking. It is safe from being reused
// by a nested program on the same CPU because the kernel does not run a
// second tracing program while one is active on that CPU (bpf_prog_active
// guard in trace_call_bpf) — that nested event is skipped instead.
BPF_PERCPU_ARRAY(ev_scratch, struct event_t, 1);
BPF_PERCPU_ARRAY(arg_scratch, struct arg_t, 1);
#ifdef HOOK_NET
BPF_PERCPU_ARRAY(net_scratch, struct net_t, 1);
#endif

// LRU hashes evict the oldest entry when full, so entries that are never
// cleaned up (thread killed mid-syscall, failed exec) can't fill the map.
BPF_TABLE("lru_hash", u64, struct open_args_t, open_args, 16384);  // key: pid_tgid
BPF_TABLE("lru_hash", u32, u64, exec_start, 16384);                 // key: thread id
#ifdef HOOK_NET
BPF_TABLE("lru_hash", u64, struct net_args_t, net_args, 16384);     // key: pid_tgid
// Accept gets its OWN map, small as it is, instead of sharing net_args.
// A listener can sit blocked inside accept() for hours (sshd), and an LRU
// evicts the OLDEST entry: sharing one map would let ordinary outbound
// churn — 16 384 connects on a busy host — throw away the stash of the one
// blocked accept we care most about, and that inbound connection would
// then be missed entirely at exit. Separating them means only other
// accepts can evict an accept.
BPF_TABLE("lru_hash", u64, struct accept_args_t, accept_args, 16384);
#endif

static inline __attribute__((always_inline)) int is_self(void) {
    return (bpf_get_current_pid_tgid() >> 32) == SELF_TGID;
}

// Describe "who is running right now", into the common prefix any record
// type starts with. The scratch slot is reused between events, so EVERY
// field is reset first — the record-specific fields by the fill_*() below.
static inline __attribute__((always_inline))
void fill_common(struct common_t *c, u32 type) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *leader = NULL;
    struct task_struct *parent = NULL;
    struct task_struct *pleader = NULL;
    u64 id = bpf_get_current_pid_tgid();
    u64 ug = bpf_get_current_uid_gid();

    c->type = type;
    c->pid = id >> 32;
    c->tid = (u32)id;
    c->uid = (u32)ug;
    c->gid = ug >> 32;
    c->ts_ns = bpf_ktime_get_ns();
    c->start_ns = 0;
    c->pstart_ns = 0;
    c->ppid = 0;
    c->comm[0] = 0;
    c->pcomm[0] = 0;

    bpf_get_current_comm(&c->tcomm, sizeof(c->tcomm));   // THREAD name

    // The group leader holds the process name and the start time all
    // threads of the process share.
    bpf_probe_read(&leader, sizeof(leader), &task->group_leader);
    if (leader) {
        bpf_probe_read(&c->start_ns, sizeof(c->start_ns), &leader->start_time);
        bpf_probe_read(&c->comm, sizeof(c->comm), &leader->comm);
    }

    // real_parent = who forked us (or the reaper after orphaning);
    // task->parent may be a debugger while ptrace is attached.
    bpf_probe_read(&parent, sizeof(parent), &task->real_parent);
    if (parent) {
        bpf_probe_read(&pleader, sizeof(pleader), &parent->group_leader);
        if (pleader) {
            bpf_probe_read(&c->ppid, sizeof(c->ppid), &pleader->tgid);
            bpf_probe_read(&c->pstart_ns, sizeof(c->pstart_ns), &pleader->start_time);
            bpf_probe_read(&c->pcomm, sizeof(c->pcomm), &pleader->comm);
        }
    }
}

// Common prefix + the fields only event_t has.
static inline __attribute__((always_inline))
void fill_event(struct event_t *ev, u32 type) {
    fill_common((struct common_t *)ev, type);
    ev->ret = 0;
    ev->flags = 0;
    ev->aux_ns = 0;
    ev->ino = 0;
    ev->dev = 0;
    ev->igen = 0;
    ev->dfd = AT_FDCWD_VAL;
    ev->pad = 0;
    ev->filename[0] = 0;
}

#ifdef FILE_IDENTITY
// A path is only a name; the inode is the file. Keying files by
// (device, inode, generation) makes "/tmp/x", "./x" and "../tmp/x" the same
// node, and keeps two different directories both called "lib" apart.
static inline __attribute__((always_inline))
void read_inode(struct event_t *ev, struct file *f) {
    struct inode *inode = NULL;
    struct super_block *sb = NULL;
    if (!f)
        return;
    bpf_probe_read(&inode, sizeof(inode), &f->f_inode);
    if (!inode)
        return;
    bpf_probe_read(&ev->ino, sizeof(ev->ino), &inode->i_ino);
    bpf_probe_read(&ev->igen, sizeof(ev->igen), &inode->i_generation);
    bpf_probe_read(&sb, sizeof(sb), &inode->i_sb);
    if (sb)
        bpf_probe_read(&ev->dev, sizeof(ev->dev), &sb->s_dev);
}

// fd -> struct file, walking task->files->fdt->fd[fd]. Another thread
// could close the fd in the instant between the syscall returning and this
// read; then we read NULL or another file. Accepted and documented.
static inline __attribute__((always_inline))
void read_fd_inode(struct event_t *ev, int fd) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files = NULL;
    struct fdtable *fdt = NULL;
    struct file **fds = NULL;
    struct file *f = NULL;
    unsigned int max_fds = 0;
    if (fd < 0)
        return;
    bpf_probe_read(&files, sizeof(files), &task->files);
    if (!files)
        return;
    bpf_probe_read(&fdt, sizeof(fdt), &files->fdt);
    if (!fdt)
        return;
    bpf_probe_read(&max_fds, sizeof(max_fds), &fdt->max_fds);
    if ((unsigned int)fd >= max_fds)
        return;
    bpf_probe_read(&fds, sizeof(fds), &fdt->fd);
    if (!fds)
        return;
    // Plain integer arithmetic for the slot address, so BCC's source
    // rewriter has nothing to reinterpret.
    u64 slot = (u64)fds + (u64)fd * sizeof(struct file *);
    bpf_probe_read(&f, sizeof(f), (void *)slot);
    read_inode(ev, f);
}

// The executable now mapped by the current process.
static inline __attribute__((always_inline))
void read_exe_inode(struct event_t *ev) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct mm_struct *mm = NULL;
    struct file *exe = NULL;
    bpf_probe_read(&mm, sizeof(mm), &task->mm);
    if (!mm)
        return;
    bpf_probe_read(&exe, sizeof(exe), &mm->exe_file);
    read_inode(ev, exe);
}
#endif

#ifdef SOCKET_TYPE
// fd -> socket type (SOCK_STREAM, SOCK_DGRAM, ...), via the same fd table
// walk, then file->private_data, which for a socket points at struct socket.
//
// Why it is worth reading: glibc's getaddrinfo() opens a UDP socket and
// connect()s it to each candidate address — with port 0 — purely to let the
// kernel pick a source address for RFC 3484 sorting. Those probes look
// exactly like connections in a record that carries only an address. The
// socket type is what separates "this program opened a TCP connection" from
// "this program resolved a name", and enforcement should only ever act on
// the former.
static inline __attribute__((always_inline))
u16 read_sock_type(int fd) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files = NULL;
    struct fdtable *fdt = NULL;
    struct file **fds = NULL;
    struct file *f = NULL;
    struct socket *sock = NULL;
    unsigned int max_fds = 0;
    short type = 0;
    if (fd < 0)
        return 0;
    bpf_probe_read(&files, sizeof(files), &task->files);
    if (!files)
        return 0;
    bpf_probe_read(&fdt, sizeof(fdt), &files->fdt);
    if (!fdt)
        return 0;
    bpf_probe_read(&max_fds, sizeof(max_fds), &fdt->max_fds);
    if ((unsigned int)fd >= max_fds)
        return 0;
    bpf_probe_read(&fds, sizeof(fds), &fdt->fd);
    if (!fds)
        return 0;
    u64 slot = (u64)fds + (u64)fd * sizeof(struct file *);
    bpf_probe_read(&f, sizeof(f), (void *)slot);
    if (!f)
        return 0;
    // sock_alloc_file() stores the struct socket here.
    bpf_probe_read(&sock, sizeof(sock), &f->private_data);
    if (!sock)
        return 0;
    bpf_probe_read(&type, sizeof(type), &sock->type);
    return (u16)type;
}

#endif  // SOCKET_TYPE

#ifdef HOOK_EXEC
// ---- Process execution ------------------------------------------------
// sys_enter_execve(at) fires BEFORE the kernel tries the exec: the caller's
// name is still in comm, and the exec may yet fail. So this only records
// the ATTEMPT (+ argv); sched_process_exec below confirms success.
static inline __attribute__((always_inline))
int exec_enter(void *ctx, const char *filename, const char *const *argv,
               int dfd, int flags) {
    if (is_self())
        return 0;
    u32 zero = 0;
    struct event_t *ev = ev_scratch.lookup(&zero);
    struct arg_t *a = arg_scratch.lookup(&zero);
    if (!ev || !a)                       // verifier requires the NULL checks
        return 0;

    fill_event(ev, EVENT_EXEC_ENTER);
    ev->dfd = dfd;
    ev->flags = flags;
    bpf_probe_read_str(&ev->filename, sizeof(ev->filename), (void *)filename);
    events.perf_submit(ctx, ev, sizeof(*ev));

    u32 tid = ev->tid;
    u64 ts = ev->ts_ns;
    exec_start.update(&tid, &ts);

    // argv: a user-space array of user-space string pointers; each read can
    // fail, leaving argp NULL. Constant loop bound: accepted by the 5.3+
    // verifier (and usually unrolled by clang anyway).
    a->type = EVENT_ARG;
    a->pid = ev->pid;
    a->enter_ts = ts;
    a->flags = 0;
    int i;
    for (i = 0; i < MAXARG; i++) {
        const char *argp = NULL;
        u64 slot = (u64)argv + (u64)i * sizeof(const char *);
        bpf_probe_read(&argp, sizeof(argp), (void *)slot);
        if (!argp)
            goto end;
        a->idx = i;
        bpf_probe_read_str(&a->arg, sizeof(a->arg), (void *)argp);
        events.perf_submit(ctx, a, sizeof(*a));
    }
    a->flags = ARG_FLAG_TRUNCATED;       // MAXARG read, there may be more
end:
    // Always an explicit END carrying the count, so userspace knows argv is
    // complete regardless of the order records are read in.
    a->idx = i;
    a->flags |= ARG_FLAG_END;
    a->arg[0] = 0;
    events.perf_submit(ctx, a, sizeof(*a));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    return exec_enter(args, (const char *)args->filename,
                      (const char *const *)args->argv, AT_FDCWD_VAL, 0);
}

// execveat(fd, "", argv, envp, AT_EMPTY_PATH) runs a program from an open
// file descriptor — glibc's fexecve(), and the usual way to run a program
// that exists only in memory (memfd_create). Core to "fileless" attacks.
TRACEPOINT_PROBE(syscalls, sys_enter_execveat) {
    return exec_enter(args, (const char *)args->filename,
                      (const char *const *)args->argv, args->fd, args->flags);
}

// Fires inside exec only after the new program image is in place.
// old_pid: in a multithreaded exec, the calling thread takes over the
// leader's id, so its thread id changes during the syscall.
TRACEPOINT_PROBE(sched, sched_process_exec) {
    if (is_self())
        return 0;
    u32 zero = 0;
    struct event_t *ev = ev_scratch.lookup(&zero);
    if (!ev)
        return 0;
    fill_event(ev, EVENT_EXEC_OK);

    u32 old = args->old_pid;
    u64 *enter_ts = exec_start.lookup(&old);
    if (enter_ts) {
        ev->aux_ns = *enter_ts;          // copy BEFORE delete invalidates it
        exec_start.delete(&old);
    }
#ifdef KERNEL_EXEC_PATH
    // __data_loc field: the low 16 bits are the string's offset inside this
    // tracepoint record. This is the kernel's own copy of the path
    // (e.g. "/dev/fd/3" for an fd exec), not user memory.
    u16 off = args->data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&ev->filename, sizeof(ev->filename), (char *)args + off);
#endif
#ifdef FILE_IDENTITY
    read_exe_inode(ev);
#endif
    events.perf_submit(args, ev, sizeof(*ev));
    return 0;
}
#endif  // HOOK_EXEC

#ifdef HOOK_OPEN
// ---- File access ------------------------------------------------------
// Enter/exit pairing (as in BCC's opensnoop): entry stashes the path
// pointer and flags; exit knows the result (fd or -errno).
static inline __attribute__((always_inline))
int stash_open(const char *fname, int flags, int dfd) {
    if (is_self())
        return 0;
    struct open_args_t oa = {};
    u64 id = bpf_get_current_pid_tgid();
    oa.fname = fname;
    oa.flags = flags;
    oa.dfd = dfd;
    open_args.update(&id, &oa);
    return 0;
}

static inline __attribute__((always_inline))
int emit_open(void *ctx, long ret) {
    u64 id = bpf_get_current_pid_tgid();
    struct open_args_t *oa = open_args.lookup(&id);
    if (!oa)
        return 0;
    u32 zero = 0;
    struct event_t *ev = ev_scratch.lookup(&zero);
    if (!ev) {
        open_args.delete(&id);
        return 0;
    }
    fill_event(ev, EVENT_OPEN);
    ev->ret = (s32)ret;
    ev->flags = oa->flags;
    ev->dfd = oa->dfd;
    // The path is read from USER memory: a hostile program could change it
    // after the kernel used it (TOCTOU). The inode below is the kernel's
    // truth about which file was actually opened.
    bpf_probe_read_str(&ev->filename, sizeof(ev->filename), (void *)oa->fname);
    open_args.delete(&id);
#ifdef FILE_IDENTITY
    if (ret >= 0)
        read_fd_inode(ev, (int)ret);
#endif
    events.perf_submit(ctx, ev, sizeof(*ev));
    return 0;
}

// glibc's open() calls openat() (Journal row 7); the plain open syscall
// still exists on x86_64 for static/old binaries.
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    return stash_open((const char *)args->filename, args->flags, args->dfd);
}
TRACEPOINT_PROBE(syscalls, sys_exit_openat) {
    return emit_open(args, args->ret);
}
TRACEPOINT_PROBE(syscalls, sys_enter_open) {
    return stash_open((const char *)args->filename, args->flags, AT_FDCWD_VAL);
}
TRACEPOINT_PROBE(syscalls, sys_exit_open) {
    return emit_open(args, args->ret);
}
#endif  // HOOK_OPEN

#ifdef HOOK_EXIT
// ---- Process exit -----------------------------------------------------
// Fires for every exiting THREAD; only the group leader counts as the
// process exiting (high half of pid_tgid == low half).
TRACEPOINT_PROBE(sched, sched_process_exit) {
    u64 id = bpf_get_current_pid_tgid();
    if ((u32)(id >> 32) != (u32)id)
        return 0;
    if (is_self())
        return 0;
    u32 zero = 0;
    struct event_t *ev = ev_scratch.lookup(&zero);
    if (!ev)
        return 0;
    fill_event(ev, EVENT_EXIT);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int code = 0;
    // do_exit() stores exit_code before this tracepoint fires (validated:
    // `sh -c 'exit 3'` reported 3).
    bpf_probe_read(&code, sizeof(code), &task->exit_code);
    ev->ret = code;      // wait status: (code >> 8) = exit(), low 7 bits = signal
    events.perf_submit(args, ev, sizeof(*ev));
    return 0;
}
#endif  // HOOK_EXIT

#ifdef HOOK_NET
// ---- Outbound connections ---------------------------------------------
// connect() is where a process names who it wants to talk to, and it is the
// only place that name exists in the process's own context: afterwards the
// traffic belongs to a socket, and by the time a packet leaves the machine
// nothing in it says which program produced it. That gap — hardware sees
// packets, the host knows processes — is what Layer 4 has to bridge.
//
// Enter/exit pairing, as with open(): entry parses the address the program
// asked for, exit reports what the kernel made of it. A FAILED connect is
// kept deliberately — a refused or timed-out connect is what port scanning
// and host discovery look like from the inside.
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    if (is_self())
        return 0;
    struct net_args_t na = {};
    u16 family = 0;
    void *uaddr = (void *)args->uservaddr;

    // Read the family first: it decides which layout the rest follows, and
    // reading the wrong number of bytes from user memory is how you both
    // mis-parse an address and risk an unnecessary fault.
    if (bpf_probe_read(&family, sizeof(family), uaddr) != 0)
        return 0;
    na.family = family;
    na.fd = args->fd;
    // The caller's own declared length. For connect() the sockaddr is an
    // INPUT, so this is not kernel truth — but it still bounds how much of
    // `path` the caller claims to have filled, which is what userspace
    // trims to. Reading past it was the latent half of the accept() bug.
    na.addrlen = (u16)(args->addrlen > 0 ? args->addrlen : 0);

    if (family == AF_INET_V) {
        struct sa_in_t sa = {};
        if (bpf_probe_read(&sa, sizeof(sa), uaddr) != 0)
            return 0;
        na.dport = sa.port;
        __builtin_memcpy(&na.daddr, &sa.addr, sizeof(sa.addr));
    } else if (family == AF_INET6_V) {
        struct sa_in6_t sa = {};
        if (bpf_probe_read(&sa, sizeof(sa), uaddr) != 0)
            return 0;
        na.dport = sa.port;
        __builtin_memcpy(&na.daddr, &sa.addr, sizeof(sa.addr));
    } else if (family == AF_UNIX_V) {
        // A unix socket is local IPC: who talks to the docker socket or the
        // system bus matters as much as who opens a TCP connection.
        struct sa_un_t sa = {};
        // addrlen is often smaller than the full 110-byte struct. Reading
        // the whole thing is normally fine (callers use a sockaddr_un on
        // the stack) and simply fails, harmlessly, when it is not — the
        // family alone is still recorded.
        if (bpf_probe_read(&sa, sizeof(sa), uaddr) == 0)
            __builtin_memcpy(&na.path, &sa.path, sizeof(na.path));
    } else {
        return 0;        // not a relationship we model (see AF_*_V above)
    }

    u64 id = bpf_get_current_pid_tgid();
    net_args.update(&id, &na);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_connect) {
    u64 id = bpf_get_current_pid_tgid();
    struct net_args_t *na = net_args.lookup(&id);
    if (!na)
        return 0;
    u32 zero = 0;
    struct net_t *n = net_scratch.lookup(&zero);
    if (!n) {
        net_args.delete(&id);
        return 0;
    }
    fill_common((struct common_t *)n, EVENT_NET);
    n->ret = (s32)args->ret;
    n->fd = na->fd;
    n->family = na->family;
    n->dport = na->dport;
    n->sport = 0;
    n->addrlen = na->addrlen;
    n->sock_type = 0;
#ifdef SOCKET_TYPE
    n->sock_type = read_sock_type(na->fd);
#endif
    __builtin_memcpy(&n->daddr, &na->daddr, sizeof(n->daddr));
    __builtin_memset(&n->saddr, 0, sizeof(n->saddr));
    __builtin_memcpy(&n->path, &na->path, sizeof(n->path));
    // A non-blocking connect returns -EINPROGRESS and may still succeed or
    // fail later; it is an attempt, not a failure. Userspace must not count
    // it as either, so say so explicitly rather than leaving -115 to be
    // interpreted downstream.
    n->nflags = (args->ret == -115) ? NET_FLAG_INPROGRESS : 0;
    net_args.delete(&id);
    events.perf_submit(args, n, sizeof(*n));
    return 0;
}

// ---------------------------------------------------------------------
// Inbound: accept() / accept4()
//
// Both are hooked because both are really used: glibc's accept() issues
// __NR_accept, while Python's socket.accept() issues __NR_accept4 with
// SOCK_CLOEXEC (both verified under strace, Journal row 86). Hooking only
// one would make half the servers on the box invisible.
// ---------------------------------------------------------------------
static inline __attribute__((always_inline))
int accept_enter(int fd, u64 uaddr, u64 ulen) {
    if (is_self())
        return 0;
    u64 id = bpf_get_current_pid_tgid();
    struct accept_args_t aa = {};
    aa.fd = fd;
    aa.uaddr = uaddr;
    aa.ulen = ulen;
    // One stash per thread, overwritten on re-entry. A thread can only be
    // inside accept() twice if a signal handler calls accept() while the
    // first call is blocked, in which case the inner call's stash wins and
    // the outer one's record is lost at exit. Known, shared with the
    // connect path, and left alone deliberately: the alternative is a
    // per-thread stack of stashes, which costs map space on every thread
    // to cover a case that needs a signal handler doing socket I/O.
    accept_args.update(&id, &aa);
    return 0;
}

static inline __attribute__((always_inline))
int accept_exit(void *ctx, s64 ret) {
    u64 id = bpf_get_current_pid_tgid();
    struct accept_args_t *aa = accept_args.lookup(&id);
    if (!aa)
        return 0;
    // A failed accept is an ABSENCE, not an attempt: -EAGAIN fires on every
    // poll of a non-blocking listener and -EINTR on every signal, no peer
    // exists and no buffer was written. Dropped here, in the kernel, before
    // it can flood the ring. This is the opposite of the connect() rule,
    // where a refusal IS the signal (that is what scanning looks like) —
    // the asymmetry is in the meaning of the failure, not in taste.
    if (ret < 0) {
        accept_args.delete(&id);
        return 0;
    }
    u32 zero = 0;
    struct net_t *n = net_scratch.lookup(&zero);
    if (!n) {
        accept_args.delete(&id);
        return 0;
    }
    fill_common((struct common_t *)n, EVENT_NET);
    n->ret = (s32)ret;          // inbound: the NEW connection fd, not a status
    n->fd = aa->fd;             // the listening socket
    n->family = 0;
    n->dport = 0;
    n->sport = 0;
    n->addrlen = 0;
    n->sock_type = 0;
    n->nflags = NET_FLAG_INBOUND;
    __builtin_memset(&n->daddr, 0, sizeof(n->daddr));
    __builtin_memset(&n->saddr, 0, sizeof(n->saddr));
    __builtin_memset(&n->path, 0, sizeof(n->path));
#ifdef SOCKET_TYPE
    n->sock_type = read_sock_type(aa->fd);
#endif
    // accept(fd, NULL, NULL) is legal and common (a server that does not
    // care who called). Then there is no peer name anywhere to read, so the
    // record says so rather than reporting 0.0.0.0.
    u64 uaddr = aa->uaddr;
    // How many bytes the kernel actually wrote. Read FIRST, because it is
    // what makes the rest of the buffer trustworthy or not: never read more
    // of a user buffer than the kernel said it wrote. See the note above
    // accept_args_t for the measurement that forced this.
    int klen = 0;
    int have_len = (aa->ulen != 0 &&
                    bpf_probe_read(&klen, sizeof(klen), (void *)aa->ulen) == 0);
    if (have_len && klen > 0 && klen <= (int)sizeof(struct sa_un_t))
        n->addrlen = (u16)klen;
    if (uaddr == 0 || !have_len || klen <= SA_UN_HDR) {
        // No buffer, no length, or a length that stops at the family: the
        // kernel is telling us it has no peer identity to give. accept(fd,
        // NULL, NULL) is legal and common (a server that does not care who
        // called), and an unnamed unix client is the same answer by a
        // different route.
        n->nflags |= NET_FLAG_NOPEER;
        // The family is still worth recording when there is one to read.
        if (uaddr != 0) {
            u16 fam = 0;
            if (bpf_probe_read(&fam, sizeof(fam), (void *)uaddr) == 0)
                n->family = fam;
        }
    } else {
        u16 family = 0;
        if (bpf_probe_read(&family, sizeof(family), (void *)uaddr) != 0) {
            n->nflags |= NET_FLAG_NOPEER;
        } else {
            n->family = family;
            if (family == AF_INET_V) {
                struct sa_in_t sa = {};
                // The kernel always writes a full sockaddr_in for an IP
                // peer, so this bound is belt-and-braces — but it makes the
                // rule one rule instead of a special case for unix.
                if (klen >= (int)sizeof(sa) &&
                    bpf_probe_read(&sa, sizeof(sa), (void *)uaddr) == 0) {
                    n->dport = sa.port;
                    __builtin_memcpy(&n->daddr, &sa.addr, sizeof(sa.addr));
                } else {
                    n->nflags |= NET_FLAG_NOPEER;
                }
            } else if (family == AF_INET6_V) {
                struct sa_in6_t sa = {};
                if (klen >= (int)sizeof(sa) &&
                    bpf_probe_read(&sa, sizeof(sa), (void *)uaddr) == 0) {
                    n->dport = sa.port;
                    __builtin_memcpy(&n->daddr, &sa.addr, sizeof(sa.addr));
                } else {
                    n->nflags |= NET_FLAG_NOPEER;
                }
            } else if (family == AF_UNIX_V) {
                // klen > SA_UN_HDR here, so the kernel DID write a name:
                // either a filesystem path or an abstract one (which begins
                // with a NUL and is why path[0] was never a sound test).
                //
                // The copy stays a CONSTANT-size read and the trimming to
                // `addrlen` happens in userspace. The first attempt at this
                // fix truncated here instead, with a constant-bound loop
                // copying sa.path[i] byte by byte — and the 5.4 verifier
                // refused the whole program: clang partially unrolled it and
                // the verifier lost track of the stack bounds,
                // `invalid read from stack off -34+0 size 1`. The argv loop
                // looks similar but is not: it reads USER memory through
                // bpf_probe_read (one helper call, constant size), never the
                // BPF stack byte by byte. Doing it in userspace is also
                // strictly better, because the truncation then has unit
                // tests — in here it could only ever be asserted by grep.
                struct sa_un_t sa = {};
                if (bpf_probe_read(&sa, sizeof(sa), (void *)uaddr) == 0)
                    __builtin_memcpy(&n->path, &sa.path, sizeof(sa.path));
                else
                    n->nflags |= NET_FLAG_NOPEER;
            } else {
                n->nflags |= NET_FLAG_NOPEER;
            }
        }
    }
    accept_args.delete(&id);
    events.perf_submit(ctx, n, sizeof(*n));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_accept) {
    return accept_enter(args->fd, (u64)args->upeer_sockaddr,
                        (u64)args->upeer_addrlen);
}

TRACEPOINT_PROBE(syscalls, sys_enter_accept4) {
    return accept_enter(args->fd, (u64)args->upeer_sockaddr,
                        (u64)args->upeer_addrlen);
}

TRACEPOINT_PROBE(syscalls, sys_exit_accept) {
    return accept_exit(args, args->ret);
}

TRACEPOINT_PROBE(syscalls, sys_exit_accept4) {
    return accept_exit(args, args->ret);
}
#endif  // HOOK_NET
