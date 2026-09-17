/*
 * apply-seccomp.c - Apply seccomp BPF filter in an isolated PID namespace
 *
 * Usage: apply-seccomp [--allow-unix-connect PATH]... [--] <command> [args...]
 *
 * This program applies a baked-in seccomp BPF filter, isolates the
 * target command in a nested user+PID+mount namespace so it cannot see or
 * ptrace any process that lacks the filter, applies the filter with
 * prctl(PR_SET_SECCOMP), and execs the command.
 *
 * Without --allow-unix-connect the filter denies socket(AF_UNIX, ...)
 * outright. With one or more --allow-unix-connect entries (a socket path,
 * or a directory whose sockets are all allowed), AF_UNIX stream/seqpacket
 * sockets may be created, and every connect()/bind() is brokered by the
 * outer stub through seccomp user notification: the stub performs the
 * syscall itself on the caller's socket and only lets a unix connect
 * through when the canonical target path is inside the allowlist. See
 * "Brokered unix connect" below for why nothing weaker is race-free.
 *
 * Process layout inside the outer bwrap sandbox:
 *
 *   bwrap init (PID 1)          <- outer PID ns, no seccomp
 *   \_ bash / socat ...         <- outer PID ns, no seccomp
 *      \_ apply-seccomp [outer] <- outer PID ns, waits for inner init
 *         |_ apply-seccomp [supervisor]  <- outer PID ns, brokered mode only:
 *         |                                 holds the notification listener,
 *         |                                 PR_SET_DUMPABLE=0
 *         ================================================= PID ns boundary
 *         \_ apply-seccomp [inner init] <- inner PID 1, PR_SET_DUMPABLE=0
 *            \_ user command            <- inner PID 2, seccomp applied
 *
 * The supervisor is forked before the PID-namespace unshare, so it is neither
 * addressable nor signallable from inside the sandbox, and it can still
 * create threads (the kernel refuses CLONE_THREAD once a task has unshared
 * its children's PID namespace).
 *
 * From the user command's point of view /proc contains only its own process
 * tree. The bwrap init, bash wrapper, and socat helpers are not addressable,
 * so they cannot be ptraced or patched via /proc/N/mem even on systems with
 * kernel.yama.ptrace_scope=0. The inner init (PID 1) sets PR_SET_DUMPABLE=0
 * so it cannot be ptraced either.
 *
 * Any failure to set up the nested namespaces aborts with a non-zero exit
 * status; we never fall back to running the command without isolation.
 *
 * Compile: gcc -static -pthread -O2 -o apply-seccomp apply-seccomp.c
 */

#define _GNU_SOURCE
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <sched.h>
#include <signal.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <poll.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/bpf_common.h>

#include "unix-block-bpf.h"

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif

#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER 2
#endif

#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif
#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
#endif

#if defined(__x86_64__)
#  define SRT_AUDIT_ARCH AUDIT_ARCH_X86_64
#  define SRT_HAS_X32 1
#elif defined(__aarch64__)
#  define SRT_AUDIT_ARCH AUDIT_ARCH_AARCH64
#  define SRT_HAS_X32 0
#else
#  define SRT_AUDIT_ARCH 0
#  define SRT_HAS_X32 0
#endif

/* ---- Optional passive observation filter ---------------------------------
 *
 * When SRT_OBSERVE_SOCK is set the worker installs a second seccomp filter
 * that traps write-intent filesystem syscalls to
 * SECCOMP_RET_USER_NOTIF, then ships the listener fd to the OUTER STUB over
 * a pre-fork socketpair. The outer stub is never under either filter, so it
 * services every notification with SECCOMP_USER_NOTIF_FLAG_CONTINUE — the
 * workload's behaviour is unchanged — and writes one JSON line per
 * observed call to the SRT_OBSERVE_SOCK unix socket (a Node net.Server).
 *
 * Paths are read from the workload's address space with process_vm_readv.
 * That memory is ATTACKER-CONTROLLED and racy (the workload can rewrite the
 * buffer between trap and read). bwrap's mount table is the only enforcement
 * boundary; the path reported here is a HINT for diagnostics and must never
 * gate a policy decision.
 *
 * Every failure path is fail-open: any error before the filter is installed
 * disables observation and proceeds; any error after still drains the notify
 * fd with CONTINUE so the workload cannot wedge. */

#ifndef SECCOMP_IOCTL_NOTIF_RECV
#  define SECCOMP_IOC_MAGIC '!'
#  define SECCOMP_IOCTL_NOTIF_RECV     _IOWR(SECCOMP_IOC_MAGIC, 0, struct seccomp_notif)
#  define SECCOMP_IOCTL_NOTIF_SEND     _IOWR(SECCOMP_IOC_MAGIC, 1, struct seccomp_notif_resp)
#  define SECCOMP_IOCTL_NOTIF_ID_VALID _IOW (SECCOMP_IOC_MAGIC, 2, __u64)
#endif
#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#  define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1UL << 0)
#endif
#ifndef SECCOMP_FILTER_FLAG_TSYNC_ESRCH
#  define SECCOMP_FILTER_FLAG_TSYNC_ESRCH (1UL << 4)
#endif
#ifndef AT_FDCWD
#  define AT_FDCWD (-100)
#endif
#ifndef SECCOMP_GET_NOTIF_SIZES
#  define SECCOMP_GET_NOTIF_SIZES 3
#endif
#ifndef __NR_pidfd_open
#  define __NR_pidfd_open 434
#endif
#ifndef __NR_pidfd_getfd
#  define __NR_pidfd_getfd 438
#endif
#ifndef __NR_fchmodat2
#  define __NR_fchmodat2 452
#endif
#ifndef __NR_io_uring_setup
#  define __NR_io_uring_setup 425
#endif
#ifndef __NR_io_uring_enter
#  define __NR_io_uring_enter 426
#endif
#ifndef __NR_io_uring_register
#  define __NR_io_uring_register 427
#endif
#ifndef PIDFD_THREAD
#  define PIDFD_THREAD O_EXCL
#endif
#ifndef SECCOMP_RET_KILL_PROCESS
#  define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif
#ifndef SECCOMP_RET_ERRNO
#  define SECCOMP_RET_ERRNO 0x00050000U
#endif
#ifndef SECCOMP_RET_DATA
#  define SECCOMP_RET_DATA 0x0000ffffU
#endif
#ifndef SECCOMP_SET_MODE_FILTER
#  define SECCOMP_SET_MODE_FILTER 1
#endif
#ifndef SECCOMP_IOC_MAGIC
#  define SECCOMP_IOC_MAGIC '!'
#endif
#ifndef _IOC_TYPESHIFT
#  define _IOC_TYPESHIFT 8
#endif

/* ---- Unix socket allowlist (--allow-unix-connect) ------------------------ */

#define MAX_ALLOW 64
static const char *g_allow[MAX_ALLOW];
static int g_nallow;
/* Brokered mode is active: the worker installs the USER_NOTIF unix filter
 * instead of the baked-in block filter, and the outer stub performs every
 * connect()/bind() on the workload's behalf. */
static int g_broker;
/* The outer stub's cwd is the pinned procfs "self/fd" directory, so a
 * relative sun_path of "<fd>" names the magic link of one of its own fds. */
static int g_fdcwd_ok;

static void add_allow(const char *p) {
    if (g_nallow == MAX_ALLOW) {
        fprintf(stderr, "apply-seccomp: too many --allow-unix-connect entries (max %d)\n", MAX_ALLOW);
        exit(1);
    }
    char buf[PATH_MAX], canon[PATH_MAX];
    const char *home = getenv("HOME");
    if (p[0] == '~' && (p[1] == '/' || p[1] == '\0') && home && *home) {
        snprintf(buf, sizeof(buf), "%s%s", home, p + 1);
    } else {
        snprintf(buf, sizeof(buf), "%s", p);
    }
    if (buf[0] != '/') {
        fprintf(stderr, "apply-seccomp: --allow-unix-connect path must be absolute: %s\n", p);
        exit(1);
    }
    if (realpath(buf, canon)) {
        g_allow[g_nallow++] = strdup(canon);
        return;
    }
    /* An entry that does not resolve now is dropped rather than kept as a
     * literal: a path the sandbox can still create is a way in, since
     * link(2) works on socket inodes and would place another daemon's
     * socket inside the "allowed" directory. Allow-list the directory the
     * socket appears in — sockets created inside it later are matched by
     * prefix — not a socket path that does not exist yet. */
    fprintf(stderr,
            "sandbox: ignoring allowed unix socket path that does not exist: %s\n",
            buf);
}

/* seatbelt "subpath" semantics: the entry itself, or anything beneath it. */
static int path_allowed(const char *canon) {
    for (int i = 0; i < g_nallow; i++) {
        const char *a = g_allow[i];
        size_t al = strlen(a);
        if (strcmp(a, "/") == 0) return 1;
        if (strncmp(canon, a, al) == 0 && (canon[al] == '\0' || canon[al] == '/')) return 1;
    }
    return 0;
}

/* Kernel support for brokered mode: seccomp user notification with
 * SECCOMP_USER_NOTIF_FLAG_CONTINUE (5.5; probed the way libseccomp does,
 * via a same-era filter flag with a NULL prog) and pidfd_getfd (5.6). */
static int broker_supported(void) {
    if (SRT_AUDIT_ARCH == 0) return 0;
    if (!(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                  SECCOMP_FILTER_FLAG_TSYNC_ESRCH, NULL) == -1 &&
          errno == EFAULT)) {
        return 0;
    }
    if (syscall(__NR_pidfd_getfd, -1, -1, 0) == -1 && errno == ENOSYS) return 0;
    return 1;
}

#define OBS_WRITE_MASK ((unsigned)(O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND))
#define OBS_PATH_MAX 4096
#define OBS_LINE_CAP (OBS_PATH_MAX * 2 + 256)

/* Single source of truth for the observed-syscall set. The BPF program and
 * the supervisor's name/path-arg lookup are both derived from this table so
 * they cannot drift. flags_arg >= 0 means the BPF gates the trap on
 * args[flags_arg] & OBS_WRITE_MASK; -1 means always trap. */
struct observe_call {
    int nr;
    const char *name;
    int8_t path_arg;
    int8_t path2_arg;
    int8_t flags_arg;
    /* Argument index of the dirfd governing path_arg/path2_arg, or -1 when
     * the path is resolved against the caller's cwd (legacy entry points). */
    int8_t dirfd_arg;
    int8_t dirfd2_arg;
};

static const struct observe_call observe_calls[] = {
    { __NR_openat,     "openat",     1, -1,  2,  0, -1 },
#ifdef __NR_openat2
    { __NR_openat2,    "openat2",    1, -1, -1,  0, -1 },
#endif
    { __NR_unlinkat,   "unlinkat",   1, -1, -1,  0, -1 },
    { __NR_mkdirat,    "mkdirat",    1, -1, -1,  0, -1 },
    { __NR_mknodat,    "mknodat",    1, -1, -1,  0, -1 },
    { __NR_symlinkat,  "symlinkat",  2, -1, -1,  1, -1 },
    { __NR_linkat,     "linkat",     1,  3, -1,  0,  2 },
#ifdef __NR_renameat
    { __NR_renameat,   "renameat",   1,  3, -1,  0,  2 },
#endif
    { __NR_renameat2,  "renameat2",  1,  3, -1,  0,  2 },
    { __NR_fchmodat,   "fchmodat",   1, -1, -1,  0, -1 },
    { __NR_fchmodat2,  "fchmodat2",  1, -1, -1,  0, -1 },
    { __NR_fchownat,   "fchownat",   1, -1, -1,  0, -1 },
    { __NR_utimensat,  "utimensat",  1, -1, -1,  0, -1 },
#ifdef __x86_64__
    /* Legacy non-*at entry points: glibc/coreutils still call these directly
     * on x86_64. aarch64 only ever had the *at forms. */
    { __NR_open,       "open",       0, -1,  1, -1, -1 },
    { __NR_creat,      "creat",      0, -1, -1, -1, -1 },
    { __NR_unlink,     "unlink",     0, -1, -1, -1, -1 },
    { __NR_rmdir,      "rmdir",      0, -1, -1, -1, -1 },
    { __NR_rename,     "rename",     0,  1, -1, -1, -1 },
    { __NR_link,       "link",       0,  1, -1, -1, -1 },
    { __NR_symlink,    "symlink",    1, -1, -1, -1, -1 },
    { __NR_mkdir,      "mkdir",      0, -1, -1, -1, -1 },
    { __NR_mknod,      "mknod",      0, -1, -1, -1, -1 },
    { __NR_truncate,   "truncate",   0, -1, -1, -1, -1 },
    { __NR_chmod,      "chmod",      0, -1, -1, -1, -1 },
    { __NR_chown,      "chown",      0, -1, -1, -1, -1 },
    { __NR_lchown,     "lchown",     0, -1, -1, -1, -1 },
    { __NR_utime,      "utime",      0, -1, -1, -1, -1 },
    { __NR_utimes,     "utimes",     0, -1, -1, -1, -1 },
#endif
};
static const int n_observe_calls = (int)(sizeof(observe_calls)/sizeof(observe_calls[0]));

static const struct observe_call *find_observe_call(int nr) {
    for (int i = 0; i < n_observe_calls; i++)
        if (observe_calls[i].nr == nr) return &observe_calls[i];
    return NULL;
}

/* Emit "if (nr == NR) { BLOCK }". Every path through BLOCK must end in a
 * RET, so falling past it leaves the accumulator holding nr for the next
 * test. Jump distances come from the block's length, never hand-counted. */
static int emit_nr_block(struct sock_filter *f, int n, int cap, unsigned nr,
                         const struct sock_filter *blk, int len) {
    if (n < 0 || n + 1 + len > cap) return -1;
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0,
                                          (unsigned char)len);
    memcpy(&f[n], blk, (size_t)len * sizeof(*blk));
    return n + len;
}

#define BPF_RET_ERRNO(e) \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ((e) & SECCOMP_RET_DATA))
#define BPF_LD_ARG(i) \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, \
             offsetof(struct seccomp_data, args) + (size_t)(i) * sizeof(__u64))

/* Build the user-notification filter. `observe` adds the write-intent
 * filesystem traps; `broker` adds the unix-socket rules that replace the
 * baked-in block filter (see "Brokered unix connect"). The kernel permits
 * only one listener-bearing filter per task, so both live in this one
 * program and the supervisor dispatches on the syscall number. */
static int build_notify_bpf(struct sock_filter *f, int cap, int observe, int broker) {
    int n = 0;
#define EMIT(ins) do { if (n >= cap) return -1; f[n++] = (struct sock_filter)ins; } while (0)

    /* A foreign personality (x32 on x86_64) reaches the same syscall table
     * under different numbers, so in brokered mode an arch we did not build
     * the rules for must not slip past them. Observation alone is
     * diagnostic and stays fail-open. */
    const unsigned foreign = broker ? SECCOMP_RET_KILL_PROCESS : SECCOMP_RET_ALLOW;

    /* arch check */
    EMIT(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, arch)));
    EMIT(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SRT_AUDIT_ARCH, 1, 0));
    EMIT(BPF_STMT(BPF_RET | BPF_K, foreign));

    /* nr */
    EMIT(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, nr)));
#if SRT_HAS_X32
    EMIT(BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000u, 0, 1));
    EMIT(BPF_STMT(BPF_RET | BPF_K, foreign));
#endif

    if (broker) {
        static const struct sock_filter deny[] = { BPF_RET_ERRNO(EPERM) };
        static const struct sock_filter notify[] = {
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        };
        /* AF_UNIX stream/seqpacket may be created — their connect() is
         * mediated below. Datagram and raw may not: sendto()/sendmsg()
         * carry a destination path of their own that this filter does not
         * intercept. */
        static const struct sock_filter socket_unix[] = {
            BPF_LD_ARG(0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 1, 0),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_LD_ARG(1),
            BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xf),  /* strip SOCK_NONBLOCK|SOCK_CLOEXEC */
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SOCK_STREAM, 2, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SOCK_SEQPACKET, 1, 0),
            BPF_RET_ERRNO(EPERM),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        /* A connected AF_UNIX datagram socketpair end can still sendto() any
         * *bound* datagram receiver (journald, /dev/log, sd_notify) by path.
         * Stream and seqpacket pairs ignore msg_name, so only those two are
         * allowed — an allowlist, not a denylist, because unix_create() maps
         * SOCK_RAW onto SOCK_DGRAM and a denylist on SOCK_DGRAM alone leaves
         * SOCK_RAW as a way back to the same channel. */
        static const struct sock_filter socketpair_unix[] = {
            BPF_LD_ARG(0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 1, 0),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_LD_ARG(1),
            BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xf),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SOCK_STREAM, 2, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SOCK_SEQPACKET, 1, 0),
            BPF_RET_ERRNO(EPERM),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        /* THE load-bearing rule for brokering. When two filters in a chain
         * return USER_NOTIF for the same syscall, the notification goes to
         * the most recently installed one — so a workload that installs its
         * own listener filter for connect() and answers CONTINUE would run
         * the syscall unmediated. The kernel refuses a second listener in a
         * chain only while the first listener file is open, which makes the
         * supervisor's death a bypass window rather than a fail-closed
         * state. Denying SECCOMP_FILTER_FLAG_NEW_LISTENER outright is what
         * makes "no supervisor" mean ENOSYS. Nested filters without a
         * listener (the Chromium/renderer pattern, prctl(PR_SET_SECCOMP))
         * are unaffected; a nested sandbox that wants its own listener gets
         * EPERM and falls back to blocking unix sockets, which is the
         * conservative direction. */
        static const struct sock_filter seccomp_no_listener[] = {
            BPF_LD_ARG(0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECCOMP_SET_MODE_FILTER, 1, 0),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_LD_ARG(1),
            BPF_STMT(BPF_ALU | BPF_AND | BPF_K, SECCOMP_FILTER_FLAG_NEW_LISTENER),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
            BPF_RET_ERRNO(EPERM),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        /* Defense in depth for the same boundary: nothing inside the sandbox
         * may answer a notification even if a listener fd somehow reaches it.
         * The whole '!' ioctl type is seccomp's (RECV/SEND/ID_VALID/ADDFD/
         * SET_FLAGS and any future member), so denying the type covers the
         * extensible ioctls without tracking their sizes. */
        static const struct sock_filter ioctl_no_seccomp_notif[] = {
            BPF_LD_ARG(1),
            BPF_STMT(BPF_ALU | BPF_RSH | BPF_K, _IOC_TYPESHIFT),
            BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xff),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECCOMP_IOC_MAGIC, 0, 1),
            BPF_RET_ERRNO(EPERM),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        /* io_uring can issue IORING_OP_CONNECT/IORING_OP_SOCKET without ever
         * entering the syscalls above; the baked-in filter denies these three
         * for the same reason, so brokered mode keeps that parity. */
        static const int io_uring_nrs[] = {
            __NR_io_uring_setup, __NR_io_uring_enter, __NR_io_uring_register,
        };
        for (size_t i = 0; i < sizeof(io_uring_nrs)/sizeof(io_uring_nrs[0]); i++) {
            n = emit_nr_block(f, n, cap, (unsigned)io_uring_nrs[i],
                              deny, (int)(sizeof(deny)/sizeof(deny[0])));
        }
        n = emit_nr_block(f, n, cap, __NR_socket, socket_unix,
                          (int)(sizeof(socket_unix)/sizeof(socket_unix[0])));
        n = emit_nr_block(f, n, cap, __NR_socketpair, socketpair_unix,
                          (int)(sizeof(socketpair_unix)/sizeof(socketpair_unix[0])));
        n = emit_nr_block(f, n, cap, __NR_seccomp, seccomp_no_listener,
                          (int)(sizeof(seccomp_no_listener)/sizeof(seccomp_no_listener[0])));
        n = emit_nr_block(f, n, cap, __NR_ioctl, ioctl_no_seccomp_notif,
                          (int)(sizeof(ioctl_no_seccomp_notif)/sizeof(ioctl_no_seccomp_notif[0])));
        /* connect()/bind()/listen() are trapped for EVERY address family —
         * see "Brokered unix connect" for why inspecting and continuing is
         * not an option, and therefore why the supervisor must perform even
         * the uninteresting inet calls itself. listen() is trapped because
         * a unix socket can acquire an abstract name without bind(): the
         * kernel autobinds one when SO_PASSCRED is set and a connect fails,
         * leaving a listenable endpoint that bind() policy never saw. */
        n = emit_nr_block(f, n, cap, __NR_connect, notify,
                          (int)(sizeof(notify)/sizeof(notify[0])));
        n = emit_nr_block(f, n, cap, __NR_bind, notify,
                          (int)(sizeof(notify)/sizeof(notify[0])));
        n = emit_nr_block(f, n, cap, __NR_listen, notify,
                          (int)(sizeof(notify)/sizeof(notify[0])));
        if (n < 0) return -1;
    }

    /* Always-trap syscalls (flags_arg < 0). */
    int j_trap[64], ntrap = 0;
    for (int i = 0; observe && i < n_observe_calls; i++) {
        if (observe_calls[i].flags_arg >= 0) continue;
        j_trap[ntrap++] = n;
        EMIT(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                      (unsigned)observe_calls[i].nr, 0, 0));         /* jt→NOTIFY */
    }

    /* Flags-gated syscalls: trap only when args[flags_arg] & OBS_WRITE_MASK.
     * Each gated syscall emits a 4-instruction block; jf of the JEQ chains to
     * the next block, last chains to ALLOW. After the flags load the
     * accumulator no longer holds nr, so a non-match must reload nr — handled
     * by chaining JEQ jf directly past the load. */
    struct { int jeq, jflags; } gated[4];
    int ngated = 0;
    for (int i = 0; observe && i < n_observe_calls; i++) {
        if (observe_calls[i].flags_arg < 0) continue;
        gated[ngated].jeq = n;
        EMIT(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                      (unsigned)observe_calls[i].nr, 0, 0));         /* jf→next gated / ALLOW */
        EMIT(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                      offsetof(struct seccomp_data, args) +
                      (size_t)observe_calls[i].flags_arg * sizeof(__u64)));
        EMIT(BPF_STMT(BPF_ALU | BPF_AND | BPF_K, OBS_WRITE_MASK));
        gated[ngated].jflags = n;
        EMIT(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 0));          /* jt→ALLOW jf→NOTIFY */
        ngated++;
    }

    int allow_at = n;
    EMIT(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    int notify_at = n;
    EMIT(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF));

#define TO(idx, tgt) ((unsigned char)((tgt) - (idx) - 1))
    for (int i = 0; i < ntrap; i++) f[j_trap[i]].jt = TO(j_trap[i], notify_at);
    for (int i = 0; i < ngated; i++) {
        int next = (i + 1 < ngated) ? gated[i + 1].jeq : allow_at;
        f[gated[i].jeq].jf    = TO(gated[i].jeq, next);
        f[gated[i].jflags].jt = TO(gated[i].jflags, allow_at);
        f[gated[i].jflags].jf = TO(gated[i].jflags, notify_at);
    }
#undef TO
#undef EMIT
    return n;
}

/* Send a single fd over a connected stream socket via SCM_RIGHTS. */
static int send_fd(int sock, int fd) {
    char dummy = 'F';
    union { struct cmsghdr align; char ctl[CMSG_SPACE(sizeof(int))]; } u;
    memset(&u, 0, sizeof(u));
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
    struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
                          .msg_control = u.ctl, .msg_controllen = sizeof(u.ctl) };
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &fd, sizeof(int));
    return sendmsg(sock, &msg, 0) < 0 ? -1 : 0;
}

/* Receive at most one fd. Returns the fd, or -1 if the peer sent no fd or
 * closed (worker declined to install the filter). */
static int recv_fd(int sock) {
    char dummy;
    union { struct cmsghdr align; char ctl[CMSG_SPACE(sizeof(int))]; } u;
    memset(&u, 0, sizeof(u));
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
    struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
                          .msg_control = u.ctl, .msg_controllen = sizeof(u.ctl) };
    ssize_t r = recvmsg(sock, &msg, 0);
    if (r <= 0) return -1;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS &&
            c->cmsg_len >= CMSG_LEN(sizeof(int))) {
            int fd; memcpy(&fd, CMSG_DATA(c), sizeof(int));
            return fd;
        }
    }
    return -1;
}

/* Called in the WORKER after PR_SET_NO_NEW_PRIVS. Installs the USER_NOTIF
 * filter and ships the listener fd to the outer stub over the pre-fork
 * socketpair. Never fatal: any pre-filter failure sends a no-fd marker and
 * returns; any post-filter failure raw-writes a diagnostic and _exit()s
 * (continuing would either wedge on the next matched syscall or leave a
 * filter with no listener, which makes matched syscalls fail ENOSYS).
 *
 * Audited syscalls between the seccomp() return and execve():
 *   sendmsg, close, close, prctl(PR_SET_SECCOMP), execve
 * None are in the observe match set (write-intent fs) and none are
 * in the unix-block set (socket(AF_UNIX)/io_uring), so the worker cannot
 * trap on itself before exec. perror()/snprintf() are deliberately avoided
 * post-filter to keep this set closed. */
static int install_notify_filter(int sp_fd, int observe, int broker) {
    if (sp_fd < 0) return -1;

    /* The supervisor replies with SECCOMP_USER_NOTIF_FLAG_CONTINUE, which
     * kernels older than 5.5 reject with EINVAL *without* completing the
     * notification — the trapped syscall would block forever. CONTINUE is
     * a response flag with no direct probe, so detect it the way
     * libseccomp does: validate a filter flag from the same era with a
     * NULL prog. EFAULT = flag known (nothing installed), EINVAL = too
     * old — skip the observer entirely and stay fail-open. */
    if (!(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                  SECCOMP_FILTER_FLAG_TSYNC_ESRCH, NULL) == -1 &&
          errno == EFAULT)) {
        (void)!write(sp_fd, "E", 1);
        close(sp_fd);
        return -1;
    }

    struct sock_filter filt[128];
    int len = build_notify_bpf(filt, (int)(sizeof(filt)/sizeof(filt[0])),
                               observe, broker);
    if (len < 0) { (void)!write(sp_fd, "E", 1); close(sp_fd); return -1; }
    struct sock_fprog prog = { .len = (unsigned short)len, .filter = filt };

    int nfd = (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                           SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (nfd < 0) {
        /* EINVAL: kernel <5.0. EBUSY: another listener already installed.
         * Either way, no filter is active — the caller falls back (observe:
         * skipped; broker: the baked-in unix-block filter). */
        (void)!write(sp_fd, "E", 1);
        close(sp_fd);
        return -1;
    }

    /* --- filter is now live --- */
    if (send_fd(sp_fd, nfd) < 0) {
        static const char msg[] = "apply-seccomp: notify sendmsg failed\n";
        (void)!write(2, msg, sizeof(msg) - 1);
        _exit(125);
    }
    close(sp_fd);
    close(nfd);   /* outer stub now holds the only reference */
    return 0;
}

/* ---- Outer-stub supervisor --------------------------------------------- */

static void json_escape_into(char *dst, size_t dstcap, const char *src, size_t srclen) {
    static const char hex[] = "0123456789abcdef";
    size_t o = 0;
    for (size_t i = 0; i < srclen && o + 7 < dstcap; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\') { dst[o++]='\\'; dst[o++]=(char)c; }
        else if (c < 0x20)         { dst[o++]='\\'; dst[o++]='u'; dst[o++]='0'; dst[o++]='0';
                                     dst[o++]=hex[c>>4]; dst[o++]=hex[c&0xf]; }
        else                       { dst[o++]=(char)c; }
    }
    dst[o] = '\0';
}

static ssize_t read_remote_bytes(pid_t pid, unsigned long addr, char *dst, size_t cap) {
    if (addr == 0) return -1;
    struct iovec local  = { .iov_base = dst, .iov_len = cap };
    struct iovec remote = { .iov_base = (void *)addr, .iov_len = cap };
    return process_vm_readv(pid, &local, 1, &remote, 1, 0);
}

static ssize_t read_remote_cstr(pid_t pid, unsigned long addr, char *dst, size_t cap) {
    ssize_t r = read_remote_bytes(pid, addr, dst, cap);
    if (r < 0 && errno == EFAULT) {
        /* String may sit at the tail of a mapping. */
        size_t first = 4096 - (addr & 4095);
        if (first > cap) first = cap;
        r = read_remote_bytes(pid, addr, dst, first);
    }
    if (r <= 0) return -1;
    char *nul = memchr(dst, '\0', (size_t)r);
    return nul ? (nul - dst) : r;
}

/* Resolve a relative path against the tracee's cwd or dirfd via the /proc
 * magic symlinks. The tracee is frozen inside the trapped syscall, so both
 * links are stable for single-threaded callers; a racing sibling thread can
 * at worst mislabel one LOG line (this channel never enforces anything).
 *
 * host_proc_fd is an O_PATH handle to /proc opened BEFORE the pid/mount
 * unshare: the worker later mounts a fresh /proc for the new pid namespace
 * into the mount namespace this process shares with it, which removes the
 * host-pid entries from the PATH "/proc" — but the held fd pins the
 * original superblock, and the notification's pid is a host-namespace pid.
 *
 * Returns the joined length, or 0 on ANY failure — the caller then skips
 * the event entirely (best-effort telemetry: never guess, never block).
 * `req` may be NULL when dirfd_arg < 0 (the cwd case). */
static size_t resolve_relative(int host_proc_fd, pid_t pid,
                               const struct seccomp_notif *req,
                               int dirfd_arg, const char *rel, size_t rellen,
                               char *dst, size_t dstcap) {
    if (host_proc_fd < 0) return 0;
    char link[64];
    /* The dirfd syscall argument is an int; the kernel exposes the raw
     * 64-bit register, so AT_FDCWD arrives zero-extended. Truncate. */
    int dirfd = dirfd_arg >= 0 ? (int)(uint32_t)req->data.args[dirfd_arg]
                               : AT_FDCWD;
    int n;
    if (dirfd == AT_FDCWD) {
        n = snprintf(link, sizeof(link), "%d/cwd", (int)pid);
    } else {
        if (dirfd < 0) return 0;  /* junk fd value */
        n = snprintf(link, sizeof(link), "%d/fd/%d", (int)pid, dirfd);
    }
    if (n <= 0 || (size_t)n >= sizeof(link)) return 0;
    ssize_t bl = readlinkat(host_proc_fd, link, dst, dstcap - 1);
    if (bl <= 0) return 0;              /* pid gone, fd closed, EACCES... */
    if (dst[0] != '/') return 0;        /* memfd:/pipe:/socket: pseudo-name */
    if ((size_t)bl + 1 + rellen + 1 > dstcap) return 0;  /* would truncate */
    size_t o = (size_t)bl;
    dst[o++] = '/';
    memcpy(dst + o, rel, rellen);
    o += rellen;
    dst[o] = '\0';
    return o;
}

/* ---- Brokered unix connect ---------------------------------------------
 *
 * Why the supervisor performs connect()/bind() itself and NEVER answers
 * SECCOMP_USER_NOTIF_FLAG_CONTINUE for them: BPF sees only an fd number and
 * a userspace pointer. Both the address family (in the socket object) and
 * the target path (in the caller's memory) can be changed by a sibling
 * thread between the supervisor's inspection and the kernel's re-execution
 * of the syscall — rewrite the sockaddr, or dup2() an AF_UNIX socket over
 * the inspected AF_INET fd. Inspect-then-continue is therefore racy by
 * construction. Instead the supervisor takes its own reference to the
 * socket (pidfd_getfd, which shares the open file description, so
 * O_NONBLOCK/EINPROGRESS semantics and the resulting connection are the
 * caller's), its own copy of the sockaddr (process_vm_readv, with
 * SECCOMP_IOCTL_NOTIF_ID_VALID as the pid-reuse guard), decides on those,
 * and performs the call. Nothing the workload can still touch is consulted
 * after the decision.
 *
 * Because every connect()/bind() must reach the supervisor for that to
 * hold, inet calls are brokered too — they are simply performed as-is
 * (the stub shares the workload's network and mount namespaces).
 *
 * Residual, by design: anything that can create a socket inside an
 * allow-listed directory can be connected to, so allow-listed directories
 * must not be writable by the sandbox. The final-component swap race is
 * eliminated (not merely narrowed) by connecting through a pinned O_PATH
 * handle rather than by re-walking the path.
 */

/* Path of the supervisor's own fd magic link, for connect()ing through a
 * pinned inode. The worker mounts a fresh /proc for the inner pid namespace
 * into the mount namespace the stub shares with it, so the path "/proc" no
 * longer shows the stub itself; the stub's cwd is the pinned procfs instead
 * (see broker_init) and a relative sun_path resolves against it. */
static void fd_link_path(char *buf, size_t cap, int fd) {
    if (g_fdcwd_ok) snprintf(buf, cap, "self/fd/%d", fd);
    else snprintf(buf, cap, "/proc/self/fd/%d", fd);
}

static void broker_init(int host_proc_fd) {
    g_fdcwd_ok = host_proc_fd >= 0 && fchdir(host_proc_fd) == 0;
}

/* seccomp_notif.pid is a *thread* id. Plain pidfd_open() only accepts thread
 * group leaders, so try PIDFD_THREAD (6.9+) and fall back to the thread's
 * Tgid (the fd table is per-process anyway). The caller validates the
 * notification id afterwards, which proves the tid — and therefore its
 * process — has not been recycled. */
static int open_task_pidfd(int host_proc_fd, pid_t tid) {
    int fd = (int)syscall(__NR_pidfd_open, tid, 0);
    if (fd >= 0) return fd;
    fd = (int)syscall(__NR_pidfd_open, tid, PIDFD_THREAD);
    if (fd >= 0) return fd;
    if (host_proc_fd < 0) { errno = ESRCH; return -1; }
    char rel[64], line[256];
    snprintf(rel, sizeof(rel), "%d/status", (int)tid);
    int sfd = openat(host_proc_fd, rel, O_RDONLY | O_CLOEXEC);
    if (sfd < 0) return -1;
    FILE *f = fdopen(sfd, "r");
    if (!f) { close(sfd); return -1; }
    pid_t tgid = -1;
    while (fgets(line, sizeof(line), f))
        if (sscanf(line, "Tgid: %d", &tgid) == 1) break;
    fclose(f);
    if (tgid <= 0) { errno = ESRCH; return -1; }
    return (int)syscall(__NR_pidfd_open, tgid, 0);
}

static int notif_alive(int notify_fd, __u64 id) {
    return ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == 0;
}

/* Log each distinct denied path once (bounded), so a hot loop cannot flood
 * the workload's stderr. */
static void log_denied_connect(const char *path) {
    static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
    static char seen[32][PATH_MAX];
    static int nseen;
    pthread_mutex_lock(&mu);
    for (int i = 0; i < nseen; i++) {
        if (strcmp(seen[i], path) == 0) { pthread_mutex_unlock(&mu); return; }
    }
    if (nseen < 32) {
        /* The path came from the sandboxed process: print it with control
         * characters folded so it cannot forge lines on the shared stderr. */
        char safe[PATH_MAX];
        size_t i = 0;
        for (; path[i] && i < sizeof(safe) - 1; i++) {
            unsigned char c = (unsigned char)path[i];
            safe[i] = (c < 0x20 || c == 0x7f) ? '?' : (char)c;
        }
        safe[i] = '\0';
        snprintf(seen[nseen++], PATH_MAX, "%s", path);
        fprintf(stderr,
                "sandbox: denied connection to unix socket %s "
                "(not in the allowed unix socket paths)\n", safe);
    }
    pthread_mutex_unlock(&mu);
}

/* Decide and perform an AF_UNIX connect on `sock` (the caller's socket).
 * Returns 0, or -errno to hand back to the caller. */
static int broker_unix_connect(int sock, pid_t pid, int host_proc_fd,
                               const struct sockaddr_un *sun, socklen_t len) {
    if (len <= (socklen_t)offsetof(struct sockaddr_un, sun_path) ||
        len > (socklen_t)sizeof(*sun)) {
        return -EINVAL;
    }
    if (sun->sun_family != AF_UNIX) return -EINVAL;   /* unix_validate_addr() */
    /* Abstract namespace: no path to match against, and abstract sockets are
     * per-network-namespace anyway under --unshare-net. */
    if (sun->sun_path[0] == '\0') return -EPERM;

    /* sun_path need not be NUL-terminated; it is bounded by len. */
    size_t plen = strnlen(sun->sun_path,
                          (size_t)len - offsetof(struct sockaddr_un, sun_path));
    char raw[PATH_MAX], canon[PATH_MAX];
    if (sun->sun_path[0] == '/') {
        if (plen >= sizeof(raw)) return -ENAMETOOLONG;
        snprintf(raw, sizeof(raw), "%.*s", (int)plen, sun->sun_path);
    } else {
        /* Relative: resolve against the CALLER's cwd, not the stub's. */
        if (resolve_relative(host_proc_fd, pid, NULL, -1, sun->sun_path, plen,
                             raw, sizeof(raw)) == 0) {
            return -EPERM;
        }
    }

    /* realpath() reports existence/type of arbitrary paths through errno,
     * but so does an unbrokered connect(), and the stub shares the caller's
     * mount namespace, so nothing new is exposed. */
    if (!realpath(raw, canon)) return -errno;
    if (!path_allowed(canon)) {
        log_denied_connect(canon);
        return -EPERM;
    }

    /* Pin the inode: O_PATH|O_NOFOLLOW takes a handle on whatever sits at
     * the canonical path right now. Verify it is a socket and that the
     * kernel still places that handle at the allowed path, then connect
     * THROUGH the handle — /proc/<self>/fd/N is a magic link to the pinned
     * dentry, not a path walk — so a symlink or rename swap after the check
     * cannot redirect the connect. */
    int pfd = open(canon, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (pfd < 0) return -errno;
    char link[64], now[PATH_MAX];
    struct stat st;
    int ret;
    fd_link_path(link, sizeof(link), pfd);
    if (fstat(pfd, &st) < 0) { ret = -errno; goto out; }
    if (!S_ISSOCK(st.st_mode)) { ret = -ECONNREFUSED; goto out; }  /* as the kernel does */
    ssize_t k = readlink(link, now, sizeof(now) - 1);
    if (k < 0) { ret = -errno; goto out; }
    now[k] = '\0';
    /* Judge where the pinned inode actually lives now, not whether it moved:
     * a daemon that publishes its socket by renaming a temporary name into
     * place inside the allowed directory is a normal pattern, and the
     * security-relevant question is only whether the destination is still
     * allowed. */
    if (!path_allowed(now)) {   /* lost a race: refuse */
        log_denied_connect(now);
        ret = -EPERM;
        goto out;
    }
    struct sockaddr_un via;
    memset(&via, 0, sizeof(via));
    via.sun_family = AF_UNIX;
    if (strlen(link) >= sizeof(via.sun_path)) { ret = -ENAMETOOLONG; goto out; }
    snprintf(via.sun_path, sizeof(via.sun_path), "%s", link);
    ret = connect(sock, (struct sockaddr *)&via, sizeof(via)) < 0 ? -errno : 0;
out:
    close(pfd);
    return ret;
}

/* The syscalls the brokered filter traps. Must match the notify blocks in
 * build_notify_bpf(): a trapped syscall missing from here would be answered
 * on the observation path — with CONTINUE, which is exactly what brokering
 * must never do. */
static int is_brokered_nr(int nr) {
    return nr == __NR_connect || nr == __NR_bind || nr == __NR_listen;
}

/* Perform one trapped connect()/bind()/listen() on the caller's behalf.
 * Returns 0 or -errno; never asks the kernel to re-run the syscall. */
static int broker_handle(int notify_fd, int host_proc_fd,
                         const struct seccomp_notif *rq) {
    int nr = (int)rq->data.nr;
    int is_connect = nr == __NR_connect;
    int is_listen = nr == __NR_listen;
    int targetfd = (int)(uint32_t)rq->data.args[0];
    long addrlen = is_listen ? 0 : (long)(int)(uint32_t)rq->data.args[2];
    pid_t pid = (pid_t)rq->pid;

    if (addrlen < 0 || (size_t)addrlen > sizeof(struct sockaddr_storage)) return -EINVAL;

    int pidfd = open_task_pidfd(host_proc_fd, pid);
    if (pidfd < 0) return -ESRCH;
    /* The notification still being live proves the task is blocked in this
     * very syscall, hence its pid was not recycled and pidfd is the caller. */
    if (!notif_alive(notify_fd, rq->id)) { close(pidfd); return -ESRCH; }

    int sock = (int)syscall(__NR_pidfd_getfd, pidfd, targetfd, 0);
    if (sock < 0) {
        int e = errno;
        close(pidfd);
        if (e == EPERM) {
            static int warned;
            if (!__atomic_exchange_n(&warned, 1, __ATOMIC_RELAXED)) {
                fprintf(stderr,
                        "apply-seccomp: cannot reach the sandboxed process's "
                        "sockets (ptrace access denied) - denying socket "
                        "connections\n");
            }
            return -EPERM;
        }
        return e == EBADF ? -EBADF : -ESRCH;
    }
    close(pidfd);

    int ret, dom;
    socklen_t ol = sizeof(dom);
    if (getsockopt(sock, SOL_SOCKET, SO_DOMAIN, &dom, &ol) < 0) { ret = -ENOTSOCK; goto out; }

    union {
        struct sockaddr sa;
        struct sockaddr_un un;
        struct sockaddr_storage ss;
    } a;
    memset(&a, 0, sizeof(a));
    if (addrlen > 0) {
        struct iovec liov = { .iov_base = &a, .iov_len = (size_t)addrlen };
        struct iovec riov = { .iov_base = (void *)(uintptr_t)rq->data.args[1],
                              .iov_len = (size_t)addrlen };
        if (process_vm_readv(pid, &liov, 1, &riov, 1, 0) != addrlen) {
            ret = -EFAULT;
            goto out;
        }
    }
    /* process_vm_readv addressed the task by pid; re-check it is still ours. */
    if (!notif_alive(notify_fd, rq->id)) { ret = -ESRCH; goto out; }

    if (dom != AF_UNIX) {
        int r;
        if (is_listen) r = listen(sock, (int)(uint32_t)rq->data.args[1]);
        else if (is_connect) r = connect(sock, &a.sa, (socklen_t)addrlen);
        else r = bind(sock, &a.sa, (socklen_t)addrlen);
        ret = r < 0 ? -errno : 0;
    } else if (!is_connect) {
        /* No listening unix endpoints inside the sandbox: bind() is refused,
         * and so is listen() on a socket the kernel autobound into the
         * abstract namespace behind bind()'s back. */
        ret = -EPERM;
    } else {
        ret = broker_unix_connect(sock, pid, host_proc_fd, &a.un, (socklen_t)addrlen);
    }
out:
    close(sock);
    return ret;
}

struct broker_job {
    int notify_fd;
    int host_proc_fd;
    struct seccomp_notif *req;
    size_t resp_size;
};

/* Cap on brokered calls in flight. A workload can park an unbounded number
 * of blocking connects (a listener with a full backlog, a blackholed
 * address); each costs a thread here, so past the cap callers are answered
 * -EAGAIN instead. Well past what any real workload connects in parallel. */
#define BROKER_MAX_INFLIGHT 128
static int g_broker_inflight;

/* One detached thread per brokered call so a slow inet connect() cannot
 * head-of-line block unrelated callers. */
static void *broker_thread(void *arg) {
    struct broker_job *j = arg;
    struct seccomp_notif_resp *resp = calloc(1, j->resp_size);
    int r = broker_handle(j->notify_fd, j->host_proc_fd, j->req);
    if (resp) {
        resp->id = j->req->id;
        resp->error = r;
        resp->val = 0;
        resp->flags = 0;   /* never CONTINUE: see "Brokered unix connect" */
        if (ioctl(j->notify_fd, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0 &&
            errno != ENOENT) {
            /* nothing to do: the caller is gone or was interrupted */
        }
        free(resp);
    }
    free(j->req);
    free(j);
    __atomic_sub_fetch(&g_broker_inflight, 1, __ATOMIC_RELAXED);
    return NULL;
}

/* Copy one connect()/bind() notification onto a detached thread. On any
 * allocation failure the caller is answered -ENOMEM rather than left
 * blocked; the notification is never continued into the kernel. */
static void answer_now(int notify_fd, struct seccomp_notif_resp *resp,
                       size_t resp_size, __u64 id, int err) {
    memset(resp, 0, resp_size);
    resp->id = id;
    resp->error = err;
    (void)ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, resp);
}

static void dispatch_broker(int notify_fd, int host_proc_fd,
                            const struct seccomp_notif *req,
                            struct seccomp_notif_resp *resp,
                            size_t req_size, size_t resp_size) {
    if (__atomic_add_fetch(&g_broker_inflight, 1, __ATOMIC_RELAXED) >
        BROKER_MAX_INFLIGHT) {
        __atomic_sub_fetch(&g_broker_inflight, 1, __ATOMIC_RELAXED);
        answer_now(notify_fd, resp, resp_size, req->id, -EAGAIN);
        return;
    }

    struct broker_job *j = calloc(1, sizeof(*j));
    struct seccomp_notif *copy = j ? malloc(req_size) : NULL;
    if (!j || !copy) {
        free(j);
        free(copy);
        __atomic_sub_fetch(&g_broker_inflight, 1, __ATOMIC_RELAXED);
        answer_now(notify_fd, resp, resp_size, req->id, -ENOMEM);
        return;
    }
    memcpy(copy, req, req_size);
    j->notify_fd = notify_fd;
    j->host_proc_fd = host_proc_fd;
    j->req = copy;
    j->resp_size = resp_size;

    pthread_t t;
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&at, 256 * 1024);
    /* Workers must not take the stub's signals: a SIGCHLD landing on one
     * would surface as a spurious EINTR from a brokered blocking connect,
     * or lose a NOTIF_SEND and leave the caller blocked forever. */
    sigset_t all, saved;
    sigfillset(&all);
    pthread_sigmask(SIG_SETMASK, &all, &saved);
    int rc = pthread_create(&t, &at, broker_thread, j);
    pthread_sigmask(SIG_SETMASK, &saved, NULL);
    pthread_attr_destroy(&at);
    if (rc != 0) {
        /* Never service the call on this thread: that is the only thread
         * receiving notifications, and one blocking connect on it would
         * stall every other sandboxed process. */
        free(j->req);
        free(j);
        __atomic_sub_fetch(&g_broker_inflight, 1, __ATOMIC_RELAXED);
        answer_now(notify_fd, resp, resp_size, req->id, -EAGAIN);
    }
}

static void emit_event(int out, const struct observe_call *oc, int nr, pid_t pid,
                       const char *path, size_t pathlen, const char *enc) {
    if (out < 0) return;
    char esc[OBS_LINE_CAP];
    json_escape_into(esc, sizeof(esc), path, pathlen);
    char line[OBS_LINE_CAP + 512];
    int n;
    if (enc && *enc) {
        n = snprintf(line, sizeof(line),
                     "{\"nr\":%d,\"syscall\":\"%s\",\"pid\":%d,\"path\":\"%s\","
                     "\"encodedCommand\":\"%s\"}\n",
                     nr, oc ? oc->name : "syscall", (int)pid, esc, enc);
    } else {
        n = snprintf(line, sizeof(line),
                     "{\"nr\":%d,\"syscall\":\"%s\",\"pid\":%d,\"path\":\"%s\"}\n",
                     nr, oc ? oc->name : "syscall", (int)pid, esc);
    }
    /* Never wait on the consumer: the pipe is a bounded queue and this
     * channel is best-effort — full pipe drops the note (a short write
     * corrupts at most one line, which the listener already ignores). */
    if (n > 0) {
        (void)!send(out, line,
                    (size_t)(n < (int)sizeof(line) ? n : (int)sizeof(line)-1),
                    MSG_DONTWAIT | MSG_NOSIGNAL);
    }
}

static int connect_observe_sock(const char *path) {
    if (!path || !*path) return -1;
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) return -1;
    struct sockaddr_un sa = { .sun_family = AF_UNIX };
    if (strlen(path) >= sizeof(sa.sun_path)) {
        close(s); errno = ENAMETOOLONG; return -1;
    }
    strcpy(sa.sun_path, path);
    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(s); return -1; }
    /* Don't take SIGPIPE if Node drops the connection mid-run. */
    signal(SIGPIPE, SIG_IGN);
    return s;
}

/* Connect the observation channel and announce which command this instance
 * is running, so the listener can attribute what follows. Returns -1 when
 * observation is off or the listener is unreachable — every caller treats
 * that as "no observation", never as a failure. */
static int open_observe_channel(const char *sock, const char *enc) {
    if (!sock || !*sock) return -1;
    int out = connect_observe_sock(sock);
    if (out < 0) {
        char buf[256];
        int n = snprintf(buf, sizeof(buf),
                         "{\"observe_init_error\":\"connect %s: %s\"}\n",
                         sock, strerror(errno));
        if (n > 0) (void)!write(2, buf, (size_t)n);
        return -1;
    }
    if (enc && *enc) {
        char hdr[768];
        int n = snprintf(hdr, sizeof(hdr),
                         "{\"encodedCommand\":\"%.700s\"}\n", enc);
        if (n > 0) (void)!send(out, hdr, (size_t)n, MSG_DONTWAIT | MSG_NOSIGNAL);
    }
    return out;
}

/* Service the notify fd until the inner-init child exits. Runs in the OUTER
 * STUB, which never installed either seccomp filter. Observed filesystem
 * calls always get CONTINUE, even when out_sock < 0, so a missing listener
 * never wedges the workload; brokered connect()/bind() (when an allowlist is
 * configured) are answered with a result the stub produced itself and never
 * with CONTINUE. */
static void supervise(pid_t child, int notify_fd, int out_sock,
                      const char *enc, int host_proc_fd) {
    struct seccomp_notif_sizes sz;
    if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sz) < 0) {
        sz.seccomp_notif = sizeof(struct seccomp_notif);
        sz.seccomp_notif_resp = sizeof(struct seccomp_notif_resp);
    }
    struct seccomp_notif *req = calloc(1, sz.seccomp_notif);
    struct seccomp_notif_resp *resp = calloc(1, sz.seccomp_notif_resp);
    char *pbuf = malloc(OBS_PATH_MAX);
    char *fbuf1 = malloc(OBS_PATH_MAX * 2);
    char *fbuf2 = malloc(OBS_PATH_MAX * 2);
    if (!req || !resp || !pbuf || !fbuf1 || !fbuf2) return;

    /* `child` <= 0 means the caller is the standalone broker supervisor: it
     * has no child to watch and stops when the last filtered task is gone
     * (POLLHUP on the listener). */
    int pidfd = child > 0 ? (int)syscall(__NR_pidfd_open, child, 0) : -1;

    struct pollfd pfds[2];
    pfds[0].fd = notify_fd; pfds[0].events = POLLIN;
    pfds[1].fd = pidfd;     pfds[1].events = POLLIN;
    nfds_t nfds = pidfd >= 0 ? 2 : 1;
    int tmo = pidfd >= 0 || child <= 0 ? -1 : 200;

    for (;;) {
        int pr = poll(pfds, nfds, tmo);
        if (pr < 0) { if (errno == EINTR) continue; break; }

        if (pfds[0].revents & POLLIN) {
            memset(req, 0, sz.seccomp_notif);
            if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, req) == 0) {
                if (g_broker && is_brokered_nr(req->data.nr)) {
                    dispatch_broker(notify_fd, host_proc_fd, req, resp,
                                    sz.seccomp_notif, sz.seccomp_notif_resp);
                } else {
                    const struct observe_call *oc = find_observe_call(req->data.nr);
                    /* Capture while the caller is frozen (its memory, cwd and
                     * dirfds are stable), but EMIT only after the reply: the
                     * workload's pause must contain no work besides this
                     * capture — never a pipe write. */
                    size_t flen[2] = { 0, 0 };
                    if (oc && out_sock >= 0 &&
                        ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &req->id) == 0) {
                        int idxs[2]   = { oc->path_arg,  oc->path2_arg  };
                        int dirfds[2] = { oc->dirfd_arg, oc->dirfd2_arg };
                        for (int k = 0; k < 2; k++) {
                            if (idxs[k] < 0) continue;
                            char *out = k == 0 ? fbuf1 : fbuf2;
                            ssize_t l = read_remote_cstr(req->pid,
                                          (unsigned long)req->data.args[idxs[k]],
                                          pbuf, OBS_PATH_MAX);
                            if (l <= 0) continue;
                            if (pbuf[0] == '/') {
                                memcpy(out, pbuf, (size_t)l);
                                flen[k] = (size_t)l;
                                continue;
                            }
                            /* Relative: resolve against the tracee's cwd or
                             * dirfd. Unresolvable → skip (best effort). */
                            flen[k] = resolve_relative(host_proc_fd,
                                         req->pid, req, dirfds[k],
                                         pbuf, (size_t)l, out, OBS_PATH_MAX * 2);
                        }
                    }
                    memset(resp, 0, sz.seccomp_notif_resp);
                    resp->id = req->id;
                    resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                    (void)ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, resp);
                    for (int k = 0; k < 2; k++) {
                        if (flen[k] > 0) {
                            emit_event(out_sock, oc, req->data.nr, req->pid,
                                       k == 0 ? fbuf1 : fbuf2, flen[k], enc);
                        }
                    }
                }
            } else if (errno != EINTR && errno != ENOENT) {
                break;
            }
        }
        /* All filtered tasks gone → notify fd reports EOF. */
        if (pfds[0].revents & (POLLHUP | POLLERR)) break;

        if (child <= 0) {
            continue;   /* no child of ours; POLLHUP above is the exit */
        } else if (pidfd >= 0) {
            if (pfds[1].revents) break;
        } else {
            /* WNOWAIT: leave the zombie for the caller's waitpid. */
            siginfo_t si = {0};
            if (waitid(P_PID, (id_t)child, &si, WEXITED|WNOHANG|WNOWAIT) == 0 &&
                si.si_pid == child) break;
        }
    }

    if (pidfd >= 0) close(pidfd);
    free(req); free(resp); free(pbuf); free(fbuf1); free(fbuf2);
}

static void die(const char *msg) {
    perror(msg);
    _exit(1);
}

static int write_file(const char *path, const char *fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (len < 0 || (size_t)len >= sizeof(buf)) {
        errno = EOVERFLOW;
        return -1;
    }

    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        return -1;
    }
    ssize_t r = write(fd, buf, (size_t)len);
    int saved = errno;
    close(fd);
    if (r != len) {
        errno = (r < 0) ? saved : EIO;
        return -1;
    }
    return 0;
}

/* PID the current process forwards signals to. Used by both the outer stub
 * (forwards to inner init) and the inner init (forwards to the worker).
 * PID 1 ignores signals it has no handler for, so the inner init MUST install
 * these or SIGTERM from the outside is silently dropped. */
static volatile pid_t forward_target = -1;

static void forward_signal(int sig) {
    if (forward_target > 0) {
        kill(forward_target, sig);
    }
}

static void install_forwarders(pid_t target) {
    forward_target = target;
    struct sigaction sa = { .sa_handler = forward_signal };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
}

/*
 * Wait for `main_child`, reaping any other children that exit first.
 * Returns as soon as `main_child` terminates — the caller then _exit()s,
 * which as PID 1 tears down the namespace and SIGKILLs any stragglers.
 * Returns an exit(3)-style status: exit code, or 128+signal.
 */
static int reap_until(pid_t main_child) {
    int status = 0;
    for (;;) {
        pid_t r = waitpid(-1, &status, 0);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return 1;  /* ECHILD without seeing main_child — shouldn't happen. */
        }
        if (r == main_child) {
            if (WIFEXITED(status)) {
                return WEXITSTATUS(status);
            }
            if (WIFSIGNALED(status)) {
                return 128 + WTERMSIG(status);
            }
            return 1;
        }
        /* Reaped an orphan that died before main_child; keep waiting. */
    }
}

int main(int argc, char *argv[]) {
    int argi = 1;
    for (; argi < argc; argi++) {
        if (strcmp(argv[argi], "--") == 0) { argi++; break; }
        if (strcmp(argv[argi], "--allow-unix-connect") == 0 && argi + 1 < argc) {
            add_allow(argv[++argi]);
            continue;
        }
        if (strncmp(argv[argi], "--allow-unix-connect=", 21) == 0) {
            add_allow(argv[argi] + 21);
            continue;
        }
        break;  /* first non-option starts the command */
    }
    if (argi >= argc) {
        fprintf(stderr,
                "Usage: %s [--allow-unix-connect PATH]... [--] <command> [args...]\n",
                argv[0]);
        return 1;
    }

    char **command_argv = &argv[argi];

    /* Brokered mode replaces the baked-in filter; if the kernel is too old
     * for it, fall back to that filter (unix sockets blocked outright) —
     * degraded, never permissive. */
    g_broker = g_nallow > 0;
    if (g_broker && !broker_supported()) {
        fprintf(stderr,
                "apply-seccomp: this kernel cannot filter unix sockets by path "
                "(needs Linux 5.6+); blocking them entirely\n");
        g_broker = 0;
    }

    _Static_assert(sizeof(unix_block_bpf) % sizeof(struct sock_filter) == 0,
                   "BPF filter size must be a multiple of sock_filter");
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(unix_block_bpf) / sizeof(struct sock_filter)),
        .filter = (struct sock_filter *)unix_block_bpf,
    };

    /* ---- Optional observation / brokering: pre-fork setup --------------- */
    const char *observe_sock = getenv("SRT_OBSERVE_SOCK");
    const char *encoded_cmd  = getenv("SRT_ENCODED_CMD");
    int observe = observe_sock && *observe_sock && SRT_AUDIT_ARCH != 0;
    int sp[2] = { -1, -1 };
    if (observe || g_broker) {
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sp) < 0) {
            sp[0] = sp[1] = -1;   /* observation fails open; brokering falls
                                   * back to the baked-in block filter */
        }
    }

    /* ---- New PID + mount namespaces. Children (not us) enter the PID ns. ----
     *
     * Two paths to get CAP_SYS_ADMIN for the unshare:
     *   (a) The caller (bwrap) kept CAP_SYS_ADMIN in this user namespace via
     *       --cap-add. Just unshare directly.
     *   (b) We don't have the cap. Create a nested user namespace to get it,
     *       map uid/gid, then unshare. This also works when apply-seccomp is
     *       run standalone outside bwrap.
     *
     * Path (a) is tried first. If the caller didn't give us the cap, the
     * kernel returns EPERM and we fall through to (b). Path (b) can itself
     * fail on hosts where unprivileged user namespaces are gated by an LSM
     * (Ubuntu 24.04's AppArmor restriction, for example) — the unshare
     * succeeds but the new namespace grants no capabilities, so the setgroups
     * write fails. In that case we abort: the caller must supply CAP_SYS_ADMIN.
     */
    /* Pinned handle to the CURRENT /proc: the worker's fresh /proc mount
     * for the new pid namespace lands in the mount namespace we are about
     * to unshare into (fork shares it), hiding host pids from the path
     * "/proc". Used by observation (to resolve relative paths) and by the
     * unix-connect broker (to reach the caller and to connect through a
     * pinned inode); harmless otherwise. */
    int host_proc_fd = (observe || g_broker)
        ? open("/proc", O_PATH | O_DIRECTORY | O_CLOEXEC)
        : -1;

    /* Step 1: make sure we hold CAP_SYS_ADMIN in our current user namespace.
     * unshare(CLONE_NEWNS) is the probe — it needs exactly that capability,
     * and we want a private mount namespace anyway. Splitting the mount
     * unshare from the PID unshare leaves a point where the broker
     * supervisor can still be forked: after unshare(CLONE_NEWPID) a fork
     * would land inside the sandbox's own PID namespace (visible to the
     * workload), and the kernel refuses CLONE_THREAD outright, so there
     * would be no way to service a blocking connect off the receive loop. */
    if (unshare(CLONE_NEWNS) < 0) {
        if (errno != EPERM) {
            die("apply-seccomp: unshare(CLONE_NEWNS)");
        }

        uid_t uid = geteuid();
        gid_t gid = getegid();

        /* If this binary was exec'd without read permission (e.g. installed
         * mode 0111), the kernel marked the process non-dumpable, which
         * makes /proc/self/{setgroups,uid_map,gid_map} root-owned, so the
         * writes below would fail with EACCES. Temporarily flip dumpable
         * on for the uid/gid mapping and restore it right after. While
         * dumpable is 1, a same-uid process can ptrace us (under yama
         * ptrace_scope=0) and dump the mapped pages that mode 0111 is
         * meant to hide; the save/restore keeps that exposure to a
         * few-syscall race window — the same unavoidable window runc and
         * systemd accept for this pattern.
         *
         * prctl failures here are ignored: they are next to impossible for
         * these calls, and if raising dumpable did fail the map writes
         * below fail with their own clearer errors. */
        int dumpable = prctl(PR_GET_DUMPABLE);
        (void)prctl(PR_SET_DUMPABLE, 1);

        if (unshare(CLONE_NEWUSER) < 0) {
            die("apply-seccomp: unshare(CLONE_NEWUSER)");
        }
        if (write_file("/proc/self/setgroups", "deny") < 0) {
            die("apply-seccomp: write /proc/self/setgroups "
                "(nested userns is capability-restricted; "
                "caller must provide CAP_SYS_ADMIN)");
        }
        if (write_file("/proc/self/uid_map", "%u %u 1\n", uid, uid) < 0) {
            die("apply-seccomp: write /proc/self/uid_map");
        }
        if (write_file("/proc/self/gid_map", "%u %u 1\n", gid, gid) < 0) {
            die("apply-seccomp: write /proc/self/gid_map");
        }
        /* PR_SET_DUMPABLE only accepts 0 or 1; if the saved value was
         * SUID_DUMP_ROOT (2) — or the read above failed — restore the more
         * restrictive 0. */
        (void)prctl(PR_SET_DUMPABLE, dumpable == 1 ? 1 : 0);
        if (unshare(CLONE_NEWNS) < 0) {
            die("apply-seccomp: unshare(CLONE_NEWNS) after userns");
        }
    }

    /* Step 2: fork the broker supervisor, while this process is still in the
     * caller's PID namespace and (on the fallback path) already inside the
     * nested user namespace whose capabilities let it reach non-dumpable
     * workload processes. It shares the workload's network namespace and
     * mount table, so the connect()s it performs are the ones the workload
     * asked for. It does not enter the sandbox's PID namespace, so the
     * workload can neither address nor signal it. */
    pid_t supervisor = -1;
    if (g_broker && sp[0] >= 0) {
        supervisor = fork();
        if (supervisor < 0) {
            die("apply-seccomp: fork(supervisor)");
        }
        if (supervisor == 0) {
            if (sp[1] >= 0) close(sp[1]);
            /* Outlive nothing: if the stub dies before the workload is
             * done, brokered calls must fail, not hang. */
            (void)prctl(PR_SET_PDEATHSIG, SIGKILL);
            int notify_fd = recv_fd(sp[0]);
            close(sp[0]);
            if (notify_fd < 0) _exit(0);   /* worker declined to install it */
            /* This process holds the only listener fd. Anything that can
             * ptrace it can steal that fd and answer notifications on its
             * own behalf, so refuse to be dumpable. A task may always read
             * its own /proc/self/fd, so the pinned-inode connect still
             * works. */
            (void)prctl(PR_SET_DUMPABLE, 0);
            broker_init(host_proc_fd);
            int out = open_observe_channel(observe_sock, encoded_cmd);
            supervise(0, notify_fd, out, encoded_cmd, host_proc_fd);
            if (out >= 0) close(out);
            close(notify_fd);
            _exit(0);
        }
        /* The supervisor owns the receiving end from here on: keeping a
         * copy would hide the EOF that tells it the worker is gone. */
        close(sp[0]);
        sp[0] = -1;
    }

    /* Step 3: the PID namespace the workload runs in. Children (not us)
     * enter it. */
    if (unshare(CLONE_NEWPID) < 0) {
        die("apply-seccomp: unshare(CLONE_NEWPID)");
    }

    pid_t child = fork();
    if (child < 0) {
        die("apply-seccomp: fork");
    }

    if (child > 0) {
        /* Outer stub: still in bwrap's PID namespace. Forward signals,
         * optionally service the USER_NOTIF observation fd, then relay the
         * child's exit status. Never under either seccomp filter. */
        if (sp[1] >= 0) close(sp[1]);
        install_forwarders(child);

        if (sp[0] >= 0) {
            int notify_fd = recv_fd(sp[0]);
            close(sp[0]);
            if (notify_fd >= 0) {
                /* This process holds the only listener fd. Anything that can
                 * ptrace it can steal that fd and answer notifications for
                 * itself, so it must not be dumpable. The workload cannot
                 * even name this process (it lives outside the nested pid
                 * namespace), and in the nested-userns path it holds
                 * capabilities the workload does not; PR_SET_DUMPABLE is the
                 * third, cheapest lock on the same door. A task can always
                 * read its own /proc/self/fd, so the pinned-inode connect is
                 * unaffected. */
                (void)prctl(PR_SET_DUMPABLE, 0);
                int out = open_observe_channel(observe_sock, encoded_cmd);
                supervise(child, notify_fd, out, encoded_cmd, host_proc_fd);
                if (out >= 0) close(out);
                close(notify_fd);
            }
        }

        int status;
        for (;;) {
            pid_t r = waitpid(child, &status, 0);
            if (r < 0 && errno == EINTR) continue;
            if (r < 0) die("apply-seccomp: waitpid");
            break;
        }
        if (WIFEXITED(status)) {
            _exit(WEXITSTATUS(status));
        }
        _exit(WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 1);
    }

    /* Child side: drop the stub's socketpair end. */
    if (sp[0] >= 0) close(sp[0]);

    /* ================================================================
     * Inner init — PID 1 in the nested PID namespace.
     * ================================================================ */

    /* Block ptrace and /proc/1/mem writes against this process. */
    if (prctl(PR_SET_DUMPABLE, 0) < 0) {
        die("apply-seccomp: prctl(PR_SET_DUMPABLE)");
    }

    /* Don't let our /proc mount propagate anywhere. */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
        die("apply-seccomp: mount(MS_PRIVATE)");
    }
    /* EPERM here means a masked /proc is underneath (unprivileged Docker)
     * and the kernel domination check refused the overmount. The nested
     * userns above is the isolation boundary; this remount only hides
     * outer PIDs from `ls /proc`. enableWeakerNestedSandbox targets
     * exactly this environment. */
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) < 0
        && errno != EPERM) {
        die("apply-seccomp: mount(/proc)");
    }

    /* bwrap --cap-add places CAP_SYS_ADMIN in the ambient set so it survives
     * exec. Clear it now that the mount is done; combined with
     * PR_SET_NO_NEW_PRIVS, the worker's execve drops to zero capabilities. */
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0) {
        die("apply-seccomp: prctl(PR_CAP_AMBIENT_CLEAR_ALL)");
    }

    /* Fork the real workload so PID 1 can stay as a non-dumpable reaper. */
    pid_t worker = fork();
    if (worker < 0) {
        die("apply-seccomp: fork(worker)");
    }

    if (worker > 0) {
        /* Inner init: reap everything, exit with the worker's status.
         * When PID 1 exits the kernel tears down the whole namespace.
         * PID 1 drops signals without handlers, so install forwarders. */
        if (sp[1] >= 0) close(sp[1]);
        install_forwarders(worker);
        _exit(reap_until(worker));
    }

    /* ---- Worker (inner PID 2): apply seccomp and exec. ---- */
    unsetenv("SRT_OBSERVE_SOCK");
    unsetenv("SRT_ENCODED_CMD");
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        die("apply-seccomp: prctl(PR_SET_NO_NEW_PRIVS)");
    }
    /* Install the USER_NOTIF filter and hand its listener fd to the outer
     * stub over the pre-fork socketpair. Runs after NO_NEW_PRIVS (required)
     * and before exec so only the workload is filtered. It carries the
     * write-intent observation traps (best-effort) and, when an allowlist was
     * given, the unix-socket rules that replace the baked-in filter — the
     * kernel allows only one listener-bearing filter per task. */
    int notify_ok = install_notify_filter(sp[1], observe, g_broker) == 0;
    if (!notify_ok && g_broker) {
        /* No broker: fall back to the baked-in filter, which blocks unix
         * sockets outright. Degraded, never permissive. */
        static const char msg[] =
            "apply-seccomp: unix socket allowlist unavailable; blocking them entirely\n";
        (void)!write(2, msg, sizeof(msg) - 1);
        g_broker = 0;
    }
    if (!g_broker && prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
        die("apply-seccomp: prctl(PR_SET_SECCOMP)");
    }

    execvp(command_argv[0], command_argv);
    die("apply-seccomp: execvp");
    return 1;
}
