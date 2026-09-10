/*
 * apply-seccomp.c - Apply seccomp BPF filter in an isolated PID namespace
 *
 * Usage: apply-seccomp <command> [args...]
 *
 * This program applies a baked-in seccomp BPF filter, isolates the
 * target command in a nested user+PID+mount namespace so it cannot see or
 * ptrace any process that lacks the filter, applies the filter with
 * prctl(PR_SET_SECCOMP), and execs the command.
 *
 * Process layout inside the outer bwrap sandbox:
 *
 *   bwrap init (PID 1)          <- outer PID ns, no seccomp
 *   \_ bash / socat ...         <- outer PID ns, no seccomp
 *      \_ apply-seccomp [outer] <- outer PID ns, waits for inner init
 *         ================================================= PID ns boundary
 *         \_ apply-seccomp [inner init] <- inner PID 1, PR_SET_DUMPABLE=0
 *            \_ user command            <- inner PID 2, seccomp applied
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
 * Compile: gcc -static -O2 -o apply-seccomp apply-seccomp.c
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
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <poll.h>
#include <time.h>
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
#ifndef __NR_fchmodat2
#  define __NR_fchmodat2 452
#endif

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

static int build_observe_bpf(struct sock_filter *f, int cap) {
    int n = 0;
#define EMIT(ins) do { if (n >= cap) return -1; f[n++] = (struct sock_filter)ins; } while (0)

    /* arch check */
    EMIT(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, arch)));
    int j_arch = n;
    EMIT(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SRT_AUDIT_ARCH, 0, 0)); /* jf→ALLOW */

    /* nr */
    EMIT(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, nr)));
#if SRT_HAS_X32
    int j_x32 = n;
    EMIT(BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000u, 0, 0));    /* jt→ALLOW */
#endif

    /* Always-trap syscalls (flags_arg < 0). */
    int j_trap[64], ntrap = 0;
    for (int i = 0; i < n_observe_calls; i++) {
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
    for (int i = 0; i < n_observe_calls; i++) {
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
    f[j_arch].jf = TO(j_arch, allow_at);
#if SRT_HAS_X32
    f[j_x32].jt  = TO(j_x32, allow_at);
#endif
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
static void install_observe_filter(int sp_fd) {
    if (sp_fd < 0) return;

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
        return;
    }

    struct sock_filter filt[80];
    int len = build_observe_bpf(filt, (int)(sizeof(filt)/sizeof(filt[0])));
    if (len < 0) { (void)!write(sp_fd, "E", 1); close(sp_fd); return; }
    struct sock_fprog prog = { .len = (unsigned short)len, .filter = filt };

    int nfd = (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                           SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (nfd < 0) {
        /* EINVAL: kernel <5.0. EBUSY: another listener already installed.
         * Either way, no filter is active — fail open. */
        (void)!write(sp_fd, "E", 1);
        close(sp_fd);
        return;
    }

    /* --- filter is now live --- */
    if (send_fd(sp_fd, nfd) < 0) {
        static const char msg[] = "apply-seccomp: observe sendmsg failed\n";
        (void)!write(2, msg, sizeof(msg) - 1);
        _exit(125);
    }
    close(sp_fd);
    close(nfd);   /* outer stub now holds the only reference */
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
 * the event entirely (best-effort telemetry: never guess, never block). */
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

/* Service the notify fd until the inner-init child exits. Runs in the OUTER
 * STUB, which never installed either seccomp filter. Always replies CONTINUE,
 * even when out_sock < 0, so a missing listener never wedges the workload. */
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

    int pidfd = (int)syscall(__NR_pidfd_open, child, 0);

    struct pollfd pfds[2];
    pfds[0].fd = notify_fd; pfds[0].events = POLLIN;
    pfds[1].fd = pidfd;     pfds[1].events = POLLIN;
    nfds_t nfds = pidfd >= 0 ? 2 : 1;
    int tmo = pidfd >= 0 ? -1 : 200;

    for (;;) {
        int pr = poll(pfds, nfds, tmo);
        if (pr < 0) { if (errno == EINTR) continue; break; }

        if (pfds[0].revents & POLLIN) {
            memset(req, 0, sz.seccomp_notif);
            if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, req) == 0) {
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
            } else if (errno != EINTR && errno != ENOENT) {
                break;
            }
        }
        /* All filtered tasks gone → notify fd reports EOF. */
        if (pfds[0].revents & (POLLHUP | POLLERR)) break;

        if (pidfd >= 0) {
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
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
        return 1;
    }

    char **command_argv = &argv[1];

    _Static_assert(sizeof(unix_block_bpf) % sizeof(struct sock_filter) == 0,
                   "BPF filter size must be a multiple of sock_filter");
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(unix_block_bpf) / sizeof(struct sock_filter)),
        .filter = (struct sock_filter *)unix_block_bpf,
    };

    /* ---- Optional observation: pre-fork setup --------------------------- */
    const char *observe_sock = getenv("SRT_OBSERVE_SOCK");
    const char *encoded_cmd  = getenv("SRT_ENCODED_CMD");
    int sp[2] = { -1, -1 };
    if (observe_sock && *observe_sock && SRT_AUDIT_ARCH != 0) {
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sp) < 0) {
            sp[0] = sp[1] = -1;   /* fail open */
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
     * "/proc". Only used when observation is active; harmless otherwise. */
    int host_proc_fd = observe_sock && *observe_sock
        ? open("/proc", O_PATH | O_DIRECTORY | O_CLOEXEC)
        : -1;

    if (unshare(CLONE_NEWPID | CLONE_NEWNS) < 0) {
        if (errno != EPERM) {
            die("apply-seccomp: unshare(CLONE_NEWPID|CLONE_NEWNS)");
        }

        uid_t uid = geteuid();
        gid_t gid = getegid();

        /* unshare(CLONE_NEWUSER) implies CLONE_THREAD, and check_unshare_flags()
         * rejects that with EINVAL while thread_group_empty() is false. A thread
         * that has already exited stays in the thread group until release_task()
         * runs, but its joiner is woken earlier, in mm_release() — so code that
         * reaches this point right after joining a thread can land inside that
         * window. The standalone apply-seccomp binary cannot: it spawns no
         * threads, and execve() reaps the caller's threads before main() runs.
         * The exposed configuration is seccomp.argv0 — a multicall runtime
         * binary that runs this sequence in-process moments after its runtime
         * parked a helper thread (an allocator scavenger, a GC worker).
         *
         * The retry must sleep, not sched_yield(): a freshly futex-woken
         * joiner sits several milliseconds behind the exiting thread in
         * vruntime, and on a single-CPU host CFS ignores yields until that
         * lead is burned (measured: ~6500 yields before the first success,
         * versus one attempt after a 1us sleep). Bounded so a permanent
         * EINVAL (a kernel built without CONFIG_USER_NS) still dies, at
         * worst 5ms later. This runs before the dumpable flip below so the
         * sleeps never extend the window in which we are ptrace-able. */
        for (int attempt = 0; unshare(CLONE_NEWUSER) < 0; attempt++) {
            if (errno != EINVAL || attempt >= 50) {
                die("apply-seccomp: unshare(CLONE_NEWUSER)");
            }
            struct timespec backoff = { .tv_nsec = 100000 };  /* 100us */
            nanosleep(&backoff, NULL);
        }

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
        if (unshare(CLONE_NEWPID | CLONE_NEWNS) < 0) {
            die("apply-seccomp: unshare(CLONE_NEWPID|CLONE_NEWNS) after userns");
        }
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
                int out = connect_observe_sock(observe_sock);
                if (out < 0) {
                    char buf[256];
                    int n = snprintf(buf, sizeof(buf),
                        "{\"observe_init_error\":\"connect %s: %s\"}\n",
                        observe_sock, strerror(errno));
                    (void)!write(2, buf, (size_t)n);
                } else if (encoded_cmd && *encoded_cmd) {
                    char hdr[768];
                    int n = snprintf(hdr, sizeof(hdr),
                        "{\"encodedCommand\":\"%.700s\"}\n", encoded_cmd);
                    if (n > 0) {
                        (void)!send(out, hdr, (size_t)n,
                                    MSG_DONTWAIT | MSG_NOSIGNAL);
                    }
                }
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
    /* Best-effort: install the USER_NOTIF observation filter and hand its
     * listener fd to the outer stub over the pre-fork socketpair. Runs after
     * NO_NEW_PRIVS (required) and before the unix-block filter / exec so only
     * the workload is observed. */
    install_observe_filter(sp[1]);
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
        die("apply-seccomp: prctl(PR_SET_SECCOMP)");
    }

    execvp(command_argv[0], command_argv);
    die("apply-seccomp: execvp");
    return 1;
}
