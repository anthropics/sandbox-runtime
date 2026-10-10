/*
 * Seccomp BPF filter generator to block Unix domain socket creation
 *
 * This program generates a seccomp-bpf filter that blocks the socket() syscall
 * when called with AF_UNIX or AF_VSOCK as the domain argument. This prevents creation
 * of Unix domain sockets and VM sockets while allowing all other socket types
 * (AF_INET, AF_INET6, etc.) and all other syscalls.
 *
 * The filter is exported in a format compatible with bubblewrap's --seccomp flag.
 *
 * SECURITY LIMITATION - 32-bit x86 (ia32):
 * TODO: This filter does NOT block socketcall() syscall, which is a security issue
 * on 32-bit x86 systems. On ia32, the socket() syscall doesn't exist - instead,
 * all socket operations are multiplexed through socketcall():
 *   - socketcall(SYS_SOCKET, [AF_UNIX, ...]) - can bypass this filter
 *   - socketcall(SYS_SOCKETPAIR, [AF_UNIX, ...]) - can bypass this filter
 *
 * To fix this, we need to add conditional rules that:
 * 1. Check if socketcall() exists on the current architecture (32-bit x86 only)
 * 2. Block socketcall(SYS_SOCKET, ...) when first arg of sub-call is AF_UNIX
 * 3. Block socketcall(SYS_SOCKETPAIR, ...) when first arg of sub-call is AF_UNIX
 *
 * This requires inspecting the arguments passed to socketcall, which is more
 * complex BPF logic. For now, 32-bit x86 is not supported.
 *
 * Compilation:
 *   gcc -o seccomp-unix-block seccomp-unix-block.c -lseccomp
 *
 * Usage:
 *   ./seccomp-unix-block <output-file> [arch] [unix|namespaces]
 *
 * If arch is given (x86_64 or aarch64), the filter is generated for that
 * architecture instead of the native one. Lets a single-arch builder emit
 * filters for both x64 and arm64; for `namespaces`, only with a libseccomp
 * that names every call in it (2.6.1 and later).
 *
 * The third argument picks the rule set: `unix` (the default) is the filter
 * above; `namespaces` is a second one, which apply-seccomp stacks on it to
 * keep the command in the namespaces the sandbox made for it (apply-seccomp.c
 * says why). Two filters, so that a command opted out of the second keeps the
 * first.
 *
 * Dependencies:
 *   - libseccomp (libseccomp-dev package on Debian/Ubuntu)
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <seccomp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Not pulled from <sched.h>: that needs _GNU_SOURCE, and the value is ABI. */
#define SRT_CLONE_NEWUSER 0x10000000UL

/*
 * The rules of the `namespaces` filter. None is ever left out: a call this
 * libseccomp cannot name fails the generator, except the two newest, which go
 * in by number where that can be done. Every rule goes in with
 * seccomp_rule_add_exact(): the plain seccomp_rule_add() takes a call the
 * target architecture lacks, adds nothing, and returns success.
 */
static int add_namespace_rules(scmp_filter_ctx ctx, int native,
                               const char *arch_name) {
    static const struct {
        const char *name;
        int err;
        /* Refused only with CLONE_NEWUSER in arg0, the flags word of both
         * calls on both architectures. Masked: other flags beside it too. */
        int newuser_only;
        /* For a call newer than the libseccomp some builders have
         * (mount_setattr is named from 2.5.2, open_tree_attr from 2.6.1): its
         * number, the same on every architecture since Linux 5.1. Taken by
         * libseccomp for the builder's own architecture only. */
        int nr_if_unnamed;
    } rules[] = {
        { "unshare", EPERM, 1, 0 },
        { "clone", EPERM, 1, 0 },
        /* clone3(2) passes its flags in a struct, which a filter cannot read.
         * ENOSYS, not EPERM: libc and the language runtimes take ENOSYS as
         * "this kernel has no clone3" and fall back to clone(2), which the
         * rule above covers; EPERM breaks thread creation. */
        { "clone3", ENOSYS, 0, 0 },
        /* Joining another namespace, and changing a mount tree: what holds a
         * command started by uid 0, which has those capabilities in the
         * helper's namespace and needs no new one. */
        { "setns", EPERM, 0, 0 },
        { "mount", EPERM, 0, 0 },
        { "umount2", EPERM, 0, 0 },
        { "pivot_root", EPERM, 0, 0 },
        { "open_tree", EPERM, 0, 0 },
        { "move_mount", EPERM, 0, 0 },
        { "fsopen", EPERM, 0, 0 },
        { "fsconfig", EPERM, 0, 0 },
        { "fsmount", EPERM, 0, 0 },
        { "fspick", EPERM, 0, 0 },
        { "mount_setattr", EPERM, 0, 442 },
        { "open_tree_attr", EPERM, 0, 467 },
    };
    for (size_t i = 0; i < sizeof(rules) / sizeof(rules[0]); i++) {
        int nr = seccomp_syscall_resolve_name(rules[i].name);
        if (nr < 0 && rules[i].nr_if_unnamed != 0 && native) {
            nr = rules[i].nr_if_unnamed;
        }
        if (nr < 0) {
            const struct scmp_version *v = seccomp_version();
            fprintf(stderr, "Error: libseccomp %u.%u.%u cannot name %s for %s\n",
                    v ? v->major : 0, v ? v->minor : 0, v ? v->micro : 0,
                    rules[i].name, arch_name);
            return -1;
        }
        int rc = rules[i].newuser_only
            ? seccomp_rule_add_exact(ctx, SCMP_ACT_ERRNO(rules[i].err), nr, 1,
                                     SCMP_A0(SCMP_CMP_MASKED_EQ, SRT_CLONE_NEWUSER,
                                             SRT_CLONE_NEWUSER))
            : seccomp_rule_add_exact(ctx, SCMP_ACT_ERRNO(rules[i].err), nr, 0);
        if (rc < 0) {
            fprintf(stderr, "Error: Failed to add %s rule: %s\n", rules[i].name,
                    strerror(-rc));
            return -1;
        }
    }
    return 0;
}

static int export_filter(scmp_filter_ctx ctx, const char *output_file);

int main(int argc, char *argv[]) {
    scmp_filter_ctx ctx;
    int rc;

    if (argc < 2 || argc > 4) {
        fprintf(stderr,
                "Usage: %s <output-file> [x86_64|aarch64] [unix|namespaces]\n",
                argv[0]);
        return 1;
    }

    const char *output_file = argv[1];
    const char *arch_name = (argc >= 3) ? argv[2] : NULL;
    const char *rule_set = (argc == 4) ? argv[3] : "unix";
    if (strcmp(rule_set, "unix") != 0 && strcmp(rule_set, "namespaces") != 0) {
        fprintf(stderr, "Error: Unknown rule set '%s'\n", rule_set);
        return 1;
    }

    /* Create seccomp context with default action ALLOW */
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL) {
        fprintf(stderr, "Error: Failed to initialize seccomp context\n");
        return 1;
    }

    int native = 1;
    if (arch_name != NULL) {
        uint32_t target;
        if (strcmp(arch_name, "x86_64") == 0) {
            target = SCMP_ARCH_X86_64;
        } else if (strcmp(arch_name, "aarch64") == 0) {
            target = SCMP_ARCH_AARCH64;
        } else {
            fprintf(stderr, "Error: Unsupported arch '%s'\n", arch_name);
            seccomp_release(ctx);
            return 1;
        }
        if (target != seccomp_arch_native()) {
            native = 0;
            rc = seccomp_arch_remove(ctx, SCMP_ARCH_NATIVE);
            if (rc == 0) rc = seccomp_arch_add(ctx, target);
            if (rc < 0) {
                fprintf(stderr, "Error: Failed to set target arch: %s\n", strerror(-rc));
                seccomp_release(ctx);
                return 1;
            }
        }
    }

    if (strcmp(rule_set, "namespaces") == 0) {
        if (add_namespace_rules(ctx, native,
                                arch_name ? arch_name : "native") < 0) {
            seccomp_release(ctx);
            return 1;
        }
        return export_filter(ctx, output_file);
    }

    /* Add rule to block socket(AF_UNIX, ...) */
    /* socket() syscall signature: int socket(int domain, int type, int protocol) */
    /* arg0 = domain (AF_UNIX = 1) */
    /* Use SCMP_CMP_MASKED_EQ with a 32-bit mask: the domain argument is a 32-bit
     * int, so the kernel ignores the upper 32 bits of the register. A plain
     * SCMP_CMP_EQ would compare all 64 bits and miss calls where the upper bits
     * are set. */
    rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 1,
                          SCMP_A0(SCMP_CMP_MASKED_EQ, 0xffffffff, AF_UNIX));
    if (rc < 0) {
        fprintf(stderr, "Error: Failed to add seccomp rule: %s\n", strerror(-rc));
        seccomp_release(ctx);
        return 1;
    }

    /* Add rule to block socket(AF_VSOCK, ...) */
    /* The network namespace does not fence VM sockets: on a machine with a
     * vsock transport one connects straight out of the sandbox, past the
     * proxies. No socketpair() rule is needed: the family has none. */
    rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 1,
                          SCMP_A0(SCMP_CMP_MASKED_EQ, 0xffffffff, AF_VSOCK));
    if (rc < 0) {
        fprintf(stderr, "Error: Failed to add AF_VSOCK rule: %s\n", strerror(-rc));
        seccomp_release(ctx);
        return 1;
    }

    /* Block io_uring entirely. IORING_OP_SOCKET (Linux 5.19+) creates sockets
     * in kernel context without going through the socket() syscall, bypassing
     * the rules above. seccomp cannot inspect io_uring SQEs (they live in a
     * shared-memory ring), so the only safe option is to deny ring creation
     * and use. Blocking all three syscalls also covers the case of an
     * inherited ring fd. */
    int io_uring_calls[] = {
        SCMP_SYS(io_uring_setup),
        SCMP_SYS(io_uring_enter),
        SCMP_SYS(io_uring_register),
    };
    for (size_t i = 0; i < sizeof(io_uring_calls) / sizeof(io_uring_calls[0]); i++) {
        rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), io_uring_calls[i], 0);
        if (rc < 0) {
            fprintf(stderr, "Error: Failed to add io_uring rule: %s\n", strerror(-rc));
            seccomp_release(ctx);
            return 1;
        }
    }

    return export_filter(ctx, output_file);
}

/* Writes the filter to output_file, and releases it. */
static int export_filter(scmp_filter_ctx ctx, const char *output_file) {
    int rc;

    /* Export the filter to a file */
    int fd = open(output_file, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) {
        fprintf(stderr, "Error: Failed to open output file: %s\n", strerror(errno));
        seccomp_release(ctx);
        return 1;
    }

    rc = seccomp_export_bpf(ctx, fd);
    if (rc < 0) {
        fprintf(stderr, "Error: Failed to export seccomp filter: %s\n", strerror(-rc));
        close(fd);
        seccomp_release(ctx);
        return 1;
    }

    /* Clean up */
    close(fd);
    seccomp_release(ctx);

    return 0;
}
