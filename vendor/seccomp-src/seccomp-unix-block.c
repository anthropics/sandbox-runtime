/*
 * Seccomp BPF filter generator to block Unix domain socket creation
 *
 * This program generates a seccomp-bpf filter that blocks the socket() syscall
 * when called with AF_UNIX as the domain argument. This prevents creation of
 * Unix domain sockets while allowing all other socket types (AF_INET, AF_INET6, etc.)
 * and all other syscalls.
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
 * filters for both x64 and arm64.
 *
 * The third argument picks the rule set. `unix` (the default) is the filter
 * described above. `namespaces` is a second, separate filter that
 * apply-seccomp stacks on top of it: it keeps the command in the namespaces
 * the sandbox made for it. Every write deny is a read-only bind, and a bind
 * protects a path only in the mount namespace it was made in, so a command
 * that may create a user namespace (no capability is needed for that) gets a
 * full capability set over a private copy of the mount tree and can take the
 * binds out of its own view. The filter refuses the user-namespace flag to
 * unshare(2) and clone(2), refuses clone3(2) outright (its flags live in a
 * struct a filter cannot read; ENOSYS sends libc to clone), and refuses
 * setns(2) and the calls that change a mount tree. The last group is what
 * holds a command started by uid 0, which already has those capabilities in
 * the helper's own namespace and needs no new one. Two filters rather than
 * one so that a caller who opts a command out of this one keeps the first.
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
 * The rules of the `namespaces` filter. A syscall this libseccomp cannot name
 * fails the build rather than being left out: a filter missing one of these is
 * a filter that does not do what its name says.
 */
static int add_namespace_rules(scmp_filter_ctx ctx, int native,
                               const char *arch_name) {
    int rc;

    /* The flags word is arg0 of unshare(2), and of clone(2) on both
     * architectures this generator emits for (x86_64 and aarch64 take
     * flags first; the ABIs that do not are not supported here). Masked, so
     * the flag is caught whatever else is set beside it. */
    const char *flag_calls[] = { "unshare", "clone" };
    for (size_t i = 0; i < sizeof(flag_calls) / sizeof(flag_calls[0]); i++) {
        int nr = seccomp_syscall_resolve_name(flag_calls[i]);
        if (nr == __NR_SCMP_ERROR) {
            fprintf(stderr, "Error: libseccomp does not know %s\n", flag_calls[i]);
            return -1;
        }
        rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), nr, 1,
                              SCMP_A0(SCMP_CMP_MASKED_EQ, SRT_CLONE_NEWUSER,
                                      SRT_CLONE_NEWUSER));
        if (rc < 0) {
            fprintf(stderr, "Error: Failed to add %s rule: %s\n", flag_calls[i],
                    strerror(-rc));
            return -1;
        }
    }

    /* clone3(2) passes its flags in a struct, which a filter cannot read.
     * ENOSYS, not EPERM: libc and the language runtimes treat ENOSYS as "this
     * kernel has no clone3" and fall back to clone(2), which the rule above
     * does cover; EPERM reads as a real failure and breaks thread creation. */
    {
        int nr = seccomp_syscall_resolve_name("clone3");
        if (nr == __NR_SCMP_ERROR) {
            fprintf(stderr, "Error: libseccomp does not know clone3\n");
            return -1;
        }
        rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), nr, 0);
        if (rc < 0) {
            fprintf(stderr, "Error: Failed to add clone3 rule: %s\n", strerror(-rc));
            return -1;
        }
    }

    /* Joining another namespace, and the calls that change a mount tree, the
     * old interface and the fd-based one, as far as this libseccomp names
     * them. Two newer ones follow. */
    const char *refused[] = {
        "setns",      "mount",    "umount2",  "pivot_root",
        "open_tree",  "move_mount", "fsopen", "fsconfig",
        "fsmount",    "fspick",
    };
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) {
        int nr = seccomp_syscall_resolve_name(refused[i]);
        if (nr == __NR_SCMP_ERROR) {
            fprintf(stderr,
                    "Error: libseccomp does not know %s\n",
                    refused[i]);
            return -1;
        }
        rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), nr, 0);
        if (rc < 0) {
            fprintf(stderr, "Error: Failed to add %s rule: %s\n", refused[i],
                    strerror(-rc));
            return -1;
        }
    }

    /* Two calls newer than the libseccomp some builders have: mount_setattr
     * (Linux 5.12, named from libseccomp 2.5.2) and open_tree_attr (Linux
     * 6.15, named from 2.6.1), which is open_tree with mount_setattr's
     * changes in one call. Where the library cannot name one it goes in by
     * number, which is the same on every architecture for each call added
     * since Linux 5.1. That works only for the builder's own architecture:
     * libseccomp carries a call from one architecture to another by name and
     * refuses a bare number for another one. Emitting for another
     * architecture with a library that cannot name the call is therefore an
     * error, never a filter with the call left out: a filter that is quietly
     * weaker on one architecture is the one outcome worth a failed build. A
     * libseccomp that names both, or generating each architecture's filter
     * on that architecture, avoids it. */
    static const struct {
        const char *name;
        int nr;
    } newer[] = {
        { "mount_setattr", 442 },
        { "open_tree_attr", 467 },
    };
    for (size_t i = 0; i < sizeof(newer) / sizeof(newer[0]); i++) {
        int nr = seccomp_syscall_resolve_name(newer[i].name);
        if (nr == __NR_SCMP_ERROR) {
            if (!native) {
                const struct scmp_version *v = seccomp_version();
                fprintf(stderr,
                        "Error: libseccomp %u.%u.%u cannot name %s, and a call can "
                        "go in by number only for the builder's own architecture, "
                        "not for %s. Build with a libseccomp that names it, or "
                        "generate this architecture's filter on that architecture.\n",
                        v ? v->major : 0, v ? v->minor : 0, v ? v->micro : 0,
                        newer[i].name, arch_name);
                return -1;
            }
            nr = newer[i].nr;
        }
        rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), nr, 0);
        if (rc < 0) {
            fprintf(stderr, "Error: Failed to add %s rule: %s\n", newer[i].name,
                    strerror(-rc));
            return -1;
        }
    }
    return 0;
}

/* The rules of the `unix` filter. */
static int add_unix_rules(scmp_filter_ctx ctx) {
    int rc;

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
        return -1;
    }

    /* Block io_uring entirely. IORING_OP_SOCKET (Linux 5.19+) creates sockets
     * in kernel context without going through the socket() syscall, bypassing
     * the rule above. seccomp cannot inspect io_uring SQEs (they live in a
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
            return -1;
        }
    }
    return 0;
}

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

    rc = strcmp(rule_set, "namespaces") == 0
             ? add_namespace_rules(ctx, native, arch_name ? arch_name : "native")
             : add_unix_rules(ctx);
    if (rc < 0) {
        seccomp_release(ctx);
        return 1;
    }

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
