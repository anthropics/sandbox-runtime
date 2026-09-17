/*
 * TOCTOU stress harness for the Linux unix-socket allowlist.
 *
 * The broker in vendor/seccomp-src/apply-seccomp.c is only sound because it
 * never asks the kernel to re-run a trapped connect(): between the check and
 * a re-execution, a sibling thread can rewrite the sockaddr or dup2() a
 * different socket over the inspected fd number. This program is that
 * sibling thread, run in both shapes:
 *
 *   uds-race addr OK OTHER SECONDS          - flip the shared sockaddr
 *                                             between an allowed and a
 *                                             forbidden path while connecting
 *   uds-race dup2 OK OTHER SECONDS PORT     - additionally flip the fd number
 *                                             between an AF_INET and an
 *                                             AF_UNIX socket
 *
 * The verdict is external: the forbidden listener must accept nothing. This
 * program also self-checks with getpeername() on every successful connect and
 * reports the count, so a run that raced but connected nowhere cannot pass
 * silently — the caller asserts on the iteration and success counts too.
 *
 * Deliberately unsynchronized: the data races on `addr` and the fd number are
 * the point of the test.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define NPAIRS 4

static const char *ok_path, *other_path;
static atomic_int running = 1;
static struct sockaddr_un ok_addr, other_addr;
static struct sockaddr_in tcp_addr;

struct pair {
    union {
        struct sockaddr_un un;
        struct sockaddr_in in;
        char raw[sizeof(struct sockaddr_un)];
    } addr;                 /* shared with the flipper thread, on purpose */
    int fdslot;             /* fd number under contention (dup2 mode) */
    atomic_int ufd, ifd;    /* backing sockets for the dup2 flip */
    long iters, ok, eperm, other, violations;
};
static struct pair pairs[NPAIRS];

/* Did this fd end up connected to the socket the policy forbids? */
static int peer_is_forbidden(int fd) {
    struct sockaddr_un p;
    socklen_t l = sizeof(p);
    memset(&p, 0, sizeof(p));
    if (fd < 0 || getpeername(fd, (struct sockaddr *)&p, &l) < 0) return 0;
    return l > offsetof(struct sockaddr_un, sun_path) &&
           strcmp(p.sun_path, other_path) == 0;
}

static void spin(int n) {
    for (volatile int i = 0; i < n; i++) {
    }
}

static void *flip_addr(void *arg) {
    struct pair *p = arg;
    while (atomic_load(&running)) {
        memcpy(&p->addr.un, &other_addr, sizeof(other_addr));
        spin(50);
        memcpy(&p->addr.un, &ok_addr, sizeof(ok_addr));
        spin(50);
    }
    return NULL;
}

static void *connect_addr(void *arg) {
    struct pair *p = arg;
    while (atomic_load(&running)) {
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            perror("socket");
            exit(2);
        }
        int r = connect(fd, (struct sockaddr *)&p->addr.un,
                        sizeof(struct sockaddr_un));
        p->iters++;
        if (r == 0) {
            p->ok++;
            if (peer_is_forbidden(fd)) p->violations++;
        } else if (errno == EPERM) {
            p->eperm++;
        } else {
            p->other++;
        }
        close(fd);
    }
    return NULL;
}

/* Replace both backing sockets, checking the retired unix one first. */
static void renew(struct pair *p) {
    int u = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int i = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (u < 0 || i < 0) {
        perror("socket");
        exit(2);
    }
    int old_u = atomic_exchange(&p->ufd, u);
    int old_i = atomic_exchange(&p->ifd, i);
    if (old_u >= 0) {
        if (peer_is_forbidden(old_u)) p->violations++;
        close(old_u);
    }
    if (old_i >= 0) close(old_i);
}

static void *flip_dup2(void *arg) {
    struct pair *p = arg;
    while (atomic_load(&running)) {
        /* unix socket at the fd number, forbidden path in the sockaddr */
        dup2(atomic_load(&p->ufd), p->fdslot);
        memcpy(&p->addr.un, &other_addr, sizeof(other_addr));
        spin(30);
        /* inet socket at the fd number, TCP address in the sockaddr */
        dup2(atomic_load(&p->ifd), p->fdslot);
        memset(&p->addr, 0, sizeof(p->addr));
        memcpy(&p->addr.in, &tcp_addr, sizeof(tcp_addr));
        spin(30);
    }
    return NULL;
}

static void *connect_dup2(void *arg) {
    struct pair *p = arg;
    while (atomic_load(&running)) {
        int r = connect(p->fdslot, (struct sockaddr *)&p->addr.un,
                        sizeof(struct sockaddr_un));
        p->iters++;
        if (r == 0) p->ok++;
        else if (errno == EPERM) p->eperm++;
        else p->other++;
        if (peer_is_forbidden(atomic_load(&p->ufd))) p->violations++;
        if (r == 0 || errno == EISCONN || (p->iters & 63) == 0) renew(p);
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: uds-race addr|dup2 OK OTHER SECONDS [PORT]\n");
        return 2;
    }
    int dup2_mode = strcmp(argv[1], "dup2") == 0;
    ok_path = argv[2];
    other_path = argv[3];
    int secs = atoi(argv[4]);
    int port = (argc > 5) ? atoi(argv[5]) : 0;

    ok_addr.sun_family = other_addr.sun_family = AF_UNIX;
    snprintf(ok_addr.sun_path, sizeof(ok_addr.sun_path), "%s", ok_path);
    snprintf(other_addr.sun_path, sizeof(other_addr.sun_path), "%s", other_path);
    tcp_addr.sin_family = AF_INET;
    tcp_addr.sin_port = htons((unsigned short)port);
    tcp_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    pthread_t th[NPAIRS * 2];
    for (int i = 0; i < NPAIRS; i++) {
        struct pair *p = &pairs[i];
        memcpy(&p->addr.un, &ok_addr, sizeof(ok_addr));
        atomic_store(&p->ufd, -1);
        atomic_store(&p->ifd, -1);
        if (dup2_mode) {
            p->fdslot = 200 + i;
            renew(p);
            dup2(atomic_load(&p->ifd), p->fdslot);
        }
        pthread_create(&th[2 * i], NULL, dup2_mode ? flip_dup2 : flip_addr, p);
        pthread_create(&th[2 * i + 1], NULL,
                       dup2_mode ? connect_dup2 : connect_addr, p);
    }
    sleep(secs);
    atomic_store(&running, 0);
    for (int i = 0; i < NPAIRS * 2; i++) pthread_join(th[i], NULL);

    long iters = 0, ok = 0, eperm = 0, other = 0, violations = 0;
    for (int i = 0; i < NPAIRS; i++) {
        struct pair *p = &pairs[i];
        if (dup2_mode && peer_is_forbidden(atomic_load(&p->ufd))) p->violations++;
        iters += p->iters;
        ok += p->ok;
        eperm += p->eperm;
        other += p->other;
        violations += p->violations;
    }
    printf("iterations=%ld connected=%ld eperm=%ld other=%ld violations=%ld\n",
           iters, ok, eperm, other, violations);
    return violations ? 1 : 0;
}
