// A small stand-in for socat: two addresses, relayed both ways.
// Knows UNIX-LISTEN, UNIX-CONNECT, TCP, TCP4, TCP6, TCP-LISTEN, TCP4-LISTEN, TCP6-LISTEN, STDIO and "-",
// and of the options only fork, backlog, ipv6only, reuseaddr, bind (others are ignored).
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

struct addr { char kind[32]; char a[4096]; char b[64]; int fork_, backlog, v6only; };

static void die(const char *what) { fprintf(stderr, "socat(stand-in): %s: %s\n", what, strerror(errno)); exit(1); }

static void parse(const char *s, struct addr *o) {
  memset(o, 0, sizeof *o); o->backlog = 5; o->v6only = -1;
  char *copy = strdup(s), *save = NULL, *head = strtok_r(copy, ",", &save);
  for (char *opt; (opt = strtok_r(NULL, ",", &save));) {
    if (!strcasecmp(opt, "fork")) o->fork_ = 1;
    else if (!strncasecmp(opt, "backlog=", 8)) o->backlog = atoi(opt + 8);
    else if (!strncasecmp(opt, "ipv6only=", 9)) o->v6only = atoi(opt + 9);
  }
  char *colon = strchr(head, ':');
  if (!colon) { snprintf(o->kind, sizeof o->kind, "%s", head); return; }
  *colon = 0; snprintf(o->kind, sizeof o->kind, "%s", head);
  char *rest = colon + 1;
  if (!strncasecmp(o->kind, "TCP", 3) && !strcasestr(o->kind, "LISTEN")) {
    char *last = strrchr(rest, ':'); if (!last) { errno = EINVAL; die(s); }
    *last = 0; snprintf(o->b, sizeof o->b, "%s", last + 1);
    if (rest[0] == '[') { rest++; rest[strlen(rest) - 1] = 0; }
  }
  snprintf(o->a, sizeof o->a, "%s", rest);
}

static int is_listen(const struct addr *a) { return strcasestr(a->kind, "LISTEN") != NULL; }

static int listen_on(const struct addr *a) {
  int fd, one = 1;
  if (!strncasecmp(a->kind, "UNIX", 4)) {
    struct sockaddr_un u = {.sun_family = AF_UNIX};
    if (strlen(a->a) >= sizeof u.sun_path) { errno = ENAMETOOLONG; die(a->a); }
    strcpy(u.sun_path, a->a);
    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) die("socket");
    if (bind(fd, (struct sockaddr *)&u, sizeof u) < 0) die(a->a);
  } else if (!strncasecmp(a->kind, "TCP6", 4)) {
    struct sockaddr_in6 s = {.sin6_family = AF_INET6, .sin6_port = htons(atoi(a->a)), .sin6_addr = in6addr_any};
    if ((fd = socket(AF_INET6, SOCK_STREAM, 0)) < 0) die("socket");
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (a->v6only >= 0) setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &a->v6only, sizeof a->v6only);
    if (bind(fd, (struct sockaddr *)&s, sizeof s) < 0) die("bind");
  } else {
    struct sockaddr_in s = {.sin_family = AF_INET, .sin_port = htons(atoi(a->a)), .sin_addr.s_addr = INADDR_ANY};
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) die("socket");
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(fd, (struct sockaddr *)&s, sizeof s) < 0) die("bind");
  }
  if (listen(fd, a->backlog) < 0) die("listen");
  return fd;
}

static void open_plain(const struct addr *a, int *in, int *out) {
  if (!strcmp(a->kind, "-") || !strcasecmp(a->kind, "STDIO")) { *in = 0; *out = 1; return; }
  int fd = -1;
  if (!strncasecmp(a->kind, "UNIX", 4)) {
    struct sockaddr_un u = {.sun_family = AF_UNIX};
    if (strlen(a->a) >= sizeof u.sun_path) { errno = ENAMETOOLONG; die(a->a); }
    strcpy(u.sun_path, a->a);
    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) die("socket");
    if (connect(fd, (struct sockaddr *)&u, sizeof u) < 0) die(a->a);
  } else if (!strncasecmp(a->kind, "TCP", 3)) {
    struct addrinfo hints = {.ai_socktype = SOCK_STREAM, .ai_family = !strcasecmp(a->kind, "TCP4") ? AF_INET : !strcasecmp(a->kind, "TCP6") ? AF_INET6 : AF_UNSPEC}, *res, *r;
    if (getaddrinfo(a->a, a->b, &hints, &res)) { errno = EHOSTUNREACH; die(a->a); }
    for (r = res; r; r = r->ai_next) {
      if ((fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol)) < 0) continue;
      if (!connect(fd, r->ai_addr, r->ai_addrlen)) break;
      close(fd); fd = -1;
    }
    if (fd < 0) die(a->a);
  } else { errno = EINVAL; die(a->kind); }
  *in = *out = fd;
}

static int pump(int from, int to) {
  char buf[65536]; ssize_t n = read(from, buf, sizeof buf);
  if (n <= 0) return 0;
  for (ssize_t off = 0; off < n;) { ssize_t w = write(to, buf + off, n - off); if (w < 0) { if (errno == EINTR) continue; return 0; } off += w; }
  return 1;
}

static void relay(int in1, int out1, int in2, int out2) {
  int open1 = 1, open2 = 1;
  while (open1 || open2) {
    struct pollfd p[2] = {{open1 ? in1 : -1, POLLIN, 0}, {open2 ? in2 : -1, POLLIN, 0}};
    if (poll(p, 2, -1) < 0) { if (errno == EINTR) continue; break; }
    if (p[0].revents && !pump(in1, out2)) { open1 = 0; shutdown(out2, SHUT_WR); }
    if (p[1].revents && !pump(in2, out1)) { open2 = 0; if (shutdown(out1, SHUT_WR) < 0 && out1 == 1) close(1); }
  }
}

int main(int argc, char **argv) {
  signal(SIGPIPE, SIG_IGN); signal(SIGCHLD, SIG_IGN);
  const char *pos[2]; int n = 0;
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "-V")) { puts("socat stand-in, version 0"); return 0; }
    if (argv[i][0] == '-' && argv[i][1]) continue;
    if (n < 2) pos[n++] = argv[i];
  }
  if (n != 2) { fprintf(stderr, "socat(stand-in): two addresses are needed\n"); return 1; }
  struct addr a, b; parse(pos[0], &a); parse(pos[1], &b);
  if (!is_listen(&a)) { int i1, o1, i2, o2; open_plain(&a, &i1, &o1); open_plain(&b, &i2, &o2); relay(i1, o1, i2, o2); return 0; }
  int l = listen_on(&a);
  for (;;) {
    int c = accept(l, NULL, NULL);
    if (c < 0) { if (errno == EINTR || errno == ECONNABORTED) continue; die("accept"); }
    if (a.fork_) { pid_t pid = fork(); if (pid) { close(c); continue; } close(l); }
    int i2, o2; open_plain(&b, &i2, &o2); relay(c, c, i2, o2);
    return 0;
  }
}
