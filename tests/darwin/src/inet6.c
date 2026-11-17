// The inet6 domain: sockets made as socreate_internal looks their
// protocols up in inet6sw (EPROTOTYPE for a protocol under another type,
// EPROTONOSUPPORT for none, EOPNOTSUPP for one with no user requests, and
// socketpair's EOPNOTSUPP from soconnect2), the socket layer's answers for
// a UDP and a TCP socket bound to nothing (listen, accept, buffer sizes,
// options, readiness), and lo0 through an inet6 socket: its flags, the
// AF_INET address commands in6_control refuses (EINVAL), and its IPv6
// addresses through SIOCAIFADDR_IN6 as in6_control and in6_update_ifa
// check and keep them, launchd's configuration of ::1 among them.
//
// With no argument the program runs as root; "user" runs it as someone
// else, whom the privileged commands refuse (EPERM).

#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <unistd.h>

// struct in6_aliasreq of a 64-bit process (in6_var.h's in6_aliasreq_64).
struct lifetime64 {
    uint64_t expire, preferred;
    uint32_t vltime, pltime;
};
struct aliasreq64 {
    char name[IFNAMSIZ];
    struct sockaddr_in6 addr, dstaddr, prefixmask;
    int flags;
    struct lifetime64 lifetime;
};
_Static_assert(sizeof(struct aliasreq64) == 128, "in6_aliasreq_64");
#define AIFADDR_IN6 _IOW('i', 26, struct aliasreq64)
#define INFINITE 0xffffffffu
#define NODAD 0x20

static const char *who;
static int fail;

static void want(const char *step, int r, int e) {
    int got = r < 0 ? errno : 0;
    if (got != e) {
        printf("inet6 %s: %s: errno %d, want %d\n", who, step, got, e);
        fflush(stdout);
        fail = 1;
    }
}

static void want_eq(const char *step, long got, long e) {
    if (got != e) {
        printf("inet6 %s: %s: %ld, want %ld\n", who, step, got, e);
        fflush(stdout);
        fail = 1;
    }
}

static struct sockaddr_in6 sin6(const char *addr16) {
    struct sockaddr_in6 s;
    memset(&s, 0, sizeof s);
    s.sin6_len = sizeof s;
    s.sin6_family = AF_INET6;
    memcpy(&s.sin6_addr, addr16, 16);
    return s;
}

// lo0, the address, a prefix length's mask, lifetimes infinite.
static struct aliasreq64 req(const char *addr16, int plen) {
    struct aliasreq64 r;
    memset(&r, 0, sizeof r);
    strcpy(r.name, "lo0");
    r.addr = sin6(addr16);
    char mask[16] = {0};
    for (int b = 0; b < plen; b++) mask[b / 8] |= (char)(0x80 >> (b % 8));
    r.prefixmask = sin6(mask);
    r.lifetime.vltime = r.lifetime.pltime = INFINITE;
    return r;
}

static const char LOOPBACK[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
static const char UNSPEC[16] = {0};
static const char MCAST[16] = {(char)0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
static const char MAPPED[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (char)0xff, (char)0xff, 10, 0, 0, 1};
static const char V4COMPAT[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
static const char LL_ZONE2[16] = {(char)0xfe, (char)0x80, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5};
static const char LL7[16] = {(char)0xfe, (char)0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7};
static const char DOC[16] = {0x20, 0x01, 0x0d, (char)0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};

static void aliases(int s) {
    // launchd's own: ::1/128, flags 0, lifetimes infinite; twice.
    struct aliasreq64 r = req(LOOPBACK, 128);
    want("launchd's ::1", ioctl(s, AIFADDR_IN6, &r), 0);
    r = req(LOOPBACK, 128);
    want("::1 again", ioctl(s, AIFADDR_IN6, &r), 0);

    r = req(LOOPBACK, 128);
    r.addr.sin6_len = 16;
    want("a short sockaddr_in6", ioctl(s, AIFADDR_IN6, &r), EAFNOSUPPORT);
    r = req(LOOPBACK, 128);
    r.addr.sin6_family = AF_INET;
    want("another family", ioctl(s, AIFADDR_IN6, &r), EAFNOSUPPORT);
    r = req(UNSPEC, 128);
    want("::", ioctl(s, AIFADDR_IN6, &r), EINVAL);
    r = req(MCAST, 128);
    want("a multicast address", ioctl(s, AIFADDR_IN6, &r), EINVAL);
    r = req(MAPPED, 128);
    want("a v4-mapped address", ioctl(s, AIFADDR_IN6, &r), EINVAL);
    r = req(V4COMPAT, 128);
    want("a v4-compatible address", ioctl(s, AIFADDR_IN6, &r), EINVAL);
    r = req(LL_ZONE2, 128);
    want("a link-local address of another zone", ioctl(s, AIFADDR_IN6, &r), EINVAL);
    r = req(LL7, 128);
    r.addr.sin6_scope_id = 3;
    want("a link-local address of another scope", ioctl(s, AIFADDR_IN6, &r), EINVAL);
    r = req(LOOPBACK, 128);
    r.prefixmask.sin6_len = 0;
    want("a mask of no length", ioctl(s, AIFADDR_IN6, &r), EINVAL);
    r = req(LOOPBACK, 0);
    want("a mask of no bits", ioctl(s, AIFADDR_IN6, &r), EINVAL);
    r = req(LOOPBACK, 128);
    r.lifetime.vltime = 10;
    r.lifetime.pltime = 20;
    want("a preferred lifetime past the valid one", ioctl(s, AIFADDR_IN6, &r), EINVAL);
    r = req(LOOPBACK, 64);
    r.dstaddr = sin6(LOOPBACK);
    want("a destination of a prefix", ioctl(s, AIFADDR_IN6, &r), EINVAL);
    r = req(LOOPBACK, 128);
    r.dstaddr.sin6_family = AF_INET;
    want("a destination of another family", ioctl(s, AIFADDR_IN6, &r), EAFNOSUPPORT);

    // New host addresses: a global one, and a link-local one by its scope.
    r = req(DOC, 128);
    r.flags = NODAD;
    want("2001:db8::2", ioctl(s, AIFADDR_IN6, &r), 0);
    want("2001:db8::2 again", ioctl(s, AIFADDR_IN6, &r), 0);
    r = req(LL7, 128);
    r.addr.sin6_scope_id = 1;
    want("fe80::7%lo0", ioctl(s, AIFADDR_IN6, &r), 0);
}

int main(int argc, char **argv) {
    int user = argc > 1 && strcmp(argv[1], "user") == 0;
    who = user ? "user" : "root";

    // Protocols.
    int u = socket(AF_INET6, SOCK_DGRAM, 0);
    want("a UDP socket", u, 0);
    int t = socket(AF_INET6, SOCK_STREAM, 0);
    want("a TCP socket", t, 0);
    int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    want("IPPROTO_UDP", fd, 0);
    close(fd);
    fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    want("IPPROTO_TCP", fd, 0);
    close(fd);
    want("UDP as a stream", socket(AF_INET6, SOCK_STREAM, IPPROTO_UDP), EPROTOTYPE);
    want("TCP as datagrams", socket(AF_INET6, SOCK_DGRAM, IPPROTO_TCP), EPROTOTYPE);
    want("SOCK_SEQPACKET", socket(AF_INET6, SOCK_SEQPACKET, 0), EPROTONOSUPPORT);
    want("protocol 200", socket(AF_INET6, SOCK_DGRAM, 200), EPROTONOSUPPORT);
    want("IPPROTO_DSTOPTS", socket(AF_INET6, SOCK_RAW, IPPROTO_DSTOPTS), EOPNOTSUPP);
    want("IPPROTO_IPV6 of no type", socket(AF_INET6, 0, IPPROTO_IPV6), EOPNOTSUPP);
    int sv[2];
    want("a stream pair", socketpair(AF_INET6, SOCK_STREAM, 0, sv), EOPNOTSUPP);
    want("a pair of no protocol", socketpair(AF_INET6, SOCK_SEQPACKET, 0, sv), EPROTONOSUPPORT);

    // The socket layer.
    want("listen on UDP", listen(u, 1), EOPNOTSUPP);
    want("accept on UDP", accept(u, NULL, NULL), EOPNOTSUPP);
    want("accept on a TCP socket not listening", accept(t, NULL, NULL), EINVAL);
    int v = 0;
    socklen_t vl = sizeof v;
    want("SO_SNDBUF", getsockopt(u, SOL_SOCKET, SO_SNDBUF, &v, &vl), 0);
    want_eq("UDP's send buffer", v, 9216);
    vl = sizeof v;
    want("SO_RCVBUF", getsockopt(t, SOL_SOCKET, SO_RCVBUF, &v, &vl), 0);
    want_eq("TCP's receive buffer", v, 1448 * 384);
    v = 1;
    want("SO_REUSEADDR", setsockopt(t, SOL_SOCKET, SO_REUSEADDR, &v, sizeof v), 0);
    vl = sizeof v;
    want("SO_REUSEADDR back", getsockopt(t, SOL_SOCKET, SO_REUSEADDR, &v, &vl), 0);
    want_eq("SO_REUSEADDR's bit", v, SO_REUSEADDR);
    want("FIONREAD", ioctl(u, FIONREAD, &v), 0);
    want_eq("bytes to read", v, 0);
    fd_set rd, wr;
    FD_ZERO(&rd);
    FD_ZERO(&wr);
    FD_SET(u, &rd);
    FD_SET(u, &wr);
    FD_SET(t, &rd);
    FD_SET(t, &wr);
    struct timeval zero = {0, 0};
    int n = select((u > t ? u : t) + 1, &rd, &wr, NULL, &zero);
    want_eq("ready", n, 1);
    want_eq("UDP writable", FD_ISSET(u, &wr) != 0, 1);
    want_eq("UDP readable", FD_ISSET(u, &rd) != 0, 0);
    want_eq("TCP writable", FD_ISSET(t, &wr) != 0, 0);
    want_eq("TCP readable", FD_ISSET(t, &rd) != 0, 0);

    // lo0.
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strcpy(ifr.ifr_name, "lo0");
    want("SIOCGIFFLAGS", ioctl(u, SIOCGIFFLAGS, &ifr), 0);
    want_eq("lo0's flags", ifr.ifr_flags & (IFF_LOOPBACK | IFF_MULTICAST), IFF_LOOPBACK | IFF_MULTICAST);
    struct ifaliasreq in4;
    memset(&in4, 0, sizeof in4);
    strcpy(in4.ifra_name, "lo0");
    want("SIOCAIFADDR on an inet6 socket", ioctl(u, SIOCAIFADDR, &in4), EINVAL);
    want("SIOCGIFADDR on an inet6 socket", ioctl(u, SIOCGIFADDR, &ifr), EINVAL);
    if (user) {
        want("SIOCSIFFLAGS", ioctl(u, SIOCSIFFLAGS, &ifr), EPERM);
        struct aliasreq64 r = req(LOOPBACK, 128);
        want("SIOCAIFADDR_IN6", ioctl(u, AIFADDR_IN6, &r), EPERM);
    } else {
        aliases(u);
        want("SIOCGIFFLAGS again", ioctl(t, SIOCGIFFLAGS, &ifr), 0);
        want_eq("lo0's flags again", ifr.ifr_flags & (IFF_LOOPBACK | IFF_MULTICAST), IFF_LOOPBACK | IFF_MULTICAST);
    }
    close(u);
    close(t);
    if (!fail) printf("inet6 %s ok\n", who);
    return fail;
}
