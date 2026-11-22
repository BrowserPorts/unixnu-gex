// A unix stream socket bound to a name, with no libSystem: a listener and
// a client of the same process meet by the name, and what XNU says of
// either end (its address, its peer's, a second bind to
// the name, a connect to a name nothing is bound to, its buffers and how
// much a write that does not block puts in) is checked against what XNU
// answers: "unixname ok", or what the calls said.

#define SYS_exit 1
#define SYS_read 3
#define SYS_write 4
#define SYS_close 6
#define SYS_unlink 10
#define SYS_accept 30
#define SYS_getpeername 31
#define SYS_getsockname 32
#define SYS_socket 97
#define SYS_connect 98
#define SYS_bind 104
#define SYS_listen 106
#define SYS_fcntl 92
#define SYS_getsockopt 118

#define AF_UNIX 1
#define SOCK_STREAM 1
#define SOL_SOCKET 0xffff
#define SO_SNDBUF 0x1001
#define SO_RCVBUF 0x1002
#define F_SETFL 4
#define O_NONBLOCK 4

struct ret {
    long x0;
    long carry;
};

static struct ret bsd(long nr, long a0, long a1, long a2, long a3, long a4) {
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x16 __asm__("x16") = nr;
    long carry;
    __asm__ volatile("svc #0x80\n\tcset %2, cs"
                     : "+r"(x0), "+r"(x1), "=r"(carry)
                     : "r"(x2), "r"(x3), "r"(x4), "r"(x16)
                     : "memory", "cc");
    return (struct ret){x0, carry};
}

struct sun {
    unsigned char len;
    unsigned char family;
    char path[104];
};

// What the calls said, one line each.
static char line[1024];
static int at;

static void put(const char *s) {
    while (*s) {
        line[at++] = *s++;
    }
}

static void num(long v) {
    char d[24];
    int k = 0;
    unsigned long u = v < 0 ? (unsigned long)-v : (unsigned long)v;
    do {
        d[k++] = (char)('0' + u % 10);
        u /= 10;
    } while (u);
    if (v < 0) {
        line[at++] = '-';
    }
    while (k) {
        line[at++] = d[--k];
    }
}

static void end(void) {
    line[at++] = '\n';
}

// A call's answer: its value, or its error negated.
static long answer(struct ret r) {
    return r.carry ? -r.x0 : r.x0;
}

static void say(const char *what, long v) {
    put(what);
    put(" ");
    num(v);
    end();
}

// An address as `len family path`.
static void addr(const char *what, long r, unsigned int len, struct sun *a) {
    put(what);
    put(" ");
    num(r);
    put(" ");
    num(len);
    if (r == 0 && len >= 2) {
        put(" ");
        num(a->len);
        put(" ");
        num(a->family);
        put(" ");
        for (unsigned int i = 2; i < len && a->path[i - 2]; i++) {
            line[at++] = a->path[i - 2];
        }
    }
    end();
}

static const char NAME[] = "/var/tmp/unixname.sock";
static const char NONE[] = "/var/tmp/unixname.none";

static unsigned int fill(struct sun *a, const char *p) {
    unsigned int n = 0;
    while (p[n]) {
        a->path[n] = p[n];
        n++;
    }
    a->path[n] = 0;
    a->family = AF_UNIX;
    a->len = (unsigned char)(2 + n + 1);
    return a->len;
}

void start(void) {
    static struct sun a, b, got;
    unsigned int alen = fill(&a, NAME);
    unsigned int nlen = fill(&b, NONE);
    bsd(SYS_unlink, (long)NAME, 0, 0, 0, 0);
    long s = answer(bsd(SYS_socket, AF_UNIX, SOCK_STREAM, 0, 0, 0));
    long c = answer(bsd(SYS_socket, AF_UNIX, SOCK_STREAM, 0, 0, 0));
    long d = answer(bsd(SYS_socket, AF_UNIX, SOCK_STREAM, 0, 0, 0));
    long e = answer(bsd(SYS_socket, AF_UNIX, SOCK_STREAM, 0, 0, 0));
    if (s < 0 || c < 0 || d < 0 || e < 0) {
        say("socket", s < 0 ? s : c < 0 ? c : d < 0 ? d : e);
        bsd(SYS_write, 1, (long)line, at, 0, 0);
        bsd(SYS_exit, 1, 0, 0, 0, 0);
    }
    say("bind", answer(bsd(SYS_bind, s, (long)&a, alen, 0, 0)));
    say("listen", answer(bsd(SYS_listen, s, 5, 0, 0, 0)));
    say("bind-again", answer(bsd(SYS_bind, d, (long)&a, alen, 0, 0)));
    say("connect-none", answer(bsd(SYS_connect, e, (long)&b, nlen, 0, 0)));
    say("connect", answer(bsd(SYS_connect, c, (long)&a, alen, 0, 0)));
    unsigned int len = sizeof got;
    long x = answer(bsd(SYS_accept, s, (long)&got, (long)&len, 0, 0));
    addr("accept", x < 0 ? x : 0, len, &got);
    if (x < 0) {
        bsd(SYS_write, 1, (long)line, at, 0, 0);
        bsd(SYS_exit, 1, 0, 0, 0, 0);
    }
    len = sizeof got;
    addr("sockname", answer(bsd(SYS_getsockname, s, (long)&got, (long)&len, 0, 0)), len, &got);
    len = sizeof got;
    addr("peername", answer(bsd(SYS_getpeername, c, (long)&got, (long)&len, 0, 0)), len, &got);
    len = sizeof got;
    addr("accepted-peername", answer(bsd(SYS_getpeername, x, (long)&got, (long)&len, 0, 0)), len, &got);
    int v = 0;
    len = sizeof v;
    long r = answer(bsd(SYS_getsockopt, c, SOL_SOCKET, SO_SNDBUF, (long)&v, (long)&len));
    say("sndbuf", r < 0 ? r : v);
    len = sizeof v;
    r = answer(bsd(SYS_getsockopt, x, SOL_SOCKET, SO_RCVBUF, (long)&v, (long)&len));
    say("rcvbuf", r < 0 ? r : v);
    say("write", answer(bsd(SYS_write, c, (long)"unix", 4, 0, 0)));
    static char buf[1000];
    say("read", answer(bsd(SYS_read, x, (long)buf, 8, 0, 0)));
    // What the stream takes before a write that does not block would.
    bsd(SYS_fcntl, c, F_SETFL, O_NONBLOCK, 0, 0);
    long filled = 0;
    for (;;) {
        r = answer(bsd(SYS_write, c, (long)buf, sizeof buf, 0, 0));
        if (r <= 0) {
            break;
        }
        filled += r;
    }
    say("filled", filled);
    say("full", r);
    long drained = 0;
    while ((r = answer(bsd(SYS_read, x, (long)buf, sizeof buf, 0, 0))) > 0 && (drained += r) < filled) {
    }
    say("drained", drained);
    bsd(SYS_close, c, 0, 0, 0, 0);
    say("read-eof", answer(bsd(SYS_read, x, (long)buf, sizeof buf, 0, 0)));
    bsd(SYS_close, x, 0, 0, 0, 0);
    bsd(SYS_close, s, 0, 0, 0, 0);
    say("unlink", answer(bsd(SYS_unlink, (long)NAME, 0, 0, 0, 0)));
    // As XNU answers: EADDRINUSE for a name in use, ENOENT for a name with
    // no file (unp_connect's lookup); the bound name as bind gave it
    // (sun_len 25) on the listener and on its client's peer; an unnamed
    // peer as sun_noname (a 16-byte sockaddr of AF_UNIX); a unix stream's
    // buffers of 8192 (unpst_sendspace, unpst_recvspace); and a write that
    // does not block refused (EWOULDBLOCK) once less than the send buffer's
    // low-water mark (2048) is left: 8000 bytes in 1000-byte writes.
    static const char want[] = "bind 0\nlisten 0\nbind-again -48\nconnect-none -2\nconnect 0\n"
                               "accept 0 16 16 1 \nsockname 0 25 25 1 /var/tmp/unixname.sock\n"
                               "peername 0 25 25 1 /var/tmp/unixname.sock\naccepted-peername 0 16 16 1 \n"
                               "sndbuf 8192\nrcvbuf 8192\nwrite 4\nread 4\nfilled 8000\nfull -35\n"
                               "drained 8000\nread-eof 0\nunlink 0\n";
    int same = at == (int)sizeof want - 1;
    for (int i = 0; same && i < at; i++) {
        same = line[i] == want[i];
    }
    if (!same) {
        bsd(SYS_write, 1, (long)line, at, 0, 0);
        bsd(SYS_exit, 1, 0, 0, 0, 0);
    }
    bsd(SYS_write, 1, (long)"unixname ok\n", 12, 0, 0);
    bsd(SYS_exit, 0, 0, 0, 0, 0);
    for (;;) {
    }
}
