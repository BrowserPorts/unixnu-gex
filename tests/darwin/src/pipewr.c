// Writes that sleep for room, with no libSystem: one write of more than a
// pipe holds, drained by another thread (all of it written, the call's
// answer the whole size); the same on a stream socket of a socketpair; a
// socket send that finds no room before its first byte and waits for the
// reader; and a pipe write whose reader closes its end while it sleeps
// (EPIPE, with SIGPIPE off on the descriptor).

#define SYS_exit 1
#define SYS_read 3
#define SYS_write 4
#define SYS_close 6
#define SYS_pipe 42
#define SYS_fcntl 92
#define SYS_socketpair 135
#define SYS_bsdthread_create 360
#define SYS_bsdthread_register 366

#define PTHREAD_START_CUSTOM 0x01000000
#define AF_UNIX 1
#define SOCK_STREAM 1
#define F_GETFL 3
#define F_SETFL 4
#define O_NONBLOCK 4
#define F_SETNOSIGPIPE 73
#define EAGAIN 35
#define EPIPE 32

struct ret {
    long x0;
    long x1;
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
    return (struct ret){x0, x1, carry};
}

static unsigned long ticks(void) {
    unsigned long t;
    __asm__ volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(t) : : "memory");
    return t;
}

#define TICKS_PER_MS 24000UL

void thread_start(long self, long port, long func, long arg, long stk, long flags);

// thread_start(pthread, port, func, arg, stack, flags): the function run,
// then the thread ended (bsdthread_terminate).
__asm__(".text\n"
        ".p2align 2\n"
        "_thread_start:\n"
        "    mov x19, x1\n"
        "    mov x0, x3\n"
        "    blr x2\n"
        "    mov x0, #0\n"
        "    mov x1, #0\n"
        "    mov x2, x19\n"
        "    mov x3, #0\n"
        "    mov x16, #361\n"
        "    svc #0x80\n"
        "    brk #1\n");

#define BIG 200000

static unsigned char out[BIG];
static unsigned char in[BIG + 65536];

// What a reader thread is to do, and what it found.
static volatile int rd_fd;
static volatile long rd_want;
static volatile long rd_delay_ms;
static volatile long rd_got;
static volatile long rd_bad;
static volatile long rd_done;

static char stacks[4][1 << 16] __attribute__((aligned(16)));
static char pthreads[4][4096] __attribute__((aligned(16)));
static int made;

// Read rd_want bytes (or up to end of file), checking them against the
// pattern from the start; with rd_want 0, read 1000 bytes and close.
static void reader(long arg) {
    (void)arg;
    if (rd_delay_ms) {
        unsigned long from = ticks();
        while (ticks() - from < rd_delay_ms * TICKS_PER_MS) {
        }
    }
    long got = 0, bad = 0;
    long want = rd_want ? rd_want : 1000;
    while (got < want) {
        long n = want - got < 7000 ? want - got : 7000;
        struct ret r = bsd(SYS_read, rd_fd, (long)(in + got), n, 0, 0);
        if (r.carry || r.x0 == 0) {
            bad |= 1;
            break;
        }
        got += r.x0;
    }
    for (long i = 0; i < got; i++) {
        if (in[i] != (unsigned char)(i * 7 + 3)) {
            bad |= 2;
            break;
        }
    }
    if (!rd_want) {
        bsd(SYS_close, rd_fd, 0, 0, 0, 0);
    }
    rd_got = got;
    rd_bad = bad;
    __atomic_store_n(&rd_done, 1, __ATOMIC_RELEASE);
}

static int spawn_reader(int fd, long want, long delay_ms) {
    rd_fd = fd;
    rd_want = want;
    rd_delay_ms = delay_ms;
    rd_got = 0;
    rd_bad = 0;
    __atomic_store_n(&rd_done, 0, __ATOMIC_RELEASE);
    int i = made++;
    struct ret r = bsd(SYS_bsdthread_create, (long)reader, 0, (long)(stacks[i] + sizeof stacks[i]), (long)pthreads[i], PTHREAD_START_CUSTOM);
    return r.carry ? -1 : 0;
}

static int join_reader(void) {
    unsigned long from = ticks();
    while (__atomic_load_n(&rd_done, __ATOMIC_ACQUIRE) == 0) {
        if (ticks() - from > 20000 * TICKS_PER_MS) {
            return -1;
        }
    }
    return 0;
}

static char line[64];

static void say(const char *what, long code) {
    int n = 0;
    while (*what) {
        line[n++] = *what++;
    }
    line[n++] = ' ';
    char d[24];
    int k = 0;
    unsigned long v = code < 0 ? (unsigned long)-code : (unsigned long)code;
    do {
        d[k++] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    if (code < 0) {
        line[n++] = '-';
    }
    while (k) {
        line[n++] = d[--k];
    }
    line[n++] = '\n';
    bsd(SYS_write, 1, (long)line, n, 0, 0);
}

static int failed;

static void fail(const char *what, long code) {
    say(what, code);
    failed++;
}

// One write of BIG bytes to fd, drained by a reader of rfd.
static void big_write(const char *what, int wfd, int rfd) {
    if (spawn_reader(rfd, BIG, 0) < 0) {
        fail(what, -1);
        return;
    }
    struct ret r = bsd(SYS_write, wfd, (long)out, BIG, 0, 0);
    if (join_reader() < 0) {
        fail(what, -2);
        return;
    }
    if (r.carry) {
        fail(what, r.x0);
    } else if (r.x0 != BIG) {
        fail(what, -3);
    } else if (rd_got != BIG || rd_bad) {
        fail(what, -4 - rd_bad);
    }
}

static const char ok[] = "pipewr ok\n";

void start(void) {
    for (long i = 0; i < BIG; i++) {
        out[i] = (unsigned char)(i * 7 + 3);
    }
    if (bsd(SYS_bsdthread_register, (long)thread_start, 0, 0, 0, 0).carry) {
        fail("register", -1);
        goto end;
    }
    // A pipe.
    struct ret p = bsd(SYS_pipe, 0, 0, 0, 0, 0);
    if (p.carry) {
        fail("pipe", p.x0);
        goto end;
    }
    big_write("pipe-write", (int)p.x1, (int)p.x0);
    // A stream socket.
    int sv[2];
    struct ret s = bsd(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0, (long)sv, 0);
    if (s.carry) {
        fail("socketpair", s.x0);
        goto end;
    }
    big_write("socket-write", sv[0], sv[1]);
    // The socket filled while it does not block, then a blocking write
    // with no room for its first byte: it waits for the reader.
    long fl = bsd(SYS_fcntl, sv[0], F_GETFL, 0, 0, 0).x0;
    bsd(SYS_fcntl, sv[0], F_SETFL, fl | O_NONBLOCK, 0, 0);
    long filled = 0;
    for (;;) {
        long n = 1000;
        struct ret r = bsd(SYS_write, sv[0], (long)(out + filled), n, 0, 0);
        if (r.carry) {
            if (r.x0 != EAGAIN) {
                fail("socket-fill", r.x0);
                goto end;
            }
            break;
        }
        filled += r.x0;
        if (filled + 1000 > BIG) {
            fail("socket-fill", -1);
            goto end;
        }
    }
    bsd(SYS_fcntl, sv[0], F_SETFL, fl, 0, 0);
    if (spawn_reader(sv[1], BIG, 50) < 0) {
        fail("socket-wait", -1);
        goto end;
    }
    struct ret w = bsd(SYS_write, sv[0], (long)(out + filled), BIG - filled, 0, 0);
    if (join_reader() < 0) {
        fail("socket-wait", -2);
    } else if (w.carry) {
        fail("socket-wait", w.x0);
    } else if (w.x0 != BIG - filled) {
        fail("socket-wait", -3);
    } else if (rd_got != BIG || rd_bad) {
        fail("socket-wait", -4 - rd_bad);
    }
    // A pipe whose reader goes away while the write sleeps.
    struct ret q = bsd(SYS_pipe, 0, 0, 0, 0, 0);
    if (q.carry) {
        fail("pipe", q.x0);
        goto end;
    }
    bsd(SYS_fcntl, q.x1, F_SETNOSIGPIPE, 1, 0, 0);
    if (spawn_reader((int)q.x0, 0, 50) < 0) {
        fail("pipe-epipe", -1);
        goto end;
    }
    struct ret e = bsd(SYS_write, q.x1, (long)out, BIG, 0, 0);
    if (join_reader() < 0) {
        fail("pipe-epipe", -2);
    } else if (!e.carry) {
        fail("pipe-epipe", -3);
    } else if (e.x0 != EPIPE) {
        fail("pipe-epipe", e.x0);
    }
end:
    if (failed == 0) {
        bsd(SYS_write, 1, (long)ok, sizeof ok - 1, 0, 0);
    }
    bsd(SYS_exit, failed, 0, 0, 0, 0);
    for (;;) {
    }
}
