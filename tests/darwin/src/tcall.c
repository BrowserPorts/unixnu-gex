// The kernel's thread calls and the commpage's quantum update, seen by a
// thread that makes no call that waits. An EVFILT_TIMER knote is fired by
// its thread call (filt_timerexpire) while the thread polls its kqueue
// with kevent64's KEVENT_FLAG_IMMEDIATE, which never waits; and the
// commpage's approximate time moves on while the thread spins without
// entering the kernel at all.

#define SYS_exit 1
#define SYS_write 4
#define SYS_kqueue 362
#define SYS_kevent64 369

#define COMM_PAGE 0x0000000FFFFFC000UL
#define APPROX_TIME 0x0c0
#define APPROX_TIME_SUPPORTED 0x0c8

#define EVFILT_TIMER (-7)
#define EV_ADD 0x0001
#define EV_ONESHOT 0x0010
#define KEVENT_FLAG_IMMEDIATE 0x1

struct kevent64_s {
    unsigned long ident;
    short filter;
    unsigned short flags;
    unsigned int fflags;
    long data;
    unsigned long udata;
    unsigned long ext[2];
};

struct ret {
    long x0;
    long carry;
};

static struct ret bsd(long nr, long a0, long a1, long a2, long a3, long a4, long a5, long a6) {
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    register long x6 __asm__("x6") = a6;
    register long x16 __asm__("x16") = nr;
    long carry;
    __asm__ volatile("svc #0x80\n\tcset %1, cs"
                     : "+r"(x0), "=r"(carry)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x6), "r"(x16)
                     : "memory", "cc");
    return (struct ret){x0, carry};
}

// mach_absolute_time's counter: 24 MHz (the timebase is 125/3).
static unsigned long ticks(void) {
    unsigned long t;
    __asm__ volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(t) : : "memory");
    return t;
}

#define TICKS_PER_MS 24000UL

static const char ok[] = "tcall ok\n";

void start(void) {
    long status = 0;

    // A 30 ms one-shot timer, looked for without waiting until it fires
    // (5 s at most).
    struct ret kq = bsd(SYS_kqueue, 0, 0, 0, 0, 0, 0, 0);
    if (kq.carry) {
        status |= 1;
    } else {
        struct kevent64_s ch = {1, EVFILT_TIMER, EV_ADD | EV_ONESHOT, 0, 30, 0, {0, 0}};
        struct ret r = bsd(SYS_kevent64, kq.x0, (long)&ch, 1, 0, 0, KEVENT_FLAG_IMMEDIATE, 0);
        if (r.carry || r.x0 != 0) {
            status |= 2;
        }
        unsigned long armed = ticks();
        struct kevent64_s ev = {0};
        for (;;) {
            r = bsd(SYS_kevent64, kq.x0, 0, 0, (long)&ev, 1, KEVENT_FLAG_IMMEDIATE, 0);
            if (r.carry) {
                status |= 4;
                break;
            }
            if (r.x0 == 1) {
                // Fired, not before its deadline: its data the intervals
                // gone by when it was read (filt_timerprocess), one or
                // more as the poll comes late.
                if (ev.ident != 1 || ev.filter != EVFILT_TIMER || ev.data < 1) {
                    status |= 8;
                }
                if (ticks() - armed < 30 * TICKS_PER_MS) {
                    status |= 16;
                }
                break;
            }
            if (ticks() - armed > 5000 * TICKS_PER_MS) {
                status |= 32;
                break;
            }
        }
    }

    // The approximate time, which the kernel keeps a quantum (10 ms) behind
    // at most: after 50 ms of spinning, it has moved on.
    const volatile unsigned long *approx = (const volatile unsigned long *)(COMM_PAGE + APPROX_TIME);
    if (*(const volatile unsigned char *)(COMM_PAGE + APPROX_TIME_SUPPORTED) != 1) {
        status |= 64;
    }
    unsigned long before = *approx;
    unsigned long from = ticks();
    while (ticks() - from < 50 * TICKS_PER_MS) {
    }
    if (*approx <= before) {
        status |= 128;
    }

    if (status == 0) {
        bsd(SYS_write, 1, (long)ok, sizeof ok - 1, 0, 0, 0, 0);
    }
    bsd(SYS_exit, status, 0, 0, 0, 0, 0, 0);
    for (;;) {
    }
}
