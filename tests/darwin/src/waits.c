// Waits in the kernel, with no libSystem: each sleeps on its waiter's wait
// queue until a wake, its deadline or its timeout. kevent until a timer
// knote fires (its thread call wakes the thread), poll and select with no
// descriptors until their timeouts, mach_msg's receive on a reply port
// until MACH_RCV_TIMEOUT's, and __ulock_wait until another thread (made by
// bsdthread_create) wakes it.

#define SYS_exit 1
#define SYS_write 4
#define SYS_select 93
#define SYS_poll 230
#define SYS_bsdthread_create 360
#define SYS_bsdthread_register 366
#define SYS_kqueue 362
#define SYS_kevent 363
#define SYS_ulock_wait 515
#define SYS_ulock_wake 516

#define MACH_reply_port (-26)
#define MACH_msg_trap (-31)

#define EVFILT_TIMER (-7)
#define EV_ADD 0x0001
#define EV_ONESHOT 0x0010
#define UL_COMPARE_AND_WAIT 1
#define PTHREAD_START_CUSTOM 0x01000000
#define MACH_RCV_MSG 0x2
#define MACH_RCV_TIMEOUT 0x100
#define MACH_RCV_TIMED_OUT 0x10004003

struct kev {
    unsigned long ident;
    short filter;
    unsigned short flags;
    unsigned int fflags;
    long data;
    unsigned long udata;
};

struct timespec {
    long tv_sec;
    long tv_nsec;
};

struct timeval {
    long tv_sec;
    int tv_usec;
};

struct ret {
    long x0;
    long carry;
};

static struct ret sys(long nr, long a0, long a1, long a2, long a3, long a4, long a5, long a6) {
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

static unsigned long ticks(void) {
    unsigned long t;
    __asm__ volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(t) : : "memory");
    return t;
}

#define TICKS_PER_MS 24000UL

static volatile unsigned int word;
static char stack[1 << 16] __attribute__((aligned(16)));
static char pthread[4096] __attribute__((aligned(16)));

// The waker: 50 ms of spinning, then the word set and its waiter woken.
static void waker(long arg) {
    unsigned long from = ticks();
    while (ticks() - from < 50 * TICKS_PER_MS) {
    }
    __atomic_store_n(&word, (unsigned int)arg, __ATOMIC_RELEASE);
    sys(SYS_ulock_wake, UL_COMPARE_AND_WAIT, (long)&word, 0, 0, 0, 0, 0);
}

void thread_start(long self, long port, long func, long arg, long stk, long flags);

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

static const char ok[] = "waits ok\n";

void start(void) {
    long status = 0;

    // kevent until a 30 ms timer fires (5 s at most).
    struct ret kq = sys(SYS_kqueue, 0, 0, 0, 0, 0, 0, 0);
    if (kq.carry) {
        status |= 1;
    } else {
        struct kev ch = {1, EVFILT_TIMER, EV_ADD | EV_ONESHOT, 0, 30, 0};
        struct kev ev = {0};
        struct timespec five = {5, 0};
        unsigned long from = ticks();
        struct ret r = sys(SYS_kevent, kq.x0, (long)&ch, 1, (long)&ev, 1, (long)&five, 0);
        if (r.carry || r.x0 != 1 || ev.ident != 1 || ev.filter != EVFILT_TIMER || ev.data < 1) {
            status |= 2;
        }
        if (ticks() - from < 30 * TICKS_PER_MS) {
            status |= 2;
        }
    }

    // poll with nothing to poll, until its 40 ms timeout.
    {
        unsigned long from = ticks();
        struct ret r = sys(SYS_poll, 0, 0, 40, 0, 0, 0, 0);
        if (r.carry || r.x0 != 0 || ticks() - from < 40 * TICKS_PER_MS) {
            status |= 4;
        }
    }

    // select with no descriptors, until its 40 ms timeout.
    {
        struct timeval tv = {0, 40000};
        unsigned long from = ticks();
        struct ret r = sys(SYS_select, 0, 0, 0, 0, (long)&tv, 0, 0);
        if (r.carry || r.x0 != 0 || ticks() - from < 40 * TICKS_PER_MS) {
            status |= 8;
        }
    }

    // A receive on a reply port nothing sends to, until its 30 ms timeout.
    {
        long port = sys(MACH_reply_port, 0, 0, 0, 0, 0, 0, 0).x0;
        unsigned int msg[64] = {0};
        unsigned long from = ticks();
        long kr = sys(MACH_msg_trap, (long)msg, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof msg, port, 30, 0).x0;
        if (port == 0 || kr != MACH_RCV_TIMED_OUT || ticks() - from < 30 * TICKS_PER_MS) {
            status |= 16;
        }
    }

    // __ulock_wait until another thread's __ulock_wake (10 s at most).
    {
        struct ret r = sys(SYS_bsdthread_register, (long)thread_start, 0, 0, 0, 0, 0, 0);
        if (!r.carry) {
            r = sys(SYS_bsdthread_create, (long)waker, 7, (long)(stack + sizeof stack), (long)pthread, PTHREAD_START_CUSTOM, 0, 0);
        }
        if (r.carry) {
            status |= 32;
        } else {
            unsigned long from = ticks();
            while (__atomic_load_n(&word, __ATOMIC_ACQUIRE) == 0) {
                r = sys(SYS_ulock_wait, UL_COMPARE_AND_WAIT, (long)&word, 0, 10000000, 0, 0, 0);
                if (r.carry || ticks() - from > 10000 * TICKS_PER_MS) {
                    status |= 64;
                    break;
                }
            }
            if (word != 7) {
                status |= 64;
            }
        }
    }

    if (status == 0) {
        sys(SYS_write, 1, (long)ok, sizeof ok - 1, 0, 0, 0, 0);
    }
    sys(SYS_exit, status, 0, 0, 0, 0, 0, 0);
    for (;;) {
    }
}
