// The calls that read a thread's processor time, with no libSystem:
// getrusage of the process and of its reaped children, thread_selfusage,
// the virtual and profiling timers, RLIMIT_CPU and thread_info's
// THREAD_BASIC_INFO. Each must succeed; one that fails is named with its
// error (an errno, or thread_info's kern_return_t), one line each.

#define SYS_exit 1
#define SYS_write 4
#define SYS_setitimer 83
#define SYS_getitimer 86
#define SYS_getrusage 117
#define SYS_getrlimit 194
#define SYS_setrlimit 195
#define SYS_thread_selfusage 482

#define MACH_reply_port (-26)
#define MACH_thread_self (-27)
#define MACH_msg2_trap (-47)

#define RUSAGE_SELF 0
#define RUSAGE_CHILDREN (-1)
#define ITIMER_VIRTUAL 1
#define ITIMER_PROF 2
#define RLIMIT_CPU 0

#define MACH_SEND_MSG 0x1
#define MACH_RCV_MSG 0x2
#define MACH64_SEND_KOBJECT_CALL 0x200000000UL
#define MACH_MSG_TYPE_COPY_SEND 19
#define MACH_MSG_TYPE_MAKE_SEND_ONCE 21
#define THREAD_BASIC_INFO 3
#define THREAD_BASIC_INFO_COUNT 10

struct ret {
    long x0;
    long carry;
};

static struct ret sys(long nr, long a0, long a1, long a2) {
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x16 __asm__("x16") = nr;
    long carry;
    __asm__ volatile("svc #0x80\n\tcset %1, cs" : "+r"(x0), "=r"(carry), "+r"(x1) : "r"(x2), "r"(x16) : "memory", "cc");
    return (struct ret){x0, carry};
}

// mach_msg2_trap(data, options, bits|send_size, remote|local, voucher|id,
// desc_count|rcv_name, rcv_size|priority, timeout).
static long msg2(void *data, unsigned long options, unsigned long a2, unsigned long a3, unsigned long a4, unsigned long a5, unsigned long a6) {
    register long x0 __asm__("x0") = (long)data;
    register unsigned long x1 __asm__("x1") = options;
    register unsigned long x2 __asm__("x2") = a2;
    register unsigned long x3 __asm__("x3") = a3;
    register unsigned long x4 __asm__("x4") = a4;
    register unsigned long x5 __asm__("x5") = a5;
    register unsigned long x6 __asm__("x6") = a6;
    register unsigned long x7 __asm__("x7") = 0;
    register long x16 __asm__("x16") = MACH_msg2_trap;
    __asm__ volatile("svc #0x80"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x6), "r"(x7), "r"(x16)
                     : "memory", "cc");
    return x0;
}

static char line[64];

// "NAME CODE\n" written out.
static void say(const char *name, long code) {
    int n = 0;
    while (*name) {
        line[n++] = *name++;
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
    sys(SYS_write, 1, (long)line, n);
}

static int failed;

static void check(const char *name, struct ret r) {
    if (r.carry) {
        say(name, r.x0);
        failed++;
    }
}

// thread_info(thread, THREAD_BASIC_INFO): thread_act.defs routine 12, its
// request the flavor and the count asked, its reply's RetCode in word 8.
static long basic_info(unsigned int port, unsigned int reply, unsigned int out[THREAD_BASIC_INFO_COUNT]) {
    unsigned int msg[48] = {0};
    unsigned int bits = MACH_MSG_TYPE_COPY_SEND | (MACH_MSG_TYPE_MAKE_SEND_ONCE << 8);
    msg[0] = bits;
    msg[1] = 40;
    msg[2] = port;
    msg[3] = reply;
    msg[5] = 3612;
    msg[7] = 1; // NDR_record: little-endian integers
    msg[8] = THREAD_BASIC_INFO;
    msg[9] = THREAD_BASIC_INFO_COUNT;
    long kr = msg2(msg, MACH_SEND_MSG | MACH_RCV_MSG | MACH64_SEND_KOBJECT_CALL, bits | (40UL << 32), port | ((unsigned long)reply << 32),
                   3612UL << 32, (unsigned long)reply << 32, sizeof msg);
    if (kr != 0) {
        return kr;
    }
    if (msg[5] != 3712) {
        return -1;
    }
    if (msg[8] != 0) {
        return (int)msg[8];
    }
    if (msg[9] != THREAD_BASIC_INFO_COUNT) {
        return -2;
    }
    for (int i = 0; i < THREAD_BASIC_INFO_COUNT; i++) {
        out[i] = msg[10 + i];
    }
    return 0;
}

static const char ok[] = "cpuclk ok\n";

void start(void) {
    long ru[18];
    check("getrusage-self", sys(SYS_getrusage, RUSAGE_SELF, (long)ru, 0));
    check("getrusage-children", sys(SYS_getrusage, RUSAGE_CHILDREN, (long)ru, 0));
    check("thread_selfusage", sys(SYS_thread_selfusage, 0, 0, 0));
    // Ten seconds of the threads' time, set, read back and taken off.
    long itv[4] = {0, 0, 10, 0};
    long zero[4] = {0, 0, 0, 0};
    long back[4];
    struct ret r = sys(SYS_setitimer, ITIMER_VIRTUAL, (long)itv, 0);
    check("setitimer-virtual", r);
    if (!r.carry) {
        check("getitimer-virtual", sys(SYS_getitimer, ITIMER_VIRTUAL, (long)back, 0));
        check("setitimer-virtual-off", sys(SYS_setitimer, ITIMER_VIRTUAL, (long)zero, 0));
    }
    r = sys(SYS_setitimer, ITIMER_PROF, (long)itv, 0);
    check("setitimer-prof", r);
    if (!r.carry) {
        check("getitimer-prof", sys(SYS_getitimer, ITIMER_PROF, (long)back, 0));
        check("setitimer-prof-off", sys(SYS_setitimer, ITIMER_PROF, (long)zero, 0));
    }
    // A thousand seconds' RLIMIT_CPU, then none again.
    unsigned long lim[2];
    r = sys(SYS_getrlimit, RLIMIT_CPU, (long)lim, 0);
    check("getrlimit-cpu", r);
    if (!r.carry) {
        unsigned long was = lim[0];
        lim[0] = 1000;
        r = sys(SYS_setrlimit, RLIMIT_CPU, (long)lim, 0);
        check("setrlimit-cpu", r);
        if (!r.carry) {
            lim[0] = was;
            check("setrlimit-cpu-back", sys(SYS_setrlimit, RLIMIT_CPU, (long)lim, 0));
        }
    }
    unsigned int reply = (unsigned int)sys(MACH_reply_port, 0, 0, 0).x0;
    unsigned int self = (unsigned int)sys(MACH_thread_self, 0, 0, 0).x0;
    unsigned int info[THREAD_BASIC_INFO_COUNT];
    long kr = basic_info(self, reply, info);
    if (kr != 0) {
        say("thread_info", kr);
        failed++;
    }
    if (failed == 0) {
        sys(SYS_write, 1, (long)ok, sizeof ok - 1);
    }
    sys(SYS_exit, failed, 0, 0);
    for (;;) {
    }
}
