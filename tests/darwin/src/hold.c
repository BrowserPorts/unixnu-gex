// A thread held on its way back to user space, with no libSystem: another
// thread spins without a system call while the main thread suspends it
// (thread_suspend, a MIG request on its thread port, answered once it is
// off its processor), finds it stays still, resumes it (thread_resume)
// and finds it running again.

#define SYS_exit 1
#define SYS_write 4
#define SYS_bsdthread_create 360
#define SYS_bsdthread_register 366

#define MACH_reply_port (-26)
#define MACH_msg2_trap (-47)

#define PTHREAD_START_CUSTOM 0x01000000
#define MACH_SEND_MSG 0x1
#define MACH_RCV_MSG 0x2
#define MACH64_SEND_KOBJECT_CALL 0x200000000UL
#define MACH_MSG_TYPE_COPY_SEND 19
#define MACH_MSG_TYPE_MAKE_SEND_ONCE 21

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

static volatile unsigned long counter;
// The spinning thread's port, as thread_start was given it.
volatile unsigned long its_port;
static char stack[1 << 16] __attribute__((aligned(16)));
static char pthread[4096] __attribute__((aligned(16)));

static void spin(long arg) {
    for (;;) {
        __atomic_fetch_add(&counter, (unsigned long)arg, __ATOMIC_RELAXED);
    }
}

void thread_start(long self, long port, long func, long arg, long stk, long flags);

__asm__(".text\n"
        ".p2align 2\n"
        "_thread_start:\n"
        "    adrp x9, _its_port@PAGE\n"
        "    str x1, [x9, _its_port@PAGEOFF]\n"
        "    mov x0, x3\n"
        "    blr x2\n"
        "    brk #1\n");

// mach_msg2_trap(data, options, bits|send_size, remote|local, voucher|id,
// desc_count|rcv_name, rcv_size|priority, timeout), as libsystem_kernel's
// mach_msg makes it.
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

// A routine of thread_act.defs with no argument but its thread: the
// request is the header alone, the reply mig_reply_error_t's RetCode.
static long thread_call(unsigned int port, unsigned int reply, int id) {
    unsigned int msg[16] = {0};
    unsigned int bits = MACH_MSG_TYPE_COPY_SEND | (MACH_MSG_TYPE_MAKE_SEND_ONCE << 8);
    msg[0] = bits;
    msg[1] = 24;
    msg[2] = port;
    msg[3] = reply;
    msg[4] = 0;
    msg[5] = (unsigned int)id;
    long kr = msg2(msg, MACH_SEND_MSG | MACH_RCV_MSG | MACH64_SEND_KOBJECT_CALL, bits | (24UL << 32), port | ((unsigned long)reply << 32),
                   (unsigned long)(unsigned int)id << 32, (unsigned long)reply << 32, sizeof msg);
    if (kr != 0) {
        return kr;
    }
    if (msg[5] != (unsigned int)id + 100) {
        return -1;
    }
    return (int)msg[8];
}

static const char ok[] = "hold ok\n";

void start(void) {
    long status = 0;
    struct ret r = sys(SYS_bsdthread_register, (long)thread_start, 0, 0, 0, 0, 0, 0);
    if (!r.carry) {
        r = sys(SYS_bsdthread_create, (long)spin, 1, (long)(stack + sizeof stack), (long)pthread, PTHREAD_START_CUSTOM, 0, 0);
    }
    if (r.carry) {
        status |= 1;
        goto out;
    }
    unsigned long from = ticks();
    while (__atomic_load_n(&counter, __ATOMIC_RELAXED) == 0) {
        if (ticks() - from > 10000 * TICKS_PER_MS) {
            status |= 2;
            goto out;
        }
    }
    unsigned int reply = (unsigned int)sys(MACH_reply_port, 0, 0, 0, 0, 0, 0, 0).x0;
    unsigned int port = (unsigned int)its_port;
    // thread_suspend: answered once the thread is off its processor, held.
    if (thread_call(port, reply, 3605) != 0) {
        status |= 4;
        goto out;
    }
    unsigned long held = __atomic_load_n(&counter, __ATOMIC_RELAXED);
    from = ticks();
    while (ticks() - from < 50 * TICKS_PER_MS) {
    }
    if (__atomic_load_n(&counter, __ATOMIC_RELAXED) != held) {
        status |= 8;
    }
    // thread_resume: let go, it runs on.
    if (thread_call(port, reply, 3606) != 0) {
        status |= 16;
        goto out;
    }
    from = ticks();
    while (__atomic_load_n(&counter, __ATOMIC_RELAXED) == held) {
        if (ticks() - from > 10000 * TICKS_PER_MS) {
            status |= 32;
            break;
        }
    }
out:
    if (status == 0) {
        sys(SYS_write, 1, (long)ok, sizeof ok - 1, 0, 0, 0, 0);
    }
    sys(SYS_exit, status, 0, 0, 0, 0, 0, 0);
    for (;;) {
    }
}
