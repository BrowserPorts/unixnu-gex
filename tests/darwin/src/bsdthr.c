// A thread made by bsdthread_create, with no libpthread: it starts at the
// thread_start bsdthread_register named, with the pthread, its port, the
// function, its argument, its stack and the flags in x0-x5 and its stack
// pointer at the stack given; it runs the function, which makes a call of
// its own, and ends with bsdthread_terminate. The main thread waits for it
// without a call that waits.

#define SYS_exit 1
#define SYS_write 4
#define SYS_getpid 20
#define SYS_bsdthread_create 360
#define SYS_bsdthread_terminate 361
#define SYS_bsdthread_register 366

#define PTHREAD_START_CUSTOM 0x01000000

struct ret {
    long x0;
    long carry;
};

static struct ret bsd(long nr, long a0, long a1, long a2, long a3, long a4, long a5) {
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    register long x16 __asm__("x16") = nr;
    long carry;
    __asm__ volatile("svc #0x80\n\tcset %1, cs"
                     : "+r"(x0), "=r"(carry)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x16)
                     : "memory", "cc");
    return (struct ret){x0, carry};
}

static unsigned long ticks(void) {
    unsigned long t;
    __asm__ volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(t) : : "memory");
    return t;
}

#define TICKS_PER_MS 24000UL

// What the thread saw at its start, and what it left.
static volatile long seen[6];
static volatile long done;
static volatile long its_pid;

static char stack[1 << 16] __attribute__((aligned(16)));
static char pthread[4096] __attribute__((aligned(16)));

static void work(long arg) {
    struct ret p = bsd(SYS_getpid, 0, 0, 0, 0, 0, 0);
    its_pid = p.carry ? -1 : p.x0;
    __atomic_store_n(&done, arg, __ATOMIC_RELEASE);
}

void thread_start(long self, long port, long func, long arg, long stk, long flags);

// thread_start(pthread, port, func, arg, stack, flags): what it was given
// noted, the function run, and the thread ended.
__asm__(".text\n"
        ".p2align 2\n"
        "_thread_start:\n"
        "    mov x19, x1\n"
        "    adrp x9, _seen@PAGE\n"
        "    add x9, x9, _seen@PAGEOFF\n"
        "    stp x0, x1, [x9]\n"
        "    stp x2, x3, [x9, #16]\n"
        "    stp x4, x5, [x9, #32]\n"
        "    mov x0, x3\n"
        "    blr x2\n"
        "    mov x0, #0\n"
        "    mov x1, #0\n"
        "    mov x2, x19\n"
        "    mov x3, #0\n"
        "    mov x16, #361\n"
        "    svc #0x80\n"
        "    brk #1\n");

static const char ok[] = "bsdthr ok\n";

void start(void) {
    long status = 0;
    struct ret r = bsd(SYS_bsdthread_register, (long)thread_start, 0, 0, 0, 0, 0);
    if (r.carry) {
        status |= 1;
        goto out;
    }
    long top = (long)(stack + sizeof stack);
    r = bsd(SYS_bsdthread_create, (long)work, 0x5eed, top, (long)pthread, PTHREAD_START_CUSTOM, 0);
    if (r.carry || r.x0 != (long)pthread) {
        status |= 2;
        goto out;
    }
    unsigned long from = ticks();
    while (__atomic_load_n(&done, __ATOMIC_ACQUIRE) == 0) {
        if (ticks() - from > 10000 * TICKS_PER_MS) {
            status |= 4;
            goto out;
        }
    }
    if (done != 0x5eed) {
        status |= 8;
    }
    // Its registers at its start.
    if (seen[0] != (long)pthread || seen[2] != (long)work || seen[3] != 0x5eed || seen[4] != top) {
        status |= 16;
    }
    if (seen[1] == 0 || (seen[5] & PTHREAD_START_CUSTOM) == 0) {
        status |= 32;
    }
    struct ret me = bsd(SYS_getpid, 0, 0, 0, 0, 0, 0);
    if (its_pid != me.x0) {
        status |= 64;
    }
out:
    if (status == 0) {
        bsd(SYS_write, 1, (long)ok, sizeof ok - 1, 0, 0, 0);
    }
    bsd(SYS_exit, status, 0, 0, 0, 0, 0);
    for (;;) {
    }
}
