// The system's identifiers and its clock, as one process sees them: its
// unique id and pidversion (proc_info PROC_PIDUNIQIDENTIFIERINFO), its
// thread's unique id (thread_selfid) and the counter (mach_absolute_time's,
// CNTVCT). Each is the system's, taken from one counter or measured from
// one origin for every process: a later process has larger ones. They go
// to stderr, for a caller that runs it twice to compare; stdout has
// "sysids ok" when each is one the kernel could give.

#define SYS_exit 1
#define SYS_write 4
#define SYS_getpid 20
#define SYS_proc_info 336
#define SYS_thread_selfid 372

#define PROC_INFO_CALL_PIDINFO 2
#define PROC_PIDUNIQIDENTIFIERINFO 17

struct uniq {
    unsigned char uuid[16];
    unsigned long uniqueid;
    unsigned long puniqueid;
    int idversion;
    unsigned int reserve2;
    unsigned long reserve3;
    unsigned long reserve4;
};

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

static char line[160];
static int at;

static void put(const char *s) {
    while (*s && at < (int)sizeof line) line[at++] = *s++;
}

static void num(unsigned long v) {
    char d[24];
    int n = 0;
    do {
        d[n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    while (n && at < (int)sizeof line) line[at++] = d[--n];
}

static const char ok[] = "sysids ok\n";

void start(void) {
    long status = 0;
    unsigned long abs = ticks();
    struct uniq u = {0};
    long pid = bsd(SYS_getpid, 0, 0, 0, 0, 0, 0).x0;
    struct ret r = bsd(SYS_proc_info, PROC_INFO_CALL_PIDINFO, pid, PROC_PIDUNIQIDENTIFIERINFO, 0, (long)&u, sizeof u);
    if (r.carry || r.x0 != (long)sizeof u || u.uniqueid == 0 || u.idversion < 0) {
        status |= 1;
    }
    struct ret t = bsd(SYS_thread_selfid, 0, 0, 0, 0, 0, 0);
    // thread_unique_id: the first is 101.
    if (t.carry || t.x0 < 101) {
        status |= 2;
    }
    put("sysids uniqueid=");
    num(u.uniqueid);
    put(" pidversion=");
    num((unsigned long)(unsigned int)u.idversion);
    put(" thread=");
    num((unsigned long)t.x0);
    put(" abs=");
    num(abs);
    put("\n");
    bsd(SYS_write, 2, (long)line, at, 0, 0, 0);
    if (status == 0) {
        bsd(SYS_write, 1, (long)ok, sizeof ok - 1, 0, 0, 0);
    }
    bsd(SYS_exit, status, 0, 0, 0, 0, 0);
    for (;;) {
    }
}
