// A process's own record: its nice value (getpriority, setpriority and
// proc_pidinfo's BSD info read it back), and its task policy (darwin
// background, which setpriority sets and getpriority reads): "ownrec ok".

#define SYS_exit 1
#define SYS_write 4
#define SYS_getpid 20
#define SYS_setpriority 96
#define SYS_getpriority 100
#define SYS_proc_info 336

#define PRIO_PROCESS 0
#define PRIO_DARWIN_PROCESS 4
#define PRIO_DARWIN_BG 0x1000

struct ret {
    long x0;
    long carry;
};

static struct ret sys6(long nr, long a0, long a1, long a2, long a3, long a4, long a5) {
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    register long x16 __asm__("x16") = nr;
    long carry;
    __asm__ volatile("svc #0x80\n\tcset %1, cs" : "+r"(x0), "=r"(carry) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x16) : "memory", "cc");
    return (struct ret){x0, carry};
}

static char line[160];
static int at;

static void put(const char *s) {
    while (*s && at < (int)sizeof line) line[at++] = *s++;
}

static void num(long v) {
    char d[24];
    int n = 0;
    if (v < 0) {
        line[at++] = '-';
        v = -v;
    }
    do {
        d[n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    while (n && at < (int)sizeof line) line[at++] = d[--n];
}

static void say(void) {
    put("\n");
    sys6(SYS_write, 1, (long)line, at, 0, 0, 0);
    at = 0;
}

static int bad(const char *what, long got, long want) {
    put("ownrec: ");
    put(what);
    put(": ");
    num(got);
    put(", want ");
    num(want);
    say();
    return 1;
}

// The value getpriority answers, or minus its errno.
static long prio(int which) {
    struct ret r = sys6(SYS_getpriority, which, 0, 0, 0, 0, 0);
    return r.carry ? -r.x0 : r.x0;
}

// proc_pidinfo(pid, PROC_PIDTBSDINFO)'s pbi_nice.
static long info_nice(long pid) {
    static int bsd[34];
    struct ret r = sys6(SYS_proc_info, 2, pid, 3, 0, (long)bsd, 136);
    if (r.carry || r.x0 != 136) return -1000 - r.x0;
    return bsd[29];
}

static int run(void) {
    long pid = sys6(SYS_getpid, 0, 0, 0, 0, 0, 0).x0;
    long n = prio(PRIO_PROCESS);
    if (n != 0) return bad("its nice value", n, 0);
    if (info_nice(pid) != 0) return bad("its nice value in its BSD info", info_nice(pid), 0);
    struct ret r = sys6(SYS_setpriority, PRIO_PROCESS, 0, 5, 0, 0, 0);
    if (r.carry) return bad("setpriority", r.x0, 0);
    if ((n = prio(PRIO_PROCESS)) != 5) return bad("its nice value after setpriority", n, 5);
    if (info_nice(pid) != 5) return bad("its BSD info's after setpriority", info_nice(pid), 5);
    if ((n = prio(PRIO_DARWIN_PROCESS)) != 0) return bad("its darwin background", n, 0);
    r = sys6(SYS_setpriority, PRIO_DARWIN_PROCESS, 0, PRIO_DARWIN_BG, 0, 0, 0);
    if (r.carry) return bad("setpriority darwin background", r.x0, 0);
    if ((n = prio(PRIO_DARWIN_PROCESS)) != 1) return bad("its darwin background after setpriority", n, 1);
    r = sys6(SYS_setpriority, PRIO_DARWIN_PROCESS, 0, 0, 0, 0, 0);
    if (r.carry) return bad("setpriority darwin foreground", r.x0, 0);
    if ((n = prio(PRIO_DARWIN_PROCESS)) != 0) return bad("its darwin background after clearing it", n, 0);
    put("ownrec ok");
    say();
    return 0;
}

int main_entry(void) {
    sys6(SYS_exit, run(), 0, 0, 0, 0, 0);
    for (;;) {
    }
}

// The entry: a static program's stack has its argc, then its argv, at sp.
__attribute__((naked)) void start(void) {
    __asm__ volatile("b _main_entry");
}
