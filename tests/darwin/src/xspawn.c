// posix_spawn of a static executable, which a RELEASE kernel refuses
// (xnu-10063 mach_loader.c parse_machfile: an MH_EXECUTE without
// MH_DYLDLINK is LOAD_FAILURE but on DEVELOPMENT and DEBUG kernels, which
// exec_mach_imgact's load_return_to_errno makes EBADEXEC). The program
// spawns itself, with no attributes or file actions: the call fails with
// EBADEXEC in the spawner's call, the child ended unseen (exit1 with
// P_LIST_DEADPARENT), so wait4 then finds no child (ECHILD). "xspawn E W":
// E posix_spawn's errno, W wait4's.
//
// (A spawned child that runs, its exit status and usage collected by wait4,
// needs a dynamic program: one the page can run once it has dyld and the
// shared cache.)

#define SYS_exit 1
#define SYS_write 4
#define SYS_wait4 7
#define SYS_posix_spawn 244

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

static char line[64];
static int at;

static void put(const char *s) {
    while (*s && at < (int)sizeof line) line[at++] = *s++;
}

static void num(long v) {
    char d[24];
    int n = 0;
    if (v < 0) {
        put("-");
        v = -v;
    }
    do {
        d[n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    while (n && at < (int)sizeof line) line[at++] = d[--n];
}

static int run(int argc, char **argv) {
    char **envp = argv + argc + 1;
    // Never run: the spawn of this static image is refused.
    if (argc != 1) return 64;
    char *args[] = {argv[0], "child", 0};
    int pid = 0;
    struct ret r = bsd(SYS_posix_spawn, (long)&pid, (long)argv[0], 0, (long)args, (long)envp, 0);
    // The errno, or -1 for a spawn that did not fail.
    long spawned = r.carry ? r.x0 : -1;
    int st = 0;
    r = bsd(SYS_wait4, -1, (long)&st, 0, 0, 0, 0);
    long waited = r.carry ? r.x0 : -1;
    put("xspawn ");
    num(spawned);
    put(" ");
    num(waited);
    put("\n");
    bsd(SYS_write, 1, (long)line, at, 0, 0, 0);
    return 0;
}

void main_entry(long argc, char **argv) {
    bsd(SYS_exit, run((int)argc, argv), 0, 0, 0, 0, 0);
    for (;;) {
    }
}

// The entry: a static program's stack has its argc, then its argv, at sp.
__attribute__((naked)) void start(void) {
    __asm__ volatile("ldr x0, [sp]\n\tadd x1, sp, #8\n\tb _main_entry");
}
