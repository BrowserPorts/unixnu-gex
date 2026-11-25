// fstat64 of the standard streams, as the process's caller gave them, as
// XNU shows what each is: a pipe `pipe_stat`'s (a FIFO of the caller's, its
// size what is buffered, its block size its buffer's), a regular file the
// file's, the null device the system's /dev/null. Under gexc they are the
// host's streams (tests/darwin/run.sh arranges a file, a pipe and the null
// device); in the page, pipes the page's global kernel holds.
//
// With no argument: one line a descriptor, "fd N mode M nlink L uid U gid G
// size S blksize B flags F" (M in octal).
// "stdstat wait": waits (at most 5 s) until standard input has bytes
// buffered, then prints fd 0's line alone.

#define SYS_exit 1
#define SYS_write 4
#define SYS_select 93
#define SYS_fstat64 339

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
    __asm__ volatile("svc #0x80\n\tcset %1, cs"
                     : "+r"(x0), "=r"(carry)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x16)
                     : "memory", "cc");
    return (struct ret){x0, carry};
}

static char line[512];
static int at;

static void put(const char *s) {
    while (*s && at < (int)sizeof line) line[at++] = *s++;
}

static void base(unsigned long v, unsigned b) {
    char d[24];
    int n = 0;
    do {
        d[n++] = (char)('0' + v % b);
        v /= b;
    } while (v);
    while (n && at < (int)sizeof line) line[at++] = d[--n];
}

// struct stat64: st_mode at 4, st_nlink at 6, st_uid at 16, st_gid at 20,
// st_size at 96, st_blksize at 112, st_flags at 116.
static unsigned char st[144];

static unsigned long u(int o, int n) {
    unsigned long v = 0;
    for (int i = n - 1; i >= 0; i--) v = v << 8 | st[o + i];
    return v;
}

static void stat_line(int fd) {
    struct ret r = bsd(SYS_fstat64, fd, (long)st, 0, 0, 0);
    put("fd ");
    base(fd, 10);
    if (r.carry) {
        put(" errno ");
        base(r.x0, 10);
    } else {
        put(" mode ");
        base(u(4, 2), 8);
        put(" nlink ");
        base(u(6, 2), 10);
        put(" uid ");
        base(u(16, 4), 10);
        put(" gid ");
        base(u(20, 4), 10);
        put(" size ");
        base(u(96, 8), 10);
        put(" blksize ");
        base(u(112, 4), 10);
        put(" flags ");
        base(u(116, 4), 10);
    }
    put("\n");
}

static int same(const char *a, const char *b) {
    while (*a && *a == *b) a++, b++;
    return *a == *b;
}

void main_entry(long argc, char **argv) {
    long status = 0;
    if (argc < 2) {
        for (int fd = 0; fd < 3; fd++) stat_line(fd);
    } else if (argc == 2 && same(argv[1], "wait")) {
        for (int i = 0; i < 500; i++) {
            if (!bsd(SYS_fstat64, 0, (long)st, 0, 0, 0).carry && u(96, 8) != 0) break;
            long tv[2] = {0, 10000};
            bsd(SYS_select, 0, 0, 0, 0, (long)tv);
        }
        stat_line(0);
    } else {
        status = 64;
    }
    bsd(SYS_write, 1, (long)line, at, 0, 0);
    bsd(SYS_exit, status, 0, 0, 0, 0);
    for (;;) {
    }
}

// The entry: a static program's stack has its argc, then its argv, at sp.
__attribute__((naked)) void start(void) {
    __asm__ volatile("ldr x0, [sp]\n\tadd x1, sp, #8\n\tb _main_entry");
}
