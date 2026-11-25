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
// Each of these waits so too, then prints a line a descriptor:
//   "stdstat kinds": "fd N type T nread R nocache E": its type as
//     proc_pidfdlist gives it (PROX_FDTYPE_*), FIONREAD's count (or "-E",
//     its errno), F_NOCACHE's errno (a vnode's only: EBADF otherwise).
//   "stdstat owner": "fd N pgid E G": TIOCSPGRP (a socket's SIOCSPGRP) of
//     4242's errno, then TIOCGPGRP's (SIOCGPGRP's) answer.
//   "stdstat fdinfo": "fd N info E size Z mode M uid U fsize S":
//     proc_pidfdinfo of its kind (PROC_PIDFDPIPEINFO, PROC_PIDFDSOCKETINFO,
//     else PROC_PIDFDVNODEINFO): its errno, the size it gave, and its
//     vinfo_stat's mode (octal), owner and size.

#define SYS_exit 1
#define SYS_write 4
#define SYS_select 93
#define SYS_fstat64 339
#define SYS_getpid 20
#define SYS_ioctl 54
#define SYS_fcntl 92
#define SYS_proc_info 336

#define FIONREAD 0x4004667fL
#define TIOCSPGRP 0x80047476L
#define TIOCGPGRP 0x40047477L
#define SIOCSPGRP 0x80047308L
#define SIOCGPGRP 0x40047309L
#define F_NOCACHE 48
#define PROC_INFO_CALL_PIDINFO 2
#define PROC_INFO_CALL_PIDFDINFO 3
#define PROC_PIDLISTFDS 1
#define PROX_FDTYPE_SOCKET 2
#define PROX_FDTYPE_PIPE 6
#define PROC_PIDFDVNODEINFO 1
#define PROC_PIDFDSOCKETINFO 3
#define PROC_PIDFDPIPEINFO 6

struct ret {
    long x0;
    long carry;
};

static struct ret bsd6(long nr, long a0, long a1, long a2, long a3, long a4, long a5) {
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

static struct ret bsd(long nr, long a0, long a1, long a2, long a3, long a4) {
    return bsd6(nr, a0, a1, a2, a3, a4, 0);
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

// proc_pidfdlist's entries: proc_fd, proc_fdtype.
static int fdlist[128];
static unsigned char info[1200];

/// The descriptor's PROX_FDTYPE_* as proc_pidfdlist gives it, -1 if absent.
static long fdtype(long pid, int fd) {
    struct ret r = bsd6(SYS_proc_info, PROC_INFO_CALL_PIDINFO, pid, PROC_PIDLISTFDS, 0, (long)fdlist, sizeof fdlist);
    if (r.carry) return -1;
    for (long i = 0; i < r.x0 / 8; i++)
        if (fdlist[2 * i] == fd) return fdlist[2 * i + 1];
    return -1;
}

static void kinds_line(long pid, int fd) {
    put("fd ");
    base(fd, 10);
    put(" type ");
    long t = fdtype(pid, fd);
    if (t < 0) {
        put("-");
    } else {
        base(t, 10);
    }
    int n = 0;
    struct ret r = bsd(SYS_ioctl, fd, FIONREAD, (long)&n, 0, 0);
    put(" nread ");
    if (r.carry) {
        put("-");
        base(r.x0, 10);
    } else {
        base(n, 10);
    }
    r = bsd(SYS_fcntl, fd, F_NOCACHE, 0, 0, 0);
    put(" nocache ");
    base(r.carry ? r.x0 : 0, 10);
    put("\n");
}

static void owner_line(long pid, int fd) {
    int socket = fdtype(pid, fd) == PROX_FDTYPE_SOCKET;
    int g = 4242;
    struct ret r = bsd(SYS_ioctl, fd, socket ? SIOCSPGRP : TIOCSPGRP, (long)&g, 0, 0);
    put("fd ");
    base(fd, 10);
    put(" pgid ");
    base(r.carry ? r.x0 : 0, 10);
    g = 0;
    r = bsd(SYS_ioctl, fd, socket ? SIOCGPGRP : TIOCGPGRP, (long)&g, 0, 0);
    put(" ");
    if (r.carry) {
        put("-");
        base(r.x0, 10);
    } else {
        base(g, 10);
    }
    put("\n");
}

// socket_fdinfo and pipe_fdinfo: proc_fileinfo (24 bytes), then the
// vinfo_stat (vst_mode at 4, vst_uid at 16, vst_size at 88);
// vnode_fdinfo's: proc_fileinfo, then vnode_info's vinfo_stat.
static unsigned long w(int o, int n) {
    unsigned long v = 0;
    for (int i = n - 1; i >= 0; i--) v = v << 8 | info[o + i];
    return v;
}

static void fdinfo_line(long pid, int fd) {
    long t = fdtype(pid, fd);
    long flavor = t == PROX_FDTYPE_PIPE ? PROC_PIDFDPIPEINFO : t == PROX_FDTYPE_SOCKET ? PROC_PIDFDSOCKETINFO : PROC_PIDFDVNODEINFO;
    struct ret r = bsd6(SYS_proc_info, PROC_INFO_CALL_PIDFDINFO, pid, flavor, fd, (long)info, sizeof info);
    put("fd ");
    base(fd, 10);
    put(" info ");
    base(r.carry ? r.x0 : 0, 10);
    if (!r.carry) {
        put(" size ");
        base(r.x0, 10);
        put(" mode ");
        base(w(24 + 4, 2), 8);
        put(" uid ");
        base(w(24 + 16, 4), 10);
        put(" fsize ");
        base(w(24 + 88, 8), 10);
    }
    put("\n");
}

/// Standard input's bytes there (at most 5 s).
static void wait_input(void) {
    for (int i = 0; i < 500; i++) {
        if (!bsd(SYS_fstat64, 0, (long)st, 0, 0, 0).carry && u(96, 8) != 0) break;
        long tv[2] = {0, 10000};
        bsd(SYS_select, 0, 0, 0, 0, (long)tv);
    }
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
        wait_input();
        stat_line(0);
    } else if (argc == 2 && (same(argv[1], "kinds") || same(argv[1], "owner") || same(argv[1], "fdinfo"))) {
        long pid = bsd(SYS_getpid, 0, 0, 0, 0, 0).x0;
        wait_input();
        for (int fd = 0; fd < 2; fd++) {
            if (same(argv[1], "kinds")) kinds_line(pid, fd);
            else if (same(argv[1], "owner")) owner_line(pid, fd);
            else fdinfo_line(pid, fd);
        }
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
