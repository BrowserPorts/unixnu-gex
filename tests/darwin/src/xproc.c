// What one process makes of the system's state that another finds: a POSIX
// shared memory name, a named semaphore, its record by its pid. With no
// argument, all in this one process: the names it made, it opens again
// (and unlinks), and its own record by its pid is found; "xproc ok".
//
// For a caller that runs it more than once in one system (each mode a
// process of its own):
//   xproc mk NAME     makes NAME as a shared memory object and a semaphore,
//                     and leaves both: "xproc made".
//   xproc open NAME   opens both: "xproc open shm=E sem=E", each E the
//                     errno (0 when it opened).
//   xproc hold FILE   writes its pid to FILE, then waits (at most 20 s)
//                     for FILE.done to exist: "xproc held nice N", N its
//                     nice value then.
//   xproc nice FILE   sets the nice value of the pid in FILE, once there
//                     (at most 20 s), to 7 and reads it back: "xproc nice E
//                     N", E setpriority's errno, N getpriority's answer;
//                     then makes FILE.done.
//   xproc peek FILE   proc_info PROC_PIDTBSDINFO of the pid in FILE, once
//                     there (at most 20 s): "xproc peek E", E the errno
//                     (0 when found with that pid and this program's
//                     name, -2 or -3 when not), then kill's signal 0 to it:
//                     "xproc peek E kill K", K the errno (0 when sent);
//                     then makes FILE.done.

#define SYS_exit 1
#define SYS_write 4
#define SYS_open 5
#define SYS_close 6
#define SYS_read 3
#define SYS_getpid 20
#define SYS_kill 37
#define SYS_setpriority 96
#define SYS_getpriority 100
#define SYS_access 33
#define SYS_select 93
#define SYS_shm_open 266
#define SYS_shm_unlink 267
#define SYS_sem_open 268
#define SYS_sem_close 269
#define SYS_sem_unlink 270
#define SYS_proc_info 336

#define O_RDONLY 0
#define O_RDWR 2
#define O_WRONLY 1
#define O_CREAT 0x200
#define O_TRUNC 0x400
#define O_EXCL 0x800

#define PROC_INFO_CALL_PIDINFO 2
#define PROC_PIDTBSDINFO 3
#define PROC_BSDINFO_SIZE 136

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

/// The call's errno, 0 when it succeeded.
static long err(struct ret r) {
    return r.carry ? r.x0 : 0;
}

static char line[256];
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

static void say(void) {
    put("\n");
    bsd(SYS_write, 1, (long)line, at, 0, 0, 0);
    at = 0;
}

static int same(const char *a, const char *b) {
    while (*a && *a == *b) a++, b++;
    return *a == *b;
}

static char done_path[256];

static const char *done_of(const char *file) {
    int i = 0;
    while (file[i] && i < 240) {
        done_path[i] = file[i];
        i++;
    }
    const char *s = ".done";
    while (*s) done_path[i++] = *s++;
    done_path[i] = 0;
    return done_path;
}

static long bsdinfo(long pid) {
    static unsigned char info[PROC_BSDINFO_SIZE];
    struct ret r = bsd(SYS_proc_info, PROC_INFO_CALL_PIDINFO, pid, PROC_PIDTBSDINFO, 0, (long)info, sizeof info);
    if (r.carry) return r.x0;
    if (r.x0 != PROC_BSDINFO_SIZE) return -1;
    // pbi_pid, and pbi_comm: this program's.
    if (*(int *)(info + 12) != (int)pid) return -2;
    if (!same((const char *)info + 48, "xproc")) return -3;
    return 0;
}

static long self_test(void) {
    const char *name = "/gex-xproc-self";
    struct ret s = bsd(SYS_shm_open, (long)name, O_CREAT | O_EXCL | O_RDWR, 0600, 0, 0, 0);
    if (s.carry) return 1;
    struct ret s2 = bsd(SYS_shm_open, (long)name, O_RDWR, 0, 0, 0, 0);
    if (s2.carry) return 2;
    bsd(SYS_close, s.x0, 0, 0, 0, 0, 0);
    bsd(SYS_close, s2.x0, 0, 0, 0, 0, 0);
    if (err(bsd(SYS_shm_unlink, (long)name, 0, 0, 0, 0, 0))) return 3;
    struct ret m = bsd(SYS_sem_open, (long)name, O_CREAT | O_EXCL, 0600, 1, 0, 0);
    if (m.carry) return 4;
    struct ret m2 = bsd(SYS_sem_open, (long)name, 0, 0, 0, 0, 0);
    if (m2.carry) return 5;
    bsd(SYS_sem_close, m.x0, 0, 0, 0, 0, 0);
    bsd(SYS_sem_close, m2.x0, 0, 0, 0, 0, 0);
    if (err(bsd(SYS_sem_unlink, (long)name, 0, 0, 0, 0, 0))) return 6;
    if (bsdinfo(bsd(SYS_getpid, 0, 0, 0, 0, 0, 0).x0)) return 7;
    return 0;
}

void main_entry(long argc, char **argv) {
    long status = 0;
    if (argc < 2) {
        status = self_test();
        if (!status) {
            put("xproc ok");
            say();
        }
    } else if (argc == 3 && same(argv[1], "mk")) {
        struct ret s = bsd(SYS_shm_open, (long)argv[2], O_CREAT | O_EXCL | O_RDWR, 0600, 0, 0, 0);
        struct ret m = bsd(SYS_sem_open, (long)argv[2], O_CREAT | O_EXCL, 0600, 1, 0, 0);
        if (s.carry || m.carry) {
            status = 1;
        } else {
            put("xproc made");
            say();
        }
    } else if (argc == 3 && same(argv[1], "open")) {
        struct ret s = bsd(SYS_shm_open, (long)argv[2], O_RDWR, 0, 0, 0, 0);
        struct ret m = bsd(SYS_sem_open, (long)argv[2], 0, 0, 0, 0, 0);
        put("xproc open shm=");
        num(err(s));
        put(" sem=");
        num(err(m));
        say();
    } else if (argc == 3 && same(argv[1], "hold")) {
        struct ret f = bsd(SYS_open, (long)argv[2], O_CREAT | O_TRUNC | O_WRONLY, 0644, 0, 0, 0);
        if (f.carry) {
            status = 1;
        } else {
            put("");
            num(bsd(SYS_getpid, 0, 0, 0, 0, 0, 0).x0);
            bsd(SYS_write, f.x0, (long)line, at, 0, 0, 0);
            at = 0;
            bsd(SYS_close, f.x0, 0, 0, 0, 0, 0);
            const char *done = done_of(argv[2]);
            status = 2;
            for (int i = 0; i < 200; i++) {
                if (!err(bsd(SYS_access, (long)done, 0, 0, 0, 0, 0))) {
                    status = 0;
                    break;
                }
                long tv[2] = {0, 100000};
                bsd(SYS_select, 0, 0, 0, 0, (long)tv, 0);
            }
            if (!status) {
                put("xproc held nice ");
                num(bsd(SYS_getpriority, 0, 0, 0, 0, 0, 0).x0);
                say();
            }
        }
    } else if (argc == 3 && same(argv[1], "nice")) {
        // The pid, once the first has written it (at most 20 s): its nice
        // value set to 7 and read back.
        long pid = 0;
        for (int tries = 0; tries < 200 && pid <= 0; tries++) {
            char buf[24];
            struct ret f = bsd(SYS_open, (long)argv[2], O_RDONLY, 0, 0, 0, 0);
            long n = f.carry ? -1 : bsd(SYS_read, f.x0, (long)buf, sizeof buf, 0, 0, 0).x0;
            if (!f.carry) bsd(SYS_close, f.x0, 0, 0, 0, 0, 0);
            for (long i = 0; i < n && buf[i] >= '0' && buf[i] <= '9'; i++) pid = pid * 10 + (buf[i] - '0');
            if (pid <= 0) {
                long tv[2] = {0, 100000};
                bsd(SYS_select, 0, 0, 0, 0, (long)tv, 0);
            }
        }
        if (pid <= 0) {
            status = 1;
        } else {
            put("xproc nice ");
            num(err(bsd(SYS_setpriority, 0, pid, 7, 0, 0, 0)));
            put(" ");
            struct ret g = bsd(SYS_getpriority, 0, pid, 0, 0, 0, 0);
            num(g.carry ? 1000 + g.x0 : g.x0);
            say();
        }
        struct ret d = bsd(SYS_open, (long)done_of(argv[2]), O_CREAT | O_WRONLY, 0644, 0, 0, 0);
        if (d.carry) status = 3;
    } else if (argc == 3 && same(argv[1], "peek")) {
        // The pid, once the first has written it (at most 20 s).
        long pid = 0;
        for (int tries = 0; tries < 200 && pid <= 0; tries++) {
            char buf[24];
            struct ret f = bsd(SYS_open, (long)argv[2], O_RDONLY, 0, 0, 0, 0);
            long n = f.carry ? -1 : bsd(SYS_read, f.x0, (long)buf, sizeof buf, 0, 0, 0).x0;
            if (!f.carry) bsd(SYS_close, f.x0, 0, 0, 0, 0, 0);
            for (long i = 0; i < n && buf[i] >= '0' && buf[i] <= '9'; i++) pid = pid * 10 + (buf[i] - '0');
            if (pid <= 0) {
                long tv[2] = {0, 100000};
                bsd(SYS_select, 0, 0, 0, 0, (long)tv, 0);
            }
        }
        if (pid <= 0) {
            status = 1;
        } else {
            put("xproc peek ");
            num(bsdinfo(pid));
            // And kill's look for it (signal 0: found, and may be signalled).
            put(" kill ");
            num(err(bsd(SYS_kill, pid, 0, 1, 0, 0, 0)));
            say();
        }
        struct ret d = bsd(SYS_open, (long)done_of(argv[2]), O_CREAT | O_WRONLY, 0644, 0, 0, 0);
        if (d.carry) status = 3;
    } else {
        status = 64;
    }
    bsd(SYS_exit, status, 0, 0, 0, 0, 0);
    for (;;) {
    }
}

// The entry: a static program's stack has its argc, then its argv, at sp.
__attribute__((naked)) void start(void) {
    __asm__ volatile("ldr x0, [sp]\n\tadd x1, sp, #8\n\tb _main_entry");
}
