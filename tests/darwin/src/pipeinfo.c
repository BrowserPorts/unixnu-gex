// proc_pidfdinfo(PROC_PIDFDPIPEINFO) of pipe ends, as XNU's fill_pipeinfo
// gives them, with no libSystem: a FIFO of the caller's (S_IFIFO | 0660, one
// link, its three times the call's), its size what the read side's buffer
// holds and its block size MAX_PIPESIZE (the write end its peer's, none once
// the reader has gone); each end's handle its peer's peer handle, the same
// through a dup, 0 for a peer that has closed; and its status the end's
// pipe_state: PIPE_ASYNC as FIOASYNC sets it, PIPE_WANTR while a reader
// sleeps for bytes, PIPE_WANTW while a writer sleeps for room (both the read
// side's, cleared by the next write and the next read), PIPE_WSELECT on an
// end's peer once the end is selected for writing, PIPE_EOF once the peer
// has closed.
//
// With no argument: one line a step, then "pipeinfo ok".
// "pipeinfo std": standard input once its writer has closed it (at most
// 20 s), then standard output, before anything is written to it: "fd N
// size S blksize B status T handle H peer P" (H and P "set" or 0).

#define SYS_exit 1
#define SYS_read 3
#define SYS_write 4
#define SYS_close 6
#define SYS_getpid 20
#define SYS_geteuid 25
#define SYS_dup 41
#define SYS_pipe 42
#define SYS_getegid 43
#define SYS_ioctl 54
#define SYS_select 93
#define SYS_proc_info 336
#define SYS_bsdthread_create 360
#define SYS_bsdthread_register 366

#define PTHREAD_START_CUSTOM 0x01000000
#define FIOASYNC 0x8004667dL
#define PROC_INFO_CALL_PIDFDINFO 3
#define PROC_PIDFDPIPEINFO 6
#define PIPE_FDINFO_SIZE 184

#define PIPE_ASYNC 0x004
#define PIPE_WANTR 0x008
#define PIPE_WANTW 0x010
#define PIPE_EOF 0x080
#define PIPE_WSELECT 0x4000

struct ret {
    long x0;
    long x1;
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
    __asm__ volatile("svc #0x80\n\tcset %2, cs"
                     : "+r"(x0), "+r"(x1), "=r"(carry)
                     : "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x16)
                     : "memory", "cc");
    return (struct ret){x0, x1, carry};
}

static unsigned long ticks(void) {
    unsigned long t;
    __asm__ volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(t) : : "memory");
    return t;
}

#define TICKS_PER_MS 24000UL

void thread_start(long self, long port, long func, long arg, long stk, long flags);

// thread_start(pthread, port, func, arg, stack, flags): the function run,
// then the thread ended (bsdthread_terminate).
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

static char out[4096];
static int at;

static void put(const char *s) {
    while (*s) out[at++] = *s++;
}

static void num(unsigned long v) {
    char d[24];
    int k = 0;
    do {
        d[k++] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    while (k) out[at++] = d[--k];
}

static void flush(void) {
    bsd(SYS_write, 1, (long)out, at, 0, 0, 0);
    at = 0;
}

static int failed;

static void fail(const char *what, long code) {
    put("FAIL ");
    put(what);
    put(" ");
    num((unsigned long)code);
    put("\n");
    failed++;
}

static long pid;
static unsigned char info[PIPE_FDINFO_SIZE];

static unsigned long w(int o, int n) {
    unsigned long v = 0;
    for (int i = n - 1; i >= 0; i--) v = v << 8 | info[o + i];
    return v;
}

// pipe_fdinfo: proc_fileinfo (24 bytes), then pipe_info: its vinfo_stat
// (vst_mode at 4, vst_nlink at 6, vst_uid at 16, vst_gid at 20, the times
// from 24, vst_size at 88, vst_blocks at 96, vst_blksize at 104), then
// pipe_handle at 136, pipe_peerhandle at 144 and pipe_status at 152.
struct pi {
    unsigned long mode, nlink, uid, gid, size, blocks, blksize, handle, peer, status;
    int times_same;
};

static int fdinfo(int fd, struct pi *p) {
    struct ret r = bsd(SYS_proc_info, PROC_INFO_CALL_PIDFDINFO, pid, PROC_PIDFDPIPEINFO, fd, (long)info, sizeof info);
    if (r.carry || r.x0 != PIPE_FDINFO_SIZE) {
        fail("proc_pidfdinfo", r.carry ? r.x0 : 1000 + r.x0);
        return -1;
    }
    const int s = 24;
    p->mode = w(s + 4, 2);
    p->nlink = w(s + 6, 2);
    p->uid = w(s + 16, 4);
    p->gid = w(s + 20, 4);
    p->size = w(s + 88, 8);
    p->blocks = w(s + 96, 8);
    p->blksize = w(s + 104, 4);
    p->handle = w(s + 136, 8);
    p->peer = w(s + 144, 8);
    p->status = w(s + 152, 4);
    p->times_same = w(s + 24, 8) != 0 && w(s + 24, 8) == w(s + 40, 8) && w(s + 40, 8) == w(s + 56, 8) && w(s + 32, 8) == w(s + 48, 8) && w(s + 48, 8) == w(s + 64, 8);
    return 0;
}

// "STEP end size S blocks K blksize B status T".
static void line(const char *step, const char *end, const struct pi *p) {
    put(step);
    put(" ");
    put(end);
    put(" size ");
    num(p->size);
    put(" blocks ");
    num(p->blocks);
    put(" blksize ");
    num(p->blksize);
    put(" status ");
    num(p->status);
    put("\n");
}

static unsigned long euid, egid;

// The fixed fields: a FIFO of the caller's, one link, the three times
// the call's.
static void fixed(const char *what, const struct pi *p) {
    if (p->mode != 010660 || p->nlink != 1 || p->uid != euid || p->gid != egid || !p->times_same) fail(what, (long)p->mode);
}

// Wait (at most 20 s) until fd's status has bit, then return it.
static int wait_status(int fd, unsigned long bit, struct pi *p) {
    unsigned long from = ticks();
    for (;;) {
        if (fdinfo(fd, p) < 0) return -1;
        if (p->status & bit) return 0;
        if (ticks() - from > 20000 * TICKS_PER_MS) return -1;
        long tv[2] = {0, 1000};
        bsd(SYS_select, 0, 0, 0, 0, (long)tv, 0);
    }
}

#define BIG 200000
static unsigned char big[BIG];

static char stacks[2][1 << 16] __attribute__((aligned(16)));
static char pthreads[2][4096] __attribute__((aligned(16)));
static int made;

// What a thread is to do: read th_len bytes of th_fd, or write them.
static volatile int th_fd;
static volatile long th_len;
static volatile int th_write;
static volatile long th_done;

static void worker(long arg) {
    (void)arg;
    long got = 0;
    while (got < th_len) {
        struct ret r = th_write ? bsd(SYS_write, th_fd, (long)(big + got), th_len - got, 0, 0, 0) : bsd(SYS_read, th_fd, (long)(big + got), th_len - got, 0, 0, 0);
        if (r.carry || r.x0 == 0) break;
        got += r.x0;
    }
    __atomic_store_n(&th_done, got + 1, __ATOMIC_RELEASE);
}

static int spawn(int fd, long len, int write) {
    th_fd = fd;
    th_len = len;
    th_write = write;
    __atomic_store_n(&th_done, 0, __ATOMIC_RELEASE);
    int i = made++;
    return bsd(SYS_bsdthread_create, (long)worker, 0, (long)(stacks[i] + sizeof stacks[i]), (long)pthreads[i], PTHREAD_START_CUSTOM, 0).carry ? -1 : 0;
}

// The thread's count of bytes, once it has ended (at most 20 s); -1 if not.
static long join(void) {
    unsigned long from = ticks();
    long d;
    while ((d = __atomic_load_n(&th_done, __ATOMIC_ACQUIRE)) == 0) {
        if (ticks() - from > 20000 * TICKS_PER_MS) return -1;
    }
    return d - 1;
}

static struct ret mkpipe(void) {
    struct ret p = bsd(SYS_pipe, 0, 0, 0, 0, 0, 0);
    if (p.carry) fail("pipe", p.x0);
    return p;
}

static void pipes(void) {
    struct pi r, wr, d;
    // A new pipe: nothing buffered, its buffer the least MAX_PIPESIZE.
    struct ret p = mkpipe();
    if (p.carry) return;
    int rfd = (int)p.x0, wfd = (int)p.x1;
    if (fdinfo(rfd, &r) < 0 || fdinfo(wfd, &wr) < 0) return;
    fixed("fixed-read", &r);
    fixed("fixed-write", &wr);
    line("open", "r", &r);
    line("open", "w", &wr);
    // Each end's handle is its peer's peer handle; a dup's is its file's.
    if (r.handle == 0 || wr.handle == 0 || r.handle == wr.handle || r.peer != wr.handle || wr.peer != r.handle) fail("handles", 0);
    struct ret dup = bsd(SYS_dup, rfd, 0, 0, 0, 0, 0);
    if (dup.carry || fdinfo((int)dup.x0, &d) < 0 || d.handle != r.handle || d.peer != r.peer) fail("dup", dup.x0);
    // Another pipe's ends are other ends.
    struct ret q = mkpipe();
    struct pi o;
    if (!q.carry && (fdinfo((int)q.x0, &o) < 0 || o.handle == r.handle || o.handle == wr.handle || o.peer == r.peer)) fail("another", 0);
    // Bytes buffered: both ends show them.
    bsd(SYS_write, wfd, (long)"abcde", 5, 0, 0, 0);
    fdinfo(rfd, &r);
    fdinfo(wfd, &wr);
    line("written", "r", &r);
    line("written", "w", &wr);
    // FIOASYNC: the end's own PIPE_ASYNC.
    int one = 1, zero = 0;
    bsd(SYS_ioctl, rfd, FIOASYNC, (long)&one, 0, 0, 0);
    fdinfo(rfd, &r);
    fdinfo(wfd, &wr);
    line("async", "r", &r);
    line("async", "w", &wr);
    bsd(SYS_ioctl, rfd, FIOASYNC, (long)&zero, 0, 0, 0);
    // A reader asleep on an empty pipe: PIPE_WANTR, until a write.
    char buf[8];
    bsd(SYS_read, rfd, (long)buf, sizeof buf, 0, 0, 0);
    if (spawn(rfd, 1, 0) < 0) {
        fail("thread", 0);
        return;
    }
    if (wait_status(rfd, PIPE_WANTR, &r) < 0) fail("wantr", (long)r.status);
    line("reader", "r", &r);
    bsd(SYS_write, wfd, (long)"x", 1, 0, 0, 0);
    if (join() != 1) fail("reader", 0);
    fdinfo(rfd, &r);
    line("read", "r", &r);
    // A writer asleep on a full pipe: PIPE_WANTW, until a read; the write
    // grows the buffer to its largest first.
    if (spawn(wfd, BIG, 1) < 0) {
        fail("thread", 1);
        return;
    }
    if (wait_status(rfd, PIPE_WANTW, &r) < 0) fail("wantw", (long)r.status);
    fdinfo(wfd, &wr);
    line("writer", "r", &r);
    line("writer", "w", &wr);
    static unsigned char sink[BIG];
    long got = 0;
    while (got < BIG) {
        struct ret n = bsd(SYS_read, rfd, (long)(sink + got), BIG - got, 0, 0, 0);
        if (n.carry || n.x0 == 0) break;
        got += n.x0;
    }
    if (got != BIG || join() != BIG) fail("writer", got);
    fdinfo(rfd, &r);
    line("drained", "r", &r);
    // The writer gone: the reader's PIPE_EOF, no peer, what is left still
    // buffered.
    bsd(SYS_write, wfd, (long)"abc", 3, 0, 0, 0);
    bsd(SYS_close, wfd, 0, 0, 0, 0, 0);
    fdinfo(rfd, &r);
    line("closed", "r", &r);
    if (r.peer != 0) fail("closed-peer", 0);
    // Select for writing marks the end's peer; the reader gone, the writer
    // has PIPE_EOF, no peer, and none of its buffer.
    struct ret s = mkpipe();
    if (s.carry) return;
    int sr = (int)s.x0, sw = (int)s.x1;
    unsigned int set[2] = {0, 0};
    set[sw / 32] |= 1u << (sw % 32);
    long tv[2] = {0, 0};
    bsd(SYS_select, sw + 1, 0, (long)set, 0, (long)tv, 0);
    fdinfo(sr, &r);
    fdinfo(sw, &wr);
    line("select-w", "r", &r);
    line("select-w", "w", &wr);
    set[0] = set[1] = 0;
    set[sr / 32] |= 1u << (sr % 32);
    bsd(SYS_select, sr + 1, 0, (long)set, 0, (long)tv, 0);
    fdinfo(sw, &wr);
    line("select-r", "w", &wr);
    bsd(SYS_write, sw, (long)"ab", 2, 0, 0, 0);
    bsd(SYS_close, sr, 0, 0, 0, 0, 0);
    fdinfo(sw, &wr);
    line("closed", "w", &wr);
    if (wr.peer != 0) fail("closed-peer", 1);
}

static void std_line(int fd) {
    struct pi p;
    if (fdinfo(fd, &p) < 0) return;
    put("fd ");
    num(fd);
    put(" size ");
    num(p.size);
    put(" blksize ");
    num(p.blksize);
    put(" status ");
    num(p.status);
    put(p.handle ? " handle set" : " handle 0");
    put(p.peer ? " peer set\n" : " peer 0\n");
}

static int same(const char *a, const char *b) {
    while (*a && *a == *b) a++, b++;
    return *a == *b;
}

void main_entry(long argc, char **argv) {
    pid = bsd(SYS_getpid, 0, 0, 0, 0, 0, 0).x0;
    euid = bsd(SYS_geteuid, 0, 0, 0, 0, 0, 0).x0;
    egid = bsd(SYS_getegid, 0, 0, 0, 0, 0, 0).x0;
    if (argc == 2 && same(argv[1], "std")) {
        // (Nothing is written to standard output before its line.)
        struct pi p;
        if (wait_status(0, PIPE_EOF, &p) < 0) fail("stdin-eof", (long)p.status);
        std_line(0);
        std_line(1);
    } else if (argc < 2) {
        if (bsd(SYS_bsdthread_register, (long)thread_start, 0, 0, 0, 0, 0).carry) {
            fail("register", 0);
        } else {
            pipes();
        }
        if (failed == 0) put("pipeinfo ok\n");
    } else {
        failed = 64;
    }
    flush();
    bsd(SYS_exit, failed, 0, 0, 0, 0, 0);
    for (;;) {
    }
}

// The entry: a static program's stack has its argc, then its argv, at sp.
__attribute__((naked)) void start(void) {
    __asm__ volatile("ldr x0, [sp]\n\tadd x1, sp, #8\n\tb _main_entry");
}
