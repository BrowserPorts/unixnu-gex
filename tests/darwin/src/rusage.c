// proc_pid_rusage (proc_info call 9): an unknown flavor is EINVAL and no
// process ESRCH; another user's process is EPERM. A flavor's copy is its
// structure's size and no more. This process's record: its executable's
// UUID, its time (recount's, in Mach time units: the getrusage time, all
// of it user time, no system time), its fork's start (ps_start, with
// p_start), no end, its runnable time (once it has blocked, at least the
// time it ran before; never more than its life), its own
// footprint, what its wirings hold (mlock's pages, until munlock), and the
// zero fields of this kernel: the flags (no ptrauth), the performance
// cluster's figures (no AMP), the secure times and what follows them. A
// child that has ended and is not yet reaped is read from what its exit
// gathered: its end after its start, nothing wired, resident or in its
// footprint, with its lifetime peak (what it touched before its end). Once
// reaped, its time and its elapsed time (end less start)
// are its parent's ri_child sums; a parent with SA_NOCLDWAIT has them
// added twice (at the child's exit and at the system's reap). The time by
// effective QoS: a thread's time goes to the QoS it ran at (utility, then
// background), and the seven sum to the task's time. Each sleep that its
// deadline timer ends is a wakeup from interrupt context, and a
// platform-idle one when no thread was on a processor then (none while a
// thread of its own spins); the energy fields are 0 (no energy counter on
// this SoC). The footprint's
// peaks: pages touched then unmapped are in the lifetime peak, the
// footprint after is below it, and TASK_VM_INFO's ledger peak is the same
// ledger's; an interval reset begins the interval's peak at the footprint
// then. The resident size holds the pages touched until they are
// unmapped. Another process's footprint and resident size, read from
// outside it, and its peak after it unmapped what it touched. The fields
// the kernel does not keep are reported, so a strict run stops at a
// call that copies one ("stop": V0's after the real timer's signal, the
// wakeups a thread call's signal made not followed).
//
// Instructions and cycles (recount's PMC1 and PMC0): a loop of a known
// count retires exactly that many more instructions for twice as many
// passes; a loop whose loads and stores take the first-touch faults of a
// file's private mapping (each instruction resumed at the access) counts
// exactly what the same loop counts over pages already touched; a signal
// handler run in the middle of a loop adds only its own; a thread's count
// stays its task's after it ends; an exec keeps the process's count, and
// a fork's child starts from none. The cycles are the time at one clock.
//
// Page-ins: the first touch of each page of a file's mapping that no pmap
// has mapped is one; a page a read brought in, or another process mapped
// first, is none; a reaped child's are its parent's ri_child_pageins.
//
// Disk I/O (task_io_stats, what spec_strategy sees the task's threads
// issue): written pages reach the disk at fsync (at least their bytes),
// an fsync with nothing dirty writes no data, a small write waits in the
// cache (none written) while an O_SYNC one is written at once; pages
// dropped from the cache (msync's invalidation) are read again, by read
// and by a fault, at least a page each. Logical writes (the
// logical_writes ledger): a page a write dirties counts at least its
// bytes; the first store fault on a shared mapping's page counts the page
// exactly (a load's fault enters a page no store has entered read only, so
// a store after it faults and counts the same), a store again nothing, and
// a shrinking file's dirty pages are taken back. A fork's child starts with none of either.

#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <pthread/qos.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int proc_pid_rusage(int pid, int flavor, void *buffer);
int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);

static int bad(const char *what, long got, long want) {
    printf("rusage: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static volatile uint64_t sink;

// A thread that keeps a processor until told to stop.
static atomic_bool spinning_stop, spinning_started;

static void *spinning(void *arg) {
    (void)arg;
    atomic_store(&spinning_started, true);
    while (!atomic_load(&spinning_stop)) sink++;
    return NULL;
}

static void spin(uint64_t ns) {
    uint64_t until = clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID) + ns;
    while (clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID) < until) {
        for (int i = 0; i < 100000; i++) sink += (uint64_t)i * i;
    }
}

static uint64_t ns_of(uint64_t mach) {
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    return mach * tb.numer / tb.denom;
}

static uint64_t usage_ns(void) {
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    return (uint64_t)ru.ru_utime.tv_sec * 1000000000u + (uint64_t)ru.ru_utime.tv_usec * 1000u;
}

// The record's fields this kernel leaves 0 (energy among them: no
// energy counter on this SoC).
static int zeros(const struct rusage_info_v6 *r, const char *whose) {
    const uint64_t *after = &r->ri_neural_footprint;
    for (int i = 0; i < 12; i++)
        if (after[i]) return bad(whose, (long)after[i], 0);
    if (r->ri_system_time || r->ri_flags || r->ri_user_ptime || r->ri_system_ptime || r->ri_pinstructions || r->ri_pcycles || r->ri_penergy_nj || r->ri_secure_time_in_system || r->ri_secure_ptime_in_system || r->ri_energy_nj || r->ri_billed_energy || r->ri_serviced_energy)
        return bad(whose, 1, 0);
    return 0;
}

// n passes of a two-instruction loop.
__attribute__((noinline)) static void loop2(uint64_t n) {
    __asm__ volatile("1: subs %0, %0, #1\n b.ne 1b" : "+r"(n) : : "cc");
}

// A load and a store, then a stride on, n times, from p: five
// instructions a pass.
__attribute__((noinline)) static void touch_loop(volatile char *p, uint64_t n, uint64_t stride) {
    __asm__ volatile("1: ldrb w9, [%0]\n strb w9, [%0]\n add %0, %0, %2\n subs %1, %1, #1\n b.ne 1b"
                     : "+r"(p), "+r"(n) : "r"(stride) : "w9", "cc", "memory");
}

static uint64_t insns(void) {
    struct rusage_info_v6 r;
    if (proc_pid_rusage(getpid(), RUSAGE_INFO_V4, &r) != 0) return 0;
    return r.ri_instructions;
}

// The rise across one touch_loop, the same code each time.
__attribute__((noinline)) static uint64_t across_touch(volatile char *p, uint64_t n) {
    uint64_t a = insns();
    touch_loop(p, n, 16384);
    return insns() - a;
}

static volatile uint64_t handled;
static void on_alarm(int s) {
    (void)s;
    handled++;
}

static void *counting_thread(void *arg) {
    loop2((uint64_t)(uintptr_t)arg);
    return NULL;
}

int proc_pidpath(int pid, void *buffer, uint32_t buffersize);

static int instructions(void) {
    char self[1024];
    if (proc_pidpath(getpid(), self, sizeof self) <= 0) return bad("its path", errno, 0);
    // The rise across a call of loop2: the loop's 2n and the fixed path
    // between the two reads, which cancels in a difference.
    uint64_t a = insns(), b, c;
    loop2(1000000);
    b = insns();
    loop2(2000000);
    c = insns();
    if ((c - b) - (b - a) != 2000000) return bad("instructions of a million more passes", (long)((c - b) - (b - a)), 2000000);
    // The same loop over a file's private mapping: first touches (a read
    // fault, then a write fault, each instruction run again) and then the
    // same pages again.
    enum { PAGES = 32 };
    char path[] = "/private/var/tmp/rusage.XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0 || ftruncate(fd, PAGES * 16384) != 0) return bad("a file to map", errno, 0);
    unlink(path);
    char *f = mmap(NULL, PAGES * 16384, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);
    if (f == MAP_FAILED) return bad("mmap of the file", errno, 0);
    uint64_t first = across_touch(f, PAGES), again = across_touch(f, PAGES);
    munmap(f, PAGES * 16384);
    if (first != again) return bad("instructions of a loop through first touches", (long)first, (long)again);
    if (again < 5 * PAGES) return bad("instructions of a loop over pages", (long)again, 5 * PAGES);
    // A loop a timer's signal interrupts: its own count and the handlers'.
    struct sigaction sa = { .sa_handler = on_alarm };
    sigaction(SIGALRM, &sa, NULL);
    struct itimerval it = { { 0, 2000 }, { 0, 2000 } };
    uint64_t s0 = insns(), loops = 0;
    handled = 0;
    setitimer(ITIMER_REAL, &it, NULL);
    while (handled < 20) {
        loop2(100000);
        loops++;
    }
    struct itimerval off = { { 0, 0 }, { 0, 0 } };
    setitimer(ITIMER_REAL, &off, NULL);
    uint64_t s1 = insns();
    signal(SIGALRM, SIG_DFL);
    // Each pass of the outer loop and each handler's frame, its return
    // and the call to it are a few hundred at most.
    uint64_t base = 2 * 100000 * loops;
    if (s1 - s0 < base || s1 - s0 - base > 1000 * (loops + handled + 4)) return bad("instructions of a loop with signals, over its own", (long)(s1 - s0 - base), (long)(1000 * (loops + handled + 4)));
    // A thread that ends: its count stays its task's.
    uint64_t j0 = insns();
    pthread_t th;
    pthread_create(&th, NULL, counting_thread, (void *)(uintptr_t)3000000);
    pthread_join(th, NULL);
    if (insns() - j0 < 6000000) return bad("an ended thread's instructions", (long)(insns() - j0), 6000000);
    // A fork's child starts from none; an exec keeps the count.
    int pp[2];
    pipe(pp);
    uint64_t before = insns();
    pid_t c1 = fork();
    if (c1 == 0) {
        uint64_t mine = insns();
        write(pp[1], &mine, sizeof mine);
        loop2(2000000);
        char n[32];
        snprintf(n, sizeof n, "%d", pp[1]);
        execl(self, self, "exec-count", n, (char *)NULL);
        _exit(3);
    }
    uint64_t child0 = 0, child1 = 0;
    read(pp[0], &child0, sizeof child0);
    read(pp[0], &child1, sizeof child1);
    int st;
    waitpid(c1, &st, 0);
    if (child0 >= before) return bad("a fork's child's instructions at its start", (long)child0, 0);
    if (child1 < child0 + 4000000) return bad("an exec's instructions after it", (long)child1, (long)(child0 + 4000000));
    // The cycles: the time at the cores' clock.
    struct rusage_info_v6 r;
    proc_pid_rusage(getpid(), RUSAGE_INFO_V4, &r);
    uint64_t ns = ns_of(r.ri_user_time), want = ns * 2400 / 1000;
    if (r.ri_cycles + want / 1000 + 2400 < want || r.ri_cycles > want + want / 1000 + 2400) return bad("the cycles against the time", (long)r.ri_cycles, (long)want);
    return 0;
}

static uint64_t pageins(void) {
    struct rusage_info_v6 r;
    if (proc_pid_rusage(getpid(), RUSAGE_INFO_V0, &r) != 0) return 0;
    return r.ri_pageins;
}

// The page-ins: each page of a file's mapping that no pmap has mapped,
// at its first touch in this process (a page the pager reads, or one a
// cluster read brought in), is one; a page a read(2) brought in is a
// cache hit, none; a page another process mapped first, none; and a
// reaped child's are its parent's ri_child_pageins.
static int page_ins(void) {
    enum { N = 64 };
    char path[] = "/private/var/tmp/rusage-pi.XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0 || ftruncate(fd, N * 16384) != 0) return bad("a file to map", errno, 0);
    unlink(path);
    // Pages 0..3 through the cache by a read.
    char buf[4 * 16384];
    if (pread(fd, buf, sizeof buf, 0) != (ssize_t)sizeof buf) return bad("pread", errno, 0);
    volatile char *f = mmap(NULL, N * 16384, PROT_READ, MAP_PRIVATE, fd, 0);
    if (f == MAP_FAILED) return bad("mmap of the file", errno, 0);
    uint64_t p0 = pageins();
    for (int i = 0; i < 4; i++) (void)f[i * 16384];
    uint64_t p1 = pageins();
    if (p1 != p0) return bad("page-ins of pages a read brought in", (long)(p1 - p0), 0);
    // Ten pages from page 20 on, each first touched here: ten, and none
    // when they are touched again.
    for (int i = 20; i < 30; i++) (void)f[i * 16384];
    uint64_t p2 = pageins();
    for (int i = 20; i < 30; i++) (void)f[i * 16384];
    uint64_t p3 = pageins();
    if (p2 - p1 != 10 || p3 != p2) return bad("page-ins of ten first touches, then again", (long)(p2 - p1), 10);
    // A child that touches pages 20..29 (mapped here first) and 40..44
    // (mapped by no one yet): five.
    int pp[2];
    pipe(pp);
    pid_t c = fork();
    if (c == 0) {
        uint64_t a = pageins();
        for (int i = 20; i < 30; i++) (void)f[i * 16384];
        for (int i = 40; i < 45; i++) (void)f[i * 16384];
        uint64_t n = pageins() - a;
        write(pp[1], &n, sizeof n);
        _exit(0);
    }
    uint64_t n = 0;
    read(pp[0], &n, sizeof n);
    struct rusage_info_v6 b0, b1;
    proc_pid_rusage(getpid(), RUSAGE_INFO_V1, &b0);
    waitpid(c, NULL, 0);
    proc_pid_rusage(getpid(), RUSAGE_INFO_V1, &b1);
    munmap((void *)f, N * 16384);
    close(fd);
    if (n != 5) return bad("a child's page-ins of pages mapped first by its parent and of new ones", (long)n, 5);
    if (b1.ri_child_pageins - b0.ri_child_pageins < 5) return bad("a reaped child's page-ins in ri_child_pageins", (long)(b1.ri_child_pageins - b0.ri_child_pageins), 5);
    return 0;
}

static struct rusage_info_v6 io_now(void) {
    struct rusage_info_v6 r;
    proc_pid_rusage(getpid(), RUSAGE_INFO_V4, &r);
    return r;
}

// Disk I/O and logical writes of this process.
static int disk_io(void) {
    enum { P = 16384 };
    char path[] = "/private/var/tmp/rusage-io.XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return bad("a file to write", errno, 0);
    unlink(path);
    static char buf[4 * P];
    memset(buf, 7, sizeof buf);
    // Four pages written: dirty in the cache, at least their bytes
    // logical writes, nothing on the disk yet; then fsync writes them.
    struct rusage_info_v6 a = io_now();
    if (pwrite(fd, buf, sizeof buf, 0) != (ssize_t)sizeof buf) return bad("pwrite", errno, 0);
    struct rusage_info_v6 b = io_now();
    if (b.ri_logical_writes - a.ri_logical_writes < sizeof buf) return bad("logical writes of four new pages", (long)(b.ri_logical_writes - a.ri_logical_writes), (long)sizeof buf);
    if (b.ri_diskio_byteswritten != a.ri_diskio_byteswritten) return bad("bytes written by a write to the cache", (long)(b.ri_diskio_byteswritten - a.ri_diskio_byteswritten), 0);
    if (fsync(fd) != 0) return bad("fsync", errno, 0);
    struct rusage_info_v6 c = io_now();
    if (c.ri_diskio_byteswritten - b.ri_diskio_byteswritten < sizeof buf) return bad("bytes written by an fsync of four pages", (long)(c.ri_diskio_byteswritten - b.ri_diskio_byteswritten), (long)sizeof buf);
    // Nothing dirty: an fsync writes no data.
    fsync(fd);
    struct rusage_info_v6 d = io_now();
    if (d.ri_diskio_byteswritten != c.ri_diskio_byteswritten) return bad("bytes written by an fsync of clean pages", (long)(d.ri_diskio_byteswritten - c.ri_diskio_byteswritten), 0);
    // The pages dropped from the cache: a read of one reads it from the
    // disk, and so does a fault on another.
    char *map = mmap(NULL, sizeof buf, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) return bad("mmap", errno, 0);
    if (msync(map, sizeof buf, MS_INVALIDATE | MS_SYNC) != 0) return bad("msync", errno, 0);
    struct rusage_info_v6 e = io_now();
    if (pread(fd, buf, P, 0) != P) return bad("pread", errno, 0);
    struct rusage_info_v6 f = io_now();
    if (f.ri_diskio_bytesread - e.ri_diskio_bytesread < P) return bad("bytes read by a read of a page not in the cache", (long)(f.ri_diskio_bytesread - e.ri_diskio_bytesread), P);
    (void)*(volatile char *)(map + 3 * P);
    struct rusage_info_v6 g = io_now();
    if (g.ri_diskio_bytesread - f.ri_diskio_bytesread < P) return bad("bytes read by a fault on a page not in the cache", (long)(g.ri_diskio_bytesread - f.ri_diskio_bytesread), P);
    munmap(map, sizeof buf);
    // An O_SYNC write is written at once.
    int fl = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, fl | O_SYNC);
    struct rusage_info_v6 h = io_now();
    if (pwrite(fd, buf, P, 8 * P) != P) return bad("an O_SYNC pwrite", errno, 0);
    struct rusage_info_v6 i = io_now();
    fcntl(fd, F_SETFL, fl);
    if (i.ri_diskio_byteswritten - h.ri_diskio_byteswritten < P) return bad("bytes written by an O_SYNC write", (long)(i.ri_diskio_byteswritten - h.ri_diskio_byteswritten), P);
    close(fd);

    // Store faults on a shared mapping of a file no write has touched:
    // the first on a page is a page's logical write, after a load on it
    // or not; a store on a page stored to before, none.
    char path2[] = "/private/var/tmp/rusage-lw.XXXXXX";
    fd = mkstemp(path2);
    if (fd < 0 || ftruncate(fd, 4 * P) != 0) return bad("a file to map", errno, 0);
    unlink(path2);
    volatile char *w = mmap(NULL, 4 * P, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (w == MAP_FAILED) return bad("mmap", errno, 0);
    struct rusage_info_v6 j = io_now();
    w[0] = 1;
    struct rusage_info_v6 k = io_now();
    (void)w[P];
    w[P] = 1;
    w[0] = 2;
    struct rusage_info_v6 l = io_now();
    munmap((void *)w, 4 * P);
    if (k.ri_logical_writes - j.ri_logical_writes != P) return bad("logical writes of a first store fault", (long)(k.ri_logical_writes - j.ri_logical_writes), P);
    if (l.ri_logical_writes - k.ri_logical_writes != P) return bad("logical writes of a store after a load, and one again", (long)(l.ri_logical_writes - k.ri_logical_writes), P);
    // Dirty pages a truncation discards are taken back.
    if (pwrite(fd, buf, 2 * P, 0) != 2 * P) return bad("pwrite", errno, 0);
    struct rusage_info_v6 t0 = io_now();
    ftruncate(fd, 0);
    struct rusage_info_v6 t1 = io_now();
    close(fd);
    if ((int64_t)(t1.ri_logical_writes - t0.ri_logical_writes) >= 0) return bad("logical writes after dirty pages are truncated away", (long)(int64_t)(t1.ri_logical_writes - t0.ri_logical_writes), -2 * P);
    // A fork's child: none of either.
    int pp[2];
    pipe(pp);
    pid_t ch = fork();
    if (ch == 0) {
        struct rusage_info_v6 r = io_now();
        uint64_t v[3] = { r.ri_diskio_bytesread, r.ri_diskio_byteswritten, r.ri_logical_writes };
        write(pp[1], v, sizeof v);
        _exit(0);
    }
    uint64_t v[3] = { 1, 1, 1 };
    read(pp[0], v, sizeof v);
    waitpid(ch, NULL, 0);
    if (v[0] || v[1] || v[2]) return bad("a fork's child's disk I/O and logical writes at its start", (long)(v[0] + v[1] + v[2]), 0);
    return 0;
}

int proc_rlimit_control(pid_t pid, int flavor, void *arg);
#ifndef RLIMIT_FOOTPRINT_INTERVAL
#define RLIMIT_FOOTPRINT_INTERVAL 4
#endif
#ifndef FOOTPRINT_INTERVAL_RESET
#define FOOTPRINT_INTERVAL_RESET 0x1
#endif

// 256 pages of 16 KiB: 4 MiB.
static const size_t SPAN = 256 * 16384;

static char *touch(size_t n) {
    char *p = mmap(NULL, n, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (p == MAP_FAILED) return NULL;
    for (size_t i = 0; i < n; i += 16384) p[i] = 1;
    return p;
}

// The footprint's peaks of this process.
static int peaks(void) {
    struct rusage_info_v6 f0, f1, f2;
    if (proc_pid_rusage(getpid(), RUSAGE_INFO_V4, &f0) != 0) return bad("V4", errno, 0);
    if (f0.ri_lifetime_max_phys_footprint < f0.ri_phys_footprint || f0.ri_interval_max_phys_footprint < f0.ri_phys_footprint) return bad("the peaks against the footprint", (long)f0.ri_lifetime_max_phys_footprint, (long)f0.ri_phys_footprint);
    char *p = touch(SPAN);
    if (!p) return bad("mmap", errno, 0);
    // The resident size (the pmap's phys_mem): the pages touched are in it
    // until their unmap.
    struct rusage_info_v6 ft;
    if (proc_pid_rusage(getpid(), RUSAGE_INFO_V4, &ft) != 0) return bad("V4", errno, 0);
    if (ft.ri_resident_size < f0.ri_resident_size + SPAN) return bad("the resident size over what was touched", (long)ft.ri_resident_size, (long)(f0.ri_resident_size + SPAN));
    munmap(p, SPAN);
    if (proc_pid_rusage(getpid(), RUSAGE_INFO_V4, &f1) != 0) return bad("V4", errno, 0);
    if (f1.ri_resident_size + SPAN / 2 > ft.ri_resident_size) return bad("the resident size after the unmap", (long)f1.ri_resident_size, (long)(ft.ri_resident_size - SPAN));
    if (f1.ri_lifetime_max_phys_footprint < f0.ri_phys_footprint + SPAN) return bad("the lifetime peak over what was touched", (long)f1.ri_lifetime_max_phys_footprint, (long)(f0.ri_phys_footprint + SPAN));
    if (f1.ri_interval_max_phys_footprint < f0.ri_phys_footprint + SPAN) return bad("the interval peak over what was touched", (long)f1.ri_interval_max_phys_footprint, (long)(f0.ri_phys_footprint + SPAN));
    if (f1.ri_phys_footprint + SPAN / 2 > f1.ri_lifetime_max_phys_footprint) return bad("the footprint after the unmap", (long)f1.ri_phys_footprint, (long)(f1.ri_lifetime_max_phys_footprint - SPAN));
    // TASK_VM_INFO's footprint and ledger peak: the same ledger's.
    task_vm_info_data_t vi;
    mach_msg_type_number_t n = TASK_VM_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&vi, &n) != KERN_SUCCESS) return bad("TASK_VM_INFO", 1, 0);
    if ((uint64_t)vi.ledger_phys_footprint_peak < f1.ri_lifetime_max_phys_footprint || vi.phys_footprint > (uint64_t)vi.ledger_phys_footprint_peak) return bad("TASK_VM_INFO's ledger peak", (long)vi.ledger_phys_footprint_peak, (long)f1.ri_lifetime_max_phys_footprint);
    // A new interval, half as much touched: the interval's peak has that,
    // the lifetime peak stays.
    if (proc_rlimit_control(-1, RLIMIT_FOOTPRINT_INTERVAL, (void *)FOOTPRINT_INTERVAL_RESET) != 0) return bad("an interval reset", errno, 0);
    struct rusage_info_v6 r0;
    proc_pid_rusage(getpid(), RUSAGE_INFO_V4, &r0);
    if (r0.ri_interval_max_phys_footprint >= f1.ri_lifetime_max_phys_footprint) return bad("the interval peak after a reset", (long)r0.ri_interval_max_phys_footprint, (long)f1.ri_phys_footprint);
    p = touch(SPAN / 2);
    if (!p) return bad("mmap", errno, 0);
    madvise(p, SPAN / 2, MADV_FREE_REUSABLE);
    proc_pid_rusage(getpid(), RUSAGE_INFO_V4, &f2);
    munmap(p, SPAN / 2);
    if (f2.ri_interval_max_phys_footprint < r0.ri_phys_footprint + SPAN / 2) return bad("the interval peak of what was touched then made reusable", (long)f2.ri_interval_max_phys_footprint, (long)(r0.ri_phys_footprint + SPAN / 2));
    if (f2.ri_interval_max_phys_footprint >= f1.ri_lifetime_max_phys_footprint || f2.ri_lifetime_max_phys_footprint < f1.ri_lifetime_max_phys_footprint) return bad("the lifetime peak after the interval's", (long)f2.ri_lifetime_max_phys_footprint, (long)f1.ri_lifetime_max_phys_footprint);
    if (f2.ri_phys_footprint + SPAN / 4 > f2.ri_interval_max_phys_footprint) return bad("reusable pages left in the footprint", (long)f2.ri_phys_footprint, (long)(f2.ri_interval_max_phys_footprint - SPAN / 2));
    return 0;
}

// Another process's footprint: a child that touches SPAN, says so, unmaps
// it when told, says so, and waits to be killed.
static int other(void) {
    int up[2], down[2];
    if (pipe(up) || pipe(down)) return bad("pipe", errno, 0);
    pid_t c = fork();
    if (c == 0) {
        char x = 0;
        char *p = touch(SPAN);
        write(up[1], &x, 1);
        read(down[0], &x, 1);
        munmap(p, SPAN);
        write(up[1], &x, 1);
        pause();
        _exit(0);
    }
    char x = 0;
    struct rusage_info_v6 a, b;
    read(up[0], &x, 1);
    if (proc_pid_rusage(c, RUSAGE_INFO_V4, &a) != 0) return bad("another process", errno, 0);
    if (a.ri_phys_footprint < SPAN || a.ri_lifetime_max_phys_footprint < a.ri_phys_footprint) return bad("another process's footprint", (long)a.ri_phys_footprint, (long)SPAN);
    if (a.ri_resident_size < SPAN) return bad("another process's resident size", (long)a.ri_resident_size, (long)SPAN);
    write(down[1], &x, 1);
    read(up[0], &x, 1);
    if (proc_pid_rusage(c, RUSAGE_INFO_V4, &b) != 0) return bad("another process", errno, 0);
    kill(c, SIGKILL);
    waitpid(c, NULL, 0);
    if (b.ri_lifetime_max_phys_footprint < a.ri_phys_footprint || b.ri_phys_footprint + SPAN / 2 > b.ri_lifetime_max_phys_footprint) return bad("another process's peak after its unmap", (long)b.ri_lifetime_max_phys_footprint, (long)a.ri_phys_footprint);
    return 0;
}

int main(int argc, char **argv) {
    struct rusage_info_v6 r;
    if (argc > 2 && strcmp(argv[1], "exec-count") == 0) {
        uint64_t n = insns();
        write(atoi(argv[2]), &n, sizeof n);
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "stop") == 0) {
        // A wakeup a thread call's signal made (the real timer's) is not
        // followed: V0's wakeup counts are not kept after it.
        printf("rusage stop\n");
        fflush(stdout);
        struct sigaction sa = { .sa_handler = on_alarm };
        sigaction(SIGALRM, &sa, NULL);
        struct itimerval it = { { 0, 0 }, { 0, 1000 } };
        setitimer(ITIMER_REAL, &it, NULL);
        while (!handled) sink++;
        proc_pid_rusage(getpid(), RUSAGE_INFO_V0, &r);
        return 0;
    }
    // The calendar and Mach clocks read together near its start, for
    // p_start and ps_start below.
    struct timeval tv0;
    gettimeofday(&tv0, NULL);
    uint64_t abs0 = mach_absolute_time();
    if (proc_pid_rusage(getpid(), 7, &r) != -1 || errno != EINVAL) return bad("flavor 7", errno, EINVAL);
    if (proc_pid_rusage(99999, RUSAGE_INFO_V6, &r) != -1 || errno != ESRCH) return bad("no such process", errno, ESRCH);

    // Only V0's 96 bytes are written for V0.
    unsigned char raw[sizeof r];
    memset(raw, 0xaa, sizeof raw);
    if (proc_pid_rusage(getpid(), RUSAGE_INFO_V0, raw) != 0) return bad("V0", errno, 0);
    for (size_t i = 96; i < sizeof raw; i++)
        if (raw[i] != 0xaa) return bad("V0 wrote past its size at", (long)i, 96);

    spin(20000000);
    uint64_t before = usage_ns();
    if (proc_pid_rusage(getpid(), RUSAGE_INFO_V6, &r) != 0) return bad("V6", errno, 0);
    uint64_t after = usage_ns(), now = mach_absolute_time();
    struct { uint8_t uuid[16]; uint64_t uniqueid, puniqueid; int32_t idversion; uint32_t r2; uint64_t r3, r4; } u;
    if (proc_pidinfo(getpid(), 17, 0, &u, sizeof u) != sizeof u || memcmp(u.uuid, r.ri_uuid, 16)) return bad("its UUID", errno, 0);
    uint64_t t = ns_of(r.ri_user_time);
    if (t + 1000 < before || t > after + 1000) return bad("its time (ms)", (long)(t / 1000000), (long)(before / 1000000));
    if (zeros(&r, "a zero field")) return 1;
    if (r.ri_proc_exit_abstime != 0 || r.ri_proc_start_abstime == 0 || r.ri_proc_start_abstime >= now) return bad("its start and end", (long)r.ri_proc_exit_abstime, 0);
    // p_start was read with ps_start: from them to the clocks read near
    // its start, the calendar clock may be slewed against the Mach clock
    // by adjtime (ntp_update_second: 5000 PPM while more than a second
    // off) and the NTP frequency (MAXFREQ, 500 PPM).
    struct { uint32_t f[30]; uint64_t start_sec, start_usec; } b;
    if (proc_pidinfo(getpid(), 3, 0, &b, 136) != 136) return bad("its BSD info", errno, 0);
    int64_t wall = ((int64_t)tv0.tv_sec - (int64_t)b.start_sec) * 1000000 + ((int64_t)tv0.tv_usec - (int64_t)b.start_usec);
    int64_t mach = (int64_t)(ns_of(abs0 - r.ri_proc_start_abstime) / 1000);
    if (llabs(wall - mach) > 20000 + mach * 5500 / 1000000) return bad("its start against p_start (us)", (long)mach, (long)wall);
    // Its runnable time: the runnable timer leaves out the stretch since its
    // last update (a dispatch, a quantum's end), so it may trail the time
    // now; once the thread blocks the timer has its whole stretch, at least
    // the time it ran (no other thread runs here).
    struct rusage_info_v6 b0, b1;
    proc_pid_rusage(getpid(), RUSAGE_INFO_V4, &b0);
    usleep(1000);
    proc_pid_rusage(getpid(), RUSAGE_INFO_V4, &b1);
    if (b1.ri_runnable_time < b0.ri_user_time || b1.ri_runnable_time < r.ri_runnable_time) return bad("its runnable time, past a block", (long)b1.ri_runnable_time, (long)b0.ri_user_time);
    if (ns_of(b1.ri_runnable_time) > ns_of(mach_absolute_time() - r.ri_proc_start_abstime)) return bad("its runnable time, against its life", (long)b1.ri_runnable_time, 0);
    if (r.ri_phys_footprint == 0) return bad("its footprint", 0, 1);
    if (r.ri_child_user_time || r.ri_child_elapsed_abstime || r.ri_billed_system_time || r.ri_serviced_system_time || r.ri_billed_energy || r.ri_serviced_energy) return bad("no children, no bank bills", 1, 0);

    // Time by effective QoS: 20 ms at utility, then 20 ms at background.
    struct rusage_info_v6 q0, q1, q2;
    if (pthread_set_qos_class_self_np(QOS_CLASS_UTILITY, 0) != 0) return bad("utility", errno, 0);
    proc_pid_rusage(getpid(), RUSAGE_INFO_V3, &q0);
    spin(20000000);
    proc_pid_rusage(getpid(), RUSAGE_INFO_V3, &q1);
    if (pthread_set_qos_class_self_np(QOS_CLASS_BACKGROUND, 0) != 0) return bad("background", errno, 0);
    spin(20000000);
    proc_pid_rusage(getpid(), RUSAGE_INFO_V3, &q2);
    if (ns_of(q1.ri_cpu_time_qos_utility - q0.ri_cpu_time_qos_utility) < 20000000) return bad("utility time (us)", (long)(ns_of(q1.ri_cpu_time_qos_utility - q0.ri_cpu_time_qos_utility) / 1000), 20000);
    if (ns_of(q2.ri_cpu_time_qos_background - q1.ri_cpu_time_qos_background) < 20000000) return bad("background time (us)", (long)(ns_of(q2.ri_cpu_time_qos_background - q1.ri_cpu_time_qos_background) / 1000), 20000);
    if (ns_of(q2.ri_cpu_time_qos_utility - q1.ri_cpu_time_qos_utility) > 5000000) return bad("utility time while background (us)", (long)(ns_of(q2.ri_cpu_time_qos_utility - q1.ri_cpu_time_qos_utility) / 1000), 0);
    uint64_t qsum = q2.ri_cpu_time_qos_default + q2.ri_cpu_time_qos_maintenance + q2.ri_cpu_time_qos_background + q2.ri_cpu_time_qos_utility + q2.ri_cpu_time_qos_legacy + q2.ri_cpu_time_qos_user_initiated + q2.ri_cpu_time_qos_user_interactive;
    if (ns_of(qsum > q2.ri_user_time ? qsum - q2.ri_user_time : q2.ri_user_time - qsum) > 1000000) return bad("the QoS times' sum against the time (us)", (long)(ns_of(qsum) / 1000), (long)(ns_of(q2.ri_user_time) / 1000));
    pthread_set_qos_class_self_np(QOS_CLASS_DEFAULT, 0);

    // Five sleeps, five interrupt wakeups (at least: a thread call may wake
    // a thread of the process meanwhile).
    struct rusage_info_v6 w0, w1;
    proc_pid_rusage(getpid(), RUSAGE_INFO_V0, &w0);
    for (int i = 0; i < 5; i++) usleep(2000);
    proc_pid_rusage(getpid(), RUSAGE_INFO_V0, &w1);
    if (w1.ri_interrupt_wkups - w0.ri_interrupt_wkups < 5) return bad("interrupt wakeups of five sleeps", (long)(w1.ri_interrupt_wkups - w0.ri_interrupt_wkups), 5);
    // Platform-idle wakeups are interrupt wakeups made while every
    // processor was idle: never more than those, and (nothing else runs
    // here) the sleeps of a process with no other thread on a processor
    // end in that state.
    uint64_t idle = w1.ri_pkg_idle_wkups - w0.ri_pkg_idle_wkups;
    if (idle > w1.ri_interrupt_wkups - w0.ri_interrupt_wkups) return bad("platform-idle wakeups over the interrupt wakeups", (long)idle, (long)(w1.ri_interrupt_wkups - w0.ri_interrupt_wkups));
    if (idle < 5) return bad("platform-idle wakeups of five sleeps alone", (long)idle, 5);
    // A thread of its own spinning on a processor meanwhile: no sleep
    // ends with every processor idle.
    struct rusage_info_v6 s0, s1;
    pthread_t spinner;
    if (pthread_create(&spinner, NULL, spinning, NULL) != 0) return bad("pthread_create", errno, 0);
    while (!atomic_load(&spinning_started)) ;
    proc_pid_rusage(getpid(), RUSAGE_INFO_V0, &s0);
    for (int i = 0; i < 5; i++) usleep(2000);
    proc_pid_rusage(getpid(), RUSAGE_INFO_V0, &s1);
    atomic_store(&spinning_stop, true);
    pthread_join(spinner, NULL);
    if (s1.ri_interrupt_wkups - s0.ri_interrupt_wkups < 5) return bad("interrupt wakeups of five sleeps beside a spinning thread", (long)(s1.ri_interrupt_wkups - s0.ri_interrupt_wkups), 5);
    if (s1.ri_pkg_idle_wkups != s0.ri_pkg_idle_wkups) return bad("platform-idle wakeups beside a spinning thread", (long)(s1.ri_pkg_idle_wkups - s0.ri_pkg_idle_wkups), 0);

    // Wirings: three 16 KiB pages, then none.
    uint64_t wired0 = r.ri_wired_size;
    char *p = mmap(NULL, 4 * 16384, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (p == MAP_FAILED || mlock(p + 16384, 3 * 16384) != 0) return bad("mlock", errno, 0);
    proc_pid_rusage(getpid(), RUSAGE_INFO_V0, &r);
    if (r.ri_wired_size != wired0 + 3 * 16384) return bad("wired", (long)r.ri_wired_size, (long)(wired0 + 3 * 16384));
    munlock(p + 16384, 16384);
    munmap(p + 2 * 16384, 2 * 16384);
    proc_pid_rusage(getpid(), RUSAGE_INFO_V0, &r);
    if (r.ri_wired_size != wired0) return bad("unwired", (long)r.ri_wired_size, (long)wired0);

    // A child, ended and not reaped, then reaped; its start is its fork's.
    uint64_t pre = mach_absolute_time();
    pid_t c = fork();
    if (c == 0) {
        spin(20000000);
        touch(SPAN);
        _exit(0);
    }
    uint64_t post = mach_absolute_time();
    siginfo_t si;
    if (waitid(P_PID, (id_t)c, &si, WEXITED | WNOWAIT) != 0) return bad("waitid", errno, 0);
    struct rusage_info_v6 z;
    if (proc_pid_rusage(c, RUSAGE_INFO_V6, &z) != 0) return bad("the zombie", errno, 0);
    if (z.ri_proc_exit_abstime <= z.ri_proc_start_abstime || z.ri_proc_start_abstime < pre || z.ri_proc_start_abstime > post) return bad("its start and end", (long)(z.ri_proc_start_abstime - pre), (long)(post - pre));
    if (z.ri_wired_size || z.ri_resident_size || z.ri_phys_footprint || ns_of(z.ri_user_time) < 20000000) return bad("its memory and time", (long)z.ri_phys_footprint, 0);
    if (z.ri_lifetime_max_phys_footprint < SPAN || z.ri_interval_max_phys_footprint < SPAN) return bad("its peaks", (long)z.ri_lifetime_max_phys_footprint, (long)SPAN);
    if (zeros(&z, "a zombie's zero field")) return 1;
    if (proc_pid_rusage(getpid(), RUSAGE_INFO_V1, &r) != 0 || r.ri_child_user_time) return bad("not reaped yet", (long)r.ri_child_user_time, 0);
    waitpid(c, NULL, 0);
    if (proc_pid_rusage(c, RUSAGE_INFO_V6, &r) != -1 || errno != ESRCH) return bad("reaped", errno, ESRCH);
    proc_pid_rusage(getpid(), RUSAGE_INFO_V1, &r);
    if (r.ri_child_user_time != z.ri_user_time || r.ri_child_system_time || r.ri_child_elapsed_abstime != z.ri_proc_exit_abstime - z.ri_proc_start_abstime)
        return bad("its sums", (long)r.ri_child_elapsed_abstime, (long)(z.ri_proc_exit_abstime - z.ri_proc_start_abstime));

    // SA_NOCLDWAIT: a child that tells its elapsed time so far, its sums
    // twice.
    uint64_t sums = r.ri_child_elapsed_abstime;
    struct sigaction sa = { .sa_handler = SIG_DFL, .sa_flags = SA_NOCLDWAIT };
    sigaction(SIGCHLD, &sa, NULL);
    int pp[2];
    pipe(pp);
    uint64_t forked = mach_absolute_time();
    c = fork();
    if (c == 0) {
        struct rusage_info_v6 s;
        proc_pid_rusage(getpid(), RUSAGE_INFO_V0, &s);
        uint64_t so_far = mach_absolute_time() - s.ri_proc_start_abstime;
        write(pp[1], &so_far, sizeof so_far);
        _exit(0);
    }
    uint64_t so_far = 0;
    read(pp[0], &so_far, sizeof so_far);
    while (kill(c, 0) == 0) usleep(1000);
    uint64_t gone = mach_absolute_time();
    proc_pid_rusage(getpid(), RUSAGE_INFO_V1, &r);
    uint64_t added = r.ri_child_elapsed_abstime - sums;
    if (added < 2 * so_far || added > 2 * (gone - forked) || added % 2) return bad("a P_NOCLDWAIT child's elapsed time, twice", (long)added, (long)(2 * so_far));

    // Another user's process: the caller's PRIV_GLOBAL_PROC_INFO.
    if (getuid() == 0) {
        sa.sa_flags = 0;
        sigaction(SIGCHLD, &sa, NULL);
        c = fork();
        if (c == 0) {
            if (setuid(501) != 0) _exit(2);
            _exit(proc_pid_rusage(getppid(), RUSAGE_INFO_V0, &r) == -1 && errno == EPERM ? 0 : 1);
        }
        int st;
        waitpid(c, &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) return bad("another user's process", st, 0);
    }
    // The footprint's peaks, after the child sums above (another process
    // read here is reaped, and its time added to them).
    if (peaks() || other() || instructions() || page_ins() || disk_io()) return 1;
    printf("rusage ok\n");
    return 0;
}
