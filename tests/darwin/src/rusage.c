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
// deadline timer ends is a wakeup from interrupt context. The energy
// fields are 0 (no energy counter on this SoC). The footprint's
// peaks: pages touched then unmapped are in the lifetime peak, the
// footprint after is below it, and TASK_VM_INFO's ledger peak is the same
// ledger's; an interval reset begins the interval's peak at the footprint
// then. The resident size holds the pages touched until they are
// unmapped. Another process's footprint and resident size, read from
// outside it, and its peak after it unmapped what it touched. The fields
// the kernel does not keep are reported, so a strict run stops at a
// call that copies one ("stop").

#include <errno.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <pthread/qos.h>
#include <signal.h>
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
    if (argc > 1 && strcmp(argv[1], "stop") == 0) {
        printf("rusage stop\n");
        fflush(stdout);
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
    if (peaks() || other()) return 1;
    printf("rusage ok\n");
    return 0;
}
