// proc_pid_rusage (proc_info call 9): an unknown flavor is EINVAL and no
// process ESRCH; another user's process is EPERM. A flavor's copy is its
// structure's size and no more. This process's record: its executable's
// UUID, its time (recount's, in Mach time units: the getrusage time, all
// of it user time, no system time), its fork's start (ps_start, with
// p_start), no end, its runnable time (at least its time), its own
// footprint, what its wirings hold (mlock's pages, until munlock), and the
// zero fields of this kernel: the flags (no ptrauth), the performance
// cluster's figures (no AMP), the secure times and what follows them. A
// child that has ended and is not yet reaped is read from what its exit
// gathered: its end after its start, nothing wired, resident or in its
// footprint. Once reaped, its time and its elapsed time (end less start)
// are its parent's ri_child sums; a parent with SA_NOCLDWAIT has them
// added twice (at the child's exit and at the system's reap). The fields
// the kernel does not keep are reported, so a strict run stops at a
// call that copies one ("stop").

#include <errno.h>
#include <mach/mach_time.h>
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

// The record's fields this kernel leaves 0.
static int zeros(const struct rusage_info_v6 *r, const char *whose) {
    const uint64_t *after = &r->ri_neural_footprint;
    for (int i = 0; i < 12; i++)
        if (after[i]) return bad(whose, (long)after[i], 0);
    if (r->ri_system_time || r->ri_flags || r->ri_user_ptime || r->ri_system_ptime || r->ri_pinstructions || r->ri_pcycles || r->ri_penergy_nj || r->ri_secure_time_in_system || r->ri_secure_ptime_in_system)
        return bad(whose, 1, 0);
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
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct { uint8_t uuid[16]; uint64_t uniqueid, puniqueid; int32_t idversion; uint32_t r2; uint64_t r3, r4; } u;
    if (proc_pidinfo(getpid(), 17, 0, &u, sizeof u) != sizeof u || memcmp(u.uuid, r.ri_uuid, 16)) return bad("its UUID", errno, 0);
    uint64_t t = ns_of(r.ri_user_time);
    if (t + 1000 < before || t > after + 1000) return bad("its time (ms)", (long)(t / 1000000), (long)(before / 1000000));
    if (zeros(&r, "a zero field")) return 1;
    if (r.ri_proc_exit_abstime != 0 || r.ri_proc_start_abstime == 0 || r.ri_proc_start_abstime >= now) return bad("its start and end", (long)r.ri_proc_exit_abstime, 0);
    // p_start was read with ps_start (the calendar clock may be slewed
    // against the Mach clock meanwhile: 0.2% of the time since).
    struct { uint32_t f[30]; uint64_t start_sec, start_usec; } b;
    if (proc_pidinfo(getpid(), 3, 0, &b, 136) != 136) return bad("its BSD info", errno, 0);
    int64_t wall = ((int64_t)tv.tv_sec - (int64_t)b.start_sec) * 1000000 + ((int64_t)tv.tv_usec - (int64_t)b.start_usec);
    int64_t mach = (int64_t)(ns_of(now - r.ri_proc_start_abstime) / 1000);
    if (llabs(wall - mach) > 20000 + mach / 500) return bad("its start against p_start (us)", (long)mach, (long)wall);
    if (r.ri_runnable_time < r.ri_user_time) return bad("its runnable time", (long)r.ri_runnable_time, (long)r.ri_user_time);
    if (r.ri_phys_footprint == 0) return bad("its footprint", 0, 1);
    if (r.ri_child_user_time || r.ri_child_elapsed_abstime || r.ri_billed_system_time || r.ri_serviced_system_time || r.ri_billed_energy || r.ri_serviced_energy) return bad("no children, no bank bills", 1, 0);

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
        _exit(0);
    }
    uint64_t post = mach_absolute_time();
    siginfo_t si;
    if (waitid(P_PID, (id_t)c, &si, WEXITED | WNOWAIT) != 0) return bad("waitid", errno, 0);
    struct rusage_info_v6 z;
    if (proc_pid_rusage(c, RUSAGE_INFO_V6, &z) != 0) return bad("the zombie", errno, 0);
    if (z.ri_proc_exit_abstime <= z.ri_proc_start_abstime || z.ri_proc_start_abstime < pre || z.ri_proc_start_abstime > post) return bad("its start and end", (long)(z.ri_proc_start_abstime - pre), (long)(post - pre));
    if (z.ri_wired_size || z.ri_resident_size || z.ri_phys_footprint || ns_of(z.ri_user_time) < 20000000) return bad("its memory and time", (long)z.ri_phys_footprint, 0);
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
    printf("rusage ok\n");
    return 0;
}
