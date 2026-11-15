// Processor time: a thread's clock (CLOCK_THREAD_CPUTIME_ID, from
// thread_selfusage) runs while it computes and not while it sleeps (nor
// while the host translates its code: a new process's main thread has
// used little of it by main); the
// process's (getrusage RUSAGE_SELF) holds the same time; a child's, reaped,
// is its parent's RUSAGE_CHILDREN, a child killed as it computes too. The
// release kernel counts a thread's time in the kernel as user time
// (recount without PRECISE_USER_KERNEL_TIME): no system time at all. An
// exec's thread keeps the time its thread had (thread_copy_resource_info),
// and its process the time of its process.

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("cputime: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static uint64_t thread_ns(void) {
    return clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID);
}

static uint64_t tv_ns(struct timeval tv) {
    return (uint64_t)tv.tv_sec * 1000000000u + (uint64_t)tv.tv_usec * 1000u;
}

static uint64_t usage_ns(int who) {
    struct rusage ru;
    getrusage(who, &ru);
    return tv_ns(ru.ru_utime) + tv_ns(ru.ru_stime);
}

static long system_us(int who) {
    struct rusage ru;
    getrusage(who, &ru);
    return (long)ru.ru_stime.tv_sec * 1000000 + ru.ru_stime.tv_usec;
}

static volatile uint64_t sink;

// Compute until this thread has used `ns` more.
static void spin(uint64_t ns) {
    uint64_t until = thread_ns() + ns;
    while (thread_ns() < until) {
        for (int i = 0; i < 100000; i++) sink += (uint64_t)i * i;
    }
}

// After the exec of a thread that had used `argv[2]` and a process that
// had used `argv[3]`.
static int after_exec(char **argv) {
    uint64_t t = thread_ns(), u = usage_ns(RUSAGE_SELF);
    uint64_t before = strtoull(argv[2], NULL, 10), process = strtoull(argv[3], NULL, 10);
    if (t < before) return bad("the thread's clock after an exec", (long)(t / 1000000), (long)(before / 1000000));
    if (u < process) return bad("the process's time after an exec", (long)(u / 1000000), (long)(process / 1000000));
    return 0;
}

int main(int argc, char **argv) {
    const uint64_t ms = 1000000;
    if (argc == 4) return after_exec(argv);
    uint64_t t0 = thread_ns(), u0 = usage_ns(RUSAGE_SELF);
    if (t0 > 500 * ms) return bad("the main thread's time by main", (long)(t0 / ms), 0);
    spin(100 * ms);
    uint64_t t1 = thread_ns(), u1 = usage_ns(RUSAGE_SELF);
    if (t1 - t0 < 100 * ms) return bad("the thread's clock", (long)((t1 - t0) / ms), 100);
    if (u1 - u0 < 90 * ms) return bad("the process's time", (long)((u1 - u0) / ms), 100);
    usleep(200000);
    uint64_t t2 = thread_ns();
    if (t2 - t1 > 50 * ms) return bad("time asleep", (long)((t2 - t1) / ms), 0);
    // Calls made (getrusage, usleep, the clock's): still no system time.
    if (system_us(RUSAGE_SELF)) return bad("the process's system time", system_us(RUSAGE_SELF), 0);

    // A child computing, then exiting; then one killed as it computes.
    int st;
    pid_t pid = fork();
    if (pid == 0) {
        spin(100 * ms);
        _exit(0);
    }
    waitpid(pid, &st, 0);
    uint64_t c1 = usage_ns(RUSAGE_CHILDREN);
    if (c1 < 90 * ms) return bad("a child's time", (long)(c1 / ms), 100);
    int p[2];
    pipe(p);
    pid = fork();
    if (pid == 0) {
        spin(100 * ms);
        write(p[1], "x", 1);
        for (;;) sink++;
    }
    char c;
    read(p[0], &c, 1);
    kill(pid, SIGKILL);
    waitpid(pid, &st, 0);
    uint64_t c2 = usage_ns(RUSAGE_CHILDREN);
    if (c2 - c1 < 90 * ms) return bad("a killed child's time", (long)((c2 - c1) / ms), 100);
    if (system_us(RUSAGE_CHILDREN)) return bad("the children's system time", system_us(RUSAGE_CHILDREN), 0);

    // A child that computes, then execs this program.
    pid = fork();
    if (pid == 0) {
        spin(100 * ms);
        char t[24], u[24];
        snprintf(t, sizeof t, "%llu", (unsigned long long)thread_ns());
        snprintf(u, sizeof u, "%llu", (unsigned long long)usage_ns(RUSAGE_SELF));
        char *args[] = {argv[0], "exec", t, u, NULL};
        execv(argv[0], args);
        _exit(100);
    }
    waitpid(pid, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) return bad("the exec'd child's status", st, 0);
    printf("cputime ok\n");
    return 0;
}
