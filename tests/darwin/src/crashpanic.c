// A process spawned with a crash behavior (posix_spawnattr_set_crash_
// behavior_np, _deadline_np), as launchd spawns its boot tasks: its end
// panics the system when its flags say (proc_handle_critical_exit), and
// only a spawner entitled to com.apple.private.spawn-panic-crash-behavior
// gives them.
//
// Without arguments: the ends that do not panic (an exit of 0 under
// PANIC_ON_NON_ZERO_EXIT; SIGKILL and SIGTERM, and a reason that asks for
// no crash report, under PANIC_ON_CRASH; a crash under PANIC_ON_NON_ZERO_
// EXIT alone; an expired deadline), then "crashpanic ok". The copy without
// the entitlement ("crashpanicnoent"): PANIC_ON_EXIT given, no panic.
// With a mode: one end that panics; the spawned child's pid is printed
// first, and the run ends with the system's panic.

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define PANIC_ON_CRASH 0x1
#define PANIC_ON_NON_ZERO_EXIT 0x2
#define PANIC_ON_EXIT 0x4
#define PANIC_ON_SPAWN_FAIL 0x8
#define OS_REASON_FLAG_NO_CRASH_REPORT 0x1

extern char **environ;
int posix_spawnattr_set_crash_behavior_np(posix_spawnattr_t *attr, uint32_t flags);
int posix_spawnattr_set_crash_behavior_deadline_np(posix_spawnattr_t *attr, uint64_t deadline, uint32_t flags);
void abort_with_reason(uint32_t ns, uint64_t code, const char *s, uint64_t flags) __attribute__((noreturn));
int terminate_with_reason(int pid, uint32_t ns, uint64_t code, const char *s, uint64_t flags);
uint64_t mach_continuous_time(void);

static char self[1024];

static int child(const char *what) {
    char c;
    if (!strcmp(what, "exit3")) return 3;
    if (!strcmp(what, "exit0")) return 0;
    if (!strcmp(what, "fault")) {
        volatile int *z = (volatile int *)0x7ff000000000;
        *z = 1;
    }
    if (!strcmp(what, "abort")) abort_with_reason(18, 0x42, "crashpanic abort", 0);
    // Until its standard input ends.
    while (read(0, &c, 1) > 0) {
    }
    return 0;
}

// Spawn this program as `what` with crash behavior `flags` (and the
// deadline, when one is given), its standard input a pipe's end: its pid,
// -1 when the spawn failed (errno its error).
static pid_t run(const char *what, uint32_t flags, uint64_t deadline, const char *open_first, int *wr) {
    int p[2];
    pipe(p);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    if (open_first) posix_spawn_file_actions_addopen(&fa, 5, open_first, O_RDONLY, 0);
    posix_spawn_file_actions_adddup2(&fa, p[0], 0);
    posix_spawn_file_actions_addclose(&fa, p[1]);
    posix_spawnattr_t at;
    posix_spawnattr_init(&at);
    // The deadline's setter takes flags but keeps only the deadline.
    posix_spawnattr_set_crash_behavior_np(&at, flags);
    if (deadline) posix_spawnattr_set_crash_behavior_deadline_np(&at, deadline, 0);
    char *args[] = {self, "child", (char *)what, NULL};
    pid_t pid = -1;
    int e = posix_spawn(&pid, self, &fa, &at, args, environ);
    close(p[0]);
    if (e) {
        close(p[1]);
        errno = e;
        return -1;
    }
    *wr = p[1];
    return pid;
}

static int bad(const char *what, long got, long want) {
    printf("crashpanic: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

// A child that ends as `what` (or is sent `sig`, or a reason) and must not
// panic: its wait status.
static int ends(const char *what, uint32_t flags, uint64_t deadline, int sig, int reason) {
    int wr, st = -1;
    pid_t pid = run(what, flags, deadline, NULL, &wr);
    if (pid < 0) return -1;
    if (sig) kill(pid, sig);
    if (reason) terminate_with_reason(pid, 18, 0x44, "crashpanic quiet", OS_REASON_FLAG_NO_CRASH_REPORT);
    close(wr);
    waitpid(pid, &st, 0);
    return st;
}

static void spawned(pid_t pid) {
    printf("spawned %d\n", pid);
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "child")) return child(argv[2]);
    strcpy(self, argv[0]);
    int st, wr;
    if (argc == 1) {
        int noent = strstr(self, "noent") != NULL;
        if ((st = ends("exit0", noent ? PANIC_ON_EXIT : PANIC_ON_NON_ZERO_EXIT, 0, 0, 0)) != 0) return bad("exit 0", st, 0);
        if (noent) {
            puts("crashpanic noent ok");
            return 0;
        }
        if ((st = ends("wait", PANIC_ON_CRASH, 0, SIGKILL, 0)) != SIGKILL) return bad("SIGKILL", st, SIGKILL);
        if ((st = ends("wait", PANIC_ON_CRASH, 0, SIGTERM, 0)) != SIGTERM) return bad("SIGTERM", st, SIGTERM);
        if ((st = ends("wait", PANIC_ON_CRASH, 0, 0, 1)) != SIGKILL) return bad("a reason with no crash report", st, SIGKILL);
        if ((st = ends("fault", PANIC_ON_NON_ZERO_EXIT, 0, 0, 0)) != SIGSEGV && st != SIGBUS) return bad("a crash under PANIC_ON_NON_ZERO_EXIT", st, SIGSEGV);
        if ((st = ends("exit3", PANIC_ON_NON_ZERO_EXIT, mach_continuous_time(), 0, 0)) != 3 << 8) return bad("an expired deadline", st, 3 << 8);
        puts("crashpanic ok");
        return 0;
    }
    const char *mode = argv[1];
    pid_t pid = -1;
    if (!strcmp(mode, "exit")) pid = run("exit3", PANIC_ON_NON_ZERO_EXIT, 0, NULL, &wr);
    if (!strcmp(mode, "onexit")) pid = run("exit0", PANIC_ON_EXIT, 0, NULL, &wr);
    if (!strcmp(mode, "crash")) pid = run("fault", PANIC_ON_CRASH, 0, NULL, &wr);
    if (!strcmp(mode, "abort")) pid = run("abort", PANIC_ON_CRASH, 0, NULL, &wr);
    if (!strcmp(mode, "deadline")) pid = run("exit3", PANIC_ON_NON_ZERO_EXIT, mach_continuous_time() + (1ull << 50), NULL, &wr);
    if (!strcmp(mode, "terminate")) {
        pid = run("wait", PANIC_ON_CRASH, 0, NULL, &wr);
        if (pid > 0) {
            spawned(pid);
            terminate_with_reason(pid, 18, 0x43, "crashpanic terminate", 0);
        }
    } else if (!strcmp(mode, "spawnfail")) {
        // The spawn fails at its file actions, after its process is made.
        pid = run("exit0", PANIC_ON_SPAWN_FAIL, 0, "/private/var/tmp/gex-crashpanic-none", &wr);
        return bad("a spawn that fails", pid, -1);
    } else if (pid > 0) {
        spawned(pid);
    }
    if (pid < 0) return bad("spawn", errno, 0);
    close(wr);
    waitpid(pid, &st, 0);
    return bad("the system went on after its end", st, 0);
}
