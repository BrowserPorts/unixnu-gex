// reboot(2) and host_reboot: a caller without root is refused (suser's
// EPERM, before its message is read), and host_reboot through the
// unprivileged host port converts to no host (KERN_INVALID_HOST); then
// "rebootcall ok". As root, with a mode: "panic" (RB_PANIC|RB_QUICK and a
// message) is refused too, the platform profile's system-reboot allowing
// RB_PANIC to initproc alone (EPERM, "rebootcall panic refused"); "halt"
// (RB_HALT|RB_QUICK), "restart" (RB_QUICK), "hostrestart" (host_reboot on
// the privileged host port), "upsdelay" (RB_QUICK|RB_UPSDELAY) and
// "hostupsdelay" (HOST_REBOOT_UPSDELAY), which halt, end the system.
//
// "full" and "fullhalt" are full shutdowns (no RB_QUICK). "fullhalt"
// (RB_HALT) has no other process: the system halts and no shutdown log is
// written. "full" (a restart) first sets up a reaper W, marked for
// delayed termination (kern.delayterm), with three children: T, which
// catches SIGTERM and exits 3; I, which ignores it; S, which catches it
// and goes on. It leaves a file it wrote, and a page of it it stored to
// through a shared mapping, unsynced. Then proc_shutdown: T and S are sent
// SIGTERM by the rebooting process (their si_pid), T exits, S does not
// within the 3 seconds; I and S are sent SIGKILL. W, which has meanwhile
// called reboot itself (EBUSY, a shutdown being under way, and P_REBOOT,
// which no signal passes), reaps them and says what it saw. In the
// delayed round W is sent SIGTERM and SIGKILL, neither of which reaches
// it, and after 3 and 10 seconds is made to exit (exit1), which the
// shutdown log records.

#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <unistd.h>

#define RB_HALT 0x08
#define RB_UPSDELAY 0x200
#define RB_QUICK 0x400
#define RB_PANIC 0x800
#define HOST_REBOOT_UPSDELAY 0x100

int reboot(int howto);
int reboot_np(int howto, const char *message);

static int bad(const char *what, long got, long want) {
    printf("rebootcall: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static void say(const char *s) {
    (void)write(1, s, strlen(s));
}

// The rebooting process, and the pipe the children report on.
static pid_t rebooter;
static int report[2];

static void t_term(int sig, siginfo_t *si, void *uc) {
    (void)sig, (void)uc;
    char r[2] = {'T', si->si_pid == rebooter ? 'r' : '?'};
    (void)write(report[1], r, 2);
    _exit(3);
}

static void s_term(int sig, siginfo_t *si, void *uc) {
    (void)sig, (void)uc;
    char r[2] = {'S', si->si_pid == rebooter ? 'r' : '?'};
    (void)write(report[1], r, 2);
}

static void w_term(int sig) {
    (void)sig;
    say("rebootcall W: SIGTERM reached a process that called reboot\n");
}

static void catch_with(void (*f)(int, siginfo_t *, void *)) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = f;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGTERM, &sa, NULL);
}

static pid_t child(int ready, char which) {
    pid_t p = fork();
    if (p != 0) return p;
    if (which == 'T') catch_with(t_term);
    if (which == 'S') catch_with(s_term);
    if (which == 'I') signal(SIGTERM, SIG_IGN);
    (void)write(ready, &which, 1);
    for (;;) pause();
}

static void how(char *out, size_t n, const char *name, int st) {
    if (WIFEXITED(st)) snprintf(out, n, "%s exit %d", name, WEXITSTATUS(st));
    else if (WIFSIGNALED(st)) snprintf(out, n, "%s signal %d", name, WTERMSIG(st));
    else snprintf(out, n, "%s status %#x", name, st);
}

static const char *from(int c) {
    return c == 'r' ? "from the rebooter" : c ? "from another" : "not caught";
}

// W: its children, then what the shutdown does to them.
static void reaper(int ready) {
    int one = 1;
    if (sysctlbyname("kern.delayterm", NULL, NULL, &one, sizeof one) != 0) {
        say("rebootcall W: kern.delayterm refused\n");
        _exit(1);
    }
    signal(SIGTERM, w_term);
    pid_t t = child(ready, 'T'), i = child(ready, 'I'), s = child(ready, 'S');
    (void)write(ready, "W", 1);
    int st;
    char line[256], a[64], b[64], c[64];
    if (waitpid(t, &st, 0) != t) _exit(1);
    how(a, sizeof a, "T", st);
    // A second shutdown while the first is under way.
    errno = 0;
    int r = reboot(RB_HALT);
    snprintf(line, sizeof line, "rebootcall W: a second reboot: %d %s\n", r, errno == EBUSY ? "EBUSY" : strerror(errno));
    say(line);
    if (waitpid(i, &st, 0) != i) _exit(1);
    how(b, sizeof b, "I", st);
    if (waitpid(s, &st, 0) != s) _exit(1);
    how(c, sizeof c, "S", st);
    char rep[8] = {0};
    int n = (int)read(report[0], rep, sizeof rep - 1);
    int t_from = 0, s_from = 0;
    for (int k = 0; k + 1 < n; k += 2) {
        if (rep[k] == 'T') t_from = rep[k + 1];
        if (rep[k] == 'S') s_from = rep[k + 1];
    }
    snprintf(line, sizeof line, "rebootcall W: %s, SIGTERM %s; %s, SIGTERM %s; %s\n", a, from(t_from), c, from(s_from), b);
    say(line);
    for (;;) pause();
}

// A file written and stored to through a shared mapping, neither synced.
static int dirty(void) {
    const char *path = "/var/tmp/gex-rebootcall-dirty";
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return bad("open the dirty file", errno, 0);
    const char *w = "rebootcall dirty write\n";
    if (write(fd, w, strlen(w)) != (ssize_t)strlen(w)) return bad("write", errno, 0);
    long pg = getpagesize();
    if (ftruncate(fd, 2 * pg) != 0) return bad("ftruncate", errno, 0);
    char *m = mmap(NULL, pg, PROT_READ | PROT_WRITE, MAP_SHARED, fd, pg);
    if (m == MAP_FAILED) return bad("mmap", errno, 0);
    const char *s = "rebootcall dirty map\n";
    memcpy(m, s, strlen(s));
    return 0;
}

static int full(void) {
    rebooter = getpid();
    int ready[2];
    if (pipe(ready) != 0 || pipe(report) != 0) return bad("pipe", errno, 0);
    fcntl(report[0], F_SETFL, O_NONBLOCK);
    pid_t w = fork();
    if (w == 0) {
        close(ready[0]);
        reaper(ready[1]);
    }
    close(ready[1]);
    char got[8];
    int n = 0;
    while (n < 4) {
        ssize_t k = read(ready[0], got + n, sizeof got - n);
        if (k <= 0) return bad("the children's readiness", n, 4);
        n += (int)k;
    }
    if (dirty()) return 1;
    say("rebootcall full: shutting down\n");
    int r = reboot(0);
    return bad("the call returned", r == -1 ? errno : r, 0);
}

int main(int argc, char **argv) {
    if (argc == 1) {
        if (getuid() == 0) return bad("uid", 0, 501);
        errno = 0;
        if (reboot(RB_HALT | RB_QUICK) != -1 || errno != EPERM) return bad("reboot as a user", errno, EPERM);
        errno = 0;
        // The message is not read: an address nothing is at is no fault.
        if (reboot_np(RB_PANIC | RB_QUICK, (const char *)8) != -1 || errno != EPERM) return bad("reboot_np as a user", errno, EPERM);
        kern_return_t kr = host_reboot(mach_host_self(), 0);
        if (kr != KERN_INVALID_HOST) return bad("host_reboot on the host port", kr, KERN_INVALID_HOST);
        puts("rebootcall ok");
        return 0;
    }
    const char *mode = argv[1];
    int r = -1;
    if (!strcmp(mode, "panic")) {
        errno = 0;
        if (reboot_np(RB_PANIC | RB_QUICK, "gex rebootcall panic") != -1 || errno != EPERM) return bad("RB_PANIC from a process not initproc", errno, EPERM);
        puts("rebootcall panic refused");
        return 0;
    }
    if (!strcmp(mode, "full")) return full();
    if (!strcmp(mode, "fullhalt")) r = reboot(RB_HALT);
    if (!strcmp(mode, "halt")) r = reboot(RB_HALT | RB_QUICK);
    if (!strcmp(mode, "restart")) r = reboot(RB_QUICK);
    if (!strcmp(mode, "upsdelay")) r = reboot(RB_QUICK | RB_UPSDELAY);
    if (!strcmp(mode, "hostrestart") || !strcmp(mode, "hostupsdelay")) {
        mach_port_t priv = MACH_PORT_NULL;
        kern_return_t kr = host_get_host_priv_port(mach_host_self(), &priv);
        if (kr != KERN_SUCCESS) return bad("host_get_host_priv_port", kr, KERN_SUCCESS);
        kr = host_reboot(priv, strcmp(mode, "hostupsdelay") ? 0 : HOST_REBOOT_UPSDELAY);
        return bad("host_reboot returned", kr, 0);
    }
    return bad("the call returned", r == -1 ? errno : r, 0);
}
