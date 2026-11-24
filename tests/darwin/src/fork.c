// fork by kern_fork.c's rules: the parent gets the child's pid, the child
// zero (its x1 set) with this process as its parent; the child has the
// descriptors but not the kqueue (FG_CONFINED) nor one opened O_CLOFORK
// (F_GETFD shows no such flag; a spawned child lacks it too), a task of
// its own whose
// ports work (libSystem's fork handlers set them up again in its new
// space) and thread calls (a kqueue timer fires in it), and its end is the
// parent's to collect; the parent's EVFILT_PROC knote on itself hears
// NOTE_FORK. Its process control (p_pcaction, PROC_SELFSET_PCONTROL's) is
// the parent's (forkproc_init copies p_forkcopy), in a fork's child, a
// spawn's without attributes, and that child after an exec in place (whose
// new proc cloneproc makes the same way).

#include <TargetConditionals.h>
#include <errno.h>
#include <spawn.h>
#include <stdlib.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <stdio.h>
#include <string.h>
#include <sys/event.h>
#include <sys/wait.h>
#include <unistd.h>

int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);
int __proc_info(int callnum, int pid, int flavor, uint64_t arg, void *buffer, int buffersize);

// PROC_PIDT_SHORTBSDINFO's.
struct shortinfo {
    uint32_t pid, ppid, pgid, status;
    char comm[16];
    uint32_t flags, uid, gid, ruid, rgid, svuid, svgid, rfu;
};

// Its pbi_flags' process control bits (PROC_FLAG_PC_*: 0x600).
static unsigned control(void) {
    struct shortinfo s;
    if (proc_pidinfo(getpid(), 13, 0, &s, sizeof s) != sizeof s) return ~0u;
    return s.flags & 0x600;
}

static int bad(const char *what, long v) {
    printf("fork: %s (%ld)\n", what, v);
    return 1;
}

extern char **environ;

// F_GETFD of an O_CLOFORK descriptor: xnu-10063's reports no close-on-fork
// flag; later kernels (a Mac's) report FD_CLOFORK.
#if TARGET_OS_OSX
#define CLOFORK_GETFD FD_CLOFORK
#else
#define CLOFORK_GETFD 0
#endif

int main(int argc, char **argv) {
    // A spawned child: whether descriptor argv[1] is closed, its control
    // its parent's (PROC_FLAG_PC_SUSP); then, after its exec in place,
    // whether the control is still that.
    if (argc > 2) return control() == 0x400 ? 0 : 3;
    if (argc > 1) {
        if (fcntl(atoi(argv[1]), F_GETFD) != -1 || errno != EBADF) return 1;
        if (control() != 0x400) return 2;
        char *xargs[] = {argv[0], argv[1], "exec", NULL};
        execv(argv[0], xargs);
        return 4;
    }
    int cf = open("/dev/null", O_RDONLY | O_CLOFORK);
    if (cf < 0 || fcntl(cf, F_GETFD) != CLOFORK_GETFD) return bad("an O_CLOFORK open", errno);
    int p[2];
    pipe(p);
    int kq = kqueue();
    struct kevent ev;
    EV_SET(&ev, getpid(), EVFILT_PROC, EV_ADD, NOTE_FORK, 0, 0);
    if (kevent(kq, &ev, 1, NULL, 0, NULL)) return bad("the knote", errno);
    pid_t parent = getpid();
    // P_PCSUSP.
    if (__proc_info(5, getpid(), 1, 2, NULL, 0) != 0 || control() != 0x400) return bad("PROC_SELFSET_PCONTROL", errno);
    pid_t pid = fork();
    if (pid < 0) return bad("fork", errno);
    if (pid == 0) {
        close(p[0]);
        const char *say = "child ok";
        if (getpid() == parent || getppid() != parent) say = "child: pids";
        else if (fcntl(kq, F_GETFD) != -1 || errno != EBADF) say = "child: the kqueue";
        else if (fcntl(cf, F_GETFD) != -1 || errno != EBADF) say = "child: the O_CLOFORK descriptor";
        else if (control() != 0x400) say = "child: its process control";
        else {
            int who = -1;
            if (pid_for_task(mach_task_self(), &who) != KERN_SUCCESS || who != getpid()) say = "child: its task port";
            int kq2 = kqueue();
            struct kevent t;
            EV_SET(&t, 1, EVFILT_TIMER, EV_ADD | EV_ONESHOT, 0, 50, 0);
            struct timespec two = {2, 0};
            if (kevent(kq2, &t, 1, &t, 1, &two) != 1 || t.filter != EVFILT_TIMER) say = "child: a timer";
        }
        write(p[1], say, strlen(say));
        _exit(5);
    }
    close(p[1]);
    char buf[64] = {0};
    size_t got = 0;
    ssize_t k;
    while ((k = read(p[0], buf + got, sizeof buf - 1 - got)) > 0) got += k;
    if (strcmp(buf, "child ok")) {
        printf("fork: %s\n", buf);
        return 1;
    }
    int st;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 5) return bad("the child's end", st);
    if (kevent(kq, NULL, 0, &ev, 1, NULL) != 1 || !(ev.fflags & NOTE_FORK) || (pid_t)ev.data != 0) return bad("NOTE_FORK", ev.fflags);
    if (fcntl(cf, F_GETFD) != CLOFORK_GETFD) return bad("the parent's O_CLOFORK descriptor", errno);
    char fdarg[16];
    snprintf(fdarg, sizeof fdarg, "%d", cf);
    char *sargs[] = {argv[0], fdarg, NULL};
    pid_t sp;
    if (posix_spawn(&sp, argv[0], NULL, NULL, sargs, environ) || waitpid(sp, &st, 0) != sp || !WIFEXITED(st) || WEXITSTATUS(st) != 0) return bad("a spawned child's O_CLOFORK descriptor and process control (1, 2: before its exec; 3: after)", st);
    printf("fork ok\n");
    return 0;
}
