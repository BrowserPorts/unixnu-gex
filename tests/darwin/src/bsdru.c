// getrusage's and wait4's struct rusage (kern_resource.c, kern_exit.c).
// Voluntary switches are the entries of _sleep: sigsuspend's tsleep0 is
// one whatever is pending, a pipe read that waits for data one, a read
// that finds data none, and a WNOHANG wait none. A signal a handler takes
// is one (postsig). On a unix stream a send is one message sent; a receive
// that takes data one received, one at the end of the stream none, and a
// send MSG_EOR refuses (EINVAL) none. The major faults are the task's
// page-ins (proc_pid_rusage's ri_pageins); the minor ones never below 0.
// The resident peak, in bytes, holds the pages just touched. A child's
// usage at its end, as wait4 copies it, is its own counts and those of the
// children it reaped (proc_exit's ruadd of p_cru), and its parent's
// RUSAGE_CHILDREN adds it (reap_child_locked), times as timeradd sums them.
// A wait4 whose rusage cannot be written is EFAULT after the status is
// written, and leaves the child to be waited for.

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

int proc_pid_rusage(int pid, int flavor, void *buffer);

static int bad(const char *what, long got, long want) {
    printf("bsdru: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static volatile sig_atomic_t taken;

static void on_usr1(int s) {
    (void)s;
    taken++;
}

static struct rusage self(void) {
    struct rusage r;
    memset(&r, 0, sizeof r);
    getrusage(RUSAGE_SELF, &r);
    return r;
}

// One SIGUSR1 raised while blocked, then taken by sigsuspend.
static void suspend_once(void) {
    sigset_t none;
    sigemptyset(&none);
    raise(SIGUSR1);
    sigsuspend(&none);
}

static int pipe_fds[2];

static void *late_writer(void *arg) {
    (void)arg;
    usleep(100000);
    (void)write(pipe_fds[1], "y", 1);
    return NULL;
}

// What a child (and its grandchild) do: signals taken and messages sent.
static void child_work(int signals, int sends) {
    int sv[2];
    char c;
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    for (int i = 0; i < signals; i++) suspend_once();
    for (int i = 0; i < sends; i++) {
        send(sv[0], "z", 1, 0);
        recv(sv[1], &c, 1, 0);
    }
}

int main(void) {
    signal(SIGUSR1, on_usr1);
    sigset_t usr1;
    sigemptyset(&usr1);
    sigaddset(&usr1, SIGUSR1);
    sigprocmask(SIG_BLOCK, &usr1, NULL);

    // sigsuspend with the signal already pending: one sleep, one signal.
    struct rusage a = self();
    suspend_once();
    struct rusage b = self();
    if (taken != 1) return bad("handlers run", taken, 1);
    if (b.ru_nvcsw - a.ru_nvcsw != 1) return bad("sigsuspend's voluntary switches", b.ru_nvcsw - a.ru_nvcsw, 1);
    if (b.ru_nsignals - a.ru_nsignals != 1) return bad("signals taken", b.ru_nsignals - a.ru_nsignals, 1);

    // A read that finds data: no sleep. One that waits: one.
    char ch;
    pipe(pipe_fds);
    (void)write(pipe_fds[1], "x", 1);
    a = self();
    (void)read(pipe_fds[0], &ch, 1);
    b = self();
    if (b.ru_nvcsw != a.ru_nvcsw) return bad("a read with data's voluntary switches", b.ru_nvcsw - a.ru_nvcsw, 0);
    pthread_t t;
    pthread_create(&t, NULL, late_writer, NULL);
    a = self();
    (void)read(pipe_fds[0], &ch, 1);
    b = self();
    pthread_join(t, NULL);
    if (b.ru_nvcsw - a.ru_nvcsw != 1) return bad("a waiting read's voluntary switches", b.ru_nvcsw - a.ru_nvcsw, 1);

    // A unix stream's messages.
    int sv[2];
    char buf[4];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    a = self();
    send(sv[0], "ab", 2, 0);
    if (recv(sv[1], buf, sizeof buf, 0) != 2) return bad("the received bytes", -1, 2);
    shutdown(sv[0], SHUT_WR);
    if (recv(sv[1], buf, sizeof buf, 0) != 0) return bad("a receive at the end", -1, 0);
    errno = 0;
    if (send(sv[1], "c", 1, MSG_EOR) != -1 || errno != EINVAL) return bad("a stream's MSG_EOR", errno, EINVAL);
    b = self();
    if (b.ru_msgsnd - a.ru_msgsnd != 1) return bad("messages sent", b.ru_msgsnd - a.ru_msgsnd, 1);
    if (b.ru_msgrcv - a.ru_msgrcv != 1) return bad("messages received", b.ru_msgrcv - a.ru_msgrcv, 1);

    // The page-ins, between two reads of them.
    struct rusage_info_v2 ri;
    a = self();
    if (proc_pid_rusage(getpid(), RUSAGE_INFO_V2, &ri) != 0) return bad("proc_pid_rusage", errno, 0);
    b = self();
    if ((uint64_t)a.ru_majflt > ri.ri_pageins || ri.ri_pageins > (uint64_t)b.ru_majflt) return bad("the major faults against ri_pageins", a.ru_majflt, (long)ri.ri_pageins);
    if (b.ru_minflt < 0) return bad("the minor faults", b.ru_minflt, 0);

    // The resident peak holds the pages touched.
    const size_t pages = 64, page = 16384;
    volatile char *mem = mmap(NULL, pages * page, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    for (size_t i = 0; i < pages; i++) mem[i * page] = 1;
    b = self();
    if ((size_t)b.ru_maxrss < pages * page) return bad("the resident peak", b.ru_maxrss, (long)(pages * page));
    munmap((void *)mem, pages * page);

    // A child's end, with its reaped grandchild's.
    struct rusage c0, c1, ru;
    getrusage(RUSAGE_CHILDREN, &c0);
    pid_t pid = fork();
    if (pid == 0) {
        pid_t g = fork();
        if (g == 0) {
            child_work(2, 2);
            _exit(0);
        }
        child_work(3, 1);
        int st;
        waitpid(g, &st, 0);
        _exit(0);
    }
    int st = -1;
    memset(&ru, 0, sizeof ru);
    if (wait4(pid, &st, 0, &ru) != pid) return bad("wait4", errno, 0);
    if (st != 0) return bad("the child's status", st, 0);
    if (ru.ru_nsignals != 5) return bad("the child's signals and its grandchild's", ru.ru_nsignals, 5);
    if (ru.ru_msgsnd != 3 || ru.ru_msgrcv != 3) return bad("the child's messages and its grandchild's", ru.ru_msgsnd, 3);
    getrusage(RUSAGE_CHILDREN, &c1);
    if (c1.ru_nsignals - c0.ru_nsignals != 5) return bad("the children's signals", c1.ru_nsignals - c0.ru_nsignals, 5);
    if (c1.ru_msgsnd - c0.ru_msgsnd != 3) return bad("the children's messages", c1.ru_msgsnd - c0.ru_msgsnd, 3);
    struct timeval u;
    timeradd(&c0.ru_utime, &ru.ru_utime, &u);
    if (timercmp(&u, &c1.ru_utime, !=)) return bad("the children's user time", c1.ru_utime.tv_usec, u.tv_usec);
    timeradd(&c0.ru_stime, &ru.ru_stime, &u);
    if (timercmp(&u, &c1.ru_stime, !=)) return bad("the children's system time", c1.ru_stime.tv_usec, u.tv_usec);
    if (c1.ru_maxrss < ru.ru_maxrss) return bad("the children's resident peak", c1.ru_maxrss, ru.ru_maxrss);

    // A rusage that cannot be written: EFAULT, the status written, the
    // child still there.
    pid = fork();
    if (pid == 0) _exit(3);
    st = -1;
    errno = 0;
    if (wait4(pid, &st, 0, (struct rusage *)8) != -1 || errno != EFAULT) return bad("wait4 into a bad rusage", errno, EFAULT);
    if (st != 3 << 8) return bad("the status written first", st, 3 << 8);
    st = -1;
    if (wait4(pid, &st, 0, &ru) != pid || st != 3 << 8) return bad("the child waited for again", st, 3 << 8);

    // WNOHANG finds nothing: no sleep.
    pid = fork();
    if (pid == 0) {
        for (;;) pause();
    }
    a = self();
    if (wait4(pid, &st, WNOHANG, &ru) != 0) return bad("WNOHANG", errno, 0);
    b = self();
    if (b.ru_nvcsw != a.ru_nvcsw) return bad("WNOHANG's voluntary switches", b.ru_nvcsw - a.ru_nvcsw, 0);
    kill(pid, SIGKILL);
    waitpid(pid, &st, 0);

    printf("bsdru ok\n");
    return 0;
}
