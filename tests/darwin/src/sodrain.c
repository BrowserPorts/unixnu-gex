// A socket's descriptor closed while another thread sleeps in a call on it
// (fileproc_drain's soo_drain, SS_DRAINING): a receive's wait fails with
// EBADF and an accept's with ECONNABORTED, whether or not a duplicate keeps
// the socket; and SS_DRAINING stays: a later receive that would wait fails
// at once, while a send with room goes on.

#include <errno.h>
#include <mach/mach.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("sodrain: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

static int fd, accepting;

static void woke(int sig) {
    (void)sig;
}
static long got;
static int err;

static void *body(void *arg) {
    (void)arg;
    char b[16];
    got = accepting ? accept(fd, NULL, NULL) : recv(fd, b, sizeof b, 0);
    err = got < 0 ? errno : 0;
    return NULL;
}

// Wait until thread `t` is asleep (TH_STATE_WAITING): in its call.
static int asleep(pthread_t t) {
    mach_port_t port = pthread_mach_thread_np(t);
    for (int i = 0; i < 2000; i++) {
        thread_basic_info_data_t info;
        mach_msg_type_number_t n = THREAD_BASIC_INFO_COUNT;
        if (thread_info(port, THREAD_BASIC_INFO, (thread_info_t)&info, &n) != KERN_SUCCESS) return 0;
        if (info.run_state == TH_STATE_WAITING) return 1;
        usleep(1000);
    }
    return 0;
}

// Close `s` while another thread sleeps in accept (or recv) on it: the
// call's errno.
static int drained(int s, int acc) {
    pthread_t t;
    fd = s;
    accepting = acc;
    got = -2;
    pthread_create(&t, NULL, body, NULL);
    if (!asleep(t)) return -1;
    if (close(s) != 0) return -2;
    pthread_join(t, NULL);
    return got == -1 ? err : 0;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    struct sockaddr_un a = {0};
    a.sun_family = AF_UNIX;
    snprintf(a.sun_path, sizeof a.sun_path, "/tmp/sodrain%d", getpid());

    for (int dup_kept = 0; dup_kept < 2; dup_kept++) {
        unlink(a.sun_path);
        int s = socket(AF_UNIX, SOCK_STREAM, 0);
        if (bind(s, (struct sockaddr *)&a, sizeof a) != 0 || listen(s, 4) != 0) return bad("listen", errno, 0);
        int keep = dup_kept ? dup(s) : -1;
        int e = drained(s, 1);
        if (e != ECONNABORTED) return bad(dup_kept ? "accept woken (dup kept)" : "accept woken", e, ECONNABORTED);
        if (keep >= 0) close(keep);
        unlink(a.sun_path);
    }

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return bad("socketpair", errno, 0);
    int e = drained(sv[0], 0);
    if (e != EBADF) return bad("recv woken", e, EBADF);
    close(sv[1]);

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return bad("socketpair", errno, 0);
    int keep = dup(sv[0]);
    e = drained(sv[0], 0);
    if (e != EBADF) return bad("recv woken (dup kept)", e, EBADF);
    char b[4];
    // SS_DRAINING stays on the socket: a receive that does not wait is
    // EAGAIN, one that would wait fails at once, a send with room goes on.
    long r = recv(keep, b, sizeof b, MSG_DONTWAIT);
    if (r != -1 || errno != EAGAIN) return bad("a later recv that does not wait", errno, EAGAIN);
    // (An alarm ends it, EINTR, should it wait after all.)
    struct sigaction sa = {0};
    sa.sa_handler = woke;
    sigaction(SIGALRM, &sa, NULL);
    alarm(5);
    r = recv(keep, b, sizeof b, 0);
    int e2 = errno;
    alarm(0);
    if (r != -1 || e2 != EBADF) return bad("a later recv that would wait", e2, EBADF);
    if (send(keep, "x", 1, 0) != 1) return bad("a later send with room", errno, 0);
    if (recv(sv[1], b, 1, 0) != 1 || b[0] != 'x') return bad("the peer's recv", errno, 0);
    close(keep);
    close(sv[1]);

    printf("sodrain ok\n");
    return 0;
}
