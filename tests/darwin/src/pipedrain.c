// A pipe's descriptor closed while another thread sleeps in a call on it
// (fp_close_and_unlock's fileproc_drain): the call is woken, a read with
// nothing to read ending in 0 and a write in EPIPE, whether the close was
// the pipe end's last descriptor (pipe_drain's PIPE_DRAIN) or a duplicate
// keeps it (FPV_DRAIN); a select of it fails with EBADF. The close returns
// once the call has left; the descriptor is gone from then on.

#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("pipedrain: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

static int fd;
static char buf[65536];
static long got;
static int err;

static void *reader(void *arg) {
    (void)arg;
    got = read(fd, buf, sizeof buf);
    err = got < 0 ? errno : 0;
    return NULL;
}

static void *selector(void *arg) {
    (void)arg;
    fd_set s;
    FD_ZERO(&s);
    FD_SET(fd, &s);
    got = select(fd + 1, &s, NULL, NULL, NULL);
    err = got < 0 ? errno : 0;
    return NULL;
}

static void *writer(void *arg) {
    (void)arg;
    got = write(fd, buf, 100);
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

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    int p[2];
    pthread_t t;

    // A reader asleep on an empty pipe, its writer still open.
    if (pipe(p) != 0) return bad("pipe", errno, 0);
    fd = p[0];
    got = -2;
    pthread_create(&t, NULL, reader, NULL);
    if (!asleep(t)) return bad("reader asleep", 0, 1);
    if (close(p[0]) != 0) return bad("close of the read end", errno, 0);
    pthread_join(t, NULL);
    if (got != 0) return bad("the read woken by the close", got, 0);
    if (fcntl(p[0], F_GETFD) != -1 || errno != EBADF) return bad("the closed read end", errno, EBADF);
    if (write(p[1], "x", 1) != -1 || errno != EPIPE) return bad("a write with the read end gone", errno, EPIPE);
    close(p[1]);

    // The same with a duplicate of the read end kept: only the call in the
    // closed descriptor ends.
    if (pipe(p) != 0) return bad("pipe", errno, 0);
    int keep = dup(p[0]);
    fd = p[0];
    got = -2;
    pthread_create(&t, NULL, reader, NULL);
    if (!asleep(t)) return bad("reader asleep (dup kept)", 0, 1);
    if (close(p[0]) != 0) return bad("close of the read end (dup kept)", errno, 0);
    pthread_join(t, NULL);
    if (got != 0) return bad("the read woken by the close (dup kept)", got, 0);
    if (write(p[1], "y", 1) != 1) return bad("a write with the duplicate reading", errno, 0);
    if (read(keep, buf, 1) != 1 || buf[0] != 'y') return bad("the duplicate's read", errno, 0);
    close(keep);
    close(p[1]);

    // A select of the read end.
    if (pipe(p) != 0) return bad("pipe", errno, 0);
    fd = p[0];
    got = -2;
    pthread_create(&t, NULL, selector, NULL);
    if (!asleep(t)) return bad("selector asleep", 0, 1);
    if (close(p[0]) != 0) return bad("close of a selected end", errno, 0);
    pthread_join(t, NULL);
    if (got != -1 || err != EBADF) return bad("the select woken by the close", err, EBADF);
    close(p[1]);

    // A writer asleep on a full pipe, its reader still open.
    if (pipe(p) != 0) return bad("pipe", errno, 0);
    memset(buf, 'a', sizeof buf);
    long filled = 0;
    fcntl(p[1], F_SETFL, O_NONBLOCK);
    for (;;) {
        long n = write(p[1], buf, sizeof buf);
        if (n < 0) break;
        filled += n;
    }
    fcntl(p[1], F_SETFL, 0);
    fd = p[1];
    got = -2;
    pthread_create(&t, NULL, writer, NULL);
    if (!asleep(t)) return bad("writer asleep", 0, 1);
    if (close(p[1]) != 0) return bad("close of the write end", errno, 0);
    pthread_join(t, NULL);
    if (got != -1 || err != EPIPE) return bad("the write woken by the close", err, EPIPE);
    // What the pipe held is still there to read, then the end of it.
    long left = 0;
    for (;;) {
        long n = read(p[0], buf, sizeof buf);
        if (n <= 0) {
            if (n != 0) return bad("reading what was left", errno, 0);
            break;
        }
        left += n;
    }
    if (left != filled) return bad("bytes left", left, filled);
    close(p[0]);

    printf("pipedrain ok\n");
    return 0;
}
