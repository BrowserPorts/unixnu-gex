// A kqueue's descriptor closed while another thread waits in kevent on it
// (fileproc_drain's kqueue_drain, KQ_DRAIN): the wait fails with EBADF,
// whether or not a duplicate keeps the kqueue, and KQ_DRAIN stays: a later
// kevent of the duplicate fails too.

#include <errno.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/event.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("kqdrain: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

static int kq;
static long got;
static int err;

static void *waiter(void *arg) {
    (void)arg;
    struct kevent ev;
    got = kevent(kq, NULL, 0, &ev, 1, NULL);
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
    for (int dup_kept = 0; dup_kept < 2; dup_kept++) {
        kq = kqueue();
        if (kq < 0) return bad("kqueue", errno, 0);
        int keep = dup_kept ? dup(kq) : -1;
        pthread_t t;
        got = -2;
        pthread_create(&t, NULL, waiter, NULL);
        if (!asleep(t)) return bad("waiter asleep", 0, 1);
        if (close(kq) != 0) return bad("close", errno, 0);
        pthread_join(t, NULL);
        if (got != -1 || err != EBADF) return bad(dup_kept ? "kevent woken (dup kept)" : "kevent woken", err, EBADF);
        if (keep >= 0) {
            struct kevent ev;
            struct timespec zero = {0, 0};
            long r = kevent(keep, NULL, 0, &ev, 1, &zero);
            if (r != -1 || errno != EBADF) return bad("a later kevent of the duplicate", r < 0 ? errno : r, EBADF);
            close(keep);
        }
    }
    printf("kqdrain ok\n");
    return 0;
}
