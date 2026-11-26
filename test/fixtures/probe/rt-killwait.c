/* rt-killwait N: N rounds of a child whose threads all wait -- one on a
 * futex (a condition variable), one reading an empty pipe, one in poll on
 * a socket, the main thread in nanosleep -- killed with SIGKILL by its
 * parent. Each round's line says how the child ended and how long the
 * kill took to end it (core/kill-race: a SIGKILL delivered ends every
 * thread, whatever it waits on). */
#include <pthread.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int pfd[2], sv[2], up[2];

static void *on_futex(void *_) {
    pthread_mutex_lock(&mu);
    (void)!write(up[1], "f", 1);
    for (;;) pthread_cond_wait(&cv, &mu);
}
static void *on_pipe(void *_) {
    char c;
    (void)!write(up[1], "p", 1);
    for (;;) (void)!read(pfd[0], &c, 1);
}
static void *on_poll(void *_) {
    struct pollfd p = { .fd = sv[0], .events = POLLIN };
    (void)!write(up[1], "s", 1);
    for (;;) poll(&p, 1, -1);
}

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 1;
    for (int r = 0; r < n; r++) {
        if (pipe(up) || pipe(pfd) || socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) return 2;
        pid_t c = fork();
        if (c == 0) {
            pthread_t t;
            pthread_create(&t, 0, on_futex, 0);
            pthread_create(&t, 0, on_pipe, 0);
            pthread_create(&t, 0, on_poll, 0);
            for (;;) sleep(100);
        }
        char b;
        for (int k = 0; k < 3; k++) (void)!read(up[0], &b, 1);
        usleep(50000); /* all three parked */
        double t0 = now();
        kill(c, SIGKILL);
        int st = 0;
        pid_t got = 0;
        while ((got = waitpid(c, &st, WNOHANG)) == 0 && now() - t0 < 10) usleep(1000);
        int how = got == c ? (WIFSIGNALED(st) ? 128 + WTERMSIG(st) : WEXITSTATUS(st)) : -1;
        printf("killwait %d %d %.0f\n", r, how, (now() - t0) * 1000);
        if (got != c) { kill(c, SIGKILL); waitpid(c, &st, 0); }
        close(up[0]); close(up[1]); close(pfd[0]); close(pfd[1]); close(sv[0]); close(sv[1]);
    }
    return 0;
}
