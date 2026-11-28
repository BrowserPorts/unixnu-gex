// A close of a descriptor another thread waits in a call on, whose file
// has no drain (a vnode's fo_no_drain): the close waits for the call to
// leave. Meanwhile the descriptor is reserved (UF_RESERVED): lookups of it
// fail, no new descriptor takes its number, and a dup2 onto it waits for
// the close to end (procfdtbl_waitfd), then takes it.

#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("closewait: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

static int fd, other;
static long locked = -2, closed = -2, duped = -2;

static void *locker(void *arg) {
    (void)arg;
    locked = flock(fd, LOCK_EX);
    return NULL;
}

static void *closer(void *arg) {
    (void)arg;
    closed = close(fd);
    return NULL;
}

static void *duper(void *arg) {
    (void)arg;
    duped = dup2(other, fd);
    return NULL;
}

// Wait until thread `t` is asleep in its call: TH_STATE_WAITING, or
// TH_STATE_UNINTERRUPTIBLE for a sleep no signal ends (the close's drain
// and the dup2's wait sleep at PRIBIO).
static int asleep(pthread_t t) {
    mach_port_t port = pthread_mach_thread_np(t);
    for (int i = 0; i < 2000; i++) {
        thread_basic_info_data_t info;
        mach_msg_type_number_t n = THREAD_BASIC_INFO_COUNT;
        if (thread_info(port, THREAD_BASIC_INFO, (thread_info_t)&info, &n) != KERN_SUCCESS) return 0;
        if (info.run_state == TH_STATE_WAITING || info.run_state == TH_STATE_UNINTERRUPTIBLE) return 1;
        usleep(1000);
    }
    return 0;
}

int main(void) {
    char path[64];
    snprintf(path, sizeof path, "/tmp/closewait%d", getpid());
    int go[2], held[2];
    if (pipe(go) != 0 || pipe(held) != 0) return bad("pipe", errno, 0);
    close(open(path, O_CREAT | O_RDWR, 0600));
    pid_t child = fork();
    if (child == 0) {
        int c = open(path, O_RDWR);
        flock(c, LOCK_EX);
        char x = 1;
        write(held[1], &x, 1);
        read(go[0], &x, 1);
        _exit(0);
    }
    char x;
    if (read(held[0], &x, 1) != 1) return bad("the child's lock", errno, 0);

    fd = open(path, O_RDWR);
    other = open("/dev/null", O_RDONLY);
    pthread_t a, b, c;
    pthread_create(&a, NULL, locker, NULL);
    if (!asleep(a)) return bad("flock asleep", 0, 1);
    pthread_create(&b, NULL, closer, NULL);
    if (!asleep(b)) return bad("close asleep", 0, 1);
    if (closed != -2) return bad("the close, with the flock still waiting", closed, -2);

    // Reserved: a lookup fails, a new descriptor goes elsewhere.
    if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) return bad("a lookup of the closing descriptor", errno, EBADF);
    int n = open("/dev/null", O_RDONLY);
    if (n == fd) return bad("a new descriptor's number", n, -1);
    close(n);

    pthread_create(&c, NULL, duper, NULL);
    if (!asleep(c)) return bad("dup2 asleep", 0, 1);
    if (duped != -2) return bad("the dup2, with the close still waiting", duped, -2);

    // The child lets its lock go: the flock gets it, the close ends, and
    // the dup2 takes the number.
    write(go[1], &x, 1);
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    pthread_join(c, NULL);
    if (locked != 0) return bad("the flock", locked, 0);
    if (closed != 0) return bad("the close", closed, 0);
    if (duped != fd) return bad("the dup2", duped, fd);
    struct stat s1, s2;
    if (fstat(fd, &s1) != 0 || fstat(other, &s2) != 0 || s1.st_rdev != s2.st_rdev || s1.st_ino != s2.st_ino) return bad("the dup2's file", errno, 0);
    // The file's lock went with its last descriptor.
    int t = open(path, O_RDWR);
    if (flock(t, LOCK_EX | LOCK_NB) != 0) return bad("the lock after the close", errno, 0);
    close(t);
    int st;
    waitpid(child, &st, 0);
    unlink(path);
    printf("closewait ok\n");
    return 0;
}
