// A pipe() pipe handed on to a posix_spawn's dynamic child (itself,
// "child"), which inherits both of its ends: the parent writes a message
// through it and closes its write end; the child closes its own copy of the
// write end, reads to the end of the file and answers through a second
// pipe with what it read; the parent reads that answer to its end and
// waits for the child.
//
// With no argument: "pipespawn spawn E answer A wait W exit X", E
// posix_spawn's error, A the child's answer ("N:BYTES", N the bytes it
// read), W 1 when wait4 answered the child (else its errno, negated), X
// its exit status (0 when it read the message whole, then the end of the
// file; 1 when it read something else; 2 when a read failed), or its
// signal negated; then "pipespawn ok".

#include <errno.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static const char MSG[] = "through a darwin pipe";

static ssize_t read_all(int fd, char *buf, size_t cap) {
    size_t got = 0;
    for (;;) {
        ssize_t n = read(fd, buf + got, cap - got);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return (ssize_t)got;
        got += (size_t)n;
        if (got == cap) return (ssize_t)got;
    }
}

int main(int argc, char **argv) {
    if (argc > 5 && strcmp(argv[1], "child") == 0) {
        int down_r = atoi(argv[2]), down_w = atoi(argv[3]), up_r = atoi(argv[4]), up_w = atoi(argv[5]);
        close(down_w);
        close(up_r);
        char buf[256];
        ssize_t n = read_all(down_r, buf, sizeof buf - 1);
        if (n < 0) return 2;
        buf[n] = 0;
        char answer[300];
        int len = snprintf(answer, sizeof answer, "%zd:%s", n, buf);
        write(up_w, answer, (size_t)len);
        close(up_w);
        return (size_t)n == strlen(MSG) && memcmp(buf, MSG, (size_t)n) == 0 ? 0 : 1;
    }
    int down[2], up[2];
    if (pipe(down) || pipe(up)) {
        printf("pipespawn pipe %d\n", errno);
        return 1;
    }
    char a[4][16];
    int fds[4] = {down[0], down[1], up[0], up[1]};
    for (int i = 0; i < 4; i++) snprintf(a[i], sizeof a[i], "%d", fds[i]);
    char *av[] = {argv[0], "child", a[0], a[1], a[2], a[3], NULL};
    pid_t pid = 0;
    int e = posix_spawn(&pid, argv[0], NULL, NULL, av, environ);
    close(down[0]);
    close(up[1]);
    if (e == 0) write(down[1], MSG, strlen(MSG));
    close(down[1]);
    char answer[300];
    ssize_t n = e == 0 ? read_all(up[0], answer, sizeof answer - 1) : 0;
    answer[n < 0 ? 0 : n] = 0;
    close(up[0]);
    int st = 0;
    pid_t w = e == 0 ? wait4(pid, &st, 0, NULL) : -1;
    int werr = w == pid ? 0 : errno;
    int code = WIFEXITED(st) ? WEXITSTATUS(st) : WIFSIGNALED(st) ? -WTERMSIG(st) : -1000;
    printf("pipespawn spawn %d answer %s wait %d exit %d\n", e, answer, w == pid ? 1 : -werr, code);
    char want[300];
    snprintf(want, sizeof want, "%zu:%s", strlen(MSG), MSG);
    if (e == 0 && strcmp(answer, want) == 0 && w == pid && code == 0) printf("pipespawn ok\n");
    return 0;
}
