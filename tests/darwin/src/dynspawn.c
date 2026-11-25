// A dynamic program's posix_spawn of a dynamic child (itself, "child"),
// waited on: the child in a process group of its own (POSIX_SPAWN_SETPGROUP
// with group 0: setpgid's work, done by the spawn), a later setpgid of it
// refused once it has exec'd (EACCES, as every spawned child has), its exit
// status, its usage among the reaped children's (getrusage
// RUSAGE_CHILDREN), and the shared cache it runs with: the system's one
// region, at its one slide.
//
// With no argument: "dynspawn spawn E pgid G setpgid S wait W exit X", E
// posix_spawn's error, G 1 when the child's group is its pid, S setpgid's
// errno, W 1 when wait4 answered the child (else its errno, negated), X
// its exit status, or its signal negated (the child exits with 7 when its
// cache is the parent's, 8 when it is not); then
// "dynspawn usage U", U 1 when the reaped children's user time is not zero
// (else getrusage's errno, negated); then "dynspawn ok".
// "dynspawn cache": "dynspawn cache A", A the shared cache's start
// (_dyld_get_shared_cache_range), in hex.

#include <errno.h>
#include <mach-o/dyld.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
extern const void *_dyld_get_shared_cache_range(size_t *length);

static uintptr_t cache_start(void) {
    size_t len = 0;
    return (uintptr_t)_dyld_get_shared_cache_range(&len);
}

int main(int argc, char **argv) {
    if (argc > 2 && strcmp(argv[1], "child") == 0) {
        // Some work of its own to be counted.
        volatile unsigned long x = 0;
        for (unsigned long i = 0; i < 20000000; i++) x += i;
        return strtoull(argv[2], NULL, 16) == cache_start() ? 7 : 8;
    }
    if (argc > 1 && strcmp(argv[1], "cache") == 0) {
        printf("dynspawn cache %lx\n", (unsigned long)cache_start());
        return 0;
    }
    posix_spawnattr_t a;
    posix_spawnattr_init(&a);
    posix_spawnattr_setflags(&a, POSIX_SPAWN_SETPGROUP);
    posix_spawnattr_setpgroup(&a, 0);
    char mine[32];
    snprintf(mine, sizeof mine, "%lx", (unsigned long)cache_start());
    pid_t pid = 0;
    char *av[] = {argv[0], "child", mine, NULL};
    int e = posix_spawn(&pid, argv[0], NULL, &a, av, environ);
    posix_spawnattr_destroy(&a);
    int pgid = e == 0 && getpgid(pid) == pid;
    int sp = setpgid(pid, getpgrp()) == 0 ? 0 : errno;
    int st = 0;
    pid_t w = e == 0 ? wait4(pid, &st, 0, NULL) : -1;
    int werr = w == pid ? 0 : errno;
    int code = WIFEXITED(st) ? WEXITSTATUS(st) : WIFSIGNALED(st) ? -WTERMSIG(st) : -1000;
    printf("dynspawn spawn %d pgid %d setpgid %d wait %d exit %d\n", e, pgid, sp, w == pid ? 1 : -werr, code);
    struct rusage ru;
    memset(&ru, 0, sizeof ru);
    int usage = getrusage(RUSAGE_CHILDREN, &ru) ? -errno : (ru.ru_utime.tv_sec || ru.ru_utime.tv_usec);
    printf("dynspawn usage %d\n", usage);
    if (e == 0 && pgid && sp == EACCES && w == pid && code == 7 && usage == 1) printf("dynspawn ok\n");
    return 0;
}
