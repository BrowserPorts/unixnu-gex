/* With an argument, runs that many children one after another, each the
 * program at /g/c<i> (the same file under many names: a different identity
 * for every name, so each child translates its code afresh), and says how
 * many ended well. Without one, a child: code on many pages, each run often. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#define F(n) __attribute__((aligned(4096), noinline)) int f##n(int x) { return x * (n + 3) + (x >> 2); }
#define F4(n) F(n##0) F(n##1) F(n##2) F(n##3)
F4(1) F4(2) F4(3) F4(4) F4(5) F4(6)
static int (*const fs[])(int) = {
    f10, f11, f12, f13, f20, f21, f22, f23, f30, f31, f32, f33,
    f40, f41, f42, f43, f50, f51, f52, f53, f60, f61, f62, f63,
};

int main(int argc, char **argv)
{
    int i, n, good = 0, st;
    if (argc < 2) {
        int v = 1, k;
        /* many times each, so each is translated rather than interpreted */
        for (k = 0; k < 20000; k++)
            for (i = 0; i < (int)(sizeof(fs) / sizeof(fs[0])); i++) v = fs[i](v);
        return v == 0x7fffffff ? 1 : 0;
    }
    n = atoi(argv[1]);
    for (i = 0; i < n; i++) {
        char path[32];
        pid_t p;
        snprintf(path, sizeof(path), "/g/c%d", i);
        p = fork();
        if (p == 0) {
            execl(path, path, (char *)NULL);
            _exit(127);
        }
        if (p > 0 && waitpid(p, &st, 0) == p && WIFEXITED(st) && WEXITSTATUS(st) == 0) good++;
    }
    printf("slotloop: %d of %d children ran\n", good, n);
    return good == n ? 0 : 1;
}
