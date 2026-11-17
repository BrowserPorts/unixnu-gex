// A file's pages are one object for every mapping and every read and write
// of it: a store through a shared mapping is seen at once through another
// mapping of the file (in this process or another, with no msync between)
// and by read, and a private mapping made since shows it until it writes
// the page; a write through the descriptor is seen in the mappings. A file's pages
// count in the resident size and as external memory, not in the
// footprint. Past the file's end there is no page: an access is SIGBUS and
// a copy from there fails with EFAULT, until the file grows to cover it;
// a page the file loses to a truncation is gone from every mapping, a
// private mapping's own copy of it kept. A POSIX shared memory object's
// pages are one object too, its size in the map's pages.

#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define PAGE 0x4000UL

extern char **environ;

static int bad(const char *what, long got, long want) {
    printf("ubcmap: %s: %#lx, want %#lx\n", what, got, want);
    fflush(stdout);
    return 1;
}

static int vm_info(task_vm_info_data_t *info) {
    mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
    return task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)info, &count) == KERN_SUCCESS ? 0 : -1;
}

// Another process: map the file shared, check its first byte, store
// another, and wait to be told to check the parent's next store.
static int other(const char *path, int up, int down) {
    int fd = open(path, O_RDWR);
    char *p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (fd < 0 || p == MAP_FAILED) return bad("the other's mapping", errno, 0);
    if (p[0] != 'P') return bad("the parent's store, in the other", p[0], 'P');
    p[1] = 'O';
    char x = 'y';
    write(up, &x, 1);
    read(down, &x, 1);
    if (p[2] != 'Q') return bad("the parent's next store, in the other", p[2], 'Q');
    return 0;
}

// Touch the page at `p` in a child, which dies of it or exits 0.
static int touch_dies(volatile char *p) {
    pid_t c = fork();
    if (c == 0) {
        (void)p[0];
        _exit(0);
    }
    int st = 0;
    waitpid(c, &st, 0);
    return WIFSIGNALED(st) ? WTERMSIG(st) : 0;
}

static int files(const char *self) {
    char path[] = "/tmp/ubcmap.XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0 || ftruncate(fd, 3 * PAGE) != 0) return bad("the file", errno, 0);

    // Two shared mappings in this process, at two addresses.
    char *a = mmap(NULL, 3 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    char *b = mmap(NULL, 3 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (a == MAP_FAILED || b == MAP_FAILED || a == b) return bad("the mappings", errno, 0);
    a[0] = 'P';
    if (b[0] != 'P') return bad("a store, in the other mapping", b[0], 'P');
    char r = 0;
    if (pread(fd, &r, 1, 0) != 1 || r != 'P') return bad("a store, read", r, 'P');
    // A private mapping made since: the file's pages until it writes.
    char *q = mmap(NULL, 3 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (q == MAP_FAILED || q[0] != 'P') return bad("a store, in a private mapping that has not written", q == MAP_FAILED ? errno : q[0], 'P');
    if (pwrite(fd, "W", 1, PAGE) != 1 || a[PAGE] != 'W' || b[PAGE] != 'W') return bad("a write, in the mappings", a[PAGE], 'W');
    q[2 * PAGE] = 'q';
    a[2 * PAGE] = 'a';
    if (q[2 * PAGE] != 'q') return bad("a private mapping's own copy", q[2 * PAGE], 'q');

    // Another process's mapping: each sees the other's stores at once.
    int up[2], down[2];
    if (pipe(up) || pipe(down)) return bad("pipe", errno, 0);
    pid_t pid;
    char ups[16], downs[16];
    snprintf(ups, sizeof ups, "%d", up[1]);
    snprintf(downs, sizeof downs, "%d", down[0]);
    char *argv[] = {(char *)self, path, ups, downs, NULL};
    if (posix_spawn(&pid, self, NULL, NULL, argv, environ) != 0) return bad("spawn", errno, 0);
    char x;
    read(up[0], &x, 1);
    if (a[1] != 'O') return bad("the other's store", a[1], 'O');
    a[2] = 'Q';
    write(down[1], &x, 1);
    int st = 0;
    waitpid(pid, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) return bad("the other process", st, 0);

    // A fork's child shares the mapping (VM_INHERIT_SHARE).
    pid_t c = fork();
    if (c == 0) {
        a[3] = 'C';
        _exit(b[0] == 'P' ? 0 : 1);
    }
    waitpid(c, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0 || b[3] != 'C') return bad("the child's store", b[3], 'C');

    // The file's pages are external: resident, not in the footprint (the
    // first touched first, for the leaf table over them).
    task_vm_info_data_t v0, v1;
    char *f = mmap(NULL, 3 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    f[9] = 1;
    vm_info(&v0);
    vm_info(&v0);
    f[PAGE + 9] = 1;
    f[2 * PAGE + 9] = 1;
    vm_info(&v1);
    if (v1.external - v0.external != 2 * PAGE || v1.resident_size - v0.resident_size != 2 * PAGE) return bad("two file pages touched, external and resident", (long)(v1.external - v0.external), (long)(2 * PAGE));
    if ((((uintptr_t)f + 2 * PAGE) >> 25) == ((uintptr_t)f >> 25) && v1.phys_footprint != v0.phys_footprint) return bad("two file pages touched, in the footprint", (long)(v1.phys_footprint - v0.phys_footprint), 0);
    munmap(f, 3 * PAGE);

    // Past the end: SIGBUS, EFAULT; the file grown, the page is there.
    char *e = mmap(NULL, 4 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (e == MAP_FAILED) return bad("a mapping past the end", errno, 0);
    if (touch_dies(e + 3 * PAGE) != SIGBUS) return bad("a page past the end", touch_dies(e + 3 * PAGE), SIGBUS);
    int pp[2];
    pipe(pp);
    errno = 0;
    if (write(pp[1], e + 3 * PAGE, 1) != -1 || errno != EFAULT) return bad("a copy from past the end", errno, EFAULT);
    if (ftruncate(fd, 4 * PAGE) != 0) return bad("growing the file", errno, 0);
    if (e[3 * PAGE] != 0 || touch_dies(e + 3 * PAGE) != 0) return bad("the page the file grew", e[3 * PAGE], 0);
    e[3 * PAGE] = 'g';
    if (pread(fd, &r, 1, 3 * PAGE) != 1 || r != 'g') return bad("a store to the page the file grew", r, 'g');
    if (write(pp[1], e + 3 * PAGE, 1) != 1) return bad("a copy from the page the file grew", errno, 0);

    // Truncated to one page: the rest leaves every mapping, but a private
    // mapping's copy.
    if (ftruncate(fd, PAGE) != 0) return bad("shrinking the file", errno, 0);
    if (touch_dies(a + PAGE) != SIGBUS || touch_dies(e + 3 * PAGE) != SIGBUS) return bad("a page the file lost", touch_dies(a + PAGE), SIGBUS);
    if (q[2 * PAGE] != 'q') return bad("a private copy past the new end", q[2 * PAGE], 'q');
    if (touch_dies(q + PAGE) != SIGBUS) return bad("a private page still the file's past the new end", touch_dies(q + PAGE), SIGBUS);
    if (a[0] != 'P') return bad("the page the file kept", a[0], 'P');
    unlink(path);
    return 0;
}

static int shm(void) {
    char name[32];
    snprintf(name, sizeof name, "/ubcmap.%d", getpid());
    int fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return bad("shm_open", errno, 0);
    shm_unlink(name);
    if (ftruncate(fd, 100) != 0) return bad("ftruncate", errno, 0);
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size != (off_t)PAGE) return bad("the object's size", (long)st.st_size, (long)PAGE);
    if (ftruncate(fd, 2 * PAGE) != -1 || errno != EINVAL) return bad("a second ftruncate", errno, EINVAL);
    char *a = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    char *b = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (a == MAP_FAILED || b == MAP_FAILED || a == b) return bad("the mappings", errno, 0);
    a[5] = 's';
    if (b[5] != 's') return bad("a store, in the second mapping", b[5], 's');
    errno = 0;
    if (mmap(NULL, 2 * PAGE, PROT_READ, MAP_SHARED, fd, 0) != MAP_FAILED || errno != EINVAL) return bad("a mapping past the object", errno, EINVAL);
    if (mmap(NULL, PAGE, PROT_READ, MAP_PRIVATE, fd, 0) != MAP_FAILED || errno != EINVAL) return bad("a private mapping", errno, EINVAL);
    pid_t c = fork();
    if (c == 0) {
        b[6] = 'c';
        _exit(a[5] == 's' ? 0 : 1);
    }
    int s = 0;
    waitpid(c, &s, 0);
    if (!WIFEXITED(s) || WEXITSTATUS(s) != 0 || a[6] != 'c') return bad("the child's store", a[6], 'c');
    // PROT_EXEC is cut to the most the object allows.
    char *x = mmap(NULL, PAGE, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
    if (x == MAP_FAILED || x[5] != 's') return bad("an executable request", errno, 0);
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 4) return other(argv[1], atoi(argv[2]), atoi(argv[3]));
    if (files(argv[0])) return 1;
    if (shm()) return 1;
    printf("ubcmap ok\n");
    return 0;
}
