// A mapping made over a file's mapping replaces its entries, and with them
// what the file's object had or lacked there (vm_map_enter's overwrite:
// vm_map_delete of the old entries). Past a file's end its mapping has no
// page, and an access there is SIGBUS; an anonymous MAP_FIXED mapping, or a
// mach_vm_allocate with VM_FLAGS_OVERWRITE, over those pages is zero-filled
// memory, read and written as any other. A private mapping's file pages
// overwritten so are zeros too. A copy of the file's mapping remapped over
// itself (mach_vm_remap, VM_FLAGS_OVERWRITE) still has the file's pages and
// none past its end.

#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define PAGE 0x4000UL

// <mach/mach_vm.h> is refused on this platform; these are in libsystem.
extern kern_return_t mach_vm_allocate(vm_map_t, mach_vm_address_t *, mach_vm_size_t, int);
extern kern_return_t mach_vm_deallocate(vm_map_t, mach_vm_address_t, mach_vm_size_t);
extern kern_return_t mach_vm_remap(vm_map_t, mach_vm_address_t *, mach_vm_size_t, mach_vm_offset_t, int, vm_map_t, mach_vm_address_t, boolean_t, vm_prot_t *, vm_prot_t *, vm_inherit_t);

static int bad(const char *what, long got, long want) {
    printf("mapover: %s: %#lx, want %#lx\n", what, got, want);
    fflush(stdout);
    return 1;
}

// Touch the byte at `p` in a child (a store when `store`), which dies of it
// or exits 0: its signal, or 0.
static int touch_dies(volatile char *p, int store) {
    pid_t c = fork();
    if (c == 0) {
        if (store) {
            p[0] = 'c';
        } else {
            (void)p[0];
        }
        _exit(0);
    }
    int st = 0;
    waitpid(c, &st, 0);
    return WIFSIGNALED(st) ? WTERMSIG(st) : 0;
}

// Every byte of `n` bytes at `p` is zero.
static int zeros(const char *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (p[i]) return 0;
    }
    return 1;
}

// A file's mapping of three pages, one page of file under them: `flags`
// MAP_PRIVATE or MAP_SHARED.
static char *file_map(int fd, int flags) {
    char *p = mmap(NULL, 3 * PAGE, PROT_READ | PROT_WRITE, flags, fd, 0);
    return p == MAP_FAILED ? NULL : p;
}

int main(void) {
    char path[] = "/tmp/mapover.XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return bad("the file", errno, 0);
    unlink(path);
    char page[PAGE];
    memset(page, 'F', sizeof page);
    if (write(fd, page, PAGE) != (ssize_t)PAGE) return bad("the file's page", errno, 0);

    // An anonymous MAP_FIXED mapping over a private mapping of the file:
    // its pages past the file's end are memory, its file page zeros.
    char *p = file_map(fd, MAP_PRIVATE);
    if (!p) return bad("the private mapping", errno, 0);
    if (p[0] != 'F') return bad("the private mapping's file page", p[0], 'F');
    int sig = touch_dies(p + 2 * PAGE, 0);
    if (sig != SIGBUS) return bad("a load past the file's end", sig, SIGBUS);
    if (mmap(p, 3 * PAGE, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0) != p) return bad("the anonymous mapping over it", errno, 0);
    sig = touch_dies(p + 2 * PAGE, 0);
    if (sig != 0) return bad("a load from the anonymous mapping, past the file's end", sig, 0);
    sig = touch_dies(p + 2 * PAGE, 1);
    if (sig != 0) return bad("a store to the anonymous mapping, past the file's end", sig, 0);
    if (!zeros(p, 3 * PAGE)) return bad("the anonymous mapping's bytes", p[0], 0);
    p[0] = 'a';
    p[2 * PAGE + 1] = 'b';
    if (p[0] != 'a' || p[2 * PAGE + 1] != 'b') return bad("the anonymous mapping's stores", p[0], 'a');
    munmap(p, 3 * PAGE);

    // mach_vm_allocate with VM_FLAGS_OVERWRITE over a shared mapping.
    char *q = file_map(fd, MAP_SHARED);
    if (!q) return bad("the shared mapping", errno, 0);
    sig = touch_dies(q + PAGE, 0);
    if (sig != SIGBUS) return bad("a load past the file's end, shared", sig, SIGBUS);
    mach_vm_address_t at = (mach_vm_address_t)q;
    kern_return_t kr = mach_vm_allocate(mach_task_self(), &at, 3 * PAGE, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE);
    if (kr != KERN_SUCCESS || at != (mach_vm_address_t)q) return bad("mach_vm_allocate over the shared mapping", kr, KERN_SUCCESS);
    sig = touch_dies(q + PAGE, 0);
    if (sig != 0) return bad("a load from the allocation, past the file's end", sig, 0);
    if (!zeros(q, 3 * PAGE)) return bad("the allocation's bytes", q[0], 0);
    q[PAGE] = 'q';
    if (q[PAGE] != 'q') return bad("the allocation's store", q[PAGE], 'q');
    char r0 = 0;
    if (pread(fd, &r0, 1, 0) != 1 || r0 != 'F') return bad("the file's byte after the allocation", r0, 'F');
    mach_vm_deallocate(mach_task_self(), at, 3 * PAGE);

    // A copy of a private mapping remapped over itself: the file's page
    // still, and none past its end.
    char *r = file_map(fd, MAP_PRIVATE);
    if (!r) return bad("the remapped mapping", errno, 0);
    mach_vm_address_t to = (mach_vm_address_t)r;
    vm_prot_t cur = 0, max = 0;
    kr = mach_vm_remap(mach_task_self(), &to, 3 * PAGE, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, mach_task_self(), (mach_vm_address_t)r, TRUE, &cur, &max, VM_INHERIT_DEFAULT);
    if (kr != KERN_SUCCESS || to != (mach_vm_address_t)r) return bad("mach_vm_remap over itself", kr, KERN_SUCCESS);
    if (r[0] != 'F') return bad("the remapped file page", r[0], 'F');
    sig = touch_dies(r + 2 * PAGE, 0);
    if (sig != SIGBUS) return bad("a load past the file's end, remapped", sig, SIGBUS);
    munmap(r, 3 * PAGE);
    close(fd);
    printf("mapover ok\n");
    return 0;
}
