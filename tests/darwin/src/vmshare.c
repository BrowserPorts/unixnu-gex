// A fork's child gets its parent's map by each entry's inheritance: a
// shared mapping's pages are the parent's (each sees the other's writes),
// a private one's a copy on write (neither sees the other's), and one not
// inherited is a hole. The child's pmap starts empty: a page it inherited
// counts in its footprint once it touches it, read or written, and the
// leaf table under it with the first.

#include <mach/mach.h>
#include <mach/vm_map.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define PAGE 0x4000UL
// A leaf table maps 32 MB.
#define LEAF (32UL << 20)

static int bad(const char *what, long got, long want) {
    printf("vmshare: %s: %#lx, want %#lx\n", what, got, want);
    fflush(stdout);
    return 1;
}

static int64_t footprint(void) {
    task_vm_info_data_t info;
    mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count)) return -1;
    return (int64_t)info.phys_footprint;
}

static int child(volatile char *shared, volatile char *private, char *none, volatile char *block) {
    // Shared: the parent sees this; private: it does not.
    shared[0] = 'c';
    private[0] = 'c';
    if (private[PAGE] != 'p') return bad("the parent's private data", private[PAGE], 'p');

    // Not inherited: no entry there.
    vm_address_t a = (vm_address_t)none;
    vm_size_t size;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object;
    kern_return_t kr = vm_region_64(mach_task_self(), &a, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object);
    if (kr == KERN_SUCCESS && a <= (vm_address_t)none) return bad("an entry not inherited", (long)a, 0);

    // Twice first, so that what the call itself touches is entered.
    footprint();
    int64_t f0 = footprint();
    long sum = 0;
    for (int i = 0; i < 10; i++) sum += block[i * PAGE];
    int64_t f1 = footprint();
    for (int i = 10; i < 15; i++) block[i * PAGE] = 2;
    int64_t f2 = footprint();
    if (sum != 10) return bad("the inherited block's data", sum, 10);
    if (f1 - f0 != (int64_t)(10 * PAGE + PAGE)) return bad("ten pages read, and their leaf table", (long)(f1 - f0), (long)(11 * PAGE));
    if (f2 - f1 != (int64_t)(5 * PAGE)) return bad("five pages written", (long)(f2 - f1), (long)(5 * PAGE));
    return 0;
}

int main(void) {
    volatile char *shared = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
    volatile char *private = mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    char *none = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (shared == MAP_FAILED || private == MAP_FAILED || none == MAP_FAILED) return bad("mmap", 0, 1);
    if (minherit(none, PAGE, VM_INHERIT_NONE)) return bad("minherit", 0, 0);
    // A leaf table's 32 MB of its own, its first pages written.
    vm_address_t at = 0;
    kern_return_t kr = vm_map(mach_task_self(), &at, LEAF, LEAF - 1, VM_FLAGS_ANYWHERE, MACH_PORT_NULL, 0, FALSE, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_ALL, VM_INHERIT_DEFAULT);
    if (kr) return bad("an aligned block", kr, 0);
    volatile char *block = (volatile char *)at;
    for (int i = 0; i < 64; i++) block[i * PAGE] = 1;
    shared[0] = 'p';
    private[0] = 'p';
    private[PAGE] = 'p';
    none[0] = 'n';

    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0) return bad("fork", pid, 0);
    if (pid == 0) _exit(child(shared, private, none, block));
    int status;
    if (waitpid(pid, &status, 0) != pid) return bad("waitpid", 0, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status)) return bad("the child", status, 0);
    if (shared[0] != 'c') return bad("the child's write to shared memory", shared[0], 'c');
    if (private[0] != 'p') return bad("the child's write to its copy", private[0], 'p');
    if (none[0] != 'n') return bad("the parent's own", none[0], 'n');

    // A copy made at the fork: the parent's write after it is its own.
    pid = fork();
    if (pid == 0) {
        usleep(100000);
        _exit(private[PAGE] == 'p' ? 0 : 1);
    }
    private[PAGE] = 'q';
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status)) return bad("the parent's write after the fork", status, 0);
    printf("vmshare ok\n");
    return 0;
}
