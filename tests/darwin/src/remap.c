// vm_remap and vm_remap_new within the task: a shared remap is the same
// pages at a second address (each sees the other's writes, both entries
// shared), a copy is the pages as they were (neither sees the other's
// writes); the legacy call gives back the strictest protections, the new
// one checks what it is asked for (a share needs it of every entry, a copy
// only reading), returns the data's address, and refuses write and
// execute together. A hole is KERN_INVALID_ADDRESS, a fixed place over a
// mapping KERN_NO_SPACE without VM_FLAGS_OVERWRITE. The new pages are not
// the task's footprint until it touches them, each mapping's counted.

#include <mach/mach.h>
#include <mach/vm_map.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#define PAGE 0x4000UL
#define LEAF (32UL << 20)

static int bad(const char *what, long got, long want) {
    printf("remap: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

static int region(vm_address_t at, vm_region_basic_info_data_64_t *info) {
    vm_size_t size;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object;
    vm_address_t a = at;
    kern_return_t kr = vm_region_64(mach_task_self(), &a, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)info, &count, &object);
    if (kr) return kr;
    return a == at ? 0 : -1;
}

static int64_t footprint(void) {
    task_vm_info_data_t info;
    mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count)) return -1;
    return (int64_t)info.phys_footprint;
}

int main(void) {
    mach_port_t me = mach_task_self();
    // A leaf table's 32 MB: the source at its start, the remaps inside it.
    vm_address_t block = 0;
    kern_return_t kr = vm_map(me, &block, LEAF, LEAF - 1, VM_FLAGS_ANYWHERE, MACH_PORT_NULL, 0, FALSE, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_ALL, VM_INHERIT_DEFAULT);
    if (kr) return bad("the block", kr, 0);
    if (vm_deallocate(me, block + 16 * PAGE, LEAF - 16 * PAGE)) return bad("the block's end", 0, 0);
    volatile char *src = (volatile char *)block;
    for (int i = 0; i < 10; i++) src[i * PAGE] = (char)('a' + i);

    // A share, fixed in the block.
    vm_address_t dst = block + 64 * PAGE;
    vm_prot_t cur = 0, max = 0;
    footprint();
    int64_t f0 = footprint();
    kr = vm_remap(me, &dst, 10 * PAGE, 0, VM_FLAGS_FIXED, me, block, FALSE, &cur, &max, VM_INHERIT_SHARE);
    if (kr) return bad("a shared remap", kr, 0);
    if (dst != block + 64 * PAGE) return bad("its address", (long)dst, (long)(block + 64 * PAGE));
    if (cur != (VM_PROT_READ | VM_PROT_WRITE) || max != VM_PROT_ALL) return bad("the strictest protections", cur << 8 | max, 0x307);
    int64_t f1 = footprint();
    if (f1 != f0) return bad("the footprint after the remap", (long)(f1 - f0), 0);
    volatile char *d = (volatile char *)dst;
    long sum = 0;
    for (int i = 0; i < 10; i++) sum += d[i * PAGE];
    int64_t f2 = footprint();
    if (sum != 10 * 'a' + 45) return bad("the shared data", sum, 10 * 'a' + 45);
    if (f2 - f1 != (int64_t)(10 * PAGE)) return bad("ten pages read through the second mapping", (long)(f2 - f1), (long)(10 * PAGE));
    d[0] = 'X';
    src[PAGE] = 'Y';
    if (src[0] != 'X' || d[PAGE] != 'Y') return bad("each mapping's writes seen by the other", src[0], 'X');
    vm_region_basic_info_data_64_t info;
    if (region(dst, &info) || !info.shared || info.inheritance != VM_INHERIT_SHARE) return bad("the new entry", info.shared << 8 | info.inheritance, 0x100);
    if (region(block, &info) || !info.shared) return bad("the source entry, shared", info.shared, 1);

    // A copy: the data as it was, each side's writes its own.
    vm_address_t cp = 0;
    kr = vm_remap(me, &cp, 2 * PAGE, 0, VM_FLAGS_ANYWHERE, me, block, TRUE, &cur, &max, VM_INHERIT_DEFAULT);
    if (kr) return bad("a copy", kr, 0);
    volatile char *c = (volatile char *)cp;
    if (c[0] != 'X' || c[PAGE] != 'Y') return bad("the copy's data", c[0], 'X');
    c[0] = 'c';
    src[PAGE] = 'Z';
    if (src[0] != 'X' || c[PAGE] != 'Y') return bad("the copy's writes its own", src[0], 'X');
    if (region(cp, &info) || info.shared) return bad("the copy, not shared", info.shared, 0);

    // vm_remap_new: the data's address, the protections asked for.
    vm_address_t n = 0;
    cur = VM_PROT_READ;
    max = VM_PROT_READ;
    kr = vm_remap_new(me, &n, 0x20, 0, VM_FLAGS_ANYWHERE, me, block + 0x10, FALSE, &cur, &max, VM_INHERIT_DEFAULT);
    if (kr) return bad("vm_remap_new", kr, 0);
    if ((n & (PAGE - 1)) != 0x10) return bad("the data's address", (long)(n & (PAGE - 1)), 0x10);
    if (region(n & ~(PAGE - 1), &info) || info.protection != VM_PROT_READ || info.max_protection != VM_PROT_READ) return bad("the new entry's protections", info.protection << 8 | info.max_protection, 0x101);
    // Write and execute together are refused; a share needs what it asks.
    cur = VM_PROT_READ;
    max = VM_PROT_WRITE | VM_PROT_EXECUTE | VM_PROT_READ;
    n = 0;
    kr = vm_remap_new(me, &n, PAGE, 0, VM_FLAGS_ANYWHERE, me, block, FALSE, &cur, &max, VM_INHERIT_DEFAULT);
    if (kr != KERN_PROTECTION_FAILURE) return bad("write and execute", kr, KERN_PROTECTION_FAILURE);
    if (vm_protect(me, block + 2 * PAGE, PAGE, FALSE, VM_PROT_READ)) return bad("vm_protect", 0, 0);
    cur = VM_PROT_READ | VM_PROT_WRITE;
    max = VM_PROT_READ | VM_PROT_WRITE;
    n = 0;
    kr = vm_remap_new(me, &n, 3 * PAGE, 0, VM_FLAGS_ANYWHERE, me, block, FALSE, &cur, &max, VM_INHERIT_DEFAULT);
    if (kr != KERN_PROTECTION_FAILURE) return bad("a share of a read-only page, writable", kr, KERN_PROTECTION_FAILURE);
    // A copy only reads it.
    kr = vm_remap_new(me, &n, 3 * PAGE, 0, VM_FLAGS_ANYWHERE, me, block, TRUE, &cur, &max, VM_INHERIT_DEFAULT);
    if (kr) return bad("a writable copy of a read-only page", kr, 0);
    ((volatile char *)n)[2 * PAGE] = 'w';

    // A hole; a fixed place taken; overwritten.
    cur = max = 0;
    vm_address_t h = 0;
    if (vm_deallocate(me, block + 12 * PAGE, PAGE)) return bad("a hole made", 0, 0);
    kr = vm_remap(me, &h, 14 * PAGE, 0, VM_FLAGS_ANYWHERE, me, block, FALSE, &cur, &max, VM_INHERIT_DEFAULT);
    if (kr != KERN_INVALID_ADDRESS) return bad("a hole", kr, KERN_INVALID_ADDRESS);
    h = cp;
    kr = vm_remap(me, &h, PAGE, 0, VM_FLAGS_FIXED, me, block, FALSE, &cur, &max, VM_INHERIT_DEFAULT);
    if (kr != KERN_NO_SPACE) return bad("a fixed place taken", kr, KERN_NO_SPACE);
    kr = vm_remap(me, &h, PAGE, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, me, block, FALSE, &cur, &max, VM_INHERIT_DEFAULT);
    if (kr || h != cp || c[0] != 'X') return bad("overwritten", kr, 0);
    // A flag a remap does not take.
    kr = vm_remap(me, &h, PAGE, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_PURGABLE, me, block, FALSE, &cur, &max, VM_INHERIT_DEFAULT);
    if (kr != KERN_INVALID_ARGUMENT) return bad("VM_FLAGS_PURGABLE", kr, KERN_INVALID_ARGUMENT);
    printf("remap ok\n");
    return 0;
}
