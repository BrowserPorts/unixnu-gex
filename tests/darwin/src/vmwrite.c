// vm_copy's pages as the pmap holds them after: a page-aligned copy larger
// than a kernel buffer gives the destination the copy's object, so its
// pages leave the footprint until touched again; a small one is a kernel
// buffer whose copyout enters the pages it writes; an unaligned large one
// copies into the destination's pages, entering none that was not.

#include <mach/mach.h>
#include <mach/vm_map.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PAGE 0x4000UL
#define LEAF (32UL << 20)

static int bad(const char *what, long got, long want) {
    printf("vmwrite: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

static int64_t footprint(void) {
    task_vm_info_data_t info;
    mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count)) return -1;
    return (int64_t)info.phys_footprint;
}

int main(void) {
    mach_port_t me = mach_task_self();
    vm_address_t block = 0;
    kern_return_t kr = vm_map(me, &block, LEAF, LEAF - 1, VM_FLAGS_ANYWHERE, MACH_PORT_NULL, 0, FALSE, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_ALL, VM_INHERIT_DEFAULT);
    if (kr) return bad("the block", kr, 0);
    volatile char *a = (volatile char *)block, *b = (volatile char *)(block + 32 * PAGE);
    for (int i = 0; i < 16; i++) {
        a[i * PAGE] = (char)i;
        b[i * PAGE] = 'b';
    }
    footprint();
    int64_t f0 = footprint();
    // Aligned and large: the destination's pages leave the pmap.
    kr = vm_copy(me, block, 16 * PAGE, block + 32 * PAGE);
    if (kr) return bad("an aligned copy", kr, 0);
    int64_t f1 = footprint();
    if (f0 - f1 != (int64_t)(16 * PAGE)) return bad("the destination's pages removed", (long)(f0 - f1), (long)(16 * PAGE));
    long sum = 0;
    for (int i = 0; i < 16; i++) sum += b[i * PAGE];
    int64_t f2 = footprint();
    if (sum != 120) return bad("the copy's data", sum, 120);
    if (f2 != f0) return bad("the pages read again", (long)(f2 - f1), (long)(16 * PAGE));
    // Small: copyout enters what it writes.
    kr = vm_copy(me, block, 2 * PAGE, block + 64 * PAGE);
    if (kr) return bad("a small copy", kr, 0);
    int64_t f3 = footprint();
    if (f3 - f2 != (int64_t)(2 * PAGE)) return bad("a kernel buffer's pages entered", (long)(f3 - f2), (long)(2 * PAGE));
    // Unaligned and large: copied into pages not entered, which stay so.
    kr = vm_copy(me, block + 0x10, 4 * PAGE, block + 96 * PAGE + 0x20);
    if (kr) return bad("an unaligned copy", kr, 0);
    int64_t f4 = footprint();
    if (f4 != f3) return bad("an unaligned copy's pages", (long)(f4 - f3), 0);
    volatile char *d = (volatile char *)(block + 96 * PAGE);
    sum = 0;
    for (int i = 0; i < 5; i++) sum += d[i * PAGE];
    int64_t f5 = footprint();
    if (f5 - f4 != (int64_t)(5 * PAGE)) return bad("its pages read", (long)(f5 - f4), (long)(5 * PAGE));
    if (d[0x20 + PAGE - 0x10] != 1) return bad("the unaligned copy's data", d[0x20 + PAGE - 0x10], 1);
    printf("vmwrite ok\n");
    return 0;
}
