// Named entries by object: the default entry of a range names the range's
// object, so MAP_MEM_NAMED_REUSE with that entry as parent gives the same
// entry (port) back, while another size or place makes a new one; a share
// of the range sees through the entry's object. MAP_MEM_ONLY changes a
// parent's cache mode and makes no entry, needs a parent and refuses data
// address flags; cache modes are taken at creation.

#include <mach/mach.h>
#include <stdio.h>
#include <sys/mman.h>

#define PAGE 0x4000UL

static int bad(const char *what, long got, long want) {
    printf("mentreuse: %s: %#lx, want %#lx\n", what, got, want);
    fflush(stdout);
    return 1;
}

int main(void) {
    volatile char *p = mmap(NULL, 4 * PAGE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (p == MAP_FAILED) return bad("mmap", 0, 0);
    p[0] = 'a';
    memory_object_size_t size = 2 * PAGE;
    mach_port_t parent = MACH_PORT_NULL, again = MACH_PORT_NULL, other = MACH_PORT_NULL;
    kern_return_t kr = mach_make_memory_entry_64(mach_task_self(), &size, (memory_object_offset_t)(uintptr_t)p, VM_PROT_READ | VM_PROT_WRITE, &parent, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS || size != 2 * PAGE) return bad("the parent entry", kr, 0);
    // The same object, place and size: the parent itself.
    size = 2 * PAGE;
    kr = mach_make_memory_entry_64(mach_task_self(), &size, (memory_object_offset_t)(uintptr_t)p, VM_PROT_READ | VM_PROT_WRITE | MAP_MEM_NAMED_REUSE, &again, parent);
    if (kr != KERN_SUCCESS || again != parent || size != 2 * PAGE) return bad("a reuse of the parent", (long)again, (long)parent);
    // Another size: a new entry.
    size = PAGE;
    kr = mach_make_memory_entry_64(mach_task_self(), &size, (memory_object_offset_t)(uintptr_t)p, VM_PROT_READ | VM_PROT_WRITE | MAP_MEM_NAMED_REUSE, &other, parent);
    if (kr != KERN_SUCCESS || other == parent) return bad("another size, reused", (long)other, 0);
    // The range's pages and the entry's are one object's.
    vm_address_t m = 0;
    kr = vm_map(mach_task_self(), &m, 2 * PAGE, 0, VM_FLAGS_ANYWHERE, parent, 0, FALSE, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_NONE);
    if (kr != KERN_SUCCESS || ((volatile char *)m)[0] != 'a') return bad("a mapping of the entry", kr, 0);
    p[1] = 'b';
    if (((volatile char *)m)[1] != 'b') return bad("a store, through the entry's mapping", ((volatile char *)m)[1], 'b');

    // MAP_MEM_ONLY: no entry, a parent's cache mode; its refusals.
    mach_port_t none = MACH_PORT_NULL;
    size = 2 * PAGE;
    kr = mach_make_memory_entry_64(mach_task_self(), &size, 0, MAP_MEM_ONLY | VM_PROT_READ | (MAP_MEM_WCOMB << 24), &none, parent);
    if (kr != KERN_SUCCESS || none != MACH_PORT_NULL) return bad("MAP_MEM_ONLY", kr, 0);
    kr = mach_make_memory_entry_64(mach_task_self(), &size, 0, MAP_MEM_ONLY | VM_PROT_READ, &none, MACH_PORT_NULL);
    if (kr != KERN_INVALID_ARGUMENT) return bad("MAP_MEM_ONLY without a parent", kr, KERN_INVALID_ARGUMENT);
    kr = mach_make_memory_entry_64(mach_task_self(), &size, 0, MAP_MEM_ONLY | MAP_MEM_USE_DATA_ADDR | VM_PROT_READ, &none, parent);
    if (kr != KERN_INVALID_ARGUMENT) return bad("MAP_MEM_ONLY with a data address", kr, KERN_INVALID_ARGUMENT);
    // A cache mode at creation.
    size = PAGE;
    mach_port_t io = MACH_PORT_NULL;
    kr = mach_make_memory_entry_64(mach_task_self(), &size, 0, MAP_MEM_NAMED_CREATE | VM_PROT_READ | VM_PROT_WRITE | (MAP_MEM_IO << 24), &io, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) return bad("a named entry with MAP_MEM_IO", kr, 0);
    printf("mentreuse ok\n");
    return 0;
}
