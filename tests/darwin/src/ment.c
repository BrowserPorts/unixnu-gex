// Named memory entries: an object made new and mapped twice is one set of
// pages (each mapping sees the other's writes; a copy mapping sees them as
// they were); an entry of a range shares it (VM_SHARE, with the data's
// offset kept) or copies it (VM_COPY), and without either names the first
// entry's object only; a part of a parent entry maps that part. The
// protections asked for are checked, a mapping's against the entry's. A
// non-purgeable object refuses purgeable control. The mappings outlive the
// entry's port. A mapping's pages count in the footprint as they are
// touched.

#include <mach/mach.h>
#include <mach/vm_map.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#define PAGE 0x4000UL

kern_return_t mach_memory_entry_purgable_control(mach_port_t entry, vm_purgable_t control, int *state);

static int bad(const char *what, long got, long want) {
    printf("ment: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

static int64_t footprint(void) {
    task_vm_info_data_t info;
    mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count)) return -1;
    return (int64_t)info.phys_footprint;
}

static kern_return_t map(mach_port_t entry, vm_address_t *at, vm_size_t size, vm_offset_t off, int flags, boolean_t copy, vm_prot_t cur, vm_prot_t max) {
    *at = 0;
    return vm_map(mach_task_self(), at, size, 0, VM_FLAGS_ANYWHERE | flags, entry, off, copy, cur, max, VM_INHERIT_DEFAULT);
}

int main(void) {
    mach_port_t me = mach_task_self();
    vm_prot_t rw = VM_PROT_READ | VM_PROT_WRITE;

    // A new object, mapped twice and once as a copy.
    memory_object_size_t size = 4 * PAGE;
    mach_port_t obj = MACH_PORT_NULL;
    kern_return_t kr = mach_make_memory_entry_64(me, &size, 0, MAP_MEM_NAMED_CREATE | rw, &obj, MACH_PORT_NULL);
    if (kr || size != 4 * PAGE || !MACH_PORT_VALID(obj)) return bad("a new object", kr, 0);
    vm_address_t a, b, c;
    if ((kr = map(obj, &a, 4 * PAGE, 0, 0, FALSE, rw, rw))) return bad("a mapping", kr, 0);
    for (int i = 0; i < 4; i++) ((volatile char *)a)[i * PAGE] = (char)('a' + i);
    footprint();
    int64_t f0 = footprint();
    if ((kr = map(obj, &b, 4 * PAGE, 0, 0, FALSE, rw, rw))) return bad("a second mapping", kr, 0);
    if (footprint() != f0) return bad("the footprint of a mapping not touched", (long)(footprint() - f0), 0);
    long sum = 0;
    for (int i = 0; i < 4; i++) sum += ((volatile char *)b)[i * PAGE];
    if (sum != 4 * 'a' + 6) return bad("the object's data", sum, 4 * 'a' + 6);
    if (footprint() - f0 != (int64_t)(4 * PAGE)) return bad("four pages read", (long)(footprint() - f0), (long)(4 * PAGE));
    ((volatile char *)b)[0] = 'X';
    if (((volatile char *)a)[0] != 'X') return bad("a write seen through the other mapping", ((volatile char *)a)[0], 'X');
    if ((kr = map(obj, &c, 4 * PAGE, 0, 0, TRUE, rw, rw))) return bad("a copy mapping", kr, 0);
    ((volatile char *)a)[PAGE] = 'Y';
    if (((volatile char *)c)[0] != 'X' || ((volatile char *)c)[PAGE] != 'b') return bad("the copy's data", ((volatile char *)c)[PAGE], 'b');
    // More than the entry allows; past its end.
    vm_address_t d;
    if ((kr = map(obj, &d, 8 * PAGE, 0, 0, FALSE, rw, rw)) != KERN_INVALID_ARGUMENT) return bad("past the end", kr, KERN_INVALID_ARGUMENT);
    mach_port_t ro = MACH_PORT_NULL;
    size = 4 * PAGE;
    if ((kr = mach_make_memory_entry_64(me, &size, 0, VM_PROT_READ, &ro, obj))) return bad("a read-only part", kr, 0);
    if ((kr = map(ro, &d, PAGE, 0, 0, FALSE, rw, rw)) != KERN_INVALID_RIGHT) return bad("writing through a read-only entry", kr, KERN_INVALID_RIGHT);
    // A part of the parent: its second page.
    mach_port_t part = MACH_PORT_NULL;
    size = PAGE;
    if ((kr = mach_make_memory_entry_64(me, &size, PAGE, rw, &part, obj))) return bad("a part", kr, 0);
    if ((kr = map(part, &d, PAGE, 0, 0, FALSE, rw, rw)) || ((volatile char *)d)[0] != 'Y') return bad("the part's data", kr, 0);
    int state = 0;
    if ((kr = mach_memory_entry_purgable_control(obj, VM_PURGABLE_GET_STATE, &state)) != KERN_INVALID_ARGUMENT) return bad("purgeable control", kr, KERN_INVALID_ARGUMENT);

    // An entry of a range, shared, its data's offset kept.
    volatile char *src = mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    src[0x30] = 's';
    mach_port_t sh = MACH_PORT_NULL;
    size = 0x20;
    if ((kr = mach_make_memory_entry_64(me, &size, (vm_offset_t)src + 0x30, MAP_MEM_VM_SHARE | MAP_MEM_USE_DATA_ADDR | rw, &sh, MACH_PORT_NULL))) return bad("a shared range", kr, 0);
    if (size != PAGE - 0x30) return bad("its size past the data's offset", (long)size, PAGE - 0x30);
    if ((kr = map(sh, &d, 0x20, 0, VM_FLAGS_RETURN_DATA_ADDR, FALSE, rw, rw))) return bad("mapping the shared range", kr, 0);
    if ((d & (PAGE - 1)) != 0x30 || ((volatile char *)d)[0] != 's') return bad("the shared range's data", (long)(d & (PAGE - 1)), 0x30);
    ((volatile char *)d)[1] = 't';
    if (src[0x31] != 't') return bad("the range's write seen", src[0x31], 't');
    // Copied: as it was.
    mach_port_t cp = MACH_PORT_NULL;
    size = 2 * PAGE;
    if ((kr = mach_make_memory_entry_64(me, &size, (vm_offset_t)src, MAP_MEM_VM_COPY | VM_PROT_READ, &cp, MACH_PORT_NULL))) return bad("a copied range", kr, 0);
    src[0] = 'z';
    if ((kr = map(cp, &d, 2 * PAGE, 0, 0, FALSE, VM_PROT_READ, VM_PROT_READ)) || ((volatile char *)d)[0x30] != 's' || ((volatile char *)d)[0] == 'z') return bad("the copy's data", kr, 0);
    // A copy's mappings are each a copy on write of it.
    mach_port_t cw = MACH_PORT_NULL;
    size = PAGE;
    if ((kr = mach_make_memory_entry_64(me, &size, (vm_offset_t)src, MAP_MEM_VM_COPY | rw, &cw, MACH_PORT_NULL))) return bad("a writable copy", kr, 0);
    vm_address_t e1, e2;
    if ((kr = map(cw, &e1, PAGE, 0, 0, FALSE, rw, rw)) || (kr = map(cw, &e2, PAGE, 0, 0, FALSE, rw, rw))) return bad("mapping a copy twice", kr, 0);
    ((volatile char *)e1)[0] = 'q';
    if (((volatile char *)e2)[0] != 'z') return bad("one mapping's write in the other", ((volatile char *)e2)[0], 'z');
    // Without either: the first entry's object only.
    volatile char *two = mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (mprotect((void *)(two + PAGE), PAGE, PROT_READ)) return bad("mprotect", 0, 0);
    mach_port_t first = MACH_PORT_NULL;
    size = 2 * PAGE;
    if ((kr = mach_make_memory_entry_64(me, &size, (vm_offset_t)two, VM_PROT_READ, &first, MACH_PORT_NULL))) return bad("a range of two entries", kr, 0);
    if (size != PAGE) return bad("the first entry's object only", (long)size, PAGE);
    // A writable entry of a read-only page.
    size = PAGE;
    mach_port_t w = MACH_PORT_NULL;
    if ((kr = mach_make_memory_entry_64(me, &size, (vm_offset_t)two + PAGE, rw, &w, MACH_PORT_NULL)) != KERN_PROTECTION_FAILURE) return bad("writing a read-only page", kr, KERN_PROTECTION_FAILURE);
    // The mappings outlive the entries.
    mach_port_deallocate(me, obj);
    mach_port_deallocate(me, ro);
    mach_port_deallocate(me, part);
    if (((volatile char *)a)[0] != 'X' || ((volatile char *)b)[PAGE] != 'Y') return bad("a mapping without its entry", ((volatile char *)a)[0], 'X');
    printf("ment ok\n");
    return 0;
}
