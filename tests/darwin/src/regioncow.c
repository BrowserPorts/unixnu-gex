// A store to the shared cache's writable data: the task's entry for the
// shared region is the region's submap, entered read-only (max read-only)
// and copy-on-write, inherited by share; a store to a page of a writable
// cache mapping takes the region's entry there out of the submap into a
// copy of the task's own (vm_map_lookup_and_lock_object), whose
// protections are the region entry's and which is inherited by copy, and
// the page it wrote is the task's from then on, in its footprint.
//
// The page is the first of a writable mapping's part of a 32 MiB twig that
// nothing has written yet (mach_vm_region still finds the submap there),
// found from the cache's headers (the main file's and its subcaches'
// mappings); its byte is stored back as it is.
//
// "regioncow before submap S prot P max M inherit I after submap S prot P
// max M inherit I grew G": mach_vm_region's report of the entry at the page
// before and after the store (is_submap, protection, max_protection,
// inheritance), and G 1 when phys_footprint grew by at least the page;
// then "regioncow ok".

#include <mach/mach.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern const void *_dyld_get_shared_cache_range(size_t *length);

#define TWIG (32UL << 20)

// <mach/mach_vm.h> is refused on this platform; it is in libsystem.
extern kern_return_t mach_vm_region(vm_map_t, mach_vm_address_t *, mach_vm_size_t *, vm_region_flavor_t, vm_region_info_t, mach_msg_type_number_t *, mach_port_t *);

static int region_at(mach_vm_address_t want, vm_region_basic_info_data_64_t *info) {
    mach_vm_address_t at = want;
    mach_vm_size_t size = 0;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t kr = mach_vm_region(mach_task_self(), &at, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)info, &count, &object);
    return kr == KERN_SUCCESS && at <= want && want < at + size ? 0 : -1;
}

static long footprint(void) {
    task_vm_info_data_t info;
    mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count) != KERN_SUCCESS) return -1;
    return (long)info.phys_footprint;
}

static uint32_t u32(const uint8_t *h, size_t o) {
    uint32_t v;
    memcpy(&v, h + o, 4);
    return v;
}

static uint64_t u64(const uint8_t *h, size_t o) {
    uint64_t v;
    memcpy(&v, h + o, 8);
    return v;
}

// A page of a writable mapping of the cache file whose header is at `h`
// (slid by `slide`) whose twig part no store has taken out of the submap
// yet, or 0.
static uintptr_t untouched(const uint8_t *h, uint64_t slide) {
    uint32_t mo = u32(h, 0x10), mc = u32(h, 0x14);
    for (uint32_t i = 0; i < mc; i++) {
        const uint8_t *m = h + mo + 32 * i;
        uint64_t address = u64(m, 0) + slide, size = u64(m, 8);
        uint32_t init_prot = u32(m, 28);
        if (!(init_prot & VM_PROT_WRITE)) continue;
        for (uint64_t at = address; at < address + size; at = (at & ~(TWIG - 1)) + TWIG) {
            vm_region_basic_info_data_64_t info;
            if (region_at(at, &info) == 0 && info.reserved) return (uintptr_t)at;
        }
    }
    return 0;
}

int main(void) {
    size_t len = 0;
    const uint8_t *cache = _dyld_get_shared_cache_range(&len);
    if (!cache) {
        printf("regioncow: no shared cache\n");
        return 1;
    }
    // The main file's first mapping is the cache's base, unslid.
    uint64_t slide = (uintptr_t)cache - u64(cache, u32(cache, 0x10));
    uintptr_t page = untouched(cache, slide);
    uint32_t hsize = u32(cache, 0x10), so = u32(cache, 0x188), sc = u32(cache, 0x18c);
    for (uint32_t i = 0; !page && i < sc; i++) {
        uint64_t vm_offset = u64(cache, so + (hsize > 0x1c8 ? 56 : 24) * i + 16);
        page = untouched(cache + vm_offset, slide);
    }
    if (!page) {
        printf("regioncow: no writable cache mapping left in the submap\n");
        return 1;
    }
    vm_region_basic_info_data_64_t before, after;
    region_at(page, &before);
    long f0 = footprint();
    volatile uint8_t *p = (volatile uint8_t *)page;
    *p = *p;
    long f1 = footprint();
    if (region_at(page, &after)) {
        printf("regioncow: no region at %#lx after the store\n", (unsigned long)page);
        return 1;
    }
    int grew = f0 >= 0 && f1 >= 0 && f1 - f0 >= getpagesize();
    printf("regioncow before submap %u prot %d max %d inherit %u after submap %u prot %d max %d inherit %u grew %d\n", before.reserved, before.protection, before.max_protection, before.inheritance, after.reserved, after.protection, after.max_protection, after.inheritance, grew);
    if (before.reserved && !after.reserved && after.protection == (VM_PROT_READ | VM_PROT_WRITE) && after.inheritance == VM_INHERIT_COPY && grew) printf("regioncow ok\n");
    return 0;
}
