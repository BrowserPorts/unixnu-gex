// Purgeable memory: VM_FLAGS_PURGABLE memory is a nonvolatile object owned
// by the task, its pages in the purgeable_nonvolatile ledger and the
// footprint; made volatile they leave the footprint for the
// purgeable_volatile ledger and stay until something empties them (the
// device's memory is never short): VM_PURGABLE_EMPTY or PURGE_ALL. An
// emptied object reads zero, stays empty when made volatile again, and is
// nonvolatile again on request. The control's errors: a mapped address of
// memory that is not purgeable, a hole, an unknown control or state. A
// purgeable named entry (MAP_MEM_PURGABLE) is the same through its port,
// its mappings sharing one object; a ledger-tagged one (MAP_MEM_LEDGER_
// TAGGED) is billed to the tagged ledger, not the purgeable ones.

#include <mach/mach.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#define PAGE 0x4000UL

// <mach/mach_vm.h> is refused on this platform; these are in libsystem.
extern kern_return_t mach_vm_allocate(vm_map_t, mach_vm_address_t *, mach_vm_size_t, int);
extern kern_return_t mach_vm_deallocate(vm_map_t, mach_vm_address_t, mach_vm_size_t);
extern kern_return_t mach_vm_protect(vm_map_t, mach_vm_address_t, mach_vm_size_t, boolean_t, vm_prot_t);
extern kern_return_t mach_memory_entry_purgable_control(mach_port_t, vm_purgable_t, int *);
extern kern_return_t mach_vm_map(vm_map_t, mach_vm_address_t *, mach_vm_size_t, mach_vm_offset_t, int, mem_entry_name_port_t, memory_object_offset_t, boolean_t, vm_prot_t, vm_prot_t, vm_inherit_t);

static int bad(const char *what, long got, long want) {
    printf("purgeable: %s: %#lx, want %#lx\n", what, got, want);
    fflush(stdout);
    return 1;
}

static int info(task_vm_info_data_t *v) {
    mach_msg_type_number_t n = TASK_VM_INFO_COUNT;
    return task_info(mach_task_self(), TASK_VM_INFO_PURGEABLE, (task_info_t)v, &n) == KERN_SUCCESS ? 0 : -1;
}

int main(void) {
    mach_vm_address_t a = 0;
    kern_return_t kr = mach_vm_allocate(mach_task_self(), &a, 4 * PAGE, VM_FLAGS_ANYWHERE | VM_FLAGS_PURGABLE);
    if (kr != KERN_SUCCESS) return bad("a purgeable allocation", kr, 0);
    int state = 0;
    kr = vm_purgable_control(mach_task_self(), a, VM_PURGABLE_GET_STATE, &state);
    if (kr != KERN_SUCCESS || state != VM_PURGABLE_NONVOLATILE) return bad("its state", state, VM_PURGABLE_NONVOLATILE);

    task_vm_info_data_t v0, v1, v2;
    info(&v0);
    memset((void *)a, 7, 4 * PAGE);
    info(&v1);
    if (v1.ledger_purgeable_nonvolatile - v0.ledger_purgeable_nonvolatile != 4 * PAGE) return bad("the nonvolatile ledger", (long)(v1.ledger_purgeable_nonvolatile - v0.ledger_purgeable_nonvolatile), (long)(4 * PAGE));
    // The pages are the object's owner's, not the pmap's: once in the
    // footprint, with what the pmap's tables cost.
    if ((int64_t)(v1.phys_footprint - v0.phys_footprint) < (int64_t)(4 * PAGE) || v1.phys_footprint - v0.phys_footprint > 5 * PAGE) return bad("the footprint", (long)(v1.phys_footprint - v0.phys_footprint), (long)(4 * PAGE));

    // Volatile, LIFO, group 2: out of the footprint, into the volatile
    // ledger, the pages kept.
    state = VM_PURGABLE_VOLATILE | VM_PURGABLE_BEHAVIOR_LIFO | VM_VOLATILE_GROUP_2;
    kr = vm_purgable_control(mach_task_self(), a, VM_PURGABLE_SET_STATE, &state);
    if (kr != KERN_SUCCESS || state != VM_PURGABLE_NONVOLATILE) return bad("making it volatile", kr, 0);
    info(&v2);
    if (v2.ledger_purgeable_volatile - v1.ledger_purgeable_volatile != 4 * PAGE || v2.ledger_purgeable_nonvolatile != v0.ledger_purgeable_nonvolatile) return bad("the volatile ledger", (long)(v2.ledger_purgeable_volatile - v1.ledger_purgeable_volatile), (long)(4 * PAGE));
    if (v1.phys_footprint - v2.phys_footprint != 4 * PAGE) return bad("the footprint once volatile", (long)(v1.phys_footprint - v2.phys_footprint), (long)(4 * PAGE));
    if (v2.purgeable_volatile_virtual != 4 * PAGE || v2.purgeable_volatile_resident != 4 * PAGE) return bad("TASK_VM_INFO_PURGEABLE's volatile memory", (long)v2.purgeable_volatile_virtual, (long)(4 * PAGE));
    if (((volatile char *)a)[PAGE] != 7) return bad("a volatile page, kept", ((volatile char *)a)[PAGE], 7);

    // Every volatile object emptied: zeros after, EMPTY, and empty still
    // when made volatile again.
    kr = vm_purgable_control(mach_task_self(), a, VM_PURGABLE_PURGE_ALL, &state);
    if (kr != KERN_SUCCESS) return bad("PURGE_ALL", kr, 0);
    vm_purgable_control(mach_task_self(), a, VM_PURGABLE_GET_STATE, &state);
    if (state != VM_PURGABLE_EMPTY || ((volatile char *)a)[PAGE] != 0) return bad("an emptied object", state, VM_PURGABLE_EMPTY);
    state = VM_PURGABLE_VOLATILE;
    vm_purgable_control(mach_task_self(), a, VM_PURGABLE_SET_STATE, &state);
    vm_purgable_control(mach_task_self(), a, VM_PURGABLE_GET_STATE, &state);
    if (state != VM_PURGABLE_EMPTY) return bad("empty, made volatile", state, VM_PURGABLE_EMPTY);
    state = VM_PURGABLE_NONVOLATILE;
    kr = vm_purgable_control(mach_task_self(), a, VM_PURGABLE_SET_STATE, &state);
    if (kr != KERN_SUCCESS || state != VM_PURGABLE_EMPTY) return bad("nonvolatile again", state, VM_PURGABLE_EMPTY);

    // Errors: memory that is not purgeable, a hole, a bad control or state.
    mach_vm_address_t plain = 0;
    mach_vm_allocate(mach_task_self(), &plain, PAGE, VM_FLAGS_ANYWHERE);
    if ((kr = vm_purgable_control(mach_task_self(), plain, VM_PURGABLE_GET_STATE, &state)) != KERN_INVALID_ARGUMENT) return bad("memory not purgeable", kr, KERN_INVALID_ARGUMENT);
    mach_vm_deallocate(mach_task_self(), plain, PAGE);
    if ((kr = vm_purgable_control(mach_task_self(), plain, VM_PURGABLE_GET_STATE, &state)) != KERN_INVALID_ADDRESS) return bad("a hole", kr, KERN_INVALID_ADDRESS);
    if ((kr = vm_purgable_control(mach_task_self(), a, 7, &state)) != KERN_INVALID_ARGUMENT) return bad("an unknown control", kr, KERN_INVALID_ARGUMENT);
    state = 1 << 20;
    if ((kr = vm_purgable_control(mach_task_self(), a, VM_PURGABLE_SET_STATE, &state)) != KERN_INVALID_ARGUMENT) return bad("an unknown state bit", kr, KERN_INVALID_ARGUMENT);
    state = VM_PURGABLE_DENY;
    if ((kr = vm_purgable_control(mach_task_self(), a, VM_PURGABLE_SET_STATE, &state)) != KERN_INVALID_ARGUMENT) return bad("DENY", kr, KERN_INVALID_ARGUMENT);
    mach_vm_protect(mach_task_self(), a, 4 * PAGE, FALSE, VM_PROT_READ);
    state = VM_PURGABLE_VOLATILE;
    if ((kr = vm_purgable_control(mach_task_self(), a, VM_PURGABLE_SET_STATE, &state)) != KERN_PROTECTION_FAILURE) return bad("a read-only mapping", kr, KERN_PROTECTION_FAILURE);
    mach_vm_deallocate(mach_task_self(), a, 4 * PAGE);

    // A purgeable named entry: two mappings, one object.
    memory_object_size_t size = 2 * PAGE;
    mach_port_t entry = MACH_PORT_NULL;
    kr = mach_make_memory_entry_64(mach_task_self(), &size, 0, MAP_MEM_NAMED_CREATE | MAP_MEM_PURGABLE | VM_PROT_READ | VM_PROT_WRITE, &entry, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) return bad("a purgeable named entry", kr, 0);
    mach_vm_address_t x = 0, y = 0;
    kr = mach_vm_map(mach_task_self(), &x, size, 0, VM_FLAGS_ANYWHERE, entry, 0, FALSE, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_NONE);
    kr |= mach_vm_map(mach_task_self(), &y, size, 0, VM_FLAGS_ANYWHERE, entry, 0, FALSE, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_NONE);
    if (kr != KERN_SUCCESS) return bad("its mappings", kr, 0);
    ((volatile char *)x)[3] = 'e';
    if (((volatile char *)y)[3] != 'e') return bad("a store, in the other mapping", ((volatile char *)y)[3], 'e');
    state = VM_PURGABLE_EMPTY;
    kr = mach_memory_entry_purgable_control(entry, VM_PURGABLE_SET_STATE, &state);
    if (kr != KERN_SUCCESS || ((volatile char *)y)[3] != 0) return bad("the entry emptied", ((volatile char *)y)[3], 0);

    // A tagged entry: the tagged ledger's (not in TASK_VM_INFO), not the
    // purgeable ones', and not purgeable.
    size = PAGE;
    mach_port_t tagged = MACH_PORT_NULL;
    kr = mach_make_memory_entry_64(mach_task_self(), &size, 0, MAP_MEM_NAMED_CREATE | MAP_MEM_LEDGER_TAGGED | VM_PROT_READ | VM_PROT_WRITE, &tagged, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) return bad("a tagged entry", kr, 0);
    state = 0;
    if ((kr = mach_memory_entry_purgable_control(tagged, VM_PURGABLE_GET_STATE, &state)) != KERN_INVALID_ARGUMENT) return bad("a tagged entry's purgeable state", kr, KERN_INVALID_ARGUMENT);
    printf("purgeable ok\n");
    return 0;
}
