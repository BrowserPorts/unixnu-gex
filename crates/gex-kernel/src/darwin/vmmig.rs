//! The VM routines of `mach_vm.defs` and `vm_map.defs` that map memory a
//! port names or that is mapped already: `mach_vm_map` (`vm_map`,
//! `vm_map_64`), `mach_vm_remap` (`vm_remap`) and `mach_vm_remap_new`
//! (`vm_remap_new`), as MIG's kernel server decodes them
//! (`vm_user.c`, xnu-10063.141.1).

use super::ipc::kr;
use super::ipc::msg::Kmsg;
use super::ipc::right::Carried;
use super::ipc::Kobject;
use super::kobject::Reply;
use super::mach::{prot, vmf};
use super::mig::{arg_after, MIG_BAD_ARGUMENTS};
use super::vmentry::VM_PROT_IS_MASK;
use super::vmshare::{Remap, Source};
use crate::syscalls::Kernel;

/// `KERN_INVALID_OBJECT`.
const KERN_INVALID_OBJECT: i32 = 29;

/// The `i`th word after a request's one port descriptor.
fn word(req: &Kmsg, i: usize) -> Option<u32> {
    arg_after(req, 1, i).map(|w| w as u32)
}

/// The 64-bit argument at words `i` and `i + 1`.
fn word64(req: &Kmsg, i: usize) -> Option<u64> {
    Some(u64::from(word(req, i)?) | (u64::from(word(req, i + 1)?) << 32))
}

/// The routine `id` on `obj`, if it is one of these.
pub(super) fn routine(k: &mut Kernel, obj: &Kobject, id: i32, req: &Kmsg) -> Option<Reply> {
    Some(match (obj, id) {
        // mach_vm_map, vm_map, vm_map_64.
        (Kobject::Task, 4811 | 3812 | 3826) => vm_map(k, req),
        (Kobject::TaskRead | Kobject::TaskInspect | Kobject::TaskName, 4811 | 3812 | 3826 | 4813 | 3814 | 4821 | 3832) => Reply::err(kr::INVALID_ARGUMENT as i32),
        // mach_vm_remap, vm_remap.
        (Kobject::Task, 4813 | 3814) => remap(k, req, false),
        // mach_vm_remap_new, vm_remap_new.
        (Kobject::Task, 4821 | 3832) => remap(k, req, true),
        // mach_make_memory_entry_64, _mach_make_memory_entry,
        // mach_make_memory_entry.
        (Kobject::Task, 3825 | 4817 | 3816) => make_memory_entry(k, req),
        (Kobject::TaskRead | Kobject::TaskInspect | Kobject::TaskName, 3825 | 4817 | 3816) => Reply::err(kr::INVALID_ARGUMENT as i32),
        // mach_memory_entry_purgable_control(entry, control, &state).
        (Kobject::NamedEntry(id), 4900) => match (super::mig::arg(req, 0), super::mig::arg(req, 1), super::vmentry::get(*id)) {
            (Some(control), Some(state), Some(e)) => match k.darwin_entry_purgable_control(&e, control as u32, state) {
                0 => Reply::ok(state.to_le_bytes().to_vec()),
                r => Reply::err(r as i32),
            },
            (Some(_), Some(_), None) => Reply::err(kr::INVALID_ARGUMENT as i32),
            _ => Reply::err(MIG_BAD_ARGUMENTS),
        },
        // mach_memory_entry_access_tracking(entry, &access_tracking).
        (Kobject::NamedEntry(id), 4901) => match (super::mig::arg(req, 0), super::vmentry::get(*id)) {
            (Some(_), Some(e)) => Reply::err(k.darwin_entry_access_tracking(&e) as i32),
            (Some(_), None) => Reply::err(kr::INVALID_ARGUMENT as i32),
            _ => Reply::err(MIG_BAD_ARGUMENTS),
        },
        // mach_memory_entry_ownership(entry, owner, ledger_tag, ledger_flags).
        (Kobject::NamedEntry(_), 4902) => {
            let mut r = Reply::err(kr::FAILURE as i32);
            r.unimplemented = Some("mach_memory_entry_ownership (an object's owner and its tag ledgers)".into());
            r
        }
        _ => return None,
    })
}

/// The named entry a port is (`mach_memory_entry_from_port`), if any.
fn entry_of(k: &mut Kernel, right: Option<Carried>) -> Option<super::vmentry::NamedEntry> {
    let Some(Carried::Port(p)) = right else { return None };
    match k.ipc().port(p).kobject {
        Some(Kobject::NamedEntry(id)) => super::vmentry::get(id),
        _ => None,
    }
}

/// `mach_make_memory_entry_64(target, &size, offset, permission,
/// &object_handle, parent_entry)`: the new entry's send right, out.
fn make_memory_entry(k: &mut Kernel, req: &Kmsg) -> Reply {
    let (Some(size), Some(offset), Some(permission)) = (word64(req, 0), word64(req, 2), word(req, 4)) else { return Reply::err(MIG_BAD_ARGUMENTS) };
    let Some(super::ipc::msg::Desc::Port { right, disp, .. }) = req.descs.first() else { return Reply::err(MIG_BAD_ARGUMENTS) };
    let (right, disp) = (*right, *disp);
    let parent = entry_of(k, right);
    let mut size = size;
    let made = match k.darwin_own_memory(|k, m| k.darwin_make_memory_entry(m, &mut size, offset, permission, parent)) {
        Ok(r) => r,
        Err(reply) => return reply,
    };
    let made = match made {
        Ok(made) => made,
        Err(e) => return Reply::err(e as i32),
    };
    if let Some(c) = right {
        k.ipc().object_destroy(c, disp);
    }
    let mut out = super::mig::NDR_RECORD.to_vec();
    out.extend_from_slice(&size.to_le_bytes());
    match made {
        super::vmentry::Made::New(id) => {
            let ipc = k.ipc();
            let port = ipc.kobject_port(Kobject::NamedEntry(id));
            ipc.port_mut(port).owner = 0;
            ipc.make_send(port);
            ipc.port_mut(port).nsrequest_kobject = true;
            let mut r = Reply::port(Carried::Port(port));
            r.out = out;
            r
        }
        super::vmentry::Made::Nothing => {
            let mut r = Reply::ok(out);
            r.ports.push(super::kobject::PortOut::Raw(0));
            r
        }
    }
}

/// `mach_vm_map_external(target, &address, size, mask, flags, object,
/// offset, copy, cur_protection, max_protection, inheritance)`.
fn vm_map(k: &mut Kernel, req: &Kmsg) -> Reply {
    let (Some(address), Some(size), Some(mask), Some(flags), Some(_offset), Some(_copy), Some(cur), Some(max), Some(inherit)) =
        (word64(req, 0), word64(req, 2), word64(req, 4), word(req, 6), word64(req, 7), word(req, 9), word(req, 10), word(req, 11), word(req, 12))
    else {
        return Reply::err(MIG_BAD_ARGUMENTS);
    };
    let Some(super::ipc::msg::Desc::Port { right, .. }) = req.descs.first() else { return Reply::err(MIG_BAD_ARGUMENTS) };
    let flags = u64::from(flags);
    if flags & !vmf::USER_MAP != 0 {
        return Reply::err(kr::INVALID_ARGUMENT as i32);
    }
    // vm_map_enter_mem_object: VM_PROT_IS_MASK comes off both.
    let (cur, max) = (u64::from(cur & !VM_PROT_IS_MASK), u64::from(max & !VM_PROT_IS_MASK));
    if cur & !prot::ALL != 0 || max & !prot::ALL != 0 || inherit > u32::from(super::vm::inherit::NONE) || size == 0 {
        return Reply::err(kr::INVALID_ARGUMENT as i32);
    }
    let cur = cur & max;
    let cur = if cur & prot::EXECUTE != 0 { cur | prot::READ } else { cur };
    match right {
        // No object: anonymous memory, the offset and copy flag ignored.
        None => {
            let mut addr = address;
            let r = k.darwin_own_memory(|k, m| {
                k.darwin_vm_enter_anon_object(m, &mut addr, size, mask, flags & !(vmf::RETURN_DATA_ADDR | vmf::RETURN_4K_DATA_ADDR), cur, max, inherit as u8)
            });
            match r {
                Ok(0) => Reply::ok(addr.to_le_bytes().to_vec()),
                Ok(e) => Reply::err(e as i32),
                Err(r) => r,
            }
        }
        Some(c) => {
            // Neither a named entry nor a memory object.
            let Some(e) = entry_of(k, Some(*c)) else { return Reply::err(KERN_INVALID_OBJECT) };
            let Some(super::ipc::msg::Desc::Port { disp, .. }) = req.descs.first() else { return Reply::err(MIG_BAD_ARGUMENTS) };
            let disp = *disp;
            let (Some(offset), Some(copy)) = (word64(req, 7), word(req, 9)) else { return Reply::err(MIG_BAD_ARGUMENTS) };
            // The masks are the entry's to apply.
            let (rc, rm) = (word(req, 10).unwrap_or(0), word(req, 11).unwrap_or(0));
            let mask_bits = |w: u32, v: u64| if w & VM_PROT_IS_MASK != 0 { v | u64::from(super::vmentry::VM_PROT_IS_MASK) } else { v };
            let mut addr = address;
            let r = k.darwin_own_memory(|k, m| k.darwin_map_named_entry(m, &mut addr, size, mask, flags, &e, offset, copy != 0, mask_bits(rc, cur), mask_bits(rm, max), inherit as u8));
            match r {
                Ok(0) => {
                    k.ipc().object_destroy(*c, disp);
                    Reply::ok(addr.to_le_bytes().to_vec())
                }
                Ok(e) => Reply::err(e as i32),
                Err(r) => r,
            }
        }
    }
}

/// The map a source task port converts to (`convert_port_to_map`, or the
/// read flavor's `convert_port_to_map_read` when `read` allows it): none
/// for anything else.
fn source_map(k: &mut Kernel, right: Option<Carried>, read: bool) -> Option<Source> {
    let Some(Carried::Port(p)) = right else { return None };
    let ipc = k.ipc();
    let port = ipc.port(p);
    let ok = port.active && match port.kobject {
        Some(Kobject::Task) => true,
        Some(Kobject::TaskRead) => read,
        _ => false,
    };
    if !ok {
        return None;
    }
    Some(if port.owner == ipc.task { Source::Same } else { Source::Other(port.owner) })
}

/// `mach_vm_remap_external` (`legacy`: cur and max out) and
/// `mach_vm_remap_new_external` (cur and max in and out).
fn remap(k: &mut Kernel, req: &Kmsg, new: bool) -> Reply {
    let (Some(target), Some(size), Some(mask), Some(flags), Some(src_addr), Some(copy)) = (word64(req, 0), word64(req, 2), word64(req, 4), word(req, 6), word64(req, 7), word(req, 9)) else {
        return Reply::err(MIG_BAD_ARGUMENTS);
    };
    let (cur, max, inherit) = if new {
        match (word(req, 10), word(req, 11), word(req, 12)) {
            (Some(c), Some(m), Some(i)) => (u64::from(c), u64::from(m), i),
            _ => return Reply::err(MIG_BAD_ARGUMENTS),
        }
    } else {
        match word(req, 10) {
            Some(i) => (0, 0, i),
            None => return Reply::err(MIG_BAD_ARGUMENTS),
        }
    };
    let Some(super::ipc::msg::Desc::Port { right, disp, .. }) = req.descs.first() else { return Reply::err(MIG_BAD_ARGUMENTS) };
    let (right, disp) = (*right, *disp);
    let mut flags = u64::from(flags);
    if flags & !vmf::USER_REMAP != 0 {
        return Reply::err(kr::INVALID_ARGUMENT as i32);
    }
    let copy = copy != 0;
    if new {
        // mach_vm_remap_new_external: always the data's address back.
        flags |= vmf::RETURN_DATA_ADDR;
        if cur & !prot::ALL != 0 || max & !prot::ALL != 0 || cur & max != cur {
            return Reply::err(kr::INVALID_ARGUMENT as i32);
        }
        if max & (prot::WRITE | prot::EXECUTE) == prot::WRITE | prot::EXECUTE {
            return Reply::err(2);
        }
    }
    let read = new && (copy || max == prot::READ || max == 0);
    let Some(src) = source_map(k, right, read) else { return Reply::err(kr::INVALID_ARGUMENT as i32) };
    let mut r = Remap { target, size, mask, flags, src, src_addr, copy, cur, max, inherit, prot_copy: false };
    let ret = match k.darwin_own_memory(|k, m| k.darwin_vm_remap(m, &mut r)) {
        Ok(ret) => ret,
        Err(reply) => return reply,
    };
    if ret != kr::SUCCESS {
        return Reply::err(ret as i32);
    }
    // The source's send right: MIG's release of a converted port, or the
    // new call's consumption of it on success.
    if let Some(c) = right {
        k.ipc().object_destroy(c, disp);
    }
    let mut out = r.target.to_le_bytes().to_vec();
    out.extend_from_slice(&(r.cur as u32).to_le_bytes());
    out.extend_from_slice(&(r.max as u32).to_le_bytes());
    Reply::ok(out)
}
