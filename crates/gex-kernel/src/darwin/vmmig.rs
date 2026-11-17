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
        _ => return None,
    })
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
    const VM_PROT_IS_MASK: u32 = 0x40;
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
        // Neither a named entry nor a memory object.
        Some(_) => Reply::err(KERN_INVALID_OBJECT),
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
