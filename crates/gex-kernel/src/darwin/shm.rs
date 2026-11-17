//! POSIX shared memory: `shm_open` and `shm_unlink`, and what is done with
//! the object they name (`bsd/kern/posix_shm.c`, xnu-10063.141.1).
//!
//! The names live in one table for the host process. An object's memory is
//! the anonymous object `pshm_truncate` makes (`mach_make_memory_entry_64`
//! with MAP_MEM_NAMED_CREATE), whose pages the host holds apart from every
//! task ([`crate::host_hold`]); every mapping of the object, in any task,
//! is the host's mapping of those pages ([`crate::host_remap`]), so a
//! store through one is seen through all of them at once.

use super::cred::Cred;
use crate::errno::{Errno, SysResult};
use crate::file::OpenFile;
use crate::syscalls::Kernel;
use crate::vfs::{FileHandle, FileType, Metadata};
use crate::GuestMem;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// `PSHMNAMLEN`: a name is at most this many bytes, and the string with its
/// NUL fits in one more.
pub const PSHMNAMLEN: usize = 31;

/// `FREAD` and `FWRITE`, the kernel's spelling of the access mode.
const FREAD: u32 = 1;
const FWRITE: u32 = 2;
/// `O_EXEC`, which is `FEXEC` as well.
const O_EXEC: u32 = 0x4000_0000;
/// `FMASK`: what of the open's flags the file keeps.
const FMASK: u32 = FREAD | FWRITE | super::ioctl::FCNTLFLAGS as u32 | O_EXEC;

/// Darwin's `O_CREAT`, `O_TRUNC` and `O_EXCL`.
const O_TRUNC: u32 = 0x400;
const O_CREAT: u32 = 0x200;
const O_EXCL: u32 = 0x800;

/// `ALLPERMS`.
const ALLPERMS: u32 = 0o7777;

/// The map's page (`vm_map_page_mask(current_map())`, iOS's 16 KiB), which
/// `ftruncate` rounds a size up to and `mmap` bounds against.
const PAGE: u64 = super::mach::PAGE_MASK + 1;

/// A POSIX shared memory object (`pshm_info_t`).
#[derive(Debug)]
pub struct Pshm {
    pub name: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// The process that made it.
    pub creator: i32,
    /// `pshm_length`, and its memory object (`pshm_mobjs`, none for a
    /// size of 0), whose reference it holds; `None` until `ftruncate`
    /// allocates it (`PSHM_ALLOCATED`).
    length: Mutex<Option<(u64, Option<u64>)>>,
}

impl Drop for Pshm {
    /// `pshm_deref`'s last: the object's memory entry released.
    fn drop(&mut self) {
        if let Some((_, Some(obj))) = *self.length.get_mut().unwrap_or_else(|e| e.into_inner()) {
            super::vmobject::release(obj);
        }
    }
}

impl Pshm {
    fn new(name: &str, mode: u32, uid: u32, gid: u32, creator: i32) -> Pshm {
        Pshm { name: name.to_string(), mode, uid, gid, creator, length: Mutex::new(None) }
    }

    pub fn length(&self) -> u64 {
        self.length.lock().unwrap().map_or(0, |(l, _)| l)
    }

    pub fn allocated(&self) -> bool {
        self.length.lock().unwrap().is_some()
    }

    /// The memory object, once allocated with a size.
    pub fn object(&self) -> Option<u64> {
        self.length.lock().unwrap().and_then(|(_, o)| o)
    }

    /// `pshm_truncate`: the one allocation an object gets, its size rounded
    /// up to the map's page, its memory one new anonymous object
    /// (`ANON_MAX_SIZE` being past any size a host can hold) made with
    /// `make`, which gives the object or the error. A second call fails.
    pub fn allocate(&self, length: u64, make: impl FnOnce(u64) -> Result<u64, Errno>) -> Result<(), Errno> {
        let mut cur = self.length.lock().unwrap();
        if cur.is_some() {
            return Err(Errno::EINVAL);
        }
        // vm_map_round_page of an off_t no larger than OFF_MAX.
        let total = (length + PAGE - 1) & !(PAGE - 1);
        let obj = if total == 0 { None } else { Some(make(total)?) };
        *cur = Some((total, obj));
        Ok(())
    }
}

/// `pshm_access`: whether the caller may open the object for `fmode`
/// (`FREAD`, `FWRITE`). Root always may; anyone else as `posix_cred_access`
/// says.
fn access(p: &Pshm, fmode: u32, cred: &Cred) -> Result<(), Errno> {
    if cred.uid == 0 {
        return Ok(());
    }
    let req = (if fmode & FREAD != 0 { 0o400 } else { 0 }) | (if fmode & FWRITE != 0 { 0o200 } else { 0 });
    super::cred::posix_cred_access(cred, p.uid, p.gid, p.mode, req)
}

/// The names (`pshm_head`).
#[derive(Debug, Default)]
pub struct Names {
    by_name: Mutex<BTreeMap<String, Arc<Pshm>>>,
}

impl Names {
    pub const fn new() -> Names {
        Names { by_name: Mutex::new(BTreeMap::new()) }
    }

    /// The object `shm_open(name, oflag, mode)` opens, and whether it was
    /// made by the call (an object already there is the caller's to check
    /// the MAC policies and its access with). `fmode` is `FFLAGS(oflag)`.
    fn open(&self, name: &str, fmode: u32, mode: u32, cred: &Cred, pid: i32) -> Result<(Arc<Pshm>, bool), Errno> {
        let mut names = self.by_name.lock().unwrap();
        match names.get(name) {
            Some(p) => {
                if fmode & (O_CREAT | O_EXCL) == (O_CREAT | O_EXCL) {
                    return Err(Errno::EEXIST);
                }
                // Truncating an object that has been given a size is refused.
                if fmode & O_TRUNC != 0 && p.allocated() {
                    return Err(Errno::EINVAL);
                }
                Ok((Arc::clone(p), false))
            }
            None => {
                if fmode & O_CREAT == 0 {
                    return Err(Errno::ENOENT);
                }
                let p = Arc::new(Pshm::new(name, mode & ALLPERMS, cred.uid, cred.groups.first().copied().unwrap_or(0), pid));
                names.insert(name.to_string(), Arc::clone(&p));
                Ok((p, true))
            }
        }
    }

    /// The object of a name.
    fn find(&self, name: &str) -> Option<Arc<Pshm>> {
        self.by_name.lock().unwrap().get(name).cloned()
    }

    /// `shm_unlink`: the name goes; the object lives while it is open.
    fn unlink(&self, name: &str, cred: &Cred) -> Result<(), Errno> {
        let mut names = self.by_name.lock().unwrap();
        let p = names.get(name).ok_or(Errno::ENOENT)?;
        if let Err(e) = access(p, FWRITE, cred) {
            if p.uid != cred.uid {
                return Err(e);
            }
        }
        names.remove(name);
        Ok(())
    }
}

/// The host process's names.
static NAMES: Names = Names::new();

/// The descriptor of an object (`pshmnode_t`): `DTYPE_PSXSHM`, which has
/// no `read` or `write` ([`Kernel::darwin_shm_fd`]).
#[derive(Debug)]
pub struct PshmHandle(pub Arc<Pshm>, AtomicU64);

impl PshmHandle {
    /// `mapp_addr`: where this open's last mapping of the object starts.
    pub fn mapp_addr(&self) -> u64 {
        self.1.load(Ordering::Acquire)
    }

    pub fn set_mapp_addr(&self, at: u64) {
        self.1.store(at, Ordering::Release);
    }
}

impl FileHandle for PshmHandle {
    fn as_posix_shm(self: Arc<Self>) -> Option<Arc<PshmHandle>> {
        Some(self)
    }

    /// `fo_no_read`: [`Kernel::darwin_shm_io`] answers a read first.
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> SysResult {
        Err(Errno::ENXIO)
    }

    /// `fo_no_write`.
    fn write_at(&self, _offset: u64, _buf: &[u8]) -> SysResult {
        Err(Errno::ENXIO)
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(Metadata {
            file_type: FileType::Regular,
            size: self.0.length(),
            mode: self.0.mode,
            ino: 0,
            mtime: 0,
            nlink: 1,
            rdev: 0,
            times: Default::default(),
        })
    }

    /// What `ftruncate` reaches only through [`Kernel::darwin_shm_ftruncate`].
    fn truncate(&self, _len: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
}

/// `FFLAGS(oflags)`: the access mode one more than it was, or taken away
/// for an execute-only open.
pub(crate) fn fflags(oflags: u32) -> u32 {
    if oflags & O_EXEC != 0 {
        oflags & !3
    } else {
        oflags.wrapping_add(1)
    }
}

/// The file's `fg_flag` (`fmode & FMASK`) as the open's flags it keeps,
/// in the canonical terms; without `FEXEC`, which neither open has kept.
pub(crate) fn file_flags(fmode: u32) -> u64 {
    super::bsd::open_flags(u64::from((fmode & FMASK).wrapping_sub(1)))
}

/// `shm_open`'s name: `copyinstr` into `PSHMNAMLEN + 1` bytes, and not empty.
fn get_name(m: &GuestMem<'_>, addr: u64) -> Result<String, Errno> {
    let raw = m.read_cstr(addr, PSHMNAMLEN + 1)?;
    if raw.is_empty() {
        return Err(Errno::EINVAL);
    }
    // The table compares bytes; a name that is not UTF-8 is kept as its
    // lossy spelling, which cannot collide with another that is.
    Ok(raw.iter().map(|&b| char::from(b)).collect())
}

impl Kernel {
    /// Whether `fd` is a shared memory object.
    pub(crate) fn darwin_shm_fd(&self, fd: u64) -> bool {
        self.fd_io().fds.get(fd as i32).is_ok_and(|f| Arc::clone(&f.handle).as_posix_shm().is_some())
    }

    /// `read` or `write` on an object: the descriptor has to be open that
    /// way, and then it has no such operation (`fo_no_read`, `fo_no_write`).
    pub(crate) fn darwin_shm_io(&self, fd: u64, write: bool) -> Errno {
        match self.fd_io().fds.get(fd as i32) {
            Ok(f) if (write && !f.writable) || (!write && !f.readable) => Errno::EBADF,
            _ => Errno::ENXIO,
        }
    }

    /// `shm_open(name, oflag, mode)`.
    pub(crate) fn darwin_shm_open(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let name = get_name(m, a[0])?;
        let fmode = fflags(a[1] as u32);
        if fmode & (FREAD | FWRITE) == 0 {
            return Err(Errno::EINVAL);
        }
        // The MAC policies' say on a name to make, before it is looked for.
        if fmode & O_CREAT != 0 {
            self.darwin_pshm_mac(78, &name)?;
        }
        let (p, made) = NAMES.open(&name, fmode, a[2] as u32 & ALLPERMS, &self.dtask.cred, self.pid)?;
        // An object there: the MAC policies' say on reading it, then on
        // writing or truncating it (`fmode & (FWRITE | O_TRUNC)`), then its
        // access.
        if !made {
            if fmode & FREAD != 0 {
                self.darwin_pshm_mac(76, &name)?;
            }
            if fmode & (FWRITE | O_TRUNC) != 0 {
                self.darwin_pshm_mac(79, &name)?;
            }
            access(&p, fmode, &self.dtask.cred)?;
        }
        let handle: Arc<dyn FileHandle> = Arc::new(PshmHandle(p, AtomicU64::new(0)));
        let file = OpenFile::new(handle, format!("/shm:{name}"), file_flags(fmode), fmode & FREAD != 0, fmode & FWRITE != 0);
        // Close-on-exec, as `FP_CLOEXEC`.
        self.fd_io().fds.insert(file, true).map(|fd| fd as u64)
    }

    /// `shm_unlink(name)`: any failure of the name is `EINVAL`.
    pub(crate) fn darwin_shm_unlink(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let name = get_name(m, a[0]).map_err(|_| Errno::EINVAL)?;
        // The object found, then the MAC policies' say on its unlink.
        NAMES.find(&name).ok_or(Errno::ENOENT)?;
        self.darwin_pshm_mac(80, &name)?;
        NAMES.unlink(&name, &self.dtask.cred).map(|_| 0)
    }

    /// Sandbox's check of operation `op` (ipc-posix-shm-read-data 76,
    /// -write-create 78, -write-data 79, -write-unlink 80) of the object of
    /// this name (`pshm_name`).
    fn darwin_pshm_mac(&mut self, op: usize, name: &str) -> Result<(), Errno> {
        let a = super::mac::SbArgs { kind: super::sandbox::kind::POSIX_IPC, string: Some(name.chars().map(|c| c as u8).collect()), ..Default::default() };
        match self.darwin_sb_evaluate(op, &a) {
            0 => Ok(()),
            e => Err(super::errno::errno_of(e as i32)),
        }
    }

    /// `fstat` of an object (`pshm_stat`): its mode (the permission bits
    /// alone), owner, group and size, the rest zero.
    pub(crate) fn darwin_shm_stat(&mut self, m: &mut GuestMem<'_>, fd: u64, buf: u64) -> Result<u64, Errno> {
        let f = self.fd_io().fds.get(fd as i32)?;
        let Some(h) = Arc::clone(&f.handle).as_posix_shm() else { return Err(Errno::EBADF) };
        let p = &h.0;
        let st = crate::fs::Stat { mode: p.mode, uid: p.uid, gid: p.gid, size: p.length() as i64, ..Default::default() };
        m.write(buf, &if self.darwin_stat_ino32 { st.encode_darwin_ino32() } else { st.encode_darwin() })?;
        Ok(0)
    }

    /// `ftruncate(fd, length)` on an object (`pshm_truncate`): its memory
    /// object made (`mach_make_memory_entry_64` with MAP_MEM_NAMED_CREATE
    /// and VM_PROT_DEFAULT), its pages the host's, held apart from every
    /// task.
    pub(crate) fn darwin_shm_ftruncate(&mut self, a: &[u64; 6]) -> Result<u64, Errno> {
        if (a[1] as i64) < 0 {
            return Err(Errno::EINVAL);
        }
        let f = self.fd_io().fds.get(a[0] as i32)?;
        let Some(h) = Arc::clone(&f.handle).as_posix_shm() else { return Err(Errno::EINVAL) };
        let mut unheld = None;
        let r = h.0.allocate(a[1], |total| {
            let Some(addr) = usize::try_from(total).ok().and_then(crate::host_hold) else {
                unheld = Some(total);
                return Err(Errno::ENOMEM);
            };
            let hold = Arc::new(super::vmobject::Hold { addr, len: total });
            Ok(super::vmobject::allocate(total, super::vmobject::Pager::Anon, Some(hold)))
        });
        if let Some(total) = unheld {
            self.darwin_unimplemented(format!("a POSIX shared memory object of {total:#x} bytes on a host that holds no pages apart from a task's, or not so many"));
        }
        r.map(|_| 0)
    }

    /// `pshm_mmap` of `size` bytes (the length with the position's offset
    /// in its page, rounded to pages) of the object open as `fd` from
    /// `file_pos` (page aligned), at `addr` (fixed) or from it as a hint,
    /// with protection `prot` and `flags`: the object's own checks, the
    /// range reserved, then the object's pages mapped over it, shared and
    /// inherited by share, at most read and write (no write where the
    /// descriptor cannot). The mapping's address.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn darwin_shm_mmap(&mut self, m: &mut GuestMem<'_>, addr: u64, size: u64, prot: u64, flags: u32, fd: i32, file_pos: u64, pageoff: u64) -> Result<u64, Errno> {
        use super::mach::{prot as vp, vmf};
        const MAP_SHARED: u32 = 0x1;
        const MAP_FIXED: u32 = 0x10;
        if size == 0 {
            return Ok(0);
        }
        if flags & MAP_SHARED == 0 {
            return Err(Errno::EINVAL);
        }
        let f = self.fd_io().fds.get(fd)?;
        let Some(h) = Arc::clone(&f.handle).as_posix_shm() else { return Err(Errno::EINVAL) };
        let mut max = vp::READ | vp::WRITE;
        if !f.writable {
            if prot & vp::WRITE != 0 {
                return Err(Errno::EPERM);
            }
            max &= !vp::WRITE;
        }
        let shm = &h.0;
        if !shm.allocated() {
            return Err(Errno::EINVAL);
        }
        let pshm_size = shm.length();
        if size > pshm_size || size.checked_add(file_pos).is_none_or(|e| e > pshm_size) {
            return Err(Errno::EINVAL);
        }
        let Some(obj) = shm.object() else { return Err(Errno::EINVAL) };
        let errno = |k: u64| match k {
            1 | 3 => Errno::ENOMEM,
            2 => Errno::EACCES,
            _ => Errno::EINVAL,
        };
        // The whole range reserved first, none and not inherited.
        let fixed = flags & MAP_FIXED != 0;
        let mut at = if fixed { addr } else { (addr + super::mach::PAGE_MASK) & !super::mach::PAGE_MASK };
        if fixed && at & super::mach::PAGE_MASK != 0 {
            return Err(Errno::EINVAL);
        }
        let vflags = if fixed { vmf::OVERWRITE } else { vmf::ANYWHERE };
        let k = self.darwin_vm_enter_anon_object(m, &mut at, size, 0, vflags, 0, 0, super::vm::inherit::NONE);
        if k != super::ipc::kr::SUCCESS {
            return Err(errno(k));
        }
        // vm_map_enter_mem_object of the object over it: a protection
        // beyond the most is cut to it, execute reads too.
        let mut cur = prot & max;
        if cur & vp::EXECUTE != 0 {
            cur |= vp::READ;
        }
        let Some(hold) = super::vmobject::with(obj, |o| o.hold.clone()).flatten() else { return Err(Errno::EINVAL) };
        if !m.remap_from(at, hold.addr + file_pos as usize, size, false).unwrap_or(false) {
            self.darwin_unimplemented("a POSIX shared memory object's mapping on a host that cannot map its pages twice".into());
            let _ = self.darwin_vm_deallocate(m, at, size);
            return Err(Errno::EINVAL);
        }
        if self.canonical(m, crate::syscalls::nr::MPROTECT, [at, size, cur, 0, 0, 0]).is_err() {
            let _ = self.darwin_vm_deallocate(m, at, size);
            return Err(Errno::EINVAL);
        }
        let attrs = super::vm::Attrs { kind: super::vm::kind::SHM, max: max as u8, inherit: super::vm::inherit::SHARE, obj, ..super::vm::Attrs::default() };
        self.dtask.vm.enter(at, at + size, attrs, file_pos);
        self.mem.lock().set_unentered(at, at + size);
        h.set_mapp_addr(at);
        Ok(at + pageoff)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RW: u32 = FREAD | FWRITE;

    fn open(n: &Names, name: &str, fmode: u32, mode: u32) -> Result<(Arc<Pshm>, bool), Errno> {
        n.open(name, fmode, mode, &Cred::of(501, 20), 7)
    }

    /// An open of an object already there by `cred`, its access checked as
    /// `shm_open` checks it (after the MAC policies').
    fn open_as(n: &Names, name: &str, fmode: u32, cred: &Cred) -> Result<(), Errno> {
        let (p, made) = n.open(name, fmode, 0, cred, 8)?;
        if !made {
            access(&p, fmode, cred)?;
        }
        Ok(())
    }

    #[test]
    fn a_name_is_made_found_and_refused_as_posix_says() {
        let n = Names::new();
        assert_eq!(open(&n, "/a", RW, 0o600).unwrap_err(), Errno::ENOENT);
        let (a, made) = open(&n, "/a", RW | O_CREAT, 0o640).unwrap();
        assert!(made);
        assert_eq!((a.mode, a.uid, a.gid), (0o640, 501, 20));
        let (b, made) = open(&n, "/a", RW | O_CREAT, 0o600).unwrap();
        assert!(!made && Arc::ptr_eq(&a, &b));
        assert_eq!(open(&n, "/a", RW | O_CREAT | O_EXCL, 0o600).unwrap_err(), Errno::EEXIST);
        // the mode is cut to the permission bits
        let (c, _) = open(&n, "/c", RW | O_CREAT, 0o170777).unwrap();
        assert_eq!(c.mode, 0o7777 & 0o170777);
    }

    #[test]
    fn truncation_of_a_sized_object_is_refused_and_one_size_is_given() {
        let n = Names::new();
        let (a, _) = open(&n, "x", RW | O_CREAT, 0o600).unwrap();
        // not sized yet: O_TRUNC is fine
        open(&n, "x", RW | O_TRUNC, 0).unwrap();
        let obj = |_| Ok(super::super::vmobject::allocate(PAGE, super::super::vmobject::Pager::Anon, None));
        a.allocate(100, obj).unwrap();
        assert_eq!(a.length(), 0x4000, "the map's page");
        assert!(a.object().is_some());
        assert_eq!(a.allocate(100, obj), Err(Errno::EINVAL));
        assert_eq!(open(&n, "x", RW | O_TRUNC, 0).unwrap_err(), Errno::EINVAL);
        let (b, _) = open(&n, "y", RW | O_CREAT, 0o600).unwrap();
        assert_eq!(b.allocate(1 << 40, |_| Err(Errno::ENOMEM)), Err(Errno::ENOMEM));
        assert!(!b.allocated());
        b.allocate(0, obj).unwrap();
        assert_eq!((b.length(), b.object()), (0, None));
    }

    #[test]
    fn unlink_removes_the_name_and_leaves_the_object() {
        let n = Names::new();
        let (a, _) = open(&n, "x", RW | O_CREAT, 0o600).unwrap();
        n.unlink("x", &Cred::of(501, 20)).unwrap();
        assert_eq!(n.unlink("x", &Cred::of(501, 20)).unwrap_err(), Errno::ENOENT);
        assert_eq!(open(&n, "x", RW, 0).unwrap_err(), Errno::ENOENT);
        // the object is still there for whoever holds it
        a.allocate(1, |_| Ok(super::super::vmobject::allocate(PAGE, super::super::vmobject::Pager::Anon, None))).unwrap();
        // a new one under the old name is another object
        let (b, made) = open(&n, "x", RW | O_CREAT, 0o600).unwrap();
        assert!(made && !Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn access_is_the_owners_the_groups_or_others() {
        let n = Names::new();
        open(&n, "x", RW | O_CREAT, 0o640).unwrap();
        // the group may read, not write; others nothing
        assert!(n.by_name.lock().unwrap().get("x").is_some());
        assert_eq!(open_as(&n, "x", FREAD, &Cred::of(600, 20)), Ok(()));
        assert_eq!(open_as(&n, "x", FWRITE, &Cred::of(600, 20)).unwrap_err(), Errno::EACCES);
        assert_eq!(open_as(&n, "x", FREAD, &Cred::of(600, 30)).unwrap_err(), Errno::EACCES);
        // root may do anything
        assert!(open_as(&n, "x", RW, &Cred::of(0, 0)).is_ok());
        // a non-owner may not unlink what he cannot write; the owner may whatever the mode
        assert_eq!(n.unlink("x", &Cred::of(600, 20)).unwrap_err(), Errno::EACCES);
        let (p, _) = open(&n, "ro", RW | O_CREAT, 0o400).unwrap();
        assert_eq!(p.uid, 501);
        n.unlink("ro", &Cred::of(501, 20)).unwrap();
    }

    #[test]
    fn the_owner_falls_through_to_the_group_and_others() {
        let n = Names::new();
        open(&n, "g", RW | O_CREAT, 0o044).unwrap();
        // no owner bits: the group's and others' let the owner read
        assert!(open_as(&n, "g", FREAD, &Cred::of(501, 20)).is_ok());
        assert_eq!(open_as(&n, "g", FWRITE, &Cred::of(501, 20)).unwrap_err(), Errno::EACCES);
        // a member of a group the bits refuse is refused, whatever others may
        open(&n, "w", RW | O_CREAT, 0o604).unwrap();
        assert_eq!(open_as(&n, "w", FREAD, &Cred::of(600, 20)).unwrap_err(), Errno::EACCES);
        assert!(open_as(&n, "w", FREAD, &Cred::of(600, 30)).is_ok());
        // supplementary groups count
        let mut c = Cred::of(600, 30);
        c.groups.push(20);
        open(&n, "s", RW | O_CREAT, 0o640).unwrap();
        assert!(open_as(&n, "s", FREAD, &c).is_ok());
    }
}
