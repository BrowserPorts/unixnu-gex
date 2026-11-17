//! A file's pages as every mapping of it holds them: the vnode pager's
//! object and the unified buffer cache (`ubc_subr.c`, `vnode_pager.c`,
//! `cluster_pagein`, `vm_map_msync`, xnu-10063.141.1).
//!
//! gex's files are the host's, read and written through the host's own
//! buffer cache, and a mapping of one, in any task, private or shared, is
//! the host's mapping of the host's file over the task's pages: the host's
//! object for the file is then the one object that every mapping, every
//! `read` and every `write` of the file meet in, as the vnode object is on
//! the device. A store through a shared mapping is the file's at once,
//! seen through every other mapping and by `read`; a private mapping's
//! pages are the file's until it writes one. The host's `vm_map_msync`
//! writes a mapping's pages back or drops them as the device's does, and
//! what nobody synced the host's pageout writes back, which the guest
//! cannot tell from the device's buffer cache keeping it. A shared mapping
//! of a file open only for reading is the host's private mapping of it:
//! the mapping can never be written, so it shows the file's pages as they
//! are, the same as a shared one, with pages the host can still copy.
//!
//! What the host's object cannot be is the device's answer past the file's
//! end. There the vnode pager has no page (`cluster_pagein` aborts the upl
//! with an error): the access is KERN_MEMORY_ERROR, SIGBUS, and a copy
//! from or to the page fails. The host would fault in its own process
//! instead, so no page past the end is the host file's: such pages are
//! absent from the task's map ([`crate::mem::MemoryMap::set_absent`]) over
//! the host's anonymous memory; an access that finds the file grown since
//! is given the file's page, as the device's next fault is; and before the
//! file shrinks, every mapping's pages past the new end, in every task,
//! are taken away (`ubc_setsize`'s flush, which disconnects the pages from
//! every pmap), the private mappings' copies made by a write kept. Which
//! pages of a private mapping are its copies is the map's to say, as the
//! device's pmap enters a file's page read-only until a write copies it
//! ([`crate::mem::MemoryMap::set_copy_pending`]): the host may have copied
//! a page for reasons of its own (a fork's remap), which the guest cannot
//! tell from the file's page.

use super::vmobject;
use crate::file::OpenFile;
use crate::proc::ProcTable;
use crate::GuestMem;
use std::sync::{Arc, Mutex, OnceLock, Weak};

/// The map's page.
const PAGE: u64 = super::mach::PAGE_MASK + 1;

fn round(v: u64) -> u64 {
    v.saturating_add(PAGE - 1) & !(PAGE - 1)
}

/// The host's file a vnode's object is: its device, number and birth.
pub type FileKey = (u64, u64, u64);

/// A file's vnode, as its pager's object knows it.
#[derive(Debug)]
pub struct Vnode {
    pub key: FileKey,
    /// The file as a mapping of it opened it: its size, and the host's
    /// descriptor its pages are mapped from (one open for writing once a
    /// shared mapping that may write is made).
    file: Mutex<Arc<OpenFile>>,
    /// The size a change in progress gives the file, held across the
    /// change and across a fault's mapping of a page past the end.
    resizing: Mutex<Option<u64>>,
}

impl Vnode {
    fn new(key: FileKey, file: &Arc<OpenFile>) -> Vnode {
        Vnode { key, file: Mutex::new(Arc::clone(file)), resizing: Mutex::new(None) }
    }

    fn file(&self) -> Arc<OpenFile> {
        Arc::clone(&self.file.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// The file's size as the pager sees it: the change in progress's,
    /// where it is smaller.
    fn size(&self, resizing: Option<u64>) -> u64 {
        let now = self.file().handle.metadata().map_or(0, |m| m.size);
        resizing.map_or(now, |r| r.min(now))
    }

    /// The host's descriptor of the file, where it has one.
    pub fn host_fd(&self) -> Option<i32> {
        self.file().handle.host_fd()
    }

    /// The file's size as the pager sees it now.
    pub fn pager_size(&self) -> u64 {
        let resizing = *self.resizing.lock().unwrap_or_else(|e| e.into_inner());
        self.size(resizing)
    }

    /// Map `[at, at + len)` of guest memory `m` from the file's `offset`:
    /// the file's own pages where `shared` and the open can write, else a
    /// copy made on write. Whether the host did.
    fn map(&self, m: &mut GuestMem<'_>, at: u64, len: u64, offset: u64, shared: bool) -> bool {
        let f = self.file();
        let Some(fd) = f.handle.host_fd() else { return false };
        if shared && f.writable {
            m.map_file_shared(at, len, fd, offset).unwrap_or(false)
        } else {
            m.map_file(at, len, fd, offset).unwrap_or(false)
        }
    }
}

static PROCS: OnceLock<Mutex<Weak<ProcTable>>> = OnceLock::new();

/// The process table [`note_procs`] noted, while it is.
fn procs() -> Option<Arc<ProcTable>> {
    PROCS.get().and_then(|w| w.lock().unwrap_or_else(|e| e.into_inner()).upgrade())
}

/// The process table whose tasks map files: the one a change of a file's
/// size looks through for its mappings.
pub fn note_procs(p: &Arc<ProcTable>) {
    let cell = PROCS.get_or_init(|| Mutex::new(Weak::new()));
    let mut w = cell.lock().unwrap_or_else(|e| e.into_inner());
    if w.upgrade().is_none() {
        *w = Arc::downgrade(p);
        crate::vfs::set_size_watch(will_resize, did_resize);
    }
}

/// The vnode object of `file`, a reference to it its caller holds: the
/// one every mapping of the same host file names. None for a file whose
/// host file is not known.
pub fn object_of(file: &Arc<OpenFile>) -> Option<u64> {
    let key = file.handle.host_id()?;
    let id = vmobject::of_file(key, || Arc::new(Vnode::new(key, file)));
    // A shared mapping that may write maps from an open that can.
    if file.writable {
        if let Some(v) = vnode(id) {
            let mut f = v.file.lock().unwrap_or_else(|e| e.into_inner());
            if !f.writable && f.handle.host_fd().is_some() {
                *f = Arc::clone(file);
            }
        }
    }
    Some(id)
}

/// Object `id`'s vnode, if it is a file's.
pub fn vnode(id: u64) -> Option<Arc<Vnode>> {
    vmobject::with(id, |o| match &o.pager {
        vmobject::Pager::Vnode(v) => Some(Arc::clone(v)),
        _ => None,
    })
    .flatten()
}

/// The pages of `[s, e)` (an entry's piece at object offset `off`) past
/// the file's end `size`: where they start, if any are.
pub fn past_end(s: u64, e: u64, off: u64, size: u64) -> Option<u64> {
    let cut = round(size);
    let first = if off >= cut { s } else { s.saturating_add(cut - off) };
    (first < e).then_some(first)
}

/// `vm_fault` of page `page_at` of a mapping `[s, e)` of vnode object
/// `obj` at object offset `off` (`shared`: the file's own pages), absent
/// in memory `m` of map `mm`: the file's page if the file now has it,
/// with the rest of the mapping's pages it now has from there, mapped and
/// waiting to be entered, the faulting one entered. False where the file
/// still has none (the pager's error, KERN_MEMORY_ERROR).
pub fn fault(m: &mut GuestMem<'_>, mm: &crate::mem::Mm, obj: u64, s: u64, e: u64, off: u64, shared: bool, page_at: u64) -> bool {
    let Some(v) = vnode(obj) else { return false };
    let resizing = v.resizing.lock().unwrap_or_else(|e| e.into_inner());
    let size = v.size(*resizing);
    let first = past_end(s, e, off, size).unwrap_or(e);
    if page_at >= first {
        return false;
    }
    let at = page_at & !(PAGE - 1);
    if !v.map(m, at, first - at, off + (at - s), shared) {
        return false;
    }
    let mut mm = mm.lock();
    mm.clear_absent(at, first);
    mm.set_unentered(at, first);
    if !shared {
        mm.set_copy_pending(at, first);
    }
    mm.enter_page(page_at >> gex_abi::PERM_PAGE_SHIFT);
    drop(resizing);
    true
}

/// What reaches one task's map from outside it: its entries, its memory
/// map and memory, and its pmap's record.
struct Task {
    entries: Arc<crate::sync::Mutex<super::vm::Map>>,
    peer: Arc<crate::proc::PeerVm>,
    meter: Arc<super::rusage::Shared>,
}

/// The tasks that may map something: each live Darwin process's map.
fn tasks(procs: &ProcTable) -> Vec<Task> {
    let mut out = Vec::new();
    for (pid, _, _, dead) in procs.listing() {
        if dead {
            continue;
        }
        let Some((r, _)) = procs.darwin(pid) else { continue };
        let Ok(p) = r.downcast::<super::procinfo::Public>() else { continue };
        let (Some(entries), Ok(peer)) = (p.vm.clone(), procs.vm(pid)) else { continue };
        out.push(Task { entries, peer, meter: Arc::clone(&p.rusage) });
    }
    out
}

/// The host file `key` is about to become `new` bytes long
/// (`ubc_setsize`, before the filesystem's truncation): the pages past its
/// new end leave every mapping of it, in every task, and every named
/// entry's hold of them.
pub fn will_resize(key: FileKey, new: u64) {
    // The object's resident pages past it go too, the dirty ones a debit
    // of the truncating thread's task's logical writes.
    super::pagecache::charge(super::pagecache::truncate(key, new));
    let Some(id) = vmobject::by_file(key) else { return };
    let Some(v) = vnode(id) else { return };
    let mut resizing = v.resizing.lock().unwrap_or_else(|e| e.into_inner());
    let old = v.size(None);
    *resizing = Some(new);
    if round(new) >= round(old) {
        return;
    }
    let Some(procs) = procs() else { return };
    for t in tasks(&procs) {
        cut(&t, id, new);
    }
    super::vmentry::hold_pages_past(id, new);
}

/// The host file `key` is `new` bytes long now: the change is done, and
/// what mappings of it had absent that it now has is the file's again.
pub fn did_resize(key: FileKey, new: u64) {
    let Some(id) = vmobject::by_file(key) else { return };
    let Some(v) = vnode(id) else { return };
    let mut resizing = v.resizing.lock().unwrap_or_else(|e| e.into_inner());
    *resizing = None;
    let size = v.size(None).max(new);
    let Some(procs) = procs() else { return };
    for t in tasks(&procs) {
        grow(&t, &v, id, size);
    }
}

/// `ubc_setsize`'s flush in task `t`: its mappings' pages of object `id`
/// past `new` taken from its map, the host's file pages there replaced by
/// its anonymous memory, a private mapping's copies kept.
fn cut(t: &Task, id: u64, new: u64) {
    t.peer.mem.with_guest(&mut |g| {
        let mut mm = t.peer.mm.lock();
        let ents = t.entries.lock();
        let mut gone: Vec<(u64, u64)> = Vec::new();
        for (s, e, a, off) in ents.of_object(id) {
            let Some(first) = past_end(s, e, off, new) else { continue };
            let shared = a.kind == super::vm::kind::FILE_SHARED && !a.cow;
            if shared {
                if g.advise(first, e - first, crate::HostAdvice::Discard).unwrap_or(false) {
                    gone.push((first, e));
                }
                continue;
            }
            // A private mapping: only the pages still the file's (not
            // written since, so not the mapping's own copies) go.
            let mut at = first;
            while at < e {
                if mm.is_copy_pending(at >> gex_abi::PERM_PAGE_SHIFT) && g.advise(at, PAGE, crate::HostAdvice::Discard).unwrap_or(false) {
                    gone.push((at, at + PAGE));
                }
                at += PAGE;
            }
        }
        drop(ents);
        for &(s, e) in &gone {
            mm.set_absent(s, e);
        }
        for (page, bytes) in mm.take_perm_writes() {
            let _ = g.kernel().write(gex_abi::PERM_TABLE64 + page, &bytes);
        }
        drop(mm);
        // pmap_disconnect of each page: the pmap enters them no more.
        let mut pm = t.meter.meter.lock();
        for (s, e) in gone {
            pm.disconnect(s, e);
        }
    });
}

/// Task `t`'s absent pages of object `id` the file has again at `size`:
/// mapped from it, waiting to be entered.
fn grow(t: &Task, v: &Vnode, id: u64, size: u64) {
    t.peer.mem.with_guest(&mut |g| {
        let mut mm = t.peer.mm.lock();
        let ents = t.entries.lock();
        let absent = mm.absent_ranges();
        if absent.is_empty() {
            return;
        }
        for (s, e, a, off) in ents.of_object(id) {
            let have = past_end(s, e, off, size).unwrap_or(e);
            let shared = a.kind == super::vm::kind::FILE_SHARED && !a.cow;
            for &(as_, ae) in &absent {
                let (lo, hi) = (as_.max(s), ae.min(have));
                if lo < hi && v.map(g, lo, hi - lo, off + (lo - s), shared) {
                    mm.clear_absent(lo, hi);
                    mm.set_unentered(lo, hi);
                    if !shared {
                        mm.set_copy_pending(lo, hi);
                    }
                }
            }
        }
        drop(ents);
        for (page, bytes) in mm.take_perm_writes() {
            let _ = g.kernel().write(gex_abi::PERM_TABLE64 + page, &bytes);
        }
    });
}
