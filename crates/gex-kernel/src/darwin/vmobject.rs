//! VM objects by identity: what a map entry or a named entry maps, and the
//! references each holds to it (`vm_object.c`, xnu-10063.141.1).
//!
//! An entry of a task's map ([`super::vm::Entries`]) names its object by a
//! number (`VME_OBJECT`), 0 for anonymous memory that is the task's own
//! (an object `vm_fault` would make on the first touch, which no one else
//! can name). Every entry that names one, and every named entry, holds a
//! reference (`vm_object_reference`): clipping an entry takes another for
//! its second half, removing one gives its reference back
//! (`vm_object_deallocate`), and the last reference's going ends the
//! object. Pages the host holds for an object apart from every task
//! ([`Hold`]) go with it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

/// Pages the host holds apart from every task's memory
/// ([`crate::host_hold`]), given back when the last holder lets go.
#[derive(Debug)]
pub struct Hold {
    pub addr: usize,
    pub len: u64,
}

impl Drop for Hold {
    fn drop(&mut self) {
        crate::host_unhold(self.addr, self.len as usize);
    }
}

/// What backs an object's pages.
#[derive(Clone, Debug)]
pub enum Pager {
    /// None: anonymous memory, internal (`vm_object_allocate`).
    Anon,
    /// A file's pages: its vnode's pager (`vnode_pager_setup`), the host's
    /// file ([`super::ubc::Vnode`]).
    Vnode(Arc<super::ubc::Vnode>),
}

/// A `vm_object`.
#[derive(Debug)]
pub struct Object {
    /// `ref_count`.
    refs: u64,
    /// `vo_size`.
    pub size: u64,
    pub pager: Pager,
    /// The pages the host holds for it, where no task's memory does
    /// (a named entry's, a POSIX shared memory object's).
    pub hold: Option<Arc<Hold>>,
}

impl Object {
    /// `internal`: anonymous memory, no file's.
    pub fn internal(&self) -> bool {
        matches!(self.pager, Pager::Anon)
    }
}

#[derive(Debug, Default)]
struct Table {
    objects: HashMap<u64, Object>,
    /// The vnode objects by their host file (`ubc_info`'s one object).
    files: HashMap<super::ubc::FileKey, u64>,
    next: u64,
}

fn table() -> &'static Mutex<Table> {
    static T: OnceLock<Mutex<Table>> = OnceLock::new();
    T.get_or_init(|| Mutex::new(Table { objects: HashMap::new(), files: HashMap::new(), next: 1 }))
}

fn lock() -> std::sync::MutexGuard<'static, Table> {
    table().lock().unwrap_or_else(|e| e.into_inner())
}

/// A new object (`vm_object_allocate`) and the one reference its maker
/// holds.
pub fn allocate(size: u64, pager: Pager, hold: Option<Arc<Hold>>) -> u64 {
    let mut t = lock();
    let id = t.next;
    t.next += 1;
    t.objects.insert(id, Object { refs: 1, size, pager, hold });
    id
}

/// The vnode object of host file `key` (`ubc_getobject`), made with the
/// vnode `make` gives when the file has none, and a reference to it its
/// caller holds.
pub fn of_file(key: super::ubc::FileKey, make: impl FnOnce() -> Arc<super::ubc::Vnode>) -> u64 {
    let mut t = lock();
    if let Some(&id) = t.files.get(&key) {
        if let Some(o) = t.objects.get_mut(&id) {
            o.refs += 1;
            return id;
        }
    }
    let id = t.next;
    t.next += 1;
    t.objects.insert(id, Object { refs: 1, size: 0, pager: Pager::Vnode(make()), hold: None });
    t.files.insert(key, id);
    id
}

/// The vnode object of host file `key`, while some mapping names it.
pub fn by_file(key: super::ubc::FileKey) -> Option<u64> {
    lock().files.get(&key).copied()
}

/// `vm_object_reference`: one more holder of object `id` (none for 0, the
/// task's own anonymous memory).
pub fn reference(id: u64) {
    if id == 0 {
        return;
    }
    let mut t = lock();
    let o = t.objects.get_mut(&id).unwrap_or_else(|| panic!("vm_object_reference of object {id}, which is gone"));
    o.refs += 1;
}

/// `vm_object_deallocate`: a holder of object `id` lets go; the last
/// takes the object with it, and what the host held of its pages.
pub fn release(id: u64) {
    if id == 0 {
        return;
    }
    let gone = {
        let mut t = lock();
        let o = t.objects.get_mut(&id).unwrap_or_else(|| panic!("vm_object_deallocate of object {id}, which is gone"));
        o.refs -= 1;
        if o.refs == 0 {
            let o = t.objects.remove(&id);
            if let Some(Object { pager: Pager::Vnode(v), .. }) = &o {
                t.files.remove(&v.key);
            }
            o
        } else {
            None
        }
    };
    // The hold is given back outside the table's lock.
    drop(gone);
}

/// `f` of object `id`, while it is.
pub fn with<R>(id: u64, f: impl FnOnce(&mut Object) -> R) -> Option<R> {
    if id == 0 {
        return None;
    }
    lock().objects.get_mut(&id).map(f)
}

/// Object `id`'s references (`ref_count`).
pub fn refs(id: u64) -> u64 {
    with(id, |o| o.refs).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_last_reference_ends_the_object() {
        let id = allocate(0x4000, Pager::Anon, None);
        assert_eq!(refs(id), 1);
        reference(id);
        assert_eq!(refs(id), 2);
        release(id);
        assert!(with(id, |o| o.internal()).unwrap());
        release(id);
        assert_eq!(refs(id), 0);
        assert!(with(id, |_| ()).is_none());
        // The task's own anonymous memory is no object.
        reference(0);
        release(0);
    }
}
