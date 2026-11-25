//! The page's store of the Darwin system's shared region: the bytes of each
//! of the region's mappings, as one process of the page mapped them (read
//! from the cache's files, slid at the system's slide), kept once in the
//! region memory every Worker's instance imports (gex-kmem's
//! `REGION_MEMORY`), so that every other process's copy of the region is
//! made from them (`gex_kernel::darwin::shregion`'s store). Keyed by what
//! names the bytes: the cache file's UUID, the mapping's place in it and
//! length, and for a slid mapping its slide information and the slide.

use std::collections::HashMap;
use std::sync::Mutex;

struct Store {
    /// Each mapping's bytes: their offset in the region memory and length.
    kept: HashMap<Vec<u8>, (u64, u64)>,
    /// Where the next is put.
    top: u64,
}

static STORE: Mutex<Option<Store>> = Mutex::new(None);

fn store() -> std::sync::MutexGuard<'static, Option<Store>> {
    STORE.lock().unwrap_or_else(|e| e.into_inner())
}

fn key(at: gex_kmem::PAddr, len: u32) -> Option<Vec<u8>> {
    if len == 0 || len > 256 {
        return None;
    }
    let mut k = vec![0u8; len as usize];
    unsafe { gex_kmem::pull_checked(k.as_mut_ptr(), at, len) }.then_some(k)
}

/// The mapping named by the key at `key` (`key_len` bytes) of `len`
/// bytes: its offset in the store, or -1 (none kept, or kept at another
/// length).
#[no_mangle]
pub extern "C" fn k_region_find(key_at: gex_kmem::PAddr, key_len: u32, len: u64) -> i64 {
    crate::note_panics();
    let Some(k) = key(key_at, key_len) else { return -22 };
    match store().as_ref().and_then(|s| s.kept.get(&k).copied()) {
        Some((off, n)) if n == len => off as i64,
        _ => -1,
    }
}

/// Keep `len` bytes of the calling process's memory64 at `src` as the
/// mapping the key names: its offset in the store (the one kept already,
/// with nothing copied, for a mapping another process kept first), or
/// -ENOMEM when the store cannot hold it, -EINVAL for a bad request.
#[no_mangle]
pub extern "C" fn k_region_put(key_at: gex_kmem::PAddr, key_len: u32, src: gex_kmem::PAddr, len: u64) -> i64 {
    crate::note_panics();
    let Some(k) = key(key_at, key_len) else { return -22 };
    if len == 0 || !gex_kmem::in_process64(src, len) {
        return -22;
    }
    let mut g = store();
    let s = g.get_or_insert_with(|| Store { kept: HashMap::new(), top: 0 });
    if let Some(&(off, _)) = s.kept.get(&k) {
        return off as i64;
    }
    // At a page's start, so a mapping's copy is a run of whole pages.
    let off = s.top.next_multiple_of(16384);
    let Some(end) = off.checked_add(len) else { return -12 };
    let have = gex_kmem::region_pages() << 16;
    if end > have && !gex_kmem::region_grow((end - have).div_ceil(65536)) {
        return -12;
    }
    if !gex_kmem::region_from_process64(off, src, len) {
        return -22;
    }
    s.top = end;
    s.kept.insert(k, (off, len));
    off as i64
}

/// `len` bytes of the store at `off` into the calling process's memory64
/// at `dst`: 0, or -EINVAL for a range outside either.
#[no_mangle]
pub extern "C" fn k_region_get(off: u64, dst: gex_kmem::PAddr, len: u64) -> i32 {
    crate::note_panics();
    if gex_kmem::region_to_process64(dst, off, len) { 0 } else { -22 }
}
