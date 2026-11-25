//! The Darwin system's disk0 in the page (`gex_kernel::darwin::pagedisk`):
//! one device every process's disk nodes reach, its image read by ranges
//! from where the page's server has it (`env.lazy_fetch`, the reading
//! Worker's synchronous ranged request), what the system writes kept in
//! this memory over it. The page names the image at boot
//! ([`k_disk0_set`]); each Darwin process's shim installs a medium over
//! the calls here (hosts/browser darwin.rs), as gexc installs the host
//! file GEX_DARWIN_DISK0 names.

use std::sync::OnceLock;

use gex_kernel::darwin::pagedisk::Device;

static DISK0: OnceLock<Device> = OnceLock::new();

/// The image of the system's disk0: at `url` (a URL the page's Workers
/// read by ranges), `size` bytes, with what its build reported missing
/// (its `.missing`, one step a line). 0; -EINVAL for an empty one; -EBUSY
/// once one is set.
#[no_mangle]
pub extern "C" fn k_disk0_set(url: gex_kmem::PAddr, url_len: u32, size: u64, missing: gex_kmem::PAddr, missing_len: u32) -> i32 {
    crate::note_panics();
    if size == 0 || url_len == 0 {
        return -22;
    }
    // Read as a device's image (`#device`): by the reading Worker alone,
    // not as a lazy file of the root (hosts/browser js/lazy-fetch.mjs).
    let url = format!("{}#device", crate::path_of_raw(url, url_len));
    let missing = crate::path_of_raw(missing, missing_len);
    match DISK0.set(Device::new(url, size, missing, crate::fetch_lazy)) {
        Ok(()) => 0,
        Err(_) => -16,
    }
}

/// The image's size in bytes; 0 when the page gave none.
#[no_mangle]
pub extern "C" fn k_disk0_size() -> u64 {
    DISK0.get().map_or(0, Device::size)
}

/// What the image's build reported missing, into `out` (at most
/// `out_len` bytes): its whole length.
#[no_mangle]
pub extern "C" fn k_disk0_missing(out: gex_kmem::PAddr, out_len: u32) -> i64 {
    let Some(d) = DISK0.get() else { return -6 };
    let m = d.missing().as_bytes();
    let n = m.len().min(out_len as usize);
    if n > 0 && !unsafe { gex_kmem::push_checked(out, m.as_ptr(), n as u32) } {
        return -14;
    }
    m.len() as i64
}

/// `len` bytes of disk0 at `off` into `dst` in the caller's memory: 0, or
/// -ENXIO without an image, -EIO when they cannot be read (past its end,
/// or the image's read failed: the reading Worker's console says so,
/// `[lazy]`).
#[no_mangle]
pub extern "C" fn k_disk0_read(off: u64, dst: gex_kmem::PAddr, len: u32) -> i32 {
    crate::note_panics();
    let Some(d) = DISK0.get() else { return -6 };
    let mut b = vec![0u8; len as usize];
    if d.read_at(off, &mut b).is_err() {
        return -5;
    }
    if len > 0 && !unsafe { gex_kmem::push_checked(dst, b.as_ptr(), len) } {
        return -14;
    }
    0
}

/// `len` bytes from `src` in the caller's memory written to disk0 at
/// `off`: 0, or -ENXIO without an image, -EIO when past its end or the
/// image's bytes a partial block keeps cannot be read.
#[no_mangle]
pub extern "C" fn k_disk0_write(off: u64, src: gex_kmem::PAddr, len: u32) -> i32 {
    crate::note_panics();
    let Some(d) = DISK0.get() else { return -6 };
    let mut b = vec![0u8; len as usize];
    if len > 0 && !unsafe { gex_kmem::pull_checked(b.as_mut_ptr(), src, len) } {
        return -14;
    }
    if d.write_at(off, &b).is_err() {
        return -5;
    }
    0
}
