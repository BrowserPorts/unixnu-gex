//! The host's `madvise` for the guest's pages, for gex-kernel, which forbids
//! `unsafe` and so takes it as a hook (`set_host_vm`). The guest's memory is
//! the host's private anonymous memory, so the host's own advice does to it
//! what the guest asked for.

use gex_kernel::HostAdvice;

pub fn install() {
    gex_kernel::set_host_vm(advise);
    gex_kernel::set_host_map_file(map_file);
    gex_kernel::set_host_pages(pages);
    #[cfg(target_os = "macos")]
    gex_kernel::set_host_remap(remap);
    #[cfg(target_os = "macos")]
    gex_kernel::set_host_hold(hold, unhold);
    #[cfg(target_os = "macos")]
    gex_kernel::set_host_map_shared(map_shared);
    #[cfg(target_os = "macos")]
    gex_kernel::set_host_msync(msync);
    #[cfg(target_os = "macos")]
    gex_kernel::set_host_purgeable(hold_purgeable, purge);
}

/// Fresh purgeable zero pages anywhere in the host's address space
/// (`mach_vm_allocate` with VM_FLAGS_PURGABLE): nonvolatile, so the host
/// never empties them on its own.
#[cfg(target_os = "macos")]
fn hold_purgeable(len: usize) -> Option<usize> {
    const VM_FLAGS_ANYWHERE: libc::c_int = 1;
    const VM_FLAGS_PURGABLE: libc::c_int = 2;
    if len == 0 || len % page() != 0 {
        return None;
    }
    let mut at = 0u64;
    // SAFETY: the kernel picks a free range and maps it; nothing else is
    // touched.
    let kr = unsafe { mach_vm_allocate(mach_task_self_, &mut at, len as u64, VM_FLAGS_ANYWHERE | VM_FLAGS_PURGABLE) };
    (kr == 0).then_some(at as usize)
}

/// [`hold_purgeable`]'s pages emptied: the host's object made empty, then
/// nonvolatile again.
#[cfg(target_os = "macos")]
fn purge(at: usize, _len: usize) -> bool {
    extern "C" {
        fn mach_vm_purgable_control(target: libc::c_uint, address: u64, control: libc::c_int, state: *mut libc::c_int) -> libc::c_int;
    }
    const SET_STATE: libc::c_int = 0;
    let (mut empty, mut nonvolatile) = (2, 0);
    // SAFETY: `at` is a purgeable range `hold_purgeable` allocated.
    unsafe { mach_vm_purgable_control(mach_task_self_, at as u64, SET_STATE, &mut empty) == 0 && mach_vm_purgable_control(mach_task_self_, at as u64, SET_STATE, &mut nonvolatile) == 0 }
}

/// A shared mapping of `fd` (open for writing) from `offset` over the
/// guest's pages at `at`: the host's object for the file, which every other
/// mapping of it and the host's reads and writes of it share, readable and
/// writable as the guest's memory is. None lies wholly past the file's end
/// (the caller maps only what the file holds).
#[cfg(target_os = "macos")]
fn map_shared(at: usize, len: usize, fd: i32, offset: u64) -> bool {
    let page = page();
    if at % page != 0 || len % page != 0 || len == 0 || offset % page as u64 != 0 {
        return false;
    }
    let Ok(off) = libc::off_t::try_from(offset) else { return false };
    // SAFETY: `at..at + len` is guest memory, mapped for the life of the
    // process; the file's pages replace what the guest mapped there.
    let p = unsafe { libc::mmap(at as *mut libc::c_void, len, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_FIXED | libc::MAP_SHARED, fd, off) };
    p as usize == at
}

/// `mach_vm_msync` of the host's mapping at `at`: the host's own
/// `vm_map_msync`, of the same objects the guest's mapping names.
#[cfg(target_os = "macos")]
fn msync(at: usize, len: usize, flags: u32) -> bool {
    extern "C" {
        fn mach_vm_msync(target: libc::c_uint, address: u64, size: u64, flags: libc::c_uint) -> libc::c_int;
    }
    // SAFETY: the range is guest memory; msync only writes back or drops
    // the pages of the objects mapped there.
    unsafe { mach_vm_msync(mach_task_self_, at as u64, len as u64, flags) == 0 }
}

#[cfg(target_os = "macos")]
extern "C" {
    fn mach_vm_allocate(target: libc::c_uint, address: *mut u64, size: u64, flags: libc::c_int) -> libc::c_int;
    fn mach_vm_deallocate(target: libc::c_uint, address: u64, size: u64) -> libc::c_int;
}

/// Fresh zero pages anywhere in the host's address space, outside every
/// guest memory (`mach_vm_allocate` with VM_FLAGS_ANYWHERE).
#[cfg(target_os = "macos")]
fn hold(len: usize) -> Option<usize> {
    const VM_FLAGS_ANYWHERE: libc::c_int = 1;
    if len == 0 || len % page() != 0 {
        return None;
    }
    let mut at = 0u64;
    // SAFETY: the kernel picks a free range and maps it; nothing else is
    // touched.
    let kr = unsafe { mach_vm_allocate(mach_task_self_, &mut at, len as u64, VM_FLAGS_ANYWHERE) };
    (kr == 0).then_some(at as usize)
}

/// What [`hold`] gave, given back.
#[cfg(target_os = "macos")]
fn unhold(at: usize, len: usize) {
    // SAFETY: `at..at + len` is a range `hold` allocated, which no guest
    // memory maps.
    unsafe {
        mach_vm_deallocate(mach_task_self_, at as u64, len as u64);
    }
}

/// `mach_vm_remap` of the host's own pages at `src` over `dst`, in place of
/// what was there: shared, or (`copy`) a copy made on write, as the host's
/// VM makes either (`vm_map_remap`).
#[cfg(target_os = "macos")]
fn remap(dst: usize, src: usize, len: usize, copy: bool) -> bool {
    extern "C" {
        fn mach_vm_remap(target: libc::c_uint, address: *mut u64, size: u64, mask: u64, flags: libc::c_int, src_task: libc::c_uint, src_address: u64, copy: libc::c_int, cur: *mut libc::c_int, max: *mut libc::c_int, inheritance: libc::c_uint) -> libc::c_int;
    }
    const VM_FLAGS_FIXED: libc::c_int = 0;
    const VM_FLAGS_OVERWRITE: libc::c_int = 0x4000;
    const VM_INHERIT_DEFAULT: libc::c_uint = 1;
    let page = page();
    if dst % page != 0 || src % page != 0 || len % page != 0 || len == 0 {
        return false;
    }
    let mut at = dst as u64;
    let (mut cur, mut max) = (0, 0);
    // SAFETY: both ranges are guest memory, which the host maps readable
    // and writable for the life of the process; the new mapping takes the
    // place of `dst`'s with the same protection.
    let kr = unsafe { mach_vm_remap(mach_task_self_, &mut at, len as u64, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, mach_task_self_, src as u64, libc::c_int::from(copy), &mut cur, &mut max, VM_INHERIT_DEFAULT) };
    kr == 0 && at == dst as u64
}

#[cfg(target_os = "macos")]
extern "C" {
    static mach_task_self_: libc::c_uint;
    fn mach_vm_page_range_query(target: libc::c_uint, address: u64, size: u64, dispositions: u64, count: *mut u64) -> libc::c_int;
}

/// Each page's state by `mach_vm_page_range_query`, the host's own VM's
/// view of its pages (`VM_PAGE_QUERY_PAGE_*`).
#[cfg(target_os = "macos")]
fn pages(at: usize, len: usize, page: usize, out: &mut [u8]) -> bool {
    use gex_kernel::page_state as ps;
    const PRESENT: i32 = 0x1;
    const PAGED_OUT: i32 = 0x10;
    const EXTERNAL: i32 = 0x80;
    const REUSABLE: i32 = 0x800;
    if page != self::page() || at % page != 0 || len % page != 0 || out.len() < len / page {
        return false;
    }
    let n = len / page;
    let mut d = vec![0i32; n];
    let mut count = n as u64;
    // SAFETY: `d` holds `count` dispositions; the range is guest memory.
    let kr = unsafe { mach_vm_page_range_query(mach_task_self_, at as u64, len as u64, d.as_mut_ptr() as u64, &mut count) };
    if kr != 0 || count as usize != n {
        return false;
    }
    for (o, &v) in out.iter_mut().zip(&d) {
        *o = [(PRESENT, ps::PRESENT), (PAGED_OUT, ps::PAGED_OUT), (EXTERNAL, ps::EXTERNAL), (REUSABLE, ps::REUSABLE)].iter().filter(|(b, _)| v & b != 0).fold(0, |a, (_, s)| a | s);
    }
    true
}

/// No per-page query of the host's VM this side of macOS.
#[cfg(not(target_os = "macos"))]
fn pages(_at: usize, _len: usize, _page: usize, _out: &mut [u8]) -> bool {
    false
}

/// The host's page size.
fn page() -> usize {
    static PAGE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    // SAFETY: sysconf reads a constant.
    *PAGE.get_or_init(|| unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize)
}

/// A private mapping of `fd` from `offset` over the guest's pages at `at`.
/// The pages are the file's until written, then the host's copy; none lies
/// wholly past the file's end (the caller maps only what the file holds).
fn map_file(at: usize, len: usize, fd: i32, offset: u64) -> bool {
    let page = page();
    if at % page != 0 || len % page != 0 || len == 0 || offset % page as u64 != 0 {
        return false;
    }
    let Ok(off) = libc::off_t::try_from(offset) else { return false };
    // SAFETY: `at..at + len` is guest memory, mapped for the life of the
    // process; the file's pages replace what the guest just mapped there,
    // readable and writable as the guest's memory is.
    let p = unsafe { libc::mmap(at as *mut libc::c_void, len, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_FIXED | libc::MAP_PRIVATE, fd, off) };
    p as usize == at
}

/// What the host does for a piece of advice.
enum Host {
    Madvise(libc::c_int),
    /// Fresh zero pages mapped over the old.
    Remap,
    /// Nothing needs doing.
    Done,
    /// The host cannot.
    Cannot,
}

/// Darwin's `MADV_*`: the same VM as the guest's.
#[cfg(target_os = "macos")]
fn advice(a: HostAdvice) -> Host {
    Host::Madvise(match a {
        HostAdvice::Free => 5,
        HostAdvice::Reusable => 7,
        HostAdvice::Reuse => 8,
        HostAdvice::Deactivate => 4,
        HostAdvice::WillNeed => 3,
        HostAdvice::Zero => 11,
        HostAdvice::Discard => return Host::Remap,
    })
}

/// Linux's nearest: `MADV_FREE` frees lazily (a page written again is
/// kept) and `MADV_COLD` deactivates; a page is the owner's without a
/// reuse; zeroing is left to the kernel's own write.
#[cfg(not(target_os = "macos"))]
fn advice(a: HostAdvice) -> Host {
    match a {
        HostAdvice::Free | HostAdvice::Reusable => Host::Madvise(8),
        HostAdvice::Deactivate => Host::Madvise(20),
        HostAdvice::WillNeed => Host::Madvise(3),
        HostAdvice::Reuse => Host::Done,
        HostAdvice::Zero => Host::Cannot,
        HostAdvice::Discard => Host::Remap,
    }
}

fn advise(at: usize, len: usize, a: HostAdvice) -> bool {
    // The host rounds a range out to its own pages, which may be larger
    // than the guest's: a range that is not whole host pages is refused.
    let page = page();
    if at % page != 0 || len % page != 0 || len == 0 {
        return false;
    }
    match advice(a) {
        Host::Done => true,
        Host::Cannot => false,
        // SAFETY: `at..at + len` is guest memory, which the host maps for
        // the life of the process; advice changes only what its pages hold
        // (each as before or zero, as the guest asked) and how they are kept.
        Host::Madvise(adv) => unsafe { libc::madvise(at as *mut libc::c_void, len, adv) == 0 },
        // SAFETY: as above; the new pages are private, anonymous and
        // readable and writable, as the guest's memory is mapped.
        Host::Remap => unsafe {
            let p = libc::mmap(at as *mut libc::c_void, len, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANON, -1, 0);
            p as usize == at
        },
    }
}
