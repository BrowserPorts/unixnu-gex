//! Corpses (`osfmk/corpses/corpse.c`, `osfmk/kern/task.c`,
//! `bsd/kern/kern_exit.c`): a crashed task kept after its process's end
//! for its EXC_CORPSE_NOTIFY handler to look at, its threads held for
//! inspection and its crash information (a kcdata buffer,
//! `populate_corpse_crashinfo`) kept with it until the last send right to
//! its port goes.
//!
//! A crash no EXC_CRASH handler took makes the crashing task itself the
//! corpse (`task_mark_corpse`, from `proc_prepareexit`): its IPC space ends
//! there, its BSD exit goes on (the parent sees it end), and its last
//! thread, once `proc_exit` is done, gives it new task and thread ports and
//! sends the notification (`task_deliver_crash_notification`). Here the
//! task's kernel outlives its process for that: its thread calls deliver
//! the notification and serve the handler's requests to the corpse's ports
//! until the corpse's port has no senders (`task_port_no_senders`), when
//! the task is terminated.
//!
//! Corpses in flight are counted (`inflight_corpses`): at most
//! `TOTAL_CORPSES_ALLOWED`, and of them at most `TOTAL_USER_FAULTS_ALLOWED`
//! for simulated user faults.

use super::kcdata::Kcdata;
use std::sync::atomic::{AtomicU32, Ordering};

/// `CORPSEINFO_ALLOCATION_SIZE`: this kernel has no `CONFIG_EXCLAVES` (its
/// `task_map_corpse_info_64` maps 0x4000 bytes).
pub const CORPSEINFO_ALLOCATION_SIZE: usize = 0x4000;
/// `TOTAL_CORPSES_ALLOWED` (not a watch), `TOTAL_USER_FAULTS_ALLOWED`: the
/// 21H461 `task_crashinfo_get_ref` compares the counts with 5 and 1.
pub const TOTAL_CORPSES_ALLOWED: u16 = 5;
pub const TOTAL_USER_FAULTS_ALLOWED: u16 = 1;
/// `VM_MEMORY_CORPSEINFO`: the tag of a mapped copy of a corpse's crash
/// information.
pub const VM_MEMORY_CORPSEINFO: u32 = 80;

/// `corpse_flags_t` (`kcd_user_flags`).
pub mod flags {
    pub const HAS_REF: u16 = 0x1;
    pub const USER_FAULT: u16 = 0x2;
}

/// `TASK_CRASHINFO_*` and the other item types a corpse's crash
/// information holds (`kcdata.h`).
pub mod ty {
    pub const BSDINFOWITHUNIQID: u32 = 0x802;
    pub const PID: u32 = 0x805;
    pub const PPID: u32 = 0x806;
    pub const RUSAGE_INFO: u32 = 0x808;
    pub const PROC_NAME: u32 = 0x809;
    pub const PROC_STARTTIME: u32 = 0x80B;
    pub const USERSTACK: u32 = 0x80C;
    pub const ARGSLEN: u32 = 0x80D;
    pub const EXCEPTION_CODES: u32 = 0x80E;
    pub const PROC_PATH: u32 = 0x80F;
    pub const PROC_CSFLAGS: u32 = 0x810;
    pub const UID: u32 = 0x812;
    pub const GID: u32 = 0x813;
    pub const PROC_ARGC: u32 = 0x814;
    pub const PROC_FLAGS: u32 = 0x815;
    pub const CPUTYPE: u32 = 0x816;
    pub const WORKQUEUEINFO: u32 = 0x817;
    pub const RESPONSIBLE_PID: u32 = 0x818;
    pub const DIRTY_FLAGS: u32 = 0x819;
    pub const CRASHED_THREADID: u32 = 0x81A;
    pub const COALITION_ID: u32 = 0x81B;
    pub const UDATA_PTRS: u32 = 0x81C;
    pub const MEMORY_LIMIT: u32 = 0x81D;
    pub const LEDGER_INTERNAL: u32 = 0x81E;
    pub const LEDGER_INTERNAL_COMPRESSED: u32 = 0x81F;
    pub const LEDGER_IOKIT_MAPPED: u32 = 0x820;
    pub const LEDGER_ALTERNATE_ACCOUNTING: u32 = 0x821;
    pub const LEDGER_ALTERNATE_ACCOUNTING_COMPRESSED: u32 = 0x822;
    pub const LEDGER_PURGEABLE_NONVOLATILE: u32 = 0x823;
    pub const LEDGER_PURGEABLE_NONVOLATILE_COMPRESSED: u32 = 0x824;
    pub const LEDGER_PAGE_TABLE: u32 = 0x825;
    pub const LEDGER_PHYS_FOOTPRINT: u32 = 0x826;
    pub const LEDGER_PHYS_FOOTPRINT_LIFETIME_MAX: u32 = 0x827;
    pub const LEDGER_NETWORK_NONVOLATILE: u32 = 0x828;
    pub const LEDGER_NETWORK_NONVOLATILE_COMPRESSED: u32 = 0x829;
    pub const LEDGER_WIRED_MEM: u32 = 0x82A;
    pub const PROC_PERSONA_ID: u32 = 0x82B;
    pub const MEMORY_LIMIT_INCREASE: u32 = 0x82C;
    pub const LEDGER_TAGGED_FOOTPRINT: u32 = 0x82D;
    pub const LEDGER_TAGGED_FOOTPRINT_COMPRESSED: u32 = 0x82E;
    pub const LEDGER_MEDIA_FOOTPRINT: u32 = 0x82F;
    pub const LEDGER_MEDIA_FOOTPRINT_COMPRESSED: u32 = 0x830;
    pub const LEDGER_GRAPHICS_FOOTPRINT: u32 = 0x831;
    pub const LEDGER_GRAPHICS_FOOTPRINT_COMPRESSED: u32 = 0x832;
    pub const LEDGER_NEURAL_FOOTPRINT: u32 = 0x833;
    pub const LEDGER_NEURAL_FOOTPRINT_COMPRESSED: u32 = 0x834;
    pub const MEMORYSTATUS_EFFECTIVE_PRIORITY: u32 = 0x835;
    pub const KERNEL_TRIAGE_INFO_V1: u32 = 0x836;
    pub const TASK_IS_CORPSE_FORK: u32 = 0x837;
    pub const EXCEPTION_TYPE: u32 = 0x838;
    pub const CRASH_COUNT: u32 = 0x839;
    pub const THROTTLE_TIMEOUT: u32 = 0x83A;
    pub const CS_SIGNING_ID: u32 = 0x83B;
    pub const CS_TEAM_ID: u32 = 0x83C;
    pub const CS_VALIDATION_CATEGORY: u32 = 0x83D;
    pub const CS_TRUST_LEVEL: u32 = 0x83E;
    pub const PROC_CPUTYPE: u32 = 0x83F;
    /// `EXIT_REASON_SNAPSHOT`.
    pub const EXIT_REASON_SNAPSHOT: u32 = 0x1001;
}

/// What holds a corpse's kernel alive after its process's end: the
/// host's reference to it, let go when the corpse is terminated.
#[derive(Default)]
pub struct Keep(pub Option<Box<dyn std::any::Any + Send>>);

impl std::fmt::Debug for Keep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_some() { "Keep(held)" } else { "Keep(none)" })
    }
}

/// A corpse's own state (`TFRO_CORPSE` and what goes with it).
#[derive(Debug)]
pub struct Corpse {
    /// `corpse_info`, with its `kcd_user_flags`.
    pub info: Kcdata,
    pub user_flags: u16,
    /// `crashed_thread_id`.
    pub crashed_thread_id: u64,
    /// `TF_CORPSE_FORK`: a copy of a live task, not the crashed task.
    pub fork: bool,
    /// `TF_PENDING_CORPSE` (`task_corpse_pending_report`).
    pub pending_report: bool,
    /// The thread the notification goes out from (the last to end, or the
    /// fork's equivalent of the one that raised it), and its register
    /// context.
    pub thread: i32,
    pub ctx: u64,
    /// The threads kept for inspection (`thread->inspection`).
    pub inspection: Vec<i32>,
    /// `task_uniqueid`, which `task_set_uniqueid` gives the corpse (no
    /// other task has one: 0).
    pub task_uniqueid: u64,
    /// The notification's exception type and subcode.
    pub etype: usize,
    pub subcode: i64,
    /// The delivery waiting for its handler's reply.
    pub pending: Option<super::triage::Pending>,
    /// The send right `convert_corpse_to_port_and_nsrequest` made, let go
    /// when the delivery is done.
    pub port: Option<super::ipc::ObjId>,
    /// The corpse's address space, as other tasks' kernels reach it.
    pub vm: Option<std::sync::Arc<crate::proc::PeerVm>>,
    pub keep: Keep,
    /// A corpse fork's notification, enqueued for its thread calls to
    /// deliver (`thread_exception_enqueue`): its exception type.
    pub enqueued: Option<usize>,
    /// A corpse fork's membership key in the corpse coalitions.
    pub coalition_key: Option<i32>,
    /// A corpse fork's footprint, collected from its parent's pmap
    /// (`vmmap_corpse_footprint`).
    pub footprint: Option<Footprint>,
    /// A corpse fork's ledgers: those `vm_map_copy_footprint_ledgers`
    /// copied from its parent; every other ledger of its task holds 0 (its
    /// pmap enters no page, it owns no object).
    pub ledgers: Option<Ledgers>,
    /// A corpse fork's audit token: its parent's (task_create_internal's
    /// task_tokens).
    pub audit: Option<[u32; 8]>,
}

/// The ledgers `vm_map_copy_footprint_ledgers` copies to a corpse fork:
/// phys_footprint, internal, alternate_accounting, page_table, wired_mem,
/// and of the objects owned the purgeable nonvolatile, network nonvolatile
/// and each tag's footprint ledgers (with their compressed parts, 0 here:
/// nothing is compressed), iokit_mapped (0: no mapping here is IOKit's
/// accounted one).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ledgers {
    pub phys_footprint: i64,
    pub internal: u64,
    pub alternate_accounting: u64,
    pub page_table: u64,
    pub wired_mem: u64,
    pub owned: super::purgeable::Owned,
}

/// `union corpse_creation_gate`'s word (`inflight_corpses`): the user
/// faults in its low half, the corpses in its high half.
static INFLIGHT: AtomicU32 = AtomicU32::new(0);

/// `KERN_RESOURCE_SHORTAGE`.
const KERN_RESOURCE_SHORTAGE: u64 = 6;

/// `total_corpses_count`: the corpses in flight.
pub fn total_corpses_count() -> u16 {
    (INFLIGHT.load(Ordering::Relaxed) >> 16) as u16
}

/// The simulated user faults among them.
pub fn total_user_faults_count() -> u16 {
    INFLIGHT.load(Ordering::Relaxed) as u16
}

/// `task_crashinfo_get_ref`: one more corpse in flight (and user fault,
/// for `flags::USER_FAULT`), unless the limit is reached:
/// KERN_RESOURCE_SHORTAGE. `who` is the calling process's best name and pid
/// for the kernel log lines it writes ([`kernel_log`]).
pub fn get_ref(f: u16, who: (&str, i32)) -> Result<(), u64> {
    let (name, pid) = who;
    let mut old = INFLIGHT.load(Ordering::Relaxed);
    loop {
        let (mut faults, mut corpses) = (old as u16, (old >> 16) as u16);
        if f & flags::USER_FAULT != 0 {
            let had = faults;
            faults = faults.wrapping_add(1);
            if had >= TOTAL_USER_FAULTS_ALLOWED {
                kernel_log(format!("{name}[{pid}] Corpse failure, too many faults {faults}"));
                return Err(KERN_RESOURCE_SHORTAGE);
            }
        }
        let had = corpses;
        corpses = corpses.wrapping_add(1);
        if had >= TOTAL_CORPSES_ALLOWED {
            kernel_log(format!("{name}[{pid}] Corpse failure, too many {corpses}"));
            return Err(KERN_RESOURCE_SHORTAGE);
        }
        let new = u32::from(faults) | (u32::from(corpses) << 16);
        match INFLIGHT.compare_exchange(old, new, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => {
                kernel_log(format!("{name}[{pid}] Corpse allowed {corpses} of {TOTAL_CORPSES_ALLOWED}"));
                return Ok(());
            }
            Err(v) => old = v,
        }
    }
}

/// A line of the kernel's log (`printf`, `os_log`), as this kernel gives
/// it: on the host's standard error. (`os_log`'s own reader, `/dev/oslog`,
/// is not modelled, and says so when opened.)
pub fn kernel_log(line: String) {
    crate::darwin_say!("{line}");
}

/// `task_crashinfo_release_ref`.
pub fn release_ref(f: u16) {
    let mut old = INFLIGHT.load(Ordering::Relaxed);
    loop {
        let (mut faults, mut corpses) = (old as u16, (old >> 16) as u16);
        if f & flags::USER_FAULT != 0 {
            faults = faults.checked_sub(1).expect("corpse in flight count over-release");
        }
        corpses = corpses.checked_sub(1).expect("corpse in flight count over-release");
        let new = u32::from(faults) | (u32::from(corpses) << 16);
        match INFLIGHT.compare_exchange(old, new, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => {
                kernel_log(format!("Corpse released, count at {corpses}"));
                return;
            }
            Err(v) => old = v,
        }
    }
}

/// `task_crashinfo_alloc_init` of a zeroed `CORPSEINFO_ALLOCATION_SIZE`
/// allocation (`task_collect_crash_info`): the reference its flags ask
/// for taken first (none for a corpse fork, whose reference its creation
/// took), the buffer begun with `TASK_CRASHINFO_BEGIN`.
pub fn crashinfo_alloc_init(user_flags: u16, who: (&str, i32)) -> Option<Kcdata> {
    if user_flags & flags::HAS_REF != 0 && get_ref(user_flags, who).is_err() {
        return None;
    }
    let k = Kcdata::alloc_init(super::kcdata::BUFFER_BEGIN_CRASHINFO, CORPSEINFO_ALLOCATION_SIZE, 0);
    if k.is_none() && user_flags & flags::HAS_REF != 0 {
        release_ref(user_flags);
    }
    k
}

/// Whether the host keeps a corpse's task past its process's end
/// ([`set_host_keeps_corpses`]).
static HOST_KEEPS_CORPSES: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The host keeps a corpse's task (its kernel and memory) past its
/// process's end, and calls [`hold`] and [`exited`] there.
pub fn set_host_keeps_corpses() {
    HOST_KEEPS_CORPSES.store(true, Ordering::Release);
}

/// `vm_map_corpse_footprint_count`, `_size_avg`, `_size_max`, `_full` and
/// `_no_buf` (the `vm.corpse_footprint_*` sysctls).
static FOOTPRINT_STATS: std::sync::Mutex<[u64; 5]> = std::sync::Mutex::new([0; 5]);

/// The `vm.corpse_footprint_*` statistic named by its sysctl's last part.
pub fn footprint_stat(name: &str) -> Option<u64> {
    let i = ["count", "size_avg", "size_max", "full", "no_buf"].iter().position(|&n| n == name)?;
    Some(FOOTPRINT_STATS.lock().unwrap_or_else(|e| e.into_inner())[i])
}

/// `sizeof(struct vm_map_corpse_footprint_header)` (`vm_size_t cf_size`,
/// `uint32_t cf_last_region`, the `cfu` union) and of the packed
/// `struct vm_map_corpse_footprint_region` (`cfr_vaddr`, `cfr_num_pages`).
const CF_HEADER: u32 = 16;
const CF_REGION: u32 = 12;
/// `effective_page_size`: MIN(PAGE_SIZE, VM_MAP_PAGE_SIZE(map)), 16 KB on
/// this device.
const CF_PAGE: u64 = super::mach::PAGE_MASK + 1;
/// `VM_MAP_CORPSE_FOOTPRINT_INFO_MAX_SIZE` on an embedded kernel.
const CF_MAX_SIZE: u64 = 256 * 1024;
/// `VM_PAGE_QUERY_PAGE_FICTITIOUS` and `_REUSABLE`: the bit a
/// `cf_disp_t` (a byte) keeps the second in.
const DISP_FICTITIOUS: i32 = 0x2;
const DISP_REUSABLE: i32 = 0x800;

/// A corpse fork's footprint (`vmmap_corpse_footprint`): the page
/// dispositions of its parent's map at the fork, packed into regions as
/// `vm_map_corpse_footprint_collect` packs them, in a buffer of the size
/// it gives one. `failed` once a collection found it full.
#[derive(Debug)]
pub struct Footprint {
    buf: Vec<u8>,
    cf_size: u64,
    last_region: u32,
    last_zeroes: u32,
    pub failed: bool,
}

impl Footprint {
    /// The buffer for a map of `nentries` entries mapping `size` bytes:
    /// the header, each entry's region header with its alignment, and a
    /// disposition a page, page rounded, at most CF_MAX_SIZE; its first
    /// region empty. (`kmem_alloc` of it does not fail here, so
    /// `vm_map_corpse_footprint_no_buf` stays as it is.)
    pub fn new(nentries: u64, size: u64) -> Footprint {
        let mut buf_size = u64::from(CF_HEADER) + nentries * (u64::from(CF_REGION) + 3) + size / CF_PAGE;
        buf_size = (buf_size + CF_PAGE - 1) & !(CF_PAGE - 1);
        buf_size = buf_size.min(CF_MAX_SIZE);
        let mut f = Footprint { buf: vec![0; buf_size as usize], cf_size: buf_size, last_region: CF_HEADER, last_zeroes: 0, failed: false };
        f.set_vaddr(CF_HEADER, 0);
        f.set_num(CF_HEADER, 0);
        f
    }

    fn vaddr(&self, r: u32) -> u64 {
        u64::from_le_bytes(self.buf[r as usize..r as usize + 8].try_into().unwrap())
    }

    fn set_vaddr(&mut self, r: u32, v: u64) {
        self.buf[r as usize..r as usize + 8].copy_from_slice(&v.to_le_bytes());
    }

    fn num(&self, r: u32) -> u32 {
        u32::from_le_bytes(self.buf[r as usize + 8..r as usize + 12].try_into().unwrap())
    }

    fn set_num(&mut self, r: u32, n: u32) {
        self.buf[r as usize + 8..r as usize + 12].copy_from_slice(&n.to_le_bytes());
    }

    /// `vm_map_corpse_footprint_new_region`: the last region closed (its
    /// trailing zero dispositions dropped) and a new one begun after it,
    /// word aligned; the last region itself if it is now empty; none past
    /// the buffer's edge.
    fn new_region(&mut self) -> Option<u32> {
        let r = self.last_region;
        let n = self.num(r) - self.last_zeroes;
        self.set_num(r, n);
        self.last_zeroes = 0;
        if n == 0 {
            return Some(r);
        }
        let off = (r + CF_REGION + n).next_multiple_of(4);
        if u64::from(off) + u64::from(CF_REGION) >= self.cf_size {
            return None;
        }
        self.last_region = off;
        self.set_vaddr(off, 0);
        self.set_num(off, 0);
        Some(off)
    }

    /// `vm_map_corpse_footprint_collect` of an entry `[start, end)`,
    /// `disp(va)` each page's disposition: false (counted in
    /// `vm_map_corpse_footprint_full`) when the buffer is full.
    pub fn collect(&mut self, start: u64, end: u64, mut disp: impl FnMut(u64) -> i32) -> bool {
        let ok = self.collect_inner(start, end, &mut disp);
        if !ok {
            FOOTPRINT_STATS.lock().unwrap_or_else(|e| e.into_inner())[3] += 1;
        }
        ok
    }

    fn collect_inner(&mut self, start: u64, end: u64, disp: &mut dyn FnMut(u64) -> i32) -> bool {
        let edge = self.cf_size;
        let mut r = self.last_region;
        if self.vaddr(r).wrapping_add(u64::from(self.num(r)) * CF_PAGE) != start {
            // Not contiguous: zero dispositions for the gap, or a new
            // region where they would take more room than its header (or
            // overflow the count).
            let num = self.num(r);
            let delta = (start.wrapping_sub(self.vaddr(r)) / CF_PAGE).wrapping_sub(u64::from(num));
            let kept = num - self.last_zeroes;
            let header_delta = CF_REGION + kept.next_multiple_of(4) - kept;
            let overflows = u64::from(num) + (delta as u32 as u64) + 1 > u64::from(u32::MAX);
            if u64::from(header_delta) < delta || overflows {
                let Some(n) = self.new_region() else { return false };
                r = n;
                self.set_vaddr(r, start);
                self.set_num(r, 0);
            } else {
                for _ in 0..delta {
                    let next = u64::from(r) + u64::from(CF_REGION) + u64::from(self.num(r));
                    if next >= edge {
                        return false;
                    }
                    let n = self.num(r) + 1;
                    self.set_num(r, n);
                    self.buf[next as usize] = 0;
                    self.last_zeroes += 1;
                }
            }
        }
        let mut va = start;
        while va < end {
            let d = disp(va);
            let cf = (if d & DISP_REUSABLE != 0 { d | DISP_FICTITIOUS } else { d }) as u8;
            if cf == 0 && self.num(r) == 0 {
                // Zero dispositions at a region's start only move it.
                let v = self.vaddr(r) + CF_PAGE;
                self.set_vaddr(r, v);
                va += CF_PAGE;
                continue;
            }
            if self.num(r) == u32::MAX {
                let Some(n) = self.new_region() else { return false };
                r = n;
                self.set_vaddr(r, va);
                self.set_num(r, 0);
            }
            let next = u64::from(r) + u64::from(CF_REGION) + u64::from(self.num(r));
            if next >= edge {
                return false;
            }
            self.buf[next as usize] = cf;
            let n = self.num(r) + 1;
            self.set_num(r, n);
            if cf != 0 {
                self.last_zeroes = 0;
                va += CF_PAGE;
                continue;
            }
            self.last_zeroes += 1;
            let pad = if ((self.num(r) - self.last_zeroes) & 3) != 0 { 4 } else { 0 };
            if self.last_zeroes + pad < CF_HEADER {
                va += CF_PAGE;
                continue;
            }
            // Too many zeroes in a row: a new region, past this one.
            let Some(n) = self.new_region() else { return false };
            r = n;
            self.set_num(r, 0);
            self.set_vaddr(r, va + CF_PAGE);
            va += CF_PAGE;
        }
        true
    }

    /// `vm_map_corpse_footprint_collect_done`: the last region's trailing
    /// zeroes dropped, the statistics told its size, the buffer trimmed to
    /// it (page rounded).
    pub fn done(&mut self) {
        let r = self.last_region;
        let n = self.num(r) - self.last_zeroes;
        self.set_num(r, n);
        self.last_zeroes = 0;
        let actual = u64::from(r) + u64::from(CF_REGION) + u64::from(n);
        {
            let mut st = FOOTPRINT_STATS.lock().unwrap_or_else(|e| e.into_inner());
            st[1] = (st[1] * st[0] + actual) / (st[0] + 1);
            st[0] += 1;
            st[2] = st[2].max(actual);
        }
        let rounded = (actual + CF_PAGE - 1) & !(CF_PAGE - 1);
        if self.cf_size > rounded {
            self.buf.truncate(rounded as usize);
        }
        self.cf_size = rounded;
    }

    /// `vm_map_corpse_footprint_query_page_info`: the disposition of the
    /// page at `va` as collected (0 for one in no region).
    pub fn query(&self, va: u64) -> i32 {
        let mut off = CF_HEADER;
        loop {
            let (s, n) = (self.vaddr(off), self.num(off));
            let e = s + u64::from(n) * CF_PAGE;
            if va >= s && va < e {
                let cf = i32::from(self.buf[(off + CF_REGION) as usize + ((va - s) / CF_PAGE) as usize]);
                return if cf & DISP_FICTITIOUS != 0 { (cf | DISP_REUSABLE) & !DISP_FICTITIOUS } else { cf };
            }
            if va < e || off >= self.last_region {
                return 0;
            }
            off = (off + CF_REGION + n).next_multiple_of(4);
        }
    }

    /// The buffer's size (`cf_size`).
    pub fn size(&self) -> u64 {
        self.cf_size
    }
}

/// `KERN_NO_SPACE`, `KERN_NOT_SUPPORTED`.
const KERN_NO_SPACE: u64 = 3;
const KERN_NOT_SUPPORTED: u64 = 46;

/// `MACH_RCV_PORT_DIED`, `KERN_FAILURE`, `KERN_TERMINATED`,
/// `KERN_SUCCESS`, `KERN_INVALID_ARGUMENT`.
const RCV_PORT_DIED: u64 = 0x1000_4009;
const KERN_FAILURE: u64 = 5;
const KERN_TERMINATED: u64 = 37;
const KERN_SUCCESS: u64 = 0;
const KERN_INVALID_ARGUMENT: i32 = 4;

/// What other tasks' kernels reach of a corpse (the `corpse_tasks` queue's
/// task): its process, its crash information as populated, its address
/// space.
#[derive(Debug)]
pub struct Registered {
    pub pid: i32,
    /// `task_uniqueid` (`find_corpse_task_by_uniqueid_grp`).
    pub task_uniqueid: u64,
    pub info: Vec<u8>,
    pub vm: Option<std::sync::Arc<crate::proc::PeerVm>>,
}

/// `corpse_tasks`, by the corpse's task key.
fn registry() -> std::sync::MutexGuard<'static, std::collections::HashMap<super::ipc::TaskKey, std::sync::Arc<Registered>>> {
    static R: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<super::ipc::TaskKey, std::sync::Arc<Registered>>>> = std::sync::OnceLock::new();
    R.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner())
}

/// `task_add_to_corpse_task_list`: task `task`'s corpse, as other tasks'
/// kernels reach it.
pub(crate) fn register(task: super::ipc::TaskKey, r: Registered) {
    registry().insert(task, std::sync::Arc::new(r));
}

/// Task `task` if it is a corpse (`task_is_a_corpse`), as its kernel
/// registered it.
pub fn find(task: super::ipc::TaskKey) -> Option<std::sync::Arc<Registered>> {
    registry().get(&task).cloned()
}

/// `CPU_TYPE_ARM64`: `cpu_type()` with `CPU_ARCH_ABI64`, for a 64-bit
/// process.
const CPU_TYPE_ARM64: u32 = 0x0100_000C;
/// `P_LP64`, `P_SUGID`.
const P_LP64: u32 = 0x4;
const P_SUGID: u32 = 0x100;
/// `MAXCOMLEN + 1`, `MAXPATHLEN`, `sizeof(rusage_info_current)`,
/// `sizeof(struct kernel_triage_info_v1)`.
const COMM_LEN: usize = 17;
const MAXPATHLEN: usize = 1024;
const RUSAGE_INFO_CURRENT_SIZE: usize = 464;
const TRIAGE_INFO_SIZE: usize = 640;
/// `MAX_CRASHINFO_SIGNING_ID_LEN`, `MAX_CRASHINFO_TEAM_ID_LEN`.
const SIGNING_ID_LEN: usize = 64;
const TEAM_ID_LEN: usize = 32;
/// `KCDATA_INVALID_CS_TRUST_LEVEL`: `get_trust_level_kdp` fails on this
/// kernel (no code signing monitor), as its `populate_corpse_crashinfo`
/// writes.
const INVALID_CS_TRUST_LEVEL: u32 = 0xffff_ffff;
/// `VM_MEMORY_IOKIT`.
const VM_MEMORY_IOKIT: u8 = 21;
/// `EXC_RESOURCE_ENCODE_TYPE`'s RESOURCE_TYPE_MEMORY and
/// `EXC_RESOURCE_ENCODE_FLAVOR`'s FLAVOR_HIGH_WATERMARK.
const RESOURCE_TYPE_MEMORY: i64 = 3;
const FLAVOR_HIGH_WATERMARK: i64 = 1;

impl crate::syscalls::Kernel {
    /// `thread_tid` of thread `tid`.
    pub(crate) fn darwin_thread_tid(&self, tid: i32) -> u64 {
        self.thread_signals.get(tid).map_or(0, |t| t.darwin_id())
    }

    /// `proc_best_name`: `p_name` when it has one, else `p_comm`.
    pub(crate) fn darwin_best_name(&self) -> String {
        let n = &self.dtask.p_name.0;
        let len = n.iter().position(|&b| b == 0).unwrap_or(n.len());
        if len > 0 {
            return String::from_utf8_lossy(&n[..len]).into_owned();
        }
        self.darwin_public(self.pid).map(|p| String::from_utf8_lossy(&p.0.comm).into_owned()).unwrap_or_default()
    }

    /// A path XNU records a kernel triage event on (`ktriage_record`) was
    /// taken by thread `tid`, the event not modelled here: what it was, for
    /// a crash report that would carry it.
    pub(crate) fn darwin_ktriage_unmodelled(&mut self, tid: i32, what: String) {
        self.dtask.ktriage_unmodelled.entry(tid).or_default().push(what);
    }

    /// The rest of `proc_prepareexit` once its EXC_CRASH went to its
    /// handlers (`kr` what `task_exception_notify` returned): a report no
    /// handler took (or a map marked a corpse source) makes the task a
    /// corpse, when the process itself is ending (not another's `exit1` of
    /// it); its crash information then gets the EXC_CRASH codes (an exit
    /// reason may rewrite them) and its usage as it ends.
    pub(crate) fn darwin_prepareexit_corpse(&mut self, kr: u64, code: i64, subcode: i64) {
        let source = std::mem::take(&mut self.dtask.corpse_source);
        let current = self.procs.forced_exit(self.pid).is_none();
        if !((kr != 0 || source) && current) {
            return;
        }
        if !HOST_KEEPS_CORPSES.load(Ordering::Acquire) {
            self.darwin_unimplemented("a corpse on a host that does not keep a task past its process's end (corpse::hold, corpse::exited)".into());
            return;
        }
        let r = self.darwin_task_mark_corpse();
        if r != KERN_SUCCESS {
            let pid = self.pid;
            kernel_log(match r {
                KERN_NO_SPACE => format!("Process[{pid}] has no vm space for corpse info."),
                KERN_NOT_SUPPORTED => format!("Process[{pid}] was destined to be corpse. But corpse is disabled by config."),
                KERN_TERMINATED => format!("Process[{pid}] has been terminated before it could be converted to a corpse."),
                _ => {
                    let comm = self.darwin_public(pid).map(|p| String::from_utf8_lossy(&p.0.comm).into_owned()).unwrap_or_default();
                    format!("Process[{pid}] crashed: {comm}. Too many corpses being created.")
                }
            });
            return;
        }
        let (code, subcode) = self.darwin_corpse_exception_codes(code, subcode);
        let udata = self.darwin_corpse_uptrs();
        let bills = self.darwin_bank_bills(self.pid, self.dtask.uniqueid, &std::sync::Arc::clone(&self.dtask.rusage));
        let Some((public, _)) = self.darwin_public(self.pid) else {
            self.darwin_unimplemented("a corpse's crash information for a process with no record of its own".into());
            return;
        };
        let record = super::rusage::crash_record(&self.procs, self.pid, &public, bills, true);
        let Some(mut c) = self.dtask.corpse.take() else { return };
        let tid = self.tid;
        let info = self.darwin_populate_corpse_crashinfo(&mut c, &public, code, subcode, &udata, None, super::exception::EXC_CRASH, record, Some(tid));
        let (vm, task_uniqueid) = (c.vm.clone(), c.task_uniqueid);
        self.dtask.corpse = Some(c);
        // task_add_to_corpse_task_list.
        let key = self.ipc().task;
        register(key, Registered { pid: self.pid, task_uniqueid, info, vm });
    }

    /// `proc_update_corpse_exception_codes`: a process killed for its
    /// memory limit has its code made an EXC_RESOURCE high watermark's
    /// (over the code as it was) and its subcode 0.
    fn darwin_corpse_exception_codes(&mut self, code: i64, subcode: i64) -> (i64, i64) {
        let Some(r) = self.procs.exit_reason(self.pid).and_then(|n| super::reason::of(&n)) else { return (code, subcode) };
        if r.namespace == super::reason::ns::JETSAM && r.code == super::reason::JETSAM_REASON_MEMORY_PERPROCESSLIMIT {
            let limit = self.procs.jetsam().ledgers.get(&self.pid).map_or(super::footprint::Ledger::default().limit, |l| l.limit);
            let c = code | ((RESOURCE_TYPE_MEMORY & 0x7) << 61) | ((FLAVOR_HIGH_WATERMARK & 0x7) << 58) | ((limit >> 20) & 0x1fff);
            return (c, 0);
        }
        (code, subcode)
    }

    /// `kevent_proc_copy_uptrs` for the crash information
    /// (proc_prepareexit's buffer holds the count it first finds and 32
    /// more, and this one's count does not change in between).
    fn darwin_corpse_uptrs(&mut self) -> Vec<u64> {
        self.dtask.kevents.proc_copy_uptrs()
    }

    /// `task_mark_corpse`: the crash information made (a corpse in flight
    /// counted, unless too many are), the task marked a corpse with its
    /// report pending, the crashing thread's id and a new `task_uniqueid`,
    /// its threads kept for inspection, its ports disabled
    /// (`ipc_task_disable`), its IPC space ended, and the task put on the
    /// corpse list once its information is in
    /// ([`Self::darwin_populate_corpse_crashinfo`]).
    fn darwin_task_mark_corpse(&mut self) -> u64 {
        let Some(info) = crashinfo_alloc_init(flags::HAS_REF, (&self.darwin_best_name(), self.pid)) else { return KERN_FAILURE };
        if self.dtask.ipc_raw.ended {
            release_ref(flags::HAS_REF);
            return KERN_TERMINATED;
        }
        let tid = self.tid;
        let mut inspection = self.thread_signals.tids_in_order();
        inspection.extend(self.dtask.threads.map.keys().copied());
        inspection.push(tid);
        inspection.sort_unstable();
        inspection.dedup();
        let vm = self.procs.vm(self.pid).ok();
        // task_set_uniqueid.
        let task_uniqueid = super::next_task_uniqueid();
        self.dtask.task_uniqueid = task_uniqueid;
        self.dtask.corpse = Some(Box::new(Corpse {
            info,
            user_flags: flags::HAS_REF,
            crashed_thread_id: self.darwin_thread_tid(tid),
            fork: false,
            pending_report: true,
            thread: tid,
            ctx: self.ctx_addr,
            inspection,
            task_uniqueid,
            etype: super::exception::EXC_CRASH,
            subcode: 0,
            pending: None,
            port: None,
            vm,
            keep: Keep::default(),
            enqueued: None,
            coalition_key: None,
            footprint: None,
            ledgers: None,
            audit: None,
        }));
        let ipc = self.ipc();
        ipc.task_disable();
        ipc.space_terminate();
        self.darwin_ipc_notify_drain();
        KERN_SUCCESS
    }

    /// `populate_corpse_crashinfo` of this process (`public` its record)
    /// into corpse `c`'s crash information (this task's own corpse, or a
    /// corpse fork of it, whose ledgers are this task's as they were at the
    /// fork), item by item in the order the 21H461 kernel writes them; an
    /// item that does not fit is left out. `reason` is a corpse fork's,
    /// which its exit reason snapshot takes over the process's exit reason;
    /// `record` its usage (`rusage_info_current`, its footprint 0);
    /// `current` the calling thread if it is this task's (whose kernel
    /// triage records the crash information holds). The information made.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn darwin_populate_corpse_crashinfo(&mut self, c: &mut Corpse, public: &super::procinfo::Public, code: i64, subcode: i64, udata: &[u64], reason: Option<std::sync::Arc<super::reason::OsReason>>, etype: usize, record: super::rusage::Record, current: Option<i32>) -> Vec<u8> {
        use std::sync::atomic::Ordering::Acquire;
        let pid = self.pid;
        let ppid = self.procs.ppid(pid);
        let exit_reason = self.procs.exit_reason(pid).and_then(|n| super::reason::of(&n));
        let unkept = record.unkept_within(RUSAGE_INFO_CURRENT_SIZE);
        if !unkept.is_empty() {
            self.darwin_unimplemented(format!("a corpse's TASK_CRASHINFO_RUSAGE_INFO: {}, not kept (given as 0)", unkept.join(", ")));
        }
        let csflags = self.dtask.csflags.load(Acquire);
        let ledger = self.procs.jetsam().ledgers.get(&pid).map_or_else(super::footprint::Ledger::default, |l| *l);
        let page = super::mach::PAGE_MASK + 1;
        let alt = self.dtask.rusage.meter.alt.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let (pages, page_table, alt_pages) = {
            let pm = self.dtask.rusage.meter.lock();
            (pm.pages(), pm.page_table(), pm.own_in(&alt))
        };
        let owned = match super::purgeable::owned(&self.dtask.rusage.meter.owner()) {
            Some(o) => o,
            None => {
                self.darwin_unimplemented("a corpse's purgeable and tagged ledgers on a host that cannot say what the task's objects hold".into());
                Default::default()
            }
        };
        // vm_map_iokit_mapped_region: IOKit's accounted mappings, which no
        // mapping made here is (iokit_acct).
        let iokit = {
            let map = self.dtask.vm.lock();
            let mut at = 0;
            let mut any = false;
            while let Some(e) = map.at_or_after(at) {
                any |= e.attrs.alias == VM_MEMORY_IOKIT;
                at = e.end;
            }
            any
        };
        if iokit {
            self.darwin_unimplemented("a corpse's TASK_CRASHINFO_LEDGER_IOKIT_MAPPED for a task with IOKit mappings (vm_map_iokit_mapped_region's iokit_acct)".into());
        }
        let wq = self.darwin_fill_procworkqueue();
        let persona = self.dtask.persona.as_ref().map_or(super::persona::ID_NONE, |p| p.id);
        let coalitions = super::coalition::membership(pid).0;
        let (dirty, effective) = {
            let j = self.procs.jetsam();
            (j.dirty_get(pid).unwrap_or(0), j.get(pid).map_or(0, |m| m.effective))
        };
        let signed = csflags & super::amfi::cs::SIGNED != 0;
        let blob = self.dtask.codesign.as_ref();
        let identity = blob.and_then(|c| c.identity.clone()).filter(|_| signed);
        let team = blob.and_then(|c| c.team_id.clone()).filter(|_| signed);
        let category = blob.filter(|_| csflags & (super::amfi::cs::VALID | super::amfi::cs::DEBUGGED) != 0).map_or(0, |c| c.category);
        // The crashed thread's id goes unless the process's exit reason
        // says it is irrelevant; the snapshot is of the reason given, else
        // of the process's exit reason.
        let no_crashed_tid = exit_reason.as_ref().is_some_and(|r| r.flags & super::reason::flag::NO_CRASHED_TID != 0);
        let reason = reason.or(exit_reason);
        if let Some(events) = current.and_then(|t| self.dtask.ktriage_unmodelled.get(&t)).filter(|e| !e.is_empty()) {
            let e = events.join("; ");
            self.darwin_unimplemented(format!("a corpse's TASK_CRASHINFO_KERNEL_TRIAGE_INFO_V1 for a thread that took paths XNU records triage events on: {e}"));
        }

        let crashed = c.crashed_thread_id;
        let fork = c.fork;
        c.etype = etype;
        let k = &mut c.info;
        let mut codes = code.to_le_bytes().to_vec();
        codes.extend_from_slice(&subcode.to_le_bytes());
        k.put(ty::EXCEPTION_CODES, &codes);
        k.put(ty::PID, &pid.to_le_bytes());
        k.put(ty::PPID, &ppid.to_le_bytes());
        if !no_crashed_tid {
            k.put(ty::CRASHED_THREADID, &crashed.to_le_bytes());
        }
        k.put(ty::BSDINFOWITHUNIQID, &super::procinfo::uniqidentifierinfo(public));
        k.put(ty::RUSAGE_INFO, &record.bytes()[..RUSAGE_INFO_CURRENT_SIZE]);
        k.put(ty::PROC_CSFLAGS, &csflags.to_le_bytes());
        let mut comm = [0u8; COMM_LEN];
        let n = public.comm.len().min(COMM_LEN - 1);
        comm[..n].copy_from_slice(&public.comm[..n]);
        k.put(ty::PROC_NAME, &comm);
        let mut start = (self.dtask.start.0 as i64).to_le_bytes().to_vec();
        start.extend_from_slice(&(self.dtask.start.1 as i64).to_le_bytes());
        k.put(ty::PROC_STARTTIME, &start);
        k.put(ty::USERSTACK, &self.darwin_user_stack.to_le_bytes());
        k.put(ty::ARGSLEN, &self.dtask.live.argslen.load(Acquire).to_le_bytes());
        k.put(ty::PROC_ARGC, &self.dtask.live.argc.load(Acquire).to_le_bytes());
        let mut path = vec![0u8; MAXPATHLEN];
        let n = public.path.len().min(MAXPATHLEN - 1);
        path[..n].copy_from_slice(&public.path[..n]);
        k.put(ty::PROC_PATH, &path);
        let pflags = P_LP64 | if self.dtask.sugid { P_SUGID } else { 0 };
        k.put(ty::PROC_FLAGS, &pflags.to_le_bytes());
        k.put(ty::UID, &self.dtask.cred.uid.to_le_bytes());
        k.put(ty::GID, &self.dtask.cred.gid().to_le_bytes());
        k.put(ty::CPUTYPE, &CPU_TYPE_ARM64.to_le_bytes());
        k.put(ty::PROC_CPUTYPE, &self.dtask.cputype.0.to_le_bytes());
        k.put(ty::MEMORY_LIMIT, &((ledger.limit >> 20) as u64).to_le_bytes());
        k.put(ty::LEDGER_PHYS_FOOTPRINT_LIFETIME_MAX, &(ledger.lifetime_max as u64).to_le_bytes());
        // The device's pages are not compressed (no pageout runs), so the
        // compressed ledgers hold nothing.
        for (t, v) in [
            (ty::LEDGER_INTERNAL, pages.internal * page),
            (ty::LEDGER_INTERNAL_COMPRESSED, 0),
            (ty::LEDGER_IOKIT_MAPPED, 0),
            (ty::LEDGER_ALTERNATE_ACCOUNTING, alt_pages * page),
            (ty::LEDGER_ALTERNATE_ACCOUNTING_COMPRESSED, 0),
            (ty::LEDGER_PURGEABLE_NONVOLATILE, owned.purgeable_nonvolatile),
            (ty::LEDGER_PURGEABLE_NONVOLATILE_COMPRESSED, 0),
            (ty::LEDGER_PAGE_TABLE, page_table),
            (ty::LEDGER_PHYS_FOOTPRINT, ledger.balance as u64),
            (ty::LEDGER_NETWORK_NONVOLATILE, owned.network_nonvolatile),
            (ty::LEDGER_NETWORK_NONVOLATILE_COMPRESSED, 0),
            (ty::LEDGER_WIRED_MEM, self.dtask.rusage.wired.load(Acquire)),
        ] {
            k.put(t, &v.to_le_bytes());
        }
        if let Some(w) = wq {
            let b: Vec<u8> = w.iter().flat_map(|x| x.to_le_bytes()).collect();
            k.put(ty::WORKQUEUEINFO, &b);
        }
        k.put(ty::RESPONSIBLE_PID, &self.dtask.responsible_pid.to_le_bytes());
        k.put(ty::PROC_PERSONA_ID, &persona.to_le_bytes());
        let ids: Vec<u8> = coalitions.iter().flat_map(|x| x.to_le_bytes()).collect();
        k.put_array(ty::COALITION_ID, 8, coalitions.len() as u32, &ids);
        k.put(ty::DIRTY_FLAGS, &(dirty as i32).to_le_bytes());
        // p_memlimit_increase: no call here raises a memory limit by it.
        k.put(ty::MEMORY_LIMIT_INCREASE, &0u32.to_le_bytes());
        for (t, v) in [
            (ty::LEDGER_TAGGED_FOOTPRINT, owned.tagged_footprint),
            (ty::LEDGER_TAGGED_FOOTPRINT_COMPRESSED, 0),
            (ty::LEDGER_MEDIA_FOOTPRINT, owned.media_footprint),
            (ty::LEDGER_MEDIA_FOOTPRINT_COMPRESSED, 0),
            (ty::LEDGER_GRAPHICS_FOOTPRINT, owned.graphics_footprint),
            (ty::LEDGER_GRAPHICS_FOOTPRINT_COMPRESSED, 0),
            (ty::LEDGER_NEURAL_FOOTPRINT, owned.neural_footprint),
            (ty::LEDGER_NEURAL_FOOTPRINT_COMPRESSED, 0),
        ] {
            k.put(t, &v.to_le_bytes());
        }
        k.put(ty::MEMORYSTATUS_EFFECTIVE_PRIORITY, &effective.to_le_bytes());
        // ktriage_extract of the current thread: the buffer zeroed (bzero in ktriage_extract), then its
        // recorded events as strings. None of the paths this kernel takes
        // records one, but those reported where taken ([`Self::darwin_ktriage_unmodelled`]).
        k.put(ty::KERNEL_TRIAGE_INFO_V1, &[0u8; TRIAGE_INFO_SIZE]);
        k.put(ty::TASK_IS_CORPSE_FORK, &u32::from(fork).to_le_bytes());
        k.put(ty::EXCEPTION_TYPE, &(etype as i32).to_le_bytes());
        k.put(ty::CRASH_COUNT, &self.dtask.crash_count.to_le_bytes());
        k.put(ty::THROTTLE_TIMEOUT, &self.dtask.throttle_timeout.to_le_bytes());
        let mut id = [0u8; SIGNING_ID_LEN];
        if let Some(s) = &identity {
            let n = s.len().min(SIGNING_ID_LEN - 1);
            id[..n].copy_from_slice(&s[..n]);
        }
        k.put(ty::CS_SIGNING_ID, &id);
        let mut tm = [0u8; TEAM_ID_LEN];
        if let Some(s) = &team {
            let n = s.len().min(TEAM_ID_LEN - 1);
            tm[..n].copy_from_slice(&s[..n]);
        }
        k.put(ty::CS_TEAM_ID, &tm);
        k.put(ty::CS_VALIDATION_CATEGORY, &category.to_le_bytes());
        k.put(ty::CS_TRUST_LEVEL, &INVALID_CS_TRUST_LEVEL.to_le_bytes());
        if let Some(r) = &reason {
            let mut ers = r.namespace.to_le_bytes().to_vec();
            ers.extend_from_slice(&r.code.to_le_bytes());
            ers.extend_from_slice(&r.flags.to_le_bytes());
            k.put(ty::EXIT_REASON_SNAPSHOT, &ers);
            let data = r.data();
            if !data.is_empty() {
                k.put(super::kcdata::TYPE_NESTED_KCDATA, data);
            }
        }
        if !udata.is_empty() {
            let b: Vec<u8> = udata.iter().flat_map(|x| x.to_le_bytes()).collect();
            k.put_array(ty::UDATA_PTRS, 8, udata.len() as u32, &b);
        }
        k.bytes().to_vec()
    }

    /// `proc_encode_exit_exception_code`: the exit reason's namespace and
    /// code, 32 bits of each.
    fn darwin_exit_exception_code(&self) -> i64 {
        let Some(r) = self.procs.exit_reason(self.pid).and_then(|n| super::reason::of(&n)) else { return 0 };
        ((u64::from(r.namespace) << 32) | (r.code & 0xffff_ffff)) as i64
    }

    /// The corpse's last thread, once `proc_exit` is done
    /// (`thread_terminate_self`): its task's ports made anew and enabled
    /// (`ipc_task_reset`, `ipc_task_enable`), then
    /// `task_deliver_crash_notification`.
    fn darwin_corpse_last_thread(&mut self, m: &mut crate::GuestMem<'_>) {
        self.darwin_corpse_task_reset();
        if let Some(l) = self.ipc().link.clone() {
            l.ipc_active.store(true, std::sync::atomic::Ordering::Release);
        }
        let subcode = self.darwin_exit_exception_code();
        self.darwin_deliver_crash_notification(m, subcode);
    }

    /// `ipc_task_reset` of a corpse: a new control port, which is its self
    /// port too (no immovable or pinned port for a task that runs no more
    /// code), and no settable self port (the corpse's port's no-senders
    /// notification wants none); the old control and self ports and the
    /// read and inspect ports gone; the handlers not set by a privileged
    /// task released, but the corpse notification's while its report is
    /// pending.
    fn darwin_corpse_task_reset(&mut self) {
        use super::exception::{EXC_CORPSE_NOTIFY, EXC_TYPES_COUNT};
        let ipc = self.ipc();
        let new = ipc.kobject_port(super::ipc::Kobject::Task);
        let old = self.dtask.kports.task.replace((new, new));
        let mut dead: Vec<super::ipc::ObjId> = self.dtask.kports.flavored.iter_mut().filter_map(Option::take).collect();
        if let Some((k, p)) = old {
            dead.push(k);
            if p != k {
                dead.push(p);
            }
        }
        let ipc = self.ipc();
        for p in dead {
            ipc.port_mut(p).kobject = None;
            ipc.port_mut(p).pinned = false;
            ipc.port_destroy(p);
        }
        let pending = self.dtask.corpse.as_ref().is_some_and(|c| c.pending_report);
        let mut released = Vec::new();
        for i in 1..EXC_TYPES_COUNT {
            if i == EXC_CORPSE_NOTIFY && pending {
                continue;
            }
            let a = &mut self.dtask.kports.exc[i];
            if !a.privileged {
                released.push(a.port.take());
            }
        }
        let ipc = self.ipc();
        for c in released {
            super::exception::release(ipc, c);
        }
        self.darwin_ipc_notify_drain();
    }

    /// `ipc_thread_reset` of a corpse's thread: a new control port (its
    /// self port too), the old ports gone, the handlers not set by a
    /// privileged task released.
    pub(crate) fn darwin_corpse_thread_reset(&mut self, tid: i32) {
        use super::kobject::flavor;
        let ipc = self.ipc();
        let new = ipc.kobject_port(super::ipc::Kobject::Thread(tid));
        let old = self.dtask.kports.threads.insert(tid, (new, new));
        let mut dead: Vec<super::ipc::ObjId> = [flavor::READ, flavor::INSPECT].iter().filter_map(|&f| self.dtask.kports.thread_flavored.remove(&(tid, f))).collect();
        if let Some((k, p)) = old {
            dead.push(k);
            if p != k {
                dead.push(p);
            }
        }
        let ipc = self.ipc();
        for p in dead {
            ipc.port_mut(p).kobject = None;
            ipc.port_mut(p).pinned = false;
            ipc.port_destroy(p);
        }
        let mut released = Vec::new();
        if let Some(a) = self.dtask.kports.thread_exc.get_mut(&tid) {
            for x in a.iter_mut().skip(1) {
                if !x.privileged {
                    released.push(x.port.take());
                }
            }
        }
        let ipc = self.ipc();
        for c in released {
            super::exception::release(ipc, c);
        }
        self.darwin_ipc_notify_drain();
    }

    /// `task_deliver_crash_notification`: EXC_CORPSE_NOTIFY, its code the
    /// exception type the crash information holds and `subcode`, from the
    /// corpse's thread, at `THREAD_UNINT`, its threads' ports made anew and
    /// a send right to the corpse's port made with its no-senders
    /// notification armed; that right goes once the handler is done.
    fn darwin_deliver_crash_notification(&mut self, m: &mut crate::GuestMem<'_>, subcode: i64) {
        let Some(c) = self.dtask.corpse.as_mut() else { return };
        c.subcode = subcode;
        let code = [c.etype as i64, subcode];
        let threads = c.inspection.clone();
        for t in threads {
            self.darwin_corpse_thread_reset(t);
        }
        // convert_corpse_to_port_and_nsrequest.
        let port = self.darwin_task_port();
        let ipc = self.ipc();
        ipc.make_send(port);
        ipc.port_mut(port).nsrequest_kobject = true;
        if let Some(c) = self.dtask.corpse.as_mut() {
            c.port = Some(port);
        }
        let t = super::triage::Triage::new(super::exception::EXC_CORPSE_NOTIFY, &code, super::triage::Then::Return, true);
        self.darwin_corpse_triage(m, t);
    }

    /// `exception_triage_thread` for the corpse's thread, from level
    /// `t.level` on: a handler's request sent is waited for
    /// ([`Self::darwin_corpse_progress`]).
    fn darwin_corpse_triage(&mut self, m: &mut crate::GuestMem<'_>, mut t: super::triage::Triage) {
        use super::triage::Delivered;
        let Some((tid, ctx)) = self.dtask.corpse.as_ref().map(|c| (c.thread, c.ctx)) else { return };
        let saved = (self.tid, self.ctx_addr);
        (self.tid, self.ctx_addr) = (tid, ctx);
        let mut last = KERN_FAILURE;
        while t.level < 3 {
            let actions: Option<super::exception::ExcActions> = match t.level {
                0 => self.dtask.kports.thread_exc.get(&tid).copied(),
                1 => Some(self.dtask.kports.exc),
                _ => Some(self.darwin_host_exc("a corpse's delivery")),
            };
            t.level += 1;
            let Some(actions) = actions else { continue };
            if !self.darwin_exc_receiver_independent(t.exc, &actions) {
                continue;
            }
            match self.darwin_exception_deliver(m, &t, &actions[t.exc]) {
                Delivered::Done(r) => {
                    last = r;
                    if r == KERN_SUCCESS || r == RCV_PORT_DIED {
                        break;
                    }
                }
                Delivered::Sent(p) => {
                    (self.tid, self.ctx_addr) = saved;
                    if let Some(c) = self.dtask.corpse.as_mut() {
                        c.pending = Some(p);
                    }
                    self.darwin_ipc_settle(m);
                    // The reply may be in already.
                    self.darwin_corpse_progress(m);
                    return;
                }
            }
        }
        (self.tid, self.ctx_addr) = saved;
        self.darwin_corpse_delivered(last);
    }

    /// The handler's reply to the corpse's notification, if it is in: the
    /// notification is done, or goes on to the next level.
    pub(crate) fn darwin_corpse_progress(&mut self, m: &mut crate::GuestMem<'_>) {
        let Some((tid, ctx)) = self.dtask.corpse.as_ref().filter(|c| c.pending.is_some()).map(|c| (c.thread, c.ctx)) else { return };
        let Some(k) = self.dtask.rpc_replies.remove(&tid) else { return };
        let p = self.dtask.corpse.as_mut().and_then(|c| c.pending.take()).expect("a pending notification");
        let saved = (self.tid, self.ctx_addr);
        (self.tid, self.ctx_addr) = (tid, ctx);
        let r = self.darwin_exc_reply(m, &p, &k);
        (self.tid, self.ctx_addr) = saved;
        self.ipc().kmsg_destroy(k, true);
        self.darwin_ipc_settle(m);
        if r == KERN_SUCCESS || r == RCV_PORT_DIED {
            self.darwin_corpse_delivered(r);
        } else {
            self.darwin_corpse_triage(m, p.t);
        }
    }

    /// The notification is done (`kr`, its printf on failure going to the
    /// console): the corpse port's send right goes, which with no other
    /// sender ends the corpse.
    fn darwin_corpse_delivered(&mut self, kr: u64) {
        if kr != KERN_SUCCESS {
            crate::darwin_say!("Failed to send exception EXC_CORPSE_NOTIFY. error code: {} for pid {}", kr as i32, self.pid);
        }
        if let Some(port) = self.dtask.corpse.as_mut().and_then(|c| c.port.take()) {
            self.ipc().release_send(port);
            self.darwin_ipc_notify_drain();
        }
    }

    /// `task_port_no_senders` (a corpse's control port, the only task port
    /// that asks for it): told to the task's own kernel when another's
    /// call let go of the last send right; there the corpse ends.
    pub(crate) fn darwin_task_port_no_senders(&mut self, port: super::ipc::ObjId, mscount: u32) {
        let ipc = self.ipc();
        let owner = ipc.port(port).owner;
        if owner != ipc.task {
            if !ipc.remote(owner, super::ipc::Remote::KobjectNoSenders { port, mscount }) {
                self.darwin_unimplemented("a task port's no-senders notification for a task that has ended".into());
            }
            return;
        }
        let ours = self.dtask.corpse.is_some() && self.dtask.kports.task.is_some_and(|(k, _)| k == port);
        if !ours {
            self.darwin_unimplemented("a no-senders notification for a task port that is not a corpse's".into());
            return;
        }
        self.darwin_corpse_terminate();
    }

    /// A corpse's end: off the corpse list, `task_clear_corpse` (its
    /// threads no longer kept, their ports disabled), and
    /// `task_terminate_internal` with the rest of its task's end; the
    /// corpse in flight is no longer counted, and its kernel is let go.
    pub(crate) fn darwin_corpse_terminate(&mut self) {
        let key = self.ipc().task;
        registry().remove(&key);
        let Some(mut c) = self.dtask.corpse.take() else { return };
        c.pending_report = false;
        let keep = std::mem::take(&mut c.keep);
        let user_flags = c.user_flags;
        let coalition_key = c.coalition_key;
        drop(c);
        self.darwin_task_terminate_internal();
        // coalitions_remove_task: a corpse fork's task leaves the corpse
        // coalitions.
        if let Some(key) = coalition_key {
            super::coalition::task_terminated(key);
        }
        if user_flags & flags::HAS_REF != 0 {
            release_ref(user_flags);
        }
        drop(keep);
    }

    /// Thread calls for a corpse whose process has ended: the requests
    /// other tasks make of its ports, and its notification's progress.
    pub(crate) fn darwin_corpse_thread_calls(&mut self, m: &mut crate::GuestMem<'_>) -> bool {
        if !self.dtask.corpse.as_ref().is_some_and(|c| c.keep.0.is_some()) {
            return false;
        }
        self.darwin_ipc_remote(m);
        // thread_exception_queue_invoke: a corpse fork's notification, its
        // threads having ended (they never ran).
        if let Some(etype) = self.dtask.corpse.as_mut().and_then(|c| c.enqueued.take()) {
            if let Some(c) = self.dtask.corpse.as_mut() {
                c.etype = etype;
            }
            self.darwin_deliver_crash_notification(m, 0);
        }
        self.darwin_corpse_progress(m);
        true
    }

    /// `task_map_corpse_info_64(task, corpse_task)` (and
    /// `task_map_corpse_info`, `narrow`): a copy of the corpse's crash
    /// information mapped into this task, `CORPSEINFO_ALLOCATION_SIZE`
    /// bytes anywhere, tagged VM_MEMORY_CORPSEINFO; its address and size.
    /// The corpse is converted as a read port (corpses allowed, the
    /// platform binary check made); this task must not be one.
    pub(crate) fn darwin_task_map_corpse_info(&mut self, corpse: Option<super::ipc::right::Carried>, narrow: bool) -> super::kobject::Reply {
        use super::ipc::right::Carried;
        use super::ipc::Kobject;
        use super::kobject::Reply;
        let target = match corpse {
            Some(Carried::Port(p)) => {
                let ipc = self.ipc();
                let port = ipc.port(p);
                match port.kobject {
                    Some(Kobject::Task | Kobject::TaskRead) if port.active => Some(port.owner),
                    _ => None,
                }
            }
            _ => None,
        };
        let Some(owner) = target else { return Reply::err(KERN_INVALID_ARGUMENT) };
        // task_conversion_eval for the read flavor: a platform binary's
        // task only for a platform binary.
        let victim_platform = self.ipc().links.get(&owner).and_then(|l| l.codesign.as_ref()).is_some_and(|c| c.platform_binary);
        let me_platform = self.dtask.codesign.as_ref().is_some_and(|c| c.platform_binary);
        if owner != self.ipc().task && victim_platform && !me_platform {
            return Reply::err(KERN_INVALID_ARGUMENT);
        }
        if self.dtask.corpse.is_some() {
            return Reply::err(KERN_INVALID_ARGUMENT);
        }
        let Some(info) = find(owner) else { return Reply::err(KERN_INVALID_ARGUMENT) };
        const VM_FLAGS_ANYWHERE: u64 = 1;
        let r = self.darwin_own_memory(|k, m| {
            let mut addr = 0;
            let kr = k.darwin_vm_map_anon(m, &mut addr, CORPSEINFO_ALLOCATION_SIZE as u64, 0, VM_FLAGS_ANYWHERE | u64::from(VM_MEMORY_CORPSEINFO) << 24);
            if kr == KERN_SUCCESS {
                // copyout: a failure is not the call's.
                let _ = m.kernel().write(addr, &info.info);
            }
            (kr, addr)
        });
        match r {
            Ok((KERN_SUCCESS, addr)) => {
                let mut out = addr.to_le_bytes().to_vec();
                if narrow {
                    out.extend_from_slice(&(CORPSEINFO_ALLOCATION_SIZE as u32).to_le_bytes());
                } else {
                    out.extend_from_slice(&(CORPSEINFO_ALLOCATION_SIZE as u64).to_le_bytes());
                }
                Reply::ok(out)
            }
            Ok((kr, _)) => Reply::err(kr as i32),
            Err(r) => r,
        }
    }
}

/// The corpses whose process's end is not yet published, by pid: their
/// kernels, held by the corpse ([`hold`]).
fn held() -> std::sync::MutexGuard<'static, std::collections::HashMap<i32, std::sync::Weak<std::sync::Mutex<crate::syscalls::Kernel>>>> {
    static H: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<i32, std::sync::Weak<std::sync::Mutex<crate::syscalls::Kernel>>>>> = std::sync::OnceLock::new();
    H.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner())
}

/// A process's task has ended as its process did
/// ([`crate::syscalls::Kernel::darwin_task_terminate`]): a corpse's kernel
/// is kept, by the corpse, until the corpse ends, whatever its host does
/// with it.
pub fn hold(kernel: &std::sync::Arc<std::sync::Mutex<crate::syscalls::Kernel>>) {
    let mut k = kernel.lock().unwrap_or_else(|e| e.into_inner());
    if !k.dtask.corpse.as_ref().is_some_and(|c| c.pending_report && c.keep.0.is_none()) {
        return;
    }
    let pid = k.pid;
    let me: Box<dyn std::any::Any + Send> = Box::new(std::sync::Arc::clone(kernel));
    if let Some(c) = k.dtask.corpse.as_mut() {
        c.keep.0 = Some(me);
    }
    held().insert(pid, std::sync::Arc::downgrade(kernel));
}

/// Process `pid`'s end is published (`proc_exit` is done): if its task is
/// a corpse, its last thread's work follows ([`hold`] kept it).
pub fn exited(pid: i32) {
    let Some(kernel) = held().remove(&pid).and_then(|w| w.upgrade()) else { return };
    let mut k = kernel.lock().unwrap_or_else(|e| e.into_inner());
    let Some(vm) = k.dtask.corpse.as_ref().and_then(|c| c.vm.clone()) else {
        k.darwin_unimplemented("a corpse on a host with no view of its process's memory".into());
        k.darwin_corpse_terminate();
        return;
    };
    let k = &mut *k;
    vm.mem.with_guest(&mut |m| k.darwin_corpse_last_thread(m));
    k.darwin_ipc_leave();
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: u64 = CF_PAGE;

    #[test]
    fn a_corpse_footprint_is_sized_as_xnu_sizes_it() {
        // The header, 15 bytes an entry, a byte a page, page rounded.
        assert_eq!(Footprint::new(2, 4 * P).size(), P);
        // At most 256 KB on an embedded kernel.
        assert_eq!(Footprint::new(10, 1 << 40).size(), CF_MAX_SIZE);
    }

    #[test]
    fn a_corpse_footprint_packs_dispositions_into_regions() {
        let a = 0x1_0000_0000;
        let mut f = Footprint::new(2, 8 * P);
        // A zero first only moves the region's start; a trailing zero is
        // dropped when the collection is done.
        let d = [0, 0xd, 0x80d, 0];
        assert!(f.collect(a, a + 4 * P, |va| d[((va - a) / P) as usize]));
        assert_eq!((f.vaddr(CF_HEADER), f.num(CF_HEADER), f.last_zeroes), (a + P, 3, 1));
        // A far entry: a new region, word aligned after the last.
        let b = a + 0x100 * P;
        assert!(f.collect(b, b + 2 * P, |_| 0x85));
        let second = (CF_HEADER + CF_REGION + 2).next_multiple_of(4);
        assert_eq!(f.last_region, second);
        assert_eq!((f.vaddr(second), f.num(second)), (b, 2));
        let count = footprint_stat("count").unwrap();
        f.done();
        assert!(footprint_stat("count").unwrap() > count);
        assert_eq!(f.size(), P);
        // The reusable bit kept in the fictitious one, and given back.
        assert_eq!(f.buf[(CF_HEADER + CF_REGION + 1) as usize], 0x0f);
        assert_eq!(f.query(a + P), 0xd);
        assert_eq!(f.query(a + 2 * P), 0x80d);
        assert_eq!(f.query(a), 0);
        assert_eq!(f.query(a + 3 * P), 0);
        assert_eq!(f.query(b + P), 0x85);
        assert_eq!(f.query(b + 2 * P), 0);
    }

    #[test]
    fn a_corpse_footprint_fills_gaps_with_zeroes_when_cheaper() {
        let a = 0x2_0000_0000;
        let mut f = Footprint::new(2, 8 * P);
        assert!(f.collect(a, a + P, |_| 0xd));
        // Two pages of gap cost less than a region header: zeroes.
        assert!(f.collect(a + 3 * P, a + 4 * P, |_| 0xd));
        assert_eq!((f.last_region, f.num(CF_HEADER)), (CF_HEADER, 4));
        assert_eq!(f.query(a + P), 0);
        assert_eq!(f.query(a + 3 * P), 0xd);
    }

    #[test]
    fn a_full_corpse_footprint_is_counted() {
        let a = 0x3_0000_0000;
        // One page of buffer for more pages than it holds.
        let mut f = Footprint::new(1, P);
        let full = footprint_stat("full").unwrap();
        assert!(!f.collect(a, a + 2 * P * P, |_| 0xd));
        assert!(footprint_stat("full").unwrap() > full);
    }

    #[test]
    fn the_gate_counts_corpses_and_user_faults() {
        // One test owns the gate: the counts are the system's.
        assert_eq!(total_corpses_count(), 0);
        for _ in 0..TOTAL_CORPSES_ALLOWED {
            get_ref(flags::HAS_REF, ("test", 1)).unwrap();
        }
        assert_eq!(get_ref(flags::HAS_REF, ("test", 1)), Err(6));
        release_ref(flags::HAS_REF);
        get_ref(flags::HAS_REF | flags::USER_FAULT, ("test", 1)).unwrap();
        assert_eq!(total_user_faults_count(), 1);
        release_ref(flags::HAS_REF);
        // a second user fault is refused while one is in flight
        assert_eq!(get_ref(flags::HAS_REF | flags::USER_FAULT, ("test", 1)), Err(6));
        release_ref(flags::HAS_REF | flags::USER_FAULT);
        assert_eq!(total_corpses_count(), 3);
        for _ in 0..3 {
            release_ref(flags::HAS_REF);
        }
        assert_eq!(INFLIGHT.load(Ordering::Relaxed), 0);
    }
}
