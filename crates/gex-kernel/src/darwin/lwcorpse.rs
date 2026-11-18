//! Lightweight corpses (xnu-10063.141.1: `osfmk/corpses/corpse.c`'s
//! `task_enqueue_exception_with_corpse` and `task_map_kcdata_object_64`,
//! `bsd/kern/kern_exit.c`'s `current_thread_collect_backtrace_info`,
//! `osfmk/kern/kern_cdata.c`'s kcdata objects, `osfmk/kern/exception.c`'s
//! `exception_deliver_backtrace`): for a simulated EXC_GUARD whose
//! EXC_CORPSE_NOTIFY handler prefers backtraces
//! (MACH_EXCEPTION_BACKTRACE_PREFERRED, which launchd asks of its
//! children's), the faulting thread's backtrace and the process's crash
//! facts in a kcdata buffer (TASK_BTINFO_*), held by a kcdata object whose
//! port goes to the handler in `mach_exception_raise_backtrace`, in place
//! of a corpse fork.
//!
//! Checked against the 21H461 kernelcache: the enqueue
//! (0xfffffff0072871e8) takes the thread, task and host handlers' ports in
//! that order (behavior byte 3 bit 5) and the LW_CORPSE throttle at 15; the
//! collector (0xfffffff0076204b4) writes the items in the source's order,
//! its buffer 0x5000 bytes begun with 0x46414E47.

use super::kcdata::Kcdata;
use crate::syscalls::Kernel;
use crate::GuestMem;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::Mutex;

/// `BTINFO_ALLOCATION_SIZE`, `KCDATA_BUFFER_BEGIN_BTINFO`.
pub const BTINFO_ALLOCATION_SIZE: usize = 20 * 1024;
const BUFFER_BEGIN_BTINFO: u32 = 0x4641_4E47;
/// `MAX_INFLIGHT_KCOBJECT_LW_CORPSE`.
const MAX_INFLIGHT: i32 = 15;
/// `VM_MEMORY_BTINFO`.
pub const VM_MEMORY_BTINFO: u32 = 105;

/// `TASK_BTINFO_*` (`kcdata.h`).
mod ty {
    pub const PID: u32 = 0xA01;
    pub const PPID: u32 = 0xA02;
    pub const PROC_NAME: u32 = 0xA03;
    pub const PROC_PATH: u32 = 0xA04;
    pub const UID: u32 = 0xA05;
    pub const GID: u32 = 0xA06;
    pub const PROC_FLAGS: u32 = 0xA07;
    pub const CPUTYPE: u32 = 0xA08;
    pub const EXCEPTION_CODES: u32 = 0xA09;
    pub const EXCEPTION_TYPE: u32 = 0xA0A;
    pub const RUSAGE_INFO: u32 = 0xA0B;
    pub const COALITION_ID: u32 = 0xA0C;
    pub const CRASH_COUNT: u32 = 0xA0D;
    pub const THROTTLE_TIMEOUT: u32 = 0xA0E;
    pub const THREAD_ID: u32 = 0xA20;
    pub const THREAD_NAME: u32 = 0xA21;
    pub const THREAD_STATE: u32 = 0xA22;
    pub const THREAD_EXCEPTION_STATE: u32 = 0xA23;
    pub const BACKTRACE64: u32 = 0xA25;
    pub const ASYNC_BACKTRACE64: u32 = 0xA26;
    pub const ASYNC_START_INDEX: u32 = 0xA27;
    pub const PLATFORM: u32 = 0xA28;
    pub const SC_LOADINFO64: u32 = 0xA2A;
    /// KCDATA_TYPE_LIBRARY_LOADINFO64.
    pub const DYLD_LOADINFO64: u32 = 0x31;
    pub const FLAGS: u32 = 0xAFF;
    pub const EXIT_REASON_SNAPSHOT: u32 = 0x1001;
}

/// `TASK_BTINFO_FLAG_*`.
mod btflag {
    pub const BT_TRUNCATED: u32 = 0x1;
    pub const ASYNC_BT_TRUNCATED: u32 = 0x2;
    pub const TASK_TERMINATED: u32 = 0x4;
    pub const KCDATA_INCOMPLETE: u32 = 0x8;
}

const KERN_SUCCESS: u64 = 0;
const KERN_FAILURE: u64 = 5;
const KERN_RESOURCE_SHORTAGE: u64 = 6;
const KERN_MEMORY_ERROR: u64 = 10;
const KERN_TERMINATED: i32 = 37;
const RCV_PORT_DIED: u64 = 0x1000_4009;

/// `lw_corpse_obj_cnt`: the lightweight corpses' kcdata objects in flight.
static LW_CORPSE_OBJ_CNT: AtomicI32 = AtomicI32::new(0);

/// `kcdata_object_throttle_get(KCDATA_OBJECT_TYPE_LW_CORPSE)`.
pub fn throttle_get() -> Result<(), u64> {
    let mut old = LW_CORPSE_OBJ_CNT.load(Ordering::Relaxed);
    loop {
        if old >= MAX_INFLIGHT {
            super::corpse::kernel_log(format!("Too many lightweight corpse in flight: {old}"));
            return Err(KERN_RESOURCE_SHORTAGE);
        }
        match LW_CORPSE_OBJ_CNT.compare_exchange(old, old + 1, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Ok(()),
            Err(v) => old = v,
        }
    }
}

/// `kcdata_object_throttle_release`.
pub fn throttle_release() {
    let n = LW_CORPSE_OBJ_CNT.fetch_sub(1, Ordering::Relaxed);
    assert!(n > 0, "Lightweight corpse kcdata object over-released");
}

/// A kcdata object (`struct kcdata_object`): its buffer, its references,
/// and its port once made (`ko_port`).
struct Object {
    data: std::sync::Arc<Vec<u8>>,
    refs: u32,
    port: Option<super::ipc::ObjId>,
}

fn objects() -> std::sync::MutexGuard<'static, HashMap<u64, Object>> {
    static O: std::sync::OnceLock<Mutex<HashMap<u64, Object>>> = std::sync::OnceLock::new();
    O.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner())
}

static NEXT_OBJECT: AtomicU64 = AtomicU64::new(1);

/// `kcdata_create_object`: an object holding `data`, one reference (the
/// throttle slot taken for it goes with it).
fn create(data: Vec<u8>) -> u64 {
    let id = NEXT_OBJECT.fetch_add(1, Ordering::Relaxed);
    objects().insert(id, Object { data: std::sync::Arc::new(data), refs: 1, port: None });
    id
}

/// `kcdata_object_reference`.
fn reference(id: u64) {
    if let Some(o) = objects().get_mut(&id) {
        o.refs += 1;
    }
}

/// `kcdata_object_release`: with its last reference the object goes, and
/// its throttle slot (`kcdata_object_destroy`). Its port, if any, is the
/// caller's to destroy.
fn release(id: u64) -> Option<super::ipc::ObjId> {
    let mut t = objects();
    let o = t.get_mut(&id)?;
    o.refs -= 1;
    if o.refs > 0 {
        return None;
    }
    let o = t.remove(&id)?;
    drop(t);
    throttle_release();
    o.port
}

/// `convert_port_to_kcdata_object`'s object: its buffer.
pub fn data(id: u64) -> Option<std::sync::Arc<Vec<u8>>> {
    objects().get(&id).map(|o| std::sync::Arc::clone(&o.data))
}

/// The pseudo-thread the kernel's backtrace delivery waits on its replies
/// as (`thread_backtrace_queue`'s daemon).
const DAEMON_TID: i32 = i32::MIN;

/// One `thread_backtrace_enqueue`d delivery: the object, the handlers'
/// send rights (thread, task, host), the next to try, and whether its
/// request waits for a reply.
#[derive(Debug)]
pub struct Delivery {
    obj: u64,
    ports: [Option<super::ipc::ObjId>; 3],
    at: usize,
    port: Option<super::ipc::ObjId>,
    waiting: bool,
}

/// What `backtrace_user` gives: its frames, error, truncation, and the
/// async frame it found (start index and context address).
struct Walk {
    frames: Vec<u64>,
    error: bool,
    truncated: bool,
    async_index: u32,
    async_addr: u64,
}

/// `backtrace_user` of a 64-bit thread whose pc and fp are `pc` and `fp`
/// (or, `custom`, from frame `fp` with no pc), at most `max` frames, each
/// return address plus `offset`, its frames read as `copyin` reads them.
fn walk(m: &GuestMem<'_>, pc: u64, fp: u64, custom: bool, offset: u64, max: usize) -> Walk {
    const SWIFT_ASYNC_FP_BIT: u64 = 1 << 60;
    let invalid = |fp: u64| fp & 0x3 != 0;
    let mut w = Walk { frames: Vec::new(), error: false, truncated: false, async_index: 0, async_addr: 0 };
    let mut fp = fp;
    let mut allow_async = true;
    if !custom {
        w.frames.push(pc.wrapping_add(offset));
    }
    'out: {
        if w.frames.len() >= max || fp == 0 {
            break 'out;
        }
        if invalid(fp) {
            w.error = true;
            w.truncated = true;
            break 'out;
        }
        while fp != 0 && w.frames.len() < max {
            let (Ok(next), Ok(ret)) = (m.read_u64(fp), m.read_u64(fp.wrapping_add(8))) else {
                w.error = true;
                w.truncated = true;
                break 'out;
            };
            w.frames.push(ret.wrapping_add(offset));
            if allow_async && next & SWIFT_ASYNC_FP_BIT != 0 {
                w.async_index = (w.frames.len() - 1) as u32;
                let Ok(ctx) = m.read_u64(fp.wrapping_sub(8)) else {
                    w.error = true;
                    break 'out;
                };
                w.async_addr = ctx;
                allow_async = false;
            }
            let next = next & !SWIFT_ASYNC_FP_BIT;
            if invalid(next) {
                break;
            }
            if next == fp || (!custom && next < fp) {
                break;
            }
            fp = next;
        }
    }
    let out_of_space = !invalid(fp) && w.frames.len() == max;
    w.truncated |= out_of_space;
    w
}

impl Kernel {
    /// `task_should_generate_lightweight_corpse` for this task's current
    /// thread (lw_corpses_enabled on an embedded kernel): the thread's,
    /// task's and host's EXC_CORPSE_NOTIFY handlers, in that order, a copy
    /// of each one's send right that prefers backtraces; none if none does.
    pub(crate) fn darwin_lightweight_corpse_ports(&mut self) -> Option<[Option<super::ipc::ObjId>; 3]> {
        use super::exception::EXC_CORPSE_NOTIFY;
        use super::ipc::right::Carried;
        const MACH_EXCEPTION_BACKTRACE_PREFERRED: i32 = 0x2000_0000;
        let thread = self.dtask.kports.thread_exc.get(&self.tid).map(|a| a[EXC_CORPSE_NOTIFY]);
        let task = Some(self.dtask.kports.exc[EXC_CORPSE_NOTIFY]);
        let host = Some(self.ipc().host_exc[EXC_CORPSE_NOTIFY]);
        let mut out = [None; 3];
        let mut any = false;
        for (i, a) in [thread, task, host].into_iter().enumerate() {
            let Some(a) = a else { continue };
            if let Some(Carried::Port(p)) = a.port {
                if a.behavior & MACH_EXCEPTION_BACKTRACE_PREFERRED != 0 {
                    self.ipc().copy_send(p);
                    out[i] = Some(p);
                    any = true;
                }
            }
        }
        any.then_some(out)
    }

    /// The handlers' rights a lightweight corpse that was not enqueued
    /// held, let go.
    pub(crate) fn darwin_lw_ports_release(&mut self, ports: [Option<super::ipc::ObjId>; 3]) {
        let ipc = self.ipc();
        for p in ports.into_iter().flatten() {
            ipc.release_send(p);
        }
        self.darwin_ipc_notify_drain();
    }

    /// The lightweight half of `task_enqueue_exception_with_corpse`, its
    /// throttle slot taken, with this task's threads held still by the
    /// host (`m` its memory) and thread `tid` the faulting one, waiting in
    /// its call: `current_thread_collect_backtrace_info`, then
    /// `kcdata_create_object` and `thread_backtrace_enqueue`, or the
    /// failure (the slot and the handlers' rights let go).
    #[allow(clippy::too_many_arguments)]
    pub fn darwin_lw_corpse(&mut self, m: &mut GuestMem<'_>, tid: i32, etype: usize, code: [i64; 2], reason: Option<std::sync::Arc<super::reason::OsReason>>, ports: [Option<super::ipc::ObjId>; 3]) -> u64 {
        match self.darwin_collect_backtrace_info(m, tid, etype, code, reason.as_deref()) {
            Ok(k) => {
                let obj = create(k.bytes().to_vec());
                self.dtask.bt_deliveries.push_back(Delivery { obj, ports, at: 0, port: None, waiting: false });
                self.dtask.timers.bell().ring();
                let name = self.darwin_best_name();
                super::corpse::kernel_log(format!("Lightweight corpse enqueued for {name}"));
                KERN_SUCCESS
            }
            Err(kr) => {
                throttle_release();
                self.darwin_lw_ports_release(ports);
                kr
            }
        }
    }

    /// `current_thread_collect_backtrace_info` for thread `tid` of this
    /// (64-bit) process.
    fn darwin_collect_backtrace_info(&mut self, m: &mut GuestMem<'_>, tid: i32, etype: usize, code: [i64; 2], reason: Option<&super::reason::OsReason>) -> Result<Kcdata, u64> {
        use gex_abi::ctx;
        const MAX_FRAMES: usize = 100;
        const MAXCOMLEN_1: usize = 17;
        const MAXPATHLEN: usize = 1024;
        const MAXTHREADNAMESIZE: usize = 64;
        const ARM_THREAD_STATE: i32 = 1;
        const ARM_UNIFIED_THREAD_STATE_COUNT: u32 = 70;
        const ARM_EXCEPTION_STATE64: i32 = 7;
        const ARM_EXCEPTION_STATE64_COUNT: u32 = 4;
        const CPU_TYPE_ARM64: u32 = 0x0100_000C;
        const P_LP64: u32 = 0x4;
        const P_SUGID: u32 = 0x100;
        const ALL_IMAGE_INFOS_SIZE: usize = 344;
        const UUID_INFO_SIZE: usize = 24;
        let c = if tid == self.tid { self.ctx_addr } else { self.thread_signals.get(tid).map_or(0, |t| t.ctx()) };
        let pc = m.kernel().read_u64(c + ctx::PC as u64).unwrap_or(0);
        let fp = m.kernel().read_u64(c + ctx::x(29) as u64).unwrap_or(0);
        let mut flags = 0u32;
        let bt = walk(m, pc, fp, false, 0, MAX_FRAMES);
        if bt.error || bt.frames.is_empty() {
            return Err(KERN_FAILURE);
        }
        if bt.truncated {
            flags |= btflag::BT_TRUNCATED;
        }
        let mut k = Kcdata::alloc_init(BUFFER_BEGIN_BTINFO, BTINFO_ALLOCATION_SIZE, 0).ok_or(KERN_RESOURCE_SHORTAGE)?;
        let flags_at = k.get_memory_addr(ty::FLAGS, 4).map_err(|_| KERN_RESOURCE_SHORTAGE)?;
        let words = |v: &[u64]| -> Vec<u8> { v.iter().flat_map(|x| x.to_le_bytes()).collect() };
        k.put_array(ty::BACKTRACE64, 8, bt.frames.len() as u32, &words(&bt.frames));
        if bt.async_addr != 0 {
            k.put(ty::ASYNC_START_INDEX, &bt.async_index.to_le_bytes());
            // BTCTL_ASYNC_ADDR_OFFSET: each return address plus 1.
            let a = walk(m, 0, bt.async_addr, true, 1, MAX_FRAMES);
            if !a.error && !a.frames.is_empty() {
                k.put_array(ty::ASYNC_BACKTRACE64, 8, a.frames.len() as u32, &words(&a.frames));
            }
            if a.truncated {
                flags |= btflag::ASYNC_BT_TRUNCATED;
            }
        }
        // The image infos (the task held still): the shared cache's load
        // info, then the images' UUIDs. A copyin that fails leaves zeros.
        let infos = m.read(self.darwin_dyld_infos, ALL_IMAGE_INFOS_SIZE).map(|b| b.to_vec()).unwrap_or_else(|_| vec![0; ALL_IMAGE_INFOS_SIZE]);
        let u64_at = |o: usize| u64::from_le_bytes(infos[o..o + 8].try_into().unwrap());
        let uuid_count = u64_at(88) as u32;
        let uuid_addr = u64_at(96);
        let mut sc = u64_at(152).to_le_bytes().to_vec();
        sc.extend_from_slice(&infos[160..176]);
        sc.extend_from_slice(&u64_at(176).to_le_bytes());
        k.put(ty::SC_LOADINFO64, &sc);
        if uuid_addr == 0 {
            return Err(KERN_MEMORY_ERROR);
        }
        if uuid_count > 0 {
            if let Ok(at) = k.get_memory_addr_for_array(ty::DYLD_LOADINFO64, UUID_INFO_SIZE as u32, uuid_count) {
                let Ok(b) = m.read(uuid_addr, UUID_INFO_SIZE * uuid_count as usize) else { return Err(KERN_MEMORY_ERROR) };
                k.memcpy(at, b);
            }
        }
        // The thread's unified state and its 64-bit exception state.
        for (t, fl, count) in [(ty::THREAD_STATE, ARM_THREAD_STATE, ARM_UNIFIED_THREAD_STATE_COUNT), (ty::THREAD_EXCEPTION_STATE, ARM_EXCEPTION_STATE64, ARM_EXCEPTION_STATE64_COUNT)] {
            if let Ok(at) = k.get_memory_addr(t, 8 + 4 * count) {
                match self.machine_thread_get_state(&m.kernel(), tid, c, fl, count) {
                    Ok(w) => {
                        let mut b = (fl as u32).to_le_bytes().to_vec();
                        b.extend_from_slice(&(w.len() as u32).to_le_bytes());
                        b.extend(w.iter().flat_map(|x| x.to_le_bytes()));
                        k.memcpy(at, &b);
                    }
                    Err(e) => {
                        k.memcpy(at, &vec![0u8; 8 + 4 * count as usize]);
                        if e == KERN_TERMINATED {
                            flags |= btflag::TASK_TERMINATED;
                        }
                    }
                }
            }
        }
        let pid = self.pid;
        let Some((public, _)) = self.darwin_public(pid) else {
            self.darwin_unimplemented("a lightweight corpse's facts of a process with no record of its own".into());
            return Err(KERN_FAILURE);
        };
        k.put(ty::PID, &pid.to_le_bytes());
        k.put(ty::PPID, &self.procs.ppid(pid).to_le_bytes());
        let mut comm = [0u8; MAXCOMLEN_1];
        let n = public.comm.len().min(MAXCOMLEN_1 - 1);
        comm[..n].copy_from_slice(&public.comm[..n]);
        k.put(ty::PROC_NAME, &comm);
        let coalitions = super::coalition::membership(pid).0;
        let ids: Vec<u8> = coalitions.iter().flat_map(|x| x.to_le_bytes()).collect();
        k.put_array(ty::COALITION_ID, 8, coalitions.len() as u32, &ids);
        // RUSAGE_INFO_V0, footprint 0, no exit time (a soft crash).
        let bills = self.darwin_bank_bills(pid, self.dtask.uniqueid, &std::sync::Arc::clone(&self.dtask.rusage));
        let record = super::rusage::crash_record(&self.procs, pid, &public, bills, false);
        k.put(ty::RUSAGE_INFO, &record.bytes()[..super::rusage::size_of(0).expect("RUSAGE_INFO_V0")]);
        k.put(ty::PLATFORM, &self.dtask.platform.0.to_le_bytes());
        let mut path = vec![0u8; MAXPATHLEN];
        let n = public.path.len().min(MAXPATHLEN - 1);
        path[..n].copy_from_slice(&public.path[..n]);
        k.put(ty::PROC_PATH, &path);
        k.put(ty::UID, &self.dtask.cred.uid.to_le_bytes());
        k.put(ty::GID, &self.dtask.cred.gid().to_le_bytes());
        let pflags = P_LP64 | if self.dtask.sugid { P_SUGID } else { 0 };
        k.put(ty::PROC_FLAGS, &pflags.to_le_bytes());
        k.put(ty::CPUTYPE, &CPU_TYPE_ARM64.to_le_bytes());
        k.put(ty::EXCEPTION_TYPE, &(etype as i32).to_le_bytes());
        k.put(ty::CRASH_COUNT, &self.dtask.crash_count.to_le_bytes());
        k.put(ty::THROTTLE_TIMEOUT, &self.dtask.throttle_timeout.to_le_bytes());
        let mut codes = code[0].to_le_bytes().to_vec();
        codes.extend_from_slice(&code[1].to_le_bytes());
        k.put(ty::EXCEPTION_CODES, &codes);
        if let Some(r) = reason {
            let mut ers = r.namespace.to_le_bytes().to_vec();
            ers.extend_from_slice(&r.code.to_le_bytes());
            ers.extend_from_slice(&r.flags.to_le_bytes());
            k.put(ty::EXIT_REASON_SNAPSHOT, &ers);
            let data = r.data();
            if !data.is_empty() {
                k.put(super::kcdata::TYPE_NESTED_KCDATA, data);
            }
        }
        let mut name = [0u8; MAXTHREADNAMESIZE];
        if let Some(n) = self.thread_signals.get(tid).and_then(|t| t.name()) {
            let l = n.len().min(MAXTHREADNAMESIZE - 1);
            name[..l].copy_from_slice(&n[..l]);
        }
        k.put(ty::THREAD_NAME, &name);
        // thread_info(THREAD_IDENTIFIER_INFO) of the current thread, which
        // is active.
        let id = self.darwin_thread_tid(tid);
        match k.get_memory_addr(ty::THREAD_ID, 8) {
            Ok(at) => k.memcpy(at, &id.to_le_bytes()),
            Err(_) => flags |= btflag::KCDATA_INCOMPLETE,
        }
        k.memcpy(flags_at, &flags.to_le_bytes());
        Ok(k)
    }

    /// `thread_backtrace_queue_invoke`'s `exception_deliver_backtrace`, as
    /// this task's thread calls run it: each enqueued object's port (made
    /// with its no-senders notification armed) sent to the thread's, task's
    /// and host's handlers in turn in `mach_exception_raise_backtrace`
    /// (EXC_CORPSE_NOTIFY, codes {etype, 0}) until one answers with
    /// success or is gone, the reply waited for at each; then the port's
    /// send right, the handlers' rights and the object's reference let go.
    pub(crate) fn darwin_bt_deliveries(&mut self, m: &mut GuestMem<'_>) {
        while let Some(mut d) = self.dtask.bt_deliveries.pop_front() {
            if d.port.is_none() {
                // kcdata_object_reference, then convert_kcdata_object_to_port
                // (the reference consumed).
                reference(d.obj);
                d.port = Some(self.darwin_kcdata_object_port(d.obj));
            }
            loop {
                if d.waiting {
                    let Some(k) = self.dtask.rpc_replies.remove(&DAEMON_TID) else {
                        self.dtask.bt_deliveries.push_front(d);
                        return;
                    };
                    d.waiting = false;
                    let kr = mig_reply_code(&k);
                    self.ipc().kmsg_destroy(k, true);
                    self.darwin_ipc_settle(m);
                    d.at = if kr == KERN_SUCCESS || kr == RCV_PORT_DIED { 3 } else { d.at + 1 };
                }
                let Some(at) = (d.at..3).find(|&i| d.ports[i].is_some_and(|p| self.ipc().port(p).active)) else { break };
                d.at = at;
                self.darwin_raise_backtrace(d.ports[at].expect("found above"), d.port.expect("made above"));
                d.waiting = true;
                self.darwin_ipc_settle(m);
            }
            let ipc = self.ipc();
            if let Some(p) = d.port {
                ipc.release_send(p);
            }
            for p in d.ports.into_iter().flatten() {
                ipc.release_send(p);
            }
            self.darwin_ipc_notify_drain();
            if let Some(port) = release(d.obj) {
                self.darwin_kcdata_port_destroy(port);
            }
        }
    }

    /// `convert_kcdata_object_to_port`: a send right to the object's port,
    /// made at first with its no-senders notification armed
    /// (`ipc_kobject_make_send_lazy_alloc_port`); a reference of the
    /// object's is the port's while it has senders.
    fn darwin_kcdata_object_port(&mut self, obj: u64) -> super::ipc::ObjId {
        let existing = objects().get(&obj).and_then(|o| o.port);
        let ipc = self.ipc();
        let port = match existing {
            Some(p) => p,
            None => {
                let p = ipc.kobject_port(super::ipc::Kobject::KcdataObject(obj));
                if let Some(o) = objects().get_mut(&obj) {
                    o.port = Some(p);
                }
                p
            }
        };
        let had = ipc.port(port).srights > 0;
        ipc.make_send(port);
        if had {
            // The port holds a reference already.
            if let Some(p) = release(obj) {
                self.darwin_kcdata_port_destroy(p);
            }
        } else {
            ipc.port_mut(port).nsrequest_kobject = true;
        }
        port
    }

    /// The port of an object that has gone.
    fn darwin_kcdata_port_destroy(&mut self, port: super::ipc::ObjId) {
        let ipc = self.ipc();
        ipc.port_mut(port).kobject = None;
        ipc.port_destroy(port);
        self.darwin_ipc_notify_drain();
    }

    /// `kcdata_object_no_senders`: the port's reference released.
    pub(crate) fn darwin_kcdata_object_no_senders(&mut self, port: super::ipc::ObjId, obj: u64) {
        if let Some(p) = release(obj) {
            debug_assert_eq!(p, port);
            self.darwin_kcdata_port_destroy(p);
        }
    }

    /// `mach_exception_raise_backtrace(exception_port, kcdata_object,
    /// EXC_CORPSE_NOTIFY, {EXC_GUARD, 0})` from the kernel's daemon: the
    /// object's port copied, the reply to its RPC port.
    fn darwin_raise_backtrace(&mut self, target: super::ipc::ObjId, obj_port: super::ipc::ObjId) {
        use super::ipc::msg::Desc;
        use super::ipc::right::Carried;
        const MACH_EXCEPTION_RAISE_BACKTRACE: i32 = 2409;
        let ipc = self.ipc();
        ipc.copy_send(obj_port);
        let mut body = 1u32.to_le_bytes().to_vec();
        body.extend_from_slice(&[0u8; 12]);
        body.extend_from_slice(&super::mig::NDR_RECORD);
        body.extend_from_slice(&(super::exception::EXC_CORPSE_NOTIFY as i32).to_le_bytes());
        body.extend_from_slice(&2u32.to_le_bytes());
        body.extend_from_slice(&(super::exception::EXC_GUARD as i64).to_le_bytes());
        body.extend_from_slice(&0i64.to_le_bytes());
        let descs = vec![Desc::Port { off: 4, right: Some(Carried::Port(obj_port)), raw: 0, disp: super::ipc::right::msgt::PORT_SEND }];
        let saved = self.tid;
        self.tid = DAEMON_TID;
        self.darwin_exc_send(target, MACH_EXCEPTION_RAISE_BACKTRACE, body, descs);
        self.tid = saved;
    }

    /// `task_map_kcdata_object_64(task, kcdata_object)`: a copy of the
    /// object's buffer, BTINFO_ALLOCATION_SIZE bytes, mapped anywhere in
    /// this task tagged VM_MEMORY_BTINFO; its address and size. A corpse,
    /// or a port that is no kcdata object's, is refused.
    pub(crate) fn darwin_task_map_kcdata_object(&mut self, obj: Option<super::ipc::right::Carried>) -> super::kobject::Reply {
        use super::ipc::right::Carried;
        use super::kobject::Reply;
        const KERN_INVALID_ARGUMENT: i32 = 4;
        const VM_FLAGS_ANYWHERE: u64 = 1;
        let id = match obj {
            Some(Carried::Port(p)) => match self.ipc().port(p).kobject {
                Some(super::ipc::Kobject::KcdataObject(id)) => Some(id),
                _ => None,
            },
            _ => None,
        };
        let Some(buf) = id.and_then(data) else { return Reply::err(KERN_INVALID_ARGUMENT) };
        if self.dtask.corpse.is_some() {
            return Reply::err(KERN_INVALID_ARGUMENT);
        }
        let r = self.darwin_own_memory(|k, m| {
            let mut addr = 0;
            let kr = k.darwin_vm_map_anon(m, &mut addr, BTINFO_ALLOCATION_SIZE as u64, 0, VM_FLAGS_ANYWHERE | u64::from(VM_MEMORY_BTINFO) << 24);
            if kr == 0 {
                // copyout: a failure is not the call's.
                let _ = m.kernel().write(addr, &buf);
            }
            (kr, addr)
        });
        match r {
            Ok((0, addr)) => {
                let mut out = addr.to_le_bytes().to_vec();
                out.extend_from_slice(&(BTINFO_ALLOCATION_SIZE as u64).to_le_bytes());
                Reply::ok(out)
            }
            Ok((kr, _)) => Reply::err(kr as i32),
            Err(r) => r,
        }
    }
}

/// The return code of a MIG reply to the kernel's request: MIG_SERVER_DIED
/// for the send-once notification of a reply right destroyed unanswered,
/// MIG_REPLY_MISMATCH for another id, MIG_TYPE_ERROR for a complex or
/// short one, else its RetCode.
fn mig_reply_code(k: &super::ipc::msg::Kmsg) -> u64 {
    const MIG_TYPE_ERROR: i32 = -300;
    const MIG_REPLY_MISMATCH: i32 = -301;
    const MIG_SERVER_DIED: i32 = -308;
    const NOTIFY_SEND_ONCE: i32 = 0x47;
    let err = |e: i32| e as u32 as u64;
    if k.id != 2409 + 100 {
        return err(if k.id == NOTIFY_SEND_ONCE { MIG_SERVER_DIED } else { MIG_REPLY_MISMATCH });
    }
    if k.bits & super::ipc::msg::bits::COMPLEX != 0 || k.body.len() < 12 {
        return err(MIG_TYPE_ERROR);
    }
    err(i32::from_le_bytes(k.body[8..12].try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_pointer_walk_stops_where_backtrace_user_does() {
        let mut buf = vec![0u8; 0x4000];
        let mut m = GuestMem::new(&mut buf);
        // Frames at 0x100 → 0x200 → 0x300 (an async frame) → 0 (the end).
        let _ = m.kernel().write_u64(0x100, 0x200);
        let _ = m.kernel().write_u64(0x108, 0xaaaa);
        let _ = m.kernel().write_u64(0x200, 0x300 | (1 << 60));
        let _ = m.kernel().write_u64(0x208, 0xbbbb);
        let _ = m.kernel().write_u64(0x1f8, 0xc0de);
        let _ = m.kernel().write_u64(0x300, 0);
        let _ = m.kernel().write_u64(0x308, 0xcccc);
        let w = walk(&m, 0x9999, 0x100, false, 0, 100);
        assert!(!w.error && !w.truncated);
        assert_eq!(w.frames, vec![0x9999, 0xaaaa, 0xbbbb, 0xcccc]);
        assert_eq!((w.async_index, w.async_addr), (2, 0xc0de));
        // A misaligned frame pointer: the pc only, truncated and faulting.
        let w = walk(&m, 0x9999, 0x101, false, 0, 100);
        assert!(w.error && w.truncated && w.frames == vec![0x9999]);
        // Out of room: truncated, no error.
        let w = walk(&m, 0x9999, 0x100, false, 0, 2);
        assert!(!w.error && w.truncated && w.frames.len() == 2);
    }

    #[test]
    fn the_lightweight_throttle_holds_fifteen() {
        for _ in 0..MAX_INFLIGHT {
            throttle_get().unwrap();
        }
        assert_eq!(throttle_get(), Err(KERN_RESOURCE_SHORTAGE));
        for _ in 0..MAX_INFLIGHT {
            throttle_release();
        }
    }
}
