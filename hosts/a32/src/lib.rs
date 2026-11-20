//! Runs an AArch32 (ARMv7-A) core's code the way gex runs a guest's: each
//! block lifted to GIR (`gex-lift-a32`), compiled to wasm by the tier-1
//! emitter (`gex-emit`, a module of [`gex_emit::ModuleBuilder::new_a32`]),
//! and run on wasmtime, the host's model of the core (`gex-a32`) answering
//! the `a32_sys` and `a32_mem` imports.
//!
//! The core's physical memory is a set of regions of the wasm memory
//! ([`Region`]); its thread context is gex's (`gex_abi::ctx`, at
//! `ctx_addr(0)`). A run is a loop: enter the block at the context's PC key,
//! run until translated code leaves (a key no module has yet, an exception
//! or a change the model reports, or a stop), translate what is missing,
//! and enter again. Translated code is dropped whenever the model's code
//! epoch moves (TLB and instruction-cache maintenance, translation regime
//! changes).
//!
//! ARM semihosting's SYS_EXIT (`SVC 0x123456` in the ARM state, `BKPT 0xAB`
//! in the Thumb state, with R0 = 0x18) ends a run when [`Machine::semihosting`]
//! is on, as QEMU's `-semihosting` does; any other semihosting call stops
//! the run loudly.

#![forbid(unsafe_code)]

use anyhow::{anyhow, bail, Result};
use gex_a32::{Core, PhysMem, Regs, Stop};
use gex_abi::{a32 as abi, ctx};
use gex_ir::{Block, Term};
use gex_isa_a32::Features;
use gex_mem::GuestMemory;
use std::collections::{BTreeMap, BTreeSet};
use wasmtime::{Caller, Engine, Func, Instance, Linker, Module, SharedMemory, Store};

/// A region of the core's physical address space backed by wasm memory.
#[derive(Clone, Debug)]
pub struct Region {
    pub pa: u64,
    pub size: u64,
    /// Where it is in the wasm memory.
    pub host: u64,
    pub writable: bool,
}

/// Where the guest's RAM windows start in the wasm memory: above gex's
/// reserved low region and dispatch directory.
pub const HOST_BASE: u64 = 0x4000_0000;
/// The sink slot (`gex_abi::a32::SINK`).
const SINK: u64 = HOST_BASE - 0x100;
const CTX: u64 = gex_abi::ctx_addr(0);

/// The physical memory map over the wasm memory.
#[derive(Clone)]
struct Phys {
    mem: GuestMemory,
    regions: Vec<Region>,
}

impl PhysMem for Phys {
    fn host(&self, pa: u64, len: u32, write: bool) -> Option<u64> {
        let r = self.regions.iter().find(|r| pa >= r.pa && pa + len as u64 <= r.pa + r.size)?;
        if write && !r.writable {
            return None;
        }
        Some(r.host + (pa - r.pa))
    }
    fn read32(&self, pa: u64) -> Option<u32> {
        let h = self.host(pa, 4, false)? as usize;
        let b = self.mem.bytes();
        Some(u32::from_le_bytes(b[h..h + 4].try_into().unwrap()))
    }
    fn write32(&mut self, pa: u64, v: u32) -> Option<()> {
        let h = self.host(pa, 4, true)? as usize;
        self.mem.bytes()[h..h + 4].copy_from_slice(&v.to_le_bytes());
        Some(())
    }
}

/// The thread context's registers (`gex_abi::a32`).
#[derive(Clone)]
pub struct CtxRegs {
    mem: GuestMemory,
}

impl CtxRegs {
    fn u64_at(&self, off: usize) -> u64 {
        let a = CTX as usize + off;
        u64::from_le_bytes(self.mem.bytes()[a..a + 8].try_into().unwrap())
    }
    fn set_u64_at(&self, off: usize, v: u64) {
        let a = CTX as usize + off;
        self.mem.bytes()[a..a + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn byte(&self, off: usize) -> u8 {
        self.mem.bytes()[CTX as usize + off]
    }
    fn set_byte(&self, off: usize, v: u8) {
        self.mem.bytes()[CTX as usize + off] = v;
    }
}

impl Regs for CtxRegs {
    fn r(&self, n: u8) -> u32 {
        assert!(n < 15);
        self.u64_at(ctx::x(n)) as u32
    }
    fn set_r(&mut self, n: u8, v: u32) {
        assert!(n < 15);
        self.set_u64_at(ctx::x(n), v as u64);
    }
    fn pc_key(&self) -> u64 {
        self.u64_at(ctx::PC)
    }
    fn set_pc_key(&mut self, key: u64) {
        self.set_u64_at(ctx::PC, key);
    }
    fn nzcv(&self) -> u32 {
        (self.byte(ctx::NF) as u32 & 1) << 31
            | (self.byte(ctx::ZF) as u32 & 1) << 30
            | (self.byte(ctx::CF) as u32 & 1) << 29
            | (self.byte(ctx::VF) as u32 & 1) << 28
    }
    fn set_nzcv(&mut self, v: u32) {
        self.set_byte(ctx::NF, (v >> 31 & 1) as u8);
        self.set_byte(ctx::ZF, (v >> 30 & 1) as u8);
        self.set_byte(ctx::CF, (v >> 29 & 1) as u8);
        self.set_byte(ctx::VF, (v >> 28 & 1) as u8);
    }
    fn q(&self) -> bool {
        self.u64_at(ctx::x(abi::Q)) & 1 != 0
    }
    fn set_q(&mut self, q: bool) {
        self.set_u64_at(ctx::x(abi::Q), q as u64);
    }
    fn ge(&self) -> u8 {
        self.u64_at(ctx::x(abi::GE)) as u8 & 15
    }
    fn set_ge(&mut self, ge: u8) {
        self.set_u64_at(ctx::x(abi::GE), (ge & 15) as u64);
    }
}

/// How a run ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Exit {
    /// Semihosting SYS_EXIT, with its reason code (R1) and the key of the
    /// call's instruction.
    Semihosting { code: u32, pc: u64 },
    /// A stop of the model's: UNPREDICTABLE, IMPLEMENTATION DEFINED, not
    /// implemented, or a wait nothing can end.
    Stopped(Stop),
}

/// What made translated code leave.
enum Leave {
    /// Run on at the context's PC key.
    Resume,
    /// A key no module has.
    Miss(u64),
    Exit(Exit),
    /// A host-side failure (an import translated code must not call).
    Fail(String),
}

struct State {
    core: Core,
    phys: Phys,
    regs: CtxRegs,
    leave: Option<Leave>,
    semihosting: bool,
}

/// One core and its memory.
pub struct Machine {
    engine: Engine,
    store: Store<State>,
    memory: SharedMemory,
    features: Features,
    /// Lifted blocks by key, for the current code epoch.
    blocks: BTreeMap<u64, Block>,
    epoch: u64,
    instance: Option<Instance>,
    /// Keys the current instance holds.
    built: BTreeSet<u64>,
    /// Blocks translated, over the run (for tests and diagnostics).
    pub translations: usize,
    pub modules: usize,
}

impl Machine {
    pub fn new(core: Core, regions: Vec<Region>) -> Result<Machine> {
        let engine = gex_native::engine()?;
        let memory = SharedMemory::new(&engine, gex_native::guest_memory_type())?;
        let gm = GuestMemory::new(memory.clone());
        for r in &regions {
            if r.host < HOST_BASE || (r.host + r.size) as usize > gm.len() {
                bail!("region {r:?} is outside the host window");
            }
        }
        let features = core.config.features;
        let mut core = core;
        core.set_sink(SINK);
        let regs = CtxRegs { mem: gm.clone() };
        regs.set_u64_at(ctx::x(abi::SINK), SINK);
        let state = State { core, phys: Phys { mem: gm, regions }, regs, leave: None, semihosting: false };
        let store = Store::new(&engine, state);
        Ok(Machine { engine, store, memory, features, blocks: BTreeMap::new(), epoch: 0, instance: None, built: BTreeSet::new(), translations: 0, modules: 0 })
    }

    /// ARM semihosting's SYS_EXIT ends a run.
    pub fn semihosting(&mut self, on: bool) {
        self.store.data_mut().semihosting = on;
    }

    pub fn core(&mut self) -> &mut Core {
        &mut self.store.data_mut().core
    }

    pub fn regs(&mut self) -> &mut CtxRegs {
        &mut self.store.data_mut().regs
    }

    /// The model's view of the core's registers and memory, together.
    pub fn with_core<R>(&mut self, f: impl FnOnce(&mut Core, &mut CtxRegs, &mut dyn PhysMem) -> R) -> R {
        let st = self.store.data_mut();
        f(&mut st.core, &mut st.regs, &mut st.phys)
    }

    /// Copy `bytes` to physical address `pa` (inside one region).
    pub fn load(&mut self, pa: u64, bytes: &[u8]) -> Result<()> {
        let st = self.store.data();
        let h = st.phys.host(pa, bytes.len() as u32, false).ok_or_else(|| anyhow!("no memory for {} bytes at PA {pa:#x}", bytes.len()))?;
        st.phys.mem.bytes()[h as usize..h as usize + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    /// Read `len` bytes at physical address `pa`.
    pub fn read(&self, pa: u64, len: usize) -> Result<Vec<u8>> {
        let st = self.store.data();
        let h = st.phys.host(pa, len as u32, false).ok_or_else(|| anyhow!("no memory for {len} bytes at PA {pa:#x}"))?;
        Ok(st.phys.mem.bytes()[h as usize..h as usize + len].to_vec())
    }

    /// The Reset exception.
    pub fn reset(&mut self) -> Result<()> {
        let st = self.store.data_mut();
        st.core.reset(&mut st.regs).map_err(|s| anyhow!("reset: {s:?}"))
    }

    /// Lift the block at `key` and everything statically reachable from it
    /// that is not lifted yet, up to `limit` blocks.
    fn discover(&mut self, key: u64, limit: usize) {
        let mut work = vec![key];
        let mut n = 0;
        while let Some(k) = work.pop() {
            if self.blocks.contains_key(&k) || n >= limit {
                continue;
            }
            let st = self.store.data();
            let user = abi::key_user(k);
            let fetch = |va: u32| st.core.fetch(&st.regs, &st.phys, va, user);
            let block = gex_lift_a32::lift_block(&fetch, k, &self.features, gex_lift_a32::BlockLimits::default());
            n += 1;
            self.translations += 1;
            match block.term {
                Term::Goto { target } => work.push(target),
                Term::Branch { taken, not_taken, .. } => {
                    work.push(taken);
                    work.push(not_taken);
                }
                _ => {}
            }
            if let Some(r) = block.call_return {
                work.push(r);
            }
            self.blocks.insert(k, block);
        }
    }

    /// Compile every lifted block into one module and instantiate it.
    fn build(&mut self) -> Result<()> {
        let mut m = gex_emit::ModuleBuilder::new_a32(0, 0);
        for b in self.blocks.values() {
            m.add_block(b.clone());
        }
        let t = m.finish();
        let module = Module::new(&self.engine, &t.wasm).map_err(|e| anyhow!("compiling an AArch32 module: {e:?}"))?;
        let linker = self.linker().map_err(|e| anyhow!("linking an AArch32 module: {e:?}"))?;
        let instance = linker.instantiate(&mut self.store, &module).map_err(|e| anyhow!("instantiating an AArch32 module: {e:?}"))?;
        self.instance = Some(instance);
        self.built = self.blocks.keys().copied().collect();
        self.modules += 1;
        Ok(())
    }

    fn linker(&mut self) -> wasmtime::Result<Linker<State>> {
        use gex_abi::imports as im;
        let mut l: Linker<State> = Linker::new(&self.engine);
        let m = gex_abi::IMPORT_MODULE;
        l.define(&mut self.store, m, gex_abi::exports::MEMORY, self.memory.clone())?;
        fn leave<T>(c: &mut Caller<'_, State>, why: Leave) -> wasmtime::Result<T> {
            c.data_mut().leave = Some(why);
            Err(wasmtime::Error::from_anyhow(anyhow!("leaving translated code")))
        }
        l.func_wrap(m, im::A32_SYS, |mut c: Caller<'_, State>, _ctx: i32, pc: i64, op: i32, a: i64, b: i64| -> wasmtime::Result<i64> {
            let st = c.data_mut();
            if st.semihosting && op == abi::sys::EXCEPTION {
                let thumb = abi::key_thumb(pc as u64);
                let call = (a == abi::exc::SVC && !thumb && b == 0x12_3456) || (a == abi::exc::BKPT && thumb && b == 0xab);
                if call {
                    let r0 = st.regs.r(0);
                    if r0 == 0x18 {
                        let code = st.regs.r(1);
                        return leave(&mut c, Leave::Exit(Exit::Semihosting { code, pc: pc as u64 }));
                    }
                    return leave(&mut c, Leave::Fail(format!("semihosting call {r0:#x} is not implemented")));
                }
            }
            let r = st.core.sys(&mut st.regs, &mut st.phys, pc as u64, op, a as u64, b as u64);
            match r {
                Ok(v) => Ok(v as i64),
                Err(Stop::Resume) => leave(&mut c, Leave::Resume),
                Err(s) => leave(&mut c, Leave::Exit(Exit::Stopped(s))),
            }
        })?;
        l.func_wrap(m, im::A32_MEM, |mut c: Caller<'_, State>, _ctx: i32, pc: i64, va: i64, access: i32| -> wasmtime::Result<i64> {
            let st = c.data_mut();
            match st.core.mem(&mut st.regs, &mut st.phys, pc as u64, va as u32, access) {
                Ok(h) => Ok(h as i64),
                Err(Stop::Resume) => leave(&mut c, Leave::Resume),
                Err(s) => leave(&mut c, Leave::Exit(Exit::Stopped(s))),
            }
        })?;
        l.func_wrap(m, im::DISPATCH_MISS, |mut c: Caller<'_, State>, _ctx: i32, pc: i64| -> wasmtime::Result<i32> {
            leave(&mut c, Leave::Miss(pc as u64))
        })?;
        l.func_wrap(m, im::BREAKPOINT, |mut c: Caller<'_, State>, _ctx: i32, pc: i64, code: i32| -> wasmtime::Result<()> {
            let why = if code == abi::BRK_UNPREDICTABLE_PC {
                Leave::Exit(Exit::Stopped(Stop::Unpredictable(format!(
                    "the instruction at key {pc:#x} writes the PC with an address that is UNPREDICTABLE (A2.3.2 BXWritePC bits 1:0 = 0b10, or a PC load from an unaligned address)"
                ))))
            } else {
                Leave::Fail(format!("breakpoint {code} at {pc:#x}"))
            };
            leave(&mut c, why)
        })?;
        l.func_wrap(m, im::SAFEPOINT, |_c: Caller<'_, State>, _ctx: i32, _pc: i64| {})?;
        // Imports an AArch32 module declares but its code never calls.
        let never = |name: &'static str| move |c: &mut Caller<'_, State>| -> wasmtime::Result<()> {
            c.data_mut().leave = Some(Leave::Fail(format!("translated AArch32 code called `{name}`")));
            Err(wasmtime::Error::from_anyhow(anyhow!("{name}")))
        };
        let f = never(im::SYSCALL);
        l.func_wrap(m, im::SYSCALL, move |mut c: Caller<'_, State>, _: i32, _: i64| f(&mut c))?;
        let f = never(im::ILLEGAL);
        l.func_wrap(m, im::ILLEGAL, move |mut c: Caller<'_, State>, _: i32, _: i64, _: i32| f(&mut c))?;
        let f = never(im::SYSREG_READ);
        l.func_wrap(m, im::SYSREG_READ, move |mut c: Caller<'_, State>, _: i32, _: i64, _: i32| -> wasmtime::Result<i64> {
            f(&mut c)?;
            Ok(0)
        })?;
        let f = never(im::SYSREG_WRITE);
        l.func_wrap(m, im::SYSREG_WRITE, move |mut c: Caller<'_, State>, _: i32, _: i64, _: i32, _: i64| f(&mut c))?;
        // A block entered for a neighbour in its dispatch slot says so
        // before it dispatches on: nothing is cached here to forget, the
        // dispatch that follows misses to the run loop. Any other cache
        // operation is not an AArch32 block's.
        let f = never(im::CACHE_OP);
        l.func_wrap(m, im::CACHE_OP, move |mut c: Caller<'_, State>, _: i32, _: i64, op: i32, _: i64| {
            if op == gex_abi::cache_op::SLOT_CONFLICT {
                return Ok(());
            }
            f(&mut c)
        })?;
        let f = never(im::FMA);
        l.func_wrap(m, im::FMA, move |mut c: Caller<'_, State>, _: i32, _: i64, _: i64, _: i64, _: i32| -> wasmtime::Result<i64> {
            f(&mut c)?;
            Ok(0)
        })?;
        let f = never(im::CRYPTO);
        l.func_wrap(m, im::CRYPTO, move |mut c: Caller<'_, State>, _: i32, _: i64, _: i64| f(&mut c))?;
        let f = never(im::X87);
        l.func_wrap(m, im::X87, move |mut c: Caller<'_, State>, _: i32, _: i32, _: i64, _: i32, _: i64, _: i32, _: i32| -> wasmtime::Result<i64> {
            f(&mut c)?;
            Ok(0)
        })?;
        let f = never(im::MX);
        l.func_wrap(m, im::MX, move |mut c: Caller<'_, State>, _: i32, _: i32, _: i64, _: i64, _: i32| -> wasmtime::Result<i64> {
            f(&mut c)?;
            Ok(0)
        })?;
        Ok(l)
    }

    /// Run from the context's PC key until the core stops or `max_entries`
    /// entries into translated code have been made.
    pub fn run(&mut self, max_entries: usize) -> Result<Exit> {
        for _ in 0..max_entries {
            let epoch = self.store.data().core.code_epoch();
            if epoch != self.epoch {
                self.epoch = epoch;
                self.blocks.clear();
                self.instance = None;
            }
            let key = self.store.data().regs.pc_key();
            if !self.built.contains(&key) || self.instance.is_none() {
                self.discover(key, 4096);
                self.build()?;
            }
            let inst = self.instance.unwrap();
            let entry: wasmtime::TypedFunc<i32, ()> = inst
                .get_typed_func(&mut self.store, &gex_emit::a32_export(key))
                .map_err(|e| anyhow!("no export for key {key:#x}: {e:?}"))?;
            self.store.data_mut().leave = None;
            // A block checks it is the one dispatch was asked for (several
            // keys share a slot): entered here, it is.
            self.store.data().regs.set_u64_at(ctx::LAST_TARGET, key);
            let r = entry.call(&mut self.store, CTX as i32);
            let why = self.store.data_mut().leave.take();
            if trace() {
                let st = self.store.data();
                let regs: Vec<String> = (0..15).map(|n| format!("{:x}", st.regs.r(n))).collect();
                eprintln!(
                    "[a32] entered {key:#x}, left {}: pc {:#x} r {}",
                    match &why {
                        Some(Leave::Resume) => "to resume".into(),
                        Some(Leave::Miss(k)) => format!("for {k:#x}"),
                        Some(Leave::Exit(e)) => format!("{e:?}"),
                        Some(Leave::Fail(s)) => s.clone(),
                        None => "with a trap".into(),
                    },
                    st.regs.pc_key(),
                    regs.join(" ")
                );
            }
            match (r, why) {
                (Err(_), Some(Leave::Resume)) => {}
                (Err(_), Some(Leave::Miss(k))) => {
                    self.store.data_mut().regs.set_pc_key(k);
                }
                (Err(_), Some(Leave::Exit(e))) => return Ok(e),
                (Err(_), Some(Leave::Fail(s))) => bail!("{s}"),
                (Err(e), None) => bail!("translated AArch32 code trapped: {e:?}"),
                (Ok(()), _) => bail!("translated AArch32 code returned to the host"),
            }
        }
        bail!("the run did not end within {max_entries} entries")
    }
}

/// `GEX_A32_TRACE=1`: each entry into translated code and why it left, with
/// the registers, to stderr.
fn trace() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("GEX_A32_TRACE").is_some())
}

/// Look up a `Func` export (diagnostics).
pub fn export(m: &mut Machine, name: &str) -> Option<Func> {
    m.instance.and_then(|i| i.get_func(&mut m.store, name))
}
