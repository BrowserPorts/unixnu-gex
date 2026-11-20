//! `gex-a32` — the system-level model of an AArch32 (ARMv7-A) core: what
//! translated code (`gex-lift-a32`) leaves to the host. The processor modes
//! and their banked registers, the PSRs, exception entry and return, the
//! CP14/CP15 registers and their access rules, and the Virtual Memory
//! System Architecture's short-descriptor translation, from the ARM
//! Architecture Reference Manual, ARMv7-A and ARMv7-R edition (ARM DDI
//! 0406C.d), chapters B1, B3, B4 and B9.
//!
//! The current mode's `R0`-`R14`, the PC key, the flags, Q and GE are in the
//! thread context ([`Regs`], `gex_abi::a32`); the model owns the rest.
//! Translated code calls [`Core::sys`] for every `A32Sys` operation and
//! [`Core::mem`] for every `A32Mem` translation; the code translator calls
//! [`Core::fetch`] for instruction fetches.
//!
//! What the model does not implement fails loudly ([`Stop::Unimplemented`]),
//! an UNPREDICTABLE case it meets stops it ([`Stop::Unpredictable`]), and an
//! IMPLEMENTATION DEFINED choice the configuration leaves open stops it
//! ([`Stop::ImpDef`]): none is given one behaviour silently.
//!
//! The core has neither the Security nor the Virtualization Extensions
//! ([`Core::new`] refuses them): `IsSecure()` is TRUE, there is one copy of
//! each CP15 register, and `HaveSecurityExt()`/`HaveVirtExt()` are FALSE in
//! every pseudocode function below.

#![forbid(unsafe_code)]

pub use gex_isa_a32::Features;

mod cp;
mod exc;
mod psr;
mod vmsa;

#[cfg(test)]
mod tests;

use gex_abi::a32 as abi;

/// The thread context's part of the core's state (`gex_abi::a32`).
pub trait Regs {
    /// `R0`-`R14` of the current mode.
    fn r(&self, n: u8) -> u32;
    fn set_r(&mut self, n: u8, v: u32);
    /// The PC key (`gex_abi::a32::key`): address, Thumb bit, ITSTATE.
    fn pc_key(&self) -> u64;
    fn set_pc_key(&mut self, key: u64);
    /// N, Z, C, V as `CPSR<31:28>` holds them (the other bits zero).
    fn nzcv(&self) -> u32;
    fn set_nzcv(&mut self, v: u32);
    fn q(&self) -> bool;
    fn set_q(&mut self, q: bool);
    /// `CPSR<19:16>`.
    fn ge(&self) -> u8;
    fn set_ge(&mut self, ge: u8);
}

/// The core's physical address space.
pub trait PhysMem {
    /// The host address (an offset in the guest's wasm memory) of the `len`
    /// bytes at physical address `pa`, when all of them are in one region
    /// of memory (RAM or ROM) that the access may use (`write` for a store),
    /// `None` otherwise.
    fn host(&self, pa: u64, len: u32, write: bool) -> Option<u64>;
    /// Read a little-endian word of memory (a translation table walk's
    /// read, SRS's and RFE's accesses, through [`Self::host`]).
    fn read32(&self, pa: u64) -> Option<u32>;
    fn write32(&mut self, pa: u64, v: u32) -> Option<()>;
}

/// An IMPLEMENTATION DEFINED CP15 register (B3.17.2: the c9 cache/TCM and
/// c10 TLB lockdown encodings, the c11 DMA encodings, the c15 encodings and
/// the c9 IMPLEMENTATION DEFINED performance monitors): its encoding as
/// `gex_abi::a32::sys::cp` gives it (coprocessor 15), its reset value, and
/// which bits a write changes (0 for a read-only register). Accessible only
/// at PL1 (B3.15.2, User mode accesses are UNDEFINED).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImpReg {
    pub cp: u32,
    pub reset: u32,
    pub writable: u32,
}

/// The IMPLEMENTATION DEFINED values and choices of the core, `None` where
/// they are not known: a read of an unknown register or a reach of an open
/// choice stops the core ([`Stop::ImpDef`]).
#[derive(Clone, Debug, Default)]
pub struct ImpDef {
    /// MIDR, CTR, TCMTR, TLBTR, MPIDR, REVIDR, ID_PFR0/1, ID_DFR0, ID_AFR0,
    /// ID_MMFR0-3, ID_ISAR0-5, CLIDR, AIDR, and the CCSIDRs by CSSELR value.
    /// An implementation without the optional REVIDR gives MIDR's value
    /// here (the encoding is then an alias of MIDR, B3.17.2 note a).
    ///
    /// The model reads its own configuration from the ID registers where
    /// the Arm ARM makes them the record of a choice: ID_MMFR0.VMSA (the
    /// PXN bit without LPAE), ID_MMFR0.FCSE, ID_MMFR0.Auxiliary registers,
    /// ID_MMFR0.Shareability levels (PRRR.NOSn), ID_MMFR2.HW Access flag,
    /// ID_MMFR3.Supersection, ID_PFR0.State2 (JOSCR.CV on exception entry),
    /// ID_PFR1.Generic Timer, ID_DFR0.Performance Monitors and coprocessor
    /// trace.
    pub midr: Option<u32>,
    pub ctr: Option<u32>,
    pub tcmtr: Option<u32>,
    pub tlbtr: Option<u32>,
    pub mpidr: Option<u32>,
    pub revidr: Option<u32>,
    pub id_pfr: [Option<u32>; 2],
    pub id_dfr0: Option<u32>,
    pub id_afr0: Option<u32>,
    pub id_mmfr: [Option<u32>; 4],
    pub id_isar: [Option<u32>; 6],
    pub clidr: Option<u32>,
    pub aidr: Option<u32>,
    pub ccsidr: Vec<(u32, u32)>,
    /// The ACTLR's reset value and writable bits.
    pub actlr: Option<(u32, u32)>,
    /// B1.9 (Conditional execution of undefined instructions): whether an
    /// UNDEFINED instruction that fails its condition takes the Undefined
    /// Instruction exception (`true`) or is a NOP (`false`).
    pub undef_cond_failed_traps: Option<bool>,
    /// The reset values the configuration inputs give: SCTLR.V (VINITHI),
    /// SCTLR.TE (TEINIT), SCTLR.EE (CFGEND), SCTLR.NMFI (CFGNMFI).
    pub reset_hivecs: Option<bool>,
    pub reset_te: Option<bool>,
    pub reset_ee: Option<bool>,
    pub reset_nmfi: Option<bool>,
    /// B4.1.130 (Figure B4-1): the SCTLR bits whose implementation is
    /// IMPLEMENTATION DEFINED, VE (24), FI (21), HA (17), RR (14), I (12),
    /// Z (11), CP15BEN (5) and C (2): `(rw, fixed)`, the bits that are
    /// read/write (resetting to 0, CP15BEN to 1), and the value of the others
    /// (RAZ, or RAO for Z when branch prediction cannot be disabled and for
    /// CP15BEN when it is not implemented).
    pub sctlr: Option<(u32, u32)>,
    /// B1.9.1: the IMPLEMENTATION DEFINED reset vector
    /// (`HasIMPDEFResetVector()`), `Some(None)` for the vector base's.
    pub reset_vector: Option<Option<u32>>,
    /// B1.8.10 (Exception return to an unimplemented instruction set state):
    /// whether the J bits of the PSRs are RAZ/WI (permitted only without
    /// ThumbEE).
    pub psr_j_raz_wi: Option<bool>,
    /// B3.8.3 (SCTLR.TRE, SCTLR.M, and the effect of the TEX remap
    /// registers): whether PRRR/NMRR have an IMPLEMENTATION DEFINED effect
    /// when SCTLR.TRE is 0 (`RemapRegsHaveResetValues()`).
    pub tre0_remap: Option<bool>,
    /// B4.1.40: whether CPACR.ASEDIS (with both the Floating-point and the
    /// Advanced SIMD Extension) and CPACR.D32DIS (with D16-D31) are
    /// implemented as read/write bits.
    pub cpacr_asedis: Option<bool>,
    pub cpacr_d32dis: Option<bool>,
    /// B1.13.5: a trivial Jazelle implementation's JOSCR is read/write with
    /// no effect (`true`) or RAZ/WI (`false`).
    pub joscr_rw: Option<bool>,
    /// C11.11: DBGDIDR, and the 64-bit DBGDRAR and DBGDSAR.
    pub dbgdidr: Option<u32>,
    pub dbgdrar: Option<u64>,
    pub dbgdsar: Option<u64>,
    /// B3.12.5: whether ICIMVAU and BPIMVA translate their address (and so
    /// can fault), and whether cache maintenance by MVA can generate Access
    /// flag faults.
    pub icimvau_translates: Option<bool>,
    pub bpimva_translates: Option<bool>,
    pub maint_access_flag_faults: Option<bool>,
    /// B3.13.2 (Data Abort on an instruction cache maintenance operation by
    /// MVA): `true` if the DFSR reports the instruction cache maintenance
    /// fault code (0b00100) with the cause in the IFSR, `false` if the DFSR
    /// reports the cause.
    pub icmaint_fault_code: Option<bool>,
    /// B4.1.112: PAR bit 8 of a successful 32-bit result, and, with LPAE,
    /// whether PAR.{SH, NOS} report the region's shareability (`true`) or
    /// 1 and 0 for Inner and Outer Non-cacheable Normal memory.
    pub par_bit8: Option<bool>,
    pub par_nc_shareability: Option<bool>,
    /// B3.15.2 rule 3: whether CP15 c15 is allocated (otherwise every access
    /// to it is UNDEFINED); its registers, with those of the other
    /// IMPLEMENTATION DEFINED encodings, are in `imp_regs`.
    pub c15_allocated: Option<bool>,
    pub imp_regs: Vec<ImpReg>,
}

/// What the core is.
#[derive(Clone, Debug)]
pub struct Config {
    pub features: Features,
    pub imp: ImpDef,
}

/// Why execution leaves translated code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stop {
    /// The core's state changed under translated code (an exception taken,
    /// an exception return, a change to how code is fetched): run on from
    /// the PC key in [`Regs`], with a fresh translation where
    /// [`Core::code_epoch`] moved.
    Resume,
    /// WFI/WFE with nothing that can wake the core.
    Wait(String),
    /// An UNPREDICTABLE case, named with its Arm ARM rule.
    Unpredictable(String),
    /// An IMPLEMENTATION DEFINED value or choice the configuration does not
    /// give.
    ImpDef(String),
    /// Something the model does not implement.
    Unimplemented(String),
}

pub(crate) fn unpred<T>(s: impl Into<String>) -> Result<T, Stop> {
    Err(Stop::Unpredictable(s.into()))
}

pub(crate) fn unimpl<T>(s: impl Into<String>) -> Result<T, Stop> {
    Err(Stop::Unimplemented(s.into()))
}

pub(crate) fn need<T: Copy>(v: Option<T>, what: &str) -> Result<T, Stop> {
    v.ok_or_else(|| Stop::ImpDef(what.to_string()))
}

/// The CP15 (and CP14) registers the model keeps (B4.1).
#[derive(Clone, Debug, Default)]
pub(crate) struct Sysregs {
    pub sctlr: u32,
    /// `None` until the configuration gives the reset value.
    pub actlr: Option<u32>,
    pub cpacr: u32,
    pub ttbr0: u64,
    pub ttbr1: u64,
    pub ttbcr: u32,
    pub dacr: u32,
    pub dfsr: u32,
    pub ifsr: u32,
    pub dfar: u32,
    pub ifar: u32,
    pub par: u64,
    pub prrr: u32,
    pub nmrr: u32,
    pub fcseidr: u32,
    pub contextidr: u32,
    pub tpidrurw: u32,
    pub tpidruro: u32,
    pub tpidrprw: u32,
    pub csselr: u32,
    /// The values of [`ImpDef::imp_regs`], in the same order.
    pub imp: Vec<u32>,
    pub teecr: u32,
    pub teehbr: u32,
    pub joscr: u32,
    /// FPEXC (B4.1.57): only EN matters to the model, which executes no
    /// Floating-point instruction (EN resets to 0 and nothing sets it).
    pub fpexc: u32,
}

/// The core's state outside the thread context.
#[derive(Clone, Debug)]
pub struct Core {
    pub config: Config,
    /// CPSR.{E, A, I, F, M} (bits 9:6, 4:0); J is 0, T and IT are the PC
    /// key's, N, Z, C, V, Q, GE the context's.
    pub(crate) psr: u32,
    /// R8_usr-R12_usr and R8_fiq-R12_fiq while not in the context.
    pub(crate) hi_usr: [u32; 5],
    pub(crate) hi_fiq: [u32; 5],
    /// SP and LR of usr (and sys), fiq, irq, svc, abt, und.
    pub(crate) sp: [u32; 6],
    pub(crate) lr: [u32; 6],
    /// SPSR_fiq, SPSR_irq, SPSR_svc, SPSR_abt, SPSR_und.
    pub(crate) spsr: [u32; 5],
    /// B1.8.13 The Event Register.
    pub(crate) event: bool,
    pub(crate) sink: Option<u64>,
    pub(crate) epoch: u64,
    pub(crate) sr: Sysregs,
}

impl Core {
    /// A core of `config`, not yet reset. Fails for what the model does not
    /// implement (e.g. the Security or Virtualization Extensions' system
    /// level).
    pub fn new(config: Config) -> Result<Core, Stop> {
        let f = &config.features;
        if f.virtualization {
            return unimpl("the Virtualization Extensions (Hyp mode, HVC/ERET to Hyp, the PL2 CP15 registers, stage 2 translation)");
        }
        if f.security {
            return unimpl("the Security Extensions (Monitor mode, SMC, Secure/Non-secure banked CP15, SCR, NSACR, VBAR)");
        }
        if let Some((rw, fixed)) = config.imp.sctlr {
            let opt = cp::SCTLR_OPTIONAL;
            if rw & !opt != 0 || fixed & !opt != 0 || rw & fixed != 0 || fixed & !(cp::SCTLR_Z | cp::SCTLR_CP15BEN) != 0 {
                return Err(Stop::ImpDef(format!("ImpDef::sctlr {rw:#x}/{fixed:#x}: only VE, FI, HA, RR, I, Z, CP15BEN, C can be read/write, and only Z and CP15BEN read-as-one (B4.1.130)")));
            }
        }
        if f.thumbee && config.imp.psr_j_raz_wi == Some(true) {
            return Err(Stop::ImpDef("PSR J bits RAZ/WI with ThumbEE (B1.8.10 permits it only without Jazelle and ThumbEE)".into()));
        }
        let imp = config.imp.imp_regs.iter().map(|r| r.reset).collect();
        Ok(Core {
            config,
            psr: psr::SVC as u32 | 0x1c0,
            hi_usr: [0; 5],
            hi_fiq: [0; 5],
            sp: [0; 6],
            lr: [0; 6],
            spsr: [0; 5],
            event: false,
            sink: None,
            epoch: 0,
            sr: Sysregs { imp, ..Sysregs::default() },
        })
    }

    /// The host address of the 16-byte sink slot (`gex_abi::a32::SINK`)
    /// that an access whose condition failed is given.
    pub fn set_sink(&mut self, host: u64) {
        self.sink = Some(host);
    }

    /// The Reset exception (B1.9.1): SCTLR and the CPSR to their reset
    /// values, the PC to the reset vector.
    pub fn reset(&mut self, regs: &mut dyn Regs) -> Result<(), Stop> {
        self.take_reset(regs)
    }

    /// An `A32Sys` operation (`gex_abi::a32::sys`) by the instruction whose
    /// key is `pc`: `Ok` with its result, translated code going on; `Err`
    /// otherwise.
    pub fn sys(&mut self, regs: &mut dyn Regs, mem: &mut dyn PhysMem, pc: u64, op: i32, a: u64, b: u64) -> Result<u64, Stop> {
        use abi::sys::*;
        match op {
            NOP => Ok(0),
            MRC | MCR | MRRC | MCRR => self.coproc(regs, mem, pc, op, a as u32, b),
            MRS => self.mrs(regs, a != 0).map(u64::from),
            MSR => self.msr(regs, a as u32, b as u32).map(|_| 0),
            MRS_BANKED | MSR_BANKED => unimpl("MRS/MSR (Banked register): the Virtualization Extensions (B9.3.9, B9.3.10)"),
            CPS => self.cps(regs, a as u32).map(|_| 0),
            SETEND => self.setend(a != 0).map(|_| 0),
            SRS => self.srs(regs, mem, pc, a as u32),
            RFE => self.rfe(regs, mem, pc, a as u32),
            ALU_RETURN => self.alu_return(regs, b as u32),
            LDM_RETURN => self.ldm_return(regs, b as u32),
            ERET => self.eret(regs),
            USER_READ => self.user_reg(regs, a as u8, None).map(u64::from),
            USER_WRITE => self.user_reg(regs, a as u8, Some(b as u32)).map(u64::from),
            EXCEPTION => self.exception(regs, mem, pc, a as i64, b),
            UNDEF_COND_FAILED => match need(self.config.imp.undef_cond_failed_traps, "whether a conditional UNDEFINED instruction failing its condition traps (B1.9.2)")? {
                true => self.take_undef(regs, pc),
                false => Ok(0),
            },
            WFI => Err(Stop::Wait("WFI: the core has no interrupt or other WFI wake-up event source (B1.8.14)".into())),
            WFE => {
                // B1.8.13 The Wait For Event instruction.
                if self.event {
                    self.event = false;
                    Ok(0)
                } else {
                    Err(Stop::Wait("WFE: the Event Register is clear and the core has no WFE wake-up event source (B1.8.13)".into()))
                }
            }
            SEV => {
                // SendEvent(): the Event Register of every processor, this one.
                self.event = true;
                Ok(0)
            }
            // A8.8.53 ISB: a context synchronization event. Every change the
            // model makes is already in effect.
            ISB => Ok(0),
            UNPREDICTABLE => unpred(format!("UNPREDICTABLE encoding {a:#010x} ({b} bytes) at {:#x}", abi::key_addr(pc))),
            UNPREDICTABLE_VALUE => {
                let what = match a as i64 {
                    abi::unpred::BX_ARM_MISALIGNED => "BXWritePC of an address with bits 1:0 = 0b10 (A2.3.2)",
                    abi::unpred::PC_MISALIGNED => "a PC value not word aligned in the ARM state",
                    _ => "an UNPREDICTABLE value",
                };
                unpred(format!("{what}: {b:#x} at {:#x}", abi::key_addr(pc)))
            }
            UNIMPLEMENTED => self.unimplemented(regs, pc, a as i64, b as u32),
            _ => unimpl(format!("A32Sys operation {op}")),
        }
    }

    /// An `A32Mem` translation (`gex_abi::a32::mem`): the host address of the
    /// access, or the Data Abort taken (`Err(Stop::Resume)`).
    pub fn mem(&mut self, regs: &mut dyn Regs, mem: &mut dyn PhysMem, pc: u64, va: u32, access: i32) -> Result<u64, Stop> {
        self.data_access(regs, mem, pc, va, access)
    }

    /// The halfword of code at `va` for the translator, as an instruction
    /// fetch at PL0 (`user`, the key's `KEY_USER`) or PL1 sees it, whatever
    /// the current mode, or `None` where the fetch aborts (or would be
    /// UNPREDICTABLE, or reaches no memory: the Prefetch Abort the lifter
    /// then raises at the instruction finds out which).
    pub fn fetch(&self, _regs: &dyn Regs, mem: &dyn PhysMem, va: u32, user: bool) -> Option<u16> {
        self.fetch_halfword(mem, va, user)
    }

    /// A counter that moves whenever code translated before may no longer
    /// be what fetching gives (translation regime changes, TLB and
    /// instruction cache maintenance). The fetching privilege is in the
    /// keys themselves (`KEY_USER`).
    pub fn code_epoch(&self) -> u64 {
        self.epoch
    }

    /// The PC key of `addr` in the current mode: `KEY_USER` exactly when it
    /// is User mode, whose fetches are made at PL0.
    pub(crate) fn pc_key(&self, addr: u32, thumb: bool, it: u8) -> u64 {
        abi::key(addr, thumb, it) | if self.mode() == psr::USR { abi::KEY_USER } else { 0 }
    }

    /// CPSR.M.
    pub fn mode(&self) -> u8 {
        (self.psr & 0x1f) as u8
    }

    /// The whole CPSR (B1.3.3): what MRS reads at PL1, with the execution
    /// state bits (IT and T from the PC key; J is 0) included.
    pub fn cpsr(&self, regs: &dyn Regs) -> u32 {
        let key = regs.pc_key();
        self.cpsr_value(regs, abi::key_it(key), abi::key_thumb(key))
    }

    /// The SPSR of the current mode, `None` in User and System modes.
    pub fn spsr(&self) -> Option<u32> {
        psr::spsr_index(self.mode()).map(|i| self.spsr[i])
    }

    /// `Rmode[n, mode]` (B1.3.2) for `n` in 0..=14.
    pub fn banked_r(&self, regs: &dyn Regs, n: u8, mode: u8) -> Result<u32, Stop> {
        self.rmode(regs, n, mode)
    }
}
