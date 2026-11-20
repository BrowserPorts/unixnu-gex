//! The CP15 and CP14 registers of a VMSAv7 core without the Security and
//! Virtualization Extensions (B3.15-B3.17, B4.1, B4.2, C6.4) and the MCR,
//! MRC, MCRR and MRRC accesses to them.

use crate::{abi, need, unimpl, unpred, Core, PhysMem, Regs, Stop};

// B4.1.130 SCTLR.
pub const SCTLR_M: u32 = 1 << 0;
pub const SCTLR_A: u32 = 1 << 1;
pub const SCTLR_C: u32 = 1 << 2;
pub const SCTLR_CP15BEN: u32 = 1 << 5;
pub const SCTLR_SW: u32 = 1 << 10;
pub const SCTLR_Z: u32 = 1 << 11;
pub const SCTLR_I: u32 = 1 << 12;
pub const SCTLR_V: u32 = 1 << 13;
pub const SCTLR_RR: u32 = 1 << 14;
pub const SCTLR_HA: u32 = 1 << 17;
pub const SCTLR_FI: u32 = 1 << 21;
pub const SCTLR_VE: u32 = 1 << 24;
pub const SCTLR_EE: u32 = 1 << 25;
pub const SCTLR_NMFI: u32 = 1 << 27;
pub const SCTLR_TRE: u32 = 1 << 28;
pub const SCTLR_AFE: u32 = 1 << 29;
pub const SCTLR_TE: u32 = 1 << 30;
/// The bits whose implementation is IMPLEMENTATION DEFINED.
pub const SCTLR_OPTIONAL: u32 = SCTLR_VE | SCTLR_FI | SCTLR_HA | SCTLR_RR | SCTLR_I | SCTLR_Z | SCTLR_CP15BEN | SCTLR_C;
/// The RAO bits (23, 22 U, 18, 16, 6, 4:3).
const SCTLR_RAO: u32 = 0x00c5_0058;
/// The SCTLR bits whose change changes translation (B3.10.2).
const SCTLR_XLATE: u32 = SCTLR_M | SCTLR_TRE | SCTLR_AFE | SCTLR_HA | SCTLR_EE;

/// A register access.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Acc {
    Read,
    Write(u32),
}

impl Core {
    /// The SCTLR's reset value (B4.1.130 Figure B4-1).
    pub(crate) fn sctlr_reset(&self) -> Result<u32, Stop> {
        let imp = &self.config.imp;
        let (rw, fixed) = need(imp.sctlr, "the SCTLR's IMPLEMENTATION DEFINED bits (B4.1.130)")?;
        if (rw | fixed) & SCTLR_CP15BEN == 0 {
            return Err(Stop::ImpDef("SCTLR.CP15BEN is read/write (reset 1) or RAO/WI (B4.1.130)".into()));
        }
        let te = need(imp.reset_te, "the reset value of SCTLR.TE (TEINIT)")?;
        let v = need(imp.reset_hivecs, "the reset value of SCTLR.V (VINITHI)")?;
        let nmfi = need(imp.reset_nmfi, "SCTLR.NMFI (CFGNMFI)")?;
        Ok(SCTLR_RAO
            | fixed
            | (rw & SCTLR_CP15BEN)
            | if te { SCTLR_TE } else { 0 }
            | if v { SCTLR_V } else { 0 }
            | if nmfi { SCTLR_NMFI } else { 0 })
    }

    /// `ResetControlRegisters()` (B3.15.2): the CP14 and CP15 registers with
    /// defined reset values; the others keep their (UNKNOWN) values.
    pub(crate) fn reset_control_registers(&mut self, sctlr: u32) {
        self.sr.sctlr = sctlr;
        // CPACR: the cpn, ASEDIS and D32DIS fields reset to 0.
        self.sr.cpacr = 0;
        self.sr.ttbcr = 0;
        self.sr.fcseidr = 0;
        self.sr.joscr = 0;
        if let Some((reset, _)) = self.config.imp.actlr {
            self.sr.actlr = Some(reset);
        }
        self.sr.imp = self.config.imp.imp_regs.iter().map(|r| r.reset).collect();
        self.epoch += 1;
    }

    fn sctlr_rw(&self) -> Result<u32, Stop> {
        let (rw, _) = need(self.config.imp.sctlr, "the SCTLR's IMPLEMENTATION DEFINED bits (B4.1.130)")?;
        let mut m = SCTLR_TE | SCTLR_AFE | SCTLR_TRE | SCTLR_EE | SCTLR_V | SCTLR_A | SCTLR_M | rw;
        if self.config.features.mp {
            m |= SCTLR_SW;
        }
        Ok(m)
    }

    /// CPACR (B4.1.40): the value of its read-only fields.
    fn cpacr_fixed(&self) -> u32 {
        let f = &self.config.features;
        let mut v = 0;
        if f.vfp.is_some() && !f.simd {
            v |= 1 << 31;
        }
        if f.vfp.is_some() && !f.d32 {
            v |= 1 << 30;
        }
        v
    }

    fn cpacr_write(&mut self, v: u32) -> Result<(), Stop> {
        let f = &self.config.features;
        let fp = f.vfp.is_some() || f.simd;
        let mut rw = if fp { 0xf << 20 } else { 0 };
        if v & (1 << 31) != 0 && f.vfp.is_some() && f.simd && need(self.config.imp.cpacr_asedis, "whether CPACR.ASEDIS is implemented (B4.1.40)")? {
            rw |= 1 << 31;
        }
        if v & (1 << 30) != 0 && f.vfp.is_some() && f.d32 && need(self.config.imp.cpacr_d32dis, "whether CPACR.D32DIS is implemented (B4.1.40)")? {
            rw |= 1 << 30;
        }
        if v & (1 << 28) != 0 {
            let dfr0 = need(self.config.imp.id_dfr0, "ID_DFR0 (whether there is a CP14 trace interface, CPACR.TRCDIS)")?;
            if (dfr0 >> 12) & 0xf == 1 {
                return unimpl("CPACR.TRCDIS with a CP14 trace interface");
            }
        }
        self.sr.cpacr = v & rw;
        Ok(())
    }

    fn translation_write(&mut self, old: u32, new: u32) -> Result<u32, Stop> {
        if old != new {
            // The translation regime changed: code translated before may not
            // be what fetching now gives.
            self.epoch += 1;
            return Err(Stop::Resume);
        }
        Ok(0)
    }

    /// MRC, MCR, MRRC, MCRR (A8.8.99, A8.8.100, A8.8.108, A8.8.109) to CP14
    /// or CP15: `a` is `gex_abi::a32::sys::cp`.
    pub(crate) fn coproc(&mut self, regs: &mut dyn Regs, mem: &mut dyn PhysMem, pc: u64, op: i32, a: u32, b: u64) -> Result<u64, Stop> {
        let coproc = (a >> 16) & 15;
        let opc1 = (a >> 12) & 7;
        let crn = (a >> 8) & 15;
        let crm = (a >> 4) & 15;
        let opc2 = a & 7;
        use abi::sys::*;
        match (op, coproc) {
            (MRC, 15) => self.cp15(regs, mem, pc, crn, opc1, crm, opc2, Acc::Read).map(u64::from),
            (MCR, 15) => self.cp15(regs, mem, pc, crn, opc1, crm, opc2, Acc::Write(b as u32)).map(|_| 0),
            (MRC, 14) => self.cp14(regs, pc, crn, opc1, crm, opc2, Acc::Read).map(u64::from),
            (MCR, 14) => self.cp14(regs, pc, crn, opc1, crm, opc2, Acc::Write(b as u32)).map(|_| 0),
            (MRRC, 15) | (MCRR, 15) => self.cp15_64(regs, pc, opc1, crm, if op == MRRC { None } else { Some(b) }),
            (MRRC, 14) | (MCRR, 14) => self.cp14_64(regs, pc, opc1, crm, op == MRRC),
            _ => unimpl(format!("coprocessor operation {op} to CP{coproc}")),
        }
    }

    fn undef(&mut self, regs: &mut dyn Regs, pc: u64) -> Result<u32, Stop> {
        self.take_undef(regs, pc).map(|v| v as u32)
    }

    /// ID_DFR0.Performance Monitors: whether the CP15 c9 c12-c14 encodings
    /// are the Performance Monitors Extension's.
    fn pmu_present(&self) -> Result<bool, Stop> {
        let dfr0 = need(self.config.imp.id_dfr0, "ID_DFR0 (whether the Performance Monitors Extension is implemented)")?;
        match (dfr0 >> 24) & 0xf {
            1 | 2 => Ok(true),
            0xf => Ok(false),
            _ => Err(Stop::ImpDef("ID_DFR0.PerfMon = 0: whether PMUv1 is implemented (B4.1.82)".into())),
        }
    }

    fn generic_timer(&self) -> Result<bool, Stop> {
        let pfr1 = need(self.config.imp.id_pfr[1], "ID_PFR1 (whether the Generic Timer Extension is implemented)")?;
        Ok((pfr1 >> 16) & 0xf == 1)
    }

    /// An IMPLEMENTATION DEFINED encoding (B3.17.2) from [`crate::ImpDef::imp_regs`].
    fn imp_reg(&mut self, crn: u32, opc1: u32, crm: u32, opc2: u32, acc: Acc) -> Result<u32, Stop> {
        let cp = abi::sys::cp(15, opc1 as u8, crn as u8, crm as u8, opc2 as u8) as u32;
        match self.config.imp.imp_regs.iter().position(|r| r.cp == cp) {
            Some(i) => match acc {
                Acc::Read => Ok(self.sr.imp[i]),
                Acc::Write(v) => {
                    let w = self.config.imp.imp_regs[i].writable;
                    self.sr.imp[i] = (self.sr.imp[i] & !w) | (v & w);
                    Ok(0)
                }
            },
            None => Err(Stop::ImpDef(format!("the IMPLEMENTATION DEFINED CP15 register c{crn}, {opc1}, c{crm}, {opc2} (B3.17.2)"))),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn cp15(&mut self, regs: &mut dyn Regs, mem: &mut dyn PhysMem, pc: u64, crn: u32, opc1: u32, crm: u32, opc2: u32, acc: Acc) -> Result<u32, Stop> {
        let name = format!("c{crn}, {opc1}, c{crm}, {opc2}");
        let ro = |acc: Acc, v: Result<u32, Stop>| -> Result<u32, Stop> {
            match acc {
                Acc::Read => v,
                Acc::Write(_) => unpred(format!("MCR to the read-only CP15 register {name} (B3.15.2)")),
            }
        };
        let wo = |acc: Acc| -> Result<u32, Stop> {
            match acc {
                Acc::Read => unpred(format!("MRC from the write-only CP15 operation {name} (B3.15.2)")),
                Acc::Write(v) => Ok(v),
            }
        };
        let unalloc = || unpred(format!("an unallocated CP15 encoding {name} (B3.15.2)"));
        let barrier = (crn, opc1, crm, opc2) == (7, 0, 5, 4) || (crn, opc1, crm) == (7, 0, 10) && matches!(opc2, 4 | 5);
        // B3.15.2: from User mode only the encodings B3.17.3 (Table B3-43)
        // lists are accessible; the others are UNDEFINED.
        if !self.privileged() {
            let ok = barrier || (crn, opc1, crm) == (13, 0, 0) && matches!(opc2, 2 | 3);
            if !ok {
                if crn == 9 && opc1 == 0 && (12..=14).contains(&crm) && self.pmu_present()? {
                    return unimpl("the Performance Monitors Extension registers (PMUSERENR controls PL0 access)");
                }
                if crn == 14 && self.generic_timer()? {
                    return unimpl("the Generic Timer Extension registers");
                }
                return self.undef(regs, pc);
            }
        }
        if barrier {
            // B4.2.5: CP15ISB, CP15DSB, CP15DMB, UNDEFINED when SCTLR.CP15BEN
            // is 0. The model's accesses are complete when made.
            if self.sr.sctlr & SCTLR_CP15BEN == 0 {
                return self.undef(regs, pc);
            }
            return wo(acc).map(|_| 0);
        }
        let imp = &self.config.imp;
        match crn {
            0 => match (opc1, crm, opc2) {
                (0, 0, 0 | 4 | 7) => ro(acc, need(imp.midr, "MIDR")),
                (0, 0, 1) => ro(acc, need(imp.ctr, "CTR")),
                (0, 0, 2) => ro(acc, need(imp.tcmtr, "TCMTR")),
                (0, 0, 3) => ro(acc, need(imp.tlbtr, "TLBTR")),
                (0, 0, 5) => ro(acc, need(imp.mpidr, "MPIDR")),
                (0, 0, 6) => ro(acc, need(imp.revidr, "REVIDR")),
                (0, 1, 0 | 1) => ro(acc, need(imp.id_pfr[opc2 as usize], "ID_PFR0/1")),
                (0, 1, 2) => ro(acc, need(imp.id_dfr0, "ID_DFR0")),
                (0, 1, 3) => ro(acc, need(imp.id_afr0, "ID_AFR0")),
                (0, 1, 4..=7) => ro(acc, need(imp.id_mmfr[opc2 as usize - 4], "ID_MMFR0-3")),
                (0, 2, 0..=5) => ro(acc, need(imp.id_isar[opc2 as usize], "ID_ISAR0-5")),
                // B3.17.1 Figure B3-27: the reserved CPUID encodings are RAZ.
                (0, 2, 6 | 7) | (0, 3..=7, _) => ro(acc, Ok(0)),
                (1, 0, 0) => {
                    let sel = self.sr.csselr;
                    let v = imp.ccsidr.iter().find(|(s, _)| *s == sel).map(|&(_, v)| v);
                    ro(acc, v.ok_or_else(|| Stop::ImpDef(format!("CCSIDR for CSSELR = {sel:#x}"))))
                }
                (1, 0, 1) => ro(acc, need(imp.clidr, "CLIDR")),
                (1, 0, 7) => ro(acc, need(imp.aidr, "AIDR")),
                (2, 0, 0) => match acc {
                    Acc::Read => Ok(self.sr.csselr),
                    Acc::Write(v) => {
                        // B4.1.41: a level (with InD) that is not implemented is
                        // UNPREDICTABLE.
                        let clidr = need(imp.clidr, "CLIDR (the cache levels CSSELR can select)")?;
                        let level = (v >> 1) & 7;
                        let ctype = if level < 7 { (clidr >> (3 * level)) & 7 } else { 0 };
                        let ok = if v & 1 != 0 { matches!(ctype, 0b001 | 0b011) } else { matches!(ctype, 0b010 | 0b011 | 0b100) };
                        if !ok {
                            return unpred(format!("CSSELR = {v:#x} selects a cache that is not implemented (B4.1.41)"));
                        }
                        self.sr.csselr = v & 0xf;
                        Ok(0)
                    }
                },
                _ => unalloc(),
            },
            1 => match (opc1, crm, opc2) {
                (0, 0, 0) => match acc {
                    Acc::Read => Ok(self.sr.sctlr),
                    Acc::Write(v) => {
                        let m = self.sctlr_rw()?;
                        let old = self.sr.sctlr;
                        self.sr.sctlr = (old & !m) | (v & m);
                        self.translation_write(old & SCTLR_XLATE, self.sr.sctlr & SCTLR_XLATE)
                    }
                },
                (0, 0, 1) => {
                    let (reset, w) = need(imp.actlr, "the ACTLR (B4.1.1)")?;
                    let cur = self.sr.actlr.unwrap_or(reset);
                    match acc {
                        Acc::Read => Ok(cur),
                        Acc::Write(v) => {
                            self.sr.actlr = Some((cur & !w) | (v & w));
                            Ok(0)
                        }
                    }
                }
                (0, 0, 2) => match acc {
                    Acc::Read => Ok(self.sr.cpacr | self.cpacr_fixed()),
                    Acc::Write(v) => self.cpacr_write(v).map(|_| 0),
                },
                _ => unalloc(),
            },
            2 => match (opc1, crm, opc2) {
                (0, 0, 0) => match acc {
                    Acc::Read => Ok(self.sr.ttbr0 as u32),
                    Acc::Write(v) => {
                        let old = self.sr.ttbr0 as u32;
                        // Bit 6 is reserved without the MP Extensions and LPAE.
                        let mask = if self.config.features.mp || self.lpae() { u32::MAX } else { !0x40 };
                        self.sr.ttbr0 = (self.sr.ttbr0 & !0xffff_ffff) | (v & mask) as u64;
                        self.translation_write(old, self.sr.ttbr0 as u32)
                    }
                },
                (0, 0, 1) => match acc {
                    Acc::Read => Ok(self.sr.ttbr1 as u32),
                    Acc::Write(v) => {
                        let old = self.sr.ttbr1 as u32;
                        let mask = if self.lpae() {
                            u32::MAX
                        } else if self.config.features.mp {
                            0xffff_c07f
                        } else {
                            0xffff_c03f
                        };
                        self.sr.ttbr1 = (self.sr.ttbr1 & !0xffff_ffff) | (v & mask) as u64;
                        self.translation_write(old, self.sr.ttbr1 as u32)
                    }
                },
                (0, 0, 2) => match acc {
                    Acc::Read => Ok(self.sr.ttbcr),
                    Acc::Write(v) => {
                        let mask = if self.lpae() {
                            if v & (1 << 31) != 0 {
                                return unimpl("TTBCR.EAE = 1: the Long-descriptor translation table format");
                            }
                            // Bits 21:19, 15:14 and 6:3 are reserved in both formats.
                            !(0x7 << 19 | 0x3 << 14 | 0xf << 3)
                        } else {
                            7
                        };
                        let old = self.sr.ttbcr;
                        self.sr.ttbcr = v & mask;
                        self.translation_write(old, self.sr.ttbcr)
                    }
                },
                _ => unalloc(),
            },
            3 => match (opc1, crm, opc2) {
                (0, 0, 0) => match acc {
                    Acc::Read => Ok(self.sr.dacr),
                    Acc::Write(v) => {
                        let old = self.sr.dacr;
                        self.sr.dacr = v;
                        self.translation_write(old, v)
                    }
                },
                _ => unalloc(),
            },
            // B3.15.2 rule 1: c4 is not allocated; c12 only with the Security
            // Extensions.
            4 | 12 => self.undef(regs, pc),
            5 => match (opc1, crm, opc2) {
                (0, 0, 0) => match acc {
                    Acc::Read => Ok(self.sr.dfsr),
                    Acc::Write(v) => {
                        self.sr.dfsr = v & if self.lpae() { 0x2eff } else { 0x0cff };
                        Ok(0)
                    }
                },
                (0, 0, 1) => match acc {
                    Acc::Read => Ok(self.sr.ifsr),
                    Acc::Write(v) => {
                        self.sr.ifsr = v & if self.lpae() { 0x063f } else { 0x040f };
                        Ok(0)
                    }
                },
                (0, 1, 0 | 1) => {
                    // B4.1.2: UNK/SBZP unless ID_MMFR0.Auxiliary registers says
                    // the IMPLEMENTATION DEFINED ADFSR and AIFSR are implemented.
                    let m0 = need(imp.id_mmfr[0], "ID_MMFR0 (whether ADFSR/AIFSR are implemented)")?;
                    if (m0 >> 20) & 0xf == 0b0010 {
                        return Err(Stop::ImpDef("the IMPLEMENTATION DEFINED ADFSR/AIFSR (B4.1.2)".into()));
                    }
                    Ok(0)
                }
                _ => unalloc(),
            },
            6 => match (opc1, crm, opc2) {
                (0, 0, 0) => match acc {
                    Acc::Read => Ok(self.sr.dfar),
                    Acc::Write(v) => {
                        self.sr.dfar = v;
                        Ok(0)
                    }
                },
                (0, 0, 2) => match acc {
                    Acc::Read => Ok(self.sr.ifar),
                    Acc::Write(v) => {
                        self.sr.ifar = v;
                        Ok(0)
                    }
                },
                _ => unalloc(),
            },
            7 => self.cp15_c7(regs, mem, pc, opc1, crm, opc2, acc, &name),
            8 => {
                // B4.2.2 TLB maintenance. The model keeps no TLB.
                let mp = self.config.features.mp;
                let ok = opc1 == 0
                    && match crm {
                        3 => mp && opc2 <= 3,
                        5 | 6 => opc2 <= 2,
                        7 => opc2 <= 2 || (mp && opc2 == 3),
                        _ => false,
                    };
                if !ok {
                    return unalloc();
                }
                wo(acc)?;
                self.epoch += 1;
                Ok(0)
            }
            9 => {
                if opc1 == 0 && (12..=14).contains(&crm) {
                    if self.pmu_present()? {
                        return unimpl("the Performance Monitors Extension registers");
                    }
                    return unpred(format!("{name}: a Performance Monitors Extension encoding without the extension (B3.18.10)"));
                }
                if matches!(crm, 0..=2 | 5..=8) || (opc1 == 0 && crm == 15) || (opc1 != 0 && (12..=15).contains(&crm)) {
                    return self.imp_reg(crn, opc1, crm, opc2, acc);
                }
                unalloc()
            }
            10 => match (opc1, crm, opc2) {
                (0, 0 | 1 | 4 | 8, _) => self.imp_reg(crn, opc1, crm, opc2, acc),
                (0, 2, 0) => match acc {
                    Acc::Read => Ok(self.sr.prrr),
                    Acc::Write(v) => {
                        let mask = if self.lpae() {
                            u32::MAX
                        } else {
                            let m0 = need(imp.id_mmfr[0], "ID_MMFR0 (whether PRRR.NOSn are implemented)")?;
                            0x000f_ffff | if (m0 >> 12) & 0xf != 0 { 0xff00_0000 } else { 0 }
                        };
                        let old = self.sr.prrr;
                        self.sr.prrr = v & mask;
                        self.translation_write(old, self.sr.prrr)
                    }
                },
                (0, 2, 1) => match acc {
                    Acc::Read => Ok(self.sr.nmrr),
                    Acc::Write(v) => {
                        let old = self.sr.nmrr;
                        self.sr.nmrr = v;
                        self.translation_write(old, v)
                    }
                },
                (0, 3, 0 | 1) if self.lpae() => Err(Stop::ImpDef("the IMPLEMENTATION DEFINED AMAIR0/AMAIR1 (B4.1.5)".into())),
                _ => unalloc(),
            },
            11 => {
                if matches!(crm, 0..=8 | 15) {
                    return self.imp_reg(crn, opc1, crm, opc2, acc);
                }
                unalloc()
            }
            13 => match (opc1, crm, opc2) {
                (0, 0, 0) => {
                    // B4.1.56: RAZ/WI without the FCSE (ID_MMFR0.FCSE).
                    let m0 = need(imp.id_mmfr[0], "ID_MMFR0 (whether the FCSE is implemented)")?;
                    let fcse = (m0 >> 24) & 0xf == 1;
                    match acc {
                        Acc::Read => Ok(self.sr.fcseidr),
                        Acc::Write(v) => {
                            let old = self.sr.fcseidr;
                            self.sr.fcseidr = if fcse { v & 0xfe00_0000 } else { 0 };
                            self.translation_write(old, self.sr.fcseidr)
                        }
                    }
                }
                (0, 0, 1) => match acc {
                    Acc::Read => Ok(self.sr.contextidr),
                    Acc::Write(v) => {
                        let old = self.sr.contextidr;
                        self.sr.contextidr = v;
                        self.translation_write(old, v)
                    }
                },
                (0, 0, 2) => match acc {
                    Acc::Read => Ok(self.sr.tpidrurw),
                    Acc::Write(v) => {
                        self.sr.tpidrurw = v;
                        Ok(0)
                    }
                },
                (0, 0, 3) => match acc {
                    Acc::Read => Ok(self.sr.tpidruro),
                    Acc::Write(_) if !self.privileged() => unpred("MCR to TPIDRURO at PL0, where it is read-only (B4.1.151, B3.15.2)"),
                    Acc::Write(v) => {
                        self.sr.tpidruro = v;
                        Ok(0)
                    }
                },
                (0, 0, 4) => match acc {
                    Acc::Read => Ok(self.sr.tpidrprw),
                    Acc::Write(v) => {
                        self.sr.tpidrprw = v;
                        Ok(0)
                    }
                },
                _ => unalloc(),
            },
            14 => {
                if self.generic_timer()? {
                    return unimpl("the Generic Timer Extension registers");
                }
                self.undef(regs, pc)
            }
            _ => match imp.c15_allocated {
                Some(false) => self.undef(regs, pc),
                _ => self.imp_reg(crn, opc1, crm, opc2, acc),
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn cp15_c7(&mut self, regs: &mut dyn Regs, mem: &mut dyn PhysMem, pc: u64, opc1: u32, crm: u32, opc2: u32, acc: Acc, name: &str) -> Result<u32, Stop> {
        let wo = |acc: Acc| -> Result<u32, Stop> {
            match acc {
                Acc::Read => unpred(format!("MRC from the write-only CP15 operation {name} (B3.15.2)")),
                Acc::Write(v) => Ok(v),
            }
        };
        let unalloc = || unpred(format!("an unallocated CP15 encoding {name} (B3.15.2)"));
        if opc1 != 0 {
            return unalloc();
        }
        let mp = self.config.features.mp;
        match (crm, opc2) {
            (0, 4) | (13, 1) => unpred(format!("{name}: an ARMv6 operation retired in ARMv7 (B3.18.15 Retired operations)")),
            (4, 0) => match acc {
                Acc::Read => Ok(self.sr.par as u32),
                Acc::Write(v) => {
                    let mask = if self.lpae() { u32::MAX } else { !0x800 };
                    self.sr.par = (self.sr.par & !0xffff_ffff) | (v & mask) as u64;
                    Ok(0)
                }
            },
            // ICIALLUIS, BPIALLIS (Multiprocessing Extensions), ICIALLU, BPIALL.
            (1, 0 | 6) if mp => wo(acc).map(|_| {
                self.epoch += 1;
                0
            }),
            (5, 0 | 6) => wo(acc).map(|_| {
                self.epoch += 1;
                0
            }),
            // ICIMVAU, BPIMVA.
            (5, 1 | 7) => {
                let va = wo(acc)?;
                let translates = if opc2 == 1 {
                    need(self.config.imp.icimvau_translates, "whether ICIMVAU translates its address (B3.12.5)")?
                } else {
                    need(self.config.imp.bpimva_translates, "whether BPIMVA translates its address (B3.12.5)")?
                };
                if translates {
                    self.maint_by_mva(regs, mem, pc, va, true)?;
                }
                self.epoch += 1;
                Ok(0)
            }
            // DCIMVAC, DCCMVAC, DCCMVAU, DCCIMVAC: the model has no cache.
            (6, 1) | (10, 1) | (11, 1) | (14, 1) => {
                let va = wo(acc)?;
                self.maint_by_mva(regs, mem, pc, va, false).map(|_| 0)
            }
            // DCISW, DCCSW, DCCISW.
            (6, 2) | (10, 2) | (14, 2) => {
                let v = wo(acc)?;
                self.check_set_way(v).map(|_| 0)
            }
            (8, 0..=3) => {
                let va = wo(acc)?;
                self.ats1c(regs, mem, pc, va, opc2 < 2, opc2 & 1 != 0).map(|_| 0)
            }
            _ => unalloc(),
        }
    }

    /// B4.2.1 Set/way: a level, set or way larger than the cache's is
    /// UNPREDICTABLE.
    fn check_set_way(&self, v: u32) -> Result<(), Stop> {
        let imp = &self.config.imp;
        let clidr = need(imp.clidr, "CLIDR (the caches a set/way operation can name)")?;
        let level = (v >> 1) & 7;
        let ctype = if level < 7 { (clidr >> (3 * level)) & 7 } else { 0 };
        if !matches!(ctype, 0b010 | 0b011 | 0b100) {
            return unpred(format!("a set/way operation on cache level {} with no data or unified cache (B4.2.1)", level + 1));
        }
        let sel = level << 1;
        let ccsidr = imp.ccsidr.iter().find(|(s, _)| *s == sel).map(|&(_, c)| c).ok_or_else(|| Stop::ImpDef(format!("CCSIDR for CSSELR = {sel:#x}")))?;
        let l = (ccsidr & 7) + 4;
        let assoc = ((ccsidr >> 3) & 0x3ff) + 1;
        let nsets = ((ccsidr >> 13) & 0x7fff) + 1;
        let a = 32 - (assoc - 1).leading_zeros();
        let s = 32 - (nsets - 1).leading_zeros();
        let set = (v >> l) & ((1u64 << s) - 1) as u32;
        let way = if a == 0 { 0 } else { v >> (32 - a) };
        if set >= nsets || way >= assoc {
            return unpred(format!("a set/way operation {v:#x} beyond the cache's sets or ways (B4.2.1)"));
        }
        Ok(())
    }

    /// MCRR/MRRC to CP15 (B3.15.2): with LPAE the 64-bit TTBR0, TTBR1 and
    /// PAR; the Generic Timer's when implemented; otherwise UNDEFINED (the
    /// LPAE encodings without LPAE are UNPREDICTABLE, B3.17.2 note e).
    fn cp15_64(&mut self, regs: &mut dyn Regs, pc: u64, opc1: u32, crm: u32, w: Option<u64>) -> Result<u64, Stop> {
        let lpae_reg = matches!((opc1, crm), (0, 2) | (1, 2) | (0, 7));
        if !self.privileged() {
            if crm == 14 && self.generic_timer()? {
                return unimpl("the Generic Timer Extension registers");
            }
            return self.take_undef(regs, pc);
        }
        if crm == 14 {
            if self.generic_timer()? {
                return unimpl("the Generic Timer Extension registers");
            }
            return self.take_undef(regs, pc);
        }
        if !lpae_reg {
            return self.take_undef(regs, pc);
        }
        if !self.lpae() {
            return unpred(format!("MCRR/MRRC p15, {opc1}, c{crm} without LPAE (B3.17.2)"));
        }
        // B4.1.154: bits 63:56 and 47:40 of a TTBR are reserved, RAZ/WI.
        const TTBR64: u64 = 0x00ff_00ff_ffff_ffff;
        match (opc1, crm, w) {
            (0, 2, None) => Ok(self.sr.ttbr0),
            (1, 2, None) => Ok(self.sr.ttbr1),
            (_, _, None) => Ok(self.sr.par),
            (0, 2, Some(v)) => {
                let old = self.sr.ttbr0;
                self.sr.ttbr0 = v & TTBR64;
                self.translation_write64(old, self.sr.ttbr0)
            }
            (1, 2, Some(v)) => {
                let old = self.sr.ttbr1;
                self.sr.ttbr1 = v & TTBR64;
                self.translation_write64(old, self.sr.ttbr1)
            }
            (_, _, Some(v)) => {
                self.sr.par = v;
                Ok(0)
            }
        }
    }

    fn translation_write64(&mut self, old: u64, new: u64) -> Result<u64, Stop> {
        if old as u32 != new as u32 {
            self.epoch += 1;
            return Err(Stop::Resume);
        }
        Ok(0)
    }

    /// MRRC to CP14 (C6.4.1 Table C6-2): with LPAE the 64-bit DBGDRAR and
    /// DBGDSAR; every other MCRR/MRRC is UNDEFINED (B3.15.2).
    fn cp14_64(&mut self, regs: &mut dyn Regs, pc: u64, opc1: u32, crm: u32, read: bool) -> Result<u64, Stop> {
        if !(read && self.lpae() && opc1 == 0 && matches!(crm, 1 | 2)) {
            return self.take_undef(regs, pc);
        }
        if crm == 1 {
            need(self.config.imp.dbgdrar, "DBGDRAR")
        } else {
            need(self.config.imp.dbgdsar, "DBGDSAR")
        }
    }

    /// MRC/MCR to CP14 (B3.15.2 For CP14, C6.4, A2.10, A2.11, B1.13.5).
    #[allow(clippy::too_many_arguments)]
    fn cp14(&mut self, regs: &mut dyn Regs, pc: u64, crn: u32, opc1: u32, crm: u32, opc2: u32, acc: Acc) -> Result<u32, Stop> {
        let name = format!("p14, {opc1}, c{crn}, c{crm}, {opc2}");
        let pl0 = !self.privileged();
        let imp = &self.config.imp;
        match opc1 {
            0 => {
                // C6.6.2 Table C6-7: the baseline registers are accessible at
                // PL0 while DBGDSCR.UDCCdis is 0, its debug logic reset value
                // (the model has no debug logic to set it).
                let ro = |acc: Acc, v: Result<u32, Stop>| -> Result<u32, Stop> {
                    match acc {
                        Acc::Read => v,
                        Acc::Write(_) => unpred(format!("MCR to the read-only debug register {name} (C6.6.2)")),
                    }
                };
                match (crn, crm, opc2) {
                    (0, 0, 0) => ro(acc, need(imp.dbgdidr, "DBGDIDR")),
                    (1, 0, 0) => ro(acc, need(imp.dbgdrar, "DBGDRAR").map(|v| v as u32)),
                    (2, 0, 0) => ro(acc, need(imp.dbgdsar, "DBGDSAR").map(|v| v as u32)),
                    (0, 1, 0) => ro(acc, unimpl("DBGDSCRint: the debug logic is not modelled")),
                    (0, 5, 0) => unimpl("the CP14 debug communications channel (DBGDTRRXint/DBGDTRTXint)"),
                    _ if pl0 => self.undef(regs, pc),
                    _ => {
                        let didr = need(imp.dbgdidr, "DBGDIDR (the debug architecture version)")?;
                        if (didr >> 16) & 0xf == 0b0100 {
                            return unpred(format!("{name}: an unallocated CP14 debug encoding with only the baseline CP14 registers (C6.6.4)"));
                        }
                        unimpl(format!("the CP14 debug register {name}"))
                    }
                }
            }
            1 => {
                if pl0 {
                    return self.undef(regs, pc);
                }
                let dfr0 = need(imp.id_dfr0, "ID_DFR0 (whether there is a CP14 trace interface)")?;
                if (dfr0 >> 12) & 0xf == 1 {
                    return unimpl(format!("the CP14 trace register {name}"));
                }
                Err(Stop::ImpDef(format!("{name}: CP14 opc1 = 1 with no CP14 trace interface (the trace architecture defines it)")))
            }
            2..=5 => self.undef(regs, pc),
            6 => {
                // A2.10 ThumbEE registers.
                if !self.config.features.thumbee {
                    if pl0 {
                        return self.undef(regs, pc);
                    }
                    return unpred(format!("{name}: a ThumbEE register without ThumbEE (B3.15.2)"));
                }
                match (crn, crm, opc2) {
                    (0, 0, 0) => match acc {
                        // B4.1.133 TEECR: an unprivileged write is UNDEFINED.
                        Acc::Read => Ok(self.sr.teecr),
                        Acc::Write(_) if pl0 => self.undef(regs, pc),
                        Acc::Write(v) => {
                            self.sr.teecr = v & 1;
                            Ok(0)
                        }
                    },
                    (1, 0, 0) => {
                        // B4.1.134 TEEHBR: unprivileged access needs TEECR.XED = 0.
                        if pl0 && self.sr.teecr & 1 != 0 {
                            return self.undef(regs, pc);
                        }
                        match acc {
                            Acc::Read => Ok(self.sr.teehbr),
                            Acc::Write(v) => {
                                self.sr.teehbr = v & !3;
                                Ok(0)
                            }
                        }
                    }
                    _ if pl0 => self.undef(regs, pc),
                    _ => unpred(format!("{name}: an unallocated ThumbEE register encoding (B3.15.2)")),
                }
            }
            _ => {
                // A2.11.5 Table A2-17, B1.13.5: the trivial Jazelle
                // implementation. JOSCR.CD has no effect, so unprivileged
                // accesses behave as with CD = 0.
                match (crn, crm, opc2) {
                    // JIDR: RAZ (the implementer and subarchitecture fields
                    // must be zero; the whole register can be RAZ).
                    (0, 0, 0) => match acc {
                        Acc::Read => Ok(0),
                        Acc::Write(_) if pl0 => self.undef(regs, pc),
                        Acc::Write(_) => unpred("MCR to JIDR at PL1 (A2.11.5)"),
                    },
                    // JOSCR: PL1 only.
                    (1, 0, 0) => {
                        if pl0 {
                            return self.undef(regs, pc);
                        }
                        let rw = need(imp.joscr_rw, "whether the trivial Jazelle JOSCR is read/write or RAZ/WI (B1.13.5)")?;
                        match acc {
                            Acc::Read => Ok(if rw { self.sr.joscr } else { 0 }),
                            Acc::Write(v) => {
                                if rw {
                                    self.sr.joscr = v & 3;
                                }
                                Ok(0)
                            }
                        }
                    }
                    // JMCR: RAZ/WI; an unprivileged read is UNDEFINED.
                    (2, 0, 0) => match acc {
                        Acc::Read if pl0 => self.undef(regs, pc),
                        _ => Ok(0),
                    },
                    _ if pl0 => self.undef(regs, pc),
                    _ => unpred(format!("{name}: an unallocated Jazelle register encoding (B3.15.2)")),
                }
            }
        }
    }
}
