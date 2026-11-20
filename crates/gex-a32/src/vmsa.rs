//! The VMSA with the Short-descriptor translation table format (B3.2-B3.13,
//! the B2.4 and B3.19 pseudocode): translation, permission and fault
//! checking, the fault reporting registers, and the data and instruction
//! accesses translated code makes.
//!
//! The model keeps no TLB: every access walks the translation tables. That
//! is a legal implementation (B3.9: a TLB is a cache of translations, and
//! nothing requires an implementation to cache any), which makes every TLB
//! maintenance operation complete trivially.

use crate::cp::{SCTLR_A, SCTLR_AFE, SCTLR_EE, SCTLR_HA, SCTLR_M, SCTLR_TRE};
use crate::{abi, need, unimpl, unpred, Core, PhysMem, Regs, Stop};

/// B2.4.1 MemType.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MemType {
    Normal,
    Device,
    StronglyOrdered,
}

/// B2.4.1 MemoryAttributes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MemAttrs {
    pub ty: MemType,
    pub innerattrs: u8,
    pub innerhints: u8,
    pub outerattrs: u8,
    pub outerhints: u8,
    pub shareable: bool,
    pub outershareable: bool,
}

impl MemAttrs {
    fn so() -> MemAttrs {
        MemAttrs { ty: MemType::StronglyOrdered, innerattrs: 0, innerhints: 0, outerattrs: 0, outerhints: 0, shareable: true, outershareable: true }
    }
    fn device(shareable: bool) -> MemAttrs {
        MemAttrs { ty: MemType::Device, shareable, outershareable: shareable, ..MemAttrs::so() }
    }
}

/// `ConvertAttrsHints()` (B3.19.6): (hints, attributes).
fn attrs_hints(rgn: u32) -> (u8, u8) {
    let rgn = rgn & 3;
    if rgn == 0 {
        (0, 0)
    } else if rgn & 1 != 0 {
        (0b10 | (!(rgn >> 1) & 1) as u8, 0b11)
    } else {
        (0b10, 0b10)
    }
}

/// The DAbort types of B2.4.10 the model reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Alignment,
    Translation,
    AccessFlag,
    Domain,
    Permission,
    /// DAbort_SyncExternalonWalk.
    ExtWalk,
    /// DAbort_ICacheMaint.
    ICacheMaint,
}

/// An MMU fault, Alignment fault or external abort on a walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Fault {
    pub kind: Kind,
    pub level: u8,
    pub domain: Option<u8>,
}

/// Why a translation did not give an address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Xlate {
    Fault(Fault),
    Stop(Stop),
}

impl From<Stop> for Xlate {
    fn from(s: Stop) -> Xlate {
        Xlate::Stop(s)
    }
}

fn fault(kind: Kind, level: u8, domain: Option<u8>) -> Xlate {
    Xlate::Fault(Fault { kind, level, domain })
}

/// `EncodeSDFSR()` (B2.4.10): the 5-bit FS of the Short-descriptor format.
pub(crate) fn encode_sd(f: &Fault) -> u32 {
    let l2 = (f.level == 2) as u32;
    match f.kind {
        Kind::AccessFlag => {
            if l2 == 0 {
                0b00011
            } else {
                0b00110
            }
        }
        Kind::Alignment => 0b00001,
        Kind::Permission => 0b01101 | l2 << 1,
        Kind::Domain => 0b01001 | l2 << 1,
        Kind::Translation => 0b00101 | l2 << 1,
        Kind::ExtWalk => 0b01100 | l2 << 1,
        Kind::ICacheMaint => 0b00100,
    }
}

/// FS in an FSR's bits 10 and 3:0 (B4.1.52, B4.1.96).
pub(crate) fn encode_fs(fs: u32) -> u32 {
    (fs & 0xf) | ((fs >> 4) & 1) << 10
}

/// A translation table lookup (`TLBRecord`, B3.19.5).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Walk {
    pub pa: u64,
    pub texcb: u32,
    pub s: bool,
    pub ap: u32,
    pub xn: bool,
    pub pxn: bool,
    pub domain: u8,
    pub level: u8,
    pub supersection: bool,
    /// A hardware Access flag update the walk must make (B3.7.4): the
    /// descriptor's address and the word to write.
    pub af_update: Option<(u64, u32)>,
}

/// What a data or instruction translation gives.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Out {
    pub pa: u64,
    pub attrs: MemAttrs,
    pub supersection: bool,
}

impl Core {
    pub(crate) fn lpae(&self) -> bool {
        self.config.features.lpae
    }

    /// Whether the Short-descriptor format has the PXN bit (B3.5.2): with
    /// LPAE, else ID_MMFR0.VMSA support >= 0b0100.
    fn has_pxn(&self) -> Result<bool, Stop> {
        if self.lpae() {
            return Ok(true);
        }
        let m = need(self.config.imp.id_mmfr[0], "ID_MMFR0 (whether the PXN bit is supported, B3.5.1)")?;
        Ok(m & 0xf >= 0b0100)
    }

    /// `FCSETranslate()` (B3.19.2).
    pub(crate) fn fcse(&self, va: u32) -> u32 {
        if va >> 25 == 0 {
            (self.sr.fcseidr & 0xfe00_0000) | va
        } else {
            va
        }
    }

    fn read_desc(&self, mem: &dyn PhysMem, pa: u64) -> Option<u32> {
        let d = mem.read32(pa)?;
        Some(if self.sr.sctlr & SCTLR_EE != 0 { d.swap_bytes() } else { d })
    }

    /// The Access flag of a descriptor at bit `bit` (B3.7.4, the
    /// `TranslationTableWalkSD()` Access flag check): Ok(None) when set or
    /// unused, Ok(Some(update)) for a hardware update, Err for the fault.
    fn access_flag(&self, desc: u32, bit: u32, pa: u64, level: u8, domain: Option<u8>) -> Result<Option<(u64, u32)>, Xlate> {
        if self.sr.sctlr & SCTLR_AFE == 0 || desc & (1 << bit) != 0 {
            return Ok(None);
        }
        if self.sr.sctlr & SCTLR_HA == 0 {
            return Err(fault(Kind::AccessFlag, level, domain));
        }
        let new = desc | (1 << bit);
        let raw = if self.sr.sctlr & SCTLR_EE != 0 { new.swap_bytes() } else { new };
        Ok(Some((pa, raw)))
    }

    /// `TranslationTableWalkSD()` (B3.19.6) for `mva`.
    pub(crate) fn walk(&self, mem: &dyn PhysMem, mva: u32) -> Result<Walk, Xlate> {
        let mut n = self.sr.ttbcr & 7;
        let ttbr = if n == 0 || mva >> (32 - n) == 0 {
            self.sr.ttbr0 as u32
        } else {
            n = 0;
            self.sr.ttbr1 as u32
        };
        // TTBCR.PD0/PD1 exist only with the Security Extensions.
        let l1pa = ((ttbr & (u32::MAX << (14 - n))) | (((mva & (u32::MAX >> n)) >> 20) << 2)) as u64;
        let l1 = match self.read_desc(mem, l1pa) {
            Some(d) => d,
            None => return Err(fault(Kind::ExtWalk, 1, None)),
        };
        let pxn_ok = self.has_pxn()?;
        match l1 & 3 {
            0b00 => Err(fault(Kind::Translation, 1, None)),
            0b01 => {
                let domain = ((l1 >> 5) & 0xf) as u8;
                let pxn = pxn_ok && l1 & (1 << 2) != 0;
                let l2pa = ((l1 & 0xffff_fc00) | ((mva >> 12) & 0xff) << 2) as u64;
                let l2 = match self.read_desc(mem, l2pa) {
                    Some(d) => d,
                    None => return Err(fault(Kind::ExtWalk, 2, Some(domain))),
                };
                if l2 & 3 == 0 {
                    return Err(fault(Kind::Translation, 2, Some(domain)));
                }
                let af_update = self.access_flag(l2, 4, l2pa, 2, Some(domain))?;
                let s = l2 & (1 << 10) != 0;
                let ap = ((l2 >> 9) & 1) << 2 | (l2 >> 4) & 3;
                let (texcb, xn, pa) = if l2 & 2 == 0 {
                    // Large page.
                    (((l2 >> 12) & 7) << 2 | (l2 >> 2) & 3, l2 & (1 << 15) != 0, (l2 & 0xffff_0000) | (mva & 0xffff))
                } else {
                    // Small page.
                    (((l2 >> 6) & 7) << 2 | (l2 >> 2) & 3, l2 & 1 != 0, (l2 & 0xffff_f000) | (mva & 0xfff))
                };
                Ok(Walk { pa: pa as u64, texcb, s, ap, xn, pxn, domain, level: 2, supersection: false, af_update })
            }
            _ => {
                if l1 & 3 == 0b11 && !pxn_ok {
                    // Reserved without the PXN attribute (B3.5.1).
                    return Err(fault(Kind::Translation, 1, None));
                }
                let texcb = ((l1 >> 12) & 7) << 2 | (l1 >> 2) & 3;
                let s = l1 & (1 << 16) != 0;
                let ap = ((l1 >> 15) & 1) << 2 | (l1 >> 10) & 3;
                let xn = l1 & (1 << 4) != 0;
                let pxn = pxn_ok && l1 & 1 != 0;
                let af_update = self.access_flag(l1, 10, l1pa, 1, None)?;
                if l1 & (1 << 18) == 0 {
                    let pa = (l1 & 0xfff0_0000) | (mva & 0xf_ffff);
                    Ok(Walk { pa: pa as u64, texcb, s, ap, xn, pxn, domain: ((l1 >> 5) & 0xf) as u8, level: 1, supersection: false, af_update })
                } else {
                    let m3 = need(self.config.imp.id_mmfr[3], "ID_MMFR3 (whether Supersections are supported, B3.5)")?;
                    if m3 >> 28 != 0 {
                        return Err(Stop::Unpredictable("a Supersection descriptor on an implementation without Supersections (ID_MMFR3, B3.5)".into()).into());
                    }
                    let ext = (((l1 >> 5) & 0xf) << 4 | (l1 >> 20) & 0xf) as u64;
                    let pa = ext << 32 | ((l1 & 0xff00_0000) | (mva & 0xff_ffff)) as u64;
                    Ok(Walk { pa, texcb, s, ap, xn, pxn, domain: 0, level: 1, supersection: true, af_update })
                }
            }
        }
    }

    /// The memory attributes of a Short-descriptor lookup (B3.19.6):
    /// `DefaultTEXDecode()` (B2.4.9) without TEX remap,
    /// `RemappedTEXDecode()` (B3.19.9) with it.
    pub(crate) fn memattrs(&self, texcb: u32, s: bool) -> Result<MemAttrs, Stop> {
        if self.sr.sctlr & SCTLR_TRE == 0 {
            if need(self.config.imp.tre0_remap, "whether PRRR/NMRR have an IMPLEMENTATION DEFINED effect with SCTLR.TRE = 0 (B3.8.3)")? {
                return unimpl("the IMPLEMENTATION DEFINED effect of PRRR/NMRR with SCTLR.TRE = 0 (B3.8.3)");
            }
            return default_tex_decode(texcb, s);
        }
        let region = texcb & 7;
        if region == 6 {
            return Err(Stop::ImpDef("TEX remap region 6 (TEX[0], C, B = 1, 1, 0) is IMPLEMENTATION DEFINED (B3.8.3)".into()));
        }
        let prrr = self.sr.prrr;
        Ok(match (prrr >> (2 * region)) & 3 {
            0b00 => MemAttrs::so(),
            0b01 => MemAttrs::device(true),
            0b10 => {
                let (ih, ia) = attrs_hints(self.sr.nmrr >> (2 * region));
                let (oh, oa) = attrs_hints(self.sr.nmrr >> (2 * region + 16));
                let s_bit = (prrr >> if s { 19 } else { 18 }) & 1 != 0;
                MemAttrs {
                    ty: MemType::Normal,
                    innerattrs: ia,
                    innerhints: ih,
                    outerattrs: oa,
                    outerhints: oh,
                    shareable: s_bit,
                    outershareable: s_bit && (prrr >> (region + 24)) & 1 == 0,
                }
            }
            _ => return unpred(format!("PRRR.TR{region} = 0b11, reserved (B4.1.127)")),
        })
    }

    /// `CheckDomain()` (B3.19.4): Ok(true) for a Client, Ok(false) for a
    /// Manager.
    fn check_domain(&self, w: &Walk) -> Result<bool, Xlate> {
        match (self.sr.dacr >> (2 * w.domain as u32)) & 3 {
            0b00 => Err(fault(Kind::Domain, w.level, Some(w.domain))),
            0b01 => Ok(true),
            0b10 => Err(Stop::Unpredictable(format!("DACR.D{} = 0b10, reserved (B3.19.4)", w.domain)).into()),
            _ => Ok(false),
        }
    }

    /// `CheckPermission()` (B2.4.8) for the Short-descriptor format.
    fn check_permission(&self, w: &Walk, priv_: bool, write: bool) -> Result<(), Xlate> {
        let mut ap = w.ap;
        if self.sr.sctlr & SCTLR_AFE != 0 {
            ap |= 1;
        }
        let abort = match ap {
            0b000 => true,
            0b001 => !priv_,
            0b010 => !priv_ && write,
            0b011 => false,
            0b100 => return Err(Stop::Unpredictable("AP[2:0] = 0b100, reserved (B2.4.8, B3.7.1)".into()).into()),
            0b101 => !priv_ || write,
            _ => write,
        };
        if abort {
            Err(fault(Kind::Permission, w.level, Some(w.domain)))
        } else {
            Ok(())
        }
    }

    /// `TranslateAddressV()` (B3.19.3) of a data access to `mva`.
    pub(crate) fn translate_data(&self, mem: &dyn PhysMem, mva: u32, priv_: bool, write: bool, wasaligned: bool) -> Result<(Out, Option<(u64, u32)>), Xlate> {
        if self.sr.sctlr & SCTLR_M == 0 {
            // TranslateAddressVS1Off(): Strongly-ordered, flat.
            if !wasaligned {
                return Err(Stop::Unpredictable(format!("an unaligned access to Strongly-ordered memory (the MMU is off) at {mva:#x} (B3.19.3, A3.2.2)")).into());
            }
            return Ok((Out { pa: mva as u64, attrs: MemAttrs::so(), supersection: false }, None));
        }
        let w = self.walk(mem, mva)?;
        let attrs = self.memattrs(w.texcb, w.s)?;
        if !wasaligned && attrs.ty != MemType::Normal {
            return Err(Stop::Unpredictable(format!("an unaligned access to Device or Strongly-ordered memory at {mva:#x} without the Virtualization Extensions (B3.19.3, A3.2.2)")).into());
        }
        if self.check_domain(&w)? {
            self.check_permission(&w, priv_, write)?;
        }
        Ok((Out { pa: w.pa, attrs, supersection: w.supersection }, w.af_update))
    }

    /// An instruction fetch's translation (B3.7.2): read permission at the
    /// current privilege, XN, and PXN at PL1, checked in a Client domain
    /// only; a fetch from Device or Strongly-ordered memory is
    /// UNPREDICTABLE (A3.5.7). With the MMU off the fetch is flat, from
    /// Normal memory (B3.2.1).
    pub(crate) fn translate_fetch(&self, mem: &dyn PhysMem, mva: u32, priv_: bool) -> Result<(u64, Option<(u64, u32)>), Xlate> {
        if self.sr.sctlr & SCTLR_M == 0 {
            return Ok((mva as u64, None));
        }
        let w = self.walk(mem, mva)?;
        let attrs = self.memattrs(w.texcb, w.s)?;
        if self.check_domain(&w)? {
            self.check_permission(&w, priv_, false)?;
            if w.xn || (priv_ && w.pxn) {
                return Err(fault(Kind::Permission, w.level, Some(w.domain)));
            }
        }
        if attrs.ty != MemType::Normal {
            return Err(Stop::Unpredictable(format!("an instruction fetch from Device or Strongly-ordered memory at {mva:#x} (A3.5.7)")).into());
        }
        Ok((w.pa, w.af_update))
    }

    pub(crate) fn fetch_halfword(&self, mem: &dyn PhysMem, va: u32, user: bool) -> Option<u16> {
        let (pa, af) = self.translate_fetch(mem, self.fcse(va), !user).ok()?;
        if af.is_some() {
            // The hardware Access flag update needs a write: the Prefetch
            // Abort path makes it and resumes.
            return None;
        }
        let word = mem.read32(pa & !3)?;
        Some((word >> ((pa & 2) * 8)) as u16)
    }

    /// The DFSR value of `DataAbort()` (B2.4.10) in the Short-descriptor
    /// format.
    pub(crate) fn dfsr_value(&self, f: &Fault, write: bool, cm: bool) -> u32 {
        let mut v = encode_fs(encode_sd(f)) | (write as u32) << 11;
        if self.lpae() && cm {
            v |= 1 << 13;
        }
        let domain_valid = f.kind == Kind::Domain
            || (f.level == 2 && matches!(f.kind, Kind::Translation | Kind::AccessFlag | Kind::ExtWalk))
            || (!self.lpae() && f.kind == Kind::Permission);
        if domain_valid {
            v |= (f.domain.unwrap_or(0) as u32) << 4;
        }
        v
    }

    /// `DataAbort()` (B2.4.10): DFSR, DFAR, and the exception.
    pub(crate) fn data_abort(&mut self, regs: &mut dyn Regs, pc: u64, mva: u32, f: &Fault, write: bool, cm: bool) -> Stop {
        self.sr.dfsr = self.dfsr_value(f, write, cm);
        self.sr.dfar = mva;
        match self.take_dabt(regs, pc) {
            Err(s) => s,
            Ok(_) => Stop::Resume,
        }
    }

    fn xlate_or_abort(&mut self, regs: &mut dyn Regs, mem: &mut dyn PhysMem, pc: u64, mva: u32, priv_: bool, write: bool, wasaligned: bool) -> Result<Out, Stop> {
        match self.translate_data(&*mem, mva, priv_, write, wasaligned) {
            Ok((out, af)) => {
                if let Some((pa, v)) = af {
                    self.af_write(mem, pa, v)?;
                }
                Ok(out)
            }
            Err(Xlate::Stop(s)) => Err(s),
            Err(Xlate::Fault(f)) => Err(self.data_abort(regs, pc, mva, &f, write, false)),
        }
    }

    fn af_write(&mut self, mem: &mut dyn PhysMem, pa: u64, v: u32) -> Result<(), Stop> {
        match mem.write32(pa, v) {
            Some(()) => Ok(()),
            None => unimpl(format!("the hardware Access flag update of the descriptor at PA {pa:#x}: no writable memory there")),
        }
    }

    fn alignment_fault(&mut self, regs: &mut dyn Regs, pc: u64, va: u32, write: bool) -> Stop {
        // AlignmentFaultV() (B3.19.1): DataAbort of the MVA.
        let mva = self.fcse(va);
        let f = Fault { kind: Kind::Alignment, level: 0, domain: None };
        self.data_abort(regs, pc, mva, &f, write, false)
    }

    /// A data access (`MemA[]`/`MemU[]`, B2.4.4, B2.4.5) as `gex_abi::a32::mem`
    /// describes it: its host address.
    pub(crate) fn data_access(&mut self, regs: &mut dyn Regs, mem: &mut dyn PhysMem, pc: u64, va: u32, access: i32) -> Result<u64, Stop> {
        use abi::mem::{ALIGN_SHIFT, SIZE_MASK, SKIP, SWP, UNPRIV, WRITE};
        let size = 1u32 << (access & SIZE_MASK);
        let write = access & WRITE != 0;
        let align = ((access >> ALIGN_SHIFT) & 7) as u32;
        // A3.1: an access to bytes 0xFFFFFFFF and 0x00000000 is UNPREDICTABLE,
        // whether or not the instruction passes its condition.
        if va as u64 + size as u64 > 1 << 32 {
            return unpred(format!("an access of {size} bytes at {va:#x} spans the top of memory (A3.1)"));
        }
        if access & SKIP != 0 {
            return self.sink.ok_or_else(|| Stop::Unimplemented("the sink slot's host address (Core::set_sink) is not set".into()));
        }
        // B4.1.130 SCTLR.SW: with the Multiprocessing Extensions, SWP and
        // SWPB are UNDEFINED while it is 0 (without them the bit is RAZ and
        // they execute).
        if access & SWP != 0 && self.config.features.mp && self.sr.sctlr & crate::cp::SCTLR_SW == 0 {
            return self.take_undef(regs, pc);
        }
        let priv_ = access & UNPRIV == 0 && self.privileged();
        // MemA (align > 0): an access the instruction requires aligned,
        // faulting whatever SCTLR.A says; MemU (align = 0): unaligned
        // permitted unless SCTLR.A is 1 (B2.4.4, B2.4.5, A3.2.1).
        let wasaligned = if align > 0 {
            if va & ((1 << align) - 1) != 0 {
                return Err(self.alignment_fault(regs, pc, va, write));
            }
            true
        } else if va & (size - 1) != 0 {
            if self.sr.sctlr & SCTLR_A != 0 {
                return Err(self.alignment_fault(regs, pc, va, write));
            }
            false
        } else {
            true
        };
        // Each 4KB page the access touches is translated.
        let first = size.min(0x1000 - (va & 0xfff));
        let mva = self.fcse(va);
        let o1 = self.xlate_or_abort(regs, mem, pc, mva, priv_, write, wasaligned)?;
        if first == size {
            return self.host(&*mem, o1.pa, size, write);
        }
        let va2 = va.wrapping_add(first);
        let mva2 = self.fcse(va2);
        let o2 = self.xlate_or_abort(regs, mem, pc, mva2, priv_, write, wasaligned)?;
        let h1 = self.host(&*mem, o1.pa, first, write)?;
        let h2 = self.host(&*mem, o2.pa, size - first, write)?;
        if h2 != h1 + first as u64 {
            return unimpl(format!(
                "an access of {size} bytes at {va:#x} across pages whose memory is not contiguous in the host (PA {:#x}, {:#x})",
                o1.pa, o2.pa
            ));
        }
        Ok(h1)
    }

    fn host(&self, mem: &dyn PhysMem, pa: u64, len: u32, write: bool) -> Result<u64, Stop> {
        match mem.host(pa, len, write) {
            Some(h) => Ok(h),
            None => unimpl(format!(
                "a data {} of {len} bytes at PA {pa:#x}: no memory there the access may use (a device the model does not have)",
                if write { "write" } else { "read" }
            )),
        }
    }

    /// `MemA[address, 4]` read for RFE (B9.3.13), at the current privilege.
    pub(crate) fn mem_a_read(&mut self, regs: &mut dyn Regs, mem: &mut dyn PhysMem, pc: u64, va: u32) -> Result<u32, Stop> {
        let pa = self.mem_a_pa(regs, mem, pc, va, false)?;
        match mem.read32(pa) {
            Some(v) => Ok(v),
            None => unimpl(format!("a data read of 4 bytes at PA {pa:#x}: no memory there (a device the model does not have)")),
        }
    }

    /// `MemA[address, 4] = v` for SRS (B9.3.16).
    pub(crate) fn mem_a_write(&mut self, regs: &mut dyn Regs, mem: &mut dyn PhysMem, pc: u64, va: u32, v: u32) -> Result<(), Stop> {
        let pa = self.mem_a_pa(regs, mem, pc, va, true)?;
        self.host(&*mem, pa, 4, true)?;
        match mem.write32(pa, v) {
            Some(()) => Ok(()),
            None => unimpl(format!("a data write of 4 bytes at PA {pa:#x}: no memory there (a device the model does not have)")),
        }
    }

    fn mem_a_pa(&mut self, regs: &mut dyn Regs, mem: &mut dyn PhysMem, pc: u64, va: u32, write: bool) -> Result<u64, Stop> {
        if va & 3 != 0 {
            return Err(self.alignment_fault(regs, pc, va, write));
        }
        let priv_ = self.privileged();
        let mva = self.fcse(va);
        Ok(self.xlate_or_abort(regs, mem, pc, mva, priv_, write, true)?.pa)
    }

    /// The FETCH exception: the instruction at `pc` could not be fetched,
    /// `va` the address that failed. The fetch is translated again: a fault
    /// is the precise Prefetch Abort (IFSR, IFAR = the MVA, B3.13.2); else
    /// the reason is UNPREDICTABLE behaviour, memory the model does not
    /// have, a hardware Access flag update (made here), or a translation
    /// that changed since the block was translated.
    pub(crate) fn prefetch_abort_at(&mut self, regs: &mut dyn Regs, mem: &mut dyn PhysMem, pc: u64, va: u32) -> Result<u64, Stop> {
        let mva = self.fcse(va);
        match self.translate_fetch(&*mem, mva, !abi::key_user(pc)) {
            Err(Xlate::Stop(s)) => Err(s),
            Err(Xlate::Fault(f)) => {
                self.sr.ifsr = encode_fs(encode_sd(&f));
                self.sr.ifar = mva;
                self.take_pabt(regs, pc)
            }
            Ok((pa, af)) => {
                if let Some((dpa, v)) = af {
                    self.af_write(mem, dpa, v)?;
                } else if mem.read32(pa & !3).is_none() {
                    return unimpl(format!("an instruction fetch at {va:#x} from PA {pa:#x}: no memory there"));
                }
                self.epoch += 1;
                Err(Stop::Resume)
            }
        }
    }

    /// The ATS1C** operations (B3.14, B4.2.4): the PAR from a stage 1
    /// translation of `va`; an MMU fault goes to the PAR, an external abort
    /// on the walk is a Data Abort (WnR = 1, CM = 1 with LPAE).
    pub(crate) fn ats1c(&mut self, regs: &mut dyn Regs, mem: &mut dyn PhysMem, pc: u64, va: u32, priv_: bool, write: bool) -> Result<u64, Stop> {
        let mva = self.fcse(va);
        match self.translate_data(&*mem, mva, priv_, write, true) {
            Err(Xlate::Stop(s)) => Err(s),
            Err(Xlate::Fault(f)) if f.kind == Kind::ExtWalk => Err(self.data_abort(regs, pc, mva, &f, true, true)),
            Err(Xlate::Fault(f)) => {
                // B4.1.112 32-bit PAR, aborted: FS (DFSR bits 12, 10, 3:0) in
                // bits 6:1, F = 1.
                let fs = encode_sd(&f);
                self.sr.par = ((fs << 1) | 1) as u64;
                Ok(0)
            }
            Ok((out, af)) => {
                if let Some((pa, v)) = af {
                    self.af_write(mem, pa, v)?;
                }
                self.sr.par = self.par_success(&out)? as u64;
                Ok(0)
            }
        }
    }

    /// B4.1.112 32-bit PAR format, successful translation.
    fn par_success(&self, o: &Out) -> Result<u32, Stop> {
        let a = &o.attrs;
        let inner = match a.ty {
            MemType::StronglyOrdered => 0b001,
            MemType::Device => 0b011,
            MemType::Normal => match (a.innerattrs, a.innerhints & 1) {
                (0b00, _) => 0b000,
                (0b10, _) => 0b110,
                (_, 1) => 0b101,
                _ => 0b111,
            },
        };
        let outer = match a.ty {
            MemType::Normal => match (a.outerattrs, a.outerhints & 1) {
                (0b00, _) => 0b00,
                (0b10, _) => 0b10,
                (_, 1) => 0b01,
                _ => 0b11,
            },
            _ => 0,
        };
        let (mut sh, mut nos) = (a.shareable, a.shareable && !a.outershareable);
        if self.lpae() {
            if a.ty != MemType::Normal {
                sh = true;
                nos = false;
            } else if a.innerattrs == 0 && a.outerattrs == 0 && !need(self.config.imp.par_nc_shareability, "PAR.{SH, NOS} for Non-cacheable Normal memory (B4.1.112)")? {
                sh = true;
                nos = false;
            }
        }
        let bit8 = need(self.config.imp.par_bit8, "the IMPLEMENTATION DEFINED PAR bit 8 (B4.1.112)")?;
        let pa = if o.supersection {
            (o.pa as u32 & 0xff00_0000) | (((o.pa >> 32) as u32 & 0xff) << 16)
        } else {
            o.pa as u32 & 0xffff_f000
        };
        Ok(pa | (nos as u32) << 10 | (bit8 as u32) << 8 | (sh as u32) << 7 | inner << 4 | outer << 2 | (o.supersection as u32) << 1)
    }

    /// A cache or branch predictor maintenance operation by MVA (B3.12.5):
    /// it translates `va` and can take a Translation fault or an external
    /// abort on the walk, and an Access flag fault where the implementation
    /// says so; never a Domain or Permission fault. `icache` for ICIMVAU and
    /// BPIMVA, whose fault reporting B3.13.2 describes.
    pub(crate) fn maint_by_mva(&mut self, regs: &mut dyn Regs, mem: &mut dyn PhysMem, pc: u64, va: u32, icache: bool) -> Result<(), Stop> {
        if self.sr.sctlr & SCTLR_M == 0 {
            return Ok(());
        }
        let mva = self.fcse(va);
        let f = match self.walk(&*mem, mva) {
            Ok(w) => {
                if let Some((pa, v)) = w.af_update {
                    self.af_write(mem, pa, v)?;
                }
                return Ok(());
            }
            Err(Xlate::Stop(s)) => return Err(s),
            Err(Xlate::Fault(f)) => f,
        };
        if f.kind == Kind::AccessFlag && !need(self.config.imp.maint_access_flag_faults, "whether cache maintenance by MVA generates Access flag faults (B3.12.5)")? {
            return Ok(());
        }
        if icache && need(self.config.imp.icmaint_fault_code, "how a fault on instruction cache maintenance by MVA is reported (B3.13.2)")? {
            self.sr.ifsr = encode_fs(encode_sd(&f));
            let ic = Fault { kind: Kind::ICacheMaint, level: 0, domain: None };
            return Err(self.data_abort(regs, pc, mva, &ic, true, true));
        }
        Err(self.data_abort(regs, pc, mva, &f, true, true))
    }
}

/// `DefaultTEXDecode()` (B2.4.9).
fn default_tex_decode(texcb: u32, s: bool) -> Result<MemAttrs, Stop> {
    let normal = |ia: u8, ih: u8, oa: u8, oh: u8| MemAttrs {
        ty: MemType::Normal,
        innerattrs: ia,
        innerhints: ih,
        outerattrs: oa,
        outerhints: oh,
        shareable: s,
        outershareable: s,
    };
    Ok(match texcb {
        0b00000 => MemAttrs::so(),
        0b00001 => MemAttrs::device(true),
        0b00010 => normal(0b10, 0b10, 0b10, 0b10),
        0b00011 => normal(0b11, 0b10, 0b11, 0b10),
        0b00100 => normal(0b00, 0b00, 0b00, 0b00),
        0b00110 => return Err(Stop::ImpDef("TEX, C, B = 001, 1, 0 is IMPLEMENTATION DEFINED (B3.8.2 Table B3-10)".into())),
        0b00111 => normal(0b11, 0b11, 0b11, 0b11),
        // Non-shareable Device: the pseudocode gives it shareable = TRUE.
        0b01000 => MemAttrs::device(true),
        t if t & 0b10000 != 0 => {
            let (ih, ia) = attrs_hints(t);
            let (oh, oa) = attrs_hints(t >> 2);
            normal(ia, ih, oa, oh)
        }
        t => return unpred(format!("TEX, C, B = {:03b}, {}, {}: reserved (B2.4.9, Table B3-10)", t >> 2, (t >> 1) & 1, t & 1)),
    })
}
