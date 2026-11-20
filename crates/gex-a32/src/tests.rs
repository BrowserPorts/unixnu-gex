//! Unit tests against the Arm ARM pseudocode, with a mock context and a
//! Vec-backed RAM.

use crate::psr::{ABT, FIQ, IRQ, SVC, SYS, UND, USR};
use crate::*;
use gex_abi::a32::{exc, key, key_addr, key_it, key_thumb, mem as acc, sys, KEY_USER};

#[derive(Default)]
pub(crate) struct R {
    pub(crate) r: [u32; 15],
    pub(crate) key: u64,
    nzcv: u32,
    q: bool,
    ge: u8,
    pub(crate) d: [u64; 32],
    pub(crate) fpscr: u32,
    pub(crate) fpen: u64,
}

impl Regs for R {
    fn r(&self, n: u8) -> u32 {
        self.r[n as usize]
    }
    fn set_r(&mut self, n: u8, v: u32) {
        self.r[n as usize] = v;
    }
    fn pc_key(&self) -> u64 {
        self.key
    }
    fn set_pc_key(&mut self, k: u64) {
        self.key = k;
    }
    fn nzcv(&self) -> u32 {
        self.nzcv
    }
    fn set_nzcv(&mut self, v: u32) {
        self.nzcv = v;
    }
    fn q(&self) -> bool {
        self.q
    }
    fn set_q(&mut self, q: bool) {
        self.q = q;
    }
    fn ge(&self) -> u8 {
        self.ge
    }
    fn set_ge(&mut self, g: u8) {
        self.ge = g;
    }
    fn d(&self, n: u8) -> u64 {
        self.d[n as usize]
    }
    fn set_d(&mut self, n: u8, v: u64) {
        self.d[n as usize] = v;
    }
    fn fpscr(&self) -> u32 {
        self.fpscr
    }
    fn set_fpscr(&mut self, v: u32) {
        self.fpscr = v;
    }
    fn set_fpen(&mut self, v: u64) {
        self.fpen = v;
    }
}

/// 4MB of RAM at PA 0, at host offset `HOST`; a second 64KB region at PA
/// 0x8000_0000, at a host offset that does not follow the first.
const RAM: usize = 0x40_0000;
const HOST: u64 = 0x1000_0000;
const HI: u64 = 0x8000_0000;
const HI_HOST: u64 = 0x2000_0000;

pub(crate) struct M {
    ram: Vec<u8>,
    hi: Vec<u8>,
}

impl M {
    fn new() -> M {
        M { ram: vec![0; RAM], hi: vec![0; 0x1_0000] }
    }
    fn w(&mut self, pa: u32, v: u32) {
        self.write32(pa as u64, v).unwrap();
    }
    fn r(&self, pa: u32) -> u32 {
        self.read32(pa as u64).unwrap()
    }
    fn region(&self, pa: u64, len: u64) -> Option<(bool, usize)> {
        if pa + len <= RAM as u64 {
            Some((false, pa as usize))
        } else if pa >= HI && pa + len <= HI + self.hi.len() as u64 {
            Some((true, (pa - HI) as usize))
        } else {
            None
        }
    }
}

impl PhysMem for M {
    fn host(&self, pa: u64, len: u32, _write: bool) -> Option<u64> {
        match self.region(pa, len as u64)? {
            (false, o) => Some(HOST + o as u64),
            (true, o) => Some(HI_HOST + o as u64),
        }
    }
    fn read32(&self, pa: u64) -> Option<u32> {
        let (hi, o) = self.region(pa, 4)?;
        let buf = if hi { &self.hi } else { &self.ram };
        Some(u32::from_le_bytes(buf[o..o + 4].try_into().unwrap()))
    }
    fn write32(&mut self, pa: u64, v: u32) -> Option<()> {
        let (hi, o) = self.region(pa, 4)?;
        let buf = if hi { &mut self.hi } else { &mut self.ram };
        buf[o..o + 4].copy_from_slice(&v.to_le_bytes());
        Some(())
    }
}

const MIDR: u32 = 0x412f_c0f1;

/// A Cortex-A15-like core without the Security and Virtualization
/// Extensions.
pub(crate) fn imp() -> ImpDef {
    ImpDef {
        midr: Some(MIDR),
        ctr: Some(0x8444_c004),
        tcmtr: Some(0),
        tlbtr: Some(0),
        mpidr: Some(0x8000_0000),
        revidr: Some(MIDR),
        id_pfr: [Some(0x0000_1131), Some(0x0001_0001)],
        id_dfr0: Some(0x0201_0555),
        id_afr0: Some(0),
        id_mmfr: [Some(0x1020_1105), Some(0x2000_0000), Some(0x0124_0000), Some(0x0210_2211)],
        id_isar: [Some(0x0210_1110), Some(0x1311_2111), Some(0x2123_2041), Some(0x1111_2131), Some(0x1001_1142), Some(0)],
        clidr: Some(0x0a20_0023),
        aidr: Some(0),
        ccsidr: vec![(0, 0x701f_e00a), (1, 0x201f_e00a), (2, 0x711f_e07a)],
        actlr: Some((0, 0x0000_0041)),
        undef_cond_failed_traps: Some(true),
        reset_hivecs: Some(false),
        reset_te: Some(false),
        reset_ee: Some(false),
        reset_nmfi: Some(false),
        sctlr: Some((cp::SCTLR_I | cp::SCTLR_C | cp::SCTLR_CP15BEN | cp::SCTLR_Z, 0)),
        reset_vector: Some(None),
        psr_j_raz_wi: Some(true),
        tre0_remap: Some(false),
        cpacr_asedis: Some(true),
        cpacr_d32dis: Some(true),
        joscr_rw: Some(false),
        fpsid: Some(0x4104_30f0),
        mvfr0: Some(0x1011_0222),
        mvfr1: Some(0x1111_1111),
        dbgdidr: Some(0x3515_f005),
        dbgdrar: Some(0),
        dbgdsar: Some(0),
        icimvau_translates: Some(false),
        bpimva_translates: Some(false),
        maint_access_flag_faults: Some(false),
        icmaint_fault_code: Some(false),
        par_bit8: Some(false),
        par_nc_shareability: Some(true),
        c15_allocated: Some(true),
        imp_regs: vec![ImpReg { cp: sys::cp(15, 4, 15, 0, 0) as u32, reset: 0x2c00_0000, writable: 0 }],
    }
}

pub(crate) fn features() -> Features {
    Features { security: false, virtualization: false, lpae: false, ..Features::ALL }
}

pub(crate) fn new_core_with(features: Features, imp: ImpDef) -> (Core, R, M) {
    let mut c = Core::new(Config { features, imp }).unwrap();
    let mut r = R::default();
    c.reset(&mut r).unwrap();
    c.set_sink(0xdead_0000);
    (c, r, M::new())
}

pub(crate) fn new_core() -> (Core, R, M) {
    new_core_with(features(), imp())
}

const PC: u32 = 0x8000;

fn k(addr: u32) -> u64 {
    key(addr, false, 0)
}

fn s(c: &mut Core, r: &mut R, m: &mut M, op: i32, a: u64, b: u64) -> Result<u64, Stop> {
    c.sys(r, m, k(PC), op, a, b)
}

fn mrc(c: &mut Core, r: &mut R, m: &mut M, opc1: u8, crn: u8, crm: u8, opc2: u8) -> Result<u64, Stop> {
    c.sys(r, m, k(PC), sys::MRC, sys::cp(15, opc1, crn, crm, opc2) as u64, 0)
}

/// MCR; a write that changes translation resumes, which is success here.
#[allow(clippy::too_many_arguments)]
fn mcr(c: &mut Core, r: &mut R, m: &mut M, opc1: u8, crn: u8, crm: u8, opc2: u8, v: u32) -> Result<u64, Stop> {
    match c.sys(r, m, k(PC), sys::MCR, sys::cp(15, opc1, crn, crm, opc2) as u64, v as u64) {
        Err(Stop::Resume) => Ok(0),
        x => x,
    }
}

/// CPS to `mode` (a change of privilege resumes at the rekeyed next
/// instruction).
fn set_mode(c: &mut Core, r: &mut R, m: &mut M, mode: u8) {
    match s(c, r, m, sys::CPS, (1 << 5) | (mode as u64) << 8, 0) {
        Ok(_) | Err(Stop::Resume) => {}
        e => panic!("{e:?}"),
    }
    assert_eq!(c.mode(), mode);
}

fn it_of(psr: u32) -> u32 {
    (psr >> 25) & 3 | ((psr >> 10) & 0x3f) << 2
}

// -- reset ------------------------------------------------------------------

#[test]
fn reset_state() {
    let (c, r, _) = new_core();
    assert_eq!(c.mode(), SVC);
    assert_eq!(r.key, k(0));
    // SCTLR: the RAO bits and CP15BEN = 1; M, A, C, I, Z, V, TE, EE = 0.
    assert_eq!(c.sr.sctlr, 0x00c5_0078);
    assert_eq!(c.cpsr(&r) & 0x3ff, 0x1d3, "A, I, F set, SVC, T = 0, E = 0");
}

#[test]
fn reset_hivecs_thumb() {
    let mut i = imp();
    i.reset_hivecs = Some(true);
    i.reset_te = Some(true);
    let (c, r, _) = new_core_with(features(), i);
    assert_eq!(r.key, key(0xffff_0000, true, 0));
    assert_eq!(c.cpsr(&r) & 0x20, 0x20);
    assert_eq!(c.sr.sctlr & (cp::SCTLR_V | cp::SCTLR_TE), cp::SCTLR_V | cp::SCTLR_TE);
    let mut i = imp();
    i.reset_vector = Some(Some(0x1234_5678));
    let (_, r, _) = new_core_with(features(), i);
    assert_eq!(r.key, k(0x1234_5678));
}

#[test]
fn reset_and_config_loud() {
    let mut i = imp();
    i.reset_ee = Some(true);
    let mut c = Core::new(Config { features: features(), imp: i }).unwrap();
    assert!(matches!(c.reset(&mut R::default()), Err(Stop::Unimplemented(_))));
    let mut i = imp();
    i.reset_te = None;
    let mut c = Core::new(Config { features: features(), imp: i }).unwrap();
    assert!(matches!(c.reset(&mut R::default()), Err(Stop::ImpDef(_))));
    let f = Features { security: true, ..features() };
    assert!(matches!(Core::new(Config { features: f, imp: imp() }), Err(Stop::Unimplemented(_))));
    let f = Features { virtualization: true, ..features() };
    assert!(matches!(Core::new(Config { features: f, imp: imp() }), Err(Stop::Unimplemented(_))));
    let mut i = imp();
    i.sctlr = Some((cp::SCTLR_M, 0));
    assert!(matches!(Core::new(Config { features: features(), imp: i }), Err(Stop::ImpDef(_))));
}

// -- modes and banked registers -----------------------------------------------

#[test]
fn banks_through_cps_and_msr() {
    let (mut c, mut r, mut m) = new_core();
    let modes = [FIQ, IRQ, SVC, ABT, UND, SYS];
    for &md in &modes {
        set_mode(&mut c, &mut r, &mut m, md);
        for n in 8..=14u8 {
            r.r[n as usize] = (md as u32) << 8 | n as u32;
        }
    }
    for &md in &modes {
        // MSR CPSR_c to the mode.
        let v = (c.cpsr(&r) & !0x1f) | md as u32;
        s(&mut c, &mut r, &mut m, sys::MSR, 1, v as u64).unwrap();
        assert_eq!(c.mode(), md);
        for n in 8..=14u8 {
            let owner = match (n, md) {
                (8..=12, FIQ) => FIQ,
                (8..=12, _) | (_, SYS) => SYS,
                _ => md,
            };
            assert_eq!(r.r[n as usize], (owner as u32) << 8 | n as u32, "R{n} in mode {md:#x}");
        }
    }
    // Rmode reads the other modes' banks; User shares System's registers.
    set_mode(&mut c, &mut r, &mut m, SVC);
    assert_eq!(c.banked_r(&r, 13, USR).unwrap(), (SYS as u32) << 8 | 13);
    assert_eq!(c.banked_r(&r, 9, FIQ).unwrap(), (FIQ as u32) << 8 | 9);
    assert_eq!(c.banked_r(&r, 14, IRQ).unwrap(), (IRQ as u32) << 8 | 14);
    assert!(matches!(c.banked_r(&r, 13, 0x16), Err(Stop::Unpredictable(_))));
    // To User mode (the next instruction's key takes KEY_USER); there CPS is
    // a NOP and MSR's mode and mask bits are ignored.
    r.key = k(PC + 4);
    assert_eq!(s(&mut c, &mut r, &mut m, sys::CPS, (1 << 5) | (USR as u64) << 8, 0), Err(Stop::Resume));
    assert_eq!(r.key, k(PC + 4) | KEY_USER);
    assert_eq!(r.r[13], (SYS as u32) << 8 | 13);
    s(&mut c, &mut r, &mut m, sys::CPS, (1 << 5) | (SVC as u64) << 8 | 0b10 | 0b11100, 0).unwrap();
    assert_eq!(c.mode(), USR);
    assert_eq!(c.cpsr(&r) & 0x1c0, 0x1c0);
    s(&mut c, &mut r, &mut m, sys::MSR, 0xf, SVC as u64).unwrap();
    assert_eq!(c.mode(), USR);
    assert_eq!(c.cpsr(&r) & 0x1c0, 0x1c0, "mask bits not writable at PL0");
    // MSR from System to User changes the level too.
    let (mut c, mut r, mut m) = new_core();
    set_mode(&mut c, &mut r, &mut m, SYS);
    r.key = k(PC + 4);
    assert_eq!(s(&mut c, &mut r, &mut m, sys::MSR, 1, USR as u64), Err(Stop::Resume));
    assert_eq!(r.key, k(PC + 4) | KEY_USER);
}

#[test]
fn cpsr_write_by_instr() {
    let (mut c, mut r, mut m) = new_core();
    // Flags from the f field, GE from s; the execution state bits ignored.
    let v = 0xf800_0000u32 | 0x0600_0000 | 0x000f_0000 | 0xfc00 | 0x20 | 0x0100_0000;
    s(&mut c, &mut r, &mut m, sys::MSR, 0b1100, v as u64).unwrap();
    assert_eq!(r.nzcv, 0xf000_0000);
    assert!(r.q);
    assert_eq!(r.ge, 0xf);
    assert_eq!(r.key, k(0), "IT, T unchanged by MSR");
    // The c field: I, F cleared; the x field: A cleared.
    s(&mut c, &mut r, &mut m, sys::MSR, 0b0011, SVC as u64).unwrap();
    assert_eq!(c.cpsr(&r) & 0x1c0, 0);
    // BadMode (Monitor, Hyp without the extensions) is UNPREDICTABLE.
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::MSR, 1, 0x16), Err(Stop::Unpredictable(_))));
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::MSR, 1, 0x1a), Err(Stop::Unpredictable(_))));
    assert_eq!(c.mode(), SVC);
    // E = 1 is big-endian, not implemented.
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::MSR, 2, 0x200), Err(Stop::Unimplemented(_))));
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::SETEND, 1, 0), Err(Stop::Unimplemented(_))));
    assert_eq!(s(&mut c, &mut r, &mut m, sys::SETEND, 0, 0), Ok(0));
    // MRS/MSR (Banked register) belong to the Virtualization Extensions.
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::MRS_BANKED, 0, 0), Err(Stop::Unimplemented(_))));
}

#[test]
fn nmfi() {
    let mut i = imp();
    i.reset_nmfi = Some(true);
    let (mut c, mut r, mut m) = new_core_with(features(), i);
    assert_ne!(c.sr.sctlr & cp::SCTLR_NMFI, 0);
    s(&mut c, &mut r, &mut m, sys::CPS, 0b10 | 0b10000, 0).unwrap(); // CPSIE f
    assert_eq!(c.cpsr(&r) & 0x40, 0);
    s(&mut c, &mut r, &mut m, sys::CPS, 0b11 | 0b10000, 0).unwrap(); // CPSID f
    assert_eq!(c.cpsr(&r) & 0x40, 0, "F cannot be set to 1 with NMFI");
    s(&mut c, &mut r, &mut m, sys::MSR, 1, (SVC as u64) | 0x40).unwrap();
    assert_eq!(c.cpsr(&r) & 0x40, 0);
    // Exception entry sets it.
    c.take_fiq(&mut r, k(0x100)).unwrap();
    assert_eq!(c.cpsr(&r) & 0x40, 0x40);
}

#[test]
fn mrs_msr_spsr() {
    let (mut c, mut r, mut m) = new_core();
    r.nzcv = 0x6000_0000;
    r.ge = 5;
    assert_eq!(s(&mut c, &mut r, &mut m, sys::MRS, 0, 0), Ok(0x6005_01d3));
    // SPSR by fields; J is RAZ/WI here, bits 23:20 RAZ.
    s(&mut c, &mut r, &mut m, sys::MSR, 0x1f, 0xf1ff_ff33).unwrap();
    assert_eq!(s(&mut c, &mut r, &mut m, sys::MRS, 1, 0), Ok(0xf00f_ff33));
    s(&mut c, &mut r, &mut m, sys::MSR, 0x14, 0x0003_0000).unwrap();
    assert_eq!(s(&mut c, &mut r, &mut m, sys::MRS, 1, 0), Ok(0xf003_ff33));
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::MSR, 0x11, 0x0f), Err(Stop::Unpredictable(_))), "BadMode in SPSR");
    // In System mode the SPSR is UNPREDICTABLE; at PL0 MRS is the APSR view.
    set_mode(&mut c, &mut r, &mut m, SYS);
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::MRS, 1, 0), Err(Stop::Unpredictable(_))));
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::MSR, 0x18, 0), Err(Stop::Unpredictable(_))));
    set_mode(&mut c, &mut r, &mut m, USR);
    assert_eq!(s(&mut c, &mut r, &mut m, sys::MRS, 0, 0), Ok(0x6005_0010));
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::MSR, 0x18, 0), Err(Stop::Unpredictable(_))));
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::MRS, 1, 0), Err(Stop::Unpredictable(_))));
}

// -- exceptions ---------------------------------------------------------------

#[test]
fn undefined_and_svc_entry() {
    for &(thumb, te) in &[(false, false), (true, false), (false, true), (true, true)] {
        let (mut c, mut r, mut m) = new_core();
        if te {
            let v = c.sr.sctlr | cp::SCTLR_TE;
            mcr(&mut c, &mut r, &mut m, 0, 1, 0, 0, v).unwrap();
        }
        set_mode(&mut c, &mut r, &mut m, USR);
        r.nzcv = 0x8000_0000;
        let pc = key(0x1000, thumb, 0) | KEY_USER;
        let before = c.cpsr(&r) & !0x20 | (thumb as u32) << 5;
        assert_eq!(c.sys(&mut r, &mut m, pc, sys::EXCEPTION, exc::UNDEFINED as u64, 0), Err(Stop::Resume));
        assert_eq!(c.mode(), UND);
        assert_eq!(r.r[14], 0x1000 + if thumb { 2 } else { 4 });
        assert_eq!(c.spsr().unwrap(), before);
        assert_eq!(r.key, key(4, te, 0), "vector, T = SCTLR.TE, no KEY_USER");
        assert_eq!(c.cpsr(&r) & 0x3ff, 0x1c0 | UND as u32 | (te as u32) << 5, "I set, A and F kept, E = 0");
        // SVC.
        set_mode(&mut c, &mut r, &mut m, USR);
        let before = c.cpsr(&r) & !0x20 | (thumb as u32) << 5;
        assert_eq!(c.sys(&mut r, &mut m, pc, sys::EXCEPTION, exc::SVC as u64, 0x12), Err(Stop::Resume));
        assert_eq!(c.mode(), SVC);
        assert_eq!(r.r[14], 0x1000 + if thumb { 2 } else { 4 });
        assert_eq!(c.spsr().unwrap(), before);
        assert_eq!(r.key, key(8, te, 0));
    }
}

#[test]
fn svc_sets_i_only() {
    let (mut c, mut r, mut m) = new_core();
    s(&mut c, &mut r, &mut m, sys::CPS, 0b10 | 0b11100, 0).unwrap();
    c.sys(&mut r, &mut m, k(0x100), sys::EXCEPTION, exc::SVC as u64, 0).unwrap_err();
    assert_eq!(c.cpsr(&r) & 0x1c0, 0x080);
}

#[test]
fn smc_hvc_undefined_without_extensions() {
    let (mut c, mut r, mut m) = new_core();
    assert_eq!(c.sys(&mut r, &mut m, k(0x2000), sys::EXCEPTION, exc::SMC as u64, 0), Err(Stop::Resume));
    assert_eq!((c.mode(), r.r[14], r.key), (UND, 0x2004, k(4)));
    assert_eq!(c.sys(&mut r, &mut m, k(0x2000), sys::EXCEPTION, exc::HVC as u64, 0), Err(Stop::Resume));
    assert_eq!(c.mode(), UND);
}

#[test]
fn bkpt_prefetch_abort() {
    for &thumb in &[false, true] {
        let (mut c, mut r, mut m) = new_core();
        c.sr.ifar = 0x1234;
        let pc = key(0x3000, thumb, 0);
        assert_eq!(c.sys(&mut r, &mut m, pc, sys::EXCEPTION, exc::BKPT as u64, 7), Err(Stop::Resume));
        assert_eq!(c.mode(), ABT);
        assert_eq!(r.r[14], 0x3004);
        assert_eq!(r.key, k(0xc));
        assert_eq!(c.sr.ifsr, 0b00010, "IFSR: debug event");
        assert_eq!(c.sr.ifar, 0x1234, "IFAR UNKNOWN: unchanged");
        assert_eq!(c.cpsr(&r) & 0x1c0, 0x1c0);
        assert_eq!(c.spsr().unwrap() & 0x3f, (thumb as u32) << 5 | SVC as u32);
    }
}

#[test]
fn it_state_through_exceptions() {
    let (mut c, mut r, mut m) = new_core();
    set_mode(&mut c, &mut r, &mut m, USR);
    // An SVC in an IT block: the SPSR holds the ITSTATE ITAdvance() gives;
    // an UNDEFINED instruction's SPSR its own.
    let it = 0x0c;
    let adv = crate::psr::it_advance(it);
    assert_eq!(adv, 0x18);
    let pc = key(0x4000, true, it) | KEY_USER;
    c.sys(&mut r, &mut m, pc, sys::EXCEPTION, exc::SVC as u64, 0).unwrap_err();
    assert_eq!(it_of(c.spsr().unwrap()), adv as u32);
    assert_eq!(c.cpsr(&r) & (3 << 25 | 0x3f << 10), 0, "IT cleared on entry");
    assert_eq!(key_it(r.key), 0);
    // MOVS PC, LR restores T and IT into the key, and the User level.
    let lr = r.r[14];
    assert_eq!(s(&mut c, &mut r, &mut m, sys::ALU_RETURN, 0, lr as u64), Err(Stop::Resume));
    assert_eq!(c.mode(), USR);
    assert_eq!(r.key, key(0x4002, true, adv) | KEY_USER);
    c.sys(&mut r, &mut m, pc, sys::EXCEPTION, exc::UNDEFINED as u64, 0).unwrap_err();
    assert_eq!(it_of(c.spsr().unwrap()), it as u32);
    // SUBS PC, LR, #2 returns to the instruction itself.
    let lr = r.r[14];
    s(&mut c, &mut r, &mut m, sys::ALU_RETURN, 0, (lr - 2) as u64).unwrap_err();
    assert_eq!(r.key, pc);
    // A Data Abort in an IT block.
    let pc = key(0x2002, true, 0x18) | KEY_USER;
    assert_eq!(c.mem(&mut r, &mut m, pc, 0x3, acc::access(2, false, false, 2)), Err(Stop::Resume));
    assert_eq!((c.mode(), r.r[14]), (ABT, 0x200a));
    assert_eq!(it_of(c.spsr().unwrap()), 0x18);
    assert!(!key_thumb(r.key) && key_addr(r.key) == 0x10);
}

#[test]
fn exception_return_checks() {
    let (mut c, mut r, mut m) = new_core();
    set_mode(&mut c, &mut r, &mut m, SYS);
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::ALU_RETURN, 0, 0), Err(Stop::Unpredictable(_))));
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::LDM_RETURN, 0, 0), Err(Stop::Unpredictable(_))));
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::ERET, 0, 0), Err(Stop::Unpredictable(_))));
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::USER_READ, 13, 0), Err(Stop::Unpredictable(_))));
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::USER_WRITE, 13, 0), Err(Stop::Unpredictable(_))));
    set_mode(&mut c, &mut r, &mut m, SVC);
    // The ARM state with ITSTATE != 0, a BadMode, a reserved ITSTATE.
    for bad in [0x0600_0013u32, 0x0000_0016, 0x0000_c033] {
        c.spsr[2] = bad;
        assert!(matches!(s(&mut c, &mut r, &mut m, sys::LDM_RETURN, 0, 0x100), Err(Stop::Unpredictable(_))), "{bad:#x}");
        assert_eq!(c.mode(), SVC, "nothing changed");
    }
    // An ARM return aligns the PC to a word and sets the Event Register.
    c.spsr[2] = 0x2000_0010;
    c.event = false;
    assert_eq!(s(&mut c, &mut r, &mut m, sys::LDM_RETURN, 0, 0x103), Err(Stop::Resume));
    assert_eq!(r.key, k(0x100) | KEY_USER);
    assert_eq!(r.nzcv, 0x2000_0000);
    assert!(c.event);
    // ERET at PL1 is MOVS PC, LR.
    let (mut c, mut r, mut m) = new_core();
    set_mode(&mut c, &mut r, &mut m, ABT);
    c.spsr[3] = 0x33;
    r.r[14] = 0x5003;
    assert_eq!(s(&mut c, &mut r, &mut m, sys::ERET, 0, 0), Err(Stop::Resume));
    assert_eq!((c.mode(), r.key), (SVC, key(0x5002, true, 0)));
}

#[test]
fn psr_j_bit() {
    let (mut c, mut r, mut m) = new_core();
    c.spsr[2] = 0x0100_0013;
    s(&mut c, &mut r, &mut m, sys::LDM_RETURN, 0, 0x100).unwrap_err();
    assert_eq!(r.key, k(0x100), "J RAZ/WI: the ARM state");
    let mut i = imp();
    i.psr_j_raz_wi = Some(false);
    let (mut c, mut r, mut m) = new_core_with(features(), i);
    c.spsr[2] = 0x0100_0013;
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::LDM_RETURN, 0, 0x100), Err(Stop::Unimplemented(_))));
}

#[test]
fn irq_fiq_entry() {
    let (mut c, mut r, mut m) = new_core();
    s(&mut c, &mut r, &mut m, sys::CPS, 0b10 | 0b11100, 0).unwrap();
    set_mode(&mut c, &mut r, &mut m, USR);
    c.take_irq(&mut r, key(0x6002, true, 0) | KEY_USER).unwrap();
    assert_eq!((c.mode(), r.r[14], r.key), (IRQ, 0x6006, k(0x18)));
    assert_eq!(c.cpsr(&r) & 0x1c0, 0x180, "I and A set, F unchanged");
    c.take_fiq(&mut r, k(0x7000)).unwrap();
    assert_eq!((c.mode(), r.r[14], r.key), (FIQ, 0x7004, k(0x1c)));
    assert_eq!(c.cpsr(&r) & 0x1c0, 0x1c0);
    assert_eq!(c.spsr().unwrap() & 0x1f, IRQ as u32);
    // SCTLR.VE is RAZ/WI here; SCTLR.EE = 1 at entry is not implemented.
    let v = c.sr.sctlr | cp::SCTLR_VE;
    mcr(&mut c, &mut r, &mut m, 0, 1, 0, 0, v).unwrap();
    assert_eq!(c.sr.sctlr & cp::SCTLR_VE, 0);
    let v = c.sr.sctlr | cp::SCTLR_EE;
    mcr(&mut c, &mut r, &mut m, 0, 1, 0, 0, v).unwrap();
    assert!(matches!(c.take_irq(&mut r, k(0)), Err(Stop::Unimplemented(_))));
    assert_eq!(c.mode(), FIQ);
}

#[test]
fn hivecs_vectors() {
    let (mut c, mut r, mut m) = new_core();
    let v = c.sr.sctlr | cp::SCTLR_V;
    mcr(&mut c, &mut r, &mut m, 0, 1, 0, 0, v).unwrap();
    c.sys(&mut r, &mut m, k(0x100), sys::EXCEPTION, exc::SVC as u64, 0).unwrap_err();
    assert_eq!(r.key, k(0xffff_0008));
    c.sys(&mut r, &mut m, k(0x100), sys::EXCEPTION, exc::BKPT as u64, 0).unwrap_err();
    assert_eq!(r.key, k(0xffff_000c));
}

#[test]
fn undef_cond_failed() {
    let (mut c, mut r, mut m) = new_core();
    assert_eq!(s(&mut c, &mut r, &mut m, sys::UNDEF_COND_FAILED, exc::UNDEFINED as u64, 0), Err(Stop::Resume));
    assert_eq!(c.mode(), UND);
    let mut i = imp();
    i.undef_cond_failed_traps = Some(false);
    let (mut c, mut r, mut m) = new_core_with(features(), i);
    assert_eq!(s(&mut c, &mut r, &mut m, sys::UNDEF_COND_FAILED, exc::UNDEFINED as u64, 0), Ok(0));
    let mut i = imp();
    i.undef_cond_failed_traps = None;
    let (mut c, mut r, mut m) = new_core_with(features(), i);
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::UNDEF_COND_FAILED, 1, 0), Err(Stop::ImpDef(_))));
}

#[test]
fn fp_checks() {
    let (mut c, mut r, mut m) = new_core();
    let fp = abi::unimpl::FP as u64;
    let vadd = 0xee30_0a00u64; // VADD.F32 s0, s0, s0
    let vmrs_fpexc = 0xeef8_0a10u64; // VMRS r0, FPEXC
    // CPACR denies access: UNDEFINED.
    assert_eq!(s(&mut c, &mut r, &mut m, sys::UNIMPLEMENTED, fp, vadd), Err(Stop::Resume));
    assert_eq!(c.mode(), UND);
    set_mode(&mut c, &mut r, &mut m, SVC);
    // Full access; FPEXC.EN = 0: UNDEFINED, except VMRS FPEXC at PL1.
    mcr(&mut c, &mut r, &mut m, 0, 1, 0, 2, 0xf << 20).unwrap();
    assert_eq!(mrc(&mut c, &mut r, &mut m, 0, 1, 0, 2), Ok(0xf << 20));
    assert_eq!(s(&mut c, &mut r, &mut m, sys::UNIMPLEMENTED, fp, vadd), Err(Stop::Resume));
    set_mode(&mut c, &mut r, &mut m, SVC);
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::UNIMPLEMENTED, fp, vmrs_fpexc), Err(Stop::Unimplemented(_))));
    set_mode(&mut c, &mut r, &mut m, USR);
    assert_eq!(s(&mut c, &mut r, &mut m, sys::UNIMPLEMENTED, fp, vmrs_fpexc), Err(Stop::Resume));
    assert_eq!(c.mode(), UND);
    // PL1-only access (0b01) from User mode.
    set_mode(&mut c, &mut r, &mut m, SVC);
    mcr(&mut c, &mut r, &mut m, 0, 1, 0, 2, 0x5 << 20).unwrap();
    set_mode(&mut c, &mut r, &mut m, USR);
    assert_eq!(s(&mut c, &mut r, &mut m, sys::UNIMPLEMENTED, fp, vadd), Err(Stop::Resume));
    // cp10 != cp11, and 0b10, are UNPREDICTABLE.
    let (mut c, mut r, mut m) = new_core();
    mcr(&mut c, &mut r, &mut m, 0, 1, 0, 2, 0x3 << 20).unwrap();
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::UNIMPLEMENTED, fp, vadd), Err(Stop::Unpredictable(_))));
    mcr(&mut c, &mut r, &mut m, 0, 1, 0, 2, 0xa << 20).unwrap();
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::UNIMPLEMENTED, fp, vadd), Err(Stop::Unpredictable(_))));
    // ThumbEE is not implemented.
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::UNIMPLEMENTED, abi::unimpl::THUMBEE as u64, 0), Err(Stop::Unimplemented(_))));
}

#[test]
fn wfe_sev_wfi() {
    let (mut c, mut r, mut m) = new_core();
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::WFE, 0, 0), Err(Stop::Wait(_))));
    s(&mut c, &mut r, &mut m, sys::SEV, 0, 0).unwrap();
    assert_eq!(s(&mut c, &mut r, &mut m, sys::WFE, 0, 0), Ok(0));
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::WFE, 0, 0), Err(Stop::Wait(_))), "WFE cleared the event");
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::WFI, 0, 0), Err(Stop::Wait(_))));
    // An exception return sets the Event Register.
    c.spsr[2] = 0x13;
    s(&mut c, &mut r, &mut m, sys::ALU_RETURN, 0, 0x100).unwrap_err();
    assert_eq!(s(&mut c, &mut r, &mut m, sys::WFE, 0, 0), Ok(0));
}

#[test]
fn unpredictable_ops() {
    let (mut c, mut r, mut m) = new_core();
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::UNPREDICTABLE, 0xe1a0_f00f, 4), Err(Stop::Unpredictable(_))));
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::UNPREDICTABLE_VALUE, 1, 2), Err(Stop::Unpredictable(_))));
    assert_eq!(s(&mut c, &mut r, &mut m, sys::NOP, 0, 0), Ok(0));
    assert_eq!(s(&mut c, &mut r, &mut m, sys::ISB, 0, 0), Ok(0));
}

// -- SRS, RFE, user registers ------------------------------------------------------

#[test]
fn srs_rfe() {
    let (mut c, mut r, mut m) = new_core();
    // SP_svc = 0x1000; from IRQ mode, SRSDB SP_svc!, #svc.
    r.r[13] = 0x1000;
    set_mode(&mut c, &mut r, &mut m, IRQ);
    r.r[14] = 0x2222_0004;
    c.spsr[1] = 0x6000_0030;
    let a = SVC as u64 | 3 << 8 | 1 << 10;
    assert_eq!(s(&mut c, &mut r, &mut m, sys::SRS, a, 0), Ok(0));
    assert_eq!((m.r(0xff8), m.r(0xffc)), (0x2222_0004, 0x6000_0030));
    assert_eq!(c.banked_r(&r, 13, SVC).unwrap(), 0xff8);
    // The other addressing modes, to the current mode's SP, no writeback.
    r.r[13] = 0x2000;
    for (amode, at) in [(0u64, 0x2000u32), (1, 0x2004), (2, 0x1ffc), (3, 0x1ff8)] {
        m.w(at, 0);
        s(&mut c, &mut r, &mut m, sys::SRS, IRQ as u64 | amode << 8, 0).unwrap();
        assert_eq!((m.r(at), m.r(at + 4), r.r[13]), (0x2222_0004, 0x6000_0030, 0x2000), "amode {amode}");
    }
    // RFEIA from SVC: R0 = 0xff8, writeback.
    set_mode(&mut c, &mut r, &mut m, SVC);
    r.r[0] = 0xff8;
    assert_eq!(s(&mut c, &mut r, &mut m, sys::RFE, 1 << 10, 0), Err(Stop::Resume));
    assert_eq!(c.mode(), USR);
    assert_eq!(r.key, key(0x2222_0004, true, 0) | KEY_USER);
    assert_eq!(r.nzcv, 0x6000_0000);
    assert_eq!(r.r[0], 0x1000);
    // UNPREDICTABLE in User mode (RFE, SRS) and System mode (SRS).
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::SRS, SVC as u64, 0), Err(Stop::Unpredictable(_))));
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::RFE, 0, 0), Err(Stop::Unpredictable(_))));
    let (mut c, mut r, mut m) = new_core();
    set_mode(&mut c, &mut r, &mut m, SYS);
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::SRS, SVC as u64, 0), Err(Stop::Unpredictable(_))));
    // A word access: an unaligned SP is an Alignment fault (Data Abort).
    set_mode(&mut c, &mut r, &mut m, SVC);
    r.r[13] = 0x1002;
    assert_eq!(s(&mut c, &mut r, &mut m, sys::SRS, SVC as u64, 0), Err(Stop::Resume));
    assert_eq!((c.mode(), c.sr.dfsr, c.sr.dfar, r.r[14]), (ABT, 0x801, 0x1002, PC + 8));
    // SRS of a BadMode's SP.
    set_mode(&mut c, &mut r, &mut m, SVC);
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::SRS, 0x16, 0), Err(Stop::Unpredictable(_))));
}

#[test]
fn user_registers() {
    let (mut c, mut r, mut m) = new_core();
    set_mode(&mut c, &mut r, &mut m, SYS);
    r.r[8] = 8;
    r.r[13] = 13;
    set_mode(&mut c, &mut r, &mut m, FIQ);
    r.r[8] = 0x88;
    assert_eq!(s(&mut c, &mut r, &mut m, sys::USER_READ, 8, 0), Ok(8));
    assert_eq!(s(&mut c, &mut r, &mut m, sys::USER_READ, 13, 0), Ok(13));
    s(&mut c, &mut r, &mut m, sys::USER_WRITE, 13, 0x1300).unwrap();
    s(&mut c, &mut r, &mut m, sys::USER_WRITE, 8, 0x800).unwrap();
    assert_eq!(r.r[8], 0x88);
    // In SVC mode R8-R12 are the User mode's: USER_WRITE writes the context.
    set_mode(&mut c, &mut r, &mut m, SVC);
    s(&mut c, &mut r, &mut m, sys::USER_WRITE, 9, 0x900).unwrap();
    assert_eq!((r.r[8], r.r[9]), (0x800, 0x900));
    set_mode(&mut c, &mut r, &mut m, USR);
    assert_eq!((r.r[8], r.r[13]), (0x800, 0x1300));
}

// -- CP15 and CP14 ----------------------------------------------------------------

#[test]
fn cp15_registers() {
    let (mut c, mut r, mut m) = new_core();
    for opc2 in [0, 4, 6, 7] {
        assert_eq!(mrc(&mut c, &mut r, &mut m, 0, 0, 0, opc2), Ok(MIDR as u64));
    }
    assert_eq!(mrc(&mut c, &mut r, &mut m, 0, 0, 1, 4), Ok(0x1020_1105));
    assert_eq!(mrc(&mut c, &mut r, &mut m, 0, 0, 5, 3), Ok(0), "reserved CPUID: RAZ");
    assert!(matches!(mcr(&mut c, &mut r, &mut m, 0, 0, 0, 0, 1), Err(Stop::Unpredictable(_))), "MCR to RO");
    // CSSELR/CCSIDR.
    mcr(&mut c, &mut r, &mut m, 2, 0, 0, 0, 1).unwrap();
    assert_eq!(mrc(&mut c, &mut r, &mut m, 1, 0, 0, 0), Ok(0x201f_e00a));
    assert!(matches!(mcr(&mut c, &mut r, &mut m, 2, 0, 0, 0, 3), Err(Stop::Unpredictable(_))), "L2 is unified");
    // SCTLR: the RAO/RAZ bits hold, the read/write ones change.
    mcr(&mut c, &mut r, &mut m, 0, 1, 0, 0, u32::MAX).unwrap();
    let rw = cp::SCTLR_TE | cp::SCTLR_AFE | cp::SCTLR_TRE | cp::SCTLR_EE | cp::SCTLR_V | cp::SCTLR_A | cp::SCTLR_M | cp::SCTLR_SW;
    let imp_rw = cp::SCTLR_I | cp::SCTLR_C | cp::SCTLR_CP15BEN | cp::SCTLR_Z;
    assert_eq!(c.sr.sctlr, 0x00c5_0058 | rw | imp_rw);
    mcr(&mut c, &mut r, &mut m, 0, 1, 0, 0, 0).unwrap();
    assert_eq!(c.sr.sctlr, 0x00c5_0058);
    // TTBCR without LPAE: N only. DACR, the FARs, the thread IDs, CONTEXTIDR,
    // NMRR.
    mcr(&mut c, &mut r, &mut m, 0, 2, 0, 2, u32::MAX).unwrap();
    assert_eq!(mrc(&mut c, &mut r, &mut m, 0, 2, 0, 2), Ok(7));
    mcr(&mut c, &mut r, &mut m, 0, 2, 0, 2, 0).unwrap();
    for (crn, crm, opc2) in [(3, 0, 0), (13, 0, 1), (13, 0, 2), (13, 0, 3), (13, 0, 4), (6, 0, 0), (6, 0, 2), (10, 2, 1)] {
        mcr(&mut c, &mut r, &mut m, 0, crn, crm, opc2, 0x1234_5678).unwrap();
        assert_eq!(mrc(&mut c, &mut r, &mut m, 0, crn, crm, opc2), Ok(0x1234_5678), "c{crn} c{crm} {opc2}");
    }
    // TTBR1's reserved bits; PRRR's (bits 23:20).
    mcr(&mut c, &mut r, &mut m, 0, 2, 0, 1, u32::MAX).unwrap();
    assert_eq!(mrc(&mut c, &mut r, &mut m, 0, 2, 0, 1), Ok(0xffff_c07f));
    mcr(&mut c, &mut r, &mut m, 0, 10, 2, 0, u32::MAX).unwrap();
    assert_eq!(mrc(&mut c, &mut r, &mut m, 0, 10, 2, 0), Ok(0xff0f_ffff));
    // DFSR/IFSR reserved bits; FCSEIDR RAZ/WI without the FCSE; the AxFSRs
    // are IMPLEMENTATION DEFINED here (ID_MMFR0.Auxiliary registers = 2).
    mcr(&mut c, &mut r, &mut m, 0, 5, 0, 0, u32::MAX).unwrap();
    assert_eq!(mrc(&mut c, &mut r, &mut m, 0, 5, 0, 0), Ok(0x0cff));
    mcr(&mut c, &mut r, &mut m, 0, 5, 0, 1, u32::MAX).unwrap();
    assert_eq!(mrc(&mut c, &mut r, &mut m, 0, 5, 0, 1), Ok(0x040f));
    mcr(&mut c, &mut r, &mut m, 0, 13, 0, 0, u32::MAX).unwrap();
    assert_eq!(mrc(&mut c, &mut r, &mut m, 0, 13, 0, 0), Ok(0));
    assert!(matches!(mrc(&mut c, &mut r, &mut m, 0, 5, 1, 0), Err(Stop::ImpDef(_))));
    // ACTLR from ImpDef; CPACR's RAZ/WI fields.
    mcr(&mut c, &mut r, &mut m, 0, 1, 0, 1, u32::MAX).unwrap();
    assert_eq!(mrc(&mut c, &mut r, &mut m, 0, 1, 0, 1), Ok(0x41));
    mcr(&mut c, &mut r, &mut m, 0, 1, 0, 2, 0xcfff_ffff).unwrap();
    assert_eq!(mrc(&mut c, &mut r, &mut m, 0, 1, 0, 2), Ok(0xc0f0_0000));
    // IMPLEMENTATION DEFINED registers: a given one, missing ones.
    assert_eq!(mrc(&mut c, &mut r, &mut m, 4, 15, 0, 0), Ok(0x2c00_0000));
    assert!(matches!(mrc(&mut c, &mut r, &mut m, 0, 15, 0, 0), Err(Stop::ImpDef(_))));
    assert!(matches!(mrc(&mut c, &mut r, &mut m, 0, 9, 0, 0), Err(Stop::ImpDef(_))));
    // Unallocated in an allocated primary register: UNPREDICTABLE; c4 and
    // c12 UNDEFINED; c14 (the Generic Timer) and c9 c12-c14 (the PMU) are
    // present here and not implemented.
    assert!(matches!(mrc(&mut c, &mut r, &mut m, 0, 1, 1, 0), Err(Stop::Unpredictable(_))));
    assert!(matches!(mrc(&mut c, &mut r, &mut m, 4, 1, 0, 0), Err(Stop::Unpredictable(_))));
    assert_eq!(mrc(&mut c, &mut r, &mut m, 0, 4, 0, 0), Err(Stop::Resume));
    assert_eq!((c.mode(), r.r[14]), (UND, PC + 4));
    set_mode(&mut c, &mut r, &mut m, SVC);
    assert_eq!(mrc(&mut c, &mut r, &mut m, 0, 12, 0, 0), Err(Stop::Resume));
    set_mode(&mut c, &mut r, &mut m, SVC);
    assert!(matches!(mrc(&mut c, &mut r, &mut m, 0, 14, 0, 0), Err(Stop::Unimplemented(_))));
    assert!(matches!(mrc(&mut c, &mut r, &mut m, 0, 9, 12, 0), Err(Stop::Unimplemented(_))));
    // Maintenance moves the code epoch.
    for (crm, opc2) in [(5, 0), (5, 6), (1, 0)] {
        let e = c.code_epoch();
        mcr(&mut c, &mut r, &mut m, 0, 7, crm, opc2, 0).unwrap();
        assert!(c.code_epoch() > e);
    }
    for (crm, opc2) in [(7, 0), (7, 1), (7, 2), (7, 3), (3, 0), (5, 0), (6, 2)] {
        let e = c.code_epoch();
        mcr(&mut c, &mut r, &mut m, 0, 8, crm, opc2, 0).unwrap();
        assert!(c.code_epoch() > e);
    }
    assert!(matches!(mrc(&mut c, &mut r, &mut m, 0, 7, 5, 0), Err(Stop::Unpredictable(_))), "MRC from WO");
    assert!(matches!(mcr(&mut c, &mut r, &mut m, 0, 7, 0, 4, 0), Err(Stop::Unpredictable(_))), "retired");
    // A change of translation resumes (at the next instruction); none does not.
    assert_eq!(c.sys(&mut r, &mut m, k(PC), sys::MCR, sys::cp(15, 0, 2, 0, 0) as u64, 0x4000), Err(Stop::Resume));
    assert_eq!(c.sys(&mut r, &mut m, k(PC), sys::MCR, sys::cp(15, 0, 2, 0, 0) as u64, 0x4000), Ok(0));
    // Set/way: L1 and L2 have data caches, L3 is none; a set beyond L1's.
    assert_eq!(mcr(&mut c, &mut r, &mut m, 0, 7, 14, 2, 0), Ok(0));
    assert_eq!(mcr(&mut c, &mut r, &mut m, 0, 7, 10, 2, 2), Ok(0));
    assert!(matches!(mcr(&mut c, &mut r, &mut m, 0, 7, 6, 2, 4), Err(Stop::Unpredictable(_))));
    assert!(matches!(mcr(&mut c, &mut r, &mut m, 0, 7, 6, 2, 0xa00 << 6 | 2), Err(Stop::Unpredictable(_))));
}

#[test]
fn cp15_pl0() {
    let (mut c, mut r, mut m) = new_core();
    mcr(&mut c, &mut r, &mut m, 0, 13, 0, 3, 0x77).unwrap();
    set_mode(&mut c, &mut r, &mut m, USR);
    // TPIDRURW RW, TPIDRURO RO, the barriers.
    mcr(&mut c, &mut r, &mut m, 0, 13, 0, 2, 0x55).unwrap();
    assert_eq!(mrc(&mut c, &mut r, &mut m, 0, 13, 0, 2), Ok(0x55));
    assert_eq!(mrc(&mut c, &mut r, &mut m, 0, 13, 0, 3), Ok(0x77));
    assert!(matches!(mcr(&mut c, &mut r, &mut m, 0, 13, 0, 3, 0), Err(Stop::Unpredictable(_))));
    for opc2 in [4, 5] {
        assert_eq!(mcr(&mut c, &mut r, &mut m, 0, 7, 10, opc2, 0), Ok(0));
    }
    assert_eq!(mcr(&mut c, &mut r, &mut m, 0, 7, 5, 4, 0), Ok(0));
    // Everything else UNDEFINED, allocated or not.
    for (opc1, crn, crm, opc2) in [(0, 0, 0, 0), (0, 1, 0, 0), (0, 13, 0, 4), (0, 2, 0, 0), (0, 7, 8, 0), (0, 1, 1, 0), (4, 15, 0, 0), (0, 8, 7, 0)] {
        set_mode(&mut c, &mut r, &mut m, USR);
        assert_eq!(mrc(&mut c, &mut r, &mut m, opc1, crn, crm, opc2), Err(Stop::Resume));
        assert_eq!((c.mode(), r.key, r.r[14]), (UND, k(4), PC + 4));
    }
    // CP15BEN = 0 makes the barriers UNDEFINED.
    set_mode(&mut c, &mut r, &mut m, SVC);
    let v = c.sr.sctlr & !cp::SCTLR_CP15BEN;
    mcr(&mut c, &mut r, &mut m, 0, 1, 0, 0, v).unwrap();
    assert_eq!(s(&mut c, &mut r, &mut m, sys::MCR, sys::cp(15, 0, 7, 10, 4) as u64, 0), Err(Stop::Resume));
    assert_eq!(c.mode(), UND);
    // MCRR/MRRC: LPAE registers without LPAE, an undefined one.
    set_mode(&mut c, &mut r, &mut m, SVC);
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::MRRC, sys::cp(15, 0, 0, 2, 0) as u64, 0), Err(Stop::Unpredictable(_))));
    assert_eq!(s(&mut c, &mut r, &mut m, sys::MRRC, sys::cp(15, 0, 0, 3, 0) as u64, 0), Err(Stop::Resume));
    assert_eq!(c.mode(), UND);
}

#[test]
fn cp15_lpae_64bit() {
    let f = Features { lpae: true, ..features() };
    let (mut c, mut r, mut m) = new_core_with(f, imp());
    let ttbr0 = sys::cp(15, 0, 0, 2, 0) as u64;
    assert_eq!(s(&mut c, &mut r, &mut m, sys::MCRR, ttbr0, u64::MAX), Err(Stop::Resume));
    assert_eq!(s(&mut c, &mut r, &mut m, sys::MRRC, ttbr0, 0), Ok(0x00ff_00ff_ffff_ffff));
    mcr(&mut c, &mut r, &mut m, 0, 2, 0, 0, 0x4000).unwrap();
    assert_eq!(s(&mut c, &mut r, &mut m, sys::MRRC, ttbr0, 0), Ok(0x00ff_00ff_0000_4000));
    let par = sys::cp(15, 0, 0, 7, 0) as u64;
    s(&mut c, &mut r, &mut m, sys::MCRR, par, 0x1234_5678_9abc_def0).unwrap();
    assert_eq!(s(&mut c, &mut r, &mut m, sys::MRRC, par, 0), Ok(0x1234_5678_9abc_def0));
    assert_eq!(mrc(&mut c, &mut r, &mut m, 0, 7, 4, 0), Ok(0x9abc_def0));
    // TTBCR keeps the Long-descriptor fields; EAE = 1 is not implemented.
    mcr(&mut c, &mut r, &mut m, 0, 2, 0, 2, 0x7fff_ffff).unwrap();
    assert_eq!(mrc(&mut c, &mut r, &mut m, 0, 2, 0, 2), Ok((0x7fff_ffff & !(0x7 << 19 | 0x3 << 14 | 0xf << 3)) as u64));
    assert!(matches!(mcr(&mut c, &mut r, &mut m, 0, 2, 0, 2, 1 << 31), Err(Stop::Unimplemented(_))));
    // DBGDRAR through MRRC p14.
    assert_eq!(s(&mut c, &mut r, &mut m, sys::MRRC, sys::cp(14, 0, 0, 1, 0) as u64, 0), Ok(0));
}

#[test]
fn cp14() {
    let (mut c, mut r, mut m) = new_core();
    let cp14 = |opc1, crn, crm, opc2| sys::cp(14, opc1, crn, crm, opc2) as u64;
    assert_eq!(s(&mut c, &mut r, &mut m, sys::MRC, cp14(0, 0, 0, 0), 0), Ok(0x3515_f005));
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::MCR, cp14(0, 0, 0, 0), 0), Err(Stop::Unpredictable(_))));
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::MRC, cp14(0, 0, 1, 0), 0), Err(Stop::Unimplemented(_))));
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::MRC, cp14(0, 0, 7, 0), 0), Err(Stop::Unimplemented(_))));
    // Jazelle: JIDR RAZ, JOSCR RAZ/WI here, JMCR RAZ/WI.
    assert_eq!(s(&mut c, &mut r, &mut m, sys::MRC, cp14(7, 0, 0, 0), 0), Ok(0));
    s(&mut c, &mut r, &mut m, sys::MCR, cp14(7, 1, 0, 0), 3).unwrap();
    assert_eq!(s(&mut c, &mut r, &mut m, sys::MRC, cp14(7, 1, 0, 0), 0), Ok(0));
    s(&mut c, &mut r, &mut m, sys::MCR, cp14(7, 2, 0, 0), 1).unwrap();
    assert_eq!(s(&mut c, &mut r, &mut m, sys::MRC, cp14(7, 2, 0, 0), 0), Ok(0));
    // ThumbEE registers without ThumbEE.
    assert!(matches!(s(&mut c, &mut r, &mut m, sys::MRC, cp14(6, 0, 0, 0), 0), Err(Stop::Unpredictable(_))));
    // opc1 2-5: UNDEFINED.
    assert_eq!(s(&mut c, &mut r, &mut m, sys::MRC, cp14(3, 0, 0, 0), 0), Err(Stop::Resume));
    assert_eq!(c.mode(), UND);
    // PL0: DBGDIDR readable, JOSCR UNDEFINED, JMCR writes permitted.
    set_mode(&mut c, &mut r, &mut m, USR);
    assert_eq!(s(&mut c, &mut r, &mut m, sys::MRC, cp14(0, 0, 0, 0), 0), Ok(0x3515_f005));
    assert_eq!(s(&mut c, &mut r, &mut m, sys::MCR, cp14(7, 2, 0, 0), 0), Ok(0));
    assert_eq!(s(&mut c, &mut r, &mut m, sys::MRC, cp14(7, 1, 0, 0), 0), Err(Stop::Resume));
    assert_eq!(c.mode(), UND);
}

#[test]
fn thumbee_registers() {
    let f = Features { thumbee: true, ..features() };
    let mut i = imp();
    i.psr_j_raz_wi = Some(false);
    let (mut c, mut r, mut m) = new_core_with(f, i);
    let teecr = sys::cp(14, 6, 0, 0, 0) as u64;
    let teehbr = sys::cp(14, 6, 1, 0, 0) as u64;
    s(&mut c, &mut r, &mut m, sys::MCR, teehbr, 0x1003).unwrap();
    assert_eq!(s(&mut c, &mut r, &mut m, sys::MRC, teehbr, 0), Ok(0x1000));
    set_mode(&mut c, &mut r, &mut m, USR);
    assert_eq!(s(&mut c, &mut r, &mut m, sys::MRC, teehbr, 0), Ok(0x1000));
    assert_eq!(s(&mut c, &mut r, &mut m, sys::MCR, teecr, 1), Err(Stop::Resume), "TEECR write at PL0");
    set_mode(&mut c, &mut r, &mut m, SVC);
    s(&mut c, &mut r, &mut m, sys::MCR, teecr, 1).unwrap();
    set_mode(&mut c, &mut r, &mut m, USR);
    assert_eq!(s(&mut c, &mut r, &mut m, sys::MRC, teehbr, 0), Err(Stop::Resume), "XED = 1");
}

// -- the VMSA -----------------------------------------------------------------------

const L1: u32 = 0x4000;
const L2: u32 = 0x8000;
const NORMAL: u32 = 0b00111; // TEX 001, C 1, B 1: Write-Back, Write-Allocate

fn section(pa: u32, ap: u32, domain: u32, texcb: u32, xn: bool) -> u32 {
    (pa & 0xfff0_0000) | (ap >> 2 & 1) << 15 | (texcb >> 2) << 12 | (ap & 3) << 10 | domain << 5 | (xn as u32) << 4 | (texcb & 3) << 2 | 0b10
}

fn page_table(pa: u32, domain: u32) -> u32 {
    (pa & 0xffff_fc00) | domain << 5 | 0b01
}

fn small(pa: u32, ap: u32, texcb: u32, xn: bool) -> u32 {
    (pa & 0xffff_f000) | (ap >> 2 & 1) << 9 | (texcb >> 2) << 6 | (ap & 3) << 4 | (texcb & 3) << 2 | 0b10 | xn as u32
}

fn large(pa: u32, ap: u32, texcb: u32, xn: bool) -> u32 {
    (pa & 0xffff_0000) | (xn as u32) << 15 | (texcb >> 2) << 12 | (ap >> 2 & 1) << 9 | (ap & 3) << 4 | (texcb & 3) << 2 | 0b01
}

fn l1(m: &mut M, va: u32, d: u32) {
    m.w(L1 + (va >> 20) * 4, d);
}

/// The MMU on with TTBR0 = L1, every domain a Client, SCTLR.AFE as given.
fn mmu_on(c: &mut Core, r: &mut R, m: &mut M, afe: bool) {
    mcr(c, r, m, 0, 2, 0, 0, L1).unwrap();
    mcr(c, r, m, 0, 3, 0, 0, 0x5555_5555).unwrap();
    let mut v = c.sr.sctlr | cp::SCTLR_M;
    if afe {
        v |= cp::SCTLR_AFE;
    }
    mcr(c, r, m, 0, 1, 0, 0, v).unwrap();
}

fn ld(c: &mut Core, r: &mut R, m: &mut M, va: u32, size_log2: u32) -> Result<u64, Stop> {
    c.mem(r, m, k(PC), va, acc::access(size_log2, false, false, 0))
}

fn st(c: &mut Core, r: &mut R, m: &mut M, va: u32, size_log2: u32) -> Result<u64, Stop> {
    c.mem(r, m, k(PC), va, acc::access(size_log2, true, false, 0))
}

/// The Data Abort just taken at `PC` (entry checked): (DFSR, DFAR).
fn dabt(c: &mut Core, r: &mut R, m: &mut M) -> (u32, u32) {
    assert_eq!(c.mode(), ABT);
    assert_eq!(r.key, k(0x10));
    assert_eq!(r.r[14], PC + 8);
    assert_eq!(c.cpsr(r) & 0x180, 0x180, "I and A set");
    let out = (c.sr.dfsr, c.sr.dfar);
    set_mode(c, r, m, SVC);
    out
}

#[test]
fn mmu_off() {
    let (mut c, mut r, mut m) = new_core();
    // Data accesses are Strongly-ordered: unaligned ones are UNPREDICTABLE.
    assert!(matches!(ld(&mut c, &mut r, &mut m, 0x1233, 2), Err(Stop::Unpredictable(_))));
    assert_eq!(ld(&mut c, &mut r, &mut m, 0x1238, 2), Ok(HOST + 0x1238));
    assert_eq!(ld(&mut c, &mut r, &mut m, 0x1235, 0), Ok(HOST + 0x1235));
    // SCTLR.A: an Alignment fault, before anything else.
    let v = c.sr.sctlr | cp::SCTLR_A;
    mcr(&mut c, &mut r, &mut m, 0, 1, 0, 0, v).unwrap();
    assert_eq!(st(&mut c, &mut r, &mut m, 0x1232, 2), Err(Stop::Resume));
    assert_eq!(dabt(&mut c, &mut r, &mut m), (0x801, 0x1232), "Alignment fault, WnR");
    assert_eq!(c.mem(&mut r, &mut m, k(PC), 0x1232, acc::access(1, false, false, 0)), Ok(HOST + 0x1232));
    // An access the instruction requires aligned faults whatever SCTLR.A.
    let v = c.sr.sctlr & !cp::SCTLR_A;
    mcr(&mut c, &mut r, &mut m, 0, 1, 0, 0, v).unwrap();
    assert_eq!(c.mem(&mut r, &mut m, k(PC), 0x1002, acc::access(2, false, false, 2)), Err(Stop::Resume));
    assert_eq!(dabt(&mut c, &mut r, &mut m), (0x001, 0x1002));
    assert_eq!(c.mem(&mut r, &mut m, k(PC), 0x1004, acc::access(3, false, false, 2)), Ok(HOST + 0x1004), "LDRD: words");
    assert_eq!(c.mem(&mut r, &mut m, k(PC), 0x1004, acc::access(3, false, false, 3) | acc::EXCL), Err(Stop::Resume), "LDREXD");
    set_mode(&mut c, &mut r, &mut m, SVC);
    // Memory the model lacks; the top of memory; the sink.
    assert!(matches!(ld(&mut c, &mut r, &mut m, 0x4000_0000, 2), Err(Stop::Unimplemented(_))));
    assert!(matches!(ld(&mut c, &mut r, &mut m, 0xffff_fffe, 2), Err(Stop::Unpredictable(_))));
    assert_eq!(c.mem(&mut r, &mut m, k(PC), 0x4000_0000, acc::access(2, false, false, 0) | acc::SKIP), Ok(0xdead_0000));
    // Fetches with the MMU off: flat.
    m.w(0x2000, 0xbeef_cafe);
    assert_eq!(c.fetch(&r, &m, 0x2000, false), Some(0xcafe));
    assert_eq!(c.fetch(&r, &m, 0x2002, true), Some(0xbeef));
    assert_eq!(c.fetch(&r, &m, 0x4000_0000, false), None);
    assert!(matches!(c.sys(&mut r, &mut m, k(0x4000_0000), sys::EXCEPTION, exc::FETCH as u64, 0x4000_0000), Err(Stop::Unimplemented(_))));
}

#[test]
fn swp_needs_sctlr_sw() {
    let (mut c, mut r, mut m) = new_core();
    let swp = acc::access(2, true, false, 2) | acc::SWP;
    assert_eq!(c.mem(&mut r, &mut m, k(PC), 0x1000, swp), Err(Stop::Resume));
    assert_eq!((c.mode(), r.r[14]), (UND, PC + 4));
    set_mode(&mut c, &mut r, &mut m, SVC);
    let v = c.sr.sctlr | cp::SCTLR_SW;
    mcr(&mut c, &mut r, &mut m, 0, 1, 0, 0, v).unwrap();
    assert_eq!(c.mem(&mut r, &mut m, k(PC), 0x1000, swp), Ok(HOST + 0x1000));
    // Without the Multiprocessing Extensions SW is RAZ and SWP executes.
    let f = Features { mp: false, ..features() };
    let (mut c, mut r, mut m) = new_core_with(f, imp());
    assert_eq!(c.mem(&mut r, &mut m, k(PC), 0x1000, swp), Ok(HOST + 0x1000));
    let v = c.sr.sctlr | cp::SCTLR_SW;
    mcr(&mut c, &mut r, &mut m, 0, 1, 0, 0, v).unwrap();
    assert_eq!(c.sr.sctlr & cp::SCTLR_SW, 0);
}

#[test]
fn sections_and_pages() {
    let (mut c, mut r, mut m) = new_core();
    l1(&mut m, 0x0010_0000, section(0x0020_0000, 0b011, 0, NORMAL, false));
    l1(&mut m, 0x0030_0000, page_table(L2, 1));
    // Small page 0x0030_5000 -> 0x0011_2000; large page 0x0031_0000 ->
    // 0x0010_0000 (repeated 16 times).
    m.w(L2 + 0x05 * 4, small(0x0011_2000, 0b011, NORMAL, false));
    for i in 0..16 {
        m.w(L2 + (0x10 + i) * 4, large(0x0010_0000, 0b011, NORMAL, false));
    }
    mmu_on(&mut c, &mut r, &mut m, false);
    assert_eq!(ld(&mut c, &mut r, &mut m, 0x0012_3456, 2), Ok(HOST + 0x0022_3456), "section");
    assert_eq!(ld(&mut c, &mut r, &mut m, 0x0030_5ffc, 2), Ok(HOST + 0x0011_2ffc), "small page");
    assert_eq!(ld(&mut c, &mut r, &mut m, 0x0031_abcd, 0), Ok(HOST + 0x0010_abcd), "large page");
    // Unaligned to Normal memory is permitted (SCTLR.A = 0).
    assert_eq!(ld(&mut c, &mut r, &mut m, 0x0012_3455, 2), Ok(HOST + 0x0022_3455));
    // Translation faults: first level, second level (with the domain).
    assert_eq!(ld(&mut c, &mut r, &mut m, 0x0050_0000, 2), Err(Stop::Resume));
    assert_eq!(dabt(&mut c, &mut r, &mut m), (0x005, 0x0050_0000));
    assert_eq!(st(&mut c, &mut r, &mut m, 0x0030_6000, 2), Err(Stop::Resume));
    assert_eq!(dabt(&mut c, &mut r, &mut m), (0x800 | 0x10 | 0x007, 0x0030_6000));
    // An access across a page into an unmapped one faults on the second.
    assert_eq!(ld(&mut c, &mut r, &mut m, 0x0030_5ffe, 2), Err(Stop::Resume));
    assert_eq!(dabt(&mut c, &mut r, &mut m), (0x10 | 0x007, 0x0030_6000));
    // Across two pages whose host memory is contiguous: one host address;
    // whose host memory is not: loud.
    m.w(L2 + 0x06 * 4, small(0x0011_3000, 0b011, NORMAL, false));
    assert_eq!(ld(&mut c, &mut r, &mut m, 0x0030_5ffe, 2), Ok(HOST + 0x0011_2ffe));
    m.w(L2 + 0x06 * 4, small(0x0011_5000, 0b011, NORMAL, false));
    assert!(matches!(ld(&mut c, &mut r, &mut m, 0x0030_5ffe, 2), Err(Stop::Unimplemented(_))));
    // Fetches.
    m.w(0x0022_0000, 0x1111_2222);
    assert_eq!(c.fetch(&r, &m, 0x0012_0002, false), Some(0x1111));
    // The first-level encoding 0b11 is a section with PXN here.
    l1(&mut m, 0x0060_0000, section(0x0020_0000, 0b011, 0, NORMAL, false) | 1);
    assert_eq!(ld(&mut c, &mut r, &mut m, 0x0060_0000, 2), Ok(HOST + 0x0020_0000));
}

#[test]
fn no_pxn_reserved_encoding() {
    let mut i = imp();
    i.id_mmfr[0] = Some(0x1020_1103);
    let (mut c, mut r, mut m) = new_core_with(features(), i);
    l1(&mut m, 0x0060_0000, section(0x0020_0000, 0b011, 0, NORMAL, false) | 1);
    mmu_on(&mut c, &mut r, &mut m, false);
    assert_eq!(ld(&mut c, &mut r, &mut m, 0x0060_0000, 2), Err(Stop::Resume));
    assert_eq!(dabt(&mut c, &mut r, &mut m).0, 0x005);
}

#[test]
fn supersection_and_external_abort() {
    let f = Features { lpae: true, ..features() };
    let (mut c, mut r, mut m) = new_core_with(f, imp());
    // A Supersection at VA 0x0100_0000 to PA 0x8000_0000 (PA[39:32] = 0).
    let ss = 0x8000_0000 | 1 << 18 | 0b011 << 10 | (NORMAL >> 2) << 12 | (NORMAL & 3) << 2 | 0b10;
    for i in 0..16 {
        m.w(L1 + (0x10 + i) * 4, ss);
    }
    // A page table at a PA with no memory: an external abort on the second
    // level walk.
    l1(&mut m, 0x0200_0000, page_table(0x3000_0000, 7));
    mmu_on(&mut c, &mut r, &mut m, false);
    assert_eq!(ld(&mut c, &mut r, &mut m, 0x0100_8000, 2), Ok(HI_HOST + 0x8000));
    assert_eq!(ld(&mut c, &mut r, &mut m, 0x0200_0000, 2), Err(Stop::Resume));
    assert_eq!(dabt(&mut c, &mut r, &mut m), (0x70 | 0x00e, 0x0200_0000));
    // ATS1CPR of the Supersection: the PAR's SS format.
    mcr(&mut c, &mut r, &mut m, 0, 7, 8, 0, 0x0123_4567).unwrap();
    assert_eq!(mrc(&mut c, &mut r, &mut m, 0, 7, 4, 0), Ok((0x8000_0000u32 | 0b101 << 4 | 0b01 << 2 | 1 << 1) as u64));
    // An external abort on an ATS walk is a Data Abort, WnR = 1, CM = 1.
    assert_eq!(c.sys(&mut r, &mut m, k(PC), sys::MCR, sys::cp(15, 0, 7, 8, 0) as u64, 0x0200_0000), Err(Stop::Resume));
    assert_eq!(dabt(&mut c, &mut r, &mut m), (0x2000 | 0x800 | 0x70 | 0x00e, 0x0200_0000));
    // A first-level external abort.
    mcr(&mut c, &mut r, &mut m, 0, 2, 0, 0, 0x3000_0000).unwrap();
    assert_eq!(ld(&mut c, &mut r, &mut m, 0x0, 2), Err(Stop::Resume));
    assert_eq!(dabt(&mut c, &mut r, &mut m).0, 0x00c);
}

#[test]
fn ttbcr_split() {
    let (mut c, mut r, mut m) = new_core();
    // N = 2: TTBR0 (a 4KB table at 0xc000) below 0x4000_0000, TTBR1 (16KB
    // at L1) above.
    let t0 = 0xc000;
    m.w(t0 + (0x0010_0000 >> 20) * 4, section(0x0010_0000, 0b011, 0, NORMAL, false));
    m.w(t0 + (0x3ff0_0000 >> 20) * 4, section(0x0020_0000, 0b011, 0, NORMAL, false));
    l1(&mut m, 0x8000_0000, section(0x0030_0000, 0b011, 0, NORMAL, false));
    l1(&mut m, 0x0010_0000, section(0x0000_0000, 0b011, 0, NORMAL, false));
    mcr(&mut c, &mut r, &mut m, 0, 2, 0, 2, 2).unwrap();
    mcr(&mut c, &mut r, &mut m, 0, 2, 0, 0, t0).unwrap();
    mcr(&mut c, &mut r, &mut m, 0, 2, 0, 1, L1).unwrap();
    mcr(&mut c, &mut r, &mut m, 0, 3, 0, 0, 1).unwrap();
    let v = c.sr.sctlr | cp::SCTLR_M;
    mcr(&mut c, &mut r, &mut m, 0, 1, 0, 0, v).unwrap();
    assert_eq!(ld(&mut c, &mut r, &mut m, 0x0010_0010, 2), Ok(HOST + 0x0010_0010));
    assert_eq!(ld(&mut c, &mut r, &mut m, 0x3ff0_0010, 2), Ok(HOST + 0x0020_0010));
    assert_eq!(ld(&mut c, &mut r, &mut m, 0x8000_0010, 2), Ok(HOST + 0x0030_0010));
    assert_eq!(ld(&mut c, &mut r, &mut m, 0x4000_0000, 2), Err(Stop::Resume), "TTBR1 has no entry there");
    assert_eq!(dabt(&mut c, &mut r, &mut m).0, 0x005);
}

#[test]
fn access_permissions() {
    // Table B3-8, as (AP[2:0], [PL1 read, PL1 write, PL0 read, PL0 write]).
    let table: [(u32, [bool; 4]); 7] = [
        (0b000, [false, false, false, false]),
        (0b001, [true, true, false, false]),
        (0b010, [true, true, true, false]),
        (0b011, [true, true, true, true]),
        (0b101, [true, false, false, false]),
        (0b110, [true, false, true, false]),
        (0b111, [true, false, true, false]),
    ];
    for afe in [false, true] {
        for &(ap, ok) in &table {
            let (mut c, mut r, mut m) = new_core();
            // With AFE, AP[0] is the Access flag (set here): AP[2:1] only
            // (Table B3-6).
            let desc_ap = if afe { ap | 1 } else { ap };
            let ok = if afe { table.iter().find(|t| t.0 == desc_ap).unwrap().1 } else { ok };
            l1(&mut m, 0x0010_0000, section(0x0020_0000, desc_ap, 2, NORMAL, false));
            mmu_on(&mut c, &mut r, &mut m, afe);
            for (i, &(pl0, write)) in [(false, false), (false, true), (true, false), (true, true)].iter().enumerate() {
                let got = c.mem(&mut r, &mut m, k(PC), 0x0010_0000, acc::access(2, write, pl0, 0));
                if ok[i] {
                    assert_eq!(got, Ok(HOST + 0x0020_0000), "ap {ap:03b} afe {afe} case {i}");
                } else {
                    assert_eq!(got, Err(Stop::Resume), "ap {ap:03b} afe {afe} case {i}");
                    assert_eq!(dabt(&mut c, &mut r, &mut m), ((write as u32) << 11 | 2 << 4 | 0x00d, 0x0010_0000), "permission fault, domain 2");
                }
            }
            // The same from User mode (not LDRT).
            set_mode(&mut c, &mut r, &mut m, USR);
            let got = ld(&mut c, &mut r, &mut m, 0x0010_0000, 2);
            assert_eq!(got.is_ok(), ok[2], "ap {ap:03b} afe {afe} User read");
        }
    }
    let (mut c, mut r, mut m) = new_core();
    l1(&mut m, 0x0010_0000, section(0x0020_0000, 0b100, 0, NORMAL, false));
    mmu_on(&mut c, &mut r, &mut m, false);
    assert!(matches!(ld(&mut c, &mut r, &mut m, 0x0010_0000, 2), Err(Stop::Unpredictable(_))));
}

#[test]
fn access_flag() {
    let (mut c, mut r, mut m) = new_core();
    // AP[0] = 0 with AFE: Access flag faults, first and second level.
    l1(&mut m, 0x0010_0000, section(0x0020_0000, 0b010, 0, NORMAL, false));
    l1(&mut m, 0x0030_0000, page_table(L2, 3));
    m.w(L2, small(0x0011_2000, 0b010, NORMAL, false));
    mmu_on(&mut c, &mut r, &mut m, true);
    assert_eq!(ld(&mut c, &mut r, &mut m, 0x0010_0000, 2), Err(Stop::Resume));
    assert_eq!(dabt(&mut c, &mut r, &mut m), (0x003, 0x0010_0000));
    assert_eq!(ld(&mut c, &mut r, &mut m, 0x0030_0000, 2), Err(Stop::Resume));
    assert_eq!(dabt(&mut c, &mut r, &mut m), (0x30 | 0x006, 0x0030_0000));
    // Without AFE, AP 010 is read/write at PL1.
    let v = c.sr.sctlr & !cp::SCTLR_AFE;
    mcr(&mut c, &mut r, &mut m, 0, 1, 0, 0, v).unwrap();
    assert_eq!(st(&mut c, &mut r, &mut m, 0x0010_0000, 2), Ok(HOST + 0x0020_0000));
}

#[test]
fn hardware_access_flag() {
    let mut i = imp();
    i.sctlr = Some((cp::SCTLR_I | cp::SCTLR_C | cp::SCTLR_CP15BEN | cp::SCTLR_HA, 0));
    let (mut c, mut r, mut m) = new_core_with(features(), i);
    let d = section(0x0020_0000, 0b010, 0, NORMAL, false);
    l1(&mut m, 0x0010_0000, d);
    mmu_on(&mut c, &mut r, &mut m, true);
    let v = c.sr.sctlr | cp::SCTLR_HA;
    mcr(&mut c, &mut r, &mut m, 0, 1, 0, 0, v).unwrap();
    // A fetch needs the update first: the FETCH exception path makes it.
    assert_eq!(c.fetch(&r, &m, 0x0010_0000, false), None);
    assert_eq!(ld(&mut c, &mut r, &mut m, 0x0010_0000, 2), Ok(HOST + 0x0020_0000));
    assert_eq!(m.r(L1 + 4), d | 1 << 10, "the Access flag set in memory");
    assert_eq!(c.fetch(&r, &m, 0x0010_0000, false), Some(0));
}

#[test]
fn domains() {
    let (mut c, mut r, mut m) = new_core();
    l1(&mut m, 0x0010_0000, section(0x0020_0000, 0b000, 5, NORMAL, true));
    l1(&mut m, 0x0030_0000, page_table(L2, 6));
    m.w(L2, small(0x0011_2000, 0b000, NORMAL, false));
    mmu_on(&mut c, &mut r, &mut m, false);
    // Client: AP 000 faults.
    assert_eq!(ld(&mut c, &mut r, &mut m, 0x0010_0000, 2), Err(Stop::Resume));
    assert_eq!(dabt(&mut c, &mut r, &mut m).0, 0x50 | 0x00d);
    // Manager: no permission check, nor XN.
    mcr(&mut c, &mut r, &mut m, 0, 3, 0, 0, 0b11 << 10 | 0b11 << 12).unwrap();
    assert_eq!(st(&mut c, &mut r, &mut m, 0x0010_0000, 2), Ok(HOST + 0x0020_0000));
    m.w(0x0020_0000, 0xabcd_1234);
    assert_eq!(c.fetch(&r, &m, 0x0010_0000, true), Some(0x1234));
    // No access: Domain faults, first and second level.
    mcr(&mut c, &mut r, &mut m, 0, 3, 0, 0, 0).unwrap();
    assert_eq!(st(&mut c, &mut r, &mut m, 0x0010_0000, 2), Err(Stop::Resume));
    assert_eq!(dabt(&mut c, &mut r, &mut m), (0x800 | 0x50 | 0x009, 0x0010_0000));
    assert_eq!(ld(&mut c, &mut r, &mut m, 0x0030_0004, 2), Err(Stop::Resume));
    assert_eq!(dabt(&mut c, &mut r, &mut m), (0x60 | 0x00b, 0x0030_0004));
    // The reserved 0b10.
    mcr(&mut c, &mut r, &mut m, 0, 3, 0, 0, 0b10 << 10).unwrap();
    assert!(matches!(ld(&mut c, &mut r, &mut m, 0x0010_0000, 2), Err(Stop::Unpredictable(_))));
}

#[test]
fn execute_never_and_prefetch_abort() {
    let (mut c, mut r, mut m) = new_core();
    l1(&mut m, 0x0010_0000, section(0x0020_0000, 0b011, 0, NORMAL, true));
    l1(&mut m, 0x0030_0000, section(0x0020_0000, 0b001, 0, NORMAL, false));
    // PXN: bits 1:0 = 0b11 (ID_MMFR0.VMSA = 5 has it).
    l1(&mut m, 0x0040_0000, section(0x0020_0000, 0b011, 0, NORMAL, false) | 1);
    l1(&mut m, 0x0050_0000, section(0x0020_0000, 0b011, 0, 0b00000, false));
    mmu_on(&mut c, &mut r, &mut m, false);
    assert_eq!(c.fetch(&r, &m, 0x0010_0000, false), None, "XN");
    assert_eq!(c.fetch(&r, &m, 0x0030_0000, false), Some(0), "PL1 only, at PL1");
    assert_eq!(c.fetch(&r, &m, 0x0040_0000, false), None, "PXN at PL1");
    assert_eq!(c.fetch(&r, &m, 0x0030_0000, true), None, "PL1 only, at PL0");
    assert_eq!(c.fetch(&r, &m, 0x0040_0000, true), Some(0), "PXN does not apply at PL0");
    // The Prefetch Abort when the lifter's FETCH arrives: IFSR, IFAR, LR.
    let pc = key(0x0010_0000, true, 0);
    assert_eq!(c.sys(&mut r, &mut m, pc, sys::EXCEPTION, exc::FETCH as u64, 0x0010_0000), Err(Stop::Resume));
    assert_eq!((c.mode(), r.key, r.r[14]), (ABT, k(0xc), 0x0010_0004));
    assert_eq!((c.sr.ifsr, c.sr.ifar), (0x00d, 0x0010_0000));
    assert_eq!(c.spsr().unwrap() & 0x3f, 0x20 | SVC as u32);
    // A FETCH at PL0 (the key's level): the second halfword of a 32-bit
    // instruction faulting, the instruction's LR, the halfword's IFAR.
    set_mode(&mut c, &mut r, &mut m, USR);
    let pc = key(0x005f_fffe, true, 0) | KEY_USER;
    assert_eq!(c.sys(&mut r, &mut m, pc, sys::EXCEPTION, exc::FETCH as u64, 0x0060_0000), Err(Stop::Resume));
    assert_eq!((c.mode(), r.r[14], c.sr.ifar, c.sr.ifsr), (ABT, 0x0060_0002, 0x0060_0000, 0x005));
    assert_eq!(c.spsr().unwrap() & 0x1f, USR as u32);
    set_mode(&mut c, &mut r, &mut m, USR);
    let pc = key(0x0030_0000, false, 0) | KEY_USER;
    assert_eq!(c.sys(&mut r, &mut m, pc, sys::EXCEPTION, exc::FETCH as u64, 0x0030_0000), Err(Stop::Resume));
    assert_eq!((c.mode(), c.sr.ifsr), (ABT, 0x00d));
    // A fetch from Strongly-ordered memory is UNPREDICTABLE.
    set_mode(&mut c, &mut r, &mut m, SVC);
    assert_eq!(c.fetch(&r, &m, 0x0050_0000, false), None);
    assert!(matches!(c.sys(&mut r, &mut m, k(0x0050_0000), sys::EXCEPTION, exc::FETCH as u64, 0x0050_0000), Err(Stop::Unpredictable(_))));
    // A FETCH whose translation now succeeds: a fresh translation.
    let e = c.code_epoch();
    assert_eq!(c.sys(&mut r, &mut m, k(0x0030_0000), sys::EXCEPTION, exc::FETCH as u64, 0x0030_0000), Err(Stop::Resume));
    assert!(c.code_epoch() > e);
    assert_eq!(c.mode(), SVC);
}

#[test]
fn device_alignment_and_tex() {
    let (mut c, mut r, mut m) = new_core();
    l1(&mut m, 0x0010_0000, section(0x0020_0000, 0b011, 0, 0b00001, false));
    l1(&mut m, 0x0060_0000, section(0x0020_0000, 0b011, 0, 0b00101, false));
    l1(&mut m, 0x0070_0000, section(0x0020_0000, 0b011, 0, 0b00110, false));
    l1(&mut m, 0x0080_0000, section(0x0020_0000, 0b011, 0, 0b10110, false));
    mmu_on(&mut c, &mut r, &mut m, false);
    assert_eq!(ld(&mut c, &mut r, &mut m, 0x0010_0004, 2), Ok(HOST + 0x0020_0004));
    assert!(matches!(ld(&mut c, &mut r, &mut m, 0x0010_0002, 2), Err(Stop::Unpredictable(_))), "unaligned to Device");
    assert_eq!(ld(&mut c, &mut r, &mut m, 0x0080_0002, 2), Ok(HOST + 0x0020_0002), "cacheable Normal");
    // Reserved TEX encodings are UNPREDICTABLE; the IMPLEMENTATION DEFINED one
    // stops.
    assert!(matches!(ld(&mut c, &mut r, &mut m, 0x0060_0000, 2), Err(Stop::Unpredictable(_))));
    assert!(matches!(ld(&mut c, &mut r, &mut m, 0x0070_0000, 2), Err(Stop::ImpDef(_))));
    // With SCTLR.A the Alignment fault comes first.
    let v = c.sr.sctlr | cp::SCTLR_A;
    mcr(&mut c, &mut r, &mut m, 0, 1, 0, 0, v).unwrap();
    assert_eq!(ld(&mut c, &mut r, &mut m, 0x0010_0002, 2), Err(Stop::Resume));
    assert_eq!(dabt(&mut c, &mut r, &mut m), (0x001, 0x0010_0002));
}

#[test]
fn tex_remap() {
    let (mut c, mut r, mut m) = new_core();
    // Region 0 reserved (TR0 = 0b11); region 1 (TEX[0] C B = 001) Device;
    // region 3 Normal, Write-Back Write-Allocate inner and outer; NS1 = 1.
    mcr(&mut c, &mut r, &mut m, 0, 10, 2, 0, 0b11 | 0b01 << 2 | 0b10 << 6 | 1 << 19).unwrap();
    mcr(&mut c, &mut r, &mut m, 0, 10, 2, 1, 0b01 << 6 | 0b01 << 22).unwrap();
    l1(&mut m, 0x0010_0000, section(0x0020_0000, 0b011, 0, 0b00001, false));
    l1(&mut m, 0x0020_0000, section(0x0020_0000, 0b011, 0, 0b00011, false) | 1 << 16);
    l1(&mut m, 0x0030_0000, section(0x0020_0000, 0b011, 0, 0b11000, false));
    l1(&mut m, 0x0040_0000, section(0x0020_0000, 0b011, 0, 0b00110, false));
    mmu_on(&mut c, &mut r, &mut m, false);
    let v = c.sr.sctlr | cp::SCTLR_TRE;
    mcr(&mut c, &mut r, &mut m, 0, 1, 0, 0, v).unwrap();
    assert!(matches!(ld(&mut c, &mut r, &mut m, 0x0010_0001, 2), Err(Stop::Unpredictable(_))), "Device");
    assert_eq!(ld(&mut c, &mut r, &mut m, 0x0020_0001, 2), Ok(HOST + 0x0020_0001), "Normal");
    assert!(matches!(ld(&mut c, &mut r, &mut m, 0x0030_0000, 2), Err(Stop::Unpredictable(_))), "TR0 = 0b11; TEX[2:1] ignored");
    assert!(matches!(ld(&mut c, &mut r, &mut m, 0x0040_0000, 2), Err(Stop::ImpDef(_))), "region 6");
    // ATS1CPR: the PAR's attributes of the remapped Normal region, Shareable
    // (NS1), Outer Shareable (NOS3 = 0).
    mcr(&mut c, &mut r, &mut m, 0, 7, 8, 0, 0x0020_0123).unwrap();
    assert_eq!(c.sr.par, (0x0020_0000 | 1 << 7 | 0b101 << 4 | 0b01 << 2) as u64);
}

#[test]
fn ats_par() {
    let (mut c, mut r, mut m) = new_core();
    l1(&mut m, 0x0010_0000, section(0x0020_0000, 0b001, 0, NORMAL, false));
    mmu_on(&mut c, &mut r, &mut m, false);
    // ATS1CPR: the PA, Write-Back Write-Allocate, Non-shareable.
    mcr(&mut c, &mut r, &mut m, 0, 7, 8, 0, 0x0012_3456).unwrap();
    assert_eq!(mrc(&mut c, &mut r, &mut m, 0, 7, 4, 0), Ok((0x0022_3000 | 0b101 << 4 | 0b01 << 2) as u64));
    // ATS1CUR: a PL0 read faults; the Permission fault goes to the PAR, no
    // exception.
    mcr(&mut c, &mut r, &mut m, 0, 7, 8, 2, 0x0012_3456).unwrap();
    assert_eq!(c.mode(), SVC);
    assert_eq!(mrc(&mut c, &mut r, &mut m, 0, 7, 4, 0), Ok((0b01101 << 1 | 1) as u64));
    // ATS1CPW of an unmapped address: a Translation fault.
    mcr(&mut c, &mut r, &mut m, 0, 7, 8, 1, 0x0090_0000).unwrap();
    assert_eq!(c.sr.par, (0b00101 << 1 | 1) as u64);
    // The Security Extensions' ATS12NSO** are unallocated without them.
    assert!(matches!(mcr(&mut c, &mut r, &mut m, 0, 7, 8, 4, 0), Err(Stop::Unpredictable(_))));
    // With the MMU off: flat, Strongly-ordered.
    let v = c.sr.sctlr & !cp::SCTLR_M;
    mcr(&mut c, &mut r, &mut m, 0, 1, 0, 0, v).unwrap();
    mcr(&mut c, &mut r, &mut m, 0, 7, 8, 0, 0x0012_3456).unwrap();
    assert_eq!(c.sr.par, (0x0012_3000 | 1 << 7 | 0b001 << 4) as u64);
}

#[test]
fn cache_maintenance_by_mva() {
    let (mut c, mut r, mut m) = new_core();
    l1(&mut m, 0x0010_0000, section(0x0020_0000, 0b000, 0, NORMAL, false));
    mmu_on(&mut c, &mut r, &mut m, false);
    // No permission check; an unmapped MVA is a Translation fault, WnR = 1.
    assert_eq!(mcr(&mut c, &mut r, &mut m, 0, 7, 14, 1, 0x0010_0040), Ok(0));
    assert_eq!(c.sys(&mut r, &mut m, k(PC), sys::MCR, sys::cp(15, 0, 7, 10, 1) as u64, 0x0090_0040), Err(Stop::Resume));
    assert_eq!(dabt(&mut c, &mut r, &mut m), (0x800 | 0x005, 0x0090_0040));
    // ICIMVAU does not translate here.
    assert_eq!(mcr(&mut c, &mut r, &mut m, 0, 7, 5, 1, 0x0090_0040), Ok(0));
}

#[test]
fn unprivileged_access() {
    let (mut c, mut r, mut m) = new_core();
    l1(&mut m, 0x0010_0000, section(0x0020_0000, 0b001, 0, NORMAL, false));
    mmu_on(&mut c, &mut r, &mut m, false);
    assert_eq!(ld(&mut c, &mut r, &mut m, 0x0010_0000, 2), Ok(HOST + 0x0020_0000));
    // LDRT from SVC is checked as PL0.
    assert_eq!(c.mem(&mut r, &mut m, k(PC), 0x0010_0000, acc::access(2, false, true, 0)), Err(Stop::Resume));
    assert_eq!(dabt(&mut c, &mut r, &mut m).0, 0x00d);
}

// -- the Advanced SIMD and Floating-point system level (B1.11) ---------------

/// CPACR (c1, c0, 2) and FPEXC through VMSR.
fn fp_enable(c: &mut Core, r: &mut R, m: &mut M, cpacr: u32, en: bool) {
    mcr(c, r, m, 0, 1, 0, 2, cpacr).unwrap();
    s(c, r, m, sys::VMSR, 0b1000, if en { 1 << 30 } else { 0 }).unwrap();
}

#[test]
fn fpen_follows_cpacr_and_fpexc() {
    use gex_abi::a32::fpen::*;
    let (mut c, mut r, mut m) = new_core();
    assert_eq!(r.fpen, 0, "CPACR and FPEXC.EN reset to 0");
    fp_enable(&mut c, &mut r, &mut m, 0x00f0_0000, false);
    assert_eq!(r.fpen, 0, "FPEXC.EN = 0");
    fp_enable(&mut c, &mut r, &mut m, 0x00f0_0000, true);
    assert_eq!(r.fpen, VFP_PL1 | VFP_PL0 | SIMD_PL1 | SIMD_PL0 | D32);
    fp_enable(&mut c, &mut r, &mut m, 0x0050_0000, true);
    assert_eq!(r.fpen, VFP_PL1 | SIMD_PL1 | D32, "cp10/cp11 = 0b01: PL1 only");
    fp_enable(&mut c, &mut r, &mut m, 0x80f0_0000, true);
    assert_eq!(r.fpen, VFP_PL1 | VFP_PL0 | D32, "ASEDIS");
    fp_enable(&mut c, &mut r, &mut m, 0xc0f0_0000, true);
    assert_eq!(r.fpen, VFP_PL1 | VFP_PL0, "D32DIS");
    mcr(&mut c, &mut r, &mut m, 0, 1, 0, 2, 0x0030_0000).unwrap();
    assert_eq!(r.fpen, 0, "cp10 != cp11 is UNPREDICTABLE: left to the full check");
}

#[test]
fn fp_check_trap_takes_undefined_or_stops() {
    let (mut c, mut r, mut m) = new_core();
    let pc = key(0x2000, false, 0);
    let code = gex_abi::a32::BRK_FP_CHECK;
    // Disabled: the Undefined Instruction exception at the instruction.
    assert_eq!(c.fp_check_failed(&mut r, pc, code), Err(Stop::Resume));
    assert_eq!(c.mode(), UND);
    assert_eq!(r.r[14], 0x2004);
    // cp10 != cp11: UNPREDICTABLE.
    let (mut c, mut r, mut m2) = new_core();
    mcr(&mut c, &mut r, &mut m2, 0, 1, 0, 2, 0x0030_0000).unwrap();
    assert!(matches!(c.fp_check_failed(&mut r, pc, code), Err(Stop::Unpredictable(_))));
    // D32DIS without ASEDIS: UNPREDICTABLE for an access to D16-D31 only.
    let (mut c, mut r, mut m3) = new_core();
    fp_enable(&mut c, &mut r, &mut m3, 0x40f0_0000, true);
    let d32 = code - gex_abi::a32::FP_CHECK_D32;
    assert!(matches!(c.fp_check_failed(&mut r, pc, d32), Err(Stop::Unpredictable(_))));
    // Enabled: a trap that should not have been taken stops loudly.
    fp_enable(&mut c, &mut r, &mut m3, 0x00f0_0000, true);
    assert!(matches!(c.fp_check_failed(&mut r, pc, code), Err(Stop::Unimplemented(_))));
    // ASEDIS: an Advanced SIMD instruction is UNDEFINED.
    fp_enable(&mut c, &mut r, &mut m3, 0x80f0_0000, true);
    assert_eq!(c.fp_check_failed(&mut r, pc, code - gex_abi::a32::FP_CHECK_SIMD), Err(Stop::Resume));
    let _ = &mut m;
}

#[test]
fn vmrs_vmsr_special_registers() {
    let (mut c, mut r, mut m) = new_core();
    let pc = key(0x2000, false, 0);
    // CPACR denies: UNDEFINED even for FPSID.
    assert_eq!(c.sys(&mut r, &mut m, pc, sys::VMRS, 0, 0), Err(Stop::Resume));
    let (mut c, mut r, mut m) = new_core();
    mcr(&mut c, &mut r, &mut m, 0, 1, 0, 2, 0x00f0_0000).unwrap();
    // FPSID, MVFR0/1, FPEXC: not affected by FPEXC.EN.
    assert_eq!(c.sys(&mut r, &mut m, pc, sys::VMRS, 0b0000, 0), Ok(0x4104_30f0));
    assert_eq!(c.sys(&mut r, &mut m, pc, sys::VMRS, 0b0111, 0), Ok(0x1011_0222));
    assert_eq!(c.sys(&mut r, &mut m, pc, sys::VMRS, 0b0110, 0), Ok(0x1111_1111));
    assert_eq!(c.sys(&mut r, &mut m, pc, sys::VMRS, 0b1000, 0), Ok(0));
    // The FPSCR needs FPEXC.EN.
    assert_eq!(c.sys(&mut r, &mut m, pc, sys::VMSR, 0b0001, 0), Err(Stop::Resume));
    let (mut c, mut r, mut m) = new_core();
    fp_enable(&mut c, &mut r, &mut m, 0x00f0_0000, true);
    // Read/write bits kept, trap enables RAZ/WI, UNK/SBZP bits refused.
    assert_eq!(c.sys(&mut r, &mut m, pc, sys::VMSR, 0b0001, 0xfff7_9f9f), Ok(0));
    assert_eq!(r.fpscr, 0xfff7_009f);
    assert!(matches!(c.sys(&mut r, &mut m, pc, sys::VMSR, 0b0001, 1 << 19), Err(Stop::Unpredictable(_))));
    assert!(matches!(c.sys(&mut r, &mut m, pc, sys::VMSR, 0b0001, 1 << 5), Err(Stop::Unpredictable(_))));
    // Unallocated registers, MVFR writes: UNPREDICTABLE; FPEXC.EX: loud.
    assert!(matches!(c.sys(&mut r, &mut m, pc, sys::VMRS, 0b0011, 0), Err(Stop::Unpredictable(_))));
    assert!(matches!(c.sys(&mut r, &mut m, pc, sys::VMSR, 0b0111, 0), Err(Stop::Unpredictable(_))));
    assert!(matches!(c.sys(&mut r, &mut m, pc, sys::VMSR, 0b1000, 1 << 31), Err(Stop::Unimplemented(_))));
    assert!(matches!(c.sys(&mut r, &mut m, pc, sys::VMRS, 0b1001, 0), Err(Stop::Unimplemented(_))));
    // A write to FPSID only serializes.
    assert_eq!(c.sys(&mut r, &mut m, pc, sys::VMSR, 0b0000, 5), Ok(0));
    // User mode: the non-FPSCR registers are UNDEFINED.
    set_mode(&mut c, &mut r, &mut m, USR);
    assert_eq!(c.sys(&mut r, &mut m, pc | KEY_USER, sys::VMRS, 0b1000, 0), Err(Stop::Resume));
    assert_eq!(c.mode(), UND);
}
