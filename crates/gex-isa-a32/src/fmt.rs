//! Disassembly in LLVM's spelling of UAL (what `llvm-mc --disassemble`
//! prints), for diagnostics and the differential tests against LLVM. The
//! `.w`/`.n` width qualifiers are not printed.

use crate::*;
use std::fmt::Write;

fn r(x: Reg) -> &'static str {
    const N: [&str; 16] = [
        "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc",
    ];
    N[(x.0 & 15) as usize]
}

fn shift_name(s: Shift) -> &'static str {
    match s {
        Shift::Lsl => "lsl",
        Shift::Lsr => "lsr",
        Shift::Asr => "asr",
        Shift::Ror => "ror",
        Shift::Rrx => "rrx",
    }
}

fn imm(v: i64) -> String {
    format!("#{v}")
}

fn operand(o: &Operand) -> String {
    match *o {
        Operand::Imm { value, .. } => imm(value as i32 as i64),
        Operand::RegImm { rm, shift: Shift::Lsl, amount: 0 } => r(rm).into(),
        Operand::RegImm { rm, shift: Shift::Rrx, .. } => format!("{}, rrx", r(rm)),
        Operand::RegImm { rm, shift, amount } => format!("{}, {} #{amount}", r(rm), shift_name(shift)),
        Operand::RegReg { rm, shift, rs } => format!("{}, {} {}", r(rm), shift_name(shift), r(rs)),
    }
}

/// An ARM modified immediate constant (A5.2.4) from its encoding (bits
/// 11:0): the constant, or `#<byte>, #<rot>` when the rotation is not the
/// lowest that encodes the constant (the encoding an assembler chooses), as
/// A5.2.4 permits and LLVM prints.
fn arm_mod_imm(raw: u32, unsigned: bool) -> String {
    let (imm8, rot) = (raw & 0xff, (raw >> 8) & 15);
    let v = imm8.rotate_right(2 * rot);
    let lowest = (0..16).find(|r| v.rotate_left(2 * r) <= 255).unwrap_or(rot);
    if lowest != rot {
        format!("#{imm8}, #{}", 2 * rot)
    } else if unsigned {
        format!("#{v}")
    } else {
        format!("#{}", v as i32)
    }
}

fn reglist(regs: u16) -> String {
    let v: Vec<&str> = (0..16).filter(|i| regs & (1 << i) != 0).map(|i| r(Reg(i))).collect();
    format!("{{{}}}", v.join(", "))
}

fn amode(m: Amode) -> &'static str {
    match m {
        Amode::Ia => "ia",
        Amode::Ib => "ib",
        Amode::Da => "da",
        Amode::Db => "db",
    }
}

fn offset_text(o: &Offset) -> String {
    match *o {
        Offset::Imm(i) => imm(i as i64),
        Offset::Reg { rm, shift, amount, add } => {
            let sign = if add { "" } else { "-" };
            match (shift, amount) {
                (Shift::Lsl, 0) => format!("{sign}{}", r(rm)),
                (Shift::Rrx, _) => format!("{sign}{}, rrx", r(rm)),
                _ => format!("{sign}{}, {} #{amount}", r(rm), shift_name(shift)),
            }
        }
    }
}

fn address(rn: Reg, o: &Offset, index: bool, wback: bool) -> String {
    let zero = matches!(o, Offset::Imm(0));
    if index {
        let bang = if wback { "!" } else { "" };
        if zero {
            format!("[{}]{bang}", r(rn))
        } else {
            format!("[{}, {}]{bang}", r(rn), offset_text(o))
        }
    } else {
        format!("[{}], {}", r(rn), offset_text(o))
    }
}

fn psr_mask(psr: Psr, mask: u8) -> String {
    let base = match psr {
        Psr::Cpsr => "CPSR",
        Psr::Spsr => "SPSR",
    };
    // The application-level masks (CPSR, `c` and `x` clear) are APSR's.
    if psr == Psr::Cpsr && mask & 3 == 0 && mask != 0 {
        return match mask {
            8 => "APSR_nzcvq",
            4 => "APSR_g",
            _ => "APSR_nzcvqg",
        }
        .into();
    }
    let mut s = String::from(base);
    if mask == 0 {
        return s;
    }
    s.push('_');
    for (bit, c) in [(3, 'f'), (2, 's'), (1, 'x'), (0, 'c')] {
        if mask & (1 << bit) != 0 {
            s.push(c);
        }
    }
    s
}

/// The Banked register an MRS/MSR (Banked register) names (B9.2.3).
pub fn banked_name(sysm: u8) -> Option<&'static str> {
    let r = sysm >> 5 & 1;
    let m = sysm & 31;
    Some(match (r, m) {
        (0, 0..=6) => ["r8_usr", "r9_usr", "r10_usr", "r11_usr", "r12_usr", "sp_usr", "lr_usr"][m as usize],
        (0, 8..=14) => ["r8_fiq", "r9_fiq", "r10_fiq", "r11_fiq", "r12_fiq", "sp_fiq", "lr_fiq"][m as usize - 8],
        (0, 16) => "lr_irq",
        (0, 17) => "sp_irq",
        (0, 18) => "lr_svc",
        (0, 19) => "sp_svc",
        (0, 20) => "lr_abt",
        (0, 21) => "sp_abt",
        (0, 22) => "lr_und",
        (0, 23) => "sp_und",
        (0, 28) => "lr_mon",
        (0, 29) => "sp_mon",
        (0, 30) => "elr_hyp",
        (0, 31) => "sp_hyp",
        (1, 14) => "SPSR_fiq",
        (1, 16) => "SPSR_irq",
        (1, 18) => "SPSR_svc",
        (1, 20) => "SPSR_abt",
        (1, 22) => "SPSR_und",
        (1, 28) => "SPSR_mon",
        (1, 30) => "SPSR_hyp",
        _ => return None,
    })
}

fn barrier_option(o: u8) -> String {
    match o {
        15 => "sy".into(),
        14 => "st".into(),
        11 => "ish".into(),
        10 => "ishst".into(),
        7 => "nsh".into(),
        6 => "nshst".into(),
        3 => "osh".into(),
        2 => "oshst".into(),
        _ => format!("#{o:#x}"),
    }
}

fn dp_name(op: DpOp) -> &'static str {
    match op {
        DpOp::And => "and",
        DpOp::Eor => "eor",
        DpOp::Sub => "sub",
        DpOp::Rsb => "rsb",
        DpOp::Add => "add",
        DpOp::Adc => "adc",
        DpOp::Sbc => "sbc",
        DpOp::Rsc => "rsc",
        DpOp::Tst => "tst",
        DpOp::Teq => "teq",
        DpOp::Cmp => "cmp",
        DpOp::Cmn => "cmn",
        DpOp::Orr => "orr",
        DpOp::Mov => "mov",
        DpOp::Bic => "bic",
        DpOp::Mvn => "mvn",
        DpOp::Orn => "orn",
    }
}

fn xy(n_top: bool, m_top: bool) -> String {
    format!("{}{}", if n_top { "t" } else { "b" }, if m_top { "t" } else { "b" })
}

/// The mnemonic and the operand text, separately.
pub fn parts(i: &Inst) -> (String, String) {
    let c = if i.cond.is_always() { "" } else { i.cond.name() };
    let m = |base: &str| format!("{base}{c}");
    let ms = |base: &str, s: bool| format!("{base}{}{c}", if s { "s" } else { "" });
    let r3 = |a: &Reg, b: &Reg, d: &Reg| format!("{}, {}, {}", r(*a), r(*b), r(*d));
    let r4 = |a: &Reg, b: &Reg, d: &Reg, e: &Reg| format!("{}, {}, {}, {}", r(*a), r(*b), r(*d), r(*e));
    match &i.op {
        Op::Dp { op, s, rd, rn, src } => {
            let s = *s && !op.is_test();
            // An ARM modified immediate as LLVM prints it (MOV to the PC
            // unsigned).
            let src_text = match src {
                Operand::Imm { .. } if i.set == InstrSet::Arm => arm_mod_imm(i.raw, *op == DpOp::Mov && rd.is_pc()),
                _ => operand(src),
            };
            match *op {
                // The shifts are MOV of a shifted register, printed as LSL..RRX.
                DpOp::Mov => match *src {
                    Operand::RegImm { rm, shift: Shift::Lsl, amount: 0 } => (ms("mov", s), format!("{}, {}", r(*rd), r(rm))),
                    Operand::RegImm { rm, shift: Shift::Rrx, .. } => (ms("rrx", s), format!("{}, {}", r(*rd), r(rm))),
                    Operand::RegImm { rm, shift, amount } => {
                        (ms(shift_name(shift), s), format!("{}, {}, #{amount}", r(*rd), r(rm)))
                    }
                    Operand::RegReg { rm, shift, rs } => (ms(shift_name(shift), s), r3(rd, &rm, &rs)),
                    Operand::Imm { .. } => (ms("mov", s), format!("{}, {src_text}", r(*rd))),
                },
                DpOp::Mvn => (ms("mvn", s), format!("{}, {src_text}", r(*rd))),
                o if o.is_test() => (m(dp_name(o)), format!("{}, {src_text}", r(*rn))),
                o => (ms(dp_name(o), s), format!("{}, {}, {src_text}", r(*rd), r(*rn))),
            }
        }
        Op::Adr { rd, imm: v } => (m("adr"), format!("{}, {}", r(*rd), imm(*v as i64))),
        Op::Movw { rd, imm: v } => (m("movw"), format!("{}, #{v}", r(*rd))),
        Op::Movt { rd, imm: v } => (m("movt"), format!("{}, #{v}", r(*rd))),
        Op::Mul { s, rd, rn, rm } => (ms("mul", *s), r3(rd, rn, rm)),
        Op::Mla { s, sub, rd, rn, rm, ra } => (ms(if *sub { "mls" } else { "mla" }, *s), r4(rd, rn, rm, ra)),
        Op::MulLong { kind, s, rdlo, rdhi, rn, rm } => {
            let n = match kind {
                MulLong::Umull => "umull",
                MulLong::Umlal => "umlal",
                MulLong::Smull => "smull",
                MulLong::Smlal => "smlal",
                MulLong::Umaal => "umaal",
            };
            (ms(n, *s), r4(rdlo, rdhi, rn, rm))
        }
        Op::Smulxy { rd, rn, rm, ra, n_top, m_top } => match ra {
            None => (m(&format!("smul{}", xy(*n_top, *m_top))), r3(rd, rn, rm)),
            Some(a) => (m(&format!("smla{}", xy(*n_top, *m_top))), r4(rd, rn, rm, a)),
        },
        Op::Smulwy { rd, rn, rm, ra, m_top } => {
            let y = if *m_top { "t" } else { "b" };
            match ra {
                None => (m(&format!("smulw{y}")), r3(rd, rn, rm)),
                Some(a) => (m(&format!("smlaw{y}")), r4(rd, rn, rm, a)),
            }
        }
        Op::Smlalxy { rdlo, rdhi, rn, rm, n_top, m_top } => (m(&format!("smlal{}", xy(*n_top, *m_top))), r4(rdlo, rdhi, rn, rm)),
        Op::Smlad { rd, rn, rm, ra, sub, swap } => {
            let x = if *swap { "x" } else { "" };
            match ra {
                None => (m(&format!("{}{x}", if *sub { "smusd" } else { "smuad" })), r3(rd, rn, rm)),
                Some(a) => (m(&format!("{}{x}", if *sub { "smlsd" } else { "smlad" })), r4(rd, rn, rm, a)),
            }
        }
        Op::Smlald { rdlo, rdhi, rn, rm, sub, swap } => {
            let x = if *swap { "x" } else { "" };
            (m(&format!("{}{x}", if *sub { "smlsld" } else { "smlald" })), r4(rdlo, rdhi, rn, rm))
        }
        Op::Smmul { rd, rn, rm, ra, sub, round } => {
            let rr = if *round { "r" } else { "" };
            match ra {
                None => (m(&format!("smmul{rr}")), r3(rd, rn, rm)),
                Some(a) => (m(&format!("{}{rr}", if *sub { "smmls" } else { "smmla" })), r4(rd, rn, rm, a)),
            }
        }
        Op::Div { signed, rd, rn, rm } => (m(if *signed { "sdiv" } else { "udiv" }), r3(rd, rn, rm)),
        Op::Qadd { sub, double, rd, rm, rn } => {
            let n = match (*double, *sub) {
                (false, false) => "qadd",
                (false, true) => "qsub",
                (true, false) => "qdadd",
                (true, true) => "qdsub",
            };
            (m(n), r3(rd, rm, rn))
        }
        Op::Sat { unsigned, rd, rn, sat, shift, amount } => {
            let sh = match (shift, amount) {
                (Shift::Lsl, 0) => String::new(),
                _ => format!(", {} #{amount}", shift_name(*shift)),
            };
            (m(if *unsigned { "usat" } else { "ssat" }), format!("{}, #{sat}, {}{sh}", r(*rd), r(*rn)))
        }
        Op::Sat16 { unsigned, rd, rn, sat } => (m(if *unsigned { "usat16" } else { "ssat16" }), format!("{}, #{sat}, {}", r(*rd), r(*rn))),
        Op::Parallel { kind, op, rd, rn, rm } => {
            let k = match kind {
                ParKind::S => "s",
                ParKind::Q => "q",
                ParKind::Sh => "sh",
                ParKind::U => "u",
                ParKind::Uq => "uq",
                ParKind::Uh => "uh",
            };
            let o = match op {
                ParOp::Add16 => "add16",
                ParOp::Asx => "asx",
                ParOp::Sax => "sax",
                ParOp::Sub16 => "sub16",
                ParOp::Add8 => "add8",
                ParOp::Sub8 => "sub8",
            };
            (m(&format!("{k}{o}")), r3(rd, rn, rm))
        }
        Op::Sel { rd, rn, rm } => (m("sel"), r3(rd, rn, rm)),
        Op::Usad8 { rd, rn, rm, ra } => match ra {
            None => (m("usad8"), r3(rd, rn, rm)),
            Some(a) => (m("usada8"), r4(rd, rn, rm, a)),
        },
        Op::Pkh { tb, rd, rn, rm, amount } => {
            let sh = if *amount == 0 {
                String::new()
            } else {
                format!(", {} #{amount}", if *tb { "asr" } else { "lsl" })
            };
            (m(if *tb { "pkhtb" } else { "pkhbt" }), format!("{}{sh}", r3(rd, rn, rm)))
        }
        Op::Extend { kind, rd, rn, rm, rotation } => {
            let (base, acc) = match kind {
                ExtKind::Sxtb => ("sxtb", "sxtab"),
                ExtKind::Sxth => ("sxth", "sxtah"),
                ExtKind::Sxtb16 => ("sxtb16", "sxtab16"),
                ExtKind::Uxtb => ("uxtb", "uxtab"),
                ExtKind::Uxth => ("uxth", "uxtah"),
                ExtKind::Uxtb16 => ("uxtb16", "uxtab16"),
            };
            let rot = if *rotation == 0 { String::new() } else { format!(", ror #{rotation}") };
            match rn {
                None => (m(base), format!("{}, {}{rot}", r(*rd), r(*rm))),
                Some(n) => (m(acc), format!("{}{rot}", r3(rd, n, rm))),
            }
        }
        Op::Rev { kind, rd, rm } => {
            let n = match kind {
                RevKind::Rev => "rev",
                RevKind::Rev16 => "rev16",
                RevKind::Revsh => "revsh",
                RevKind::Rbit => "rbit",
            };
            (m(n), format!("{}, {}", r(*rd), r(*rm)))
        }
        Op::Clz { rd, rm } => (m("clz"), format!("{}, {}", r(*rd), r(*rm))),
        Op::Bfi { rd, rn, lsb, msb } => {
            let w = (*msb as i32) - (*lsb as i32) + 1;
            match rn {
                None => (m("bfc"), format!("{}, #{lsb}, #{w}", r(*rd))),
                Some(n) => (m("bfi"), format!("{}, {}, #{lsb}, #{w}", r(*rd), r(*n))),
            }
        }
        Op::Bfx { signed, rd, rn, lsb, width } => {
            (m(if *signed { "sbfx" } else { "ubfx" }), format!("{}, {}, #{lsb}, #{width}", r(*rd), r(*rn)))
        }
        Op::B { imm: v } => (m("b"), imm(*v as i64)),
        Op::Bl { imm: v, switch } => (m(if *switch { "blx" } else { "bl" }), imm(*v as i64)),
        Op::Bx { rm } => (m("bx"), r(*rm).into()),
        Op::BlxReg { rm } => (m("blx"), r(*rm).into()),
        Op::Bxj { rm } => (m("bxj"), r(*rm).into()),
        Op::Cbz { nonzero, rn, imm: v } => (m(if *nonzero { "cbnz" } else { "cbz" }), format!("{}, #{v}", r(*rn))),
        Op::Tb { half: true, rn, rm } => (m("tbh"), format!("[{}, {}, lsl #1]", r(*rn), r(*rm))),
        Op::Tb { half: false, rn, rm } => (m("tbb"), format!("[{}, {}]", r(*rn), r(*rm))),
        Op::Ldst { load, size, signed, user, rt, rn, offset, index, wback } => {
            let mut n = String::from(if *load { "ldr" } else { "str" });
            if *signed {
                n.push('s');
            }
            match size {
                Size::B => n.push('b'),
                Size::H => n.push('h'),
                _ => {}
            }
            if *user {
                n.push('t');
            }
            // An unprivileged access's writeback is implied: no `!`.
            let a = address(*rn, offset, *index, *wback && !*user);
            (m(&n), format!("{}, {a}", r(*rt)))
        }
        Op::Ldrd { load, rt, rt2, rn, offset, index, wback } => {
            (m(if *load { "ldrd" } else { "strd" }), format!("{}, {}, {}", r(*rt), r(*rt2), address(*rn, offset, *index, *wback)))
        }
        Op::Ldm { load, mode, rn, regs, wback, user } => {
            let n = format!("{}{}", if *load { "ldm" } else { "stm" }, if *mode == Amode::Ia { "" } else { amode(*mode) });
            (m(&n), format!("{}{}, {}{}", r(*rn), if *wback { "!" } else { "" }, reglist(*regs), if *user { " ^" } else { "" }))
        }
        Op::Ldrex { size, rt, rt2, rn, imm: v } | Op::Strex { size, rt, rt2, rn, imm: v, .. } => {
            let load = matches!(i.op, Op::Ldrex { .. });
            let sfx = match size {
                Size::B => "b",
                Size::H => "h",
                Size::W => "",
                Size::D => "d",
            };
            let addr = if *v == 0 { format!("[{}]", r(*rn)) } else { format!("[{}, #{v}]", r(*rn)) };
            let mut ops = String::new();
            if let Op::Strex { rd, .. } = &i.op {
                ops = format!("{}, ", r(*rd));
            }
            ops += r(*rt);
            if *size == Size::D {
                ops += ", ";
                ops += r(*rt2);
            }
            (m(&format!("{}{sfx}", if load { "ldrex" } else { "strex" })), format!("{ops}, {addr}"))
        }
        Op::Clrex => (m("clrex"), String::new()),
        Op::Swp { byte, rt, rt2, rn } => (m(if *byte { "swpb" } else { "swp" }), format!("{}, {}, [{}]", r(*rt), r(*rt2), r(*rn))),
        Op::Pld { write, instr, rn, offset } => {
            let n = if *instr {
                "pli"
            } else if *write {
                "pldw"
            } else {
                "pld"
            };
            (m(n), address(*rn, offset, true, false))
        }
        Op::Mrs { rd, psr } => (m("mrs"), format!("{}, {}", r(*rd), if *psr == Psr::Spsr { "spsr" } else { "apsr" })),
        Op::Msr { psr, mask, src } => {
            let s = match src {
                MsrSrc::Imm(_) if i.set == InstrSet::Arm => arm_mod_imm(i.raw, true),
                MsrSrc::Imm(v) => format!("#{v}"),
                MsrSrc::Reg(x) => r(*x).into(),
            };
            (m("msr"), format!("{}, {s}", psr_mask(*psr, *mask)))
        }
        Op::MrsBanked { rd, sysm } => (m("mrs"), format!("{}, {}", r(*rd), banked_name(*sysm).unwrap_or("?"))),
        Op::MsrBanked { rn, sysm } => (m("msr"), format!("{}, {}", banked_name(*sysm).unwrap_or("?"), r(*rn))),
        Op::Cps { imod, a, i: ii, f, mode } => {
            let mut flags = String::new();
            for (on, ch) in [(*a, 'a'), (*ii, 'i'), (*f, 'f')] {
                if on {
                    flags.push(ch);
                }
            }
            match (imod, mode) {
                (2 | 3, md) => {
                    let n = if *imod == 2 { "cpsie" } else { "cpsid" };
                    match md {
                        Some(md) => (n.into(), format!("{flags}, #{md}")),
                        None => (n.into(), flags),
                    }
                }
                (_, Some(md)) => ("cps".into(), format!("#{md}")),
                _ => ("cps".into(), String::new()),
            }
        }
        Op::Setend { big } => ("setend".into(), if *big { "be" } else { "le" }.into()),
        Op::Srs { mode, amode: a, wback } => (m(&format!("srs{}", amode(*a))), format!("sp{}, #{mode}", if *wback { "!" } else { "" })),
        Op::Rfe { rn, amode: a, wback } => (m(&format!("rfe{}", amode(*a))), format!("{}{}", r(*rn), if *wback { "!" } else { "" })),
        Op::Svc { imm: v } => (m("svc"), format!("#{v}")),
        Op::Smc { imm: v } => (m("smc"), format!("#{v}")),
        Op::Hvc { imm: v } => ("hvc".into(), format!("#{v}")),
        Op::Eret => (m("eret"), String::new()),
        Op::Bkpt { imm: v } => ("bkpt".into(), format!("#{v}")),
        Op::Udf { imm: v } => ("udf".into(), format!("#{v}")),
        Op::Hint(h) => match h {
            Hint::Nop => (m("nop"), String::new()),
            Hint::Yield => (m("yield"), String::new()),
            Hint::Wfe => (m("wfe"), String::new()),
            Hint::Wfi => (m("wfi"), String::new()),
            Hint::Sev => (m("sev"), String::new()),
            Hint::Csdb => (m("csdb"), String::new()),
            Hint::Dbg(o) => (m("dbg"), format!("#{o}")),
        },
        Op::Barrier { kind, option } => match kind {
            Barrier::Dmb => (m("dmb"), barrier_option(*option)),
            Barrier::Dsb => (m("dsb"), barrier_option(*option)),
            Barrier::Isb => (m("isb"), if *option == 15 { "sy".into() } else { format!("#{option:#x}") }),
        },
        Op::It { firstcond, mask } => {
            // After the first, T where the mask bit equals firstcond<0>, E otherwise.
            let m4 = *mask & 15;
            let tz = m4.trailing_zeros();
            let mut s = String::new();
            for k in (tz + 1..4).rev() {
                s.push(if (m4 >> k) & 1 == firstcond & 1 { 't' } else { 'e' });
            }
            let fc = if *firstcond >= 14 { "al" } else { Cond(*firstcond).name() };
            (format!("it{s}"), fc.into())
        }
        Op::Enterx { leave } => ((if *leave { "leavex" } else { "enterx" }).into(), String::new()),
        Op::Mcr { read, two, coproc, opc1, rt, crn, crm, opc2 } => {
            let n = format!("{}{}", if *read { "mrc" } else { "mcr" }, if *two { "2" } else { "" });
            let t = if *read && rt.is_pc() { "apsr_nzcv" } else { r(*rt) };
            (m(&n), format!("p{coproc}, #{opc1}, {t}, c{crn}, c{crm}, #{opc2}"))
        }
        Op::Mcrr { read, two, coproc, opc1, rt, rt2, crm } => {
            let n = format!("{}{}", if *read { "mrrc" } else { "mcrr" }, if *two { "2" } else { "" });
            (m(&n), format!("p{coproc}, #{opc1}, {}, {}, c{crm}", r(*rt), r(*rt2)))
        }
        Op::Cdp { two, coproc, opc1, crd, crn, crm, opc2 } => {
            (m(&format!("cdp{}", if *two { "2" } else { "" })), format!("p{coproc}, #{opc1}, c{crd}, c{crn}, c{crm}, #{opc2}"))
        }
        Op::Ldc { load, two, long, coproc, crd, rn, imm: v, index, wback, option } => {
            let n = format!("{}{}{}", if *load { "ldc" } else { "stc" }, if *two { "2" } else { "" }, if *long { "l" } else { "" });
            let a = match option {
                Some(o) => format!("[{}], {{{o}}}", r(*rn)),
                None => address(*rn, &Offset::Imm(*v), *index, *wback),
            };
            (m(&n), format!("p{coproc}, c{crd}, {a}"))
        }
        Op::Fp(f) => {
            let t = fp::fmt(f);
            let (a, b) = t.split_once(' ').unwrap_or((&t, ""));
            // The condition goes after the mnemonic, before the data type.
            let a = match a.split_once('.') {
                Some((mn, dt)) => format!("{mn}{c}.{dt}"),
                None => format!("{a}{c}"),
            };
            (a, b.trim().to_string())
        }
        Op::Undefined => ("<undefined>".into(), String::new()),
    }
}

/// The instruction as one line of text.
pub fn disasm(i: &Inst) -> String {
    let (m, o) = parts(i);
    let mut s = m;
    if !o.is_empty() {
        let _ = write!(s, " {o}");
    }
    s
}
