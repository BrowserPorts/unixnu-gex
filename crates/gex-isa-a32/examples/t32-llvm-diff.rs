//! Differential test of the Thumb decoder against LLVM's disassembler.
//!
//! Sweeps the 16-bit space, every first halfword of the 32-bit space with
//! structured and random second halfwords, a million random 32-bit
//! instructions, and IT-block cases; runs `llvm-mc --disassemble` on them
//! and compares valid/UNDEFINED, the mnemonic, the operands and the
//! UNPREDICTABLE flag. Prints the disagreements grouped by class.
//!
//! Usage: t32-llvm-diff [--base] [--quick] [--work DIR]

use gex_isa_a32::*;
use std::collections::BTreeMap;
use std::io::Write as _;
use std::process::Command;

const LLVM_MC: &str = "/opt/homebrew/opt/llvm/bin/llvm-mc";

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn h(&mut self) -> u32 {
        (self.next() & 0xffff) as u32
    }
}

/// One test: an optional IT prefix (and the ITSTATE the instruction sees),
/// the instruction, and how many filler NOPs complete the block.
#[derive(Clone)]
struct Case {
    prefix: Option<u16>,
    it: ItState,
    hw1: u16,
    hw2: u16,
    fill: usize,
    /// For IT encodings: compare the IT line only.
    is_it: bool,
}

/// Whether the encoding is in the Floating-point/Advanced SIMD space that
/// `fp.rs` decodes (excluded while it is a stub).
fn fp_space(hw1: u16, hw2: u16) -> bool {
    if !thumb_is_32(hw1) {
        return false;
    }
    let (h1, h2) = (hw1 as u32, hw2 as u32);
    let op1 = (h1 >> 11) & 3;
    let op2 = (h1 >> 4) & 0x7f;
    let coproc_space = (op1 == 1 || op1 == 3) && op2 & 0x40 != 0;
    if coproc_space {
        let cop1 = (h1 >> 4) & 63;
        if cop1 & 0b110000 == 0b110000 {
            return true;
        }
        let cp = (h2 >> 8) & 15;
        if cp & 0b1110 == 0b1010 && cop1 & 0b111110 != 0 {
            return true;
        }
    }
    op1 == 3 && op2 & 0b1110001 == 0b0010000
}

fn is_it_insn(hw: u16) -> bool {
    hw & 0xff00 == 0xbf00 && hw & 0xf != 0
}

fn bytes(hw1: u16, hw2: u16) -> String {
    if thumb_is_32(hw1) {
        format!("[0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x}]", hw1 & 0xff, hw1 >> 8, hw2 & 0xff, hw2 >> 8)
    } else {
        format!("[0x{:02x} 0x{:02x}]", hw1 & 0xff, hw1 >> 8)
    }
}

#[derive(Default, Clone)]
struct Llvm {
    valid: bool,
    soft: bool,
    text: String,
}

/// Runs llvm-mc on `lines`; returns per-line results.
fn run_llvm(lines: &[String], work: &str, tag: &str, attrs: &[&str]) -> Vec<Llvm> {
    let path = format!("{work}/in-{tag}.txt");
    {
        let mut f = std::fs::File::create(&path).unwrap();
        for l in lines {
            writeln!(f, "{l}").unwrap();
        }
    }
    let mut cmd = Command::new(LLVM_MC);
    cmd.args(["--disassemble", "--show-encoding", "-triple=thumbv7a"]);
    cmd.args(attrs);
    cmd.arg(&path);
    let out = cmd.output().expect("llvm-mc");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let mut res = vec![Llvm { valid: true, ..Default::default() }; lines.len()];
    for l in stderr.lines() {
        if !l.contains(": warning: ") {
            continue;
        }
        let mut it = l.splitn(4, ':');
        let _ = it.next();
        let ln: usize = match it.next().and_then(|x| x.parse().ok()) {
            Some(n) => n,
            None => continue,
        };
        if l.contains("invalid instruction encoding") {
            res[ln - 1].valid = false;
        } else if l.contains("potentially undefined") {
            res[ln - 1].soft = true;
        } else {
            eprintln!("unknown warning: {l}");
        }
    }
    let n_out = stdout.lines().filter(|l| l.starts_with('\t') && l.contains("@ encoding")).count();
    assert_eq!(n_out, res.iter().filter(|r| r.valid).count(), "llvm output count mismatch in {path}");
    let mut outs = stdout.lines().filter(|l| l.starts_with('\t') && l.contains("@ encoding"));
    for (i, r) in res.iter_mut().enumerate() {
        if r.valid {
            let l = outs.next().unwrap_or_else(|| panic!("llvm output ran out at line {}", i + 1));
            let t = l.split("@ encoding").next().unwrap().trim();
            // `--show-encoding` re-encodes the MCInst, so only the size is
            // checked against the input (an UNPREDICTABLE form can come back
            // in its canonical encoding).
            let enc = l.split("@ encoding: [").nth(1).unwrap().trim_end_matches(']');
            let inp = lines[i].trim_matches(|c| c == '[' || c == ']');
            assert_eq!(enc.split(',').count(), inp.split(' ').count(), "desync at line {}", i + 1);
            r.text = t.to_string();
        }
    }
    res
}

/// Splits `mn\toperands` and normalizes LLVM's spelling.
fn norm_llvm(t: &str) -> (String, Vec<String>) {
    let (mn, ops) = t.split_once(['\t', ' ']).unwrap_or((t, ""));
    let mut mn = mn.trim().to_string();
    for q in [".w", ".n"] {
        if let Some(x) = mn.strip_suffix(q) {
            mn = x.to_string();
        }
    }
    (mn, split_ops(ops))
}

/// Splits operands at top-level commas (not inside `[]` or `{}`).
fn split_ops(ops: &str) -> Vec<String> {
    let mut v = Vec::new();
    let mut depth = 0;
    let mut cur = String::new();
    for c in ops.chars() {
        match c {
            '[' | '{' => depth += 1,
            ']' | '}' => depth -= 1,
            _ => {}
        }
        if c == ',' && depth == 0 {
            v.push(cur.trim().to_string());
            cur.clear();
        } else {
            cur.push(c);
        }
    }
    if !cur.trim().is_empty() {
        v.push(cur.trim().to_string());
    }
    v.into_iter().map(|s| norm_op(&s)).collect()
}

/// Spelling-only normalization of one operand.
fn norm_op(s: &str) -> String {
    let mut s = s.to_lowercase().replace(" ,", ",");
    // Immediates: decimal, as unsigned 32-bit; #-0 is #0.
    if let Some(x) = s.strip_prefix('#') {
        if let Some(v) = parse_int(x) {
            return format!("#{}", v as u32 as i64);
        }
    }
    s = s.replace("#-0]", "#0]").replace("#-0", "#0");
    // Inside an address, `[rn, #0]` is `[rn]`.
    s = s.replace(", #0]", "]");
    s
}

fn parse_int(x: &str) -> Option<i64> {
    let (neg, x) = match x.strip_prefix('-') {
        Some(y) => (true, y),
        None => (false, x),
    };
    let v = if let Some(h) = x.strip_prefix("0x") { i64::from_str_radix(h, 16).ok()? } else { x.parse::<i64>().ok()? };
    Some(if neg { -v } else { v })
}

/// Our text, rewritten into LLVM's preferred aliases where the Arm ARM
/// spelling differs only in syntax.
fn ours_text(i: &Inst) -> (String, Vec<String>) {
    let (mn, ops) = fmt::parts(i);
    let mut mn = mn;
    let mut ops = split_ops(&ops);
    let c = if i.cond.is_always() { "" } else { i.cond.name() };
    match &i.op {
        // PUSH/POP for SP! LDM/STM of LLVM's choice.
        Op::Ldm { load, mode, rn, wback: true, user: false, regs } if rn.is_sp() => {
            if (*load && *mode == Amode::Ia) || (!*load && *mode == Amode::Db) {
                let _ = regs;
                mn = format!("{}{c}", if *load { "pop" } else { "push" });
                ops = vec![ops[1].clone()];
            }
        }
        // MOV of a register to itself shift-free is printed as MOV.
        _ => {}
    }
    (mn, ops)
}

/// Compares; returns None when equal, or a class string.
fn compare(i: &Inst, l: &Llvm) -> Option<String> {
    let (lm, lo) = norm_llvm(&l.text);
    let (om, oo) = ours_text(i);
    if lm == om && lo == oo {
        return None;
    }
    // Two-operand forms: `op rd, rm` for `op rd, rd, rm`.
    if lm == om && oo.len() == lo.len() + 1 && oo[0] == oo[1] && oo[1..] == lo[..] {
        return None;
    }
    if lm == om && oo.len() == lo.len() + 1 && oo[0] == oo[1] && oo[0] == lo[0] && oo[2..] == lo[1..] {
        return None;
    }
    if alias_equal(i, &om, &oo, &lm, &lo) {
        return None;
    }
    Some(format!("{om} vs {lm}"))
}

/// Known spelling-only differences, each checked narrowly.
fn alias_equal(i: &Inst, om: &str, oo: &[String], lm: &str, lo: &[String]) -> bool {
    let c = if i.cond.is_always() { "" } else { i.cond.name() };
    match &i.op {
        // LLVM prints the register-to-register MOV forms and shifts by 0 as
        // MOV; LSL #0 never reaches here (it is MOV).
        Op::Hint(Hint::Nop) => {
            // Unallocated hints: LLVM prints `hint #n`.
            lm == format!("hint{c}") || lm == format!("nop{c}")
        }
        // ADDW/SUBW: LLVM's name for the plain 12-bit immediate forms.
        Op::Dp { op: DpOp::Add | DpOp::Sub, s: false, src: Operand::Imm { .. }, .. } if lm == format!("{}w{c}", &om[..3]) => {
            oo == lo
        }
        // LLVM's aliases of UDF #249 and #254.
        Op::Udf { imm: 249 } => lm == "__brkdiv0",
        Op::Udf { imm: 254 } => lm == "trap",
        // ADR with a zero subtracted offset: LLVM prints SUBW rd, pc, #0.
        Op::Adr { imm: 0, .. } if i.raw & 0x0080_0000 != 0 => lm == format!("subw{c}") && lo.len() == 3 && lo[1] == "pc" && lo[2] == "#0" && lo[0] == oo[0],
        Op::Msr { .. } | Op::Mrs { .. } => {
            let f = |v: &[String]| v.iter().map(|s| s.replace("apsr_nzcvqg", "cpsr_fs").replace("apsr_nzcvq", "cpsr_f").replace("apsr_g", "cpsr_s").replace("apsr", "cpsr")).collect::<Vec<_>>();
            om == lm && f(oo) == f(lo)
        }
        _ => false,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let base = args.iter().any(|a| a == "--base");
    let quick = args.iter().any(|a| a == "--quick");
    let no_fp = args.iter().any(|a| a == "--no-fp");
    let work = args.iter().position(|a| a == "--work").map(|p| args[p + 1].clone()).unwrap_or_else(|| concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/a32-llvm-diff/t32").into());
    std::fs::create_dir_all(&work).unwrap();
    let feats = if base { Features::BASE } else { Features::ALL };
    let attrs: Vec<&str> = if base {
        vec!["-mcpu=cortex-a15", "-mattr=-hwdiv,-hwdiv-arm,-virtualization,-trustzone,-mp"]
    } else {
        vec!["-mcpu=cortex-a15", "-mattr=+virtualization,+trustzone,+mp,+hwdiv"]
    };
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut cases: Vec<(String, Case)> = Vec::new();
    let plain = |hw1: u16, hw2: u16| Case { prefix: None, it: ItState(0), hw1, hw2, fill: 0, is_it: false };

    // 1. Every 16-bit halfword outside an IT block.
    for h in 0..=0xffffu32 {
        let h = h as u16;
        if thumb_is_32(h) || is_it_insn(h) {
            continue;
        }
        cases.push(("16".into(), plain(h, 0)));
    }
    // 2. Every first halfword of the 32-bit space with structured second
    // halfwords: each 4-bit and 6-bit field position swept, the rest random.
    let per = if quick { 24 } else { 1 };
    for h1 in 0xe800u32..=0xffff {
        let h1 = h1 as u16;
        if !thumb_is_32(h1) {
            continue;
        }
        let mut hw2s = vec![0u16, 0xffff, 0xf000, 0x0f00, 0x00f0, 0x000f, 0x8000];
        for k in (0..64u32).step_by(per) {
            hw2s.push(((rng.h() & !0x0fc0) | k << 6) as u16);
        }
        for k in (0..16u32).step_by(per.min(4)) {
            hw2s.push(((rng.h() & !0x00f0) | k << 4) as u16);
            hw2s.push(((rng.h() & !0xf000) | k << 12) as u16);
            hw2s.push(((rng.h() & !0x0f00) | k << 8) as u16);
            hw2s.push(((rng.h() & !0x7000) | (k & 7) << 12) as u16);
        }
        for _ in 0..(if quick { 4 } else { 60 }) {
            hw2s.push(rng.h() as u16);
        }
        for hw2 in hw2s {
            cases.push(("32s".into(), plain(h1, hw2)));
        }
    }
    // 3. Random 32-bit instructions.
    let nrand = if quick { 50_000 } else { 1_000_000 };
    for _ in 0..nrand {
        let mut h1 = rng.h() as u16;
        h1 |= 0xe000;
        if h1 & 0x1800 == 0 {
            h1 |= 0x0800;
        }
        cases.push(("32r".into(), plain(h1, rng.h() as u16)));
    }
    // 4. IT blocks: the instruction last in `it eq`, and first (not last) in
    // `itt ne`; every 16-bit halfword and a sample of 32-bit ones.
    let in_it = |cases: &mut Vec<(String, Case)>, hw1: u16, hw2: u16, tag: &str| {
        cases.push((format!("{tag}-last"), Case { prefix: Some(0xbf08), it: ItState(0x08), hw1, hw2, fill: 0, is_it: false }));
        cases.push((format!("{tag}-first"), Case { prefix: Some(0xbf14), it: ItState(0x14), hw1, hw2, fill: 1, is_it: false }));
    };
    for h in 0..=0xffffu32 {
        let h = h as u16;
        if thumb_is_32(h) || is_it_insn(h) || (quick && h % 7 != 0) {
            continue;
        }
        in_it(&mut cases, h, 0, "it16");
    }
    let n32 = if quick { 20_000 } else { 200_000 };
    for _ in 0..n32 {
        let mut h1 = rng.h() as u16;
        h1 |= 0xe000;
        if h1 & 0x1800 == 0 {
            h1 |= 0x0800;
        }
        in_it(&mut cases, h1, rng.h() as u16, "it32");
    }
    // 4b. The system and miscellaneous control encodings, each with its
    // option/immediate field swept, inside an IT block.
    for (h1, base, mask) in [
        (0xf3bfu16, 0x8f00u16, 0x00ffu16), // misc control: CLREX, DSB, DMB, ISB
        (0xf3af, 0x8000, 0x07ff),          // CPS and hints
        (0xf3de, 0x8f00, 0x00ff),          // SUBS PC, LR / ERET
        (0xf3ef, 0x8000, 0x0f00),          // MRS
        (0xf3ff, 0x8000, 0x0f00),          // MRS SPSR
        (0xf381, 0x8000, 0x0f00),          // MSR
        (0xf391, 0x8000, 0x0f00),          // MSR SPSR
        (0xf3c1, 0x8f00, 0x0000),          // BXJ
        (0xf7f1, 0x8000, 0x0000),          // SMC
        (0xf7e1, 0x8000, 0x0fff),          // HVC
        (0xe82d, 0xc000, 0x001f),          // SRSDB
        (0xe991, 0xc000, 0x0000),          // RFEIA
        (0xf7f1, 0xa000, 0x0fff),          // UDF.W
    ] {
        let mut v = 0u16;
        loop {
            let hw2 = base | v;
            in_it(&mut cases, h1, hw2, "itsys");
            cases.push(("sys".into(), plain(h1, hw2)));
            if v == mask {
                break;
            }
            v = (v.wrapping_sub(mask)) & mask;
        }
    }
    // 5. The IT instructions themselves, outside and inside an IT block.
    for h in 0xbf01u16..=0xbfff {
        if !is_it_insn(h) {
            continue;
        }
        let fill = 4 - (h & 15).trailing_zeros() as usize;
        cases.push(("it-insn".into(), Case { prefix: None, it: ItState(0), hw1: h, hw2: 0, fill, is_it: true }));
        cases.push(("it-in-it".into(), Case { prefix: Some(0xbf08), it: ItState(0x08), hw1: h, hw2: 0, fill, is_it: true }));
    }

    // Build the lines; record the index of each case's instruction line.
    let mut lines = Vec::new();
    let mut at = Vec::new();
    let mut starts = Vec::new();
    for (_, c) in &cases {
        if no_fp && fp_space(c.hw1, c.hw2) {
            at.push(usize::MAX);
            continue;
        }
        starts.push(lines.len());
        if let Some(p) = c.prefix {
            lines.push(bytes(p, 0));
        }
        at.push(lines.len());
        lines.push(bytes(c.hw1, c.hw2));
        for _ in 0..c.fill {
            lines.push(bytes(0xbf00, 0));
        }
    }
    // Chunk on case boundaries (no IT block straddles a chunk): llvm-mc in
    // parallel.
    let chunk = 100_000;
    let mut bounds = vec![0];
    {
        let mut last = 0;
        for &start in &starts {
            if start - last >= chunk && start > *bounds.last().unwrap() {
                bounds.push(start);
                last = start;
            }
        }
    }
    bounds.push(lines.len());
    let mut results: Vec<Llvm> = vec![Llvm::default(); lines.len()];
    let jobs: Vec<(usize, usize)> = bounds.windows(2).map(|w| (w[0], w[1])).collect();
    eprintln!("{} cases, {} lines, {} chunks", cases.len(), lines.len(), jobs.len());
    std::thread::scope(|s| {
        let lines = &lines;
        let attrs = &attrs;
        let work = &work;
        let mut handles = Vec::new();
        for (k, group) in jobs.chunks(jobs.len().div_ceil(4)).enumerate() {
            let group = group.to_vec();
            handles.push(s.spawn(move || {
                let mut out = Vec::new();
                for (j, (a, b)) in group.into_iter().enumerate() {
                    let r = run_llvm(&lines[a..b], work, &format!("{}-{k}-{j}", if base { "base" } else { "all" }), attrs);
                    out.push((a, r));
                }
                out
            }));
        }
        for h in handles {
            for (a, r) in h.join().unwrap() {
                for (i, x) in r.into_iter().enumerate() {
                    results[a + i] = x;
                }
            }
        }
    });

    // Compare.
    #[derive(Default)]
    struct Stat {
        n: usize,
        examples: Vec<String>,
    }
    let mut classes: BTreeMap<String, Stat> = BTreeMap::new();
    let nex: usize = std::env::var("EXAMPLES").ok().and_then(|v| v.parse().ok()).unwrap_or(4);
    let mut add = |k: String, ex: String| {
        let s = classes.entry(k).or_default();
        s.n += 1;
        if s.examples.len() < nex {
            s.examples.push(ex);
        }
    };
    let mut compared = 0usize;
    let mut agree = 0usize;
    let mut unp = [[0usize; 2]; 2];
    let mut per_group: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for ((group, c), &a) in cases.iter().zip(&at) {
        if a == usize::MAX {
            continue;
        }
        let l = &results[a];
        let i = decode_thumb(c.hw1, c.hw2, c.it, &feats);
        compared += 1;
        let g = per_group.entry(group.clone()).or_default();
        g.0 += 1;
        let enc = if thumb_is_32(c.hw1) { format!("{:04x} {:04x}", c.hw1, c.hw2) } else { format!("{:04x}", c.hw1) };
        let ctx = match c.prefix {
            Some(p) => format!("[{p:04x}] {enc}"),
            None => enc.clone(),
        };
        let ours_txt = fmt::disasm(&i);
        let ex = format!("{ctx}: ours `{ours_txt}`{} llvm `{}`{}", i.unpredictable.map(|w| format!(" (UNP: {w})")).unwrap_or_default(), if l.valid { l.text.replace('\t', " ") } else { "<invalid>".into() }, if l.soft { " (soft)" } else { "" });
        let _ = c.is_it;
        match (i.is_undefined(), l.valid) {
            (true, false) => {
                agree += 1;
                g.1 += 1;
                continue;
            }
            (true, true) => {
                add(format!("[{group}] UNDEFINED vs llvm {}", norm_llvm(&l.text).0), ex);
                continue;
            }
            (false, false) => {
                let (m, _) = fmt::parts(&i);
                match i.unpredictable {
                    Some(w) => add(format!("[{}] UNP, llvm invalid: {w}", if group.starts_with("it") { "it" } else { "plain" }), ex),
                    None => add(format!("[{group}] {m} vs llvm invalid"), ex),
                }
                continue;
            }
            (false, true) => {}
        }
        if let Some(k) = compare(&i, l) {
            match i.unpredictable {
                Some(w) => add(format!("[{}] UNP, text differs: {w}", if group.starts_with("it") { "it" } else { "plain" }), ex.clone()),
                None => add(format!("[{group}] text {k}"), ex.clone()),
            }
            continue;
        }
        let u = i.unpredictable.is_some() as usize;
        unp[u][l.soft as usize] += 1;
        if (u == 1) != l.soft {
            let why = i.unpredictable.unwrap_or("-");
            add(format!("[{}] UNP ours={} llvm={}: {}", if group.starts_with("it") { "it" } else { "plain" }, u == 1, l.soft, why), ex);
        } else {
            agree += 1;
            g.1 += 1;
        }
    }
    println!("compared {compared}, full agreement {agree} ({:.3}%)", 100.0 * agree as f64 / compared as f64);
    println!("UNPREDICTABLE flag (valid in both, same text): ours/llvm: no/no {} no/yes {} yes/no {} yes/yes {}", unp[0][0], unp[0][1], unp[1][0], unp[1][1]);
    for (g, (n, a)) in &per_group {
        println!("  group {g}: {n} compared, {a} agree");
    }
    let mut v: Vec<_> = classes.into_iter().collect();
    v.sort_by(|a, b| b.1.n.cmp(&a.1.n));
    for (k, s) in v {
        println!("{:8} {k}", s.n);
        for e in s.examples {
            println!("           {e}");
        }
    }
}
