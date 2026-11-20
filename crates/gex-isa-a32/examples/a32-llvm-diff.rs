//! Differential test of the ARM (A32) decoder against LLVM's disassembler.
//!
//! `cargo run --release --example a32-llvm-diff [random-count]` sweeps every
//! opcode-field combination of the A5 tables (bits 27:20 and 7:4 under three
//! conditions) with varied register fields and immediates, the hint space,
//! and random words, runs `llvm-mc --disassemble` over them in batches, and
//! compares valid against UNDEFINED, the text (mnemonic and operands, LLVM's
//! pure spelling differences normalized) and the UNPREDICTABLE flag against
//! LLVM's "potentially undefined" (SoftFail). The Floating-point and Advanced
//! SIMD spaces (fp.rs) are excluded. Disagreements are grouped in classes,
//! each with a count and examples.

use gex_isa_a32::*;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

const LLVM_MC: &str = "/opt/homebrew/opt/llvm/bin/llvm-mc";
const BATCH: usize = 50_000;
const JOBS: usize = 4;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u32 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        (self.0.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 32) as u32
    }
}

/// The spaces fp.rs decodes (A5.6 coproc 101x, A5.7.1 Advanced SIMD).
fn is_fp_space(w: u32) -> bool {
    let cond = w >> 28;
    if cond == 15 {
        return (w >> 25) & 7 == 0b001 || ((w >> 24) & 15 == 0b0100 && w & (1 << 20) == 0);
    }
    let op1 = (w >> 20) & 0x3f;
    (w >> 26) & 3 == 0b11 && (w >> 9) & 7 == 0b101 && op1 & 0b111110 != 0 && op1 & 0b110000 != 0b110000
}

/// A register field value: random, or one of the special registers, or a
/// copy of another field, so that the n == t, PC and SP rules are hit.
fn nibble(rng: &mut Rng, others: &[u32]) -> u32 {
    match rng.next() % 8 {
        0 => 15,
        1 => 13,
        2 => 14,
        3 => 0,
        4 if !others.is_empty() => others[(rng.next() as usize) % others.len()],
        _ => rng.next() & 15,
    }
}

fn varied(rng: &mut Rng, fixed: u32, fixed_mask: u32) -> u32 {
    let mut w = rng.next();
    // Fill the four register-sized fields, sometimes with special values.
    let mut vals = Vec::new();
    for lo in [16u32, 12, 8, 0] {
        let v = nibble(rng, &vals);
        vals.push(v);
        if rng.next() % 3 != 0 {
            w = (w & !(15 << lo)) | (v << lo);
        }
    }
    // Small immediates now and then.
    if rng.next() % 4 == 0 {
        w &= !0xf80;
    }
    (w & !fixed_mask) | (fixed & fixed_mask)
}

fn words(random: usize, with_fp: bool) -> Vec<u32> {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut out = Vec::new();
    // Every combination of bits 27:20 and 7:4 (the op fields of all the A5
    // tables) under AL, EQ and the unconditional space.
    for cond in [0b1110u32, 0b0000, 0b1111] {
        for hi in 0..256u32 {
            for lo in 0..16u32 {
                let fixed = cond << 28 | hi << 20 | lo << 4;
                for _ in 0..24 {
                    out.push(varied(&mut rng, fixed, 0xfff0_00f0));
                }
            }
        }
    }
    // MSR (immediate) and hints: every op1 and op2, with good and bad
    // (1)/(0) bits.
    for cond in [0b1110u32, 0b0001] {
        for r in 0..2u32 {
            for mask in 0..16u32 {
                for op2 in 0..256u32 {
                    let base = cond << 28 | 0x0320_0000 | r << 22 | mask << 16 | op2;
                    out.push(base | 0xf000);
                    out.push(base | (rng.next() & 0xff00));
                }
            }
        }
    }
    // Miscellaneous (A5.2.12): every op, op1, B and op2 with good fields.
    for op in 0..4u32 {
        for op1 in 0..16u32 {
            for b in 0..2u32 {
                for op2 in 0..8u32 {
                    for m in 0..2u32 {
                        let base = 0xe100_0000 | op << 21 | op1 << 16 | b << 9 | m << 8 | op2 << 4;
                        out.push(base | 0xf000 | (rng.next() & 0xf));
                        out.push(base | (rng.next() & 0xf000f));
                        out.push(base | 0xfff00 | (rng.next() & 0xf));
                    }
                }
            }
        }
    }
    // Coprocessor spaces with every coproc value.
    for cond in [0b1110u32, 0b1111] {
        for op1 in 0..64u32 {
            for cp in 0..16u32 {
                for _ in 0..6 {
                    let fixed = cond << 28 | 0b11 << 26 | op1 << 20 | cp << 8;
                    out.push(varied(&mut rng, fixed, 0xfff0_0f00));
                }
            }
        }
    }
    // Uniform random words.
    for _ in 0..random {
        out.push(rng.next());
    }
    // Random words in the AL and unconditional halves, which hold the
    // rarer encodings.
    for _ in 0..random / 4 {
        out.push(0xe000_0000 | (rng.next() & 0x0fff_ffff));
        out.push(0xf000_0000 | (rng.next() & 0x0fff_ffff));
    }
    if !with_fp {
        out.retain(|w| !is_fp_space(*w));
    }
    out
}

/// LLVM's view of one word: its text, or None if invalid, and SoftFail.
#[derive(Clone)]
struct Llvm {
    text: Option<String>,
    soft: bool,
}

fn run_llvm(dir: &PathBuf, words: &[u32], tag: usize) -> Vec<Llvm> {
    let path = dir.join(format!("llvm-in-{tag}.txt"));
    {
        let mut f = std::io::BufWriter::new(std::fs::File::create(&path).unwrap());
        for w in words {
            let b = w.to_le_bytes();
            writeln!(f, "0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x}", b[0], b[1], b[2], b[3]).unwrap();
        }
    }
    let out = Command::new(LLVM_MC)
        .args([
            "--disassemble",
            "-triple=armv7a",
            "-mcpu=cortex-a15",
            "-mattr=+virtualization,+trustzone,+mp,+hwdiv-arm",
        ])
        .arg(&path)
        .output()
        .expect("llvm-mc");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let mut invalid = vec![false; words.len()];
    let mut soft = vec![false; words.len()];
    for l in stderr.lines() {
        // <file>:<line>:<col>: warning: ...
        let Some(rest) = l.strip_prefix(path.to_str().unwrap()) else { continue };
        let mut it = rest.split(':');
        it.next();
        let Some(line) = it.next().and_then(|x| x.parse::<usize>().ok()) else { continue };
        if l.contains("invalid instruction encoding") {
            invalid[line - 1] = true;
        } else if l.contains("potentially undefined") {
            soft[line - 1] = true;
        }
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut lines = stdout.lines().filter(|l| !l.trim().is_empty());
    let mut res = Vec::with_capacity(words.len());
    for i in 0..words.len() {
        if invalid[i] {
            res.push(Llvm { text: None, soft: false });
        } else {
            let t = lines.next().expect("llvm-mc output out of step").to_string();
            res.push(Llvm { text: Some(t), soft: soft[i] });
        }
    }
    assert!(lines.next().is_none(), "llvm-mc output out of step");
    let _ = std::fs::remove_file(&path);
    res
}

const CONDS: [&str; 15] = ["eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", ""];

/// Spelling-only normalization, applied to both sides.
fn norm(s: &str) -> String {
    let mut t = s.split('@').next().unwrap().trim().replace('\t', " ");
    while t.contains("  ") {
        t = t.replace("  ", " ");
    }
    // A zero offset: `[rn, #0]`, `[rn, #-0]` and `[rn]` are the same
    // address; `#-0` is the U = 0 spelling of 0.
    t = t.replace(", #-0]", "]").replace(", #0]", "]").replace("#-0", "#0");
    // PUSH and POP are LLVM's aliases of STMDB SP! and LDM SP!.
    if let Some(r) = t.strip_prefix("push") {
        if let Some((c, list)) = r.split_once(' ') {
            t = format!("stmdb{c} sp!, {list}");
        }
    } else if let Some(r) = t.strip_prefix("pop") {
        if let Some((c, list)) = r.split_once(' ') {
            t = format!("ldm{c} sp!, {list}");
        }
    }
    // The unallocated hints behave as NOP (A5.2.11): LLVM spells them
    // `hint #n`.
    if let Some(r) = t.strip_prefix("hint") {
        if let Some((c, _)) = r.split_once(' ') {
            if CONDS.contains(&c) {
                t = format!("nop{c}");
            }
        }
    }
    t
}

fn mnemonic(s: &str) -> String {
    s.split(' ').next().unwrap_or("").to_string()
}

/// LLVM's mnemonic without its condition suffix (best effort, for classes).
fn base_mnemonic(s: &str) -> String {
    let m = mnemonic(s);
    for c in &CONDS[..14] {
        if let Some(b) = m.strip_suffix(c) {
            if b.len() >= 2 {
                return b.to_string();
            }
        }
    }
    m
}

/// Our operation's kind, for classes.
fn kind(op: &Op) -> String {
    let d = format!("{op:?}");
    let k: String = d.chars().take_while(|c| c.is_alphanumeric()).collect();
    match op {
        Op::Dp { op, .. } => format!("Dp.{op:?}"),
        Op::Ldst { load, size, user, .. } => format!("Ldst.{}{size:?}{}", if *load { "L" } else { "S" }, if *user { "T" } else { "" }),
        Op::Ldm { load, user, .. } => format!("Ldm.{}{}", if *load { "L" } else { "S" }, if *user { "^" } else { "" }),
        _ => k,
    }
}

#[derive(Default)]
struct Class {
    count: usize,
    examples: Vec<String>,
}

fn main() {
    let random: usize = std::env::args().skip(1).find_map(|s| s.parse().ok()).unwrap_or(1_200_000);
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/a32-llvm-diff");
    std::fs::create_dir_all(&dir).unwrap();
    // `--with-fp` keeps the Floating-point and Advanced SIMD spaces.
    let with_fp = std::env::args().any(|a| a == "--with-fp");
    let words = words(random, with_fp);
    eprintln!("{} words", words.len());

    let chunks: Vec<&[u32]> = words.chunks(BATCH).collect();
    let mut llvm: Vec<Llvm> = Vec::with_capacity(words.len());
    for group in chunks.chunks(JOBS) {
        let results: Vec<Vec<Llvm>> = std::thread::scope(|s| {
            let hs: Vec<_> = group
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    let dir = dir.clone();
                    let tag = (llvm.len() / BATCH) + i;
                    s.spawn(move || run_llvm(&dir, c, tag))
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        for r in results {
            llvm.extend(r);
        }
        eprint!("\r{} / {}", llvm.len(), words.len());
    }
    eprintln!();

    let mut classes: BTreeMap<String, Class> = BTreeMap::new();
    let mut agree = 0usize;
    let mut agree_valid = 0usize;
    let mut agree_undef = 0usize;
    let mut text_agree = 0usize;
    let mut unp_agree = 0usize;
    let mut both_valid = 0usize;
    // Over the encodings we do not flag UNPREDICTABLE: valid/UNDEFINED and
    // text agreement.
    let (mut clean, mut clean_agree) = (0usize, 0usize);
    let mut add = |key: String, ex: String| {
        let c = classes.entry(key).or_default();
        c.count += 1;
        if c.examples.len() < 4 {
            c.examples.push(ex);
        }
    };
    for (w, l) in words.iter().zip(&llvm) {
        let i = decode_arm(*w, &Features::ALL);
        let ours = if i.is_undefined() { None } else { Some(norm(&fmt::disasm(&i))) };
        let theirs = l.text.as_deref().map(norm);
        let reason = i.unpredictable.unwrap_or("");
        let fpk = if is_fp_space(*w) { "[fp] " } else { "" };
        let ex = format!(
            "{w:08x}: ours `{}`{} | llvm `{}`{}",
            ours.as_deref().unwrap_or("UNDEFINED"),
            if reason.is_empty() { String::new() } else { format!(" [UNP: {reason}]") },
            theirs.as_deref().unwrap_or("invalid"),
            if l.soft { " [SoftFail]" } else { "" }
        );
        if i.unpredictable.is_none() {
            clean += 1;
            if ours == theirs {
                clean_agree += 1;
            }
        }
        match (&ours, &theirs) {
            (None, None) => {
                agree += 1;
                agree_undef += 1;
                if i.unpredictable.is_some() {
                    add(format!("info: UNPREDICTABLE row (no instruction), LLVM invalid: {reason}"), ex);
                }
            }
            (Some(_), None) => add(format!("{fpk}valid vs LLVM invalid: {}{}", kind(&i.op), if reason.is_empty() { String::new() } else { format!(" [ours UNP: {reason}]") }), ex),
            (None, Some(t)) => add(
                format!("{fpk}UNDEFINED vs LLVM valid: {}{}", base_mnemonic(t), if i.unpredictable.is_some() { " [ours UNP row]" } else { "" }),
                ex,
            ),
            (Some(o), Some(t)) => {
                both_valid += 1;
                let same_text = o == t;
                let same_unp = i.unpredictable.is_some() == l.soft;
                if same_text {
                    text_agree += 1;
                } else {
                    add(format!("{fpk}text: {} vs {}", kind(&i.op), base_mnemonic(t)), ex.clone());
                }
                if same_unp {
                    unp_agree += 1;
                } else if l.soft {
                    add(format!("{fpk}SoftFail only in LLVM: {}", kind(&i.op)), ex.clone());
                } else {
                    add(format!("{fpk}UNPREDICTABLE only in ours: {reason}"), ex.clone());
                }
                if same_text && same_unp {
                    agree += 1;
                    agree_valid += 1;
                }
            }
        }
    }
    println!("words compared: {}", words.len());
    println!("full agreement: {agree} ({:.4}%)", agree as f64 * 100.0 / words.len() as f64);
    println!("  both UNDEFINED/invalid: {agree_undef}");
    println!("  both valid, same text and UNPREDICTABLE flag: {agree_valid}");
    println!("both valid: {both_valid}; same text: {text_agree}; same UNPREDICTABLE flag: {unp_agree}");
    println!(
        "not UNPREDICTABLE in ours: {clean}; same validity and text: {clean_agree} ({:.4}%)",
        clean_agree as f64 * 100.0 / clean as f64
    );
    println!();
    for (k, c) in &classes {
        println!("[{}] {k}", c.count);
        for e in &c.examples {
            println!("      {e}");
        }
    }
}
