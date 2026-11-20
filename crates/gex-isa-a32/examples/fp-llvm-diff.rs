//! Differential test of the Floating-point and Advanced SIMD decoder against
//! LLVM's disassembler (`llvm-mc --disassemble`, ARMv7-A, Cortex-A15: VFPv4-D32,
//! Advanced SIMDv2, half precision).
//!
//! `cargo run --release --example fp-llvm-diff [-- SPACE...] [--words HEX...]`
//! SPACE is `simd`, `ldst`, `cp` or `all` (the default). The scratch files go
//! in the workspace's `target/a32-llvm-diff/`.

use gex_isa_a32::fp::{decode_cp, decode_simd_dp, decode_simd_ldst, fmt};
use gex_isa_a32::{Features, Op};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

const LLVM_MC: &str = "/opt/homebrew/opt/llvm/bin/llvm-mc";
const BATCH: usize = 50_000;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 16) as u32
    }
}

/// Words with the bits of `fixed_mask` from `fixed`, every combination of
/// the bits in `sweep`, and `fills` random values of the remaining bits.
fn sweep(rng: &mut Rng, fixed: u32, fixed_mask: u32, sweep: u32, fills: usize, out: &mut Vec<u32>) {
    let bits: Vec<u32> = (0..32).filter(|b| sweep >> b & 1 == 1).collect();
    let free = !(fixed_mask | sweep);
    for k in 0..(1u64 << bits.len()) {
        let mut w = fixed & fixed_mask;
        for (i, b) in bits.iter().enumerate() {
            if k >> i & 1 == 1 {
                w |= 1 << b;
            }
        }
        for _ in 0..fills {
            out.push(w | (rng.next() & free));
        }
    }
}

fn gen_simd(rng: &mut Rng) -> Vec<u32> {
    let mut v = Vec::new();
    // Table A7-8 and the 3-register tables: U, A (23:19), B/C (11:4).
    sweep(rng, 0xf200_0000, 0xfe00_0000, 1 << 24 | 0x1f << 19 | 0xff << 4, 4, &mut v);
    // Two registers, miscellaneous: size and A (19:16), B (10:6).
    sweep(rng, 0xf3b0_0000, 0xffb0_0800, 0xf << 16 | 0x1f << 6 | 1 << 4, 8, &mut v);
    // Shifts: U, imm6, A, L, B.
    sweep(rng, 0xf280_0010, 0xfe80_0010, 1 << 24 | 0x3f << 16 | 0xff << 6, 2, &mut v);
    // Modified immediates: every a..h, cmode, Q, op.
    sweep(rng, 0xf280_0010, 0xfeb8_0090, 1 << 24 | 7 << 16 | 0xf << 8 | 3 << 5 | 0xf, 1, &mut v);
    // VEXT, VTBL, VDUP (scalar).
    sweep(rng, 0xf2b0_0000, 0xfeb0_0010, 1 << 24 | 0xf << 8 | 0xf << 4, 16, &mut v);
    for _ in 0..1_000_000 {
        v.push(0xf200_0000 | (rng.next() & 0x01ff_ffff));
    }
    v
}

fn gen_ldst(rng: &mut Rng) -> Vec<u32> {
    let mut v = Vec::new();
    // A, L, B and the size/align fields, with Rm PC, SP or another.
    for rm in [15u32, 13, 0] {
        let fixed = 0xf400_0000 | rm;
        sweep(rng, fixed, 0xff10_000f, 1 << 23 | 1 << 21 | 0xff << 4, 8, &mut v);
    }
    for _ in 0..500_000 {
        v.push(0xf400_0000 | (rng.next() & 0x00ef_ffff));
    }
    v
}

fn gen_cp(rng: &mut Rng) -> Vec<u32> {
    let mut v = Vec::new();
    // Extension register load/store and 64-bit transfers: P U D W L, sz,
    // and op (7:4) with random registers and imm8.
    sweep(rng, 0xec00_0a00, 0xfe00_0e00, 0x1f << 20 | 1 << 8 | 0xf << 4, 16, &mut v);
    // Floating-point data processing and the 8/16/32-bit transfers: opc1,
    // opc2, sz and 7:4.
    sweep(rng, 0xee00_0a00, 0xff00_0e00, 0xff << 16 | 0x1f << 4 | 1 << 8, 6, &mut v);
    for _ in 0..400_000 {
        v.push(0xec00_0a00 | (rng.next() & 0x01ff_f1ff));
    }
    for _ in 0..400_000 {
        v.push(0xee00_0a00 | (rng.next() & 0x00ff_f1ff));
    }
    v
}

fn ours(w: u32, f: &Features) -> (Op, Option<&'static str>) {
    match w >> 24 {
        0xf2 | 0xf3 => decode_simd_dp(w, f),
        0xf4 => decode_simd_ldst(w, f),
        _ => decode_cp(w, f),
    }
}

/// LLVM's view of one word: `None` for an invalid encoding, else its text
/// and whether it warned "potentially undefined".
type Llvm = Option<(String, bool)>;

fn run_llvm(dir: &PathBuf, words: &[u32]) -> Vec<Llvm> {
    let path = dir.join("batch.txt");
    {
        let mut f = std::io::BufWriter::new(std::fs::File::create(&path).unwrap());
        for w in words {
            writeln!(f, "0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x}", w & 0xff, w >> 8 & 0xff, w >> 16 & 0xff, w >> 24).unwrap();
        }
    }
    let out = Command::new(LLVM_MC)
        .current_dir(dir)
        .args(["--disassemble", "-triple=armv7a", "-mcpu=cortex-a15", "batch.txt"])
        .output()
        .expect("llvm-mc");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let mut invalid = vec![false; words.len()];
    let mut soft = vec![false; words.len()];
    for line in stderr.lines() {
        if let Some(rest) = line.strip_prefix("batch.txt:") {
            let mut it = rest.splitn(3, ':');
            let ln: usize = match it.next().and_then(|s| s.parse().ok()) {
                Some(n) => n,
                None => continue,
            };
            if ln == 0 || ln > words.len() {
                continue;
            }
            if line.contains("invalid instruction encoding") {
                invalid[ln - 1] = true;
            } else if line.contains("potentially undefined") {
                soft[ln - 1] = true;
            }
        }
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut texts = stdout.lines().filter(|l| {
        let t = l.trim();
        !t.is_empty() && !t.starts_with(".text")
    });
    let mut res = Vec::with_capacity(words.len());
    for i in 0..words.len() {
        if invalid[i] {
            res.push(None);
        } else {
            let t = texts.next().expect("llvm-mc printed fewer lines than valid words");
            let t = t.split('@').next().unwrap();
            let t = t.split_whitespace().collect::<Vec<_>>().join(" ");
            res.push(Some((t, soft[i])));
        }
    }
    assert!(texts.next().is_none(), "llvm-mc printed more lines than valid words");
    res
}

#[derive(Default)]
struct Stats {
    total: usize,
    agree_undef: usize,
    agree_text: usize,
    agree_unpred: usize,
    ours_unpred: usize,
    disagree_unpred: usize,
    disagree_other: usize,
    cats: BTreeMap<String, (usize, Vec<String>)>,
}

impl Stats {
    fn add(&mut self, key: String, ex: String) {
        if key.contains("UNPRED") {
            self.disagree_unpred += 1;
        } else {
            self.disagree_other += 1;
        }
        let e = self.cats.entry(key).or_insert((0, Vec::new()));
        e.0 += 1;
        if e.1.len() < 4 {
            e.1.push(ex);
        }
    }
}

fn mnemonic(s: &str) -> &str {
    s.split(' ').next().unwrap_or("")
}

fn compare(words: &[u32], llvm: &[Llvm], f: &Features, st: &mut Stats) {
    for (w, l) in words.iter().zip(llvm) {
        st.total += 1;
        let (op, why) = ours(*w, f);
        if why.is_some() {
            st.ours_unpred += 1;
        }
        let mine = match &op {
            Op::Fp(i) => Some(fmt(i)),
            _ => None,
        };
        match (&mine, l) {
            (None, None) => st.agree_undef += 1,
            (None, Some((t, s))) => {
                st.add(format!("UNDEF vs llvm {}", mnemonic(t)), format!("{:08x}: llvm `{}`{}", w, t, if *s { " (soft)" } else { "" }));
            }
            (Some(m), None) => {
                let k = if why.is_some() { "valid(UNPRED) vs llvm invalid" } else { "valid vs llvm invalid" };
                st.add(format!("{}: {}", k, why.unwrap_or(mnemonic(m))), format!("{:08x}: ours `{}`", w, m));
            }
            (Some(m), Some((t, s))) => {
                if mnemonic(m) != mnemonic(t) {
                    let k = if why.is_some() { "mnemonic (ours UNPRED)" } else { "mnemonic" };
                    st.add(format!("{}: ours {} llvm {}", k, mnemonic(m), mnemonic(t)), format!("{:08x}: ours `{}` llvm `{}`", w, m, t));
                } else if m != t {
                    let k = if why.is_some() { "operands (ours UNPRED)" } else { "operands" };
                    st.add(format!("{}: {}", k, why.unwrap_or(mnemonic(m))), format!("{:08x}: ours `{}` llvm `{}`", w, m, t));
                } else {
                    st.agree_text += 1;
                }
                match (why.is_some(), *s) {
                    (true, true) | (false, false) => st.agree_unpred += 1,
                    (true, false) => st.add(format!("UNPRED ours only: {}", why.unwrap()), format!("{:08x}: `{}`", w, m)),
                    (false, true) => st.add(format!("UNPRED llvm only: {}", mnemonic(m)), format!("{:08x}: `{}`", w, m)),
                }
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/a32-llvm-diff");
    std::fs::create_dir_all(&dir).unwrap();
    let f = Features::ALL;
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);

    if let Some(p) = args.iter().position(|a| a == "--words") {
        let words: Vec<u32> = args[p + 1..].iter().map(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap()).collect();
        let l = run_llvm(&dir, &words);
        for (w, l) in words.iter().zip(&l) {
            let (op, why) = ours(*w, &f);
            let mine = match &op {
                Op::Fp(i) => fmt(i),
                _ => "UNDEFINED".into(),
            };
            let theirs = match l {
                None => "INVALID".to_string(),
                Some((t, s)) => format!("{}{}", t, if *s { " [soft]" } else { "" }),
            };
            println!("{:08x}  ours: {:40} {}\n          llvm: {}", w, mine, why.map(|s| format!("[{}]", s)).unwrap_or_default(), theirs);
        }
        return;
    }

    let spaces: Vec<&str> = if args.is_empty() { vec!["all"] } else { args.iter().map(|s| s.as_str()).collect() };
    let mut words = Vec::new();
    for s in &spaces {
        if *s == "simd" || *s == "all" {
            words.extend(gen_simd(&mut rng));
        }
        if *s == "ldst" || *s == "all" {
            words.extend(gen_ldst(&mut rng));
        }
        if *s == "cp" || *s == "all" {
            words.extend(gen_cp(&mut rng));
        }
    }
    let mut st = Stats::default();
    for chunk in words.chunks(BATCH) {
        let l = run_llvm(&dir, chunk);
        compare(chunk, &l, &f, &mut st);
        eprint!("\r{} / {}", st.total, words.len());
    }
    eprintln!();
    println!("words: {}", st.total);
    println!("agree UNDEFINED/invalid: {}", st.agree_undef);
    println!("agree text: {}", st.agree_text);
    println!("agree UNPREDICTABLE flag (both valid): {}", st.agree_unpred);
    println!("ours UNPREDICTABLE: {}", st.ours_unpred);
    println!("disagreements on encodings we flag UNPREDICTABLE: {}", st.disagree_unpred);
    println!("other disagreements: {}", st.disagree_other);
    let mut cats: Vec<_> = st.cats.iter().collect();
    cats.sort_by_key(|c| std::cmp::Reverse(c.1 .0));
    for (k, (n, ex)) in cats {
        println!("\n[{}] {}", n, k);
        for e in ex {
            println!("    {}", e);
        }
    }
}
