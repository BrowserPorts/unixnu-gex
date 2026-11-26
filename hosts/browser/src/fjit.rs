//! The function JIT in the browser (`gex_xlate::fjit`): the browser half of
//! `gexc run --fjit`, as the native
//! `ftab::lookup`/`serve` do it.
//!
//! * A `gex.lookup` miss (cgen.rs) translates the function at the address on
//!   this Worker, inside the shim, and publishes the module into the function
//!   table under module id `FJIT | n` with the page values it was made under;
//!   every Worker instantiates it as it replays the table's log (gex.mjs
//!   `#cgenInstall`), the bytes read from here.
//! * A tier-1 dispatch miss asks first (`serve`): an address a function
//!   serves is reached from tier-1 through the bridge in its slot, as units'.
//! * A function whose pages changed (their `PAGE_GEN` words) is retired at its
//!   next lookup and translated again.
//!
//! Off unless the page asks (`gex_set_fjit`), and then driven one of two
//! ways. At the first miss (`?fjit=1`): every miss and every lookup miss is
//! translated on the Worker that missed, before its thread goes on. Hot
//! (`?fjit=hot`): tier-1 takes every miss, and the JIT takes what the
//! safepoint's back-edge samples find hot (`hot_sample`), plus the callees
//! JIT code and units keep calling through the fallback (`fallback_call`);
//! a helper Worker of the process
//! translates and compiles it off the guest's threads (`gex_fjit_bg_*`,
//! gex.mjs `#fjitServe`) while tier-1 runs it, and a thread whose loop it was
//! goes into the new function at its next sample there (`redirect_due`).
//! `?fjit=hotsync` is the hot mode with the translation inline at the
//! sample, for comparing the two.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

/// Module ids at and above this are the JIT's (`MODULES`).
pub(crate) const FJIT: u32 = 1 << 30;

static ON: AtomicBool = AtomicBool::new(false);
/// `gex_set_fjit(2)` (and 4, 6): each translation on stderr.
static TRACE: AtomicBool = AtomicBool::new(false);

/// What drives the JIT (`gex_set_fjit`): the first tier-1 miss at an address,
/// or the safepoint's samples with the translation on a helper Worker, or the
/// samples with the translation inline.
const AT_MISS: u8 = 0;
const HOT_HELPER: u8 = 1;
const HOT_INLINE: u8 = 2;
static DRIVE: AtomicU8 = AtomicU8::new(AT_MISS);

/// Samples (`hot_sample`'s count, one per safepoint at that pc, which comes
/// every `SAFEPOINT_INTERVAL` back edges and indirect branches of a thread)
/// that make a pc hot; asked again at each multiple of it, for a translation
/// a code change dropped. `?fjitlibs=hotn=N` sets it. At 8, Notepad's start
/// with no units (eight Wine processes, each with a helper) took 5.77 s
/// against tier-1's 5.26; at 32, 5.52: fewer of start-up's loops count as
/// hot, and 32K back edges are still a few milliseconds of a loop that is.
static HOT_AT: AtomicU32 = AtomicU32::new(32);
/// At most this many translations, the rest declined (bisecting a bad one).
static LIMIT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(u32::MAX);
/// Translate only the function at this address (0: any).
static ONLY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Debugging: translate at most `n` functions, or (`only` != 0) just the one at `only`.
#[no_mangle]
pub extern "C" fn gex_fjit_limit(n: u32, only: i64) {
    LIMIT.store(n, Ordering::Relaxed);
    ONLY.store(only as u64, Ordering::Relaxed);
}

fn trace(s: &str) {
    if TRACE.load(Ordering::Relaxed) {
        crate::stderr_line(&format!("[fjit] {s}\n"));
    }
}
static JIT: OnceLock<gex_xlate::fjit::Jit> = OnceLock::new();

/// What translating has cost this process: shim time in `translate_root`
/// (recovery and emission, declined ones included) and the wasm it made.
static TRANSLATE_NS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static WASM_BYTES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Milliseconds this process has spent translating (`TRANSLATE_NS`).
#[no_mangle]
pub extern "C" fn gex_fjit_translate_ms() -> u32 {
    (TRANSLATE_NS.load(Ordering::Relaxed) / 1_000_000) as u32
}

/// KiB of wasm the JIT has made in this process, and how many modules.
#[no_mangle]
pub extern "C" fn gex_fjit_wasm_kib() -> u32 {
    (WASM_BYTES.load(Ordering::Relaxed) / 1024) as u32
}

#[no_mangle]
pub extern "C" fn gex_fjit_modules() -> u32 {
    lock(&MODULES).len() as u32
}

/// One translation: its bytes (named `gex-fjit` for profiles), the bridges
/// every Worker writes (cgen.rs `bridges`), the pages it numbered and what
/// the dispatch tables must hold.
pub(crate) struct Module {
    pub wasm: Vec<u8>,
    pub regs: Vec<u32>,
    pub dirs: Vec<(u64, u32)>,
    pub slots: u64,
}

pub(crate) static MODULES: Mutex<Vec<Module>> = Mutex::new(Vec::new());

/// Each JIT install's page checks: `(page, PAGE_GEN value)` it was made under.
static CHECKS: Mutex<Option<HashMap<u32, Vec<(u64, u32)>>>> = Mutex::new(None);

/// Addresses the bridge handed back to tier-1 (`cache_op::FTAB_TIER1`).
static TIER1_ONLY: Mutex<Option<HashSet<u64>>> = Mutex::new(None);

static TRANSLATED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Translations, functions and wasm bytes by object (`?fjitlibs=byobj=1`
/// prints them every 256 translations): what the JIT spends start-up on.
static BY_OBJECT: Mutex<Option<std::collections::BTreeMap<String, (u64, u64, u64)>>> = Mutex::new(None);
static BY_OBJECT_ON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// `?fjitlibs=dumpmod=ADDR`: print (base64, in 3,000-character lines: the page console cuts
/// a line at about 4,000) every JIT module
/// whose functions include guest address ADDR, with its root, to rebuild the
/// page's translation offline.
static DUMP_MOD: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

static DUMP_OBJ: Mutex<Option<(String, u64)>> = Mutex::new(None);
/// `?fjitlibs=scanconst=ADDR`: say which translations mention guest address
/// ADDR as an `i64.const` (a call or jump to it, or a pc it stores), and
/// every translation asked for at ADDR: who made a mid-function address a
/// function start.
static SCAN_CONST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn scan_const(root: u64, funcs: &[u64], wasm: &[u8]) {
    let want = SCAN_CONST.load(Ordering::Relaxed);
    if want == 0 {
        return;
    }
    // `i64.const` (0x42) and its signed LEB128.
    let mut pat = vec![0x42u8];
    let mut v = want as i64;
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        let done = (v == 0 && b & 0x40 == 0) || (v == -1 && b & 0x40 != 0);
        pat.push(if done { b } else { b | 0x80 });
        if done {
            break;
        }
    }
    let hits = wasm.windows(pat.len()).filter(|w| *w == &pat[..]).count();
    if hits > 0 {
        let list: Vec<String> = funcs.iter().take(24).map(|a| format!("{a:x}")).collect();
        crate::warn_line(&format!(
            "[fjitscan] {want:#x} x{hits} in the module of root {root:#x} ({}), {} functions: {}\n",
            crate::object_off_at(root),
            funcs.len(),
            list.join(",")
        ));
    }
}

fn dump_module(root: u64, funcs: &[u64], wasm: &[u8]) {
    let mut want = DUMP_MOD.load(Ordering::Relaxed);
    if want == 0 {
        let obj = lock(&DUMP_OBJ).clone();
        if let Some((name, off)) = obj {
            if let Some(&a) = funcs.iter().find(|&&a| crate::object_file_off(a) == (name.clone(), off)) {
                DUMP_MOD.store(a, Ordering::Relaxed);
                *lock(&DUMP_OBJ) = None;
                crate::warn_line(&format!("[fjitdump] {name}@{off:x} is {a:#x}\n"));
                want = a;
            }
        }
    }
    if want == 0 || !funcs.contains(&want) {
        return;
    }
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b = String::with_capacity(wasm.len() * 4 / 3 + 4);
    for c in wasm.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for k in 0..4 {
            if k <= c.len() {
                b.push(T[(n >> (18 - 6 * k)) as usize & 63] as char);
            } else {
                b.push('=');
            }
        }
    }
    const W: usize = 3000;
    let lines = b.len().div_ceil(W);
    crate::warn_line(&format!("[fjitdump] root {root:#x} funcs {} bytes {} lines {lines}\n", funcs.len(), wasm.len()));
    for (i, fs) in funcs.chunks(32).enumerate() {
        let list: Vec<String> = fs.iter().map(|a| format!("{a:x}")).collect();
        crate::warn_line(&format!("[fjitdump] {root:x} funcs {i}: {}\n", list.join(",")));
    }
    for (i, ch) in b.as_bytes().chunks(W).enumerate() {
        crate::warn_line(&format!("[fjitdump] {root:x} {i} {}\n", std::str::from_utf8(ch).unwrap_or("")));
    }
}

fn note_object(addr: u64, funcs: usize, bytes: usize) {
    if !BY_OBJECT_ON.load(Ordering::Relaxed) {
        return;
    }
    let (name, _) = crate::object_file_off(addr);
    let mut g = lock(&BY_OBJECT);
    let m = g.get_or_insert_with(Default::default);
    let e = m.entry(name).or_default();
    e.0 += 1;
    e.1 += funcs as u64;
    e.2 += bytes as u64;
    let total: u64 = m.values().map(|e| e.0).sum();
    if total % 256 == 0 {
        let mut v: Vec<_> = m.iter().collect();
        v.sort_by(|a, b| b.1 .2.cmp(&a.1 .2));
        let list: Vec<String> = v.iter().take(12).map(|(n, e)| format!("{n} {}/{}/{}K", e.0, e.1, e.2 / 1024)).collect();
        crate::warn_line(&format!("[fjit] {total} translations by object (translations/functions/wasm): {}\n", list.join(", ")));
    }
}
static DECLINED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) fn on() -> bool {
    ON.load(Ordering::Relaxed)
}

/// Whether the safepoint's samples drive the JIT (`?fjit=hot`, `hotsync`).
pub(crate) fn hot() -> bool {
    on() && DRIVE.load(Ordering::Relaxed) != AT_MISS
}

/// The function JIT on or off, before the guest runs: 1 at the first miss,
/// 3 hot with a helper Worker translating, 5 hot translating inline; one
/// more than each (2, 4, 6) with each translation traced.
#[no_mangle]
pub extern "C" fn gex_set_fjit(on: i32) {
    ON.store(on != 0, Ordering::Relaxed);
    TRACE.store(matches!(on, 2 | 4 | 6), Ordering::Relaxed);
    DRIVE.store(
        match on {
            3 | 4 => HOT_HELPER,
            5 | 6 => HOT_INLINE,
            _ => AT_MISS,
        },
        Ordering::Relaxed,
    );
    if on != 0 {
        let _ = JIT.get_or_init(|| gex_xlate::fjit::Jit::new(Default::default()));
    }
}

#[no_mangle]
pub extern "C" fn gex_fjit_on() -> i32 {
    on() as i32
}

/// The bridge handed `addr` back to tier-1: serve it no more.
pub(crate) fn tier1_only(addr: u64) {
    lock(&TIER1_ONLY).get_or_insert_with(Default::default).insert(addr);
}

fn is_tier1_only(addr: u64) -> bool {
    lock(&TIER1_ONLY).as_ref().is_some_and(|s| s.contains(&addr))
}

/// Whether the JIT function of install `install` still matches its pages.
pub(crate) fn current(install: u32) -> bool {
    let mem = crate::guest();
    let word = |off: u64| mem.read_u32(off).unwrap_or(0);
    lock(&CHECKS)
        .as_ref()
        .and_then(|c| c.get(&install))
        .is_none_or(|c| c.iter().all(|&(w, g)| word(w) == g))
}

/// The `PAGE_GEN` word of page key `key` (`gex_abi::page_key`: its mode's
/// directory) and its value, numbering the page (its directory written
/// when the translation is installed: `fresh`) if it has no translation
/// yet.
fn page_gen(key: u64, fresh: &mut Vec<(u64, u32)>) -> (u64, u32) {
    let at = crate::dir_word(key);
    if at == u64::MAX {
        return (gex_abi::page_gen() + 4 * gex_abi::key_page(key).0, u32::MAX);
    }
    let have = crate::guest().read_u32(at).unwrap_or(0);
    if have != 0 {
        return (at, have);
    }
    crate::with_jit_only(|j| match j.page_table.lookup(key) {
        Some(b) => (at, b),
        None => {
            let b = j.page_table.base(key);
            fresh.push((key, b));
            (at, b)
        }
    })
}

/// Each object's `.eh_frame` function ranges (unbiased, sorted by start)
/// and `PT_LOAD` headers (file offset, vaddr, file size), by file path;
/// empty when it has none or cannot be read.
type ObjFdes = (Vec<(u64, u64)>, Vec<(u64, u64, u64)>);
static FDES: Mutex<Option<std::collections::HashMap<String, std::sync::Arc<ObjFdes>>>> = Mutex::new(None);
static MID_DECLINED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// An ELF's `PT_LOAD` headers: (file offset, vaddr, file size).
fn loads(elf: &[u8]) -> Vec<(u64, u64, u64)> {
    let mut out = Vec::new();
    let Some(&class) = elf.get(4) else { return out };
    let wide = class == 2;
    let rd = |o: usize, n: usize| -> Option<u64> {
        let b = elf.get(o..o + n)?;
        Some(b.iter().rev().fold(0u64, |a, &x| a << 8 | x as u64))
    };
    let hdr = if wide { (rd(0x20, 8), rd(0x36, 2), rd(0x38, 2)) } else { (rd(0x1c, 4), rd(0x2a, 2), rd(0x2c, 2)) };
    let (Some(phoff), Some(phentsize), Some(phnum)) = hdr else { return out };
    for i in 0..phnum {
        let ph = (phoff + i * phentsize) as usize;
        if rd(ph, 4) != Some(1) {
            continue;
        }
        let f = if wide { (rd(ph + 8, 8), rd(ph + 16, 8), rd(ph + 32, 8)) } else { (rd(ph + 4, 4), rd(ph + 8, 4), rd(ph + 16, 4)) };
        if let (Some(o), Some(v), Some(n)) = f {
            out.push((o, v, n));
        }
    }
    out
}

/// Whether `addr` lies strictly inside a function of its object, by the
/// object's `.eh_frame`: a miss there is a resume into the middle of a
/// function (a signal's return, a block boundary of the fallback's), not an
/// entry. Translated as a root, `recover_one` records it as a function start
/// for good, and every later translation of the function around it ends at
/// it as at a tail call, with the flags dead across it: a `cmov` after the
/// point then reads flags its `cmp` set before it (in libxcb's
/// `_xcb_in_read_block`, a memmove of -8 bytes). The fallback runs it
/// instead; the function's real entry still gets translated.
fn mid_function(addr: u64) -> bool {
    let Some((name, x, _)) = enclosing(addr) else { return false };
    let n = MID_DECLINED.fetch_add(1, Ordering::Relaxed);
    // Routine (a start the JIT declines; the fallback runs it), so only
    // with each translation traced: `fjit=2`.
    if TRACE.load(Ordering::Relaxed) && (n < 32 || (n + 1).is_power_of_two()) {
        crate::warn_line(&format!("[fjit] {addr:#x} ({name} +{x:#x}) is inside a function: left to the fallback ({} so far)\n", n + 1));
    }
    true
}

/// The function `addr` lies strictly inside, by its object's `.eh_frame`:
/// the object's file name, `addr` in the file's addresses, and the
/// function's entry where it is mapped. None at an entry, or with no
/// `.eh_frame` to say (a PE image's 32-bit code).
fn enclosing(addr: u64) -> Option<(String, u64, u64)> {
    let home = crate::sigs::proc_home();
    let found = home.mm().lock().vmas().iter().find(|v| addr >= v.start && addr < v.end).and_then(|v| v.code.clone().map(|(p, o)| (p, o, v.start)));
    let (path, off, start) = found?;
    let cached = lock(&FDES).get_or_insert_with(Default::default).get(&path).cloned();
    let obj = match cached {
        Some(o) => o,
        None => {
            let bytes = home.read_elf(&path).unwrap_or_default();
            // Not the PLT's: one FDE covers all of `.plt`, whose stubs are
            // each an entry (left to the fallback, they died).
            let plt: Vec<(u64, u64)> = gex_xlate::ehframe::sections(&bytes)
                .into_iter()
                .filter(|s| s.name.starts_with(".plt"))
                .map(|s| (s.addr, s.addr + s.size))
                .collect();
            let mut f: Vec<(u64, u64)> = gex_xlate::ehframe::fdes(&bytes, 0)
                .into_iter()
                .filter(|f| !plt.iter().any(|&(lo, hi)| f.start >= lo && f.start < hi))
                .map(|f| (f.start, f.end))
                .collect();
            f.sort_unstable();
            let o = std::sync::Arc::new((f, loads(&bytes)));
            lock(&FDES).get_or_insert_with(Default::default).insert(path.clone(), o.clone());
            o
        }
    };
    let (fdes, loads) = &*obj;
    // The vma's file offset gives its vaddr in the file, hence the bias.
    let base = loads.iter().find(|&&(o, _, n)| off >= o && off < o + n.max(1)).map(|&(o, v, _)| v + (off - o))?;
    let x = addr - start + base;
    let i = fdes.partition_point(|&(s, _)| s <= x);
    if !(i > 0 && fdes[i - 1].0 < x && x < fdes[i - 1].1) {
        return None;
    }
    let name = path.rsplit('/').next().unwrap_or(&path).to_string();
    Some((name, x, fdes[i - 1].0 - base + start))
}

/// Code in `ranges` was unmapped or reprotected (`retire_unmapped_code`):
/// what the JIT learned there goes (`Jit::retire`). SDL loads libdbus,
/// unloads it, and maps libxcb over the same range; with libdbus's starts
/// kept, a libxcb function ends at a libdbus function's address as at a
/// tail call, flags dead, and computes from stale flags.
pub(crate) fn on_retire(ranges: &[(u64, u64)]) {
    for &(s, e) in ranges {
        if e > s {
            code_changed(s / gex_abi::DISPATCH_PAGE, (e - 1) / gex_abi::DISPATCH_PAGE + 1);
        }
    }
    if let Some(jit) = JIT.get() {
        jit.retire(0, ranges);
    }
    lock(&SEEDED).retain(|&(_, lo, hi)| !ranges.iter().any(|&(s, e)| s < hi && lo < e));
    // Asked again when hot again: what is there now is other code.
    if let Some(a) = lock(&ASKED).as_mut() {
        a.retain(|&x| !ranges.iter().any(|&(s, e)| x >= s && x < e));
    }
}

/// Bumped with every retirement of code ([`code_changed`]): a translation
/// made on a helper while its thread ran on publishes only if no page it read
/// was retired meanwhile (`publish_made`). Inline, the thread that translates
/// is the one that would have run the code, and the miss path publishes as
/// it always has.
static CODE_EPOCH: AtomicU64 = AtomicU64::new(0);
/// The latest retirements: (epoch after it, first page, end page), in
/// dispatch pages of either mode, at most `RETIRED_KEPT` of them.
static RETIRED: Mutex<VecDeque<(u64, u64, u64)>> = Mutex::new(VecDeque::new());
const RETIRED_KEPT: usize = 512;

/// Pages `[lo, hi)` (dispatch pages) lost their translations: unmapped or
/// reprotected (`on_retire`), or found rewritten (lib.rs `gex_cache_op`'s
/// invalidation). Code is written only after one of these: a page the JIT
/// takes is not writable and executable at once (`volatile`), so making it
/// writable retires it first.
pub(crate) fn code_changed(lo: u64, hi: u64) {
    if !hot() {
        return;
    }
    let mut r = lock(&RETIRED);
    let e = CODE_EPOCH.fetch_add(1, Ordering::AcqRel) + 1;
    if r.len() >= RETIRED_KEPT {
        r.pop_front();
    }
    r.push_back((e, lo, hi));
}

/// Whether any of `pages` retired after `epoch`: true too when more
/// retirements came since than are kept.
fn retired_since(epoch: u64, pages: &[u64]) -> bool {
    if CODE_EPOCH.load(Ordering::Acquire) == epoch {
        return false;
    }
    let r = lock(&RETIRED);
    if r.front().is_none_or(|&(e, _, _)| e > epoch + 1) {
        return true;
    }
    r.iter().filter(|&&(e, _, _)| e > epoch).any(|&(_, lo, hi)| pages.iter().any(|&p| p >= lo && p < hi))
}

/// The objects whose function starts the JIT has (`seed_mapped`): path and
/// the address range of their `PT_LOAD`s, dropped when code there retires.
static SEEDED: Mutex<Vec<(String, u64, u64)>> = Mutex::new(Vec::new());

/// Give the JIT the function starts of every mapped object it lacks (its
/// symbols, `.eh_frame`, init arrays and relocations, `Jit::add_image`),
/// as natively ahead of time. Without them recovery knows only the starts
/// calls name, and follows a tail jump into the function it reaches: each
/// of libasound's exported wrappers carried a copy of the function it
/// jumps to. Offline, translating each of libasound's 1,698 exports in
/// turn made 57.2 MiB of wasm in 16.4 s without its starts and 9.7 MiB in
/// 7.1 s with them (one function per module: 49.7 MiB and 14.1 s against
/// 3.2 MiB and 1.7 s).
fn seed_mapped(jit: &gex_xlate::fjit::Jit) {
    let home = crate::sigs::proc_home();
    let maps: Vec<(u64, String, u64)> = {
        use gex_kernel::mem::prot;
        home.mm().lock().vmas().iter().filter(|v| v.prot & prot::EXEC != 0).filter_map(|v| v.code.clone().map(|(p, o)| (v.start, p, o))).collect()
    };
    for (start, path, off) in maps {
        if lock(&SEEDED).iter().any(|(p, lo, hi)| *p == path && start >= *lo && start < *hi) {
            continue;
        }
        let bytes = home.read_elf(&path).unwrap_or_default();
        let lds = loads(&bytes);
        // The vma's file offset gives its vaddr in the file, hence the bias.
        let Some(bias) = lds.iter().find(|&&(o, _, n)| off >= o && off < o + n.max(1)).map(|&(o, v, _)| start.wrapping_sub(v + (off - o))) else {
            lock(&SEEDED).push((path, start, start + 1));
            continue;
        };
        let lo = lds.iter().map(|l| l.1).min().unwrap_or(0).wrapping_add(bias) & !0xfff;
        let hi = lds.iter().map(|l| l.1 + l.2).max().unwrap_or(0).wrapping_add(bias);
        let n = match gex_ld::elf::load(&bytes, bias) {
            Ok(mut image) => {
                gex_ld::elf::apply_own_relative(&mut image);
                jit.add_image(&image, Some(&bytes))
            }
            Err(_) => 0,
        };
        if BY_OBJECT_ON.load(Ordering::Relaxed) {
            let name = path.rsplit('/').next().unwrap_or(&path);
            crate::warn_line(&format!("[fjit] starts of {name} at {bias:#x}: {n}\n"));
        }
        lock(&SEEDED).push((path, lo, hi.max(lo + 1)));
    }
}

/// Translate the function at `addr` and publish it (`gex.lookup`'s miss):
/// its index in the function table, or `None` (the fallback runs it). Hot,
/// not yet: the fallback's calls count (`fallback_call`).
pub(crate) fn translate(addr: u64) -> Option<u32> {
    let r = if hot() { None } else { translate_root(addr, crate::thread_alt()) };
    if addr != 0 && addr == SCAN_CONST.load(Ordering::Relaxed) {
        crate::warn_line(&format!("[fjitscan] translation asked at {addr:#x}: {r:?}\n"));
    }
    r
}

/// The guest memory as far as it exists now: the translator's view
/// (`guest_whole`) spans the whole address space, and recovery reads the slots of `call [addr]` and `jmp
/// [addr]` straight from it. A slot past the memory's end (Wine's system
/// call stubs' `call [0x7ffe1000]`, in a process whose memory stops below
/// the shared user data) is then out of bounds: a trap in the shim, which
/// the thread took for a fault at its last PC.
fn mem_now() -> &'static [u8] {
    // SAFETY: the translator's whole-memory view (`guest_whole`), cut to
    // what exists.
    let mem = unsafe { crate::guest_whole() };
    &mem[..(crate::warch::memory_size(0) as usize).saturating_mul(65536).min(mem.len())]
}

/// Translate the function at `addr` and publish it at once: the miss
/// path's, on the thread that missed (`alt_thread`: it runs the process's
/// other mode).
fn translate_root(addr: u64, alt_thread: bool) -> Option<u32> {
    let (n, made) = make(addr, alt_thread)?;
    publish_made(n, made, false)
}

/// A translation made (`make`) and not yet published: what its publication
/// needs. `epoch` and `pages`: the code epoch before any byte was read, and
/// the dispatch pages it read, for a publication that comes later
/// (`publish_made`).
struct Made {
    addr: u64,
    funcs: Vec<u64>,
    checks: Vec<(u64, u32)>,
    fresh: Vec<(u64, u32)>,
    alt: bool,
    epoch: u64,
    pages: Vec<u64>,
}

/// Translate the function at `addr` into module number `n` (its bytes in
/// `MODULES`, read by no Worker until it is published), or `None` when the
/// JIT declines it.
fn make(addr: u64, alt_thread: bool) -> Option<(u32, Made)> {
    if !on() || is_tier1_only(addr) || !lib_wanted(addr) {
        return None;
    }
    let epoch = CODE_EPOCH.load(Ordering::Acquire);
    let only = ONLY.load(Ordering::Relaxed);
    if (only != 0 && addr != only) || lock(&MODULES).len() as u32 >= LIMIT.load(Ordering::Relaxed) {
        return None;
    }
    let jit = JIT.get()?;
    seed_mapped(jit);
    let (exec, ro, wx): (Vec<(u64, u64)>, Vec<(u64, u64)>, Vec<(u64, u64)>) = {
        use gex_kernel::mem::prot;
        let mm = crate::sigs::proc_home().mm().lock();
        let v = mm.vmas();
        (
            v.iter().filter(|v| v.prot & prot::EXEC != 0).map(|v| (v.start, v.end)).collect(),
            v.iter().filter(|v| v.prot & prot::WRITE == 0 && v.prot & prot::READ != 0).map(|v| (v.start, v.end)).collect(),
            mm.volatile_code(),
        )
    };
    if !exec.iter().any(|&(s, e)| addr >= s && addr < e) {
        return None;
    }
    if mid_function(addr) || crate::cgen::unit_due(addr) {
        return None;
    }
    // An address an ELF provider holds is not code to translate (cgen::elfprov).
    // With `?fjitlibs=` rules, callees outside them are not brought in either.
    let rules = !lock(&LIBS).is_empty();
    // A callee a unit or the JIT already serves is not brought into the
    // batch: the call reaches it through the table. Without this, a miss in
    // a library with a unit (a function the unit lacks) re-translates dozens
    // of the unit's own functions with it, JIT code shadowing clang's, and a
    // served library's callees go into every batch (tens of MiB of wasm).
    // `skip` bounds the batch only. Asked of instruction fetch (as part of
    // `executable`), an entry inside the function being recovered -- a
    // resume point, or a root the JIT took inside a function and, since
    // misses no longer make starts, does not stop recovery at -- read as
    // non-code and decoded as illegal (a SIGILL on a valid `cmovle`).
    let served_memo = std::cell::RefCell::new(std::collections::HashMap::<u64, bool>::new());
    let served = |a: u64| *served_memo.borrow_mut().entry(a).or_insert_with(|| crate::cgen::unit_serves(a) || crate::cgen::jit_serves(a));
    // Asked of every byte fetched: the providers' addresses and replaced
    // ranges taken once, and the range checks kept by 4 KiB page (exec,
    // replaced and object ranges are pages; `?fjitlibs=` ranges are not).
    let provided = crate::cgen::elfprov::provided_set();
    // Native wasm32 Wine DLLs' skeletons as replaced: no x86 code there.
    let mut replaced = crate::cgen::libprov::replaced_ranges();
    replaced.extend(crate::cgen::skeleton_code());
    let page_memo = std::cell::RefCell::new(std::collections::HashMap::<u64, bool>::new());
    let ranged = rules && lock(&LIBS).iter().any(|r| r.range.is_some());
    let executable = |a: u64| {
        let page_ok = |a: u64| exec.iter().any(|&(s, e)| a >= s && a < e) && !replaced.iter().any(|&(lo, hi)| a >= lo && a < hi) && (!rules || lib_wanted(a));
        let ok = if ranged { page_ok(a) } else { *page_memo.borrow_mut().entry(a >> 12).or_insert_with(|| page_ok(a)) };
        // Native Wine's return pad and the stops after it: the miss path's.
        ok && !provided.contains(&a) && !(gex_abi::X86 && gex_kernel::win::tramp::filler(a))
    };
    let read_only = |a: u64, n: u64| ro.iter().any(|&(s, e)| a >= s && a.saturating_add(n) <= e);
    // Writable-and-executable code (a JIT's) stays tier-1, as natively.
    let volatile = |a: u64| wx.iter().any(|&(s, e)| a >= s && a < e);
    // The mode the code is in: a WoW64 process's i386 images are lifted in
    // compatibility mode, their pages keyed in the other directory
    // (`gex_abi::ALT_PAGE`), which tier-1 in that mode dispatches through
    // and so has made. Code in no PE image is lifted in the process's own
    // mode, and not at all for a thread in the other.
    let own = gex_abi::X86 && gex_xlate::default_compat();
    let class32 = match gex_abi::X86.then(|| gex_xlate::fjit::pe_class32_at(mem_now(), addr, &executable, &read_only)).flatten() {
        Some(c) => c,
        None if alt_thread => return None,
        None => own,
    };
    let alt = class32 != own;
    if alt && crate::gex_alt_dir() == 0 {
        return None;
    }
    let fresh = std::cell::RefCell::new(Vec::new());
    let checks = std::cell::RefCell::new(Vec::<(u64, u32)>::new());
    let pages = std::cell::RefCell::new(Vec::<u64>::new());
    let pg = |page: u64| {
        let (w, g) = page_gen(gex_abi::page_key(page * gex_abi::DISPATCH_PAGE, alt), &mut fresh.borrow_mut());
        let mut c = checks.borrow_mut();
        if !c.iter().any(|&(q, _)| q == w) {
            c.push((w, g));
            pages.borrow_mut().push(page);
        }
        (w, g)
    };
    trace(&format!("translate {addr:#x}"));
    // Declined (or not holding `addr`): the pages numbered for it get their
    // directory entries anyway, as an install would give them. A page with a
    // base and no entry strands tier-1's blocks there (they go into that
    // base, which is not fresh, so their unit writes no entry for it) --
    // natively a livelock once the emitter left a function over V8's size
    // limit to tier-1 (gex-fjit `max_body_bytes`); here the miss path's
    // reconcile covers the faulting page, not the others.
    let declined = |fresh: Vec<(u64, u32)>| {
        DECLINED.fetch_add(1, Ordering::Relaxed);
        let mut gm = crate::guest();
        for (key, b) in fresh {
            let at = crate::dir_word(key);
            if at != u64::MAX && gm.read_u32(at).unwrap_or(0) == 0 {
                let _ = gm.write_u32(at, b);
            }
        }
    };
    let mem = mem_now();
    let t0 = crate::now_ns();
    let wasm = jit.translate_skipping(0, mem, addr, &executable, &served, &read_only, &volatile, &pg, class32);
    TRANSLATE_NS.fetch_add(crate::now_ns().saturating_sub(t0), Ordering::Relaxed);
    crate::note_kuser_folds(addr);
    if let Some(w) = &wasm {
        WASM_BYTES.fetch_add(w.len() as u64, Ordering::Relaxed);
    }
    let Some(wasm) = wasm else {
        trace(&format!("declined {addr:#x}"));
        declined(fresh.into_inner());
        return None;
    };
    let Some(funcs) = gex_kernel::ftab::module_funcs(&wasm) else {
        declined(fresh.into_inner());
        return None;
    };
    if !funcs.contains(&addr) {
        declined(fresh.into_inner());
        return None;
    }
    note_object(addr, funcs.len(), wasm.len());
    dump_module(addr, &funcs, &wasm);
    scan_const(addr, &funcs, &wasm);
    let wasm = named(wasm);
    // Its number now, its bridges at the publication: no Worker reads a
    // module the log has not named, and two Workers translating at once get
    // numbers of their own.
    let mut modules = lock(&MODULES);
    let n = modules.len() as u32;
    modules.push(Module { wasm, regs: Vec::new(), dirs: Vec::new(), slots: 0 });
    drop(modules);
    let made = Made { addr, funcs, checks: checks.into_inner(), fresh: fresh.into_inner(), alt, epoch, pages: pages.into_inner() };
    Some((n, made))
}

/// Publish module `n`, made as `made` says, into the function table: the
/// index serving its root, or `None`. `later`: made on a helper while the
/// guest ran on, so dropped if a page it read has retired since (the bytes it
/// read may not be the bytes there now), its pages' directory entries
/// written as a declined translation's are.
fn publish_made(n: u32, made: Made, later: bool) -> Option<u32> {
    let Made { addr, funcs, checks, fresh, alt, epoch, pages } = made;
    // Held until the module's bridges are in the list: a Worker replaying
    // the function table's log (`gex_fjit_ptr`, `gex_fjit_regs`) waits for
    // them rather than reading nothing.
    let mut modules = lock(&MODULES);
    if later && retired_since(epoch, &pages) {
        if let Some(m) = modules.get_mut(n as usize) {
            m.wasm = Vec::new();
        }
        drop(modules);
        DROPPED.fetch_add(1, Ordering::Relaxed);
        trace(&format!("dropped {addr:#x}: its code retired while it was translated"));
        crate::cgen::write_dirs(fresh);
        // Asked again when hot again.
        if let Some(a) = lock(&ASKED).as_mut() {
            a.remove(&addr);
        }
        return None;
    }
    let pairs: Vec<(u64, u32)> = funcs.iter().enumerate().map(|(k, &a)| (a, k as u32)).collect();
    let install = crate::cgen::publish(funcs.len() as u32, FJIT | n, gex_kernel::ftab::Tier::Jit, &pairs);
    lock(&CHECKS).get_or_insert_with(Default::default).insert(install, checks);
    let entries: Vec<u64> = funcs.iter().copied().filter(|&a| a != 0).collect();
    {
        let mut mem = crate::guest();
        for &a in &entries {
            gex_kernel::ftab::fcache_clear(&mut mem, a);
        }
    }
    let (regs, mut dirs, slots) = crate::cgen::bridges_mode(&entries, alt);
    for d in fresh {
        if !dirs.contains(&d) {
            dirs.push(d);
        }
    }
    if let Some(m) = modules.get_mut(n as usize) {
        m.regs = regs;
        m.dirs = dirs;
        m.slots = slots;
    }
    drop(modules);
    if hot() {
        promoted(addr);
    }
    let n = TRANSLATED.fetch_add(1, Ordering::Relaxed) + 1;
    // The translator's line at 1024, 2048, ... translations: a process that
    // never exits (a game) reports too. The hot tier translates only what
    // runs hot, a few dozen functions where the first-miss JIT makes
    // thousands, so it reports from 16 on.
    if n >= if hot() { 16 } else { 1024 } && n.is_power_of_two() {
        gex_fjit_report();
    }
    let idx = crate::cgen::index_of(addr);
    if TRACE.load(Ordering::Relaxed) {
        let names: Vec<String> = funcs.iter().map(|&a| format!("{a:#x} {}", crate::object_off_at(a))).collect();
        trace(&format!("module {n}: {addr:#x} {} funcs, install {install}, index {idx:?}: {}", funcs.len(), names.join(", ")));
    }
    idx
}

/// `wasm` with a module name, `gex-fjit`, which a CPU profile shows.
fn named(mut wasm: Vec<u8>) -> Vec<u8> {
    let name = b"gex-fjit";
    let mut sec = vec![4u8];
    sec.extend_from_slice(b"name");
    sec.push(0);
    sec.push(1 + name.len() as u8);
    sec.push(name.len() as u8);
    sec.extend_from_slice(name);
    wasm.push(0);
    wasm.push(sec.len() as u8);
    wasm.extend_from_slice(&sec);
    wasm
}

/// A tier-1 dispatch miss at `pc`: does a function serve it (or can the JIT
/// make one)? Then its bridge reaches it once this Worker has installed
/// what the table's log holds (the caller traps or installs in place).
pub(crate) fn serve(pc: u64) -> bool {
    // Hot, tier-1 takes every miss: the samples say what the JIT gets.
    if !on() || hot() || is_tier1_only(pc) || !lib_wanted(pc) {
        return false;
    }
    if crate::cgen::index_of(pc).is_some() {
        return false;
    }
    translate(pc).is_some()
}

// ---- The hot tier ----------------------------------------------------------
//
// Tier-1 runs everything first. The safepoint counts where each thread's back
// edges and indirect branches land (lib.rs `HOT_PC`/`HOT_N`, one sample per
// `SAFEPOINT_INTERVAL` of them), and a pc sampled `HOT_AT` times in code
// tier-1 translated makes a root: the function around it where its object's
// `.eh_frame` says (an ELF object's), else the pc itself (a PE image's code,
// which says nothing): the function JIT translates from there, a loop and
// what follows to the function's return, with the callees not yet
// translated (`Jit::translate_skipping`'s batch). A callee JIT code or a
// unit keeps calling and nothing serves is one too (`fallback_call`).
//
// The translation runs on a helper Worker of the process (gex.mjs
// `#fjitServe`), started at the first root, which compiles the module as well
// (V8 compiles it off that Worker's thread too) and then publishes it; the
// guest's threads install it as any module of the log, compiling the same
// bytes again from V8's cache of them. A page retired meanwhile drops the
// translation (`publish_made`). Its root's slot gets the bridge, so the next
// dispatch there runs the function: a thread still in a loop that is the
// root gets there at its next sample of it (`redirect_due`), which leaves
// through the run loop (a trap), installs, and resumes at the root through
// the bridge; one in a function rooted at its entry, at its next call.

/// Roots asked for: each once, until its code retires or its translation is
/// dropped.
static ASKED: Mutex<Option<HashSet<u64>>> = Mutex::new(None);
/// Roots for the helper, oldest first.
static QUEUE: Mutex<VecDeque<u64>> = Mutex::new(VecDeque::new());
/// Bumped and notified at each root queued: the word the helper waits on.
static QUEUE_SEQ: AtomicI32 = AtomicI32::new(0);
/// Translations the helper made and has not published, by module number.
static MADE: Mutex<Option<HashMap<u32, Made>>> = Mutex::new(None);
/// Translations a retirement dropped before their publication.
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// The helper Worker: none, wanted (the next trap's JS starts it), being
/// started, running, or impossible here (a single-thread build, a memory not
/// shared): roots are then translated inline.
const HELPER_NONE: u8 = 0;
const HELPER_WANTED: u8 = 1;
const HELPER_STARTING: u8 = 2;
const HELPER_UP: u8 = 3;
const HELPER_UNABLE: u8 = 4;
static HELPER: AtomicU8 = AtomicU8::new(HELPER_NONE);
/// The process the state is of: a fork's child copies it with the memory,
/// and has no helper of its own.
static HELPER_PID: AtomicI32 = AtomicI32::new(0);

fn helper_state() -> u8 {
    let s = HELPER.load(Ordering::Acquire);
    if s != HELPER_NONE && HELPER_PID.load(Ordering::Acquire) != crate::my_pid() {
        HELPER_NONE
    } else {
        s
    }
}

fn set_helper(s: u8) {
    HELPER_PID.store(crate::my_pid(), Ordering::Release);
    HELPER.store(s, Ordering::Release);
}

/// The process wants its helper started: the next trap goes through JS, which
/// asks (`gex_fjit_helper_wanted`).
pub(crate) fn helper_due() -> bool {
    hot() && helper_state() == HELPER_WANTED
}

/// Published roots, in order, for each Worker's redirect (`redirect_due`).
static PROMOTED: Mutex<Vec<u64>> = Mutex::new(Vec::new());
static PROMOTED_LEN: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    /// How much of `PROMOTED` this Worker has taken into `PENDING`.
    static SEEN: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Roots published that this Worker has not redirected at.
    static PENDING: std::cell::RefCell<Vec<u64>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn promoted(root: u64) {
    let mut p = lock(&PROMOTED);
    p.push(root);
    PROMOTED_LEN.store(p.len(), Ordering::Release);
}

/// Whether this Worker's thread, at a safepoint at `pc`, goes into the
/// function published there since it last looked: once a Worker for each
/// root, which then runs its loop as JIT code. The sample may be the JIT
/// function's own (its loop's safepoint): the resume then only enters it
/// again from its root.
fn redirect_due(pc: u64) -> bool {
    let len = PROMOTED_LEN.load(Ordering::Acquire);
    let seen = SEEN.with(|s| s.get());
    if len != seen {
        let p = lock(&PROMOTED);
        // (a fork's child: the list is its parent's, this Worker's count none of it)
        let from = if seen <= p.len() { seen } else { 0 };
        PENDING.with(|v| v.borrow_mut().extend_from_slice(&p[from..]));
        SEEN.with(|s| s.set(p.len()));
    }
    let hit = PENDING.with(|v| {
        let mut v = v.borrow_mut();
        match v.iter().position(|&a| a == pc) {
            Some(i) => {
                v.swap_remove(i);
                true
            }
            None => false,
        }
    });
    hit && crate::cgen::jit_serves(pc)
}

/// Whether tier-1 translated a block at `pc` and no unit has code on its
/// page: a sample there may be tier-1's, and a root worth translating. A
/// sample of a JIT function's own loop (which tier-1 never ran) or of a
/// unit's is not one.
fn tier1_sampled(pc: u64) -> bool {
    crate::with_jit_only(|j| j.translated.contains(&gex_abi::addr_key(pc, false))) && crate::cgen::unit_pages_of(&[pc / gex_abi::DISPATCH_PAGE]).is_empty()
}

/// Ask for a root (a hot sample's pc, or a callee the fallback keeps running):
/// translated here (`hotsync`, or a process that can have no helper), its
/// index then, or queued for the helper.
fn request(root: u64) -> Option<u32> {
    if !hot() || is_tier1_only(root) || !lib_wanted(root) || crate::cgen::index_of(root).is_some() {
        return None;
    }
    if !lock(&ASKED).get_or_insert_with(Default::default).insert(root) {
        return None;
    }
    let state = helper_state();
    if DRIVE.load(Ordering::Relaxed) == HOT_INLINE || state == HELPER_UNABLE {
        return translate_root(root, false);
    }
    lock(&QUEUE).push_back(root);
    QUEUE_SEQ.fetch_add(1, Ordering::AcqRel);
    #[cfg(feature = "shared-memory")]
    // SAFETY: a word of this module's statics, in the shared memory.
    unsafe {
        crate::warch::memory_atomic_notify(QUEUE_SEQ.as_ptr(), 1);
    }
    if state == HELPER_NONE {
        set_helper(HELPER_WANTED);
    }
    None
}

/// Calls JIT code and units made through the fallback (`cgen::gex_ftab_fallback`,
/// tier-1 run as a call-out), counted by target as the safepoint counts its
/// samples, direct-mapped and aging: a callee called `HOT_CALLS` times that
/// way is a root. A unit's call out of its image to a function nothing else
/// serves, made a few times at start-up, is not one: asked at its first call
/// (as at the first miss), they started a helper in each Wine process with
/// units, and Notepad's start took 3.70 s against 3.47 s on tier-1.
const CALL_SLOTS: usize = 1024;
static CALL_PC: [AtomicU64; CALL_SLOTS] = [const { AtomicU64::new(0) }; CALL_SLOTS];
static CALL_N: [AtomicU32; CALL_SLOTS] = [const { AtomicU32::new(0) }; CALL_SLOTS];
const HOT_CALLS: u32 = 16;

/// A call to `target` found no function and goes to the fallback.
pub(crate) fn fallback_call(target: u64) {
    if !hot() || target == 0 {
        return;
    }
    let s = ((target ^ (target >> 10)) as usize) % CALL_SLOTS;
    let n = if CALL_PC[s].load(Ordering::Relaxed) == target {
        CALL_N[s].fetch_add(1, Ordering::Relaxed) + 1
    } else if CALL_N[s].load(Ordering::Relaxed) == 0 {
        CALL_PC[s].store(target, Ordering::Relaxed);
        CALL_N[s].store(1, Ordering::Relaxed);
        1
    } else {
        // Someone else's slot: aged, as the safepoint's are.
        CALL_N[s].fetch_sub(1, Ordering::Relaxed);
        0
    };
    if n == HOT_CALLS {
        request(target);
    }
}

/// A safepoint at `pc` (not in the process's other mode), sampled `n` times
/// so far: true when the thread is to leave and resume at `pc` (lib.rs
/// `safepoint` traps): into a function published there, after one translated
/// here, or so that JS starts the helper.
pub(crate) fn hot_sample(pc: u64, n: u64) -> bool {
    if redirect_due(pc) {
        return true;
    }
    let before = helper_state();
    let at = HOT_AT.load(Ordering::Relaxed).max(1) as u64;
    if n >= at && n % at == 0 {
        // Inside a function its object's `.eh_frame` bounds, the root is
        // that function's entry (a root inside one is declined,
        // `mid_function`), and it takes effect at the function's next entry.
        // Elsewhere (a PE image's code) it is the sample's pc itself, which
        // the thread goes into through the redirect.
        let root = enclosing(pc).map_or(pc, |(_, _, entry)| entry);
        // (asked already, for the multiples after the first: no JIT lock taken)
        let asked = lock(&ASKED).as_ref().is_some_and(|s| s.contains(&root));
        if !asked && tier1_sampled(pc) && request(root).is_some() && root == pc {
            // Translated here: published now, so this Worker goes in at once
            // and takes no later redirect for it.
            let len = PROMOTED_LEN.load(Ordering::Acquire);
            SEEN.with(|s| {
                if s.get() + 1 == len {
                    s.set(len);
                }
            });
            return true;
        }
    }
    // No helper after all: the roots it was to take, one a sample, here.
    if before == HELPER_UNABLE {
        let next = lock(&QUEUE).pop_front();
        if let Some(root) = next {
            if translate_root(root, false).is_some() && root == pc {
                return true;
            }
        }
    }
    // The process has just come to want its helper: out to JS once, which
    // starts it (any later trap would too).
    before != HELPER_WANTED && helper_due()
}

/// JS, at a trap of the process's Worker: 1 once when the process wants its
/// helper (it is then being started), else 0.
#[no_mangle]
pub extern "C" fn gex_fjit_helper_wanted() -> i32 {
    if helper_due() {
        set_helper(HELPER_STARTING);
        1
    } else {
        0
    }
}

/// The helper's state, from JS: 1 its loop runs, 0 it has ended (another is
/// wanted for what is queued), -1 the process can have none (what is queued
/// is translated inline from now on).
#[no_mangle]
pub extern "C" fn gex_fjit_helper_up(up: i32) {
    match up {
        1 => set_helper(HELPER_UP),
        0 => set_helper(if lock(&QUEUE).is_empty() { HELPER_NONE } else { HELPER_WANTED }),
        _ => set_helper(HELPER_UNABLE),
    }
}

/// The word the helper waits on (`Atomics.waitAsync`): its address.
#[no_mangle]
pub extern "C" fn gex_fjit_bg_word() -> u32 {
    QUEUE_SEQ.as_ptr() as usize as u32
}

/// The helper: translate the oldest queued root, unpublished. Its module
/// number (the bytes at `gex_fjit_ptr`), -1 with nothing queued, -2 when the
/// JIT declined it.
#[no_mangle]
pub extern "C" fn gex_fjit_bg_translate() -> i32 {
    loop {
        let next = lock(&QUEUE).pop_front();
        let Some(root) = next else { return -1 };
        if !hot() || crate::cgen::index_of(root).is_some() {
            continue;
        }
        return match make(root, false) {
            Some((n, made)) => {
                lock(&MADE).get_or_insert_with(Default::default).insert(n, made);
                n as i32
            }
            None => -2,
        };
    }
}

/// The helper compiled module `n` (`compiled` 0: V8 refused it): publish it,
/// unless a page it read retired meanwhile. The index serving its root, or
/// -1.
#[no_mangle]
pub extern "C" fn gex_fjit_bg_publish(n: u32, compiled: i32) -> i32 {
    let made = lock(&MADE).as_mut().and_then(|m| m.remove(&n));
    let Some(made) = made else { return -1 };
    if compiled == 0 {
        if let Some(m) = lock(&MODULES).get_mut(n as usize) {
            m.wasm = Vec::new();
        }
        crate::cgen::write_dirs(made.fresh);
        return -1;
    }
    match publish_made(n, made, true) {
        Some(idx) => idx as i32,
        None => -1,
    }
}

/// `+name,-name` (`?fjitlibs=`): the objects the JIT is limited to (any `+`)
/// and kept from (`-`), by file name. `name@lo-hi` (hex) narrows a rule to
/// the functions whose entry lies at those offsets into their mapping (the
/// `name +0x..` a trap prints), for bisecting within an object. Checked at
/// every translation, the table lookups' (`gex.lookup`) as well as tier-1's
/// misses: JIT code calling through a pointer must not pull in objects the
/// rules keep out.
struct Rule {
    include: bool,
    name: String,
    range: Option<(u64, u64)>,
}

static LIBS: Mutex<Vec<Rule>> = Mutex::new(Vec::new());

#[no_mangle]
pub extern "C" fn gex_fjit_libs(ptr: u32, len: u32) {
    // The string is in the shim's heap (`gex_alloc`), above the guest's
    // range (`GUEST_LIMIT`): read it directly, not through `guest()`.
    // SAFETY: JS wrote `len` bytes at `ptr`, a live `gex_alloc` allocation.
    let spec = String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(ptr as usize as *const u8, len as usize) }).into_owned();
    let mut v = lock(&LIBS);
    v.clear();
    for w in spec.split(',').map(str::trim).filter(|w| !w.is_empty()) {
        // `watch=0xADDR` (a debugging aid riding on the same query): say when
        // the u64 there changes, at syscalls and safepoints (`watch_check`).
        if let Some(a) = w.strip_prefix("watch=") {
            if let Ok(a) = u64::from_str_radix(a.trim_start_matches("0x"), 16) {
                WATCH.store(a, Ordering::Relaxed);
            }
            continue;
        }
        // `callout=0|2`, `inplace=0`, `callouttrap=1`: the A/B switches of
        // the call-out and the in-place redispatch (bisection aids);
        // `provcheck=1`: check each provider guest call ends at its return;
        // `byobj=1`: count translations by object (`note_object`).
        if let Some(a) = w.strip_prefix("scanconst=") {
            if let Ok(a) = u64::from_str_radix(a.trim_start_matches("0x"), 16) {
                SCAN_CONST.store(a, Ordering::Relaxed);
            }
            continue;
        }
        if let Some(a) = w.strip_prefix("dumpmod=") {
            // `dumpmod=OBJ@OFF`: by the object's name and the hex offset from
            // its text mapping (as `object_off_at` prints), for a layout
            // whose addresses are not known ahead.
            if let Some((name, off)) = a.split_once('@') {
                if let Ok(off) = u64::from_str_radix(off.trim_start_matches("0x"), 16) {
                    *lock(&DUMP_OBJ) = Some((name.to_string(), off));
                }
            } else if let Ok(a) = u64::from_str_radix(a.trim_start_matches("0x"), 16) {
                DUMP_MOD.store(a, Ordering::Relaxed);
            }
            continue;
        }
        if let Some((k, v)) = w.split_once('=') {
            let v: i32 = v.parse().unwrap_or(1);
            match k {
                "callout" => crate::cgen::gex_set_callout(v),
                "inplace" => crate::gex_set_in_place(v),
                "callouttrap" => crate::cgen::TRAP_CALLOUTS.store(v != 0, Ordering::Relaxed),
                "provcheck" => crate::cgen::libprov::PROV_CHECK.store(v != 0, Ordering::Relaxed),
                "byobj" => BY_OBJECT_ON.store(v != 0, Ordering::Relaxed),
                "coutstat" => crate::cgen::COUT_STAT.store(v != 0, Ordering::Relaxed),
                // `hotn=N`: samples that make a pc hot (`?fjit=hot`).
                "hotn" => HOT_AT.store(v.max(1) as u32, Ordering::Relaxed),
                _ => crate::warn_line(&format!("gex: ?fjitlibs: no switch {k}\n")),
            }
            continue;
        }
        let (include, w) = match w.strip_prefix('-') {
            Some(n) => (false, n),
            None => (true, w.trim_start_matches('+')),
        };
        let hex = |x: &str| u64::from_str_radix(x.trim_start_matches("0x"), 16).ok();
        let (name, range) = match w.split_once('@') {
            Some((n, r)) => (n, r.split_once('-').and_then(|(lo, hi)| Some((hex(lo)?, hex(hi)?)))),
            None => (w, None),
        };
        v.push(Rule { include, name: name.to_string(), range });
    }
}

static WATCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static WATCH_LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MAX);
static WATCH_SAID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// `?fjitlibs=watch=0xADDR`: the u64 at ADDR changed since the last look
/// (any thread's): say where this thread is (`at`: syscall or safepoint).
pub(crate) fn watch_check(pc: u64, at: &str) {
    let a = WATCH.load(Ordering::Relaxed);
    if a == 0 {
        return;
    }
    // Not before the memory reaches it (the slice spans the maximum).
    if a + 8 > crate::warch::memory_size(0) as u64 * 65536 {
        return;
    }
    let Ok(v) = crate::guest().read_u64(a) else { return };
    let last = WATCH_LAST.swap(v, Ordering::Relaxed);
    if last != v && WATCH_SAID.fetch_add(1, Ordering::Relaxed) < 64 {
        let (thread, whose, vwhose) = (crate::cur(), crate::object_off_at(pc), crate::object_off_at(v));
        crate::warn_line(&format!(
            "[watch] {a:#x}: {last:#x} -> {v:#x} ({vwhose}), seen by thread {thread} at {at} pc {pc:#x} ({whose}), {} JIT modules\n",
            lock(&MODULES).len()
        ));
    }
}

fn lib_wanted(pc: u64) -> bool {
    let rules = lock(&LIBS);
    if rules.is_empty() {
        return true;
    }
    let (name, off) = crate::object_file_off(pc);
    let hit = |r: &Rule| r.name == name && r.range.is_none_or(|(lo, hi)| off >= lo && off < hi);
    if rules.iter().any(|r| !r.include && hit(r)) {
        return false;
    }
    !rules.iter().any(|r| r.include) || rules.iter().any(|r| r.include && hit(r))
}

/// JIT module `n`'s bytes.
#[no_mangle]
pub extern "C" fn gex_fjit_ptr(n: u32) -> u32 {
    lock(&MODULES).get(n as usize).map_or(0, |m| m.wasm.as_ptr() as u32)
}

#[no_mangle]
pub extern "C" fn gex_fjit_len(n: u32) -> u32 {
    lock(&MODULES).get(n as usize).map_or(0, |m| m.wasm.len() as u32)
}

/// JIT module `n`'s bridges (as `gex_cgen_regs`).
#[no_mangle]
pub extern "C" fn gex_fjit_regs(n: u32, buf: u32, cap: u32) -> u32 {
    let ms = lock(&MODULES);
    let Some(m) = ms.get(n as usize) else { return 0 };
    let k = m.regs.len().min(cap as usize);
    crate::cgen::put_u32s(&m.regs[..k], buf);
    m.regs.len() as u32
}

#[no_mangle]
pub extern "C" fn gex_fjit_slots(n: u32) -> u32 {
    lock(&MODULES).get(n as usize).map_or(0, |m| m.slots.min(u32::MAX as u64) as u32)
}

/// A Worker installed JIT module `n`: the directory for the pages it numbered.
#[no_mangle]
pub extern "C" fn gex_fjit_installed(n: u32) {
    let dirs = lock(&MODULES).get(n as usize).map(|m| m.dirs.clone()).unwrap_or_default();
    crate::cgen::write_dirs(dirs);
}

/// The translator's line (`gex_xlate::fjit::Jit::stats`: modules, time,
/// and how often its lock was found held), for the host to print as the
/// process ends. Not for a process the JIT did nothing in (no translation,
/// no hot root): every short-lived helper of Wine's printed a line of
/// zeros, on the console's error level.
#[no_mangle]
pub extern "C" fn gex_fjit_report() {
    if TRANSLATED.load(Ordering::Relaxed) == 0 && PROMOTED_LEN.load(Ordering::Relaxed) == 0 {
        return;
    }
    if let (true, Some(jit)) = (on(), JIT.get()) {
        crate::warn_line(&format!(
            "[gex] fjit: {} (translated {}, declined {}{})\n",
            jit.stats(),
            TRANSLATED.load(Ordering::Relaxed),
            DECLINED.load(Ordering::Relaxed),
            if hot() { format!(", hot roots {}, dropped {}", PROMOTED_LEN.load(Ordering::Relaxed), DROPPED.load(Ordering::Relaxed)) } else { String::new() }
        ));
    }
}

/// libffi's call thunks (gexcc-win's libffi, `gex.ffi_thunk`), by signature:
/// their slots. A forked child has its parent's with the memory it copied.
static FFI_THUNKS: Mutex<Option<HashMap<String, u32>>> = Mutex::new(None);

/// `gex.ffi_thunk`'s shim half: the slot of the call thunk for the wasm
/// signature in `buf` (`len` bytes, the shim's heap; `gex_cgen::ffi`), made
/// and published once per process as a JIT module, which every Worker
/// installs as it replays the function table's log (JS catches the asking
/// Worker up before handing the value back). `u32::MAX` for a signature
/// that is not one (said on stderr).
#[no_mangle]
pub extern "C" fn gex_ffi_thunk(buf: u32, len: u32) -> u32 {
    // SAFETY: JS wrote `len` bytes at `buf`, a `gex_alloc` block of this heap.
    let bytes = unsafe { std::slice::from_raw_parts(buf as usize as *const u8, len as usize) };
    let Ok(sig) = std::str::from_utf8(bytes) else {
        crate::warn_line("gex.ffi_thunk: the signature is not text\n");
        return u32::MAX;
    };
    if let Some(&k) = lock(&FFI_THUNKS).as_ref().and_then(|m| m.get(sig)) {
        return k;
    }
    let wasm = match gex_cgen::ffi::thunk(sig) {
        Ok(w) => w,
        Err(e) => {
            crate::warn_line(&format!("gex.ffi_thunk: {e}\n"));
            return u32::MAX;
        }
    };
    // (held across the publish, as `translate_root`: a Worker replaying the
    // log waits for the bytes rather than reading nothing)
    let mut modules = lock(&MODULES);
    let n = modules.len() as u32;
    let install = crate::cgen::publish(1, FJIT | n, gex_kernel::ftab::Tier::Jit, &[]);
    modules.push(Module { wasm, regs: Vec::new(), dirs: Vec::new(), slots: 0 });
    drop(modules);
    let base = crate::cgen::gex_ftab_install_base(install);
    // (two Workers making one at once: the first stays; the other's install
    // still takes a slot in every Worker's table, unused)
    *lock(&FFI_THUNKS).get_or_insert_with(Default::default).entry(sig.to_string()).or_insert(base)
}
