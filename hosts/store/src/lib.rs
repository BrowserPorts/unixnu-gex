//! store.wasm: gex-store's offline editor ([`gex_store::editor`]) for the
//! page (page/runtime/src/store.js), one store per instance.
//!
//! The page answers `store.io(which, op, offset, ptr, len)` against a store
//! file's sync access handle (`blocks.mjs` `handleOp`): 0, or a negative
//! errno. `which` is 0 for the store opened (`st_open`), 1 for a copy's
//! destination (`st_open_dest`). A copy reports with `store.progress(done,
//! total)`, which answers 0 to stop it. Every export answers 0 or more on success and a negative
//! errno on failure; one that returns text (a listing, a record, a link's
//! target) leaves it at `st_out()` and answers its length. Strings and
//! buffers are in this module's memory, from `st_alloc`.

use gex_store::editor::{Editor, Entry, Io, Kind};
use gex_store::format::Found;
use gex_store::Errno;
use std::cell::RefCell;

#[link(wasm_import_module = "store")]
extern "C" {
    fn io(which: u32, op: u32, offset: u64, ptr: *mut u8, len: u32) -> i32;
    fn progress(done: f64, total: f64) -> i32;
}

/// Store 0 (the one opened) or 1 (a copy's destination).
struct Host(u32);

impl Io for Host {
    fn op(&mut self, op: u32, off: u64, buf: &mut [u8]) -> Result<(), Errno> {
        // SAFETY: the page reads or writes `len` bytes at `ptr`, in this
        // module's memory, and nothing else.
        let r = unsafe { io(self.0, op, off, buf.as_mut_ptr(), buf.len() as u32) };
        if r < 0 {
            Err(Errno(-r))
        } else {
            Ok(())
        }
    }
}

thread_local! {
    static ED: RefCell<Option<Editor<Host>>> = const { RefCell::new(None) };
    static DEST: RefCell<Option<Editor<Host>>> = const { RefCell::new(None) };
    static OUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn with<R>(f: impl FnOnce(&mut Editor<Host>) -> Result<R, Errno>) -> Result<R, Errno> {
    ED.with(|e| match e.borrow_mut().as_mut() {
        Some(ed) => f(ed),
        None => Err(Errno::EINVAL),
    })
}

fn code(r: Result<i32, Errno>) -> i32 {
    r.unwrap_or_else(|e| -e.0)
}

/// SAFETY (every caller): the page passes a pointer and length from
/// `st_alloc` (or 0, 0).
unsafe fn text<'a>(p: *const u8, n: u32) -> Result<&'a str, Errno> {
    if n == 0 {
        return Ok("");
    }
    std::str::from_utf8(std::slice::from_raw_parts(p, n as usize)).map_err(|_| Errno::EINVAL)
}

fn out(s: String) -> Result<i32, Errno> {
    let n = s.len() as i32;
    OUT.with(|o| *o.borrow_mut() = s.into_bytes());
    Ok(n)
}

fn json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn kind(k: Kind) -> &'static str {
    match k {
        Kind::File => "file",
        Kind::Dir => "directory",
        Kind::Link => "symlink",
        Kind::Gone => "gone",
        Kind::Attrs => "attrs",
        Kind::Lazy => "lazy",
    }
}

/// `[path, kind, size, mode, mtime]`.
fn json_entry(out: &mut String, e: &Entry) {
    out.push('[');
    json_str(out, &e.path);
    out.push_str(&format!(",\"{}\",{},{},{}]", kind(e.kind), e.size, e.mode, e.mtime));
}

#[no_mangle]
pub extern "C" fn st_alloc(len: u32) -> *mut u8 {
    let mut v = vec![0u8; len.max(1) as usize].into_boxed_slice();
    let p = v.as_mut_ptr();
    std::mem::forget(v);
    p
}

/// # Safety
/// `p` and `len` from one `st_alloc`.
#[no_mangle]
pub unsafe extern "C" fn st_dealloc(p: *mut u8, len: u32) {
    drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(p, len.max(1) as usize)));
}

#[no_mangle]
pub extern "C" fn st_out() -> *const u8 {
    OUT.with(|o| o.borrow().as_ptr())
}

/// Open the store: blocks of `bs` bytes, files up to `inline` bytes in their
/// records. 0 a fresh store, 1 its newest generation, 2 the one before (the
/// newest torn); EIO when nothing reads.
#[no_mangle]
pub extern "C" fn st_open(bs: u32, inline: u32) -> i32 {
    code(Editor::open(Host(0), bs as u64, inline as u64).map(|ed| {
        let f = match ed.found() {
            Found::Fresh => 0,
            Found::Restored => 1,
            _ => 2,
        };
        ED.with(|e| *e.borrow_mut() = Some(ed));
        f
    }))
}

#[no_mangle]
pub extern "C" fn st_close() {
    ED.with(|e| *e.borrow_mut() = None);
}

/// The generation read or last written.
#[no_mangle]
pub extern "C" fn st_generation() -> f64 {
    with(|e| Ok(e.generation() as f64)).unwrap_or(-1.0)
}

/// Every record at or under the path, as JSON `[[path, kind, size, mode,
/// mtime], ...]` at `st_out`.
///
/// # Safety
/// See [`text`].
#[no_mangle]
pub unsafe extern "C" fn st_list(p: *const u8, n: u32) -> i32 {
    code(text(p, n).and_then(|path| {
        with(|e| {
            let mut s = String::from("[");
            for (i, x) in e.list(path)?.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                json_entry(&mut s, x);
            }
            s.push(']');
            out(s)
        })
    }))
}

/// The record at the path, as JSON `[path, kind, size, mode, mtime]`.
///
/// # Safety
/// See [`text`].
#[no_mangle]
pub unsafe extern "C" fn st_stat(p: *const u8, n: u32) -> i32 {
    code(text(p, n).and_then(|path| {
        with(|e| {
            let mut s = String::new();
            json_entry(&mut s, &e.stat(path)?);
            out(s)
        })
    }))
}

/// # Safety
/// See [`text`].
#[no_mangle]
pub unsafe extern "C" fn st_readlink(p: *const u8, n: u32) -> i32 {
    code(text(p, n).and_then(|path| with(|e| out(e.readlink(path)?))))
}

/// `len` bytes of the file into `dst` from `offset`: how many.
///
/// # Safety
/// See [`text`]; `dst` and `len` from `st_alloc`.
#[no_mangle]
pub unsafe extern "C" fn st_read(p: *const u8, n: u32, offset: u64, dst: *mut u8, len: u32) -> i32 {
    let buf = std::slice::from_raw_parts_mut(dst, len as usize);
    code(text(p, n).and_then(|path| with(|e| Ok(e.read(path, offset, buf)? as i32))))
}

/// `len` bytes from `src` into the file at `offset` (made with `mode` if
/// missing; emptied first when `truncate`), its time `mtime` seconds.
///
/// # Safety
/// See [`text`]; `src` and `len` from `st_alloc`.
#[no_mangle]
pub unsafe extern "C" fn st_write(p: *const u8, n: u32, offset: u64, src: *const u8, len: u32, mode: u32, mtime: f64, truncate: u32) -> i32 {
    let data = if len == 0 { &[][..] } else { std::slice::from_raw_parts(src, len as usize) };
    code(text(p, n).and_then(|path| with(|e| e.write(path, offset, data, mode, mtime as i64, truncate != 0).map(|()| 0))))
}

/// The record at the path and all under it gone; `hide`: the sources' file
/// there removed too.
///
/// # Safety
/// See [`text`].
#[no_mangle]
pub unsafe extern "C" fn st_remove(p: *const u8, n: u32, hide: u32) -> i32 {
    code(text(p, n).and_then(|path| with(|e| e.remove(path, hide != 0).map(|()| 0))))
}

/// # Safety
/// See [`text`].
#[no_mangle]
pub unsafe extern "C" fn st_mkdir(p: *const u8, n: u32, mode: u32, mtime: f64) -> i32 {
    code(text(p, n).and_then(|path| with(|e| e.mkdir(path, mode, mtime as i64).map(|()| 0))))
}

/// # Safety
/// See [`text`].
#[no_mangle]
pub unsafe extern "C" fn st_symlink(t: *const u8, tn: u32, p: *const u8, n: u32) -> i32 {
    code(text(t, tn).and_then(|target| text(p, n).and_then(|path| with(|e| e.symlink(target, path).map(|()| 0)))))
}

/// # Safety
/// See [`text`].
#[no_mangle]
pub unsafe extern "C" fn st_chmod(p: *const u8, n: u32, mode: u32) -> i32 {
    code(text(p, n).and_then(|path| with(|e| e.chmod(path, mode).map(|()| 0))))
}

/// # Safety
/// See [`text`].
#[no_mangle]
pub unsafe extern "C" fn st_rename(a: *const u8, an: u32, b: *const u8, bn: u32) -> i32 {
    code(text(a, an).and_then(|from| text(b, bn).and_then(|to| with(|e| e.rename(from, to).map(|()| 0)))))
}

/// The changes written as the next generation (every record when
/// `checkpoint`): 1 written, 0 nothing to write.
#[no_mangle]
pub extern "C" fn st_commit(checkpoint: u32) -> i32 {
    code(with(|e| e.commit(checkpoint != 0).map(|w| w as i32)))
}

/// Open a copy's destination (store 1), which must be empty.
#[no_mangle]
pub extern "C" fn st_open_dest(bs: u32, inline: u32) -> i32 {
    code(Editor::open(Host(1), bs as u64, inline as u64).map(|ed| {
        DEST.with(|d| *d.borrow_mut() = Some(ed));
        0
    }))
}

/// How long the destination's file needs to be, once a copy is written:
/// a compacted store is cut to it.
#[no_mangle]
pub extern "C" fn st_dest_len() -> f64 {
    DEST.with(|d| d.borrow().as_ref().map_or(-1.0, |e| e.used_len() as f64))
}

#[no_mangle]
pub extern "C" fn st_close_dest() {
    DEST.with(|d| *d.borrow_mut() = None);
}

/// The records under any of the paths (newline-separated; all when empty)
/// copied into the destination, packed, and written there as a checkpoint
/// (gex_store::editor::Editor::copy_into).
///
/// # Safety
/// See [`text`].
#[no_mangle]
pub unsafe extern "C" fn st_copy(p: *const u8, n: u32) -> i32 {
    code(text(p, n).and_then(|list| {
        let only: Vec<String> = list.split('\n').filter(|s| !s.is_empty()).map(String::from).collect();
        DEST.with(|d| {
            let mut d = d.borrow_mut();
            let dest = d.as_mut().ok_or(Errno::EINVAL)?;
            // SAFETY: the page's progress takes two numbers.
            with(|e| e.copy_into(dest, &only, &mut |done, total| unsafe { progress(done as f64, total as f64) } != 0).map(|()| 0))
        })
    }))
}

/// Where the file's bytes are in the store file, as JSON `[[offset,
/// length], ...]`, offset -1 for a hole; EINVAL for a file kept in its
/// record.
///
/// # Safety
/// See [`text`].
#[no_mangle]
pub unsafe extern "C" fn st_runs(p: *const u8, n: u32) -> i32 {
    code(text(p, n).and_then(|path| {
        with(|e| {
            let runs = e.runs(path)?;
            let parts: Vec<String> = runs.iter().map(|(o, l)| format!("[{},{}]", o.map_or(-1, |o| o as i64), l)).collect();
            out(format!("[{}]", parts.join(",")))
        })
    }))
}
