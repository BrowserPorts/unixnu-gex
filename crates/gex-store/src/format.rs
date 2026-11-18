//! The root kept across loads in its block store: what the programs
//! changed of the tree as the sources laid it, written into the store beside
//! the files' blocks, and laid over the sources again at the next boot.
//!
//! The store's block 0 holds two superblocks, written in turn, each naming
//! a generation: its number, the newest block of its records and how many
//! blocks those are. The records are a chain of blocks, each naming the one
//! before it, each with a checksum: a checkpoint (every record) and then a
//! segment per generation since (the records that changed, and the paths
//! that no longer have one). A record is a path's difference from the
//! sources: gone, a directory, a symlink, a file of the sources with its
//! mode and extended attributes changed (its bytes still the sources'), or
//! a file with its bytes (a small one) or its blocks in the store.
//!
//! A generation is written ([`Journal::write`]): the files' blocks first,
//! then the records, a flush, then the superblock, a flush. A block freed
//! meanwhile is not used again until the generation after the one that last
//! named it is written, so the one before stays whole. A load ([`load`])
//! reads the newest superblock whose records all check; one torn or failing
//! checks falls back to the one before. The files' bytes are not journalled
//! by the kernel: after a fall back, a file reads what was last written into
//! the blocks it had.
//!
//! A record names a path without its leading `/`.

use crate::{Errno, OP_FLUSH, OP_READ, OP_WRITE};
use std::collections::{BTreeMap, HashMap};

const SB_MAGIC: &[u8; 8] = b"gexroot\x01";
pub const SB_LEN: usize = 60;
/// Superblock `g` is at `(g % 2)` halves of block 0.
pub fn sb_at(gen: u64, bs: u64) -> u64 {
    (gen % 2) * (bs / 2)
}
const CHAIN_MAGIC: u32 = 0x4252_5847; // "GXRB"
/// A chain block's header: magic, checksum, generation, the block before, length.
pub const HDR: usize = 32;
/// The journal is folded into a new checkpoint once its records are more
/// bytes than the last checkpoint's, or once it takes this many blocks
/// (each generation's segment takes a block of its own at least, written
/// only as far as it is used): a checkpoint is written once per its own
/// size of journal, not once per its size in generations.
const JOURNAL_MAX: u64 = 512;

const CRC_TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

/// CRC-32 (IEEE).
pub fn crc32(b: &[u8]) -> u32 {
    let mut c = !0u32;
    for &x in b {
        c = CRC_TABLE[((c ^ x as u32) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

/// FNV-1a: a record's signature, which says whether it changed.
pub fn fnv(h: u64, b: &[u8]) -> u64 {
    let mut h = h;
    for &x in b {
        h = (h ^ x as u64).wrapping_mul(0x0100_0000_01b3);
    }
    h
}
pub const FNV0: u64 = 0xcbf2_9ce4_8422_2325;

pub type Xattrs = Vec<(String, Vec<u8>)>;

#[derive(Debug, Clone, PartialEq)]
pub enum Body {
    Inline(Vec<u8>),
    /// Size and the store's blocks (each plus one, 0 a hole).
    Blocks(u64, Vec<u32>),
    /// A lazy file still fetched from its URL: URL and size.
    Lazy(String, u64),
}

impl Body {
    pub fn size(&self) -> u64 {
        match self {
            Body::Inline(d) => d.len() as u64,
            Body::Blocks(size, _) | Body::Lazy(_, size) => *size,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Rec {
    /// A path of the sources removed, and all under it.
    Gone,
    Dir { mode: u32, mtime: i64, xattrs: Xattrs },
    Link { target: String },
    /// A file of the sources, its mode changed (read from older stores;
    /// [`Rec::Attrs`] is written instead).
    Mode { mode: u32 },
    /// A file of the sources, its mode or extended attributes changed, its
    /// bytes not, or a file of a layer laid after boot that has extended
    /// attributes: laid over the sources' file, or over the layer's when it
    /// is laid again, so a site's newer file keeps what was set on the old
    /// one (a `user.gex.mem64` record).
    Attrs { mode: u32, xattrs: Xattrs },
    /// `ino` names the file among this generation's records (hard links).
    File { ino: u64, mode: u32, mtime: i64, body: Body, xattrs: Xattrs },
}

#[derive(Default)]
struct W(Vec<u8>);

impl W {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.0.extend_from_slice(b);
    }
    fn xattrs(&mut self, x: &Xattrs) {
        self.u32(x.len() as u32);
        for (k, v) in x {
            self.bytes(k.as_bytes());
            self.bytes(v);
        }
    }
    fn rec(&mut self, path: &str, r: &Rec) {
        self.u8(TAG_PUT);
        self.bytes(path.as_bytes());
        match r {
            Rec::Gone => self.u8(0),
            Rec::Dir { mode, mtime, xattrs } => {
                self.u8(1);
                self.u32(*mode);
                self.u64(*mtime as u64);
                self.xattrs(xattrs);
            }
            Rec::Link { target } => {
                self.u8(2);
                self.bytes(target.as_bytes());
            }
            Rec::Mode { mode } => {
                self.u8(3);
                self.u32(*mode);
            }
            Rec::Attrs { mode, xattrs } => {
                self.u8(5);
                self.u32(*mode);
                self.xattrs(xattrs);
            }
            Rec::File { ino, mode, mtime, body, xattrs } => {
                self.u8(4);
                self.u64(*ino);
                self.u32(*mode);
                self.u64(*mtime as u64);
                self.xattrs(xattrs);
                match body {
                    Body::Inline(d) => {
                        self.u8(0);
                        self.bytes(d);
                    }
                    Body::Blocks(size, map) => {
                        self.u8(1);
                        self.u64(*size);
                        self.u32(map.len() as u32);
                        for &b in map {
                            self.u32(b);
                        }
                    }
                    Body::Lazy(url, size) => {
                        self.u8(2);
                        self.bytes(url.as_bytes());
                        self.u64(*size);
                    }
                }
            }
        }
    }
    fn mark(&mut self, gen: u64, checkpoint: bool) {
        self.u8(TAG_MARK);
        self.u64(gen);
        self.u8(checkpoint as u8);
    }
}

const TAG_MARK: u8 = 1;
const TAG_PUT: u8 = 2;
const TAG_DROP: u8 = 3;

/// Generation `gen`'s segment: the records that changed, then the paths
/// that no longer have one.
pub fn segment<'a, P: AsRef<str>>(gen: u64, puts: impl IntoIterator<Item = (P, Rec)>, drops: impl IntoIterator<Item = &'a str>) -> Vec<u8> {
    let mut j = W::default();
    j.mark(gen, false);
    for (p, r) in puts {
        j.rec(p.as_ref(), &r);
    }
    for p in drops {
        j.u8(TAG_DROP);
        j.bytes(p.as_bytes());
    }
    j.0
}

/// Generation `gen`'s checkpoint: every record.
pub fn checkpoint<P: AsRef<str>>(gen: u64, all: impl IntoIterator<Item = (P, Rec)>) -> Vec<u8> {
    let mut c = W::default();
    c.mark(gen, true);
    for (p, r) in all {
        c.rec(p.as_ref(), &r);
    }
    c.0
}

struct R<'a>(&'a [u8], usize);

impl R<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], Errno> {
        let b = self.0.get(self.1..self.1 + n).ok_or(Errno::EIO)?;
        self.1 += n;
        Ok(b)
    }
    fn u8(&mut self) -> Result<u8, Errno> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, Errno> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, Errno> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn bytes(&mut self) -> Result<Vec<u8>, Errno> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn str(&mut self) -> Result<String, Errno> {
        String::from_utf8(self.bytes()?).map_err(|_| Errno::EIO)
    }
    fn xattrs(&mut self) -> Result<Xattrs, Errno> {
        let n = self.u32()?;
        (0..n).map(|_| Ok((self.str()?, self.bytes()?))).collect()
    }
    fn rec(&mut self) -> Result<Rec, Errno> {
        Ok(match self.u8()? {
            0 => Rec::Gone,
            1 => Rec::Dir { mode: self.u32()?, mtime: self.u64()? as i64, xattrs: self.xattrs()? },
            2 => Rec::Link { target: self.str()? },
            3 => Rec::Mode { mode: self.u32()? },
            5 => Rec::Attrs { mode: self.u32()?, xattrs: self.xattrs()? },
            4 => {
                let (ino, mode, mtime, xattrs) = (self.u64()?, self.u32()?, self.u64()? as i64, self.xattrs()?);
                let body = match self.u8()? {
                    0 => Body::Inline(self.bytes()?),
                    1 => {
                        let size = self.u64()?;
                        let n = self.u32()?;
                        Body::Blocks(size, (0..n).map(|_| self.u32()).collect::<Result<_, _>>()?)
                    }
                    2 => Body::Lazy(self.str()?, self.u64()?),
                    _ => return Err(Errno::EIO),
                };
                Rec::File { ino, mode, mtime, body, xattrs }
            }
            _ => return Err(Errno::EIO),
        })
    }
}

/// One superblock.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sb {
    pub gen: u64,
    /// The newest block of the records, plus one (0: none).
    pub head: u32,
    /// The store's blocks in use or free (the allocator's `high`).
    pub high: u32,
    /// How many blocks the records take.
    pub chain: u32,
    /// The checkpoint's bytes and the journal's since.
    pub ck: u64,
    pub jb: u64,
}

impl Sb {
    pub fn encode(&self, bs: u32) -> [u8; SB_LEN] {
        let mut b = [0u8; SB_LEN];
        b[0..8].copy_from_slice(SB_MAGIC);
        b[8..12].copy_from_slice(&1u32.to_le_bytes());
        b[12..16].copy_from_slice(&bs.to_le_bytes());
        b[16..24].copy_from_slice(&self.gen.to_le_bytes());
        b[24..28].copy_from_slice(&self.head.to_le_bytes());
        b[28..32].copy_from_slice(&self.high.to_le_bytes());
        b[32..36].copy_from_slice(&self.chain.to_le_bytes());
        b[40..48].copy_from_slice(&self.ck.to_le_bytes());
        b[48..56].copy_from_slice(&self.jb.to_le_bytes());
        let c = crc32(&b[..56]);
        b[56..60].copy_from_slice(&c.to_le_bytes());
        b
    }
    /// `None`: no superblock here; `Some(Err)`: one, but torn.
    pub fn decode(b: &[u8], bs: u32) -> Option<Result<Sb, ()>> {
        if &b[0..8] != SB_MAGIC {
            return None;
        }
        let u32_at = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
        let u64_at = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        if crc32(&b[..56]) != u32_at(56) || u32_at(8) != 1 || u32_at(12) != bs {
            return Some(Err(()));
        }
        Some(Ok(Sb { gen: u64_at(16), head: u32_at(24), high: u32_at(28), chain: u32_at(32), ck: u64_at(40), jb: u64_at(48) }))
    }
}

/// What writing and reading generations needs of the store: the kernel's
/// block layer (gex-kernel `vfs::blocks`), or the editor's own.
pub trait Blocks {
    /// The block size.
    fn block(&self) -> u64;
    /// The store read or written at `off` directly, not through a cache.
    fn raw(&mut self, op: u32, off: u64, buf: &mut [u8]) -> Result<(), Errno>;
    /// A block for the records.
    fn alloc_meta(&mut self) -> Result<u32, Errno>;
    /// Blocks free for use again now.
    fn release(&mut self, v: Vec<u32>);
    /// How many blocks of the store are in use or free below the highest.
    fn high(&self) -> u32;
    /// The store made durable.
    fn flush(&mut self) -> Result<(), Errno> {
        self.raw(OP_FLUSH, 0, &mut [])
    }
}

/// `payload` as a chain of blocks after `prev` (plus one, 0 none), each
/// marked `gen`: the blocks, oldest first.
fn write_chain(s: &mut impl Blocks, payload: &[u8], gen: u64, prev: u32) -> Result<Vec<u32>, Errno> {
    let bs = s.block() as usize;
    let room = bs - HDR;
    let mut out: Vec<u32> = Vec::new();
    let mut prev = prev;
    let mut buf = vec![0u8; bs];
    for part in payload.chunks(room) {
        let b = match s.alloc_meta() {
            Ok(b) => b,
            Err(e) => {
                s.release(out);
                return Err(e);
            }
        };
        out.push(b);
        let n = HDR + part.len();
        buf[..n].fill(0);
        buf[0..4].copy_from_slice(&CHAIN_MAGIC.to_le_bytes());
        buf[8..16].copy_from_slice(&gen.to_le_bytes());
        buf[16..20].copy_from_slice(&prev.to_le_bytes());
        buf[20..24].copy_from_slice(&(part.len() as u32).to_le_bytes());
        buf[HDR..n].copy_from_slice(part);
        let c = crc32(&buf[8..n]);
        buf[4..8].copy_from_slice(&c.to_le_bytes());
        if let Err(e) = s.raw(OP_WRITE, b as u64 * bs as u64, &mut buf[..n]) {
            s.release(out);
            return Err(e);
        }
        prev = b + 1;
    }
    Ok(out)
}

/// The records `sb` names, oldest first, and their blocks; EIO for any
/// block that fails its checks.
fn read_chain(s: &mut impl Blocks, sb: &Sb) -> Result<(Vec<u8>, Vec<u32>), Errno> {
    let bs = s.block() as usize;
    let mut parts: Vec<Vec<u8>> = Vec::new();
    let mut chain = Vec::new();
    let mut at = sb.head;
    let mut buf = vec![0u8; bs];
    let mut newest = true;
    while at != 0 {
        if chain.len() as u32 >= sb.chain || at > sb.high {
            return Err(Errno::EIO);
        }
        let b = at - 1;
        s.raw(OP_READ, b as u64 * bs as u64, &mut buf)?;
        let u32_at = |i: usize| u32::from_le_bytes(buf[i..i + 4].try_into().unwrap());
        let gen = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        let len = u32_at(20) as usize;
        if u32_at(0) != CHAIN_MAGIC || len > bs - HDR || crc32(&buf[8..HDR + len]) != u32_at(4) || gen > sb.gen || (newest && gen != sb.gen) {
            return Err(Errno::EIO);
        }
        newest = false;
        parts.push(buf[HDR..HDR + len].to_vec());
        chain.push(b);
        at = u32_at(16);
    }
    if chain.len() as u32 != sb.chain {
        return Err(Errno::EIO);
    }
    parts.reverse();
    chain.reverse();
    Ok((parts.concat(), chain))
}

/// The records a stream leaves: the checkpoint's, then each segment's. A
/// tag or a record kind this build does not know is EIO, never skipped.
///
/// A file's `ino` names it among one generation's records only: each boot
/// numbers its files afresh, so two generations' records may give one
/// number to two files. Read back, a file is its generation and its number,
/// renumbered here so that the records' `ino`s are one numbering again:
/// paths a generation wrote as one file (hard links) share one, and no two
/// files of different generations do.
fn replay(stream: &[u8]) -> Result<BTreeMap<String, Rec>, Errno> {
    let mut r = R(stream, 0);
    let mut out = BTreeMap::new();
    let mut first = true;
    let mut gen = 0u64;
    let mut ids: HashMap<(u64, u64), u64> = HashMap::new();
    while r.1 < stream.len() {
        match r.u8()? {
            TAG_MARK => {
                gen = r.u64()?;
                let ck = r.u8()?;
                if first && ck != 1 {
                    return Err(Errno::EIO);
                }
                if ck == 1 {
                    out.clear();
                }
            }
            TAG_PUT => {
                let p = r.str()?;
                let mut rec = r.rec()?;
                if let Rec::File { ino, .. } = &mut rec {
                    let next = ids.len() as u64 + 1;
                    *ino = *ids.entry((gen, *ino)).or_insert(next);
                }
                out.insert(p, rec);
            }
            TAG_DROP => {
                out.remove(&r.str()?);
            }
            _ => return Err(Errno::EIO),
        }
        first = false;
    }
    Ok(out)
}

/// What a load found in the store ([`load`]).
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Found {
    /// Nothing kept: an empty store.
    Fresh,
    /// The newest generation, laid over the sources.
    Restored,
    /// The newest was torn or failed its checks: the one before it.
    FellBack,
    /// Something was kept, but no generation reads whole: started from
    /// the sources alone.
    Unreadable,
}

/// The generation last written or read, and the blocks its records take.
#[derive(Debug, Default)]
pub struct Journal {
    pub sb: Sb,
    /// The records' blocks, oldest first.
    pub chain: Vec<u32>,
}

impl Journal {
    /// The next generation's number.
    pub fn next_gen(&self) -> u64 {
        self.sb.gen + 1
    }

    /// Whether the next generation, whose segment is `segment` bytes, is to
    /// be a checkpoint instead: none yet, or the journal past its bound.
    pub fn fold(&self, segment: usize, bs: u64) -> bool {
        let room = bs - HDR as u64;
        let ck_blocks = self.sb.ck.div_ceil(room);
        let journal = self.sb.chain as u64 - ck_blocks + (segment as u64).div_ceil(room);
        self.sb.head == 0 || journal > JOURNAL_MAX || self.sb.jb + segment as u64 > self.sb.ck.max(room)
    }

    /// The next generation written: `payload` (a [`segment`], or a
    /// [`checkpoint`] when `fold`) as records after the last generation's,
    /// a flush, the superblock, a flush. The files' blocks the records name
    /// are the caller's to have written first. A checkpoint frees the
    /// chain before it; a failure frees what it took and leaves the last
    /// generation as it was.
    pub fn write(&mut self, s: &mut impl Blocks, payload: &[u8], fold: bool) -> Result<(), Errno> {
        let gen = self.next_gen();
        let prev = if fold { 0 } else { self.sb.head };
        let new = write_chain(s, payload, gen, prev)?;
        let sb = Sb {
            gen,
            head: *new.last().unwrap() + 1,
            high: s.high(),
            chain: if fold { new.len() as u32 } else { self.sb.chain + new.len() as u32 },
            ck: if fold { payload.len() as u64 } else { self.sb.ck },
            jb: if fold { 0 } else { self.sb.jb + payload.len() as u64 },
        };
        let bs = s.block();
        let wrote = (|| {
            s.flush()?;
            let mut b = sb.encode(bs as u32);
            s.raw(OP_WRITE, sb_at(gen, bs), &mut b)?;
            s.flush()
        })();
        if let Err(e) = wrote {
            s.release(new);
            return Err(e);
        }
        if fold {
            s.release(std::mem::replace(&mut self.chain, new));
        } else {
            self.chain.extend(new);
        }
        self.sb = sb;
        Ok(())
    }
}

/// What [`load`] read: what it found, the generation, its records, and
/// which blocks they and their chain take (block 0 included).
#[derive(Debug)]
pub struct Loaded {
    pub found: Found,
    pub journal: Journal,
    pub recs: BTreeMap<String, Rec>,
    pub used: Vec<bool>,
}

/// The store's newest generation that reads whole, else the one before it.
/// Nothing is written.
pub fn load(s: &mut impl Blocks) -> Loaded {
    let bs = s.block() as u32;
    let mut head = vec![0u8; bs as usize];
    let read = s.raw(OP_READ, 0, &mut head);
    let slots: Vec<Option<Result<Sb, ()>>> = if read.is_ok() {
        (0..2u64).map(|g| Sb::decode(&head[sb_at(g, bs as u64) as usize..sb_at(g, bs as u64) as usize + SB_LEN], bs)).collect()
    } else {
        vec![Some(Err(())), None]
    };
    let mut ok: Vec<Sb> = slots.iter().filter_map(|s| s.and_then(|r| r.ok())).collect();
    ok.sort_by(|a, b| b.gen.cmp(&a.gen));
    let torn = slots.iter().any(|s| matches!(s, Some(Err(()))));
    let any = slots.iter().any(|s| s.is_some());
    let max_gen = ok.first().map_or(0, |s| s.gen);
    let mut out = Loaded {
        found: if any { Found::Unreadable } else { Found::Fresh },
        journal: Journal { sb: Sb { gen: max_gen, ..Default::default() }, chain: Vec::new() },
        recs: BTreeMap::new(),
        used: vec![true],
    };
    for (i, sb) in ok.iter().enumerate() {
        let Ok((stream, chain)) = read_chain(s, sb) else { continue };
        let Ok(recs) = replay(&stream) else { continue };
        let mut mark = |b: u32| {
            let i = b as usize;
            if out.used.len() <= i {
                out.used.resize(i + 1, false);
            }
            out.used[i] = true;
        };
        for &b in &chain {
            mark(b);
        }
        for r in recs.values() {
            if let Rec::File { body: Body::Blocks(_, map), .. } = r {
                for &b in map {
                    if b != 0 {
                        mark(b - 1);
                    }
                }
            }
        }
        // The next generation goes over the other superblock: after a
        // fall back, the one that failed.
        out.journal = Journal { sb: *sb, chain };
        out.recs = recs;
        out.found = if i == 0 && !torn { Found::Restored } else { Found::FellBack };
        break;
    }
    if out.found != Found::Restored && out.found != Found::FellBack {
        // Fresh, or nothing whole: the store is used from block 1 up.
        out.journal.sb.head = 0;
    }
    out
}
