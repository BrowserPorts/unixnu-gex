//! A B-tree node's bytes (`btree_node_phys_t`), changed in place as APFS
//! 2236.140.6 changes them (the addresses are `apfs_invert`'s copy of the
//! library): the header, the table of contents (`kvloc_t` entries for
//! variable-size records, `kvoff_t` for fixed-size ones), the key area
//! growing forward from the table's end, the value area growing back from
//! the node's end (the root's from its `btree_info_t`), and the two free
//! lists that removed records leave.
//!
//! - The table of contents starts at 8 entries (a fixed-size tree's at its
//!   capacity, `node_format` 0x1000252d8) and grows only when an insert
//!   needs it, to `toc_need` (0x100025944); a removal shrinks it by 8 when
//!   16 or more slots are free.
//! - Keys take the free gap's low end, values its high end; lengths are
//!   rounded to 8 unless the tree is `KV_NONALIGNED`.
//! - A freed region of more than 3 bytes is pushed at its free list's head
//!   with an `nloc_t {next, len}` in its first bytes; every freed byte is
//!   counted in the list's length. An insert takes the first entry long
//!   enough (0x10003013c), its low front (0x100030348); a remainder under
//!   5 bytes leaves the chain but stays counted.
//! - When the gap is too small for what the free lists cannot give, the
//!   node is compacted (0x10002fc14): its records reinserted in order into
//!   a fresh node.

use super::Put;

/// `sizeof(btree_node_phys_t)`, `sizeof(btree_info_t)`.
pub const HDR: usize = 56;
pub const INFO: usize = 40;
/// `BTOFF_INVALID`; the value offset of a record whose value length is
/// the 0xfffe sentinel.
pub const OFF_INVALID: u16 = 0xffff;
pub const OFF_SENTINEL: u16 = 0xfffe;
/// `ENOSPC`.
pub const ENOSPC: i32 = 28;

/// `btn_flags`.
pub mod flags {
    pub const ROOT: u16 = 0x1;
    pub const LEAF: u16 = 0x2;
    pub const FIXED_KV_SIZE: u16 = 0x4;
    pub const HASHED: u16 = 0x8;
    pub const NOHEADER: u16 = 0x10;
}

/// `bt_flags`.
pub mod tree_flags {
    pub const UINT64_KEYS: u32 = 0x1;
    pub const SEQUENTIAL_INSERT: u32 = 0x2;
    pub const ALLOW_GHOSTS: u32 = 0x4;
    pub const EPHEMERAL: u32 = 0x8;
    pub const PHYSICAL: u32 = 0x10;
    pub const NONPERSISTENT: u32 = 0x20;
    pub const KV_NONALIGNED: u32 = 0x40;
    pub const HASHED: u32 = 0x80;
    pub const NOHEADER: u32 = 0x100;
}

fn u16a(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32a(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u64a(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// What a tree's nodes share: its flags, node size, fixed key and value
/// sizes (zero for variable-size records) and hash size (an index
/// value is a child identifier and its hash).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    pub bt_flags: u32,
    pub node_size: usize,
    pub key_size: usize,
    pub val_size: usize,
    pub hash_size: usize,
}

impl Shape {
    pub fn fixed(&self) -> bool {
        self.key_size != 0 && self.val_size != 0
    }
    fn ghosts(&self) -> bool {
        self.bt_flags & tree_flags::ALLOW_GHOSTS != 0
    }
    /// A length as space is reserved for it.
    pub fn r(&self, n: usize) -> usize {
        if self.bt_flags & tree_flags::KV_NONALIGNED != 0 {
            n
        } else {
            (n + 7) & !7
        }
    }
    /// An index entry's value length.
    pub fn index_val(&self) -> usize {
        8 + self.hash_size
    }
    /// A fixed-size node's capacity by space (`node_format`).
    fn fixed_capacity(&self, leaf: bool) -> usize {
        let vsz = if leaf { self.val_size } else { self.index_val() };
        ((self.node_size - HDR) / (self.key_size + vsz + 4)) & !1
    }
}

/// A table-of-contents entry: the key's offset in the key area and its
/// length, the value's offset back from the value area's end and its
/// length (a fixed-size tree's entries hold the offsets only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Loc {
    pub k: u16,
    pub kl: u16,
    pub v: u16,
    pub vl: u16,
}

/// Which free list.
#[derive(Clone, Copy, PartialEq, Eq)]
enum List {
    Key,
    Val,
}

/// A node, its block's bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    pub b: Vec<u8>,
}

impl Node {
    /// `node_format` (0x1000252d8): an empty node with flags `fl` (root,
    /// leaf, hashed, headerless) at `level`, its object header zero.
    pub fn format(s: &Shape, fl: u16, level: u16) -> Node {
        let mut n = Node { b: vec![0u8; s.node_size] };
        n.reformat(s, fl, level);
        n
    }

    /// The header past the object header, formatted afresh (the bytes
    /// from `btn_flags` on are zero first).
    fn reformat(&mut self, s: &Shape, fl: u16, level: u16) {
        let end = self.b.len() - if fl & flags::ROOT != 0 { INFO } else { 0 };
        self.b[0x20..end].fill(0);
        let mut f = fl & 0x1b;
        if s.fixed() {
            f |= flags::FIXED_KV_SIZE;
        }
        self.b.put16(0x20, f);
        self.b.put16(0x22, level);
        let toc = if s.fixed() { 4 * s.fixed_capacity(fl & flags::LEAF != 0) } else { 0x40 };
        self.b.put16(0x28, 0);
        self.b.put16(0x2a, toc as u16);
        self.b.put16(0x2c, 0);
        self.b.put16(0x2e, (s.node_size - HDR - if fl & flags::ROOT != 0 { INFO } else { 0 } - toc) as u16);
        self.b.put16(0x30, OFF_INVALID);
        self.b.put16(0x32, 0);
        self.b.put16(0x34, OFF_INVALID);
        self.b.put16(0x36, 0);
    }

    pub fn flags(&self) -> u16 {
        u16a(&self.b, 0x20)
    }
    pub fn set_flags(&mut self, f: u16) {
        self.b.put16(0x20, f);
    }
    pub fn level(&self) -> u16 {
        u16a(&self.b, 0x22)
    }
    pub fn nkeys(&self) -> usize {
        u32a(&self.b, 0x24) as usize
    }
    fn set_nkeys(&mut self, n: usize) {
        self.b.put32(0x24, n as u32);
    }
    pub fn is_root(&self) -> bool {
        self.flags() & flags::ROOT != 0
    }
    pub fn is_leaf(&self) -> bool {
        self.flags() & flags::LEAF != 0
    }
    fn is_fixed(&self) -> bool {
        self.flags() & flags::FIXED_KV_SIZE != 0
    }
    fn esz(&self) -> usize {
        if self.is_fixed() {
            4
        } else {
            8
        }
    }
    /// `btn_table_space.len`.
    pub fn toc_len(&self) -> usize {
        u16a(&self.b, 0x2a) as usize
    }
    fn set_toc_len(&mut self, n: usize) {
        self.b.put16(0x2a, n as u16);
    }
    /// `btn_free_space`: offset (from the key area's start) and length.
    pub fn free_off(&self) -> usize {
        u16a(&self.b, 0x2c) as usize
    }
    pub fn free_len(&self) -> usize {
        u16a(&self.b, 0x2e) as usize
    }
    fn set_free(&mut self, off: usize, len: usize) {
        self.b.put16(0x2c, off as u16);
        self.b.put16(0x2e, len as u16);
    }
    fn head_at(l: List) -> usize {
        match l {
            List::Key => 0x30,
            List::Val => 0x34,
        }
    }
    /// The key and value free lists' total lengths.
    pub fn key_free_len(&self) -> usize {
        u16a(&self.b, 0x32) as usize
    }
    pub fn val_free_len(&self) -> usize {
        u16a(&self.b, 0x36) as usize
    }
    /// Where the key area starts (the table of contents' end).
    pub fn kstart(&self) -> usize {
        HDR + u16a(&self.b, 0x28) as usize + self.toc_len()
    }
    /// Where the value area ends.
    pub fn vend(&self) -> usize {
        self.b.len() - if self.is_root() { INFO } else { 0 }
    }
    fn toc_at(&self, i: usize) -> usize {
        HDR + u16a(&self.b, 0x28) as usize + self.esz() * i
    }

    /// Table-of-contents entry `i`; a fixed-size node's lengths are the
    /// tree's.
    pub fn loc(&self, s: &Shape, i: usize) -> Loc {
        let at = self.toc_at(i);
        if self.is_fixed() {
            let vl = if self.is_leaf() { s.val_size } else { s.index_val() };
            Loc { k: u16a(&self.b, at), kl: s.key_size as u16, v: u16a(&self.b, at + 2), vl: vl as u16 }
        } else {
            Loc { k: u16a(&self.b, at), kl: u16a(&self.b, at + 2), v: u16a(&self.b, at + 4), vl: u16a(&self.b, at + 6) }
        }
    }
    fn set_loc(&mut self, i: usize, l: Loc) {
        let at = self.toc_at(i);
        if self.is_fixed() {
            self.b.put16(at, l.k);
            self.b.put16(at + 2, l.v);
        } else {
            self.b.put16(at, l.k);
            self.b.put16(at + 2, l.kl);
            self.b.put16(at + 4, l.v);
            self.b.put16(at + 6, l.vl);
        }
    }
    pub fn key(&self, s: &Shape, i: usize) -> &[u8] {
        let l = self.loc(s, i);
        if l.k == OFF_INVALID {
            return &[];
        }
        let st = self.kstart() + l.k as usize;
        &self.b[st..st + l.kl as usize]
    }
    /// Record `i`'s value: none for a ghost or the sentinel.
    pub fn val(&self, s: &Shape, i: usize) -> Option<&[u8]> {
        let l = self.loc(s, i);
        if l.v >= OFF_SENTINEL {
            return None;
        }
        let e = self.vend() - l.v as usize;
        Some(&self.b[e..e + l.vl as usize])
    }
    /// Record `i`'s value length as the space computations take it
    /// (`btree_node_val_len`, 0x100025a48): none for a ghost or the
    /// sentinel, an index entry's child identifier and hash.
    pub fn val_len(&self, s: &Shape, i: usize) -> usize {
        let l = self.loc(s, i);
        if l.v >= OFF_SENTINEL {
            0
        } else if !self.is_leaf() {
            s.index_val()
        } else {
            l.vl as usize
        }
    }
    /// An index entry's child identifier.
    pub fn child(&self, s: &Shape, i: usize) -> u64 {
        u64a(self.val(s, i).expect("an index entry with no value"), 0)
    }
    /// The size record `i` takes (its key and value, rounded).
    pub fn entry_size(&self, s: &Shape, i: usize) -> usize {
        let l = self.loc(s, i);
        let k = if l.k == OFF_INVALID { 0 } else { s.r(l.kl as usize) };
        let v = if l.v >= OFF_SENTINEL { 0 } else { s.r(l.vl as usize) };
        k + v
    }

    /// `toc_need` (0x100025944): the entries the table of contents needs
    /// for `extra` more records.
    pub fn toc_need(&self, s: &Shape, extra: isize) -> usize {
        let n = (self.nkeys() as isize + extra).max(0) as usize;
        if !self.is_fixed() {
            return ((n + 7) & !7).max(8);
        }
        if !s.ghosts() {
            return self.toc_len() / 4;
        }
        let m = s.fixed_capacity(self.is_leaf());
        if n <= m {
            m
        } else {
            (n + 7) & !7
        }
    }

    /// The free space a node has for records: the table's spare slots
    /// past what it needs, the gap and the free lists (0x10002f620).
    pub fn free(&self, s: &Shape) -> usize {
        let spare = if self.is_fixed() && !s.ghosts() {
            0
        } else {
            self.toc_len().saturating_sub(self.toc_need(s, 0) * self.esz())
        };
        spare + self.free_len() + self.key_free_len() + self.val_free_len()
    }

    /// `has_room` (0x10002791c): whether records of these key and value
    /// lengths (and `ea` + `eb` more bytes) fit, and the bytes the table of
    /// contents would grow by.
    pub fn has_room(&self, s: &Shape, klens: &[usize], vlens: &[usize], ea: usize, eb: usize) -> (bool, usize) {
        let esz = self.esz();
        let cnt = klens.len();
        let cur = self.toc_need(s, 0);
        if self.is_fixed() && !s.ghosts() && self.nkeys() + cnt > cur {
            return (false, 0x7fff_ffff);
        }
        let new = self.toc_need(s, cnt as isize);
        let grow = (new * esz).saturating_sub(self.toc_len());
        let cap = self.toc_len() / esz;
        let need: usize = klens.iter().map(|&k| s.r(k)).sum::<usize>() + vlens.iter().map(|&v| s.r(v)).sum::<usize>() + ea + eb + new.saturating_sub(cur) * esz;
        let avail = cap.saturating_sub(cur) * esz + self.free_len() + self.key_free_len() + self.val_free_len();
        (need <= avail, grow)
    }

    /// Where a free-list entry's `nloc_t` is.
    fn nloc_at(&self, l: List, off: u16) -> usize {
        match l {
            List::Key => self.kstart() + off as usize,
            List::Val => self.vend() - off as usize,
        }
    }

    /// Pushes a freed region on its list (every free site).
    fn push(&mut self, s: &Shape, l: List, off: u16, len: usize) {
        let len = s.r(len);
        let h = Self::head_at(l);
        if len > 3 {
            let at = self.nloc_at(l, off);
            let head = u16a(&self.b, h);
            self.b.put16(at, head);
            self.b.put16(at + 2, len as u16);
            self.b.put16(h, off);
        }
        let t = u16a(&self.b, h + 2);
        self.b.put16(h + 2, t.wrapping_add(len as u16));
    }

    /// The first entry of list `l` long enough for `len` bytes, and its
    /// predecessor (0xffff: the head) (0x10003013c).
    fn first_fit(&self, s: &Shape, l: List, len: usize) -> (u16, u16) {
        let want = s.r(len);
        let mut prev = OFF_INVALID;
        let mut cur = u16a(&self.b, Self::head_at(l));
        let mut guard = 0;
        while cur != OFF_INVALID && guard < self.b.len() {
            let at = self.nloc_at(l, cur);
            let elen = u16a(&self.b, at + 2) as usize;
            if elen >= want {
                return (prev, cur);
            }
            prev = cur;
            cur = u16a(&self.b, at);
            guard += 1;
        }
        (OFF_INVALID, OFF_INVALID)
    }

    /// Takes `len` bytes at the front of list `l`'s entry at `off`
    /// (0x100030348).
    fn take(&mut self, s: &Shape, l: List, len: usize, prev: u16, off: u16) {
        let want = s.r(len);
        let h = Self::head_at(l);
        let t = u16a(&self.b, h + 2);
        self.b.put16(h + 2, t.wrapping_sub(want as u16));
        if prev == OFF_INVALID && u16a(&self.b, h) != off {
            return;
        }
        let at = self.nloc_at(l, off);
        let next = u16a(&self.b, at);
        let rem = (u16a(&self.b, at + 2) as usize).wrapping_sub(want) & 0xffff;
        let link = if prev == OFF_INVALID { h } else { self.nloc_at(l, prev) };
        if rem < 5 {
            self.b.put16(link, next);
        } else {
            let noff = match l {
                List::Key => off as usize + want,
                List::Val => off as usize - want,
            } as u16;
            self.b.put16(link, noff);
            let nat = self.nloc_at(l, noff);
            self.b.put16(nat, next);
            self.b.put16(nat + 2, rem as u16);
        }
    }

    /// Fresh space from the gap (0x100030440): a key at its low end, a
    /// value at its high end; the offset.
    fn gap_alloc(&mut self, s: &Shape, l: List, len: usize) -> Result<u16, i32> {
        let want = s.r(len);
        let (off, flen) = (self.free_off(), self.free_len());
        if flen < want {
            return Err(ENOSPC);
        }
        Ok(match l {
            List::Key => {
                self.set_free(off + want, flen - want);
                off as u16
            }
            List::Val => {
                self.set_free(off, flen - want);
                (self.vend() - self.kstart() - off - (flen - want)) as u16
            }
        })
    }

    /// Space for `len` bytes (0x100030440): the first free-list entry long
    /// enough (the list as it is now, the record's old space pushed),
    /// else the gap.
    fn space_alloc(&mut self, s: &Shape, l: List, len: usize) -> Result<u16, i32> {
        let (prev, off) = self.first_fit(s, l, len);
        if off != OFF_INVALID {
            self.take(s, l, len, prev, off);
            return Ok(off);
        }
        self.gap_alloc(s, l, len)
    }

    /// Grows the table of contents by `grow` bytes: the key area moves up
    /// and the gap left is zeroed (0x10002a224, 0x100030034).
    fn toc_grow(&mut self, grow: usize) {
        if grow == 0 {
            return;
        }
        let ks = self.kstart();
        let used = self.free_off();
        self.b.copy_within(ks..ks + used, ks + grow);
        self.b[ks..ks + grow].fill(0);
        let (fo, fl) = (self.free_off(), self.free_len());
        self.set_toc_len(self.toc_len() + grow);
        self.set_free(fo, fl - grow);
    }

    /// Shrinks the table of contents by `by` bytes: the key area moves
    /// down, its old tail left as it was (0x100030034).
    fn toc_shrink(&mut self, by: usize) {
        if by == 0 {
            return;
        }
        let ks = self.kstart();
        let used = self.free_off();
        self.b.copy_within(ks..ks + used, ks - by);
        let (fo, fl) = (self.free_off(), self.free_len());
        self.set_toc_len(self.toc_len() - by);
        self.set_free(fo, fl + by);
    }

    /// Resizes the table of contents to `entries` entries.
    fn toc_resize(&mut self, entries: usize) {
        let want = entries * self.esz();
        let have = self.toc_len();
        if want > have {
            self.toc_grow(want - have);
        } else {
            self.toc_shrink(have - want);
        }
    }

    /// `btree_node_insert_internal` (0x10002a224): record (`key`, `val`) at
    /// table slot `idx`. A value of length 0xfffe (`sentinel`) takes no
    /// space and records the sentinel.
    pub fn insert_at(&mut self, s: &Shape, idx: usize, key: Option<&[u8]>, val: Option<&[u8]>, sentinel: bool) -> Result<(), i32> {
        let key = key.filter(|k| !k.is_empty());
        let kl = key.map_or(0, |k| k.len());
        let vl = if sentinel { 0 } else { val.map_or(0, |v| v.len()) };
        let val = val.filter(|_| vl != 0);
        let (ok, grow) = self.has_room(s, &[kl], &[vl], 0, 0);
        if !ok {
            return Err(ENOSPC);
        }
        let (mut kprev, mut koff) = (OFF_INVALID, OFF_INVALID);
        let (mut vprev, mut voff) = (OFF_INVALID, OFF_INVALID);
        if key.is_some() {
            (kprev, koff) = self.first_fit(s, List::Key, kl);
        }
        if val.is_some() {
            (vprev, voff) = self.first_fit(s, List::Val, vl);
        }
        let fresh = if koff == OFF_INVALID { s.r(kl) } else { 0 } + if voff == OFF_INVALID { s.r(vl) } else { 0 };
        if self.free_len() < grow + fresh {
            self.compact(s, 1);
            koff = OFF_INVALID;
            voff = OFF_INVALID;
        } else {
            self.toc_grow(grow);
        }
        if key.is_some() {
            if koff == OFF_INVALID {
                koff = self.gap_alloc(s, List::Key, kl)?;
            } else {
                self.take(s, List::Key, kl, kprev, koff);
            }
        }
        if val.is_some() {
            if voff == OFF_INVALID {
                voff = self.gap_alloc(s, List::Val, vl)?;
            } else {
                self.take(s, List::Val, vl, vprev, voff);
            }
        }
        if vl == 0 {
            voff = if sentinel { OFF_SENTINEL } else { OFF_INVALID };
        }
        let n = self.nkeys();
        if idx < n {
            let (a, e) = (self.toc_at(idx), self.esz());
            self.b.copy_within(a..a + e * (n - idx), a + e);
        }
        self.set_nkeys(n + 1);
        let vlen_raw = if sentinel { OFF_SENTINEL } else { vl as u16 };
        self.set_loc(idx, Loc { k: koff, kl: kl as u16, v: voff, vl: vlen_raw });
        if let Some(k) = key {
            let at = self.kstart() + koff as usize;
            self.b[at..at + kl].copy_from_slice(k);
        }
        if let Some(v) = val {
            let at = self.vend() - voff as usize;
            self.b[at..at + vl].copy_from_slice(v);
        }
        Ok(())
    }

    /// `btree_node_compact` (0x10002fc14): the records reinserted, in
    /// order, into the node formatted afresh with room in its table for
    /// `extra` more. A root keeps its info; another node keeps its object
    /// header.
    pub fn compact(&mut self, s: &Shape, extra: usize) {
        let old = self.clone();
        let fl = self.flags();
        let level = self.level();
        if self.is_root() {
            let end = self.vend();
            self.b[HDR..end].fill(0);
            self.set_nkeys(0);
            self.b.put16(0x28, 0);
            self.set_free(0, end - self.kstart());
            self.b.put16(0x30, OFF_INVALID);
            self.b.put16(0x32, 0);
            self.b.put16(0x34, OFF_INVALID);
            self.b.put16(0x36, 0);
        } else {
            let hdr: Vec<u8> = self.b[..0x20].to_vec();
            self.b.fill(0);
            self.b[..0x20].copy_from_slice(&hdr);
            self.reformat(s, fl, level);
        }
        let need = old.toc_need(s, extra as isize);
        self.toc_resize(need);
        for i in 0..old.nkeys() {
            let l = old.loc(s, i);
            let k = (l.k != OFF_INVALID).then(|| old.key(s, i).to_vec());
            let sentinel = l.v == OFF_SENTINEL;
            let v = old.val(s, i).map(|v| v.to_vec());
            self.insert_at(s, i, k.as_deref(), v.as_deref(), sentinel).expect("a compacted node holding what it held");
        }
    }

    /// `node_remove` (0x10002c064): record `idx` out, its space to the
    /// free lists, the table shrunk when 16 slots are spare. A root left
    /// empty becomes an empty root leaf unless `keep_root`.
    pub fn remove(&mut self, s: &Shape, idx: usize, keep_root: bool) {
        let l = self.loc(s, idx);
        if l.k != OFF_INVALID {
            self.push(s, List::Key, l.k, l.kl as usize);
        }
        if l.v < OFF_SENTINEL {
            self.push(s, List::Val, l.v, l.vl as usize);
        }
        let n = self.nkeys();
        let (a, end, e) = (self.toc_at(idx), self.toc_at(n), self.esz());
        self.b.copy_within(a + e..end, a);
        self.set_nkeys(n - 1);
        self.shrink_after_remove(s);
        if self.is_root() && self.nkeys() == 0 && !keep_root {
            let fl = flags::ROOT | flags::LEAF | (self.flags() & (flags::HASHED | flags::NOHEADER));
            self.reformat(s, fl, 0);
        }
    }

    fn shrink_after_remove(&mut self, s: &Shape) {
        let esz = self.esz();
        let cap = self.toc_len() / esz;
        let n = self.nkeys();
        if cap < n + 16 {
            return;
        }
        if !self.is_fixed() {
            self.toc_shrink(8 * esz);
        } else if s.ghosts() {
            let m = s.fixed_capacity(self.is_leaf());
            if m + 8 <= cap {
                self.toc_shrink(8 * esz);
            } else if cap > m {
                self.toc_shrink((cap - m) * esz);
            }
        }
    }

    /// `btree_node_entry_update` (0x100029918): record `idx`'s key and/or
    /// value replaced (`idx` == the record count appends).
    pub fn update(&mut self, s: &Shape, idx: usize, key: Option<&[u8]>, val: Option<&[u8]>, sentinel: bool) -> Result<(), i32> {
        let n = self.nkeys();
        let vlen = if sentinel { 0 } else { val.map_or(0, |v| v.len()) };
        let (ok, okl, old_vl, old_v) = if idx < n {
            let l = self.loc(s, idx);
            let okl = if l.k == OFF_INVALID { 0 } else { l.kl as usize };
            let ovl = if l.v < OFF_SENTINEL { l.vl as usize } else { 0 };
            (l.k, okl, ovl, l.v)
        } else {
            (OFF_INVALID, 0, 0, OFF_INVALID)
        };
        let dk: isize = if key.is_some() { key.unwrap().len() as isize - okl as isize } else { 0 };
        let mut dv: isize = if val.is_some() { vlen as isize - old_vl as isize } else { 0 };
        let (mut kprev, mut koff) = (OFF_INVALID, ok);
        let mut vprev;
        let mut slot_v = old_v;
        if dk == 0 && dv == 0 {
            if sentinel && old_v != OFF_SENTINEL {
                slot_v = OFF_SENTINEL;
                dv = 1;
            }
        } else {
            let gk = if key.is_some() { s.r(key.unwrap().len()) as isize - s.r(okl) as isize } else { 0 };
            let gv = if val.is_some() { s.r(vlen) as isize - s.r(old_vl) as isize } else { 0 };
            if (self.free(s) as isize) < gk + gv {
                return Err(ENOSPC);
            }
            let kl = key.map_or(0, |k| k.len());
            let mut fresh = 0usize;
            vprev = OFF_INVALID;
            koff = OFF_INVALID;
            if kl != 0 && dk != 0 {
                (kprev, koff) = self.first_fit(s, List::Key, kl);
                if koff == OFF_INVALID {
                    if dk < 0 {
                        kprev = OFF_INVALID;
                        koff = ok;
                    } else {
                        fresh = s.r(kl);
                    }
                }
            }
            let mut voff_new = OFF_INVALID;
            if vlen != 0 && dv != 0 {
                let (p, o) = self.first_fit(s, List::Val, vlen);
                vprev = p;
                voff_new = o;
                if o == OFF_INVALID {
                    if dv < 0 {
                        vprev = OFF_INVALID;
                        voff_new = old_v;
                    } else {
                        fresh += s.r(vlen);
                    }
                }
            }
            let fl_before = self.free_len();
            let free_key = ok != OFF_INVALID && dk != 0 && okl != 0;
            if free_key {
                self.push(s, List::Key, ok, okl);
                if koff != OFF_INVALID && kprev == OFF_INVALID && u16a(&self.b, 0x30) == ok && koff != ok {
                    kprev = ok;
                }
            }
            let free_val = old_v < OFF_SENTINEL && old_vl != 0 && dv != 0;
            if free_val {
                self.push(s, List::Val, old_v, old_vl);
                if voff_new != OFF_INVALID && vprev == OFF_INVALID && u16a(&self.b, 0x34) == old_v && voff_new != old_v {
                    vprev = old_v;
                }
            }
            if fl_before < fresh {
                if idx < n {
                    let at = self.toc_at(idx);
                    if self.is_fixed() {
                        if free_key {
                            self.b.put16(at, OFF_INVALID);
                        }
                        if free_val {
                            self.b.put16(at + 2, OFF_INVALID);
                        }
                    } else {
                        if free_key {
                            self.b.put32(at, 0xffff);
                        }
                        if free_val {
                            self.b.put32(at + 4, 0xffff);
                        }
                    }
                }
                self.compact(s, 0);
                kprev = OFF_INVALID;
                koff = OFF_INVALID;
                vprev = OFF_INVALID;
                voff_new = OFF_INVALID;
            }
            // The key.
            if dk == 0 {
                koff = if idx < n { self.loc(s, idx).k } else { OFF_INVALID };
            } else if koff == OFF_INVALID {
                koff = self.space_alloc(s, List::Key, kl)?;
            } else {
                self.take(s, List::Key, kl, kprev, koff);
            }
            // The value.
            if dv == 0 {
                slot_v = if idx < n { self.loc(s, idx).v } else { OFF_INVALID };
            } else if vlen == 0 {
                slot_v = if sentinel { OFF_SENTINEL } else { OFF_INVALID };
            } else {
                slot_v = if voff_new == OFF_INVALID {
                    self.space_alloc(s, List::Val, vlen)?
                } else {
                    self.take(s, List::Val, vlen, vprev, voff_new);
                    voff_new
                };
            }
        }
        let at = self.toc_at(idx);
        if self.is_fixed() {
            if dk != 0 {
                self.b.put16(at, koff);
            }
            if dv != 0 {
                self.b.put16(at + 2, slot_v);
            }
        } else {
            if dk != 0 {
                self.b.put16(at, koff);
                self.b.put16(at + 2, key.map_or(0, |k| k.len()) as u16);
            }
            if dv != 0 {
                self.b.put16(at + 4, slot_v);
                self.b.put16(at + 6, if sentinel { OFF_SENTINEL } else { vlen as u16 });
            }
        }
        if let Some(k) = key.filter(|k| !k.is_empty()) {
            let o = if dk != 0 { koff } else { self.loc(s, idx).k };
            let a = self.kstart() + o as usize;
            self.b[a..a + k.len()].copy_from_slice(k);
        }
        if let Some(v) = val.filter(|_| vlen != 0) {
            let o = if dv != 0 { slot_v } else { self.loc(s, idx).v };
            let a = self.vend() - o as usize;
            self.b[a..a + vlen].copy_from_slice(v);
        }
        Ok(())
    }

    /// Makes room in the table for `count` more records before records
    /// move in: resized when the gap allows, else compacted.
    fn toc_room(&mut self, s: &Shape, count: usize) {
        let want = self.toc_need(s, count as isize) * self.esz();
        if want > self.toc_len() {
            if self.free_len() >= want - self.toc_len() {
                self.toc_grow(want - self.toc_len());
            } else {
                self.compact(s, count);
            }
        }
    }

    /// After records moved out: the table shrunk to what 8 more need.
    fn toc_trim_after_move(&mut self, s: &Shape) {
        let want = self.toc_need(s, 8) * self.esz();
        if self.toc_len() > want {
            self.toc_shrink(self.toc_len() - want);
        }
    }

    /// The record at `i` as owned bytes (key, value, sentinel).
    fn record(&self, s: &Shape, i: usize) -> (Option<Vec<u8>>, Option<Vec<u8>>, bool) {
        let l = self.loc(s, i);
        let k = (l.k != OFF_INVALID).then(|| self.key(s, i).to_vec());
        (k, self.val(s, i).map(|v| v.to_vec()), l.v == OFF_SENTINEL)
    }

    /// `bt_move_entries` (0x10002f698) with a positive count: the last
    /// `count` records of `self` to the front of `dst`.
    pub fn move_last_to_front(&mut self, s: &Shape, dst: &mut Node, count: usize) {
        if count == 0 {
            return;
        }
        dst.toc_room(s, count);
        let n = dst.nkeys();
        let (a, e) = (dst.toc_at(0), dst.esz());
        dst.b.copy_within(a..a + e * n, a + e * count);
        for i in 0..count {
            dst.set_loc(i, Loc { k: OFF_INVALID, kl: 0, v: OFF_INVALID, vl: 0 });
        }
        dst.set_nkeys(n + count);
        for j in (0..count).rev() {
            let src = self.nkeys() - 1;
            let (k, v, sent) = self.record(s, src);
            dst.update(s, j, k.as_deref(), v.as_deref(), sent).expect("records moving into room made for them");
            let l = self.loc(s, src);
            self.set_nkeys(src);
            if l.k != OFF_INVALID {
                self.push(s, List::Key, l.k, l.kl as usize);
            }
            if l.v < OFF_SENTINEL {
                self.push(s, List::Val, l.v, l.vl as usize);
            }
        }
        self.toc_trim_after_move(s);
    }

    /// `bt_move_entries` with a negative count: the first `count` records
    /// of `src` appended to `self`.
    pub fn append_from_front(&mut self, s: &Shape, src: &mut Node, count: usize) {
        if count == 0 {
            return;
        }
        self.toc_room(s, count);
        for i in 0..count {
            let (k, v, sent) = src.record(s, i);
            let n = self.nkeys();
            self.insert_at(s, n, k.as_deref(), v.as_deref(), sent).expect("records moving into room made for them");
            let l = src.loc(s, i);
            if l.k != OFF_INVALID {
                src.push(s, List::Key, l.k, l.kl as usize);
            }
            if l.v < OFF_SENTINEL {
                src.push(s, List::Val, l.v, l.vl as usize);
            }
        }
        let n = src.nkeys();
        let (a, e) = (src.toc_at(0), src.esz());
        src.b.copy_within(a + e * count..a + e * n, a);
        src.set_nkeys(n - count);
        src.toc_trim_after_move(s);
    }

    /// The longest key (0x100027a90).
    pub fn longest_key(&self, s: &Shape) -> usize {
        if s.fixed() {
            return s.key_size;
        }
        (0..self.nkeys()).map(|i| self.loc(s, i).kl as usize).max().unwrap_or(0)
    }

    /// A root that becomes an index node one level up, empty
    /// (`bt_shift_or_split`'s root step).
    pub fn reformat_root_index(&mut self, s: &Shape, level: u16) {
        let fl = flags::ROOT | (self.flags() & (flags::HASHED | flags::NOHEADER));
        self.reformat(s, fl, level);
    }
}

/// `btree_info_t` of a root node.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Info {
    pub flags: u32,
    pub node_size: u32,
    pub key_size: u32,
    pub val_size: u32,
    pub longest_key: u32,
    pub longest_val: u32,
    pub key_count: u64,
    pub node_count: u64,
}

impl Info {
    pub fn read(root: &[u8]) -> Info {
        let i = root.len() - INFO;
        Info {
            flags: u32a(root, i),
            node_size: u32a(root, i + 4),
            key_size: u32a(root, i + 8),
            val_size: u32a(root, i + 12),
            longest_key: u32a(root, i + 16),
            longest_val: u32a(root, i + 20),
            key_count: u64a(root, i + 24),
            node_count: u64a(root, i + 32),
        }
    }
    pub fn write(&self, root: &mut [u8]) {
        let i = root.len() - INFO;
        root.put32(i, self.flags);
        root.put32(i + 4, self.node_size);
        root.put32(i + 8, self.key_size);
        root.put32(i + 12, self.val_size);
        root.put32(i + 16, self.longest_key);
        root.put32(i + 20, self.longest_val);
        root.put64(i + 24, self.key_count);
        root.put64(i + 32, self.node_count);
    }
}
