//! The space manager's free-extent cache as APFS 2236.140.6 keeps it
//! (`spaceman_free_extent_cache_*`; addresses are `apfs_invert`'s copy of
//! the library, I:, the kext's K: where it was read): the device's free
//! extents in two orders, by address and by length (equal lengths by
//! address descending), and the search a data allocation makes in it.
//!
//! - Filled when the container is mounted, every maximal free run of the
//!   bitmaps (whole free chunks as one, merged across chunk boundaries;
//!   I:0x1000421fc, K:0xfffffff00675197c).
//! - An inserted extent merges with its neighbours by address
//!   (I:0x10000b0bc); an allocated one is cut out of what holds it, the
//!   rest kept on either side (I:0x10000c714).
//! - The search (I:0x10000cfb0, inlined in K:0xfffffff0067535b0) takes the
//!   best fit by clipped length: an extent's part outside the metazone and
//!   the allocation zones' chunks (I:0x10000963c, the larger side kept, the
//!   one before on a tie, I:0x100009558), the candidates compared by
//!   I:0x10000d9c4; the roving pointer only orders equal lengths and
//!   breaks ties by distance.
//!
//! The cache's capacity (`min(blocks >> 18, 0xff80) + 0x80` nodes, one a
//! sentinel; I:0x10000afa8) is kept: an extent that would need a node past
//! it is what the library then recycles or remembers as missed
//! (I:0x10000bf18, I:0x10000ba34), not transcribed; the cache is then marked
//! inexact and a search in it refused.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound::{Excluded, Unbounded};

/// `spaceman_alloc`'s flags the search reads.
pub mod flags {
    /// Fewer blocks than asked may be returned (the caller takes a count).
    pub const PARTIAL: u32 = 0x1000;
    /// Clip the metazone and the allocation zones' chunks.
    pub const AVOID: u32 = 0x2000;
    /// The hint is the caller's.
    pub const HINT: u32 = 0x4000;
}

/// `ENOSPC`.
pub const ENOSPC: i32 = 28;

/// What a search clips: the metazone and the allocation zones' current
/// chunks.
#[derive(Clone, Copy, Debug, Default)]
pub struct Clip {
    pub metazone: Option<(u64, u64)>,
    pub zones: [Option<(u64, u64)>; 4],
}

/// An extent: start and length.
pub type Ext = (u64, u64);

/// The cache.
#[derive(Clone, Debug)]
pub struct Fxc {
    by_addr: BTreeMap<u64, u64>,
    by_len: BTreeSet<(u64, Reverse<u64>)>,
    capacity: usize,
    exact: bool,
}

/// `|[s, s + l) ∩ [zs, zs + zl)|` and where it starts (I:0x10000e284).
fn overlap(s: u64, l: u64, zs: u64, zl: u64) -> (u64, u64) {
    let a = s.max(zs);
    let b = (s + l).min(zs + zl);
    if a < b {
        (b - a, a)
    } else {
        (0, a)
    }
}

/// `clip_one` (I:0x100009558): extent `(s, l)` without `[zs, zs + zl)`,
/// whether it changed.
fn clip_one(s: u64, l: u64, zs: u64, zl: u64, fl: u32, hint: u64) -> (Ext, bool) {
    let (ov, os) = overlap(s, l, zs, zl);
    if ov == 0 {
        return ((s, l), false);
    }
    if ov == l {
        return ((s, 0), true);
    }
    let d = os - s;
    if d == 0 {
        return ((s + ov, l - ov), true);
    }
    let after = l - (d + ov);
    let before = ((s, d), true);
    let behind = ((os + ov, after), true);
    if fl & flags::HINT == 0 {
        return if after > d { behind } else { before };
    }
    if d + ov == l || os >= hint {
        return before;
    }
    if os + ov <= hint {
        return behind;
    }
    if hint - os <= (os + ov) - hint {
        before
    } else {
        behind
    }
}

/// `clip_all` (I:0x10000963c) with the avoid flag: the metazone, then each
/// zone's chunk; whether anything was clipped.
fn clip_all(e: Ext, fl: u32, hint: u64, c: &Clip) -> (Ext, bool) {
    let (mut cur, mut changed) = (e, false);
    if fl & flags::AVOID == 0 {
        return (cur, false);
    }
    if let Some((zs, ze)) = c.metazone {
        let (n, ch) = clip_one(cur.0, cur.1, zs, ze - zs, fl, hint);
        if ch {
            cur = n;
            changed = true;
        }
    }
    for &(zs, ze) in c.zones.iter().flatten() {
        let (n, ch) = clip_one(cur.0, cur.1, zs, ze - zs, fl, hint);
        if ch {
            cur = n;
            changed = true;
        }
    }
    (cur, changed)
}

/// An extent's distance from `hint` (none if it holds it).
fn dist(e: Ext, hint: u64) -> u64 {
    if e.0 < hint {
        if hint - e.0 < e.1 {
            0
        } else {
            hint - (e.0 + e.1)
        }
    } else {
        e.0 - hint
    }
}

/// `better` (I:0x10000d9c4): whether `cand` replaces `best` for `count`
/// blocks near `hint`.
fn better(hint: u64, count: u64, best: Ext, cand: Ext, fl: u32) -> bool {
    let (bl, cl) = (best.1, cand.1);
    let near = fl & flags::HINT != 0;
    if cl == 0 {
        return false;
    }
    if bl == 0 {
        return true;
    }
    if bl < count {
        if bl < cl {
            return true;
        }
        return cl == bl && near && dist(cand, hint) < dist((best.0, cl), hint);
    }
    if bl == count {
        if count <= cl && (cl == count || near) && dist(cand, hint) < dist(best, hint) {
            return cl == bl || cl - bl > 15;
        }
        return false;
    }
    if count > cl {
        return false;
    }
    let (be, ce) = (bl - count, cl - count);
    if cl == count || (be < 16 && be < ce) {
        return true;
    }
    if !near {
        ce < be && ce > 15
    } else {
        ce > 15 && dist(cand, hint) < dist(best, hint)
    }
}

/// The best and the best unclipped candidate a search keeps.
#[derive(Clone, Copy, Default)]
struct Pick {
    best: Ext,
    sec: Ext,
}

/// `walk`'s stop modes (I:0x10000d6c8).
mod mode {
    pub const STOP_UNCLIPPED_EXACT: u32 = 0x100;
    pub const STOP_ABOVE: u32 = 0x200;
    pub const STOP_SHORTER: u32 = 0x400;
    pub const STOP_FIRST: u32 = 0x800;
    pub const NEAR: u32 = 0x1000;
}

impl Fxc {
    /// An empty cache for a device of `blocks` blocks
    /// (`spaceman_free_extent_cache_setup`, I:0x10000afa8).
    pub fn new(blocks: u64) -> Fxc {
        let nodes = (blocks >> 18).min(0xff80) + 0x80;
        Fxc { by_addr: BTreeMap::new(), by_len: BTreeSet::new(), capacity: nodes as usize - 1, exact: true }
    }

    /// The cached extents by address.
    pub fn extents(&self) -> Vec<Ext> {
        self.by_addr.iter().map(|(&s, &l)| (s, l)).collect()
    }

    /// Blocks the cache holds.
    pub fn total(&self) -> u64 {
        self.by_addr.values().sum()
    }

    /// Whether every extent asked for found room in the cache.
    pub fn exact(&self) -> bool {
        self.exact
    }

    fn put(&mut self, s: u64, l: u64) {
        self.by_addr.insert(s, l);
        self.by_len.insert((l, Reverse(s)));
    }

    fn take(&mut self, s: u64) -> u64 {
        let l = self.by_addr.remove(&s).expect("a cached extent");
        self.by_len.remove(&(l, Reverse(s)));
        l
    }

    /// `spaceman_free_extent_cache_insert` (I:0x10000b0bc): `[s, s + l)`
    /// cached, merged with the extents it touches or overlaps.
    pub fn insert(&mut self, s: u64, l: u64) {
        if l == 0 {
            return;
        }
        let (mut start, mut end) = (s, s + l);
        if let Some((&ps, &pl)) = self.by_addr.range(..=s).next_back() {
            if ps + pl >= s {
                start = ps;
                end = end.max(ps + pl);
                self.take(ps);
            }
        }
        while let Some((&ns, &nl)) = self.by_addr.range((Excluded(start), Unbounded)).next() {
            if ns > end {
                break;
            }
            end = end.max(ns + nl);
            self.take(ns);
        }
        if self.by_addr.len() >= self.capacity {
            self.exact = false;
            return;
        }
        self.put(start, end - start);
    }

    /// `spaceman_free_extent_cache_remove` (I:0x10000c714): `[s, s + n)` no
    /// longer free.
    pub fn remove(&mut self, s: u64, n: u64) {
        if n == 0 {
            return;
        }
        let end = s + n;
        if let Some((&ps, &pl)) = self.by_addr.range(..s).next_back() {
            let pe = ps + pl;
            if pe > s {
                self.take(ps);
                self.put(ps, s - ps);
                if pe > end {
                    if self.by_addr.len() >= self.capacity {
                        self.exact = false;
                    } else {
                        self.put(end, pe - end);
                    }
                }
            }
        }
        while let Some((&ns, &nl)) = self.by_addr.range(s..).next() {
            if ns >= end {
                break;
            }
            self.take(ns);
            if ns + nl > end {
                self.put(end, ns + nl - end);
                break;
            }
        }
    }

    /// `walk` (I:0x10000d6c8) over `it`: each extent clipped, the best and
    /// the best unclipped candidates updated, until its mode stops it.
    #[allow(clippy::too_many_arguments)]
    fn walk(it: &mut dyn Iterator<Item = Ext>, md: u32, hint: u64, count: u64, maxdist: u64, fl: u32, c: &Clip, p: &mut Pick) {
        for (n, e) in it.enumerate() {
            if e.1 == 0 {
                if md & mode::NEAR != 0 && n > 0x7e {
                    return;
                }
                continue;
            }
            let (cur, changed) = clip_all(e, fl, hint, c);
            if changed && better(hint, count, p.sec, e, fl) {
                p.sec = e;
            }
            if better(hint, count, p.best, cur, fl) {
                p.best = cur;
                if md & mode::STOP_FIRST != 0 {
                    return;
                }
            }
            if md & mode::STOP_UNCLIPPED_EXACT != 0 && e.1 == count && cur.1 == e.1 {
                return;
            }
            if md & mode::STOP_ABOVE != 0 && count < p.best.1 {
                return;
            }
            if md & mode::STOP_SHORTER != 0 && e.1 < count && e.1 <= p.best.1 {
                return;
            }
            if md & mode::NEAR != 0 && (n > 0x7e || maxdist <= dist(cur, hint)) {
                return;
            }
        }
    }

    /// `spaceman_free_extent_cache_search` (I:0x10000cfb0): where `count`
    /// blocks go near `hint` and how many fit there (fewer only with
    /// [`flags::PARTIAL`]); `Err(ENOSPC)` when nothing fits.
    pub fn search(&self, hint: u64, count: u64, mut fl: u32, c: &Clip) -> Result<Result<Ext, i32>, String> {
        if !self.exact {
            return Err("not implemented: a search in a free-extent cache that ran out of nodes (its recycling and missed-extent rules)".into());
        }
        let mut p = Pick::default();
        let key = (count, Reverse(hint));
        let mut done = false;
        if self.by_len.contains(&key) {
            let e = (hint, count);
            let (cur, changed) = clip_all(e, fl, hint, c);
            if changed {
                p.sec = e;
            }
            p.best = cur;
            done = cur.1 == count;
        }
        if !done {
            let mut up = self.by_len.range((Excluded(key), Unbounded)).map(|&(l, Reverse(s))| (s, l));
            Self::walk(&mut up, mode::STOP_UNCLIPPED_EXACT | mode::STOP_ABOVE | 1, hint, count, u64::MAX, fl, c, &mut p);
            let mut down = self.by_len.range(..key).rev().map(|&(l, Reverse(s))| (s, l));
            Self::walk(&mut down, mode::STOP_UNCLIPPED_EXACT | mode::STOP_SHORTER | 2, hint, count, u64::MAX, fl, c, &mut p);
            if p.best.1 < count && p.best.1 < p.sec.1 {
                p.best = p.sec;
                p.sec = (0, 0);
                fl &= !flags::AVOID;
            }
            if count <= p.best.1 || fl & flags::PARTIAL != 0 {
                let d = dist(p.best, hint);
                if d != 0 {
                    let mut improved = false;
                    if let Some(&l) = self.by_addr.get(&hint) {
                        let e = (hint, l);
                        let (cur, changed) = clip_all(e, fl, hint, c);
                        if changed && better(hint, count, p.sec, e, fl) {
                            p.sec = e;
                        }
                        if better(hint, count, p.best, cur, fl) {
                            p.best = cur;
                            improved = true;
                        }
                    }
                    if !improved {
                        let mut below = self.by_addr.range(..hint).rev().map(|(&s, &l)| (s, l));
                        Self::walk(&mut below, mode::NEAR | mode::STOP_FIRST | 2, hint, count, d, fl, c, &mut p);
                        let mut above = self.by_addr.range((Excluded(hint), Unbounded)).map(|(&s, &l)| (s, l));
                        Self::walk(&mut above, mode::NEAR | mode::STOP_FIRST | 1, hint, count, d, fl, c, &mut p);
                    }
                }
            }
        }
        if p.best.1 == 0 && p.sec.1 != 0 {
            p.best = p.sec;
        }
        if count <= p.best.1 {
            return Ok(Ok((p.best.0, count)));
        }
        // Too small: the rescan heuristic (I:0x10000db70) answers "no
        // rescan" when the cache holds every free block, which the caller
        // checks.
        if fl & flags::PARTIAL != 0 && p.best.1 != 0 {
            return Ok(Ok(p.best));
        }
        Ok(Err(ENOSPC))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// gexc's container before asr's writes and the placements the device
    /// library's own spaceman_alloc made for them (re-dataalloc.md §7: a
    /// clone of the container, the binary's function called in process).
    fn restore_container() -> (Fxc, Clip) {
        let mut f = Fxc::new(15_624_989);
        for (s, l) in [(29_412, 15_351_439), (15_380_857, 2), (15_380_865, 2), (15_380_873, 2), (15_380_900, 244_089)] {
            f.insert(s, l);
        }
        let c = Clip { metazone: Some((15_136_709, 15_624_989)), zones: [Some((4_096_000, 4_128_768)), Some((32_768, 65_536)), Some((65_536, 98_304)), Some((98_304, 131_072))] };
        (f, c)
    }

    fn alloc(f: &mut Fxc, c: &Clip, rove: &mut u64, count: u64) -> Ext {
        let e = f.search(*rove, count, flags::PARTIAL | flags::AVOID, c).unwrap().unwrap();
        f.remove(e.0, e.1);
        *rove = e.0 + e.1;
        e
    }

    #[test]
    fn asr_writes_land_as_measured() {
        let (mut f, c) = restore_container();
        assert_eq!(f.capacity, 186);
        let mut rove = 0;
        assert_eq!(alloc(&mut f, &c, &mut rove, 256), (4_128_768, 256));
        let mut at = 131_072;
        let sizes: Vec<u64> = std::iter::repeat(256).take(61).chain([27]).chain(std::iter::repeat(256).take(178)).chain([230]).chain(std::iter::repeat(256).take(5263)).chain([27]).collect();
        for n in sizes {
            assert_eq!(alloc(&mut f, &c, &mut rove, n), (at, n));
            at += n;
        }
        assert_eq!(at, 1_539_868);
    }

    #[test]
    fn other_measured_sequences() {
        // "300, 256, 256".
        let (mut f, c) = restore_container();
        let mut rove = 0;
        assert_eq!(alloc(&mut f, &c, &mut rove, 300), (4_128_768, 300));
        assert_eq!(alloc(&mut f, &c, &mut rove, 256), (131_072, 256));
        assert_eq!(alloc(&mut f, &c, &mut rove, 256), (131_328, 256));
        // "12,000,000 x3": partial grants, the unclipped extent first (the
        // third grant is the reserve check's, not the cache's).
        let (mut f, c) = restore_container();
        let mut rove = 0;
        assert_eq!(alloc(&mut f, &c, &mut rove, 12_000_000), (29_412, 12_000_000));
        assert_eq!(alloc(&mut f, &c, &mut rove, 12_000_000), (12_029_412, 3_351_439));
        assert_eq!(alloc(&mut f, &c, &mut rove, 12_000_000).0, 15_380_900);
        // "2, then 256x20" after the zone's block: 13 grants from the
        // smaller leftover, then the zone's far side, then 131,072.
        let (mut f, c) = restore_container();
        f.remove(32_768, 2);
        let mut rove = 0;
        for k in 0..13 {
            assert_eq!(alloc(&mut f, &c, &mut rove, 256), (29_412 + 256 * k, 256));
        }
        assert_eq!(alloc(&mut f, &c, &mut rove, 256), (4_128_768, 256));
        assert_eq!(alloc(&mut f, &c, &mut rove, 256), (131_072, 256));
    }
}
