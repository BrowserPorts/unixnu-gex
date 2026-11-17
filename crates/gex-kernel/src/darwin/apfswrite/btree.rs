//! B-trees as APFS 2236.140.6 changes them (`apfs_invert`'s copy of the
//! library): `bt_insert` (0x100025e78) with `bt_shift_or_split`
//! (0x100027afc), `bt_remove_internal` (0x10002b138) with `bt_merge_up`
//! (0x10002c4a4) and `bt_merge_nodes` (0x100030548), and the comparators
//! of the trees the writer keeps (0x10001a1a4, 0x10003d0b4, 0x100043c64,
//! 0x100009fc0).
//!
//! Nodes come from a [`Store`]: fetched for modification top-down (the
//! root first), a physical tree's node taking a new address at its first
//! change in a transaction (its parent's entry following), a virtual
//! tree's keeping its identifier.

use super::node::{flags, tree_flags, Info, Node, Shape, ENOSPC, HDR, INFO};
use super::Put;
use std::cmp::Ordering;

/// Where a tree's nodes live and how they change.
pub trait Store {
    /// Node `id`'s bytes.
    fn get(&mut self, id: u64) -> Result<Node, String>;
    /// Node `id`'s bytes changed in this transaction.
    fn put(&mut self, id: u64, n: Node) -> Result<(), String>;
    /// Node `id` fetched for modification: its identifier from now on (a
    /// physical node's new address at its first change in a transaction).
    fn modify(&mut self, id: u64) -> Result<u64, String>;
    /// A new node's identifier (`node_create`, 0x10002db90), its bytes
    /// `n`.
    fn create(&mut self, n: Node) -> Result<u64, String>;
    /// Node `id` deleted.
    fn delete(&mut self, id: u64) -> Result<(), String>;
}

/// A key comparator.
pub type Cmp = fn(&[u8], &[u8]) -> Ordering;

/// A tree: its root's identifier, its nodes' shape, its order.
#[derive(Clone, Copy)]
pub struct Tree {
    pub root: u64,
    pub shape: Shape,
    pub cmp: Cmp,
}

/// `node_search` (0x100027630): the record's index and whether it is
/// there, else where it would go.
pub fn search(s: &Shape, n: &Node, cmp: Cmp, key: &[u8]) -> (usize, bool) {
    let (mut lo, mut hi) = (0isize, n.nkeys() as isize - 1);
    while lo <= hi {
        let mid = (lo + hi) / 2;
        match cmp(key, n.key(s, mid as usize)) {
            Ordering::Equal => return (mid as usize, true),
            Ordering::Greater => lo = mid + 1,
            Ordering::Less => hi = mid - 1,
        }
    }
    (lo as usize, false)
}

/// The child an index node sends `key` to (0x10002780c).
pub fn search_index(s: &Shape, n: &Node, cmp: Cmp, key: &[u8]) -> (usize, bool) {
    let (i, f) = search(s, n, cmp, key);
    if !f && i > 0 {
        (i - 1, false)
    } else {
        (i, f)
    }
}

/// A node on a descent: its identifier, the slot taken in it and whether
/// the key was there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct At {
    id: u64,
    idx: usize,
    found: bool,
}

/// What `bt_shift_or_split` was asked to make room for: the pending
/// records' key and value lengths and the extra bytes the parent's key
/// may grow by.
struct Pending<'k> {
    key: &'k [u8],
    klens: Vec<usize>,
    vlens: Vec<usize>,
    extra: usize,
}

impl Tree {
    /// `btree_create` (0x10002d9e0): an empty root leaf, made by `st`.
    pub fn create(st: &mut dyn Store, shape: Shape, cmp: Cmp) -> Result<Tree, String> {
        let mut fl = flags::ROOT | flags::LEAF;
        if shape.bt_flags & tree_flags::HASHED != 0 {
            fl |= flags::HASHED;
        }
        if shape.bt_flags & tree_flags::NOHEADER != 0 {
            fl |= flags::NOHEADER;
        }
        let mut n = Node::format(&shape, fl, 0);
        let info = Info { flags: shape.bt_flags, node_size: shape.node_size as u32, key_size: shape.key_size as u32, val_size: shape.val_size as u32, node_count: 1, ..Default::default() };
        info.write(&mut n.b);
        let root = st.create(n)?;
        Ok(Tree { root, shape, cmp })
    }

    fn info(&self, st: &mut dyn Store) -> Result<Info, String> {
        Ok(Info::read(&st.get(self.root)?.b))
    }

    fn set_info(&self, st: &mut dyn Store, f: impl FnOnce(&mut Info)) -> Result<(), String> {
        let mut r = st.get(self.root)?;
        let mut i = Info::read(&r.b);
        f(&mut i);
        i.write(&mut r.b);
        st.put(self.root, r)
    }

    /// An index entry's value for child `id`: its identifier (relative to
    /// the root's in a hashed tree, `btree_node_insert` 0x10002a6ac), the
    /// hash space after it.
    fn child_val(&self, n: &Node, id: u64) -> Result<Vec<u8>, String> {
        let mut v = if n.flags() & (flags::HASHED | flags::LEAF) == flags::HASHED {
            if id <= self.root {
                return Err(format!("invalid relative OID: {id} < root OID: {}", self.root));
            }
            (id - self.root).to_le_bytes().to_vec()
        } else {
            id.to_le_bytes().to_vec()
        };
        v.resize(self.shape.index_val(), 0);
        Ok(v)
    }

    /// Child `i` of index node `n` (`btree_node_child_val`, 0x100025da0).
    fn child_of(&self, n: &Node, i: usize) -> u64 {
        let c = n.child(&self.shape, i);
        if n.flags() & flags::HASHED != 0 {
            c + self.root
        } else {
            c
        }
    }

    /// Child `i` of `p` fetched for modification; `p`'s entry follows a
    /// new address (`child_id_update`, 0x10002784c).
    fn child_modify(&self, st: &mut dyn Store, p: u64, i: usize) -> Result<u64, String> {
        let s = &self.shape;
        let pn = st.get(p)?;
        let c = self.child_of(&pn, i);
        let nc = st.modify(c)?;
        if nc != c {
            let mut pn = pn;
            let v = self.child_val(&pn, nc)?;
            pn.update(s, i, None, Some(&v[..8]), false).map_err(|e| format!("updating a child's address: {e}"))?;
            // The hash past the identifier is the seal's, not changed here.
            st.put(p, pn)?;
        }
        Ok(nc)
    }

    /// The search a descent makes in a node: exact in a leaf (0x100027630),
    /// the child's slot in an index node (0x10002780c).
    fn find(&self, n: &Node, key: &[u8]) -> (usize, bool) {
        if n.is_leaf() {
            search(&self.shape, n, self.cmp, key)
        } else {
            search_index(&self.shape, n, self.cmp, key)
        }
    }

    /// `btree_node_key_update`: entry `i`'s key replaced.
    fn key_update(&self, st: &mut dyn Store, id: u64, i: usize, key: &[u8]) -> Result<(), String> {
        let mut n = st.get(id)?;
        n.update(&self.shape, i, Some(key), None, false).map_err(|e| format!("btree_node_key_update failed: {e}"))?;
        st.put(id, n)
    }

    /// `btree_node_insert` (0x10002a6ac): an index entry for child `child`
    /// under `key`, replacing one with the same key.
    fn node_insert_child(&self, st: &mut dyn Store, id: u64, key: &[u8], child: u64) -> Result<(), String> {
        let s = self.shape;
        let mut n = st.get(id)?;
        let v = self.child_val(&n, child)?;
        let (i, f) = search(&s, &n, self.cmp, key);
        let r = if f { n.update(&s, i, Some(key), Some(&v), false) } else { n.insert_at(&s, i, Some(key), Some(&v), false) };
        r.map_err(|e| format!("btree_node_insert failed: {e}"))?;
        st.put(id, n)
    }

    /// `btree_node_insert` of a record.
    fn node_insert_record(&self, st: &mut dyn Store, id: u64, key: &[u8], val: Option<&[u8]>) -> Result<(usize, bool), String> {
        let s = self.shape;
        let mut n = st.get(id)?;
        let (i, f) = search(&s, &n, self.cmp, key);
        let r = if f { n.update(&s, i, Some(key), val, false) } else { n.insert_at(&s, i, Some(key), val, false) };
        r.map_err(|e| format!("btree_node_insert failed: {e}"))?;
        st.put(id, n)?;
        Ok((i, f))
    }

    /// A new node like `n` (`node_create`, 0x10002db90: its leaf, hashed
    /// and headerless flags, its level), counted in the tree's info.
    fn new_node_like(&self, st: &mut dyn Store, n: &Node) -> Result<u64, String> {
        let fl = n.flags() & (flags::LEAF | flags::HASHED | flags::NOHEADER);
        let id = st.create(Node::format(&self.shape, fl, n.level()))?;
        self.set_info(st, |i| i.node_count += 1)?;
        Ok(id)
    }

    /// A node of the tree deleted (`obj_delete`, 0x100038cd8), uncounted.
    fn drop_node(&self, st: &mut dyn Store, id: u64) -> Result<(), String> {
        st.delete(id)?;
        self.set_info(st, |i| i.node_count -= 1)
    }

    /// `bt_move_entries(a, b, count)` (0x10002f698): a positive count moves
    /// `a`'s last records to `b`'s front, a negative one `b`'s first
    /// records to `a`'s end.
    fn move_entries(&self, st: &mut dyn Store, a: u64, b: u64, count: isize) -> Result<(), String> {
        let s = self.shape;
        let mut an = st.get(a)?;
        let mut bn = st.get(b)?;
        if count > 0 {
            an.move_last_to_front(&s, &mut bn, count as usize);
        } else if count < 0 {
            an.append_from_front(&s, &mut bn, count.unsigned_abs());
        }
        st.put(a, an)?;
        st.put(b, bn)
    }

    /// Looks `key` up: its value.
    pub fn get(&self, st: &mut dyn Store, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let s = &self.shape;
        let mut id = self.root;
        loop {
            let n = st.get(id)?;
            if n.is_leaf() {
                let (i, f) = search(s, &n, self.cmp, key);
                return Ok(f.then(|| n.val(s, i).map(|v| v.to_vec()).unwrap_or_default()));
            }
            if n.nkeys() == 0 {
                return Ok(None);
            }
            let (i, _) = search_index(s, &n, self.cmp, key);
            id = self.child_of(&n, i);
        }
    }

    /// Every record in key order.
    pub fn records(&self, st: &mut dyn Store) -> Result<Vec<(Vec<u8>, Option<Vec<u8>>)>, String> {
        let mut out = Vec::new();
        self.walk(st, self.root, &mut out)?;
        Ok(out)
    }

    fn walk(&self, st: &mut dyn Store, id: u64, out: &mut Vec<(Vec<u8>, Option<Vec<u8>>)>) -> Result<(), String> {
        let s = &self.shape;
        let n = st.get(id)?;
        for i in 0..n.nkeys() {
            if n.is_leaf() {
                out.push((n.key(s, i).to_vec(), n.val(s, i).map(|v| v.to_vec())));
            } else {
                self.walk(st, self.child_of(&n, i), out)?;
            }
        }
        Ok(())
    }

    /// Every node's identifier, parents before their children, children
    /// in order (`btree_iterate_nodes`, 0x10002de68).
    pub fn node_ids(&self, st: &mut dyn Store) -> Result<Vec<u64>, String> {
        let mut out = Vec::new();
        let mut stack = vec![self.root];
        while let Some(id) = stack.pop() {
            out.push(id);
            let n = st.get(id)?;
            if !n.is_leaf() {
                for i in (0..n.nkeys()).rev() {
                    stack.push(self.child_of(&n, i));
                }
            }
        }
        Ok(out)
    }

    /// `bt_insert` (0x100025e78): record (`key`, `val`) inserted, or its
    /// value replaced; a `None` value is a ghost (no value bytes).
    ///
    /// The descent fetches each node for modification. A leaf with no
    /// room for a record past its end hands it to its right sibling (the
    /// move-right rule). Before stepping into a child, the parent is split
    /// when it lacks room for the entries a split of the child would add
    /// and the child lacks room for what the insert adds to it. A key below
    /// its subtree's first key becomes the first key of every index node on
    /// the way down to it (the minimum-key update).
    pub fn insert(&mut self, st: &mut dyn Store, key: &[u8], val: Option<&[u8]>) -> Result<(), String> {
        let s = self.shape;
        let klen = key.len();
        let vl = val.map_or(0, |v| v.len());
        let info0 = self.info(st)?;
        let longest = (info0.longest_key as usize).max(klen);
        self.root = st.modify(self.root)?;
        let root = self.root;
        let idxv = s.index_val();
        let rn = st.get(root)?;
        let (i0, f0) = self.find(&rn, key);
        let mut c = At { id: root, idx: i0, found: f0 };
        let mut p: Option<At> = None;
        // The minimum-key state: whether the key is the new first key of
        // the subtree under `mk_top`'s entry `mk_idx`, and the index node
        // the leftmost path starts at.
        let mut minkey = i0 == 0 && !f0 && !rn.is_leaf();
        let mut mk_top: Option<u64> = None;
        let mut mk_idx = 0usize;
        let mut mk_path: Option<u64> = if minkey { Some(root) } else { None };
        if !rn.is_leaf() {
            let mut gp: Option<At>;
            loop {
                gp = p;
                p = Some(c);
                let pp = c;
                let cid = self.child_modify(st, pp.id, pp.idx)?;
                let cn = st.get(cid)?;
                let (ci, cf) = self.find(&cn, key);
                c = At { id: cid, idx: ci, found: cf };
                // The move-right rule.
                loop {
                    let cn = st.get(c.id)?;
                    let pn = st.get(p.unwrap().id)?;
                    let pidx = p.unwrap().idx;
                    if !cn.is_leaf() || c.idx != cn.nkeys() || pidx + 1 >= pn.nkeys() || cn.has_room(&s, &[klen], &[vl], 0, 0).0 {
                        break;
                    }
                    let old = pidx;
                    p.as_mut().unwrap().idx += 1;
                    if minkey && old == 0 {
                        mk_top = None;
                        minkey = false;
                        mk_path = None;
                    }
                    let cid = self.child_modify(st, p.unwrap().id, old + 1)?;
                    let cn = st.get(cid)?;
                    let (ci, cf) = self.find(&cn, key);
                    c = At { id: cid, idx: ci, found: cf };
                }
                let pp = p.unwrap();
                let cn = st.get(c.id)?;
                if minkey || c.idx != 0 || c.found {
                    if minkey && c.idx != 0 {
                        mk_top = None;
                        minkey = false;
                        mk_path = None;
                    }
                } else if !cn.is_leaf() {
                    mk_top = Some(pp.id);
                    minkey = true;
                    mk_idx = pp.idx;
                    mk_path = Some(c.id);
                } else {
                    minkey = false;
                }
                let lc = cn.longest_key(&s);
                let pn = st.get(pp.id)?;
                let (one, kreplace) = if c.idx == 0 && !c.found && (self.cmp)(key, pn.key(&s, pp.idx)) == Ordering::Less {
                    (true, s.r(klen).saturating_sub(s.r(pn.key(&s, pp.idx).len())))
                } else {
                    (false, 0)
                };
                let lens: Vec<usize> = if pn.level() < 2 {
                    if one {
                        vec![lc]
                    } else {
                        vec![lc, klen]
                    }
                } else {
                    vec![klen.max(lc); if one { 1 } else { 2 }]
                };
                let vls = vec![idxv; lens.len()];
                let ok = pn.has_room(&s, &lens, &vls, kreplace, 0).0
                    || if pn.level() < 2 {
                    let mut ok = if c.found {
                        let (okl, ovl) = (cn.loc(&s, c.idx).kl as usize, cn.val_len(&s, c.idx));
                        let (rk, rv, rok, rov) = (s.r(klen), s.r(vl), s.r(okl), s.r(ovl));
                        if rok < rk || rov < rv {
                            cn.has_room(&s, &[], &[], rk.saturating_sub(rok), rv.saturating_sub(rov)).0
                        } else {
                            true
                        }
                    } else {
                        cn.has_room(&s, &[klen], &[vl], 0, 0).0
                    };
                    if ok && kreplace != 0 {
                        ok = pn.has_room(&s, &[], &[], kreplace, 0).0;
                    }
                    ok
                    } else {
                        cn.has_room(&s, &vec![longest; lens.len()], &vls, kreplace, 0).0
                    };
                if !ok {
                    let at = if pp.found { pp.idx } else { pp.idx + 1 };
                    let pend = Pending { key, klens: lens.clone(), vlens: vls.clone(), extra: kreplace };
                    let r = self.shift_or_split(st, gp.map(|g| (g.id, g.idx)), pp.id, at, &pend)?;
                    if let Some(r) = r {
                        let old_p = pp.id;
                        match gp.as_mut() {
                            None => {
                                let rn = st.get(r)?;
                                let k2 = if rn.nkeys() != 0 { rn.key(&s, 0).to_vec() } else { key.to_vec() };
                                let gn = st.get(old_p)?;
                                let (gi, gf) = search_index(&s, &gn, self.cmp, &k2);
                                gp = Some(At { id: old_p, idx: gi, found: gf });
                            }
                            Some(g) => g.idx += 1,
                        }
                        let g = gp.unwrap();
                        let iv = if mk_top.is_some() && mk_top == Some(g.id) { g.idx } else { mk_idx };
                        let rn = st.get(r)?;
                        let (pi, pf) = search_index(&s, &rn, self.cmp, key);
                        p = Some(At { id: r, idx: pi, found: pf });
                        let cid = self.child_modify(st, r, pi)?;
                        let cn = st.get(cid)?;
                        let (ci, cf) = self.find(&cn, key);
                        c = At { id: cid, idx: ci, found: cf };
                        mk_idx = iv;
                        if mk_top == Some(old_p) {
                            if old_p == root && pi == 0 {
                                mk_path = Some(r);
                                mk_top = Some(root);
                            } else {
                                mk_path = Some(c.id);
                                mk_idx = pi;
                                mk_top = Some(r);
                                if pi == 0 {
                                    mk_path = Some(r);
                                    mk_idx = g.idx;
                                    mk_top = Some(g.id);
                                }
                            }
                        } else {
                            let mut keep = false;
                            let mut path = mk_path;
                            let mut iv2 = iv;
                            if minkey {
                                if pi == 0 && c.idx == 0 {
                                    keep = true;
                                } else {
                                    mk_top = None;
                                    iv2 = 0;
                                    path = None;
                                }
                            }
                            if !keep {
                                mk_path = path;
                                mk_idx = iv2;
                                if c.idx == 0 {
                                    if pi == 0 && !pf {
                                        minkey = true;
                                        mk_path = Some(r);
                                        mk_idx = g.idx;
                                        mk_top = Some(g.id);
                                    } else if c.found {
                                        minkey = false;
                                    } else {
                                        minkey = !cn.is_leaf();
                                        if minkey {
                                            mk_path = Some(c.id);
                                            mk_idx = pi;
                                            mk_top = Some(r);
                                        }
                                    }
                                } else {
                                    minkey = false;
                                }
                            }
                        }
                    }
                }
                if st.get(c.id)?.is_leaf() {
                    break;
                }
            }
        }
        // The leaf.
        let mut ln = st.get(c.id)?;
        let rc = if c.found { ln.update(&s, c.idx, Some(key), val, false) } else { ln.insert_at(&s, c.idx, Some(key), val, false) };
        match rc {
            Ok(()) => st.put(c.id, ln)?,
            Err(ENOSPC) => {
                let pend = Pending { key, klens: vec![klen], vlens: vec![vl], extra: 0 };
                let r = self.shift_or_split(st, p.map(|x| (x.id, x.idx)), c.id, c.idx, &pend)?;
                if let Some(r) = r {
                    match p.as_mut() {
                        None => {
                            let rn = st.get(r)?;
                            let k2 = if rn.nkeys() != 0 { rn.key(&s, 0).to_vec() } else { key.to_vec() };
                            let pn = st.get(c.id)?;
                            let (pi, pf) = search_index(&s, &pn, self.cmp, &k2);
                            p = Some(At { id: c.id, idx: pi, found: pf });
                        }
                        Some(x) => x.idx += 1,
                    }
                    c.id = r;
                }
                // `btree_node_insert` reports where the record went: the
                // checks below take that slot.
                let (i, f) = self.node_insert_record(st, c.id, key, val)?;
                c.idx = i;
                c.found = f;
            }
            Err(e) => return Err(format!("inserting a record: {e}")),
        }
        if c.idx == 0 {
            if let Some(pp) = p {
                let pn = st.get(pp.id)?;
                if (self.cmp)(key, pn.key(&s, pp.idx)) != Ordering::Equal {
                    self.key_update(st, pp.id, pp.idx, key)?;
                }
            }
        }
        self.set_info(st, |i| {
            i.longest_key = i.longest_key.max(klen as u32);
            i.longest_val = i.longest_val.max(vl as u32);
            if !c.found {
                i.key_count += 1;
            }
        })?;
        // The minimum-key update down the leftmost path.
        if minkey && c.idx == 0 {
            if let Some(t) = mk_top {
                self.key_update(st, t, mk_idx, key)?;
            }
            if let Some(mut n) = mk_path {
                while st.get(n)?.level() > 1 {
                    let nn = st.get(n)?;
                    let (i, f) = search_index(&s, &nn, self.cmp, key);
                    if i != 0 || f {
                        return Err(format!("minkey update traversal unexpectedly found the key ({}) or a non-zero index ({i})", f as u8));
                    }
                    self.key_update(st, n, 0, key)?;
                    if nn.level() == 2 {
                        break;
                    }
                    n = self.child_modify(st, n, 0)?;
                }
            }
        }
        Ok(())
    }

    /// `bt_shift_or_split` (0x100027afc): room in node `n` (entry `pidx`
    /// of `parent`, none for the root) for the pending records at slot
    /// `idx`, made by moving `n`'s last records to its right sibling (or a
    /// new node), a new middle node when they do not fit either, and a new
    /// left node taking a split root's records. The node the pending
    /// records belong in, or none for `n` itself.
    fn shift_or_split(&mut self, st: &mut dyn Store, parent: Option<(u64, usize)>, n: u64, idx: usize, pend: &Pending) -> Result<Option<u64>, String> {
        let s = self.shape;
        let key = pend.key;
        let cnt = pend.klens.len() as i64;
        let seq = s.bt_flags & tree_flags::SEQUENTIAL_INSERT != 0;
        let nn = st.get(n)?;
        let leaf = nn.is_leaf();
        let fixed_ng = nn.flags() & flags::FIXED_KV_SIZE != 0 && s.bt_flags & tree_flags::ALLOW_GHOSTS == 0;
        // The right sibling, fetched for modification whether used or not.
        let mut sib = None;
        if let Some((p, pidx)) = parent {
            let pn = st.get(p)?;
            if (pidx as u32) < (pn.nkeys() as u32).wrapping_sub(1) {
                sib = Some(self.child_modify(st, p, pidx + 1)?);
            }
        }
        let newb: i64 = pend.klens.iter().zip(&pend.vlens).map(|(&k, &v)| (s.r(k) + s.r(v)) as i64).sum();
        // A replaced record (a leaf's record with the key at `idx`).
        let (freed_n, keyeq, repl) = if idx < nn.nkeys() && (self.cmp)(key, nn.key(&s, idx)) == Ordering::Equal {
            if leaf {
                ((s.r(nn.loc(&s, idx).kl as usize) + s.r(nn.val_len(&s, idx))) as i64, -1i64, true)
            } else {
                (0, -1, false)
            }
        } else {
            (0, 0, false)
        };
        let mut r: Option<u64>;
        let mut rnew: bool;
        let mut middle: Option<u64> = None;
        let mut pend_n: i64;
        let split: i64;
        let nk = nn.nkeys() as i64;
        let end = if let Some(sid) = sib {
            r = Some(sid);
            rnew = false;
            pend_n = cnt;
            self.scan(st, n, &nn, &mut r, &mut rnew, &mut pend_n, idx as i64, newb, pend, freed_n, keyeq, repl, fixed_ng, seq)?
        } else {
            r = Some(self.new_node_like(st, &nn)?);
            rnew = true;
            if seq && nk == idx as i64 {
                pend_n = 0;
                End::NoMiddle(i64::from(leaf) + idx as i64 - 1)
            } else {
                pend_n = cnt;
                self.scan(st, n, &nn, &mut r, &mut rnew, &mut pend_n, idx as i64, newb, pend, freed_n, keyeq, repl, fixed_ng, seq)?
            }
        };
        match end {
            End::Stop(sp) | End::NoMiddle(sp) => split = sp,
            End::Middle(sp) => {
                split = sp;
                if nk == sp && r.is_some() {
                    middle = r.take();
                    rnew = false;
                } else {
                    middle = Some(self.new_node_like(st, &nn)?);
                    rnew = true;
                }
            }
        }
        let mut is_middle = middle.is_some();
        // A split root's records go to a new left node.
        let l = if parent.is_none() && (is_middle || rnew) { Some(self.new_node_like(st, &nn)?) } else { None };
        let (p, pidx) = parent.unzip();
        let pidx = pidx.unwrap_or(0);
        if repl && (idx as i64) >= split {
            // The replaced record moves right: the records after it first,
            // then it goes, then the rest.
            let c2 = st.get(n)?.nkeys() as i64 - 1 - idx as i64;
            if c2 >= 1 {
                self.move_entries(st, n, r.ok_or("a split with no right node")?, c2 as isize)?;
                if !rnew {
                    let rk = st.get(r.unwrap())?.key(&s, 0).to_vec();
                    self.key_update(st, p.ok_or("a sibling with no parent")?, pidx + 1, &rk)?;
                }
            }
            let mut nn = st.get(n)?;
            nn.remove(&s, idx, false);
            st.put(n, nn)?;
            self.set_info(st, |i| i.key_count -= 1)?;
        }
        let count = st.get(n)?.nkeys() as i64 - split;
        if count >= 1 {
            self.move_entries(st, n, r.ok_or("a split with no right node")?, count as isize)?;
            if !rnew {
                let rk = st.get(r.unwrap())?.key(&s, 0).to_vec();
                self.key_update(st, p.ok_or("a sibling with no parent")?, pidx + 1, &rk)?;
            }
            if let Some(p) = p {
                if st.get(n)?.nkeys() == 0 {
                    self.key_update(st, p, pidx, key)?;
                }
            }
        }
        let mut into = p;
        if let Some(l) = l {
            let cnt_n = st.get(n)?.nkeys();
            self.move_entries(st, l, n, -(cnt_n as isize))?;
            let mut root = st.get(n)?;
            let info = Info::read(&root.b);
            let level = root.level();
            root.reformat_root_index(&s, level + 1);
            info.write(&mut root.b);
            st.put(n, root)?;
            let ln = st.get(l)?;
            let first = if ln.nkeys() != 0 { ln.key(&s, 0).to_vec() } else { key.to_vec() };
            self.node_insert_child(st, n, &first, l)?;
            into = Some(n);
        }
        let into = into.ok_or("a split with no parent")?;
        if rnew {
            if let Some(rid) = r {
                let rn = st.get(rid)?;
                if rn.nkeys() != 0 {
                    let rk = rn.key(&s, 0).to_vec();
                    self.node_insert_child(st, into, &rk, rid)?;
                } else {
                    if !rn.is_leaf() {
                        self.drop_node(st, rid)?;
                    } else {
                        middle = Some(rid);
                        is_middle = true;
                    }
                    r = None;
                }
            }
        }
        if !is_middle {
            return Ok(if pend_n != 0 { l } else { r });
        }
        let m = middle.unwrap();
        let src = l.unwrap_or(n);
        let k = if !st.get(src)?.is_leaf() {
            self.move_entries(st, src, m, 1)?;
            st.get(m)?.key(&s, 0).to_vec()
        } else {
            key.to_vec()
        };
        self.node_insert_child(st, into, &k, m)?;
        Ok(Some(m))
    }

    /// `bt_remove` (0x10002c9e4, `bt_remove_internal` 0x10002b138): the
    /// record with `key` removed; its value (none for a ghost), or none if
    /// there is no such record (the descent's copies happen either way).
    ///
    /// The descent splits an index node that may lack room for its
    /// child's entry under a longer first key. A removed first key is
    /// replaced by the leaf's new first key in the parent, and in every
    /// index node above that held it. An underfull leaf is merged with its
    /// right sibling, and its ancestors in turn ([`Tree::merge_up`]).
    pub fn remove(&mut self, st: &mut dyn Store, key: &[u8]) -> Result<Option<Option<Vec<u8>>>, String> {
        let s = self.shape;
        let klen = key.len();
        if s.key_size != 0 && klen != s.key_size {
            return Err(format!("removing a {klen}-byte key from a tree of {}-byte keys", s.key_size));
        }
        let longest = self.info(st)?.longest_key as usize;
        self.root = st.modify(self.root)?;
        let root = self.root;
        let idxv = s.index_val();
        let rn = st.get(root)?;
        let (i0, f0) = search_index(&s, &rn, self.cmp, key);
        let mut c = At { id: root, idx: i0, found: f0 };
        let mut p: Option<At> = None;
        let mut gp: Option<At> = None;
        // The topmost node whose first key is the removed one, its parent
        // and that parent's entry for it.
        let mut mk_node: Option<u64> = None;
        let mut mk_parent: Option<u64> = None;
        let mut mk_idx = 0usize;
        let mut first = false;
        loop {
            if !first && c.found && c.idx == 0 {
                mk_idx = p.map_or(0, |x| x.idx);
                first = true;
                mk_node = Some(c.id);
                mk_parent = p.map(|x| x.id);
            }
            if let (Some(pp), 0) = (p, s.key_size) {
                let pn = st.get(pp.id)?;
                let cn = st.get(c.id)?;
                let grow = if c.found { s.r(longest).saturating_sub(s.r(pn.key(&s, pp.idx).len())) } else { 0 };
                let lc = cn.longest_key(&s);
                if !pn.has_room(&s, &[lc], &[idxv], grow, 0).0 {
                    let at = if pp.found { pp.idx } else { pp.idx + 1 };
                    let pend = Pending { key, klens: vec![lc], vlens: vec![idxv], extra: grow };
                    if let Some(r) = self.shift_or_split(st, gp.map(|g| (g.id, g.idx)), pp.id, at, &pend)? {
                        match gp.as_mut() {
                            None => {
                                let rn = st.get(r)?;
                                let k2 = if rn.nkeys() == 0 { key.to_vec() } else { rn.key(&s, 0).to_vec() };
                                let gn = st.get(pp.id)?;
                                let (gi, gf) = search_index(&s, &gn, self.cmp, &k2);
                                gp = Some(At { id: pp.id, idx: gi, found: gf });
                            }
                            Some(g) => g.idx += 1,
                        }
                        let g = gp.unwrap();
                        let iv = if mk_parent.is_some() && mk_parent == Some(g.id) { g.idx } else { mk_idx };
                        let old_p = pp.id;
                        let rn = st.get(r)?;
                        let (pi, pf) = search_index(&s, &rn, self.cmp, key);
                        p = Some(At { id: r, idx: pi, found: pf });
                        let cid = self.child_modify(st, r, pi)?;
                        let cn = st.get(cid)?;
                        let (ci, cf) = search_index(&s, &cn, self.cmp, key);
                        c = At { id: cid, idx: ci, found: cf };
                        mk_idx = iv;
                        if mk_parent == Some(old_p) {
                            if old_p == root && pi == 0 {
                                mk_node = Some(r);
                                mk_parent = Some(root);
                            } else if pi == 0 {
                                mk_idx = g.idx;
                                mk_node = Some(r);
                                mk_parent = Some(g.id);
                            } else {
                                mk_node = Some(c.id);
                                mk_idx = pi;
                                mk_parent = Some(r);
                            }
                        } else if first {
                        } else if !pf || pi != 0 {
                            if c.found && c.idx == 0 {
                                first = true;
                                mk_node = Some(c.id);
                                mk_idx = pi;
                                mk_parent = Some(r);
                            }
                        } else {
                            first = true;
                            mk_idx = g.idx;
                            mk_node = Some(r);
                            mk_parent = Some(g.id);
                        }
                    }
                }
            }
            if st.get(c.id)?.is_leaf() {
                break;
            }
            gp = p;
            p = Some(c);
            let cid = self.child_modify(st, c.id, c.idx)?;
            let cn = st.get(cid)?;
            let (ci, cf) = search_index(&s, &cn, self.cmp, key);
            c = At { id: cid, idx: ci, found: cf };
        }
        if !c.found {
            return Ok(None);
        }
        let mut cn = st.get(c.id)?;
        let v = cn.val(&s, c.idx).map(|v| v.to_vec());
        cn.remove(&s, c.idx, false);
        st.put(c.id, cn)?;
        self.set_info(st, |i| i.key_count -= 1)?;
        let cn = st.get(c.id)?;
        if c.idx == 0 && cn.nkeys() != 0 {
            if let Some(pp) = p {
                let k0 = cn.key(&s, 0).to_vec();
                self.key_update(st, pp.id, pp.idx, &k0)?;
            }
        }
        let under = self.underflow(&cn);
        if first && cn.nkeys() != 0 {
            let newmin = cn.key(&s, 0).to_vec();
            if let Some(mp) = mk_parent {
                self.key_update(st, mp, mk_idx, &newmin)?;
            }
            let mut node = mk_node;
            while let Some(nid) = node {
                let nn = st.get(nid)?;
                if nn.is_leaf() {
                    break;
                }
                let (i, f) = search_index(&s, &nn, self.cmp, key);
                if !f || nn.level() == 1 {
                    break;
                }
                self.key_update(st, nid, i, &newmin)?;
                node = Some(self.child_modify(st, nid, i)?);
            }
        }
        if under {
            let mkey = if c.idx != 0 || cn.nkeys() == 0 { key.to_vec() } else { cn.key(&s, 0).to_vec() };
            self.merge_up(st, &mkey)?;
        }
        Ok(Some(v))
    }

    /// The underflow test (0x10002c408): never a root leaf; a fixed-size
    /// node without ghosts under half its table, any other empty or more
    /// than half free.
    fn underflow(&self, n: &Node) -> bool {
        let s = &self.shape;
        if n.is_root() && n.is_leaf() {
            return false;
        }
        if n.flags() & flags::FIXED_KV_SIZE == 0 || s.bt_flags & tree_flags::ALLOW_GHOSTS != 0 {
            if n.nkeys() == 0 {
                return true;
            }
            let space = s.node_size - if n.is_root() { HDR + INFO } else { HDR };
            space / 2 < n.free(s)
        } else {
            n.nkeys() < n.toc_len() / 8
        }
    }

    /// `bt_merge_up` (0x10002c4a4): the path to `key`'s leaf fetched for
    /// modification, then from the leaf up, while the node underflows, its
    /// merge with its right sibling ([`Tree::merge_nodes`]) and its
    /// parent's key for it brought up to date; at the root, the height
    /// shrink.
    fn merge_up(&mut self, st: &mut dyn Store, key: &[u8]) -> Result<(), String> {
        let s = self.shape;
        self.root = st.modify(self.root)?;
        let mut nodes = vec![self.root];
        let mut idxs: Vec<usize> = Vec::new();
        loop {
            let n = st.get(*nodes.last().unwrap())?;
            if n.is_leaf() {
                break;
            }
            let (i, _) = search_index(&s, &n, self.cmp, key);
            idxs.push(i);
            let c = self.child_modify(st, *nodes.last().unwrap(), i)?;
            nodes.push(c);
        }
        let depth = idxs.len();
        if depth == 0 {
            return Ok(());
        }
        idxs.push(0);
        let mut u = depth;
        loop {
            if u < 1 {
                self.merge_nodes(st, None, 0, nodes[0], idxs[0], Some(nodes[1]))?;
                break;
            }
            let child = if u < depth { Some(nodes[u + 1]) } else { None };
            // An emptied node is deleted: its record count reads zero.
            let gone = self.merge_nodes(st, Some(nodes[u - 1]), idxs[u - 1], nodes[u], idxs[u], child)?;
            let un = if gone { None } else { Some(st.get(nodes[u])?) };
            let un_keys = un.as_ref().map_or(0, |n| n.nkeys());
            if un_keys == 0 && u > 1 {
                if idxs[u - 1] == 0 {
                    let mut v = u - 1;
                    if st.get(nodes[v])?.nkeys() != 0 {
                        loop {
                            if idxs[v] != 0 {
                                break;
                            }
                            let k0 = st.get(nodes[v])?.key(&s, 0).to_vec();
                            let was = v;
                            v -= 1;
                            let kp = st.get(nodes[v])?.key(&s, idxs[v]).to_vec();
                            if (self.cmp)(&k0, &kp) != Ordering::Equal {
                                self.key_update(st, nodes[v], idxs[v], &k0)?;
                            }
                            if !(st.get(nodes[v])?.nkeys() != 0 && was > 1) {
                                break;
                            }
                        }
                    }
                }
            } else if let Some(un) = un.filter(|n| n.nkeys() != 0) {
                let kp = st.get(nodes[u - 1])?.key(&s, idxs[u - 1]).to_vec();
                let k0 = un.key(&s, 0).to_vec();
                if (self.cmp)(&k0, &kp) != Ordering::Equal {
                    self.key_update(st, nodes[u - 1], idxs[u - 1], &k0)?;
                }
            }
            let under = self.underflow(&st.get(nodes[u - 1])?);
            u -= 1;
            if !under {
                break;
            }
        }
        Ok(())
    }

    /// `bt_merge_nodes` (0x100030548): node `n` (entry `pidx` of `parent`)
    /// emptied is removed; else records move to it from the front of its
    /// right sibling, all of them if they fit, else up to the point that
    /// balances the two nodes' free space (half the records for fixed-size
    /// nodes), the sibling removed when emptied. A root index node with
    /// one entry takes its child's records when there is room for its
    /// info (the height shrink).
    fn merge_nodes(&mut self, st: &mut dyn Store, parent: Option<u64>, pidx: usize, n: u64, nidx: usize, child: Option<u64>) -> Result<bool, String> {
        let s = self.shape;
        let ghosts = s.bt_flags & tree_flags::ALLOW_GHOSTS != 0;
        let nn = st.get(n)?;
        let Some(p) = parent else {
            if nn.is_leaf() || nn.nkeys() != 1 {
                return Ok(false);
            }
            let c = match (nidx, child) {
                (0, Some(c)) => c,
                _ => self.child_modify(st, n, 0)?,
            };
            let mut cn = st.get(c)?;
            if cn.free(&s) < INFO {
                return Ok(false);
            }
            if cn.free_len() < INFO {
                if cn.flags() & flags::FIXED_KV_SIZE == 0 || ghosts {
                    cn.compact(&s, 0);
                    st.put(c, cn.clone())?;
                    if cn.free_len() < INFO {
                        return Ok(false);
                    }
                } else {
                    return Ok(false);
                }
            }
            let mut rn = st.get(n)?;
            let level = rn.level();
            rn.b.put16(0x22, level - 1);
            if !cn.is_leaf() {
                rn.remove(&s, 0, true);
                if rn.flags() & flags::FIXED_KV_SIZE == 0 || ghosts {
                    rn.compact(&s, 0);
                }
            } else {
                rn.remove(&s, 0, false);
            }
            st.put(n, rn)?;
            let cnt = cn.nkeys();
            self.move_entries(st, n, c, -(cnt as isize))?;
            self.drop_node(st, c)?;
            return Ok(false);
        };
        if nn.nkeys() == 0 {
            let mut pn = st.get(p)?;
            pn.remove(&s, pidx, false);
            st.put(p, pn)?;
            self.drop_node(st, n)?;
            return Ok(true);
        }
        let pn = st.get(p)?;
        if (pidx as u32) >= (pn.nkeys() as u32).wrapping_sub(1) {
            return Ok(false);
        }
        let sid = self.child_modify(st, p, pidx + 1)?;
        let sn = st.get(sid)?;
        let ns = sn.nkeys();
        let (fail, cnt) = if nn.flags() & flags::FIXED_KV_SIZE == 0 {
            let tocn0 = nn.toc_need(&s, 0) as u32;
            let freen = nn.free(&s) as u32;
            let frees = sn.free(&s) as u32;
            let (mut cnt, mut size, mut i) = (0u32, 0u32, 0usize);
            let fail = loop {
                if i == ns {
                    break None;
                }
                if cnt == 0 && i != 0 {
                    let t = nn.toc_need(&s, i as isize) as u32;
                    let g = if tocn0 * 8 <= t * 8 { t * 8 - tocn0 * 8 } else { 0 };
                    cnt = i as u32;
                    if (frees.wrapping_add(freen)) >> 1 <= freen.wrapping_sub(size).wrapping_sub(g) {
                        cnt = 0;
                    }
                }
                size += (s.r(sn.loc(&s, i).kl as usize) + s.r(sn.val_len(&s, i))) as u32;
                let t = nn.toc_need(&s, i as isize + 1) as u32;
                let g2 = if tocn0 * 8 <= t * 8 { t * 8 - tocn0 * 8 } else { 0 };
                if size + g2 > freen {
                    break Some(i);
                }
                i += 1;
            };
            (fail, cnt as usize)
        } else {
            let nnk = nn.nkeys();
            if nn.toc_need(&s, 0) < ns + nnk {
                let half = (ns + nnk) >> 1;
                let c = if nnk <= half { half - nnk } else { 0 };
                (Some(c), c)
            } else {
                (None, 0)
            }
        };
        let count = match fail {
            None => ns,
            Some(f) if f == ns => ns,
            Some(_) => {
                let old = s.r(pn.key(&s, pidx + 1).len());
                let new = s.r(sn.loc(&s, cnt).kl as usize);
                if new <= old || pn.has_room(&s, &[], &[], new - old, 0).0 {
                    cnt
                } else {
                    return Ok(false);
                }
            }
        };
        if count == 0 {
            return Ok(false);
        }
        self.move_entries(st, n, sid, -(count as isize))?;
        let sn = st.get(sid)?;
        if sn.nkeys() == 0 {
            let mut pn = st.get(p)?;
            pn.remove(&s, pidx + 1, false);
            st.put(p, pn)?;
            self.drop_node(st, sid)?;
        } else {
            let k0 = sn.key(&s, 0).to_vec();
            self.key_update(st, p, pidx + 1, &k0)?;
        }
        Ok(false)
    }

    /// `bt_shift_or_split`'s scan (0x100027d4c..0x100028618): from `n`'s
    /// last record down, which records (and whether the pending ones)
    /// move to the right node `r` (the sibling, given up for a new node
    /// when what has to move does not fit it), until `n` has room for what
    /// stays (a new right node also balancing the free space), or a middle
    /// node is needed.
    #[allow(clippy::too_many_arguments)]
    fn scan(&self, st: &mut dyn Store, _n: u64, nn: &Node, r: &mut Option<u64>, rnew: &mut bool, pend_n: &mut i64, idx: i64, newb: i64, pend: &Pending, freed0: i64, keyeq: i64, repl: bool, fixed_ng: bool, seq: bool) -> Result<End, String> {
        let s = self.shape;
        let leaf = nn.is_leaf();
        let cnt = pend.klens.len() as i64;
        let esz: i64 = if nn.flags() & flags::FIXED_KV_SIZE != 0 { 4 } else { 8 };
        let nk = nn.nkeys() as i64;
        let tocn0 = nn.toc_need(&s, 0) as i64;
        let freen = nn.free(&s) as i64;
        let mut i = nk - 1;
        let mut b = nk;
        if i < 0 {
            return Ok(End::Stop(0));
        }
        let pb = newb + pend.extra as i64;
        let mut need_n = pb;
        let mut freed_n = freed0;
        let mut out_n = i64::from(repl);
        let mut moved_cnt = 0i64;
        let mut moved_bytes = 0i64;
        let mut rn = st.get(r.ok_or("a split scan with no right node")?)?;
        let mut toc_r = rn.toc_need(&s, 0) as i64 * esz;
        let mut free_r = rn.free(&s) as i64;
        let tn = |n: &Node, x: i64| n.toc_need(&s, x as isize) as i64;
        let back = |i: i64, b: i64| if repl { b - 2 } else { i };
        loop {
            let net = *pend_n - out_n;
            let room_n = freed_n + freen + (tocn0 - tn(nn, net)) * esz;
            let spare_n = room_n - need_n;
            let fits = if need_n <= room_n && fixed_ng { tn(nn, 0) > net + nk } else { need_n <= room_n };
            let nr = rn.nkeys() as i64;
            let spare_r = |mb: i64, mc: i64, rn: &Node| toc_r + free_r - mb - esz * tn(rn, mc);
            if fits {
                if !*rnew {
                    return Ok(End::Stop(i + 1));
                }
                if !seq {
                    let stop = if fixed_ng { net + nk <= nr + moved_cnt || i == 0 } else { spare_n >= spare_r(moved_bytes, moved_cnt, &rn) || i == 0 };
                    if stop {
                        return Ok(End::Stop(i + 1));
                    }
                } else if leaf || nr + moved_cnt >= 2 || i == 0 || spare_n >= spare_r(moved_bytes, moved_cnt, &rn) / 4 {
                    return Ok(End::Stop(i + 1));
                }
            }
            // Something moves to the right node.
            let mut cur = moved_cnt;
            if leaf && b - i64::from(repl) == idx {
                // The pending records sit at the boundary.
                let mc2 = moved_cnt + cnt;
                let tr = tn(&rn, mc2);
                let need = moved_bytes + newb - toc_r + tr * esz;
                let fits_r = need <= free_r && (!fixed_ng || mc2 + nr < tn(&rn, 0));
                if fits_r {
                    *pend_n -= cnt;
                    if !*rnew || seq {
                        return Ok(End::Stop(back(i, b) + 1));
                    }
                    need_n -= pb;
                    moved_bytes += pb;
                    let stop = if fixed_ng { i == 0 || (*pend_n - out_n) + nk <= nr + mc2 } else { i == 0 || toc_r + free_r - moved_bytes - tr * esz <= spare_n };
                    if stop {
                        return Ok(End::Stop(back(i, b) + 1));
                    }
                    cur = mc2;
                } else {
                    if !*rnew {
                        *r = Some(self.new_node_like(st, nn)?);
                        *rnew = true;
                        rn = st.get(r.unwrap())?;
                        toc_r = rn.toc_need(&s, 0) as i64 * esz;
                        free_r = rn.free(&s) as i64;
                        i = b - 1;
                        if i < 0 {
                            return Ok(End::Stop(0));
                        }
                        continue;
                    }
                    let i2 = back(i, b);
                    return Ok(if spare_n >= 0 { End::Stop(i2 + 1) } else { End::Middle(i2 + 1) });
                }
            }
            // Record `i` moves, with the pending records if they go
            // after it.
            let sz = (s.r(nn.loc(&s, i as usize).kl as usize) + s.r(nn.val_len(&s, i as usize))) as i64;
            moved_cnt = cur;
            if repl && i == idx {
                b = idx;
                i = b - 1;
                if i < 0 {
                    return Ok(End::Stop(0));
                }
                continue;
            }
            let takes = !(*pend_n == 0 || idx <= i + keyeq);
            let (pc, pbb) = if takes { (cnt, pb) } else { (0, 0) };
            let mc_new = cur + pc + 1;
            let need = pbb + moved_bytes - toc_r + sz + tn(&rn, mc_new) * esz;
            let fits_r = need <= free_r && (!fixed_ng || mc_new + nr < tn(&rn, 0));
            if fits_r {
                moved_bytes += pbb + sz;
                *pend_n -= pc;
                need_n -= pbb;
                out_n += 1;
                freed_n += sz;
                moved_cnt = mc_new;
                b = i;
                i = b - 1;
                if i < 0 {
                    return Ok(End::Stop(0));
                }
                continue;
            }
            if !*rnew {
                *r = Some(self.new_node_like(st, nn)?);
                *rnew = true;
                rn = st.get(r.unwrap())?;
                toc_r = rn.toc_need(&s, 0) as i64 * esz;
                free_r = rn.free(&s) as i64;
                moved_cnt = cur;
                continue;
            }
            if spare_n >= 0 {
                return Ok(End::Stop(i + 1));
            }
            if leaf {
                return Ok(End::Middle(i + 1));
            }
            if i < 1 {
                return Ok(End::NoMiddle(i + 1));
            }
            return Ok(End::Middle(i + 1));
        }
    }
}

/// Where `bt_shift_or_split`'s scan ends: the split point, and whether a
/// middle node takes the pending records.
enum End {
    Stop(i64),
    Middle(i64),
    NoMiddle(i64),
}

/// The free space of a node's root measure (the free queue's "too big"
/// test): its gap and free lists.
pub fn root_free(n: &Node) -> usize {
    n.free_len() + n.key_free_len() + n.val_free_len()
}

/// The bytes a node's records may take (`nodesize - 0x38`, less the info
/// of a root).
pub fn node_space(s: &Shape, root: bool) -> usize {
    s.node_size - HDR - if root { INFO } else { 0 }
}

/// The object-map key order (0x10003d0b4): identifier, then transaction,
/// unsigned.
pub fn cmp_omap(a: &[u8], b: &[u8]) -> Ordering {
    let q = |k: &[u8], o: usize| u64::from_le_bytes(k[o..o + 8].try_into().unwrap());
    q(a, 0).cmp(&q(b, 0)).then(q(a, 8).cmp(&q(b, 8)))
}

/// The free queue's (0x100043c64): transaction unsigned, then address
/// signed.
pub fn cmp_fq(a: &[u8], b: &[u8]) -> Ordering {
    let q = |k: &[u8], o: usize| u64::from_le_bytes(k[o..o + 8].try_into().unwrap());
    q(a, 0).cmp(&q(b, 0)).then((q(a, 8) as i64).cmp(&(q(b, 8) as i64)))
}

/// The file extent tree's (0x100009fc0): private identifier, then
/// logical address.
pub fn cmp_fext(a: &[u8], b: &[u8]) -> Ordering {
    cmp_omap(a, b)
}

/// `name_cmp` (0x10001d56c): the first `min(la, lb) - 1` bytes, stopping
/// after a NUL; then the shorter first.
fn name_cmp(a: &[u8], b: &[u8]) -> Ordering {
    let n = a.len().min(b.len()).saturating_sub(1);
    for i in 0..n {
        if a[i] != b[i] {
            return a[i].cmp(&b[i]);
        }
        if a[i] == 0 {
            return Ordering::Equal;
        }
    }
    a.len().cmp(&b.len())
}

/// The file-system object key order (`jobj` keys of the fs, extent
/// reference and snapshot trees, 0x10001a1a4), for a volume whose names
/// are hashed (`incompat & 9`) or not.
pub fn cmp_jobj(a: &[u8], b: &[u8], hashed: bool) -> Ordering {
    let q = |k: &[u8], o: usize| u64::from_le_bytes(k[o..o + 8].try_into().unwrap());
    let (ha, hb) = (q(a, 0), q(b, 0));
    let (oa, ob) = (ha & 0x0fff_ffff_ffff_ffff, hb & 0x0fff_ffff_ffff_ffff);
    if oa != ob {
        return oa.cmp(&ob);
    }
    let (ta, tb) = (ha >> 60, hb >> 60);
    if ta == 0 || tb == 0 {
        return match (ta == 0, tb == 0) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Less,
            _ => Ordering::Greater,
        };
    }
    if ta != tb {
        return ta.cmp(&tb);
    }
    let u16_at = |k: &[u8], o: usize| u16::from_le_bytes([k[o], k[o + 1]]) as usize;
    let first_low = |x: u64, y: u64, low: u64| -> Ordering {
        match (x == low, y == low) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => x.cmp(&y),
        }
    };
    match ta {
        4 | 11 => name_cmp(&a[10..10 + u16_at(a, 8)], &b[10..10 + u16_at(b, 8)]),
        9 if hashed => {
            let (xa, xb) = (u32::from_le_bytes(a[8..12].try_into().unwrap()), u32::from_le_bytes(b[8..12].try_into().unwrap()));
            (xa >> 10).cmp(&(xb >> 10)).then_with(|| name_cmp(&a[12..12 + (xa & 0x3ff) as usize], &b[12..12 + (xb & 0x3ff) as usize]))
        }
        9 => name_cmp(&a[10..10 + u16_at(a, 8)], &b[10..10 + u16_at(b, 8)]),
        5 => first_low(q(a, 8), q(b, 8), 0),
        8 => first_low(q(a, 8), q(b, 8), u64::MAX),
        13 => {
            let (ia, ib) = (a[15] as u64, b[15] as u64);
            first_low(ia, ib, 0).then_with(|| first_low(q(a, 8) & 0x00ff_ffff_ffff_ffff, q(b, 8) & 0x00ff_ffff_ffff_ffff, 0x00ff_ffff_ffff_ffff))
        }
        14 => {
            let (sa, sb) = (a[8], b[8]);
            if sa != sb {
                return sa.cmp(&sb);
            }
            match sa {
                0x10 => first_low(q(a, 12), q(b, 12), 0).then_with(|| first_low(q(a, 20), q(b, 20), 0)),
                0x11 => first_low(q(a, 12), q(b, 12), 0),
                0x13 => q(a, 12).cmp(&q(b, 12)).then(q(a, 20).cmp(&q(b, 20))),
                _ => Ordering::Equal,
            }
        }
        _ => Ordering::Equal,
    }
}

/// [`cmp_jobj`] for a volume whose directory-record names are hashed.
pub fn cmp_jobj_hashed(a: &[u8], b: &[u8]) -> Ordering {
    cmp_jobj(a, b, true)
}

/// [`cmp_jobj`] for a volume whose directory-record names are not hashed.
pub fn cmp_jobj_plain(a: &[u8], b: &[u8]) -> Ordering {
    cmp_jobj(a, b, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Nodes in memory, numbered in creation order, kept where they are
    /// (a virtual tree within one transaction).
    #[derive(Default)]
    pub(crate) struct Mem {
        pub nodes: HashMap<u64, Node>,
        next: u64,
    }

    impl Store for Mem {
        fn get(&mut self, id: u64) -> Result<Node, String> {
            self.nodes.get(&id).cloned().ok_or_else(|| format!("no node {id}"))
        }
        fn put(&mut self, id: u64, n: Node) -> Result<(), String> {
            self.nodes.insert(id, n);
            Ok(())
        }
        fn modify(&mut self, id: u64) -> Result<u64, String> {
            Ok(id)
        }
        fn create(&mut self, n: Node) -> Result<u64, String> {
            let id = self.next;
            self.next += 1;
            self.nodes.insert(id, n);
            Ok(id)
        }
        fn delete(&mut self, id: u64) -> Result<(), String> {
            self.nodes.remove(&id);
            Ok(())
        }
    }

    /// Each index value's hash filled in bottom up, the root's hash.
    fn seal(m: &mut Mem, s: &Shape, id: u64) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut n = m.nodes[&id].clone();
        if !n.is_leaf() {
            for i in 0..n.nkeys() {
                let c = n.child(s, i);
                let h = seal(m, s, c);
                let mut v = c.to_le_bytes().to_vec();
                v.extend_from_slice(&h);
                n.update(s, i, None, Some(&v), false).unwrap();
            }
            m.nodes.insert(id, n.clone());
        }
        Sha256::digest(&n.b).into()
    }

    /// The sealed tree's sequential build is seal.rs's, node for node and
    /// hash for hash, for records of many sizes.
    #[test]
    fn sequential_build_matches_the_seal_builder() {
        let s = Shape { bt_flags: 0x1c2, node_size: 4096, key_size: 0, val_size: 0, hash_size: 32 };
        let mut m = Mem::default();
        let mut t = Tree::create(&mut m, s, cmp_jobj_hashed).unwrap();
        let mut recs = Vec::new();
        let mut x = 0x1234_5678u64;
        for oid in 16..9000u64 {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let k = (oid | 3 << 60).to_le_bytes().to_vec();
            let v = vec![(x >> 33) as u8; 20 + (x >> 40) as usize % 300];
            recs.push((k, v));
        }
        for (k, v) in &recs {
            t.insert(&mut m, k, Some(v)).unwrap();
        }
        let h = seal(&mut m, &s, t.root);
        let (b, want) = super::super::seal::build(recs.clone()).unwrap();
        let mut keep = Some(std::collections::BTreeMap::new());
        b.seal(0x1c2, &mut keep).unwrap();
        let keep = keep.unwrap();
        assert_eq!(keep.len(), m.nodes.len());
        for (id, bytes) in &keep {
            assert_eq!(&m.nodes[id].b, bytes, "node {id}");
        }
        assert_eq!(h, want);
        assert_eq!(t.records(&mut m).unwrap().len(), recs.len());
    }

    /// The tree's signature as the oracle computes it after each
    /// operation: FNV-1a over the nodes past their headers in preorder,
    /// index values replaced by the children's preorder numbers.
    fn signature(m: &mut Mem, t: &Tree) -> u64 {
        let ids = t.node_ids(m).unwrap();
        let pos: HashMap<u64, u64> = ids.iter().enumerate().map(|(i, &o)| (o, i as u64)).collect();
        let mut h: u64 = 0xcbf29ce484222325;
        for id in ids {
            let mut b = m.nodes[&id].clone();
            if !b.is_leaf() {
                for i in 0..b.nkeys() {
                    let c = b.child(&t.shape, i);
                    let e = b.vend() - b.loc(&t.shape, i).v as usize;
                    b.b[e..e + 8].copy_from_slice(&pos.get(&c).copied().unwrap_or(u64::MAX).to_le_bytes());
                }
            }
            for &x in &b.b[0x20..] {
                h ^= u64::from(x);
                h = h.wrapping_mul(0x100000001b3);
            }
        }
        h
    }

    /// Operation sequences replayed against the device library's own
    /// `btree_create`, `bt_insert` and `bt_remove` (GEX_TEST_BT_ORACLE: a
    /// directory of `NAME.ops` and the nodes the device made, `NAME.out`):
    /// every node byte for byte past its object header, in the same tree
    /// shape.
    #[test]
    fn operations_match_the_device_library() {
        let Ok(dir) = std::env::var("GEX_TEST_BT_ORACLE") else { return };
        let mut names: Vec<_> = std::fs::read_dir(&dir).unwrap().filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "ops")).collect();
        names.sort();
        assert!(!names.is_empty());
        let mut failures = Vec::new();
        for ops in names {
            let out = ops.with_extension("out");
            let Ok(dev) = std::fs::read(&out) else { continue };
            let b = std::fs::read(&ops).unwrap();
            let h = |i: usize| u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().unwrap());
            let s = Shape { bt_flags: h(0), node_size: h(4) as usize, key_size: h(1) as usize, val_size: h(2) as usize, hash_size: 0 };
            let cmp: Cmp = match h(3) {
                0 => cmp_jobj_hashed,
                1 => cmp_omap,
                _ => cmp_fq,
            };
            let mut m = Mem::default();
            let mut t = Tree::create(&mut m, s, cmp).unwrap();
            let mut at = 20;
            let mut n = 0;
            let name = ops.file_name().unwrap().to_string_lossy().to_string();
            if std::env::var("GEX_TEST_BT_ONLY").is_ok_and(|o| !name.starts_with(&o)) {
                continue;
            }
            let mut err = None;
            let sigs: Option<Vec<u64>> = std::fs::read(ops.with_extension("sig")).ok().map(|v| v.chunks(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect());
            let mut first_diverging = None;
            while at < b.len() {
                let op = b[at];
                let kl = u16::from_le_bytes([b[at + 1], b[at + 2]]) as usize;
                let vl = u16::from_le_bytes([b[at + 3], b[at + 4]]) as usize;
                let k = b[at + 5..at + 5 + kl].to_vec();
                let v = b[at + 5 + kl..at + 5 + kl + vl].to_vec();
                at += 5 + kl + vl;
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| if op == 1 { t.insert(&mut m, &k, (vl != 0).then_some(&v[..])) } else { t.remove(&mut m, &k).map(|_| ()) })).unwrap_or_else(|_| Err("panicked".into()));
                if std::env::var("GEX_TEST_BT_DUMPAT").is_ok_and(|d| d.parse() == Ok(n)) {
                    let mut f = Vec::new();
                    for id in t.node_ids(&mut m).unwrap() {
                        f.extend_from_slice(&id.to_le_bytes());
                        f.extend_from_slice(&m.nodes[&id].b);
                    }
                    std::fs::write(std::env::var("GEX_TEST_BT_DUMP").unwrap() + ".at", f).unwrap();
                }
                if let Some(sig) = &sigs {
                    if first_diverging.is_none() && r.is_ok() && sig.get(n) != Some(&signature(&mut m, &t)) {
                        first_diverging = Some(n);
                        if let Ok(path) = std::env::var("GEX_TEST_BT_DUMP") {
                            let mut f = Vec::new();
                            for id in t.node_ids(&mut m).unwrap() {
                                f.extend_from_slice(&id.to_le_bytes());
                                f.extend_from_slice(&m.nodes[&id].b);
                            }
                            std::fs::write(path, f).unwrap();
                        }
                    }
                }
                if let Err(e) = r {
                    err = Some(format!("{name}: op {n}: {e}"));
                    break;
                }
                n += 1;
            }
            if let (Some(e), None) = (&err, first_diverging) {
                failures.push(e.clone());
                continue;
            }
            if let Some(f) = first_diverging {
                failures.push(format!("{name}: diverges at op {f}"));
                continue;
            }
            // The device's nodes, preorder.
            let ns = s.node_size;
            let dn: Vec<(u64, Vec<u8>)> = dev.chunks(8 + ns).map(|c| (u64::from_le_bytes(c[..8].try_into().unwrap()), c[8..].to_vec())).collect();
            let mine = t.node_ids(&mut m).unwrap();
            if mine.len() != dn.len() {
                failures.push(format!("{name}: {} nodes, the device {}", mine.len(), dn.len()));
                continue;
            }
            let dpos: HashMap<u64, u64> = dn.iter().enumerate().map(|(i, (o, _))| (*o, i as u64)).collect();
            let mpos: HashMap<u64, u64> = mine.iter().enumerate().map(|(i, o)| (*o, i as u64)).collect();
            let norm = |bytes: &[u8], pos: &HashMap<u64, u64>| -> Vec<u8> {
                let mut nd = Node { b: bytes.to_vec() };
                if !nd.is_leaf() {
                    for i in 0..nd.nkeys() {
                        let c = nd.child(&s, i);
                        let p = pos.get(&c).copied().unwrap_or(u64::MAX);
                        let e = nd.vend() - nd.loc(&s, i).v as usize;
                        nd.b[e..e + 8].copy_from_slice(&p.to_le_bytes());
                    }
                }
                nd.b[0x20..].to_vec()
            };
            for (j, id) in mine.iter().enumerate() {
                let a = norm(&m.nodes[id].b, &mpos);
                let d = norm(&dn[j].1, &dpos);
                if a != d {
                    let first = a.iter().zip(&d).position(|(x, y)| x != y).unwrap() + 0x20;
                    failures.push(format!("{name}: node {j} (level {}) differs first at byte {first:#x}", Node { b: dn[j].1.clone() }.level()));
                    break;
                }
            }
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }
}
