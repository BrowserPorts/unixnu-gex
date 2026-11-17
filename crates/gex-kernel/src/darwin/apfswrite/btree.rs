//! B-trees as APFS 2236.140.6 changes them (`apfs_invert`'s copy of the
//! library): `bt_insert` (0x100025e78) with the sequential split of
//! `bt_shift_or_split` (0x100027afc), `bt_remove_internal` (0x10002b138),
//! and the comparators of the trees the writer keeps (0x10001a1a4,
//! 0x10003d0b4, 0x100043c64, 0x100009fc0).
//!
//! Nodes come from a [`Store`]: fetched for modification top-down (the
//! root first), a physical tree's node taking a new address at its first
//! change in a transaction (its parent's entry following), a virtual
//! tree's keeping its identifier. Every tree here is a sequential-insert
//! tree; an insert that would split a node anywhere but at its end (the
//! general scan of `bt_shift_or_split`), and a removal that leaves a node
//! of a tree of more than one node underfull (`bt_merge_up`), are refused
//! as not implemented.

use super::node::{flags, tree_flags, Info, Node, Shape, ENOSPC, HDR, INFO};
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

fn nim(what: &str) -> String {
    format!("not implemented: {what}")
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

    /// An index entry's value for child `id`.
    fn child_val(&self, id: u64) -> Vec<u8> {
        let mut v = id.to_le_bytes().to_vec();
        v.resize(self.shape.index_val(), 0);
        v
    }

    /// Child `i` of `p` fetched for modification; `p`'s entry follows a
    /// new address (`child_id_update`, 0x10002784c).
    fn child_modify(&self, st: &mut dyn Store, p: u64, i: usize) -> Result<u64, String> {
        let s = &self.shape;
        let pn = st.get(p)?;
        let c = pn.child(s, i);
        let nc = st.modify(c)?;
        if nc != c {
            let mut pn = pn;
            let v = self.child_val(nc);
            pn.update(s, i, None, Some(&v[..8]), false).map_err(|e| format!("updating a child's address: {e}"))?;
            // The hash past the identifier is the seal's, not changed here.
            st.put(p, pn)?;
        }
        Ok(nc)
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
            id = n.child(s, i);
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
                self.walk(st, n.child(s, i), out)?;
            }
        }
        Ok(())
    }

    /// `bt_insert` (0x100025e78): record (`key`, `val`) inserted, or its
    /// value replaced; a `None` value is a ghost (no value bytes).
    pub fn insert(&mut self, st: &mut dyn Store, key: &[u8], val: Option<&[u8]>) -> Result<(), String> {
        let s = self.shape;
        let vl = val.map_or(0, |v| v.len());
        let longest_before = self.info(st)?.longest_key as usize;
        self.root = st.modify(self.root)?;
        let idxv = s.index_val();
        // The path down: (node, its slot in its parent).
        let mut gp: Option<(u64, usize)> = None;
        let mut p = self.root;
        let mut found_new = true;
        loop {
            let pn = st.get(p)?;
            if pn.is_leaf() {
                break;
            }
            let (pidx, pfound) = search_index(&s, &pn, self.cmp, key);
            let mut c = self.child_modify(st, p, pidx)?;
            let cn = st.get(c)?;
            let (cidx, cfound) = if cn.is_leaf() { search(&s, &cn, self.cmp, key) } else { search_index(&s, &cn, self.cmp, key) };
            if cn.is_leaf() && !cfound && cidx == cn.nkeys() && pidx + 1 < pn.nkeys() && !cn.has_room(&s, &[key.len()], &[vl], 0, 0).0 {
                return Err(nim("an insert moving right to the next leaf (bt_insert's move-right rule)"));
            }
            let pn = st.get(p)?;
            if cidx == 0 && !cfound && cn.is_leaf() && (self.cmp)(key, pn.key(&s, pidx)) == Ordering::Less {
                return Err(nim("an insert below its leaf's first key (the minimum-key update of bt_insert)"));
            }
            let lc = cn.longest_key(&s);
            let lens: Vec<usize> = if pn.level() < 2 { vec![lc, key.len()] } else { vec![key.len().max(lc); 2] };
            let vls = vec![idxv; lens.len()];
            if !pn.has_room(&s, &lens, &vls, 0, 0).0 {
                let ok = if cn.is_leaf() {
                    if cfound {
                        return Err(nim("replacing a record below a full index node"));
                    }
                    cn.has_room(&s, &[key.len()], &[vl], 0, 0).0
                } else {
                    let m2 = longest_before.max(key.len());
                    cn.has_room(&s, &vec![m2; lens.len()], &vls, 0, 0).0
                };
                if !ok {
                    let at = if pfound { pidx } else { pidx + 1 };
                    let r = self.shift_or_split(st, gp, p, at, key, &lens, &vls)?;
                    if let Some(r) = r {
                        p = r;
                        let pn = st.get(p)?;
                        let (pidx, _) = search_index(&s, &pn, self.cmp, key);
                        c = self.child_modify(st, p, pidx)?;
                        gp = Some((p, pidx));
                        p = c;
                        continue;
                    }
                }
            }
            gp = Some((p, pidx));
            p = c;
        }
        // The leaf.
        let mut ln = st.get(p)?;
        let (cidx, cfound) = search(&s, &ln, self.cmp, key);
        let rc = if cfound { ln.update(&s, cidx, None, val, false) } else { ln.insert_at(&s, cidx, Some(key), val, false) };
        match rc {
            Ok(()) => st.put(p, ln)?,
            Err(ENOSPC) => {
                if cfound {
                    return Err(nim("a replaced value that does not fit its leaf"));
                }
                let r = self.shift_or_split(st, gp, p, cidx, key, &[key.len()], &[vl])?.ok_or("a leaf split with nowhere for the record")?;
                let mut rn = st.get(r)?;
                let (ri, rf) = search(&s, &rn, self.cmp, key);
                if rf {
                    return Err("a split leaf holding the key being inserted".into());
                }
                rn.insert_at(&s, ri, Some(key), val, false).map_err(|e| format!("inserting into the split's node: {e}"))?;
                st.put(r, rn)?;
            }
            Err(e) => return Err(format!("inserting a record: {e}")),
        }
        if cfound {
            found_new = false;
        }
        self.set_info(st, |i| {
            i.longest_key = i.longest_key.max(key.len() as u32);
            i.longest_val = i.longest_val.max(vl as u32);
            if found_new {
                i.key_count += 1;
            }
        })
    }

    /// `bt_shift_or_split` (0x100027afc) for an insert at node `n`'s end
    /// with no right sibling (the sequential split): the node the pending
    /// entries (lengths `klens`, `vlens`) go in.
    fn shift_or_split(&mut self, st: &mut dyn Store, parent: Option<(u64, usize)>, n: u64, idx: usize, key: &[u8], _klens: &[usize], _vlens: &[usize]) -> Result<Option<u64>, String> {
        let s = self.shape;
        let nn = st.get(n)?;
        if let Some((p, pidx)) = parent {
            let pn = st.get(p)?;
            if pidx + 1 < pn.nkeys() {
                return Err(nim("a split with a right sibling (bt_shift_or_split's general scan)"));
            }
        }
        if s.bt_flags & tree_flags::SEQUENTIAL_INSERT == 0 || idx != nn.nkeys() {
            return Err(nim("a split inside a node (bt_shift_or_split's general scan)"));
        }
        let leaf = nn.is_leaf();
        let level = nn.level();
        let child_fl = (nn.flags() & (flags::LEAF | flags::HASHED | flags::NOHEADER)) & !flags::ROOT;
        // R, then (a root) L.
        let r = st.create(Node::format(&s, child_fl, level))?;
        self.set_info(st, |i| i.node_count += 1)?;
        let mut nn = st.get(n)?;
        let mut rn = st.get(r)?;
        if !leaf {
            nn.move_last_to_front(&s, &mut rn, 1);
        }
        st.put(n, nn)?;
        st.put(r, rn)?;
        let mut target_parent = parent.map(|(p, _)| p);
        if n == self.root {
            let l = st.create(Node::format(&s, child_fl, level))?;
            self.set_info(st, |i| i.node_count += 1)?;
            let mut root = st.get(n)?;
            let mut ln = st.get(l)?;
            let cnt = root.nkeys();
            ln.append_from_front(&s, &mut root, cnt);
            let info = Info::read(&root.b);
            root.reformat_root_index(&s, level + 1);
            info.write(&mut root.b);
            let first = if ln.nkeys() > 0 { ln.key(&s, 0).to_vec() } else { key.to_vec() };
            st.put(l, ln)?;
            let v = self.child_val(l);
            let (i, _) = search(&s, &root, self.cmp, &first);
            root.insert_at(&s, i, Some(&first), Some(&v), false).map_err(|e| format!("the root's first entry: {e}"))?;
            st.put(n, root)?;
            target_parent = Some(n);
        }
        let tp = target_parent.ok_or("a split of a node with no parent")?;
        let rn = st.get(r)?;
        let mut pn = st.get(tp)?;
        if rn.nkeys() > 0 {
            let rk = rn.key(&s, 0).to_vec();
            let v = self.child_val(r);
            let (i, f) = search(&s, &pn, self.cmp, &rk);
            if f {
                return Err("a split's right node keyed as an existing entry".into());
            }
            pn.insert_at(&s, i, Some(&rk), Some(&v), false).map_err(|e| format!("the split's parent entry: {e}"))?;
            st.put(tp, pn)?;
            return Ok(Some(r));
        }
        if !leaf {
            return Err("an index split leaving its right node empty".into());
        }
        // The empty right leaf is the middle node, keyed by the record.
        let v = self.child_val(r);
        let (i, f) = search(&s, &pn, self.cmp, key);
        if f {
            return Err("a split's new leaf keyed as an existing entry".into());
        }
        pn.insert_at(&s, i, Some(key), Some(&v), false).map_err(|e| format!("the split's parent entry: {e}"))?;
        st.put(tp, pn)?;
        Ok(Some(r))
    }

    /// `bt_remove` of `key` (0x10002b138): its value, or none if absent.
    pub fn remove(&mut self, st: &mut dyn Store, key: &[u8]) -> Result<Option<Option<Vec<u8>>>, String> {
        let s = self.shape;
        if self.get(st, key)?.is_none() {
            return Ok(None);
        }
        self.root = st.modify(self.root)?;
        let rn = st.get(self.root)?;
        if !rn.is_leaf() {
            return Err(nim("removing a record from a tree of more than one node"));
        }
        let mut rn = rn;
        let (i, _) = search(&s, &rn, self.cmp, key);
        let v = rn.val(&s, i).map(|v| v.to_vec());
        rn.remove(&s, i, false);
        st.put(self.root, rn)?;
        self.set_info(st, |i| i.key_count -= 1)?;
        Ok(Some(v))
    }
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
}
