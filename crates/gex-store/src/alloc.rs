//! The store's block numbers: the next never used, and the freed. The
//! lowest freed block first, so that the store file grows only when every
//! block below its end is in use (a block above what was ever written costs
//! the origin's quota).
//!
//! While the root is kept across loads, a freed block waits ([`defer_frees`])
//! until the next generation is written: the last one written may still
//! name it. And a few blocks are kept back for the records: on a full store,
//! a delete's blocks are free only once a generation that no longer names
//! them is written, and writing it needs blocks of its own.
//!
//! [`defer_frees`]: Allocator::defer_frees

use crate::Errno;
use std::cmp::Reverse;
use std::collections::BinaryHeap;

/// How far the store file is grown at a time, in bytes.
pub const GROW: u64 = 64 << 20;
/// Blocks kept back for the records while frees are deferred. Files never
/// take these.
pub const RESERVE_BLOCKS: usize = 64;

#[derive(Debug)]
pub struct Allocator {
    /// The next block never used.
    next: u32,
    freed: BinaryHeap<Reverse<u32>>,
    /// How many blocks long the store file has been made: it is grown ahead,
    /// [`GROW`] at a time, so that a write never extends it (a sync access
    /// handle's write that has to grow the file can fail, and says so only
    /// through its count).
    grown: u64,
    reserve: Vec<u32>,
    /// Freed and waiting for the next generation.
    pending: Vec<u32>,
    defer: bool,
}

/// Make the store file at least this many bytes long: done, or why not.
pub type Grow<'a> = &'a mut dyn FnMut(u64) -> Result<(), Errno>;

impl Allocator {
    pub const fn new() -> Allocator {
        Allocator { next: 0, freed: BinaryHeap::new(), grown: 0, reserve: Vec::new(), pending: Vec::new(), defer: false }
    }

    /// Block 0 is the superblocks': never handed out.
    pub fn start(&mut self) {
        self.next = self.next.max(1);
    }

    /// The store's next block past the highest, the store grown ahead when
    /// it has none (ENOSPC when it cannot grow).
    fn grow_one(&mut self, bs: u64, grow: Grow) -> Result<u32, Errno> {
        if self.next as u64 >= self.grown {
            // Grown ahead, so that a quota failure comes here, at
            // allocation, as ENOSPC, not at a write-back; one block at a
            // time once the room left is less than that.
            let mut want = self.grown.max(self.next as u64) + (GROW / bs).max(1);
            if grow(want * bs).is_err() {
                want = self.next as u64 + 1;
                if grow(want * bs).is_err() {
                    return Err(Errno::ENOSPC);
                }
            }
            self.grown = want;
        }
        self.next += 1;
        Ok(self.next - 1)
    }

    /// A free block, the lowest first, else a new one.
    fn take(&mut self, bs: u64, grow: Grow) -> Result<u32, Errno> {
        match self.freed.pop() {
            Some(Reverse(p)) => Ok(p),
            None => self.grow_one(bs, grow),
        }
    }

    /// A place for a file's block, the lowest free first, the store grown
    /// ahead when there is none; the records' reserve kept full first,
    /// while frees are deferred.
    pub fn alloc_place(&mut self, bs: u64, grow: Grow) -> Result<u32, Errno> {
        if self.defer {
            while self.reserve.len() < RESERVE_BLOCKS {
                match self.take(bs, grow) {
                    Ok(p) => self.reserve.push(p),
                    Err(_) => break,
                }
            }
        }
        self.take(bs, grow)
    }

    /// A block for the records: the reserve's when the store has no other.
    pub fn alloc_meta(&mut self, bs: u64, grow: Grow) -> Result<u32, Errno> {
        self.take(bs, grow).or_else(|e| self.reserve.pop().ok_or(e))
    }

    /// A block no longer used: free now, or once the next generation is
    /// written while frees are deferred.
    pub fn free(&mut self, p: u32) {
        if self.defer {
            self.pending.push(p);
        } else {
            self.freed.push(Reverse(p));
        }
    }

    /// Frees wait for the next generation from now on.
    pub fn defer_frees(&mut self) {
        self.defer = true;
    }

    /// The blocks freed since the last call: a generation about to be
    /// written no longer names them.
    pub fn take_pending(&mut self) -> Vec<u32> {
        std::mem::take(&mut self.pending)
    }

    /// Blocks given back to the pending list (a generation that failed).
    pub fn repend(&mut self, v: Vec<u32>) {
        self.pending.extend(v);
    }

    /// Blocks free for use again now.
    pub fn release(&mut self, v: impl IntoIterator<Item = u32>) {
        for p in v {
            self.freed.push(Reverse(p));
        }
    }

    /// How many blocks of the store are in use or free below the highest
    /// ever allocated (block 0 included).
    pub fn high(&self) -> u32 {
        self.next
    }

    /// After a load's root was read back: `high` blocks long, those `used`
    /// taken (block 0 always), the rest free.
    pub fn rebuild(&mut self, high: u32, used: &[bool]) {
        self.reserve.clear();
        self.next = high.max(1);
        self.freed.clear();
        for p in 1..self.next {
            if !used.get(p as usize).copied().unwrap_or(false) {
                self.freed.push(Reverse(p));
            }
        }
        self.grown = self.grown.max(self.next as u64);
    }

    /// A fresh start: nothing allocated, frees at once.
    pub fn reset(&mut self) {
        *self = Allocator { next: 1, ..Allocator::new() };
    }
}

impl Default for Allocator {
    fn default() -> Allocator {
        Allocator::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lowest_free_block_comes_first_and_frees_wait_for_a_generation() {
        let mut a = Allocator::new();
        a.start();
        let mut grown = Vec::new();
        let mut grow = |n: u64| -> Result<(), Errno> {
            grown.push(n);
            Ok(())
        };
        let b: Vec<u32> = (0..4).map(|_| a.alloc_place(4096, &mut grow).unwrap()).collect();
        assert_eq!(b, [1, 2, 3, 4]);
        a.free(2);
        assert_eq!(a.alloc_place(4096, &mut grow).unwrap(), 2);
        a.defer_frees();
        a.free(3);
        let p = a.alloc_place(4096, &mut grow).unwrap();
        assert_ne!(p, 3, "a deferred free is not used before the next generation");
        let p = a.take_pending();
        a.release(p);
        assert_eq!(a.alloc_meta(4096, &mut grow).unwrap(), 3);
        assert_eq!(grown[0], (GROW / 4096 + 1) * 4096);
    }

    #[test]
    fn a_rebuild_frees_what_no_record_names() {
        let mut a = Allocator::new();
        a.rebuild(6, &[true, true, false, true, false, false]);
        let mut grow = |_: u64| -> Result<(), Errno> { Ok(()) };
        assert_eq!(a.alloc_meta(4096, &mut grow).unwrap(), 2);
        assert_eq!(a.alloc_meta(4096, &mut grow).unwrap(), 4);
        assert_eq!(a.alloc_meta(4096, &mut grow).unwrap(), 5);
        assert_eq!(a.alloc_meta(4096, &mut grow).unwrap(), 6);
        assert_eq!(a.high(), 7);
    }
}
