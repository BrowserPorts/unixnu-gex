//! An APFS writer: the web device's internal storage made as its restore
//! makes it, in process (the product runs in a browser, so no host tool
//! builds it).
//!
//! The on-disk structures are the "Apple File System Reference"'s
//! (revision 2020-06-22); every layout decision that document leaves to
//! the implementation is the restore's own `newfs_apfs` (the erase
//! ramdisk's, APFS 2236.140.6, the version of the kernelcache's APFS kext):
//! its container sizing (0x100010208), metadata zone (0x100013fac,
//! 0x1000140b0), and what `-C` writes, checked byte for byte against what
//! that binary writes ([`container`]), and its transactions as they run
//! on a mounted container ([`tx`]). The GPT is MediaKit's ([`gpt`]); the
//! restore's steps are [`restore`]'s.

pub mod asr;
pub mod btree;
pub mod container;
pub mod fsops;
pub mod fxc;
pub mod gpt;
pub mod invert;
pub mod node;
pub mod restore;
pub mod seal;
pub mod sealvolume;
pub mod snapshot;
pub mod tx;

use super::apfsread::Medium;

/// What a writer writes to: the medium's bytes, read and written in place.
pub trait Sink: Medium {
    /// All of `buf` at byte `off`.
    fn write_at(&self, off: u64, buf: &[u8]) -> Result<(), String>;
}

/// A host file as a sink.
pub struct HostFile(pub std::fs::File, pub u64);

impl Medium for HostFile {
    fn size(&self) -> u64 {
        self.1
    }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<(), String> {
        use std::os::unix::fs::FileExt;
        self.0.read_exact_at(buf, off).map_err(|e| e.to_string())
    }
}

impl Sink for HostFile {
    fn write_at(&self, off: u64, buf: &[u8]) -> Result<(), String> {
        use std::os::unix::fs::FileExt;
        self.0.write_all_at(buf, off).map_err(|e| e.to_string())
    }
}

/// A window of a sink: a partition's bytes on its disk.
pub struct Window<'a> {
    pub sink: &'a dyn Sink,
    pub base: u64,
    pub size: u64,
}

impl Medium for Window<'_> {
    fn size(&self) -> u64 {
        self.size
    }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<(), String> {
        if off + buf.len() as u64 > self.size {
            return Err(format!("a read of {off}+{} past a {}-byte window", buf.len(), self.size));
        }
        self.sink.read_at(self.base + off, buf)
    }
}

impl Sink for Window<'_> {
    fn write_at(&self, off: u64, buf: &[u8]) -> Result<(), String> {
        if off + buf.len() as u64 > self.size {
            return Err(format!("a write of {off}+{} past a {}-byte window", buf.len(), self.size));
        }
        self.sink.write_at(self.base + off, buf)
    }
}

/// Little-endian stores into a block.
pub(crate) trait Put {
    fn put16(&mut self, o: usize, v: u16);
    fn put32(&mut self, o: usize, v: u32);
    fn put64(&mut self, o: usize, v: u64);
}

impl Put for [u8] {
    fn put16(&mut self, o: usize, v: u16) {
        self[o..o + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put32(&mut self, o: usize, v: u32) {
        self[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put64(&mut self, o: usize, v: u64) {
        self[o..o + 8].copy_from_slice(&v.to_le_bytes());
    }
}

/// `obj_phys_t`'s fields past the checksum.
pub(crate) fn put_header(b: &mut [u8], oid: u64, xid: u64, otype: u32, subtype: u32) {
    b.put64(8, oid);
    b.put64(16, xid);
    b.put32(24, otype);
    b.put32(28, subtype);
}

/// `obj_checksum_set`: the object's Fletcher-64 in its first eight bytes.
pub(crate) fn set_checksum(b: &mut [u8]) {
    let c = super::apfsread::fletcher64(b);
    b.put64(0, c);
}

pub(crate) fn cdiv(a: u64, b: u64) -> u64 {
    a.div_ceil(b)
}
