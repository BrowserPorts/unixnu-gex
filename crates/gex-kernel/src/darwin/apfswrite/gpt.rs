//! disk0's partition map as the restore writes it: `restored_external`'s
//! `create_filesystem_partition` (0x1000288e4) asks MediaKit for one GPT
//! partition, "Container" of type Apple_APFS over all the disk
//! (`MKCFBuildPartition(0x10, 0, "Apple_APFS", "Container", 0, 0, ...)`,
//! `MKCFCreateMap(..., alignment 8, ..., {Direct Mode: true})`), and
//! MediaKit (in the erase ramdisk) lays it out:
//!
//! - `GPTCFCreateMap` (0x2ea4): header at LBA 1, revision 1.0, 92 bytes;
//!   128 entries of 128 bytes from LBA 2, `E = 16384 / block size` blocks
//!   of them; FirstUsableLBA `E + 2`, LastUsableLBA `N - E - 2`; the
//!   backup entries at `N - 1 - E` and the backup header at `N - 1`;
//!   "Direct Mode" adds no loader partition;
//! - `GPTCFCreatePartition` (0x5154): alignment 8 sectors (one 4 KiB block
//!   at 4096-byte blocks); the partition from FirstUsableLBA rounded up to
//!   it to LastUsableLBA + 1 rounded down, less one; no attributes; name
//!   "Container" in UTF-16LE;
//! - `GPTWriteMedia` (0x7ad8): the type GUID of "Apple_APFS"
//!   (7C3457EF-0000-11AA-AA11-00306543ECAC, 0x34c7c); GUIDs stored with
//!   their first three fields little-endian (`uuid_BtoL`); the entry
//!   array's CRC-32 and the headers' (over their 92 bytes);
//! - the protective MBR (`PMNewPartitionExtended(.., 0xee, 0, 1, size)`,
//!   0x80ec, written by `MBRWriteMedia` 0x940c): one entry of type 0xee
//!   from LBA 1 over `min(N - 1, 0xffffffff)` blocks, no boot code, the
//!   0xaa55 signature; its CHS fields are `Setupdpp`'s (0x9d7c) with the
//!   map's 63 sectors a track (0x86e4): a start or end it cannot express
//!   (any but cylinder 0, head 1, sector 1 of a track) is 0xfe, 0xff, 0xff.
//!
//! The disk's and partition's GUIDs are `uuid_generate`'s: the caller's.

use super::{Put, Sink};
use crate::darwin::udif::Crc32;

/// `Apple_APFS`'s partition type.
pub const APPLE_APFS: &str = "7C3457EF-0000-11AA-AA11-00306543ECAC";

/// The partition's name.
pub const NAME: &str = "Container";

/// The GPT laid out on a disk of `blocks` blocks of `bs` bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Map {
    pub bs: u64,
    pub blocks: u64,
    /// Blocks of entries.
    pub entry_blocks: u64,
    pub first_usable: u64,
    pub last_usable: u64,
    /// The partition's first and last block.
    pub first: u64,
    pub last: u64,
}

impl Map {
    pub fn new(bs: u64, blocks: u64) -> Map {
        let entry_blocks = 16384u64.div_ceil(bs);
        let first_usable = entry_blocks + 2;
        let last_usable = blocks - entry_blocks - 2;
        // 8 sectors, in blocks (1024-byte blocks and up divide it).
        let align = if bs >= 1024 { (8 / (bs / 512)).max(1) } else { 8 };
        let first = first_usable.div_ceil(align) * align;
        let end = (last_usable + 1) / align * align;
        Map { bs, blocks, entry_blocks, first_usable, last_usable, first, last: end - 1 }
    }

    /// The partition's offset and size in bytes.
    pub fn extent(&self) -> (u64, u64) {
        (self.first * self.bs, (self.last + 1 - self.first) * self.bs)
    }
}

/// A GUID's 16 bytes as GPT stores them (`uuid_BtoL`): its first three
/// fields little-endian.
pub fn guid_le(u: [u8; 16]) -> [u8; 16] {
    let mut g = u;
    g[0..4].reverse();
    g[4..6].reverse();
    g[6..8].reverse();
    g
}

/// `uuid_parse`.
pub fn parse_uuid(s: &str) -> [u8; 16] {
    let h: Vec<u8> = s.bytes().filter(|c| *c != b'-').collect();
    let mut out = [0u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(std::str::from_utf8(&h[2 * i..2 * i + 2]).unwrap(), 16).unwrap();
    }
    out
}

fn crc(b: &[u8]) -> u32 {
    let mut c = Crc32::default();
    c.update(b);
    c.finish()
}

/// `Setupdpp`'s CHS of `lba` with 63 sectors a track: only a block a
/// whole track into cylinder 0 has one (head 1, sector 1); any other is
/// out of range.
fn chs(lba: u64, heads: u64) -> [u8; 3] {
    let track = 63u64;
    let cyl = lba / (track * heads);
    if cyl == 0 && lba % track == 0 && lba / track == 1 {
        return [1, 1, 0];
    }
    [0xfe, 0xff, 0xff]
}

/// Writes the protective MBR, both headers and both entry arrays on
/// `sink`, the whole disk.
pub fn write(sink: &dyn Sink, m: &Map, disk_guid: [u8; 16], partition_guid: [u8; 16]) -> Result<(), String> {
    let bs = m.bs as usize;
    // Protective MBR. The map's heads start at 2 and double while the
    // cylinders exceed 1024 (0x86f0..0x8750); a start of LBA 1 has no CHS
    // whatever they are (it is not a whole track in).
    let mut mbr = vec![0u8; bs];
    let size = (m.blocks - 1).min(0xffff_ffff) as u32;
    let e = 0x1be;
    mbr[e + 1..e + 4].copy_from_slice(&chs(1, 2));
    mbr[e + 4] = 0xee;
    mbr[e + 5..e + 8].copy_from_slice(&chs(u64::from(size), 2));
    mbr.put32(e + 8, 1);
    mbr.put32(e + 12, size);
    mbr.put16(0x1fe, 0xaa55);
    sink.write_at(0, &mbr)?;

    let mut entries = vec![0u8; (m.entry_blocks as usize) * bs];
    entries[0..16].copy_from_slice(&guid_le(parse_uuid(APPLE_APFS)));
    entries[16..32].copy_from_slice(&guid_le(partition_guid));
    entries.put64(32, m.first);
    entries.put64(40, m.last);
    for (i, u) in NAME.encode_utf16().enumerate() {
        entries.put16(56 + 2 * i, u);
    }
    let entries_crc = crc(&entries[..128 * 128]);
    let header = |my: u64, alt: u64, entry_lba: u64| {
        let mut h = vec![0u8; bs];
        h[0..8].copy_from_slice(b"EFI PART");
        h.put32(8, 0x0001_0000);
        h.put32(12, 92);
        h.put64(24, my);
        h.put64(32, alt);
        h.put64(40, m.first_usable);
        h.put64(48, m.last_usable);
        h[56..72].copy_from_slice(&guid_le(disk_guid));
        h.put64(72, entry_lba);
        h.put32(80, 128);
        h.put32(84, 128);
        h.put32(88, entries_crc);
        let c = crc(&h[..92]);
        h.put32(16, c);
        h
    };
    sink.write_at(2 * m.bs, &entries)?;
    sink.write_at((m.blocks - 1 - m.entry_blocks) * m.bs, &entries)?;
    sink.write_at(m.bs, &header(1, m.blocks - 1, 2))?;
    sink.write_at((m.blocks - 1) * m.bs, &header(m.blocks - 1, 1, m.blocks - 1 - m.entry_blocks))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_follows_mediakit() {
        let m = Map::new(4096, 15_625_000);
        assert_eq!((m.entry_blocks, m.first_usable, m.last_usable, m.first, m.last), (4, 6, 15_624_994, 6, 15_624_994));
        let s = Map::new(512, 1_000_000);
        assert_eq!((s.entry_blocks, s.first, s.last), (32, 40, 999_960 - 1));
        assert_eq!(guid_le(parse_uuid(APPLE_APFS))[..4], [0xef, 0x57, 0x34, 0x7c]);
    }
}
