//! A reader of UDIF disk images (".dmg"), the format an IPSW's operating
//! system image is in (044-76040-038.dmg for 21H461), for the restore's
//! System volume, read without the host's DiskImages.
//!
//! Apple publishes no specification of the format; what is read is what
//! the image holds, and every byte this reader produces is checked by the
//! image's own CRC-32 of each partition's data ([`Udif::verify`]),
//! the checksum `hdiutil verify` checks, and matches what `hdiutil convert
//! -format UDTO` makes of the IPSW's system image chunk for chunk:
//!
//! - the trailer ("koly", the image's last 512 bytes, big-endian): the
//!   data fork's offset (+0x18) and length (+0x20), the property list's
//!   offset (+0xd8) and length (+0xe0), and the image's sector count
//!   (+0x1ec);
//! - the property list's `resource-fork`/`blkx` array: one entry per
//!   partition of the image's partition map, its `Name` the partition's
//!   name and type, its `Data` a "mish" table: the partition's first
//!   sector (+8) and sector count (+0x10), its data's offset in the data
//!   fork (+0x18), its checksum (type +0x40, bit count +0x44, value from
//!   +0x48), and its chunks from +0xcc, 40 bytes each: type, comment,
//!   first sector and sector count (relative to the partition's), and the
//!   chunk's offset (from the data fork's start) and length;
//! - chunk types: 0 (zeros), 1 (the bytes as they are), 2 (unallocated,
//!   read as zeros), 0x80000007 (LZFSE, [`super::lzfse`]), 0x7ffffffe (a
//!   comment: no data) and 0xffffffff (the table's end). A partition's
//!   CRC-32 covers its chunks' data except unallocated chunks' (measured:
//!   the system image's APFS partition's checksum, 0xcba7c2d2, is that of
//!   its data without its three type-2 chunks'). The other
//!   compressions images can use (ADC 0x80000004, zlib 0x80000005, bzip2
//!   0x80000006, LZMA 0x80000008) are refused as not implemented.
//!
//! Sectors are 512 bytes.

use super::apfsread::Medium;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

pub const SECTOR: u64 = 512;

/// A chunk's type.
pub mod chunk {
    pub const ZERO: u32 = 0x0000_0000;
    pub const RAW: u32 = 0x0000_0001;
    pub const IGNORE: u32 = 0x0000_0002;
    pub const ADC: u32 = 0x8000_0004;
    pub const ZLIB: u32 = 0x8000_0005;
    pub const BZIP2: u32 = 0x8000_0006;
    pub const LZFSE: u32 = 0x8000_0007;
    pub const LZMA: u32 = 0x8000_0008;
    pub const COMMENT: u32 = 0x7fff_fffe;
    pub const TERMINATOR: u32 = 0xffff_ffff;
}

/// A chunk of a partition's data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chunk {
    pub kind: u32,
    /// Its first sector in the image.
    pub sector: u64,
    pub sectors: u64,
    /// Its bytes' offset in the image file, and their length.
    pub offset: u64,
    pub length: u64,
}

/// A partition of the image (a `blkx` entry).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Partition {
    pub name: String,
    pub sector: u64,
    pub sectors: u64,
    /// The CRC-32 of its data, if the entry has one (checksum type 2).
    pub crc32: Option<u32>,
    pub chunks: Vec<Chunk>,
}

/// A UDIF image over a medium holding the image file's bytes.
pub struct Udif {
    file: Arc<dyn Medium>,
    pub sectors: u64,
    pub partitions: Vec<Partition>,
    /// The most recently decoded chunks: (partition, chunk index, bytes).
    cache: Mutex<VecDeque<(usize, usize, Arc<Vec<u8>>)>>,
}

/// How many decoded chunks are kept.
const CACHED_CHUNKS: usize = 8;

fn be32(b: &[u8], o: usize) -> Result<u32, String> {
    b.get(o..o + 4).map(|s| u32::from_be_bytes(s.try_into().unwrap())).ok_or_else(|| format!("a field at {o} past a {}-byte table", b.len()))
}

fn be64(b: &[u8], o: usize) -> Result<u64, String> {
    b.get(o..o + 8).map(|s| u64::from_be_bytes(s.try_into().unwrap())).ok_or_else(|| format!("a field at {o} past a {}-byte table", b.len()))
}

/// `CRC-32` (the reflected polynomial 0xedb88320, initial and final
/// inversion), the checksum the image keeps of each partition's data.
pub struct Crc32 {
    table: [u32; 256],
    value: u32,
}

impl Default for Crc32 {
    fn default() -> Self {
        let mut table = [0u32; 256];
        for (i, t) in table.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            *t = c;
        }
        Crc32 { table, value: 0xffff_ffff }
    }
}

impl Crc32 {
    pub fn update(&mut self, b: &[u8]) {
        let mut c = self.value;
        for &x in b {
            c = self.table[((c ^ u32::from(x)) & 0xff) as usize] ^ (c >> 8);
        }
        self.value = c;
    }
    pub fn finish(&self) -> u32 {
        self.value ^ 0xffff_ffff
    }
}

impl Udif {
    /// The image whose file's bytes `file` holds.
    pub fn open(file: Arc<dyn Medium>) -> Result<Udif, String> {
        let size = file.size();
        if size < 512 {
            return Err("an image shorter than its trailer".into());
        }
        let mut koly = [0u8; 512];
        file.read_at(size - 512, &mut koly)?;
        if &koly[..4] != b"koly" {
            return Err("no UDIF trailer (\"koly\") at the image's end".into());
        }
        let data_fork = be64(&koly, 0x18)?;
        let (xml_off, xml_len) = (be64(&koly, 0xd8)?, be64(&koly, 0xe0)?);
        let sectors = be64(&koly, 0x1ec)?;
        if xml_len == 0 || xml_off.checked_add(xml_len).is_none_or(|e| e > size) {
            return Err("the trailer's property list is not in the image".into());
        }
        let mut xml = vec![0u8; xml_len as usize];
        file.read_at(xml_off, &mut xml)?;
        let plist = super::plist::parse(&xml)?;
        let blkx = plist.get("resource-fork").and_then(|r| r.get("blkx")).and_then(|b| b.as_array()).ok_or("the property list has no resource-fork/blkx")?;
        let mut partitions = Vec::new();
        for e in blkx {
            let name = e.get("Name").and_then(|n| n.as_str()).unwrap_or("").to_string();
            let d = e.get("Data").and_then(|d| d.as_data()).ok_or("a blkx entry without Data")?;
            if d.get(..4) != Some(b"mish") {
                return Err(format!("partition {name:?}: its table is not \"mish\""));
            }
            let first = be64(d, 8)?;
            let count = be64(d, 0x10)?;
            let data_off = be64(d, 0x18)?;
            let crc32 = (be32(d, 0x40)? == 2 && be32(d, 0x44)? == 32).then(|| be32(d, 0x48)).transpose()?;
            let n = be32(d, 0xc8)? as usize;
            let mut chunks = Vec::with_capacity(n);
            for i in 0..n {
                let o = 0xcc + 40 * i;
                let kind = be32(d, o)?;
                let c = Chunk { kind, sector: first + be64(d, o + 8)?, sectors: be64(d, o + 16)?, offset: data_fork + data_off + be64(d, o + 24)?, length: be64(d, o + 32)? };
                if kind == chunk::TERMINATOR {
                    break;
                }
                if kind == chunk::COMMENT {
                    continue;
                }
                chunks.push(c);
            }
            // The chunks cover the partition in order, without gaps.
            let mut at = first;
            for c in &chunks {
                if c.sector != at {
                    return Err(format!("partition {name:?}: a chunk at sector {} where {at} was expected", c.sector));
                }
                at += c.sectors;
            }
            if at != first + count {
                return Err(format!("partition {name:?}: its chunks end at sector {at}, not {}", first + count));
            }
            partitions.push(Partition { name, sector: first, sectors: count, crc32, chunks });
        }
        Ok(Udif { file, sectors, partitions, cache: Mutex::new(VecDeque::new()) })
    }

    /// The first partition whose name has `kind` in it (as "Apple_APFS"
    /// is in "Apple_APFS : 4" or "... (Apple_APFS : 4)").
    pub fn partition(&self, kind: &str) -> Option<usize> {
        self.partitions.iter().position(|p| p.name.contains(kind))
    }

    /// A chunk's bytes, decoded.
    fn chunk_bytes(&self, p: usize, i: usize) -> Result<Arc<Vec<u8>>, String> {
        if let Some((_, _, b)) = self.cache.lock().unwrap().iter().find(|(cp, ci, _)| *cp == p && *ci == i) {
            return Ok(Arc::clone(b));
        }
        let c = self.partitions[p].chunks[i];
        let n = usize::try_from(c.sectors * SECTOR).map_err(|_| "a chunk larger than memory")?;
        let mut out = vec![0u8; n];
        match c.kind {
            chunk::ZERO | chunk::IGNORE => {}
            chunk::RAW => {
                if c.length != c.sectors * SECTOR {
                    return Err(format!("a raw chunk of {} bytes for {} sectors", c.length, c.sectors));
                }
                self.file.read_at(c.offset, &mut out)?;
            }
            chunk::LZFSE => {
                let mut src = vec![0u8; c.length as usize];
                self.file.read_at(c.offset, &mut src)?;
                super::lzfse::decode(&src, &mut out).map_err(|e| format!("chunk at sector {}: {e}", c.sector))?;
            }
            chunk::ADC | chunk::ZLIB | chunk::BZIP2 | chunk::LZMA => return Err(format!("not implemented: decoding a UDIF chunk of type {:#x}", c.kind)),
            k => return Err(format!("a UDIF chunk of unknown type {k:#x}")),
        }
        let out = Arc::new(out);
        let mut cache = self.cache.lock().unwrap();
        if cache.len() == CACHED_CHUNKS {
            cache.pop_front();
        }
        cache.push_back((p, i, Arc::clone(&out)));
        Ok(out)
    }

    /// `buf.len()` bytes of partition `p` from byte `off` of it.
    pub fn read_partition(&self, p: usize, off: u64, buf: &mut [u8]) -> Result<(), String> {
        let part = &self.partitions[p];
        let end = off.checked_add(buf.len() as u64).ok_or("a read past the partition")?;
        if end > part.sectors * SECTOR {
            return Err(format!("a read of {}..{end} past partition {:?}'s {} bytes", off, part.name, part.sectors * SECTOR));
        }
        let mut done = 0usize;
        while done < buf.len() {
            let at = part.sector * SECTOR + off + done as u64;
            let i = part.chunks.partition_point(|c| (c.sector + c.sectors) * SECTOR <= at);
            let c = part.chunks[i];
            let bytes = self.chunk_bytes(p, i)?;
            let from = (at - c.sector * SECTOR) as usize;
            let n = (bytes.len() - from).min(buf.len() - done);
            buf[done..done + n].copy_from_slice(&bytes[from..from + n]);
            done += n;
        }
        Ok(())
    }

    /// Checks partition `p`'s data against its CRC-32, decoding all of it
    /// (unallocated chunks are not in the checksum).
    pub fn verify(&self, p: usize) -> Result<(), String> {
        let part = &self.partitions[p];
        let Some(want) = part.crc32 else { return Err(format!("partition {:?} has no CRC-32", part.name)) };
        let mut crc = Crc32::default();
        for (i, c) in part.chunks.iter().enumerate() {
            if c.kind != chunk::IGNORE {
                crc.update(&self.chunk_bytes(p, i)?);
            }
        }
        if crc.finish() != want {
            return Err(format!("partition {:?}: CRC-32 {:#010x}, the image says {want:#010x}", part.name, crc.finish()));
        }
        Ok(())
    }
}

/// A partition of a UDIF image as a medium.
pub struct PartitionMedium {
    pub image: Arc<Udif>,
    pub index: usize,
}

impl Medium for PartitionMedium {
    fn size(&self) -> u64 {
        self.image.partitions[self.index].sectors * SECTOR
    }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<(), String> {
        self.image.read_partition(self.index, off, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_check_value() {
        let mut c = Crc32::default();
        c.update(b"123456789");
        assert_eq!(c.finish(), 0xcbf4_3926);
    }

    /// The IPSW's system image decodes to the CRC-32 it keeps of every
    /// partition, when the image is at hand (GEX_TEST_UDIF).
    #[test]
    fn system_image_partitions_verify() {
        let Ok(path) = std::env::var("GEX_TEST_UDIF") else { return };
        let f = std::fs::File::open(&path).unwrap();
        let size = f.metadata().unwrap().len();
        let img = Udif::open(Arc::new(crate::darwin::apfsread::tests_support::HostFile(f, size))).unwrap();
        for p in 0..img.partitions.len() {
            img.verify(p).unwrap_or_else(|e| panic!("{e}"));
        }
        let apfs = img.partition("Apple_APFS").unwrap();
        let mut b = [0u8; 64];
        img.read_partition(apfs, 0, &mut b).unwrap();
        assert_eq!(&b[32..36], b"NXSB");
    }
}
