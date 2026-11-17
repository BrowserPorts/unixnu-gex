//! decmpfs files as AppleFSCompressionTypeZlib 163.140.2 (the only
//! decompressor of this kernelcache) reads them: its ChunkCompression
//! code, the same for every type it registers (its registrations at
//! 0xfffffff006fbcf40: types 3, 7, 9, 11 and 13 keep their data in the
//! `com.apple.decmpfs` attribute, after the header, with no validate,
//! `adjust_fetch` 0xfffffff006b29f24 and `fetch` 0xfffffff006b29a54;
//! types 4, 8, 10, 12 and 14 in the resource fork, with `validate`
//! 0xfffffff006b29704, `adjust_fetch` 0xfffffff006b29a2c and the same
//! `fetch`).
//!
//! A file's type names a compression scheme and a chunking scheme (its
//! table at 0xfffffff005873ae4, 12 bytes a type, read by
//! 0xfffffff006b29fdc). The file is made of 64 KiB chunks: one, the
//! attribute's bytes, for chunking 0x10000; for chunking 0x30000 as many as
//! the size needs, the resource fork starting with one more 32-bit offset
//! than chunks, chunk i the bytes from offset i to offset i + 1. A chunk
//! whose first byte is the scheme's low byte holds the rest as they are;
//! any other is the scheme's algorithm's (0xfffffff006b2a2ac).
//!
//! A read is what `decmpfs_read_compressed` fetches: from the chunk
//! holding its first byte (`adjust_fetch`: the 64 KiB boundary below it;
//! the whole file for an attribute's data) to the one holding its last,
//! each chunk made whole.

use super::fs::{Decmpfs, Inode, Xattr, XattrData, RESOURCEFORK_NAME};
use super::lzbitmap;
use super::{Error, Le, Result, Volume};

/// `EIO`, `EINVAL`, `ENOATTR`: the errors a fetch returns.
pub const EIO: i32 = 5;
pub const EINVAL: i32 = 22;
pub const ENOATTR: i32 = 93;

/// A chunk's expanded size.
pub const CHUNK: u64 = 0x10000;

/// Chunking schemes.
pub mod chunking {
    /// The data in the attribute, one chunk.
    pub const ATTRIBUTE: u32 = 0x10000;
    /// A resource fork with a resource map (zlib's type 4).
    pub const RESOURCE_MAP: u32 = 0x20000;
    /// A resource fork that starts with its chunks' offsets.
    pub const OFFSETS: u32 = 0x30000;
}

/// Compression schemes, and the algorithms they name (fetch at
/// 0xfffffff006b29af4).
pub mod scheme {
    pub const UNCOMPRESSED: u32 = 0x1cc;
    pub const ZLIB: u32 = 0x2ff;
    pub const LZVN: u32 = 0x306;
    pub const LZFSE: u32 = 0x4ff;
    pub const LZBITMAP: u32 = 0x5ff;
}

/// A type's schemes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kind {
    pub scheme: u32,
    pub chunking: u32,
}

/// The schemes of a type the decompressor registers.
pub fn kind(t: u32) -> Option<Kind> {
    use chunking::*;
    use scheme::*;
    let (scheme, chunking) = match t {
        3 => (ZLIB, ATTRIBUTE),
        4 => (ZLIB, RESOURCE_MAP),
        7 => (LZVN, ATTRIBUTE),
        8 => (LZVN, OFFSETS),
        9 => (UNCOMPRESSED, ATTRIBUTE),
        10 => (UNCOMPRESSED, OFFSETS),
        11 => (LZFSE, ATTRIBUTE),
        12 => (LZFSE, OFFSETS),
        13 => (LZBITMAP, ATTRIBUTE),
        14 => (LZBITMAP, OFFSETS),
        _ => return None,
    };
    Some(Kind { scheme, chunking })
}

/// The most of a chunk this reader takes from the resource fork at once:
/// the kernel allocates a chunk's bytes whole (`IOMallocData`, at
/// 0xfffffff006b2a264), and whether that succeeds past this is its
/// memory's to say.
const CHUNK_READ_MAX: u64 = 16 << 20;

fn fetch_error<T>(errno: i32, why: impl Into<String>) -> Result<T> {
    Err(Error::Decmpfs { errno, why: why.into() })
}

/// The `com.apple.decmpfs` header's length.
pub const HEADER: usize = 16;

/// A chunk's bytes made into at most `cap` (0xfffffff006b2a4d0..): as they
/// are after the scheme's marker byte, or through the scheme's algorithm,
/// which gives no bytes when it fails.
pub fn chunk(scheme: u32, data: &[u8], cap: usize) -> Result<Vec<u8>> {
    if data.first() == Some(&(scheme as u8)) {
        return Ok(data[1..data.len().min(cap + 1)].to_vec());
    }
    match scheme {
        scheme::LZBITMAP => {
            let mut out = vec![0u8; cap];
            match lzbitmap::decode(&mut out, data) {
                Ok(0) => fetch_error(EINVAL, "the LZBITMAP decoder gives no bytes for a chunk"),
                Ok(n) => {
                    out.truncate(n);
                    Ok(out)
                }
                Err(e @ lzbitmap::Error::Rejected(_)) => fetch_error(EINVAL, e.to_string()),
                Err(e @ lzbitmap::Error::Undefined(_)) => Err(Error::Unsupported(e.to_string())),
            }
        }
        // The whole chunk through its `compression_decode_buffer`
        // (0xfffffff006b28f10): algorithm 0x900 for LZVN, 0x801 for LZFSE
        // (0xfffffff006b2a598, 0xfffffff006b2a6a8); no bytes is "decode
        // failed", EINVAL (0xfffffff006b2a874).
        scheme::LZVN | scheme::LZFSE => {
            let mut out = vec![0u8; cap];
            let n = if scheme == scheme::LZVN { crate::darwin::lzfse::lzvn_decode_buffer(data, &mut out) } else { crate::darwin::lzfse::decode_buffer(data, &mut out) };
            if n == 0 {
                return fetch_error(EINVAL, format!("decode failed for compression scheme {scheme:#x}"));
            }
            out.truncate(n);
            Ok(out)
        }
        scheme::ZLIB => Err(Error::Unsupported(format!("decoding a chunk of compression scheme {scheme:#x} (zlib)"))),
        _ => fetch_error(EINVAL, format!("a chunk of compression scheme {scheme:#x} without its marker byte")),
    }
}

impl Volume {
    /// Bytes of the attribute `x` from `off` into all of `buf`, as
    /// ChunkCompression reads the resource fork (0xfffffff006b2a114: a
    /// short read is `EIO`).
    fn attribute_at(&self, x: &Xattr, off: u64, buf: &mut [u8]) -> Result<()> {
        if off.checked_add(buf.len() as u64).is_none_or(|e| e > x.len()) {
            return Err(Error::Unsupported(format!("APFS's getxattr of {} bytes at {off} of the {}-byte {}", buf.len(), x.len(), x.name)));
        }
        match &x.data {
            XattrData::Embedded(v) => buf.copy_from_slice(&v[off as usize..off as usize + buf.len()]),
            XattrData::Stream { id, dstream } => {
                if self.read_stream_unchecked(*id, dstream.size, off, buf)? != buf.len() {
                    return fetch_error(EIO, format!("a short read of {}", x.name));
                }
            }
        }
        Ok(())
    }

    fn resource_fork(&self, ino: &Inode) -> Result<Xattr> {
        match self.xattr(ino.oid, RESOURCEFORK_NAME)? {
            Some(x) => Ok(x),
            None => fetch_error(ENOATTR, format!("the compressed file {:#x} without {RESOURCEFORK_NAME}", ino.oid)),
        }
    }

    /// The chunk count of a file of `size` bytes in `chunking`
    /// (0xfffffff006b2a07c).
    fn chunks(chunking: u32, size: u64) -> u64 {
        if chunking == chunking::ATTRIBUTE { 1 } else { (size + CHUNK - 1) >> 16 }
    }

    /// The resource-fork types' `validate` (0xfffffff006b29704), which
    /// `decmpfs_validate_compressed_file` calls when APFS opens the file:
    /// for chunking 0x30000, a resource fork long enough for the offsets
    /// whose last is its length.
    pub fn decmpfs_validate(&self, ino: &Inode) -> Result<()> {
        let (h, _) = self.decmpfs(ino)?;
        let Some(k) = kind(h.kind) else {
            return Err(Error::Unsupported(format!("validating decmpfs type {} of {:#x}", h.kind, ino.oid)));
        };
        match k.chunking {
            chunking::ATTRIBUTE => Ok(()),
            chunking::OFFSETS => {
                let rf = self.resource_fork(ino)?;
                let n = Self::chunks(k.chunking, h.uncompressed_size);
                let min = (n + 1) * 4;
                if rf.len() < min {
                    return fetch_error(EINVAL, format!("a resource fork of {} bytes, under the {min} its offsets take", rf.len()));
                }
                let mut last = [0u8; 4];
                self.attribute_at(&rf, n * 4, &mut last)?;
                if u64::from(u32::from_le_bytes(last)) != rf.len() {
                    return fetch_error(EINVAL, format!("a resource fork of {} bytes whose last offset is {}", rf.len(), u32::from_le_bytes(last)));
                }
                Ok(())
            }
            c => Err(Error::Unsupported(format!("validating decmpfs chunking {c:#x}"))),
        }
    }

    /// Bytes of compressed file `ino` (its header `h`, the attribute's
    /// bytes `attr`) from `off` into `buf`: how many (fewer only at its
    /// end).
    pub(crate) fn read_decmpfs(&self, ino: &Inode, h: &Decmpfs, attr: &[u8], off: u64, buf: &mut [u8]) -> Result<usize> {
        let size = h.uncompressed_size;
        if off >= size || buf.is_empty() {
            return Ok(0);
        }
        let n = (buf.len() as u64).min(size - off) as usize;
        let Some(k) = kind(h.kind) else {
            return Err(Error::Unsupported(format!("reading the compressed file {:#x}: decmpfs type {}, which the kernel's decompressor does not register", ino.oid, h.kind)));
        };
        let chunks = Self::chunks(k.chunking, size);
        let (first, last) = match k.chunking {
            chunking::ATTRIBUTE => (0, (size - 1) / CHUNK),
            chunking::OFFSETS => (off / CHUNK, (off + n as u64 - 1) / CHUNK),
            c => return Err(Error::Unsupported(format!("reading the compressed file {:#x}: decmpfs chunking {c:#x}", ino.oid))),
        };
        let rf = if k.chunking == chunking::OFFSETS { Some(self.resource_fork(ino)?) } else { None };
        // On a sealed volume, the expanded bytes are checked against the
        // data hashes kept under the resource fork's stream (what
        // decmpfs's VNOP_VERIFY of a fetched UPL checks).
        let hashed = match &rf {
            Some(Xattr { data: XattrData::Stream { id, .. }, .. }) => Some(*id),
            Some(_) if self.hash_type.is_some() => return Err(Error::Unsupported(format!("checking the expanded bytes of {:#x}, a sealed volume's compressed file whose resource fork is in its record", ino.oid))),
            _ => None,
        };
        let mut done = 0usize;
        for c in first..=last {
            if c >= chunks {
                return fetch_error(EINVAL, format!("chunk {c} of a file with {chunks}"));
            }
            let cap = CHUNK.min(size - c * CHUNK) as usize;
            let data = match &rf {
                None => {
                    if attr.len() <= HEADER {
                        return fetch_error(EINVAL, format!("a {}-byte decmpfs attribute with no data", attr.len()));
                    }
                    attr[HEADER..].to_vec()
                }
                Some(rf) => {
                    let mut o = [0u8; 8];
                    self.attribute_at(rf, c * 4, &mut o)?;
                    let (from, to) = (o.u32_at(0)?, o.u32_at(4)?);
                    if to <= from {
                        return fetch_error(EINVAL, format!("chunk {c}'s offsets out of order ({from}, {to})"));
                    }
                    let len = u64::from(to - from);
                    if len > CHUNK_READ_MAX {
                        return Err(Error::Unsupported(format!("the kernel's allocation of a {len}-byte chunk of {:#x}", ino.oid)));
                    }
                    let mut d = vec![0u8; len as usize];
                    self.attribute_at(rf, u64::from(from), &mut d)?;
                    d
                }
            };
            let made = chunk(k.scheme, &data, cap)?;
            if made.len() != cap {
                // decmpfs_read_compressed zero-fills its UPL past what the
                // fetch counts, which a short chunk puts before later ones.
                return Err(Error::Unsupported(format!("chunk {c} of {:#x} expands to {} bytes, not {cap}", ino.oid, made.len())));
            }
            let start = c * CHUNK;
            if let Some(id) = hashed {
                self.check_expanded(id, start, &made, size)?;
            }
            let from = off.max(start);
            let to = (off + n as u64).min(start + cap as u64);
            if from < to {
                buf[(from - off) as usize..(to - off) as usize].copy_from_slice(&made[(from - start) as usize..(to - start) as usize]);
                done += (to - from) as usize;
            }
        }
        debug_assert_eq!(done, n);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types_name_their_schemes() {
        assert_eq!(kind(14), Some(Kind { scheme: scheme::LZBITMAP, chunking: chunking::OFFSETS }));
        assert_eq!(kind(13), Some(Kind { scheme: scheme::LZBITMAP, chunking: chunking::ATTRIBUTE }));
        assert_eq!(kind(9), Some(Kind { scheme: scheme::UNCOMPRESSED, chunking: chunking::ATTRIBUTE }));
        for t in [0, 1, 2, 5, 6, 15, 0x8000_0001] {
            assert_eq!(kind(t), None, "{t}");
        }
    }

    #[test]
    fn chunks_are_marked_or_decoded() {
        // The scheme's low byte marks a chunk held as it is, cut to the
        // room there is.
        assert_eq!(chunk(scheme::LZBITMAP, b"\xffabc", 16).unwrap(), b"abc");
        assert_eq!(chunk(scheme::LZBITMAP, b"\xffabc", 2).unwrap(), b"ab");
        assert_eq!(chunk(scheme::UNCOMPRESSED, b"\xccxy", 16).unwrap(), b"xy");
        assert_eq!(chunk(scheme::UNCOMPRESSED, b"\xcc", 16).unwrap(), b"");
        // Uncompressed data without its marker: the scheme has no algorithm.
        assert!(matches!(chunk(scheme::UNCOMPRESSED, b"xy", 16), Err(Error::Decmpfs { errno: EINVAL, .. })));
        // An LZBITMAP stream, and the decoder's failures.
        let s = b"ZBM\x00\x09\x00\x00\x03\x00\x00abc\x06\x00\x00\x00\x00\x00";
        assert_eq!(chunk(scheme::LZBITMAP, s, 16).unwrap(), b"abc");
        assert!(matches!(chunk(scheme::LZBITMAP, b"ZBM\x00\x06\x00\x00\x00\x00\x00", 16), Err(Error::Decmpfs { errno: EINVAL, .. })));
        assert!(matches!(chunk(scheme::LZBITMAP, b"ZBQ\x00", 16), Err(Error::Decmpfs { errno: EINVAL, .. })));
        // A truncated LZFSE stream: no bytes, "decode failed".
        assert!(matches!(chunk(scheme::LZFSE, b"bvx2", 16), Err(Error::Decmpfs { errno: EINVAL, .. })));
        assert!(matches!(chunk(scheme::ZLIB, b"\x78\x9c", 16), Err(Error::Unsupported(_))));
    }

    /// An LZVN chunk: no block header; literals, a match, end of stream;
    /// cut where the destination ends.
    #[test]
    fn lzvn_chunks() {
        // sml_l "abc" (0xe3), sml_m 4 at no distance yet: refused; then a
        // sml_d of 1 literal, 3 matched at distance 1, and eos.
        let eos = [6u8, 0, 0, 0, 0, 0, 0, 0];
        let mut s = vec![0xe3, b'a', b'b', b'c'];
        // sml_d: L=1 (bits 6-7), M-3=0 (bits 3-5), D=1 (bits 0-2 high, next low).
        s.extend([0x40, 0x01, b'd']);
        s.extend(eos);
        assert_eq!(chunk(scheme::LZVN, &s, 64).unwrap(), b"abcdddd");
        // Cut to the room there is.
        assert_eq!(chunk(scheme::LZVN, &s, 5).unwrap(), b"abcdd");
        // A match before any distance, and a stream with no end.
        let mut bad = vec![0xf4];
        bad.extend(eos);
        assert!(matches!(chunk(scheme::LZVN, &bad, 64), Err(Error::Decmpfs { errno: EINVAL, .. })));
        assert!(matches!(chunk(scheme::LZVN, &s[..s.len() - 1], 64), Err(Error::Decmpfs { errno: EINVAL, .. })));
    }

    /// An LZFSE chunk: an uncompressed block, then the end; a destination
    /// shorter than the stream takes its first bytes.
    #[test]
    fn lzfse_chunks() {
        let mut s = b"bvx-".to_vec();
        s.extend(5u32.to_le_bytes());
        s.extend(b"hello");
        s.extend(b"bvx$");
        assert_eq!(chunk(scheme::LZFSE, &s, 64).unwrap(), b"hello");
        assert_eq!(chunk(scheme::LZFSE, &s, 3).unwrap(), b"hel");
        assert!(matches!(chunk(scheme::LZFSE, &s[..s.len() - 4], 64), Err(Error::Decmpfs { errno: EINVAL, .. })));
    }

    /// Every file of decmpfs types 7, 8, 11 and 12 on the first volume of
    /// each image (UDIF or a raw container) in GEX_TEST_DECMPFS_IMAGES
    /// (colon-separated) reads
    /// back as the host reads the same image mounted at the matching entry
    /// of GEX_TEST_DECMPFS_MNTS.
    #[test]
    fn image_files_of_lzvn_and_lzfse_types() {
        use std::sync::Arc;
        let (Ok(imgs), Ok(mnts)) = (std::env::var("GEX_TEST_DECMPFS_IMAGES"), std::env::var("GEX_TEST_DECMPFS_MNTS")) else { return };
        for (img, mnt) in imgs.split(':').zip(mnts.split(':')) {
            let f = std::fs::File::open(img).unwrap();
            let size = f.metadata().unwrap().len();
            let file = Arc::new(crate::darwin::apfsread::tests_support::HostFile(f, size));
            let mut tail = [0u8; 4];
            crate::darwin::apfsread::Medium::read_at(file.as_ref(), size - 512, &mut tail).unwrap();
            // A UDIF image (its "koly" trailer) or a raw container.
            let medium: Arc<dyn crate::darwin::apfsread::Medium> = if &tail == b"koly" {
                let u = Arc::new(crate::darwin::udif::Udif::open(file).unwrap());
                let p = u.partition("Apple_APFS").unwrap();
                Arc::new(crate::darwin::udif::PartitionMedium { image: u, index: p })
            } else {
                file
            };
            let c = Arc::new(crate::darwin::apfsread::Container::open(medium).unwrap());
            let v = c.volume(0).unwrap().unwrap();
            let mut oids = Vec::new();
            v.fs_tree
                .walk(&v.container, &mut |k, _| {
                    let (oid, t) = super::super::fs::key_header(k)?;
                    if t == 4 && k.len() >= 12 && k[10..k.len() - 1] == *b"com.apple.decmpfs" {
                        oids.push(oid);
                    }
                    Ok(true)
                })
                .unwrap();
            let mut seen = std::collections::BTreeMap::<u32, usize>::new();
            for oid in oids {
                let ino = v.inode(oid).unwrap().unwrap();
                let (h, _) = v.decmpfs(&ino).unwrap();
                *seen.entry(h.kind).or_default() += 1;
                if ![7, 8, 11, 12].contains(&h.kind) {
                    continue;
                }
                let path = v.path_of(oid).unwrap().unwrap();
                let want = std::fs::read(format!("{mnt}{path}")).unwrap();
                let mut got = vec![0u8; want.len()];
                let n = v.read_file(&ino, 0, &mut got).unwrap();
                assert_eq!(n, want.len(), "{img}: {path}");
                assert!(got == want, "{img}: {path} (type {})", h.kind);
            }
            eprintln!("{img}: decmpfs types {seen:?}");
        }
    }
}
