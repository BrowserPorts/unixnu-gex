//! A volume's file-system records ("File-System Objects", "Data Streams",
//! "Extended Fields", "Siblings", "Sealed Volumes" in the Reference):
//! inodes, directory entries, extended attributes, symbolic links and file
//! data, with a sealed volume's data checked against its file-info
//! records' hashes as it is read, and decmpfs files of the kinds the
//! cryptex images hold.

use super::{malformed, Container, Error, Le, Result, Volume};
use std::cmp::Ordering;

/// `j_obj_types`.
pub mod jtype {
    pub const INODE: u8 = 3;
    pub const XATTR: u8 = 4;
    pub const SIBLING_LINK: u8 = 5;
    pub const DSTREAM_ID: u8 = 6;
    pub const CRYPTO_STATE: u8 = 7;
    pub const FILE_EXTENT: u8 = 8;
    pub const DIR_REC: u8 = 9;
    pub const DIR_STATS: u8 = 10;
    pub const SIBLING_MAP: u8 = 12;
    pub const FILE_INFO: u8 = 13;
}

/// `OBJ_ID_MASK`, `OBJ_TYPE_SHIFT`.
pub const OBJ_ID_MASK: u64 = 0x0fff_ffff_ffff_ffff;
pub const OBJ_TYPE_SHIFT: u32 = 60;

/// Inode numbers: `ROOT_DIR_PARENT`, `ROOT_DIR_INO_NUM`, `PRIV_DIR_INO_NUM`.
pub const ROOT_DIR_PARENT: u64 = 1;
pub const ROOT_DIR_INO_NUM: u64 = 2;
pub const PRIV_DIR_INO_NUM: u64 = 3;

/// `j_inode_flags` this reader looks at.
pub mod inode_flags {
    pub const HAS_RSRC_FORK: u64 = 0x0000_4000;
    pub const HAS_UNCOMPRESSED_SIZE: u64 = 0x0004_0000;
}

/// `j_xattr_flags`.
pub mod xattr_flags {
    pub const DATA_STREAM: u16 = 0x1;
    pub const DATA_EMBEDDED: u16 = 0x2;
    pub const FILE_SYSTEM_OWNED: u16 = 0x4;
}

/// Extended-field types (`INO_EXT_TYPE_*`, `DREC_EXT_TYPE_*`).
pub mod xf {
    pub const DREC_SIBLING_ID: u8 = 1;
    pub const SNAP_XID: u8 = 1;
    pub const DOCUMENT_ID: u8 = 3;
    pub const NAME: u8 = 4;
    pub const PREV_FSIZE: u8 = 5;
    pub const DSTREAM: u8 = 8;
    pub const SPARSE_BYTES: u8 = 13;
    pub const RDEV: u8 = 14;
}

/// `DREC_TYPE_MASK`.
pub const DREC_TYPE_MASK: u16 = 0x000f;

/// `S_IFMT` and the types an inode's mode holds.
pub mod mode {
    pub const S_IFMT: u16 = 0o170000;
    pub const S_IFIFO: u16 = 0o010000;
    pub const S_IFCHR: u16 = 0o020000;
    pub const S_IFDIR: u16 = 0o040000;
    pub const S_IFBLK: u16 = 0o060000;
    pub const S_IFREG: u16 = 0o100000;
    pub const S_IFLNK: u16 = 0o120000;
    pub const S_IFSOCK: u16 = 0o140000;
}

/// `UF_COMPRESSED`.
pub const UF_COMPRESSED: u32 = 0x20;

/// `SYMLINK_EA_NAME`, `DECMPFS_XATTR_NAME`, `XATTR_RESOURCEFORK_NAME`.
pub const SYMLINK_EA_NAME: &str = "com.apple.fs.symlink";
pub const DECMPFS_XATTR_NAME: &str = "com.apple.decmpfs";
pub const RESOURCEFORK_NAME: &str = "com.apple.ResourceFork";

/// A key's object identifier and record type (`j_key_t`).
pub fn key_header(k: &[u8]) -> Result<(u64, u8)> {
    let v = k.u64_at(0)?;
    Ok((v & OBJ_ID_MASK, (v >> OBJ_TYPE_SHIFT) as u8))
}

/// A data stream (`j_dstream_t`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Dstream {
    pub size: u64,
    pub alloced_size: u64,
    pub default_crypto_id: u64,
}

impl Dstream {
    fn parse(b: &[u8]) -> Result<Dstream> {
        Ok(Dstream { size: b.u64_at(0)?, alloced_size: b.u64_at(8)?, default_crypto_id: b.u64_at(16)? })
    }
}

/// An extended field (`x_field_t`) and its value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XField {
    pub kind: u8,
    pub flags: u8,
    pub value: Vec<u8>,
}

/// The extended fields of a blob (`xf_blob_t`): the fields' headers, then
/// their values, each at an 8-byte boundary. `xf_used_data` counts the
/// values alone (the Reference says the headers too; in every inode and
/// directory entry of the 21H461 cryptexes it is the values' bytes, the
/// record ending right after them).
pub fn xfields(b: &[u8]) -> Result<Vec<XField>> {
    if b.is_empty() {
        return Ok(Vec::new());
    }
    let n = b.u16_at(0)? as usize;
    let used = b.u16_at(2)? as usize;
    let heads = b.slice_at(4, 4 * n)?;
    let values = b.slice_at(4 + 4 * n, used)?;
    let mut at = 0;
    let mut out = Vec::with_capacity(n);
    for h in heads.chunks_exact(4) {
        let size = u16::from_le_bytes([h[2], h[3]]) as usize;
        out.push(XField { kind: h[0], flags: h[1], value: values.slice_at(at, size)?.to_vec() });
        at += (size + 7) & !7;
    }
    Ok(out)
}

/// An inode (`j_inode_val_t`) and its extended fields' values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inode {
    pub oid: u64,
    pub parent_id: u64,
    pub private_id: u64,
    pub create_time: u64,
    pub mod_time: u64,
    pub change_time: u64,
    pub access_time: u64,
    pub internal_flags: u64,
    /// `nchildren` of a directory, `nlink` of anything else.
    pub nchildren_or_nlink: i32,
    pub default_protection_class: u32,
    pub write_generation_counter: u32,
    pub bsd_flags: u32,
    pub owner: u32,
    pub group: u32,
    pub mode: u16,
    pub uncompressed_size: u64,
    pub dstream: Option<Dstream>,
    pub name: Option<String>,
    pub rdev: Option<u32>,
    pub document_id: Option<u32>,
}

impl Inode {
    fn parse(oid: u64, v: &[u8]) -> Result<Inode> {
        let mut ino = Inode {
            oid,
            parent_id: v.u64_at(0)?,
            private_id: v.u64_at(8)?,
            create_time: v.u64_at(16)?,
            mod_time: v.u64_at(24)?,
            change_time: v.u64_at(32)?,
            access_time: v.u64_at(40)?,
            internal_flags: v.u64_at(48)?,
            nchildren_or_nlink: v.u32_at(56)? as i32,
            default_protection_class: v.u32_at(60)?,
            write_generation_counter: v.u32_at(64)?,
            bsd_flags: v.u32_at(68)?,
            owner: v.u32_at(72)?,
            group: v.u32_at(76)?,
            mode: v.u16_at(80)?,
            uncompressed_size: v.u64_at(84)?,
            dstream: None,
            name: None,
            rdev: None,
            document_id: None,
        };
        for f in xfields(v.slice_at(92, v.len().saturating_sub(92))?)? {
            match f.kind {
                xf::DSTREAM => ino.dstream = Some(Dstream::parse(&f.value)?),
                xf::NAME => ino.name = Some(cstr(&f.value)?),
                xf::RDEV => ino.rdev = Some(f.value.u32_at(0)?),
                xf::DOCUMENT_ID => ino.document_id = Some(f.value.u32_at(0)?),
                _ => {}
            }
        }
        Ok(ino)
    }

    pub fn kind(&self) -> u16 {
        self.mode & mode::S_IFMT
    }
    pub fn is_dir(&self) -> bool {
        self.kind() == mode::S_IFDIR
    }
    pub fn compressed(&self) -> bool {
        self.bsd_flags & UF_COMPRESSED != 0
    }
}

/// A NUL-terminated UTF-8 string of a record.
fn cstr(b: &[u8]) -> Result<String> {
    let n = b.iter().position(|&c| c == 0).ok_or_else(|| Error::Malformed("a name without its NUL".into()))?;
    String::from_utf8(b[..n].to_vec()).map_err(|_| Error::Malformed("a name that is not UTF-8".into()))
}

/// A directory entry (`j_drec_key_t` or `j_drec_hashed_key_t`, and
/// `j_drec_val_t`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    /// The 22-bit hash a hashed key keeps.
    pub hash: Option<u32>,
    pub file_id: u64,
    pub date_added: u64,
    /// `flags & DREC_TYPE_MASK`: the entry's `DT_*` type.
    pub dtype: u16,
    pub sibling_id: Option<u64>,
}

/// `J_DREC_LEN_MASK`, `J_DREC_HASH_MASK`, `J_DREC_HASH_SHIFT`.
const J_DREC_LEN_MASK: u32 = 0x0000_03ff;
const J_DREC_HASH_SHIFT: u32 = 10;

/// CRC-32C (the Castagnoli polynomial, reflected 0x82F63B78), with the
/// usual initial value and final complement.
pub fn crc32c(data: &[u8]) -> u32 {
    const fn table() -> [u32; 256] {
        let mut t = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut c = i as u32;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 { (c >> 1) ^ 0x82f6_3b78 } else { c >> 1 };
                k += 1;
            }
            t[i] = c;
            i += 1;
        }
        t
    }
    static T: [u32; 256] = table();
    let mut crc = !0u32;
    for &b in data {
        crc = T[((crc ^ u32::from(b)) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

/// A name in canonical decomposition (NFD).
pub fn nfd(name: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    name.nfd().collect()
}

/// `j_drec_hashed_key_t`'s name hash: CRC-32C of the name decomposed (NFD)
/// as UTF-32, complemented, its low 22 bits. (The UTF-32 string's
/// terminating NUL is not hashed: so every hashed key of the 21H461
/// cryptexes is.)
pub fn name_hash(name: &str) -> u32 {
    let mut utf32 = Vec::with_capacity(name.len() * 4);
    for ch in nfd(name).chars() {
        utf32.extend_from_slice(&(ch as u32).to_le_bytes());
    }
    !crc32c(&utf32) & 0x003f_ffff
}

/// An extended attribute (`j_xattr_key_t`, `j_xattr_val_t`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Xattr {
    pub name: String,
    pub flags: u16,
    pub data: XattrData,
}

/// Where an attribute's value is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum XattrData {
    Embedded(Vec<u8>),
    /// In a data stream (`j_xattr_dstream_t`).
    Stream { id: u64, dstream: Dstream },
}

impl Xattr {
    pub fn len(&self) -> u64 {
        match &self.data {
            XattrData::Embedded(v) => v.len() as u64,
            XattrData::Stream { dstream, .. } => dstream.size,
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A decmpfs file's header (`decmpfs_disk_header`): its type and size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decmpfs {
    pub kind: u32,
    pub uncompressed_size: u64,
}

/// `DECMPFS_MAGIC` ('cmpf'), `sizeof(decmpfs_disk_header)`.
pub const DECMPFS_MAGIC: u32 = 0x636d_7066;
const DECMPFS_HEADER: usize = 16;

/// The decmpfs types AppleFSCompressionTypeZlib (163.140.2, the only
/// decompressor of this kernelcache) registers (its table at
/// 0xfffffff006fbcf40), with the compression scheme each names (its type
/// table at 0xfffffff005873ae4, the scheme's algorithm at
/// 0xfffffff006b2a580): what reading a file of the type needs.
pub fn decmpfs_kind(kind: u32) -> Option<&'static str> {
    Some(match kind {
        3 => "zlib in the attribute (scheme 0x2ff, COMPRESSION_ZLIB)",
        4 => "zlib in the resource fork (scheme 0x2ff, COMPRESSION_ZLIB)",
        7 => "LZVN in the attribute (scheme 0x306, algorithm 0x900)",
        8 => "LZVN in the resource fork (scheme 0x306, algorithm 0x900)",
        9 => "uncompressed in the attribute (scheme 0x1cc)",
        10 => "uncompressed in the resource fork (scheme 0x1cc)",
        11 => "LZFSE in the attribute (scheme 0x4ff, COMPRESSION_LZFSE)",
        12 => "LZFSE in the resource fork (scheme 0x4ff, COMPRESSION_LZFSE)",
        13 => "LZBITMAP in the attribute (scheme 0x5ff, COMPRESSION_LZBITMAP, which has no published specification)",
        14 => "LZBITMAP in the resource fork (scheme 0x5ff, COMPRESSION_LZBITMAP, which has no published specification)",
        _ => return None,
    })
}

/// The marker a scheme-0x1cc attribute's data starts with (its scheme's
/// low byte): what follows it is the file, uncompressed.
const UNCOMPRESSED_MARKER: u8 = 0xcc;

/// A file-info record's data hash (`j_file_data_hash_val_t`): the stream
/// offset it starts at, its length in blocks, the hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataHash {
    pub offset: u64,
    pub blocks: u16,
    pub hash: Vec<u8>,
}

/// `J_FILE_INFO_LBA_MASK`, `J_FILE_INFO_TYPE_SHIFT`,
/// `APFS_FILE_INFO_DATA_HASH`.
const J_FILE_INFO_LBA_MASK: u64 = 0x00ff_ffff_ffff_ffff;
const J_FILE_INFO_TYPE_SHIFT: u32 = 56;
const APFS_FILE_INFO_DATA_HASH: u64 = 1;

/// `J_FILE_EXTENT_LEN_MASK`.
const J_FILE_EXTENT_LEN_MASK: u64 = 0x00ff_ffff_ffff_ffff;

/// An extent of a data stream: its logical start, its length and its
/// first physical block (0, a hole); or none at an offset, and where the
/// next starts.
enum Extent {
    At { start: u64, len: u64, block: u64 },
    Hole { next: Option<u64> },
}

/// The most an attribute's value may be when it is read whole.
const XATTR_READ_MAX: u64 = 64 << 20;

impl Volume {
    fn c(&self) -> &Container {
        &self.container
    }

    /// Whether directory entries have hashed keys: on a case- or
    /// normalization-insensitive volume.
    pub fn hashed_names(&self) -> bool {
        self.sb.incompat & (super::incompat::CASE_INSENSITIVE | super::incompat::NORMALIZATION_INSENSITIVE) != 0
    }

    /// The records of object `oid` of type `t`, in order, until `visit`
    /// says to stop.
    fn records(&self, oid: u64, t: u8, visit: &mut dyn FnMut(&[u8], &[u8]) -> Result<bool>) -> Result<()> {
        let target = (oid, t);
        self.fs_tree.scan(
            self.c(),
            &mut |k| {
                let h = key_header(k)?;
                Ok(if h < target { Ordering::Less } else { Ordering::Greater })
            },
            &mut |k, v| {
                if key_header(k)? != target {
                    return Ok(false);
                }
                let v = v.ok_or_else(|| Error::Malformed("a file-system record without a value".into()))?;
                visit(k, v)
            },
        )
    }

    /// The inode `oid`, if there is one.
    pub fn inode(&self, oid: u64) -> Result<Option<Inode>> {
        let mut found = None;
        self.records(oid, jtype::INODE, &mut |k, v| {
            if k.len() != 8 {
                return malformed(format!("an inode key of {} bytes", k.len()));
            }
            found = Some(Inode::parse(oid, v)?);
            Ok(false)
        })?;
        Ok(found)
    }

    fn dir_entry(&self, k: &[u8], v: &[u8]) -> Result<DirEntry> {
        let (name, hash) = if self.hashed_names() {
            let nlh = k.u32_at(8)?;
            let len = (nlh & J_DREC_LEN_MASK) as usize;
            (cstr(k.slice_at(12, len)?)?, Some(nlh >> J_DREC_HASH_SHIFT))
        } else {
            let len = k.u16_at(8)? as usize;
            (cstr(k.slice_at(10, len)?)?, None)
        };
        let mut e = DirEntry { name, hash, file_id: v.u64_at(0)?, date_added: v.u64_at(8)?, dtype: v.u16_at(16)? & DREC_TYPE_MASK, sibling_id: None };
        for f in xfields(v.slice_at(18, v.len() - 18)?)? {
            if f.kind == xf::DREC_SIBLING_ID {
                e.sibling_id = Some(f.value.u64_at(0)?);
            }
        }
        Ok(e)
    }

    /// The entries of directory `dir`, in the tree's order (a directory
    /// listing's).
    pub fn dir_entries(&self, dir: u64) -> Result<Vec<DirEntry>> {
        let mut out = Vec::new();
        self.records(dir, jtype::DIR_REC, &mut |k, v| {
            out.push(self.dir_entry(k, v)?);
            Ok(true)
        })?;
        Ok(out)
    }

    /// The entry named `name` in directory `dir`: on a
    /// normalization-insensitive volume, the one whose name has the same
    /// canonical decomposition (its hash first).
    pub fn lookup(&self, dir: u64, name: &str) -> Result<Option<DirEntry>> {
        let insensitive = self.sb.incompat & super::incompat::NORMALIZATION_INSENSITIVE != 0;
        let (want_hash, want) = if insensitive { (Some(name_hash(name)), nfd(name)) } else { (None, name.to_string()) };
        let mut found = None;
        self.records(dir, jtype::DIR_REC, &mut |k, v| {
            let e = self.dir_entry(k, v)?;
            if want_hash.is_some() && e.hash.is_some() && e.hash != want_hash {
                return Ok(true);
            }
            let same = if insensitive { nfd(&e.name) == want } else { e.name == want };
            if same {
                found = Some(e);
                return Ok(false);
            }
            Ok(true)
        })?;
        Ok(found)
    }

    /// The extended attributes of object `oid`, in the tree's order.
    pub fn xattrs(&self, oid: u64) -> Result<Vec<Xattr>> {
        let mut out = Vec::new();
        self.records(oid, jtype::XATTR, &mut |k, v| {
            let len = k.u16_at(8)? as usize;
            let name = cstr(k.slice_at(10, len)?)?;
            let flags = v.u16_at(0)?;
            let xlen = v.u16_at(2)? as usize;
            let x = v.slice_at(4, xlen)?;
            let data = if flags & xattr_flags::DATA_STREAM != 0 {
                XattrData::Stream { id: x.u64_at(0)?, dstream: Dstream::parse(x.slice_at(8, 40)?)? }
            } else if flags & xattr_flags::DATA_EMBEDDED != 0 {
                XattrData::Embedded(x.to_vec())
            } else {
                return malformed(format!("the attribute {name} with flags {flags:#x}"));
            };
            out.push(Xattr { name, flags, data });
            Ok(true)
        })?;
        Ok(out)
    }

    /// Object `oid`'s attribute `name`.
    pub fn xattr(&self, oid: u64, name: &str) -> Result<Option<Xattr>> {
        Ok(self.xattrs(oid)?.into_iter().find(|x| x.name == name))
    }

    /// An attribute's value, whole.
    pub fn xattr_value(&self, x: &Xattr) -> Result<Vec<u8>> {
        match &x.data {
            XattrData::Embedded(v) => Ok(v.clone()),
            XattrData::Stream { id, dstream } => {
                if dstream.size > XATTR_READ_MAX {
                    return Err(Error::Unsupported(format!("reading the {}-byte attribute {} whole", dstream.size, x.name)));
                }
                let mut b = vec![0u8; dstream.size as usize];
                let n = self.read_stream(*id, dstream.size, 0, &mut b)?;
                b.truncate(n);
                Ok(b)
            }
        }
    }

    /// The target of symbolic link `ino` (its `SYMLINK_EA_NAME`).
    pub fn symlink_target(&self, ino: &Inode) -> Result<String> {
        let x = self.xattr(ino.oid, SYMLINK_EA_NAME)?.ok_or_else(|| Error::Malformed(format!("the symbolic link {:#x} without {SYMLINK_EA_NAME}", ino.oid)))?;
        cstr(&self.xattr_value(&x)?)
    }

    /// The decmpfs header of compressed file `ino`.
    pub fn decmpfs(&self, ino: &Inode) -> Result<(Decmpfs, Vec<u8>)> {
        let x = self.xattr(ino.oid, DECMPFS_XATTR_NAME)?.ok_or_else(|| Error::Malformed(format!("the compressed file {:#x} without {DECMPFS_XATTR_NAME}", ino.oid)))?;
        let b = self.xattr_value(&x)?;
        if b.len() < DECMPFS_HEADER || b.u32_at(0)? != DECMPFS_MAGIC {
            return malformed(format!("the decmpfs header of {:#x}", ino.oid));
        }
        Ok((Decmpfs { kind: b.u32_at(4)?, uncompressed_size: b.u64_at(8)? }, b))
    }

    /// What `stat` says a file's size is (`apfs_vnop_getattr`'s
    /// `va_data_size`, 0xfffffff00669e65c): a directory's entries at 32
    /// bytes each and 64 more; a symbolic link's target's length; a
    /// compressed file's decmpfs size; else its data stream's.
    pub fn file_size(&self, ino: &Inode) -> Result<u64> {
        match ino.kind() {
            mode::S_IFDIR => Ok((i64::from(ino.nchildren_or_nlink) as u64).wrapping_shl(5).wrapping_add(0x40)),
            mode::S_IFLNK => Ok(self.symlink_target(ino)?.len() as u64),
            mode::S_IFREG if ino.compressed() => Ok(self.decmpfs(ino)?.0.uncompressed_size),
            _ => Ok(ino.dstream.map_or(0, |d| d.size)),
        }
    }

    /// Bytes of regular file `ino` from `off` into `buf`; how many (fewer
    /// only at its end).
    pub fn read_file(&self, ino: &Inode, off: u64, buf: &mut [u8]) -> Result<usize> {
        if ino.compressed() {
            let (h, b) = self.decmpfs(ino)?;
            return match h.kind {
                9 => {
                    let data = &b[DECMPFS_HEADER..];
                    if data.first() != Some(&UNCOMPRESSED_MARKER) || (data.len() - 1) as u64 != h.uncompressed_size {
                        return Err(Error::Unsupported(format!("the decmpfs type 9 data of {:#x}: {} bytes where {} are the file's", ino.oid, data.len(), h.uncompressed_size)));
                    }
                    let file = &data[1..];
                    let at = off.min(file.len() as u64) as usize;
                    let n = buf.len().min(file.len() - at);
                    buf[..n].copy_from_slice(&file[at..at + n]);
                    Ok(n)
                }
                k => Err(Error::Unsupported(format!(
                    "reading the compressed file {:#x}: decmpfs type {k} ({})",
                    ino.oid,
                    decmpfs_kind(k).unwrap_or("a type the kernel's decompressor does not register")
                ))),
            };
        }
        let size = ino.dstream.map_or(0, |d| d.size);
        self.read_stream(ino.private_id, size, off, buf)
    }

    /// Bytes of data stream `id` of `size` bytes from `off`: its extents
    /// (a sealed volume's file extent tree's, else the file-system tree's
    /// file extent records), a hole read as zeros; a sealed volume's data
    /// checked against the stream's data hashes first.
    pub fn read_stream(&self, id: u64, size: u64, off: u64, buf: &mut [u8]) -> Result<usize> {
        if off >= size {
            return Ok(0);
        }
        let n = buf.len().min((size - off).min(usize::MAX as u64) as usize);
        let buf = &mut buf[..n];
        if self.fext_tree.is_none() {
            self.read_extents(id, off, buf)?;
            return Ok(n);
        }
        let bs = u64::from(self.c().block_size());
        let end = off + n as u64;
        let mut at = off;
        while at < end {
            let h = self.data_hash(id, at)?.ok_or_else(|| Error::Integrity(format!("no data hash covers byte {at} of stream {id:#x} of a sealed volume")))?;
            let seg_end = h.offset + u64::from(h.blocks) * bs;
            let to = end.min(seg_end);
            let piece = &mut buf[(at - off) as usize..(to - off) as usize];
            let seen = self.verified.lock().unwrap_or_else(|e| e.into_inner()).contains(&(id, h.offset));
            if seen {
                self.read_extents(id, at, piece)?;
            } else {
                let mut seg = vec![0u8; (seg_end - h.offset) as usize];
                self.read_extents(id, h.offset, &mut seg)?;
                let t = self.hash_type.ok_or_else(|| Error::Malformed("a sealed volume without a hash type".into()))?;
                if h.hash.len() != t.size() || t.digest(&seg) != h.hash {
                    return Err(Error::Integrity(format!("bytes {}..{seg_end} of stream {id:#x} do not have their data hash", h.offset)));
                }
                self.verified.lock().unwrap_or_else(|e| e.into_inner()).insert((id, h.offset));
                let from = (at - h.offset) as usize;
                piece.copy_from_slice(&seg[from..from + piece.len()]);
            }
            at = to;
        }
        Ok(n)
    }

    /// The data hash of stream `id` covering byte `at`: the file-info
    /// record of the greatest offset not past it, if it reaches it.
    pub fn data_hash(&self, id: u64, at: u64) -> Result<Option<DataHash>> {
        let target = (id, jtype::FILE_INFO, (APFS_FILE_INFO_DATA_HASH << J_FILE_INFO_TYPE_SHIFT) | (at & J_FILE_INFO_LBA_MASK));
        let found = self.fs_tree.find_le(self.c(), &mut |k| {
            let (o, t) = key_header(k)?;
            let rest = if (o, t) == (id, jtype::FILE_INFO) { k.u64_at(8)? } else { 0 };
            Ok((o, t, rest).cmp(&target))
        })?;
        let Some((k, v)) = found else { return Ok(None) };
        if key_header(&k)? != (id, jtype::FILE_INFO) {
            return Ok(None);
        }
        let info = k.u64_at(8)?;
        if info >> J_FILE_INFO_TYPE_SHIFT != APFS_FILE_INFO_DATA_HASH {
            return Err(Error::Unsupported(format!("a file-info record of type {}", info >> J_FILE_INFO_TYPE_SHIFT)));
        }
        let v = v.ok_or_else(|| Error::Malformed("a file-info record without a value".into()))?;
        let blocks = v.u16_at(0)?;
        let hs = v.slice_at(2, 1)?[0] as usize;
        let h = DataHash { offset: info & J_FILE_INFO_LBA_MASK, blocks, hash: v.slice_at(3, hs)?.to_vec() };
        let bs = u64::from(self.c().block_size());
        Ok((at < h.offset + u64::from(h.blocks) * bs).then_some(h))
    }

    /// The extent of stream `id` holding byte `at`, or where the next one
    /// starts when none does.
    fn extent_at(&self, id: u64, at: u64) -> Result<Extent> {
        match &self.fext_tree {
            Some(t) => {
                let target = (id, at);
                let found = t.find_le(self.c(), &mut |k| Ok((k.u64_at(0)?, k.u64_at(8)?).cmp(&target)))?;
                if let Some((k, Some(v))) = &found {
                    let (pid, la) = (k.u64_at(0)?, k.u64_at(8)?);
                    let len = v.u64_at(0)? & J_FILE_EXTENT_LEN_MASK;
                    if pid == id && at < la + len {
                        return Ok(Extent::At { start: la, len, block: v.u64_at(8)? });
                    }
                }
                let mut next = None;
                t.scan(self.c(), &mut |k| Ok((k.u64_at(0)?, k.u64_at(8)?).cmp(&target)), &mut |k, _| {
                    if k.u64_at(0)? == id && k.u64_at(8)? > at {
                        next = Some(k.u64_at(8)?);
                    }
                    Ok(false)
                })?;
                Ok(Extent::Hole { next })
            }
            None => {
                let target = (id, jtype::FILE_EXTENT, at);
                let key = |k: &[u8]| -> Result<(u64, u8, u64)> {
                    let (o, t) = key_header(k)?;
                    Ok((o, t, if (o, t) == (id, jtype::FILE_EXTENT) { k.u64_at(8)? } else { 0 }))
                };
                let found = self.fs_tree.find_le(self.c(), &mut |k| Ok(key(k)?.cmp(&target)))?;
                if let Some((k, Some(v))) = &found {
                    let (o, t, la) = key(k)?;
                    let len = v.u64_at(0)? & J_FILE_EXTENT_LEN_MASK;
                    if (o, t) == (id, jtype::FILE_EXTENT) && at < la + len {
                        return Ok(Extent::At { start: la, len, block: v.u64_at(8)? });
                    }
                }
                let mut next = None;
                self.fs_tree.scan(self.c(), &mut |k| Ok(key(k)?.cmp(&target)), &mut |k, _| {
                    let (o, t, la) = key(k)?;
                    if (o, t) == (id, jtype::FILE_EXTENT) && la > at {
                        next = Some(la);
                    }
                    Ok(false)
                })?;
                Ok(Extent::Hole { next })
            }
        }
    }

    /// `buf` from byte `off` of stream `id` through its extents, holes as
    /// zeros.
    fn read_extents(&self, id: u64, off: u64, buf: &mut [u8]) -> Result<()> {
        let end = off + buf.len() as u64;
        let mut at = off;
        while at < end {
            let piece_end;
            match self.extent_at(id, at)? {
                Extent::At { start: la, len, block: pb } => {
                    piece_end = end.min(la + len);
                    let piece = &mut buf[(at - off) as usize..(piece_end - off) as usize];
                    if pb == 0 {
                        piece.fill(0);
                    } else {
                        self.c().read_extent(pb, at - la, piece)?;
                    }
                }
                Extent::Hole { next } => {
                    piece_end = next.map_or(end, |n| n.min(end));
                    buf[(at - off) as usize..(piece_end - off) as usize].fill(0);
                }
            }
            if piece_end <= at {
                return malformed(format!("an extent of stream {id:#x} that does not advance at {at}"));
            }
            at = piece_end;
        }
        Ok(())
    }

    /// The path of inode `oid` from the volume's root, by its parents and
    /// its name (a hard link's primary name).
    pub fn path_of(&self, oid: u64) -> Result<Option<String>> {
        let mut parts = Vec::new();
        let mut cur = oid;
        for _ in 0..4096 {
            if cur == ROOT_DIR_INO_NUM {
                parts.reverse();
                return Ok(Some(format!("/{}", parts.join("/"))));
            }
            let Some(ino) = self.inode(cur)? else { return Ok(None) };
            let Some(name) = ino.name.clone() else { return Ok(None) };
            parts.push(name);
            cur = ino.parent_id;
        }
        malformed(format!("the parents of {oid:#x} do not reach the root"))
    }

    /// The inode at `path` (absolute, from the volume's root), links not
    /// followed.
    pub fn resolve(&self, path: &str) -> Result<Option<Inode>> {
        let mut cur = ROOT_DIR_INO_NUM;
        for part in path.split('/').filter(|p| !p.is_empty()) {
            let Some(e) = self.lookup(cur, part)? else { return Ok(None) };
            cur = e.file_id;
        }
        self.inode(cur)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_is_castagnolis() {
        // RFC 3720's check value of "123456789".
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
        assert_eq!(crc32c(b""), 0);
    }

    /// Names hash to the keys' 22 bits, decomposed first: a precomposed
    /// and a decomposed é hash alike.
    #[test]
    fn names_hash_decomposed() {
        assert_eq!(name_hash("caf\u{e9}"), name_hash("cafe\u{301}"));
        assert_ne!(name_hash("cafe"), name_hash("caf\u{e9}"));
        assert!(name_hash("private-dir") < 1 << 22);
        // The first key of the 21H461 SystemOS cryptex's tree, the root's
        // entry "private-dir": name_len_and_hash 0xaca68c0c (12 bytes).
        assert_eq!(name_hash("private-dir"), 0xaca68c0c >> 10);
    }

    #[test]
    fn extended_fields_are_aligned() {
        // Two fields: a name of 5 bytes (padded to 8), then a dstream.
        let mut b = Vec::new();
        b.extend_from_slice(&2u16.to_le_bytes());
        b.extend_from_slice(&(8 + 40u16).to_le_bytes());
        b.extend_from_slice(&[xf::NAME, 0, 5, 0]);
        b.extend_from_slice(&[xf::DSTREAM, 0, 40, 0]);
        b.extend_from_slice(b"name\0\0\0\0");
        let mut d = [0u8; 40];
        d[..8].copy_from_slice(&1234u64.to_le_bytes());
        b.extend_from_slice(&d);
        let f = xfields(&b).unwrap();
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].value, b"name\0");
        assert_eq!(Dstream::parse(&f[1].value).unwrap().size, 1234);
        assert!(xfields(&b[..20]).is_err());
        assert!(xfields(&[]).unwrap().is_empty());
    }

    fn os_volume() -> Volume {
        let c = super::super::tests::restore_image("044-76034-038.dmg");
        c.volume(0).unwrap().unwrap()
    }

    /// The SystemOS cryptex's root: its one tree walked whole (every
    /// node's hash checked), the shared cache's header read, and the
    /// compressed files: uncompressed ones read, the LZBITMAP ones
    /// refused.
    #[test]
    #[ignore = "needs GEX_DARWIN_RESTORE's 044-76034-038.dmg (21H461)"]
    fn the_os_cryptex_is_read() {
        let v = os_volume();
        let mut n = 0u64;
        v.fs_tree.walk(&v.container, &mut |_, _| {
            n += 1;
            Ok(true)
        })
        .unwrap();
        assert_eq!(n, v.fs_tree.info.key_count);
        let root = v.inode(ROOT_DIR_INO_NUM).unwrap().unwrap();
        assert!(root.is_dir());
        let names: Vec<String> = v.dir_entries(ROOT_DIR_INO_NUM).unwrap().into_iter().map(|e| e.name).collect();
        assert!(names.contains(&"System".to_string()), "{names:?}");
        for e in v.dir_entries(ROOT_DIR_INO_NUM).unwrap() {
            assert_eq!(e.hash, Some(name_hash(&e.name)), "{}", e.name);
        }
        let cache = v.resolve("/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64").unwrap().unwrap();
        assert_eq!(cache.kind(), mode::S_IFREG);
        assert!(!cache.compressed());
        assert_eq!((cache.owner, cache.group, cache.mode & 0o7777), (0, 80, 0o755));
        let mut head = [0u8; 16];
        assert_eq!(v.read_file(&cache, 0, &mut head).unwrap(), 16);
        assert_eq!(&head, b"dyld_v1   arm64\0");
        // A read across data hash segments, and past the end.
        let size = v.file_size(&cache).unwrap();
        let mut mid = vec![0u8; 40_000];
        assert_eq!(v.read_file(&cache, 10_000, &mut mid).unwrap(), 40_000);
        let mut tail = [0u8; 64];
        assert_eq!(v.read_file(&cache, size - 10, &mut tail).unwrap(), 10);
        assert_eq!(v.read_file(&cache, size, &mut tail).unwrap(), 0);
        // The two symbolic links.
        let mut links = 0;
        v.fs_tree.walk(&v.container, &mut |k, val| {
            if key_header(k)?.1 == jtype::INODE {
                let ino = Inode::parse(key_header(k)?.0, val.unwrap())?;
                if ino.kind() == mode::S_IFLNK {
                    assert!(!v.symlink_target(&ino)?.is_empty());
                    links += 1;
                }
                if ino.compressed() {
                    let (h, _) = v.decmpfs(&ino)?;
                    assert_eq!(h.uncompressed_size, ino.uncompressed_size);
                    let mut b = vec![0u8; 256];
                    match h.kind {
                        9 => assert_eq!(v.read_file(&ino, 0, &mut b)?, (h.uncompressed_size as usize).min(256)),
                        14 => assert!(matches!(v.read_file(&ino, 0, &mut b), Err(Error::Unsupported(_)))),
                        k => panic!("decmpfs type {k}"),
                    }
                }
            }
            Ok(true)
        })
        .unwrap();
        assert_eq!(links, 2);
        assert_eq!(v.path_of(cache.oid).unwrap().as_deref(), Some("/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64"));
        assert!(v.resolve("/System/Library/Caches/com.apple.dyld/no-such-file").unwrap().is_none());
    }

    /// The AppOS cryptex opens and its root is read too.
    #[test]
    #[ignore = "needs GEX_DARWIN_RESTORE's 044-75188-038.dmg (21H461)"]
    fn the_app_cryptex_is_read() {
        let c = super::super::tests::restore_image("044-75188-038.dmg");
        let v = c.volume(0).unwrap().unwrap();
        assert!(v.sb.sealed());
        let mut n = 0u64;
        v.fs_tree.walk(&v.container, &mut |_, _| {
            n += 1;
            Ok(true)
        })
        .unwrap();
        assert_eq!(n, v.fs_tree.info.key_count);
        assert!(v.inode(ROOT_DIR_INO_NUM).unwrap().unwrap().is_dir());
    }
}
