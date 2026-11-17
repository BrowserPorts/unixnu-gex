//! Apple Archive streams ("AA01") and the chunked compression container
//! ("pbz") they are kept in, read in-process: an IPSW's
//! `Firmware/<system image>.dmg.mtree` (044-76040-038.dmg.mtree for
//! 21H461) is an IM4P of type `msys` whose data is a pbz stream of an
//! archive holding the restore's `digest.db` and `mtree.txt`
//! ([`mtree_payload`]).
//!
//! Apple publishes neither format. What is read here is what
//! libAppleArchive and libcompression do as the host's `aa` (macOS 27.0.1)
//! and `compression_decode_buffer` show it: on archives `aa archive` made
//! with each of its algorithms and with every field it can record, and on
//! streams made to probe each rule below, every one compared with what
//! `aa list -list-format json` and `aa extract` make of it.
//!
//! # pbz
//!
//! "pbz", an algorithm byte, then the block size, a big-endian u64 from 1
//! to [`PBZ_MAX_BLOCK`] (else "invalid block size"). Chunks follow to the
//! stream's end, with no trailer: each is its raw size and its payload
//! size, big-endian u64s, then the payload. A chunk either of whose sizes
//! is above the block size is refused ("Invalid block header"), as is a
//! chunk header or payload the stream ends inside. A payload as long as
//! the raw size is the bytes as they are (whatever the algorithm; `aa`
//! stores a chunk its algorithm does not shrink); any other is decoded,
//! and must give exactly the raw size ("invalid output size"). A chunk of
//! raw size 0 ends the data: a later chunk with bytes is refused ("write
//! after EOF"), and one with a payload is refused by its decoder. A stream
//! of no chunks is an empty archive.
//!
//! The algorithm byte, as `aa archive -a` writes it and `aa` reads it:
//!
//! | byte | algorithm | here |
//! |------|-----------|------|
//! | `e` | LZFSE (`bvx2`, `bvx1`, `bvxn`, `bvx-` blocks to `bvx$`) | [`super::lzfse`] |
//! | `f` | LZVN, a bare stream | [`super::lzfse`], as one `bvxn` block |
//! | `b` | LZBITMAP ("ZBM") | [`super::apfsread::lzbitmap`] |
//! | `4` | LZ4 in libcompression's `bv41`/`bv4-`/`bv4$` blocks | below |
//! | `-` | none: only stored chunks | refused otherwise, as `aa` does |
//! | `z` | zlib: RFC 1950 streams (`78 5e`) | [`super::inflate`], below |
//! | `x` | LZMA (xz streams) | not implemented |
//! | `m` | LZRAVEN (`aa -a lzraven`) | not implemented |
//!
//! Any other byte is "Invalid/non-supported archive stream".
//!
//! libcompression decodes a chunk into a buffer of its raw size and stops
//! when the buffer is full, so a payload that expands past its raw size
//! gives its first raw-size bytes and what follows is not read (`aa` takes
//! such LZFSE, LZVN, LZBITMAP, LZ4 and zlib chunks). The LZBITMAP, LZ4
//! and DEFLATE decoders here do the same; the LZFSE decoder refuses a
//! stream that does not end exactly at its destination's end, so an LZFSE
//! or LZVN chunk that expands past its raw size, or (LZVN) has bytes after
//! its end-of-stream opcode, is refused here, as not implemented.
//!
//! A zlib chunk's first two bytes, the RFC 1950 header, are skipped
//! whatever they hold (a payload under 2 bytes is refused), and the rest is
//! decoded as raw DEFLATE; the Adler-32 trailer is not read, and bytes
//! after the final block are not read either. `aa` takes chunks whose
//! header has a bad check, a preset dictionary flag or another method, a
//! bad or missing trailer, or a stored block whose NLEN is wrong.
//!
//! The LZBITMAP decoder is the kernel's (AppleFSCompressionTypeZlib's
//! copy); the host's libcompression refuses two things it takes, a stream
//! whose flags lack bit 3 and table entries of width 3 (`aa` itself writes
//! flags 9).
//!
//! # LZ4 blocks
//!
//! Each block starts with a little-endian magic: `bv4$` ends the stream;
//! `bv4-` is a u32 length and that many bytes as they are; `bv41` is the
//! block's raw size and payload size (u32s) and a payload of LZ4
//! sequences (the LZ4 block format: a token of literal length and match
//! length less 4, each 15 extended by bytes summed to the first under
//! 255; the literals; a 16-bit little-endian distance back into what the
//! chunk has produced, 0 refused; the match, which may overlap). The
//! payload's last sequence may end after its literals or after a match.
//! Measured against `compression_decode_buffer` (`COMPRESSION_LZ4`):
//!
//! - A block must be whole in the input, whatever the destination holds.
//! - The destination full at a block's start ends the decoding there
//!   (nothing more read, the end block not needed).
//! - Within a block, a literal run or match that would overrun the
//!   destination fills it and ends the decoding; one that fills it
//!   exactly does not, so the next sequence is still read up to its
//!   distance (and refused if that is 0 or reaches before the output).
//! - A `bv41` block whose sequences end without filling the destination
//!   must have produced its raw size; a block that fills it need not.
//! - A sequence's bytes that the payload does not hold are refused before
//!   anything is copied for it.
//!
//! # Archives
//!
//! An archive is entries, each a header and then its blobs. A header is
//! "AA01" (or "YAA1", read the same: `aa` lists a "YAA1" header with
//! every field type as it does "AA01"), its size as a little-endian u16
//! (the whole header's, magic and size included, at least 6), then fields
//! to its end: a 3-byte key (any bytes) and a subtype byte, then the
//! value. The subtypes, all that `aa` takes (any other byte is "invalid
//! field subtype"):
//!
//! | subtype | value |
//! |---------|-------|
//! | `*` | none: a flag |
//! | `1` `2` `4` `8` | an unsigned little-endian integer of that many bytes |
//! | `P` | a string: a u16 length and its bytes, no NUL |
//! | `S` | a time: seconds, u64 (`aa list` prints it unsigned) |
//! | `T` | a time: seconds, u64, and nanoseconds, u32 (not range-checked) |
//! | `F` `G` `H` `I` `J` | a digest: CRC-32 (POSIX `cksum`'s, its u32 little-endian), SHA-1, SHA-256, SHA-384, SHA-512 (4, 20, 32, 48, 64 bytes) |
//! | `A` `B` `C` | a blob: its size as a u16, u32 or u64; its bytes follow the header, the blobs in field order |
//!
//! A header's bytes after its last whole field, or a value its size cuts
//! off, are a truncated header. An entry's blobs may total at most
//! [`MAX_BLOBS`] bytes ("blob field size too large"). Bytes after the last
//! entry that do not make a header are a truncated stream.
//!
//! An entry needs a `TYP` field, an unsigned integer whose low byte is
//! its type (`D` directory, `F` regular file, `L` symbolic link, and
//! `b`, `c`, `p`, `s`, `h`, `m` as `man aa` lists them; others are
//! listed as they are). Of a key given more than once, the first is the
//! entry's (`aa list` shows every one). `PAT`, the path, is a string: one
//! of [`PATH_MAX`] bytes or more is no path; else it ends at its first
//! NUL; then it must not start or end with "/", have an empty component,
//! or (after one leading "./") have "." or ".." as any but its last
//! component ("Invalid entry path"). The root directory's path is empty.
//! A `PAT` that is not a string, a `TYP` that is not an unsigned integer
//! and a `DAT` (a file's data) that is not a blob are refused.

use std::borrow::Cow;
use std::ops::Range;

use super::apfsread::lzbitmap;
use super::image4::{self, der, tag};
use super::inflate;
use super::lzfse;

/// The largest block size a pbz stream may have (`aa` refuses 0x8000001).
pub const PBZ_MAX_BLOCK: u64 = 0x800_0000;

/// The most an entry's blobs may hold together (`aa` refuses one more).
pub const MAX_BLOBS: u64 = 1 << 48;

/// A path this long or longer is no path (`aa list` shows none for 1024
/// bytes; 1023 it shows).
pub const PATH_MAX: usize = 1024;

const PBZ_HEADER: usize = 12;
const CHUNK_HEADER: usize = 16;
const ENTRY_HEADER: usize = 6;

/// A pbz stream's algorithm, its fourth byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Lzfse,
    Lzvn,
    Lzbitmap,
    Lz4,
    None,
    Zlib,
    Lzma,
    Lzraven,
}

impl Algorithm {
    pub fn of(b: u8) -> Option<Algorithm> {
        Some(match b {
            b'e' => Algorithm::Lzfse,
            b'f' => Algorithm::Lzvn,
            b'b' => Algorithm::Lzbitmap,
            b'4' => Algorithm::Lz4,
            b'-' => Algorithm::None,
            b'z' => Algorithm::Zlib,
            b'x' => Algorithm::Lzma,
            b'm' => Algorithm::Lzraven,
            _ => return None,
        })
    }
}

fn be64(b: &[u8], at: usize) -> Option<u64> {
    let mut v = [0u8; 8];
    v.copy_from_slice(b.get(at..at.checked_add(8)?)?);
    Some(u64::from_be_bytes(v))
}

fn le(b: &[u8], at: usize, n: usize) -> Option<u64> {
    let s = b.get(at..at.checked_add(n)?)?;
    Some(s.iter().rev().fold(0u64, |v, &x| v << 8 | u64::from(x)))
}

/// Whether `src` is a pbz stream (by its magic).
pub fn is_pbz(src: &[u8]) -> bool {
    src.starts_with(b"pbz")
}

/// A chunk: its raw size and its payload's place in the stream.
struct Chunk {
    raw: usize,
    payload: Range<usize>,
}

/// The stream's algorithm and chunks, its framing checked.
fn pbz_chunks(src: &[u8]) -> Result<(Algorithm, Vec<Chunk>), String> {
    if !is_pbz(src) || src.len() < PBZ_HEADER {
        return Err("not a pbz stream (Invalid/non-supported archive stream)".into());
    }
    let alg = Algorithm::of(src[3]).ok_or_else(|| format!("pbz algorithm byte {:#04x}: not one libAppleArchive reads (Invalid/non-supported archive stream)", src[3]))?;
    let block = be64(src, 4).unwrap_or(0);
    if block == 0 || block > PBZ_MAX_BLOCK {
        return Err(format!("pbz block size {block:#x}: not 1 to {PBZ_MAX_BLOCK:#x} (invalid block size)"));
    }
    let mut chunks = Vec::new();
    let mut at = PBZ_HEADER;
    let mut ended = false;
    while at < src.len() {
        let (Some(raw), Some(size)) = (be64(src, at), be64(src, at + 8)) else {
            return Err(format!("a pbz chunk header at {at:#x} truncated ({} of {CHUNK_HEADER} bytes)", src.len() - at));
        };
        if raw > block || size > block {
            return Err(format!("the pbz chunk at {at:#x}: raw size {raw:#x}, payload size {size:#x}, over the block size {block:#x} (Invalid block header)"));
        }
        // Both are at most PBZ_MAX_BLOCK, which any usize holds.
        let (raw, size) = (raw as usize, size as usize);
        let start = at + CHUNK_HEADER;
        let end = start.checked_add(size).filter(|&e| e <= src.len()).ok_or_else(|| format!("the pbz chunk at {at:#x}: its payload of {size:#x} bytes truncated"))?;
        if raw == 0 && size != 0 {
            return Err(format!("the pbz chunk at {at:#x}: a payload of {size:#x} bytes for no bytes (invalid output size)"));
        }
        if ended && raw != 0 {
            return Err(format!("the pbz chunk at {at:#x}: data after a chunk of no bytes, which ends the stream (write after EOF)"));
        }
        ended |= raw == 0;
        chunks.push(Chunk { raw, payload: start..end });
        at = end;
    }
    Ok((alg, chunks))
}

/// Decodes a pbz stream whole.
pub fn pbz_decode(src: &[u8]) -> Result<Vec<u8>, String> {
    let (alg, chunks) = pbz_chunks(src)?;
    let total = chunks.iter().try_fold(0usize, |t, c| t.checked_add(c.raw)).ok_or("a pbz stream larger than memory")?;
    let mut out = vec![0u8; total];
    let mut at = 0usize;
    for c in &chunks {
        let dst = &mut out[at..at + c.raw];
        decode_chunk(alg, &src[c.payload.clone()], dst).map_err(|e| format!("the pbz chunk at {:#x}: {e}", c.payload.start - CHUNK_HEADER))?;
        at += c.raw;
    }
    Ok(out)
}

/// One chunk's payload into `dst`, its raw size.
fn decode_chunk(alg: Algorithm, payload: &[u8], dst: &mut [u8]) -> Result<(), String> {
    if payload.len() == dst.len() {
        dst.copy_from_slice(payload);
        return Ok(());
    }
    let n = match alg {
        Algorithm::Lzfse => {
            lzfse::decode(payload, dst).map_err(|e| format!("{e} (a stream that expands past its chunk, of which libcompression keeps the chunk's size, is not implemented here)"))?;
            dst.len()
        }
        Algorithm::Lzvn => lzvn(payload, dst)?,
        Algorithm::Lzbitmap => lzbitmap::decode(dst, payload).map_err(|e| e.to_string())?,
        Algorithm::Lz4 => lz4(payload, dst)?,
        Algorithm::None => return Err("a payload not stored in a stream of no algorithm (invalid output size)".into()),
        Algorithm::Zlib => {
            let raw = payload.get(2..).ok_or("a zlib payload under 2 bytes (invalid output size)")?;
            match inflate::decode_buffer(raw, dst, inflate::Variant::Host) {
                Ok(n) => n,
                Err(e @ inflate::Error::Rejected(_)) => return Err(format!("{e} (invalid output size)")),
                Err(e @ inflate::Error::Undefined(_)) => return Err(format!("{e}: not implemented")),
            }
        }
        Algorithm::Lzma => return Err("LZMA-compressed pbz chunks: not implemented".into()),
        Algorithm::Lzraven => return Err("LZRAVEN-compressed pbz chunks: not implemented".into()),
    };
    if n != dst.len() {
        return Err(format!("the payload expands to {n:#x} bytes, not {:#x} (invalid output size)", dst.len()));
    }
    Ok(())
}

/// A bare LZVN stream, decoded as the one `bvxn` block of an LZFSE
/// stream: the reference decoder's LZVN blocks are the same LZVN.
fn lzvn(payload: &[u8], dst: &mut [u8]) -> Result<usize, String> {
    // Both are at most PBZ_MAX_BLOCK, under 4 GiB.
    let mut s = Vec::with_capacity(payload.len() + 16);
    s.extend_from_slice(b"bvxn");
    s.extend_from_slice(&(dst.len() as u32).to_le_bytes());
    s.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    s.extend_from_slice(payload);
    s.extend_from_slice(b"bvx$");
    lzfse::decode(&s, dst).map_err(|e| format!("{e} (an LZVN stream that expands past its chunk or has bytes after its end, which libcompression takes: not implemented)"))?;
    Ok(dst.len())
}

const LZ4_COMPRESSED: &[u8; 4] = b"bv41";
const LZ4_UNCOMPRESSED: &[u8; 4] = b"bv4-";
const LZ4_END: &[u8; 4] = b"bv4$";

/// An LZ4 stream of `bv4` blocks into `dst`: how many bytes it fills.
fn lz4(src: &[u8], dst: &mut [u8]) -> Result<usize, String> {
    let u32_at = |at: usize| le(src, at, 4).map(|v| v as usize);
    let bytes = |at: usize, n: usize| src.get(at..at.checked_add(n)?);
    let (mut at, mut out) = (0usize, 0usize);
    loop {
        if out == dst.len() {
            return Ok(out);
        }
        let Some(magic) = src.get(at..at + 4) else { return Err("an LZ4 stream ends without its end block".into()) };
        if magic == LZ4_END {
            return Ok(out);
        } else if magic == LZ4_UNCOMPRESSED {
            let n = u32_at(at + 4).ok_or("an LZ4 uncompressed block's header truncated")?;
            let b = bytes(at + 8, n).ok_or("an LZ4 uncompressed block truncated")?;
            let k = n.min(dst.len() - out);
            dst[out..out + k].copy_from_slice(&b[..k]);
            out += k;
            at += 8 + b.len();
        } else if magic == LZ4_COMPRESSED {
            let (Some(n_raw), Some(n_payload)) = (u32_at(at + 4), u32_at(at + 8)) else { return Err("an LZ4 block's header truncated".into()) };
            let payload = bytes(at + 12, n_payload).ok_or("an LZ4 block truncated")?;
            let from = out;
            out = lz4_block(payload, dst, out)?;
            if out < dst.len() && out - from != n_raw {
                return Err(format!("an LZ4 block of raw size {n_raw:#x} expands to {:#x} bytes", out - from));
            }
            at += 12 + payload.len();
        } else {
            return Err(format!("LZ4 block magic {magic:02x?}"));
        }
    }
}

/// An LZ4 extended length: `n` plus the bytes from `at` up to and
/// including the first under 255.
fn lz4_length(p: &[u8], at: &mut usize, mut n: usize) -> Result<usize, String> {
    loop {
        let &b = p.get(*at).ok_or("an LZ4 length truncated")?;
        *at += 1;
        n = n.checked_add(usize::from(b)).ok_or("an LZ4 length too large")?;
        if b != 255 {
            return Ok(n);
        }
    }
}

/// One `bv41` block's sequences into `dst` from `out`, distances reaching
/// back to `dst`'s start: where the output ends (`dst.len()` when full).
fn lz4_block(p: &[u8], dst: &mut [u8], mut out: usize) -> Result<usize, String> {
    let end = dst.len();
    if out >= end {
        return Ok(out);
    }
    let mut s = 0usize;
    while s < p.len() {
        let token = p[s];
        s += 1;
        let mut lit = usize::from(token >> 4);
        if lit == 15 {
            lit = lz4_length(p, &mut s, lit)?;
        }
        if lit > p.len() - s {
            return Err("LZ4 literals truncated".into());
        }
        if lit > end - out {
            let k = end - out;
            dst[out..end].copy_from_slice(&p[s..s + k]);
            return Ok(end);
        }
        dst[out..out + lit].copy_from_slice(&p[s..s + lit]);
        s += lit;
        out += lit;
        if s == p.len() {
            break;
        }
        let distance = le(p, s, 2).ok_or("an LZ4 distance truncated")? as usize;
        s += 2;
        if distance == 0 {
            return Err("an LZ4 distance of 0".into());
        }
        if distance > out {
            return Err(format!("an LZ4 distance of {distance:#x} at {out:#x}, before the output's start"));
        }
        let mut m = 4 + usize::from(token & 15);
        if m == 19 {
            m = lz4_length(p, &mut s, m)?;
        }
        let k = m.min(end - out);
        for i in out..out + k {
            let b = dst[i - distance];
            dst[i] = b;
        }
        out += k;
        if k < m {
            return Ok(end);
        }
    }
    Ok(out)
}

/// The archive an archive stream holds: a pbz stream's decoded, an
/// uncompressed one ("AA01" or "YAA1", or nothing) as it is.
pub fn archive_stream(data: &[u8]) -> Result<Cow<'_, [u8]>, String> {
    if is_pbz(data) {
        return pbz_decode(data).map(Cow::Owned);
    }
    if data.is_empty() || data.starts_with(b"AA01") || data.starts_with(b"YAA1") {
        return Ok(Cow::Borrowed(data));
    }
    if data.starts_with(b"AEA1") {
        return Err("an encrypted archive (AEA1): not implemented".into());
    }
    Err(format!("an archive stream starting {:02x?}: not pbz, AA01 or YAA1 (Invalid/non-supported archive stream)", &data[..data.len().min(4)]))
}

/// A field's value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value<'a> {
    /// `*`.
    Flag,
    /// `1`, `2`, `4`, `8`.
    Uint(u64),
    /// `P`.
    String(&'a [u8]),
    /// `S` (no nanoseconds) and `T`.
    Time { sec: u64, nsec: Option<u32> },
    /// `F` to `J`, as stored.
    Digest(&'a [u8]),
    /// `A`, `B`, `C`: the blob's place in the archive.
    Blob(Range<usize>),
}

/// A header field: its key, its subtype byte and its value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field<'a> {
    pub key: [u8; 3],
    pub subtype: u8,
    pub value: Value<'a>,
}

/// An archive entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    /// "AA01" or "YAA1".
    pub magic: [u8; 4],
    /// Where its header starts in the archive.
    pub offset: usize,
    /// Its header's fields in order.
    pub fields: Vec<Field<'a>>,
    /// Its type: `TYP`'s low byte.
    pub kind: u8,
    /// Its path, as the module's documentation says; `None` without one.
    pub path: Option<&'a [u8]>,
    /// Where the next entry starts: past its header and blobs.
    pub end: usize,
}

impl<'a> Entry<'a> {
    /// The first field of key `key`.
    pub fn field(&self, key: &[u8; 3]) -> Option<&Field<'a>> {
        self.fields.iter().find(|f| &f.key == key)
    }

    /// The first field of key `key`, when an unsigned integer.
    pub fn uint(&self, key: &[u8; 3]) -> Option<u64> {
        match self.field(key)?.value {
            Value::Uint(v) => Some(v),
            _ => None,
        }
    }

    /// The first field of key `key`, when a blob: its bytes' place.
    pub fn blob(&self, key: &[u8; 3]) -> Option<Range<usize>> {
        match &self.field(key)?.value {
            Value::Blob(r) => Some(r.clone()),
            _ => None,
        }
    }

    /// Its data (`DAT`), when it has any.
    pub fn data(&self) -> Option<Range<usize>> {
        self.blob(b"DAT")
    }
}

/// Whether `p` (cut at its first NUL) is a path `aa` takes.
fn path_valid(p: &[u8]) -> bool {
    if p.is_empty() {
        return true;
    }
    if p.starts_with(b"/") || p.ends_with(b"/") {
        return false;
    }
    let rest = p.strip_prefix(b"./").unwrap_or(p);
    let n = rest.split(|&c| c == b'/').count();
    rest.split(|&c| c == b'/').enumerate().all(|(i, c)| !c.is_empty() && (i + 1 == n || (c != b"." && c != b"..")))
}

fn subtype(st: u8) -> String {
    if st.is_ascii_graphic() { format!("'{}'", st as char) } else { format!("{st:#04x}") }
}

/// The entry whose header starts at `at`.
fn parse_entry(a: &[u8], at: usize) -> Result<Entry<'_>, String> {
    let rest = &a[at..];
    if rest.len() < ENTRY_HEADER {
        return Err(format!("{} bytes at {at:#x}, short of an entry header (truncated stream)", rest.len()));
    }
    let magic = [rest[0], rest[1], rest[2], rest[3]];
    if &magic != b"AA01" && &magic != b"YAA1" {
        return Err(format!("the entry at {at:#x}: header magic {magic:02x?} (invalid header magic)"));
    }
    let size = usize::from(u16::from_le_bytes([rest[4], rest[5]]));
    if size < ENTRY_HEADER {
        return Err(format!("the entry at {at:#x}: header size {size}, under {ENTRY_HEADER} (header size mismatch)"));
    }
    let h = rest.get(..size).ok_or_else(|| format!("the entry at {at:#x}: its header of {size} bytes truncated (truncated archive)"))?;
    let truncated = || format!("the entry at {at:#x}: truncated header");
    let mut fields = Vec::new();
    let mut blobs: Vec<(usize, u64)> = Vec::new();
    let mut p = ENTRY_HEADER;
    while p < size {
        if size - p < 4 {
            return Err(truncated());
        }
        let key = [h[p], h[p + 1], h[p + 2]];
        let st = h[p + 3];
        p += 4;
        let value = match st {
            b'*' => Value::Flag,
            b'1' | b'2' | b'4' | b'8' => {
                let n = usize::from(st - b'0');
                let v = le(h, p, n).ok_or_else(truncated)?;
                p += n;
                Value::Uint(v)
            }
            b'P' => {
                let n = le(h, p, 2).ok_or_else(truncated)? as usize;
                let s = h.get(p + 2..p + 2 + n).ok_or_else(truncated)?;
                p += 2 + n;
                Value::String(s)
            }
            b'S' | b'T' => {
                let sec = le(h, p, 8).ok_or_else(truncated)?;
                p += 8;
                let nsec = if st == b'T' {
                    let ns = le(h, p, 4).ok_or_else(truncated)? as u32;
                    p += 4;
                    Some(ns)
                } else {
                    None
                };
                Value::Time { sec, nsec }
            }
            b'F' | b'G' | b'H' | b'I' | b'J' => {
                let n = match st {
                    b'F' => 4,
                    b'G' => 20,
                    b'H' => 32,
                    b'I' => 48,
                    _ => 64,
                };
                let d = h.get(p..p + n).ok_or_else(truncated)?;
                p += n;
                Value::Digest(d)
            }
            b'A' | b'B' | b'C' => {
                let n = match st {
                    b'A' => 2,
                    b'B' => 4,
                    _ => 8,
                };
                let len = le(h, p, n).ok_or_else(truncated)?;
                p += n;
                blobs.push((fields.len(), len));
                Value::Blob(0..0)
            }
            _ => return Err(format!("the entry at {at:#x}: field {} of subtype {} (invalid field subtype)", String::from_utf8_lossy(&key), subtype(st))),
        };
        fields.push(Field { key, subtype: st, value });
    }
    let total = blobs.iter().try_fold(0u64, |t, &(_, n)| t.checked_add(n).filter(|&t| t <= MAX_BLOBS));
    if total.is_none() {
        return Err(format!("the entry at {at:#x}: blobs over {MAX_BLOBS:#x} bytes (blob field size too large)"));
    }
    let mut off = at + size;
    for (i, n) in blobs {
        let end = usize::try_from(n).ok().and_then(|n| off.checked_add(n)).filter(|&e| e <= a.len());
        let end = end.ok_or_else(|| format!("the entry at {at:#x}: its {} blob of {n:#x} bytes truncated (truncated archive)", String::from_utf8_lossy(&fields[i].key)))?;
        fields[i].value = Value::Blob(off..end);
        off = end;
    }
    let first = |k: &[u8; 3]| fields.iter().find(|f| &f.key == k);
    let kind = match first(b"TYP") {
        Some(Field { value: Value::Uint(v), .. }) => *v as u8,
        Some(f) => return Err(format!("the entry at {at:#x}: TYP of subtype {}, not an unsigned integer (no TYP field)", subtype(f.subtype))),
        None => return Err(format!("the entry at {at:#x}: no TYP field")),
    };
    let path = match first(b"PAT") {
        Some(Field { value: Value::String(s), .. }) if s.len() >= PATH_MAX => None,
        Some(Field { value: Value::String(s), .. }) => {
            let s = &s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())];
            if !path_valid(s) {
                return Err(format!("the entry at {at:#x}: path {:?} (Invalid entry path)", String::from_utf8_lossy(s)));
            }
            Some(s)
        }
        Some(f) => return Err(format!("the entry at {at:#x}: PAT of subtype {}, not a string", subtype(f.subtype))),
        None => None,
    };
    if let Some(f) = first(b"DAT") {
        if !matches!(f.value, Value::Blob(_)) {
            return Err(format!("the entry at {at:#x}: DAT of subtype {}, not a blob", subtype(f.subtype)));
        }
    }
    Ok(Entry { magic, offset: at, fields, kind, path, end: off })
}

/// An archive's entries in order; after an error, none.
pub struct Entries<'a> {
    archive: &'a [u8],
    at: usize,
    failed: bool,
}

impl<'a> Iterator for Entries<'a> {
    type Item = Result<Entry<'a>, String>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.at >= self.archive.len() {
            return None;
        }
        let r = parse_entry(self.archive, self.at);
        match &r {
            Ok(e) => self.at = e.end,
            Err(_) => self.failed = true,
        }
        Some(r)
    }
}

/// The entries of `archive`, a decoded archive.
pub fn iter(archive: &[u8]) -> Entries<'_> {
    Entries { archive, at: 0, failed: false }
}

/// All the entries of `archive`, or its first error.
pub fn entries(archive: &[u8]) -> Result<Vec<Entry<'_>>, String> {
    iter(archive).collect()
}

/// The data of the regular file at `path` in `archive`: there must be
/// exactly one entry of that path (`aa extract` fails on a second), a
/// regular file with a `DAT` blob (`aa extract` makes no file of one
/// without). Every entry is read, so an archive with an error anywhere
/// gives that error.
pub fn file<'a>(archive: &'a [u8], path: &str) -> Result<&'a [u8], String> {
    let mut found = None;
    for e in iter(archive) {
        let e = e?;
        if e.path == Some(path.as_bytes()) {
            if found.is_some() {
                return Err(format!("{path:?}: more than one entry"));
            }
            found = Some(e);
        }
    }
    let e = found.ok_or_else(|| format!("{path:?}: no entry"))?;
    if e.kind != b'F' {
        return Err(format!("{path:?}: an entry of type {:?}, not a regular file", e.kind as char));
    }
    let r = e.data().ok_or_else(|| format!("{path:?}: a regular file with no DAT field"))?;
    Ok(&archive[r])
}

/// An IM4P's items, with and without its properties, as
/// `DERImg4DecodePayload` takes them.
const IM4P: [der::Spec; 7] = [
    der::spec(tag::IA5_STRING, 0),
    der::spec(tag::IA5_STRING, 0),
    der::spec(tag::IA5_STRING, 0),
    der::spec(tag::OCTET_STRING, 0),
    der::spec(tag::OCTET_STRING, der::OPTIONAL),
    der::spec(tag::SEQUENCE, der::OPTIONAL),
    der::spec(tag::context(0), der::OPTIONAL),
];

/// An IM4P's type (its second item, "msys" for the mtree) and data, as
/// `Img4DecodeInitAsPayload` decodes it ([`image4::init_as_payload`]).
/// An IM4P whose data is compressed (its compression sequence there) is
/// refused, as not implemented.
pub fn im4p_payload(im4p: &[u8]) -> Result<(&[u8], &[u8]), String> {
    let p = image4::init_as_payload(im4p).map_err(|e| format!("not an IM4P (libDER error {e})"))?;
    let data = p.data.ok_or("an IM4P with no data")?;
    let it = der::parse_sequence(im4p, &IM4P).or_else(|_| der::parse_sequence(im4p, &IM4P[..6])).map_err(|e| format!("not an IM4P (libDER error {e})"))?;
    if it[5].is_some() {
        return Err("an IM4P whose data is compressed (its compression sequence): not implemented".into());
    }
    Ok((it[1].unwrap_or(&[]), data))
}

/// The archive an IPSW's `.dmg.mtree` holds: its IM4P's data decoded.
/// [`file`] reads `digest.db` and `mtree.txt` from it.
pub fn mtree_payload(im4p: &[u8]) -> Result<Vec<u8>, String> {
    let (_, data) = im4p_payload(im4p)?;
    archive_stream(data).map(Cow::into_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest as _;

    fn hdr(magic: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut h = magic.to_vec();
        h.extend_from_slice(&((ENTRY_HEADER + body.len()) as u16).to_le_bytes());
        h.extend_from_slice(body);
        h
    }

    fn aa(body: &[u8]) -> Vec<u8> {
        hdr(b"AA01", body)
    }

    fn pat(p: &[u8]) -> Vec<u8> {
        [b"PATP".as_slice(), &(p.len() as u16).to_le_bytes(), p].concat()
    }

    fn dir(p: &[u8]) -> Vec<u8> {
        aa(&[b"TYP1D".as_slice(), &pat(p)].concat())
    }

    fn pbz(alg: u8, block: u64, chunks: &[(u64, &[u8])]) -> Vec<u8> {
        let mut s = vec![b'p', b'b', b'z', alg];
        s.extend_from_slice(&block.to_be_bytes());
        for &(raw, payload) in chunks {
            s.extend_from_slice(&raw.to_be_bytes());
            s.extend_from_slice(&(payload.len() as u64).to_be_bytes());
            s.extend_from_slice(payload);
        }
        s
    }

    /// One entry with a field of every subtype, its blobs in field order.
    #[test]
    fn every_subtype() {
        let body = [
            b"TYP1F".as_slice(),
            &pat(b"a/b"),
            b"FLG*",
            b"UID2\xf5\x01",
            b"GID4\x14\0\0\0",
            b"INO8\x01\x02\x03\x04\x05\x06\x07\x08",
            b"MTMS\x00\xf1\x53\x65\0\0\0\0",
            b"CTMT\x01\xf1\x53\x65\0\0\0\0\x15\xcd\x5b\x07",
            b"CKSF\xff\xff\xff\xff",
            b"SH1G",
            &[1; 20],
            b"SH2H",
            &[2; 32],
            b"SH3I",
            &[3; 48],
            b"SH5J",
            &[5; 64],
            b"XATA\x02\0",
            b"DATB\x03\0\0\0",
            b"ACLC\x01\0\0\0\0\0\0\0",
        ]
        .concat();
        let mut a = aa(&body);
        let h = a.len();
        a.extend_from_slice(b"xyabcz");
        let es = entries(&a).unwrap();
        assert_eq!(es.len(), 1);
        let e = &es[0];
        assert_eq!((e.kind, e.path, e.end), (b'F', Some(b"a/b".as_slice()), a.len()));
        let v: Vec<_> = e.fields.iter().map(|f| (f.key, f.subtype, f.value.clone())).collect();
        assert_eq!(v[2], (*b"FLG", b'*', Value::Flag));
        assert_eq!(e.uint(b"UID"), Some(501));
        assert_eq!(e.uint(b"GID"), Some(20));
        assert_eq!(e.uint(b"INO"), Some(0x0807_0605_0403_0201));
        assert_eq!(e.field(b"MTM").unwrap().value, Value::Time { sec: 1_700_000_000, nsec: None });
        assert_eq!(e.field(b"CTM").unwrap().value, Value::Time { sec: 1_700_000_001, nsec: Some(123_456_789) });
        assert_eq!(e.field(b"CKS").unwrap().value, Value::Digest(&[0xff; 4]));
        assert_eq!(e.field(b"SH5").unwrap().value, Value::Digest(&[5; 64]));
        assert_eq!(e.blob(b"XAT"), Some(h..h + 2));
        assert_eq!(e.data(), Some(h + 2..h + 5));
        assert_eq!(e.blob(b"ACL"), Some(h + 5..h + 6));
        assert_eq!(file(&a, "a/b").unwrap(), b"abc");
        // "YAA1" reads the same.
        let y = [hdr(b"YAA1", &body), b"xyabcz".to_vec()].concat();
        assert_eq!(file(&y, "a/b").unwrap(), b"abc");
    }

    #[test]
    fn header_errors() {
        let e = |a: &[u8]| entries(a).unwrap_err();
        let typ = b"TYP1D".as_slice();
        assert!(e(&aa(&[typ, b"MTMN", &[0; 16]].concat())).contains("invalid field subtype"));
        assert!(e(&aa(&[typ, b"MTM3"].concat())).contains("invalid field subtype"));
        // A field key cut off, or a value.
        assert!(e(&aa(&[typ, b"\0"].concat())).contains("truncated header"));
        assert!(e(&aa(&[typ, b"XYZ"].concat())).contains("truncated header"));
        assert!(e(&aa(&[typ, b"UID4\x01"].concat())).contains("truncated header"));
        assert!(e(&aa(&[typ, b"PATP\x05\0ab"].concat())).contains("truncated header"));
        // A trailing flag is a whole field.
        assert_eq!(entries(&aa(&[typ, b"XYZ*"].concat())).unwrap()[0].fields.len(), 2);
        for size in [0u16, 5] {
            let mut h = b"AA01".to_vec();
            h.extend_from_slice(&size.to_le_bytes());
            assert!(e(&h).contains("header size mismatch"));
        }
        assert!(e(&[dir(b""), hdr(b"AA02", b"TYP1D")].concat()).contains("invalid header magic"));
        assert!(e(&[dir(b""), b"AA0".to_vec()].concat()).contains("truncated stream"));
        assert!(e(&aa(&[typ, b"DATA\x03\0"].concat())).contains("truncated archive"));
        let blob = |n: u64, m: u64| aa(&[typ, b"DATC", &n.to_le_bytes(), b"XATC", &m.to_le_bytes()].concat());
        assert!(e(&blob(MAX_BLOBS, 0)).contains("truncated archive"));
        assert!(e(&blob(MAX_BLOBS / 2, MAX_BLOBS / 2)).contains("truncated archive"));
        assert!(e(&blob(MAX_BLOBS / 2, MAX_BLOBS / 2 + 1)).contains("too large"));
        assert!(e(&blob(1 << 63, 1 << 63)).contains("too large"));
        // TYP: needed, an unsigned integer, its low byte; the first wins.
        assert!(e(&aa(&pat(b"x"))).contains("no TYP field"));
        assert!(e(&aa(b"TYPP\x01\0D")).contains("no TYP field"));
        assert!(e(&aa(b"TYP*")).contains("no TYP field"));
        assert_eq!(entries(&aa(b"TYP2\x44\x01")).unwrap()[0].kind, b'D');
        assert_eq!(entries(&aa(b"TYP8\x44\0\0\0\x01\0\0\0")).unwrap()[0].kind, b'D');
        assert_eq!(entries(&aa(b"TYP1DTYP1F")).unwrap()[0].kind, b'D');
        assert!(e(&aa(b"TYPP\x01\0FTYP1D")).contains("no TYP field"));
        assert!(e(&aa(&[typ, b"PAT1\x05"].concat())).contains("not a string"));
        assert!(e(&aa(&[typ, b"DAT4\x05\0\0\0"].concat())).contains("not a blob"));
        // An entry stops the iteration at its error.
        let two = [dir(b""), b"AA0".to_vec()].concat();
        let mut it = iter(&two).collect::<Vec<_>>().into_iter();
        assert!(it.next().unwrap().is_ok());
        assert!(it.next().unwrap().is_err());
        assert!(it.next().is_none());
        assert!(entries(&[]).unwrap().is_empty());
    }

    /// Paths as `aa list` took or refused them.
    #[test]
    fn paths() {
        let ok: &[&[u8]] = &[b"", b".", b"..", b"./a", b"a/.", b"a/..", b"./.", b"./..", b"...", b"..a", b"a..", b"a\\b", b"a/b/c", b"a/.../b", b".a/b", b"a/b/..", b"a/b/.", b"a/.a", b"a/..b"];
        for p in ok {
            assert_eq!(entries(&dir(p)).unwrap()[0].path, Some(*p), "{p:?}");
        }
        let bad: &[&[u8]] = &[b"a/./b", b"a/../b", b"a//b", b"a/", b"/", b"//", b"/a", b"../a", b"./", b".//a", b"a/./", b"/.", b"../..", b".././a", b"././a", b"./b/./c", b"./../a"];
        for p in bad {
            assert!(entries(&dir(p)).unwrap_err().contains("Invalid entry path"), "{p:?}");
        }
        // Cut at a NUL, then checked.
        assert_eq!(entries(&dir(b"a\0b")).unwrap()[0].path, Some(b"a".as_slice()));
        assert_eq!(entries(&dir(b".\0/a")).unwrap()[0].path, Some(b".".as_slice()));
        assert!(entries(&dir(b"a/\0x")).is_err());
        // 1024 bytes or more (NULs counted) is no path.
        assert_eq!(entries(&dir(&[b'a'; 1023])).unwrap()[0].path.map(<[u8]>::len), Some(1023));
        assert_eq!(entries(&dir(&[b'a'; 1024])).unwrap()[0].path, None);
        let mut p = b"abc\0".to_vec();
        p.resize(1100, b'x');
        assert_eq!(entries(&dir(&p)).unwrap()[0].path, None);
        // The first PAT is the entry's.
        let two = aa(&[b"TYP1D".as_slice(), &pat(b"a"), &pat(b"/")].concat());
        assert_eq!(entries(&two).unwrap()[0].path, Some(b"a".as_slice()));
        let two = aa(&[b"TYP1D".as_slice(), &pat(b"/"), &pat(b"a")].concat());
        assert!(entries(&two).is_err());
    }

    #[test]
    fn files() {
        let f = |p: &[u8], d: &[u8]| [aa(&[b"TYP1F".as_slice(), &pat(p), b"DATA", &(d.len() as u16).to_le_bytes()].concat()), d.to_vec()].concat();
        let a = [dir(b""), f(b"x", b"one"), f(b"e", b""), aa(&[b"TYP1F".as_slice(), &pat(b"nodat")].concat()), dir(b"d"), f(b"dup", b"1"), f(b"dup", b"2")].concat();
        assert_eq!(file(&a, "x").unwrap(), b"one");
        assert_eq!(file(&a, "e").unwrap(), b"");
        assert!(file(&a, "nodat").unwrap_err().contains("no DAT"));
        assert!(file(&a, "d").unwrap_err().contains("not a regular file"));
        assert!(file(&a, "dup").unwrap_err().contains("more than one"));
        assert!(file(&a, "y").unwrap_err().contains("no entry"));
    }

    #[test]
    fn pbz_framing() {
        let a = [dir(b""), dir(b"x")].concat();
        let n = a.len() as u64;
        assert_eq!(pbz_decode(&pbz(b'e', 0x10000, &[(n, &a)])).unwrap(), a);
        assert_eq!(pbz_decode(&pbz(b'-', 0x10000, &[(10, &a[..10]), (n - 10, &a[10..])])).unwrap(), a);
        assert_eq!(pbz_decode(&pbz(b'e', 0x10000, &[])).unwrap(), b"");
        // Block sizes.
        assert!(pbz_decode(&pbz(b'e', 0, &[])).unwrap_err().contains("invalid block size"));
        assert!(pbz_decode(&pbz(b'e', 1, &[])).is_ok());
        assert!(pbz_decode(&pbz(b'e', PBZ_MAX_BLOCK, &[])).is_ok());
        assert!(pbz_decode(&pbz(b'e', PBZ_MAX_BLOCK + 1, &[])).unwrap_err().contains("invalid block size"));
        assert!(pbz_decode(&pbz(b'e', 1 << 63 | 0x10000, &[])).unwrap_err().contains("invalid block size"));
        // A chunk over the block size, raw or payload.
        assert!(pbz_decode(&pbz(b'e', n - 1, &[(n, &a)])).unwrap_err().contains("Invalid block header"));
        assert!(pbz_decode(&pbz(b'e', n, &[(n, &[a.as_slice(), b"\0"].concat())])).unwrap_err().contains("Invalid block header"));
        // Truncation, and nothing after the last chunk.
        let s = pbz(b'e', 0x10000, &[(n, &a)]);
        assert!(pbz_decode(&s[..s.len() - 1]).unwrap_err().contains("truncated"));
        assert!(pbz_decode(&[s.as_slice(), &[0; 8]].concat()).unwrap_err().contains("truncated"));
        assert!(pbz_decode(&s[..8]).unwrap_err().contains("non-supported"));
        // A chunk of no bytes ends the data.
        assert_eq!(pbz_decode(&pbz(b'e', 0x10000, &[(n, &a), (0, b"")])).unwrap(), a);
        assert_eq!(pbz_decode(&pbz(b'e', 0x10000, &[(n, &a), (0, b""), (0, b"")])).unwrap(), a);
        assert!(pbz_decode(&pbz(b'e', 0x10000, &[(0, b""), (n, &a)])).unwrap_err().contains("write after EOF"));
        assert!(pbz_decode(&pbz(b'e', 0x10000, &[(n, &a), (0, b"bvx$")])).unwrap_err().contains("invalid output size"));
        // Algorithms.
        assert!(pbz_decode(&pbz(b'q', 0x10000, &[(n, &a)])).unwrap_err().contains("non-supported"));
        assert!(pbz_decode(&pbz(b'-', 0x10000, &[(n + 1, &a)])).unwrap_err().contains("not stored"));
        assert!(pbz_decode(&pbz(b'z', 0x10000, &[(n + 1, &a)])).unwrap_err().contains("invalid output size"));
        assert!(pbz_decode(&pbz(b'x', 0x10000, &[(n + 1, &a)])).unwrap_err().contains("LZMA"));
        assert!(pbz_decode(&pbz(b'm', 0x10000, &[(n + 1, &a)])).unwrap_err().contains("LZRAVEN"));
        // Stored chunks need no decoder, whatever the algorithm.
        for alg in *b"ebf4-zxm" {
            assert_eq!(pbz_decode(&pbz(alg, 0x10000, &[(n, &a)])).unwrap(), a);
        }
    }

    #[test]
    fn pbz_algorithms() {
        // LZFSE: an uncompressed block; bytes after the end are not read.
        let mut s = b"bvx-\x05\0\0\0hellobvx$".to_vec();
        assert_eq!(pbz_decode(&pbz(b'e', 64, &[(5, &s)])).unwrap(), b"hello");
        s.extend_from_slice(b"junk");
        assert_eq!(pbz_decode(&pbz(b'e', 64, &[(5, &s)])).unwrap(), b"hello");
        assert!(pbz_decode(&pbz(b'e', 64, &[(6, &s)])).is_err());
        // LZVN: five literals, then the end-of-stream opcode.
        let v = b"\xe5hello\x06\0\0\0\0\0\0\0";
        assert_eq!(pbz_decode(&pbz(b'f', 64, &[(5, v)])).unwrap(), b"hello");
        assert!(pbz_decode(&pbz(b'f', 64, &[(6, v)])).is_err());
        // LZBITMAP: a stored block and the end block; the decoder stops
        // when its destination is full.
        let z = b"ZBM\x09\x0b\0\0\x05\0\0hello\x06\0\0\0\0\0junk";
        assert_eq!(pbz_decode(&pbz(b'b', 64, &[(5, z)])).unwrap(), b"hello");
        assert_eq!(pbz_decode(&pbz(b'b', 64, &[(3, z)])).unwrap(), b"hel");
        assert!(pbz_decode(&pbz(b'b', 64, &[(9, z)])).unwrap_err().contains("invalid output size"));
        // LZ4.
        assert_eq!(pbz_decode(&pbz(b'4', 64, &[(5, b"bv41\x05\0\0\0\x06\0\0\0\x50abcdebv4$")])).unwrap(), b"abcde");
        // zlib: "hello" in a fixed block; the header and trailer not read,
        // the decoder stopping when the chunk is full.
        let z = b"\x78\x5e\xcb\x48\xcd\xc9\xc9\x07\x00\x06\x2c\x02\x15";
        assert_eq!(pbz_decode(&pbz(b'z', 64, &[(5, z)])).unwrap(), b"hello");
        assert_eq!(pbz_decode(&pbz(b'z', 64, &[(5, &[b"\xff\xff", &z[2..9]].concat())])).unwrap(), b"hello");
        assert_eq!(pbz_decode(&pbz(b'z', 64, &[(3, z)])).unwrap(), b"hel");
        assert!(pbz_decode(&pbz(b'z', 64, &[(6, z)])).unwrap_err().contains("invalid output size"));
        assert!(pbz_decode(&pbz(b'z', 64, &[(5, &z[..1])])).unwrap_err().contains("under 2 bytes"));
        assert!(pbz_decode(&pbz(b'z', 64, &[(5, b"\x78\x5e\x07")])).unwrap_err().contains("invalid output size"));
    }

    /// An LZ4 sequence: `lit` literals, then a match of `m` bytes
    /// `distance` back.
    fn seq(lit: &[u8], m: Option<(u16, usize)>) -> Vec<u8> {
        let ext = |v: &mut Vec<u8>, n: usize| {
            if n >= 15 {
                let mut r = n - 15;
                while r >= 255 {
                    v.push(255);
                    r -= 255;
                }
                v.push(r as u8);
            }
        };
        let ml = m.map_or(0, |(_, n)| n - 4);
        let mut v = vec![((lit.len().min(15) as u8) << 4) | ml.min(15) as u8];
        ext(&mut v, lit.len());
        v.extend_from_slice(lit);
        if let Some((d, _)) = m {
            v.extend_from_slice(&d.to_le_bytes());
            ext(&mut v, ml);
        }
        v
    }

    fn blk(n_raw: u32, p: &[u8]) -> Vec<u8> {
        [b"bv41".as_slice(), &n_raw.to_le_bytes(), &(p.len() as u32).to_le_bytes(), p].concat()
    }

    fn unc(b: &[u8]) -> Vec<u8> {
        [b"bv4-".as_slice(), &(b.len() as u32).to_le_bytes(), b].concat()
    }

    /// A stream's name, the stream, a capacity and what it decodes to.
    type Case<'a> = (&'a str, Vec<u8>, usize, Option<&'a [u8]>);

    /// Streams with what `compression_decode_buffer` (`COMPRESSION_LZ4`)
    /// made of them at a capacity: `None` its failure.
    #[test]
    fn lz4_as_libcompression() {
        let end = b"bv4$".as_slice();
        let a = seq(b"abcde", None);
        let m = seq(b"wxyz", Some((1, 8)));
        let c = [m.clone(), seq(b"123", None)].concat();
        let cases: Vec<Case<'_>> = vec![
            ("lit_only", [blk(5, &a), end.to_vec()].concat(), 5, Some(b"abcde")),
            ("ends_match", [blk(12, &m), end.to_vec()].concat(), 12, Some(b"wxyzzzzzzzzz")),
            ("normal", [blk(15, &c), end.to_vec()].concat(), 15, Some(b"wxyzzzzzzzzz123")),
            ("nraw_more", [blk(20, &c), end.to_vec()].concat(), 20, None),
            ("nraw_less", [blk(10, &c), end.to_vec()].concat(), 10, Some(b"wxyzzzzzzz")),
            ("nraw_less_then_more", [blk(10, &c), blk(5, &a), end.to_vec()].concat(), 15, Some(b"wxyzzzzzzzzz123")),
            ("nraw_less_bigcap", [blk(10, &c), end.to_vec()].concat(), 30, None),
            ("nraw0_bigcap", [blk(0, &a), end.to_vec()].concat(), 30, None),
            ("nraw0_full", [blk(0, &a), end.to_vec()].concat(), 5, Some(b"abcde")),
            ("nraw_more_full", [blk(20, &c), end.to_vec()].concat(), 15, Some(b"wxyzzzzzzzzz123")),
            ("pad_payload", [blk(15, &[c.as_slice(), b"\0\0"].concat()), end.to_vec()].concat(), 15, None),
            ("off0", [blk(12, &seq(b"wxyz", Some((0, 8)))), end.to_vec()].concat(), 12, None),
            ("off_far", [blk(12, &seq(b"wxyz", Some((9, 8)))), end.to_vec()].concat(), 12, None),
            ("cross_block_ref", [blk(5, &a), blk(8, &seq(b"", Some((5, 8)))), end.to_vec()].concat(), 13, Some(b"abcdeabcdeabc")),
            ("far_offset_cross", [blk(5, &a), blk(8, &seq(b"", Some((6, 8)))), end.to_vec()].concat(), 13, None),
            ("uncomp", [unc(b"xyz"), end.to_vec()].concat(), 3, Some(b"xyz")),
            ("uncomp_then_ref", [unc(b"xyz"), blk(8, &seq(b"", Some((3, 8)))), end.to_vec()].concat(), 11, Some(b"xyzxyzxyzxy")),
            ("uncomp_cap2", [unc(b"xyz"), end.to_vec()].concat(), 2, Some(b"xy")),
            ("uncomp_trunc", unc(b"xyzab")[..11].to_vec(), 10, None),
            ("uncomp_trunc_capsmall", unc(b"xyzab")[..11].to_vec(), 2, None),
            ("uncomp_zero", [unc(b""), blk(5, &a), end.to_vec()].concat(), 5, Some(b"abcde")),
            ("noend_short", blk(15, &c), 20, None),
            ("noend_full", blk(15, &c), 15, Some(b"wxyzzzzzzzzz123")),
            ("end_short", [blk(15, &c), end.to_vec()].concat(), 20, Some(b"wxyzzzzzzzzz123")),
            ("end_then_junk", [blk(15, &c), end.to_vec(), b"junk".to_vec()].concat(), 20, Some(b"wxyzzzzzzzzz123")),
            ("bad_magic", [blk(15, &c), b"bv4x".to_vec(), end.to_vec()].concat(), 20, None),
            ("bvx_magic", b"bvx-\x03\0\0\0xyzbvx$".to_vec(), 3, None),
            ("cap_mid", [blk(15, &c), end.to_vec()].concat(), 7, Some(b"wxyzzzz")),
            ("empty_block", [blk(0, b""), blk(5, &a), end.to_vec()].concat(), 5, Some(b"abcde")),
            ("only_end", end.to_vec(), 10, Some(b"")),
            ("hdr_trunc", b"bv41\0\0".to_vec(), 10, None),
            ("payload_trunc", blk(15, &c)[..blk(15, &c).len() - 2].to_vec(), 20, None),
            ("payload_trunc_capsmall", blk(10, &seq(b"abcdefghij", None))[..18].to_vec(), 2, None),
            ("magic_trunc_after_full", [blk(5, &a), b"bv".to_vec()].concat(), 5, Some(b"abcde")),
            ("magic_trunc", [blk(5, &a), b"bv".to_vec()].concat(), 10, None),
            ("full_then_off0", [blk(16, &[m.as_slice(), &seq(b"", Some((0, 4)))].concat()), end.to_vec()].concat(), 12, None),
            ("full_then_far", [blk(16, &[m.as_slice(), &seq(b"", Some((100, 4)))].concat()), end.to_vec()].concat(), 12, None),
            ("full_then_ok", [blk(16, &[m.as_slice(), &seq(b"", Some((3, 4)))].concat()), end.to_vec()].concat(), 12, Some(b"wxyzzzzzzzzz")),
            ("litfull_then_off0", [blk(9, &seq(b"abcde", Some((0, 4)))), end.to_vec()].concat(), 5, None),
            ("litfull_then_far", [blk(9, &seq(b"abcde", Some((9, 4)))), end.to_vec()].concat(), 5, None),
            ("litfull_trunc_dist", [blk(9, &[a.as_slice(), b"\0"].concat()), end.to_vec()].concat(), 5, None),
            ("litpartial", [blk(6, &seq(b"abcdef", None)), end.to_vec()].concat(), 5, Some(b"abcde")),
            ("full_then_badlit", [blk(16, &[m.as_slice(), b"\xf0\x05ab"].concat()), end.to_vec()].concat(), 12, None),
            ("full_block_then_garbage", [blk(12, &m), b"garbage!".to_vec()].concat(), 12, Some(b"wxyzzzzzzzzz")),
            ("matchpartial_then_bad", [blk(16, &[m.as_slice(), &seq(b"", Some((0, 4)))].concat()), end.to_vec()].concat(), 10, Some(b"wxyzzzzzzz")),
            ("full_then_off0_nextblock", [blk(12, &m), blk(4, &seq(b"", Some((0, 4)))), end.to_vec()].concat(), 12, Some(b"wxyzzzzzzzzz")),
            ("lit_trunc_cap_small", [blk(10, &seq(b"abcdefghij", None)[..4]), end.to_vec()].concat(), 2, None),
        ];
        for (name, s, cap, want) in cases {
            let mut dst = vec![0u8; cap];
            let got = lz4(&s, &mut dst).ok().map(|n| dst[..n].to_vec());
            // libcompression's 0 bytes is its failure.
            let got = got.filter(|g| !g.is_empty());
            let want = want.filter(|w| !w.is_empty()).map(<[u8]>::to_vec);
            assert_eq!(got, want, "{name}");
        }
        // Long literal and match lengths.
        let lit: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
        let s = [blk(600, &seq(&lit, Some((300, 300)))), end.to_vec()].concat();
        let mut dst = vec![0u8; 600];
        assert_eq!(lz4(&s, &mut dst), Ok(600));
        assert_eq!(&dst[..300], lit.as_slice());
        assert_eq!(&dst[300..], lit.as_slice());
    }

    fn hex(d: &[u8]) -> String {
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// An entry as `aa list -list-format json` prints it, whitespace
    /// left out.
    fn json(e: &Entry<'_>) -> String {
        let fields: Vec<String> = e
            .fields
            .iter()
            .map(|f| {
                let v = match &f.value {
                    Value::Flag => "true".to_string(),
                    Value::Uint(v) if &f.key == b"TYP" => format!("\"{}\"", *v as u8 as char),
                    Value::Uint(v) => v.to_string(),
                    Value::String(s) => format!("\"{}\"", String::from_utf8_lossy(&s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())])),
                    Value::Time { sec, nsec } => format!("{sec}.{:09}", nsec.unwrap_or(0)),
                    Value::Digest(d) if d.len() == 4 => u32::from_le_bytes([d[0], d[1], d[2], d[3]]).to_string(),
                    Value::Digest(d) => format!("\"{}\"", hex(d)),
                    Value::Blob(r) => (r.end - r.start).to_string(),
                };
                format!("\"{}\":{v}", String::from_utf8_lossy(&f.key))
            })
            .collect();
        format!("{{{}}}", fields.join(","))
    }

    /// Archives the host's `aa` made, beside its listing of each
    /// (GEX_TEST_AAR_DIR: `<name>.aar` or `<name>.aa` with `<name>.json`,
    /// `aa list -list-format json`; `raw.aar`, `aa archive -a raw` of the
    /// tree `src/`, which the other `.aar` archive with their algorithms;
    /// `lzma.aar`, `lzraven.aar` the algorithms not read).
    #[test]
    fn host_archives() {
        let Ok(dir) = std::env::var("GEX_TEST_AAR_DIR") else { return };
        let dir = std::path::Path::new(&dir);
        let raw = std::fs::read(dir.join("raw.aar")).unwrap();
        let mut listed = 0;
        for de in std::fs::read_dir(dir).unwrap() {
            let path = de.unwrap().path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext != "aar" && ext != "aa" {
                continue;
            }
            let name = path.file_stem().unwrap().to_str().unwrap().to_string();
            let src = std::fs::read(&path).unwrap();
            let decoded = archive_stream(&src);
            match name.as_str() {
                "lzma" | "lzraven" => {
                    assert!(decoded.unwrap_err().contains("not implemented"), "{name}");
                    continue;
                }
                _ => {}
            }
            let a = decoded.unwrap_or_else(|e| panic!("{name}: {e}"));
            if ["lzfse", "lzbitmap", "lz4", "lzfse4m", "zlib"].contains(&name.as_str()) {
                assert!(*a == *raw, "{name}: not the raw archive");
            }
            let es = entries(&a).unwrap_or_else(|e| panic!("{name}: {e}"));
            let Ok(want) = std::fs::read_to_string(dir.join(format!("{name}.json"))) else { continue };
            let want: String = want.chars().filter(|c| !c.is_whitespace()).collect();
            let got = format!("[{}]", es.iter().map(json).collect::<Vec<_>>().join(","));
            assert_eq!(got, want, "{name}");
            listed += 1;
            for e in &es {
                let Some(r) = e.data() else { continue };
                let d = &a[r];
                if let Some(Field { value: Value::Digest(h), .. }) = e.field(b"SH2") {
                    assert_eq!(sha2::Sha256::digest(d).as_slice(), *h, "{name}");
                }
                if let Some(Field { value: Value::Digest(h), .. }) = e.field(b"SH1") {
                    assert_eq!(sha1::Sha1::digest(d).as_slice(), *h, "{name}");
                }
                if let Some(siz) = e.uint(b"SIZ") {
                    assert_eq!(siz as usize, d.len(), "{name}");
                }
                if e.kind == b'F' && !name.starts_with("c_") {
                    let p = std::str::from_utf8(e.path.unwrap()).unwrap();
                    assert_eq!(std::fs::read(dir.join("src").join(p)).unwrap(), d, "{name}: {p}");
                    assert_eq!(file(&a, p).unwrap(), d);
                }
            }
        }
        assert!(listed > 0, "no listings in {}", dir.display());
    }

    /// The IPSW's `.dmg.mtree` (GEX_TEST_MTREE): its archive and the two
    /// files the restore reads, compared with what `aa extract` made.
    #[test]
    fn ipsw_mtree() {
        let Ok(path) = std::env::var("GEX_TEST_MTREE") else { return };
        let im4p = std::fs::read(path).unwrap();
        let (kind, data) = im4p_payload(&im4p).unwrap();
        assert_eq!(kind, b"msys");
        assert!(data.starts_with(b"pbze"));
        let t = std::time::Instant::now();
        let a = mtree_payload(&im4p).unwrap();
        let decoded = t.elapsed();
        assert_eq!(a.len(), 99_085_424);
        let es = entries(&a).unwrap();
        let summary: Vec<_> = es.iter().map(|e| (e.kind, e.path.unwrap(), e.data().map(|r| r.end - r.start))).collect();
        assert_eq!(summary, [(b'D', b"".as_slice(), None), (b'F', b"digest.db", Some(37_945_344)), (b'F', b"mtree.txt", Some(61_139_836))]);
        let sha = |p: &str| hex(&sha2::Sha256::digest(file(&a, p).unwrap()));
        assert_eq!(sha("digest.db"), "cbf2bc5a688a2c712b52ae50c854469d40f7c66abb4f8acd57b0ded842435e19");
        assert_eq!(sha("mtree.txt"), "2a59ded00e7ecb973eb293a35585cd824bb656affedc5a433ff4a6ff85326eb6");
        eprintln!("044-76040-038.dmg.mtree: decoded in {decoded:?}, read in {:?}", t.elapsed());
    }
}
