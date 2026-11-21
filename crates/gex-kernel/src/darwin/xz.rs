//! .xz streams (the .xz file format 1.0.4) of LZMA2 data, decoded as the
//! host's libcompression (macOS 27.0.1) decodes `COMPRESSION_LZMA` (0x306)
//! in `compression_decode_buffer`, the decoder of Apple Archive's pbz `x`
//! chunks. That call tries two decoders: libcompression's own
//! (`lzma_xz_buffer_decode`, [`fast`] here), and, when it gives no bytes,
//! liblzma 5.4.3's `lzma_stream_buffer_decode` with no memory limit and no
//! flags ([`strict`] here). A stream decodes if either takes it, to the
//! bytes of the first that does; the result is the bytes written, which
//! must all fit the destination.
//!
//! LZMA and LZMA2 are as the LZMA SDK and XZ Utils define them (both public
//! domain; the branch/call/jump filters are ported from liblzma 5.4.3's
//! `simple/*.c`, see NOTICE).
//!
//! # libcompression's decoder
//!
//! It takes one stream of LZMA2-only blocks and reads only what it needs:
//!
//! - The stream header: magic, CRC32, a first flags byte of 0 and a check
//!   type of none, CRC32, CRC64 or SHA-256 (any other is refused). The
//!   check fields are skipped unread.
//! - Each block header: its CRC32; flags with one filter and no reserved
//!   bits; the sizes, if present, read as variable-length integers and
//!   not used; the filter LZMA2 with one property byte of at most 40 (the
//!   dictionary size, not used either); its padding not read. The header
//!   must have a byte after it.
//! - The block's LZMA2 data ([`fast::lzma2`]), then the check field and
//!   the padding the data's length implies, unread.
//! - The index: its records read and not compared with the blocks, its
//!   padding not read, its CRC32 checked. The footer: its CRC32, flags
//!   equal to the header's, and "YZ"; its backward size not read. Bytes
//!   after the footer are not read.
//!
//! # liblzma
//!
//! liblzma decodes one stream and checks everything the format defines:
//! header and footer (magic, CRC32, reserved bits, equal flags, the
//! backward size the index takes), block headers (CRC32, reserved bits,
//! sizes when present against the block's, minimal variable-length
//! integers, filter chains of 1 to 4 filters ending in LZMA2, the
//! properties each takes, zero padding), the block's padding and its check
//! (CRC32, CRC64 and SHA-256 compared; the other types' fields skipped),
//! the index (one record per block, each the block's unpadded and
//! uncompressed sizes, zero padding, CRC32). Bytes after the footer are
//! not read. Filters before LZMA2 may be delta and the branch/call/jump
//! converters for x86, PowerPC, IA-64, ARM, ARM-Thumb, SPARC and ARM64.

use sha2::Digest;

/// Why neither decoder takes a stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the LZMA decoders refuse the stream: {}", self.0)
    }
}

/// `compression_decode_buffer(dst, dst.len(), src, src.len(), _,
/// COMPRESSION_LZMA)`: the bytes written, which may be 0.
pub fn decode_buffer(src: &[u8], dst: &mut [u8]) -> Result<usize, Error> {
    let first = match fast::decode(src, dst) {
        Ok(n) if n > 0 => return Ok(n),
        Ok(_) => "no bytes".to_string(),
        Err(e) => e,
    };
    strict::decode(src, dst).map_err(|e| Error(format!("libcompression's decoder: {first}; liblzma: {e}")))
}

const MAGIC: [u8; 6] = [0xfd, b'7', b'z', b'X', b'Z', 0];
const FOOTER_MAGIC: [u8; 2] = *b"YZ";
const LZMA2: u64 = 0x21;

fn crc32(b: &[u8]) -> u32 {
    let mut c = !0u32;
    for &x in b {
        c ^= u32::from(x);
        for _ in 0..8 {
            c = (c >> 1) ^ (0xedb8_8320 & (c & 1).wrapping_neg());
        }
    }
    !c
}

fn crc64(b: &[u8]) -> u64 {
    let mut c = !0u64;
    for &x in b {
        c ^= u64::from(x);
        for _ in 0..8 {
            c = (c >> 1) ^ (0xc96c_5795_d787_0f42 & (c & 1).wrapping_neg());
        }
    }
    !c
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

/// The size of a check field of type `id`.
fn check_size(id: u8) -> usize {
    match id {
        0 => 0,
        1..=3 => 4,
        4..=6 => 8,
        7..=9 => 16,
        10..=12 => 32,
        _ => 64,
    }
}

/// An LZMA2 dictionary property's size (40: 4 GiB less 1).
fn dict_size(p: u8) -> u64 {
    if p == 40 { u64::from(u32::MAX) } else { u64::from(2 | (p & 1)) << (p / 2 + 11) }
}

/// The LZMA decoder: its model and state, kept from chunk to chunk.
mod lzma {
    const STATES: usize = 12;
    const POS_STATES: usize = 16;
    const LIT: usize = 0x300;

    /// The probabilities of one length decoder.
    #[derive(Clone)]
    struct Len {
        choice: u16,
        choice2: u16,
        low: [[u16; 8]; POS_STATES],
        mid: [[u16; 8]; POS_STATES],
        high: [u16; 256],
    }

    impl Len {
        fn new() -> Len {
            Len { choice: 1024, choice2: 1024, low: [[1024; 8]; POS_STATES], mid: [[1024; 8]; POS_STATES], high: [1024; 256] }
        }
    }

    /// The range decoder over a chunk's input: past its end, either zeros
    /// (libcompression's decoder) or an error (liblzma's, whose input a
    /// chunk may not overrun).
    pub struct Rc<'a> {
        pub input: &'a [u8],
        pub pos: usize,
        pub zeros_past_end: bool,
        pub range: u32,
        pub code: u32,
    }

    impl Rc<'_> {
        fn byte(&mut self) -> Result<u8, String> {
            let b = match self.input.get(self.pos) {
                Some(&b) => b,
                None if self.zeros_past_end => 0,
                None => return Err("a chunk's LZMA data runs past its packed size".into()),
            };
            self.pos += 1;
            Ok(b)
        }

        /// The five initial bytes: the first 0.
        pub fn init(&mut self) -> Result<(), String> {
            let first = self.byte()?;
            self.code = 0;
            for _ in 0..4 {
                self.code = self.code << 8 | u32::from(self.byte()?);
            }
            self.range = u32::MAX;
            if first != 0 {
                return Err("an LZMA chunk's first byte is not 0".into());
            }
            Ok(())
        }

        pub fn normalize(&mut self) -> Result<(), String> {
            if self.range < 1 << 24 {
                self.range <<= 8;
                self.code = self.code << 8 | u32::from(self.byte()?);
            }
            Ok(())
        }

        fn bit(&mut self, p: &mut u16) -> Result<u32, String> {
            self.normalize()?;
            let bound = (self.range >> 11) * u32::from(*p);
            if self.code < bound {
                self.range = bound;
                *p += (2048 - *p) >> 5;
                Ok(0)
            } else {
                self.range -= bound;
                self.code -= bound;
                *p -= *p >> 5;
                Ok(1)
            }
        }

        fn tree(&mut self, p: &mut [u16], bits: u32) -> Result<u32, String> {
            let mut s = 1u32;
            for _ in 0..bits {
                s = s << 1 | self.bit(&mut p[s as usize])?;
            }
            Ok(s - (1 << bits))
        }

        /// A reverse bit tree: symbol s (from 1) at `p[off + s - 1]`.
        fn reverse(&mut self, p: &mut [u16], off: usize, bits: u32) -> Result<u32, String> {
            let (mut s, mut v) = (1u32, 0u32);
            for i in 0..bits {
                let b = self.bit(&mut p[off + s as usize - 1])?;
                s = s << 1 | b;
                v |= b << i;
            }
            Ok(v)
        }

        fn direct(&mut self, bits: u32) -> Result<u32, String> {
            let mut v = 0u32;
            for _ in 0..bits {
                self.normalize()?;
                self.range >>= 1;
                let b = u32::from(self.code >= self.range);
                if b == 1 {
                    self.code -= self.range;
                }
                v = v << 1 | b;
            }
            Ok(v)
        }
    }

    /// The model, state and distances (0-based) of an LZMA decoder.
    #[derive(Clone)]
    pub struct Decoder {
        lc: u32,
        lp: u32,
        pb: u32,
        state: usize,
        reps: [u32; 4],
        is_match: [[u16; POS_STATES]; STATES],
        is_rep: [u16; STATES],
        is_rep0: [u16; STATES],
        is_rep1: [u16; STATES],
        is_rep2: [u16; STATES],
        is_rep0_long: [[u16; POS_STATES]; STATES],
        dist_slot: [[u16; 64]; 4],
        dist_special: [u16; 114],
        align: [u16; 16],
        match_len: Box<Len>,
        rep_len: Box<Len>,
        literal: Vec<u16>,
    }

    /// Where a chunk's output goes: `out[at..end]`; positions count from
    /// `origin` (the start of the dictionary, whose last byte before any
    /// output reads as 0), and a distance must reach no further back than
    /// it or than `window` bytes.
    pub struct Span {
        pub origin: usize,
        pub at: usize,
        pub end: usize,
        pub window: u64,
    }

    impl Decoder {
        /// A model reset with properties `lc`, `lp`, `pb`.
        pub fn new(lc: u32, lp: u32, pb: u32) -> Decoder {
            Decoder {
                lc,
                lp,
                pb,
                state: 0,
                reps: [0; 4],
                is_match: [[1024; POS_STATES]; STATES],
                is_rep: [1024; STATES],
                is_rep0: [1024; STATES],
                is_rep1: [1024; STATES],
                is_rep2: [1024; STATES],
                is_rep0_long: [[1024; POS_STATES]; STATES],
                dist_slot: [[1024; 64]; 4],
                dist_special: [1024; 114],
                align: [1024; 16],
                match_len: Box::new(Len::new()),
                rep_len: Box::new(Len::new()),
                literal: vec![1024; LIT << (lc + lp)],
            }
        }

        fn len(rc: &mut Rc<'_>, l: &mut Len, ps: usize) -> Result<u32, String> {
            Ok(if rc.bit(&mut l.choice)? == 0 {
                2 + rc.tree(&mut l.low[ps], 3)?
            } else if rc.bit(&mut l.choice2)? == 0 {
                10 + rc.tree(&mut l.mid[ps], 3)?
            } else {
                18 + rc.tree(&mut l.high, 8)?
            })
        }

        /// Symbols into `out[s.at..s.end]` until it is full. A match that
        /// runs past its end, or reaches before what the span allows, is
        /// refused.
        pub fn run(&mut self, rc: &mut Rc<'_>, out: &mut [u8], s: &Span) -> Result<(), String> {
            let mut at = s.at;
            let pos_mask = (1usize << self.pb) - 1;
            let lit_mask = (1usize << self.lp) - 1;
            while at < s.end {
                let pos = at - s.origin;
                let ps = pos & pos_mask;
                let st = self.state;
                if rc.bit(&mut self.is_match[st][ps])? == 0 {
                    let prev = if at > s.origin { out[at - 1] } else { 0 };
                    let base = LIT * (((pos & lit_mask) << self.lc) + (usize::from(prev) >> (8 - self.lc)));
                    let p = &mut self.literal[base..base + LIT];
                    let mut sym = 1u32;
                    if st < 7 {
                        while sym < 0x100 {
                            sym = sym << 1 | rc.bit(&mut p[sym as usize])?;
                        }
                    } else {
                        let mut m = u32::from(out[at - self.reps[0] as usize - 1]);
                        let mut offset = 0x100u32;
                        while sym < 0x100 {
                            m <<= 1;
                            let mb = m & offset;
                            let b = rc.bit(&mut p[(offset + mb + sym) as usize])?;
                            sym = sym << 1 | b;
                            offset &= if b == 1 { mb } else { !mb };
                        }
                    }
                    out[at] = sym as u8;
                    at += 1;
                    self.state = if st < 4 { 0 } else if st < 10 { st - 3 } else { st - 6 };
                    continue;
                }
                let len;
                if rc.bit(&mut self.is_rep[st])? == 1 {
                    if at == s.origin {
                        return Err("a repeated match before any output".into());
                    }
                    if rc.bit(&mut self.is_rep0[st])? == 0 {
                        if rc.bit(&mut self.is_rep0_long[st][ps])? == 0 {
                            self.state = if st < 7 { 9 } else { 11 };
                            out[at] = out[at - self.reps[0] as usize - 1];
                            at += 1;
                            continue;
                        }
                    } else {
                        let d;
                        if rc.bit(&mut self.is_rep1[st])? == 0 {
                            d = self.reps[1];
                        } else {
                            if rc.bit(&mut self.is_rep2[st])? == 0 {
                                d = self.reps[2];
                            } else {
                                d = self.reps[3];
                                self.reps[3] = self.reps[2];
                            }
                            self.reps[2] = self.reps[1];
                        }
                        self.reps[1] = self.reps[0];
                        self.reps[0] = d;
                    }
                    self.state = if st < 7 { 8 } else { 11 };
                    len = Self::len(rc, &mut self.rep_len, ps)?;
                } else {
                    self.reps = [0, self.reps[0], self.reps[1], self.reps[2]];
                    self.state = if st < 7 { 7 } else { 10 };
                    len = Self::len(rc, &mut self.match_len, ps)?;
                    let slot = rc.tree(&mut self.dist_slot[(len as usize - 2).min(3)], 6)?;
                    let dist = if slot < 4 {
                        slot
                    } else {
                        let bits = (slot >> 1) - 1;
                        let base = (2 | (slot & 1)) << bits;
                        if slot < 14 {
                            base + rc.reverse(&mut self.dist_special, (base - slot) as usize, bits)?
                        } else {
                            let high = rc.direct(bits - 4)?;
                            base.wrapping_add(high << 4).wrapping_add(rc.reverse(&mut self.align, 1, 4)?)
                        }
                    };
                    self.reps[0] = dist;
                    let have = ((at - s.origin) as u64).min(s.window);
                    if u64::from(dist) >= have {
                        return Err(format!("a match distance of {} with {have} bytes behind it", u64::from(dist) + 1));
                    }
                }
                let len = len as usize;
                if len > s.end - at {
                    return Err("a match past the chunk's end".into());
                }
                let d = self.reps[0] as usize + 1;
                for i in at..at + len {
                    out[i] = out[i - d];
                }
                at += len;
            }
            Ok(())
        }
    }

    /// A range encoder, for hand-made streams.
    #[cfg(test)]
    struct RcEnc {
        low: u64,
        range: u32,
        cache: u8,
        cache_size: u64,
        out: Vec<u8>,
    }

    #[cfg(test)]
    impl RcEnc {
        fn shift_low(&mut self) {
            if (self.low as u32) < 0xff00_0000 || self.low >> 32 != 0 {
                let carry = (self.low >> 32) as u8;
                let mut t = self.cache;
                loop {
                    self.out.push(t.wrapping_add(carry));
                    t = 0xff;
                    self.cache_size -= 1;
                    if self.cache_size == 0 {
                        break;
                    }
                }
                self.cache = (self.low >> 24) as u8;
            }
            self.cache_size += 1;
            self.low = (self.low & 0x00ff_ffff) << 8;
        }

        fn normalize(&mut self) {
            while self.range < 1 << 24 {
                self.range <<= 8;
                self.shift_low();
            }
        }

        fn bit(&mut self, p: &mut u16, b: u32) {
            let bound = (self.range >> 11) * u32::from(*p);
            if b == 0 {
                self.range = bound;
                *p += (2048 - *p) >> 5;
            } else {
                self.low += u64::from(bound);
                self.range -= bound;
                *p -= *p >> 5;
            }
            self.normalize();
        }

        fn tree(&mut self, p: &mut [u16], bits: u32, v: u32) {
            let mut s = 1usize;
            for i in (0..bits).rev() {
                let b = (v >> i) & 1;
                self.bit(&mut p[s], b);
                s = s << 1 | b as usize;
            }
        }

        fn reverse(&mut self, p: &mut [u16], off: usize, bits: u32, v: u32) {
            let mut s = 1usize;
            for i in 0..bits {
                let b = (v >> i) & 1;
                self.bit(&mut p[off + s - 1], b);
                s = s << 1 | b as usize;
            }
        }

        fn direct(&mut self, bits: u32, v: u32) {
            for i in (0..bits).rev() {
                self.range >>= 1;
                if (v >> i) & 1 == 1 {
                    self.low += u64::from(self.range);
                }
                self.normalize();
            }
        }
    }

    /// An LZMA encoder of chosen symbols over the decoder's model, for
    /// hand-made streams.
    #[cfg(test)]
    pub struct Encoder {
        m: Decoder,
        rc: RcEnc,
        /// Positions count from the dictionary's start.
        pos: usize,
        history: Vec<u8>,
    }

    #[cfg(test)]
    impl Encoder {
        /// An encoder with properties `lc`, `lp`, `pb`, after `history`
        /// (the dictionary's bytes so far).
        pub fn new(lc: u32, lp: u32, pb: u32, history: &[u8]) -> Encoder {
            Encoder { m: Decoder::new(lc, lp, pb), rc: RcEnc { low: 0, range: u32::MAX, cache: 0, cache_size: 1, out: Vec::new() }, pos: history.len(), history: history.to_vec() }
        }

        fn ps(&self) -> usize {
            self.pos & ((1 << self.m.pb) - 1)
        }

        fn push(&mut self, b: u8) {
            self.history.push(b);
            self.pos += 1;
        }

        pub fn literal(&mut self, byte: u8) {
            let (st, ps) = (self.m.state, self.ps());
            self.rc.bit(&mut self.m.is_match[st][ps], 0);
            let prev = if self.pos > 0 { *self.history.last().unwrap() } else { 0 };
            let base = LIT * (((self.pos & ((1 << self.m.lp) - 1)) << self.m.lc) + (usize::from(prev) >> (8 - self.m.lc)));
            let p = &mut self.m.literal[base..base + LIT];
            let mut sym = 1u32;
            if st < 7 {
                for i in (0..8).rev() {
                    let b = u32::from(byte >> i) & 1;
                    self.rc.bit(&mut p[sym as usize], b);
                    sym = sym << 1 | b;
                }
            } else {
                let mut m = u32::from(self.history[self.history.len() - self.m.reps[0] as usize - 1]);
                let mut offset = 0x100u32;
                for i in (0..8).rev() {
                    let b = u32::from(byte >> i) & 1;
                    m <<= 1;
                    let mb = m & offset;
                    self.rc.bit(&mut p[(offset + mb + sym) as usize], b);
                    sym = sym << 1 | b;
                    offset &= if b == 1 { mb } else { !mb };
                }
            }
            self.m.state = if st < 4 { 0 } else if st < 10 { st - 3 } else { st - 6 };
            self.push(byte);
        }

        fn len(rc: &mut RcEnc, l: &mut Len, ps: usize, len: u32) {
            if len < 10 {
                rc.bit(&mut l.choice, 0);
                rc.tree(&mut l.low[ps], 3, len - 2);
            } else if len < 18 {
                rc.bit(&mut l.choice, 1);
                rc.bit(&mut l.choice2, 0);
                rc.tree(&mut l.mid[ps], 3, len - 10);
            } else {
                rc.bit(&mut l.choice, 1);
                rc.bit(&mut l.choice2, 1);
                rc.tree(&mut l.high, 8, len - 18);
            }
        }

        /// A match of `len` (2-273) bytes `dist` (0-based) back.
        pub fn matched(&mut self, dist: u32, len: u32) {
            let (st, ps) = (self.m.state, self.ps());
            self.rc.bit(&mut self.m.is_match[st][ps], 1);
            self.rc.bit(&mut self.m.is_rep[st], 0);
            self.m.reps = [dist, self.m.reps[0], self.m.reps[1], self.m.reps[2]];
            self.m.state = if st < 7 { 7 } else { 10 };
            Self::len(&mut self.rc, &mut self.m.match_len, ps, len);
            let slot = if dist < 4 {
                dist
            } else {
                let n = 32 - dist.leading_zeros();
                2 * (n - 1) + ((dist >> (n - 2)) & 1)
            };
            self.rc.tree(&mut self.m.dist_slot[(len as usize - 2).min(3)], 6, slot);
            if slot >= 4 {
                let bits = (slot >> 1) - 1;
                let base = (2 | (slot & 1)) << bits;
                let rem = dist - base;
                if slot < 14 {
                    self.rc.reverse(&mut self.m.dist_special, (base - slot) as usize, bits, rem);
                } else {
                    self.rc.direct(bits - 4, rem >> 4);
                    self.rc.reverse(&mut self.m.align, 1, 4, rem & 15);
                }
            }
            self.copy(dist, len);
        }

        /// A match of one byte at the last distance.
        pub fn shortrep(&mut self) {
            let (st, ps) = (self.m.state, self.ps());
            self.rc.bit(&mut self.m.is_match[st][ps], 1);
            self.rc.bit(&mut self.m.is_rep[st], 1);
            self.rc.bit(&mut self.m.is_rep0[st], 0);
            self.rc.bit(&mut self.m.is_rep0_long[st][ps], 0);
            self.m.state = if st < 7 { 9 } else { 11 };
            self.copy(self.m.reps[0], 1);
        }

        fn copy(&mut self, dist: u32, len: u32) {
            for _ in 0..len {
                let b = self.history.get(self.history.len().wrapping_sub(dist as usize + 1)).copied().unwrap_or(0);
                self.push(b);
            }
        }

        /// The range coder's bytes, flushed.
        pub fn finish(mut self) -> Vec<u8> {
            for _ in 0..5 {
                self.rc.shift_low();
            }
            self.rc.out
        }
    }

    /// lc, lp, pb from a properties byte, unless lc + lp > 4 or it is past
    /// 224.
    pub fn props(p: u8) -> Option<(u32, u32, u32)> {
        if p > 224 {
            return None;
        }
        let p = u32::from(p);
        let (lc, lp, pb) = (p % 9, p / 9 % 5, p / 45);
        if lc + lp > 4 { None } else { Some((lc, lp, pb)) }
    }
}

/// libcompression's own decoder (`lzma_xz_buffer_decode`).
pub mod fast {
    use super::lzma::{props, Decoder, Rc, Span};
    use super::*;

    /// `xz_read_multi_byte`: a variable-length integer from `b[*at..]`,
    /// ending before `limit`, of at most 9 bytes, none after the first 0.
    fn vli(b: &[u8], limit: usize, at: &mut usize) -> Result<u64, String> {
        let limit = limit.min(b.len());
        if *at >= limit {
            return Err("a variable-length integer past its field".into());
        }
        let end = (*at + 9).min(limit);
        let mut v = u64::from(b[*at] & 0x7f);
        let mut p = *at + 1;
        let mut shift = 7;
        if b[*at] & 0x80 != 0 {
            loop {
                if p == end {
                    return Err("a variable-length integer too long".into());
                }
                let x = b[p];
                if x == 0 {
                    return Err("a variable-length integer ending in 0".into());
                }
                v |= u64::from(x & 0x7f) << shift;
                p += 1;
                if x & 0x80 == 0 {
                    break;
                }
                shift += 7;
            }
        }
        *at = p;
        Ok(v)
    }

    /// The stream into `dst`: the bytes written.
    pub fn decode(src: &[u8], dst: &mut [u8]) -> Result<usize, String> {
        if src.len() < 12 {
            return Err("a stream under 12 bytes".into());
        }
        if src[..6] != MAGIC || le32(src, 8) != crc32(&src[6..8]) || src[6] != 0 {
            return Err("a stream header it does not take".into());
        }
        let check = match src[7] {
            0 => 0,
            1 => 4,
            4 => 8,
            10 => 32,
            c => return Err(format!("check type {c}")),
        };
        if src.len() < 13 {
            return Err("a stream with no block or index".into());
        }
        let mut pos = 12usize;
        let mut out = 0usize;
        loop {
            let b = src[pos];
            if b == 0 {
                break;
            }
            let hs = usize::from(b) * 4 + 4;
            let limit = pos + 1 + hs;
            if limit > src.len() {
                return Err("a block header past the stream".into());
            }
            if le32(src, pos + hs - 4) != crc32(&src[pos..pos + hs - 4]) {
                return Err("a block header's CRC32".into());
            }
            let flags = src[pos + 1];
            if flags & 0x3f != 0 {
                return Err("a block of more than one filter, or reserved flags".into());
            }
            let mut at = pos + 2;
            if flags & 0x40 != 0 {
                vli(src, limit, &mut at)?;
            }
            if flags & 0x80 != 0 {
                vli(src, limit, &mut at)?;
            }
            let id = vli(src, limit, &mut at)?;
            let size = vli(src, limit, &mut at)?;
            if id != LZMA2 || size != 1 || at >= limit || src[at] > 40 {
                return Err("a filter other than LZMA2 with one property byte of at most 40".into());
            }
            let data = pos + hs;
            let (n, used) = lzma2(&src[data..], &mut dst[out..])?;
            if n == 0 || used == 0 {
                return Err("a block of no bytes".into());
            }
            out += n;
            pos = data + check + ((used + 3) & !3);
            if pos >= src.len() {
                return Err("the stream ends before its index".into());
            }
        }
        // The index.
        let mut at = pos + 1;
        let count = vli(src, src.len(), &mut at)?;
        for _ in 0..count {
            vli(src, src.len(), &mut at)?;
            vli(src, src.len(), &mut at)?;
        }
        let len = (at - pos + 3) & !3;
        if pos + len + 4 > src.len() || le32(src, pos + len) != crc32(&src[pos..pos + len]) {
            return Err("the index's CRC32".into());
        }
        let f = pos + len + 4;
        if f + 12 > src.len() || src[f + 8..f + 10] != src[6..8] || src[f + 10..f + 12] != FOOTER_MAGIC || le32(src, f) != crc32(&src[f + 4..f + 10]) {
            return Err("a stream footer it does not take".into());
        }
        Ok(out)
    }

    /// `lzma2_block_decode`: a block's LZMA2 data from the start of `src`
    /// into `dst`; the bytes written and the data's length (through its
    /// end marker). An LZMA chunk's packed size only places the next
    /// chunk: its range decoder reads on into what follows, and past the
    /// stream's end reads zeros. No chunk need reset the dictionary, which
    /// is the block's output; the first LZMA chunk must reset the state
    /// (else there is no model), with properties of its own or 0, 0, 0.
    pub fn lzma2(src: &[u8], dst: &mut [u8]) -> Result<(usize, usize), String> {
        if src.is_empty() {
            return Err("no LZMA2 data".into());
        }
        let (mut lc, mut lp, mut pb) = (0, 0, 0);
        let mut model: Option<Decoder> = None;
        let (mut pos, mut out) = (0usize, 0usize);
        while pos < src.len() {
            let control = src[pos];
            if control < 0x80 {
                if control == 0 {
                    return Ok((out, pos + 1));
                }
                if control > 2 || pos + 3 > src.len() {
                    return Err(format!("LZMA2 control byte {control:#x}"));
                }
                let n = (usize::from(src[pos + 1]) << 8 | usize::from(src[pos + 2])) + 1;
                let end = pos + 3 + n;
                if end > src.len() || out + n > dst.len() {
                    return Err("an uncompressed chunk past the stream or the destination".into());
                }
                dst[out..out + n].copy_from_slice(&src[pos + 3..end]);
                out += n;
                pos = end;
                continue;
            }
            if pos + 5 > src.len() {
                return Err("an LZMA chunk's header past the stream".into());
            }
            let mut data = pos + 5;
            let reset = control >> 5 & 3;
            if reset >= 2 {
                let Some(&p) = src.get(data) else { return Err("an LZMA chunk's properties past the stream".into()) };
                (lc, lp, pb) = props(p).ok_or_else(|| format!("LZMA properties {p:#x}"))?;
                data += 1;
            }
            if reset >= 1 {
                model = Some(Decoder::new(lc, lp, pb));
            }
            let unpacked = (usize::from(control & 0x1f) << 16 | usize::from(src[pos + 1]) << 8 | usize::from(src[pos + 2])) + 1;
            let packed = (usize::from(src[pos + 3]) << 8 | usize::from(src[pos + 4])) + 1;
            let next = data + packed;
            if next > src.len() || out + unpacked > dst.len() {
                return Err("an LZMA chunk past the stream or the destination".into());
            }
            let Some(m) = model.as_mut() else { return Err("an LZMA chunk with no model".into()) };
            let mut rc = Rc { input: &src[data..], pos: 0, zeros_past_end: true, range: 0, code: 0 };
            rc.init()?;
            if rc.code == u32::MAX {
                return Err("an LZMA chunk whose initial code is all ones".into());
            }
            m.run(&mut rc, dst, &Span { origin: 0, at: out, end: out + unpacked, window: u64::MAX })?;
            if rc.code != 0 {
                return Err("an LZMA chunk that ends with its range decoder's code not 0".into());
            }
            out += unpacked;
            pos = next;
        }
        Err("LZMA2 data with no end marker".into())
    }
}

/// liblzma 5.4.3's `lzma_stream_buffer_decode`.
pub mod strict {
    use super::lzma::{props, Decoder, Rc, Span};
    use super::*;

    /// The largest value a variable-length integer holds, and the largest
    /// unpadded size (`LZMA_VLI_MAX`, `UNPADDED_SIZE_MAX`).
    const VLI_MAX: u64 = u64::MAX / 2;
    const UNPADDED_MAX: u64 = VLI_MAX & !3;
    const UNPADDED_MIN: u64 = 5;

    /// `lzma_vli_decode` on a buffer: at most 9 bytes, the last not 0
    /// unless it is the only one.
    fn vli(b: &[u8], at: &mut usize) -> Result<u64, String> {
        let mut v = 0u64;
        for i in 0..9 {
            let Some(&x) = b.get(*at) else { return Err("a variable-length integer cut short".into()) };
            *at += 1;
            v |= u64::from(x & 0x7f) << (7 * i);
            if x & 0x80 == 0 {
                if x == 0 && i > 0 {
                    return Err("a variable-length integer ending in 0".into());
                }
                return Ok(v);
            }
        }
        Err("a variable-length integer too long".into())
    }

    fn vli_len(v: u64) -> usize {
        let mut n = 1;
        let mut v = v >> 7;
        while v != 0 {
            n += 1;
            v >>= 7;
        }
        n
    }

    /// A filter of a block's chain.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Filter {
        Delta(usize),
        X86(u32),
        PowerPc(u32),
        Ia64(u32),
        Arm(u32),
        ArmThumb(u32),
        Sparc(u32),
        Arm64(u32),
        Lzma2(u8),
    }

    /// `lzma_filter_flags_decode` and the filter's properties decoder.
    fn filter(h: &[u8], at: &mut usize) -> Result<Filter, String> {
        let id = vli(h, at)?;
        if id >= 1 << 62 {
            return Err(format!("filter ID {id:#x}"));
        }
        let size = vli(h, at)?;
        if size > (h.len() - *at) as u64 {
            return Err("filter properties past the block header".into());
        }
        let p = &h[*at..*at + size as usize];
        *at += size as usize;
        // A converter's start offset, a multiple of its alignment
        // (`lzma_simple_coder_init`).
        let start = |align: u32| -> Result<u32, String> {
            let s = match p.len() {
                0 => 0,
                4 => le32(p, 0),
                _ => return Err("branch filter properties of other than 0 or 4 bytes".into()),
            };
            if s & (align - 1) != 0 {
                return Err(format!("a start offset of {s:#x}, not a multiple of {align}"));
            }
            Ok(s)
        };
        Ok(match id {
            0x03 => match p {
                [d] => Filter::Delta(usize::from(*d) + 1),
                _ => return Err("delta properties of other than 1 byte".into()),
            },
            0x04 => Filter::X86(start(1)?),
            0x05 => Filter::PowerPc(start(4)?),
            0x06 => Filter::Ia64(start(16)?),
            0x07 => Filter::Arm(start(4)?),
            0x08 => Filter::ArmThumb(start(2)?),
            0x09 => Filter::Sparc(start(4)?),
            0x0a => Filter::Arm64(start(4)?),
            LZMA2 => match p {
                [d] if *d <= 40 => Filter::Lzma2(*d),
                _ => return Err("LZMA2 properties not one byte of at most 40".into()),
            },
            _ => return Err(format!("filter ID {id:#x}")),
        })
    }

    /// The stream into `dst`: the bytes written.
    pub fn decode(src: &[u8], dst: &mut [u8]) -> Result<usize, String> {
        let header = src.get(..12).ok_or("the stream ends in its header")?;
        if header[..6] != MAGIC {
            return Err("no stream magic".into());
        }
        if le32(header, 8) != crc32(&header[6..8]) {
            return Err("the stream header's CRC32".into());
        }
        if header[6] != 0 || header[7] & 0xf0 != 0 {
            return Err("reserved stream flags".into());
        }
        let check = header[7];
        let mut pos = 12usize;
        let mut out = 0usize;
        let mut records: Vec<(u64, u64)> = Vec::new();
        loop {
            let &b = src.get(pos).ok_or("the stream ends before its index")?;
            if b == 0 {
                break;
            }
            let hs = (usize::from(b) + 1) * 4;
            let h = src.get(pos..pos + hs).ok_or("the stream ends in a block header")?;
            let (h, crc) = h.split_at(hs - 4);
            if crc32(h) != le32(crc, 0) {
                return Err("a block header's CRC32".into());
            }
            if h[1] & 0x3c != 0 {
                return Err("reserved block flags".into());
            }
            let mut at = 2;
            let csize = if h[1] & 0x40 != 0 {
                let c = vli(h, &mut at)?;
                if c == 0 || (hs as u64).checked_add(c).and_then(|v| v.checked_add(check_size(check) as u64)).is_none_or(|u| u > UNPADDED_MAX) {
                    return Err("a block's compressed size".into());
                }
                Some(c)
            } else {
                None
            };
            let usize_ = if h[1] & 0x80 != 0 { Some(vli(h, &mut at)?) } else { None };
            let mut chain = Vec::new();
            for _ in 0..=(h[1] & 3) {
                chain.push(filter(h, &mut at)?);
            }
            if h[at..].iter().any(|&x| x != 0) {
                return Err("a block header's padding".into());
            }
            // `validate_chain`: LZMA2 last and only last.
            let last = chain.len() - 1;
            if chain.iter().enumerate().any(|(i, f)| matches!(f, Filter::Lzma2(_)) != (i == last)) {
                return Err("a filter chain not ending in LZMA2 alone".into());
            }
            let Filter::Lzma2(dict) = chain[last] else { unreachable!() };
            let data = pos + hs;
            let (n, used) = lzma2(&src[data..], &mut dst[out..], dict_size(dict))?;
            if csize.is_some_and(|c| c != used as u64) || usize_.is_some_and(|u| u != n as u64) {
                return Err("a block's sizes against its header".into());
            }
            let block = &mut dst[out..out + n];
            for f in chain[..last].iter().rev() {
                unfilter(*f, block);
            }
            let mut end = data + used;
            while (end - data) % 4 != 0 {
                match src.get(end) {
                    Some(0) => end += 1,
                    Some(_) => return Err("a block's padding".into()),
                    None => return Err("the stream ends in a block's padding".into()),
                }
            }
            let cs = check_size(check);
            let field = src.get(end..end + cs).ok_or("the stream ends in a block's check")?;
            let ok = match check {
                1 => field == crc32(block).to_le_bytes(),
                4 => field == crc64(block).to_le_bytes(),
                10 => field == sha2::Sha256::digest(&*block).as_slice(),
                _ => true,
            };
            if !ok {
                return Err("a block's check".into());
            }
            records.push(((hs + used + cs) as u64, n as u64));
            out += n;
            pos = end + cs;
        }
        // The index (`lzma_index_hash_decode`).
        let start = pos;
        let mut at = pos + 1;
        let count = vli(src, &mut at)?;
        if count != records.len() as u64 {
            return Err("the index's record count".into());
        }
        let mut list = 0usize;
        for &(unpadded, uncompressed) in &records {
            let u = vli(src, &mut at)?;
            if !(UNPADDED_MIN..=UNPADDED_MAX).contains(&u) {
                return Err("an index record's unpadded size".into());
            }
            let n = vli(src, &mut at)?;
            if (u, n) != (unpadded, uncompressed) {
                return Err("an index record not its block's".into());
            }
            list += vli_len(u) + vli_len(n);
        }
        let unpadded = 1 + vli_len(count) + list;
        while (at - start) % 4 != 0 {
            match src.get(at) {
                Some(0) => at += 1,
                Some(_) => return Err("the index's padding".into()),
                None => return Err("the stream ends in its index".into()),
            }
        }
        debug_assert_eq!(at - start, (unpadded + 3) & !3);
        let crc = src.get(at..at + 4).ok_or("the stream ends in its index")?;
        if le32(crc, 0) != crc32(&src[start..at]) {
            return Err("the index's CRC32".into());
        }
        let index_size = at + 4 - start;
        let f = src.get(at + 4..at + 16).ok_or("the stream ends in its footer")?;
        if f[10..] != FOOTER_MAGIC {
            return Err("no footer magic".into());
        }
        if le32(f, 0) != crc32(&f[4..10]) {
            return Err("the footer's CRC32".into());
        }
        if f[8] != 0 || f[9] & 0xf0 != 0 {
            return Err("reserved footer flags".into());
        }
        if (u64::from(le32(f, 4)) + 1) * 4 != index_size as u64 {
            return Err("the footer's backward size".into());
        }
        if f[9] != check {
            return Err("footer flags unlike the header's".into());
        }
        Ok(out)
    }

    /// `lzma2_decode`: a block's LZMA2 data from the start of `src` into
    /// `dst` with a dictionary of `dict` bytes; the bytes written and the
    /// data's length (through its end marker).
    fn lzma2(src: &[u8], dst: &mut [u8], dict: u64) -> Result<(usize, usize), String> {
        // `lzma_lz_decoder_init`: at least 4096 bytes, a multiple of 16.
        let window = (dict.max(4096) + 15) & !15;
        let (mut need_dict_reset, mut need_props) = (true, true);
        let mut origin = 0usize;
        let mut options = (0, 0, 0);
        let mut model: Option<Decoder> = None;
        let (mut pos, mut out) = (0usize, 0usize);
        loop {
            let &control = src.get(pos).ok_or("LZMA2 data with no end marker")?;
            pos += 1;
            if control == 0 {
                return Ok((out, pos));
            }
            if control >= 0xe0 || control == 1 {
                need_props = true;
                need_dict_reset = false;
                origin = out;
            } else if need_dict_reset {
                return Err("LZMA2 data that does not start with a dictionary reset".into());
            }
            let header = |at: usize, n: usize| src.get(at..at + n).ok_or("an LZMA2 chunk header past the stream");
            if control < 0x80 {
                if control > 2 {
                    return Err(format!("LZMA2 control byte {control:#x}"));
                }
                let h = header(pos, 2)?;
                let n = (usize::from(h[0]) << 8 | usize::from(h[1])) + 1;
                pos += 2;
                let data = src.get(pos..pos + n).ok_or("an uncompressed chunk past the stream")?;
                if out + n > dst.len() {
                    return Err("output past the destination".into());
                }
                dst[out..out + n].copy_from_slice(data);
                out += n;
                pos += n;
                continue;
            }
            let h = header(pos, 4)?;
            let unpacked = (usize::from(control & 0x1f) << 16 | usize::from(h[0]) << 8 | usize::from(h[1])) + 1;
            let packed = (usize::from(h[2]) << 8 | usize::from(h[3])) + 1;
            pos += 4;
            if control >= 0xc0 {
                let &p = src.get(pos).ok_or("LZMA properties past the stream")?;
                pos += 1;
                options = props(p).ok_or_else(|| format!("LZMA properties {p:#x}"))?;
                need_props = false;
                model = Some(Decoder::new(options.0, options.1, options.2));
            } else if need_props {
                return Err("an LZMA chunk without the properties a dictionary reset needs".into());
            } else if control >= 0xa0 {
                model = Some(Decoder::new(options.0, options.1, options.2));
            }
            let input = src.get(pos..pos + packed).unwrap_or(&src[pos.min(src.len())..]);
            if out + unpacked > dst.len() {
                return Err("output past the destination".into());
            }
            let m = model.as_mut().expect("properties precede every LZMA chunk");
            let mut rc = Rc { input, pos: 0, zeros_past_end: false, range: 0, code: 0 };
            rc.init()?;
            m.run(&mut rc, dst, &Span { origin, at: out, end: out + unpacked, window })?;
            // At the chunk's end: one more byte if the range needs it, and
            // the code 0 (`rc_is_finished`).
            rc.normalize()?;
            if rc.code != 0 {
                return Err("an LZMA chunk that ends with its range decoder's code not 0".into());
            }
            if rc.pos != packed {
                return Err("an LZMA chunk shorter than its packed size".into());
            }
            out += unpacked;
            pos += packed;
        }
    }

    /// A filter's decoding of a block's output, whole (as liblzma runs it
    /// when the block decodes in one call: the bytes a converter cannot
    /// look at, at the end, are left as they are).
    fn unfilter(f: Filter, b: &mut [u8]) {
        match f {
            Filter::Delta(d) => {
                for i in d..b.len() {
                    b[i] = b[i].wrapping_add(b[i - d]);
                }
            }
            Filter::X86(p) => x86(b, p),
            Filter::PowerPc(p) => {
                let mut i = 0;
                while i + 4 <= b.len() {
                    if b[i] >> 2 == 0x12 && b[i + 3] & 3 == 1 {
                        let src = (u32::from(b[i]) & 3) << 24 | u32::from(b[i + 1]) << 16 | u32::from(b[i + 2]) << 8 | (u32::from(b[i + 3]) & !3);
                        let dest = src.wrapping_sub(p.wrapping_add(i as u32));
                        b[i] = 0x48 | ((dest >> 24) & 3) as u8;
                        b[i + 1] = (dest >> 16) as u8;
                        b[i + 2] = (dest >> 8) as u8;
                        b[i + 3] = (b[i + 3] & 3) | dest as u8;
                    }
                    i += 4;
                }
            }
            Filter::Ia64(p) => ia64(b, p),
            Filter::Arm(p) => {
                let mut i = 0;
                while i + 4 <= b.len() {
                    if b[i + 3] == 0xeb {
                        let src = (u32::from(b[i + 2]) << 16 | u32::from(b[i + 1]) << 8 | u32::from(b[i])) << 2;
                        let dest = src.wrapping_sub(p.wrapping_add(i as u32).wrapping_add(8)) >> 2;
                        b[i + 2] = (dest >> 16) as u8;
                        b[i + 1] = (dest >> 8) as u8;
                        b[i] = dest as u8;
                    }
                    i += 4;
                }
            }
            Filter::ArmThumb(p) => {
                let mut i = 0;
                while i + 4 <= b.len() {
                    if b[i + 1] & 0xf8 == 0xf0 && b[i + 3] & 0xf8 == 0xf8 {
                        let src = ((u32::from(b[i + 1]) & 7) << 19 | u32::from(b[i]) << 11 | (u32::from(b[i + 3]) & 7) << 8 | u32::from(b[i + 2])) << 1;
                        let dest = src.wrapping_sub(p.wrapping_add(i as u32).wrapping_add(4)) >> 1;
                        b[i + 1] = 0xf0 | ((dest >> 19) & 7) as u8;
                        b[i] = (dest >> 11) as u8;
                        b[i + 3] = 0xf8 | ((dest >> 8) & 7) as u8;
                        b[i + 2] = dest as u8;
                        i += 2;
                    }
                    i += 2;
                }
            }
            Filter::Sparc(p) => {
                let mut i = 0;
                while i + 4 <= b.len() {
                    if (b[i] == 0x40 && b[i + 1] & 0xc0 == 0) || (b[i] == 0x7f && b[i + 1] & 0xc0 == 0xc0) {
                        let src = u32::from_be_bytes(b[i..i + 4].try_into().unwrap()) << 2;
                        let mut dest = src.wrapping_sub(p.wrapping_add(i as u32)) >> 2;
                        dest = ((0u32.wrapping_sub((dest >> 22) & 1) << 22) & 0x3fff_ffff) | (dest & 0x3f_ffff) | 0x4000_0000;
                        b[i..i + 4].copy_from_slice(&dest.to_be_bytes());
                    }
                    i += 4;
                }
            }
            Filter::Arm64(p) => {
                let mut i = 0;
                while i + 4 <= b.len() {
                    let pc = p.wrapping_add(i as u32);
                    let mut instr = le32(b, i);
                    if instr >> 26 == 0x25 {
                        let src = instr;
                        instr = 0x9400_0000 | (src.wrapping_add(0u32.wrapping_sub(pc >> 2)) & 0x03ff_ffff);
                        b[i..i + 4].copy_from_slice(&instr.to_le_bytes());
                    } else if instr & 0x9f00_0000 == 0x9000_0000 {
                        let src = ((instr >> 29) & 3) | ((instr >> 3) & 0x001f_fffc);
                        if src.wrapping_add(0x0002_0000) & 0x001c_0000 == 0 {
                            instr &= 0x9000_001f;
                            let dest = src.wrapping_add(0u32.wrapping_sub(pc >> 12));
                            instr |= (dest & 3) << 29;
                            instr |= (dest & 0x0003_fffc) << 3;
                            instr |= 0u32.wrapping_sub(dest & 0x0002_0000) & 0x00e0_0000;
                            b[i..i + 4].copy_from_slice(&instr.to_le_bytes());
                        }
                    }
                    i += 4;
                }
            }
            Filter::Lzma2(_) => unreachable!(),
        }
    }

    /// The x86 converter (`x86_code`), decoding.
    fn x86(b: &mut [u8], now: u32) {
        const ALLOWED: [bool; 8] = [true, true, true, false, true, false, false, false];
        const BIT: [u32; 8] = [0, 1, 2, 2, 3, 3, 3, 3];
        let ms_byte = |x: u8| x == 0 || x == 0xff;
        if b.len() < 5 {
            return;
        }
        let mut prev_mask = 0u32;
        let mut prev_pos = now.wrapping_sub(5);
        let limit = b.len() - 5;
        let mut i = 0usize;
        while i <= limit {
            let x = b[i];
            if x != 0xe8 && x != 0xe9 {
                i += 1;
                continue;
            }
            let here = now.wrapping_add(i as u32);
            let offset = here.wrapping_sub(prev_pos);
            prev_pos = here;
            if offset > 5 {
                prev_mask = 0;
            } else {
                for _ in 0..offset {
                    prev_mask &= 0x77;
                    prev_mask <<= 1;
                }
            }
            let x4 = b[i + 4];
            if ms_byte(x4) && ALLOWED[((prev_mask >> 1) & 7) as usize] && (prev_mask >> 1) < 0x10 {
                let mut src = u32::from_le_bytes(b[i + 1..i + 5].try_into().unwrap());
                let mut dest;
                loop {
                    dest = src.wrapping_sub(here.wrapping_add(5));
                    if prev_mask == 0 {
                        break;
                    }
                    let k = BIT[(prev_mask >> 1) as usize];
                    let t = (dest >> (24 - k * 8)) as u8;
                    if !ms_byte(t) {
                        break;
                    }
                    src = dest ^ ((1u32 << (32 - k * 8)) - 1);
                }
                b[i + 4] = !(((dest >> 24) & 1).wrapping_sub(1)) as u8;
                b[i + 1..i + 4].copy_from_slice(&dest.to_le_bytes()[..3]);
                i += 5;
                prev_mask = 0;
            } else {
                i += 1;
                prev_mask |= 1;
                if ms_byte(x4) {
                    prev_mask |= 0x10;
                }
            }
        }
    }

    /// The IA-64 converter (`ia64_code`), decoding.
    fn ia64(b: &mut [u8], now: u32) {
        const BRANCH: [u32; 32] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0];
        let mut i = 0usize;
        while i + 16 <= b.len() {
            let mask = BRANCH[usize::from(b[i] & 0x1f)];
            let mut bit_pos = 5u32;
            for slot in 0..3 {
                if (mask >> slot) & 1 != 0 {
                    let byte_pos = (bit_pos >> 3) as usize;
                    let bit_res = bit_pos & 7;
                    let mut instr = 0u64;
                    for j in 0..6 {
                        instr |= u64::from(b[i + j + byte_pos]) << (8 * j);
                    }
                    let mut norm = instr >> bit_res;
                    if (norm >> 37) & 0xf == 5 && (norm >> 9) & 7 == 0 {
                        let mut src = ((norm >> 13) & 0xf_ffff) as u32;
                        src |= (((norm >> 36) & 1) as u32) << 20;
                        src <<= 4;
                        let dest = src.wrapping_sub(now.wrapping_add(i as u32)) >> 4;
                        norm &= !(0x8f_ffffu64 << 13);
                        norm |= u64::from(dest & 0xf_ffff) << 13;
                        norm |= u64::from(dest & 0x10_0000) << (36 - 20);
                        instr &= (1u64 << bit_res) - 1;
                        instr |= norm << bit_res;
                        for j in 0..6 {
                            b[i + j + byte_pos] = (instr >> (8 * j)) as u8;
                        }
                    }
                }
                bit_pos += 41;
            }
            i += 16;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Results files beside a cases file: each the u64 a call returned and
    /// the bytes it wrote.
    fn results(path: &std::path::Path) -> Vec<Vec<u8>> {
        let b = std::fs::read(path).unwrap();
        let mut v = Vec::new();
        let mut at = 0;
        while at < b.len() {
            let n = u64::from_le_bytes(b[at..at + 8].try_into().unwrap()) as usize;
            v.push(b[at + 8..at + 8 + n].to_vec());
            at += 8 + n;
        }
        v
    }

    /// An LZMA2 LZMA chunk: `reset` (0 none, 1 state, 2 properties, 3
    /// dictionary), the bytes it expands to, the properties byte when
    /// `reset` is 2 or 3, the range coder's bytes.
    fn lzma_chunk(reset: u8, unpacked: usize, props: u8, data: &[u8]) -> Vec<u8> {
        let (u, p) = (unpacked - 1, data.len() - 1);
        let mut c = vec![0x80 | reset << 5 | (u >> 16) as u8, (u >> 8) as u8, u as u8, (p >> 8) as u8, p as u8];
        if reset >= 2 {
            c.push(props);
        }
        c.extend_from_slice(data);
        c
    }

    /// An LZMA2 uncompressed chunk, resetting the dictionary or not.
    fn stored_chunk(reset: bool, data: &[u8]) -> Vec<u8> {
        let n = data.len() - 1;
        let mut c = vec![if reset { 1 } else { 2 }, (n >> 8) as u8, n as u8];
        c.extend_from_slice(data);
        c
    }

    fn vli(mut v: u64) -> Vec<u8> {
        let mut b = Vec::new();
        while v >= 0x80 {
            b.push(v as u8 | 0x80);
            v >>= 7;
        }
        b.push(v as u8);
        b
    }

    /// A block: its filters before LZMA2, its LZMA2 data (end marker
    /// added) and dictionary property, what it expands to, and what to
    /// write in its header and check field instead of the truth.
    #[derive(Clone, Default)]
    struct Block {
        filters: Vec<(u64, Vec<u8>)>,
        lzma2: Vec<u8>,
        dict: u8,
        out: Vec<u8>,
        sizes: Option<(u64, u64)>,
        check: Option<Vec<u8>>,
        record: Option<(u64, u64)>,
    }

    /// A stream of `blocks` with check type `check`.
    fn stream(blocks: &[Block], check: u8) -> Vec<u8> {
        let flags = [0, check];
        let mut s = MAGIC.to_vec();
        s.extend_from_slice(&flags);
        s.extend_from_slice(&crc32(&flags).to_le_bytes());
        let mut records = Vec::new();
        for b in blocks {
            let data = [b.lzma2.as_slice(), &[0]].concat();
            let mut h = vec![0, (b.filters.len() as u8) | if b.sizes.is_some() { 0xc0 } else { 0 }];
            if let Some((c, u)) = b.sizes {
                h.extend(vli(c));
                h.extend(vli(u));
            }
            for (id, p) in &b.filters {
                h.extend(vli(*id));
                h.extend(vli(p.len() as u64));
                h.extend_from_slice(p);
            }
            h.extend([0x21, 1, b.dict]);
            while (h.len() + 4) % 4 != 0 {
                h.push(0);
            }
            h[0] = ((h.len() + 4) / 4 - 1) as u8;
            let crc = crc32(&h);
            h.extend_from_slice(&crc.to_le_bytes());
            let field = b.check.clone().unwrap_or_else(|| match check {
                0 => vec![],
                1 => crc32(&b.out).to_le_bytes().to_vec(),
                4 => crc64(&b.out).to_le_bytes().to_vec(),
                10 => sha2::Sha256::digest(&b.out).to_vec(),
                c => vec![0; check_size(c)],
            });
            records.push(b.record.unwrap_or(((h.len() + data.len() + field.len()) as u64, b.out.len() as u64)));
            s.extend_from_slice(&h);
            s.extend_from_slice(&data);
            while (s.len() % 4) != 0 {
                s.push(0);
            }
            s.extend_from_slice(&field);
        }
        let mut index = vec![0];
        index.extend(vli(records.len() as u64));
        for (u, n) in &records {
            index.extend(vli(*u));
            index.extend(vli(*n));
        }
        while index.len() % 4 != 0 {
            index.push(0);
        }
        let crc = crc32(&index);
        index.extend_from_slice(&crc.to_le_bytes());
        let backward = (index.len() / 4 - 1) as u32;
        s.extend_from_slice(&index);
        let mut footer = backward.to_le_bytes().to_vec();
        footer.extend_from_slice(&flags);
        s.extend_from_slice(&crc32(&footer).to_le_bytes());
        s.extend_from_slice(&footer);
        s.extend_from_slice(&FOOTER_MAGIC);
        s
    }

    /// A block of one chunk from a fresh encoder (lc 3, lp 0, pb 2) run
    /// over `symbols`.
    fn one_chunk(f: impl FnOnce(&mut lzma::Encoder), out: &[u8]) -> Block {
        let mut e = lzma::Encoder::new(3, 0, 2, &[]);
        f(&mut e);
        Block { lzma2: lzma_chunk(3, out.len(), 0x5d, &e.finish()), dict: 16, out: out.to_vec(), ..Default::default() }
    }

    /// Which decoders take a stream: libcompression's, liblzma's, and the
    /// bytes `decode_buffer` gives.
    fn takes(s: &[u8], n: usize) -> (bool, bool, Option<Vec<u8>>) {
        let mut d = vec![0u8; n];
        let f = fast::decode(s, &mut d.clone()).is_ok_and(|k| k > 0);
        let l = strict::decode(s, &mut d.clone()).is_ok();
        let r = decode_buffer(s, &mut d).ok().map(|k| d[..k].to_vec());
        (f, l, r)
    }

    /// Hand-made streams and which decoders take them; with
    /// GEX_TEST_XZ_DUMP, also written as a cases file (`vectors.cases`)
    /// for [`host_decodes`].
    #[test]
    fn vectors() {
        let mut dump = Vec::new();
        let mut check = |name: &str, s: &[u8], n: usize, want: (bool, bool), out: Option<&[u8]>| {
            let (f, l, r) = takes(s, n);
            assert_eq!((f, l), want, "{name}");
            assert_eq!(r.as_deref(), out, "{name}");
            dump.extend_from_slice(&0x306u32.to_le_bytes());
            dump.extend_from_slice(&(n as u32).to_le_bytes());
            dump.extend_from_slice(&(s.len() as u32).to_le_bytes());
            dump.extend_from_slice(s);
        };
        // Literals, matches near and far (slots under 4, under 14, and
        // with direct bits), a repeat of one byte.
        let mut text: Vec<u8> = (0..1100u32).map(|i| (i * 7 % 251) as u8).collect();
        let mut want = text.clone();
        want.extend_from_slice(&text[1100 - 2..][..2]);
        want.extend_from_slice(&[want[want.len() - 2], want[want.len() - 1], want[want.len() - 2]]);
        let w0 = want.len();
        want.extend_from_slice(&want[w0 - 37..w0 - 37 + 20].to_vec());
        let w1 = want.len();
        want.extend_from_slice(&want[w1 - 1000..w1 - 1000 + 273].to_vec());
        let last = *want.last().unwrap();
        want.push(want[want.len() - 1000]);
        let _ = last;
        let b = one_chunk(
            |e| {
                for &c in &text {
                    e.literal(c);
                }
                e.matched(1, 2);
                e.matched(1, 3);
                e.matched(36, 20);
                e.matched(999, 273);
                e.shortrep();
            },
            &want,
        );
        for c in [0, 1, 4, 10] {
            check("symbols", &stream(&[b.clone()], c), want.len(), (true, true), Some(&want));
        }
        // A destination one byte short: both refuse.
        check("short destination", &stream(&[b.clone()], 1), want.len() - 1, (false, false), None);
        text.truncate(10);

        // libcompression's decoder alone: a first chunk that resets only
        // the state (properties 0, 0, 0); sizes, check and index records
        // not compared.
        let mut e = lzma::Encoder::new(0, 0, 0, &[]);
        for &c in b"abcab" {
            e.literal(c);
        }
        let first = Block { lzma2: lzma_chunk(1, 5, 0, &e.finish()), dict: 0, out: b"abcab".to_vec(), ..Default::default() };
        check("state reset first", &stream(&[first], 1), 5, (true, false), Some(b"abcab"));
        let hi = one_chunk(|e| b"hi".iter().for_each(|&c| e.literal(c)), b"hi");
        check("wrong sizes", &stream(&[Block { sizes: Some((7, 9)), ..hi.clone() }], 1), 2, (true, false), Some(b"hi"));
        check("wrong check", &stream(&[Block { check: Some(vec![0; 4]), ..hi.clone() }], 1), 2, (true, false), Some(b"hi"));
        check("wrong record", &stream(&[Block { record: Some((99, 1)), ..hi.clone() }], 1), 2, (true, false), Some(b"hi"));
        // A distance past the dictionary property's 4 KiB (6 KiB: both
        // take it), and one across a dictionary reset.
        let head: Vec<u8> = (0..5000u32).map(|i| (i * 13 % 256) as u8).collect();
        let far = |dict: u8| {
            let mut e = lzma::Encoder::new(3, 0, 2, &head);
            e.matched(4999, 100);
            let mut lz = stored_chunk(true, &head[..4096]);
            lz.extend(stored_chunk(false, &head[4096..]));
            lz.extend(lzma_chunk(2, 100, 0x5d, &e.finish()));
            let mut out = head.clone();
            out.extend_from_slice(&head[..100]);
            (Block { lzma2: lz, dict, out: out.clone(), ..Default::default() }, out)
        };
        let (b0, out) = far(0);
        check("past the dictionary", &stream(&[b0], 0), out.len(), (true, false), Some(&out));
        let (b1, out) = far(1);
        check("within the dictionary", &stream(&[b1], 0), out.len(), (true, true), Some(&out));
        let mut e = lzma::Encoder::new(3, 0, 2, &head[..200]);
        e.matched(150, 10);
        let mut lz = stored_chunk(true, &head[..100]);
        lz.extend(stored_chunk(true, &head[100..200]));
        lz.extend(lzma_chunk(2, 10, 0x5d, &e.finish()));
        let mut out = head[..200].to_vec();
        out.extend_from_slice(&head[49..59]);
        check("across a dictionary reset", &stream(&[Block { lzma2: lz, out: out.clone(), dict: 16, ..Default::default() }], 0), out.len(), (true, false), Some(&out));
        // A packed size past the chunk's data: libcompression's decoder
        // reads the next control byte there.
        let mut e = lzma::Encoder::new(3, 0, 2, &[]);
        b"hello".iter().for_each(|&c| e.literal(c));
        let data = e.finish();
        let lz = lzma_chunk(3, 5, 0x5d, &[data.as_slice(), &[0x7f; 3]].concat());
        check("packed size long", &stream(&[Block { lzma2: lz, out: b"hello".to_vec(), dict: 16, ..Default::default() }], 0), 5, (true, false), Some(b"hello"));

        // liblzma alone: a filter before LZMA2, a reserved check type.
        let delta = Block { filters: vec![(3, vec![0])], out: b"acegi".to_vec(), ..one_chunk(|e| [b'a', 2, 2, 2, 2].iter().for_each(|&c| e.literal(c)), b"a\x02\x02\x02\x02") };
        check("delta", &stream(&[delta], 1), 5, (false, true), Some(b"acegi"));
        check("check type 2", &stream(&[hi.clone()], 2), 2, (false, true), Some(b"hi"));
        let x86 = Block { filters: vec![(4, vec![1, 0, 0, 0])], ..hi.clone() };
        check("x86 at 1", &stream(&[x86], 1), 2, (false, true), Some(b"hi"));
        let arm = Block { filters: vec![(7, vec![2, 0, 0, 0])], ..hi.clone() };
        check("ARM at 2", &stream(&[arm], 1), 2, (false, false), None);

        // Both refuse: a distance past the output, a match past the
        // chunk's end, a first byte not 0, the stream cut short.
        let bad = one_chunk(
            |e| {
                b"abc".iter().for_each(|&c| e.literal(c));
                e.matched(3, 2);
            },
            b"abcab",
        );
        check("distance past the output", &stream(&[bad], 0), 5, (false, false), None);
        let mut e = lzma::Encoder::new(3, 0, 2, &[]);
        b"abc".iter().for_each(|&c| e.literal(c));
        e.matched(2, 4);
        let long = Block { lzma2: lzma_chunk(3, 5, 0x5d, &e.finish()), dict: 16, out: b"abcab".to_vec(), ..Default::default() };
        check("match past the chunk", &stream(&[long], 0), 7, (false, false), None);
        let mut nz = hi.clone();
        nz.lzma2[6] = 1;
        check("first byte not 0", &stream(&[nz], 0), 2, (false, false), None);
        let s = stream(&[hi.clone()], 1);
        check("cut short", &s[..s.len() - 1], 2, (false, false), None);
        check("no blocks", &stream(&[], 1), 2, (false, true), Some(b""));

        if let Ok(dir) = std::env::var("GEX_TEST_XZ_DUMP") {
            std::fs::write(std::path::Path::new(&dir).join("vectors.cases"), &dump).unwrap();
        }
    }

    /// Streams beside what the host made of each (GEX_TEST_XZ_CASES: a file
    /// of cases, each a u32 algorithm, destination size and source size,
    /// then the source; beside it, the same name with extension `results`,
    /// `compression_decode_buffer`'s, and `liblzma`, liblzma's
    /// `lzma_stream_buffer_decode`'s, each the bytes written (0 for a
    /// refusal)).
    #[test]
    fn host_decodes() {
        let Ok(path) = std::env::var("GEX_TEST_XZ_CASES") else { return };
        let path = std::path::Path::new(&path);
        let cases = std::fs::read(path).unwrap();
        let (host, liblzma) = (results(&path.with_extension("results")), results(&path.with_extension("liblzma")));
        let u32_at = |b: &[u8], i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap()) as usize;
        let (mut at, mut n) = (0, 0);
        let (mut by_fast, mut by_strict, mut refused) = (0, 0, 0);
        while at < cases.len() {
            let (alg, dst_len, src_len) = (u32_at(&cases, at), u32_at(&cases, at + 4), u32_at(&cases, at + 8));
            assert_eq!(alg, 0x306);
            let src = &cases[at + 12..at + 12 + src_len];
            at += 12 + src_len;
            let mut dst = vec![0u8; dst_len];
            let s = strict::decode(src, &mut dst);
            match &s {
                Ok(k) => assert!(dst[..*k] == liblzma[n][..], "case {n}: liblzma gives {} bytes, this {k}", liblzma[n].len()),
                Err(e) => assert!(liblzma[n].is_empty(), "case {n}: liblzma gives {} bytes, this refuses: {e}", liblzma[n].len()),
            }
            let mut dst = vec![0u8; dst_len];
            match decode_buffer(src, &mut dst) {
                Ok(k) => {
                    assert!(dst[..k] == host[n][..], "case {n}: the host gives {} bytes, this {k} (fast: {:?})", host[n].len(), fast::decode(src, &mut vec![0; dst_len]));
                    if fast::decode(src, &mut vec![0; dst_len]).is_ok_and(|k| k > 0) {
                        by_fast += 1;
                    } else if k > 0 {
                        by_strict += 1;
                    }
                }
                Err(e) => {
                    assert!(host[n].is_empty(), "case {n}: the host gives {} bytes, this refuses: {e}", host[n].len());
                    refused += 1;
                }
            }
            n += 1;
        }
        crate::darwin_say!("{n} streams: {by_fast} by libcompression's decoder, {by_strict} by liblzma's alone, {refused} refused");
    }
}
