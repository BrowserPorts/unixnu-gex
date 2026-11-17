//! LZFSE and LZVN decoding, ported from Apple's reference implementation
//! (github.com/lzfse/lzfse, `lzfse_decode_base.c`, `lzfse_fse.c`,
//! `lzfse_fse.h`, `lzfse_internal.h`, `lzvn_decode_base.c`; Copyright (c)
//! 2015-2016 Apple Inc., BSD-3-Clause, see NOTICE), the format a disk
//! image's `bvx` chunks and decmpfs's LZFSE and LZVN schemes are in.
//!
//! The reference decodes in steps, stopping where its source runs out or its
//! destination fills; this decodes a whole stream into a destination of the
//! size the caller knows the stream expands to, and refuses (as the
//! reference's `LZFSE_STATUS_ERROR` does) any stream that does not end
//! exactly there.
//!
//! A stream is a sequence of blocks, each starting with a 32-bit
//! little-endian magic: `bvx$` ends the stream; `bvx-` holds `n_raw_bytes`
//! bytes as they are; `bvxn` holds an LZVN stream of `n_payload_bytes`
//! that expands to `n_raw_bytes`; `bvx1` and `bvx2` hold an LZFSE block,
//! its frequency tables plain (v1) or packed (v2), then the literals and
//! the L, M, D (literal length, match length, match distance) triples, each
//! an FSE-coded bit stream read backwards from its end.

/// Why a stream does not decode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LZFSE stream refused: {}", self.0)
    }
}

fn err<T>(why: impl Into<String>) -> Result<T, Error> {
    Err(Error(why.into()))
}

const ENDOFSTREAM_BLOCK_MAGIC: u32 = 0x2478_7662;
const UNCOMPRESSED_BLOCK_MAGIC: u32 = 0x2d78_7662;
const COMPRESSEDV1_BLOCK_MAGIC: u32 = 0x3178_7662;
const COMPRESSEDV2_BLOCK_MAGIC: u32 = 0x3278_7662;
const COMPRESSEDLZVN_BLOCK_MAGIC: u32 = 0x6e78_7662;

const L_SYMBOLS: usize = 20;
const M_SYMBOLS: usize = 20;
const D_SYMBOLS: usize = 64;
const LITERAL_SYMBOLS: usize = 256;
const L_STATES: usize = 64;
const M_STATES: usize = 64;
const D_STATES: usize = 256;
const LITERAL_STATES: usize = 1024;
const MATCHES_PER_BLOCK: u32 = 10000;
const LITERALS_PER_BLOCK: u32 = 4 * MATCHES_PER_BLOCK;

/// `sizeof(lzfse_compressed_block_header_v1)`: magic, six counts, the
/// literal bits, four literal states, the L, M, D bits and states, and the
/// four frequency tables of 16-bit entries.
const V1_HEADER_SIZE: usize = 4 * 7 + 4 + 2 * 4 + 4 + 2 * 3 + 2 * (L_SYMBOLS + M_SYMBOLS + D_SYMBOLS + LITERAL_SYMBOLS);

const L_EXTRA_BITS: [u8; L_SYMBOLS] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 5, 8];
const L_BASE_VALUE: [i32; L_SYMBOLS] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 28, 60];
const M_EXTRA_BITS: [u8; M_SYMBOLS] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 5, 8, 11];
const M_BASE_VALUE: [i32; M_SYMBOLS] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 24, 56, 312];
const D_EXTRA_BITS: [u8; D_SYMBOLS] = [
    0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 11, 11, 11, 11, 12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15,
];
const D_BASE_VALUE: [i32; D_SYMBOLS] = [
    0, 1, 2, 3, 4, 6, 8, 10, 12, 16, 20, 24, 28, 36, 44, 52, 60, 76, 92, 108, 124, 156, 188, 220, 252, 316, 380, 444, 508, 636, 764, 892, 1020, 1276, 1532, 1788, 2044, 2556, 3068, 3580, 4092, 5116, 6140, 7164, 8188, 10236, 12284, 14332, 16380, 20476, 24572, 28668,
    32764, 40956, 49148, 57340, 65532, 81916, 98300, 114684, 131068, 163836, 196604, 229372,
];

fn load4(b: &[u8], at: usize) -> Result<u32, Error> {
    match b.get(at..at + 4) {
        Some(s) => Ok(u32::from_le_bytes(s.try_into().unwrap())),
        None => err("source truncated"),
    }
}

/// The value of `bits`'s low end as `lzfse_decode_v1_freq_value` reads a
/// packed frequency, and how many bits it took.
fn freq_value(bits: u32) -> (u16, u32) {
    const NBITS: [u8; 32] = [2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14, 2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14];
    const VALUE: [i8; 32] = [0, 2, 1, 4, 0, 3, 1, -1, 0, 2, 1, 5, 0, 3, 1, -1, 0, 2, 1, 6, 0, 3, 1, -1, 0, 2, 1, 7, 0, 3, 1, -1];
    let b = (bits & 31) as usize;
    let n = u32::from(NBITS[b]);
    match n {
        8 => (8 + ((bits >> 4) & 0xf) as u16, n),
        14 => (24 + ((bits >> 4) & 0x3ff) as u16, n),
        _ => (VALUE[b] as u16, n),
    }
}

/// `lzfse_compressed_block_header_v1`, as the decoder uses it.
struct Header {
    n_literals: u32,
    n_matches: u32,
    n_literal_payload_bytes: u32,
    n_lmd_payload_bytes: u32,
    literal_bits: i32,
    literal_state: [u16; 4],
    lmd_bits: i32,
    l_state: u16,
    m_state: u16,
    d_state: u16,
    /// L, M, D and literal frequencies, in that order.
    freq: Vec<u16>,
}

/// `get_field`.
fn field(v: u64, offset: u32, nbits: u32) -> u32 {
    if nbits == 32 {
        return (v >> offset) as u32;
    }
    ((v >> offset) & ((1u64 << nbits) - 1)) as u32
}

/// `lzfse_decode_v1`: a v2 header (`h`, the whole of it) unpacked.
fn header_v2(h: &[u8]) -> Result<Header, Error> {
    let q = |i: usize| u64::from_le_bytes(h[8 + 8 * i..16 + 8 * i].try_into().unwrap());
    let (v0, v1, v2) = (q(0), q(1), q(2));
    let mut out = Header {
        n_literals: field(v0, 0, 20),
        n_literal_payload_bytes: field(v0, 20, 20),
        n_matches: field(v0, 40, 20),
        literal_bits: field(v0, 60, 3) as i32 - 7,
        literal_state: [field(v1, 0, 10) as u16, field(v1, 10, 10) as u16, field(v1, 20, 10) as u16, field(v1, 30, 10) as u16],
        n_lmd_payload_bytes: field(v1, 40, 20),
        lmd_bits: field(v1, 60, 3) as i32 - 7,
        l_state: field(v2, 32, 10) as u16,
        m_state: field(v2, 42, 10) as u16,
        d_state: field(v2, 52, 10) as u16,
        freq: vec![0; L_SYMBOLS + M_SYMBOLS + D_SYMBOLS + LITERAL_SYMBOLS],
    };
    let src = &h[32..];
    // No tables: the frequencies stay 0.
    if src.is_empty() {
        return Ok(out);
    }
    let (mut accum, mut accum_nbits, mut at) = (0u32, 0u32, 0usize);
    for f in out.freq.iter_mut() {
        while at < src.len() && accum_nbits + 8 <= 32 {
            accum |= u32::from(src[at]) << accum_nbits;
            accum_nbits += 8;
            at += 1;
        }
        let (v, nbits) = freq_value(accum);
        *f = v;
        if nbits > accum_nbits {
            return err("a v2 header's frequency tables run past the header");
        }
        accum >>= nbits;
        accum_nbits -= nbits;
    }
    if accum_nbits >= 8 || at != src.len() {
        return err("a v2 header's frequency tables do not end at the header's end");
    }
    Ok(out)
}

/// A v1 header, as it is stored.
fn header_v1(h: &[u8]) -> Header {
    let w = |i: usize| u32::from_le_bytes(h[4 * i..4 * i + 4].try_into().unwrap());
    let hw = |at: usize| u16::from_le_bytes(h[at..at + 2].try_into().unwrap());
    let freq = (0..L_SYMBOLS + M_SYMBOLS + D_SYMBOLS + LITERAL_SYMBOLS).map(|i| hw(54 + 2 * i)).collect();
    Header {
        n_literals: w(3),
        n_matches: w(4),
        n_literal_payload_bytes: w(5),
        n_lmd_payload_bytes: w(6),
        literal_bits: w(7) as i32,
        literal_state: [hw(32), hw(34), hw(36), hw(38)],
        lmd_bits: w(10) as i32,
        l_state: hw(44),
        m_state: hw(46),
        d_state: hw(48),
        freq,
    }
}

/// `fse_check_freq`.
fn freq_fits(freq: &[u16], nstates: usize) -> bool {
    freq.iter().map(|&f| usize::from(f)).sum::<usize>() <= nstates
}

/// `lzfse_check_block_header_v1`.
fn check_header(h: &Header) -> Result<(), Error> {
    let (l, rest) = h.freq.split_at(L_SYMBOLS);
    let (m, rest) = rest.split_at(M_SYMBOLS);
    let (d, lit) = rest.split_at(D_SYMBOLS);
    let ok = h.n_literals <= LITERALS_PER_BLOCK
        && h.n_matches <= MATCHES_PER_BLOCK
        && h.literal_state.iter().all(|&s| usize::from(s) < LITERAL_STATES)
        && usize::from(h.l_state) < L_STATES
        && usize::from(h.m_state) < M_STATES
        && usize::from(h.d_state) < D_STATES
        && freq_fits(l, L_STATES)
        && freq_fits(m, M_STATES)
        && freq_fits(d, D_STATES)
        && freq_fits(lit, LITERAL_STATES);
    if ok { Ok(()) } else { err("a block header fails the decoder's checks") }
}

/// A decoder table entry (`fse_decoder_entry`): bits to read, symbol, and
/// the next state's base.
#[derive(Clone, Copy, Default)]
struct Entry {
    k: u32,
    symbol: u8,
    delta: i32,
}

/// A value decoder table entry (`fse_value_decoder_entry`).
#[derive(Clone, Copy, Default)]
struct ValueEntry {
    total_bits: u32,
    value_bits: u32,
    delta: i32,
    vbase: i32,
}

/// The shift `__builtin_clz(f) - __builtin_clz(nstates)` gives each
/// symbol, and the first state past its `k`-bit states.
fn spread(nstates: usize, f: usize) -> (u32, usize) {
    let k = (f as u32).leading_zeros() - (nstates as u32).leading_zeros();
    (k, ((2 * nstates) >> k) - f)
}

/// `fse_init_decoder_table`.
fn decoder_table(nstates: usize, freq: &[u16]) -> Result<Vec<Entry>, Error> {
    let mut t = vec![Entry::default(); nstates];
    let mut at = 0;
    for (i, &f) in freq.iter().enumerate() {
        let f = usize::from(f);
        if f == 0 {
            continue;
        }
        if at + f > nstates {
            return err("a frequency table sums past its states");
        }
        let (k, j0) = spread(nstates, f);
        for j in 0..f {
            t[at] = if j < j0 { Entry { k, symbol: i as u8, delta: (((f + j) << k) as i32) - nstates as i32 } } else { Entry { k: k - 1, symbol: i as u8, delta: ((j - j0) << (k - 1)) as i32 } };
            at += 1;
        }
    }
    Ok(t)
}

/// `fse_init_value_decoder_table`.
fn value_decoder_table(nstates: usize, freq: &[u16], vbits: &[u8], vbase: &[i32]) -> Vec<ValueEntry> {
    let mut t = vec![ValueEntry::default(); nstates];
    let mut at = 0;
    for (i, &f) in freq.iter().enumerate() {
        let f = usize::from(f);
        if f == 0 {
            continue;
        }
        let (k, j0) = spread(nstates, f);
        let value_bits = u32::from(vbits[i]);
        for j in 0..f {
            t[at] = if j < j0 {
                ValueEntry { total_bits: k + value_bits, value_bits, delta: (((f + j) << k) as i32) - nstates as i32, vbase: vbase[i] }
            } else {
                ValueEntry { total_bits: k - 1 + value_bits, value_bits, delta: ((j - j0) << (k - 1)) as i32, vbase: vbase[i] }
            };
            at += 1;
        }
    }
    t
}

/// `fse_in_stream64`: bits read backwards from `pos` towards `start`.
struct InStream<'a> {
    buf: &'a [u8],
    start: usize,
    pos: usize,
    accum: u64,
    accum_nbits: i32,
}

fn mask(x: u64, nbits: i32) -> u64 {
    if nbits >= 64 { x } else { x & ((1u64 << nbits) - 1) }
}

impl<'a> InStream<'a> {
    /// `fse_in_checked_init64`: `n` the encoder's final bit count, the
    /// first word bounded by `init_start` and later reads by `start`.
    fn new(buf: &'a [u8], init_start: usize, start: usize, end: usize, n: i32) -> Result<Self, Error> {
        let take = if n != 0 { 8 } else { 7 };
        if end < init_start + take {
            return err("a bit stream is shorter than its first word");
        }
        let pos = end - take;
        let mut w = [0u8; 8];
        w[..take].copy_from_slice(&buf[pos..end]);
        let accum = u64::from_le_bytes(w);
        let accum_nbits = n + if n != 0 { 64 } else { 56 };
        if !(56..64).contains(&accum_nbits) || accum >> accum_nbits != 0 {
            return err("a bit stream's first word is not what its encoder leaves");
        }
        Ok(InStream { buf, start, pos, accum, accum_nbits })
    }

    /// `fse_in_checked_flush64`.
    fn flush(&mut self) -> Result<(), Error> {
        let nbits = (63 - self.accum_nbits) & -8;
        let n = (nbits >> 3) as usize;
        if self.pos < self.start + n {
            return err("a bit stream reads past its start");
        }
        self.pos -= n;
        let mut w = [0u8; 8];
        w[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        let incoming = u64::from_le_bytes(w);
        self.accum = if nbits == 0 { self.accum } else { (self.accum << nbits) | mask(incoming, nbits) };
        self.accum_nbits += nbits;
        Ok(())
    }

    /// `fse_in_pull64`.
    fn pull(&mut self, n: u32) -> u64 {
        self.accum_nbits -= n as i32;
        let result = self.accum >> self.accum_nbits;
        self.accum = mask(self.accum, self.accum_nbits);
        result
    }
}

/// `fse_decode`.
fn decode_symbol(state: &mut u16, t: &[Entry], s: &mut InStream<'_>) -> u8 {
    let e = t[usize::from(*state)];
    *state = (e.delta as u16).wrapping_add(s.pull(e.k) as u16);
    e.symbol
}

/// `fse_value_decode`.
fn decode_value(state: &mut u16, t: &[ValueEntry], s: &mut InStream<'_>) -> i32 {
    let e = t[usize::from(*state)];
    let bits = s.pull(e.total_bits) as u32;
    *state = (e.delta + (bits >> e.value_bits) as i32) as u16;
    e.vbase + mask(u64::from(bits), e.value_bits as i32) as i32
}

/// Decodes the LZFSE stream `src` into `dst`, which the stream must fill
/// exactly. Bytes after the end-of-stream block are not read.
pub fn decode(src: &[u8], dst: &mut [u8]) -> Result<usize, Error> {
    let mut at = 0usize;
    let mut out = 0usize;
    loop {
        let magic = load4(src, at)?;
        match magic {
            ENDOFSTREAM_BLOCK_MAGIC => {
                if out != dst.len() {
                    return err(format!("the stream ends after {out} of {} bytes", dst.len()));
                }
                return Ok(at + 4);
            }
            UNCOMPRESSED_BLOCK_MAGIC => {
                let n = load4(src, at + 4)? as usize;
                at += 8;
                let Some(b) = src.get(at..at + n) else { return err("an uncompressed block is truncated") };
                let Some(d) = dst.get_mut(out..out + n) else { return err("an uncompressed block overruns the destination") };
                d.copy_from_slice(b);
                at += n;
                out += n;
            }
            COMPRESSEDLZVN_BLOCK_MAGIC => {
                let n_raw = load4(src, at + 4)? as usize;
                let n_payload = load4(src, at + 8)? as usize;
                at += 12;
                let Some(payload) = src.get(at..at + n_payload) else { return err("an LZVN block is truncated") };
                if out + n_raw > dst.len() {
                    return err("an LZVN block overruns the destination");
                }
                let r = lzvn_run(payload, dst, out, out + n_raw);
                if !(r.end_of_stream && r.src_used == n_payload && r.dst_at == out + n_raw) {
                    return err("an LZVN block does not end at its payload's and output's end");
                }
                at += n_payload;
                out += n_raw;
            }
            COMPRESSEDV1_BLOCK_MAGIC | COMPRESSEDV2_BLOCK_MAGIC => {
                let (h, header_size) = if magic == COMPRESSEDV2_BLOCK_MAGIC {
                    if src.len() < at + 32 {
                        return err("a v2 header is truncated");
                    }
                    let size = field(u64::from_le_bytes(src[at + 24..at + 32].try_into().unwrap()), 0, 32) as usize;
                    // The packed fields are always there.
                    if size < 32 {
                        return err("a v2 header is shorter than its fixed part");
                    }
                    let Some(hb) = src.get(at..at + size) else { return err("a v2 header is truncated") };
                    (header_v2(hb)?, size)
                } else {
                    let Some(hb) = src.get(at..at + V1_HEADER_SIZE) else { return err("a v1 header is truncated") };
                    (header_v1(hb), V1_HEADER_SIZE)
                };
                let lit_bytes = h.n_literal_payload_bytes as usize;
                let lmd_bytes = h.n_lmd_payload_bytes as usize;
                if at + header_size + lit_bytes + lmd_bytes > src.len() {
                    return err("a compressed block is truncated");
                }
                check_header(&h)?;
                at += header_size;
                let (end, full) = lzfse_block(&h, src, at, dst, out)?;
                if full {
                    return err("a block's output overruns the destination");
                }
                out = end;
                at += lit_bytes + lmd_bytes;
            }
            _ => return err(format!("block magic {magic:#010x}")),
        }
    }
}

/// `lzfse_decode_buffer`: as much of the stream as `dst` holds. The bytes
/// written at the end-of-stream block; all of `dst` when it fills first
/// (`LZFSE_STATUS_DST_FULL`, also what an LZVN block that stops short of
/// its end reports); 0 for a stream that is malformed or ends early.
pub fn decode_buffer(src: &[u8], dst: &mut [u8]) -> usize {
    let mut at = 0usize;
    let mut out = 0usize;
    loop {
        let Ok(magic) = load4(src, at) else { return 0 };
        match magic {
            ENDOFSTREAM_BLOCK_MAGIC => return out,
            UNCOMPRESSED_BLOCK_MAGIC => {
                let Ok(n) = load4(src, at + 4) else { return 0 };
                at += 8;
                let mut n = n as usize;
                // Copied in pieces bounded by the source and the
                // destination; the source's end is checked first.
                while n > 0 {
                    if at >= src.len() {
                        return 0;
                    }
                    if out >= dst.len() {
                        return dst.len();
                    }
                    let c = n.min(src.len() - at).min(dst.len() - out);
                    dst[out..out + c].copy_from_slice(&src[at..at + c]);
                    at += c;
                    out += c;
                    n -= c;
                }
            }
            COMPRESSEDLZVN_BLOCK_MAGIC => {
                let (Ok(n_raw), Ok(n_payload)) = (load4(src, at + 4), load4(src, at + 8)) else { return 0 };
                let (n_raw, n_payload) = (n_raw as usize, n_payload as usize);
                at += 12;
                if n_payload > 0 && at >= src.len() {
                    return 0;
                }
                let payload = &src[at..src.len().min(at + n_payload)];
                let to = dst.len().min(out + n_raw);
                let r = lzvn_run(payload, dst, out, to);
                let (src_used, dst_used) = (r.src_used, r.dst_at - out);
                let (payload_left, raw_left) = (n_payload - src_used, n_raw - dst_used);
                at += src_used;
                out += dst_used;
                if payload_left == 0 && raw_left == 0 && r.end_of_stream {
                    continue;
                }
                if payload_left == 0 || raw_left == 0 || r.end_of_stream {
                    return 0;
                }
                return dst.len();
            }
            COMPRESSEDV1_BLOCK_MAGIC | COMPRESSEDV2_BLOCK_MAGIC => {
                let header = if magic == COMPRESSEDV2_BLOCK_MAGIC {
                    if src.len() < at + 32 {
                        return 0;
                    }
                    let size = field(u64::from_le_bytes(src[at + 24..at + 32].try_into().unwrap()), 0, 32) as usize;
                    if size < 32 {
                        return 0;
                    }
                    let Some(hb) = src.get(at..at + size) else { return 0 };
                    header_v2(hb).map(|h| (h, size))
                } else {
                    let Some(hb) = src.get(at..at + V1_HEADER_SIZE) else { return 0 };
                    Ok((header_v1(hb), V1_HEADER_SIZE))
                };
                let Ok((h, header_size)) = header else { return 0 };
                let (lit_bytes, lmd_bytes) = (h.n_literal_payload_bytes as usize, h.n_lmd_payload_bytes as usize);
                if at + header_size + lit_bytes + lmd_bytes > src.len() || check_header(&h).is_err() {
                    return 0;
                }
                at += header_size;
                match lzfse_block(&h, src, at, dst, out) {
                    Ok((_, true)) => return dst.len(),
                    Ok((end, false)) => out = end,
                    Err(_) => return 0,
                }
                at += lit_bytes + lmd_bytes;
            }
            _ => return 0,
        }
    }
}

/// The raw LZVN decoder the kernel's decmpfs decompressor uses for its
/// LZVN scheme (algorithm 0x900 of its `compression_decode_buffer`,
/// 0xfffffff006b20440): a stream with no block header, decoded into `dst`.
/// Each opcode is fetched only while at least 8 source bytes remain from
/// it (checked before the opcode's literal and match are copied); the
/// distance starts at 0, and a match at distance 0 or reaching before the
/// output fails. It gives the bytes written at the end-of-stream opcode,
/// all of `dst` once a literal or match reaches its end (the copy stops
/// there), and 0 for an empty
/// destination, an undefined opcode, a bad distance, or a source that runs
/// out.
pub fn lzvn_decode_buffer(src: &[u8], dst: &mut [u8]) -> usize {
    if dst.is_empty() {
        return 0;
    }
    let (mut sp, mut dp, mut d) = (0usize, 0usize, 0usize);
    let e = |v: u8, lsb: u32, w: u32| ((u32::from(v) >> lsb) & ((1 << w) - 1)) as usize;
    loop {
        if sp + 8 > src.len() {
            return 0;
        }
        let opc = src[sp];
        let b1 = usize::from(src[sp + 1]);
        let b12 = usize::from(u16::from_le_bytes([src[sp + 1], src[sp + 2]]));
        // (opcode length, literal length, match length, distance)
        let (ol, l, m, nd) = match opc {
            6 => return dp,
            14 | 22 => (1, 0, 0, d),
            30 | 38 | 46 | 54 | 62 | 112..=127 | 208..=223 => return 0,
            224 => (2, b1 + 16, 0, d),
            225..=239 => (1, e(opc, 0, 4), 0, d),
            240 => (2, 0, b1 + 16, d),
            241..=255 => (1, 0, e(opc, 0, 4), d),
            160..=191 => (3, e(opc, 3, 2), ((e(opc, 0, 3) << 2) | (b12 & 3)) + 3, b12 >> 2),
            _ if opc & 7 == 7 => (3, e(opc, 6, 2), e(opc, 3, 3) + 3, b12),
            _ if opc & 7 == 6 => (1, e(opc, 6, 2), e(opc, 3, 3) + 3, d),
            _ => (2, e(opc, 6, 2), e(opc, 3, 3) + 3, (e(opc, 0, 3) << 8) | b1),
        };
        let lit = sp + ol;
        sp = lit + l;
        if sp + 8 > src.len() {
            return 0;
        }
        d = nd;
        let n = l.min(dst.len() - dp);
        dst[dp..dp + n].copy_from_slice(&src[lit..lit + n]);
        dp += n;
        // Filling the destination ends the decode at once.
        if l > 0 && dp == dst.len() {
            return dst.len();
        }
        if m == 0 {
            continue;
        }
        if d > dp || d == 0 {
            return 0;
        }
        let n = m.min(dst.len() - dp);
        dp = copy_match(dst, dp, d, n);
        if dp == dst.len() {
            return dst.len();
        }
    }
}

/// One LZFSE block whose literal payload starts at `at`: its output from
/// `out`, where that ends, and whether it stopped there because `dst` is
/// full (`LZFSE_STATUS_DST_FULL`).
fn lzfse_block(h: &Header, src: &[u8], at: usize, dst: &mut [u8], out: usize) -> Result<(usize, bool), Error> {
    let (l_freq, rest) = h.freq.split_at(L_SYMBOLS);
    let (m_freq, rest) = rest.split_at(M_SYMBOLS);
    let (d_freq, lit_freq) = rest.split_at(D_SYMBOLS);
    let literal_decoder = decoder_table(LITERAL_STATES, lit_freq)?;
    let l_decoder = value_decoder_table(L_STATES, l_freq, &L_EXTRA_BITS, &L_BASE_VALUE);
    let m_decoder = value_decoder_table(M_STATES, m_freq, &M_EXTRA_BITS, &M_BASE_VALUE);
    let d_decoder = value_decoder_table(D_STATES, d_freq, &D_EXTRA_BITS, &D_BASE_VALUE);

    // The literals: four interleaved streams, read backwards from the
    // literal payload's end (the reference bounds the reads by the
    // stream's start, not the payload's).
    let lit_end = at + h.n_literal_payload_bytes as usize;
    let mut literals = vec![0u8; LITERALS_PER_BLOCK as usize + 64];
    {
        let mut s = InStream::new(src, 0, 0, lit_end, h.literal_bits)?;
        let mut st = h.literal_state;
        let mut i = 0;
        while i < h.n_literals as usize {
            s.flush()?;
            for (j, state) in st.iter_mut().enumerate() {
                literals[i + j] = decode_symbol(state, &literal_decoder, &mut s);
            }
            i += 4;
        }
    }

    // The L, M, D triples, read backwards from the block's end: the first
    // word bounded by the L, M, D payload's start, the rest (as the
    // reference's `lzfse_decode_lmd` does) by the stream's.
    let lmd_start = lit_end;
    let mut s = InStream::new(src, lmd_start, 0, lmd_start + h.n_lmd_payload_bytes as usize, h.lmd_bits)?;
    let (mut l_state, mut m_state, mut d_state) = (h.l_state, h.m_state, h.d_state);
    let mut lit = 0usize;
    let mut out = out;
    let mut d: i32 = -1;
    for _ in 0..h.n_matches {
        s.flush()?;
        let l = decode_value(&mut l_state, &l_decoder, &mut s);
        if lit + l as usize >= LITERALS_PER_BLOCK as usize + 64 {
            return err("a literal length runs past the block's literals");
        }
        let m = decode_value(&mut m_state, &m_decoder, &mut s);
        let new_d = decode_value(&mut d_state, &d_decoder, &mut s);
        if new_d != 0 {
            d = new_d;
        }
        let (l, m) = (l as usize, m as usize);
        // D past what has been written (counted from the stream's first
        // output byte, as `dst_begin` is) is refused.
        if (d as u32) as usize > out + l {
            return err("a match distance reaches before the output");
        }
        let dd = d as usize;
        if out + l + m > dst.len() {
            // The careful path at the destination's end: the literal, then
            // the match, each as much as fits (`DestinationBufferIsFull`).
            let n = l.min(dst.len() - out);
            dst[out..out + n].copy_from_slice(&literals[lit..lit + n]);
            out += n;
            let n = m.min(dst.len() - out);
            for i in 0..n {
                dst[out + i] = dst[out + i - dd];
            }
            return Ok((out + n, true));
        }
        dst[out..out + l].copy_from_slice(&literals[lit..lit + l]);
        out += l;
        lit += l;
        for i in 0..m {
            dst[out + i] = dst[out + i - dd];
        }
        out += m;
    }
    Ok((out, false))
}

/// Where an LZVN run stopped.
struct LzvnEnd {
    src_used: usize,
    dst_at: usize,
    end_of_stream: bool,
}

/// `lzvn_decode` over `src`, writing `dst[from..to]` (distances may reach
/// back to `dst[0]`, the stream's first output byte). It stops at the
/// end-of-stream opcode, an undefined opcode, a bad distance, or where its
/// source or destination runs out.
fn lzvn_run(src: &[u8], dst: &mut [u8], from: usize, to: usize) -> LzvnEnd {
    let (mut sp, mut dp) = (0usize, from);
    // The state last known good (`UPDATE_GOOD`): where a truncated or
    // refused opcode leaves the decoder.
    let mut good = LzvnEnd { src_used: 0, dst_at: from, end_of_stream: false };
    let mut d = 0usize;
    if src.is_empty() || from == to {
        return good;
    }
    loop {
        let src_len = src.len() - sp;
        let dst_len = to - dp;
        let opc = src[sp];
        let e = |v: u8, lsb: u32, w: u32| (u32::from(v) >> lsb) & ((1 << w) - 1);
        // (opcode length, L, M, new D or none, whether L and M are both
        // given: a literal-and-match opcode)
        let (opc_len, l, m, new_d): (usize, usize, usize, Option<usize>);
        match opc {
            // eos
            6 => {
                if src_len < 8 {
                    return good;
                }
                return LzvnEnd { src_used: sp + 8, dst_at: dp, end_of_stream: true };
            }
            // nop
            14 | 22 => {
                good = LzvnEnd { src_used: sp, dst_at: dp, end_of_stream: false };
                if src_len <= 1 {
                    return good;
                }
                sp += 1;
                continue;
            }
            // udef
            30 | 38 | 46 | 54 | 62 | 112..=127 | 208..=223 => return LzvnEnd { src_used: sp, dst_at: dp, end_of_stream: false },
            // lrg_l, sml_l: literals alone
            224..=239 => {
                good = LzvnEnd { src_used: sp, dst_at: dp, end_of_stream: false };
                let (ol, l) = if opc == 224 {
                    if src_len <= 2 {
                        return good;
                    }
                    (2, usize::from(src[sp + 1]) + 16)
                } else {
                    (1, e(opc, 0, 4) as usize)
                };
                if src_len <= ol + l {
                    return good;
                }
                sp += ol;
                if l > dst_len {
                    return good_after_partial(src, dst, sp, dp, dst_len);
                }
                dst[dp..dp + l].copy_from_slice(&src[sp..sp + l]);
                dp += l;
                sp += l;
                continue;
            }
            // lrg_m, sml_m: a match alone at the previous distance
            240..=255 => {
                good = LzvnEnd { src_used: sp, dst_at: dp, end_of_stream: false };
                let ol = if opc == 240 { 2 } else { 1 };
                if src_len <= ol {
                    return good;
                }
                let m = if opc == 240 { usize::from(src[sp + 1]) + 16 } else { e(opc, 0, 4) as usize };
                // No distance yet: the reference copies memory the stream
                // never wrote.
                if d == 0 {
                    return good;
                }
                sp += ol;
                if m > dst_len {
                    return LzvnEnd { src_used: sp, dst_at: copy_match(dst, dp, d, dst_len), end_of_stream: false };
                }
                dp = copy_match(dst, dp, d, m);
                continue;
            }
            // med_d
            160..=191 => {
                if src_len < 3 {
                    good = LzvnEnd { src_used: sp, dst_at: dp, end_of_stream: false };
                    return good;
                }
                let opc23 = u16::from_le_bytes([src[sp + 1], src[sp + 2]]);
                opc_len = 3;
                l = e(opc, 3, 2) as usize;
                m = ((e(opc, 0, 3) << 2 | (u32::from(opc23) & 3)) + 3) as usize;
                new_d = Some(usize::from(opc23 >> 2));
            }
            // lrg_d
            _ if opc & 7 == 7 => {
                opc_len = 3;
                l = e(opc, 6, 2) as usize;
                m = e(opc, 3, 3) as usize + 3;
                new_d = if src_len >= 3 { Some(usize::from(u16::from_le_bytes([src[sp + 1], src[sp + 2]]))) } else { None };
            }
            // pre_d
            _ if opc & 7 == 6 => {
                opc_len = 1;
                l = e(opc, 6, 2) as usize;
                m = e(opc, 3, 3) as usize + 3;
                new_d = Some(d);
            }
            // sml_d
            _ => {
                opc_len = 2;
                l = e(opc, 6, 2) as usize;
                m = e(opc, 3, 3) as usize + 3;
                new_d = if src_len >= 2 { Some((e(opc, 0, 3) as usize) << 8 | usize::from(src[sp + 1])) } else { None };
            }
        }
        // copy_literal_and_match
        good = LzvnEnd { src_used: sp, dst_at: dp, end_of_stream: false };
        if src_len <= opc_len + l {
            return good;
        }
        let Some(nd) = new_d else { return good };
        d = nd;
        sp += opc_len;
        if l > dst_len {
            return good_after_partial(src, dst, sp, dp, dst_len);
        }
        dst[dp..dp + l].copy_from_slice(&src[sp..sp + l]);
        dp += l;
        sp += l;
        if d > dp || d == 0 {
            // invalid_match_distance: the state stays the last good one.
            return good;
        }
        let dst_len = to - dp;
        if m > dst_len {
            return LzvnEnd { src_used: sp, dst_at: copy_match(dst, dp, d, dst_len), end_of_stream: false };
        }
        dp = copy_match(dst, dp, d, m);
    }
}

/// A literal the destination cannot hold: as much of it as fits.
fn good_after_partial(src: &[u8], dst: &mut [u8], sp: usize, dp: usize, n: usize) -> LzvnEnd {
    dst[dp..dp + n].copy_from_slice(&src[sp..sp + n]);
    LzvnEnd { src_used: sp + n, dst_at: dp + n, end_of_stream: false }
}

/// `n` bytes copied from `d` back, forwards (the overlapping copy a short
/// distance repeats); where the output then ends.
fn copy_match(dst: &mut [u8], dp: usize, d: usize, n: usize) -> usize {
    for i in 0..n {
        dst[dp + i] = dst[dp + i - d];
    }
    dp + n
}

#[cfg(test)]
mod tests {
    /// Streams the host's encoder made (GEX_TEST_LZFSE_DIR: `cN.lzfse`
    /// beside `cN.raw`, from `compression_tool -encode -a lzfse`) decode to
    /// their input, whole or cut short; the LZVN payloads of their `bvxn`
    /// blocks decode alone as the kernel's raw LZVN decoder takes them.
    #[test]
    fn host_encoded_streams() {
        let Ok(dir) = std::env::var("GEX_TEST_LZFSE_DIR") else { return };
        let mut n = 0;
        for e in std::fs::read_dir(&dir).unwrap() {
            let p = e.unwrap().path();
            if p.extension().and_then(|x| x.to_str()) != Some("lzfse") {
                continue;
            }
            let src = std::fs::read(&p).unwrap();
            let raw = std::fs::read(p.with_extension("raw")).unwrap();
            let mut out = vec![0u8; raw.len()];
            assert_eq!(decode_buffer(&src, &mut out), raw.len(), "{p:?}");
            assert!(out == raw, "{p:?}");
            let mut short = vec![0u8; raw.len() / 2];
            assert_eq!(decode_buffer(&src, &mut short), raw.len() / 2, "{p:?}");
            assert!(short[..] == raw[..raw.len() / 2], "{p:?}");
            if u32::from_le_bytes(src[..4].try_into().unwrap()) == COMPRESSEDLZVN_BLOCK_MAGIC {
                let n_payload = u32::from_le_bytes(src[8..12].try_into().unwrap()) as usize;
                let payload = &src[12..12 + n_payload];
                let mut out = vec![0u8; raw.len() + 64];
                assert_eq!(lzvn_decode_buffer(payload, &mut out), raw.len(), "{p:?}");
                assert!(out[..raw.len()] == raw[..], "{p:?}");
                let mut short = vec![0u8; raw.len() - 1];
                assert_eq!(lzvn_decode_buffer(payload, &mut short), raw.len() - 1, "{p:?}");
                assert!(short[..] == raw[..raw.len() - 1], "{p:?}");
                assert_eq!(lzvn_decode_buffer(&payload[..payload.len() - 1], &mut out), 0, "{p:?}");
            }
            n += 1;
        }
        assert!(n > 0);
    }

    use super::*;

    #[test]
    fn uncompressed_and_end() {
        let mut s = Vec::new();
        s.extend_from_slice(&UNCOMPRESSED_BLOCK_MAGIC.to_le_bytes());
        s.extend_from_slice(&3u32.to_le_bytes());
        s.extend_from_slice(b"abc");
        s.extend_from_slice(&ENDOFSTREAM_BLOCK_MAGIC.to_le_bytes());
        let mut d = [0u8; 3];
        assert_eq!(decode(&s, &mut d), Ok(s.len()));
        assert_eq!(&d, b"abc");
        let mut short = [0u8; 4];
        assert!(decode(&s, &mut short).is_err());
    }

    #[test]
    fn lzvn_literal_and_match() {
        // sml_l of 4 literals "abcd", then sml_d L=0 M=4 D=4, then eos.
        let mut s = vec![0xe4, b'a', b'b', b'c', b'd'];
        // sml_d: L in bits 6-7 (0), M-3 in bits 3-5 (1), D high in 0-2.
        s.push(0b00_001_000);
        s.push(4);
        s.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]);
        let mut block = COMPRESSEDLZVN_BLOCK_MAGIC.to_le_bytes().to_vec();
        block.extend_from_slice(&8u32.to_le_bytes());
        block.extend_from_slice(&(s.len() as u32).to_le_bytes());
        block.extend_from_slice(&s);
        block.extend_from_slice(&ENDOFSTREAM_BLOCK_MAGIC.to_le_bytes());
        let mut d = [0u8; 8];
        assert_eq!(decode(&block, &mut d), Ok(block.len()));
        assert_eq!(&d, b"abcdabcd");
    }

    #[test]
    fn freq_values() {
        assert_eq!(freq_value(0b00), (0, 2));
        assert_eq!(freq_value(0b111 | 0x50), (8 + 5, 8));
        assert_eq!(freq_value(0b1111 | (0x3ff << 4)), (24 + 0x3ff, 14));
    }
}
