//! LZBITMAP (`COMPRESSION_LZBITMAP`, 0x702), decoded as the kernel's own
//! decoder does it: AppleFSCompressionTypeZlib 163.140.2's copy of
//! libcompression's (0xfffffff006b2144c, reached through
//! 0xfffffff006b238cc from the algorithm dispatch at 0xfffffff006b28f10).
//! The format has no published specification; what follows is that code's.
//!
//! A stream is "ZBM", a flags byte, then blocks. The flags byte is at most
//! 0xf: its low two bits are the most a block expands to (0: 16 KiB, 1:
//! 32 KiB; 2 and 3 are refused); bit 2 stores a block's nibbles plainly
//! (else they are run-length coded) and gives its symbol table a sixteenth
//! entry; bit 3 makes three nibble values name a bitmap from the stream
//! (else four).
//!
//! A block starts with its length (header included) and its expanded
//! length, each 24 bits: length 6 and expanded length 0 end the stream;
//! a length 6 more than the expanded length holds the bytes as they are.
//! Any other block (32 bytes or more) has three more 24-bit offsets in the
//! block, A, B and C (15 <= A <= B <= C <= length - 17): literals from byte
//! 15, distances from A, bitmaps from B, nibbles from C up to the last 17
//! bytes, which hold the symbol table, 10-bit entries packed from the least
//! significant bit.
//!
//! The block's bytes are made eight at a time (a group), eight groups (64
//! bytes) a step, each group by its nibble. A nibble below the special
//! count takes its bitmap from the bitmap bytes and its distance width
//! from its own value; any other is a table entry: bitmap the low 8 bits,
//! width bits 8-9. A width of n reads the group's distance as the next n
//! bytes of the distance bytes, little-endian; width 0 repeats the
//! previous group's distance (8 at a block's start). Bit j of the bitmap
//! set makes byte j the next literal; clear, a copy of the byte that
//! distance back. Run-length coded nibbles: 0xf repeats the nibble before
//! it 3 more times and then as many more as the next nibble says, another
//! nibble following while the count is 0xf.
//!
//! The decoder's refusals all give 0 bytes ([`Error::Rejected`]); where it
//! reads memory the stream does not set (a group that copies bytes it has
//! not written yet, nibbles its run-length decoding reads past the block's,
//! or a block whose nibbles it never writes), the result is not the
//! stream's ([`Error::Undefined`]).

/// Why the decoder gives no bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The decoder returns 0, its callers' "decode failed".
    Rejected(&'static str),
    /// The decoder's result depends on memory the stream does not set.
    Undefined(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Rejected(why) => write!(f, "the LZBITMAP decoder refuses the stream: {why}"),
            Error::Undefined(why) => write!(f, "the LZBITMAP decoder reads memory the stream does not set: {why}"),
        }
    }
}

/// The bytes a stream starts with.
pub const MAGIC: [u8; 3] = *b"ZBM";

/// The bytes a block's header takes, and a compressed block's least.
const STORED_HEADER: usize = 6;
const COMPRESSED_HEADER: usize = 15;
const MIN_COMPRESSED: usize = 0x20;
/// The tail holding a compressed block's symbol table.
const TABLE_TAIL: usize = 17;
/// The run-length escape among the nibbles.
const RUN: u8 = 0xf;
/// The distance a block's first group repeats.
const FIRST_DISTANCE: u32 = 8;

fn u24(b: &[u8], at: usize) -> usize {
    usize::from(b[at]) | usize::from(b[at + 1]) << 8 | usize::from(b[at + 2]) << 16
}

/// The stream's settings, from its flags byte.
struct Flags {
    block_max: usize,
    plain_nibbles: bool,
    specials: usize,
    entries: usize,
}

impl Flags {
    fn of(f: u8) -> Result<Flags, Error> {
        if f > 0xf {
            return Err(Error::Rejected("flags above 0xf"));
        }
        if f & 3 >= 2 {
            return Err(Error::Rejected("a block size of 2 or 3"));
        }
        let specials = if f & 8 != 0 { 3 } else { 4 };
        let entries = if f & 8 != 0 { 12 } else { 11 } + usize::from(f & 4 != 0);
        Ok(Flags { block_max: if f & 3 == 0 { 0x4000 } else { 0x8000 }, plain_nibbles: f & 4 != 0, specials, entries })
    }
}

/// Decodes `src` into `dst`, as many bytes as the stream holds or `dst`
/// takes: how many. The decoder stops when `dst` is full, without reading
/// further; or at the end block.
pub fn decode(dst: &mut [u8], src: &[u8]) -> Result<usize, Error> {
    if (src.len() | dst.len()) as u64 >> 32 != 0 {
        return Err(Error::Rejected("a buffer of 4 GiB or more"));
    }
    if src.len() < 4 {
        return Err(Error::Rejected("a stream under 4 bytes"));
    }
    if src[..3] != MAGIC {
        return Err(Error::Rejected("no ZBM magic"));
    }
    let flags = Flags::of(src[3])?;
    if dst.is_empty() {
        return Err(Error::Rejected("no room for output"));
    }
    let mut d = Decoder { dst, undefined: None, lo: [0; 16], hi: [0; 16], nibbles: Vec::new() };
    let n = d.run(src, &flags)?;
    match d.undefined {
        Some(why) => Err(Error::Undefined(why)),
        None => Ok(n),
    }
}

struct Decoder<'a> {
    dst: &'a mut [u8],
    /// The first read of output the stream did not set.
    undefined: Option<String>,
    /// The symbol table: each entry's bitmap (low 8 bits) and distance
    /// width (bits 8-9); kept from block to block as the decoder keeps it.
    lo: [u8; 16],
    hi: [u8; 16],
    nibbles: Vec<u8>,
}

impl Decoder<'_> {
    fn run(&mut self, src: &[u8], flags: &Flags) -> Result<usize, Error> {
        let (mut pos, mut out) = (4usize, 0usize);
        loop {
            if pos + STORED_HEADER > src.len() {
                return Err(Error::Rejected("a block header past the stream's end"));
            }
            let len = u24(src, pos);
            let expanded = u24(src, pos + 3);
            if len == STORED_HEADER && expanded == 0 {
                return Ok(out);
            }
            if len < STORED_HEADER || expanded > flags.block_max || len > expanded + STORED_HEADER {
                return Err(Error::Rejected("a block's lengths"));
            }
            let end = (out + expanded).min(self.dst.len());
            // The decoder's sums are 32-bit: past the stream's end with
            // one that wraps, it would read memory that is not the stream's.
            let wraps = |n: usize| (n as u64) > u64::from(u32::MAX);
            if len == expanded + STORED_HEADER {
                let n = end - out;
                let to = pos + STORED_HEADER + n;
                if wraps(to) {
                    return Err(Error::Undefined("a stored block's bytes past the stream's end".into()));
                }
                if to > src.len() {
                    return Err(Error::Rejected("a stored block past the stream's end"));
                }
                self.dst[out..end].copy_from_slice(&src[pos + STORED_HEADER..to]);
            } else {
                if len < MIN_COMPRESSED {
                    return Err(Error::Rejected("a compressed block under 32 bytes"));
                }
                if wraps(pos + len) {
                    return Err(Error::Undefined("a compressed block past the stream's end".into()));
                }
                if pos + len > src.len() {
                    return Err(Error::Rejected("a compressed block past the stream's end"));
                }
                self.block(&src[pos..pos + len], flags, out, end)?;
            }
            pos += len;
            out = end;
            if out >= self.dst.len() {
                return Ok(out);
            }
        }
    }

    /// A compressed block `b`, made into `dst[out..end]`.
    fn block(&mut self, b: &[u8], flags: &Flags, out: usize, end: usize) -> Result<(), Error> {
        let len = b.len();
        let (a, bm, c) = (u24(b, 6), u24(b, 9), u24(b, 12));
        if a < COMPRESSED_HEADER || a > bm || bm > c || c > len - TABLE_TAIL {
            return Err(Error::Rejected("a block's stream offsets"));
        }
        // One nibble per group, a step's eight at a time.
        let count = ((end - out + 63) >> 3) & 0x1fff_fff8;
        for i in 0..flags.specials {
            self.lo[i] = 0;
            self.hi[i] = i as u8;
        }
        let table = len - TABLE_TAIL;
        for f in 0..flags.entries {
            let bit = f * 10;
            let v = u16::from_le_bytes([b[table + bit / 8], b[table + bit / 8 + 1]]) >> (bit & 6);
            self.lo[flags.specials + f] = v as u8;
            self.hi[flags.specials + f] = (v >> 8) as u8 & 3;
        }
        self.nibbles.clear();
        self.nibbles.resize(count, 0);
        if flags.plain_nibbles {
            if c + count / 2 > table {
                return Err(Error::Rejected("plain nibbles past the symbol table"));
            }
            for (i, &x) in b[c..c + count / 2].iter().enumerate() {
                self.nibbles[2 * i] = x & 0xf;
                self.nibbles[2 * i + 1] = x >> 4;
            }
        } else {
            let bytes = table - c;
            if bytes > flags.block_max >> 4 {
                return Err(Error::Rejected("run-length coded nibbles longer than a block's"));
            }
            // The decoder expands the coded nibbles 16 bytes at a time,
            // into the work buffer whose earlier content lies past them.
            let span = bytes.div_ceil(16) * 16;
            let coded: Vec<u8> = b[c..c + span].iter().flat_map(|&x| [x & 0xf, x >> 4]).collect();
            unrun(&coded, &mut self.nibbles)?;
        }
        let (mut lit, mut dist, mut maps) = (COMPRESSED_HEADER, a, bm);
        let mut last = FIRST_DISTANCE;
        let mut step = out;
        for s in 0..count / 8 {
            if maps + 8 > len {
                return Err(Error::Rejected("bitmap bytes past the block"));
            }
            if dist + 16 > len {
                return Err(Error::Rejected("distance bytes past the block"));
            }
            let n: [u8; 8] = self.nibbles[s * 8..s * 8 + 8].try_into().unwrap();
            let width = n.map(|x| self.hi[usize::from(x)]);
            let mut bitmap = [0u8; 8];
            let mut special = 0usize;
            for k in 0..8 {
                bitmap[k] = if usize::from(n[k]) < flags.specials {
                    special += 1;
                    b[maps + special - 1]
                } else {
                    self.lo[usize::from(n[k])]
                };
            }
            let first: usize = width[..4].iter().map(|&w| usize::from(w)).sum();
            let second: usize = width[4..].iter().map(|&w| usize::from(w)).sum();
            if dist + first + 16 > len {
                return Err(Error::Rejected("distance bytes past the block"));
            }
            let mut distance = [0u32; 8];
            let mut at = dist;
            for k in 0..8 {
                if k == 4 {
                    at = dist + first;
                }
                let w = usize::from(width[k]);
                distance[k] = if w == 0 {
                    if k == 0 { last } else { distance[k - 1] }
                } else {
                    let v = b[at..at + w].iter().rev().fold(0u32, |v, &x| v << 8 | u32::from(x));
                    at += w;
                    v
                };
            }
            // Where each group copies from; a group of literals alone is
            // not checked.
            let mut from = [0u32; 8];
            for k in 0..8 {
                let here = (step as u32).wrapping_add(8 * k as u32);
                if bitmap[k] != 0xff {
                    if distance[k] > here {
                        return Err(Error::Rejected("a distance before the output's start"));
                    }
                    from[k] = here - distance[k];
                }
            }
            if step + 64 > end {
                // The last step: byte by byte, to the block's end.
                let mut o = step;
                for k in 0..8 {
                    if lit + 8 > len {
                        return Err(Error::Rejected("literals past the block"));
                    }
                    if o >= end {
                        continue;
                    }
                    let mut j = 0;
                    loop {
                        let byte = if bitmap[k] >> j & 1 != 0 {
                            lit += 1;
                            b[lit - 1]
                        } else {
                            self.copied(from[k] as usize + j, o + j)
                        };
                        self.dst[o + j] = byte;
                        j += 1;
                        if j == 8 || o + j >= end {
                            break;
                        }
                    }
                    o += j;
                }
                return Ok(());
            }
            // Literals are fetched 16 at a time for each pair of groups.
            if lit + 16 > len {
                return Err(Error::Rejected("literals past the block"));
            }
            let mut pair = lit;
            for p in 0..3 {
                pair += (bitmap[2 * p].count_ones() + bitmap[2 * p + 1].count_ones()) as usize;
                if pair + 16 > len {
                    return Err(Error::Rejected("literals past the block"));
                }
            }
            // Each group's eight bytes are loaded from the output before
            // any of them is written.
            for k in 0..8 {
                let o = step + 8 * k;
                for j in 0..8 {
                    let byte = if bitmap[k] >> j & 1 != 0 {
                        lit += 1;
                        b[lit - 1]
                    } else {
                        self.copied(from[k] as usize + j, o)
                    };
                    self.dst[o + j] = byte;
                }
            }
            step += 64;
            maps += special;
            dist += first + second;
            last = distance[7];
        }
        Ok(())
    }

    /// The output byte at `at`, read while bytes from `written` on are not
    /// yet this block's.
    fn copied(&mut self, at: usize, written: usize) -> u8 {
        if at >= written {
            self.undefined.get_or_insert_with(|| format!("a copy of byte {at} before it is written (output up to {written})"));
            return 0;
        }
        self.dst[at]
    }
}

/// Run-length decoding of `coded` into all of `out` (0xfffffff006b20a98).
fn unrun(coded: &[u8], out: &mut [u8]) -> Result<(), Error> {
    if out.is_empty() {
        return Ok(());
    }
    let past = |i: usize| Error::Undefined(format!("run-length decoding reads nibble {i} of a block's {}", coded.len()));
    match coded.first() {
        None => return Err(past(0)),
        // The decoder writes nothing: the work buffer keeps what it held.
        Some(&RUN) => return Err(Error::Undefined("run-length coded nibbles that start with 0xf".into())),
        Some(_) => {}
    }
    let want = out.len();
    let fill = |out: &mut [u8], o: &mut usize, v: u8, n: usize| {
        let to = (*o + n).min(want);
        if *o < to {
            out[*o..to].fill(v);
        }
        *o += n;
    };
    let (mut i, mut o) = (0usize, 0usize);
    while o < want {
        let v = *coded.get(i).ok_or_else(|| past(i))?;
        i += 1;
        if v != RUN {
            out[o] = v;
            o += 1;
            continue;
        }
        let x = coded[i - 2];
        fill(out, &mut o, x, 3);
        loop {
            if o >= want {
                break;
            }
            let c = *coded.get(i).ok_or_else(|| past(i))?;
            i += 1;
            fill(out, &mut o, x, usize::from(c));
            if c != RUN {
                break;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn u24le(v: usize) -> [u8; 3] {
        [v as u8, (v >> 8) as u8, (v >> 16) as u8]
    }

    /// A compressed block from its parts: literals, distance bytes,
    /// bitmap bytes, nibble bytes, and table entries (from the first
    /// nibble past the specials).
    pub(crate) fn block(expanded: usize, lits: &[u8], dists: &[u8], maps: &[u8], nibbles: &[u8], entries: &[u16]) -> Vec<u8> {
        let a = COMPRESSED_HEADER + lits.len();
        let bm = a + dists.len();
        let c = bm + maps.len();
        let len = (c + nibbles.len() + TABLE_TAIL).max(MIN_COMPRESSED);
        let mut b = Vec::with_capacity(len);
        for v in [len, expanded, a, bm, c] {
            b.extend_from_slice(&u24le(v));
        }
        b.extend_from_slice(lits);
        b.extend_from_slice(dists);
        b.extend_from_slice(maps);
        b.extend_from_slice(nibbles);
        b.resize(len - TABLE_TAIL, 0);
        let mut t = 0u128;
        for (f, &e) in entries.iter().enumerate() {
            t |= u128::from(e & 0x3ff) << (10 * f);
        }
        b.extend_from_slice(&t.to_le_bytes());
        b.push(0);
        b
    }

    pub(crate) fn stream(flags: u8, blocks: &[Vec<u8>], end: bool) -> Vec<u8> {
        let mut s = b"ZBM".to_vec();
        s.push(flags);
        for b in blocks {
            s.extend_from_slice(b);
        }
        if end {
            s.extend_from_slice(&[6, 0, 0, 0, 0, 0]);
        }
        s
    }

    fn stored(data: &[u8]) -> Vec<u8> {
        let mut b = u24le(data.len() + 6).to_vec();
        b.extend_from_slice(&u24le(data.len()));
        b.extend_from_slice(data);
        b
    }

    /// Bytes `from..to`, and `n` copies of a slice.
    fn run(from: u8, to: u8) -> Vec<u8> {
        (from..to).collect()
    }
    fn times(s: &[u8], n: usize) -> Vec<u8> {
        s.repeat(n)
    }

    /// Table entries for three specials (flags bit 3): nibble 3 unused,
    /// 4 all literals, 5 all copies, both repeating the distance.
    const E3: [u16; 3] = [0x0fe, 0x0ff, 0x000];

    /// Streams with what the decoder makes of them, at a capacity; the
    /// last field says whether macOS's own libcompression (Darwin 27)
    /// decodes the stream as the kernel's copy does: it refuses flags
    /// without bit 3 and table entries of width 3, which the kernel's
    /// copy takes.
    pub(crate) fn cases() -> Vec<(&'static str, Vec<u8>, usize, Result<Vec<u8>, Error>, bool)> {
        let lits = run(0, 16);
        let copies = [run(0, 16), times(&run(8, 16), 6)].concat();
        // Groups 2 and 3 are specials: 1 (width 1, distance 16) with
        // bitmap 0x0f and 0 (width 0) with bitmap 0xf0; the rest copy.
        let specials = {
            let mut o = run(100, 120);
            o.extend_from_slice(&[104, 105, 106, 107, 108, 109, 110, 111]);
            o.extend(run(120, 124));
            let g = o[16..32].to_vec();
            o.extend_from_slice(&g);
            o.extend_from_slice(&g);
            o
        };
        let specials_block = block(64, &run(100, 124), &[16], &[0x0f, 0xf0], &[0x44, 0x01, 0x55, 0x55], &E3);
        let copies_block = block(64, &lits, &[], &[], &[0x44, 0x55, 0x55, 0x55], &E3);
        let pattern: Vec<u8> = (0..300u32).map(|i| (i * 7 + 3) as u8).collect();
        let hello = [stored(b"hello "), stored(b"world")];
        let big = stored(&[7; 0x4001]);
        let rejected = |w| Err(Error::Rejected(w));
        let undefined = Err(Error::Undefined(String::new()));
        vec![
            ("stored", stream(9, &hello, true), 64, Ok(b"hello world".to_vec()), true),
            ("stored_cut", stream(9, &hello, true), 8, Ok(b"hello wo".to_vec()), true),
            ("stored_full_without_end", stream(9, &hello, false), 11, Ok(b"hello world".to_vec()), true),
            ("stored_without_end", stream(9, &hello[..1], false), 64, rejected("a block header past the stream's end"), true),
            ("end_only", stream(9, &[], true), 64, Ok(Vec::new()), true),
            ("stored_32k", stream(9, &[big.clone()], true), 0x9000, Ok(vec![7; 0x4001]), true),
            ("stored_over_16k", stream(8, &[big], true), 0x9000, rejected("a block's lengths"), true),
            ("copies", stream(12, &[copies_block.clone()], true), 64, Ok(copies.clone()), true),
            ("coded_nibbles", stream(8, &[block(64, &lits, &[], &[], &[0x44, 0xf5, 0x03], &E3)], true), 64, Ok(copies.clone()), true),
            // 4, 4, then 5 repeated 3 + 15 + 15 times: the second count
            // is read while the output still wants nibbles.
            ("coded_runs", stream(8, &[block(160, &lits, &[], &[], &[0x44, 0xf5, 0xff, 0x01], &E3)], true), 160, Ok([run(0, 16), times(&run(8, 16), 18)].concat()), true),
            ("specials", stream(12, &[specials_block.clone()], true), 64, Ok(specials.clone()), true),
            ("two_blocks", stream(12, &[copies_block.clone(), specials_block.clone()], true), 128, Ok([copies.clone(), specials.clone()].concat()), true),
            ("two_blocks_cut", stream(12, &[copies_block, specials_block], true), 100, Ok([copies, specials[..36].to_vec()].concat()), true),
            // A last step under 64 bytes, byte by byte: distance 1 runs.
            ("last_step", stream(12, &[block(40, &lits[..8], &[1], &[], &[0x64, 0x55, 0x55, 0x55], &[0x0fe, 0x0ff, 0x000, 0x100])], true), 64, Ok([run(0, 8), vec![7; 32]].concat()), true),
            // A two-byte distance into an earlier block.
            ("width_2", stream(13, &[stored(&pattern), block(64, &[], &[0x2c, 0x01], &[], &[0x56, 0x55, 0x55, 0x55], &[0x0fe, 0x0ff, 0x000, 0x200])], true), 364, Ok([pattern.clone(), pattern[..64].to_vec()].concat()), true),
            ("distance_before_start", stream(12, &[block(64, &lits, &[], &[], &[0x55, 0x55, 0x55, 0x55], &E3)], true), 64, rejected("a distance before the output's start"), true),
            // All literals: the third pair's 16 start at 47 of 52 bytes.
            ("literals_past_block", stream(12, &[block(64, &lits, &[], &[], &[0x44; 4], &E3)], true), 64, rejected("literals past the block"), true),
            ("plain_nibbles_past_table", stream(12, &[block(256, &lits, &[], &[], &[0x44; 4], &E3)], true), 256, rejected("plain nibbles past the symbol table"), true),
            ("coded_nibbles_over_16k", stream(8, &[block(0x4000, &lits, &[], &[], &[0x44; 0x401], &E3)], true), 0x4000, rejected("run-length coded nibbles longer than a block's"), true),
            // Four specials (flags without bit 3): nibble 3 is a special of
            // width 3, entries start at nibble 4.
            ("four_specials", stream(4, &[block(64, &lits, &[16, 0, 0], &[0x00], &[0x44, 0x53, 0x55, 0x55], &[0x0ff, 0x000])], true), 64, Ok(times(&lits, 4)), false),
            ("four_specials_coded", stream(1, &[stored(b"ab"), block(64, &lits, &[16, 0, 0], &[0x00], &[0x44, 0x53, 0xf5, 0x01], &[0x0ff, 0x000])], true), 66, Ok([b"ab".to_vec(), times(&lits, 4)].concat()), false),
            ("width_3_entry", stream(12, &[block(64, &lits, &[16, 0, 0], &[], &[0x44, 0x56, 0x55, 0x55], &[0x0fe, 0x0ff, 0x000, 0x300])], true), 64, Ok(times(&lits, 4)), false),
            // Copies of bytes not written yet: inside a group's 8-byte load
            // (distance 1 in a full step), and distance 0 byte by byte.
            ("copy_inside_load", stream(12, &[block(64, &lits[..8], &[1], &[], &[0x64, 0x55, 0x55, 0x55], &[0x0fe, 0x0ff, 0x000, 0x100])], true), 64, undefined.clone(), true),
            ("copy_at_distance_0", stream(12, &[block(100, &run(0, 64), &[0], &[], &[0x44, 0x44, 0x44, 0x44, 0x56, 0x55, 0x55, 0x55], &[0x0fe, 0x0ff, 0x000, 0x100])], true), 128, undefined.clone(), true),
            ("coded_starting_with_run", stream(8, &[block(64, &lits, &[], &[], &[0x4f, 0x03], &E3)], true), 64, undefined, true),
        ]
    }

    fn dec(s: &[u8], cap: usize) -> Result<Vec<u8>, Error> {
        let mut d = vec![0u8; cap];
        let n = decode(&mut d, s)?;
        d.truncate(n);
        Ok(d)
    }

    #[test]
    fn streams_decode_as_the_format_says() {
        for (name, s, cap, want, _) in cases() {
            match (dec(&s, cap), want) {
                (Err(Error::Undefined(_)), Err(Error::Undefined(_))) => {}
                (got, want) => assert_eq!(got, want, "{name}"),
            }
        }
    }

    #[test]
    fn the_header_is_checked() {
        let ok = stream(9, &[stored(b"abc")], true);
        assert_eq!(dec(&ok, 16).unwrap(), b"abc");
        assert_eq!(dec(&ok, 0), Err(Error::Rejected("no room for output")));
        assert_eq!(dec(b"ZBM", 16), Err(Error::Rejected("a stream under 4 bytes")));
        assert_eq!(dec(b"ZBX\x09\x06\x00\x00\x00\x00\x00", 16), Err(Error::Rejected("no ZBM magic")));
        assert_eq!(dec(&stream(0x19, &[stored(b"abc")], true), 16), Err(Error::Rejected("flags above 0xf")));
        for f in [2, 3, 10, 11, 14, 15] {
            assert_eq!(dec(&stream(f, &[stored(b"abc")], true), 16), Err(Error::Rejected("a block size of 2 or 3")), "{f}");
        }
        // Every other flags value is taken.
        for f in [0, 1, 4, 5, 8, 9, 12, 13] {
            assert_eq!(dec(&stream(f, &[stored(b"abc")], true), 16).unwrap(), b"abc", "{f}");
        }
    }

    #[test]
    fn block_lengths_are_checked() {
        let lengths = |len: usize, expanded: usize| {
            let mut b = u24le(len).to_vec();
            b.extend_from_slice(&u24le(expanded));
            b.resize(len.max(6), 0);
            b
        };
        // Longer than its expansion and header, shorter than a header,
        // and compressed under 32 bytes.
        assert_eq!(dec(&stream(9, &[lengths(10, 3)], true), 64), Err(Error::Rejected("a block's lengths")));
        assert_eq!(dec(&stream(9, &[lengths(5, 3)], true), 64), Err(Error::Rejected("a block's lengths")));
        assert_eq!(dec(&stream(9, &[lengths(31, 64)], true), 64), Err(Error::Rejected("a compressed block under 32 bytes")));
        // A compressed block or a stored one cut by the stream; a stored
        // one only as far as the output reaches.
        let mut s = stream(12, &[block(64, &run(0, 16), &[], &[], &[0x44, 0x55, 0x55, 0x55], &E3)], false);
        s.pop();
        assert_eq!(dec(&s, 64), Err(Error::Rejected("a compressed block past the stream's end")));
        let mut s = stream(9, &[stored(b"hello")], false);
        s.pop();
        assert_eq!(dec(&s, 64), Err(Error::Rejected("a stored block past the stream's end")));
        assert_eq!(dec(&s, 4).unwrap(), b"hell");
    }

    #[test]
    fn stream_offsets_are_checked() {
        let good = block(64, &run(0, 16), &[], &[], &[0x44, 0x55, 0x55, 0x55], &E3);
        assert!(dec(&stream(12, &[good.clone()], true), 64).is_ok());
        // A inside the header, B before A, C into the table.
        for (at, v) in [(6, 14usize), (9, 30), (12, good.len() - 16)] {
            let mut b = good.clone();
            b[at..at + 3].copy_from_slice(&u24le(v));
            assert_eq!(dec(&stream(12, &[b], true), 64), Err(Error::Rejected("a block's stream offsets")), "{at}");
        }
    }

    #[test]
    fn run_length_nibbles() {
        let mut out = [0u8; 12];
        // 1, 2, then 2 repeated 3 + 4 times, then 5, then 5 repeated 3.
        unrun(&[1, 2, 0xf, 4, 5, 0xf, 0], &mut out).unwrap();
        assert_eq!(out, [1, 2, 2, 2, 2, 2, 2, 2, 2, 5, 5, 5]);
        // A count of 0xf reads another.
        let mut out = [0u8; 21];
        unrun(&[3, 0xf, 0xf, 2], &mut out).unwrap();
        assert_eq!(out, [3; 21]);
        // A run right after a run repeats the count nibble before it.
        let mut out = [0u8; 9];
        unrun(&[1, 0xf, 2, 0xf, 0, 9], &mut out).unwrap();
        assert_eq!(out, [1, 1, 1, 1, 1, 1, 2, 2, 2]);
        // Starting with 0xf, or running out of nibbles.
        assert!(matches!(unrun(&[0xf, 1], &mut [0u8; 4]), Err(Error::Undefined(_))));
        assert!(matches!(unrun(&[1, 2], &mut [0u8; 4]), Err(Error::Undefined(_))));
        assert!(matches!(unrun(&[], &mut [0u8; 4]), Err(Error::Undefined(_))));
        unrun(&[], &mut []).unwrap();
    }
}
