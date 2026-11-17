//! DEFLATE (RFC 1951) decoding as libcompression's `COMPRESSION_ZLIB`
//! (0x205) `compression_decode_buffer` does it, in two copies
//! ([`Variant`]): AppleFSCompressionTypeZlib 163.140.2's, which decmpfs's
//! zlib chunks go through (0xfffffff006b22050 with its wrapper flag clear,
//! reached through the algorithm dispatch at 0xfffffff006b28f10; its block
//! decoder 0xfffffff006b22830, dynamic header 0xfffffff006b22f6c, code
//! tables 0xfffffff006b233b8), and the host's libcompression (macOS
//! 27.0.1: `zlib_decode_buffer`, `zlibDecodeBufferSafe`,
//! `readHuffmanTable`), which Apple Archive's pbz `z` chunks go through.
//! They differ only in one table's unused entries (below). The algorithm
//! is raw DEFLATE: both callers' chunks are RFC 1950 streams whose 2-byte
//! header they skip themselves, and nothing reads the Adler-32 trailer.
//!
//! The decoder fills the destination and gives the bytes it wrote. It
//! stops after the end-of-block code of a block marked final, and when a
//! literal finds the destination full, or a match or stored block fills it
//! (the rest of the stream is then not read). Anything else that ends the
//! decoding is a refusal, which gives 0 bytes ([`Error::Rejected`]):
//!
//! - a block header with fewer than 3 bits left, or type 3;
//! - a stored block with fewer than 16 bits left after its header (its
//!   LEN is read, its NLEN skipped unread; a stored block the input ends
//!   inside gives the bytes it holds, and the decoding stops there);
//! - a literal/length code begun with no bits left, or a length code with
//!   none left after it (codes and extra bits that run past the end are
//!   read with zeros there);
//! - length codes 286 and 287, distance codes 30 and 31, and a distance
//!   reaching before the destination's start;
//! - a dynamic header whose fields, code-length codes or repeat counts the
//!   input does not hold, or whose repeats run past 319 lengths.
//!
//! A code table is built from its lengths without checking that they make
//! a complete code: codes are given in symbol order, and where an
//! over-subscribed set's codes collide a later symbol's entry replaces the
//! earlier one's. HLIT may be up to 288 and HDIST up to 32. A repeat (16)
//! repeats the last length read as itself (0 before any), not one a 17 or
//! 18 wrote, and repeats may run past HLIT + HDIST. An incomplete code's
//! unused codes read the decoder's tables as they were: in the
//! literal/length and distance tables (kept in its scratch memory) an
//! entry an earlier block of the stream built, or, where none did, memory
//! the stream does not set ([`Error::Undefined`]); in the code-length
//! table, what [`Variant`] says.

/// Which copy of the decoder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    /// AppleFSCompressionTypeZlib 163.140.2's: the code-length table on
    /// the stack, zeroed for each header (0xfffffff006b230ac), so an
    /// unused code-length code is a length of 0 in 1 bit.
    Kernel,
    /// The host's libcompression: the code-length table on the stack over
    /// the array of next codes `readHuffmanTable` computed for it (16
    /// 32-bit words, each code's length counted in as it was given, those
    /// of length 0 in the first), so an unused code-length code among the
    /// first 32 reads half a word of it; past those, the stack memory a
    /// stream does not set.
    Host,
}

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
            Error::Rejected(why) => write!(f, "the DEFLATE decoder refuses the stream: {why}"),
            Error::Undefined(why) => write!(f, "the DEFLATE decoder reads memory the stream does not set: {why}"),
        }
    }
}

/// Lengths of length codes 257-285 (index 1-29), and of distance codes
/// 0-29 (0xfffffff0058731d8, 0xfffffff005873214).
const LENGTH_BASE: [u16; 30] = [0, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const DISTANCE_BASE: [u16; 30] = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];

/// The order code-length code lengths are stored in (0xfffffff005873350).
const CL_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/// The most lengths a dynamic header's repeats may reach.
const LENGTHS_MAX: usize = 319;

/// A table entry not written in this decoding (no entry has these bits:
/// the largest is symbol 319's with length 15).
const HOLE: u16 = u16::MAX;

/// The input as bits from the least significant of each byte, read past
/// its end as zeros.
struct Bits<'a> {
    src: &'a [u8],
    /// Bits consumed, which may pass the input's end.
    pos: u64,
}

impl Bits<'_> {
    fn left(&self) -> u64 {
        (self.src.len() as u64 * 8).saturating_sub(self.pos)
    }

    /// The next `n` (at most 32) bits.
    fn peek(&self, n: u32) -> u32 {
        let at = (self.pos >> 3) as usize;
        let window = match self.src.get(at..at.saturating_add(8)) {
            Some(b) => u64::from_le_bytes(b.try_into().unwrap()),
            None => self.src.get(at..).unwrap_or(&[]).iter().rev().fold(0u64, |v, &b| v << 8 | u64::from(b)),
        };
        ((window >> (self.pos & 7)) & ((1u64 << n) - 1)) as u32
    }

    fn take(&mut self, n: u32) -> u32 {
        let v = self.peek(n);
        self.pos += u64::from(n);
        v
    }
}

/// A code table: `1 << bits` entries, each a symbol (bits 4 up) and its
/// code's length less 1 (bits 0-3), indexed by the next `bits` input bits.
#[derive(Default)]
struct Table {
    entries: Vec<u16>,
    bits: u32,
}

impl Table {
    /// The table for code lengths `lens` (0xfffffff006b233b8): as many
    /// entries as the longest code (at least 1 bit) indexes, the rest of
    /// what the table held before left as it was.
    fn build(&mut self, lens: &[u8], fresh: u16) {
        let max = lens.iter().copied().max().unwrap_or(0).max(1);
        let size = 1usize << max;
        if self.entries.len() < size {
            self.entries.resize(size, fresh);
        }
        self.bits = u32::from(max);
        let mut count = [0u32; 16];
        for &l in lens {
            count[usize::from(l)] += 1;
        }
        count[0] = 0;
        let mut next = [0u32; 16];
        for l in 1..16 {
            next[l] = (next[l - 1] + count[l - 1]) << 1;
        }
        for (sym, &l) in lens.iter().enumerate() {
            if l == 0 {
                continue;
            }
            let code = next[usize::from(l)];
            next[usize::from(l)] += 1;
            // The code's low `l` bits, reversed: an over-subscribed set
            // wraps around onto earlier codes.
            let at = (code & ((1 << l) - 1)).reverse_bits() >> (32 - u32::from(l));
            let entry = (sym as u16) << 4 | u16::from(l - 1);
            let mut j = at as usize;
            while j < size {
                self.entries[j] = entry;
                j += 1 << l;
            }
        }
    }

    /// The entry the next bits index.
    fn get(&self, b: &Bits<'_>) -> u16 {
        self.entries[b.peek(self.bits) as usize]
    }
}

/// `compression_decode_buffer(dst, dst.len(), src, src.len(), _,
/// COMPRESSION_ZLIB)`: the bytes written, which may be 0.
pub fn decode_buffer(src: &[u8], dst: &mut [u8], variant: Variant) -> Result<usize, Error> {
    let mut b = Bits { src, pos: 0 };
    let (mut lit, mut dist) = (Table::default(), Table::default());
    let mut out = 0usize;
    let mut last = false;
    loop {
        if last {
            return Ok(out);
        }
        if b.left() < 3 {
            return Err(Error::Rejected("the input ends before a block header"));
        }
        last = b.take(1) == 1;
        match b.take(2) {
            0 => {
                if b.left() < 16 {
                    return Err(Error::Rejected("the input ends in a stored block's header"));
                }
                b.pos = (b.pos + 7) & !7;
                // At least 16 bits are left past the byte boundary.
                let len = b.peek(16) as usize;
                b.pos += 32;
                // NLEN may pass the input's end; then nothing is copied.
                let n = len.min((b.left() / 8) as usize).min(dst.len() - out);
                if n > 0 {
                    let at = (b.pos >> 3) as usize;
                    dst[out..out + n].copy_from_slice(&src[at..at + n]);
                }
                out += n;
                b.pos += 8 * n as u64;
                if n < len {
                    return Ok(out);
                }
                continue;
            }
            1 => {
                let mut lens = [0u8; 288];
                lens[..144].fill(8);
                lens[144..256].fill(9);
                lens[256..280].fill(7);
                lens[280..].fill(8);
                lit.build(&lens, HOLE);
                dist.build(&[5; 32], HOLE);
            }
            2 => dynamic_header(&mut b, &mut lit, &mut dist, variant)?,
            _ => return Err(Error::Rejected("block type 3")),
        }
        if let Some(n) = codes(&mut b, &lit, &dist, dst, &mut out)? {
            return Ok(n);
        }
    }
}

/// A dynamic block's header (0xfffffff006b22f6c), building its tables.
fn dynamic_header(b: &mut Bits<'_>, lit: &mut Table, dist: &mut Table, variant: Variant) -> Result<(), Error> {
    if b.left() < 14 {
        return Err(Error::Rejected("the input ends in a dynamic block's header"));
    }
    let hlit = b.take(5) as usize + 257;
    let hdist = b.take(5) as usize + 1;
    let hclen = b.take(4) as usize + 4;
    if b.left() < 3 * hclen as u64 {
        return Err(Error::Rejected("the input ends in a dynamic block's code-length code"));
    }
    let mut cl = [0u8; 19];
    for &i in &CL_ORDER[..hclen] {
        cl[i] = b.take(3) as u8;
    }
    let clt = cl_table(&cl, variant);
    let mut lens = [0u8; LENGTHS_MAX + 1];
    let (mut n, mut prev) = (0usize, 0u8);
    while n < hlit + hdist {
        let e = clt.get(b);
        if e == HOLE {
            return Err(Error::Undefined(format!("an unused code-length code at bit {}", b.pos)));
        }
        let len = u64::from(e & 15) + 1;
        if b.left() < len {
            return Err(Error::Rejected("the input ends in a code length"));
        }
        b.pos += len;
        let sym = e >> 4;
        let (base, bits, value) = match sym {
            0..=15 => {
                lens[n] = sym as u8;
                n += 1;
                prev = sym as u8;
                continue;
            }
            16 => (3, 2, prev),
            17 => (3, 3, 0),
            _ => (11, 7, 0),
        };
        if b.left() < u64::from(bits) {
            return Err(Error::Rejected("the input ends in a repeat count"));
        }
        let count = base + b.take(bits) as usize;
        if n + count > LENGTHS_MAX {
            return Err(Error::Rejected("code-length repeats past 319 lengths"));
        }
        lens[n..n + count].fill(value);
        n += count;
    }
    lit.build(&lens[..hlit], HOLE);
    dist.build(&lens[hlit..hlit + hdist], HOLE);
    Ok(())
}

/// The code-length code's table, over what the copy's stack holds there.
fn cl_table(cl: &[u8; 19], variant: Variant) -> Table {
    let mut t = Table { entries: vec![0; 128], bits: 0 };
    if variant == Variant::Host {
        t.entries.fill(HOLE);
        for (i, w) in next_codes(cl).into_iter().enumerate() {
            t.entries[2 * i] = w as u16;
            t.entries[2 * i + 1] = (w >> 16) as u16;
        }
    }
    t.build(cl, HOLE);
    t
}

/// The host's array of next codes for code lengths `lens` once each
/// symbol's code is given: the first code of each length (with the count of
/// length 0 taken as 0) plus the symbols of that length, and in word 0 the
/// symbols of length 0.
fn next_codes(lens: &[u8]) -> [u32; 16] {
    let mut count = [0u32; 16];
    for &l in lens {
        count[usize::from(l)] += 1;
    }
    let mut next = [0u32; 16];
    for l in 1..16 {
        next[l] = (next[l - 1] + if l == 1 { 0 } else { count[l - 1] }) << 1;
    }
    for l in 0..16 {
        next[l] += count[l];
    }
    next
}

/// A Huffman block's codes to its end of block (`None`), or to where the
/// destination is full (`Some`, the bytes written).
fn codes(b: &mut Bits<'_>, lit: &Table, dist: &Table, dst: &mut [u8], out: &mut usize) -> Result<Option<usize>, Error> {
    loop {
        if b.left() == 0 {
            return Err(Error::Rejected("the input ends before a literal/length code"));
        }
        let e = lit.get(b);
        if e == HOLE {
            return Err(Error::Undefined(format!("an unused literal/length code at bit {}", b.pos)));
        }
        b.pos += u64::from(e & 15) + 1;
        let sym = usize::from(e >> 4);
        if sym < 256 {
            if *out == dst.len() {
                return Ok(Some(*out));
            }
            dst[*out] = sym as u8;
            *out += 1;
            continue;
        }
        if sym == 256 {
            return Ok(None);
        }
        if b.left() == 0 {
            return Err(Error::Rejected("the input ends after a length code"));
        }
        let l = sym - 256;
        if l >= 30 {
            return Err(Error::Rejected("length code 286 or 287"));
        }
        let extra = if l < 9 || l == 29 { 0 } else { (l as u32 - 5) >> 2 };
        let length = usize::from(LENGTH_BASE[l]) + b.take(extra) as usize;
        let e = dist.get(b);
        if e == HOLE {
            return Err(Error::Undefined(format!("an unused distance code at bit {}", b.pos)));
        }
        if e >= 30 << 4 {
            return Err(Error::Rejected("distance code 30 or 31"));
        }
        b.pos += u64::from(e & 15) + 1;
        let d = usize::from(e >> 4);
        let extra = if d < 4 { 0 } else { (d as u32 - 2) >> 1 };
        let distance = usize::from(DISTANCE_BASE[d]) + b.take(extra) as usize;
        if distance > *out {
            return Err(Error::Rejected("a distance reaching before the output"));
        }
        let n = length.min(dst.len() - *out);
        for i in *out..*out + n {
            dst[i] = dst[i - distance];
        }
        *out += n;
        if n < length {
            return Ok(Some(*out));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DEFLATE bits, least significant first; Huffman codes most
    /// significant bit first.
    #[derive(Default)]
    struct W(Vec<bool>);

    impl W {
        fn put(&mut self, v: u32, n: u32) -> &mut Self {
            self.0.extend((0..n).map(|i| v >> i & 1 == 1));
            self
        }
        fn code(&mut self, c: u32, n: u32) -> &mut Self {
            self.0.extend((0..n).rev().map(|i| c >> i & 1 == 1));
            self
        }
        fn align(&mut self) -> &mut Self {
            while self.0.len() % 8 != 0 {
                self.0.push(false);
            }
            self
        }
        fn bytes(&self) -> Vec<u8> {
            self.0.chunks(8).map(|c| c.iter().enumerate().fold(0u8, |v, (i, &b)| v | u8::from(b) << i)).collect()
        }
        /// A fixed-code literal/length symbol.
        fn fixed(&mut self, sym: u32) -> &mut Self {
            match sym {
                0..=143 => self.code(0x30 + sym, 8),
                144..=255 => self.code(0x190 + sym - 144, 9),
                256..=279 => self.code(sym - 256, 7),
                _ => self.code(0xc0 + sym - 280, 8),
            }
        }
        /// A fixed-code length: its code and extra bits.
        fn length(&mut self, n: u32) -> &mut Self {
            let l = (1..30).rev().find(|&l| u32::from(LENGTH_BASE[l]) <= n && (l != 28 || n < 258)).unwrap();
            let extra = if l < 9 || l == 29 { 0 } else { (l as u32 - 5) >> 2 };
            self.fixed(256 + l as u32).put(n - u32::from(LENGTH_BASE[l]), extra)
        }
        /// A fixed-code distance: its code and extra bits.
        fn distance(&mut self, n: u32) -> &mut Self {
            let d = (0..30).rev().find(|&d| u32::from(DISTANCE_BASE[d]) <= n).unwrap();
            let extra = if d < 4 { 0 } else { (d as u32 - 2) >> 1 };
            self.code(d as u32, 5).put(n - u32::from(DISTANCE_BASE[d]), extra)
        }
    }

    fn dec(src: &[u8], n: usize) -> Result<Vec<u8>, Error> {
        let mut d = vec![0u8; n];
        let k = decode_buffer(src, &mut d, Variant::Kernel)?;
        d.truncate(k);
        Ok(d)
    }

    fn rejected(src: &[u8], n: usize) -> bool {
        matches!(decode_buffer(src, &mut vec![0u8; n], Variant::Kernel), Err(Error::Rejected(_)))
    }

    /// Canonical codes for `lens`, as RFC 1951 3.2.2 gives them.
    fn canonical(lens: &[u8]) -> Vec<u32> {
        let mut count = [0u32; 16];
        lens.iter().filter(|&&l| l != 0).for_each(|&l| count[usize::from(l)] += 1);
        let mut next = [0u32; 16];
        for l in 1..16 {
            next[l] = (next[l - 1] + count[l - 1]) << 1;
        }
        lens.iter()
            .map(|&l| {
                let c = next[usize::from(l)];
                next[usize::from(l)] += 1;
                c
            })
            .collect()
    }

    /// A dynamic block's header for literal/length lengths `lit` and
    /// distance lengths `dist`, each length sent as itself with a
    /// code-length code of 5-bit codes; the codes of both returned.
    fn dynamic(w: &mut W, last: bool, lit: &[u8], dist: &[u8]) -> (Vec<u32>, Vec<u32>) {
        w.put(u32::from(last), 1).put(2, 2);
        w.put(lit.len() as u32 - 257, 5).put(dist.len() as u32 - 1, 5).put(15, 4);
        let mut cl = [0u8; 19];
        cl[..16].fill(5);
        for i in CL_ORDER {
            w.put(u32::from(cl[i]), 3);
        }
        let clc = canonical(&cl);
        for &l in lit.iter().chain(dist) {
            w.code(clc[usize::from(l)], 5);
        }
        (canonical(lit), canonical(dist))
    }

    /// Streams beside what the host's `compression_decode_buffer`
    /// (`COMPRESSION_ZLIB`) made of each (GEX_TEST_INFLATE_CASES: a file of
    /// cases, each a u32 algorithm, destination size and source size, then
    /// the source; beside it, the same name with extensions `results` and
    /// `r00`, the calls' results with scratch memory filled with 0xa5 and
    /// with 0, each the u64 the call returned and the bytes it wrote). A
    /// stream whose results the scratch memory changes must be one this
    /// decoder finds reading memory the stream does not set; others must
    /// decode as the host decodes them.
    #[test]
    fn host_decodes() {
        let Ok(path) = std::env::var("GEX_TEST_INFLATE_CASES") else { return };
        let path = std::path::Path::new(&path);
        let cases = std::fs::read(path).unwrap();
        let results = [std::fs::read(path.with_extension("results")).unwrap(), std::fs::read(path.with_extension("r00")).unwrap()];
        let mut rat = [0usize; 2];
        let mut at = 0usize;
        let (mut n, mut accepted, mut undefined, mut host_undefined) = (0, 0, 0, 0);
        let u32_at = |b: &[u8], i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap()) as usize;
        while at < cases.len() {
            let (alg, dst_len, src_len) = (u32_at(&cases, at), u32_at(&cases, at + 4), u32_at(&cases, at + 8));
            assert_eq!(alg, 0x205);
            let src = &cases[at + 12..at + 12 + src_len];
            at += 12 + src_len;
            let host: Vec<&[u8]> = (0..2)
                .map(|i| {
                    let k = u64::from_le_bytes(results[i][rat[i]..rat[i] + 8].try_into().unwrap()) as usize;
                    let r = &results[i][rat[i]..rat[i] + 8 + k];
                    rat[i] += 8 + k;
                    r
                })
                .collect();
            let (k, want) = ((host[0].len() - 8), &host[0][8..]);
            let mut dst = vec![0u8; dst_len];
            match decode_buffer(src, &mut dst, Variant::Host) {
                Ok(got) => {
                    assert_eq!(host[0], host[1], "case {n}: the host's result depends on its scratch memory");
                    assert_eq!(got, k, "case {n}");
                    assert!(dst[..got] == *want, "case {n}");
                    accepted += usize::from(got > 0);
                }
                Err(Error::Rejected(why)) => {
                    assert_eq!(host[0], host[1], "case {n}: the host's result depends on its scratch memory");
                    assert_eq!(k, 0, "case {n}: {why}");
                }
                Err(Error::Undefined(_)) => {
                    undefined += 1;
                    host_undefined += usize::from(host[0] != host[1]);
                }
            }
            n += 1;
        }
        eprintln!("{n} streams: {accepted} decoded to bytes; {undefined} reading unset memory, of which the host's scratch changed {host_undefined}");
    }

    #[test]
    fn stored_blocks() {
        let mut w = W::default();
        w.put(1, 1).put(0, 2).align();
        let mut s = w.bytes();
        s.extend([5, 0, 0xfa, 0xff]);
        s.extend(b"hello");
        assert_eq!(dec(&s, 16).unwrap(), b"hello");
        // The destination full first: its bytes, the rest unread.
        assert_eq!(dec(&s, 3).unwrap(), b"hel");
        // NLEN is not checked.
        let mut bad = s.clone();
        bad[3] = 0;
        assert_eq!(dec(&bad, 16).unwrap(), b"hello");
        // Cut inside the data: what it holds; inside the header: refused.
        assert_eq!(dec(&s[..s.len() - 2], 16).unwrap(), b"hel");
        assert_eq!(dec(&s[..5], 16).unwrap(), b"");
        assert!(rejected(&s[..2], 16));
        // A block that is not the last needs another header after it, even
        // with the destination full.
        let mut w = W::default();
        w.put(0, 1).put(0, 2).align();
        let mut s = w.bytes();
        s.extend([2, 0, 0xfd, 0xff]);
        s.extend(b"ab");
        assert!(rejected(&s, 2));
        let mut w = W::default();
        w.put(1, 1).put(1, 2).fixed(256);
        s.extend(w.bytes());
        assert_eq!(dec(&s, 2).unwrap(), b"ab");
    }

    #[test]
    fn fixed_blocks() {
        let mut w = W::default();
        w.put(1, 1).put(1, 2).fixed(b'a'.into()).fixed(b'b'.into()).length(5).distance(2).fixed(256);
        let s = w.bytes();
        assert_eq!(dec(&s, 16).unwrap(), b"abababa");
        // A match the destination cuts, and one that finds it full.
        assert_eq!(dec(&s, 4).unwrap(), b"abab");
        assert_eq!(dec(&s, 2).unwrap(), b"ab");
        // An empty final block writes nothing.
        let mut w = W::default();
        w.put(1, 1).put(1, 2).fixed(256);
        assert_eq!(dec(&w.bytes(), 4).unwrap(), b"");
        assert!(rejected(&[], 4));
        // Block type 3.
        let mut w = W::default();
        w.put(1, 1).put(3, 2).put(0, 13);
        assert!(rejected(&w.bytes(), 4));
    }

    #[test]
    fn lengths_and_distances() {
        // The longest length (code 285, and code 284 with all its extra
        // bits set, both 258) and the farthest distance (32768).
        let mut w = W::default();
        w.put(1, 1).put(1, 2);
        for i in 0..32768u32 {
            w.fixed(i % 251);
        }
        w.length(258).distance(32768);
        w.fixed(284).put(31, 5).distance(1);
        w.fixed(256);
        let d = dec(&w.bytes(), 40000).unwrap();
        assert_eq!(d.len(), 32768 + 516);
        let want: Vec<u8> = (0..32768u32).map(|i| (i % 251) as u8).collect();
        assert_eq!(d[..32768], want[..]);
        assert_eq!(d[32768..32768 + 258], want[..258]);
        assert!(d[32768 + 258..].iter().all(|&c| c == want[257]));
        // Length codes 286, 287 and distance codes 30, 31: refused, even
        // with the destination full.
        for (len_code, dist_code) in [(286, 0), (287, 0), (257, 30), (257, 31)] {
            let mut w = W::default();
            w.put(1, 1).put(1, 2).fixed(b'a'.into()).fixed(len_code).code(dist_code, 5).fixed(256);
            assert!(rejected(&w.bytes(), 16), "{len_code} {dist_code}");
            assert!(rejected(&w.bytes(), 1), "{len_code} {dist_code}");
        }
        // A distance past the output's start.
        let mut w = W::default();
        w.put(1, 1).put(1, 2).fixed(b'a'.into()).length(3).distance(2).fixed(256);
        assert!(rejected(&w.bytes(), 16));
        assert!(rejected(&w.bytes(), 1));
    }

    #[test]
    fn input_end() {
        // Bits past the end read as zeros: the end-of-block code (seven
        // zeros) may run past it, but no code may start there.
        let mut w = W::default();
        w.put(1, 1).put(1, 2).fixed(b'a'.into()).fixed(b'b'.into()).fixed(256);
        let s = w.bytes();
        assert_eq!(s.len(), 4);
        assert_eq!(dec(&s[..3], 4).unwrap(), b"ab");
        assert!(rejected(&s[..2], 4));
        // A length code with no bits after it; with some, the distance
        // code and what follows read zeros.
        let mut w = W::default();
        w.put(1, 1).put(1, 2);
        for _ in 0..6 {
            w.fixed(200);
        }
        w.fixed(257);
        assert_eq!(w.0.len(), 64);
        assert!(rejected(&w.bytes(), 16));
        w.put(0, 8);
        assert_eq!(dec(&w.bytes(), 16).unwrap(), [200u8; 9]);
    }

    #[test]
    fn dynamic_blocks() {
        let mut lit = vec![0u8; 257];
        lit[usize::from(b'x')] = 1;
        lit[256] = 1;
        let mut w = W::default();
        let (lc, _) = dynamic(&mut w, true, &lit, &[1, 1]);
        w.code(lc[usize::from(b'x')], 1).code(lc[256], 1);
        assert_eq!(dec(&w.bytes(), 4).unwrap(), b"x");
        // HLIT 288 and HDIST 32 are taken; codes 286-287 and 30-31 refused
        // where used.
        let mut lit = vec![0u8; 288];
        for s in [usize::from(b'x'), 256, 257, 287] {
            lit[s] = 2;
        }
        let mut dl = vec![0u8; 32];
        dl[0] = 1;
        dl[31] = 1;
        let mut head = W::default();
        let (lc, dc) = dynamic(&mut head, true, &lit, &dl);
        let x = usize::from(b'x');
        let mut ok = W(head.0.clone());
        ok.code(lc[x], 2).code(lc[257], 2).code(dc[0], 1).code(lc[256], 2);
        assert_eq!(dec(&ok.bytes(), 8).unwrap(), b"xxxx");
        let mut bad = W(head.0.clone());
        bad.code(lc[x], 2).code(lc[257], 2).code(dc[31], 1).code(lc[256], 2);
        assert!(rejected(&bad.bytes(), 8));
        let mut bad = W(head.0);
        bad.code(lc[x], 2).code(lc[287], 2).code(dc[0], 1).code(lc[256], 2);
        assert!(rejected(&bad.bytes(), 8));
    }

    #[test]
    fn code_tables() {
        // Over-subscribed: three 1-bit codes; the third (code 2, low bit
        // 0) replaces the first.
        let mut t = Table::default();
        t.build(&[1, 1, 1], HOLE);
        assert_eq!(t.entries, [2 << 4, 1 << 4]);
        // Incomplete: an unused code is a hole, or what an earlier table
        // left there.
        let mut t = Table::default();
        t.build(&[2, 2, 0, 2], HOLE);
        assert_eq!(t.entries, [1, 3 << 4 | 1, 1 << 4 | 1, HOLE]);
        t.build(&[1, 1], HOLE);
        t.build(&[2, 0, 2], HOLE);
        assert_eq!(t.entries, [1, 1 << 4, 2 << 4 | 1, HOLE]);
        // No codes: a 1-bit table with no entries.
        let mut t = Table::default();
        t.build(&[0, 0], HOLE);
        assert_eq!((t.bits, t.entries.as_slice()), (1, [HOLE, HOLE].as_slice()));
    }

    /// An unused literal/length code reads memory the stream does not set,
    /// unless an earlier block's table left an entry there.
    #[test]
    fn unused_codes() {
        let x = usize::from(b'x');
        let mut lit = vec![0u8; 257];
        lit[x] = 2;
        lit[256] = 2;
        // 'x' is index 0, 256 index 2; 1 and 3 are unused.
        let mut w = W::default();
        let (lc, _) = dynamic(&mut w, true, &lit, &[1, 1]);
        w.code(lc[x], 2).put(0b11, 2);
        assert!(matches!(decode_buffer(&w.bytes(), &mut [0u8; 8], Variant::Kernel), Err(Error::Undefined(_))));
        // After a block whose 3-bit codes give 'a'-'g' and 256, index 3
        // (code 110) holds 'g'.
        let mut first = vec![0u8; 257];
        first[usize::from(b'a')..=usize::from(b'g')].fill(3);
        first[256] = 3;
        let mut w = W::default();
        let (fc, _) = dynamic(&mut w, false, &first, &[1, 1]);
        w.code(fc[usize::from(b'a')], 3).code(fc[256], 3);
        let (lc, _) = dynamic(&mut w, true, &lit, &[1, 1]);
        w.code(lc[x], 2).put(0b011, 3).code(lc[256], 2);
        assert_eq!(dec(&w.bytes(), 8).unwrap(), b"axg");
    }

    /// Repeats: 16 repeats the last length read as itself (0 before any,
    /// and across 17 and 18), and may run past HLIT + HDIST up to 319
    /// lengths.
    #[test]
    fn repeats() {
        let cl = canonical(&[5; 19]);
        let mut w = W::default();
        w.put(1, 1).put(2, 2).put(0, 5).put(0, 5).put(15, 4);
        for _ in CL_ORDER {
            w.put(5, 3);
        }
        // 16 before any length repeats 0 (lengths 0-5), 18 gives 114 zeros,
        // 'x' (120) is 1, then 135 zeros to 255.
        w.code(cl[16], 5).put(3, 2).code(cl[18], 5).put(103, 7);
        w.code(cl[1], 5).code(cl[18], 5).put(124, 7);
        let head = w.0.clone();
        // 16 repeats the 1 across the 18: 256, the distance code, and one
        // past HLIT + HDIST.
        w.code(cl[16], 5).put(0, 2);
        w.code(0, 1).code(1, 1);
        assert_eq!(dec(&w.bytes(), 4).unwrap(), b"x");
        // 18 up to 319 lengths: taken (the padding then decodes as 'x' to
        // the input's end); one more is refused.
        let mut far = W(head.clone());
        far.code(cl[18], 5).put(52, 7);
        assert_eq!(decode_buffer(&far.bytes(), &mut [0u8; 64], Variant::Kernel), Err(Error::Rejected("the input ends before a literal/length code")));
        let mut over = W(head);
        over.code(cl[18], 5).put(53, 7);
        assert_eq!(decode_buffer(&over.bytes(), &mut [0u8; 64], Variant::Kernel), Err(Error::Rejected("code-length repeats past 319 lengths")));
    }

    /// An unused code-length code: a length of 0 in 1 bit in the kernel's
    /// copy; in the host's, half a word of its next codes, or (past the
    /// first 32 entries) memory the stream does not set.
    #[test]
    fn unused_code_length_codes() {
        // Length 1 in 2 bits (00: entries 0 and 4), 16 in 3 (010: entry 2).
        let mut cl = [0u8; 19];
        cl[1] = 2;
        cl[16] = 3;
        // The host's next codes once given: 17 of length 0; length 2 from
        // 0, one given; length 3 from (0 + 1) << 1 = 2, one given.
        assert_eq!(next_codes(&cl)[..4], [17, 0, 1, 3]);
        let (one, rep) = (1 << 4 | 1, 16 << 4 | 2);
        assert_eq!(cl_table(&cl, Variant::Kernel).entries[..8], [one, 0, rep, 0, one, 0, 0, 0]);
        assert_eq!(cl_table(&cl, Variant::Host).entries[..8], [one, 0, rep, 0, one, 0, 3, 0]);
        // Entry 6 (bits 0, 1, 1): length 0 in 1 bit, or in 4.
        let mut w = W::default();
        w.put(1, 1).put(2, 2).put(0, 5).put(0, 5).put(15, 4);
        for i in CL_ORDER {
            w.put(u32::from(cl[i]), 3);
        }
        let start = w.0.len() as u64;
        w.put(0b0110, 4);
        let s = w.bytes();
        for (v, used) in [(Variant::Kernel, 1), (Variant::Host, 4)] {
            let t = cl_table(&cl, v);
            let b = Bits { src: &s, pos: start };
            assert_eq!(u64::from(t.get(&b) & 15) + 1, used);
        }
        // Past entry 31: a 6-bit code's unused entry 32.
        let mut cl = [0u8; 19];
        cl[0] = 6;
        let mut w = W::default();
        w.put(1, 1).put(2, 2).put(0, 5).put(0, 5).put(15, 4);
        for i in CL_ORDER {
            w.put(u32::from(cl[i]), 3);
        }
        w.put(0b100000, 6);
        for _ in 0..200 {
            w.put(0, 8);
        }
        let (mut l, mut d) = (Table::default(), Table::default());
        assert!(matches!(dynamic_header(&mut Bits { src: &w.bytes(), pos: 3 }, &mut l, &mut d, Variant::Host), Err(Error::Undefined(_))));
        assert!(dynamic_header(&mut Bits { src: &w.bytes(), pos: 3 }, &mut l, &mut d, Variant::Kernel).is_ok());
    }

    #[test]
    fn truncated_headers() {
        let mut w = W::default();
        w.put(1, 1).put(2, 2).put(0, 10);
        assert!(rejected(&w.bytes(), 4));
        let mut w = W::default();
        w.put(1, 1).put(2, 2).put(0, 10).put(15, 4);
        for _ in 0..18 {
            w.put(0, 3);
        }
        assert!(rejected(&w.bytes(), 4));
    }
}
