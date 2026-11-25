//! The page's disk0: the image the native host serves from a host file
//! (`GEX_DARWIN_DISK0`, [`super::apfswrite::HostFile`]), served in the page
//! by its global kernel to every process, without a copy of it anywhere.
//!
//! The image itself is read by ranges, where the page's server has it
//! (a synchronous ranged request in the reading Worker, the host's
//! `fetch`), a chunk at a time, the chunks read last kept in memory. What
//! the system writes never reaches the image: it goes to an overlay of
//! blocks, which a read takes before the image, as a device's own media
//! would hold it. A run keeps nothing of it past the page's life.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// The bytes one ranged request reads of the image, and the unit the
/// memory keeps.
pub const CHUNK: u64 = 64 << 10;

/// How many chunks the memory keeps (4 MiB of chunks per 64).
pub const CHUNKS_KEPT: usize = 1024;

/// The overlay's unit: a write of part of one fills the rest from the
/// image first.
pub const BLOCK: u64 = 4096;

/// The image's ranged read: `buf.len()` bytes from byte `off`, all of them
/// or none (false).
pub type Fetch = fn(url: &str, off: u64, buf: &mut [u8]) -> bool;

/// The device: the image's place and size, the chunks kept, the blocks
/// written.
pub struct Device {
    url: String,
    size: u64,
    /// What the image's build reported missing (its `.missing`), served
    /// to each process's disk nodes with it.
    missing: String,
    fetch: Fetch,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// Chunks of the image by number, each with when it was last used.
    kept: HashMap<u64, (Arc<[u8]>, u64)>,
    uses: u64,
    /// Written blocks by number, each whole.
    written: HashMap<u64, Box<[u8]>>,
}

impl Device {
    pub fn new(url: String, size: u64, missing: String, fetch: Fetch) -> Device {
        Device { url, size, missing, fetch, state: Mutex::new(State::default()) }
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn missing(&self) -> &str {
        &self.missing
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn check(&self, what: &str, off: u64, len: usize) -> Result<(), String> {
        match off.checked_add(len as u64) {
            Some(end) if end <= self.size => Ok(()),
            _ => Err(format!("a {what} of {len} bytes at {off} past disk0's {} bytes", self.size)),
        }
    }

    /// The image's chunks `first..=last`: those kept, and the rest read
    /// (without the lock: the image never changes, so a chunk read twice
    /// at once is the same bytes), then kept.
    fn chunks(&self, first: u64, last: u64) -> Result<HashMap<u64, Arc<[u8]>>, String> {
        let mut have = HashMap::new();
        let mut want = Vec::new();
        {
            let mut s = self.state();
            for k in first..=last {
                s.uses += 1;
                let now = s.uses;
                match s.kept.get_mut(&k) {
                    Some((c, used)) => {
                        *used = now;
                        have.insert(k, Arc::clone(c));
                    }
                    None => want.push(k),
                }
            }
        }
        // Adjacent chunks wanted together are one request.
        let mut i = 0;
        while i < want.len() {
            let mut j = i;
            while j + 1 < want.len() && want[j + 1] == want[j] + 1 {
                j += 1;
            }
            let lo = want[i] * CHUNK;
            let hi = ((want[j] + 1) * CHUNK).min(self.size);
            let mut b = vec![0u8; (hi - lo) as usize];
            if !(self.fetch)(&self.url, lo, &mut b) {
                return Err(format!("disk0's image at {}: its ranged read of {} bytes at {lo} failed", self.url, hi - lo));
            }
            let mut s = self.state();
            for (n, k) in (want[i]..=want[j]).enumerate() {
                let from = n * CHUNK as usize;
                let c: Arc<[u8]> = b[from..(from + CHUNK as usize).min(b.len())].into();
                s.uses += 1;
                let now = s.uses;
                s.kept.insert(k, (Arc::clone(&c), now));
                have.insert(k, c);
            }
            while s.kept.len() > CHUNKS_KEPT {
                let Some(old) = s.kept.iter().min_by_key(|(_, (_, used))| *used).map(|(k, _)| *k) else { break };
                s.kept.remove(&old);
            }
            i = j + 1;
        }
        Ok(have)
    }

    /// The image's bytes `[off, off + buf.len())` from `chunks`.
    fn from_image(chunks: &HashMap<u64, Arc<[u8]>>, off: u64, buf: &mut [u8]) {
        let mut at = 0;
        while at < buf.len() {
            let p = off + at as u64;
            let c = &chunks[&(p / CHUNK)];
            let o = (p % CHUNK) as usize;
            let n = (c.len() - o).min(buf.len() - at);
            buf[at..at + n].copy_from_slice(&c[o..o + n]);
            at += n;
        }
    }

    /// The disk's bytes at `off`: each block written from the overlay,
    /// every other byte the image's.
    pub fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<(), String> {
        self.check("read", off, buf.len())?;
        if buf.is_empty() {
            return Ok(());
        }
        let end = off + buf.len() as u64;
        // Which of the image's chunks the blocks not written need, asked
        // under the lock; then read; then the read made from the overlay
        // as it is then and the chunks.
        let need: Vec<u64> = {
            let s = self.state();
            let mut need = Vec::new();
            for b in off / BLOCK..end.div_ceil(BLOCK) {
                if !s.written.contains_key(&b) {
                    let (lo, hi) = ((b * BLOCK).max(off), ((b + 1) * BLOCK).min(end));
                    for k in lo / CHUNK..=(hi - 1) / CHUNK {
                        if need.last() != Some(&k) {
                            need.push(k);
                        }
                    }
                }
            }
            need
        };
        let mut chunks = HashMap::new();
        if let (Some(&first), Some(&last)) = (need.first(), need.last()) {
            chunks = self.chunks(first, last)?;
        }
        let s = self.state();
        for b in off / BLOCK..end.div_ceil(BLOCK) {
            let (lo, hi) = ((b * BLOCK).max(off), ((b + 1) * BLOCK).min(end));
            let dst = &mut buf[(lo - off) as usize..(hi - off) as usize];
            match s.written.get(&b) {
                Some(w) => dst.copy_from_slice(&w[(lo - b * BLOCK) as usize..(hi - b * BLOCK) as usize]),
                None => {
                    // A block written since the chunks were asked for:
                    // its chunk may not have been read.
                    if (lo / CHUNK..=(hi - 1) / CHUNK).any(|k| !chunks.contains_key(&k)) {
                        drop(s);
                        return self.read_at(off, buf);
                    }
                    Self::from_image(&chunks, lo, dst)
                }
            }
        }
        Ok(())
    }

    /// `buf` written at `off`, into the overlay: a block written in part
    /// takes the rest of its bytes from the disk as it was.
    pub fn write_at(&self, off: u64, buf: &[u8]) -> Result<(), String> {
        self.check("write", off, buf.len())?;
        if buf.is_empty() {
            return Ok(());
        }
        let end = off + buf.len() as u64;
        // The blocks written in part and not in the overlay yet, from the
        // image first.
        let partial: Vec<u64> = {
            let s = self.state();
            [off / BLOCK, (end - 1) / BLOCK]
                .into_iter()
                .filter(|&b| (b * BLOCK < off || (b + 1) * BLOCK > end) && !s.written.contains_key(&b))
                .fold(Vec::new(), |mut v, b| {
                    if v.last() != Some(&b) {
                        v.push(b);
                    }
                    v
                })
        };
        let mut base: HashMap<u64, Box<[u8]>> = HashMap::new();
        for b in partial {
            let lo = b * BLOCK;
            let hi = ((b + 1) * BLOCK).min(self.size);
            let chunks = self.chunks(lo / CHUNK, (hi - 1) / CHUNK)?;
            let mut blk = vec![0u8; BLOCK as usize];
            Self::from_image(&chunks, lo, &mut blk[..(hi - lo) as usize]);
            base.insert(b, blk.into_boxed_slice());
        }
        let mut s = self.state();
        for b in off / BLOCK..end.div_ceil(BLOCK) {
            let (lo, hi) = ((b * BLOCK).max(off), ((b + 1) * BLOCK).min(end));
            let blk = s.written.entry(b).or_insert_with(|| base.remove(&b).unwrap_or_else(|| vec![0u8; BLOCK as usize].into_boxed_slice()));
            blk[(lo - b * BLOCK) as usize..(hi - b * BLOCK) as usize].copy_from_slice(&buf[(lo - off) as usize..(hi - off) as usize]);
        }
        Ok(())
    }

    /// How many blocks the overlay holds.
    pub fn written_blocks(&self) -> usize {
        self.state().written.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// The image: byte `i` is `i * 7 + i / 4096` (mod 256), 40 chunks and
    /// a short one.
    const SIZE: u64 = 40 * CHUNK + 1000;
    static FETCHES: AtomicUsize = AtomicUsize::new(0);

    fn image_byte(i: u64) -> u8 {
        (i.wrapping_mul(7) + i / 4096) as u8
    }

    fn fetch(url: &str, off: u64, buf: &mut [u8]) -> bool {
        assert_eq!(url, "/disk0");
        if off + buf.len() as u64 > SIZE {
            return false;
        }
        FETCHES.fetch_add(1, Ordering::Relaxed);
        for (i, b) in buf.iter_mut().enumerate() {
            *b = image_byte(off + i as u64);
        }
        true
    }

    fn failing(_: &str, _: u64, _: &mut [u8]) -> bool {
        false
    }

    #[test]
    fn reads_are_the_image_and_writes_read_back_over_it() {
        let d = Device::new("/disk0".into(), SIZE, "a step\n".into(), fetch);
        assert_eq!((d.size(), d.missing()), (SIZE, "a step\n"));
        // Across a chunk boundary, and the short last chunk.
        let mut b = vec![0u8; 10_000];
        d.read_at(CHUNK - 5000, &mut b).unwrap();
        assert!(b.iter().enumerate().all(|(i, &v)| v == image_byte(CHUNK - 5000 + i as u64)));
        let mut tail = vec![0u8; 1000];
        d.read_at(SIZE - 1000, &mut tail).unwrap();
        assert!(tail.iter().enumerate().all(|(i, &v)| v == image_byte(SIZE - 1000 + i as u64)));
        // Past the end: refused, nothing read.
        assert!(d.read_at(SIZE - 10, &mut [0u8; 11]).is_err());
        assert!(d.write_at(SIZE, &[1]).is_err());
        // A write in part of two blocks keeps the rest of each.
        let w = vec![0xeeu8; 100];
        d.write_at(3 * BLOCK - 50, &w).unwrap();
        assert_eq!(d.written_blocks(), 2);
        let mut r = vec![0u8; 2 * BLOCK as usize];
        d.read_at(2 * BLOCK, &mut r).unwrap();
        for (i, &v) in r.iter().enumerate() {
            let at = 2 * BLOCK + i as u64;
            let want = if (3 * BLOCK - 50..3 * BLOCK + 50).contains(&at) { 0xee } else { image_byte(at) };
            assert_eq!(v, want, "byte {at}");
        }
        // A whole block over it, and a read of part of it.
        d.write_at(2 * BLOCK, &vec![0x11u8; BLOCK as usize]).unwrap();
        let mut p = [0u8; 8];
        d.read_at(3 * BLOCK - 4, &mut p).unwrap();
        assert_eq!(p, [0x11, 0x11, 0x11, 0x11, 0xee, 0xee, 0xee, 0xee]);
        // The image's last block, short of a whole one, written in part.
        d.write_at(SIZE - 3, &[9, 9, 9]).unwrap();
        let mut e = [0u8; 6];
        d.read_at(SIZE - 6, &mut e).unwrap();
        assert_eq!(e[..3], [image_byte(SIZE - 6), image_byte(SIZE - 5), image_byte(SIZE - 4)]);
        assert_eq!(e[3..], [9, 9, 9]);
    }

    #[test]
    fn chunks_are_kept_and_the_oldest_let_go() {
        let d = Device::new("/disk0".into(), SIZE, String::new(), fetch);
        let before = FETCHES.load(Ordering::Relaxed);
        let mut b = [0u8; 16];
        d.read_at(5 * CHUNK, &mut b).unwrap();
        d.read_at(5 * CHUNK + 100, &mut b).unwrap();
        // One request for the chunk, the second read from memory (other
        // tests may fetch meanwhile: at least one, and the chunk kept).
        assert!(FETCHES.load(Ordering::Relaxed) > before);
        assert!(d.state().kept.contains_key(&5));
        // Two chunks wanted together: one request each run of them.
        let mut big = vec![0u8; 3 * CHUNK as usize];
        d.read_at(10 * CHUNK, &mut big).unwrap();
        assert!(big.iter().enumerate().all(|(i, &v)| v == image_byte(10 * CHUNK + i as u64)));
        assert!((10..13).all(|k| d.state().kept.contains_key(&k)));
        // The memory's bound.
        let mut s = d.state();
        for k in 0..CHUNKS_KEPT as u64 + 10 {
            s.uses += 1;
            let u = s.uses;
            s.kept.insert(1000 + k, (Arc::from(vec![0u8; 1]), u));
        }
        drop(s);
        d.read_at(0, &mut b).unwrap();
        let s = d.state();
        assert_eq!(s.kept.len(), CHUNKS_KEPT);
        assert!(s.kept.contains_key(&0) && !s.kept.contains_key(&5));
    }

    #[test]
    fn a_failed_read_of_the_image_is_an_error() {
        let d = Device::new("/disk0".into(), SIZE, String::new(), failing);
        let e = d.read_at(0, &mut [0u8; 4]).unwrap_err();
        assert!(e.contains("ranged read"), "{e}");
        // A write in part of a block needs the image too.
        assert!(d.write_at(1, &[1]).is_err());
        // A whole block does not.
        d.write_at(BLOCK, &vec![3u8; BLOCK as usize]).unwrap();
        let mut b = [0u8; 4];
        d.read_at(BLOCK + 8, &mut b).unwrap();
        assert_eq!(b, [3; 4]);
    }
}
