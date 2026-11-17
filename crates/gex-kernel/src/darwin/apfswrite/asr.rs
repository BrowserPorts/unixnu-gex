//! asr's restore of the operating system image into a file on the System
//! volume, as the erase restore runs it (`asr -source asr://fd<N> -target
//! /mnt1/apfs_invert_asr_img --embed -erase …`, asr-615; restored_external
//! 0x10002d928) and as the kernel's APFS takes its calls:
//!
//! - the target: `open(O_RDWR | O_CREAT, 0644)`, `ftruncate` to the
//!   Apple_APFS partition's size (asr 0x10000c0ac..0x10000c12c), then
//!   `F_NOCACHE` and `F_SETSTATICCONTENT`, neither of which changes what is
//!   on disk (the latter an I/O hint, K 0x66d60d0);
//! - what is written: the partition's UDIF chunk table turned into copy
//!   instructions (asr 0x10000dcb0..0x10000df68): every chunk but the
//!   "ignore" ones (type 2, the free space the image's maker marked),
//!   runs of contiguous chunks of the same kind merged;
//! - how: MediaKit's IOEngine hands out each instruction in steps of the
//!   buffer size (1 MiB: 2048 sectors, asr 0x10002c664) from its start,
//!   each step one `pwrite` of its bytes at its offset (MK 0x16c04,
//!   MK 0x4950), in order;
//! - each `pwrite` a direct write whose block map allocates the sparse
//!   extent's blocks ([`fsops::write_sparse`]).
//!
//! Four MediaKit threads run steps concurrently; their data arrives in
//! file order, so the writes reach the kernel in step order (the order of
//! two concurrent `pwrite`s is not forced by asr: a stand-in, with the
//! kernel's transaction grouping, in [`super::restore::RUN_STAND_IN`]).

use super::fsops;
use super::tx::Nx;
use crate::darwin::apfsread::Medium;
use crate::darwin::udif::{chunk, Partition};

/// The image file's name in the System volume's root directory.
pub const IMAGE_NAME: &str = "apfs_invert_asr_img";
/// UDIF's sector.
const SECTOR: u64 = 512;
/// IOEngine's step: the buffer size over the block size (1 MiB).
const STEP_SECTORS: u64 = 2048;

/// A copy instruction: the partition's sectors from `start`, `count` of
/// them, to the same offset of the target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Instr {
    pub start: u64,
    pub count: u64,
}

/// The copy instructions of a partition's chunk table (asr
/// 0x10000dcb0..0x10000df68): compressed and raw chunks copy (code 8),
/// zero chunks fill (code 10), ignore chunks and comments make none; an
/// entry extends the instruction before it when it has its code and
/// starts where that one ends.
pub fn instructions(p: &Partition) -> Result<Vec<Instr>, String> {
    let mut out: Vec<(u32, Instr)> = Vec::new();
    for c in &p.chunks {
        let code = if c.kind >> 28 == 8 {
            8
        } else if c.kind == chunk::ZERO {
            10
        } else if c.kind == chunk::IGNORE {
            continue;
        } else if c.kind >> 28 == 0 {
            8
        } else {
            continue;
        };
        let start = c.sector - p.sector;
        match out.last_mut() {
            Some((pc, i)) if *pc == code && i.start + i.count == start => i.count += c.sectors,
            _ => out.push((code, Instr { start, count: c.sectors })),
        }
    }
    if out.iter().any(|(c, _)| *c == 10) {
        return Err("not implemented: asr's zero-fill instructions (code 10)".into());
    }
    Ok(out.into_iter().map(|(_, i)| i).collect())
}

/// The `pwrite`s of the instructions, in order: (byte offset, length).
pub fn writes(instrs: &[Instr]) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    for i in instrs {
        let mut at = i.start;
        while at < i.start + i.count {
            let n = (i.start + i.count - at).min(STEP_SECTORS);
            out.push((at * SECTOR, n * SECTOR));
            at += n;
        }
    }
    out
}

/// asr's run on the System volume (`vol`, mounted read-write): the image
/// file made and filled from `src` (the Apple_APFS partition's bytes, its
/// chunk table `part`). The image file's inode number.
pub fn restore_image(nx: &mut Nx<'_>, vol: usize, src: &dyn Medium, part: &Partition, now: &mut dyn FnMut() -> u64) -> Result<u64, String> {
    const ROOT_INO: u64 = 2;
    let size = part.sectors * SECTOR;
    if src.size() != size {
        return Err(format!("a source of {} bytes for a {size}-byte partition", src.size()));
    }
    let ino = fsops::create(nx, vol, ROOT_INO, IMAGE_NAME, 0o644, 0, 0, now)?.map_err(|e| format!("creating /{IMAGE_NAME}: errno {e}"))?;
    fsops::truncate_grow(nx, vol, ino, size, now)?;
    let mut buf = Vec::new();
    for (off, len) in writes(&instructions(part)?) {
        buf.resize(len as usize, 0);
        src.read_at(off, &mut buf)?;
        fsops::write_sparse(nx, vol, ino, off, &buf, now)?;
    }
    Ok(ino)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::darwin::udif::Chunk;

    fn c(kind: u32, sector: u64, sectors: u64) -> Chunk {
        Chunk { kind, sector, sectors, offset: 0, length: 0 }
    }

    /// Ignore chunks split the copy; raw and compressed chunks merge.
    #[test]
    fn chunk_table_to_instructions_and_writes() {
        let p = Partition {
            name: "Apple_APFS".into(),
            sector: 40,
            sectors: 9000,
            crc32: None,
            chunks: vec![c(chunk::LZFSE, 40, 2048), c(chunk::RAW, 2088, 100), c(chunk::IGNORE, 2188, 812), c(chunk::LZFSE, 3000, 6040), c(chunk::TERMINATOR, 9040, 0)],
        };
        let i = instructions(&p).unwrap();
        assert_eq!(i, vec![Instr { start: 0, count: 2148 }, Instr { start: 2960, count: 6040 }]);
        let w = writes(&i);
        assert_eq!(w[0], (0, 1 << 20));
        assert_eq!(w[1], (2048 * 512, 100 * 512));
        assert_eq!(w[2], (2960 * 512, 1 << 20));
        assert_eq!(w.len(), 2 + 3);
        assert_eq!(*w.last().unwrap(), ((2960 + 2 * 2048) * 512, (6040 - 2 * 2048) * 512));
    }

    /// The IPSW's system image (GEX_TEST_UDIF): three instructions, 5,506
    /// writes (re-asr-write.md A.3, A.5).
    #[test]
    fn the_system_image_writes() {
        let Ok(path) = std::env::var("GEX_TEST_UDIF") else { return };
        let f = std::fs::File::open(&path).unwrap();
        let len = f.metadata().unwrap().len();
        let u = crate::darwin::udif::Udif::open(std::sync::Arc::new(super::super::HostFile(f, len))).unwrap();
        let p = &u.partitions[u.partition("Apple_APFS").unwrap()];
        let i = instructions(p).unwrap();
        assert_eq!(i, vec![Instr { start: 0, count: 127_192 }, Instr { start: 524_288, count: 366_384 }, Instr { start: 1_048_576, count: 10_778_840 }]);
        let w = writes(&i);
        assert_eq!(w.len(), 5506);
        assert_eq!(w.iter().map(|x| x.1).sum::<u64>(), 5_771_476_992);
    }
}
