//! The memory the AP and the SEP both address: the web device's carve-outs
//! for the sepOS, the shared buffer and the endpoints' buffers.
//!
//! The SEP has no IOMapper on the J120 (the `sep` node has no
//! `iommu-parent` and `/arm-io` has no `dart-sep`), so every address the AP
//! gives it is a physical address: the firmware's
//! (`AppleSEPFirmware::_mapMemoryToSEP`), the shared memory's
//! (`IOSlaveMemoryBuffer::initWithOptions`: the slave address is
//! `getPhysicalAddress()`), the endpoints' OOL buffers'. gex has no AP DRAM
//! to point at, so the carve-outs are the web device's own: this pool hands
//! out physical addresses and holds their bytes, which the AP's side
//! (the manager) and the SEP core's (the harness) both read and write.
//! Nothing else observes the addresses.

use std::sync::{Arc, Mutex, MutexGuard};

/// Where the pool's addresses start: a 2 MiB boundary, as the manager's
/// shared buffer needs ("slaveAddress % sep_mapping_boundary ...").
pub const POOL_BASE: u64 = 0x8_0000_0000;

/// `sep_mapping_boundary`: a shared buffer's slave address range must not
/// cross a multiple of it (K 0xfffffff0063d78dc).
pub const MAPPING_BOUNDARY: u64 = 0x20_0000;

struct Region {
    base: u64,
    bytes: Vec<u8>,
}

#[derive(Default)]
struct Pool {
    regions: Vec<Region>,
    next: u64,
}

/// The pool, shared.
#[derive(Clone)]
pub struct SepMem(Arc<Mutex<Pool>>);

/// An access outside every region.
#[derive(Debug, PartialEq, Eq)]
pub struct Unmapped {
    pub address: u64,
    pub len: usize,
}

impl std::fmt::Display for Unmapped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} bytes at SEP-visible physical address {:#x}, which no carve-out holds", self.len, self.address)
    }
}

impl Default for SepMem {
    fn default() -> SepMem {
        SepMem::new()
    }
}

impl SepMem {
    pub fn new() -> SepMem {
        SepMem(Arc::new(Mutex::new(Pool { regions: Vec::new(), next: POOL_BASE })))
    }

    fn lock(&self) -> MutexGuard<'_, Pool> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A zeroed region of `size` bytes whose address is a multiple of
    /// `align` (a power of two); its physical address.
    pub fn alloc(&self, size: usize, align: u64) -> u64 {
        assert!(align.is_power_of_two());
        let mut p = self.lock();
        let base = (p.next + align - 1) & !(align - 1);
        p.next = base + (size as u64 + 0xfff & !0xfff);
        p.regions.push(Region { base, bytes: vec![0; size] });
        base
    }

    fn find<'a>(p: &'a mut Pool, address: u64, len: usize) -> Result<(&'a mut Region, usize), Unmapped> {
        let r = p.regions.iter_mut().find(|r| address >= r.base && address - r.base + len as u64 <= r.bytes.len() as u64);
        match r {
            Some(r) => {
                let off = (address - r.base) as usize;
                Ok((r, off))
            }
            None => Err(Unmapped { address, len }),
        }
    }

    pub fn read(&self, address: u64, out: &mut [u8]) -> Result<(), Unmapped> {
        let mut p = self.lock();
        let (r, off) = Self::find(&mut p, address, out.len())?;
        out.copy_from_slice(&r.bytes[off..off + out.len()]);
        Ok(())
    }

    pub fn write(&self, address: u64, data: &[u8]) -> Result<(), Unmapped> {
        let mut p = self.lock();
        let (r, off) = Self::find(&mut p, address, data.len())?;
        r.bytes[off..off + data.len()].copy_from_slice(data);
        Ok(())
    }

    pub fn bytes(&self, address: u64, len: usize) -> Result<Vec<u8>, Unmapped> {
        let mut v = vec![0; len];
        self.read(address, &mut v)?;
        Ok(v)
    }

    /// The size of the region at `address`, which must be its base.
    pub fn region_len(&self, address: u64) -> Option<usize> {
        self.lock().regions.iter().find(|r| r.base == address).map(|r| r.bytes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regions_are_aligned_disjoint_and_zeroed() {
        let m = SepMem::new();
        let a = m.alloc(0x5b000, MAPPING_BOUNDARY);
        let b = m.alloc(0x1000, 0x1000);
        assert_eq!(a % MAPPING_BOUNDARY, 0);
        assert!(b >= a + 0x5b000);
        assert_eq!(m.bytes(a, 16).unwrap(), vec![0; 16]);
        m.write(b + 8, b"abcd").unwrap();
        assert_eq!(m.bytes(b + 8, 4).unwrap(), b"abcd");
        assert_eq!(m.region_len(a), Some(0x5b000));
    }

    #[test]
    fn an_access_outside_a_region_is_named() {
        let m = SepMem::new();
        let a = m.alloc(0x1000, 0x1000);
        assert_eq!(m.read(a + 0xff8, &mut [0; 16]), Err(Unmapped { address: a + 0xff8, len: 16 }));
        assert!(m.write(0x1234, b"x").unwrap_err().to_string().contains("0x1234"));
    }
}
