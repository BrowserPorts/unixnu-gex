//! Kernel chunked data (`osfmk/kern/kern_cdata.c`, `kern/kcdata.h`): a
//! buffer of items, each a 16-byte header (type, size, flags) and a payload
//! padded to 16 bytes, opened by a begin item and closed by an end marker
//! that each addition rewrites past itself. A corpse's crash information is
//! one ([`super::corpse`]), made with `KCFLAG_USE_MEMCOPY` in a kernel
//! allocation.

/// `KCDATA_TYPE_ARRAY_PAD0`: an array whose element type and count are in
/// the header's flags, its padding in the type's low four bits.
pub const TYPE_ARRAY_PAD0: u32 = 0x20;
/// `KCDATA_TYPE_NESTED_KCDATA`.
pub const TYPE_NESTED_KCDATA: u32 = 0x38;
/// `KCDATA_TYPE_BUFFER_END`.
pub const TYPE_BUFFER_END: u32 = 0xF191_58ED;
/// `KCDATA_BUFFER_BEGIN_CRASHINFO` (`TASK_CRASHINFO_BEGIN`).
pub const BUFFER_BEGIN_CRASHINFO: u32 = 0xDEAD_F157;

/// `KCDATA_FLAGS_STRUCT_PADDING_MASK`, `KCDATA_FLAGS_STRUCT_HAS_PADDING`.
const FLAGS_STRUCT_PADDING_MASK: u64 = 0xf;
const FLAGS_STRUCT_HAS_PADDING: u64 = 0x80;

/// `KCFLAG_NO_AUTO_ENDBUFFER`.
pub const KCFLAG_NO_AUTO_ENDBUFFER: u16 = 0x2;

/// `sizeof(struct kcdata_item)`.
pub const ITEM: usize = 16;

/// `KERN_INVALID_ARGUMENT`, `KERN_INSUFFICIENT_BUFFER_SIZE`.
const KERN_INVALID_ARGUMENT: u32 = 4;
const KERN_INSUFFICIENT_BUFFER_SIZE: u32 = 52;

/// `kcdata_calc_padding`: what makes `size` a multiple of 16.
pub fn calc_padding(size: u32) -> u32 {
    size.wrapping_neg() & 0xf
}

/// A `kcdata_descriptor` over a buffer of its own (`kcd_addr_begin` is
/// offset 0, `kcd_addr_end` is [`Kcdata::end`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Kcdata {
    buf: Vec<u8>,
    /// `kcd_addr_end`, as an offset.
    end: usize,
    /// `kcd_length`.
    length: usize,
    /// `kcd_flags`.
    flags: u16,
}

impl Kcdata {
    /// `kcdata_memory_alloc_init` over a zeroed allocation of `size` bytes
    /// (`kalloc_data(..., Z_ZERO)`): the begin item of type `data_type`
    /// written, or none when it does not fit.
    pub fn alloc_init(data_type: u32, size: usize, flags: u16) -> Option<Kcdata> {
        let mut k = Kcdata { buf: vec![0; size], end: 0, length: size, flags };
        k.get_memory_addr(data_type, 0).ok()?;
        Some(k)
    }

    /// `kcdata_get_memory_addr`: room for an item of `size` bytes, its
    /// padding recorded in the low bits of its flags.
    pub fn get_memory_addr(&mut self, ty: u32, size: u32) -> Result<usize, u32> {
        let flags = (FLAGS_STRUCT_PADDING_MASK & u64::from(calc_padding(size))) | FLAGS_STRUCT_HAS_PADDING;
        self.with_flavor(ty, size, flags)
    }

    /// `kcdata_get_memory_addr_for_array`: `count` elements of
    /// `elem_type`, each `elem_size` bytes.
    pub fn get_memory_addr_for_array(&mut self, elem_type: u32, elem_size: u32, count: u32) -> Result<usize, u32> {
        let flags = (u64::from(elem_type) << 32) | u64::from(count);
        let total = count.wrapping_mul(elem_size);
        let pad = calc_padding(total);
        self.with_flavor(TYPE_ARRAY_PAD0 | pad, total, flags)
    }

    /// `kcdata_get_memory_addr_with_flavor`: the header written, the
    /// padding zeroed, the end marker rewritten past the item; the
    /// payload's offset.
    fn with_flavor(&mut self, ty: u32, size: u32, flags: u64) -> Result<usize, u32> {
        let orig = size;
        let padding = calc_padding(size);
        let size = size.wrapping_add(padding);
        let total = size.wrapping_add(ITEM as u32);
        if total.wrapping_add(ITEM as u32) < orig {
            return Err(KERN_INVALID_ARGUMENT);
        }
        let need = total as usize + ITEM;
        if need > self.length || self.length - need < self.end {
            return Err(KERN_INSUFFICIENT_BUFFER_SIZE);
        }
        let at = self.end;
        self.buf[at..at + 4].copy_from_slice(&ty.to_le_bytes());
        self.buf[at + 4..at + 8].copy_from_slice(&size.to_le_bytes());
        self.buf[at + 8..at + 16].copy_from_slice(&flags.to_le_bytes());
        self.end += ITEM;
        if padding != 0 {
            let p = self.end + size as usize - padding as usize;
            self.buf[p..p + padding as usize].fill(0);
        }
        let payload = self.end;
        self.end += size as usize;
        if self.flags & KCFLAG_NO_AUTO_ENDBUFFER == 0 {
            self.write_buffer_end();
        }
        Ok(payload)
    }

    /// `kcdata_write_buffer_end`: the end marker at the end, which stays
    /// where it is.
    pub fn write_buffer_end(&mut self) {
        let at = self.end;
        self.buf[at..at + 4].copy_from_slice(&TYPE_BUFFER_END.to_le_bytes());
        self.buf[at + 4..at + ITEM].fill(0);
    }

    /// `kcdata_memcpy` at a payload offset.
    pub fn memcpy(&mut self, at: usize, data: &[u8]) {
        self.buf[at..at + data.len()].copy_from_slice(data);
    }

    /// An item of type `ty` holding `data`, as `kcdata_get_memory_addr`
    /// and `kcdata_memcpy` make it; nothing when it does not fit.
    pub fn put(&mut self, ty: u32, data: &[u8]) -> bool {
        match self.get_memory_addr(ty, data.len() as u32) {
            Ok(at) => {
                self.memcpy(at, data);
                true
            }
            Err(_) => false,
        }
    }

    /// The same for an array of `count` elements of `elem_size` bytes.
    pub fn put_array(&mut self, elem_type: u32, elem_size: u32, count: u32, data: &[u8]) -> bool {
        match self.get_memory_addr_for_array(elem_type, elem_size, count) {
            Ok(at) => {
                self.memcpy(at, data);
                true
            }
            Err(_) => false,
        }
    }

    /// `kcdata_memory_get_used_bytes`: the items and the end marker.
    pub fn used_bytes(&self) -> usize {
        self.end + ITEM
    }

    /// The whole allocation, as `kcd_addr_begin` holds it.
    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }
}

/// The items of a kcdata buffer, in order, up to its end marker: (type,
/// flags, payload). For readers here and tests.
pub fn items(buf: &[u8]) -> Vec<(u32, u64, &[u8])> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + ITEM <= buf.len() {
        let ty = u32::from_le_bytes(buf[at..at + 4].try_into().unwrap());
        let size = u32::from_le_bytes(buf[at + 4..at + 8].try_into().unwrap()) as usize;
        let flags = u64::from_le_bytes(buf[at + 8..at + 16].try_into().unwrap());
        if ty == TYPE_BUFFER_END || at + ITEM + size > buf.len() {
            break;
        }
        out.push((ty, flags, &buf[at + ITEM..at + ITEM + size]));
        at += ITEM + size;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn begin_item_and_end_marker() {
        let k = Kcdata::alloc_init(BUFFER_BEGIN_CRASHINFO, 0x4000, 0).unwrap();
        let b = k.bytes();
        assert_eq!(&b[0..4], &BUFFER_BEGIN_CRASHINFO.to_le_bytes());
        assert_eq!(&b[4..8], &0u32.to_le_bytes());
        assert_eq!(&b[8..16], &0x80u64.to_le_bytes());
        assert_eq!(&b[16..20], &TYPE_BUFFER_END.to_le_bytes());
        assert_eq!(k.used_bytes(), 32);
    }

    #[test]
    fn items_are_padded_to_sixteen() {
        let mut k = Kcdata::alloc_init(BUFFER_BEGIN_CRASHINFO, 0x4000, 0).unwrap();
        assert!(k.put(0x805, &7i32.to_le_bytes()));
        assert!(k.put(0x809, b"seventeen bytes!\0"));
        let it = items(k.bytes());
        assert_eq!(it.len(), 3);
        // a pid: 4 bytes, 12 of padding (flags 0x8c, as the release
        // kernel's calls pass)
        assert_eq!((it[1].0, it[1].1, it[1].2.len()), (0x805, 0x8c, 16));
        assert_eq!((it[2].0, it[2].1, it[2].2.len()), (0x809, 0x8f, 32));
        assert_eq!(k.used_bytes(), 16 + 32 + 48 + 16);
    }

    #[test]
    fn arrays_carry_type_and_count() {
        let mut k = Kcdata::alloc_init(BUFFER_BEGIN_CRASHINFO, 0x4000, 0).unwrap();
        assert!(k.put_array(0x81b, 8, 2, &[1u8; 16]));
        let it = items(k.bytes());
        // the coalition ids: KCDATA_TYPE_ARRAY_PAD0, (0x81b << 32) | 2
        assert_eq!((it[1].0, it[1].1, it[1].2.len()), (0x20, (0x81b << 32) | 2, 16));
        let mut k = Kcdata::alloc_init(BUFFER_BEGIN_CRASHINFO, 0x4000, 0).unwrap();
        assert!(k.put_array(0x81c, 8, 3, &[0u8; 24]));
        assert_eq!(items(k.bytes())[1].0, 0x28);
    }

    #[test]
    fn a_full_buffer_refuses() {
        let mut k = Kcdata::alloc_init(BUFFER_BEGIN_CRASHINFO, 64, 0).unwrap();
        // 16 used, 16 for the end marker: room for one 16-byte item
        assert_eq!(k.get_memory_addr(1, 17), Err(52));
        assert!(k.get_memory_addr(1, 16).is_ok());
        assert_eq!(k.get_memory_addr(1, 0), Err(52));
    }
}
