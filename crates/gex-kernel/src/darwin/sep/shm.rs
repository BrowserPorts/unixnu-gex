//! The shared memory buffer: one contiguous SEP-visible buffer with a
//! channel table at its start (`AppleSEPSharedMemoryBuffer`,
//! K 0xfffffff0063d79c4 `withChannels`, K 0xfffffff0063d0cfc
//! `_allocateShm`).
//!
//! The table has 16-byte entries `{u32 name, u32 size, u64 offset}` (a
//! channel's name is its four characters as a number, the first character
//! most significant) and ends with the sentinel `null`. The first channel
//! begins at the table's size rounded up to the SEP page, each channel's
//! size is rounded up to it, and its offset is where the one before it
//! ended. The SEP's page is 0x1000 on the J120 (its `sep` node has no
//! `aarch64`: `getSepPageSize`, K 0xfffffff0063b6190).

use super::frame::fourcc;
use super::mem::{SepMem, MAPPING_BOUNDARY};

/// `getSepPageSize()` without the `aarch64` property, and with it.
pub const SEP_PAGE: u64 = 0x1000;
pub const SEP_PAGE_AARCH64: u64 = 0x4000;

/// The channels' names.
pub mod chan {
    use super::fourcc;
    pub const PANIC: u32 = fourcc(b"PNIC");
    pub const FLAG: u32 = fourcc(b"FLAG");
    pub const CONSOLE: u32 = fourcc(b"CONS");
    pub const DEBUG: u32 = fourcc(b"DBUG");
    pub const CORE: u32 = fourcc(b"CORE");
    pub const TRACE: u32 = fourcc(b"TRAC");
    pub const TIDS: u32 = fourcc(b"TIDS");
    pub const DARG: u32 = fourcc(b"DARG");
    pub const MLOG: u32 = fourcc(b"MLOG");
    /// The fixed test object of `_loadChannelObjectEntries`'s table (the
    /// two named by device-tree properties of `/chosen/boot-object-manifests`
    /// are absent from the IPSW's tree, which iBoot fills).
    pub const TEST_OBJECT: u32 = 0x53434f54;
    pub const SENTINEL: u32 = fourcc(b"null");
}

/// The test object's data, which `_loadChannelObjectEntries` carries in
/// its table (K 0xfffffff0055340a0 region: "This is my wonderful test
/// data!"), 0x20 bytes with its terminator.
pub const TEST_OBJECT_DATA: &[u8; 32] = b"This is my wonderful test data!\0";

/// Sizes of the `full` boot's channels that `PE_parse_boot_argn` can
/// change: `sep-shmcon-size` for CONS and DBUG, `sep-trace-size` for TRAC.
pub const DEFAULT_SHMCON_SIZE: u64 = 0x4000;
pub const DEFAULT_TRACE_SIZE: u64 = 0x40000;

/// One channel of the layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Channel {
    pub name: u32,
    pub size: u64,
    pub offset: u64,
}

/// The layout of a table of `(name, size)` entries at page size `page`:
/// every channel's size and offset, and the whole buffer's length.
pub fn layout(entries: &[(u32, u64)], page: u64) -> (Vec<Channel>, u64) {
    let table = (entries.len() as u64 + 1) * 16;
    let mut off = (page + table - 1) & !(page - 1);
    let mut out = Vec::new();
    for &(name, size) in entries {
        let size = (size + page - 1) & !(page - 1);
        out.push(Channel { name, size, offset: off });
        off += size;
    }
    (out, off)
}

/// The entries `_allocateShm` makes: PNIC and FLAG, the boot objects, and
/// for a `full` boot the console, debug, core, trace, TIDS, DARG and MLOG
/// channels.
pub fn entries(full: bool, shmcon: u64, trace: u64) -> Vec<(u32, u64)> {
    let mut e = vec![(chan::PANIC, 0x8000), (chan::FLAG, 0x1000), (chan::TEST_OBJECT, TEST_OBJECT_DATA.len() as u64 + 4)];
    if full {
        e.extend([(chan::CONSOLE, shmcon), (chan::DEBUG, shmcon), (chan::CORE, 0x2000), (chan::TRACE, trace), (chan::TIDS, 0x4000), (chan::DARG, 0x1000), (chan::MLOG, 0x1000)]);
    }
    e
}

/// The buffer, in the pool.
#[derive(Clone)]
pub struct SharedMemory {
    mem: SepMem,
    /// The slave address the SEP is told (the physical address, with no
    /// mapper) and the buffer's length.
    pub address: u64,
    pub len: u64,
    channels: Vec<Channel>,
}

/// Why a buffer could not be made.
#[derive(Debug, PartialEq, Eq)]
pub enum ShmError {
    /// "size < sep_mapping_boundary" and the page multiple (`initWithOptionsAligned`).
    TooBig(u64),
    /// A trace or console size that is not a multiple of the SEP page.
    NotPageMultiple(&'static str, u64),
}

impl SharedMemory {
    /// `AppleSEPSharedMemoryBuffer::withChannels` over `entries`.
    pub fn new(mem: &SepMem, entries: &[(u32, u64)], page: u64) -> Result<SharedMemory, ShmError> {
        let (channels, len) = layout(entries, page);
        if len >= MAPPING_BOUNDARY {
            return Err(ShmError::TooBig(len));
        }
        let address = mem.alloc(len as usize, MAPPING_BOUNDARY);
        // The slave address range must not cross the 2 MiB mapping boundary: allocated on one, it cannot.
        debug_assert!(address % MAPPING_BOUNDARY < (address + len - 1) % MAPPING_BOUNDARY);
        let mut table = Vec::new();
        for c in &channels {
            table.extend_from_slice(&c.name.to_le_bytes());
            table.extend_from_slice(&(c.size as u32).to_le_bytes());
            table.extend_from_slice(&c.offset.to_le_bytes());
        }
        table.extend_from_slice(&chan::SENTINEL.to_le_bytes());
        table.extend_from_slice(&[0; 12]);
        mem.write(address, &table).expect("the table is inside its buffer");
        Ok(SharedMemory { mem: mem.clone(), address, len, channels })
    }

    pub fn channels(&self) -> &[Channel] {
        &self.channels
    }

    /// `findIndexForName`.
    pub fn find(&self, name: u32) -> Option<&Channel> {
        self.channels.iter().find(|c| c.name == name)
    }

    pub fn read_channel(&self, name: u32) -> Option<Vec<u8>> {
        let c = self.find(name)?;
        self.mem.bytes(self.address + c.offset, c.size as usize).ok()
    }

    pub fn write_channel(&self, name: u32, at: usize, data: &[u8]) -> bool {
        match self.find(name) {
            Some(c) if at + data.len() <= c.size as usize => self.mem.write(self.address + c.offset + at as u64, data).is_ok(),
            _ => false,
        }
    }

    /// The panic channel's state: the AP writes 1 to its first byte when it
    /// enables it (K 0xfffffff0063d84c0), and a SEP that panics overwrites it
    /// with the first character of its message: `buffer[0] > 0x1f`
    /// (K 0xfffffff0063d8508). The message is the channel's text.
    pub fn arm_panic_channel(&self) {
        self.write_channel(chan::PANIC, 0, &[1]);
    }

    pub fn panic_message(&self) -> Option<String> {
        let b = self.read_channel(chan::PANIC)?;
        if b.first().copied()? <= 0x1f {
            return None;
        }
        let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
        Some(String::from_utf8_lossy(&b[..end]).into_owned())
    }

    /// The boot objects' data: a channel's first u32 is the data's length
    /// and the data follows (`_loadChannelObjectData`).
    pub fn load_object(&self, name: u32, data: &[u8]) -> bool {
        self.write_channel(name, 0, &(data.len() as u32).to_le_bytes()) && self.write_channel(name, 4, data)
    }

    /// The FLAG channel: a length word 0x20, then `{u32 'xART', u32 oblit}`
    /// (`_loadFlagData`, K 0xfffffff0063d0b90).
    pub fn load_flags(&self, oblit: bool) -> bool {
        let mut v = Vec::new();
        v.extend_from_slice(&0x20u32.to_le_bytes());
        v.extend_from_slice(&fourcc(b"xART").to_le_bytes());
        v.extend_from_slice(&u32::from(oblit).to_le_bytes());
        self.write_channel(chan::FLAG, 0, &v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_boots_layout_is_the_kexts() {
        let e = entries(true, DEFAULT_SHMCON_SIZE, DEFAULT_TRACE_SIZE);
        let names: Vec<u32> = e.iter().map(|x| x.0).collect();
        assert_eq!(names, [chan::PANIC, chan::FLAG, chan::TEST_OBJECT, chan::CONSOLE, chan::DEBUG, chan::CORE, chan::TRACE, chan::TIDS, chan::DARG, chan::MLOG]);
        let (ch, len) = layout(&e, SEP_PAGE);
        // 10 entries and the sentinel: 176 bytes in the first page.
        assert_eq!(ch[0], Channel { name: chan::PANIC, size: 0x8000, offset: 0x1000 });
        assert_eq!(ch[1].offset, 0x9000);
        assert_eq!(ch[2], Channel { name: chan::TEST_OBJECT, size: 0x1000, offset: 0xa000 });
        assert_eq!(ch[5].size, 0x2000);
        assert_eq!(len, 0x5b000);
        for w in ch.windows(2) {
            assert_eq!(w[1].offset, w[0].offset + w[0].size);
        }
    }

    #[test]
    fn a_resume_builds_the_first_entries_only() {
        assert_eq!(entries(false, DEFAULT_SHMCON_SIZE, DEFAULT_TRACE_SIZE).len(), 3);
    }

    #[test]
    fn the_16kib_sep_page_moves_the_first_channel() {
        let e = entries(false, DEFAULT_SHMCON_SIZE, DEFAULT_TRACE_SIZE);
        let (ch, len) = layout(&e, SEP_PAGE_AARCH64);
        assert_eq!(ch[0].offset, 0x4000);
        assert_eq!(len, 0x4000 + 0x8000 + 0x4000 + 0x4000);
    }

    #[test]
    fn the_table_is_in_memory_with_its_sentinel() {
        let mem = SepMem::new();
        let s = SharedMemory::new(&mem, &entries(true, DEFAULT_SHMCON_SIZE, DEFAULT_TRACE_SIZE), SEP_PAGE).unwrap();
        assert_eq!(s.address % MAPPING_BOUNDARY, 0);
        let t = mem.bytes(s.address, 16 * 11).unwrap();
        assert_eq!(u32::from_le_bytes(t[0..4].try_into().unwrap()), chan::PANIC);
        assert_eq!(u32::from_le_bytes(t[4..8].try_into().unwrap()), 0x8000);
        assert_eq!(u64::from_le_bytes(t[8..16].try_into().unwrap()), 0x1000);
        assert_eq!(u32::from_le_bytes(t[160..164].try_into().unwrap()), chan::SENTINEL);
        assert_eq!(s.find(chan::TRACE).unwrap().size, 0x40000);
    }

    #[test]
    fn the_panic_channel_reports_a_message_the_sep_wrote() {
        let mem = SepMem::new();
        let s = SharedMemory::new(&mem, &entries(false, 0, 0), SEP_PAGE).unwrap();
        s.arm_panic_channel();
        assert_eq!(s.panic_message(), None);
        s.write_channel(chan::PANIC, 0, b"L4 panic: oops\0");
        assert_eq!(s.panic_message().as_deref(), Some("L4 panic: oops"));
    }

    #[test]
    fn objects_and_flags_are_length_prefixed() {
        let mem = SepMem::new();
        let s = SharedMemory::new(&mem, &entries(false, 0, 0), SEP_PAGE).unwrap();
        assert!(s.load_object(chan::TEST_OBJECT, TEST_OBJECT_DATA));
        let b = s.read_channel(chan::TEST_OBJECT).unwrap();
        assert_eq!(u32::from_le_bytes(b[..4].try_into().unwrap()), 0x20);
        assert_eq!(&b[4..4 + 31], &TEST_OBJECT_DATA[..31]);
        assert!(s.load_flags(true));
        let f = s.read_channel(chan::FLAG).unwrap();
        // 'xART' as the number 0x78415254, little endian.
        assert_eq!(&f[..12], &[0x20, 0, 0, 0, 0x54, 0x52, 0x41, 0x78, 1, 0, 0, 0]);
    }

    #[test]
    fn a_buffer_of_2mib_or_more_is_refused() {
        let mem = SepMem::new();
        assert_eq!(SharedMemory::new(&mem, &[(chan::TRACE, 0x200000)], SEP_PAGE).err(), Some(ShmError::TooBig(0x1000 + 0x200000)));
    }
}
