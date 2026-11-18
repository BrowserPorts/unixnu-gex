//! The block store a root is kept in across loads (an `OPFSFilesystem`'s
//! `gex-fs-<name>/blocks`, a page's own store): its format and its blocks,
//! in one place for whatever reads or writes the store.
//!
//! - The kernel (gex-kernel `vfs::persist`, `vfs::blocks`) keeps the running
//!   tree's changes in it: [`format`] writes and reads its generations, and
//!   [`alloc::Allocator`] places its blocks.
//! - The page's offline editor ([`editor::Editor`], built alone as
//!   `store.wasm` by hosts/store) reads and writes the same records while no
//!   system holds the store: a file written there is one the next boot lays,
//!   and the records a run wrote are kept as they are.
//!
//! The store is one file of blocks of one size. Block 0 holds the two
//! superblocks; the rest are the records' chain and the files' bytes
//! ([`format`] says how).

pub mod alloc;
pub mod editor;
pub mod format;

/// A failure, as the kernel's errno: EIO, ENOSPC, and the like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl Errno {
    pub const ENOENT: Errno = Errno(2);
    pub const EIO: Errno = Errno(5);
    pub const ENXIO: Errno = Errno(6);
    pub const EEXIST: Errno = Errno(17);
    pub const ENOTDIR: Errno = Errno(20);
    pub const EISDIR: Errno = Errno(21);
    pub const EINVAL: Errno = Errno(22);
    pub const EFBIG: Errno = Errno(27);
    pub const ENOSPC: Errno = Errno(28);
}

/// The store file's operations, as its host takes them (hosts/browser
/// `blocks.mjs` `handleOp`): read or write `buf` at an offset, make the file
/// at least an offset long, or make what was written durable.
pub const OP_READ: u32 = 1;
pub const OP_WRITE: u32 = 2;
/// Make the store file at least `offset` bytes long (no buffer).
pub const OP_GROW: u32 = 4;
/// Make what was written durable (no offset, no buffer).
pub const OP_FLUSH: u32 = 8;
