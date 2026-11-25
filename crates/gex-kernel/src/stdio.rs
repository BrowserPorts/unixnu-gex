//! The standard streams.
//!
//! On the native runtime these pass through to the host's stdio. In the
//! browser the same descriptors are backed by the terminal, which is why they
//! are a [`FileHandle`] like anything else rather than a special case in the
//! syscall layer.

use crate::errno::{Errno, SysResult};
use crate::vfs::{FileHandle, FileType, Metadata};
use std::io::{Read, Write};

/// Which standard stream a handle refers to.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Stream {
    In,
    Out,
    Err,
}

/// Whether the host's stdin has data or has hit end of file, without
/// reading it. The kernel has no host-system calls of its own, so the
/// embedder sets this (gexc: `poll` on fd 0). Unset, stdin is always
/// "readable", which a `select` on an empty pipe gets wrong: the guest then
/// blocks in `read` (a game server that polls its console every frame
/// stops dead).
pub static STDIN_READY: std::sync::OnceLock<fn() -> bool> = std::sync::OnceLock::new();

/// What a host's standard stream really is, from the host's `fstat` of
/// its descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostKind {
    /// An anonymous pipe (a FIFO with no name: no links): the bytes
    /// buffered (`st_size`), its buffer's size (`st_blksize`) and its inode
    /// number as the host gives them.
    Pipe { size: u64, blksize: u64, ino: u64 },
    /// A named FIFO (or, on a host other than macOS, any FIFO).
    Fifo,
    /// A terminal.
    Tty,
    /// A regular file (`prog < file`, `> file`), and its I/O size as the
    /// host gives it (`st_blksize`).
    File { blksize: u64 },
    /// A socket: on macOS, what the host's own XNU says of it (`soo_stat`
    /// and the protocol's `pru_sense`: its mode, the bytes it has to read,
    /// its send buffer's high-water mark as its block size, its inode and
    /// device); `None` elsewhere.
    Socket(Option<HostSocket>),
    /// The host's null device (`/dev/null`).
    Null,
    /// Any other device.
    Device,
}

/// A host socket's `fstat` as macOS's XNU gives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostSocket {
    pub mode: u32,
    pub size: u64,
    pub blksize: u64,
    pub ino: u64,
    pub dev: u64,
}

/// A standard stream, optionally reported as a terminal.
#[derive(Debug)]
pub struct StdStream {
    pub stream: Stream,
    /// Whether `isatty` should say yes, which decides libc's buffering.
    pub tty: bool,
    /// The host's descriptor is a regular file (`prog < file`, `> file`).
    /// Its offset stays the host's: reads and writes go through the host
    /// descriptor, and `lseek` and `fstat` reach it too, so the next host
    /// reader or writer continues where the guest stopped (`(prog; head) <
    /// file`, `pcre2grep -m`) and concurrent writers to one log file share
    /// the offset as on Linux.
    host_file: bool,
}

/// The host's own descriptor for a stream: a duplicate, which shares the
/// open-file description and so its offset (made once, kept open).
#[cfg(not(target_family = "wasm"))]
fn host(stream: Stream) -> Option<&'static std::fs::File> {
    use std::os::fd::AsFd;
    use std::sync::OnceLock;
    static FDS: [OnceLock<Option<std::fs::File>>; 3] = [OnceLock::new(), OnceLock::new(), OnceLock::new()];
    let (k, fd) = match stream {
        Stream::In => (0, std::io::stdin().as_fd().try_clone_to_owned()),
        Stream::Out => (1, std::io::stdout().as_fd().try_clone_to_owned()),
        Stream::Err => (2, std::io::stderr().as_fd().try_clone_to_owned()),
    };
    FDS[k].get_or_init(|| fd.ok().map(std::fs::File::from)).as_ref()
}

impl StdStream {
    pub fn new(stream: Stream, tty: bool) -> StdStream {
        #[cfg(not(target_family = "wasm"))]
        let host_file = !tty && host(stream).is_some_and(|f| f.metadata().is_ok_and(|m| m.is_file()));
        #[cfg(target_family = "wasm")]
        let host_file = false;
        StdStream { stream, tty, host_file }
    }
}

impl FileHandle for StdStream {
    fn is_host_stdio(&self) -> bool {
        true
    }

    #[cfg(all(unix, not(target_family = "wasm")))]
    fn host_kind(&self) -> Option<HostKind> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        if self.tty {
            return Some(HostKind::Tty);
        }
        let md = host(self.stream)?.metadata().ok()?;
        let t = md.file_type();
        Some(if t.is_file() {
            HostKind::File { blksize: md.blksize() }
        } else if cfg!(target_os = "macos") && t.is_fifo() && md.nlink() == 0 {
            // The host's own XNU's `pipe_stat` (no links, as only a pipe
            // has); another host's pipe is told from a named FIFO by
            // nothing here.
            HostKind::Pipe { size: md.size(), blksize: md.blksize(), ino: md.ino() }
        } else if t.is_fifo() {
            HostKind::Fifo
        } else if t.is_socket() {
            HostKind::Socket(cfg!(target_os = "macos").then(|| HostSocket { mode: md.mode(), size: md.size(), blksize: md.blksize(), ino: md.ino(), dev: md.dev() }))
        } else if t.is_char_device() && std::fs::metadata("/dev/null").is_ok_and(|n| n.rdev() == md.rdev()) {
            HostKind::Null
        } else {
            HostKind::Device
        })
    }

    fn poll_readable(&self) -> bool {
        self.stream != Stream::In || STDIN_READY.get().is_none_or(|f| f())
    }

    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> SysResult {
        if self.stream != Stream::In {
            return Err(Errno::EBADF);
        }
        // Unbuffered, so the guest takes no more than it asked for: what it
        // leaves stays for whoever reads the host's stdin next.
        #[cfg(not(target_family = "wasm"))]
        if let Some(mut f) = host(self.stream) {
            return f.read(buf).map(|n| n as u64).map_err(|e| Errno::from_io(&e));
        }
        std::io::stdin()
            .read(buf)
            .map(|n| n as u64)
            .map_err(|e| Errno::from_io(&e))
    }

    fn write_at(&self, _offset: u64, buf: &[u8]) -> SysResult {
        let n = match self.stream {
            Stream::In => return Err(Errno::EBADF),
            Stream::Out => {
                let mut o = std::io::stdout();
                let n = o.write(buf).map_err(|e| Errno::from_io(&e))?;
                // Flushing on every write keeps interleaving with stderr
                // faithful, which the differential tests compare byte for
                // byte against QEMU.
                let _ = o.flush();
                n
            }
            Stream::Err => {
                let mut e = std::io::stderr();
                let n = e.write(buf).map_err(|e| Errno::from_io(&e))?;
                let _ = e.flush();
                n
            }
        };
        Ok(n as u64)
    }

    fn seek(&self, offset: i64, whence: u32) -> Option<SysResult> {
        #[cfg(not(target_family = "wasm"))]
        if self.host_file {
            use std::io::{Seek, SeekFrom};
            let to = match whence {
                0 if offset >= 0 => SeekFrom::Start(offset as u64),
                1 => SeekFrom::Current(offset),
                2 => SeekFrom::End(offset),
                _ => return Some(Err(Errno::EINVAL)),
            };
            let mut f = host(self.stream)?;
            return Some(f.seek(to).map_err(|e| Errno::from_io(&e)));
        }
        let _ = (offset, whence);
        None
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        #[cfg(not(target_family = "wasm"))]
        if self.host_file {
            if let Some(f) = host(self.stream) {
                return f.metadata().map(|m| crate::vfs::hostfs::convert(&m)).map_err(|e| Errno::from_io(&e));
            }
        }
        Ok(Metadata {
            file_type: FileType::CharDevice,
            size: 0,
            mode: 0o620,
            ino: crate::vfs::anon_ino(self as *const Self as *const u8),
            mtime: 0,
            nlink: 1,
            rdev: 0,
            dev: 0,
            times: Default::default(),
        })
    }

    fn is_stream(&self) -> bool {
        true
    }

    fn is_tty(&self) -> bool {
        self.tty
    }
}
