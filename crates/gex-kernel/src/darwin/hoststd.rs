//! A Darwin `fstat` of one of the host's standard streams (gexc's
//! [`crate::stdio::StdStream`]): what XNU shows for the stream's real kind,
//! as the process's parent would have handed it over on the device. A pipe
//! is `pipe_stat`'s (the host's own XNU answers the buffered count and the
//! buffer's size); a terminal is a tty's devfs node as `grantpt` leaves it
//! (`devfs_setattr(dev, 0620, uid, GID_TTY)`); a regular file is the host
//! file's, owned by the caller (the host's owner is no id of the guest's);
//! a socket is `soo_stat`'s (the host's XNU again); the host's null device
//! is the system's `/dev/null`.

use crate::fs::Stat;
use crate::stdio::HostKind;
use crate::vfs::Metadata;

/// `S_IFIFO`, `S_IFCHR`.
const S_IFIFO: u32 = 0o010000;
const S_IFCHR: u32 = 0o020000;

static TTY: std::sync::Once = std::sync::Once::new();
static FILE: std::sync::Once = std::sync::Once::new();
static SOCKET: std::sync::Once = std::sync::Once::new();

/// What a report about the host's standard streams starts with: a host's
/// own, which another host's streams (the page's pipes) do not share.
pub const REPORT: &str = "[gex] Darwin: the host's standard streams stand in:";

/// A stand-in said once a run.
fn stand_in(once: &std::sync::Once, what: &str) {
    once.call_once(|| crate::darwin_say!("{REPORT} {what}"));
}

/// The stat of a host stream of kind `kind` (the stream's own metadata
/// `md`), for a caller of ids `uid`, `gid`; or what is not modelled for it.
/// The null device is the caller's to stat by path ([`HostKind::Null`]).
pub fn stat(kind: HostKind, md: &Metadata, uid: u32, gid: u32) -> Result<Stat, String> {
    match kind {
        HostKind::Pipe { size, blksize, ino } => Ok(Stat {
            ino,
            mode: S_IFIFO | 0o660,
            uid,
            gid,
            size: size as i64,
            blksize: blksize as i32,
            blocks: size.div_ceil(blksize.max(1)) as i64,
            ..Default::default()
        }),
        // devfs_getattr of a tty node: S_IFCHR and its mode, its one link,
        // the owner grantpt gave it, MAXPHYSIO as its I/O size.
        HostKind::Tty => {
            stand_in(&TTY, "the host's terminal for a tty's devfs node: its st_dev and st_rdev 0, its inode the host's (no devfs node of the system's is the host's terminal)");
            Ok(Stat {
                ino: md.ino,
                mode: S_IFCHR | 0o620,
                nlink: 1,
                uid,
                gid: super::ptmx::GID_TTY,
                blksize: 64 * 1024,
                ..Default::default()
            })
        }
        HostKind::File { blksize } => {
            stand_in(&FILE, "a host file: its st_dev 0 (it is on no volume of the system's) and its owner the caller (the host's owner is no id of the system's)");
            let mut st = crate::syscalls::Kernel::stat_from(md);
            st.uid = uid;
            st.gid = gid;
            st.blksize = blksize as i32;
            Ok(st)
        }
        HostKind::Null => Err("the host's null device (the caller stats the system's /dev/null)".into()),
        HostKind::Fifo => Err("a named FIFO of the host's, or a pipe on a host whose fstat is not XNU's (its vnode or its pipe_stat)".into()),
        // soo_stat and the protocol's pru_sense, as the host's XNU answered
        // them; the socket's credential the caller's.
        HostKind::Socket(Some(s)) => {
            stand_in(&SOCKET, "a host socket: its owner the caller (the socket's credential is the host process's that made it, no id of the system's)");
            Ok(Stat { ino: s.ino, dev: s.dev, mode: s.mode, uid, gid, size: s.size as i64, blksize: s.blksize as i32, ..Default::default() })
        }
        HostKind::Socket(None) => Err("a socket of the host's, on a host whose fstat is not XNU's (soo_stat)".into()),
        HostKind::Device => Err("a device of the host's other than its terminal and its null device (that device's devfs node)".into()),
    }
}
