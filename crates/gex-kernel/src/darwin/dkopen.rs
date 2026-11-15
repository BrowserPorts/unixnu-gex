//! IOMediaBSDClient's opens of a disk's nodes (IOStorageFamily-333.40.1,
//! IOMediaBSDClient.cpp): `dkopen` keeps, for each minor, how many times its
//! block and character nodes are open and the access each holds, and opens
//! the minor's medium for the access they hold together. A volume's medium
//! is an `AppleAPFSVolume`, whose `handleOpen` (0xfffffff00666d224, the
//! override in its vtable 0xfffffff006f277b8) shares a writer's access and
//! hands the open to `IOMedia::handleOpen` (IOMedia.cpp), which opens the
//! medium's provider, the `AppleAPFSContainer`, when the medium's level
//! changes.

use std::sync::Mutex;

/// `IOStorageAccess`.
pub mod access {
    pub const NONE: u32 = 0x00;
    pub const READER: u32 = 0x01;
    pub const WRITER: u32 = 0x02;
    pub const READER_WRITER: u32 = 0x03;
    pub const SHARED_LOCK: u32 = 0x04;
    pub const EXCLUSIVE_LOCK: u32 = 0x08;
    pub const INVALID: u32 = 0x0d;
}

/// `FWRITE`, `O_SHLOCK`, `O_EXLOCK`.
const FWRITE: u32 = 0x2;
const O_SHLOCK: u32 = 0x10;
const O_EXLOCK: u32 = 0x20;

/// `DK_ADD_ACCESS`: the access two openers hold together; none where they
/// conflict.
pub fn dk_add_access(a1: u32, a2: u32) -> u32 {
    const TABLE: [[u32; 4]; 4] = [[0o0, 0o1, 0o2, 0o3], [0o1, 0o1, 0o1, 0o1], [0o2, 0o1, 0o2, 0o3], [0o3, 0o1, 0o3, 0o3]];
    if a1 == access::NONE {
        return a2;
    }
    if a2 == access::NONE {
        return a1;
    }
    let (a1, a2) = (a1.wrapping_sub(1) >> 1, a2.wrapping_sub(1) >> 1);
    if a1 > 0o3 || a2 > 0o3 {
        return access::NONE;
    }
    (TABLE[a1 as usize][a2 as usize] << 1) + 1
}

/// `IOMediaAccess::operator+=`: `level` with `access` added, through
/// `gIOMediaAccessTable`; [`access::INVALID`] where they conflict.
pub fn media_add_access(level: u32, access: u32) -> u32 {
    const TABLE: [[u32; 8]; 8] = [
        [0o00, 0o01, 0o02, 0o03, 0o06, 0o06, 0o06, 0o00],
        [0o11, 0o06, 0o11, 0o06, 0o06, 0o06, 0o06, 0o11],
        [0o02, 0o01, 0o02, 0o03, 0o06, 0o06, 0o06, 0o02],
        [0o03, 0o06, 0o03, 0o03, 0o06, 0o06, 0o06, 0o03],
        [0o06, 0o06, 0o06, 0o06, 0o06, 0o06, 0o06, 0o04],
        [0o06, 0o06, 0o06, 0o06, 0o06, 0o06, 0o06, 0o15],
        [0o06, 0o06, 0o06, 0o06, 0o06, 0o06, 0o06, 0o06],
        [0o06, 0o06, 0o06, 0o06, 0o06, 0o06, 0o06, 0o06],
    ];
    let have = (level.wrapping_sub(1) >> 1) & 7;
    let r = TABLE[((access.wrapping_sub(1) >> 1) & 7) as usize][have as usize];
    ((r & 7) << 1) + 1
}

/// `AppleAPFSVolume::handleOpen`'s access: a reader-writer's open is made
/// shared (`(access & 3) == 3` adds `kIOStorageAccessSharedLock`) before
/// `IOMedia::handleOpen` takes it.
pub fn apfs_volume_access(a: u32) -> u32 {
    if a & access::READER_WRITER == access::READER_WRITER {
        a | access::SHARED_LOCK
    } else {
        a
    }
}

/// A minor's `MinorSlot` open state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MinorSlot {
    pub bdev_open: u32,
    pub bdev_level: u32,
    pub cdev_open: u32,
    pub cdev_level: u32,
}

/// The opens a medium's `IOMedia::handleOpen` has granted: by client, the
/// access each holds (`_openClients`), and the level it holds of its
/// provider (`_openLevel`). The client here is the medium's
/// `IOMediaBSDClient` (`minor->client`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MediaOpens {
    pub bsd_client: u32,
    pub level: u32,
}

/// The table: a slot and the medium's opens per minor, and the static
/// `root` of `dkopen`'s first-open upgrade (the "///w" block).
struct Table {
    minors: Vec<MinorSlot>,
    media: Vec<MediaOpens>,
    root: bool,
}

static TABLE: Mutex<Option<Table>> = Mutex::new(None);

fn with<R>(f: impl FnOnce(&mut Table) -> R) -> R {
    let mut g = TABLE.lock().unwrap_or_else(|e| e.into_inner());
    let t = g.get_or_insert_with(|| Table { minors: vec![MinorSlot::default(); super::storage::MEDIA], media: vec![MediaOpens::default(); super::storage::MEDIA], root: false });
    f(t)
}

/// A minor's open state.
pub fn minor(m: u32) -> Option<MinorSlot> {
    with(|t| t.minors.get(m as usize).copied())
}

/// Why `dkopen` did not open the minor: an error it returns, or a part of
/// the open below the medium that is not modelled.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    Errno(i32),
    Unmodelled(String),
}

/// `ENXIO`, `EBUSY`, `EACCES`.
const ENXIO: i32 = 6;
const EBUSY: i32 = 16;
const EACCES: i32 = 13;

/// `IOMedia::handleOpen` of the volume `media` for its BSD client at
/// `access_in` (after `AppleAPFSVolume::handleOpen`'s change). A volume
/// that is not mounted has no other client, so the level is the BSD
/// client's access alone;
/// the volume has no storage driver client (`copyClientWithCategory` of
/// kIOStorageCategory), so a writer tears none down. A change of level is
/// the provider's open: the `AppleAPFSContainer`'s
/// `IOPartitionScheme::handleOpen` (0xfffffff00597c57c in its vtable
/// 0xfffffff006f26ac0), whose level depends on the opens APFS made of the
/// container's volumes to mount the root (apfs_vfsop_mount's IOKit opens,
/// 0xfffffff0066d1934 -> 0xfffffff006670890), which are not modelled.
fn volume_handle_open(t: &mut Table, minor: usize, media: super::storage::Media, access_in: u32) -> Result<(), Refused> {
    // A mounted volume has APFS's own open as a client too.
    if let super::storage::Media::Volume(v) = media {
        if super::kern::mounts().iter().any(|m| super::kern::mount_volume(m) == Some(v)) {
            return Err(Refused::Unmodelled(format!("the open of {}'s AppleAPFSVolume (IOMedia::handleOpen) beside the open APFS holds of it for its mount", super::storage::media_bsd_name(media))));
        }
    }
    let mut level = media_add_access(access::NONE, access_in);
    if level == access::INVALID {
        return Err(Refused::Errno(EBUSY));
    }
    if access_in & access::WRITER != 0 && !super::storage::volume_writable() {
        return Err(Refused::Errno(EBUSY));
    }
    level &= access::READER_WRITER;
    let opens = &mut t.media[minor];
    if opens.level != level {
        let name = super::storage::media_bsd_name(media);
        return Err(Refused::Unmodelled(format!(
            "the open of {name}'s AppleAPFSVolume at level {level:#x} (IOMedia::handleOpen): its provider's, the AppleAPFSContainer's IOPartitionScheme::handleOpen, whose open level since APFS's opens for the root mount (0xfffffff0066d1934) is not modelled"
        )));
    }
    opens.bsd_client = access_in;
    opens.level = level;
    Ok(())
}

/// `dkopen(dev, flags, devtype)` of the disk at `minor`, through its block
/// node (`block`) or character node.
pub fn dkopen(minor: u32, flags: u32, block: bool) -> Result<(), Refused> {
    let mut want = access::READER;
    if flags & FWRITE != 0 {
        want |= access::READER_WRITER;
    }
    if flags & O_SHLOCK != 0 {
        want |= access::SHARED_LOCK;
    }
    if flags & O_EXLOCK != 0 {
        want |= access::EXCLUSIVE_LOCK;
    }
    with(|t| {
        // getMinor: a minor in the table, whose medium is not orphaned (no
        // medium is ejected here).
        let order = super::storage::media_order();
        let Some(&media) = order.get(minor as usize) else { return Err(Refused::Errno(ENXIO)) };
        let writable = match media {
            super::storage::Media::Volume(_) => super::storage::volume_writable(),
            _ => {
                return Err(Refused::Unmodelled(format!("dkopen of {}: the open of a medium that is no APFS volume (its IOMedia's and its storage driver's open state)", super::storage::media_bsd_name(media))));
            }
        };
        // The first dkopen there has ever been opens its medium for writing
        // too, unless the medium is not writable or is an APFS container's
        // (an AppleAPFSContainer or AppleAPFSContainerScheme among its
        // children: a volume has neither).
        if !t.root {
            t.root = true;
            if writable {
                want |= access::READER_WRITER;
            }
        }
        let slot = t.minors[minor as usize];
        let level = dk_add_access(slot.bdev_level, slot.cdev_level);
        let level_out = dk_add_access(level, want);
        if level_out == access::NONE {
            return Err(Refused::Errno(EBUSY));
        }
        if flags & FWRITE != 0 && !writable {
            return Err(Refused::Errno(EACCES));
        }
        let was = slot;
        let s = &mut t.minors[minor as usize];
        if block {
            s.bdev_open += 1;
            s.bdev_level = dk_add_access(was.bdev_level, want);
        } else {
            s.cdev_open += 1;
            s.cdev_level = dk_add_access(was.cdev_level, want);
        }
        if level != level_out {
            // media->open(client, 0, levelOut): IOService::open takes the
            // provider's lock and calls handleOpen.
            if let Err(e) = volume_handle_open(t, minor as usize, media, apfs_volume_access(level_out)) {
                t.minors[minor as usize] = was;
                return Err(match e {
                    Refused::Errno(_) => Refused::Errno(EBUSY),
                    u => u,
                });
            }
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_tables() {
        use access::*;
        assert_eq!(dk_add_access(NONE, READER), READER);
        assert_eq!(dk_add_access(READER, READER_WRITER), READER_WRITER);
        assert_eq!(dk_add_access(READER_WRITER, READER_WRITER), READER_WRITER);
        assert_eq!(dk_add_access(READER | SHARED_LOCK, READER_WRITER | SHARED_LOCK), READER_WRITER | SHARED_LOCK);
        assert_eq!(dk_add_access(READER | EXCLUSIVE_LOCK, READER), NONE);
        assert_eq!(media_add_access(NONE, READER_WRITER | SHARED_LOCK), READER_WRITER | SHARED_LOCK);
        assert_eq!(media_add_access(READER_WRITER, READER_WRITER), INVALID);
        assert_eq!(media_add_access(READER | SHARED_LOCK, READER_WRITER | SHARED_LOCK), READER_WRITER | SHARED_LOCK);
        assert_eq!(media_add_access(NONE, READER_WRITER | EXCLUSIVE_LOCK), READER_WRITER | EXCLUSIVE_LOCK);
        assert_eq!(apfs_volume_access(READER_WRITER), READER_WRITER | SHARED_LOCK);
        assert_eq!(apfs_volume_access(READER), READER);
    }
}
