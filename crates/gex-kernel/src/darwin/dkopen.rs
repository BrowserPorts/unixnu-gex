//! IOMediaBSDClient's opens of a disk's nodes (IOStorageFamily-333.40.1,
//! IOMediaBSDClient.cpp) and the opens they make of the storage stack
//! below them.
//!
//! `dkopen` keeps, for each minor, how many times its block and character
//! nodes are open and the access each holds, and opens the minor's medium
//! for the access they hold together; `dkclose` closes it or downgrades it
//! once a node's last close leaves less. Each object of the stack grants
//! an open by its own rules and opens its provider when its level changes:
//!
//! - an `IOMedia` (IOMedia.cpp `handleOpen`/`handleClose`), summing its
//!   clients' access through `gIOMediaAccessTable` and opening its
//!   provider at the reader-writer part of the sum. A volume's medium is an
//!   `AppleAPFSVolume`, whose `handleOpen` (0xfffffff00666d224, the override
//!   in its vtable 0xfffffff006f277b8) shares a reader-writer's access
//!   first; the container's `AppleAPFSMedia` (vtable 0xfffffff006f29808)
//!   uses IOMedia's own;
//! - a partition scheme (IOPartitionScheme.cpp): the GPT scheme of disk0 and
//!   the `AppleAPFSContainer` of the container's medium (its `handleOpen`
//!   is IOPartitionScheme's, 0xfffffff00597c57c in its vtable
//!   0xfffffff006f26ac0), opening their provider shared, at reader-writer
//!   while any client writes;
//! - the `AppleAPFSContainerScheme` of the partition ([`scheme_open`]);
//! - the `IOBlockStorageDriver` of disk0 (IOBlockStorageDriver.cpp), which
//!   opens its NVMe namespace's `IONVMeBlockStorageDevice` on its first
//!   client and closes it after its last; the device's `handleOpen`
//!   (0xfffffff006a994fc, vtable 0xfffffff006fab200) hands an open without
//!   its option bit 16 to IOService's, which grants one opener at a time.
//!
//! The kernel opens two media before any process runs: `vfs_mountroot`'s
//! `bdevvp` of the root device opens it for reading (`VNOP_OPEN(FREAD)`,
//! vfs_subr.c), the first `dkopen` there is; then APFS's
//! `container_rootmount` (0xfffffff00667fa0c) finds the volume's container
//! medium and `bdevvp`s it too (0xfffffff00667fc3c) for the container it
//! loads with that vnode (`container_load_with_callback`,
//! 0xfffffff006670890, which opens a path itself only for a container not
//! loaded yet). APFS opens no medium through IOKit to mount: its only
//! `IOStorage::open` calls are its user clients', and the container
//! scheme's probe, which opens the partition to read the container's
//! superblock and closes it again (0xfffffff0066826e4).

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

use super::storage::Media;

/// A client of an open of the stack: a medium's `IOMediaBSDClient`, a
/// medium (opening its provider), or a scheme or the block storage driver
/// (opening theirs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Client {
    Bsd(Media),
    Media(Media),
    Gpt,
    Scheme,
    Container,
    Driver,
}

/// An `IOMedia`'s opens: its clients' access (`_openClients`) and the level
/// it holds of its provider (`_openLevel`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MediaOpens {
    pub clients: Vec<(Client, u32)>,
    pub level: u32,
}

/// A partition scheme's opens (`_openReaders`, `_openReaderWriters`,
/// `_openLevel`), and the container scheme's (its sets at +0x118 and
/// +0x120, its level at +0x114).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SchemeOpens {
    pub readers: Vec<Client>,
    pub writers: Vec<Client>,
    pub level: u32,
}

/// The table: a slot per minor, the stack's open state, and the static
/// `root` of `dkopen`'s first-open upgrade (the "///w" block).
#[derive(Clone, Debug)]
struct Table {
    minors: Vec<MinorSlot>,
    media: Vec<MediaOpens>,
    gpt: SchemeOpens,
    scheme: SchemeOpens,
    container: SchemeOpens,
    /// `IOBlockStorageDriver::_openClients`.
    driver: Vec<Client>,
    /// The NVMe device's `IOService` owner (`__owner`).
    device_owner: Option<Client>,
    root: bool,
}

static TABLE: Mutex<Option<Result<Table, String>>> = Mutex::new(None);

/// The table as the kernel leaves it when the first process starts: the
/// root mount's two `bdevvp` opens made ([`boot`]).
fn with<R>(f: impl FnOnce(&mut Table) -> Result<R, Refused>) -> Result<R, Refused> {
    let mut g = TABLE.lock().unwrap_or_else(|e| e.into_inner());
    let t = g.get_or_insert_with(boot);
    match t {
        Ok(t) => f(t),
        Err(e) => Err(Refused::Unmodelled(e.clone())),
    }
}

/// The kernel's opens at boot. `vfs_mountroot`'s `bdevvp(rootdev)` opens
/// the root device for reading: the System volume's medium, which iBoot's
/// `root-matching` names (/chosen; the IPSW's device tree holds only its
/// placeholder) and APFS's `container_rootmount` takes as a volume (its
/// `AppleAPFSVolume` check, 0xfffffff006671e4c). Then APFS `bdevvp`s the
/// volume's container medium, the provider of the volume's
/// `AppleAPFSContainer`, for reading. `bdevvp` panics when the open fails.
fn boot() -> Result<Table, String> {
    boot_in(super::kern::boot_state())
}

/// [`boot`]'s table for a system in boot state `state`.
fn boot_in(state: super::kern::BootState) -> Result<Table, String> {
    let mut t = Table {
        minors: vec![MinorSlot::default(); super::storage::MEDIA],
        media: vec![MediaOpens::default(); super::storage::MEDIA],
        gpt: SchemeOpens::default(),
        scheme: SchemeOpens::default(),
        container: SchemeOpens::default(),
        driver: Vec::new(),
        device_owner: None,
        root: false,
    };
    let system = super::storage::volume_with_role(super::storage::role::SYSTEM).ok_or("the container has no System volume")?.index;
    for m in [Media::Volume(system), Media::Container] {
        let minor = minor_of(m) as u32;
        match dkopen_in(&mut t, minor, FREAD, true) {
            Ok(()) => {}
            Err(Refused::Errno(e)) => return Err(format!("bdevvp's open of {} at boot failed ({e}): the kernel panics (\"bdevvp failed: open\")", super::storage::media_bsd_name(m))),
            Err(Refused::Unmodelled(u)) => return Err(format!("bdevvp's open of {} at boot: {u}", super::storage::media_bsd_name(m))),
        }
    }
    // A booted system's: the Preboot volume's, which libignition's
    // read-write mount of it opened (mount_common's VNOP_OPEN of the
    // device, FREAD | FWRITE: super::kern::boot_mounts).
    if state == super::kern::BootState::Booted {
        let preboot = super::storage::volume_with_role(super::storage::role::PREBOOT).ok_or("the container has no Preboot volume")?.index;
        let m = Media::Volume(preboot);
        match dkopen_in(&mut t, minor_of(m) as u32, FREAD | FWRITE, true) {
            Ok(()) => {}
            Err(Refused::Errno(e)) => return Err(format!("the booted system's open of {} for its Preboot mount failed ({e})", super::storage::media_bsd_name(m))),
            Err(Refused::Unmodelled(u)) => return Err(format!("the booted system's open of {} for its Preboot mount: {u}", super::storage::media_bsd_name(m))),
        }
    }
    Ok(t)
}

/// A minor's open state.
pub fn minor(m: u32) -> Option<MinorSlot> {
    with(|t| Ok(t.minors.get(m as usize).copied())).ok().flatten()
}

/// A medium's open state.
pub fn media_opens(m: Media) -> Option<MediaOpens> {
    with(|t| Ok(t.media[minor_of(m)].clone())).ok()
}

/// Why `dkopen` did not open the minor: an error it returns, or a part of
/// the open below the medium that is not modelled.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    Errno(i32),
    Unmodelled(String),
}

/// `ENXIO`, `EBUSY`, `EACCES`; `FREAD`.
const ENXIO: i32 = 6;
const EBUSY: i32 = 16;
const EACCES: i32 = 13;
const FREAD: u32 = 0x1;

/// A medium's minor: its place in the order the media took them.
fn minor_of(m: Media) -> usize {
    super::storage::media_order().iter().position(|&x| x == m).expect("every medium has a minor")
}

/// `IOMedia::isWritable`: the volumes' as APFS creates them, the others'
/// as the NVMe namespace reports its write protection (the GPT scheme and
/// the container scheme give their media their provider's).
fn writable(m: Media) -> bool {
    match m {
        Media::Volume(_) => super::storage::volume_writable(),
        _ => super::storage::disk_writable(),
    }
}

/// The medium's client of the kIOStorageCategory match category, its
/// "storage driver" (`copyClientWithCategory`): the scheme or container
/// that matched it. A volume has none.
fn storage_driver(m: Media) -> Option<Client> {
    match m {
        Media::Whole => Some(Client::Gpt),
        Media::Partition => Some(Client::Scheme),
        Media::Container => Some(Client::Container),
        Media::Volume(_) | Media::Firmware => None,
    }
}

/// `_IOMedia_is_APFS`: an `AppleAPFSContainer` or `AppleAPFSContainerScheme`
/// among the medium's children.
fn is_apfs(m: Media) -> bool {
    matches!(m, Media::Partition | Media::Container)
}

/// `IOService::open(client, 0, access)` of a medium: its `handleOpen`, the
/// `AppleAPFSVolume` override's change first for a volume.
fn media_open(t: &mut Table, m: Media, client: Client, access_in: u32) -> Result<bool, String> {
    let access_in = if let Media::Volume(_) = m { apfs_volume_access(access_in) } else { access_in };
    let i = minor_of(m);
    let access = t.media[i].clients.iter().find(|(c, _)| *c == client).map_or(access::NONE, |&(_, a)| a);
    let driver = storage_driver(m);
    let mut level = t.media[i].clients.iter().filter(|(c, _)| *c != client).fold(access::NONE, |l, &(_, a)| media_add_access(l, a));
    level = media_add_access(level, access_in);
    if level == access::INVALID {
        return Ok(false);
    }
    let mut rebuild = false;
    if access_in & access::WRITER != 0 {
        if !writable(m) {
            return Ok(false);
        }
        if access_in & access::SHARED_LOCK == 0 {
            if let Some(d) = driver.filter(|&d| d != client) {
                // The storage driver is torn down for an exclusive writer:
                // refused while it holds the medium open.
                if t.media[i].clients.iter().any(|(c, _)| *c == d) {
                    return Ok(false);
                }
                return Err(format!("the exclusive writer's open of {}: its storage driver's termination ({d:?}->terminate)", super::storage::media_bsd_name(m)));
            }
        }
    } else if access & access::WRITER != 0 {
        rebuild = true;
    }
    level &= access::READER_WRITER;
    if t.media[i].level != level && !provider_open(t, m, level)? {
        return Ok(false);
    }
    let opens = &mut t.media[i];
    match opens.clients.iter_mut().find(|(c, _)| *c == client) {
        Some(e) => e.1 = access_in,
        None => opens.clients.push((client, access_in)),
    }
    opens.level = level;
    if rebuild {
        return Err(rematch(m, driver, client));
    }
    Ok(true)
}

/// What a writer's downgrade or close of a medium sets off: the storage
/// driver's re-probe, or the medium's re-registration for matching.
fn rematch(m: Media, driver: Option<Client>, client: Client) -> String {
    let name = super::storage::media_bsd_name(m);
    match driver {
        Some(d) if d != client => format!("the re-probe of {name}'s storage driver ({d:?}) after a writer left it"),
        Some(_) => format!("{name}'s storage driver leaving as a writer"),
        None => format!("the re-registration of {name} for matching (registerService) after a writer left it"),
    }
}

/// `IOService::close(client)` of a medium: `IOMedia::handleClose` (the
/// volume's too).
fn media_close(t: &mut Table, m: Media, client: Client) -> Result<(), String> {
    let i = minor_of(m);
    let Some(access) = t.media[i].clients.iter().find(|(c, _)| *c == client).map(|&(_, a)| a) else {
        // handleIsOpen: a client without an open closes nothing.
        return Ok(());
    };
    let driver = storage_driver(m);
    let level = t.media[i].clients.iter().filter(|(c, _)| *c != client).fold(access::NONE, |l, &(_, a)| media_add_access(l, a)) & access::READER_WRITER;
    if t.media[i].level != level {
        if level == access::NONE {
            provider_close(t, m)?;
        } else if !provider_open(t, m, level)? {
            return Err(format!("the downgrade of {}'s provider open, which IOMedia::handleClose asserts succeeds", super::storage::media_bsd_name(m)));
        }
    }
    let opens = &mut t.media[i];
    opens.clients.retain(|(c, _)| *c != client);
    opens.level = level;
    if access & access::WRITER != 0 {
        return Err(rematch(m, driver, client));
    }
    Ok(())
}

/// The open of a medium's provider at `level`, by the medium.
fn provider_open(t: &mut Table, m: Media, level: u32) -> Result<bool, String> {
    match m {
        Media::Whole => Ok(driver_open(t, Client::Media(m))),
        Media::Partition => partition_open(t, Client::Gpt, Client::Media(m), level),
        Media::Container => scheme_open(t, Client::Media(m), level),
        Media::Volume(_) => partition_open(t, Client::Container, Client::Media(m), level),
        Media::Firmware => Err("the open of the firmware namespace's storage driver (NS_02's IOBlockStorageDriver)".to_string()),
    }
}

/// The close of a medium's provider, by the medium.
fn provider_close(t: &mut Table, m: Media) -> Result<(), String> {
    match m {
        Media::Whole => {
            driver_close(t, Client::Media(m));
            Ok(())
        }
        Media::Partition => partition_close(t, Client::Gpt, Client::Media(m)),
        Media::Container => scheme_close(t, Client::Media(m)),
        Media::Volume(_) => partition_close(t, Client::Container, Client::Media(m)),
        Media::Firmware => Err("the close of the firmware namespace's storage driver (NS_02's IOBlockStorageDriver)".to_string()),
    }
}

/// A partition scheme's opens and the medium it is the scheme of: the GPT
/// scheme's disk0, the `AppleAPFSContainer`'s container medium.
fn partition_scheme(t: &mut Table, which: Client) -> (&mut SchemeOpens, Media) {
    match which {
        Client::Gpt => (&mut t.gpt, Media::Whole),
        _ => (&mut t.container, Media::Container),
    }
}

/// `IOPartitionScheme::handleOpen(client, 0, access)`: one open below for
/// all its clients, reader-writer while any of them writes, shared.
fn partition_open(t: &mut Table, which: Client, client: Client, access: u32) -> Result<bool, String> {
    let (s, below) = partition_scheme(t, which);
    let mut writers = s.writers.len() - usize::from(s.writers.contains(&client));
    if access == access::READER_WRITER {
        writers += 1;
    }
    let mut level = if writers > 0 { access::READER_WRITER } else { access::READER };
    if s.level != level {
        level |= access::SHARED_LOCK;
        let ok = media_open(t, below, which, level)?;
        level &= access::READER_WRITER;
        if !ok {
            return Ok(false);
        }
    }
    let (s, _) = partition_scheme(t, which);
    if access == access::READER {
        if !s.readers.contains(&client) {
            s.readers.push(client);
        }
        s.writers.retain(|c| *c != client);
    } else {
        if !s.writers.contains(&client) {
            s.writers.push(client);
        }
        s.readers.retain(|c| *c != client);
    }
    s.level = level;
    Ok(true)
}

/// `IOPartitionScheme::handleClose(client)`: closes below with the last
/// client, downgrades below with the last writer.
fn partition_close(t: &mut Table, which: Client, client: Client) -> Result<(), String> {
    let (s, below) = partition_scheme(t, which);
    if s.writers.contains(&client) {
        s.writers.retain(|c| *c != client);
    } else if s.readers.contains(&client) {
        s.readers.retain(|c| *c != client);
    } else {
        return Ok(());
    }
    let mut level = if !s.writers.is_empty() {
        access::READER_WRITER
    } else if !s.readers.is_empty() {
        access::READER
    } else {
        access::NONE
    };
    if s.level != level {
        if level == access::NONE {
            media_close(t, below, which)?;
        } else {
            level |= access::SHARED_LOCK;
            if !media_open(t, below, which, level)? {
                return Err(format!("the downgrade of {}'s open by its partition scheme, which IOPartitionScheme::handleClose asserts succeeds", super::storage::media_bsd_name(below)));
            }
            level &= access::READER_WRITER;
        }
        partition_scheme(t, which).0.level = level;
    }
    Ok(())
}

/// `AppleAPFSContainerScheme::handleOpen(client, options, access)`
/// (0xfffffff006683340): reader-writer for a reader-writer or while another
/// client writes, else reader; a change of level opens its provider, the
/// partition, at that level with the shared lock when +0x110 is set, and
/// only once the scheme has started on it (+0x10e); a fusion container's
/// second provider (+0xd8, +0x10f) is opened alike. The scheme's probe
/// (0xfffffff0066825cc) sets +0x110 only for a probe score of 0, and the
/// three personalities of the class have 2000: it is clear, and the
/// medium the scheme publishes has the Content Hint the `AppleAPFSContainer`
/// matches. Its start (0xfffffff0066829d4) sets +0x10e once IOService's
/// start on the partition succeeds; the restore's container has one
/// device, no second one.
fn scheme_open(t: &mut Table, client: Client, access: u32) -> Result<bool, String> {
    const SHARED_FLAG: u32 = 0;
    let want = access & access::READER_WRITER;
    let level = if want == access::READER_WRITER {
        access::READER_WRITER
    } else {
        let s = &t.scheme;
        if s.writers.len() > usize::from(s.writers.contains(&client)) { access::READER_WRITER } else { access::READER }
    };
    if t.scheme.level != level && !media_open(t, Media::Partition, Client::Scheme, level | SHARED_FLAG << 2)? {
        return Ok(false);
    }
    let s = &mut t.scheme;
    s.level = level;
    if want == access::READER_WRITER {
        if !s.writers.contains(&client) {
            s.writers.push(client);
        }
        s.readers.retain(|c| *c != client);
    } else {
        if !s.readers.contains(&client) {
            s.readers.push(client);
        }
        s.writers.retain(|c| *c != client);
    }
    Ok(true)
}

/// `AppleAPFSContainerScheme::handleClose(client)` (0xfffffff0066834c4):
/// the client leaves its set; the level the rest hold is reopened below,
/// or the provider closed when none is left.
fn scheme_close(t: &mut Table, client: Client) -> Result<(), String> {
    let s = &mut t.scheme;
    if s.writers.contains(&client) {
        s.writers.retain(|c| *c != client);
    } else if s.readers.contains(&client) {
        s.readers.retain(|c| *c != client);
    } else {
        return Ok(());
    }
    let level = if !s.writers.is_empty() {
        access::READER_WRITER
    } else if !s.readers.is_empty() {
        access::READER
    } else {
        access::NONE
    };
    if s.level == level {
        return Ok(());
    }
    if level == access::NONE {
        media_close(t, Media::Partition, Client::Scheme)?;
    } else {
        media_open(t, Media::Partition, Client::Scheme, level)?;
    }
    t.scheme.level = level;
    Ok(())
}

/// `IOBlockStorageDriver::handleOpen(client)`: its first client opens the
/// NVMe device (`getProvider()->open(this)`, IOService's exclusive
/// `handleOpen` through the device's override).
fn driver_open(t: &mut Table, client: Client) -> bool {
    if t.driver.is_empty() {
        if t.device_owner.is_some() {
            return false;
        }
        t.device_owner = Some(Client::Driver);
    }
    if !t.driver.contains(&client) {
        t.driver.push(client);
    }
    true
}

/// `IOBlockStorageDriver::handleClose(client)`: its last client closes the
/// device.
fn driver_close(t: &mut Table, client: Client) {
    t.driver.retain(|c| *c != client);
    if t.driver.is_empty() {
        t.device_owner = None;
    }
}

/// Whether a vnode of the medium's device is marked
/// mounted on (SI_MOUNTEDON), which `vfs_mountedon` and `vfs_setmounting`
/// find through the device's aliases. A mount's device is (`vfs_mountroot` marks
/// the root's, mount_common the others'), and so is the container medium
/// once APFS has loaded the container from it
/// (`container_load_with_callback`'s `vnode_setmountedon`,
/// 0xfffffff006671344), which it did for the root.
pub fn mounted_on(m: Media) -> bool {
    m == Media::Container || super::kern::mounts().iter().any(|mnt| super::kern::mount_volume(mnt).map(Media::Volume) == Some(m))
}

/// `dkopen(dev, flags, devtype)` of the disk at `minor`, through its block
/// node (`block`) or character node.
pub fn dkopen(minor: u32, flags: u32, block: bool) -> Result<(), Refused> {
    with(|t| dkopen_in(t, minor, flags, block))
}

fn dkopen_in(t: &mut Table, minor: u32, flags: u32, block: bool) -> Result<(), Refused> {
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
    // getMinor: a minor in the table, whose medium is not orphaned (no
    // medium is ejected here).
    let order = super::storage::media_order();
    let Some(&media) = order.get(minor as usize) else { return Err(Refused::Errno(ENXIO)) };
    // The first dkopen there has ever been opens its medium for writing
    // too, unless the medium is not writable or is an APFS container's.
    if !t.root {
        t.root = true;
        if writable(media) && !is_apfs(media) {
            want |= access::READER_WRITER;
        }
    }
    let slot = t.minors[minor as usize];
    let level = dk_add_access(slot.bdev_level, slot.cdev_level);
    let level_out = dk_add_access(level, want);
    if level_out == access::NONE {
        return Err(Refused::Errno(EBUSY));
    }
    if flags & FWRITE != 0 && !writable(media) {
        return Err(Refused::Errno(EACCES));
    }
    let s = &mut t.minors[minor as usize];
    if block {
        s.bdev_open += 1;
        s.bdev_level = dk_add_access(slot.bdev_level, want);
    } else {
        s.cdev_open += 1;
        s.cdev_level = dk_add_access(slot.cdev_level, want);
    }
    if level != level_out {
        // media->open(client, 0, levelOut): IOService::open takes the
        // medium's arbitration lock and calls its handleOpen.
        match media_open(t, media, Client::Bsd(media), level_out) {
            Ok(true) => {}
            Ok(false) => {
                t.minors[minor as usize] = slot;
                return Err(Refused::Errno(EBUSY));
            }
            Err(u) => return Err(Refused::Unmodelled(u)),
        }
    }
    Ok(())
}

/// `dkclose(dev, flags, devtype)`, the last close of the minor's block or
/// character node: its count and level go; with no node left open the
/// medium is closed, else downgraded to what the other node holds.
pub fn dkclose(minor: u32, block: bool) -> Result<(), Refused> {
    with(|t| {
        let order = super::storage::media_order();
        let Some(&media) = order.get(minor as usize) else { return Err(Refused::Errno(ENXIO)) };
        let s = &mut t.minors[minor as usize];
        let level = dk_add_access(s.bdev_level, s.cdev_level);
        if block {
            s.bdev_open = 0;
            s.bdev_level = access::NONE;
        } else {
            s.cdev_open = 0;
            s.cdev_level = access::NONE;
        }
        let level_out = dk_add_access(s.bdev_level, s.cdev_level);
        let r = if s.bdev_open == 0 && s.cdev_open == 0 {
            media_close(t, media, Client::Bsd(media))
        } else if level != level_out {
            media_open(t, media, Client::Bsd(media), level_out).map(|_| ())
        } else {
            Ok(())
        };
        r.map_err(Refused::Unmodelled)
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

    #[test]
    fn boot_opens_and_a_volume_open() {
        use access::*;
        let mut t = boot_in(super::super::kern::BootState::Kernel).expect("the root's opens");
        let sys = Media::Volume(0);
        // The root volume's first dkopen was made a writer's, shared by the
        // volume; the container medium holds the AppleAPFSContainer's
        // shared writer and the second bdevvp's reader.
        assert_eq!(t.minors[minor_of(sys)].bdev_level, READER_WRITER);
        assert_eq!(t.media[minor_of(sys)].clients, vec![(Client::Bsd(sys), READER_WRITER | SHARED_LOCK)]);
        assert_eq!(t.container.writers, vec![Client::Media(sys)]);
        assert_eq!(t.media[minor_of(Media::Container)].clients, vec![(Client::Container, READER_WRITER | SHARED_LOCK), (Client::Bsd(Media::Container), READER)]);
        assert_eq!(t.scheme.writers, vec![Client::Media(Media::Container)]);
        assert_eq!(t.media[minor_of(Media::Partition)].clients, vec![(Client::Scheme, READER_WRITER)]);
        assert_eq!(t.gpt.level, READER_WRITER);
        assert_eq!(t.media[minor_of(Media::Whole)].clients, vec![(Client::Gpt, READER_WRITER | SHARED_LOCK)]);
        assert_eq!((t.driver.clone(), t.device_owner), (vec![Client::Media(Media::Whole)], Some(Client::Driver)));
        // Preboot's mount opens its volume for writing: the container is
        // open for writing already.
        let preboot = Media::Volume(4);
        dkopen_in(&mut t, minor_of(preboot) as u32, FREAD | FWRITE, true).unwrap();
        assert_eq!(t.container.writers, vec![Client::Media(sys), Client::Media(preboot)]);
        // An exclusive writer of the partition would tear its scheme down,
        // which holds it open: refused.
        assert_eq!(dkopen_in(&mut t, minor_of(Media::Partition) as u32, FREAD | FWRITE, false), Err(Refused::Errno(EBUSY)));
        assert_eq!(t.minors[minor_of(Media::Partition)], MinorSlot::default());
        // A booted system's table has the Preboot mount's open already.
        let b = boot_in(super::super::kern::BootState::Booted).expect("a booted system's opens");
        assert_eq!(b.container.writers, vec![Client::Media(sys), Client::Media(preboot)]);
        assert_eq!(b.minors[minor_of(preboot)].bdev_level, t.minors[minor_of(preboot)].bdev_level);
    }
}
