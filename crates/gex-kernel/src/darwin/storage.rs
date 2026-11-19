//! The web device's storage: an iPad7,1 (J120) erase-restored with iPadOS
//! 17.7.11 (21H461), as its restore lays the NAND out.
//!
//! The restore (`restored_external` in the erase identity's ramdisk,
//! 044-75545-038.dmg) partitions the storage with one GPT partition,
//! "Container" of type Apple_APFS (`ConstrainContainerSize` unset: all of
//! it), formats it as a container with `newfs_apfs -C`, and adds each volume
//! with `newfs_apfs -A -D -o role=<letter> -v <name> <container>`, giving no
//! index. Its steps add them in this order: `format_media`'s
//! `create_apfs_filesystems` adds System, xART (the device tree has
//! `/arm-io/sep/iop-sep-nub/xART`), Hardware and Preboot (no Baseband Data:
//! J120 has no `baseband` service and no `fstab/baseband-vol`; no Logs:
//! `LogPartitionSize` is unset; Scratch is never made);
//! `init_permanent_update_volume` adds Update; then
//! `perform_restore_installing`'s `create_protected_filesystems` adds Data,
//! and User, as `/filesystems` has `e-apfs`. There is no recoveryOS (the
//! build identities have none).
//!
//! APFS's `apfs_newfs` gives a volume added with no index the slot its role
//! asks for: System slot 0, Data slot 1 (EBUSY if taken), any other role the
//! first free slot from 2 on. A volume's BSD name is its container's and
//! "s" and its slot plus one (`"%ss%d"`); `-D` makes no volume group, so no
//! volume is in one.
//!
//! What the restore's files do not say is a fact of the real device, unset
//! here until it is measured ([`Facts`]) and answered with a documented
//! stand-in meanwhile ([`unmeasured`], which gexc reports at start): the
//! NVMe namespaces the NAND has (each a whole disk ahead of the container's
//! synthesized one, an `AppleAPFSMedia`, which `IOMediaBSDClient` names
//! `disk<N>` with the first free anchor number), and the capacity of disk0,
//! the main namespace.

/// `APFS_VOL_ROLE_*`, as `vol.fs_role` gives them.
pub mod role {
    pub const SYSTEM: u16 = 0x1;
    pub const USER: u16 = 0x2;
    pub const PREBOOT: u16 = 0x10;
    pub const DATA: u16 = 0x40;
    pub const UPDATE: u16 = 0xc0;
    pub const XART: u16 = 0x100;
    pub const HARDWARE: u16 = 0x140;
}

/// A volume of the container: its slot (`apfs_fs_index`), name and role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Volume {
    pub index: u32,
    pub name: &'static str,
    pub role: u16,
}

/// The container's volumes by slot.
pub const VOLUMES: [Volume; 7] = [
    Volume { index: 0, name: "System", role: role::SYSTEM },
    Volume { index: 1, name: "Data", role: role::DATA },
    Volume { index: 2, name: "xART", role: role::XART },
    Volume { index: 3, name: "Hardware", role: role::HARDWARE },
    Volume { index: 4, name: "Preboot", role: role::PREBOOT },
    Volume { index: 5, name: "Update", role: role::UPDATE },
    Volume { index: 6, name: "User", role: role::USER },
];

/// The volume at slot `index`.
pub fn volume(index: u32) -> Option<&'static Volume> {
    VOLUMES.iter().find(|v| v.index == index)
}

/// The first volume, by slot, with role `role`.
pub fn volume_with_role(role: u16) -> Option<&'static Volume> {
    VOLUMES.iter().find(|v| v.role == role)
}

/// A volume's group (`apfs_volume_group_id`): none of these is in one.
pub fn volume_group(_index: u32) -> Option<[u8; 16]> {
    None
}

/// The device facts only a measurement of the real device gives.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Facts {
    /// The BSD unit numbers of the main NVMe namespace's whole disk and of
    /// the container's `AppleAPFSMedia`: the anchor numbers they took as
    /// the NAND's namespaces' disks registered at boot.
    pub units: Option<Units>,
    /// The order the storage's media took their BSD minors in
    /// ([`media_order`]).
    pub media_order: Option<[Media; MEDIA]>,
    /// What the NVMe controller and its main namespace report of
    /// themselves.
    pub nvme: Option<Nvme>,
    /// The GPT the restore wrote on disk0.
    pub gpt: Option<Gpt>,
    /// The container's `nx_uuid`, which newfs_apfs made at the restore.
    pub container_uuid: Option<[u8; 16]>,
}

/// What the internal storage's NVMe controller answers of itself (Identify
/// Controller: the model, serial and firmware strings, trailing spaces
/// trimmed, and ONCS) and of its main namespace, NSID 1 (Identify
/// Namespace: the current LBA format's size, NCAP and EUI64), as
/// IONVMeFamily reads them (0xfffffff006a85d58, 0xfffffff006a954d8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nvme {
    pub model: &'static str,
    pub serial: &'static str,
    pub firmware: &'static str,
    /// ONCS bit 2, Dataset Management: whether the namespace can unmap.
    pub dataset_management: bool,
    /// The LBA size, 512 to 4096 bytes.
    pub block_size: u32,
    /// NCAP, in blocks: disk0's size.
    pub blocks: u64,
    pub eui64: u64,
}

/// disk0's GPT: its disk GUID, and its one entry's first and last LBA,
/// unique GUID and attributes (the restore made the partition "Container",
/// of type Apple_APFS).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gpt {
    pub disk_guid: [u8; 16],
    pub first_lba: u64,
    pub last_lba: u64,
    pub partition_guid: [u8; 16],
    pub attributes: u64,
}

/// The BSD unit numbers ([`Facts::units`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Units {
    pub main: u32,
    pub container: u32,
    /// The firmware namespace's (NSID 2) whole disk's.
    pub firmware: u32,
}

/// The web device's facts. Unset until measured on a 64 GB J120 erase-
/// restored with 21H461; each, once measured, is set here with the
/// measurement cited.
pub const DEVICE: Facts = Facts { units: None, media_order: None, nvme: None, gpt: None, container_uuid: None };

/// What measures [`Facts::units`].
pub const UNITS_MEASUREMENT: &str = "the BSD names of the NVMe namespaces' IOMedia (NS_01's and NS_02's) and of the AppleAPFSMedia (a sysdiagnose's ioreg IOMedia entries)";

/// What measures [`Facts::nvme`].
pub const NVME_MEASUREMENT: &str = "disk0's IOMedia's name, Size and Preferred Block Size, its NVMe namespace's NamespaceUUID, Device Characteristics and IOStorageFeatures (a sysdiagnose's ioreg IOService plane)";

/// What stands in for [`Facts::nvme`] while it is unset: a 64 GB disk
/// (64,000,000,000 bytes) of 4096-byte blocks, the size every other
/// namespace of the device tree's `namespaces` must have (IONVMeFamily's
/// namespace size check, 0xfffffff006a604a8), able to unmap, no EUI64,
/// and strings that say what they are. A reported shortcut
/// ([`unmeasured`]), not a fact of the device.
pub const STAND_IN_NVME: Nvme = Nvme { model: "APPLE SSD (unmeasured)", serial: "(unmeasured)", firmware: "(unmeasured)", dataset_management: true, block_size: 4096, blocks: 15_625_000, eui64: 0 };

/// The NVMe facts in force: the device's, or the stand-in.
pub fn nvme() -> Nvme {
    DEVICE.nvme.unwrap_or(STAND_IN_NVME)
}

/// What measures [`Facts::gpt`].
pub const GPT_MEASUREMENT: &str = "the UUID of disk0's IOGUIDPartitionScheme and the Base, Size, UUID and GPT Attributes of its partition (a sysdiagnose's ioreg IOMedia entries)";

/// What stands in for [`Facts::gpt`]: GUIDs that say they are not the
/// device's (the restore makes them at random), and the partition MediaKit
/// lays out for the restore over the whole disk at [`nvme`]'s geometry
/// ([`super::apfswrite::gpt::Map`]), with no attributes.
pub fn stand_in_gpt() -> Gpt {
    let n = nvme();
    let m = super::apfswrite::gpt::Map::new(u64::from(n.block_size), n.blocks);
    Gpt { disk_guid: uuid("00000000-0000-4000-8000-000000000001"), first_lba: m.first, last_lba: m.last, partition_guid: uuid("00000000-0000-4000-8000-000000000002"), attributes: 0 }
}

/// The GPT in force: the device's, or the stand-in.
pub fn gpt() -> Gpt {
    DEVICE.gpt.unwrap_or_else(stand_in_gpt)
}

/// What measures [`Facts::container_uuid`].
pub const CONTAINER_UUID_MEASUREMENT: &str = "the UUID of the AppleAPFSMedia (a sysdiagnose's ioreg IOMedia entries, or `diskutil apfs list`'s container reference UUID)";

/// What stands in for [`Facts::container_uuid`]: a UUID that says it is
/// not the device's.
pub const STAND_IN_CONTAINER_UUID: [u8; 16] = uuid("00000000-0000-4000-8000-000000000003");

/// The container's `nx_uuid` in force: the device's, or the stand-in.
pub fn container_uuid() -> [u8; 16] {
    DEVICE.container_uuid.unwrap_or(STAND_IN_CONTAINER_UUID)
}

/// disk0's size in bytes: its namespace's blocks.
pub fn disk0_bytes() -> u64 {
    let n = nvme();
    n.blocks * u64::from(n.block_size)
}

/// The container partition's offset and size in bytes on disk0
/// (IOGUIDPartitionScheme's Base and Size: its first LBA, and its last
/// less its first plus one, in disk0's blocks).
pub fn partition_extent() -> (u64, u64) {
    let g = gpt();
    let b = u64::from(nvme().block_size);
    (g.first_lba * b, (g.last_lba + 1 - g.first_lba) * b)
}

/// What stands in for [`Facts::units`] while it is unset: the main
/// namespace the first whole disk, the container the next, the firmware
/// namespace's after it. Each whole disk's `IOMediaBSDClient` takes the
/// first free anchor as it starts, which is when the IOBSD resource is
/// published for the disks already registered by then, so the order is
/// the boot's. The firmware namespace's disk after the container's is
/// what a report of the iOS 16 and later devices' layout gives (the
/// firmware namespace dumped from disk2 there, disk1 before iOS 16 made
/// the container a whole disk of its own). A reported shortcut
/// ([`unmeasured`]), not a fact of the device.
pub const STAND_IN_UNITS: Units = Units { main: 0, container: 1, firmware: 2 };

/// The unit numbers in force: the device's, or the stand-in.
pub fn units() -> Units {
    DEVICE.units.unwrap_or(STAND_IN_UNITS)
}

/// A medium of the storage that `IOMediaBSDClient` gives nodes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Media {
    /// The main namespace's whole disk.
    Whole,
    /// The GPT partition the container is in.
    Partition,
    /// The container's `AppleAPFSMedia`.
    Container,
    /// The container's volume at this slot.
    Volume(u32),
    /// The firmware namespace's (NSID 2) whole disk.
    Firmware,
}

/// How many media have nodes: the disk, its partition, the container, its
/// volumes and the firmware namespace's disk.
pub const MEDIA: usize = 4 + VOLUMES.len();

/// The major `IOMediaBSDClient` takes for every disk, block and character
/// alike: `devsw_add(-1)`, in IOStorageFamily's `IOMediaBSDClientGlobals`
/// constructor, gives the first slot from 1 (`bdevsw_isfree(-1)`) free in
/// both switches. It runs before anything else adds a device: AppleARMPlatform
/// links IOStorageFamily (its OSBundleLibraries in the kernelcache's prelink
/// info), so the family is started, its constructors run, before the platform
/// expert starts and `setPlatform` first publishes IOResources; the kernel's
/// own `cdevsw_add(-1)` callers (pf in `dlil_init`, the pseudo-devices of
/// `bsd_autoconf`, fsevents) run after `bsd_init`'s `IOKitInitializeTime`
/// waits for the platform's IORTC; memdev's `bdevsw_add(-1)` runs only for a
/// RAM disk; and the kexts that call `cdevsw_add` (IOCryptoAcceleratorFamily,
/// IOSerialFamily, AppleOnboardSerial, AppleEmbeddedGPS, AppleStockholmControl,
/// AppleBluetooth) and APFS, which calls `bdevsw_add`, start from nubs below
/// the platform expert. `bdevsw` (conf.c) is all `NO_BDEVICE` and `cdevsw[1]`
/// is `NO_CDEVICE`: the slot is 1.
pub const DISK_MAJOR: u32 = 1;

/// The owner, group and mode of a disk's nodes: `UID_ROOT`, `GID_OPERATOR`,
/// 0640, as `MinorTable::insert` gives a medium with no `owner-uid`,
/// `owner-gid` or `owner-mode` (only the disk image drivers set them).
pub const DISK_OWNER: (u32, u32, u32) = (0, 5, 0o640);

/// What stands in for [`Facts::media_order`] while it is unset: the order
/// the media register in, the disk, its partition (the GPT scheme publishes
/// it from its start on the disk), the container (the container scheme's,
/// on the partition), then the volumes by slot. `IOMediaBSDClient` matches
/// only once `bsd_autoconf`'s `IOKitBSDInit` publishes the IOBSD resource,
/// so the media registered by then take their minors in the order the
/// matching threads start their clients: a fact of the boot, not of the
/// kernelcache. The firmware namespace's disk comes last, after the
/// container's as its unit does ([`STAND_IN_UNITS`]). A reported shortcut
/// ([`unmeasured`]).
pub const STAND_IN_MEDIA_ORDER: [Media; MEDIA] = {
    let mut out = [Media::Whole, Media::Partition, Media::Container, Media::Volume(0), Media::Volume(0), Media::Volume(0), Media::Volume(0), Media::Volume(0), Media::Volume(0), Media::Volume(0), Media::Firmware];
    let mut i = 0;
    while i < VOLUMES.len() {
        out[3 + i] = Media::Volume(VOLUMES[i].index);
        i += 1;
    }
    out
};

/// What measures [`Facts::media_order`].
pub const MEDIA_ORDER_MEASUREMENT: &str = "the BSD Minor of each IOMedia (a sysdiagnose's ioreg IOMedia entries), or `ls -l /dev/disk*`";

/// The media in the order they took their minors: the device's, or the
/// stand-in. A medium's minor is its place here (`MinorTable::insert`
/// takes the first free slot, and none is freed at boot).
pub fn media_order() -> [Media; MEDIA] {
    DEVICE.media_order.unwrap_or(STAND_IN_MEDIA_ORDER)
}

/// A medium's BSD name (`"disk%d%s"`: its whole disk's unit and its slice
/// path).
pub fn media_bsd_name(m: Media) -> String {
    match m {
        Media::Whole => main_bsd_name(),
        Media::Partition => partition_bsd_name(),
        Media::Container => container_bsd_name(),
        Media::Volume(i) => volume_bsd_name(i),
        Media::Firmware => format!("disk{}", units().firmware),
    }
}

/// The medium a BSD name is of, with its minor.
pub fn media_by_name(name: &str) -> Option<(Media, u32)> {
    media_order().into_iter().zip(0..).find(|&(m, _)| media_bsd_name(m) == name)
}

/// Whether the System volume's `apfs_fs_flags` have `APFS_FS_UNENCRYPTED`,
/// which keeps `MNT_CPROTECT` off the root (APFS's live mount,
/// 0xfffffff0066cd35c). The restore makes the volume; what it gives it is
/// unmeasured. Stand-in: unencrypted, as the SystemOS cryptex image's
/// volume is (fs_flags 0x1 in 044-76034-038.dmg).
pub const SYSTEM_UNENCRYPTED: bool = true;

/// What measures [`SYSTEM_UNENCRYPTED`].
pub const SYSTEM_UNENCRYPTED_MEASUREMENT: &str = "`statfs(\"/\")`'s f_flags on the device: MNT_CPROTECT (0x80) clear means unencrypted";

/// Whether the Preboot volume's `apfs_fs_flags` have `APFS_FS_UNENCRYPTED`
/// (or `APFS_FS_ONEKEY`), which keeps `MNT_CPROTECT` off its mount
/// (0xfffffff0066cd35c). The restore makes it (`newfs_apfs -A`, whose
/// arguments `restored_external` builds per role); what it gives it is
/// unmeasured. Stand-in: unencrypted, as the System volume's stand-in is.
pub const PREBOOT_UNENCRYPTED: bool = true;

/// What measures [`PREBOOT_UNENCRYPTED`].
pub const PREBOOT_UNENCRYPTED_MEASUREMENT: &str = "`statfs(\"/private/preboot\")`'s f_flags on the device: MNT_CPROTECT (0x80) clear means unencrypted";

/// `APFS_FS_UNENCRYPTED`, `APFS_FS_ONEKEY`.
pub const APFS_FS_UNENCRYPTED: u64 = 0x1;
pub const APFS_FS_ONEKEY: u64 = 0x8;

/// The `apfs_fs_flags` of the volume at slot `index`: its superblock's in
/// the disk0 image served ([`super::disknode`]); without an image, the
/// System's and Preboot's stand-ins (unencrypted), none for the others.
pub fn volume_fs_flags(index: u32) -> Result<Option<u64>, String> {
    if super::disknode::installed() {
        return super::disknode::volume_fs_flags(index);
    }
    Ok(match volume(index).map(|v| v.role) {
        Some(role::SYSTEM) if SYSTEM_UNENCRYPTED => Some(APFS_FS_UNENCRYPTED),
        Some(role::PREBOOT) if PREBOOT_UNENCRYPTED => Some(APFS_FS_UNENCRYPTED),
        _ => None,
    })
}

/// Whether the volume at slot `index` has `APFS_FS_UNENCRYPTED` (none:
/// not known, see [`volume_fs_flags`]).
pub fn volume_unencrypted(index: u32) -> Option<bool> {
    volume_fs_flags(index).ok().flatten().map(|f| f & APFS_FS_UNENCRYPTED != 0)
}

/// Whether a volume's IOMedia is writable: `AppleAPFSVolume::init` gives
/// `IOMedia::init` its container medium's `isWritable` (0xfffffff00666d52c,
/// the `AppleAPFSMedia` the container is on), which is disk0's
/// ([`disk_writable`]).
pub fn volume_writable() -> bool {
    disk_writable()
}

/// Whether iBoot's `/chosen` names the System volume as the one booted:
/// `apfs-preboot-uuid` its volume group's UUID, or `boot-uuid` its own or
/// its group's (APFS's 0xfffffff0066812b4). Then the root's snapshot gets
/// a virtual device of its own (0xfffffff00667f0a0); else a new fsid and
/// its name before the device's ([`super::kern::ROOT_FSID`],
/// [`super::kern::mount_from`]). The IPSW's device tree has neither
/// property: iBoot adds what it adds at boot. Stand-in: no match.
pub const BOOT_UUID_MATCHES: bool = false;

/// What measures [`BOOT_UUID_MATCHES`].
pub const BOOT_UUID_MEASUREMENT: &str = "`statfs(\"/\")`'s f_mntfromname on the device: \"com.apple.os.update-...@/dev/disk1s1\" for no match, a snapshot device's path for one";

/// Whether disk0, its partition and the container's medium are writable.
/// disk0's IOMedia is writable when its NVMe namespace does not report
/// itself write-protected (IOBlockStorageDriver.cpp `instantiateMediaObject`:
/// `!_writeProtected`), and the GPT partition (IOGUIDPartitionScheme.cpp)
/// and the container's `AppleAPFSMedia` (the container scheme's start,
/// `isWritable()` of the partition at 0xfffffff006682de4) are writable as
/// it is. The namespace's `IONVMeBlockStorageDevice::reportWriteProtection`
/// (0xfffffff006a96f7c, slot 0x5a8 of its vtable 0xfffffff006fab200)
/// answers bit 8 of its controller's flags (+0x188). Only
/// `IONVMeController`'s handler of the SMART log's critical warning (slot
/// 0x628, 0xfffffff006a86214) sets that bit, from the warning's read-only
/// bit, and `AppleEmbeddedNVMeController`, the internal storage's
/// controller, replaces that handler with one that clears the bit and
/// succeeds (0xfffffff006a5cd90, in its vtable 0xfffffff006f9fab0): the
/// namespace is never write-protected.
pub fn disk_writable() -> bool {
    true
}

/// The facts still unset, each with what measures it, as the line gexc
/// reports at start; none once all are measured.
pub fn unmeasured() -> Option<String> {
    let mut gaps = Vec::new();
    if DEVICE.units.is_none() {
        gaps.push(format!("the storage's BSD units (stand-in disk{}, disk{}, firmware disk{}; measure {UNITS_MEASUREMENT})", STAND_IN_UNITS.main, STAND_IN_UNITS.container, STAND_IN_UNITS.firmware));
    }
    if DEVICE.media_order.is_none() {
        gaps.push(format!("the disks' BSD minors (stand-in: the media's registration order; measure {MEDIA_ORDER_MEASUREMENT})"));
    }
    gaps.push(format!("vfs.generic.apfs's sysctl number (stand-in {}; measure {})", super::sysctl::APFS_NODE_STAND_IN, super::sysctl::APFS_NODE_MEASUREMENT));
    gaps.push(format!("whether the System volume is unencrypted without a disk0 image (stand-in {SYSTEM_UNENCRYPTED}, no MNT_CPROTECT on /; measure {SYSTEM_UNENCRYPTED_MEASUREMENT})"));
    gaps.push(format!("whether the Preboot volume is unencrypted without a disk0 image (stand-in {PREBOOT_UNENCRYPTED}, no MNT_CPROTECT on its mount; measure {PREBOOT_UNENCRYPTED_MEASUREMENT})"));
    gaps.push(super::img4::chosen_stand_in().to_string());
    gaps.push(super::preboot::TIMES_STAND_IN.to_string());
    gaps.push(super::preboot::FOUNDATION_MODE_STAND_IN.to_string());
    gaps.push(super::preboot::NEXT_OBJ_ID_STAND_IN.to_string());
    gaps.push(super::kern::DEVFS_STAT_STAND_IN.to_string());
    gaps.push(super::kern::PREBOOT_BOOTED_FLAGS_STAND_IN.to_string());
    gaps.push(super::mig::machine::MEM_ACTUAL_STAND_IN.to_string());
    gaps.push(super::mig::machine::MEM_SIZE_STAND_IN.to_string());
    gaps.push(super::rusage::EL1_STAND_IN.to_string());
    gaps.push(super::rusage::DVFS_STAND_IN.to_string());
    gaps.extend(super::pagecache::stand_ins());
    gaps.push(format!("whether iBoot's /chosen boot-uuid or apfs-preboot-uuid names the System volume (stand-in {BOOT_UUID_MATCHES}: the root mounted from its snapshot by name, with a new fsid; measure {BOOT_UUID_MEASUREMENT})"));
    if DEVICE.nvme.is_none() {
        let n = STAND_IN_NVME;
        gaps.push(format!("the NVMe controller's identity and disk0's geometry (stand-in model {:?}, {} blocks of {} bytes, unmap {}, no EUI64; APFS statfs counts are stand-ins too; measure {NVME_MEASUREMENT})", n.model, n.blocks, n.block_size, n.dataset_management));
    }
    if DEVICE.gpt.is_none() {
        gaps.push(format!("disk0's GPT GUIDs and layout (stand-in: unmeasured GUIDs, the partition over all usable blocks; measure {GPT_MEASUREMENT})"));
    }
    gaps.extend(super::storagestack::unmeasured());
    if DEVICE.container_uuid.is_none() {
        gaps.push(format!("the container's nx_uuid (stand-in 00000000-0000-4000-8000-000000000003; measure {CONTAINER_UUID_MEASUREMENT})"));
    }
    (!gaps.is_empty()).then(|| format!("unmeasured facts of a 64 GB J120 answered with stand-ins: {}", gaps.join("; ")))
}

/// The main namespace's whole disk's BSD name (`disk<main>`).
pub fn main_bsd_name() -> String {
    format!("disk{}", units().main)
}

/// The container partition's BSD name: GPT's first partition of disk0.
pub fn partition_bsd_name() -> String {
    format!("{}s1", main_bsd_name())
}

/// The container's BSD name (`disk<container>`).
pub fn container_bsd_name() -> String {
    format!("disk{}", units().container)
}

/// The BSD name of the volume at slot `index` (`"%ss%d"`).
pub fn volume_bsd_name(index: u32) -> String {
    format!("{}s{}", container_bsd_name(), index + 1)
}

/// A hex digit's value.
const fn hex(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => c - b'A' + 10,
    }
}

/// `uuid_parse` of a string, at compile time.
const fn uuid(s: &str) -> [u8; 16] {
    let b = s.as_bytes();
    let mut out = [0u8; 16];
    let (mut i, mut o) = (0, 0);
    while o < 16 {
        if b[i] == b'-' {
            i += 1;
            continue;
        }
        out[o] = hex(b[i]) << 4 | hex(b[i + 1]);
        i += 2;
        o += 1;
    }
    out
}

/// A volume's UUID as newfs_apfs 2236.140.6 gives it to every volume it
/// adds: the UUID `uuid_from_role` makes (on unless `-T`; the restore's
/// `-D` asks for it again): "apfsuuid", the role big-endian, "volum" and the
/// volume's slot, 61706673-7575-6964-RRRR-766f6c756dII (0x10001b554; the
/// kernel's volume creation, 0xfffffff006672cc8, sets the same last byte).
/// The System volume keeps its own through `apfs_invert`, which makes the
/// system image's volume of the file ASR wrote into it and keeps the outer
/// volume's UUID (its superblock update, 0x100006d00), up to the seal
/// ([`volume_uuid`]).
pub fn formatted_volume_uuid(index: u32) -> [u8; 16] {
    let Some(v) = volume(index) else { return [0; 16] };
    let mut u = uuid("61706673-7575-6964-0000-766f6c756d00");
    u[8..10].copy_from_slice(&v.role.to_be_bytes());
    u[15] = v.index as u8;
    u
}

/// A volume's UUID as the restore leaves it: newfs_apfs's
/// ([`formatted_volume_uuid`]), but the System volume's byte 14 one more,
/// as `apfs_sealvolume -R` raises a predefined UUID's (its main between
/// 0x100006f88 and 0x10000710c, `apfs_is_predefined_volume_uuid`
/// 0x100046264), so 61706673-7575-6964-0001-766f6c756e00.
pub fn volume_uuid(index: u32) -> [u8; 16] {
    let mut u = formatted_volume_uuid(index);
    if volume(index).is_some_and(|v| v.role == role::SYSTEM) {
        u[14] = u[14].wrapping_add(1);
    }
    u
}

/// The name of the System volume's sealed snapshot the restore makes and
/// the root is mounted from: "com.apple.os.update-" and, in hex capitals,
/// the root hash the root hash object holds (`copy_arv_apfs_system_snapshot_name`,
/// restored_external 0x10001d74c, of Preboot's
/// usr/standalone/firmware/root_hash.img4: its payload, the IPSW's
/// Firmware/044-76040-038.dmg.root_hash, whose length at +0xc is 0x20 and
/// hash at +0x10).
pub const ROOT_SNAPSHOT: &str = "com.apple.os.update-61F50C6269A33B16100D87E8A69DE5797CCF07C1AB54AD68B02D5F236F366745";


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_follow_the_restore() {
        // System and Data take their own slots; the rest go from 2 in the
        // order the restore adds them.
        let by_role = |r| volume_with_role(r).unwrap().index;
        assert_eq!(by_role(role::SYSTEM), 0);
        assert_eq!(by_role(role::DATA), 1);
        let rest = [role::XART, role::HARDWARE, role::PREBOOT, role::UPDATE, role::USER];
        assert_eq!(rest.map(by_role), [2, 3, 4, 5, 6]);
        assert!(VOLUMES.iter().enumerate().all(|(i, v)| v.index == i as u32));
    }

    #[test]
    fn names_come_from_the_units() {
        assert_eq!(DEVICE, Facts::default(), "the device's facts stay unset until measured");
        assert_eq!(volume_bsd_name(4), "disk1s5");
        assert!(unmeasured().is_some());
    }

    #[test]
    fn minors_follow_the_media_order() {
        assert_eq!(media_by_name("disk0"), Some((Media::Whole, 0)));
        assert_eq!(media_by_name("disk0s1"), Some((Media::Partition, 1)));
        assert_eq!(media_by_name("disk1"), Some((Media::Container, 2)));
        assert_eq!(media_by_name("disk1s5"), Some((Media::Volume(4), 7)));
        assert_eq!(media_by_name("disk1s8"), None);
    }

    #[test]
    fn volumes_take_their_roles_uuids() {
        assert_eq!(volume_uuid(4), uuid("61706673-7575-6964-0010-766f6c756d04"), "Preboot");
        assert_eq!(volume_uuid(3), uuid("61706673-7575-6964-0140-766f6c756d03"), "Hardware");
        assert_eq!(volume_uuid(0), uuid("61706673-7575-6964-0001-766f6c756e00"), "System, sealed");
        assert_eq!(formatted_volume_uuid(0), uuid("61706673-7575-6964-0001-766f6c756d00"), "System, formatted");
        assert_eq!(volume_uuid(1), uuid("61706673-7575-6964-0040-766f6c756d01"), "Data");
    }
}
