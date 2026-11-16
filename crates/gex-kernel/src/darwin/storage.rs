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
    /// The size in bytes of disk0, the main namespace (its IOMedia's
    /// "Size", 4096-byte blocks).
    pub disk0_bytes: Option<u64>,
}

/// The BSD unit numbers ([`Facts::units`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Units {
    pub main: u32,
    pub container: u32,
}

/// The web device's facts. Unset until measured on a 64 GB J120 erase-
/// restored with 21H461; each, once measured, is set here with the
/// measurement cited.
pub const DEVICE: Facts = Facts { units: None, media_order: None, disk0_bytes: None };

/// What measures [`Facts::units`].
pub const UNITS_MEASUREMENT: &str = "the BSD names of the main NVMe namespace's IOMedia and of the AppleAPFSMedia (a sysdiagnose's ioreg IOMedia entries)";

/// What measures [`Facts::disk0_bytes`].
pub const CAPACITY_MEASUREMENT: &str = "the Size of the main NVMe namespace's IOMedia (a sysdiagnose's ioreg IOMedia entries, or TotalDiskCapacity of `ideviceinfo -q com.apple.disk_usage`)";

/// What stands in for [`Facts::units`] while it is unset: the main
/// namespace the first whole disk, the container the next. A reported
/// shortcut ([`unmeasured`]), not a fact of the device.
pub const STAND_IN_UNITS: Units = Units { main: 0, container: 1 };

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
}

/// How many media have nodes: the disk, its partition, the container and
/// its volumes.
pub const MEDIA: usize = 3 + VOLUMES.len();

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
/// kernelcache. A reported shortcut ([`unmeasured`]).
pub const STAND_IN_MEDIA_ORDER: [Media; MEDIA] = {
    let mut out = [Media::Whole, Media::Partition, Media::Container, Media::Volume(0), Media::Volume(0), Media::Volume(0), Media::Volume(0), Media::Volume(0), Media::Volume(0), Media::Volume(0)];
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

/// Whether the volume at slot `index` is unencrypted (or one-key): the
/// System's and Preboot's stand-ins; none for the others yet.
pub fn volume_unencrypted(index: u32) -> Option<bool> {
    match volume(index)?.role {
        role::SYSTEM => Some(SYSTEM_UNENCRYPTED),
        role::PREBOOT => Some(PREBOOT_UNENCRYPTED),
        _ => None,
    }
}

/// Whether the volumes' IOMedia are writable (`IOMedia::isWritable`, the
/// `isWritable` APFS gives `IOMedia::init`, which it calls only through
/// the vtable, 0xfffffff006f27da0): unmeasured. Stand-in: writable.
pub const VOLUMES_WRITABLE: bool = true;

/// What measures [`VOLUMES_WRITABLE`].
pub const VOLUMES_WRITABLE_MEASUREMENT: &str = "the \"Writable\" property of the AppleAPFSVolume entries (a sysdiagnose's ioreg IOMedia entries)";

/// Whether a volume's IOMedia is writable ([`VOLUMES_WRITABLE`]).
pub fn volume_writable() -> bool {
    VOLUMES_WRITABLE
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

/// Whether the NVMe namespace reports itself write-protected: its
/// `IONVMeBlockStorageDevice::reportWriteProtection` (0xfffffff006a96f7c,
/// slot 0x5a8 of its vtable 0xfffffff006fab200) answers bit 0 of the
/// controller's byte +0x189, which the controller sets at run time. disk0's
/// IOMedia is writable when it is not (IOBlockStorageDriver.cpp
/// `instantiateMediaObject`: `!_writeProtected`), and the GPT partition
/// (IOGUIDPartitionScheme.cpp) and the container's `AppleAPFSMedia` (the
/// container scheme's start, 0xfffffff0066829d4, `isWritable()` of the
/// partition at 0xfffffff006682de4) are writable as it is. Unmeasured.
/// Stand-in: writable.
pub const DISK_WRITABLE: bool = true;

/// What measures [`DISK_WRITABLE`].
pub const DISK_WRITABLE_MEASUREMENT: &str = "the \"Writable\" property of disk0's IOMedia (a sysdiagnose's ioreg IOMedia entries)";

/// Whether disk0, its partition and the container's medium are writable
/// ([`DISK_WRITABLE`]).
pub fn disk_writable() -> bool {
    DISK_WRITABLE
}

/// The facts still unset, each with what measures it, as the line gexc
/// reports at start; none once all are measured.
pub fn unmeasured() -> Option<String> {
    let mut gaps = Vec::new();
    if DEVICE.units.is_none() {
        gaps.push(format!("the storage's BSD units (stand-in disk{}, disk{}; measure {UNITS_MEASUREMENT})", STAND_IN_UNITS.main, STAND_IN_UNITS.container));
    }
    if DEVICE.media_order.is_none() {
        gaps.push(format!("the disks' BSD minors (stand-in: the media's registration order; measure {MEDIA_ORDER_MEASUREMENT})"));
    }
    gaps.push(format!("vfs.generic.apfs's sysctl number (stand-in {}; measure {})", super::sysctl::APFS_NODE_STAND_IN, super::sysctl::APFS_NODE_MEASUREMENT));
    gaps.push(format!("whether the System volume is unencrypted (stand-in {SYSTEM_UNENCRYPTED}, no MNT_CPROTECT on /; measure {SYSTEM_UNENCRYPTED_MEASUREMENT})"));
    gaps.push(format!("whether the Preboot volume is unencrypted (stand-in {PREBOOT_UNENCRYPTED}, no MNT_CPROTECT on its mount; measure {PREBOOT_UNENCRYPTED_MEASUREMENT})"));
    gaps.push(super::img4::CHOSEN_STAND_IN.to_string());
    gaps.push(super::preboot::TIMES_STAND_IN.to_string());
    gaps.push(super::preboot::FOUNDATION_MODE_STAND_IN.to_string());
    gaps.push(super::preboot::NEXT_OBJ_ID_STAND_IN.to_string());
    gaps.push(super::kern::DEVFS_STAT_STAND_IN.to_string());
    gaps.push(super::kern::PREBOOT_BOOTED_FLAGS_STAND_IN.to_string());
    gaps.push(format!("whether iBoot's /chosen boot-uuid or apfs-preboot-uuid names the System volume (stand-in {BOOT_UUID_MATCHES}: the root mounted from its snapshot by name, with a new fsid; measure {BOOT_UUID_MEASUREMENT})"));
    gaps.push(format!("whether the volumes' IOMedia are writable (stand-in {VOLUMES_WRITABLE}; measure {VOLUMES_WRITABLE_MEASUREMENT})"));
    gaps.push(format!("whether disk0 is write-protected (stand-in writable: {DISK_WRITABLE}; measure {DISK_WRITABLE_MEASUREMENT})"));
    if DEVICE.disk0_bytes.is_none() {
        gaps.push(format!("disk0's capacity (APFS statfs counts are stand-ins; measure {CAPACITY_MEASUREMENT})"));
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

/// A volume's UUID. newfs_apfs gives the volumes the restore adds (`-D`,
/// no `-T`) the UUID `uuid_from_role` makes of their role:
/// 61706673-7575-6964-RRRR-766f6c756d00 ("apfsuuid", the role, "volum").
/// The System volume is then ASR's restore of the system image's volume,
/// whose UUID is 04769D26-2CA0-4825-B443-E2E5F88300F2 (044-76040-038.dmg);
/// whether ASR keeps it or the volume's own is not yet traced, and the
/// image's stands in (a reported shortcut).
pub fn volume_uuid(index: u32) -> [u8; 16] {
    let Some(v) = volume(index) else { return [0; 16] };
    if v.role == role::SYSTEM {
        return SYSTEM_IMAGE_UUID;
    }
    let mut u = uuid("61706673-7575-6964-0000-766f6c756d00");
    u[8..10].copy_from_slice(&v.role.to_be_bytes());
    u
}

/// The system image's volume's UUID (044-76040-038.dmg).
pub const SYSTEM_IMAGE_UUID: [u8; 16] = uuid("04769D26-2CA0-4825-B443-E2E5F88300F2");


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
        assert_eq!(volume_uuid(4), uuid("61706673-7575-6964-0010-766f6c756d00"), "Preboot");
        assert_eq!(volume_uuid(3), uuid("61706673-7575-6964-0140-766f6c756d00"), "Hardware");
        assert_eq!(volume_uuid(0), SYSTEM_IMAGE_UUID);
    }
}
