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
pub const DEVICE: Facts = Facts { units: None, disk0_bytes: None };

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

/// The facts still unset, each with what measures it, as the line gexc
/// reports at start; none once all are measured.
pub fn unmeasured() -> Option<String> {
    let mut gaps = Vec::new();
    if DEVICE.units.is_none() {
        gaps.push(format!("the storage's BSD units (stand-in disk{}, disk{}; measure {UNITS_MEASUREMENT})", STAND_IN_UNITS.main, STAND_IN_UNITS.container));
    }
    if DEVICE.disk0_bytes.is_none() {
        gaps.push(format!("disk0's capacity (APFS statfs counts are stand-ins; measure {CAPACITY_MEASUREMENT})"));
    }
    (!gaps.is_empty()).then(|| format!("unmeasured 64 GB J120 facts answered with stand-ins: {}", gaps.join("; ")))
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
}
