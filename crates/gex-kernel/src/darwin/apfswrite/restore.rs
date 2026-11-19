//! disk0 as the erase restore leaves it (the iPad7,1 erase identity's
//! ramdisk, `restored_external` 2899.140.4), its steps in its order:
//!
//! 1. `clean_nand`: DKIOCFORMAT of the whole disk (zeros: the medium starts
//!    zeroed);
//! 2. `create_filesystem_partition`: the GPT ([`super::gpt`]) with the
//!    container partition, its first and last 200 blocks zeroed;
//! 3. `create_apfs_filesystems`: `newfs_apfs -C`, then System, xART
//!    (`-s 10485760`), Hardware (`-s 6291456`) and Preboot, each a
//!    `volumeCreate` the kernel ends with a checkpoint
//!    (`tx_leave(nx, tx, 5)`, 0xfffffff006673bf8) on the container it mounted
//!    read-write once (`nx_ro_to_rw`);
//! 4. `prepare_for_asr`: Update, and its directories;
//! 5. ASR of the operating system image into a file on System,
//!    `apfs_invert`, the removal of the data-volume trees, the seal and the
//!    root snapshot;
//! 6. `create_protected_filesystems`: Data and User, encrypted (`-P`);
//! 7. the Preboot, xART, Hardware and Data contents.
//!
//! The device facts it needs are [`super::super::storage`]'s (geometry, GUIDs,
//! `nx_uuid`). What is not implemented yet is returned, step by step, for
//! the caller to report; the image is complete only when that list is
//! empty.

use super::container;
use super::fsops;
use super::gpt;
use super::tx::{Mode, NewVolume, Nx, VolumeTimes};
use super::{Sink, Window};
use crate::darwin::storage;

/// The steps of the restore the image does not have yet.
pub type Missing = Vec<String>;

/// `cp_os_version()` for the restore's kernel ("21H461", the ramdisk's
/// `kern.osversion`): the Reference's `key_os_version` encoding, the major
/// version in the high byte, the minor letter next, the build number in
/// the low 16 bits.
pub fn key_os_version(build: &str) -> Result<u32, String> {
    let b = build.as_bytes();
    let letter = b.iter().position(|c| c.is_ascii_uppercase()).ok_or_else(|| format!("build {build:?} has no minor letter"))?;
    let major: u32 = build[..letter].parse().map_err(|_| format!("build {build:?}"))?;
    let num: u32 = build[letter + 1..].trim_end_matches(|c: char| c.is_ascii_lowercase()).parse().map_err(|_| format!("build {build:?}"))?;
    if major > 0xff || num > 0xffff {
        return Err(format!("build {build:?} out of the encoding's range"));
    }
    Ok(major << 24 | u32::from(b[letter]) << 16 | num)
}

/// The facts of the restore's run that only the device has: what the
/// kernel's clock read at each call, and which calls each of its
/// transactions holds (on internal storage the kernel commits only when a
/// sync, an unmount or a full transaction asks it to, K 0x675a6a0, so the
/// grouping follows what else wrote to the container meanwhile).
pub const RUN_STAND_IN: &str = "the erase restore's clock readings, transaction grouping and the order its concurrent writers reach the kernel on disk0 (stand-in: the clock of the machine building the image; each call joining the open transaction until a sync, an unmount, a volume creation or a volume rename commits it; asr's thread mounting System first, then restored_external's main-thread steps from init_gigalocker to commit_sep_os all reaching the kernel before asr's first call, then asr's file, its size and its four writer threads' pwrites in step order; the kernel's container unmounted (its last transaction committed, block 0 written) after the unmounts of everything and before apfs_invert opens the device, and again before apfs_sealvolume opens it (drafts/s27/re-seal-snap.md U-H), and the kernel's apfs_reaper thread, started by its next mount of the container, running to its end before anything else reaches the container, so that apfs_sealvolume's mount finds no reaper work (re-seal-snap.md U1'); the threads Data's read-write mount starts making their writes in the order the mount starts them, the pfkur thread's temporary inode then the fixup thread's transaction, both before User's volumeCreate; measure the device's disk0 after its erase restore)";

/// Every stand-in the build takes, for the caller to report: the image
/// is the device's only where these are.
pub fn stand_ins(os: bool, boot: bool) -> Vec<&'static str> {
    let mut v = vec![RUN_STAND_IN, HOST_UUID_STAND_IN, GIGALOCKER_STAND_IN, CLUSTER_STAND_IN, NSIH_STAND_IN];
    if boot {
        v.push(SPLAT_STAND_IN);
        v.push(TICKET_STAND_IN);
        v.push(RESTORE_HOST_STAND_IN);
        v.push(super::snapshot::SNAP_UUID_STAND_IN);
    }
    if os {
        v.push(fsops::FILE_INODE_STAND_IN);
        v.push(super::tx::KEYS_STAND_IN);
        v.push(fsops::PER_FILE_KEY_STAND_IN);
        v.push(USERSESSION_STAND_IN);
        v.push(RESTORE_OPTIONS_STAND_IN);
        v.push(BOM_STAND_IN);
    }
    v
}

/// The restore's build.
pub const RESTORE_BUILD: &str = "21H461";

/// The operating system image asr restores: the IPSW's
/// `044-76040-038.dmg` and its Apple_APFS partition.
pub struct OsImage {
    pub image: std::sync::Arc<crate::darwin::udif::Udif>,
    pub partition: usize,
    /// The IPSW's boot objects install_kernel_cache's list installs
    /// (listed as missing without them).
    pub boot: Option<BootObjects>,
    /// The host's files seal_system_volume takes (the restore's later
    /// steps listed as missing without them).
    pub seal: Option<SealFiles>,
}

/// What the restore host sends seal_system_volume
/// (drafts/s27/re-seal-snap.md 3.1): SystemImageCanonicalMetadataFile and
/// SystemImageRootHashFile, the IPSW's `Firmware/044-76040-038.dmg.mtree`
/// and `.root_hash` (the latter as the host's Image4 file of it,
/// TICKET_STAND_IN).
pub struct SealFiles {
    /// The `.mtree` IM4P: an Apple Archive of `digest.db` and `mtree.txt`.
    pub mtree: Vec<u8>,
    /// The `.root_hash` IM4P.
    pub root_hash: Vec<u8>,
}

impl SealFiles {
    /// The files from an IPSW extracted at `dir`.
    pub fn read(dir: &std::path::Path) -> Result<Self, String> {
        let r = |p: &str| std::fs::read(dir.join(p)).map_err(|e| format!("{}: {e}", dir.join(p).display()));
        Ok(SealFiles { mtree: r("Firmware/044-76040-038.dmg.mtree")?, root_hash: r("Firmware/044-76040-038.dmg.root_hash")? })
    }
}

/// Where a caller looks at the build or stops it (see
/// [`build_disk0_hooked`]).
pub struct Hooks<'h> {
    /// Given the container as asr's first call reaches the kernel; the
    /// build goes on only if it returns true.
    pub before_asr: &'h mut dyn FnMut(&mut Nx<'_>) -> Result<bool, String>,
    /// Run when the container is handed to apfs_invert (its state on disk
    /// then complete).
    pub before_invert: &'h mut dyn FnMut() -> Result<(), String>,
    /// Given the container apfs_invert left; the build goes on only if it
    /// returns true.
    pub after_invert: &'h mut dyn FnMut(&mut Nx<'_>) -> Result<bool, String>,
    /// Run when the container is handed to apfs_sealvolume (its state on
    /// disk then complete).
    pub before_seal: &'h mut dyn FnMut() -> Result<(), String>,
    /// Given the container apfs_sealvolume left; the build goes on only if
    /// it returns true.
    pub after_seal: &'h mut dyn FnMut(&mut Nx<'_>) -> Result<bool, String>,
    /// The device apfs_invert and apfs_sealvolume open reporting
    /// `DK_FEATURE_BARRIER` as this says (the container device's own
    /// answer when `None`).
    pub barrier: Option<bool>,
}

/// Writes disk0 on `disk` (zeroed, the size of [`storage::disk0_bytes`]),
/// with `now` the kernel's clock in nanoseconds since 1970 and `os` the
/// operating system image (the System step is left out without it).
pub fn build_disk0(disk: std::sync::Arc<dyn Sink>, now: &mut dyn FnMut() -> u64, os: Option<&OsImage>) -> Result<Missing, String> {
    build_disk0_with(disk, now, os, &mut |_| Ok(true), &mut || Ok(()), &mut |_| Ok(true), None)
}

/// [`build_disk0`], with `before_asr` given the container as asr's first
/// call reaches the kernel (the build goes on only if it returns true),
/// `before_invert` run when the container is handed to apfs_invert (its state on disk then complete),
/// `after_invert` given the container apfs_invert left (the build goes
/// on only if it returns true), and the device apfs_invert opens
/// reporting `DK_FEATURE_BARRIER` as `barrier` says (the container
/// device's own answer when `None`).
pub fn build_disk0_with(disk: std::sync::Arc<dyn Sink>, now: &mut dyn FnMut() -> u64, os: Option<&OsImage>, before_asr: &mut dyn FnMut(&mut Nx<'_>) -> Result<bool, String>, before_invert: &mut dyn FnMut() -> Result<(), String>, after_invert: &mut dyn FnMut(&mut Nx<'_>) -> Result<bool, String>, barrier: Option<bool>) -> Result<Missing, String> {
    build_disk0_hooked(disk, now, os, &mut Hooks { before_asr, before_invert, after_invert, before_seal: &mut || Ok(()), after_seal: &mut |_| Ok(true), barrier })
}

/// [`build_disk0`] with the caller's [`Hooks`].
pub fn build_disk0_hooked(disk: std::sync::Arc<dyn Sink>, now: &mut dyn FnMut() -> u64, os: Option<&OsImage>, hooks: &mut Hooks<'_>) -> Result<Missing, String> {
    let barrier = hooks.barrier;
    let n = storage::nvme();
    let bs = u64::from(n.block_size);
    if disk.size() != storage::disk0_bytes() {
        return Err(format!("a disk of {} bytes for disk0's {}", disk.size(), storage::disk0_bytes()));
    }
    let mut missing = Missing::new();
    // 2. The GPT, as the device's facts (or their stand-ins) have it.
    let map = gpt::Map::new(bs, n.blocks);
    let g = storage::gpt();
    if (g.first_lba, g.last_lba) != (map.first, map.last) {
        return Err(format!("disk0's GPT facts place the partition at {}..{}, MediaKit at {}..{}", g.first_lba, g.last_lba, map.first, map.last));
    }
    gpt::write(&*disk, &map, g.disk_guid, g.partition_guid)?;
    let (base, size) = map.extent();
    let part = Window { sink: &*disk, base, size };

    // 3. The container and the volumes format_media adds.
    let f = container::format(&part, bs, size / bs, storage::container_uuid())?;
    let mut nx = Nx::formatted(&part, &f, storage::container_uuid(), Mode::Kernel)?;
    // The free queues' age limit follows the container device's
    // DK_FEATURE_BARRIER (0xfffffff00674d5f4 reads it at +0x4f8).
    nx.set_barrier(crate::darwin::storagestack::container_barrier());
    nx.set_solid_state(crate::darwin::storagestack::container_solid_state());
    nx.mount_rw()?;
    let kv = key_os_version(RESTORE_BUILD)?;
    let add_with = |nx: &mut Nx<'_>, name: &str, role: u16, size_bytes: Option<u64>, encrypted: bool, now: &mut dyn FnMut() -> u64| -> Result<u64, String> {
        let formatted = now();
        let root = now();
        let private = now();
        let modified = now();
        let v = NewVolume { name: name.into(), role, encrypted, e_apfs: true, times: VolumeTimes { formatted, root, private, modified }, uid: 0, gid: 0, key_os_version: kv, size_bytes };
        let oid = nx.create_volume(&v)?;
        nx.commit()?;
        Ok(oid)
    };
    let add = |nx: &mut Nx<'_>, name: &str, role: u16, size_bytes: Option<u64>, now: &mut dyn FnMut() -> u64| add_with(nx, name, role, size_bytes, false, now);
    let slot = |nx: &Nx<'_>, oid: u64| nx.fs_oid.iter().position(|&o| o == oid).ok_or_else(|| format!("no volume {oid:#x}"));
    let o = add(&mut nx, "System", storage::role::SYSTEM, None, now)?;
    let system = slot(&nx, o)?;
    let o = add(&mut nx, "xART", storage::role::XART, Some(10_485_760), now)?;
    let xart = slot(&nx, o)?;
    let o = add(&mut nx, "Hardware", storage::role::HARDWARE, Some(6_291_456), now)?;
    let hardware = slot(&nx, o)?;
    let o = add(&mut nx, "Preboot", storage::role::PREBOOT, None, now)?;
    let preboot = slot(&nx, o)?;
    // 4. Update, mounted at /mnt4 and given its directories
    // (`_create_update_partition_folder_hierarchy`, 0x100020854: for each,
    // mkdir, chmod and chown of the user's ids, under the umask 0 the
    // restore set at its start), then unmounted.
    let o = add(&mut nx, "Update", storage::role::UPDATE, None, now)?;
    let update = slot(&nx, o)?;
    fsops::mount_rw(&mut nx, update, now)?;
    update_hierarchy(&mut nx, update, now)?;
    fsops::unmount(&mut nx, update, false, now)?;
    if !(hooks.before_asr)(&mut nx)? {
        return Ok(missing);
    }
    // 5. restore_asr starts asr on its own queue (0x10003f4f4) and the main
    // thread goes on with the steps up to await_asr_and_retry, which waits
    // for it (drafts/s21/re-ops.md): nothing orders the two, so the order
    // here is RUN_STAND_IN's. The asr thread's mount of System
    // (mount_partition(0), `mount_apfs -R`) comes first.
    fsops::mount_rw(&mut nx, system, now)?;
    concurrent_steps(&mut nx, Volumes { system, xart, hardware, preboot, update }, now, &mut missing)?;
    match os {
        Some(os) => {
            // asr's image file written into System (restore_apfs_image_async,
            // restored_external 0x10002d2a4).
            let src = crate::darwin::udif::PartitionMedium { image: std::sync::Arc::clone(&os.image), index: os.partition };
            super::asr::restore_image(&mut nx, system, &src, &os.image.partitions[os.partition], now)?;
        }
        None => missing.push("the System volume's content: ASR of 044-76040-038.dmg into /mnt1/apfs_invert_asr_img (no image given), apfs_invert, the data-volume trees' removal, apfs_sealvolume to the signed root hash, and the com.apple.os.update- snapshot".into()),
    }
    // await_asr_and_retry's unmount of everything (0x100017488 →
    // 0x10002ecb8): from the last slot of restored's table down, each
    // forced (`unmount(MNT_FORCE)`: no VFS_SYNC, but the kernel's
    // tx_finish and its modified_by transaction all the same), xART's after
    // `seputil --gigalocker-shutdown` (a Secure Enclave call only).
    for v in [preboot, update, hardware, xart, system] {
        fsops::unmount(&mut nx, v, true, now)?;
    }
    // The container handed to apfs_invert: the kernel's last transaction
    // committed and block 0 written (a stand-in, in RUN_STAND_IN), then the
    // tool's own mount.
    nx.unmount()?;
    if let Some(os) = os {
        (hooks.before_invert)()?;
        let tool_barrier = barrier.unwrap_or_else(crate::darwin::storagestack::container_barrier);
        super::invert::invert(&mut nx, system, super::asr::IMAGE_NAME, std::sync::Arc::clone(&disk), base, tool_barrier, now)?;
        if !(hooks.after_invert)(&mut nx)? {
            return Ok(missing);
        }
        // The kernel's next mount of the container (await_asr_and_retry
        // mounting xART, 0x100017510): its device's barrier answer, the
        // reaper started on the old trees apfs_invert queued (the
        // apfs_reaper thread, run to its end at the mount: RUN_STAND_IN),
        // its transaction left open.
        nx.set_barrier(crate::darwin::storagestack::container_barrier());
        nx.remount(Mode::Kernel)?;
        nx.reaper_run()?;
        after_invert_mounts(&mut nx, Volumes { system, xart, hardware, preboot, update }, now)?;
        // 6. create_protected_filesystems (0x10002a54c): class D's key
        // obliterated (effaceable storage only), then Data made encrypted
        // (`newfs_apfs -A -D -o role=d -v Data -P`: the kernel's
        // volumeCreate with the container keybag's entries,
        // drafts/s16/re-protected.md; keys and ciphertext KEYS_STAND_IN).
        // Each is mounted read-write as it is made (0x10002a698 →
        // mount_partition, `mount_apfs -R`): Data's mount starts its pfkur
        // and fixup threads, whose writes reach the kernel before User's
        // volumeCreate (RUN_STAND_IN), whose checkpoint commits them; the
        // `.fseventsd/.ramdisk-boot-done` opens after each mount fail at
        // their lookups.
        let o = add_with(&mut nx, "Data", storage::role::DATA, None, true, now)?;
        let data = slot(&nx, o)?;
        fsops::mount_rw(&mut nx, data, now)?;
        // User only when the data volume is split, which `e-apfs` in the
        // device tree's /filesystems makes so (0x100047258).
        let o = add_with(&mut nx, "User", storage::role::USER, None, true, now)?;
        let user = slot(&nx, o)?;
        fsops::mount_rw(&mut nx, user, now)?;
        configure_data_volumes(&mut nx, system, data, user, now)?;
        // reserve_overprov_space (0x1000184ec → 0x10002e5bc, erase only):
        // the disk's size from the whole-disk node's block size and count.
        fsops::reserve_overprov_space(&mut nx, data, storage::disk0_bytes(), crate::darwin::storagestack::container_unmap(), now)?;
        // read_new_os_build_version only reads System; install_splat
        // (0x1000185a8 → 0x10003af24) writes the Cryptex1 under Preboot's
        // cryptex1/current, then install_kernel_cache's list.
        match &os.boot {
            Some(b) => {
                install_splat(&mut nx, Volumes { system, xart, hardware, preboot, update }, b, now)?;
                install_kernel_cache(&mut nx, Volumes { system, xart, hardware, preboot, update }, b, &cluster_pushes, now)?
            }
            None => missing.push("install_splat's Cryptex1 and install_kernel_cache's list (no IPSW given: the Cryptex1 components, the version files, the build manifest and the Cryptex1 ticket in Preboot's cryptex1/current; the kernelcache, devicetree, iBoot and root_hash Image4 files and the AP ticket on Preboot and Hardware)".into()),
        }
        // check_mounted (0x100018b6c): fixup_var (0x10002ef8c):
        // MKBKeyBagCreateSystem writes nothing with enhanced APFS, then the
        // system data volume's bootstrap.
        aks_bootstrap_fs(&mut nx, data, now)?;
        // Then the copy of /private/var, interleaved with System's
        // removals; restore_ota_logs (0x1000367e0) has no saved logs on a
        // device with no previous install and touches no volume; then
        // create_partition_mountpoints.
        fixup_var_copy(&mut nx, system, data, now)?;
        create_partition_mountpoints(&mut nx, system, data, &RestoreOptions::DEFAULTS, now)?;
        let v = Volumes { system, xart, hardware, preboot, update };
        match &os.seal {
            Some(files) => {
                // The main list after check_mounted's block and the NVRAM
                // steps (drafts/s27/re-seal-snap.md 0).
                missing.push("populate_preboot_volume (drafts/s27/re-populate.md: the firmware items copied into Preboot's preallocated files, /mnt9/active's O_TRUNC fast truncate (K 0x669d444 not traced), the directories it makes; its NVRAM reads)".into());
                missing.push(autoboot_sync_missing(&mut nx));
                let tool_barrier = barrier.unwrap_or_else(crate::darwin::storagestack::container_barrier);
                missing.push(IMAGE4_CHECKS_MISSING.into());
                if !seal_system_volume(&mut nx, v, data, user, files, tool_barrier, hooks, now)? {
                    return Ok(missing);
                }
                match &os.boot {
                    Some(_) => {
                        create_system_snapshot(&mut nx, v, now)?;
                        // prepare_data_split, convert_eds_volumes,
                        // split_data_volume and commit_temporary_checkpoint
                        // log and return on an erase restore
                        // (re-seal-snap.md 5).
                        migrate_user_fsevents(&mut nx, v, data, user, now)?;
                        unmount_filesystems(&mut nx, v, data, user, now)?;
                    }
                    None => missing.push("create_system_snapshot, migrate_user_fsevents' mounts and unmount_filesystems (no IPSW boot objects: Preboot has no usr/standalone/firmware/root_hash.img4, whose absence takes the legacy snapshot name and fs_snapshot_root, not implemented)".into()),
                }
            }
            None => missing.push("the restore's later steps, in its order: populate_preboot_volume, set_autoboot_delay's sync, seal_system_volume (its unmounts and apfs_sealvolume), create_system_snapshot, migrate_user_fsevents' mounts and unmount_filesystems (no canonical metadata and root hash given)".into()),
        }
    }
    if os.is_none() {
        missing.push("the Data and User volumes (newfs_apfs -P), made after apfs_invert".into());
        // 7.
        missing.push("the restore's later writes to Preboot (install_kernel_cache's boot objects, populate_preboot_volume, install_splat's cryptex1) and Data's contents".into());
    }
    if os.is_some() {
        missing.push(nvram_missing(&nvram_after_fixup_var(&RestoreOptions::DEFAULTS)?));
    }
    // The kernel's own counting of the checksums it sets (its kext has
    // sites newfs_apfs's copy does not) and whether its read-write mount's
    // block-0 write has the newest mounting version are not traced.
    // Times the kernel still holds in memory: the next rewrite of their
    // inodes (for Data's /keybags, aks_bootstrap_fs's class change in
    // fixup_var, drafts/s26/re-aks-data.md 1) is not reached.
    let mut slots: Vec<usize> = nx.jobj_times.keys().map(|k| k.0).collect();
    slots.dedup();
    for v in slots {
        let held: Vec<String> = nx.jobj_times.iter().filter(|(k, _)| k.0 == v).map(|(k, t)| format!("{:#x} ({}, {})", k.1, t.0, t.1)).collect();
        missing.push(format!("the times {} inodes of volume slot {v} hold in memory (modification, change), written by their next rewrite, a sync pass or their vnodes' reclaim: {}", held.len(), held.join(", ")));
    }
    missing.push("nx_counters[0] and block 0's nx_newest_mounted_version as the kernel's transactions leave them (projected from newfs_apfs's three counting sites; the kext has ten)".into());
    nx.unmount()?;
    Ok(missing)
}

/// The container's volumes by slot.
#[derive(Clone, Copy)]
struct Volumes {
    system: usize,
    xart: usize,
    hardware: usize,
    preboot: usize,
    update: usize,
}

const ROOT_INO: u64 = 2;

/// `_create_update_partition_folder_hierarchy` (0x100020854; helper
/// 0x100020a20): for each directory, mkdir (EEXIST tolerated), chmod and
/// chown to the user `getpwnam` names, under the umask 0 the restore set at
/// its start.
fn update_hierarchy(nx: &mut Nx<'_>, update: usize, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    const MOBILE: (u32, u32) = (501, 501);
    for (path, mode, (uid, gid)) in [("Controller", 0o711, MOBILE), ("Firmware", 0o755, (0, 0)), ("db", 0o777, MOBILE), ("Hardware", 0o500, (0, 0)), ("Hardware/Battery", 0o700, (0, 0))] {
        let (dir, name) = match path.rsplit_once('/') {
            Some((d, n)) => (fsops::lookup(nx, update, ROOT_INO, d)?.ok_or_else(|| format!("no /{d} on Update"))?, n),
            None => (ROOT_INO, path),
        };
        let ino = match fsops::mkdir(nx, update, dir, name, mode, 0, 0, now)? {
            Ok(ino) => ino,
            Err(_) => fsops::lookup(nx, update, dir, name)?.ok_or("an existing directory not found")?,
        };
        fsops::chmod(nx, update, ino, mode, now)?;
        fsops::chown(nx, update, ino, uid, gid, now)?;
    }
    Ok(())
}

/// `_ramrod_create_directory(path, mode, uid, gid)` (0x100047aa4 →
/// 0x100047828, class -1) on volume `vol` for `path` below its root: each
/// component `lstat`ed (repeated slashes skipped by the lookup,
/// vfs_lookup.c:888), and one that does not exist made (mkdir with
/// `mode & 0777` by root, the new directory taking its parent's group,
/// chmod to `mode`, chown to the ids); an existing one is left as it is.
/// The last component's inode number.
fn create_directory(nx: &mut Nx<'_>, vol: usize, path: &str, mode: u16, uid: u32, gid: u32, now: &mut dyn FnMut() -> u64) -> Result<u64, String> {
    let mut dir = ROOT_INO;
    for name in path.split('/').filter(|c| !c.is_empty()) {
        dir = match fsops::lookup(nx, vol, dir, name)? {
            Some(ino) => ino,
            None => {
                let pgid = u32::from_le_bytes(fsops::inode(nx, vol, dir)?[0x4c..0x50].try_into().unwrap());
                let ino = fsops::mkdir(nx, vol, dir, name, mode & 0o777, 0, pgid, now)?.map_err(|e| format!("mkdir {path}: errno {e}"))?;
                fsops::chmod(nx, vol, ino, mode, now)?;
                fsops::chown(nx, vol, ino, uid, gid, now)?;
                ino
            }
        };
    }
    Ok(dir)
}

/// The name of the Preboot volume's directory for this device: the AP
/// ticket's SHA-384 (`/chosen`'s `crypto-hash-method`) in upper-case
/// hexadecimal (0x10004bf94), the ticket the host sends as RootTicketData,
/// whose hash restored checks against `/chosen`'s `boot-manifest-hash`
/// (0x100066150).
pub const NSIH_STAND_IN: &str = "the AP ticket's hash that names the Preboot volume's directory and fills its active file (the host's personalized RootTicketData, equal to iBoot's /chosen boot-manifest-hash) (stand-in: 48 zero bytes, 96 '0' digits; measure /private/preboot/active on the device)";

fn nsih() -> String {
    "0".repeat(super::super::preboot::HASH_DIGITS)
}

/// The main thread's steps between restore_asr and await_asr_and_retry
/// (drafts/s21/re-ops.md sections 3 and 4) as they reach the container.
fn concurrent_steps(nx: &mut Nx<'_>, v: Volumes, now: &mut dyn FnMut() -> u64, missing: &mut Missing) -> Result<(), String> {
    // init_gigalocker (0x1000176e8 → 0x1000296c8): xART mounted read-write
    // at /mnt7 (`mount_apfs -R`; the `.fseventsd/.ramdisk-boot-done` open
    // after it fails at its lookup), then `seputil --gigalocker-init`.
    fsops::mount_rw(nx, v.xart, now)?;
    gigalocker_init(nx, v.xart, now)?;
    // init_permanent_update_volume (0x100017760): Update mounted with
    // `mount -t apfs -o nobrowse`, its hierarchy again (every mkdir finds
    // its directory), `unlink("/mnt4/.reserved")` (ENOENT: a lookup), the
    // unmount.
    fsops::mount_rw(nx, v.update, now)?;
    update_hierarchy(nx, v.update, now)?;
    fsops::unmount(nx, v.update, false, now)?;
    // mount_filesystem (0x10001785c): mount_filesystems mounts Hardware and
    // Preboot (`mount_apfs -R`), Update is mounted again, and System is
    // given its name (set_system_vol_name, 0x100027be0).
    fsops::mount_rw(nx, v.hardware, now)?;
    fsops::mount_rw(nx, v.preboot, now)?;
    fsops::mount_rw(nx, v.update, now)?;
    fsops::set_volume_name(nx, v.system, "System")?;
    // fdr_restore_saved_data (0x100017e10): with no saved FDR archive, the
    // dummy FDR path.
    create_directory(nx, v.hardware, "FactoryData/System/Library/Caches/com.apple.factorydata", 0o755, 0, 0, now)?;
    // update_device_firmware_pre_fdr (0x100017ed4 → 0x100031660 →
    // 0x10002dfe4): the Preboot directory for this ticket, its firmware and
    // kernel-cache directories and the factorydata link; then
    // `_ramrod_write_active_nsih_file_and_heirarchy` (0x100031890 →
    // 0x100056fa8): Cryptexes/OS and Cryptexes/App at the volume's root by
    // `mkpathat_np` (mode 0777: `mkdirat` of Cryptexes/OS fails twice,
    // Cryptexes is made, then OS and App; no chmod or chown), and `active`.
    let p = nsih();
    create_directory(nx, v.preboot, &format!("{p}/usr/standalone/firmware"), 0o755, 0, 0, now)?;
    let caches = create_directory(nx, v.preboot, &format!("{p}/System/Library/Caches/com.apple.kernelcaches"), 0o755, 0, 0, now)?;
    let caches = fsops::parent_of(nx, v.preboot, caches)?;
    // symlink(2) by root under umask 0: ACCESSPERMS, the parent's group.
    fsops::symlink(nx, v.preboot, caches, "com.apple.factorydata", "/mnt6/FactoryData/System/Library/Caches/com.apple.factorydata", 0o777, 0, 0, now)?.map_err(|e| format!("symlink com.apple.factorydata: errno {e}"))?;
    let cryptexes = fsops::mkdir(nx, v.preboot, ROOT_INO, "Cryptexes", 0o777, 0, 0, now)?.map_err(|e| format!("mkdir Cryptexes: errno {e}"))?;
    for name in ["OS", "App"] {
        fsops::mkdir(nx, v.preboot, cryptexes, name, 0o777, 0, 0, now)?.map_err(|e| format!("mkdir Cryptexes/{name}: errno {e}"))?;
    }
    fsops::write_new_file(nx, v.preboot, ROOT_INO, "active", 0o644, p.as_bytes(), &|n| Err(format!("a {n}-byte active file (the direct path's)")), now)?;
    // fdr_prepare's removefile walk of the empty factorydata directory and
    // the access() checks of the later steps only read.
    missing.push("the FDR local store on Hardware (libFDR's writes into /FactoryData/System/Library/Caches/com.apple.factorydata by fdr_prepare's commit, fdr_recover, fdr_auto_challenge_claim and verify_fdr_data: server and device data, file names not traced)".into());
    missing.push("install_fud's firmware on Preboot (<nsih>/usr/standalone/firmware/FUD and the host's personalized images in it, AOP, AVE and StaticTrustCache for the erase identity)".into());
    Ok(())
}

/// What stands in for `/mnt2/keybags/usersession.kb`: UserManagementLayout
/// writes its user manifest with NSPropertyListSerialization (binary,
/// drafts/s21/re-data.md 2.1), two of its values fresh random UUIDs, the
/// order CFBinaryPList takes the dictionaries' keys in and the user
/// dictionary's fields after `userFromManifestDictionary:` not traced.
pub const USERSESSION_STAND_IN: &str = "the bytes of Data's /keybags/usersession.kb (UserManagementLayout's binary user manifest: two random UUIDs per device run, CFBinaryPList's key order and the user dictionary's serialized fields not traced: re-data UNSETTLED-4) (stand-in: a binary property list of the manifest's and the user's listed keys in sorted order, objects uniqued, the UUIDs 00000000-0000-4000-8000-0000000001F5 and ...1F6)";

/// A binary property list (`bplist00`) of `v`: the objects in the order
/// a depth-first walk first meets them (a dictionary's keys, then its
/// values), strings and numbers uniqued, the smallest integer sizes.
fn bplist(v: &super::super::plist::Value) -> Vec<u8> {
    use super::super::plist::Value;
    fn flatten(v: &Value, objs: &mut Vec<Value>, refs: &mut Vec<Vec<usize>>) -> usize {
        if !matches!(v, Value::Dict(_) | Value::Array(_)) {
            if let Some(i) = objs.iter().position(|o| o == v) {
                return i;
            }
        }
        let i = objs.len();
        objs.push(v.clone());
        refs.push(Vec::new());
        let r = match v {
            Value::Dict(d) => {
                let mut d = d.clone();
                d.sort_by(|a, b| a.0.cmp(&b.0));
                let ks: Vec<usize> = d.iter().map(|(k, _)| flatten(&Value::String(k.clone()), objs, refs)).collect();
                let vs: Vec<usize> = d.iter().map(|(_, x)| flatten(x, objs, refs)).collect();
                ks.into_iter().chain(vs).collect()
            }
            Value::Array(a) => a.iter().map(|x| flatten(x, objs, refs)).collect(),
            _ => Vec::new(),
        };
        refs[i] = r;
        i
    }
    fn size_of(n: u64) -> usize {
        if n <= 0xff {
            1
        } else if n <= 0xffff {
            2
        } else if n <= 0xffff_ffff {
            4
        } else {
            8
        }
    }
    fn be(out: &mut Vec<u8>, n: u64, w: usize) {
        out.extend_from_slice(&n.to_be_bytes()[8 - w..]);
    }
    fn marker(out: &mut Vec<u8>, hi: u8, n: usize) {
        if n < 15 {
            out.push(hi | n as u8);
        } else {
            out.push(hi | 0xf);
            let w = size_of(n as u64);
            out.push(0x10 | w.trailing_zeros() as u8);
            be(out, n as u64, w);
        }
    }
    let (mut objs, mut refs) = (Vec::new(), Vec::new());
    flatten(v, &mut objs, &mut refs);
    let rs = size_of(objs.len() as u64);
    let mut out = b"bplist00".to_vec();
    let mut offs = Vec::new();
    for (o, r) in objs.iter().zip(&refs) {
        offs.push(out.len() as u64);
        match o {
            Value::Bool(b) => out.push(if *b { 9 } else { 8 }),
            Value::Integer(n) => {
                let w = if *n < 0 { 8 } else { size_of(*n as u64) };
                out.push(0x10 | w.trailing_zeros() as u8);
                be(&mut out, *n as u64, w);
            }
            Value::String(t) if t.is_ascii() => {
                marker(&mut out, 0x50, t.len());
                out.extend_from_slice(t.as_bytes());
            }
            Value::String(t) => {
                let u: Vec<u16> = t.encode_utf16().collect();
                marker(&mut out, 0x60, u.len());
                u.iter().for_each(|c| out.extend_from_slice(&c.to_be_bytes()));
            }
            Value::Data(d) => {
                marker(&mut out, 0x40, d.len());
                out.extend_from_slice(d);
            }
            Value::Array(_) => {
                marker(&mut out, 0xa0, r.len());
                r.iter().for_each(|&x| be(&mut out, x as u64, rs));
            }
            Value::Dict(_) => {
                marker(&mut out, 0xd0, r.len() / 2);
                r.iter().for_each(|&x| be(&mut out, x as u64, rs));
            }
        }
    }
    let table = out.len() as u64;
    let os = size_of(table);
    offs.iter().for_each(|&o| be(&mut out, o, os));
    out.extend_from_slice(&[0; 6]);
    out.push(os as u8);
    out.push(rs as u8);
    out.extend_from_slice(&(objs.len() as u64).to_be_bytes());
    out.extend_from_slice(&0u64.to_be_bytes());
    out.extend_from_slice(&table.to_be_bytes());
    out
}

/// USERSESSION_STAND_IN's bytes: the user manifest UserManagementLayout's
/// `saveManifest:toPath:` writes for the primary user (drafts/s21/re-data.md
/// 2.1's tables).
fn usersession_kb() -> Vec<u8> {
    use super::super::plist::Value;
    let s = |x: &str| Value::String(x.into());
    let i = |n: i128| Value::Integer(n);
    let user = Value::Dict(vec![
        ("MKBUserSessionID".into(), i(501)),
        ("MKBUserSessionGroupID".into(), i(501)),
        ("MKBUserTypeKey".into(), s("UserSessionOther")),
        ("ShortName".into(), s("mobile")),
        ("FirstName".into(), s("mobile")),
        ("LastName".into(), s("mobile")),
        ("Name".into(), s("mobile")),
        ("DisplayName".into(), s("mobile")),
        ("Language".into(), s("en_US")),
        ("MKBUserSessionUUID".into(), s("00000000-0000-4000-8000-0000000001F5")),
        ("MKBUserSessionAlternateUUID".into(), s("00000000-0000-4000-8000-0000000001F6")),
        ("CreateTimeStamp".into(), s("1970-01-01 00:00:01 +0000")),
        ("LoginTimeStamp".into(), s("1970-01-01 00:00:01 +0000")),
        ("LoginUser".into(), Value::Bool(false)),
        ("Dirty".into(), Value::Bool(false)),
        ("Foreground".into(), Value::Bool(true)),
        ("isPrimary".into(), Value::Bool(true)),
        ("isAdminKey".into(), Value::Bool(true)),
        ("LibinfoHomeDir".into(), s("/var/mobile")),
    ]);
    bplist(&Value::Dict(vec![
        ("DEVICECONFIG".into(), i(0)),
        ("BOOTEDUSER".into(), i(0)),
        ("APNSID".into(), i(1)),
        ("MKBUserSessionVolumeFSType".into(), s("UserVolumeAPFSNative")),
        ("USESSTYPE".into(), i(0)),
        ("LOGINCHECKIN".into(), i(0)),
        ("DEVICENETWORKBG".into(), i(0)),
        ("NUMENT".into(), i(1)),
        ("BLOB".into(), Value::Data(bplist(&Value::Array(vec![user])))),
        ("UserManifestVersion".into(), i(1)),
    ]))
}

/// configure_data_volumes (0x10002a098; drafts/s21/re-data.md 2) on Data
/// (`data`) and User (`user`), when System's image has
/// /System/Library/Templates/User: UserManagementLayout's primary user on
/// Data (2.1, drafts/s23/re-uml-data.md), the AKS identity calls (Secure
/// Enclave only), the user protection of Data's VEK (2.3) and
/// AKSVolumeMap's cookie on User (2.5), each with its checkpoint, the
/// template's copy onto User and aks_bootstrap_user_fs (2.4). The rename
/// leaves /keybags' times in the kernel's memory (`nx.jobj_times`).
fn configure_data_volumes(nx: &mut Nx<'_>, system: usize, data: usize, user: usize, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    let mut t = ROOT_INO;
    for n in ["System", "Library", "Templates", "User"] {
        match fsops::lookup(nx, system, t, n)? {
            Some(i) => t = i,
            None => return Ok(()),
        }
    }
    // createPrimaryUserOnSharedDataVolumePath:@"/mnt2" (UML 0x94a0 →
    // saveManifest:toPath: UML 0xb8b0): mkpath_np of /keybags (0700, root,
    // the root's group), then atomicallyWriteData (UML 0x5a28): the
    // `.writing` file's unlink (ENOENT), its class-D create, one write, the
    // fsync, the swap's ENOENT, the rename, F_BARRIERFSYNC (the commit),
    // the close and the unlink (ENOENT): nothing else written.
    if fsops::lookup(nx, data, ROOT_INO, "keybags")?.is_some() {
        return Err("not implemented: UML finding /mnt2/keybags".into());
    }
    let keybags = fsops::mkdir(nx, data, ROOT_INO, "keybags", 0o700, 0, 0, now)?.map_err(|e| format!("mkdir /mnt2/keybags: errno {e}"))?;
    let ino = fsops::create_protected(nx, data, keybags, "usersession.kb.writing", 0o644, 0, 4, now)?;
    let w = fsops::write_new_protected(nx, data, ino, &usersession_kb(), now)?;
    fsops::fsync_pending(nx, data, &w, now)?;
    let rt = fsops::rename_in_dir(nx, data, keybags, "usersession.kb.writing", "usersession.kb", ino, now)?;
    fsops::barrier_fsync(nx, data, ino, rt.file, now)?;
    // bindAPFSSystemDataVolume (enc 2) and AKSVolumeMap(User, 501).
    nx.vek_set_protection(data)?;
    nx.volume_payload_set(user, 0)?;
    // createPrimaryUserLayoutWithOnUserVolumePath:@"/mnt10"
    // fromSystemVolumePath:@"/mnt1" (UML 0x9f34): the template copied by
    // libcopyfile with the handler's lchown to 501:501, then
    // aks_bootstrap_user_fs.
    user_template_copy(nx, system, t, user, now)?;
    aks_bootstrap_user_fs(nx, user, now)
}

const MOBILE: u32 = 501;

/// copyfile(".../Templates/User/", "/mnt10", COPYFILE_ALL |
/// COPYFILE_RECURSIVE | COPYFILE_NOFOLLOW) by libcopyfile 196.120.5 with
/// UserManagementLayout's handler (lchown to 501:501 at every FINISH),
/// from the template directory `tmpl` on System onto User's root
/// (drafts/s23/re-user-copy.md 1.5 and 5): fts in the source's directory
/// order, each directory made and closed over by the cleanup pass, empty
/// files truncated, compressed ones copied by their decmpfs attribute and
/// UF_COMPRESSED; the source's modes, times and flags applied as
/// COPYFILE_STAT does.
fn user_template_copy(nx: &mut Nx<'_>, system: usize, tmpl: u64, user: usize, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    use fsops::SetAttr;
    let ids = |u: u32, g: u32| SetAttr { uid: Some(u), gid: Some(g), ..Default::default() };
    let times = |m: u64, a: u64| SetAttr { mtime: Some(m), atime: Some(a), ..Default::default() };
    let src_inode = |nx: &mut Nx<'_>, ino: u64| -> Result<(u16, u64, u64, u32), String> {
        let v = fsops::inode(nx, system, ino)?;
        let q = |o: usize| u64::from_le_bytes(v[o..o + 8].try_into().unwrap());
        let (uid, gid, flags) = (u32::from_le_bytes(v[0x48..0x4c].try_into().unwrap()), u32::from_le_bytes(v[0x4c..0x50].try_into().unwrap()), u32::from_le_bytes(v[0x44..0x48].try_into().unwrap()));
        if (uid, gid) != (0, 0) || flags & !0x20 != 0 {
            return Err(format!("not implemented: copying a template item owned {uid}:{gid} or with BSD flags {flags:#x}"));
        }
        Ok((u16::from_le_bytes([v[0x50], v[0x51]]), q(0x18), q(0x28), flags))
    };
    // The root's pre-order: mkdir finds it (EEXIST), then chmodx_np,
    // the empty fchmodx_np, fchown, fchmod, the handler's lchown.
    let (rmode, rmtime, ratime, _) = src_inode(nx, tmpl)?;
    fsops::setattr(nx, user, ROOT_INO, SetAttr { mode: Some(rmode & 0o7777), ..ids(0, 0) }, now)?;
    fsops::setattr(nx, user, ROOT_INO, ids(0, 0), now)?;
    fsops::setattr(nx, user, ROOT_INO, SetAttr { mode: Some(rmode & 0o7777), ..Default::default() }, now)?;
    fsops::setattr(nx, user, ROOT_INO, ids(MOBILE, MOBILE), now)?;
    fn walk(nx: &mut Nx<'_>, system: usize, src: u64, user: usize, dst: u64, now: &mut dyn FnMut() -> u64, item: &dyn Fn(&mut Nx<'_>, u64) -> Result<(u16, u64, u64, u32), String>) -> Result<(), String> {
        use fsops::SetAttr;
        let ids = |u: u32, g: u32| SetAttr { uid: Some(u), gid: Some(g), ..Default::default() };
        let times = |m: u64, a: u64| SetAttr { mtime: Some(m), atime: Some(a), ..Default::default() };
        for (k, ino, ty) in fsops::read_dir(nx, system, src)? {
            let nl = (u32::from_le_bytes(k[8..12].try_into().unwrap()) & 0x3ff) as usize;
            let name = std::str::from_utf8(&k[12..12 + nl - 1]).map_err(|_| "a template name that is not UTF-8")?.to_string();
            let (mode, mtime, atime, flags) = item(nx, ino)?;
            let xattrs = fsops::xattr_names(nx, system, ino)?;
            let gid = u32::from_le_bytes(fsops::inode(nx, user, dst)?[0x4c..0x50].try_into().unwrap());
            match ty {
                4 => {
                    if !xattrs.is_empty() {
                        return Err(format!("not implemented: copying a template directory with extended attributes ({name})"));
                    }
                    let d = fsops::mkdir(nx, user, dst, &name, mode & 0o7777, 0, gid, now)?.map_err(|e| format!("mkdir /mnt10/.../{name}: errno {e}"))?;
                    fsops::setattr(nx, user, d, ids(MOBILE, MOBILE), now)?;
                    walk(nx, system, ino, user, d, now, item)?;
                    cleanup(nx, user, d, mode, mtime, atime, now)?;
                }
                8 => {
                    let v = fsops::inode(nx, system, ino)?;
                    let compressed = flags & 0x20 != 0;
                    let has_stream = v.len() > 0x5c && {
                        let n = u16::from_le_bytes([v[0x5c], v[0x5d]]) as usize;
                        (0..n).any(|i| v[0x60 + 4 * i] == 8)
                    };
                    if has_stream || xattrs.iter().any(|x| !(compressed && x == "com.apple.decmpfs")) {
                        return Err(format!("not implemented: copying a template file with data or extended attributes other than an embedded decmpfs one ({name})"));
                    }
                    let f = fsops::create(nx, user, dst, &name, mode & 0o7777, 0, gid, now)?.map_err(|e| format!("create /mnt10/.../{name}: errno {e}"))?;
                    if compressed {
                        let hdr = fsops::xattr_embedded(nx, system, ino, "com.apple.decmpfs")?.ok_or("a compressed template file with no decmpfs attribute")?;
                        fsops::set_decmpfs_xattr(nx, user, f, &hdr, now)?;
                        fsops::setattr(nx, user, f, ids(MOBILE, MOBILE), now)?;
                        fsops::cas_bsdflags(nx, user, f, 0, 0x20, now)?;
                    } else {
                        fsops::truncate_same(nx, user, f, now)?;
                    }
                    fsops::setattr(nx, user, f, SetAttr { mode: Some(mode & 0o7777), ..ids(0, 0) }, now)?;
                    fsops::setattr(nx, user, f, times(mtime, atime), now)?;
                    fsops::setattr(nx, user, f, ids(0, 0), now)?;
                    fsops::setattr(nx, user, f, SetAttr { mode: Some(mode & 0o7777), ..Default::default() }, now)?;
                    fsops::cas_bsdflags(nx, user, f, flags, flags, now)?;
                    if compressed {
                        fsops::setattr(nx, user, f, times(mtime, atime), now)?;
                    }
                    fsops::setattr(nx, user, f, ids(MOBILE, MOBILE), now)?;
                }
                _ => return Err(format!("not implemented: copying a template item of type {ty} ({name})")),
            }
        }
        Ok(())
    }
    /// The cleanup pass of a copied directory: chmodx_np, fchmod,
    /// fsetattrlist of the source's times, fchown(0, 0), fchmod, the flags'
    /// compare-and-swap, the handler's lchown.
    fn cleanup(nx: &mut Nx<'_>, user: usize, d: u64, mode: u16, mtime: u64, atime: u64, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
        use fsops::SetAttr;
        let ids = |u: u32, g: u32| SetAttr { uid: Some(u), gid: Some(g), ..Default::default() };
        let same = SetAttr { mode: Some(mode & 0o7777), ..Default::default() };
        fsops::setattr(nx, user, d, SetAttr { mode: Some(mode & 0o7777), ..ids(MOBILE, MOBILE) }, now)?;
        fsops::setattr(nx, user, d, same, now)?;
        fsops::setattr(nx, user, d, SetAttr { mtime: Some(mtime), atime: Some(atime), ..Default::default() }, now)?;
        fsops::setattr(nx, user, d, ids(0, 0), now)?;
        fsops::setattr(nx, user, d, same, now)?;
        fsops::cas_bsdflags(nx, user, d, 0, 0, now)?;
        fsops::setattr(nx, user, d, ids(MOBILE, MOBILE), now)
    }
    let _ = times;
    walk(nx, system, tmpl, user, ROOT_INO, now, &src_inode)?;
    cleanup(nx, user, ROOT_INO, rmode, rmtime, ratime, now)
}

/// AppleKeyStore's map for a user's volume (AKS 0x30f60, 72 entries;
/// drafts/s14/restored/aks_bootstrap_map.txt): path, flags (1: set the
/// class on a directory, 2 and 4 kept for its other users, 8: skipped),
/// mode, class. The entries with flags 0x0a are left out: skipped.
const USER_MAP: [(&str, u32, u16, u32); 46] = [
    ("", 0x00, 0o711, 0),
    ("/.ssh", 0x05, 0o700, 4),
    ("/Applications", 0x02, 0o755, 0),
    ("/Containers", 0x02, 0o755, 0),
    ("/Library", 0x00, 0o711, 0),
    ("/Library/CoreDuet", 0x01, 0o755, 4),
    ("/Library/Logs", 0x01, 0o755, 4),
    ("/Library/Logs/CoreDuet", 0x01, 0o755, 4),
    ("/Library/Logs/AppleSupport", 0x01, 0o700, 4),
    ("/Library/Passes", 0x01, 0o755, 4),
    ("/Library/Preferences", 0x01, 0o755, 4),
    ("/Library/MobileInstallation", 0x05, 0o755, 4),
    ("/Library/Voicemail", 0x05, 0o755, 4),
    ("/Library/VoiceServices", 0x05, 0o755, 4),
    ("/Library/CallHistoryDB", 0x05, 0o755, 4),
    ("/Library/Carrier Bundles", 0x05, 0o755, 4),
    ("/Library/CrashReporter", 0x05, 0o755, 4),
    ("/Library/Logs/CrashReporter", 0x05, 0o755, 4),
    ("/Library/Assistant", 0x01, 0o755, 4),
    ("/Library/ApplePushService", 0x01, 0o755, 4),
    ("/Library/AggregateDictionary", 0x01, 0o755, 4),
    ("/Library/BackBoard", 0x01, 0o755, 4),
    ("/Library/DataAccess", 0x01, 0o755, 4),
    ("/Library/IdentityServices", 0x01, 0o755, 4),
    ("/Library/SyncedPreferences", 0x01, 0o755, 4),
    ("/Library/SoftwareUpdate", 0x01, 0o755, 4),
    ("/Library/TCC", 0x01, 0o755, 4),
    ("/Library/MediaStream", 0x01, 0o755, 4),
    ("/Library/MediaStream", 0x05, 0o755, 4),
    ("/Library/Caches", 0x01, 0o700, 4),
    ("/Library/AddressBook", 0x01, 0o700, 4),
    ("/Library/Keyboard", 0x01, 0o700, 4),
    ("/Library/mad", 0x01, 0o700, 4),
    ("/Library/mad/activation_records", 0x01, 0o755, 4),
    ("/Library/ConfigurationProfiles", 0x01, 0o755, 4),
    ("/Library/UserConfigurationProfiles", 0x01, 0o755, 4),
    ("/Library/BulletinBoard", 0x01, 0o755, 4),
    ("/Library/SMS", 0x01, 0o700, 4),
    ("/Library/Calendar", 0x01, 0o700, 4),
    ("/Library/SpringBoard", 0x01, 0o755, 4),
    ("/Library/Cookies", 0x01, 0o700, 4),
    ("/Library/Accounts", 0x01, 0o700, 4),
    ("/Library/Mail", 0x01, 0o700, 4),
    ("/Media", 0x00, 0o750, 0),
    ("/Media/iTunes_Control", 0x05, 0o755, 4),
    ("/Media/Downloads", 0x05, 0o755, 4),
];

/// aks_bootstrap_user_fs("/mnt10", 0, 501, 501) (AKS 0x13a28 →
/// aks_bootstrap_fs_with_map AKS 0x13634; drafts/s21/re-data.md 2.4,
/// drafts/s23/re-user-copy.md 3): with no /.bootstrapped, each map entry
/// in order: a missing path made by mkpath_np with the entry's mode (its
/// parent exists: one mkdir; a mode of 01000 or more would be chmodded:
/// none is) and chowned to 501:501; then a directory whose entry has
/// flag 1 given the entry's class when it has another; existing paths
/// keep their mode and owner. Then /.bootstrapped made (open O_CREAT,
/// 0644) and closed.
fn aks_bootstrap_user_fs(nx: &mut Nx<'_>, user: usize, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    if fsops::lookup(nx, user, ROOT_INO, ".bootstrapped")?.is_some() {
        return Err("not implemented: aks_bootstrap_user_fs on a bootstrapped volume".into());
    }
    for (path, flags, mode, class) in USER_MAP {
        let mut dir = ROOT_INO;
        let mut ino = Some(ROOT_INO);
        let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        for (i, c) in comps.iter().enumerate() {
            match fsops::lookup(nx, user, dir, c)? {
                Some(x) => dir = x,
                None if i + 1 == comps.len() => {
                    ino = None;
                    break;
                }
                None => return Err(format!("not implemented: mkpath_np making the intermediate directories of {path}")),
            }
        }
        let ino = match ino {
            Some(_) => dir,
            None => {
                if mode >= 0o1000 {
                    return Err("not implemented: the chmod of a map mode of 01000 or more".into());
                }
                let gid = u32::from_le_bytes(fsops::inode(nx, user, dir)?[0x4c..0x50].try_into().unwrap());
                let d = fsops::mkdir(nx, user, dir, comps[comps.len() - 1], mode, 0, gid, now)?.map_err(|e| format!("mkdir /mnt10{path}: errno {e}"))?;
                fsops::setattr(nx, user, d, fsops::SetAttr { uid: Some(MOBILE), gid: Some(MOBILE), ..Default::default() }, now)?;
                d
            }
        };
        let v = fsops::inode(nx, user, ino)?;
        let is_dir = u16::from_le_bytes([v[0x50], v[0x51]]) & 0o170000 == 0o040000;
        if is_dir && flags & 1 != 0 {
            fsops::set_dir_class(nx, user, ino, class, now)?;
        } else if !is_dir {
            return Err(format!("not implemented: a bootstrap map path that is not a directory (/mnt10{path})"));
        }
    }
    let gid = u32::from_le_bytes(fsops::inode(nx, user, ROOT_INO)?[0x4c..0x50].try_into().unwrap());
    fsops::create(nx, user, ROOT_INO, ".bootstrapped", 0o644, 0, gid, now)?.map_err(|e| format!("create /mnt10/.bootstrapped: errno {e}"))?;
    Ok(())
}

/// `gethostuuid` on the device (the platform's UUID), which names xART's
/// gigalocker file.
pub const HOST_UUID_STAND_IN: &str = "the device's host UUID (gethostuuid), which names the xART volume's gigalocker file (stand-in 00000000-0000-4000-8000-000000000005; measure `ls /private/xarts` on the device)";
const HOST_UUID: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 5];

/// What the Secure Enclave writes into the gigalocker file through the
/// raw device AppleSEPManager opens on it (S 0x63c8af8): records of 0x9000
/// bytes, written in place with no change to the file system's records.
pub const GIGALOCKER_STAND_IN: &str = "the records the Secure Enclave writes into the xART volume's gigalocker file (device-only: written in place through the file's raw device) (stand-in: none, the zeros the close's fill left; measure the file on the device)";

/// `seputil --gigalocker-init` (SEPU 0x100008484, /mnt7): with no
/// gigalocker file, SEPU 0x10000c8b0 makes "<host UUID>.gl" (upper case,
/// SEPU 0x10000cbe0) with `open(O_RDWR | O_CREAT | O_EXCL, 0600)`,
/// preallocates 6 MiB (`F_PREALLOCATE` {F_ALLOCATEALL, F_PEOFPOSMODE, 0,
/// 0x600000}, the size already a multiple of the volume's block and the
/// page size), grows the file to it and closes it, whose fsync zero-fills
/// the range in the cluster layer's block maps (drafts/s27/re-zerofill.md:
/// /mnt7's I/O attributes come from its volume node as /mnt9's do); then the Secure Enclave call (selector 0x2c) opens the file
/// and its raw device (no file-system write: GIGALOCKER_STAND_IN).
fn gigalocker_init(nx: &mut Nx<'_>, xart: usize, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    const SIZE: u64 = 0x60_0000;
    let u = HOST_UUID;
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02X}")).collect::<String>();
    let name = format!("{}-{}-{}-{}-{}.gl", hex(&u[0..4]), hex(&u[4..6]), hex(&u[6..8]), hex(&u[8..10]), hex(&u[10..16]));
    if fsops::lookup(nx, xart, ROOT_INO, &name)?.is_some() {
        return Err("not implemented: seputil finding a gigalocker file at its first run".into());
    }
    let ino = fsops::create(nx, xart, ROOT_INO, &name, 0o600, 0, 0, now)?.map_err(|e| format!("creating /{name}: errno {e}"))?;
    let got = fsops::preallocate(nx, xart, ino, SIZE, now)?;
    if got != SIZE {
        return Err(format!("the gigalocker preallocation got {got} bytes of {SIZE} (F_ALLOCATEALL fails)"));
    }
    fsops::truncate_grow(nx, xart, ino, SIZE, now)?;
    let (c, m) = cluster_sizes();
    fsops::close_after_grow(nx, xart, ino, c, m, now)
}

/// The IPSW's boot objects the host personalizes for install_kernel_cache's
/// list (drafts/s23/re-kernelcache.md 3): the IM4P payloads as the IPSW has
/// them (their SHA-384 the erase identity's digests).
pub struct BootObjects {
    /// `kernelcache.release.ipad7`.
    pub kernelcache: Vec<u8>,
    /// `Firmware/all_flash/DeviceTree.j120ap.im4p`.
    pub devicetree: Vec<u8>,
    /// `Firmware/all_flash/iBoot.j120.RELEASE.im4p`.
    pub iboot: Vec<u8>,
    /// `Firmware/044-76040-038.dmg.root_hash`.
    pub root_hash: Vec<u8>,
    /// `BuildManifest.plist`, whose erase identity names install_splat's
    /// Cryptex1 components.
    pub manifest: Vec<u8>,
    /// The extracted IPSW, where those components are read from.
    pub dir: std::path::PathBuf,
}

impl BootObjects {
    /// The objects from an IPSW extracted at `dir`.
    pub fn read(dir: &std::path::Path) -> Result<Self, String> {
        let r = |p: &str| std::fs::read(dir.join(p)).map_err(|e| format!("{}: {e}", dir.join(p).display()));
        Ok(BootObjects { kernelcache: r("kernelcache.release.ipad7")?, devicetree: r("Firmware/all_flash/DeviceTree.j120ap.im4p")?, iboot: r("Firmware/all_flash/iBoot.j120.RELEASE.im4p")?, root_hash: r("Firmware/044-76040-038.dmg.root_hash")?, manifest: r("BuildManifest.plist")?, dir: dir.to_path_buf() })
    }
}

/// The AP ticket the host sends as RootTicketData (TSS's, personalized
/// for the device's ECID and nonces) and what the host makes of the boot
/// objects with it.
pub const TICKET_STAND_IN: &str = "the AP ticket (the host's RootTicketData from TSS: its bytes and length decide the personalized files' lengths and so their placement) and the host's Image4 files (KernelCacheFile, DeviceTreeFile, NorImageData's iBoot, SystemImageRootHashFile: drafts/s23/re-kernelcache.md UNSETTLED-3 and 4) (stand-in: the ticket an empty DER SEQUENCE, 30 00; each file IMG4 { \"IMG4\", the IPSW's IM4P, [0] the ticket } in DER, no IM4R; measure /private/preboot/<nsih>/System/Library/Caches/apticket.der and the files beside it on the device)";
const TICKET: [u8; 2] = [0x30, 0x00];

/// What the host answers that decides which of the list's files exist:
/// install_device_tree runs only for a RestoreProtocolVersion of 15 or more
/// (0x100012ce8), and the names take ".img4" when MobileGestalt's
/// Image4Supported is true.
pub const RESTORE_HOST_STAND_IN: &str = "the restore host's RestoreProtocolVersion (15 or more makes install_device_tree write devicetree.img4) and the ramdisk's Image4Supported answer (the .img4 names) (stand-in: 15 or more, and true, as a current host and an Image4 device give; measure /private/preboot/<nsih>/usr/standalone/firmware on the device)";

/// A DER length.
fn der_len(out: &mut Vec<u8>, n: usize) {
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let b = (n as u64).to_be_bytes();
        let skip = b.iter().position(|&x| x != 0).unwrap();
        out.push(0x80 | (8 - skip) as u8);
        out.extend_from_slice(&b[skip..]);
    }
}

/// `IMG4 ::= SEQUENCE { IA5String "IMG4", IM4P, [0] EXPLICIT IM4M }` in
/// DER (TICKET_STAND_IN: no IM4R).
fn img4(im4p: &[u8], ticket: &[u8]) -> Vec<u8> {
    let mut tagged = vec![0xa0];
    der_len(&mut tagged, ticket.len());
    tagged.extend_from_slice(ticket);
    let mut body = vec![0x16, 4];
    body.extend_from_slice(b"IMG4");
    body.extend_from_slice(im4p);
    body.extend_from_slice(&tagged);
    let mut out = vec![0x30];
    der_len(&mut out, body.len());
    out.extend_from_slice(&body);
    out
}

/// What install_splat takes from the restore host and the device's own
/// randomness that only a device run has (drafts/s27/re-splat.md
/// UNSETTLED 1, 4, 5, 9, 12).
pub const SPLAT_STAND_IN: &str = "what install_splat's Cryptex1 on Preboot takes from the restore host and the run (drafts/s27/re-splat.md): the host's SourceBootObjectV4 message sizes, which make the write(2) calls (stand-in: idevicerestore's 8192-byte FileData chunks), the time the transfer takes, which decides when the kernel's grow-ahead starts on os.dmg and app.dmg (stand-in: the model's clock), the build identity the host sends back and CoreFoundation's XML of it (stand-in: the IPSW's erase identity, written by this model's plist writer), the TSS Cryptex1 ticket (stand-in: an empty DER SEQUENCE, 30 00) and Foundation's temporary name for it (stand-in .dat.nosync0000.AAAAAA); measure /private/preboot/cryptex1/current on the device: its files' extents, BuildManifest.plist's bytes and the ticket";

/// The host's FileData message size ([`SPLAT_STAND_IN`]).
const SPLAT_HOST_CHUNK: u64 = 8192;
/// The Cryptex1 ticket ([`SPLAT_STAND_IN`]).
const SPLAT_TICKET: [u8; 2] = [0x30, 0x00];
/// Foundation's temporary file for the ticket (`.dat.nosync%04x.XXXXXX`,
/// F 0x1d63c: the process's identifier and mktemp's random characters;
/// [`SPLAT_STAND_IN`]).
const SPLAT_TICKET_TEMP: &str = ".dat.nosync0000.AAAAAA";

/// The `write(2)` calls stdio makes of a file `fopen(dest, "wb")` gets in
/// `chunk`-byte `fwrite`s, then `fclose` (drafts/s27/re-splat.md 1.5):
/// the buffer is `st_blksize`, 4096 here; an `fwrite` into an empty
/// buffer of at least its size writes the whole buffers of it at once and
/// keeps the rest; `fclose` writes what is kept.
fn stdio_writes(size: u64, chunk: u64) -> Result<Vec<u64>, String> {
    const BUF: u64 = 4096;
    let mut out = Vec::new();
    let mut kept = 0u64;
    let mut at = 0u64;
    while at < size {
        let l = chunk.min(size - at);
        if kept != 0 {
            return Err("not implemented: an fwrite into a partly filled stdio buffer (__sfvwrite's fill-and-flush path)".into());
        }
        if l >= BUF {
            out.push(l / BUF * BUF);
        }
        kept = l % BUF;
        if l < BUF {
            kept = l;
        }
        at += l;
    }
    if kept != 0 {
        out.push(kept);
    }
    Ok(out)
}

/// A file of the extracted IPSW, read as it is needed.
struct IpswFile(std::fs::File, u64);

impl fsops::Bytes for IpswFile {
    fn len(&self) -> u64 {
        self.1
    }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<(), String> {
        std::os::unix::fs::FileExt::read_exact_at(&self.0, buf, off).map_err(|e| e.to_string())
    }
}

/// A regular file's bytes on a volume of the container (one with no
/// hole), read through its extents.
fn file_bytes(nx: &mut Nx<'_>, vol: usize, ino: u64) -> Result<Vec<u8>, String> {
    let v = fsops::inode(nx, vol, ino)?;
    let n = u16::from_le_bytes([v[0x5c], v[0x5d]]) as usize;
    let at = (0..n).position(|i| v[0x60 + 4 * i] == 8).ok_or("not implemented: reading a file with no data stream")?;
    let mut off = 0x60 + 4 * n;
    for i in 0..at {
        off += (u16::from_le_bytes([v[0x60 + 4 * i + 2], v[0x60 + 4 * i + 3]]) as usize + 7) & !7;
    }
    let size = u64::from_le_bytes(v[off..off + 8].try_into().unwrap());
    let oid = u64::from_le_bytes(v[8..16].try_into().unwrap());
    let mut out = vec![0u8; size as usize];
    let bs = nx.block_size();
    let mut pos = 0u64;
    while pos < size {
        let (l, len, p) = fsops::extent_at(nx, vol, oid, pos)?.ok_or("not implemented: reading a file's hole")?;
        let run = (l + len - pos).min(size - pos);
        let first = (pos - l) / bs;
        let mut b = vec![0u8; (run + (pos - l) % bs).div_ceil(bs) as usize * bs as usize];
        nx.read_data(p + first, &mut b)?;
        let skip = ((pos - l) % bs) as usize;
        out[pos as usize..(pos + run) as usize].copy_from_slice(&b[skip..skip + run as usize]);
        pos += run;
    }
    Ok(out)
}

/// install_splat (0x10003af24; drafts/s27/re-splat.md), with Preboot
/// mounted read-write at /mnt9 and System at /mnt1: the build identity's
/// Cryptex1 components (none: nothing), then ramrod_splat_install
/// (0x10006419c): cryptex1/current made by NSFileManager's mkpath_np
/// (mkdirat 0777 under umask 0, so no chmod); each component of the
/// table (0x100268528) present in the identity `fopen(dest, "wb")` (0666)
/// and written in the host's chunks through stdio, its SHA-384 checked;
/// RestoreVersion.plist and SystemVersion.plist copyfile'd from System
/// (COPYFILE_ALL, no state); BuildManifest.plist by -[NSDictionary
/// writeToFile:atomically:NO] (one write, fsync); the Cryptex1 ticket
/// written atomically through a temporary file (write, fsync, rename). No
/// LocalPolicy: J120's chip 0x8011 is in the restore's list of chips
/// without one (0x10027e8d8).
fn install_splat(nx: &mut Nx<'_>, v: Volumes, boot: &BootObjects, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    use super::super::plist::Value;
    use super::super::preboot;
    use fsops::SetAttr;
    let manifest = super::super::plist::parse(&boot.manifest).map_err(|e| format!("BuildManifest.plist: {e}"))?;
    let identity = preboot::erase_identity(&manifest, "j120ap")?;
    let comps = identity.get("Manifest").ok_or("the build identity has no Manifest")?;
    let Value::Dict(keys) = comps else { return Err("the build identity's Manifest is not a dictionary".into()) };
    if !keys.iter().any(|(k, _)| k.starts_with("Cryptex1,")) {
        return Ok(());
    }
    let pb = v.preboot;
    if fsops::lookup(nx, pb, ROOT_INO, preboot::cryptex1::DIR)?.is_some() {
        return Err("not implemented: install_splat finding a cryptex1 directory (removeItemAtPath of proposed and current)".into());
    }
    let root_gid = u32::from_le_bytes(fsops::inode(nx, pb, ROOT_INO)?[0x4c..0x50].try_into().unwrap());
    let cx = fsops::mkdir(nx, pb, ROOT_INO, "cryptex1", 0o777, 0, root_gid, now)?.map_err(|e| format!("mkdir /mnt9/cryptex1: errno {e}"))?;
    let cur = fsops::mkdir(nx, pb, cx, "current", 0o777, 0, root_gid, now)?.map_err(|e| format!("mkdir /mnt9/cryptex1/current: errno {e}"))?;
    let gid = root_gid;
    let (c, m) = cluster_sizes();
    for (key, name) in preboot::cryptex1::OBJECTS {
        let Some(comp) = comps.get(key) else { continue };
        let path = comp.get("Info").and_then(|i| i.get("Path")).and_then(Value::as_str).ok_or_else(|| format!("the build identity's {key} has no Info.Path"))?;
        let digest = comp.get("Digest").and_then(Value::as_data).ok_or_else(|| format!("the build identity's {key} has no Digest"))?;
        let host = boot.dir.join(path);
        let f = std::fs::File::open(&host).map_err(|e| format!("{}: {e}", host.display()))?;
        let size = f.metadata().map_err(|e| e.to_string())?.len();
        let src = IpswFile(f, size);
        {
            use sha2::Digest as _;
            let mut d = sha2::Sha384::new();
            let mut buf = vec![0u8; 8 << 20];
            let mut at = 0;
            while at < size {
                let n = (size - at).min(8 << 20) as usize;
                fsops::Bytes::read_at(&src, at, &mut buf[..n])?;
                d.update(&buf[..n]);
                at += n as u64;
            }
            if d.finalize()[..] != digest[..] {
                return Err(format!("not implemented: install_splat's {key} whose SHA-384 is not its digest (the file left written, the restore failing)"));
            }
        }
        let writes = stdio_writes(size, SPLAT_HOST_CHUNK)?;
        if writes.len() == 1 {
            let mut data = vec![0u8; size as usize];
            fsops::Bytes::read_at(&src, 0, &mut data)?;
            fsops::write_new_file(nx, pb, cur, name, 0o666, &data, &cluster_pushes, now)?;
        } else {
            let ino = fsops::create(nx, pb, cur, name, 0o666, 0, gid, now)?.map_err(|e| format!("open /mnt9/cryptex1/current/{name}: errno {e}"))?;
            fsops::write_appends(nx, pb, ino, &writes, &src, c, m, now)?;
        }
    }
    // The version files, copyfile'd from System's CoreServices.
    let cs = {
        let mut d = ROOT_INO;
        for comp in ["System", "Library", "CoreServices"] {
            d = fsops::lookup(nx, v.system, d, comp)?.ok_or("no /mnt1/System/Library/CoreServices")?;
        }
        d
    };
    let ids = |u: u32, g: u32| SetAttr { uid: Some(u), gid: Some(g), ..Default::default() };
    let times = |m: u64, a: u64| SetAttr { mtime: Some(m), atime: Some(a), ..Default::default() };
    for (_, name) in preboot::cryptex1::VERSIONS {
        let Some(si) = fsops::lookup(nx, v.system, cs, name)? else { continue };
        let sv = fsops::inode(nx, v.system, si)?;
        let q = |o: usize| u64::from_le_bytes(sv[o..o + 8].try_into().unwrap());
        let (uid, sgid, flags) = (u32::from_le_bytes(sv[0x48..0x4c].try_into().unwrap()), u32::from_le_bytes(sv[0x4c..0x50].try_into().unwrap()), u32::from_le_bytes(sv[0x44..0x48].try_into().unwrap()));
        let mode = u16::from_le_bytes([sv[0x50], sv[0x51]]);
        let (mtime, atime) = (q(0x18), q(0x28));
        let xattrs = fsops::xattr_names(nx, v.system, si)?;
        if mode & 0o170000 != 0o100000 || flags & !0x20 != 0 || xattrs.iter().any(|x| !(flags & 0x20 != 0 && x == "com.apple.decmpfs")) {
            return Err(format!("not implemented: copyfile of a {name} with mode {mode:o}, flags {flags:#x} or attributes {xattrs:?}"));
        }
        let keep = flags & !preboot::cryptex1::COPYFILE_OMIT_FLAGS;
        let f = fsops::create(nx, pb, cur, name, (mode | 0o200) & 0o7777, 0, gid, now)?.map_err(|e| format!("open /mnt9/cryptex1/current/{name}: errno {e}"))?;
        if flags & 0x20 != 0 {
            let hdr = fsops::xattr_embedded(nx, v.system, si, "com.apple.decmpfs")?.ok_or("a compressed version file with no decmpfs attribute")?;
            fsops::set_decmpfs_xattr(nx, pb, f, &hdr, now)?;
            fsops::cas_bsdflags(nx, pb, f, 0, 0x20, now)?;
            fsops::setattr(nx, pb, f, SetAttr { mode: Some(mode & 0o7777), ..ids(uid, sgid) }, now)?;
            fsops::setattr(nx, pb, f, times(mtime, atime), now)?;
            fsops::setattr(nx, pb, f, ids(uid, sgid), now)?;
            fsops::setattr(nx, pb, f, SetAttr { mode: Some(mode & 0o7777), ..Default::default() }, now)?;
            fsops::cas_bsdflags(nx, pb, f, 0x20, keep, now)?;
            fsops::setattr(nx, pb, f, times(mtime, atime), now)?;
        } else {
            let data = file_bytes(nx, v.system, si)?;
            if data.is_empty() || data.len() as u64 > nx.block_size() {
                return Err(format!("not implemented: copyfile of a {name} of {} bytes (copyfile_data's loop past one buffer)", data.len()));
            }
            // F_PREALLOCATE {0, F_PEOFPOSMODE, 0, size}: no F_ALLOCATEALL,
            // its result unused by copyfile.
            fsops::preallocate(nx, pb, f, data.len() as u64, now)?;
            let (_, written) = fsops::write_into_preallocation(nx, pb, f, &data, now)?;
            fsops::truncate_equal(nx, pb, f, written, now)?;
            fsops::setattr(nx, pb, f, SetAttr { mode: Some(mode & 0o7777), ..ids(uid, sgid) }, now)?;
            fsops::setattr(nx, pb, f, times(mtime, atime), now)?;
            fsops::setattr(nx, pb, f, ids(uid, sgid), now)?;
            fsops::setattr(nx, pb, f, SetAttr { mode: Some(mode & 0o7777), ..Default::default() }, now)?;
            fsops::cas_bsdflags(nx, pb, f, 0, keep, now)?;
            fsops::close_pushed(nx, pb, f, &data, now)?;
        }
    }
    // BuildManifest.plist: open(0x601, 0666), write, fsync, close. The
    // fsync (apfs_fsync_internal, no commit: drafts/s27/re-txdata.md 4)
    // pushes the data and removes PREV_FSIZE as the close's would; the
    // close then finds nothing to do.
    let xml = preboot::restore_manifest(identity);
    fsops::write_new_file(nx, pb, cur, preboot::cryptex1::MANIFEST, 0o666, &xml, &cluster_pushes, now)?;
    // The ticket: a temporary file (open 0xa02, 0666), write, fsync, the
    // rename onto its name, then the close, whose fsync writes the change
    // time the rename left in the file's memory (K 0x66a1878).
    let tname = preboot::ticket_name()?;
    let t = fsops::write_new_file(nx, pb, cur, SPLAT_TICKET_TEMP, 0o666, &SPLAT_TICKET, &cluster_pushes, now)?;
    let rt = fsops::rename_in_dir(nx, pb, cur, SPLAT_TICKET_TEMP, &tname, t, now)?;
    fsops::write_times(nx, pb, t, rt.file, now)?;
    Ok(())
}

/// install_kernel_cache's nested list (0x100018620; drafts/s23/
/// re-kernelcache.md 1, 2), run after install_splat with Preboot and
/// Hardware mounted read-write: the kernel cache, device tree, iBoot and
/// root hash, each a new file under the Preboot directory of the ticket's
/// hash written by one `write` and closed ([`fsops::write_new_file`]), then
/// write_ticket's AP ticket there, its symbolic link in the firmware
/// directory and its copy on Hardware. The /mnt1 `stat`s and the
/// `access`es only read.
fn install_kernel_cache(nx: &mut Nx<'_>, v: Volumes, boot: &BootObjects, pushes: &dyn Fn(u64) -> Result<fsops::Pushes, String>, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    let p = nsih();
    let dir = |nx: &mut Nx<'_>, vol: usize, path: &str| -> Result<u64, String> {
        let mut d = ROOT_INO;
        for c in path.split('/') {
            d = fsops::lookup(nx, vol, d, c)?.ok_or_else(|| format!("not implemented: install_kernel_cache with no {path} (its mkdir chain)"))?;
        }
        Ok(d)
    };
    let kc = dir(nx, v.preboot, &format!("{p}/System/Library/Caches/com.apple.kernelcaches"))?;
    fsops::write_new_file(nx, v.preboot, kc, "kernelcache", 0o644, &img4(&boot.kernelcache, &TICKET), pushes, now)?;
    let fw = dir(nx, v.preboot, &format!("{p}/usr/standalone/firmware"))?;
    fsops::write_new_file(nx, v.preboot, fw, "devicetree.img4", 0o644, &img4(&boot.devicetree, &TICKET), pushes, now)?;
    fsops::write_new_file(nx, v.preboot, fw, "iBoot.img4", 0o644, &img4(&boot.iboot, &TICKET), pushes, now)?;
    fsops::write_new_file(nx, v.preboot, fw, "root_hash.img4", 0o644, &img4(&boot.root_hash, &TICKET), pushes, now)?;
    // write_ticket (0x1000303d8 → ramrod_ticket_write_explicit 0x1000667a4):
    // the ticket by a plain open(O_WRONLY | O_CREAT | O_TRUNC, 0644), its
    // link (symlink(2) by root under umask 0: ACCESSPERMS, the parent's
    // group) to /private/preboot's path, and the Hardware copy, not linked.
    let caches = dir(nx, v.preboot, &format!("{p}/System/Library/Caches"))?;
    fsops::write_new_file(nx, v.preboot, caches, "apticket.der", 0o644, &TICKET, pushes, now)?;
    let gid = u32::from_le_bytes(fsops::inode(nx, v.preboot, fw)?[0x4c..0x50].try_into().unwrap());
    fsops::symlink(nx, v.preboot, fw, "apticket.der", &format!("/private/preboot/{p}/System/Library/Caches/apticket.der"), 0o777, 0, gid, now)?.map_err(|e| format!("symlink apticket.der: errno {e}"))?;
    let hw = dir(nx, v.hardware, "FactoryData/System/Library/Caches")?;
    fsops::write_new_file(nx, v.hardware, hw, "apticket.der", 0o644, &TICKET, pushes, now)?;
    Ok(())
}

/// What decides how XNU's cluster layer pushes a file's data on disk0's
/// volumes that only the device answers.
pub const CLUSTER_STAND_IN: &str = "how the cluster layer pushes the gigalocker file's close-time zero fill and install_kernel_cache's large files (drafts/s26/re-cluster.md, drafts/s27/re-zerofill.md): the main namespace's limit table index (the byte at its object's +0x1f0) that sets IOMaximumByteCountWrite, and the controller's IOMinimumSaturationByteCount, throttling and any syncer push, which only move the pushes in time (stand-in: the table's type-1 limits, 1 MiB, so 1 MiB clusters and block maps: six for the 6 MiB fill, the first adding a PREV_FSIZE field of 0x100000 the close's fsync removes; the write-behind leaving its last four clusters to the close, the pushes ordered by offset; measure the kernelcache's file extents on the device's Preboot and the xART volume's last_mod_time against the gigalocker file's times)";

/// A disk0 volume's cluster size C and block-map length M
/// (drafts/s26/re-cluster.md): the mount's I/O attributes from the volume
/// node's limits (vfs_init_io_attributes X 0xfffffff0073742f4: Wc the
/// byte count, or the block count's bytes when fewer, 64 MiB with
/// neither; the segment count, else Wc / 16 KiB, at most 0xffff), C =
/// cluster_max_io_size (X 0xfffffff00735ee9c: min(segments, 4096) pages or
/// Wc, a 16 KiB multiple, at least 1 MiB) and M (Wc to a 16 KiB multiple).
fn cluster_sizes() -> (u64, u64) {
    const PAGE: u64 = 16 << 10;
    let bs = u64::from(storage::nvme().block_size);
    let (w, b, sg) = crate::darwin::storagestack::disk0_write_limits();
    let mut wc = if w != 0 { w.min(u64::from(u32::MAX)) } else { 64 << 20 };
    if b != 0 && (b * bs).min(u64::from(u32::MAX)) < wc {
        wc = (b * bs).min(u64::from(u32::MAX));
    }
    let sc = if sg != 0 { sg.min(0xffff) } else { (wc / PAGE).min(0xffff) };
    let c = ((sc.min(4096) * PAGE).min(wc) & !(PAGE - 1)).max(1 << 20);
    let m = match wc & !(PAGE - 1) {
        0 => PAGE,
        x => x,
    };
    (c, m)
}

/// The pushes of one `write(2)` of `n` bytes from offset 0 into a new file
/// on a disk0 volume (drafts/s26/re-cluster.md): the mount's I/O
/// attributes from the volume node's limits (vfs_init_io_attributes X
/// 0xfffffff0073742f4: Wc the byte count, or the block count's bytes when
/// fewer, 64 MiB with neither; the segment count, else Wc / 16 KiB, at
/// most 0xffff), the cluster size C = cluster_max_io_size (X
/// 0xfffffff00735ee9c: min(segments, 4096) pages or Wc, a 16 KiB multiple,
/// at least 1 MiB) and the block-map length M (Wc to a 16 KiB multiple);
/// cluster_write_copy files the data in clusters of C up to the 16 KiB
/// page end, each pushed as block maps of at most M; with MAX_CLUSTERS 4,
/// the write-behind pushes the lowest cluster each time a fifth is added,
/// so all but the last four go during the write and the close's push takes
/// those in order. Block maps are clipped at the file's hole end (round_up
/// to the volume's block), where APFS stops allocating.
fn cluster_pushes(n: u64) -> Result<fsops::Pushes, String> {
    const PAGE: u64 = 16 << 10;
    const MAX_CLUSTERS: usize = 4;
    let bs = u64::from(storage::nvme().block_size);
    let (c, m) = cluster_sizes();
    let end16 = n.div_ceil(PAGE) * PAGE;
    let hole = n.div_ceil(bs) * bs;
    let clusters = end16.div_ceil(c);
    let mut maps = Vec::new();
    let mut before_end = 0;
    for k in 0..clusters {
        let (start, stop) = (k * c, ((k + 1) * c).min(end16));
        let mut off = start;
        while off < stop {
            let len = m.min(stop - off);
            if off >= hole {
                return Err(format!("not implemented: a block map past a file's hole end ({off:#x} of {n} bytes)"));
            }
            maps.push((off, len.min(hole - off)));
            off += len;
        }
        if (k as usize) + MAX_CLUSTERS < clusters as usize {
            before_end = maps.len();
        }
    }
    Ok(fsops::Pushes { maps, before_end })
}

/// AppleKeyStore's map for the system data volume (AKS 0x308d0, 35
/// entries; drafts/s14/restored/aks_bootstrap_map.txt): path, flags (1:
/// set the class on a directory, 8: skipped), mode, owner and group as the
/// ramdisk's /etc/master.passwd and /etc/group name them (root and wheel
/// 0, daemon 1, _securityd 64, _wireless 25, _networkd 24, mobile 501;
/// drafts/s26/re-aks-data.md 2.5), class. The flags-0x0a entries are left
/// out: skipped.
const SYSTEM_MAP: [(&str, u32, u16, u32, u32, u32); 27] = [
    ("/keybags", 0x01, 0o700, 0, 0, 4),
    ("/logs", 0x01, 0o755, 0, 0, 4),
    ("/logs/AppleSupport", 0x01, 0o755, 0, 0, 4),
    ("/logs/BurnIn", 0x05, 0o755, 0, 0, 4),
    ("/log", 0x01, 0o755, 0, 0, 4),
    ("/log/com.apple.xpc.launchd", 0x01, 0o755, 0, 0, 4),
    ("/MobileSoftwareUpdate", 0x01, 0o755, 0, 0, 4),
    ("/tmp", 0x01, 0o1777, 0, 0, 4),
    ("/Keychains", 0x01, 0o755, 64, 0, 4),
    ("/preferences", 0x01, 0o755, 0, 0, 4),
    ("/vm", 0x01, 0o755, 0, 0, 4),
    ("/run", 0x01, 0o775, 0, 1, 4),
    ("/db", 0x01, 0o755, 0, 0, 4),
    ("/db/com.apple.xpc.launchd", 0x01, 0o755, 0, 0, 4),
    ("/wireless", 0x05, 0o755, 25, 25, 4),
    ("/Managed Preferences", 0x01, 0o755, 0, 0, 4),
    ("/networkd", 0x01, 0o755, 24, 24, 4),
    ("/root", 0x01, 0o755, 0, 0, 4),
    ("/root/Library", 0x00, 0o755, 0, 0, 0),
    ("/root/Library/Logs", 0x01, 0o755, 0, 0, 4),
    ("/root/Library/Preferences", 0x01, 0o755, 0, 0, 4),
    ("/root/Library/Lockdown", 0x01, 0o700, 0, 0, 4),
    ("/root/Library/Caches", 0x05, 0o700, 0, 0, 4),
    ("/containers", 0x02, 0o755, 0, 0, 0),
    ("/MobileAsset", 0x01, 0o755, 0, 0, 4),
    ("/MobileDevice/ProvisioningProfiles", 0x01, 0o755, 0, 0, 4),
    ("/Managed Preferences/mobile", 0x01, 0o755, 501, 501, 4),
];

/// fixup_var's `aks_bootstrap_fs("/mnt2", 1)` (AKS 0x13b1c; drafts/s26/
/// re-aks-data.md 2-4), after `MKBKeyBagCreateSystem`, which writes nothing
/// with enhanced APFS: with no /root/.bootstrapped, each system map entry in
/// order (the mobile map is skipped with enhanced APFS): a missing path made
/// by mkpath_np (missing intermediates by mkdir 0777 with no owner or class
/// change, then the entry's mkdir with its mode masked to 0777), chmod to the
/// entry's mode when it is 0x200 or more, chown to its owner and group; then
/// a directory whose entry has flag 1 given the entry's class when its
/// stored class differs. Then /root/.bootstrapped made by open(O_WRONLY |
/// O_CREAT, 0644), which takes /root's class, and closed.
fn aks_bootstrap_fs(nx: &mut Nx<'_>, data: usize, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    use fsops::SetAttr;
    if let Some(root) = fsops::lookup(nx, data, ROOT_INO, "root")? {
        if fsops::lookup(nx, data, root, ".bootstrapped")?.is_some() {
            return Err("not implemented: aks_bootstrap_fs on a bootstrapped data volume".into());
        }
    }
    let gid_of = |nx: &mut Nx<'_>, ino: u64| -> Result<u32, String> { Ok(u32::from_le_bytes(fsops::inode(nx, data, ino)?[0x4c..0x50].try_into().unwrap())) };
    for (path, flags, mode, uid, gid, class) in SYSTEM_MAP {
        let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        let mut dir = ROOT_INO;
        let mut made = false;
        for (i, c) in comps.iter().enumerate() {
            dir = match fsops::lookup(nx, data, dir, c)? {
                Some(x) => x,
                None => {
                    let last = i + 1 == comps.len();
                    let m = if last { mode & 0o777 } else { 0o777 };
                    let g = gid_of(nx, dir)?;
                    let d = fsops::mkdir(nx, data, dir, c, m, 0, g, now)?.map_err(|e| format!("mkdir /mnt2{path}: errno {e}"))?;
                    made |= last;
                    d
                }
            };
        }
        if made {
            if mode >= 0x200 {
                fsops::setattr(nx, data, dir, SetAttr { mode: Some(mode), ..Default::default() }, now)?;
            }
            fsops::setattr(nx, data, dir, SetAttr { uid: Some(uid), gid: Some(gid), ..Default::default() }, now)?;
        }
        let v = fsops::inode(nx, data, dir)?;
        if u16::from_le_bytes([v[0x50], v[0x51]]) & 0o170000 != 0o040000 {
            return Err(format!("not implemented: a bootstrap map path that is not a directory (/mnt2{path})"));
        }
        if flags & 1 != 0 && u32::from_le_bytes(v[0x3c..0x40].try_into().unwrap()) != class {
            fsops::set_dir_class(nx, data, dir, class, now)?;
        }
    }
    let root = fsops::lookup(nx, data, ROOT_INO, "root")?.ok_or("no /mnt2/root after the bootstrap map")?;
    let g = gid_of(nx, root)?;
    fsops::create(nx, data, root, ".bootstrapped", 0o644, 0, g, now)?.map_err(|e| format!("create /mnt2/root/.bootstrapped: errno {e}"))?;
    Ok(())
}

/// What fixup_var's copy of /private/var onto Data takes from the device
/// run and from what is not traced (drafts/s27/re-bomcopy.md UNSETTLED,
/// drafts/s27/re-datawrite.md UNSETTLED).
pub const BOM_STAND_IN: &str = "what fixup_var's BOM copy of /private/var onto Data takes from the run (drafts/s27/re-bomcopy.md, re-datawrite.md): mktemp's random temporary names, which decide where their directory records sit until the rename (stand-in .BC.T_AAAAAA for files, .BC.D_AAAAAA for the link), the kernel's readdir order of a System directory whose files the copy unlinks as it goes (stand-in: key order, resumed after the last entry read), listxattr's order and its hiding of com.apple.fs.symlink (stand-in: the attribute records' key order, the link's target attribute not listed), when the change times the renames of the copied plain files leave in memory are written (a sync pass or the vnode's reclaim: listed as pending), and for the files written in several 128 KiB writes the cluster layer's sizes and pushes (as CLUSTER_STAND_IN's) and whether a second passes between a file's creation and an append, which starts grow-ahead (stand-in: the clock of the machine building the image); measure /private/var on a restored device, and a kdebug trace of the copy";

/// BOM's temporary names ([`BOM_STAND_IN`]).
const BOM_FILE_TEMP: &str = ".BC.T_AAAAAA";
const BOM_LINK_TEMP: &str = ".BC.D_AAAAAA";

/// fixup_var's copy of /mnt1/private/var onto /mnt2 (Bom's legacy engine,
/// drafts/s27/re-bomcopy.md 0.1, 2; drafts/s27/re-datawrite.md 0) with
/// restored's handler unlinking each copied regular file under a moved
/// tree from System (drafts/s18/re-unlink-order.md), then removefile of
/// the moved trees. The walk takes System's directories in readdir order
/// onto Data's root, which is never changed itself:
/// - a directory not on Data (only one under a directory BOM found there
///   is looked for): mkdir 0777 (its parent's group), lchown, chmod to its
///   mode, its contents, then setattrlist of its modification and access
///   times; one there is walked into and left as it is;
/// - a regular file: a temporary file opened O_CREAT|O_EXCL 0600, a plain
///   one's data written in writes of at most 0x20000 bytes and the close,
///   a compressed one given no data but its attributes in listxattr's
///   order by setxattr in chunks of at most 8 MiB (the resource fork's
///   stream, the decmpfs header embedded); lchown, chmod, setattrlist of its
///   times; the rename into place; for a compressed one the flags'
///   compare-and-swap to UF_COMPRESSED and its times again. A plain file
///   keeps the change time its rename left in memory;
/// - a symbolic link: made under a temporary name (mode 0777), renamed,
///   lchown and lchmod.
pub fn fixup_var_copy(nx: &mut Nx<'_>, system: usize, data: usize, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    let var = resolve(nx, system, "private/var")?.ok_or("no /mnt1/private/var")?;
    let mut linked = std::collections::BTreeSet::new();
    copy_dir(nx, system, data, var, ROOT_INO, "", true, &mut linked, now)?;
    fsops::removefile_moved(nx, system, var, now)
}

/// An object's owner, group, mode, BSD flags, modification and access
/// times and link count, as stat gives them.
struct SrcStat {
    uid: u32,
    gid: u32,
    mode: u16,
    flags: u32,
    mtime: u64,
    atime: u64,
    nlink: u32,
}

fn src_stat(nx: &mut Nx<'_>, vol: usize, ino: u64) -> Result<SrcStat, String> {
    let v = fsops::inode(nx, vol, ino)?;
    let q = |o: usize| u64::from_le_bytes(v[o..o + 8].try_into().unwrap());
    let d = |o: usize| u32::from_le_bytes(v[o..o + 4].try_into().unwrap());
    Ok(SrcStat { uid: d(0x48), gid: d(0x4c), mode: u16::from_le_bytes([v[0x50], v[0x51]]), flags: d(0x44), mtime: q(0x18), atime: q(0x28), nlink: d(0x38) })
}

/// An attribute's whole value on unencrypted volume `vol`: embedded, or
/// read from its stream.
fn xattr_value(nx: &mut Nx<'_>, vol: usize, ino: u64, name: &str) -> Result<Vec<u8>, String> {
    let r = fsops::xattr_record(nx, vol, ino, name)?.ok_or_else(|| format!("no attribute {name}"))?;
    if u16::from_le_bytes([r[0], r[1]]) & 1 != 0 {
        let q = |o: usize| u64::from_le_bytes(r[o..o + 8].try_into().unwrap());
        fsops::read_stream(nx, vol, q(4), q(12))
    } else {
        Ok(r[4..4 + u16::from_le_bytes([r[2], r[3]]) as usize].to_vec())
    }
}

/// `__copyFromDirToDir` (BOM@0x2d714) of System's directory `sdir` (at
/// /private/var/`rel`) onto Data's `ddir`, `preexisted` when BOM found
/// `ddir` there ([`fixup_var_copy`]).
#[allow(clippy::too_many_arguments)]
fn copy_dir(nx: &mut Nx<'_>, system: usize, data: usize, sdir: u64, ddir: u64, rel: &str, preexisted: bool, linked: &mut std::collections::BTreeSet<u64>, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    use fsops::SetAttr;
    const DT_DIR: u16 = 4;
    const DT_REG: u16 = 8;
    const DT_LNK: u16 = 10;
    let ids = |s: &SrcStat| SetAttr { uid: Some(s.uid), gid: Some(s.gid), ..Default::default() };
    let times = |s: &SrcStat| SetAttr { mtime: Some(s.mtime), atime: Some(s.atime), ..Default::default() };
    let moved = |path: &str| fsops::MOVED_FROM_VAR.iter().any(|m| path.starts_with(&format!("{m}/")));
    for (k, ino, ty) in fsops::read_dir(nx, system, sdir)? {
        let nl = (u32::from_le_bytes(k[8..12].try_into().unwrap()) & 0x3ff) as usize;
        let name = std::str::from_utf8(&k[12..12 + nl - 1]).map_err(|_| "a /private/var name that is not UTF-8")?.to_string();
        if name.starts_with(".nfs") || name.starts_with(".afpDeleted") {
            continue;
        }
        let path = if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") };
        if ty == DT_REG && name.starts_with("._") {
            return Err(format!("not implemented: an AppleDouble file BOM copies after its directory (/private/var/{path})"));
        }
        let exists = if preexisted { fsops::lookup(nx, data, ddir, &name)? } else { None };
        let s = src_stat(nx, system, ino)?;
        let xattrs = fsops::xattr_names(nx, system, ino)?;
        let pgid = u32::from_le_bytes(fsops::inode(nx, data, ddir)?[0x4c..0x50].try_into().unwrap());
        match ty {
            DT_DIR => {
                if let Some(d) = exists {
                    if u16::from_le_bytes(fsops::inode(nx, data, d)?[0x50..0x52].try_into().unwrap()) & 0o170000 != 0o040000 {
                        return Err(format!("BOM meeting a non-directory at /mnt2/{path} (a conflict: the copy fails)"));
                    }
                    copy_dir(nx, system, data, ino, d, &path, true, linked, now)?;
                    continue;
                }
                if !xattrs.is_empty() || s.flags != 0 || s.mode & 0o700 != 0o700 {
                    return Err(format!("not implemented: copying a directory with extended attributes, flags or without owner rwx (/private/var/{path})"));
                }
                let d = fsops::mkdir(nx, data, ddir, &name, 0o777, 0, pgid, now)?.map_err(|e| format!("mkdir /mnt2/{path}: errno {e}"))?;
                fsops::setattr(nx, data, d, ids(&s), now)?;
                fsops::chmod(nx, data, d, s.mode & 0o7777, now)?;
                copy_dir(nx, system, data, ino, d, &path, false, linked, now)?;
                fsops::setattr(nx, data, d, times(&s), now)?;
            }
            DT_REG => {
                if exists.is_some() {
                    return Err(format!("not implemented: BOM meeting an existing file at /mnt2/{path}"));
                }
                if s.nlink > 1 && !linked.insert(ino) {
                    return Err(format!("not implemented: a second link to a copied file (BOM's link(2) of /mnt2/{path})"));
                }
                let compressed = s.flags & 0x4000_0020 == 0x20;
                if s.flags & !0x20 != 0 {
                    return Err(format!("not implemented: copying a file with BSD flags {:#x} (/private/var/{path})", s.flags));
                }
                let t = fsops::create(nx, data, ddir, BOM_FILE_TEMP, 0o600, 0, pgid, now)?.map_err(|e| format!("open /mnt2/{rel}/{BOM_FILE_TEMP}: errno {e}"))?;
                if compressed {
                    for x in &xattrs {
                        let value = xattr_value(nx, system, ino, x)?;
                        match x.as_str() {
                            "com.apple.ResourceFork" => {
                                for (i, chunk) in value.chunks(0x80_0000).enumerate() {
                                    fsops::setxattr_rsrc_fork(nx, data, t, (i * 0x80_0000) as u64, chunk, now)?;
                                }
                            }
                            "com.apple.decmpfs" if value.len() <= 0x80_0000 => fsops::set_decmpfs_xattr(nx, data, t, &value, now)?,
                            _ => return Err(format!("not implemented: copying the attribute {x} (/private/var/{path})")),
                        }
                    }
                } else {
                    if !xattrs.is_empty() {
                        return Err(format!("not implemented: copying a plain file's extended attributes (/private/var/{path})"));
                    }
                    let sv = fsops::inode(nx, system, ino)?;
                    let size = fsops::dstream_size(&sv)?;
                    if size != 0 {
                        let bytes = fsops::read_stream(nx, system, u64::from_le_bytes(sv[8..16].try_into().unwrap()), size)?;
                        let writes: Vec<u64> = (0..size).step_by(0x20000).map(|o| (size - o).min(0x20000)).collect();
                        if writes.len() == 1 {
                            fsops::write_first(nx, data, t, &bytes, &cluster_pushes, now)?;
                        } else {
                            let (c, m) = cluster_sizes();
                            fsops::write_appends(nx, data, t, &writes, &bytes, c, m, now)?;
                        }
                    }
                }
                fsops::setattr(nx, data, t, ids(&s), now)?;
                fsops::chmod(nx, data, t, s.mode & 0o7777, now)?;
                fsops::setattr(nx, data, t, times(&s), now)?;
                let rt = fsops::rename_in_dir(nx, data, ddir, BOM_FILE_TEMP, &name, t, now)?;
                if compressed {
                    fsops::cas_bsdflags(nx, data, t, 0, 0x20, now)?;
                    fsops::setattr(nx, data, t, times(&s), now)?;
                } else {
                    nx.jobj_times.insert((data, t), rt.file);
                }
                if moved(&path) {
                    fsops::unlink(nx, system, sdir, &k, ino, now)?;
                }
            }
            DT_LNK => {
                if exists.is_some() || moved(&path) || xattrs.iter().any(|x| x != "com.apple.fs.symlink") {
                    return Err(format!("not implemented: a link meeting an existing name, under a moved tree or with extended attributes (/private/var/{path})"));
                }
                let r = fsops::xattr_embedded(nx, system, ino, "com.apple.fs.symlink")?.ok_or("a symbolic link with no target")?;
                let target = std::str::from_utf8(r.strip_suffix(&[0]).unwrap_or(&r)).map_err(|_| "a link target that is not UTF-8")?.to_string();
                let l = fsops::symlink(nx, data, ddir, BOM_LINK_TEMP, &target, 0o777, 0, pgid, now)?.map_err(|e| format!("symlink /mnt2/{rel}/{BOM_LINK_TEMP}: errno {e}"))?;
                fsops::rename_in_dir(nx, data, ddir, BOM_LINK_TEMP, &name, l, now)?;
                fsops::setattr(nx, data, l, ids(&s), now)?;
                fsops::chmod(nx, data, l, s.mode & 0o7777, now)?;
            }
            _ => return Err(format!("not implemented: copying an object of type {ty} (/private/var/{path})")),
        }
    }
    Ok(())
}

/// What the restore host decides for the steps after fixup_var: the
/// restore options restored_external reads (get_bool RE@0x1000408d0 and
/// get_int with restored's defaults) and the host's answer to
/// persistent_boot_args' message 0x19 (RE@0x100026c6c).
pub const RESTORE_OPTIONS_STAND_IN: &str = "the restore host's RestoreOptions as restored_external reads them after fixup_var, and its answer to persistent_boot_args' message 0x19 (stand-in: no option given, so restored's defaults: SystemImage, ReadOnlyRootFilesystem and CreateFilesystemPartitions true, LogPartitionSize 0, SkipProductionUCRTRetrieval and SetFieldDiagnosticsBoot false, no BridgeOS.SetTargetDiskMode; the answer success; drafts/s27/re-mountpoints.md UNSETTLED 1; capture the options a restore host sends)";

/// The restore options the steps after fixup_var read
/// ([`RESTORE_OPTIONS_STAND_IN`]). `UpdateBaseband` changes nothing on this
/// device (create_partition_mountpoints' baseband entry is skipped either
/// way, [`J120_BASEBAND`]).
#[derive(Clone, Copy, Debug)]
pub struct RestoreOptions {
    pub system_image: bool,
    pub read_only_root_filesystem: bool,
    pub create_filesystem_partitions: bool,
    pub log_partition_size: i64,
    pub skip_production_ucrt_retrieval: bool,
    pub set_field_diagnostics_boot: bool,
    /// `BridgeOS.SetTargetDiskMode`, when it is a boolean.
    pub set_target_disk_mode: Option<bool>,
}

impl RestoreOptions {
    /// restored's defaults, no option given.
    pub const DEFAULTS: RestoreOptions = RestoreOptions { system_image: true, read_only_root_filesystem: true, create_filesystem_partitions: true, log_partition_size: 0, skip_production_ucrt_retrieval: false, set_field_diagnostics_boot: false, set_target_disk_mode: None };
}

/// A variable's value as the kernel stores it (IONVRAM.cpp's type for its
/// name: an OSData, or an OSString for a string variable).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NvramValue {
    Data(&'static [u8]),
    String(&'static str),
}

/// A change restored makes to the NVRAM variables (`IODeviceTree:/options`,
/// IODTNVRAM) through IORegistryEntrySetCFProperty on its NVRAM queue
/// (RE@0x100062818; drafts/s27/re-mountpoints.md 0.2, 5.5): a variable
/// deleted (`IONVRAM-DELETE-PROPERTY` = its name; one that is not there is
/// no error) or set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NvramOp {
    Delete(&'static str),
    Set(&'static str, NvramValue),
}

/// set_filesystem_permissions (RE@0x10002f430), the first act of
/// check_mounted's create_partition_mountpoints block (RE@0x100018f00) when
/// `SystemImage` holds: root-live-fs deleted (set to "1" without
/// `ReadOnlyRootFilesystem`), allow-root-hash-mismatch deleted, and with
/// `CreateFilesystemPartitions` the three oblit- variables. Their results
/// are not checked.
fn set_filesystem_permissions(o: &RestoreOptions, nv: &mut Vec<NvramOp>) {
    nv.push(if o.read_only_root_filesystem { NvramOp::Delete("root-live-fs") } else { NvramOp::Set("root-live-fs", NvramValue::Data(b"1")) });
    nv.push(NvramOp::Delete("allow-root-hash-mismatch"));
    if o.create_filesystem_partitions {
        for v in ["oblit-inprogress", "oblit-begins", "oblit-failure"] {
            nv.push(NvramOp::Delete(v));
        }
    }
}

/// The NVRAM changes of the steps from check_mounted's
/// create_partition_mountpoints to set_tdm (drafts/s27/re-mountpoints.md
/// 0.2, 2.2, 4, 5), in order: set_filesystem_permissions'; none from
/// create_production_ucrt (its UCRT fetch is compiled out, RE@0x1000266f0
/// returns NULL, so it makes no call at all); set_one_time_boot_command's
/// (RE@0x100039ebc: one-time-boot-command deleted, or set to "checkerboard"
/// with `SetFieldDiagnosticsBoot`); none from set_nvram_variables (a no-op,
/// RE@0x100039f30); persistent_boot_args' (RE@0x100039e14: after the host
/// answers its message 0x19, boot-args set to "": the CFData attempt is
/// refused by the kernel, boot-args being a string variable, and the
/// CFString one stored); set_tdm's only with `BridgeOS.SetTargetDiskMode`
/// true (not implemented). restored asks for no NVRAM sync anywhere here
/// (no sync flag, no IONVRAM-FORCESYNCNOW-PROPERTY), and its NVRAM file
/// shadow has no session on an erase (no write on any volume).
pub fn nvram_after_fixup_var(o: &RestoreOptions) -> Result<Vec<NvramOp>, String> {
    let mut nv = Vec::new();
    if o.system_image {
        set_filesystem_permissions(o, &mut nv);
    }
    nv.push(if o.set_field_diagnostics_boot { NvramOp::Set("one-time-boot-command", NvramValue::Data(b"checkerboard")) } else { NvramOp::Delete("one-time-boot-command") });
    nv.push(NvramOp::Set("boot-args", NvramValue::String("")));
    if o.set_target_disk_mode == Some(true) {
        return Err("not implemented: set_tdm's enter-tdm-mode and auto-boot-x86-once (restored's type attempts for each against the kernel's variable types)".into());
    }
    Ok(nv)
}

/// The restore's NVRAM changes `nv` as a missing entry: gex keeps no NVRAM
/// variables a run of the restore could change and the next boot read.
pub fn nvram_missing(nv: &[NvramOp]) -> String {
    let ops: Vec<String> = nv
        .iter()
        .map(|op| match op {
            NvramOp::Delete(n) => format!("delete {n}"),
            NvramOp::Set(n, NvramValue::Data(d)) => format!("set {n} to the data {:?}", String::from_utf8_lossy(d)),
            NvramOp::Set(n, NvramValue::String(s)) => format!("set {n} to the string {s:?}"),
        })
        .collect();
    format!("the restore's NVRAM changes after fixup_var (IODeviceTree:/options, in order, no sync asked: {}): gex has no NVRAM variable store for them (needed: IODTNVRAM's variables over an image of the device's NVRAM that a restore run writes and the next boot reads; the boot's /options is the boot payload's device tree, read-only)", ops.join(", "))
}

/// restored's volume table (RE@0x100285668, 64-byte records): each
/// volume's name and its path in the operating system.
const VOLUME_TABLE: [(&str, &str); 10] = [
    ("System", "/"),
    ("xART", "/private/xarts"),
    ("Data", "/private/var"),
    ("User", "/private/var/mobile"),
    ("Baseband Data", "/private/var/wireless/baseband_data"),
    ("Logs", "/private/var/logs"),
    ("Hardware", "/private/var/hardware"),
    ("Scratch", "/private/var/internal"),
    ("Update", "/private/var/MobileSoftwareUpdate"),
    ("Preboot", "/private/preboot"),
];

/// Whether the device has a baseband for create_partition_mountpoints'
/// Baseband Data entry: with `UpdateBaseband` RE@0x10004af6c needs an
/// IOService "baseband" (not Leda) or "AppleConvergedIPCLedaBBControl",
/// without it RE@0x1000456ac needs `/filesystems/fstab/baseband-vol`; J120's
/// device tree has none of them (drafts/s14/restored/dt.txt: no baseband
/// node, fstab xart, system, preboot, data, update, hardware).
const J120_BASEBAND: bool = false;

/// The object `path` names below volume `vol`'s root, if any (repeated
/// slashes skipped).
fn resolve(nx: &mut Nx<'_>, vol: usize, path: &str) -> Result<Option<u64>, String> {
    let mut dir = ROOT_INO;
    for name in path.split('/').filter(|c| !c.is_empty()) {
        match fsops::lookup(nx, vol, dir, name)? {
            Some(ino) => dir = ino,
            None => return Ok(None),
        }
    }
    Ok(Some(dir))
}

/// create_partition_mountpoints (RE@0x10003a070; drafts/s27/
/// re-mountpoints.md 2.3), after its block's set_filesystem_permissions
/// (NVRAM changes only, re-mountpoints.md 2.2): for the volume table's
/// xART, Logs (with a `LogPartitionSize`), Hardware, Scratch and Update
/// entries (Baseband Data only with a baseband; System, Data, User and
/// Preboot skipped), the mount
/// point below Data's /mnt2 for a path under /private/var (only when the
/// install creates the data partitions), else below System's /mnt1, made
/// where missing by `_ramrod_create_directory(path, 0755, 0, 0)`; then the
/// Scratch one (`/mnt2//internal`) given mode 0777 and SF_IMMUTABLE |
/// UF_IMMUTABLE whether it was there or not, a failure of either logged and
/// not fatal. After fixup_var only /internal is missing on the erase
/// restore: one directory made by mkdir 0755, chmod's fast path, chown 0:0,
/// chmod 0777 and chflags 0x20002 (re-mountpoints.md 0.1). The ramdisk's
/// securelevel is not known (re-mountpoints.md UNSETTLED 5): a flags change
/// whose answer needs it is refused.
pub fn create_partition_mountpoints(nx: &mut Nx<'_>, system: usize, data: usize, o: &RestoreOptions, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    use fsops::bsd_flags::{SF_APPEND, SF_IMMUTABLE, UF_APPEND, UF_IMMUTABLE};
    for (i, (name, path)) in VOLUME_TABLE.iter().enumerate() {
        let go = match i {
            0 | 2 | 3 | 9 => false,
            4 => J120_BASEBAND,
            5 => o.log_partition_size != 0,
            _ => true,
        };
        if !go {
            continue;
        }
        let (vol, rel) = if let Some(rest) = path.strip_prefix("/private/var") {
            if !o.create_filesystem_partitions {
                continue;
            }
            (data, rest)
        } else if let Some(rest) = path.strip_prefix('/') {
            (system, rest)
        } else {
            return Err(format!("could not determine the parent device of the {name} mount point {path:?}"));
        };
        let existed = resolve(nx, vol, rel)?.is_some();
        let ino = create_directory(nx, vol, rel, 0o755, 0, 0, now)?;
        if i == 7 {
            let flags = u32::from_le_bytes(fsops::inode(nx, vol, ino)?[0x44..0x48].try_into().unwrap());
            if existed && flags & (SF_IMMUTABLE | UF_IMMUTABLE | SF_APPEND | UF_APPEND) != 0 {
                return Err(format!("not implemented: chmod of the existing {path} with flags {flags:#x} (vnode_authorize_checkimmutable: EPERM unless its owner's process ignores node permissions)"));
            }
            fsops::chmod(nx, vol, ino, 0o777, now)?;
            // An error of chflags is logged ("Not fatal") and the loop goes on.
            let _ = fsops::chflags(nx, vol, ino, SF_IMMUTABLE | UF_IMMUTABLE, None, now)?;
        }
    }
    Ok(())
}

/// The mounts await_asr_and_retry makes after apfs_invert: xART
/// (0x100017510 → 0x1000296c8, with `seputil --gigalocker-init` finding
/// its file), mount_filesystems' System, Hardware and Preboot
/// (0x100017654), then Update (0x100017670 → 0x100027f10), each
/// `mount_apfs -R`.
fn after_invert_mounts(nx: &mut Nx<'_>, v: Volumes, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    for vol in [v.xart, v.system, v.hardware, v.preboot, v.update] {
        fsops::mount_rw(nx, vol, now)?;
    }
    Ok(())
}

/// What restored_external checks with libimg4 before the seal that the
/// image cannot answer.
const IMAGE4_CHECKS_MISSING: &str = "restored_external's Image4 checks against the AP ticket of the canonical metadata (ramrod_verify_manifest_for_mountpoint, RE@0x100058108 → RE@0x1000583e0) and of /mnt5/root_hash (tag 'isys', RE@0x100058714): TICKET_STAND_IN's ticket signs nothing, so they are not run (the files are the IPSW's, which the device's checks pass)";

/// set_autoboot_delay's `sync()` (RE@0x100033ef8; drafts/s27/
/// re-seal-snap.md 2.1), not implemented: XNU's VFS_SYNC of each mounted
/// read-write volume, oldest mount first, whose vnode pass writes the
/// times inodes hold in memory (in each mount's vnode-list order, which
/// depends on the vnodes the restore's copies left: re-txdata.md 4.2,
/// re-datawrite.md UNSETTLED-4), and the first volume's tx_finish commit.
/// The times it writes are not written: they leave the kernel's memory
/// here, as the device's sync leaves them on disk, so that the seal's
/// forced unmounts find none (the first of those commits the transaction
/// the sync would have, with the same identifier). The missing entry.
fn autoboot_sync_missing(nx: &mut Nx<'_>) -> String {
    let held: Vec<String> = nx.jobj_times.iter().map(|((v, i), t)| format!("slot {v} {i:#x} ({}, {})", t.0, t.1)).collect();
    nx.jobj_times.clear();
    format!("set_autoboot_delay's sync(2) (its vnode passes over every read-write volume): the {} inodes' modification and change times it writes are not written: {}", held.len(), held.join(", "))
}

/// seal_system_volume (RE@0x10003ab6c; drafts/s27/re-seal-snap.md 3): the
/// canonical metadata unarchived on the ramdisk's /mnt5 (tmpfs) and
/// `mtree -m` reading /mnt1 (the mounts set MNT_NOATIME: no write);
/// unmount_filesystems_everything without Update (RE@0x10002ecb8: from
/// the volume table's last slot down, each mounted volume forced:
/// Preboot, Hardware, User, Data, xART after `seputil
/// --gigalocker-shutdown` (a Secure Enclave call only), System), then
/// Update's `unmount("/mnt4", 0)`; the container handed to
/// apfs_sealvolume (RUN_STAND_IN, as for apfs_invert); the seal
/// ([`super::sealvolume::seal_volume`]); then `mount_partition(0, ro)`,
/// the kernel's next mount of the container (its reaper idle, System
/// read-only: no write), and Update's read-write mount. Whether the build
/// goes on.
#[allow(clippy::too_many_arguments)]
fn seal_system_volume(nx: &mut Nx<'_>, v: Volumes, data: usize, user: usize, files: &SealFiles, barrier: bool, hooks: &mut Hooks<'_>, now: &mut dyn FnMut() -> u64) -> Result<bool, String> {
    let archive = crate::darwin::aar::mtree_payload(&files.mtree)?;
    let digest_db = crate::darwin::aar::file(&archive, "digest.db")?;
    let mtree_txt = crate::darwin::aar::file(&archive, "mtree.txt")?;
    // writeToFile:"/mnt5/root_hash": the host's Image4 file of the root
    // hash (TICKET_STAND_IN).
    let root_hash = img4(&files.root_hash, &TICKET);
    for vol in [v.preboot, v.hardware, user, data, v.xart, v.system] {
        fsops::unmount(nx, vol, true, now)?;
    }
    fsops::unmount(nx, v.update, false, now)?;
    nx.unmount()?;
    (hooks.before_seal)()?;
    super::sealvolume::seal_volume(nx, v.system, &super::sealvolume::SealInputs { root_hash: &root_hash, digest_db, mtree_txt }, barrier, now)?;
    if !(hooks.after_seal)(nx)? {
        return Ok(false);
    }
    nx.set_barrier(crate::darwin::storagestack::container_barrier());
    nx.remount(Mode::Kernel)?;
    nx.reaper_run()?;
    fsops::mount_rw(nx, v.update, now)?;
    Ok(true)
}

/// `copy_arv_apfs_system_snapshot_name(data, 1)` (RE@0x10001d74c →
/// RE@0x10001d558): the Image4 file's payload (Img4DecodeInit), at least
/// 16 bytes, its hash length at +0xc and at least that many bytes after
/// +0x10; "com.apple.os.update-" and those bytes in "%02X".
fn arv_snapshot_name(img4_file: &[u8]) -> Result<String, String> {
    let (_, p) = super::seal::img4_payload(img4_file)?;
    if p.len() < 16 {
        return Err("a root hash payload under 16 bytes".into());
    }
    let n = u32::from_le_bytes(p[0xc..0x10].try_into().unwrap()) as usize;
    if p.len() < 0x10 + n {
        return Err("a root hash payload shorter than its hash".into());
    }
    Ok(format!("com.apple.os.update-{}", p[0x10..0x10 + n].iter().map(|b| format!("{b:02X}")).collect::<String>()))
}

/// create_system_snapshot (RE@0x100039ab4; drafts/s27/re-seal-snap.md 4):
/// preboot_path's `mount_partition(9, rw)` and its /mnt9/<nsih>; the root
/// hash Image4 file install_root_hash wrote there read; the update
/// snapshot's name made of it (the name the device tree's
/// `root-snapshot-name` gives the booted kernel, [`storage::ROOT_SNAPSHOT`]);
/// `fs_snapshot_create` on /mnt1 ([`super::snapshot::fs_snapshot_create`]).
/// With that name, no `mount_partition(0, 0)` and no `fs_snapshot_root`.
fn create_system_snapshot(nx: &mut Nx<'_>, v: Volumes, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    fsops::mount_rw(nx, v.preboot, now)?;
    let dir = nsih();
    resolve(nx, v.preboot, &dir)?.ok_or_else(|| format!("no /mnt9/{dir}"))?;
    let f = resolve(nx, v.preboot, &format!("{dir}/usr/standalone/firmware/root_hash.img4"))?.ok_or("not implemented: no root_hash.img4 on Preboot (the legacy snapshot name and fs_snapshot_root)")?;
    let bytes = file_bytes(nx, v.preboot, f)?;
    let name = arv_snapshot_name(&bytes)?;
    if name != storage::ROOT_SNAPSHOT {
        return Err(format!("the update snapshot {name} is not the one the boot mounts ({})", storage::ROOT_SNAPSHOT));
    }
    match super::snapshot::fs_snapshot_create(nx, v.system, &name, now)? {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Failed to create ARV snapshot. (errno {e})")),
    }
}

/// migrate_user_fsevents (RE@0x10003c044; re-seal-snap.md 5): with
/// `e-apfs` the data volume is split, so xART (`seputil
/// --gigalocker-init` only stats it and calls the Secure Enclave), Data
/// and User are mounted read-write (`mount_apfs -R`; the
/// `.ramdisk-boot-done` opens fail at their lookups); neither User's nor
/// Data's root has `.fseventsd`, so nothing is migrated.
fn migrate_user_fsevents(nx: &mut Nx<'_>, v: Volumes, data: usize, user: usize, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    for vol in [v.xart, data, user] {
        fsops::mount_rw(nx, vol, now)?;
    }
    for vol in [user, data] {
        if fsops::lookup(nx, vol, ROOT_INO, ".fseventsd")?.is_some() {
            return Err("not implemented: migrating user fsevents (RE@0x100058c7c with a .fseventsd)".into());
        }
    }
    Ok(())
}

/// unmount_filesystems (RE@0x10001af18 → RE@0x10002ef18): the same loop as
/// the seal's, without Update, forced: Preboot, User, Data, xART (after
/// `seputil --gigalocker-shutdown`); System is mounted read-only (no
/// transaction), Hardware not at all.
fn unmount_filesystems(nx: &mut Nx<'_>, v: Volumes, data: usize, user: usize, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    for vol in [v.preboot, user, data, v.xart] {
        fsops::unmount(nx, vol, true, now)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// disk0 as built reads back through gex's own APFS reader: the
    /// container on the partition, each volume made with its name, role,
    /// slot and UUID, and its root directory.
    #[test]
    fn disk0_reads_back() {
        use crate::darwin::apfsread::{Container, Medium};
        let size = storage::disk0_bytes();
        let tmp = std::env::temp_dir().join(format!("gex-disk0-{}", std::process::id()));
        let f = std::fs::OpenOptions::new().create(true).truncate(true).read(true).write(true).open(&tmp).unwrap();
        f.set_len(size).unwrap();
        let disk = std::sync::Arc::new(super::super::HostFile(f, size));
        let mut t = 1_800_000_000_000_000_000u64;
        let mut now = || {
            t += 1000;
            t
        };
        let missing = build_disk0(disk.clone(), &mut now, None).unwrap();
        assert!(!missing.is_empty());
        struct Part(std::sync::Arc<super::super::HostFile>, u64, u64);
        impl Medium for Part {
            fn size(&self) -> u64 {
                self.2
            }
            fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<(), String> {
                self.0.read_at(self.1 + off, buf)
            }
        }
        let (base, psize) = storage::partition_extent();
        let c = std::sync::Arc::new(Container::open(std::sync::Arc::new(Part(disk, base, psize))).unwrap());
        assert_eq!(c.nx.uuid, storage::container_uuid());
        for v in [0u32, 2, 3, 4, 5] {
            let want = storage::volume(v).unwrap();
            let vol = c.volume(v as usize).unwrap().unwrap();
            assert_eq!((vol.sb.volname.as_str(), vol.sb.role, vol.sb.fs_index), (want.name, want.role, v));
            // Without the system image the seal does not run.
            assert_eq!(vol.sb.uuid, storage::formatted_volume_uuid(v));
            assert!(vol.inode(2).unwrap().is_some_and(|i| i.is_dir()));
            assert_eq!(vol.lookup(2, "nothing").unwrap().map(|e| e.name), None);
        }
        assert!(c.volume(1).unwrap().is_none(), "Data is not made yet");
        // Update's directories, their owners and modes.
        let u = c.volume(5).unwrap().unwrap();
        let dir = |parent: u64, name: &str, mode: u16, uid: u32| {
            let e = u.lookup(parent, name).unwrap().unwrap_or_else(|| panic!("no {name}"));
            let i = u.inode(e.file_id).unwrap().unwrap();
            assert!(i.is_dir());
            assert_eq!((i.mode & 0o7777, i.owner, i.group), (mode, uid, uid), "{name}");
            e.file_id
        };
        dir(2, "Controller", 0o711, 501);
        dir(2, "Firmware", 0o755, 0);
        dir(2, "db", 0o777, 501);
        let hw = dir(2, "Hardware", 0o500, 0);
        dir(hw, "Battery", 0o700, 0);
        // xART's gigalocker file: 6 MiB, preallocated, zero-filled.
        let x = c.volume(2).unwrap().unwrap();
        let e = x.lookup(2, "00000000-0000-4000-8000-000000000005.gl").unwrap().unwrap();
        let gl = x.inode(e.file_id).unwrap().unwrap();
        assert_eq!((gl.mode & 0o7777, x.file_size(&gl).unwrap()), (0o600, 0x60_0000));
        let mut buf = vec![1u8; 4096];
        x.read_file(&gl, 0x5f_f000, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
        // Hardware's dummy FDR path.
        let h = c.volume(3).unwrap().unwrap();
        let mut d = 2;
        for n in ["FactoryData", "System", "Library", "Caches", "com.apple.factorydata"] {
            d = h.lookup(d, n).unwrap().unwrap_or_else(|| panic!("no {n} on Hardware")).file_id;
        }
        // Preboot: the ticket's directory, the link, Cryptexes, active.
        let p = c.volume(4).unwrap().unwrap();
        let nsih = "0".repeat(96);
        let mut d = p.lookup(2, &nsih).unwrap().unwrap().file_id;
        for n in ["System", "Library", "Caches"] {
            d = p.lookup(d, n).unwrap().unwrap().file_id;
        }
        assert!(p.lookup(d, "com.apple.kernelcaches").unwrap().is_some());
        assert!(p.lookup(d, "com.apple.factorydata").unwrap().is_some());
        let cx = p.lookup(2, "Cryptexes").unwrap().unwrap().file_id;
        assert!(p.lookup(cx, "OS").unwrap().is_some() && p.lookup(cx, "App").unwrap().is_some());
        let e = p.lookup(2, "active").unwrap().unwrap();
        let a = p.inode(e.file_id).unwrap().unwrap();
        let mut buf = vec![0u8; p.file_size(&a).unwrap() as usize];
        p.read_file(&a, 0, &mut buf).unwrap();
        assert_eq!(buf, nsih.as_bytes());
        let _ = std::fs::remove_file(&tmp);
    }

    /// disk0 without the system image (GEX_TEST_FSCK: the device's
    /// host-runnable fsck_apfs, with GEX_TEST_SCRATCH): the container the
    /// steps alongside asr leave, consistent to the device's and the host's
    /// fsck_apfs.
    #[test]
    fn concurrent_steps_leave_a_consistent_container() {
        let (Ok(dir), Ok(fsck)) = (std::env::var("GEX_TEST_SCRATCH"), std::env::var("GEX_TEST_FSCK")) else { return };
        let size = storage::disk0_bytes();
        let dir = std::path::Path::new(&dir);
        let disk_path = dir.join(format!("gex-cs-disk-{}", std::process::id()));
        let ctr_path = dir.join(format!("gex-cs-ctr-{}", std::process::id()));
        let f = std::fs::OpenOptions::new().create(true).truncate(true).read(true).write(true).open(&disk_path).unwrap();
        f.set_len(size).unwrap();
        let disk = std::sync::Arc::new(super::super::HostFile(f, size));
        let (base, psize) = storage::partition_extent();
        let mut t = 1_700_000_000_000_000_000u64;
        let mut now = move || {
            t += 1000;
            t
        };
        build_disk0(disk.clone(), &mut now, None).unwrap();
        disk.0.sync_all().unwrap();
        copy_container(&disk_path, &ctr_path, base, psize);
        let dev = std::process::Command::new(&fsck).args(["-n", "-W", "-s"]).arg(&ctr_path).output().unwrap();
        let host = std::process::Command::new("/sbin/fsck_apfs").args(["-n", "-s"]).arg(&ctr_path).output().unwrap();
        if std::env::var("GEX_TEST_KEEP").is_err() {
            let _ = std::fs::remove_file(&disk_path);
            let _ = std::fs::remove_file(&ctr_path);
        }
        assert!(dev.status.success(), "device fsck: {}{}", String::from_utf8_lossy(&dev.stdout), String::from_utf8_lossy(&dev.stderr));
        assert!(host.status.success(), "host fsck: {}{}", String::from_utf8_lossy(&host.stdout), String::from_utf8_lossy(&host.stderr));
    }

    /// The library's allocator replayed on a container file (GEX_TEST_NEWFS_A
    /// with the GEX_TEST_DA_HOOK hook): the requests `seq` (counts, in
    /// order) run at its mount's first allocation; each one's (blocks, got,
    /// roving pointer after it).
    fn device_allocations(tool: &str, hook: &str, ctr: &std::path::Path, seq: &[u64]) -> Vec<(u64, u64, u64)> {
        let mut toks: Vec<String> = Vec::new();
        let mut i = 0;
        while i < seq.len() {
            let mut j = i;
            while j < seq.len() && seq[j] == seq[i] {
                j += 1;
            }
            toks.push(if j - i > 1 { format!("{}x{}", seq[i], j - i) } else { seq[i].to_string() });
            i = j;
        }
        let run = std::process::Command::new(tool)
            .args(["-A", "-D", "-U", "0", "-G", "0", "-v", "Vtmp"])
            .arg(ctr)
            .env("DYLD_INSERT_LIBRARIES", hook)
            .env("DA_SEQ", toks.join(","))
            .env("DA_NODES", "0")
            .output()
            .unwrap();
        let out = String::from_utf8_lossy(&run.stdout).to_string();
        let num = |l: &str, k: &str| -> u64 { l.split(k).nth(1).unwrap().split_whitespace().next().unwrap().parse().unwrap() };
        let r: Vec<(u64, u64, u64)> = out.lines().filter(|l| l.starts_with("alloc ")).map(|l| (num(l, " paddr "), num(l, " got "), num(l, " roving "))).collect();
        assert!(!r.is_empty(), "the hook made no allocation: {out}{}", String::from_utf8_lossy(&run.stderr));
        r
    }

    /// With the IPSW's system image (GEX_TEST_UDIF; GEX_TEST_NEWFS_A and
    /// GEX_TEST_DA_HOOK; the disk built in GEX_TEST_SCRATCH): every data
    /// allocation from restore_asr's start to apfs_invert (the gigalocker
    /// file's, Preboot's active file, asr's image file) lands where the
    /// device library's allocator puts the same requests on the container
    /// as restore_asr finds it, and asr's image file holds the partition's
    /// bytes.
    #[test]
    fn data_placements_before_the_invert_match_the_device_library() {
        use crate::darwin::apfsread::{Container, Medium};
        let (Ok(dmg), Ok(dir), Ok(tool), Ok(hook)) = (std::env::var("GEX_TEST_UDIF"), std::env::var("GEX_TEST_SCRATCH"), std::env::var("GEX_TEST_NEWFS_A"), std::env::var("GEX_TEST_DA_HOOK")) else { return };
        let f = std::fs::File::open(&dmg).unwrap();
        let len = f.metadata().unwrap().len();
        let image = std::sync::Arc::new(crate::darwin::udif::Udif::open(std::sync::Arc::new(super::super::HostFile(f, len))).unwrap());
        let partition = image.partition("Apple_APFS").unwrap();
        let os = OsImage { image: std::sync::Arc::clone(&image), partition, boot: None, seal: None };
        let size = storage::disk0_bytes();
        let dir = std::path::Path::new(&dir);
        let disk_path = dir.join(format!("gex-disk0-asr-{}", std::process::id()));
        let ctr_path = dir.join(format!("gex-disk0-asr-ctr-{}", std::process::id()));
        let f = std::fs::OpenOptions::new().create(true).truncate(true).read(true).write(true).open(&disk_path).unwrap();
        f.set_len(size).unwrap();
        let disk = std::sync::Arc::new(super::super::HostFile(f, size));
        let mut t = 1_800_000_000_000_000_000u64;
        let mut now = || {
            t += 1000;
            t
        };
        let (base, psize) = storage::partition_extent();
        let d1 = disk.clone();
        let (dp, cp) = (disk_path.clone(), ctr_path.clone());
        let mut before_asr = move |nx: &mut Nx<'_>| -> Result<bool, String> {
            nx.unmount()?;
            d1.0.sync_all().map_err(|e| e.to_string())?;
            copy_container(&dp, &cp, base, psize);
            nx.remount(Mode::Kernel)?;
            nx.alloc_log = Some(Vec::new());
            Ok(true)
        };
        let d2 = disk.clone();
        let mut hook_inv = move || -> Result<(), String> {
            struct Part(std::sync::Arc<super::super::HostFile>, u64, u64);
            impl Medium for Part {
                fn size(&self) -> u64 {
                    self.2
                }
                fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<(), String> {
                    self.0.read_at(self.1 + off, buf)
                }
            }
            let c = std::sync::Arc::new(Container::open(std::sync::Arc::new(Part(std::sync::Arc::clone(&d2), base, psize))).unwrap());
            let v = c.volume(0).unwrap().unwrap();
            let e = v.lookup(2, super::super::asr::IMAGE_NAME).unwrap().unwrap();
            let ino = v.inode(e.file_id).unwrap().unwrap();
            assert_eq!(v.file_size(&ino).unwrap(), image.partitions[partition].sectors * 512);
            let mut want = vec![0u8; 4096];
            let mut got = vec![0u8; 4096];
            for fb in [0u64, 255, 256, 15_898, 65_536, 131_072, 1_478_426] {
                image.read_partition(partition, fb * 4096, &mut want).unwrap();
                v.read_file(&ino, fb * 4096, &mut got).unwrap();
                assert_eq!(got, want, "file block {fb}");
            }
            Ok(())
        };
        let mut log = Vec::new();
        let mut after = |nx: &mut Nx<'_>| -> Result<bool, String> {
            log = nx.alloc_log.take().unwrap_or_default();
            Ok(false)
        };
        build_disk0_with(disk.clone(), &mut now, Some(&os), &mut before_asr, &mut hook_inv, &mut after, None).unwrap();
        let reqs: Vec<u64> = log.iter().map(|l| l.0).collect();
        let theirs = device_allocations(&tool, &hook, &ctr_path, &reqs);
        if std::env::var("GEX_TEST_KEEP").is_err() {
            let _ = std::fs::remove_file(&disk_path);
            let _ = std::fs::remove_file(&ctr_path);
        }
        assert_eq!(theirs.len(), log.len());
        for (i, (a, b)) in log.iter().zip(&theirs).enumerate() {
            assert_eq!((a.1, a.2, a.3), *b, "allocation {i} of {} blocks", a.0);
        }
    }

    /// apfs_invert against the device's own binary (GEX_TEST_INVERT: the
    /// host-runnable apfs_invert, with GEX_TEST_UDIF and GEX_TEST_SCRATCH):
    /// the container as the restore hands it to apfs_invert, inverted by
    /// the binary on a copy and by the port, block for block (the port
    /// given the binary's two clock readings).
    #[test]
    fn invert_matches_the_device_binary() {
        use std::cell::RefCell;
        use std::rc::Rc;
        let (Ok(dmg), Ok(dir), Ok(tool)) = (std::env::var("GEX_TEST_UDIF"), std::env::var("GEX_TEST_SCRATCH"), std::env::var("GEX_TEST_INVERT")) else { return };
        let f = std::fs::File::open(&dmg).unwrap();
        let len = f.metadata().unwrap().len();
        let image = std::sync::Arc::new(crate::darwin::udif::Udif::open(std::sync::Arc::new(super::super::HostFile(f, len))).unwrap());
        let partition = image.partition("Apple_APFS").unwrap();
        let os = OsImage { image: std::sync::Arc::clone(&image), partition, boot: None, seal: None };
        let size = storage::disk0_bytes();
        let dir = std::path::Path::new(&dir);
        let disk_path = dir.join(format!("gex-inv-disk-{}", std::process::id()));
        let ctr_path = dir.join(format!("gex-inv-ctr-{}", std::process::id()));
        let f = std::fs::OpenOptions::new().create(true).truncate(true).read(true).write(true).open(&disk_path).unwrap();
        f.set_len(size).unwrap();
        let disk = std::sync::Arc::new(super::super::HostFile(f, size));
        let (base, psize) = storage::partition_extent();
        let clock: Rc<RefCell<(u64, Vec<u64>)>> = Rc::new(RefCell::new((1_800_000_000_000_000_000, Vec::new())));
        let c2 = Rc::clone(&clock);
        let mut now = move || {
            let mut c = c2.borrow_mut();
            if let Some(t) = c.1.pop() {
                return t;
            }
            c.0 += 1000;
            c.0
        };
        let c3 = Rc::clone(&clock);
        let d2 = std::sync::Arc::clone(&disk);
        let (dp, cp) = (disk_path.clone(), ctr_path.clone());
        let mut hook = move || -> Result<(), String> {
            d2.0.sync_all().map_err(|e| e.to_string())?;
            let copy = std::process::Command::new("python3")
                .args(["-I", "/Volumes/Ferrochrome/offloaded-builds/gex-cryptex/drafts/s16/tools/sparsecopy.py"])
                .arg(&dp)
                .arg(&cp)
                .args([base.to_string(), psize.to_string()])
                .status()
                .map_err(|e| e.to_string())?;
            assert!(copy.success());
            let run = std::process::Command::new(&tool).args(["-d"]).arg(&cp).args(["-s", "1", "-n", super::super::asr::IMAGE_NAME, "-f"]).output().map_err(|e| e.to_string())?;
            eprintln!("{}", String::from_utf8_lossy(&run.stderr));
            assert!(run.status.success(), "apfs_invert failed");
            // The binary's clock readings, from its volume superblock.
            use crate::darwin::apfsread::Medium as _;
            let ctr = super::super::HostFile(std::fs::File::open(&cp).unwrap(), psize);
            let c = std::sync::Arc::new(Container::open(std::sync::Arc::new(ctr)).unwrap());
            let v = c.volume(0).unwrap().unwrap();
            let paddr = c.omap().unwrap().lookup(&c, v.sb.header.oid, c.xid()).unwrap().unwrap().paddr;
            let sb = c.read_raw(paddr).unwrap();
            let q = |o: usize| u64::from_le_bytes(sb[o..o + 8].try_into().unwrap());
            // Popped last first: the modified_by time, then the unmount time.
            c3.borrow_mut().1 = vec![q(0x40), q(0x140 + 32)];
            Ok(())
        };
        use crate::darwin::apfsread::Container;
        // The binary runs on a regular file: no DK_FEATURE_BARRIER.
        build_disk0_with(disk.clone(), &mut now, Some(&os), &mut |_| Ok(true), &mut hook, &mut |_| Ok(false), Some(false)).unwrap();
        // Block for block.
        use crate::darwin::apfsread::Medium;
        let theirs = super::super::HostFile(std::fs::File::open(&ctr_path).unwrap(), psize);
        let (mut a, mut b) = (vec![0u8; 1 << 20], vec![0u8; 1 << 20]);
        let mut diffs = Vec::new();
        let mut off = 0;
        while off < psize {
            let n = (psize - off).min(1 << 20) as usize;
            disk.read_at(base + off, &mut a[..n]).unwrap();
            theirs.read_at(off, &mut b[..n]).unwrap();
            if a[..n] != b[..n] {
                for blk in 0..n / 4096 {
                    if a[blk * 4096..(blk + 1) * 4096] != b[blk * 4096..(blk + 1) * 4096] {
                        let t = u32::from_le_bytes(b[blk * 4096 + 24..blk * 4096 + 28].try_into().unwrap());
                        diffs.push(format!("block {} (their type {t:#x})", off / 4096 + blk as u64));
                    }
                }
            }
            off += n as u64;
        }
        if std::env::var("GEX_TEST_KEEP").is_err() {
            let _ = std::fs::remove_file(&disk_path);
            let _ = std::fs::remove_file(&ctr_path);
        }
        assert!(diffs.is_empty(), "{} blocks differ: {:?}", diffs.len(), &diffs[..diffs.len().min(40)]);
    }

    /// apfs_sealvolume against the device's own binary
    /// (GEX_TEST_SEALVOLUME: the host-runnable copy that takes a container
    /// file, drafts/s18/bin/sv_file.mac; with GEX_TEST_UDIF, GEX_TEST_MTREE,
    /// GEX_TEST_ROOT_HASH and GEX_TEST_SCRATCH): the container as the
    /// restore hands it to apfs_sealvolume, sealed by the binary on a copy
    /// and by the port, block for block (the port given the binary's two
    /// clock readings; `-P` gives the binary the root hash's IM4P, whose
    /// payload the device's Image4 file carries).
    #[test]
    fn seal_matches_the_device_binary() {
        use crate::darwin::apfsread::Container;
        use std::cell::RefCell;
        use std::rc::Rc;
        let (Ok(dmg), Ok(dir), Ok(tool), Ok(mtree), Ok(rh)) = (std::env::var("GEX_TEST_UDIF"), std::env::var("GEX_TEST_SCRATCH"), std::env::var("GEX_TEST_SEALVOLUME"), std::env::var("GEX_TEST_MTREE"), std::env::var("GEX_TEST_ROOT_HASH")) else { return };
        let f = std::fs::File::open(&dmg).unwrap();
        let len = f.metadata().unwrap().len();
        let image = std::sync::Arc::new(crate::darwin::udif::Udif::open(std::sync::Arc::new(super::super::HostFile(f, len))).unwrap());
        let partition = image.partition("Apple_APFS").unwrap();
        let files = SealFiles { mtree: std::fs::read(&mtree).unwrap(), root_hash: std::fs::read(&rh).unwrap() };
        let archive = crate::darwin::aar::mtree_payload(&files.mtree).unwrap();
        let os = OsImage { image: std::sync::Arc::clone(&image), partition, boot: None, seal: Some(files) };
        let dir = std::path::Path::new(&dir);
        let pid = std::process::id();
        let disk_path = dir.join(format!("gex-seal-disk-{pid}"));
        let ctr_path = dir.join(format!("gex-seal-ctr-{pid}"));
        let db_path = dir.join(format!("gex-seal-digest-{pid}.db"));
        let plist_path = dir.join(format!("gex-seal-remap-{pid}.plist"));
        std::fs::write(&db_path, crate::darwin::aar::file(&archive, "digest.db").unwrap()).unwrap();
        // The remap dictionary mtree -m writes (drafts/s18/exp/remap.plist).
        let t = "1777576853000000000";
        let keys = ["ACCESS", "BIRTH", "CHANGE", "DATEADDED", "MODIFICATION"].iter().map(|k| format!("\t<key>{k}</key>\n\t<integer>{t}</integer>\n")).collect::<String>();
        std::fs::write(&plist_path, format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n{keys}</dict>\n</plist>\n")).unwrap();
        let size = storage::disk0_bytes();
        let f = std::fs::OpenOptions::new().create(true).truncate(true).read(true).write(true).open(&disk_path).unwrap();
        f.set_len(size).unwrap();
        let disk = std::sync::Arc::new(super::super::HostFile(f, size));
        let (base, psize) = storage::partition_extent();
        // Clocks before the checkers' own: fsck warns of times to come.
        let clock: Rc<RefCell<(u64, Vec<u64>)>> = Rc::new(RefCell::new((1_760_000_000_000_000_000, Vec::new())));
        let c2 = Rc::clone(&clock);
        let mut now = move || {
            let mut c = c2.borrow_mut();
            if let Some(t) = c.1.pop() {
                return t;
            }
            c.0 += 1000;
            c.0
        };
        let c3 = Rc::clone(&clock);
        let c4 = Rc::clone(&clock);
        let d2 = std::sync::Arc::clone(&disk);
        let (dp, cp, dbp, pp) = (disk_path.clone(), ctr_path.clone(), db_path.clone(), plist_path.clone());
        let mut before_seal = move || -> Result<(), String> {
            d2.0.sync_all().map_err(|e| e.to_string())?;
            copy_container(&dp, &cp, base, psize);
            let run = std::process::Command::new(&tool).arg("-R").arg(&pp).arg("-I").arg(&rh).arg("-P").arg("-u").arg(&dbp).args(["-d", "-v"]).arg(&cp).output().map_err(|e| e.to_string())?;
            let log = String::from_utf8_lossy(&run.stderr);
            eprintln!("{}", log.lines().filter(|l| !l.contains("skipping extended attribute file extent")).collect::<Vec<_>>().join("\n"));
            assert!(run.status.success(), "apfs_sealvolume failed");
            // The binary's clock readings, from its volume superblock.
            let ctr = super::super::HostFile(std::fs::File::open(&cp).unwrap(), psize);
            let c = std::sync::Arc::new(Container::open(std::sync::Arc::new(ctr)).unwrap());
            let v = c.volume(0).unwrap().unwrap();
            let paddr = c.omap().unwrap().lookup(&c, v.sb.header.oid, c.xid()).unwrap().unwrap().paddr;
            let sb = c.read_raw(paddr).unwrap();
            let q = |o: usize| u64::from_le_bytes(sb[o..o + 8].try_into().unwrap());
            // Popped last first: the modified_by time, then the unmount time.
            c3.borrow_mut().1 = vec![q(0x40), q(0x140 + 32)];
            Ok(())
        };
        let diffs = Rc::new(RefCell::new(None));
        let dd = Rc::clone(&diffs);
        let fscks = Rc::new(RefCell::new(Vec::new()));
        let ff = Rc::clone(&fscks);
        let (d3, cp2, dp2) = (std::sync::Arc::clone(&disk), ctr_path.clone(), disk_path.clone());
        let mut after_seal = move |nx: &mut Nx<'_>| -> Result<bool, String> {
            use crate::darwin::apfsread::Medium;
            let mut diffs = differing_blocks(&d3, base, psize, &cp2);
            // The differing words of each differing block, for the report.
            let theirs = super::super::HostFile(std::fs::File::open(&cp2).unwrap(), psize);
            for d in diffs.iter_mut() {
                let blk: u64 = d.split_whitespace().nth(1).unwrap().parse().unwrap();
                let (mut a, mut b) = (vec![0u8; 4096], vec![0u8; 4096]);
                d3.read_at(base + blk * 4096, &mut a).unwrap();
                theirs.read_at(blk * 4096, &mut b).unwrap();
                let w: Vec<String> = (8..512).filter(|i| a[8 * i..8 * i + 8] != b[8 * i..8 * i + 8]).take(8).map(|i| format!("{:#x}: ours {:#x} theirs {:#x}", 8 * i, u64::from_le_bytes(a[8 * i..8 * i + 8].try_into().unwrap()), u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().unwrap()))).collect();
                d.push_str(&format!(" [{}]", w.join(", ")));
            }
            *dd.borrow_mut() = Some(diffs);
            // Then the kernel's update snapshot of the sealed volume on the
            // port's container, checked by the device's and the host's
            // fsck (GEX_TEST_FSCK).
            if let Ok(fsck) = std::env::var("GEX_TEST_FSCK") {
                let mut tick = || {
                    let mut c = c4.borrow_mut();
                    c.0 += 1000;
                    c.0
                };
                let system = (0..nx.fs_oid.len()).find(|&i| nx.vol_oid(i).is_some() && nx.vol_sb_read(i).is_ok_and(|(b, _)| u16::from_le_bytes([b[0x3c4], b[0x3c5]]) == storage::role::SYSTEM)).unwrap();
                nx.remount(Mode::Kernel)?;
                nx.reaper_run()?;
                let n = super::super::snapshot::fs_snapshot_create(nx, system, storage::ROOT_SNAPSHOT, &mut tick)?.map_err(|e| format!("fs_snapshot_create: errno {e}"))?;
                assert_eq!(super::super::snapshot::fs_snapshot_create(nx, system, storage::ROOT_SNAPSHOT, &mut tick)?, Err(17));
                nx.unmount()?;
                d3.0.sync_all().map_err(|e| e.to_string())?;
                copy_container(&dp2, &cp2, base, psize);
                // -M: the container keybag is KEYS_STAND_IN's plaintext.
                let dev = std::process::Command::new(&fsck).args(["-n", "-W", "-s", "-M"]).arg(&cp2).output().unwrap();
                let host = std::process::Command::new("/sbin/fsck_apfs").args(["-n", "-s", "-M"]).arg(&cp2).output().unwrap();
                eprintln!("snapshot xid {n}\n{}{}", String::from_utf8_lossy(&dev.stdout), String::from_utf8_lossy(&host.stdout));
                ff.borrow_mut().push((dev.status.success(), String::from_utf8_lossy(&dev.stdout).into_owned() + &String::from_utf8_lossy(&dev.stderr)));
                ff.borrow_mut().push((host.status.success(), String::from_utf8_lossy(&host.stdout).into_owned() + &String::from_utf8_lossy(&host.stderr)));
            }
            Ok(false)
        };
        // The binary runs on a regular file: no DK_FEATURE_BARRIER.
        build_disk0_hooked(disk.clone(), &mut now, Some(&os), &mut Hooks { before_asr: &mut |_| Ok(true), before_invert: &mut || Ok(()), after_invert: &mut |_| Ok(true), before_seal: &mut before_seal, after_seal: &mut after_seal, barrier: Some(false) }).unwrap();
        let diffs = diffs.borrow_mut().take().expect("the seal ran");
        if std::env::var("GEX_TEST_KEEP").is_err() {
            for p in [&disk_path, &ctr_path, &db_path, &plist_path] {
                let _ = std::fs::remove_file(p);
            }
        }
        assert!(diffs.is_empty(), "{} blocks differ: {:?}", diffs.len(), &diffs[..diffs.len().min(60)]);
        for (ok, out) in fscks.borrow().iter() {
            assert!(ok, "fsck after the snapshot: {out}");
        }
    }

    /// The blocks of `psize` bytes at `base` of `disk` that differ from the
    /// container file `theirs`.
    fn differing_blocks(disk: &super::super::HostFile, base: u64, psize: u64, theirs: &std::path::Path) -> Vec<String> {
        use crate::darwin::apfsread::Medium;
        let theirs = super::super::HostFile(std::fs::File::open(theirs).unwrap(), psize);
        let (mut a, mut b) = (vec![0u8; 1 << 20], vec![0u8; 1 << 20]);
        let mut diffs = Vec::new();
        let mut off = 0;
        while off < psize {
            let n = (psize - off).min(1 << 20) as usize;
            disk.read_at(base + off, &mut a[..n]).unwrap();
            theirs.read_at(off, &mut b[..n]).unwrap();
            if a[..n] != b[..n] {
                for blk in 0..n / 4096 {
                    if a[blk * 4096..(blk + 1) * 4096] != b[blk * 4096..(blk + 1) * 4096] {
                        let t = u32::from_le_bytes(b[blk * 4096 + 24..blk * 4096 + 28].try_into().unwrap());
                        diffs.push(format!("block {} (their type {t:#x})", off / 4096 + blk as u64));
                    }
                }
            }
            off += n as u64;
        }
        diffs
    }

    /// The container partition of disk file `disk` copied to the
    /// container file `ctr`.
    fn copy_container(disk: &std::path::Path, ctr: &std::path::Path, base: u64, psize: u64) {
        let _ = std::fs::remove_file(ctr);
        let copy = std::process::Command::new("python3")
            .args(["-I", "/Volumes/Ferrochrome/offloaded-builds/gex-cryptex/drafts/s16/tools/sparsecopy.py"])
            .arg(disk)
            .arg(ctr)
            .args([base.to_string(), psize.to_string()])
            .status()
            .unwrap();
        assert!(copy.success());
    }

    /// The reaper at the next mount after apfs_invert, against the device
    /// library's (GEX_TEST_NEWFS_A: the host-runnable user-space
    /// `newfs_apfs -A`, with GEX_TEST_UDIF and GEX_TEST_SCRATCH): its
    /// mount reaps apfs_invert's old trees, and the volume it adds joins
    /// the reaper's open transaction; the container block for block (the
    /// port given the tool's clock readings).
    #[test]
    fn reaper_matches_the_device_library() {
        use crate::darwin::apfsread::Container;
        let (Ok(dmg), Ok(dir), Ok(tool)) = (std::env::var("GEX_TEST_UDIF"), std::env::var("GEX_TEST_SCRATCH"), std::env::var("GEX_TEST_NEWFS_A")) else { return };
        let f = std::fs::File::open(&dmg).unwrap();
        let len = f.metadata().unwrap().len();
        let image = std::sync::Arc::new(crate::darwin::udif::Udif::open(std::sync::Arc::new(super::super::HostFile(f, len))).unwrap());
        let partition = image.partition("Apple_APFS").unwrap();
        let os = OsImage { image: std::sync::Arc::clone(&image), partition, boot: None, seal: None };
        let size = storage::disk0_bytes();
        let dir = std::path::Path::new(&dir);
        let disk_path = dir.join(format!("gex-reap-disk-{}", std::process::id()));
        let ctr_path = dir.join(format!("gex-reap-ctr-{}", std::process::id()));
        let f = std::fs::OpenOptions::new().create(true).truncate(true).read(true).write(true).open(&disk_path).unwrap();
        f.set_len(size).unwrap();
        let disk = std::sync::Arc::new(super::super::HostFile(f, size));
        let (base, psize) = storage::partition_extent();
        let mut t = 1_800_000_000_000_000_000u64;
        let mut now = || {
            t += 1000;
            t
        };
        let d2 = std::sync::Arc::clone(&disk);
        let (dp, cp) = (disk_path.clone(), ctr_path.clone());
        let mut after = move |nx: &mut Nx<'_>| -> Result<bool, String> {
            d2.0.sync_all().map_err(|e| e.to_string())?;
            copy_container(&dp, &cp, base, psize);
            let run = std::process::Command::new(&tool).args(["-A", "-D", "-U", "0", "-G", "0", "-v", "Vtmp"]).arg(&cp).output().map_err(|e| e.to_string())?;
            eprintln!("{}", String::from_utf8_lossy(&run.stderr));
            assert!(run.status.success(), "newfs_apfs -A failed");
            // The tool's clock readings, from the volume it made.
            let c = std::sync::Arc::new(Container::open(std::sync::Arc::new(super::super::HostFile(std::fs::File::open(&cp).unwrap(), psize))).unwrap());
            let com = c.omap().unwrap();
            let q = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
            let sbb = c.read_raw(com.lookup(&c, c.nx.fs_oid[6], c.xid()).unwrap().unwrap().paddr).unwrap();
            let vom = crate::darwin::apfsread::Omap::open(&c, q(&sbb, 0x80)).unwrap();
            let rootb = c.read_raw(vom.lookup(&c, q(&sbb, 0x88), c.xid()).unwrap().unwrap().paddr).unwrap();
            let toc_v = |slot: usize| 4096 - 40 - u16::from_le_bytes(rootb[56 + 8 * slot + 4..56 + 8 * slot + 6].try_into().unwrap()) as usize;
            let times = super::super::tx::VolumeTimes { formatted: q(&sbb, 0x130), root: q(&rootb, toc_v(1) + 8), private: q(&rootb, toc_v(0) + 8), modified: q(&sbb, 0x100) };
            // The same on the port's container: the tool's mount (a
            // regular file: no DK_FEATURE_BARRIER), its reaper, the volume.
            nx.set_barrier(false);
            nx.remount(Mode::Userspace)?;
            nx.reaper_run()?;
            nx.create_volume(&NewVolume { name: "Vtmp".into(), role: 0, encrypted: false, e_apfs: true, times, uid: 0, gid: 0, key_os_version: 0, size_bytes: None })?;
            nx.commit()?;
            nx.unmount()?;
            Ok(false)
        };
        build_disk0_with(disk.clone(), &mut now, Some(&os), &mut |_| Ok(true), &mut || Ok(()), &mut after, Some(false)).unwrap();
        let diffs = differing_blocks(&disk, base, psize, &ctr_path);
        if std::env::var("GEX_TEST_KEEP").is_err() {
            let _ = std::fs::remove_file(&disk_path);
            let _ = std::fs::remove_file(&ctr_path);
        }
        assert!(diffs.is_empty(), "{} blocks differ: {:?}", diffs.len(), &diffs[..diffs.len().min(40)]);
    }

    /// fixup_var's removals from System after the invert and the reaper
    /// (GEX_TEST_FSCK: the device's host-runnable fsck_apfs, with
    /// GEX_TEST_UDIF and GEX_TEST_SCRATCH): 4,244 files and 6,636
    /// directories go (measured on the image), the moved trees are gone,
    /// and the device's and the host's fsck_apfs find the container
    /// consistent.
    #[test]
    fn removals_leave_a_consistent_container() {
        let (Ok(dmg), Ok(dir), Ok(fsck)) = (std::env::var("GEX_TEST_UDIF"), std::env::var("GEX_TEST_SCRATCH"), std::env::var("GEX_TEST_FSCK")) else { return };
        let f = std::fs::File::open(&dmg).unwrap();
        let len = f.metadata().unwrap().len();
        let image = std::sync::Arc::new(crate::darwin::udif::Udif::open(std::sync::Arc::new(super::super::HostFile(f, len))).unwrap());
        let partition = image.partition("Apple_APFS").unwrap();
        let os = OsImage { image: std::sync::Arc::clone(&image), partition, boot: None, seal: None };
        let size = storage::disk0_bytes();
        let dir = std::path::Path::new(&dir);
        let disk_path = dir.join(format!("gex-rm-disk-{}", std::process::id()));
        let ctr_path = dir.join(format!("gex-rm-ctr-{}", std::process::id()));
        let f = std::fs::OpenOptions::new().create(true).truncate(true).read(true).write(true).open(&disk_path).unwrap();
        f.set_len(size).unwrap();
        let disk = std::sync::Arc::new(super::super::HostFile(f, size));
        let (base, psize) = storage::partition_extent();
        // Clocks before the checkers' own: fsck warns of times to come.
        let mut t = 1_700_000_000_000_000_000u64;
        let mut now = move || {
            t += 1000;
            t
        };
        let mut counts = Vec::new();
        let mut after = |nx: &mut Nx<'_>| -> Result<bool, String> {
            let mut clock = 1_710_000_000_000_000_000u64;
            let mut now = || {
                clock += 1000;
                clock
            };
            nx.remount(Mode::Kernel)?;
            nx.reaper_run()?;
            let q = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
            let sb = nx.vol_sb(0)?.clone();
            counts.push((q(&sb, 0xb8), q(&sb, 0xc0)));
            fsops::remove_moved_trees(nx, 0, &mut now)?;
            let sb = nx.vol_sb(0)?.clone();
            counts.push((q(&sb, 0xb8), q(&sb, 0xc0)));
            let mut var = 2;
            for n in ["private", "var"] {
                var = fsops::lookup(nx, 0, var, n)?.unwrap();
            }
            assert!(fsops::lookup(nx, 0, var, "staged_system_apps")?.is_none());
            let ma = fsops::lookup(nx, 0, var, "MobileAsset")?.unwrap();
            assert!(fsops::lookup(nx, 0, ma, "PreinstalledAssetsV2")?.is_none());
            nx.unmount()?;
            Ok(false)
        };
        build_disk0_with(disk.clone(), &mut now, Some(&os), &mut |_| Ok(true), &mut || Ok(()), &mut after, None).unwrap();
        assert_eq!((counts[0].0 - counts[1].0, counts[0].1 - counts[1].1), (4_244, 6_636));
        disk.0.sync_all().unwrap();
        copy_container(&disk_path, &ctr_path, base, psize);
        let dev = std::process::Command::new(&fsck).args(["-n", "-W", "-s"]).arg(&ctr_path).output().unwrap();
        let host = std::process::Command::new("/sbin/fsck_apfs").args(["-n", "-s"]).arg(&ctr_path).output().unwrap();
        if std::env::var("GEX_TEST_KEEP").is_err() {
            let _ = std::fs::remove_file(&disk_path);
            let _ = std::fs::remove_file(&ctr_path);
        }
        assert!(dev.status.success(), "device fsck: {}{}", String::from_utf8_lossy(&dev.stdout), String::from_utf8_lossy(&dev.stderr));
        assert!(host.status.success(), "host fsck: {}{}", String::from_utf8_lossy(&host.stdout), String::from_utf8_lossy(&host.stderr));
    }

    /// Data allocations of every size against the device library's
    /// `spaceman_alloc` (GEX_TEST_NEWFS_A: the host-runnable user-space
    /// `newfs_apfs -A`; GEX_TEST_DA_HOOK: the hook that calls the
    /// library's own allocator at its first allocation, drafts/s18/da;
    /// with GEX_TEST_SCRATCH): on disk0's container as asr finds it, each
    /// allocation's blocks and the roving pointer after it, then every
    /// allocation zone's chunk, ring and index. The sequence fills the
    /// 4- and 1-block zones' chunks (the 1-block zone's is its chunk-info
    /// block's last) and makes larger allocations between them.
    #[test]
    fn data_allocations_match_the_device_library() {
        let (Ok(dir), Ok(tool), Ok(hook)) = (std::env::var("GEX_TEST_SCRATCH"), std::env::var("GEX_TEST_NEWFS_A"), std::env::var("GEX_TEST_DA_HOOK")) else { return };
        const SEQ: &str = "2,3356,4x8193,3356,1x32769,2x16385,3x10923,256,4x3,5000,1x3,2x2,40000,3x2";
        let size = storage::disk0_bytes();
        let dir = std::path::Path::new(&dir);
        let disk_path = dir.join(format!("gex-da-disk-{}", std::process::id()));
        let ctr_path = dir.join(format!("gex-da-ctr-{}", std::process::id()));
        let f = std::fs::OpenOptions::new().create(true).truncate(true).read(true).write(true).open(&disk_path).unwrap();
        f.set_len(size).unwrap();
        let disk = std::sync::Arc::new(super::super::HostFile(f, size));
        let (base, psize) = storage::partition_extent();
        let mut t = 1_700_000_000_000_000_000u64;
        let mut now = || {
            t += 1000;
            t
        };
        let d2 = std::sync::Arc::clone(&disk);
        let (dp, cp) = (disk_path.clone(), ctr_path.clone());
        let mut theirs: Vec<(u64, u64, u64)> = Vec::new();
        let mut ours: Vec<(u64, u64, u64)> = Vec::new();
        let mut zones_theirs: Vec<String> = Vec::new();
        let mut zones_ours: Vec<String> = Vec::new();
        let mut before_asr = |nx: &mut Nx<'_>| -> Result<bool, String> {
            nx.unmount()?;
            d2.0.sync_all().map_err(|e| e.to_string())?;
            copy_container(&dp, &cp, base, psize);
            let run = std::process::Command::new(&tool)
                .args(["-A", "-D", "-U", "0", "-G", "0", "-v", "Vtmp"])
                .arg(&cp)
                .env("DYLD_INSERT_LIBRARIES", &hook)
                .env("DA_SEQ", SEQ)
                .env("DA_NODES", "0")
                .output()
                .map_err(|e| e.to_string())?;
            let out = String::from_utf8_lossy(&run.stdout).to_string();
            let num = |l: &str, k: &str| -> u64 { l.split(k).nth(1).unwrap().split_whitespace().next().unwrap().parse().unwrap() };
            let mut after = false;
            for l in out.lines() {
                if l.starts_with("alloc ") {
                    assert_eq!(num(l, " ret "), 0, "{l}");
                    theirs.push((num(l, " paddr "), num(l, " got "), num(l, " roving ")));
                } else if l.starts_with("-- after") {
                    after = true;
                } else if after && l.trim_start().starts_with("zone ") {
                    // "zone N [s,e) en E pend P priv V slot S cur [..) id I idx X prev [..)x7"
                    let l = l.trim_start();
                    let en = l.split(" en ").nth(1).unwrap().starts_with('1');
                    let cur = l.split(" cur ").nth(1).map(|x| x.split(" id ").next().unwrap().to_string()).unwrap_or_default();
                    let idx = l.split(" idx ").nth(1).map(|x| x.split_whitespace().next().unwrap().to_string()).unwrap_or_default();
                    let prev = l.split(" prev ").nth(1).unwrap_or("").trim().to_string();
                    zones_theirs.push(format!("{en} {cur} idx {idx} prev {prev}"));
                }
            }
            assert!(!theirs.is_empty(), "the hook made no allocation: {out}{}", String::from_utf8_lossy(&run.stderr));
            // The same on the port's container: the tool's mount (a regular
            // file: no barrier), its transaction, then the allocations.
            nx.set_barrier(false);
            nx.remount(Mode::Userspace)?;
            nx.begin()?;
            for tok in SEQ.split(',') {
                let (c, r) = match tok.split_once('x') {
                    Some((c, r)) => (c.parse::<u64>().unwrap(), r.parse::<u64>().unwrap()),
                    None => (tok.parse().unwrap(), 1),
                };
                for _ in 0..r {
                    let (p, g) = nx.alloc_data(c)?;
                    ours.push((p, g, nx.rove()));
                }
            }
            for (en, (s, e), prev, idx) in nx.zones() {
                let prev: Vec<String> = prev.iter().map(|(a, b)| format!("[{a},{b})")).collect();
                zones_ours.push(format!("{en} [{s},{e}) idx {idx} prev {}", prev.join(" ")));
            }
            Ok(false)
        };
        build_disk0_with(disk.clone(), &mut now, None, &mut before_asr, &mut || Ok(()), &mut |_| Ok(true), None).unwrap();
        if std::env::var("GEX_TEST_KEEP").is_err() {
            let _ = std::fs::remove_file(&disk_path);
            let _ = std::fs::remove_file(&ctr_path);
        }
        assert_eq!(ours.len(), theirs.len());
        for (i, (a, b)) in ours.iter().zip(&theirs).enumerate() {
            assert_eq!(a, b, "allocation {i} (paddr, got, roving)");
        }
        assert_eq!(zones_ours, zones_theirs);
    }

    /// The encrypted Data and User volumes after the invert (GEX_TEST_UDIF,
    /// GEX_TEST_SCRATCH, GEX_TEST_FSCK): Data's superblock as the kernel's
    /// volumeCreate and read-write mount leave it (drafts/s16/re-protected.md
    /// 2.1, drafts/s21/re-data.md 1) with fixup_var's directories and copy
    /// counted, the copy's objects by type, /internal, the pfkur thread's temporary inode,
    /// User's epoch, the container keybag's four entries; the device's and
    /// the host's fsck_apfs with -M (their keybag read needs the device's
    /// crypto I/O, drafts/s21/re-data.md 4), and the host's on a copy
    /// presenting the encrypted volumes as unencrypted, which checks their
    /// trees.
    #[test]
    fn data_volume_is_made_as_the_kernel_makes_it() {
        use crate::darwin::apfsread::{Container, Medium, Omap};
        let (Ok(dmg), Ok(dir), Ok(fsck)) = (std::env::var("GEX_TEST_UDIF"), std::env::var("GEX_TEST_SCRATCH"), std::env::var("GEX_TEST_FSCK")) else { return };
        let f = std::fs::File::open(&dmg).unwrap();
        let len = f.metadata().unwrap().len();
        let image = std::sync::Arc::new(crate::darwin::udif::Udif::open(std::sync::Arc::new(super::super::HostFile(f, len))).unwrap());
        let partition = image.partition("Apple_APFS").unwrap();
        let os = OsImage { image: std::sync::Arc::clone(&image), partition, boot: None, seal: None };
        let size = storage::disk0_bytes();
        let dir = std::path::Path::new(&dir);
        let disk_path = dir.join(format!("gex-data-disk-{}", std::process::id()));
        let ctr_path = dir.join(format!("gex-data-ctr-{}", std::process::id()));
        let f = std::fs::OpenOptions::new().create(true).truncate(true).read(true).write(true).open(&disk_path).unwrap();
        f.set_len(size).unwrap();
        let disk = std::sync::Arc::new(super::super::HostFile(f, size));
        let (base, psize) = storage::partition_extent();
        let mut t = 1_700_000_000_000_000_000u64;
        let mut now = move || {
            t += 1000;
            t
        };
        build_disk0(disk.clone(), &mut now, Some(&os)).unwrap();
        disk.0.sync_all().unwrap();
        let _ = std::fs::remove_file(&disk_path);
        copy_container_from(&disk, &ctr_path, base, psize);
        drop(disk);
        let open = || std::sync::Arc::new(Container::open(std::sync::Arc::new(super::super::HostFile(std::fs::File::open(&ctr_path).unwrap(), psize))).unwrap());
        let c = open();
        let q = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let com = c.omap().unwrap();
        let sb_paddr = com.lookup(&c, c.nx.fs_oid[1], c.xid()).unwrap().unwrap().paddr;
        let sb = c.read_raw(sb_paddr).unwrap();
        // Its block count (+0x58: the copy's data and metadata past the
        // overprovisioning file's 156,250) is the fsck runs' below to check.
        assert_eq!((q(&sb, 0x28), q(&sb, 0x30), q(&sb, 0x38), q(&sb, 0x108)), (2, 0xc, 0x2c8, 0x100));
        assert!(q(&sb, 0x58) > 7 + 156_250);
        assert_eq!(&sb[0x60..0x74], &[5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0xcd, 0x01, 0x48, 0x15, 1, 0, 0, 0][..]);
        // The mount: the epoch, then the pfkur thread's inode 0x10; then
        // /keybags (0x11), usersession.kb (0x12) and the overprovisioning
        // file (0x13: one contiguous unwritten extent of 156,250 blocks,
        // trimmed when the device answers DK_FEATURE_UNMAP); then fixup_var:
        // aks_bootstrap_fs' 27 directories and /root/.bootstrapped
        // (drafts/s26/re-aks-data.md), BOM's copy of the image's /private/var
        // (drafts/s27/re-bomcopy.md 0.1: 6,719 directories, 530 plain and
        // 3,723 compressed files, 2,041 of these with a resource-fork stream
        // named by an object identifier of its own, one link), then
        // create_partition_mountpoints' /internal.
        let (files, links, forks) = (2 + 1 + 530 + 3_723, 1, 2_041);
        let next = 0x14 + 27 + 1 + 6_719 + 530 + 3_723 + links + forks + 1;
        assert_eq!((q(&sb, 0xb0), q(&sb, 0x3d8), q(&sb, 0xb8), q(&sb, 0xc8), u32::from_le_bytes(sb[0x428..0x42c].try_into().unwrap())), (next, 0x10, files, links, 0x10));
        let pfkur = c.read_raw(q(&sb, 0x418)).unwrap();
        assert_eq!((u32::from_le_bytes(pfkur[24..28].try_into().unwrap()), u32::from_le_bytes(pfkur[28..32].try_into().unwrap())), (0x4000_0002, 0x20));
        let usb = c.read_raw(com.lookup(&c, c.nx.fs_oid[6], c.xid()).unwrap().unwrap().paddr).unwrap();
        assert_eq!((q(&usb, 0x38), q(&usb, 0x108), q(&usb, 0xb0), q(&usb, 0x3d8), u16::from_le_bytes([usb[0x3c4], usb[0x3c5]])), (0x388, 0, 0x48, 0x10, 2));
        // The template copy and the AKS bootstrap (drafts/s23/re-user-copy.md
        // 4): 18 + 34 directories, 4 files.
        assert_eq!((q(&usb, 0xb8), q(&usb, 0xc0)), (4, 52));
        assert_ne!(q(&usb, 0x448), 0);
        // The volume's object map and file-system tree, read raw (the reader
        // refuses an encrypted mapping): every mapping, the root node's
        // flagged encrypted, then every leaf record.
        let raw = |blk: u64| {
            let mut b = vec![0u8; 4096];
            super::super::HostFile(std::fs::File::open(&ctr_path).unwrap(), psize).read_at(blk * 4096, &mut b).unwrap();
            b
        };
        let vend = |b: &[u8]| if u16::from_le_bytes([b[0x20], b[0x21]]) & 1 != 0 { 4096 - 0x28 } else { 4096 };
        let vom = Omap::open(&c, q(&sb, 0x80)).unwrap();
        let mut map = std::collections::BTreeMap::new();
        let mut stack = vec![vom.tree.root_oid];
        while let Some(p) = stack.pop() {
            let b = raw(p);
            let kstart = 0x38 + u16::from_le_bytes([b[0x2a], b[0x2b]]) as usize;
            for i in 0..u32::from_le_bytes(b[0x24..0x28].try_into().unwrap()) as usize {
                let ko = u16::from_le_bytes([b[0x38 + 4 * i], b[0x38 + 4 * i + 1]]) as usize;
                let vat = vend(&b) - u16::from_le_bytes([b[0x38 + 4 * i + 2], b[0x38 + 4 * i + 3]]) as usize;
                if u16::from_le_bytes([b[0x22], b[0x23]]) > 0 {
                    stack.push(q(&b, vat));
                } else {
                    map.insert(q(&b, kstart + ko), (u32::from_le_bytes(b[vat..vat + 4].try_into().unwrap()), q(&b, vat + 8)));
                }
            }
        }
        assert_eq!(map.get(&q(&sb, 0x88)).map(|m| m.0), Some(4));
        let rootb = raw(map[&q(&sb, 0x88)].1);
        assert_eq!(u32::from_le_bytes(rootb[24..28].try_into().unwrap()), 0x1000_0002);
        let mut recs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let mut stack = vec![q(&sb, 0x88)];
        while let Some(oid) = stack.pop() {
            let b = raw(map.get(&oid).expect("a tree node the object map does not map").1);
            let toc = u16::from_le_bytes([b[0x2a], b[0x2b]]) as usize;
            for i in 0..u32::from_le_bytes(b[0x24..0x28].try_into().unwrap()) as usize {
                let e = |o: usize| u16::from_le_bytes([b[0x38 + 8 * i + o], b[0x38 + 8 * i + o + 1]]) as usize;
                let k = 0x38 + toc + e(0);
                let v = vend(&b) - e(4);
                if u16::from_le_bytes([b[0x22], b[0x23]]) > 0 {
                    stack.push(q(&b, v));
                } else {
                    recs.push((b[k..k + e(2)].to_vec(), b[v..v + e(6)].to_vec()));
                }
            }
        }
        // The inodes by type: the root, the private directory and /keybags
        // with the directories made since; the temporary inode with the
        // counted files; the link.
        let modes: Vec<u16> = recs.iter().filter(|(k, _)| k.len() == 8 && q(k, 0) >> 60 == 3).map(|(_, v)| u16::from_le_bytes([v[0x50], v[0x51]]) & 0o170000).collect();
        let count = |m: u16| modes.iter().filter(|&&x| x == m).count() as u64;
        assert_eq!((count(0o040000), count(0o100000), count(0o120000)), (3 + 27 + 6_719 + 1, 1 + files, links));
        assert_eq!(recs.iter().filter(|(k, v)| q(k, 0) >> 60 == 4 && k.ends_with(b"com.apple.ResourceFork\0") && v[0] & 1 != 0).count() as u64, forks);
        let internal = recs.iter().find(|(k, _)| q(k, 0) == (ROOT_INO | 9 << 60) && k.ends_with(b"internal\0")).map(|(_, v)| q(v, 0)).expect("/internal");
        let iv = &recs.iter().find(|(k, _)| k[..] == (internal | 3 << 60).to_le_bytes()).unwrap().1;
        assert_eq!((u16::from_le_bytes([iv[0x50], iv[0x51]]), u32::from_le_bytes(iv[0x44..0x48].try_into().unwrap())), (0o40777, 0x2_0002));
        let name = b"tmp-ino-xattr-dstream-0x0-0x10\0";
        let drec = recs.iter().find(|(k, _)| q(k, 0) == (3 | 9 << 60) && k.ends_with(name)).expect("the temporary inode's entry in the private directory");
        assert_eq!(q(&drec.1, 0), 0x10);
        let ino = &recs.iter().find(|(k, _)| k[..] == (0x10u64 | 3 << 60).to_le_bytes()).expect("the temporary inode").1;
        assert_eq!((q(ino, 0), q(ino, 0x30), u32::from_le_bytes(ino[0x3c..0x40].try_into().unwrap()), u16::from_le_bytes([ino[0x50], ino[0x51]])), (3, 0x8000, 0, 0o100600));
        assert_eq!(q(&ino[ino.len() - 0x28..], 0x10), u64::MAX, "the stream's default crypto identifier");
        assert!(recs.iter().any(|(k, v)| k[..] == (0x10u64 | 6 << 60).to_le_bytes() && v[..4] == 1u32.to_le_bytes()));
        let op = &recs.iter().find(|(k, _)| k[..] == (0x13u64 | 3 << 60).to_le_bytes()).expect("the overprovisioning file").1;
        let trimmed = if crate::darwin::storagestack::container_unmap() { 0x800 } else { 0 };
        assert_eq!((q(op, 0x30), u32::from_le_bytes(op[0x3c..0x40].try_into().unwrap())), (0x800_8000 | trimmed, 3));
        let fx = &recs.iter().find(|(k, _)| k.len() == 16 && q(k, 0) == (0x13 | 8 << 60)).expect("its extent").1;
        assert_eq!((q(fx, 0), q(fx, 16)), (0x0300_0000_2625_a000, q(fx, 8)));
        // The keybag: its block from the checkpoint's nx_keylocker.
        let latest = (0..u64::from(c.nx.xp_desc_blocks & 0x7fff_ffff)).map(|i| raw(c.nx.xp_desc_base + i)).filter(|b| &b[32..36] == b"NXSB").max_by_key(|b| q(b, 16)).unwrap();
        let (kb, kn) = (q(&latest, 0x510), q(&latest, 0x518));
        assert_eq!(kn, 1);
        let kbb = c.read_raw(kb).unwrap();
        assert_eq!(u32::from_le_bytes(kbb[24..28].try_into().unwrap()), 0x6b65_7973);
        let n = u16::from_le_bytes([kbb[0x22], kbb[0x23]]);
        let mut at = 0x30;
        let mut ents = Vec::new();
        for _ in 0..n {
            let len = u16::from_le_bytes([kbb[at + 0x12], kbb[at + 0x13]]) as usize;
            ents.push((kbb[at..at + 16].to_vec(), u16::from_le_bytes([kbb[at + 0x10], kbb[at + 0x11]])));
            at += (0x18 + len).div_ceil(16) * 16;
        }
        let (d, u) = (sb[0xf0..0x100].to_vec(), usb[0xf0..0x100].to_vec());
        assert_eq!(ents, vec![(d.clone(), 2), (d, 10), (u.clone(), 2), (u.clone(), 0xd), (u, 0xf8)]);
        drop(c);
        let run = |args: &[&str], tool: &str| std::process::Command::new(tool).args(args).arg(&ctr_path).output().unwrap();
        let dev = run(&["-n", "-W", "-s", "-M"], &fsck);
        let host = run(&["-n", "-s", "-M"], "/sbin/fsck_apfs");
        let (orphans, unnamed) = unencrypted_view(&ctr_path, psize);
        let host_trees = run(&["-n", "-s"], "/sbin/fsck_apfs");
        assert!(dev.status.success(), "device fsck -M: {}{}", String::from_utf8_lossy(&dev.stdout), String::from_utf8_lossy(&dev.stderr));
        assert!(host.status.success(), "host fsck -M: {}{}", String::from_utf8_lossy(&host.stdout), String::from_utf8_lossy(&host.stderr));
        let out = String::from_utf8_lossy(&host_trees.stdout).to_string() + &String::from_utf8_lossy(&host_trees.stderr);
        assert!(!out.contains("skipping the fsroot tree"), "{out}");
        let bad: Vec<&str> = out.lines().filter(|l| (l.contains("error") || l.contains("warning")) && !view_says(l, &unnamed)).collect();
        assert!(bad.is_empty(), "{out}");
        assert_eq!(out.lines().filter(|l| l.starts_with("warning: overallocation detected")).count(), orphans.len(), "{out}");
        assert!(out.contains("appears to be OK") && out.contains(&format!("{:x}+1", kb)), "{out}");
        // User's tree through the view (drafts/s23/re-user-copy.md 4), its
        // expanded-records and unwritten-extents flags cleared for gex's
        // reader, which refuses them (User has no extents, and the records
        // read here are laid out alike).
        {
            use std::os::unix::fs::FileExt;
            let c = open();
            let at = c.omap().unwrap().lookup(&c, c.nx.fs_oid[6], c.xid()).unwrap().unwrap().paddr;
            let f = std::fs::OpenOptions::new().read(true).write(true).open(&ctr_path).unwrap();
            let mut b = vec![0u8; 4096];
            f.read_exact_at(&mut b, at * 4096).unwrap();
            let inc = q(&b, 0x38) & !0x280;
            b[0x38..0x40].copy_from_slice(&inc.to_le_bytes());
            super::super::set_checksum(&mut b);
            f.write_all_at(&b, at * 4096).unwrap();
        }
        let c = open();
        let u = c.volume(6).unwrap().unwrap();
        let at = |p: &str| u.resolve(p).unwrap().unwrap_or_else(|| panic!("no {p} on User"));
        let root = at("/");
        assert_eq!((root.nchildren_or_nlink, root.uncompressed_size, root.owner, root.group, root.mode), (7, 5, 501, 501, 0o40755));
        let lib = at("/Library");
        assert_eq!((lib.nchildren_or_nlink, lib.uncompressed_size, lib.default_protection_class), (38, 37, 0));
        let caches = at("/Library/Caches");
        assert_eq!((caches.default_protection_class, caches.internal_flags, caches.mode), (4, 0x8008, 0o40755));
        let cd = at("/Library/Logs/CoreDuet");
        assert_eq!((cd.default_protection_class, cd.internal_flags), (4, 0x8000));
        let fwd = at("/.forward");
        assert_eq!((fwd.bsd_flags, fwd.internal_flags, fwd.uncompressed_size, fwd.default_protection_class, fwd.owner, fwd.group), (0x20, 0x4_8000, 10, 3, 501, 501));
        assert!(fwd.dstream.is_none());
        let mut buf = vec![0u8; 16];
        assert_eq!(u.read_file(&fwd, 0, &mut buf).unwrap(), 10);
        assert_eq!(&buf[..10], b"/dev/null\n");
        let gp = at("/Library/Preferences/.GlobalPreferences.plist");
        assert_eq!((gp.uncompressed_size, gp.default_protection_class), (89, 3));
        let bs = at("/.bootstrapped");
        assert_eq!((bs.owner, bs.group, bs.mode, bs.default_protection_class), (0, 501, 0o100644, 3));
        assert_eq!(u.resolve("/Library/mad/activation_records").unwrap().map(|i| i.oid), Some(0x3c));
        drop(c);
        if std::env::var("GEX_TEST_KEEP").is_err() {
            let _ = std::fs::remove_file(&ctr_path);
        }
    }

    /// The container partition of `disk` (at `base`, `psize` bytes) copied
    /// to the container file `ctr`, keeping holes.
    fn copy_container_from(disk: &super::super::HostFile, ctr: &std::path::Path, base: u64, psize: u64) {
        use crate::darwin::apfsread::Medium;
        use std::os::unix::fs::FileExt;
        let _ = std::fs::remove_file(ctr);
        let out = std::fs::OpenOptions::new().create(true).truncate(true).write(true).open(ctr).unwrap();
        out.set_len(psize).unwrap();
        let mut b = vec![0u8; 1 << 20];
        let mut off = 0;
        while off < psize {
            let n = (psize - off).min(1 << 20) as usize;
            disk.read_at(base + off, &mut b[..n]).unwrap();
            if b[..n].iter().any(|&x| x != 0) {
                out.write_all_at(&b[..n], off).unwrap();
            }
            off += n as u64;
        }
    }

    /// The container file `ctr` (`psize` bytes) changed in place into a
    /// view that presents its plaintext encrypted volumes as unencrypted,
    /// for the host's fsck_apfs to check their trees (it skips an
    /// encrypted volume's): no container keybag, each encrypted volume's
    /// fs_flags 1 with no per-file-key or secondary-tree features and no
    /// pfkur tree or secondary root named, its object map's crypto flags
    /// cleared and its objects' OBJ_ENCRYPTED. The blocks the view leaves
    /// with nothing naming them (the keybag's and each pfkur tree's), and
    /// the virtual objects mapped with nothing naming them (each secondary
    /// root).
    fn unencrypted_view(ctr: &std::path::Path, psize: u64) -> (Vec<u64>, Vec<u64>) {
        use crate::darwin::apfsread::{Container, Medium, Omap};
        use std::os::unix::fs::FileExt;
        let q = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let c = Container::open(std::sync::Arc::new(super::super::HostFile(std::fs::File::open(ctr).unwrap(), psize))).unwrap();
        let file = super::super::HostFile(std::fs::File::open(ctr).unwrap(), psize);
        let raw = |blk: u64| {
            let mut b = vec![0u8; 4096];
            file.read_at(blk * 4096, &mut b).unwrap();
            b
        };
        let f = std::fs::OpenOptions::new().read(true).write(true).open(ctr).unwrap();
        let rw = |blk: u64, edit: &dyn Fn(&mut Vec<u8>)| {
            let mut b = vec![0u8; 4096];
            f.read_exact_at(&mut b, blk * 4096).unwrap();
            edit(&mut b);
            super::super::set_checksum(&mut b);
            f.write_all_at(&b, blk * 4096).unwrap();
        };
        let latest = (0..u64::from(c.nx.xp_desc_blocks & 0x7fff_ffff)).map(|i| (c.nx.xp_desc_base + i, raw(c.nx.xp_desc_base + i))).filter(|(_, b)| &b[32..36] == b"NXSB").max_by_key(|(_, b)| q(b, 16)).unwrap();
        let mut orphans = Vec::new();
        let mut unnamed = Vec::new();
        if q(&latest.1, 0x510) != 0 {
            orphans.push(q(&latest.1, 0x510));
        }
        for blk in [0, latest.0] {
            rw(blk, &|b| b[0x510..0x520].fill(0));
        }
        let com = c.omap().unwrap();
        for &oid in c.nx.fs_oid.iter().filter(|&&o| o != 0) {
            let sb_paddr = com.lookup(&c, oid, c.xid()).unwrap().unwrap().paddr;
            let sb = raw(sb_paddr);
            if q(&sb, 0x108) & 1 != 0 {
                continue;
            }
            if q(&sb, 0x418) != 0 {
                orphans.push(q(&sb, 0x418));
            }
            if q(&sb, 0x448) != 0 {
                unnamed.push(q(&sb, 0x448));
            }
            rw(sb_paddr, &|b| {
                b[0x108..0x110].copy_from_slice(&1u64.to_le_bytes());
                let inc = q(b, 0x38) & !0x140;
                b[0x38..0x40].copy_from_slice(&inc.to_le_bytes());
                b[0x418..0x420].fill(0);
                b[0x448..0x450].fill(0);
            });
            let vom = Omap::open(&c, q(&sb, 0x80)).unwrap();
            // The object map's leaves (a root holds the tree's info at its
            // end; an index node's values are its children's addresses).
            let vend = |b: &[u8]| if u16::from_le_bytes([b[0x20], b[0x21]]) & 1 != 0 { 4096 - 0x28 } else { 4096 };
            let mut leaves = Vec::new();
            let mut stack = vec![vom.tree.root_oid];
            while let Some(p) = stack.pop() {
                let b = raw(p);
                let n = u32::from_le_bytes(b[0x24..0x28].try_into().unwrap()) as usize;
                if u16::from_le_bytes([b[0x22], b[0x23]]) == 0 {
                    leaves.push(p);
                    continue;
                }
                for i in (0..n).rev() {
                    let vo = u16::from_le_bytes([b[0x38 + 4 * i + 2], b[0x38 + 4 * i + 3]]) as usize;
                    stack.push(q(&b, vend(&b) - vo));
                }
            }
            // Each mapping: (flags' offset in its leaf, oid, paddr).
            let maps = |leaf: &[u8]| -> Vec<(usize, u64, u64)> {
                let nk = u32::from_le_bytes(leaf[0x24..0x28].try_into().unwrap()) as usize;
                let kstart = 0x38 + u16::from_le_bytes([leaf[0x2a], leaf[0x2b]]) as usize;
                (0..nk)
                    .map(|i| {
                        let vo = u16::from_le_bytes([leaf[0x38 + 4 * i + 2], leaf[0x38 + 4 * i + 3]]) as usize;
                        let at = vend(leaf) - vo;
                        (at, q(leaf, kstart + u16::from_le_bytes([leaf[0x38 + 4 * i], leaf[0x38 + 4 * i + 1]]) as usize), q(leaf, at + 8))
                    })
                    .collect()
            };
            let ids: Vec<u64> = leaves.iter().flat_map(|&l| maps(&raw(l))).flat_map(|(_, _, p)| per_file_ids(&raw(p))).collect();
            for &l in &leaves {
                let leaf = raw(l);
                for (at, oid, paddr) in maps(&leaf) {
                    let fl = u32::from_le_bytes(leaf[at..at + 4].try_into().unwrap());
                    assert!(fl & 0x20 == 0 || unnamed.contains(&oid), "a secondary-root mapping of an object the superblock does not name");
                    rw(paddr, &|b| {
                        let ty = u32::from_le_bytes(b[24..28].try_into().unwrap()) & !0x1000_0000;
                        b[24..28].copy_from_slice(&ty.to_le_bytes());
                        per_file_ids_cleared(b, &ids);
                    });
                }
                rw(l, &|b| {
                    for (at, _, _) in maps(b) {
                        let fl = u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) & !0x724;
                        b[at..at + 4].copy_from_slice(&fl.to_le_bytes());
                    }
                });
            }
        }
        (orphans, unnamed)
    }

    /// In the view, a one-leaf file-system tree's per-file crypto
    /// identifiers (a data stream's or an attribute stream's default crypto
    /// identifier, the VEK's 4 or a per-file key's, and the extents' crypto field naming a per-file
    /// key's crypto-state record or the block as the VEK's tweak) set to
    /// 0, as on an unencrypted volume;
    /// the records stay.
    /// The per-file crypto identifiers an fs-tree leaf's crypto-state keys
    /// name (all but the VEK's, 4).
    fn per_file_ids(b: &[u8]) -> Vec<u64> {
        let q = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        if u16::from_le_bytes([b[0x22], b[0x23]]) != 0 || u32::from_le_bytes(b[28..32].try_into().unwrap()) != 0xe {
            return Vec::new();
        }
        let toc = u16::from_le_bytes([b[0x2a], b[0x2b]]) as usize;
        let n = u32::from_le_bytes(b[0x24..0x28].try_into().unwrap()) as usize;
        (0..n)
            .filter_map(|i| {
                let k = 0x38 + toc + u16::from_le_bytes([b[0x38 + 8 * i], b[0x38 + 8 * i + 1]]) as usize;
                let key = q(b, k);
                (key >> 60 == 7 && key & 0x0fff_ffff_ffff_ffff != 4).then_some(key & 0x0fff_ffff_ffff_ffff)
            })
            .collect()
    }

    /// An fs-tree leaf with the per-file identifiers `ids` (and the VEK's
    /// tweaks) cleared from its file extents and data streams.
    fn per_file_ids_cleared(b: &mut [u8], ids: &[u64]) {
        let q = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        if u16::from_le_bytes([b[0x22], b[0x23]]) != 0 || u32::from_le_bytes(b[28..32].try_into().unwrap()) != 0xe {
            return;
        }
        let toc = u16::from_le_bytes([b[0x2a], b[0x2b]]) as usize;
        let n = u32::from_le_bytes(b[0x24..0x28].try_into().unwrap()) as usize;
        // A root node ends with the tree's info.
        let vend = if u16::from_le_bytes([b[0x20], b[0x21]]) & 1 != 0 { b.len() - 0x28 } else { b.len() };
        for i in 0..n {
            let e = |o: usize| u16::from_le_bytes([b[0x38 + 8 * i + o], b[0x38 + 8 * i + o + 1]]) as usize;
            let (k, v, vl) = (0x38 + toc + e(0), vend - e(4), e(6));
            let key = q(b, k);
            match key >> 60 {
                8 if ids.contains(&q(b, v + 16)) || b[v + 7] & 1 != 0 => {
                    // A per-file key's identifier, or the physical block as
                    // the VEK's tweak (FEXT_CRYPTO_ID_IS_TWEAK).
                    b[v + 7] &= !1;
                    b[v + 16..v + 24].fill(0);
                }
                3 if vl > 0x5c => {
                    let nx = u16::from_le_bytes([b[v + 0x5c], b[v + 0x5d]]) as usize;
                    let mut at = v + 0x60 + 4 * nx;
                    for j in 0..nx {
                        let d = v + 0x60 + 4 * j;
                        let size = u16::from_le_bytes([b[d + 2], b[d + 3]]) as usize;
                        if b[d] == 8 && (ids.contains(&q(b, at + 16)) || q(b, at + 16) == 4) {
                            b[at + 16..at + 24].fill(0);
                        }
                        at += size.div_ceil(8) * 8;
                    }
                }
                // An attribute stream's j_xattr_dstream default crypto
                // identifier.
                4 if vl == 0x34 && u16::from_le_bytes([b[v], b[v + 1]]) & 1 != 0 && (ids.contains(&q(b, v + 28)) || q(b, v + 28) == 4) => {
                    b[v + 28..v + 36].fill(0);
                }
                _ => {}
            }
        }
    }

    /// The container keybag's entries (volume UUID, tag, key length) as
    /// the container file's latest checkpoint names it.
    fn keybag_entries(ctr: &std::path::Path, psize: u64) -> Vec<(Vec<u8>, u16, usize)> {
        use crate::darwin::apfsread::{Container, Medium};
        let q = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let file = super::super::HostFile(std::fs::File::open(ctr).unwrap(), psize);
        let raw = |blk: u64| {
            let mut b = vec![0u8; 4096];
            file.read_at(blk * 4096, &mut b).unwrap();
            b
        };
        let c = Container::open(std::sync::Arc::new(super::super::HostFile(std::fs::File::open(ctr).unwrap(), psize))).unwrap();
        let latest = (0..u64::from(c.nx.xp_desc_blocks & 0x7fff_ffff)).map(|i| raw(c.nx.xp_desc_base + i)).filter(|b| &b[32..36] == b"NXSB").max_by_key(|b| q(b, 16)).unwrap();
        let kbb = raw(q(&latest, 0x510));
        assert_eq!(u32::from_le_bytes(kbb[24..28].try_into().unwrap()), 0x6b65_7973);
        let mut at = 0x30;
        let mut out = Vec::new();
        for _ in 0..u16::from_le_bytes([kbb[0x22], kbb[0x23]]) {
            let len = u16::from_le_bytes([kbb[at + 0x12], kbb[at + 0x13]]) as usize;
            out.push((kbb[at..at + 16].to_vec(), u16::from_le_bytes([kbb[at + 0x10], kbb[at + 0x11]]), len));
            at += (0x18 + len).div_ceil(16) * 16;
        }
        assert_eq!(u32::from_le_bytes(kbb[0x24..0x28].try_into().unwrap()) as usize, at - 0x20);
        assert!(kbb[at..].iter().all(|&b| b == 0));
        out
    }

    /// Whether a line of the host fsck's output on the unencrypted view is
    /// one the view itself makes it say: the view's file name, Data's
    /// crypto-state records (the per-file keys' of version 6.0, K
    /// 0x6734490) and its sixth counted block (the pfkur tree's) on a
    /// volume it takes as unencrypted, the unnamed blocks and the unnamed
    /// secondary roots' mappings.
    fn view_says(l: &str, unnamed: &[u64]) -> bool {
        l.contains("not a valid disk name")
            || l.contains("crypto state object (id ")
            || (l.contains("crypto state (id ") && l.contains("invalid state.major_version (6)"))
            || l.split("apfs_fs_alloc_count is not valid (expected ").nth(1).and_then(|r| {
                let (e, a) = r.trim_end_matches(')').split_once(", actual ")?;
                Some(e.parse::<u64>().ok()? + 1 == a.parse::<u64>().ok()?)
            }) == Some(true)
            || l.contains("overallocation detected on Main device")
            || (l.contains("orphan mappings found") && l.contains(&format!(" {} orphan", unnamed.len())))
            || unnamed.iter().any(|o| l.contains(&format!("orphan omap mapping found for oid {o}")) || l.contains(&format!("orphan omap mapping (oid {o} ")))
    }

    /// The NVRAM changes of the steps after fixup_var
    /// (drafts/s27/re-mountpoints.md 0.2): with restored's defaults, and with
    /// the options that change them.
    #[test]
    fn nvram_changes_follow_the_restore_options() {
        use NvramOp::{Delete, Set};
        let d = RestoreOptions::DEFAULTS;
        assert_eq!(
            nvram_after_fixup_var(&d).unwrap(),
            vec![Delete("root-live-fs"), Delete("allow-root-hash-mismatch"), Delete("oblit-inprogress"), Delete("oblit-begins"), Delete("oblit-failure"), Delete("one-time-boot-command"), Set("boot-args", NvramValue::String(""))]
        );
        let o = RestoreOptions { read_only_root_filesystem: false, create_filesystem_partitions: false, set_field_diagnostics_boot: true, ..d };
        assert_eq!(nvram_after_fixup_var(&o).unwrap(), vec![Set("root-live-fs", NvramValue::Data(b"1")), Delete("allow-root-hash-mismatch"), Set("one-time-boot-command", NvramValue::Data(b"checkerboard")), Set("boot-args", NvramValue::String(""))]);
        let o = RestoreOptions { system_image: false, ..d };
        assert_eq!(nvram_after_fixup_var(&o).unwrap(), vec![Delete("one-time-boot-command"), Set("boot-args", NvramValue::String(""))]);
        assert!(nvram_after_fixup_var(&RestoreOptions { set_target_disk_mode: Some(true), ..d }).is_err());
        assert_eq!(nvram_after_fixup_var(&RestoreOptions { set_target_disk_mode: Some(false), ..d }).unwrap(), nvram_after_fixup_var(&d).unwrap());
    }

    /// check_mounted's create_partition_mountpoints on a container of its
    /// own (GEX_TEST_FSCK, GEX_TEST_SCRATCH; drafts/s27/re-mountpoints.md 0.1,
    /// 3): System's /private/xarts and Data's /hardware and
    /// /MobileSoftwareUpdate already there (the image's, the BOM copy's and
    /// aks_bootstrap_fs'), so only /internal is made: mkdir 0755, chmod's
    /// fast path (a clock reading, nothing written), chown 0:0, chmod 0777,
    /// chflags SF_IMMUTABLE | UF_IMMUTABLE, ten clock readings in all;
    /// nothing on System. Then chflags' own refusals (each before any
    /// transaction), its masks and its write of unchanged flags; the
    /// device's and the host's fsck_apfs -M and the host's on the
    /// unencrypted view, mounted and after the unmounts.
    #[test]
    fn partition_mountpoints_make_only_internal() {
        use fsops::bsd_flags::*;
        let (Ok(dir), Ok(fsck)) = (std::env::var("GEX_TEST_SCRATCH"), std::env::var("GEX_TEST_FSCK")) else { return };
        let dir = std::path::Path::new(&dir);
        let path = dir.join(format!("gex-mp-{}", std::process::id()));
        let blocks = 15_625_000u64;
        let f = std::fs::OpenOptions::new().create(true).truncate(true).read(true).write(true).open(&path).unwrap();
        f.set_len(blocks * 4096).unwrap();
        let sink = super::super::HostFile(f, blocks * 4096);
        let uuid = *b"gex-mountpoints1";
        let fm = container::format(&sink, 4096, blocks, uuid).unwrap();
        let mut nx = Nx::formatted(&sink, &fm, uuid, Mode::Kernel).unwrap();
        nx.mount_rw().unwrap();
        let clock = std::cell::Cell::new(1_700_000_000_000_000_000u64);
        let mut now = || {
            clock.set(clock.get() + 1000);
            clock.get()
        };
        let q = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let u = |b: &[u8], o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let kv = key_os_version(RESTORE_BUILD).unwrap();
        let make = |nx: &mut Nx<'_>, name: &str, role: u16, encrypted: bool, now: &mut dyn FnMut() -> u64| {
            let times = VolumeTimes { formatted: now(), root: now(), private: now(), modified: now() };
            let o = nx.create_volume(&NewVolume { name: name.into(), role, encrypted, e_apfs: true, times, uid: 0, gid: 0, key_os_version: kv, size_bytes: None }).unwrap();
            nx.commit().unwrap();
            nx.fs_oid.iter().position(|&x| x == o).unwrap()
        };
        let system = make(&mut nx, "System", storage::role::SYSTEM, false, &mut now);
        fsops::mount_rw(&mut nx, system, &mut now).unwrap();
        let private = fsops::mkdir(&mut nx, system, ROOT_INO, "private", 0o755, 0, 0, &mut now).unwrap().unwrap();
        fsops::mkdir(&mut nx, system, private, "xarts", 0o755, 0, 0, &mut now).unwrap().unwrap();
        let data = make(&mut nx, "Data", storage::role::DATA, true, &mut now);
        fsops::mount_rw(&mut nx, data, &mut now).unwrap();
        let hw = fsops::mkdir(&mut nx, data, ROOT_INO, "hardware", 0o755, 0, 0, &mut now).unwrap().unwrap();
        let msu = fsops::mkdir(&mut nx, data, ROOT_INO, "MobileSoftwareUpdate", 0o755, 0, 0, &mut now).unwrap().unwrap();
        nx.commit().unwrap();
        let recs = |nx: &mut Nx<'_>, vol: usize| {
            let (t, mut st) = nx.fs_tree(vol).unwrap();
            t.records(&mut st).unwrap()
        };
        let sys_before = recs(&mut nx, system);
        let sys_sb = nx.vol_sb_read(system).unwrap().0.to_vec();
        let (hw_before, msu_before) = (fsops::inode(&mut nx, data, hw).unwrap(), fsops::inode(&mut nx, data, msu).unwrap());
        let root_before = fsops::inode(&mut nx, data, ROOT_INO).unwrap();
        let sb0 = nx.vol_sb_read(data).unwrap().0.to_vec();
        let t0 = clock.get();
        let c = |i: u64| t0 + 1000 * i;
        create_partition_mountpoints(&mut nx, system, data, &RestoreOptions::DEFAULTS, &mut now).unwrap();
        assert_eq!(clock.get(), c(10), "ten clock readings");
        assert!(nx.jobj_times.is_empty(), "chmod's change time written by chown");
        assert_eq!(recs(&mut nx, system), sys_before, "nothing on System");
        assert_eq!(nx.vol_sb_read(system).unwrap().0, &sys_sb[..]);
        assert_eq!((fsops::inode(&mut nx, data, hw).unwrap(), fsops::inode(&mut nx, data, msu).unwrap()), (hw_before.clone(), msu_before));
        let ino = fsops::lookup(&mut nx, data, ROOT_INO, "internal").unwrap().expect("/internal");
        let v = fsops::inode(&mut nx, data, ino).unwrap();
        assert_eq!(ino, q(&sb0, 0xb0));
        assert_eq!((q(&v, 0), q(&v, 0x10), q(&v, 0x18), q(&v, 0x20), q(&v, 0x28)), (ROOT_INO, c(1), c(1), c(9), c(1)));
        assert_eq!((q(&v, 0x30), u(&v, 0x38), u(&v, 0x3c), u(&v, 0x40), u(&v, 0x44)), (0x8008, 0, 0, 1, 0x2_0002));
        assert_eq!((u(&v, 0x48), u(&v, 0x4c), u16::from_le_bytes([v[0x50], v[0x51]]), q(&v, 0x54)), (0, 0, 0o40777, 0));
        let r = fsops::inode(&mut nx, data, ROOT_INO).unwrap();
        assert_eq!((q(&r, 0x18), q(&r, 0x20)), (c(2), c(2)));
        assert_eq!((u(&r, 0x38), u(&r, 0x40), u(&r, 0x54)), (u(&root_before, 0x38) + 1, u(&root_before, 0x40) + 1, u(&root_before, 0x54) + 1));
        let sb = nx.vol_sb_read(data).unwrap().0.to_vec();
        assert_eq!((q(&sb, 0xb0), q(&sb, 0xc0), q(&sb, 0xb8)), (q(&sb0, 0xb0) + 1, q(&sb0, 0xc0) + 1, q(&sb0, 0xb8)));
        assert_eq!((q(&sb, 0x100), q(&sb, 0x420), u(&sb, 0x428) & 0x10), (c(10), nx.xid, 0x10));
        // Without the data partitions' creation only System is looked at.
        create_partition_mountpoints(&mut nx, system, data, &RestoreOptions { create_filesystem_partitions: false, ..RestoreOptions::DEFAULTS }, &mut now).unwrap();
        assert_eq!(clock.get(), c(10));
        // Run again, the existing immutable /internal's chmod is refused.
        assert!(create_partition_mountpoints(&mut nx, system, data, &RestoreOptions::DEFAULTS, &mut now).is_err());
        assert_eq!(clock.get(), c(10));
        // chflags' refusals write nothing and read no clock: clearing
        // SF_IMMUTABLE (EPERM above securelevel 0, unknown securelevel
        // refused), SF_FIRMLINK newly set, UF_TRACKED with no document
        // identifier, UF_COMPRESSED.
        let data_recs = recs(&mut nx, data);
        assert!(fsops::chflags(&mut nx, data, ino, UF_IMMUTABLE, None, &mut now).is_err());
        assert_eq!(fsops::chflags(&mut nx, data, ino, UF_IMMUTABLE, Some(1), &mut now).unwrap(), Err(1));
        assert_eq!(fsops::chflags(&mut nx, data, hw, SF_FIRMLINK, Some(0), &mut now).unwrap(), Err(1));
        assert!(fsops::chflags(&mut nx, data, hw, UF_TRACKED, Some(0), &mut now).is_err());
        assert!(fsops::chflags(&mut nx, data, hw, UF_COMPRESSED, Some(0), &mut now).is_err());
        assert_eq!(recs(&mut nx, data), data_recs);
        assert_eq!(clock.get(), c(10));
        // The synthetic bits and those vnode_setattr masks are dropped, and
        // unchanged flags are written all the same.
        assert_eq!(fsops::chflags(&mut nx, data, hw, SF_SYNTHETIC | 0x0100_0000, None, &mut now).unwrap(), Ok(()));
        let h = fsops::inode(&mut nx, data, hw).unwrap();
        assert_eq!((u(&h, 0x44), q(&h, 0x20), q(&h, 0x18)), (0, c(11), q(&hw_before, 0x18)));
        assert_eq!(&h[..0x20], &hw_before[..0x20]);
        assert_eq!(&h[0x28..], &hw_before[0x28..]);
        assert_eq!(q(nx.vol_sb_read(data).unwrap().0, 0x100), c(12));
        nx.commit().unwrap();
        let check = |tag: &str| {
            sink.0.sync_all().unwrap();
            let view = dir.join(format!("gex-mp-view-{}", std::process::id()));
            let _ = std::fs::remove_file(&view);
            assert!(std::process::Command::new("cp").arg("-c").arg(&path).arg(&view).status().unwrap().success());
            let run = |args: &[&str], tool: &str, p: &std::path::Path| std::process::Command::new(tool).args(args).arg(p).output().unwrap();
            let dev = run(&["-n", "-W", "-s", "-M"], &fsck, &path);
            let host = run(&["-n", "-s", "-M"], "/sbin/fsck_apfs", &path);
            let (orphans, unnamed) = unencrypted_view(&view, blocks * 4096);
            let trees = run(&["-n", "-s"], "/sbin/fsck_apfs", &view);
            let _ = std::fs::remove_file(&view);
            let out = String::from_utf8_lossy(&trees.stdout).to_string() + &String::from_utf8_lossy(&trees.stderr);
            eprintln!("{tag}: view fsck (orphans {orphans:x?}):\n{out}");
            assert!(dev.status.success(), "{tag}: device fsck -M: {}{}", String::from_utf8_lossy(&dev.stdout), String::from_utf8_lossy(&dev.stderr));
            assert!(host.status.success(), "{tag}: host fsck -M: {}{}", String::from_utf8_lossy(&host.stdout), String::from_utf8_lossy(&host.stderr));
            assert!(!out.contains("skipping the fsroot tree"), "{tag}: {out}");
            let bad: Vec<&str> = out.lines().filter(|l| (l.contains("error") || l.contains("warning")) && !view_says(l, &unnamed)).collect();
            assert!(bad.is_empty(), "{tag}: {out}");
            assert_eq!(out.lines().filter(|l| l.starts_with("warning: overallocation detected")).count(), orphans.len(), "{tag}: {out}");
            assert!(out.contains("appears to be OK"), "{tag}: {out}");
        };
        check("mounted");
        fsops::unmount(&mut nx, data, false, &mut now).unwrap();
        fsops::unmount(&mut nx, system, false, &mut now).unwrap();
        nx.commit().unwrap();
        nx.unmount().unwrap();
        check("unmounted");
        let _ = std::fs::remove_file(&path);
    }

    /// fixup_var's copy of a small /private/var on System onto Data, with the
    /// moved tree's removal (GEX_TEST_FSCK, GEX_TEST_SCRATCH; drafts/s27/
    /// re-bomcopy.md, re-datawrite.md): a directory Data has left as it is
    /// and walked into; new directories with the source's owners, modes and
    /// times; plain files of class 3 (the volume's key: identifier 4, each
    /// extent its own block as tweak) written once or in three appends, a
    /// class-4 file (a per-file key, its record referenced per extent) of
    /// two blocks, an empty file; a compressed file with its decmpfs header
    /// and one with a resource fork stream; a symbolic link; the plain
    /// files' rename times held in memory; the moved tree's file unlinked
    /// and its directories removed from System. Then the device's and the
    /// host's fsck_apfs -M and the host's on the unencrypted view.
    #[test]
    fn var_copy_makes_data_as_the_kernel_makes_it() {
        let (Ok(dir), Ok(fsck)) = (std::env::var("GEX_TEST_SCRATCH"), std::env::var("GEX_TEST_FSCK")) else { return };
        let dir = std::path::Path::new(&dir);
        let path = dir.join(format!("gex-bom-{}", std::process::id()));
        let blocks = 15_625_000u64;
        let f = std::fs::OpenOptions::new().create(true).truncate(true).read(true).write(true).open(&path).unwrap();
        f.set_len(blocks * 4096).unwrap();
        let sink = super::super::HostFile(f, blocks * 4096);
        let uuid = *b"gex-bom-copy-001";
        let fm = container::format(&sink, 4096, blocks, uuid).unwrap();
        let mut nx = Nx::formatted(&sink, &fm, uuid, Mode::Kernel).unwrap();
        nx.mount_rw().unwrap();
        let clock = std::cell::Cell::new(1_700_000_000_000_000_000u64);
        let mut now = || {
            clock.set(clock.get() + 1000);
            clock.get()
        };
        let q = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let u = |b: &[u8], o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let kv = key_os_version(RESTORE_BUILD).unwrap();
        let make = |nx: &mut Nx<'_>, name: &str, role: u16, encrypted: bool, now: &mut dyn FnMut() -> u64| {
            let times = VolumeTimes { formatted: now(), root: now(), private: now(), modified: now() };
            let o = nx.create_volume(&NewVolume { name: name.into(), role, encrypted, e_apfs: true, times, uid: 0, gid: 0, key_os_version: kv, size_bytes: None }).unwrap();
            nx.commit().unwrap();
            nx.fs_oid.iter().position(|&x| x == o).unwrap()
        };
        let pattern = |n: usize, seed: u8| -> Vec<u8> { (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect() };
        // System's /private/var.
        let system = make(&mut nx, "System", storage::role::SYSTEM, false, &mut now);
        fsops::mount_rw(&mut nx, system, &mut now).unwrap();
        let s = system;
        let md = |nx: &mut Nx<'_>, parent: u64, name: &str, mode: u16, uid: u32, now: &mut dyn FnMut() -> u64| {
            let d = fsops::mkdir(nx, s, parent, name, mode, 0, 0, now).unwrap().unwrap();
            fsops::setattr(nx, s, d, fsops::SetAttr { uid: Some(uid), gid: Some(uid), ..Default::default() }, now).unwrap();
            d
        };
        let private = md(&mut nx, ROOT_INO, "private", 0o755, 0, &mut now);
        let var = md(&mut nx, private, "var", 0o755, 0, &mut now);
        let logs = md(&mut nx, var, "logs", 0o770, 0, &mut now);
        let a = fsops::write_new_file(&mut nx, s, logs, "a.log", 0o644, &pattern(5000, 1), &cluster_pushes, &mut now).unwrap();
        let mobile = md(&mut nx, var, "mobile", 0o711, 501, &mut now);
        let lib = md(&mut nx, mobile, "Library", 0o755, 501, &mut now);
        fsops::write_new_file(&mut nx, s, lib, "small.plist", 0o644, &pattern(300, 2), &cluster_pushes, &mut now).unwrap();
        fsops::create(&mut nx, s, lib, ".localized", 0o444, 0, 0, &mut now).unwrap().unwrap();
        let fwd = fsops::create(&mut nx, s, mobile, ".forward", 0o444, 0, 0, &mut now).unwrap().unwrap();
        let mut hdr9 = b"fpmc".to_vec();
        hdr9.extend_from_slice(&9u32.to_le_bytes());
        hdr9.extend_from_slice(&10u64.to_le_bytes());
        hdr9.extend_from_slice(b"\xcc/dev/null\n");
        fsops::set_decmpfs_xattr(&mut nx, s, fwd, &hdr9, &mut now).unwrap();
        fsops::cas_bsdflags(&mut nx, s, fwd, 0, 0x20, &mut now).unwrap();
        let db = md(&mut nx, var, "db", 0o755, 0, &mut now);
        let tz = md(&mut nx, db, "timezone", 0o755, 0, &mut now);
        let lt = fsops::symlink(&mut nx, s, tz, "localtime", "/var/db/timezone/zoneinfo/US/Pacific", 0o755, 0, 0, &mut now).unwrap().unwrap();
        let ssa = md(&mut nx, var, "staged_system_apps", 0o755, 501, &mut now);
        let app = md(&mut nx, ssa, "X.app", 0o755, 501, &mut now);
        let big = pattern(0x40000 + 100, 3);
        fsops::write_new_file(&mut nx, s, app, "big", 0o644, &pattern(1, 0), &cluster_pushes, &mut now).unwrap();
        // The appended file on System: its bytes through a stream of its own.
        let bigf = fsops::create(&mut nx, s, app, "Assets.car", 0o644, 0, 501, &mut now).unwrap().unwrap();
        fsops::write_appends(&mut nx, s, bigf, &[0x20000, 0x20000, 100], &big, 0x10_0000, 0x10_0000, &mut now).unwrap();
        let rf = fsops::create(&mut nx, s, app, "X", 0o755, 0, 501, &mut now).unwrap().unwrap();
        let fork = pattern(9000, 4);
        fsops::setxattr_rsrc_fork(&mut nx, s, rf, 0, &fork, &mut now).unwrap();
        let mut hdr4 = b"fpmc".to_vec();
        hdr4.extend_from_slice(&4u32.to_le_bytes());
        hdr4.extend_from_slice(&20000u64.to_le_bytes());
        fsops::set_decmpfs_xattr(&mut nx, s, rf, &hdr4, &mut now).unwrap();
        fsops::cas_bsdflags(&mut nx, s, rf, 0, 0x20, &mut now).unwrap();
        // Data, its /logs class D as aks_bootstrap_fs leaves it.
        let data = make(&mut nx, "Data", storage::role::DATA, true, &mut now);
        fsops::mount_rw(&mut nx, data, &mut now).unwrap();
        let dlogs = fsops::mkdir(&mut nx, data, ROOT_INO, "logs", 0o755, 0, 0, &mut now).unwrap().unwrap();
        fsops::set_dir_class(&mut nx, data, dlogs, 4, &mut now).unwrap();
        nx.commit().unwrap();
        let src = |nx: &mut Nx<'_>, ino: u64| fsops::inode(nx, s, ino).unwrap();
        let (sa, sfwd, slt, srf, sbig) = (src(&mut nx, a), src(&mut nx, fwd), src(&mut nx, lt), src(&mut nx, rf), src(&mut nx, bigf));
        let (smob, slib) = (src(&mut nx, mobile), src(&mut nx, lib));
        let dlogs_before = fsops::inode(&mut nx, data, dlogs).unwrap();
        fixup_var_copy(&mut nx, system, data, &mut now).unwrap();
        // System: the moved tree gone, the rest there.
        assert_eq!(fsops::lookup(&mut nx, s, var, "staged_system_apps").unwrap(), None);
        assert!(fsops::lookup(&mut nx, s, lib, "small.plist").unwrap().is_some());
        let walk = |nx: &mut Nx<'_>, p: &str| resolve(nx, data, p).unwrap().unwrap_or_else(|| panic!("no /mnt2/{p}"));
        let ino = |nx: &mut Nx<'_>, p: &str| {
            let i = walk(nx, p);
            fsops::inode(nx, data, i).unwrap()
        };
        let fext = |nx: &mut Nx<'_>, oid: u64| -> Vec<(u64, Vec<u8>)> {
            let (t, mut st) = nx.fs_tree(data).unwrap();
            t.records(&mut st).unwrap().into_iter().filter(|(k, _)| k.len() == 16 && q(k, 0) == (oid | 8 << 60)).map(|(k, v)| (q(&k, 8), v.unwrap())).collect()
        };
        let ds = |v: &[u8]| -> Vec<u8> { v[v.len() - 0x28..].to_vec() };
        let read = |nx: &mut Nx<'_>, oid: u64, size: usize| -> Vec<u8> {
            let mut out = Vec::new();
            for (_, v) in fext(nx, oid) {
                let mut b = vec![0u8; (q(&v, 0) & 0x00ff_ffff_ffff_ffff) as usize];
                if q(&v, 8) != 0 {
                    nx.read_data(q(&v, 8), &mut b).unwrap();
                }
                out.extend_from_slice(&b);
            }
            out.truncate(size);
            out
        };
        // The directory Data had: its own attributes kept; its child's
        // create and rename counted (children, write generation +2), the
        // rename's times held in memory.
        let dl = fsops::inode(&mut nx, data, dlogs).unwrap();
        assert_eq!((&dl[..0x18], &dl[0x28..0x38], &dl[0x3c..0x40], &dl[0x44..]), (&dlogs_before[..0x18], &dlogs_before[0x28..0x38], &dlogs_before[0x3c..0x40], &dlogs_before[0x44..]));
        assert_eq!((u(&dl, 0x38), u(&dl, 0x40)), (u(&dlogs_before, 0x38) + 1, u(&dlogs_before, 0x40) + 2));
        assert!(nx.jobj_times.contains_key(&(data, dlogs)));
        // New directories: the source's owner, mode and times, class 0
        // explicit under the root.
        let m = ino(&mut nx, "mobile");
        assert_eq!((u(&m, 0x48), u(&m, 0x4c), u16::from_le_bytes([m[0x50], m[0x51]]), u(&m, 0x3c), q(&m, 0x30)), (501, 501, 0o40711, 0, 0x8008));
        assert_eq!((q(&m, 0x18), q(&m, 0x28)), (q(&smob, 0x18), q(&smob, 0x28)));
        let l = ino(&mut nx, "mobile/Library");
        assert_eq!((q(&l, 0x18), q(&l, 0x28), u(&l, 0x38)), (q(&slib, 0x18), q(&slib, 0x28), 2));
        // A class-3 file written once: identifier 4, the block as tweak.
        let sp = ino(&mut nx, "mobile/Library/small.plist");
        assert_eq!((u(&sp, 0x3c), q(&sp, 0x30), q(&ds(&sp), 0), q(&ds(&sp), 0x10)), (3, 0x8000, 300, 4));
        let e = fext(&mut nx, q(&sp, 8));
        assert_eq!(e.len(), 1);
        assert_eq!((q(&e[0].1, 0), q(&e[0].1, 16)), (4096 | 1 << 56, q(&e[0].1, 8)));
        assert_eq!(read(&mut nx, q(&sp, 8), 300), pattern(300, 2));
        assert!(get_crypto(&mut nx, data, q(&sp, 8)).is_none());
        // Its rename's change time is held in memory, its times otherwise
        // the source's.
        let spi = walk(&mut nx, "mobile/Library/small.plist");
        assert_eq!(nx.jobj_times.get(&(data, spi)).map(|t| t.0), Some(q(&sp, 0x18)));
        let empty = ino(&mut nx, "mobile/Library/.localized");
        assert_eq!((u16::from_le_bytes([empty[0x50], empty[0x51]]), fsops::dstream_size(&empty).unwrap()), (0o100444, 0));
        // A class-4 file of two blocks: its own key, referenced per extent.
        let al = ino(&mut nx, "logs/a.log");
        assert_eq!((u(&al, 0x3c), q(&al, 0x30), q(&ds(&al), 0x10)), (4, 0x8008, q(&al, 8)));
        let e = fext(&mut nx, q(&al, 8));
        assert!(e.iter().all(|(_, v)| q(v, 16) == q(&al, 8) && q(v, 0) >> 56 == 0));
        assert_eq!(u(&get_crypto(&mut nx, data, q(&al, 8)).unwrap(), 0) as usize, 1 + e.len());
        assert_eq!(read(&mut nx, q(&al, 8), 5000), pattern(5000, 1));
        assert_eq!((q(&al, 0x18), u(&al, 0x48)), (q(&sa, 0x18), 0));
        // Three appends of class 3: pushed extents tweaked by their blocks.
        let bc = walk(&mut nx, "staged_system_apps/X.app/Assets.car");
        let b = fsops::inode(&mut nx, data, bc).unwrap();
        assert_eq!((q(&ds(&b), 0), q(&ds(&b), 0x10), q(&ds(&b), 0x18)), (big.len() as u64, 4, big.len() as u64));
        let e = fext(&mut nx, q(&b, 8));
        assert!(e.iter().all(|(_, v)| q(v, 8) == 0 || (q(v, 0) >> 56 == 1 && q(v, 16) == q(v, 8))));
        assert_eq!(read(&mut nx, q(&b, 8), big.len()), big);
        assert_eq!((q(&b, 0x18), u(&b, 0x40)), (q(&sbig, 0x18), u(&sbig, 0x40)));
        // The compressed files.
        let fw = ino(&mut nx, "mobile/.forward");
        assert_eq!((u(&fw, 0x44), q(&fw, 0x30), u(&fw, 0x3c), q(&fw, 0x54), q(&fw, 0x18)), (0x20, 0x4_8000, 3, 10, q(&sfwd, 0x18)));
        assert_eq!({
            let i = walk(&mut nx, "mobile/.forward");
            fsops::xattr_embedded(&mut nx, data, i, "com.apple.decmpfs")
        }.unwrap(), Some(hdr9.clone()));
        let xi = walk(&mut nx, "staged_system_apps/X.app/X");
        let x = fsops::inode(&mut nx, data, xi).unwrap();
        assert_eq!((u(&x, 0x44), q(&x, 0x30), q(&x, 0x54), u16::from_le_bytes([x[0x50], x[0x51]])), (0x20, 0x4_4000, 20000, u16::from_le_bytes([srf[0x50], srf[0x51]])));
        let r = fsops::xattr_record(&mut nx, data, xi, "com.apple.ResourceFork").unwrap().unwrap();
        assert_eq!((u16::from_le_bytes([r[0], r[1]]), u16::from_le_bytes([r[2], r[3]]), q(&r, 12), q(&r, 20), q(&r, 28), q(&r, 36)), (1, 0x30, 9000, 3 * 4096, 4, 9000));
        let e = fext(&mut nx, q(&r, 4));
        assert!(e.iter().all(|(_, v)| q(v, 0) >> 56 == 1 && q(v, 16) == q(v, 8)));
        assert_eq!(read(&mut nx, q(&r, 4), fork.len()), fork);
        // The link: class 0, the source's mode, its target.
        let lk = ino(&mut nx, "db/timezone/localtime");
        assert_eq!((u16::from_le_bytes([lk[0x50], lk[0x51]]), u(&lk, 0x3c), q(&lk, 0x30)), (u16::from_le_bytes([slt[0x50], slt[0x51]]), 0, 0x8000));
        assert_eq!({
            let i = walk(&mut nx, "db/timezone/localtime");
            fsops::xattr_embedded(&mut nx, data, i, "com.apple.fs.symlink")
        }.unwrap().unwrap(), b"/var/db/timezone/zoneinfo/US/Pacific\0".to_vec());
        // No temporary name left.
        let (t, mut st) = nx.fs_tree(data).unwrap();
        assert!(!t.records(&mut st).unwrap().iter().any(|(k, _)| q(k, 0) >> 60 == 9 && k.windows(6).any(|w| w == b".BC.T_" || w == b".BC.D_")));
        drop(st);
        let _ = sbig;
        nx.commit().unwrap();
        sink.0.sync_all().unwrap();
        let view = dir.join(format!("gex-bom-view-{}", std::process::id()));
        let _ = std::fs::remove_file(&view);
        assert!(std::process::Command::new("cp").arg("-c").arg(&path).arg(&view).status().unwrap().success());
        let run = |args: &[&str], tool: &str, p: &std::path::Path| std::process::Command::new(tool).args(args).arg(p).output().unwrap();
        let dev = run(&["-n", "-W", "-s", "-M"], &fsck, &path);
        let host = run(&["-n", "-s", "-M"], "/sbin/fsck_apfs", &path);
        let (orphans, unnamed) = unencrypted_view(&view, blocks * 4096);
        let trees = run(&["-n", "-s"], "/sbin/fsck_apfs", &view);
        let _ = std::fs::remove_file(&view);
        let _ = std::fs::remove_file(&path);
        let out = String::from_utf8_lossy(&trees.stdout).to_string() + &String::from_utf8_lossy(&trees.stderr);
        eprintln!("view fsck (orphans {orphans:x?}):\n{out}");
        assert!(dev.status.success(), "device fsck -M: {}{}", String::from_utf8_lossy(&dev.stdout), String::from_utf8_lossy(&dev.stderr));
        assert!(host.status.success(), "host fsck -M: {}{}", String::from_utf8_lossy(&host.stdout), String::from_utf8_lossy(&host.stderr));
        assert!(!out.contains("skipping the fsroot tree"), "{out}");
        let bad: Vec<&str> = out.lines().filter(|l| (l.contains("error") || l.contains("warning")) && !view_says(l, &unnamed)).collect();
        assert!(bad.is_empty(), "{out}");
        assert!(out.contains("appears to be OK"), "{out}");
    }

    /// A built disk0's container (GEX_TEST_DISK0_CTR: the container
    /// partition copied out of `gexc darwin-disk0`'s image) through the host's
    /// fsck_apfs on the unencrypted view, which checks the Data and User
    /// trees the -M runs skip.
    #[test]
    fn disk0_encrypted_trees_check_through_the_view() {
        let Ok(ctr) = std::env::var("GEX_TEST_DISK0_CTR") else { return };
        let ctr = std::path::Path::new(&ctr);
        let size = std::fs::metadata(ctr).unwrap().len();
        let view = ctr.with_extension(format!("view-{}", std::process::id()));
        let _ = std::fs::remove_file(&view);
        assert!(std::process::Command::new("cp").arg("-c").arg(ctr).arg(&view).status().unwrap().success());
        let (orphans, unnamed) = unencrypted_view(&view, size);
        let trees = std::process::Command::new("/sbin/fsck_apfs").args(["-n", "-s"]).arg(&view).output().unwrap();
        let _ = std::fs::remove_file(&view);
        let out = String::from_utf8_lossy(&trees.stdout).to_string() + &String::from_utf8_lossy(&trees.stderr);
        eprintln!("view fsck (orphans {orphans:x?}):\n{out}");
        assert!(!out.contains("skipping the fsroot tree"), "{out}");
        let bad: Vec<&str> = out.lines().filter(|l| (l.contains("error") || l.contains("warning")) && !view_says(l, &unnamed)).collect();
        assert!(bad.is_empty(), "{out}");
        assert_eq!(out.lines().filter(|l| l.starts_with("warning: overallocation detected")).count(), orphans.len(), "{out}");
        assert!(out.contains("appears to be OK"), "{out}");
    }

    /// A per-file key's crypto-state record on volume `vol`.
    fn get_crypto(nx: &mut Nx<'_>, vol: usize, id: u64) -> Option<Vec<u8>> {
        let (t, mut st) = nx.fs_tree(vol).unwrap();
        t.get(&mut st, &(id | 7 << 60).to_le_bytes()).unwrap()
    }

    /// Data's read-write mount and unmount on a container of its own
    /// (GEX_TEST_FSCK: the device's host-runnable fsck_apfs; scratch in
    /// GEX_TEST_SCRATCH): the clone epoch, the pfkur thread's temporary
    /// inode (drafts/s23: alloc_tmp_ino_helper's parameters) and the fixup
    /// thread's transaction at the mount, User's epoch only, the inode gone
    /// at Data's unmount; the device's and the host's fsck_apfs -M, and the
    /// host's on the unencrypted view, after each.
    #[test]
    fn data_mount_makes_and_unmount_removes_the_pfkur_inode() {
        let (Ok(dir), Ok(fsck)) = (std::env::var("GEX_TEST_SCRATCH"), std::env::var("GEX_TEST_FSCK")) else { return };
        let dir = std::path::Path::new(&dir);
        let path = dir.join(format!("gex-pfkur-{}", std::process::id()));
        let blocks = 15_625_000u64;
        let f = std::fs::OpenOptions::new().create(true).truncate(true).read(true).write(true).open(&path).unwrap();
        f.set_len(blocks * 4096).unwrap();
        let sink = super::super::HostFile(f, blocks * 4096);
        let uuid = *b"gex-pfkur-test-1";
        let fm = container::format(&sink, 4096, blocks, uuid).unwrap();
        let mut nx = Nx::formatted(&sink, &fm, uuid, Mode::Kernel).unwrap();
        nx.mount_rw().unwrap();
        let mut t = 1_700_000_000_000_000_000u64;
        let mut now = || {
            t += 1000;
            t
        };
        let q = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let kv = key_os_version(RESTORE_BUILD).unwrap();
        let make = |nx: &mut Nx<'_>, name: &str, role: u16, now: &mut dyn FnMut() -> u64| {
            let times = VolumeTimes { formatted: now(), root: now(), private: now(), modified: now() };
            nx.create_volume(&NewVolume { name: name.into(), role, encrypted: true, e_apfs: true, times, uid: 0, gid: 0, key_os_version: kv, size_bytes: None }).unwrap();
            nx.commit().unwrap();
        };
        make(&mut nx, "Data", 0x40, &mut now);
        fsops::mount_rw(&mut nx, 1, &mut now).unwrap();
        assert_eq!(nx.pfkur_tmp.get(&1), Some(&0x10));
        let sb = nx.vol_sb_read(1).unwrap().0.to_vec();
        assert_eq!((q(&sb, 0xb0), q(&sb, 0x3d8), q(&sb, 0xb8), q(&sb, 0x108)), (0x11, 0x10, 0, 0x100));
        assert_eq!(fsops::lookup(&mut nx, 1, 3, "tmp-ino-xattr-dstream-0x0-0x10").unwrap(), Some(0x10));
        make(&mut nx, "User", 0x2, &mut now);
        fsops::mount_rw(&mut nx, 2, &mut now).unwrap();
        assert!(!nx.pfkur_tmp.contains_key(&2));
        let sb = nx.vol_sb_read(2).unwrap().0.to_vec();
        assert_eq!((q(&sb, 0xb0), q(&sb, 0x3d8)), (0x10, 0x10));
        // UserManagementLayout's manifest on Data (drafts/s23/re-uml-data.md):
        // /keybags with the subdirectory count, the class-D file with its
        // per-file key record, the fsync, the rename, F_BARRIERFSYNC's commit.
        let keybags = fsops::mkdir(&mut nx, 1, 2, "keybags", 0o700, 0, 0, &mut now).unwrap().unwrap();
        let ino = fsops::create_protected(&mut nx, 1, keybags, "usersession.kb.writing", 0o644, 0, 4, &mut now).unwrap();
        let kb = usersession_kb();
        let w = fsops::write_new_protected(&mut nx, 1, ino, &kb, &mut now).unwrap();
        fsops::fsync_pending(&mut nx, 1, &w, &mut now).unwrap();
        let rt = fsops::rename_in_dir(&mut nx, 1, keybags, "usersession.kb.writing", "usersession.kb", ino, &mut now).unwrap();
        let xid = nx.xid;
        fsops::barrier_fsync(&mut nx, 1, ino, rt.file, &mut now).unwrap();
        assert_eq!(nx.xid, xid + 1, "F_BARRIERFSYNC's checkpoint");
        assert_eq!(nx.jobj_times.iter().map(|(&k, &v)| (k, v)).collect::<Vec<_>>(), vec![((1, keybags), rt.dir)], "/keybags' times stay in memory");
        {
            let (t, mut st) = nx.fs_tree(1).unwrap();
            let recs = t.records(&mut st).unwrap();
            let get = |k: u64| recs.iter().find(|(kk, _)| kk[..] == k.to_le_bytes()).unwrap().1.clone().unwrap();
            let root = get(2 | 3 << 60);
            assert_eq!((u32::from_le_bytes(root[0x38..0x3c].try_into().unwrap()), q(&root, 0x54)), (1, 1));
            let kd = get(keybags | 3 << 60);
            assert_eq!((q(&kd, 0x30), u32::from_le_bytes(kd[0x3c..0x40].try_into().unwrap()), u32::from_le_bytes(kd[0x40..0x44].try_into().unwrap()), kd.len()), (0x8008, 0, 3, 0x6c));
            let f = get(ino | 3 << 60);
            assert_eq!((q(&f, 0x30), u32::from_le_bytes(f[0x3c..0x40].try_into().unwrap()), u32::from_le_bytes(f[0x40..0x44].try_into().unwrap()), f.len()), (0x8008, 4, 2, 0xa0));
            assert_eq!((q(&f, 0x18), q(&f, 0x20)), rt.file);
            let cs = get(ino | 7 << 60);
            assert_eq!(&cs[..0x10], &[2, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0][..]);
            let ds = &f[f.len() - 0x28..];
            assert_eq!((q(ds, 0), q(ds, 8), q(ds, 0x10), q(ds, 0x18)), (kb.len() as u64, 4096, ino, kb.len() as u64));
        }
        // configure_data_volumes' keybag rewrites: the user protection of
        // Data's VEK and AKSVolumeMap's cookie on User, each committed.
        let (du, uu) = (nx.vol_sb_read(1).unwrap().0[0xf0..0x100].to_vec(), sb[0xf0..0x100].to_vec());
        let xid = nx.xid;
        nx.vek_set_protection(1).unwrap();
        assert_eq!(nx.xid, xid + 1, "the protection's checkpoint");
        nx.volume_payload_set(2, 0).unwrap();
        assert_eq!(nx.xid, xid + 2, "the payload's checkpoint");
        sink.0.sync_all().unwrap();
        assert_eq!(keybag_entries(&path, blocks * 4096), vec![(du.clone(), 2, 0x28), (du, 10, 0x28), (uu.clone(), 2, 0x28), (uu.clone(), 0xd, 0x28), (uu, 0xf8, 0x28)]);
        // reserve_overprov_space on Data (drafts/s21/re-overprov.md 4): the
        // file, its one contiguous unwritten extent of 156,250 blocks, the
        // commit, the trim's flag.
        let xid = nx.xid;
        let ino = fsops::reserve_overprov_space(&mut nx, 1, 64_000_000_000, true, &mut now).unwrap();
        assert_eq!(nx.xid, xid + 1, "F_FULLFSYNC's checkpoint");
        let (t, mut st) = nx.fs_tree(1).unwrap();
        let recs = t.records(&mut st).unwrap();
        let inode = recs.iter().find(|(k, _)| k[..] == (ino | 3 << 60).to_le_bytes()).unwrap().1.clone().unwrap();
        assert_eq!((q(&inode, 0x30), u32::from_le_bytes(inode[0x3c..0x40].try_into().unwrap()), u32::from_le_bytes(inode[0x40..0x44].try_into().unwrap())), (0x800_8800, 3, 2));
        let fext: Vec<_> = recs.iter().filter(|(k, _)| k.len() == 16 && q(k, 0) == (ino | 8 << 60)).map(|(_, v)| v.clone().unwrap()).collect();
        assert_eq!(fext.len(), 1);
        assert_eq!((q(&fext[0], 0), q(&fext[0], 16)), (0x0300_0000_2625_a000, q(&fext[0], 8)));
        let sb = nx.vol_sb_read(1).unwrap().0.to_vec();
        assert_eq!((q(&sb, 0xb8), q(&sb, 0xe0)), (2, 156_251));
        // fixup_var's aks_bootstrap_fs("/mnt2") (drafts/s26/re-aks-data.md): its
        // first entry, /keybags, written from its in-memory object with the
        // rename's times and class D; then the map's directories, owners,
        // modes and classes, and /root/.bootstrapped taking /root's class.
        let before = fsops::inode(&mut nx, 1, keybags).unwrap();
        let sb0 = nx.vol_sb_read(1).unwrap().0.to_vec();
        aks_bootstrap_fs(&mut nx, 1, &mut now).unwrap();
        assert!(nx.jobj_times.is_empty());
        let kd = fsops::inode(&mut nx, 1, keybags).unwrap();
        assert_eq!((q(&kd, 0x18), u32::from_le_bytes(kd[0x3c..0x40].try_into().unwrap()), q(&kd, 0x30)), (rt.dir.0, 4, 0x8008));
        assert!(q(&kd, 0x20) > rt.dir.1);
        assert_eq!((&kd[..0x18], &kd[0x28..0x3c], &kd[0x40..]), (&before[..0x18], &before[0x28..0x3c], &before[0x40..]));
        let sb = nx.vol_sb_read(1).unwrap().0.to_vec();
        assert_eq!((q(&sb, 0xb0) - q(&sb0, 0xb0), q(&sb, 0xc0) - q(&sb0, 0xc0), q(&sb, 0xb8) - q(&sb0, 0xb8)), (28, 27, 1));
        let walk = |nx: &mut Nx<'_>, p: &str| p.split('/').fold(2u64, |d, c| fsops::lookup(nx, 1, d, c).unwrap().unwrap_or_else(|| panic!("no {p}")));
        let attrs = |nx: &mut Nx<'_>, p: &str| {
            let ino = walk(nx, p);
            let v = fsops::inode(nx, 1, ino).unwrap();
            let u = |o: usize| u32::from_le_bytes(v[o..o + 4].try_into().unwrap());
            (u16::from_le_bytes([v[0x50], v[0x51]]), u(0x48), u(0x4c), u(0x3c), q(&v, 0x30))
        };
        assert_eq!(attrs(&mut nx, "tmp"), (0o41777, 0, 0, 4, 0x8008));
        assert_eq!(attrs(&mut nx, "Keychains"), (0o40755, 64, 0, 4, 0x8008));
        assert_eq!(attrs(&mut nx, "run"), (0o40775, 0, 1, 4, 0x8008));
        assert_eq!(attrs(&mut nx, "logs/BurnIn"), (0o40755, 0, 0, 4, 0x8008));
        assert_eq!(attrs(&mut nx, "containers"), (0o40755, 0, 0, 0, 0x8008));
        assert_eq!(attrs(&mut nx, "MobileDevice"), (0o40777, 0, 0, 0, 0x8008));
        assert_eq!(attrs(&mut nx, "MobileDevice/ProvisioningProfiles"), (0o40755, 0, 0, 4, 0x8008));
        assert_eq!(attrs(&mut nx, "Managed Preferences/mobile"), (0o40755, 501, 501, 4, 0x8008));
        assert_eq!(attrs(&mut nx, "root/Library/Caches"), (0o40700, 0, 0, 4, 0x8008));
        assert_eq!(attrs(&mut nx, "root/.bootstrapped"), (0o100644, 0, 0, 4, 0x8008));
        nx.commit().unwrap();
        let check = |tag: &str| {
            sink.0.sync_all().unwrap();
            let view = dir.join(format!("gex-pfkur-view-{}", std::process::id()));
            let _ = std::fs::remove_file(&view);
            assert!(std::process::Command::new("cp").arg("-c").arg(&path).arg(&view).status().unwrap().success());
            let run = |args: &[&str], tool: &str, p: &std::path::Path| std::process::Command::new(tool).args(args).arg(p).output().unwrap();
            let dev = run(&["-n", "-W", "-s", "-M"], &fsck, &path);
            let host = run(&["-n", "-s", "-M"], "/sbin/fsck_apfs", &path);
            let (orphans, unnamed) = unencrypted_view(&view, blocks * 4096);
            let trees = run(&["-n", "-s"], "/sbin/fsck_apfs", &view);
            let _ = std::fs::remove_file(&view);
            let out = String::from_utf8_lossy(&trees.stdout).to_string() + &String::from_utf8_lossy(&trees.stderr);
            eprintln!("{tag}: view fsck (orphans {orphans:x?}):\n{out}");
            assert!(dev.status.success(), "{tag}: device fsck -M: {}{}", String::from_utf8_lossy(&dev.stdout), String::from_utf8_lossy(&dev.stderr));
            assert!(host.status.success(), "{tag}: host fsck -M: {}{}", String::from_utf8_lossy(&host.stdout), String::from_utf8_lossy(&host.stderr));
            assert!(!out.contains("skipping the fsroot tree"), "{tag}: {out}");
            let bad: Vec<&str> = out.lines().filter(|l| (l.contains("error") || l.contains("warning")) && !view_says(l, &unnamed)).collect();
            assert!(bad.is_empty(), "{tag}: {out}");
            assert_eq!(out.lines().filter(|l| l.starts_with("warning: overallocation detected")).count(), orphans.len(), "{tag}: {out}");
            assert!(out.contains("appears to be OK"), "{tag}: {out}");
        };
        check("mounted");
        fsops::unmount(&mut nx, 1, false, &mut now).unwrap();
        assert!(nx.pfkur_tmp.is_empty());
        assert_eq!(fsops::lookup(&mut nx, 1, 3, "tmp-ino-xattr-dstream-0x0-0x10").unwrap(), None);
        let (t, mut st) = nx.fs_tree(1).unwrap();
        let priv_dir = t.get(&mut st, &(3u64 | 3 << 60).to_le_bytes()).unwrap().unwrap();
        assert_eq!((u32::from_le_bytes(priv_dir[0x38..0x3c].try_into().unwrap()), u32::from_le_bytes(priv_dir[0x40..0x44].try_into().unwrap())), (0, 3));
        nx.commit().unwrap();
        nx.unmount().unwrap();
        check("unmounted");
        let _ = std::fs::remove_file(&path);
    }

    /// The checkpoint descriptor block `i`'s address in the container file.
    fn c_desc(ctr: &std::path::Path, psize: u64, i: u64) -> u64 {
        use crate::darwin::apfsread::Container;
        let c = Container::open(std::sync::Arc::new(super::super::HostFile(std::fs::File::open(ctr).unwrap(), psize))).unwrap();
        c.nx.xp_desc_base + i
    }

    #[test]
    fn cluster_pushes_follow_the_cluster_layer() {
        // drafts/s26/re-cluster.md 2's table for 1 MiB clusters and maps.
        let p = cluster_pushes(16_243_000).unwrap();
        let mut want: Vec<(u64, u64)> = (0..15).map(|k| (k << 20, 1 << 20)).collect();
        want.push((15_728_640, 516_096));
        assert_eq!((p.maps, p.before_end), (want, 12));
        let p = cluster_pushes(600_000).unwrap();
        assert_eq!((p.maps, p.before_end), (vec![(0, 602_112)], 0));
    }

    /// install_kernel_cache's two paths on a fresh Preboot-role volume: a
    /// direct multi-block file and two deferred ones (one block map, and
    /// write-behind with sixteen), their final inodes, extents and the
    /// container's consistency.
    #[test]
    fn new_files_are_written_as_the_kernel_writes_them() {
        let (Ok(dir), Ok(fsck)) = (std::env::var("GEX_TEST_SCRATCH"), std::env::var("GEX_TEST_FSCK")) else { return };
        let dir = std::path::Path::new(&dir);
        let path = dir.join(format!("gex-nf-{}", std::process::id()));
        let blocks = 15_625_000u64;
        let f = std::fs::OpenOptions::new().create(true).truncate(true).read(true).write(true).open(&path).unwrap();
        f.set_len(blocks * 4096).unwrap();
        let sink = super::super::HostFile(f, blocks * 4096);
        let uuid = *b"gex-newfile-test";
        let fm = container::format(&sink, 4096, blocks, uuid).unwrap();
        let mut nx = Nx::formatted(&sink, &fm, uuid, Mode::Kernel).unwrap();
        nx.mount_rw().unwrap();
        let mut t = 1_700_000_000_000_000_000u64;
        let mut now = || {
            t += 1000;
            t
        };
        let q = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let kv = key_os_version(RESTORE_BUILD).unwrap();
        let times = VolumeTimes { formatted: now(), root: now(), private: now(), modified: now() };
        let o = nx.create_volume(&NewVolume { name: "Preboot".into(), role: storage::role::PREBOOT, encrypted: false, e_apfs: true, times, uid: 0, gid: 0, key_os_version: kv, size_bytes: None }).unwrap();
        nx.commit().unwrap();
        let vol = nx.fs_oid.iter().position(|&x| x == o).unwrap();
        fsops::mount_rw(&mut nx, vol, &mut now).unwrap();
        let data = |n: usize| (0..n).map(|i| (i * 7 + i / 4096) as u8).collect::<Vec<u8>>();
        for (name, n) in [("direct", 35_276usize), ("one", 600_000), ("many", 16_243_000)] {
            let d = data(n);
            let ino = fsops::write_new_file(&mut nx, vol, ROOT_INO, name, 0o644, &d, &cluster_pushes, &mut now).unwrap();
            let v = fsops::inode(&mut nx, vol, ino).unwrap();
            // NAME and DSTREAM only: no SPARSE_BYTES or PREV_FSIZE left.
            assert_eq!((q(&v, 0x30), u32::from_le_bytes(v[0x40..0x44].try_into().unwrap()), u16::from_le_bytes([v[0x5c], v[0x5d]])), (0x9000, 2, 2), "{name}");
            let ds = &v[v.len() - 0x28..];
            let alloced = (n as u64).div_ceil(4096) * 4096;
            assert_eq!((q(ds, 0), q(ds, 8), q(ds, 0x18)), (n as u64, alloced, n as u64), "{name}");
            assert_eq!(q(&v, 0x18), q(&v, 0x20), "{name}: mod = change");
            // The extents cover the file and hold its bytes.
            let (tr, mut st) = nx.fs_tree(vol).unwrap();
            let ext: Vec<(u64, u64, u64)> = tr.records(&mut st).unwrap().into_iter().filter(|(k, _)| k.len() == 16 && q(k, 0) == (ino | 8 << 60)).map(|(k, v)| (q(&k, 8), q(v.as_ref().unwrap(), 0) & 0x00ff_ffff_ffff_ffff, q(v.as_ref().unwrap(), 8))).collect();
            drop(st);
            assert_eq!(ext.iter().map(|e| e.1).sum::<u64>(), alloced, "{name}");
            let mut back = Vec::new();
            for (l, len, p) in ext {
                assert_eq!(l, back.len() as u64);
                assert_ne!(p, 0, "{name}: a sparse extent left");
                let mut b = vec![0u8; len as usize];
                std::os::unix::fs::FileExt::read_exact_at(&sink.0, &mut b, p * 4096).unwrap();
                back.extend_from_slice(&b);
            }
            assert_eq!(&back[..n], &d[..], "{name}");
            assert!(back[n..].iter().all(|&b| b == 0));
        }
        nx.commit().unwrap();
        nx.unmount().unwrap();
        sink.0.sync_all().unwrap();
        let dev = std::process::Command::new(&fsck).args(["-n", "-W", "-s"]).arg(&path).output().unwrap();
        let host = std::process::Command::new("/sbin/fsck_apfs").args(["-n", "-s"]).arg(&path).output().unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(dev.status.success(), "device fsck: {}{}", String::from_utf8_lossy(&dev.stdout), String::from_utf8_lossy(&dev.stderr));
        assert!(host.status.success(), "host fsck: {}{}", String::from_utf8_lossy(&host.stdout), String::from_utf8_lossy(&host.stderr));
    }

    /// The gigalocker file's close-time zero fill (drafts/s27/re-zerofill.md)
    /// on a fresh xART-role volume: with 1 MiB block maps the first adds a
    /// PREV_FSIZE field and the close's fsync removes it, two file-system
    /// transactions (two clock readings, the last the volume's last
    /// modification); one 6 MiB block map changes nothing; the inode and
    /// records end as the truncate left them, the blocks zeroed; the
    /// device's and the host's fsck.
    #[test]
    fn gigalocker_zero_fill_follows_its_block_maps() {
        let (Ok(dir), Ok(fsck)) = (std::env::var("GEX_TEST_SCRATCH"), std::env::var("GEX_TEST_FSCK")) else { return };
        let dir = std::path::Path::new(&dir);
        for (c, m, reads) in [(1u64 << 20, 1u64 << 20, 2u64), (6 << 20, 6 << 20, 0)] {
            let path = dir.join(format!("gex-gl-{}-{m}", std::process::id()));
            let blocks = 15_625_000u64;
            let f = std::fs::OpenOptions::new().create(true).truncate(true).read(true).write(true).open(&path).unwrap();
            f.set_len(blocks * 4096).unwrap();
            let sink = super::super::HostFile(f, blocks * 4096);
            let uuid = *b"gex-gigalocker-t";
            let fm = container::format(&sink, 4096, blocks, uuid).unwrap();
            let mut nx = Nx::formatted(&sink, &fm, uuid, Mode::Kernel).unwrap();
            nx.mount_rw().unwrap();
            let clock = std::cell::Cell::new(1_700_000_000_000_000_000u64);
            let mut now = || {
                clock.set(clock.get() + 1000);
                clock.get()
            };
            let q = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
            let kv = key_os_version(RESTORE_BUILD).unwrap();
            let times = VolumeTimes { formatted: now(), root: now(), private: now(), modified: now() };
            let o = nx.create_volume(&NewVolume { name: "xART".into(), role: storage::role::XART, encrypted: false, e_apfs: true, times, uid: 0, gid: 0, key_os_version: kv, size_bytes: Some(10_485_760) }).unwrap();
            nx.commit().unwrap();
            let vol = nx.fs_oid.iter().position(|&x| x == o).unwrap();
            fsops::mount_rw(&mut nx, vol, &mut now).unwrap();
            let ino = fsops::create(&mut nx, vol, ROOT_INO, "gl", 0o600, 0, 0, &mut now).unwrap().unwrap();
            assert_eq!(fsops::preallocate(&mut nx, vol, ino, 0x60_0000, &mut now).unwrap(), 0x60_0000);
            fsops::truncate_grow(&mut nx, vol, ino, 0x60_0000, &mut now).unwrap();
            let before = fsops::inode(&mut nx, vol, ino).unwrap();
            let recs_before = { let (t, mut st) = nx.fs_tree(vol).unwrap(); t.records(&mut st).unwrap() };
            let lm_before = q(nx.vol_sb(vol).unwrap(), 0x100);
            let t0 = clock.get();
            fsops::close_after_grow(&mut nx, vol, ino, c, m, &mut now).unwrap();
            assert_eq!((clock.get() - t0) / 1000, reads, "clock readings of the close (m {m})");
            let lm = q(nx.vol_sb(vol).unwrap(), 0x100);
            assert_eq!(lm, if reads == 0 { lm_before } else { clock.get() });
            assert_eq!(fsops::inode(&mut nx, vol, ino).unwrap(), before);
            let recs_after = { let (t, mut st) = nx.fs_tree(vol).unwrap(); t.records(&mut st).unwrap() };
            assert!(recs_after == recs_before);
            let ext: Vec<(u64, u64)> = recs_after.iter().filter(|(k, _)| k.len() == 16 && q(k, 0) == (ino | 8 << 60)).map(|(_, v)| (q(v.as_ref().unwrap(), 0) & 0x00ff_ffff_ffff_ffff, q(v.as_ref().unwrap(), 8))).collect();
            assert_eq!(ext.len(), 1);
            let mut b = vec![0xffu8; 0x60_0000];
            std::os::unix::fs::FileExt::read_exact_at(&sink.0, &mut b, ext[0].1 * 4096).unwrap();
            assert!(b.iter().all(|&x| x == 0));
            nx.commit().unwrap();
            nx.unmount().unwrap();
            sink.0.sync_all().unwrap();
            let dev = std::process::Command::new(&fsck).args(["-n", "-W", "-s"]).arg(&path).output().unwrap();
            let host = std::process::Command::new("/sbin/fsck_apfs").args(["-n", "-s"]).arg(&path).output().unwrap();
            let _ = std::fs::remove_file(&path);
            assert!(dev.status.success(), "device fsck: {}{}", String::from_utf8_lossy(&dev.stdout), String::from_utf8_lossy(&dev.stderr));
            assert!(host.status.success(), "host fsck: {}{}", String::from_utf8_lossy(&host.stdout), String::from_utf8_lossy(&host.stderr));
        }
    }

    #[test]
    fn stdio_turns_host_chunks_into_writes() {
        assert_eq!(stdio_writes(229, 8192).unwrap(), vec![229]);
        assert_eq!(stdio_writes(3 * 8192, 8192).unwrap(), vec![8192; 3]);
        assert_eq!(stdio_writes(2 * 8192 + 5000, 8192).unwrap(), vec![8192, 8192, 4096, 904]);
        assert!(stdio_writes(3 * 5000, 5000).is_err(), "a partly filled buffer before the next fwrite");
    }

    /// install_splat's kernel paths on a fresh Preboot-role volume
    /// (drafts/s27/re-splat.md 4): a file appended to in 8 KiB writes with no
    /// grow-ahead (the clock barely moving) and one whose clock passes a
    /// second after its creation (grow-ahead's hole left past the pushed
    /// end), the copyfile of a small plain file into its preallocation, a
    /// rename and the close's time write; the records and the device's and
    /// host's fsck.
    #[test]
    fn splat_files_are_written_as_the_kernel_writes_them() {
        let (Ok(dir), Ok(fsck)) = (std::env::var("GEX_TEST_SCRATCH"), std::env::var("GEX_TEST_FSCK")) else { return };
        let dir = std::path::Path::new(&dir);
        let path = dir.join(format!("gex-splat-{}", std::process::id()));
        let blocks = 15_625_000u64;
        let f = std::fs::OpenOptions::new().create(true).truncate(true).read(true).write(true).open(&path).unwrap();
        f.set_len(blocks * 4096).unwrap();
        let sink = super::super::HostFile(f, blocks * 4096);
        let uuid = *b"gex-splat-tests!";
        let fm = container::format(&sink, 4096, blocks, uuid).unwrap();
        let mut nx = Nx::formatted(&sink, &fm, uuid, Mode::Kernel).unwrap();
        nx.mount_rw().unwrap();
        let step = std::cell::Cell::new(1000u64);
        let clock = std::cell::Cell::new(1_700_000_000_000_000_000u64);
        let mut now = || {
            clock.set(clock.get() + step.get());
            clock.get()
        };
        let q = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let kv = key_os_version(RESTORE_BUILD).unwrap();
        let times = VolumeTimes { formatted: now(), root: now(), private: now(), modified: now() };
        let o = nx.create_volume(&NewVolume { name: "Preboot".into(), role: storage::role::PREBOOT, encrypted: false, e_apfs: true, times, uid: 0, gid: 0, key_os_version: kv, size_bytes: None }).unwrap();
        nx.commit().unwrap();
        let vol = nx.fs_oid.iter().position(|&x| x == o).unwrap();
        fsops::mount_rw(&mut nx, vol, &mut now).unwrap();
        let (c, m) = (1u64 << 20, 1u64 << 20);
        // An inode's extended field of type `t`.
        let xf = |v: &[u8], t: u8| -> Option<Vec<u8>> {
            let n = u16::from_le_bytes([v[0x5c], v[0x5d]]) as usize;
            let mut off = 0x60 + 4 * n;
            for i in 0..n {
                let len = u16::from_le_bytes([v[0x60 + 4 * i + 2], v[0x60 + 4 * i + 3]]) as usize;
                if v[0x60 + 4 * i] == t {
                    return Some(v[off..off + len].to_vec());
                }
                off += (len + 7) & !7;
            }
            None
        };
        let extents = |nx: &mut Nx<'_>, ino: u64| -> Vec<(u64, u64, u64)> {
            let (tr, mut st) = nx.fs_tree(vol).unwrap();
            tr.records(&mut st).unwrap().into_iter().filter(|(k, _)| k.len() == 16 && q(k, 0) == (ino | 8 << 60)).map(|(k, v)| (q(&k, 8), q(v.as_ref().unwrap(), 0) & 0x00ff_ffff_ffff_ffff, q(v.as_ref().unwrap(), 8))).collect()
        };
        for (name, n, tick) in [("steady", 6u64 << 20, 1000u64), ("grows", 6 << 20, 3_000_000)] {
            let data: Vec<u8> = (0..n as usize).map(|i| (i * 13 + i / 4096) as u8).collect();
            step.set(1000);
            let ino = fsops::create(&mut nx, vol, ROOT_INO, name, 0o666, 0, 0, &mut now).unwrap().unwrap();
            step.set(tick);
            let writes = stdio_writes(n, 8192).unwrap();
            fsops::write_appends(&mut nx, vol, ino, &writes, &data, c, m, &mut now).unwrap();
            let v = fsops::inode(&mut nx, vol, ino).unwrap();
            let ds = &xf(&v, 8).unwrap()[..];
            assert_eq!((q(ds, 0), q(ds, 0x18)), (n, n), "{name}");
            assert!(xf(&v, 5).is_none(), "{name}: PREV_FSIZE removed");
            assert_eq!(u32::from_le_bytes(v[0x40..0x44].try_into().unwrap()), 1 + writes.len() as u32, "{name}: a write generation per write");
            let ext = extents(&mut nx, ino);
            let mut back = Vec::new();
            for &(l, len, p) in &ext {
                assert_eq!(l, back.len() as u64, "{name}");
                if p == 0 {
                    assert_eq!(l, n, "{name}: the only hole is past the pushed end");
                    back.resize((l + len) as usize, 0);
                    continue;
                }
                let mut b = vec![0u8; len as usize];
                std::os::unix::fs::FileExt::read_exact_at(&sink.0, &mut b, p * 4096).unwrap();
                back.extend_from_slice(&b);
            }
            assert_eq!(&back[..n as usize], &data[..], "{name}");
            let hole = ext.iter().find(|e| e.2 == 0).map(|e| e.1);
            assert_eq!(q(ds, 8), n + hole.unwrap_or(0), "{name}: allocated size");
            assert_eq!(q(&v, 0x30), if hole.is_some() { 0x9200 } else { 0x9000 }, "{name}: internal flags");
            assert_eq!(xf(&v, 0xd).map(|b| q(&b, 0)), hole, "{name}: the hole's sparse bytes");
            assert_eq!(hole.is_some(), tick > 1000, "{name}: grow-ahead only after a second");
        }
        // A copyfile of a 574-byte plain file.
        step.set(1000);
        let small: Vec<u8> = (0..574).map(|i| i as u8).collect();
        let f = fsops::create(&mut nx, vol, ROOT_INO, "SystemVersion.plist", 0o644, 0, 0, &mut now).unwrap().unwrap();
        assert_eq!(fsops::preallocate(&mut nx, vol, f, 574, &mut now).unwrap(), 4096);
        let (_, written) = fsops::write_into_preallocation(&mut nx, vol, f, &small, &mut now).unwrap();
        fsops::truncate_equal(&mut nx, vol, f, written, &mut now).unwrap();
        fsops::setattr(&mut nx, vol, f, fsops::SetAttr { mode: Some(0o444), uid: Some(0), gid: Some(0), ..Default::default() }, &mut now).unwrap();
        fsops::setattr(&mut nx, vol, f, fsops::SetAttr { mtime: Some(1_777_573_253_000_000_000), atime: Some(1_777_573_253_000_000_000), ..Default::default() }, &mut now).unwrap();
        fsops::cas_bsdflags(&mut nx, vol, f, 0, 0, &mut now).unwrap();
        fsops::close_pushed(&mut nx, vol, f, &small, &mut now).unwrap();
        let v = fsops::inode(&mut nx, vol, f).unwrap();
        let ds = &v[v.len() - 0x28..];
        assert_eq!((q(ds, 0), q(ds, 8), q(ds, 0x18), u32::from_le_bytes(v[0x40..0x44].try_into().unwrap()), u16::from_le_bytes([v[0x5c], v[0x5d]])), (574, 4096, 574, 2, 2));
        assert_eq!(q(&v, 0x18), 1_777_573_253_000_000_000);
        let ext = extents(&mut nx, f);
        let mut b = vec![0u8; 4096];
        std::os::unix::fs::FileExt::read_exact_at(&sink.0, &mut b, ext[0].2 * 4096).unwrap();
        assert_eq!(&b[..574], &small[..]);
        assert!(b[574..].iter().all(|&x| x == 0));
        // The ticket's temporary file renamed, then its close.
        let t = fsops::write_new_file(&mut nx, vol, ROOT_INO, SPLAT_TICKET_TEMP, 0o666, &SPLAT_TICKET, &cluster_pushes, &mut now).unwrap();
        let rt = fsops::rename_in_dir(&mut nx, vol, ROOT_INO, SPLAT_TICKET_TEMP, "apticket.j120ap.0.im4m", t, &mut now).unwrap();
        fsops::write_times(&mut nx, vol, t, rt.file, &mut now).unwrap();
        assert_eq!(fsops::lookup(&mut nx, vol, ROOT_INO, "apticket.j120ap.0.im4m").unwrap(), Some(t));
        assert_eq!(q(&fsops::inode(&mut nx, vol, t).unwrap(), 0x20), rt.file.1);
        nx.jobj_times.remove(&(vol, ROOT_INO));
        nx.commit().unwrap();
        nx.unmount().unwrap();
        sink.0.sync_all().unwrap();
        let dev = std::process::Command::new(&fsck).args(["-n", "-W", "-s"]).arg(&path).output().unwrap();
        let host = std::process::Command::new("/sbin/fsck_apfs").args(["-n", "-s"]).arg(&path).output().unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(dev.status.success(), "device fsck: {}{}", String::from_utf8_lossy(&dev.stdout), String::from_utf8_lossy(&dev.stderr));
        assert!(host.status.success(), "host fsck: {}{}", String::from_utf8_lossy(&host.stdout), String::from_utf8_lossy(&host.stderr));
    }

    #[test]
    fn os_version_encoding() {
        assert_eq!(key_os_version("21H461"), Ok(0x1548_01cd));
    }
}
