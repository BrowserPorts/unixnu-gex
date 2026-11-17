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
pub const RUN_STAND_IN: &str = "the erase restore's clock readings, transaction grouping and the order its concurrent writers reach the kernel on disk0 (stand-in: the clock of the machine building the image; each call joining the open transaction until a sync, an unmount, a volume creation or a volume rename commits it; asr's thread mounting System first, then restored_external's main-thread steps from init_gigalocker to commit_sep_os all reaching the kernel before asr's first call, then asr's file, its size and its four writer threads' pwrites in step order; the kernel's container unmounted (its last transaction committed, block 0 written) after the unmounts of everything and before apfs_invert opens the device, and the kernel's apfs_reaper thread, started by its next mount of the container, running to its end before anything else reaches the container; measure the device's disk0 after its erase restore)";

/// Every stand-in the build takes, for the caller to report: the image
/// is the device's only where these are.
pub fn stand_ins(os: bool) -> Vec<&'static str> {
    let mut v = vec![RUN_STAND_IN, HOST_UUID_STAND_IN, GIGALOCKER_STAND_IN, fsops::UNWRITTEN_STAND_IN, NSIH_STAND_IN];
    if os {
        v.push(fsops::FILE_INODE_STAND_IN);
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
    let add = |nx: &mut Nx<'_>, name: &str, role: u16, size_bytes: Option<u64>, now: &mut dyn FnMut() -> u64| -> Result<u64, String> {
        let formatted = now();
        let root = now();
        let private = now();
        let modified = now();
        let v = NewVolume { name: name.into(), role, encrypted: false, e_apfs: true, times: VolumeTimes { formatted, root, private, modified }, uid: 0, gid: 0, key_os_version: kv, size_bytes };
        let oid = nx.create_volume(&v)?;
        nx.commit()?;
        Ok(oid)
    };
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
    fsops::unmount(&mut nx, update, now)?;
    if !before_asr(&mut nx)? {
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
        fsops::unmount(&mut nx, v, now)?;
    }
    // The container handed to apfs_invert: the kernel's last transaction
    // committed and block 0 written (a stand-in, in RUN_STAND_IN), then the
    // tool's own mount.
    nx.unmount()?;
    if let Some(_os) = os {
        before_invert()?;
        let barrier = barrier.unwrap_or_else(crate::darwin::storagestack::container_barrier);
        super::invert::invert(&mut nx, system, super::asr::IMAGE_NAME, std::sync::Arc::clone(&disk), base, barrier, now)?;
        if !after_invert(&mut nx)? {
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
        missing.push("the System volume after apfs_invert and the reaping of its old trees: (once Data and User exist) the data-volume trees' removal (restored_external's fixup_var), /private/xarts, apfs_sealvolume to the signed root hash, and the com.apple.os.update- snapshot".into());
    }
    // 6.
    missing.push("the Data and User volumes (newfs_apfs -P: encrypted with keys the device's Secure Enclave makes)".into());
    // 7.
    missing.push("the restore's later writes to Preboot (install_kernel_cache's boot objects, populate_preboot_volume, install_splat's cryptex1) and Data's contents".into());
    // The kernel's own counting of the checksums it sets (its kext has
    // sites newfs_apfs's copy does not) and whether its read-write mount's
    // block-0 write has the newest mounting version are not traced.
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
        fsops::chmod(nx, update, ino, mode)?;
        fsops::chown(nx, update, ino, uid, gid, now)?;
    }
    Ok(())
}

/// `_ramrod_create_directory(path, mode, uid, gid)` (0x100047aa4 →
/// 0x100047828, class -1) on volume `vol` for `path` below its root: each
/// component `lstat`ed, and one that does not exist made (mkdir with
/// `mode & 0777`, chmod to `mode`, chown to the ids); an existing one is
/// left as it is. The last component's inode number.
fn create_directory(nx: &mut Nx<'_>, vol: usize, path: &str, mode: u16, uid: u32, gid: u32, now: &mut dyn FnMut() -> u64) -> Result<u64, String> {
    let mut dir = ROOT_INO;
    for name in path.split('/') {
        dir = match fsops::lookup(nx, vol, dir, name)? {
            Some(ino) => ino,
            None => {
                let ino = fsops::mkdir(nx, vol, dir, name, mode & 0o777, 0, 0, now)?.map_err(|e| format!("mkdir {path}: errno {e}"))?;
                fsops::chmod(nx, vol, ino, mode)?;
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
    fsops::unmount(nx, v.update, now)?;
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
    fsops::write_new_file(nx, v.preboot, ROOT_INO, "active", 0o644, p.as_bytes(), now)?;
    // fdr_prepare's removefile walk of the empty factorydata directory and
    // the access() checks of the later steps only read.
    missing.push("the FDR local store on Hardware (libFDR's writes into /FactoryData/System/Library/Caches/com.apple.factorydata by fdr_prepare's commit, fdr_recover, fdr_auto_challenge_claim and verify_fdr_data: server and device data, file names not traced)".into());
    missing.push("install_fud's firmware on Preboot (<nsih>/usr/standalone/firmware/FUD and the host's personalized images in it, AOP, AVE and StaticTrustCache for the erase identity)".into());
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
/// the range; then the Secure Enclave call (selector 0x2c) opens the file
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
    fsops::close_after_grow(nx, xart, ino)
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
            assert_eq!(vol.sb.uuid, storage::volume_uuid(v));
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
        let os = OsImage { image: std::sync::Arc::clone(&image), partition };
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
        let os = OsImage { image: std::sync::Arc::clone(&image), partition };
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
        let os = OsImage { image: std::sync::Arc::clone(&image), partition };
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
        let os = OsImage { image: std::sync::Arc::clone(&image), partition };
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

    #[test]
    fn os_version_encoding() {
        assert_eq!(key_os_version("21H461"), Ok(0x1548_01cd));
    }
}
