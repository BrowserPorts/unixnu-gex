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
pub const RUN_STAND_IN: &str = "the erase restore's clock readings, transaction grouping and the order its concurrent writers reach the kernel on disk0 (stand-in: the clock of the machine building the image; each call joining the open transaction until a sync, an unmount, a volume creation or a volume rename commits it; asr's thread mounting System first, then restored_external's main-thread steps from init_gigalocker to commit_sep_os all reaching the kernel before asr's first call, then asr's file, its size and its four writer threads' pwrites in step order; the kernel's container unmounted (its last transaction committed, block 0 written) after the unmounts of everything and before apfs_invert opens the device, and the kernel's apfs_reaper thread, started by its next mount of the container, running to its end before anything else reaches the container; the threads Data's read-write mount starts making their writes in the order the mount starts them, the pfkur thread's temporary inode then the fixup thread's transaction, both before User's volumeCreate; measure the device's disk0 after its erase restore)";

/// Every stand-in the build takes, for the caller to report: the image
/// is the device's only where these are.
pub fn stand_ins(os: bool) -> Vec<&'static str> {
    let mut v = vec![RUN_STAND_IN, HOST_UUID_STAND_IN, GIGALOCKER_STAND_IN, fsops::UNWRITTEN_STAND_IN, NSIH_STAND_IN];
    if os {
        v.push(fsops::FILE_INODE_STAND_IN);
        v.push(super::tx::KEYS_STAND_IN);
        v.push(fsops::PER_FILE_KEY_STAND_IN);
        v.push(USERSESSION_STAND_IN);
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
        fsops::unmount(&mut nx, v, true, now)?;
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
        configure_data_volumes(&mut nx, system, data, user, now, &mut missing)?;
        missing.push("the System volume after apfs_invert and the reaping of its old trees: (once Data and User exist) the data-volume trees' removal (restored_external's fixup_var), /private/xarts, apfs_sealvolume to the signed root hash, and the com.apple.os.update- snapshot".into());
    }
    if os.is_none() {
        missing.push("the Data and User volumes (newfs_apfs -P), made after apfs_invert".into());
    }
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
    fsops::write_new_file(nx, v.preboot, ROOT_INO, "active", 0o644, p.as_bytes(), now)?;
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
/// AKSVolumeMap's cookie on User (2.5), each with its checkpoint; the
/// template's copy onto User (2.4) is not implemented and is returned as
/// missing.
fn configure_data_volumes(nx: &mut Nx<'_>, system: usize, data: usize, user: usize, now: &mut dyn FnMut() -> u64, missing: &mut Missing) -> Result<(), String> {
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
    aks_bootstrap_user_fs(nx, user, now)?;
    missing.push(format!("Data's /keybags times the rename left in memory (mod and change {}: written at that inode's next write or a sync pass, drafts/s23/re-uml-data.md UNSETTLED-5)", rt.dir.0));
    Ok(())
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

    /// The encrypted Data and User volumes after the invert (GEX_TEST_UDIF,
    /// GEX_TEST_SCRATCH, GEX_TEST_FSCK): Data's superblock as the kernel's
    /// volumeCreate and read-write mount leave it (drafts/s16/re-protected.md
    /// 2.1, drafts/s21/re-data.md 1), the pfkur thread's temporary inode,
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
        let os = OsImage { image: std::sync::Arc::clone(&image), partition };
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
        assert_eq!((q(&sb, 0x28), q(&sb, 0x30), q(&sb, 0x38), q(&sb, 0x108), q(&sb, 0x58)), (2, 0xc, 0x2c8, 0x100, 7));
        assert_eq!(&sb[0x60..0x74], &[5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0xcd, 0x01, 0x48, 0x15, 1, 0, 0, 0][..]);
        // The mount: the epoch, then the pfkur thread's inode 0x10; then
        // /keybags (0x11) and usersession.kb (0x12).
        assert_eq!((q(&sb, 0xb0), q(&sb, 0x3d8), q(&sb, 0xb8), u32::from_le_bytes(sb[0x428..0x42c].try_into().unwrap())), (0x13, 0x10, 1, 0x10));
        let pfkur = c.read_raw(q(&sb, 0x418)).unwrap();
        assert_eq!((u32::from_le_bytes(pfkur[24..28].try_into().unwrap()), u32::from_le_bytes(pfkur[28..32].try_into().unwrap())), (0x4000_0002, 0x20));
        let usb = c.read_raw(com.lookup(&c, c.nx.fs_oid[6], c.xid()).unwrap().unwrap().paddr).unwrap();
        assert_eq!((q(&usb, 0x38), q(&usb, 0x108), q(&usb, 0xb0), q(&usb, 0x3d8), u16::from_le_bytes([usb[0x3c4], usb[0x3c5]])), (0x388, 0, 0x48, 0x10, 2));
        // The template copy and the AKS bootstrap (drafts/s23/re-user-copy.md
        // 4): 18 + 34 directories, 4 files.
        assert_eq!((q(&usb, 0xb8), q(&usb, 0xc0)), (4, 52));
        assert_ne!(q(&usb, 0x448), 0);
        // The volume's object map: one leaf, the root node's mapping (the
        // reader refuses an encrypted mapping, so read it raw).
        let raw = |blk: u64| {
            let mut b = vec![0u8; 4096];
            super::super::HostFile(std::fs::File::open(&ctr_path).unwrap(), psize).read_at(blk * 4096, &mut b).unwrap();
            b
        };
        let vom = Omap::open(&c, q(&sb, 0x80)).unwrap();
        let leaf = raw(vom.tree.root_oid);
        assert_eq!(u32::from_le_bytes(leaf[0x24..0x28].try_into().unwrap()), 1);
        let ko = u16::from_le_bytes([leaf[0x38], leaf[0x39]]) as usize;
        let vo = u16::from_le_bytes([leaf[0x3a], leaf[0x3b]]) as usize;
        let toc_len = u16::from_le_bytes([leaf[0x2a], leaf[0x2b]]) as usize;
        assert_eq!(q(&leaf, 0x38 + toc_len + ko), q(&sb, 0x88));
        let vat = 4096 - 0x28 - vo;
        assert_eq!(u32::from_le_bytes(leaf[vat..vat + 4].try_into().unwrap()), 4);
        let rootb = raw(q(&leaf, vat + 8));
        assert_eq!(u32::from_le_bytes(rootb[24..28].try_into().unwrap()), 0x1000_0002);
        // The temporary inode among the root node's records: its name in
        // the private directory, mode 0100600, class 0.
        assert_eq!(u16::from_le_bytes([rootb[0x22], rootb[0x23]]), 0, "Data's tree in one leaf");
        let toc = u16::from_le_bytes([rootb[0x2a], rootb[0x2b]]) as usize;
        let recs: Vec<(Vec<u8>, Vec<u8>)> = (0..u32::from_le_bytes(rootb[0x24..0x28].try_into().unwrap()) as usize)
            .map(|i| {
                let e = |o: usize| u16::from_le_bytes([rootb[0x38 + 8 * i + o], rootb[0x38 + 8 * i + o + 1]]) as usize;
                let k = 0x38 + toc + e(0);
                let v = 4096 - 0x28 - e(4);
                (rootb[k..k + e(2)].to_vec(), rootb[v..v + e(6)].to_vec())
            })
            .collect();
        let name = b"tmp-ino-xattr-dstream-0x0-0x10\0";
        let drec = recs.iter().find(|(k, _)| q(k, 0) == (3 | 9 << 60) && k.ends_with(name)).expect("the temporary inode's entry in the private directory");
        assert_eq!(q(&drec.1, 0), 0x10);
        let ino = &recs.iter().find(|(k, _)| k[..] == (0x10u64 | 3 << 60).to_le_bytes()).expect("the temporary inode").1;
        assert_eq!((q(ino, 0), q(ino, 0x30), u32::from_le_bytes(ino[0x3c..0x40].try_into().unwrap()), u16::from_le_bytes([ino[0x50], ino[0x51]])), (3, 0x8000, 0, 0o100600));
        assert_eq!(q(&ino[ino.len() - 0x28..], 0x10), u64::MAX, "the stream's default crypto identifier");
        assert!(recs.iter().any(|(k, v)| k[..] == (0x10u64 | 6 << 60).to_le_bytes() && v[..4] == 1u32.to_le_bytes()));
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
            let leaf = raw(vom.tree.root_oid);
            assert_eq!(u16::from_le_bytes([leaf[0x22], leaf[0x23]]), 0, "a volume object map of more than one node");
            let nk = u32::from_le_bytes(leaf[0x24..0x28].try_into().unwrap()) as usize;
            for i in 0..nk {
                let vo = u16::from_le_bytes([leaf[0x38 + 4 * i + 2], leaf[0x38 + 4 * i + 3]]) as usize;
                let at = 4096 - 0x28 - vo;
                let fl = u32::from_le_bytes(leaf[at..at + 4].try_into().unwrap());
                let paddr = q(&leaf, at + 8);
                let kstart = 0x38 + u16::from_le_bytes([leaf[0x2a], leaf[0x2b]]) as usize;
                let oid = q(&leaf, kstart + u16::from_le_bytes([leaf[0x38 + 4 * i], leaf[0x38 + 4 * i + 1]]) as usize);
                assert!(fl & 0x20 == 0 || unnamed.contains(&oid), "a secondary-root mapping of an object the superblock does not name");
                let fs_root = oid == q(&sb, 0x88);
                rw(paddr, &|b| {
                    let ty = u32::from_le_bytes(b[24..28].try_into().unwrap()) & !0x1000_0000;
                    b[24..28].copy_from_slice(&ty.to_le_bytes());
                    if fs_root {
                        per_file_ids_cleared(b);
                    }
                });
            }
            rw(vom.tree.root_oid, &|b| {
                for i in 0..nk {
                    let vo = u16::from_le_bytes([b[0x38 + 4 * i + 2], b[0x38 + 4 * i + 3]]) as usize;
                    let at = 4096 - 0x28 - vo;
                    let fl = u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) & !0x724;
                    b[at..at + 4].copy_from_slice(&fl.to_le_bytes());
                }
            });
        }
        (orphans, unnamed)
    }

    /// In the view, a one-leaf file-system tree's per-file crypto
    /// identifiers (a data stream's default crypto identifier, the VEK's 4
    /// or a per-file key's, and the extents' crypto field naming a per-file
    /// key's crypto-state record or the block as the VEK's tweak) set to
    /// 0, as on an unencrypted volume;
    /// the records stay.
    fn per_file_ids_cleared(b: &mut [u8]) {
        let q = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        // Per-file identifiers exist here only on Data, whose tree is one
        // leaf (checked by the test); another volume's tree root may be an
        // index node.
        if u16::from_le_bytes([b[0x22], b[0x23]]) != 0 {
            return;
        }
        let toc = u16::from_le_bytes([b[0x2a], b[0x2b]]) as usize;
        let n = u32::from_le_bytes(b[0x24..0x28].try_into().unwrap()) as usize;
        let vend = b.len() - 0x28;
        let ids: Vec<u64> = (0..n)
            .filter_map(|i| {
                let k = 0x38 + toc + u16::from_le_bytes([b[0x38 + 8 * i], b[0x38 + 8 * i + 1]]) as usize;
                let key = q(b, k);
                (key >> 60 == 7 && key & 0x0fff_ffff_ffff_ffff != 4).then_some(key & 0x0fff_ffff_ffff_ffff)
            })
            .collect();
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
    fn os_version_encoding() {
        assert_eq!(key_os_version("21H461"), Ok(0x1548_01cd));
    }
}
