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
pub const RUN_STAND_IN: &str = "the erase restore's clock readings, transaction grouping and the order its concurrent writers reach the kernel on disk0 (stand-in: the clock of the machine building the image; each call joining the open transaction until a sync, unmount or volume creation commits it, as with no other writer on the container; asr's four writer threads' pwrites reaching the kernel in step order, the System volume's rename to the name it already has after them, the kernel's container unmounted (its last transaction committed, block 0 written) before apfs_invert opens the device, and the kernel's apfs_reaper thread, started by its next mount of the container, running to its end before anything else reaches the container; measure the device's disk0 after its erase restore)";

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
    add(&mut nx, "System", storage::role::SYSTEM, None, now)?;
    add(&mut nx, "xART", storage::role::XART, Some(10_485_760), now)?;
    add(&mut nx, "Hardware", storage::role::HARDWARE, Some(6_291_456), now)?;
    add(&mut nx, "Preboot", storage::role::PREBOOT, None, now)?;
    // 4. Update, mounted at /mnt4 and given its directories
    // (`_create_update_partition_folder_hierarchy`, 0x100020854: for each,
    // mkdir, chmod and chown of the user's ids, under the umask 0 the
    // restore set at its start), then unmounted.
    let oid = add(&mut nx, "Update", storage::role::UPDATE, None, now)?;
    let update = nx.fs_oid.iter().position(|&o| o == oid).ok_or("no Update volume")?;
    fsops::mount_rw(&mut nx, update, now)?;
    const ROOT_INO: u64 = 2;
    const MOBILE: (u32, u32) = (501, 501);
    for (path, mode, (uid, gid)) in [("Controller", 0o711, MOBILE), ("Firmware", 0o755, (0, 0)), ("db", 0o777, MOBILE), ("Hardware", 0o500, (0, 0)), ("Hardware/Battery", 0o700, (0, 0))] {
        let (dir, name) = match path.rsplit_once('/') {
            Some((d, n)) => (fsops::lookup(&mut nx, update, ROOT_INO, d)?.ok_or_else(|| format!("no /{d} on Update"))?, n),
            None => (ROOT_INO, path),
        };
        let ino = match fsops::mkdir(&mut nx, update, dir, name, mode, 0, 0, now)? {
            Ok(ino) => ino,
            Err(_) => fsops::lookup(&mut nx, update, dir, name)?.ok_or("an existing directory not found")?,
        };
        fsops::chmod(&mut nx, update, ino, mode)?;
        fsops::chown(&mut nx, update, ino, uid, gid, now)?;
    }
    fsops::unmount(&mut nx, update, now)?;
    // While asr writes (restore_asr starts it asynchronously), the steps
    // after it in perform_main_os_prepare and perform_restore_installing
    // run on the same container until await_asr_and_retry: init_gigalocker
    // (xART mounted read-write, seputil's gigalocker file),
    // init_permanent_update_volume (Update remounted, its directories'
    // chown, its unmount), mount_filesystem (System renamed, Update
    // mounted), fdr_restore_saved_data (System and Hardware mounted,
    // Hardware's /FactoryData/System/Library/Caches/com.apple.factorydata),
    // commit_sep_os (xART, the Preboot paths and their factorydata link),
    // and await_asr_and_retry's unmount of everything (Update's forced).
    // None is made yet: the container apfs_invert gets lacks them.
    missing.push("the kernel operations restored_external runs while asr writes and before apfs_invert (init_gigalocker's xART mount and gigalocker file, init_permanent_update_volume's Update remount, chown and unmount, mount_filesystem, fdr_restore_saved_data's Hardware FactoryData directories, commit_sep_os's Preboot paths and link, the forced unmount of Update): the container before apfs_invert lacks them, so every placement from asr's on follows a state the device does not have".into());
    if !before_asr(&mut nx)? {
        return Ok(missing);
    }
    // 5. System mounted read-write at /mnt1 and asr's image file written
    // into it (restore_apfs_image_async, restored_external 0x10002d2a4),
    // then everything unmounted for the invert (0x100017488).
    match os {
        Some(os) => {
            let system = 0;
            fsops::mount_rw(&mut nx, system, now)?;
            let src = crate::darwin::udif::PartitionMedium { image: std::sync::Arc::clone(&os.image), index: os.partition };
            super::asr::restore_image(&mut nx, system, &src, &os.image.partitions[os.partition], now)?;
            fsops::unmount(&mut nx, system, now)?;
            // The container handed to apfs_invert: the kernel's last
            // transaction committed and block 0 written (a stand-in, in
            // RUN_STAND_IN), then the tool's own mount.
            nx.unmount()?;
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
            missing.push("the System volume after apfs_invert and the reaping of its old trees: the kernel's mounts of xART and Update, then (once Data and User exist) the data-volume trees' removal (restored_external's fixup_var), /private/xarts, apfs_sealvolume to the signed root hash, and the com.apple.os.update- snapshot".into());
        }
        None => missing.push("the System volume's content: ASR of 044-76040-038.dmg into /mnt1/apfs_invert_asr_img (no image given), apfs_invert, the data-volume trees' removal, apfs_sealvolume to the signed root hash, and the com.apple.os.update- snapshot".into()),
    }
    // 6.
    missing.push("the Data and User volumes (newfs_apfs -P: encrypted with keys the device's Secure Enclave makes)".into());
    // 7.
    missing.push("the Preboot volume's files, xART's gigalocker, Hardware's FactoryData and Data's contents".into());
    // The kernel's own counting of the checksums it sets (its kext has
    // sites newfs_apfs's copy does not) and whether its read-write mount's
    // block-0 write has the newest mounting version are not traced.
    missing.push("nx_counters[0] and block 0's nx_newest_mounted_version as the kernel's transactions leave them (projected from newfs_apfs's three counting sites; the kext has ten)".into());
    nx.unmount()?;
    Ok(missing)
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
        let _ = std::fs::remove_file(&tmp);
    }

    /// With the IPSW's system image (GEX_TEST_UDIF, the disk built in
    /// GEX_TEST_SCRATCH): asr's image file holds the partition's bytes
    /// where the device library's allocator puts them (re-dataalloc.md §8:
    /// its first 256 blocks at 4,128,768, the rest from 131,072 on).
    #[test]
    fn asr_image_file_lands_as_measured() {
        use crate::darwin::apfsread::{Container, Medium};
        let (Ok(dmg), Ok(dir)) = (std::env::var("GEX_TEST_UDIF"), std::env::var("GEX_TEST_SCRATCH")) else { return };
        let f = std::fs::File::open(&dmg).unwrap();
        let len = f.metadata().unwrap().len();
        let image = std::sync::Arc::new(crate::darwin::udif::Udif::open(std::sync::Arc::new(super::super::HostFile(f, len))).unwrap());
        let partition = image.partition("Apple_APFS").unwrap();
        let os = OsImage { image: std::sync::Arc::clone(&image), partition };
        let size = storage::disk0_bytes();
        let tmp = std::path::Path::new(&dir).join(format!("gex-disk0-asr-{}", std::process::id()));
        let f = std::fs::OpenOptions::new().create(true).truncate(true).read(true).write(true).open(&tmp).unwrap();
        f.set_len(size).unwrap();
        let disk = std::sync::Arc::new(super::super::HostFile(f, size));
        let mut t = 1_800_000_000_000_000_000u64;
        let mut now = || {
            t += 1000;
            t
        };
        let (base, psize) = storage::partition_extent();
        let d2 = disk.clone();
        let mut hook = move || -> Result<(), String> {
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
            for (fb, paddr) in [(0u64, 4_128_768u64), (255, 4_129_023), (256, 131_072), (15_898, 146_714), (65_536, 146_715), (131_072, 192_513), (1_478_426, 1_539_867)] {
                image.read_partition(partition, fb * 4096, &mut want).unwrap();
                v.read_file(&ino, fb * 4096, &mut got).unwrap();
                assert_eq!(got, want, "file block {fb}");
                d2.read_at(base + paddr * 4096, &mut got).unwrap();
                assert_eq!(got, want, "file block {fb} at {paddr}");
            }
            Ok(())
        };
        build_disk0_with(disk.clone(), &mut now, Some(&os), &mut |_| Ok(true), &mut hook, &mut |_| Ok(false), None).unwrap();
        // After apfs_invert: the System volume holds the image's files.
        struct Part2(std::sync::Arc<super::super::HostFile>, u64, u64);
        impl Medium for Part2 {
            fn size(&self) -> u64 {
                self.2
            }
            fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<(), String> {
                self.0.read_at(self.1 + off, buf)
            }
        }
        let c = std::sync::Arc::new(Container::open(std::sync::Arc::new(Part2(disk.clone(), base, psize))).unwrap());
        let v = c.volume(0).unwrap().unwrap();
        assert!(v.lookup(2, super::super::asr::IMAGE_NAME).unwrap().is_none());
        let mut dir = 2;
        for n in ["System", "Library", "CoreServices", "SystemVersion.plist"] {
            dir = v.lookup(dir, n).unwrap().unwrap_or_else(|| panic!("no {n}")).file_id;
        }
        let ino = v.inode(dir).unwrap().unwrap();
        let mut buf = vec![0u8; v.file_size(&ino).unwrap() as usize];
        v.read_file(&ino, 0, &mut buf).unwrap();
        assert!(String::from_utf8_lossy(&buf).contains("21H461"));
        let _ = std::fs::remove_file(&tmp);
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
