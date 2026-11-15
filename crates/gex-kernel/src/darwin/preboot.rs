//! The Preboot volume's files, as the erase restore of 21H461 leaves them
//! (`restored_external` in the erase identity's ramdisk, 044-75545-038.dmg).
//!
//! - The volume's root: `newfs_apfs -A -D -o role=B -v Preboot`
//!   (`restored_external` 0x100021ad8 builds the arguments: no `-U` or `-G`)
//!   makes it in `apfs_newfs` (newfs_apfs 0x10001bde8): inode 2, mode
//!   0x41ed, owned by the options' user and group (+0x1bc, +0x1c0), which
//!   are newfs_apfs's `getuid()` and `getgid()` (0x10000764c, 0x100007654):
//!   `restored_external`'s, root and wheel (its launchd job names no user).
//! - `Cryptexes/OS` and `Cryptexes/App`: `mkpathat_np` on the mounted
//!   volume's root (0x100057708, the table at 0x100285980), mode 0777, the
//!   intermediate `Cryptexes` too (Libc-1592.100.35 `util/mkpath_np.c`:
//!   `mkdirat(..., S_IRWXU | S_IRWXG | S_IRWXO)`, already `u+wx`, so no
//!   `fchmodat`), with `restored_external`'s umask 0 (its launchd job's
//!   `Umask` and its own `umask(0)`, 0x10000f2f0). `Cryptexes/ExclaveOS`
//!   only when the AP ticket has an `exvl` digest (0x100067434): J120's
//!   build identities have no exclave component. Each is the maker's (root)
//!   and its directory's group (wheel).
//! - `active` (0x100056fa8): `open_dprotected_np(O_WRONLY | O_CREAT |
//!   O_TRUNC, class 0, 0644)` (0x100047ab0), holding the AP ticket's hash
//!   in hexadecimal capitals (0x100065728) by `/chosen`'s
//!   `crypto-hash-method` (sha2-384: 96 digits).
//! - The directory named by that hash (`"%s/%@"`, 0x10004bf94), which the
//!   boot objects, the root hash and the firmware go under.
//! - `cryptex1` (`_get_os_preboot_path`, 0x100065044, is the mount point;
//!   0x1000650f0 adds "cryptex1"): `install_splat` (0x10003af24) puts the
//!   personalized cryptex there when the build identity has a `Cryptex1,`
//!   component (0x100063fbc), as J120's has.
//!
//! The hash, `active`'s contents and what `cryptex1` holds come from the
//! device's personalized tickets, whose contents wait on the owner's
//! decision: those files are not modelled ([`unmodelled`]). The rest is
//! modelled exactly, but for what only the device says: when the restore
//! made the files ([`TIMES_STAND_IN`]).

use super::vattr::Owned;
use crate::vfs::{FileSystem, XattrOp};
use std::sync::{Arc, OnceLock};

/// A directory the restore leaves on the volume: its path below the root
/// and its attributes.
pub struct Dir {
    pub path: &'static str,
    pub owned: Owned,
}

/// The directories, the root first.
pub const DIRS: [Dir; 4] = [
    Dir { path: "", owned: Owned { uid: 0, gid: 0, mode: 0o755, flags: 0 } },
    Dir { path: "Cryptexes", owned: Owned { uid: 0, gid: 0, mode: 0o777, flags: 0 } },
    Dir { path: "Cryptexes/OS", owned: Owned { uid: 0, gid: 0, mode: 0o777, flags: 0 } },
    Dir { path: "Cryptexes/App", owned: Owned { uid: 0, gid: 0, mode: 0o777, flags: 0 } },
];

/// How many hexadecimal digits the ticket hash's name has: SHA-384's 48
/// bytes, `/chosen`'s `crypto-hash-method` being "sha2-384".
pub const HASH_DIGITS: usize = 96;

/// What stands in for the time the restore made the files: the volume's
/// first mount in this boot. A reported shortcut (storage::unmeasured).
pub const TIMES_STAND_IN: &str = "the time the restore made the Preboot volume's files (stand-in: its first mount in this boot; measure the times `stat` gives /private/preboot/Cryptexes on the device)";

/// Why the entry `name` of the volume's root is not modelled, if it is not:
/// `active`, `cryptex1`, and a name that can be the ticket hash's.
pub fn unmodelled(name: &str) -> Option<String> {
    let personalized = "personalized from the device's tickets, whose contents wait on the owner";
    match name {
        "active" => Some(format!("the Preboot volume's active file (the AP ticket's hash, {personalized})")),
        "cryptex1" => Some(format!("the Preboot volume's cryptex1 directory (the cryptex install_splat puts there, {personalized})")),
        _ if name.len() == HASH_DIGITS && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'A'..=b'F')) => {
            Some(format!("the Preboot volume's directory named by the AP ticket's hash ({personalized}): whether {name} is it"))
        }
        _ => None,
    }
}

/// Why the volume's root cannot be listed: its entries name the ticket
/// hash's directory.
pub fn root_listing() -> String {
    "the Preboot volume's root, whose entries are Cryptexes, active, cryptex1 and the directory named by the AP ticket's hash (personalized from the device's tickets, whose contents wait on the owner)".to_string()
}

/// The volume's files, made at its first mount and kept for the system's
/// life, as the device keeps them: the directories of [`DIRS`], each with
/// its attributes' record (what a file made later gets too).
pub fn volume() -> Result<Arc<crate::vfs::tmpfs::TmpFs>, String> {
    static VOLUME: OnceLock<Result<Arc<crate::vfs::tmpfs::TmpFs>, String>> = OnceLock::new();
    VOLUME
        .get_or_init(|| {
            let fs = crate::vfs::tmpfs::TmpFs::new();
            for d in &DIRS {
                if !d.path.is_empty() {
                    fs.mkdir(d.path, d.owned.mode).map_err(|e| format!("making the Preboot volume's {}: {e:?}", d.path))?;
                }
                let text = d.owned.record();
                fs.xattr(d.path, XattrOp::Set { name: super::vattr::RECORD, value: text.as_bytes(), flags: 0 })
                    .map_err(|e| format!("recording the attributes of the Preboot volume's /{}: {e:?}", d.path))?;
            }
            Ok(Arc::new(fs))
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_names_are_not_modelled() {
        assert!(unmodelled("active").is_some());
        assert!(unmodelled("cryptex1").is_some());
        assert!(unmodelled(&"A".repeat(HASH_DIGITS)).is_some());
        assert!(unmodelled(&"a".repeat(HASH_DIGITS)).is_none(), "the hash is in capitals");
        assert!(unmodelled(&"A".repeat(HASH_DIGITS - 1)).is_none());
        assert!(unmodelled("Cryptexes").is_none());
    }

    #[test]
    fn the_restores_directories() {
        let fs = volume().unwrap();
        for d in &DIRS {
            let mut buf = [0u8; 64];
            let n = fs.xattr(d.path, XattrOp::Get { name: super::super::vattr::RECORD, buf: &mut buf }).unwrap();
            assert_eq!(Owned::parse(&buf[..n]).unwrap(), d.owned);
            assert_eq!(fs.metadata(d.path).unwrap().file_type, crate::vfs::FileType::Directory);
        }
        let names: Vec<String> = fs.open("", 0, 0).unwrap().read_dir().unwrap().into_iter().map(|e| e.name).filter(|n| n != "." && n != "..").collect();
        assert_eq!(names, ["Cryptexes"]);
    }
}
