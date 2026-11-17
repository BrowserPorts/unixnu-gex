//! APFS's own `fsctl` commands, its `vnop_ioctl` (apfs.kext 2236.140.6 of
//! iPad7,1 21H461), for a vnode on one of the container's volumes
//! ([`super::storage`]).

use crate::errno::Errno;
use crate::syscalls::Kernel;

/// `APFSIOC_GET_DEV_BY_ROLE`: `_IOWR('J', 0x50, struct { u8 where; u8;
/// u16 role; char dev[256]; })`.
pub const APFSIOC_GET_DEV_BY_ROLE: u64 = 0xc104_4a50;

/// Where `get_dev_by_role` looks, relative to the source volume's group.
mod lookup {
    /// Inside its volume group (the source must be in one).
    pub const IN_GROUP: u8 = 1;
    /// Out of any volume group (the source must be in none).
    pub const OUT_OF_GROUP: u8 = 2;
    /// Anywhere in the container.
    pub const ANY: u8 = 3;
}

/// The entitlement `handle_get_dev_by_role` needs of the caller's task.
const GET_DEV_BY_ROLE_ENTITLEMENT: &str = "com.apple.apfs.get-dev-by-role";

/// The room `handle_get_dev_by_role` gives the name (`snprintf(dev, 0xff)`).
const DEV_ROOM: usize = 0xff;

impl Kernel {
    /// APFS's answer to `cmd` for a vnode on the volume at slot `source`,
    /// with the copied-in `buf` it fills; `None` for a command that is not
    /// one of these.
    pub(crate) fn darwin_apfs_ioctl(&mut self, source: u32, cmd: u64, buf: &mut [u8]) -> Option<Result<(), Errno>> {
        match cmd {
            APFSIOC_GET_DEV_BY_ROLE => Some(self.darwin_apfs_get_dev_by_role(source, buf)),
            _ => None,
        }
    }

    /// `handle_get_dev_by_role` (0xfffffff0066e2160): the caller's
    /// entitlement (EPERM), `where` against the source volume's group
    /// (EINVAL), `apfs_get_with_role`'s search (ENOENT for none), and the
    /// volume's device path, `/dev/<container>s<slot + 1>` (ERANGE, the
    /// name zeroed, when it does not fit).
    fn darwin_apfs_get_dev_by_role(&mut self, source: u32, buf: &mut [u8]) -> Result<(), Errno> {
        if !self.darwin_entitled(GET_DEV_BY_ROLE_ENTITLEMENT) {
            return Err(Errno::EPERM);
        }
        let where_ = buf[0];
        let role = u16::from_le_bytes([buf[2], buf[3]]);
        let group = super::storage::volume_group(source);
        let any_group = match where_ {
            lookup::IN_GROUP if group.is_none() => return Err(Errno::EINVAL),
            lookup::OUT_OF_GROUP if group.is_some() => return Err(Errno::EINVAL),
            lookup::IN_GROUP | lookup::OUT_OF_GROUP => false,
            lookup::ANY => true,
            _ => return Err(Errno::EINVAL),
        };
        let found = get_with_role(source, role, any_group).ok_or(Errno::ENOENT)?;
        let container = super::storage::container_bsd_name();
        let path = format!("/dev/{container}s{}", found + 1);
        let dev = &mut buf[4..4 + 256];
        if path.len() > DEV_ROOM {
            dev.fill(0);
            return Err(Errno::ERANGE);
        }
        // snprintf into 0xff bytes: the name and its NUL, the rest as it was.
        let n = path.len().min(DEV_ROOM - 1);
        dev[..n].copy_from_slice(&path.as_bytes()[..n]);
        dev[n] = 0;
        Ok(())
    }
}

/// `apfs_get_with_role` (0xfffffff00671a838): the source volume if it has
/// the role; else the first volume by slot with it and, unless `any_group`,
/// the source's group (`uuid_compare`, no group being equal to no group).
pub fn get_with_role(source: u32, role: u16, any_group: bool) -> Option<u32> {
    if super::storage::volume(source)?.role == role {
        return Some(source);
    }
    let group = super::storage::volume_group(source);
    super::storage::VOLUMES.iter().find(|v| v.role == role && (any_group || super::storage::volume_group(v.index) == group)).map(|v| v.index)
}

/// `struct edt_fstab`'s size and its fields' places: `fs_spec[32]`,
/// `fs_file[64]`, `fs_vfstype[32]`, `fs_mntops[64]`, `fs_type[32]`,
/// `fs_passno` and `fs_role`.
pub mod edt {
    pub const SIZE: usize = 0xec;
    pub const SPEC: usize = 0x00;
    pub const FILE: usize = 0x20;
    pub const VFSTYPE: usize = 0x60;
    pub const MNTOPS: usize = 0x80;
    pub const TYPE: usize = 0xc0;
    pub const PASSNO: usize = 0xe4;
    pub const ROLE: usize = 0xe8;
}

/// What `DT_get_fstab_entries` (0xfffffff0066e9504, the
/// `vfs.generic.apfs.edt_fstab` handler) answers: the room the device
/// tree's `max_fs_entries` asks for, and the entries.
pub enum Fstab {
    /// No buffer's length given: the size to ask with.
    Size(u64),
    /// The entries, `count * edt::SIZE` bytes.
    Entries(Vec<u8>),
}

/// `get_ioreg_entry_property`: the property's first `len` bytes at most,
/// ENOENT without it.
fn dt_prop(props: &[(String, Vec<u8>)], name: &str, dst: &mut [u8]) -> Result<(), Errno> {
    let (_, v) = props.iter().find(|(k, _)| k == name).ok_or(Errno::ENOENT)?;
    let n = v.len().min(dst.len());
    dst[..n].copy_from_slice(&v[..n]);
    Ok(())
}

/// `strlen` of a field: up to its first NUL.
fn field_len(b: &[u8]) -> usize {
    b.iter().position(|&c| c == 0).unwrap_or(b.len())
}

/// `strncat(dst, src, n)` in a field of its size (`__strncat_chk`).
fn field_cat(dst: &mut [u8], src: &[u8], n: usize) {
    let at = field_len(dst);
    let add = &src[..field_len(src).min(n)];
    assert!(at + add.len() < dst.len(), "__strncat_chk: the field overflows");
    dst[at..at + add.len()].copy_from_slice(add);
    dst[at + add.len()] = 0;
}

/// `DT_get_fstab_entries` for a request with `oldlen` bytes of room: the
/// device tree's `/filesystems/fstab` (ENOENT without it), its
/// `max_fs_entries` (the property's error), the size alone for no room,
/// ENOMEM for too little; then for each of its nodes in order: "apfs", the
/// node's `vol.fs_file`, `vol.fs_type`, `vol.fs_mntopts` and
/// `vol.fs_passno` (the first missing ends the walk); `fs_spec` "ramdisk"
/// for an ephemeral one, else its `vol.fs_role` and the device of the boot
/// container's volume with that role (none: a Data entry is left out and
/// the walk goes on, any other ends it); and `fs_mntops` with "," and its
/// `fs_type` after any options. The boot container is the root's.
pub fn edt_fstab(oldlen: u64) -> Result<Fstab, Errno> {
    edt_fstab_in(super::iokit::tree(), oldlen, &super::storage::volume_bsd_name)
}

/// [`edt_fstab`] over the registry `t`, with volumes' BSD names from
/// `bsd_name`.
fn edt_fstab_in(t: &[super::iokit::Node], oldlen: u64, bsd_name: &dyn Fn(u32) -> String) -> Result<Fstab, Errno> {
    let fstab = match super::iokit::from_path(t, "IODeviceTree:/filesystems/fstab") {
        Ok(Some(f)) => &t[f as usize],
        _ => return Err(Errno::ENOENT),
    };
    let mut env = 1u32.to_le_bytes();
    let _ = dt_prop(&fstab.props, "os_env_type", &mut env);
    let mut max = [0u8; 4];
    dt_prop(&fstab.props, "max_fs_entries", &mut max)?;
    let size = u64::from(u32::from_le_bytes(max)) * edt::SIZE as u64;
    if oldlen == 0 {
        return Ok(Fstab::Size(size));
    }
    if size > oldlen {
        return Err(Errno::ENOMEM);
    }
    let mut buf = vec![0u8; size as usize];
    let mut count = 0usize;
    for &c in &fstab.children {
        let props = &t[c as usize].props;
        let e = &mut buf[count * edt::SIZE..(count + 1) * edt::SIZE];
        e[edt::VFSTYPE..edt::VFSTYPE + 5].copy_from_slice(b"apfs\0");
        let read = |e: &mut [u8], name: &str, at: usize, len: usize| dt_prop(props, name, &mut e[at..at + len]);
        if read(e, "vol.fs_file", edt::FILE, 0x40).is_err() || read(e, "vol.fs_type", edt::TYPE, 0x20).is_err() || read(e, "vol.fs_mntopts", edt::MNTOPS, 0x40).is_err() || read(e, "vol.fs_passno", edt::PASSNO, 4).is_err() {
            break;
        }
        if props.iter().any(|(k, _)| k == "vol.fs_ephemeral") {
            e[edt::SPEC..edt::SPEC + 8].copy_from_slice(b"ramdisk\0");
        } else {
            let mut role = [0u8; 2];
            if read(&mut role, "vol.fs_role", 0, 2).is_err() {
                break;
            }
            let role = u16::from_le_bytes(role);
            e[edt::ROLE..edt::ROLE + 4].copy_from_slice(&u32::from(role).to_le_bytes());
            let Some(v) = super::storage::volume_with_role(role) else {
                if role == super::storage::role::DATA {
                    e.fill(0);
                    continue;
                }
                break;
            };
            let bsd = bsd_name(v.index);
            // snprintf(fs_spec, 0x20, "%s%s", "/dev/", name).
            let spec = format!("/dev/{bsd}");
            let n = spec.len().min(0x1f);
            e[edt::SPEC..edt::SPEC + n].copy_from_slice(&spec.as_bytes()[..n]);
        }
        let ty = e[edt::TYPE..edt::TYPE + 0x20].to_vec();
        let opts = &mut e[edt::MNTOPS..edt::MNTOPS + 0x40];
        if field_len(opts) != 0 {
            field_cat(opts, b",", 2);
        }
        field_cat(opts, &ty, 0x20);
        count += 1;
    }
    buf.truncate(count * edt::SIZE);
    Ok(Fstab::Entries(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::darwin::storage::role;

    /// The boot payload's device tree (GEX_DARWIN_BOOT), and a name for
    /// the container that is this test's own.
    #[test]
    #[ignore = "needs GEX_DARWIN_BOOT's DeviceTree"]
    fn edt_fstab_has_the_device_trees_volumes() {
        let dir = std::env::var("GEX_DARWIN_BOOT").expect("GEX_DARWIN_BOOT");
        let dt = std::fs::read(format!("{dir}/DeviceTree")).unwrap();
        let mut t = crate::darwin::iokit::parse(&dt).unwrap();
        crate::darwin::storagestack::add(&mut t, None);
        let name = |i: u32| format!("diskTs{}", i + 1);
        let Ok(Fstab::Size(n)) = edt_fstab_in(&t, 0, &name) else { panic!() };
        assert_eq!(n, 7 * 0xec, "max_fs_entries 7");
        assert!(matches!(edt_fstab_in(&t, n - 1, &name), Err(Errno::ENOMEM)));
        let Ok(Fstab::Entries(b)) = edt_fstab_in(&t, 0x938, &name) else { panic!() };
        assert_eq!(b.len(), 6 * 0xec);
        let s = |e: &[u8], at: usize, len: usize| String::from_utf8_lossy(&e[at..at + field_len(&e[at..at + len])]).into_owned();
        let got: Vec<(String, String, String, String, u32)> = b
            .chunks(0xec)
            .map(|e| (s(e, edt::SPEC, 0x20), s(e, edt::FILE, 0x40), s(e, edt::VFSTYPE, 0x20), s(e, edt::MNTOPS, 0x40), u32::from_le_bytes(e[edt::ROLE..edt::ROLE + 4].try_into().unwrap())))
            .collect();
        let want = [
            ("/dev/diskTs3", "/private/xarts", "nosuid,nodev,nobrowse,rw", 0x100),
            ("/dev/diskTs1", "/", "ro", 0x1),
            ("/dev/diskTs5", "/private/preboot", "nosuid,nodev,nobrowse,ro", 0x10),
            ("/dev/diskTs2", "/private/var", "nosuid,nodev,rw", 0x40),
            ("/dev/diskTs6", "/private/var/MobileSoftwareUpdate", "nosuid,nodev,nobrowse,rw", 0xc0),
            ("/dev/diskTs4", "/private/var/hardware", "nosuid,nodev,nobrowse,rw", 0x140),
        ];
        for (g, w) in got.iter().zip(want) {
            assert_eq!((g.0.as_str(), g.1.as_str(), g.2.as_str(), g.3.as_str(), g.4), (w.0, w.1, "apfs", w.2, w.3));
        }
    }

    #[test]
    fn a_role_is_found_from_the_system_volume() {
        assert_eq!(get_with_role(0, role::PREBOOT, false), Some(4));
        assert_eq!(get_with_role(0, role::SYSTEM, false), Some(0), "the source itself");
        assert_eq!(get_with_role(0, role::UPDATE, true), Some(5));
        assert_eq!(get_with_role(0, 0x200, false), None, "no Scratch volume");
    }
}
