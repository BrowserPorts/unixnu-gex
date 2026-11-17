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
//! - `cryptex1` ([`cryptex1`]): `install_splat` (0x10003af24) puts the
//!   Cryptex1 there when the build identity has a `Cryptex1,` component
//!   (0x100063fbc), as J120's has.
//!
//! The AP ticket's hash and `active`'s contents come from the device's
//! personalized AP ticket, which is not modelled ([`unmodelled`]); the
//! Cryptex1 ticket comes from the source configured for it ([`Ticket`]).
//! The rest is modelled exactly, but for what only the device says: when
//! the restore made the files ([`TIMES_STAND_IN`]) and the modes of what
//! Foundation writes ([`FOUNDATION_MODE_STAND_IN`]).

use super::plist::{self, Value};
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
pub const TIMES_STAND_IN: &str = "the time the restore made the Preboot volume's files (stand-in: its first mount in this boot, for cryptex1's RestoreVersion.plist and SystemVersion.plist too, which copyfile gives the system volume's times; measure the times `stat` gives /private/preboot/Cryptexes and /private/preboot/cryptex1/current's files on the device)";

/// The Cryptex1, as `install_splat` (0x10003af24) and
/// `ramrod_splat_install` (0x10006419c) put it on the volume. Not staged
/// (the restore sets no "StageToProposed"): the target is
/// `<Preboot>/cryptex1/current` (`_get_splat_preboot_paths`, 0x1000650f0),
/// removed and made again with `-[NSFileManager
/// createDirectoryAtPath:withIntermediateDirectories:YES attributes:nil]`
/// (0x100064a0c): `mkdir` 0777, under the umask 0 (so `cryptex1` and
/// `cryptex1/current` are 0777, root's, group wheel); no
/// `cryptex1/proposed` is left. Then each object of the table at
/// 0x100268528 ([`OBJECTS`]), in its order:
///
/// - a component of the build identity's manifest (one it does not have is
///   skipped, 0x100064d20) is asked of the host and streamed into
///   `fopen(dest, "wb")` (`_get_and_save_large_file_internal`, 0x10003bbcc:
///   mode 0666) with its SHA-384 compared to its digest (0x10003be88,
///   "digest mismatch"): the IPSW's file, byte for byte;
/// - `RestoreVersion.plist` and `SystemVersion.plist`: `copyfile` of the
///   system volume's `/System/Library/CoreServices` ones with
///   `COPYFILE_ALL` (0x10003ba18): their bytes, extended attributes, owner,
///   group and mode, and their flags less `COPYFILE_OMIT_FLAGS`
///   (copyfile-240 `copyfile_stat`);
/// - `BuildManifest.plist`: `{"BuildIdentities": [identity]}` written with
///   `-[NSDictionary writeToFile:atomically:NO]` (0x10003b9c8), XML as
///   CoreFoundation writes it ([`plist::to_xml`]).
///
/// And last the Cryptex1 ticket, `apticket.<hw.target>.<ECID>.im4m`
/// ([`ticket_name`]), written atomically with `NSData` (0x100064e70).
pub mod cryptex1 {
    /// The directory the restore makes, and the one it fills.
    pub const DIR: &str = "cryptex1";
    pub const CURRENT: &str = "cryptex1/current";

    /// The table's components: their build manifest key and the name they
    /// are written to.
    pub const OBJECTS: [(&str, &str); 6] = [
        ("Cryptex1,SystemOS", "os.dmg"),
        ("Cryptex1,SystemVolume", "os.dmg.root_hash"),
        ("Cryptex1,SystemTrustCache", "os.dmg.trustcache"),
        ("Cryptex1,AppOS", "app.dmg"),
        ("Cryptex1,AppVolume", "app.dmg.root_hash"),
        ("Cryptex1,AppTrustCache", "app.dmg.trustcache"),
    ];

    /// The system volume's files `copyfile` copies, and their names.
    pub const VERSIONS: [(&str, &str); 2] = [
        ("/System/Library/CoreServices/RestoreVersion.plist", "RestoreVersion.plist"),
        ("/System/Library/CoreServices/SystemVersion.plist", "SystemVersion.plist"),
    ];

    /// The manifest the restore writes.
    pub const MANIFEST: &str = "BuildManifest.plist";

    /// The build identity an erase restore is of (the model's restore).
    pub const ERASE_VARIANT: &str = "Customer Erase Install (IPSW)";

    /// `COPYFILE_OMIT_FLAGS` (copyfile-240 copyfile_private.h):
    /// UF_TRACKED, SF_RESTRICTED, SF_NOUNLINK, UF_DATAVAULT.
    pub const COPYFILE_OMIT_FLAGS: u32 = 0x40 | 0x8_0000 | 0x10_0000 | 0x80;
}

/// What stands in for the modes of the files Foundation writes on the
/// volume, `BuildManifest.plist` (`writeToFile:atomically:NO`) and the
/// Cryptex1 ticket (`NSDataWritingAtomic`), under the umask 0: 0666, as an
/// `open` with the default file mode gives. A reported shortcut
/// (storage::unmeasured).
pub const FOUNDATION_MODE: u32 = 0o666;

/// [`FOUNDATION_MODE`]'s report.
pub const FOUNDATION_MODE_STAND_IN: &str = "the modes of the Preboot volume's cryptex1/current/BuildManifest.plist and Cryptex1 ticket, which Foundation writes (stand-in 0666, and the IPSW's build identity as the restore host sends it, with RestoreVersion.plist's flags as copyfile sets them; measure `ls -lO` and the bytes of /private/preboot/cryptex1/current on the device)";

/// Where the Cryptex1 ticket comes from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Ticket {
    /// None is configured: looking it up is reported.
    #[default]
    Unset,
    /// The device's own, a file the owner copied from its Preboot volume
    /// (GEX_DARWIN_CRYPTEX1_TICKET=path).
    File(String),
    /// The web device's own (GEX_DARWIN_CRYPTEX1_TICKET=web-device): the one
    /// its manifest key signed for it ([`super::webdevice`]), when it has
    /// one; looking it up is reported when it has none.
    WebDevice,
}

/// How the host's files are read: a file's size, and its bytes from an
/// offset (all of them, or false). The volume's copies of the IPSW's files
/// are read the same way when the guest reads them (the tmpfs's lazy
/// files, [`crate::vfs::tmpfs::set_lazy_fetch`]).
#[derive(Clone, Copy, Debug)]
pub struct Host {
    pub size: fn(&str) -> Option<u64>,
    pub read: crate::vfs::tmpfs::LazyFetch,
    /// A host file's SHA-384 as the host keeps it for a file it has
    /// hashed whole and that has not changed since (none: hashed here,
    /// through `read`).
    pub sha384: Option<fn(&str) -> Option<[u8; 48]>>,
}

/// Where the restore's Cryptex1 comes from: the files the host's restore
/// would send, read through the host.
#[derive(Clone, Debug, Default)]
pub struct Sources {
    /// The directory holding the IPSW's `BuildManifest.plist` and its files
    /// at their paths in the IPSW (GEX_DARWIN_RESTORE). Without one the
    /// `cryptex1` directory is reported.
    pub restore: Option<String>,
    pub ticket: Ticket,
    /// The device's current cryptex1 boot nonce hash, hexadecimal
    /// (GEX_DARWIN_CRYPTEX1_NONCE_HASH): what its AppleImage4 makes of the
    /// nonce in its NVRAM, a measured input ([`cryptex1_boot_nonce_hash`]).
    pub nonce_hash: Option<String>,
    pub host: Option<Host>,
    /// The web device the system boots as (GEX_DARWIN_WEB_DEVICE), with
    /// [`Ticket::WebDevice`].
    pub web_device: Option<super::webdevice::WebDevice>,
}

static SOURCES: OnceLock<Sources> = OnceLock::new();

/// The sources, once at boot; the host's reads serve the volume's lazy
/// files.
pub fn set_sources(s: Sources) -> Result<(), String> {
    if let Some(h) = s.host {
        crate::vfs::tmpfs::set_lazy_fetch(h.read);
    }
    SOURCES.set(s).map_err(|_| "the Cryptex1's sources are set already".to_string())
}

/// The device's current cryptex1 boot nonce hash, which the Cryptex1
/// ticket's `cnch` must be: AppleImage4 makes it from the cryptex1 boot
/// nonce domain's nonce in the device's NVRAM (`nonce-seeds`), entangled
/// with the device's UID key when the device asks for it, so only the
/// device has it and the owner supplies it (GEX_DARWIN_CRYPTEX1_NONCE_HASH):
/// while the device has not rolled the nonce since the restore, it is the
/// device's ticket's `cnch`.
pub fn cryptex1_boot_nonce_hash() -> Result<Vec<u8>, String> {
    if super::webdevice::get().is_some() {
        return Err("the measured cryptex1 boot nonce hash of a device of Apple's: the web device makes its own".to_string());
    }
    let Some(hex) = sources().nonce_hash.as_deref() else {
        return Err("the device's cryptex1 boot nonce hash (its AppleImage4's hash of the cryptex1 boot nonce in its NVRAM nonce-seeds, entangled with its UID key when asked: a measured input, GEX_DARWIN_CRYPTEX1_NONCE_HASH, is not configured)".to_string());
    };
    let hex = hex.trim();
    if hex.is_empty() || hex.len() % 2 != 0 || hex.len() > 128 {
        return Err(format!("GEX_DARWIN_CRYPTEX1_NONCE_HASH is not a hash in hexadecimal: {hex:?}"));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| format!("GEX_DARWIN_CRYPTEX1_NONCE_HASH is not a hash in hexadecimal: {hex:?}")))
        .collect()
}

/// How the host's files are read, if the host reads them.
pub fn host() -> Option<Host> {
    sources().host
}

/// What stands in for the Preboot volume's next object identifier
/// (`apfs_next_obj_id`), where a graft's range of its inode numbers starts:
/// the next inode number of the volume's files here. A reported shortcut
/// (storage::unmeasured).
pub const NEXT_OBJ_ID_STAND_IN: &str = "the Preboot volume's apfs_next_obj_id, where a cryptex graft's inode numbers start (stand-in: the next inode number of the volume's files as this kernel numbers them; measure `stat -f %i` of /private/preboot/Cryptexes/OS/System on the device and its graft's jobj_id range in the kernel log, \"Graft ino %llu, jobj_id range %llu+%llu\")";

fn sources() -> &'static Sources {
    static NONE: OnceLock<Sources> = OnceLock::new();
    SOURCES.get().unwrap_or_else(|| NONE.get_or_init(Sources::default))
}

/// A host file's bytes, whole.
fn host_read(h: &Host, path: &str) -> Result<Vec<u8>, String> {
    let size = (h.size)(path).ok_or_else(|| format!("{path}: not readable"))?;
    let mut b = vec![0u8; usize::try_from(size).map_err(|_| format!("{path}: too large"))?];
    if !b.is_empty() && !(h.read)(path, 0, &mut b) {
        return Err(format!("{path}: not readable"));
    }
    Ok(b)
}

/// A host file's SHA-384: the host's, else read in pieces.
fn host_sha384(h: &Host, path: &str, size: u64) -> Result<[u8; 48], String> {
    use sha2::Digest;
    if let Some(d) = h.sha384.and_then(|f| f(path)) {
        return Ok(d);
    }
    const PIECE: u64 = 8 << 20;
    let mut d = sha2::Sha384::new();
    let mut buf = vec![0u8; PIECE.min(size) as usize];
    let mut at = 0u64;
    while at < size {
        let n = (size - at).min(PIECE) as usize;
        if !(h.read)(path, at, &mut buf[..n]) {
            return Err(format!("{path}: not readable at {at}"));
        }
        d.update(&buf[..n]);
        at += n as u64;
    }
    Ok(d.finalize().into())
}

/// The Cryptex1 ticket's name (`_ticket_file_name_personalized`,
/// 0x100064b30): "apticket.%@.%llX.im4m" of `hw.target` lowercased
/// ("x86legacyap" when it has none) and `IODeviceTree:/chosen`'s
/// `unique-chip-id`, the ECID.
pub fn ticket_name() -> Result<String, String> {
    ticket_name_of(super::iokit::tree())
}

/// [`ticket_name`] of device tree `t`.
pub fn ticket_name_of(t: &[super::iokit::Node]) -> Result<String, String> {
    let target = super::iokit::target_name_of(t).map_or_else(|| "x86legacyap".to_string(), |n| String::from_utf8_lossy(&n).to_lowercase());
    let ecid = super::iokit::dt_prop(t, "IODeviceTree:/chosen", "unique-chip-id")
        .filter(|v| v.len() == 8)
        .map(|v| u64::from_le_bytes(v.try_into().unwrap()))
        .ok_or_else(|| "the Cryptex1 ticket's name: the device tree's /chosen has no 8-byte unique-chip-id".to_string())?;
    Ok(format!("apticket.{target}.{ecid:X}.im4m"))
}

/// The build identity the erase restore of this device installs: the
/// IPSW manifest's identity of the device's class (`hw.target`) and the
/// erase variant.
pub fn erase_identity<'a>(manifest: &'a Value, class: &str) -> Result<&'a Value, String> {
    let ids = manifest.get("BuildIdentities").and_then(Value::as_array).ok_or("the IPSW's BuildManifest.plist has no BuildIdentities")?;
    ids.iter()
        .find(|i| {
            let info = i.get("Info");
            info.and_then(|x| x.get("DeviceClass")).and_then(Value::as_str) == Some(class) && info.and_then(|x| x.get("Variant")).and_then(Value::as_str) == Some(cryptex1::ERASE_VARIANT)
        })
        .ok_or_else(|| format!("the IPSW's BuildManifest.plist has no {class} identity of variant {}", cryptex1::ERASE_VARIANT))
}

/// The manifest the restore writes: the one identity it installed.
pub fn restore_manifest(identity: &Value) -> Vec<u8> {
    plist::to_xml(&Value::Dict(vec![("BuildIdentities".to_string(), Value::Array(vec![identity.clone()]))]))
}

/// Why the entry at `rel` (its path below the volume's root) is not
/// modelled, if it is not: the entries the AP ticket makes (`active`, a
/// name that can be the ticket hash's), `cryptex1` when no restore source
/// is configured, the Cryptex1 ticket when its source is not a file, and
/// on a booted system without a restore source what its cryptexes' grafts
/// hold. `listing` asks for the directory's entries.
pub fn unmodelled(rel: &str, listing: bool) -> Option<String> {
    let personalized = "personalized from the device's AP ticket, which is not modelled";
    let first = rel.split('/').next().unwrap_or("");
    match first {
        "active" => Some(format!("the Preboot volume's active file (the AP ticket's hash, {personalized})")),
        cryptex1::DIR => cryptex1_unmodelled(rel, listing),
        "Cryptexes" => booted_graft_unmodelled(rel, listing),
        _ if first.len() == HASH_DIGITS && first.bytes().all(|b| matches!(b, b'0'..=b'9' | b'A'..=b'F')) => {
            Some(format!("the Preboot volume's directory named by the AP ticket's hash ({personalized}): whether {first} is it"))
        }
        _ => None,
    }
}

/// The grafts of a booted system's Preboot volume ([`BOOTED_GRAFTS`]), made
/// from the restore source's images: without one, a path below a graft
/// directory, or a listing of one, is not modelled.
fn booted_graft_unmodelled(rel: &str, listing: bool) -> Option<String> {
    if super::kern::boot_state() != super::kern::BootState::Booted || sources().restore.is_some() {
        return None;
    }
    let g = BOOTED_GRAFTS.iter().find(|g| rel.strip_prefix(g.dir).is_some_and(|r| r.starts_with('/') || (r.is_empty() && listing)))?;
    Some(format!("the booted system's graft of the {} cryptex on /private/preboot/{} (made from the restore source's {}: no restore source is configured, GEX_DARWIN_RESTORE)", g.name, g.dir, g.image))
}

/// A boot cryptex libignition grafts at boot (its graft stage, after the
/// preboot stage's mount): the Preboot volume's image in `cryptex1/current`,
/// its graft directory, libignition's `graftdmg` flags (the SystemOS
/// cryptex's 0x2d, the AppOS cryptex's 0x2e), its root hash and trust
/// cache, and the trust cache's type.
#[derive(Clone, Copy, Debug)]
pub struct BootGraft {
    pub name: &'static str,
    pub image: &'static str,
    pub dir: &'static str,
    pub sbc_flags: u64,
    pub root_hash: &'static str,
    pub trust_cache: &'static str,
    pub tc_type: u8,
}

/// The boot cryptexes in the order libignition grafts them, each trust
/// cache loaded right after its graft: the SystemOS cryptex, then (on a
/// sealed boot, the root mounted `MNT_SNAPSHOT`) the AppOS cryptex.
pub const BOOTED_GRAFTS: [BootGraft; 2] = [
    BootGraft { name: "OS", image: "os.dmg", dir: "Cryptexes/OS", sbc_flags: 0x2d, root_hash: "os.dmg.root_hash", trust_cache: "os.dmg.trustcache", tc_type: super::trustcache::tc_type::CRYPTEX1_BOOT_OS },
    BootGraft { name: "App", image: "app.dmg", dir: "Cryptexes/App", sbc_flags: 0x2e, root_hash: "app.dmg.root_hash", trust_cache: "app.dmg.trustcache", tc_type: super::trustcache::tc_type::CRYPTEX1_BOOT_APP },
];

/// Whether a restore source is configured: the Cryptex1's files, the
/// cryptexes' images among them, are laid out.
pub fn has_restore() -> bool {
    sources().restore.is_some()
}

fn cryptex1_unmodelled(rel: &str, listing: bool) -> Option<String> {
    let s = sources();
    if s.restore.is_none() {
        return Some("the Preboot volume's cryptex1 directory (the Cryptex1 install_splat lays out from the IPSW's files: no restore source is configured, GEX_DARWIN_RESTORE)".to_string());
    }
    let why = match &s.ticket {
        Ticket::File(_) => return None,
        Ticket::Unset => "no source of it is configured (GEX_DARWIN_CRYPTEX1_TICKET: the device's own ticket file, or web-device)",
        Ticket::WebDevice => match &s.web_device {
            Some(w) if w.ticket.is_some() => return None,
            _ => "the web device has none: its manifest key has not signed one for it (gexc darwin-web-ticket)",
        },
    };
    let name = match ticket_name() {
        Ok(n) => n,
        Err(e) => return Some(e),
    };
    let at = format!("{}/{name}", cryptex1::CURRENT);
    if rel == at || rel.starts_with(&format!("{at}/")) {
        return Some(format!("the Cryptex1 ticket {name}, which the restore writes in cryptex1/current as TSS personalized it for the device: {why}"));
    }
    if listing && rel == cryptex1::CURRENT {
        return Some(format!("cryptex1/current's entries, among them the Cryptex1 ticket {name}: {why}"));
    }
    None
}

/// Why the volume's root cannot be listed: its entries name the ticket
/// hash's directory.
pub fn root_listing() -> String {
    "the Preboot volume's root, whose entries are Cryptexes, active, cryptex1 and the directory named by the AP ticket's hash (personalized from the device's AP ticket, which is not modelled)".to_string()
}

/// Record a file's attributes.
fn record(fs: &crate::vfs::tmpfs::TmpFs, path: &str, o: &Owned) -> Result<(), String> {
    let text = o.record();
    fs.xattr(path, XattrOp::Set { name: super::vattr::RECORD, value: text.as_bytes(), flags: 0 }).map(|_| ()).map_err(|e| format!("recording the attributes of the Preboot volume's /{path}: {e:?}"))
}

/// A file of the system volume: its bytes and attributes, if it has one.
pub type SystemFile<'a> = &'a dyn Fn(&str) -> Result<Option<(Vec<u8>, Owned)>, String>;

/// Lay the Cryptex1 out on `fs` as the restore does ([`cryptex1`]), from
/// the configured sources, on the device the device tree `t` describes;
/// `system` reads a file of the system volume.
fn lay_cryptex1(fs: &crate::vfs::tmpfs::TmpFs, s: &Sources, t: &[super::iokit::Node], system: SystemFile<'_>) -> Result<(), String> {
    let Some(dir) = s.restore.as_deref() else { return Ok(()) };
    let h = s.host.as_ref().ok_or("the Cryptex1's restore source: the host does not read its files")?;
    let dir = dir.trim_end_matches('/');
    let manifest = plist::parse(&host_read(h, &format!("{dir}/BuildManifest.plist"))?).map_err(|e| format!("{dir}/BuildManifest.plist: {e}"))?;
    let class = super::iokit::target_name_of(t).map(|n| String::from_utf8_lossy(&n).to_lowercase()).ok_or("the Cryptex1's build identity: the device tree names no target")?;
    let identity = erase_identity(&manifest, &class)?;
    let components = identity.get("Manifest").ok_or("the build identity has no Manifest")?;
    let dir_owned = Owned { uid: 0, gid: 0, mode: 0o777, flags: 0 };
    for d in [cryptex1::DIR, cryptex1::CURRENT] {
        fs.mkdir(d, dir_owned.mode).map_err(|e| format!("making the Preboot volume's {d}: {e:?}"))?;
        record(fs, d, &dir_owned)?;
    }
    // The restore's files all date from its making of the directory.
    let made = fs.metadata(cryptex1::CURRENT).map_err(|e| format!("the Preboot volume's {}: {e:?}", cryptex1::CURRENT))?.mtime;
    let file_owned = |mode| Owned { uid: 0, gid: 0, mode, flags: 0 };
    for (key, name) in cryptex1::OBJECTS {
        let Some(c) = components.get(key) else { continue };
        let path = c.get("Info").and_then(|i| i.get("Path")).and_then(Value::as_str).ok_or_else(|| format!("the build identity's {key} has no Info.Path"))?;
        let digest = c.get("Digest").and_then(Value::as_data).ok_or_else(|| format!("the build identity's {key} has no Digest"))?;
        let host = format!("{dir}/{path}");
        let n = (h.size)(&host).ok_or_else(|| format!("the Cryptex1's {key}: {host} is not readable"))?;
        let got = host_sha384(h, &host, n)?;
        if got[..] != digest[..] {
            return Err(format!("the Cryptex1's {key}: {host}'s SHA-384 is not the build identity's digest (the restore fails: digest mismatch)"));
        }
        let at = format!("{}/{name}", cryptex1::CURRENT);
        fs.add_lazy(&at, n, &host);
        fs.set_times_now(&at, Some((made, 0)), Some((made, 0)), made).map_err(|e| format!("the Preboot volume's {at}: {e:?}"))?;
        record(fs, &at, &file_owned(0o666))?;
    }
    for (src, name) in cryptex1::VERSIONS {
        let Some((bytes, a)) = system(src).map_err(|e| format!("copying {src} to the Preboot volume: {e}"))? else { continue };
        let at = format!("{}/{name}", cryptex1::CURRENT);
        fs.add_file(&at, bytes);
        fs.set_times_now(&at, Some((made, 0)), Some((made, 0)), made).map_err(|e| format!("the Preboot volume's {at}: {e:?}"))?;
        record(fs, &at, &Owned { flags: a.flags & !cryptex1::COPYFILE_OMIT_FLAGS, ..a })?;
    }
    let at = format!("{}/{}", cryptex1::CURRENT, cryptex1::MANIFEST);
    fs.add_file(&at, restore_manifest(identity));
    fs.set_times_now(&at, Some((made, 0)), Some((made, 0)), made).map_err(|e| format!("the Preboot volume's {at}: {e:?}"))?;
    record(fs, &at, &file_owned(FOUNDATION_MODE))?;
    let ticket = match (&s.ticket, &s.web_device) {
        (Ticket::File(path), _) => Some(path),
        (Ticket::WebDevice, Some(w)) => w.ticket.as_ref(),
        _ => None,
    };
    if let Some(path) = ticket {
        let bytes = host_read(h, path).map_err(|e| format!("the Cryptex1 ticket {path}: {e}"))?;
        let at = format!("{}/{}", cryptex1::CURRENT, ticket_name_of(t)?);
        fs.add_file(&at, bytes);
        fs.set_times_now(&at, Some((made, 0)), Some((made, 0)), made).map_err(|e| format!("the Preboot volume's {at}: {e:?}"))?;
        record(fs, &at, &file_owned(FOUNDATION_MODE))?;
    }
    Ok(())
}

/// The volume's files once made ([`volume`]).
static VOLUME: OnceLock<Result<Arc<crate::vfs::tmpfs::TmpFs>, String>> = OnceLock::new();

/// The volume's files, if its first mount has made them.
pub fn made() -> Option<Arc<crate::vfs::tmpfs::TmpFs>> {
    VOLUME.get().and_then(|r| r.as_ref().ok()).cloned()
}

/// The volume's files, made at its first mount and kept for the system's
/// life, as the device keeps them: the directories of [`DIRS`] and the
/// Cryptex1, each with its attributes' record (what a file made later gets
/// too). `system` reads a file of the system volume.
pub fn volume(system: SystemFile<'_>) -> Result<Arc<crate::vfs::tmpfs::TmpFs>, String> {
    VOLUME
        .get_or_init(|| {
            let fs = crate::vfs::tmpfs::TmpFs::new();
            for d in &DIRS {
                if !d.path.is_empty() {
                    fs.mkdir(d.path, d.owned.mode).map_err(|e| format!("making the Preboot volume's {}: {e:?}", d.path))?;
                }
                record(&fs, d.path, &d.owned)?;
            }
            lay_cryptex1(&fs, sources(), super::iokit::tree(), system)?;
            Ok(Arc::new(fs))
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_names_are_not_modelled() {
        assert!(unmodelled("active", false).is_some());
        assert!(unmodelled(&"A".repeat(HASH_DIGITS), false).is_some());
        assert!(unmodelled(&"a".repeat(HASH_DIGITS), false).is_none(), "the hash is in capitals");
        assert!(unmodelled(&"A".repeat(HASH_DIGITS - 1), false).is_none());
        assert!(unmodelled("Cryptexes", false).is_none());
        // No restore source in the unit tests: cryptex1 is reported.
        assert!(unmodelled("cryptex1/current", false).is_some());
        // Nor, on the booted system the unit tests run on, what the boot
        // cryptexes' grafts hold: below a graft directory, or its listing.
        assert!(unmodelled("Cryptexes/OS/System", false).is_some());
        assert!(unmodelled("Cryptexes/App/x", false).is_some());
        assert!(unmodelled("Cryptexes/OS", true).is_some());
        assert!(unmodelled("Cryptexes/OS", false).is_none());
        assert!(unmodelled("Cryptexes", true).is_none());
        assert!(unmodelled("Cryptexes/OSX/a", false).is_none());
    }

    #[test]
    fn the_restores_directories() {
        let fs = volume(&|_| Ok(None)).unwrap();
        for d in &DIRS {
            let mut buf = [0u8; 64];
            let n = fs.xattr(d.path, XattrOp::Get { name: super::super::vattr::RECORD, buf: &mut buf }).unwrap();
            assert_eq!(Owned::parse(&buf[..n]).unwrap(), d.owned);
            assert_eq!(fs.metadata(d.path).unwrap().file_type, crate::vfs::FileType::Directory);
        }
        let names: Vec<String> = fs.open("", 0, 0).unwrap().read_dir().unwrap().into_iter().map(|e| e.name).filter(|n| n != "." && n != "..").collect();
        assert_eq!(names, ["Cryptexes"]);
    }

    fn tree(ecid: &[u8]) -> Vec<super::super::iokit::Node> {
        fn prop(out: &mut Vec<u8>, name: &str, value: &[u8]) {
            let mut n = [0u8; 32];
            n[..name.len()].copy_from_slice(name.as_bytes());
            out.extend_from_slice(&n);
            out.extend_from_slice(&(value.len() as u32).to_le_bytes());
            out.extend_from_slice(value);
            out.resize((out.len() + 3) & !3, 0);
        }
        let mut b = Vec::new();
        b.extend_from_slice(&3u32.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());
        prop(&mut b, "name", b"device-tree\0");
        prop(&mut b, "compatible", b"J120AP\0iPad7,1\0AppleARM\0");
        prop(&mut b, "model", b"iPad7,1\0");
        b.extend_from_slice(&2u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        prop(&mut b, "name", b"chosen\0");
        prop(&mut b, "unique-chip-id", ecid);
        super::super::iokit::parse(&b).unwrap()
    }

    #[test]
    fn the_ticket_is_named_by_target_and_ecid() {
        assert_eq!(ticket_name_of(&tree(&0x0001_2345_6789_abcdu64.to_le_bytes())).unwrap(), "apticket.j120ap.123456789ABCD.im4m");
        assert_eq!(ticket_name_of(&tree(&[0; 8])).unwrap(), "apticket.j120ap.0.im4m");
        assert!(ticket_name_of(&tree(&[0; 4])).is_err());
    }

    fn manifest() -> Value {
        let id = |class: &str, variant: &str| {
            Value::Dict(vec![
                ("Info".into(), Value::Dict(vec![("DeviceClass".into(), Value::String(class.into())), ("Variant".into(), Value::String(variant.into()))])),
                ("Manifest".into(), Value::Dict(vec![("Cryptex1,SystemOS".into(), Value::Dict(vec![("Digest".into(), Value::Data(vec![1; 48]))]))])),
            ])
        };
        Value::Dict(vec![(
            "BuildIdentities".into(),
            Value::Array(vec![id("j121ap", cryptex1::ERASE_VARIANT), id("j120ap", "Customer Upgrade Install (IPSW)"), id("j120ap", cryptex1::ERASE_VARIANT)]),
        )])
    }

    #[test]
    fn the_erase_identity_is_written_alone() {
        let m = manifest();
        let id = erase_identity(&m, "j120ap").unwrap();
        assert_eq!(id, &m.get("BuildIdentities").unwrap().as_array().unwrap()[2]);
        assert!(erase_identity(&m, "j207ap").is_err());
        let x = restore_manifest(id);
        let back = plist::parse(&x).unwrap();
        assert_eq!(back.get("BuildIdentities").unwrap().as_array().unwrap(), std::slice::from_ref(id));
        assert!(String::from_utf8(x).unwrap().starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n\t<key>BuildIdentities</key>\n\t<array>\n\t\t<dict>\n\t\t\t<key>Info</key>\n"));
    }

    fn host_size(p: &str) -> Option<u64> {
        std::fs::metadata(p).ok().map(|m| m.len())
    }

    fn host_read(p: &str, off: u64, into: &mut [u8]) -> bool {
        use std::io::{Read, Seek, SeekFrom};
        let Ok(mut f) = std::fs::File::open(p) else { return false };
        f.seek(SeekFrom::Start(off)).is_ok() && f.read_exact(into).is_ok()
    }

    #[test]
    fn the_cryptex1_is_laid_out_as_the_restore_lays_it() {
        use sha2::Digest;
        let dir = std::env::temp_dir().join(format!("gex-preboot-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("Firmware")).unwrap();
        let (os, hash) = (b"an os image".to_vec(), b"a root hash".to_vec());
        std::fs::write(dir.join("os.dmg"), &os).unwrap();
        std::fs::write(dir.join("Firmware/os.dmg.root_hash"), &hash).unwrap();
        std::fs::write(dir.join("ticket"), b"IM4M").unwrap();
        let component = |path: &str, bytes: &[u8]| Value::Dict(vec![("Digest".into(), Value::Data(sha2::Sha384::digest(bytes).to_vec())), ("Info".into(), Value::Dict(vec![("Path".into(), Value::String(path.into()))]))]);
        let identity = Value::Dict(vec![
            ("Info".into(), Value::Dict(vec![("DeviceClass".into(), Value::String("j120ap".into())), ("Variant".into(), Value::String(cryptex1::ERASE_VARIANT.into()))])),
            ("Manifest".into(), Value::Dict(vec![("Cryptex1,SystemOS".into(), component("os.dmg", &os)), ("Cryptex1,SystemVolume".into(), component("Firmware/os.dmg.root_hash", &hash))])),
        ]);
        let m = Value::Dict(vec![("BuildIdentities".into(), Value::Array(vec![identity.clone()]))]);
        std::fs::write(dir.join("BuildManifest.plist"), plist::to_xml(&m)).unwrap();
        let d = dir.to_str().unwrap().to_string();
        let s = Sources { restore: Some(d.clone()), ticket: Ticket::File(format!("{d}/ticket")), nonce_hash: None, host: Some(Host { size: host_size, read: host_read, sha384: None }), web_device: None };
        let system = |p: &str| -> Result<Option<(Vec<u8>, Owned)>, String> {
            Ok(p.ends_with("SystemVersion.plist").then(|| (b"<plist/>".to_vec(), Owned { uid: 0, gid: 0, mode: 0o444, flags: 0x40 | 0x20 })))
        };
        let t = tree(&0xabcu64.to_le_bytes());
        let fs = crate::vfs::tmpfs::TmpFs::new();
        lay_cryptex1(&fs, &s, &t, &system).unwrap();
        let rec = |p: &str| {
            let mut buf = [0u8; 64];
            let n = fs.xattr(p, XattrOp::Get { name: super::super::vattr::RECORD, buf: &mut buf }).unwrap();
            Owned::parse(&buf[..n]).unwrap()
        };
        let mut names: Vec<String> = fs.open(cryptex1::CURRENT, 0, 0).unwrap().read_dir().unwrap().into_iter().map(|e| e.name).filter(|n| n != "." && n != "..").collect();
        names.sort();
        assert_eq!(names, ["BuildManifest.plist", "SystemVersion.plist", "apticket.j120ap.ABC.im4m", "os.dmg", "os.dmg.root_hash"]);
        assert_eq!(rec(cryptex1::DIR), Owned { uid: 0, gid: 0, mode: 0o777, flags: 0 });
        assert_eq!(rec(cryptex1::CURRENT), Owned { uid: 0, gid: 0, mode: 0o777, flags: 0 });
        assert_eq!(rec("cryptex1/current/os.dmg"), Owned { uid: 0, gid: 0, mode: 0o666, flags: 0 });
        assert_eq!(fs.metadata("cryptex1/current/os.dmg").unwrap().size, os.len() as u64);
        assert_eq!(rec("cryptex1/current/SystemVersion.plist"), Owned { uid: 0, gid: 0, mode: 0o444, flags: 0x20 }, "UF_TRACKED is not copied");
        assert_eq!(rec("cryptex1/current/apticket.j120ap.ABC.im4m").mode, FOUNDATION_MODE);
        let mut buf = vec![0u8; 1 << 16];
        let n = fs.open("cryptex1/current/BuildManifest.plist", 0, 0).unwrap().read_at(0, &mut buf).unwrap() as usize;
        assert_eq!(&buf[..n], &restore_manifest(&identity)[..]);
        // A file that is not the identity's is the restore's failure.
        std::fs::write(dir.join("os.dmg"), b"another image").unwrap();
        assert!(lay_cryptex1(&crate::vfs::tmpfs::TmpFs::new(), &s, &t, &system).unwrap_err().contains("digest mismatch"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The restore's manifest of the IPSW's erase identity, as macOS's
    /// CoreFoundation writes it (`plutil -convert xml1` of the same
    /// dictionary): its SHA-384.
    #[test]
    #[ignore = "needs GEX_DARWIN_RESTORE's BuildManifest.plist (21H461)"]
    fn the_ipsws_identity_is_written_as_core_foundation_writes_it() {
        use sha2::Digest;
        let dir = std::env::var("GEX_DARWIN_RESTORE").expect("GEX_DARWIN_RESTORE");
        let m = plist::parse(&std::fs::read(format!("{dir}/BuildManifest.plist")).unwrap()).unwrap();
        let x = restore_manifest(erase_identity(&m, "j120ap").unwrap());
        let h: [u8; 48] = sha2::Sha384::digest(&x).into();
        let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "3c1b3a01d78c5dccfd43c7518f61a4168bd93134d07bcbe6605e57ae197b094973651c0c3fa8cd1f0fa60a4b77f24459");
    }
}
