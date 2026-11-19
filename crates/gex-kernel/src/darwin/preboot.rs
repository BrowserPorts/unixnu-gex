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
//!   O_TRUNC, class -1, 0644)` (0x100047ab0, given its class by the caller
//!   at 0x100057078): `PROTECTION_CLASS_DEFAULT`, for which XNU's
//!   `openat_dprotected_internal` sets no class, so APFS gives the file the
//!   volume's default, class C (K 0x6737260). It holds the AP ticket's hash
//!   in hexadecimal capitals (0x100065728) by `/chosen`'s
//!   `crypto-hash-method` (sha2-384: 96 digits).
//! - The directory named by that hash (`"%s/%@"`, 0x10004bf94), which the
//!   boot objects, the root hash and the firmware go under.
//! - `cryptex1` ([`cryptex1`]): `install_splat` (0x10003af24) puts the
//!   Cryptex1 there when the build identity has a `Cryptex1,` component
//!   (0x100063fbc), as J120's has.
//!
//! The restore model writes these to the Preboot volume of disk0
//! ([`super::apfswrite::restore`]), and the system serves the volume's
//! files as the disk0 image holds them ([`super::graftfs::GraftFs::live`]).
//! What stays here is what both take from the device and the IPSW: the
//! Cryptex1's layout ([`cryptex1`]), its build identity and ticket's name,
//! the boot cryptexes libignition grafts ([`BOOTED_GRAFTS`]), and the
//! device's cryptex1 boot nonce hash.

use super::plist::{self, Value};
use std::sync::OnceLock;

/// How many hexadecimal digits the ticket hash's name has: SHA-384's 48
/// bytes, `/chosen`'s `crypto-hash-method` being "sha2-384".
pub const HASH_DIGITS: usize = 96;

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

/// Whose Cryptex1 ticket the system boots with (the ticket itself is the
/// one the restore wrote to the Preboot volume): the web device's pairs
/// with its identity in `/chosen` ([`super::boot`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Ticket {
    /// None is configured.
    #[default]
    Unset,
    /// A device of Apple's own, a file the owner copied from its Preboot
    /// volume (GEX_DARWIN_CRYPTEX1_TICKET=path).
    File(String),
    /// The web device's own (GEX_DARWIN_CRYPTEX1_TICKET=web-device): the one
    /// its manifest key signed for it ([`super::webdevice`]).
    WebDevice,
}

/// What the Cryptex1's evaluation takes from the device: its ticket's
/// source and its cryptex1 boot nonce hash.
#[derive(Clone, Debug, Default)]
pub struct Sources {
    pub ticket: Ticket,
    /// The device's current cryptex1 boot nonce hash, hexadecimal
    /// (GEX_DARWIN_CRYPTEX1_NONCE_HASH): what its AppleImage4 makes of the
    /// nonce in its NVRAM, a measured input ([`cryptex1_boot_nonce_hash`]).
    pub nonce_hash: Option<String>,
    /// The web device the system boots as (GEX_DARWIN_WEB_DEVICE), with
    /// [`Ticket::WebDevice`].
    pub web_device: Option<super::webdevice::WebDevice>,
}

static SOURCES: OnceLock<Sources> = OnceLock::new();

/// The sources, once at boot.
pub fn set_sources(s: Sources) -> Result<(), String> {
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

fn sources() -> &'static Sources {
    static NONE: OnceLock<Sources> = OnceLock::new();
    SOURCES.get().unwrap_or_else(|| NONE.get_or_init(Sources::default))
}

/// The Cryptex1 ticket's name (`_ticket_file_name_personalized`,
/// 0x100064b30): "apticket.%@.%llX.im4m" of `hw.target` lowercased
/// ("x86legacyap" when it has none) and `IODeviceTree:/chosen`'s
/// `unique-chip-id`, the ECID.
pub fn ticket_name() -> Result<String, String> {
    ticket_name_of(super::iokit::tree())
}

/// [`ticket_name`] of device tree `t`.
/// `_ticket_file_name_personalized` (restored_external 0x100064b30): the
/// `hw.target` sysctl lowered, "x86legacyap" when it is empty
/// (0x100064bc4..0x100064bec), and `/chosen`'s `unique-chip-id` as a
/// native u64 in `%llX`, 0 when /chosen has none (0x100064c28 →
/// 0x100064cd4).
pub fn ticket_name_of(t: &[super::iokit::Node]) -> Result<String, String> {
    let target = super::iokit::target_name_of(t).filter(|n| !n.is_empty()).map_or_else(|| "x86legacyap".to_string(), |n| String::from_utf8_lossy(&n).to_lowercase());
    let ecid = match super::iokit::dt_prop(t, "IODeviceTree:/chosen", "unique-chip-id") {
        None => 0,
        Some(v) => u64::from_le_bytes(v.get(..8).ok_or("the Cryptex1 ticket's name: /chosen's unique-chip-id is shorter than 8 bytes")?.try_into().unwrap()),
    };
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

#[cfg(test)]
mod tests {
    use super::*;

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
