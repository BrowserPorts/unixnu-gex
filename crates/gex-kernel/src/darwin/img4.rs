//! AppleImage4's ignition blob (`security.mac.img4.ignition_blob`), which
//! libignition in launchd's dyld reads first thing (its
//! `configuration_init`): the device's identity as the kext's AP chip
//! instance has it, the secure boot level and the running OS's long
//! version, 0x84 bytes (the node's `oid_arg2`; its `oid_arg1` is the blob,
//! 0xfffffff006cf6b00, in 21H461's iPad7,1 kernelcache).
//!
//! The kext makes it once, in its start (0xfffffff005a94c4c, after it
//! registers its nodes), from its "darwin arm kernel" runtime, which reads
//! the device tree's `/chosen` and `/chosen/manifest-properties`:
//!
//! - The secure boot level (the runtime's 0xfffffff005a98f14): 0 without a
//!   `/chosen/asmb` node (a Mac's LocalPolicy boot modes, `lp-smb0` and
//!   `lp-smb1`, are read from it).
//! - The expert chip for that level (0xfffffff005a98f9c): by `/chosen`'s
//!   `crypto-hash-method`, "sha2-384" the personalized AP chip `2spa`, unless
//!   `/chosen` has `use-ddi-secure-boot`, `allow-ecid-mismatch` or
//!   `uses-avp-root-ca`, which choose others.
//! - Its instance (0xfffffff005a9f97c): each property descriptor with a
//!   place in the instance (the list at 0xfffffff006cf82f0) queried of the
//!   runtime, a property the device tree does not have left out (and zero).
//!   A property is read whole into a zeroed buffer of its size; one longer
//!   than that fails the instance (EOVERFLOW), which is the kext's panic.
//!   The unique device identifier is made of the chip and the ECID
//!   (0xfffffff005a9c914).
//!
//! What the blob holds (0xfffffff005a94d9c..0xfffffff005a94edc), all of it
//! zero but what is written:
//!
//! | offset | size | what |
//! |--------|------|------|
//! | 0x00 | 2 | never written |
//! | 0x02 | 4 x 4 | the instance's +0x10: chip epoch (`chip-epoch`), board (`board-id`), chip (`chip-id`), security domain (`security-domain`) |
//! | 0x12 | 8 | the ECID (`unique-chip-id`) |
//! | 0x1a | 4 x 4 | certificate production status and security mode, effective production status and security mode (`certificate-production-status`, `certificate-security-mode`, `effective-production-status-ap`, `effective-security-mode-ap`, each nonzero or not), each byte widened |
//! | 0x2a | 4 | the extended security domain (`esdm-fuses`) |
//! | 0x2e | 4 | the secure boot level (below 4) |
//! | 0x32 | 64 | the long OS version (`/chosen/manifest-properties`' `love`), a string; empty when the property is not there |
//! | 0x72 | 16 | the unique device identifier, when the instance has one |
//! | 0x82 | 2 | never written |
//!
//! libignition takes the ECID (0x12, the Cryptex1 ticket's name), the level
//! (0x2e) and the version (0x32) from it.
//!
//! Next to it, the ignition failure blob
//! (`security.mac.img4.ignition_failure_blob`, `oid_arg1` 0xfffffff007ae5b74,
//! `oid_arg2` 0xa0, the same kind), which libignition's `ignition_halt`
//! writes before it aborts (`ignition_write_BRA_blob`): zero until written,
//! and only its node reads or writes it. Its handler (0xfffffff005a94a9c)
//! lets the same tasks as the ignition blob's (the entitlement, or the init
//! process; else EPERM), with no gate; `sysctl_handle_opaque` of the 0xa0
//! bytes (out, and in when there is a new value), whose error it returns;
//! then, for every call that gets that far, a read as much as a write, it
//! writes the NVRAM keys of the table at 0xfffffff006cf6bf8 (the runtime's
//! 0xfffffff005a92c60: `IODTNVRAM::setProperties` of a one-key dictionary,
//! once the IONVRAM resource is published; a failure is logged and the
//! next key written) and forces an NVRAM sync (0xfffffff005a92f70, type 3:
//! `IONVRAM-FORCESYNCNOW-PROPERTY`, whose result is not looked at). What
//! libignition puts in it, and the keys:
//!
//! | offset | size | what | NVRAM key (system GUID) |
//! |--------|------|------|-------------------------|
//! | 0x00 | 2 | zero | |
//! | 0x02 | 24 | the boot spec's name | `ignition-failure-boot` |
//! | 0x1a | 24 | the stage's name | `ignition-failure-stage` |
//! | 0x32 | 8 | the error, a 64-bit integer | `ignition-failure-code` |
//! | 0x3a | 37 | the volume, "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE" | `ignition-failure-volume` |
//! | 0x5f | 64 | the halt's message | `ignition-failure-reason` |
//! | 0x9f | 1 | 0xaa | |
//!
//! and `recovery-boot-mode` = "ignition-failure" with its terminator (17
//! bytes), which sends the next boot to recovery.
//!
//! The kext's evaluation of a firmware payload against its manifest, which
//! APFS asks for a cryptex's graft ([`super::graft`]), is
//! [`super::image4`]'s for `CHIP_CRYPTEX1_BOOT_AP`, against this device
//! tree's `/chosen` and the device's cryptex1 boot nonce hash (the
//! measured one of a device of Apple's,
//! [`super::preboot::cryptex1_boot_nonce_hash`], or the web device's own,
//! [`super::webdevice`]); the other chips are
//! reported ([`crate::syscalls::Kernel::darwin_img4_firmware_execute`]).

use std::sync::Mutex;

use super::iokit::{dt_has, dt_prop, Node};

/// The blob's size: its node's `oid_arg2`.
pub const IGNITION_BLOB_SIZE: usize = 0x84;

/// The entitlement that lets a task read the blob (the init process may
/// without it).
pub const IGNITION_BLOB_ENTITLEMENT: &str = "com.apple.private.img4.ignition-blob";

const CHOSEN: &str = "IODeviceTree:/chosen";
const MANIFEST_PROPERTIES: &str = "IODeviceTree:/chosen/manifest-properties";
const EOVERFLOW: i32 = 84;

/// A property read as the runtime reads it (0xfffffff005a9280c): `None`
/// when it is not there, `Err` when it is longer than `size`, else its
/// bytes in `size` zeroed ones.
fn read(t: &[Node], path: &str, name: &str, size: usize) -> Result<Option<Vec<u8>>, i32> {
    let Some(v) = dt_prop(t, path, name) else { return Ok(None) };
    if v.len() > size {
        return Err(EOVERFLOW);
    }
    let mut b = vec![0u8; size];
    b[..v.len()].copy_from_slice(v);
    Ok(Some(b))
}

fn u32_of(b: &[u8]) -> u32 {
    u32::from_le_bytes(b[..4].try_into().unwrap())
}

/// The blob tree `t` gives, or why the kext would panic making it (or what
/// of it is not modelled).
pub fn ignition_blob_of(t: &[Node]) -> Result<[u8; IGNITION_BLOB_SIZE], String> {
    let panic = |what: &str, e: i32| format!("AppleImage4's ignition blob: the kext's start panics (failed to init ignition blob): {what}: {e}");
    if dt_has(t, "IODeviceTree:/chosen/asmb") {
        return Err("AppleImage4's ignition blob: the secure boot level of a device tree with /chosen/asmb (lp-smb0 and lp-smb1, a LocalPolicy's)".into());
    }
    let level = 0u32;
    let method = dt_prop(t, CHOSEN, "crypto-hash-method").ok_or_else(|| "AppleImage4's ignition blob: the kext's start panics: no /chosen crypto-hash-method (non-sensical crypto hash method)".to_string())?;
    if method.starts_with(b"sha1") {
        return Err("AppleImage4's ignition blob: the expert chip of a sha1 device".into());
    }
    if !method.starts_with(b"sha2-384") {
        return Err(format!("AppleImage4's ignition blob: the kext's start panics: non-sensical crypto hash method: {}", String::from_utf8_lossy(method)));
    }
    for other in ["use-ddi-secure-boot", "allow-ecid-mismatch", "uses-avp-root-ca"] {
        if dt_prop(t, CHOSEN, other).is_some() {
            return Err(format!("AppleImage4's ignition blob: the expert chip /chosen's {other} chooses"));
        }
    }
    let u32_prop = |name: &str| read(t, CHOSEN, name, 4).map(|o| o.map(|b| u32_of(&b))).map_err(|e| panic(name, e));
    let bool_prop = |name: &str| read(t, CHOSEN, name, 4).map(|o| o.map(|b| u32_of(&b) != 0)).map_err(|e| panic(name, e));
    let cepo = u32_prop("chip-epoch")?;
    let bord = u32_prop("board-id")?;
    let chip = u32_prop("chip-id")?;
    let sdom = u32_prop("security-domain")?;
    let ecid = read(t, CHOSEN, "unique-chip-id", 8).map_err(|e| panic("unique-chip-id", e))?.map(|b| u64::from_le_bytes(b[..8].try_into().unwrap()));
    let cpro = bool_prop("certificate-production-status")?;
    let csec = bool_prop("certificate-security-mode")?;
    let epro = bool_prop("effective-production-status-ap")?;
    let esec = bool_prop("effective-security-mode-ap")?;
    let esdm = u32_prop("esdm-fuses")?;
    // The research mode is in the instance but not the blob; a property too
    // long still fails the instance.
    bool_prop("research-enabled")?;
    let udid = match (chip, ecid) {
        (Some(c), Some(e)) => {
            let mut u = [0u8; 16];
            u[4..8].copy_from_slice(&c.to_be_bytes());
            u[8..16].copy_from_slice(&e.to_be_bytes());
            Some(u)
        }
        _ => None,
    };
    let mut blob = [0u8; IGNITION_BLOB_SIZE];
    for (i, v) in [cepo, bord, chip, sdom].into_iter().enumerate() {
        blob[0x02 + 4 * i..0x06 + 4 * i].copy_from_slice(&v.unwrap_or(0).to_le_bytes());
    }
    blob[0x12..0x1a].copy_from_slice(&ecid.unwrap_or(0).to_le_bytes());
    for (i, v) in [cpro, csec, epro, esec].into_iter().enumerate() {
        blob[0x1a + 4 * i..0x1e + 4 * i].copy_from_slice(&u32::from(v.unwrap_or(false)).to_le_bytes());
    }
    blob[0x2a..0x2e].copy_from_slice(&esdm.unwrap_or(0).to_le_bytes());
    blob[0x2e..0x32].copy_from_slice(&level.to_le_bytes());
    if let Some(s) = long_os_version(t)? {
        blob[0x32..0x32 + s.len()].copy_from_slice(&s);
    }
    if let Some(u) = udid {
        blob[0x72..0x82].copy_from_slice(&u);
    }
    Ok(blob)
}

/// The blob's long OS version, as the kext's start makes it: the
/// expert's version query (0xfffffff005a9c58c → the runtime's
/// 0xfffffff005a99b7c) reads `/chosen/manifest-properties`' `love`
/// (0xfffffff005a9c7a4 → the runtime's read, 0xfffffff005a9280c: into a
/// zeroed 64-byte buffer, EOVERFLOW when longer, its length the
/// property's), and the version parse (0xfffffff005a9dc3c) keeps it as a
/// string (0xfffffff005a9df64, libimage4's `cstring_init_with_buff`: a
/// trap for an empty one or one whose bytes hold a NUL within its length;
/// the first `min(length, 63)` bytes); the blob takes that string
/// (0xfffffff005a9de9c, `strlcpy` of 64). No `love` (ENOENT, or the
/// property's default) leaves it empty; another failure is the start's
/// panic. The parse's numbers (the components split at "," and ".") are
/// not in the blob.
fn long_os_version(t: &[Node]) -> Result<Option<Vec<u8>>, String> {
    let Some(v) = dt_prop(t, MANIFEST_PROPERTIES, "love") else { return Ok(None) };
    if v.len() > 64 {
        return Err(format!("AppleImage4's ignition blob: the kext's start panics (failed to init ignition blob): /chosen/manifest-properties' love: {EOVERFLOW}"));
    }
    let mut buf = [0u8; 64];
    buf[..v.len()].copy_from_slice(v);
    // strlen of the buffer: past its end when it holds no NUL, which is at
    // least the length.
    let strlen = buf.iter().position(|&c| c == 0).unwrap_or(64);
    if v.is_empty() || strlen < v.len() {
        return Err(format!("AppleImage4's ignition blob: the kext's start panics: /chosen/manifest-properties' love of {} bytes holds a string of {strlen} (the version's string trap, 0xfffffff005a9df64)", v.len()));
    }
    Ok(Some(buf[..v.len().min(63)].to_vec()))
}

/// The blob as it is now: made from the device tree when first asked
/// (the kext's start, which runs before any task), then what was written.
static BLOB: Mutex<Option<[u8; IGNITION_BLOB_SIZE]>> = Mutex::new(None);

/// The blob, or why there is none.
pub fn ignition_blob() -> Result<[u8; IGNITION_BLOB_SIZE], String> {
    let mut g = BLOB.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(b) = *g {
        return Ok(b);
    }
    let b = ignition_blob_of(super::iokit::tree())?;
    *g = Some(b);
    Ok(b)
}

/// A new blob, from a write of the node.
pub fn set_ignition_blob(b: [u8; IGNITION_BLOB_SIZE]) {
    *BLOB.lock().unwrap_or_else(|e| e.into_inner()) = Some(b);
}

/// The failure blob's size: its node's `oid_arg2`.
pub const IGNITION_FAILURE_BLOB_SIZE: usize = 0xa0;

/// The failure blob: zero in the kext's data until a write of its node.
static FAILURE_BLOB: Mutex<[u8; IGNITION_FAILURE_BLOB_SIZE]> = Mutex::new([0; IGNITION_FAILURE_BLOB_SIZE]);

/// The failure blob as it is now.
pub fn ignition_failure_blob() -> [u8; IGNITION_FAILURE_BLOB_SIZE] {
    *FAILURE_BLOB.lock().unwrap_or_else(|e| e.into_inner())
}

/// A new failure blob, from a write of its node.
pub fn set_ignition_failure_blob(b: [u8; IGNITION_FAILURE_BLOB_SIZE]) {
    *FAILURE_BLOB.lock().unwrap_or_else(|e| e.into_inner()) = b;
}

/// Apple's system variable GUID, the NVRAM keys' namespace.
const SYSTEM_GUID: &str = "40A0DDD2-77F8-4392-B4A3-1E7304206516";

/// The table at 0xfffffff006cf6bf8: each key's name in the system GUID,
/// and its value, a range of the failure blob (offset, length).
const FAILURE_KEYS: [(&str, usize, usize); 5] = [
    ("ignition-failure-boot", 0x02, 24),
    ("ignition-failure-stage", 0x1a, 24),
    ("ignition-failure-code", 0x32, 8),
    ("ignition-failure-volume", 0x3a, 37),
    ("ignition-failure-reason", 0x5f, 64),
];

/// The table's last key and its value, a string of the kext's
/// (0xfffffff0052d7f63, its terminator in the 17 bytes).
const RECOVERY_BOOT_MODE: (&str, &[u8; 17]) = ("recovery-boot-mode", b"ignition-failure\0");

/// What the failure blob's handler writes to NVRAM, in order: each key
/// (`GUID:name`) and its value's bytes.
pub fn ignition_failure_nvram(b: &[u8; IGNITION_FAILURE_BLOB_SIZE]) -> Vec<(String, Vec<u8>)> {
    let mut keys: Vec<(String, Vec<u8>)> = FAILURE_KEYS.iter().map(|&(name, at, len)| (format!("{SYSTEM_GUID}:{name}"), b[at..at + len].to_vec())).collect();
    keys.push((format!("{SYSTEM_GUID}:{}", RECOVERY_BOOT_MODE.0), RECOVERY_BOOT_MODE.1.to_vec()));
    keys
}

/// The failure blob as libignition fills it, for a report: its boot spec,
/// stage, error and message.
pub fn ignition_failure_summary(b: &[u8; IGNITION_FAILURE_BLOB_SIZE]) -> String {
    let text = |at: usize, len: usize| {
        let s = &b[at..at + len];
        String::from_utf8_lossy(&s[..s.iter().position(|&c| c == 0).unwrap_or(len)]).into_owned()
    };
    let code = i64::from_le_bytes(b[0x32..0x3a].try_into().expect("8 bytes"));
    format!("boot {:?}, stage {:?}, code {code}, volume {:?}, reason {:?}", text(0x02, 24), text(0x1a, 24), text(0x3a, 37), text(0x5f, 64))
}

/// The `/chosen` values iBoot fills in at boot, which AppleImage4's AP chip
/// instance (the ignition blob, the Cryptex1 ticket's name) and restored
/// read: the IPSW's device tree has them zero or does not have them, and
/// they stand in until measured. A reported shortcut (storage::unmeasured).
/// The `/chosen` stand-in's report: on the web device its boot fills in
/// its identity ([`super::webdevice::Identity::chosen`]), and the rest stands
/// in.
pub fn chosen_stand_in() -> &'static str {
    if super::webdevice::get().is_some() {
        WEB_DEVICE_CHOSEN_STAND_IN
    } else {
        CHOSEN_STAND_IN
    }
}

/// The `/chosen` values the web device's boot does not fill in yet.
pub const WEB_DEVICE_CHOSEN_STAND_IN: &str = "the /chosen values iBoot fills in beyond the web device's identity, its AP ticket's boot-manifest-hash, its NVRAM's boot-nonce, fsboot's boot-command (1) and the AP ticket's manifest properties the 21H461 readers name in /chosen/manifest-properties (love, BNCH, ECID) (stand-in: the IPSW device tree's, die-id, unique-device-id and random-seed zero, no esdm-fuses; in manifest-properties the ticket's other properties (BORD, CEPO, CHIP, CPRO, CSEC, SDOM, srvn, prtp, sdkp, tagt, tatp) not published and the Unused*Property placeholders left as they are, and manifest-object-properties left with its placeholders: iBoot (encrypted in the IPSW) is what decides them, and no 21H461 binary reads them; boot-manifest-hash and boot-nonce zero when the web device has no AP ticket or generator)";

pub const CHOSEN_STAND_IN: &str = "the /chosen values iBoot fills in (stand-in: the IPSW device tree's, chip-id, board-id, unique-chip-id, certificate-production-status, certificate-security-mode, effective-production-status-ap and effective-security-mode-ap zero, and no security-domain, chip-epoch, esdm-fuses, boot-command (iBoot's fsboot adds 1; without it AppleImage4's nonce magazine takes its preserve strategy) or manifest-properties love: an ignition blob, a Cryptex1 ticket name of ECID 0 and the platform UUID (gethostuuid, IOPlatformUUID) of ECID 0 and chip 0; measure IODeviceTree:/chosen on the device, `ioreg -p IODeviceTree -n chosen -l`)";

/// The chip environment AppleImage4 evaluates against: this device tree's
/// `/chosen`, as its runtime reads it ([`read`]), the device's cryptex1
/// boot nonce hash, and the anchor the boot payload has.
struct Device<'a> {
    tree: &'a [Node],
}

impl super::image4::Environment for Device<'_> {
    fn chosen(&self, name: &str, size: usize) -> Result<Option<Vec<u8>>, i32> {
        read(self.tree, CHOSEN, name, size)
    }

    /// The hash of the cryptex1 boot slot of the nonce magazine AppleImage4
    /// booted over the device's NVRAM; with no NVRAM, a device of Apple's
    /// has the measured one, and the web device none.
    fn cryptex1_boot_nonce_hash(&self, _domain: u32) -> Result<Vec<u8>, super::image4::Fail> {
        if let Some(h) = super::noncemag::running_cryptex1_boot_hash() {
            return h;
        }
        match super::webdevice::get() {
            Some(_) => Err(super::image4::Fail::Unmodelled("the web device's cryptex1 boot nonce: its nonce magazine is in its NVRAM, which its boot was not given (its nvram.bin)".into())),
            None => super::preboot::cryptex1_boot_nonce_hash().map_err(super::image4::Fail::Unmodelled),
        }
    }

    /// The web device's AppleImage4 trusts its platform's root; a device of
    /// Apple's, the root its kext embeds.
    fn anchor(&self) -> Result<Vec<u8>, String> {
        match super::webdevice::get() {
            Some(w) => Ok(w.root.clone()),
            None => super::image4::anchor(),
        }
    }
}

impl crate::syscalls::Kernel {
    /// AppleImage4's evaluation of a payload against its Image4 manifest,
    /// as `validate_payload_and_manifest` asks it for a graft:
    /// `img4_firmware_new` (0xfffffff005a8e8f0) of the payload with its
    /// type and `sel`'s flags, `img4_firmware_attach_manifest`
    /// (0xfffffff005a8eb14), `img4_firmware_execute` (0xfffffff005a8edac)
    /// for `sel`'s chip, with the nonce when `sel` gives one, whose
    /// `root_hash_execution_cb` (0xfffffff006680dc8) leaves the status, 0
    /// with the authenticated payload. The status is returned; `None` where
    /// what decides it is not implemented, or the kext panics (reported).
    pub(crate) fn darwin_img4_firmware_execute(&mut self, sel: super::graft::Selection, fourcc: u32, payload: &[u8], manifest: &[u8]) -> Option<Result<Vec<u8>, i32>> {
        use super::image4::Outcome;
        let cc: String = fourcc.to_be_bytes().iter().map(|&b| if b.is_ascii_graphic() { b as char } else { '?' }).collect();
        let what = format!("Image4 evaluation of a '{cc}' payload ({} bytes) against its manifest ({} bytes) for {}", payload.len(), manifest.len(), sel.chip.describe());
        if sel.chip != super::graft::Chip::Cryptex1BootAp || sel.pdi_nonce || sel.firmware_flags != 0 {
            self.darwin_unimplemented(format!("{what} (img4_firmware_execute, firmware flags {:#x})", sel.firmware_flags));
            return None;
        }
        match super::image4::execute(fourcc, payload, manifest, &Device { tree: super::iokit::tree() }) {
            Outcome::Authenticated(data) => Some(Ok(data)),
            Outcome::Status(s) => Some(Err(s)),
            Outcome::Panic(why) => {
                self.darwin_unimplemented(format!("{what}: the kext panics ({why})"));
                None
            }
            Outcome::Unmodelled(why) => {
                self.darwin_unimplemented(format!("{what}: {why}"));
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::darwin::iokit::parse;

    fn prop(out: &mut Vec<u8>, name: &str, value: &[u8]) {
        let mut n = [0u8; 32];
        n[..name.len()].copy_from_slice(name.as_bytes());
        out.extend_from_slice(&n);
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value);
        out.resize((out.len() + 3) & !3, 0);
    }

    fn node(b: &mut Vec<u8>, name: &str, props: &[(&str, &[u8])], children: u32) {
        b.extend_from_slice(&(props.len() as u32 + 1).to_le_bytes());
        b.extend_from_slice(&children.to_le_bytes());
        prop(b, "name", format!("{name}\0").as_bytes());
        for (k, v) in props {
            prop(b, k, v);
        }
    }

    fn tree(chosen: &[(&str, &[u8])], manifest: &[(&str, &[u8])]) -> Vec<Node> {
        let mut b = Vec::new();
        node(&mut b, "device-tree", &[("compatible", b"J120AP\0iPad7,1\0AppleARM\0")], 1);
        node(&mut b, "chosen", chosen, 1);
        node(&mut b, "manifest-properties", manifest, 0);
        parse(&b).unwrap()
    }

    #[test]
    fn the_blob_holds_the_chip_instance() {
        let ecid = 0x0012_3456_789a_bcdeu64.to_le_bytes();
        let t = tree(
            &[
                ("crypto-hash-method", b"sha2-384\0"),
                ("chip-epoch", &1u32.to_le_bytes()),
                ("board-id", &0x0cu32.to_le_bytes()),
                ("chip-id", &0x8011u32.to_le_bytes()),
                ("security-domain", &1u32.to_le_bytes()),
                ("unique-chip-id", &ecid),
                ("certificate-production-status", &1u32.to_le_bytes()),
                ("certificate-security-mode", &0u32.to_le_bytes()),
                ("effective-production-status-ap", &7u32.to_le_bytes()),
                ("effective-security-mode-ap", &1u32.to_le_bytes()),
                ("esdm-fuses", &2u32.to_le_bytes()),
            ],
            &[],
        );
        let b = ignition_blob_of(&t).unwrap();
        assert_eq!(b.len(), 0x84);
        assert_eq!(&b[0..2], &[0, 0]);
        let w = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        assert_eq!([w(0x02), w(0x06), w(0x0a), w(0x0e)], [1, 0x0c, 0x8011, 1]);
        assert_eq!(&b[0x12..0x1a], &ecid);
        assert_eq!([w(0x1a), w(0x1e), w(0x22), w(0x26)], [1, 0, 1, 1]);
        assert_eq!(w(0x2a), 2);
        assert_eq!(w(0x2e), 0, "no /chosen/asmb: level 0");
        assert!(b[0x32..0x72].iter().all(|&c| c == 0), "no love: an empty version");
        assert_eq!(&b[0x72..0x82], &[0, 0, 0, 0, 0, 0, 0x80, 0x11, 0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde]);
        assert_eq!(&b[0x82..], &[0, 0]);
    }

    #[test]
    fn what_is_not_there_is_zero_and_what_is_too_long_panics() {
        let t = tree(&[("crypto-hash-method", b"sha2-384\0"), ("board-id", &[3])], &[]);
        let b = ignition_blob_of(&t).unwrap();
        assert_eq!(b[0x06], 3, "a short property is read into zeroes");
        assert!(b[0x72..0x82].iter().all(|&c| c == 0), "no chip or ECID: no device identifier");
        let t = tree(&[("crypto-hash-method", b"sha2-384\0"), ("chip-id", &[0; 8])], &[]);
        assert!(ignition_blob_of(&t).unwrap_err().contains("panics"));
        assert!(ignition_blob_of(&tree(&[], &[])).is_err(), "no hash method");
        assert!(ignition_blob_of(&tree(&[("crypto-hash-method", b"sha2-384\0"), ("allow-ecid-mismatch", b"")], &[])).is_err());
        // A love whose length runs past its string's NUL is the version
        // string's trap, as are an empty one and one too long to read.
        let sha = [("crypto-hash-method", &b"sha2-384\0"[..])];
        assert!(ignition_blob_of(&tree(&sha, &[("love", b"21.8.461.0.0,0\0")])).unwrap_err().contains("panics"));
        assert!(ignition_blob_of(&tree(&sha, &[("love", b"")])).unwrap_err().contains("panics"));
        assert!(ignition_blob_of(&tree(&sha, &[("love", &[b'1'; 65])])).unwrap_err().contains("panics"));
    }

    /// The long OS version is the manifest's love as a string: its bytes
    /// when they hold no NUL, the first 63 of a 64-byte one.
    #[test]
    fn the_blob_holds_the_manifests_long_os_version() {
        let sha = [("crypto-hash-method", &b"sha2-384\0"[..])];
        let b = ignition_blob_of(&tree(&sha, &[("love", b"21.8.461.0.0,0")])).unwrap();
        assert_eq!(&b[0x32..0x40], b"21.8.461.0.0,0");
        assert!(b[0x40..0x72].iter().all(|&c| c == 0));
        let b = ignition_blob_of(&tree(&sha, &[("love", &[b'7'; 64])])).unwrap();
        assert_eq!(&b[0x32..0x71], &[b'7'; 63][..]);
        assert_eq!(b[0x71], 0, "the string's terminator");
    }

    /// libignition's `ignition_write_BRA_blob`: the boot spec's and the
    /// stage's names, the error, the volume placeholder, the message and
    /// 0xaa past it; the keys take their ranges, and recovery-boot-mode
    /// its string.
    #[test]
    fn the_failure_blob_goes_to_its_nvram_keys() {
        let mut b = [0u8; IGNITION_FAILURE_BLOB_SIZE];
        b[0x02..0x07].copy_from_slice(b"local");
        b[0x1a..0x1f].copy_from_slice(b"graft");
        b[0x32..0x3a].copy_from_slice(&2i64.to_le_bytes());
        b[0x3a..0x5e].copy_from_slice(b"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE");
        let reason = b"failed to open canonical cryptex location";
        b[0x5f..0x5f + reason.len()].copy_from_slice(reason);
        b[0x9f] = 0xaa;
        let keys = ignition_failure_nvram(&b);
        let names: Vec<&str> = keys.iter().map(|(k, _)| k.strip_prefix("40A0DDD2-77F8-4392-B4A3-1E7304206516:").unwrap()).collect();
        assert_eq!(names, ["ignition-failure-boot", "ignition-failure-stage", "ignition-failure-code", "ignition-failure-volume", "ignition-failure-reason", "recovery-boot-mode"]);
        let lens: Vec<usize> = keys.iter().map(|(_, v)| v.len()).collect();
        assert_eq!(lens, [24, 24, 8, 37, 64, 17]);
        assert_eq!(&keys[0].1[..6], b"local\0");
        assert_eq!(keys[2].1, 2i64.to_le_bytes());
        assert_eq!(keys[3].1[36], 0, "the volume's terminator");
        assert!(keys[4].1.iter().all(|&c| c != 0xaa), "0x9f is no key's");
        assert_eq!(keys[5].1, b"ignition-failure\0");
        assert_eq!(
            ignition_failure_summary(&b),
            "boot \"local\", stage \"graft\", code 2, volume \"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE\", reason \"failed to open canonical cryptex location\""
        );
        // Zero until written.
        assert_eq!(ignition_failure_summary(&[0; IGNITION_FAILURE_BLOB_SIZE]), "boot \"\", stage \"\", code 0, volume \"\", reason \"\"");
    }
}
