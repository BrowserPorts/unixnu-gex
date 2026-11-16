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
//! The kext's evaluation of a firmware payload against its manifest, which
//! APFS asks for a cryptex's graft ([`super::graft`]), is not implemented:
//! it is reported ([`crate::syscalls::Kernel::darwin_img4_firmware_execute`]).

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
    // The long OS version: what the kext's parse (0xfffffff005a9dc3c) and
    // its string (0xfffffff005a9de9c) make of a `love` there is not
    // modelled; without one the string is empty.
    if dt_prop(t, MANIFEST_PROPERTIES, "love").is_some() {
        return Err("AppleImage4's ignition blob: the long OS version from /chosen/manifest-properties' love (its parse, 0xfffffff005a9dc3c, and its string, 0xfffffff005a9de9c)".into());
    }
    if let Some(u) = udid {
        blob[0x72..0x82].copy_from_slice(&u);
    }
    Ok(blob)
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

/// The `/chosen` values iBoot fills in at boot, which AppleImage4's AP chip
/// instance (the ignition blob, the Cryptex1 ticket's name) and restored
/// read: the IPSW's device tree has them zero or does not have them, and
/// they stand in until measured. A reported shortcut (storage::unmeasured).
pub const CHOSEN_STAND_IN: &str = "the /chosen values iBoot fills in (stand-in: the IPSW device tree's, chip-id, board-id, unique-chip-id, certificate-production-status, certificate-security-mode, effective-production-status-ap and effective-security-mode-ap zero, and no security-domain, chip-epoch, esdm-fuses or manifest-properties love: an ignition blob and a Cryptex1 ticket name of ECID 0; measure IODeviceTree:/chosen on the device, `ioreg -p IODeviceTree -n chosen -l`)";

impl crate::syscalls::Kernel {
    /// AppleImage4's evaluation of a payload against its Image4 manifest,
    /// as `validate_payload_and_manifest` asks it for a graft:
    /// `img4_firmware_new` (0xfffffff005a8e8f0) of the payload with its
    /// type and `sel`'s flags, `img4_firmware_attach_manifest`
    /// (0xfffffff005a8eb14), `img4_firmware_execute` (0xfffffff005a8edac)
    /// for `sel`'s chip, with the nonce when `sel` gives one, whose
    /// `root_hash_execution_cb` (0xfffffff006680dc8) leaves the status, 0
    /// with the authenticated payload; -1 when it is not called. The status
    /// is returned; `None` while the evaluation is not implemented
    /// (reported).
    pub(crate) fn darwin_img4_firmware_execute(&mut self, sel: super::graft::Selection, fourcc: u32, payload: &[u8], manifest: &[u8]) -> Option<Result<Vec<u8>, i32>> {
        let cc: String = fourcc.to_be_bytes().iter().map(|&b| if b.is_ascii_graphic() { b as char } else { '?' }).collect();
        self.darwin_unimplemented(format!(
            "Image4 evaluation of a '{cc}' payload ({} bytes) against its manifest ({} bytes) for {} (img4_firmware_execute, firmware flags {:#x})",
            payload.len(),
            manifest.len(),
            sel.chip.describe(),
            sel.firmware_flags
        ));
        None
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
        assert!(ignition_blob_of(&tree(&[("crypto-hash-method", b"sha2-384\0")], &[("love", b"21.8.461.0.0,0\0")])).is_err());
    }
}
