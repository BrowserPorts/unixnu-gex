//! The SEP core harness: what releasing the SEP core (CPU_CTRL's run bit)
//! must find in place, checked in the order a real boot needs it, and what
//! stands between it and running the real sepOS.
//!
//! The SEP core is a 32-bit ARMv7 core on the J120: the kernel registers
//! its core dumps as `CPU_TYPE_ARM`, `CPU_SUBTYPE_ARM_V7` unless the `sep`
//! node has an `aarch64` property, which it does not
//! (`drafts/sep/07-sep-core.md`, K 0xfffffff0063d88d8). A core runs only
//! when every input is the owner's real one:
//!
//! 1. the decrypted sepOS payload (`GEX_DARWIN_SEPOS`): the AP sends it to
//!    the SEP ROM, which decrypts it with the SEP's GID key and verifies
//!    its IMG4; the web device has neither, so the owner decrypts it;
//! 2. the SEP ROM (`GEX_DARWIN_SEPROM`): the AP's first protocol (status,
//!    BootTz0, Boot) is the ROM's, whose replies are not the AP's to make;
//! 3. the SEP's UID (the web device's `sep-uid.bin`): the AES engine's key;
//! 4. a core that can execute the image. gex's translators decode A64 only,
//!    and the SEP's peripherals (its side of the mailbox, the AES engine,
//!    the memory protection engine, its interrupt controller and timers)
//!    have no model: their registers are in the SEP ROM and the sepOS.
//!
//! Each gap fails the wait the AP is in with its own words
//! ([`super::manager::MgrError::CoreGone`]); nothing here replies in the
//! SEP's place.

use super::image::{ImageError, SepOsImage};
use super::secrets::{Missing, SepUid};
use std::path::PathBuf;

/// What the run was given of the SEP's inputs (`GEX_DARWIN_SEPOS`,
/// `GEX_DARWIN_SEPROM`, and the web device's directory).
#[derive(Clone, Debug, Default)]
pub struct Inputs {
    pub sepos: Option<PathBuf>,
    pub seprom: Option<PathBuf>,
    pub device_dir: Option<PathBuf>,
}

/// The SEP core's architecture, by the `aarch64` property of the `sep` node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    /// ARMv7 (ARM and Thumb-2), 32-bit: no `aarch64` property.
    Armv7,
    Aarch64,
}

impl Arch {
    pub fn of_device_tree(aarch64_property: bool) -> Arch {
        if aarch64_property {
            Arch::Aarch64
        } else {
            Arch::Armv7
        }
    }
}

/// What is missing for the SEP core to run.
#[derive(Debug)]
pub enum Gap {
    NoSepOs,
    BadSepOs(PathBuf, ImageError),
    NoSepRom,
    SepRomUnreadable(PathBuf, String),
    NoUid(Missing),
    /// Everything given: the core still cannot execute the image.
    NoTranslator(Arch),
}

impl std::fmt::Display for Gap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Gap::NoSepOs => f.write_str("the SEP needs the decrypted sepOS payload of sep-firmware.<board>.RELEASE.im4p (GEX_DARWIN_SEPOS=<file>): the sepOS is encrypted under the SEP's own GID key, which only a device's SEP ROM can use, so the owner decrypts it on a device"),
            Gap::BadSepOs(p, e) => write!(f, "GEX_DARWIN_SEPOS={} is not a decrypted sepOS payload: {e}", p.display()),
            Gap::NoSepRom => f.write_str("the SEP needs its boot ROM (GEX_DARWIN_SEPROM=<file>), which is in the A10X's mask ROM and is in no IPSW: the AP's boot protocol (status, BootTz0, Boot) is the ROM's, and its replies are not made up"),
            Gap::SepRomUnreadable(p, e) => write!(f, "GEX_DARWIN_SEPROM={}: {e}", p.display()),
            Gap::NoUid(m) => write!(f, "{m}"),
            Gap::NoTranslator(Arch::Armv7) => f.write_str("the SEP core is ARMv7 (the J120's sep node has no aarch64 property) and gex decodes A64 only: an AArch32 (ARM and Thumb-2) decoder, its lifter and a system-level model of the SEP's peripherals are not built (drafts/sep/07-sep-core.md)"),
            Gap::NoTranslator(Arch::Aarch64) => f.write_str("the SEP core is AArch64 (the sep node has an aarch64 property): gex's translator runs user-mode A64 and has no system-level model of the SEP's peripherals"),
        }
    }
}

/// What the harness holds once every input is there.
#[derive(Debug)]
pub struct Loaded {
    pub sepos: SepOsImage,
    pub seprom: Vec<u8>,
    pub uid: SepUid,
    pub arch: Arch,
}

/// The inputs checked in the order a boot needs them: the sepOS, the ROM,
/// the UID.
pub fn load(inputs: &Inputs, arch: Arch) -> Result<Loaded, Gap> {
    let Some(p) = &inputs.sepos else { return Err(Gap::NoSepOs) };
    let sepos = SepOsImage::load(p).map_err(|e| Gap::BadSepOs(p.clone(), e))?;
    let Some(r) = &inputs.seprom else { return Err(Gap::NoSepRom) };
    let seprom = std::fs::read(r).map_err(|e| Gap::SepRomUnreadable(r.clone(), e.to_string()))?;
    if seprom.is_empty() {
        return Err(Gap::SepRomUnreadable(r.clone(), "the file is empty".into()));
    }
    let uid = match &inputs.device_dir {
        Some(d) => SepUid::load(d).map_err(Gap::NoUid)?,
        None => return Err(Gap::NoUid(Missing::NoFile("no web device (GEX_DARWIN_WEB_DEVICE): the SEP's UID is a secret of the web device".into()))),
    };
    Ok(Loaded { sepos, seprom, uid, arch })
}

/// What runs when the SEP core is released: the checks, and then the
/// gap that remains. There is no core to run past them, so the result is
/// always the gap that ended the attempt.
pub fn release(inputs: &Inputs, arch: Arch) -> Gap {
    match load(inputs, arch) {
        Err(g) => g,
        Ok(l) => Gap::NoTranslator(l.arch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("gex-sep-core-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn structured(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i / 7 % 13) as u8).collect()
    }

    #[test]
    fn the_architecture_follows_the_aarch64_property() {
        assert_eq!(Arch::of_device_tree(false), Arch::Armv7);
        assert_eq!(Arch::of_device_tree(true), Arch::Aarch64);
    }

    #[test]
    fn without_a_sepos_the_gap_names_the_decrypted_firmware() {
        let g = release(&Inputs::default(), Arch::Armv7);
        let text = g.to_string();
        assert!(matches!(g, Gap::NoSepOs));
        assert!(text.contains("GEX_DARWIN_SEPOS") && text.contains("decrypted sepOS"), "{text}");
    }

    #[test]
    fn a_sepos_that_is_not_decrypted_is_refused_by_name() {
        let d = tmp("bad");
        let p = d.join("sepos.bin");
        std::fs::write(&p, []).unwrap();
        let g = release(&Inputs { sepos: Some(p.clone()), ..Default::default() }, Arch::Armv7);
        assert!(g.to_string().contains(&p.display().to_string()), "{g}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_rom_and_the_uid_are_checked_in_order() {
        let d = tmp("order");
        let sepos = d.join("sepos.bin");
        std::fs::write(&sepos, structured(100_000)).unwrap();
        let mut i = Inputs { sepos: Some(sepos), ..Default::default() };
        assert!(matches!(release(&i, Arch::Armv7), Gap::NoSepRom));
        let rom = d.join("seprom.bin");
        std::fs::write(&rom, [1, 2, 3]).unwrap();
        i.seprom = Some(rom);
        assert!(matches!(release(&i, Arch::Armv7), Gap::NoUid(_)));
        i.device_dir = Some(d.clone());
        assert!(matches!(release(&i, Arch::Armv7), Gap::NoUid(Missing::NoFile(_))));
        std::fs::write(d.join(crate::darwin::webdevice::files::SEP_UID), [9; 32]).unwrap();
        // Every input there: the core itself is what is missing.
        let g = release(&i, Arch::Armv7);
        assert!(matches!(g, Gap::NoTranslator(Arch::Armv7)), "{g}");
        assert!(g.to_string().contains("AArch32"));
        assert!(release(&i, Arch::Aarch64).to_string().contains("AArch64"));
        let _ = std::fs::remove_dir_all(&d);
    }
}
