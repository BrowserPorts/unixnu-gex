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
//! 4. a core that can execute the image: gex's AArch32 front end (the
//!    decoder `gex-isa-a32`, the lifter `gex-lift-a32`, the system-level
//!    model `gex-a32`, run by `gex-a32-host`) executes ARMv7 code; what it
//!    is not given is the SEP's platform ([`Platform`]: where the ROM, the
//!    SRAM and TZ0 are in the core's physical address space, how the
//!    decrypted sepOS enters it, the core's IMPLEMENTATION DEFINED identity
//!    and optional extensions), and the SEP's peripherals (its side of the
//!    mailbox, the AES engine, the PKA, the TRNG, the memory protection
//!    engine, its interrupt controller and timers) have no model: all of
//!    them are in the SEP ROM and the sepOS.
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
    /// The core is AArch64: gex has no system-level A64 model.
    NoA64SystemModel,
    /// Everything given: the SEP's platform, which no input gives, is not
    /// known ([`Platform`]); the list names each missing part.
    NoPlatform(Vec<&'static str>),
    /// The core's configuration is one the AArch32 model refuses.
    CoreModel(gex_a32::Stop),
    /// The core is set up ([`Boot`]): the SEP's peripherals, which the ROM
    /// and the sepOS reach at once, have no model.
    NoPeripherals,
}

impl std::fmt::Display for Gap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Gap::NoSepOs => f.write_str("the SEP needs the decrypted sepOS payload of sep-firmware.<board>.RELEASE.im4p (GEX_DARWIN_SEPOS=<file>): the sepOS is encrypted under the SEP's own GID key, which only a device's SEP ROM can use, so the owner decrypts it on a device"),
            Gap::BadSepOs(p, e) => write!(f, "GEX_DARWIN_SEPOS={} is not a decrypted sepOS payload: {e}", p.display()),
            Gap::NoSepRom => f.write_str("the SEP needs its boot ROM (GEX_DARWIN_SEPROM=<file>), which is in the A10X's mask ROM and is in no IPSW: the AP's boot protocol (status, BootTz0, Boot) is the ROM's, and its replies are not made up"),
            Gap::SepRomUnreadable(p, e) => write!(f, "GEX_DARWIN_SEPROM={}: {e}", p.display()),
            Gap::NoUid(m) => write!(f, "{m}"),
            Gap::NoA64SystemModel => f.write_str("the SEP core is AArch64 (the sep node has an aarch64 property): gex's translator runs user-mode A64 and has no system-level A64 model"),
            Gap::NoPlatform(missing) => write!(f, "the SEP core is ARMv7 and gex's AArch32 front end can run it, but the SEP's platform is not known: {} (in the SEP ROM and the sepOS; drafts/sep/07-sep-core.md)", missing.join("; ")),
            Gap::CoreModel(s) => write!(f, "the SEP core's configuration is not one gex's AArch32 model implements: {s:?}"),
            Gap::NoPeripherals => f.write_str("the SEP core is set up, but its peripherals (the SEP side of the mailbox, the AES engine with the UID and GID keys, the PKA, the TRNG, the memory protection engine over TZ0, the interrupt controller, the timers) have no model: their registers are in the SEP ROM and the sepOS"),
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

/// What running the core needs that no input gives: the SEP's physical
/// memory map and the core's identity.
#[derive(Clone, Debug)]
pub struct Platform {
    /// Where the boot ROM is in the core's physical address space.
    pub rom_pa: u64,
    /// The SEP's SRAM: physical address and size.
    pub sram: (u64, u64),
    /// TZ0, the SEP's DRAM carve-out, as the core sees it: its physical
    /// address, and its size (the sepi image's `tz0s`, 0xd38000 on J120).
    pub tz0: (u64, u64),
    /// Where the decrypted sepOS payload is in the core's memory when the
    /// ROM hands over to it (the ROM's own decryption, which the web
    /// device cannot do, is what would put it there).
    pub sepos_pa: u64,
    /// The core: its optional extensions and IMPLEMENTATION DEFINED values.
    pub config: gex_a32::Config,
}

/// The SEP's platform, as far as the evidence gives it. The AP's binaries
/// say only that the core is ARMv7 with 4 KiB pages (07-sep-core.md §1);
/// everything [`Platform`] holds is in the SEP ROM and the sepOS.
pub fn platform() -> Result<Platform, Gap> {
    Err(Gap::NoPlatform(vec![
        "the physical addresses of the ROM, the SRAM and TZ0",
        "where the decrypted sepOS is placed for the ROM to hand over to it",
        "the core's identity (MIDR and the ID registers) and its optional extensions (Floating-point and Advanced SIMD, the divide instructions, the Security Extensions)",
        "the core's reset configuration inputs (SCTLR.V, TE, EE, NMFI)",
    ]))
}

/// A memory region of the SEP's core, with what it holds at reset.
#[derive(Clone, Debug)]
pub struct BootRegion {
    pub pa: u64,
    pub size: u64,
    pub writable: bool,
    /// Bytes at its start; the rest is zero.
    pub init: Vec<u8>,
}

/// The core set up to run: its model, reset, and its memory.
pub struct Boot {
    pub core: gex_a32::Core,
    pub regions: Vec<BootRegion>,
}

/// Set the core up on `platform`: the model of the core (refused where it
/// does not implement the configuration), the ROM read-only at its
/// address, the SRAM, and TZ0 holding the decrypted sepOS where the
/// platform says the ROM leaves it.
pub fn boot(l: &Loaded, p: &Platform) -> Result<Boot, Gap> {
    let core = gex_a32::Core::new(p.config.clone()).map_err(Gap::CoreModel)?;
    let (tz0_pa, tz0_size) = p.tz0;
    let at = p.sepos_pa.checked_sub(tz0_pa).filter(|o| o + l.sepos.bytes.len() as u64 <= tz0_size).ok_or_else(|| {
        Gap::NoPlatform(vec!["a sepOS placement inside TZ0 (the platform's does not hold the payload)"])
    })?;
    let mut tz0 = vec![0u8; at as usize];
    tz0.extend_from_slice(&l.sepos.bytes);
    Ok(Boot {
        core,
        regions: vec![
            BootRegion { pa: p.rom_pa, size: l.seprom.len() as u64, writable: false, init: l.seprom.clone() },
            BootRegion { pa: p.sram.0, size: p.sram.1, writable: true, init: Vec::new() },
            BootRegion { pa: tz0_pa, size: tz0_size, writable: true, init: tz0 },
        ],
    })
}

/// What runs when the SEP core is released: the checks, the platform and
/// the core's set-up, and then the gap that remains. Nothing runs the
/// core past them yet, so the result is always the gap that ended the
/// attempt.
pub fn release(inputs: &Inputs, arch: Arch) -> Gap {
    let l = match load(inputs, arch) {
        Err(g) => return g,
        Ok(l) => l,
    };
    if l.arch == Arch::Aarch64 {
        return Gap::NoA64SystemModel;
    }
    let p = match platform() {
        Err(g) => return g,
        Ok(p) => p,
    };
    match boot(&l, &p) {
        Err(g) => g,
        Ok(_) => Gap::NoPeripherals,
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
        // Every input there: the platform is what is missing.
        let g = release(&i, Arch::Armv7);
        assert!(matches!(g, Gap::NoPlatform(_)), "{g}");
        assert!(g.to_string().contains("AArch32 front end") && g.to_string().contains("ROM"), "{g}");
        assert!(matches!(release(&i, Arch::Aarch64), Gap::NoA64SystemModel));
        let _ = std::fs::remove_dir_all(&d);
    }

    fn loaded() -> Loaded {
        let d = tmp("boot");
        std::fs::write(d.join(crate::darwin::webdevice::files::SEP_UID), [7; 32]).unwrap();
        let uid = SepUid::load(&d).unwrap();
        let _ = std::fs::remove_dir_all(&d);
        Loaded {
            sepos: SepOsImage { path: PathBuf::from("sepos"), bytes: vec![0xaa; 64] },
            seprom: vec![0xfe, 0xff, 0xff, 0xea],
            uid,
            arch: Arch::Armv7,
        }
    }

    fn armv7() -> gex_a32::Config {
        let mut features = gex_a32::Features::BASE;
        features.mp = true;
        gex_a32::Config { features, imp: gex_a32::ImpDef::default() }
    }

    #[test]
    fn a_platform_sets_the_core_up_and_the_peripherals_are_the_next_gap() {
        let p = Platform { rom_pa: 0, sram: (0x1000_0000, 0x1_0000), tz0: (0x8000_0000, 0xd3_8000), sepos_pa: 0x8000_4000, config: armv7() };
        let b = boot(&loaded(), &p).expect("set up");
        assert_eq!(b.regions.len(), 3);
        assert_eq!(b.regions[0].init, vec![0xfe, 0xff, 0xff, 0xea]);
        assert!(!b.regions[0].writable);
        assert_eq!(&b.regions[2].init[0x4000..], &[0xaa; 64][..]);
        // A sepOS placed outside TZ0 is refused by name.
        let bad = Platform { sepos_pa: 0x7000_0000, ..p };
        assert!(matches!(boot(&loaded(), &bad), Err(Gap::NoPlatform(_))));
    }

    #[test]
    fn a_configuration_the_model_does_not_implement_is_named() {
        let mut c = armv7();
        c.features.security = true;
        let p = Platform { rom_pa: 0, sram: (0x1000_0000, 0x1_0000), tz0: (0x8000_0000, 0xd3_8000), sepos_pa: 0x8000_0000, config: c };
        match boot(&loaded(), &p) {
            Err(Gap::CoreModel(_)) => {}
            other => panic!("{:?}", other.err()),
        }
    }
}
