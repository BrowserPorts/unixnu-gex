//! `gexc darwin-disk0 <out> [<os.dmg> [<ipsw-dir>]]`: the web device's
//! disk0 made as its erase restore makes it
//! (`gex_kernel::darwin::apfswrite::restore`), written to a new sparse file
//! of the device's size, the IPSW's operating system image
//! (044-76040-038.dmg) restored into it when given, and the boot objects
//! install_kernel_cache installs and the canonical metadata and root hash
//! the seal takes read from the extracted IPSW at `<ipsw-dir>` when given;
//! the restore steps it does not have yet are
//! listed in `<out>.missing`.
//!
//! With the IPSW's boot objects the restore is of a device, named as the
//! boot names it:
//!
//! - `GEX_DARWIN_CRYPTEX1_TICKET=web-device` with
//!   `GEX_DARWIN_WEB_DEVICE=<dir>`: the web device, whose identity iBoot
//!   puts in the restore device tree's `/chosen` as its boot does, and
//!   whose manifest key plays TSS's part for install_splat's Cryptex1
//!   ticket, signed for its current cryptex1 boot nonce;
//! - `GEX_DARWIN_CRYPTEX1_TICKET=<path>`: a device of Apple's, its own
//!   Cryptex1 ticket as its restore wrote it
//!   (`apticket.j120ap.<ECID>.im4m`, copied from its Preboot volume's
//!   `cryptex1/current`), the ECID its name holds being the one iBoot put
//!   in that restore's `/chosen`.

use anyhow::{anyhow, bail, Context, Result};
use gex_kernel::darwin::{apfswrite, image4, iokit, preboot, storage, webdevice};
use std::path::Path;
use std::process::ExitCode;

/// The device restored with the boot objects `boot`, from the run's
/// environment: the restore device tree from the IPSW's IM4P with
/// `/chosen` filled in for it, and its Cryptex1 ticket.
fn device(boot: &apfswrite::restore::BootObjects) -> Result<apfswrite::restore::Device> {
    let source = std::env::var("GEX_DARWIN_CRYPTEX1_TICKET").ok().filter(|s| !s.is_empty());
    let web = std::env::var_os("GEX_DARWIN_WEB_DEVICE").filter(|v| !v.is_empty()).map(std::path::PathBuf::from);
    let bytes = apfswrite::restore::restore_device_tree(&boot.devicetree).map_err(|e| anyhow!("Firmware/all_flash/DeviceTree.j120ap.im4p: {e}"))?;
    let mut tree = iokit::parse(&bytes).map_err(|e| anyhow!("the restore device tree: {e}"))?;
    let target = iokit::target_name_of(&tree).map(|n| String::from_utf8_lossy(&n).to_lowercase()).ok_or_else(|| anyhow!("the restore device tree's root has no compatible"))?;
    let ticket = match (source.as_deref(), web) {
        (None, _) => bail!("install_splat needs the device's Cryptex1 ticket: GEX_DARWIN_CRYPTEX1_TICKET is not set (web-device, with GEX_DARWIN_WEB_DEVICE, or the path of the device's apticket.{target}.<ECID>.im4m)"),
        (Some("web-device"), None) => bail!("the Cryptex1 ticket is the web device's (GEX_DARWIN_CRYPTEX1_TICKET=web-device), but no web device is configured (GEX_DARWIN_WEB_DEVICE)"),
        (Some("web-device"), Some(dir)) => {
            let w = crate::darwin_web::load(&dir)?;
            iokit::fill_chosen(&mut tree, &w.identity.chosen()).map_err(|e| anyhow!("the restore device tree: {e}"))?;
            let manifest = gex_kernel::darwin::plist::parse(&boot.manifest).map_err(|e| anyhow!("BuildManifest.plist: {e}"))?;
            let build = preboot::erase_identity(&manifest, &target).map_err(|e| anyhow!("{e}"))?;
            // The nonce's hash as AppleImage4 makes it, entangled when the
            // device tree's /defaults asks.
            let entangle = iokit::dt_prop(&tree, "IODeviceTree:/defaults", "entangle-nonce").is_some();
            let cnch = webdevice::nonce_hash(&w, entangle).map_err(|e| anyhow!("the web device's cryptex1 boot nonce hash: {e:?}"))?;
            let ticket = crate::darwin_web::signed_cryptex1_ticket(&dir, &w, build, &cnch, &boot.dir)?;
            let hex: String = cnch.iter().map(|b| format!("{b:02x}")).collect();
            eprintln!("gexc: install_splat's Cryptex1 ticket: the web device's (ECID {:X}), signed by its manifest key for cryptex1 boot nonce hash {hex}, {} bytes", w.identity.ecid, ticket.len());
            ticket
        }
        (Some(_), Some(_)) => bail!("a web device is configured (GEX_DARWIN_WEB_DEVICE), but the Cryptex1 ticket is not its own (GEX_DARWIN_CRYPTEX1_TICKET=web-device)"),
        (Some(path), None) => {
            let p = Path::new(path);
            let name = p.file_name().and_then(|n| n.to_str()).ok_or_else(|| anyhow!("{path}: not a ticket file's name"))?;
            // `_ticket_file_name_personalized`'s "apticket.%@.%llX.im4m".
            let hex = name
                .strip_prefix(&format!("apticket.{target}."))
                .and_then(|r| r.strip_suffix(".im4m"))
                .filter(|h| !h.is_empty() && h.len() <= 16 && h.bytes().all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(&c)) && (h.len() == 1 || !h.starts_with('0')))
                .ok_or_else(|| anyhow!("{path}: not named as the device's restore names its Cryptex1 ticket (apticket.{target}.<ECID in capital hexadecimal>.im4m)"))?;
            let ecid = u64::from_str_radix(hex, 16).map_err(|e| anyhow!("{path}: {e}"))?;
            let ticket = std::fs::read(p).with_context(|| format!("reading {path}"))?;
            let theirs = image4::manifest_property(&ticket, image4::fourcc(b"ECID"), image4::tag::INTEGER)
                .and_then(image4::der::integer64)
                .map_err(|e| anyhow!("{path}: not a Cryptex1 ticket with an ECID (libDER {e})"))?;
            if theirs != ecid {
                bail!("{path}: the ticket is personalized for ECID {theirs:X}, not the {ecid:X} its name gives");
            }
            iokit::fill_chosen(&mut tree, &[("unique-chip-id", ecid.to_le_bytes().to_vec())]).map_err(|e| anyhow!("the restore device tree: {e}"))?;
            eprintln!("gexc: install_splat's Cryptex1 ticket: {path} ({} bytes), the device's of ECID {ecid:X}", ticket.len());
            ticket
        }
    };
    Ok(apfswrite::restore::Device { tree, cryptex1_ticket: ticket })
}

pub fn cmd(args: &[String]) -> Result<ExitCode> {
    let (out, dmg, ipsw) = match args {
        [out] => (out, None, None),
        [out, dmg] => (out, Some(dmg), None),
        [out, dmg, ipsw] => (out, Some(dmg), Some(ipsw)),
        _ => bail!("usage: gexc darwin-disk0 <out> [<os.dmg> [<ipsw-dir>]]"),
    };
    let boot = match ipsw {
        Some(d) => Some(apfswrite::restore::BootObjects::read(std::path::Path::new(d)).map_err(|e| anyhow!("{e}"))?),
        None => None,
    };
    let has_boot = boot.is_some();
    let device = match &boot {
        Some(b) => Some(device(b)?),
        None if std::env::var_os("GEX_DARWIN_CRYPTEX1_TICKET").is_some_and(|v| !v.is_empty()) => bail!("GEX_DARWIN_CRYPTEX1_TICKET is install_splat's, which runs with the IPSW's boot objects (<ipsw-dir>)"),
        None => None,
    };
    let seal = match ipsw {
        Some(d) => Some(apfswrite::restore::SealFiles::read(std::path::Path::new(d)).map_err(|e| anyhow!("{e}"))?),
        None => None,
    };
    let os = match dmg {
        Some(dmg) => {
            let f = std::fs::File::open(dmg).with_context(|| format!("opening {dmg}"))?;
            let len = f.metadata()?.len();
            let image = gex_kernel::darwin::udif::Udif::open(std::sync::Arc::new(apfswrite::HostFile(f, len))).map_err(|e| anyhow!("{dmg}: {e}"))?;
            let partition = image.partition("Apple_APFS").ok_or_else(|| anyhow!("{dmg}: no Apple_APFS partition"))?;
            Some(apfswrite::restore::OsImage { image: std::sync::Arc::new(image), partition, boot, seal, device })
        }
        None => None,
    };
    let size = storage::disk0_bytes();
    let f = std::fs::OpenOptions::new().read(true).write(true).create_new(true).open(out).with_context(|| format!("creating {out}"))?;
    // A new file reads as zeros, as clean_nand's DKIOCFORMAT leaves the disk.
    f.set_len(size).with_context(|| format!("sizing {out}"))?;
    let sink = std::sync::Arc::new(apfswrite::HostFile(f, size));
    if let Some(gaps) = storage::unmeasured() {
        eprintln!("gexc: {gaps}");
    }
    for s in apfswrite::restore::stand_ins(os.is_some(), has_boot) {
        eprintln!("gexc: {s}");
    }
    // The kernel's clock: the time the restore runs.
    let mut now = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64);
    let missing = apfswrite::restore::build_disk0(sink, &mut now, os.as_ref()).map_err(|e| anyhow!("{out}: {e}"))?;
    // What the image lacks, beside it, for the disk nodes to report.
    let missing_path = format!("{out}.missing");
    if missing.is_empty() {
        let _ = std::fs::remove_file(&missing_path);
        return Ok(ExitCode::SUCCESS);
    }
    std::fs::write(&missing_path, missing.join("\n") + "\n").with_context(|| format!("writing {missing_path}"))?;
    for m in &missing {
        eprintln!("gexc: not implemented: {m}");
    }
    eprintln!("gexc: {out} is incomplete ({} restore steps not implemented)", missing.len());
    Ok(ExitCode::from(2))
}
