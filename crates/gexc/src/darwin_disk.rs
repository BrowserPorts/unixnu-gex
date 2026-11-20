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
//!   `GEX_DARWIN_WEB_DEVICE=<dir>`: the web device, whose identity, AP
//!   nonce generator and AP ticket's hash iBoot puts in the restore device
//!   tree's `/chosen` as its boot does, whose AP ticket (signed by
//!   `gexc darwin-web-device apticket` for its AP nonce) is the restore's
//!   RootTicketData, whose NVRAM (its `nvram.bin`) the restore changes in
//!   place (written when its ramdisk's IODTNVRAM syncs), and whose
//!   manifest key plays TSS's part for install_splat's Cryptex1 ticket,
//!   signed for the cryptex1 boot nonce the restore rolls in that NVRAM;
//! - `GEX_DARWIN_NVRAM=<file>`: for a device of Apple's, its NVRAM
//!   namespace image, which the restore's NVRAM steps change in place;
//!   without it they are listed as missing;
//! - `GEX_DARWIN_CRYPTEX1_TICKET=<path>`: a device of Apple's, its own
//!   Cryptex1 ticket as its restore wrote it
//!   (`apticket.j120ap.<ECID>.im4m`, copied from its Preboot volume's
//!   `cryptex1/current`), the ECID its name holds being the one iBoot put
//!   in that restore's `/chosen`; with `GEX_DARWIN_AP_TICKET=<path>`, its
//!   AP ticket (`apticket.der` from its Preboot volume's
//!   `<hash>/System/Library/Caches`) as the restore's RootTicketData, its
//!   hash the restore's `/chosen` `boot-manifest-hash`; without it the AP
//!   ticket stands in.

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
    let mut ap_ticket = None;
    let mut web_nvram = None;
    let mut ap_anchor: std::result::Result<Vec<u8>, String> = Err("the root the restore ramdisk's libimage4 embeds for the AP chip (\"Apple Secure Boot Root CA - G2\", libimage4 0x2c590): not given for a device of Apple's".into());
    let ticket = match (source.as_deref(), web) {
        (None, _) => bail!("install_splat needs the device's Cryptex1 ticket: GEX_DARWIN_CRYPTEX1_TICKET is not set (web-device, with GEX_DARWIN_WEB_DEVICE, or the path of the device's apticket.{target}.<ECID>.im4m)"),
        (Some("web-device"), None) => bail!("the Cryptex1 ticket is the web device's (GEX_DARWIN_CRYPTEX1_TICKET=web-device), but no web device is configured (GEX_DARWIN_WEB_DEVICE)"),
        (Some("web-device"), Some(dir)) => {
            let w = crate::darwin_web::load(&dir)?;
            web_nvram = Some(dir.join(webdevice::files::NVRAM));
            if w.ap_ticket.is_none() {
                bail!("the web device has no AP ticket for the restore's RootTicketData (gexc darwin-web-device apticket {})", dir.display());
            }
            let booted = w.boot_chosen().map_err(|e| anyhow!("{}: {e}", dir.display()))?;
            iokit::fill_chosen(&mut tree, &w.identity.chosen()).map_err(|e| anyhow!("the restore device tree: {e}"))?;
            iokit::fill_chosen(&mut tree, &booted).map_err(|e| anyhow!("the restore device tree: {e}"))?;
            if std::env::var_os("GEX_DARWIN_NVRAM").is_some_and(|v| !v.is_empty()) {
                bail!("GEX_DARWIN_NVRAM is a device of Apple's: the web device's NVRAM is its own {}", dir.join(webdevice::files::NVRAM).display());
            }
            let at = w.ap_ticket.clone().expect("checked");
            let hash: String = webdevice::boot_manifest_hash(&at).iter().map(|b| format!("{b:02X}")).collect();
            eprintln!("gexc: the restore's RootTicketData: the web device's AP ticket ({} bytes, boot-manifest-hash {hash})", at.len());
            ap_ticket = Some(at);
            // The web device's libimage4 trusts its platform's root.
            ap_anchor = Ok(w.root.clone());
            let manifest = gex_kernel::darwin::plist::parse(&boot.manifest).map_err(|e| anyhow!("BuildManifest.plist: {e}"))?;
            let build = preboot::erase_identity(&manifest, &target).map_err(|e| anyhow!("{e}"))?;
            // TSS for _personalize_splat_ticket's request: the web device's
            // manifest key signs for the nonce its restore proposes.
            let (build, ipsw, ecid) = (build.clone(), boot.dir.clone(), w.identity.ecid);
            let tss = move |cnch: &[u8]| -> std::result::Result<Vec<u8>, String> {
                let ticket = crate::darwin_web::signed_cryptex1_ticket(&dir, &w, &build, cnch, &ipsw).map_err(|e| format!("{e:#}"))?;
                let hex: String = cnch.iter().map(|b| format!("{b:02x}")).collect();
                eprintln!("gexc: install_splat's Cryptex1 ticket: the web device's (ECID {ecid:X}), signed by its manifest key for the proposed cryptex1 boot nonce's hash {hex}, {} bytes", ticket.len());
                Ok(ticket)
            };
            apfswrite::restore::Cryptex1Ticket::Tss(Box::new(tss))
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
            if let Some(ap) = std::env::var_os("GEX_DARWIN_AP_TICKET").filter(|v| !v.is_empty()) {
                let at = std::fs::read(&ap).with_context(|| format!("reading {}", Path::new(&ap).display()))?;
                let theirs = image4::manifest_property(&at, image4::fourcc(b"ECID"), image4::tag::INTEGER)
                    .and_then(image4::der::integer64)
                    .map_err(|e| anyhow!("{}: not an AP ticket with an ECID (libDER {e})", Path::new(&ap).display()))?;
                if theirs != ecid {
                    bail!("{}: the AP ticket is personalized for ECID {theirs:X}, not the Cryptex1 ticket's {ecid:X}", Path::new(&ap).display());
                }
                iokit::fill_chosen(&mut tree, &[("boot-manifest-hash", webdevice::boot_manifest_hash(&at).to_vec())]).map_err(|e| anyhow!("the restore device tree: {e}"))?;
                eprintln!("gexc: the restore's RootTicketData: {} ({} bytes)", Path::new(&ap).display(), at.len());
                ap_ticket = Some(at);
            }
            apfswrite::restore::Cryptex1Ticket::Given(ticket)
        }
    };
    // iBEC's bootx boots the restore ramdisk, adding its boot command to
    // /chosen (iBoot-10151.140.19 0x1800b0e74 → 0x1800ccc44, 0x1800f07b8).
    iokit::fill_chosen(&mut tree, &[("boot-command", gex_kernel::darwin::noncemag::boot_command::BOOTX.to_le_bytes().to_vec())]).map_err(|e| anyhow!("the restore device tree: {e}"))?;
    // The device's NVRAM namespace the restore changes, updated in place:
    // the web device's own, or a device's image.
    let nvram_path = match &web_nvram {
        Some(p) => Some(p.clone().into_os_string()),
        None => std::env::var_os("GEX_DARWIN_NVRAM").filter(|v| !v.is_empty()),
    };
    let nvram = match nvram_path {
        Some(path) => {
            let f = std::fs::OpenOptions::new().read(true).write(true).open(&path).with_context(|| format!("opening {}", Path::new(&path).display()))?;
            let size = f.metadata()?.len();
            eprintln!("gexc: the restore's NVRAM changes go to {} ({size} bytes)", Path::new(&path).display());
            Some(apfswrite::restore::NvramDevice { medium: std::sync::Arc::new(apfswrite::HostFile(f, size)), size: size as usize })
        }
        None => None,
    };
    Ok(apfswrite::restore::Device { nvram, tree, cryptex1: ticket, ap_ticket, ap_anchor })
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
    let has_ap_ticket = os.as_ref().and_then(|o| o.device.as_ref()).is_some_and(|d| d.ap_ticket.is_some());
    for s in apfswrite::restore::stand_ins(os.is_some(), has_boot, has_ap_ticket) {
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
