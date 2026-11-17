//! `gexc darwin-disk0 <out> [<os.dmg>]`: the web device's disk0 made as
//! its erase restore makes it (`gex_kernel::darwin::apfswrite::restore`),
//! written to a new sparse file of the device's size, the IPSW's operating
//! system image (044-76040-038.dmg) restored into it when given; the
//! restore steps it does not have yet are listed in `<out>.missing`.

use anyhow::{anyhow, bail, Context, Result};
use gex_kernel::darwin::{apfswrite, storage};
use std::process::ExitCode;

pub fn cmd(args: &[String]) -> Result<ExitCode> {
    let (out, dmg) = match args {
        [out] => (out, None),
        [out, dmg] => (out, Some(dmg)),
        _ => bail!("usage: gexc darwin-disk0 <out> [<os.dmg>]"),
    };
    let os = match dmg {
        Some(dmg) => {
            let f = std::fs::File::open(dmg).with_context(|| format!("opening {dmg}"))?;
            let len = f.metadata()?.len();
            let image = gex_kernel::darwin::udif::Udif::open(std::sync::Arc::new(apfswrite::HostFile(f, len))).map_err(|e| anyhow!("{dmg}: {e}"))?;
            let partition = image.partition("Apple_APFS").ok_or_else(|| anyhow!("{dmg}: no Apple_APFS partition"))?;
            Some(apfswrite::restore::OsImage { image: std::sync::Arc::new(image), partition })
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
    for s in apfswrite::restore::stand_ins(os.is_some()) {
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
