//! `gexc darwin-disk0 <out>`: the web device's disk0 made as its erase
//! restore makes it (`gex_kernel::darwin::apfswrite::restore`), written
//! to a new sparse file of the device's size; the restore steps it does
//! not have yet are listed in `<out>.missing`.

use anyhow::{anyhow, bail, Context, Result};
use gex_kernel::darwin::{apfswrite, storage};
use std::process::ExitCode;

pub fn cmd(args: &[String]) -> Result<ExitCode> {
    let [out] = args else { bail!("usage: gexc darwin-disk0 <out>") };
    let size = storage::disk0_bytes();
    let f = std::fs::OpenOptions::new().read(true).write(true).create_new(true).open(out).with_context(|| format!("creating {out}"))?;
    // A new file reads as zeros, as clean_nand's DKIOCFORMAT leaves the disk.
    f.set_len(size).with_context(|| format!("sizing {out}"))?;
    let sink = apfswrite::HostFile(f, size);
    if let Some(gaps) = storage::unmeasured() {
        eprintln!("gexc: {gaps}");
    }
    eprintln!("gexc: {}", apfswrite::restore::RUN_STAND_IN);
    // The kernel's clock: the time the restore runs.
    let mut now = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64);
    let missing = apfswrite::restore::build_disk0(&sink, &mut now).map_err(|e| anyhow!("{out}: {e}"))?;
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
