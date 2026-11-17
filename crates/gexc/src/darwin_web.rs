//! The web device's tools (`gex_kernel::darwin::webdevice`):
//!
//! ```text
//!   gexc darwin-web-device init <dir>   make a web device: its root, manifest key, identity, UID, nonce slot
//!   gexc darwin-web-device show <dir>   its identity and current cryptex1 boot nonce hash
//!   gexc darwin-web-device roll <dir>   roll its cryptex1 boot nonce (its tickets go stale)
//!   gexc darwin-web-ticket <dir>        sign its Cryptex1 ticket for its current nonce
//! ```
//!
//! `init` and `darwin-web-ticket` read the IPSW's build identity of the
//! device (GEX_DARWIN_RESTORE). The directory holds the device's secrets,
//! its private keys and UID (mode 0600, the directory 0700): it belongs to
//! one installation, outside every repository. Random bytes come from the
//! host's (`getrandom`), as the kernel's random source gives AppleImage4's.

use anyhow::{anyhow, bail, Context, Result};
use gex_kernel::darwin::image4::{self, nonce, Outcome};
use gex_kernel::darwin::plist::{self, Value};
use gex_kernel::darwin::webdevice::{self, files, Identity, Signer, WebDevice};
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use rsa::rand_core::{OsRng, RngCore};
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Sign, RsaPrivateKey};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// An RSA key that signs as the web device's root or manifest key.
struct Key(RsaPrivateKey);

impl Signer for Key {
    fn public_key(&self) -> Vec<u8> {
        webdevice::rsa_public_key(&self.0.n().to_bytes_be(), &self.0.e().to_bytes_be())
    }

    fn sign_sha384(&self, digest: &[u8; 48]) -> std::result::Result<Vec<u8>, String> {
        self.0.sign(Pkcs1v15Sign::new::<rsa::sha2::Sha384>(), digest).map_err(|e| e.to_string())
    }
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

/// A certificate serial number: 20 random bytes, positive and minimal.
fn serial() -> [u8; 20] {
    let mut s = random::<20>();
    s[0] &= 0x7f;
    if s[0] == 0 {
        s[0] = 1;
    }
    s
}

/// The civil date of `days` since 1970-01-01 (proleptic Gregorian).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// A UTCTime string of `secs` since the epoch, "YYMMDDHHMMSSZ" (years 1950
/// to 2049).
fn utc_time(secs: i64) -> Result<String> {
    let (y, m, d) = civil(secs.div_euclid(86_400));
    let t = secs.rem_euclid(86_400);
    if !(1950..2050).contains(&y) {
        bail!("{y} is past what a UTCTime holds");
    }
    Ok(format!("{:02}{m:02}{d:02}{:02}{:02}{:02}Z", y % 100, t / 3600, t / 60 % 60, t % 60))
}

/// The certificates' validity: from now, for 20 years (Apple's secure boot
/// roots have 25; UTCTime ends with 2049).
fn validity() -> Result<(String, String)> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e| anyhow!("the clock: {e}"))?.as_secs() as i64;
    Ok((utc_time(now)?, utc_time(now + 20 * 365 * 86_400 + 5 * 86_400)?))
}

/// Write a new file of `mode`, refusing one that is there.
fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(mode).open(path).with_context(|| format!("creating {}", path.display()))?;
    f.write_all(bytes).with_context(|| format!("writing {}", path.display()))?;
    f.sync_all().with_context(|| format!("writing {}", path.display()))
}

/// Replace a file atomically, with `mode`.
fn replace(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let tmp = path.with_extension("new");
    let _ = std::fs::remove_file(&tmp);
    write_new(&tmp, bytes, mode)?;
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
}

fn read(dir: &Path, name: &str) -> Result<Vec<u8>> {
    std::fs::read(dir.join(name)).with_context(|| format!("reading {}", dir.join(name).display()))
}

/// The IPSW's build identity of the erase restore for a device of `chip`
/// and `board` (GEX_DARWIN_RESTORE), and its restore directory.
fn build_identity(chip: Option<(u32, u32)>) -> Result<(PathBuf, Value)> {
    let dir = PathBuf::from(std::env::var_os("GEX_DARWIN_RESTORE").ok_or_else(|| anyhow!("GEX_DARWIN_RESTORE is not set: the IPSW's BuildManifest.plist and files"))?);
    let path = dir.join("BuildManifest.plist");
    let m = plist::parse(&std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?).map_err(|e| anyhow!("{}: {e}", path.display()))?;
    let ids = m.get("BuildIdentities").and_then(Value::as_array).ok_or_else(|| anyhow!("{}: no BuildIdentities", path.display()))?;
    let erase = gex_kernel::darwin::preboot::cryptex1::ERASE_VARIANT;
    let found = ids.iter().find(|i| {
        let variant = i.get("Info").and_then(|x| x.get("Variant")).and_then(Value::as_str);
        let num = |k: &str| i.get(k).and_then(webdevice::number);
        let target = i.get("Ap,Target").and_then(Value::as_str);
        variant == Some(erase)
            && match chip {
                Some((c, b)) => num("ApChipID") == Some(u64::from(c)) && num("ApBoardID") == Some(u64::from(b)),
                // The device the web device models: the J120AP.
                None => target == Some("J120AP"),
            }
    });
    let id = found.ok_or_else(|| anyhow!("{}: no {erase} identity for this device", path.display()))?;
    Ok((dir, id.clone()))
}

fn load(dir: &Path) -> Result<WebDevice> {
    let ticket = dir.join(files::CRYPTEX1_TICKET);
    let ticket = ticket.exists().then(|| ticket.to_string_lossy().into_owned());
    webdevice::of_files(read(dir, files::ROOT_CERT)?, &read(dir, files::IDENTITY)?, &read(dir, files::CRYPTEX1_BOOT_SLOT)?, ticket).map_err(|e| anyhow!("{}: {e}", dir.display()))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02x}")).collect()
}

fn nonce_hash(w: &WebDevice) -> Result<Vec<u8>> {
    webdevice::nonce_hash(w, false).map_err(|e| anyhow!("the web device's cryptex1 boot nonce hash: {e:?}"))
}

fn init(dir: &Path) -> Result<()> {
    let (_, build) = build_identity(None)?;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("creating {} (a new directory: a web device is made once)", dir.display()))?;
    eprintln!("gexc: making the root's and the manifest key's RSA-{} keys", webdevice::KEY_BITS);
    let root = Key(RsaPrivateKey::new(&mut OsRng, webdevice::KEY_BITS).context("making the root's key")?);
    let manifest = Key(RsaPrivateKey::new(&mut OsRng, webdevice::KEY_BITS).context("making the manifest key")?);
    let (from, to) = validity()?;
    let root_cert = webdevice::certificate(&webdevice::root_spec(serial(), &from, &to, root.public_key()), &root).map_err(|e| anyhow!("the root's certificate: {e}"))?;
    let leaf = webdevice::certificate(&webdevice::manifest_key_spec(serial(), &from, &to, manifest.public_key(), &root.public_key()), &root).map_err(|e| anyhow!("the manifest key's certificate: {e}"))?;
    let mut ecid = 0u64;
    while ecid == 0 {
        ecid = u64::from_be_bytes(random::<8>());
    }
    let identity = Identity::for_build(&build, ecid).map_err(|e| anyhow!("{e}"))?;
    // The magazine's cryptex1 boot slot: version 0, a nonce from the random
    // source as the kext's roll takes one, no flags, no proposal.
    let slot = nonce::Slot {
        flags: 0,
        nonce: random::<{ nonce::CRYPTEX1_BOOT_NONCE_LENGTH }>(),
        proposal: [0; 16],
    };
    let key_der = |k: &Key| k.0.to_pkcs1_der().map(|d| d.as_bytes().to_vec()).map_err(|e| anyhow!("encoding a key: {e}"));
    write_new(&dir.join(files::ROOT_KEY), &key_der(&root)?, 0o600)?;
    write_new(&dir.join(files::MANIFEST_KEY), &key_der(&manifest)?, 0o600)?;
    write_new(&dir.join(files::UID), &random::<32>(), 0o600)?;
    write_new(&dir.join(files::CRYPTEX1_BOOT_SLOT), &slot.to_bytes(), 0o600)?;
    write_new(&dir.join(files::ROOT_CERT), &root_cert, 0o644)?;
    write_new(&dir.join(files::MANIFEST_CERT), &leaf, 0o644)?;
    write_new(&dir.join(files::IDENTITY), &plist::to_xml(&identity.to_plist()), 0o644)?;
    show(dir)
}

fn show(dir: &Path) -> Result<()> {
    let w = load(dir)?;
    let i = &w.identity;
    println!("ECID {:X}", i.ecid);
    println!("ChipID {:#x}", i.chip);
    println!("BoardID {:#x}", i.board);
    println!("SecurityDomain {:#x}", i.security_domain);
    println!(
        "ProductionMode {} SecurityMode {} EffectiveProductionStatusAp {} EffectiveSecurityModeAp {}",
        i.production, i.security, i.effective_production, i.effective_security
    );
    println!("cryptex1 boot nonce hash {}", hex(&nonce_hash(&w)?));
    match &w.ticket {
        Some(p) => println!("Cryptex1 ticket {p}"),
        None => println!("Cryptex1 ticket none (gexc darwin-web-ticket {})", dir.display()),
    }
    Ok(())
}

fn roll(dir: &Path) -> Result<()> {
    let path = dir.join(files::CRYPTEX1_BOOT_SLOT);
    let slot = nonce::Slot::parse(&read(dir, files::CRYPTEX1_BOOT_SLOT)?).map_err(|e| anyhow!("{}: not a nonce slot (errno {e})", path.display()))?;
    let rolled = slot.rolled(random::<{ nonce::CRYPTEX1_BOOT_NONCE_LENGTH }>()).map_err(|e| anyhow!("{e}"))?;
    replace(&path, &rolled.to_bytes(), 0o600)?;
    show(dir)
}

/// Sign the device's Cryptex1 ticket for its current nonce, and check it
/// as its AppleImage4 will: the SystemOS cryptex's root hash evaluated
/// against it must authenticate.
fn sign(dir: &Path) -> Result<()> {
    let w = load(dir)?;
    let (restore, build) = build_identity(Some((w.identity.chip, w.identity.board)))?;
    let manifest = Key(RsaPrivateKey::from_pkcs1_der(&read(dir, files::MANIFEST_KEY)?).map_err(|e| anyhow!("{}: {e}", dir.join(files::MANIFEST_KEY).display()))?);
    let leaf = read(dir, files::MANIFEST_CERT)?;
    let cnch = nonce_hash(&w)?;
    let ticket = webdevice::cryptex1_ticket(&w.identity, &build, &cnch, &random::<20>(), &manifest, &leaf).map_err(|e| anyhow!("{e}"))?;
    let path = build
        .get("Manifest")
        .and_then(|m| m.get("Cryptex1,SystemVolume"))
        .and_then(|c| c.get("Info"))
        .and_then(|i| i.get("Path"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("the build identity has no Cryptex1,SystemVolume path"))?;
    let root_hash = std::fs::read(restore.join(path)).with_context(|| format!("reading {}", restore.join(path).display()))?;
    match image4::execute(image4::fourcc(b"cssy"), &root_hash, &ticket, &webdevice::DeviceEnv(&w)) {
        Outcome::Authenticated(_) => {}
        other => bail!("the signed ticket does not authenticate the SystemOS cryptex's root hash on this device: {other:?}"),
    }
    replace(&dir.join(files::CRYPTEX1_TICKET), &ticket, 0o644)?;
    println!("Cryptex1 ticket {} ({} bytes) for nonce hash {}", dir.join(files::CRYPTEX1_TICKET).display(), ticket.len(), hex(&cnch));
    Ok(())
}

/// `gexc darwin-web-device init|show|roll <dir>`.
pub fn cmd_device(args: &[String]) -> Result<ExitCode> {
    match args {
        [op, dir] if op == "init" => init(Path::new(dir))?,
        [op, dir] if op == "show" => show(Path::new(dir))?,
        [op, dir] if op == "roll" => roll(Path::new(dir))?,
        _ => bail!("usage: gexc darwin-web-device init|show|roll <dir>"),
    }
    Ok(ExitCode::SUCCESS)
}

/// `gexc darwin-web-ticket <dir>`.
pub fn cmd_ticket(args: &[String]) -> Result<ExitCode> {
    match args {
        [dir] => sign(Path::new(dir))?,
        _ => bail!("usage: gexc darwin-web-ticket <dir>"),
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_times_are_civil() {
        assert_eq!(utc_time(0).unwrap(), "700101000000Z");
        // 2026-11-17 10:04:05 UTC.
        assert_eq!(utc_time(1_794_909_845).unwrap(), "261117100405Z");
        assert_eq!(utc_time(951_782_400).unwrap(), "000229000000Z");
        assert!(utc_time(2_524_608_000).is_err(), "2050 needs a GeneralizedTime");
    }
}
