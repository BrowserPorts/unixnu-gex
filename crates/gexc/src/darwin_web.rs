//! The web device's tools (`gex_kernel::darwin::webdevice`):
//!
//! ```text
//!   gexc darwin-web-device init <dir>   make a web device: its root, manifest key, identity, UIDs, NVRAM
//!   gexc darwin-web-device show <dir>   its identity and the cryptex1 boot nonce hash its next boot holds
//!   gexc darwin-web-device sep <dir>    add the Secure Enclave's UID to a device made without one
//!   gexc darwin-web-device migrate <dir>  move the cryptex1 boot slot of a device made before its
//!                                       NVRAM held its nonce magazine into its NVRAM
//!   gexc darwin-web-device apkey <dir>  add the AP manifest key to a device made without one
//!   gexc darwin-web-device apticket <dir>  sign its AP ticket for its AP nonce (making the
//!                                       nonce's generator in its NVRAM when it has none)
//!   gexc darwin-web-ticket <dir>        sign its Cryptex1 ticket for its current nonce
//! ```
//!
//! The device's cryptex1 boot nonce is its AppleImage4's, in its NVRAM's
//! nonce magazine (`gex_kernel::darwin::noncemag`): a new device has none
//! until its restore (`gexc darwin-disk0`) rolls one and has its Cryptex1
//! ticket signed for it.
//!
//! `init`, `apticket` and `darwin-web-ticket` read the IPSW's build
//! identity of the device (GEX_DARWIN_RESTORE). The directory holds the device's secrets,
//! its private keys and UIDs (the AP's and the Secure Enclave's; mode 0600,
//! the directory 0700): it belongs to one installation, outside every
//! repository. No tool prints a UID. Random bytes come from the
//! host's (`getrandom`), as the kernel's random source gives AppleImage4's.

use anyhow::{anyhow, bail, Context, Result};
use gex_kernel::darwin::image4::{self, Outcome};
use gex_kernel::darwin::plist::{self, Value};
use gex_kernel::darwin::sep::secrets::SepUid;
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

/// The web device of directory `dir`, as a run has it: its root's
/// certificate, identity, the path of its ticket, its AP ticket and its
/// NVRAM. A device that keeps its cryptex1 boot slot in a file of its own
/// is refused: its NVRAM is where its AppleImage4 reads the slot.
pub(crate) fn load(dir: &Path) -> Result<WebDevice> {
    if dir.join(files::CRYPTEX1_BOOT_SLOT).exists() {
        bail!("{} keeps its cryptex1 boot slot in {}, which its NVRAM's nonce magazine now holds: gexc darwin-web-device migrate {}", dir.display(), files::CRYPTEX1_BOOT_SLOT, dir.display());
    }
    load_files(dir)
}

fn load_files(dir: &Path) -> Result<WebDevice> {
    let ticket = dir.join(files::CRYPTEX1_TICKET);
    let ticket = ticket.exists().then(|| ticket.to_string_lossy().into_owned());
    let ap_ticket = read_optional(dir, files::AP_TICKET)?;
    let nvram = read_optional(dir, files::NVRAM)?;
    webdevice::of_files(read(dir, files::ROOT_CERT)?, &read(dir, files::IDENTITY)?, ticket, ap_ticket, nvram.as_deref()).map_err(|e| anyhow!("{}: {e}", dir.display()))
}

fn read_optional(dir: &Path, name: &str) -> Result<Option<Vec<u8>>> {
    match std::fs::read(dir.join(name)) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow!("reading {}: {e}", dir.join(name).display())),
    }
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
    let ap_manifest = Key(RsaPrivateKey::new(&mut OsRng, webdevice::KEY_BITS).context("making the AP manifest key")?);
    let (from, to) = validity()?;
    let root_cert = webdevice::certificate(&webdevice::root_spec(serial(), &from, &to, root.public_key()), &root).map_err(|e| anyhow!("the root's certificate: {e}"))?;
    let leaf = webdevice::certificate(&webdevice::manifest_key_spec(serial(), &from, &to, manifest.public_key(), &root.public_key()), &root).map_err(|e| anyhow!("the manifest key's certificate: {e}"))?;
    let mut ecid = 0u64;
    while ecid == 0 {
        ecid = u64::from_be_bytes(random::<8>());
    }
    let identity = Identity::for_build(&build, ecid).map_err(|e| anyhow!("{e}"))?;
    let ap_leaf = webdevice::certificate(&webdevice::ap_manifest_key_spec(serial(), &from, &to, ap_manifest.public_key(), &root.public_key(), &identity, webdevice::AP_CERTIFICATE_EPOCH), &root).map_err(|e| anyhow!("the AP manifest key's certificate: {e}"))?;
    let key_der = |k: &Key| k.0.to_pkcs1_der().map(|d| d.as_bytes().to_vec()).map_err(|e| anyhow!("encoding a key: {e}"));
    write_new(&dir.join(files::ROOT_KEY), &key_der(&root)?, 0o600)?;
    write_new(&dir.join(files::MANIFEST_KEY), &key_der(&manifest)?, 0o600)?;
    write_new(&dir.join(files::AP_MANIFEST_KEY), &key_der(&ap_manifest)?, 0o600)?;
    write_new(&dir.join(files::UID), &random::<32>(), 0o600)?;
    write_new(&dir.join(files::SEP_UID), &random::<32>(), 0o600)?;
    write_new(&dir.join(files::ROOT_CERT), &root_cert, 0o644)?;
    write_new(&dir.join(files::MANIFEST_CERT), &leaf, 0o644)?;
    write_new(&dir.join(files::AP_MANIFEST_CERT), &ap_leaf, 0o644)?;
    write_new(&dir.join(files::IDENTITY), &plist::to_xml(&identity.to_plist()), 0o644)?;
    write_new(&dir.join(files::NVRAM), &gex_kernel::darwin::nvram::factory_image(), 0o644)?;
    show(dir)
}

/// The web device's factory NVRAM, for a device made before it had one
/// (`gex_kernel::darwin::nvram::factory_image`); one that is there is
/// kept.
fn nvram(dir: &Path) -> Result<()> {
    load(dir)?;
    write_new(&dir.join(files::NVRAM), &gex_kernel::darwin::nvram::factory_image(), 0o644)?;
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
    match nonce_hash(&w) {
        Ok(h) => println!("cryptex1 boot nonce hash {} (its next boot's)", hex(&h)),
        Err(e) => println!("cryptex1 boot nonce hash none: {e}"),
    }
    match SepUid::load(dir) {
        Ok(_) => println!("SEP UID present"),
        Err(e) => println!("SEP UID absent: {e}"),
    }
    match &w.ticket {
        Some(p) => println!("Cryptex1 ticket {p}"),
        None => println!("Cryptex1 ticket none (gexc darwin-web-ticket {})", dir.display()),
    }
    match w.boot_nonce {
        Some(g) => println!("AP nonce {}", hex(&webdevice::apnonce::hash(g))),
        None => println!("AP nonce none (its NVRAM holds no com.apple.System.boot-nonce; gexc darwin-web-device apticket {} makes one)", dir.display()),
    }
    match &w.ap_ticket {
        Some(t) => {
            println!("AP ticket {} ({} bytes), boot-manifest-hash {}", dir.join(files::AP_TICKET).display(), t.len(), hex(&webdevice::boot_manifest_hash(t)).to_uppercase());
            // What its boot publishes in /chosen/manifest-properties.
            match webdevice::manifest_properties(t) {
                Ok(props) => {
                    for (name, v) in props {
                        let code = name.trim_start_matches("manifest-properties/");
                        match code {
                            "love" => println!("manifest-properties {code} {}", String::from_utf8_lossy(&v)),
                            _ => println!("manifest-properties {code} {}", hex(&v)),
                        }
                    }
                }
                Err(e) => println!("manifest-properties none: {e}"),
            }
            if let Err(e) = w.check_ap_ticket() {
                println!("AP ticket not this device's current one: {e}");
            }
        }
        None => println!("AP ticket none (gexc darwin-web-device apticket {})", dir.display()),
    }
    if !dir.join(files::AP_MANIFEST_KEY).exists() {
        println!("AP manifest key absent (gexc darwin-web-device apkey {})", dir.display());
    }
    let path = dir.join(files::NVRAM);
    match std::fs::read(&path) {
        Ok(image) => {
            let (version, generation) = gex_kernel::darwin::nvram::chrp::version(&image);
            println!("NVRAM {} bytes, version {version}, generation {generation}", image.len());
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => println!("NVRAM none (gexc darwin-web-device nvram {})", dir.display()),
        Err(e) => bail!("reading {}: {e}", path.display()),
    }
    Ok(())
}

/// Add the Secure Enclave's UID to the web device of `dir` that has none:
/// 32 bytes from the host's random source, as `init` makes it. A device
/// that has one keeps it (a UID is fused once: replacing it would make
/// every key derived from the old one unreachable).
fn add_sep_uid(dir: &Path) -> Result<()> {
    load(dir)?;
    write_new(&dir.join(files::SEP_UID), &random::<32>(), 0o600).with_context(|| format!("{} has a SEP UID already, or cannot be written", dir.display()))?;
    println!("SEP UID made");
    Ok(())
}

/// Add the AP manifest key to the web device of `dir` made without one:
/// a new RSA key whose certificate its root issues
/// ([`webdevice::ap_manifest_key_spec`]). A device that has one keeps it.
fn add_ap_key(dir: &Path) -> Result<()> {
    let w = load(dir)?;
    if dir.join(files::AP_MANIFEST_KEY).exists() || dir.join(files::AP_MANIFEST_CERT).exists() {
        bail!("{} has an AP manifest key already", dir.display());
    }
    let root = Key(RsaPrivateKey::from_pkcs1_der(&read(dir, files::ROOT_KEY)?).map_err(|e| anyhow!("{}: {e}", dir.join(files::ROOT_KEY).display()))?);
    // The root that signs is the one the device trusts.
    let (key, _) = image4::verify_chain(&w.root, &w.root).map_err(|e| anyhow!("{}: the root's certificate does not verify ({e})", dir.join(files::ROOT_CERT).display()))?;
    if key != root.public_key().as_slice() {
        bail!("{} is not the key of {}", dir.join(files::ROOT_KEY).display(), dir.join(files::ROOT_CERT).display());
    }
    eprintln!("gexc: making the AP manifest key's RSA-{} key", webdevice::KEY_BITS);
    let ap = Key(RsaPrivateKey::new(&mut OsRng, webdevice::KEY_BITS).context("making the AP manifest key")?);
    let (from, to) = validity()?;
    let leaf = webdevice::certificate(&webdevice::ap_manifest_key_spec(serial(), &from, &to, ap.public_key(), &root.public_key(), &w.identity, webdevice::AP_CERTIFICATE_EPOCH), &root).map_err(|e| anyhow!("the AP manifest key's certificate: {e}"))?;
    let der = ap.0.to_pkcs1_der().map(|d| d.as_bytes().to_vec()).map_err(|e| anyhow!("encoding a key: {e}"))?;
    write_new(&dir.join(files::AP_MANIFEST_KEY), &der, 0o600)?;
    write_new(&dir.join(files::AP_MANIFEST_CERT), &leaf, 0o644)?;
    println!("AP manifest key made");
    Ok(())
}

/// The web device's AP ticket for build identity `build` and AP nonce
/// hash `bnch`, as TSS signs a device's: its AP manifest key (from `dir`)
/// signs the body ([`webdevice::ap_ticket`]), with 20 random bytes of the
/// signer's own.
pub(crate) fn signed_ap_ticket(dir: &Path, w: &WebDevice, build: &Value, bnch: &[u8]) -> Result<Vec<u8>> {
    let key = Key(RsaPrivateKey::from_pkcs1_der(&read(dir, files::AP_MANIFEST_KEY)?).map_err(|e| anyhow!("{}: {e}", dir.join(files::AP_MANIFEST_KEY).display()))?);
    let leaf = read(dir, files::AP_MANIFEST_CERT)?;
    let (_, constraints) = image4::verify_chain(&w.root, &leaf).map_err(|e| anyhow!("{}: not issued by the device's root ({e})", dir.join(files::AP_MANIFEST_CERT).display()))?;
    if constraints != Some(&webdevice::ap_manifest_constraints(&w.identity, webdevice::AP_CERTIFICATE_EPOCH)[..]) {
        bail!("{}: not this device's AP manifest key (its constraints differ)", dir.join(files::AP_MANIFEST_CERT).display());
    }
    webdevice::ap_ticket(&w.identity, build, bnch, webdevice::AP_CERTIFICATE_EPOCH, &random::<20>(), &key, &leaf).map_err(|e| anyhow!("{e}"))
}

/// Sign the device's AP ticket for its AP nonce. A device whose NVRAM
/// holds no generator gets one first, made and saved as AppleMobileApNonce
/// makes and saves one (`_generateNonce`: 8 bytes from the random source,
/// "0x%016llx", IODTNVRAM's `setProperty` and a forced sync).
fn sign_ap(dir: &Path) -> Result<()> {
    let w = load(dir)?;
    let (_, build) = build_identity(Some((w.identity.chip, w.identity.board)))?;
    let nvram_path = dir.join(files::NVRAM);
    let image = read(dir, files::NVRAM)?;
    let generator = match webdevice::apnonce::read(&image).map_err(|e| anyhow!("{}: {e}", nvram_path.display()))? {
        Some(g) => g,
        None => {
            let g = u64::from_be_bytes(random::<8>());
            let saved = webdevice::apnonce::saved(&image, g).map_err(|e| anyhow!("{}: {e}", nvram_path.display()))?;
            replace(&nvram_path, &saved, 0o644)?;
            println!("AP nonce generator made in {}", nvram_path.display());
            g
        }
    };
    let bnch = webdevice::apnonce::hash(generator);
    let ticket = signed_ap_ticket(dir, &w, &build, &bnch)?;
    let signed = WebDevice { ap_ticket: Some(ticket.clone()), boot_nonce: Some(generator), ..w };
    signed.check_ap_ticket().map_err(|e| anyhow!("the signed AP ticket: {e}"))?;
    replace(&dir.join(files::AP_TICKET), &ticket, 0o644)?;
    println!("AP ticket {} ({} bytes) for AP nonce {}, boot-manifest-hash {}", dir.join(files::AP_TICKET).display(), ticket.len(), hex(&bnch), hex(&webdevice::boot_manifest_hash(&ticket)).to_uppercase());
    Ok(())
}

/// Move the cryptex1 boot slot of a device made before its NVRAM held its
/// nonce magazine into its NVRAM ([`webdevice::migrated_nvram`]), then
/// remove the slot's file. Its next boot holds the same nonce, so the
/// tickets signed for it stay good.
fn migrate(dir: &Path) -> Result<()> {
    let path = dir.join(files::CRYPTEX1_BOOT_SLOT);
    let slot = read(dir, files::CRYPTEX1_BOOT_SLOT)?;
    let w = load_files(dir)?;
    let nvram_path = dir.join(files::NVRAM);
    let image = read(dir, files::NVRAM)?;
    let out = webdevice::migrated_nvram(&w, &image, &slot).map_err(|e| anyhow!("{}: {e}", dir.display()))?;
    replace(&nvram_path, &out, 0o644)?;
    std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
    println!("cryptex1 boot slot moved from {} into {}", path.display(), nvram_path.display());
    show(dir)
}

/// The Image4 payloads of a Cryptex1 the device's AppleImage4 evaluates
/// against its ticket when the cryptexes are grafted: the root hashes and
/// trust caches (the disk images are not Image4 payloads).
const CRYPTEX1_PAYLOADS: [(&str, &[u8; 4]); 4] = [("Cryptex1,SystemVolume", b"cssy"), ("Cryptex1,SystemTrustCache", b"trcs"), ("Cryptex1,AppVolume", b"casy"), ("Cryptex1,AppTrustCache", b"trca")];

/// The web device's Cryptex1 ticket for build identity `build` and its
/// cryptex1 boot nonce hash `cnch`, as TSS signs a device's: its manifest
/// key (from `dir`, which holds it) signs the body
/// ([`webdevice::cryptex1_ticket`]), with 20 random bytes of the signer's
/// own. Then checked as the device's AppleImage4 will check it: each
/// Image4 payload the ticket has an object for, read from `ipsw` (the
/// extracted IPSW) at the identity's paths, must authenticate on the
/// device `w` once its cryptex1 boot nonce is the one of hash `cnch`.
pub(crate) fn signed_cryptex1_ticket(dir: &Path, w: &WebDevice, build: &Value, cnch: &[u8], ipsw: &Path) -> Result<Vec<u8>> {
    let manifest = Key(RsaPrivateKey::from_pkcs1_der(&read(dir, files::MANIFEST_KEY)?).map_err(|e| anyhow!("{}: {e}", dir.join(files::MANIFEST_KEY).display()))?);
    let leaf = read(dir, files::MANIFEST_CERT)?;
    let ticket = webdevice::cryptex1_ticket(&w.identity, build, cnch, &random::<20>(), &manifest, &leaf).map_err(|e| anyhow!("{e}"))?;
    for (key, code) in CRYPTEX1_PAYLOADS {
        let path = build
            .get("Manifest")
            .and_then(|m| m.get(key))
            .and_then(|c| c.get("Info"))
            .and_then(|i| i.get("Path"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("the build identity has no {key} path"))?;
        let payload = std::fs::read(ipsw.join(path)).with_context(|| format!("reading {}", ipsw.join(path).display()))?;
        match image4::execute(image4::fourcc(code), &payload, &ticket, &webdevice::ProposedEnv(w, cnch)) {
            Outcome::Authenticated(_) => {}
            other => bail!("the signed ticket does not authenticate {key} on this device: {other:?}"),
        }
    }
    Ok(ticket)
}

/// Sign the device's Cryptex1 ticket for the nonce its next boot holds,
/// checked as its AppleImage4 will check it ([`signed_cryptex1_ticket`]).
fn sign(dir: &Path) -> Result<()> {
    let w = load(dir)?;
    let (restore, build) = build_identity(Some((w.identity.chip, w.identity.board)))?;
    let cnch = nonce_hash(&w)?;
    let ticket = signed_cryptex1_ticket(dir, &w, &build, &cnch, &restore)?;
    replace(&dir.join(files::CRYPTEX1_TICKET), &ticket, 0o644)?;
    println!("Cryptex1 ticket {} ({} bytes) for nonce hash {}", dir.join(files::CRYPTEX1_TICKET).display(), ticket.len(), hex(&cnch));
    Ok(())
}

/// `gexc darwin-web-device init|show|migrate|nvram|sep|apkey|apticket <dir>`.
pub fn cmd_device(args: &[String]) -> Result<ExitCode> {
    match args {
        [op, dir] if op == "init" => init(Path::new(dir))?,
        [op, dir] if op == "show" => show(Path::new(dir))?,
        [op, dir] if op == "migrate" => migrate(Path::new(dir))?,
        [op, dir] if op == "nvram" => nvram(Path::new(dir))?,
        [op, dir] if op == "sep" => add_sep_uid(Path::new(dir))?,
        [op, dir] if op == "apkey" => add_ap_key(Path::new(dir))?,
        [op, dir] if op == "apticket" => sign_ap(Path::new(dir))?,
        _ => bail!("usage: gexc darwin-web-device init|show|migrate|nvram|sep|apkey|apticket <dir>"),
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
