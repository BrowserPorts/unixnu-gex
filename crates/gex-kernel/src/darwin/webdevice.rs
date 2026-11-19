//! The web device: a platform of its own, fused with its own root of trust
//! and identity, on which the J120AP's software runs unchanged
//! (GEX_DARWIN_CRYPTEX1_TICKET=web-device).
//!
//! AppleImage4's evaluation ([`super::image4`]) is the same as on an
//! Apple device; what differs is what a device's hardware and its
//! manufacturer give it:
//!
//! - The trust anchor. The web device's AppleImage4 trusts its platform's
//!   root certificate where the J120's trusts the root the kext embeds for
//!   `CHIP_CRYPTEX1_BOOT_AP` ([`Environment::anchor`]). The root is made
//!   per installation ([`root_spec`]), with the structure of Apple's
//!   secure boot roots: an X.509 v3 certificate with a 20-byte serial,
//!   sha384WithRSAEncryption, an RSA-4096 key, and the extensions basic
//!   constraints (critical, a CA), subject key identifier and key usage
//!   (critical, certificate and CRL signing).
//! - The manifest key. As Apple's TSS signs a Cryptex1 ticket with a leaf
//!   its root issued, the web device's tickets are signed by its manifest
//!   key, whose certificate the root issues ([`manifest_key_spec`]) with
//!   the extensions of Apple's manifest keys: basic constraints (critical,
//!   not a CA), authority and subject key identifiers, key usage (critical,
//!   digital signature) and the Image4 constraints
//!   (1.2.840.113635.100.6.1.15, critical, [`manifest_constraints`]).
//! - The identity ([`Identity`]): the ECID, chosen at random when the
//!   device is made, and the J120AP's chip, board and security domain from
//!   the IPSW's build identity, in production and secure mode. The web
//!   device's boot puts them in `/chosen` as iBoot does
//!   ([`Identity::chosen`]).
//! - The nonces. The web device keeps the cryptex1 boot slot of its nonce
//!   magazine ([`super::image4::nonce::Slot`], AppleImage4's 37-byte slot
//!   data), whose hash AppleImage4 makes as it does on the J120
//!   ([`super::image4::nonce::cryptex1_boot_hash`]): SHA-384 of the
//!   16-byte nonce, truncated to 32 bytes. Its nonces come from the
//!   kernel's random source, as the kext's roll takes them; nothing in
//!   the kext entangles them unless the slot or `/defaults` asks, and the
//!   web device's do not.
//! - The UID: a 32-byte secret of the web device's, made with it, which
//!   stands where the J120's AES engine's UID is: the key the engine's
//!   UID-derived keys (0x8A4, which would entangle a nonce, among them)
//!   come from once that engine is modelled. No computation here uses it.
//!
//! The Cryptex1 ticket ([`cryptex1_ticket`]) has the encoding, the
//! property set's order and the object layout of Apple's Cryptex1
//! manifests: the manifest properties from the build identity (its
//! `Ap*` and `Cryptex1,*` keys), the identity, the nonce hash and the
//! nonce domain, and one object per `Cryptex1,*` component of the build
//! identity with its digest and the properties its restore request rules
//! give a device in production and secure mode.
//!
//! - The SEP's UID ([`files::SEP_UID`]): the Secure Enclave has its own
//!   fused key, which only its AES engine uses ([`super::sep::secrets`]).
//!
//! The secrets (the two private keys, the UID) live per installation
//! outside every repository, and only the tools that make and sign read
//! them; a run reads what the device has: the root's certificate, the
//! identity, the nonce slot and the ticket ([`WebDevice`]). The SEP's UID
//! is read by the run's SEP core, as the fuse is read by the engine that
//! holds it, and by no other code.

use super::image4::{enc, fourcc, nonce, Fail};
use super::plist::Value;
use std::sync::OnceLock;

/// The web device's identity: its fuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub ecid: u64,
    pub chip: u32,
    pub board: u32,
    pub security_domain: u32,
    /// The certificate production status and security mode.
    pub production: bool,
    pub security: bool,
    /// The AP's effective production status and security mode.
    pub effective_production: bool,
    pub effective_security: bool,
}

/// A number of a build identity or an identity: an integer, or a string of
/// one in hexadecimal ("0x8011") or decimal.
pub fn number(v: &Value) -> Option<u64> {
    match v {
        Value::Integer(i) => u64::try_from(*i).ok(),
        Value::String(s) => match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            Some(h) => u64::from_str_radix(h, 16).ok(),
            None => s.parse().ok(),
        },
        _ => None,
    }
}

fn get_number(d: &Value, key: &str, what: &str) -> Result<u64, String> {
    number(d.get(key).ok_or_else(|| format!("{what} has no {key}"))?).ok_or_else(|| format!("{what}'s {key} is not a number"))
}

fn get_u32(d: &Value, key: &str, what: &str) -> Result<u32, String> {
    u32::try_from(get_number(d, key, what)?).map_err(|_| format!("{what}'s {key} is past 32 bits"))
}

fn get_bool(d: &Value, key: &str, what: &str) -> Result<bool, String> {
    match d.get(key) {
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(format!("{what}'s {key} is not a boolean")),
        None => Err(format!("{what} has no {key}")),
    }
}

impl Identity {
    /// The identity a device of build identity `build` has, with ECID
    /// `ecid`: the build identity's chip, board and security domain, in
    /// production and secure mode.
    pub fn for_build(build: &Value, ecid: u64) -> Result<Identity, String> {
        let what = "the build identity";
        Ok(Identity {
            ecid,
            chip: get_u32(build, "ApChipID", what)?,
            board: get_u32(build, "ApBoardID", what)?,
            security_domain: get_u32(build, "ApSecurityDomain", what)?,
            production: true,
            security: true,
            effective_production: true,
            effective_security: true,
        })
    }

    /// The identity's file (`device.plist`): the keys of a restore's
    /// device information where it has them.
    pub fn to_plist(&self) -> Value {
        Value::Dict(vec![
            ("ApECID".into(), Value::Integer(i128::from(self.ecid))),
            ("ApChipID".into(), Value::Integer(i128::from(self.chip))),
            ("ApBoardID".into(), Value::Integer(i128::from(self.board))),
            ("ApSecurityDomain".into(), Value::Integer(i128::from(self.security_domain))),
            ("ApProductionMode".into(), Value::Bool(self.production)),
            ("ApSecurityMode".into(), Value::Bool(self.security)),
            ("EffectiveProductionStatusAp".into(), Value::Bool(self.effective_production)),
            ("EffectiveSecurityModeAp".into(), Value::Bool(self.effective_security)),
        ])
    }

    pub fn of_plist(v: &Value) -> Result<Identity, String> {
        let what = "the web device's identity";
        Ok(Identity {
            ecid: get_number(v, "ApECID", what)?,
            chip: get_u32(v, "ApChipID", what)?,
            board: get_u32(v, "ApBoardID", what)?,
            security_domain: get_u32(v, "ApSecurityDomain", what)?,
            production: get_bool(v, "ApProductionMode", what)?,
            security: get_bool(v, "ApSecurityMode", what)?,
            effective_production: get_bool(v, "EffectiveProductionStatusAp", what)?,
            effective_security: get_bool(v, "EffectiveSecurityModeAp", what)?,
        })
    }

    /// What the web device's boot puts in `/chosen`, as iBoot fills it in
    /// on a device: the properties AppleImage4's instances read (its
    /// runtime, 0xfffffff005a9280c), in their sizes, little-endian. The
    /// IPSW's device tree has each but `security-domain` as a zero
    /// placeholder; the web device's boot adds that one, which the Cryptex1
    /// ticket's SDOM is held to. The mix-n-match prevention status is a
    /// production device's (prevented).
    pub fn chosen(&self) -> Vec<(&'static str, Vec<u8>)> {
        let b = |v: bool| u32::from(v).to_le_bytes().to_vec();
        vec![
            ("chip-id", self.chip.to_le_bytes().to_vec()),
            ("board-id", self.board.to_le_bytes().to_vec()),
            ("unique-chip-id", self.ecid.to_le_bytes().to_vec()),
            ("security-domain", self.security_domain.to_le_bytes().to_vec()),
            ("certificate-production-status", b(self.production)),
            ("certificate-security-mode", b(self.security)),
            ("effective-production-status-ap", b(self.effective_production)),
            ("effective-security-mode-ap", b(self.effective_security)),
            ("mix-n-match-prevention-status", b(true)),
        ]
    }
}

/// The OIDs the certificates name (their contents).
pub mod oid {
    pub const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
    pub const ORGANIZATION: &[u8] = &[0x55, 0x04, 0x0a];
    pub const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
    pub const SUBJECT_KEY_ID: &[u8] = &[0x55, 0x1d, 0x0e];
    pub const AUTHORITY_KEY_ID: &[u8] = &[0x55, 0x1d, 0x23];
    pub const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
    pub const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    pub const SHA384_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
    /// Apple's Image4 constraints extension, 1.2.840.113635.100.6.1.15.
    pub const IMG4: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x01, 0x0f];
}

/// The root's name.
pub const ROOT_NAME: &str = "UniXNU Web Device Secure Boot Root CA - G1";
/// The manifest key's name.
pub const MANIFEST_KEY_NAME: &str = "UniXNU Web Device Cryptex1 Manifest Key - G1";
/// The organization both name.
pub const ORGANIZATION: &str = "UniXNU";
/// The keys' size: the RSA-4096 of Apple's roots and manifest keys.
pub const KEY_BITS: usize = 4096;

/// A Name of a common name and an organization, each its own RDN.
pub fn name(cn: &str, o: &str) -> Vec<u8> {
    enc::seq(&[enc::set(&[enc::seq(&[enc::oid(oid::COMMON_NAME), enc::utf8(cn)])]), enc::set(&[enc::seq(&[enc::oid(oid::ORGANIZATION), enc::utf8(o)])])])
}

/// An RSAPublicKey (PKCS #1) of a modulus and exponent, big-endian.
pub fn rsa_public_key(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    enc::seq(&[enc::uint(modulus), enc::uint(exponent)])
}

/// A key's identifier (RFC 5280 4.2.1.2's first method): SHA-1 of its
/// subject public key's bits.
pub fn key_id(rsa_public_key: &[u8]) -> [u8; 20] {
    use sha1::Digest;
    sha1::Sha1::digest(rsa_public_key).into()
}

/// What a certificate says, to be signed.
#[derive(Clone, Debug)]
pub struct CertSpec {
    /// The serial number's 20 bytes, the first nonzero and below 0x80.
    pub serial: [u8; 20],
    pub issuer: Vec<u8>,
    pub subject: Vec<u8>,
    /// UTCTime strings, "YYMMDDHHMMSSZ".
    pub not_before: String,
    pub not_after: String,
    /// The subject's RSAPublicKey.
    pub key: Vec<u8>,
    /// The issuer's key identifier (none for a root, which issues itself).
    pub authority_key_id: Option<[u8; 20]>,
    pub ca: bool,
    /// The Image4 constraints, a leaf's.
    pub img4: Option<Vec<u8>>,
}

fn extension(id: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut items = vec![enc::oid(id)];
    if critical {
        items.push(enc::boolean(true));
    }
    items.push(enc::octets(value));
    enc::seq(&items)
}

fn sha384_with_rsa() -> Vec<u8> {
    enc::seq(&[enc::oid(oid::SHA384_WITH_RSA), enc::null()])
}

/// The certificate's signed part, its extensions in the order of Apple's.
pub fn tbs(c: &CertSpec) -> Result<Vec<u8>, String> {
    if c.serial[0] == 0 || c.serial[0] & 0x80 != 0 {
        return Err("a certificate's serial number must start with a byte in 1..0x80".into());
    }
    if c.not_before.len() != 13 || c.not_after.len() != 13 {
        return Err("a certificate's times are UTCTime strings, YYMMDDHHMMSSZ".into());
    }
    let mut ext = vec![extension(oid::BASIC_CONSTRAINTS, true, &if c.ca { enc::seq(&[enc::boolean(true)]) } else { enc::seq(&[]) })];
    if let Some(aki) = c.authority_key_id {
        ext.push(extension(oid::AUTHORITY_KEY_ID, false, &enc::seq(&[enc::tlv(&[0x80], &aki)])));
    }
    ext.push(extension(oid::SUBJECT_KEY_ID, false, &enc::octets(&key_id(&c.key))));
    // keyCertSign and cRLSign; digitalSignature.
    ext.push(extension(oid::KEY_USAGE, true, &if c.ca { vec![0x03, 0x02, 0x01, 0x06] } else { vec![0x03, 0x02, 0x07, 0x80] }));
    if let Some(img4) = &c.img4 {
        ext.push(extension(oid::IMG4, true, img4));
    }
    Ok(enc::seq(&[
        enc::context(0, &enc::int(2)),
        enc::tlv(&[0x02], &c.serial),
        sha384_with_rsa(),
        c.issuer.clone(),
        enc::seq(&[enc::tlv(&[0x17], c.not_before.as_bytes()), enc::tlv(&[0x17], c.not_after.as_bytes())]),
        c.subject.clone(),
        enc::seq(&[enc::seq(&[enc::oid(oid::RSA_ENCRYPTION), enc::null()]), enc::bits(&c.key)]),
        enc::context(3, &enc::seq(&ext)),
    ]))
}

/// What signs: RSA PKCS #1 v1.5 over a SHA-384 digest with its key, whose
/// RSAPublicKey it gives.
pub trait Signer {
    fn public_key(&self) -> Vec<u8>;
    fn sign_sha384(&self, digest: &[u8; 48]) -> Result<Vec<u8>, String>;
}

fn sha384(b: &[u8]) -> [u8; 48] {
    use sha2::Digest;
    sha2::Sha384::digest(b).into()
}

/// The certificate `c` describes, signed by `issuer`.
pub fn certificate(c: &CertSpec, issuer: &dyn Signer) -> Result<Vec<u8>, String> {
    let t = tbs(c)?;
    let sig = issuer.sign_sha384(&sha384(&t))?;
    Ok(enc::seq(&[t, sha384_with_rsa(), enc::bits(&sig)]))
}

/// The root's certificate's description: it issues itself.
pub fn root_spec(serial: [u8; 20], not_before: &str, not_after: &str, key: Vec<u8>) -> CertSpec {
    let n = name(ROOT_NAME, ORGANIZATION);
    CertSpec {
        serial,
        issuer: n.clone(),
        subject: n,
        not_before: not_before.into(),
        not_after: not_after.into(),
        key,
        authority_key_id: None,
        ca: true,
        img4: None,
    }
}

/// The manifest key's certificate's description, issued by the root of
/// key `root_key`.
pub fn manifest_key_spec(serial: [u8; 20], not_before: &str, not_after: &str, key: Vec<u8>, root_key: &[u8]) -> CertSpec {
    CertSpec {
        serial,
        issuer: name(ROOT_NAME, ORGANIZATION),
        subject: name(MANIFEST_KEY_NAME, ORGANIZATION),
        not_before: not_before.into(),
        not_after: not_after.into(),
        key,
        authority_key_id: Some(key_id(root_key)),
        ca: false,
        img4: Some(manifest_constraints()),
    }
}

fn cc(s: &[u8; 4]) -> u32 {
    fourcc(s)
}

/// A constraint that the manifest has the property (`[0]`), or has not
/// (`[1]`), whatever its value.
fn present(code: &[u8; 4], yes: bool) -> Vec<u8> {
    enc::property(cc(code), enc::context(if yes { 0 } else { 1 }, &enc::null()))
}

/// The manifest key's Image4 constraints, as Apple's Cryptex1 manifest
/// keys put them (the set of `MANP` and `OBJP`, each a set of
/// properties): the identity, the Cryptex1 chip's class and the version
/// must be there; the epoch and the Cryptex1 chip are fixed, as Apple's
/// keys fix them; the manifest is personalized, so its ECID, nonce hash
/// and nonce domain must be there (where a global key forbids them), and
/// no universal device identifier; and each object has its digest.
pub fn manifest_constraints() -> Vec<u8> {
    let manp = enc::set(&[
        present(b"BORD", true),
        enc::property(cc(b"CEPO"), enc::int(1)),
        present(b"CHIP", true),
        present(b"CPRO", true),
        present(b"CSEC", true),
        present(b"ECID", true),
        present(b"SDOM", true),
        present(b"UDID", false),
        present(b"clas", true),
        present(b"cnch", true),
        enc::property(cc(b"fchp"), enc::int(0xff10)),
        present(b"ndom", true),
        present(b"styp", true),
        present(b"type", true),
        present(b"vnum", true),
    ]);
    let objp = enc::set(&[present(b"DGST", true)]);
    enc::set(&[enc::property(cc(b"MANP"), manp), enc::property(cc(b"OBJP"), objp)])
}

/// The Cryptex1's components and their objects' codes (restored's table at
/// 0x100268528).
pub const CRYPTEX1_OBJECTS: [(&str, &[u8; 4]); 6] = [
    ("Cryptex1,SystemOS", b"csos"),
    ("Cryptex1,SystemVolume", b"cssy"),
    ("Cryptex1,SystemTrustCache", b"trcs"),
    ("Cryptex1,AppOS", b"caos"),
    ("Cryptex1,AppVolume", b"casy"),
    ("Cryptex1,AppTrustCache", b"trca"),
];

/// The epoch the ticket carries: the one `CHIP_CRYPTEX1_BOOT_AP`'s own
/// instance answers (0xfffffff0052cf550), which the ticket's must be at
/// least.
pub const CRYPTEX1_EPOCH: u64 = 1;

/// A restore request rule's conditions against the device's: each must
/// be the device's value; one the device does not have fails the rule.
fn rule_applies(conditions: &Value, device: &[(&str, bool)]) -> Result<bool, String> {
    let Value::Dict(c) = conditions else { return Err("a restore request rule's Conditions is not a dictionary".into()) };
    for (k, v) in c {
        let Value::Bool(want) = v else {
            // ApDemotionPolicyOverride names a policy the device has none of.
            return Ok(false);
        };
        match device.iter().find(|(n, _)| n == k) {
            Some((_, have)) if have == want => {}
            _ => return Ok(false),
        }
    }
    Ok(true)
}

/// A component's object properties: its digest and what its restore
/// request rules give the device, applied in order.
fn object_properties(component: &Value, key: &str, id: &Identity) -> Result<Vec<Vec<u8>>, String> {
    let digest = component.get("Digest").and_then(Value::as_data).ok_or_else(|| format!("the build identity's {key} has no Digest"))?;
    let mut props: Vec<(u32, Vec<u8>)> = vec![(cc(b"DGST"), enc::octets(digest))];
    // The device's restore parameters the rules ask about: in production
    // mode, secure, an Image4 device, not in DFU.
    let device = [("ApRequiresImage4", true), ("ApCurrentProductionMode", id.effective_production), ("ApRawSecurityMode", id.security), ("ApInRomDFU", false)];
    if let Some(rules) = component.get("Info").and_then(|i| i.get("RestoreRequestRules")) {
        let rules = rules.as_array().ok_or_else(|| format!("the build identity's {key} RestoreRequestRules is not an array"))?;
        for r in rules {
            let cond = r.get("Conditions").ok_or_else(|| format!("a restore request rule of {key} has no Conditions"))?;
            if !rule_applies(cond, &device)? {
                continue;
            }
            let Some(Value::Dict(actions)) = r.get("Actions") else {
                return Err(format!("a restore request rule of {key} has no Actions"));
            };
            for (name, v) in actions {
                let code: [u8; 4] = name.as_bytes().try_into().map_err(|_| format!("a restore request rule of {key} sets {name:?}, not a property"))?;
                let Value::Bool(b) = v else {
                    return Err(format!("a restore request rule of {key} sets {name} to a value that is not a boolean"));
                };
                let code = cc(&code);
                props.retain(|(c, _)| *c != code);
                props.push((code, enc::boolean(*b)));
            }
        }
    }
    Ok(props.into_iter().map(|(c, v)| enc::property(c, v)).collect())
}

/// The Cryptex1 ticket's manifest body (the set holding `MANB`) for the
/// device `id` and build identity `build`, with the device's cryptex1 boot
/// nonce hash `cnch` and the signer's random `srvn` (Apple's TSS puts 20
/// bytes of its own there).
pub fn cryptex1_body(id: &Identity, build: &Value, cnch: &[u8], srvn: &[u8; 20]) -> Result<Vec<u8>, String> {
    let what = "the build identity";
    if get_u32(build, "ApChipID", what)? != id.chip || get_u32(build, "ApBoardID", what)? != id.board || get_u32(build, "ApSecurityDomain", what)? != id.security_domain {
        return Err("the build identity is not the web device's chip, board and security domain".into());
    }
    let version = |k: &str| build.get(k).and_then(Value::as_str).map(|s| enc::octets(s.as_bytes())).ok_or_else(|| format!("{what} has no {k}"));
    let manp = enc::set(&[
        enc::property(cc(b"BORD"), enc::int(id.board.into())),
        enc::property(cc(b"CEPO"), enc::int(CRYPTEX1_EPOCH)),
        enc::property(cc(b"CHIP"), enc::int(id.chip.into())),
        enc::property(cc(b"CPRO"), enc::boolean(id.production)),
        enc::property(cc(b"CSEC"), enc::boolean(id.security)),
        enc::property(cc(b"ECID"), enc::int(id.ecid)),
        enc::property(cc(b"SDOM"), enc::int(id.security_domain.into())),
        enc::property(cc(b"clas"), enc::int(get_number(build, "Cryptex1,ProductClass", what)?)),
        enc::property(cc(b"cnch"), enc::octets(cnch)),
        enc::property(cc(b"fchp"), enc::int(get_number(build, "Cryptex1,ChipID", what)?)),
        enc::property(cc(b"ndom"), enc::int(get_number(build, "Cryptex1,NonceDomain", what)?)),
        enc::property(cc(b"pave"), version("Cryptex1,PreauthorizationVersion")?),
        enc::property(cc(b"srvn"), enc::octets(srvn)),
        enc::property(cc(b"styp"), enc::int(get_number(build, "Cryptex1,SubType", what)?)),
        enc::property(cc(b"type"), enc::int(get_number(build, "Cryptex1,Type", what)?)),
        enc::property(cc(b"vnum"), version("Cryptex1,Version")?),
    ]);
    let components = build.get("Manifest").ok_or("the build identity has no Manifest")?;
    let mut manb = vec![enc::property(cc(b"MANP"), manp)];
    for (key, code) in CRYPTEX1_OBJECTS {
        let Some(c) = components.get(key) else { continue };
        manb.push(enc::property(cc(code), enc::set(&object_properties(c, key, id)?)));
    }
    Ok(enc::set(&[enc::property(cc(b"MANB"), enc::set(&manb))]))
}

/// An IM4M of version 0: the body, its signature and the chain's
/// certificates.
pub fn im4m(body: &[u8], signature: &[u8], chain: &[Vec<u8>]) -> Vec<u8> {
    enc::seq(&[enc::ia5(b"IM4M"), enc::int(0), body.to_vec(), enc::octets(signature), enc::seq(chain)])
}

/// The Cryptex1 ticket, signed by the manifest key `signer` whose
/// certificate is `leaf`.
pub fn cryptex1_ticket(id: &Identity, build: &Value, cnch: &[u8], srvn: &[u8; 20], signer: &dyn Signer, leaf: &[u8]) -> Result<Vec<u8>, String> {
    let body = cryptex1_body(id, build, cnch, srvn)?;
    let sig = signer.sign_sha384(&sha384(&body))?;
    Ok(im4m(&body, &sig, &[leaf.to_vec()]))
}

/// The files of a web device's directory.
pub mod files {
    pub const ROOT_KEY: &str = "root.key";
    pub const ROOT_CERT: &str = "root.der";
    pub const MANIFEST_KEY: &str = "manifest.key";
    pub const MANIFEST_CERT: &str = "manifest.der";
    pub const IDENTITY: &str = "device.plist";
    pub const UID: &str = "uid.bin";
    /// The Secure Enclave's own UID, 32 bytes: the AES engine's UID key as
    /// the SEP's code sees it, distinct from the AP's ([`UID`]), as the
    /// fuses of the two engines are. The sepOS derives every key it keeps
    /// from it ([`super::sep::secrets`]).
    pub const SEP_UID: &str = "sep-uid.bin";
    /// The cryptex1 boot slot of its nonce magazine.
    pub const CRYPTEX1_BOOT_SLOT: &str = "nonce-cryptex1-boot.slot";
    /// Its Cryptex1 ticket, which its Preboot volume holds as
    /// `cryptex1/current/apticket.<target>.<ECID>.im4m`.
    pub const CRYPTEX1_TICKET: &str = "cryptex1.im4m";
    /// Its NVRAM namespace: the bank IODTNVRAM's controller writes
    /// (`super::super::nvram`), made as its factory left it.
    pub const NVRAM: &str = "nvram.bin";
}

/// The web device a run boots: what it has of its own.
#[derive(Clone, Debug)]
pub struct WebDevice {
    /// The root certificate its AppleImage4 trusts.
    pub root: Vec<u8>,
    pub identity: Identity,
    /// Its cryptex1 boot nonce slot.
    pub slot: nonce::Slot,
    /// Its Cryptex1 ticket's host path, when one is signed.
    pub ticket: Option<String>,
}

static WEB: OnceLock<WebDevice> = OnceLock::new();

/// The web device, once at boot.
pub fn set(w: WebDevice) -> Result<(), String> {
    WEB.set(w).map_err(|_| "the web device is set already".to_string())
}

/// The web device the system boots as, if it is one.
pub fn get() -> Option<&'static WebDevice> {
    WEB.get()
}

/// The web device's current cryptex1 boot nonce hash, as its AppleImage4
/// makes it from its slot; `entangle_nonce` is `/defaults`'
/// `entangle-nonce`.
pub fn nonce_hash(w: &WebDevice, entangle_nonce: bool) -> Result<Vec<u8>, Fail> {
    nonce::cryptex1_boot_hash(&w.slot, entangle_nonce)
}

/// The web device from its directory's files as the host read them: its
/// root's certificate, its identity, its cryptex1 boot slot, and the path
/// of its Cryptex1 ticket when it has one.
pub fn of_files(root: Vec<u8>, identity: &[u8], slot: &[u8], ticket: Option<String>) -> Result<WebDevice, String> {
    let identity = Identity::of_plist(&super::plist::parse(identity).map_err(|e| format!("the web device's {}: {e}", files::IDENTITY))?)?;
    let slot = nonce::Slot::parse(slot).map_err(|e| format!("the web device's {}: not a nonce slot AppleImage4 takes (errno {e})", files::CRYPTEX1_BOOT_SLOT))?;
    Ok(WebDevice { root, identity, slot, ticket })
}

/// The web device as its AppleImage4 sees it with nothing else in
/// `/chosen` than what its boot puts there ([`Identity::chosen`]): its
/// identity, its own nonce hash and its root. The tools check what they
/// sign against it.
pub struct DeviceEnv<'a>(pub &'a WebDevice);

impl super::image4::Environment for DeviceEnv<'_> {
    fn chosen(&self, name: &str, size: usize) -> Result<Option<Vec<u8>>, i32> {
        let Some((_, v)) = self.0.identity.chosen().into_iter().find(|(n, _)| *n == name) else { return Ok(None) };
        if v.len() > size {
            return Err(super::image4::e::EOVERFLOW);
        }
        let mut b = vec![0u8; size];
        b[..v.len()].copy_from_slice(&v);
        Ok(Some(b))
    }

    fn cryptex1_boot_nonce_hash(&self, _domain: u32) -> Result<Vec<u8>, Fail> {
        nonce_hash(self.0, false)
    }

    fn anchor(&self) -> Result<Vec<u8>, String> {
        Ok(self.0.root.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::super::image4::{self, e, execute, Outcome};
    use super::*;
    use rsa::traits::PublicKeyParts;
    use std::sync::OnceLock;

    struct Key(rsa::RsaPrivateKey);

    impl Signer for Key {
        fn public_key(&self) -> Vec<u8> {
            rsa_public_key(&self.0.n().to_bytes_be(), &self.0.e().to_bytes_be())
        }

        fn sign_sha384(&self, digest: &[u8; 48]) -> Result<Vec<u8>, String> {
            self.0.sign(rsa::Pkcs1v15Sign::new::<rsa::sha2::Sha384>(), digest).map_err(|e| e.to_string())
        }
    }

    /// The keys, made once: the root, the manifest key, and a root of
    /// another installation.
    struct Keys {
        root: Key,
        manifest: Key,
        other: Key,
    }

    fn keys() -> &'static Keys {
        static K: OnceLock<Keys> = OnceLock::new();
        K.get_or_init(|| {
            let mut rng = rsa::rand_core::OsRng;
            let mut k = |bits| Key(rsa::RsaPrivateKey::new(&mut rng, bits).unwrap());
            Keys {
                root: k(KEY_BITS),
                manifest: k(KEY_BITS),
                other: k(2048),
            }
        })
    }

    const FROM: &str = "261117000000Z";
    const TO: &str = "461112000000Z";

    fn root_cert(k: &Key) -> Vec<u8> {
        certificate(&root_spec([0x11; 20], FROM, TO, k.public_key()), k).unwrap()
    }

    fn leaf_cert(by: &Key) -> Vec<u8> {
        certificate(&manifest_key_spec([0x22; 20], FROM, TO, keys().manifest.public_key(), &by.public_key()), by).unwrap()
    }

    fn im4p(ty: &str, data: &[u8]) -> Vec<u8> {
        enc::seq(&[enc::ia5(b"IM4P"), enc::ia5(ty.as_bytes()), enc::ia5(b"1"), enc::octets(data)])
    }

    /// The build identity's restore request rules on a Cryptex1 component
    /// (21H461's).
    fn rules() -> Value {
        let rule = |action: &str, v: bool, cond: Vec<(&str, Value)>| {
            Value::Dict(vec![
                ("Actions".into(), Value::Dict(vec![(action.into(), Value::Bool(v))])),
                ("Conditions".into(), Value::Dict(cond.into_iter().map(|(k, v)| (k.to_string(), v)).collect())),
            ])
        };
        let b = Value::Bool;
        Value::Array(vec![
            rule("EPRO", false, vec![("ApCurrentProductionMode", b(false)), ("ApRequiresImage4", b(true))]),
            rule("EPRO", true, vec![("ApCurrentProductionMode", b(true)), ("ApRequiresImage4", b(true))]),
            rule(
                "EPRO",
                false,
                vec![
                    ("ApCurrentProductionMode", b(true)),
                    ("ApDemotionPolicyOverride", Value::String("Demote".into())),
                    ("ApInRomDFU", b(true)),
                    ("ApRequiresImage4", b(true)),
                ],
            ),
            rule("ESEC", false, vec![("ApRawSecurityMode", b(false)), ("ApRequiresImage4", b(true))]),
            rule("ESEC", true, vec![("ApRawSecurityMode", b(true)), ("ApRequiresImage4", b(true))]),
        ])
    }

    /// The payloads, by object code: the root hashes and trust caches as
    /// IM4Ps, the images as raw bytes.
    fn payloads() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("Cryptex1,SystemOS", b"an os image".to_vec()),
            ("Cryptex1,SystemVolume", im4p("cssy", b"an os root hash")),
            ("Cryptex1,SystemTrustCache", im4p("trcs", b"an os trust cache")),
            ("Cryptex1,AppOS", b"an app image".to_vec()),
            ("Cryptex1,AppVolume", im4p("casy", b"an app root hash")),
            ("Cryptex1,AppTrustCache", im4p("trca", b"an app trust cache")),
        ]
    }

    fn build() -> Value {
        let s = |v: &str| Value::String(v.into());
        let components = payloads()
            .into_iter()
            .map(|(k, p)| {
                (
                    k.to_string(),
                    Value::Dict(vec![("Digest".into(), Value::Data(sha384(&p).to_vec())), ("Info".into(), Value::Dict(vec![("RestoreRequestRules".into(), rules())]))]),
                )
            })
            .collect();
        Value::Dict(vec![
            ("ApBoardID".into(), s("0x0C")),
            ("ApChipID".into(), s("0x8011")),
            ("ApSecurityDomain".into(), s("0x01")),
            ("Cryptex1,ChipID".into(), s("0xFF10")),
            ("Cryptex1,NonceDomain".into(), Value::Integer(1)),
            ("Cryptex1,PreauthorizationVersion".into(), s("21.8.461.0.0,0")),
            ("Cryptex1,ProductClass".into(), s("0xF2")),
            ("Cryptex1,SubType".into(), Value::Integer(1)),
            ("Cryptex1,Type".into(), Value::Integer(1)),
            ("Cryptex1,Version".into(), s("21.8.461.0.0,0")),
            ("Manifest".into(), Value::Dict(components)),
        ])
    }

    fn device() -> WebDevice {
        let identity = Identity::for_build(&build(), 0x0001_2345_6789_abcd).unwrap();
        WebDevice {
            root: root_cert(&keys().root),
            identity,
            slot: nonce::Slot { flags: 0, nonce: [7; 16], proposal: [0; 16] },
            ticket: None,
        }
    }

    fn ticket_for(w: &WebDevice) -> Vec<u8> {
        let cnch = nonce_hash(w, false).unwrap();
        cryptex1_ticket(&w.identity, &build(), &cnch, &[3; 20], &keys().manifest, &leaf_cert(&keys().root)).unwrap()
    }

    fn payload(key: &str) -> Vec<u8> {
        payloads().into_iter().find(|(k, _)| *k == key).unwrap().1
    }

    fn eval(code: &[u8; 4], key: &str, ticket: &[u8], w: &WebDevice) -> Outcome {
        execute(image4::fourcc(code), &payload(key), ticket, &DeviceEnv(w))
    }

    #[test]
    fn der_is_as_apples_manifests_have_it() {
        // The tags and values of Apple's Cryptex1 manifests.
        assert_eq!(enc::private_tag(image4::fourcc(b"MANB")), [0xff, 0x84, 0xea, 0x85, 0x9c, 0x42]);
        assert_eq!(enc::private_tag(image4::fourcc(b"cssy")), [0xff, 0x86, 0x9b, 0xcd, 0xe6, 0x79]);
        assert_eq!(enc::int(0x8132), [0x02, 0x03, 0x00, 0x81, 0x32]);
        assert_eq!(enc::int(0), [0x02, 0x01, 0x00]);
        assert_eq!(enc::len(0x435), [0x82, 0x04, 0x35]);
        // A set in DER's order, whatever the order given.
        let (a, b, c) = (
            enc::property(image4::fourcc(b"CHIP"), enc::int(1)),
            enc::property(image4::fourcc(b"BORD"), enc::int(1)),
            enc::property(image4::fourcc(b"clas"), enc::int(1)),
        );
        assert_eq!(enc::set(&[c.clone(), a.clone(), b.clone()]), enc::set(&[b, a, c]));
        // Shorter encodings are compared padded with zeros.
        assert_eq!(enc::set(&[vec![0x04, 0x01, 0x00], vec![0x04, 0x00]]), [0x31, 0x05, 0x04, 0x00, 0x04, 0x01, 0x00]);
    }

    #[test]
    fn the_root_issues_the_manifest_key_with_its_constraints() {
        let k = keys();
        let root = root_cert(&k.root);
        let leaf = leaf_cert(&k.root);
        // The root issues itself; the leaf is its, and carries the Image4
        // constraints AppleImage4 holds the manifest to.
        let (key, constraints) = image4::verify_chain(&root, &root).unwrap();
        assert_eq!(key, &k.root.public_key()[..]);
        assert!(constraints.is_none());
        let (key, constraints) = image4::verify_chain(&root, &leaf).unwrap();
        assert_eq!(key, &k.manifest.public_key()[..]);
        assert_eq!(constraints, Some(&manifest_constraints()[..]));
        // Another installation's root did not issue it; a leaf another
        // root signed under this root's name is not this root's.
        assert_eq!(image4::verify_chain(&root_cert(&k.other), &leaf), Err(-1));
        assert_eq!(image4::verify_chain(&root, &leaf_cert(&k.other)), Err(-1));
        // The chain is the one leaf.
        assert_eq!(image4::verify_chain(&root, &[leaf.clone(), leaf.clone()].concat()), Err(-1));
        // The serial number's DER: positive and minimal.
        assert!(tbs(&root_spec([0x80; 20], FROM, TO, k.root.public_key())).is_err());
        assert!(tbs(&root_spec([0; 20], FROM, TO, k.root.public_key())).is_err());
    }

    #[test]
    fn a_signed_ticket_authenticates_each_payload() {
        let w = device();
        let t = ticket_for(&w);
        for (code, key) in [(b"cssy", "Cryptex1,SystemVolume"), (b"trcs", "Cryptex1,SystemTrustCache"), (b"casy", "Cryptex1,AppVolume"), (b"trca", "Cryptex1,AppTrustCache")] {
            let data = image4::init_as_payload(&payload(key)).unwrap().data.unwrap().to_vec();
            assert_eq!(eval(code, key, &t, &w), Outcome::Authenticated(data), "{key}");
        }
    }

    /// The ticket's properties in their order: the manifest's and each
    /// object's, by code.
    fn layout(t: &[u8]) -> (Vec<String>, Vec<(String, Vec<String>)>) {
        use super::super::image4::der;
        let m = image4::init_as_manifest(t).unwrap();
        fn codes(c: &[u8]) -> Vec<(String, &[u8])> {
            let mut s = der::Seq::of(c);
            let mut v = vec![];
            while let Ok(it) = s.next() {
                let p = image4::property(it.content, it.tag).unwrap();
                v.push((String::from_utf8_lossy(&(it.tag as u32).to_be_bytes()).into_owned(), p.value));
            }
            v
        }
        let body = der::decode_item(m.body).unwrap();
        let manb = codes(body.content)[0].1;
        let items = codes(manb);
        let manp = items[0].1;
        (
            codes(manp).into_iter().map(|(c, _)| c).collect(),
            items[1..].iter().map(|(c, v)| (c.clone(), codes(v).into_iter().map(|(c, _)| c).collect())).collect(),
        )
    }

    #[test]
    fn the_ticket_has_apples_layout() {
        let t = ticket_for(&device());
        let (manp, objects) = layout(&t);
        assert_eq!(manp, ["BORD", "CEPO", "CHIP", "CPRO", "CSEC", "ECID", "SDOM", "clas", "cnch", "fchp", "ndom", "pave", "srvn", "styp", "type", "vnum"]);
        let names: Vec<&str> = objects.iter().map(|(c, _)| c.as_str()).collect();
        assert_eq!(names, ["caos", "casy", "csos", "cssy", "trca", "trcs"]);
        assert!(objects.iter().all(|(_, p)| p == &["DGST", "EPRO", "ESEC"]));
        // Version 0, a signature of the manifest key's size, one certificate.
        let m = image4::init_as_manifest(&t).unwrap();
        assert_eq!((m.version, m.signature.len()), (0, KEY_BITS / 8));
        assert_eq!(image4::der::decode_item(m.chain).unwrap().whole.len(), m.chain.len());
    }

    #[test]
    fn what_the_device_does_not_match_fails_as_appleimage4_fails_it() {
        let k = keys();
        let w = device();
        let t = ticket_for(&w);
        let cssy = |t: &[u8], w: &WebDevice| eval(b"cssy", "Cryptex1,SystemVolume", t, w);
        // Another installation's root: the chain fails, EAUTH.
        let other = WebDevice { root: root_cert(&k.other), ..w.clone() };
        assert_eq!(cssy(&t, &other), Outcome::Status(e::EAUTH));
        // Another device's ECID, chip or board: the manifest's property is
        // violated, EACCES.
        for id in [
            Identity { ecid: w.identity.ecid + 1, ..w.identity },
            Identity { chip: 0x8010, ..w.identity },
            Identity { board: 0x0e, ..w.identity },
            Identity { security: false, ..w.identity },
        ] {
            assert_eq!(cssy(&t, &WebDevice { identity: id, ..w.clone() }), Outcome::Status(e::EACCES), "{id:?}");
        }
        // The nonce rolled since the ticket was signed: ESTALE; a spent
        // nonce: the slot's ESTALE.
        let rolled = WebDevice {
            slot: w.slot.rolled([9; 16]).unwrap(),
            ..w.clone()
        };
        assert_eq!(cssy(&t, &rolled), Outcome::Status(e::ESTALE));
        let spent = WebDevice {
            slot: nonce::Slot { flags: nonce::flag::SPENT, ..w.slot },
            ..w.clone()
        };
        assert_eq!(cssy(&t, &spent), Outcome::Status(e::ESTALE));
        // A payload that is not the one the ticket names: its digest, an
        // object's violated constraint, ENOEXEC; so is an object's EPRO the
        // device's effective production status does not match.
        let other_payload = im4p("cssy", b"another root hash");
        assert_eq!(execute(image4::fourcc(b"cssy"), &other_payload, &t, &DeviceEnv(&w)), Outcome::Status(e::ENOEXEC));
        let demoted = WebDevice {
            identity: Identity { effective_production: false, ..w.identity },
            ..w.clone()
        };
        assert_eq!(cssy(&t, &demoted), Outcome::Status(e::ENOEXEC));
        // A payload type the ticket has no object of: libDER's end of the
        // sequence, EAUTH.
        assert_eq!(execute(image4::fourcc(b"exvl"), &im4p("exvl", b"x"), &t, &DeviceEnv(&w)), Outcome::Status(e::EAUTH));
        // A byte of the body or the signature changed: EAUTH.
        let m = image4::init_as_manifest(&t).unwrap();
        let body_at = m.body.as_ptr() as usize - t.as_ptr() as usize;
        let sig_at = m.signature.as_ptr() as usize - t.as_ptr() as usize;
        for at in [body_at + 40, sig_at + 7] {
            let mut bad = t.clone();
            bad[at] ^= 1;
            assert_eq!(cssy(&bad, &w), Outcome::Status(e::EAUTH), "byte {at}");
        }
        // The manifest key signed by another root.
        let cnch = nonce_hash(&w, false).unwrap();
        let foreign = cryptex1_ticket(&w.identity, &build(), &cnch, &[3; 20], &k.manifest, &leaf_cert(&k.other)).unwrap();
        assert_eq!(cssy(&foreign, &w), Outcome::Status(e::EAUTH));
        // A ticket signed by another key than the leaf's.
        let forged = cryptex1_ticket(&w.identity, &build(), &cnch, &[3; 20], &k.other, &leaf_cert(&k.root)).unwrap();
        assert_eq!(cssy(&forged, &w), Outcome::Status(e::EAUTH));
        // Not a manifest at all: EFTYPE.
        assert_eq!(cssy(b"not a ticket", &w), Outcome::Status(e::EFTYPE));
    }

    #[test]
    fn the_manifest_keys_constraints_hold_what_it_signs() {
        // A body without the nonce domain the key requires, signed by the
        // key itself: the certificate's constraints fail it, EAUTH.
        let k = keys();
        let w = device();
        let cnch = nonce_hash(&w, false).unwrap();
        let body = cryptex1_body(&w.identity, &build(), &cnch, &[3; 20]).unwrap();
        let ndom = enc::property(image4::fourcc(b"ndom"), enc::int(1));
        let at = body.windows(ndom.len()).position(|x| x == ndom.as_slice()).unwrap();
        // Rebuild the sets around the shorter MANP.
        let mut manp_props = Vec::new();
        let mut s = image4::der::Seq::of(image4::der::decode_item(&body[..]).unwrap().content);
        let manb = s.next().unwrap();
        let manb_set = image4::property(manb.content, manb.tag).unwrap().value;
        let mut items = image4::der::Seq::of(manb_set);
        let manp = items.next().unwrap();
        let mut ps = image4::der::Seq::of(image4::property(manp.content, manp.tag).unwrap().value);
        while let Ok(p) = ps.next() {
            if p.whole != ndom.as_slice() {
                manp_props.push(p.whole.to_vec());
            }
        }
        assert!(at > 0);
        let mut manb_items = vec![enc::property(image4::fourcc(b"MANP"), enc::set(&manp_props))];
        while let Ok(o) = items.next() {
            manb_items.push(o.whole.to_vec());
        }
        let body = enc::set(&[enc::property(image4::fourcc(b"MANB"), enc::set(&manb_items))]);
        let sig = k.manifest.sign_sha384(&sha384(&body)).unwrap();
        let t = im4m(&body, &sig, &[leaf_cert(&k.root)]);
        assert_eq!(eval(b"cssy", "Cryptex1,SystemVolume", &t, &w), Outcome::Status(e::EAUTH));
    }

    #[test]
    fn the_nonce_hash_is_appleimage4s() {
        use sha2::Digest;
        let slot = nonce::Slot {
            flags: 0,
            nonce: [0xa5; 16],
            proposal: [0; 16],
        };
        let h = nonce::cryptex1_boot_hash(&slot, false).unwrap();
        assert_eq!(h, sha2::Sha384::digest([0xa5; 16])[..32].to_vec());
        // The slot's data round trips; the parse keeps the flags' last
        // byte's low bits.
        let b = nonce::Slot { flags: 0x44, ..slot }.to_bytes();
        assert_eq!(&b[..5], &[0, 0, 0, 0, 0x44]);
        assert_eq!(nonce::Slot::parse(&b).unwrap().flags, 0x44);
        let mut hi = b;
        hi[1] = 0xff;
        hi[4] = 0xc4;
        assert_eq!(nonce::Slot::parse(&hi).unwrap().flags, 0x44);
        assert_eq!(nonce::Slot::parse(&[]), Err(e::ENODATA));
        assert_eq!(nonce::Slot::parse(&b[..36]), Err(e::ERANGE));
        let mut v1 = b.to_vec();
        v1[0] = 1;
        assert_eq!(nonce::Slot::parse(&v1), Err(e::ESHLIBVERS));
        assert_eq!(nonce::Slot::parse(&v1[..36]), Err(e::ERANGE));
        // Entangling, asked by the slot or /defaults, is the AES engine's.
        assert!(matches!(nonce::cryptex1_boot_hash(&nonce::Slot { flags: nonce::flag::ENTANGLE, ..slot }, false), Err(Fail::Unmodelled(_))));
        assert!(matches!(nonce::cryptex1_boot_hash(&slot, true), Err(Fail::Unmodelled(_))));
        assert!(matches!(nonce::cryptex1_boot_hash(&nonce::Slot { flags: nonce::flag::UNAVAILABLE, ..slot }, false), Err(Fail::Unmodelled(_))));
        // A roll: a new nonce, the flags cleared as the kext clears them.
        let r = nonce::Slot { flags: 0x40 | 0x2 | 0x1, ..slot }.rolled([1; 16]).unwrap();
        assert_eq!((r.flags, r.nonce), (0, [1; 16]));
        assert!(nonce::Slot { flags: nonce::flag::PROPOSAL, ..slot }.rolled([1; 16]).is_err());
    }

    #[test]
    fn the_identity_is_kept_and_put_in_chosen() {
        let w = device();
        let x = super::super::plist::to_xml(&w.identity.to_plist());
        assert_eq!(Identity::of_plist(&super::super::plist::parse(&x).unwrap()).unwrap(), w.identity);
        let chosen = w.identity.chosen();
        let get = |n: &str| chosen.iter().find(|(k, _)| *k == n).unwrap().1.clone();
        assert_eq!(get("unique-chip-id"), 0x0001_2345_6789_abcdu64.to_le_bytes());
        assert_eq!(get("chip-id"), 0x8011u32.to_le_bytes());
        assert_eq!(get("board-id"), 0x0cu32.to_le_bytes());
        // A build identity of another device is not signed for this one.
        let mut other = build();
        if let Value::Dict(d) = &mut other {
            d[0].1 = Value::String("0x0E".into());
        }
        assert!(cryptex1_body(&w.identity, &other, &[0; 32], &[0; 20]).is_err());
    }

    /// An Apple-signed Cryptex1 ticket (a Mac's global one from its Preboot
    /// volume, with that cryptex's root hash and its root, Apple Extra
    /// Content Global Root CA - G1, from the kernelcache; local files,
    /// GEX_TEST_APPLE_CRYPTEX1): re-encoded from its properties, it is
    /// itself byte for byte; against Apple's root (a device of Apple's) its
    /// chain and signature verify and the evaluation reaches the
    /// properties, where this kext's product class (0xF2, an iPad's) is not
    /// the Mac's (EACCES); against the web device's root, EAUTH.
    #[test]
    #[ignore = "needs GEX_TEST_APPLE_CRYPTEX1: a Mac's apticket.j713ap.im4m, os.dmg.root_hash and extra-content-global-root-g1.der"]
    fn an_apple_ticket_evaluates_against_apples_root_and_not_the_web_devices() {
        let dir = std::env::var("GEX_TEST_APPLE_CRYPTEX1").expect("GEX_TEST_APPLE_CRYPTEX1");
        let t = std::fs::read(format!("{dir}/apticket.j713ap.im4m")).unwrap();
        let payload = std::fs::read(format!("{dir}/os.dmg.root_hash")).unwrap();
        let apple_root = std::fs::read(format!("{dir}/extra-content-global-root-g1.der")).unwrap();
        // The encoder against Apple's encoding: each property set rebuilt
        // from its items in DER's order.
        fn reencode(it: &image4::der::Item<'_>) -> Vec<u8> {
            let (_, mut s) = image4::der::seq_init(it.content).unwrap();
            let _name = s.next().unwrap();
            let value = s.next().unwrap();
            let value = if value.tag == image4::tag::SET { set_of(value.content) } else { value.whole.to_vec() };
            enc::property(it.tag as u32, value)
        }
        fn set_of(c: &[u8]) -> Vec<u8> {
            let mut items = vec![];
            let mut s = image4::der::Seq::of(c);
            while let Ok(it) = s.next() {
                items.push(reencode(&it));
            }
            enc::set(&items)
        }
        let m = image4::init_as_manifest(&t).unwrap();
        let body = set_of(image4::der::decode_item(m.body).unwrap().content);
        assert_eq!(body, m.body, "the manifest body re-encoded");
        assert_eq!(im4m(&body, m.signature, &[m.chain.to_vec()]), t, "the whole ticket re-encoded");
        // The device whose ticket it is, as far as this kext's AP chip asks.
        struct Mac(Vec<u8>);
        impl image4::Environment for Mac {
            fn chosen(&self, name: &str, size: usize) -> Result<Option<Vec<u8>>, i32> {
                let v: u32 = match name {
                    "chip-id" => 0x8132,
                    "board-id" => 0x2c,
                    "security-domain" | "certificate-production-status" | "certificate-security-mode" | "mix-n-match-prevention-status" => 1,
                    _ => return Ok(None),
                };
                let mut b = vec![0u8; size];
                b[..4].copy_from_slice(&v.to_le_bytes());
                Ok(Some(b))
            }
            fn cryptex1_boot_nonce_hash(&self, _: u32) -> Result<Vec<u8>, Fail> {
                Err(Fail::Unmodelled("a global ticket has no nonce".into()))
            }
            fn anchor(&self) -> Result<Vec<u8>, String> {
                Ok(self.0.clone())
            }
        }
        let cssy = image4::fourcc(b"cssy");
        // The digest restored_external takes for the object, as
        // libamsupport finds it: the root hash's.
        use sha2::Digest;
        assert_eq!(image4::object_property_data(&t, cssy, image4::fourcc(b"DGST")).unwrap(), &sha2::Sha384::digest(&payload)[..]);
        assert_eq!(execute(cssy, &payload, &t, &Mac(apple_root.clone())), Outcome::Status(e::EACCES));
        let mut bad = t.clone();
        let at = m.signature.as_ptr() as usize - t.as_ptr() as usize + 100;
        bad[at] ^= 1;
        assert_eq!(execute(cssy, &payload, &bad, &Mac(apple_root)), Outcome::Status(e::EAUTH));
        assert_eq!(execute(cssy, &payload, &t, &Mac(root_cert(&keys().root))), Outcome::Status(e::EAUTH));
    }

    /// The IPSW's build identity (GEX_DARWIN_RESTORE): a ticket signed for
    /// it authenticates the four Image4 payloads of 21H461's Cryptex1.
    #[test]
    #[ignore = "needs GEX_DARWIN_RESTORE (21H461)"]
    fn a_ticket_for_the_ipsws_identity_authenticates_its_payloads() {
        let dir = std::env::var("GEX_DARWIN_RESTORE").expect("GEX_DARWIN_RESTORE");
        let m = super::super::plist::parse(&std::fs::read(format!("{dir}/BuildManifest.plist")).unwrap()).unwrap();
        let b = super::super::preboot::erase_identity(&m, "j120ap").unwrap().clone();
        let w = WebDevice {
            identity: Identity::for_build(&b, 0x0001_2345_6789_abcd).unwrap(),
            ..device()
        };
        let cnch = nonce_hash(&w, false).unwrap();
        let t = cryptex1_ticket(&w.identity, &b, &cnch, &[3; 20], &keys().manifest, &leaf_cert(&keys().root)).unwrap();
        let comps = b.get("Manifest").unwrap();
        for (key, code) in [("Cryptex1,SystemVolume", b"cssy"), ("Cryptex1,SystemTrustCache", b"trcs"), ("Cryptex1,AppVolume", b"casy"), ("Cryptex1,AppTrustCache", b"trca")] {
            let path = comps.get(key).unwrap().get("Info").unwrap().get("Path").unwrap().as_str().unwrap();
            let p = std::fs::read(format!("{dir}/{path}")).unwrap();
            assert!(matches!(execute(image4::fourcc(code), &p, &t, &DeviceEnv(&w)), Outcome::Authenticated(_)), "{key}");
        }
    }
}
