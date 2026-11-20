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
//! - The nonces. The web device's NVRAM holds its AppleImage4's nonce
//!   magazine as the J120's does ([`super::noncemag`]): the slots, the
//!   cryptex1 boot one's hash made as on the J120
//!   ([`super::image4::nonce::cryptex1_boot_hash`]: SHA-384 of the 16-byte
//!   nonce, truncated to 32 bytes). Its nonces come from the kernel's
//!   random source, as the kext's roll and preroll take them; its restore
//!   rolls the cryptex1 boot nonce before TSS signs its ticket; nothing in
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
//! identity, its NVRAM and the tickets ([`WebDevice`]). The SEP's UID
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
    /// runtime, 0xfffffff005a9280c) and libimage4's AP chip reads, in their
    /// sizes, little-endian. The IPSW's device tree has each but
    /// `security-domain` and `chip-epoch` as a zero placeholder; the web
    /// device's boot adds those, which the tickets' SDOM and the AP ticket's
    /// CEPO are held to (libimage4's AP chip queries `chip-epoch` for CEPO,
    /// `ge`, with no answer of its own). The mix-n-match prevention status
    /// is a production device's (prevented).
    pub fn chosen(&self) -> Vec<(&'static str, Vec<u8>)> {
        let b = |v: bool| u32::from(v).to_le_bytes().to_vec();
        vec![
            ("chip-id", self.chip.to_le_bytes().to_vec()),
            ("board-id", self.board.to_le_bytes().to_vec()),
            ("unique-chip-id", self.ecid.to_le_bytes().to_vec()),
            ("security-domain", self.security_domain.to_le_bytes().to_vec()),
            ("chip-epoch", (AP_CERTIFICATE_EPOCH as u32).to_le_bytes().to_vec()),
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

/// The device's values a restore request rule's conditions name
/// (`__AMAuthInstallBundleGetValueForReservedKey`, libauthinstall 0x24210):
/// the raw production and security modes (the certificate's), the current
/// ones (the effective), whether it takes Image4, whether it is in the
/// ROM's DFU (a restore from iBoot's recovery is not), and its demotion
/// policy override, which the web device does not ask for (the empty
/// string the rules for a device without one test).
fn device_conditions(id: &Identity) -> [(&'static str, Value); 7] {
    [
        ("ApRawProductionMode", Value::Bool(id.production)),
        ("ApRawSecurityMode", Value::Bool(id.security)),
        ("ApCurrentProductionMode", Value::Bool(id.effective_production)),
        ("ApCurrentSecurityMode", Value::Bool(id.effective_security)),
        ("ApRequiresImage4", Value::Bool(true)),
        ("ApInRomDFU", Value::Bool(false)),
        ("ApDemotionPolicyOverride", Value::String(String::new())),
    ]
}

/// A restore request rule's conditions against the device's
/// (`__AMAuthInstallBundleCheckCondition` 0x24628 and
/// `__AMAuthInstallBundleGetValueForCondition` 0x244b0): all must hold; a
/// boolean or string condition holds when it is the device's value; one
/// naming none of the device's values holds when its value is false, the
/// empty string, zero or empty data (`__AMAuthInstallBundleGetDefaultResult`
/// 0x243b8).
fn rule_applies(conditions: &Value, id: &Identity) -> Result<bool, String> {
    let Value::Dict(c) = conditions else { return Err("a restore request rule's Conditions is not a dictionary".into()) };
    let device = device_conditions(id);
    for (k, want) in c {
        let holds = match device.iter().find(|(n, _)| n == k) {
            Some((_, have)) => match (have, want) {
                (Value::Bool(h), Value::Bool(w)) => h == w,
                (Value::String(h), Value::String(w)) => h == w,
                (Value::Bool(_), _) => false,
                (Value::String(_), _) => false,
                _ => return Err(format!("a restore request rule's condition {k} of a kind the device's value is not")),
            },
            None => match want {
                Value::Bool(b) => !b,
                Value::String(s) => s.is_empty(),
                Value::Integer(i) => *i == 0,
                Value::Data(d) => d.is_empty(),
                _ => false,
            },
        };
        if !holds {
            return Ok(false);
        }
    }
    Ok(true)
}

/// What a component's restore request rules give the device, in order
/// (`AMAuthInstallBundleProcessRules`, libauthinstall 0x248d4: each rule
/// whose conditions hold sets its actions, a later one replacing an
/// earlier's).
fn rule_actions(component: &Value, key: &str, id: &Identity) -> Result<Vec<(u32, bool)>, String> {
    let mut out: Vec<(u32, bool)> = Vec::new();
    let Some(rules) = component.get("Info").and_then(|i| i.get("RestoreRequestRules")) else { return Ok(out) };
    let rules = rules.as_array().ok_or_else(|| format!("the build identity's {key} RestoreRequestRules is not an array"))?;
    for r in rules {
        let cond = r.get("Conditions").ok_or_else(|| format!("a restore request rule of {key} has no Conditions"))?;
        if !rule_applies(cond, id)? {
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
            out.retain(|(c, _)| *c != code);
            out.push((code, *b));
        }
    }
    Ok(out)
}

/// A component's object properties: its digest and what its restore
/// request rules give the device, applied in order.
fn object_properties(component: &Value, key: &str, id: &Identity) -> Result<Vec<Vec<u8>>, String> {
    let digest = component.get("Digest").and_then(Value::as_data).ok_or_else(|| format!("the build identity's {key} has no Digest"))?;
    let mut props: Vec<(u32, Vec<u8>)> = vec![(cc(b"DGST"), enc::octets(digest))];
    for (code, v) in rule_actions(component, key, id)? {
        props.retain(|(c, _)| *c != code);
        props.push((code, enc::boolean(v)));
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

/// The AP manifest key's name. As Apple's TSS signs an AP ticket with a
/// leaf of its own for the chip and security domain
/// ("T8132-SDOM1-TssLive-ManifestKey-...", the host Mac's AP ticket), a
/// key other than its Cryptex1 key, the web device's AP tickets are
/// signed by an AP manifest key its root issues.
pub const AP_MANIFEST_KEY_NAME: &str = "UniXNU Web Device AP Manifest Key - G1";

/// The web device's AP certificate epoch: what its boot puts in `/chosen`'s
/// `chip-epoch` ([`Identity::chosen`]), the request's `ApCertificateEpoch`
/// its AP tickets carry as CEPO (`AMAuthInstallApImg4LocalCreateManifestBody`'s
/// first property) and its AP manifest key fixes, as Apple's AP manifest
/// keys fix theirs (the host Mac's: CEPO 1).
pub const AP_CERTIFICATE_EPOCH: u64 = 1;

/// The AP manifest key's Image4 constraints, in the form of Apple's AP
/// manifest keys (the host Mac's: `MANP` {BORD [0], CEPO, CHIP, SDOM, ...},
/// `OBJP` {DGST [0], EKEY [0]}): its chip, security domain and certificate
/// epoch fixed; the board, the modes, the ECID and the boot nonce hash
/// present, the ticket being personalized; each object's digest and its
/// encryption flag present.
pub fn ap_manifest_constraints(id: &Identity, epoch: u64) -> Vec<u8> {
    let manp = enc::set(&[
        present(b"BNCH", true),
        present(b"BORD", true),
        enc::property(cc(b"CEPO"), enc::int(epoch)),
        enc::property(cc(b"CHIP"), enc::int(id.chip.into())),
        present(b"CPRO", true),
        present(b"CSEC", true),
        present(b"ECID", true),
        enc::property(cc(b"SDOM"), enc::int(id.security_domain.into())),
    ]);
    let objp = enc::set(&[present(b"DGST", true), present(b"EKEY", true)]);
    enc::set(&[enc::property(cc(b"MANP"), manp), enc::property(cc(b"OBJP"), objp)])
}

/// The AP manifest key's certificate's description, issued by the root of
/// key `root_key`.
pub fn ap_manifest_key_spec(serial: [u8; 20], not_before: &str, not_after: &str, key: Vec<u8>, root_key: &[u8], id: &Identity, epoch: u64) -> CertSpec {
    CertSpec {
        serial,
        issuer: name(ROOT_NAME, ORGANIZATION),
        subject: name(AP_MANIFEST_KEY_NAME, ORGANIZATION),
        not_before: not_before.into(),
        not_after: not_after.into(),
        key,
        authority_key_id: Some(key_id(root_key)),
        ca: false,
        img4: Some(ap_manifest_constraints(id, epoch)),
    }
}

/// The AP nonce: its generator, NVRAM's `com.apple.System.boot-nonce`, and
/// the hash a TSS request's `ApNonce` and the AP ticket's `BNCH` carry.
pub mod apnonce {
    use super::super::nvram;
    use std::sync::Arc;

    /// The variable (`AppleMobileApNonce::start`, 0xfffffff006581618: its
    /// symbol; IODTNVRAM keeps it as a string, for the kernel only).
    pub const KEY: &[u8] = b"com.apple.System.boot-nonce";
    /// The variable's length: "0x" and 16 hexadecimal digits
    /// (0xfffffff006582840 refuses any other; 0xfffffff006581f1c too).
    pub const TEXT_LENGTH: usize = 0x12;
    /// The hash's length for `/chosen`'s `crypto-hash-method` "sha2-384":
    /// AppleMobileApNonce's method record 0xfffffff005581738 {2, 0x20}
    /// (SHA-384, 32 bytes; "sha1" is {1, 0x14}).
    pub const HASH_LENGTH: usize = 0x20;

    /// `_generateNonceHash` (0xfffffff006582224) without `/defaults`'
    /// `entangle-nonce` (the J120's has none): SHA-384 of the generator's
    /// eight bytes as the kext holds them (little-endian), its first
    /// [`HASH_LENGTH`] bytes.
    pub fn hash(generator: u64) -> Vec<u8> {
        use sha2::Digest;
        sha2::Sha384::digest(generator.to_le_bytes())[..HASH_LENGTH].to_vec()
    }

    /// The variable's text for a generator: `_generateNonce`'s
    /// "0x%016llx" (0xfffffff006581b50).
    pub fn text(generator: u64) -> String {
        format!("0x{generator:016x}")
    }

    /// The generator of the variable's bytes, as `_retrieveNonce`
    /// (0xfffffff006581f1c) takes it: 18 bytes, "0x", then `strtouq`
    /// in base 16 consuming the rest.
    pub fn parse(v: &[u8]) -> Result<u64, String> {
        if v.len() != TEXT_LENGTH {
            return Err(format!("nonce length {} expected {TEXT_LENGTH}", v.len()));
        }
        let digits = v.strip_prefix(b"0x").ok_or("the nonce does not start with 0x")?;
        let s = std::str::from_utf8(digits).map_err(|_| "the nonce is not hexadecimal")?;
        if !s.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("invalid nonce {s:?}"));
        }
        u64::from_str_radix(s, 16).map_err(|e| format!("invalid nonce {s:?}: {e}"))
    }

    /// The clock the save's forced sync reads, which it does not rate
    /// limit.
    struct Start;

    impl nvram::Clock for Start {
        fn uptime_secs(&self) -> i64 {
            0
        }
    }

    fn started(image: &[u8]) -> Result<(nvram::Nvram, Arc<nvram::MemMedium>), String> {
        nvram::over_image(image)
    }

    /// The generator the NVRAM image `image` holds, read as the kernel's
    /// IODTNVRAM gives it to AppleMobileApNonce (`copyProperty` by the
    /// kernel); none when the variable is not there.
    pub fn read(image: &[u8]) -> Result<Option<u64>, String> {
        let (mut nv, _) = started(image)?;
        match nv.copy_property(&nvram::Kernel, KEY) {
            None => Ok(None),
            Some(nvram::Value::String(s) | nvram::Value::Symbol(s) | nvram::Value::Data(s)) => parse(&s).map(Some),
            Some(v) => Err(format!("com.apple.System.boot-nonce holds {v:?}, not the nonce's text")),
        }
    }

    /// The NVRAM image `image` with the generator saved as
    /// `_saveNonceInNVRAM` (0xfffffff006582840) saves it: IODTNVRAM's
    /// `setProperty` of the variable to its text (a string), then
    /// `IONVRAM-FORCESYNCNOW-PROPERTY`, whose sync writes the namespace.
    pub fn saved(image: &[u8], generator: u64) -> Result<Vec<u8>, String> {
        let (mut nv, medium) = started(image)?;
        let r = nv.set_property_clocked(&nvram::Kernel, KEY, &nvram::Given::Value(nvram::Value::String(text(generator).into_bytes())), None, &Start);
        if r != nvram::ret::SUCCESS {
            return Err(format!("IODTNVRAM refuses com.apple.System.boot-nonce: {r:#x}"));
        }
        let sync = nvram::key::FORCE_SYNC_NOW;
        let r = nv.set_property_clocked(&nvram::Kernel, sync, &nvram::Given::Value(nvram::Value::String(sync.to_vec())), None, &Start);
        if !nv.write_errors.is_empty() {
            return Err(nv.write_errors.join("; "));
        }
        if r != nvram::ret::SUCCESS {
            return Err(format!("IODTNVRAM's forced sync: {r:#x}"));
        }
        let out = medium.0.lock().unwrap().clone();
        match read(&out)? {
            Some(g) if g == generator => Ok(out),
            other => Err(format!("the synced namespace holds {other:?}, not the generator saved")),
        }
    }
}

/// The AP ticket's digest as the boot's `/chosen` `boot-manifest-hash`
/// holds it and the Preboot volume's directory is named by: SHA-384 (the
/// J120's `crypto-hash-method` "sha2-384") of the whole IM4M, as AppleImage4
/// keeps the manifest's (0xfffffff005aa6df8's digest of the whole
/// manifest), restored's `ramrod_ticket_copy_nsih` names the directory and
/// the kernel's `kern.bootobjectspath` reads it back; on the host Mac the
/// three agree (its `/chosen` boot-manifest-hash, its Preboot
/// `boot/<hash>` and SHA-384 of the apticket.der there).
pub fn boot_manifest_hash(ticket: &[u8]) -> [u8; 48] {
    sha384(ticket)
}

/// The objects of the AP ticket by the build identity's component name:
/// libauthinstall's entry-name table (`_kImg4Types`, 0xc9240, which
/// `AMAuthInstallApImg4GetTypeForEntryName` gives a request tag's object by)
/// for the J120 identity's components, the four of no file whose names are
/// their tags, and the two restored evaluates by tag ('msys'
/// RE@0x100058108, 'isys' RE@0x100058714), which the table has not. The
/// `Cryptex1,` components are the Cryptex1 ticket's (restored's
/// `_personalize_splat_ticket` asks for theirs); `OS`, a disk image
/// restored by digest alone, has no object code in any 21H461 binary.
pub const AP_OBJECTS: [(&str, &[u8; 4]); 30] = [
    ("AOP", b"aopf"),
    ("AVE", b"avef"),
    ("Ap,SystemVolumeCanonicalMetadata", b"msys"),
    ("AppleLogo", b"logo"),
    ("BatteryCharging0", b"chg0"),
    ("BatteryCharging1", b"chg1"),
    ("BatteryFull", b"batF"),
    ("BatteryLow0", b"bat0"),
    ("BatteryLow1", b"bat1"),
    ("BatteryPlugin", b"glyP"),
    ("DeviceTree", b"dtre"),
    ("KernelCache", b"krnl"),
    ("LLB", b"illb"),
    ("RecoveryMode", b"recm"),
    ("RestoreDeviceTree", b"rdtr"),
    ("RestoreKernelCache", b"rkrn"),
    ("RestoreLogo", b"rlgo"),
    ("RestoreRamDisk", b"rdsk"),
    ("RestoreSEP", b"rsep"),
    ("RestoreTrustCache", b"rtsc"),
    ("SEP", b"sepi"),
    ("StaticTrustCache", b"trst"),
    ("SystemVolume", b"isys"),
    ("ftap", b"ftap"),
    ("ftsp", b"ftsp"),
    ("iBEC", b"ibec"),
    ("iBSS", b"ibss"),
    ("iBoot", b"ibot"),
    ("rfta", b"rfta"),
    ("rfts", b"rfts"),
];

/// The components the AP ticket leaves to others.
fn not_ap(key: &str) -> bool {
    key.starts_with("Cryptex1,") || key == "OS"
}

/// The build identity's manifest properties the request copies
/// (`__AMAuthInstallBundlePopulateManifestProperties`, libauthinstall
/// 0x26304: Ap,OSLongVersion, Ap,TargetType, Ap,ProductType, Ap,SDKPlatform,
/// Ap,Target among them) and the AP ticket's properties TSS makes of them
/// (the host Mac's AP ticket: love, tatp, prtp, sdkp and tagt hold its build
/// identity's values as octet strings).
pub const AP_IDENTITY_PROPERTIES: [(&str, &[u8; 4]); 5] = [("Ap,OSLongVersion", b"love"), ("Ap,ProductType", b"prtp"), ("Ap,SDKPlatform", b"sdkp"), ("Ap,Target", b"tagt"), ("Ap,TargetType", b"tatp")];

/// An AP component's object properties (`AMAuthInstallApImg4LocalAddImageProperties`,
/// libauthinstall 0xe19c, from the request entry
/// `__AMAuthInstallBundleCreateServerRequestDictionary` 0x1f478 makes of
/// the build identity's): its digest when the entry has one and it is
/// personalized (an entry with `Personalize` false is asked for with an
/// empty digest, which the ticket leaves out), `EKEY` its `Trusted`, and
/// what its restore request rules give the device.
fn ap_object_properties(component: &Value, key: &str, id: &Identity) -> Result<Vec<Vec<u8>>, String> {
    let info = component.get("Info").ok_or_else(|| format!("the build identity's {key} has no Info"))?;
    let personalize = match info.get("Personalize") {
        None => true,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err(format!("the build identity's {key} Personalize is not a boolean")),
    };
    let mut props: Vec<(u32, Vec<u8>)> = Vec::new();
    if personalize {
        if let Some(d) = component.get("Digest") {
            let d = d.as_data().ok_or_else(|| format!("the build identity's {key} Digest is not data"))?;
            if !d.is_empty() {
                props.push((cc(b"DGST"), enc::octets(d)));
            }
        }
    }
    match component.get("Trusted") {
        None => {}
        Some(Value::Bool(t)) => props.push((cc(b"EKEY"), enc::boolean(*t))),
        Some(_) => return Err(format!("the build identity's {key} Trusted is not a boolean")),
    }
    for (code, v) in rule_actions(component, key, id)? {
        props.retain(|(c, _)| *c != code);
        props.push((code, enc::boolean(v)));
    }
    Ok(props.into_iter().map(|(c, v)| enc::property(c, v)).collect())
}

/// The AP ticket's manifest body (the set holding `MANB`) for the device
/// `id` and build identity `build`, with the AP nonce hash `bnch`, the
/// device's certificate epoch `epoch` and the signer's random `srvn`
/// (TSS's 20 bytes, as in the host Mac's AP ticket). `MANP` is what
/// `AMAuthInstallApImg4LocalCreateManifestBody` (libauthinstall 0xca18)
/// makes of the request (CEPO, CHIP, BORD, ECID, SDOM, CPRO, CSEC, BNCH;
/// no SEP nonce, the web device's SEP having none to give), the
/// identity's properties ([`AP_IDENTITY_PROPERTIES`]) and `srvn`; one
/// object per component of [`AP_OBJECTS`].
pub fn ap_body(id: &Identity, build: &Value, bnch: &[u8], epoch: u64, srvn: &[u8; 20]) -> Result<Vec<u8>, String> {
    let what = "the build identity";
    if get_u32(build, "ApChipID", what)? != id.chip || get_u32(build, "ApBoardID", what)? != id.board || get_u32(build, "ApSecurityDomain", what)? != id.security_domain {
        return Err("the build identity is not the web device's chip, board and security domain".into());
    }
    let mut manp = vec![
        enc::property(cc(b"BNCH"), enc::octets(bnch)),
        enc::property(cc(b"BORD"), enc::int(id.board.into())),
        enc::property(cc(b"CEPO"), enc::int(epoch)),
        enc::property(cc(b"CHIP"), enc::int(id.chip.into())),
        enc::property(cc(b"CPRO"), enc::boolean(id.production)),
        enc::property(cc(b"CSEC"), enc::boolean(id.security)),
        enc::property(cc(b"ECID"), enc::int(id.ecid)),
        enc::property(cc(b"SDOM"), enc::int(id.security_domain.into())),
        enc::property(cc(b"srvn"), enc::octets(srvn)),
    ];
    for (k, code) in AP_IDENTITY_PROPERTIES {
        let v = build.get(k).and_then(Value::as_str).ok_or_else(|| format!("{what} has no {k}"))?;
        manp.push(enc::property(cc(code), enc::octets(v.as_bytes())));
    }
    let Some(Value::Dict(components)) = build.get("Manifest") else { return Err("the build identity has no Manifest".into()) };
    let mut manb = vec![enc::property(cc(b"MANP"), enc::set(&manp))];
    let mut seen: Vec<u32> = Vec::new();
    for (key, c) in components {
        if not_ap(key) {
            continue;
        }
        let code = AP_OBJECTS.iter().find(|(k, _)| k == key).map(|(_, c)| cc(c)).ok_or_else(|| format!("not implemented: the AP ticket's object for the build identity's {key} (no object code for it)"))?;
        if seen.contains(&code) {
            return Err(format!("the build identity's {key} names an object another component has"));
        }
        seen.push(code);
        manb.push(enc::property(code, enc::set(&ap_object_properties(c, key, id)?)));
    }
    Ok(enc::set(&[enc::property(cc(b"MANB"), enc::set(&manb))]))
}

/// The AP ticket, signed by the AP manifest key `signer` whose certificate
/// is `leaf`.
pub fn ap_ticket(id: &Identity, build: &Value, bnch: &[u8], epoch: u64, srvn: &[u8; 20], signer: &dyn Signer, leaf: &[u8]) -> Result<Vec<u8>, String> {
    let body = ap_body(id, build, bnch, epoch, srvn)?;
    let sig = signer.sign_sha384(&sha384(&body))?;
    Ok(im4m(&body, &sig, &[leaf.to_vec()]))
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
    /// Where a device made before its NVRAM held its nonce magazine kept
    /// the magazine's cryptex1 boot slot (AppleImage4's 37 bytes); `gexc
    /// darwin-web-device migrate` moves it into the NVRAM
    /// ([`super::noncemag`]) and removes the file.
    pub const CRYPTEX1_BOOT_SLOT: &str = "nonce-cryptex1-boot.slot";
    /// Its Cryptex1 ticket, which its Preboot volume holds as
    /// `cryptex1/current/apticket.<target>.<ECID>.im4m`.
    pub const CRYPTEX1_TICKET: &str = "cryptex1.im4m";
    /// Its NVRAM namespace: the bank IODTNVRAM's controller writes
    /// (`super::super::nvram`), made as its factory left it.
    pub const NVRAM: &str = "nvram.bin";
    /// The AP manifest key and its certificate.
    pub const AP_MANIFEST_KEY: &str = "ap-manifest.key";
    pub const AP_MANIFEST_CERT: &str = "ap-manifest.der";
    /// Its AP ticket: the RootTicketData its restore takes and the ticket
    /// its boot boots with (`boot-manifest-hash`), which its Preboot volume
    /// holds as `<hash>/System/Library/Caches/apticket.der`.
    pub const AP_TICKET: &str = "apticket.der";
}

/// The web device a run boots: what it has of its own.
#[derive(Clone, Debug)]
pub struct WebDevice {
    /// The root certificate its AppleImage4 trusts.
    pub root: Vec<u8>,
    pub identity: Identity,
    /// The cryptex1 boot slot its AppleImage4 will hold after its next boot
    /// ([`super::noncemag::next_boot_cryptex1_slot`] of its NVRAM), or why
    /// none is known.
    pub slot: Result<nonce::Slot, String>,
    /// Its Cryptex1 ticket's host path, when one is signed.
    pub ticket: Option<String>,
    /// Its AP ticket, when one is signed.
    pub ap_ticket: Option<Vec<u8>>,
    /// Its AP nonce generator, when its NVRAM holds one.
    pub boot_nonce: Option<u64>,
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

/// The web device's cryptex1 boot nonce hash after its next boot, as its
/// AppleImage4 makes it from its slot; `entangle_nonce` is `/defaults`'
/// `entangle-nonce`.
pub fn nonce_hash(w: &WebDevice, entangle_nonce: bool) -> Result<Vec<u8>, Fail> {
    let slot = w.slot.as_ref().map_err(|why| Fail::Unmodelled(why.clone()))?;
    nonce::cryptex1_boot_hash(slot, entangle_nonce)
}

/// The `/chosen` of the web device's boot as AppleImage4 reads it for its
/// nonce magazine: its identity, what its boot adds for its AP ticket and
/// nonce ([`WebDevice::boot_chosen`]) and iBoot's `fsboot` boot command.
struct BootChosen(Vec<(&'static str, Vec<u8>)>);

impl super::noncemag::Tree for BootChosen {
    fn prop(&self, node: &str, name: &str) -> Option<Vec<u8>> {
        (node == "/chosen").then(|| self.0.iter().find(|(n, _)| *n == name).map(|(_, v)| v.clone())).flatten()
    }
}

/// The web device from its directory's files as the host read them: its
/// root's certificate, its identity, the path of its Cryptex1 ticket when
/// it has one, its AP ticket when it has one and its NVRAM image when it
/// has one (its AP nonce generator read from it, and the cryptex1 boot
/// slot its next boot will hold).
pub fn of_files(root: Vec<u8>, identity: &[u8], ticket: Option<String>, ap_ticket: Option<Vec<u8>>, nvram: Option<&[u8]>) -> Result<WebDevice, String> {
    let identity = Identity::of_plist(&super::plist::parse(identity).map_err(|e| format!("the web device's {}: {e}", files::IDENTITY))?)?;
    let boot_nonce = match nvram {
        Some(image) => apnonce::read(image).map_err(|e| format!("the web device's {}: {e}", files::NVRAM))?,
        None => None,
    };
    let mut w = WebDevice { root, identity, slot: Err(String::new()), ticket, ap_ticket, boot_nonce };
    w.slot = match nvram {
        None => Err(format!("the web device has no NVRAM ({}), which holds its nonce magazine", files::NVRAM)),
        Some(image) => w.next_boot_chosen().and_then(|c| {
            super::noncemag::next_boot_cryptex1_slot(image, &BootChosen(c)).map_err(|e| match e {
                Fail::Unmodelled(w) => w,
                Fail::Panic(p) => format!("its kernel panics at AppleImage4's boot: {p}"),
                Fail::Code(c) => format!("errno {c}"),
            })
        }),
    };
    Ok(w)
}

impl WebDevice {
    /// Whether its AP ticket is its own for its current AP nonce: the
    /// ticket's ECID, chip, board and security domain its identity's and its
    /// BNCH the hash of the generator its NVRAM holds ([`apnonce::hash`]),
    /// which iBoot holds a ticket to before it boots with it. An error says
    /// what differs.
    pub fn check_ap_ticket(&self) -> Result<(), String> {
        use super::image4::{der, fourcc, manifest_property, tag};
        let Some(t) = &self.ap_ticket else { return Err(format!("the web device has no AP ticket ({})", files::AP_TICKET)) };
        let int = |code: &[u8; 4]| manifest_property(t, fourcc(code), tag::INTEGER).and_then(der::integer64).map_err(|e| format!("the AP ticket has no {} (libDER {e})", String::from_utf8_lossy(code)));
        let i = &self.identity;
        for (code, want) in [(b"ECID", i.ecid), (b"CHIP", i.chip.into()), (b"BORD", i.board.into()), (b"SDOM", i.security_domain.into())] {
            let have = int(code)?;
            if have != want {
                return Err(format!("the AP ticket's {} is {have:#x}, the web device's {want:#x}", String::from_utf8_lossy(code)));
            }
        }
        let bnch = manifest_property(t, fourcc(b"BNCH"), tag::OCTET_STRING).map_err(|e| format!("the AP ticket has no BNCH (libDER {e})"))?;
        let Some(g) = self.boot_nonce else { return Err("the web device's NVRAM holds no AP nonce generator (com.apple.System.boot-nonce)".into()) };
        if bnch != apnonce::hash(g).as_slice() {
            return Err("the AP ticket was signed for another AP nonce than the one the web device's NVRAM generator gives (the generator changed since)".into());
        }
        Ok(())
    }

    /// Its boot's `/chosen` beyond the device tree's: its identity, what its
    /// boot adds ([`WebDevice::boot_chosen`]) and the boot command of
    /// iBoot's `fsboot`, which boots it ([`super::noncemag::boot_command`]).
    pub fn next_boot_chosen(&self) -> Result<Vec<(&'static str, Vec<u8>)>, String> {
        let mut c = self.identity.chosen();
        c.extend(self.boot_chosen()?);
        c.push(("boot-command", super::noncemag::boot_command::FSBOOT.to_le_bytes().to_vec()));
        Ok(c)
    }

    /// What its boot puts in `/chosen` beyond its identity
    /// ([`Identity::chosen`]), as iBoot does for the ticket it boots with:
    /// `boot-nonce`, the AP nonce generator's eight bytes (the
    /// IPSW's placeholder's size; restored hashes them for its ApNonce,
    /// RE@0x10005b158, and takes them as BNCN, RE@0x10001e59c), and
    /// `boot-manifest-hash` ([`boot_manifest_hash`]) and the ticket's
    /// manifest properties ([`manifest_properties`]), when it has an AP
    /// ticket, which must be its own ([`WebDevice::check_ap_ticket`]).
    pub fn boot_chosen(&self) -> Result<Vec<(&'static str, Vec<u8>)>, String> {
        let mut v = Vec::new();
        if let Some(g) = self.boot_nonce {
            v.push(("boot-nonce", g.to_le_bytes().to_vec()));
        }
        if let Some(t) = &self.ap_ticket {
            self.check_ap_ticket()?;
            v.push(("boot-manifest-hash", boot_manifest_hash(t).to_vec()));
            v.extend(manifest_properties(t)?);
        }
        Ok(v)
    }
}

/// The AP ticket's manifest properties the boot publishes in
/// `/chosen/manifest-properties` (as [`super::iokit::fill_chosen`]'s
/// `manifest-properties/<code>` names), as iBoot fills that node from the
/// ticket it boots with: the IPSW's device tree holds it as placeholders
/// by type (UnusedIntegerProperty0-19 of 8 bytes, UnusedBooleanProperty0-19
/// of 4, UnusedStringProperty0-9 of 64), and the 21H461 readers ask it for
/// these by their codes: `love` (AppleImage4's ignition blob and version
/// query, 0xfffffff005a99b7c, and libimage4's,
/// `__darwin_el0_query_property_version` 0x6e54: read into 64 bytes, their
/// length the property's, which the version's string requires to hold no
/// NUL: the octets as they are), `BNCH` (the kext's digest dump
/// 0xfffffff005a98b6c and its odometer's nonce entanglement
/// 0xfffffff005a96578: the octets, a digest of their length) and `ECID`
/// (the kext's query of the original ECID, 0xfffffff005a94e9c: 8 bytes,
/// little-endian). Which of the ticket's other manifest properties iBoot
/// publishes, and what becomes of the placeholders it does not use, no
/// reader shows ([`super::img4::WEB_DEVICE_CHOSEN_STAND_IN`]).
pub fn manifest_properties(ticket: &[u8]) -> Result<Vec<(&'static str, Vec<u8>)>, String> {
    use super::image4::{der, fourcc, manifest_property, tag};
    let octets = |code: &[u8; 4]| manifest_property(ticket, fourcc(code), tag::OCTET_STRING).map(<[u8]>::to_vec).map_err(|e| format!("the AP ticket has no {} (libDER {e})", String::from_utf8_lossy(code)));
    let ecid = manifest_property(ticket, fourcc(b"ECID"), tag::INTEGER).and_then(der::integer64).map_err(|e| format!("the AP ticket has no ECID (libDER {e})"))?;
    Ok(vec![("manifest-properties/love", octets(b"love")?), ("manifest-properties/BNCH", octets(b"BNCH")?), ("manifest-properties/ECID", ecid.to_le_bytes().to_vec())])
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

/// The NVRAM namespace `image` of a web device that kept its cryptex1
/// boot slot in a file of its own ([`files::CRYPTEX1_BOOT_SLOT`], the
/// slot's 37 bytes `slot`), with that slot in its nonce magazine as
/// AppleImage4 leaves it after a boot under the device's AP ticket
/// ([`super::noncemag`]): the slot at its key and the magazine data with
/// the boot manifest hash, set by the kernel's task through IODTNVRAM,
/// then a forced sync. Its next boot holds the slot's nonce; the other
/// slots are what that boot makes of slots it cannot read. A namespace
/// that holds a magazine already is refused.
pub fn migrated_nvram(w: &WebDevice, image: &[u8], slot: &[u8]) -> Result<Vec<u8>, String> {
    use super::noncemag::{self, Storage};
    let old = nonce::Slot::parse(slot).map_err(|e| format!("{}: not a nonce slot AppleImage4 takes (errno {e})", files::CRYPTEX1_BOOT_SLOT))?;
    let Some(t) = &w.ap_ticket else { return Err(format!("the web device has no AP ticket ({}): its boot's boot-manifest-hash, which the magazine keeps, is its hash", files::AP_TICKET)) };
    w.check_ap_ticket()?;
    let (mut nv, medium) = super::nvram::over_image(image)?;
    struct Start;
    impl super::nvram::Clock for Start {
        fn uptime_secs(&self) -> i64 {
            0
        }
    }
    let mut st = noncemag::NvramStorage { nv: &mut nv, clock: &Start };
    for key in [noncemag::magazine_key(), noncemag::slot_key(noncemag::CRYPTEX1_BOOT)] {
        if st.read(&key, 0x80)? != Err(2) {
            return Err(format!("the NVRAM holds {key} already: its nonce magazine is there"));
        }
    }
    for (key, data) in [(noncemag::slot_key(noncemag::CRYPTEX1_BOOT), old.to_bytes().to_vec()), (noncemag::magazine_key(), noncemag::MagazineData::to_bytes(&boot_manifest_hash(t)).to_vec())] {
        let r = st.write(&key, Some(&data))?;
        if r != 0 {
            return Err(format!("IODTNVRAM refuses {key}: errno {r}"));
        }
    }
    st.sync(3)?;
    let out = medium.bytes();
    let moved = of_files(w.root.clone(), &super::plist::to_xml(&w.identity.to_plist()), w.ticket.clone(), w.ap_ticket.clone(), Some(&out))?;
    let had = nonce::cryptex1_boot_hash(&old, false).map_err(|e| format!("the slot's nonce hash: {e:?}"))?;
    match nonce_hash(&moved, false) {
        Ok(h) if h == had => Ok(out),
        other => Err(format!("the migrated NVRAM's next boot does not hold the slot's nonce: {other:?}")),
    }
}

/// The web device as its AppleImage4 will see it once the nonce whose
/// hash is the second field is its cryptex1 boot nonce: how a ticket
/// signed for a nonce its restore proposed is checked before the restore
/// writes it.
pub struct ProposedEnv<'a>(pub &'a WebDevice, pub &'a [u8]);

impl super::image4::Environment for ProposedEnv<'_> {
    fn chosen(&self, name: &str, size: usize) -> Result<Option<Vec<u8>>, i32> {
        DeviceEnv(self.0).chosen(name, size)
    }

    fn cryptex1_boot_nonce_hash(&self, _domain: u32) -> Result<Vec<u8>, Fail> {
        Ok(self.1.to_vec())
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
            slot: Ok(nonce::Slot { flags: 0, nonce: [7; 16], proposal: [0; 16] }),
            ticket: None,
            ap_ticket: None,
            boot_nonce: None,
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
        let slot = *w.slot.as_ref().unwrap();
        let rolled = WebDevice {
            slot: Ok(nonce::Slot { nonce: [9; 16], ..slot }),
            ..w.clone()
        };
        assert_eq!(cssy(&t, &rolled), Outcome::Status(e::ESTALE));
        let spent = WebDevice {
            slot: Ok(nonce::Slot { flags: nonce::flag::SPENT, ..slot }),
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
        // A roll at a spent nonce's level: a new nonce, the flags cleared
        // as the kext clears them.
        let mut r = nonce::Slot { flags: 0x40 | 0x2 | 0x1, ..slot };
        let d = super::super::noncemag::DOMAINS[super::super::noncemag::CRYPTEX1_BOOT];
        assert!(super::super::noncemag::roll(&mut r, &d, 0, &mut |b: &mut [u8]| {
            b.fill(1);
            Ok(())
        })
        .unwrap());
        assert_eq!((r.flags, r.nonce), (0, [1; 16]));
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

    fn ap_leaf_cert(by: &Key, id: &Identity) -> Vec<u8> {
        certificate(&ap_manifest_key_spec([0x33; 20], FROM, TO, keys().manifest.public_key(), &by.public_key(), id, AP_CERTIFICATE_EPOCH), by).unwrap()
    }

    /// A build identity shaped as 21H461's J120AP erase identity, with a
    /// few of its components: the SEP (rules on the raw modes, DSEC for a
    /// demoted development device), the system volume (rules on the current
    /// production mode), a component of no file (ftap: no digest, not
    /// personalized) and the two the AP ticket leaves to others.
    fn ap_build() -> Value {
        let b = Value::Bool;
        let rule = |actions: Vec<(&str, bool)>, cond: Vec<(&str, Value)>| {
            Value::Dict(vec![
                ("Actions".into(), Value::Dict(actions.into_iter().map(|(k, v)| (k.to_string(), Value::Bool(v))).collect())),
                ("Conditions".into(), Value::Dict(cond.into_iter().map(|(k, v)| (k.to_string(), v)).collect())),
            ])
        };
        let sep_rules = Value::Array(vec![
            rule(vec![("ESEC", false)], vec![("ApRawSecurityMode", b(false))]),
            rule(vec![("ESEC", true)], vec![("ApRawSecurityMode", b(true))]),
            rule(vec![("DSEC", true), ("ESEC", false)], vec![("ApDemotionPolicyOverride", Value::String(String::new())), ("ApRawProductionMode", b(false)), ("ApRawSecurityMode", b(true))]),
            rule(vec![("EPRO", false)], vec![("ApRawProductionMode", b(false))]),
            rule(vec![("EPRO", true)], vec![("ApRawProductionMode", b(true))]),
        ]);
        let comp = |digest: Option<u8>, trusted: Option<bool>, personalize: bool, rules: Value| {
            let mut d = Vec::new();
            if let Some(x) = digest {
                d.push(("Digest".to_string(), Value::Data(vec![x; 48])));
            }
            d.push(("Info".to_string(), Value::Dict(vec![("Personalize".into(), b(personalize)), ("RestoreRequestRules".into(), rules)])));
            if let Some(t) = trusted {
                d.push(("Trusted".to_string(), b(t)));
            }
            Value::Dict(d)
        };
        let mut id = match build() {
            Value::Dict(d) => d,
            _ => unreachable!(),
        };
        id.retain(|(k, _)| k != "Manifest");
        let s = |v: &str| Value::String(v.into());
        id.push(("Ap,OSLongVersion".into(), s("21.8.461.0.0,0")));
        id.push(("Ap,ProductType".into(), s("iPad7,1")));
        id.push(("Ap,SDKPlatform".into(), s("iphoneos")));
        id.push(("Ap,Target".into(), s("J120AP")));
        id.push(("Ap,TargetType".into(), s("j120")));
        id.push((
            "Manifest".into(),
            Value::Dict(vec![
                ("SEP".into(), comp(Some(0x5e), Some(true), true, sep_rules.clone())),
                ("SystemVolume".into(), comp(Some(0xda), Some(true), true, rules())),
                ("ftap".into(), comp(None, Some(true), false, rules())),
                ("OS".into(), comp(Some(0xd4), Some(true), false, rules())),
                ("Cryptex1,SystemVolume".into(), comp(Some(0x56), None, true, rules())),
            ]),
        ));
        Value::Dict(id)
    }

    /// An object's property's value (its content) in ticket `t`.
    fn object_value(t: &[u8], object: &[u8; 4], prop: &[u8; 4]) -> Vec<u8> {
        use super::super::image4::der;
        let m = image4::init_as_manifest(t).unwrap();
        let find = |c: &[u8], code: &[u8; 4]| -> Vec<u8> {
            let mut s = der::Seq::of(c);
            while let Ok(it) = s.next() {
                if (it.tag as u32).to_be_bytes() == *code {
                    return image4::property(it.content, it.tag).unwrap().value.to_vec();
                }
            }
            panic!("no {code:?}")
        };
        let body = der::decode_item(m.body).unwrap();
        let manb = find(body.content, b"MANB");
        find(&find(&manb, object), prop)
    }

    #[test]
    fn an_ap_ticket_has_what_tss_gives_the_device() {
        let w = device();
        let bnch = apnonce::hash(0x1122_3344_5566_7788);
        let t = ap_ticket(&w.identity, &ap_build(), &bnch, AP_CERTIFICATE_EPOCH, &[4; 20], &keys().manifest, &ap_leaf_cert(&keys().root, &w.identity)).unwrap();
        let (manp, objects) = layout(&t);
        assert_eq!(manp, ["BNCH", "BORD", "CEPO", "CHIP", "CPRO", "CSEC", "ECID", "SDOM", "love", "prtp", "sdkp", "srvn", "tagt", "tatp"]);
        let names: Vec<&str> = objects.iter().map(|(c, _)| c.as_str()).collect();
        assert_eq!(names, ["ftap", "isys", "sepi"]);
        let props = |c: &str| objects.iter().find(|(n, _)| n == c).unwrap().1.clone();
        assert_eq!(props("sepi"), ["DGST", "EKEY", "EPRO", "ESEC"]);
        assert_eq!(props("isys"), ["DGST", "EKEY", "EPRO", "ESEC"]);
        // Not personalized: asked for with an empty digest, so none.
        assert_eq!(props("ftap"), ["EKEY", "EPRO", "ESEC"]);
        let get = |o: &[u8; 4], p: &[u8; 4]| object_value(&t, o, p);
        assert_eq!(get(b"sepi", b"DGST"), [0x5e; 48]);
        assert_eq!(get(b"isys", b"DGST"), [0xda; 48]);
        // A production, secure device: EPRO and ESEC true, EKEY the
        // component's Trusted.
        for o in [b"sepi", b"isys", b"ftap"] {
            for p in [b"EKEY", b"EPRO", b"ESEC"] {
                assert_eq!(get(o, p), [0xff], "{o:?} {p:?}");
            }
        }
        let mp = |p: &[u8; 4], tag| image4::manifest_property(&t, image4::fourcc(p), tag).unwrap().to_vec();
        assert_eq!(mp(b"BNCH", image4::tag::OCTET_STRING), bnch);
        assert_eq!(mp(b"love", image4::tag::OCTET_STRING), b"21.8.461.0.0,0");
        assert_eq!(mp(b"tagt", image4::tag::OCTET_STRING), b"J120AP");
        assert_eq!(mp(b"srvn", image4::tag::OCTET_STRING), [4; 20]);
        assert_eq!(image4::der::integer64(&mp(b"ECID", image4::tag::INTEGER)).unwrap(), w.identity.ecid);
        // A development device (raw production false): the SEP's rules
        // demote it.
        let dev = Identity { production: false, ..w.identity };
        let body = ap_body(&dev, &ap_build(), &bnch, AP_CERTIFICATE_EPOCH, &[4; 20]).unwrap();
        let t2 = im4m(&body, &[0; 512], &[vec![0x30, 0x00]]);
        let get2 = |o: &[u8; 4], p: &[u8; 4]| object_value(&t2, o, p);
        assert_eq!((get2(b"sepi", b"DSEC"), get2(b"sepi", b"ESEC"), get2(b"sepi", b"EPRO")), (vec![0xff], vec![0x00], vec![0x00]));
        // A component the AP ticket has no object code for is refused.
        let mut other = ap_build();
        if let Value::Dict(d) = &mut other {
            if let Some((_, Value::Dict(m))) = d.iter_mut().find(|(k, _)| k == "Manifest") {
                m.push(("Unknown".into(), Value::Dict(vec![("Info".into(), Value::Dict(vec![]))])));
            }
        }
        assert!(ap_body(&w.identity, &other, &bnch, 1, &[4; 20]).unwrap_err().contains("Unknown"));
    }

    #[test]
    fn the_ap_manifest_key_carries_ap_constraints() {
        let k = keys();
        let w = device();
        let root = root_cert(&k.root);
        let leaf = ap_leaf_cert(&k.root, &w.identity);
        let (key, constraints) = image4::verify_chain(&root, &leaf).unwrap();
        assert_eq!(key, &k.manifest.public_key()[..]);
        assert_eq!(constraints, Some(&ap_manifest_constraints(&w.identity, AP_CERTIFICATE_EPOCH)[..]));
        assert_eq!(image4::verify_chain(&root_cert(&k.other), &leaf), Err(-1));
    }

    /// The generator as AppleMobileApNonce keeps it in NVRAM and hashes
    /// it; the web device's factory NVRAM has none, and one saved there is
    /// read back after the forced sync, the bank's generation moved on.
    #[test]
    fn the_ap_nonce_is_apple_mobile_ap_nonces() {
        use sha2::Digest;
        let g = 0x0123_4567_89ab_cdefu64;
        assert_eq!(apnonce::hash(g), sha2::Sha384::digest([0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01])[..32].to_vec());
        assert_eq!(apnonce::text(g), "0x0123456789abcdef");
        assert_eq!(apnonce::parse(b"0x0123456789abcdef"), Ok(g));
        assert_eq!(apnonce::parse(b"0x0123456789ABCDEF"), Ok(g));
        assert!(apnonce::parse(b"0x0123456789abcde").is_err());
        assert!(apnonce::parse(b"010123456789abcdef").is_err());
        assert!(apnonce::parse(b"0x0123456789abcdeg").is_err());
        assert!(apnonce::parse(b"0x+123456789abcdef").is_err());
        let factory = super::super::nvram::factory_image();
        assert_eq!(apnonce::read(&factory), Ok(None));
        let saved = apnonce::saved(&factory, g).unwrap();
        assert_eq!(saved.len(), factory.len());
        assert_eq!(apnonce::read(&saved), Ok(Some(g)));
        assert!(super::super::nvram::chrp::version(&saved).1 > super::super::nvram::chrp::version(&factory).1);
        let again = apnonce::saved(&saved, 0x42).unwrap();
        assert_eq!(apnonce::read(&again), Ok(Some(0x42)));
    }

    /// The boot's /chosen for its AP ticket: boot-nonce the generator's
    /// eight bytes and boot-manifest-hash SHA-384 of the whole ticket, for
    /// a ticket of its own; a ticket of another nonce or device is refused.
    #[test]
    fn the_boot_puts_its_ap_tickets_hash_in_chosen() {
        use sha2::Digest;
        let w = device();
        let g = 0x5555_aaaa_1234_9876u64;
        let leaf = ap_leaf_cert(&keys().root, &w.identity);
        let t = ap_ticket(&w.identity, &ap_build(), &apnonce::hash(g), AP_CERTIFICATE_EPOCH, &[4; 20], &keys().manifest, &leaf).unwrap();
        let mine = WebDevice { ap_ticket: Some(t.clone()), boot_nonce: Some(g), ..w.clone() };
        assert_eq!(mine.check_ap_ticket(), Ok(()));
        let c = mine.boot_chosen().unwrap();
        assert_eq!(
            c,
            vec![
                ("boot-nonce", g.to_le_bytes().to_vec()),
                ("boot-manifest-hash", sha2::Sha384::digest(&t).to_vec()),
                ("manifest-properties/love", b"21.8.461.0.0,0".to_vec()),
                ("manifest-properties/BNCH", apnonce::hash(g)),
                ("manifest-properties/ECID", w.identity.ecid.to_le_bytes().to_vec()),
            ]
        );
        assert_eq!(boot_manifest_hash(&t).to_vec(), sha2::Sha384::digest(&t).to_vec());
        // The generator changed since the ticket was signed.
        let rolled = WebDevice { boot_nonce: Some(g + 1), ..mine.clone() };
        assert!(rolled.boot_chosen().unwrap_err().contains("another AP nonce"));
        // No generator at all.
        assert!(WebDevice { boot_nonce: None, ..mine.clone() }.check_ap_ticket().unwrap_err().contains("no AP nonce generator"));
        // Another device's ticket.
        let other = WebDevice { identity: Identity { ecid: w.identity.ecid + 1, ..w.identity }, ..mine.clone() };
        assert!(other.check_ap_ticket().unwrap_err().contains("ECID"));
        // No ticket: only the generator.
        let bare = WebDevice { ap_ticket: None, ..mine };
        assert_eq!(bare.boot_chosen().unwrap(), vec![("boot-nonce", g.to_le_bytes().to_vec())]);
    }

    /// A slot kept in its own file moved into the NVRAM's nonce magazine:
    /// the next boot holds its nonce; a new device's NVRAM holds none (its
    /// first boot draws one); a namespace with a magazine is refused.
    #[test]
    fn the_nonce_slot_moves_into_the_nvram() {
        let w = device();
        let g = 0x5555_aaaa_1234_9876u64;
        let leaf = ap_leaf_cert(&keys().root, &w.identity);
        let t = ap_ticket(&w.identity, &ap_build(), &apnonce::hash(g), AP_CERTIFICATE_EPOCH, &[4; 20], &keys().manifest, &leaf).unwrap();
        let image = apnonce::saved(&super::super::nvram::factory_image(), g).unwrap();
        let identity = super::super::plist::to_xml(&w.identity.to_plist());
        let fresh = of_files(w.root.clone(), &identity, None, Some(t.clone()), Some(&image)).unwrap();
        assert!(fresh.slot.as_ref().unwrap_err().contains("random source"), "{:?}", fresh.slot);
        let slot = nonce::Slot { flags: 0, nonce: [0x3c; 16], proposal: [0; 16] };
        let moved = migrated_nvram(&fresh, &image, &slot.to_bytes()).unwrap();
        let after = of_files(w.root.clone(), &identity, None, Some(t), Some(&moved)).unwrap();
        assert_eq!(after.slot, Ok(slot));
        assert_eq!(nonce_hash(&after, false).unwrap(), nonce::cryptex1_boot_hash(&slot, false).unwrap());
        assert!(migrated_nvram(&after, &moved, &slot.to_bytes()).unwrap_err().contains("already"));
        assert!(migrated_nvram(&WebDevice { ap_ticket: None, ..after }, &image, &slot.to_bytes()).is_err());
    }

    /// The IPSW's build identity (GEX_DARWIN_RESTORE): the AP ticket has an
    /// object for each of the J120AP erase identity's components but the
    /// Cryptex1 ones and OS, each with the identity's digest when the
    /// component is personalized, EKEY its Trusted, EPRO and ESEC true; and
    /// the digests are of the IPSW's files where the directory has them
    /// (msys, isys, sepi).
    #[test]
    #[ignore = "needs GEX_DARWIN_RESTORE (21H461)"]
    fn an_ap_ticket_for_the_ipsws_identity_has_every_component() {
        use sha2::Digest;
        let dir = std::env::var("GEX_DARWIN_RESTORE").expect("GEX_DARWIN_RESTORE");
        let m = super::super::plist::parse(&std::fs::read(format!("{dir}/BuildManifest.plist")).unwrap()).unwrap();
        let b = super::super::preboot::erase_identity(&m, "j120ap").unwrap().clone();
        let id = Identity::for_build(&b, 0x0001_2345_6789_abcd).unwrap();
        let bnch = apnonce::hash(7);
        let t = ap_ticket(&id, &b, &bnch, AP_CERTIFICATE_EPOCH, &[4; 20], &keys().manifest, &ap_leaf_cert(&keys().root, &id)).unwrap();
        let (_, objects) = layout(&t);
        assert_eq!(objects.len(), AP_OBJECTS.len());
        let Some(Value::Dict(comps)) = b.get("Manifest") else { panic!() };
        for (key, c) in comps {
            let Some((_, code)) = AP_OBJECTS.iter().find(|(k, _)| k == key) else {
                assert!(key.starts_with("Cryptex1,") || key == "OS", "{key}");
                continue;
            };
            let props = &objects.iter().find(|(n, _)| n.as_bytes() == *code).unwrap().1;
            let personalize = c.get("Info").and_then(|i| i.get("Personalize")) != Some(&Value::Bool(false));
            let digest = c.get("Digest").and_then(Value::as_data).filter(|d| !d.is_empty());
            assert_eq!(props.contains(&"DGST".to_string()), personalize && digest.is_some(), "{key}");
            if let (true, Some(d)) = (personalize, digest) {
                assert_eq!(image4::object_property_data(&t, image4::fourcc(code), image4::fourcc(b"DGST")).unwrap(), d, "{key}");
                if let Some(path) = c.get("Info").and_then(|i| i.get("Path")).and_then(Value::as_str) {
                    if let Ok(file) = std::fs::read(format!("{dir}/{path}")) {
                        if c.get("Info").and_then(|i| i.get("Img4PayloadType")).is_none() {
                            assert_eq!(sha2::Sha384::digest(&file).as_slice(), d, "{key}");
                            // The file's IM4P type is the object's code.
                            if let Ok((ty, _)) = super::super::aar::im4p_payload(&file) {
                                assert_eq!(ty, code.as_slice(), "{key}");
                            }
                        }
                    }
                }
            }
            for p in [b"EPRO", b"ESEC"] {
                assert_eq!(object_value(&t, code, p), [0xff], "{key} {p:?}");
            }
            if let Some(Value::Bool(tr)) = c.get("Trusted") {
                assert_eq!(object_value(&t, code, b"EKEY"), [if *tr { 0xff } else { 0 }], "{key}");
            }
        }
    }
}
