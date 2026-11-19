//! libimage4's evaluation of an Image4 payload for the AP chip, as the
//! restore ramdisk's `restored_external` asks for it
//! (`ramrod_get_trusted_img4_payload`, RE@0x100057818) when it checks the
//! canonical metadata ('msys', RE@0x100058108) and the root hash ('isys',
//! RE@0x100058714) against the AP ticket stitched to them
//! (`/usr/lib/libimage4.dylib` of the 21H461 erase ramdisk, 257.140.2).
//!
//! RE@0x100057818 with no separate manifest and no custom manifest hash:
//! `img4_chip_select_effective_ap()` ([`select_effective_ap`]),
//! `img4_firmware_new(_img4_runtime_restore, ctx, tag, payload, 5)`
//! (`IMG4_FIRMWARE_FLAG_ATTACHED_MANIFEST | IMG4_FIRMWARE_FLAG_SUBSEQUENT_STAGE`,
//! "im4m is NULL. Assuming payload with attached manifest") and
//! `img4_firmware_execute(fw, chip, NULL)`; its callback (RE@0x100057d64)
//! takes the image's bytes when the execution hands it an image, and fails
//! with the status otherwise.
//!
//! `_img4_runtime_restore` (0x3ee80) is a stock runtime
//! (`img4_runtime_check_custom_bool` 0x10a10 and `_digest` 0x10a54 find
//! it in the list of stock runtimes at 0x3f640), whose expert is
//! `generic_expert_specialist`'s (`_restore_runtime_resolve_expert`
//! 0xef5c): in userspace the darwin el0 expert (`___del0` 0x48000), which
//! reads the device tree through IOKit: `IODeviceTree:/chosen`, its
//! `manifest-properties` (both required, `_darwin_el0_init` 0x5cc4) and
//! `asmb` ([`Registry`]).
//!
//! `img4_firmware_execute` (0x9f34) → `img4_firmware_evaluate` (0xa02c):
//! 1. the payload parsed (`payload_parse_relax` 0xb718 →
//!    `Img4DecodeInitAsPayload` 0xa7b4: an IMG4, else an IM4P; no type
//!    check): its libDER error as an errno (`posixdr` 0xd710);
//! 2. the manifest the payload carries (`manifest_init_borrow` 0x860c of
//!    the payload's buffer, `manifest_parse` 0x86d8 →
//!    `Img4DecodeInitAsManifest` 0xa808): any failure EFTYPE;
//! 3. `manifest_impose` (0x88b0 → 0x8140) for the chip: the odometer
//!    prepared ([`Odometer::prepare`]), the firmware's prepare callback
//!    (`_img4_firmware_prepare` 0xa204: the subsequent stage forces the
//!    sideload mix-n-match policy; a chip with no nonce domain at +0x1b8
//!    sets mix-n-match god mode), the trust evaluation
//!    (`Img4DecodePerformTrustEvaluationWithCallbacks` 0x233d0, with
//!    `_manifest_validate_property` 0x88e8 for each property), and the
//!    odometer's enforcement ([`Odometer::enforce`]);
//! 4. EBADEXEC (an object's violated constraint) becomes ENOEXEC.
//!
//! On success the image's bytes are the IM4P's data
//! (`_payload_im4p_get_verified_bytes` 0xb9f4: `Img4DecodeGetPayload`).

use super::image4::{self, der, dr, e, fourcc, tag, Fail, Outcome};
use sha2::{Digest, Sha384};

/// What the darwin el0 expert reads through IOKit.
pub trait Registry {
    /// Whether the device tree has the node at `path` (`IORegistryEntryFromPath`).
    fn node(&self, path: &str) -> bool;
    /// Property `name` of the node at `path`, as `IORegistryEntryCreateCFProperty`
    /// gives it: `None` when the node or the property is not there.
    fn property(&self, path: &str, name: &str) -> Option<Vec<u8>>;
    /// The anchor the chip's chain is verified against: on the web device
    /// its platform's root; on a device of Apple's the "Apple Secure Boot
    /// Root CA - G2" `crack_chain_rsa4k_sha384` (0x2482c) embeds
    /// (0x2c590, 1374 bytes), or why it is not there.
    fn anchor(&self) -> Result<Vec<u8>, String>;
}

pub const CHOSEN: &str = "IODeviceTree:/chosen";
pub const MANIFEST_PROPERTIES: &str = "IODeviceTree:/chosen/manifest-properties";
pub const ASMB: &str = "IODeviceTree:/chosen/asmb";

/// A device tree as the registry: a restore ramdisk's, with the anchor its
/// libimage4 trusts.
pub struct Tree<'a> {
    pub nodes: &'a [super::iokit::Node],
    pub anchor: Result<Vec<u8>, String>,
}

impl Registry for Tree<'_> {
    fn node(&self, path: &str) -> bool {
        super::iokit::dt_has(self.nodes, path)
    }
    fn property(&self, path: &str, name: &str) -> Option<Vec<u8>> {
        super::iokit::dt_prop(self.nodes, path, name).map(<[u8]>::to_vec)
    }
    fn anchor(&self) -> Result<Vec<u8>, String> {
        self.anchor.clone()
    }
}

type R<T> = Result<T, Fail>;

/// `_darwin_read_iokit_node` (0x1124): property `name` of the node at
/// `path` into a buffer of `cap` bytes: ENOENT when absent, EOVERFLOW
/// (0x54) when longer, else its bytes.
fn read_node(r: &dyn Registry, path: &str, name: &str, cap: usize) -> Result<Vec<u8>, i32> {
    match r.property(path, name) {
        None => Err(e::ENOENT),
        Some(v) if v.len() > cap => Err(e::EOVERFLOW),
        Some(v) => Ok(v),
    }
}

/// A little-endian value of at most `n` bytes, zero-extended (the readers'
/// zeroed buffers).
fn le(b: &[u8], n: usize) -> u64 {
    let mut x = [0u8; 8];
    x[..b.len().min(n)].copy_from_slice(&b[..b.len().min(n)]);
    u64::from_le_bytes(x)
}

/// `_darwin_read_iokit_bool` (0x1244) and `_u32` (0x1304): absent is
/// false or 0; another error panics.
fn read_u32_or_absent(r: &dyn Registry, path: &str, name: &str) -> R<u32> {
    match read_node(r, path, name, 4) {
        Ok(v) => Ok(le(&v, 4) as u32),
        Err(e::ENOENT) => Ok(0),
        Err(c) => Err(Fail::Panic(format!("failed to read property: {name}: {c}"))),
    }
}

/// The chips `img4_chip_select_effective_ap` can give.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chip {
    /// `_chip_ap_sha2_384` (0x416f8, 'aps2'): decode
    /// `kImg4DecodeSecureBootRsa4kSha384` (0x44230), digest SHA-384, no
    /// constraint overrides (+0x40..+0x138), no chip expert (+0x150), the
    /// properties it leaves out (+0x158: AMNM, iuou, euou, fpgt, love),
    /// nonce hash BNCH (+0x190), mix-n-match AMNM (+0x1a8), no nonce domain
    /// (+0x1b8), boot manifest hash bmfh (+0x1f0), digest DGST (+0x1f8 0).
    ApSha2_384,
}

/// `img4_chip_select_effective_ap` (0x78bc): the specialist's secure boot
/// state (`_darwin_el0_get_secure_boot` 0x6410: `asmb`'s `lp-smb0` +
/// `lp-smb1`, 0 without the node, 3 or more panics), then
/// `_darwin_el0_query_chip` (0x64d8): for state 0 the chip of `/chosen`'s
/// `crypto-hash-method` ("sha1": none; "sha2-384": `_chip_ap_sha2_384`;
/// anything else panics), replaced by `_img4_chip_ap_vma2` for
/// `use-ddi-secure-boot`, `_img4_chip_ap_vma2_clone` for
/// `allow-ecid-mismatch` and `_chip_vma3` for `uses-avp-root-ca`; for
/// states 1 and 2 `_chip_ap_reduced`.
pub fn select_effective_ap(r: &dyn Registry) -> R<Chip> {
    el0_init(r)?;
    let sb = if r.node(ASMB) { read_u32_or_absent(r, ASMB, "lp-smb0")?.wrapping_add(read_u32_or_absent(r, ASMB, "lp-smb1")?) } else { 0 };
    if sb >= 3 {
        return Err(Fail::Panic(format!("invalid secure boot state: {sb:#x}")));
    }
    if sb != 0 {
        return Err(Fail::Unmodelled(format!("libimage4's _chip_ap_reduced (0x3cb58), the chip of secure boot state {sb}")));
    }
    // `_darwin_read_iokit_cstr` (0x13d0): 64 bytes, absent an empty string.
    let m = match read_node(r, CHOSEN, "crypto-hash-method", 0x40) {
        Ok(v) => v,
        Err(e::ENOENT) => Vec::new(),
        Err(c) => return Err(Fail::Panic(format!("failed to read property: crypto-hash-method: {c}"))),
    };
    let s: Vec<u8> = m.iter().copied().take_while(|&c| c != 0).collect();
    let chip = if s.starts_with(b"sha1") {
        None
    } else if s.len() >= 8 && &s[..8] == b"sha2-384" {
        Some(Chip::ApSha2_384)
    } else {
        return Err(Fail::Panic(format!("non-sensical crypto hash method: {}", String::from_utf8_lossy(&s))));
    };
    for (name, other) in [("use-ddi-secure-boot", "_img4_chip_ap_vma2"), ("allow-ecid-mismatch", "_img4_chip_ap_vma2_clone"), ("uses-avp-root-ca", "_chip_vma3")] {
        if read_u32_or_absent(r, CHOSEN, name)? != 0 {
            return Err(Fail::Unmodelled(format!("libimage4's {other}, the chip /chosen's {name} selects")));
        }
    }
    chip.ok_or_else(|| Fail::Unmodelled("the AP chip of a \"sha1\" crypto-hash-method (none: the execution's chip would be NULL)".into()))
}

/// `_darwin_el0_init` (0x5cc4): `/chosen` and its `manifest-properties`
/// must be there.
fn el0_init(r: &dyn Registry) -> R<()> {
    if !r.node(CHOSEN) {
        return Err(Fail::Panic("failed to get chosen node".into()));
    }
    if !r.node(MANIFEST_PROPERTIES) {
        return Err(Fail::Panic("failed to get manifest properties".into()));
    }
    Ok(())
}

/// A property type (`_property_type_*`, 0x3f0c0..).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ty {
    Bool,
    U32,
    U64,
    Digest,
    Version,
}

/// A constraint (`_property_constraint_*`, 0x3f110..): eq, lt, le, gt, ge,
/// ne, un, rp, na.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Eq,
    Lt,
    Le,
    Gt,
    Ge,
    Ne,
    Un,
    Rp,
    Na,
}

/// A property descriptor (0x68 bytes): its code (+0x18), the expert's index
/// (+0x10, 0x1f none), type (+0x28), constraint (+0x30), container (+0x38:
/// 0 the manifest's, 1 an object's, 3 and 5 others), and whether
/// `___handle_absence` (0x26f4) answers false for it when the device does
/// not have it (+0x58).
#[derive(Clone, Copy, Debug)]
struct Desc {
    code: u32,
    index: u8,
    ty: Ty,
    op: Op,
    container: u8,
    absent_false: bool,
}

const fn d(code: &[u8; 4], index: u8, ty: Ty, op: Op, container: u8) -> Desc {
    Desc { code: fourcc(code), index, ty, op, container, absent_false: false }
}

const fn da(code: &[u8; 4], index: u8, ty: Ty, op: Op, container: u8) -> Desc {
    Desc { absent_false: true, ..d(code, index, ty, op, container) }
}

const NONE: u8 = 0x1f;

/// The property list `_property_iterator_next` (0xa668) walks: 0x3b2d0, 37
/// descriptors in this order.
const DESCS: [Desc; 37] = [
    d(b"CEPO", 0x00, Ty::U32, Op::Ge, 0),
    d(b"BORD", 0x01, Ty::U32, Op::Eq, 0),
    d(b"CHIP", 0x02, Ty::U32, Op::Eq, 0),
    d(b"SDOM", 0x03, Ty::U32, Op::Eq, 0),
    d(b"ECID", 0x04, Ty::U64, Op::Eq, 0),
    d(b"CPRO", 0x05, Ty::Bool, Op::Eq, 0),
    d(b"CSEC", 0x06, Ty::Bool, Op::Eq, 0),
    d(b"UDID", 0x09, Ty::Digest, Op::Eq, 0),
    d(b"BNCN", NONE, Ty::Digest, Op::Na, 3),
    d(b"BNCH", NONE, Ty::Digest, Op::Eq, 0),
    d(b"DGST", NONE, Ty::Digest, Op::Eq, 1),
    d(b"EPRO", 0x07, Ty::Bool, Op::Eq, 1),
    d(b"ESEC", 0x08, Ty::Bool, Op::Eq, 1),
    da(b"AMNM", 0x0b, Ty::Bool, Op::Rp, 0),
    d(b"CHMH", 0x0a, Ty::Digest, Op::Eq, 0),
    d(b"iuob", 0x0c, Ty::Bool, Op::Le, 0),
    da(b"iuou", 0x0d, Ty::Bool, Op::Na, 0),
    d(b"love", 0x11, Ty::Version, Op::Na, 0),
    d(b"vnum", 0x11, Ty::Version, Op::Ge, 0),
    da(b"euou", 0x0e, Ty::Bool, Op::Na, 0),
    da(b"fpgt", 0x0f, Ty::Bool, Op::Na, 0),
    d(b"snuf", NONE, Ty::Digest, Op::Eq, 0),
    d(b"vuid", 0x10, Ty::Digest, Op::Eq, 0),
    d(b"fchp", 0x14, Ty::U32, Op::Eq, 0),
    d(b"type", 0x15, Ty::U32, Op::Eq, 0),
    d(b"styp", 0x16, Ty::U32, Op::Eq, 0),
    d(b"clas", 0x17, Ty::U32, Op::Eq, 0),
    d(b"ndom", 0x18, Ty::U32, Op::Rp, 0),
    d(b"cnch", NONE, Ty::Digest, Op::Eq, 0),
    d(b"spih", 0x19, Ty::Digest, Op::Eq, 0),
    d(b"nsph", 0x1a, Ty::Digest, Op::Eq, 5),
    d(b"stng", 0x1b, Ty::U64, Op::Gt, 0),
    d(b"rsch", 0x12, Ty::Bool, Op::Le, 0),
    d(b"esdm", 0x13, Ty::U32, Op::Eq, 0),
    d(b"boid", 0x1e, Ty::Digest, Op::Eq, 0),
    d(b"lndm", 0x1d, Ty::U32, Op::Rp, 0),
    d(b"lnch", NONE, Ty::Digest, Op::Eq, 0),
];

/// `_property_bmfh` (0x3fd48), the chip's boot manifest hash property
/// (+0x1f0): container 5, outside the list.
const BMFH: Desc = d(b"bmfh", 0x0a, Ty::Digest, Op::Eq, 5);

fn desc(code: &[u8; 4]) -> &'static Desc {
    DESCS.iter().find(|x| x.code == fourcc(code)).expect("a listed property")
}

/// `_property_find_from_fourcc` (0xf574): the first descriptor of container
/// `container` coded `code`, those of constraint `na` left out.
fn find_desc(code: u32, container: u8) -> Option<&'static Desc> {
    DESCS.iter().find(|x| x.container == container && x.op != Op::Na && x.code == code)
}

/// `_property_imposable` (0xf668) for `_chip_ap_sha2_384`: the chip's
/// digest property (DGST, by fourcc: `_property_equal` 0xf620) always;
/// else none without an index or of constraint `rp`, and none the chip
/// leaves out (`_chip_check_entitlement` 0xb190 over +0x158).
fn imposable(p: &Desc) -> bool {
    if p.code == fourcc(b"DGST") {
        return true;
    }
    if p.index == NONE || p.op == Op::Rp {
        return false;
    }
    ![b"AMNM", b"iuou", b"euou", b"fpgt", b"love"].iter().any(|c| fourcc(c) == p.code)
}

/// The darwin el0 expert's answers (0x68fc, 0x6a54, 0x6b4c, 0x6c00) for
/// `_chip_ap_sha2_384`, which has no chip expert of its own, after
/// `_expert_query_property_*`'s absence transform (0x2fac..): the value,
/// or the errno the query fails with.
struct Expert<'a> {
    r: &'a dyn Registry,
}

impl Expert<'_> {
    fn absent<T>(&self, p: &Desc, err: i32, f: T) -> R<T> {
        if err == e::ENOENT && p.absent_false {
            return Ok(f);
        }
        Err(Fail::Code(err))
    }

    fn bool(&self, p: &Desc) -> R<bool> {
        let (name, zero_is_true) = match p.index {
            0x05 => ("certificate-production-status", false),
            0x06 => ("certificate-security-mode", false),
            0x07 => ("effective-production-status-ap", false),
            0x08 => ("effective-security-mode-ap", false),
            0x0b => ("mix-n-match-prevention-status", true),
            0x0d => ("internal-use-only-unit", false),
            0x0e => ("engineering-use-only-unit", false),
            0x0f => ("factory-prerelease-global-trust", false),
            0x12 => ("research-enabled", false),
            0x0c => return Err(Fail::Unmodelled("the el0 expert's iuob, _expert_compute_eieiou (0x69a8)".into())),
            i => return Err(Fail::Panic(format!("illegal bool property: index {i:#x}"))),
        };
        match read_node(self.r, CHOSEN, name, 4) {
            Ok(v) => Ok((le(&v, 4) as u32 == 0) == zero_is_true),
            Err(c) => self.absent(p, c, false),
        }
    }

    fn u32(&self, p: &Desc) -> R<u32> {
        let name = match p.index {
            0x00 => "chip-epoch",
            0x01 => "board-id",
            0x02 => "chip-id",
            0x03 => "security-domain",
            0x13 => "esdm-fuses",
            // The AP's product class.
            0x17 => return Ok(0xf2),
            0x14..=0x16 | 0x18 | 0x1d => return self.absent(p, e::ENOTSUP, 0),
            i => return Err(Fail::Panic(format!("illegal uint32 property: index {i:#x}"))),
        };
        match read_node(self.r, CHOSEN, name, 4) {
            Ok(v) => Ok(le(&v, 4) as u32),
            Err(c) => self.absent(p, c, 0),
        }
    }

    fn u64(&self, p: &Desc) -> R<u64> {
        let (path, name) = match p.index {
            0x04 => (CHOSEN, "unique-chip-id"),
            0x1b => (ASMB, "lp-stng"),
            i => return Err(Fail::Panic(format!("illegal uint64 property: index {i:#x}"))),
        };
        match read_node(self.r, path, name, 8) {
            Ok(v) => Ok(le(&v, 8)),
            Err(c) => self.absent(p, c, 0),
        }
    }

    fn digest(&self, p: &Desc) -> R<Vec<u8>> {
        match p.index {
            0x0a => match read_node(self.r, CHOSEN, "boot-manifest-hash", 0x40) {
                Ok(v) => Ok(v),
                Err(c) => self.absent(p, c, Vec::new()),
            },
            i => Err(Fail::Unmodelled(format!("the el0 expert's digest property of index {i:#x} (_darwin_el0_query_property_digest 0x6c00)"))),
        }
    }
}

/// `_property_constrain_bool`/`_uint32`/`_uint64` (0xf708..): whether the
/// manifest's `m` violates `op` against the device's `v`.
fn violates<T: Ord>(op: Op, m: T, v: T) -> R<bool> {
    Ok(match op {
        Op::Eq => m != v,
        Op::Lt => m >= v,
        Op::Le => m > v,
        Op::Gt => m <= v,
        Op::Ge => m < v,
        Op::Ne => m == v,
        Op::Un => false,
        Op::Rp | Op::Na => return Err(Fail::Panic("property is not constrainable".into())),
    })
}

/// `_property_constrain_digest`: lengths and bytes.
fn violates_digest(op: Op, m: &[u8], v: &[u8]) -> R<bool> {
    Ok(match op {
        Op::Eq => m != v,
        Op::Ne => m == v,
        Op::Un => false,
        _ => return Err(Fail::Panic("property is not constrainable".into())),
    })
}

fn sha384(b: &[u8]) -> Vec<u8> {
    Sha384::digest(b).to_vec()
}

/// The odometer (`_odometer_init` 0x128c8) as the AP chip's evaluation
/// fills it.
#[derive(Default, Debug)]
struct Odometer {
    /// +0x438..+0x43d: the cylinders `_odometer_prepare` (0x1297c) queries
    /// (0x40010: AMNM, CPRO, CSEC, iuou, euou, fpgt).
    mixn_match: bool,
    /// +0x90: a consumed BNCH (`_odometer_consume_nonce_hash` 0x12ed0).
    nonce_hash: Option<Vec<u8>>,
    /// +0x140: a consumed CHMH (`_odometer_consume_chain_hash` 0x133b4).
    chain_hash: Option<Vec<u8>>,
    /// +0x1b8: a consumed AMNM (`_odometer_consume_mixn_match` 0x1344c).
    manifest_mixn_match: bool,
    /// +0x1b9: mix-n-match god mode (`_odometer_prepare_mix_n_match_god_mode` 0x12b58).
    god_mode: bool,
    /// +0x1ba: the sideload mix-n-match policy (0x12b64).
    sideload: bool,
}

impl Odometer {
    /// `_odometer_prepare` (0x1297c): each cylinder's bool from the expert;
    /// a failed query is the evaluation's error.
    fn prepare(&mut self, x: &Expert<'_>) -> R<()> {
        for code in [b"AMNM", b"CPRO", b"CSEC", b"iuou", b"euou", b"fpgt"] {
            let v = x.bool(desc(code))?;
            if code == b"AMNM" {
                self.mixn_match = v;
            }
        }
        Ok(())
    }

    /// `_odometer_update` (0x12bac) over the consumers at 0x40070 for this
    /// chip: BNCH, CHMH and AMNM are taken (a value of the wrong type is
    /// not, and is then imposed); the chip has no nonce domain, side or
    /// ephemeral nonce, pivot or static-lifetime properties.
    fn consume(&mut self, p: &Desc, prop: &image4::Property<'_>) -> bool {
        match &p.code.to_be_bytes() {
            b"BNCH" if prop.value_tag == tag::OCTET_STRING => {
                self.nonce_hash = Some(prop.value.to_vec());
                true
            }
            b"CHMH" if prop.value_tag == tag::OCTET_STRING => {
                self.chain_hash = Some(prop.value.to_vec());
                true
            }
            b"AMNM" if prop.value_tag == tag::BOOLEAN => match der::boolean(prop.value) {
                Ok(v) => {
                    self.manifest_mixn_match = v;
                    true
                }
                Err(_) => false,
            },
            _ => false,
        }
    }

    /// `_odometer_enforce` (0x12c74). The darwin el0 expert boots only the
    /// chips of `_darwin_el0_query_chip_boot.bin` (0x39f20: acdc, cryptex0,
    /// srdp; `_chip_bin_check` 0x8104), and no nonce or nonce hash is
    /// supplied (`_odometer_query_chip_boot` 0x1221c: 0x2d), so the boot
    /// chain policies (0x48138) apply: `chain_future` needs a notarized
    /// manifest hash only a custom runtime gives, `chain_sideload` and
    /// `chain_pivot` chip properties this chip has not (+0x1a0, +0x1b0),
    /// so `chain` (`_chain_enforceable` 0x10088: bmfh at +0x1f0, the
    /// expert not booting the chip). Then `chain_manifest` (0x3c738), for a
    /// consumed CHMH, which `_odometer_policy_enforce` (0xe7a4) relaxes for
    /// a chip the expert does not boot.
    fn enforce(&self, x: &Expert<'_>, manifest_digest: &[u8]) -> R<()> {
        // `_odometer_policy_enforce`, kind 1: relaxed when the device
        // allows mix-n-match; else, with god mode, relaxed when the
        // sideload policy is forced and the manifest is entitled to
        // mix-n-match; else `_chain_enforce` (0x1017c).
        let relaxed = self.mixn_match || (self.god_mode && self.sideload && self.manifest_mixn_match);
        if !relaxed {
            // `_manifest_measure` (0x8d18): the manifest's digest
            // (`Img4DecodeCopyManifestDigest`), against bmfh's
            // (`_odometer_enforce_property` 0x124dc), equal.
            let v = x.digest(&BMFH)?;
            if violates_digest(Op::Eq, manifest_digest, &v)? {
                // The policy's error 0x1f, ESTALE with god mode (0x12d88).
                return Err(Fail::Code(if self.god_mode { e::ESTALE } else { 0x1f }));
            }
        }
        Ok(())
    }
}

/// An IMG4 as `Img4DecodeInit` (0x22ce0) takes it apart, or an IM4P.
struct Decoded<'a> {
    /// The IM4P, whole.
    im4p: &'a [u8],
    /// The IM4M (the `[0]`'s content), if an IMG4 carried one.
    im4m: Option<&'a [u8]>,
}

/// `DERImg4Decode` (0x205d0) and the decoders after it: an IMG4 is a
/// SEQUENCE filling the buffer of `IA5String "IMG4"`, the IM4P (whole),
/// `[0]` the IM4M and `[1]` the IM4R (both optional, items at 0x2a428); the
/// IM4R, when there, a sequence of `IA5String "IM4R"` and a set
/// (`DERImg4DecodeRestoreInfo` 0x20a40). 2 (`UNEXPECTED_TAG`) when the
/// buffer is not an IMG4, which the callers take as an IM4P or IM4M.
fn decode_img4(b: &[u8]) -> Result<Decoded<'_>, i32> {
    let it = der::decode_item(b)?;
    if it.tag != tag::SEQUENCE {
        return Err(dr::UNEXPECTED_TAG);
    }
    if it.whole.len() != b.len() {
        return Err(dr::BUF_OVERFLOW);
    }
    let items = der::parse_content(it.content, &[der::spec(tag::IA5_STRING, 0), der::spec(tag::SEQUENCE, der::SAVE_DER), der::spec(tag::context(0), der::OPTIONAL), der::spec(tag::context(1), der::OPTIONAL)])?;
    if items[0] != Some(b"IMG4".as_slice()) {
        return Err(dr::UNEXPECTED_TAG);
    }
    let im4p = items[1].unwrap_or(&[]);
    image4::init_as_payload(im4p)?;
    let im4m = items[2];
    if let Some(m) = im4m {
        image4::init_as_manifest(m)?;
    }
    if let Some(r) = items[3] {
        let ri = der::parse_sequence(r, &[der::spec(tag::IA5_STRING, 0), der::spec(tag::SET, 0)])?;
        if ri[0] != Some(b"IM4R".as_slice()) {
            return Err(dr::UNEXPECTED_TAG);
        }
    }
    Ok(Decoded { im4p, im4m })
}

/// A libDER code as an errno (`posixdr` 0xd710, its table at 0x26ed8).
fn posix(d: i32) -> i32 {
    image4::dr_errno(d)
}

/// `DERImg4DecodeFindProperty`: the content of the first item tagged `t`
/// in `content`, its value of tag `value_tag`.
fn find_property(content: &[u8], t: u64, value_tag: u64) -> Result<&[u8], i32> {
    let mut s = der::Seq::of(content);
    loop {
        let it = s.next()?;
        if it.tag == t {
            let p = der::parse_sequence(it.content, &[der::spec(tag::IA5_STRING, 0), der::spec(value_tag, 0)])?;
            if tag::private(der::integer(p[0].unwrap_or(&[]))?) != t {
                return Err(dr::UNEXPECTED_TAG);
            }
            return Ok(p[1].unwrap_or(&[]));
        }
    }
}

/// The evaluation's state: the chip's expert, the odometer, the payload's
/// digest and the error a property set (the manifest's +0x480).
struct Eval<'a> {
    x: Expert<'a>,
    odo: Odometer,
    payload_digest: Option<Vec<u8>>,
    error: Option<i32>,
}

impl Eval<'_> {
    /// `_manifest_impose_property` (0x9270): violation EACCES (0xd) for a
    /// manifest property and EBADEXEC (0x55) for an object's.
    fn impose(&mut self, p: &Desc, prop: &image4::Property<'_>) -> R<()> {
        let violation = match p.container {
            0 => e::EACCES,
            1 => e::EBADEXEC,
            _ => return Ok(()),
        };
        if !imposable(p) {
            return Ok(());
        }
        let get = |t| if prop.value_tag == t { Ok(prop.value) } else { Err(Fail::Code(posix(dr::UNEXPECTED_TAG))) };
        let bad = match p.ty {
            Ty::Bool => {
                let m = der::boolean(get(tag::BOOLEAN)?).map_err(|d| Fail::Code(posix(d)))?;
                violates(p.op, m, self.x.bool(p)?)?
            }
            Ty::U32 => {
                let m = der::integer(get(tag::INTEGER)?).map_err(|d| Fail::Code(posix(d)))?;
                violates(p.op, m, self.x.u32(p)?)?
            }
            Ty::U64 => {
                let m = der::integer64(get(tag::INTEGER)?).map_err(|d| Fail::Code(posix(d)))?;
                violates(p.op, m, self.x.u64(p)?)?
            }
            Ty::Digest => {
                let m = get(tag::OCTET_STRING)?.to_vec();
                let v = if p.code == fourcc(b"DGST") {
                    // `_payload_im4p_measure` (0xb90c): the digest the trust
                    // evaluation made of the IM4P.
                    self.payload_digest.clone().ok_or_else(|| Fail::Panic("Img4DecodeCopyPayloadDigest: the payload has no digest".into()))?
                } else {
                    self.x.digest(p)?
                };
                violates_digest(p.op, &m, &v)?
            }
            Ty::Version => {
                get(tag::OCTET_STRING)?;
                return Err(Fail::Unmodelled(format!("the version constraint of '{}' (_property_constrain_version, _expert_query_property_version)", String::from_utf8_lossy(&p.code.to_be_bytes()))));
            }
        };
        if bad {
            return Err(Fail::Code(violation));
        }
        Ok(())
    }

    /// `_manifest_validate_property_manifest` (0x8ef8) and `_object`
    /// (0x909c): an unrecognized property passes; the odometer takes the
    /// manifest's anti-replay properties; the rest are imposed, an error
    /// kept and failing the walk.
    fn validate(&mut self, prop: &image4::Property<'_>, container: u8) -> R<()> {
        let Some(p) = find_desc(prop.fourcc(), container) else { return Ok(()) };
        if container == 0 && self.odo.consume(p, prop) {
            return Ok(());
        }
        match self.impose(p, prop) {
            Ok(()) => Ok(()),
            Err(Fail::Code(c)) => {
                self.error = Some(c);
                Err(Fail::Code(dr::DECODE_ERROR))
            }
            Err(f) => Err(f),
        }
    }

    /// `Img4DecodeEvaluateDictionaryProperties`: each property of the set's
    /// content, a `[PRIVATE]` constructed item whose value is a BOOLEAN,
    /// INTEGER, OCTET STRING or IA5String.
    fn properties(&mut self, c: &[u8], container: u8) -> R<()> {
        let mut s = der::Seq::of(c);
        loop {
            let it = match s.next() {
                Ok(it) => it,
                Err(dr::END_OF_SEQUENCE) => return Ok(()),
                Err(d) => return Err(Fail::Code(d)),
            };
            let p = image4::property(it.content, it.tag)?;
            if !matches!(p.value_tag, tag::BOOLEAN | tag::INTEGER | tag::OCTET_STRING | tag::IA5_STRING) {
                return Err(Fail::Code(dr::UNEXPECTED_TAG));
            }
            if it.tag >> 62 == 0 || it.tag & (1 << 61) == 0 {
                return Err(Fail::Code(dr::UNEXPECTED_TAG));
            }
            self.validate(&p, container)?;
        }
    }
}

const SHA384_DIGEST_INFO: &[u8] = &[0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30];

/// `_verify_signature_rsa` (0x23a80) for `kImg4DecodeSecureBootRsa4kSha384`:
/// an RSAPublicKey of at most 4096 bits, odd and at least 3, the exponent
/// no wider; a signature as long as the modulus, below it, whose
/// encoding is exactly `00 01 FF.. 00 DigestInfo(sha384, digest)`.
fn rsa_verify(key: &[u8], sig: &[u8], digest: &[u8]) -> Result<(), i32> {
    use num_bigint::BigUint;
    let k = der::parse_sequence(key, &[der::spec(tag::INTEGER, 0x100), der::spec(tag::INTEGER, 0x100)]).map_err(|_| -1)?;
    let strip = |b: &'_ [u8]| -> Vec<u8> { b.iter().skip_while(|&&c| c == 0).copied().collect() };
    let m = strip(k[0].unwrap_or(&[]));
    let words = m.len().div_ceil(8);
    if words > 4096 / 64 {
        return Err(-1);
    }
    let exp = strip(k[1].unwrap_or(&[]));
    if exp.len() > words * 8 {
        return Err(-1);
    }
    if m.last().is_none_or(|&c| c & 1 == 0) || (m.len() == 1 && m[0] < 3) || sig.len() != m.len() {
        return Err(-1);
    }
    let modulus = BigUint::from_bytes_be(&m);
    let s = BigUint::from_bytes_be(sig);
    if s >= modulus {
        return Err(-1);
    }
    let em_n = s.modpow(&BigUint::from_bytes_be(&exp), &modulus).to_bytes_be();
    let mut em = vec![0u8; m.len() - em_n.len().min(m.len())];
    em.extend_from_slice(&em_n);
    let t_len = SHA384_DIGEST_INFO.len() + digest.len();
    if em.len() < t_len + 11 {
        return Err(-1);
    }
    let mut want = vec![0x00, 0x01];
    want.resize(em.len() - t_len - 1, 0xff);
    want.push(0x00);
    want.extend_from_slice(SHA384_DIGEST_INFO);
    want.extend_from_slice(digest);
    if em != want {
        return Err(-1);
    }
    Ok(())
}

/// `Img4DecodeEvaluateCertificateProperties` (0x227a4): the leaf's
/// constraints, a set holding `MANP` (on the manifest's properties),
/// `OBJP` (on the payload's object's) and `manx` (passed over), each a set
/// of properties: a BOOLEAN, INTEGER or OCTET STRING one the manifest must
/// have byte for byte, a `[0]` one it must have, a `[1]` one it must not.
fn certificate_constraints(props: Option<&[u8]>, manp: &[u8], objp: &[u8]) -> Result<(), i32> {
    let Some(props) = props else { return Err(dr::DECODE_ERROR) };
    let (t, mut outer) = der::seq_init(props)?;
    if t != tag::SET {
        return Err(dr::UNEXPECTED_TAG);
    }
    let find = |content: &[u8], t: u64| -> Result<Vec<u8>, i32> {
        let mut s = der::Seq::of(content);
        loop {
            let it = s.next()?;
            if it.tag == t {
                return Ok(it.content.to_vec());
            }
        }
    };
    loop {
        let it = match outer.next() {
            Ok(it) => it,
            Err(dr::END_OF_SEQUENCE) => return Ok(()),
            Err(_) => return Err(-1),
        };
        let container = match it.tag {
            x if x == tag::private(fourcc(b"MANP")) => manp,
            x if x == tag::private(fourcc(b"manx")) => continue,
            x if x == tag::private(fourcc(b"OBJP")) => objp,
            _ => return Err(dr::UNEXPECTED_TAG),
        };
        let p = image4::property(it.content, it.tag)?;
        if p.value_tag != tag::SET {
            return Err(dr::UNEXPECTED_TAG);
        }
        let mut inner = der::Seq::of(p.value);
        loop {
            let c = match inner.next() {
                Ok(c) => c,
                Err(dr::END_OF_SEQUENCE) => break,
                Err(_) => return Err(-1),
            };
            let cp = image4::property(c.content, c.tag)?;
            let found = find(container, c.tag);
            match cp.value_tag {
                tag::BOOLEAN | tag::INTEGER | tag::OCTET_STRING => {
                    if found? != c.content {
                        return Err(-1);
                    }
                }
                x if x == tag::context(0) => {
                    found?;
                }
                x if x == tag::context(1) => match found {
                    Err(dr::END_OF_SEQUENCE) => {}
                    _ => return Err(dr::UNEXPECTED_TAG),
                },
                _ => return Err(dr::UNEXPECTED_TAG),
            }
        }
    }
}

/// `_Img4DecodePerformTrustEvaluationWithCallbacksInternal` (0x233dc), in
/// its order: the manifest's digest; the chain (`_verify_chain_img4_v2`
/// 0x24820: the leaf under the anchor) and the body's signature (no
/// manifest-hash callback skips them, 0x3b250); `MANB` and `MANP`; the
/// object of the payload's tag; the leaf's constraints; the payload's
/// digest (the whole IM4P); the manifest's properties, then the object's.
fn trust(ev: &mut Eval<'_>, code: u32, m: &image4::Manifest<'_>, im4p: &[u8], anchor: &[u8]) -> R<()> {
    let (key, constraints) = image4::verify_chain(anchor, m.chain)?;
    rsa_verify(key, m.signature, &sha384(m.body))?;
    let set = der::decode_item(m.body)?;
    if set.tag != tag::SET {
        return Err(Fail::Code(-1));
    }
    let manb_tag = if m.version == 2 { tag::SEQUENCE } else { tag::SET };
    let manb = find_property(set.content, tag::private(fourcc(b"MANB")), manb_tag)?;
    let manp = find_property(manb, tag::private(fourcc(b"MANP")), tag::SET)?;
    let object = find_property(manb, tag::private(code), tag::SET)?;
    certificate_constraints(constraints, manp, object)?;
    ev.payload_digest = Some(sha384(im4p));
    ev.properties(manp, 0)?;
    ev.properties(object, 1)?;
    Ok(())
}

/// `ramrod_get_trusted_img4_payload` (RE@0x100057818) of payload `img4`
/// for tag `code` ('msys', 'isys'), its manifest attached, on the restore
/// ramdisk whose registry is `r`: the authenticated payload's data, or the
/// status `img4_firmware_execute` hands restored's callback.
pub fn restore_trusted_payload(code: u32, img4: &[u8], r: &dyn Registry) -> Outcome {
    match evaluate(code, img4, r) {
        Ok(data) => Outcome::Authenticated(data),
        Err(Fail::Code(c)) => Outcome::Status(c),
        Err(Fail::Panic(s)) => Outcome::Panic(s),
        Err(Fail::Unmodelled(s)) => Outcome::Unmodelled(s),
    }
}

fn evaluate(code: u32, buf: &[u8], r: &dyn Registry) -> R<Vec<u8>> {
    let Chip::ApSha2_384 = select_effective_ap(r)?;
    // `payload_parse_relax`: an IMG4, else (UNEXPECTED_TAG) an IM4P.
    let decoded = match decode_img4(buf) {
        Ok(d) => d,
        Err(dr::UNEXPECTED_TAG) => match image4::init_as_payload(buf) {
            Ok(_) => Decoded { im4p: buf, im4m: None },
            Err(d) => return Err(Fail::Code(posix(d))),
        },
        Err(d) => return Err(Fail::Code(posix(d))),
    };
    // `manifest_parse`: the IMG4's IM4M, else the buffer as an IM4M.
    let im4m = match decoded.im4m {
        Some(m) => m,
        None if decoded.im4p.len() != buf.len() => return Err(Fail::Unmodelled("an IMG4 without its [0] manifest (DERImg4DecodeManifest of an absent item, 0x2096c)".into())),
        None => buf,
    };
    let m = image4::init_as_manifest(im4m).map_err(|_| Fail::Code(e::EFTYPE))?;
    let payload = image4::init_as_payload(decoded.im4p).map_err(|d| Fail::Code(posix(d)))?;
    let mut ev = Eval { x: Expert { r }, odo: Odometer::default(), payload_digest: None, error: None };
    let status = (|| -> R<()> {
        ev.odo.prepare(&ev.x)?;
        // `_img4_firmware_prepare`: the subsequent stage's sideload
        // policy; mix-n-match god mode for a chip with no nonce domain.
        ev.odo.sideload = true;
        ev.odo.god_mode = true;
        let anchor = r.anchor().map_err(Fail::Unmodelled)?;
        match trust(&mut ev, code, &m, decoded.im4p, &anchor) {
            Ok(()) => {}
            Err(Fail::Code(_)) => return Err(Fail::Code(ev.error.unwrap_or(e::EAUTH))),
            Err(f) => return Err(f),
        }
        ev.odo.enforce(&ev.x, &sha384(m.whole))
    })();
    match status {
        Ok(()) => payload.data.map(<[u8]>::to_vec).ok_or_else(|| Fail::Panic("Img4DecodeGetPayload: the payload has no data".into())),
        Err(Fail::Code(e::EBADEXEC)) => Err(Fail::Code(e::ENOEXEC)),
        Err(f) => Err(f),
    }
}

#[cfg(test)]
mod tests {
    use super::super::image4::enc;
    use super::super::webdevice::{self, certificate, root_spec, CertSpec, Signer};
    use super::*;
    use rsa::traits::PublicKeyParts;
    use std::collections::HashMap;
    use std::sync::OnceLock;

    struct Key(rsa::RsaPrivateKey);

    impl Signer for Key {
        fn public_key(&self) -> Vec<u8> {
            webdevice::rsa_public_key(&self.0.n().to_bytes_be(), &self.0.e().to_bytes_be())
        }
        fn sign_sha384(&self, digest: &[u8; 48]) -> Result<Vec<u8>, String> {
            self.0.sign(rsa::Pkcs1v15Sign::new::<rsa::sha2::Sha384>(), digest).map_err(|e| e.to_string())
        }
    }

    struct Keys {
        root: Key,
        leaf: Key,
        other: Key,
    }

    fn keys() -> &'static Keys {
        static K: OnceLock<Keys> = OnceLock::new();
        K.get_or_init(|| {
            let mut rng = rsa::rand_core::OsRng;
            let mut k = || Key(rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap());
            Keys { root: k(), leaf: k(), other: k() }
        })
    }

    const FROM: &str = "261117000000Z";
    const TO: &str = "461112000000Z";

    fn root_cert(k: &Key) -> Vec<u8> {
        certificate(&root_spec([0x11; 20], FROM, TO, k.public_key()), k).unwrap()
    }

    fn present(code: &[u8; 4]) -> Vec<u8> {
        enc::property(fourcc(code), enc::context(0, &enc::null()))
    }

    /// A leaf with AP-ticket constraints: the identity and nonce hash there,
    /// each object's digest there.
    fn leaf_cert(by: &Key) -> Vec<u8> {
        let manp = enc::set(&[present(b"BORD"), present(b"CHIP"), present(b"ECID"), present(b"SDOM"), present(b"BNCH")]);
        let objp = enc::set(&[present(b"DGST")]);
        let img4 = enc::set(&[enc::property(fourcc(b"MANP"), manp), enc::property(fourcc(b"OBJP"), objp)]);
        let spec = CertSpec {
            serial: [0x22; 20],
            issuer: webdevice::name(webdevice::ROOT_NAME, webdevice::ORGANIZATION),
            subject: webdevice::name("AP test leaf", webdevice::ORGANIZATION),
            not_before: FROM.into(),
            not_after: TO.into(),
            key: keys().leaf.public_key(),
            authority_key_id: Some(webdevice::key_id(&by.public_key())),
            ca: false,
            img4: Some(img4),
        };
        certificate(&spec, by).unwrap()
    }

    fn im4p(ty: &[u8], data: &[u8]) -> Vec<u8> {
        enc::seq(&[enc::ia5(b"IM4P"), enc::ia5(ty), enc::ia5(b"1"), enc::octets(data)])
    }

    const ECID: u64 = 0x6890_e970_0eb4_c4bf;

    fn manp(ecid: u64, chip: u64, board: u64) -> Vec<Vec<u8>> {
        let p = |c: &[u8; 4], v| enc::property(fourcc(c), v);
        vec![
            p(b"BNCH", enc::octets(&[0x5a; 32])),
            p(b"BORD", enc::int(board)),
            p(b"CEPO", enc::int(1)),
            p(b"CHIP", enc::int(chip)),
            p(b"CPRO", enc::boolean(true)),
            p(b"CSEC", enc::boolean(true)),
            p(b"ECID", enc::int(ecid)),
            p(b"SDOM", enc::int(1)),
            p(b"srvn", enc::octets(&[0x33; 20])),
        ]
    }

    fn object(code: &[u8; 4], digest: &[u8]) -> Vec<u8> {
        let p = |c: &[u8; 4], v| enc::property(fourcc(c), v);
        enc::property(fourcc(code), enc::set(&[p(b"DGST", enc::octets(digest)), p(b"EKEY", enc::boolean(true)), p(b"EPRO", enc::boolean(true)), p(b"ESEC", enc::boolean(true))]))
    }

    fn ticket(manp: Vec<Vec<u8>>, objects: Vec<Vec<u8>>, signer: &Key, leaf: &[u8]) -> Vec<u8> {
        let mut manb = vec![enc::property(fourcc(b"MANP"), enc::set(&manp))];
        manb.extend(objects);
        let body = enc::set(&[enc::property(fourcc(b"MANB"), enc::set(&manb))]);
        let digest: [u8; 48] = Sha384::digest(&body).into();
        let sig = signer.sign_sha384(&digest).unwrap();
        webdevice::im4m(&body, &sig, &[leaf.to_vec()])
    }

    fn stitch(p: &[u8], m: &[u8]) -> Vec<u8> {
        enc::seq(&[enc::ia5(b"IMG4"), p.to_vec(), enc::context(0, m)])
    }

    struct Fake {
        chosen: HashMap<&'static str, Vec<u8>>,
        anchor: Vec<u8>,
        manifest_properties: bool,
    }

    impl Registry for Fake {
        fn node(&self, path: &str) -> bool {
            path == CHOSEN || (path == MANIFEST_PROPERTIES && self.manifest_properties)
        }
        fn property(&self, path: &str, name: &str) -> Option<Vec<u8>> {
            (path == CHOSEN).then(|| self.chosen.get(name).cloned()).flatten()
        }
        fn anchor(&self) -> Result<Vec<u8>, String> {
            Ok(self.anchor.clone())
        }
    }

    /// The restore ramdisk of a J120 as its boot fills /chosen, for the
    /// ticket `t`.
    fn device(t: &[u8]) -> Fake {
        let mut c = HashMap::new();
        for (k, v) in [("chip-id", 0x8011u32), ("board-id", 0x0c), ("security-domain", 1), ("chip-epoch", 1), ("certificate-production-status", 1), ("certificate-security-mode", 1), ("effective-production-status-ap", 1), ("effective-security-mode-ap", 1), ("mix-n-match-prevention-status", 1)] {
            c.insert(k, v.to_le_bytes().to_vec());
        }
        c.insert("unique-chip-id", ECID.to_le_bytes().to_vec());
        c.insert("crypto-hash-method", b"sha2-384\0".to_vec());
        c.insert("boot-manifest-hash", Sha384::digest(t).to_vec());
        Fake { chosen: c, anchor: root_cert(&keys().root), manifest_properties: true }
    }

    struct Case {
        msys: Vec<u8>,
        isys: Vec<u8>,
        ticket: Vec<u8>,
    }

    fn case() -> Case {
        let k = keys();
        let msys = im4p(b"msys", b"an archive of digest.db and mtree.txt");
        let isys = im4p(b"isys", b"a root hash");
        let objects = vec![object(b"isys", &Sha384::digest(&isys)), object(b"msys", &Sha384::digest(&msys))];
        let ticket = ticket(manp(ECID, 0x8011, 0x0c), objects, &k.leaf, &leaf_cert(&k.root));
        Case { msys, isys, ticket }
    }

    fn run(code: &[u8; 4], img4: &[u8], d: &Fake) -> Outcome {
        restore_trusted_payload(fourcc(code), img4, d)
    }

    #[test]
    fn the_j120_selects_the_sha2_384_ap_chip() {
        let c = case();
        let mut d = device(&c.ticket);
        assert_eq!(select_effective_ap(&d), Ok(Chip::ApSha2_384));
        d.chosen.insert("crypto-hash-method", b"md5\0".to_vec());
        assert!(matches!(select_effective_ap(&d), Err(Fail::Panic(_))));
        d.chosen.insert("crypto-hash-method", b"sha1\0".to_vec());
        assert!(matches!(select_effective_ap(&d), Err(Fail::Unmodelled(_))));
        let mut d = device(&c.ticket);
        d.chosen.insert("allow-ecid-mismatch", 1u32.to_le_bytes().to_vec());
        assert!(matches!(select_effective_ap(&d), Err(Fail::Unmodelled(_))));
        let mut d = device(&c.ticket);
        d.manifest_properties = false;
        assert!(matches!(select_effective_ap(&d), Err(Fail::Panic(_))));
    }

    #[test]
    fn stitched_payloads_authenticate() {
        let c = case();
        let d = device(&c.ticket);
        assert_eq!(run(b"msys", &stitch(&c.msys, &c.ticket), &d), Outcome::Authenticated(b"an archive of digest.db and mtree.txt".to_vec()));
        assert_eq!(run(b"isys", &stitch(&c.isys, &c.ticket), &d), Outcome::Authenticated(b"a root hash".to_vec()));
        // An IM4R does not change the evaluation.
        let r = enc::context(1, &enc::seq(&[enc::ia5(b"IM4R"), enc::set(&[])]));
        let with_r = enc::seq(&[enc::ia5(b"IMG4"), c.isys.clone(), enc::context(0, &c.ticket), r]);
        assert_eq!(run(b"isys", &with_r, &d), Outcome::Authenticated(b"a root hash".to_vec()));
    }

    #[test]
    fn what_the_device_does_not_match_fails() {
        let k = keys();
        let c = case();
        let d = device(&c.ticket);
        // Another payload under the isys object: its digest, EBADEXEC as
        // ENOEXEC.
        assert_eq!(run(b"isys", &stitch(&im4p(b"isys", b"another root hash"), &c.ticket), &d), Outcome::Status(e::ENOEXEC));
        // A tag the ticket has no object of: EAUTH.
        assert_eq!(run(b"rosi", &stitch(&c.isys, &c.ticket), &d), Outcome::Status(e::EAUTH));
        // The identity: the manifest property violated, EACCES.
        for (ecid, chip, board) in [(ECID + 1, 0x8011, 0x0c), (ECID, 0x8010, 0x0c), (ECID, 0x8011, 0x0e)] {
            let objects = vec![object(b"isys", &Sha384::digest(&c.isys))];
            let t = ticket(manp(ecid, chip, board), objects, &k.leaf, &leaf_cert(&k.root));
            assert_eq!(run(b"isys", &stitch(&c.isys, &t), &device(&t)), Outcome::Status(e::EACCES), "{ecid:x} {chip:x} {board:x}");
        }
        // A changed signature byte: EAUTH.
        let m = image4::init_as_manifest(&c.ticket).unwrap();
        let at = m.signature.as_ptr() as usize - c.ticket.as_ptr() as usize + 9;
        let mut bad = c.ticket.clone();
        bad[at] ^= 1;
        assert_eq!(run(b"isys", &stitch(&c.isys, &bad), &device(&bad)), Outcome::Status(e::EAUTH));
        // Another root: EAUTH.
        let mut other = device(&c.ticket);
        other.anchor = root_cert(&k.other);
        assert_eq!(run(b"isys", &stitch(&c.isys, &c.ticket), &other), Outcome::Status(e::EAUTH));
        // A boot of another manifest: the boot chain's integrity, ESTALE;
        // none in /chosen: ENOENT.
        let mut stale = device(&c.ticket);
        stale.chosen.insert("boot-manifest-hash", vec![0; 48]);
        assert_eq!(run(b"isys", &stitch(&c.isys, &c.ticket), &stale), Outcome::Status(e::ESTALE));
        stale.chosen.remove("boot-manifest-hash");
        assert_eq!(run(b"isys", &stitch(&c.isys, &c.ticket), &stale), Outcome::Status(e::ENOENT));
        // A device allowing mix-n-match relaxes the chain.
        stale.chosen.insert("mix-n-match-prevention-status", 0u32.to_le_bytes().to_vec());
        assert!(matches!(run(b"isys", &stitch(&c.isys, &c.ticket), &stale), Outcome::Authenticated(_)));
        // No chip-epoch: CEPO's query fails, ENOENT.
        let mut no_epoch = device(&c.ticket);
        no_epoch.chosen.remove("chip-epoch");
        assert_eq!(run(b"isys", &stitch(&c.isys, &c.ticket), &no_epoch), Outcome::Status(e::ENOENT));
        // No certificate production status: the odometer's cylinder, ENOENT.
        let mut no_cpro = device(&c.ticket);
        no_cpro.chosen.remove("certificate-production-status");
        assert_eq!(run(b"isys", &stitch(&c.isys, &c.ticket), &no_cpro), Outcome::Status(e::ENOENT));
        // A bare IM4P has no manifest: EFTYPE.
        assert_eq!(run(b"isys", &c.isys, &d), Outcome::Status(e::EFTYPE));
        // Not Image4 at all: libDER's error.
        assert!(matches!(run(b"isys", b"not der", &d), Outcome::Status(_)));
    }

    #[test]
    fn the_leafs_constraints_hold() {
        let k = keys();
        let c = case();
        // A body without BNCH, which the leaf requires: EAUTH.
        let m: Vec<Vec<u8>> = manp(ECID, 0x8011, 0x0c).into_iter().filter(|p| !p.windows(4).any(|w| w == b"BNCH")).collect();
        let t = ticket(m, vec![object(b"isys", &Sha384::digest(&c.isys))], &k.leaf, &leaf_cert(&k.root));
        assert_eq!(run(b"isys", &stitch(&c.isys, &t), &device(&t)), Outcome::Status(e::EAUTH));
    }
}
