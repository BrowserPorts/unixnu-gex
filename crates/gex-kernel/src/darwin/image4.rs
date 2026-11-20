//! AppleImage4's evaluation of a firmware payload against its Image4
//! manifest for `CHIP_CRYPTEX1_BOOT_AP` ('c1bt', 0xfffffff006cf29b0), the
//! chip APFS's `validate_payload_and_manifest` names for a graft of type
//! `GRAFTDMG_CRYPTEX_BOOT` (AppleImage4 257.140.2 of iPad7,1 21H461).
//!
//! `img4_firmware_execute` (0xfffffff005a8edac) with no nonce and no
//! firmware flags, in its order ([`execute`]):
//!
//! 1. The payload decoded as an IM4P (`Img4DecodeInitAsPayload`,
//!    0xfffffff005aa67f0): its errors are libDER's, made errno numbers by
//!    0xfffffff005a8f818 ([`dr_errno`]).
//! 2. The manifest decoded as an IM4M (`Img4DecodeInitAsManifest`,
//!    0xfffffff005aa6880): any error is EFTYPE.
//! 3. The odometer prepared (0xfffffff005aa1318): the device's mix-n-match,
//!    certificate production status and certificate security mode queried
//!    from `/chosen`; an error is the status.
//! 4. The trust evaluation (`Img4DecodePerformTrustEvaluationWithCallbacks`,
//!    0xfffffff005aa6df8): the certificate chain up to the chip's anchor,
//!    the manifest body's signature, the payload's object, the certificate's
//!    constraints, then each manifest and object property imposed on the
//!    chip's environment ([`trust`]). A failure is the error a property set,
//!    else EAUTH (0xfffffff005a9d5fc).
//! 5. The anti-replay policy (0xfffffff005aa15d8): a manifest with a
//!    cryptex1 boot nonce hash ('cnch') must carry the device's current
//!    one, else ESTALE.
//!
//! EBADEXEC, an object's violated constraint, becomes ENOEXEC
//! (0xfffffff005a8ef94). On success the authenticated payload is the IM4P's
//! data (`Img4DecodeGetPayload`, 0xfffffff005aa4a0c).
//!
//! The chip's anchor is the "Apple DDI Secure Boot Root CA - G1" the kext
//! embeds (0xfffffff0052d4640, 1394 bytes): the chip's decode
//! implementation (its +0x20, 0xfffffff006cf9be8) loads it
//! (0xfffffff005aa8054). It comes from the boot payload, extracted from the
//! kernelcache (`tools/darwin-img4-anchor.py`, [`set_anchor`]). Digests are SHA-384 (`ccsha384_di`, the
//! implementation's digest, 48 bytes); signatures RSA PKCS#1 v1.5 through
//! corecrypto's `ccrsa_verify_pkcs1v15`.
//!
//! The cryptex1 boot nonce's hash is the device's
//! ([`Environment::cryptex1_boot_nonce_hash`]): the nonce of the cryptex1
//! boot slot of its nonce magazine ([`super::noncemag`], kept in its
//! NVRAM), hashed as [`nonce`] does. With the device's NVRAM modelled it
//! is the magazine's as AppleImage4 booted it; a device of Apple's run
//! without its NVRAM has it as a measured input.

use sha2::{Digest, Sha384};

/// libDER's return codes (`DERReturn`).
pub mod dr {
    pub const END_OF_SEQUENCE: i32 = 1;
    pub const UNEXPECTED_TAG: i32 = 2;
    pub const DECODE_ERROR: i32 = 3;
    pub const INCOMPLETE_SEQ: i32 = 5;
    pub const PARAM_ERR: i32 = 6;
    pub const BUF_OVERFLOW: i32 = 7;
}

/// Darwin's errno numbers the evaluation returns.
pub mod e {
    pub const ENOENT: i32 = 2;
    pub const ENOEXEC: i32 = 8;
    pub const EACCES: i32 = 13;
    pub const ENOTSUP: i32 = 45;
    pub const ESTALE: i32 = 70;
    pub const EFTYPE: i32 = 79;
    pub const EAUTH: i32 = 80;
    pub const EOVERFLOW: i32 = 84;
    pub const ENXIO: i32 = 6;
    pub const ERANGE: i32 = 34;
    pub const ESHLIBVERS: i32 = 87;
    pub const ENODATA: i32 = 96;
    /// An object's violated constraint (`EBADEXEC`).
    pub const EBADEXEC: i32 = 85;
}

/// A libDER return code as the kext's errno (0xfffffff005a8f818, its table
/// at 0xfffffff0052cf750).
pub fn dr_errno(d: i32) -> i32 {
    match d {
        0 => 0,
        1 => 34,
        2 => 33,
        3 => 92,
        4 => 78,
        5 => 40,
        6 => 22,
        7 => 84,
        _ => 14,
    }
}

/// libDER's tags: the class and constructed bits of the first byte at the
/// top, the tag number below.
pub mod tag {
    pub const BOOLEAN: u64 = 0x01;
    pub const INTEGER: u64 = 0x02;
    pub const BIT_STRING: u64 = 0x03;
    pub const OCTET_STRING: u64 = 0x04;
    pub const OID: u64 = 0x06;
    pub const IA5_STRING: u64 = 0x16;
    pub const SEQUENCE: u64 = 0x2000_0000_0000_0010;
    pub const SET: u64 = 0x2000_0000_0000_0011;
    /// `[n]` constructed.
    pub const fn context(n: u64) -> u64 {
        0xa000_0000_0000_0000 | n
    }
    /// `[n]` primitive.
    pub const fn context_primitive(n: u64) -> u64 {
        0x8000_0000_0000_0000 | n
    }
    /// `[PRIVATE n]` constructed: an Image4 property's tag.
    pub const fn private(n: u32) -> u64 {
        0xe000_0000_0000_0000 | n as u64
    }
}

/// libDER (as AppleImage4 links it): DER items, sequences and the
/// primitive types.
pub mod der {
    use super::dr;

    /// An item: its tag, its content and the whole of it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Item<'a> {
        pub tag: u64,
        pub content: &'a [u8],
        pub whole: &'a [u8],
    }

    /// `DERDecodeItem` (0xfffffff005aa8e1c): the item `b` starts with. Its
    /// length is definite and minimal, and its content within `b`.
    pub fn decode_item(b: &[u8]) -> Result<Item<'_>, i32> {
        if b.len() < 2 {
            return Err(dr::DECODE_ERROR);
        }
        let mut at = 1usize;
        let mut rem = b.len() - 1;
        let first = b[0];
        let mut number = u64::from(first & 0x1f);
        if number == 0x1f {
            // A high tag number: base 128, no leading zero digit, at
            // least 31, under 2^61.
            if b[1] == 0x80 || b[1] < 0x1f {
                return Err(dr::DECODE_ERROR);
            }
            let mut n = 0u64;
            loop {
                if rem < 2 {
                    return Err(dr::DECODE_ERROR);
                }
                let prev = n;
                if prev >> 57 != 0 {
                    return Err(dr::DECODE_ERROR);
                }
                let c = b[at];
                at += 1;
                rem -= 1;
                n = (prev << 7) | u64::from(c & 0x7f);
                if c & 0x80 == 0 {
                    if prev >> 54 != 0 {
                        return Err(dr::DECODE_ERROR);
                    }
                    break;
                }
            }
            number = n;
        }
        let tag = number | (u64::from(first & 0xe0) << 56);
        let lb = b[at];
        at += 1;
        rem -= 1;
        let len = if lb < 0x80 {
            let l = usize::from(lb);
            if rem < l {
                return Err(dr::DECODE_ERROR);
            }
            l
        } else {
            let n = usize::from(lb & 0x7f);
            if n > 8 || n == 0 || rem < n || b[at] == 0 {
                return Err(dr::DECODE_ERROR);
            }
            let mut l = 0u64;
            for &c in &b[at..at + n] {
                l = (l << 8) | u64::from(c);
            }
            at += n;
            rem -= n;
            if l > rem as u64 || l < 0x80 {
                return Err(dr::DECODE_ERROR);
            }
            l as usize
        };
        Ok(Item { tag, content: &b[at..at + len], whole: &b[..at + len] })
    }

    /// A sequence's or set's content being walked (`DERSequence`).
    #[derive(Clone, Copy, Debug)]
    pub struct Seq<'a> {
        rest: &'a [u8],
    }

    impl<'a> Seq<'a> {
        /// `DERDecodeSeqContentInit` (0xfffffff005aa93dc).
        pub fn of(content: &'a [u8]) -> Self {
            Seq { rest: content }
        }

        /// `DERDecodeSeqNext` (0xfffffff005aa9400): the next item, or
        /// `END_OF_SEQUENCE`.
        #[allow(clippy::should_implement_trait)]
        pub fn next(&mut self) -> Result<Item<'a>, i32> {
            if self.rest.is_empty() {
                return Err(dr::END_OF_SEQUENCE);
            }
            let it = decode_item(self.rest)?;
            self.rest = &self.rest[it.whole.len()..];
            Ok(it)
        }

        /// Whether the walk has reached the content's end.
        pub fn done(&self) -> bool {
            self.rest.is_empty()
        }
    }

    /// `DERDecodeSeqInit` (0xfffffff005aa932c): the item `b` starts with,
    /// a sequence or a set, and its content's walk.
    pub fn seq_init(b: &[u8]) -> Result<(u64, Seq<'_>), i32> {
        let it = decode_item(b)?;
        if it.tag != super::tag::SEQUENCE && it.tag != super::tag::SET {
            return Err(dr::UNEXPECTED_TAG);
        }
        Ok((it.tag, Seq::of(it.content)))
    }

    /// An item specification (`DERItemSpec`): its tag and options.
    #[derive(Clone, Copy, Debug)]
    pub struct Spec {
        pub tag: u64,
        pub opts: u16,
    }

    pub const OPTIONAL: u16 = 1;
    pub const ANY: u16 = 2;
    pub const SKIP: u16 = 4;
    pub const SAVE_DER: u16 = 8;

    pub const fn spec(tag: u64, opts: u16) -> Spec {
        Spec { tag, opts }
    }

    /// `DERParseSequenceContent` (0xfffffff005aa9564): the items of
    /// `content` against `specs`, in order. An item matches the next spec
    /// whose tag it has (or that takes any), optional specs before it
    /// skipped; an item no spec takes is `UNEXPECTED_TAG`, a required spec
    /// left over `INCOMPLETE_SEQ`, and anything after the last spec's item
    /// `DECODE_ERROR`. Each spec's item is its content, or the whole item
    /// with `SAVE_DER`; `None` for one not there.
    pub fn parse_content<'a>(content: &'a [u8], specs: &[Spec]) -> Result<Vec<Option<&'a [u8]>>, i32> {
        let mut out = vec![None; specs.len()];
        if specs.is_empty() {
            return if content.is_empty() { Ok(out) } else { Err(dr::DECODE_ERROR) };
        }
        let mut seq = Seq::of(content);
        let mut i = 0usize;
        loop {
            let it = match seq.next() {
                Ok(it) => it,
                Err(dr::END_OF_SEQUENCE) => {
                    if specs[i..].iter().any(|s| s.opts & OPTIONAL == 0) {
                        return Err(dr::INCOMPLETE_SEQ);
                    }
                    return Ok(out);
                }
                Err(e) => return Err(e),
            };
            let mut j = i;
            loop {
                let s = specs[j];
                if s.opts & ANY != 0 || it.tag == s.tag {
                    break;
                }
                if s.opts & OPTIONAL == 0 {
                    return Err(dr::UNEXPECTED_TAG);
                }
                j += 1;
                if j >= specs.len() {
                    return Err(dr::UNEXPECTED_TAG);
                }
            }
            let s = specs[j];
            if s.opts & SKIP == 0 {
                out[j] = Some(if s.opts & SAVE_DER != 0 { it.whole } else { it.content });
            }
            i = j + 1;
            if i == specs.len() {
                return if seq.done() { Ok(out) } else { Err(dr::DECODE_ERROR) };
            }
        }
    }

    /// `DERParseSequence` (0xfffffff005aa949c): the item `b` starts with,
    /// a sequence, its content against `specs`.
    pub fn parse_sequence<'a>(b: &'a [u8], specs: &[Spec]) -> Result<Vec<Option<&'a [u8]>>, i32> {
        let it = decode_item(b)?;
        if it.tag != super::tag::SEQUENCE {
            return Err(dr::UNEXPECTED_TAG);
        }
        parse_content(it.content, specs)
    }

    /// `DERParseBitString` (0xfffffff005aa9108): the bits and the count of
    /// unused bits, which the last byte must have clear.
    pub fn bit_string(c: &[u8]) -> Result<(&[u8], u8), i32> {
        let Some(&unused) = c.first() else { return Err(dr::DECODE_ERROR) };
        if c.len() == 1 {
            return if unused == 0 { Ok((&[], 0)) } else { Err(dr::DECODE_ERROR) };
        }
        if unused > 7 {
            return Err(dr::DECODE_ERROR);
        }
        let mask = 0xffu32.checked_shr(8 - u32::from(unused)).unwrap_or(0) as u8;
        if c[c.len() - 1] & mask != 0 {
            return Err(dr::DECODE_ERROR);
        }
        Ok((&c[1..], unused))
    }

    /// `DERParseBoolean` (0xfffffff005aa91a0): one byte, 0x00 or 0xff.
    pub fn boolean(c: &[u8]) -> Result<bool, i32> {
        match c {
            [0x00] => Ok(false),
            [0xff] => Ok(true),
            _ => Err(dr::DECODE_ERROR),
        }
    }

    /// `DERParseInteger64` (0xfffffff005aa929c): a non-negative minimal
    /// INTEGER's content of at most 64 bits.
    pub fn integer64(c: &[u8]) -> Result<u64, i32> {
        let Some(&first) = c.first() else { return Err(dr::DECODE_ERROR) };
        if first & 0x80 != 0 {
            return Err(dr::DECODE_ERROR);
        }
        if first == 0 {
            if c.len() >= 2 {
                if c[1] & 0x80 == 0 {
                    return Err(dr::DECODE_ERROR);
                }
                if c.len() > 9 {
                    return Err(dr::BUF_OVERFLOW);
                }
            }
        } else if c.len() > 8 {
            return Err(dr::BUF_OVERFLOW);
        }
        Ok(c.iter().fold(0u64, |v, &b| (v << 8) | u64::from(b)))
    }

    /// `DERParseInteger` (0xfffffff005aa921c): [`integer64`] within 32
    /// bits.
    pub fn integer(c: &[u8]) -> Result<u32, i32> {
        let v = integer64(c)?;
        u32::try_from(v).map_err(|_| dr::BUF_OVERFLOW)
    }
}

use der::{spec, Seq, Spec, ANY, OPTIONAL, SAVE_DER};

/// A four-character code as a number, big-endian.
pub const fn fourcc(s: &[u8; 4]) -> u32 {
    u32::from_be_bytes(*s)
}

/// 0xfffffff005aa3f84: an IA5String's content against a four-character
/// code: shorter -1, longer 1, not an integer -2, else their order.
fn ia5_cmp(c: &[u8], code: u32) -> i32 {
    if c.len() < 4 {
        return -1;
    }
    if c.len() > 4 {
        return 1;
    }
    match der::integer(c) {
        Err(_) => -2,
        Ok(v) => match v.cmp(&code) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        },
    }
}

/// An IM4P, as `Img4DecodeInitAsPayload` keeps it: the whole buffer (what
/// its digest covers) and its data.
#[derive(Clone, Debug)]
pub struct Payload<'a> {
    pub whole: &'a [u8],
    pub data: Option<&'a [u8]>,
    /// The compression's sequence content, `{ INTEGER algorithm, INTEGER
    /// size }`, when the IM4P has one.
    pub compression: Option<&'a [u8]>,
}

const IM4P6: [Spec; 6] = [
    spec(tag::IA5_STRING, 0),
    spec(tag::IA5_STRING, 0),
    spec(tag::IA5_STRING, 0),
    spec(tag::OCTET_STRING, 0),
    spec(tag::OCTET_STRING, OPTIONAL),
    spec(tag::SEQUENCE, OPTIONAL),
];
const IM4P7: [Spec; 7] = [
    spec(tag::IA5_STRING, 0),
    spec(tag::IA5_STRING, 0),
    spec(tag::IA5_STRING, 0),
    spec(tag::OCTET_STRING, 0),
    spec(tag::OCTET_STRING, OPTIONAL),
    spec(tag::SEQUENCE, OPTIONAL),
    spec(tag::context(0), OPTIONAL),
];

/// 0xfffffff005aa40d8: an IM4P's compression, two INTEGERs, the algorithm
/// at most 1.
fn compression(c: &[u8]) -> Result<(), i32> {
    let it = der::parse_content(c, &[spec(tag::INTEGER, 0), spec(tag::INTEGER, 0)])?;
    if der::integer(it[0].unwrap_or(&[]))? > 1 {
        return Err(dr::PARAM_ERR);
    }
    Ok(())
}

/// 0xfffffff005aa4210: an IM4P's `[0]` properties, `PAYP`, when not
/// empty.
fn payload_properties(c: &[u8]) -> Result<(), i32> {
    if c.is_empty() {
        return Ok(());
    }
    let it = der::parse_sequence(c, &[spec(tag::IA5_STRING, 0), spec(tag::SET, 0)])?;
    if ia5_cmp(it[0].unwrap_or(&[]), fourcc(b"PAYP")) != 0 {
        return Err(dr::UNEXPECTED_TAG);
    }
    Ok(())
}

/// `DERImg4DecodePayload` (0xfffffff005aa428c): the IM4P with properties
/// (0xfffffff005aa4158), and failing that without.
fn decode_payload(b: &[u8]) -> Result<Vec<Option<&[u8]>>, i32> {
    let with = || -> Result<Vec<Option<&[u8]>>, i32> {
        let it = der::parse_sequence(b, &IM4P7)?;
        if ia5_cmp(it[0].unwrap_or(&[]), fourcc(b"IM4P")) != 0 {
            return Err(dr::UNEXPECTED_TAG);
        }
        if let Some(c) = it[5] {
            compression(c)?;
        }
        if let Some(p) = it[6] {
            payload_properties(p)?;
        }
        Ok(it[..6].to_vec())
    };
    if let Ok(it) = with() {
        return Ok(it);
    }
    let it = der::parse_sequence(b, &IM4P6)?;
    if ia5_cmp(it[0].unwrap_or(&[]), fourcc(b"IM4P")) != 0 {
        return Err(dr::UNEXPECTED_TAG);
    }
    if let Some(c) = it[5] {
        compression(c)?;
    }
    Ok(it)
}

/// `Img4DecodeInitAsPayload` (0xfffffff005aa67f0).
pub fn init_as_payload(b: &[u8]) -> Result<Payload<'_>, i32> {
    if b.is_empty() {
        return Err(dr::PARAM_ERR);
    }
    let it = decode_payload(b)?;
    Ok(Payload { whole: b, data: it[3], compression: it[5] })
}

/// An IM4M, as `Img4DecodeInitAsManifest` keeps it.
#[derive(Clone, Debug)]
pub struct Manifest<'a> {
    pub whole: &'a [u8],
    pub version: u32,
    /// The manifest body's set, whole: what is signed.
    pub body: &'a [u8],
    pub signature: &'a [u8],
    /// The certificate chain's content.
    pub chain: &'a [u8],
}

const IM4M5: [Spec; 5] = [spec(tag::IA5_STRING, 0), spec(tag::INTEGER, 0), spec(tag::SET, SAVE_DER), spec(tag::OCTET_STRING, 0), spec(tag::SEQUENCE, 0)];

/// `Img4DecodeInitAsManifest` (0xfffffff005aa6880): `DERImg4DecodeManifest`
/// (0xfffffff005aa4394: an IM4M of version at most 2), its body there, and
/// the manifest one item filling the buffer.
pub fn init_as_manifest(b: &[u8]) -> Result<Manifest<'_>, i32> {
    if b.is_empty() {
        return Err(dr::DECODE_ERROR);
    }
    let it = der::parse_sequence(b, &IM4M5)?;
    if ia5_cmp(it[0].unwrap_or(&[]), fourcc(b"IM4M")) != 0 {
        return Err(dr::UNEXPECTED_TAG);
    }
    let version = der::integer(it[1].unwrap_or(&[]))?;
    if version > 2 {
        return Err(dr::UNEXPECTED_TAG);
    }
    let Some(body) = it[2] else { return Err(dr::DECODE_ERROR) };
    let top = der::decode_item(b)?;
    if top.whole.len() != b.len() {
        return Err(dr::BUF_OVERFLOW);
    }
    Ok(Manifest { whole: b, version, body, signature: it[3].unwrap_or(&[]), chain: it[4].unwrap_or(&[]) })
}

/// A property (0xfffffff005aa44e4): `[PRIVATE n] { IA5String n, value }`
/// decoded from its tag and content.
#[derive(Clone, Copy, Debug)]
pub struct Property<'a> {
    pub tag: u64,
    /// The `[PRIVATE n]`'s content: the sequence of name and value.
    pub wrapper: &'a [u8],
    pub value: &'a [u8],
    pub value_tag: u64,
}

impl Property<'_> {
    pub fn fourcc(&self) -> u32 {
        self.tag as u32
    }
}

/// 0xfffffff005aa44e4: the property tagged `tag` with content `c`: a
/// sequence of exactly its name, an IA5String naming the tag, and a value,
/// filling the content.
pub fn property(c: &[u8], tagged: u64) -> Result<Property<'_>, i32> {
    let (t, mut seq) = der::seq_init(c)?;
    if t != tag::SEQUENCE {
        return Err(dr::UNEXPECTED_TAG);
    }
    let name = seq.next()?;
    if name.tag != tag::IA5_STRING {
        return Err(dr::UNEXPECTED_TAG);
    }
    let n = der::integer(name.content)?;
    if tag::private(n) != tagged {
        return Err(dr::UNEXPECTED_TAG);
    }
    let value = seq.next()?;
    match seq.next() {
        Err(dr::END_OF_SEQUENCE) => {}
        _ => return Err(dr::UNEXPECTED_TAG),
    }
    let whole = der::decode_item(c)?.whole;
    if whole.len() != c.len() {
        return Err(dr::BUF_OVERFLOW);
    }
    Ok(Property { tag: tagged, wrapper: c, value: value.content, value_tag: value.tag })
}

/// 0xfffffff005aa3edc: the content of the first item tagged `t` in
/// `content`, or `END_OF_SEQUENCE`.
fn find(content: &[u8], t: u64) -> Result<&[u8], i32> {
    let mut seq = Seq::of(content);
    loop {
        let it = seq.next()?;
        if it.tag == t {
            return Ok(it.content);
        }
    }
}

/// 0xfffffff005aa4614: `DERImg4DecodeProperty` of an item's content: a
/// sequence of its name, which must be `t`'s, and a value tagged
/// `value_tag`.
fn property_of_tag(c: &[u8], t: u64, value_tag: u64) -> Result<&[u8], i32> {
    let it = der::parse_sequence(c, &[spec(tag::IA5_STRING, 0), spec(value_tag, 0)])?;
    let n = der::integer(it[0].unwrap_or(&[]))?;
    if tag::private(n) != t {
        return Err(dr::UNEXPECTED_TAG);
    }
    Ok(it[1].unwrap_or(&[]))
}

/// 0xfffffff005aa473c: the value of the property tagged `t` in `content`.
fn find_property(content: &[u8], t: u64, value_tag: u64) -> Result<&[u8], i32> {
    property_of_tag(find(content, t)?, t, value_tag)
}

/// The manifest body's `MANB` and its `MANP`, as libamsupport's
/// `DERImg4DecodeParseManifestProperties` (0xea54) finds them: the body a
/// set (else -1), `MANB` a sequence in a version 2 manifest and a set in
/// the others, and `MANP` a set in it, which must be there.
fn manifest_sections<'a>(m: &Manifest<'a>) -> Result<(&'a [u8], &'a [u8]), i32> {
    let set = der::decode_item(m.body)?;
    if set.tag != tag::SET {
        return Err(-1);
    }
    let manb_tag = if m.version == 2 { tag::SEQUENCE } else { tag::SET };
    let manb = find_property(set.content, tag::private(fourcc(b"MANB")), manb_tag)?;
    let manp = find_property(manb, tag::private(fourcc(b"MANP")), tag::SET)?;
    Ok((manb, manp))
}

/// The data of `object`'s property `property` in the IM4M `manifest`, as
/// the restore ramdisk's libamsupport (`/usr/lib/libamsupport.dylib`,
/// which `restored_external` links) gives it to
/// `ramrod_ticket_copy_data_object_property_from_ticket_data`:
/// `Img4DecodeInitManifest` (0x10b40: `DERImg4DecodeManifest` with the
/// kext's item specifications, an `IM4M` of version at most 2 whose body
/// is there and whose item fills the buffer), then
/// `Img4DecodeGetObjectPropertyData` (0xfff0 → 0xfdf8): `MANB` and `MANP`
/// ([`manifest_sections`]), the object's set in `MANB`, and the
/// property's OCTET STRING in it. Both are the libDER and DERImg4Decode
/// code the kext has ([`init_as_manifest`], [`find_property`]); no
/// signature or certificate is looked at. A failure is the code of the
/// step that failed, which the restore only logs.
pub fn object_property_data(manifest: &[u8], object: u32, property: u32) -> Result<&[u8], i32> {
    let m = init_as_manifest(manifest)?;
    let (manb, _) = manifest_sections(&m)?;
    let o = find_property(manb, tag::private(object), tag::SET)?;
    find_property(o, tag::private(property), tag::OCTET_STRING)
}

/// The value tagged `value_tag` of the manifest property `property`, in
/// `MANP` (libamsupport's `Img4DecodeGetPropertyFromSection`, 0x101b0,
/// for the manifest's section).
pub fn manifest_property(manifest: &[u8], property: u32, value_tag: u64) -> Result<&[u8], i32> {
    let m = init_as_manifest(manifest)?;
    let (_, manp) = manifest_sections(&m)?;
    find_property(manp, tag::private(property), value_tag)
}

/// The errors of the evaluation's steps: the code a step returns (libDER's,
/// -1, or an errno, as the step has it), or what stops it here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fail {
    Code(i32),
    /// The kext panics.
    Panic(String),
    /// What decides the step is not modelled.
    Unmodelled(String),
}

impl From<i32> for Fail {
    fn from(c: i32) -> Self {
        Fail::Code(c)
    }
}

type R<T> = Result<T, Fail>;

/// The evaluation's result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Authenticated: the payload's data.
    Authenticated(Vec<u8>),
    /// The errno `img4_firmware_execute` hands the execution callback.
    Status(i32),
    Panic(String),
    Unmodelled(String),
}

/// What the chip's environment answers: the device tree's `/chosen` and the
/// device's nonce.
pub trait Environment {
    /// A `/chosen` property as the runtime reads it (0xfffffff005a9280c):
    /// `None` when it is not there, EOVERFLOW when longer than `size`, else
    /// its bytes in `size` zeroed ones.
    fn chosen(&self, name: &str, size: usize) -> Result<Option<Vec<u8>>, i32>;
    /// The hash AppleImage4 makes of the current nonce of the chip's nonce
    /// domain `domain` (0xfffffff005a99118, 0xfffffff005a99210,
    /// 0xfffffff005aa0a5c; [`nonce::cryptex1_boot_hash`]): the errno the
    /// query fails with, or why it is not known.
    fn cryptex1_boot_nonce_hash(&self, domain: u32) -> Result<Vec<u8>, Fail>;
    /// The chip's anchor, the kext's root certificate, or why it is not
    /// there.
    fn anchor(&self) -> Result<Vec<u8>, String>;
}

static ANCHOR: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();

/// The chip's anchor from the boot payload (`img4_anchor.der`), once at
/// boot.
pub fn set_anchor(der: Vec<u8>) -> Result<(), String> {
    ANCHOR.set(der).map_err(|_| "AppleImage4's anchor is set already".to_string())
}

/// The chip's anchor the boot payload gave, or why there is none.
pub fn anchor() -> Result<Vec<u8>, String> {
    ANCHOR.get().cloned().ok_or_else(|| "CHIP_CRYPTEX1_BOOT_AP's anchor, the Apple DDI Secure Boot Root CA - G1 AppleImage4 embeds (0xfffffff0052d4640): the boot payload (GEX_DARWIN_BOOT) has no img4_anchor.der (tools/darwin-img4-anchor.py writes it from the kernelcache)".to_string())
}

/// The property types (`bool`, `uint32`, `uint64`, `digest`, `version`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ty {
    Bool,
    U32,
    U64,
    Digest,
    Version,
}

/// The constraint operators, by their index (0xfffffff006cf8dd8..); no
/// descriptor uses `<`, `>`, `!=` or `*=`.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Eq,
    Lt,
    Le,
    Gt,
    Ge,
    Ne,
    Any,
    Sideload,
    Never,
}

/// A property descriptor (the list at 0xfffffff006cf82f0): its code, type,
/// operator, container (0 the manifest's, 1 an object's), its index (+0x10;
/// 0x1f none), the lowest chip kind answering it from its own instance
/// (+0x50) and its place there (+0x48 mask).
#[derive(Clone, Copy, Debug)]
struct Desc {
    code: u32,
    ty: Ty,
    op: Op,
    container: u8,
    index: u8,
    rank: u8,
    mask: u64,
    /// The answer when the device does not have it (+0x58): AMNM's, false.
    absent_false: bool,
}

const fn d(code: &[u8; 4], ty: Ty, op: Op, container: u8, index: u8, rank: u8, mask: u64) -> Desc {
    Desc { code: fourcc(code), ty, op, container, index, rank, mask, absent_false: false }
}

const NONE: u8 = 0x1f;

/// The 28 descriptors, in the list's order.
const DESCS: [Desc; 28] = [
    d(b"CEPO", Ty::U32, Op::Ge, 0, 0x00, 1, 0x1),
    d(b"BORD", Ty::U32, Op::Eq, 0, 0x01, 2, 0x2),
    d(b"CHIP", Ty::U32, Op::Eq, 0, 0x02, 2, 0x4),
    d(b"SDOM", Ty::U32, Op::Eq, 0, 0x03, 2, 0x8),
    d(b"ECID", Ty::U64, Op::Eq, 0, 0x04, 2, 0x10),
    d(b"CPRO", Ty::Bool, Op::Eq, 0, 0x05, 3, 0x20),
    d(b"CSEC", Ty::Bool, Op::Eq, 0, 0x06, 3, 0x40),
    d(b"UDID", Ty::Digest, Op::Eq, 0, 0x09, 2, 0x200),
    d(b"BNCN", Ty::Digest, Op::Never, 3, NONE, 4, 0),
    d(b"BNCH", Ty::Digest, Op::Eq, 0, NONE, 4, 0),
    d(b"DGST", Ty::Digest, Op::Eq, 1, NONE, 4, 0),
    d(b"EPRO", Ty::Bool, Op::Eq, 1, 0x07, 3, 0x80),
    d(b"ESEC", Ty::Bool, Op::Eq, 1, 0x08, 2, 0x100),
    Desc { absent_false: true, ..d(b"AMNM", Ty::Bool, Op::Sideload, 0, 0x0b, 4, 0) },
    d(b"CHMH", Ty::Digest, Op::Eq, 0, 0x0a, 4, 0),
    d(b"love", Ty::Version, Op::Never, 0, 0x11, 4, 0),
    d(b"vnum", Ty::Version, Op::Ge, 0, 0x11, 4, 0),
    d(b"fchp", Ty::U32, Op::Eq, 0, 0x14, 0, 0x400),
    d(b"type", Ty::U32, Op::Eq, 0, 0x15, 0, 0x800),
    d(b"styp", Ty::U32, Op::Eq, 0, 0x16, 0, 0x1000),
    d(b"clas", Ty::U32, Op::Eq, 0, 0x17, 0, 0x2000),
    d(b"ndom", Ty::U32, Op::Sideload, 0, 0x18, 1, 0x4000),
    d(b"cnch", Ty::Digest, Op::Eq, 0, NONE, 4, 0),
    d(b"rsch", Ty::Bool, Op::Le, 0, 0x12, 3, 0x80000),
    d(b"esdm", Ty::U32, Op::Eq, 0, 0x13, 2, 0x40000),
    d(b"boid", Ty::Digest, Op::Eq, 0, 0x1e, 4, 0),
    d(b"lndm", Ty::U32, Op::Sideload, 0, 0x1d, 1, 0x100000),
    d(b"lnch", Ty::Digest, Op::Eq, 0, NONE, 4, 0),
];

/// 0xfffffff005a9b0cc: the descriptor of the property coded `code` in
/// container `container`, those of operator `**` left out.
fn lookup(code: u32, container: u8) -> Option<&'static Desc> {
    DESCS.iter().find(|d| d.container == container && d.op != Op::Never && d.code == code)
}

/// `CHIP_CRYPTEX1_BOOT_AP`'s kind (+0x10): its own instance answers the
/// properties of rank at most 1 it has.
const CHIP_KIND: u8 = 1;

/// The chip's own instance (0xfffffff0052cf550, mask 0x5c01): its
/// certificate epoch 1, Cryptex1 chip 0xFF10, type 1, subtype 1 and nonce
/// domain 1.
fn chip_instance(desc: &Desc) -> Option<u32> {
    const MASK: u64 = 0x5c01;
    if CHIP_KIND < desc.rank || desc.mask & MASK == 0 {
        return None;
    }
    Some(match &desc.code.to_be_bytes() {
        b"CEPO" => 1,
        b"fchp" => 0xff10,
        b"type" => 1,
        b"styp" => 1,
        b"ndom" => 1,
        _ => return None,
    })
}

/// The chip's nonce domain: the instance's `ndom`.
pub const CRYPTEX1_BOOT_NONCE_DOMAIN: u32 = 1;

/// 0xfffffff005a9b1c0: whether the chip constrains a property: the object
/// digest always; one with no index, or of operator `|>`, never; the rest
/// unless the chip leaves it out (+0x158; `CHIP_CRYPTEX1_BOOT_AP` leaves
/// none out).
fn constrainable(desc: &Desc) -> bool {
    if desc.code == fourcc(b"DGST") {
        return true;
    }
    desc.index != NONE && desc.op != Op::Sideload
}

/// A digest as the kext holds it (at most 64 bytes, 0xfffffff005a9f750).
fn digest_of(b: &[u8]) -> R<Vec<u8>> {
    if b.len() > 64 {
        return Err(Fail::Panic(format!("digest length overflow: actual = {}, expected <= 64", b.len())));
    }
    Ok(b.to_vec())
}

/// The darwin expert's queries (0xfffffff005a995a4 and on) and the chip's
/// (its +0x150 struct), as 0xfffffff005a9c05c and its siblings make them:
/// ENOENT for a property the device does not have takes the descriptor's
/// answer for that case when it has one.
struct Env<'a> {
    env: &'a dyn Environment,
}

impl Env<'_> {
    fn read_u32(&self, name: &str) -> Result<u32, i32> {
        match self.env.chosen(name, 4)? {
            None => Err(e::ENOENT),
            Some(b) => Ok(u32::from_le_bytes(b[..4].try_into().unwrap())),
        }
    }

    fn query_bool(&self, desc: &Desc) -> R<bool> {
        let r = match desc.index {
            0x05 => self.read_u32("certificate-production-status").map(|v| v != 0),
            0x06 => self.read_u32("certificate-security-mode").map(|v| v != 0),
            0x07 => self.read_u32("effective-production-status-ap").map(|v| v != 0),
            0x08 => self.read_u32("effective-security-mode-ap").map(|v| v != 0),
            0x0b => self.read_u32("mix-n-match-prevention-status").map(|v| v == 0),
            0x0c => Err(e::ENOTSUP),
            0x0d => self.read_u32("internal-use-only-unit").map(|v| v != 0),
            0x0e => self.read_u32("engineering-use-only-unit").map(|v| v != 0),
            0x0f => self.read_u32("factory-prerelease-global-trust").map(|v| v != 0),
            0x12 => self.read_u32("research-enabled").map(|v| v != 0),
            i => return Err(Fail::Panic(format!("illegal bool property: index {i:#x}"))),
        };
        match r {
            Err(e::ENOENT) if desc.absent_false => Ok(false),
            r => r.map_err(Fail::Code),
        }
    }

    fn query_u32(&self, desc: &Desc) -> R<u32> {
        if let Some(v) = chip_instance(desc) {
            return Ok(v);
        }
        let r = match desc.index {
            0x00 => self.read_u32("chip-epoch"),
            0x01 => self.read_u32("board-id"),
            0x02 => self.read_u32("chip-id"),
            0x03 => self.read_u32("security-domain"),
            0x13 => self.read_u32("esdm-fuses"),
            0x14..=0x16 | 0x18 | 0x1d => Err(e::ENOTSUP),
            // The AP's product class.
            0x17 => Ok(0xf2),
            i => return Err(Fail::Panic(format!("illegal uint32 property: index {i:#x}"))),
        };
        r.map_err(Fail::Code)
    }

    fn query_u64(&self, desc: &Desc) -> R<u64> {
        let r = match desc.index {
            0x04 => match self.env.chosen("unique-chip-id", 8) {
                Ok(None) => Err(e::ENOENT),
                Ok(Some(b)) => Ok(u64::from_le_bytes(b[..8].try_into().unwrap())),
                Err(e) => Err(e),
            },
            0x1b => Err(e::ENOTSUP),
            i => return Err(Fail::Panic(format!("illegal uint64 property: index {i:#x}"))),
        };
        r.map_err(Fail::Code)
    }

    fn query_digest(&self, desc: &Desc) -> R<Vec<u8>> {
        match desc.index {
            // The universal device identifier (0xfffffff005a9c914): 0, the
            // chip and the ECID, big-endian.
            0x09 => {
                let chip = self.query_u32(&DESCS[2])?;
                let ecid = self.query_u64(&DESCS[4])?;
                let mut u = vec![0u8; 16];
                u[4..8].copy_from_slice(&chip.to_be_bytes());
                u[8..16].copy_from_slice(&ecid.to_be_bytes());
                Ok(u)
            }
            0x0a => match self.env.chosen("boot-manifest-hash", 64).map_err(Fail::Code)? {
                None => Err(Fail::Code(e::ENOENT)),
                Some(b) => Ok(b),
            },
            0x1e => Err(Fail::Unmodelled("the boot UUID AppleImage4's darwin expert answers for 'boid' (0xfffffff005a99888, its case 0x1e)".into())),
            i => Err(Fail::Unmodelled(format!("the digest property of index {i:#x} AppleImage4's darwin expert answers (0xfffffff005a99888)"))),
        }
    }
}

/// An ordering constraint (0xfffffff005a9b260 and its integer siblings):
/// whether manifest value `m` violates `op` against the device's `e`.
fn violates<T: Ord>(op: Op, m: T, e: T) -> R<bool> {
    Ok(match op {
        Op::Eq => m != e,
        Op::Lt => m >= e,
        Op::Le => m > e,
        Op::Gt => m <= e,
        Op::Ge => m < e,
        Op::Ne => m == e,
        Op::Any => false,
        Op::Sideload => return Err(Fail::Panic("unreachable".into())),
        Op::Never => return Err(Fail::Panic("property is not constrainable".into())),
    })
}

/// The odometer (0xfffffff005aa1264): what the manifest's anti-replay
/// properties recorded.
#[derive(Default, Debug)]
struct Odometer {
    cnch: Option<Vec<u8>>,
    ndom: Option<u32>,
}

/// The evaluation's state: the decoded manifest and payload, the error a
/// property set (+0x480), and the odometer.
struct Eval<'a> {
    env: Env<'a>,
    fourcc: u32,
    payload: &'a Payload<'a>,
    payload_digest: Option<[u8; 48]>,
    error: Option<i32>,
    odometer: Odometer,
}

fn sha384(b: &[u8]) -> [u8; 48] {
    Sha384::digest(b).into()
}

/// `Img4DecodeGetProperty*` (0xfffffff005aa60c4 and on) of a decoded
/// property: its value's tag must be the type's.
fn value_of<'a>(p: &Property<'a>, want: u64) -> Result<&'a [u8], i32> {
    if p.value_tag != want {
        return Err(dr::UNEXPECTED_TAG);
    }
    Ok(p.value)
}

impl Eval<'_> {
    /// The odometer's consumers (0xfffffff005aa1500, their list at
    /// 0xfffffff006cf92e0): whether one records `p` instead of its being
    /// imposed. The cryptex1 boot nonce hash and the nonce domain are kept
    /// for the anti-replay policy; the chained manifest hash and the long
    /// OS version are recorded for the policies a chip of chained
    /// manifests or pivots has, which this chip has not.
    fn consumed(&mut self, desc: &Desc, p: &Property<'_>) -> R<bool> {
        match &desc.code.to_be_bytes() {
            b"cnch" => match value_of(p, tag::OCTET_STRING) {
                Ok(v) => {
                    self.odometer.cnch = Some(digest_of(v)?);
                    Ok(true)
                }
                Err(_) => Ok(false),
            },
            b"ndom" => match value_of(p, tag::INTEGER).and_then(der::integer) {
                Ok(v) => {
                    self.odometer.ndom = Some(v);
                    Ok(true)
                }
                Err(_) => Ok(false),
            },
            b"CHMH" => match value_of(p, tag::OCTET_STRING) {
                Ok(v) => {
                    digest_of(v)?;
                    Ok(true)
                }
                Err(_) => Ok(false),
            },
            // 0xfffffff005aa1980: the version parsed (0xfffffff005a9dc3c)
            // into the odometer, which this chip's policy does not read.
            b"vnum" => Ok(value_of(p, tag::OCTET_STRING).is_ok()),
            _ => Ok(false),
        }
    }

    /// 0xfffffff005a9d650: `p` imposed on the chip's environment: the
    /// manifest's value against the device's under the descriptor's
    /// operator. A violation is EACCES for the manifest's properties and
    /// EBADEXEC for an object's; a value of the wrong type or encoding is
    /// libDER's error as an errno; the device's error is the error.
    fn impose(&mut self, desc: &Desc, p: &Property<'_>) -> R<()> {
        let violation = match desc.container {
            0 => e::EACCES,
            1 => e::EBADEXEC,
            _ => return Ok(()),
        };
        if !constrainable(desc) {
            return Ok(());
        }
        let get = |t| value_of(p, t).map_err(|d| Fail::Code(dr_errno(d)));
        let bad = match desc.ty {
            Ty::Bool => {
                let m = der::boolean(get(tag::BOOLEAN)?).map_err(|d| Fail::Code(dr_errno(d)))?;
                let e = self.env.query_bool(desc)?;
                violates(desc.op, m, e)?
            }
            Ty::U32 => {
                let m = der::integer(get(tag::INTEGER)?).map_err(|d| Fail::Code(dr_errno(d)))?;
                let e = self.env.query_u32(desc)?;
                violates(desc.op, m, e)?
            }
            Ty::U64 => {
                let m = der::integer64(get(tag::INTEGER)?).map_err(|d| Fail::Code(dr_errno(d)))?;
                let e = self.env.query_u64(desc)?;
                violates(desc.op, m, e)?
            }
            Ty::Digest => {
                let m = digest_of(get(tag::OCTET_STRING)?)?;
                let e = if desc.code == fourcc(b"DGST") {
                    // The payload's digest (0xfffffff005aa0914).
                    match self.payload_digest {
                        Some(h) => h.to_vec(),
                        None => return Err(Fail::Panic("Img4DecodeCopyPayloadDigest: the payload has no data, so no digest".into())),
                    }
                } else {
                    self.env.query_digest(desc)?
                };
                // 0xfffffff005a9b674: lengths and bytes.
                match desc.op {
                    Op::Eq => m != e,
                    Op::Ne => m.len() == e.len() && m == e,
                    _ => return Err(Fail::Panic("property is not constrainable".into())),
                }
            }
            Ty::Version => {
                get(tag::OCTET_STRING)?;
                return Err(Fail::Unmodelled("the long OS version constraint of a 'vnum' the odometer did not take (0xfffffff005a9dc3c, 0xfffffff005a9b85c)".into()));
            }
        };
        if bad {
            return Err(Fail::Code(violation));
        }
        Ok(())
    }

    /// The property callback (0xfffffff005a9d0a8) for container `container`:
    /// a property without a descriptor is kept and not imposed; one of the
    /// manifest's the odometer takes is not imposed either. An impose's
    /// error is kept as the evaluation's and fails the walk.
    fn on_property(&mut self, p: &Property<'_>, container: u8) -> R<()> {
        let Some(desc) = lookup(p.fourcc(), container) else { return Ok(()) };
        if container == 0 && self.consumed(desc, p)? {
            return Ok(());
        }
        match self.impose(desc, p) {
            Ok(()) => Ok(()),
            Err(Fail::Code(c)) => {
                self.error = Some(c);
                Err(Fail::Code(dr::DECODE_ERROR))
            }
            Err(f) => Err(f),
        }
    }

    /// 0xfffffff005aa65e0: each property of the set's content `c`, a
    /// `[PRIVATE]` constructed item whose value is a BOOLEAN, INTEGER,
    /// OCTET STRING or IA5String.
    fn properties(&mut self, c: &[u8], container: u8) -> R<()> {
        let mut seq = Seq::of(c);
        loop {
            let it = match seq.next() {
                Ok(it) => it,
                Err(dr::END_OF_SEQUENCE) => return Ok(()),
                Err(e) => return Err(Fail::Code(e)),
            };
            let p = property(it.content, it.tag)?;
            if !matches!(p.value_tag, tag::BOOLEAN | tag::INTEGER | tag::OCTET_STRING | tag::IA5_STRING) {
                return Err(Fail::Code(dr::UNEXPECTED_TAG));
            }
            if it.tag >> 62 == 0 || it.tag & (1 << 61) == 0 {
                return Err(Fail::Code(dr::UNEXPECTED_TAG));
            }
            self.on_property(&p, container)?;
        }
    }
}

/// The Apple Image4 certificate extension (1.2.840.113635.100.6.1.15): the
/// constraints a leaf puts on the manifests it signs.
const IMG4_EXTENSION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x01, 0x0f];
/// rsaEncryption.
const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/// sha384WithRSAEncryption.
const SHA384_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
/// id-ecPublicKey, whose parameters a signature algorithm may carry.
const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// SHA-384's DigestInfo prefix (`ccsha384_di`'s OID, NULL parameters).
const SHA384_DIGEST_INFO: &[u8] = &[0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30];

const CERT: [Spec; 3] = [spec(tag::SEQUENCE, SAVE_DER), spec(tag::SEQUENCE, 0), spec(tag::BIT_STRING, 0)];
const TBS: [Spec; 10] = [
    spec(tag::context(0), OPTIONAL),
    spec(tag::INTEGER, 0),
    spec(tag::SEQUENCE, 0),
    spec(tag::SEQUENCE, 0),
    spec(tag::SEQUENCE, 0),
    spec(tag::SEQUENCE, 0),
    spec(tag::SEQUENCE, 0),
    spec(tag::context_primitive(1), OPTIONAL),
    spec(tag::context_primitive(2), OPTIONAL),
    spec(tag::context(3), OPTIONAL),
];
const SPKI: [Spec; 2] = [spec(tag::SEQUENCE, 0), spec(tag::BIT_STRING, 0)];
const ALGORITHM: [Spec; 2] = [spec(tag::OID, 0), spec(0, OPTIONAL | ANY | SAVE_DER)];
const EXTENSION: [Spec; 3] = [spec(tag::OID, 0), spec(tag::BOOLEAN, OPTIONAL), spec(tag::OCTET_STRING, 0)];

/// A certificate as 0xfffffff005aa7a34 parses it.
struct Cert<'a> {
    tbs: &'a [u8],
    signature_algorithm: &'a [u8],
    signature: &'a [u8],
    issuer: &'a [u8],
    subject: &'a [u8],
    key: &'a [u8],
    img4: Option<&'a [u8]>,
}

/// -1 for any failure, as the chain's functions return it.
fn chain_err<T>(r: Result<T, i32>) -> Result<T, i32> {
    r.map_err(|_| -1)
}

/// 0xfffffff005aa8cc0: the value of the certificate's Image4 extension,
/// whose content must be a set; none without extensions. Extensions there
/// but empty fail.
fn img4_extension<'a>(extensions: Option<&'a [u8]>) -> Result<Option<&'a [u8]>, i32> {
    let Some(ext) = extensions.filter(|e| !e.is_empty()) else { return Ok(None) };
    let (t, mut seq) = chain_err(der::seq_init(ext))?;
    if t != tag::SEQUENCE {
        return Err(-1);
    }
    let mut any = false;
    let mut out = None;
    loop {
        let it = match seq.next() {
            Ok(it) => it,
            Err(dr::END_OF_SEQUENCE) => break,
            Err(_) => return Err(-1),
        };
        if it.tag != tag::SEQUENCE {
            return Err(-1);
        }
        let x = chain_err(der::parse_content(it.content, &EXTENSION))?;
        any = true;
        if x[0] == Some(IMG4_EXTENSION) {
            let value = x[2].unwrap_or(&[]);
            if chain_err(der::decode_item(value))?.tag != tag::SET {
                return Err(-1);
            }
            out = Some(value);
        }
    }
    if !any {
        return Err(-1);
    }
    Ok(out)
}

/// An algorithm's parameters: absent, or NULL.
fn null_parameters(p: Option<&[u8]>) -> bool {
    match p {
        None | Some([]) => true,
        Some(b) => b == [0x05, 0x00],
    }
}

/// 0xfffffff005aa7a34: certificate `b` parsed: its signed part, its
/// subject's key (rsaEncryption, a bit string of whole bytes) and its
/// Image4 extension.
fn parse_cert(b: &[u8]) -> Result<Cert<'_>, i32> {
    let c = chain_err(der::parse_sequence(b, &CERT))?;
    let tbs = c[0].unwrap_or(&[]);
    let t = chain_err(der::parse_sequence(tbs, &TBS))?;
    let spki = chain_err(der::parse_content(t[6].unwrap_or(&[]), &SPKI))?;
    let alg = chain_err(der::parse_content(spki[0].unwrap_or(&[]), &ALGORITHM))?;
    if alg[0] != Some(RSA_ENCRYPTION) || !null_parameters(alg[1]) {
        return Err(-1);
    }
    let (key, unused) = chain_err(der::bit_string(spki[1].unwrap_or(&[])))?;
    if unused != 0 {
        return Err(-1);
    }
    let img4 = img4_extension(t[9])?;
    Ok(Cert { tbs, signature_algorithm: c[1].unwrap_or(&[]), signature: c[2].unwrap_or(&[]), issuer: t[3].unwrap_or(&[]), subject: t[5].unwrap_or(&[]), key, img4 })
}

/// 0xfffffff005aa7c98: `cert`'s signature by `key`: sha384WithRSAEncryption
/// (parameters NULL or absent, unless the algorithm is id-ecPublicKey's)
/// over its signed part.
fn verify_cert(key: &[u8], cert: &Cert<'_>) -> Result<(), i32> {
    let alg = chain_err(der::parse_content(cert.signature_algorithm, &ALGORITHM))?;
    if alg[1].is_some_and(|p| !p.is_empty()) && alg[0] != Some(EC_PUBLIC_KEY) && !null_parameters(alg[1]) {
        return Err(-1);
    }
    if alg[0] != Some(SHA384_WITH_RSA) {
        return Err(-1);
    }
    let digest = sha384(cert.tbs);
    let (sig, unused) = chain_err(der::bit_string(cert.signature))?;
    if unused != 0 {
        return Err(-1);
    }
    rsa_verify(key, sig, &digest)
}

/// The chain (0xfffffff005aa7e48 with the anchor 0xfffffff005aa8054): the
/// manifest's chain is one certificate under 128 KiB (0xfffffff005aa8be8),
/// issued by the anchor's subject and signed by its key. The leaf's key and
/// Image4 constraints.
pub fn verify_chain<'a>(anchor: &'a [u8], chain: &'a [u8]) -> Result<(&'a [u8], Option<&'a [u8]>), i32> {
    let mut certs = vec![anchor];
    let mut rest = chain;
    loop {
        let it = chain_err(der::decode_item(rest))?;
        let total = it.whole.len();
        if total >> 17 != 0 || certs.len() >= 2 {
            return Err(-1);
        }
        certs.push(it.whole);
        rest = &rest[total..];
        if rest.is_empty() {
            break;
        }
    }
    if certs.len() != 2 {
        return Err(-1);
    }
    let parsed = certs.iter().map(|c| parse_cert(c)).collect::<Result<Vec<_>, _>>()?;
    let (root, leaf) = (&parsed[0], &parsed[1]);
    if leaf.issuer != root.subject {
        return Err(-1);
    }
    verify_cert(root.key, leaf)?;
    Ok((leaf.key, leaf.img4.filter(|p| !p.is_empty())))
}

/// RSA PKCS#1 v1.5 with SHA-384 (0xfffffff005aa7284): an RSAPublicKey of a
/// modulus of at most 4096 bits (`ccrsa_make_pub`: odd, at least 3, the
/// exponent no wider than it) and `ccrsa_verify_pkcs1v15`: a signature as
/// long as the modulus, below it, whose encoding is exactly
/// `00 01 FF.. 00 DigestInfo(sha384, digest)`.
fn rsa_verify(key: &[u8], sig: &[u8], digest: &[u8; 48]) -> Result<(), i32> {
    use num_bigint::BigUint;
    let k = chain_err(der::parse_sequence(key, &[spec(tag::INTEGER, 0x100), spec(tag::INTEGER, 0x100)]))?;
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
    let modulus = BigUint::from_bytes_be(&m);
    if m.last().is_none_or(|&c| c & 1 == 0) || (m.len() == 1 && m[0] < 3) {
        return Err(-1);
    }
    if sig.len() != m.len() {
        return Err(-1);
    }
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

/// 0xfffffff005aa61d4: the leaf's constraints: its extension's set holds
/// `MANP` (on the manifest's properties), `OBJP` (on the payload's
/// object's) and `manx` (passed over), each a set of properties: a BOOLEAN,
/// INTEGER or OCTET STRING one the manifest must have byte for byte, a
/// `[0]` one it must have, a `[1]` one it must not.
fn certificate_constraints(props: Option<&[u8]>, manp: &[u8], objp: &[u8]) -> Result<(), i32> {
    let Some(props) = props else { return Err(dr::DECODE_ERROR) };
    let (t, mut outer) = der::seq_init(props)?;
    if t != tag::SET {
        return Err(dr::UNEXPECTED_TAG);
    }
    loop {
        let it = match outer.next() {
            Ok(it) => it,
            Err(dr::END_OF_SEQUENCE) => return Ok(()),
            Err(_) => return Err(-1),
        };
        let container = match it.tag {
            t if t == tag::private(fourcc(b"MANP")) => manp,
            t if t == tag::private(fourcc(b"manx")) => continue,
            // (An `OBJP` is passed over for an evaluation without an object,
            // the manifest's alone, which this is not.)
            t if t == tag::private(fourcc(b"OBJP")) => objp,
            _ => return Err(dr::UNEXPECTED_TAG),
        };
        let p = property(it.content, it.tag)?;
        if p.value_tag != tag::SET {
            return Err(dr::UNEXPECTED_TAG);
        }
        let mut inner = Seq::of(p.value);
        loop {
            let c = match inner.next() {
                Ok(c) => c,
                Err(dr::END_OF_SEQUENCE) => break,
                Err(_) => return Err(-1),
            };
            let cp = property(c.content, c.tag)?;
            let found = find(container, c.tag);
            match cp.value_tag {
                tag::BOOLEAN | tag::INTEGER | tag::OCTET_STRING => {
                    let m = found?;
                    if m != c.content {
                        return Err(-1);
                    }
                }
                t if t == tag::context(0) => {
                    found?;
                }
                t if t == tag::context(1) => match found {
                    Err(dr::END_OF_SEQUENCE) => {}
                    _ => return Err(dr::UNEXPECTED_TAG),
                },
                _ => return Err(dr::UNEXPECTED_TAG),
            }
        }
    }
}

/// `Img4DecodePerformTrustEvaluationWithCallbacks` (0xfffffff005aa6df8),
/// in its order.
fn trust(ev: &mut Eval<'_>, m: &Manifest<'_>) -> R<()> {
    // The whole manifest's digest is kept for a chip that checks it
    // against its boot's; this chip does not.
    let _ = sha384(m.whole);
    let anchor = ev.env.env.anchor().map_err(Fail::Unmodelled)?;
    let (key, constraints) = verify_chain(&anchor, m.chain)?;
    let body_digest = sha384(m.body);
    rsa_verify(key, m.signature, &body_digest)?;
    // 0xfffffff005aa4794: the body's `MANB` (a sequence in version 2
    // manifests), its `MANP`.
    let set = der::decode_item(m.body)?;
    if set.tag != tag::SET {
        return Err(Fail::Code(-1));
    }
    let manb_tag = if m.version == 2 { tag::SEQUENCE } else { tag::SET };
    let manb = find_property(set.content, tag::private(fourcc(b"MANB")), manb_tag)?;
    let manp = find_property(manb, tag::private(fourcc(b"MANP")), tag::SET)?;
    let object = find_property(manb, tag::private(ev.fourcc), tag::SET)?;
    certificate_constraints(constraints, manp, object)?;
    // 0xfffffff005aa49d4: a payload with data has its digest, of the
    // whole IM4P.
    if ev.payload.data.is_some_and(|d| !d.is_empty()) {
        ev.payload_digest = Some(sha384(ev.payload.whole));
    }
    ev.properties(manp, 0)?;
    ev.properties(object, 1)?;
    Ok(())
}

/// The anti-replay policy (0xfffffff005aa15d8): this chip boots (its boot
/// query, 0xfffffff005a99108, answers it), so of the boot policies the
/// first that applies: `BOOT` (0xfffffff005a96474) when the manifest has a
/// cryptex1 boot nonce hash, else `NULL`, which passes. `BOOT` compares the
/// manifest's hash with the device's for the manifest's nonce domain: no
/// domain is no nonce (ENOTSUP), a different hash ESTALE.
fn anti_replay(ev: &Eval<'_>) -> R<()> {
    let Some(cnch) = &ev.odometer.cnch else { return Ok(()) };
    let Some(domain) = ev.odometer.ndom else { return Err(Fail::Code(e::ENOTSUP)) };
    if domain != CRYPTEX1_BOOT_NONCE_DOMAIN {
        return Err(Fail::Unmodelled(format!("the nonce magazine's slot for CHIP_CRYPTEX1_BOOT_AP in nonce domain {domain} (0xfffffff005a9f268)")));
    }
    let hash = ev.env.env.cryptex1_boot_nonce_hash(domain)?;
    if *cnch != hash {
        return Err(Fail::Code(e::ESTALE));
    }
    Ok(())
}

/// 0xfffffff005aa1318: the odometer's cylinders, the device's mix-n-match
/// prevention (unknown is allowed), certificate production status and
/// certificate security mode.
fn prepare(env: &Env<'_>) -> R<()> {
    for i in [13usize, 5, 6] {
        env.query_bool(&DESCS[i])?;
    }
    Ok(())
}

/// `img4_firmware_execute` for `CHIP_CRYPTEX1_BOOT_AP` of payload type
/// `fourcc` with no nonce and no flags (module documentation).
pub fn execute(fourcc: u32, payload: &[u8], manifest: &[u8], env: &dyn Environment) -> Outcome {
    let p = match init_as_payload(payload) {
        Ok(p) => p,
        Err(d) => return Outcome::Status(dr_errno(d)),
    };
    let Ok(m) = init_as_manifest(manifest) else { return Outcome::Status(e::EFTYPE) };
    let mut ev = Eval { env: Env { env }, fourcc, payload: &p, payload_digest: None, error: None, odometer: Odometer::default() };
    let status = match prepare(&ev.env) {
        Err(Fail::Code(c)) => c,
        Err(Fail::Panic(s)) => return Outcome::Panic(s),
        Err(Fail::Unmodelled(s)) => return Outcome::Unmodelled(s),
        Ok(()) => match trust(&mut ev, &m) {
            Err(Fail::Code(_)) => ev.error.unwrap_or(e::EAUTH),
            Err(Fail::Panic(s)) => return Outcome::Panic(s),
            Err(Fail::Unmodelled(s)) => return Outcome::Unmodelled(s),
            Ok(()) => match anti_replay(&ev) {
                Err(Fail::Code(c)) => c,
                Err(Fail::Panic(s)) => return Outcome::Panic(s),
                Err(Fail::Unmodelled(s)) => return Outcome::Unmodelled(s),
                Ok(()) => 0,
            },
        },
    };
    match status {
        0 => match p.data.filter(|d| !d.is_empty()) {
            Some(d) => Outcome::Authenticated(d.to_vec()),
            None => Outcome::Panic("Img4DecodeGetPayload: the payload has no data".into()),
        },
        e::EBADEXEC => Outcome::Status(e::ENOEXEC),
        s => Outcome::Status(s),
    }
}

/// AppleImage4's nonce slots (one per nonce domain in its nonce magazine,
/// [`super::noncemag`]) and the hash the BOOT anti-replay policy
/// (0xfffffff005a96474) makes of the cryptex1 boot slot's nonce.
///
/// A slot's data (parsed at 0xfffffff005a9a254, written at
/// 0xfffffff005a9a3a0) is 37 bytes: a version byte (0), the flags as a
/// big-endian `u32` of which the parse keeps the last byte's low seven
/// bits, the nonce (16 bytes) and the proposal (16 bytes, there with flag
/// [`flag::PROPOSAL`]).
///
/// The cryptex1 boot domain (its record at 0xfffffff006cf24a8: domain 1,
/// entitlement `com.apple.private.img4.nonce.cryptex1.boot`) has nonces of
/// 16 bytes (the record's +0x48). The policy queries the nonce (runtime
/// +0x70, 0xfffffff005a99118; the slot's access, 0xfffffff005a8f7d4, and
/// the domain's own check, 0xfffffff005a8d65c, which a device without PPL
/// passes), entangles it (runtime +0x78, 0xfffffff005a99210) and hashes it
/// (0xfffffff005aa0a5c). Entangling is IOAESAccelerator's AES with key
/// 0x8A4, the UID's, over the nonce (a multiple of 16 bytes, else the kext
/// panics), a zero IV, operation 0 and a 128-bit key spec, done only when
/// `/defaults` has `entangle-nonce` (read at 0xfffffff005a988f0) or the
/// slot has [`flag::ENTANGLE`]; AppleImage4 never sets that flag (its roll
/// clears it), so only NVRAM written elsewhere does. The hash is SHA-384
/// truncated to 32 bytes: the chip's digest (its +0x30, `ccsha384_di`,
/// 48 bytes) and the kext's copy of it with 32 (0xfffffff006cf9a90, made at
/// 0xfffffff005aa3a28), of which 0xfffffff005a98ebc takes the shorter when
/// the chip has BNCH and nonce domain constraints (its +0x198, +0x1b8) and
/// no +0x1a0, as `CHIP_CRYPTEX1_BOOT_AP` has.
pub mod nonce {
    use super::{e, Fail};
    use sha2::{Digest, Sha384};

    /// A slot's data.
    pub const SLOT_SIZE: usize = 37;
    /// The cryptex1 boot domain's nonce length (its record's +0x48).
    pub const CRYPTEX1_BOOT_NONCE_LENGTH: usize = 16;
    /// The hash's length: SHA-384 truncated.
    pub const HASH_LENGTH: usize = 32;

    /// A slot's flags.
    pub mod flag {
        /// The nonce is spent (0xfffffff005a9a240 sets it): ESTALE.
        pub const SPENT: u32 = 0x2;
        /// The proposal is there.
        pub const PROPOSAL: u32 = 0x4;
        /// The nonce is not to be had: ENXIO, whose policy asks for the
        /// boot nonce hash instead.
        pub const UNAVAILABLE: u32 = 0x8;
        /// The nonce is entangled with the UID key.
        pub const ENTANGLE: u32 = 0x40;
    }

    /// A slot, as the kext holds it parsed.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Slot {
        pub flags: u32,
        pub nonce: [u8; 16],
        pub proposal: [u8; 16],
    }

    impl Slot {
        /// 0xfffffff005a9a254: a slot's data. None is ENODATA, a version
        /// past 0 ESHLIBVERS when there is a whole slot of it and ERANGE
        /// when not, version 0 of another length ERANGE.
        pub fn parse(b: &[u8]) -> Result<Slot, i32> {
            let Some(&version) = b.first() else { return Err(e::ENODATA) };
            if version != 0 {
                return Err(if b.len() > SLOT_SIZE - 1 { e::ESHLIBVERS } else { e::ERANGE });
            }
            if b.len() != SLOT_SIZE {
                return Err(e::ERANGE);
            }
            Ok(Slot { flags: u32::from(b[4] & 0x7f), nonce: b[5..21].try_into().unwrap(), proposal: b[21..37].try_into().unwrap() })
        }

        /// 0xfffffff005a9a3a0: the slot's data.
        pub fn to_bytes(&self) -> [u8; SLOT_SIZE] {
            let mut b = [0u8; SLOT_SIZE];
            b[1..5].copy_from_slice(&self.flags.to_be_bytes());
            b[5..21].copy_from_slice(&self.nonce);
            b[21..37].copy_from_slice(&self.proposal);
            b
        }

    }

    /// The cryptex1 boot nonce hash of `slot`, as the BOOT policy makes it:
    /// the access check's errno (ESTALE for a spent nonce, the status the
    /// policy fails with), the policy's other path for an unavailable one
    /// and the entangling (both not modelled), else SHA-384 of the nonce,
    /// truncated. `entangle_nonce` is `/defaults`' `entangle-nonce`.
    pub fn cryptex1_boot_hash(slot: &Slot, entangle_nonce: bool) -> Result<Vec<u8>, Fail> {
        if slot.flags & flag::SPENT != 0 {
            return Err(Fail::Code(e::ESTALE));
        }
        if slot.flags & flag::UNAVAILABLE != 0 {
            return Err(Fail::Unmodelled("the BOOT anti-replay policy's boot nonce hash query for a nonce slot whose nonce is unavailable (ENXIO; 0xfffffff005a96558, runtime +0x80)".into()));
        }
        let n = &slot.nonce[..CRYPTEX1_BOOT_NONCE_LENGTH];
        if entangle_nonce || slot.flags & flag::ENTANGLE != 0 {
            return Err(Fail::Unmodelled("entangling the cryptex1 boot nonce with the UID key: IOAESAccelerator's performAES (vtable +0x550) with key 0x8A4, a zero IV and operation 0 (0xfffffff005a99210), whose AES direction and mode are the accelerator driver's, not traced".into()));
        }
        Ok(Sha384::digest(n)[..HASH_LENGTH].to_vec())
    }
}

/// DER as Image4 has it: the items, the `[PRIVATE]` properties, and sets
/// in DER's order (X.690 11.6: by their encodings, compared as octet
/// strings, the shorter padded with zeros), which is the order of Apple's
/// manifests' properties and objects.
pub mod enc {
    /// A definite, minimal length.
    pub fn len(n: usize) -> Vec<u8> {
        if n < 0x80 {
            return vec![n as u8];
        }
        let b: Vec<u8> = n.to_be_bytes().iter().copied().skip_while(|&c| c == 0).collect();
        let mut v = vec![0x80 | b.len() as u8];
        v.extend(b);
        v
    }

    pub fn tlv(tag: &[u8], content: &[u8]) -> Vec<u8> {
        let mut v = tag.to_vec();
        v.extend(len(content.len()));
        v.extend_from_slice(content);
        v
    }

    pub fn seq(items: &[Vec<u8>]) -> Vec<u8> {
        tlv(&[0x30], &items.concat())
    }

    /// A SET in DER's order.
    pub fn set(items: &[Vec<u8>]) -> Vec<u8> {
        let mut v: Vec<&Vec<u8>> = items.iter().collect();
        v.sort_by(|a, b| {
            let n = a.len().max(b.len());
            let pad = |x: &Vec<u8>| x.iter().copied().chain(std::iter::repeat(0)).take(n).collect::<Vec<u8>>();
            pad(a).cmp(&pad(b))
        });
        tlv(&[0x31], &v.into_iter().flatten().copied().collect::<Vec<u8>>())
    }

    pub fn ia5(s: &[u8]) -> Vec<u8> {
        tlv(&[0x16], s)
    }

    pub fn utf8(s: &str) -> Vec<u8> {
        tlv(&[0x0c], s.as_bytes())
    }

    /// An INTEGER of the unsigned big-endian `b`, minimal.
    pub fn uint(b: &[u8]) -> Vec<u8> {
        let mut v: Vec<u8> = b.iter().copied().skip_while(|&c| c == 0).collect();
        if v.first().is_none_or(|&c| c & 0x80 != 0) {
            v.insert(0, 0);
        }
        tlv(&[0x02], &v)
    }

    pub fn int(v: u64) -> Vec<u8> {
        uint(&v.to_be_bytes())
    }

    pub fn boolean(v: bool) -> Vec<u8> {
        tlv(&[0x01], &[if v { 0xff } else { 0x00 }])
    }

    pub fn octets(b: &[u8]) -> Vec<u8> {
        tlv(&[0x04], b)
    }

    pub fn null() -> Vec<u8> {
        vec![0x05, 0x00]
    }

    /// An OBJECT IDENTIFIER of its content's bytes.
    pub fn oid(content: &[u8]) -> Vec<u8> {
        tlv(&[0x06], content)
    }

    /// A BIT STRING of whole bytes.
    pub fn bits(b: &[u8]) -> Vec<u8> {
        let mut c = vec![0u8];
        c.extend_from_slice(b);
        tlv(&[0x03], &c)
    }

    /// `[n]` constructed.
    pub fn context(n: u8, content: &[u8]) -> Vec<u8> {
        tlv(&[0xa0 | n], content)
    }

    /// `[PRIVATE code]` constructed's identifier: 0xff and the code in base
    /// 128.
    pub fn private_tag(code: u32) -> Vec<u8> {
        let mut digits = vec![];
        let mut v = code;
        loop {
            digits.push((v & 0x7f) as u8);
            v >>= 7;
            if v == 0 {
                break;
            }
        }
        digits.reverse();
        let last = digits.len() - 1;
        let mut t = vec![0xff];
        t.extend(digits.iter().enumerate().map(|(i, &d)| if i == last { d } else { d | 0x80 }));
        t
    }

    /// An Image4 property: `[PRIVATE code] { IA5String code, value }`.
    pub fn property(code: u32, value: Vec<u8>) -> Vec<u8> {
        tlv(&private_tag(code), &seq(&[ia5(&code.to_be_bytes()), value]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A DER length.
    fn len(n: usize) -> Vec<u8> {
        if n < 0x80 {
            return vec![n as u8];
        }
        let b: Vec<u8> = n.to_be_bytes().iter().copied().skip_while(|&c| c == 0).collect();
        let mut v = vec![0x80 | b.len() as u8];
        v.extend(b);
        v
    }

    fn tlv(t: &[u8], c: &[u8]) -> Vec<u8> {
        let mut v = t.to_vec();
        v.extend(len(c.len()));
        v.extend_from_slice(c);
        v
    }

    fn seq(items: &[Vec<u8>]) -> Vec<u8> {
        tlv(&[0x30], &items.concat())
    }

    fn set(items: &[Vec<u8>]) -> Vec<u8> {
        tlv(&[0x31], &items.concat())
    }

    fn ia5(s: &str) -> Vec<u8> {
        tlv(&[0x16], s.as_bytes())
    }

    fn int(v: u64) -> Vec<u8> {
        let mut b: Vec<u8> = v.to_be_bytes().iter().copied().skip_while(|&c| c == 0).collect();
        if b.first().is_none_or(|&c| c & 0x80 != 0) {
            b.insert(0, 0);
        }
        tlv(&[0x02], &b)
    }

    fn octets(b: &[u8]) -> Vec<u8> {
        tlv(&[0x04], b)
    }

    fn boolean(v: bool) -> Vec<u8> {
        tlv(&[0x01], &[if v { 0xff } else { 0x00 }])
    }

    /// `[PRIVATE code]` constructed: 0xff and the code in base 128.
    fn private_tag(code: &str) -> Vec<u8> {
        let n = u32::from_be_bytes(code.as_bytes().try_into().unwrap());
        let mut digits = vec![];
        let mut v = n;
        loop {
            digits.push((v & 0x7f) as u8);
            v >>= 7;
            if v == 0 {
                break;
            }
        }
        digits.reverse();
        let last = digits.len() - 1;
        let mut t = vec![0xff];
        t.extend(digits.iter().enumerate().map(|(i, &d)| if i == last { d } else { d | 0x80 }));
        t
    }

    /// An Image4 property: `[PRIVATE code] { IA5String code, value }`.
    fn prop(code: &str, value: Vec<u8>) -> Vec<u8> {
        tlv(&private_tag(code), &seq(&[ia5(code), value]))
    }

    fn im4p(ty: &str, data: &[u8]) -> Vec<u8> {
        seq(&[ia5("IM4P"), ia5(ty), ia5("1"), octets(data)])
    }

    /// An IM4M around `manb`'s properties: `MANP` and `objects`, with
    /// `signature` and `chain` as given (not a signed manifest).
    fn im4m(manp: Vec<Vec<u8>>, objects: Vec<(&str, Vec<Vec<u8>>)>, signature: &[u8], chain: &[u8]) -> Vec<u8> {
        let mut manb = vec![prop("MANP", set(&manp))];
        for (code, props) in objects {
            manb.push(prop(code, set(&props)));
        }
        let body = set(&[prop("MANB", set(&manb))]);
        seq(&[ia5("IM4M"), int(0), body, octets(signature), tlv(&[0x30], chain)])
    }

    #[derive(Default)]
    struct Fake {
        chosen: HashMap<&'static str, Vec<u8>>,
        nonce: Option<Vec<u8>>,
        anchor: Option<Vec<u8>>,
    }

    /// The boot payload's anchor (GEX_DARWIN_BOOT's img4_anchor.der).
    fn boot_anchor() -> Vec<u8> {
        let dir = std::env::var("GEX_DARWIN_BOOT").expect("GEX_DARWIN_BOOT");
        std::fs::read(format!("{dir}/img4_anchor.der")).expect("img4_anchor.der")
    }

    impl Environment for Fake {
        fn chosen(&self, name: &str, size: usize) -> Result<Option<Vec<u8>>, i32> {
            let Some(v) = self.chosen.get(name) else { return Ok(None) };
            if v.len() > size {
                return Err(e::EOVERFLOW);
            }
            let mut b = vec![0u8; size];
            b[..v.len()].copy_from_slice(v);
            Ok(Some(b))
        }

        fn cryptex1_boot_nonce_hash(&self, _domain: u32) -> Result<Vec<u8>, Fail> {
            self.nonce.clone().ok_or_else(|| Fail::Unmodelled("not measured".to_string()))
        }

        fn anchor(&self) -> Result<Vec<u8>, String> {
            self.anchor.clone().ok_or_else(|| "no anchor".to_string())
        }
    }

    /// A device whose `/chosen` has what an AP's iBoot fills in.
    fn device() -> Fake {
        let mut f = Fake::default();
        for (k, v) in [("chip-id", 0x8011u32), ("board-id", 0x0c), ("security-domain", 1), ("certificate-production-status", 1), ("certificate-security-mode", 1), ("effective-production-status-ap", 1), ("effective-security-mode-ap", 1), ("mix-n-match-prevention-status", 1), ("research-enabled", 0)] {
            f.chosen.insert(k, v.to_le_bytes().to_vec());
        }
        f.chosen.insert("unique-chip-id", 0x0011_2233_4455_6677u64.to_le_bytes().to_vec());
        f
    }

    #[test]
    fn items_are_definite_minimal_and_inside() {
        assert_eq!(der::decode_item(&[0x04, 0x02, 1, 2, 9]).map(|i| (i.tag, i.content, i.whole.len())), Ok((4, &[1u8, 2][..], 4)));
        // Too short, a length past the end, the indefinite form, a long
        // form for a short length, a leading zero length byte.
        assert_eq!(der::decode_item(&[0x04]), Err(dr::DECODE_ERROR));
        assert_eq!(der::decode_item(&[0x04, 0x03, 1, 2]), Err(dr::DECODE_ERROR));
        assert_eq!(der::decode_item(&[0x30, 0x80, 0, 0]), Err(dr::DECODE_ERROR));
        assert_eq!(der::decode_item(&[0x04, 0x81, 0x05, 1, 2, 3, 4, 5]), Err(dr::DECODE_ERROR));
        assert_eq!(der::decode_item(&[0x04, 0x82, 0x00, 0x80]), Err(dr::DECODE_ERROR));
        let long: Vec<u8> = [&[0x04, 0x81, 0x80][..], &[7u8; 0x80]].concat();
        assert_eq!(der::decode_item(&long).map(|i| i.content.len()), Ok(0x80));
        // High tag numbers: private constructed 'MANB', and the forms
        // libDER refuses (a leading 0x80 digit, a number under 31).
        let t = private_tag("MANB");
        let b = tlv(&t, &[]);
        let it = der::decode_item(&b).unwrap();
        assert_eq!(it.tag, tag::private(fourcc(b"MANB")));
        assert_eq!(der::decode_item(&[0x1f, 0x80, 0x01, 0x00]), Err(dr::DECODE_ERROR));
        assert_eq!(der::decode_item(&[0x1f, 0x1e, 0x00]), Err(dr::DECODE_ERROR));
        assert_eq!(der::decode_item(&[0x1f, 0x1f, 0x00]).map(|i| i.tag), Ok(0x1f));
    }

    #[test]
    fn sequences_match_their_specs_in_order() {
        let specs = [spec(tag::INTEGER, 0), spec(tag::OCTET_STRING, OPTIONAL), spec(tag::BOOLEAN, 0)];
        let both = [int(5), octets(b"x"), boolean(true)].concat();
        let r = der::parse_content(&both, &specs).unwrap();
        assert_eq!(r[1], Some(&b"x"[..]));
        let skipped = [int(5), boolean(true)].concat();
        assert_eq!(der::parse_content(&skipped, &specs).unwrap()[1], None);
        // A required spec left over, an item no spec takes, and anything
        // after the last spec's item.
        assert_eq!(der::parse_content(&int(5), &specs), Err(dr::INCOMPLETE_SEQ));
        assert_eq!(der::parse_content(&[int(5), ia5("x")].concat(), &specs), Err(dr::UNEXPECTED_TAG));
        assert_eq!(der::parse_content(&[both.clone(), int(1)].concat(), &specs), Err(dr::DECODE_ERROR));
        // The whole item kept with SAVE_DER.
        let five = int(5);
        let saved = der::parse_content(&five, &[spec(tag::INTEGER, SAVE_DER)]).unwrap();
        assert_eq!(saved[0], Some(&int(5)[..]));
        // DERParseSequence takes a SEQUENCE only.
        assert_eq!(der::parse_sequence(&set(&[int(5)]), &[spec(tag::INTEGER, 0)]), Err(dr::UNEXPECTED_TAG));
    }

    #[test]
    fn primitives_as_libder_reads_them() {
        assert_eq!(der::integer64(&[0x00]), Ok(0));
        assert_eq!(der::integer64(&[0x00, 0x7f]), Err(dr::DECODE_ERROR));
        assert_eq!(der::integer64(&[0x80]), Err(dr::DECODE_ERROR));
        assert_eq!(der::integer64(&[0x00, 0xff, 1, 2, 3, 4, 5, 6, 7]), Ok(0xff01_0203_0405_0607));
        assert_eq!(der::integer64(&[1, 2, 3, 4, 5, 6, 7, 8, 9]), Err(dr::BUF_OVERFLOW));
        assert_eq!(der::integer(&[1, 0, 0, 0, 0]), Err(dr::BUF_OVERFLOW));
        assert_eq!(der::integer(b"IM4M"), Ok(fourcc(b"IM4M")));
        assert_eq!(der::boolean(&[0xff]), Ok(true));
        assert_eq!(der::boolean(&[0x01]), Err(dr::DECODE_ERROR));
        assert_eq!(der::bit_string(&[0, 0xa5]), Ok((&[0xa5u8][..], 0)));
        assert_eq!(der::bit_string(&[1, 0xa5]), Err(dr::DECODE_ERROR));
        assert_eq!(der::bit_string(&[1, 0xa4]), Ok((&[0xa4u8][..], 1)));
        assert_eq!(der::bit_string(&[8, 0x00]), Err(dr::DECODE_ERROR));
        assert_eq!(dr_errno(dr::DECODE_ERROR), 92);
        assert_eq!(dr_errno(9), 14);
    }

    #[test]
    fn payloads_and_manifests_decode_as_img4_has_them() {
        let p = im4p("cssy", b"root");
        assert_eq!(init_as_payload(&p).unwrap().data, Some(&b"root"[..]));
        assert_eq!(init_as_payload(&seq(&[ia5("IM4X"), ia5("cssy"), ia5("1"), octets(b"x")])).err(), Some(dr::UNEXPECTED_TAG));
        // A compression algorithm past 1.
        let compressed = seq(&[ia5("IM4P"), ia5("cssy"), ia5("1"), octets(b"x"), seq(&[int(2), int(1)])]);
        assert_eq!(init_as_payload(&compressed).err(), Some(dr::PARAM_ERR));
        let m = im4m(vec![], vec![], b"sig", &[]);
        let d = init_as_manifest(&m).unwrap();
        assert_eq!((d.version, d.signature), (0, &b"sig"[..]));
        // Trailing bytes, a later version, and not an IM4M at all.
        assert_eq!(init_as_manifest(&[m.clone(), vec![0]].concat()).err(), Some(dr::BUF_OVERFLOW));
        let v3 = seq(&[ia5("IM4M"), int(3), set(&[]), octets(b""), seq(&[])]);
        assert_eq!(init_as_manifest(&v3).err(), Some(dr::UNEXPECTED_TAG));
        assert!(init_as_manifest(b"placeholder, not a ticket").is_err());
    }

    #[test]
    fn a_manifest_that_is_not_one_is_eftype() {
        let s = execute(fourcc(b"cssy"), &im4p("cssy", b"root"), b"placeholder, not a ticket", &device());
        assert_eq!(s, Outcome::Status(e::EFTYPE));
        // A payload that is not Image4 is libDER's error as an errno,
        // before the manifest is looked at.
        let s = execute(fourcc(b"cssy"), b"\x30\x80", b"anything", &device());
        assert_eq!(s, Outcome::Status(92));
    }

    #[test]
    fn the_odometer_needs_the_certificate_status_and_mode() {
        let m = im4m(vec![], vec![], b"", &[]);
        let p = im4p("cssy", b"root");
        let mut f = device();
        f.chosen.remove("certificate-production-status");
        assert_eq!(execute(fourcc(b"cssy"), &p, &m, &f), Outcome::Status(e::ENOENT));
        // An unknown mix-n-match prevention is allowed: the evaluation
        // goes on to the chain, which needs the anchor.
        let mut f = device();
        f.chosen.remove("mix-n-match-prevention-status");
        assert_eq!(execute(fourcc(b"cssy"), &p, &m, &f), Outcome::Unmodelled("no anchor".into()));
        // Longer than its four bytes: EOVERFLOW.
        let mut f = device();
        f.chosen.insert("certificate-security-mode", vec![1; 8]);
        assert_eq!(execute(fourcc(b"cssy"), &p, &m, &f), Outcome::Status(e::EOVERFLOW));
    }

    #[test]
    #[ignore = "needs GEX_DARWIN_BOOT's img4_anchor.der (21H461)"]
    fn the_anchor_is_the_ddi_root_and_signs_itself() {
        let anchor = boot_anchor();
        let root = parse_cert(&anchor).unwrap();
        assert_eq!(root.issuer, root.subject);
        assert!(root.img4.is_none());
        verify_cert(root.key, &root).unwrap();
        // A signature with one bit changed is not the key's.
        let mut bad = anchor.clone();
        let n = bad.len();
        bad[n - 10] ^= 1;
        let b = parse_cert(&bad).unwrap();
        assert_eq!(verify_cert(root.key, &b), Err(-1));
    }

    #[test]
    fn the_chain_is_one_certificate() {
        // None, or two, are refused before a certificate is parsed.
        let cert = seq(&[seq(&[]), seq(&[]), tlv(&[0x03], &[0])]);
        assert_eq!(verify_chain(&cert, &[]).err(), Some(-1));
        assert_eq!(verify_chain(&cert, &[cert.clone(), cert.clone()].concat()).err(), Some(-1));
        // One that is not a certificate.
        assert_eq!(verify_chain(&cert, &cert).err(), Some(-1));
    }

    #[test]
    #[ignore = "needs GEX_DARWIN_BOOT's img4_anchor.der (21H461)"]
    fn the_chain_is_one_certificate_under_the_anchor() {
        // The anchor itself chains (it issued itself) but carries no Image4
        // constraints.
        let anchor = boot_anchor();
        let (key, props) = verify_chain(&anchor, &anchor).unwrap();
        assert_eq!(key, parse_cert(&anchor).unwrap().key);
        assert!(props.is_none());
        // So a manifest whose chain is the anchor fails at its body's
        // signature: EAUTH.
        let m = im4m(vec![], vec![("cssy", vec![])], &[0u8; 512], &anchor);
        let mut f = device();
        f.anchor = Some(anchor.clone());
        assert_eq!(execute(fourcc(b"cssy"), &im4p("cssy", b"root"), &m, &f), Outcome::Status(e::EAUTH));
    }

    #[test]
    #[ignore = "needs GEX_DARWIN_BOOT's img4_anchor.der (21H461)"]
    fn signatures_are_exactly_the_modulus_long() {
        let anchor = boot_anchor();
        let root = parse_cert(&anchor).unwrap();
        let digest = sha384(root.tbs);
        let (sig, _) = der::bit_string(root.signature).unwrap();
        rsa_verify(root.key, sig, &digest).unwrap();
        // A leading zero byte more, the wrong digest.
        assert_eq!(rsa_verify(root.key, &[&[0u8][..], sig].concat(), &digest), Err(-1));
        assert_eq!(rsa_verify(root.key, sig, &[0u8; 48]), Err(-1));
    }

    #[test]
    fn certificate_constraints_hold_the_manifest_to_the_leaf() {
        let manp = [prop("CHIP", int(0x8011)), prop("ECID", int(7))].concat();
        let objp = prop("DGST", octets(&[1; 48]));
        let leaf = |c: Vec<Vec<u8>>, o: Vec<Vec<u8>>| set(&[prop("MANP", set(&c)), prop("OBJP", set(&o))]);
        let ok = leaf(vec![prop("CHIP", int(0x8011)), prop("ECID", tlv(&[0xa0], &[]))], vec![prop("DGST", tlv(&[0xa0], &[]))]);
        assert_eq!(certificate_constraints(Some(&ok), &manp, &objp), Ok(()));
        let other = leaf(vec![prop("CHIP", int(0x8010))], vec![]);
        assert_eq!(certificate_constraints(Some(&other), &manp, &objp), Err(-1));
        let missing = leaf(vec![prop("BORD", tlv(&[0xa0], &[]))], vec![]);
        assert_eq!(certificate_constraints(Some(&missing), &manp, &objp), Err(dr::END_OF_SEQUENCE));
        let forbidden = leaf(vec![prop("ECID", tlv(&[0xa1], &[]))], vec![]);
        assert_eq!(certificate_constraints(Some(&forbidden), &manp, &objp), Err(dr::UNEXPECTED_TAG));
        let absent = leaf(vec![prop("BORD", tlv(&[0xa1], &[]))], vec![]);
        assert_eq!(certificate_constraints(Some(&absent), &manp, &objp), Ok(()));
        // A leaf without constraints fails.
        assert_eq!(certificate_constraints(None, &manp, &objp), Err(dr::DECODE_ERROR));
    }

    fn eval<'a>(env: &'a Fake, p: &'a Payload<'a>) -> Eval<'a> {
        Eval { env: Env { env }, fourcc: fourcc(b"cssy"), payload: p, payload_digest: Some(sha384(p.whole)), error: None, odometer: Odometer::default() }
    }

    #[test]
    fn manifest_properties_are_imposed_on_the_device() {
        let f = device();
        let raw = im4p("cssy", b"root");
        let p = init_as_payload(&raw).unwrap();
        let run = |props: Vec<Vec<u8>>| {
            let mut ev = eval(&f, &p);
            let r = ev.properties(&props.concat(), 0);
            (r, ev.error)
        };
        let good = vec![
            prop("CHIP", int(0x8011)),
            prop("BORD", int(0x0c)),
            prop("SDOM", int(1)),
            prop("ECID", int(0x0011_2233_4455_6677)),
            prop("CPRO", boolean(true)),
            prop("CSEC", boolean(true)),
            prop("CEPO", int(3)),
            prop("fchp", int(0xff10)),
            prop("type", int(1)),
            prop("styp", int(1)),
            prop("clas", int(0xf2)),
            prop("rsch", boolean(false)),
            prop("BNCH", octets(&[9; 48])),
            prop("love", octets(b"21.8.461.0.0,0")),
            prop("XXXX", int(1)),
        ];
        assert_eq!(run(good), (Ok(()), None));
        // Each violation is EACCES.
        for bad in [prop("CHIP", int(0x8010)), prop("ECID", int(1)), prop("CEPO", int(0)), prop("fchp", int(0xff11)), prop("clas", int(0xf1)), prop("CPRO", boolean(false)), prop("rsch", boolean(true))] {
            assert_eq!(run(vec![bad]), (Err(Fail::Code(dr::DECODE_ERROR)), Some(e::EACCES)));
        }
        // A value of the wrong type is libDER's error (EDOM); a property
        // the device does not have is its ENOENT.
        assert_eq!(run(vec![prop("CHIP", octets(&[0x80, 0x11]))]).1, Some(33));
        assert_eq!(run(vec![prop("esdm", int(0))]).1, Some(e::ENOENT));
        // The universal device identifier: 0, the chip and the ECID.
        let udid = [&[0u8; 4][..], &0x8011u32.to_be_bytes(), &0x0011_2233_4455_6677u64.to_be_bytes()].concat();
        assert_eq!(run(vec![prop("UDID", octets(&udid))]), (Ok(()), None));
        // A digest past 64 bytes panics the kext.
        assert!(matches!(run(vec![prop("BNCH", octets(&[0; 65]))]).0, Ok(())));
        assert!(matches!(run(vec![prop("cnch", octets(&[0; 65]))]).0, Err(Fail::Panic(_))));
        // The property set's items are [PRIVATE] properties of the four
        // value types.
        assert_eq!(run(vec![prop("CHIP", seq(&[]))]).0, Err(Fail::Code(dr::UNEXPECTED_TAG)));
        assert_eq!(run(vec![tlv(&[0xa0], &seq(&[ia5("CHIP"), int(1)]))]).0, Err(Fail::Code(dr::UNEXPECTED_TAG)));
    }

    #[test]
    fn object_properties_bind_the_payload() {
        let f = device();
        let raw = im4p("cssy", b"root");
        let p = init_as_payload(&raw).unwrap();
        let mut ev = eval(&f, &p);
        assert_eq!(ev.properties(&[prop("DGST", octets(&sha384(&raw))), prop("EPRO", boolean(true)), prop("ESEC", boolean(true))].concat(), 1), Ok(()));
        let mut ev = eval(&f, &p);
        assert_eq!(ev.properties(&prop("DGST", octets(&[0; 48])), 1), Err(Fail::Code(dr::DECODE_ERROR)));
        assert_eq!(ev.error, Some(e::EBADEXEC));
        let mut ev = eval(&f, &p);
        assert_eq!(ev.properties(&prop("ESEC", boolean(false)), 1), Err(Fail::Code(dr::DECODE_ERROR)));
        assert_eq!(ev.error, Some(e::EBADEXEC));
    }

    #[test]
    fn the_cryptex1_boot_nonce_hash_is_the_devices() {
        let raw = im4p("cssy", b"root");
        let p = init_as_payload(&raw).unwrap();
        let mut f = device();
        f.nonce = Some(vec![5; 48]);
        let run = |f: &Fake, props: Vec<Vec<u8>>| {
            let mut ev = eval(f, &p);
            ev.properties(&props.concat(), 0).unwrap();
            anti_replay(&ev)
        };
        assert_eq!(run(&f, vec![prop("cnch", octets(&[5; 48])), prop("ndom", int(1))]), Ok(()));
        assert_eq!(run(&f, vec![prop("cnch", octets(&[6; 48])), prop("ndom", int(1))]), Err(Fail::Code(e::ESTALE)));
        assert_eq!(run(&f, vec![prop("cnch", octets(&[5; 48]))]), Err(Fail::Code(e::ENOTSUP)));
        // No cryptex1 boot nonce hash, no anti-replay.
        assert_eq!(run(&f, vec![prop("ndom", int(1))]), Ok(()));
        assert!(matches!(run(&f, vec![prop("cnch", octets(&[5; 48])), prop("ndom", int(2))]), Err(Fail::Unmodelled(_))));
        f.nonce = None;
        assert!(matches!(run(&f, vec![prop("cnch", octets(&[5; 48])), prop("ndom", int(1))]), Err(Fail::Unmodelled(_))));
    }

    #[test]
    fn a_tickets_object_and_manifest_properties_are_found_as_libamsupport_finds_them() {
        let d = [7u8; 48];
        let objects = vec![("csos", vec![prop("DGST", octets(&d)), prop("EPRO", boolean(true))]), ("trcs", vec![prop("ESEC", boolean(true))])];
        let t = im4m(vec![prop("ECID", int(0x6890_e970_0eb4_c4bf)), prop("CHIP", int(0x8011))], objects, &[0; 4], &[]);
        assert_eq!(object_property_data(&t, fourcc(b"csos"), fourcc(b"DGST")), Ok(&d[..]));
        assert_eq!(der::integer64(manifest_property(&t, fourcc(b"ECID"), tag::INTEGER).unwrap()), Ok(0x6890_e970_0eb4_c4bf));
        // An object the ticket has no digest in, one it does not have, a
        // property of another type: libDER's end of the sequence and
        // unexpected tag.
        assert_eq!(object_property_data(&t, fourcc(b"trcs"), fourcc(b"DGST")), Err(dr::END_OF_SEQUENCE));
        assert_eq!(object_property_data(&t, fourcc(b"caos"), fourcc(b"DGST")), Err(dr::END_OF_SEQUENCE));
        assert_eq!(object_property_data(&t, fourcc(b"csos"), fourcc(b"EPRO")), Err(dr::UNEXPECTED_TAG));
        // MANB without MANP: the object is not looked for.
        let no_manp = {
            let body = set(&[prop("MANB", set(&[prop("csos", set(&[prop("DGST", octets(&d))]))]))]);
            seq(&[ia5("IM4M"), int(0), body, octets(&[0; 4]), tlv(&[0x30], &[])])
        };
        assert_eq!(object_property_data(&no_manp, fourcc(b"csos"), fourcc(b"DGST")), Err(dr::END_OF_SEQUENCE));
        // Not a manifest: what the restore's 30 00 placeholder was.
        assert!(object_property_data(&[0x30, 0x00], fourcc(b"csos"), fourcc(b"DGST")).is_err());
        let mut long = t.clone();
        long.push(0);
        assert_eq!(object_property_data(&long, fourcc(b"csos"), fourcc(b"DGST")), Err(dr::BUF_OVERFLOW));
    }

    #[test]
    #[ignore = "needs GEX_DARWIN_RESTORE's Firmware/044-76034-038.dmg.root_hash (21H461)"]
    fn the_ipsws_root_hash_is_a_cssy_payload() {
        let dir = std::env::var("GEX_DARWIN_RESTORE").expect("GEX_DARWIN_RESTORE");
        let raw = std::fs::read(format!("{dir}/Firmware/044-76034-038.dmg.root_hash")).unwrap();
        let p = init_as_payload(&raw).unwrap();
        assert!(p.data.is_some_and(|d| !d.is_empty()));
        let s = execute(fourcc(b"cssy"), &raw, b"placeholder, not a ticket", &device());
        assert_eq!(s, Outcome::Status(e::EFTYPE));
    }
}
