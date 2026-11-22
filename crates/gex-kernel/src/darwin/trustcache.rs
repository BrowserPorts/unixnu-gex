//! Trust caches: the cdhashes of the code the system trusts as platform
//! code (`bsd/kern/kern_trustcache.c`, and libTrustCache as AMFI links it).
//!
//! The boot loader hands the kernel a bundle at `/chosen/memory-map/
//! TrustCache`: a count, each module's offset from the bundle's start, and
//! the modules. Module 0 is the static trust cache; on a release kernel
//! the others are engineering modules, skipped. A module is a version, a
//! UUID, a count and its entries: a cdhash (v0), with its hash type and
//! flags (v1), and a launch-constraint category (v2), sorted by cdhash.

use std::sync::OnceLock;

use super::share::{self, Remote};

/// A trust cache entry as a query finds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub hash_type: u8,
    pub flags: u8,
    /// The launch-constraint category (v2 modules), none in an older one.
    pub category: Option<u8>,
}

/// One loaded module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Module {
    pub version: u32,
    pub uuid: [u8; 16],
    entries: Vec<u8>,
}

/// Why a module or a bundle does not load (libTrustCache's errors, and
/// the kernel's panics for the bundle).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Shorter than the header, or than its entries.
    Truncated,
    /// A version other than 0, 1 and 2.
    Version(u32),
    /// The bundle's offsets or count are out of its length.
    Bundle(String),
}

const HEADER: usize = 0x18;

fn entry_size(version: u32) -> Option<usize> {
    match version {
        0 => Some(20),
        1 => Some(22),
        2 => Some(24),
        _ => None,
    }
}

impl Module {
    /// libTrustCache's module check (`0x...bb8f8`, then the version's,
    /// 0x...bb59c, 0x...bb67c, 0x...bb7a4), in its order: room for the
    /// version, a known version, room for the header, room for its entries
    /// (bytes past them are allowed; order, duplicates and the entries'
    /// fields are not checked).
    pub fn load(b: &[u8]) -> Result<Module, Error> {
        if b.len() < 4 {
            return Err(Error::Truncated);
        }
        let version = u32::from_le_bytes(b[0..4].try_into().unwrap());
        let size = entry_size(version).ok_or(Error::Version(version))?;
        if b.len() < HEADER {
            return Err(Error::Truncated);
        }
        let count = u32::from_le_bytes(b[0x14..0x18].try_into().unwrap()) as usize;
        let end = count.checked_mul(size).and_then(|n| n.checked_add(HEADER)).ok_or(Error::Truncated)?;
        if end > b.len() {
            return Err(Error::Truncated);
        }
        Ok(Module { version, uuid: b[4..20].try_into().unwrap(), entries: b[HEADER..end].to_vec() })
    }

    /// The module as [`Module::load`] reads it: its header and entries.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(HEADER + self.entries.len());
        b.extend_from_slice(&self.version.to_le_bytes());
        b.extend_from_slice(&self.uuid);
        b.extend_from_slice(&(self.count() as u32).to_le_bytes());
        b.extend_from_slice(&self.entries);
        b
    }

    fn entry(&self, i: usize) -> &[u8] {
        let size = entry_size(self.version).unwrap();
        &self.entries[i * size..(i + 1) * size]
    }

    fn count(&self) -> usize {
        self.entries.len() / entry_size(self.version).unwrap()
    }

    /// The entry for `cdhash`, on the 20 bytes of the cdhash only: the
    /// first of a v0 module's (a scan, 0x...bb5ec); a later module's by
    /// libTrustCache's binary search (0x...bb6d0, 0x...bb7f8), whose probes
    /// an unsorted module decides: the low and high indices inclusive,
    /// 32-bit, the probe their sum halved, ending where the low passes the
    /// high or a probe at index 0 is above the cdhash.
    pub fn lookup(&self, cdhash: &[u8; 20]) -> Option<Entry> {
        let count = self.count();
        if count == 0 {
            return None;
        }
        let at = if self.version == 0 {
            (0..count).find(|&i| &self.entry(i)[..20] == cdhash)?
        } else {
            let (mut lo, mut hi) = (0u32, count as u32 - 1);
            loop {
                let sum = hi.wrapping_add(lo);
                let mid = sum >> 1;
                match self.entry(mid as usize)[..20].cmp(cdhash) {
                    std::cmp::Ordering::Equal => break mid as usize,
                    std::cmp::Ordering::Less => lo = mid + 1,
                    std::cmp::Ordering::Greater => {
                        if sum < 2 {
                            return None;
                        }
                        hi = mid - 1;
                    }
                }
                if lo > hi {
                    return None;
                }
            }
        };
        let e = self.entry(at);
        Some(match self.version {
            0 => Entry { hash_type: 0, flags: 0, category: None },
            1 => Entry { hash_type: e[20], flags: e[21], category: None },
            _ => Entry { hash_type: e[20], flags: e[21], category: Some(e[22]) },
        })
    }
}

/// `load_static_trust_cache`: the bundle's module 0 as the static trust
/// cache (its failure is the kernel's panic); the other modules are
/// engineering modules, which a release kernel skips.
pub fn load_bundle(b: &[u8]) -> Result<Module, Error> {
    let bad = |what: &str| Error::Bundle(what.into());
    let num = b.get(0..4).map(|s| u32::from_le_bytes(s.try_into().unwrap())).ok_or(bad("no module count"))? as usize;
    if num == 0 {
        return Err(bad("trust cache segment isn't zero but no trust caches available"));
    }
    if b.len() < 4 + 4 * num {
        return Err(bad("trust cache segment length smaller than required"));
    }
    let off = u32::from_le_bytes(b[4..8].try_into().unwrap()) as usize;
    if off >= b.len() {
        return Err(bad("trust cache module begins after segment ends"));
    }
    Module::load(&b[off..])
}

/// The static trust cache the system booted with; none when the boot gave
/// no bundle ("no external trust caches found").
static STATIC: OnceLock<Option<Module>> = OnceLock::new();

/// Set the boot's static trust cache, once: the system boots once. Where
/// the global kernel holds the system's state ([`share`]), a process of the
/// page that boots after the first finds the system's set, and booting with
/// another is an error.
pub fn set_static(m: Option<Module>) -> Result<(), String> {
    let same = match share::remote() {
        Some(r) => set_static_through(r, m.as_ref()),
        None => set_static_here(m),
    };
    if same {
        Ok(())
    } else {
        Err("its static trust cache differs from the one the system booted with".into())
    }
}

/// Whether the static trust cache is `m`, set now if it was not.
fn set_static_here(m: Option<Module>) -> bool {
    STATIC.get_or_init(|| m.clone()) == &m
}

fn set_static_through(r: Remote, m: Option<&Module>) -> bool {
    let mut o = [0u8; 1];
    share::call(r, share::op::TC_SET_STATIC, &m.map_or_else(Vec::new, Module::to_bytes), &mut o);
    o[0] != 0
}

/// The trust caches loaded since boot, the last loaded first (the
/// runtime's list, which an add, 0x...bbb34, heads): a boot cryptex's
/// (`kTCTypeCryptex1BootOS`), which libignition in launchd's dyld loads
/// through AMFI after checking the cryptex's manifest.
static LOADED: std::sync::Mutex<Vec<Module>> = std::sync::Mutex::new(Vec::new());

/// `checkRuntimeForUUID` (0x...bbb84, 0x...bbf48): whether the static trust
/// cache or a loaded one has UUID `uuid`.
pub fn runtime_has_uuid(uuid: &[u8; 16]) -> bool {
    match share::remote() {
        Some(r) => {
            let mut o = [0u8; 1];
            share::call(r, share::op::TC_HAS_UUID, uuid, &mut o);
            o[0] != 0
        }
        None => runtime_has_uuid_here(uuid),
    }
}

fn runtime_has_uuid_here(uuid: &[u8; 16]) -> bool {
    STATIC.get().and_then(Option::as_ref).is_some_and(|m| &m.uuid == uuid) || LOADED.lock().unwrap_or_else(|e| e.into_inner()).iter().any(|m| &m.uuid == uuid)
}

/// A trust cache added to the runtime, at the head of the loaded ones:
/// whether it was (none whose UUID the runtime has is).
fn add(m: Module) -> bool {
    let mut l = LOADED.lock().unwrap_or_else(|e| e.into_inner());
    if STATIC.get().and_then(Option::as_ref).is_some_and(|s| s.uuid == m.uuid) || l.iter().any(|x| x.uuid == m.uuid) {
        return false;
    }
    l.insert(0, m);
    true
}

/// libTrustCache's loadable trust cache types (`TCType_t`): 0 to 2 are the
/// static, engineering and legacy ones, which no load names; `kTCTypeTotal`
/// is 0x19.
pub mod tc_type {
    pub const ENGINEERING_ROOT: u8 = 0x03;
    pub const CRYPTEX1_BOOT_OS: u8 = 0x0d;
    pub const CRYPTEX1_BOOT_APP: u8 = 0x0e;
    pub const CRYPTEX1_PREBOOT_APP: u8 = 0x0f;
    pub const TOTAL: u8 = 0x19;
}

/// The entitlement a trust cache's loader needs
/// (`load_trust_cache_with_type`), whose value must allow the type's.
pub const LOAD_ENTITLEMENT: &str = "com.apple.private.pmap.load-trust-cache";

/// `TCTypeConfig` (AMFI's 0xfffffff006cfdc48, the kernel's
/// 0xfffffff0071524e0, 0x28 bytes a type) of types 3 to 0x18: the 4CC of
/// the type's IM4P and the value of [`LOAD_ENTITLEMENT`] it asks for.
const CONFIG: [(&[u8; 4], &str); (tc_type::TOTAL - 3) as usize] = [
    (b"dtrs", "personalized.engineering-root"),
    (b"ltrs", "personalized.trust-cache"),
    (b"ltrs", "personalized.pdi"),
    (b"trdv", "personalized.ddi"),
    (b"ltrs", "personalized.ddi"),
    (b"ltrs", "personalized.cryptex-research"),
    (b"ltrs", "personalized.ephemeral-cryptex"),
    (b"ltrs", "global.ota-update-brain"),
    (b"ltrs", "global.install-assistant"),
    (b"trbb", "global.bootability-brain"),
    (b"trcs", "cryptex1.boot.os"),
    (b"trca", "cryptex1.boot.app"),
    (b"trca", "cryptex1.preboot.app"),
    (b"ltrs", "global.pdi"),
    (b"trab", "personalized.mobile-asset-brain"),
    (b"trca", "cryptex1.safari-downlevel"),
    (b"trcs", "cryptex1.preboot.os"),
    (b"ltrs", "personalized.supplemental-persistent"),
    (b"ltrs", "personalized.supplemental-ephemeral"),
    (b"gtcd", "cryptex1.generic"),
    (b"gtcd", "cryptex1.generic.supplemental"),
    (b"trab", "personalized.mobile-asset-brain"),
];

/// A loadable type's IM4P 4CC and entitlement value.
pub fn config(ty: u8) -> Option<(u32, &'static str)> {
    let (cc, value) = CONFIG.get(usize::from(ty).checked_sub(3)?)?;
    Some((u32::from_be_bytes(**cc), value))
}

/// `kern_return_t` values a trust cache load returns.
pub mod kr {
    pub const SUCCESS: i32 = 0;
    pub const INVALID_ARGUMENT: i32 = 4;
    pub const FAILURE: i32 = 5;
    pub const ALREADY_IN_SET: i32 = 11;
    pub const NOT_SUPPORTED: i32 = 46;
    pub const DENIED: i32 = 53;
    pub const NOT_FOUND: i32 = 56;
}

/// AMFI's `_load_trust_cache`'s errno for its load's `kern_return_t`
/// (0xfffffff005ab7b0c..0xfffffff005ab7ba8, the table at
/// 0xfffffff0052e5e4e): success 0, INVALID_ARGUMENT EINVAL, FAILURE
/// ECANCELED, RESOURCE_SHORTAGE ENOMEM, NOT_SUPPORTED ENOTSUP, NOT_FOUND
/// ENOENT, anything else EPERM.
pub fn amfi_errno(k: i32) -> i32 {
    match k {
        kr::SUCCESS => 0,
        kr::INVALID_ARGUMENT => 22,
        kr::FAILURE => 89,
        6 => 12,
        kr::NOT_SUPPORTED => 45,
        kr::NOT_FOUND => 2,
        _ => 1,
    }
}

/// `load_trust_cache_with_type`'s check of the type (bsd/kern/
/// kern_trustcache.c 821-826; 0xfffffff007662e88): the static, engineering
/// and legacy types, and those past `kTCTypeTotal`, are INVALID_ARGUMENT.
pub fn check_type(ty: u8) -> Result<(), i32> {
    if (3..tc_type::TOTAL).contains(&ty) {
        Ok(())
    } else {
        Err(kr::INVALID_ARGUMENT)
    }
}

/// Whether a boot cryptex trust cache of type `ty` has been loaded
/// (`boot_os_tc_loaded`, `boot_app_tc_loaded`): a second one is DENIED.
static BOOT_OS_LOADED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static BOOT_APP_LOADED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn boot_flag(ty: u8) -> Option<&'static std::sync::atomic::AtomicBool> {
    match ty {
        tc_type::CRYPTEX1_BOOT_OS => Some(&BOOT_OS_LOADED),
        tc_type::CRYPTEX1_BOOT_APP => Some(&BOOT_APP_LOADED),
        _ => None,
    }
}

/// `load_trust_cache_with_type` (kern_trustcache.c 841-846): a boot
/// cryptex type loaded already.
pub fn boot_type_loaded(ty: u8) -> bool {
    match share::remote() {
        Some(r) => {
            let mut o = [0u8; 1];
            share::call(r, share::op::TC_BOOT_LOADED, &[ty], &mut o);
            o[0] != 0
        }
        None => boot_type_loaded_here(ty),
    }
}

fn boot_type_loaded_here(ty: u8) -> bool {
    boot_flag(ty).is_some_and(|f| f.load(std::sync::atomic::Ordering::Acquire))
}

/// `load_trust_cache_with_type` after a load of type `ty` (869-877).
pub fn mark_loaded(ty: u8) {
    match share::remote() {
        Some(r) => share::call(r, share::op::TC_MARK_LOADED, &[ty], &mut []),
        None => mark_loaded_here(ty),
    }
}

fn mark_loaded_here(ty: u8) {
    if let Some(f) = boot_flag(ty) {
        f.store(true, std::sync::atomic::Ordering::Release);
    }
}

/// Why `trustCacheLoad` refuses a cache (its `TCReturn`): the duplicate
/// (`kTCReturnDuplicate`, 0x23, the kernel's KERN_ALREADY_IN_SET), or any
/// other error (the kernel's KERN_FAILURE).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoadError {
    Duplicate,
    Failed(String),
}

/// `trustCacheLoad` (0x...bc218) of a cache of type `ty` past its Image4
/// evaluation (0x...bb060), whose execution callback (0x...bb2f8) left
/// `authenticated`: the authenticated payload, or the evaluation's errno.
/// In its order: an evaluation's error; an empty module; the module check
/// ([`Module::load`]); its UUID in the runtime (the duplicate); the type
/// (an engineering root only where the runtime allows engineering caches,
/// which a release kernel's does not; 4 to 0x18 otherwise); then the
/// cache added to the runtime ([`add`]).
pub fn load_module(ty: u8, authenticated: Result<Vec<u8>, i32>) -> Result<(), LoadError> {
    let data = authenticated.map_err(|e| LoadError::Failed(format!("the Image4 evaluation failed with {e}")))?;
    match share::remote() {
        Some(r) => load_through(r, ty, &data),
        None => load_here(ty, data),
    }
}

/// [`load_module`]'s steps past the evaluation, on the system's runtime.
fn load_here(ty: u8, data: Vec<u8>) -> Result<(), LoadError> {
    if data.is_empty() {
        return Err(LoadError::Failed("an empty module".into()));
    }
    let m = Module::load(&data).map_err(|e| LoadError::Failed(format!("the module: {e:?}")))?;
    if runtime_has_uuid(&m.uuid) {
        return Err(LoadError::Duplicate);
    }
    if !(4..tc_type::TOTAL).contains(&ty) {
        return Err(LoadError::Failed(format!("type {ty:#x} (engineering caches not allowed)")));
    }
    if !add(m) {
        return Err(LoadError::Duplicate);
    }
    Ok(())
}

/// AMFI's `trustCacheIsDuplicateImg4` (0xfffffff005aad3a4): the module of
/// object `b` (0x...bbbe0: its IM4P's data, `Img4DecodeInitAsPayload`
/// 0x...bd088, the same decoder as AppleImage4's, else an IMG4's,
/// `Img4DecodeInit` 0x...bcfa0; then [`Module::load`]) has a UUID the
/// runtime has (`check_trust_cache_runtime_for_uuid`). An object no module
/// can be taken from is no duplicate. An IMG4 container's payload is not
/// read here: an object that can be one (a SEQUENCE spanning it whose
/// first item is the IA5String "IMG4") is `Err`, to be reported.
pub fn is_duplicate_img4(b: &[u8]) -> Result<bool, String> {
    use super::image4::{der, tag};
    let data = match super::image4::init_as_payload(b) {
        Ok(p) => p.data.unwrap_or(&[]),
        Err(_) => {
            let img4 = der::decode_item(b).is_ok_and(|it| {
                it.tag == tag::SEQUENCE && it.whole.len() == b.len() && der::Seq::of(it.content).next().is_ok_and(|f| f.tag == tag::IA5_STRING && f.content == b"IMG4")
            });
            if img4 {
                return Err("Img4DecodeInit (0xfffffff005abcfa0) of an IMG4 container's payload, for trustCacheIsDuplicateImg4".into());
            }
            return Ok(false);
        }
    };
    Ok(Module::load(data).is_ok_and(|m| runtime_has_uuid(&m.uuid)))
}

fn load_through(r: Remote, ty: u8, data: &[u8]) -> Result<(), LoadError> {
    let mut req = Vec::with_capacity(1 + data.len());
    req.push(ty);
    req.extend_from_slice(data);
    let mut o = [0u8; LOAD_ANSWER];
    let n = share::call_upto(r, share::op::TC_LOAD, &req, &mut o);
    match &o[..n] {
        [0] => Ok(()),
        [1] => Err(LoadError::Duplicate),
        [2, why @ ..] => Err(LoadError::Failed(String::from_utf8_lossy(why).into_owned())),
        _ => panic!("gex: the global kernel's answer to a trust cache load: {:?}", &o[..n]),
    }
}

/// The longest answer to a load through the global kernel: its outcome and
/// why it failed (a few words; a longer one is the channel's error).
const LOAD_ANSWER: usize = 512;

/// A trust cache query's type (libTrustCache's `TCQueryType_t`, as AMFI
/// uses it: its platform test, 0x...ab3e10, asks 1 and then, where loaded
/// caches count, 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Query {
    /// The static trust cache (1).
    Static,
    /// The loaded ones (2).
    Loadable,
}

/// `query_trust_cache` of one type: its entry for `cdhash`.
pub fn query(q: Query, cdhash: &[u8; 20]) -> Option<Entry> {
    match share::remote() {
        Some(r) => query_through(r, q, cdhash),
        None => query_here(q, cdhash),
    }
}

fn query_here(q: Query, cdhash: &[u8; 20]) -> Option<Entry> {
    match q {
        Query::Static => STATIC.get().and_then(Option::as_ref).and_then(|m| m.lookup(cdhash)),
        Query::Loadable => LOADED.lock().unwrap_or_else(|e| e.into_inner()).iter().find_map(|m| m.lookup(cdhash)),
    }
}

impl Query {
    /// Its `TCQueryType_t`.
    fn number(self) -> u8 {
        match self {
            Query::Static => 1,
            Query::Loadable => 2,
        }
    }

    fn of(n: u8) -> Option<Query> {
        match n {
            1 => Some(Query::Static),
            2 => Some(Query::Loadable),
            _ => None,
        }
    }
}

/// An entry found, or none, as 5 bytes: found, hash type, flags, whether
/// there is a category, the category.
fn entry_bytes(e: Option<Entry>) -> [u8; 5] {
    match e {
        None => [0; 5],
        Some(e) => [1, e.hash_type, e.flags, u8::from(e.category.is_some()), e.category.unwrap_or(0)],
    }
}

fn entry_of(b: [u8; 5]) -> Option<Entry> {
    (b[0] != 0).then(|| Entry { hash_type: b[1], flags: b[2], category: (b[3] != 0).then_some(b[4]) })
}

fn query_through(r: Remote, q: Query, cdhash: &[u8; 20]) -> Option<Entry> {
    let mut req = [0u8; 21];
    req[0] = q.number();
    req[1..].copy_from_slice(cdhash);
    let mut o = [0u8; 5];
    share::call(r, share::op::TC_QUERY, &req, &mut o);
    entry_of(o)
}

/// A trust cache call the global kernel's channel carried ([`share::serve`]),
/// answered on this kernel's runtime: `None` for a call that is not one of
/// these.
pub(crate) fn serve(op: u32, req: &[u8], out: &mut [u8]) -> Option<i64> {
    const EINVAL: i64 = 22;
    const E2BIG: i64 = 7;
    let answer = |out: &mut [u8], b: &[u8]| -> i64 {
        if b.len() > out.len() {
            return -E2BIG;
        }
        out[..b.len()].copy_from_slice(b);
        b.len() as i64
    };
    Some(match op {
        share::op::TC_SET_STATIC => {
            let m = if req.is_empty() {
                None
            } else {
                match Module::load(req) {
                    Ok(m) => Some(m),
                    Err(_) => return Some(-EINVAL),
                }
            };
            answer(out, &[u8::from(set_static_here(m))])
        }
        share::op::TC_QUERY => {
            let (Some(q), Ok(h)) = (req.first().and_then(|&n| Query::of(n)), <[u8; 20]>::try_from(req.get(1..).unwrap_or(&[]))) else { return Some(-EINVAL) };
            answer(out, &entry_bytes(query_here(q, &h)))
        }
        share::op::TC_HAS_UUID => {
            let Ok(u) = <[u8; 16]>::try_from(req) else { return Some(-EINVAL) };
            answer(out, &[u8::from(runtime_has_uuid_here(&u))])
        }
        share::op::TC_LOAD => {
            let Some((&ty, data)) = req.split_first() else { return Some(-EINVAL) };
            match load_here(ty, data.to_vec()) {
                Ok(()) => answer(out, &[0]),
                Err(LoadError::Duplicate) => answer(out, &[1]),
                Err(LoadError::Failed(why)) => {
                    let mut b = vec![2];
                    b.extend_from_slice(why.as_bytes());
                    answer(out, &b)
                }
            }
        }
        share::op::TC_BOOT_LOADED => {
            let [ty] = req else { return Some(-EINVAL) };
            answer(out, &[u8::from(boot_type_loaded_here(*ty))])
        }
        share::op::TC_MARK_LOADED => {
            let [ty] = req else { return Some(-EINVAL) };
            mark_loaded_here(*ty);
            0
        }
        _ => return None,
    })
}

/// AMFI's platform test (`0x...ab3e10`): a query of the static trust cache,
/// then of the loaded ones.
pub fn platform(cdhash: &[u8; 20]) -> Option<Entry> {
    query(Query::Static, cdhash).or_else(|| query(Query::Loadable, cdhash))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(version: u32, hashes: &[[u8; 20]]) -> Vec<u8> {
        let mut b = version.to_le_bytes().to_vec();
        b.extend_from_slice(&[7u8; 16]);
        b.extend_from_slice(&(hashes.len() as u32).to_le_bytes());
        for (i, h) in hashes.iter().enumerate() {
            b.extend_from_slice(h);
            if version > 0 {
                b.extend_from_slice(&[2, i as u8]);
            }
            if version > 1 {
                b.extend_from_slice(&[9, 0]);
            }
        }
        b
    }

    #[test]
    fn a_module_finds_its_cdhashes() {
        let hs: Vec<[u8; 20]> = (1..=9u8).map(|i| [i * 10; 20]).collect();
        for v in 0..=2 {
            let m = Module::load(&module(v, &hs)).unwrap();
            for (i, h) in hs.iter().enumerate() {
                let e = m.lookup(h).unwrap();
                assert_eq!(e.flags, if v > 0 { i as u8 } else { 0 });
                assert_eq!(e.category, (v == 2).then_some(9));
            }
            assert_eq!(m.lookup(&[15; 20]), None);
        }
        assert_eq!(Module::load(&module(3, &hs)), Err(Error::Version(3)));
        let b = module(2, &hs);
        assert_eq!(Module::load(&b[..b.len() - 1]), Err(Error::Truncated));
    }

    /// A v2 module of UUID `uuid` (and the given entries, in their order).
    fn module_of(uuid: [u8; 16], hashes: &[[u8; 20]]) -> Vec<u8> {
        let mut b = module(2, hashes);
        b[4..20].copy_from_slice(&uuid);
        b
    }

    /// DER of `tag` around `content`.
    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut b = vec![tag];
        match content.len() {
            n if n < 0x80 => b.push(n as u8),
            n if n < 0x100 => b.extend_from_slice(&[0x81, n as u8]),
            n => b.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]),
        }
        b.extend_from_slice(content);
        b
    }

    /// An IM4P of type `kind` around `payload`.
    fn im4p(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut c = der(0x16, b"IM4P");
        c.extend(der(0x16, kind));
        c.extend(der(0x16, b"1"));
        c.extend(der(0x04, payload));
        der(0x30, &c)
    }

    /// An unsorted module answers as libTrustCache's probes find it: the
    /// low and high indices inclusive, the probe their halved sum.
    #[test]
    fn a_lookup_probes_as_libtrustcache_does() {
        // Four entries: the first probe is index 1 ((0 + 3) / 2), not 2.
        let hs = [[0x10; 20], [0x50; 20], [0x20; 20], [0x40; 20]];
        let m = Module::load(&module(1, &hs)).unwrap();
        assert!(m.lookup(&[0x50; 20]).is_some());
        // 0x40 is past the probe at 1 (0x50) the other way: not found.
        assert!(m.lookup(&[0x40; 20]).is_none());
        // 0x20: below 0x50, then the probe at 0 (0x10), then none left.
        assert!(m.lookup(&[0x20; 20]).is_none());
        assert!(m.lookup(&[0x10; 20]).is_some());
        // Below the probe at index 0: the search ends there.
        assert!(m.lookup(&[0x05; 20]).is_none());
        // A v0 module is scanned: any order, the first match.
        let m = Module::load(&module(0, &hs)).unwrap();
        assert!(hs.iter().all(|h| m.lookup(h).is_some()));
        // An empty module has nothing.
        assert!(Module::load(&module(2, &[])).unwrap().lookup(&[0; 20]).is_none());
    }

    /// The check's order: the version needs 4 bytes, then is checked before
    /// the header's length.
    #[test]
    fn the_module_check_reads_the_version_first() {
        assert_eq!(Module::load(&[2, 0, 0]), Err(Error::Truncated));
        assert_eq!(Module::load(&[9, 0, 0, 0]), Err(Error::Version(9)));
        assert_eq!(Module::load(&[2, 0, 0, 0, 0]), Err(Error::Truncated));
        let b = module(2, &[[1; 20]]);
        assert!(Module::load(&b).is_ok());
        let mut extra = b.clone();
        extra.extend_from_slice(&[0xee; 5]);
        assert!(Module::load(&extra).is_ok(), "bytes past the entries are allowed");
    }

    /// Types 3 to 0x18 load, each with its IM4P's 4CC and the value its
    /// loader's entitlement must allow; AMFI's errno for each result.
    #[test]
    fn types_name_their_payload_and_entitlement() {
        assert_eq!(config(tc_type::CRYPTEX1_BOOT_OS), Some((u32::from_be_bytes(*b"trcs"), "cryptex1.boot.os")));
        assert_eq!(config(tc_type::CRYPTEX1_BOOT_APP), Some((u32::from_be_bytes(*b"trca"), "cryptex1.boot.app")));
        assert_eq!(config(tc_type::ENGINEERING_ROOT), Some((u32::from_be_bytes(*b"dtrs"), "personalized.engineering-root")));
        assert_eq!(config(0x18), Some((u32::from_be_bytes(*b"trab"), "personalized.mobile-asset-brain")));
        assert_eq!(config(2), None);
        assert_eq!(config(0x19), None);
        for t in 0..=255u8 {
            assert_eq!(check_type(t).is_ok(), (3..=0x18).contains(&t), "type {t:#x}");
        }
        assert_eq!(check_type(0), Err(kr::INVALID_ARGUMENT));
        assert_eq!(amfi_errno(kr::SUCCESS), 0);
        assert_eq!(amfi_errno(kr::INVALID_ARGUMENT), 22);
        assert_eq!(amfi_errno(kr::FAILURE), 89);
        assert_eq!(amfi_errno(6), 12);
        assert_eq!(amfi_errno(kr::NOT_SUPPORTED), 45);
        assert_eq!(amfi_errno(kr::DENIED), 1);
        assert_eq!(amfi_errno(kr::NOT_FOUND), 2);
        assert_eq!(amfi_errno(kr::ALREADY_IN_SET), 1);
        assert_eq!(amfi_errno(7), 1);
    }

    /// The load's order: the evaluation's result, the module, the
    /// duplicate, the type; a loaded cache heads the queries.
    #[test]
    fn a_loaded_module_is_queried_first() {
        let (a, b) = ([0xa1; 16], [0xa2; 16]);
        let h = [0xd3; 20];
        assert!(matches!(load_module(0x0d, Err(79)), Err(LoadError::Failed(_))));
        assert!(matches!(load_module(0x0d, Ok(Vec::new())), Err(LoadError::Failed(_))));
        assert!(matches!(load_module(0x0d, Ok(vec![7, 0, 0, 0])), Err(LoadError::Failed(_))));
        // An engineering root, where engineering caches are not allowed.
        assert!(matches!(load_module(tc_type::ENGINEERING_ROOT, Ok(module_of([0xa0; 16], &[h]))), Err(LoadError::Failed(_))));
        assert!(!runtime_has_uuid(&[0xa0; 16]));
        // Two caches with the same cdhash: the last loaded answers.
        let mut first = module_of(a, &[h]);
        first[0x18 + 21] = 1;
        let mut second = module_of(b, &[h]);
        second[0x18 + 21] = 2;
        assert_eq!(load_module(0x0d, Ok(first.clone())), Ok(()));
        assert_eq!(query(Query::Loadable, &h).map(|e| e.flags), Some(1));
        assert_eq!(load_module(0x0e, Ok(second)), Ok(()));
        assert_eq!(query(Query::Loadable, &h).map(|e| e.flags), Some(2));
        assert_eq!(platform(&h).map(|e| e.flags), Some(2));
        // The same UUID again is the duplicate, whatever its type.
        assert_eq!(load_module(0x0f, Ok(first.clone())), Err(LoadError::Duplicate));
        // AMFI finds it first, from the IM4P alone.
        assert_eq!(is_duplicate_img4(&im4p(b"trcs", &first)), Ok(true));
        assert_eq!(is_duplicate_img4(&im4p(b"trcs", &module_of([0xa3; 16], &[h]))), Ok(false));
        // Not an IM4P and no IMG4: no module, no duplicate.
        assert_eq!(is_duplicate_img4(b"not der"), Ok(false));
        assert_eq!(is_duplicate_img4(&im4p(b"trcs", &[1, 2, 3])), Ok(false));
        // What may be an IMG4 container is reported.
        let mut c = der(0x16, b"IMG4");
        c.extend(im4p(b"trcs", &first));
        assert!(is_duplicate_img4(&der(0x30, &c)).is_err());
    }

    /// A second Cryptex1 boot cache of a type is refused; other types may
    /// load again.
    #[test]
    fn a_boot_cryptex_type_loads_once() {
        assert!(!boot_type_loaded(tc_type::CRYPTEX1_BOOT_APP));
        mark_loaded(tc_type::CRYPTEX1_BOOT_APP);
        assert!(boot_type_loaded(tc_type::CRYPTEX1_BOOT_APP));
        mark_loaded(tc_type::CRYPTEX1_PREBOOT_APP);
        assert!(!boot_type_loaded(tc_type::CRYPTEX1_PREBOOT_APP));
    }

    /// The IPSW's Cryptex1 trust caches (044-76034-038.dmg.trustcache for
    /// the SystemOS, 044-75188-038.dmg.trustcache for the AppOS): each an
    /// IM4P whose data, as AppleImage4 decodes it, is a version 2 module
    /// libTrustCache's check accepts, every entry read and found by the
    /// search.
    #[test]
    #[ignore = "needs GEX_DARWIN_RESTORE's Firmware/*.dmg.trustcache (21H461)"]
    fn the_ipsws_cryptex_trust_caches_load() {
        let dir = std::env::var("GEX_DARWIN_RESTORE").expect("GEX_DARWIN_RESTORE");
        for (file, kind) in [("044-76034-038.dmg.trustcache", b"trcs"), ("044-75188-038.dmg.trustcache", b"trca")] {
            let b = std::fs::read(format!("{dir}/Firmware/{file}")).unwrap();
            let p = super::super::image4::init_as_payload(&b).unwrap();
            let data = p.data.unwrap();
            assert_eq!(&b[12..16], kind);
            let m = Module::load(data).unwrap();
            assert_eq!(m.version, 2, "{file}");
            let n = u32::from_le_bytes(data[0x14..0x18].try_into().unwrap()) as usize;
            assert_eq!(m.count(), n);
            assert_eq!(data.len(), 0x18 + 24 * n, "{file}: no bytes past the entries");
            for i in 0..n {
                let e = m.entry(i);
                let h: [u8; 20] = e[..20].try_into().unwrap();
                if i > 0 {
                    assert!(m.entry(i - 1)[..20] < e[..20], "{file}: sorted, no duplicates");
                }
                let got = m.lookup(&h).unwrap();
                assert_eq!(got, Entry { hash_type: e[20], flags: e[21], category: Some(e[22]) });
                assert_eq!(got.hash_type, 2, "{file}: SHA-256 cdhashes");
            }
            crate::darwin_say!("{file}: {n} entries, uuid {:02x?}", m.uuid);
        }
    }

    /// Each call through the global kernel's channel answers as the
    /// serving kernel's runtime does: the boot's static cache set once and
    /// then only matched, queries, a load and its duplicate, a boot type's
    /// mark.
    #[test]
    fn the_runtime_through_the_channel_is_the_serving_kernels() {
        let r = Remote { call: share::serve, park: super::share::park_by_asking };
        let h = [0x5c; 20];
        let st = Module::load(&module_of([0x5c; 16], &[h])).unwrap();
        assert_eq!(Module::load(&st.to_bytes()), Ok(st.clone()));
        assert!(set_static_through(r, Some(&st)));
        assert!(set_static_through(r, Some(&st)));
        assert!(!set_static_through(r, None));
        assert_eq!(query_through(r, Query::Static, &h), query_here(Query::Static, &h));
        assert!(query_through(r, Query::Static, &h).is_some());
        assert_eq!(query_through(r, Query::Loadable, &[0x5d; 20]), None);
        let mut o = [0u8; 1];
        share::call(r, share::op::TC_HAS_UUID, &[0x5c; 16], &mut o);
        assert_eq!(o, [1]);
        let l = module_of([0x5e; 16], &[[0x5e; 20]]);
        assert_eq!(load_through(r, 0x0d, &l), Ok(()));
        assert_eq!(query_through(r, Query::Loadable, &[0x5e; 20]).map(|e| e.flags), Some(0));
        assert_eq!(load_through(r, 0x0d, &l), Err(LoadError::Duplicate));
        assert!(matches!(load_through(r, 0x0d, &[]), Err(LoadError::Failed(w)) if w == "an empty module"));
        let mut b = [0u8; 1];
        share::call(r, share::op::TC_BOOT_LOADED, &[0x0f], &mut b);
        assert_eq!(b, [0]);
        share::call(r, share::op::TC_MARK_LOADED, &[0x0f], &mut []);
        assert_eq!(serve(share::op::TC_QUERY, &[3; 21], &mut [0; 5]), Some(-22));
        assert_eq!(serve(1, &[], &mut []), None);
    }

    #[test]
    fn a_bundles_first_module_is_the_static_cache() {
        let m = module(2, &[[1; 20]]);
        let mut b = 2u32.to_le_bytes().to_vec();
        b.extend_from_slice(&12u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&m);
        assert!(load_bundle(&b).unwrap().lookup(&[1; 20]).is_some());
        assert!(load_bundle(&0u32.to_le_bytes()).is_err());
    }
}
