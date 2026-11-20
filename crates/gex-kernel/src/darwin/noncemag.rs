//! AppleImage4's nonce magazine (AppleImage4 257.140.2 of iPad7,1 21H461):
//! the nonce slots of its nonce domains, which it keeps in the device's
//! NVRAM, rolls when it boots, and changes for the callers its traps serve
//! (libimage4's `img4_nonce_domain_*`, through `AppleImage4UserClient`).
//!
//! The magazine (made at 0xfffffff005a9e398 by the el2 expert's init,
//! 0xfffffff005a984bc) holds the eight slots of 0xfffffff007ae59c0 in that
//! order ([`DOMAINS`]); each slot is the domain's record and 37 bytes of
//! data ([`nonce::Slot`]). Its storage is the NVRAM, by the expert's
//! operations (0xfffffff006cf84f0: read +0x90, 0xfffffff005a9957c, a
//! property of the `/options` entry, `OSData` only; write +0x98,
//! 0xfffffff005a92c60, `IODTNVRAM::setProperties` of `{key: OSData}` or
//! `IONVRAM-DELETE-PROPERTY`; sync +0xa0, 0xfffffff005a92f70), with keys
//! of the prefix [`PREFIX`] (0xfffffff005a9e424) and a name: each slot's
//! its record's four characters (+0xc), the magazine's own data
//! [`MAGAZINE`] (its +4, `"zine"`, as the "magazine pseudo-descriptor"
//! 0xfffffff006cf4110 names it). The trap's work runs on a kernel thread
//! (0xfffffff005a95050: `kernel_thread_start`), so the NVRAM sees the
//! kernel's task, which the `krn.` names need.
//!
//! The i/o strategy (0xfffffff006cf9098, five records {name, flags, read,
//! write, raw write}) is chosen at the boot (0xfffffff005a98710) from what
//! the magazine data read gives and from `/chosen`'s `boot-command`,
//! which iBoot adds (iBoot-10151.140.19 of J120, 0x1800ccc44: the boot
//! routine's argument 0, 1 or 2 as 1, 3 or 7; `fsboot` 0x1800b0b2c passes
//! 0, `bootx` 0x1800b0e74 2): [`boot_command`].

use super::image4::{nonce::{self, Slot}, Fail};

/// The slots' and the magazine's keys' prefix: the system namespace and
/// the kernel-only `krn.` names.
pub const PREFIX: &str = "40A0DDD2-77F8-4392-B4A3-1E7304206516:krn.";
/// The magazine's own data's name.
pub const MAGAZINE: &str = "zine";
/// The legacy nonce blob (0xfffffff005aa3a80, 0xfffffff005aa3c58).
pub const LEGACY: &str = "40A0DDD2-77F8-4392-B4A3-1E7304206516:nonce-seeds";
/// The magazine data: a version byte, a digest of up to 64 bytes and its
/// length in its last byte (written at 0xfffffff005a9ef90).
pub const MAGAZINE_DATA_SIZE: usize = 0x42;
/// A digest's room (0xfffffff005a9f750).
pub const DIGEST_MAX: usize = 0x40;
/// The buffer a slot is read into (0xfffffff005a9ea50).
const SLOT_READ_MAX: usize = 0x80;
/// The legacy blob's buffer.
const LEGACY_READ_MAX: usize = 0x203;

/// Darwin's errno numbers the magazine returns.
mod errno {
    pub const EPERM: i32 = 1;
    pub const ENOENT: i32 = 2;
    pub const ENOMEM: i32 = 12;
    pub const EINVAL: i32 = 22;
    pub const ENOSPC: i32 = 28;
    pub const EROFS: i32 = 30;
    pub const ERANGE: i32 = 34;
    pub const EAGAIN: i32 = 35;
    pub const EALREADY: i32 = 37;
    pub const ENOTSUP: i32 = 45;
    pub const ESTALE: i32 = 70;
    pub const EDEVERR: i32 = 83;
    pub const EOVERFLOW: i32 = 84;
    pub const ESHLIBVERS: i32 = 87;
    pub const ENODATA: i32 = 96;
}

/// iBoot's `/chosen` `boot-command` (0x1800f07b8 adds it as a 4-byte
/// integer; the Mac this was traced on has 1 after a normal boot).
pub mod boot_command {
    /// `fsboot`: the operating system from its volume.
    pub const FSBOOT: u32 = 1;
    /// `bootx`: a kernel from memory, as iBEC boots the restore ramdisk
    /// (its image `rkrn`); `/chosen` `osenvironment` is `darwinos-ramdisk`
    /// only for a ticket whose `osev` is 2 or 3 (0x1800c6908), which the
    /// erase restore's has not.
    pub const BOOTX: u32 = 7;
}

/// A nonce domain's record: its name (+0), its four characters (+0xc),
/// what its slot's flags gain when its data cannot be read (+0x20), its
/// handle among its chip's domains (+0x30), its index (+0x40: the handle
/// libimage4's domain objects carry at +8, which the traps find the slot
/// by, 0xfffffff005a9f408, and its place in the legacy blob), its nonce's
/// length (+0x48) and its persistence (+0x50: 0 is
/// not kept in the NVRAM and rolls every boot; 1 to 3 kept). No record
/// asks for its slot's deletion (+0x18 bit 1).
#[derive(Clone, Copy, Debug)]
pub struct Domain {
    pub name: &'static str,
    pub code: &'static str,
    pub unread_flags: u32,
    pub handle: u32,
    pub index: u64,
    pub nonce_length: usize,
    pub persistence: u64,
}

/// The magazine's slots in its order (0xfffffff007ae59c0 → the records
/// 0xfffffff006cf2370 to 0xfffffff006cf2648).
pub const DOMAINS: [Domain; 8] = [
    Domain { name: "personalized disk image", code: "pdmg", unread_flags: 0, handle: 0xffff_ffff, index: 2, nonce_length: 16, persistence: 0 },
    Domain { name: "research cryptex", code: "cptx", unread_flags: 0, handle: 0xffff_ffff, index: 3, nonce_length: 16, persistence: 2 },
    Domain { name: "developer disk image", code: "dvdi", unread_flags: 0, handle: 0xffff_ffff, index: 4, nonce_length: 16, persistence: 2 },
    Domain { name: "cryptex1 boot", code: "c1bt", unread_flags: nonce::flag::UNAVAILABLE, handle: 1, index: 7, nonce_length: 16, persistence: 2 },
    Domain { name: "cryptex1 asset brain", code: "c1ab", unread_flags: 0, handle: 2, index: 8, nonce_length: 16, persistence: 2 },
    Domain { name: "cryptex1 generic", code: "c1gn", unread_flags: 0, handle: 3, index: 9, nonce_length: 16, persistence: 2 },
    Domain { name: "cryptex1 simulator", code: "c1sm", unread_flags: 0, handle: 4, index: 10, nonce_length: 16, persistence: 2 },
    Domain { name: "cryptex1 ephemeral", code: "c1ep", unread_flags: 0, handle: 5, index: 11, nonce_length: 16, persistence: 0 },
];

/// The cryptex1 boot domain's slot.
pub const CRYPTEX1_BOOT: usize = 3;

/// A slot's key.
pub fn slot_key(i: usize) -> String {
    format!("{PREFIX}{}", DOMAINS[i].code)
}

/// The magazine data's key.
pub fn magazine_key() -> String {
    format!("{PREFIX}{MAGAZINE}")
}

/// The roll (0xfffffff005a9a5dc) of a slot of domain `d` at `level`: the
/// level a spent or consumed nonce (flags 0x1, 0x2) has is at least 3; a
/// slot rolls when its domain's persistence (with a proposal, at most 2)
/// is no more than that. A proposal becomes the nonce and is cleared;
/// with none a new nonce comes from the kernel's random source
/// (`read_random`, runtime +0xd8). The flags lose 0x40 (rolled with no
/// proposal) or 0x8 (rolled with one), then 0x23 (0x27 with a proposal),
/// and 0x8 when the nonce was spent. Whether it drew a nonce.
pub fn roll(slot: &mut Slot, d: &Domain, level: u64, random: &mut dyn FnMut(&mut [u8]) -> Result<(), String>) -> Result<bool, String> {
    let flags = slot.flags;
    let proposal = flags & nonce::flag::PROPOSAL != 0;
    let threshold = if proposal { d.persistence.min(2) } else { d.persistence };
    let effective = if flags & 3 != 0 { level.max(3) } else { level };
    let mut kept = flags;
    let mut drawn = false;
    if threshold <= effective {
        if proposal {
            slot.nonce = slot.proposal;
            slot.proposal = [0; 16];
            kept &= !nonce::flag::UNAVAILABLE;
        } else {
            random(&mut slot.nonce[..d.nonce_length])?;
            kept &= !nonce::flag::ENTANGLE;
            drawn = true;
        }
    }
    let clear = if proposal { 0x27 } else { 0x23 } | ((flags & nonce::flag::SPENT) << 2);
    slot.flags = kept & !clear;
    Ok(drawn)
}

/// A slot whose data could not be read (0xfffffff005a9a5a4): with flag
/// 0x10 its level is 0 when 0x20 is set too, else 2, and both go; with
/// none the domain's unread flags and 0x1 are set and the level is 2;
/// then the roll. Whether it drew a nonce.
pub fn consume(slot: &mut Slot, d: &Domain, random: &mut dyn FnMut(&mut [u8]) -> Result<(), String>) -> Result<bool, String> {
    let f = slot.flags;
    let level = if f & 0x10 != 0 {
        slot.flags = f & !0x30;
        if f & 0x20 == 0 {
            2
        } else {
            0
        }
    } else {
        slot.flags = d.unread_flags | f | 1;
        2
    };
    roll(slot, d, level, random)
}

/// The slot's data as the magazine writes it (0xfffffff005a9a3a0): none
/// for a domain not kept (persistence 0), else its 37 bytes.
pub fn slot_data(slot: &Slot, d: &Domain) -> Result<Option<[u8; nonce::SLOT_SIZE]>, Fail> {
    match d.persistence {
        0 => Ok(None),
        1..=3 => Ok(Some(slot.to_bytes())),
        _ => Err(Fail::Panic("panic: unreachable (0xfffffff005a9a3a0)".into())),
    }
}

/// The NVRAM as the magazine reaches it through its expert.
pub trait Storage {
    /// The expert's read (0xfffffff005a9280c of `/options`): the bytes of
    /// the property, at most `cap`; ENOENT when absent, ENODATA when not
    /// data, EOVERFLOW when longer.
    fn read(&mut self, key: &str, cap: usize) -> Result<Result<Vec<u8>, i32>, String>;
    /// The expert's write (0xfffffff005a92c60): the errno it makes of
    /// `setProperties`' return; `None` deletes, which answers 0.
    fn write(&mut self, key: &str, data: Option<&[u8]>) -> Result<i32, String>;
    /// The expert's sync (0xfffffff005a92f70): 2 sets
    /// `IONVRAM-SYNCNOW-PROPERTY`, 3 `IONVRAM-FORCESYNCNOW-PROPERTY`.
    fn sync(&mut self, kind: u32) -> Result<(), String>;
}

/// The device tree as the expert reads it: a property of `/chosen`,
/// `/defaults` or `/product`.
pub trait Tree {
    fn prop(&self, node: &str, name: &str) -> Option<Vec<u8>>;
}

impl Tree for Vec<super::iokit::Node> {
    fn prop(&self, node: &str, name: &str) -> Option<Vec<u8>> {
        super::iokit::dt_prop(self, &format!("IODeviceTree:{node}"), name).map(<[u8]>::to_vec)
    }
}

/// 0xfffffff005a9280c over the device tree: absent ENOENT, longer than
/// `cap` EOVERFLOW.
fn tree_read(t: &dyn Tree, node: &str, name: &str, cap: usize) -> Result<Vec<u8>, i32> {
    match t.prop(node, name) {
        None => Err(errno::ENOENT),
        Some(v) if v.len() > cap => Err(errno::EOVERFLOW),
        Some(v) => Ok(v),
    }
}

/// A Boolean property (0xfffffff005a928d8): 4 bytes, nonzero; absent is
/// false; any other failure panics.
fn tree_bool(t: &dyn Tree, node: &str, name: &str) -> Result<bool, Fail> {
    match tree_read(t, node, name, 4) {
        Ok(v) => {
            let mut b = [0u8; 4];
            b[..v.len()].copy_from_slice(&v);
            Ok(u32::from_le_bytes(b) != 0)
        }
        Err(errno::ENOENT) => Ok(false),
        Err(r) => Err(Fail::Panic(format!("panic: failed to read property: {name}: {r}"))),
    }
}

/// A NUL-ended string of up to `cap` bytes as `strcmp` sees it.
fn c_string(v: &[u8]) -> &[u8] {
    v.iter().position(|&c| c == 0).map_or(v, |n| &v[..n])
}

/// The i/o strategies (0xfffffff006cf9098).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strategy {
    /// Reads and writes.
    Default,
    /// Reads; writes are EROFS.
    Preserve,
    /// Reads; writes EAGAIN until the first demand for i/o.
    Demand,
    /// Reads ENOENT; writes.
    Stale,
    /// Reads; a write panics.
    Panic,
}

impl Strategy {
    pub fn name(self) -> &'static str {
        match self {
            Strategy::Default => "default",
            Strategy::Preserve => "preserve",
            Strategy::Demand => "demand",
            Strategy::Stale => "stale",
            Strategy::Panic => "panic",
        }
    }

    /// Its flags' bit 1: the demand strategy's.
    fn on_demand(self) -> bool {
        self == Strategy::Demand
    }
}

/// The magazine.
#[derive(Clone, Debug)]
pub struct Magazine {
    pub slots: [Slot; 8],
    pub strategy: Strategy,
    /// The demand counter (+0x88): -1 until the first demand for i/o.
    demand: i64,
    /// The boot manifest hash it keeps (+0x90).
    pub hash: Vec<u8>,
    /// Whether the device allows mix-n-match (+0xf0).
    pub allow_mix_n_match: bool,
    /// The level the boot rolls the slots it reads at (+0xe8).
    pub level: u64,
    /// The slot written first (+0x20): the first read with a proposal.
    priority: Option<usize>,
    /// The magazine data's version as read (+0x80).
    pub version: u8,
    /// `/defaults` `entangle-nonce` (the expert's +0xee).
    pub entangle: bool,
    /// The slots whose boot drew a nonce from the random source.
    pub drawn: [bool; 8],
    /// What the kext only logs.
    pub log: Vec<String>,
}

/// The magazine data.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MagazineData {
    pub version: u8,
    pub hash: Vec<u8>,
}

impl MagazineData {
    /// Its bytes as the magazine writes them (0xfffffff005a9ef90):
    /// version 0, the digest, its length last.
    pub fn to_bytes(hash: &[u8]) -> [u8; MAGAZINE_DATA_SIZE] {
        let mut b = [0u8; MAGAZINE_DATA_SIZE];
        b[1..1 + hash.len()].copy_from_slice(hash);
        b[MAGAZINE_DATA_SIZE - 1] = hash.len() as u8;
        b
    }
}

impl Magazine {
    fn new() -> Magazine {
        let empty = Slot { flags: 0, nonce: [0; 16], proposal: [0; 16] };
        Magazine { slots: [empty; 8], strategy: Strategy::Default, demand: -1, hash: Vec::new(), allow_mix_n_match: false, level: 0, priority: None, version: 0, entangle: false, drawn: [false; 8], log: Vec::new() }
    }

    fn note(&mut self, s: String) {
        self.log.push(s);
    }

    /// The strategy's read (+0x10): the prefix and `name` (the magazine's
    /// own with none).
    fn read(&mut self, st: &mut dyn Storage, name: Option<&str>, cap: usize) -> Result<Result<Vec<u8>, i32>, String> {
        if self.strategy == Strategy::Stale {
            return Ok(Err(errno::ENOENT));
        }
        st.read(&format!("{PREFIX}{}", name.unwrap_or(MAGAZINE)), cap)
    }

    /// The strategy's write (+0x18).
    fn write(&mut self, st: &mut dyn Storage, name: Option<&str>, data: &[u8]) -> Result<i32, Fail> {
        let key = format!("{PREFIX}{}", name.unwrap_or(MAGAZINE));
        match self.strategy {
            Strategy::Preserve => Ok(errno::EROFS),
            Strategy::Panic => Err(Fail::Panic("panic: writing anti-replay state not supported in this environment".into())),
            Strategy::Demand if self.demand < 0 => Ok(errno::EAGAIN),
            _ => st.write(&key, Some(data)).map_err(Fail::Unmodelled),
        }
    }

    /// The strategy's raw write (+0x20) of the legacy blob's deletion
    /// (0xfffffff005aa3e20).
    fn delete_legacy(&mut self, st: &mut dyn Storage) -> Result<i32, Fail> {
        match self.strategy {
            Strategy::Preserve => Ok(errno::EROFS),
            Strategy::Panic => Err(Fail::Panic("panic: writing anti-replay state not supported in this environment".into())),
            Strategy::Demand if self.demand < 0 => Ok(errno::EAGAIN),
            _ => st.write(LEGACY, None).map_err(Fail::Unmodelled),
        }
    }

    /// 0xfffffff005a9f0a4: slot `i`'s data, when its domain keeps it.
    fn write_slot(&mut self, st: &mut dyn Storage, i: usize) -> Result<i32, Fail> {
        let d = DOMAINS[i];
        let Some(b) = slot_data(&self.slots[i], &d)? else { return Ok(0) };
        let r = self.write(st, Some(d.code), &b)?;
        if !matches!(r, 0 | errno::EROFS | errno::EAGAIN) {
            self.note(format!("magazine[{}]: failed to write nonce data: {r}", d.code));
        }
        Ok(r)
    }

    /// 0xfffffff005a9ef90: the magazine data.
    fn write_data(&mut self, st: &mut dyn Storage) -> Result<i32, Fail> {
        let b = MagazineData::to_bytes(&self.hash);
        let r = self.write(st, None, &b)?;
        if r != 0 && r != errno::EROFS {
            self.note(format!("magazine[{MAGAZINE}]: failed to write nonce magazine data: {r}"));
        }
        Ok(r)
    }

    /// 0xfffffff005a9edec: the priority slot, every other slot, then the
    /// magazine data.
    fn write_all(&mut self, st: &mut dyn Storage) -> Result<i32, Fail> {
        let mut first = self.priority.take();
        if let Some(p) = first {
            let r = self.write_slot(st, p)?;
            if r != 0 {
                self.note(format!("magazine[{}]: failed to write priority slot: {r}", DOMAINS[p].code));
                first = None;
            }
        }
        for i in 0..DOMAINS.len() {
            if Some(i) == first {
                continue;
            }
            match self.write_slot(st, i)? {
                0 => {}
                r @ (errno::ENOSPC | errno::EROFS) => {
                    self.note(format!("magazine[{}]: magazine data cannot be written: {r}", DOMAINS[i].code));
                    return Ok(r);
                }
                errno::EAGAIN => return Ok(errno::EAGAIN),
                r => self.note(format!("magazine[{}]: failed to write slot: {r}", DOMAINS[i].code)),
            }
        }
        let r = self.write_data(st)?;
        if r != 0 {
            self.note(format!("magazine[{MAGAZINE}]: failed to write magazine data: {r}"));
            return Ok(r);
        }
        Ok(0)
    }

    /// 0xfffffff005a9f20c: the expert's sync of `kind`.
    fn sync(&mut self, st: &mut dyn Storage, kind: u32) -> Result<(), String> {
        st.sync(kind)
    }

    /// 0xfffffff005a9ecc0: the first demand for i/o writes the whole
    /// magazine (EALREADY when it did); a full NVRAM under the demand
    /// strategy has the legacy blob deleted and asks for a retry (EAGAIN).
    fn demand_io(&mut self, st: &mut dyn Storage) -> Result<i32, Fail> {
        let old = self.demand;
        self.demand += 1;
        if old >= 0 {
            return Ok(0);
        }
        match self.write_all(st)? {
            0 => Ok(errno::EALREADY),
            errno::ENOSPC => {
                if !self.strategy.on_demand() {
                    self.note(format!("magazine[{MAGAZINE}]: initial demand write failed: {}", errno::ENOSPC));
                    return Ok(errno::ENOSPC);
                }
                if self.delete_legacy(st)? == 0 {
                    Ok(errno::EAGAIN)
                } else {
                    self.note(format!("magazine[{MAGAZINE}]: failed to nuke legacy blob: {}", errno::ENOSPC));
                    Ok(errno::ENOSPC)
                }
            }
            r => {
                self.note(format!("magazine[{MAGAZINE}]: initial demand write failed: {r}"));
                Ok(r)
            }
        }
    }

    /// 0xfffffff005a953f4: the i/o a trap demands after changing slot
    /// `i`, then the sync.
    fn trap_io(&mut self, st: &mut dyn Storage, i: usize) -> Result<i32, Fail> {
        let code = DOMAINS[i].code;
        match self.demand_io(st)? {
            errno::EAGAIN => {
                let r = self.write_data(st)?;
                if r != 0 {
                    self.note(format!("magazine[{code}]: failed retry write of magazine: {r}"));
                    return Ok(r);
                }
                let r = self.write_slot(st, i)?;
                if r != 0 {
                    self.note(format!("magazine[{code}]: failed retry write of slot: {r}"));
                    return Ok(r);
                }
            }
            0 => {
                let r = self.write_slot(st, i)?;
                if r != 0 {
                    self.note(format!("magazine[{code}]: failed to write slot after rolling: {r}"));
                    return Ok(r);
                }
            }
            _ => {}
        }
        self.sync(st, 2).map_err(Fail::Unmodelled)?;
        Ok(0)
    }

    /// The legacy blob, which no model reads: its absence only.
    fn legacy_absent(st: &mut dyn Storage) -> Result<(), Fail> {
        match st.read(LEGACY, LEGACY_READ_MAX).map_err(Fail::Unmodelled)? {
            Err(errno::ENOENT) => Ok(()),
            _ => Err(Fail::Unmodelled(format!("AppleImage4's legacy nonce blob ({LEGACY}): its header and slots (0xfffffff005aa3a80, 0xfffffff005aa3c58) and their migration into the magazine (0xfffffff005a9ea50) are not modelled"))),
        }
    }

    /// 0xfffffff005a9e4ac: the boot manifest hash and the mix-n-match
    /// policy queried, then the magazine data read: its status and data.
    fn read_data(&mut self, t: &dyn Tree, st: &mut dyn Storage) -> Result<(i32, MagazineData), Fail> {
        // The expert's digest query of `boot-manifest-hash`
        // (0xfffffff005a99888: /chosen, 64 bytes).
        let hash = match tree_read(t, "/chosen", "boot-manifest-hash", DIGEST_MAX) {
            Ok(v) => v,
            Err(errno::ENOENT) => Vec::new(),
            Err(r) => {
                self.note(format!("magazine[{MAGAZINE}]: failed to query boot manifest hash: {r}"));
                return Ok((r, MagazineData::default()));
            }
        };
        // The Boolean query (0xfffffff005a9c05c, 0xfffffff005a995a4 0xb):
        // allowed when the prevention status is 0; absent, the
        // descriptor's default (0xfffffff005a95bf8) false.
        let allow = match tree_read(t, "/chosen", "mix-n-match-prevention-status", 4) {
            Ok(v) => {
                let mut b = [0u8; 4];
                b[..v.len()].copy_from_slice(&v);
                u32::from_le_bytes(b) == 0
            }
            Err(errno::ENOENT) => false,
            Err(r) => return Err(Fail::Panic(format!("panic: failed to query mix-n-match policy: {r}"))),
        };
        self.hash = hash;
        self.allow_mix_n_match = allow;
        let raw = match self.read(st, None, MAGAZINE_DATA_SIZE).map_err(Fail::Unmodelled)? {
            Ok(b) => b,
            Err(errno::EOVERFLOW | errno::ENOENT) => return Ok((0, MagazineData::default())),
            Err(r) => {
                self.note(format!("magazine[{MAGAZINE}]: failed to query storage for nonce magazine: {r}"));
                return Ok((r, MagazineData::default()));
            }
        };
        if raw.is_empty() {
            self.note(format!("magazine[{MAGAZINE}]: magazine data too small for version"));
            return Ok((errno::ENODATA, MagazineData::default()));
        }
        let version = raw[0];
        if version >= 2 {
            if raw.len() > MAGAZINE_DATA_SIZE - 1 {
                return Ok((errno::ESHLIBVERS, MagazineData::default()));
            }
            self.note(format!("magazine[{MAGAZINE}]: future magazine is bogus: version = {version}"));
            return Ok((errno::ERANGE, MagazineData::default()));
        }
        if raw.len() != MAGAZINE_DATA_SIZE {
            self.note(format!("magazine[{MAGAZINE}]: magazine data has incorrect length: version = {version}, actual = {}", raw.len()));
            return Ok((errno::ERANGE, MagazineData::default()));
        }
        Self::legacy_absent(st)?;
        let len = raw[MAGAZINE_DATA_SIZE - 1] as usize;
        if len > DIGEST_MAX {
            self.note(format!("magazine[{MAGAZINE}]: magazine data has invalid manifest hash length: actual = {len}"));
            return Ok((errno::EOVERFLOW, MagazineData::default()));
        }
        // A stored digest of another length than the boot's is the boot's.
        let stored = if len == self.hash.len() { raw[1..1 + len].to_vec() } else { self.hash.clone() };
        self.version = version;
        Ok((0, MagazineData { version, hash: stored }))
    }

    /// 0xfffffff005a9e918: the boot's level, 0 when the magazine was
    /// written under the boot's manifest; else 1 when mix-n-match is
    /// allowed (the stored hash kept), 2 when not (the boot's taken).
    fn apply_hash(&mut self, data: &MagazineData) {
        if data.hash == self.hash {
            self.level = 0;
        } else if self.allow_mix_n_match {
            self.level = 1;
            self.hash = data.hash.clone();
        } else {
            self.level = 2;
        }
    }

    /// 0xfffffff005a9ea50: each slot read and rolled at the boot's level;
    /// one that cannot be read consumed. The first read with a proposal
    /// is written first.
    fn read_slots(&mut self, st: &mut dyn Storage, random: &mut dyn FnMut(&mut [u8]) -> Result<(), String>) -> Result<(), Fail> {
        Self::legacy_absent(st)?;
        for i in 0..DOMAINS.len() {
            let d = DOMAINS[i];
            let read = match self.read(st, Some(d.code), SLOT_READ_MAX).map_err(Fail::Unmodelled)? {
                Ok(b) => Slot::parse(&b).map_err(|r| {
                    self.log.push(format!("slot[{}]: invalid nonce slot data: {r}", d.code));
                    r
                }),
                Err(r) => {
                    self.note(format!("magazine[{}]: failed to read nonce slot data: {r}", d.code));
                    Err(r)
                }
            };
            match read {
                Ok(s) => {
                    self.slots[i] = s;
                    let proposal = s.flags & nonce::flag::PROPOSAL != 0;
                    self.drawn[i] = roll(&mut self.slots[i], &d, self.level, random).map_err(Fail::Unmodelled)?;
                    if self.priority.is_none() && proposal {
                        self.priority = Some(i);
                    }
                }
                Err(_) => self.drawn[i] = consume(&mut self.slots[i], &d, random).map_err(Fail::Unmodelled)?,
            }
        }
        Ok(())
    }
}

/// The expert's boot (0xfffffff005a98710) over the device tree `t` and the
/// NVRAM `st`: `/chosen`'s `boot-type`, `osenvironment` and `boot-command`,
/// `/product`'s `allow-hactivation`, `/defaults`' `entangle-nonce`, the
/// magazine data, the strategy, the boot's level and the slots.
pub fn boot(t: &dyn Tree, st: &mut dyn Storage, random: &mut dyn FnMut(&mut [u8]) -> Result<(), String>) -> Result<Magazine, Fail> {
    let fails = |what: &str, r: i32| Fail::Panic(format!("panic: expert boot failed: {what}: {r}"));
    let remote = match tree_read(t, "/chosen", "boot-type", 0x40) {
        Ok(v) => c_string(&v) == b"remote",
        Err(errno::ENOENT) => false,
        Err(r) => return Err(fails("failed to read boot command", r)),
    };
    let darwinos = match tree_read(t, "/chosen", "osenvironment", 0x40) {
        Ok(v) => c_string(&v) == b"darwinos-ramdisk",
        Err(errno::ENOENT) => false,
        Err(r) => return Err(fails("failed to read os environment", r)),
    };
    let command = match tree_read(t, "/chosen", "boot-command", 4) {
        Ok(v) => {
            let mut b = [0u8; 8];
            b[..v.len()].copy_from_slice(&v);
            let c = u64::from_le_bytes(b);
            if c > 0xff {
                return Err(Fail::Panic(format!("panic: integer cast overflow: v = boot command, actual = {c}, expected <= 255")));
            }
            c as u8
        }
        Err(errno::ENOENT) => 0xe,
        Err(r) => return Err(fails("failed to read boot command", r)),
    };
    tree_bool(t, "/product", "allow-hactivation")?;
    let entangle = tree_bool(t, "/defaults", "entangle-nonce")?;
    let mut m = Magazine::new();
    m.entangle = entangle;
    let (status, data) = m.read_data(t, st)?;
    let from_data = match status {
        errno::ESTALE => Some(Strategy::Stale),
        errno::ESHLIBVERS => Some(Strategy::Preserve),
        0 | errno::ERANGE | errno::ENODATA => None,
        r => return Err(fails("magazine data", r)),
    };
    let from_command = match command {
        0 => remote.then_some(Strategy::Preserve),
        1 | 2 | 4 | 9 | 10 | 11 | 12 => None,
        7 => Some(if darwinos { Strategy::Preserve } else { Strategy::Demand }),
        _ => Some(Strategy::Preserve),
    };
    if let Some(s) = from_command.or(from_data) {
        m.strategy = s;
    }
    m.apply_hash(&data);
    m.read_slots(st, random)?;
    Ok(m)
}

impl Magazine {
    /// `kmod_expert_uncork_userspace` (0xfffffff005a982d4), at the
    /// AppleImage4 service's start (0xfffffff005a8d1bc): with mix-n-match
    /// prevented the legacy blob deleted, the whole magazine written, the
    /// NVRAM synced (`IONVRAM-SYNCNOW-PROPERTY`). Failures are logged.
    pub fn uncork(&mut self, st: &mut dyn Storage) -> Result<(), Fail> {
        if !self.allow_mix_n_match {
            let r = self.delete_legacy(st)?;
            if !matches!(r, 0 | errno::ENOENT | errno::EROFS) {
                self.note(format!("magazine[{MAGAZINE}]: failed to nuke legacy nonce blob: {r}"));
            }
        }
        let r = self.write_all(st)?;
        if r != 0 {
            self.note(format!("magazine[{MAGAZINE}]: magazine write failed; may be expected: {r}"));
        }
        self.sync(st, 2).map_err(Fail::Unmodelled)
    }

    /// The `nonce proposal generate` trap (0xfffffff005a94604, libimage4's
    /// `img4_nonce_domain_preroll_nonce`, selector 10) for slot `i`, whose
    /// entitlement the caller has: a proposal from the random source
    /// (0xfffffff005a9a6c8: the domain's nonce length, flag 0x4), the
    /// magazine's i/o (an error fails the trap), then the proposal's hash
    /// ([`proposal_hash`]).
    pub fn generate_proposal(&mut self, st: &mut dyn Storage, i: usize, random: &mut dyn FnMut(&mut [u8]) -> Result<(), String>) -> Result<Result<Vec<u8>, i32>, Fail> {
        let d = DOMAINS[i];
        random(&mut self.slots[i].proposal[..d.nonce_length]).map_err(Fail::Unmodelled)?;
        self.slots[i].flags |= nonce::flag::PROPOSAL;
        let proposal = self.slots[i].proposal;
        let r = self.trap_io(st, i)?;
        if r != 0 {
            self.note(format!("magazine[{}]: demand magazine i/o failed: {r}", d.code));
            return Ok(Err(r));
        }
        proposal_hash(i, &proposal[..d.nonce_length], self.entangle).map(Ok)
    }

    /// The `nonce roll` trap (0xfffffff005a943cc, libimage4's
    /// `img4_nonce_domain_roll_nonce`, selector 8) for slot `i`: on a
    /// device without a monitor (J120's, 0xfffffff005a8f314) the slot's
    /// nonce marked spent (0xfffffff005a9a240, flag 0x2), which the next
    /// boot rolls, and the magazine's i/o.
    pub fn roll_nonce(&mut self, st: &mut dyn Storage, i: usize) -> Result<i32, Fail> {
        self.slots[i].flags |= nonce::flag::SPENT;
        let r = self.trap_io(st, i)?;
        if r != 0 {
            self.note(format!("magazine[{}]: demand magazine i/o failed: {r}", DOMAINS[i].code));
        }
        Ok(r)
    }

    /// The cryptex1 boot nonce hash the BOOT anti-replay policy makes of
    /// the cryptex1 boot slot ([`nonce::cryptex1_boot_hash`]).
    pub fn cryptex1_boot_hash(&self) -> Result<Vec<u8>, Fail> {
        nonce::cryptex1_boot_hash(&self.slots[CRYPTEX1_BOOT], self.entangle)
    }
}

/// The digest of a nonce of slot `i` (0xfffffff005a9a484 →
/// 0xfffffff005aa0c48): entangled when asked (not modelled), then the
/// chip's digest (0xfffffff005aa0a5c) by the domain's chip
/// (0xfffffff005a8f74c: its +0x28, else its +0x58, which for the cryptex1
/// boot domain, 0xfffffff005a8d7f4, is the expert's chip's +0x138: the
/// J120's `crypto-hash-method` "sha2-384" chip 0xfffffff006cf1870 gives
/// `CHIP_CRYPTEX1_BOOT_AP` 0xfffffff006cf29b0), as the BOOT policy hashes
/// the nonce.
pub fn proposal_hash(i: usize, nonce: &[u8], entangle: bool) -> Result<Vec<u8>, Fail> {
    if i != CRYPTEX1_BOOT {
        return Err(Fail::Unmodelled(format!("the nonce digest of the {} domain's chip (0xfffffff005aa0a5c)", DOMAINS[i].name)));
    }
    let mut n = [0u8; 16];
    n.copy_from_slice(nonce);
    nonce::cryptex1_boot_hash(&Slot { flags: 0, nonce: n, proposal: [0; 16] }, entangle)
}

/// The NVRAM model as the magazine's expert reaches it: the kernel's task,
/// with `clock` for a sync's rate limit.
pub struct NvramStorage<'a> {
    pub nv: &'a mut super::nvram::Nvram,
    pub clock: &'a dyn super::nvram::Clock,
}

impl Storage for NvramStorage<'_> {
    fn read(&mut self, key: &str, cap: usize) -> Result<Result<Vec<u8>, i32>, String> {
        use super::nvram::{Kernel, Value};
        Ok(match self.nv.copy_property(&Kernel, key.as_bytes()) {
            None => Err(errno::ENOENT),
            Some(Value::Data(d)) if d.len() > cap => Err(errno::EOVERFLOW),
            Some(Value::Data(d)) => Ok(d),
            Some(_) => Err(errno::ENODATA),
        })
    }

    fn write(&mut self, key: &str, data: Option<&[u8]>) -> Result<i32, String> {
        use super::nvram::{key as k, ret, Given, Kernel, Value};
        let r = match data {
            None => {
                self.nv.set_property_clocked(&Kernel, k::DELETE, &Given::Value(Value::String(key.as_bytes().to_vec())), None, self.clock);
                0
            }
            Some(d) => match self.nv.set_property_clocked(&Kernel, key.as_bytes(), &Given::Value(Value::Data(d.to_vec())), None, self.clock) {
                ret::SUCCESS => 0,
                ret::NO_MEMORY => errno::ENOMEM,
                ret::NOT_PRIVILEGED => errno::EPERM,
                ret::BAD_ARGUMENT => errno::EINVAL,
                ret::UNSUPPORTED => errno::ENOTSUP,
                ret::NO_SPACE => errno::ENOSPC,
                _ => errno::EDEVERR,
            },
        };
        let e = std::mem::take(&mut self.nv.write_errors);
        if !e.is_empty() {
            return Err(e.join("; "));
        }
        Ok(r)
    }

    fn sync(&mut self, kind: u32) -> Result<(), String> {
        use super::nvram::{key as k, Given, Kernel, Value};
        let key = match kind {
            0 => return Ok(()),
            2 => k::SYNC_NOW,
            3 => k::FORCE_SYNC_NOW,
            _ => return Err(format!("AppleImage4's NVRAM sync of type {kind} (0xfffffff005a92f70): not modelled")),
        };
        self.nv.set_property_clocked(&Kernel, key, &Given::Value(Value::String(b"1".to_vec())), None, self.clock);
        let e = std::mem::take(&mut self.nv.write_errors);
        if !e.is_empty() {
            return Err(e.join("; "));
        }
        Ok(())
    }
}

/// The running system's magazine: none until AppleImage4 boots over the
/// NVRAM, or why there is none.
static RUNNING: std::sync::Mutex<Option<Result<Magazine, String>>> = std::sync::Mutex::new(None);

/// AppleImage4's boot and its service's start over the running NVRAM
/// (`super::nvram::with`) and the device tree `t`: the magazine read and
/// rolled, then uncorked. Without NVRAM the magazine is not had.
pub fn start(t: &dyn Tree) -> Result<(), String> {
    let r = super::nvram::with(|nv| -> Result<Magazine, Fail> {
        let mut st = NvramStorage { nv, clock: &super::nvram::Uptime };
        let mut random = |b: &mut [u8]| -> Result<(), String> {
            crate::vfs::devfs::fill_random(b);
            Ok(())
        };
        let mut m = boot(t, &mut st, &mut random)?;
        m.uncork(&mut st)?;
        Ok(m)
    });
    let m = match r {
        Ok(Ok(m)) => Ok(m),
        Ok(Err(Fail::Panic(p))) => return Err(format!("the kernel panics at AppleImage4's boot: {p}")),
        Ok(Err(Fail::Unmodelled(w))) => return Err(format!("not implemented: AppleImage4's nonce magazine at boot: {w}")),
        Ok(Err(Fail::Code(c))) => return Err(format!("AppleImage4's nonce magazine at boot: errno {c}")),
        Err(why) => Err(why),
    };
    *RUNNING.lock().unwrap_or_else(|e| e.into_inner()) = Some(m);
    Ok(())
}

/// The running magazine's cryptex1 boot nonce hash, as the BOOT policy
/// makes it; `None` when AppleImage4 has not booted over an NVRAM.
pub fn running_cryptex1_boot_hash() -> Option<Result<Vec<u8>, Fail>> {
    let g = RUNNING.lock().unwrap_or_else(|e| e.into_inner());
    match &*g {
        None => None,
        Some(Ok(m)) => Some(m.cryptex1_boot_hash()),
        Some(Err(why)) => Some(Err(Fail::Unmodelled(format!("AppleImage4's nonce magazine: the device's NVRAM: {why}")))),
    }
}

/// The cryptex1 boot slot the next boot of the NVRAM namespace `image`,
/// with `t` its device tree, will hold, read without writing anything; a
/// nonce that boot draws from its random source is not known before it,
/// and is an error.
pub fn next_boot_cryptex1_slot(image: &[u8], t: &dyn Tree) -> Result<Slot, Fail> {
    let (mut nv, _) = super::nvram::over_image(image).map_err(Fail::Unmodelled)?;
    let mut st = NvramStorage { nv: &mut nv, clock: &super::nvram::Uptime };
    let mut random = |b: &mut [u8]| -> Result<(), String> {
        b.fill(0);
        Ok(())
    };
    let m = boot(t, &mut st, &mut random)?;
    if m.drawn[CRYPTEX1_BOOT] {
        return Err(Fail::Unmodelled(format!(
            "the next boot rolls the cryptex1 boot nonce to one from its random source (its NVRAM {}: level {}): no ticket can be signed for it before that boot; a restore makes one",
            if m.version == 0 && m.hash.is_empty() { "holds no nonce magazine" } else { "magazine's slot is spent or its boot manifest hash is another" },
            m.level
        )));
    }
    Ok(m.slots[CRYPTEX1_BOOT])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::darwin::nvram;

    /// The device tree's properties the boot reads.
    struct T(Vec<(&'static str, &'static str, Vec<u8>)>);

    impl Tree for T {
        fn prop(&self, node: &str, name: &str) -> Option<Vec<u8>> {
            self.0.iter().find(|(n, k, _)| *n == node && *k == name).map(|(_, _, v)| v.clone())
        }
    }

    fn tree(command: u32, hash: &[u8]) -> T {
        T(vec![
            ("/chosen", "boot-type", b"local\0\0\0\0\0\0\0".to_vec()),
            ("/chosen", "osenvironment", vec![0; 32]),
            ("/chosen", "boot-command", command.to_le_bytes().to_vec()),
            ("/chosen", "boot-manifest-hash", hash.to_vec()),
            ("/chosen", "mix-n-match-prevention-status", 1u32.to_le_bytes().to_vec()),
        ])
    }

    fn counter() -> impl FnMut(&mut [u8]) -> Result<(), String> {
        let mut n = 0u8;
        move |b: &mut [u8]| {
            n += 1;
            b.fill(n);
            Ok(())
        }
    }

    fn data(nv: &mut nvram::Nvram, key: &str) -> Option<Vec<u8>> {
        match nv.copy_property(&nvram::Kernel, key.as_bytes()) {
            Some(nvram::Value::Data(d)) => Some(d),
            None => None,
            v => panic!("{key}: {v:?}"),
        }
    }

    #[test]
    fn a_roll_follows_the_kexts_levels() {
        let d = DOMAINS[CRYPTEX1_BOOT];
        let mut r = counter();
        let s = Slot { flags: 0, nonce: [7; 16], proposal: [0; 16] };
        // The same manifest: kept.
        let mut a = s;
        roll(&mut a, &d, 0, &mut r).unwrap();
        assert_eq!(a, s);
        // Another manifest with mix-n-match prevented: a new nonce.
        let mut b = s;
        roll(&mut b, &d, 2, &mut r).unwrap();
        assert_eq!((b.flags, b.nonce), (0, [1; 16]));
        // Spent with a proposal: the proposal is the nonce.
        let mut c = Slot { flags: nonce::flag::SPENT | nonce::flag::PROPOSAL | nonce::flag::UNAVAILABLE, nonce: [7; 16], proposal: [9; 16] };
        roll(&mut c, &d, 0, &mut r).unwrap();
        assert_eq!(c, Slot { flags: 0, nonce: [9; 16], proposal: [0; 16] });
        // Unread: the domain's flags, a new nonce, unavailable.
        let mut u = Slot { flags: 0, nonce: [0; 16], proposal: [0; 16] };
        consume(&mut u, &d, &mut r).unwrap();
        assert_eq!((u.flags, u.nonce), (nonce::flag::UNAVAILABLE, [2; 16]));
        // A domain not kept rolls at every boot.
        let mut e = s;
        roll(&mut e, &DOMAINS[7], 0, &mut r).unwrap();
        assert_eq!(e.nonce, [3; 16]);
    }

    #[test]
    fn a_restore_rolls_the_nonce_its_ticket_is_for() {
        let hash = [0x5a; 48];
        let (mut nv, _) = nvram::over_image(&nvram::factory_image()).unwrap();
        let clock = nvram::Uptime;
        let mut r = counter();
        // The restore ramdisk's boot: bootx, the demand strategy, nothing
        // in the NVRAM, every slot read fails.
        let mut m = {
            let mut st = NvramStorage { nv: &mut nv, clock: &clock };
            let mut m = boot(&tree(boot_command::BOOTX, &hash), &mut st, &mut r).unwrap();
            assert_eq!((m.strategy, m.level), (Strategy::Demand, 2));
            assert_eq!(m.slots[CRYPTEX1_BOOT].flags, nonce::flag::UNAVAILABLE);
            m.uncork(&mut st).unwrap();
            m
        };
        assert_eq!(data(&mut nv, &magazine_key()), None, "the demand strategy writes nothing at the boot");
        // restored's preroll: a proposal, the whole magazine written.
        let proposal = {
            let mut st = NvramStorage { nv: &mut nv, clock: &clock };
            m.generate_proposal(&mut st, CRYPTEX1_BOOT, &mut r).unwrap().unwrap()
        };
        let p = m.slots[CRYPTEX1_BOOT].proposal;
        assert_eq!(proposal, proposal_hash(CRYPTEX1_BOOT, &p, false).unwrap());
        assert_eq!(data(&mut nv, &magazine_key()).unwrap(), MagazineData::to_bytes(&hash));
        for (i, d) in DOMAINS.iter().enumerate() {
            assert_eq!(data(&mut nv, &slot_key(i)).is_some(), d.persistence != 0, "{}", d.code);
        }
        // Its roll: spent.
        {
            let mut st = NvramStorage { nv: &mut nv, clock: &clock };
            assert_eq!(m.roll_nonce(&mut st, CRYPTEX1_BOOT).unwrap(), 0);
        }
        let saved = Slot::parse(&data(&mut nv, &slot_key(CRYPTEX1_BOOT)).unwrap()).unwrap();
        assert_eq!(saved.flags, nonce::flag::UNAVAILABLE | nonce::flag::PROPOSAL | nonce::flag::SPENT);
        // The system's boot (fsboot, the same AP ticket): the proposal is
        // the nonce, the ticket's.
        let mut st = NvramStorage { nv: &mut nv, clock: &clock };
        let mut b = boot(&tree(boot_command::FSBOOT, &hash), &mut st, &mut r).unwrap();
        assert_eq!((b.strategy, b.level), (Strategy::Default, 0));
        assert_eq!(b.slots[CRYPTEX1_BOOT], Slot { flags: 0, nonce: p, proposal: [0; 16] });
        assert_eq!(b.cryptex1_boot_hash().unwrap(), proposal);
        b.uncork(&mut st).unwrap();
        drop(st);
        assert_eq!(Slot::parse(&data(&mut nv, &slot_key(CRYPTEX1_BOOT)).unwrap()).unwrap().flags, 0);
        // A later boot keeps it.
        let mut st = NvramStorage { nv: &mut nv, clock: &clock };
        let again = boot(&tree(boot_command::FSBOOT, &hash), &mut st, &mut r).unwrap();
        assert_eq!(again.cryptex1_boot_hash().unwrap(), proposal);
        // Another AP ticket: mix-n-match prevented, a new nonce.
        let other = boot(&tree(boot_command::FSBOOT, &[0x11; 48]), &mut st, &mut r).unwrap();
        assert_ne!(other.cryptex1_boot_hash().unwrap(), proposal);
    }

    #[test]
    fn the_strategy_follows_the_boot_command_and_the_data() {
        let (mut nv, _) = nvram::over_image(&nvram::factory_image()).unwrap();
        let clock = nvram::Uptime;
        let mut r = counter();
        let mut st = NvramStorage { nv: &mut nv, clock: &clock };
        // No boot-command (0xe): preserve, and the uncork writes nothing.
        let mut t = tree(0, &[1; 48]);
        t.0.retain(|(_, k, _)| *k != "boot-command");
        let mut m = boot(&t, &mut st, &mut r).unwrap();
        assert_eq!(m.strategy, Strategy::Preserve);
        m.uncork(&mut st).unwrap();
        assert_eq!(st.read(&magazine_key(), 0x42).unwrap(), Err(errno::ENOENT));
        // bootx of a darwinOS ramdisk: preserve.
        let mut t = tree(boot_command::BOOTX, &[1; 48]);
        t.0.push(("/chosen", "osenvironment", b"darwinos-ramdisk\0".to_vec()));
        t.0.retain(|(_, k, v)| *k != "osenvironment" || v[0] != 0);
        assert_eq!(boot(&t, &mut st, &mut r).unwrap().strategy, Strategy::Preserve);
        // Magazine data of a future version too long: preserve.
        let mut long = vec![2u8; MAGAZINE_DATA_SIZE];
        long[0] = 2;
        st.write(&magazine_key(), Some(&long)).unwrap();
        assert_eq!(boot(&tree(boot_command::FSBOOT, &[1; 48]), &mut st, &mut r).unwrap().strategy, Strategy::Preserve);
        // A legacy blob is not modelled.
        st.write(LEGACY, Some(&[2; 0x170])).unwrap();
        st.write(&magazine_key(), Some(&MagazineData::to_bytes(&[1; 48]))).unwrap();
        assert!(matches!(boot(&tree(boot_command::FSBOOT, &[1; 48]), &mut st, &mut r), Err(Fail::Unmodelled(_))));
    }
}
