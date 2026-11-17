//! IOService matching as a task's matching dictionary reaches it
//! (`internal_io_service_get_matching_services` and its kin in
//! `IOUserClient.cpp`, `IOService::copyExistingServices`, `instanceMatch`,
//! `matchInternal` and `matchPassive` in `IOService.cpp`, xnu-10063): the
//! services of the registry here that a dictionary matches, with libkern's
//! comparison of each kind of object (`isEqualTo` of OSString, OSSymbol,
//! OSData, OSNumber, OSBoolean, OSDictionary, OSArray and OSSet), and the
//! overrides the classes here have of `compareName`, `matchPropertyTable`
//! and `matchLocation` (their vtables in the kernelcache: slots 0x200,
//! 0x328 and 0x338 from each class's vptr).
//!
//! What a match would need that the registry here does not hold (a
//! property its drivers set that is not modelled, the services of a class
//! not all here) is an `Err` naming it, never an answer.

use super::iokit::{self, Node, Prop};
use super::osserialize::{Graph, Id, Obj};

/// The keys `matchInternal` and `matchPassive` read (`IOKitKeys.h`,
/// `IOKitKeysPrivate.h`, `IOBSD.h`).
mod key {
    pub const USER: &str = "IOServiceNotificationUser";
    pub const EXCLAVE_PROXY: &str = "IOExclaveProxy";
    pub const COMPATIBILITY_MATCH: &str = "IOCompatibilityMatch";
    pub const COMPATIBILITY_PROPERTIES: &str = "IOCompatibilityProperties";
    pub const PROVIDER_CLASS: &str = "IOProviderClass";
    pub const NAME_MATCH: &str = "IONameMatch";
    pub const LOCATION_MATCH: &str = "IOLocationMatch";
    pub const PROPERTY_MATCH: &str = "IOPropertyMatch";
    pub const PROPERTY_EXISTS_MATCH: &str = "IOPropertyExistsMatch";
    pub const PATH_MATCH: &str = "IOPathMatch";
    pub const REGISTRY_ENTRY_ID: &str = "IORegistryEntryID";
    pub const MATCHED_SERVICE_COUNT: &str = "IOMatchedServiceCountMatch";
    pub const MATCH_CATEGORY: &str = "IOMatchCategory";
    pub const PARENT_MATCH: &str = "IOParentMatch";
    pub const RESOURCE_MATCH: &str = "IOResourceMatch";
    pub const RESOURCE_MATCHED: &str = "IOResourceMatched";
    pub const BSD_NAME: &str = "BSD Name";
    pub const BSD_MAJOR: &str = "BSD Major";
    pub const BSD_MINOR: &str = "BSD Minor";
    pub const BSD_UNIT: &str = "BSD Unit";
    pub const RESOURCES: &str = "IOResources";
}

/// `kIOServiceClassDone` and `kIOServiceInternalDone` (`IOServicePrivate.h`).
const CLASS_DONE: u32 = 0x0000_0001;
const INTERNAL_DONE: u32 = 0x0000_0002;

/// One side of a comparison: an object of the matching dictionary's graph,
/// or a registry property (with the dictionary it is in, whose earlier key
/// a [`Prop::SameAs`] names).
#[derive(Clone, Copy)]
enum V<'a> {
    G(&'a Graph, Id),
    P(&'a Prop),
    /// A string of a [`Prop::Strs`] array, an OSString.
    S(&'a [u8]),
}

/// An object's kind and contents, as `OSDynamicCast` sees it.
enum K<'a> {
    String(&'a [u8]),
    Symbol(&'a [u8]),
    Data(&'a [u8]),
    Number(u64),
    Bool(bool),
    Dict(Vec<(&'a [u8], V<'a>)>),
    Array(Vec<V<'a>>),
    Set(Vec<V<'a>>),
}

/// A dictionary's entries with each key that shares an earlier key's
/// object given that object.
fn prop_dict(entries: &[(String, Prop)]) -> Vec<(&[u8], V<'_>)> {
    entries
        .iter()
        .map(|(k, v)| {
            let v = match v {
                Prop::SameAs(other) => entries.iter().find(|(o, _)| o == other).map_or(v, |(_, p)| p),
                v => v,
            };
            (k.as_bytes(), V::P(v))
        })
        .collect()
}

impl<'a> V<'a> {
    fn kind(self) -> K<'a> {
        match self {
            V::G(g, id) => match g.get(id) {
                Obj::String(s) => K::String(s),
                Obj::Symbol(s) => K::Symbol(s),
                Obj::Data(d) => K::Data(d),
                Obj::Number { .. } => K::Number(g.u64_value(id).unwrap_or(0)),
                Obj::Bool(b) => K::Bool(*b),
                Obj::Dict(e) => K::Dict(e.iter().map(|(k, v)| (k.as_slice(), V::G(g, *v))).collect()),
                Obj::Array(e) => K::Array(e.iter().map(|&v| V::G(g, v)).collect()),
                Obj::Set(e) => K::Set(e.iter().map(|&v| V::G(g, v)).collect()),
            },
            V::P(p) => match p {
                Prop::Str(s) => K::String(s.as_bytes()),
                Prop::Sym(s) => K::Symbol(s.as_bytes()),
                Prop::Data(d) => K::Data(d),
                Prop::Num(v, bits) => K::Number(if *bits >= 64 { *v } else { v & (u64::MAX >> (64 - bits)) }),
                Prop::Bool(b) => K::Bool(*b),
                Prop::Strs(items) => K::Array(items.iter().map(|s| V::S(s.as_bytes())).collect()),
                Prop::Dict(e) => K::Dict(prop_dict(e)),
                Prop::Array(e) => K::Array(e.iter().map(V::P).collect()),
                // Resolved by the dictionary holding it.
                Prop::SameAs(_) => K::Bool(false),
            },
            V::S(s) => K::String(s),
        }
    }

    /// Whether `self` and `other` are one object: symbols are uniqued and
    /// the booleans are two constants; anything else is one object only
    /// within one graph.
    fn same(self, other: V<'_>) -> bool {
        match (self.kind(), other.kind()) {
            (K::Symbol(a), K::Symbol(b)) => a == b,
            (K::Bool(a), K::Bool(b)) => a == b,
            _ => match (self, other) {
                (V::G(g1, a), V::G(g2, b)) => std::ptr::eq(g1, g2) && a == b,
                (V::P(a), V::P(b)) => std::ptr::eq(a, b),
                _ => false,
            },
        }
    }
}

/// `strncmp(a, b, n) == 0` over `n` bytes both strings have.
fn strncmp_eq(a: &[u8], b: &[u8], n: usize) -> bool {
    for i in 0..n {
        let (x, y) = (a.get(i).copied().unwrap_or(0), b.get(i).copied().unwrap_or(0));
        if x != y {
            return false;
        }
        if x == 0 {
            return true;
        }
    }
    true
}

/// `OSString::isEqualTo(const OSString *)`: equal lengths, then
/// `strncmp` over the length (which stops at a NUL).
fn string_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && strncmp_eq(a, b, a.len())
}

/// `OSString::isEqualTo(const OSData *)` and `OSData::isEqualTo(const
/// OSString *)` (the same rule both ways): the data's bytes are the
/// string's, a trailing NUL beyond the string allowed.
fn string_data_eq(s: &[u8], d: &[u8]) -> bool {
    let mut len = d.len();
    if len != s.len() {
        if len.wrapping_sub(s.len()) == 1 && d[len - 1] == 0 {
            len -= 1;
        } else {
            return false;
        }
    }
    d[..len] == s[..len]
}

/// `a->isEqualTo(b)`: the receiver's class decides.
fn equal(a: V<'_>, b: V<'_>) -> bool {
    match (a.kind(), b.kind()) {
        // OSSymbol::isEqualTo: another symbol by identity, a string by its
        // characters; nothing else.
        (K::Symbol(x), K::Symbol(y)) => x == y,
        (K::Symbol(x), K::String(y)) => string_eq(x, y),
        // OSString::isEqualTo: a string (or symbol), or data.
        (K::String(x), K::String(y) | K::Symbol(y)) => string_eq(x, y),
        (K::String(x), K::Data(y)) => string_data_eq(x, y),
        // OSData::isEqualTo: data of the same length and bytes, or a
        // string (or symbol).
        (K::Data(x), K::Data(y)) => x == y,
        (K::Data(x), K::String(y) | K::Symbol(y)) => string_data_eq(y, x),
        // OSNumber::isEqualTo: the 64-bit values, whatever the sizes.
        (K::Number(x), K::Number(y)) => x == y,
        (K::Bool(x), K::Bool(y)) => x == y,
        // OSDictionary::isEqualTo: as many entries, each of this one's
        // keys in the other with an equal value.
        (K::Dict(x), K::Dict(y)) => x.len() == y.len() && x.iter().all(|(k, v)| y.iter().find(|(yk, _)| yk == k).is_some_and(|&(_, o)| equal(*v, o))),
        // OSArray::isEqualTo: as many, each equal to the other's at its
        // index.
        (K::Array(x), K::Array(y)) => x.len() == y.len() && x.iter().zip(&y).all(|(&p, &q)| equal(p, q)),
        // OSSet::isEqualTo: as many; each of the other's members this set
        // holds (by identity) passes, any other must equal this set's
        // member at its index.
        (K::Set(x), K::Set(y)) => x.len() == y.len() && y.iter().enumerate().all(|(i, &o1)| x.iter().any(|&m| m.same(o1)) || equal(o1, x[i])),
        _ => false,
    }
}

/// A registry entry's property as `copyProperty` gives it, with its
/// class's `getProperty` override: `Err` for one that may be the device's
/// but is not here.
fn copy_property(t: &[Node], i: u32, name: &str) -> Result<Option<Prop>, String> {
    if let Some(what) = super::storagestack::property_override(t, i, name) {
        return Err(what);
    }
    let n = &t[i as usize];
    // AGXAccelerator's copyProperty override (0xfffffff005be1898), not
    // followed.
    if n.class == super::accel::CLASS {
        return Err(format!("{}'s copyProperty of {name:?}", n.class));
    }
    if let Some(p) = iokit::live_prop(t, i, name) {
        return Ok(Some(p));
    }
    if let Some(p) = iokit::service_prop(n, name) {
        return Ok(Some(p.clone()));
    }
    if let Some((_, v)) = iokit::dt_table(n).find(|(k, _)| k == name) {
        return Ok(Some(Prop::Data(if n.kernel_only { Vec::new() } else { v.clone() })));
    }
    if iokit::property_unknown(t, i, name) {
        return Err(format!("the {} property {name:?}", iokit::name(t, i)));
    }
    Ok(None)
}

/// The value the dictionary `table` has for `k`.
fn get(g: &Graph, table: Id, k: &str) -> Option<Id> {
    g.lookup(table, k.as_bytes())
}

fn as_string(g: &Graph, id: Id) -> Option<&[u8]> {
    match g.get(id) {
        Obj::String(s) | Obj::Symbol(s) => Some(s),
        _ => None,
    }
}

/// The members an `OSCollectionIterator` gives of a collection (a
/// dictionary's keys, as symbols), or none for an object that is not one.
fn collection(g: &Graph, id: Id) -> Option<Vec<CollItem>> {
    match g.get(id) {
        Obj::Dict(e) => Some(e.iter().map(|(k, _)| CollItem::Key(k.clone())).collect()),
        Obj::Array(e) | Obj::Set(e) => Some(e.iter().map(|&v| CollItem::Obj(v)).collect()),
        _ => None,
    }
}

/// A member of a collection: an object, or a dictionary's key (a symbol).
enum CollItem {
    Obj(Id),
    Key(Vec<u8>),
}

impl CollItem {
    /// The member as an OSString (`OSDynamicCast(OSString, ...)`).
    fn string<'a>(&'a self, g: &'a Graph) -> Option<&'a [u8]> {
        match self {
            CollItem::Obj(id) => as_string(g, *id),
            CollItem::Key(k) => Some(k),
        }
    }
}

/// The names `compareNames` compares: one string, or a collection's
/// strings (stopping at its first member that is not one).
fn names_of(g: &Graph, names: Id) -> Vec<Vec<u8>> {
    if let Some(items) = collection(g, names) {
        return items.iter().map_while(|c| c.string(g).map(<[u8]>::to_vec)).collect();
    }
    as_string(g, names).map(|s| vec![s.to_vec()]).unwrap_or_default()
}

/// `CompareKey` of `IODTCompareNubName`: whether one of the names the
/// entry's property `prop` holds (an OSData of NUL-separated names, or an
/// OSString) is `key`, or begins with it less a final '*'.
fn compare_key(t: &[Node], i: u32, key: &[u8], prop: &str) -> Result<bool, String> {
    let names: Vec<u8> = match copy_property(t, i, prop)? {
        Some(Prop::Data(d)) => d,
        Some(Prop::Str(s) | Prop::Sym(s)) => [s.as_bytes(), b"\0"].concat(),
        _ => return Ok(false),
    };
    let wild = key.last() == Some(&b'*');
    let mut at = 0;
    while at < names.len() {
        let rest = &names[at..];
        let nlen = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
        let matched = if wild {
            nlen >= key.len() - 1 && strncmp_eq(key, rest, key.len() - 1)
        } else {
            key.len() == nlen && strncmp_eq(key, rest, key.len())
        };
        if matched {
            return Ok(true);
        }
        at += nlen + 1;
    }
    Ok(false)
}

/// `IODTCompareNubName`: the entry's name, compatible, device_type or
/// model names `name`.
fn dt_compare_nub_name(t: &[Node], i: u32, name: &[u8]) -> Result<bool, String> {
    for prop in ["name", "compatible", "device_type", "model"] {
        if compare_key(t, i, name, prop)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// `IORegistryEntry::compareName`: the entry's name is `name`.
fn entry_compare_name(t: &[Node], i: u32, name: &[u8]) -> bool {
    string_eq(iokit::name(t, i).as_bytes(), name)
}

/// The entry's `compareName`, by its class's override:
/// - `IOPlatformExpertDevice` (0xfffffff00780dda0): `IODTCompareNubName`.
/// - `IOPlatformDevice`: its platform expert's `compareNubName`, which
///   AppleARMPE takes from `IODTPlatformExpert` (0xfffffff00780cd6c):
///   `IODTCompareNubName`, else the entry's name.
/// - `AppleARMIODevice` (0xfffffff00598cf1c): `IODTCompareNubName`, else
///   the entry's name.
/// - `IOPCIDevice` (0xfffffff0064d2838): its bridge's `compareNubName`
///   (slot 0x5a8), every bridge here IOPCIBridge's: `IODTCompareNubName`.
/// - Every other class here keeps `IORegistryEntry::compareName`.
fn compare_name(t: &[Node], i: u32, name: &[u8]) -> Result<bool, String> {
    let class = iokit::class(t, i)?;
    let chain = iokit::superclasses(class);
    if i == 0 {
        return dt_compare_nub_name(t, i, name);
    }
    if chain.contains(&super::storagestack::PCI_DEVICE) {
        return dt_compare_nub_name(t, i, name);
    }
    if chain.contains(&super::platform::ARM_IO_DEVICE) || chain.contains(&super::platform::PLATFORM_DEVICE) {
        return Ok(dt_compare_nub_name(t, i, name)? || entry_compare_name(t, i, name));
    }
    Ok(entry_compare_name(t, i, name))
}

/// Whether the entry is registered: an instance its class's metaclass
/// tracks (`doServiceMatch` adds it, 0xfffffff0077b5174's caller) and a
/// service in the matched state. The platform expert device, the nubs the
/// platform's drivers published and IOResources are; every driver that
/// calls `registerService` on itself ([`super::storagestack::registers`]);
/// the GPU's accelerator, the display's framebuffer and IOSurfaceRoot,
/// which their frameworks find by matching. A device tree entry no driver
/// made a nub of is not a service of the plane.
fn registered(t: &[Node], i: u32) -> Result<bool, String> {
    let n = &t[i as usize];
    if n.class.is_empty() {
        return Ok(i == 0 || n.nub.is_some());
    }
    if n.class == super::platform::RESOURCES {
        return Ok(true);
    }
    if n.class == super::accel::CLASS || n.class == super::iomfb::CLASS || n.class == super::iosurface::CLASS {
        return Ok(true);
    }
    if let Some(r) = super::storagestack::registers(n.class) {
        return Ok(r);
    }
    if !iokit::superclasses(n.class).contains(&"IOService") {
        return Ok(false);
    }
    Err(format!("whether {} ({}) registers itself", n.name, n.class))
}

/// The class chain of entry `i`, most derived first, to OSObject.
fn chain(t: &[Node], i: u32) -> Vec<&'static str> {
    iokit::class(t, i).ok().and_then(iokit::class_chain).unwrap_or_default()
}

/// `applyToInstances` of `class`'s metaclass over the entries `members`
/// (each of the class, registered): its set holds its own instances and,
/// for each subclass, that subclass's set, each where it was added
/// (`OSMetaClass::addInstance`: a subclass's set joins its superclass's
/// when its first instance registers), walked depth first. An entry's
/// registration is its place in the registry here.
fn instance_order(t: &[Node], class: &str, members: &[u32]) -> Vec<u32> {
    enum Slot {
        One(u32),
        Sub(&'static str, Vec<u32>),
    }
    let mut slots: Vec<(u32, Slot)> = Vec::new();
    for &m in members {
        let c = chain(t, m);
        let Some(p) = c.iter().position(|&x| x == class) else { continue };
        if p == 0 {
            slots.push((m, Slot::One(m)));
            continue;
        }
        let sub = c[p - 1];
        match slots.iter_mut().find(|(_, s)| matches!(s, Slot::Sub(name, _) if *name == sub)) {
            Some((first, Slot::Sub(_, v))) => {
                *first = (*first).min(m);
                v.push(m);
            }
            _ => slots.push((m, Slot::Sub(sub, vec![m]))),
        }
    }
    slots.sort_by_key(|(at, _)| *at);
    let mut out = Vec::new();
    for (_, s) in slots {
        match s {
            Slot::One(m) => out.push(m),
            Slot::Sub(name, v) => out.extend(instance_order(t, name, &v)),
        }
    }
    out
}

/// `copyExistingServices(matching, kIOServiceMatchedState, once ?
/// kIONotifyOnce : 0)` over a dictionary `table` of graph `g` (to which,
/// as `IOTaskRegistryCompatibilityMatching` does for every task's
/// dictionary, IOServiceNotificationUser has been added): the services it
/// matches, in the order their class's instances are kept, the first only
/// with `once`.
pub fn existing(t: &[Node], g: &Graph, table: Id, once: bool) -> Result<Vec<u32>, String> {
    let provider = get(g, table, key::PROVIDER_CLASS);
    // IOResources, by IOResources::matchPropertyTable.
    if provider.is_some_and(|p| matches!(g.get(p), Obj::String(s) | Obj::Symbol(s) if string_eq(s, key::RESOURCES.as_bytes()))) {
        let Some(r) = t.iter().position(|n| n.class == super::platform::RESOURCES) else { return Ok(Vec::new()) };
        return Ok(if match_passive(t, r as u32, g, table, 0)? { vec![r as u32] } else { Vec::new() });
    }
    let class = provider.and_then(|p| as_string(g, p)).map(|s| String::from_utf8_lossy(s).into_owned());
    let base = class.as_deref().unwrap_or("IOService");
    let members: Vec<u32> = (0..t.len() as u32).filter(|&i| chain(t, i).contains(&base)).collect();
    let mut found = Vec::new();
    let mut gap: Option<String> = None;
    for i in instance_order(t, base, &members) {
        match registered(t, i) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(e) => {
                gap.get_or_insert(e);
                continue;
            }
        }
        // instanceMatch: matchInternal with the class done; what it leaves
        // undone, matchPassive with the class and itself done.
        let one = match match_internal(t, i, g, table, CLASS_DONE) {
            Ok((true, done)) if done == count(g, table) => Ok(true),
            Ok((true, _)) => match_passive(t, i, g, table, CLASS_DONE | INTERNAL_DONE),
            Ok((false, _)) => Ok(false),
            Err(e) => Err(e),
        };
        match one {
            Ok(true) => {
                found.push(i);
                if once {
                    break;
                }
            }
            Ok(false) => {}
            Err(e) => {
                gap.get_or_insert(e);
            }
        }
    }
    if once {
        found.truncate(1);
    }
    // Which of the class's services the device has beyond these is known
    // only for the classes whose every service is here; else a match by a
    // key no other service can share (a BSD name, a registry entry ID of
    // the registry here) or by a device tree path is still the answer.
    let complete = class.as_deref().is_some_and(class_complete);
    let unique = (get(g, table, key::BSD_NAME).is_some() && !found.is_empty()) || get(g, table, key::REGISTRY_ENTRY_ID).is_some();
    match gap {
        Some(e) if !(unique && !found.is_empty()) => Err(e),
        None if !complete && !unique => Err(format!("the services of class {base} beyond those here (the drivers' own are not here)")),
        _ => Ok(found),
    }
}

/// Whether every registered service of `class` is in the registry here:
/// the platform expert device is the one of its class (the device tree's
/// root, `IOPlatformExpertDevice::initWithArgs`).
fn class_complete(class: &str) -> bool {
    class == "IOPlatformExpertDevice"
        || super::storagestack::class_complete(class) || super::accel::class_complete(class) || super::iosurface::class_complete(class) || super::iomfb::class_complete(class)
}

/// `OSDictionary::getCount`.
fn count(g: &Graph, table: Id) -> u32 {
    match g.get(table) {
        Obj::Dict(e) => e.len() as u32,
        _ => 0,
    }
}

/// `IOService::matchInternal`: whether entry `i` matches what of `table`
/// IOService itself compares, and how many of its keys that was.
fn match_internal(t: &[Node], i: u32, g: &Graph, table: Id, options: u32) -> Result<(bool, u32), String> {
    let total = count(g, table);
    let mut done = 0;
    macro_rules! step {
        ($m:expr) => {{
            let m: bool = $m;
            if !m || done == total {
                return Ok((m, done));
            }
        }};
    }
    // A task's dictionary: no medium hidden from user space is here
    // (`kIOServiceUserInvisibleMatchState`: none has a provider with
    // IOPrimaryDriverTerminateOptions, which only IONVMeFamily's generic
    // personalities have).
    let user = get(g, table, key::USER).is_some();
    if user {
        done += 1;
        step!(true);
    }
    // No entry is assigned to an exclave: only the exp boot-arg gives
    // `IODeviceTreeAlloc` cause to set it.
    if get(g, table, key::EXCLAVE_PROXY).is_some() {
        return Ok((false, done));
    }
    // No task here has registry compatibility, and no entry has
    // IOCompatibilityProperties: matchProps stays none.
    if get(g, table, key::COMPATIBILITY_MATCH).is_some() {
        done += 1;
        if copy_property(t, i, key::COMPATIBILITY_PROPERTIES)?.is_some() {
            return Err(format!("the IOCompatibilityProperties of {}", iokit::name(t, i)));
        }
    }
    if let Some(s) = get(g, table, key::PROVIDER_CLASS).and_then(|p| as_string(g, p)) {
        done += 1;
        let m = options & CLASS_DONE != 0 || chain(t, i).iter().any(|c| c.as_bytes() == s);
        step!(m);
    }
    if let Some(names) = get(g, table, key::NAME_MATCH) {
        done += 1;
        let mut m = false;
        for n in names_of(g, names) {
            if compare_name(t, i, &n)? {
                m = true;
                break;
            }
        }
        step!(m);
    }
    if let Some(s) = get(g, table, key::LOCATION_MATCH).and_then(|p| as_string(g, p)) {
        done += 1;
        let m = location(t, i)?.is_some_and(|l| string_eq(l.as_bytes(), s));
        step!(m);
    }
    if let Some(obj) = get(g, table, key::PROPERTY_MATCH) {
        done += 1;
        let dicts: Vec<Id> = match g.get(obj) {
            Obj::Dict(_) => vec![obj],
            Obj::Array(e) | Obj::Set(e) => e.iter().copied().take_while(|&d| matches!(g.get(d), Obj::Dict(_))).collect(),
            _ => Vec::new(),
        };
        let mut m = false;
        for d in dicts {
            if property_match(t, i, g, d)? {
                m = true;
                break;
            }
        }
        step!(m);
    }
    if let Some(obj) = get(g, table, key::PROPERTY_EXISTS_MATCH) {
        done += 1;
        let keys: Vec<Vec<u8>> = match collection(g, obj) {
            Some(items) => items.iter().map_while(|c| c.string(g).map(<[u8]>::to_vec)).collect(),
            None => as_string(g, obj).map(|s| vec![s.to_vec()]).unwrap_or_default(),
        };
        let mut m = false;
        for k in keys {
            if table_has(t, i, &String::from_utf8_lossy(&k))? {
                m = true;
                break;
            }
        }
        step!(m);
    }
    if let Some(s) = get(g, table, key::PATH_MATCH).and_then(|p| as_string(g, p)) {
        done += 1;
        let path = String::from_utf8_lossy(s);
        let m = iokit::from_path(t, &path)? == Some(i);
        step!(m);
    }
    if let Some(n) = get(g, table, key::REGISTRY_ENTRY_ID).and_then(|n| g.u64_value(n)) {
        done += 1;
        step!(iokit::registry_id(i) == n);
    }
    if let Some(n) = get(g, table, key::MATCHED_SERVICE_COUNT).and_then(|n| g.u32_value(n)) {
        done += 1;
        // Its clients that are drivers (have a match category).
        let clients = iokit::links(t, i, iokit::Plane::Service, false)?;
        let mut c = 0u32;
        for k in clients {
            if copy_property(t, k, key::MATCH_CATEGORY)?.is_some() {
                c += 1;
            }
        }
        step!(c == n);
    }
    for k in [key::BSD_NAME, key::BSD_MAJOR, key::BSD_MINOR, key::BSD_UNIT] {
        if let Some(obj) = get(g, table, k) {
            done += 1;
            let prop = copy_property(t, i, k)?;
            let m = prop.as_ref().is_some_and(|p| equal(V::G(g, obj), V::P(p)));
            step!(m);
        }
    }
    Ok((true, done))
}

/// `copyLocation()`: the location the entry's driver gave it. A device
/// tree entry's is its unit address (`IODeviceTreeAlloc`), which is not
/// modelled.
fn location(t: &[Node], i: u32) -> Result<Option<String>, String> {
    let n = &t[i as usize];
    if n.class.is_empty() {
        return Err(format!("the location of the device tree entry {}", n.name));
    }
    Ok(iokit::location(n))
}

/// Whether entry `i`'s property table has `name` (`dictionaryWithProperties`
/// then `getObject`).
fn table_has(t: &[Node], i: u32, name: &str) -> Result<bool, String> {
    if iokit::properties(t, i).iter().any(|(k, _)| k == name) {
        return Ok(true);
    }
    if iokit::property_unknown(t, i, name) {
        return Err(format!("the {} property {name:?}", iokit::name(t, i)));
    }
    Ok(false)
}

/// IOPropertyMatch's `dictionaryWithProperties()->isEqualTo(dict, dict)`:
/// the table has at least as many entries as `dict`, and each of `dict`'s
/// keys, the table's value (the receiver) equal to `dict`'s.
fn property_match(t: &[Node], i: u32, g: &Graph, dict: Id) -> Result<bool, String> {
    let props = iokit::properties(t, i);
    let Obj::Dict(entries) = g.get(dict) else { return Ok(false) };
    if props.len() < entries.len() {
        if iokit::properties_missing(t, i).is_some() {
            return Err(format!("how many properties {} has", iokit::name(t, i)));
        }
        return Ok(false);
    }
    let resolved = prop_dict(&props);
    for (k, v) in entries {
        let name = String::from_utf8_lossy(k);
        match resolved.iter().find(|(pk, _)| *pk == k.as_slice()) {
            Some(&(_, p)) => {
                if !equal(p, V::G(g, *v)) {
                    return Ok(false);
                }
            }
            None if iokit::property_unknown(t, i, &name) => return Err(format!("the {} property {name:?}", iokit::name(t, i))),
            None => return Ok(false),
        }
    }
    Ok(true)
}

/// `IOService::compareProperty(table, key)`: true when the table has no
/// such key, else whether its value equals the entry's property.
fn compare_property(t: &[Node], i: u32, g: &Graph, table: Id, k: &str) -> Result<bool, String> {
    let Some(v) = get(g, table, k) else { return Ok(true) };
    Ok(copy_property(t, i, k)?.is_some_and(|p| equal(V::G(g, v), V::P(&p))))
}

/// The entry's `matchPropertyTable(table, score)` (slot 0x328), by its
/// class:
/// - `IOService`'s calls the one-argument form (slot 0x330), true but for
///   IOResources' (`IOResourcesMatchPropertyTable`).
/// - `IOMedia`'s (0xfffffff005976094, IOMedia.cpp) compares Content,
///   Content Hint, Ejectable, Leaf, Open, Preferred Block Size,
///   Removable, Size, UUID, Whole and Writable.
/// - `IOPCIDevice`'s (0xfffffff0064d279c) asks its bridge
///   (`matchNubWithPropertyTable`, slot 0x5a0, IOPCIBridge's for every
///   bridge here: `pciMatchNub` against the configuration registers, then
///   the tunnel checks, which no nub here is subject to).
/// - `IOHIDEventService`'s is its own (0xfffffff005aec640), not followed.
/// - The other classes here keep IOService's.
fn match_property_table(t: &[Node], i: u32, g: &Graph, table: Id) -> Result<bool, String> {
    let c = chain(t, i);
    if c.contains(&"IOHIDEventService") {
        return Err(format!("IOHIDEventService's matchPropertyTable on {}", iokit::name(t, i)));
    }
    if c.contains(&"IOMedia") {
        for k in ["Content", "Content Hint", "Ejectable", "Leaf", "Open", "Preferred Block Size", "Removable", "Size", "UUID", "Whole", "Writable"] {
            if !compare_property(t, i, g, table, k)? {
                return Ok(false);
            }
        }
        return Ok(true);
    }
    if c.contains(&super::storagestack::PCI_DEVICE) {
        return pci_match_nub(t, i, g, table);
    }
    if t[i as usize].class == super::platform::RESOURCES {
        return resources_match(t, i, g, table);
    }
    Ok(true)
}

/// `IOResourcesMatchPropertyTable`: each resource IOResourceMatch names
/// (one string, or a collection's members) is published; else, with
/// IOResourceMatched, that object is in the resources' IOResourceMatched
/// array (by identity: a symbol of the same characters).
fn resources_match(t: &[Node], i: u32, g: &Graph, table: Id) -> Result<bool, String> {
    if let Some(prop) = get(g, table, key::RESOURCE_MATCH) {
        let items: Vec<Option<Vec<u8>>> = match collection(g, prop) {
            Some(c) => c.iter().map(|m| m.string(g).map(<[u8]>::to_vec)).collect(),
            None => vec![as_string(g, prop).map(<[u8]>::to_vec)],
        };
        for s in items {
            let Some(s) = s else { return Ok(false) };
            if copy_property(t, i, &String::from_utf8_lossy(&s))?.is_none() {
                return Ok(false);
            }
        }
        return Ok(true);
    }
    if let Some(prop) = get(g, table, key::RESOURCE_MATCHED) {
        let Some(Prop::Array(keys)) = copy_property(t, i, key::RESOURCE_MATCHED)? else { return Ok(false) };
        return Ok(keys.iter().any(|k| V::P(k).same(V::G(g, prop))));
    }
    Ok(true)
}

/// `IOPCIBridge::pciMatchNub` (0xfffffff0064ca5e4, its key table at
/// 0xfffffff006edf8f0): IOPCIMatch against the vendor and device register
/// and then the subsystem's; IOPCIPrimaryMatch the former,
/// IOPCISecondaryMatch the latter; IOPCIClassMatch the class register
/// under 0xffffff00. Each value is a list of hex values, each with an
/// optional `&mask`.
fn pci_match_nub(t: &[Node], i: u32, g: &Graph, table: Id) -> Result<bool, String> {
    const KEYS: [(&str, &[u8], u32); 4] = [("IOPCIMatch", &[0x00 | 1, 0x2c], 0xffff_ffff), ("IOPCIPrimaryMatch", &[0x00], 0xffff_ffff), ("IOPCISecondaryMatch", &[0x2c], 0xffff_ffff), ("IOPCIClassMatch", &[0x08], 0xffff_ff00)];
    for (k, regs, mask) in KEYS {
        let Some(v) = get(g, table, k) else { continue };
        // The value is taken as an OSString unchecked.
        let Some(s) = as_string(g, v) else { return Err(format!("{k} given as other than a string")) };
        let mut m = false;
        for &r in regs {
            m = match_keys(super::storagestack::pci_config(t, i, r & 0xfc)?, s, mask);
            if m || r & 1 == 0 {
                break;
            }
        }
        if !m {
            return Ok(false);
        }
    }
    Ok(true)
}

/// `IOPCIBridge::matchKeys`: whether one of the values (`strtoul` base 16,
/// spaces skipped, `&` a mask) matches the register under its mask.
fn match_keys(reg: u32, keys: &[u8], default_mask: u32) -> bool {
    let strtoul = |s: &[u8]| -> (u64, usize) {
        let mut i = 0;
        while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
            i += 1;
        }
        let mut neg = false;
        if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
            neg = s[i] == b'-';
            i += 1;
        }
        if i + 1 < s.len() && s[i] == b'0' && (s[i + 1] | 0x20) == b'x' && s.get(i + 2).is_some_and(u8::is_ascii_hexdigit) {
            i += 2;
        }
        let start = i;
        let mut v: u64 = 0;
        while i < s.len() && s[i].is_ascii_hexdigit() {
            v = v.saturating_mul(16).saturating_add(u64::from((s[i] as char).to_digit(16).unwrap()));
            i += 1;
        }
        if i == start {
            return (0, 0);
        }
        // unsigned long's saturation, then the sign.
        (if neg { v.wrapping_neg() } else { v }, i)
    };
    let mut at = 0;
    loop {
        let (value, used) = strtoul(&keys[at..]);
        if used == 0 {
            return false;
        }
        let mut next = at + used;
        while keys.get(next) == Some(&b' ') {
            next += 1;
        }
        let mask = if keys.get(next) == Some(&b'&') {
            let (m, u) = strtoul(&keys[next + 1..]);
            next += 1 + u;
            m
        } else {
            u64::from(default_mask)
        };
        if value & mask == u64::from(reg) & mask {
            return true;
        }
        at = next;
    }
}

/// `IOService::matchLocation` of entry `i`: the first of it and its
/// providers whose class answers itself (`IOPlatformDevice`,
/// `AppleARMIODevice` 0xfffffff00598cf7c, `IOPCIDevice`); none past the
/// root.
fn match_location(t: &[Node], i: u32) -> Result<Option<u32>, String> {
    let mut at = i;
    loop {
        let c = chain(t, at);
        if [super::platform::PLATFORM_DEVICE, super::platform::ARM_IO_DEVICE, super::storagestack::PCI_DEVICE].iter().any(|k| c.contains(k)) {
            return Ok(Some(at));
        }
        match iokit::provider(t, at)? {
            Some(p) => at = p,
            None => return Ok(None),
        }
    }
}

/// `IOService::matchPassive(table, options)` of entry `i`: its own match,
/// then IOParentMatch's anywhere up its providers, or IOLocationMatch's at
/// its provider's `matchLocation`.
fn match_passive(t: &[Node], i: u32, g: &Graph, table: Id, options: u32) -> Result<bool, String> {
    let (mut at, mut table, mut options) = (i, table, options);
    let mut match_parent = false;
    loop {
        let mut matched;
        loop {
            let total = count(g, table);
            if options & INTERNAL_DONE == 0 {
                let (m, done) = match_internal(t, at, g, table, options)?;
                matched = m;
                if !m || done == total {
                    break;
                }
            }
            matched = match_property_table(t, at, g, table)?;
            if !matched {
                break;
            }
            options = 0;
            match_parent = false;
            if let Some(next) = get(g, table, key::PARENT_MATCH).filter(|&n| matches!(g.get(n), Obj::Dict(_))) {
                matched = false;
                match_parent = true;
                table = next;
                break;
            }
            let Some(next) = get(g, table, key::LOCATION_MATCH).filter(|&n| matches!(g.get(n), Obj::Dict(_))) else { break };
            table = next;
            matched = false;
            match iokit::provider(t, at)? {
                Some(p) => match match_location(t, p)? {
                    Some(l) => at = l,
                    None => break,
                },
                None => break,
            }
        }
        if matched {
            return Ok(true);
        }
        if !match_parent {
            return Ok(false);
        }
        match iokit::provider(t, at)? {
            Some(p) => at = p,
            None => return Ok(false),
        }
    }
}

/// A task's matching dictionary, as `internal_io_service_get_matching_services`
/// and its kin take it: `OSUnserializeXML` of the bytes (the binary form
/// here), which must be a dictionary (kIOReturnBadArgument), then
/// IOServiceNotificationUser set true. `Err` for XML text, which is not
/// read here.
pub fn task_dictionary(bytes: &[u8]) -> Result<Option<(Graph, Id)>, String> {
    use super::osserialize::Parsed;
    let (mut g, root) = match super::osserialize::unserialize(bytes) {
        Parsed::Binary(Some(x)) => x,
        Parsed::Binary(None) | Parsed::Invalid => return Ok(None),
        Parsed::Xml => return Err("a matching dictionary in XML".to_string()),
    };
    if !matches!(g.get(root), Obj::Dict(_)) {
        return Ok(None);
    }
    let t = g.add(Obj::Bool(true));
    g.dict_set(root, key::USER.as_bytes(), t);
    Ok(Some((g, root)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::darwin::osserialize::serialize_binary;

    /// A task's dictionary of `entries` as IOKit.framework sends it, read
    /// back as the kernel reads it.
    fn dict(entries: &[(&str, Obj)]) -> (Graph, Id) {
        let mut g = Graph::default();
        let d = g.add(Obj::Dict(Vec::new()));
        for (k, v) in entries {
            let v = match v {
                Obj::Dict(e) => {
                    let inner = g.add(Obj::Dict(Vec::new()));
                    for (ik, iv) in e {
                        g.dict_set(inner, ik, *iv);
                    }
                    inner
                }
                v => g.add(v.clone()),
            };
            g.dict_set(d, k.as_bytes(), v);
        }
        task_dictionary(&serialize_binary(&g, d)).unwrap().unwrap()
    }

    fn s(v: &str) -> Obj {
        Obj::String(v.as_bytes().to_vec())
    }

    #[test]
    fn objects_compare_as_libkern_compares_them() {
        let p = |p: &Prop| V::P(Box::leak(Box::new(p.clone())));
        let str_ = Prop::Str("disk0".to_string());
        let sym = Prop::Sym("disk0".to_string());
        let data = Prop::Data(b"disk0\0".to_vec());
        // A string equals data of its bytes and a NUL, both ways; a symbol
        // does not compare data at all.
        assert!(equal(p(&str_), p(&data)) && equal(p(&data), p(&str_)));
        assert!(!equal(p(&sym), p(&data)));
        assert!(equal(p(&data), p(&sym)));
        assert!(equal(p(&sym), p(&str_)) && equal(p(&str_), p(&sym)));
        assert!(!equal(p(&Prop::Data(b"disk0\0\0".to_vec())), p(&str_)));
        // Numbers compare their 64-bit values, whatever their sizes.
        assert!(equal(p(&Prop::Num(1, 32)), p(&Prop::Num(1, 64))));
        assert!(!equal(p(&Prop::Num(1, 32)), p(&Prop::Bool(true))));
        // Collections: their counts, then each member by the receiver's.
        let a = Prop::Dict(vec![("a".to_string(), Prop::Num(1, 8)), ("b".to_string(), str_.clone())]);
        let b = Prop::Dict(vec![("b".to_string(), data.clone()), ("a".to_string(), Prop::Num(1, 64))]);
        assert!(equal(p(&a), p(&b)));
        assert!(!equal(p(&Prop::Array(vec![sym.clone()])), p(&Prop::Array(vec![data.clone()]))));
        assert!(equal(p(&Prop::Strs(vec!["x".to_string()])), p(&Prop::Array(vec![Prop::Sym("x".to_string())]))));
        assert!(match_keys(0x2002_106b, b"0x2002106b", 0xffff_ffff));
        assert!(match_keys(0x0180_0200, b"0x01800200&0xffffff00", 0xffff_ff00));
        assert!(match_keys(0x1234_106b, b"0x1 0x106b&0xffff", 0xffff_ffff));
        assert!(!match_keys(0x1234_106b, b"zz", 0xffff_ffff));
    }

    #[test]
    fn storage_services_match_by_every_kind_of_key() {
        let mut t = Vec::new();
        super::super::storagestack::add(&mut t, None);
        let find = |name: &str| t.iter().position(|n| n.name == name).unwrap() as u32;
        let media = find("AppleAPFSMedia");
        let name = super::super::storage::container_bsd_name();
        let (_, minor) = super::super::storage::media_by_name(&name).unwrap();
        // BSD Major and Minor as the numbers CFNumber makes (32 and 64
        // bits): the property's 32-bit numbers equal them.
        let (g, d) = dict(&[("IOProviderClass", s("IOMedia")), ("BSD Name", s(&name)), ("BSD Major", Obj::Number { size: 32, value: u64::from(super::super::storage::DISK_MAJOR) }), ("BSD Minor", Obj::Number { size: 64, value: u64::from(minor) })]);
        assert_eq!(existing(&t, &g, d, false), Ok(vec![media]));
        let (g, d) = dict(&[("BSD Name", s(&name)), ("BSD Minor", Obj::Number { size: 32, value: u64::from(minor) + 1 })]);
        assert_eq!(existing(&t, &g, d, false), Err("the services of class IOService beyond those here (the drivers' own are not here)".to_string()));
        // A key neither IOService nor IOMedia compares is passed over;
        // IOMedia's own keys are compared.
        let (g, d) = dict(&[("IOProviderClass", s("AppleAPFSMedia")), ("Unknown Key", Obj::Bool(true)), ("Content Hint", s(super::super::storagestack::APFS_CONTAINER_HINT))]);
        assert_eq!(existing(&t, &g, d, false), Ok(vec![media]));
        let (g, d) = dict(&[("IOProviderClass", s("AppleAPFSMedia")), ("Whole", Obj::Bool(false))]);
        assert_eq!(existing(&t, &g, d, false), Ok(vec![]));
        // The partition schemes never register themselves.
        let (g, d) = dict(&[("IOProviderClass", s("AppleAPFSContainerScheme"))]);
        assert_eq!(existing(&t, &g, d, false), Ok(vec![]));
        // IOPropertyMatch compares the entry's table with the entry's
        // object as the receiver: a symbol's Content does not equal data.
        let mut inner = Graph::default();
        let _ = &mut inner;
        let (mut g, d) = dict(&[("IOProviderClass", s("AppleAPFSMedia"))]);
        let pm = g.add(Obj::Dict(Vec::new()));
        let v = g.add(s(super::super::storagestack::APFS_CONTAINER_HINT));
        g.dict_set(pm, b"Content", v);
        g.dict_set(d, b"IOPropertyMatch", pm);
        assert_eq!(existing(&t, &g, d, false), Ok(vec![media]));
        // IOParentMatch: some provider up the plane matches.
        let (mut g, d) = dict(&[("IOProviderClass", s("AppleAPFSMedia"))]);
        let pm = g.add(Obj::Dict(Vec::new()));
        let v = g.add(s("IOBlockStorageDriver"));
        g.dict_set(pm, b"IOProviderClass", v);
        g.dict_set(d, b"IOParentMatch", pm);
        assert_eq!(existing(&t, &g, d, false), Ok(vec![media]));
        // Volumes: the class's instances in their order; the first only
        // for a single service.
        let (g, d) = dict(&[("IOProviderClass", s("AppleAPFSVolume"))]);
        let vols = existing(&t, &g, d, false).unwrap();
        assert_eq!(vols.len(), super::super::storage::VOLUMES.len());
        assert_eq!(existing(&t, &g, d, true), Ok(vec![vols[0]]));
        // Names: a medium has no device tree names, only its own.
        let (g, d) = dict(&[("IOProviderClass", s("AppleAPFSVolume")), ("IONameMatch", s("Preboot"))]);
        assert_eq!(existing(&t, &g, d, false), Ok(vec![find("Preboot")]));
        // A namespace's WriteCacheState is its getProperty override's.
        assert!(copy_property(&t, find("NS_01"), "WriteCacheState").is_err());
    }
}
