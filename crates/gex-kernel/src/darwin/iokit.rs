//! IOKit as a task reaches it (`iokit/Kernel/IOUserClient.cpp`), over the
//! device's own device tree: the registry's `IODeviceTree` plane. Of the
//! `IOService` plane's drivers, those on the path to the GPU
//! ([`super::platform`], [`super::accel`]) and to the display
//! ([`super::iomfb`]) and APFS's are here; what would need the others is
//! reported.

use std::sync::OnceLock;

/// One entry of the device tree.
#[derive(Debug)]
pub struct Node {
    pub name: String,
    pub props: Vec<(String, Vec<u8>)>,
    /// A service's class (the `IOService` plane), and its typed properties;
    /// a device tree node is empty and has `OSData` properties only.
    pub class: &'static str,
    pub service_props: Vec<(String, Prop)>,
    pub parent: Option<u32>,
    pub children: Vec<u32>,
    /// A `kernel-only` node: a release kernel's `IODeviceTreeAlloc` makes
    /// each of its properties unserializable, so a task reads them empty.
    pub kernel_only: bool,
    /// A device tree entry a driver made a nub of: the nub's class, and its
    /// provider in the `IOService` plane.
    pub nub: Option<(&'static str, u32)>,
    /// A service a driver also attached in the `IODeviceTree` plane.
    pub dt: Option<DtLink>,
    /// What the service's property table has of the device's.
    pub table: Table,
}

/// A service's link in the `IODeviceTree` plane (`attachToParent(parent,
/// gIODTPlane)`): its parent there, and the name and location it was given
/// in that plane (`setName`/`setLocation` with the plane, which key its
/// registry table by the plane's `pathNameKey` and `pathLocationKey`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DtLink {
    pub parent: u32,
    pub name: String,
    pub location: String,
}

/// What a service's property table has of the device's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Table {
    /// What its drivers set beyond what is here is not modelled
    /// ([`property_unknown`]'s rules).
    Drivers,
    /// All of it.
    Complete,
    /// All but these keys, each with why it is not here (its value is set
    /// at run time, or by code not followed).
    Lacks(Vec<(&'static str, &'static str)>),
    /// Some of it: what this says is not modelled, which may be any key.
    Partial(String),
}

/// A property of a service, as `OSSerialize` writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Prop {
    Str(String),
    Bool(bool),
    Strs(Vec<String>),
    /// An `OSNumber`: its value and its size in bits.
    Num(u64, u32),
    Data(Vec<u8>),
    /// An `OSSymbol` (what `setProperty(const char *, const char *)` sets).
    Sym(String),
    /// An `OSDictionary` of named values, in its order.
    Dict(Vec<(String, Prop)>),
    /// An `OSArray`.
    Array(Vec<Prop>),
    /// In a dictionary, the very object an earlier key of it holds (one
    /// object set under two keys, which `OSSerialize` writes once and then
    /// refers to).
    SameAs(String),
}

/// The classes a service belongs to, most derived first.
pub fn superclasses(class: &str) -> &'static [&'static str] {
    if let s @ [_, ..] = super::storagestack::superclasses(class) {
        return s;
    }
    match class {
        "IOPlatformExpertDevice" => &["IOPlatformExpertDevice", "IOService", "IORegistryEntry"],
        "IORegistryEntry" => &["IORegistryEntry"],
        "IOUserClient" => &["IOUserClient", "IOService", "IORegistryEntry"],
        "AppleAPFSUserClient" => &["AppleAPFSUserClient", "IOUserClient", "IOService", "IORegistryEntry"],
        "IOSurfaceRoot" | "IOSurfaceRootUserClient" => super::iosurface::superclasses(class),
        super::iomfb::CLASS | super::iomfb::UC_CLASS => super::iomfb::superclasses(class),
        _ => match super::platform::superclasses(class) {
            [] => super::accel::superclasses(class),
            s => s,
        },
    }
}

static TREE: OnceLock<Vec<Node>> = OnceLock::new();

/// Parse the flattened device tree (`DeviceTree.im4p`'s payload): each node
/// a count of properties and of children, each property a name of 32 bytes
/// and a length whose top bit iBoot uses, its value padded to 4 bytes.
pub fn parse(b: &[u8]) -> Result<Vec<Node>, String> {
    fn node(b: &[u8], at: &mut usize, parent: Option<u32>, out: &mut Vec<Node>) -> Result<u32, String> {
        let word = |o: usize| b.get(o..o + 4).map(|w| u32::from_le_bytes(w.try_into().unwrap())).ok_or("the device tree ends early".to_string());
        let (nprops, nchildren) = (word(*at)?, word(*at + 4)?);
        *at += 8;
        let mut props = Vec::with_capacity(nprops as usize);
        for _ in 0..nprops {
            let raw = b.get(*at..*at + 32).ok_or("the device tree ends early")?;
            let name = String::from_utf8_lossy(&raw[..raw.iter().position(|&c| c == 0).unwrap_or(32)]).into_owned();
            let len = (word(*at + 32)? & 0x7fff_ffff) as usize;
            *at += 36;
            props.push((name, b.get(*at..*at + len).ok_or("the device tree ends early")?.to_vec()));
            *at += (len + 3) & !3;
        }
        let name = props.iter().find(|(k, _)| k == "name").map_or(String::new(), |(_, v)| String::from_utf8_lossy(&v[..v.iter().position(|&c| c == 0).unwrap_or(v.len())]).into_owned());
        let id = out.len() as u32;
        let kernel_only = props.iter().any(|(k, _)| k == "kernel-only");
        out.push(Node { name, props, class: "", service_props: Vec::new(), parent, children: Vec::new(), kernel_only, nub: None, dt: None, table: Table::Drivers });
        for _ in 0..nchildren {
            let c = node(b, at, Some(id), out)?;
            out[id as usize].children.push(c);
        }
        Ok(id)
    }
    let mut out = Vec::new();
    let mut at = 0;
    node(b, &mut at, None, &mut out)?;
    Ok(out)
}

/// Install the device tree the boot payload carries, and the services
/// published over it: the platform's, the GPU's, the display's and the
/// storage's ([`super::storagestack`]).
pub fn set_tree(b: &[u8]) -> Result<(), String> {
    let mut t = parse(b)?;
    let io = super::platform::add(&mut t);
    if let Some(io) = io {
        if let Some(gpu) = super::platform::arm_io_nub(&mut t, io, "gpu,t8011") {
            super::accel::add_service(&mut t, gpu);
        }
        if let Some(disp) = super::platform::arm_io_nub(&mut t, io, "disp0,t8011") {
            super::iomfb::add_service(&mut t, disp);
        }
    }
    super::storagestack::add(&mut t, io);
    let resources = super::platform::add_resources(&mut t);
    super::iosurface::add_service(&mut t, resources);
    add_root(&mut t);
    let _ = TREE.set(t);
    Ok(())
}

/// `IORegistryEntry::initialize`: the registry's root, "Root"; the device
/// tree hangs from it in the `IODeviceTree` plane.
fn add_root(t: &mut Vec<Node>) {
    t.push(Node { name: "Root".to_string(), props: Vec::new(), class: "IORegistryEntry", service_props: Vec::new(), parent: None, children: vec![0], kernel_only: false, nub: None, dt: None, table: Table::Drivers });
}

/// Whether the kernel sets the root entry's property `name`: the planes
/// (`IORegistryEntry::initialize`), IOKit's build version and diagnostics
/// and the OS build version (`StartIOKit`), the console's lock and users
/// (`IOService::updateConsoleUsers`), and the kernel's CPU type and the
/// kernel collection's kext count (`OSKext`). The root has no other.
pub fn root_has(name: &str) -> bool {
    matches!(
        name,
        "IORegistryPlanes" | "IOKitBuildVersion" | "IOKitDiagnostics" | "OS Build Version" | "IOConsoleLocked" | "IOConsoleUsers" | "OSKernelCPUType" | "OSKernelCPUSubtype" | "OSPrelinkKextCount"
    )
}

/// The registry's root entry (`IORegistryEntry::getRegistryRoot`), the
/// last of the tree; none when the boot payload had no device tree.
pub fn root() -> Option<u32> {
    tree().len().checked_sub(1).map(|i| i as u32)
}

/// A registry plane (`IORegistryEntry::getPlane`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plane {
    Service,
    DeviceTree,
}

/// The plane of a name; `Err` for one whose links are not here: the power
/// plane, and the planes families make (and a name that is none, which
/// xnu answers as no plane).
pub fn plane(name: &[u8]) -> Result<Plane, String> {
    match name {
        b"IOService" => Ok(Plane::Service),
        b"IODeviceTree" => Ok(Plane::DeviceTree),
        _ => Err(format!("the {} plane", String::from_utf8_lossy(name))),
    }
}

/// `getParentSetReference` or `getChildSetReference` in `plane`: the
/// entries the entry is linked to there, in the order they were attached;
/// `Err` for links that drivers make. The device tree is all of the
/// `IODeviceTree` plane (the platform expert's `deleteList` takes none
/// away). Its root is the `IOPlatformExpertDevice`, also the root's child
/// in the `IOService` plane, where the platform's drivers hang from it and
/// the other device tree entries are its nubs or not.
pub fn links(t: &[Node], i: u32, plane: Plane, parents: bool) -> Result<Vec<u32>, String> {
    let Some(n) = t.get(i as usize) else { return Ok(Vec::new()) };
    let root = t.len() as u32 - 1;
    if i == root {
        return match (plane, parents) {
            (_, true) => Ok(Vec::new()),
            (Plane::DeviceTree, false) => Ok(n.children.clone()),
            (Plane::Service, false) => Err("the registry root's children in the IOService plane (IOResources, IOUserResources and the platform)".to_string()),
        };
    }
    // The services a driver attached below an entry in the IODeviceTree
    // plane, after the device tree's own children.
    let dt_children = || t.iter().enumerate().filter(|(_, c)| c.dt.as_ref().is_some_and(|d| d.parent == i)).map(|(c, _)| c as u32);
    if n.class.is_empty() {
        return match (plane, parents) {
            (Plane::DeviceTree, true) => Ok(vec![n.parent.unwrap_or(root)]),
            (Plane::DeviceTree, false) => Ok(n.children.iter().copied().chain(dt_children()).collect()),
            (Plane::Service, true) => provider(t, i).map(|p| p.into_iter().collect()),
            (Plane::Service, false) if i == 0 => Err("the platform expert device's children in the IOService plane (its drivers)".to_string()),
            (Plane::Service, false) if n.nub.is_some() => Err(format!("the drivers matched on {} (its children in the IOService plane)", n.name)),
            (Plane::Service, false) => Err(format!("whether the platform made {} a nub in the IOService plane", n.name)),
        };
    }
    match (plane, parents) {
        (Plane::DeviceTree, true) => Ok(n.dt.iter().map(|d| d.parent).collect()),
        (Plane::DeviceTree, false) => Ok(dt_children().collect()),
        (Plane::Service, true) => provider(t, i).map(|p| p.into_iter().collect()),
        // The user clients a service has opened are attached to it, and
        // they are not registry entries here.
        (Plane::Service, false) if n.class == super::accel::CLASS || n.class == super::iomfb::CLASS => Err(format!("the user clients of {} as its children in the IOService plane", n.name)),
        (Plane::Service, false) if super::platform::is_driver(n.class) => Err(format!("the nubs and clients of {} (its children in the IOService plane)", n.name)),
        (Plane::Service, false) if n.class == super::platform::RESOURCES => Err("the services matched on IOResources (its children in the IOService plane)".to_string()),
        (Plane::Service, false) => match super::storagestack::children_unknown(n.class) {
            Some(what) => Err(format!("{what} (children of {} in the IOService plane)", n.name)),
            None => Ok(n.children.clone()),
        },
    }
}

/// The entry's provider, its parent in the `IOService` plane: none for the
/// registry's root; the root for the platform expert device and for
/// IOResources; a nub's driver; a driver's nub. `Err` for a device tree
/// entry the platform's drivers here did not make a nub of.
pub fn provider(t: &[Node], i: u32) -> Result<Option<u32>, String> {
    let Some(n) = t.get(i as usize) else { return Ok(None) };
    let root = t.len() as u32 - 1;
    if i == root {
        return Ok(None);
    }
    if n.class.is_empty() {
        return match n.nub {
            _ if i == 0 => Ok(Some(root)),
            Some((_, p)) => Ok(Some(p)),
            None => Err(format!("whether the platform made {} a nub in the IOService plane", n.name)),
        };
    }
    if n.class == super::platform::RESOURCES {
        return Ok(Some(root));
    }
    n.parent.map(Some).ok_or_else(|| format!("the provider of {} (the storage controller)", n.name))
}

/// `IORegistryEntry::getName()`: the device tree root's is its first
/// `compatible` name (`IODeviceTreeAlloc`), its `IODeviceTree` plane name
/// staying `device-tree`.
pub fn name(t: &[Node], i: u32) -> String {
    let Some(n) = t.get(i as usize) else { return String::new() };
    if i == 0 {
        if let Some((_, v)) = n.props.iter().find(|(k, _)| k == "compatible") {
            return String::from_utf8_lossy(&v[..v.iter().position(|&c| c == 0).unwrap_or(v.len())]).into_owned();
        }
    }
    n.name.clone()
}

/// The entry's class: a device tree entry other than the root is an
/// `IOService` that a driver may have replaced with a nub of its own class:
/// those the drivers here made ([`super::platform`]) have theirs, and the
/// others' are the platform's to say.
pub fn class(t: &[Node], i: u32) -> Result<&'static str, String> {
    let Some(n) = t.get(i as usize) else { return Err("no such entry".to_string()) };
    if !n.class.is_empty() {
        return Ok(n.class);
    }
    if i == 0 {
        return Ok("IOPlatformExpertDevice");
    }
    if let Some((class, _)) = n.nub {
        return Ok(class);
    }
    Err(format!("the class of the device tree entry {}", n.name))
}

/// What entry `i`'s whole property table lacks of the device's, for
/// `io_registry_entry_get_properties_bin_buf`; none when the entry has
/// all of it.
pub fn properties_missing(t: &[Node], i: u32) -> Option<String> {
    let n = t.get(i as usize)?;
    match &n.table {
        Table::Complete => None,
        Table::Lacks(keys) => Some(keys.iter().map(|(k, why)| format!("{k} ({why})")).collect::<Vec<_>>().join(", ")),
        Table::Partial(what) => Some(what.clone()),
        Table::Drivers if !property_unknown(t, i, "") => None,
        Table::Drivers => Some("the properties its drivers set".to_string()),
    }
}

/// Entry `i`'s properties in its table's order, the device tree's first
/// (a kernel-only entry's as empty data), then its service's, the live
/// values in place of their keys.
pub fn properties(t: &[Node], i: u32) -> Vec<(String, Prop)> {
    let Some(n) = t.get(i as usize) else { return Vec::new() };
    let mut out: Vec<(String, Prop)> = dt_table(n).map(|(k, v)| (k.clone(), Prop::Data(if n.kernel_only { Vec::new() } else { v.clone() }))).collect();
    for (k, v) in &n.service_props {
        match out.iter_mut().find(|(o, _)| o == k) {
            Some(slot) => slot.1 = v.clone(),
            None => out.push((k.clone(), v.clone())),
        }
    }
    for (k, v) in out.iter_mut() {
        if let Some(l) = live_prop(t, i, k) {
            *v = l;
        }
    }
    out
}

/// Whether a property entry `i` lacks may yet be one the device's entry
/// has, which is reported rather than answered missing (`""` asking
/// whether any may be):
/// - An entry whose whole table is here has no other; one that lacks
///   only some keys may have those ([`Table`]).
/// - The registry's root has only the properties [`root_has`] names.
/// - A device tree entry that no driver here made a nub of has only its
///   own, and IOSurfaceRoot only those it is given
///   ([`super::iosurface::is_service`]).
/// - IOResources has the resources kexts and user space publish besides
///   those modelled ([`super::platform`]), and IOResourceMatched.
/// - Every other entry has properties its drivers set that are not
///   modelled. The exception is `IOClassNameOverride`, which no entry here
///   has: in the kernelcache only IOSkywalkFamily sets it, on its own
///   objects ("IO80211Controller", 0xfffffff00593be08), and the kernel only
///   names it among the keys IODTNVRAM's `skipKey` passes over
///   (0xfffffff007816644). IOKit.framework asks for it whenever
///   `io_object_conforms_to` says no. On the display's framebuffer and its nub, so are
///   the names no driver sets there ([`super::iomfb::property_absent`]).
pub fn property_unknown(t: &[Node], i: u32, name: &str) -> bool {
    let Some(n) = t.get(i as usize) else { return false };
    if name == "IOClassNameOverride" {
        return false;
    }
    match &n.table {
        Table::Complete => return false,
        Table::Lacks(keys) => return name.is_empty() || keys.iter().any(|(k, _)| *k == name),
        Table::Partial(_) => return true,
        Table::Drivers => {}
    }
    if i as usize + 1 == t.len() {
        return root_has(name);
    }
    if n.class == super::platform::RESOURCES {
        return true;
    }
    if n.class.is_empty() && n.nub.is_none() && i != 0 || n.class == super::iosurface::CLASS {
        return false;
    }
    let display = n.class == super::iomfb::CLASS || t.iter().any(|m| m.class == super::iomfb::CLASS && m.parent == Some(i));
    if display && super::iomfb::property_absent(t, i, name) {
        return false;
    }
    true
}

/// A property entry `i`'s driver keeps and may change while it runs,
/// ahead of its fixed ones: a medium's open state
/// ([`super::storagestack::live_prop`]), the framebuffer's published
/// runtime properties ([`super::iomfb::rtprop`]) and its console mode
/// (`SystemConsoleMode`).
pub fn live_prop(t: &[Node], i: u32, name: &str) -> Option<Prop> {
    if let Some(p) = super::storagestack::live_prop(t, i, name) {
        return Some(p);
    }
    if t.get(i as usize)?.class != super::iomfb::CLASS {
        return None;
    }
    if name == "SystemConsoleMode" {
        return super::iomfb::swap::console_property().map(Prop::Bool);
    }
    super::iomfb::rtprop::published(name)
}

/// The service's own property `name`, a key that shares another's object
/// giving that object.
pub fn service_prop<'a>(n: &'a Node, name: &str) -> Option<&'a Prop> {
    let find = |name: &str| n.service_props.iter().find(|(k, _)| *k == name).map(|(_, p)| p);
    match find(name)? {
        Prop::SameAs(other) => find(other),
        p => Some(p),
    }
}

/// Entry `i`'s property `name` serialized, as `IOCopyPropertyCompatible`
/// copies it (`copyProperty`, then the entry's IOUserServiceProperties or
/// IOCompatibilityProperties, which no entry here has): a live value, the
/// service's, else the device tree's (empty for a kernel-only entry's).
/// `Err` names a property that is absent here but may be the device's
/// ([`property_unknown`]).
pub fn lookup(t: &[Node], i: u32, name: &str) -> Result<Option<Vec<u8>>, String> {
    let Some(node) = t.get(i as usize) else { return Ok(None) };
    if let Some(what) = super::storagestack::property_override(t, i, name) {
        return Err(what);
    }
    if let Some(p) = live_prop(t, i, name) {
        return Ok(Some(serialize_prop(&p)));
    }
    if let Some(p) = service_prop(node, name) {
        return Ok(Some(serialize_prop(p)));
    }
    if let Some((_, value)) = dt_table(node).find(|(k, _)| *k == name) {
        return Ok(Some(serialize_data(if node.kernel_only { &[] } else { value })));
    }
    if let Table::Lacks(keys) = &node.table {
        if let Some((_, why)) = keys.iter().find(|(k, _)| *k == name) {
            return Err(format!("the {} property {name:?} ({why})", self::name(t, i)));
        }
    }
    if property_unknown(t, i, name) {
        return Err(format!("the {} property {name:?}", self::name(t, i)));
    }
    Ok(None)
}

/// `is_io_registry_entry_get_property_bin_buf`'s recursive search: the
/// entry's own property, else the first an `IORegistryIterator` over its
/// links in `plane` with `options` finds (depth first; its parents with
/// `kIORegistryIterateParents`), passing over each entry whose value
/// `allowed` (the MAC check of that entry) refuses. The value, and whether
/// a refusal passed one over (kIOReturnNotPermitted rather than
/// kIOReturnNotFound when none is found).
pub fn search(t: &[Node], i: u32, plane: Plane, options: u32, name: &str, mut allowed: impl FnMut(u32) -> bool) -> Result<(Option<Vec<u8>>, bool), String> {
    if let Some(v) = lookup(t, i, name)? {
        return Ok((Some(v), false));
    }
    let mut it = RegistryIter::new(i, plane, options);
    let mut refused = false;
    while let Some(e) = it.next(t)? {
        let Some(v) = lookup(t, e, name)? else { continue };
        if !allowed(e) {
            refused = true;
            continue;
        }
        return Ok((Some(v), refused));
    }
    Ok((None, refused))
}

/// `OSObject::metaCast`: whether the entry is, or inherits from, `class`,
/// up to `OSObject`, the root of every class. Every device tree entry is an
/// `IOService`, whatever nub replaced it.
pub fn conforms(t: &[Node], i: u32, class: &str) -> Result<bool, String> {
    match self::class(t, i) {
        Ok(c) => Ok(class_chain(c).is_some_and(|chain| chain.contains(&class))),
        Err(_) if matches!(class, "IOService" | "IORegistryEntry" | "OSObject") => Ok(true),
        Err(what) => Err(what),
    }
}

/// The device tree property `IODeviceTreeAlloc` makes an entry's location
/// and takes out of its table (`MakeReferenceTable`).
pub const DT_UNIT_KEY: &str = "AAPL,unit-string";

/// A device tree entry's properties as its table has them: all but
/// [`DT_UNIT_KEY`].
pub fn dt_table(n: &Node) -> impl Iterator<Item = &(String, Vec<u8>)> {
    n.props.iter().filter(|(k, _)| k != DT_UNIT_KEY)
}

/// `IORegistryEntry::getLocation`: a device tree entry's (and so a nub's
/// made of it, which takes over its table) is what `MakeReferenceTable`
/// set: its `AAPL,unit-string`, at most 31 characters, else `"%X"` of
/// its `reg`'s first word, else none; a service's, what its driver gave
/// it ([`super::storagestack::location`]).
pub fn location(n: &Node) -> Option<String> {
    if !n.class.is_empty() {
        return super::storagestack::location(n);
    }
    if let Some((_, v)) = n.props.iter().find(|(k, _)| k == DT_UNIT_KEY) {
        let v = &v[..v.len().min(31)];
        let v = &v[..v.iter().position(|&c| c == 0).unwrap_or(v.len())];
        return Some(String::from_utf8_lossy(v).into_owned());
    }
    let (_, reg) = n.props.iter().find(|(k, _)| k == "reg")?;
    let mut w = [0u8; 4];
    let k = reg.len().min(4);
    w[..k].copy_from_slice(&reg[..k]);
    Some(format!("{:X}", u32::from_le_bytes(w)))
}

/// `IORegistryEntry::getLocation(plane)`: the location the entry was given
/// in that plane, else its own ([`location`]).
pub fn location_in(n: &Node, plane: Option<Plane>) -> Option<String> {
    match (&n.dt, plane) {
        (Some(d), Some(Plane::DeviceTree)) => Some(d.location.clone()),
        _ => location(n),
    }
}

/// `AppleAPFSVolume::init`'s name for a role (its "Role" array's one
/// string); none for a role it has no name for, whose key it removes.
pub fn apfs_role_name(role: u16) -> Option<&'static str> {
    Some(match role {
        0x1 => "System",
        0x2 => "User",
        0x4 => "Recovery",
        0x8 => "VM",
        0x10 => "Preboot",
        0x20 => "Installer",
        0x40 => "Data",
        0x80 => "Baseband data",
        0xc0 => "Update",
        0x100 => "xART",
        0x140 => "Hardware",
        0x180 => "Backup",
        0x1c0 => "SideCar",
        0x200 => "Internal",
        0x240 => "Enterprise data",
        0x280 => "iDiags",
        0x2c0 => "Exclaves",
        _ => return None,
    })
}

/// The role of the volume at slot `index` in the container.
pub fn volume_role(index: u64) -> Option<u16> {
    super::storage::volume(u32::try_from(index).ok()?).map(|v| v.role)
}

/// `IOGetBootManifestHash`: `/chosen`'s `boot-manifest-hash`.
pub fn boot_manifest_hash() -> Option<&'static [u8]> {
    let t = tree();
    let chosen = from_path(t, "IODeviceTree:/chosen").ok()??;
    t[chosen as usize].props.iter().find(|(k, _)| k == "boot-manifest-hash").map(|(_, v)| v.as_slice())
}

/// `IODTPlatformExpert::getTargetName` on arm: `getModelName` of the
/// platform expert's provider, the device tree's root, with the 64 bytes
/// `PEGetTargetName` is given ([`target_name_of`]).
pub fn target_name() -> Option<Vec<u8>> {
    target_name_of(tree())
}

/// `getModelName` of tree `t`'s root: `compatible`'s first string, a
/// leading "AAPL," dropped, '/' and ' ' made '-', at most 63 bytes (the 64
/// less one, less one more for the terminator). `None` with no
/// `compatible`, which `hw.target` answers with EINVAL.
pub fn target_name_of(t: &[Node]) -> Option<Vec<u8>> {
    const MAX_LENGTH: usize = 64 - 1;
    let (_, v) = t.first()?.props.iter().find(|(k, _)| k == "compatible")?;
    let first = &v[..v.iter().position(|&c| c == 0).unwrap_or(v.len())];
    let s = first.strip_prefix(b"AAPL,").unwrap_or(first);
    let mut name = Vec::new();
    for &c in s {
        name.push(if c == b'/' || c == b' ' { b'-' } else { c });
        if name.len() >= MAX_LENGTH {
            break;
        }
    }
    Some(name)
}

/// A property of tree `t`'s node at `path` (`IODeviceTree:/chosen`), as
/// `getProperty` gives it: `None` when the node or the property is not
/// there.
pub fn dt_prop<'a>(t: &'a [Node], path: &str, name: &str) -> Option<&'a [u8]> {
    let at = from_path(t, path).ok()??;
    t[at as usize].props.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_slice())
}

/// Whether tree `t` has a node at `path`.
pub fn dt_has(t: &[Node], path: &str) -> bool {
    matches!(from_path(t, path), Ok(Some(_)))
}

/// An iterator handed out: an `OSCollectionIterator` over a fixed set,
/// or an `IORegistryIterator`.
enum Iter {
    Set(Vec<u32>, usize),
    Registry(RegistryIter),
}

/// `IORegistryIterator`: its root and plane, its options, the stack of
/// cursors entered (`where`, the first being `start`), and the entries
/// already recursed into (`done`).
struct RegistryIter {
    root: u32,
    plane: Plane,
    options: u32,
    cursors: Vec<Cursor>,
    done: Vec<u32>,
}

/// `IORegCursor`: the entry whose links it walks, or last gave, and the
/// links once it has started on them.
struct Cursor {
    current: Option<u32>,
    links: Option<(Vec<u32>, usize)>,
}

const K_IO_REGISTRY_ITERATE_RECURSIVELY: u32 = 1;
const K_IO_REGISTRY_ITERATE_PARENTS: u32 = 2;
/// `kIORegistryIteratorInvalidFlag`, which `iterateOver` clears.
const K_IO_REGISTRY_ITERATOR_INVALID_FLAG: u32 = 0x8000_0000;

impl RegistryIter {
    /// `getNextObjectFlat`: the next link of the cursor's entry, which it
    /// then holds as its current.
    fn next_flat(&mut self, t: &[Node]) -> Result<Option<u32>, String> {
        let parents = self.options & K_IO_REGISTRY_ITERATE_PARENTS != 0;
        let w = self.cursors.last_mut().expect("the start cursor");
        if w.links.is_none() {
            if let Some(c) = w.current {
                w.links = Some((links(t, c, self.plane, parents)?, 0));
            }
        }
        let next = match &mut w.links {
            Some((l, at)) => {
                let n = l.get(*at).copied();
                if n.is_some() {
                    *at += 1;
                }
                n
            }
            None => None,
        };
        w.current = next;
        Ok(next)
    }

    /// `getNextObjectRecursive`: depth first, each entry entered the first
    /// time it is given.
    fn next_recursive(&mut self, t: &[Node]) -> Result<Option<u32>, String> {
        let next = loop {
            let n = self.next_flat(t)?;
            if n.is_some() || !self.exit() {
                break n;
            }
        };
        if let Some(n) = next {
            if !self.done.contains(&n) {
                self.done.push(n);
                self.enter();
            }
        }
        Ok(next)
    }

    fn next(&mut self, t: &[Node]) -> Result<Option<u32>, String> {
        if self.options & K_IO_REGISTRY_ITERATE_RECURSIVELY != 0 { self.next_recursive(t) } else { self.next_flat(t) }
    }

    fn new(root: u32, plane: Plane, options: u32) -> Self {
        let start = Cursor { current: Some(root), links: None };
        RegistryIter { root, plane, options: options & !K_IO_REGISTRY_ITERATOR_INVALID_FLAG, cursors: vec![start], done: Vec::new() }
    }

    /// `enterEntry`: a cursor over the links of the entry last given.
    fn enter(&mut self) {
        let current = self.cursors.last().expect("the start cursor").current;
        self.cursors.push(Cursor { current, links: None });
    }

    /// `exitEntry`: the cursor's links dropped, and it popped unless it is
    /// the start; whether it was.
    fn exit(&mut self) -> bool {
        self.cursors.last_mut().expect("the start cursor").links = None;
        if self.cursors.len() > 1 {
            self.cursors.pop();
            true
        } else {
            false
        }
    }

    /// `reset`: every cursor exited, the done set dropped, and the start
    /// back on the root.
    fn reset(&mut self) {
        while self.exit() {}
        self.done.clear();
        self.cursors[0].current = Some(self.root);
        self.options &= !K_IO_REGISTRY_ITERATOR_INVALID_FLAG;
    }
}

static ITERATORS: std::sync::Mutex<Vec<Iter>> = std::sync::Mutex::new(Vec::new());

fn iterator_add(it: Iter) -> u32 {
    let mut t = ITERATORS.lock().unwrap_or_else(|e| e.into_inner());
    t.push(it);
    (t.len() - 1) as u32
}

/// A new iterator over `items`, by number.
pub fn iterator_new(items: Vec<u32>) -> u32 {
    iterator_add(Iter::Set(items, 0))
}

/// `IORegistryIterator::iterateOver(root, plane, options)`, by number.
pub fn registry_iterator_new(root: u32, plane: Plane, options: u32) -> u32 {
    iterator_add(Iter::Registry(RegistryIter::new(root, plane, options)))
}

/// The iterator's next entry; `Err` for links that are not here.
pub fn iterator_next(id: u32) -> Result<Option<u32>, String> {
    let mut t = ITERATORS.lock().unwrap_or_else(|e| e.into_inner());
    match t.get_mut(id as usize) {
        Some(Iter::Set(items, at)) => {
            let next = items.get(*at).copied();
            if next.is_some() {
                *at += 1;
            }
            Ok(next)
        }
        Some(Iter::Registry(r)) => r.next(tree()),
        None => Ok(None),
    }
}

/// `OSIterator::reset`: back to the first entry.
pub fn iterator_reset(id: u32) {
    match ITERATORS.lock().unwrap_or_else(|e| e.into_inner()).get_mut(id as usize) {
        Some(Iter::Set(_, at)) => *at = 0,
        Some(Iter::Registry(r)) => r.reset(),
        None => {}
    }
}

/// `enterEntry` on a registry iterator; `false` for another iterator.
pub fn iterator_enter(id: u32) -> bool {
    match ITERATORS.lock().unwrap_or_else(|e| e.into_inner()).get_mut(id as usize) {
        Some(Iter::Registry(r)) => {
            r.enter();
            true
        }
        _ => false,
    }
}

/// `exitEntry` on a registry iterator: whether it left an entry; `None`
/// for another iterator.
pub fn iterator_exit(id: u32) -> Option<bool> {
    match ITERATORS.lock().unwrap_or_else(|e| e.into_inner()).get_mut(id as usize) {
        Some(Iter::Registry(r)) => Some(r.exit()),
        _ => None,
    }
}

/// An `IOServiceUserNotification`: the services its matching notification
/// has handed it and not yet given out (`newSet`, taken from its end), and
/// the send right to the port it would ping (`remotePort`). No service
/// comes or goes once the registry is built, so after the services already
/// there none is added and no ping is owed.
struct Notification {
    new_set: Vec<u32>,
    wake: Option<u64>,
}

static NOTIFICATIONS: std::sync::Mutex<Vec<Option<Notification>>> = std::sync::Mutex::new(Vec::new());

/// `kMaxOutstanding`: a notification holds at most this many services.
const MAX_OUTSTANDING: usize = 1024;

/// A notification of the services `existing` hands it, in that order, and
/// the right `wake` it keeps; its number.
pub fn notification_new(existing: Vec<u32>, wake: Option<u64>) -> u32 {
    let new_set = existing.into_iter().take(MAX_OUTSTANDING).collect();
    let mut t = NOTIFICATIONS.lock().unwrap_or_else(|e| e.into_inner());
    t.push(Some(Notification { new_set, wake }));
    (t.len() - 1) as u32
}

/// `copyNextObject`: the last service handed it, or none (and it is armed
/// again).
pub fn notification_next(id: u32) -> Option<u32> {
    NOTIFICATIONS.lock().unwrap_or_else(|e| e.into_inner()).get_mut(id as usize)?.as_mut()?.new_set.pop()
}

/// The notification freed: the right it kept, to release.
pub fn notification_free(id: u32) -> Option<u64> {
    NOTIFICATIONS.lock().unwrap_or_else(|e| e.into_inner()).get_mut(id as usize)?.take()?.wake
}

/// `serialize_str` and `serialize_bool`'s common frame.
pub fn serialize_prop(p: &Prop) -> Vec<u8> {
    const K_OS_SERIALIZE_BINARY_SIGNATURE: &[u8; 4] = b"\xd3\0\0\0";
    const K_OS_SERIALIZE_STRING: u32 = 0x0900_0000;
    const K_OS_SERIALIZE_BOOLEAN: u32 = 0x0b00_0000;
    const K_OS_SERIALIZE_END_COLLECTION: u32 = 0x8000_0000;
    let mut b = K_OS_SERIALIZE_BINARY_SIGNATURE.to_vec();
    match p {
        Prop::Str(s) => {
            b.extend_from_slice(&(K_OS_SERIALIZE_END_COLLECTION | K_OS_SERIALIZE_STRING | s.len() as u32).to_le_bytes());
            b.extend_from_slice(s.as_bytes());
            b.resize((b.len() + 3) & !3, 0);
        }
        Prop::Bool(v) => b.extend_from_slice(&(K_OS_SERIALIZE_END_COLLECTION | K_OS_SERIALIZE_BOOLEAN | u32::from(*v)).to_le_bytes()),
        // The number's size in bits, then its 64-bit value.
        Prop::Num(v, bits) => {
            const K_OS_SERIALIZE_NUMBER: u32 = 0x0400_0000;
            b.extend_from_slice(&(K_OS_SERIALIZE_END_COLLECTION | K_OS_SERIALIZE_NUMBER | bits).to_le_bytes());
            b.extend_from_slice(&v.to_le_bytes());
        }
        Prop::Data(d) => return serialize_data(d),
        // The symbol's characters and NUL.
        Prop::Sym(s) => {
            const K_OS_SERIALIZE_SYMBOL: u32 = 0x0800_0000;
            b.extend_from_slice(&(K_OS_SERIALIZE_END_COLLECTION | K_OS_SERIALIZE_SYMBOL | (s.len() as u32 + 1)).to_le_bytes());
            b.extend_from_slice(s.as_bytes());
            b.push(0);
            b.resize((b.len() + 3) & !3, 0);
        }
        Prop::Dict(_) | Prop::Array(_) | Prop::SameAs(_) => {
            let mut g = super::osserialize::Graph::default();
            let root = prop_object(&mut g, p);
            return super::osserialize::serialize_binary(&g, root);
        }
        Prop::Strs(items) => {
            const K_OS_SERIALIZE_ARRAY: u32 = 0x0200_0000;
            b.extend_from_slice(&(K_OS_SERIALIZE_END_COLLECTION | K_OS_SERIALIZE_ARRAY | items.len() as u32).to_le_bytes());
            for (i, s) in items.iter().enumerate() {
                let end = if i + 1 == items.len() { K_OS_SERIALIZE_END_COLLECTION } else { 0 };
                b.extend_from_slice(&(end | K_OS_SERIALIZE_STRING | s.len() as u32).to_le_bytes());
                b.extend_from_slice(s.as_bytes());
                b.resize((b.len() + 3) & !3, 0);
            }
        }
    }
    b
}

/// A property as a libkern object of graph `g`.
fn prop_object(g: &mut super::osserialize::Graph, p: &Prop) -> super::osserialize::Id {
    use super::osserialize::Obj;
    match p {
        Prop::Str(s) => g.add(Obj::String(s.as_bytes().to_vec())),
        Prop::Sym(s) => g.add(Obj::Symbol(s.as_bytes().to_vec())),
        Prop::Bool(b) => g.add(Obj::Bool(*b)),
        Prop::Num(v, bits) => g.number(*v, *bits),
        Prop::Data(d) => g.add(Obj::Data(d.clone())),
        Prop::Strs(items) => {
            let ids = items.iter().map(|s| g.add(Obj::String(s.as_bytes().to_vec()))).collect();
            g.add(Obj::Array(ids))
        }
        Prop::Dict(entries) => {
            let d = g.add(Obj::Dict(Vec::new()));
            for (k, v) in entries {
                let id = match v {
                    Prop::SameAs(other) => g.lookup(d, other.as_bytes()).unwrap_or_else(|| panic!("{k} shares {other}, which its dictionary does not hold before it")),
                    v => prop_object(g, v),
                };
                g.dict_set(d, k.as_bytes(), id);
            }
            d
        }
        Prop::Array(items) => {
            let ids = items.iter().map(|v| prop_object(g, v)).collect();
            g.add(Obj::Array(ids))
        }
        Prop::SameAs(other) => panic!("a property shares {other} outside a dictionary"),
    }
}

/// IOReturn codes (`IOReturn.h`).
pub mod ret {
    pub const SUCCESS: i32 = 0;
    pub const ERROR: i32 = 0xe00002bc_u32 as i32;
    pub const NO_MEMORY: i32 = 0xe00002bd_u32 as i32;
    pub const NO_RESOURCES: i32 = 0xe00002be_u32 as i32;
    pub const IPC_ERROR: i32 = 0xe00002bf_u32 as i32;
    pub const NO_DEVICE: i32 = 0xe00002c0_u32 as i32;
    pub const NOT_PRIVILEGED: i32 = 0xe00002c1_u32 as i32;
    pub const BAD_ARGUMENT: i32 = 0xe00002c2_u32 as i32;
    pub const UNSUPPORTED: i32 = 0xe00002c7_u32 as i32;
    pub const VM_ERROR: i32 = 0xe00002c8_u32 as i32;
    pub const NOT_READY: i32 = 0xe00002d8_u32 as i32;
    pub const NOT_FOUND: i32 = 0xe00002f0_u32 as i32;
    pub const NOT_PERMITTED: i32 = 0xe00002e2_u32 as i32;
    pub const NO_COMPLETION: i32 = 0xe00002ea_u32 as i32;
    pub const UNDERRUN: i32 = 0xe00002e7_u32 as i32;
}

/// `kOSNotificationMessageID`, `kIOAsyncCompletionNotificationType`,
/// `kMaxAsyncArgs` and `kOSAsyncRef64Count` (`OSMessageNotification.h`).
pub const NOTIFICATION_MESSAGE_ID: i32 = 53;
pub const ASYNC_COMPLETION_TYPE: u32 = 150;
pub const MAX_ASYNC_ARGS: usize = 16;
pub const ASYNC_REF64_COUNT: usize = 8;

/// `kIOUCVariableStructureSize`: a dispatch count that is not checked.
pub const VARIABLE: u32 = 0xffff_ffff;

/// `sizeof(io_struct_inband_t)`.
pub const STRUCT_INBAND_MAX: usize = 4096;

/// An `IOExternalMethodDispatch`'s checks: the scalar input count, the
/// structure input size, the scalar output count and the structure output
/// size a selector takes, each [`VARIABLE`] or exact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dispatch {
    pub scalar_in: u32,
    pub struct_in: u32,
    pub scalar_out: u32,
    pub struct_out: u32,
}

/// `IOExternalMethodArguments` as a method sees them: the inputs, and the
/// outputs sized to what the caller has room for (a method lowers the
/// counts it fills less of). An out-of-line structure is its address and
/// size in the calling task, the `IOMemoryDescriptor` over it.
#[derive(Clone, Debug, Default)]
pub struct MethodArgs {
    pub selector: u32,
    /// An asynchronous call (io_connect_async_method: `asyncReference` set),
    /// its `asyncWakePort` (a send right the kernel holds; none for a null
    /// port) and its reference.
    pub is_async: bool,
    pub wake: Option<super::ipc::ObjId>,
    pub reference: Vec<u64>,
    /// Set by a method that answers later (a WebMetal call the host
    /// executor runs, a framebuffer swap or power wait): the token its reply
    /// is sent by ([`super::mig::later_token`], [`super::mig::later_reply`]).
    pub later: Option<u64>,
    pub scalar_in: Vec<u64>,
    pub struct_in: Vec<u8>,
    pub ool_in: Option<(u64, u64)>,
    pub scalar_out: Vec<u64>,
    pub struct_out: Vec<u8>,
    pub ool_out: Option<(u64, u64)>,
}

impl MethodArgs {
    /// The structure input's size: the descriptor's length, else the inband
    /// bytes'.
    pub fn struct_in_size(&self) -> u64 {
        self.ool_in.map_or(self.struct_in.len() as u64, |(_, n)| n)
    }

    pub fn struct_out_size(&self) -> u64 {
        self.ool_out.map_or(self.struct_out.len() as u64, |(_, n)| n)
    }
}

/// `IOUserClient::externalMethod`'s checks of a dispatch entry: every count
/// that is not [`VARIABLE`] must be the caller's (kIOReturnBadArgument).
pub fn dispatch_check(d: &Dispatch, a: &MethodArgs) -> Result<(), i32> {
    let ok = |want: u32, got: u64| want == VARIABLE || u64::from(want) == got;
    if !ok(d.scalar_in, a.scalar_in.len() as u64) || !ok(d.struct_in, a.struct_in_size()) || !ok(d.scalar_out, a.scalar_out.len() as u64) || !ok(d.struct_out, a.struct_out_size()) {
        return Err(ret::BAD_ARGUMENT);
    }
    Ok(())
}

/// `IOUserClient::externalMethod` without a dispatch entry: the
/// pre-Leopard method vector, which takes no out-of-line structure
/// (kIOReturnIPCError); a client with no vector (`getTargetAndMethodForIndex`
/// and `getAsyncTargetAndMethodForIndex` answering none) has no method
/// (kIOReturnUnsupported).
pub fn no_method(a: &MethodArgs) -> i32 {
    if a.ool_in.is_some() || a.ool_out.is_some() {
        return ret::IPC_ERROR;
    }
    ret::UNSUPPORTED
}

/// What kind of user client one is, and its own state.
pub enum Kind {
    /// AppleAPFSContainer's.
    Apfs,
    /// One of the accelerator's ([`super::accel`]).
    Accel(super::accel::Client),
    /// IOSurfaceRoot's, by its number among the root's clients
    /// ([`super::iosurface`]).
    Surface(u32),
    /// The display framebuffer's ([`super::iomfb`]).
    Framebuffer(super::iomfb::Client),
}

/// An `IOUserClient` a task opened: the service it is attached to, its
/// class, its registry entry id, `IOUserClientCreator`, whether
/// `IOUserClientDefaultLocking` was set on it, whether it has been closed
/// (`closed`: io_service_close or clientDied ran clientClose), and its
/// kind's state.
pub struct UserClient {
    pub service: u32,
    pub class: &'static str,
    pub id: u64,
    pub creator: String,
    pub default_locking: bool,
    pub closed: bool,
    pub kind: Kind,
}

/// The user clients, each behind its own lock: a call on a client holds it
/// for the call, as IOUserClient's default locking (`ipcEnter`) does, while
/// other clients' calls go on.
static CLIENTS: std::sync::Mutex<Vec<Option<std::sync::Arc<std::sync::Mutex<UserClient>>>>> = std::sync::Mutex::new(Vec::new());

/// The next registry entry id: the entries of the device tree have theirs
/// in creation order (`gIORegistryLastID`), and each user client the next.
static NEXT_CLIENT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// `kIORegistryEntryIDPrefix`, the first registry entry id.
pub const REGISTRY_ID_PREFIX: u64 = 0x1_0000_0000;

/// The registry entry id of entry `i` of the tree.
pub fn registry_id(i: u32) -> u64 {
    REGISTRY_ID_PREFIX + u64::from(i)
}

/// A new user client of `service`, by its number.
pub fn client_add(service: u32, class: &'static str, creator: String, default_locking: bool, kind: Kind) -> u32 {
    let serial = NEXT_CLIENT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let id = REGISTRY_ID_PREFIX + tree().len() as u64 + serial;
    let c = UserClient { service, class, id, creator, default_locking, closed: false, kind };
    let mut t = CLIENTS.lock().unwrap_or_else(|e| e.into_inner());
    t.push(Some(std::sync::Arc::new(std::sync::Mutex::new(c))));
    (t.len() - 1) as u32
}

/// The user client numbered `id`; none once it is freed.
pub fn client(id: u32) -> Option<std::sync::Arc<std::sync::Mutex<UserClient>>> {
    CLIENTS.lock().unwrap_or_else(|e| e.into_inner()).get(id as usize)?.clone()
}

/// The client freed: out of the table, nothing naming it any more.
fn client_remove(id: u32) -> Option<std::sync::Arc<std::sync::Mutex<UserClient>>> {
    CLIENTS.lock().unwrap_or_else(|e| e.into_inner()).get_mut(id as usize)?.take()
}

/// `is_io_service_open_extended` after its checks: the service's
/// `newUserClient(owningTask, securityID, type, properties)`, and the
/// properties the open sets on the new client: `IOUserClientCreator`
/// (`IOCopyLogNameForPID`: "pid N, " and the process's `p_comm`), and
/// `IOUserClientDefaultLocking` for a client of a kext that does not depend
/// on IOSurface and set no locking property itself.
pub fn open_user_client(k: &mut crate::syscalls::Kernel, service: u32, ty: u32) -> Result<u32, i32> {
    let t = tree();
    let Some(n) = t.get(service as usize) else { return Err(ret::BAD_ARGUMENT) };
    let pid = k.pid;
    let comm = k.darwin_public(pid).map(|(p, _)| String::from_utf8_lossy(&p.comm).into_owned()).unwrap_or_default();
    let creator = format!("pid {pid}, {comm}");
    let (class, kind, default_locking) = match n.class {
        // IOService::newUserClient by the container's IOUserClientClass
        // (its personality's), for any type; the apfs kext does not depend
        // on IOSurface.
        "AppleAPFSContainer" => ("AppleAPFSUserClient", Kind::Apfs, true),
        // IOSurfaceRootUserClient sets its own locking properties (start,
        // 0xfffffff005baf29c): no default locking.
        c if c == super::iosurface::CLASS => (super::iosurface::UC_CLASS, Kind::Surface(super::iosurface::new_user_client(k, ty)?), false),
        // AGXG9G and IOGPUFamily, whose classes the accelerator's clients
        // are, both depend on IOSurface.
        c if c == super::accel::CLASS => {
            let (class, client) = super::accel::new_user_client(k, service, ty)?;
            (class, Kind::Accel(client), false)
        }
        // IOMobileGraphicsFamily, whose class the framebuffer's client is,
        // depends on IOSurface.
        c if c == super::iomfb::CLASS => (super::iomfb::UC_CLASS, Kind::Framebuffer(super::iomfb::new_user_client(k, ty)?), false),
        _ => {
            k.darwin_unimplemented(format!("newUserClient of {} (type {ty:#x})", name(t, service)));
            return Err(ret::UNSUPPORTED);
        }
    };
    let framebuffer = matches!(kind, Kind::Framebuffer(_));
    let id = client_add(service, class, creator, default_locking, kind);
    // is_io_service_open_extended, the client made: the MAC policies'
    // mac_iokit_check_open, then, allowed, Sandbox's filter resolver; a
    // refusal is the open's result, the client closed and let go.
    let Some(cell) = client(id) else { return Err(ret::ERROR) };
    // The framebuffer's client started (IOMobileFramebufferUserClient::start,
    // in newUserClient).
    if framebuffer {
        super::iomfb::swap::client_started(cell.lock().unwrap_or_else(|e| e.into_inner()).id as u32);
    }
    let object = sb_client(&cell.lock().unwrap_or_else(|e| e.into_inner()));
    let res = match k.darwin_mac_check_iokit_open(object.clone()) {
        0 => match k.darwin_sb_iokit_resolve(object) {
            ret::UNSUPPORTED => ret::SUCCESS,
            r => r,
        },
        _ => ret::NOT_PERMITTED,
    };
    if res != ret::SUCCESS {
        if let Some(cell) = client_remove(id) {
            let mut c = cell.lock().unwrap_or_else(|e| e.into_inner());
            c.closed = true;
            client_close(k, &mut c, None);
            let key = c.id as u32;
            match &mut c.kind {
                Kind::Accel(a) => super::accel::client_free(k, a),
                Kind::Framebuffer(f) => super::iomfb::client_free(k, key, f),
                _ => {}
            }
        }
        return Err(res);
    }
    Ok(id)
}

/// A class with its superclasses and OSObject, as `metaCast` and a Sandbox
/// class walk visit them (`getMetaClass`, then each `getSuperClass`); none
/// for a class this registry does not know.
pub fn class_chain(class: &str) -> Option<Vec<&'static str>> {
    let s = superclasses(class);
    if s.is_empty() {
        return None;
    }
    let mut v = s.to_vec();
    v.push("OSObject");
    Some(v)
}

/// The class chains from entry `at` up the IOService plane, as Sandbox's
/// iokit-connection walk (`0x...9f2564`) takes them with
/// `getParentEntry(gIOServicePlane)`: its own, each provider's, to the
/// registry's root (an IORegistryEntry). An entry whose provider this
/// registry does not know ends the chains with none.
fn chains_from(t: &[Node], mut at: Option<u32>) -> Vec<Option<Vec<&'static str>>> {
    let mut out = Vec::new();
    while let Some(i) = at {
        out.push(class(t, i).ok().and_then(class_chain));
        match provider(t, i) {
            Ok(p) => at = p,
            Err(_) => {
                out.push(None);
                break;
            }
        }
    }
    out
}

/// Registry entry `i` as a Sandbox IOKit operation names it.
pub fn sb_entry(i: u32) -> super::sandbox::IoKitObject {
    super::sandbox::IoKitObject { chains: chains_from(tree(), Some(i)), ..Default::default() }
}

/// User client `c` as a Sandbox IOKit operation names it: its classes,
/// then its provider's (the service it was opened on, which it is attached
/// to) and up; and its provider's USB device class and subclass.
pub fn sb_client(c: &UserClient) -> super::sandbox::IoKitObject {
    let t = tree();
    let mut chains = vec![class_chain(c.class)];
    chains.extend(chains_from(t, Some(c.service)));
    let num = |name: &str| {
        t.get(c.service as usize)?.service_props.iter().find(|(k, _)| k == name).and_then(|(_, p)| match p {
            Prop::Num(v, bits) => Some((*v, *bits)),
            _ => None,
        })
    };
    super::sandbox::IoKitObject { chains, usb_class: num("bDeviceClass"), usb_subclass: num("bDeviceSubClass"), ..Default::default() }
}

/// Whether entry `i` is the NVRAM's (IODTNVRAM, which the platform expert
/// publishes on `/options`: `createNVRAM`).
pub fn is_nvram(i: u32) -> bool {
    from_path(tree(), "IODeviceTree:/options").ok().flatten() == Some(i)
}

/// The client's `clientClose`. A framebuffer client's may sleep in the
/// closing thread (its last swap client's going): `closer` is the
/// io_service_close that would wait, answered later by that token, and the
/// result is whether it waits. The open that a MAC check refuses closes its
/// client without its reply waiting, and a client that dies has no caller
/// to hold up: the display goes on with the work by itself.
pub fn client_close(k: &mut crate::syscalls::Kernel, c: &mut UserClient, closer: Option<u64>) -> bool {
    match &mut c.kind {
        // AppleAPFSUserClient's (0xfffffff00666facc) closes what the client
        // opened on its container and terminates it; neither has a state
        // here, the container's opens not being modelled.
        Kind::Apfs => false,
        Kind::Accel(a) => {
            super::accel::client_close(k, a);
            false
        }
        Kind::Surface(id) => {
            super::iosurface::client_close(k, *id);
            false
        }
        Kind::Framebuffer(f) => super::iomfb::client_close(k, c.id as u32, f, closer),
    }
}

/// `clientDied`, when the connection's last send right goes
/// (`iokit_client_died`): clientClose unless the client was closed; then
/// the client is gone, nothing naming it any more.
pub fn client_died(k: &mut crate::syscalls::Kernel, id: u32) {
    let Some(cell) = client_remove(id) else { return };
    let mut c = cell.lock().unwrap_or_else(|e| e.into_inner());
    if !c.closed {
        c.closed = true;
        client_close(k, &mut c, None);
    }
    if let Kind::Accel(a) = &mut c.kind {
        super::accel::client_free(k, a);
    }
    if let Kind::Surface(id) = c.kind {
        super::iosurface::client_free(k, id);
    }
    let key = c.id as u32;
    if let Kind::Framebuffer(f) = &mut c.kind {
        super::iomfb::client_free(k, key, f);
    }
}

/// `getService`: the provider for the accelerator's clients, none for
/// IOUserClient's default.
pub fn client_service(c: &UserClient) -> Option<u32> {
    match &c.kind {
        Kind::Apfs | Kind::Surface(_) | Kind::Framebuffer(_) => None,
        Kind::Accel(a) => super::accel::client_service(c.service, a),
    }
}

/// `clientMemoryForType`: the memory a client gives for a type. `Ok(None)`:
/// the client answers success with none (the framebuffer's for most types);
/// `Err`: its error (IOUserClient's default, kIOReturnUnsupported).
pub fn client_memory_for_type(c: &mut UserClient, ty: u32) -> Result<Option<super::iomfb::Memory>, i32> {
    match &c.kind {
        Kind::Framebuffer(_) => super::iomfb::client_memory_for_type(c.id as u32, ty),
        _ => Err(ret::UNSUPPORTED),
    }
}

/// `IOUserClient::mapClientMemory64` into the calling task with the
/// caller's `flags`: the type's memory mapped with the user options
/// (`kIOMapUserOptionsMask`) of the flags and none of the client's. Its
/// address and size; `Ok(None)` when no mapping is made (no memory, or an
/// error from the client); `Err` is what is not modelled.
pub fn map_client_memory(k: &mut crate::syscalls::Kernel, c: &mut UserClient, ty: u32, flags: u32) -> Result<Option<(u64, u64)>, String> {
    const K_IO_MAP_ANYWHERE: u32 = 0x1;
    const K_IO_MAP_USER_OPTIONS_MASK: u32 = 0xfff;
    let Ok(Some(memory)) = client_memory_for_type(c, ty) else { return Ok(None) };
    let options = flags & K_IO_MAP_USER_OPTIONS_MASK;
    if options != K_IO_MAP_ANYWHERE {
        return Err(format!("mapping {}'s memory of type {ty} with the options {options:#x} (only kIOMapAnywhere with the default cache mode is modelled)", c.class));
    }
    match memory {
        super::iomfb::Memory::FrameInfo(id) => match super::iomfb::finfo::map(k, id) {
            Some(Ok(m)) => Ok(Some(m)),
            Some(Err(e)) => Err(format!("mapping {}'s frame information queue (Mach error {e:#x})", c.class)),
            None => Ok(None),
        },
    }
}

/// `registerNotificationPort(port, type, refCon)`.
pub fn register_notification_port(k: &mut crate::syscalls::Kernel, c: &mut UserClient, port: Option<super::ipc::ObjId>, ty: u32, reference: u64) -> i32 {
    let key = c.id as u32;
    match &mut c.kind {
        Kind::Apfs => {
            k.darwin_unimplemented("AppleAPFSUserClient::registerNotificationPort".to_string());
            ret::UNSUPPORTED
        }
        Kind::Accel(a) => super::accel::register_notification_port(k, a, port, ty, reference),
        // IOUserClient's (IOSurfaceRootUserClient has none of its own).
        Kind::Surface(_) => ret::UNSUPPORTED,
        Kind::Framebuffer(f) => super::iomfb::register_notification_port(k, key, f, port, ty, reference),
    }
}

/// `callExternalMethod`: the client's externalMethod.
pub fn external_method(k: &mut crate::syscalls::Kernel, c: &mut UserClient, a: &mut MethodArgs) -> i32 {
    let key = c.id as u32;
    match &mut c.kind {
        Kind::Apfs => apfs_method(k, c.service, a),
        Kind::Accel(x) => super::accel::external_method(k, x, a),
        Kind::Surface(id) => super::iosurface::external_method(k, *id, a),
        Kind::Framebuffer(f) => super::iomfb::methods::external_method(k, key, f, a),
    }
}

/// AppleAPFSUserClient's methods: of them, selector 9, a volume's
/// information by its index, which APFSVolumeRoleFind reads the role from
/// (the first two bytes).
fn apfs_method(k: &mut crate::syscalls::Kernel, _service: u32, a: &mut MethodArgs) -> i32 {
    if a.selector == 9 && a.struct_in.len() == 8 && a.ool_in.is_none() {
        let index = u64::from_le_bytes(a.struct_in[..8].try_into().unwrap());
        let Some(role) = volume_role(index) else { return ret::NOT_FOUND };
        a.struct_out.iter_mut().for_each(|b| *b = 0);
        if a.struct_out.len() >= 2 {
            a.struct_out[..2].copy_from_slice(&role.to_le_bytes());
        }
        return ret::SUCCESS;
    }
    k.darwin_unimplemented(format!("IOConnectCallMethod on AppleAPFSContainer: selector {}, {} scalars, {} bytes in: {:x?}", a.selector, a.scalar_in.len(), a.struct_in.len(), &a.struct_in[..a.struct_in.len().min(64)]));
    ret::UNSUPPORTED
}

/// A property of user client `c`: what is_io_service_open_extended sets,
/// and the client's own. `Err`: one whose value is not modelled.
pub fn client_property(c: &UserClient, name: &str) -> Result<Option<Prop>, String> {
    match name {
        "IOUserClientCreator" => Ok(Some(Prop::Str(c.creator.clone()))),
        "IOUserClientDefaultLocking" if c.default_locking => Ok(Some(Prop::Bool(true))),
        _ => match &c.kind {
            Kind::Surface(_) => Ok(super::iosurface::client_property(name)),
            Kind::Framebuffer(f) => Ok(super::iomfb::client_property(f, name)),
            _ => super::accel::client_property(c, name),
        },
    }
}

/// `is_io_registry_entry_get_property_bytes`'s bytes of a property: an
/// OSString's characters and NUL, an OSBoolean's "Yes" or "No", an
/// OSData's bytes, an OSNumber's low `numberOfBytes` bytes; a collection
/// has none (`None`: kIOReturnBadArgument).
pub fn prop_bytes(p: &Prop) -> Option<Vec<u8>> {
    match p {
        Prop::Str(s) | Prop::Sym(s) => Some([s.as_bytes(), b"\0"].concat()),
        Prop::Bool(b) => Some(if *b { b"Yes\0".to_vec() } else { b"No\0".to_vec() }),
        Prop::Data(d) => Some(d.clone()),
        Prop::Num(v, bits) => Some(v.to_le_bytes()[..((*bits as usize + 7) / 8).min(8)].to_vec()),
        Prop::Strs(_) | Prop::Dict(_) | Prop::Array(_) | Prop::SameAs(_) => None,
    }
}

/// The device tree; empty when the boot payload had none.
pub fn tree() -> &'static [Node] {
    TREE.get().map_or(&[], Vec::as_slice)
}

/// `IORegistryEntry::fromPath` in the `IODeviceTree` plane; `Err` for a
/// plane whose entries are not here.
pub fn from_path(tree: &[Node], path: &str) -> Result<Option<u32>, String> {
    let Some((plane, rest)) = path.split_once(':') else { return Err(format!("a registry path with no plane: {path}")) };
    if plane != "IODeviceTree" {
        return Err(format!("the {plane} plane ({path})"));
    }
    if tree.is_empty() {
        return Ok(None);
    }
    let Some(rest) = rest.strip_prefix('/') else { return Err(format!("a device tree alias: {path}")) };
    let mut at = 0u32;
    for part in rest.split('/').filter(|p| !p.is_empty()) {
        match tree[at as usize].children.iter().find(|&&c| tree[c as usize].name == part) {
            Some(&c) => at = c,
            None => return Ok(None),
        }
    }
    Ok(Some(at))
}

/// `OSData::serialize` into OSSerializeBinary: the signature, then the
/// one object's header (its type and length, the end of the outermost
/// collection) and bytes, padded to 4.
pub fn serialize_data(value: &[u8]) -> Vec<u8> {
    const K_OS_SERIALIZE_BINARY_SIGNATURE: &[u8; 4] = b"\xd3\0\0\0";
    const K_OS_SERIALIZE_DATA: u32 = 0x0a00_0000;
    const K_OS_SERIALIZE_END_COLLECTION: u32 = 0x8000_0000;
    let mut b = K_OS_SERIALIZE_BINARY_SIGNATURE.to_vec();
    b.extend_from_slice(&(K_OS_SERIALIZE_END_COLLECTION | K_OS_SERIALIZE_DATA | value.len() as u32).to_le_bytes());
    b.extend_from_slice(value);
    b.resize((b.len() + 3) & !3, 0);
    b
}

impl crate::syscalls::Kernel {
    /// `iokit_user_client_trap(userClientRef, index, p1, ...)`: a trap of
    /// the user client the caller's name `userClientRef` sends to. A name
    /// with bit 0 clear or bit 32 set names a DriverKit (`uext`) object,
    /// which none is here; one that sends to no user client, or null or
    /// dead, is kIOReturnBadArgument. A client with no trap at the index
    /// answers kIOReturnSuccess (`trap` stays null).
    pub(crate) fn darwin_iokit_user_client_trap(&mut self, a: &[u64; 6]) -> i32 {
        const MACH_PORT_DEAD: u64 = 0xffff_ffff;
        let reference = a[0];
        if reference == 0 || reference == MACH_PORT_DEAD {
            return ret::BAD_ARGUMENT;
        }
        if reference & (1 << 32) != 0 || reference & 1 == 0 {
            return ret::BAD_ARGUMENT;
        }
        let ipc = self.ipc();
        let id = match ipc.translate_send(reference as u32) {
            Ok(p) => match ipc.port(p).kobject {
                Some(super::ipc::Kobject::IoConnect(id)) => id,
                _ => return ret::BAD_ARGUMENT,
            },
            Err(_) => return ret::BAD_ARGUMENT,
        };
        let Some(cell) = client(id) else { return ret::BAD_ARGUMENT };
        let mut c = cell.lock().unwrap_or_else(|e| e.into_inner());
        let index = a[1] as u32;
        let r = match &mut c.kind {
            Kind::Apfs => {
                self.darwin_unimplemented(format!("AppleAPFSUserClient trap {index}"));
                ret::UNSUPPORTED
            }
            Kind::Accel(x) => super::accel::trap(self, x, index, [a[2], a[3], a[4], a[5]]),
            Kind::Surface(id) => {
                let id = *id;
                super::iosurface::trap(self, id, index, [a[2], a[3], a[4], a[5]])
            }
            // IOMobileFramebufferUserClient has no trap: IOUserClient's
            // getTargetAndTrapForIndex, none, and so success.
            Kind::Framebuffer(_) => ret::SUCCESS,
        };
        r
    }
}

impl crate::syscalls::Kernel {
    /// `IOUserClient::_sendAsyncResult64` to the wake port of a 64-bit
    /// task's async reference: a message from the kernel with a copy of the
    /// kernel's send right, `kOSNotificationMessageID`, an
    /// `OSNotificationHeader64` of type `kIOAsyncCompletionNotificationType`
    /// whose reference is the async reference with its first word zero, the
    /// result and the arguments. Its size is the reply structure's less the
    /// arguments not sent (the 64-bit arm of the structure is 8-aligned, so
    /// it ends with 4 bytes of zeros after the arguments). `can_drop`:
    /// `kIOUserNotifyOptionCanDrop`, the send made with a zero timeout and
    /// without `MACH_SEND_ALWAYS`, so a full queue drops the message; else
    /// `mach_msg_send_from_kernel`'s.
    pub(crate) fn darwin_io_async_result(&mut self, wake: super::ipc::ObjId, reference: &[u64; ASYNC_REF64_COUNT], result: i32, args: &[u64], can_drop: bool) {
        use super::ipc::msg::{bits, Kmsg, Sender};
        use super::ipc::right::msgt;
        debug_assert!(args.len() <= MAX_ASYNC_ARGS);
        let ipc = self.ipc();
        if !ipc.port(wake).active {
            return;
        }
        ipc.copy_send(wake);
        // struct { OSNotificationHeader64 notifyHdr; IOAsyncCompletionContent
        // asyncContent; io_user_reference_t args[kMaxAsyncArgs] packed; }:
        // 72 + 4 + 128 bytes, 208 with its alignment.
        const MSG64: usize = 208;
        let len = MSG64 - (MAX_ASYNC_ARGS - args.len()) * 8;
        let mut body = vec![0u8; len];
        let size = 4 + 8 * args.len() as u32;
        body[0..4].copy_from_slice(&size.to_le_bytes());
        body[4..8].copy_from_slice(&ASYNC_COMPLETION_TYPE.to_le_bytes());
        for (i, r) in reference.iter().enumerate().skip(1) {
            body[8 + 8 * i..16 + 8 * i].copy_from_slice(&r.to_le_bytes());
        }
        body[72..76].copy_from_slice(&result.to_le_bytes());
        for (i, v) in args.iter().enumerate() {
            body[76 + 8 * i..84 + 8 * i].copy_from_slice(&v.to_le_bytes());
        }
        let k = Kmsg { bits: bits::set(msgt::PORT_SEND, 0, 0, 0), size: 24 + body.len() as u32, dest: wake, reply: None, voucher: None, voucher_raw: 0, id: NOTIFICATION_MESSAGE_ID, body, descs: Vec::new(), sender: Sender::KERNEL, aux: Vec::new(), keep_alive: false, ppriority: 0, qos_override: 0, imp: None };
        if can_drop {
            self.darwin_kernel_send_droppable(Box::new(k));
        } else {
            self.darwin_kernel_send(Box::new(k));
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_apfs_entries_are_as_appleapfs_makes_them() {
        use super::*;
        let mut t = Vec::new();
        super::super::storagestack::add(&mut t, None);
        let find = |name: &str| t.iter().position(|n| n.name == name).unwrap() as u32;
        let media = find("AppleAPFSMedia");
        // No storage entry has IOClassNameOverride; the container's medium
        // has its whole table.
        assert!(!property_unknown(&t, media, "IOClassNameOverride"));
        assert!(!property_unknown(&t, media, "IOStorageFeatures"));
        assert_eq!(properties_missing(&t, media), None);
        assert!(superclasses("AppleAPFSContainer").contains(&"IOPartitionScheme"));
        assert!(!superclasses("AppleAPFSContainerScheme").contains(&"IOPartitionScheme"));
        // A volume's location is its slot plus one; its role by name.
        let system = &t[find("System") as usize];
        assert_eq!(location(system).as_deref(), Some("1"));
        assert_eq!(location(&t[find("Container") as usize]).as_deref(), Some("1"));
        assert!(system.service_props.contains(&("Role".to_string(), Prop::Strs(vec!["System".to_string()]))));
        assert_eq!(apfs_role_name(0x140), Some("Hardware"));
        assert_eq!(apfs_role_name(0x3), None);
        // AppleAPFSMedia::init's dictionary, then IOMedia::init's keys,
        // then the UUID and the BSD keys.
        let props = properties(&t, media);
        let keys: Vec<&str> = props.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(&keys[..7], &["Physical Block Size", "Logical Block Size", "IOStorageFeatures", "EncryptionBlockSize", "Content", "Leaf", "Open"]);
        assert!(keys.iter().any(|k| *k == "BSD Name") && keys.iter().any(|k| *k == "UUID"));
        // The two block sizes are one number, written once.
        let bin = serialize_prop(&Prop::Dict(props.clone()));
        let g = super::super::osserialize::unserialize_binary(&bin).unwrap().0;
        assert_eq!(g.objs.iter().filter(|o| matches!(o, super::super::osserialize::Obj::Number { value: 4096, size: 32 })).count(), 2, "Physical/Logical Block Size shared, EncryptionBlockSize its own");
        // An OSSymbol's string matches as an OSString's does.
        let bsd = super::super::storage::container_bsd_name();
        let mut g = super::super::osserialize::Graph::default();
        let d = g.add(super::super::osserialize::Obj::Dict(Vec::new()));
        let v = g.add(super::super::osserialize::Obj::Symbol(bsd.into_bytes()));
        g.dict_set(d, b"BSD Name", v);
        let (g, d) = super::super::iomatch::task_dictionary(&super::super::osserialize::serialize_binary(&g, d)).unwrap().unwrap();
        assert_eq!(super::super::iomatch::existing(&t, &g, d, false), Ok(vec![media]));
        // Up the IOService plane from the medium to the namespace, which
        // has no provider here (no platform).
        let mut up = vec![media];
        while let Ok(Some(p)) = provider(&t, *up.last().unwrap()) {
            up.push(p);
        }
        let classes: Vec<&str> = up.iter().map(|&i| t[i as usize].class).collect();
        assert_eq!(classes, ["AppleAPFSMedia", "AppleAPFSContainerScheme", "IOMedia", "IOGUIDPartitionScheme", "IOMedia", "IOBlockStorageDriver", "IOEmbeddedNVMeBlockDevice"]);
        assert!(provider(&t, *up.last().unwrap()).is_err());
        // Each medium's children: its storage driver, then its BSD client.
        let disk0 = up[4];
        let kids: Vec<&str> = links(&t, disk0, Plane::Service, false).unwrap().iter().map(|&i| t[i as usize].class).collect();
        assert_eq!(kids, ["IOGUIDPartitionScheme", "IOMediaBSDClient"]);
        // A recursive search up the parents finds the namespace's
        // characteristics.
        let (found, refused) = search(&t, media, Plane::Service, 3, "Protocol Characteristics", |_| true).unwrap();
        assert!(found.is_some() && !refused);
    }

    #[test]
    fn async_result_sizes_follow_the_kernel_structure() {
        // One argument: 24 + 208 - 15 * 8 = 112 bytes, as
        // _sendAsyncResult64 computes msgh_size.
        assert_eq!(24 + 208 - (super::MAX_ASYNC_ARGS - 1) * 8, 112);
    }

    use super::*;

    fn prop(out: &mut Vec<u8>, name: &str, value: &[u8]) {
        let mut n = [0u8; 32];
        n[..name.len()].copy_from_slice(name.as_bytes());
        out.extend_from_slice(&n);
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value);
        out.resize((out.len() + 3) & !3, 0);
    }

    #[test]
    fn paths_walk_the_device_tree_by_name() {
        let mut b = Vec::new();
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());
        prop(&mut b, "name", b"device-tree\0");
        b.extend_from_slice(&2u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        prop(&mut b, "name", b"chosen\0");
        prop(&mut b, "boot-type", b"local\0");
        let t = parse(&b).unwrap();
        assert_eq!(t[0].name, "device-tree");
        assert_eq!(from_path(&t, "IODeviceTree:/").unwrap(), Some(0));
        assert_eq!(from_path(&t, "IODeviceTree:/chosen").unwrap(), Some(1));
        assert_eq!(from_path(&t, "IODeviceTree:/nothing").unwrap(), None);
        assert!(from_path(&t, "IOService:/").is_err());
        assert_eq!(t[1].props[1].1, b"local\0");
    }

    fn node(b: &mut Vec<u8>, name: &str, props: &[(&str, &[u8])], children: u32) {
        b.extend_from_slice(&(props.len() as u32 + 1).to_le_bytes());
        b.extend_from_slice(&children.to_le_bytes());
        prop(b, "name", format!("{name}\0").as_bytes());
        for (k, v) in props {
            prop(b, k, v);
        }
    }

    /// device-tree { chosen { memory-map }, arm-io }, under the root.
    fn small_tree() -> Vec<Node> {
        let mut b = Vec::new();
        node(&mut b, "device-tree", &[("compatible", b"J120AP\0iPad7,1\0AppleARM\0")], 2);
        node(&mut b, "chosen", &[], 1);
        node(&mut b, "memory-map", &[("kernel-only", b"")], 0);
        node(&mut b, "arm-io", &[], 0);
        let mut t = parse(&b).unwrap();
        add_root(&mut t);
        t
    }

    #[test]
    fn the_target_is_the_roots_first_compatible() {
        assert_eq!(target_name_of(&small_tree()).unwrap(), b"J120AP");
        let mut b = Vec::new();
        node(&mut b, "device-tree", &[("compatible", b"AAPL,Power Mac/G5\0x\0")], 0);
        assert_eq!(target_name_of(&parse(&b).unwrap()).unwrap(), b"Power-Mac-G5");
        let mut b = Vec::new();
        node(&mut b, "device-tree", &[("compatible", format!("{}\0", "A".repeat(80)).as_bytes())], 0);
        assert_eq!(target_name_of(&parse(&b).unwrap()).unwrap().len(), 63);
        let mut b = Vec::new();
        node(&mut b, "device-tree", &[], 0);
        assert_eq!(target_name_of(&parse(&b).unwrap()), None);
        assert_eq!(target_name_of(&[]), None);
    }

    fn all(t: &[Node], r: &mut RegistryIter) -> Vec<u32> {
        std::iter::from_fn(|| r.next(t).unwrap()).collect()
    }

    #[test]
    fn registry_iterators_walk_the_device_tree_plane() {
        let t = small_tree();
        let root = t.len() as u32 - 1;
        assert_eq!(name(&t, 0), "J120AP");
        assert_eq!(t[0].name, "device-tree");
        assert_eq!(class(&t, 0), Ok("IOPlatformExpertDevice"));
        assert_eq!(class(&t, root), Ok("IORegistryEntry"));
        assert!(t[2].kernel_only && !t[1].kernel_only);
        assert!(class(&t, 1).is_err());
        assert_eq!(conforms(&t, 1, "IOService"), Ok(true));
        assert_eq!(conforms(&t, root, "IOService"), Ok(false));
        // OSObject is every class's root, the registry's root's too.
        assert_eq!(conforms(&t, root, "OSObject"), Ok(true));
        assert_eq!(conforms(&t, 0, "OSObject"), Ok(true));
        assert_eq!(conforms(&t, 1, "OSObject"), Ok(true));
        // Flat: the root's one child; recursive: depth first.
        let mut flat = RegistryIter::new(root, Plane::DeviceTree, 0);
        assert_eq!(all(&t, &mut flat), vec![0]);
        let mut deep = RegistryIter::new(root, Plane::DeviceTree, K_IO_REGISTRY_ITERATE_RECURSIVELY);
        assert_eq!(all(&t, &mut deep), vec![0, 1, 2, 3]);
        deep.reset();
        assert_eq!(all(&t, &mut deep), vec![0, 1, 2, 3]);
        // Entered by hand: the children of the entry last given, and out
        // again to its siblings; no way out of the start.
        let mut hand = RegistryIter::new(0, Plane::DeviceTree, 0);
        assert_eq!(hand.next(&t).unwrap(), Some(1));
        hand.enter();
        assert_eq!(hand.next(&t).unwrap(), Some(2));
        assert_eq!(hand.next(&t).unwrap(), None);
        assert!(hand.exit());
        assert_eq!(hand.next(&t).unwrap(), Some(3));
        assert_eq!(hand.next(&t).unwrap(), None);
        assert!(!hand.exit());
        // Parents: up to the root, and none above it.
        let mut up = RegistryIter::new(2, Plane::DeviceTree, K_IO_REGISTRY_ITERATE_PARENTS | K_IO_REGISTRY_ITERATE_RECURSIVELY);
        assert_eq!(all(&t, &mut up), vec![1, 0, root]);
        // The IOService plane below the root is the drivers'.
        let mut svc = RegistryIter::new(root, Plane::Service, 0);
        assert!(svc.next(&t).is_err());
        assert_eq!(links(&t, 0, Plane::Service, true), Ok(vec![root]));
        assert!(links(&t, 1, Plane::Service, false).is_err());
    }

    /// The path to the GPU: device-tree { chosen, arm-io { sgx, uart0 } }.
    #[test]
    fn the_gpu_path_is_the_devices() {
        let mut b = Vec::new();
        node(&mut b, "device-tree", &[("compatible", b"J120AP\0iPad7,1\0AppleARM\0")], 2);
        node(&mut b, "chosen", &[], 0);
        node(&mut b, "arm-io", &[("compatible", b"arm-io,t8011\0"), ("device_type", b"t8011-io\0")], 2);
        node(&mut b, "sgx", &[("compatible", b"gpu,t8011\0")], 0);
        node(&mut b, "uart0", &[("compatible", b"uart-1,samsung\0")], 0);
        let mut t = parse(&b).unwrap();
        let (chosen, arm_io, sgx, uart) = (1, 2, 3, 4);
        let io = super::super::platform::add(&mut t).unwrap();
        let gpu = super::super::platform::arm_io_nub(&mut t, io, "gpu,t8011").unwrap();
        assert_eq!(gpu, sgx);
        super::super::accel::add_service(&mut t, gpu);
        add_root(&mut t);
        let root = t.len() as u32 - 1;
        let accel = root - 1;
        // Up the IOService plane, each entry's class.
        let mut up = vec![accel];
        while let Some(p) = provider(&t, *up.last().unwrap()).unwrap() {
            up.push(p);
        }
        let classes: Vec<&str> = up.iter().map(|&i| class(&t, i).unwrap()).collect();
        assert_eq!(classes, ["AGXAcceleratorG9G_A0", "AppleARMIODevice", "AppleT8011IO", "IOPlatformDevice", "AppleARMPE", "IOPlatformExpertDevice", "IORegistryEntry"]);
        assert_eq!((up[1], up[3], up[5], up[6]), (sgx, arm_io, 0, root));
        assert_eq!(name(&t, up[2]), "AppleT8011IO");
        assert_eq!(superclasses("AGXAcceleratorG9G_A0")[5..], ["IOGPU", "IOAcceleratorES", "IOService", "IORegistryEntry"]);
        assert_eq!(conforms(&t, up[4], "IODTPlatformExpert"), Ok(true));
        assert_eq!(conforms(&t, up[2], "AppleARMIO"), Ok(true));
        assert_eq!(links(&t, sgx, Plane::Service, true), Ok(vec![up[2]]));
        // The device tree plane is as it was; the drivers' other nubs and
        // the entries no driver here published are not known.
        assert_eq!(links(&t, sgx, Plane::DeviceTree, true), Ok(vec![arm_io]));
        assert!(class(&t, uart).is_err() && provider(&t, uart).is_err() && provider(&t, chosen).is_err());
        assert!(links(&t, arm_io, Plane::Service, false).is_err() && links(&t, up[2], Plane::Service, false).is_err());
        // Properties a driver here may have set are reported, but for
        // IOClassNameOverride; a plain device tree entry has only its own.
        assert!(property_unknown(&t, accel, "PerformanceStatistics") && property_unknown(&t, sgx, "IODeviceMemory"));
        assert!(!property_unknown(&t, accel, "IOClassNameOverride") && !property_unknown(&t, up[4], "IOClassNameOverride") && !property_unknown(&t, 0, "IOClassNameOverride"));
        assert!(property_unknown(&t, 0, "IOPlatformSerialNumber"));
        assert!(!property_unknown(&t, uart, "anything") && property_unknown(&t, root, "IOKitBuildVersion") && !property_unknown(&t, root, "anything"));
        // The display's framebuffer on disp0's nub, a nub of arm-io's
        // driver as the GPU's is.
        let mut b = Vec::new();
        node(&mut b, "device-tree", &[("compatible", b"J120AP\0iPad7,1\0AppleARM\0")], 1);
        node(&mut b, "arm-io", &[("compatible", b"arm-io,t8011\0")], 1);
        node(&mut b, "disp0", &[("compatible", b"disp0,t8011\0")], 0);
        let mut t = parse(&b).unwrap();
        let io = super::super::platform::add(&mut t).unwrap();
        let disp = super::super::platform::arm_io_nub(&mut t, io, "disp0,t8011").unwrap();
        super::super::iomfb::add_service(&mut t, disp);
        add_root(&mut t);
        let clcd = t.len() as u32 - 2;
        let mut up = vec![clcd];
        while let Some(p) = provider(&t, *up.last().unwrap()).unwrap() {
            up.push(p);
        }
        let classes: Vec<&str> = up.iter().map(|&i| class(&t, i).unwrap()).collect();
        assert_eq!(classes, ["AppleCLCD", "AppleARMIODevice", "AppleT8011IO", "IOPlatformDevice", "AppleARMPE", "IOPlatformExpertDevice", "IORegistryEntry"]);
        assert_eq!(conforms(&t, clcd, "IOMobileFramebuffer"), Ok(true));
        // What no driver sets is missing, on the service and its nub;
        // the rest of what the drivers set is not known.
        assert!(!property_unknown(&t, clcd, "GainMapVersion") && !property_unknown(&t, disp, "canvas-width"));
        assert!(!property_unknown(&t, clcd, "dfr") && !property_unknown(&t, clcd, "IOMFBIntDcpUsedForExtWhenLidClose"));
        assert!(property_unknown(&t, clcd, "IOMFBSupportsHeadOfLineSwaps") && property_unknown(&t, disp, "IODeviceMemory"));
        // AppleCLCD sets external only from its provider's device tree
        // entry, which has none here.
        assert!(!property_unknown(&t, clcd, "external"));
        t[disp as usize].props.push(("external".to_string(), 1u32.to_le_bytes().to_vec()));
        assert!(property_unknown(&t, clcd, "external"));
        // The personality's dictionary, serialized as OSSerializeBinary.
        let backlight = &t[clcd as usize].service_props.iter().find(|(k, _)| k == "BacklightMatching").unwrap().1;
        let bin = serialize_prop(backlight);
        assert_eq!(&bin[..8], &[0xd3, 0, 0, 0, 1, 0, 0, 0x81]);
        // Without the platform's compatible name, no expert here matches.
        let mut b = Vec::new();
        node(&mut b, "device-tree", &[("compatible", b"Other\0")], 0);
        assert_eq!(super::super::platform::add(&mut parse(&b).unwrap()), None);
    }

    /// IOSurfaceRoot on IOResources, on the root.
    #[test]
    fn iosurface_root_hangs_from_the_resources_nub() {
        let mut t = small_tree();
        t.pop();
        let resources = super::super::platform::add_resources(&mut t);
        super::super::iosurface::add_service(&mut t, resources);
        let surface = resources + 1;
        add_root(&mut t);
        let root = t.len() as u32 - 1;
        assert_eq!((class(&t, resources), class(&t, surface)), (Ok("IOResources"), Ok("IOSurfaceRoot")));
        assert_eq!(name(&t, resources), "IOResources");
        assert_eq!((provider(&t, surface), provider(&t, resources)), (Ok(Some(resources)), Ok(Some(root))));
        assert_eq!(links(&t, resources, Plane::Service, true), Ok(vec![root]));
        assert!(links(&t, resources, Plane::Service, false).is_err());
        // Sandbox's walk: the root's class, its provider's, the registry's.
        let chains: Vec<Vec<&str>> = chains_from(&t, Some(surface)).into_iter().map(Option::unwrap).collect();
        assert_eq!(chains, [vec!["IOSurfaceRoot", "IOService", "IORegistryEntry", "OSObject"], vec!["IOResources", "IOService", "IORegistryEntry", "OSObject"], vec!["IORegistryEntry", "OSObject"]]);
        // The kernel's resources are published; the others are not known.
        assert!(t[resources as usize].service_props.iter().all(|(_, v)| *v == Prop::Sym("IOService".to_string())));
        assert!(property_unknown(&t, resources, "IONVRAM") && property_unknown(&t, resources, "IOResourceMatched"));
        let matching = |pairs: &[(&str, &str)]| {
            use super::super::osserialize::{serialize_binary, Graph, Obj};
            let mut g = Graph::default();
            let d = g.add(Obj::Dict(Vec::new()));
            for (k, v) in pairs {
                let v = g.add(Obj::String(v.as_bytes().to_vec()));
                g.dict_set(d, k.as_bytes(), v);
            }
            let (g, d) = super::super::iomatch::task_dictionary(&serialize_binary(&g, d)).unwrap().unwrap();
            super::super::iomatch::existing(&t, &g, d, false)
        };
        assert_eq!(matching(&[("IOProviderClass", "IOResources")]), Ok(vec![resources]));
        assert_eq!(matching(&[("IOProviderClass", "IOResources"), ("IOResourceMatch", "IOBSD")]), Ok(vec![resources]));
        assert!(matching(&[("IOProviderClass", "IOResources"), ("IOResourceMatch", "IONVRAM")]).is_err());
    }
}
