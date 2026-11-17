//! The registry's power plane (`IOPower`) and the power management
//! dictionary of the services that join it, as the device's kernelcache
//! (21H461, iPad7,1) builds them by the end of boot, with the system awake:
//!
//! ```text
//! Root                            the registry's root
//!   IORootParent                  the power plane's root node
//!     IOPowerConnection
//!       IOPMrootDomain            the root power domain
//!         IOPowerConnection
//!           AppleCLCD             (the display's framebuffer)
//!         IOPowerConnection
//!           AppleT8011PCIe        the PCIe root complex's driver
//!             IOPowerConnection
//!               pci-bridge0       the root port's nub
//!                 IOPowerConnection
//!                   IOPP          the root port's driver
//!                     IOPowerConnection
//!                       s3e       the NAND controller's nub
//!                         IOPowerConnection
//!                           AppleEmbeddedNVMeController
//!                             IOPowerConnection
//!                               IOBlockStorageDriver (NS_01's)
//!                             IOPowerConnection
//!                               IOBlockStorageDriver (NS_02's)
//! ```
//!
//! - The root domain. AppleARMPE's `PMInstantiatePowerDomains`
//!   (0xfffffff005990054, its vtable's slot 0x568) makes an
//!   `IOPMrootDomain`, attaches it to the platform expert in the
//!   `IOService` plane and starts it; `IOPlatformExpert::start` calls it
//!   (0xfffffff00780b260) before `configure` publishes the top-level nubs.
//!   Its start (0xfffffff0078615a0) makes the power plane's root, an
//!   `IORootParent` it attaches below itself in the `IOService` plane
//!   (0xfffffff0078626f4) and whose start attaches it to the registry's
//!   root in the power plane (0xfffffff00786a448), then makes itself that
//!   node's power child (0xfffffff00786271c). It registers itself
//!   (0xfffffff0078629f8); the root parent does not.
//! - The other services. `joinPMtree` hands a service to the platform
//!   expert's `PMRegisterDevice`, which AppleARMPE overrides
//!   (0xfffffff005990128, slot 0x620): from the nub up its providers, the
//!   first service already in the power plane becomes the parent, else the
//!   root domain, by `addPowerChild`, which links parent, a new
//!   `IOPowerConnection` and child there at once. Of the platform's
//!   services here only AppleCLCD joins (its nub's `joinPMtree`,
//!   0xfffffff006bf525c): AppleARMPE joins only when its provider has
//!   "no-suspend" (0xfffffff00598f910), which the device tree root has not;
//!   AppleARMIO's start (0xfffffff00598c0b4) calls `PMinit` and
//!   `temporaryPowerClampOn` but never joins; the nubs, IOResources and
//!   IOSurfaceRoot never call `PMinit`. AGX joins below the GPU
//!   coprocessor's RTBuddy service (through its firmware object,
//!   0xfffffff006c3e98c), which is not here. On the storage's path,
//!   `IOPCIBridge::start` (0xfffffff0064c4f5c) and `IOPCIDevice::attach`
//!   join their providers, the controller joins its nub
//!   (0xfffffff006a874dc), and each `IOBlockStorageDriver` its namespace,
//!   whose walk ends at the controller. No other service of the storage
//!   stack calls `PMinit`.
//!
//! `IOPowerConnection` (its metaclass 0xfffffff007942918, below
//! `IOService`) has no properties, is in no other plane and is not
//! registered; its name is its class's.
//!
//! The dictionary (`IOServicePM::gatedSerialize`, 0xfffffff0077cfdb0):
//! a copy of the service's power clients in the order they were first
//! requested (32-bit numbers), then CurrentPowerState, CapabilityFlags,
//! MaxPowerState (with a power driver: its count of states less one) and
//! DesiredPowerState (when it differs from the current), 64-bit numbers;
//! MachineState only while a change is in progress, and no service here
//! has an idle timer, an override or a clamp. `PMinit` sets the key in
//! the service's table where it is called.

use super::iokit::{Node, Prop, Table};

/// The classes here.
pub const ROOT_DOMAIN: &str = "IOPMrootDomain";
pub const ROOT_PARENT: &str = "IORootParent";
pub const CONNECTION: &str = "IOPowerConnection";

/// The power management dictionary's key (`kPwrMgtKey`).
pub const KEY: &str = "IOPowerManagement";

/// A node's link to its parent in the power plane ([`Node::power`]) that
/// names the registry's root, which is the tree's last entry.
pub const TO_REGISTRY_ROOT: u32 = u32::MAX;

/// The classes here, most derived first, from their metaclasses
/// (IOPMrootDomain 0xfffffff007942c90, IORootParent 0xfffffff007942e28 and
/// IOPowerConnection 0xfffffff007942918, each below IOService).
pub fn superclasses(class: &str) -> &'static [&'static str] {
    match class {
        ROOT_DOMAIN => &[ROOT_DOMAIN, "IOService", "IORegistryEntry"],
        ROOT_PARENT => &[ROOT_PARENT, "IOService", "IORegistryEntry"],
        CONNECTION => &[CONNECTION, "IOService", "IORegistryEntry"],
        _ => &[],
    }
}

/// Whether a service of `class` here registers itself: the root domain
/// does; the root parent and the connections do not.
pub fn registers(class: &str) -> Option<bool> {
    match class {
        ROOT_DOMAIN => Some(true),
        ROOT_PARENT | CONNECTION => Some(false),
        _ => None,
    }
}

/// Whether every service of `class` is here: there is one root domain.
pub fn class_complete(class: &str) -> bool {
    class == ROOT_DOMAIN
}

/// A power management dictionary: the power clients in their order, then
/// the current state, its capability flags and, for a service with a
/// power driver, the highest state's index.
pub fn dict(clients: &[(&str, u32)], current: u64, capabilities: u64, max: Option<u64>) -> Prop {
    let mut d: Vec<(String, Prop)> = clients.iter().map(|&(k, v)| (k.to_string(), Prop::Num(u64::from(v), 32))).collect();
    d.push(("CurrentPowerState".to_string(), Prop::Num(current, 64)));
    d.push(("CapabilityFlags".to_string(), Prop::Num(capabilities, 64)));
    if let Some(m) = max {
        d.push(("MaxPowerState".to_string(), Prop::Num(m, 64)));
    }
    Prop::Dict(d)
}

/// The dictionary of a service whose `PMinit` and `temporaryPowerClampOn`
/// ran and that registered no power driver (AppleARMIO's start): its child
/// proxy's request, `kIOPMPowerStateMax`, which the state limit leaves as
/// it is with no power states; state 0, no capabilities.
pub fn clamped_without_driver() -> Prop {
    dict(&[("ChildProxyPowerState", u32::MAX)], 0, 0, None)
}

/// The dictionary of a service that joined the plane and registered no
/// power driver (`IOBlockStorageDriver::start`, 0xfffffff00596f594): it
/// never requests power, and stays in state 0.
pub fn joined_without_driver() -> Prop {
    dict(&[], 0, 0, None)
}

/// The PCI host bridge's and a PCI-to-PCI bridge's power states
/// (IOPCIBridge's, 0xfffffff0055536a0) and a PCI function's
/// (IOPCIDevice's, 0xfffffff005553820): off, doze, on and paused, ordered
/// off, doze, paused, on, so the highest is on, index 2, whose capability
/// flags are kIOPMPowerOn | kIOPMDeviceUsable (0x102). With the root
/// domain on and giving kIOPMPowerOn, each settles there: the bridge on its
/// child's request for it (ChildrenPowerState), a function too once its
/// `temporaryPowerClampOn` (`IOPCIDevice::attach`) has asked its child
/// proxy for `kIOPMPowerStateMax`, which registering its states limits to
/// the highest, 2.
pub fn pci_bridge() -> Prop {
    dict(&[("ChildrenPowerState", 2)], 2, 0x102, Some(3))
}

/// A PCI function's dictionary ([`pci_bridge`]).
pub fn pci_function() -> Prop {
    dict(&[("ChildProxyPowerState", 2), ("ChildrenPowerState", 2)], 2, 0x102, Some(3))
}

/// The NVMe controller's (`InitializePowerManagement`, 0xfffffff006a874dc):
/// two states (0xfffffff007c17c78), off and usable (0x8000, needing
/// kIOPMPowerOn), and `makeUsable`, which asks for the highest; its
/// storage drivers, with no power states, never ask it for power.
pub fn nvme_controller() -> Prop {
    dict(&[("DevicePowerState", 1)], 1, 0x8000, Some(1))
}

/// AGX's (0xfffffff005be465c on): two states (0xfffffff007aeb988), off and
/// on (capability, output and input kIOPMPowerOn), and
/// `changePowerStateTo(1)`, its one request, at its start
/// (0xfffffff005be46a8).
pub fn gpu() -> Prop {
    dict(&[("DriverPowerState", 1)], 1, 2, Some(1))
}

/// The root domain's: five states (0xfffffff0078df1a0; ON, index 4, has
/// capability kIOPMPowerOn), the state its start asks for
/// (`changePowerStateWithTagToPriv(ON_STATE)`, 0xfffffff00786274c), and
/// its children's requests, which its `requestPowerDomainState` override
/// (0xfffffff00786307c) maps to state 0.
pub fn root_domain() -> Prop {
    dict(&[("DevicePowerState", 4), ("ChildrenPowerState", 0)], 4, 2, Some(4))
}

/// A service entry here.
fn entry(name: &str, class: &'static str, parent: Option<u32>, service_props: Vec<(String, Prop)>, table: Table) -> Node {
    Node { name: name.to_string(), props: Vec::new(), class, service_props, parent, children: Vec::new(), kernel_only: false, nub: None, dt: None, table, power: None }
}

/// Add the root domain below the platform expert `pe`, and the power
/// plane's root: the root domain's index.
///
/// The root domain's table, in the order it is set: its start's
/// IOSleepSupported (0xfffffff007861e8c), IOPMUserIsActive
/// (0xfffffff007861fa8), System Capabilities 0xf (64 bits,
/// 0xfffffff007861fd4), BootSessionUUID (`initializeBootSessionUUID`: a
/// random UUID in capitals, a symbol; the one `kern.bootsessionuuid`
/// gives), Supported Features (0xfffffff0078622c8), an empty
/// SystemPowerProfileOverrideDict (0xfffffff007862360), IOPowerManagement
/// (`PMinit`, 0xfffffff0078625b0) and IOUserClientClass
/// "RootDomainUserClient" (0xfffffff007862968); then AppleT801xIO's start's
/// IOPMSystemSleepType 7 (32 bits, 0xfffffff006c414d0). Supported Features
/// gains each feature a kext publishes at boot (`publishFeature`: an id
/// counted from 500 in the order the publishers start, AppleARMRTC's six
/// among them), and the kexts and powerd set more keys at run time: those
/// are not modelled.
///
/// The root parent's table is its dictionary alone, which holds the PM
/// work queue's counters (WQ-CheckForWork and its kin, the kernel's build
/// having WORK_QUEUE_STATS): not modelled.
pub fn add(t: &mut Vec<Node>, pe: u32) -> u32 {
    let sym = |s: &str| Prop::Sym(s.to_string());
    let props = vec![
        ("IOSleepSupported".to_string(), Prop::Bool(true)),
        ("IOPMUserIsActive".to_string(), Prop::Bool(true)),
        ("System Capabilities".to_string(), Prop::Num(0xf, 64)),
        ("BootSessionUUID".to_string(), sym(super::sysctl::bootsessionuuid())),
        ("SystemPowerProfileOverrideDict".to_string(), Prop::Dict(Vec::new())),
        (KEY.to_string(), root_domain()),
        ("IOUserClientClass".to_string(), sym("RootDomainUserClient")),
        ("IOPMSystemSleepType".to_string(), Prop::Num(7, 32)),
    ];
    let what = "Supported Features (the features the kexts publish at boot, each with an id in the order they start), and the keys the kexts and powerd set at run time".to_string();
    let rd = t.len() as u32;
    t.push(entry(ROOT_DOMAIN, ROOT_DOMAIN, Some(pe), props, Table::Partial(what)));
    t[pe as usize].children.push(rd);
    let rp = t.len() as u32;
    let mut parent = entry(ROOT_PARENT, ROOT_PARENT, Some(rd), Vec::new(), Table::Lacks(vec![(KEY, "the PM work queue's counters, which it serializes")]));
    parent.power = Some(TO_REGISTRY_ROOT);
    t.push(parent);
    t[rd as usize].children.push(rp);
    join(t, rp, rd);
    rd
}

/// `parent->addPowerChild(child)`: a connection between them in the power
/// plane.
pub fn join(t: &mut Vec<Node>, parent: u32, child: u32) {
    let c = t.len() as u32;
    let mut n = entry(CONNECTION, CONNECTION, None, Vec::new(), Table::Complete);
    n.power = Some(parent);
    t.push(n);
    t[child as usize].power = Some(c);
}

/// Join the services here that join the power plane at boot, in the order
/// their joins run: AppleCLCD and the PCIe root complex below the root
/// domain `rd`; the root port's nub below the root complex, its driver
/// below it, the controller's nub below that, the controller below its
/// nub; each namespace's storage driver below the controller, in the order
/// they started.
pub fn join_services(t: &mut Vec<Node>, rd: u32) {
    let find = |t: &[Node], class: &str| t.iter().position(|n| n.class == class).map(|i| i as u32);
    if let Some(clcd) = find(t, super::iomfb::CLASS) {
        join(t, rd, clcd);
    }
    let Some(rc) = find(t, super::storagestack::T8011_PCIE) else { return };
    join(t, rd, rc);
    let mut parent = rc;
    for class in [super::storagestack::PCI_DEVICE, super::storagestack::HOST_BRIDGE, super::storagestack::PCI_DEVICE, super::storagestack::CONTROLLER] {
        let Some(c) = t.iter().enumerate().find(|(_, n)| n.class == class && n.parent == Some(parent)).map(|(i, _)| i as u32) else { return };
        join(t, parent, c);
        parent = c;
    }
    let drivers: Vec<u32> = t.iter().enumerate().filter(|(_, n)| n.class == super::storagestack::DRIVER && n.parent.and_then(|ns| t[ns as usize].parent) == Some(parent)).map(|(i, _)| i as u32).collect();
    for d in drivers {
        join(t, parent, d);
    }
}

/// Whether entry `i` (not the registry's root) is in the power plane;
/// `Err` naming what is not known of it.
fn in_plane(t: &[Node], i: u32) -> Result<bool, String> {
    let n = &t[i as usize];
    if n.power.is_some() {
        return Ok(true);
    }
    if n.class == super::accel::CLASS {
        return Err(format!("{}'s parent in the power plane, the GPU coprocessor's RTBuddy service", n.name));
    }
    Ok(false)
}

/// The power children not here of a service that has some: the root
/// domain's (every other driver that joins at boot), AppleCLCD's (not
/// traced), the PCIe root complex's (pci-bridge2's nub, as in the
/// `IOService` plane).
fn children_unknown(class: &str) -> Option<&'static str> {
    match class {
        ROOT_DOMAIN => Some("the root domain's other power children (the drivers of every kext that joins the power plane at boot)"),
        super::iomfb::CLASS => Some("AppleCLCD's power children, not traced"),
        super::storagestack::T8011_PCIE => Some("pci-bridge2's nub, which joins the root complex once the WLAN driver enables its port"),
        super::accel::CLASS => Some("AGX's power children, not traced"),
        _ => None,
    }
}

/// The entry's links in the power plane: its parent there (the registry's
/// root for the root parent, a connection for a joined service, the parent
/// for a connection), or its children (connections, or a connection's
/// child), in the order they were linked.
pub fn links(t: &[Node], i: u32, parents: bool) -> Result<Vec<u32>, String> {
    let root = t.len() as u32 - 1;
    let below = |p: u32| t.iter().enumerate().filter(|(_, n)| n.power == Some(p)).map(|(j, _)| j as u32).collect::<Vec<_>>();
    if i == root {
        return Ok(if parents { Vec::new() } else { below(TO_REGISTRY_ROOT) });
    }
    let n = &t[i as usize];
    if !in_plane(t, i)? {
        return Ok(Vec::new());
    }
    if parents {
        return Ok(match n.power {
            Some(TO_REGISTRY_ROOT) => vec![root],
            Some(p) => vec![p],
            None => Vec::new(),
        });
    }
    if let Some(what) = children_unknown(n.class) {
        return Err(what.to_string());
    }
    Ok(below(i))
}
