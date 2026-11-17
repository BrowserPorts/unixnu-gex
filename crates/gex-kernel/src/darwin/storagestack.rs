//! The internal storage's entries in the registry, as the device's
//! kernelcache (21H461, iPad7,1) publishes them in the `IOService` plane:
//!
//! ```text
//! AppleT8011IO                    arm-io's driver (super::platform)
//!   apcie                         AppleARMIODevice, a nub of arm-io's apcie
//!     AppleT8011PCIe              the PCIe root complex's driver
//!       pci-bridge0@0             IOPCIDevice, the root port
//!         IOPP                    ApplePCIEHostBridge
//!           s3e@0                 IOPCIDevice, the NAND's controller
//!             AppleEmbeddedNVMeController
//!               NS_01@1           IOEmbeddedNVMeBlockDevice, NSID 1
//!                 IOBlockStorageDriver
//!                   <model> Media IOMedia, disk0
//!                     IOGUIDPartitionScheme
//!                       Container@1           IOMedia, disk0s1
//!                         AppleAPFSContainerScheme
//!                           AppleAPFSMedia    disk1
//!                             AppleAPFSContainer
//!                               <volume>@<slot+1>   AppleAPFSVolume
//!                                 AppleAPFSVolumeBSDClient
//!                             AppleAPFSMediaBSDClient
//!                         IOMediaBSDClient
//!                     IOMediaBSDClient
//! ```
//!
//! - The PCIe path. `AppleT8011PCIe` (com.apple.driver.AppleT8011PCIe) is
//!   the one personality naming apcie (`IONameMatch` "apcie,t8011"). Its
//!   `IOPCIBridge::start` publishes a new `IOPCIDevice` for each device it
//!   finds (`bridgeConstructDeviceTree`, 0xfffffff0064d9540): the nub
//!   copies its device tree entry's properties, is named after it and
//!   attached below the bridge's device tree entry in the `IODeviceTree`
//!   plane (0xfffffff0064d998c), its location `"%X"` of its device number
//!   (`publishNub`), the entry's `AAPL,unit-string` 00000000 being device 0.
//!   `ApplePCIEHostBridge` (`IONameMatch` "apcie-bridge", score 5000) drives
//!   the root port and names itself "IOPP" (`IOPCI2PCIBridge::start`,
//!   0xfffffff0064cc67c); it publishes s3e's nub the same way, below the
//!   root port's nub in the `IODeviceTree` plane.
//! - The controller. `AppleEmbeddedNVMeController` (IONVMeFamily,
//!   `IOPCIMatch` 0x2002106b, `IOPCIClassMatch` 0x01800200&0xffffff00) is
//!   the one personality that matches s3e. Its start (0xfffffff006a81d90)
//!   makes its temperature sensor, its NVRAM, then a nub per namespace of
//!   the device tree's `namespaces` (`AllocateNodes`, 0xfffffff006a5e35c):
//!   NSID 1, the root, an `IOEmbeddedNVMeBlockDevice` named "NS_01"
//!   (0xfffffff006a6ee48) at location "1" (`initWithNamespace`,
//!   0xfffffff006a98c20).
//! - `IOBlockStorageDevice::init` (0xfffffff00596ee30) gives the namespace
//!   "device-type" "Generic", which `IOBlockStorageDriver`'s personality
//!   matches; the driver's media is the whole disk, named "<vendor>
//!   <product> Media" (`acceptNewMedia`; the vendor string is empty,
//!   0xfffffff006a96df4) and attached in the `IODeviceTree` plane to the
//!   nearest provider there, s3e's nub, as "disk" at "<IOUnit>:0".
//! - `IOGUIDPartitionScheme` (score 4000, `Content Mask`
//!   "GUID_partition_scheme") reads the GPT and publishes the partition,
//!   named for its entry and attached in the `IODeviceTree` plane beside
//!   the disk (`attachMediaObjectToDeviceTree`, 0xfffffff00597cb0c) as
//!   "disk" at "<IOUnit>:1".
//! - APFS's: `AppleAPFSContainerScheme` matches the partition by its type
//!   (`Content Hint` 7C3457EF-..., score 2000), publishes the container's
//!   synthesized whole disk, an `AppleAPFSMedia` (0xfffffff0066829d4), on
//!   which `AppleAPFSContainer` (`Content Hint` EF57347C-..., score 1000)
//!   publishes a volume per slot ([`super::storage`]).
//! - `IOMediaBSDClient` (`IOResourceMatch` IOBSD, score 30000) matches every
//!   IOMedia, and APFS's `AppleAPFSMediaBSDClient` and
//!   `AppleAPFSVolumeBSDClient` (31000) its own. Each gives its medium its
//!   BSD keys ([`super::storage::units`]). It matches once `IOKitBSDInit`
//!   publishes IOBSD, so it attaches after the storage driver below the
//!   medium (the media order's stand-in, [`super::storage::media_order`]).
//!
//! The controller's other namespaces (its firmware namespace NS_02 with its
//! own driver and whole disk, NS_03's diagnostics, NS_05's NVRAM, NS_06's
//! effaceable storage and NS_07's panic log) and its temperature sensor are
//! its children too, and not modelled: its children are reported when read.
//!
//! Each class's superclasses are its `OSMetaClass` constructor's.

use super::iokit::{DtLink, Node, Prop, Table};
use super::storage::Media;

pub const T8011_PCIE: &str = "AppleT8011PCIe";
pub const PCI_DEVICE: &str = "IOPCIDevice";
pub const HOST_BRIDGE: &str = "ApplePCIEHostBridge";
pub const CONTROLLER: &str = "AppleEmbeddedNVMeController";
pub const BLOCK_DEVICE: &str = "IOEmbeddedNVMeBlockDevice";
pub const DRIVER: &str = "IOBlockStorageDriver";
pub const GPT: &str = "IOGUIDPartitionScheme";
pub const BSD_CLIENT: &str = "IOMediaBSDClient";
pub const APFS_SCHEME: &str = "AppleAPFSContainerScheme";
pub const APFS_MEDIA: &str = "AppleAPFSMedia";
pub const APFS_CONTAINER: &str = "AppleAPFSContainer";
pub const APFS_VOLUME: &str = "AppleAPFSVolume";
pub const APFS_MEDIA_BSD: &str = "AppleAPFSMediaBSDClient";
pub const APFS_VOLUME_BSD: &str = "AppleAPFSVolumeBSDClient";

/// The classes here, most derived first (to `IORegistryEntry`), from their
/// metaclasses' constructors: AppleT8011PCIe's (0xfffffff007c186e8,
/// AppleT801xPCIe 0xfffffff007c18698), AppleEmbeddedPCIE's
/// (0xfffffff007b2cc58, ApplePCIEHostBridge 0xfffffff007b2ccd0),
/// IOPCIFamily's (IOPCIHostBridge 0xfffffff007b261a8, IOPCIBridge
/// 0xfffffff007b261d0, IOPCI2PCIBridge 0xfffffff007b261f8, IOPCIDevice
/// 0xfffffff007b26248), IONVMeFamily's (0xfffffff006a5aa84 and on),
/// IOStorageFamily's and APFS's (the scheme an IOStorage, the container an
/// IOPartitionScheme).
pub fn superclasses(class: &str) -> &'static [&'static str] {
    match class {
        T8011_PCIE => &[T8011_PCIE, "AppleT801xPCIe", "AppleEmbeddedPCIE", "IOPCIHostBridge", "IOPCIBridge", "IOService", "IORegistryEntry"],
        PCI_DEVICE => &[PCI_DEVICE, "IOService", "IORegistryEntry"],
        HOST_BRIDGE => &[HOST_BRIDGE, "IOPCI2PCIBridge", "IOPCIBridge", "IOService", "IORegistryEntry"],
        CONTROLLER => &[CONTROLLER, "AppleNVMeController", "IONVMeController", "IOService", "IORegistryEntry"],
        BLOCK_DEVICE => &[BLOCK_DEVICE, "IONVMeBlockStorageDevice", "IOBlockStorageDevice", "IOService", "IORegistryEntry"],
        DRIVER => &[DRIVER, "IOStorage", "IOService", "IORegistryEntry"],
        "IOMedia" => &["IOMedia", "IOStorage", "IOService", "IORegistryEntry"],
        GPT => &[GPT, "IOPartitionScheme", "IOStorage", "IOService", "IORegistryEntry"],
        BSD_CLIENT => &[BSD_CLIENT, "IOService", "IORegistryEntry"],
        APFS_SCHEME => &[APFS_SCHEME, "IOStorage", "IOService", "IORegistryEntry"],
        APFS_MEDIA => &[APFS_MEDIA, "IOMedia", "IOStorage", "IOService", "IORegistryEntry"],
        APFS_CONTAINER => &[APFS_CONTAINER, "IOPartitionScheme", "IOStorage", "IOService", "IORegistryEntry"],
        APFS_VOLUME => &[APFS_VOLUME, "IOMedia", "IOStorage", "IOService", "IORegistryEntry"],
        APFS_MEDIA_BSD => &[APFS_MEDIA_BSD, BSD_CLIENT, "IOService", "IORegistryEntry"],
        APFS_VOLUME_BSD => &[APFS_VOLUME_BSD, BSD_CLIENT, "IOService", "IORegistryEntry"],
        _ => &[],
    }
}

/// What is not modelled of a service's children in the `IOService` plane:
/// the root complex's other ports and its user clients; the controller's
/// other namespaces and objects (the module's documentation). The others
/// here have all theirs (user clients are not registry entries here).
pub fn children_unknown(class: &str) -> Option<&'static str> {
    match class {
        T8011_PCIE => Some("the root complex's other ports (pci-bridge2, whose port is enabled by hand)"),
        CONTROLLER => Some("the controller's temperature sensor, NVRAM and namespaces other than NSID 1"),
        _ => None,
    }
}

/// Whether every service of `class` is here: the storage stack's, whose
/// objects are one each but for the media, BSD clients and drivers the
/// controller's other namespaces add.
pub fn class_complete(class: &str) -> bool {
    matches!(class, APFS_SCHEME | APFS_MEDIA | APFS_CONTAINER | APFS_VOLUME | APFS_MEDIA_BSD | APFS_VOLUME_BSD | GPT | HOST_BRIDGE | T8011_PCIE)
}

/// A string as an `OSSymbol` (`setProperty(const char *, const char *)`,
/// and the keys personalities unique).
fn sym(s: &str) -> Prop {
    Prop::Sym(s.to_string())
}

/// A string as an `OSString` (a personality's other strings, and the
/// dictionaries the drivers build with `OSString::withCString`).
fn string(s: &str) -> Prop {
    Prop::Str(s.to_string())
}

fn num32(v: u64) -> Prop {
    Prop::Num(v, 32)
}

fn num64(v: u64) -> Prop {
    Prop::Num(v, 64)
}

fn key(k: &str, v: Prop) -> (String, Prop) {
    (k.to_string(), v)
}

/// `uuid_unparse` (libkern's, capitals) of a UUID.
pub fn uuid_string(u: &[u8; 16]) -> String {
    let h: Vec<String> = u.iter().map(|b| format!("{b:02X}")).collect();
    format!("{}-{}-{}-{}-{}", h[0..4].concat(), h[4..6].concat(), h[6..8].concat(), h[8..10].concat(), h[10..16].concat())
}

/// A matched driver's properties: its personality's, with what matching
/// adds ([`super::platform::driver_props`]).
fn driver(bundle: &str, class: &str, provider: &str, matched: Option<&str>, category: &str, score: u64, personality: Vec<(String, Prop)>) -> Vec<(String, Prop)> {
    super::platform::driver_props(bundle, class, provider, matched, category, score, personality)
}

/// `IOMedia::init`'s keys in the kernelcache's order (0xfffffff005977630):
/// Content and Leaf and Open (a medium's first init), then Content Hint,
/// Ejectable, Preferred Block Size, Removable, Size, Whole and Writable;
/// Content and Content Hint as symbols. A storage driver attached below it
/// (IOMatchCategory IOStorage) made it no leaf and its Content the driver's
/// Content Mask, if it has one (`attachToChild`).
fn medium(content: &str, hint: &str, leaf: bool, block: u64, size: u64, whole: bool, writable: bool) -> Vec<(String, Prop)> {
    vec![
        key("Content", sym(content)),
        key("Leaf", Prop::Bool(leaf)),
        key("Open", Prop::Bool(false)),
        key("Content Hint", sym(hint)),
        key("Ejectable", Prop::Bool(false)),
        key("Preferred Block Size", num64(block)),
        key("Removable", Prop::Bool(false)),
        key("Size", num64(size)),
        key("Whole", Prop::Bool(whole)),
        key("Writable", Prop::Bool(writable)),
    ]
}

/// What `IOMediaBSDClient::createNodes` sets on a medium: its "BSD Name"
/// (a symbol), and as 32-bit numbers its "BSD Unit" (its whole disk's
/// anchor), "BSD Major" and "BSD Minor" (IOMediaBSDClient.cpp).
fn bsd_keys(m: Media) -> Vec<(String, Prop)> {
    let name = super::storage::media_bsd_name(m);
    let minor = super::storage::media_by_name(&name).map_or(0, |(_, minor)| minor);
    let unit = match m {
        Media::Whole | Media::Partition => super::storage::units().main,
        Media::Container | Media::Volume(_) => super::storage::units().container,
    };
    vec![key("BSD Name", Prop::Sym(name)), key("BSD Unit", num32(u64::from(unit))), key("BSD Major", num32(u64::from(super::storage::DISK_MAJOR))), key("BSD Minor", num32(u64::from(minor)))]
}

/// The GPT partition type of an APFS container, the AppleAPFSMedia's
/// content, and an APFS volume's.
pub const CONTAINER_PARTITION_HINT: &str = "7C3457EF-0000-11AA-AA11-00306543ECAC";
pub const APFS_CONTAINER_HINT: &str = "EF57347C-0000-11AA-AA11-00306543ECAC";
pub const APFS_VOLUME_HINT: &str = "41504653-0000-11AA-AA11-00306543ECAC";

/// The container's medium's block sizes: min(nx_block_size, 4096) (the
/// container scheme's probe, 0xfffffff0066827e4), 4096 since a container's
/// block is at least NX_MINIMUM_BLOCK_SIZE, 4096 (Apple File System
/// Reference).
pub const APFS_BLOCK: u64 = 4096;

/// The partition's GPT entry name, which the restore gives it.
pub const PARTITION_NAME: &str = "Container";

/// A service entry.
fn service(name: &str, class: &'static str, parent: Option<u32>, service_props: Vec<(String, Prop)>, table: Table) -> Node {
    Node { name: name.to_string(), props: Vec::new(), class, service_props, parent, children: Vec::new(), kernel_only: false, nub: None, dt: None, table }
}

/// Push `n` below its parent; its index.
fn push(t: &mut Vec<Node>, n: Node) -> u32 {
    let at = t.len() as u32;
    if let Some(p) = n.parent {
        t[p as usize].children.push(at);
    }
    t.push(n);
    at
}

/// Publish the storage stack. With `io`, arm-io's driver, the PCIe path to
/// the controller is published too; without, the namespace's block device
/// heads the stack with no provider (a registry with no platform).
pub(crate) fn add(t: &mut Vec<Node>, io: Option<u32>) {
    let controller = io.and_then(|io| add_pcie(t, io));
    add_storage(t, controller);
}

/// The PCIe path from arm-io's driver to the NVMe controller: the
/// controller's entry, when the device tree has the path.
fn add_pcie(t: &mut Vec<Node>, io: u32) -> Option<u32> {
    let apcie = super::platform::arm_io_nub(t, io, "apcie,t8011")?;
    let bridge0 = super::platform::child(t, apcie, "pci-bridge0", &[])?;
    let s3e = super::platform::child(t, bridge0, "s3e", &[])?;
    // The personality "AppleT8011PCIe"; no probe of its own, and
    // IOPCIHostBridge's (0xfffffff0064c3dfc) leaves the score. Its start
    // sets its user client class (0xfffffff0066183c8) and the function
    // parent key AppleARMPlatform's helper makes of apcie's phandle 0xa5
    // (0xfffffff005988104), empty data.
    let mut props = driver("com.apple.driver.AppleT8011PCIe", T8011_PCIE, super::platform::ARM_IO_DEVICE, Some("apcie,t8011"), "IODefaultMatchCategory", 0, vec![
        key("IONameMatch", string("apcie,t8011")),
        key("IOPlatformQuiesceAction", num64(4000)),
        key("IOPlatformActiveAction", num64(1500)),
    ]);
    props.push(key("IOUserClientClass", sym("AppleEmbeddedPCIEUserClient")));
    props.push(key(&format!("IOFunctionParent{:08X}", 0xa5), Prop::Data(Vec::new())));
    let rc = push(t, service(T8011_PCIE, T8011_PCIE, Some(apcie), props, Table::Lacks(vec![("what AppleEmbeddedPCIE::configure sets", "not followed")])));
    // apcie as the host bridge's configuration left it: three address
    // cells and two size cells (as its device tree entry has them), and
    // configured (`bridgeConstructDeviceTree`).
    t[apcie as usize].service_props.push(key("IOPCIConfigured", Prop::Bool(true)));
    // Each root port's entry gains its port object (`_buildPortProperties`,
    // 0xfffffff00661858c), which serializes as its class's note.
    for name in ["pci-bridge0", "pci-bridge2"] {
        if let Some(e) = super::platform::child(t, apcie, name, &[]) {
            t[e as usize].service_props.push(port_object());
        }
    }
    // The root port's nub, then (its secondary bus's dtBridge) three
    // address cells, two size cells and configured; published, its port
    // gives it its interrupt when it attaches to the host bridge
    // (0xfffffff006627154: "apcie-0", the provider's name and the port).
    let f = pci_facts();
    let port = add_pci_nub(t, bridge0, rc, apcie, "0", &f.root_port, &format!("0:0:0(1:{})", f.root_port_subordinate));
    let p = &mut t[port as usize];
    for (k, v) in [
        ("#address-cells", Prop::Data(3u32.to_le_bytes().to_vec())),
        ("#size-cells", Prop::Data(2u32.to_le_bytes().to_vec())),
        ("IOPCIConfigured", Prop::Bool(true)),
    ] {
        set(&mut p.service_props, k, v);
    }
    publish_nub(p, &f.root_port);
    for (k, v) in [("IOInterruptControllers", Prop::Array(vec![sym("apcie-0")])), ("IOInterruptSpecifiers", Prop::Array(vec![Prop::Data(vec![0; 8])])), ("IOPCIResourced", Prop::Bool(true))] {
        set(&mut p.service_props, k, v);
    }
    // The personality "ApplePCIEHostBridge", by bundle AppleT8011PCIe:
    // matched by the nub's compatible; its probe keeps the score
    // (0xfffffff00662af30); IOPCI2PCIBridge's start sets IOPCIPowerOnProbe.
    let mut props = driver("com.apple.driver.AppleT8011PCIe", HOST_BRIDGE, PCI_DEVICE, Some("apcie-bridge"), "IODefaultMatchCategory", 5000, vec![key("IONameMatch", string("apcie-bridge"))]);
    props.push(key("IOPCIPowerOnProbe", Prop::Bool(true)));
    let host = push(t, service("IOPP", HOST_BRIDGE, Some(port), props, Table::Complete));
    let nvme = add_pci_nub(t, s3e, host, port, "0", &f.nvme, "1:0:0");
    let n = &mut t[nvme as usize];
    publish_nub(n, &f.nvme);
    set(&mut n.service_props, "IOPCIResourced", Prop::Bool(true));
    if let Table::Lacks(l) = &mut n.table {
        l.push(("IOInterruptControllers", "the MSI vectors the controller's driver allocates (ApplePCIEMSIController)"));
        l.push(("IOInterruptSpecifiers", "the MSI vectors the controller's driver allocates (ApplePCIEMSIController)"));
    }
    // The personality "AppleEmbeddedNVMeController" (IONVMeFamily), and
    // what its start sets of the controller's own: its panic action, its
    // NAND's status once its namespaces are up, and Identify Controller's
    // strings as symbols (0xfffffff006a85d58).
    let n = super::storage::nvme();
    let mut props = driver("com.apple.iokit.IONVMeFamily", CONTROLLER, PCI_DEVICE, None, "IODefaultMatchCategory", 0, vec![
        key("IOPCIClassMatch", string("0x01800200&0xffffff00")),
        key("IOUserClientClass", string("AppleNVMeUpdateUC")),
        key("IOPCIMatch", string("0x2002106b")),
        key("Physical Interconnect", string("PCI-Express")),
        key("Vendor Name", string("Apple")),
        key("IOUnitName", string("disk")),
        key("Chipset Name", string("SSD Controller")),
        key("Physical Interconnect Location", string("Internal")),
        key("IOPCIUseDeviceMapper", Prop::Bool(true)),
    ]);
    props.push(key("Serial Number", sym(n.serial)));
    props.push(key("Model Number", sym(n.model)));
    props.push(key("Firmware Revision", sym(n.firmware)));
    props.push(key("IOPlatformPanicAction", num32(0)));
    props.push(key("AppleNANDStatus", sym("Ready")));
    let lacks = vec![
        ("IOProbeScore", "the PCI match's score, not followed"),
        ("IOCommandPoolSize", "CAP.MQES, the controller's"),
        ("NVMe Revision Supported", "the VS register, the controller's"),
        ("Controller Characteristics", "the NAND's vendor commands' answers"),
        ("IOPolledInterface", "the polled adapter object"),
        ("IOReportLegend", "the controller's reporters"),
        ("chip-id", "the NAND's"),
        ("IOMinimumSaturationByteCount", "not followed"),
        ("IOMaximumSwapWrite", "not followed"),
        ("VCParams", "not followed"),
    ];
    // Its score is the PCI match's, not followed: not the personality's.
    props.retain(|(k, _)| k != "IOProbeScore");
    Some(push(t, service(CONTROLLER, CONTROLLER, Some(nvme), props, Table::Lacks(lacks))))
}

/// A root port's entry's port object (`_buildPortProperties`), which
/// serializes as its class's note (`OSObject::serialize`).
fn port_object() -> (String, Prop) {
    key("AppleEmbeddedPCIEPort", string("AppleT8011PCIePort is not serializable"))
}

/// `setProperty`: a key's value replaced where it is, else the pair
/// appended.
fn set(props: &mut Vec<(String, Prop)>, k: &str, v: Prop) {
    match props.iter_mut().find(|(o, _)| o == k) {
        Some(slot) => slot.1 = v,
        None => props.push(key(k, v)),
    }
}

/// What IOPCIFamily reads of a PCI function's configuration space and
/// publishes (`constructProperties`, `checkProperties`): its IDs and
/// revision, the dword at 0x2c (a function's subsystem IDs; a bridge's
/// prefetchable base's upper half), and its PCI Express capability's
/// capabilities, link capabilities and link status registers. The class
/// code is not here: each function's is known ([`ROOT_PORT_CLASS`],
/// [`NVME_CLASS`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciFunction {
    pub vendor: u16,
    pub device: u16,
    pub revision: u8,
    pub dword_2c: u32,
    pub express_caps: u16,
    pub link_caps: u32,
    pub link_status: u16,
}

/// The configuration space of the root port and of the NAND's controller,
/// and the subordinate bus number IOPCIFamily gave the root port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciFacts {
    pub root_port: PciFunction,
    pub nvme: PciFunction,
    pub root_port_subordinate: u8,
}

/// The device's, once measured (with the measurement cited).
pub const PCI_DEVICE_FACTS: Option<PciFacts> = None;

/// What measures [`PCI_DEVICE_FACTS`].
pub const PCI_MEASUREMENT: &str = "the vendor-id, device-id, revision-id, subsystem-vendor-id, subsystem-id, pcidebug, IOPCIExpressCapabilities, IOPCIExpressLinkCapabilities and IOPCIExpressLinkStatus of the IOPCIDevice entries pci-bridge0 and s3e (a sysdiagnose's ioreg IOService plane)";

/// A root port's class code: a PCI-to-PCI bridge (base class 06h,
/// subclass 04h, interface 00h), which the PCI Express Base Specification
/// requires of every Root Port's Type 1 header.
pub const ROOT_PORT_CLASS: u32 = 0x06_04_00;

/// The NAND controller's class code: the one its driver's personality
/// matched (`IOPCIClassMatch` "0x01800200&0xffffff00", the class register
/// under the mask: base class 01h, subclass 80h, interface 02h).
pub const NVME_CLASS: u32 = 0x01_80_02;

/// What stands in for [`PCI_DEVICE_FACTS`] while it is unset. The
/// controller's IDs are the ones its driver's `IOPCIMatch` names
/// (0x2002106b: vendor 0x106b, device 0x2002), which it may instead match
/// on the subsystem IDs; it has none here. The root port's IDs and
/// revision, and both revisions, are zero. Both PCI Express capabilities
/// are version 2 (as every device of the 2.0 specification on has), the
/// root port's of type 4 (Root Port) with no slot, the controller's of
/// type 0 (Endpoint); both links up at 8 GT/s (the root port's device tree
/// `maximum-link-speed`, 3) and one lane wide. The root port's prefetchable
/// window is below 4 GiB, and its subordinate bus its secondary. A
/// reported shortcut (`unmeasured`), not the device's.
pub const STAND_IN_PCI: PciFacts = PciFacts {
    root_port: PciFunction { vendor: 0, device: 0, revision: 0, dword_2c: 0, express_caps: 0x0042, link_caps: 0x13, link_status: 0x13 },
    nvme: PciFunction { vendor: 0x106b, device: 0x2002, revision: 0, dword_2c: 0, express_caps: 0x0002, link_caps: 0x13, link_status: 0x13 },
    root_port_subordinate: 1,
};

/// The PCI facts in force: the device's, or the stand-in.
pub fn pci_facts() -> PciFacts {
    PCI_DEVICE_FACTS.unwrap_or(STAND_IN_PCI)
}

/// The facts here still unset, as lines for gexc's report at start.
pub fn unmeasured() -> Vec<String> {
    let mut gaps = Vec::new();
    if PCI_DEVICE_FACTS.is_none() {
        gaps.push(format!("the PCIe functions' configuration space (stand-in: the NAND controller 106b:2002, the root port 0:0, revisions 0, no subsystem IDs, PCIe capability version 2, links at 8 GT/s x1, root port subordinate bus 1; measure {PCI_MEASUREMENT})"));
    }
    gaps
}

/// The `IOPCIDevice` a bridge publishes for device tree entry `entry`
/// (`bridgeConstructDeviceTree`, 0xfffffff0064d9540): initialized with a
/// copy of the entry's table, attached below `dt_parent` in the
/// `IODeviceTree` plane and named after the entry; it keeps the entry as
/// IOPCIDeviceDeviceTreeEntry (an IOService, which serializes as its
/// class's note), then takes each key of `constructProperties` it lacks
/// (and pcidebug, reg, assigned-addresses and ranges always): pcidebug
/// (`"%u:%u:%u"` of its bus, device and function, and a bridge's
/// `"(%u:%u)"` secondary and subordinate buses), reg, assigned-addresses,
/// ranges, its IDs, revision and class code as 32-bit data, its subsystem
/// IDs if the dword at 0x2c is nonzero, compatible (the subsystem's
/// `"pci%x,%x"` if they differ from the IDs, the IDs', `"pciclass,%06x"`
/// and the entry's name), IOName (the class's generic name, else the IDs'
/// compatible name) and name, and IOPCIExpressLinkCapabilities. Its
/// location in the service plane is `"%X"` of its device number
/// (`publishNub`).
fn add_pci_nub(t: &mut Vec<Node>, entry: u32, bridge: u32, dt_parent: u32, location: &str, f: &PciFunction, pcidebug: &str) -> u32 {
    let e = &t[entry as usize];
    let class = if e.name == "s3e" { NVME_CLASS } else { ROOT_PORT_CLASS };
    let mut n = service(&e.name, PCI_DEVICE, Some(bridge), Vec::new(), Table::Lacks(vec![
        ("reg", "the functions' BAR sizes, the device's"),
        ("assigned-addresses", "the BARs' addresses, the bridge's allocation over the device's sizes"),
        ("ranges", "the bridge windows, the configurator's allocation over the device's sizes"),
        ("IODeviceMemory", "the BARs' ranges, from the allocation"),
        ("IOMapperID", "what the DART mapper and the platform's IOPCIDeviceChanged handler set, not followed"),
    ]));
    n.props = e.props.clone();
    // The entry's own table: what was set on it before (a root port's
    // port object), after its device tree properties.
    n.service_props = e.service_props.clone();
    n.dt = Some(DtLink { parent: dt_parent, name: e.name.clone(), location: location.to_string() });
    let data32 = |v: u32| Prop::Data(v.to_le_bytes().to_vec());
    let has = |k: &str| e.props.iter().any(|(pk, _)| pk == k && pk != super::iokit::DT_UNIT_KEY) || e.service_props.iter().any(|(pk, _)| pk == k);
    let mut add: Vec<(String, Prop)> = vec![key("pcidebug", Prop::Str(pcidebug.to_string()))];
    add.push(key("vendor-id", data32(u32::from(f.vendor))));
    add.push(key("device-id", data32(u32::from(f.device))));
    add.push(key("revision-id", data32(u32::from(f.revision))));
    add.push(key("class-code", data32(class)));
    let (sv, sp) = (f.dword_2c & 0xffff, f.dword_2c >> 16);
    if f.dword_2c != 0 {
        add.push(key("subsystem-vendor-id", data32(sv)));
        add.push(key("subsystem-id", data32(sp)));
    }
    // snprintf into sizeof("pcivvvv,pppp") and sizeof("pciclass,cccccc").
    let clip = |s: String, n: usize| s.chars().take(n - 1).collect::<String>();
    let mut compat: Vec<String> = Vec::new();
    if (sv != 0 || sp != 0) && (sv != u32::from(f.vendor) || sp != u32::from(f.device)) {
        compat.push(clip(format!("pci{sv:x},{sp:x}"), 13));
    }
    let ids = clip(format!("pci{:x},{:x}", f.vendor, f.device), 13);
    compat.push(ids.clone());
    compat.push(clip(format!("pciclass,{class:06x}"), 16));
    compat.push(e.name.chars().take(30).collect());
    let generic = [("display", 0xff_ffff, 0x00_0100), ("scsi", 0xff_ff00, 0x01_0000), ("ethernet", 0xff_ff00, 0x02_0000), ("display", 0xff_0000, 0x03_0000), ("pci-bridge", 0xff_ff00, 0x06_0400)].iter().find(|g| class & g.1 == g.2).map(|g| g.0.to_string());
    let name = generic.unwrap_or(ids);
    let mut cb = Vec::new();
    for c in &compat {
        cb.extend_from_slice(c.as_bytes());
        cb.push(0);
    }
    add.push(key("compatible", Prop::Data(cb)));
    add.push(key("IOName", Prop::Sym(name.clone())));
    add.push(key("name", Prop::Data([name.as_bytes(), b"\0"].concat())));
    add.push(key("IOPCIExpressLinkCapabilities", Prop::Num(u64::from(f.link_caps), 32)));
    n.service_props.push(key("IOPCIDeviceDeviceTreeEntry", string("IOService is not serializable")));
    for (k, v) in add {
        if k == "pcidebug" || !has(&k) {
            n.service_props.push((k, v));
        }
    }
    push(t, n)
}

/// What `publishNub` and `checkProperties` add to a PCI nub: its DriverKit
/// entitlements (a function's transport, and a bridge's too), then its PCI
/// Express capabilities, link status and link capabilities as 32-bit
/// numbers (the last replacing `constructProperties`'), and a slot's
/// status and capabilities when it has one (none here).
fn publish_nub(n: &mut Node, f: &PciFunction) {
    let mut ents = vec!["com.apple.developer.driverkit.transport.pci".to_string()];
    if n.service_props.iter().any(|(k, v)| k == "class-code" && *v == Prop::Data(ROOT_PORT_CLASS.to_le_bytes().to_vec())) {
        ents.push("com.apple.developer.driverkit.transport.pci.bridge".to_string());
    }
    set(&mut n.service_props, "IOServiceDEXTEntitlements", Prop::Array(vec![Prop::Strs(ents)]));
    set(&mut n.service_props, "IOPCIExpressCapabilities", Prop::Num(u64::from(f.express_caps), 32));
    set(&mut n.service_props, "IOPCIExpressLinkStatus", Prop::Num(u64::from(f.link_status), 32));
    set(&mut n.service_props, "IOPCIExpressLinkCapabilities", Prop::Num(u64::from(f.link_caps), 32));
}

/// The storage below the controller (its entry, if the PCIe path is
/// here): NSID 1's block device, its driver, disk0, the GPT, the
/// container's partition, APFS's scheme, medium and container, the
/// volumes, and each medium's BSD client.
fn add_storage(t: &mut Vec<Node>, controller: Option<u32>) {
    let n = super::storage::nvme();
    let block = u64::from(n.block_size);
    let writable = super::storage::disk_writable();
    // NSID 1's block device (IOEmbeddedNVMeBlockDevice, made by the
    // controller, not matched): IOBlockStorageDevice::init's device type,
    // the namespace's unit, Identify Namespace's EUI64 and NSID
    // (0xfffffff006a954d8), its reporters' legend, then the namespace's
    // properties (0xfffffff006a70014 and 0xfffffff006a97a20): the transfer
    // limits, its encryption and root type, its storage features
    // (Unmap from ONCS Dataset Management, gNVMeDebug's bit 0x200 being
    // clear and no vendor quirk; Priority, the controller's slot 0x5b0
    // answering 1; Barrier, flags bit 4, always set here, on NSID 1), its
    // throttling, the block sizes, its characteristics (the controller's
    // strings; the vendor name empty) and protocol characteristics (found
    // up the plane, the controller personality's), and on NSID 1 the SMART
    // plug-in.
    let ns_props = vec![
        key("device-type", sym("Generic")),
        key("IOUnit", num32(1)),
        key("NamespaceUUID", num64(n.eui64)),
        key("NamespaceID", num32(1)),
        key("IOReportLegendPublic", Prop::Bool(true)),
        key("IOMaximumSegmentCountRead", num32(256)),
        key("IOMaximumSegmentCountWrite", num32(256)),
        key("IOMaximumSegmentByteCountRead", num32(0x10_0000)),
        key("IOMaximumSegmentByteCountWrite", num32(0x10_0000)),
        key("IOMinimumSegmentAlignmentByteCount", num32(4096)),
        key("IOMaximumByteCountRead", num32(0x10_0000)),
        key("IOMaximumByteCountWrite", num32(0x10_0000)),
        key("IOMaximumBlockCountRead", num32(256)),
        key("IOMaximumBlockCountWrite", num32(256)),
        key("Encryption", Prop::Bool(true)),
        key("EmbeddedDeviceTypeRoot", Prop::Bool(true)),
        key("IOStorageFeatures", storage_features()),
        key("ThermalThrottlingSupported", Prop::Bool(true)),
        key("Physical Block Size", num32(block)),
        key("Logical Block Size", num32(block)),
        key("Device Characteristics", Prop::Dict(vec![
            key("Vendor Name", string("")),
            key("Product Name", string(n.model)),
            key("Product Revision Level", string(n.firmware)),
            key("Medium Type", string("Solid State")),
            key("Serial Number", string(n.serial)),
        ])),
        key("Protocol Characteristics", Prop::Dict(vec![key("Physical Interconnect", string("PCI-Express")), key("Physical Interconnect Location", string("Internal"))])),
        key("IOCFPlugInTypes", Prop::Dict(vec![key("AA0FA6F9-C2D6-457F-B10B-59A13253292F", string("NVMeSMARTLib.plugin"))])),
        key("NVMe SMART Capable", Prop::Bool(true)),
    ];
    let ns = push(t, service("NS_01", BLOCK_DEVICE, controller, ns_props, Table::Lacks(vec![("IOReportLegend", "its reporters' legend, whose encoding is IOReporter's")])));
    // IOBlockStorageDriver's personality; its init's statistics.
    let props = driver("com.apple.iokit.IOStorageFamily", DRIVER, "IOBlockStorageDevice", None, "IODefaultMatchCategory", 0, vec![key("IOPropertyMatch", Prop::Dict(vec![key("device-type", string("Generic"))]))]);
    let drv = push(t, service(DRIVER, DRIVER, Some(ns), props, Table::Lacks(vec![("Statistics", "the driver's counters, which each read and write of the disk moves")])));
    // disk0: its content the GPT scheme's Content Mask, no leaf; its icon
    // the internal one (the namespace's Physical Interconnect Location).
    let mut props = medium("GUID_partition_scheme", "", false, block, super::storage::disk0_bytes(), true, writable);
    props.push(key("IOMediaIcon", Prop::Dict(vec![key("CFBundleIdentifier", string("com.apple.iokit.IOStorageFamily")), key("IOBundleResourceFile", string("Internal.icns"))])));
    props.extend(bsd_keys(Media::Whole));
    let mut whole = service(&format!("{} Media", n.model), "IOMedia", Some(drv), props, Table::Complete);
    let dt_parent = controller.and_then(|c| t[c as usize].parent);
    whole.dt = dt_parent.map(|p| DtLink { parent: p, name: "disk".to_string(), location: "1:0".to_string() });
    let whole = push(t, whole);
    // The GPT scheme: its personality, and the disk's GUID it publishes.
    let g = super::storage::gpt();
    let mut props = driver("com.apple.iokit.IOStorageFamily", GPT, "IOMedia", None, "IOStorage", 4000, vec![key("IOPropertyMatch", Prop::Dict(vec![key("Whole", Prop::Bool(true))])), key("Content Mask", string("GUID_partition_scheme"))]);
    props.push(key("UUID", sym(&uuid_string(&g.disk_guid))));
    let gpt = push(t, service(GPT, GPT, Some(whole), props, Table::Complete));
    // The partition (IOGUIDPartitionScheme::instantiateMediaObject,
    // 0xfffffff005975a90): the disk's block size, attributes and
    // writability, its type for hint; Base, Partition ID, UUID and GPT
    // Attributes; then the APFS scheme's TierType (0xfffffff006682d0c).
    let (base, size) = super::storage::partition_extent();
    let mut props = medium(CONTAINER_PARTITION_HINT, CONTAINER_PARTITION_HINT, false, block, size, false, writable);
    props.push(key("Base", num64(base)));
    props.push(key("Partition ID", num32(1)));
    props.push(key("UUID", sym(&uuid_string(&g.partition_guid))));
    props.push(key("GPT Attributes", num64(g.attributes)));
    props.push(key("TierType", sym("Main")));
    props.extend(bsd_keys(Media::Partition));
    let mut part = service(PARTITION_NAME, "IOMedia", Some(gpt), props, Table::Complete);
    part.dt = dt_parent.map(|p| DtLink { parent: p, name: "disk".to_string(), location: "1:1".to_string() });
    let part = push(t, part);
    // AppleAPFSContainerScheme: its personality, its init's statistics
    // and APFSComposited (the container's nx_fusion_uuid null,
    // 0xfffffff0066824d4).
    let mut props = driver("com.apple.filesystems.apfs", APFS_SCHEME, "IOMedia", None, "IOStorage", 2000, vec![key("IOPropertyMatch", Prop::Array(vec![Prop::Dict(vec![key("Content Hint", string(CONTAINER_PARTITION_HINT))])]))]);
    props.push(key("APFSComposited", Prop::Bool(false)));
    let scheme = push(t, service(APFS_SCHEME, APFS_SCHEME, Some(part), props, Table::Lacks(vec![("Statistics", "the scheme's counters, which each read and write of the container moves")])));
    // AppleAPFSMedia (the scheme's start, 0xfffffff0066829d4): its init's
    // dictionary first (AppleAPFSMedia::init, 0xfffffff006682168): the
    // block sizes, min(nx_block_size, 4096), one number under both keys,
    // which is 4096 since nx_block_size is at least NX_MINIMUM_BLOCK_SIZE;
    // the nearest IOStorageFeatures up the plane, the namespace's; the
    // partition's preferred block size as EncryptionBlockSize. Then
    // IOMedia::init's (the partition's size; the container's hint; whole;
    // the partition's writability), and the container's UUID.
    let apfs_block = APFS_BLOCK;
    let mut props = vec![
        key("Physical Block Size", num32(apfs_block)),
        key("Logical Block Size", Prop::SameAs("Physical Block Size".to_string())),
        key("IOStorageFeatures", storage_features()),
        key("EncryptionBlockSize", num32(block)),
    ];
    props.extend(medium(APFS_CONTAINER_HINT, APFS_CONTAINER_HINT, false, apfs_block, size, true, writable));
    props.push(key("UUID", sym(&uuid_string(&super::storage::container_uuid()))));
    props.extend(bsd_keys(Media::Container));
    let media = push(t, service(APFS_MEDIA, APFS_MEDIA, Some(scheme), props, Table::Complete));
    // AppleAPFSContainer: its personality; what its start sets (its
    // statistics, Status) is run-time state.
    let props = driver("com.apple.filesystems.apfs", APFS_CONTAINER, "IOMedia", None, "IOStorage", 1000, vec![
        key("IOPropertyMatch", Prop::Array(vec![Prop::Dict(vec![key("Content Hint", string(APFS_CONTAINER_HINT))])])),
        key("IOUserClientClass", string("AppleAPFSUserClient")),
    ]);
    let container = push(t, service(APFS_CONTAINER, APFS_CONTAINER, Some(media), props, Table::Lacks(vec![("Statistics", "the container's counters"), ("Status", "the container's state")])));
    for v in super::storage::VOLUMES {
        let mut props = medium(APFS_VOLUME_HINT, APFS_VOLUME_HINT, true, apfs_block, 0, false, super::storage::volume_writable());
        props.retain(|(k, _)| k != "Preferred Block Size" && k != "Size");
        props.extend(bsd_keys(Media::Volume(v.index)));
        props.push(key("FullName", sym(v.name)));
        props.push(key("RoleValue", num32(u64::from(v.role))));
        if let Some(r) = super::iokit::apfs_role_name(v.role) {
            props.push(key("Role", Prop::Strs(vec![r.to_string()])));
        }
        // AppleAPFSVolume::init (0xfffffff00666d49c) starts from a copy of
        // a dictionary the container keeps (+0x420), not followed.
        let partial = "the dictionary AppleAPFSVolume::init starts from (the container's at +0x420), the volume's Preferred Block Size and Size, UUID, CaseSensitive, FormattedBy, IncompatibleFeatures, VolGroupUUID, the encryption keys, autodiskmount, Sealed, Status and Statistics (from the volume superblock and its state)";
        let vol = push(t, service(v.name, APFS_VOLUME, Some(container), props, Table::Partial(partial.to_string())));
        add_bsd_client(t, vol, APFS_VOLUME_BSD);
    }
    add_bsd_client(t, media, APFS_MEDIA_BSD);
    add_bsd_client(t, part, BSD_CLIENT);
    add_bsd_client(t, whole, BSD_CLIENT);
}

/// The namespace's IOStorageFeatures, a dictionary of three booleans in
/// this order (0xfffffff006a97a20).
fn storage_features() -> Prop {
    let n = super::storage::nvme();
    Prop::Dict(vec![key("Unmap", Prop::Bool(n.dataset_management)), key("Priority", Prop::Bool(true)), key("Barrier", Prop::Bool(true))])
}

/// A medium's BSD client of `class`: its personality's properties; neither
/// IOMediaBSDClient nor APFS's subclasses override its probe or start to
/// set any of its own.
fn add_bsd_client(t: &mut Vec<Node>, medium: u32, class: &'static str) {
    let (bundle, provider, score) = match class {
        APFS_MEDIA_BSD => ("com.apple.filesystems.apfs", APFS_MEDIA, 31000),
        APFS_VOLUME_BSD => ("com.apple.filesystems.apfs", APFS_VOLUME, 31000),
        _ => ("com.apple.iokit.IOStorageFamily", "IOMedia", 30000),
    };
    let props = driver(bundle, class, provider, None, "IOMediaBSDClient", score, vec![key("IOResourceMatch", string("IOBSD"))]);
    push(t, service(class, class, Some(medium), props, Table::Complete));
}

/// Whether a service of `class` here registers itself (`registerService`,
/// which makes it an instance its metaclass tracks): the PCI bridges
/// (`IOPCIBridge::start`), the nubs they publish (`publishNub`), the
/// controller (0xfffffff006a81f50) and its namespaces (0xfffffff006a958d8),
/// IOBlockStorageDriver and IOMediaBSDClient (their starts), every medium
/// (by its driver or scheme), and AppleAPFSContainer (its start,
/// 0xfffffff00666b24c, after its volumes). The partition schemes do not:
/// IOGUIDPartitionScheme's start registers only its partitions, and
/// AppleAPFSContainerScheme's (0xfffffff0066829d4) only its medium.
/// None for a class not here.
pub fn registers(class: &str) -> Option<bool> {
    match class {
        GPT | APFS_SCHEME => Some(false),
        T8011_PCIE | PCI_DEVICE | HOST_BRIDGE | CONTROLLER | BLOCK_DEVICE | DRIVER | "IOMedia" | BSD_CLIENT | APFS_MEDIA | APFS_CONTAINER | APFS_VOLUME | APFS_MEDIA_BSD | APFS_VOLUME_BSD => Some(true),
        _ => None,
    }
}

/// A property a class here answers from its `getProperty` override rather
/// than its table, when that answer is not modelled: a namespace's
/// WriteCacheState (IOBlockStorageDevice's override, 0xfffffff00596ee88,
/// asks `getWriteCacheState`, slot 0x5b0, whose IONVMeBlockStorageDevice
/// answer rests on flags at +0xb0 not traced).
pub fn property_override(t: &[Node], i: u32, name: &str) -> Option<String> {
    let n = t.get(i as usize)?;
    if name == "WriteCacheState" && superclasses(n.class).contains(&"IOBlockStorageDevice") {
        return Some(format!("{}'s WriteCacheState (getWriteCacheState, from flags not traced)", n.name));
    }
    None
}

/// The configuration register at `reg` (a dword's offset) of the PCI nub
/// `i`, as IOPCIFamily saved it (`savedConfig`) and `checkProperties`
/// rewrote it from the nub's properties: the IDs, the class code and
/// revision, and the subsystem IDs when both are nonzero (else the dword
/// read at 0x2c).
pub fn pci_config(t: &[Node], i: u32, reg: u8) -> Result<u32, String> {
    let n = &t[i as usize];
    let f = pci_facts();
    let func = match n.name.as_str() {
        "s3e" => f.nvme,
        "pci-bridge0" => f.root_port,
        _ => return Err(format!("the configuration space of {}", n.name)),
    };
    let word = |k: &str| match super::iokit::service_prop(n, k) {
        Some(Prop::Data(d)) if d.len() >= 4 => u32::from_le_bytes(d[..4].try_into().unwrap()),
        _ => 0,
    };
    Ok(match reg {
        0x00 => word("device-id") << 16 | word("vendor-id"),
        0x08 => word("class-code") << 8 | word("revision-id"),
        0x2c => {
            let (sv, sp) = (word("subsystem-vendor-id"), word("subsystem-id"));
            if sv != 0 && sp != 0 { sp << 16 | sv } else { func.dword_2c }
        }
        _ => return Err(format!("the configuration register {reg:#04x} of {}", n.name)),
    })
}

/// `IORegistryEntry::getLocation`: what the drivers gave their objects
/// (`setLocation`): a PCI nub's device number, a namespace's NSID
/// (`"%x"`), the GPT partition's number (`"%d"`), a volume's slot plus
/// one (`AppleAPFSVolume::init`'s `"%d"`, 0xfffffff00666d684).
pub fn location(n: &Node) -> Option<String> {
    match n.class {
        APFS_VOLUME => super::storage::VOLUMES.iter().find(|v| v.name == n.name).map(|v| (v.index + 1).to_string()),
        "IOMedia" if n.name == PARTITION_NAME => Some("1".to_string()),
        BLOCK_DEVICE => Some("1".to_string()),
        PCI_DEVICE => n.dt.as_ref().map(|d| d.location.clone()),
        _ => None,
    }
}

/// The medium a storage entry is, by its BSD name.
fn media_of(n: &Node) -> Option<Media> {
    let name = n.service_props.iter().find_map(|(k, v)| match (k.as_str(), v) {
        ("BSD Name", Prop::Sym(s)) => Some(s.as_str()),
        _ => None,
    })?;
    super::storage::media_by_name(name).map(|(m, _)| m)
}

/// A medium's live "Open": `IOMedia::handleOpen` sets it once it holds its
/// provider open at some level and `handleClose` clears it once it holds
/// none ([`super::dkopen`]'s levels).
pub fn live_prop(t: &[Node], i: u32, name: &str) -> Option<Prop> {
    let n = t.get(i as usize)?;
    if name != "Open" || !superclasses(n.class).contains(&"IOMedia") {
        return None;
    }
    let m = media_of(n)?;
    let level = super::dkopen::media_opens(m)?.level;
    Some(Prop::Bool(level != super::dkopen::access::NONE))
}

