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
//!                     IOMediaBSDClient
//!                     IOGUIDPartitionScheme
//!                       Container@1           IOMedia, disk0s1
//!                         IOMediaBSDClient
//!                         AppleAPFSContainerScheme
//!                           AppleAPFSMedia    disk1
//!                             AppleAPFSMediaBSDClient
//!                             AppleAPFSContainer
//!                               <volume>@<slot+1>   AppleAPFSVolume
//!                                 AppleAPFSVolumeBSDClient
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
//!   0xfffffff006a98c20). Before it makes the namespaces it attaches
//!   itself below its nub in the `IODeviceTree` plane (0xfffffff006a81ec0).
//! - `IOBlockStorageDevice::init` (0xfffffff00596ee30) gives the namespace
//!   "device-type" "Generic", which `IOBlockStorageDriver`'s personality
//!   matches; the driver's media is the whole disk, named "<vendor>
//!   <product> Media" (`acceptNewMedia`; the vendor string is empty,
//!   0xfffffff006a96df4) and attached in the `IODeviceTree` plane to the
//!   nearest provider there, the controller, as "disk" at "<IOUnit>:0"
//!   (`IOUnitName` the controller personality's).
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
//!   BSD keys ([`super::storage::units`]). Its category is started before
//!   the storage drivers' (`probeCandidates` starts the categories in the
//!   order of their best probe score, 30000 and 31000 above the schemes'),
//!   and `startCandidate` attaches it before it stalls for IOBSD, which
//!   `IOKitBSDInit` publishes: it is the medium's first child. When it
//!   gets its nodes is the media order's stand-in
//!   ([`super::storage::media_order`]).
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
pub const TEMP_SENSOR: &str = "AppleEmbeddedNVMeTemperatureSensor";
pub const NVRAM: &str = "AppleEmbeddedNVMeNVRAM";
pub const DIAGNOSTICS: &str = "AppleEmbeddedNVMeDiagnostics";
pub const DIAG_DRIVER: &str = "AppleDiagnosticDataAccessReadOnly";
pub const EFFACEABLE: &str = "IONVMeEffaceableDevice";
pub const EFFACEABLE_DRIVER: &str = "AppleEffaceableBlockDevice";
pub const NAMESPACE_DEVICE: &str = "AppleNVMeNamespaceDevice";

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
        TEMP_SENSOR => &[TEMP_SENSOR, "AppleEmbeddedHIDEventService", "IOHIDEventService", "IOService", "IORegistryEntry"],
        NVRAM => &[NVRAM, "IONVRAMController", "IOService", "IORegistryEntry"],
        DIAGNOSTICS => &[DIAGNOSTICS, "AppleNANDConfigAccess", "IOService", "IORegistryEntry"],
        DIAG_DRIVER => &[DIAG_DRIVER, "IOService", "IORegistryEntry"],
        EFFACEABLE => &[EFFACEABLE, BLOCK_DEVICE, "IONVMeBlockStorageDevice", "IOBlockStorageDevice", "IOService", "IORegistryEntry"],
        EFFACEABLE_DRIVER => &[EFFACEABLE_DRIVER, "AppleEffaceableStorage", "IOService", "IORegistryEntry"],
        NAMESPACE_DEVICE => &[NAMESPACE_DEVICE, "IOService", "IORegistryEntry"],
        _ => &[],
    }
}

/// What is not modelled of a service's children in the `IOService` plane:
/// the root complex's other ports and its user clients; the controller's
/// other namespaces and objects (the module's documentation). The others
/// here have all theirs (user clients are not registry entries here).
pub fn children_unknown(class: &str) -> Option<&'static str> {
    match class {
        // pci-bridge2's port has manual-enable: AppleEmbeddedPCIE's port
        // bring-up leaves it down (0xfffffff00662337c) and config space
        // behind a port not up is not read (0xfffffff00661d6bc), so its nub
        // (and the wlan function below it) is published only once its
        // client, the WLAN driver, enables the port at run time.
        T8011_PCIE => Some("pci-bridge2's nub and the wlan function below it, which the bridge publishes once the WLAN driver enables that manual-enable port"),
        NAMESPACE_DEVICE => Some("the clients its family attaches, not followed"),
        _ => None,
    }
}

/// Whether every service of `class` is here: the storage stack's, whose
/// objects are one each but for the media, BSD clients and drivers the
/// controller's other namespaces add.
pub fn class_complete(class: &str) -> bool {
    matches!(
        class,
        APFS_SCHEME | APFS_MEDIA | APFS_CONTAINER | APFS_VOLUME | APFS_MEDIA_BSD | APFS_VOLUME_BSD | GPT | HOST_BRIDGE | T8011_PCIE | CONTROLLER | "AppleNVMeController" | "IONVMeController" | BLOCK_DEVICE | EFFACEABLE | "IONVMeBlockStorageDevice" | "IOBlockStorageDevice" | DRIVER | "IOMedia" | BSD_CLIENT | "IOPartitionScheme" | NAMESPACE_DEVICE | DIAGNOSTICS | TEMP_SENSOR | NVRAM | DIAG_DRIVER | EFFACEABLE_DRIVER
    )
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
        Media::Firmware => super::storage::units().firmware,
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
    Node { name: name.to_string(), props: Vec::new(), class, service_props, parent, children: Vec::new(), kernel_only: false, nub: None, dt: None, table, power: None }
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
    // (AppleEmbeddedPCIE's, 0xfffffff0066175b4) sets its reporters' legend
    // ([`pcie_legend`]), its user client class (0xfffffff0066183c8) and the
    // function parent key AppleARMPlatform's helper makes of apcie's
    // phandle (0xfffffff005988104), empty data; its `configure`
    // (0xfffffff006619f34) sets nothing.
    let mut props = driver("com.apple.driver.AppleT8011PCIe", T8011_PCIE, super::platform::ARM_IO_DEVICE, Some("apcie,t8011"), "IODefaultMatchCategory", 0, vec![
        key("IONameMatch", string("apcie,t8011")),
        key("IOPlatformQuiesceAction", num64(4000)),
        key("IOPlatformActiveAction", num64(1500)),
    ]);
    props.push(key("IOReportLegend", pcie_legend(t, apcie)));
    props.push(key("IOReportLegendPublic", Prop::Bool(true)));
    props.push(key("IOUserClientClass", sym("AppleEmbeddedPCIEUserClient")));
    props.push(key(&super::platform::function_parent(t, apcie), Prop::Data(Vec::new())));
    // `IOPCIBridge::start`'s PMinit, after `configure`.
    props.push(key(super::iopower::KEY, super::iopower::pci_bridge()));
    let rc = push(t, service(T8011_PCIE, T8011_PCIE, Some(apcie), props, Table::Complete));
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
    // `IOPCIDevice::attach`'s PMinit comes after `attachToChild`.
    for (k, v) in [("IOInterruptControllers", Prop::Array(vec![sym("apcie-0")])), ("IOInterruptSpecifiers", Prop::Array(vec![Prop::Data(vec![0; 8])])), (super::iopower::KEY, super::iopower::pci_function()), ("IOPCIResourced", Prop::Bool(true))] {
        set(&mut p.service_props, k, v);
    }
    // The personality "ApplePCIEHostBridge", by bundle AppleT8011PCIe:
    // matched by the nub's compatible; its probe keeps the score
    // (0xfffffff00662af30); IOPCI2PCIBridge's start sets IOPCIPowerOnProbe.
    let mut props = driver("com.apple.driver.AppleT8011PCIe", HOST_BRIDGE, PCI_DEVICE, Some("apcie-bridge"), "IODefaultMatchCategory", 5000, vec![key("IONameMatch", string("apcie-bridge"))]);
    // `IOPCIBridge::start`'s PMinit, then IOPCI2PCIBridge's key.
    props.push(key(super::iopower::KEY, super::iopower::pci_bridge()));
    props.push(key("IOPCIPowerOnProbe", Prop::Bool(true)));
    let host = push(t, service("IOPP", HOST_BRIDGE, Some(port), props, Table::Complete));
    let nvme = add_pci_nub(t, s3e, host, port, "0", &f.nvme, "1:0:0");
    let n = &mut t[nvme as usize];
    publish_nub(n, &f.nvme);
    set(&mut n.service_props, super::iopower::KEY, super::iopower::pci_function());
    set(&mut n.service_props, "IOPCIResourced", Prop::Bool(true));
    if let Table::Lacks(l) = &mut n.table {
        l.push(("IOInterruptControllers", "the MSI vectors the controller's driver allocates (ApplePCIEMSIController): how many IONVMeFamily asks for, and the function's MSI capability, are not traced"));
        l.push(("IOInterruptSpecifiers", "the MSI vectors the controller's driver allocates (ApplePCIEMSIController): how many IONVMeFamily asks for, and the function's MSI capability, are not traced"));
        // `IOPCIBridge::getNubResources` (0xfffffff0064ca150) gives a nub
        // whose iommu-parent is a DART mapper its window, from the DART's
        // retrieveVMLimits (0xfffffff005f29334, not followed), and the
        // mapper's page size; pci-bridge0 has no iommu-parent.
        l.push(("IOPCIDeviceMemoryMapBase", "the DART's retrieveVMLimits, not followed"));
        l.push(("IOPCIDeviceMemoryMapSize", "the DART's retrieveVMLimits, not followed"));
        l.push(("IOPCIDeviceMapperPageSize", "the DART mapper's getPageSize, not followed"));
    }
    // The personality "AppleEmbeddedNVMeController" (IONVMeFamily). Its
    // score: the personality has none, and `pciMatchNub` adds 1000 for an
    // IOPCIMatch matched on the IDs or the subsystem's; neither class
    // overrides `probe`. Then what its start sets ([`controller_props`]).
    let mut props = driver("com.apple.iokit.IONVMeFamily", CONTROLLER, PCI_DEVICE, None, "IODefaultMatchCategory", 1000, vec![
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
    props.extend(controller_props(t, &f.nvme));
    // Its start attaches it below its nub in the `IODeviceTree` plane
    // (0xfffffff006a81ec0), with no name or location of that plane's.
    let mut c = service(CONTROLLER, CONTROLLER, Some(nvme), props, Table::Complete);
    c.dt = Some(DtLink { parent: nvme, name: CONTROLLER.to_string(), location: None });
    Some(push(t, c))
}

/// What the controller's start (IONVMeController::start,
/// 0xfffffff006a81d90) sets on itself, in its order:
/// - `IOControllerInit` (0xfffffff006a8316c): IOCommandPoolSize, the
///   request pool's size, min(CAP.MQES + 1, 65) less one (the embedded
///   controller's queue limit, slot 0x680, is 0x40: 0xfffffff006a64180);
///   "NVMe Revision Supported", `"%u.%u%u"` of the VS register's major,
///   minor and tertiary bytes (a symbol); IOPlatformPanicAction 0. Its
///   "Physical Interconnect Location" needs the embedded flag clear, which
///   the embedded InitializeController sets first (0xfffffff006a5b4dc), and
///   no entry up the plane has "ssd-off-in-S4".
/// - `AllocateResources`, through the embedded slot 0x850
///   (0xfffffff006a5dd18): a new reporters' legend of one
///   `IOStateReporter` (kIOReportCategoryPower, 2 states, unit
///   0x0101000000000000): channel 'NVMe Pwr' "NVMe Power States", states
///   'OFF' and 'ACTIVE', in group "NVMe" with no subgroup.
/// - Identify Controller's handler (0xfffffff006a85d58): IOPolledInterface
///   when the request pool holds at least two (an
///   `IONVMeControllerPolledAdapter`, which serializes as its class's note);
///   the transfer limits (0xfffffff006a872e8 on) from MDTS's exponent `m`
///   (MDTS if it is 1 to 7, else 8): segments of 4096 bytes (64-bit
///   numbers), `1 << m` of them, `4096 << m` bytes, aligned to 4096;
///   IOMinimumSaturationByteCount 0x800000 only on a link at 8 GT/s x4
///   (slot 0x7c0, 0xfffffff006a88258: s3e's IOPCIExpressLinkStatus & 0x3ff
///   is 0x43); Controller Characteristics ([`controller_characteristics`],
///   replaced twice later in its place); the Identify strings as symbols,
///   trailing spaces cut (0xfffffff006a85e40 on).
/// - PMinit, which adds IOPowerManagement (0xfffffff006a8754c;
///   [`super::iopower::nvme_controller`]).
/// - `IdentifyNamespaces` (0xfffffff006a5b84c): IOMaximumSwapWrite
///   ([`swap_write_limit`]).
/// - `StartController` (0xfffffff006a5e25c): once the namespaces are made,
///   AppleNANDStatus "Ready".
/// "NVMe Debug Data" and "nand-fragmentation" are set only by
/// `setProperties` from a privileged task (0xfffffff006a83570,
/// 0xfffffff006a9139c); chip-id and chip-revision are read from the device
/// tree (0xfffffff006a89534), not set; VCParams and QueueSize are
/// AppleANS3CGv2Controller's. None is here at boot.
fn controller_props(t: &[Node], link: &PciFunction) -> Vec<(String, Prop)> {
    let n = super::storage::nvme();
    let c = controller_facts();
    let pool = u64::from(c.mqes).min(64);
    let m = mdts_exponent(c.mdts);
    let mut p = vec![
        key("IOCommandPoolSize", num32(pool)),
        key("NVMe Revision Supported", sym(&format!("{}.{}{}", c.vs >> 16 & 0xff, c.vs >> 8 & 0xff, c.vs & 0xff))),
        key("IOPlatformPanicAction", num32(0)),
        key("IOReportLegend", Prop::Array(vec![legend_entry(&[(0x4e56_4d65_2050_7772, "NVMe Power States")], channel_type(2, 1 << 1, 2), 0x0101_0000_0000_0000, "NVMe", None)])),
        key("IOReportLegendPublic", Prop::Bool(true)),
    ];
    if pool >= 2 {
        p.push(key("IOPolledInterface", string("IONVMeControllerPolledAdapter is not serializable")));
    }
    p.extend([
        key("IOMaximumSegmentByteCountRead", num64(4096)),
        key("IOMaximumSegmentByteCountWrite", num64(4096)),
        key("IOMaximumSegmentCountRead", num32(1 << m)),
        key("IOMaximumSegmentCountWrite", num32(1 << m)),
        key("IOMaximumByteCountRead", num32(4096 << m)),
        key("IOMaximumByteCountWrite", num32(4096 << m)),
        key("IOMinimumSegmentAlignmentByteCount", num32(4096)),
    ]);
    if link.link_status & 0x3ff == 0x43 {
        p.push(key("IOMinimumSaturationByteCount", num32(0x80_0000)));
    }
    p.push(key("Controller Characteristics", controller_characteristics(&c, m)));
    p.push(key("Serial Number", sym(n.serial)));
    p.push(key("Model Number", sym(n.model)));
    p.push(key("Firmware Revision", sym(n.firmware)));
    p.push(key(super::iopower::KEY, super::iopower::nvme_controller()));
    if let Some(limit) = swap_write_limit(t, c.capacity_gb) {
        p.push(key("IOMaximumSwapWrite", num64(limit)));
    }
    p.push(key("AppleNANDStatus", sym("Ready")));
    p
}

/// MDTS's exponent as Identify Controller's handler takes it
/// (0xfffffff006a85d9c): MDTS if it is 1 to 7, else (0, no limit, or more)
/// 8.
fn mdts_exponent(mdts: u8) -> u32 {
    if (1..=7).contains(&mdts) { u32::from(mdts) } else { 8 }
}

/// `SetSwapWriteLimit` (0xfffffff006a5f25c) of the NAND's capacity in GB,
/// by the device tree's /product artwork-device-idiom: a pad's or a
/// phone's 4 GiB above 256 GB, 3 GiB above 128, 2 GiB above 64, 1 GiB above
/// 16, else 0 (still set); a watch's 1 GiB from 16 GB, else none; none for
/// any other idiom, or with no /product.
fn swap_write_limit(t: &[Node], capacity_gb: u64) -> Option<u64> {
    let idiom = super::iokit::dt_prop(t, "IODeviceTree:/product", "artwork-device-idiom")?;
    let idiom = &idiom[..idiom.iter().position(|&b| b == 0).unwrap_or(idiom.len())];
    match idiom {
        b"pad" | b"phone" => Some(match capacity_gb {
            c if c > 256 => 0x1_0000_0000,
            c if c > 128 => 0xc000_0000,
            c if c > 64 => 0x8000_0000,
            c if c > 16 => 0x4000_0000,
            _ => 0,
        }),
        b"watch" => (capacity_gb >= 16).then_some(0x4000_0000),
        _ => None,
    }
}

/// The controller's Controller Characteristics, in the order it is built:
/// Preferred IO Size (`4096 << m`, 32 bits) and Encryption Type "AES-XTS"
/// (the embedded slot 0x770, 0xfffffff006a5d7bc), then what
/// `IdentifyNamespaces` appends to a copy of it (0xfffffff006a5b84c), from
/// Identify Controller's Apple area and two vendor commands: vendor-name
/// (bytes 0xe38, 16), nand-marketing-name (0xe18, 32), firmware-version
/// (the 8 bytes of FR), msp-version (0xc00, 16), chip-id (the name of byte
/// 0xc1c's chip, from the table at 0xfffffff006fa0688), controller-unique-id
/// (the 20 bytes of SN), each an OSString of the bytes up to a NUL;
/// nand-device-desc, the 64-bit number at 0xd00 if it is nonzero, else a
/// 32-bit number of the halfword at 0xc1e and the byte at 0xc20 above it;
/// manufacturer-id, 8 bytes of data, the first 6 the vendor command 0x38's
/// answer (0xfffffff006a5f6e4); capacity, the halfword at 0xe06 in GB times
/// 10^9 (64 bits); and the geometry the vendor command 0x37 answers
/// (0xfffffff006a630ec), each a 32-bit number of the answer's words. "Low
/// Power Mode" would come first if the controller's +0x268 were set, which
/// nothing in IONVMeFamily writes.
fn controller_characteristics(c: &ControllerFacts, m: u32) -> Prop {
    let n = super::storage::nvme();
    let field = |s: &str, len: usize| {
        let mut b: Vec<u8> = s.bytes().take(len).collect();
        b.resize(len, b' ');
        string(&String::from_utf8_lossy(&b))
    };
    let upto = |s: &str, len: usize| string(&s.chars().take(len).collect::<String>());
    let w = &c.geometry;
    let desc = if c.nand_device_desc_64 != 0 { num64(c.nand_device_desc_64) } else { num32(u64::from(c.nand_device_desc_16) | u64::from(c.nand_device_desc_8) << 16) };
    let mut id = c.manufacturer_id.to_vec();
    id.resize(8, 0);
    let mut d = vec![
        key("Preferred IO Size", num32(4096 << m)),
        key("Encryption Type", string("AES-XTS")),
        key("vendor-name", upto(c.vendor_name, 16)),
        key("nand-marketing-name", upto(c.nand_marketing_name, 32)),
        key("firmware-version", field(n.firmware, 8)),
        key("msp-version", upto(c.msp_version, 16)),
        key("chip-id", string(["S3E", "S1X", "S4E", "S5E"].get(c.chip).copied().unwrap_or(""))),
        key("controller-unique-id", field(n.serial, 20)),
        key("nand-device-desc", desc),
        key("manufacturer-id", Prop::Data(id)),
        key("capacity", num64(c.capacity_gb * 1_000_000_000)),
    ];
    let g = |i: usize| num32(u64::from(w[i]));
    d.extend([
        key("caus", num32(u64::from(w[1].wrapping_mul(w[3])))),
        key("blocks-per-cau", g(5)),
        key("page-size", num32(u64::from(w[6] << 12))),
        key("pages-per-block-mlc", g(10)),
        key("num-bus", g(2)),
        key("default-bits-per-cell", g(13)),
        key("dies-per-channel", g(3)),
        key("pages-per-block-slc", g(11)),
        key("pages-in-read-verify", g(14)),
        key("package_blocks_at_EOL", g(15)),
        key("block-pairing-scheme", g(16)),
        key("cau-per-die", g(1)),
        key("num-dip", g(4)),
        key("sec-per-page", g(6)),
        key("sec-per-full-band", g(7)),
        key("sec-per-full-band-slc", g(8)),
        key("bytes-per-sec-meta", g(9)),
        key("pages-per-block0", g(12)),
        key("cell-type", g(13)),
        key("ce-per-bus", g(0)),
        key("program-scheme", g(17)),
    ]);
    Prop::Dict(d)
}

/// What the NAND's controller answers that its driver publishes: CAP.MQES
/// (register 0x00, bits 15:0), the VS register (0x08), Identify
/// Controller's MDTS (byte 77) and its Apple area, and the answers to the
/// vendor commands 0x38 (the manufacturer's ID) and 0x37 (the geometry's
/// 18 words, from offset 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControllerFacts {
    pub mqes: u16,
    pub vs: u32,
    pub mdts: u8,
    pub vendor_name: &'static str,
    pub nand_marketing_name: &'static str,
    pub msp_version: &'static str,
    /// Byte 0xc1c, the chip's index.
    pub chip: usize,
    /// The 64-bit number at 0xd00, the halfword at 0xc1e and the byte at
    /// 0xc20.
    pub nand_device_desc_64: u64,
    pub nand_device_desc_16: u16,
    pub nand_device_desc_8: u8,
    pub manufacturer_id: [u8; 6],
    /// The halfword at 0xe06.
    pub capacity_gb: u64,
    pub geometry: [u32; 18],
}

/// The device's, once measured (with the measurement cited).
pub const CONTROLLER_DEVICE_FACTS: Option<ControllerFacts> = None;

/// What measures [`CONTROLLER_DEVICE_FACTS`].
pub const CONTROLLER_MEASUREMENT: &str = "the AppleEmbeddedNVMeController's IOCommandPoolSize, NVMe Revision Supported, IOMaximumSegmentCountRead and Controller Characteristics (a sysdiagnose's ioreg IOService plane)";

/// What stands in for [`CONTROLLER_DEVICE_FACTS`] while it is unset: a
/// queue at least as deep as the driver's limit (so a pool of 64), no
/// version (VS 0), no transfer limit (MDTS 0), strings that say what they
/// are, the first chip of the table (S3E, as the controller's device tree
/// entry is named), no device description, manufacturer ID or geometry
/// (zeros), and the capacity of disk0's stand-in size in GB. A reported
/// shortcut (`unmeasured`), not the device's.
pub fn stand_in_controller() -> ControllerFacts {
    ControllerFacts {
        mqes: 0xffff,
        vs: 0,
        mdts: 0,
        vendor_name: "(unmeasured)",
        nand_marketing_name: "(unmeasured)",
        msp_version: "(unmeasured)",
        chip: 0,
        nand_device_desc_64: 0,
        nand_device_desc_16: 0,
        nand_device_desc_8: 0,
        manufacturer_id: [0; 6],
        capacity_gb: super::storage::disk0_bytes() / 1_000_000_000,
        geometry: [0; 18],
    }
}

/// The controller facts in force: the device's, or the stand-in.
pub fn controller_facts() -> ControllerFacts {
    CONTROLLER_DEVICE_FACTS.unwrap_or_else(stand_in_controller)
}

/// The root complex's reporters' legend (`_createReporters`,
/// 0xfffffff0066187cc), for each of apcie's ports that has a port object
/// (its children with "apcie-port"), in port order:
/// - its link states, an `IOStateReporter` (kIOReportCategoryPower, 4
///   states, unit 0x0100007900000000): channel "LStPrt" and the port's
///   character, "PCIe Port <n> Link States";
/// - its energy, an `IOSimpleReporter` (kIOReportCategoryPower, unit
///   0x0300007900000000): "EngyPrt" and the character, "PCIe Port <n>
///   Energy";
/// - its events, an `IOSimpleReporter` (kIOReportCategoryDebug, unit 0):
///   "Ev", the event's two digits, "Prt" and the character, named by the
///   format table at 0xfffffff007b2c888 ([`PCIE_EVENTS`]).
/// The legend holds them as link states (group "AppleEmbeddedPCIE",
/// subgroup "Link States"), events (group "Link Events") and energy (group
/// "Energy Model").
fn pcie_legend(t: &[Node], apcie: u32) -> Prop {
    let mut ports: Vec<u32> = t[apcie as usize].children.iter().filter_map(|&c| t[c as usize].props.iter().find(|(k, _)| k == "apcie-port").and_then(|(_, v)| v.get(..4)).map(|v| u32::from_le_bytes(v.try_into().unwrap()))).collect();
    ports.sort_unstable();
    let ch = |i: u32| u64::from(if i < 10 { b'0' + i as u8 } else { b'a' + (i - 10) as u8 });
    let (mut states, mut energy, mut events) = (Vec::new(), Vec::new(), Vec::new());
    for &i in &ports {
        states.push((0x4c53_7450_7274 << 8 | ch(i), format!("PCIe Port {i} Link States")));
        energy.push((0x456e_6779_5072_74 << 8 | ch(i), format!("PCIe Port {i} Energy")));
        for (j, &(title, width)) in PCIE_EVENTS.iter().enumerate() {
            let j = j as u64;
            let id = 0x4576 << 48 | (0x30 + j / 10) << 40 | (0x30 + j % 10) << 32 | 0x5072_7400 | ch(i);
            let format = format!("Port %u {title}");
            events.push((id, format!("{:<width$}", format, width = width).replacen("%u", &i.to_string(), 1)));
        }
    }
    let entry = |chans: &[(u64, String)], ty, unit, group, sub| {
        let c: Vec<(u64, &str)> = chans.iter().map(|(id, n)| (*id, n.as_str())).collect();
        legend_entry(&c, ty, unit, group, sub)
    };
    Prop::Array(vec![
        entry(&states, channel_type(2, 1 << 1, 4), 0x0100_0079_0000_0000, "AppleEmbeddedPCIE", Some("Link States")),
        entry(&events, channel_type(1, 1 << 15, 1), 0, "Link Events", None),
        entry(&energy, channel_type(1, 1 << 1, 1), 0x0300_0079_0000_0000, "Energy Model", None),
    ])
}

/// The root complex's port events' names (the format table at
/// 0xfffffff007b2c888): each "Port %u " and its title, padded with spaces
/// to the width given.
const PCIE_EVENTS: [(&str, usize); 62] = [
    ("Enable Request", 40),
    ("Enable Complete", 40),
    ("Disable Request", 40),
    ("Disable Complete", 40),
    ("Disable Hardware Off", 40),
    ("Disable LTSSM Off", 40),
    ("Suspend Request", 40),
    ("Suspend Complete", 40),
    ("Suspend Hardware Off", 40),
    ("Suspend LTSSM Off", 40),
    ("Deep Sleep Entry", 40),
    ("Deep Sleep Exit", 40),
    ("Link Up", 40),
    ("Link Up Timeout", 40),
    ("Unexpected Link Down", 40),
    ("PMETO Timeout", 40),
    ("Root Port Error Interrupt", 40),
    ("Correctable Error Interrupt", 40),
    ("Non-fatal Error Interrupt", 40),
    ("Fatal Error Interrupt Error", 40),
    ("AER EP Unc Data Link Protocol Error", 43),
    ("AER EP Unc Surprise Down Error", 43),
    ("AER EP Unc Poisoned TLP", 43),
    ("AER EP Unc Flow Ctrl Protocol Error", 43),
    ("AER EP Unc Completion Timeout", 43),
    ("AER EP Unc Completer Abort", 43),
    ("AER EP Unc Unexpected Completion", 43),
    ("AER EP Unc Receiver Overflow", 43),
    ("AER EP Unc Malformed TLP", 43),
    ("AER EP Unc ECRC Error", 43),
    ("AER EP Unc Unsupported Request", 43),
    ("AER EP Unc Uncorrected Internal Err", 43),
    ("AER EP Unc Atomic OP Egress Blocked", 43),
    ("AER EP Unc TLP Prefix Blocked Error", 43),
    ("AER EP Cor Receiver Error", 43),
    ("AER EP Cor Bad TLP", 43),
    ("AER EP Cor Bad DLLP", 43),
    ("AER EP Cor REPLAY_NUM Rollover", 43),
    ("AER EP Cor Retry Timer Timeout", 43),
    ("AER EP Cor Advisory Non-Fatal Error", 43),
    ("AER EP Cor Corrected Internal Error", 43),
    ("AER RC Unc Data Link Protocol Error", 43),
    ("AER RC Unc Surprise Down Error", 43),
    ("AER RC Unc Poisoned TLP", 43),
    ("AER RC Unc Flow Ctrl Protocol Error", 43),
    ("AER RC Unc Completion Timeout", 43),
    ("AER RC Unc Completer Abort", 43),
    ("AER RC Unc Unexpected Completion", 43),
    ("AER RC Unc Receiver Overflow", 43),
    ("AER RC Unc Malformed TLP", 43),
    ("AER RC Unc ECRC Error", 43),
    ("AER RC Unc Unsupported Request", 43),
    ("AER RC Unc Uncorrected Internal Err", 43),
    ("AER RC Unc Atomic OP Egress Blocked", 43),
    ("AER RC Unc TLP Prefix Blocked Error", 43),
    ("AER RC Cor Receiver Error", 43),
    ("AER RC Cor Bad TLP", 43),
    ("AER RC Cor Bad DLLP", 43),
    ("AER RC Cor REPLAY_NUM Rollover", 43),
    ("AER RC Cor Retry Timer Timeout", 43),
    ("AER RC Cor Advisory Non-Fatal Error", 43),
    ("AER RC Cor Corrected Internal Error", 43),
];

/// `IOReportChannelType` as `IOReporter::legendWith` stores it, a 64-bit
/// number of its bytes: the report format, a reserved byte, the
/// categories (16 bits), the elements per channel (16 bits) and the
/// element index (0).
fn channel_type(format: u8, categories: u16, nelements: u16) -> u64 {
    u64::from(format) | u64::from(categories) << 16 | u64::from(nelements) << 32
}

/// A reporter's legend entry (`IOReporter::legendWith`, then
/// `IOReportLegend::organizeLegend`): its channels, each an array of its
/// ID and type (64-bit numbers) and name (a symbol); its unit; its group
/// and subgroup names (symbols).
fn legend_entry(channels: &[(u64, &str)], ty: u64, unit: u64, group: &str, subgroup: Option<&str>) -> Prop {
    let chans = channels.iter().map(|&(id, name)| Prop::Array(vec![num64(id), num64(ty), sym(name)])).collect();
    let mut e = vec![key("IOReportChannels", Prop::Array(chans)), key("IOReportChannelInfo", Prop::Dict(vec![key("IOReportChannelUnit", num64(unit))])), key("IOReportGroupName", sym(group))];
    if let Some(sg) = subgroup {
        e.push(key("IOReportSubGroupName", sym(sg)));
    }
    Prop::Dict(e)
}

/// A namespace's reporters' legend (0xfffffff006a95e10): two
/// `IOSimpleReporter`s of kIOReportCategoryDebug and unit 0, in group
/// "NVMe": "BW Limits", the four tiers' bandwidth scale factors, and "Time
/// weighted throttle statistics", the time elapsed and the four tiers'
/// throttle times.
fn namespace_legend() -> Prop {
    let ty = channel_type(1, 1 << 15, 1);
    let tier = |n: u64, tail: u64| 0x5469_6572_2030_0000 | n << 16 | tail;
    Prop::Array(vec![
        legend_entry(&[(tier(0, 0x4257), "Tier0 BW Scale Factor"), (tier(1, 0x4257), "Tier1 BW Scale Factor"), (tier(2, 0x4257), "Tier2 BW Scale Factor"), (tier(3, 0x4257), "Tier3 BW Scale Factor")], ty, 0, "NVMe", Some("BW Limits")),
        legend_entry(&[(0x546f_7420_5469_6d65, "Total time elapsed"), (tier(0, 0x2020), "Tier0 Throttle Time"), (tier(1, 0x2020), "Tier1 Throttle Time"), (tier(2, 0x2020), "Tier2 Throttle Time"), (tier(3, 0x2020), "Tier3 Throttle Time")], ty, 0, "NVMe", Some("Time weighted throttle statistics")),
    ])
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
    if FIRMWARE_EUI64.is_none() {
        gaps.push(format!("NS_02's EUI64 (stand-in 0) and that no partition scheme recognizes the firmware namespace's contents (stand-in: a leaf with no content); measure {FIRMWARE_EUI64_MEASUREMENT} and its IOMedia's Content"));
    }
    if EFFACEABLE_EUI64.is_none() {
        gaps.push(format!("NS_06's EUI64 (stand-in 0); measure {EFFACEABLE_EUI64_MEASUREMENT}"));
    }
    if CONTAINER_STATUS.is_none() {
        gaps.push(format!("the AppleAPFSContainer's Status (stand-in {STAND_IN_CONTAINER_STATUS:?}; measure {CONTAINER_STATUS_MEASUREMENT})"));
    }
    gaps.push("the storage statistics count the disk nodes' requests only: the APFS container's own I/O at its start and the volumes' mounts (all 35 of its counters) is not modelled".into());
    if CONTROLLER_DEVICE_FACTS.is_none() {
        gaps.push(format!("the NAND controller's registers and Apple Identify area (stand-in: CAP.MQES 0xffff, VS 0, MDTS 0, its strings \"(unmeasured)\", chip S3E, no device description, manufacturer ID or geometry, capacity {} GB; measure {CONTROLLER_MEASUREMENT})", stand_in_controller().capacity_gb));
    }
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
    ]));
    n.props = e.props.clone();
    // The entry's own table: what was set on it before (a root port's
    // port object), after its device tree properties.
    n.service_props = e.service_props.clone();
    n.dt = Some(DtLink { parent: dt_parent, name: e.name.clone(), location: Some(location.to_string()) });
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
    // The controller's children before it, in the order its start makes
    // them: its temperature sensor, then its NVRAM (NSID 5).
    if let Some(c) = controller {
        add_controller_objects(t, c);
    }
    let ns_props = namespace_props(1, n.eui64, block);
    let ns = push(t, service("NS_01", BLOCK_DEVICE, controller, ns_props, Table::Complete));
    // IOBlockStorageDriver's personality; its init's statistics (live,
    // [`stats`]).
    let mut props = driver("com.apple.iokit.IOStorageFamily", DRIVER, "IOBlockStorageDevice", None, "IODefaultMatchCategory", 0, vec![key("IOPropertyMatch", Prop::Dict(vec![key("device-type", string("Generic"))]))]);
    props.push(key("Statistics", stats::driver(1)));
    // Its start's PMinit, after `handleStart` publishes its medium.
    props.push(key(super::iopower::KEY, super::iopower::joined_without_driver()));
    let drv = push(t, service(DRIVER, DRIVER, Some(ns), props, Table::Complete));
    // disk0: its content the GPT scheme's Content Mask, no leaf; its icon
    // the internal one (the namespace's Physical Interconnect Location).
    let mut props = medium("GUID_partition_scheme", "", false, block, super::storage::disk0_bytes(), true, writable);
    props.push(key("IOMediaIcon", Prop::Dict(vec![key("CFBundleIdentifier", string("com.apple.iokit.IOStorageFamily")), key("IOBundleResourceFile", string("Internal.icns"))])));
    props.extend(bsd_keys(Media::Whole));
    let mut whole = service(&format!("{} Media", n.model), "IOMedia", Some(drv), props, Table::Complete);
    // The media's parent in the `IODeviceTree` plane: the first provider
    // up the plane that is in it (`acceptNewMedia`, and for a partition
    // `attachMediaObjectToDeviceTree` through its whole disk's), the
    // controller.
    let dt_parent = controller;
    whole.dt = dt_parent.map(|p| DtLink { parent: p, name: "disk".to_string(), location: Some("1:0".to_string()) });
    let whole = push(t, whole);
    add_bsd_client(t, whole, BSD_CLIENT);
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
    part.dt = dt_parent.map(|p| DtLink { parent: p, name: "disk".to_string(), location: Some("1:1".to_string()) });
    let part = push(t, part);
    add_bsd_client(t, part, BSD_CLIENT);
    // AppleAPFSContainerScheme: its personality, its init's statistics
    // and APFSComposited (the container's nx_fusion_uuid null,
    // 0xfffffff0066824d4).
    let mut props = driver("com.apple.filesystems.apfs", APFS_SCHEME, "IOMedia", None, "IOStorage", 2000, vec![key("IOPropertyMatch", Prop::Array(vec![Prop::Dict(vec![key("Content Hint", string(CONTAINER_PARTITION_HINT))])]))]);
    props.push(key("Statistics", stats::scheme()));
    props.push(key("APFSComposited", Prop::Bool(false)));
    let scheme = push(t, service(APFS_SCHEME, APFS_SCHEME, Some(part), props, Table::Complete));
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
    add_bsd_client(t, media, APFS_MEDIA_BSD);
    // AppleAPFSContainer: its personality, then what its start sets
    // (0xfffffff00666ade4): its statistics (live, [`stats`]), then its
    // Status.
    let mut props = driver("com.apple.filesystems.apfs", APFS_CONTAINER, "IOMedia", None, "IOStorage", 1000, vec![
        key("IOPropertyMatch", Prop::Array(vec![Prop::Dict(vec![key("Content Hint", string(APFS_CONTAINER_HINT))])])),
        key("IOUserClientClass", string("AppleAPFSUserClient")),
    ]);
    props.push(key("Statistics", stats::container()));
    props.push(key("Status", sym(container_status())));
    let container = push(t, service(APFS_CONTAINER, APFS_CONTAINER, Some(media), props, Table::Complete));
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
    add_namespaces(t, controller, dt_parent);
}

/// A namespace's properties (IONVMeBlockStorageDevice and
/// IOEmbeddedNVMeBlockDevice, 0xfffffff006a954d8, 0xfffffff006a95e10,
/// 0xfffffff006a70014 and 0xfffffff006a97a20): IOBlockStorageDevice::init's
/// device type, its unit, Identify Namespace's EUI64 and NSID, its
/// reporters' legend, the transfer limits (its type's,
/// [`NAMESPACE_MAX_BYTES`]), Encryption, its type's key
/// (from the table at 0xfffffff007c17c08: the root's EmbeddedDeviceTypeRoot,
/// the firmware's EmbeddedDeviceTypeFirmware, ...) and, but on the root,
/// autodiskmount false; its storage features (Unmap from ONCS Dataset
/// Management, gNVMeDebug's bit 0x200 being clear and no vendor quirk;
/// Priority, the controller's slot 0x5b0 answering 1; Barrier, flags bit
/// 4, always set here, on NSID 1 only), its throttling, the block sizes,
/// its characteristics (the controller's strings; the vendor name empty)
/// and protocol characteristics (found up the plane, the controller
/// personality's), and on NSID 1 the SMART plug-in.
fn namespace_props(nsid: u32, eui64: u64, block: u64) -> Vec<(String, Prop)> {
    let n = super::storage::nvme();
    let ty = namespace_type(nsid);
    let max = u64::from(NAMESPACE_MAX_BYTES[ty as usize]);
    let mut p = vec![
        key("device-type", sym("Generic")),
        key("IOUnit", num32(u64::from(nsid))),
        key("NamespaceUUID", num64(eui64)),
        key("NamespaceID", num32(u64::from(nsid))),
        key("IOReportLegend", namespace_legend()),
        key("IOReportLegendPublic", Prop::Bool(true)),
        key("IOMaximumSegmentCountRead", num32(max >> 12)),
        key("IOMaximumSegmentCountWrite", num32(max >> 12)),
        key("IOMaximumSegmentByteCountRead", num32(max)),
        key("IOMaximumSegmentByteCountWrite", num32(max)),
        key("IOMinimumSegmentAlignmentByteCount", num32(4096)),
        key("IOMaximumByteCountRead", num32(max)),
        key("IOMaximumByteCountWrite", num32(max)),
        key("IOMaximumBlockCountRead", num32(max >> 12)),
        key("IOMaximumBlockCountWrite", num32(max >> 12)),
        key("Encryption", Prop::Bool(true)),
        key(NAMESPACE_TYPE_KEYS[ty as usize], Prop::Bool(true)),
    ];
    if ty != 1 {
        p.push(key("autodiskmount", Prop::Bool(false)));
    }
    p.extend([
        key("IOStorageFeatures", features(nsid == 1)),
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
    ]);
    if nsid == 1 {
        p.push(key("IOCFPlugInTypes", Prop::Dict(vec![key("AA0FA6F9-C2D6-457F-B10B-59A13253292F", string("NVMeSMARTLib.plugin"))])));
        p.push(key("NVMe SMART Capable", Prop::Bool(true)));
    }
    p
}

/// The most a namespace's transfer may be, in bytes, by its type
/// (0xfffffff007c17d38): the namespace's publishing (0xfffffff006a70014)
/// takes it as its byte counts and a segment's size, and its 4096-byte
/// blocks as its block and segment counts.
const NAMESPACE_MAX_BYTES: [u32; 14] = [0, 0x10_0000, 0x10_0000, 0x1000, 0x1000, 0x2000, 0x1000, 0, 0x10_0000, 0x10_0000, 0x10_0000, 0x10_0000, 0x10_0000, 0x10_0000];

/// The namespaces' types' keys (0xfffffff007c17c08), by type.
const NAMESPACE_TYPE_KEYS: [&str; 14] = [
    "NULL",
    "EmbeddedDeviceTypeRoot",
    "EmbeddedDeviceTypeFirmware",
    "EmbeddedDeviceTypeSysConfig",
    "EmbeddedDeviceTypeControlBits",
    "EmbeddedDeviceTypeNVRAM",
    "EmbeddedDeviceTypeEffaceable",
    "EmbeddedDeviceTypeCalibration",
    "EmbeddedDeviceTypePanicLog",
    "EmbeddedDeviceTypeAHCI",
    "EmbeddedDeviceTypeBIS",
    "EmbeddedDeviceTypeME",
    "EmbeddedDeviceTypeLifeboat",
    "EmbeddedDeviceTypeEAN",
];

/// A namespace's type: the device tree's `namespaces` (s3e), entries of
/// NSID, type and size in blocks: (1, 1, 0), (2, 2, 2048), (3, 3, 32),
/// (4, 4, 2), (5, 5, 2), (6, 6, 1), (7, 8, 256); a restored device's
/// Identify Namespace answers them (`CreateNamespaces` made them so).
fn namespace_type(nsid: u32) -> u32 {
    match nsid {
        7 => 8,
        n => n,
    }
}

/// The firmware namespace's size in blocks of 4096 bytes: the device
/// tree's, which IONVMeFamily enforces (`ValidateNamespaceSize`,
/// 0xfffffff006a604a8, panics on any other NCAP or LBA size).
pub const FIRMWARE_BLOCKS: u64 = 2048;

/// The firmware namespace's Identify Namespace EUI64: the device's, once
/// measured; zero (as the main namespace's stand-in) meanwhile, a reported
/// shortcut.
pub const FIRMWARE_EUI64: Option<u64> = None;

/// The effaceable namespace's (NSID 6) Identify Namespace EUI64: the
/// device's, once measured; zero meanwhile, a reported shortcut.
pub const EFFACEABLE_EUI64: Option<u64> = None;

/// What measures [`EFFACEABLE_EUI64`].
pub const EFFACEABLE_EUI64_MEASUREMENT: &str = "the NamespaceUUID of NS_06 (a sysdiagnose's ioreg IOService plane)";

/// What measures [`FIRMWARE_EUI64`].
pub const FIRMWARE_EUI64_MEASUREMENT: &str = "the NamespaceUUID of NS_02 (a sysdiagnose's ioreg IOService plane)";

/// The controller's objects made before its namespaces (InitializeController,
/// 0xfffffff006a5b640, then slot 0x930, 0xfffffff006a5ecc4), neither given
/// a name (each is its class's) or a location:
/// - Its temperature sensor, an `AppleEmbeddedNVMeTemperatureSensor` (an
///   IOHIDEventService). Its init (0xfffffff006a651d0) sets QueueSize 0;
///   AppleEmbeddedHIDEventService's `handleStart` (0xfffffff006b03430) sets
///   Built-In (its orientation and placement are 0, so not those);
///   `IOHIDEventService::start` (0xfffffff005aeb150) then sets its location
///   ID ('TN0n'), vendor, vendor source, product, version and country
///   (32-bit numbers, the controller giving none), its product name "NAND
///   CH0 temp", its one usage pair (page 0xff00, usage 5), its report
///   interval (0: the override 0xfffffff006b039c8) and primary usage; the
///   controller has no Transport, Manufacturer or SerialNumber to copy. It
///   registers (0xfffffff005aeb8c0). IOHIDFamily's personality of
///   `IOHIDProviderPropertyMerger` on IOHIDEventService then merges its
///   IOProviderMergeProperties into it (its probe merges them and fails):
///   IOCFPlugInTypes, HIDServiceSupport and IOUserClientClass. No driver
///   matches it.
/// - Its NVRAM, an `AppleEmbeddedNVMeNVRAM` on NSID 5: its start
///   (0xfffffff006a757fc) sets nothing and registers (0xfffffff006a75920,
///   `IONVRAMController::registerService`). No driver matches it.
fn add_controller_objects(t: &mut Vec<Node>, controller: u32) {
    let props = vec![
        key("QueueSize", num32(0)),
        key("Built-In", Prop::Bool(true)),
        key("LocationID", num32(0x544e_306e)),
        key("VendorID", num32(0)),
        key("VendorIDSource", num32(0)),
        key("ProductID", num32(0)),
        key("VersionNumber", num32(0)),
        key("CountryCode", num32(0)),
        key("Product", string("NAND CH0 temp")),
        key("DeviceUsagePairs", Prop::Array(vec![Prop::Dict(vec![key("DeviceUsagePage", num32(0xff00)), key("DeviceUsage", num32(5))])])),
        key("ReportInterval", num32(0)),
        key("PrimaryUsagePage", num32(0xff00)),
        key("PrimaryUsage", num32(5)),
        key("IOCFPlugInTypes", Prop::Dict(vec![
            key("7DDEECA8-A7B4-11DA-8A0E-0014519758EF", string("IOHIDFamily.kext/PlugIns/IOHIDLib.plugin")),
            key("FA12FA38-6F1A-11D4-BA0C-0005028F18D5", string("IOHIDFamily.kext/PlugIns/IOHIDLib.plugin")),
        ])),
        key("HIDServiceSupport", Prop::Bool(true)),
        key("IOUserClientClass", string("IOHIDEventServiceUserClient")),
    ];
    push(t, service(TEMP_SENSOR, TEMP_SENSOR, Some(controller), props, Table::Complete));
    push(t, service(NVRAM, NVRAM, Some(controller), Vec::new(), Table::Complete));
}

/// The namespaces after the root (`AllocateNodes`, 0xfffffff006a5e35c,
/// NSID 2 on, but the types it makes elsewhere, 4 and 5):
/// - NSID 2, the firmware, an `IOEmbeddedNVMeBlockDevice` "NS_02" at "2":
///   IOBlockStorageDriver matches it as NSID 1's, and its whole disk, of
///   2048 blocks, no partition scheme claims (its contents are the
///   firmware's, not a partition map: a stand-in, [`unmeasured`]), so it is
///   a leaf with no content; attached in the `IODeviceTree` plane as
///   "disk" at "2:0".
/// - NSID 3, `AppleEmbeddedNVMeDiagnostics` (an AppleNANDConfigAccess),
///   on which AppleDiagnosticDataAccessReadOnly's personality
///   AppleNANDDiagnosticDataAccess matches (score 99, its own category).
/// - NSID 6, an `IONVMeEffaceableDevice` "NS_06" at "6": both
///   AppleEffaceableBlockDevice's "-NVMe" personality and
///   IOBlockStorageDriver's match it, in the default category at score 0;
///   `IOCatalogue::findDrivers` adds the most derived provider class's
///   personalities first and `OSOrderedSet` keeps equal scores in order, so
///   AppleEffaceableBlockDevice is tried, and taken, first: no IOMedia.
/// - NSID 7 (type 8, the panic log), an `AppleNVMeNamespaceDevice` "NS_07"
///   (0xfffffff006a7d7a0).
fn add_namespaces(t: &mut Vec<Node>, controller: Option<u32>, dt_parent: Option<u32>) {
    let Some(c) = controller else { return };
    let n = super::storage::nvme();
    let block = 4096;
    let eui = FIRMWARE_EUI64.unwrap_or(0);
    let ns = push(t, service("NS_02", BLOCK_DEVICE, Some(c), namespace_props(2, eui, block), Table::Complete));
    let mut props = driver("com.apple.iokit.IOStorageFamily", DRIVER, "IOBlockStorageDevice", None, "IODefaultMatchCategory", 0, vec![key("IOPropertyMatch", Prop::Dict(vec![key("device-type", string("Generic"))]))]);
    props.push(key("Statistics", stats::driver(2)));
    props.push(key(super::iopower::KEY, super::iopower::joined_without_driver()));
    let drv = push(t, service(DRIVER, DRIVER, Some(ns), props, Table::Complete));
    let mut props = medium("", "", true, block, FIRMWARE_BLOCKS * block, true, super::storage::disk_writable());
    props.push(key("IOMediaIcon", Prop::Dict(vec![key("CFBundleIdentifier", string("com.apple.iokit.IOStorageFamily")), key("IOBundleResourceFile", string("Internal.icns"))])));
    props.extend(bsd_keys(Media::Firmware));
    let mut whole = service(&format!("{} Media", n.model), "IOMedia", Some(drv), props, Table::Complete);
    whole.dt = dt_parent.map(|p| DtLink { parent: p, name: "disk".to_string(), location: Some("2:0".to_string()) });
    let whole = push(t, whole);
    add_bsd_client(t, whole, BSD_CLIENT);
    // Diagnostics' start (0xfffffff006a713b8) and its driver's
    // (0xfffffff006c7b2cc) set nothing; both register (0xfffffff006a71504,
    // 0xfffffff006c7b474).
    let diag = push(t, service(DIAGNOSTICS, DIAGNOSTICS, Some(c), Vec::new(), Table::Complete));
    let props = driver("com.apple.driver.AppleDiagnosticDataAccessReadOnly", DIAG_DRIVER, "AppleNANDConfigAccess", None, "AppleDiagnosticDataAccess", 99, Vec::new());
    push(t, service(DIAG_DRIVER, DIAG_DRIVER, Some(diag), props, Table::Complete));
    // NS_06: IONVMeEffaceableDevice overrides the strings the namespace's
    // Device Characteristics take (its vtable 0xfffffff006fa4380): vendor
    // "Apple", product "Effaceable", revision "unknown revision".
    let mut props = namespace_props(6, EFFACEABLE_EUI64.unwrap_or(0), block);
    if let Some((_, Prop::Dict(d))) = props.iter_mut().find(|(k, _)| k == "Device Characteristics") {
        for (k, v) in [("Vendor Name", "Apple"), ("Product Name", "Effaceable"), ("Product Revision Level", "unknown revision")] {
            set(d, k, string(v));
        }
    }
    let eff = push(t, service("NS_06", EFFACEABLE, Some(c), props, Table::Complete));
    // AppleEffaceableBlockDevice's start (AppleEffaceableStorage's,
    // 0xfffffff006586900) sets nothing and registers (0xfffffff006586ab4).
    let props = driver("com.apple.driver.AppleEffaceableBlockDevice", EFFACEABLE_DRIVER, EFFACEABLE, None, "IODefaultMatchCategory", 0, Vec::new());
    push(t, service(EFFACEABLE_DRIVER, EFFACEABLE_DRIVER, Some(eff), props, Table::Complete));
    // NS_07's start (0xfffffff006a7d5c4) names it, sets its type's key
    // (0xfffffff006a7d8a0, the panic log's) and registers.
    push(t, service("NS_07", NAMESPACE_DEVICE, Some(c), vec![key(NAMESPACE_TYPE_KEYS[namespace_type(7) as usize], Prop::Bool(true))], Table::Complete));
}

/// The namespace's IOStorageFeatures, a dictionary of three booleans in
/// this order (0xfffffff006a97a20).
fn storage_features() -> Prop {
    features(true)
}

/// A namespace's IOStorageFeatures, Barrier only on NSID 1.
fn features(barrier: bool) -> Prop {
    let n = super::storage::nvme();
    Prop::Dict(vec![key("Unmap", Prop::Bool(n.dataset_management)), key("Priority", Prop::Bool(true)), key("Barrier", Prop::Bool(barrier))])
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
        T8011_PCIE | PCI_DEVICE | HOST_BRIDGE | CONTROLLER | BLOCK_DEVICE | EFFACEABLE | DRIVER | "IOMedia" | BSD_CLIENT | APFS_MEDIA | APFS_CONTAINER | APFS_VOLUME | APFS_MEDIA_BSD | APFS_VOLUME_BSD | DIAGNOSTICS | NAMESPACE_DEVICE | TEMP_SENSOR | NVRAM | DIAG_DRIVER | EFFACEABLE_DRIVER => Some(true),
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
    if name == "WriteCacheState" && superclasses(n.class).contains(&"IOBlockStorageDevice") && n.class != EFFACEABLE {
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
        BLOCK_DEVICE | EFFACEABLE => n.name.strip_prefix("NS_").and_then(|d| d.parse::<u32>().ok()).map(|nsid| format!("{nsid:x}")),
        PCI_DEVICE => n.dt.as_ref().and_then(|d| d.location.clone()),
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

/// The medium a storage entry is: an `IOMedia` with BSD nodes.
pub fn medium_of(n: &Node) -> Option<Media> {
    superclasses(n.class).contains(&"IOMedia").then(|| media_of(n)).flatten()
}

/// A storage driver's live Statistics ([`stats`]), and a medium's live
/// "Open": `IOMedia::handleOpen` sets it once it holds its
/// provider open at some level and `handleClose` clears it once it holds
/// none ([`super::dkopen`]'s levels).
pub fn live_prop(t: &[Node], i: u32, name: &str) -> Option<Prop> {
    let n = t.get(i as usize)?;
    // The effaceable namespace's getWriteCacheState (0xfffffff006a709f0)
    // answers success without writing, and IOBlockStorageDevice's
    // getProperty override (0xfffffff00596ee88) starts from false.
    if name == "WriteCacheState" && n.class == EFFACEABLE {
        return Some(Prop::Bool(false));
    }
    if name == "Statistics" {
        return match n.class {
            DRIVER => stats::namespace_of(t, i).map(stats::driver),
            APFS_SCHEME => Some(stats::scheme()),
            APFS_CONTAINER => Some(stats::container()),
            _ => None,
        };
    }
    if name != "Open" || !superclasses(n.class).contains(&"IOMedia") {
        return None;
    }
    let m = media_of(n)?;
    let level = super::dkopen::media_opens(m)?.level;
    Some(Prop::Bool(level != super::dkopen::access::NONE))
}

/// What `AppleAPFSContainer`'s start sets as its Status (0xfffffff00666b0d0):
/// "Online", or "Readonly" when the container's state has the flag at its
/// +0x38 set (from the table at 0xfffffff006f297c0, which also names
/// Offline, Pairing, Checking, Corrupt and Incompatible). Which the
/// device's mounted container has is not traced: "Online" (the container
/// writable, as its disk is) stands in, a reported shortcut
/// ([`unmeasured`]).
pub const STAND_IN_CONTAINER_STATUS: &str = "Online";

/// The device's, once measured.
pub const CONTAINER_STATUS: Option<&str> = None;

/// What measures [`CONTAINER_STATUS`].
pub const CONTAINER_STATUS_MEASUREMENT: &str = "the Status of the AppleAPFSContainer (a sysdiagnose's ioreg IOService plane)";

fn container_status() -> &'static str {
    CONTAINER_STATUS.unwrap_or(STAND_IN_CONTAINER_STATUS)
}

/// The storage's I/O counters, as the drivers keep them and publish them
/// in their Statistics dictionaries, each a live view of these counts.
/// The disk nodes' requests move them ([`super::disknode`]): through
/// [`driver_transfer`] and [`driver_error`] for every request that reaches
/// the medium, and [`scheme_transfer`] for the container's. The APFS
/// container's own I/O (its start, the volumes' mounts, its object cache
/// and transactions), which [`container_count`] and the other two would
/// count, is not modelled: the volumes are not mounted from the container
/// yet, and that gap is reported at start ([`unmeasured`]).
/// `IOBlockStorageDriver::incrementRetries` has no caller in the family;
/// [`driver_retry`] is for a device driver that retries.
pub mod stats {
    use super::{key, num64, Node, Prop};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// IOBlockStorageDriver's statistics in the order its init adds them
    /// to its dictionary (0xfffffff00596f408), each a 64-bit number.
    pub const DRIVER_KEYS: [&str; 12] = [
        "Bytes (Read)",
        "Bytes (Write)",
        "Errors (Read)",
        "Errors (Write)",
        "Latency Time (Read)",
        "Latency Time (Write)",
        "Operations (Read)",
        "Operations (Write)",
        "Retries (Read)",
        "Retries (Write)",
        "Total Time (Read)",
        "Total Time (Write)",
    ];

    /// The counters of each namespace's storage driver (NSID 1 and 2).
    static DRIVERS: [[AtomicU64; 12]; 2] = [const { [const { AtomicU64::new(0) }; 12] }; 2];

    /// AppleAPFSContainerScheme's (0xfffffff006682418): APFSOSNumberAtomic
    /// counters of 64 bits.
    pub const SCHEME_KEYS: [&str; 4] = ["Bytes (Read)", "Bytes (Write)", "Operations (Read)", "Operations (Write)"];
    static SCHEME: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

    /// AppleAPFSContainer's statistics: the names of its 86 counters
    /// (0xfffffff006f284c0), of which its init (0xfffffff00666ae40) makes
    /// all but the Fusion ones (4 to 54), each an APFSOSNumberAtomic of 64
    /// bits, added to its dictionary in this order.
    pub const CONTAINER_KEYS: [&str; 35] = [
        "Read requests sent to block device",
        "Bytes read from block device",
        "Write requests sent to block device",
        "Bytes written to block device",
        "Object cache: Total number of queries",
        "Object cache: Number of hits",
        "Object cache: Number of evictions",
        "Object cache: Number of reads",
        "Object cache: Number of writes",
        "Object cache: Number of full cache flushes",
        "Object cache: Number of partial cache flushes",
        "Object cache: Number of objects processed by partial cache flushes",
        "Metadata: Number of bytes read",
        "Metadata: Number of read errors",
        "Metadata: Number of spaceman bitmap bytes read",
        "Metadata: Number of bytes written",
        "Metadata: Number of write errors",
        "Metadata: Number of spaceman bitmap bytes written",
        "Metadata: Number of bytes written to checkpoint area",
        "FX defrag: Number of blocks reallocated",
        "FX defrag: Number of file extents reallocated",
        "FX defrag: Number of file extents skipped during relocation",
        "FX defrag: Number of spaceman chunks chosen for data relocation",
        "FX defrag: Number of times free extent defrag has run",
        "FX defrag: Number of times free extent defrag has completed",
        "FX defrag: Number of times free extent defrag has run aggressively",
        "FX defrag: Number of times free extent defrag has completed aggressively",
        "Number of transactions flushed",
        "Number of transaction updates",
        "Number of times device's cache flushed",
        "Write burst: Total time",
        "Write burst: Total number of bytes written",
        "Write burst: Total number of I/Os",
        "Write burst: Total time between bursts",
        "Write burst: Burst count",
    ];
    static CONTAINER: [AtomicU64; 35] = [const { AtomicU64::new(0) }; 35];

    fn dict(keys: &[&str], values: &[AtomicU64]) -> Prop {
        Prop::Dict(keys.iter().zip(values).map(|(k, v)| key(k, num64(v.load(Ordering::Relaxed)))).collect())
    }

    /// The namespace (1 or 2) whose storage driver is entry `i`.
    pub fn namespace_of(t: &[Node], i: u32) -> Option<u32> {
        let ns = &t[t.get(i as usize)?.parent? as usize];
        ns.name.strip_prefix("NS_")?.parse().ok()
    }

    /// The Statistics of namespace `nsid`'s storage driver.
    pub fn driver(nsid: u32) -> Prop {
        dict(&DRIVER_KEYS, &DRIVERS[(nsid as usize).saturating_sub(1).min(1)])
    }

    pub fn scheme() -> Prop {
        dict(&SCHEME_KEYS, &SCHEME)
    }

    pub fn container() -> Prop {
        dict(&CONTAINER_KEYS, &CONTAINER)
    }

    /// `IOBlockStorageDriver::addToBytesTransferred`: one transfer of
    /// `bytes` through namespace `nsid`'s driver, its total and latent
    /// times in nanoseconds.
    pub fn driver_transfer(nsid: u32, bytes: u64, total_ns: u64, latent_ns: u64, write: bool) {
        let d = &DRIVERS[(nsid as usize).saturating_sub(1).min(1)];
        let w = usize::from(write);
        d[6 + w].fetch_add(1, Ordering::Relaxed);
        d[w].fetch_add(bytes, Ordering::Relaxed);
        d[10 + w].fetch_add(total_ns, Ordering::Relaxed);
        d[4 + w].fetch_add(latent_ns, Ordering::Relaxed);
    }

    /// `IOBlockStorageDriver::incrementRetries`.
    pub fn driver_retry(nsid: u32, write: bool) {
        DRIVERS[(nsid as usize).saturating_sub(1).min(1)][8 + usize::from(write)].fetch_add(1, Ordering::Relaxed);
    }

    /// `IOBlockStorageDriver::incrementErrors`.
    pub fn driver_error(nsid: u32, write: bool) {
        DRIVERS[(nsid as usize).saturating_sub(1).min(1)][2 + usize::from(write)].fetch_add(1, Ordering::Relaxed);
    }

    /// One transfer of `bytes` through the container scheme.
    pub fn scheme_transfer(bytes: u64, write: bool) {
        let w = usize::from(write);
        SCHEME[w].fetch_add(bytes, Ordering::Relaxed);
        SCHEME[2 + w].fetch_add(1, Ordering::Relaxed);
    }

    /// Add `n` to the container's counter named `name` (one of
    /// [`CONTAINER_KEYS`]); false for a name it does not keep.
    pub fn container_count(name: &str, n: u64) -> bool {
        match CONTAINER_KEYS.iter().position(|k| *k == name) {
            Some(i) => {
                CONTAINER[i].fetch_add(n, Ordering::Relaxed);
                true
            }
            None => false,
        }
    }
}
