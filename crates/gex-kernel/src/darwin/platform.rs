//! The platform's drivers between the registry's root and the GPU, as the
//! device's kernelcache (21H461, iPad7,1) matches and publishes them over
//! its device tree in the `IOService` plane:
//!
//! ```text
//! Root                    IORegistryEntry
//!   J120AP                IOPlatformExpertDevice (the device tree's root)
//!     AppleARMPE          the platform expert
//!       IOPMrootDomain    the root power domain (`super::iopower`)
//!       cpu0 .. cpus ..   IOPlatformDevice nubs of /cpus's children and of
//!                         the root's children, arm-io among them
//!       arm-io            IOPlatformDevice, a nub of the device tree's arm-io
//!         AppleT8011IO    arm-io's driver
//!           ...           AppleARMIODevice, a nub of each of arm-io's children:
//!           sgx           (the GPU's accelerator, `super::accel`)
//!           disp0         (the display's framebuffer, `super::iomfb`)
//!           apcie         (the PCIe root complex, `super::storagestack`)
//! ```
//!
//! - The platform expert. `AppleARMPE` (com.apple.driver.AppleARMPlatform)
//!   is the only personality whose `IOProviderClass` is
//!   `IOPlatformExpertDevice`. Its `IONameMatch` "AppleARM" is one of the
//!   root's `compatible` names. Its probe is IODTPlatformExpert's, which
//!   keeps the personality's score.
//! - The top-level nubs. AppleARMPE's start (0xfffffff00598f844) calls
//!   `IOPlatformExpert::start` through IODTPlatformExpert's vtable
//!   (0xfffffff00598f93c), which ends in `configure` and so in
//!   `processTopLevel`. AppleARMPE overrides neither of those, nor
//!   `createNub` or `createNubs` (vtable slots 174, 208, 211, 212).
//!   - The nubs are the root's children less its `excludeList`
//!     (0xfffffff00598fee8): `('chosen', 'memory', 'options', 'aliases')`.
//!     Its `deleteList` (0xfffffff00598fedc) is empty.
//!   - `IODTPlatformExpert::createNub` (0xfffffff00780d2f8) makes each an
//!     `IOPlatformDevice`; its vtable is stored at 0xfffffff00780d370.
//!   - `createNubs` attaches each to the expert (0xfffffff00780d500).
//! - arm-io's driver. `AppleT8011IO` (com.apple.driver.AppleT8011) is the
//!   only personality naming arm-io: `IOProviderClass` `IOPlatformDevice`,
//!   `IONameMatch` "arm-io,t8011". Its probe is IOService's (score 0).
//! - arm-io's nubs. AppleARMIO's publishing routine (vtable slot 178,
//!   0xfffffff00598c1d4) is not overridden by `AppleT801xIO` or
//!   `AppleT8011IO`.
//!   - It takes every child of its provider; the exclude list is empty
//!     (`IODTFindMatchingEntries` at 0xfffffff00598c278).
//!   - Each child becomes an `AppleARMIODevice` (slot 176, 0xfffffff00598c118:
//!     216 bytes, AppleARMIODevice's vtable stored at 0xfffffff00598c160).
//!   - Each is attached to the AppleARMIO (0xfffffff00598c2b8).
//!
//! Each class's superclasses are its `OSMetaClass` constructor's (the
//! metaclass, its name and its superclass's metaclass, from the kernel's and
//! each kext's static initializers).
//!
//! A driver's properties are its personality plus what matching adds:
//! - `CFBundleIdentifier`, the kext's, where the personality has none
//!   (`OSKext::copyPersonalitiesArray`).
//! - `CFBundleIdentifierKernel` (`uniquePersonalityProperties` in
//!   `IOCatalogue::addDrivers`, which also uniques `IOClass`,
//!   `IOProviderClass` and `IOMatchCategory` to OSSymbols).
//! - `IONameMatched`, the name `IONameMatch` matched (`matchInternal`).
//! - `IOMatchedAtBoot`, the kext being in the boot collection
//!   (`personalityIsBoot`).
//! - `IOMatchCategory` (`IODefaultMatchCategory` if the personality has
//!   none).
//! - `IOProbeScore`, a 32-bit number of the probe's score (`probeCandidates`).
//!
//! What the drivers' starts set is in [`add`]; what the drivers matched on
//! the nubs set on them is not modelled, and is reported when read. So are
//! the platform expert's other children (IOSystemStateNotification, the
//! PCIe MSI controller) and the drivers' clients.
//!
//! The resources nub. `IOService::initialize` makes `IOResources` (its
//! `resources()`, inlined at 0xfffffff0077c8ec0, keeps it in gIOResources,
//! 0xfffffff007974520). `IOService::setPlatform` attaches it to the root in
//! the `IOService` plane. `IOResources::init` (0xfffffff0077c479c) sets no
//! property: the PAL's resource property is x86's. Its properties are the
//! resources published with `IOService::publishResource` (the `const char *`
//! form 0xfffffff0077cb108, the `const OSSymbol *` form 0xfffffff0077ca428,
//! and their inlined copies): a resource published with no value has
//! gIOServiceKey, "IOService". The kernelcache's publishers and keys:
//! - The kernel: "IOKit" (`publishPMRootDomain`, 0xfffffff0077c9d60),
//!   "IOBSD" (0xfffffff0075eb650, 0xfffffff007850d58), "IONVRAM"
//!   (0xfffffff00780bda8, 0xfffffff00780d038), "IOPlatformUUID"
//!   (0xfffffff00780c494), "boot-uuid" (0xfffffff007851b94,
//!   0xfffffff007852584), "com.apple.AppleDiskImageController.load"
//!   (0xfffffff00785317c), "OSKextReceiptQueried" (0xfffffff00730bce0),
//!   "com.apple.AppleFSCompression.Type%u" for each decompressor a kext
//!   registers (0xfffffff0073b68b0), and "IOConsoleUsersSeed"
//!   (`updateConsoleUsers`, 0xfffffff0077c5110).
//! - `IOResources::setProperties` (0xfffffff007860960): any key a task
//!   with com.apple.private.iokit.ioresources.setproperty, or an
//!   administrator's, sets.
//! - The kexts: "kdp" (IONetworkingFamily); "AppleARMCPU-BootCPU-Initialized",
//!   "AppleARMCPU-AllCPU-Initialized", "IOAllCPUInitialized" and "IORTC"
//!   (AppleARMPlatform); "AppleUSBCableDetect" and "AppleUSBCableType"
//!   (IOAccessoryManager, AppleEmbeddedUSB); "IOPMU" (AppleD2400PMU);
//!   "IOTimeSyncTime" and "IOTimeSyncClockManager" (IOTimeSyncFamily);
//!   "IOTimeSyncDaemonService" (IOgPTPPlugin); "CoreAnalyticsMessenger"
//!   (CoreAnalyticsFamily); "DieTempControllerResource"
//!   (AppleEmbeddedTempSensor); "AppleSMCEmbeddedResource" (AppleSMC);
//!   "SEP" (AppleSEPManager); "AKSFileSystemKeyServices",
//!   "AKSKernelServices" and "AKSFileVaultServices" (AppleSEPKeyStore);
//!   "KeyboardBacklight" (AppleHIDKeyboard); "CCCapture", "CCPipe" and its
//!   own objects' names (corecapture); and a name AppleSEPCredentialManager
//!   formats.
//! - `IOService` itself sets "IOResourceMatched", the resources' keys when
//!   it last matched drivers on the nub.
//!
//! Of these, the nub here has those the kernel publishes on every boot
//! before any process runs, in their order: "IOKit" (IOPMrootDomain's
//! start, from `PMInstantiatePowerDomains` in `IOPlatformExpert::start`),
//! "IOPlatformUUID" (`publishPlatformUUIDAndSerial`, next in that start,
//! when the platform's UUID was made: [`platform_uuid`]) and "IOBSD"
//! (`bsd_init`; IOSurfaceRoot's `IOResourceMatch`). Whether the others are
//! published, and with what, is the kexts', the hardware's and user
//! space's, so they are reported when read.
//!
//! The platform's UUID. `IOPlatformExpert::start` (0xfffffff00780b088)
//! calls `publishPlatformUUIDAndSerial` (0xfffffff00780c340) once
//! `PMInstantiatePowerDomains` has run (0xfffffff00780b270). Unless
//! gIOPlatformUUIDAndSerialDone (0xfffffff007941790) is set, it gives the
//! expert's provider, the `IOPlatformExpertDevice`, an
//! "IOPlatformSerialNumber" from its "serial-number" (through the expert's
//! `createSystemSerialNumberString`, vtable +0x650; not modelled: reported
//! when read) and calls the device's `generatePlatformUUID`
//! (0xfffffff00780c4a8); once the flag is set it publishes the device's
//! "IOPlatformUUID" as the resource of that name, the same `OSString`
//! (0xfffffff00780c494). On arm64 the UUID is the device's identity in
//! `/chosen` and nothing else ([`platform_uuid`]); the kernel's other call
//! of `generatePlatformUUID`, `IOPlatformExpertDevice::configureDefaults`,
//! publishes no resource, and only this start publishes it
//! (`registerNVRAMController`'s call is x86's). IOUSBDeviceFamily names
//! "IOPlatformUUID" too (0xfffffff00547aee2), beside
//! "IOPlatformSerialNumber", to read them.

use super::iokit::{Node, Prop};

/// The platform expert's class.
pub const PE: &str = "AppleARMPE";

/// arm-io's driver's class.
pub const ARM_IO: &str = "AppleT8011IO";

/// The resources nub's class.
pub const RESOURCES: &str = "IOResources";

/// The class of a nub the platform expert publishes.
pub const PLATFORM_DEVICE: &str = "IOPlatformDevice";

/// The class of a nub arm-io's driver publishes.
pub const ARM_IO_DEVICE: &str = "AppleARMIODevice";

/// The classes of the drivers and nubs here, most derived first (to
/// `IORegistryEntry`; `OSObject` is above it). Each class's `OSMetaClass`
/// and the image that constructs it:
/// - `AppleARMPE` 0xfffffff007addf00 and `AppleARMIO` 0xfffffff007adddf8,
///   both AppleARMPlatform.
/// - `AppleARMIODevice` 0xfffffff007adde20, AppleARMPlatform.
/// - `AppleT8011IO` 0xfffffff007c2b130 and `AppleT801xIO` 0xfffffff007c2b158,
///   both AppleT8011.
/// - The kernel's: `IODTPlatformExpert` 0xfffffff007941798,
///   `IOPlatformExpert` 0xfffffff007941760, `IOPlatformIO`
///   0xfffffff007941850 and `IOPlatformDevice` 0xfffffff007941800.
/// - The kernel's `IOResources` 0xfffffff007940e38, whose superclass is
///   `IOService` 0xfffffff007942cb8 (0xfffffff0077c77cc).
pub fn superclasses(class: &str) -> &'static [&'static str] {
    match class {
        RESOURCES => &[RESOURCES, "IOService", "IORegistryEntry"],
        PE => &[PE, "IODTPlatformExpert", "IOPlatformExpert", "IOService", "IORegistryEntry"],
        ARM_IO => &[ARM_IO, "AppleT801xIO", "AppleARMIO", "IOPlatformIO", "IOService", "IORegistryEntry"],
        PLATFORM_DEVICE => &[PLATFORM_DEVICE, "IOService", "IORegistryEntry"],
        ARM_IO_DEVICE => &[ARM_IO_DEVICE, "IOService", "IORegistryEntry"],
        _ => &[],
    }
}

/// Whether a driver of `class` here registers itself: the platform expert
/// does at the end of its start (0xfffffff00598f964), arm-io's driver after
/// publishing its nubs (0xfffffff006c41910).
pub fn registers(class: &str) -> Option<bool> {
    if matches!(class, PE | ARM_IO) {
        return Some(true);
    }
    super::sep::registry::registers(class)
}

/// A property of entry `i` the platform's drivers changed in a way not
/// modelled: the root's clock-frequency, which `IOPlatformExpert::start`
/// (0xfffffff00780b1dc) replaces in place with the bus clock, the running
/// CPU's bus-frequency, which iBoot fills in the device tree.
pub fn property_override(t: &[Node], i: u32, name: &str) -> Option<String> {
    (i == 0 && name == "clock-frequency" && t.iter().any(|n| n.class == PE)).then(|| "the root's clock-frequency (the bus clock: cpu0's bus-frequency, which iBoot fills)".to_string())
}

/// Whether `class` is one of the drivers here, whose children in the
/// `IOService` plane are not all modelled.
pub fn is_driver(class: &str) -> bool {
    matches!(class, PE | ARM_IO)
}

/// The NUL-separated strings of a device tree property.
fn strings(v: &[u8]) -> impl Iterator<Item = &[u8]> {
    v.split(|&c| c == 0).filter(|s| !s.is_empty())
}

/// `IODTCompareNubName`: whether `name` is one of the entry's `name`,
/// `compatible`, `device_type` or `model` strings.
fn names(n: &Node, name: &str) -> bool {
    ["name", "compatible", "device_type", "model"].iter().any(|key| n.props.iter().any(|(k, v)| k == key && strings(v).any(|s| s == name.as_bytes())))
}

/// Whether `IODTFindMatchingEntries` passes the entry over: one with
/// `AAPL,ignore`, or whose `device_type` is "associated-service".
fn skipped(n: &Node) -> bool {
    n.props.iter().any(|(k, v)| k == "AAPL,ignore" || (k == "device_type" && v.as_slice() == b"associated-service\0"))
}

/// `IODTFindMatchingEntries(parent, kIODTExclusive, excluded)`: the
/// children of `parent` in the device tree, in its order, less those it
/// passes over and those whose names include one of `excluded`.
pub(crate) fn matching(t: &[Node], parent: u32, excluded: &[&str]) -> Vec<u32> {
    t[parent as usize].children.iter().copied().filter(|&c| {
        let n = &t[c as usize];
        !skipped(n) && !excluded.iter().any(|x| names(n, x))
    }).collect()
}

/// The child of `parent` in the device tree that `IODTFindMatchingEntries`
/// gives and whose names include `name`, less the names `excluded`.
pub(crate) fn child(t: &[Node], parent: u32, name: &str, excluded: &[&str]) -> Option<u32> {
    matching(t, parent, excluded).into_iter().find(|&c| names(&t[c as usize], name))
}

/// The platform expert's `excludeList` (0xfffffff00598fee8).
const EXCLUDED: [&str; 4] = ["chosen", "memory", "options", "aliases"];

/// Make device tree entry `entry` a nub of class `class` that driver
/// `driver` published, with the device memory its first matching gives it
/// (`getResources`, before probing: `IODTPlatformExpert::getNubResources`
/// for an `IOPlatformDevice`, AppleARMIODevice's 0xfffffff00598cf80 for
/// one of arm-io's, both `IODTResolveAddressing(nub, "reg", NULL)`, as
/// arm-io's driver keeps no device memory of its own). A range the
/// unfilled template gives as empty (iBoot fills it) is not answered.
pub(crate) fn make_nub(t: &mut [Node], entry: u32, class: &'static str, driver: u32) {
    t[entry as usize].nub = Some((class, driver));
    if t[entry as usize].service_props.iter().any(|(k, _)| k == "IODeviceMemory") {
        return;
    }
    match super::iodt::device_memory(t, entry) {
        Ok(Some(Prop::Array(ranges))) if ranges.iter().all(|r| !is_empty_range(r)) => t[entry as usize].service_props.push(("IODeviceMemory".to_string(), Prop::Array(ranges))),
        _ => {}
    }
}

/// Whether a serialized device memory range has length 0.
fn is_empty_range(r: &Prop) -> bool {
    matches!(r, Prop::Array(a) if a.iter().any(|d| matches!(d, Prop::Dict(e) if e.iter().any(|(k, v)| k == "length" && *v == Prop::Num(0, 64)))))
}

/// A driver's properties from its personality and matching (see the
/// module's documentation): its bundle, class, provider class, the name it
/// matched (a personality by name), its category and score.
pub(crate) fn driver_props(bundle: &str, class: &str, provider: &str, matched: Option<&str>, category: &str, score: u64, mut personality: Vec<(String, Prop)>) -> Vec<(String, Prop)> {
    let sym = |s: &str| Prop::Sym(s.to_string());
    let mut p = vec![
        ("CFBundleIdentifier".to_string(), sym(bundle)),
        ("CFBundleIdentifierKernel".to_string(), sym(bundle)),
        ("IOClass".to_string(), sym(class)),
        ("IOProviderClass".to_string(), sym(provider)),
    ];
    if let Some(m) = matched {
        p.push(("IONameMatched".to_string(), Prop::Str(m.to_string())));
    }
    p.extend([
        ("IOMatchedAtBoot".to_string(), Prop::Bool(true)),
        ("IOMatchCategory".to_string(), sym(category)),
        ("IOProbeScore".to_string(), Prop::Num(score, 32)),
    ]);
    p.append(&mut personality);
    p
}

/// Publish the platform expert and arm-io's driver, and make the device
/// tree's entries the nubs they are; arm-io's driver's entry, when the
/// device tree has arm-io. `t[0]` is the device tree's root, the
/// `IOPlatformExpertDevice`.
///
/// The platform expert's table: its personality's and matching's keys,
/// then "Platform Memory Ranges" (`IOPlatformExpert::start`,
/// 0xfffffff00780b228: an `IORangeAllocator` of one free range, 0 to
/// 0xffffffff, which serializes as its start and end, 64-bit numbers,
/// 0xfffffff007808454; nothing allocates from it on arm64),
/// "IOPlatformMaxBusDelay" (`setPlatform`, 0xfffffff0077c9d10: the live
/// numbers of the CPUs' latency, not modelled) and, once `configure` has
/// published the nubs, "IOFunctionParent00000001" (empty data:
/// AppleARMPlatform's helper 0xfffffff005988104 of the root's phandle).
///
/// `configure`'s `processTopLevel` makes an `IOPlatformDevice` of each of
/// /cpus's children (each also given its "logical-cpu-id" and
/// "logical-cluster-id", 32-bit numbers: on the T8011, with no clusters,
/// its `reg` and 0), then of each of the root's children less the
/// excluded ones. arm-io's driver's start (AppleT801xIO's,
/// 0xfffffff006c41408) sets, after its personality's and matching's keys,
/// IOPowerManagement (AppleARMIO's PMinit) and "IOFunctionParent0000001C"
/// (arm-io's phandle), then publishes an `AppleARMIODevice` of each of
/// arm-io's children (0xfffffff00598c1d4: its delete and exclude lists are
/// empty).
pub fn add(t: &mut Vec<Node>) -> Option<u32> {
    let root = t.first()?;
    if !names(root, "AppleARM") {
        return None;
    }
    let driver = |name: &str, class: &'static str, parent: u32, service_props| Node { name: name.to_string(), props: Vec::new(), class, service_props, parent: Some(parent), children: Vec::new(), kernel_only: false, nub: None, dt: None, table: super::iokit::Table::Drivers, power: None };
    let pe = t.len() as u32;
    // The personality "AppleARMPE": IONameMatch "AppleARM", IOProbeScore
    // 1000 (a 64-bit number, which the probe's 32-bit score replaces).
    let mut props = driver_props("com.apple.driver.AppleARMPlatform", PE, "IOPlatformExpertDevice", Some("AppleARM"), "IODefaultMatchCategory", 1000, vec![("IONameMatch".to_string(), Prop::Str("AppleARM".to_string()))]);
    props.push(("Platform Memory Ranges".to_string(), Prop::Array(vec![Prop::Num(0, 64), Prop::Num(0xffff_ffff, 64)])));
    props.push((function_parent(t, 0), Prop::Data(Vec::new())));
    t.push(driver(PE, PE, 0, props));
    // publishPlatformUUIDAndSerial's generatePlatformUUID, on the expert's
    // provider, before `configure` publishes the nubs.
    if let Some(uuid) = platform_uuid(t) {
        t[0].service_props.push((UUID_KEY.to_string(), Prop::Str(uuid)));
    }
    if let Some(cpus) = child(t, 0, "cpus", &[]) {
        for c in matching(t, cpus, &[]) {
            make_nub(t, c, PLATFORM_DEVICE, pe);
            let reg = t[c as usize].props.iter().find(|(k, _)| k == "reg").and_then(|(_, v)| v.get(..4)).map_or(0, |v| u32::from_le_bytes(v.try_into().unwrap()));
            let n = &mut t[c as usize];
            n.service_props.push(("logical-cpu-id".to_string(), Prop::Num(u64::from(reg), 32)));
            n.service_props.push(("logical-cluster-id".to_string(), Prop::Num(0, 32)));
        }
    }
    for c in matching(t, 0, &EXCLUDED) {
        make_nub(t, c, PLATFORM_DEVICE, pe);
    }
    let arm_io = child(t, 0, "arm-io,t8011", &EXCLUDED)?;
    let io = t.len() as u32;
    // The personality "AppleT8011IO": IONameMatch "arm-io,t8011",
    // IOPlatformActiveAction 80000.
    let mut props = driver_props("com.apple.driver.AppleT8011", ARM_IO, PLATFORM_DEVICE, Some("arm-io,t8011"), "IODefaultMatchCategory", 0, vec![
        ("IONameMatch".to_string(), Prop::Str("arm-io,t8011".to_string())),
        ("IOPlatformActiveAction".to_string(), Prop::Num(80000, 64)),
    ]);
    // AppleARMIO's start (0xfffffff00598c0b4): PMinit (0xfffffff00598c0f0)
    // and temporaryPowerClampOn (0xfffffff00598c100), before what
    // AppleT801xIO's start sets; it never joins the power plane.
    props.push((super::iopower::KEY.to_string(), super::iopower::clamped_without_driver()));
    props.push((function_parent(t, arm_io), Prop::Data(Vec::new())));
    t.push(driver(ARM_IO, ARM_IO, arm_io, props));
    for c in matching(t, arm_io, &[]) {
        make_nub(t, c, ARM_IO_DEVICE, io);
    }
    Some(io)
}

/// The key AppleARMPlatform's helper (0xfffffff005988104) sets on a driver
/// of device tree entry `entry`: "IOFunctionParent" and the entry's
/// `AAPL,phandle` as `"%08X"`.
pub(crate) fn function_parent(t: &[Node], entry: u32) -> String {
    let ph = t[entry as usize].props.iter().find(|(k, _)| k == "AAPL,phandle").and_then(|(_, v)| v.get(..4)).map_or(0, |v| u32::from_le_bytes(v.try_into().unwrap()));
    format!("IOFunctionParent{ph:08X}")
}

/// The `AppleARMIODevice` nub arm-io's driver `io` publishes for its
/// device tree child whose names include `name`, when there is one.
pub fn arm_io_nub(t: &mut [Node], io: u32, name: &str) -> Option<u32> {
    let arm_io = t[io as usize].parent?;
    let nub = child(t, arm_io, name, &[])?;
    make_nub(t, nub, ARM_IO_DEVICE, io);
    Some(nub)
}

/// Publish the resources nub, whose provider is the registry's root (see
/// the module's documentation): its index. "IOPlatformUUID" is published
/// with the platform expert device's value when its start made one.
pub fn add_resources(t: &mut Vec<Node>) -> u32 {
    let published = |key: &str| (key.to_string(), Prop::Sym("IOService".to_string()));
    let mut props = vec![published("IOKit")];
    if let Some(uuid) = t.first().and_then(|r| r.service_props.iter().find(|(k, _)| k == UUID_KEY)) {
        props.push(uuid.clone());
    }
    props.push(published("IOBSD"));
    let at = t.len() as u32;
    t.push(Node { name: RESOURCES.to_string(), props: Vec::new(), class: RESOURCES, service_props: props, parent: None, children: Vec::new(), kernel_only: false, nub: None, dt: None, table: super::iokit::Table::Drivers, power: None });
    at
}

/// The platform's UUID's key (`kIOPlatformUUIDKey`), on the platform expert
/// device and as a resource.
pub const UUID_KEY: &str = "IOPlatformUUID";

/// `generatePlatformUUID`'s name space for the arm64 UUID (its `space`,
/// 0xfffffff007028bd8 in the kernel's `__TEXT,__const`).
pub const UUID_NAMESPACE: [u8; 16] = [0xA6, 0xDD, 0x4C, 0xCB, 0xB5, 0xE8, 0x4A, 0xF5, 0xAC, 0xDD, 0xB6, 0xDC, 0x6A, 0x05, 0x42, 0xB8];

/// `IOPlatformExpertDevice::generatePlatformUUID` on arm64
/// (0xfffffff00780c4a8; xnu-10063 IOPlatformExpert.cpp:2205): the device
/// tree's `/chosen` `unique-chip-id`, which must be `OSData` of 8 bytes
/// (the ECID), and `chip-id`, of 4; the SHA-1 of the name space
/// [`UUID_NAMESPACE`], then those two as the device tree holds them; of
/// the digest's first 16 bytes, byte 6's high nibble made 5 (the version)
/// and byte 8's top two bits 10 (the variant); written as
/// "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X"
/// (0xfffffff00780c6e0, upper case). None when either property is missing
/// or of another length: the device then has no "IOPlatformUUID" and the
/// resource is never published.
pub fn platform_uuid(t: &[Node]) -> Option<String> {
    use sha1::Digest;
    let ecid = super::iokit::dt_prop(t, "IODeviceTree:/chosen", "unique-chip-id").filter(|v| v.len() == 8)?;
    let chip = super::iokit::dt_prop(t, "IODeviceTree:/chosen", "chip-id").filter(|v| v.len() == 4)?;
    let mut h = sha1::Sha1::new();
    h.update(UUID_NAMESPACE);
    h.update(ecid);
    h.update(chip);
    let mut d: [u8; 20] = h.finalize().into();
    d[6] = (d[6] & 0x0f) | 0x50;
    d[8] = (d[8] & 0x3f) | 0x80;
    Some(uuid_unparse_upper(d[..16].try_into().unwrap()))
}

/// A UUID's 16 bytes as "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX", upper case
/// (libkern's and libc's `uuid_unparse_upper`).
pub fn uuid_unparse_upper(u: &[u8; 16]) -> String {
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02X}")).collect::<String>();
    format!("{}-{}-{}-{}-{}", hex(&u[0..4]), hex(&u[4..6]), hex(&u[6..8]), hex(&u[8..10]), hex(&u[10..16]))
}

/// libkern's `uuid_parse` (libkern/uuid/uuid.c:142) of a UUID in the
/// canonical form [`uuid_unparse_upper`] writes, the only form the platform
/// expert device's "IOPlatformUUID" takes: 36 characters, hyphens at 8,
/// 13, 18 and 23 and hexadecimal digit pairs of either case elsewhere.
/// None for anything else, which its `sscanf` may read otherwise (not
/// modelled).
pub fn uuid_parse(s: &str) -> Option<[u8; 16]> {
    let b = s.as_bytes();
    if b.len() != 36 || [8, 13, 18, 23].iter().any(|&i| b[i] != b'-') {
        return None;
    }
    let digits: Vec<u8> = b.iter().enumerate().filter(|(i, _)| ![8, 13, 18, 23].contains(i)).map(|(_, &c)| c).collect();
    let mut out = [0u8; 16];
    for (i, pair) in digits.chunks(2).enumerate() {
        if !pair.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}
