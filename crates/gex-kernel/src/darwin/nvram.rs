//! The NVRAM variables: `IODTNVRAM` (`iokit/Kernel/IONVRAM.cpp`) over the
//! CHRP image (`IONVRAMCHRPHandler.cpp`), xnu-10063.141.1 as the 21H461
//! kernel has them, and the controller that keeps the image,
//! `AppleEmbeddedNVMeNVRAM` (IONVMeFamily).
//!
//! # Where the image is
//!
//! The J120's NVRAM is namespace 5 of its NVMe storage, two 4 KiB blocks
//! (the s3e node's `namespaces`, type 5, "NVRAM", 8 KiB at most in
//! IONVMeFamily's table). iBoot reads it and hands the kernel its bank in
//! `/chosen`: `nvram-proxy-data` (the IPSW's device tree has an 8192-byte
//! placeholder for it), `nvram-bank-size`, `nvram-bank-count` and
//! `nvram-current-bank`. The release kernel leaves `nvram-proxy-data` in
//! `/chosen` after reading it (`initImageFormat`, 0xfffffff007814b5c, has
//! no `removeProperty`).
//!
//! `IODTNVRAM::start` takes the image as the format handler the image's
//! header selects: `NVV3` (`IONVRAMV3Handler`, which also wants
//! `/chosen/nvram-raw`, a property the J120's device tree has no
//! placeholder for) or CHRP. The CHRP handler wants the bank's length to
//! be `nvram-bank-size` and keeps a copy of it.
//!
//! `AppleEmbeddedNVMeNVRAM` (vtable 0xfffffff006fa5e28) is the
//! `IONVRAMController`: its start (0xfffffff006a757fc) reads the namespace
//! (`nvram-bank-size` bytes, `GetNVRAMSize` 0xfffffff006a75680) into a
//! shadow buffer and registers, which hands the controller to the format
//! handler (`registerNVRAMController`, then `setController`'s
//! `reloadInternal`) and publishes the IONVRAM resource. Its `read` and
//! `write` (0xfffffff006a75cc8, 0xfffffff006a75d60) copy from and to the
//! shadow (kIOReturnBadArgument past it, kIOReturnCannotLock with
//! preemption off); it has no `select` or `eraseBank`
//! (kIOReturnUnsupported, `IONVRAMController`'s); its `sync`
//! (0xfffffff006a75df8) writes the whole shadow to the namespace from
//! block 0, when the controller found namespaces in its NAND (its +0x416,
//! "Found %d namespaces in current NAND"). So the namespace is written
//! exactly when the CHRP handler's `serializeVariables` writes its image
//! and syncs the controller, which [`Nvram::sync`] models: the medium gets
//! the bank then.
//!
//! # What the kernel does
//!
//! Its tables are the binary's: the variable types (0xfffffff00716eb50),
//! the permissions (0xfffffff00716e7d0, 24-byte entries), the
//! variable-specific entitlements (0xfffffff00716e550) and the system
//! region's allow list (0xfffffff00716eaa0), each as xnu-10063 has them.
//! The release code differs from the source where checked only in what
//! `initImageFormat` does not remove; `gInternalBuild` is macOS's
//! (`XNU_TARGET_OS_OSX`), false here, and the empty-data removal of
//! `setPropertyWithGUIDAndName` is macOS's too.
//!
//! Every variable lives in `_varDict` under its canonical key, the GUID
//! (`uuid_unparse`, capitals) and the name joined by a colon; the CHRP
//! handler writes the common region and, when the image has one, the
//! system region. Of the handler's quirks the model keeps: the generation
//! the header gets is two past the one the handler had (`++_generation`,
//! then `nvram_set_apple_header`'s own increment); every variable set
//! counts its `name=value\0` against its region's size; the first sync
//! after boot always writes (unserializeVariables leaves `_newData` set).

use super::osserialize::{Graph, Id, Obj};
use std::sync::Arc;

/// IOReturn values the variables' calls give.
pub mod ret {
    pub const SUCCESS: i32 = 0;
    pub const ERROR: i32 = 0xe00002bc_u32 as i32;
    pub const NO_MEMORY: i32 = 0xe00002bd_u32 as i32;
    pub const NOT_PRIVILEGED: i32 = 0xe00002c1_u32 as i32;
    pub const BAD_ARGUMENT: i32 = 0xe00002c2_u32 as i32;
    pub const UNSUPPORTED: i32 = 0xe00002c7_u32 as i32;
    pub const CANNOT_LOCK: i32 = 0xe00002cc_u32 as i32;
    pub const NOT_READY: i32 = 0xe00002d8_u32 as i32;
    pub const NO_SPACE: i32 = 0xe00002db_u32 as i32;
    pub const NOT_FOUND: i32 = 0xe00002f0_u32 as i32;
}

/// The variable namespaces.
pub mod guid {
    /// `gAppleSystemVariableGuid`, the system region's.
    pub const SYSTEM: [u8; 16] = [0x40, 0xA0, 0xDD, 0xD2, 0x77, 0xF8, 0x43, 0x92, 0xB4, 0xA3, 0x1E, 0x73, 0x04, 0x20, 0x65, 0x16];
    /// `gAppleNVRAMGuid` (APPLE_VENDOR_OS_VARIABLE_GUID), the common
    /// region's, which a name without a GUID is in.
    pub const COMMON: [u8; 16] = [0x7C, 0x43, 0x61, 0x10, 0xAB, 0x2A, 0x4B, 0xBB, 0xA8, 0x80, 0xFE, 0x41, 0x99, 0x5C, 0x9F, 0x82];
    /// `gAppleWifiGuid`.
    pub const WIFI: [u8; 16] = [0x36, 0xC2, 0x8A, 0xB5, 0x65, 0x66, 0x4C, 0x50, 0x9E, 0xBD, 0xCB, 0xB9, 0x20, 0xF8, 0x38, 0x43];
}

/// The special keys (`IOKitKeys.h`, `IOKitKeysPrivate.h`).
pub mod key {
    pub const DELETE: &[u8] = b"IONVRAM-DELETE-PROPERTY";
    pub const DELETE_WRET: &[u8] = b"IONVRAM-DELETEWRET-PROPERTY";
    pub const SYNC_NOW: &[u8] = b"IONVRAM-SYNCNOW-PROPERTY";
    pub const FORCE_SYNC_NOW: &[u8] = b"IONVRAM-FORCESYNCNOW-PROPERTY";
    pub const BOOT_ARGS: &[u8] = b"boot-args";
}

/// `IONVRAMOperation`.
pub mod op {
    pub const INIT: u8 = 0;
    pub const READ: u8 = 1;
    pub const WRITE: u8 = 2;
    pub const DELETE: u8 = 3;
    pub const OBLITERATE: u8 = 4;
    pub const RESET: u8 = 5;
}

/// `IONVRAMVariableType`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VarType {
    Boolean,
    Number,
    String,
    Data,
}

/// `gVariableTypes` (0xfffffff00716eb50); any other name is data.
const VARIABLE_TYPES: [(&str, VarType); 54] = {
    use VarType::{Boolean as B, Number as N, String as S};
    [
        ("auto-boot?", B),
        ("boot-args", S),
        ("boot-command", S),
        ("boot-device", S),
        ("boot-file", S),
        ("boot-screen", S),
        ("boot-script", S),
        ("console-screen", S),
        ("default-client-ip", S),
        ("default-gateway-ip", S),
        ("default-mac-address?", B),
        ("default-router-ip", S),
        ("default-server-ip", S),
        ("default-subnet-mask", S),
        ("diag-device", S),
        ("diag-file", S),
        ("diag-switch?", B),
        ("fcode-debug?", B),
        ("input-device", S),
        ("input-device-1", S),
        ("little-endian?", B),
        ("ldm", B),
        ("load-base", N),
        ("mouse-device", S),
        ("nvramrc", S),
        ("oem-banner", S),
        ("oem-banner?", B),
        ("oem-logo", S),
        ("oem-logo?", B),
        ("output-device", S),
        ("output-device-1", S),
        ("pci-probe-list", N),
        ("pci-probe-mask", N),
        ("real-base", N),
        ("real-mode?", B),
        ("real-size", N),
        ("screen-#columns", N),
        ("screen-#rows", N),
        ("security-mode", S),
        ("selftest-#megs", N),
        ("use-generic?", B),
        ("use-nvramrc?", B),
        ("virt-base", N),
        ("virt-size", N),
        ("test-bool", B),
        ("test-num", N),
        ("test-str", S),
        ("test-data", VarType::Data),
        ("acc-cm-override-charger-count", N),
        ("acc-cm-override-count", N),
        ("acc-mb-ld-lifetime", N),
        ("com.apple.System.boot-nonce", S),
        ("darkboot", B),
        ("enter-tdm-mode", B),
    ]
};

/// `getVariableType`.
pub fn variable_type(name: &[u8]) -> VarType {
    VARIABLE_TYPES.iter().find(|(n, _)| n.as_bytes() == name).map_or(VarType::Data, |&(_, t)| t)
}

/// `VariablePermission`'s bits.
pub mod perm {
    pub const USER_WRITE: u64 = 1 << 0;
    pub const ROOT_REQUIRED: u64 = 1 << 1;
    pub const KERNEL_ONLY: u64 = 1 << 2;
    pub const RESET_NVRAM_ONLY_DELETE: u64 = 1 << 3;
    pub const NEVER_ALLOWED_TO_DELETE: u64 = 1 << 4;
    pub const SYSTEM_READ_HIDDEN: u64 = 1 << 5;
    pub const FULL_ACCESS: u64 = 1 << 6;
    pub const INTERNAL_ONLY: u64 = 1 << 7;
}

/// `gVariablePermissions` (0xfffffff00716e7d0); any other name has full
/// access.
const PERMISSIONS: [(&str, u64); 29] = {
    use perm::*;
    [
        ("aapl,pci", ROOT_REQUIRED),
        ("battery-health", ROOT_REQUIRED | NEVER_ALLOWED_TO_DELETE),
        ("boot-image", USER_WRITE),
        ("com.apple.System.fp-state", KERNEL_ONLY),
        ("fm-account-masked", ROOT_REQUIRED | NEVER_ALLOWED_TO_DELETE),
        ("fm-activation-locked", ROOT_REQUIRED | NEVER_ALLOWED_TO_DELETE),
        ("fm-spkeys", ROOT_REQUIRED | NEVER_ALLOWED_TO_DELETE),
        ("fm-spstatus", ROOT_REQUIRED | NEVER_ALLOWED_TO_DELETE),
        ("policy-nonce-digests", RESET_NVRAM_ONLY_DELETE),
        ("recoveryos-passcode-blob", SYSTEM_READ_HIDDEN),
        ("security-password", ROOT_REQUIRED),
        ("system-passcode-lock-blob", SYSTEM_READ_HIDDEN),
        ("acc-cm-override-charger-count", KERNEL_ONLY),
        ("acc-cm-override-count", KERNEL_ONLY),
        ("acc-mb-ld-lifetime", KERNEL_ONLY),
        ("backlight-level", USER_WRITE),
        ("backlight-nits", USER_WRITE),
        ("ldm", KERNEL_ONLY),
        ("com.apple.System.boot-nonce", KERNEL_ONLY),
        ("com.apple.System.sep.art", KERNEL_ONLY),
        ("darkboot", USER_WRITE),
        ("nonce-seeds", KERNEL_ONLY),
        ("testSysReadHidden", SYSTEM_READ_HIDDEN),
        ("testKernelOnly", KERNEL_ONLY),
        ("testResetOnlyDel", RESET_NVRAM_ONLY_DELETE),
        ("testNeverDel", NEVER_ALLOWED_TO_DELETE),
        ("testUserWrite", USER_WRITE),
        ("testRootReq", ROOT_REQUIRED),
        ("reclaim-int", INTERNAL_ONLY),
    ]
};

/// `getVariablePermission`.
pub fn variable_permission(name: &[u8]) -> u64 {
    PERMISSIONS.iter().find(|(n, _)| n.as_bytes() == name).map_or(perm::FULL_ACCESS, |&(_, p)| p)
}

/// `gNVRAMSystemList` (0xfffffff00716eaa0, `IONVRAMSystemVariableList`):
/// the variables kept in the system region when there is one.
pub const SYSTEM_LIST: [&str; 21] = [
    "allow-root-hash-mismatch",
    "auto-boot",
    "auto-boot-halt-stage",
    "base-system-path",
    "boot-args",
    "boot-command",
    "boot-image",
    "bootdelay",
    "com.apple.System.boot-nonce",
    "darkboot",
    "emu",
    "one-time-boot-command",
    "policy-nonce-digests",
    "prevent-restores",
    "prev-lang:kbd",
    "root-live-fs",
    "sep-debug-args",
    "StartupMute",
    "SystemAudioVolume",
    "SystemAudioVolumeExtension",
    "SystemAudioVolumeSaved",
];

/// `variableInAllowList` (the list for a build that is not internal).
pub fn in_allow_list(name: &[u8]) -> bool {
    SYSTEM_LIST.iter().any(|n| n.as_bytes() == name)
}

/// `ENT_*`: the operations an entitlement entry checks.
const ENT_MOD_RST: u8 = (1 << op::WRITE) | (1 << op::DELETE) | (1 << op::OBLITERATE) | (1 << op::RESET);
const ENT_MOD: u8 = (1 << op::WRITE) | (1 << op::DELETE);
const ENT_RST: u8 = (1 << op::OBLITERATE) | (1 << op::RESET);
const ENT_RD: u8 = 1 << op::READ;
const ENT_DEL: u8 = 1 << op::DELETE;

/// `gVariableEntitlements` (0xfffffff00716e550): operations, namespace,
/// name, entitlement.
const ENTITLEMENTS: [(u8, [u8; 16], &str, &str); 19] = {
    use guid::{COMMON, SYSTEM, WIFI};
    const WIFI_PSKS: &str = "com.apple.private.security.nvram.wifi-psks";
    const BLUETOOTH: &str = "com.apple.private.iokit.nvram-bluetooth";
    [
        (ENT_MOD_RST, COMMON, "ownership-warning", "com.apple.private.iokit.ddl-write"),
        (ENT_MOD, SYSTEM, "BluetoothInfo", BLUETOOTH),
        (ENT_MOD, SYSTEM, "BluetoothUHEDevices", BLUETOOTH),
        (ENT_MOD, COMMON, "bluetoothExternalDongleFailed", BLUETOOTH),
        (ENT_MOD, COMMON, "bluetoothInternalControllerInfo", BLUETOOTH),
        (ENT_RD, SYSTEM, "current-network", WIFI_PSKS),
        (ENT_RD, WIFI, "current-network", WIFI_PSKS),
        (ENT_RD, SYSTEM, "preferred-networks", WIFI_PSKS),
        (ENT_RD, WIFI, "preferred-networks", WIFI_PSKS),
        (ENT_RD, SYSTEM, "preferred-count", WIFI_PSKS),
        (ENT_RD, WIFI, "preferred-count", WIFI_PSKS),
        (ENT_MOD_RST, COMMON, "testEntModRst", "com.apple.private.iokit.testEntModRst"),
        (ENT_MOD_RST, SYSTEM, "testEntModRstSys", "com.apple.private.iokit.testEntModRst"),
        (ENT_RST, COMMON, "testEntRst", "com.apple.private.iokit.testEntRst"),
        (ENT_RST, SYSTEM, "testEntRstSys", "com.apple.private.iokit.testEntRst"),
        (ENT_RD, COMMON, "testEntRd", "com.apple.private.iokit.testEntRd"),
        (ENT_RD, SYSTEM, "testEntRdSys", "com.apple.private.iokit.testEntRd"),
        (ENT_DEL, COMMON, "testEntDel", "com.apple.private.iokit.testEntDel"),
        (ENT_DEL, SYSTEM, "testEntDelSys", "com.apple.private.iokit.testEntDel"),
    ]
};

/// The entitlements `verifyPermission` asks for (`IOKitKeys.h`,
/// `IOKitKeysPrivate.h`).
pub mod ent {
    pub const WRITE_ACCESS: &str = "com.apple.private.iokit.nvram-write-access";
    pub const READ_ACCESS: &str = "com.apple.private.iokit.nvram-read-access";
    pub const SYSTEM_ALLOW: &str = "com.apple.private.iokit.system-nvram-allow";
    pub const SYSTEM_INTERNAL_ALLOW: &str = "com.apple.private.iokit.system-nvram-internal-allow";
    pub const SYSTEM_HIDDEN_ALLOW: &str = "com.apple.private.iokit.system-nvram-hidden-allow";
}

/// `BOOT_LINE_LENGTH` (arm64's `boot.h`, the binary's `cmp w24, #0x400`).
pub const BOOT_LINE_LENGTH: usize = 1024;

/// The task a call runs for: the kernel's own (`current_task() ==
/// kernel_task`), whether it has `clientHasPrivilege(task, "root")` (its
/// security token's uid, the effective one, is 0), and its boolean-true
/// entitlements (`IOCurrentTaskHasEntitlement`, always false for the
/// kernel's task).
pub trait Caller {
    fn kernel(&self) -> bool;
    fn admin(&self) -> bool;
    fn entitled(&self, entitlement: &str) -> bool;
}

/// The kernel's own task.
pub struct Kernel;

impl Caller for Kernel {
    fn kernel(&self) -> bool {
        true
    }
    fn admin(&self) -> bool {
        true
    }
    fn entitled(&self, _: &str) -> bool {
        false
    }
}

/// A variable's value: the `OSObject` `_varDict` holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Bool(bool),
    /// An `OSNumber`: its size in bits (63 or 31: a double's bits) and its
    /// value.
    Number { bits: u32, value: u64 },
    String(Vec<u8>),
    /// An `OSSymbol` given as a string variable's value.
    Symbol(Vec<u8>),
    Data(Vec<u8>),
}

impl Value {
    /// `OSNumber::unsigned32BitValue`.
    fn unsigned32(bits: u32, value: u64) -> u32 {
        if bits == 63 || bits == 31 {
            f64::from_bits(value) as u32
        } else {
            value as u32
        }
    }
}

/// An object a caller gives a variable: one of `OSUnserializeXML`'s, or a
/// kernel caller's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Given {
    Value(Value),
    /// A collection (dictionary, array, set), which no variable takes.
    Collection,
}

impl Given {
    /// Object `id` of graph `g`.
    pub fn of(g: &Graph, id: Id) -> Given {
        match g.get(id) {
            Obj::Bool(b) => Given::Value(Value::Bool(*b)),
            Obj::Number { size, value } => Given::Value(Value::Number { bits: *size, value: *value }),
            Obj::String(s) => Given::Value(Value::String(s.clone())),
            Obj::Symbol(s) => Given::Value(Value::Symbol(s.clone())),
            Obj::Data(d) => Given::Value(Value::Data(d.clone())),
            Obj::Dict(_) | Obj::Array(_) | Obj::Set(_) => Given::Collection,
        }
    }

    /// `OSDynamicCast(OSString, ...)`'s C string (an `OSSymbol` is an
    /// `OSString`).
    fn string(&self) -> Option<&[u8]> {
        match self {
            Given::Value(Value::String(s) | Value::Symbol(s)) => Some(s),
            _ => None,
        }
    }
}

/// A C string's characters up to its first NUL (`getCStringNoCopy`).
fn cstr(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// libkern's `uuid_parse` of the 37-byte `temp` (36 characters and a
/// NUL): the kernel's `sscanf` with `"%2hhx%2hhx%2hhx%2hhx-%2hhx%2hhx-
/// %2hhx%2hhx-%2hhx%2hhx-%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%n"`
/// (`libkern/stdio/scanf.c`): each conversion skips white space, takes a
/// sign and a `0x` within its two characters, and is converted by
/// `strtouq`; the parse succeeds when `%n` is 36 and the NUL follows.
fn uuid_parse(temp: &[u8; 37]) -> Option<[u8; 16]> {
    // scanf.c's isspace.
    let space = |c: u8| matches!(c, b' ' | b'\t' | b'\n');
    let fmt: &[u8] = b"xxxx-xx-xx-xx-xxxxxx";
    let input = &temp[..36];
    let mut at = 0usize;
    let mut out = [0u8; 16];
    let mut field = 0;
    for &f in fmt {
        if f == b'-' {
            // A literal: it must be next.
            if input.get(at) != Some(&b'-') {
                return None;
            }
            at += 1;
            continue;
        }
        // Leading white space; running out of input is an input failure.
        while at < input.len() && space(input[at]) {
            at += 1;
        }
        if at >= input.len() {
            return None;
        }
        // CT_INT, base 16, width 2: SIGNOK | NDIGITS | NZDIGITS | PFXOK.
        let (mut signok, mut ndigits, mut nzdigits, mut pfxok) = (true, true, true, true);
        let mut buf: Vec<u8> = Vec::new();
        for _ in 0..2 {
            let Some(&c) = input.get(at) else { break };
            let ok = match c {
                b'0' => {
                    if nzdigits {
                        signok = false;
                        nzdigits = false;
                        ndigits = false;
                    } else {
                        signok = false;
                        pfxok = false;
                        ndigits = false;
                    }
                    true
                }
                b'1'..=b'9' | b'A'..=b'F' | b'a'..=b'f' => {
                    signok = false;
                    pfxok = false;
                    ndigits = false;
                    true
                }
                b'+' | b'-' if signok => {
                    signok = false;
                    true
                }
                b'x' | b'X' if pfxok && buf.len() == 1 => {
                    pfxok = false;
                    true
                }
                _ => false,
            };
            if !ok {
                break;
            }
            buf.push(c);
            at += 1;
        }
        if ndigits {
            return None;
        }
        if matches!(buf.last(), Some(b'x' | b'X')) {
            buf.pop();
            at -= 1;
        }
        out[field] = strtouq16(&buf) as u8;
        field += 1;
    }
    // %n: the characters read, then uuid_parse's own check.
    (at == 36 && temp[36] == 0).then_some(out)
}

/// `strtouq(buf, NULL, 16)` of the digits a conversion collected (at most
/// a sign and two characters).
fn strtouq16(buf: &[u8]) -> u64 {
    let (neg, digits) = match buf.first() {
        Some(b'-') => (true, &buf[1..]),
        Some(b'+') => (false, &buf[1..]),
        _ => (false, buf),
    };
    let mut acc: u64 = 0;
    for &c in digits {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => break,
        };
        acc = acc * 16 + u64::from(d);
    }
    if neg {
        acc.wrapping_neg()
    } else {
        acc
    }
}

/// `parseVariableName`: a key of the form `GUID:name` gives that GUID and
/// the name after the colon; any other key is a name in the common
/// namespace. Whether a GUID was there.
pub fn parse_name(key: &[u8]) -> ([u8; 16], &[u8], bool) {
    if key.len() > 37 {
        let mut temp = [0u8; 37];
        temp[..36].copy_from_slice(&key[..36]);
        if let Some(g) = uuid_parse(&temp) {
            if key[36] == b':' {
                return (g, &key[37..], true);
            }
        }
    }
    (guid::COMMON, key, false)
}

/// `uuid_unparse` (capitals).
pub fn unparse(g: &[u8; 16]) -> String {
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        g[0], g[1], g[2], g[3], g[4], g[5], g[6], g[7], g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]
    )
}

/// `keyWithGuidAndCString`: the canonical key.
pub fn canonical(g: &[u8; 16], name: &[u8]) -> Vec<u8> {
    let mut k = unparse(g).into_bytes();
    k.push(b':');
    k.extend_from_slice(cstr(name));
    k
}

/// `translateGUID`: the namespace a variable is kept in.
fn translate(g: &[u8; 16], name: &[u8], system_active: bool) -> [u8; 16] {
    let system = *g == guid::SYSTEM;
    if system_active {
        if in_allow_list(name) || system {
            guid::SYSTEM
        } else {
            *g
        }
    } else if system {
        guid::COMMON
    } else {
        *g
    }
}

/// `getPartitionTypeForGUID`: `kIONVRAMPartitionSystem` (1) or
/// `kIONVRAMPartitionCommon` (2).
fn partition_type(g: &[u8; 16]) -> u8 {
    if *g == guid::SYSTEM {
        1
    } else {
        2
    }
}

/// `skipKey`: the registry's own keys, which IODTNVRAM never answers.
pub fn skip_key(name: &[u8]) -> bool {
    const KEYS: [&[u8]; 11] = [
        b"IORegistryEntryAllowableSetProperties",
        b"IORegistryEntryDefaultLockingSetProperties",
        b"IOClassNameOverride",
        b"BSD Name",
        b"BSD Names",
        b"BSD Major",
        b"BSD Minor",
        b"BSD Unit",
        b"IOUserServiceProperties",
        b"exclave-assigned",
        b"IOMatchCategory",
    ];
    KEYS.contains(&name)
}

/// `verifyPermission(op, varGuid, varName, systemActive)`.
pub fn verify_permission(c: &dyn Caller, op: u8, g: &[u8; 16], name: &[u8], system_active: bool) -> bool {
    // verifyVarEntitlement, with the translated GUID.
    let translated = translate(g, name, system_active);
    let mut var_entitled = false;
    if let Some(&(check, _, _, entitlement)) = ENTITLEMENTS.iter().find(|(_, eg, n, _)| n.as_bytes() == name && *eg == translated) {
        if check & (1 << op) != 0 {
            var_entitled = true;
            if !c.entitled(entitlement) {
                return false;
            }
        }
    }
    let p = variable_permission(name);
    let kernel = c.kernel();
    if p & perm::KERNEL_ONLY != 0 || name.starts_with(b"krn.") {
        return kernel;
    }
    // gInternalBuild is false.
    if p & perm::INTERNAL_ONLY != 0 {
        return false;
    }
    let allow = in_allow_list(name);
    let system = *g == guid::SYSTEM;
    let admin = c.admin();
    let write_entitled = c.entitled(ent::WRITE_ACCESS);
    let read_entitled = c.entitled(ent::READ_ACCESS);
    let system_entitled = c.entitled(ent::SYSTEM_ALLOW);
    let _system_internal = c.entitled(ent::SYSTEM_INTERNAL_ALLOW);
    let hidden_allow = c.entitled(ent::SYSTEM_HIDDEN_ALLOW);
    let system_allow = system_entitled || kernel;
    let may_modify = kernel || p & perm::USER_WRITE != 0 || admin || write_entitled || var_entitled;
    // A system-region change needs the allow list, the variable's own
    // entitlement or the system one.
    let system_ok = !system || allow || var_entitled || system_allow;
    match op {
        op::READ => {
            if system && p & perm::SYSTEM_READ_HIDDEN != 0 {
                hidden_allow
            } else {
                kernel || admin || read_entitled || p & perm::FULL_ACCESS != 0 || var_entitled
            }
        }
        op::WRITE => may_modify && system_ok,
        op::DELETE | op::OBLITERATE | op::RESET => {
            if p & perm::NEVER_ALLOWED_TO_DELETE != 0 || (op == op::OBLITERATE || op == op::DELETE) && p & perm::RESET_NVRAM_ONLY_DELETE != 0 {
                return false;
            }
            may_modify && system_ok
        }
        _ => false,
    }
}

/// `verifyWriteSizeLimit`: an allow-listed variable's value is at most 768
/// bytes, a breadcrumbs one's 1024.
fn write_size_ok(name: &[u8], size: usize) -> bool {
    if !in_allow_list(name) {
        return true;
    }
    if name.windows(11).any(|w| w == b"breadcrumbs") {
        size <= 1024
    } else {
        size <= 768
    }
}

/// The kernel's `strtol(s, NULL, 0)` (`IOStringFuncs.c`): white space, a
/// sign, a `0x` or `0b` prefix or a leading `0` for octal, clamped to
/// `LONG_MIN`/`LONG_MAX` on overflow. `s` ends at its NUL.
fn strtol0(s: &[u8]) -> i64 {
    let at = |i: usize| s.get(i).copied().unwrap_or(0);
    let space = |c: u8| matches!(c, b' ' | b'\t' | b'\n');
    let mut i = 0;
    let mut c = at(i);
    i += 1;
    while space(c) {
        c = at(i);
        i += 1;
    }
    let mut neg = false;
    if c == b'-' {
        neg = true;
        c = at(i);
        i += 1;
    } else if c == b'+' {
        c = at(i);
        i += 1;
    }
    let mut base: u64 = 0;
    if c == b'0' && matches!(at(i), b'x' | b'X') {
        c = at(i + 1);
        i += 2;
        base = 16;
    } else if c == b'0' && matches!(at(i), b'b' | b'B') {
        c = at(i + 1);
        i += 2;
        base = 2;
    }
    if base == 0 {
        base = if c == b'0' { 8 } else { 10 };
    }
    let cutoff_full: u64 = if neg { 1u64 << 63 } else { i64::MAX as u64 };
    let cutlim = cutoff_full % base;
    let cutoff = cutoff_full / base;
    let (mut acc, mut any) = (0u64, 0i32);
    loop {
        let d = match c {
            b'0'..=b'9' => u64::from(c - b'0'),
            b'A'..=b'Z' => u64::from(c - b'A' + 10),
            b'a'..=b'z' => u64::from(c - b'a' + 10),
            _ => break,
        };
        if d >= base {
            break;
        }
        if any < 0 || acc > cutoff || (acc == cutoff && d > cutlim) {
            any = -1;
        } else {
            any = 1;
            acc = acc * base + d;
        }
        c = at(i);
        i += 1;
    }
    if any < 0 {
        if neg {
            i64::MIN
        } else {
            i64::MAX
        }
    } else if neg {
        (acc as i64).wrapping_neg()
    } else {
        acc as i64
    }
}

/// The CHRP image's layout and its encodings.
pub mod chrp {
    /// `NVRAM_CHRP_LENGTH_BLOCK_SIZE`.
    pub const BLOCK: usize = 0x10;
    /// `sizeof(chrp_nvram_header_t)`.
    pub const HEADER: usize = 16;
    /// `sizeof(apple_nvram_header_t)`.
    pub const APPLE_HEADER: usize = 32;
    /// `offsetof(apple_nvram_header, adler)` and `generation`.
    pub const ADLER: usize = 16;
    pub const GENERATION: usize = 20;
    /// The bank's names by version (`kNVRAMVersion1`, `kNVRAMVersion2`).
    pub const BANK_V1: &[u8] = b"nvram";
    pub const BANK_V2: &[u8] = b"2nvram";
    pub const COMMON_V1: &[u8] = b"common";
    pub const COMMON_V2: &[u8] = b"2common";
    pub const SYSTEM_V1: &[u8] = b"system";
    pub const SYSTEM_V2: &[u8] = b"2system";

    /// `chrp_checksum`: the signature and the bytes from the length to the
    /// end of the name, their carries folded in.
    pub fn checksum(h: &[u8]) -> u8 {
        let mut sum: u16 = u16::from(h[0]);
        for &b in &h[2..HEADER] {
            sum = sum.wrapping_add(u16::from(b));
        }
        while sum > 0xff {
            sum = (sum & 0xff) + (sum >> 8);
        }
        sum as u8
    }

    /// `adler32` as the handler computes it (its modulo every 5000 bytes).
    pub fn adler32(b: &[u8]) -> u32 {
        let (mut low, mut high) = (1u32, 0u32);
        for (i, &c) in b.iter().enumerate() {
            if i % 5000 == 0 {
                low %= 65521;
                high %= 65521;
            }
            low = low.wrapping_add(u32::from(c));
            high = high.wrapping_add(low);
        }
        low %= 65521;
        high %= 65521;
        (high << 16) | low
    }

    /// `adler32_with_version`: from the generation to the bank's end.
    pub fn bank_adler(image: &[u8]) -> u32 {
        adler32(&image[GENERATION..])
    }

    /// `nvram_validate_header_v1v2`: the bank's name for `version` (its
    /// first characters only) and its header's checksum; the generation.
    pub fn validate(buf: &[u8], version: u32) -> Option<u32> {
        let name = if version == 1 { BANK_V1 } else { BANK_V2 };
        if buf.len() < APPLE_HEADER || &buf[4..4 + name.len()] != name || checksum(buf) != buf[1] {
            return None;
        }
        Some(u32::from_le_bytes(buf[GENERATION..GENERATION + 4].try_into().unwrap()))
    }

    /// `validateNVRAMVersion`: 1, 2, or 0 (unknown), and the generation.
    pub fn version(buf: &[u8]) -> (u32, u32) {
        if let Some(g) = validate(buf, 1) {
            return (1, g);
        }
        if let Some(g) = validate(buf, 2) {
            return (2, g);
        }
        (0, 0)
    }

    /// A partition header: signature, length in bytes (a multiple of
    /// [`BLOCK`], the header's own included), name; its checksum set.
    pub fn header(sig: u8, len: usize, name: &[u8]) -> [u8; HEADER] {
        let mut h = [0u8; HEADER];
        h[0] = sig;
        h[2..4].copy_from_slice(&((len / BLOCK) as u16).to_le_bytes());
        h[4..4 + name.len()].copy_from_slice(name);
        h[1] = checksum(&h);
        h
    }

    /// `escapeDataToData`: a run of up to 127 zero or 0xff bytes becomes
    /// 0xff and the run's length (with 0x80 for 0xff); the NUL after it is
    /// not included here.
    pub fn escape(v: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(v.len());
        let mut i = 0;
        while i < v.len() {
            let start = i;
            let mut byte = v[i];
            i += 1;
            if byte == 0x00 || byte == 0xff {
                while i - start < 0x7f && i < v.len() && v[i] == byte {
                    i += 1;
                }
                out.push(0xff);
                byte = (byte & 0x80) | (i - start) as u8;
            }
            out.push(byte);
        }
        out
    }

    /// `unescapeBytesToData` of the value's bytes, the NUL that ends them
    /// read past their end as the handler reads it: none for 0xff then a
    /// zero length.
    pub fn unescape(b: &[u8]) -> Option<Vec<u8>> {
        let at = |i: usize| b.get(i).copied().unwrap_or(0);
        let mut i = 0;
        while i < b.len() {
            let byte = at(i);
            i += 1;
            if byte == 0xff {
                let n = at(i);
                i += 1;
                if n == 0 {
                    return None;
                }
            }
        }
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            let mut byte = at(i);
            i += 1;
            let count = if byte == 0xff {
                let n = at(i);
                i += 1;
                byte = if n & 0x80 != 0 { 0xff } else { 0x00 };
                usize::from(n & 0x7f)
            } else {
                1
            };
            out.extend(std::iter::repeat(byte).take(count));
        }
        Some(out)
    }
}

/// `convertObjectToProp`'s value for `name` of type `t`: none when the
/// object is not of the type. The number's text (`-1`, decimal below
/// 1000, else `%#x` of its low 32 bits), the boolean's, the string's
/// characters, or the escaped data.
fn prop_text(name: &[u8], v: &Value) -> Option<Vec<u8>> {
    match (variable_type(name), v) {
        (VarType::Boolean, Value::Bool(b)) => Some(if *b { b"true".to_vec() } else { b"false".to_vec() }),
        (VarType::Number, Value::Number { bits, value }) => {
            let n = Value::unsigned32(*bits, *value);
            Some(if n == u32::MAX {
                b"-1".to_vec()
            } else if n < 1000 {
                format!("{}", n as i32).into_bytes()
            } else {
                format!("{n:#x}").into_bytes()
            })
        }
        (VarType::String, Value::String(s) | Value::Symbol(s)) => Some(s.clone()),
        (VarType::Data, Value::Data(d)) => Some(chrp::escape(d)),
        _ => None,
    }
}

/// `convertObjectToProp(NULL, &length, ...)`: the length `name=value\0`
/// takes, none when the object is not of the name's type.
fn prop_length(name: &[u8], v: &Value) -> Option<u32> {
    prop_text(name, v).map(|t| (cstr(name).len() + 1 + t.len() + 1) as u32)
}

/// `convertObjectToProp(buffer, &length, ...)` into `room` bytes: the
/// entry, or none when it does not fit (the name, the value at its
/// largest — 5 for a boolean, 10 for a number — and the two delimiters).
fn prop_bytes(name: &[u8], v: &Value, room: u32) -> Option<Vec<u8>> {
    let text = prop_text(name, v)?;
    let name = cstr(name);
    let max = match variable_type(name) {
        VarType::Boolean => 5,
        VarType::Number => 10,
        _ => text.len(),
    };
    if (name.len() + max + 2) as u64 > u64::from(room) {
        return None;
    }
    let mut e = name.to_vec();
    e.push(b'=');
    e.extend_from_slice(&text);
    e.push(0);
    Some(e)
}

/// `convertPropToObject`: the name (to its first NUL) and the object its
/// type makes of the value, none when it makes none.
fn prop_object(name: &[u8], data: &[u8]) -> Option<(Vec<u8>, Value)> {
    let name = cstr(name).to_vec();
    let v = match variable_type(&name) {
        // strncmp over the value's length: an empty value is "true".
        VarType::Boolean => {
            let eq = |w: &[u8]| data.len() <= w.len() && data == &w[..data.len()];
            if eq(b"true") {
                Value::Bool(true)
            } else if eq(b"false") {
                Value::Bool(false)
            } else {
                return None;
            }
        }
        VarType::Number => Value::Number { bits: 32, value: (strtol0(data) as u64) & 0xffff_ffff },
        VarType::String => Value::String(cstr(data).to_vec()),
        VarType::Data => Value::Data(chrp::unescape(data)?),
    };
    Some((name, v))
}

/// What a kernel panic the model meets says: the release kernel's own
/// message where it has one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Panic(pub String);

/// `/chosen`'s NVRAM properties as the boot left them: each one's bytes
/// when present.
#[derive(Clone, Debug, Default)]
pub struct Chosen {
    pub bank_size: Option<Vec<u8>>,
    pub bank_count: Option<Vec<u8>>,
    pub current_bank: Option<Vec<u8>>,
    pub proxy_data: Option<Vec<u8>>,
}

/// The four bytes `*((uint32_t *)data->getBytesNoCopy())` reads: a
/// property shorter than that is read past its end, which the model does
/// not answer.
fn word(name: &str, v: &[u8]) -> Result<u32, String> {
    v.get(..4).map(|w| u32::from_le_bytes(w.try_into().unwrap())).ok_or_else(|| format!("/chosen's {name} is {} bytes: IODTNVRAM reads four from it, past its end", v.len()))
}

/// `IONVRAMCHRPHandler`'s state.
#[derive(Clone, Debug)]
pub struct ChrpHandler {
    pub bank_size: u32,
    pub bank_count: u32,
    pub current_bank: u32,
    pub new_data: bool,
    pub reload: bool,
    pub version: u32,
    pub generation: u32,
    pub image: Option<Vec<u8>>,
    pub common_offset: u32,
    pub common_size: u32,
    pub system_offset: u32,
    pub system_size: u32,
    pub common_used: u32,
    pub system_used: u32,
}

impl ChrpHandler {
    /// The constructor: zeroed, a common size of 0x800.
    fn new(bank_size: u32, bank_count: u32, current_bank: u32) -> ChrpHandler {
        ChrpHandler {
            bank_size,
            bank_count,
            current_bank,
            new_data: false,
            reload: false,
            version: 0,
            generation: 0,
            image: None,
            common_offset: 0,
            common_size: 0x800,
            system_offset: 0,
            system_size: 0,
            common_used: 0,
            system_used: 0,
        }
    }

    /// `getSystemPartitionActive`.
    pub fn system_active(&self) -> bool {
        self.system_size != 0
    }

    /// `unserializeImage`: the version, the copy, the adler (a mismatch is
    /// the kernel's panic), and the partitions.
    fn unserialize_image(&mut self, image: &[u8]) -> Result<(), Panic> {
        self.common_offset = 0xffff_ffff;
        self.system_offset = 0xffff_ffff;
        let (version, generation) = chrp::version(&image[..(self.bank_size as usize).min(image.len())]);
        self.version = version;
        if version == 0 {
            return Ok(());
        }
        self.generation = generation;
        let img = image.to_vec();
        self.bank_size = img.len() as u32;
        let hdr = u32::from_le_bytes(img[chrp::ADLER..chrp::ADLER + 4].try_into().unwrap());
        let calc = chrp::bank_adler(&img);
        if hdr != calc {
            return Err(Panic(format!("header adler {hdr:#08X} != calculated_adler {calc:#08X}\n @IONVRAMCHRPHandler.cpp:432")));
        }
        let mut at: u32 = 0;
        while at < self.bank_size {
            let h = &img[at as usize..];
            if h.len() < chrp::HEADER {
                // The header read past the bank: the handler reads its
                // length from the bytes beyond.
                return Err(Panic(format!("not modelled: the CHRP partition header at {at:#x} runs past the bank's end ({:#x})", self.bank_size)));
            }
            let len = u32::from(u16::from_le_bytes([h[2], h[3]])) * chrp::BLOCK as u32;
            if len < chrp::HEADER as u32 {
                break;
            }
            let (off, plen) = (at + chrp::HEADER as u32, len - chrp::HEADER as u32);
            if u64::from(off) + u64::from(plen) > u64::from(self.bank_size) {
                break;
            }
            let name = &h[4..chrp::HEADER];
            let named = |n: &[u8]| name[..n.len()] == *n && name[n.len()..].iter().all(|&c| c == 0);
            if named(chrp::COMMON_V1) || named(chrp::COMMON_V2) {
                self.common_offset = off;
                self.common_size = plen;
            } else if named(chrp::SYSTEM_V1) || named(chrp::SYSTEM_V2) {
                self.system_offset = off;
                self.system_size = plen;
            }
            at = at.wrapping_add(len);
        }
        self.image = Some(img);
        Ok(())
    }

    /// The regions in the handler's order, common first: type, offset,
    /// size.
    fn regions(&self) -> [(u8, u32, u32); 2] {
        [(2, self.common_offset, self.common_size), (1, self.system_offset, self.system_size)]
    }
}

/// `IODTNVRAMDiags`' "Stats": per region and name ("%02X:%s"), its counts
/// and state, in the order logVariable set them.
#[derive(Clone, Debug, Default)]
pub struct Stats(pub Vec<(Vec<u8>, Vec<(&'static str, Stat)>)>);

/// A Stats entry's value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stat {
    /// An OSNumber of 64 bits.
    Num(u64),
    Bool(bool),
}

impl Stats {
    /// `IODTNVRAMDiags::logVariable`.
    fn log(&mut self, region: u8, op: u8, name: &[u8], size: u64) {
        let mut key = format!("{region:02X}:").into_bytes();
        key.extend_from_slice(cstr(name));
        let i = match self.0.iter().position(|(k, _)| *k == key) {
            Some(i) => i,
            None => {
                self.0.push((key, Vec::new()));
                self.0.len() - 1
            }
        };
        let e = &mut self.0[i].1;
        let set = |e: &mut Vec<(&'static str, Stat)>, k: &'static str, v: Stat| match e.iter_mut().find(|(n, _)| *n == k) {
            Some(slot) => slot.1 = v,
            None => e.push((k, v)),
        };
        let count = match op {
            op::READ => {
                if !e.iter().any(|(n, _)| *n == "Present") {
                    e.push(("Present", Stat::Bool(false)));
                }
                Some("Read")
            }
            op::WRITE => {
                set(e, "Size", Stat::Num(size));
                set(e, "Present", Stat::Bool(true));
                Some("Write")
            }
            op::DELETE | op::OBLITERATE | op::RESET => {
                set(e, "Present", Stat::Bool(false));
                Some("Delete")
            }
            op::INIT => {
                set(e, "Init", Stat::Num(size));
                set(e, "Size", Stat::Num(size));
                set(e, "Present", Stat::Bool(true));
                None
            }
            _ => return,
        };
        if let Some(k) = count {
            match e.iter_mut().find(|(n, _)| *n == k) {
                Some((_, Stat::Num(n))) => *n += 1,
                _ => e.push((k, Stat::Num(1))),
            }
        }
    }
}

/// `IODTNVRAMDiags`' property table, in the order its keys were set:
/// "Stats" (its serializer, at its start), then the CHRP handler's
/// "SystemUsed" and "CommonUsed", IODTNVRAM's start's "Version", and each
/// sync's "Generation" (all 32-bit numbers).
#[derive(Clone, Debug, Default)]
pub struct Diags {
    pub order: Vec<&'static str>,
    pub system_used: u32,
    pub common_used: u32,
    pub version: u32,
    pub generation: u32,
    pub stats: Stats,
}

impl Diags {
    fn set(&mut self, k: &'static str) {
        if !self.order.contains(&k) {
            self.order.push(k);
        }
    }
}

/// The controller's medium: the NVRAM namespace.
pub trait Medium: Send + Sync {
    /// Its first `len` bytes.
    fn read(&self, len: usize) -> Result<Vec<u8>, String>;
    /// `bytes` from block 0.
    fn write(&self, bytes: &[u8]) -> Result<(), String>;
}

/// `AppleEmbeddedNVMeNVRAM`: its shadow of the namespace and the medium.
pub struct Controller {
    shadow: Vec<u8>,
    medium: Arc<dyn Medium>,
}

/// One variable of `_varDict`: its canonical key, its value, and which
/// object it is (a value set under two keys from one object is one object,
/// which a serialization writes once).
#[derive(Clone, Debug)]
struct Var {
    key: Vec<u8>,
    value: Value,
    object: u64,
}

/// `IODTNVRAM` with its CHRP handler, its diagnostics and its controller.
pub struct Nvram {
    vars: Vec<Var>,
    next_object: u64,
    pub fmt: ChrpHandler,
    pub diags: Diags,
    last_device_sync: i64,
    fresh_interval: bool,
    controller: Option<Controller>,
    /// `getSystemUsed()` when start made the services: whether
    /// "options-system" was made.
    pub system_service: bool,
    /// What the medium refused, for the next call to report.
    pub write_errors: Vec<String>,
}

/// The time base of `safeToSync` (`clock_get_uptime`): seconds since boot.
pub trait Clock {
    fn uptime_secs(&self) -> i64;
}

impl Nvram {
    fn new_object(&mut self) -> u64 {
        self.next_object += 1;
        self.next_object
    }

    fn system_active(&self) -> bool {
        self.fmt.system_active()
    }

    fn index(&self, key: &[u8]) -> Option<usize> {
        self.vars.iter().position(|v| v.key == key)
    }

    /// `IODTNVRAM::init` and `start`, up to the services: the image as
    /// `initImageFormat` takes it from `/chosen`, and the variables.
    pub fn start(chosen: &Chosen) -> Result<Nvram, Panic> {
        let mut size: u32 = 0;
        let mut image: Option<&[u8]> = None;
        if let Some(b) = &chosen.bank_size {
            size = word("nvram-bank-size", b).map_err(Panic)?;
            if size == 0 {
                return Err(Panic("NVRAM size is 0 bytes, possibly due to bad config with iBoot + xnu mismatch @IONVRAM.cpp:1432".into()));
            }
            if let Some(p) = &chosen.proxy_data {
                if p.len() < size as usize {
                    return Err(Panic(format!("not modelled: /chosen's nvram-proxy-data is {} bytes, and IODTNVRAM reads nvram-bank-size's {size} from it", p.len())));
                }
                image = Some(&p[..size as usize]);
            }
        }
        // IONVRAMV3Handler::isValidImage.
        if let Some(i) = image {
            if size >= 0x18 && i[..4] == *b"3VVN" && i[0xe] == 1 {
                return Err(Panic("not implemented: an NVV3 NVRAM image (IONVRAMV3Handler); the J120's is CHRP".into()));
            }
        }
        // IONVRAMCHRPHandler::init: getNVRAMProperties, then the length.
        let (Some(bs), Some(bc), Some(cb)) = (&chosen.bank_size, &chosen.bank_count, &chosen.current_bank) else {
            return Err(Panic("IONVRAMCHRPHandler creation failed\n @IONVRAM.cpp:1449".into()));
        };
        let mut fmt = ChrpHandler::new(word("nvram-bank-size", bs).map_err(Panic)?, word("nvram-bank-count", bc).map_err(Panic)?, word("nvram-current-bank", cb).map_err(Panic)?);
        if size != fmt.bank_size {
            return Err(Panic("IONVRAMCHRPHandler creation failed\n @IONVRAM.cpp:1449".into()));
        }
        if let Some(i) = image {
            fmt.unserialize_image(i)?;
        }
        let mut n = Nvram { vars: Vec::new(), next_object: 0, fmt, diags: Diags::default(), last_device_sync: 0, fresh_interval: true, controller: None, system_service: false, write_errors: Vec::new() };
        n.diags.set("Stats");
        n.unserialize_variables()?;
        n.diags.version = n.fmt.version;
        n.diags.set("Version");
        n.system_service = n.fmt.system_used != 0;
        Ok(n)
    }

    /// `IONVRAMCHRPHandler::unserializeVariables`, then the boot-args the
    /// kernel makes when there are none.
    fn unserialize_variables(&mut self) -> Result<(), Panic> {
        for (ty, off, size) in self.fmt.regions() {
            if size == 0 {
                continue;
            }
            let Some(img) = self.fmt.image.as_ref() else {
                return Err(Panic("not modelled: IONVRAMCHRPHandler::unserializeVariables with no image (the kernel reads its regions through a NULL _nvramImage)".into()));
            };
            if u64::from(off) + u64::from(size) > img.len() as u64 {
                return Err(Panic(format!("not modelled: IONVRAMCHRPHandler::unserializeVariables reads region {ty} at {off:#x} ({size:#x} bytes), past the {:#x}-byte image", img.len())));
            }
            let data = img[off as usize..(off + size) as usize].to_vec();
            let mut cnt: usize = 0;
            while cnt < data.len() {
                let start = cnt;
                if data[cnt] == 0 {
                    break;
                }
                let Some(eq) = data[cnt..].iter().position(|&c| c == b'=') else { break };
                let name = &data[cnt..cnt + eq];
                cnt += eq + 1;
                let Some(nul) = data[cnt..].iter().position(|&c| c == 0) else { break };
                let value = &data[cnt..cnt + nul];
                cnt += nul + 1;
                if let Some((name, obj)) = prop_object(name, value) {
                    let g = if ty == 2 { guid::COMMON } else { guid::SYSTEM };
                    let key = canonical(&g, &name);
                    let object = self.new_object();
                    match self.index(&key) {
                        Some(i) => {
                            self.vars[i].value = obj;
                            self.vars[i].object = object;
                        }
                        None => self.vars.push(Var { key, value: obj, object }),
                    }
                    let len = (cnt - start) as u32;
                    self.diags.stats.log(ty, op::INIT, &name, u64::from(len));
                    if ty == 1 {
                        self.fmt.system_used = self.fmt.system_used.wrapping_add(len);
                    } else {
                        self.fmt.common_used = self.fmt.common_used.wrapping_add(len);
                    }
                }
            }
        }
        self.diags.system_used = self.fmt.system_used;
        self.diags.set("SystemUsed");
        self.diags.common_used = self.fmt.common_used;
        self.diags.set("CommonUsed");
        // _provider->getProperty(kIONVRAMBootArgsKey), then its setProperty,
        // as the kernel's task.
        if self.copy_property(&Kernel, key::BOOT_ARGS).is_none() {
            let _ = self.set_property(&Kernel, key::BOOT_ARGS, &Given::Value(Value::String(Vec::new())), None);
        }
        self.fmt.new_data = true;
        Ok(())
    }

    /// `registerNVRAMController`: the controller's start read the
    /// namespace (`nvram-bank-size` bytes, its `GetNVRAMSize`) into its
    /// shadow; `setController`'s `reloadInternal` takes the current bank
    /// and generation from it.
    pub fn register_controller(&mut self, medium: Arc<dyn Medium>) -> Result<(), String> {
        let shadow = medium.read(self.fmt.bank_size as usize)?;
        self.controller = Some(Controller { shadow, medium });
        self.reload_internal();
        Ok(())
    }

    /// `findCurrentBank` through the controller (no `select`: every bank
    /// reads its shadow), then `reloadInternal`'s update.
    fn reload_internal(&mut self) {
        let Some(c) = &self.controller else { return };
        let (mut current, mut max) = (0u32, 0u32);
        for i in 0..self.fmt.bank_count {
            let header = c.shadow.get(..chrp::APPLE_HEADER).unwrap_or(&[]);
            let (v, g) = chrp::version(header);
            if v != 0 && g >= max {
                current = i;
                max = g;
            }
        }
        self.fmt.current_bank = current;
        self.fmt.generation = max;
    }

    /// The controller's shadow, as `read` would give it.
    pub fn shadow(&self) -> Option<&[u8]> {
        self.controller.as_ref().map(|c| c.shadow.as_slice())
    }

    /// `IONVRAMCHRPHandler::serializeVariables`.
    fn serialize_variables(&mut self) -> i32 {
        if self.controller.is_none() {
            return ret::NOT_READY;
        }
        if !self.fmt.new_data || self.fmt.bank_size == 0 {
            return ret::SUCCESS;
        }
        let Some(old) = self.fmt.image.clone() else { return ret::SUCCESS };
        let mut image = vec![0u8; self.fmt.bank_size as usize];
        let n = old.len().min(image.len());
        image[..n].copy_from_slice(&old[..n]);
        let active = self.system_active();
        for (ty, off, size) in self.fmt.regions() {
            if size == 0 {
                continue;
            }
            if u64::from(off) + u64::from(size) > image.len() as u64 {
                // The handler's bzero of a region past its buffer.
                self.write_errors.push(format!("not modelled: IONVRAMCHRPHandler::serializeVariables writes region {ty} at {off:#x} ({size:#x} bytes), past the {:#x}-byte image", image.len()));
                return ret::ERROR;
            }
            let region = &mut image[off as usize..(off + size) as usize];
            region.fill(0);
            let mut at: usize = 0;
            let mut room = size;
            for v in &self.vars {
                let (g, name, _) = parse_name(&v.key);
                if active {
                    if ty == 1 && g != guid::SYSTEM || ty == 2 && g == guid::SYSTEM {
                        continue;
                    }
                }
                match prop_bytes(name, &v.value, room) {
                    Some(e) => {
                        region[at..at + e.len()].copy_from_slice(&e);
                        at += e.len();
                        room -= e.len() as u32;
                    }
                    None => return ret::NO_SPACE,
                }
            }
            if ty == 1 {
                self.fmt.system_used = at as u32;
            } else {
                self.fmt.common_used = at as u32;
            }
        }
        // nvram_set_apple_header(image, size, ++_generation, version).
        self.fmt.generation = self.fmt.generation.wrapping_add(1);
        if self.fmt.version == 1 || self.fmt.version == 2 {
            let g = self.fmt.generation.wrapping_add(1);
            image[chrp::GENERATION..chrp::GENERATION + 4].copy_from_slice(&g.to_le_bytes());
            let a = chrp::bank_adler(&image);
            image[chrp::ADLER..chrp::ADLER + 4].copy_from_slice(&a.to_le_bytes());
        }
        if self.fmt.bank_count != 0 {
            self.fmt.current_bank = (self.fmt.current_bank.wrapping_add(1)) % self.fmt.bank_count;
        } else {
            self.fmt.current_bank = self.fmt.current_bank.wrapping_add(1);
        }
        // select and eraseBank: the controller has neither
        // (kIOReturnUnsupported, logged only); write(0, image, size) into
        // its shadow (kIOReturnBadArgument past it), whose result is the
        // handler's; the controller's sync to the namespace.
        let c = self.controller.as_mut().expect("checked");
        let r = if image.len() <= c.shadow.len() {
            c.shadow[..image.len()].copy_from_slice(&image);
            ret::SUCCESS
        } else {
            ret::BAD_ARGUMENT
        };
        if let Err(e) = c.medium.write(&c.shadow) {
            self.write_errors.push(format!("the NVRAM namespace's write: {e}"));
        }
        self.fmt.image = Some(image);
        self.fmt.new_data = false;
        r
    }

    /// `IODTNVRAM::syncInternal`: rate-limited by `safeToSync` (15 minutes
    /// after the last, the first free) when asked, then the handler's
    /// sync, then the diagnostics' "Generation".
    pub fn sync_internal(&mut self, rate_limit: bool, clock: &dyn Clock) -> i32 {
        if rate_limit {
            let secs = clock.uptime_secs() as i32;
            if i64::from(secs) > self.last_device_sync + 15 * 60 || self.fresh_interval {
                self.last_device_sync = i64::from(secs);
                self.fresh_interval = false;
            } else {
                return ret::SUCCESS;
            }
        }
        // IONVRAMCHRPHandler::sync: a marked reload first.
        if self.fmt.reload {
            self.reload_internal();
            self.fmt.reload = false;
        }
        let r = self.serialize_variables();
        self.diags.generation = self.fmt.generation;
        self.diags.set("Generation");
        r
    }

    /// `IODTNVRAM::sync` (`PESyncNVRAM`'s).
    pub fn sync(&mut self, clock: &dyn Clock) -> i32 {
        self.sync_internal(false, clock)
    }

    /// `copyPropertyWithGUIDAndName`.
    pub fn copy_property_guid(&mut self, c: &dyn Caller, g: &[u8; 16], name: &[u8]) -> Option<Value> {
        let active = self.system_active();
        if !verify_permission(c, op::READ, g, name, active) {
            return None;
        }
        let t = translate(g, name, active);
        let key = canonical(&t, name);
        let v = self.index(&key).map(|i| self.vars[i].value.clone());
        self.diags.stats.log(partition_type(&t), op::READ, name, 0);
        v
    }

    /// `IODTNVRAM::copyProperty(const char *)`.
    pub fn copy_property(&mut self, c: &dyn Caller, key: &[u8]) -> Option<Value> {
        let key = cstr(key);
        if skip_key(key) {
            return None;
        }
        let (g, name, _) = parse_name(key);
        let name = name.to_vec();
        self.copy_property_guid(c, &g, &name)
    }

    /// `IONVRAMCHRPHandler::setVariableInternal`.
    fn set_variable_internal(&mut self, g: &[u8; 16], name: &[u8], value: Option<(Value, u64)>) -> i32 {
        let system = *g == guid::SYSTEM;
        let key = canonical(g, name);
        let existing = self.index(&key).and_then(|i| prop_length(name, &self.vars[i].value)).unwrap_or(0);
        match value {
            Some((v, object)) => {
                let new = prop_length(name, &v).unwrap_or(0);
                let (used, size) = if system { (self.fmt.system_used, self.fmt.system_size) } else { (self.fmt.common_used, self.fmt.common_size) };
                if new.wrapping_add(used).wrapping_sub(existing) > size {
                    return ret::NO_SPACE;
                }
                let used = used.wrapping_add(new).wrapping_sub(existing);
                if system {
                    self.fmt.system_used = used;
                } else {
                    self.fmt.common_used = used;
                }
                match self.index(&key) {
                    Some(i) => {
                        self.vars[i].value = v;
                        self.vars[i].object = object;
                    }
                    None => self.vars.push(Var { key, value: v, object }),
                }
                self.diags.stats.log(partition_type(g), op::WRITE, name, u64::from(new));
            }
            None => {
                if system {
                    self.fmt.system_used = self.fmt.system_used.wrapping_sub(existing);
                } else {
                    self.fmt.common_used = self.fmt.common_used.wrapping_sub(existing);
                }
                if let Some(i) = self.index(&key) {
                    self.vars.remove(i);
                }
                self.diags.stats.log(partition_type(g), op::DELETE, name, 0);
            }
        }
        self.diags.system_used = self.fmt.system_used;
        self.diags.common_used = self.fmt.common_used;
        self.fmt.new_data = true;
        ret::SUCCESS
    }

    /// `IONVRAMCHRPHandler::setVariable`: the system namespace (or the
    /// common one, without a system region) for a system or allow-listed
    /// variable.
    fn set_variable(&mut self, g: &[u8; 16], name: &[u8], value: Option<(Value, u64)>) -> i32 {
        let dest = if *g == guid::SYSTEM || in_allow_list(name) {
            if self.system_active() {
                guid::SYSTEM
            } else {
                guid::COMMON
            }
        } else {
            *g
        };
        self.set_variable_internal(&dest, name, value)
    }

    /// `removePropertyWithGUIDAndName`.
    pub fn remove_property_guid(&mut self, c: &dyn Caller, g: &[u8; 16], name: &[u8]) -> i32 {
        let active = self.system_active();
        if !verify_permission(c, op::DELETE, g, name, active) {
            return ret::NOT_PRIVILEGED;
        }
        let t = translate(g, name, active);
        if self.set_variable(&t, name, None) != ret::SUCCESS {
            return ret::NOT_FOUND;
        }
        ret::SUCCESS
    }

    /// `IODTNVRAM::removeProperty` (its result is only logged).
    pub fn remove_property(&mut self, c: &dyn Caller, key: &[u8]) -> i32 {
        let (g, name, _) = parse_name(cstr(key));
        let name = name.to_vec();
        self.remove_property_guid(c, &g, &name)
    }

    /// `handleSpecialVariables`: ObliterateNVRam and ResetNVRam. Their
    /// permission checks are the caller's in the source; the handler's
    /// flush asks `verifyPermission` for the current task, the caller.
    fn special(&mut self, c: &dyn Caller, name: &[u8], g: &[u8; 16]) -> Option<i32> {
        let active = self.system_active();
        let flush = |n: &mut Nvram, fg: &[u8; 16], o: u8| -> i32 {
            let flush_system = active && *fg == guid::SYSTEM;
            let flush_common = *fg == guid::COMMON;
            if flush_system || flush_common {
                let keys: Vec<Vec<u8>> = n.vars.iter().map(|v| v.key.clone()).collect();
                for k in keys {
                    let (vg, vname, _) = parse_name(&k);
                    let vname = vname.to_vec();
                    if (flush_system && vg == guid::SYSTEM || flush_common && vg != guid::SYSTEM) && verify_permission(c, o, &vg, &vname, active) {
                        n.set_variable_internal(&vg, &vname, None);
                    }
                }
            }
            ret::SUCCESS
        };
        if name == b"ObliterateNVRam" {
            Some(flush(self, g, op::OBLITERATE))
        } else if name == b"ResetNVRam" {
            let r = flush(self, &guid::SYSTEM, op::RESET);
            if r != ret::SUCCESS {
                return Some(r);
            }
            Some(flush(self, &guid::COMMON, op::RESET))
        } else {
            None
        }
    }

    /// `setPropertyWithGUIDAndName`. `object` is the given object's
    /// identity (none: a new one).
    pub fn set_property_guid(&mut self, c: &dyn Caller, g: &[u8; 16], name: &[u8], given: &Given, object: Option<u64>, clock: &dyn Clock) -> i32 {
        let name = cstr(name);
        if name == key::DELETE || name == key::DELETE_WRET {
            let Some(s) = given.string() else { return ret::ERROR };
            let s = cstr(s).to_vec();
            let (vg, vname, provided) = parse_name(&s);
            let vname = vname.to_vec();
            let r = if provided { self.remove_property_guid(c, &vg, &vname) } else { self.remove_property_guid(c, g, &vname) };
            return if name == key::DELETE_WRET { r } else { ret::SUCCESS };
        }
        if name == key::SYNC_NOW || name == key::FORCE_SYNC_NOW {
            if given.string().is_none() {
                return ret::ERROR;
            }
            return self.sync_internal(name == key::SYNC_NOW, clock);
        }
        let active = self.system_active();
        if !verify_permission(c, op::WRITE, g, name, active) {
            return ret::NOT_PRIVILEGED;
        }
        let mut size = 0usize;
        let mut object = object;
        let v = match (variable_type(name), given) {
            (VarType::Boolean, Given::Value(v @ Value::Bool(_))) => v.clone(),
            (VarType::Number, Given::Value(v @ Value::Number { .. })) => v.clone(),
            (VarType::String, Given::Value(v @ (Value::String(_) | Value::Symbol(_)))) => {
                let (Value::String(s) | Value::Symbol(s)) = v else { unreachable!() };
                size = s.len();
                if name == key::BOOT_ARGS && size >= BOOT_LINE_LENGTH {
                    return ret::NO_SPACE;
                }
                v.clone()
            }
            (VarType::Data, Given::Value(Value::Data(d))) => {
                size = d.len();
                Value::Data(d.clone())
            }
            (VarType::Data, Given::Value(Value::String(s) | Value::Symbol(s))) => {
                // OSData::withBytes of the string: a new object.
                object = None;
                size = s.len();
                Value::Data(s.clone())
            }
            _ => return ret::BAD_ARGUMENT,
        };
        if !write_size_ok(name, size) {
            return ret::NO_SPACE;
        }
        if let Some(r) = self.special(c, name, g) {
            return r;
        }
        let t = translate(g, name, active);
        let object = object.unwrap_or_else(|| self.new_object());
        self.set_variable(&t, name, Some((v, object)))
    }

    /// `setPropertyInternal`: the key parsed for its GUID.
    pub fn set_property(&mut self, c: &dyn Caller, key: &[u8], given: &Given, object: Option<u64>) -> i32 {
        struct Boot;
        impl Clock for Boot {
            fn uptime_secs(&self) -> i64 {
                0
            }
        }
        self.set_property_clocked(c, key, given, object, &Boot)
    }

    /// `setPropertyInternal` with the clock a sync key's rate limit reads.
    pub fn set_property_clocked(&mut self, c: &dyn Caller, key: &[u8], given: &Given, object: Option<u64>, clock: &dyn Clock) -> i32 {
        let (g, name, _) = parse_name(cstr(key));
        let name = name.to_vec();
        self.set_property_guid(c, &g, &name, given, object, clock)
    }

    /// A fresh object identity for an object a set gives.
    pub fn object_id(&mut self) -> u64 {
        self.new_object()
    }

    /// `IODTNVRAM::serializeProperties`: the system namespace's variables
    /// the caller may read, then the common one's whose names are not
    /// there yet, each by its name; with each value's object identity.
    pub fn serialize_properties(&self, c: &dyn Caller) -> Vec<(Vec<u8>, Value, u64)> {
        let active = self.system_active();
        let mut out: Vec<(Vec<u8>, Value, u64)> = Vec::new();
        for v in &self.vars {
            let (g, name, _) = parse_name(&v.key);
            if g == guid::SYSTEM && verify_permission(c, op::READ, &g, name, active) {
                match out.iter_mut().find(|(k, _, _)| k.as_slice() == name) {
                    Some(slot) => {
                        slot.1 = v.value.clone();
                        slot.2 = v.object;
                    }
                    None => out.push((name.to_vec(), v.value.clone(), v.object)),
                }
            }
        }
        for v in &self.vars {
            let (g, name, _) = parse_name(&v.key);
            if g == guid::COMMON {
                if out.iter().any(|(k, _, _)| k.as_slice() == name) {
                    continue;
                }
                if verify_permission(c, op::READ, &g, name, active) {
                    out.push((name.to_vec(), v.value.clone(), v.object));
                }
            }
        }
        out
    }

    /// `IODTNVRAMVariables::serializeProperties` for namespace `ns`: its
    /// variables the caller may read (asked of the canonical key), by name.
    pub fn variables_properties(&self, c: &dyn Caller, ns: &[u8; 16]) -> Vec<(Vec<u8>, Value, u64)> {
        let active = self.system_active();
        let mut out: Vec<(Vec<u8>, Value, u64)> = Vec::new();
        for v in &self.vars {
            let (g, name, _) = parse_name(&v.key);
            if verify_permission(c, op::READ, &g, name, active) && g == *ns {
                match out.iter_mut().find(|(k, _, _)| k.as_slice() == name) {
                    Some(slot) => {
                        slot.1 = v.value.clone();
                        slot.2 = v.object;
                    }
                    None => out.push((name.to_vec(), v.value.clone(), v.object)),
                }
            }
        }
        out
    }

    /// The canonical keys and values, in `_varDict`'s order.
    pub fn variables(&self) -> Vec<(Vec<u8>, Value)> {
        self.vars.iter().map(|v| (v.key.clone(), v.value.clone())).collect()
    }
}

/// Dictionary `entries` (name, value, object identity) as an OSDictionary
/// in `g`; its id.
pub fn to_graph(g: &mut Graph, entries: &[(Vec<u8>, Value, u64)]) -> Id {
    let mut made: Vec<(u64, Id)> = Vec::new();
    let mut e = Vec::with_capacity(entries.len());
    for (k, v, object) in entries {
        let id = match made.iter().find(|(o, _)| o == object) {
            Some(&(_, id)) => id,
            None => {
                let id = value_obj(g, v);
                made.push((*object, id));
                id
            }
        };
        e.push((k.clone(), id));
    }
    g.add(Obj::Dict(e))
}

/// A value as an object of `g`.
pub fn value_obj(g: &mut Graph, v: &Value) -> Id {
    match v {
        Value::Bool(b) => g.add(Obj::Bool(*b)),
        Value::Number { bits, value } => g.add(Obj::Number { size: *bits, value: *value }),
        Value::String(s) => g.add(Obj::String(s.clone())),
        Value::Symbol(s) => g.add(Obj::Symbol(s.clone())),
        Value::Data(d) => g.add(Obj::Data(d.clone())),
    }
}

/// The diagnostics' property table as objects of `g`: (key, object), in
/// order.
pub fn diags_graph(g: &mut Graph, d: &Diags) -> Vec<(Vec<u8>, Id)> {
    let mut out = Vec::new();
    for &k in &d.order {
        let id = match k {
            "Stats" => {
                let mut entries = Vec::new();
                for (name, stat) in &d.stats.0 {
                    let mut e = Vec::new();
                    for (sk, sv) in stat {
                        let id = match sv {
                            Stat::Num(n) => g.add(Obj::Number { size: 64, value: *n }),
                            Stat::Bool(b) => g.add(Obj::Bool(*b)),
                        };
                        e.push((sk.as_bytes().to_vec(), id));
                    }
                    let id = g.add(Obj::Dict(e));
                    entries.push((name.clone(), id));
                }
                g.add(Obj::Dict(entries))
            }
            "SystemUsed" => g.add(Obj::Number { size: 32, value: u64::from(d.system_used) }),
            "CommonUsed" => g.add(Obj::Number { size: 32, value: u64::from(d.common_used) }),
            "Version" => g.add(Obj::Number { size: 32, value: u64::from(d.version) }),
            "Generation" => g.add(Obj::Number { size: 32, value: u64::from(d.generation) }),
            _ => continue,
        };
        out.push((k.as_bytes().to_vec(), id));
    }
    out
}

/// The web device's factory NVRAM: one 8 KiB bank (the namespace's two
/// blocks) of version 2, a "2nvram" bank header (generation 0) and one
/// "2common" partition filling the rest (`kNVRAMVersion2`: the 0x2000
/// bank less the two headers), with no variable. The signatures are zero:
/// nothing in the 21H461 kernel reads them (the handler checks names,
/// checksums and lengths), and the J120's are its encrypted iBoot's.
pub fn factory_image() -> Vec<u8> {
    const BANK: usize = 0x2000;
    let mut b = vec![0u8; BANK];
    b[..chrp::HEADER].copy_from_slice(&chrp::header(0, chrp::APPLE_HEADER, chrp::BANK_V2));
    b[chrp::APPLE_HEADER..chrp::APPLE_HEADER + chrp::HEADER].copy_from_slice(&chrp::header(0, BANK - chrp::APPLE_HEADER, chrp::COMMON_V2));
    let a = chrp::bank_adler(&b);
    b[chrp::ADLER..chrp::ADLER + 4].copy_from_slice(&a.to_le_bytes());
    b
}

/// The size of the web device's bank: `nvram-bank-size`.
pub const FACTORY_BANK_SIZE: u32 = 0x2000;

/// What the web device's boot puts in `/chosen` for an image of its NVRAM
/// namespace: the bank (the whole namespace, which has no other bank: its
/// controller has no `select`), one bank, the current one 0.
pub fn chosen_for(image: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("nvram-bank-size", (image.len() as u32).to_le_bytes().to_vec()),
        ("nvram-bank-count", 1u32.to_le_bytes().to_vec()),
        ("nvram-current-bank", 0u32.to_le_bytes().to_vec()),
        ("nvram-proxy-data", image.to_vec()),
    ]
}

/// Every entitlement `verifyPermission` may ask a task for.
pub fn entitlements_asked() -> Vec<&'static str> {
    let mut v = vec![ent::WRITE_ACCESS, ent::READ_ACCESS, ent::SYSTEM_ALLOW, ent::SYSTEM_INTERNAL_ALLOW, ent::SYSTEM_HIDDEN_ALLOW];
    for &(_, _, _, e) in &ENTITLEMENTS {
        if !v.contains(&e) {
            v.push(e);
        }
    }
    v
}

/// A user task as `verifyPermission` sees it: its security token's uid
/// is 0 or not, and the entitlements it holds of those asked.
#[derive(Clone, Debug)]
pub struct Task {
    pub admin: bool,
    pub entitled: Vec<&'static str>,
}

impl Task {
    /// The task whose security token is root's or not (`admin`), holding
    /// the entitlements `has` says it holds.
    pub fn new(admin: bool, has: impl Fn(&str) -> bool) -> Task {
        Task { admin, entitled: entitlements_asked().into_iter().filter(|e| has(e)).collect() }
    }
}

impl Caller for Task {
    fn kernel(&self) -> bool {
        false
    }
    fn admin(&self) -> bool {
        self.admin
    }
    fn entitled(&self, entitlement: &str) -> bool {
        self.entitled.contains(&entitlement)
    }
}

/// `clock_get_uptime` in whole seconds, as `safeToSync` takes it.
pub struct Uptime;

impl Clock for Uptime {
    fn uptime_secs(&self) -> i64 {
        i64::from(super::mach::uptime().as_secs() as i32)
    }
}

/// A host file holding the NVRAM namespace.
impl Medium for super::apfswrite::HostFile {
    fn read(&self, len: usize) -> Result<Vec<u8>, String> {
        use super::apfsread::Medium as _;
        if (len as u64) > self.size() {
            return Err(format!("the NVRAM namespace image is {} bytes, shorter than the {len} the controller reads", self.size()));
        }
        let mut b = vec![0u8; len];
        self.read_at(0, &mut b)?;
        Ok(b)
    }
    fn write(&self, bytes: &[u8]) -> Result<(), String> {
        use super::apfswrite::Sink as _;
        self.write_at(0, bytes)?;
        self.0.sync_data().map_err(|e| e.to_string())
    }
}

/// The NVRAM the system runs with: none until the boot, then the model,
/// or why there is none.
enum State {
    Unset,
    Absent(String),
    Running(Nvram),
}

static STATE: std::sync::Mutex<State> = std::sync::Mutex::new(State::Unset);

/// Why no NVRAM is modelled when the boot is given none.
pub const NO_IMAGE: &str = "the device's NVRAM (iBoot's /chosen nvram-proxy-data and nvram-bank-*, and the NVRAM namespace AppleEmbeddedNVMeNVRAM writes) is not given: the web device's (GEX_DARWIN_WEB_DEVICE, its nvram.bin) or a device's image (GEX_DARWIN_NVRAM)";

/// The boot's NVRAM: IODTNVRAM's start over `chosen` (`/chosen` as the
/// boot left it), then the controller's registration with `medium`.
pub fn boot(chosen: &Chosen, medium: Arc<dyn Medium>) -> Result<(), String> {
    let mut n = Nvram::start(chosen).map_err(|p| format!("the kernel panics at IODTNVRAM's start: {}", p.0))?;
    n.register_controller(medium).map_err(|e| format!("AppleEmbeddedNVMeNVRAM's start: {e}"))?;
    *STATE.lock().unwrap_or_else(|e| e.into_inner()) = State::Running(n);
    Ok(())
}

/// No NVRAM for this boot, and why.
pub fn absent(why: String) {
    *STATE.lock().unwrap_or_else(|e| e.into_inner()) = State::Absent(why);
}

/// `f` over the running NVRAM; `Err` says why there is none.
pub fn with<R>(f: impl FnOnce(&mut Nvram) -> R) -> Result<R, String> {
    let mut g = STATE.lock().unwrap_or_else(|e| e.into_inner());
    match &mut *g {
        State::Running(n) => Ok(f(n)),
        State::Absent(why) => Err(why.clone()),
        State::Unset => Err(NO_IMAGE.to_string()),
    }
}

/// Whether the boot made the "options-system" service: `None` when no
/// NVRAM is modelled.
pub fn system_service() -> Option<bool> {
    with(|n| n.system_service).ok()
}

/// `/chosen`'s NVRAM properties of tree `t`.
pub fn chosen_of(t: &[super::iokit::Node]) -> Chosen {
    let p = |name: &str| super::iokit::dt_prop(t, "IODeviceTree:/chosen", name).map(<[u8]>::to_vec);
    Chosen { bank_size: p("nvram-bank-size"), bank_count: p("nvram-bank-count"), current_bank: p("nvram-current-bank"), proxy_data: p("nvram-proxy-data") }
}

/// A registry entry of the NVRAM's that answers for itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry {
    /// IODTNVRAM, on `/options`.
    Nvram,
    /// An IODTNVRAMVariables, of its namespace.
    Variables([u8; 16]),
    /// IODTNVRAMDiags.
    Diags,
}

/// The NVRAM entry `i` of tree `t` is, if it is one.
pub fn entry(t: &[super::iokit::Node], i: u32) -> Option<Entry> {
    use super::iokit::{NVRAM_CLASS, NVRAM_DIAGS, NVRAM_VARIABLES};
    let n = t.get(i as usize)?;
    if matches!(n.nub, Some((NVRAM_CLASS, _))) {
        return Some(Entry::Nvram);
    }
    match n.class {
        NVRAM_VARIABLES => Some(Entry::Variables(if n.name == "options-system" { guid::SYSTEM } else { guid::COMMON })),
        NVRAM_DIAGS => Some(Entry::Diags),
        _ => None,
    }
}

/// The entry's property table as `serializeProperties` writes it for
/// caller `c`: its keys and their objects in `g`.
pub fn entry_properties(e: Entry, c: &dyn Caller, g: &mut Graph) -> Result<Vec<(Vec<u8>, Id)>, String> {
    with(|n| match e {
        Entry::Nvram => dict_entries(g, &n.serialize_properties(c)),
        Entry::Variables(ns) => dict_entries(g, &n.variables_properties(c, &ns)),
        Entry::Diags => diags_graph(g, &n.diags),
    })
}

/// Entries (name, value, object) as objects of `g`, one per object.
fn dict_entries(g: &mut Graph, entries: &[(Vec<u8>, Value, u64)]) -> Vec<(Vec<u8>, Id)> {
    let d = to_graph(g, entries);
    match g.get(d) {
        Obj::Dict(e) => e.clone(),
        _ => Vec::new(),
    }
}

/// The entry's `copyProperty(name)` for caller `c`: its object in `g`.
pub fn entry_property(e: Entry, c: &dyn Caller, name: &[u8], g: &mut Graph) -> Result<Option<Id>, String> {
    with(|n| match e {
        Entry::Nvram => n.copy_property(c, name).map(|v| value_obj(g, &v)),
        Entry::Variables(ns) => {
            let name = cstr(name);
            if skip_key(name) {
                None
            } else {
                n.copy_property_guid(c, &ns, name).map(|v| value_obj(g, &v))
            }
        }
        // IODTNVRAMDiags' table, as IORegistryEntry's copyProperty reads it.
        Entry::Diags => {
            let d = n.diags.clone();
            diags_graph(g, &d).into_iter().find(|(k, _)| k.as_slice() == cstr(name)).map(|(_, id)| id)
        }
    })
}

/// `setProperties` of entry `e` (IODTNVRAM's or an IODTNVRAMVariables')
/// with object `obj` of `g`, for caller `c`: a dictionary's keys in its
/// order, each `setPropertyInternal` (with the namespace for a variables
/// service), until one fails; anything else is kIOReturnBadArgument.
pub fn entry_set_properties(e: Entry, c: &dyn Caller, g: &Graph, obj: Id, clock: &dyn Clock) -> Result<i32, String> {
    let Obj::Dict(entries) = g.get(obj) else { return Ok(ret::BAD_ARGUMENT) };
    let entries = entries.clone();
    with(|n| {
        let mut objects: Vec<(Id, u64)> = Vec::new();
        let mut r = ret::SUCCESS;
        for (key, v) in entries {
            if r != ret::SUCCESS {
                break;
            }
            let object = match objects.iter().find(|(o, _)| *o == v) {
                Some(&(_, id)) => id,
                None => {
                    let id = n.object_id();
                    objects.push((v, id));
                    id
                }
            };
            let given = Given::of(g, v);
            r = match e {
                Entry::Nvram => n.set_property_clocked(c, cstr(&key), &given, Some(object), clock),
                Entry::Variables(ns) => n.set_property_guid(c, &ns, cstr(&key), &given, Some(object), clock),
                Entry::Diags => ret::UNSUPPORTED,
            };
        }
        r
    })
}

/// The bytes `is_io_registry_entry_get_property_bytes` gives of object
/// `id` of `g`: a string's and its NUL, a boolean's "Yes" or "No", a
/// number's low `numberOfBytes`, data's; none for a collection.
pub fn property_bytes(g: &Graph, id: Id) -> Option<Vec<u8>> {
    match g.get(id) {
        Obj::String(s) | Obj::Symbol(s) => Some([s.as_slice(), b"\0"].concat()),
        Obj::Bool(b) => Some(if *b { b"Yes\0".to_vec() } else { b"No\0".to_vec() }),
        Obj::Number { size, .. } => {
            let v = g.u64_value(id)?;
            Some(v.to_le_bytes()[..((*size as usize + 7) / 8).min(8)].to_vec())
        }
        Obj::Data(d) => Some(d.clone()),
        Obj::Dict(_) | Obj::Array(_) | Obj::Set(_) => None,
    }
}

/// The device's NVRAM namespace a boot has: the web device's own, or a
/// device's image dumped from it.
pub struct Source {
    pub medium: Arc<dyn Medium>,
    /// Its size, the bank's.
    pub size: usize,
    /// A device's image rather than the web device's.
    pub device: bool,
}

impl Source {
    /// What the boot puts in `/chosen` for the namespace: its image as
    /// one bank ([`chosen_for`]).
    pub fn chosen(&self) -> Result<Vec<(&'static str, Vec<u8>)>, String> {
        if !self.device && self.size != FACTORY_BANK_SIZE as usize {
            return Err(format!("the web device's NVRAM image is {} bytes, not its namespace's {FACTORY_BANK_SIZE}", self.size));
        }
        let image = self.medium.read(self.size)?;
        Ok(chosen_for(&image))
    }

    /// What stands in for a device's iBoot: its `nvram-bank-count` and
    /// `nvram-current-bank`, which the web device's boot sets to its own
    /// (one bank, the current one 0).
    pub fn unmeasured(&self) -> Option<String> {
        self.device.then(|| "the device's iBoot's /chosen nvram-bank-count and nvram-current-bank are not measured (stand-ins: 1 and 0, the web device's boot's); measure them with ioreg -p IODeviceTree -n chosen -l, with nvram-bank-size and nvram-proxy-data, on the device".to_string())
    }
}

impl crate::syscalls::Kernel {
    /// The calling task as `verifyPermission` sees it: its security
    /// token's uid and its entitlements.
    pub(crate) fn darwin_nvram_task(&self) -> Task {
        Task::new(self.creds.uid() == 0, |e| self.darwin_task_entitled(e))
    }

    /// What the NVRAM namespace's medium refused since the last report.
    pub(crate) fn darwin_nvram_take_errors(&mut self) -> Option<String> {
        let e = with(|n| std::mem::take(&mut n.write_errors)).ok()?;
        (!e.is_empty()).then(|| e.join("; "))
    }

    /// Report what the medium refused.
    pub(crate) fn darwin_nvram_report(&mut self) {
        if let Some(what) = self.darwin_nvram_take_errors() {
            self.darwin_unimplemented(what);
        }
    }

    /// `PEHaltRestart` of a halt or restart: `handlePlatformHaltRestart`'s
    /// `PESyncNVRAM`, IODTNVRAM's sync, before the machine ends. With no
    /// NVRAM modelled no variable could have changed, and there is nothing
    /// to write.
    pub(crate) fn darwin_nvram_halt_restart(&mut self) {
        let _ = with(|n| n.sync(&Uptime));
        self.darwin_nvram_report();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Mem(Mutex<Vec<u8>>, Mutex<u32>);
    impl Medium for Mem {
        fn read(&self, len: usize) -> Result<Vec<u8>, String> {
            Ok(self.0.lock().unwrap()[..len].to_vec())
        }
        fn write(&self, b: &[u8]) -> Result<(), String> {
            *self.0.lock().unwrap() = b.to_vec();
            *self.1.lock().unwrap() += 1;
            Ok(())
        }
    }
    struct At(i64);
    impl Clock for At {
        fn uptime_secs(&self) -> i64 {
            self.0
        }
    }
    struct User {
        root: bool,
        ents: Vec<&'static str>,
    }
    impl Caller for User {
        fn kernel(&self) -> bool {
            false
        }
        fn admin(&self) -> bool {
            self.root
        }
        fn entitled(&self, e: &str) -> bool {
            self.ents.contains(&e)
        }
    }

    fn boot(image: &[u8]) -> (Nvram, Arc<Mem>) {
        let mut chosen = Chosen::default();
        for (k, v) in chosen_for(image) {
            match k {
                "nvram-bank-size" => chosen.bank_size = Some(v),
                "nvram-bank-count" => chosen.bank_count = Some(v),
                "nvram-current-bank" => chosen.current_bank = Some(v),
                _ => chosen.proxy_data = Some(v),
            }
        }
        let mut n = Nvram::start(&chosen).expect("boots");
        let m = Arc::new(Mem(Mutex::new(image.to_vec()), Mutex::new(0)));
        n.register_controller(m.clone()).unwrap();
        (n, m)
    }

    #[test]
    fn the_checksums_are_the_handlers() {
        // chrp_checksum folds the carries: 0x5a + "nvram" + len 2.
        let h = chrp::header(0x5a, 32, b"nvram");
        let mut sum: u32 = 0x5a + 2 + b"nvram".iter().map(|&c| u32::from(c)).sum::<u32>();
        while sum > 0xff {
            sum = (sum & 0xff) + (sum >> 8);
        }
        assert_eq!(h[1] as u32, sum);
        // adler32 of "Wikipedia" is 0x11E60398.
        assert_eq!(chrp::adler32(b"Wikipedia"), 0x11E6_0398);
        // Past 5000 bytes the handler's reductions keep it the standard
        // one.
        let big: Vec<u8> = (0..20000u32).map(|i| (i * 7 + 3) as u8).collect();
        let (mut a, mut b) = (1u64, 0u64);
        for &c in &big {
            a = (a + u64::from(c)) % 65521;
            b = (b + a) % 65521;
        }
        assert_eq!(chrp::adler32(&big), ((b << 16) | a) as u32);
    }

    #[test]
    fn the_factory_bank_is_a_version_2_bank() {
        let f = factory_image();
        assert_eq!(f.len(), 0x2000);
        assert_eq!(chrp::version(&f), (2, 0));
        assert_eq!(&f[4..10], b"2nvram");
        assert_eq!(u16::from_le_bytes([f[2], f[3]]), 2);
        assert_eq!(&f[36..43], b"2common");
        assert_eq!(u16::from_le_bytes([f[34], f[35]]), 0x1fe);
        assert_eq!(chrp::checksum(&f[32..48]), f[33]);
        assert_eq!(u32::from_le_bytes(f[16..20].try_into().unwrap()), chrp::bank_adler(&f));
        let (n, _) = boot(&f);
        assert_eq!((n.fmt.version, n.fmt.common_offset, n.fmt.common_size, n.fmt.system_size), (2, 48, 0x2000 - 48, 0));
        // The kernel's own boot-args, made at its start.
        assert_eq!(n.variables(), vec![(canonical(&guid::COMMON, b"boot-args"), Value::String(Vec::new()))]);
        assert_eq!(n.fmt.common_used, 11);
        assert!(n.fmt.new_data);
    }

    #[test]
    fn a_sync_writes_the_bank_two_generations_on() {
        let (mut n, m) = boot(&factory_image());
        let k = User { root: true, ents: vec![] };
        assert_eq!(n.set_property(&k, b"auto-boot", &Given::Value(Value::String(b"true".to_vec())), None), ret::SUCCESS);
        assert_eq!(n.set_property(&k, b"test-num", &Given::Value(Value::Number { bits: 64, value: 4096 }), None), ret::SUCCESS);
        assert_eq!(n.set_property(&k, b"test-data", &Given::Value(Value::Data(vec![0, 0, 0, 1, 0xff, 0xff, 2])), None), ret::SUCCESS);
        assert_eq!(n.sync(&At(0)), ret::SUCCESS);
        let img = m.0.lock().unwrap().clone();
        assert_eq!(*m.1.lock().unwrap(), 1);
        assert_eq!(chrp::version(&img), (2, 2));
        assert_eq!(n.fmt.generation, 1);
        assert_eq!(u32::from_le_bytes(img[16..20].try_into().unwrap()), chrp::bank_adler(&img));
        let common = &img[48..];
        let want: &[u8] = b"boot-args=\0auto-boot=true\0test-num=0x1000\0test-data=\xff\x03\x01\xff\x82\x02\0";
        assert_eq!(&common[..want.len()], want);
        assert!(common[want.len()..].iter().all(|&c| c == 0));
        // Nothing new: the next sync writes nothing.
        assert_eq!(n.sync(&At(0)), ret::SUCCESS);
        assert_eq!(*m.1.lock().unwrap(), 1);
        // The bank boots back to the same variables, the number as the
        // 32-bit one its text makes.
        let (n2, _) = boot(&img);
        let mut want = n.variables();
        want[2].1 = Value::Number { bits: 32, value: 4096 };
        assert_eq!(n2.variables(), want);
        assert_eq!(n2.fmt.generation, 2);
    }

    #[test]
    fn data_escapes_round_trip() {
        for v in [vec![], vec![0u8; 300], vec![0xff; 128], vec![1, 0, 0xff, 0, 2], (0..=255u8).collect::<Vec<_>>()] {
            assert_eq!(chrp::unescape(&chrp::escape(&v)).as_deref(), Some(v.as_slice()));
        }
        // 0xff then a zero count is no data; a trailing 0xff reads the NUL.
        assert_eq!(chrp::unescape(&[1, 0xff]), None);
        assert_eq!(chrp::unescape(&[0xff, 0x00]), None);
    }

    #[test]
    fn names_take_a_guid_prefix() {
        let k = b"40A0DDD2-77F8-4392-B4A3-1E7304206516:boot-args";
        assert_eq!(parse_name(k), (guid::SYSTEM, &b"boot-args"[..], true));
        assert_eq!(parse_name(b"40a0ddd2-77f8-4392-b4a3-1e7304206516:x"), (guid::SYSTEM, &b"x"[..], true));
        assert_eq!(parse_name(b"boot-args"), (guid::COMMON, &b"boot-args"[..], false));
        // The colon must follow the GUID.
        assert_eq!(parse_name(b"40A0DDD2-77F8-4392-B4A3-1E7304206516-x").2, false);
        // sscanf's sign within a field's width.
        assert_eq!(parse_name(b"+AA0DDD2-77F8-4392-B4A3-1E7304206516:y").0[..2], [0x0a, 0xa0]);
        // White space before a field, and a field cut short by the next
        // character, still make 36.
        assert_eq!(parse_name(b" AA0DDD2-77F8-4392-B4A3-1E7304206516:y").0[..4], [0xaa, 0x0d, 0xdd, 0x02]);
        assert_eq!(canonical(&guid::COMMON, b"x"), b"7C436110-AB2A-4BBB-A880-FE41995C9F82:x".to_vec());
    }

    #[test]
    fn permissions_follow_the_tables() {
        let (mut n, _) = boot(&factory_image());
        let user = User { root: false, ents: vec![] };
        let root = User { root: true, ents: vec![] };
        let s = |b: &[u8]| Given::Value(Value::String(b.to_vec()));
        // A kernel-only variable.
        assert_eq!(n.set_property(&root, b"nonce-seeds", &s(b"x"), None), ret::NOT_PRIVILEGED);
        assert_eq!(n.set_property(&Kernel, b"nonce-seeds", &s(b"x"), None), ret::SUCCESS);
        assert_eq!(n.copy_property(&root, b"nonce-seeds"), None);
        assert_eq!(n.copy_property(&Kernel, b"nonce-seeds"), Some(Value::Data(b"x".to_vec())));
        // A user may not write without root, but backlight-level is
        // user-writable.
        assert_eq!(n.set_property(&user, b"foo", &s(b"1"), None), ret::NOT_PRIVILEGED);
        assert_eq!(n.set_property(&user, b"backlight-level", &s(b"1"), None), ret::SUCCESS);
        // A system namespace write needs the entitlement unless the name is
        // allow-listed.
        let sys = |n: &str| format!("40A0DDD2-77F8-4392-B4A3-1E7304206516:{n}").into_bytes();
        assert_eq!(n.set_property(&root, &sys("foo"), &s(b"1"), None), ret::NOT_PRIVILEGED);
        assert_eq!(n.set_property(&root, &sys("boot-args"), &s(b"-v"), None), ret::SUCCESS);
        let ent = User { root: true, ents: vec![ent::SYSTEM_ALLOW] };
        assert_eq!(n.set_property(&ent, &sys("foo"), &s(b"1"), None), ret::SUCCESS);
        // No system region: the system namespace is kept as the common one.
        assert_eq!(n.copy_property(&root, b"foo"), Some(Value::Data(b"1".to_vec())));
        assert_eq!(n.copy_property(&root, b"boot-args"), Some(Value::String(b"-v".to_vec())));
        // Types: a string variable takes no data; boot-args is at most 1023.
        assert_eq!(n.set_property(&root, b"boot-args", &Given::Value(Value::Data(vec![])), None), ret::BAD_ARGUMENT);
        assert_eq!(n.set_property(&root, b"boot-args", &s(&[b'a'; 1024]), None), ret::NO_SPACE);
        assert_eq!(n.set_property(&root, b"boot-args", &s(&[b'a'; 768]), None), ret::SUCCESS);
        assert_eq!(n.set_property(&root, b"boot-args", &s(&[b'a'; 769]), None), ret::NO_SPACE);
        // Deletes: never-deletable and reset-only variables.
        assert_eq!(n.set_property(&root, b"testNeverDel", &s(b"1"), None), ret::SUCCESS);
        assert_eq!(n.set_property(&root, key::DELETE_WRET, &s(b"testNeverDel"), None), ret::NOT_PRIVILEGED);
        assert_eq!(n.set_property(&root, key::DELETE, &s(b"testNeverDel"), None), ret::SUCCESS);
        assert!(n.copy_property(&root, b"testNeverDel").is_some());
        assert_eq!(n.set_property(&root, key::DELETE_WRET, &s(b"absent"), None), ret::SUCCESS);
        assert_eq!(n.set_property(&root, key::DELETE, &Given::Value(Value::Data(vec![])), None), ret::ERROR);
        // The registry's own keys are never variables.
        assert_eq!(n.copy_property(&root, b"IOMatchCategory"), None);
    }

    #[test]
    fn a_full_region_refuses_a_set() {
        let (mut n, _) = boot(&factory_image());
        let room = (0x2000 - 48 - 11) as usize;
        let name = b"big";
        let fits = room - name.len() - 2;
        let d = |len: usize| Given::Value(Value::Data(vec![1; len]));
        assert_eq!(n.set_property(&Kernel, name, &d(fits + 1), None), ret::NO_SPACE);
        assert_eq!(n.set_property(&Kernel, name, &d(fits), None), ret::SUCCESS);
        assert_eq!(n.fmt.common_used, 0x2000 - 48);
    }

    #[test]
    fn sync_now_is_rate_limited() {
        let (mut n, m) = boot(&factory_image());
        let s = Given::Value(Value::String(b"1".to_vec()));
        assert_eq!(n.set_property_clocked(&Kernel, key::SYNC_NOW, &s, None, &At(10)), ret::SUCCESS);
        assert_eq!(*m.1.lock().unwrap(), 1);
        n.set_property(&Kernel, b"x", &Given::Value(Value::Data(vec![1])), None);
        // Within 15 minutes of the last: nothing.
        assert_eq!(n.set_property_clocked(&Kernel, key::SYNC_NOW, &s, None, &At(10 + 900)), ret::SUCCESS);
        assert_eq!(*m.1.lock().unwrap(), 1);
        assert_eq!(n.set_property_clocked(&Kernel, key::SYNC_NOW, &s, None, &At(10 + 901)), ret::SUCCESS);
        assert_eq!(*m.1.lock().unwrap(), 2);
        n.set_property(&Kernel, b"y", &Given::Value(Value::Data(vec![1])), None);
        assert_eq!(n.set_property_clocked(&Kernel, key::FORCE_SYNC_NOW, &s, None, &At(912)), ret::SUCCESS);
        assert_eq!(*m.1.lock().unwrap(), 3);
    }

    #[test]
    fn a_system_region_keeps_system_variables() {
        // A bank with a system partition before the common one.
        let mut b = vec![0u8; 0x2000];
        b[..16].copy_from_slice(&chrp::header(0x5a, 32, chrp::BANK_V1));
        b[32..48].copy_from_slice(&chrp::header(0x70, 0x400, chrp::SYSTEM_V1));
        b[0x420..0x430].copy_from_slice(&chrp::header(0x70, 0x2000 - 0x420, chrp::COMMON_V1));
        b[48..48 + 12].copy_from_slice(b"boot-args=-v");
        b[0x430..0x430 + 6].copy_from_slice(b"a=\xff\x03b\0");
        let a = chrp::bank_adler(&b);
        b[16..20].copy_from_slice(&a.to_le_bytes());
        let (mut n, m) = boot(&b);
        assert!(n.system_service);
        assert_eq!(n.copy_property(&Kernel, b"boot-args"), Some(Value::String(b"-v".to_vec())));
        assert_eq!(n.copy_property(&Kernel, b"a"), Some(Value::Data(vec![0, 0, 0, b'b'])));
        let root = User { root: true, ents: vec![] };
        assert_eq!(n.set_property(&root, b"root-live-fs", &Given::Value(Value::String(b"1".to_vec())), None), ret::SUCCESS);
        assert_eq!(n.variables()[2].0, canonical(&guid::SYSTEM, b"root-live-fs"));
        let names: Vec<Vec<u8>> = n.serialize_properties(&root).into_iter().map(|(k, _, _)| k).collect();
        assert_eq!(names, vec![b"boot-args".to_vec(), b"root-live-fs".to_vec(), b"a".to_vec()]);
        assert_eq!(n.sync(&At(0)), ret::SUCCESS);
        let img = m.0.lock().unwrap().clone();
        assert_eq!(&img[48..48 + 29], b"boot-args=-v\0root-live-fs=1\0\0");
        assert_eq!(&img[0x420..0x430], &b[0x420..0x430]);
        assert_eq!(&img[0x430..0x437], b"a=\xff\x03b\0\0");
    }
}
