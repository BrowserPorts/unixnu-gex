//! AppleSEPUserClient: the dispatch table of 84 selectors at K
//! 0xfffffff006eb6950 (24-byte `IOExternalMethodDispatch` entries) and the
//! selectors the data-protection boot reaches (`drafts/sep/04-userclient-idp.md`).
//!
//! `init_data_protection` opens the client with type 0 (the type is
//! ignored), asks the xART gigalocker to initialise (selector 44, which
//! needs no running SEP) and, unless the firmware is preloaded, sends the
//! sepOS to the SEP (selector 6, whose boot handshake is the SEP ROM's).
//! Every other selector needs the SEP/OS running, a SEP ROM or an endpoint
//! service this port does not have; each reports itself and answers with
//! what the kernel answers when the SEP is not there.

use super::manager::{io, MgrError};
use crate::darwin::iokit::{self, ret, Dispatch, MethodArgs, VARIABLE as V};
use crate::syscalls::Kernel;

/// The entitlement `initWithTask` requires (`copyClientEntitlement`, K
/// 0xfffffff0063c31f8); without it IOServiceOpen fails with
/// kIOReturnBadArgument.
pub const ENTITLEMENT: &str = "com.apple.private.applesepmanager.allow";

/// What a selector needs beyond the AP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Needs {
    /// The AP alone.
    Host,
    /// The SEP ROM and the AP's manager.
    Boot,
    /// The SEP/OS running, or an endpoint service it publishes.
    SepOs,
}

/// One entry: the selector's name (the kext's `Dispatch*` names, else the
/// option of seputil that calls it), the four counts of its dispatch entry,
/// and what it needs. `None` counts: a NULL function.
pub struct Entry {
    pub name: &'static str,
    pub counts: Option<[u32; 4]>,
    pub needs: Needs,
}

const fn e(name: &'static str, a: u32, b: u32, c: u32, d: u32, needs: Needs) -> Entry {
    Entry { name, counts: Some([a, b, c, d]), needs }
}

const NULL: Entry = Entry { name: "(no function)", counts: None, needs: Needs::Host };

use Needs::{Boot, Host, SepOs};

/// The table, index = selector.
pub const TABLE: [Entry; 84] = [
    e("ping", 0, 0, 0, 0, SepOs),
    e("sleep", 0, 0, 0, 0, SepOs),
    e("nap", 0, 0, 0, 0, SepOs),
    e("rom command", 1, 0, 1, 0, Boot),
    e("security mode", 0, 0, 1, 0, SepOs),
    e("control message 0x0a", 1, 0, 0, 0, SepOs),
    e("LoadFirmware", 3, V, 0, 0, Boot),
    e("LoadRestoreFirmware", 3, V, 0, 0, Boot),
    e("LoadRestoreFirmwareWithART", 3, V, 0, 0, Boot),
    e("CommitHash", 0, 0, 0, 0, SepOs),
    e("erase install notification", 0, 0, 0, 0, SepOs),
    e("L4 panic notification", 0, 0, 0, 0, SepOs),
    e("SEP/OS panic notification", 0, 0, 0, 0, SepOs),
    e("mailbox log size", 0, 0, 1, 0, Host),
    e("mailbox raw log", 0, 0, 2, V, Host),
    e("new nonce", 0, 0, 0, 20, SepOs),
    e("InvalidateNonce", 0, 0, 0, 0, SepOs),
    NULL,
    e("GetART", 0, 0, 0, 2048, Host),
    e("SetART", 0, 2048, 0, 0, SepOs),
    e("ClearART", 0, 0, 0, 0, SepOs),
    e("PairKey", 1, V, 0, 12288, SepOs),
    e("testing: run with input", 1, V, 1, 0, SepOs),
    e("testing: get output", 0, 0, 1, V, SepOs),
    e("testing", 0, 0, 3, 0, SepOs),
    e("testing: RunAll", 1, 0, 0, 0, SepOs),
    e("testing: QueryTests", 0, 0, 1, V, SepOs),
    e("testing: RunAll (variant)", 0, 0, 1, V, SepOs),
    e("testing: RunCat", 1, 0, 0, V, SepOs),
    e("testing: RunHandle", 2, 0, 1, 0, SepOs),
    e("testing: GetResult", 0, 0, 0, V, SepOs),
    e("debug objects: create", 1, V, 0, 0, SepOs),
    e("debug objects: share", 1, 4, 0, 0, SepOs),
    e("debug objects: read", 3, 0, 3, 1024, SepOs),
    e("debug objects: write", 3, V, 3, 0, SepOs),
    e("RNG dump", 1, 0, 1, 1024, SepOs),
    e("CounterSelfTest", 0, 0, 2, 0, SepOs),
    NULL,
    NULL,
    NULL,
    NULL,
    e("LcrtVerify", 0, V, 0, 0, SepOs),
    e("LynxGetCPSN", 0, 0, 0, V, SepOs),
    e("LynxGetPubKey", 0, 0, 0, V, SepOs),
    e("GigalockerInit", 0, 1024, 0, 0, Host),
    e("GigalockerStressTest", 0, 1024, 0, 0, Host),
    e("GigalockerShutdown", 0, 0, 0, 0, SepOs),
    e("EraseAllContentAndSettings", 0, 0, 0, 0, SepOs),
    e("Hilo AccumulateTestPattern", 1, 0, 0, 0, SepOs),
    e("Hilo CheckGainTestPattern", 1, 0, 0, 0, SepOs),
    e("Hilo GetLthBackup", 0, 0, 0, V, SepOs),
    e("Hilo LoadLthBackup", 0, V, 0, 0, SepOs),
    e("Hilo GetLthRaw", 0, 0, 0, V, SepOs),
    e("Hilo UpdateTimer", 0, 0, 0, 0, SepOs),
    e("Hilo LoadLthRaw", 0, V, 0, 0, SepOs),
    e("Hilo GetDisasterRecoveryLthBackup", 0, 0, 0, V, SepOs),
    e("Hilo LoadDisasterRecoveryLthBackup", 0, V, 0, 0, SepOs),
    e("Hilo GetDisplayParams", 0, 0, 0, 10, SepOs),
    e("Hilo SetGainParamSet", 1, 0, 0, 0, SepOs),
    e("Hilo TestLthTransferAttestation", 0, 64, 0, 0, SepOs),
    e("Hilo GetLthTransferAttestation", 0, 0, 0, 176, SepOs),
    e("Hilo GetLthTransferMessage", 2, V, 0, 3145856, SepOs),
    e("Hilo LoadLthTransferMessage", 0, V, 0, 0, SepOs),
    e("Hilo AdvanceGainRestrictionPhase", 0, 0, 0, 0, SepOs),
    e("Hilo TestGainRestriction", 1, 0, 0, 0, SepOs),
    e("debug: process info", 1, 0, 1, 1024, SepOs),
    e("PurgeSystemToken", 0, 0, 0, 0, SepOs),
    e("new ROM nonce", 0, 0, 0, 20, Boot),
    e("get nonce", 0, 0, 0, 20, SepOs),
    e("request panic", 0, 0, 0, 0, Host),
    e("selector 70 (not traced)", 1, 0, 0, 0, SepOs),
    e("DiscoveryGetEndpointInfo", 0, 0, 0, V, Boot),
    NULL,
    e("selector 73 (not traced)", 0, 0, 0, 3, SepOs),
    e("testing: list variables", 1, 0, 0, 0, SepOs),
    e("debug variable get", 1, 28, 3, 0, SepOs),
    e("debug variable set", 2, 28, 0, 0, SepOs),
    NULL,
    NULL,
    NULL,
    NULL,
    e("selector 81 (not traced)", 0, 0, 0, 0, SepOs),
    e("DynamicObjectOp", 2, 0, 0, 0, Boot),
    e("testing: tunable check mode", 1, 0, 0, 0, SepOs),
];

/// The dispatch entry's checks of selector `sel`, when it has a function.
pub fn dispatch(sel: u32) -> Option<Dispatch> {
    let c = TABLE.get(sel as usize)?.counts?;
    Some(Dispatch { scalar_in: c[0], struct_in: c[1], scalar_out: c[2], struct_out: c[3] })
}

/// `AppleSEPUserClient::initWithTask`: the caller must hold the
/// entitlement; the open type is ignored.
pub fn open(k: &Kernel) -> Result<(), i32> {
    if k.darwin_entitled(ENTITLEMENT) {
        Ok(())
    } else {
        Err(ret::BAD_ARGUMENT)
    }
}

/// What a failure of the manager is, reported and answered: a gap says
/// what is missing (strict mode stops there), a kernel panic is reported
/// (this port does not stop the machine for it), an IOReturn is returned.
fn answer(k: &mut Kernel, what: &str, e: MgrError) -> i32 {
    match e {
        MgrError::Io(c) => c,
        MgrError::CoreGone(why) => {
            k.darwin_unimplemented(format!("AppleSEPUserClient {what}: {why}"));
            io::NOT_READY
        }
        MgrError::Unimplemented(s) => {
            k.darwin_unimplemented(format!("AppleSEPUserClient {what}: {s}"));
            io::UNSUPPORTED
        }
        MgrError::Panic(s) => {
            k.darwin_unimplemented(format!("AppleSEPUserClient {what}: the kernel panics here ({s}); the machine's panic is not modelled for it"));
            io::ERROR
        }
    }
}

/// `externalMethod`: the table's checks, then the selector.
pub fn external_method(k: &mut Kernel, a: &mut MethodArgs) -> i32 {
    let Some(entry) = TABLE.get(a.selector as usize) else { return iokit::no_method(a) };
    let Some(d) = dispatch(a.selector) else {
        // A NULL function: the base class checks the counts (all zero here) and
        // answers kIOReturnNoCompletion.
        return match iokit::dispatch_check(&Dispatch { scalar_in: 0, struct_in: 0, scalar_out: 0, struct_out: 0 }, a) {
            Ok(()) => ret::NO_COMPLETION,
            Err(c) => c,
        };
    };
    if let Err(c) = iokit::dispatch_check(&d, a) {
        return c;
    }
    match a.selector {
        6..=8 => load_firmware(k, a),
        44 => gigalocker_init(k, a),
        _ => {
            let why = match entry.needs {
                Needs::Host => "a host-side method of the AP that is not ported",
                Needs::Boot => "the SEP ROM, whose boot protocol is not answered by anything here",
                Needs::SepOs => "the SEP/OS running (or an endpoint service it publishes)",
            };
            let mut text = format!("selector {} ({}) needs {why}", a.selector, entry.name);
            if entry.needs != Needs::Host {
                let i = super::inputs();
                if i.sepos.is_none() {
                    text.push_str(&format!("; {}", super::core::Gap::NoSepOs));
                }
            }
            k.darwin_unimplemented(format!("AppleSEPUserClient {text}"));
            // The kernel's answer for a SEP that is not receptive.
            io::NOT_READY
        }
    }
}

/// Selectors 6, 7 and 8: `setFirmwareBytes` with the user's buffer
/// (a descriptor is required) and the scalars `{firmware, patches, uStuff}`.
fn load_firmware(k: &mut Kernel, a: &mut MethodArgs) -> i32 {
    let (restore, with_art) = match a.selector {
        6 => (false, true),
        7 => (true, false),
        _ => (true, true),
    };
    let Some((addr, len)) = a.ool_in else { return io::BAD_ARGUMENT };
    let name = TABLE[a.selector as usize].name;
    // Without a decrypted sepOS nothing can answer the ROM: say so before anything is copied.
    let inputs = super::inputs();
    if inputs.sepos.is_none() {
        k.darwin_unimplemented(format!("AppleSEPUserClient {name}: {}", super::core::Gap::NoSepOs));
        return io::NOT_READY;
    }
    let data = match k.darwin_vm_copyin(addr, len) {
        Ok(d) => d,
        Err(_) => return ret::VM_ERROR,
    };
    let sep = match super::system(iokit::tree()) {
        Ok(s) => s,
        Err(e) => return answer(k, name, e),
    };
    let lens = [a.scalar_in[0], a.scalar_in[1], a.scalar_in[2]];
    let r = sep.mgr.set_firmware_bytes(&data, lens, restore, with_art);
    for g in sep.mgr.take_gaps() {
        k.darwin_unimplemented(format!("AppleSEPManager: {g}"));
    }
    match r {
        Ok(()) => ret::SUCCESS,
        Err(e) => answer(k, name, e),
    }
}

/// Selector 44, `GigalockerInit` (K 0xfffffff0063c1c48): the structure is a
/// C string, the gigalocker file's path; the manager needs the `xART`
/// child of its provider in the device tree. Which of the SEP's xART
/// endpoints then initialise the gigalocker is the SEP's to ask for
/// (`checkInMaster`), so nothing here reads the file.
fn gigalocker_init(k: &mut Kernel, a: &mut MethodArgs) -> i32 {
    let bytes = match a.ool_in {
        None => a.struct_in.clone(),
        Some((addr, len)) => match k.darwin_vm_copyin(addr, len) {
            Ok(b) => b,
            Err(_) => return ret::VM_ERROR,
        },
    };
    let t = iokit::tree();
    if !iokit::dt_has(t, "IODeviceTree:/arm-io/sep/iop-sep-nub/xART") {
        return ret::BAD_ARGUMENT;
    }
    // strnlen(s, len) < len and < 0x400, else kIOReturnIOError.
    let n = bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len());
    if n >= bytes.len() || n >= 0x400 {
        return 0xe00002ca_u32 as i32;
    }
    let path = String::from_utf8_lossy(&bytes[..n]).into_owned();
    let sep = match super::system(t) {
        Ok(s) => s,
        Err(e) => return answer(k, "GigalockerInit", e),
    };
    let mut g = sep.gigalocker.lock().unwrap_or_else(|e| e.into_inner());
    if g.is_some() {
        // `_setGigalockerAvailable` requires the migrate status to be 0 or 2, which a second
        // call has (2): it sets the path again.
    }
    *g = Some(path.clone());
    drop(g);
    // The SEP-driven xART master has not checked in (the SEP is not running), so the
    // call returns 0 and the gigalocker is opened when it does.
    if sep.mgr.endpoint_service(super::frame::name::XART_MASTER).is_some() {
        k.darwin_unimplemented(format!("AppleSEPXART::gl_initialize({path}): the gigalocker's open, record repair and CRC (05-xart-art.md) is not ported"));
        return io::UNSUPPORTED;
    }
    ret::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_the_kexts() {
        assert_eq!(TABLE.len(), 84);
        let nulls: Vec<usize> = (0..84).filter(|&i| TABLE[i].counts.is_none()).collect();
        assert_eq!(nulls, [17, 37, 38, 39, 40, 72, 77, 78, 79, 80]);
        assert_eq!(dispatch(6), Some(Dispatch { scalar_in: 3, struct_in: V, scalar_out: 0, struct_out: 0 }));
        assert_eq!(dispatch(44), Some(Dispatch { scalar_in: 0, struct_in: 1024, scalar_out: 0, struct_out: 0 }));
        assert_eq!(dispatch(61), Some(Dispatch { scalar_in: 2, struct_in: V, scalar_out: 0, struct_out: 3145856 }));
        assert_eq!(dispatch(75), Some(Dispatch { scalar_in: 1, struct_in: 28, scalar_out: 3, struct_out: 0 }));
        assert_eq!(dispatch(84), None);
        assert_eq!(TABLE[6].name, "LoadFirmware");
        assert_eq!(TABLE[44].name, "GigalockerInit");
        assert_eq!(TABLE[71].name, "DiscoveryGetEndpointInfo");
    }

    #[test]
    fn the_load_selectors_are_the_three_variants() {
        for s in 6..=8 {
            assert_eq!(TABLE[s].needs, Needs::Boot);
        }
    }
}
