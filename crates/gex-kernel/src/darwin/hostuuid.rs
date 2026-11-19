//! `gethostuuid` (bsd/kern/sys_generic.c:2192; 21H461 0xfffffff00766cf40):
//! the platform's UUID, the platform expert device's "IOPlatformUUID"
//! ([`super::platform::platform_uuid`]), through `IOBSDGetPlatformUUID`
//! (iokit/bsddev/IOKitBSDInit.cpp:1084; 0xfffffff0078529a8).
//!
//! - A caller without `com.apple.private.getprivatesysid` (an
//!   `IOCurrentTaskHasEntitlement` the kernel task never has) is asked of
//!   the MAC policies for "hw.uuid" (`mac_system_check_info`,
//!   0xfffffff007898414, which checks no enforcement switch): only
//!   Sandbox has the hook ([`Kernel::darwin_mac_check_system_info`]).
//!   Its error is the call's.
//! - The timeout, a `struct user64_timespec` (every Darwin process here is
//!   64-bit): its seconds as an `unsigned int` and its nanoseconds as a
//!   `clock_res_t`, the low 32 bits of each. A fault is the copyin's
//!   EFAULT.
//! - `IOBSDGetPlatformUUID` waits for the "IOPlatformUUID" resource
//!   (`waitForMatchingService` of `resourceMatching`, forever when both
//!   halves are zero, else for seconds * 10^9 + nanoseconds), then parses
//!   the platform expert device's property. A timeout or a missing
//!   property is EWOULDBLOCK; the 16 bytes are copied out (EFAULT on a
//!   fault).
//!
//! The resource is published by the platform expert's start or never
//! ([`super::platform`]), before any process runs; a call that would wait
//! for it is reported, since nothing here can publish it later
//! (`IOResources::setProperties` is not modelled).

use super::platform::{RESOURCES, UUID_KEY};
use crate::errno::Errno;
use crate::syscalls::Kernel;
use crate::GuestMem;

/// The entitlement that skips the MAC check.
pub const GETPRIVATESYSID: &str = "com.apple.private.getprivatesysid";

/// The information type the MAC policies are asked about.
pub const INFO_TYPE: &[u8] = b"hw.uuid";

impl Kernel {
    /// `gethostuuid(uuid_buf, timeoutp)`.
    pub(crate) fn darwin_gethostuuid(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let (buf, timeoutp) = (a[0], a[1]);
        if !self.darwin_entitled(GETPRIVATESYSID) {
            let e = self.darwin_mac_check_system_info(INFO_TYPE);
            if e != 0 {
                return Err(super::errno::errno_of(e as i32));
            }
        }
        let ts = m.read(timeoutp, 16).map_err(|_| Errno::EFAULT)?;
        let sec = u32::from_le_bytes(ts[0..4].try_into().unwrap());
        let nsec = i32::from_le_bytes(ts[8..12].try_into().unwrap());
        let uuid = match platform_uuid_bytes() {
            Ok(u) => u,
            Err(why) => {
                let wait = if sec == 0 && nsec == 0 { "forever".to_string() } else { format!("for {sec} s {nsec} ns") };
                self.darwin_unimplemented(format!("gethostuuid (waiting {wait}): {why}"));
                return Err(Errno::EAGAIN);
            }
        };
        m.write(buf, &uuid).map_err(|_| Errno::EFAULT)?;
        Ok(0)
    }
}

/// `IOBSDGetPlatformUUID`'s answer once the resource is there: the
/// platform expert device's "IOPlatformUUID" parsed. `Err` names what is
/// not there.
pub fn platform_uuid_bytes() -> Result<[u8; 16], String> {
    let t = super::iokit::tree();
    if t.is_empty() {
        return Err(format!("the {UUID_KEY} resource, which no platform expert publishes: the boot payload has no device tree"));
    }
    let published = t.iter().any(|n| n.class == RESOURCES && n.service_props.iter().any(|(k, _)| k == UUID_KEY));
    if !published {
        return Err(format!("the {UUID_KEY} resource, which no platform expert's start published (generatePlatformUUID makes no UUID when /chosen lacks a unique-chip-id of 8 bytes or a chip-id of 4, and AppleARMPE starts only on a root that names AppleARM)"));
    }
    match super::iokit::service_prop(&t[0], UUID_KEY) {
        Some(super::iokit::Prop::Str(s)) => super::platform::uuid_parse(s).ok_or_else(|| format!("the platform expert device's {UUID_KEY} {s:?}, which is not a UUID")),
        _ => Err(format!("the platform expert device's {UUID_KEY}, which the resource is published without")),
    }
}
