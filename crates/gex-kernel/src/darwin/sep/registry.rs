//! The SEP's drivers in the registry's `IOService` plane, as the
//! kernelcache matches them over the device tree
//! (`drafts/sep/01-a7iop-mailbox.md` section 1):
//!
//! ```text
//!   sep                 AppleARMIODevice, a nub of /arm-io/sep
//!     AppleA7IOPV2      personality AppleA7IOPV2, IONameMatch "iop,s8000"
//!       iop-sep-nub     AppleA7IOPNub, a nub AppleA7IOP::start makes of the
//!                       device-tree child (compatible "iop-nub,sep")
//!         AppleSEPManager   personality A7IOPNub, IONameMatch "iop-nub,sep"
//! ```
//!
//! The manager's endpoint services (`sep-endpoint,<4cc>`) are published
//! as the SEP advertises its endpoints, which a running sepOS does and
//! this registry, made once at boot, has no entries for: they are reported
//! when the SEP advertises one ([`super::manager::Manager::take_gaps`]).
//!
//! Each driver's property table is its personality's and matching's keys
//! and what its start sets that was read; the rest is not modelled and is
//! reported when read ([`Table::Partial`]).

use crate::darwin::iokit::{Node, Prop, Table};
use crate::darwin::platform;

pub const A7IOP: &str = "AppleA7IOPV2";
pub const NUB: &str = "AppleA7IOPNub";
pub const MANAGER: &str = "AppleSEPManager";
pub const USER_CLIENT: &str = "AppleSEPUserClient";

/// The classes here, most derived first, each the superclass its
/// `OSMetaClass` constructor names (AppleIOP's is IOSlaveCPU's metaclass at
/// K 0xfffffff007ae77f8 through its GOT entry K 0xfffffff006d0e148; the
/// manager's is IOSlaveProcessor's, K 0xfffffff007ae7758; both of those
/// have IOService's, K 0xfffffff007942cb8).
pub fn superclasses(class: &str) -> &'static [&'static str] {
    match class {
        A7IOP => &[A7IOP, "AppleA7IOP", "AppleIOP", "IOSlaveCPU", "IOService", "IORegistryEntry"],
        NUB => &[NUB, "IOService", "IORegistryEntry"],
        MANAGER => &[MANAGER, "IOSlaveProcessor", "IOService", "IORegistryEntry"],
        USER_CLIENT => &[USER_CLIENT, "IOUserClient", "IOService", "IORegistryEntry"],
        _ => &[],
    }
}

/// Publish the drivers over `/arm-io/sep`; the manager's entry.
pub fn add(t: &mut Vec<Node>, io: u32) -> Option<u32> {
    let sep = platform::arm_io_nub(t, io, "sep")?;
    let nub_entry = platform::child(t, sep, "iop-sep-nub", &[])?;
    let sym = |s: &str| Prop::Sym(s.to_string());
    let driver = |name: &str, class: &'static str, parent: u32, service_props, why: &str| Node {
        name: name.to_string(),
        props: Vec::new(),
        class,
        service_props,
        parent: Some(parent),
        children: Vec::new(),
        kernel_only: false,
        nub: None,
        dt: None,
        table: Table::Partial(why.to_string()),
        power: None,
    };
    // AppleA7IOPV2: IONameMatch "iop,s8000" (the second of the node's compatible strings),
    // IOProviderClass AppleARMIODevice; AppleA7IOP::start sets "role" from the node's.
    let mut props = platform::driver_props("com.apple.driver.AppleA7IOP-AKFWrap-v2", A7IOP, platform::ARM_IO_DEVICE, Some("iop,s8000"), "IODefaultMatchCategory", 0, vec![("IONameMatch".to_string(), Prop::Str("iop,s8000".to_string()))]);
    props.push(("role".to_string(), Prop::Str("SEP".to_string())));
    let a7iop = t.len() as u32;
    t.push(driver(A7IOP, A7IOP, sep, props, "what AppleA7IOP::start sets beyond \"role\" (its power-management and IOFunctionParent keys)"));
    platform::make_nub(t, nub_entry, NUB, a7iop);
    // AppleSEPManager: personality A7IOPNub, IOPlatformQuiesceAction 89999, IONameMatch
    // "iop-nub,sep"; its start sets IOUserClientClass, and HasXART with the xART child.
    let mut props = platform::driver_props("com.apple.driver.AppleSEPManager", MANAGER, NUB, Some("iop-nub,sep"), "IODefaultMatchCategory", 0, vec![("IOPlatformQuiesceAction".to_string(), Prop::Num(89999, 64)), ("IONameMatch".to_string(), Prop::Str("iop-nub,sep".to_string()))]);
    if t[nub_entry as usize].children.iter().any(|&c| t[c as usize].name == "xART") {
        props.push(("HasXART".to_string(), Prop::Bool(true)));
    }
    props.push(("IOUserClientClass".to_string(), sym(USER_CLIENT)));
    let m = t.len() as u32;
    t.push(driver(MANAGER, MANAGER, nub_entry, props, "what AppleSEPManager::start sets besides IOUserClientClass and HasXART (its power-management keys, \"sep-booted\" and the order of them)"));
    Some(m)
}

#[cfg(test)]
mod tests {
    use super::super::super::iokit::{self, build};

    fn tree() -> Vec<iokit::Node> {
        let mut b = Vec::new();
        let node = |b: &mut Vec<u8>, name: &str, props: &[(&str, &[u8])], children: u32| {
            b.extend_from_slice(&(props.len() as u32 + 1).to_le_bytes());
            b.extend_from_slice(&children.to_le_bytes());
            let mut put = |k: &str, v: &[u8]| {
                let mut kk = [0u8; 32];
                kk[..k.len()].copy_from_slice(k.as_bytes());
                b.extend_from_slice(&kk);
                b.extend_from_slice(&(v.len() as u32).to_le_bytes());
                b.extend_from_slice(v);
                b.resize(b.len().div_ceil(4) * 4, 0);
            };
            put("name", &[name.as_bytes(), b"\0"].concat());
            for (k, v) in props {
                put(k, v);
            }
        };
        node(&mut b, "device-tree", &[("compatible", b"J120AP\0iPad7,1\0AppleARM\0")], 1);
        node(&mut b, "arm-io", &[("compatible", b"arm-io,t8011\0")], 1);
        node(&mut b, "sep", &[("compatible", b"iop,t8011\0iop,s8000\0"), ("role", b"SEP\0")], 1);
        node(&mut b, "iop-sep-nub", &[("compatible", b"iop-nub,sep\0"), ("rom-panic-bytes", &0x38u32.to_le_bytes())], 1);
        node(&mut b, "xART", &[], 0);
        build(&b).unwrap()
    }

    #[test]
    fn the_drivers_stand_over_the_sep_node() {
        let t = tree();
        let m = t.iter().position(|n| n.class == super::MANAGER).expect("the manager") as u32;
        let chain: Vec<&str> = std::iter::successors(Some(m), |&i| iokit::provider(&t, i).ok().flatten()).map(|i| iokit::name(&t, i)).collect::<Vec<_>>().iter().map(|s| Box::leak(s.clone().into_boxed_str()) as &str).collect();
        assert_eq!(&chain[..5], ["AppleSEPManager", "iop-sep-nub", "AppleA7IOPV2", "sep", "AppleT8011IO"]);
        assert_eq!(iokit::class(&t, m - 1 - 0).ok(), Some(super::A7IOP));
        assert!(iokit::conforms(&t, m, "IOService").unwrap() && iokit::conforms(&t, m, "IOSlaveProcessor").unwrap());
        let props = iokit::properties(&t, m);
        let get = |k: &str| props.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        assert_eq!(get("IONameMatch"), Some(iokit::Prop::Str("iop-nub,sep".into())));
        assert_eq!(get("IOUserClientClass"), Some(iokit::Prop::Sym("AppleSEPUserClient".into())));
        assert_eq!(get("HasXART"), Some(iokit::Prop::Bool(true)));
        // What its start sets beyond is not modelled, and reading it is reported.
        assert!(iokit::property_unknown(&t, m, "sep-booted"));
    }

    #[test]
    fn the_keys_only_the_device_tree_has_are_absent_where_it_lacks_them() {
        let t = tree();
        let sep = t.iter().position(|n| n.name == "sep" && n.nub.is_some()).unwrap() as u32;
        // seputil's search of the sep entry (options 0) for these: absent, not unmodelled.
        for key in ["sepfw-loaded", "sepfw-booted", "has-art", "ap-manifest", "aarch64", "skip-lynx", "pcie-up-interrupts"] {
            assert!(!iokit::property_unknown(&t, sep, key), "{key}");
            assert_eq!(iokit::lookup(&t, sep, key), Ok(None), "{key}");
            assert_eq!(iokit::search(&t, sep, iokit::Plane::DeviceTree, 0, key, |_| true), Ok((None, false)), "{key}");
        }
        // A key a driver may have set stays unknown there.
        assert!(iokit::property_unknown(&t, sep, "IOPowerManagement-unmodelled"));
        // And a device tree that has the key answers it.
        let mut t2 = tree();
        t2[sep as usize].props.push(("sepfw-loaded".into(), vec![1, 0, 0, 0]));
        assert_eq!(iokit::dt_prop(&t2, "IODeviceTree:/arm-io/sep", "sepfw-loaded"), Some(&[1u8, 0, 0, 0][..]));
        assert!(iokit::lookup(&t2, sep, "sepfw-loaded").unwrap().is_some());
    }
}
