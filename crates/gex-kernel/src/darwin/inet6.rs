//! The inet6 domain (`PF_INET6`, 30) for a Darwin process: socket creation
//! through `inet6sw` as `socreate_internal` looks its protocols up
//! (`bsd/netinet6/in6_proto.c`, `bsd/kern/uipc_domain.c`), the UDP and TCP
//! sockets `udp6_attach` and `tcp_attach` make, and the loopback
//! interface's IPv6 addresses as `in6_control`'s `SIOCAIFADDR_IN6` keeps
//! them (`bsd/netinet6/in6.c`, `in6_ifattach.c`, `scope6.c`,
//! `in6_src.c`; xnu-10063.141.1), in the kernel's embedded-scope form
//! (`in6_embedded_scope` is 1 and no boot argument changes it).
//!
//! An inet6 socket is made and takes the socket layer's calls (its options
//! at `SOL_SOCKET`, the readiness of a socket with nothing bound,
//! connected or queued); its protocols' own calls (binding, connecting,
//! sending, receiving, the `IPPROTO_IPV6` options) are not modelled and say
//! so. The routes, the neighbor-discovery prefixes and the multicast
//! memberships an address brings are not kept: nothing here reads them
//! (route sockets, the `NET_RT_*` sysctls, the nd6 ioctls and the inet6
//! data path are not modelled and say so).

use super::bsd::sys;
use super::errno::EOPNOTSUPP;
use crate::errno::Errno;
use crate::syscalls::Kernel;
use crate::vfs::{FileHandle, FileType, Metadata, SoState};
use crate::GuestMem;
use std::sync::{Arc, Mutex};

/// `AF_INET6`.
pub const AF_INET6: u8 = 30;
/// `sizeof(struct sockaddr_in6)`.
pub const SOCKADDR_IN6_LEN: usize = 28;
/// `IFNAMSIZ`.
const IFNAMSIZ: usize = 16;
/// `EADDRNOTAVAIL`, in this kernel's numbering.
const EADDRNOTAVAIL: Errno = Errno(99);

const SOCK_STREAM: i32 = 1;
const SOCK_DGRAM: i32 = 2;
const SOCK_RAW: i32 = 3;
const IPPROTO_IPV4: i32 = 4;
const IPPROTO_TCP: i32 = 6;
const IPPROTO_UDP: i32 = 17;
const IPPROTO_IPV6: i32 = 41;
const IPPROTO_ROUTING: i32 = 43;
const IPPROTO_FRAGMENT: i32 = 44;
const IPPROTO_ESP: i32 = 50;
const IPPROTO_AH: i32 = 51;
const IPPROTO_ICMPV6: i32 = 58;
const IPPROTO_DSTOPTS: i32 = 60;
const IPPROTO_RAW: i32 = 255;

/// What a protocol of `inet6sw` attaches with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Usr {
    /// `nousrreqs`, whose `pru_attach` `pru_sanitize` fills with
    /// `pru_attach_notsupp`.
    NotSupp,
    Udp,
    Tcp,
    /// `rip6_usrreqs`.
    Rip6,
    /// `icmp6_dgram_usrreqs`.
    Icmp6Dgram,
}

/// `inet6sw`, in the order `in6_dinit` adds it to the domain (each at the
/// tail), as (`pr_type`, `pr_protocol`, user requests). IPsec's AH and ESP
/// entries (`IPSEC`, `IPSEC_ESP`), which sit between FRAGMENT and IPV4,
/// are left out: a lookup that could land on them is not answered here
/// ([`lookup`]).
const INET6SW: [(i32, i32, Usr); 12] = [
    (0, IPPROTO_IPV6, Usr::NotSupp),
    (SOCK_DGRAM, IPPROTO_UDP, Usr::Udp),
    (SOCK_STREAM, IPPROTO_TCP, Usr::Tcp),
    (SOCK_RAW, IPPROTO_RAW, Usr::Rip6),
    (SOCK_RAW, IPPROTO_ICMPV6, Usr::Rip6),
    (SOCK_DGRAM, IPPROTO_ICMPV6, Usr::Icmp6Dgram),
    (SOCK_RAW, IPPROTO_DSTOPTS, Usr::NotSupp),
    (SOCK_RAW, IPPROTO_ROUTING, Usr::NotSupp),
    (SOCK_RAW, IPPROTO_FRAGMENT, Usr::NotSupp),
    (SOCK_RAW, IPPROTO_IPV4, Usr::Rip6),
    (SOCK_RAW, IPPROTO_IPV6, Usr::Rip6),
    (SOCK_RAW, 0, Usr::Rip6),
];

/// An inet6 socket's protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Udp,
    Tcp,
}

impl Proto {
    /// `so_type`.
    pub fn ty(self) -> u32 {
        match self {
            Proto::Udp => SOCK_DGRAM as u32,
            Proto::Tcp => SOCK_STREAM as u32,
        }
    }

    /// `so_protocol` (`pr_protocol`).
    pub fn protocol(self) -> u32 {
        match self {
            Proto::Udp => IPPROTO_UDP as u32,
            Proto::Tcp => IPPROTO_TCP as u32,
        }
    }

    /// The buffers `soreserve` gives the attached socket, receive and send:
    /// [`udp_recvspace`] and `udp_sendspace`, or `tcp_recvspace` and
    /// `tcp_sendspace`.
    fn hiwat(self) -> (u64, u64) {
        match self {
            Proto::Udp => (udp_recvspace(), 9216),
            Proto::Tcp => (1448 * 384, 1448 * 256),
        }
    }
}

/// What `socreate_internal` makes of a type and protocol in the inet6
/// domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    Made(Proto),
    Refused(Errno),
    /// A protocol whose attachment is not modelled.
    Unported(&'static str),
}

/// `socreate_internal`'s protocol lookup in the inet6 domain:
/// `pffindproto` for a protocol (an exact match, else the raw wildcard for
/// SOCK_RAW), `pffindtype` (the first protocol of the type) for none;
/// nothing found is `EPROTOTYPE` when the protocol is in the domain under
/// another type, else `EPROTONOSUPPORT`; a found protocol of another type
/// is `EPROTOTYPE`; then its `pru_attach`.
pub fn lookup(ty: i32, protocol: i32) -> Lookup {
    if matches!(protocol, IPPROTO_AH | IPPROTO_ESP) {
        return Lookup::Unported("IPsec's AH and ESP protocols of the inet6 domain");
    }
    let found = if protocol != 0 {
        let exact = INET6SW.iter().find(|p| p.1 == protocol && p.0 == ty);
        exact.or_else(|| if ty == SOCK_RAW { INET6SW.iter().find(|p| p.0 == SOCK_RAW && p.1 == 0) } else { None })
    } else {
        INET6SW.iter().find(|p| p.0 != 0 && p.0 == ty)
    };
    let Some(&(pr_type, _, usr)) = found else {
        if protocol != 0 && INET6SW.iter().any(|p| p.1 == protocol) {
            return Lookup::Refused(Errno::EPROTOTYPE);
        }
        return Lookup::Refused(Errno::EPROTONOSUPPORT);
    };
    if pr_type != ty {
        return Lookup::Refused(Errno::EPROTOTYPE);
    }
    match usr {
        Usr::NotSupp => Lookup::Refused(EOPNOTSUPP),
        Usr::Udp => Lookup::Made(Proto::Udp),
        Usr::Tcp => Lookup::Made(Proto::Tcp),
        Usr::Rip6 => Lookup::Unported("a raw inet6 socket (rip6_attach)"),
        Usr::Icmp6Dgram => Lookup::Unported("an ICMPv6 datagram socket (icmp6_dgram_attach)"),
    }
}

/// The name of an inet6 socket bound to nothing (`in6_mapped_sockaddr`: a
/// UDP socket, `INP_IPV4` set with mapped addresses on, has its inet name
/// mapped, which for 0.0.0.0 port 0 is `::`; a TCP one its own): `::`,
/// port 0, scope 0.
pub fn unbound_name() -> Vec<u8> {
    Sin6 { len: SOCKADDR_IN6_LEN as u8, family: AF_INET6, ..Default::default() }.bytes().to_vec()
}

/// An inet6 socket, bound to nothing and connected to nothing.
#[derive(Debug)]
pub struct Inet6Socket {
    pub proto: Proto,
}

impl FileHandle for Inet6Socket {
    // The data path is not modelled: the calls that read and write are
    // refused before they get here (`Kernel::darwin_inet6_call`).
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> crate::errno::SysResult {
        Err(EOPNOTSUPP)
    }

    fn write_at(&self, _offset: u64, _buf: &[u8]) -> crate::errno::SysResult {
        Err(EOPNOTSUPP)
    }

    /// `soo_stat`'s mode for a socket that can still receive and send.
    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(Metadata { file_type: FileType::Socket, size: 0, mode: 0o666, ino: 0, mtime: 0, nlink: 0, rdev: 0, times: Default::default() })
    }

    fn is_stream(&self) -> bool {
        true
    }

    fn available(&self) -> Option<u64> {
        Some(0)
    }

    /// `soreadable`: nothing received, nothing to accept, no error.
    fn poll_readable(&self) -> bool {
        false
    }

    /// `sowriteable`: send space, and a protocol that needs no connection
    /// (UDP) or a connection (TCP, which has none).
    fn poll_writable(&self) -> bool {
        self.proto == Proto::Udp
    }

    fn so_state(&self) -> Option<SoState> {
        let udp = self.proto == Proto::Udp;
        Some(SoState {
            qlen: None,
            rcv: 0,
            cantrcv: false,
            cantsend: false,
            error: 0,
            can_write: udp,
            snd_used: 0,
            hiwat: self.proto.hiwat(),
            // soreserve's MCLBYTES.
            snd_lowat: 2048,
            unix_stream: false,
            ctl: 0,
            records: udp.then_some((0, 0)),
            exact: true,
            peer_space: None,
            snd_mbmax: None,
            unp_cc: 0,
            live_hiwat: false,
        })
    }

    fn as_darwin_inet6(self: Arc<Self>) -> Option<Arc<Inet6Socket>> {
        Some(self)
    }
}

/// A `struct sockaddr_in6`: length, family, port and flow information (in
/// network order, as given), address, scope.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sin6 {
    pub len: u8,
    pub family: u8,
    pub port: [u8; 2],
    pub flowinfo: [u8; 4],
    pub addr: [u8; 16],
    pub scope_id: u32,
}

impl Sin6 {
    /// The structure at the start of `b` (28 bytes).
    pub fn read(b: &[u8]) -> Sin6 {
        Sin6 {
            len: b[0],
            family: b[1],
            port: [b[2], b[3]],
            flowinfo: b[4..8].try_into().unwrap(),
            addr: b[8..24].try_into().unwrap(),
            scope_id: u32::from_le_bytes(b[24..28].try_into().unwrap()),
        }
    }

    pub fn bytes(&self) -> [u8; SOCKADDR_IN6_LEN] {
        let mut b = [0u8; SOCKADDR_IN6_LEN];
        b[0] = self.len;
        b[1] = self.family;
        b[2..4].copy_from_slice(&self.port);
        b[4..8].copy_from_slice(&self.flowinfo);
        b[8..24].copy_from_slice(&self.addr);
        b[24..28].copy_from_slice(&self.scope_id.to_le_bytes());
        b
    }
}

/// The address classes of `bsd/netinet6/in6.h`.
mod class {
    pub fn unspecified(a: &[u8; 16]) -> bool {
        *a == [0; 16]
    }
    pub fn loopback(a: &[u8; 16]) -> bool {
        a[..15] == [0; 15] && a[15] == 1
    }
    pub fn multicast(a: &[u8; 16]) -> bool {
        a[0] == 0xff
    }
    pub fn linklocal(a: &[u8; 16]) -> bool {
        a[0] == 0xfe && a[1] & 0xc0 == 0x80
    }
    pub fn v4mapped(a: &[u8; 16]) -> bool {
        a[..10] == [0; 10] && a[10] == 0xff && a[11] == 0xff
    }
    /// `::a.b.c.d`, but neither `::` nor `::1`.
    pub fn v4compat(a: &[u8; 16]) -> bool {
        let last = u32::from_be_bytes([a[12], a[13], a[14], a[15]]);
        a[..12] == [0; 12] && last != 0 && last != 1
    }
    /// `IN6_IS_ADDR_MC_LINKLOCAL`: not a unicast-prefix-based group.
    pub fn mc_linklocal(a: &[u8; 16]) -> bool {
        multicast(a) && a[1] & 0xf0 != 0x30 && a[1] & 0x0f == 2
    }
    pub fn mc_intfacelocal(a: &[u8; 16]) -> bool {
        multicast(a) && a[1] & 0x0f == 1
    }
    /// `IN6_IS_SCOPE_LINKLOCAL`.
    pub fn scope_linklocal(a: &[u8; 16]) -> bool {
        linklocal(a) || mc_linklocal(a)
    }
    /// The addresses whose zone the kernel keeps in `s6_addr16[1]`.
    pub fn zoned(a: &[u8; 16]) -> bool {
        scope_linklocal(a) || mc_intfacelocal(a)
    }
}

/// `lo0`'s interface index: `if_next_index` gives the first interface
/// attached 1, and `bsd_init`'s `loopattach` (after `bsd_autoconf`) is the
/// first `ifnet_attach`: IONetworkingFamily's IONetworkStack attaches no
/// published interface until configd's InterfaceNamer names it
/// (`interfacePublished` leaves it in `_ifListNaming`), and gif and the
/// other cloned interfaces are made later.
pub const LO0_INDEX: u16 = 1;

/// `udp_recvspace` once `udp_init` has run: 786896 for an mbuf pool
/// (`nmbclusters` 2 KB clusters) of 96 MB or more, else its initial
/// `187 * (1024 + sizeof(struct sockaddr_in6))`. With no `ncl` or
/// `mbuf_pool` boot argument, `bsd_mbuf_cluster_reserve` sizes the pool by
/// `mbuf_default_ncl(mem_actual)` (`ncl_table`), rounded down to whole
/// 16 KiB pages of clusters; `mem_actual` is iBoot's `memSizeActual`, a
/// fact of the device answered with the 4 GiB stand-in
/// ([`MEM_ACTUAL_STAND_IN`]).
pub fn udp_recvspace() -> u64 {
    const MB: u64 = 1 << 20;
    const GB: u64 = 1 << 30;
    const MCLSHIFT: u32 = 11;
    const NCLPG: u64 = 16384 >> MCLSHIFT;
    // ncl_table: (nt_maxmem, nt_mbpool).
    const NCL_TABLE: [(u64, u64); 5] = [(GB, 64 * MB), (4 * GB, 96 * MB), (8 * GB, 128 * MB), (16 * GB, 256 * MB), (32 * GB, 512 * MB)];
    let mem = super::mig::machine::MEMORY;
    let mut pool = NCL_TABLE[0].1;
    for (maxmem, mbpool) in NCL_TABLE {
        if mem < maxmem {
            break;
        }
        pool = mbpool;
    }
    let nmbclusters = (pool >> MCLSHIFT) / NCLPG * NCLPG;
    if (nmbclusters << MCLSHIFT) >> 20 >= 96 {
        786896
    } else {
        187 * (1024 + 28)
    }
}

/// The stand-in [`udp_recvspace`] rests on, as gexc reports it.
pub const MEM_ACTUAL_STAND_IN: &str = "the device's physical memory size (iBoot's memSizeActual, mem_actual: hw.memsize, and the mbuf pool's tier that sets udp_recvspace) (stand-in 4 GiB, so a 96 MB pool and udp_recvspace 786896; under 4 GiB the pool is 64 MB and udp_recvspace 196724; measure `sysctl hw.memsize hw.memsize_physical net.inet.udp.recvspace` on the device)";

/// The zone embedded in a scoped address (`ntohs(s6_addr16[1])`).
fn zone(a: &[u8; 16]) -> u16 {
    u16::from_be_bytes([a[2], a[3]])
}

fn set_zone(a: &mut [u8; 16], z: u16) {
    a[2..4].copy_from_slice(&z.to_be_bytes());
}

/// `in6_addrscope`'s scopes.
const SCOPE_INTFACELOCAL: u8 = 0x01;
const SCOPE_LINKLOCAL: u8 = 0x02;
const SCOPE_SITELOCAL: u8 = 0x05;
const SCOPE_GLOBAL: u8 = 0x0e;

/// `in6_addrscope`: `::1` is link-local, `::` global.
fn addrscope(a: &[u8; 16]) -> u8 {
    if a[0] == 0xfe {
        return match a[1] & 0xc0 {
            0x80 => SCOPE_LINKLOCAL,
            0xc0 => SCOPE_SITELOCAL,
            _ => SCOPE_GLOBAL,
        };
    }
    if a[0] == 0xff {
        return match a[1] & 0x0f {
            SCOPE_INTFACELOCAL => SCOPE_INTFACELOCAL,
            SCOPE_LINKLOCAL => SCOPE_LINKLOCAL,
            SCOPE_SITELOCAL => SCOPE_SITELOCAL,
            _ => SCOPE_GLOBAL,
        };
    }
    if class::loopback(a) {
        return SCOPE_LINKLOCAL;
    }
    SCOPE_GLOBAL
}

/// `in6_addr2scopeid` on lo0: `scope6_ifattach` set its interface-local
/// and link-local zones to its index; the others (no `MULTI_SCOPE`) are 0.
fn addr2scopeid(a: &[u8; 16]) -> u32 {
    match addrscope(a) {
        SCOPE_INTFACELOCAL | SCOPE_LINKLOCAL => u32::from(LO0_INDEX),
        _ => 0,
    }
}

/// `in6_to_kamescope` on lo0: the address in the kernel's form, its zone
/// embedded and its scope field cleared. `in6_recoverscope` takes the zone
/// from the address (one not lo0's is ENXIO), the scope field of the
/// result is that or the address's default zone (another is EINVAL), and
/// `in6_embedscope` writes it back into the address.
fn to_kamescope(sin6: &mut Sin6) -> Result<(), Errno> {
    let mut tmp = *sin6;
    tmp.scope_id = 0;
    if class::zoned(&tmp.addr) {
        let z = zone(&tmp.addr);
        if z != 0 {
            if z != LO0_INDEX {
                return Err(Errno::ENXIO);
            }
            set_zone(&mut tmp.addr, 0);
            tmp.scope_id = u32::from(z);
        }
    }
    let id = addr2scopeid(&tmp.addr);
    if tmp.scope_id == 0 {
        tmp.scope_id = id;
    } else if tmp.scope_id != id {
        return Err(Errno::EINVAL);
    }
    if class::zoned(&tmp.addr) && tmp.scope_id != 0 {
        set_zone(&mut tmp.addr, tmp.scope_id as u16);
    }
    tmp.scope_id = 0;
    *sin6 = tmp;
    Ok(())
}

/// `in6_mask2len(mask, lim0)`: the prefix length of a mask, its bytes up
/// to `lim` (`lim0 - mask`, unsigned: a negative or a too-long one is all
/// 16) looked at; a bit set past the first clear one is -1, but for a
/// partial byte whose top bit is clear.
fn mask2len(mask: &[u8; 16], lim: Option<isize>) -> i32 {
    let lim = match lim {
        Some(d) if (d as usize) <= 16 => d as usize,
        _ => 16,
    };
    let mut p = 0;
    while p < lim && mask[p] == 0xff {
        p += 1;
    }
    let x = p as i32;
    let mut y = 0;
    if p < lim {
        while y < 8 && mask[p] & (0x80 >> y) != 0 {
            y += 1;
        }
        if y != 0 && mask[p] & (0x00ff >> y) != 0 {
            return -1;
        }
        if mask[p + 1..lim].iter().any(|&b| b != 0) {
            return -1;
        }
    }
    x * 8 + y
}

/// `ND6_INFINITE_LIFETIME`.
pub const INFINITE: u32 = 0xffff_ffff;

/// `IN6_IFF_*`.
pub mod iff {
    pub const TENTATIVE: u32 = 0x0002;
    pub const DUPLICATED: u32 = 0x0004;
    pub const DETACHED: u32 = 0x0008;
    pub const DEPRECATED: u32 = 0x0010;
    pub const NODAD: u32 = 0x0020;
    pub const OPTIMISTIC: u32 = 0x0200;
}

/// A `struct in6_aliasreq` in the kernel's form.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AliasReq {
    pub name: [u8; IFNAMSIZ],
    pub addr: Sin6,
    pub dstaddr: Sin6,
    pub prefixmask: Sin6,
    pub flags: u32,
    pub vltime: u32,
    pub pltime: u32,
}

impl AliasReq {
    /// `in6_aliasreq_to_native`: a 64-bit caller's `in6_aliasreq_64`
    /// (lifetimes at 104: 64-bit expiry and preferred times, then the
    /// valid and preferred lifetimes), or an `in6_aliasreq_32` (lifetimes
    /// of four 32-bit words). The expiry times are not read by the kernel.
    pub fn read(b: &[u8], is64: bool) -> AliasReq {
        let life = if is64 { 120 } else { 112 };
        AliasReq {
            name: b[..IFNAMSIZ].try_into().unwrap(),
            addr: Sin6::read(&b[16..44]),
            dstaddr: Sin6::read(&b[44..72]),
            prefixmask: Sin6::read(&b[72..100]),
            flags: u32::from_le_bytes(b[100..104].try_into().unwrap()),
            vltime: u32::from_le_bytes(b[life..life + 4].try_into().unwrap()),
            pltime: u32::from_le_bytes(b[life + 4..life + 8].try_into().unwrap()),
        }
    }
}

/// An IPv6 address of lo0 (`struct in6_ifaddr`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ifaddr {
    /// `ia_addr`, in the kernel's form.
    pub addr: Sin6,
    /// `ia_dstaddr`: a loopback interface's address always has one
    /// (`ifa_dstaddr` set), of `AF_UNSPEC` when none was given.
    pub dstaddr: Sin6,
    /// `ia_prefixmask`, as the address was made with.
    pub prefixmask: Sin6,
    /// `ia_plen`.
    pub plen: u8,
    /// `ia6_flags`.
    pub flags: u32,
    pub vltime: u32,
    pub pltime: u32,
    /// `IFA_ROUTE`: its host route to the destination is installed.
    pub route: bool,
}

/// Why a configuration of lo0's IPv6 addresses did not complete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fail {
    Refused(Errno),
    Unported(String),
}

impl From<Errno> for Fail {
    fn from(e: Errno) -> Fail {
        Fail::Refused(e)
    }
}

/// lo0's inet6 state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lo0Inet6 {
    /// `proto_plumb(PF_INET6, lo0)` has been done.
    pub plumbed: bool,
    /// Its IPv6 addresses, in `if_addrlist`'s order.
    pub addrs: Vec<Ifaddr>,
}

/// The request `in6_ifattach_loopback` makes: `::1/128` to `::1`, no DAD,
/// lifetimes infinite.
fn loopback_req() -> AliasReq {
    let mut one = [0u8; 16];
    one[15] = 1;
    let sin6 = |addr| Sin6 { len: SOCKADDR_IN6_LEN as u8, family: AF_INET6, addr, ..Default::default() };
    let mut name = [0u8; IFNAMSIZ];
    name[..3].copy_from_slice(b"lo0");
    AliasReq { name, addr: sin6(one), dstaddr: sin6(one), prefixmask: sin6([0xff; 16]), flags: iff::NODAD, vltime: INFINITE, pltime: INFINITE }
}

impl Lo0Inet6 {
    /// lo0 as the kernel leaves it before any process runs:
    /// `ip6_init_delayed`'s `in6_ifattach_prelim` (no `proto_plumb`) gives
    /// it `in6_ifattach_loopback`'s `::1`.
    pub fn boot() -> Lo0Inet6 {
        let mut s = Lo0Inet6 { plumbed: false, addrs: Vec::new() };
        s.update_ifa(&loopback_req(), true).expect("the loopback address at boot");
        s
    }

    /// `in6ifa_ifpwithaddr`.
    fn find(&self, a: &[u8; 16]) -> Option<usize> {
        self.addrs.iter().position(|ia| ia.addr.addr == *a)
    }

    /// `in6_update_ifa(lo0, ifra, ...)`; `boot` for the kernel's own
    /// first configuration, when the routing table has no route yet that
    /// `in6_ifinit`'s could meet.
    fn update_ifa(&mut self, ifra: &AliasReq, boot: bool) -> Result<(), Fail> {
        if ifra.addr.family != AF_INET6 || ifra.addr.len as usize != SOCKADDR_IN6_LEN {
            return Err(Errno::EAFNOSUPPORT.into());
        }
        if ifra.prefixmask.len == 0 || ifra.prefixmask.len as usize > SOCKADDR_IN6_LEN {
            return Err(Errno::EINVAL.into());
        }
        // The limit is the end of the mask's sockaddr, 8 bytes before its
        // address; the length kept is the result cut to 8 bits.
        let plen = i32::from(mask2len(&ifra.prefixmask.addr, Some(ifra.prefixmask.len as isize - 8)) as u8);
        if plen <= 0 {
            return Err(Errno::EINVAL.into());
        }
        if ifra.pltime > ifra.vltime {
            return Err(Errno::EINVAL.into());
        }
        let mut lookup = ifra.addr;
        if class::linklocal(&lookup.addr) {
            if zone(&lookup.addr) == 0 {
                set_zone(&mut lookup.addr, LO0_INDEX);
            } else if zone(&lookup.addr) != LO0_INDEX {
                return Err(Errno::EINVAL.into());
            }
            if lookup.scope_id != 0 && lookup.scope_id != u32::from(LO0_INDEX) {
                return Err(Errno::EINVAL.into());
            }
        }
        let found = self.find(&lookup.addr);
        // A loopback interface takes a destination of AF_INET6 for a host
        // address only, or none.
        match ifra.dstaddr.family {
            AF_INET6 if plen != 128 => return Err(Errno::EINVAL.into()),
            AF_INET6 | 0 => {}
            _ => return Err(Errno::EAFNOSUPPORT.into()),
        }
        // nd6 expires a finite lifetime's address and deprecates it.
        if ifra.vltime != INFINITE || ifra.pltime != INFINITE {
            return Err(Fail::Unported(format!("an IPv6 address of lo0 of lifetimes {:#x}/{:#x} (nd6's expiry of addresses)", ifra.vltime, ifra.pltime)));
        }
        let i = match found {
            Some(i) => i,
            None => {
                let mut addr = Sin6 { len: SOCKADDR_IN6_LEN as u8, family: AF_INET6, addr: ifra.addr.addr, ..Default::default() };
                let prefixmask = Sin6 { len: SOCKADDR_IN6_LEN as u8, family: AF_INET6, addr: ifra.prefixmask.addr, ..Default::default() };
                to_kamescope(&mut addr)?;
                let mut dstaddr = ifra.dstaddr;
                to_kamescope(&mut dstaddr)?;
                // in6_ifinit's rtinit of the host route to the
                // destination, which an existing route refuses.
                if plen == 128 && dstaddr.family == AF_INET6 && !boot {
                    return Err(Fail::Unported("a new IPv6 address of lo0 with a destination (in6_ifinit's host route: the routing table is not modelled)".into()));
                }
                self.addrs.push(Ifaddr { addr, dstaddr, prefixmask, plen: 0, flags: 0, vltime: 0, pltime: 0, route: false });
                self.addrs.len() - 1
            }
        };
        let ia = &mut self.addrs[i];
        if !ia.route && plen == 128 && ia.dstaddr.family == AF_INET6 && !boot {
            return Err(Fail::Unported("an IPv6 address of lo0 without its host route (in6_ifinit's rtinit: the routing table is not modelled)".into()));
        }
        ia.vltime = ifra.vltime;
        ia.pltime = ifra.pltime;
        ia.plen = plen as u8;
        // in6_ifaupdate_aux: the flags a configuration clears, and DAD's,
        // which a loopback interface does not do (in6if_do_dad).
        ia.flags = ifra.flags & !(iff::DEPRECATED | iff::DETACHED | iff::DUPLICATED) & !(iff::TENTATIVE | iff::OPTIMISTIC);
        // in6_ifinit: a host address with a destination gets its route;
        // SIOCSIFADDR goes to the interface only for its first address,
        // which never is (its link-level address comes first).
        if plen == 128 && ia.dstaddr.family == AF_INET6 {
            ia.route = true;
        }
        Ok(())
    }

    /// `in6_ifattach_prelim(lo0)`: its loopback address (again).
    fn prelim(&mut self) -> Result<(), Fail> {
        match self.update_ifa(&loopback_req(), false) {
            Err(Fail::Refused(_)) => Err(EADDRNOTAVAIL.into()),
            r => r,
        }
    }

    /// `in6_domifattach(lo0)`: EEXIST once plumbed.
    fn domifattach(&mut self) -> Result<(), Fail> {
        if self.plumbed {
            return Err(Errno::EEXIST.into());
        }
        self.plumbed = true;
        if let Err(e) = self.prelim() {
            self.plumbed = false;
            return Err(e);
        }
        Ok(())
    }

    /// `in6_ifattach_aliasreq(lo0, NULL, NULL)`: `prelim`, then
    /// (`ip6_auto_linklocal`) the link-local `fe80::1%lo0/64` when it has
    /// none, whose failure is not one.
    fn ifattach_aliasreq(&mut self) -> Result<(), Fail> {
        self.prelim()?;
        if self.addrs.iter().any(|ia| class::linklocal(&ia.addr.addr)) {
            return Ok(());
        }
        let mut ll = loopback_req();
        ll.addr.addr = [0xfe, 0x80, 0, LO0_INDEX as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        ll.dstaddr = Sin6::default();
        let mut m64 = [0u8; 16];
        m64[..8].fill(0xff);
        ll.prefixmask.addr = m64;
        ll.flags = 0;
        match self.update_ifa(&ll, false) {
            Err(Fail::Unported(s)) => Err(Fail::Unported(s)),
            _ => Ok(()),
        }
    }

    /// `in6_control`'s `SIOCAIFADDR_IN6` of a privileged caller, once lo0
    /// was found.
    pub fn aifaddr(&mut self, ifra: &AliasReq) -> Result<(), Fail> {
        // The address the request names, as it is looked up: a link-local
        // one's zone must be lo0's, embedded or in its scope.
        let sa6 = ifra.addr;
        if sa6.family == AF_INET6 && class::linklocal(&sa6.addr) {
            let z = zone(&sa6.addr);
            if z != 0 && z != LO0_INDEX {
                return Err(Errno::EINVAL.into());
            }
            if sa6.scope_id != 0 && sa6.scope_id != u32::from(LO0_INDEX) {
                return Err(Errno::EINVAL.into());
            }
        }
        if sa6.family != AF_INET6 || sa6.len as usize != SOCKADDR_IN6_LEN {
            return Err(Errno::EAFNOSUPPORT.into());
        }
        let a = &sa6.addr;
        if class::unspecified(a) || class::multicast(a) || class::v4mapped(a) || class::v4compat(a) {
            return Err(Errno::EINVAL.into());
        }
        // in6ctl_aifaddr.
        let mut ifra = *ifra;
        if class::linklocal(&ifra.addr.addr) {
            set_zone(&mut ifra.addr.addr, LO0_INDEX);
        }
        match self.domifattach() {
            Ok(()) => self.ifattach_aliasreq()?,
            Err(Fail::Refused(Errno::EEXIST)) => {}
            Err(e) => return Err(e),
        }
        self.update_ifa(&ifra, false)?;
        let plen = mask2len(&ifra.prefixmask.addr, None) as u8;
        if plen != 128 {
            return Err(Fail::Unported(format!("an IPv6 address of lo0 of prefix length {plen} (in6ctl_aifaddr's on-link prefix: nd6's prefix list is not modelled)")));
        }
        Ok(())
    }
}

/// lo0's inet6 state, the system's.
static LO0: Mutex<Option<Lo0Inet6>> = Mutex::new(None);

/// `SIOCAIFADDR_IN6_64` and `SIOCAIFADDR_IN6_32` (`_IOW('i', 26, ...)` of
/// 128 and 120 bytes).
pub const SIOCAIFADDR_IN6_64: u64 = 0x8080_691a;
pub const SIOCAIFADDR_IN6_32: u64 = 0x8078_691a;

/// The AF_INET address commands `in6_control` refuses on an inet6 socket:
/// SIOCGIFDSTADDR, SIOCGIFBRDADDR, SIOCGIFNETMASK, SIOCGIFADDR, SIOCAIFADDR
/// and SIOCDIFADDR (the `SIOCSIF*ADDR` ones go another way in `ifioctl`).
const INET_ADDR_CMDS: [u64; 6] = [0xc020_6922, 0xc020_6923, 0xc020_6925, 0xc020_6921, 0x8040_691a, 0x8020_6919];

impl Kernel {
    /// The inet6 socket behind a descriptor, if it is one.
    pub(crate) fn darwin_inet6_of(&self, fd: i32) -> Option<Arc<Inet6Socket>> {
        Arc::clone(&self.fds.get(fd).ok()?.handle).as_darwin_inet6()
    }

    /// `socket(AF_INET6, type, protocol)` after its MAC check.
    fn darwin_inet6_socket(&mut self, ty: i32, protocol: i32) -> Result<u64, Errno> {
        let proto = match lookup(ty, protocol) {
            Lookup::Made(p) => p,
            Lookup::Refused(e) => return Err(e),
            Lookup::Unported(what) => {
                self.darwin_unimplemented(format!("socket(AF_INET6, {ty}, {protocol}): {what}"));
                return Err(Errno::EPROTONOSUPPORT);
            }
        };
        let handle: Arc<dyn FileHandle> = Arc::new(Inet6Socket { proto });
        let file = crate::file::OpenFile::new(handle, "socket".to_string(), 0, true, true);
        self.fds.insert(file, false)
    }

    /// `socketpair(AF_INET6, ...)`: both sockets made, then `soconnect2`,
    /// which neither UDP nor TCP takes (`pru_connect2_notsupp`).
    fn darwin_inet6_socketpair(&mut self, ty: i32, protocol: i32) -> Result<u64, Errno> {
        match lookup(ty, protocol) {
            Lookup::Made(_) => Err(EOPNOTSUPP),
            Lookup::Refused(e) => Err(e),
            Lookup::Unported(what) => {
                self.darwin_unimplemented(format!("socketpair(AF_INET6, {ty}, {protocol}): {what}"));
                Err(Errno::EPROTONOSUPPORT)
            }
        }
    }

    /// The calls of the inet6 domain and those on its sockets: `None` for
    /// one that is neither, or that the socket layer answers for every
    /// socket alike.
    pub(crate) fn darwin_inet6_call(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &[u64; 6]) -> Option<Result<u64, Errno>> {
        match raw {
            sys::SOCKET if a[0] as u32 == u32::from(AF_INET6) => return Some(self.darwin_inet6_socket(a[1] as i32, a[2] as i32)),
            sys::SOCKETPAIR if a[0] as u32 == u32::from(AF_INET6) => return Some(self.darwin_inet6_socketpair(a[1] as i32, a[2] as i32)),
            _ => {}
        }
        let name = match raw {
            sys::READ | sys::READ_NOCANCEL | sys::READV | sys::READV_NOCANCEL => "read",
            sys::WRITE | sys::WRITE_NOCANCEL | sys::WRITEV | sys::WRITEV_NOCANCEL => "write",
            sys::RECVMSG | sys::RECVMSG_NOCANCEL | sys::RECVFROM | sys::RECVFROM_NOCANCEL | sys::RECVMSG_X => "receive",
            sys::SENDMSG | sys::SENDMSG_NOCANCEL | sys::SENDTO | sys::SENDTO_NOCANCEL | sys::SENDMSG_X => "send",
            sys::ACCEPT | sys::ACCEPT_NOCANCEL => "accept",
            sys::GETPEERNAME => "getpeername",
            sys::GETSOCKNAME => "getsockname",
            sys::CONNECT | sys::CONNECT_NOCANCEL | sys::CONNECTX => "connect",
            sys::DISCONNECTX => "disconnectx",
            sys::PEELOFF => "peeloff",
            sys::BIND => "bind",
            sys::LISTEN => "listen",
            sys::SHUTDOWN => "shutdown",
            sys::FSTAT | sys::FSTAT64 | sys::FSTAT_EXTENDED | sys::FSTAT64_EXTENDED => "fstat (soo_stat)",
            sys::SETSOCKOPT => "setsockopt",
            sys::GETSOCKOPT => "getsockopt",
            _ => return None,
        };
        let s = self.darwin_inet6_of(a[0] as i32)?;
        // The socket-level options kept for every socket.
        if a[1] & 0xffff_ffff == super::sockopt::SOL_SOCKET {
            let r = match raw {
                sys::SETSOCKOPT => self.darwin_setsockopt(m, a),
                sys::GETSOCKOPT => self.darwin_getsockopt(m, a),
                _ => None,
            };
            if let Some(r) = r {
                return Some(r);
            }
        }
        let what = match raw {
            sys::SETSOCKOPT | sys::GETSOCKOPT => format!("{name} level {} option {:#x} on an inet6 {:?} socket", a[1] as u32 as i32, a[2] as u32, s.proto),
            _ => format!("{name} on an inet6 {:?} socket (the inet6 protocols' calls: udp6_usrreqs, tcp6_usrreqs)", s.proto),
        };
        self.darwin_unimplemented(what);
        Some(Err(EOPNOTSUPP))
    }

    /// `soioctl` of an inet6 socket, past its MAC check.
    pub(crate) fn darwin_inet6_soioctl(&mut self, com: u64, data: &mut [u8]) -> Result<(), Errno> {
        use super::ioctl::cmd;
        match com {
            cmd::FIONBIO => Ok(()),
            cmd::FIOASYNC if i32::from_le_bytes(data[..4].try_into().unwrap()) == 0 => Ok(()),
            cmd::FIONREAD => {
                data[..4].copy_from_slice(&0u32.to_le_bytes());
                Ok(())
            }
            // ifioctllocked: the interface commands.
            _ if (com >> 8) & 0xff == u64::from(b'i') => self.darwin_inet6_ifioctl(com, data),
            _ => {
                self.darwin_unimplemented(format!("ioctl {com:#x} on an inet6 socket (soioctl)"));
                Err(EOPNOTSUPP)
            }
        }
    }

    /// `ifioctl` of an inet6 socket: the interface's flags as for any
    /// socket, its addresses through `in6_control`.
    fn darwin_inet6_ifioctl(&mut self, com: u64, data: &mut [u8]) -> Result<(), Errno> {
        use super::ioctl::cmd;
        match com {
            cmd::SIOCGIFFLAGS | cmd::SIOCSIFFLAGS if com == cmd::SIOCGIFFLAGS || self.darwin_suser().is_ok() => self.darwin_ifflags(com, data),
            cmd::SIOCSIFFLAGS => Err(Errno::EPERM),
            SIOCAIFADDR_IN6_64 | SIOCAIFADDR_IN6_32 => {
                self.darwin_ifunit(data)?;
                self.darwin_suser()?;
                let ifra = AliasReq::read(data, com == SIOCAIFADDR_IN6_64);
                let mut lo0 = LO0.lock().unwrap_or_else(|e| e.into_inner());
                match lo0.get_or_insert_with(Lo0Inet6::boot).aifaddr(&ifra) {
                    Ok(()) => Ok(()),
                    Err(Fail::Refused(e)) => Err(e),
                    Err(Fail::Unported(what)) => {
                        drop(lo0);
                        self.darwin_unimplemented(what);
                        Err(EOPNOTSUPP)
                    }
                }
            }
            c if INET_ADDR_CMDS.contains(&c) => {
                self.darwin_ifunit(data)?;
                Err(Errno::EINVAL)
            }
            _ => {
                self.darwin_unimplemented(format!("interface ioctl {com:#x} on an inet6 socket (ifioctl, in6_control)"));
                Err(EOPNOTSUPP)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocols_are_looked_up_as_socreate_does() {
        assert_eq!(lookup(SOCK_DGRAM, 0), Lookup::Made(Proto::Udp));
        assert_eq!(lookup(SOCK_STREAM, 0), Lookup::Made(Proto::Tcp));
        assert_eq!(lookup(SOCK_DGRAM, IPPROTO_UDP), Lookup::Made(Proto::Udp));
        assert_eq!(lookup(SOCK_STREAM, IPPROTO_TCP), Lookup::Made(Proto::Tcp));
        // The protocol under another type.
        assert_eq!(lookup(SOCK_STREAM, IPPROTO_UDP), Lookup::Refused(Errno::EPROTOTYPE));
        assert_eq!(lookup(SOCK_DGRAM, IPPROTO_TCP), Lookup::Refused(Errno::EPROTOTYPE));
        assert_eq!(lookup(SOCK_DGRAM, IPPROTO_IPV6), Lookup::Refused(Errno::EPROTOTYPE));
        // No such type or protocol.
        assert_eq!(lookup(5, 0), Lookup::Refused(Errno::EPROTONOSUPPORT));
        assert_eq!(lookup(0, 0), Lookup::Refused(Errno::EPROTONOSUPPORT));
        assert_eq!(lookup(SOCK_DGRAM, 200), Lookup::Refused(Errno::EPROTONOSUPPORT));
        assert_eq!(lookup(5, IPPROTO_UDP), Lookup::Refused(Errno::EPROTOTYPE));
        // nousrreqs: pru_attach_notsupp.
        assert_eq!(lookup(SOCK_RAW, IPPROTO_DSTOPTS), Lookup::Refused(EOPNOTSUPP));
        assert_eq!(lookup(SOCK_RAW, IPPROTO_FRAGMENT), Lookup::Refused(EOPNOTSUPP));
        assert_eq!(lookup(0, IPPROTO_IPV6), Lookup::Refused(EOPNOTSUPP));
        // Raw and ICMPv6 datagram sockets, and IPsec's, are not made here.
        assert!(matches!(lookup(SOCK_RAW, 0), Lookup::Unported(_)));
        assert!(matches!(lookup(SOCK_RAW, 99), Lookup::Unported(_)));
        assert!(matches!(lookup(SOCK_DGRAM, IPPROTO_ICMPV6), Lookup::Unported(_)));
        assert!(matches!(lookup(SOCK_RAW, IPPROTO_AH), Lookup::Unported(_)));
    }

    #[test]
    fn masks_measure_as_in6_mask2len_does() {
        let mut m = [0u8; 16];
        m[..8].fill(0xff);
        assert_eq!(mask2len(&m, None), 64);
        assert_eq!(mask2len(&[0xff; 16], Some(20)), 128);
        // A limit inside the mask: only its bytes count.
        assert_eq!(mask2len(&[0xff; 16], Some(8)), 64);
        assert_eq!(mask2len(&[0xff; 16], Some(0)), 0);
        // A negative distance is a huge one: all 16.
        assert_eq!(mask2len(&[0xff; 16], Some(-8)), 128);
        m[8] = 0xe0;
        assert_eq!(mask2len(&m, None), 67);
        m[8] = 0xe1;
        assert_eq!(mask2len(&m, None), -1);
        // A partial byte with its top bit clear is not checked.
        m[8] = 0x7f;
        assert_eq!(mask2len(&m, None), 64);
        m[9] = 1;
        assert_eq!(mask2len(&m, None), -1);
    }

    fn sin6(addr: [u8; 16]) -> Sin6 {
        Sin6 { len: 28, family: AF_INET6, addr, ..Default::default() }
    }

    fn req(addr: [u8; 16], plen: usize) -> AliasReq {
        let mut mask = [0u8; 16];
        for b in 0..plen {
            mask[b / 8] |= 0x80 >> (b % 8);
        }
        let mut name = [0u8; 16];
        name[..3].copy_from_slice(b"lo0");
        AliasReq { name, addr: sin6(addr), dstaddr: Sin6::default(), prefixmask: sin6(mask), flags: 0, vltime: INFINITE, pltime: INFINITE }
    }

    fn one() -> [u8; 16] {
        let mut a = [0u8; 16];
        a[15] = 1;
        a
    }

    #[test]
    fn lo0_boots_with_its_loopback_address() {
        let s = Lo0Inet6::boot();
        assert!(!s.plumbed);
        assert_eq!(s.addrs.len(), 1);
        let ia = s.addrs[0];
        assert_eq!(ia.addr, sin6(one()));
        assert_eq!(ia.dstaddr, sin6(one()));
        assert_eq!((ia.plen, ia.flags, ia.route), (128, iff::NODAD, true));
    }

    #[test]
    fn launchds_loopback_request_attaches_inet6_and_its_link_local() {
        let mut s = Lo0Inet6::boot();
        // launchd's: ::1/128, no destination, flags 0, lifetimes infinite.
        assert_eq!(s.aifaddr(&req(one(), 128)), Ok(()));
        assert!(s.plumbed);
        assert_eq!(s.addrs.len(), 2);
        assert_eq!(s.addrs[0].flags, 0, "launchd's flags replace the boot's NODAD");
        assert_eq!(s.addrs[0].dstaddr, sin6(one()), "an existing address keeps its destination");
        let ll = s.addrs[1];
        assert_eq!(ll.addr.addr, [0xfe, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], "fe80::1%lo0, its zone embedded");
        assert_eq!((ll.plen, ll.flags, ll.dstaddr.family), (64, 0, 0));
        // Again: plumbed (EEXIST) and updated in place.
        let before = s.clone();
        assert_eq!(s.aifaddr(&req(one(), 128)), Ok(()));
        assert_eq!(s, before);
    }

    #[test]
    fn requests_are_checked_as_in6_control_and_in6_update_ifa_check_them() {
        let mut s = Lo0Inet6::boot();
        let refused = |s: &mut Lo0Inet6, r: AliasReq| match s.aifaddr(&r) {
            Err(Fail::Refused(e)) => e,
            other => panic!("{other:?}"),
        };
        let mut r = req(one(), 128);
        r.addr.len = 16;
        assert_eq!(refused(&mut s, r), Errno::EAFNOSUPPORT);
        let mut r = req(one(), 128);
        r.addr.family = 2;
        assert_eq!(refused(&mut s, r), Errno::EAFNOSUPPORT);
        assert_eq!(refused(&mut s, req([0; 16], 128)), Errno::EINVAL);
        let mut mc = [0u8; 16];
        mc[0] = 0xff;
        mc[1] = 2;
        mc[15] = 1;
        assert_eq!(refused(&mut s, req(mc, 128)), Errno::EINVAL);
        let mapped = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1];
        assert_eq!(refused(&mut s, req(mapped, 128)), Errno::EINVAL);
        let compat = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1];
        assert_eq!(refused(&mut s, req(compat, 128)), Errno::EINVAL);
        // A link-local address of another zone, embedded or scoped.
        let other_zone = [0xfe, 0x80, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
        assert_eq!(refused(&mut s, req(other_zone, 128)), Errno::EINVAL);
        let mut r = req([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5], 128);
        r.addr.scope_id = 3;
        assert_eq!(refused(&mut s, r), Errno::EINVAL);
        // The mask's length and contents.
        let mut r = req(one(), 128);
        r.prefixmask.len = 0;
        assert_eq!(refused(&mut s, r), Errno::EINVAL);
        let mut r = req(one(), 128);
        r.prefixmask.len = 29;
        assert_eq!(refused(&mut s, r), Errno::EINVAL);
        assert_eq!(refused(&mut s, req(one(), 0)), Errno::EINVAL);
        // The preferred lifetime past the valid one.
        let mut r = req(one(), 128);
        r.vltime = 10;
        r.pltime = 20;
        assert_eq!(refused(&mut s, r), Errno::EINVAL);
        // A destination: AF_INET6 for a host address only, else AF_UNSPEC.
        let mut r = req(one(), 64);
        r.dstaddr = sin6(one());
        assert_eq!(refused(&mut s, r), Errno::EINVAL);
        let mut r = req(one(), 128);
        r.dstaddr.family = 2;
        assert_eq!(refused(&mut s, r), Errno::EAFNOSUPPORT);
    }

    /// 2001:db8::2, of the documentation prefix.
    fn doc() -> [u8; 16] {
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]
    }

    #[test]
    fn new_addresses_are_kept_in_the_kernels_form() {
        let mut s = Lo0Inet6::boot();
        // ::2 is a v4-compatible address, which in6_control refuses.
        let mut v4compat = one();
        v4compat[15] = 2;
        assert_eq!(s.aifaddr(&req(v4compat, 128)), Err(Fail::Refused(Errno::EINVAL)));
        let two = doc();
        let mut r = req(two, 128);
        r.flags = iff::NODAD | iff::TENTATIVE | iff::DEPRECATED;
        assert_eq!(s.aifaddr(&r), Ok(()));
        let ia = *s.addrs.iter().find(|ia| ia.addr.addr == two).unwrap();
        assert_eq!(ia.flags, iff::NODAD, "the flags a configuration clears, and DAD's");
        assert_eq!(ia.dstaddr.family, 0);
        // A link-local one given by its scope: kept with its zone embedded.
        let mut r = req([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7], 128);
        r.addr.scope_id = 1;
        assert_eq!(s.aifaddr(&r), Ok(()));
        let ll7 = [0xfe, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7];
        let ia = *s.addrs.iter().find(|ia| ia.addr.addr == ll7).unwrap();
        assert_eq!(ia.addr.scope_id, 0);
    }

    #[test]
    fn what_needs_routes_prefixes_or_expiry_is_not_answered() {
        let mut s = Lo0Inet6::boot();
        let two = doc();
        let mut r = req(two, 128);
        r.dstaddr = sin6(one());
        assert!(matches!(s.aifaddr(&r), Err(Fail::Unported(_))));
        assert!(matches!(s.aifaddr(&req(two, 64)), Err(Fail::Unported(_))));
        let mut r = req(two, 128);
        r.vltime = 3600;
        r.pltime = 3600;
        assert!(matches!(s.aifaddr(&r), Err(Fail::Unported(_))));
    }

    #[test]
    fn aliasreqs_of_either_size_read_alike() {
        let mut b = [0u8; 128];
        b[..3].copy_from_slice(b"lo0");
        b[16] = 28;
        b[17] = 30;
        b[16 + 8 + 15] = 1;
        b[100] = 0x20;
        b[120..128].copy_from_slice(&[0xff; 8]);
        let r = AliasReq::read(&b, true);
        assert_eq!((r.addr.len, r.addr.family, r.addr.addr[15], r.flags, r.vltime, r.pltime), (28, 30, 1, 0x20, INFINITE, INFINITE));
        let mut c = b;
        c[112..120].copy_from_slice(&[0xff; 8]);
        c[120..].fill(0);
        assert_eq!(AliasReq::read(&c, false), r);
    }

    #[test]
    fn udp_recvspace_follows_the_mbuf_pool() {
        assert_eq!(udp_recvspace(), 786896);
        assert_eq!(187 * (1024 + 28), 196724);
    }

    #[test]
    fn a_fresh_socket_is_in_no_state_but_its_buffers() {
        let u = Inet6Socket { proto: Proto::Udp }.so_state().unwrap();
        assert_eq!((u.hiwat, u.can_write, u.records, u.rcv), ((786896, 9216), true, Some((0, 0)), 0));
        let t = Inet6Socket { proto: Proto::Tcp }.so_state().unwrap();
        assert_eq!((t.hiwat, t.can_write, t.records), ((556032, 370688), false, None));
        assert_eq!(unbound_name(), [28, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }
}
