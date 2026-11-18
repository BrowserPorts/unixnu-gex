//! Sockets.
//!
//! A page cannot open TCP; it can talk to a proxy over a WebSocket, and Wisp
//! multiplexes streams down one. So the kernel implements the *shape* of a
//! socket -- descriptors, `connect`, `send`, `recv` and their blocking -- and
//! hands the carrying to the host: a real socket natively, a Wisp stream in a
//! page.
//!
//! DNS is the awkward part: a Wisp stream opens by hostname, but a guest
//! resolves first and connects to an address. So the kernel answers DNS
//! itself, handing back an address from a private range and remembering the
//! name against it; when the guest connects to that address the name comes
//! back and the host is asked for a stream to it.
//!
//! UDP off this machine goes the same way: each (socket, far address) is a
//! flow the host carries (`NetStack::udp`), one datagram per `send` and per
//! `recv`. DNS stays the kernel's even so: the names it answers are what
//! page-served hosts and the proxy are reached by.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use crate::errno::{Errno, SysResult};
use crate::vfs::{FileHandle, FileType, Metadata};

/// How a connection is getting on.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// Asked for, not answered yet.
    Connecting,
    Open,
    /// The peer hung up. Reads drain what is left and then return zero.
    Closed,
    /// It never opened.
    Refused,
}

/// One connection, as the host carries it.
///
/// Everything here is non-blocking. The kernel does the waiting, because the
/// kernel is what knows how to park a guest thread; a host that blocked
/// inside `recv` would take the browser's only wasm stack with it.
pub trait Transport: Send + Sync + std::fmt::Debug {
    /// Begin connecting. Returns as soon as the request is placed.
    fn connect(&self, host: &str, port: u16) -> Result<(), Errno>;
    fn status(&self) -> Status;
    /// Queue bytes. A transport that cannot take them all says how many.
    fn send(&self, data: &[u8]) -> Result<usize, Errno>;
    /// Take what has arrived. `Err(EAGAIN)` when nothing has and the
    /// connection is still open; `Ok(0)` once it is closed and drained.
    fn recv(&self, buf: &mut [u8]) -> Result<usize, Errno>;
    /// Whether `recv` would return without waiting -- which includes a closed
    /// connection, because end-of-file is an answer.
    fn has_data(&self) -> bool;
    /// How many bytes are waiting, for `FIONREAD`. A stream may under-report
    /// and the caller simply reads again; the number only has to be right
    /// when it is zero.
    fn available(&self) -> usize {
        usize::from(self.has_data())
    }
    fn close(&self);
    /// The wait queue a change in this end's readiness is announced on
    /// (`FileHandle::wait_queue`); 0 for one no event announces.
    fn wait_queue(&self) -> u32 {
        0
    }
    /// `shutdown(how)`: 0 reads, 1 writes, 2 both. A transport that cannot
    /// half-close accepts it and does nothing.
    fn shutdown(&self, how: u64) -> Result<(), Errno> {
        let _ = how;
        Ok(())
    }
    /// A write once `status` says Closed: `EPIPE`, unless the transport
    /// knows better (only the reading side went away, as after the peer's
    /// `shutdown(SHUT_WR)`).
    fn send_closed(&self, data: &[u8]) -> Result<usize, Errno> {
        let _ = data;
        Err(Errno::EPIPE)
    }
    /// `recv(MSG_PEEK)`: what `recv` would take, left queued.
    fn peek(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        let _ = buf;
        Err(Errno::EOPNOTSUPP)
    }
    /// Whether this end can send no more (`SS_CANTSENDMORE`), `closed`
    /// being whether `status` says Closed: a transport whose writes after
    /// that are `EPIPE` has none, one that knows a peer's half-close
    /// (`send_closed`) says itself.
    fn send_over(&self, closed: bool) -> bool {
        closed
    }
    /// This connection as a name another process can hold it by (a socket
    /// passed over `SCM_RIGHTS`, or inherited across a fork, in a page where
    /// each process has its own memory), counted as one more holder: the
    /// connection ends when its last holder closes, as a socket outlives one
    /// of its descriptors. `None` for one that cannot leave this process.
    /// What the name means is the host's (`Socket::carry`).
    fn carry(&self) -> Option<String> {
        None
    }
    /// `carry`'s name without the hold: what another holder takes up with
    /// `NetStack::adopt` (a moved socket's connection out, `Socket::go_out`).
    fn name(&self) -> Option<String> {
        None
    }
    /// Where this end's TCP has got to, for a connection both of whose
    /// ends are this kernel's ([`TcpEnd`]); `None` for one whose TCP is the
    /// host's, which says nothing of its FINs and resets.
    fn tcp_end(&self) -> Option<TcpEnd> {
        None
    }
    /// The pending error a reset left (`so_error`), taken as `SO_ERROR`
    /// takes it; `None` when there is none.
    fn take_error(&self) -> Option<Errno> {
        None
    }
    /// The owner of the socket this end is ([`crate::vfs::SoOwner`]), for
    /// the wakeups its connection makes; whether this transport makes them
    /// as XNU's TCP would.
    fn set_owner(&self, owner: &Arc<crate::vfs::SoOwner>) -> bool {
        let _ = owner;
        false
    }
    /// A send of urgent data (`tcp_usr_send` with PRUS_OOB): the urgent
    /// pointer after its last byte. `None` for a transport whose TCP is the
    /// host's, which carries no urgent pointer here.
    fn send_oob(&self, data: &[u8]) -> Option<Result<usize, Errno>> {
        let _ = data;
        None
    }
    /// `tcp_usr_rcvoob`: the out-of-band byte, left for another when
    /// `peek`. `None` as for [`Self::send_oob`].
    fn recv_oob(&self, peek: bool) -> Option<Result<u8, Errno>> {
        let _ = peek;
        None
    }
    /// The reading socket's `SO_OOBINLINE`, which the urgent data that
    /// arrives goes by; whether this transport follows urgent data.
    fn set_oobinline(&self, on: bool) -> bool {
        let _ = on;
        false
    }
    /// `so_oobmark` and `SS_RCVATMARK` of the reading socket; `None` as for
    /// [`Self::send_oob`].
    fn oob_state(&self) -> Option<(u64, bool)> {
        None
    }
    /// `sorflush`: this end's reading shut down, what waits to be read
    /// thrown away and what arrives after dropped (SB_DROP); false for a
    /// transport that cannot (the host's).
    fn sorflush(&self) -> bool {
        false
    }
    /// The end dropped while its listener's queue held it (`soabort`): a
    /// transport whose TCP is not this kernel's closes it.
    fn abort(&self) {
        self.close();
    }
    /// The socket's options its TCP reads ([`crate::tcploop::TcpOpts`]),
    /// with what `tcp_ctloutput` does on the change; false for a transport
    /// whose TCP is not this kernel's.
    fn tcp_opts(&self, opts: crate::tcploop::TcpOpts, change: crate::tcploop::OptChange) -> bool {
        let _ = (opts, change);
        false
    }
    /// The timers due run, and when the next of this connection's TCP
    /// timers is due.
    fn next_deadline(&self) -> Option<std::time::Instant> {
        None
    }
}

/// One end of a TCP connection's state as XNU's TCP leaves it, for a
/// connection carried between two ends this kernel holds
/// ([`crate::tcploop`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpEnd {
    /// `t_state` ([`crate::tcploop::state`]).
    pub state: u8,
    /// This end sent its FIN (`shutdown(SHUT_WR)` or its close).
    pub fin_sent: bool,
    /// The peer's FIN arrived (`socantrcvmore`).
    pub fin_rcvd: bool,
    /// A reset was taken (SO_FILT_HINT_CONNRESET).
    pub reset: bool,
    /// This end shut its reading down (`sorflush`'s `socantrcvmore`).
    pub rd_shut: bool,
    /// It did so before it sent its FIN: when that FIN was acknowledged
    /// (`TCPS_FIN_WAIT_1` to `TCPS_FIN_WAIT_2`) it could receive no more,
    /// which is `soisdisconnected`.
    pub rd_shut_first: bool,
    /// A reset's ECONNRESET is still to be read (`so_error`).
    pub reset_error: bool,
    /// `so_error`.
    pub error: Option<Errno>,
    /// SS_ISCONNECTED, SS_CANTRCVMORE, SS_CANTSENDMORE.
    pub connected: bool,
    pub cantrcv: bool,
    pub cantsend: bool,
    /// `tcp_close` has run: the PCB is dead (INPCB_STATE_DEAD).
    pub closed: bool,
    /// The `soisdisconnected` calls, the resets taken, the drops for a
    /// timer (SO_FILT_HINT_TIMEOUT) and the keepalive probes received
    /// (SO_FILT_HINT_KEEPALIVE).
    pub disconnects: u32,
    pub resets: u32,
    pub timeouts: u32,
    pub keepalives: u32,
}

impl TcpEnd {
    /// SS_ISDISCONNECTED: `soisdisconnected` has run.
    pub fn disconnected(&self) -> bool {
        self.disconnects != 0
    }
}

/// Where a host's connections come from.
pub trait NetStack: Send + Sync + std::fmt::Debug {
    fn tcp(&self) -> Result<Arc<dyn Transport>, Errno>;
    /// A UDP flow: `connect` names the far end, each `send` is one datagram
    /// to it and each `recv` one datagram from it (`Err(EAGAIN)`: none yet).
    /// `ENETUNREACH` from a network that carries no datagrams.
    fn udp(&self) -> Result<Arc<dyn Transport>, Errno> {
        Err(Errno::ENETUNREACH)
    }
    /// A connection by `Transport::name`, held once more here; `None` when
    /// it has ended or this network has no such names.
    fn adopt(&self, name: &str) -> Option<Arc<dyn Transport>> {
        let _ = name;
        None
    }
}

/// No network behind the kernel (the browser without a Wisp relay): inet
/// sockets still work over loopback -- bind, listen, connect and the
/// kernel's own DNS answers -- and a connection out is unreachable.
#[derive(Debug)]
pub struct NoNet;

impl NetStack for NoNet {
    fn tcp(&self) -> Result<Arc<dyn Transport>, Errno> {
        Err(Errno::ENETUNREACH)
    }
}

// -- names ------------------------------------------------------------------

/// The private range the synthetic answers come from. 240.0.0.0/4 is reserved
/// and unroutable, so one of these addresses can only ever be a synthetic one.
const FAKE_BASE: u32 = 0xf000_0001;

/// Names the guest has asked about, and what it was told.
#[derive(Debug, Default)]
pub struct Resolver {
    by_name: Mutex<HashMap<String, u32>>,
    by_addr: Mutex<HashMap<u32, String>>,
    next: AtomicU32,
}

impl Resolver {
    pub fn new() -> Resolver {
        Resolver {
            next: AtomicU32::new(FAKE_BASE),
            ..Default::default()
        }
    }

    /// The address to answer a query for `name` with, allocating one if this
    /// is the first time it has been asked.
    pub fn address_for(&self, name: &str) -> u32 {
        let key = name.trim_end_matches('.').to_ascii_lowercase();
        if let Some(h) = SHARED_NAMES.get() {
            return (h.address_for)(&key);
        }
        if let Some(&a) = self.by_name.lock().unwrap().get(&key) {
            return a;
        }
        let a = self.next.fetch_add(1, Ordering::AcqRel);
        self.by_name.lock().unwrap().insert(key.clone(), a);
        self.by_addr.lock().unwrap().insert(a, key);
        a
    }

    /// The name an address was handed out for.
    pub fn name_for(&self, addr: u32) -> Option<String> {
        if let Some(h) = SHARED_NAMES.get() {
            return (h.name_for)(addr);
        }
        self.by_addr.lock().unwrap().get(&addr).cloned()
    }
}

/// The machine's one table of synthetic answers, where processes do not share
/// a kernel (a page: a Worker and a memory per process). One process resolves
/// a name and another connects to the address it was told -- Wine's clients
/// call getaddrinfo and its wineserver makes the connection -- so every
/// process must give a name the same address and read it back the same way.
#[derive(Clone, Copy)]
pub struct SharedNames {
    pub address_for: fn(&str) -> u32,
    pub name_for: fn(u32) -> Option<String>,
}

static SHARED_NAMES: std::sync::OnceLock<SharedNames> = std::sync::OnceLock::new();

/// Answer every `Resolver`'s questions from `names` (set once, by a host with
/// a global kernel, before any process resolves).
pub fn share_names(names: SharedNames) {
    let _ = SHARED_NAMES.set(names);
}

/// Build a DNS response for a query.
///
/// Only what a resolver actually sends: one question, class IN, type A or
/// AAAA. An AAAA query is answered with no records rather than an error,
/// which is what tells a dual-stack resolver to ask for A instead -- an
/// error would make it give up on the name entirely.
pub fn answer_dns(query: &[u8], resolver: &Resolver) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    if qdcount != 1 {
        return None;
    }
    // Walk the question's labels.
    let mut i = 12;
    let mut name = String::new();
    loop {
        let len = *query.get(i)? as usize;
        i += 1;
        if len == 0 {
            break;
        }
        // No compression pointers in a question.
        if len & 0xc0 != 0 || i + len > query.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(std::str::from_utf8(&query[i..i + len]).ok()?);
        i += len;
    }
    let qtype = u16::from_be_bytes([*query.get(i)?, *query.get(i + 1)?]);
    let qend = i + 4;
    if qend > query.len() {
        return None;
    }

    let mut out = Vec::with_capacity(qend + 16);
    out.extend_from_slice(&query[..2]); // the id, echoed
    // QR=1 (response), RD copied, RA=1 (recursion available), RCODE=0.
    out.push(0x81);
    out.push(0x80);
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    let answers: u16 = if qtype == 1 { 1 } else { 0 };
    out.extend_from_slice(&answers.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // nscount
    out.extend_from_slice(&0u16.to_be_bytes()); // arcount
    out.extend_from_slice(&query[12..qend]); // the question, echoed
    if answers == 1 {
        out.extend_from_slice(&[0xc0, 0x0c]); // a pointer back to the name
        out.extend_from_slice(&1u16.to_be_bytes()); // type A
        out.extend_from_slice(&1u16.to_be_bytes()); // class IN
        out.extend_from_slice(&60u32.to_be_bytes()); // ttl
        out.extend_from_slice(&4u16.to_be_bytes()); // rdlength
        out.extend_from_slice(&resolver.address_for(&name).to_be_bytes());
    }
    Some(out)
}

// -- loopback ---------------------------------------------------------------

pub use crate::tcploop::LoopEnd;

/// One end of a TCP connection between guests in different processes of a
/// page: a stream in the global kernel (`unix::Remote`), named by the port
/// (`tcp_name`), each end an id there.
pub struct RemoteEnd {
    id: i32,
    remote: crate::unix::Remote,
    /// A write found the far end closed and was taken anyway, as Linux takes
    /// the first one before the peer's reset arrives; the next is `EPIPE`
    /// (`LoopEnd::reset`; tests/gexcc/tcphalfclose).
    reset: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for RemoteEnd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RemoteEnd({})", self.id)
    }
}

impl RemoteEnd {
    /// An end by its id in the global kernel: one `carry` handed over.
    pub fn adopt(id: i32, remote: crate::unix::Remote) -> RemoteEnd {
        RemoteEnd { id, remote, reset: Default::default() }
    }
}

impl Transport for RemoteEnd {
    fn connect(&self, _host: &str, _port: u16) -> Result<(), Errno> {
        Ok(())
    }
    /// Another id on the same end of the global kernel's stream: the end
    /// lives until its last id closes, and `shutdown` on any id is the end's.
    fn carry(&self) -> Option<String> {
        match (self.remote.dup)(self.id) {
            n if n >= 0 => Some(format!("loop:{n}")),
            _ => None,
        }
    }
    fn wait_queue(&self) -> u32 {
        (self.remote.queue)(self.id)
    }
    fn status(&self) -> Status {
        Status::Open
    }
    fn send(&self, data: &[u8]) -> Result<usize, Errno> {
        match (self.remote.write)(self.id, data.as_ptr() as crate::PAddr, data.len() as u32) {
            n if n >= 0 => Ok(n as usize),
            n if Errno(-n) == Errno::EPIPE && !data.is_empty() && !self.reset.swap(true, Ordering::Relaxed) => Ok(data.len()),
            n => Err(Errno(-n)),
        }
    }
    fn recv(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        match (self.remote.read)(self.id, buf.as_mut_ptr() as crate::PAddr, buf.len() as u32) {
            n if n >= 0 => Ok(n as usize),
            n => Err(Errno(-n)),
        }
    }
    /// The global kernel's `recv` with `MSG_PEEK` (its descriptor-passing
    /// read, asked for none).
    fn peek(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        let mut out = [0u8; 8];
        let n = (self.remote.read_fds)(
            self.id,
            buf.as_mut_ptr() as crate::PAddr,
            buf.len() as u32,
            0,
            1,
            0,
            out.as_mut_ptr() as crate::PAddr,
            out.len() as u32,
        );
        if n < 0 {
            return Err(Errno(-n));
        }
        Ok(n as usize)
    }
    fn has_data(&self) -> bool {
        (self.remote.readable)(self.id) != 0
    }
    fn available(&self) -> usize {
        (self.remote.available)(self.id).max(0) as usize
    }
    fn close(&self) {
        (self.remote.close)(self.id);
    }
    /// The global kernel's shutdown is SHUT_WR's: the far end reads to its
    /// end. SHUT_RD only changes this end, which the far end is not told.
    fn shutdown(&self, how: u64) -> Result<(), Errno> {
        if how == 1 || how == 2 {
            let _ = (self.remote.shutdown)(self.id, 1);
        }
        Ok(())
    }
}

/// The global kernel's name for a TCP port (abstract, so no file appears).
fn tcp_name(port: u16) -> String {
    format!("\0gex-tcp:{port}")
}

/// The global kernel's name for a UDP port. The global kernel has only
/// streams, so datagrams between a page's processes travel framed over one
/// stream per (sender, port): a 4-byte length and a 2-byte source port
/// (little-endian), then the bytes.
fn udp_name(port: u16) -> String {
    format!("\0gex-udp:{port}")
}

/// A UDP socket's side of the global kernel (`Socket::udp_remote`).
#[derive(Debug, Default)]
struct UdpRemote {
    /// The listener its port is bound as.
    listener: Option<i32>,
    /// Accepted streams from senders, each with the bytes read from it that
    /// do not yet make a whole datagram.
    inbound: Vec<(i32, Vec<u8>)>,
    /// Streams to the ports this socket has sent to.
    outbound: HashMap<u16, i32>,
}

/// A UDP socket's flow off this machine: where to, and the host's transport.
#[derive(Debug)]
struct Flow {
    to: (u32, u16),
    t: Arc<dyn Transport>,
}

impl Flow {
    fn ended(&self) -> bool {
        matches!(self.t.status(), Status::Closed | Status::Refused)
    }
}

/// In the global kernel, a moved UDP socket's flows off the machine: one per
/// far address, the last one a holder opened there (`op::FLOW`), each line
/// `ADDR:PORT:TRANSPORT`. `gen` counts the changes, so a holder takes the
/// table up only when it has changed (`Socket::sync_flows`).
#[derive(Debug, Default)]
struct FlowNames {
    gen: u64,
    list: Vec<((u32, u16), String)>,
}

impl FlowNames {
    fn set(&mut self, line: &str) {
        let Some((to, _)) = parse_flow(line) else { return };
        match self.list.iter_mut().find(|e| e.0 == to) {
            Some(e) => e.1 = line.to_string(),
            None => self.list.push((to, line.to_string())),
        }
        self.gen += 1;
    }

    fn text(&self) -> String {
        self.list.iter().map(|e| e.1.as_str()).collect::<Vec<_>>().join("\n")
    }
}

/// A moved UDP socket's AVAILABLE answer: the next datagram's length in
/// the low bits (at most 65535), the flow table's generation above them.
const DGRAM_LEN_BITS: u32 = 17;
const DGRAM_LEN_MASK: u64 = (1 << DGRAM_LEN_BITS) - 1;

/// A flow table line, `ADDR:PORT:TRANSPORT`.
fn parse_flow(line: &str) -> Option<((u32, u16), &str)> {
    let mut p = line.splitn(3, ':');
    let (a, port, name) = (p.next()?, p.next()?, p.next()?);
    Some(((a.parse().ok()?, port.parse().ok()?), name))
}

/// The TCP ports guests on this machine listen on. Shared across `fork`, as
/// the resolver is: a child connects to its parent's listener.
#[derive(Debug, Default)]
pub struct Ports {
    listeners: Mutex<HashMap<u16, std::sync::Weak<Socket>>>,
    /// Bound UDP sockets, by port: where a datagram to the loopback goes.
    udp: Mutex<HashMap<u16, std::sync::Weak<Socket>>>,
    next_ephemeral: AtomicU32,
}

impl Ports {
    pub fn new() -> Ports {
        Ports::default()
    }

    /// A port nothing listens on, from Linux's ephemeral range.
    fn ephemeral(&self) -> u16 {
        loop {
            let n = self.next_ephemeral.fetch_add(1, Ordering::Relaxed);
            let port = 32768 + (n % 28232) as u16;
            if !self.listening(port) {
                return port;
            }
        }
    }

    fn listening(&self, port: u16) -> bool {
        self.listeners.lock().unwrap().get(&port).is_some_and(|w| w.strong_count() > 0)
    }

    fn listener(&self, port: u16) -> Option<Arc<Socket>> {
        self.listeners.lock().unwrap().get(&port).and_then(|w| w.upgrade())
    }

    fn udp_at(&self, port: u16) -> Option<Arc<Socket>> {
        self.udp.lock().unwrap().get(&port).and_then(|w| w.upgrade())
    }

    /// A UDP port nothing is bound to.
    fn udp_ephemeral(&self) -> u16 {
        loop {
            let p = self.ephemeral();
            if self.udp_at(p).is_none() {
                return p;
            }
        }
    }
}

/// Whether an address is this machine: the loopback network, or the
/// unspecified address, which Linux takes to mean it too.
pub fn is_local(addr: u32) -> bool {
    addr >> 24 == 127 || addr == 0
}

// -- sockets ----------------------------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Tcp,
    /// To the resolver (this kernel), guests on this machine, and the host's
    /// flows (`NetStack::udp`).
    Udp,
}

/// A socket, as a descriptor.
#[derive(Debug)]
pub struct Socket {
    pub kind: Kind,
    net: Arc<dyn NetStack>,
    resolver: Arc<Resolver>,
    transport: Mutex<Option<Arc<dyn Transport>>>,
    /// Where `connect` pointed, for `getpeername`.
    peer: Mutex<Option<(u32, u16)>>,
    /// Datagrams waiting to be read, with where each came from: the
    /// resolver's answers, and datagrams from guests on this machine.
    dgrams: Mutex<VecDeque<(Vec<u8>, (u32, u16))>>,
    /// Where the last datagram read came from, for `recvfrom`.
    last_from: Mutex<Option<(u32, u16)>>,
    /// Held by a `recvfrom`/`recvmsg` from its read until it has read
    /// `last_from` ([`Self::recv_turn`]): the address is set by the read and
    /// asked for after it, so two threads receiving on one socket could each
    /// report the other's sender.
    recv_turn: Mutex<()>,
    /// This socket, for registering itself (a UDP port's table entry).
    me: Mutex<std::sync::Weak<Socket>>,
    nonblocking: AtomicBool,
    /// The machine's listening ports.
    ports: Arc<Ports>,
    /// Where `bind` (or a loopback `connect`) put this end, for
    /// `getsockname`; the port `listen` listens on.
    local: Mutex<Option<(u32, u16)>>,
    /// A listener's connections waiting for `accept`: the far end of each,
    /// and the port it came from. `None` unless listening.
    backlog: Mutex<Option<VecDeque<(Arc<dyn Transport>, u16)>>>,
    /// The global kernel, when there is one (a page: a Worker per process).
    /// Listeners and loopback connections live there, so a guest in another
    /// process can reach them.
    remote: Option<crate::unix::Remote>,
    /// A listener's id in the global kernel.
    remote_listener: Mutex<Option<i32>>,
    /// A UDP socket's streams in the global kernel.
    udp_remote: Mutex<UdpRemote>,
    /// The id of this socket's hold in the global kernel once it has moved
    /// there (`move_out`), else -1: every call is then that socket's, and the
    /// fields above are unused, until a connection out brings it back
    /// (`go_out`, `come_back`). For a socket that never leaves its process
    /// it costs one load per call.
    moved: std::sync::atomic::AtomicI32,
    /// In the global kernel: the connection a holder made out of it, by
    /// name (`op::GO_OUT`). Every holder then holds that connection itself.
    went_out: Mutex<Option<String>>,
    /// A UDP socket's flows off this machine (`send_out`), each opened at
    /// its first datagram. A moved socket's holders each hold the ones any
    /// of them opened (`sync_flows`); what arrives on them is read here.
    flows: Mutex<Vec<Flow>>,
    /// A moved socket's flow table's generation when this holder last took
    /// it up (`sync_flows`).
    flows_seen: std::sync::atomic::AtomicU64,
    /// Where a moved socket's holder starts its next look over its flows
    /// (`flow_read`), so a busy one does not keep the rest waiting.
    flow_turn: std::sync::atomic::AtomicUsize,
    /// A moved socket's last datagram read came from one of this holder's
    /// flows, not the global kernel's queue: `last_from` is this one's.
    from_here: AtomicBool,
    /// In the global kernel: a moved socket's flows (`op::FLOW`).
    flow_names: Mutex<FlowNames>,
    /// A UDP socket's connects (`udp_connect`'s `soisconnected`).
    connects: AtomicU32,
    /// A read found the end of a connection whose TCP is the host's (its
    /// end of file, or an error): a FIN, a reset or a timeout that
    /// connection does not say which.
    host_end_seen: AtomicBool,
    /// How a connect the host made failed: [`CONNECT_RESET`],
    /// [`CONNECT_TIMED_OUT`], or 0.
    connect_failed: std::sync::atomic::AtomicU8,
    /// Its owner (`so_pgid`, `SS_ASYNC`).
    owner: Arc<crate::vfs::SoOwner>,
    /// Its connection makes the wakeups that signal the owner
    /// ([`Transport::set_owner`]).
    owner_linked: AtomicBool,
    /// SO_OOBINLINE, for the connection it makes.
    oobinline: AtomicBool,
    /// A Darwin process's socket: its options kept with it (which its
    /// connections' new sockets take, `sonewconn`), and XNU's errors.
    xnu: AtomicBool,
    xnu_opts: Mutex<Option<crate::darwin::sockopt::SockOpts>>,
    /// The ECONNREFUSED a refused connection left (`tcp_drop`'s so_error)
    /// has been taken.
    refused_taken: AtomicBool,
    /// [`Self::started`]'s failure, for the call that reports it.
    started_err: Mutex<Option<Errno>>,
}

/// What a Darwin connect's first part leaves ([`Socket::xnu_connect`]).
#[derive(Debug, PartialEq, Eq)]
pub enum XnuConnect {
    /// The call's answer.
    Done(Result<(), Errno>),
    /// The socket is connecting: the call sleeps until it is not
    /// (`connectit`'s msleep), then reports `so_error`
    /// ([`Socket::xnu_connect_waited`]).
    Wait,
    /// A case this kernel does not model, to be said.
    Unmodelled(&'static str),
}

/// A connect met a reset (`tcp_input` in SYN_SENT: SO_FILT_HINT_CONNRESET,
/// then `tcp_drop(ECONNREFUSED)`).
const CONNECT_RESET: u8 = 1;
/// A connect's retransmissions ran out (`tcp_timers`' TCPT_REXMT:
/// SO_FILT_HINT_TIMEOUT, then `tcp_drop(ETIMEDOUT)`).
const CONNECT_TIMED_OUT: u8 = 2;

impl Socket {
    pub fn new(kind: Kind, net: Arc<dyn NetStack>, resolver: Arc<Resolver>, ports: Arc<Ports>, remote: Option<crate::unix::Remote>) -> Socket {
        Socket {
            kind,
            net,
            resolver,
            transport: Mutex::new(None),
            peer: Mutex::new(None),
            dgrams: Mutex::new(VecDeque::new()),
            last_from: Mutex::new(None),
            recv_turn: Mutex::new(()),
            me: Mutex::new(std::sync::Weak::new()),
            nonblocking: AtomicBool::new(false),
            ports,
            local: Mutex::new(None),
            backlog: Mutex::new(None),
            remote,
            remote_listener: Mutex::new(None),
            udp_remote: Mutex::new(UdpRemote::default()),
            moved: std::sync::atomic::AtomicI32::new(-1),
            went_out: Mutex::new(None),
            flows: Mutex::new(Vec::new()),
            flows_seen: std::sync::atomic::AtomicU64::new(0),
            flow_turn: std::sync::atomic::AtomicUsize::new(0),
            from_here: AtomicBool::new(false),
            flow_names: Mutex::new(FlowNames::default()),
            connects: AtomicU32::new(0),
            host_end_seen: AtomicBool::new(false),
            connect_failed: Default::default(),
            owner: Default::default(),
            owner_linked: AtomicBool::new(false),
            oobinline: AtomicBool::new(false),
            xnu: AtomicBool::new(false),
            xnu_opts: Mutex::new(None),
            refused_taken: AtomicBool::new(false),
            started_err: Mutex::new(None),
        }
    }

    /// A connect started ahead of the call that reports it (a blocking
    /// call's wait set up first): a failure it met is that call's answer,
    /// not a second connect's.
    pub fn started(&self, r: Result<(), Errno>) {
        if let Err(e) = r {
            if e != Errno::EINPROGRESS {
                *self.started_err.lock().unwrap() = Some(e);
            }
        }
    }

    /// A Darwin process's socket ([`Self::xnu`]).
    pub fn use_xnu(&self) {
        self.xnu.store(true, Ordering::Release);
    }

    fn is_xnu(&self) -> bool {
        self.xnu.load(Ordering::Acquire)
    }

    /// What of a Darwin socket's options its TCP reads.
    fn xnu_tcp_opts(&self) -> crate::tcploop::TcpOpts {
        self.xnu_opts.lock().unwrap().map(|o| o.tcp()).unwrap_or_default()
    }

    /// A Darwin socket's options changed (`tcp_ctloutput`): its connection's
    /// TCP told, with what the change does to its timers.
    pub fn xnu_tcp_opts_changed(&self, change: crate::tcploop::OptChange) {
        let opts = self.xnu_tcp_opts();
        if let Some(t) = self.transport.lock().unwrap().as_ref() {
            t.tcp_opts(opts, change);
        }
    }

    /// Whether this socket's TCP, if it has a connection, is this kernel's
    /// (its timers run here): a connection between two sockets here; a
    /// socket with none yet whose connection may be (a listener here, a
    /// socket yet to connect, which [`Self::connects_here`] decides).
    pub fn tcp_here(&self) -> bool {
        if self.kind != Kind::Tcp || self.moved().is_some() || self.remote_listener.lock().unwrap().is_some() {
            return false;
        }
        match self.transport.lock().unwrap().as_ref() {
            Some(t) => t.tcp_end().is_some(),
            None => true,
        }
    }

    /// Whether a connect to `addr`:`port` would make a connection between
    /// two sockets here (a guest listening on this machine's port).
    pub fn connects_here(&self, addr: u32, port: u16) -> bool {
        self.kind == Kind::Tcp && is_local(addr) && self.remote.is_none() && self.moved().is_none() && self.ports.listener(port).is_some()
    }

    /// The timers of this socket's connection run, and when its next is
    /// due ([`Transport::next_deadline`]).
    pub fn tcp_deadline(&self) -> Option<std::time::Instant> {
        let t = self.transport.lock().unwrap().clone();
        t.and_then(|t| t.next_deadline())
    }

    /// `connectit` for a Darwin internet socket, up to its sleep:
    /// `soconnectlock`'s checks, the protocol's connect, and what is left
    /// for the call (`nbio`: the socket is SS_NBIO).
    pub fn xnu_connect(&self, addr: u32, port: u16, nbio: bool) -> XnuConnect {
        use XnuConnect::*;
        // A UDP socket's connect, and one the global kernel holds, as they
        // were.
        if self.moved().is_some() || self.kind == Kind::Udp {
            return Done(self.connect(addr, port));
        }
        let t = self.transport.lock().unwrap().clone();
        let connecting = t.as_ref().is_some_and(|t| t.status() == Status::Connecting);
        // connectit: a non-blocking socket still connecting.
        if nbio && connecting {
            return Done(Err(Errno::EALREADY));
        }
        // soconnectlock: a listener (SO_ACCEPTCONN).
        if self.backlog.lock().unwrap().is_some() || self.remote_listener.lock().unwrap().is_some() {
            return Done(Err(Errno::EOPNOTSUPP));
        }
        if let Some(t) = t {
            // soconnectlock: SS_ISCONNECTED or SS_ISCONNECTING, and TCP
            // connects once (PR_CONNREQUIRED).
            if connecting {
                return Done(Err(Errno::EISCONN));
            }
            match t.tcp_end() {
                Some(e) if e.connected => return Done(Err(Errno::EISCONN)),
                // tcp_usr_connect on a dead PCB: so_error, taken, else
                // EINVAL.
                Some(e) if e.closed => return Done(Err(t.take_error().unwrap_or(Errno::EINVAL))),
                // tcp_connect: the connection, in FIN_WAIT_2 or TIME_WAIT,
                // is still in the hash under the address asked for.
                Some(_) if self.peer() == Some((addr, port)) => return Done(Err(Errno::EADDRINUSE)),
                Some(_) => return Unmodelled("connect of a TCP socket whose connection has not closed, to another address (tcp_connect starting a new connection on its PCB)"),
                None => {}
            }
            return match t.status() {
                Status::Open => Done(Err(Errno::EISCONN)),
                // tcp_drop(ECONNREFUSED)'s dead PCB: so_error if not taken.
                Status::Refused => Done(Err(if self.take_refused() { Errno::ECONNREFUSED } else { Errno::EINVAL })),
                Status::Closed => Unmodelled("connect of a TCP socket whose connection the host carried has ended (its PCB's state is the host's)"),
                Status::Connecting => unreachable!("handled above"),
            };
        }
        // A connection the host's connect failed: its PCB is dead, its
        // so_error taken by that connect.
        if self.connect_failed.load(Ordering::Acquire) != 0 {
            return Done(Err(Errno::EINVAL));
        }
        match self.connect(addr, port) {
            // tcp_connect leaves the socket SS_ISCONNECTING with its SYN
            // sent; a connection between two sockets here is up before the
            // call is back, but a non-blocking call returns as connectit
            // does, before the SYN's answer.
            Ok(()) | Err(Errno::EINPROGRESS) if nbio => Done(Err(Errno::EINPROGRESS)),
            Err(Errno::EINPROGRESS) => Wait,
            r => Done(r),
        }
    }

    /// `connectit` after its sleep: SS_ISCONNECTING over, `so_error`
    /// taken. `r` is the wait's own answer, for a connection whose end
    /// says nothing more (the host's).
    pub fn xnu_connect_waited(&self, r: Result<(), Errno>) -> Result<(), Errno> {
        match self.status() {
            Status::Open => Ok(()),
            // Another taking it first leaves the connect 0.
            Status::Refused => {
                if self.take_refused() {
                    Err(Errno::ECONNREFUSED)
                } else {
                    Ok(())
                }
            }
            Status::Connecting | Status::Closed => r,
        }
    }

    /// A refused connection's so_error, taken once (connect, a read or
    /// SO_ERROR report it).
    fn take_refused(&self) -> bool {
        !self.refused_taken.swap(true, Ordering::AcqRel)
    }

    /// `soshutdown` of a Darwin TCP socket's reading: `sorflush` (the
    /// buffer dropped, later data with it); false where the connection is
    /// the host's.
    pub fn sorflush(&self) -> bool {
        match self.transport.lock().unwrap().as_ref() {
            Some(t) => t.sorflush(),
            None => false,
        }
    }

    /// Remember the `Arc` this socket lives in (made right after `new`).
    pub fn set_self(self: &Arc<Self>) {
        *self.me.lock().unwrap() = Arc::downgrade(self);
    }

    /// One receiver at a time, from its read to its `last_from`: a guard
    /// the syscall layer holds across both.
    pub fn recv_turn(&self) -> std::sync::MutexGuard<'_, ()> {
        self.recv_turn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Where the last datagram read came from.
    pub fn last_from(&self) -> Option<(u32, u16)> {
        if self.moved().is_some() && self.from_here.load(Ordering::Acquire) {
            return *self.last_from.lock().unwrap();
        }
        if let Some(v) = self.fwd(op::LAST_FROM, 0, 0, &mut []) {
            return unpack_addr(v);
        }
        *self.last_from.lock().unwrap()
    }

    /// Give this UDP socket a port (`bind`, or the first send unbound),
    /// registered so guests here can send to it.
    fn udp_take(&self, addr: u32, mut port: u16) -> Result<(), Errno> {
        // In a page: the port is a name in the global kernel, where every
        // process sees it.
        if let Some(r) = self.remote {
            let fixed = port != 0;
            for _ in 0..1000 {
                if !fixed {
                    port = self.ports.udp_ephemeral();
                }
                let n = udp_name(port);
                let id = (r.bind)(n.as_ptr() as crate::PAddr, n.len() as u32, 0, 0, 0);
                if id >= 0 {
                    self.udp_remote.lock().unwrap().listener = Some(id);
                    *self.local.lock().unwrap() = Some((addr, port));
                    return Ok(());
                }
                if fixed || -id != Errno::EADDRINUSE.0 {
                    return Err(Errno(-id));
                }
            }
            return Err(Errno::EADDRINUSE);
        }
        let mut udp = self.ports.udp.lock().unwrap();
        if port == 0 {
            drop(udp);
            port = self.ports.udp_ephemeral();
            udp = self.ports.udp.lock().unwrap();
        }
        if udp.get(&port).is_some_and(|w| w.strong_count() > 0) {
            return Err(Errno::EADDRINUSE);
        }
        udp.insert(port, self.me.lock().unwrap().clone());
        *self.local.lock().unwrap() = Some((addr, port));
        Ok(())
    }

    /// `bind`: where this socket is. A port another listener holds is
    /// `EADDRINUSE` (SO_REUSEADDR is not modelled: a listener that went away
    /// frees its port at once).
    pub fn bind(&self, addr: u32, port: u16) -> Result<(), Errno> {
        if let Some(v) = self.fwd(op::BIND, addr as u64, port as u64, &mut []) {
            return Socket::unit(v);
        }
        if self.local.lock().unwrap().is_some() {
            return Err(Errno::EINVAL);
        }
        if self.kind == Kind::Udp {
            return self.udp_take(addr, port);
        }
        // (In a page the global kernel answers at `listen`: its name table
        // keeps a closed listener's name until the name is bound again.)
        if port != 0 && self.kind == Kind::Tcp && self.remote.is_none() && self.ports.listening(port) {
            return Err(Errno::EADDRINUSE);
        }
        // Port 0 is a port of the kernel's choosing, chosen now, as Linux
        // does: a program reads it back with getsockname before listening
        // (Wine's server does, for every bind), and connects to it.
        let mut port = port;
        if port == 0 {
            port = self.ports.ephemeral();
            while self.remote_taken(port) {
                port = self.ports.ephemeral();
            }
        }
        *self.local.lock().unwrap() = Some((addr, port));
        Ok(())
    }

    /// Whether a guest in any process of the page listens on `port`.
    fn remote_taken(&self, port: u16) -> bool {
        self.remote.is_some_and(|r| {
            let n = tcp_name(port);
            (r.exists)(n.as_ptr() as crate::PAddr, n.len() as u32) > 0
        })
    }

    /// Where this end is, for `getsockname`: 0.0.0.0:0 when unbound.
    pub fn local(&self) -> (u32, u16) {
        if let Some(v) = self.fwd(op::LOCAL, 0, 0, &mut []) {
            return unpack_addr(v).unwrap_or((0, 0));
        }
        self.local.lock().unwrap().unwrap_or((0, 0))
    }

    /// `listen`: take the bound port (an ephemeral one if none), and
    /// connections from this machine's guests.
    pub fn listen(self: &Arc<Self>) -> Result<(), Errno> {
        if let Some(v) = self.fwd(op::LISTEN, 0, 0, &mut []) {
            return Socket::unit(v);
        }
        if self.kind != Kind::Tcp || self.transport.lock().unwrap().is_some() {
            return Err(Errno::EOPNOTSUPP);
        }
        let mut backlog = self.backlog.lock().unwrap();
        if backlog.is_some() {
            return Ok(());
        }
        let (addr, mut port) = self.local();
        if let Some(r) = self.remote {
            // In the global kernel: bound and listening in one, as a unix
            // socket there is.
            if port == 0 {
                port = self.ports.ephemeral();
                while self.remote_taken(port) {
                    port = self.ports.ephemeral();
                }
            }
            let n = tcp_name(port);
            let id = (r.bind)(n.as_ptr() as crate::PAddr, n.len() as u32, 0, 0, 0);
            if id < 0 {
                return Err(if -id == Errno::EADDRINUSE.0 || -id == 98 { Errno::EADDRINUSE } else { Errno(-id) });
            }
            *self.remote_listener.lock().unwrap() = Some(id);
            *self.local.lock().unwrap() = Some((addr, port));
            *backlog = Some(VecDeque::new());
            return Ok(());
        }
        let mut listeners = self.ports.listeners.lock().unwrap();
        if port == 0 {
            drop(listeners);
            port = self.ports.ephemeral();
            listeners = self.ports.listeners.lock().unwrap();
        }
        if listeners.get(&port).is_some_and(|w| w.strong_count() > 0) {
            return Err(Errno::EADDRINUSE);
        }
        listeners.insert(port, Arc::downgrade(self));
        *self.local.lock().unwrap() = Some((addr, port));
        *backlog = Some(VecDeque::new());
        Ok(())
    }

    pub fn is_listening(&self) -> bool {
        if let Some(v) = self.fwd(op::LISTENING, 0, 0, &mut []) {
            return v > 0;
        }
        self.backlog.lock().unwrap().is_some()
    }

    /// `accept`: the next waiting connection as a socket of its own, or
    /// `EAGAIN`; `EINVAL` when not listening.
    pub fn accept(&self) -> Result<Arc<Socket>, Errno> {
        let mut name = [0u8; 160];
        if let Some(n) = self.moved().and_then(|_| self.fwd(op::ACCEPT, 0, 0, &mut name)) {
            // The connection comes back as its `carry` name: an end in the
            // global kernel, held by this process now.
            if n < 0 {
                return Err(errno_of(n));
            }
            let name = std::str::from_utf8(&name[..n as usize]).map_err(|_| Errno::EINVAL)?;
            let r = self.remote.ok_or(Errno::EINVAL)?;
            let id = Socket::carried_transport(name)
                .and_then(|t| t.strip_prefix("loop:"))
                .and_then(|t| t.parse::<i32>().ok())
                .ok_or(Errno::EINVAL)?;
            let t: Arc<dyn Transport> = Arc::new(RemoteEnd::adopt(id, r));
            return Socket::adopt(name, t, Arc::clone(&self.net), Arc::clone(&self.resolver), Arc::clone(&self.ports), self.remote)
                .ok_or(Errno::EINVAL);
        }
        let remote_listener = *self.remote_listener.lock().unwrap();
        let (t, from): (Arc<dyn Transport>, (u32, u16)) = match (remote_listener, self.remote) {
            (Some(id), Some(r)) => match (r.accept)(id) {
                // Where the far end connected from, as its `connect` said.
                n if n >= 0 => {
                    let mut b = [0u8; 8];
                    let from = if (r.peer_addr)(n, b.as_mut_ptr() as crate::PAddr) == 0 {
                        (u32::from_le_bytes(b[..4].try_into().unwrap()), u32::from_le_bytes(b[4..].try_into().unwrap()) as u16)
                    } else {
                        (0x7f00_0001, 0)
                    };
                    (Arc::new(RemoteEnd { id: n, remote: r, reset: Default::default() }), from)
                }
                n => return Err(Errno(-n)),
            },
            _ => match &mut *self.backlog.lock().unwrap() {
                Some(q) => q.pop_front().map(|(t, p)| (t, (0x7f00_0001, p))).ok_or(Errno::EAGAIN)?,
                None => return Err(Errno::EINVAL),
            },
        };
        let s = Socket::new(Kind::Tcp, Arc::clone(&self.net), Arc::clone(&self.resolver), Arc::clone(&self.ports), self.remote);
        // sonewconn: the listener's owner, options and buffers (and TCP's
        // from its listener's), and SO_OOBINLINE with them.
        s.owner.inherit(&self.owner);
        s.owner_linked.store(t.set_owner(&s.owner), Ordering::Release);
        if self.is_xnu() {
            s.use_xnu();
            let head = *self.xnu_opts.lock().unwrap();
            if let Some(h) = head {
                *s.xnu_opts.lock().unwrap() = Some(crate::darwin::sockopt::SockOpts::inherited(&h, h.snd_hiwat, h.rcv_hiwat));
                let inline = h.options & crate::darwin::sockopt::so::OOBINLINE != 0;
                s.oobinline.store(inline, Ordering::Release);
                t.set_oobinline(inline);
            }
        }
        *s.transport.lock().unwrap() = Some(t);
        *s.peer.lock().unwrap() = Some(from);
        *s.local.lock().unwrap() = Some((0x7f00_0001, self.local().1));
        let s = Arc::new(s);
        s.set_self();
        Ok(s)
    }

    /// A connection to a port a guest on this machine listens on: both ends
    /// made here, the far one queued for the listener's `accept`.
    fn connect_local(&self, listener: &Socket, port: u16) -> Result<(), Errno> {
        let (mine, theirs) = LoopEnd::pair();
        // A Darwin end's TCP is XNU's: this socket's options, and the new
        // connection's those its listener's give it (sonewconn, tcp_input).
        if self.is_xnu() {
            mine.set_xnu(self.xnu_tcp_opts());
        }
        if listener.is_xnu() {
            let head = listener.xnu_opts.lock().unwrap().map(|h| crate::darwin::sockopt::SockOpts::inherited(&h, h.snd_hiwat, h.rcv_hiwat).tcp());
            theirs.set_xnu(head.unwrap_or_default());
        }
        let from = self.ports.ephemeral();
        match &mut *listener.backlog.lock().unwrap() {
            Some(q) => q.push_back((theirs, from)),
            None => return Err(Errno::ECONNREFUSED),
        }
        *self.peer.lock().unwrap() = Some((0x7f00_0001, port));
        *self.local.lock().unwrap() = Some((0x7f00_0001, from));
        self.owner_linked.store(mine.set_owner(&self.owner), Ordering::Release);
        mine.set_oobinline(self.oobinline.load(Ordering::Acquire));
        *self.transport.lock().unwrap() = Some(mine);
        // The connection queued (soisconnected's sorwakeup of the head),
        // and this end connected (its sorwakeup and sowwakeup).
        listener.owner.wakeup();
        self.owner.wakeup();
        Ok(())
    }

    pub fn set_nonblocking(&self, on: bool) {
        self.nonblocking.store(on, Ordering::Relaxed);
    }

    pub fn peer(&self) -> Option<(u32, u16)> {
        if let Some(v) = self.fwd(op::PEER, 0, 0, &mut []) {
            return unpack_addr(v);
        }
        *self.peer.lock().unwrap()
    }

    /// Remember where a datagram went, so the reply can be reported as coming
    /// from there: a resolver drops replies whose source is not the nameserver
    /// it asked, so 0.0.0.0 made every answer look spoofed.
    pub fn set_peer(&self, addr: u32, port: u16) {
        if self.fwd(op::SET_PEER, addr as u64, port as u64, &mut []).is_some() {
            return;
        }
        *self.peer.lock().unwrap() = Some((addr, port));
    }

    /// This socket as a name another process can rebuild it from (a page's
    /// `SCM_RIGHTS` and fork): `inet:PEER:PORT:LOCAL:PORT:TRANSPORT`, the last
    /// part the transport's own (`Transport::carry`), counted as one more
    /// holder of the connection. Only a TCP socket with a connection (open or
    /// still connecting) can go: the two copies are then one connection, as
    /// two descriptors are one socket. One not yet connected cannot -- its
    /// copies would connect apart -- nor can a listener or a UDP socket.
    pub fn carry(&self) -> Option<String> {
        // A moved socket goes as another hold on it (`move_out`).
        if self.moved().is_some() {
            return None;
        }
        if self.kind != Kind::Tcp || self.backlog.lock().unwrap().is_some() {
            return None;
        }
        let t = self.transport.lock().unwrap().as_ref()?.carry()?;
        let (pa, pp) = self.peer().unwrap_or((0, 0));
        let (la, lp) = self.local();
        Some(format!("inet:{pa}:{pp}:{la}:{lp}:{t}"))
    }

    /// The other half of `carry`: a TCP socket on `transport` (what the
    /// name's last part was rebuilt into), where the name says it was.
    pub fn adopt(
        desc: &str,
        transport: Arc<dyn Transport>,
        net: Arc<dyn NetStack>,
        resolver: Arc<Resolver>,
        ports: Arc<Ports>,
        remote: Option<crate::unix::Remote>,
    ) -> Option<Arc<Socket>> {
        let mut p = desc.strip_prefix("inet:")?.splitn(5, ':');
        let pa = p.next()?.parse::<u32>().ok()?;
        let pp = p.next()?.parse::<u16>().ok()?;
        let la = p.next()?.parse::<u32>().ok()?;
        let lp = p.next()?.parse::<u16>().ok()?;
        let sock = Arc::new(Socket::new(Kind::Tcp, net, resolver, ports, remote));
        sock.set_self();
        if pa != 0 || pp != 0 {
            *sock.peer.lock().unwrap() = Some((pa, pp));
        }
        if la != 0 || lp != 0 {
            *sock.local.lock().unwrap() = Some((la, lp));
        }
        *sock.transport.lock().unwrap() = Some(transport);
        Some(sock)
    }

    /// The transport part of a `carry` name (`wisp:N`, `loop:N`).
    pub fn carried_transport(desc: &str) -> Option<&str> {
        desc.strip_prefix("inet:")?.splitn(5, ':').nth(4)
    }

    /// `connect`. Returns `EINPROGRESS` while still connecting; the kernel
    /// turns that into a wait for a blocking descriptor. Idempotent: asking
    /// twice does not open a second connection.
    pub fn connect(&self, addr: u32, port: u16) -> Result<(), Errno> {
        // The answer of the connect a waiting call started
        // ([`Self::started`]), which this call reports.
        if let Some(e) = self.started_err.lock().unwrap().take() {
            return Err(e);
        }
        if let Some(v) = self.fwd(op::CONNECT, addr as u64, port as u64, &mut []) {
            // The global kernel has no network of its own: a connection
            // out is made here, and the socket comes back to this process
            // (`go_out`).
            if v != -(Errno::ENETUNREACH.0 as i64) || self.kind != Kind::Tcp {
                return Socket::unit(v);
            }
            return self.go_out(addr, port);
        }
        if let Some(t) = self.transport.lock().unwrap().as_ref() {
            if self.is_xnu() && t.tcp_end().is_some_and(|e| e.disconnected()) {
                return Err(Errno::EINVAL);
            }
            return match t.status() {
                Status::Connecting => Err(Errno::EINPROGRESS),
                Status::Open => Ok(()),
                // XNU's connect takes so_error; after that the dead PCB's
                // pru_connect is EINVAL.
                Status::Refused if self.is_xnu() && !self.take_refused() => Err(Errno::EINVAL),
                Status::Refused => Err(Errno::ECONNREFUSED),
                Status::Closed => Err(Errno::ECONNRESET),
            };
        }
        // A Darwin socket whose connection was dropped: its PCB is dead.
        if self.is_xnu() && self.kind == Kind::Tcp && self.connect_failed.load(Ordering::Acquire) != 0 {
            return Err(Errno::EINVAL);
        }
        // A port a guest here listens on: connected at once, no network
        // involved. (One nothing here listens on still goes out: the host
        // may have a service on its own loopback.)
        if self.kind == Kind::Tcp && is_local(addr) {
            if let Some(r) = self.remote {
                let n = tcp_name(port);
                // This end's address goes with the connection: the accepted
                // end's peer is this end (libcurl's loopback socketpair
                // compares the two).
                let from = self.ports.ephemeral();
                let id = (r.connect)(n.as_ptr() as crate::PAddr, n.len() as u32, 0, 0, 0, 0x7f00_0001, from as u32);
                if id >= 0 {
                    *self.peer.lock().unwrap() = Some((0x7f00_0001, port));
                    *self.local.lock().unwrap() = Some((0x7f00_0001, from));
                    *self.transport.lock().unwrap() = Some(Arc::new(RemoteEnd { id, remote: r, reset: Default::default() }));
                    return Ok(());
                }
            } else if let Some(listener) = self.ports.listener(port) {
                return self.connect_local(&listener, port);
            }
        }
        *self.peer.lock().unwrap() = Some((addr, port));
        if self.kind == Kind::Udp {
            // A connected UDP socket only fixes the default destination, and
            // the only destination that means anything here is the resolver.
            self.connects.fetch_add(1, Ordering::AcqRel);
            return Ok(());
        }
        let host = self.host_for(addr);
        let t = self.net.tcp()?;
        if let Err(e) = t.connect(&host, port) {
            // The host's connect ended it: a reset to its SYN, or its
            // retransmissions given up.
            let how = match e {
                Errno::ECONNREFUSED => CONNECT_RESET,
                Errno::ETIMEDOUT => CONNECT_TIMED_OUT,
                _ => 0,
            };
            self.connect_failed.store(how, Ordering::Release);
            return Err(e);
        }
        *self.transport.lock().unwrap() = Some(t);
        Err(Errno::EINPROGRESS)
    }

    /// `shutdown` on a connected stream.
    pub fn shutdown(&self, how: u64) -> Result<u64, Errno> {
        if let Some(v) = self.fwd(op::SHUTDOWN, how, 0, &mut []) {
            return Socket::count(v);
        }
        if how > 2 {
            return Err(Errno::EINVAL);
        }
        match &*self.transport.lock().unwrap() {
            Some(t) => t.shutdown(how).map(|_| 0),
            None => Err(Errno::ENOTCONN),
        }
    }

    /// SO_OOBINLINE of a connected TCP socket, or one yet to connect, for
    /// the urgent data its connection takes; whether it does follow it (a
    /// connection the host or the global kernel carries does not, nor a
    /// listener, whose connections would take its options).
    pub fn set_oobinline(&self, on: bool) -> bool {
        if self.kind != Kind::Tcp || self.moved().is_some() || self.remote_listener.lock().unwrap().is_some() {
            return false;
        }
        self.oobinline.store(on, Ordering::Release);
        match self.transport.lock().unwrap().as_ref() {
            Some(t) => t.set_oobinline(on),
            None => self.remote.is_none(),
        }
    }

    /// Whether urgent data on this socket is followed here: a TCP socket
    /// whose connection, if it has one, is between two sockets here.
    pub fn urgent_followed(&self) -> bool {
        if self.kind != Kind::Tcp || self.moved().is_some() {
            return false;
        }
        match self.transport.lock().unwrap().as_ref() {
            Some(t) => t.oob_state().is_some(),
            None => self.remote.is_none() && self.remote_listener.lock().unwrap().is_none(),
        }
    }

    /// Urgent data sent on the connection ([`Transport::send_oob`]).
    pub fn send_oob(&self, data: &[u8]) -> Option<Result<usize, Errno>> {
        self.transport.lock().unwrap().as_ref().and_then(|t| t.send_oob(data))
    }

    /// The out-of-band byte ([`Transport::recv_oob`]); a socket with no
    /// connection has no mark (EINVAL).
    pub fn recv_oob(&self, peek: bool) -> Option<Result<u8, Errno>> {
        match self.transport.lock().unwrap().as_ref() {
            Some(t) => t.recv_oob(peek),
            None if self.kind == Kind::Tcp && self.moved().is_none() => Some(Err(Errno::EINVAL)),
            None => None,
        }
    }

    /// `SO_ERROR` of a refused connection: ECONNREFUSED, which a Darwin
    /// socket's reading takes.
    pub fn refused_so_error(&self) -> i32 {
        if !self.is_xnu() || self.take_refused() {
            Errno::ECONNREFUSED.0
        } else {
            0
        }
    }

    /// `SO_ERROR`: the error a reset left, taken.
    pub fn take_so_error(&self) -> Option<Errno> {
        self.transport.lock().unwrap().as_ref().and_then(|t| t.take_error())
    }

    pub fn status(&self) -> Status {
        if let Some(v) = self.fwd(op::STATUS, 0, 0, &mut []) {
            return match v {
                0 => Status::Connecting,
                1 => Status::Open,
                3 => Status::Refused,
                _ => Status::Closed,
            };
        }
        match &*self.transport.lock().unwrap() {
            Some(t) => t.status(),
            None => Status::Closed,
        }
    }

    /// A datagram: to a guest on this machine bound to the port it is for,
    /// else to the resolver, which answers it and queues the reply.
    pub fn send_dgram(&self, data: &[u8]) -> SysResult {
        if let Some(v) = self.fwd_write(data) {
            // The global kernel has no network: a datagram off this machine
            // goes out here, on a flow every holder reads (`sync_flows`).
            if v == -(Errno::ENETUNREACH.0 as i64) {
                if let (Some(m), Some(to)) = (self.moved(), self.peer().filter(|&(a, _)| !is_local(a))) {
                    self.sync_flows(m, None);
                    return self.send_out(to, data).map(|_| data.len() as u64);
                }
            }
            return Socket::count(v);
        }
        let to = self.peer();
        if let (Some((_, port)), Some(r)) = (to.filter(|&(a, _)| is_local(a)), self.remote) {
            if self.local.lock().unwrap().is_none() {
                self.udp_take(0, 0)?;
            }
            if let Some(id) = self.udp_stream_to(r, port) {
                let mut frame = Vec::with_capacity(6 + data.len());
                frame.extend_from_slice(&(data.len() as u32).to_le_bytes());
                frame.extend_from_slice(&self.local().1.to_le_bytes());
                frame.extend_from_slice(data);
                let mut at = 0;
                // A stream's buffer is far larger than a datagram; a full one
                // (a receiver that stopped reading) drops it, as UDP may.
                for _ in 0..64 {
                    match (r.write)(id, frame[at..].as_ptr() as crate::PAddr, (frame.len() - at) as u32) {
                        n if n > 0 => at += n as usize,
                        _ => {}
                    }
                    if at == frame.len() {
                        break;
                    }
                }
                return Ok(data.len() as u64);
            }
            // Nothing bound there in any process: lost, as UDP is.
            if answer_dns(data, &self.resolver).is_none() {
                return Ok(data.len() as u64);
            }
        }
        if let Some((addr, port)) = to.filter(|&(a, _)| is_local(a)) {
            if let Some(dest) = self.ports.udp_at(port) {
                if self.local.lock().unwrap().is_none() {
                    self.udp_take(0, 0)?;
                }
                let from = (0x7f00_0001, self.local().1);
                let _ = addr;
                dest.dgrams.lock().unwrap().push_back((data.to_vec(), from));
                return Ok(data.len() as u64);
            }
        }
        // Off this machine, but for DNS: the network's flow there.
        if let Some(to) = to.filter(|&(a, p)| !is_local(a) && p != 53) {
            if self.local.lock().unwrap().is_none() {
                self.udp_take(0, 0)?;
            }
            return self.send_out(to, data).map(|_| data.len() as u64);
        }
        match answer_dns(data, &self.resolver) {
            Some(reply) => {
                self.dgrams.lock().unwrap().push_back((reply, to.unwrap_or((0, 0))));
                Ok(data.len() as u64)
            }
            // Not a question this can answer. Accepting it and never
            // replying is what a lost packet looks like, and a resolver
            // handles that.
            None => Ok(data.len() as u64),
        }
    }

    /// The stream to UDP port `port` in the global kernel, opened once.
    fn udp_stream_to(&self, r: crate::unix::Remote, port: u16) -> Option<i32> {
        let mut u = self.udp_remote.lock().unwrap();
        if let Some(&id) = u.outbound.get(&port) {
            return Some(id);
        }
        let n = udp_name(port);
        let id = (r.connect)(n.as_ptr() as crate::PAddr, n.len() as u32, 0, 0, 0, 0, 0);
        (id >= 0).then(|| {
            u.outbound.insert(port, id);
            id
        })
    }

    /// The name the host is asked for `addr` by: the name, if the address
    /// came from an answer the kernel gave, otherwise the dotted quad -- a
    /// guest using a literal address is asking for exactly that.
    fn host_for(&self, addr: u32) -> String {
        self.resolver.name_for(addr).unwrap_or_else(|| {
            let b = addr.to_be_bytes();
            format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
        })
    }

    /// A datagram to `to`, off this machine: on the host's flow there,
    /// opened at the first (a moved socket's named to the global kernel, so
    /// its other holders read the replies too). `ENETUNREACH` when the
    /// network carries no datagrams.
    fn send_out(&self, to: (u32, u16), data: &[u8]) -> Result<(), Errno> {
        let t = {
            let mut flows = self.flows.lock().unwrap();
            // One the network refused or ended is asked for again.
            flows.retain(|f| {
                let gone = f.to == to && f.ended();
                if gone {
                    f.t.close();
                }
                !gone
            });
            // The last one there: a holder's own and one another opened
            // there after it (`sync_flows`), both read, the newer sent on.
            match flows.iter().rev().find(|f| f.to == to) {
                Some(f) => f.t.clone(),
                None => {
                    let t = self.net.udp()?;
                    t.connect(&self.host_for(to.0), to.1)?;
                    // Refused at once: a network that carries no datagrams.
                    if t.status() == Status::Refused {
                        t.close();
                        return Err(Errno::ENETUNREACH);
                    }
                    if let (Some(m), Some(n)) = (self.moved(), t.name()) {
                        let mut name = format!("{}:{}:{n}", to.0, to.1).into_bytes();
                        (m.r.op)(m.id, op::FLOW, 0, 0, &mut name);
                    }
                    flows.push(Flow { to, t: t.clone() });
                    t
                }
            }
        };
        // A flow that cannot take it drops it, as UDP may.
        let _ = t.send(data);
        Ok(())
    }

    /// The flows a moved socket's other holders opened, held here too, if
    /// the global kernel's table has changed since this holder last looked
    /// (`gen`: its generation, when the caller has it already; else asked).
    /// A flow there that this holder holds already is skipped; one that
    /// replaced this holder's there (it ended and was opened again, or two
    /// opened at once) is taken up beside it, and this holder's ended ones
    /// go.
    fn sync_flows(&self, m: Moved, gen: Option<u64>) {
        let gen = match gen {
            Some(g) => g,
            None => match (m.r.op)(m.id, op::FLOWS, 0, 0, &mut []) {
                g if g >= 0 => g as u64,
                _ => return,
            },
        };
        if self.flows_seen.load(Ordering::Acquire) == gen {
            return;
        }
        let len = (m.r.op)(m.id, op::FLOWS, 2, 0, &mut []);
        if len < 0 {
            return;
        }
        let mut buf = vec![0u8; len as usize];
        let len = (m.r.op)(m.id, op::FLOWS, 1, 0, &mut buf);
        if len < 0 {
            return;
        }
        let mut flows = self.flows.lock().unwrap();
        flows.retain(|f| {
            let gone = f.ended() && !f.t.has_data();
            if gone {
                f.t.close();
            }
            !gone
        });
        let list = String::from_utf8_lossy(&buf[..len as usize]).into_owned();
        for line in list.lines() {
            let Some((to, name)) = parse_flow(line) else { continue };
            if flows.iter().any(|f| f.to == to && f.t.name().as_deref() == Some(name)) {
                continue;
            }
            if let Some(t) = self.net.adopt(name) {
                flows.push(Flow { to, t });
            }
        }
        self.flows_seen.store(gen, Ordering::Release);
    }

    /// What arrived on this socket's flows, queued with where it came from;
    /// a flow that has ended goes (the next datagram there opens another).
    /// Not a moved socket's: its holders read the flows themselves
    /// (`flow_read`), as a datagram queued in one would be lost to the rest.
    fn flows_pump(&self) {
        if self.moved().is_some() {
            return;
        }
        let mut flows = self.flows.lock().unwrap();
        if flows.is_empty() {
            return;
        }
        let mut q = self.dgrams.lock().unwrap();
        let mut buf = Vec::new();
        flows.retain(|f| {
            while f.t.has_data() {
                buf.resize(65536, 0);
                match f.t.recv(&mut buf) {
                    Ok(n) => q.push_back((buf[..n].to_vec(), f.to)),
                    Err(_) => break,
                }
            }
            match f.t.status() {
                Status::Closed | Status::Refused => {
                    f.t.close();
                    false
                }
                _ => true,
            }
        });
    }

    /// A moved socket's next datagram off the machine, read straight off
    /// the flow it came in on (or left there, `peek`), ahead of the global
    /// kernel's queue.
    fn flow_read(&self, m: Moved, buf: &mut [u8], peek: bool) -> Option<usize> {
        if self.kind != Kind::Udp {
            return None;
        }
        // The flows this holder knows first: a poll has just taken the
        // table up. Only with nothing on them is the table asked after.
        if let Some(n) = self.flow_take(buf, peek) {
            return Some(n);
        }
        self.sync_flows(m, None);
        self.flow_take(buf, peek)
    }

    /// The next datagram on one of this holder's flows, in turn.
    fn flow_take(&self, buf: &mut [u8], peek: bool) -> Option<usize> {
        let flows = self.flows.lock().unwrap();
        let k = flows.len();
        let at = self.flow_turn.fetch_add(1, Ordering::Relaxed);
        for f in (0..k).map(|i| &flows[(at + i) % k]) {
            let r = if peek { f.t.peek(buf) } else { f.t.recv(buf) };
            if let Ok(n) = r {
                *self.last_from.lock().unwrap() = Some(f.to);
                self.from_here.store(true, Ordering::Release);
                return Some(n);
            }
        }
        None
    }

    /// Whether one of a moved socket's flows has a datagram: the next one's
    /// length, or `None`. `gen`: the flow table's generation, if the caller
    /// has it.
    fn flow_ready(&self, m: Moved, gen: Option<u64>) -> Option<usize> {
        if self.kind != Kind::Udp {
            return None;
        }
        self.sync_flows(m, gen);
        self.flow_ready_here()
    }

    /// The next datagram's length on one of this holder's flows as it
    /// knows them, or `None`.
    fn flow_ready_here(&self) -> Option<usize> {
        self.flows.lock().unwrap().iter().find(|f| f.t.has_data()).map(|f| f.t.available())
    }

    /// Take what senders in other processes wrote: accept new streams, read
    /// each, and queue every whole datagram. And what the flows off this
    /// machine brought.
    fn udp_pump(&self) {
        self.flows_pump();
        let Some(r) = self.remote else { return };
        let mut u = self.udp_remote.lock().unwrap();
        let Some(l) = u.listener else { return };
        while (r.pending)(l) != 0 {
            let id = (r.accept)(l);
            if id < 0 {
                break;
            }
            u.inbound.push((id, Vec::new()));
        }
        let mut q = self.dgrams.lock().unwrap();
        let mut chunk = [0u8; 4096];
        let mut gone = Vec::new();
        for (id, buf) in u.inbound.iter_mut() {
            while (r.readable)(*id) != 0 {
                let n = (r.read)(*id, chunk.as_mut_ptr() as crate::PAddr, chunk.len() as u32);
                if n == 0 {
                    // The sender closed (its socket or its process went).
                    gone.push(*id);
                }
                if n <= 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n as usize]);
            }
            while buf.len() >= 6 {
                let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                if buf.len() < 6 + len {
                    break;
                }
                let from = u16::from_le_bytes([buf[4], buf[5]]);
                q.push_back((buf[6..6 + len].to_vec(), (0x7f00_0001, from)));
                buf.drain(..6 + len);
            }
        }
        for id in gone {
            (r.close)(id);
            u.inbound.retain(|(i, _)| *i != id);
        }
    }

    pub fn recv_dgram(&self, buf: &mut [u8]) -> SysResult {
        if let Some(v) = self.fwd(op::READ, 0, 0, buf) {
            return Socket::count(v);
        }
        self.udp_pump();
        match self.dgrams.lock().unwrap().pop_front() {
            Some((d, from)) => {
                let n = buf.len().min(d.len());
                buf[..n].copy_from_slice(&d[..n]);
                *self.last_from.lock().unwrap() = Some(from);
                Ok(n as u64)
            }
            None => Err(Errno::EAGAIN),
        }
    }
}

impl Socket {
    /// `recv` with `MSG_PEEK`: the bytes (or the next datagram) left queued
    /// for the next read. Wine's server peeks a byte to tell a socket that
    /// has data from one that was closed.
    pub fn peek(&self, buf: &mut [u8]) -> SysResult {
        if let Some(m) = self.moved() {
            if let Some(n) = self.flow_read(m, buf, true) {
                return Ok(n as u64);
            }
            self.from_here.store(false, Ordering::Release);
        }
        if let Some(v) = self.fwd(op::PEEK, 0, 0, buf) {
            return Socket::count(v);
        }
        if self.kind == Kind::Udp {
            self.udp_pump();
            return match self.dgrams.lock().unwrap().front() {
                Some((d, from)) => {
                    let n = buf.len().min(d.len());
                    buf[..n].copy_from_slice(&d[..n]);
                    *self.last_from.lock().unwrap() = Some(*from);
                    Ok(n as u64)
                }
                None => Err(Errno::EAGAIN),
            };
        }
        let t = self.transport.lock().unwrap();
        let Some(t) = t.as_ref() else {
            return Err(Errno::ENOTCONN);
        };
        match t.status() {
            Status::Refused if self.is_xnu() && self.refused_taken.load(Ordering::Acquire) => Ok(0),
            Status::Refused => Err(Errno::ECONNREFUSED),
            Status::Closed => match t.peek(buf) {
                Ok(n) => Ok(n as u64),
                Err(Errno::EAGAIN) => Ok(0),
                Err(e) => Err(e),
            },
            _ => t.peek(buf).map(|n| n as u64),
        }
    }
}

// -- sockets in the global kernel ----------------------------------------------

/// Internet sockets that live in the global kernel module (a page: a Worker
/// and a memory per process). A socket that has to be in two processes at
/// once -- Wine's wineserver makes every socket, binds it and polls it, while
/// the client sends, receives and sets options on the same one -- moves there
/// the first time it leaves its process unconnected (`Socket::move_out`), and
/// each process's descriptor forwards to it by id. A connected TCP socket
/// still travels as its connection (`Socket::carry`), and one that never
/// leaves stays where it is.
#[derive(Clone, Copy, Debug)]
pub struct InetRemote {
    /// A socket rebuilt from `Socket::export`'s bytes: its id, or a negated
    /// errno.
    pub adopt: fn(state: &[u8]) -> i32,
    /// One call on socket `id` (`op::*`), `buf` filled by those `op::fills`
    /// names: the result, or a negated errno.
    pub op: fn(id: i32, op: u32, a: u64, b: u64, buf: &mut [u8]) -> i64,
    /// `op::WRITE`, whose bytes are the caller's to send.
    pub write: fn(id: i32, data: &[u8]) -> i64,
    /// Another holder of the same socket (a descriptor on its way to another
    /// process): its id, or a negated errno.
    pub dup: fn(id: i32) -> i32,
    /// One holder gone; the socket goes with its last.
    pub close: fn(id: i32),
}

static INET_REMOTE: std::sync::OnceLock<InetRemote> = std::sync::OnceLock::new();

/// Let unconnected sockets leave their process (set once, by a host with a
/// global kernel).
pub fn share_inet(remote: InetRemote) {
    let _ = INET_REMOTE.set(remote);
}

/// A socket's place in the global kernel.
#[derive(Clone, Copy, Debug)]
struct Moved {
    id: i32,
    r: InetRemote,
}

/// The calls `InetRemote::op` carries, one per `Socket` method.
pub mod op {
    pub const BIND: u32 = 1;
    pub const LISTEN: u32 = 2;
    /// The connection's `carry` name into `buf`; its length.
    pub const ACCEPT: u32 = 3;
    pub const CONNECT: u32 = 4;
    pub const SHUTDOWN: u32 = 5;
    pub const STATUS: u32 = 6;
    pub const LOCAL: u32 = 7;
    pub const PEER: u32 = 8;
    pub const SET_PEER: u32 = 9;
    pub const LAST_FROM: u32 = 10;
    /// `buf` is the bytes to send.
    pub const WRITE: u32 = 11;
    /// `buf` is filled; the bytes read.
    pub const READ: u32 = 12;
    pub const PEEK: u32 = 13;
    pub const AVAILABLE: u32 = 14;
    pub const READABLE: u32 = 15;
    pub const WRITABLE: u32 = 16;
    pub const LISTENING: u32 = 17;
    pub const QUEUE: u32 = 18;
    /// A holder connected it out (`Socket::go_out`): `buf` is the
    /// connection's `carry` name. `EISCONN` if another holder did first.
    pub const GO_OUT: u32 = 19;
    /// That name into `buf`; its length. Every other call on such a socket
    /// is `EREMCHG`, which tells its holder to take the connection up.
    pub const WENT_OUT: u32 = 20;
    /// A holder opened a flow off the machine (`Socket::send_out`): `buf`
    /// is its name, `ADDR:PORT:TRANSPORT`, which replaces the one there.
    pub const FLOW: u32 = 21;
    /// The flow table's generation (`a` 0), its names, one a line, into
    /// `buf` (`a` 1: their length), or that length (`a` 2).
    pub const FLOWS: u32 = 22;

    /// Whether the call reads `buf` (copied from the caller first).
    pub fn takes(op: u32) -> bool {
        matches!(op, WRITE | GO_OUT | FLOW)
    }

    /// Whether the call fills `buf` (copied back to the caller).
    pub fn fills(op: u32) -> bool {
        matches!(op, ACCEPT | READ | PEEK | WENT_OUT | FLOWS)
    }
}

fn pack_addr(a: Option<(u32, u16)>) -> i64 {
    a.map_or(-1, |(ip, port)| (ip as i64) << 16 | port as i64)
}

fn unpack_addr(v: i64) -> Option<(u32, u16)> {
    (v >= 0).then(|| ((v >> 16) as u32, v as u16))
}

fn errno_of(v: i64) -> Errno {
    Errno((-v) as i32)
}

/// The little-endian writer and reader of `Socket::export`'s bytes.
#[derive(Default)]
struct StateOut(Vec<u8>);

impl StateOut {
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn addr(&mut self, a: Option<(u32, u16)>) {
        match a {
            Some((ip, port)) => {
                self.u32(1);
                self.u32(ip);
                self.u32(port as u32);
            }
            None => self.u32(0),
        }
    }
    fn id(&mut self, v: Option<i32>) {
        self.u32(v.map_or(u32::MAX, |v| v as u32));
    }
    fn bytes(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.0.extend_from_slice(b);
    }
}

struct StateIn<'a>(&'a [u8]);

impl StateIn<'_> {
    fn u32(&mut self) -> Option<u32> {
        let (h, t) = self.0.split_at_checked(4)?;
        self.0 = t;
        Some(u32::from_le_bytes(h.try_into().ok()?))
    }
    fn addr(&mut self) -> Option<Option<(u32, u16)>> {
        Some(match self.u32()? {
            0 => None,
            _ => Some((self.u32()?, self.u32()? as u16)),
        })
    }
    fn id(&mut self) -> Option<Option<i32>> {
        Some(match self.u32()? {
            u32::MAX => None,
            v => Some(v as i32),
        })
    }
    fn bytes(&mut self) -> Option<Vec<u8>> {
        let n = self.u32()? as usize;
        let (h, t) = self.0.split_at_checked(n)?;
        self.0 = t;
        Some(h.to_vec())
    }
}

impl Socket {
    /// The global kernel's socket this one forwards to, if it has moved.
    fn moved(&self) -> Option<Moved> {
        match self.moved.load(Ordering::Acquire) {
            id if id < 0 => None,
            id => Some(Moved { id, r: *INET_REMOTE.get()? }),
        }
    }

    /// One call on the moved socket, if this one has moved: its result.
    /// `None` too once the socket has come back to this process as a
    /// connection another holder made (`come_back`): the caller then goes
    /// on as for a socket that never left.
    fn fwd(&self, call: u32, a: u64, b: u64, buf: &mut [u8]) -> Option<i64> {
        let m = self.moved()?;
        let v = (m.r.op)(m.id, call, a, b, buf);
        if v == -(Errno::EREMCHG.0 as i64) {
            return match self.come_back(m) {
                Ok(()) => None,
                Err(e) => Some(-(e.0 as i64)),
            };
        }
        Some(v)
    }

    fn fwd_write(&self, data: &[u8]) -> Option<i64> {
        let m = self.moved()?;
        let v = (m.r.write)(m.id, data);
        if v == -(Errno::EREMCHG.0 as i64) {
            return match self.come_back(m) {
                Ok(()) => None,
                Err(e) => Some(-(e.0 as i64)),
            };
        }
        Some(v)
    }

    /// A moved TCP socket connecting out: the connection is this process's
    /// (a Wisp stream), made here; the global kernel keeps its name for the
    /// other holders, each of which takes it up at its next call, and this
    /// one stops forwarding.
    fn go_out(&self, addr: u32, port: u16) -> Result<(), Errno> {
        let Some(m) = self.moved() else { return self.connect(addr, port) };
        let host = self.host_for(addr);
        let t = self.net.tcp()?;
        t.connect(&host, port)?;
        let Some(tname) = t.name() else {
            t.close();
            return Err(Errno::ENETUNREACH);
        };
        let mut name = format!("inet:{addr}:{port}:0:0:{tname}").into_bytes();
        let v = (m.r.op)(m.id, op::GO_OUT, 0, 0, &mut name);
        if v < 0 {
            // Another holder got there first: its connection is this one's.
            t.close();
            self.come_back(m)?;
            return self.connect(addr, port);
        }
        *self.peer.lock().unwrap() = Some((addr, port));
        *self.transport.lock().unwrap() = Some(t);
        if self.moved.compare_exchange(m.id, -1, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            (m.r.close)(m.id);
        }
        Err(Errno::EINPROGRESS)
    }

    /// The connection another holder made out of this socket, held here
    /// now (`go_out`): this holder stops forwarding.
    fn come_back(&self, m: Moved) -> Result<(), Errno> {
        let mut name = [0u8; 160];
        let n = (m.r.op)(m.id, op::WENT_OUT, 0, 0, &mut name);
        if n < 0 {
            return Err(errno_of(n));
        }
        let name = std::str::from_utf8(&name[..n as usize]).map_err(|_| Errno::EINVAL)?;
        let t = Socket::carried_transport(name).and_then(|t| self.net.adopt(t)).ok_or(Errno::ECONNRESET)?;
        let mut p = name.strip_prefix("inet:").unwrap_or("").splitn(3, ':');
        let pa = p.next().and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
        let pp = p.next().and_then(|v| v.parse::<u16>().ok()).unwrap_or(0);
        let _guard = self.udp_remote.lock().unwrap();
        if self.moved.compare_exchange(m.id, -1, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            *self.peer.lock().unwrap() = Some((pa, pp));
            *self.transport.lock().unwrap() = Some(t);
            (m.r.close)(m.id);
        } else {
            // Another thread here took it up first.
            t.close();
        }
        Ok(())
    }

    fn unit(v: i64) -> Result<(), Errno> {
        if v < 0 { Err(errno_of(v)) } else { Ok(()) }
    }

    fn count(v: i64) -> SysResult {
        if v < 0 { Err(errno_of(v)) } else { Ok(v as u64) }
    }

    /// Everything this socket is, as bytes `import` rebuilds it from, taken
    /// out of it: its ids in the global kernel are the new socket's now.
    fn export(&self, u: UdpRemote) -> Vec<u8> {
        let mut o = StateOut::default();
        o.u32(match self.kind {
            Kind::Tcp => 0,
            Kind::Udp => 1,
        });
        o.addr(*self.local.lock().unwrap());
        o.addr(*self.peer.lock().unwrap());
        o.addr(*self.last_from.lock().unwrap());
        o.id(self.remote_listener.lock().unwrap().take());
        // A listener's waiting connections are the global kernel's already
        // (in a page nothing queues here).
        o.u32(self.backlog.lock().unwrap().take().is_some() as u32);
        o.id(u.listener);
        o.u32(u.inbound.len() as u32);
        for (id, buf) in &u.inbound {
            o.u32(*id as u32);
            o.bytes(buf);
        }
        o.u32(u.outbound.len() as u32);
        for (port, id) in &u.outbound {
            o.u32(*port as u32);
            o.u32(*id as u32);
        }
        let q = std::mem::take(&mut *self.dgrams.lock().unwrap());
        o.u32(q.len() as u32);
        for (d, from) in &q {
            o.bytes(d);
            o.addr(Some(*from));
        }
        o.0
    }

    /// The other half of `export`: the socket, here (the global kernel).
    pub fn import(
        state: &[u8],
        net: Arc<dyn NetStack>,
        resolver: Arc<Resolver>,
        ports: Arc<Ports>,
        remote: Option<crate::unix::Remote>,
    ) -> Option<Arc<Socket>> {
        let mut i = StateIn(state);
        let kind = match i.u32()? {
            0 => Kind::Tcp,
            _ => Kind::Udp,
        };
        let s = Socket::new(kind, net, resolver, ports, remote);
        *s.local.lock().unwrap() = i.addr()?;
        *s.peer.lock().unwrap() = i.addr()?;
        *s.last_from.lock().unwrap() = i.addr()?;
        *s.remote_listener.lock().unwrap() = i.id()?;
        if i.u32()? != 0 {
            *s.backlog.lock().unwrap() = Some(VecDeque::new());
        }
        {
            let mut u = s.udp_remote.lock().unwrap();
            u.listener = i.id()?;
            for _ in 0..i.u32()? {
                let id = i.u32()? as i32;
                u.inbound.push((id, i.bytes()?));
            }
            for _ in 0..i.u32()? {
                let port = i.u32()? as u16;
                u.outbound.insert(port, i.u32()? as i32);
            }
        }
        {
            let mut q = s.dgrams.lock().unwrap();
            for _ in 0..i.u32()? {
                let d = i.bytes()?;
                q.push_back((d, i.addr()??));
            }
        }
        let s = Arc::new(s);
        s.set_self();
        Some(s)
    }

    /// This socket as one another process can hold too: moved to the global
    /// kernel if it is not there yet, then held once more. The name it goes
    /// by (`inetg:KIND:ID`), or `None` where there is no global kernel to
    /// move to, or for a connected TCP socket (`carry`'s).
    pub fn move_out(&self) -> Option<String> {
        let r = *INET_REMOTE.get()?;
        let kind = match self.kind {
            Kind::Tcp => 0,
            Kind::Udp => 1,
        };
        // The UDP state's lock is the move's: two threads handing the socket
        // on at once move it once.
        let mut u = self.udp_remote.lock().unwrap();
        if self.moved().is_none() {
            if self.transport.lock().unwrap().is_some() {
                return None;
            }
            let state = self.export(std::mem::take(&mut *u));
            let id = (r.adopt)(&state);
            if id < 0 {
                return None;
            }
            self.moved.store(id, Ordering::Release);
            // Its flows off the machine stay this holder's, named to the
            // global kernel for the others (`sync_flows`).
            let flows = self.flows.lock().unwrap();
            for f in flows.iter() {
                if let Some(n) = f.t.name() {
                    let mut name = format!("{}:{}:{n}", f.to.0, f.to.1).into_bytes();
                    (r.op)(id, op::FLOW, 0, 0, &mut name);
                }
            }
            // Its own: named just now.
            self.flows_seen.store((r.op)(id, op::FLOWS, 0, 0, &mut []).max(0) as u64, Ordering::Release);
        }
        drop(u);
        let m = self.moved()?;
        let dup = (m.r.dup)(m.id);
        (dup >= 0).then(|| format!("inetg:{kind}:{dup}"))
    }

    /// A descriptor's socket from `move_out`'s name: the global kernel's,
    /// held by this process now.
    pub fn moved_proxy(
        name: &str,
        net: Arc<dyn NetStack>,
        resolver: Arc<Resolver>,
        ports: Arc<Ports>,
        remote: Option<crate::unix::Remote>,
    ) -> Option<Arc<Socket>> {
        let r = *INET_REMOTE.get()?;
        let (kind, id) = name.strip_prefix("inetg:")?.split_once(':')?;
        let kind = if kind == "1" { Kind::Udp } else { Kind::Tcp };
        let id = id.parse::<i32>().ok()?;
        let s = Socket::new(kind, net, resolver, ports, remote);
        let _ = r;
        s.moved.store(id, Ordering::Release);
        let s = Arc::new(s);
        s.set_self();
        Some(s)
    }

    /// `InetRemote::op`'s other end, run by the global kernel on its own
    /// socket. `buf` is the caller's bytes for `op::WRITE`, and what the
    /// `op::fills` calls fill.
    pub fn serve(self: &Arc<Self>, call: u32, a: u64, b: u64, buf: &mut [u8]) -> i64 {
        let unit = |r: Result<(), Errno>| r.map_or_else(|e| -(e.0 as i64), |_| 0);
        let count = |r: SysResult| r.map_or_else(|e| -(e.0 as i64), |n| n as i64);
        {
            let mut out = self.went_out.lock().unwrap();
            match (call, out.as_ref()) {
                (op::WENT_OUT, Some(name)) if name.len() <= buf.len() => {
                    buf[..name.len()].copy_from_slice(name.as_bytes());
                    return name.len() as i64;
                }
                (op::WENT_OUT, _) => return -(Errno::EINVAL.0 as i64),
                (op::GO_OUT, Some(_)) => return -(Errno::EISCONN.0 as i64),
                (op::GO_OUT, None) => {
                    if self.transport.lock().unwrap().is_some() || self.is_listening() {
                        return -(Errno::EISCONN.0 as i64);
                    }
                    *out = Some(String::from_utf8_lossy(buf).into_owned());
                    return 0;
                }
                (_, Some(_)) => return -(Errno::EREMCHG.0 as i64),
                _ => {}
            }
        }
        match call {
            op::BIND => unit(self.bind(a as u32, b as u16)),
            op::LISTEN => unit(self.listen()),
            op::ACCEPT => match self.accept() {
                Ok(s) => match s.carry() {
                    Some(name) if name.len() <= buf.len() => {
                        buf[..name.len()].copy_from_slice(name.as_bytes());
                        name.len() as i64
                    }
                    _ => -(Errno::ENOMEM.0 as i64),
                },
                Err(e) => -(e.0 as i64),
            },
            op::CONNECT => unit(self.connect(a as u32, b as u16)),
            op::SHUTDOWN => count(self.shutdown(a)),
            op::STATUS => match self.status() {
                Status::Connecting => 0,
                Status::Open => 1,
                Status::Closed => 2,
                Status::Refused => 3,
            },
            op::LOCAL => pack_addr(Some(self.local())),
            op::PEER => pack_addr(self.peer()),
            op::SET_PEER => {
                self.set_peer(a as u32, b as u16);
                0
            }
            op::LAST_FROM => pack_addr(self.last_from()),
            op::WRITE => count(self.write_at(0, buf)),
            op::READ => count(self.read_at(0, buf)),
            op::PEEK => count(self.peek(buf)),
            // A UDP socket's next datagram's length, its flow table's
            // generation above it (`available`).
            op::AVAILABLE if self.kind == Kind::Udp => {
                (self.available().unwrap_or(0) & DGRAM_LEN_MASK | self.flow_names.lock().unwrap().gen << DGRAM_LEN_BITS) as i64
            }
            op::AVAILABLE => self.available().unwrap_or(0) as i64,
            // A UDP socket's with its flow table's generation above the
            // first bit, so a holder takes the table up only when it changed
            // (`poll_readable`).
            op::READABLE if self.kind == Kind::Udp => self.poll_readable() as i64 | (self.flow_names.lock().unwrap().gen << 1) as i64,
            op::READABLE => self.poll_readable() as i64,
            op::WRITABLE => self.poll_writable() as i64,
            op::LISTENING => self.is_listening() as i64,
            op::QUEUE => self.wait_queue() as i64,
            op::FLOW => {
                self.flow_names.lock().unwrap().set(&String::from_utf8_lossy(buf));
                0
            }
            op::FLOWS => {
                let names = self.flow_names.lock().unwrap();
                if a == 0 {
                    return names.gen as i64;
                }
                let list = names.text();
                if a == 2 {
                    return list.len() as i64;
                }
                if list.len() > buf.len() {
                    return -(Errno::ENOMEM.0 as i64);
                }
                buf[..list.len()].copy_from_slice(list.as_bytes());
                list.len() as i64
            }
            _ => -(Errno::ENOSYS.0 as i64),
        }
    }
}

impl FileHandle for Socket {
    fn as_inet_socket(self: Arc<Self>) -> Option<Arc<Socket>> {
        Some(self)
    }

    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> SysResult {
        if let Some(m) = self.moved() {
            if let Some(n) = self.flow_read(m, buf, false) {
                return Ok(n as u64);
            }
            self.from_here.store(false, Ordering::Release);
        }
        if let Some(v) = self.fwd(op::READ, 0, 0, buf) {
            return Socket::count(v);
        }
        if self.kind == Kind::Udp {
            return self.recv_dgram(buf);
        }
        let t = self.transport.lock().unwrap();
        let Some(t) = t.as_ref() else {
            return Err(Errno::ENOTCONN);
        };
        match t.status() {
            // so_error, taken once; then the end of the stream.
            Status::Refused if self.is_xnu() && !self.take_refused() => Ok(0),
            Status::Refused => Err(Errno::ECONNREFUSED),
            // Closed and drained is end of file, not "try again": a transport
            // reports "nothing right now" as EAGAIN and cannot tell an empty
            // connection from a finished one, so `status` decides. Without
            // this a reader spins on EAGAIN forever. Counterpart of `send`
            // answering Closed with EPIPE.
            Status::Closed => match t.recv(buf) {
                Ok(n) => Ok(n as u64),
                Err(Errno::EAGAIN) => Ok(0),
                Err(e) => Err(e),
            },
            _ => {
                let r = t.recv(buf);
                // The end of a connection the host's TCP carries shows
                // only here.
                if t.tcp_end().is_none() && matches!(r, Ok(0) if !buf.is_empty()) | matches!(r, Err(e) if e != Errno::EAGAIN) {
                    self.host_end_seen.store(true, Ordering::Release);
                }
                r.map(|n| n as u64)
            }
        }
    }

    fn write_at(&self, _offset: u64, buf: &[u8]) -> SysResult {
        // A moved one's too: `send_dgram` forwards, and sends off the
        // machine itself.
        if self.kind == Kind::Udp {
            return self.send_dgram(buf);
        }
        if let Some(v) = self.fwd_write(buf) {
            return Socket::count(v);
        }
        let t = self.transport.lock().unwrap();
        let Some(t) = t.as_ref() else {
            return Err(Errno::ENOTCONN);
        };
        match t.status() {
            // After tcp_drop the socket can send no more (sosendcheck's EPIPE).
            Status::Refused if self.is_xnu() => Err(Errno::EPIPE),
            Status::Refused => Err(Errno::ECONNREFUSED),
            Status::Closed => t.send_closed(buf).map(|n| n as u64),
            // Still connecting: the bytes cannot go yet, and a caller that
            // waited for the connection would not be here.
            Status::Connecting => Err(Errno::EAGAIN),
            Status::Open => t.send(buf).map(|n| n as u64),
        }
    }

    fn metadata(&self) -> Result<Metadata, Errno> {
        Ok(Metadata {
            file_type: FileType::Socket,
            size: 0,
            mode: 0o600,
            ino: 3,
            mtime: 0,
            nlink: 1,
            rdev: 0,
            dev: 0,
            times: Default::default(),
        })
    }

    fn is_stream(&self) -> bool {
        true
    }

    /// Bytes available to read, for `FIONREAD`. For a datagram socket this
    /// must be exact -- the length of the next datagram, which a caller uses
    /// to size its buffer.
    fn available(&self) -> Option<u64> {
        if let (Kind::Udp, Some(m)) = (self.kind, self.moved()) {
            // This holder's flows, then the global kernel's queue, whose
            // answer carries the flow table's generation (as READABLE's):
            // the table is asked after only when that moved.
            if let Some(n) = self.flow_ready_here() {
                return Some(n as u64);
            }
            if let Some(v) = self.fwd(op::AVAILABLE, 0, 0, &mut []) {
                if v <= 0 {
                    return Some(0);
                }
                let len = v as u64 & DGRAM_LEN_MASK;
                if len > 0 {
                    return Some(len);
                }
                return Some(self.flow_ready(m, Some(v as u64 >> DGRAM_LEN_BITS)).unwrap_or(0) as u64);
            }
        }
        if let Some(v) = self.fwd(op::AVAILABLE, 0, 0, &mut []) {
            return Some(v.max(0) as u64);
        }
        if self.kind == Kind::Udp {
            self.udp_pump();
            return Some(
                self.dgrams
                    .lock()
                    .unwrap()
                    .front()
                    .map_or(0, |d| d.0.len() as u64),
            );
        }
        Some(
            self.transport
                .lock()
                .unwrap()
                .as_ref()
                .map_or(0, |t| t.available() as u64),
        )
    }

    fn poll_readable(&self) -> bool {
        if let Some(v) = self.fwd(op::READABLE, 0, 0, &mut []) {
            if v & 1 != 0 || v < 0 || self.kind != Kind::Udp {
                return v != 0;
            }
            // Its flows off the machine, this holder's own, the table's
            // generation in the answer: no more calls to the global kernel
            // unless it changed.
            return self.moved().and_then(|m| self.flow_ready(m, Some((v as u64) >> 1))).is_some();
        }
        if self.kind == Kind::Udp {
            self.udp_pump();
            return !self.dgrams.lock().unwrap().is_empty();
        }
        // A listener is readable when a connection waits.
        if let (Some(id), Some(r)) = (*self.remote_listener.lock().unwrap(), self.remote) {
            return (r.pending)(id) != 0;
        }
        if let Some(q) = &*self.backlog.lock().unwrap() {
            return !q.is_empty();
        }
        match &*self.transport.lock().unwrap() {
            // A connection that has failed or finished is readable: the
            // answer is an error or an end, and either way it is ready.
            Some(t) => t.has_data() || matches!(t.status(), Status::Closed | Status::Refused),
            None => true,
        }
    }

    /// `tcp_sendspace` and `tcp_recvspace` or `udp_sendspace` and
    /// `udp_recvspace`. How much of a connection's send queue the host still
    /// holds is not visible here, so it counts as empty until the transport
    /// refuses more.
    fn so_state(&self) -> Option<crate::vfs::SoState> {
        const TCP_HIWAT: (u64, u64) = (1448 * 384, 1448 * 256);
        const UDP_HIWAT: (u64, u64) = (786896, 9216);
        const ECONNREFUSED: i32 = 61;
        if self.kind == Kind::Udp {
            let rcv = self.available().unwrap_or(0);
            let connects = self.connects.load(Ordering::Acquire);
            let conn = crate::vfs::SoConn { connected: connects != 0, connects, evconninfo: true, ..Default::default() };
            // The datagrams' addresses are not counted with their bytes.
            return Some(crate::vfs::SoState { qlen: None, rcv, cantrcv: false, cantsend: false, error: 0, can_write: true, snd_used: 0, hiwat: UDP_HIWAT, snd_lowat: 2048, unix_stream: false, ctl: 0, records: None, exact: false, peer_space: None, snd_mbmax: None, unp_cc: 0, live_hiwat: false, conn, oobmark: 0, rcvatmark: false, oob_unmodelled: None });
        }
        let conn = crate::vfs::SoConn { evconninfo: true, ..Default::default() };
        let mut st = crate::vfs::SoState { qlen: None, rcv: 0, cantrcv: false, cantsend: false, error: 0, can_write: false, snd_used: 0, hiwat: TCP_HIWAT, snd_lowat: 2048, unix_stream: false, ctl: 0, records: None, exact: true, peer_space: None, snd_mbmax: None, unp_cc: 0, live_hiwat: false, conn, oobmark: 0, rcvatmark: false, oob_unmodelled: None };
        if let (Some(id), Some(r)) = (*self.remote_listener.lock().unwrap(), self.remote) {
            st.qlen = Some(((r.pending)(id) != 0).into());
            return Some(st);
        }
        if let Some(q) = &*self.backlog.lock().unwrap() {
            st.qlen = Some(q.len() as u64);
            return Some(st);
        }
        // A connect the host failed: tcp_drop's tcp_close, its error taken
        // by the connect that waited for it.
        match self.connect_failed.load(Ordering::Acquire) {
            _ if self.transport.lock().unwrap().is_some() => {}
            0 => {}
            how => {
                st.cantrcv = true;
                st.cantsend = true;
                st.conn.disconnected = true;
                st.conn.disconnects = 1;
                st.conn.resets = u32::from(how == CONNECT_RESET);
                st.conn.timeouts = u32::from(how == CONNECT_TIMED_OUT);
                return Some(st);
            }
        }
        if let Some(t) = self.transport.lock().unwrap().as_ref() {
            match t.status() {
                Status::Connecting => {}
                Status::Open => {
                    st.can_write = true;
                    st.rcv = t.available() as u64;
                    st.cantsend = t.send_over(false);
                }
                Status::Closed => {
                    st.can_write = true;
                    st.rcv = t.available() as u64;
                    st.cantrcv = true;
                    st.cantsend = t.send_over(true);
                }
                Status::Refused => {
                    st.cantrcv = true;
                    st.cantsend = true;
                    if !(self.is_xnu() && self.refused_taken.load(Ordering::Acquire)) {
                        st.error = ECONNREFUSED;
                    }
                }
            }
            // The connection's events (soisconnected, socantrcvmore,
            // soisdisconnected, a reset), from where this end's TCP is.
            let status = t.status();
            let opened = matches!(status, Status::Open | Status::Closed);
            if let Some((mark, at)) = t.oob_state() {
                st.oobmark = mark;
                st.rcvatmark = at;
            }
            match t.tcp_end() {
                Some(e) => {
                    st.conn.connects = u32::from(opened);
                    st.conn.connected = e.connected;
                    st.conn.disconnected = e.disconnected();
                    st.conn.disconnects = e.disconnects;
                    st.conn.resets = e.resets;
                    st.conn.timeouts = e.timeouts;
                    st.conn.keepalives = e.keepalives;
                    st.cantrcv = e.cantrcv || e.rd_shut;
                    st.cantsend = e.cantsend;
                    st.error = e.error.map_or(0, |x| crate::darwin::errno::to_darwin(x.0));
                }
                None => {
                    st.oob_unmodelled = Some("urgent data on a TCP connection the host carries (its so_oobmark and SS_RCVATMARK)");
                    st.conn.connects = u32::from(opened);
                    st.conn.connected = opened;
                    if status == Status::Refused {
                        // tcp_drop(ECONNREFUSED) after the SYN's reset.
                        st.conn.connected = false;
                        st.conn.disconnected = true;
                        st.conn.disconnects = 1;
                        st.conn.resets = 1;
                    } else if status == Status::Closed || self.host_end_seen.load(Ordering::Acquire) {
                        st.conn.unmodelled = Some("the end of a TCP connection the host carries (whether a FIN, a reset or a timeout ended it, and so SO_FILT_HINT_CONNRESET, TIMEOUT and DISCONNECTED)");
                    }
                }
            }
        }
        Some(st)
    }

    /// A Darwin socket's options, kept with it.
    fn xnu_sockopts(&self) -> Option<crate::darwin::sockopt::SockOpts> {
        if self.is_xnu() {
            *self.xnu_opts.lock().unwrap()
        } else {
            None
        }
    }

    fn set_xnu_sockopts(&self, o: crate::darwin::sockopt::SockOpts) -> bool {
        if !self.is_xnu() {
            return false;
        }
        *self.xnu_opts.lock().unwrap() = Some(o);
        true
    }

    /// A TCP socket on this machine's connections (or none yet) makes
    /// XNU's wakeups; a datagram socket, one whose TCP is the host's, or
    /// one the global kernel holds does not here.
    fn so_owner(&self) -> Option<(Arc<crate::vfs::SoOwner>, bool)> {
        let local = self.kind == Kind::Tcp && self.moved().is_none() && self.remote_listener.lock().unwrap().is_none() && (self.owner_linked.load(Ordering::Acquire) || self.transport.lock().unwrap().is_none());
        Some((Arc::clone(&self.owner), local))
    }

    /// Changes as the bytes waiting or the connection do.
    fn wakes(&self) -> Option<u64> {
        let st = self.so_state()?;
        Some(((st.rcv << 8) | (u64::from(st.cantrcv) << 2) | (u64::from(st.can_write) << 1) | st.qlen.unwrap_or(0) << 3 | u64::from(st.error != 0)) ^ (st.oobmark << 40) ^ (u64::from(st.rcvatmark) << 63))
    }

    /// In a page, a listener's and a loopback connection's ends are in the
    /// global kernel, and so is the queue their changes are announced on: a
    /// thread parked in `accept`, `poll` or `read` on one had none, and slept
    /// through the connection or the bytes (tests/x86-programs/tcp-loopback,
    /// a forked child connecting to its parent).
    fn wait_queue(&self) -> u32 {
        if let Some(v) = self.fwd(op::QUEUE, 0, 0, &mut []) {
            return v.max(0) as u32;
        }
        if let (Some(id), Some(r)) = (*self.remote_listener.lock().unwrap(), self.remote) {
            return (r.queue)(id);
        }
        self.transport.lock().unwrap().as_ref().map_or(0, |t| t.wait_queue())
    }

    /// Writable, which for a socket mid-`connect` means the connect has
    /// finished either way. This is how a non-blocking connect reports itself:
    /// the caller waits for writable, then asks `SO_ERROR`. The trait's
    /// default `true` would signal "finished" before it was.
    fn poll_writable(&self) -> bool {
        if let Some(v) = self.fwd(op::WRITABLE, 0, 0, &mut []) {
            return v != 0;
        }
        if self.kind == Kind::Udp {
            return true;
        }
        match &*self.transport.lock().unwrap() {
            Some(t) => !matches!(t.status(), Status::Connecting),
            // No `connect` yet. A fresh TCP socket is writable on Linux too,
            // and a caller polling one has not asked about a connection.
            None => true,
        }
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        // Its flows off the machine: this holder's hold on each.
        for f in std::mem::take(&mut *self.flows.lock().unwrap()) {
            f.t.close();
        }
        // A moved socket's state is the global kernel's: this was one hold.
        if let Some(m) = self.moved() {
            (m.r.close)(m.id);
            return;
        }
        if let Some(t) = self.transport.lock().unwrap().take() {
            t.close();
        }
        if let (Some(id), Some(r)) = (self.remote_listener.lock().unwrap().take(), self.remote) {
            (r.close)(id);
        }
        // A UDP socket's streams in the global kernel close (its name goes
        // with the listener).
        if let Some(r) = self.remote {
            let u = std::mem::take(&mut *self.udp_remote.lock().unwrap());
            for id in u.listener.into_iter().chain(u.inbound.into_iter().map(|(i, _)| i)).chain(u.outbound.into_values()) {
                (r.close)(id);
            }
        }
        // A UDP socket gives its port back.
        if self.kind == Kind::Udp {
            if let Some((_, port)) = *self.local.lock().unwrap() {
                let mut udp = self.ports.udp.lock().unwrap();
                if udp.get(&port).is_some_and(|w| w.strong_count() == 0) {
                    udp.remove(&port);
                }
            }
        }
        // A listener gives its port back, and the connections nobody
        // accepted see their peer gone.
        if let Some(q) = self.backlog.lock().unwrap().take() {
            let port = self.local.lock().unwrap().map_or(0, |l| l.1);
            let mut listeners = self.ports.listeners.lock().unwrap();
            if listeners.get(&port).is_some_and(|w| w.strong_count() == 0) {
                listeners.remove(&port);
            }
            // soclose of a listener: soabort of each connection queued.
            for (t, _) in q {
                t.abort();
            }
        }
    }
}

// -- sockaddr ---------------------------------------------------------------

/// Read a `sockaddr_in`, returning the address and port in host order.
pub fn parse_sockaddr(bytes: &[u8]) -> Result<(u32, u16), Errno> {
    if bytes.len() < 8 {
        return Err(Errno::EINVAL);
    }
    let family = u16::from_le_bytes([bytes[0], bytes[1]]);
    if family != 2 {
        return Err(Errno::EAFNOSUPPORT);
    }
    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
    let addr = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    Ok((addr, port))
}

/// Write a `sockaddr_in`.
pub fn build_sockaddr(addr: u32, port: u16) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..2].copy_from_slice(&2u16.to_le_bytes());
    out[2..4].copy_from_slice(&port.to_be_bytes());
    out[4..8].copy_from_slice(&addr.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q
    }

    #[test]
    fn an_a_query_gets_an_address_back() {
        let r = Resolver::new();
        let a = answer_dns(&query("deb.debian.org", 1), &r).unwrap();
        assert_eq!(&a[0..2], &[0x12, 0x34], "the id is echoed");
        assert_eq!(u16::from_be_bytes([a[6], a[7]]), 1, "one answer");
        let addr = u32::from_be_bytes(a[a.len() - 4..].try_into().unwrap());
        assert_eq!(r.name_for(addr).as_deref(), Some("deb.debian.org"));
    }

    #[test]
    fn the_same_name_keeps_the_same_address() {
        let r = Resolver::new();
        let first = r.address_for("example.com");
        assert_eq!(r.address_for("example.com"), first);
        assert_eq!(r.address_for("EXAMPLE.COM."), first, "and is case-folded");
        assert_ne!(r.address_for("other.com"), first);
    }

    #[test]
    fn an_aaaa_query_is_answered_with_nothing_rather_than_an_error() {
        let r = Resolver::new();
        let a = answer_dns(&query("deb.debian.org", 28), &r).unwrap();
        assert_eq!(u16::from_be_bytes([a[6], a[7]]), 0, "no answers");
        assert_eq!(a[3] & 0x0f, 0, "but not an error, or the name is given up on");
    }

    #[test]
    fn a_truncated_query_is_not_answered() {
        let r = Resolver::new();
        assert!(answer_dns(&[0x12, 0x34], &r).is_none());
        let mut q = query("example.com", 1);
        q.truncate(15);
        assert!(answer_dns(&q, &r).is_none());
    }

    /// No network: loopback between guests only.
    #[derive(Debug)]
    struct NoNet;
    impl NetStack for NoNet {
        fn tcp(&self) -> Result<Arc<dyn Transport>, Errno> {
            Err(Errno::ENETUNREACH)
        }
    }

    #[test]
    fn a_tcp_bind_to_port_zero_gets_its_port_at_once() {
        let (net, res, ports) = (Arc::new(NoNet) as Arc<dyn NetStack>, Arc::new(Resolver::new()), Arc::new(Ports::new()));
        let l = Arc::new(Socket::new(Kind::Tcp, Arc::clone(&net), Arc::clone(&res), Arc::clone(&ports), None));
        l.set_self();
        l.bind(0x7f00_0001, 0).unwrap();
        let port = l.local().1;
        assert_ne!(port, 0, "getsockname after bind has the port");
        l.listen().unwrap();
        assert_eq!(l.local().1, port, "listen keeps it");
        let c = Socket::new(Kind::Tcp, net, res, ports, None);
        c.connect(0x7f00_0001, port).unwrap();
        let s = l.accept().expect("a connection to it arrives");
        assert_eq!(c.write_at(0, b"hi").unwrap(), 2);
        let mut b = [0u8; 8];
        assert_eq!(s.peek(&mut b[..1]).unwrap(), 1, "a peek sees the first byte");
        assert_eq!(s.read_at(0, &mut b).unwrap(), 2, "and leaves it for the read");
        assert_eq!(&b[..2], b"hi");
        c.shutdown(1).unwrap();
        assert_eq!(s.status(), Status::Closed, "and its shutdown reaches the far end");
    }

    #[test]
    fn sockaddr_round_trips() {
        let bytes = build_sockaddr(0xf0000001, 80);
        assert_eq!(parse_sockaddr(&bytes), Ok((0xf0000001, 80)));
    }

    #[test]
    fn only_ipv4_is_understood() {
        let mut bytes = build_sockaddr(1, 1);
        bytes[0] = 10; // AF_INET6
        assert_eq!(parse_sockaddr(&bytes), Err(Errno::EAFNOSUPPORT));
    }
}
