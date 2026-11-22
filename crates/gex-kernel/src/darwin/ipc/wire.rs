//! The system's IPC table as bytes: what a process of the page takes from
//! the global kernel for a kernel call, and gives back after it
//! ([`super::IpcShared`]). Natively the table never leaves the host
//! process, and none of this is used.
//!
//! Every field goes as it is, little-endian; a map as its length and its
//! entries, an option as a byte (0 none) and the value. A table that does
//! not decode is a broken system, which goes no further ([`Bad`]).

use super::msg::{Desc, Kmsg, Queues, RcvWait, Received, Sender};
use super::right::Carried;
use super::{Kobject, Object, ObjId, Port, Pset, Receiver, ReplySemantics, Request, ServiceLabel};
use std::collections::{BTreeMap, HashMap, VecDeque};

/// Bytes that are not a table's encoding: where, and what was wanted.
#[derive(Debug, PartialEq, Eq)]
pub struct Bad(pub usize, pub &'static str);

/// An encoding under way.
#[derive(Default)]
pub struct Put(pub Vec<u8>);

impl Put {
    pub fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    pub fn bool(&mut self, v: bool) {
        self.0.push(u8::from(v));
    }
    pub fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn i32(&mut self, v: i32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn len(&mut self, n: usize) {
        self.u64(n as u64);
    }
    pub fn bytes(&mut self, b: &[u8]) {
        self.len(b.len());
        self.0.extend_from_slice(b);
    }
    pub fn opt<T>(&mut self, v: Option<T>, f: impl FnOnce(&mut Put, T)) {
        match v {
            None => self.u8(0),
            Some(x) => {
                self.u8(1);
                f(self, x);
            }
        }
    }
}

/// A decoding under way.
pub struct Get<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Get<'a> {
    pub fn new(b: &'a [u8]) -> Get<'a> {
        Get { b, at: 0 }
    }
    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], Bad> {
        let end = self.at.checked_add(n).filter(|&e| e <= self.b.len()).ok_or(Bad(self.at, what))?;
        let s = &self.b[self.at..end];
        self.at = end;
        Ok(s)
    }
    pub fn u8(&mut self) -> Result<u8, Bad> {
        Ok(self.take(1, "a byte")?[0])
    }
    pub fn bool(&mut self) -> Result<bool, Bad> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Bad(self.at - 1, "a truth value")),
        }
    }
    pub fn u32(&mut self) -> Result<u32, Bad> {
        Ok(u32::from_le_bytes(self.take(4, "a 32-bit word")?.try_into().unwrap()))
    }
    pub fn i32(&mut self) -> Result<i32, Bad> {
        Ok(self.u32()? as i32)
    }
    pub fn u64(&mut self) -> Result<u64, Bad> {
        Ok(u64::from_le_bytes(self.take(8, "a 64-bit word")?.try_into().unwrap()))
    }
    pub fn len(&mut self) -> Result<usize, Bad> {
        let at = self.at;
        let n = self.u64()?;
        // No count larger than the bytes left could hold one byte each.
        usize::try_from(n).ok().filter(|&n| n <= self.b.len() - self.at).ok_or(Bad(at, "a count"))
    }
    pub fn bytes(&mut self) -> Result<Vec<u8>, Bad> {
        let n = self.len()?;
        Ok(self.take(n, "bytes")?.to_vec())
    }
    pub fn opt<T>(&mut self, f: impl FnOnce(&mut Get<'a>) -> Result<T, Bad>) -> Result<Option<T>, Bad> {
        match self.u8()? {
            0 => Ok(None),
            1 => f(self).map(Some),
            _ => Err(Bad(self.at - 1, "an option")),
        }
    }
    /// Whether every byte has been read.
    pub fn done(&self) -> bool {
        self.at == self.b.len()
    }
}

fn put_kobject(p: &mut Put, k: &Kobject) {
    use Kobject as K;
    match k {
        K::Task => p.u8(0),
        K::TaskRead => p.u8(1),
        K::TaskInspect => p.u8(2),
        K::TaskName => p.u8(3),
        K::Thread(t) => {
            p.u8(4);
            p.i32(*t);
        }
        K::ThreadRead(t) => {
            p.u8(5);
            p.i32(*t);
        }
        K::ThreadInspect(t) => {
            p.u8(6);
            p.i32(*t);
        }
        K::Host => p.u8(7),
        K::HostPriv => p.u8(8),
        K::Clock(c) => {
            p.u8(9);
            p.u8(*c);
        }
        K::Semaphore => p.u8(10),
        K::Timer => p.u8(11),
        K::Voucher(v) => {
            p.u8(12);
            p.u64(*v);
        }
        K::TaskResume => p.u8(13),
        K::UxHandler => p.u8(14),
        K::IoMain => p.u8(15),
        K::IoEntry(i) => {
            p.u8(16);
            p.u32(*i);
        }
        K::FilePort(i) => {
            p.u8(17);
            p.u32(*i);
        }
        K::IoIterator(i) => {
            p.u8(18);
            p.u32(*i);
        }
        K::IoNotification(i) => {
            p.u8(19);
            p.u32(*i);
        }
        K::IoConnect(i) => {
            p.u8(20);
            p.u32(*i);
        }
        K::IoIdent(i) => {
            p.u8(21);
            p.u32(*i);
        }
        K::RpcReply(t) => {
            p.u8(22);
            p.i32(*t);
        }
        K::WorkInterval(i) => {
            p.u8(23);
            p.u64(*i);
        }
        K::Eventlink(i, end) => {
            p.u8(24);
            p.u64(*i);
            p.u8(*end);
        }
        K::NamedEntry(i) => {
            p.u8(25);
            p.u64(*i);
        }
        K::KcdataObject(i) => {
            p.u8(26);
            p.u64(*i);
        }
        K::TaskIdToken(i) => {
            p.u8(27);
            p.u64(*i);
        }
        K::SubstOnce(o) => {
            p.u8(28);
            p.u64(*o);
        }
    }
}

fn get_kobject(g: &mut Get<'_>) -> Result<Kobject, Bad> {
    use Kobject as K;
    let at = g.at;
    Ok(match g.u8()? {
        0 => K::Task,
        1 => K::TaskRead,
        2 => K::TaskInspect,
        3 => K::TaskName,
        4 => K::Thread(g.i32()?),
        5 => K::ThreadRead(g.i32()?),
        6 => K::ThreadInspect(g.i32()?),
        7 => K::Host,
        8 => K::HostPriv,
        9 => K::Clock(g.u8()?),
        10 => K::Semaphore,
        11 => K::Timer,
        12 => K::Voucher(g.u64()?),
        13 => K::TaskResume,
        14 => K::UxHandler,
        15 => K::IoMain,
        16 => K::IoEntry(g.u32()?),
        17 => K::FilePort(g.u32()?),
        18 => K::IoIterator(g.u32()?),
        19 => K::IoNotification(g.u32()?),
        20 => K::IoConnect(g.u32()?),
        21 => K::IoIdent(g.u32()?),
        22 => K::RpcReply(g.i32()?),
        23 => K::WorkInterval(g.u64()?),
        24 => K::Eventlink(g.u64()?, g.u8()?),
        25 => K::NamedEntry(g.u64()?),
        26 => K::KcdataObject(g.u64()?),
        27 => K::TaskIdToken(g.u64()?),
        28 => K::SubstOnce(g.u64()?),
        _ => return Err(Bad(at, "a kernel object's kind")),
    })
}

fn put_receiver(p: &mut Put, r: Receiver) {
    match r {
        Receiver::Space(n) => {
            p.u8(0);
            p.u32(n);
        }
        Receiver::Kernel => p.u8(1),
        Receiver::Transit => p.u8(2),
        Receiver::None => p.u8(3),
    }
}

fn get_receiver(g: &mut Get<'_>) -> Result<Receiver, Bad> {
    let at = g.at;
    Ok(match g.u8()? {
        0 => Receiver::Space(g.u32()?),
        1 => Receiver::Kernel,
        2 => Receiver::Transit,
        3 => Receiver::None,
        _ => return Err(Bad(at, "a receive right's place")),
    })
}

fn reply_semantics_of(g: &mut Get<'_>) -> Result<ReplySemantics, Bad> {
    use ReplySemantics as R;
    let at = g.at;
    Ok(match g.u8()? {
        0 => R::None,
        1 => R::ReplyPort,
        2 => R::Enforce,
        3 => R::Provisional,
        4 => R::EnforceRigid,
        5 => R::IdProtOptOut,
        _ => return Err(Bad(at, "reply semantics")),
    })
}

fn reply_semantics_byte(r: ReplySemantics) -> u8 {
    use ReplySemantics as R;
    match r {
        R::None => 0,
        R::ReplyPort => 1,
        R::Enforce => 2,
        R::Provisional => 3,
        R::EnforceRigid => 4,
        R::IdProtOptOut => 5,
    }
}

fn put_ids(p: &mut Put, ids: impl ExactSizeIterator<Item = ObjId>) {
    p.len(ids.len());
    for i in ids {
        p.u64(i);
    }
}

fn get_ids<C: FromIterator<ObjId>>(g: &mut Get<'_>) -> Result<C, Bad> {
    let n = g.len()?;
    (0..n).map(|_| g.u64()).collect()
}

pub fn put_carried(p: &mut Put, c: Option<Carried>) {
    match c {
        None => p.u8(0),
        Some(Carried::Port(o)) => {
            p.u8(1);
            p.u64(o);
        }
        Some(Carried::Dead) => p.u8(2),
    }
}

pub fn get_carried(g: &mut Get<'_>) -> Result<Option<Carried>, Bad> {
    let at = g.at;
    Ok(match g.u8()? {
        0 => None,
        1 => Some(Carried::Port(g.u64()?)),
        2 => Some(Carried::Dead),
        _ => return Err(Bad(at, "a carried right")),
    })
}

fn put_port(p: &mut Put, o: &Port) {
    p.bool(o.active);
    put_receiver(p, o.receiver);
    p.u64(o.owner);
    p.opt(o.kobject.as_ref(), put_kobject);
    for w in [o.mscount, o.srights, o.sorights, o.seqno, o.qlimit] {
        p.u32(w);
    }
    p.u64(o.context);
    for b in [o.guarded, o.strict_guard, o.immovable_receive, o.immovable_send, o.pinned, o.specialreply] {
        p.bool(b);
    }
    p.u8(reply_semantics_byte(o.reply_semantics));
    p.bool(o.tempowner);
    p.bool(o.impdonation);
    p.u32(o.impcount);
    p.bool(o.spimportant);
    p.opt(o.imp_task, Put::u64);
    p.opt(o.watchport, Put::u64);
    p.opt(o.destination, Put::u64);
    for b in [o.no_grant, o.service_port, o.bootstrap_port, o.connection_port] {
        p.bool(b);
    }
    p.opt(o.splabel.as_ref(), |p, l: &ServiceLabel| {
        p.bytes(&l.name);
        p.u8(l.domain);
        p.u32(l.flags);
        p.u32(l.launchd_name);
        p.u64(l.launchd_context);
    });
    p.bool(o.filter_msg);
    p.bool(o.sprequests);
    p.opt(o.nsrequest, Put::u64);
    p.bool(o.nsrequest_kobject);
    p.opt(o.subst, Put::u64);
    p.u32(o.knotes);
    p.opt(o.pdrequest, Put::u64);
    p.opt(o.requests.as_ref(), |p, rs: &Vec<Request>| {
        p.len(rs.len());
        for r in rs {
            p.u32(r.name);
            p.opt(r.notify, Put::u64);
            p.bool(r.spreq);
            p.bool(r.sparm);
            p.u32(r.next);
        }
    });
    put_ids(p, o.psets.iter().copied());
    p.len(o.messages.len());
    for m in &o.messages {
        put_kmsg(p, m);
    }
    p.u32(o.msgcount);
    p.bool(o.fullwaiters);
    p.u64(o.reply_context);
    p.u32(o.timestamp);
    p.u32(o.refs);
}

fn get_port(g: &mut Get<'_>) -> Result<Port, Bad> {
    let active = g.bool()?;
    let mut o = Port::new(get_receiver(g)?);
    o.active = active;
    o.owner = g.u64()?;
    o.kobject = g.opt(get_kobject)?;
    o.mscount = g.u32()?;
    o.srights = g.u32()?;
    o.sorights = g.u32()?;
    o.seqno = g.u32()?;
    o.qlimit = g.u32()?;
    o.context = g.u64()?;
    o.guarded = g.bool()?;
    o.strict_guard = g.bool()?;
    o.immovable_receive = g.bool()?;
    o.immovable_send = g.bool()?;
    o.pinned = g.bool()?;
    o.specialreply = g.bool()?;
    o.reply_semantics = reply_semantics_of(g)?;
    o.tempowner = g.bool()?;
    o.impdonation = g.bool()?;
    o.impcount = g.u32()?;
    o.spimportant = g.bool()?;
    o.imp_task = g.opt(Get::u64)?;
    o.watchport = g.opt(Get::u64)?;
    o.destination = g.opt(Get::u64)?;
    o.no_grant = g.bool()?;
    o.service_port = g.bool()?;
    o.bootstrap_port = g.bool()?;
    o.connection_port = g.bool()?;
    o.splabel = g.opt(|g| Ok(ServiceLabel { name: g.bytes()?, domain: g.u8()?, flags: g.u32()?, launchd_name: g.u32()?, launchd_context: g.u64()? }))?;
    o.filter_msg = g.bool()?;
    o.sprequests = g.bool()?;
    o.nsrequest = g.opt(Get::u64)?;
    o.nsrequest_kobject = g.bool()?;
    o.subst = g.opt(Get::u64)?;
    o.knotes = g.u32()?;
    o.pdrequest = g.opt(Get::u64)?;
    o.requests = g.opt(|g| {
        let n = g.len()?;
        (0..n).map(|_| Ok(Request { name: g.u32()?, notify: g.opt(Get::u64)?, spreq: g.bool()?, sparm: g.bool()?, next: g.u32()? })).collect()
    })?;
    o.psets = get_ids(g)?;
    let n = g.len()?;
    o.messages = (0..n).map(|_| get_kmsg(g).map(Box::new)).collect::<Result<VecDeque<_>, _>>()?;
    o.msgcount = g.u32()?;
    o.fullwaiters = g.bool()?;
    o.reply_context = g.u64()?;
    o.timestamp = g.u32()?;
    o.refs = g.u32()?;
    Ok(o)
}

fn put_pset(p: &mut Put, s: &Pset) {
    p.bool(s.active);
    p.u64(s.owner);
    p.u32(s.name);
    put_ids(p, s.members.iter().copied());
    p.u32(s.refs);
    p.u32(s.knotes);
}

fn get_pset(g: &mut Get<'_>) -> Result<Pset, Bad> {
    Ok(Pset { active: g.bool()?, owner: g.u64()?, name: g.u32()?, members: get_ids(g)?, refs: g.u32()?, knotes: g.u32()? })
}

/// The ports and sets, by id.
pub fn put_objects(p: &mut Put, objects: &BTreeMap<ObjId, Object>) {
    p.len(objects.len());
    for (&id, o) in objects {
        p.u64(id);
        match o {
            Object::Port(port) => {
                p.u8(0);
                put_port(p, port);
            }
            Object::Pset(s) => {
                p.u8(1);
                put_pset(p, s);
            }
        }
    }
}

pub fn get_objects(g: &mut Get<'_>) -> Result<BTreeMap<ObjId, Object>, Bad> {
    let n = g.len()?;
    let mut out = BTreeMap::new();
    for _ in 0..n {
        let id = g.u64()?;
        let at = g.at;
        let o = match g.u8()? {
            0 => Object::Port(get_port(g)?),
            1 => Object::Pset(get_pset(g)?),
            _ => return Err(Bad(at, "an object's kind")),
        };
        out.insert(id, o);
    }
    Ok(out)
}

fn put_sender(p: &mut Put, s: &Sender) {
    for w in s.sec.iter().chain(s.audit.iter()) {
        p.u32(*w);
    }
}

fn get_sender(g: &mut Get<'_>) -> Result<Sender, Bad> {
    let mut s = Sender::default();
    for w in s.sec.iter_mut().chain(s.audit.iter_mut()) {
        *w = g.u32()?;
    }
    Ok(s)
}

fn put_desc(p: &mut Put, d: &Desc) {
    match d {
        Desc::Port { off, right, raw, disp } => {
            p.u8(0);
            p.len(*off);
            put_carried(p, *right);
            p.u32(*raw);
            p.u32(*disp);
        }
        Desc::Ool { off, data, copy, addr } => {
            p.u8(1);
            p.len(*off);
            p.bytes(data);
            p.u8(*copy);
            p.u64(*addr);
        }
        Desc::OolPorts { off, rights, disp, copy } => {
            p.u8(2);
            p.len(*off);
            p.len(rights.len());
            for (c, raw) in rights {
                put_carried(p, *c);
                p.u32(*raw);
            }
            p.u32(*disp);
            p.u8(*copy);
        }
        Desc::Guarded { off, right, raw, disp, flags } => {
            p.u8(3);
            p.len(*off);
            put_carried(p, *right);
            p.u32(*raw);
            p.u32(*disp);
            p.u32(*flags);
        }
    }
}

fn get_off(g: &mut Get<'_>) -> Result<usize, Bad> {
    let at = g.at;
    usize::try_from(g.u64()?).map_err(|_| Bad(at, "an offset"))
}

fn get_desc(g: &mut Get<'_>) -> Result<Desc, Bad> {
    let at = g.at;
    Ok(match g.u8()? {
        0 => Desc::Port { off: get_off(g)?, right: get_carried(g)?, raw: g.u32()?, disp: g.u32()? },
        1 => Desc::Ool { off: get_off(g)?, data: g.bytes()?, copy: g.u8()?, addr: g.u64()? },
        2 => {
            let off = get_off(g)?;
            let n = g.len()?;
            let rights = (0..n).map(|_| Ok((get_carried(g)?, g.u32()?))).collect::<Result<_, Bad>>()?;
            Desc::OolPorts { off, rights, disp: g.u32()?, copy: g.u8()? }
        }
        3 => Desc::Guarded { off: get_off(g)?, right: get_carried(g)?, raw: g.u32()?, disp: g.u32()?, flags: g.u32()? },
        _ => return Err(Bad(at, "a descriptor's kind")),
    })
}

pub fn put_kmsg(p: &mut Put, k: &Kmsg) {
    p.u32(k.bits);
    p.u32(k.size);
    p.u64(k.dest);
    put_carried(p, k.reply);
    p.opt(k.voucher, Put::u64);
    p.u32(k.voucher_raw);
    p.i32(k.id);
    p.bytes(&k.body);
    p.len(k.descs.len());
    for d in &k.descs {
        put_desc(p, d);
    }
    put_sender(p, &k.sender);
    p.bytes(&k.aux);
    p.bool(k.keep_alive);
    p.u32(k.ppriority);
    p.u8(k.qos_override);
    p.opt(k.imp, Put::u64);
}

pub fn get_kmsg(g: &mut Get<'_>) -> Result<Kmsg, Bad> {
    let (bits, size, dest, reply, voucher, voucher_raw, id, body) = (g.u32()?, g.u32()?, g.u64()?, get_carried(g)?, g.opt(Get::u64)?, g.u32()?, g.i32()?, g.bytes()?);
    let n = g.len()?;
    let descs = (0..n).map(|_| get_desc(g)).collect::<Result<_, _>>()?;
    Ok(Kmsg { bits, size, dest, reply, voucher, voucher_raw, id, body, descs, sender: get_sender(g)?, aux: g.bytes()?, keep_alive: g.bool()?, ppriority: g.u32()?, qos_override: g.u8()?, imp: g.opt(Get::u64)? })
}

/// A map's entries in its keys' order: the same table is the same bytes.
pub fn sorted<K: Ord, V>(m: &HashMap<K, V>) -> Vec<(&K, &V)> {
    let mut v: Vec<(&K, &V)> = m.iter().collect();
    v.sort_by(|a, b| a.0.cmp(b.0));
    v
}

fn put_waiters(p: &mut Put, m: &HashMap<ObjId, VecDeque<u64>>) {
    p.len(m.len());
    for (&k, v) in sorted(m) {
        p.u64(k);
        put_ids(p, v.iter().copied());
    }
}

fn get_waiters(g: &mut Get<'_>) -> Result<HashMap<ObjId, VecDeque<u64>>, Bad> {
    let n = g.len()?;
    (0..n).map(|_| Ok((g.u64()?, get_ids(g)?))).collect()
}

/// The message queues' waiters and results.
pub fn put_queues(p: &mut Put, q: &Queues) {
    put_waiters(p, &q.receivers);
    p.len(q.rcv_wait.len());
    for (&w, r) in sorted(&q.rcv_wait) {
        p.u64(w);
        p.u64(r.object);
        p.u64(r.options);
        p.u32(r.rcv_size);
        p.u32(r.aux_size);
    }
    put_waiters(p, &q.senders);
    p.len(q.received.len());
    for (&w, r) in sorted(&q.received) {
        p.u64(w);
        p.u32(r.state);
        p.opt(r.kmsg.as_deref(), put_kmsg);
        p.u32(r.seqno);
        p.u32(r.msize);
        p.u32(r.asize);
        p.u32(r.receiver_name);
    }
    p.len(q.send_ready.len());
    for (&w, &b) in sorted(&q.send_ready) {
        p.u64(w);
        p.bool(b);
    }
    put_waiters(p, &q.preposts);
    put_ids(p, q.wake.iter().copied());
    put_ids(p, q.knotes.iter().copied());
    p.len(q.pset_knotes.len());
    for &(a, b) in &q.pset_knotes {
        p.u64(a);
        p.u64(b);
    }
    put_ids(p, q.vanish.iter().copied());
}

pub fn get_queues(g: &mut Get<'_>) -> Result<Queues, Bad> {
    let receivers = get_waiters(g)?;
    let n = g.len()?;
    let rcv_wait = (0..n).map(|_| Ok((g.u64()?, RcvWait { object: g.u64()?, options: g.u64()?, rcv_size: g.u32()?, aux_size: g.u32()? }))).collect::<Result<_, Bad>>()?;
    let senders = get_waiters(g)?;
    let n = g.len()?;
    let received = (0..n)
        .map(|_| Ok((g.u64()?, Received { state: g.u32()?, kmsg: g.opt(|g| get_kmsg(g).map(Box::new))?, seqno: g.u32()?, msize: g.u32()?, asize: g.u32()?, receiver_name: g.u32()? })))
        .collect::<Result<_, Bad>>()?;
    let n = g.len()?;
    let send_ready = (0..n).map(|_| Ok((g.u64()?, g.bool()?))).collect::<Result<_, Bad>>()?;
    let preposts = get_waiters(g)?;
    let wake = get_ids(g)?;
    let knotes = get_ids(g)?;
    let n = g.len()?;
    let pset_knotes = (0..n).map(|_| Ok((g.u64()?, g.u64()?))).collect::<Result<_, Bad>>()?;
    let vanish = get_ids(g)?;
    Ok(Queues { receivers, rcv_wait, senders, received, send_ready, preposts, wake, knotes, pset_knotes, vanish })
}

/// The kernel's objects every task names alike.
pub fn put_globals(p: &mut Put, gl: &[(Kobject, ObjId)]) {
    p.len(gl.len());
    for (k, o) in gl {
        put_kobject(p, k);
        p.u64(*o);
    }
}

pub fn get_globals(g: &mut Get<'_>) -> Result<Vec<(Kobject, ObjId)>, Bad> {
    let n = g.len()?;
    (0..n).map(|_| Ok((get_kobject(g)?, g.u64()?))).collect()
}

/// An exception action per type.
pub fn put_exc(p: &mut Put, a: &super::super::exception::ExcActions) {
    for x in a {
        put_carried(p, x.port);
        p.i32(x.behavior);
        p.i32(x.flavor);
        p.bool(x.privileged);
    }
}

pub fn get_exc(g: &mut Get<'_>) -> Result<super::super::exception::ExcActions, Bad> {
    let mut a: super::super::exception::ExcActions = Default::default();
    for x in a.iter_mut() {
        x.port = get_carried(g)?;
        x.behavior = g.i32()?;
        x.flavor = g.i32()?;
        x.privileged = g.bool()?;
    }
    Ok(a)
}

impl super::IpcShared {
    /// The table as bytes, but for its links and its vouchers (which hold
    /// what is a task's own: its mailbox and bell, its policy, its bank
    /// ledger): its objects, spaces, queues, the kernel's objects every
    /// task names, the host's special ports and exception actions, and its
    /// counters.
    pub fn table_bytes(&self) -> Vec<u8> {
        let mut p = Put::default();
        put_objects(&mut p, &self.objects);
        p.u64(self.next_id);
        p.u32(self.timestamp);
        p.len(self.spaces.len());
        for (&k, sp) in sorted(&self.spaces) {
            p.u64(k);
            sp.put(&mut p);
        }
        p.u64(self.next_task);
        put_queues(&mut p, &self.queues);
        put_globals(&mut p, &self.globals);
        put_exc(&mut p, &self.host_exc);
        p.len(self.host_special.len());
        for &(id, o) in &self.host_special {
            p.i32(id);
            p.u64(o);
        }
        p.0
    }

    /// The table [`Self::table_bytes`] made, with `links` and `vouchers` as
    /// its own; bytes that are not all of one, refused.
    pub fn of_table_bytes(b: &[u8], links: HashMap<super::TaskKey, std::sync::Arc<super::TaskLink>>, vouchers: super::super::voucher::VoucherTables) -> Result<super::IpcShared, Bad> {
        let g = &mut Get::new(b);
        let objects = get_objects(g)?;
        let next_id = g.u64()?;
        let timestamp = g.u32()?;
        let n = g.len()?;
        let spaces = (0..n).map(|_| Ok((g.u64()?, super::space::Space::get(g)?))).collect::<Result<_, Bad>>()?;
        let next_task = g.u64()?;
        let queues = get_queues(g)?;
        let globals = get_globals(g)?;
        let host_exc = get_exc(g)?;
        let n = g.len()?;
        let host_special = (0..n).map(|_| Ok((g.i32()?, g.u64()?))).collect::<Result<_, Bad>>()?;
        if !g.done() {
            return Err(Bad(g.at, "the table's end"));
        }
        Ok(super::IpcShared { objects, next_id, timestamp, spaces, next_task, queues, links, globals, host_exc, host_special, vouchers })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{Ipc, IpcCell};
    use std::sync::Arc;

    /// A table as two tasks' kernel calls leave it: ports and a set, a
    /// message with descriptors queued, rights in both spaces, the host's
    /// actions as the first call made them.
    fn table() -> (Arc<IpcCell>, u32, u32) {
        let cell = Arc::new(IpcCell::default());
        let mut a = Ipc::default();
        a.check_out(&cell);
        let (name, port) = a.port_alloc(true).expect("a port");
        let (set, _) = a.pset_alloc().expect("a set");
        let (_, other) = a.port_alloc(false).expect("another port");
        a.mqueue_reserve(port, false, 0, true).expect("room");
        let k = Kmsg {
            bits: 0x8000_0013,
            size: 64,
            dest: port,
            reply: Some(Carried::Port(other)),
            voucher: None,
            voucher_raw: 0,
            id: 4242,
            body: (0..40).collect(),
            descs: vec![Desc::Ool { off: 4, data: vec![1, 2, 3], copy: 1, addr: 0x1000 }, Desc::Port { off: 20, right: Some(Carried::Dead), raw: 7, disp: 17 }],
            sender: Sender { sec: [501, 20], audit: [1, 2, 3, 4, 5, 6, 7, 8] },
            aux: vec![9; 5],
            keep_alive: false,
            ppriority: 31,
            qos_override: 4,
            imp: None,
        };
        a.mqueue_post(port, Box::new(k), 64);
        a.check_in();
        let mut b = Ipc::default();
        b.check_out(&cell);
        let _ = b.port_alloc(true).expect("b's port");
        b.check_in();
        (cell, name, set)
    }

    fn bytes_of(s: &super::super::IpcShared) -> Vec<u8> {
        s.table_bytes()
    }

    fn of(b: &[u8]) -> Result<super::super::IpcShared, Bad> {
        super::super::IpcShared::of_table_bytes(b, HashMap::new(), Default::default())
    }

    #[test]
    fn a_table_is_the_same_table_after_its_bytes() {
        let (cell, name, set) = table();
        let s = cell.take();
        let b = bytes_of(&s);
        let back = of(&b).expect("it decodes");
        assert_eq!(bytes_of(&back), b);
        assert_eq!(format!("{:?}", back.objects), format!("{:?}", s.objects));
        // The decoded table works as the system's: the first task's names
        // are what they were.
        cell.put(back);
        let mut a = Ipc::default();
        a.task = 1;
        a.check_out(&cell);
        assert_eq!(a.right_info(name).0 & 0x1f_0000, 0x3_0000, "receive and send rights");
        assert_ne!(a.right_info(set).0, 0);
        a.check_in();
    }

    #[test]
    fn bytes_that_are_not_a_table_are_refused() {
        let (cell, _, _) = table();
        let b = bytes_of(&cell.take());
        for cut in [0, 1, b.len() / 2, b.len() - 1] {
            assert!(of(&b[..cut]).is_err(), "cut at {cut}");
        }
        let mut bad = b.clone();
        // The first object's kind.
        bad[16] = 9;
        assert!(of(&bad).is_err());
        // Bytes past a table's end.
        let mut long = b.clone();
        long.push(0);
        assert!(of(&long).is_err());
    }
}
