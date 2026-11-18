//! EVFILT_SOCK: a socket's connection events as `soevent` posts them to
//! the knotes on its `so_klist`, and the filter that reads them
//! (`filt_sockattach`, `filt_sockdetach`, `filt_sockev`, `filt_socktouch`,
//! `filt_sockprocess` and `filt_sockev_common` in `bsd/kern/uipc_socket.c`;
//! the hints in `bsd/sys/socketvar.h`, the notes in
//! `bsd/sys/event_private.h`; xnu-10063.141.1).
//!
//! A socket here posts no hints as it goes: its protocol keeps its
//! connection's state ([`crate::vfs::SoConn`]), with a count of each event
//! that changes it. Each change since the socket was last looked at is the
//! `soevent` XNU makes at it:
//!
//! - a connect (`soisconnected` outside a listener's queue):
//!   SO_FILT_HINT_CONNECTED | SO_FILT_HINT_CONNINFO_UPDATED;
//! - `socantsendmore`: SO_FILT_HINT_CANTSENDMORE;
//! - `socantrcvmore`: SO_FILT_HINT_CANTRCVMORE;
//! - a TCP reset taken (`tcp_input`'s RST in SYN_SENT, ESTABLISHED,
//!   FIN_WAIT_1, CLOSE_WAIT or FIN_WAIT_2): SO_FILT_HINT_CONNRESET;
//! - a TCP connection its retransmission or keepalive timer dropped:
//!   SO_FILT_HINT_TIMEOUT;
//! - a TCP keepalive probe received (`tcp_input`'s duplicate segment one
//!   byte before what it acknowledged): SO_FILT_HINT_KEEPALIVE;
//! - `soisdisconnected`: SO_FILT_HINT_DISCONNECTED |
//!   SO_FILT_HINT_CONNINFO_UPDATED.
//!
//! The socket is looked at before a knote is attached to it and whenever
//! its knotes are told it may have changed, so a knote is posted every
//! hint made after it was attached, as `so_klist`'s are. The other hints
//! (NOSRCADDR, IFDENIED, SUSPEND, RESUME, the adaptive timeouts,
//! NOTIFY_ACK, WAKE_PKT) come from interface policy, flow advisories,
//! TCP options not ported and acknowledgement markers, none of which a
//! connection here goes through; where a socket's protocol would post an
//! event this kernel does not carry, its state says so and the knote's
//! process is told when it is seen.

use super::kevent::{ev, Kev, KnId};
use crate::syscalls::Kernel;

/// `SO_FILT_HINT_*` (`bsd/sys/socketvar.h`).
pub mod hint {
    pub const LOCKED: u32 = 0x0000_0001;
    pub const CONNRESET: u32 = 0x0000_0002;
    pub const CANTRCVMORE: u32 = 0x0000_0004;
    pub const CANTSENDMORE: u32 = 0x0000_0008;
    pub const TIMEOUT: u32 = 0x0000_0010;
    pub const NOSRCADDR: u32 = 0x0000_0020;
    pub const IFDENIED: u32 = 0x0000_0040;
    pub const SUSPEND: u32 = 0x0000_0080;
    pub const RESUME: u32 = 0x0000_0100;
    pub const KEEPALIVE: u32 = 0x0000_0200;
    pub const ADAPTIVE_WTIMO: u32 = 0x0000_0400;
    pub const ADAPTIVE_RTIMO: u32 = 0x0000_0800;
    pub const CONNECTED: u32 = 0x0000_1000;
    pub const DISCONNECTED: u32 = 0x0000_2000;
    pub const CONNINFO_UPDATED: u32 = 0x0000_4000;
    pub const NOTIFY_ACK: u32 = 0x0008_0000;
    pub const WAKE_PKT: u32 = 0x0020_0000;
    /// `SO_FILT_HINT_EV`: the hints with a kqueue event.
    pub const EV: u32 = CONNRESET | CANTRCVMORE | CANTSENDMORE | TIMEOUT | NOSRCADDR | IFDENIED | SUSPEND | RESUME | KEEPALIVE | ADAPTIVE_WTIMO | ADAPTIVE_RTIMO | CONNECTED | DISCONNECTED | CONNINFO_UPDATED | NOTIFY_ACK | WAKE_PKT;
}

/// EVFILT_SOCK's `NOTE_*` (`bsd/sys/event_private.h`).
pub mod note {
    pub const CONNRESET: u32 = 0x0000_0001;
    pub const READCLOSED: u32 = 0x0000_0002;
    pub const WRITECLOSED: u32 = 0x0000_0004;
    pub const TIMEOUT: u32 = 0x0000_0008;
    pub const NOSRCADDR: u32 = 0x0000_0010;
    pub const IFDENIED: u32 = 0x0000_0020;
    pub const SUSPEND: u32 = 0x0000_0040;
    pub const RESUME: u32 = 0x0000_0080;
    pub const KEEPALIVE: u32 = 0x0000_0100;
    pub const ADAPTIVE_WTIMO: u32 = 0x0000_0200;
    pub const ADAPTIVE_RTIMO: u32 = 0x0000_0400;
    pub const CONNECTED: u32 = 0x0000_0800;
    pub const DISCONNECTED: u32 = 0x0000_1000;
    pub const CONNINFO_UPDATED: u32 = 0x0000_2000;
    pub const NOTIFY_ACK: u32 = 0x0000_4000;
    pub const WAKE_PKT: u32 = 0x0000_8000;
    /// `EVFILT_SOCK_LEVEL_TRIGGER_MASK`.
    pub const LEVEL_TRIGGER_MASK: u32 = READCLOSED | WRITECLOSED | SUSPEND | RESUME | CONNECTED | DISCONNECTED;
    /// `EVFILT_SOCK_ALL_MASK`.
    pub const ALL_MASK: u32 = CONNRESET | READCLOSED | WRITECLOSED | TIMEOUT | NOSRCADDR | IFDENIED | SUSPEND | RESUME | KEEPALIVE | ADAPTIVE_WTIMO | ADAPTIVE_RTIMO | CONNECTED | DISCONNECTED | CONNINFO_UPDATED | NOTIFY_ACK | WAKE_PKT;
}

/// `SOCKEV_CONNECTED` and `SOCKEV_DISCONNECTED`: `get_sockev_state`'s.
const SOCKEV_CONNECTED: i64 = 0x1;
const SOCKEV_DISCONNECTED: i64 = 0x2;

/// What of a socket's connection the hints are told from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Seen {
    connects: u32,
    disconnects: u32,
    resets: u32,
    timeouts: u32,
    cantrcv: bool,
    cantsend: bool,
    keepalives: u32,
}

impl Seen {
    fn of(st: &crate::vfs::SoState) -> Seen {
        Seen { connects: st.conn.connects, disconnects: st.conn.disconnects, resets: st.conn.resets, timeouts: st.conn.timeouts, cantrcv: st.cantrcv, cantsend: st.cantsend, keepalives: st.conn.keepalives }
    }

    /// The `soevent` hints the changes from `old` to `self` are.
    fn hints_from(&self, old: &Seen) -> u32 {
        let mut h = 0;
        if self.connects > old.connects {
            h |= hint::CONNECTED | hint::CONNINFO_UPDATED;
        }
        if self.cantsend && !old.cantsend {
            h |= hint::CANTSENDMORE;
        }
        if self.cantrcv && !old.cantrcv {
            h |= hint::CANTRCVMORE;
        }
        if self.resets > old.resets {
            h |= hint::CONNRESET;
        }
        if self.timeouts > old.timeouts {
            h |= hint::TIMEOUT;
        }
        if self.keepalives > old.keepalives {
            h |= hint::KEEPALIVE;
        }
        if self.disconnects > old.disconnects {
            h |= hint::DISCONNECTED | hint::CONNINFO_UPDATED;
        }
        h
    }
}

/// A socket's hints as its knotes are posted them: the state last looked
/// at, and when each hint was last posted, counted in posts.
#[derive(Debug, Default)]
pub struct SoEv {
    seen: Option<Seen>,
    /// The posts made.
    seq: u64,
    /// `seq` at each hint bit's last post.
    posted: [u64; 32],
    /// An unmodelled event of the socket's has been said.
    said: bool,
}

impl SoEv {
    /// Look at the socket as it is: post what changed since the last look
    /// (the first look posts nothing). The unmodelled event to say, once.
    fn look(&mut self, st: &crate::vfs::SoState) -> Option<&'static str> {
        let now = Seen::of(st);
        if let Some(old) = self.seen {
            let h = now.hints_from(&old);
            if h != 0 {
                self.seq += 1;
                for b in 0..32 {
                    if h & (1 << b) != 0 {
                        self.posted[b] = self.seq;
                    }
                }
            }
        }
        self.seen = Some(now);
        match st.conn.unmodelled {
            Some(what) if !self.said => {
                self.said = true;
                Some(what)
            }
            _ => None,
        }
    }

    /// The hints posted after post `since`.
    fn since(&self, since: u64) -> u32 {
        (0..32).filter(|&b| self.posted[b] > since).fold(0, |h, b| h | 1 << b)
    }
}

impl Kernel {
    /// The TCP timers of this process's sockets (`tcp_run_timerlist`):
    /// those due run, with the wakeups and events they make; when the next
    /// is due. The sockets are counted in the pipe watch while there are
    /// any, so a change another process makes to one of their connections
    /// (which may arm a timer here) wakes the thread calls.
    pub(crate) fn darwin_tcp_timers(&mut self) -> Option<std::time::Instant> {
        let gen = self.fds.generation();
        if self.dtask.tcp_socks_gen != Some(gen) {
            self.dtask.tcp_socks = self
                .fds
                .entries()
                .into_iter()
                .filter_map(|(_, f, _)| std::sync::Arc::clone(&f.handle).as_inet_socket())
                .filter(|s| s.kind == crate::net::Kind::Tcp)
                .map(|s| std::sync::Arc::downgrade(&s))
                .collect();
            self.dtask.tcp_socks_gen = Some(gen);
            let want = !self.dtask.tcp_socks.is_empty();
            if want != self.dtask.tcp_watch {
                self.dtask.tcp_watch = want;
                if want {
                    self.dtask.kevents.pipe_watch.fetch_add(1, std::sync::atomic::Ordering::Release);
                } else {
                    self.dtask.kevents.pipe_watch.fetch_sub(1, std::sync::atomic::Ordering::Release);
                }
            }
        }
        let mut next: Option<std::time::Instant> = None;
        for w in &self.dtask.tcp_socks {
            if let Some(d) = w.upgrade().and_then(|s| s.tcp_deadline()) {
                next = Some(next.map_or(d, |n| n.min(d)));
            }
        }
        next
    }

    /// Look at a socket knote's socket ([`SoEv::look`]): its state, and the
    /// posts made so far.
    fn sockev_look(&mut self, n: KnId) -> (crate::vfs::SoState, u64) {
        let fp = self.knote(n).fp.clone().expect("a socket knote's file");
        let st = fp.handle.so_state().expect("a socket knote's socket");
        let (said, seq) = {
            let mut e = fp.darwin_sockev.lock().unwrap_or_else(|e| e.into_inner());
            (e.look(&st), e.seq)
        };
        if let Some(what) = said {
            self.darwin_unimplemented(format!("EVFILT_SOCK: {what}"));
        }
        (st, seq)
    }

    /// The hints posted to a socket knote since it was last posted, the
    /// knote marked as told of them.
    fn sockev_pending(&mut self, n: KnId) -> (crate::vfs::SoState, u32) {
        let (st, seq) = self.sockev_look(n);
        let k = self.knote(n);
        let last = k.seen.unwrap_or(seq);
        k.seen = Some(seq);
        if last == seq {
            return (st, 0);
        }
        let fp = k.fp.clone().expect("a socket knote's file");
        let h = fp.darwin_sockev.lock().unwrap_or_else(|e| e.into_inner()).since(last);
        (st, h | hint::LOCKED)
    }

    /// `filt_sockattach`: on the socket's list, posted nothing made before
    /// now; whether its state already fires it.
    pub(crate) fn filt_sockattach(&mut self, n: KnId) -> u32 {
        let (st, seq) = self.sockev_look(n);
        let k = self.knote(n);
        k.hook32 = 0;
        k.seen = Some(seq);
        self.filt_sockev_common(n, None, &st, 0)
    }

    /// The knote's socket list told it may have changed: `KNOTE(&so->
    /// so_klist, hint)` for each post it has not been told of; whether any
    /// was made.
    pub(crate) fn sockev_knote(&mut self, n: KnId) -> bool {
        let (_, seq) = self.sockev_look(n);
        if self.knote(n).seen == Some(seq) {
            return false;
        }
        let fp = self.knote(n).fp.clone().expect("a socket knote's file");
        let last = self.knote(n).seen.unwrap_or(seq);
        let h = fp.darwin_sockev.lock().unwrap_or_else(|e| e.into_inner()).since(last);
        self.knote(n).seen = Some(seq);
        self.knote_list(&[n], i64::from(h | hint::LOCKED));
        true
    }

    /// `filt_sockev`: the hint's events.
    pub(crate) fn filt_sockev(&mut self, n: KnId, h: i64) -> u32 {
        let fp = self.knote(n).fp.clone().expect("a socket knote's file");
        let st = fp.handle.so_state().expect("a socket knote's socket");
        self.filt_sockev_common(n, None, &st, h as u32 & hint::EV)
    }

    /// `filt_socktouch`: the new interest, the delivered level events no
    /// longer asked for forgotten.
    pub(crate) fn filt_socktouch(&mut self, n: KnId, kev: &Kev) -> u32 {
        // What was posted and not yet told (its KNOTE runs as it is made).
        let (st, h) = self.sockev_pending(n);
        if h != 0 {
            self.filt_sockev_common(n, None, &st, h & hint::EV);
        }
        let k = self.knote(n);
        let changed = k.sfflags ^ k.hook32;
        k.sfflags = kev.fflags;
        k.sdata = kev.data;
        // kn_fflags are left as they were, as XNU leaves them.
        k.hook32 &= !(changed & note::LEVEL_TRIGGER_MASK);
        self.filt_sockev_common(n, None, &st, 0)
    }

    /// `filt_sockprocess`.
    pub(crate) fn filt_sockprocess(&mut self, n: KnId, kev: &mut Kev) -> u32 {
        let (st, h) = self.sockev_pending(n);
        if h != 0 {
            self.filt_sockev_common(n, None, &st, h & hint::EV);
        }
        self.filt_sockev_common(n, Some(kev), &st, 0)
    }

    /// `filt_sockev_common`: the hint's events and the socket's state's
    /// collected in the knote's fflags, those it does not ask for dropped,
    /// a level event it has been delivered not delivered again; whether
    /// any is left, the event filled in when asked.
    fn filt_sockev_common(&mut self, n: KnId, kev: Option<&mut Kev>, st: &crate::vfs::SoState, ev_hint: u32) -> u32 {
        let k = self.knote(n);
        let mut ret = false;
        let mut level_trigger = 0u32;
        for (h, nb) in [
            (hint::CONNRESET, note::CONNRESET),
            (hint::TIMEOUT, note::TIMEOUT),
            (hint::NOSRCADDR, note::NOSRCADDR),
            (hint::IFDENIED, note::IFDENIED),
            (hint::KEEPALIVE, note::KEEPALIVE),
            (hint::ADAPTIVE_WTIMO, note::ADAPTIVE_WTIMO),
            (hint::ADAPTIVE_RTIMO, note::ADAPTIVE_RTIMO),
        ] {
            if ev_hint & h != 0 {
                k.fflags |= nb;
            }
        }
        if ev_hint & hint::CONNECTED != 0 || st.conn.connected {
            k.fflags |= note::CONNECTED;
            level_trigger |= note::CONNECTED;
        }
        if ev_hint & hint::DISCONNECTED != 0 || st.conn.disconnected {
            k.fflags |= note::DISCONNECTED;
            level_trigger |= note::DISCONNECTED;
        }
        if ev_hint & hint::CONNINFO_UPDATED != 0 && st.conn.evconninfo {
            k.fflags |= note::CONNINFO_UPDATED;
        }
        // tcp_notify_ack_active: no TCP_NOTIFY_ACKNOWLEDGEMENT marker can
        // be set here (the option is refused as not ported).
        if ev_hint & hint::NOTIFY_ACK != 0 {
            k.fflags |= note::NOTIFY_ACK;
        }
        if ev_hint & hint::WAKE_PKT != 0 {
            k.fflags |= note::WAKE_PKT;
        }
        // No content filter holds data back here (cfil_sock_data_pending).
        if st.cantrcv {
            k.fflags |= note::READCLOSED;
            level_trigger |= note::READCLOSED;
        }
        if st.cantsend {
            k.fflags |= note::WRITECLOSED;
            level_trigger |= note::WRITECLOSED;
        }
        // SOF_SUSPENDED is set by an interface's flow advisory, which no
        // output here takes: never suspended, so resumed.
        let suspended = false;
        if ev_hint & hint::SUSPEND != 0 || suspended {
            k.fflags &= !(note::SUSPEND | note::RESUME);
            k.hook32 &= !note::RESUME;
            k.fflags |= note::SUSPEND;
            level_trigger |= note::SUSPEND;
        }
        if ev_hint & hint::RESUME != 0 || !suspended {
            k.fflags &= !(note::SUSPEND | note::RESUME);
            k.hook32 &= !note::SUSPEND;
            k.fflags |= note::RESUME;
            level_trigger |= note::RESUME;
        }
        let data = if st.error != 0 {
            ret = true;
            k.flags |= ev::EOF;
            i64::from(st.error)
        } else {
            // get_sockev_state, from a state of zero.
            let mut s = 0;
            if st.conn.connected {
                s |= SOCKEV_CONNECTED;
            }
            if st.conn.disconnected {
                s |= SOCKEV_DISCONNECTED;
            }
            s
        };
        k.fflags &= k.sfflags & note::ALL_MASK;
        level_trigger &= k.sfflags & note::ALL_MASK;
        // The level events already delivered are not delivered again.
        level_trigger &= k.hook32;
        level_trigger &= note::LEVEL_TRIGGER_MASK;
        if k.fflags & !level_trigger != 0 {
            ret = true;
        }
        if ret {
            if let Some(kev) = kev {
                if k.fflags != 0 {
                    k.hook32 |= k.fflags & note::LEVEL_TRIGGER_MASK;
                }
                // Only the last of NOTE_SUSPEND and NOTE_RESUME delivered is
                // remembered.
                if k.fflags & note::SUSPEND != 0 {
                    k.hook32 &= !note::RESUME;
                }
                if k.fflags & note::RESUME != 0 {
                    k.hook32 &= !note::SUSPEND;
                }
                *kev = k.fill_kevent(data);
            }
        }
        u32::from(ret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs::{SoConn, SoState};

    fn state(conn: SoConn, cantrcv: bool, cantsend: bool) -> SoState {
        SoState { qlen: None, rcv: 0, cantrcv, cantsend, error: 0, can_write: true, snd_used: 0, hiwat: (0, 0), snd_lowat: 0, unix_stream: false, ctl: 0, records: None, exact: true, peer_space: None, snd_mbmax: None, unp_cc: 0, live_hiwat: false, conn, oobmark: 0, rcvatmark: false, oob_unmodelled: None }
    }

    #[test]
    fn the_first_look_posts_nothing() {
        let mut e = SoEv::default();
        e.look(&state(SoConn { connected: true, connects: 1, ..Default::default() }, false, false));
        assert_eq!(e.seq, 0);
        assert_eq!(e.since(0), 0);
    }

    #[test]
    fn a_connect_then_a_reset_post_their_hints_in_turn() {
        let mut e = SoEv::default();
        e.look(&state(SoConn::default(), false, false));
        e.look(&state(SoConn { connected: true, connects: 1, ..Default::default() }, false, false));
        assert_eq!(e.since(0), hint::CONNECTED | hint::CONNINFO_UPDATED);
        let after_connect = e.seq;
        e.look(&state(SoConn { disconnected: true, connects: 1, disconnects: 1, resets: 1, ..Default::default() }, true, true));
        assert_eq!(e.since(after_connect), hint::CONNRESET | hint::DISCONNECTED | hint::CONNINFO_UPDATED | hint::CANTRCVMORE | hint::CANTSENDMORE);
        assert_eq!(e.since(0) & hint::CONNECTED, hint::CONNECTED, "an earlier knote has both");
        assert_eq!(e.since(e.seq), 0);
    }

    #[test]
    fn a_connect_and_disconnect_between_looks_are_both_posted() {
        let mut e = SoEv::default();
        e.look(&state(SoConn::default(), false, false));
        e.look(&state(SoConn { disconnected: true, connects: 1, disconnects: 1, ..Default::default() }, true, true));
        assert_eq!(e.since(0) & (hint::CONNECTED | hint::DISCONNECTED), hint::CONNECTED | hint::DISCONNECTED);
    }

    #[test]
    fn an_unmodelled_event_is_said_once() {
        let mut e = SoEv::default();
        let st = state(SoConn { unmodelled: Some("x"), ..Default::default() }, false, false);
        assert_eq!(e.look(&st), Some("x"));
        assert_eq!(e.look(&st), None);
    }

    #[test]
    fn the_masks_are_xnus() {
        assert_eq!(note::ALL_MASK, 0xffff);
        assert_eq!(note::LEVEL_TRIGGER_MASK, 0x18c6);
        assert_eq!(hint::EV, 0x28_7ffe);
    }
}
