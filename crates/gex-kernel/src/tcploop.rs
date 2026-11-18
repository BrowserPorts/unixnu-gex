//! TCP between two sockets this kernel holds (a guest connecting to a port
//! another guest listens on): the two byte streams, and each end's TCP
//! control block as XNU keeps it (`bsd/netinet/tcp_input.c`,
//! `tcp_output.c`, `tcp_timer.c`, `tcp_usrreq.c` and `tcp_subr.c` of
//! xnu-10063.141.1).
//!
//! On loopback a segment arrives as it is sent and is acknowledged at once,
//! so between two calls an end is in a state no segment is in flight for:
//! ESTABLISHED, CLOSE_WAIT, FIN_WAIT_2, TIME_WAIT or closed. FIN_WAIT_1,
//! CLOSING and LAST_ACK last only from a FIN's sending to its
//! acknowledgement.
//!
//! A Darwin end runs TCP's timers (`tcp_timers`): TCPT_KEEP (the keepalive
//! probes, and their drop) and TCPT_2MSL (FIN_WAIT_2's timeout and
//! TIME_WAIT's end), each kept as its deadline. A look at the connection
//! first runs the timers that are due, each at its own deadline (that
//! deadline is `tcp_now` for it), so what the look finds is what the
//! timers firing on time would have left; the thread calls of the
//! processes holding the ends look at it at its next deadline
//! ([`LoopEnd::next_deadline`]).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use crate::errno::Errno;
use crate::net::{Status, TcpEnd, Transport};
use crate::vfs::SoOwner;

/// The TCP sysctls a connection here follows (`bsd/netinet/tcp_timer.c`),
/// kernel-wide as XNU's are, in milliseconds (TCP_RETRANSHZ is 1000). The
/// defaults are those 21H461's kernelcache holds (`tcp_keepinit` 75000,
/// `tcp_keepidle` 7200000, `tcp_keepintvl` 75000, `tcp_keepcnt` 8,
/// `tcp_msl` 15000, `tcp_fin_timeout` 60000, `always_keepalive` 0).
pub mod sysctl {
    use super::*;

    pub static KEEPINIT: AtomicI32 = AtomicI32::new(75_000);
    pub static KEEPIDLE: AtomicI32 = AtomicI32::new(7_200_000);
    pub static KEEPINTVL: AtomicI32 = AtomicI32::new(75_000);
    pub static KEEPCNT: AtomicI32 = AtomicI32::new(8);
    pub static MSL: AtomicI32 = AtomicI32::new(15_000);
    pub static FIN_TIMEOUT: AtomicI32 = AtomicI32::new(TCPTV_FINWAIT2);
    pub static ALWAYS_KEEPALIVE: AtomicI32 = AtomicI32::new(0);
    /// `TCPTV_FINWAIT2`, which `net.inet.tcp.fin_timeout` set to -1
    /// restores.
    pub const TCPTV_FINWAIT2: i32 = 60_000;

    pub fn get(v: &AtomicI32) -> i32 {
        v.load(Ordering::Acquire)
    }

    pub fn set(v: &AtomicI32, n: i32) {
        v.store(n, Ordering::Release);
    }
}

/// `TCP_MAXWIN`, and the receive window's scale `tcp_set_max_rwinscale`
/// asks for: at least `tcp_win_scale` (net.inet.tcp.win_scale_factor, 3),
/// enough for the largest receive buffer (`tcp_autorcvbuf_max`,
/// net.inet.tcp.autorcvbufmax, 2097152, unless SO_RCVBUF set it:
/// SB_USRSIZE), at most TCP_MAX_WINSHIFT.
const TCP_MAXWIN: u32 = 65535;
const TCP_MAX_WINSHIFT: u32 = 14;
const TCP_WIN_SCALE: u32 = 3;
const TCP_AUTORCVBUF_MAX: u32 = 2_097_152;
/// `t_maxseg` of a connection over lo0: its MTU (LOMTU, 16384) less the
/// IP and TCP headers (40) and the timestamp option both ends use
/// (TCPOLEN_TSTAMP_APPA, 12), as `tcp_mss` takes it.
const LO_MAXSEG: u32 = 16384 - 40 - 12;

/// Far more than a guest leaves unread in practice; a writer past it gets a
/// short count and waits, as on a full socket buffer.
const LOOP_BUF_MAX: usize = 4 << 20;
/// `TCPOOB_HAVEDATA` and `TCPOOB_HADDATA`.
const TCPOOB_HAVEDATA: u8 = 0x01;
const TCPOOB_HADDATA: u8 = 0x02;
/// `sb_max`, which an urgent pointer past it, with what is buffered, is
/// not taken against (`tcp_input`).
const SB_MAX: u64 = 8192 * 1024;

/// `t_state` (`bsd/netinet/tcp_fsm.h`), of the states an end here passes.
pub mod state {
    pub const CLOSED: u8 = 0;
    pub const ESTABLISHED: u8 = 4;
    pub const CLOSE_WAIT: u8 = 5;
    pub const FIN_WAIT_1: u8 = 6;
    pub const CLOSING: u8 = 7;
    pub const LAST_ACK: u8 = 8;
    pub const FIN_WAIT_2: u8 = 9;
    pub const TIME_WAIT: u8 = 10;
}

/// What of an end's socket its TCP reads: `so_options`' SO_KEEPALIVE,
/// `t_keepidle`, `t_keepintvl` (milliseconds) and `t_keepcnt` (0 is the
/// system's), and its receive buffer's `sb_hiwat` and `sb_lowat`, with
/// SB_USRSIZE (SO_RCVBUF set it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpOpts {
    pub keepalive: bool,
    pub keepidle: u32,
    pub keepintvl: u32,
    pub keepcnt: u32,
    pub rcv_hiwat: u32,
    pub rcv_lowat: u32,
    pub rcv_usrsize: bool,
}

impl Default for TcpOpts {
    /// A socket that set none: `tcp_recvspace` (556032) to receive into.
    fn default() -> TcpOpts {
        TcpOpts { keepalive: false, keepidle: 0, keepintvl: 0, keepcnt: 0, rcv_hiwat: 556_032, rcv_lowat: 1, rcv_usrsize: false }
    }
}

/// The option a `setsockopt` changed, for what `tcp_ctloutput` does on
/// the change besides keeping it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OptChange {
    /// SO_KEEPALIVE, SO_RCVBUF, SO_RCVLOWAT: kept, no timer moved.
    Kept,
    /// TCP_KEEPALIVE: TCPT_KEEP rearmed for an established connection.
    KeepIdle,
    /// TCP_KEEPINTVL or TCP_KEEPCNT: FIN_WAIT_2's TCPT_2MSL rearmed.
    KeepIntvlOrCnt,
}

/// One direction's bytes, as the receiving end's socket buffer holds them.
#[derive(Debug, Default)]
struct RcvBuf {
    data: VecDeque<u8>,
    /// The bytes ever sent this way, an urgent byte pulled out of the
    /// stream among them (the sequence space), and `rcv_up`, the urgent
    /// pointer as far as it has been taken, in it.
    seq: u64,
    rcv_up: u64,
    /// The receiver's `so_oobmark` (bytes of `data` ahead of the mark) and
    /// `SS_RCVATMARK`.
    oobmark: usize,
    atmark: bool,
    /// The receiver's `t_iobc` and `t_oobflags`.
    iobc: u8,
    oobflags: u8,
    /// The receiver's `SO_OOBINLINE`.
    oobinline: bool,
}

/// One end's TCP control block, with the socket state its TCP changes.
#[derive(Debug)]
struct Tcb {
    /// A Darwin socket's end: XNU's TCP, timers and all.
    xnu: bool,
    state: u8,
    /// `t_rcvtime`: when a segment last arrived.
    rcvtime: Instant,
    /// `t_timer[TCPT_KEEP]` and `t_timer[TCPT_2MSL]`, as deadlines.
    keep: Option<Instant>,
    msl2: Option<Instant>,
    opts: TcpOpts,
    /// TF_SENTFIN.
    fin_sent: bool,
    /// TCPS_HAVERCVDFIN.
    fin_rcvd: bool,
    /// SS_NOFDREF: its descriptor is closed.
    nofdref: bool,
    /// SS_ISCONNECTED, SS_CANTRCVMORE, SS_CANTSENDMORE.
    connected: bool,
    cantrcv: bool,
    cantsend: bool,
    /// `sorflush`, and whether it came before this end's FIN.
    rd_shut: bool,
    rd_first: bool,
    /// INPCB_STATE_DEAD: `tcp_close` has run.
    dead: bool,
    so_error: Option<Errno>,
    /// The `soevent`s posted: `soisdisconnected` calls, resets taken,
    /// timer drops, keepalive probes received.
    disconnects: u32,
    resets: u32,
    timeouts: u32,
    keepalives: u32,
    /// `rcv_adv - rcv_nxt`: the window last advertised, not yet filled.
    adv_room: u32,
    owner: Weak<SoOwner>,
}

impl Tcb {
    fn new(now: Instant) -> Tcb {
        Tcb {
            xnu: false,
            state: state::ESTABLISHED,
            rcvtime: now,
            keep: None,
            msl2: None,
            opts: TcpOpts::default(),
            fin_sent: false,
            fin_rcvd: false,
            nofdref: false,
            connected: true,
            cantrcv: false,
            cantsend: false,
            rd_shut: false,
            rd_first: false,
            dead: false,
            so_error: None,
            disconnects: 0,
            resets: 0,
            timeouts: 0,
            keepalives: 0,
            adv_room: TcpOpts::default().rcv_hiwat,
            owner: Weak::new(),
        }
    }

    /// TCP_CONN_KEEPIDLE: `t_keepidle` only with SO_KEEPALIVE.
    fn conn_keepidle(&self) -> u32 {
        if self.opts.keepidle != 0 && self.opts.keepalive {
            self.opts.keepidle
        } else {
            sysctl::get(&sysctl::KEEPIDLE) as u32
        }
    }

    fn conn_keepintvl(&self) -> u32 {
        if self.opts.keepintvl > 0 {
            self.opts.keepintvl
        } else {
            sysctl::get(&sysctl::KEEPINTVL) as u32
        }
    }

    fn conn_keepcnt(&self) -> u32 {
        if self.opts.keepcnt > 0 {
            self.opts.keepcnt
        } else {
            sysctl::get(&sysctl::KEEPCNT) as u32
        }
    }

    /// TCP_CONN_MAXIDLE, in `uint32_t` as XNU multiplies it.
    fn conn_maxidle(&self) -> u32 {
        self.conn_keepcnt().wrapping_mul(self.conn_keepintvl())
    }

    /// TCPS_HAVEESTABLISHED.
    fn have_established(&self) -> bool {
        self.state >= state::ESTABLISHED
    }

    /// `tcp_keepalive_reset`.
    fn keepalive_reset(&mut self, t: Instant) {
        self.keep = Some(after(t, self.conn_keepidle()));
    }

    /// `tcp_set_finwait_timeout`.
    fn set_finwait_timeout(&mut self, t: Instant) {
        let fin = sysctl::get(&sysctl::FIN_TIMEOUT);
        let maxidle = self.conn_maxidle();
        self.msl2 = Some(if fin > 0 && (fin as u32) < maxidle { after(t, fin as u32) } else { after(t, maxidle) });
    }

    /// The receive window's scale (`tcp_set_max_rwinscale`).
    fn rcv_scale(&self) -> u32 {
        let max = if self.opts.rcv_usrsize { self.opts.rcv_hiwat } else { TCP_AUTORCVBUF_MAX };
        let mut s = TCP_WIN_SCALE;
        while s < TCP_MAX_WINSHIFT && ((TCP_MAXWIN + 1) << s) < max {
            s += 1;
        }
        s.min(TCP_MAX_WINSHIFT)
    }

    /// The next deadline of its timers.
    fn next(&self) -> Option<Instant> {
        match (self.keep, self.msl2) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

/// Whether every timer offset a connection with these options can arm is
/// under 2^31 ms: XNU keeps `tcp_now` and its timers in 32 bits and
/// compares them as signed differences (TSTMP_GEQ), which an offset past
/// that wraps; such timers are not modelled.
pub fn offsets_fit(opts: &TcpOpts) -> bool {
    let mut t = Tcb::new(Instant::now());
    t.opts = *opts;
    let keepidle = t.conn_keepidle();
    t.opts.keepalive = !opts.keepalive;
    let other = t.conn_keepidle();
    let msl2 = 2u64 * u64::from(sysctl::get(&sysctl::MSL) as u32);
    let fin = sysctl::get(&sysctl::FIN_TIMEOUT).max(0) as u64;
    [u64::from(keepidle), u64::from(other), u64::from(t.conn_keepintvl()), u64::from(t.conn_maxidle()), msl2, fin].iter().all(|&v| v < 1 << 31)
}

/// `tcp_now + off` as a deadline.
fn after(t: Instant, off: u32) -> Instant {
    t + Duration::from_millis(u64::from(off))
}

/// A connection: each end's receive buffer and control block.
#[derive(Debug)]
struct Conn {
    rcv: [RcvBuf; 2],
    tcb: [Tcb; 2],
    /// The ends whose owners the operation woke, and the one it told of
    /// urgent data.
    wake: [bool; 2],
    urgent: [bool; 2],
}

/// What a timer is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Timer {
    Keep,
    Msl2,
}

impl Conn {
    /// `sowakeup` of end `i`'s socket.
    fn wake(&mut self, i: usize) {
        self.wake[i] = true;
    }

    /// `soisdisconnected`.
    fn soisdisconnected(&mut self, i: usize) {
        let e = &mut self.tcb[i];
        e.connected = false;
        e.cantrcv = true;
        e.cantsend = true;
        e.disconnects += 1;
        self.wake(i);
    }

    /// `tcp_close`: its timers cancelled, its PCB dead, its socket
    /// disconnected.
    fn tcp_close(&mut self, i: usize) {
        let e = &mut self.tcb[i];
        e.state = state::CLOSED;
        e.keep = None;
        e.msl2 = None;
        e.dead = true;
        self.soisdisconnected(i);
    }

    /// `tcp_drop`: a reset to the peer (TCPS_HAVERCVDSYN), `so_error` set
    /// to `err` (cleared for none), then `tcp_close`.
    fn tcp_drop(&mut self, i: usize, err: Option<Errno>, t: Instant) {
        if self.tcb[i].state != state::CLOSED {
            self.tcb[i].state = state::CLOSED;
            self.rst_to(1 - i, t);
        }
        self.tcb[i].so_error = err;
        self.tcp_close(i);
    }

    /// A segment arrives at end `i` (`tcp_input`): `t_rcvtime`, and the
    /// keepalive timer reset for a connection established.
    fn segment_in(&mut self, i: usize, t: Instant) {
        let e = &mut self.tcb[i];
        e.rcvtime = t;
        if e.xnu && e.have_established() && e.state != state::CLOSED {
            e.keepalive_reset(t);
        }
    }

    /// A reset arrives at end `i`, from its peer or from no PCB at all
    /// (`tcp_input`'s TH_RST, in sequence on loopback).
    fn rst_to(&mut self, i: usize, t: Instant) {
        if self.tcb[i].dead {
            return;
        }
        self.segment_in(i, t);
        match self.tcb[i].state {
            state::ESTABLISHED | state::FIN_WAIT_1 | state::CLOSE_WAIT | state::FIN_WAIT_2 => {
                self.tcb[i].so_error = Some(Errno::ECONNRESET);
                self.tcb[i].resets += 1;
                self.tcp_close(i);
            }
            state::CLOSING | state::LAST_ACK => self.tcp_close(i),
            _ => {}
        }
    }

    /// End `i` sends its window (an ACK, a window update, data): the
    /// receive window `tcp_output` computes, which is now the peer's to
    /// fill (`rcv_adv`).
    fn advertise(&mut self, i: usize) {
        let w = self.recwin(i);
        self.tcb[i].adv_room = w;
    }

    /// `tcp_output`'s `recwin`: the buffer's room, nothing below a
    /// quarter of it and a segment, no more than the scaled maximum, no
    /// less than what was advertised.
    fn recwin(&self, i: usize) -> u32 {
        let e = &self.tcb[i];
        let hiwat = e.opts.rcv_hiwat;
        let cc = self.rcv[i].data.len().min(u32::MAX as usize) as u32;
        let mut recwin = hiwat.saturating_sub(cc);
        if recwin < hiwat / 4 && recwin < LO_MAXSEG {
            recwin = 0;
        }
        recwin = recwin.min(TCP_MAXWIN << e.rcv_scale());
        recwin.max(e.adv_room)
    }

    /// After a read at end `i` (`tcp_usr_rcvd`'s `tcp_output`): whether
    /// the window has opened enough to say so (TCP_ACK_STRATEGY_MODERN,
    /// net.inet.tcp.ack_strategy 1; every segment here is acknowledged on
    /// arrival, so `last_ack_sent` is `rcv_nxt`).
    fn window_update(&mut self, i: usize, t: Instant) {
        if !self.tcb[i].xnu || self.tcb[i].dead || self.tcb[1 - i].dead {
            return;
        }
        let recwin = self.recwin(i);
        if recwin == 0 {
            return;
        }
        let e = &self.tcb[i];
        let scale = e.rcv_scale();
        let oldwin = e.adv_room;
        let adv = recwin.min(TCP_MAXWIN << scale) as i64 - i64::from(oldwin);
        let cc = self.rcv[i].data.len() as u64;
        let mut send = false;
        if adv >= i64::from(2 * LO_MAXSEG) && cc < u64::from(e.opts.rcv_lowat) && ((i64::from(oldwin) + adv) >> scale) > (i64::from(oldwin) >> scale) {
            send = true;
        }
        if 4 * adv >= i64::from(e.opts.rcv_hiwat) {
            send = true;
        }
        if send {
            self.tcb[i].adv_room = recwin;
            self.segment_in(1 - i, t);
        }
    }

    /// End `i` sends `n` bytes (urgent: the last of them the urgent byte)
    /// to its peer, at `t`: the peer's TCP takes them, or resets.
    fn deliver(&mut self, i: usize, data: &[u8], urgent: bool, t: Instant) {
        let j = 1 - i;
        // No PCB there: the reset `tcp_input` answers with.
        if self.tcb[j].dead {
            self.rst_to(i, t);
            return;
        }
        if self.tcb[j].xnu {
            self.segment_in(j, t);
            // New data after the user is gone, or after the receiver can
            // receive no more: `tcp_close` and a reset.
            let pj = &self.tcb[j];
            if (pj.nofdref && pj.state > state::CLOSE_WAIT) || pj.cantrcv {
                self.tcp_close(j);
                self.rst_to(i, t);
                return;
            }
        } else if self.tcb[j].nofdref {
            // A Linux end closed: the first write meets its reset.
            self.tcb[j].dead = true;
            self.rst_to_linux(i);
            return;
        }
        let rb = &mut self.rcv[j];
        if urgent {
            let n = data.len();
            let cc = rb.data.len();
            let up = rb.seq + n as u64;
            let mut taken = false;
            if (n + cc) as u64 <= SB_MAX && up > rb.rcv_up {
                rb.rcv_up = up;
                rb.oobmark = cc + n - 1;
                if rb.oobmark == 0 {
                    rb.atmark = true;
                }
                rb.oobflags &= !(TCPOOB_HAVEDATA | TCPOOB_HADDATA);
                taken = true;
            }
            if taken && !rb.oobinline {
                rb.iobc = data[n - 1];
                rb.oobflags |= TCPOOB_HAVEDATA;
                rb.data.extend(&data[..n - 1]);
            } else {
                rb.data.extend(data);
            }
            rb.seq += n as u64;
            if taken {
                self.urgent[j] = true;
            }
        } else {
            rb.data.extend(data);
            rb.seq += data.len() as u64;
        }
        let filled = data.len().min(u32::MAX as usize) as u32;
        self.tcb[j].adv_room = self.tcb[j].adv_room.saturating_sub(filled);
        self.wake(j);
        // Its acknowledgement, with the receiver's window.
        self.advertise(j);
        self.segment_in(i, t);
        self.wake(i);
    }

    /// A Linux end's reset after a write to a closed peer: ECONNRESET to be
    /// read, and the connection over.
    fn rst_to_linux(&mut self, i: usize) {
        let e = &mut self.tcb[i];
        e.so_error = Some(Errno::ECONNRESET);
        e.resets += 1;
        e.dead = true;
        e.connected = false;
        e.cantrcv = true;
        e.cantsend = true;
        e.disconnects += 1;
        self.wake(i);
    }

    /// End `i`'s FIN goes out (`tcp_output` in FIN_WAIT_1, CLOSING or
    /// LAST_ACK), at `t`: the peer takes it and acknowledges it.
    fn send_fin(&mut self, i: usize, t: Instant) {
        if self.tcb[i].fin_sent {
            return;
        }
        self.tcb[i].fin_sent = true;
        let j = 1 - i;
        if self.tcb[j].dead {
            self.rst_to(i, t);
            return;
        }
        // The peer's tcp_input: the FIN.
        self.segment_in(j, t);
        let pj = &mut self.tcb[j];
        if !pj.fin_rcvd {
            pj.fin_rcvd = true;
            // socantrcvmore.
            pj.cantrcv = true;
        }
        match pj.state {
            state::ESTABLISHED => pj.state = state::CLOSE_WAIT,
            state::FIN_WAIT_1 => pj.state = state::CLOSING,
            state::FIN_WAIT_2 => {
                pj.state = state::TIME_WAIT;
                // tcp_canceltimers, add_to_time_wait.
                pj.keep = None;
                pj.msl2 = None;
                if pj.xnu {
                    pj.msl2 = Some(after(t, 2u32.wrapping_mul(sysctl::get(&sysctl::MSL) as u32)));
                }
                self.soisdisconnected(j);
            }
            state::TIME_WAIT => {
                if pj.xnu {
                    pj.msl2 = Some(after(t, 2u32.wrapping_mul(sysctl::get(&sysctl::MSL) as u32)));
                }
            }
            _ => {}
        }
        self.wake(j);
        // Its acknowledgement of the FIN.
        self.advertise(j);
        self.fin_acked(i, t);
    }

    /// End `i`'s FIN is acknowledged (`tcp_input`'s `ourfinisacked`).
    fn fin_acked(&mut self, i: usize, t: Instant) {
        self.segment_in(i, t);
        match self.tcb[i].state {
            state::FIN_WAIT_1 => {
                self.tcb[i].state = state::FIN_WAIT_2;
                if self.tcb[i].cantrcv {
                    if self.tcb[i].xnu {
                        self.tcb[i].set_finwait_timeout(t);
                    }
                    self.soisdisconnected(i);
                }
            }
            state::CLOSING => {
                let e = &mut self.tcb[i];
                e.state = state::TIME_WAIT;
                e.keep = None;
                e.msl2 = None;
                if e.xnu {
                    e.msl2 = Some(after(t, 2u32.wrapping_mul(sysctl::get(&sysctl::MSL) as u32)));
                }
                self.soisdisconnected(i);
            }
            state::LAST_ACK => {
                if self.tcb[i].xnu {
                    self.tcp_close(i);
                } else {
                    // Linux's LAST_ACK: the end is over, its socket left
                    // as disconnected.
                    self.soisdisconnected(i);
                }
            }
            _ => {}
        }
        self.wake(i);
    }

    /// `tcp_usrclosed`, then `tcp_output`'s FIN.
    fn usrclosed(&mut self, i: usize, t: Instant) {
        match self.tcb[i].state {
            state::ESTABLISHED => self.tcb[i].state = state::FIN_WAIT_1,
            state::CLOSE_WAIT => self.tcb[i].state = state::LAST_ACK,
            _ => {}
        }
        if self.tcb[i].state >= state::FIN_WAIT_2 {
            self.soisdisconnected(i);
            if self.tcb[i].state == state::FIN_WAIT_2 && self.tcb[i].xnu {
                self.tcb[i].set_finwait_timeout(t);
            }
        }
        if matches!(self.tcb[i].state, state::FIN_WAIT_1 | state::CLOSING | state::LAST_ACK) {
            self.send_fin(i, t);
        }
    }

    /// `tcp_disconnect`: unread data drops the connection (a reset);
    /// otherwise `soisdisconnecting`, the receive buffer flushed, and
    /// `tcp_usrclosed`.
    fn tcp_disconnect(&mut self, i: usize, t: Instant) {
        if self.tcb[i].dead {
            return;
        }
        if !self.rcv[i].data.is_empty() {
            self.tcp_drop(i, None, t);
            return;
        }
        let e = &mut self.tcb[i];
        e.cantrcv = true;
        e.cantsend = true;
        self.usrclosed(i, t);
        self.wake(i);
    }

    /// The timer of end `i` that is due first, at or before `now`, across
    /// both ends.
    fn due(&self, now: Instant) -> Option<(usize, Timer, Instant)> {
        let mut best: Option<(usize, Timer, Instant)> = None;
        for i in 0..2 {
            // TCPT_KEEP before TCPT_2MSL at one instant (`tcp_run_conn_timer`
            // runs them in index order).
            for (kind, at) in [(Timer::Keep, self.tcb[i].keep), (Timer::Msl2, self.tcb[i].msl2)] {
                if let Some(at) = at {
                    if at <= now && best.map_or(true, |b| at < b.2) {
                        best = Some((i, kind, at));
                    }
                }
            }
        }
        best
    }

    /// Run every timer due by `now`, each at its deadline.
    fn advance(&mut self, now: Instant) {
        while let Some((i, kind, t)) = self.due(now) {
            match kind {
                Timer::Keep => {
                    self.tcb[i].keep = None;
                    self.keep_timer(i, t);
                }
                Timer::Msl2 => {
                    self.tcb[i].msl2 = None;
                    self.msl2_timer(i, t);
                }
            }
        }
    }

    /// `tcp_timers`' TCPT_KEEP.
    fn keep_timer(&mut self, i: usize, t: Instant) {
        let e = &self.tcb[i];
        if e.state < state::ESTABLISHED {
            self.dropit(i, t);
            return;
        }
        let keepalive = sysctl::get(&sysctl::ALWAYS_KEEPALIVE) != 0 || e.opts.keepalive;
        if keepalive && (e.state <= state::CLOSING || e.state == state::FIN_WAIT_2) {
            // idle_time >= TCP_CONN_KEEPIDLE + TCP_CONN_MAXIDLE, compared
            // as uint32_t.
            let idle = t.saturating_duration_since(e.rcvtime).as_millis().min(u128::from(u32::MAX)) as u32;
            if idle >= e.conn_keepidle().wrapping_add(e.conn_maxidle()) {
                self.dropit(i, t);
                return;
            }
            let intvl = e.conn_keepintvl();
            self.tcb[i].keep = Some(after(t, intvl));
            self.keep_probe(i, t);
        } else {
            let idle = e.conn_keepidle();
            self.tcb[i].keep = Some(after(t, idle));
        }
    }

    /// `tcp_send_keep_alive`: a segment one before what the peer has
    /// acknowledged, which the peer takes as a duplicate (`todrop` of 1:
    /// SO_FILT_HINT_KEEPALIVE) and acknowledges; a peer with no PCB
    /// resets.
    fn keep_probe(&mut self, i: usize, t: Instant) {
        let j = 1 - i;
        if self.tcb[j].dead {
            self.rst_to(i, t);
            return;
        }
        self.segment_in(j, t);
        self.tcb[j].keepalives += 1;
        self.wake(j);
        self.advertise(j);
        self.segment_in(i, t);
    }

    /// `tcp_timers`' `dropit`: SO_FILT_HINT_TIMEOUT, then `tcp_drop`
    /// with ETIMEDOUT (no `t_softerror` here).
    fn dropit(&mut self, i: usize, t: Instant) {
        self.tcb[i].timeouts += 1;
        self.tcp_drop(i, Some(Errno::ETIMEDOUT), t);
    }

    /// `tcp_timers`' TCPT_2MSL.
    fn msl2_timer(&mut self, i: usize, t: Instant) {
        let e = &self.tcb[i];
        let idle = t.saturating_duration_since(e.rcvtime).as_millis().min(i32::MAX as u128) as u32;
        if e.state != state::TIME_WAIT && e.state != state::FIN_WAIT_2 && idle > 0 && idle < e.conn_maxidle() {
            let intvl = e.conn_keepintvl();
            self.tcb[i].msl2 = Some(after(t, intvl));
        } else if e.state == state::FIN_WAIT_2 {
            self.tcp_drop(i, None, t);
        } else {
            self.tcp_close(i);
        }
    }
}

/// One end of a TCP connection between two sockets this kernel holds.
#[derive(Debug)]
pub struct LoopEnd {
    conn: Arc<Mutex<Conn>>,
    me: usize,
}

impl LoopEnd {
    /// A connection, established at both ends.
    pub fn pair() -> (Arc<LoopEnd>, Arc<LoopEnd>) {
        let now = Instant::now();
        let conn = Arc::new(Mutex::new(Conn { rcv: Default::default(), tcb: [Tcb::new(now), Tcb::new(now)], wake: [false; 2], urgent: [false; 2] }));
        (Arc::new(LoopEnd { conn: Arc::clone(&conn), me: 0 }), Arc::new(LoopEnd { conn, me: 1 }))
    }

    /// The connection, its timers run up to now.
    fn lock(&self) -> Guard<'_> {
        self.lock_at(Instant::now())
    }

    fn lock_at(&self, now: Instant) -> Guard<'_> {
        let mut c = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        c.advance(now);
        Guard { c: Some(c) }
    }

    /// This end as a Darwin socket's: XNU's TCP with the socket's
    /// options, its keepalive timer armed as at the connection's
    /// establishment (TCP_CONN_KEEPIDLE).
    pub fn set_xnu(&self, opts: TcpOpts) {
        let mut g = self.lock();
        let i = self.me;
        let e = &mut g.c().tcb[i];
        e.xnu = true;
        e.opts = opts;
        e.adv_room = opts.rcv_hiwat;
        if e.have_established() && !e.dead {
            let at = e.rcvtime;
            e.keepalive_reset(at);
        }
    }

    /// Run the timers due by `now` and say when the next one is due:
    /// the connection's, either end's.
    pub fn next_deadline(&self) -> Option<Instant> {
        let mut g = self.lock();
        let c = g.c();
        match (c.tcb[0].next(), c.tcb[1].next()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Run the timers due by `at` (a test's clock).
    #[cfg(test)]
    fn advance_to(&self, at: Instant) {
        drop(self.lock_at(at));
    }

    /// `soreceive`'s read of the buffer (a peek leaves it).
    fn read(&self, buf: &mut [u8], peek: bool) -> Result<usize, Errno> {
        let now = Instant::now();
        let mut g = self.lock_at(now);
        let i = self.me;
        let c = g.c();
        if c.rcv[i].data.is_empty() {
            // so_error ahead of the end of the stream; a peek leaves it.
            if let Some(e) = c.tcb[i].so_error {
                if !peek {
                    c.tcb[i].so_error = None;
                }
                return Err(e);
            }
            return if c.tcb[i].cantrcv { Ok(0) } else { Err(Errno::EAGAIN) };
        }
        // soreceive stops at the urgent mark, and is at it once there.
        let rb = &mut c.rcv[i];
        let mut n = buf.len().min(rb.data.len());
        if rb.oobmark != 0 {
            n = n.min(rb.oobmark);
        }
        rb.atmark = false;
        if peek {
            for (d, s) in buf.iter_mut().zip(rb.data.iter()) {
                *d = *s;
            }
            return Ok(n);
        }
        for (d, s) in buf.iter_mut().zip(rb.data.drain(..n)) {
            *d = s;
        }
        if rb.oobmark != 0 {
            rb.oobmark -= n;
            if rb.oobmark == 0 {
                rb.atmark = true;
            }
        }
        // pru_rcvd: tcp_output, and the window it may now say.
        if n != 0 {
            c.window_update(i, now);
        }
        Ok(n)
    }

    /// A send of `data` (`sosend`, `tcp_usr_send`): its checks, then the
    /// bytes to the peer.
    fn write(&self, data: &[u8], urgent: bool) -> Result<usize, Errno> {
        let now = Instant::now();
        let mut g = self.lock_at(now);
        let i = self.me;
        let c = g.c();
        // sosendcheck: SS_CANTSENDMORE, then so_error.
        if c.tcb[i].cantsend {
            return Err(Errno::EPIPE);
        }
        if let Some(e) = c.tcb[i].so_error.take() {
            return Err(e);
        }
        let room = LOOP_BUF_MAX.saturating_sub(c.rcv[1 - i].data.len());
        if urgent && room == 0 {
            // sbspace of the send buffer: none, no urgent data squeezed in.
            return Err(Errno::ENOBUFS);
        }
        let n = data.len().min(room);
        if n == 0 {
            return if data.is_empty() { Ok(0) } else { Err(Errno::EAGAIN) };
        }
        c.deliver(i, &data[..n], urgent, now);
        Ok(n)
    }
}

/// The connection locked; its owners woken once it is let go.
struct Guard<'a> {
    c: Option<MutexGuard<'a, Conn>>,
}

impl Guard<'_> {
    fn c(&mut self) -> &mut Conn {
        self.c.as_mut().expect("held")
    }
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        let Some(mut c) = self.c.take() else { return };
        let wake = std::mem::take(&mut c.wake);
        let urgent = std::mem::take(&mut c.urgent);
        let owners = [c.tcb[0].owner.clone(), c.tcb[1].owner.clone()];
        drop(c);
        for i in 0..2 {
            if let Some(o) = owners[i].upgrade() {
                if urgent[i] {
                    o.urgent();
                }
                if wake[i] {
                    o.wakeup();
                }
            }
        }
    }
}

impl Transport for LoopEnd {
    fn connect(&self, _host: &str, _port: u16) -> Result<(), Errno> {
        Ok(())
    }

    /// Closed once this end can receive no more (the peer's FIN, its own
    /// shut reading, a reset, its close): reading is then an answer.
    fn status(&self) -> Status {
        let mut g = self.lock();
        let e = &g.c().tcb[self.me];
        if e.cantrcv || e.dead {
            Status::Closed
        } else {
            Status::Open
        }
    }

    fn send(&self, data: &[u8]) -> Result<usize, Errno> {
        self.write(data, false)
    }

    fn recv(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        self.read(buf, false)
    }

    fn has_data(&self) -> bool {
        let mut g = self.lock();
        let i = self.me;
        let c = g.c();
        !c.rcv[i].data.is_empty() || c.tcb[i].cantrcv || c.tcb[i].so_error.is_some()
    }

    fn available(&self) -> usize {
        let mut g = self.lock();
        g.c().rcv[self.me].data.len()
    }

    /// The last descriptor closed (`soclose`): a Darwin end's
    /// `tcp_disconnect` (`sodisconnectlocked`, then `pru_detach`'s), its
    /// socket gone (SS_NOFDREF); a Linux end's FIN.
    fn close(&self) {
        let now = Instant::now();
        let mut g = self.lock_at(now);
        let i = self.me;
        let c = g.c();
        if c.tcb[i].xnu {
            c.tcp_disconnect(i, now);
            c.tcb[i].nofdref = true;
            return;
        }
        c.tcb[i].nofdref = true;
        c.tcb[i].cantsend = true;
        c.rcv[i].data.clear();
        if !c.tcb[i].dead {
            match c.tcb[i].state {
                state::ESTABLISHED => c.tcb[i].state = state::FIN_WAIT_1,
                state::CLOSE_WAIT => c.tcb[i].state = state::LAST_ACK,
                _ => {}
            }
            if matches!(c.tcb[i].state, state::FIN_WAIT_1 | state::LAST_ACK) {
                c.send_fin(i, now);
            }
        }
        c.wake(1 - i);
    }

    /// A listener closing with this end queued for its `accept`
    /// (`soclose`'s `soabort`): a Darwin end's `tcp_usr_abort`, which is
    /// `tcp_drop` with ECONNABORTED (the peer's reset); a Linux end's
    /// close.
    fn abort(&self) {
        let now = Instant::now();
        let mut g = self.lock_at(now);
        let i = self.me;
        let c = g.c();
        if !c.tcb[i].xnu {
            drop(g);
            self.close();
            return;
        }
        if !c.tcb[i].dead {
            c.tcp_drop(i, Some(Errno::ECONNABORTED), now);
        }
        c.tcb[i].nofdref = true;
    }

    /// SHUT_RD (`sorflush`, of this end alone: the peer is not told) and
    /// SHUT_WR (`tcp_usr_shutdown`: `socantsendmore`, `tcp_usrclosed`, the
    /// FIN).
    fn shutdown(&self, how: u64) -> Result<(), Errno> {
        let now = Instant::now();
        let mut g = self.lock_at(now);
        let i = self.me;
        let c = g.c();
        if how == 0 || how == 2 {
            // A Darwin end's is `sorflush`: what waits thrown away, and
            // SS_CANTRCVMORE. A Linux end's only marks its reading shut.
            let e = &mut c.tcb[i];
            e.rd_first |= !e.fin_sent && !e.rd_shut;
            e.rd_shut = true;
            if e.xnu {
                e.cantrcv = true;
                c.rcv[i].data.clear();
            }
            c.wake(i);
        }
        if how == 1 || how == 2 {
            c.tcb[i].cantsend = true;
            c.wake(i);
            if c.tcb[i].dead {
                return Ok(());
            }
            if c.tcb[i].xnu {
                c.usrclosed(i, now);
            } else {
                match c.tcb[i].state {
                    state::ESTABLISHED => c.tcb[i].state = state::FIN_WAIT_1,
                    state::CLOSE_WAIT => c.tcb[i].state = state::LAST_ACK,
                    _ => {}
                }
                if matches!(c.tcb[i].state, state::FIN_WAIT_1 | state::LAST_ACK) {
                    c.send_fin(i, now);
                }
            }
        }
        Ok(())
    }

    fn send_closed(&self, data: &[u8]) -> Result<usize, Errno> {
        self.send(data)
    }

    /// SS_CANTSENDMORE.
    fn send_over(&self, _closed: bool) -> bool {
        let mut g = self.lock();
        g.c().tcb[self.me].cantsend
    }

    fn peek(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        self.read(buf, true)
    }

    fn tcp_end(&self) -> Option<TcpEnd> {
        let mut g = self.lock();
        let i = self.me;
        let c = g.c();
        let e = &c.tcb[i];
        Some(TcpEnd {
            state: e.state,
            fin_sent: e.fin_sent,
            fin_rcvd: e.fin_rcvd,
            reset: e.resets != 0,
            rd_shut: e.rd_shut,
            rd_shut_first: e.rd_first,
            reset_error: e.so_error == Some(Errno::ECONNRESET),
            error: e.so_error,
            connected: e.connected,
            cantrcv: e.cantrcv,
            cantsend: e.cantsend,
            closed: e.dead,
            disconnects: e.disconnects,
            resets: e.resets,
            timeouts: e.timeouts,
            keepalives: e.keepalives,
        })
    }

    fn take_error(&self) -> Option<Errno> {
        let mut g = self.lock();
        g.c().tcb[self.me].so_error.take()
    }

    fn set_owner(&self, owner: &Arc<SoOwner>) -> bool {
        let mut g = self.lock();
        g.c().tcb[self.me].owner = Arc::downgrade(owner);
        true
    }

    /// The data goes as a send's; its segment carries the urgent pointer
    /// after its last byte (`snd_up`), which the peer's `tcp_input` takes:
    /// the mark before that byte (`so_oobmark`), SIGURG and NOTE_OOB
    /// (`sohasoutofband`), and the byte pulled out of the stream into
    /// `t_iobc` unless the peer has SO_OOBINLINE (`tcp_pulloutofband`).
    fn send_oob(&self, data: &[u8]) -> Option<Result<usize, Errno>> {
        Some(self.write(data, true))
    }

    fn recv_oob(&self, peek: bool) -> Option<Result<u8, Errno>> {
        let mut g = self.lock();
        let rb = &mut g.c().rcv[self.me];
        if (rb.oobmark == 0 && !rb.atmark) || rb.oobinline || rb.oobflags & TCPOOB_HADDATA != 0 {
            return Some(Err(Errno::EINVAL));
        }
        if rb.oobflags & TCPOOB_HAVEDATA == 0 {
            return Some(Err(Errno::EAGAIN));
        }
        let b = rb.iobc;
        rb.atmark = false;
        if !peek {
            rb.oobflags ^= TCPOOB_HAVEDATA | TCPOOB_HADDATA;
        }
        Some(Ok(b))
    }

    fn set_oobinline(&self, on: bool) -> bool {
        let mut g = self.lock();
        g.c().rcv[self.me].oobinline = on;
        true
    }

    fn sorflush(&self) -> bool {
        self.shutdown(0).expect("SHUT_RD");
        true
    }

    fn oob_state(&self) -> Option<(u64, bool)> {
        let mut g = self.lock();
        let rb = &g.c().rcv[self.me];
        Some((rb.oobmark as u64, rb.atmark))
    }

    fn tcp_opts(&self, opts: TcpOpts, change: OptChange) -> bool {
        let now = Instant::now();
        let mut g = self.lock_at(now);
        let e = &mut g.c().tcb[self.me];
        if !e.xnu {
            return false;
        }
        e.opts = opts;
        if e.dead {
            return true;
        }
        match change {
            OptChange::Kept => {}
            // tcp_ctloutput's TCP_KEEPALIVE: TCPT_KEEP from now.
            OptChange::KeepIdle if e.have_established() => e.keepalive_reset(now),
            OptChange::KeepIdle => {}
            // TCP_KEEPINTVL, TCP_KEEPCNT: FIN_WAIT_2's TCPT_2MSL from now.
            OptChange::KeepIntvlOrCnt => {
                if e.state == state::FIN_WAIT_2 && e.conn_maxidle() > 0 {
                    e.msl2 = Some(after(now, e.conn_maxidle()));
                }
            }
        }
        true
    }

    fn next_deadline(&self) -> Option<Instant> {
        LoopEnd::next_deadline(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xnu_pair(opts: TcpOpts) -> (Arc<LoopEnd>, Arc<LoopEnd>) {
        let (a, b) = LoopEnd::pair();
        a.set_xnu(opts);
        b.set_xnu(opts);
        (a, b)
    }

    fn ms(t: Instant, n: u64) -> Instant {
        t + Duration::from_millis(n)
    }

    #[test]
    fn a_write_after_the_peer_closed_meets_its_reset() {
        let (a, b) = xnu_pair(TcpOpts::default());
        b.close();
        let e = a.tcp_end().unwrap();
        assert!(e.fin_rcvd && e.connected && e.state == state::CLOSE_WAIT, "the peer's FIN alone: CLOSE_WAIT");
        assert_eq!(a.send(b"x").unwrap(), 1, "the write is taken");
        let e = a.tcp_end().unwrap();
        assert!(e.reset && e.reset_error && e.closed && !e.connected);
        let mut buf = [0u8; 4];
        assert_eq!(a.peek(&mut buf), Err(Errno::ECONNRESET), "a peek reads the error and leaves it");
        assert_eq!(a.recv(&mut buf), Err(Errno::ECONNRESET));
        assert_eq!(a.recv(&mut buf), Ok(0), "then the end of file");
        assert_eq!(a.take_error(), None);
        assert_eq!(a.send(b"x"), Err(Errno::EPIPE));
    }

    #[test]
    fn a_closed_listener_resets_what_it_had_queued() {
        let (a, b) = xnu_pair(TcpOpts::default());
        b.abort();
        let (ea, eb) = (a.tcp_end().unwrap(), b.tcp_end().unwrap());
        assert!(eb.closed && eb.error == Some(Errno::ECONNABORTED));
        assert!(ea.closed && ea.error == Some(Errno::ECONNRESET) && ea.resets == 1);
    }

    #[test]
    fn data_after_shut_rd_closes_and_resets() {
        let (a, b) = xnu_pair(TcpOpts::default());
        b.shutdown(0).unwrap();
        assert_eq!(a.send(b"x"), Ok(1));
        let (ea, eb) = (a.tcp_end().unwrap(), b.tcp_end().unwrap());
        assert!(eb.closed && eb.error.is_none() && eb.disconnects == 1, "tcp_close, no error");
        assert!(ea.closed && ea.error == Some(Errno::ECONNRESET) && ea.resets == 1);
    }

    #[test]
    fn closing_with_unread_data_resets_the_peer() {
        let (a, b) = xnu_pair(TcpOpts::default());
        a.send(b"left").unwrap();
        b.close();
        let e = a.tcp_end().unwrap();
        assert!(e.closed && e.error == Some(Errno::ECONNRESET), "tcp_disconnect's tcp_drop");
    }

    #[test]
    fn both_fins_or_a_fin_after_shut_rd_disconnect() {
        let (a, b) = xnu_pair(TcpOpts::default());
        a.shutdown(1).unwrap();
        let e = a.tcp_end().unwrap();
        assert!(e.connected && e.state == state::FIN_WAIT_2, "FIN_WAIT_2");
        b.shutdown(1).unwrap();
        let (ea, eb) = (a.tcp_end().unwrap(), b.tcp_end().unwrap());
        assert!(!ea.connected && ea.state == state::TIME_WAIT && !ea.closed);
        assert!(!eb.connected && eb.closed, "LAST_ACK's tcp_close");
        let (c, _d) = xnu_pair(TcpOpts::default());
        c.shutdown(2).unwrap();
        let e = c.tcp_end().unwrap();
        assert!(e.rd_shut && e.rd_shut_first && !e.connected, "SHUT_RDWR flushes the reading first");
        let (f, _g) = xnu_pair(TcpOpts::default());
        f.shutdown(1).unwrap();
        f.shutdown(0).unwrap();
        let e = f.tcp_end().unwrap();
        assert!(e.rd_shut && !e.rd_shut_first && e.connected, "SHUT_RD after the FIN was acknowledged");
    }

    #[test]
    fn time_wait_ends_after_twice_the_msl() {
        let (a, b) = xnu_pair(TcpOpts::default());
        let t0 = Instant::now();
        a.shutdown(1).unwrap();
        b.shutdown(1).unwrap();
        let msl = sysctl::get(&sysctl::MSL) as u64;
        a.advance_to(ms(t0, 2 * msl - 50));
        assert!(!a.tcp_end().unwrap().closed);
        a.advance_to(ms(t0, 2 * msl + 1000));
        let e = a.tcp_end().unwrap();
        assert!(e.closed && e.disconnects == 2, "tcp_close's soisdisconnected again");
    }

    #[test]
    fn fin_wait_2_with_nothing_more_to_read_times_out() {
        // TCP_KEEPINTVL 1s, TCP_KEEPCNT 2: TCP_CONN_MAXIDLE (2s) is under
        // tcp_fin_timeout, and is the timeout.
        let o = TcpOpts { keepintvl: 1000, keepcnt: 2, ..TcpOpts::default() };
        let (a, b) = xnu_pair(o);
        let t0 = Instant::now();
        a.shutdown(0).unwrap();
        a.shutdown(1).unwrap();
        let e = a.tcp_end().unwrap();
        assert!(e.state == state::FIN_WAIT_2 && !e.connected);
        a.advance_to(ms(t0, 1500));
        assert!(!a.tcp_end().unwrap().closed);
        a.advance_to(ms(t0, 2500));
        let (ea, eb) = (a.tcp_end().unwrap(), b.tcp_end().unwrap());
        assert!(ea.closed && ea.error.is_none() && ea.timeouts == 0, "tcp_drop(tp, 0)");
        assert!(eb.closed && eb.error == Some(Errno::ECONNRESET) && eb.resets == 1, "its reset at the peer in CLOSE_WAIT");
    }

    #[test]
    fn an_orphan_in_fin_wait_2_resets_its_peer_after_the_timeout() {
        let (a, b) = xnu_pair(TcpOpts::default());
        let t0 = Instant::now();
        b.close();
        let fin = sysctl::get(&sysctl::FIN_TIMEOUT) as u64;
        a.advance_to(ms(t0, fin - 100));
        assert!(!a.tcp_end().unwrap().closed);
        a.advance_to(ms(t0, fin + 100));
        let e = a.tcp_end().unwrap();
        assert!(e.closed && e.error == Some(Errno::ECONNRESET));
    }

    #[test]
    fn keepalive_probes_keep_an_idle_connection_and_tell_the_peer() {
        let o = TcpOpts { keepalive: true, keepidle: 2000, keepintvl: 1000, keepcnt: 2, ..TcpOpts::default() };
        let (a, b) = LoopEnd::pair();
        a.set_xnu(o);
        b.set_xnu(TcpOpts::default());
        let t0 = Instant::now();
        a.advance_to(ms(t0, 1900));
        assert_eq!(b.tcp_end().unwrap().keepalives, 0);
        a.advance_to(ms(t0, 2100));
        assert_eq!(b.tcp_end().unwrap().keepalives, 1, "the first probe after the idle time");
        // The peer's acknowledgement put the timer back to the idle time.
        a.advance_to(ms(t0, 4300));
        assert_eq!(b.tcp_end().unwrap().keepalives, 2);
        a.advance_to(ms(t0, 60_000));
        let (ea, eb) = (a.tcp_end().unwrap(), b.tcp_end().unwrap());
        assert!(ea.connected && ea.timeouts == 0 && eb.keepalives >= 29);
        // Data resets the idle time.
        let t1 = Instant::now();
        let before = b.tcp_end().unwrap().keepalives;
        b.send(b"x").unwrap();
        a.advance_to(ms(t1, 1500));
        assert_eq!(b.tcp_end().unwrap().keepalives, before);
    }

    #[test]
    fn keepalive_without_so_keepalive_sends_nothing() {
        let o = TcpOpts { keepalive: false, keepidle: 1000, ..TcpOpts::default() };
        let (a, b) = xnu_pair(o);
        a.advance_to(Instant::now() + Duration::from_secs(10_000));
        assert_eq!(b.tcp_end().unwrap().keepalives, 0);
        assert!(a.tcp_end().unwrap().connected);
    }

    #[test]
    fn unanswered_probes_drop_with_etimedout() {
        // A peer whose PCB went without a word cannot happen on loopback;
        // the drop's own path, as tcp_timers takes it when the idle time
        // has passed the probes.
        let o = TcpOpts { keepalive: true, keepidle: 1000, keepintvl: 1000, keepcnt: 2, ..TcpOpts::default() };
        let (a, b) = xnu_pair(o);
        let t0 = Instant::now();
        {
            let mut c = a.conn.lock().unwrap();
            c.tcb[0].keep = Some(ms(t0, 3000));
            c.tcb[0].rcvtime = t0;
            c.tcb[1].keep = None;
        }
        a.advance_to(ms(t0, 3001));
        let (ea, eb) = (a.tcp_end().unwrap(), b.tcp_end().unwrap());
        assert!(ea.closed && ea.timeouts == 1 && ea.error == Some(Errno::ETIMEDOUT));
        assert!(eb.closed && eb.error == Some(Errno::ECONNRESET), "the drop's reset");
    }

    #[test]
    fn a_large_read_sends_a_window_update_and_a_small_one_does_not() {
        let o = TcpOpts { keepalive: true, keepidle: 10_000, ..TcpOpts::default() };
        let (a, b) = xnu_pair(o);
        let t0 = Instant::now();
        a.send(&vec![0u8; 100]).unwrap();
        let rcv = a.conn.lock().unwrap().tcb[0].rcvtime;
        let mut buf = vec![0u8; 100_000];
        assert_eq!(b.recv(&mut buf), Ok(100));
        assert_eq!(a.conn.lock().unwrap().tcb[0].rcvtime, rcv, "100 bytes open no window worth saying");
        a.send(&vec![0u8; 3 * LO_MAXSEG as usize]).unwrap();
        let rcv = a.conn.lock().unwrap().tcb[0].rcvtime;
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(b.recv(&mut buf), Ok(3 * LO_MAXSEG as usize));
        assert!(a.conn.lock().unwrap().tcb[0].rcvtime > rcv, "two segments' worth drained: the update");
        let _ = t0;
    }

    #[test]
    fn tcp_keepalive_rearms_from_now() {
        let o = TcpOpts { keepalive: true, ..TcpOpts::default() };
        let (a, b) = xnu_pair(o);
        let o2 = TcpOpts { keepidle: 1000, ..o };
        a.tcp_opts(o2, OptChange::KeepIdle);
        a.advance_to(Instant::now() + Duration::from_millis(1100));
        assert_eq!(b.tcp_end().unwrap().keepalives, 1);
    }

    #[test]
    fn urgent_data_marks_the_stream_before_its_last_byte() {
        let (a, b) = xnu_pair(TcpOpts::default());
        a.send(b"ab").unwrap();
        assert_eq!(a.send_oob(b"XY"), Some(Ok(2)));
        assert_eq!(b.oob_state(), Some((3, false)), "the mark after a, b and X");
        assert_eq!(b.recv_oob(true), Some(Ok(b'Y')));
        assert_eq!(b.recv_oob(false), Some(Ok(b'Y')));
        assert_eq!(b.recv_oob(false), Some(Err(Errno::EINVAL)), "TCPOOB_HADDATA");
        let mut buf = [0u8; 8];
        assert_eq!(b.recv(&mut buf), Ok(3));
        assert_eq!(&buf[..3], b"abX");
        assert_eq!(b.oob_state(), Some((0, true)), "at the mark");
        a.send(b"z").unwrap();
        assert_eq!(b.recv(&mut buf), Ok(1));
        assert_eq!(b.oob_state(), Some((0, false)));
        b.set_oobinline(true);
        a.send_oob(b"Q").unwrap().unwrap();
        assert_eq!(b.oob_state(), Some((0, true)));
        assert_eq!(b.recv_oob(false), Some(Err(Errno::EINVAL)));
        assert_eq!(b.recv(&mut buf), Ok(1));
        assert_eq!(buf[0], b'Q');
    }
}
