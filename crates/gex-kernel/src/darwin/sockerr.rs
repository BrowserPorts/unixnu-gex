//! What the socket layer refuses before a protocol is asked: `solisten`,
//! `accept_nocancel`, `soconnectlock`, `sosend`, `soreceive` and
//! `soconnect2`, in the error each gives.

use super::bsd::sys;
use super::errno::EOPNOTSUPP;
use crate::errno::Errno;
use crate::net;
use crate::syscalls::Kernel;
use crate::vfs::FileHandle;
use crate::GuestMem;
use std::sync::Arc;

const MSG_OOB: u64 = 1;
const AF_INET: u64 = 2;
const SOCK_STREAM: u64 = 1;
const SOCK_DGRAM: u64 = 2;
const IPPROTO_TCP: u64 = 6;
const IPPROTO_UDP: u64 = 17;

/// A socket's protocol, as far as these checks need it.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Proto {
    UnixStream,
    Tcp,
    /// No connections (`PR_CONNREQUIRED` clear), and no out-of-band data.
    Datagram,
}

impl Kernel {
    pub(crate) fn darwin_sock_proto(&self, fd: i32) -> Option<Proto> {
        let io = self.fd_io();
        if io.dgram_of(fd).is_ok() {
            return Some(Proto::Datagram);
        }
        if io.unix_of(fd).is_ok() || io.remote_unix_of(fd).is_ok() {
            return Some(Proto::UnixStream);
        }
        if let Some(s) = self.darwin_inet6_of(fd) {
            return Some(if s.proto == super::inet6::Proto::Udp { Proto::Datagram } else { Proto::Tcp });
        }
        let s = io.socket_of(fd).ok()?;
        Some(if s.kind == net::Kind::Udp { Proto::Datagram } else { Proto::Tcp })
    }

    /// The error, if this socket call is one that is refused here.
    pub(crate) fn darwin_sock_refused(&mut self, raw: u64, a: &[u64; 6]) -> Option<Errno> {
        // pru_connect2_notsupp, once the two sockets exist.
        if raw == sys::SOCKETPAIR {
            let made = matches!((a[1] as u32 as u64, a[2] as u32 as u64), (SOCK_STREAM, 0 | IPPROTO_TCP) | (SOCK_DGRAM, 0 | IPPROTO_UDP));
            return (a[0] as u32 as u64 == AF_INET && made).then_some(EOPNOTSUPP);
        }
        let (send, flags) = match raw {
            sys::SENDTO | sys::SENDTO_NOCANCEL => (true, a[3]),
            sys::SENDMSG | sys::SENDMSG_NOCANCEL => (true, a[2]),
            sys::RECVFROM | sys::RECVFROM_NOCANCEL => (false, a[3]),
            sys::RECVMSG | sys::RECVMSG_NOCANCEL => (false, a[2]),
            sys::LISTEN | sys::ACCEPT | sys::ACCEPT_NOCANCEL | sys::CONNECT | sys::CONNECT_NOCANCEL => (false, 0),
            _ => return None,
        };
        let fd = a[0] as i32;
        let proto = self.darwin_sock_proto(fd)?;
        let state = self.fds.get(fd).ok()?.handle.so_state()?;
        let listening = state.qlen.is_some();
        match raw {
            sys::LISTEN => (proto == Proto::Datagram).then_some(EOPNOTSUPP),
            sys::ACCEPT | sys::ACCEPT_NOCANCEL => match (proto, listening) {
                (Proto::Datagram, _) => Some(EOPNOTSUPP),
                (_, false) => Some(Errno::EINVAL),
                _ => None,
            },
            sys::CONNECT | sys::CONNECT_NOCANCEL => listening.then_some(EOPNOTSUPP),
            _ if flags & MSG_OOB == 0 => None,
            _ => match (proto, send) {
                // sosend, before it looks at the socket's state.
                (Proto::Datagram, true) => Some(EOPNOTSUPP),
                // uipc_send, for what sosendcheck lets through.
                (Proto::UnixStream, true) => (!state.cantsend && state.can_write).then_some(EOPNOTSUPP),
                // pru_rcvoob_notsupp.
                (Proto::Datagram | Proto::UnixStream, false) => Some(EOPNOTSUPP),
                // Urgent data on a connection between two sockets here
                // (darwin_tcp_oob); a connection the host or the global
                // kernel carries has no urgent pointer here.
                (Proto::Tcp, _) if self.fds.get(fd).ok().and_then(|f| Arc::clone(&f.handle).as_inet_socket()).is_some_and(|s| s.urgent_followed()) => None,
                (Proto::Tcp, _) => {
                    self.darwin_unimplemented("MSG_OOB on a TCP connection the host or the global kernel carries (no urgent pointer reaches it here)".into());
                    Some(Errno::EINVAL)
                }
            },
        }
    }
}

impl Kernel {
    /// MSG_OOB on a TCP socket whose connection is this kernel's:
    /// `sosend` to `tcp_usr_send` with PRUS_OOB, and `soreceive`'s
    /// `pru_rcvoob` (`tcp_usr_rcvoob`), for `sendto` and `recvfrom`; `None`
    /// for anything else, which goes on as it would.
    pub(crate) fn darwin_tcp_oob(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &[u64; 6]) -> Option<Result<u64, Errno>> {
        const MSG_PEEK: u64 = 0x2;
        let flags = match raw {
            sys::SENDTO | sys::SENDTO_NOCANCEL | sys::RECVFROM | sys::RECVFROM_NOCANCEL => a[3],
            sys::SENDMSG | sys::SENDMSG_NOCANCEL | sys::RECVMSG | sys::RECVMSG_NOCANCEL => a[2],
            _ => return None,
        };
        if flags & MSG_OOB == 0 || self.darwin_sock_proto(a[0] as i32) != Some(Proto::Tcp) {
            return None;
        }
        let s = Arc::clone(&self.fds.get(a[0] as i32).ok()?.handle).as_inet_socket()?;
        match raw {
            sys::SENDMSG | sys::SENDMSG_NOCANCEL | sys::RECVMSG | sys::RECVMSG_NOCANCEL => {
                // The user_msghdr_x of a 64-bit process: name, namelen, iov,
                // iovlen, control, controllen, flags; its iovecs base, len.
                const UIO_MAXIOV: u32 = 1024;
                let send = matches!(raw, sys::SENDMSG | sys::SENDMSG_NOCANCEL);
                let hdr = match m.read(a[1], 48) {
                    Ok(b) => b.to_vec(),
                    Err(e) => return Some(Err(e)),
                };
                let u64at = |o: usize| u64::from_le_bytes(hdr[o..o + 8].try_into().unwrap());
                let u32at = |o: usize| u32::from_le_bytes(hdr[o..o + 4].try_into().unwrap());
                let (name, iov, iovlen, control, controllen) = (u64at(0), u64at(16), u32at(24) as i32, u64at(32), u32at(40));
                if iovlen <= 0 || iovlen as u32 > UIO_MAXIOV {
                    return Some(Err(Errno::EMSGSIZE));
                }
                let vecs = match m.read(iov, iovlen as usize * 16) {
                    Ok(b) => b.chunks_exact(16).map(|c| (u64::from_le_bytes(c[..8].try_into().unwrap()), u64::from_le_bytes(c[8..].try_into().unwrap()))).collect::<Vec<_>>(),
                    Err(e) => return Some(Err(e)),
                };
                if vecs.iter().try_fold(0u64, |t, &(_, l)| t.checked_add(l).filter(|&t| t <= i32::MAX as u64)).is_none() {
                    return Some(Err(Errno::EINVAL));
                }
                if send {
                    if control != 0 && controllen != 0 {
                        self.darwin_unimplemented("control with MSG_OOB on a TCP socket (sockargs and tcp_usr_send's disposal of it)".into());
                        return Some(Err(Errno::EOPNOTSUPP));
                    }
                    let st = s.so_state()?;
                    if st.cantsend || st.error != 0 || !st.conn.connected {
                        return None;
                    }
                    let mut data = Vec::new();
                    for &(base, len) in &vecs {
                        match m.read(base, len as usize) {
                            Ok(b) => data.extend_from_slice(b),
                            Err(e) => return Some(Err(e)),
                        }
                    }
                    return Some(s.send_oob(&data)?.map(|n| n as u64));
                }
                let b = match s.recv_oob(flags & MSG_PEEK != 0)? {
                    Ok(b) => b,
                    Err(e) => return Some(Err(e)),
                };
                // uiomove of the one byte into the first iovec with room.
                let mut n = 0;
                if let Some(&(base, _)) = vecs.iter().find(|&&(_, l)| l > 0) {
                    if let Err(e) = m.write(base, &[b]) {
                        return Some(Err(e));
                    }
                    n = 1;
                }
                // recvit: no address (copyout_sa's length 0), no control,
                // the flags as given; the header copied back.
                let mut out = hdr.clone();
                if name != 0 {
                    out[8..12].copy_from_slice(&0u32.to_le_bytes());
                }
                if control != 0 {
                    out[40..44].copy_from_slice(&0u32.to_le_bytes());
                }
                out[44..48].copy_from_slice(&(flags as u32).to_le_bytes());
                if let Err(e) = m.write(a[1], &out) {
                    return Some(Err(e));
                }
                Some(Ok(n))
            }
            sys::SENDTO | sys::SENDTO_NOCANCEL => {
                // sosendcheck's refusals (a shut down or failed or
                // unconnected socket) are the ordinary send's.
                let st = s.so_state()?;
                if st.cantsend || st.error != 0 || !st.conn.connected {
                    return None;
                }
                let data = match m.read(a[1], a[2] as usize) {
                    Ok(b) => b.to_vec(),
                    Err(e) => return Some(Err(e)),
                };
                Some(s.send_oob(&data)?.map(|n| n as u64))
            }
            _ => {
                let b = match s.recv_oob(flags & MSG_PEEK != 0)? {
                    Ok(b) => b,
                    Err(e) => return Some(Err(e)),
                };
                // One byte, as much of it as the buffer takes.
                let n = a[2].min(1);
                if n != 0 {
                    if let Err(e) = m.write(a[1], &[b]) {
                        return Some(Err(e));
                    }
                }
                // No address: a length of 0, where one was asked for.
                if a[4] != 0 && a[5] != 0 {
                    if let Err(e) = m.write(a[5], &0u32.to_le_bytes()) {
                        return Some(Err(e));
                    }
                }
                Some(Ok(n))
            }
        }
    }
}

impl Kernel {
    /// `shutdown` of a Darwin TCP socket (`soshutdown`,
    /// `soshutdownlock_final`): ENOTCONN unless connected or connecting,
    /// and for a direction already shut; its reading is `sorflush`, which
    /// drops what is buffered and what arrives after. `None` for anything
    /// else.
    pub(crate) fn darwin_tcp_shutdown(&mut self, raw: u64, a: &[u64; 6]) -> Option<Result<u64, Errno>> {
        const SHUT_RD: u64 = 0;
        const SHUT_WR: u64 = 1;
        if raw != sys::SHUTDOWN || self.darwin_sock_proto(a[0] as i32) != Some(Proto::Tcp) {
            return None;
        }
        let s = Arc::clone(&self.fds.get(a[0] as i32).ok()?.handle).as_inet_socket()?;
        let how = a[1] as u32 as u64;
        if how > 2 {
            return Some(Err(Errno::EINVAL));
        }
        let st = s.so_state()?;
        if !st.conn.connected && s.status() != net::Status::Connecting {
            return Some(Err(Errno::ENOTCONN));
        }
        if how != SHUT_WR {
            if st.cantrcv {
                return Some(Err(Errno::ENOTCONN));
            }
            if !s.sorflush() {
                self.darwin_unimplemented("shutdown(SHUT_RD) of a TCP connection the host or the global kernel carries (sorflush's dropping of what arrives)".into());
                return Some(Err(Errno::EOPNOTSUPP));
            }
        }
        if how != SHUT_RD {
            if st.cantsend {
                return Some(Err(Errno::ENOTCONN));
            }
            return Some(s.shutdown(SHUT_WR));
        }
        Some(Ok(0))
    }
}
