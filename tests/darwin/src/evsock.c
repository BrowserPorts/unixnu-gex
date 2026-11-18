// EVFILT_SOCK (filt_sockev): a loopback TCP connection's events -- its
// connect, the peer's close, the reset a write after it meets -- and a
// refused connect; a unix stream pair's shutdown and close and a unix
// connect; the level events delivered once, EV_CLEAR, and a touch that
// drops and restores interest. EVFILT_EXCEPT on a socket (filt_sorattach's
// read filter with NOTE_OOB). A socket's owner (so_pgid) through F_SETOWN,
// FIOSETOWN and SIOCSPGRP, kept as given, and sowakeup's SIGIO to it. TCP
// urgent data on loopback: the mark (SIOCATMARK), the byte read apart with
// MSG_OOB or in line with SO_OOBINLINE, SIGURG to the owner and
// EVFILT_EXCEPT's NOTE_OOB.

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

// bsd/sys/event_private.h
#define EVFILT_SOCK (-13)
#define NOTE_CONNRESET 0x00000001
#define NOTE_READCLOSED 0x00000002
#define NOTE_WRITECLOSED 0x00000004
#define NOTE_TIMEOUT 0x00000008
#define NOTE_RESUME 0x00000080
#define NOTE_CONNECTED 0x00000800
#define NOTE_DISCONNECTED 0x00001000
#define NOTE_CONNINFO_UPDATED 0x00002000
// get_sockev_state
#define SOCKEV_CONNECTED 1
#define SOCKEV_DISCONNECTED 2

#define ALL (NOTE_CONNRESET | NOTE_READCLOSED | NOTE_WRITECLOSED | NOTE_TIMEOUT | NOTE_CONNECTED | NOTE_DISCONNECTED | NOTE_CONNINFO_UPDATED)

static int bad(const char *what, long got, long want) {
    printf("evsock: %s: %#lx, want %#lx\n", what, got, want);
    fflush(stdout);
    return 1;
}

static int add(int kq, int fd, int filter, unsigned flags, unsigned fflags) {
    struct kevent c;
    EV_SET(&c, fd, filter, EV_ADD | flags, fflags, 0, NULL);
    struct timespec z = {0, 0};
    return kevent(kq, &c, 1, NULL, 0, &z);
}

// The next event within `ms` milliseconds: 1, or 0 for none.
static int next(int kq, struct kevent *ev, int ms) {
    struct timespec t = {ms / 1000, (ms % 1000) * 1000000L};
    int n = kevent(kq, NULL, 0, ev, 1, &t);
    return n == 1;
}

static int listener(struct sockaddr_in *in) {
    int l = socket(AF_INET, SOCK_STREAM, 0);
    memset(in, 0, sizeof *in);
    in->sin_len = sizeof *in;
    in->sin_family = AF_INET;
    in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t il = sizeof *in;
    if (bind(l, (struct sockaddr *)in, sizeof *in) || listen(l, 4) || getsockname(l, (struct sockaddr *)in, &il)) return -1;
    return l;
}

static int tcp(void) {
    struct sockaddr_in in;
    struct kevent ev;
    int l = listener(&in);
    if (l < 0) return bad("listen", errno, 0);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    int kq = kqueue();

    // Nothing is connected yet, and NOTE_RESUME was not asked for.
    if (add(kq, c, EVFILT_SOCK, EV_CLEAR, ALL)) return bad("EVFILT_SOCK", errno, 0);
    if (next(kq, &ev, 50)) return bad("an unconnected socket's event", ev.fflags, 0);

    // soisconnected: SO_FILT_HINT_CONNECTED | SO_FILT_HINT_CONNINFO_UPDATED,
    // and TCP has PR_EVCONNINFO.
    if (connect(c, (struct sockaddr *)&in, sizeof in)) return bad("connect", errno, 0);
    if (!next(kq, &ev, 1000)) return bad("the connect's event", 0, 1);
    if (ev.fflags != (NOTE_CONNECTED | NOTE_CONNINFO_UPDATED)) return bad("the connect's fflags", ev.fflags, NOTE_CONNECTED | NOTE_CONNINFO_UPDATED);
    if (ev.data != SOCKEV_CONNECTED || (ev.flags & EV_EOF)) return bad("the connect's data", ev.data, SOCKEV_CONNECTED);
    // NOTE_CONNECTED is level: delivered once.
    if (next(kq, &ev, 50)) return bad("NOTE_CONNECTED again", ev.fflags, 0);

    // The accepted end was presented connected (no hint): its state alone.
    int s = accept(l, NULL, NULL);
    if (s < 0) return bad("accept", errno, 0);
    int kq2 = kqueue();
    if (add(kq2, s, EVFILT_SOCK, EV_CLEAR, ALL)) return bad("EVFILT_SOCK on the accepted end", errno, 0);
    if (!next(kq2, &ev, 1000) || ev.fflags != NOTE_CONNECTED || ev.data != SOCKEV_CONNECTED) return bad("the accepted end's event", ev.fflags, NOTE_CONNECTED);

    // The peer's close: its FIN is socantrcvmore, NOTE_READCLOSED; the
    // connection is still SS_ISCONNECTED (CLOSE_WAIT).
    close(s);
    if (!next(kq, &ev, 1000)) return bad("the peer's close", 0, 1);
    if (ev.fflags != (NOTE_CONNECTED | NOTE_READCLOSED) || ev.data != SOCKEV_CONNECTED) return bad("the peer's close's fflags", ev.fflags, NOTE_CONNECTED | NOTE_READCLOSED);

    // A write after it is taken; the closed peer's reset comes back:
    // NOTE_CONNRESET, then tcp_close's soisdisconnected; so_error is the
    // event's data.
    if (write(c, "x", 1) != 1) return bad("the write after the peer's close", errno, 0);
    if (!next(kq, &ev, 1000)) return bad("the reset", 0, 1);
    unsigned want = NOTE_CONNRESET | NOTE_DISCONNECTED | NOTE_CONNINFO_UPDATED | NOTE_READCLOSED | NOTE_WRITECLOSED;
    if (ev.fflags != want) return bad("the reset's fflags", ev.fflags, want);
    if (!(ev.flags & EV_EOF) || ev.data != ECONNRESET) return bad("the reset's so_error", ev.data, ECONNRESET);

    // The read takes so_error; the state is disconnected.
    char b[4];
    if (read(c, b, sizeof b) != -1 || errno != ECONNRESET) return bad("the read after the reset", errno, ECONNRESET);
    if (read(c, b, sizeof b) != 0) return bad("the read after that", errno, 0);
    int err = -1;
    socklen_t el = sizeof err;
    if (getsockopt(c, SOL_SOCKET, SO_ERROR, &err, &el) || err != 0) return bad("SO_ERROR after the read", err, 0);
    if (next(kq, &ev, 50)) return bad("an event after the reset", ev.fflags, 0);

    // A new knote: the level events, and the disconnected state as data.
    close(kq);
    kq = kqueue();
    if (add(kq, c, EVFILT_SOCK, 0, ALL)) return bad("EVFILT_SOCK again", errno, 0);
    want = NOTE_DISCONNECTED | NOTE_READCLOSED | NOTE_WRITECLOSED;
    if (!next(kq, &ev, 1000) || ev.fflags != want || ev.data != SOCKEV_DISCONNECTED || (ev.flags & EV_EOF)) return bad("a disconnected socket's state", ev.fflags, want);
    // Without EV_CLEAR the level events stay collected, and are still not
    // delivered twice.
    if (next(kq, &ev, 50)) return bad("the level events again", ev.fflags, 0);
    close(c);
    close(kq);
    close(kq2);

    // An unconnected socket's NOTE_RESUME: SOF_SUSPENDED is clear.
    c = socket(AF_INET, SOCK_STREAM, 0);
    kq = kqueue();
    if (add(kq, c, EVFILT_SOCK, EV_CLEAR, NOTE_RESUME | NOTE_CONNECTED)) return bad("NOTE_RESUME", errno, 0);
    if (!next(kq, &ev, 1000) || ev.fflags != NOTE_RESUME || ev.data != 0) return bad("NOTE_RESUME's event", ev.fflags, NOTE_RESUME);
    if (next(kq, &ev, 50)) return bad("NOTE_RESUME again", ev.fflags, 0);

    // Connected, then the connection's shutdowns: this end's SHUT_WR is
    // socantsendmore (NOTE_WRITECLOSED); the peer's FIN after it ends the
    // connection (TIME_WAIT: soisdisconnected).
    if (connect(c, (struct sockaddr *)&in, sizeof in)) return bad("connect again", errno, 0);
    s = accept(l, NULL, NULL);
    // NOTE_RESUME stays collected with the new event.
    if (!next(kq, &ev, 1000) || ev.fflags != (NOTE_CONNECTED | NOTE_RESUME)) return bad("the second connect", ev.fflags, NOTE_CONNECTED | NOTE_RESUME);
    struct kevent ch;
    EV_SET(&ch, c, EVFILT_SOCK, EV_ADD | EV_CLEAR, ALL, 0, NULL);
    if (kevent(kq, &ch, 1, NULL, 0, NULL)) return bad("the touch", errno, 0);
    if (shutdown(c, SHUT_WR)) return bad("shutdown", errno, 0);
    if (!next(kq, &ev, 1000) || ev.fflags != (NOTE_CONNECTED | NOTE_WRITECLOSED)) return bad("this end's shutdown", ev.fflags, NOTE_CONNECTED | NOTE_WRITECLOSED);
    if (shutdown(s, SHUT_WR)) return bad("the peer's shutdown", errno, 0);
    want = NOTE_DISCONNECTED | NOTE_CONNINFO_UPDATED | NOTE_READCLOSED | NOTE_WRITECLOSED;
    if (!next(kq, &ev, 1000) || ev.fflags != want || ev.data != SOCKEV_DISCONNECTED) return bad("both FINs", ev.fflags, want);
    close(s);
    close(c);
    close(kq);

    // A refused connect: the SYN's reset (NOTE_CONNRESET), then tcp_drop's
    // soisdisconnected; the connect took so_error.
    in.sin_port = 0;
    close(l);
    l = listener(&in);
    close(l);
    c = socket(AF_INET, SOCK_STREAM, 0);
    kq = kqueue();
    if (add(kq, c, EVFILT_SOCK, EV_CLEAR, ALL)) return bad("EVFILT_SOCK before a refused connect", errno, 0);
    if (connect(c, (struct sockaddr *)&in, sizeof in) != -1 || errno != ECONNREFUSED) return bad("the refused connect", errno, ECONNREFUSED);
    want = NOTE_CONNRESET | NOTE_DISCONNECTED | NOTE_CONNINFO_UPDATED | NOTE_READCLOSED | NOTE_WRITECLOSED;
    if (!next(kq, &ev, 1000) || ev.fflags != want || ev.data != SOCKEV_DISCONNECTED) return bad("the refused connect's event", ev.fflags, want);
    close(c);
    close(kq);
    return 0;
}

static int unixstream(void) {
    int sv[2];
    struct kevent ev;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) return bad("socketpair", errno, 0);
    int kq = kqueue();
    if (add(kq, sv[0], EVFILT_SOCK, EV_CLEAR, ALL)) return bad("EVFILT_SOCK on a unix socket", errno, 0);
    // unp_connect2's soisconnected came before the knote: the state alone.
    if (!next(kq, &ev, 1000) || ev.fflags != NOTE_CONNECTED || ev.data != SOCKEV_CONNECTED) return bad("a socketpair's state", ev.fflags, NOTE_CONNECTED);

    // A touch that drops NOTE_CONNECTED and one that asks for it again:
    // the delivered level event is forgotten, and delivered anew.
    struct kevent ch;
    EV_SET(&ch, sv[0], EVFILT_SOCK, EV_ADD | EV_CLEAR, NOTE_READCLOSED, 0, NULL);
    if (kevent(kq, &ch, 1, NULL, 0, NULL)) return bad("the first touch", errno, 0);
    if (next(kq, &ev, 50)) return bad("an event after dropping NOTE_CONNECTED", ev.fflags, 0);
    EV_SET(&ch, sv[0], EVFILT_SOCK, EV_ADD | EV_CLEAR, ALL, 0, NULL);
    if (kevent(kq, &ch, 1, NULL, 0, NULL)) return bad("the second touch", errno, 0);
    if (!next(kq, &ev, 1000) || ev.fflags != NOTE_CONNECTED) return bad("NOTE_CONNECTED asked for again", ev.fflags, NOTE_CONNECTED);

    // The peer's shutdown: unp_shutdown's socantrcvmore.
    if (shutdown(sv[1], SHUT_WR)) return bad("the peer's shutdown", errno, 0);
    if (!next(kq, &ev, 1000) || ev.fflags != (NOTE_CONNECTED | NOTE_READCLOSED)) return bad("the peer's shutdown's event", ev.fflags, NOTE_CONNECTED | NOTE_READCLOSED);
    // Its close: unp_disconnect's soisdisconnected (no NOTE_CONNINFO_UPDATED:
    // the unix protocols do not have PR_EVCONNINFO).
    close(sv[1]);
    unsigned want = NOTE_DISCONNECTED | NOTE_READCLOSED | NOTE_WRITECLOSED;
    if (!next(kq, &ev, 1000) || ev.fflags != want || ev.data != SOCKEV_DISCONNECTED || (ev.flags & EV_EOF)) return bad("the peer's close's event", ev.fflags, want);
    close(sv[0]);

    // A unix connect: the connecting socket is posted CONNECTED.
    char path[64];
    snprintf(path, sizeof path, "/tmp/evsock.%d", getpid());
    unlink(path);
    struct sockaddr_un un = {.sun_family = AF_UNIX};
    strncpy(un.sun_path, path, sizeof un.sun_path - 1);
    un.sun_len = SUN_LEN(&un);
    int l = socket(AF_UNIX, SOCK_STREAM, 0);
    if (bind(l, (struct sockaddr *)&un, un.sun_len) || listen(l, 1)) return bad("a unix listener", errno, 0);
    int c = socket(AF_UNIX, SOCK_STREAM, 0);
    if (add(kq, c, EVFILT_SOCK, EV_CLEAR, ALL)) return bad("EVFILT_SOCK before a unix connect", errno, 0);
    if (next(kq, &ev, 50)) return bad("an unconnected unix socket's event", ev.fflags, 0);
    if (connect(c, (struct sockaddr *)&un, un.sun_len)) return bad("the unix connect", errno, 0);
    if (!next(kq, &ev, 1000) || ev.fflags != NOTE_CONNECTED) return bad("the unix connect's event", ev.fflags, NOTE_CONNECTED);
    close(c);
    close(l);
    unlink(path);

    // A datagram pair is connected too.
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv)) return bad("a datagram socketpair", errno, 0);
    if (add(kq, sv[0], EVFILT_SOCK, EV_CLEAR, ALL)) return bad("EVFILT_SOCK on a datagram socket", errno, 0);
    if (!next(kq, &ev, 1000) || ev.fflags != NOTE_CONNECTED) return bad("a datagram pair's state", ev.fflags, NOTE_CONNECTED);
    close(sv[0]);
    close(sv[1]);
    close(kq);
    return 0;
}

// EVFILT_EXCEPT on a socket is the read filter (filt_sorattach): with no
// out-of-band data, NOTE_OOB falls through to the data's readability.
static int except(void) {
    int sv[2];
    struct kevent ev;
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    int kq = kqueue();
    if (add(kq, sv[0], EVFILT_EXCEPT, 0, NOTE_OOB)) return bad("EVFILT_EXCEPT", errno, 0);
    if (next(kq, &ev, 50)) return bad("an empty socket's exception", ev.fflags, 0);
    write(sv[1], "abc", 3);
    if (!next(kq, &ev, 1000) || ev.filter != EVFILT_EXCEPT || ev.fflags != 0 || ev.data != 3) return bad("EVFILT_EXCEPT on data", ev.data, 3);
    close(sv[0]);
    close(sv[1]);
    close(kq);
    return 0;
}

static volatile sig_atomic_t ios;

static void on_io(int sig) {
    (void)sig;
    ios++;
}

// Whether a SIGIO arrives within a second.
static int sigio_came(void) {
    for (int i = 0; i < 1000 && !ios; i++) usleep(1000);
    int got = ios != 0;
    ios = 0;
    return got;
}

static int owner(void) {
    signal(SIGIO, on_io);
    setpgid(0, 0);
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) return bad("socketpair", errno, 0);
    // so_pgid as given, and back as it was (a pipe's is negated back).
    if (fcntl(sv[0], F_SETOWN, getpid())) return bad("F_SETOWN", errno, 0);
    if (fcntl(sv[0], F_GETOWN) != getpid()) return bad("F_GETOWN", fcntl(sv[0], F_GETOWN), getpid());
    int v = -getpgrp(), r = 0;
    if (ioctl(sv[0], SIOCSPGRP, &v) || ioctl(sv[0], SIOCGPGRP, &r) || r != -getpgrp()) return bad("SIOCSPGRP", r, -getpgrp());
    if (fcntl(sv[0], F_GETOWN) != -getpgrp()) return bad("F_GETOWN of a group", fcntl(sv[0], F_GETOWN), -getpgrp());
    if (ioctl(sv[0], FIOGETOWN, &r) || r != -getpgrp()) return bad("FIOGETOWN", r, -getpgrp());
    // Nothing is checked when it is set.
    v = 99999;
    if (ioctl(sv[0], FIOSETOWN, &v) || fcntl(sv[0], F_GETOWN) != 99999) return bad("an owner that does not exist", errno, 0);

    // Not async: data arrives and nothing is sent.
    fcntl(sv[0], F_SETOWN, getpid());
    write(sv[1], "a", 1);
    if (sigio_came()) return bad("SIGIO without FIOASYNC", 1, 0);
    // Async: uipc_send's sorwakeup.
    int on = 1;
    if (ioctl(sv[0], FIOASYNC, &on)) return bad("FIOASYNC", errno, 0);
    write(sv[1], "b", 1);
    if (!sigio_came()) return bad("SIGIO to the process", 0, 1);
    // To the group.
    v = -getpgrp();
    ioctl(sv[0], SIOCSPGRP, &v);
    write(sv[1], "c", 1);
    if (!sigio_came()) return bad("SIGIO to the group", 0, 1);
    // The writer, async by F_SETFL's O_ASYNC: a read that frees its room
    // (uipc_rcvd's sowwakeup).
    on = 0;
    ioctl(sv[0], FIOASYNC, &on);
    fcntl(sv[1], F_SETOWN, getpid());
    if (fcntl(sv[1], F_SETFL, O_ASYNC)) return bad("O_ASYNC", errno, 0);
    char b[8];
    if (read(sv[0], b, sizeof b) != 3) return bad("the read", errno, 3);
    if (!sigio_came()) return bad("SIGIO to the writer", 0, 1);
    // Its own shutdown: socantsendmore's sowwakeup.
    shutdown(sv[1], SHUT_WR);
    if (!sigio_came()) return bad("SIGIO at the shutdown", 0, 1);
    close(sv[0]);
    close(sv[1]);
    ios = 0;

    // A loopback TCP connection's end: the peer's data arrives.
    struct sockaddr_in in;
    int l = listener(&in);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(c, (struct sockaddr *)&in, sizeof in)) return bad("connect", errno, 0);
    int s = accept(l, NULL, NULL);
    fcntl(s, F_SETOWN, getpid());
    on = 1;
    if (ioctl(s, FIOASYNC, &on)) return bad("FIOASYNC on TCP", errno, 0);
    if (sigio_came()) return bad("SIGIO before data", 1, 0);
    write(c, "d", 1);
    if (!sigio_came()) return bad("SIGIO for TCP data", 0, 1);
    // The peer's FIN.
    close(c);
    if (!sigio_came()) return bad("SIGIO for the peer's FIN", 0, 1);
    close(s);
    close(l);
    signal(SIGIO, SIG_DFL);
    return 0;
}

static volatile sig_atomic_t urgs;

static void on_urg(int sig) {
    (void)sig;
    urgs++;
}

static int atmark(int s) {
    int v = -1;
    return ioctl(s, SIOCATMARK, &v) ? -1 : v;
}

static int oob(void) {
    struct sockaddr_in in;
    struct kevent ev;
    char b[16];
    int l = listener(&in);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(c, (struct sockaddr *)&in, sizeof in)) return bad("connect", errno, 0);
    int s = accept(l, NULL, NULL);
    signal(SIGURG, on_urg);
    fcntl(s, F_SETOWN, getpid());
    int kq = kqueue();
    if (add(kq, s, EVFILT_EXCEPT, 0, NOTE_OOB)) return bad("EVFILT_EXCEPT", errno, 0);
    if (atmark(s) != 0) return bad("SIOCATMARK with no urgent data", atmark(s), 0);
    if (recv(s, b, 1, MSG_OOB) != -1 || errno != EINVAL) return bad("MSG_OOB with no mark", errno, EINVAL);

    // "ab", then "XY" urgent: Y is the out-of-band byte, the mark after X.
    if (send(c, "ab", 2, 0) != 2 || send(c, "XY", 2, MSG_OOB) != 2) return bad("the sends", errno, 0);
    for (int i = 0; i < 1000 && !urgs; i++) usleep(1000);
    if (!urgs) return bad("SIGURG", 0, 1);
    // NOTE_OOB, its data what is ahead of the mark less the mark: none.
    if (!next(kq, &ev, 1000) || ev.fflags != NOTE_OOB || ev.data != 0) return bad("NOTE_OOB", ev.fflags, NOTE_OOB);
    if (atmark(s) != 0) return bad("SIOCATMARK ahead of the mark", atmark(s), 0);
    if (recv(s, b, 1, MSG_OOB | MSG_PEEK) != 1 || b[0] != 'Y') return bad("a peek at the urgent byte", b[0], 'Y');
    if (recv(s, b, sizeof b, MSG_OOB) != 1 || b[0] != 'Y') return bad("the urgent byte", b[0], 'Y');
    if (recv(s, b, 1, MSG_OOB) != -1 || errno != EINVAL) return bad("the urgent byte again", errno, EINVAL);
    // The read stops at the mark, and is then at it.
    if (read(s, b, sizeof b) != 3 || memcmp(b, "abX", 3)) return bad("the read up to the mark", b[0], 'a');
    if (atmark(s) != 1) return bad("SIOCATMARK at the mark", atmark(s), 1);
    send(c, "z", 1, 0);
    if (read(s, b, sizeof b) != 1 || b[0] != 'z' || atmark(s) != 0) return bad("the read past the mark", b[0], 'z');
    close(s);
    close(c);
    close(kq);

    // SO_OOBINLINE: the urgent byte stays in the stream, at the mark.
    c = socket(AF_INET, SOCK_STREAM, 0);
    connect(c, (struct sockaddr *)&in, sizeof in);
    s = accept(l, NULL, NULL);
    fcntl(s, F_SETOWN, getpid());
    int on = 1;
    if (setsockopt(s, SOL_SOCKET, SO_OOBINLINE, &on, sizeof on)) return bad("SO_OOBINLINE", errno, 0);
    urgs = 0;
    if (send(c, "XY", 2, MSG_OOB) != 2) return bad("the inline send", errno, 0);
    for (int i = 0; i < 1000 && !urgs; i++) usleep(1000);
    if (!urgs) return bad("SIGURG inline", 0, 1);
    if (read(s, b, sizeof b) != 1 || b[0] != 'X' || atmark(s) != 1) return bad("the read up to an inline mark", b[0], 'X');
    if (recv(s, b, 1, MSG_OOB) != -1 || errno != EINVAL) return bad("MSG_OOB with SO_OOBINLINE", errno, EINVAL);
    if (read(s, b, sizeof b) != 1 || b[0] != 'Y') return bad("the urgent byte in line", b[0], 'Y');
    close(s);
    close(c);
    close(l);
    signal(SIGURG, SIG_DFL);
    return 0;
}

int main(void) {
    if (tcp() || unixstream() || except() || owner() || oob()) return 1;
    printf("evsock ok\n");
    return 0;
}
