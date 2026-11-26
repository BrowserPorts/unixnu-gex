// X11 for every windows part: display :0 held by the page (programs.js) until
// the first X client connects, then the runtime's X server (runtime/src/host/hostx.js,
// runtime.js `startXServer`) started on those sockets, where the client
// waits.

/** A windows part's `env`: its compositor's, and display :0 when it has X
 *  (its `x11` option; a program finding `DISPLAY` would try X first, Wine's
 *  driver among them, and wait for the server). */
export function xEnv(x11) {
  return x11 ? { XDG_RUNTIME_DIR: '/tmp', WAYLAND_DISPLAY: 'wayland-0', DISPLAY: ':0' } : { XDG_RUNTIME_DIR: '/tmp', WAYLAND_DISPLAY: 'wayland-0' };
}

/** Arm it for a system's internals `i`, once the system runs. `x`: what a
 *  preset asks of the server (a test page's runProgram): `rootful`, one
 *  fullscreen X screen under the session's own window manager (hostx.js). */
export function xOnDemand(i, x = {}) {
  i.afterBoot(async (sys) => {
    // The single-thread build's server is in its system Worker (`startX`).
    if (!sys.wlChannel && !sys.startX) return;
    const ids = await i.programs().holdX();
    let server = null;
    i.on('x-wanted', () => {
      server ??= sys.startX
        ? sys.startX({ listen: ids, rootful: !!x.rootful })
        : sys.rt.startXServer({ kernel: sys.kernel, wlChannel: sys.wlChannel, compositor: () => sys.compositor, term: sys.term, listen: ids, rootful: !!x.rootful });
      server.catch((e) => i.say(`gex: the X server would not start: ${e?.message ?? e}\n`));
    });
    // Its Worker's `main` never returns: ending the system ends the Worker.
    sys.onStop(() => server?.then((w) => w?.terminate?.(), () => {}));
  });
}
