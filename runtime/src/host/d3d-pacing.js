// D3D presents, paced in the compositor.
//
// A GL client paces itself: eglSwapBuffers learns from the host how many of
// its frames the page has shown and sleeps while it is too far ahead
// (guest/gl/gexgl.c). A D3D client's present goes out as dirk's records
// instead (ports/mesa/src/gexd3d-mesa.cpp), files its frame under its window
// and returns without asking, so a program that presents faster than the
// page shows frames drew every one of them and had all but the newest
// passed over.
//
// The pacing is therefore here, where the frames are shown: after a D3D
// client's submit, its reply is held while that client has as many frames
// presented and not yet shown as its swap interval, and released when the
// page has shown them, or after a capped wait so a page that stops showing
// (a hidden tab) slows the program rather than wedging it, as GL's pacing
// does. A D3D window's frames are shown newest-first, so one present more
// per shown frame would be drawn and passed over: paced, a program presents
// once per frame the page shows. It draws its next frame while held -- the
// unwaited submit has returned -- and waits only to send it. The ring is one,
// so the hold is a hold on the device: no other client's batch runs
// meanwhile either.
//
// The interval is the player's, as GL's GEXGL_SWAP_INTERVAL is: from the
// environment the page gives Mesa (`?mesaenv=GEXGL_SWAP_INTERVAL=0`), since
// the guest's environment never reaches the page. 0 never paces, 1 paces,
// and with neither it paces at 1, EGL's default and what a vsynced D3D
// program asks for.

/** The interval from Mesa's environment (`K=V,K=V`): 0 or 1, else 1. */
export function d3dSwapInterval(env) {
  for (const pair of String(env ?? '').split(',')) {
    const [key, value] = pair.split('=');
    if (key?.trim() === 'GEXGL_SWAP_INTERVAL' && (value === '0' || value === '1')) return Number(value);
  }
  return 1;
}

export class D3dPacer {
  #interval;
  #unshown;
  #capMs;
  #setTimer;
  #clearTimer;
  #waiting = [];

  /**
   * `unshown(client)`: the frames that client's D3D windows presented and
   * the page has not shown (gexgl-mesa.cpp gex_gl_client_unshown). The
   * default timers are plain calls: a browser's setTimeout called as a method
   * of this object throws "Illegal invocation" (Node's does not).
   */
  constructor({ interval = 1, unshown, capMs = 50, setTimer = (fn, ms) => setTimeout(fn, ms), clearTimer = (t) => clearTimeout(t) }) {
    this.#interval = interval;
    this.#unshown = unshown;
    this.#capMs = capMs;
    this.#setTimer = setTimer;
    this.#clearTimer = clearTimer;
  }

  get interval() {
    return this.#interval;
  }

  /** After a D3D client's submit: null when its reply may go now, else a
   *  promise that resolves when it may. */
  after(client) {
    if (this.#interval <= 0 || this.#unshown(client) < this.#interval) return null;
    return new Promise((resolve) => {
      const w = { client, resolve, timer: null };
      w.timer = this.#setTimer(() => this.#release(w), this.#capMs);
      this.#waiting.push(w);
    });
  }

  /** The page has shown frames: whoever is no longer too far ahead goes. */
  shown() {
    for (const w of [...this.#waiting])
      if (this.#unshown(w.client) < this.#interval) this.#release(w);
  }

  /** How many replies are being held. */
  get held() {
    return this.#waiting.length;
  }

  #release(w) {
    const at = this.#waiting.indexOf(w);
    if (at < 0) return;
    this.#waiting.splice(at, 1);
    this.#clearTimer(w.timer);
    w.resolve();
  }
}
