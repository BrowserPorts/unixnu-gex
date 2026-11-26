// `SingleCanvas`: the guest's windows drawn straight into one element of the
// page, laid out there with no frames (runtime/src/host/bare-desktop.js): for a page
// that is one program -- a game, a Win32 program whose windows draw their own
// frames -- rather than a desktop.

import { INTERNAL, internals } from '../internal.js';
import { xEnv, xOnDemand } from './x11.js';
import { mirrored } from './mirrored.js';

export class SingleCanvas extends EventTarget {
  #d = null;
  #container;
  #x11;

  /**
   * `container`: a positioned element; its size is the output's, what a
   * program asking for the screen's size sees. The windows' canvases go in
   * it, the first at its corner, popups over their parents, a window its
   * client places (Wine's) where it says. `x11`: 'rootless' for X11
   * programs, through the runtime's X server; none unless asked (no
   * `DISPLAY` in `env`).
   */
  constructor(sys, { container, x11 = null } = {}) {
    super();
    if (!container || container.nodeType !== 1) throw new TypeError('SingleCanvas: a container element');
    if (x11 !== null && x11 !== 'rootless') throw new TypeError("SingleCanvas: x11 is 'rootless' or null");
    this.#x11 = !!x11;
    const i = internals(sys, 'SingleCanvas');
    this.#container = container;
    i.attach('windows', this, { beforeBoot: true });
    // What a preset asks (a test page's runProgram): the X server's kind, and
    // `onDesktop(desktop, bare)` when the desktop is made.
    const x = {};
    i.devices(async (dev) => {
      const { bareDesktop } = await import('../host/bare-desktop.js');
      const onDesktop = (d) => {
        this.#d = bareDesktop(d, container);
        x.onDesktop?.(d, this.#d);
        d.onwindowgone = () => this.dispatchEvent(new Event('change'));
        const onwindow = d.onwindow;
        d.onwindow = (w) => {
          onwindow(w);
          this.dispatchEvent(new Event('change'));
        };
      };
      if (dev.single) {
        mirrored(dev, container, { width: container.clientWidth, height: container.clientHeight, scale: 1 }, onDesktop);
        return;
      }
      Object.assign(dev, await dev.rt.openWayland({ wl: container, onDesktop, say: (t) => dev.say(`${t}\n`) }));
    });
    if (x11) xOnDemand(i, x);
    this[INTERNAL] = {
      x,
      of: () => [],
      shutdown: () => this.#d?.stop(),
    };
  }

  /** What a program needs to reach this compositor, and the X display when
   *  there is one. */
  get env() {
    return xEnv(this.#x11);
  }

  /** The container's new size, as the output's: after the page resized it. */
  resized() {
    this.#d?.resizeOutput(this.#container.clientWidth, this.#container.clientHeight);
  }

  /** The windows' titles, surfaces and a hash of what is shown, as a test
   *  harness reads it (`change` events say when it changes). */
  describe() {
    return this.#d?.describe?.() ?? null;
  }
}
