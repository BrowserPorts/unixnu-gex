// `CompositorWindows`: the guest's whole desktop drawn into one canvas by
// gex's scene compositor (runtime/src/host/compositor.js, on WebGPU in a Worker of its
// own): window frames, title bars, stacking, the cursor and its own hit
// testing. For a page that wants a desktop without being a window manager.

import { INTERNAL, internals } from '../internal.js';
import { xEnv, xOnDemand } from './x11.js';

/** The page's compositor (runtime/src/host/compositor.js) for one whose scene is in
 *  the single-thread build's system Worker `k`: what it would post to its
 *  Worker goes as `{ comp }`, what comes back arrives as `comp-out` events
 *  (`listeners`), and its counters, which it cannot share, as copies. */
async function relayed(canvas, scale, k, listeners, background) {
  const { Compositor } = await import('../host/compositor.js');
  const mine = new Set();
  let stats = null;
  listeners.add((m) => {
    if (m.ev === 'comp-out') for (const f of [...mine]) f({ data: m.m });
    else if (m.ev === 'comp-stats' && stats) stats.set(m.stats.subarray(0, stats.length));
  });
  const port = {
    postMessage(m, transfer = []) {
      if (m?.kind === 'init' && m.stats) stats = new Int32Array(m.stats);
      k.post({ comp: m }, transfer);
    },
    addEventListener(type, f) { if (type === 'message') mine.add(f); },
    removeEventListener(type, f) { mine.delete(f); },
    terminate() {},
  };
  return Compositor.create(canvas, null, canvas, { makeWorker: () => port, scale, background });
}

/** `background` as the compositor takes it: the colour as fractions, the
 *  image decoded (an ImageBitmap) once it has loaded. */
function backgroundOf(bg) {
  if (bg == null) return null;
  const { color = null, image = null, anchor = 'center' } = typeof bg === 'string' ? { color: bg } : bg;
  if (color !== null && !/^#[0-9a-fA-F]{6}$/.test(color)) throw new TypeError(`CompositorWindows: background colour ${color} (#rrggbb)`);
  if (!['top', 'center', 'bottom'].includes(anchor)) throw new TypeError(`CompositorWindows: background anchor ${anchor} (top, center or bottom)`);
  const desktop = color ? [1, 3, 5].map((i) => parseInt(color.slice(i, i + 2), 16) / 255) : null;
  const wallpaper = image ? (async () => {
    try {
      const blob = typeof Blob === 'function' && image instanceof Blob ? image : await (await fetch(new URL(image, globalThis.location?.href))).blob();
      return { bitmap: await createImageBitmap(blob), anchor };
    } catch (e) {
      console.warn('gex: the background image did not load:', e);
      return null;
    }
  })() : null;
  return { desktop, wallpaper };
}

/** The page's device pixels per CSS pixel, unrounded. */
const dprNow = () => Math.max(1, Number(globalThis.devicePixelRatio) || 1);

/**
 * The canvas's backing store set to its content box in device pixels, before
 * its control goes to the compositor's Worker (after that only `resize`
 * reaches it). A canvas whose CSS size is its backing store's (no width or
 * height of its own in any style) would grow with it every time: its CSS
 * size is pinned first, to what it is now.
 */
function fitCanvas(canvas) {
  if (typeof canvas.getBoundingClientRect !== 'function' || !canvas.isConnected) return;
  const r = canvas.getBoundingClientRect();
  if (!r.width || !r.height) return;
  const w0 = canvas.width, h0 = canvas.height;
  canvas.width = w0 + 1;
  canvas.height = h0 + 1;
  const r1 = canvas.getBoundingClientRect();
  canvas.width = w0;
  canvas.height = h0;
  if (r1.width !== r.width) canvas.style.width = `${r.width}px`;
  if (r1.height !== r.height) canvas.style.height = `${r.height}px`;
  const s = dprNow();
  // Its content box: the border box less borders and padding.
  const cs = getComputedStyle(canvas);
  const px = (v) => parseFloat(v) || 0;
  const cw = r.width - px(cs.borderLeftWidth) - px(cs.borderRightWidth) - px(cs.paddingLeft) - px(cs.paddingRight);
  const ch = r.height - px(cs.borderTopWidth) - px(cs.borderBottomWidth) - px(cs.paddingTop) - px(cs.paddingBottom);
  canvas.width = Math.max(1, Math.round(cw * s));
  canvas.height = Math.max(1, Math.round(ch * s));
}

export class CompositorWindows extends EventTarget {
  #c = null;
  #x11;

  /**
   * `canvas`: the output. By default the runtime sizes its backing store:
   * the canvas's content box in device pixels (devicePixelContentBoxSize),
   * followed as the page lays it out, zooms or moves to another monitor, at
   * the real devicePixelRatio (1.5 is 1.5), which clients are told: in
   * 120ths to those that take a fractional scale, rounded up to the rest,
   * whose pixels are then sampled down. `scale`, a number: that scale, and
   * the page sizes the backing store itself (the output's size in device
   * pixels) and calls `resize`; `scale: 1` is a page that is not HiDPI. The
   * canvas's control goes to the compositor's Worker. `x11`: X11 programs'
   * display, none unless asked (no `DISPLAY` in `env`): 'rootless', each X
   * window a window of the desktop, placed by the runtime's window manager;
   * or 'rootful', one X screen filling the output, run by the session's own
   * window manager (kwin_x11 and the like). `background`: the desktop
   * behind the windows, a colour ('#rrggbb') or `{ color, image, anchor }`:
   * `image` a URL or a Blob, covering the output, `anchor` the edge that
   * always shows ('top', 'center', the default, or 'bottom'); the colour
   * shows until the image is in.
   */
  constructor(sys, { canvas, scale, x11 = null, background = null } = {}) {
    super();
    if (typeof canvas?.getContext !== 'function') throw new TypeError('CompositorWindows: a canvas');
    if (x11 !== null && x11 !== 'rootless' && x11 !== 'rootful') throw new TypeError("CompositorWindows: x11 is 'rootless', 'rootful' or null");
    const bg = backgroundOf(background);
    const i = internals(sys, 'CompositorWindows');
    i.attach('windows', this, { beforeBoot: true });
    const auto = scale === undefined || scale === null || scale === 'auto';
    if (auto) fitCanvas(canvas);
    this.#scale = auto ? dprNow() : Math.max(1, Number(scale) || 1);
    i.devices(async (dev) => {
      const wlScale = this.#scale;
      // The single-thread build: the scene is drawn in its system Worker,
      // which holds the memories it reads; this side relays to it.
      if (dev.single) {
        dev.single.wl = {
          width: canvas.width,
          height: canvas.height,
          scale: wlScale,
          attach: async (k, listeners) => {
            this.#c = await relayed(canvas, wlScale, k, listeners, bg);
            if (auto) this.#follow(canvas);
            return { compositor: this.#c };
          },
        };
        return;
      }
      Object.assign(dev, await dev.rt.openWayland({ wl: canvas, wlScale, background: bg, say: (t) => dev.say(`${t}\n`) }));
      this.#c = dev.compositor;
      if (auto) this.#follow(canvas);
    });
    const x = { rootful: x11 === 'rootful' };
    if (x11) xOnDemand(i, x);
    this.#x11 = !!x11;
    this[INTERNAL] = {
      x,
      of: () => [],
      shutdown: () => {
        this.#unfollow?.();
        this.#c?.stop();
      },
      /** The compositor's window at a page point, with its block (drop.js). */
      windowAt: (x, y) => this.#c?.windowAt?.(x, y) ?? null,
    };
  }

  #scale = 1;
  #unfollow = null;

  /** The canvas's device-pixel size and the page's scale, followed: a
   *  ResizeObserver on its device-pixel content box (which a zoom or another
   *  monitor changes as well as a layout), and a resolution query for a
   *  scale that changes with no change of size. */
  #follow(canvas) {
    if (typeof ResizeObserver !== 'function') return;
    let w = canvas.width, h = canvas.height, query = null;
    const scaleNow = () => {
      const s = dprNow();
      if (s !== this.#scale) {
        this.#scale = s;
        this.#c?.setScale?.(s);
      }
    };
    const watchScale = () => {
      query?.removeEventListener('change', onScale);
      query = globalThis.matchMedia?.(`(resolution: ${dprNow()}dppx)`) ?? null;
      query?.addEventListener('change', onScale);
    };
    const onScale = () => {
      again();
      watchScale();
    };
    const sized = (box, css) => {
      // The device-pixel box is the CSS box times the scale, snapped to
      // whole pixels; one that is not (an emulated scale reports the CSS
      // box there) is not taken.
      const s = dprNow();
      const take = (d, c) => (d && Math.abs(d - c * s) < 2 ? d : Math.round(c * s));
      const nw = take(box?.inlineSize, css?.inlineSize ?? 0);
      const nh = take(box?.blockSize, css?.blockSize ?? 0);
      scaleNow();
      if (!nw || !nh || (nw === w && nh === h)) return;
      w = nw;
      h = nh;
      this.#c?.resize(w, h);
    };
    const ro = new ResizeObserver(([e]) => {
      // Zoomed out below 1: the output stays at the CSS size (scale 1), and
      // the browser shrinks it.
      sized((Number(globalThis.devicePixelRatio) || 1) >= 1 ? e.devicePixelContentBoxSize?.[0] : null, e.contentBoxSize?.[0]);
    });
    // A scale that changes the device-pixel box without the observer seeing
    // it (an emulated one): the CSS box again, at the scale there is now.
    const again = () => {
      const r = canvas.getBoundingClientRect();
      sized(null, { inlineSize: canvas.clientWidth || r.width, blockSize: canvas.clientHeight || r.height });
    };
    globalThis.addEventListener?.('resize', again);
    try {
      ro.observe(canvas, { box: 'device-pixel-content-box' });
    } catch {
      ro.observe(canvas);
    }
    watchScale();
    this.#unfollow = () => {
      ro.disconnect();
      query?.removeEventListener('change', onScale);
      globalThis.removeEventListener?.('resize', again);
    };
  }

  /** What a program needs to reach this compositor, and the X display when
   *  there is one. */
  get env() {
    return xEnv(this.#x11);
  }

  /** The output's new size, in device pixels. */
  resize(width, height) {
    this.#c?.resize(width, height);
  }

  /** The scene: its windows, titles and a hash of what is shown;
   *  `pixels: false` leaves out the hash (cheap enough to ask often). */
  describe({ pixels = true } = {}) {
    return this.#c?.describe({ pixels }) ?? Promise.resolve(null);
  }
}
