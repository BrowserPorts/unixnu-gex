// `HostDrop`: files and folders dropped on the page, copied into the guest's
// filesystem with their tree (runtime/src/host/drop.js, in a Worker of its own on the
// shared kernel, so the page never waits on the copy), then dragged onto the
// window under the point, whose program may take them (runtime/src/host/drag.js, a
// drag of their text/uri-list through the guest's Wayland compositor). The
// page wires its own drop events to it; nothing listens to the DOM here.

import { INTERNAL, internals } from './internal.js';
import { Dropper, checkDrop, dropItems, walk } from './host/drop.js';

export class HostDrop {
  #sys = null;
  #windows;
  #dropper = null;
  #drag = null;

  /**
   * `windows`: the system's CompositorWindows, whose window under a drop's
   * point it is dragged onto; without it (or with windows of another
   * kind), a drop is copied, and `window` is null. The default build only.
   */
  constructor(sys, { windows = null } = {}) {
    const i = internals(sys, 'HostDrop');
    i.attach('drop', this);
    this.#windows = windows;
    i.afterBoot((s) => { this.#sys = s; });
  }

  /** The window at a page point (an event's clientX and clientY), as a
   *  drop there names it: `{ title, client, surface, x, y }` (the point in
   *  it), or null. For a drag over the page: a browser names a drag's files
   *  only at its drop. */
  async windowAt(x, y) {
    if (!Number.isFinite(x) || !Number.isFinite(y)) throw new TypeError('windowAt(x, y): a point\'s clientX and clientY');
    const w = await this.#hit(x, y);
    return w && { title: w.title, client: w.client, surface: w.surface, x: w.x, y: w.y };
  }

  #hit(x, y) {
    const at = this.#windows?.[INTERNAL]?.windowAt;
    return at ? Promise.resolve(at(x, y)).then((w) => w ?? null) : Promise.resolve(null);
  }

  /**
   * `data` dropped on the page: the drop event's `dataTransfer` (or its
   * `items`, a FileList, an array of Files), read at once, so call it in the
   * event's handler before anything there awaits (a browser empties it once
   * the event is over). Options: `x`, `y` (the event's clientX and clientY:
   * the window there is dragged onto), `dir` (the guest directory to copy
   * into, made if missing; default a new /tmp/drops/N), `fallback` (a guest
   * directory the copy moves into when no window takes it), `signal` (stops
   * the copy and takes back what it wrote), `onProgress({ done, total,
   * files, filesDone, name })`. Resolves `{ path, files, bytes, ms, window,
   * accepted, paths }`: the directory made, its files and bytes, the window
   * at the point or null, whether its program took the drop, and where the
   * top-level files and folders are now. Files 0644 (0755 for one that
   * starts as a program does), folders 0755, the guest user's.
   */
  drop(data, opts = {}) {
    try {
      checkDrop(data, opts);
    } catch (e) {
      return Promise.reject(new TypeError(e.message));
    }
    const items = dropItems(data);
    const { x, y, dir = null, fallback = null, signal, onProgress } = opts ?? {};
    const s = this.#sys;
    if (!s?.host || !s.kernel?.memory) return Promise.reject(new Error('drop(): the system is not running, or this is the single-thread build'));
    return (async () => {
      signal?.throwIfAborted();
      const at = x !== undefined ? this.#hit(x, y) : Promise.resolve(null);
      const entries = await walk(items, signal);
      if (!entries.length) throw new Error('drop(): nothing in it to copy (no files or folders)');
      this.#dropper ??= new Dropper(s);
      const { names, ...r } = await this.#dropper.copy(entries, { dir: dir ? dir.replace(/\/+$/, '') : null, signal, onProgress });
      let paths = names.map((n) => `${r.path}/${n}`);
      // Dragged to the window once copied: its program reads where they
      // are as the drag enters, to decide whether it takes them.
      const hit = await at;
      let accepted = false;
      if (hit && s.wlChannel) {
        if (!this.#drag) {
          const { PageDrag } = await import('./host/drag.js');
          this.#drag = new PageDrag(s.wlChannel, await import('../../hosts/browser/js/wl-bridge.mjs'));
        }
        accepted = await this.#drag.drop(hit, paths);
      }
      const window = hit && { title: hit.title, client: hit.client, surface: hit.surface, x: hit.x, y: hit.y };
      if (!accepted && fallback) ({ paths } = await this.#dropper.move(r.path, names, fallback.replace(/\/+$/, '')));
      return { ...r, window, accepted, paths };
    })();
  }
}
