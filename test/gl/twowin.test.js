// Two GL windows of one client and one context in the scene compositor
// (CompositorWindows, rootless X): /probes/gles-twowin makes its context
// current on each window's surface in turn, "twowin A" 200x150 magenta and
// "twowin B" 100x80 cyan. Each window must show its own frame: with one shared
// GL canvas for every window, each showed the other's (the second's pasted
// over the first's corner, the first's scaled into the second), which is what
// Godot's project manager and its dialogs looked like (compositor-worker.js
// glSurfaceCanvases). x86 only: the probe is in that tree alone (the host's Xlib).
import { System } from '../../runtime/src/index.js';
import { MemoryFilesystem } from '../../runtime/src/fs.js';
import { CompositorWindows } from '../../runtime/src/windows/compositor.js';
import { MesaGl } from '../../runtime/src/gl.js';

export const meta = { hosts: ['browser'], arches: ['x86'], images: ['gl-probes'], timeout: 300, html: `<style>html, body { margin: 0; }</style>
<canvas id="out" width="800" height="600" style="width: 800px; height: 600px; display: block;"></canvas>` };

export default async function (t) {
  const { check, until, lines } = t;
  const adapter = await navigator.gpu?.requestAdapter().catch(() => null);
  if (!adapter) return t.skip('no WebGPU adapter here');
  if (!(await fetch(t.work('gl-probes-x86.tar'), { method: 'HEAD' })).ok) return t.skip('no gl-probes-x86.tar (fixtures/images.mjs)');
  const sys = new System({ baseUrl: t.baseUrl, debug: t.debug() });
  new MemoryFilesystem(sys).addTar(t.work('gl-probes-x86.tar'));
  const out = new CompositorWindows(sys, { canvas: document.getElementById('out'), scale: 1 });
  new MesaGl(sys);
  await t.timeout(sys.boot(), 60000, 'boot');
  const p = sys.spawn(['/probes/gles-twowin', '30', '60'], { env: { HOME: '/', ...out.env } });
  const said = lines(p);
  const err = lines(p, p.stderr);
  const why = () => `stdout ${JSON.stringify(said)}, stderr ${JSON.stringify(err.slice(-8))}`;
  await until(() => said.some((l) => l.startsWith('frames')), 'its frames', 120000).catch((e) => { throw new Error(`${e.message}; ${why()}`); });
  t.eq('no GL error', said.find((l) => l.startsWith('frames')), 'frames 30 gl error 0');
  // Each window's place on the canvas, from the compositor's own list.
  const place = async (title) => {
    const d = await out.describe();
    const l = d?.list?.find((s) => s.endsWith(`"${title}"`));
    const m = l && /(\d+)x(\d+)@(-?\d+),(-?\d+)/.exec(l);
    return m ? { w: +m[1], h: +m[2], x: +m[3], y: +m[4] } : null;
  };
  let a, b;
  await until(async () => (a = await place('twowin A')) && (b = await place('twowin B')), 'both windows listed', 30000)
    .catch(async (e) => { throw new Error(`${e.message}; ${JSON.stringify((await out.describe())?.list)}`); });
  const colour = (px, [r, g, bl]) => Math.abs(px[0] - r) < 40 && Math.abs(px[1] - g) < 40 && Math.abs(px[2] - bl) < 40;
  // The points of WIN that no window in OVER covers (the window manager may
  // stack B on part of A): its middle and its four corners' insets, among
  // them the top-left, which the other window's frame covered when both
  // shared one canvas.
  const inside = (w, x, y) => x >= w.x && x < w.x + w.w && y >= w.y && y < w.y + w.h;
  const look = async (win, name, want, over = []) => {
    const pts = [[win.x + (win.w >> 1), win.y + (win.h >> 1)], [win.x + 6, win.y + 6], [win.x + win.w - 7, win.y + 6],
      [win.x + 6, win.y + win.h - 7], [win.x + win.w - 7, win.y + win.h - 7]].filter(([x, y]) => !over.some((o) => inside(o, x, y)));
    check(`${name} has points no other window covers`, pts.length >= 2, `window ${JSON.stringify(win)}, over it ${JSON.stringify(over)}`);
    let px = [];
    const ok = await until(async () => {
      px = await Promise.all(pts.map(([x, y]) => t.pixel(x, y)));
      return px.every((v) => colour(v, want));
    }, `${name} its own colour`, 20000).then(() => true, () => false);
    check(`${name} shows its own frame`, ok, `at ${JSON.stringify(pts)}: ${JSON.stringify(px)}; window ${JSON.stringify(win)}`);
  };
  await look(a, 'twowin A (magenta)', [255, 0, 255], [b]);
  await look(b, 'twowin B (cyan)', [0, 255, 255]);
  p.kill?.();
  await sys.shutdown();
}
