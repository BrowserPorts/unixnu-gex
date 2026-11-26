// A placed window (gex_window_placement_v1, Wine's top-levels) on a 1.5x
// output: its position is its client's screen coordinates, which are the
// output's device pixels, and the compositor shows it there -- not scaled a
// second time, which put a Win32 taskbar at the bottom of the work area half
// a screen below the output. Two rt-wl windows placed at the bottom of a
// 400x300 CSS canvas (600x450 device pixels), at x 0 and 300, each 40x20 in
// its units (60x30 device pixels): each is listed where its client put it,
// and a press over each, in CSS pixels on the page, reaches it at its own
// surface coordinates.
import { System } from '../../runtime/src/index.js';
import { MemoryFilesystem } from '../../runtime/src/fs.js';
import { CompositorWindows } from '../../runtime/src/windows/compositor.js';

export const meta = {
  hosts: ['browser'], images: ['busybox'], timeout: 180,
  html: '<style>html, body { margin: 0; }</style><canvas id="out" style="position:absolute;left:0;top:0;width:400px;height:300px"></canvas>',
};

export default async function (t) {
  const { check, timeout, until, lines, input } = t;
  const adapter = await navigator.gpu?.requestAdapter().catch(() => null);
  if (!adapter) return t.skip('no WebGPU adapter here');
  await t.cdp({ method: 'Emulation.setDeviceMetricsOverride', width: 900, height: 700, deviceScaleFactor: 1.5, mobile: false });
  await until(async () => devicePixelRatio === 1.5, 'devicePixelRatio 1.5', 5000);
  const sys = new System({ baseUrl: t.baseUrl, debug: t.debug() });
  new MemoryFilesystem(sys).addTar(t.work('bb.tar.zst'));
  const canvas = document.getElementById('out');
  const out = new CompositorWindows(sys, { canvas });
  await timeout(sys.boot(), 60000, 'boot');
  let d = null;
  await until(async () => { d = await out.describe({ pixels: false }); return d?.output === '600x450'; }, 'a 600x450 output', 10000)
    .catch((e) => { throw new Error(`${e.message}: ${d?.output} ${d?.scale}`); });
  const env = { PATH: '/bin', ...out.env };
  const start = async (title, x, y) => {
    const p = sys.spawn(['rt-wl', title, 'size', '40', '20', 'place', String(x), String(y), '0'], { env });
    const said = lines(p);
    await until(() => said.some((l) => l.startsWith('drawn')), `${title} drawn`, 60000)
      .catch((e) => { throw new Error(`${e.message}: ${JSON.stringify(said)}`); });
    return { p, said };
  };
  const left = await start('left', 0, 420);
  const right = await start('right', 300, 420);
  const geom = async (title) => {
    let g = null;
    await until(async () => {
      d = await out.describe({ pixels: false });
      const l = d?.list?.find((s) => s.endsWith(`"${title}"`));
      const m = l && /role=1 (\d+)x(\d+)@(-?\d+),(-?\d+)/.exec(l);
      g = m && m.slice(1).map(Number);
      return g && g[2] === (title === 'left' ? 0 : 300);
    }, `${title} listed`, 10000).catch(() => {});
    return g;
  };
  const gl = await geom('left'), gr = await geom('right');
  check(`a window placed at 0,420 is at 0,420 in device pixels, 60x30 (${gl})`, `${gl}` === '60,30,0,420');
  check(`and one at 300,420 at 300,420 (${gr})`, `${gr}` === '60,30,300,420');
  const press = async (cx, cy, said, want, what) => {
    const before = said.length;
    await input({ method: 'Input.dispatchMouseEvent', type: 'mouseMoved', x: cx, y: cy, button: 'none', buttons: 0 });
    await new Promise((r) => setTimeout(r, 300));
    await input(
      { method: 'Input.dispatchMouseEvent', type: 'mousePressed', x: cx, y: cy, button: 'left', buttons: 1, clickCount: 1 },
      { method: 'Input.dispatchMouseEvent', type: 'mouseReleased', x: cx, y: cy, button: 'left', buttons: 0, clickCount: 1 },
    );
    const m = await until(() => said.slice(before).map((l) => /^pressed (-?\d+) (-?\d+)$/.exec(l)).find(Boolean), what, 10000).catch(() => null);
    const got = m && [Number(m[1]), Number(m[2])];
    check(`${what} (${got ?? 'no press'}, want ${want})`, !!got && Math.abs(got[0] - want[0]) <= 1 && Math.abs(got[1] - want[1]) <= 1);
  };
  // CSS 20,290 is device 30,435: 30,15 into the left window, its units 20,10.
  await press(20, 290, left.said, [20, 10], 'a press at the bottom of the page reaches the window placed there');
  // CSS 210,290 is device 315,435: 15,15 into the right one, its units 10,10.
  await press(210, 290, right.said, [10, 10], 'and one further along reaches the other');
  left.p.kill('SIGKILL');
  right.p.kill('SIGKILL');
  await sys.shutdown();
}
