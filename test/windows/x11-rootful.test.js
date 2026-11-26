// A rootful X screen (CompositorWindows x11: 'rootful'): the X server fills
// the output, started for the first X client, and that client's window shows
// in the screen's own pixels, not as a window of the scene. rt-x11 maps a
// 160x80 window at (0, 0), its background #3060c0.
import { System } from '../../runtime/src/index.js';
import { MemoryFilesystem } from '../../runtime/src/fs.js';
import { CompositorWindows } from '../../runtime/src/windows/compositor.js';

export const meta = { hosts: ['browser'], images: ['busybox'], timeout: 180, html: `<style>html, body { margin: 0; }</style>
<canvas id="out" width="640" height="480" style="width: 640px; height: 480px; display: block;"></canvas>` };

const blue = (p) => Math.abs(p[0] - 0x30) < 12 && Math.abs(p[1] - 0x60) < 12 && Math.abs(p[2] - 0xc0) < 12;

export default async function (t) {
  const { check, eq, until, lines, timeout } = t;
  const sys = new System({ baseUrl: t.baseUrl, debug: t.debug() });
  new MemoryFilesystem(sys).addTar(t.work('bb.tar.zst'));
  const canvas = document.getElementById('out');
  const out = new CompositorWindows(sys, { canvas, scale: 1, x11: 'rootful' });
  await timeout(sys.boot(), 60000, 'boot');
  eq('env', out.env.DISPLAY, ':0');
  const r = canvas.getBoundingClientRect();
  const at = (x, y) => [Math.round(r.left + x), Math.round(r.top + y)];
  const p = sys.spawn(['rt-x11', 'rooted'], { env: { PATH: '/bin', HOME: '/root', ...out.env } });
  const o = lines(p);
  const err = lines(p, p.stderr);
  const said = () => `stdout ${JSON.stringify(o.slice(-6))}, stderr ${JSON.stringify(err.slice(-8))}, console ${JSON.stringify(sys.state.console.slice(-600))}`;
  await until(() => o.includes('mapped'), 'the client mapped its window', 60000).catch((e) => { throw new Error(`${e.message}; ${said()}`); });
  check('the X server started for it', true);
  let px = null;
  const shown = await until(async () => blue(px = await t.pixel(...at(80, 40))), 'its pixels on the screen', 30000).then(() => true, () => false);
  check('the window shows in the X screen', shown, `pixel ${JSON.stringify(px)}; ${said()}`);
  const outside = await t.pixel(...at(400, 300));
  check('the screen past it is not the window', !blue(outside), JSON.stringify(outside));
  if (!shown) await t.screenshot('x11-rootful');
  p.kill?.();
  await sys.shutdown();
}
