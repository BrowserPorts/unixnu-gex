// HostWindows at a scale that is not whole (1.5): the clients are told 180
// 120ths (record word 18), and a window's size stays in CSS pixels, its
// surface units, whatever its buffer is.
import { System } from '../../runtime/src/index.js';
import { MemoryFilesystem } from '../../runtime/src/fs.js';
import { HostWindows } from '../../runtime/src/windows/host.js';

export const meta = { hosts: ['browser'], images: ['busybox'], timeout: 120, html: `<style>html, body { margin: 0; } #desk { position: relative; width: 800px; height: 600px; }</style>
<div id="desk"></div>` };

export default async function (t) {
  const { check, eq, timeout, until } = t;
  const sys = new System({ baseUrl: t.baseUrl, debug: t.debug() });
  new MemoryFilesystem(sys).addTar(t.work('bb.tar.zst'));
  const hw = new HostWindows(sys, { width: 800, height: 600, scale: 1.5 });
  const desk = document.getElementById('desk');
  const wins = [];
  hw.addEventListener('window', (e) => {
    const w = e.window;
    wins.push(w);
    w.canvas.style.position = 'absolute';
    desk.append(w.canvas);
  });
  await timeout(sys.boot(), 60000, 'boot');
  sys.spawn(['rt-wl', 'hello'], { env: { PATH: '/bin', ...hw.env } });
  const w = await until(() => wins.find((x) => x.title === 'hello'), 'a window');
  const rec = await until(() => globalThis.__gexDesktop?.records?.().find((r) => r.title === 'hello'), 'its record');
  eq('told the real scale', rec.scale120, 180);
  eq('its size in CSS pixels', [w.width, w.height], [200, 100]);
  check('its canvas laid out at that size', w.canvas.style.width === '200px' && w.canvas.style.height === '100px', `${w.canvas.style.width} ${w.canvas.style.height}`);
  await sys.shutdown();
}
