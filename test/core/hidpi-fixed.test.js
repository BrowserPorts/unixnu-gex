// CompositorWindows with a number for `scale`: the page's own sizing, left as it
// is at any devicePixelRatio (here 1.5), and that scale for the frames.
import { System } from '../../runtime/src/index.js';
import { MemoryFilesystem } from '../../runtime/src/fs.js';
import { CompositorWindows } from '../../runtime/src/windows/compositor.js';

export const meta = {
  hosts: ['browser'], images: ['busybox'], timeout: 120,
  html: '<canvas id="a" width="320" height="200" style="position:absolute;left:0;top:0;width:160px;height:100px"></canvas>',
};

export default async function (t) {
  const { check, timeout, until } = t;
  await t.cdp({ method: 'Emulation.setDeviceMetricsOverride', width: 1000, height: 700, deviceScaleFactor: 1.5, mobile: false });
  const sys = new System({ baseUrl: t.baseUrl, debug: t.debug() });
  new MemoryFilesystem(sys).addTar(t.work('bb.tar.zst'));
  const out = new CompositorWindows(sys, { canvas: document.getElementById('a'), scale: 1 });
  await timeout(sys.boot(), 60000, 'boot');
  let d = null;
  await until(async () => (d = await out.describe({ pixels: false }))?.output === '320x200', 'scale 1: 320x200', 10000)
    .catch((e) => { throw new Error(`${e.message}: ${d?.output}`); });
  check('scale: 1 keeps the page\'s size and draws at 1', d.scale === 1, String(d.scale));
  document.getElementById('a').style.width = '300px';
  await new Promise((r) => setTimeout(r, 500));
  d = await out.describe({ pixels: false });
  check('and does not follow the CSS size', d.output === '320x200', d.output);
  await sys.shutdown();
  await t.cdp({ method: 'Emulation.setDeviceMetricsOverride', width: 1000, height: 700, deviceScaleFactor: 1, mobile: false });
}
