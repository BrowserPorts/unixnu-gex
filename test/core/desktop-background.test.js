// CompositorWindows' `background`: the desktop's colour, and an image over
// it once it is in, the image anchored at the edge that always shows.
import { System } from '../../runtime/src/index.js';
import { MemoryFilesystem } from '../../runtime/src/fs.js';
import { CompositorWindows } from '../../runtime/src/windows/compositor.js';

export const meta = {
  hosts: ['browser'], images: ['busybox'], timeout: 120,
  html: '<canvas id="a" width="160" height="120" style="position:absolute;left:0;top:0"></canvas>',
};

const near = (px, want) => px.slice(0, 3).every((v, i) => Math.abs(v - want[i]) <= 3);

export default async function (t) {
  const { check, timeout, until } = t;
  // The image: its top half red, its bottom half blue, twice the output's
  // height, anchored at the top: only red shows.
  const img = new OffscreenCanvas(160, 240);
  const g = img.getContext('2d');
  g.fillStyle = '#ff0000'; g.fillRect(0, 0, 160, 120);
  g.fillStyle = '#0000ff'; g.fillRect(0, 120, 160, 120);
  const blob = await img.convertToBlob({ type: 'image/png' });
  const sys = new System({ baseUrl: t.baseUrl, debug: t.debug() });
  let bad = '';
  try { new CompositorWindows(sys, { canvas: document.createElement('canvas'), background: 'teal' }); } catch (e) { bad = e.message; }
  check('a colour not #rrggbb is refused', /#rrggbb/.test(bad), bad);
  new MemoryFilesystem(sys).addTar(t.work('bb.tar.zst'));
  let release;
  const held = new Promise((r) => { release = r; });
  // The image is had only once the colour has been seen.
  const url = URL.createObjectURL(blob);
  const origFetch = globalThis.fetch;
  globalThis.fetch = async (u, o) => (String(u) === url ? (await held, origFetch(u, o)) : origFetch(u, o));
  new CompositorWindows(sys, { canvas: document.getElementById('a'), background: { color: '#20c040', image: url, anchor: 'top' } });
  await timeout(sys.boot(), 60000, 'boot');
  await until(async () => near(await t.pixel(80, 60), [0x20, 0xc0, 0x40]), 'the desktop\'s colour', 20000)
    .catch(async (e) => { throw new Error(`${e.message}: ${await t.pixel(80, 60)}`); });
  check('the colour shows until the image is in', true);
  release();
  await until(async () => near(await t.pixel(80, 100), [255, 0, 0]), 'the image', 20000)
    .catch(async (e) => { throw new Error(`${e.message}: ${await t.pixel(80, 100)}`); });
  check('the image, anchored at its top', near(await t.pixel(80, 10), [255, 0, 0]) && near(await t.pixel(80, 110), [255, 0, 0]), String(await t.pixel(80, 110)));
  globalThis.fetch = origFetch;
  URL.revokeObjectURL(url);
  await sys.shutdown();
}
