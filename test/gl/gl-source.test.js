// MesaGl's `source`: Mesa's files are the page's, asked by name (the glue,
// the module, its cold part), not fetched from the system's baseUrl. A
// source that gives a broken module makes the start fail; the right bytes
// start Mesa, the glue and the module asked for once each (a page of its
// own: a page runs one system). Says so and passes where the browser has no
// WebGPU, or the build has no Mesa.
import { System } from '../../runtime/src/index.js';
import { MemoryFilesystem } from '../../runtime/src/fs.js';
import { CompositorWindows } from '../../runtime/src/windows/compositor.js';
import { MesaGl } from '../../runtime/src/gl.js';
import { SP_CODE, MP_CODE } from '../../hosts/browser/js/mode.mjs';

// The single-thread build's Mesa is its own (gex/st/).
const DIR = !MP_CODE || (SP_CODE && typeof SharedArrayBuffer !== 'function') ? '/gex/st/' : '/gex/';

export const meta = { hosts: ['browser'], images: ['busybox'], timeout: 240, html: `<canvas id="out" width="320" height="240"></canvas>` };

export default async function (t) {
  const { check, eq, timeout } = t;
  const adapter = await navigator.gpu?.requestAdapter().catch(() => null);
  if (!adapter) return t.skip('no WebGPU adapter here');
  const have = await fetch(`${DIR}gex-wgpu-replay.js`, { method: 'HEAD' }).then((r) => r.ok && !/html/.test(r.headers.get('content-type') ?? ''), () => false);
  if (!have) return t.skip('no Mesa in this build');
  const bytes = async (name) => {
    const r = await fetch(`${DIR}${name}`);
    return r.ok ? new Uint8Array(await r.arrayBuffer()) : null;
  };
  const system = async (source) => {
    const sys = new System({ baseUrl: t.baseUrl, debug: t.debug() });
    new MemoryFilesystem(sys).addTar(t.work('bb.tar.zst'));
    const gl = new MesaGl(sys, { source });
    new CompositorWindows(sys, { canvas: document.getElementById('out'), scale: 1 });
    await timeout(sys.boot(), 60000, 'boot');
    return { sys, gl };
  };

  // A broken module from the source: the device takes it, and fails.
  if (t.phase === 1) {
    const asked = [];
    const { sys, gl } = await system(async (name) => {
      asked.push(name);
      return name === 'gex-wgpu-replay.wasm' ? new Uint8Array([0, 0x61, 0x73, 0x6d, 9, 9, 9, 9]) : bytes(name);
    });
    const r = await timeout(gl.start().then(() => 'started', (e) => `failed: ${e?.message ?? e}`), 120000, 'Mesa (broken)');
    check('a broken module from the source fails the start', r.startsWith('failed'), r);
    check('the source was asked for the module', asked.includes('gex-wgpu-replay.wasm'), JSON.stringify(asked));
    await sys.shutdown();
    return t.reload();
  }

  // The right bytes: Mesa starts.
  {
    const asked = [];
    const { sys, gl } = await system(async (name) => { asked.push(name); return bytes(name); });
    const d = await timeout(gl.start(), 120000, 'Mesa');
    check(`start() from the source: ${d}`, /Mesa/.test(d), d);
    for (const n of ['gex-wgpu-replay.js', 'gex-wgpu-replay.wasm']) eq(`${n} asked once`, asked.filter((x) => x === n).length, 1);
    await sys.shutdown();
  }
}
