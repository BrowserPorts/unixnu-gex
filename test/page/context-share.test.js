// Two contexts of one client on the page's Mesa (op::CONTEXT_CURRENT): the
// objects are one share group's and the state is each context's own. Context
// 1 renders green into a framebuffer object on a texture of its own; context
// 0, which set its own clear colour, viewport and blend enable first, draws
// that texture over its window and reads the window back: green, and its own
// state as it left it. With every context one host context, context 1's
// viewport and blend enable were context 0's too (a Qt Quick panel, drawn in a
// context of its own, composited black). The mt build's module unsplit (the
// `mesa-cold` image), or the st build's without SharedArrayBuffer.

export const meta = { hosts: ['browser'], arches: ['x86'], images: ['mesa-cold'], timeout: 600 };

const W = 64, H = 48;

/** One batch: [opcode, words...] each, as the guest writes them. */
function batch(cmds) {
  const words = cmds.flatMap(([op, ...args]) => [op, (args.length + 2) * 4, ...args]);
  const b = new Uint8Array(words.length * 4);
  const v = new DataView(b.buffer);
  words.forEach((w, i) => v.setUint32(i * 4, w >>> 0, true));
  return b;
}
const f = (x) => { const v = new DataView(new ArrayBuffer(4)); v.setFloat32(0, x, true); return v.getUint32(0, true); };

/** A canvas whose WebGPU context draws into a texture (as mesa-cold's). */
function textureCanvas() {
  const canvas = new OffscreenCanvas(W, H);
  let config = null;
  let texture = null;
  const context = {
    canvas,
    configure(c) { config = c; },
    unconfigure() { config = null; },
    getConfiguration() { return config; },
    getCurrentTexture() {
      if (!texture || texture.width !== canvas.width || texture.height !== canvas.height) {
        texture?.destroy();
        texture = config.device.createTexture({
          size: [canvas.width, canvas.height], format: config.format, viewFormats: config.viewFormats ?? [],
          usage: (config.usage ?? GPUTextureUsage.RENDER_ATTACHMENT) | GPUTextureUsage.TEXTURE_BINDING | GPUTextureUsage.COPY_DST | GPUTextureUsage.COPY_SRC,
        });
      }
      return texture;
    },
  };
  const own = canvas.getContext.bind(canvas);
  canvas.getContext = (type, o) => (type === 'webgpu' ? context : own(type, o));
  return canvas;
}

export default async function (t) {
  const build = typeof SharedArrayBuffer === 'function' ? 'mt' : 'st';
  const mesa = t.work(`mesa-cold/${build}/whole/gex-wgpu-replay.js`);
  const adapter = await navigator.gpu.requestAdapter();
  if (!t.check('a WebGPU adapter', !!adapter)) return;
  const device = await adapter.requestDevice();
  let validation = 0;
  device.addEventListener('uncapturederror', (e) => { if (validation++ < 5) t.say(`  WebGPU validation: ${e.error?.message}`); });
  const glCanvas = textureCanvas();
  const qs = document.querySelector.bind(document);
  document.querySelector = (s) => (String(s).includes('gex-gl') ? glCanvas : qs(s));
  const { default: create } = await import(/* @vite-ignore */ mesa);
  const m = await create({ preinitializedWebGPUDevice: device, mainScriptUrlOrBlob: mesa, locateFile: (x) => new URL(x, mesa).href, print: () => {}, printErr: () => {} });
  const submit = WebAssembly.promising(m.gexGlSubmitRaw);
  if (!t.check('gex_gl_init', m._gex_gl_init(W, H) === 0)) return;
  const ptr = m._malloc(1 << 16);
  let rejects = 0;
  const send = async (cmds) => { const b = batch(cmds); m.HEAPU8.set(b, ptr); if ((await submit(ptr, b.length, 0)) !== 0) rejects++; };
  const reply = () => m.HEAPU8.slice(m._gex_gl_reply_data(), m._gex_gl_reply_data() + m._gex_gl_reply_len());
  /** glGetIntegerv, in a batch of its own: the reply is its blob alone. */
  const ints = async (pname) => { await send([[130, pname]]); const r = reply(); return [...new Int32Array(r.buffer, 4, new DataView(r.buffer).getUint32(0, true) / 4)]; };
  const GL_TEXTURE_2D = 0x0DE1, GL_FRAMEBUFFER = 0x8D40, GL_BLEND = 0x0BE2, GL_VIEWPORT = 0x0BA2;
  const TEX_COORD2F = 10673, VERTEX2F = 11057, TEX_ENVI = 10740;
  const CONTEXT_CURRENT = 9, ctx = (id) => [CONTEXT_CURRENT, id, 1, 2, 1, 1];
  await send([
    [1, 1, 2, 1, 1], // CONTEXT_CREATE: desktop 2.1, compatibility (context 0)
    [5, 0, 7, 1, 1], // SURFACE_ATTACH: a Wayland surface, handle 1
    [2, W, H], // SURFACE_RESIZE
    [16, f(1), f(0), f(0), f(1)], // context 0's clear colour: red
    [18, 1, 2, 30, 40], // its viewport
    [20, GL_BLEND], // blend off
    ctx(1),
    [18, 5, 6, 7, 8], [19, GL_BLEND], // context 1's own viewport and blend
    [96, 1, 50], [98, GL_TEXTURE_2D, 50], // a texture, 50
    [101, GL_TEXTURE_2D, 0, 0x8058, W, H, 0, 0x1908, 0x1401, 0, 0, 0, 0], // RGBA8, no data
    [100, GL_TEXTURE_2D, 0x2801, 0x2600], [100, GL_TEXTURE_2D, 0x2800, 0x2600], // NEAREST
    [103, 1, 60], [105, GL_FRAMEBUFFER, 60], [107, GL_FRAMEBUFFER, 0x8CE0, GL_TEXTURE_2D, 50, 0],
    [18, 0, 0, W, H], [16, f(0), f(200 / 255), f(0), f(1)], [17, 0x4000], // green into it
    [105, GL_FRAMEBUFFER, 0],
    [18, 5, 6, 7, 8],
    ctx(0),
  ]);
  const vp = await ints(GL_VIEWPORT);
  const blend = await ints(GL_BLEND);
  t.check("context 0's viewport is its own after context 1 set one", vp.join() === '1,2,30,40', vp.join());
  t.check("context 0's blend enable is its own after context 1 enabled it", blend[0] === 0, String(blend[0]));
  await send([
    [18, 0, 0, W, H], [17, 0x4000], // red, context 0's clear colour
    [19, GL_TEXTURE_2D], [98, GL_TEXTURE_2D, 50], [TEX_ENVI, 0x2300, 0x2200, 0x1E01], // GL_REPLACE
    [173, 7], // GL_QUADS
    [TEX_COORD2F, f(0), f(0)], [VERTEX2F, f(-1), f(-1)], [TEX_COORD2F, f(1), f(0)], [VERTEX2F, f(1), f(-1)],
    [TEX_COORD2F, f(1), f(1)], [VERTEX2F, f(1), f(1)], [TEX_COORD2F, f(0), f(1)], [VERTEX2F, f(-1), f(1)],
    [174], [20, GL_TEXTURE_2D],
  ]);
  await send([[128, 0, 0, W, H, 0x1908, 0x1401, 0, 0, 0]]); // READ_PIXELS, RGBA bytes
  await device.queue.onSubmittedWorkDone();
  const px = reply().subarray(8);
  if (!t.eq('the read-back is the window', px.length, W * H * 4)) return;
  const at = (x, y) => [...px.subarray((y * W + x) * 4, (y * W + x) * 4 + 3)];
  t.check("context 0 samples the texture context 1 rendered: green", Math.abs(at(W / 2, H / 2)[1] - 200) <= 2 && at(W / 2, H / 2)[0] < 3, String(at(W / 2, H / 2)));
  await send([ctx(1)]);
  const vp1 = await ints(GL_VIEWPORT);
  const blend1 = await ints(GL_BLEND);
  t.check("context 1's viewport and blend enable are still its own", vp1.join() === '5,6,7,8' && blend1[0] === 1, `${vp1.join()} blend ${blend1[0]}`);
  await send([ctx(0), [10, 1]]); // CONTEXT_DROP 1
  const vp0 = await ints(GL_VIEWPORT);
  t.check('context 0 is current after context 1 is dropped', vp0.join() === `0,0,${W},${H}`, vp0.join());
  t.check('no rejected batch or validation error', rejects === 0 && validation === 0, `${rejects} rejected, ${validation} validation errors`);
}
