/**
 * Does a surface's glass (`gex_glass_v1`) reach the compositor whole?
 *
 * A client publishes a framed window with glass through `WlProxy`, as the shim
 * does, with gex-wayland's record layout (`REC_GLASS`, after every other
 * word): its rectangles, colorization, frame buttons, afterglow and client
 * area must read back (`readScene`), with the words before them untouched. Its
 * caption icon (`set_icon`) is an address in the process's memory, which a
 * compositor with pixel buffers never holds: the proxy copies the icon into
 * the surface's region of its buffer, on every publish (it changes without a
 * commit), and the page's mirror of a Worker's arena carries it likewise.
 * dwm-frame.js's `attachDwmIcon` reads it from either.
 *
 * Usage: node test/fixtures/page/wl-glass.mjs
 */
import { pathToFileURL as gexPathToFileURL } from 'node:url';
import { join as gexJoin } from 'node:path';
// gex: the checkout these fixtures are in, or GEX_ROOT.
const GEX_ROOT = process.env.GEX_ROOT || gexJoin(import.meta.dirname, '..', '..', '..');
const gexUrl = (p) => gexPathToFileURL(gexJoin(GEX_ROOT, p)).href;
const wl = await import(gexUrl('hosts/browser/js/wl-bridge.mjs'));
const { attachDwmIcon } = await import(gexUrl('runtime/src/host/dwm-frame.js'));
const {
  makeWlChannel, WlProxy, readScene, mirrorState, mirrorTake, mirrorChannel, mirrorApply,
  REC, R_CLIENT, R_SURFACE, R_ROLE, R_WIDTH, R_HEIGHT, R_ADDR, R_STRIDE, R_SERIAL, R_DAMAGE_W, R_DAMAGE_H,
  R_TITLE, R_PID, R_GLASS, R_GLASS_ARGB, R_GLASS_BALANCE, R_GLASS_RECTS, R_GLASS_FRAME, R_GLASS_AFTERGLOW,
  R_GLASS_CLIENT, R_GLASS_ICON, ICON_BYTES, ROLE_TOPLEVEL,
} = wl;

let failed = 0;
const check = (what, cond, detail = '') => {
  console.log(`${cond ? 'ok' : 'FAIL'} ${what}${!cond && detail ? ` (${detail})` : ''}`);
  if (!cond) failed++;
};

// gex-wayland's layout (`crates/gex-wayland`: REC_GLASS 119, Glass::WORDS 40,
// REC_GLASS_ICON 159, REC 160; its a_windows_glass_reaches_its_record test).
check('the record is gex-wayland\'s: glass at 119, the icon at 159, 160 words',
  R_GLASS === 119 && R_GLASS_FRAME === 138 && R_GLASS_AFTERGLOW === 154 && R_GLASS_CLIENT === 155
    && R_GLASS_ICON === 159 && REC === 160 && R_GLASS > R_PID,
  `R_GLASS ${R_GLASS} R_GLASS_ICON ${R_GLASS_ICON} REC ${REC}`);

const W = 32, H = 24;
const RECS = 0, PIX = 4096, ICON = 16384;
/** One framed window with glass, its pixels and icon in `mem`. */
function write(mem, { serial = 1, iconSeed = 1 } = {}) {
  const bytes = new Uint8Array(mem.buffer);
  for (let i = 0; i < W * H * 4; i++) bytes[PIX + i] = (i * 7) & 0xff;
  for (let i = 0; i < ICON_BYTES; i++) bytes[ICON + i] = (i * iconSeed + 3) & 0xff;
  // Opaque white in the icon's first pixel and a premultiplied half-grey in
  // its second, which attachDwmIcon makes straight.
  bytes.set([255, 255, 255, 255, 64, 64, 64, 128], ICON);
  const r = new Int32Array(mem.buffer, RECS, REC);
  r.fill(0);
  r[R_CLIENT] = 1; r[R_SURFACE] = 6; r[R_ROLE] = ROLE_TOPLEVEL;
  r[R_WIDTH] = W; r[R_HEIGHT] = H; r[R_ADDR] = PIX; r[R_STRIDE] = W * 4;
  r[R_SERIAL] = serial; r[R_DAMAGE_W] = W; r[R_DAMAGE_H] = H;
  r.set(new Int32Array(new Uint8Array([...new TextEncoder().encode('Computer'), 0, 0, 0, 0]).buffer.slice(0, 8)), R_TITLE);
  r[R_PID] = 4242;
  r[R_GLASS] = 2;
  r[R_GLASS_ARGB] = 0x6b74b8fc;
  r[R_GLASS_BALANCE] = 8 | (43 << 8) | (31 << 16);
  r.set([0, 0, W, 20, 0, 20, 4, H - 20], R_GLASS_RECTS);
  r[R_GLASS_FRAME] = 1 | 2;
  r.set([W - 10, 0, 10, 8, 2, W - 20, 0, 10, 8, 1, W - 30, 0, 10, 8, 4], R_GLASS_FRAME + 1);
  r[R_GLASS_AFTERGLOW] = 0x0074b8fc;
  r.set([4, 20, W - 8, H - 24], R_GLASS_CLIENT);
  r[R_GLASS_ICON] = ICON;
}

function glassReads(what, s) {
  const g = s?.glass;
  check(`${what}: the glass reads back`, !!g
    && JSON.stringify(g.rects) === JSON.stringify([{ x: 0, y: 0, w: W, h: 20 }, { x: 0, y: 20, w: 4, h: H - 20 }])
    && g.argb === 0x6b74b8fc && g.balance === 8 && g.blurBalance === 43 && g.afterglowBalance === 31
    && g.afterglow === 0x0074b8fc && g.frame === 3
    && JSON.stringify(g.close) === JSON.stringify({ x: W - 10, y: 0, w: 10, h: 8, state: 2 }) && g.min.state === 4
    && JSON.stringify(g.client) === JSON.stringify({ x: 4, y: 20, w: W - 8, h: H - 24 }),
  JSON.stringify(g));
  check(`${what}: the words before the glass are the window's`, s?.title === 'Computer' && s?.pid === 4242,
    `${s?.title} ${s?.pid}`);
}

function iconReads(what, view, s, mem) {
  const at = s?.glass?.icon;
  const want = new Uint8Array(mem.buffer, ICON, ICON_BYTES);
  const got = at && view && at + ICON_BYTES <= view.length ? view.subarray(at, at + ICON_BYTES) : null;
  check(`${what}: the icon is where the record says`, !!got && got.every((v, i) => v === want[i]),
    `at ${at}, ${view?.length ?? 'no'} bytes`);
  attachDwmIcon(s.glass, view);
  const px = s.glass.iconPixels;
  check(`${what}: attachDwmIcon has it, straight`, !!px && px[0] === 255 && px[3] === 255
    && Math.abs(px[4] - 128) <= 1 && px[7] === 128 && s.glass.iconKey !== 0,
  px ? `${[...px.subarray(0, 8)]}` : 'none');
  return s.glass.iconKey;
}

// 1. Pixel buffers (the multi-thread page): the proxy copies, the record
//    names the buffer.
{
  const channel = makeWlChannel();
  check('a channel with pixel buffers', !!channel.pixels);
  const bufs = new Map();
  const proxy = new WlProxy(channel, () => {}, () => 7);
  proxy.onPixels = ({ id, buffer }) => bufs.set(id, new Uint8Array(buffer));
  const mem = new WebAssembly.Memory({ initial: 1, maximum: 1, shared: true });
  write(mem);
  proxy.publish(mem, RECS, 1);
  let s = readScene(channel).surfaces[0];
  glassReads('pixel buffers', s);
  const view = bufs.get(s?.pix);
  const pixOk = view && new Uint8Array(mem.buffer, PIX, W * H * 4).every((v, i) => v === view[s.addr + i]);
  check('pixel buffers: the surface\'s own pixels are as they were', !!pixOk);
  const k1 = iconReads('pixel buffers', view, s, mem);
  // A new icon with no commit: the same serial.
  write(mem, { serial: 1, iconSeed: 5 });
  proxy.publish(mem, RECS, 1);
  s = readScene(channel).surfaces[0];
  const k2 = iconReads('pixel buffers, a new icon and no commit', bufs.get(s?.pix), s, mem);
  check('pixel buffers: the new icon\'s key is another', k1 !== k2);
  // No icon: none read.
  new Int32Array(mem.buffer, RECS, REC)[R_GLASS_ICON] = 0;
  proxy.publish(mem, RECS, 1);
  s = readScene(channel).surfaces[0];
  check('pixel buffers: no icon is none', s?.glass?.icon === 0);
}

// 2. A Worker's arena mirrored to the page (the single-thread build): no
//    pixel buffers in the Worker, the page's buffer per surface.
{
  const channel = { arena: makeWlChannel().arena };
  const proxy = new WlProxy(channel, () => {}, () => 7);
  const mem = new WebAssembly.Memory({ initial: 1, maximum: 1, shared: true });
  write(mem);
  proxy.publish(mem, RECS, 1);
  const st = mirrorState();
  const page = mirrorChannel(() => {});
  const take = () => {
    const t = mirrorTake(channel, st, (token) => (token === 7 ? new Uint8Array(mem.buffer) : null));
    if (t) mirrorApply(page, t.update, () => {});
  };
  take();
  let s = readScene(page).surfaces[0];
  glassReads('the mirror', s);
  const k1 = iconReads('the mirror', page.buffers.get(s?.pix)?.view, s, mem);
  write(mem, { serial: 1, iconSeed: 9 });
  proxy.publish(mem, RECS, 1);
  take();
  s = readScene(page).surfaces[0];
  const k2 = iconReads('the mirror, a new icon and no commit', page.buffers.get(s?.pix)?.view, s, mem);
  check('the mirror: the new icon\'s key is another', k1 !== k2);
}

if (failed) {
  console.error(`wl glass check FAILED: ${failed}`);
  process.exit(1);
}
