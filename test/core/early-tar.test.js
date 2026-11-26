// fs.addTar(stream, { early: true }): an archive whose first entry is its
// index is named whole once the index is in, and the programs start before
// its end: a file laid reads, a file still to come is there to a lookup and
// waits for its bytes, and reads once they come.
import { System } from '../../runtime/src/index.js';
import { MemoryFilesystem } from '../../runtime/src/fs.js';

export const meta = { hosts: ['browser', 'node'], images: ['busybox'], timeout: 120, single: 'laid whole before the program starts (no early start: a read cannot wait in the one Worker)' };

const enc = new TextEncoder();

/** A ustar archive of `entries` (`[path, bytes]`, files only). */
function tarOf(entries) {
  const out = [];
  for (const [path, data] of entries) {
    const h = new Uint8Array(512);
    const put = (at, s) => h.set(enc.encode(s), at);
    put(0, path.replace(/^\//, ''));
    put(100, '0000644\0');
    put(108, '0000000\0');
    put(116, '0000000\0');
    put(124, `${data.length.toString(8).padStart(11, '0')}\0`);
    put(136, '00000000000\0');
    h.fill(0x20, 148, 156);
    h[156] = 0x30;
    put(257, 'ustar\0');
    put(263, '00');
    let sum = 0;
    for (const b of h) sum += b;
    put(148, `${sum.toString(8).padStart(6, '0')}\0 `);
    out.push(h, data, new Uint8Array((512 - (data.length % 512)) % 512));
  }
  out.push(new Uint8Array(1024));
  const b = new Uint8Array(out.reduce((n, x) => n + x.length, 0));
  let at = 0;
  for (const x of out) { b.set(x, at); at += x.length; }
  return b;
}

/** The index's records (hosts/kernel `k_fs_seed`: 6 a directory, 5 a file
 *  still to come). */
function indexOf(dirs, files) {
  const out = [];
  const u32 = (v) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, v, true); out.push(b); };
  const u64 = (v) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(v), true); out.push(b); };
  const text = (s) => { const b = enc.encode(s); u32(b.length); out.push(b); };
  for (const p of dirs) { out.push(Uint8Array.of(6)); u32(0o755); u64(1_700_000_000); text(p); }
  for (const [p, d] of files) { out.push(Uint8Array.of(5)); u32(0o644); u64(d.length); u64(1_700_000_000); text(p); }
  const b = new Uint8Array(out.reduce((n, x) => n + x.length, 0));
  let at = 0;
  for (const x of out) { b.set(x, at); at += x.length; }
  return b;
}

export default async function (t) {
  const { eq, check, timeout } = t;
  const sys = new System({ baseUrl: t.baseUrl, debug: t.debug() });
  const fs = new MemoryFilesystem(sys);
  fs.addTar(t.work('bb.tar.zst'));
  const early = enc.encode('early\n');
  const late = new Uint8Array(3 << 20).map((_, i) => (i * 7) & 0xff);
  const files = [['/opt/e/early', early], ['/opt/e/late', late]];
  const all = tarOf([['/.gex-index', indexOf(['/opt', '/opt/e'], files)], ...files]);
  // Everything up to the late file's body, then the rest once released.
  const cut = all.length - 1024 - late.length;
  let release;
  const gate = new Promise((r) => { release = r; });
  const stream = new ReadableStream({
    async start(c) {
      c.enqueue(all.slice(0, cut));
      await gate;
      c.enqueue(all.slice(cut));
      c.close();
    },
  });
  fs.addTar(stream, { early: true });
  let threw = '';
  try { fs.addTar(stream, { early: true }); } catch (e) { threw = e.message; }
  check('one early tar per filesystem', /one per filesystem/.test(threw), threw);
  await timeout(sys.boot(), 60000, 'boot before the archive\'s end');
  const env = { PATH: '/bin:/usr/bin', HOME: '/root' };
  const sh = (cmd) => timeout(sys.run(['sh', '-c', cmd], { env }), 60000, cmd);
  eq('a file laid reads', (await sh('cat /opt/e/early')).stdout, 'early\n');
  eq('a file still to come has its size', (await sh('ls -ln /opt/e/late')).stdout.trim().split(/\s+/)[4], String(late.length));
  eq('and its folder lists it', (await sh('ls /opt/e')).stdout.split(/\s+/).filter(Boolean).sort().join(' '), 'early late');
  let done = false;
  const wait = sh('wc -c < /opt/e/late').then((r) => { done = true; return r; });
  await new Promise((r) => setTimeout(r, 500));
  check('a read of it waits', !done);
  release();
  eq('and reads once it comes', (await wait).stdout.trim(), String(late.length));
  const got = await fs.readFile('/opt/e/late');
  check('its bytes', got.length === late.length && got.every((v, i) => v === late[i]));
  await sys.shutdown();
}
