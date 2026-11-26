// fs.setLazySource: the page's own module answers the programs' reads of
// lazy files, by keys of its own; bytes it hands over ahead (ctx.put) are
// read without asking it; a read it fails is EIO to the program; its port
// reaches the page.
import { System } from '../../runtime/src/index.js';
import { MemoryFilesystem } from '../../runtime/src/fs.js';

export const meta = { hosts: ['browser'], images: ['busybox'], timeout: 180, single: 'a lazy source needs the default build' };

// The source: each file's byte i is (i * 31 + seed + the key's length) & 0xff.
const SOURCE = `
let seed = 0, port = null;
const asked = {};
const byte = (key, i) => (i * 31 + seed + key.length) & 0xff;
const make = (key, from, len) => { const b = new Uint8Array(len); for (let i = 0; i < len; i++) b[i] = byte(key, from + i); return b; };
export async function init(ctx) {
  seed = ctx.data.seed;
  port = ctx.port;
  port.onmessage = () => port.postMessage({ ...asked });
  ctx.put('ahead', 0, make('ahead', 0, 200000));
}
export async function read(key, offset, length) {
  asked[key] = (asked[key] ?? 0) + 1;
  if (key === 'bad') throw new Error('no such bytes');
  await new Promise((r) => setTimeout(r, 5));
  return make(key, offset, length);
}
`;

const expected = (key, size, seed) => {
  const b = new Uint8Array(size);
  for (let i = 0; i < size; i++) b[i] = (i * 31 + seed + key.length) & 0xff;
  return b;
};

export default async function (t) {
  const { eq, check, timeout } = t;
  const sys = new System({ baseUrl: t.baseUrl, debug: t.debug() });
  const fs = new MemoryFilesystem(sys);
  const url = URL.createObjectURL(new Blob([SOURCE], { type: 'text/javascript' }));
  fs.setLazySource(url, { data: { seed: 7 } });
  let threw = '';
  try { fs.setLazySource(url); } catch (e) { threw = e.message; }
  check('a second source is refused', /already/.test(threw), threw);
  fs.addTar(t.work('bb.tar.zst'));
  const files = [['/data/big', 3 << 20, 'gen:big'], ['/data/small', 1000, 'gen:small'], ['/data/ahead', 200000, 'ahead'], ['/data/bad', 10, 'bad']];
  fs.addTar(null, { lazy: files });
  await timeout(sys.boot(), 60000, 'boot');
  threw = '';
  try { fs.setLazySource(url); } catch (e) { threw = e.message; }
  check('no source after boot', /before boot/.test(threw), threw);
  const env = { PATH: '/bin:/usr/bin', HOME: '/root' };
  const sh = (cmd) => timeout(sys.run(['sh', '-c', cmd], { env }), 60000, cmd);

  for (const [path, size, key] of files.slice(0, 3)) {
    const r = await sh(`cat ${path} > /tmp/copy`);
    const got = await fs.readFile('/tmp/copy');
    const want = expected(key, size, 7);
    check(`${path} reads as the source gives it`, r.code === 0 && got.length === size && got.every((v, i) => v === want[i]), `code ${r.code}, ${got.length} bytes ${r.stderr.trim()}`);
  }
  eq('a size from the list', (await sh('wc -c < /data/big')).stdout.trim(), String(3 << 20));
  const bad = await sh('cat /data/bad');
  check('a read the source fails is an error to the program', bad.code !== 0, `code ${bad.code}: ${bad.stderr.trim()}`);

  const port = fs.lazyPort;
  check('the page has the source\'s port', port instanceof MessagePort);
  const asked = await timeout(new Promise((r) => { port.onmessage = (e) => r(e.data); port.postMessage('asked?'); }), 10000, 'the port');
  check('the big file was asked for in parts', (asked['gen:big'] ?? 0) >= 2, JSON.stringify(asked));
  eq('the file put ahead was never asked for', asked.ahead ?? 0, 0);
  URL.revokeObjectURL(url);
  await sys.shutdown();
}
