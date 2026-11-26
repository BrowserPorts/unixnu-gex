// A ustar archive made in the test, for a layer of its own (`fs.addTar`).

const enc = new TextEncoder();

/** A ustar archive of `entries`, each `{ path, data }` (a file: bytes or a
 *  string), `{ path, dir: true }` or `{ path, link }` (a symbolic link to
 *  `link`), with `mode` and `mtime` (seconds) when given. */
export function tarOf(entries) {
  const out = [];
  for (const e of entries) {
    const data = e.data === undefined ? new Uint8Array(0) : typeof e.data === 'string' ? enc.encode(e.data) : e.data;
    const type = e.dir ? '5' : e.link !== undefined ? '2' : '0';
    const h = new Uint8Array(512);
    const put = (at, s) => h.set(enc.encode(s), at);
    const oct = (v, n) => `${v.toString(8).padStart(n - 1, '0')}\0`;
    put(0, e.path.replace(/^\//, '') + (e.dir ? '/' : ''));
    put(100, oct(e.mode ?? (e.dir ? 0o755 : e.link !== undefined ? 0o777 : 0o644), 8));
    put(108, oct(0, 8));
    put(116, oct(0, 8));
    put(124, oct(type === '0' ? data.length : 0, 12));
    put(136, oct(e.mtime ?? 1_700_000_000, 12));
    h.fill(0x20, 148, 156);
    put(156, type);
    if (e.link !== undefined) put(157, e.link);
    put(257, 'ustar\0');
    put(263, '00');
    let sum = 0;
    for (const b of h) sum += b;
    put(148, `${sum.toString(8).padStart(6, '0')}\0 `);
    out.push(h);
    if (type === '0') out.push(data, new Uint8Array((512 - (data.length % 512)) % 512));
  }
  out.push(new Uint8Array(1024));
  const b = new Uint8Array(out.reduce((n, x) => n + x.length, 0));
  let at = 0;
  for (const x of out) { b.set(x, at); at += x.length; }
  return b;
}
