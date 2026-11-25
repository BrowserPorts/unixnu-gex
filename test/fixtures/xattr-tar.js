// A ustar archive of one file with extended attributes, for a page's
// filesystem (fs.js `addTar`): what a Darwin program's owner record needs
// (`user.gex.darwin.attrs`, as tests/darwin/run.sh's `place` writes it),
// which a single file laid by `addFiles` cannot carry.

/** A ustar archive of the one file `path` (relative), mode 0755, with a
 *  pax header that carries `xattrs` (`SCHILY.xattr.<name>`), as
 *  `tar --xattrs` writes one. */
export function tarWithXattrs(path, body, xattrs) {
  const enc = new TextEncoder();
  const header = (name, size, type) => {
    const h = new Uint8Array(512);
    const put = (at, len, text) => h.set(enc.encode(text).subarray(0, len), at);
    const oct = (at, len, v) => put(at, len, `${v.toString(8).padStart(len - 1, '0')}\0`);
    put(0, 100, name);
    oct(100, 8, 0o755);
    oct(108, 8, 0);
    oct(116, 8, 0);
    oct(124, 12, size);
    oct(136, 12, 0);
    h.fill(0x20, 148, 156);
    put(156, 1, type);
    put(257, 8, 'ustar\x0000');
    let sum = 0;
    for (const b of h) sum += b;
    put(148, 8, `${sum.toString(8).padStart(6, '0')}\0 `);
    return h;
  };
  const pad = (n) => new Uint8Array((512 - (n % 512)) % 512);
  let records = '';
  for (const [k, v] of Object.entries(xattrs)) {
    const rest = ` SCHILY.xattr.${k}=${v}\n`;
    let n = rest.length;
    while (`${n}${rest}`.length !== n) n = `${n}${rest}`.length;
    records += `${n}${rest}`;
  }
  const pax = enc.encode(records);
  const parts = [header(`PaxHeaders/${path}`, pax.length, 'x'), pax, pad(pax.length), header(path, body.length, '0'), body, pad(body.length), new Uint8Array(1024)];
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** The owner record tests/darwin/run.sh's `place` gives a program. */
export const ROOT_OWNED = { 'user.gex.darwin.attrs': 'uid=0 gid=0 mode=0755 flags=0' };
