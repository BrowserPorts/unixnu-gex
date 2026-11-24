// tests/darwin/src/xspawn.c on the page: a Darwin process posix_spawns its
// own static image, which a RELEASE kernel refuses (parse_machfile's
// LOAD_FAILURE, EBADEXEC). In the page the refusal is the child's: its
// spawner's call stages it for a Worker of its own, the child's load there
// fails, the child ends as posix_spawn's failure ends it, and its start's
// answer wakes the spawner, whose call fails with EBADEXEC; wait4 then
// finds no child (ECHILD). The program is in the root's /var/tmp with its
// owner, group, mode and flags recorded, as tests/darwin/run.sh places it
// for gexc (the record a file the device's image does not have needs, for
// the platform profile's process-exec rules); the run is strict, so a
// report would stop it.
// (A spawned child that runs, its exit status and usage collected, needs a
// dynamic program, which needs dyld and the shared cache in the page.)
import { System } from '../../page/runtime/src/index.js';
import { MemoryFilesystem } from '../../page/runtime/src/fs.js';

export const meta = { hosts: ['browser'], arches: ['a64'], images: ['darwin-static'], timeout: 300 };

const PROG = '/private/var/tmp/xspawn';

/** A ustar archive of the one file `path` (relative), mode 0755, with a
 *  pax header that carries `xattrs` (`SCHILY.xattr.<name>`), as
 *  `tar --xattrs` writes one. */
function tarWithXattrs(path, body, xattrs) {
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

export default async function (t) {
  const { eq, timeout } = t;
  const image = await (await fetch(t.work('darwin-static.json'))).json();
  const boot = Object.fromEntries(image.boot.map((f) => [f, new URL(t.work(`darwin-static/boot/${f}`))]));
  const sys = new System({ baseUrl: t.baseUrl, arch: 'aarch64', darwin: { boot, strict: true }, debug: t.debug() });
  const fs = new MemoryFilesystem(sys);
  const body = new Uint8Array(await (await fetch(t.work('darwin-static/xspawn'))).arrayBuffer());
  fs.addTar(tarWithXattrs(PROG.slice(1), body, { 'user.gex.darwin.attrs': 'uid=0 gid=0 mode=0755 flags=0' }));
  await timeout(sys.boot(), 60000, 'boot');
  // The device's layout, as gexc's root has it: /var a link to private/var.
  await fs.rm('/var/tmp');
  await fs.rm('/var');
  await fs.symlink('private/var', '/var');
  await fs.chmod('/private/var/tmp', 0o1777);
  const r = await timeout(sys.run([PROG]), 120000, 'xspawn');
  await t.saveFile('console.txt', sys.state.console);
  const ctx = `stderr: ${r.stderr.slice(-2000)}\nconsole: ${sys.state.console.slice(-3000)}`;
  // gexc's, tests/darwin/run.sh's xspawn: EBADEXEC (85), then ECHILD (10).
  eq('the spawn of a static image fails with EBADEXEC, and no child is left', r.stdout, 'xspawn 85 10\n', ctx);
  eq('and it ends', r.code, 0, r.signal ? `signal ${r.signal}` : ctx);
  await sys.shutdown();
}
