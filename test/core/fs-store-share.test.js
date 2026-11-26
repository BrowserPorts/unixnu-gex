// A copy of a file in an OPFSFilesystem's store (copy_file_range of all of
// it, the busybox image's rt-clonecopy: as coreutils' cp and Wine's CopyFile
// ask) shares the source's blocks until written (gex_kernel::vfs::blocks):
//   1. 96 MiB written, copied, the copy copied again; a write to each side
//      (one across a 64 KiB block's end), the source removed; synced and
//      stopped: the store holds the bytes about once, not three times;
//   2. after a reload both copies read back with their own writes; a write
//      to one leaves the other as it was; that other removed;
//   3. after a reload the last copy is whole.
import { System } from '../../runtime/src/index.js';
import { OPFSFilesystem } from '../../runtime/src/fs.js';

export const meta = { hosts: ['browser'], images: ['busybox'], timeout: 600 };

const ENV = { PATH: '/bin:/usr/bin', HOME: '/root' };
const MB = 1 << 20;
const BIG = 96 * MB;

/** No two 64 KiB blocks alike. */
function pattern(n) {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = (i * 31 + (i >>> 16) * 7) & 255;
  return b;
}

/** `pattern(BIG)` with each [offset, text] written over it. */
function want(...edits) {
  const b = pattern(BIG);
  for (const [at, s] of edits) b.set(new TextEncoder().encode(s), at);
  return b;
}

function same(a, b) {
  if (a.length !== b.length) return `${a.length} bytes, not ${b.length}`;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return `byte ${i} is ${a[i]}, not ${b[i]}`;
  return '';
}

async function sh(t, sys, cmd) {
  const r = await t.timeout(sys.run(['sh', '-c', cmd], { env: ENV }), 300000, cmd.slice(0, 40));
  return { code: r.code, out: (r.stdout + r.stderr).trim() };
}

const poke = (path, at, s) => `rt-clonecopy -w ${path} ${at} ${s}`;

const EDGE = [65534, 'EDGE'];
const COPY = [70000, 'COPY'];
const C2 = [200000, 'C2'];
const CC = [70000, 'cccc'];

export default async function (t) {
  const { eq, check, timeout } = t;
  const STORE = `gex-test-share-${t.arch}`;
  if (t.phase === 1) await OPFSFilesystem.erase(STORE);
  const sys = new System({ baseUrl: t.baseUrl, debug: t.debug() });
  const fs = new OPFSFilesystem(sys, { name: STORE, cache: 16 });
  fs.addTar(t.work('bb.tar.zst'));
  await timeout(sys.boot(), 60000, 'boot');
  const is = async (what, path, bytes) => {
    const why = same(await fs.readFile(path), bytes);
    check(what, !why, why);
  };

  if (t.phase === 1) {
    await fs.writeFile('/root/a', pattern(BIG));
    const ab = await sh(t, sys, 'rt-clonecopy /root/a /root/b');
    eq('a copied to b', ab.out, `copied ${BIG}`);
    eq('writes to b, one across a block\'s end', (await sh(t, sys, `${poke('/root/b', ...EDGE)} && ${poke('/root/b', ...COPY)}`)).code, 0);
    eq('and to a', (await sh(t, sys, poke('/root/a', 5, 'SRC'))).code, 0);
    eq('b copied to c', (await sh(t, sys, 'rt-clonecopy /root/b /root/c')).out, `copied ${BIG}`);
    eq('a write to c', (await sh(t, sys, poke('/root/c', ...C2))).code, 0);
    await is('a has its own write only', '/root/a', want([5, 'SRC']));
    await is('b has its own writes only', '/root/b', want(EDGE, COPY));
    await is('c has b\'s and its own', '/root/c', want(EDGE, COPY, C2));
    eq('a removed', (await sh(t, sys, 'rm /root/a')).code, 0);
    await sys.sync();
    await sys.shutdown();
    // Three files of 96 MiB: about 96 MiB of blocks (the store grows 64
    // MiB ahead), not 288.
    const size = await fs.size();
    check(`the store holds the bytes about once (${(size / MB).toFixed(0)} MiB)`, size < 192 * MB, `${size}`);
    return t.reload();
  }
  if (t.phase === 2) {
    await is('after a reload: b', '/root/b', want(EDGE, COPY));
    await is('after a reload: c', '/root/c', want(EDGE, COPY, C2));
    eq('a is gone', (await sh(t, sys, 'test -e /root/a && echo there || echo gone')).out, 'gone');
    eq('a write to c', (await sh(t, sys, poke('/root/c', ...CC))).code, 0);
    await is('b as it was', '/root/b', want(EDGE, COPY));
    eq('b removed', (await sh(t, sys, 'rm /root/b')).code, 0);
    await is('c after b went', '/root/c', want(EDGE, CC, C2));
    await sys.sync();
    await sys.shutdown();
    return t.reload();
  }
  await is('after a second reload: c', '/root/c', want(EDGE, CC, C2));
  eq('b is gone', (await sh(t, sys, 'test -e /root/b && echo there || echo gone')).out, 'gone');
  await sys.shutdown();
  await fs.erase();
}
