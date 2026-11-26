// write(2) with a count far past a small buffer, and writes far past a
// file's end (test/fixtures/programs/big-write.c), from x86-64's and
// aarch64's own programs and wasm32's, on an in-memory root and, in the
// browser, after a reload (a page runs one system), on an OPFSFilesystem's
// store (block lists): each case gives a count or an error, and the kernel
// lives on (a "capacity overflow" panic there took every process down).
import { System } from '../../runtime/src/index.js';
import { MemoryFilesystem, OPFSFilesystem } from '../../runtime/src/fs.js';

export const meta = { hosts: ['browser', 'node'], images: ['busybox', 'native-progs'], timeout: 300 };

export default async function (t) {
  const { eq, timeout } = t;
  const STORE = `gex-test-big-write-${t.arch}`;
  const browser = typeof navigator !== 'undefined' && !!navigator.storage?.getDirectory;
  const store = browser && t.phase === 2;
  if (store) await OPFSFilesystem.erase(STORE).catch(() => {});
  const where = store ? 'on a store' : 'in memory';
  const sys = new System({ baseUrl: t.baseUrl, debug: t.debug() });
  const fs = store ? new OPFSFilesystem(sys, { name: STORE, cache: 16 }) : new MemoryFilesystem(sys);
  fs.addTar(t.work('bb.tar.zst'));
  fs.addFiles({ '/g/big-write': new URL(t.work(`big-write.${t.arch === 'x86' ? 'x86' : 'a64'}`)) }, { mode: 0o755 });
  await timeout(sys.boot(), 60000, 'boot');
  const env = { PATH: '/bin', HOME: '/' };
  for (const [what, prog] of [['the native program', '/g/big-write'], ['wasm32', '/bin/rt-bigwrite']]) {
    const r = await timeout(sys.run([prog, '/tmp'], { env }), 120000, prog);
    const out = r.stdout.trim().split('\n');
    eq(`${where}, ${what}: every case a count or an error`, [r.code, out.at(-1)], [0, 'big-write ok'], r.stdout + r.stderr.slice(-2000));
  }
  // the kernel still serves another process
  const r = await timeout(sys.run(['echo', 'alive'], { env }), 60000, 'echo');
  eq(`${where}: the kernel lives on`, r.stdout.trim(), 'alive');
  if (browser && t.phase === 1) return t.reload();
  await sys.shutdown();
  if (store) await OPFSFilesystem.erase(STORE).catch(() => {});
}
