// Dynamic Darwin processes in one page share the system's shared region
// (tests/darwin/src/dynspawn.c, the `darwin-dyn` image's): each process of
// the page maps the boot's region as its own copy, made of the same cache
// files at the slide the system drew once, so two processes find the cache
// at the same address, as two tasks of one system do.
import { System } from '../../page/runtime/src/index.js';
import { MemoryFilesystem } from '../../page/runtime/src/fs.js';
import { ROOT_OWNED, tarWithXattrs } from '../fixtures/xattr-tar.js';

export const meta = { hosts: ['browser'], arches: ['a64'], images: ['darwin-root', 'darwin-dyn'], timeout: 900 };

const PROG = '/var/tmp/gex-darwin-dynspawn';

export default async function (t) {
  const { eq, timeout } = t;
  const image = await (await fetch(t.work('darwin-dyn.json'))).json();
  const boot = Object.fromEntries(image.boot.map((f) => [f, new URL(t.work(`darwin-dyn/boot/${f}`))]));
  const disk0 = { url: t.work('darwin-root/disk0'), missing: new URL(t.work('darwin-root/disk0.missing')) };
  const sys = new System({ baseUrl: t.baseUrl, arch: 'aarch64', darwin: { boot, disk0, strict: false }, debug: t.debug() });
  const fs = new MemoryFilesystem(sys);
  fs.addTar(t.work('darwin-root/root.tar'), { lazy: t.work('darwin-root/root-lazy.json') });
  const body = new Uint8Array(await (await fetch(t.work('darwin-dyn/dynspawn'))).arrayBuffer());
  fs.addTar(tarWithXattrs(`private${PROG}`, body, ROOT_OWNED));
  await timeout(sys.boot(), 240000, 'boot');
  const first = await timeout(sys.run([PROG, 'cache']), 800000, 'dynspawn cache');
  const ctx = (r) => `stderr: ${r.stderr.slice(-2000)}\nconsole: ${sys.state.console.slice(-3000)}`;
  t.check("the first process's cache", /^dynspawn cache [0-9a-f]+\n$/.test(first.stdout), ctx(first));
  const s0 = performance.now();
  const second = await timeout(sys.run([PROG, 'cache']), 800000, 'dynspawn cache again');
  t.say(`a second process started and ran in ${((performance.now() - s0) / 1000).toFixed(1)} s`);
  eq("a second process's cache, at the first's address", second.stdout, first.stdout, ctx(second));
  for (const l of sys.state.console.split('\n').filter((l) => l.includes('Darwin: not implemented'))) t.say(`console: ${l.slice(0, 240)}`);
  await sys.shutdown();
}
