// A store to the shared cache's writable data in the page
// (tests/darwin/src/regioncow.c, the `darwin-dyn` image's): the region's
// entry at the page it wrote becomes the task's own copy, read and write
// and inherited by copy, and the page counts in the task's footprint, as
// gexc runs it. Each process of the page has its own copy of the region's
// pages; the store still takes the page out of the submap's into the
// task's, as the copy-on-write of XNU's submap does.
import { System } from '../../runtime/src/index.js';
import { MemoryFilesystem } from '../../runtime/src/fs.js';
import { ROOT_OWNED, tarWithXattrs } from '../fixtures/xattr-tar.js';

export const meta = { hosts: ['browser'], arches: ['a64'], images: ['darwin-root', 'darwin-dyn'], timeout: 900 };

const PROG = '/var/tmp/gex-darwin-regioncow';

export default async function (t) {
  const { eq, timeout } = t;
  const image = await (await fetch(t.work('darwin-dyn.json'))).json();
  const boot = Object.fromEntries(image.boot.map((f) => [f, new URL(t.work(`darwin-dyn/boot/${f}`))]));
  const disk0 = { url: t.work('darwin-root/disk0'), missing: new URL(t.work('darwin-root/disk0.missing')) };
  const sys = new System({ baseUrl: t.baseUrl, arch: 'aarch64', darwin: { boot, disk0, strict: true }, debug: t.debug() });
  const fs = new MemoryFilesystem(sys);
  fs.addTar(t.work('darwin-root/root.tar'), { lazy: t.work('darwin-root/root-lazy.json') });
  const body = new Uint8Array(await (await fetch(t.work('darwin-dyn/regioncow'))).arrayBuffer());
  fs.addTar(tarWithXattrs(`private${PROG}`, body, ROOT_OWNED));
  await timeout(sys.boot(), 240000, 'boot');
  const native = image.native.regioncow;
  t.check("gexc's run", /\nregioncow ok\n$/.test(native.stdout), native.stdout);
  const r = await timeout(sys.run([PROG]), 800000, 'regioncow');
  await t.saveFile('console.txt', sys.state.console);
  eq("the entry at the page it wrote, before and after, and the footprint's growth, as gexc's", r.stdout, native.stdout, `stderr: ${r.stderr.slice(-2000)}\nconsole: ${sys.state.console.slice(-3000)}`);
  eq('and it ends', r.code, native.status, r.signal ? `signal ${r.signal}` : '');
  await sys.shutdown();
}
