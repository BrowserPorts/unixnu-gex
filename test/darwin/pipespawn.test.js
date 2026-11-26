// A Darwin pipe() pipe handed on to a posix_spawn's child in the page
// (tests/darwin/src/pipespawn.c, the `darwin-dyn` image's): the child, in a
// Worker of its own, inherits both pipes' ends; the parent's message
// reaches it through the first, to the end of the file once both writers
// have closed, and its answer comes back through the second, as gexc runs
// it. The page makes a Darwin process's pipe in its global kernel, with
// XNU's rules there, so that the child's ends are the same pipe's.
import { System } from '../../runtime/src/index.js';
import { MemoryFilesystem } from '../../runtime/src/fs.js';
import { ROOT_OWNED, tarWithXattrs } from '../fixtures/xattr-tar.js';

export const meta = { hosts: ['browser'], arches: ['a64'], images: ['darwin-root', 'darwin-dyn'], timeout: 900 };

const PROG = '/var/tmp/gex-darwin-pipespawn';

export default async function (t) {
  const { eq, timeout } = t;
  const image = await (await fetch(t.work('darwin-dyn.json'))).json();
  const boot = Object.fromEntries(image.boot.map((f) => [f, new URL(t.work(`darwin-dyn/boot/${f}`))]));
  const disk0 = { url: t.work('darwin-root/disk0'), missing: new URL(t.work('darwin-root/disk0.missing')) };
  const sys = new System({ baseUrl: t.baseUrl, arch: 'aarch64', darwin: { boot, disk0, strict: true }, debug: t.debug() });
  const fs = new MemoryFilesystem(sys);
  fs.addTar(t.work('darwin-root/root.tar'), { lazy: t.work('darwin-root/root-lazy.json') });
  const body = new Uint8Array(await (await fetch(t.work('darwin-dyn/pipespawn'))).arrayBuffer());
  fs.addTar(tarWithXattrs(`private${PROG}`, body, ROOT_OWNED));
  await timeout(sys.boot(), 240000, 'boot');
  const native = image.native.pipespawn;
  eq("gexc's run", native.stdout, 'pipespawn spawn 0 answer 21:through a darwin pipe wait 1 exit 0\npipespawn ok\n');
  const r = await timeout(sys.run([PROG]), 800000, 'pipespawn');
  await t.saveFile('console.txt', sys.state.console);
  eq("the child's answer through the pipes, its wait and its status, as gexc's", r.stdout, native.stdout, `stderr: ${r.stderr.slice(-2000)}\nconsole: ${sys.state.console.slice(-3000)}`);
  eq('and it ends', r.code, native.status, r.signal ? `signal ${r.signal}` : '');
  await sys.shutdown();
}
