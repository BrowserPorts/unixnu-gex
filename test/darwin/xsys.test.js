// tests/darwin/src/xsys.c on the page, two processes at once: the first
// allocates a persona and puts itself in a jetsam band with its own user
// data, then waits for the persona to go; the second finds the persona by
// its login, reads it, finds the first in the priority list, and
// deallocates the persona. Each process is a Worker with a Darwin kernel
// instance of its own; the persona registry and the jetsam table are the
// global kernel's, which each takes whole for as long as natively their
// lock is held (gexc's run of xsys does both in one process: "xsys ok").
import { System } from '../../page/runtime/src/index.js';
import { MemoryFilesystem } from '../../page/runtime/src/fs.js';

export const meta = { hosts: ['browser'], arches: ['a64'], images: ['darwin-static'], timeout: 300 };

export default async function (t) {
  const { eq, timeout } = t;
  const image = await (await fetch(t.work('darwin-static.json'))).json();
  eq("xsys: gexc's output", image.native.xsys.stdout, 'xsys ok\n');
  eq("xsys: gexc's status", image.native.xsys.status, 0);
  const boot = Object.fromEntries(image.boot.map((f) => [f, new URL(t.work(`darwin-static/boot/${f}`))]));
  const sys = new System({ baseUrl: t.baseUrl, arch: 'aarch64', darwin: { boot, strict: true }, debug: t.debug() });
  const fs = new MemoryFilesystem(sys);
  fs.addFiles({ '/var/tmp/xsys': new URL(t.work('darwin-static/xsys')) }, { mode: 0o755 });
  await timeout(sys.boot(), 60000, 'boot');
  const ctx = (r) => `stderr: ${r.stderr.slice(-2000)}\nconsole: ${sys.state.console.slice(-3000)}`;
  // (The second looks for the persona until the first has made it, the
  // first waits for it to go, each at most 20 s.)
  const making = timeout(sys.run(['/var/tmp/xsys', 'make']), 60000, 'xsys make');
  const found = await timeout(sys.run(['/var/tmp/xsys', 'find']), 60000, 'xsys find');
  const made = await making;
  await t.saveFile('console.txt', sys.state.console);
  eq("the second process finds the first's persona and jetsam band", found.stdout, 'xsys found\n', ctx(found));
  eq('and ends', found.code, 0, found.signal ? `signal ${found.signal}` : undefined);
  eq('the first process sees its persona deallocated by the second', made.stdout, 'xsys made\n', ctx(made));
  eq('and ends', made.code, 0, made.signal ? `signal ${made.signal}` : undefined);
  await sys.shutdown();
}
