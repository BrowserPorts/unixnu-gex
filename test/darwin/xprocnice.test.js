// tests/darwin/src/xproc.c on the page, two processes at once: the first
// writes its pid to a file and waits; the second sets the first's nice
// value by that pid (setpriority) and reads it back (getpriority). Natively
// the second changes the first's entry in the one process table. In the
// page the first's own process table holds it: the change goes to the
// first's process through the global kernel, which makes it as its thread
// calls run, and the second waits for it, as it waits for the table's lock
// natively; the first then reads its own nice value. Strict: a report
// would stop either.
import { System } from '../../page/runtime/src/index.js';
import { MemoryFilesystem } from '../../page/runtime/src/fs.js';

export const meta = { hosts: ['browser'], arches: ['a64'], images: ['darwin-static'], timeout: 300 };

const PIDFILE = '/var/tmp/xproc-nice.pid';

export default async function (t) {
  const { eq, timeout } = t;
  const image = await (await fetch(t.work('darwin-static.json'))).json();
  eq("xproc: gexc's output", image.native.xproc.stdout, 'xproc ok\n');
  const boot = Object.fromEntries(image.boot.map((f) => [f, new URL(t.work(`darwin-static/boot/${f}`))]));
  const sys = new System({ baseUrl: t.baseUrl, arch: 'aarch64', darwin: { boot, strict: true }, debug: t.debug() });
  const fs = new MemoryFilesystem(sys);
  // The device's layout, as gexc's root has it: /var is a link to
  // private/var, whose tmp (mode 1777) the pid file is made in.
  fs.addFiles({ '/private/var/tmp/xproc': new URL(t.work('darwin-static/xproc')) }, { mode: 0o755 });
  await timeout(sys.boot(), 60000, 'boot');
  // The page's root has an empty /var/tmp of its own (the global kernel's
  // root), which goes first.
  await fs.rm('/var/tmp');
  await fs.rm('/var');
  await fs.symlink('private/var', '/var');
  await fs.chmod('/private/var/tmp', 0o1777);
  const ctx = (r) => `stderr: ${r.stderr.slice(-2000)}\nconsole: ${sys.state.console.slice(-3000)}`;
  const holding = timeout(sys.run(['/private/var/tmp/xproc', 'hold', PIDFILE]), 60000, 'xproc hold');
  // (The second waits for the pid in the file, the first for the second's
  // mark, each at most 20 s.)
  const niced = await timeout(sys.run(['/private/var/tmp/xproc', 'nice', PIDFILE]), 60000, 'xproc nice');
  const held = await holding;
  await t.saveFile('console.txt', sys.state.console);
  eq("the second process sets the first's nice value and reads it back", niced.stdout, 'xproc nice 0 7\n', ctx(niced));
  eq('and it ends', niced.code, 0, niced.signal ? `signal ${niced.signal}` : undefined);
  eq('the first sees its own nice value changed', held.stdout, 'xproc held nice 7\n', ctx(held));
  eq('with status 0', held.code, 0, held.signal ? `signal ${held.signal}` : undefined);
  await sys.shutdown();
}
