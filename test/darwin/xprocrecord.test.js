// tests/darwin/src/xproc.c on the page, two processes at once: the first
// writes its pid to a file and waits; the second asks proc_info for the
// first's record (PROC_PIDTBSDINFO) by that pid. Natively one host process
// holds every task's record, and the second finds it (gexc's run of xproc
// finds its own the same way: "xproc ok"). In the page each process gives
// the global kernel its record as it changes, and the second finds the
// first's there, and kill finds the first by it (signal 0); the run is
// strict, so a report would stop it.
import { System } from '../../page/runtime/src/index.js';
import { MemoryFilesystem } from '../../page/runtime/src/fs.js';

export const meta = { hosts: ['browser'], arches: ['a64'], images: ['darwin-static'], timeout: 300 };

const PIDFILE = '/var/tmp/xproc.pid';

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
  const peeked = await timeout(sys.run(['/private/var/tmp/xproc', 'peek', PIDFILE]), 60000, 'xproc peek');
  const held = await holding;
  await t.saveFile('console.txt', sys.state.console);
  eq("the second process finds the first's record, and may signal it", peeked.stdout, 'xproc peek 0 kill 0\n', ctx(peeked));
  eq('and it ends', peeked.code, 0, peeked.signal ? `signal ${peeked.signal}` : undefined);
  eq('the first sees its mark and ends', held.stdout, 'xproc held nice 0\n', ctx(held));
  eq('with status 0', held.code, 0, held.signal ? `signal ${held.signal}` : undefined);
  await sys.shutdown();
}
