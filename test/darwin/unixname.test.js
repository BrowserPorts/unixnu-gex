// tests/darwin/src/unixname.c on the page: a unix stream socket bound to a
// name, which a client of the same process connects to by it. A Darwin
// process's named sockets are its own, kept by XNU's rules as gexc keeps
// every one (the global kernel's follow Linux's), so the page answers each
// call as gexc does: the program's output and status match gexc's, and the
// run is strict, so anything the kernel reports as not done stops it.
import { System } from '../../page/runtime/src/index.js';
import { MemoryFilesystem } from '../../page/runtime/src/fs.js';

export const meta = { hosts: ['browser'], arches: ['a64'], images: ['darwin-static'], timeout: 300 };

export default async function (t) {
  const { eq, timeout } = t;
  const image = await (await fetch(t.work('darwin-static.json'))).json();
  const native = image.native.unixname;
  eq("unixname: gexc's output", native.stdout, 'unixname ok\n');
  eq("unixname: gexc's status", native.status, 0);
  const boot = Object.fromEntries(image.boot.map((f) => [f, new URL(t.work(`darwin-static/boot/${f}`))]));
  const sys = new System({ baseUrl: t.baseUrl, arch: 'aarch64', darwin: { boot, strict: true }, debug: t.debug() });
  const fs = new MemoryFilesystem(sys);
  // The device's layout, as gexc's root has it: /var is a link to
  // private/var, whose tmp (mode 1777) the socket is made in.
  fs.addFiles({ '/private/var/tmp/unixname': new URL(t.work('darwin-static/unixname')) }, { mode: 0o755 });
  await timeout(sys.boot(), 60000, 'boot');
  // The page's root has an empty /var/tmp of its own (the global kernel's
  // root), which the link takes the place of.
  await fs.rm('/var/tmp');
  await fs.rm('/var');
  await fs.symlink('private/var', '/var');
  // Its mode as the device's image has it.
  await fs.chmod('/private/var/tmp', 0o1777);
  const r = await timeout(sys.run(['/private/var/tmp/unixname']), 120000, 'unixname');
  await t.saveFile('console.txt', sys.state.console);
  const ctx = `stderr: ${r.stderr.slice(-2000)}\nconsole: ${sys.state.console.slice(-4000)}`;
  eq('unixname: output, as gexc\'s', r.stdout, native.stdout, ctx);
  eq('unixname: status, as gexc\'s', r.code, native.status, r.signal ? `signal ${r.signal}` : undefined);
  await sys.shutdown();
}
