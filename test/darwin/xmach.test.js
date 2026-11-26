// tests/darwin/src/xmach.c on the page, two processes at once: the first
// makes a port and sets it as the host's telemetry port, then waits for a
// message on it; the second looks the telemetry port up and sends it a
// message. Each process is a Worker with a Darwin kernel instance of its
// own; the system's IPC table (the ports, every task's space, the
// messages queued, the host's special ports) is the global kernel's, which
// each takes for the length of a kernel call, as one host process's tasks
// take it from its cell for gexc's run (gexc's run of xmach does both in
// one process: "xmach ok"). The second's send right names the first's
// port, the message waits in that port's queue in the global table, and
// the first's receive, parked, is woken through its task's mailbox there.
import { System } from '../../runtime/src/index.js';
import { MemoryFilesystem } from '../../runtime/src/fs.js';

export const meta = { hosts: ['browser'], arches: ['a64'], images: ['darwin-static'], timeout: 300 };

export default async function (t) {
  const { eq, timeout } = t;
  const image = await (await fetch(t.work('darwin-static.json'))).json();
  eq("xmach: gexc's output", image.native.xmach.stdout, 'xmach ok\n');
  eq("xmach: gexc's status", image.native.xmach.status, 0);
  const boot = Object.fromEntries(image.boot.map((f) => [f, new URL(t.work(`darwin-static/boot/${f}`))]));
  const sys = new System({ baseUrl: t.baseUrl, arch: 'aarch64', darwin: { boot, strict: true }, debug: t.debug() });
  const fs = new MemoryFilesystem(sys);
  fs.addFiles({ '/var/tmp/xmach': new URL(t.work('darwin-static/xmach')) }, { mode: 0o755 });
  await timeout(sys.boot(), 60000, 'boot');
  const ctx = (r) => `stderr: ${r.stderr.slice(-2000)}\nconsole: ${sys.state.console.slice(-3000)}`;
  // (The second looks for the port until the first has set it, the first
  // waits for the message, each at most 20 s.)
  const serving = timeout(sys.run(['/var/tmp/xmach', 'serve']), 60000, 'xmach serve');
  const sent = await timeout(sys.run(['/var/tmp/xmach', 'send']), 60000, 'xmach send');
  const served = await serving;
  await t.saveFile('console.txt', sys.state.console);
  eq('the second process sends to the port it looked up', sent.stdout, 'xmach sent\n', ctx(sent));
  eq('and ends', sent.code, 0, sent.signal ? `signal ${sent.signal}` : undefined);
  eq('the first process receives the message', served.stdout, 'xmach got 4242 hello across\n', ctx(served));
  eq('and ends', served.code, 0, served.signal ? `signal ${served.signal}` : undefined);
  await sys.shutdown();
}
