// Darwin programs with no dyld on the page (tests/darwin/src/hello-static.c,
// bsd-carry.c, tcall.c, bsdthr.c, waits.c, hold.c, pipewr.c and ownrec.c): each runs
// in a 64-bit memory of its own, on the boot payload tests/darwin/run.sh
// boots them with (the `darwin-static` image), and must print what it
// prints under gexc and end with the same status. tcall's timer is fired by its process's thread
// calls, and its commpage kept up to date every quantum, on the Worker the
// page starts for them; bsdthr's thread, made by bsdthread_create, runs on a
// Worker of its own; waits's kevent, poll, select, mach_msg and __ulock_wait
// park their thread until the kernel ends their waits; hold's spinning
// thread, suspended, is held at its safepoints until it is resumed; pipewr's
// writes to a pipe and a socket sleep for room their reader thread makes
// (and one ends in EPIPE as its reader goes), each ended by the kernel;
// ownrec's nice value and task policy are its own record's in its own
// process table, taken from the global kernel's as it starts.
import { System } from '../../page/runtime/src/index.js';
import { MemoryFilesystem } from '../../page/runtime/src/fs.js';

export const meta = { hosts: ['browser'], arches: ['a64'], images: ['darwin-static'], timeout: 300 };

/** What tests/darwin/run.sh expects of each (its `check`). */
const WANT = { 'hello-static': ['hello from darwin\n', 0], 'bsd-carry': ['carry ok\n', 0], tcall: ['tcall ok\n', 0], bsdthr: ['bsdthr ok\n', 0], waits: ['waits ok\n', 0], hold: ['hold ok\n', 0], pipewr: ['pipewr ok\n', 0], ownrec: ['ownrec ok\n', 0] };

export default async function (t) {
  const { eq, timeout } = t;
  const image = await (await fetch(t.work('darwin-static.json'))).json();
  const boot = Object.fromEntries(image.boot.map((f) => [f, new URL(t.work(`darwin-static/boot/${f}`))]));
  const sys = new System({ baseUrl: t.baseUrl, arch: 'aarch64', darwin: { boot, strict: true }, debug: t.debug() });
  const fs = new MemoryFilesystem(sys);
  const progs = Object.keys(WANT);
  fs.addFiles(Object.fromEntries(progs.map((p) => [`/var/tmp/${p}`, new URL(t.work(`darwin-static/${p}`))])), { mode: 0o755 });
  await timeout(sys.boot(), 60000, 'boot');
  for (const p of progs) {
    const [out, status] = WANT[p];
    const native = image.native[p];
    eq(`${p}: gexc's output`, native.stdout, out);
    eq(`${p}: gexc's status`, native.status, status);
    const r = await timeout(sys.run([`/var/tmp/${p}`]), 120000, p);
    eq(`${p}: output, as gexc's`, r.stdout, native.stdout, `stderr: ${r.stderr.slice(-2000)}\nconsole: ${sys.state.console.slice(-4000)}`);
    eq(`${p}: status, as gexc's`, r.code, native.status, r.signal ? `signal ${r.signal}` : undefined);
  }
  // What the Darwin kernel reported, on the system's console as on gexc's
  // stderr (its report sink): each of gexc's reports, by its subject (up to
  // its second colon), as the page's host has it (a stand-in may differ by
  // host: the page cannot tell a file's holes, SEEK_DATA/SEEK_HOLE).
  await t.saveFile('console.txt', sys.state.console);
  const said = sys.state.console.split('\n');
  const reports = new Set(progs.flatMap((p) => image.native[p].reports));
  for (const line of reports) {
    const subject = line.slice(0, line.indexOf(':', line.indexOf(':') + 1) + 1);
    const ours = said.find((l) => l.startsWith(subject));
    t.check(`the Darwin kernel's report on the console: ${subject}`, ours !== undefined, sys.state.console.slice(-2000));
    if (ours !== undefined && ours !== line) t.say(`the page's ${subject} differs from gexc's (${ours.length} bytes, gexc's ${line.length})`);
  }
  const reported = sys.state.console.split('\n').filter((l) => l.startsWith('[gex] Darwin: ') || l.includes('Darwin: not implemented'));
  for (const l of reported) t.say(`console: ${l.slice(0, 200)}`);
  await sys.shutdown();
}
