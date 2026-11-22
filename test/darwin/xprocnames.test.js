// tests/darwin/src/xproc.c on the page, twice: the first run makes a POSIX
// shared memory name and a named semaphore and leaves both, as the system
// keeps them; the second opens them. Natively one host process holds every
// task, so the second finds what the first made (gexc's run of xproc does
// both in one process: "xproc ok"). In the page each process is a Worker
// with a Darwin kernel instance of its own, whose names are its own copy:
// the second process's opens reach names another process of the page holds,
// which the global kernel's record says, and each fails with its report
// (gex_kernel::darwin::held) where it would otherwise have found nothing.
// The run is not strict: a strict one stops at the first report.
import { System } from '../../page/runtime/src/index.js';
import { MemoryFilesystem } from '../../page/runtime/src/fs.js';

export const meta = { hosts: ['browser'], arches: ['a64'], images: ['darwin-static'], timeout: 300 };

const ENOSYS = 78;
const NAME = '/gex-xproc-names';

export default async function (t) {
  const { eq, timeout } = t;
  const image = await (await fetch(t.work('darwin-static.json'))).json();
  const native = image.native.xproc;
  eq("xproc: gexc's output", native.stdout, 'xproc ok\n');
  eq("xproc: gexc's status", native.status, 0);
  const boot = Object.fromEntries(image.boot.map((f) => [f, new URL(t.work(`darwin-static/boot/${f}`))]));
  const sys = new System({ baseUrl: t.baseUrl, arch: 'aarch64', darwin: { boot, strict: false }, debug: t.debug() });
  const fs = new MemoryFilesystem(sys);
  fs.addFiles({ '/var/tmp/xproc': new URL(t.work('darwin-static/xproc')) }, { mode: 0o755 });
  await timeout(sys.boot(), 60000, 'boot');
  const ctx = (r) => `stderr: ${r.stderr.slice(-2000)}\nconsole: ${sys.state.console.slice(-3000)}`;
  const made = await timeout(sys.run(['/var/tmp/xproc', 'mk', NAME]), 60000, 'xproc mk');
  eq('the first process makes the names', made.stdout, 'xproc made\n', ctx(made));
  eq('and ends', made.code, 0, made.signal ? `signal ${made.signal}` : undefined);
  const opened = await timeout(sys.run(['/var/tmp/xproc', 'open', NAME]), 60000, 'xproc open');
  await t.saveFile('console.txt', sys.state.console);
  eq("the second process's opens of them fail", opened.stdout, `xproc open shm=${ENOSYS} sem=${ENOSYS}\n`, ctx(opened));
  eq('and it ends', opened.code, 0, opened.signal ? `signal ${opened.signal}` : undefined);
  const said = sys.state.console.split('\n');
  for (const what of [`shm_open of the POSIX shared memory name "${NAME}"`, `sem_open of the POSIX semaphore name "${NAME}"`]) {
    t.check(`the Darwin kernel's report: ${what}`, said.some((l) => l.includes(`Darwin: not implemented: ${what}, which process `) && l.includes('of the page holds')), sys.state.console.slice(-2000));
  }
  await sys.shutdown();
}
