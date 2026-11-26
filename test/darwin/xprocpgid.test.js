// tests/darwin/src/xproc.c on the page, two processes at once, each a
// session's leader as the page starts its programs: the first asks to
// make itself a group's leader (Darwin's setpgid(0, 0)), which a session
// leader may not (kern_prot.c: EPERM), writes its pid to a file and waits;
// the second asks the system's table for that pid's group (getpgid: the
// pid, its session's) and tries setpgid of it, which is not its descendant
// (inferior(): ESRCH). A page process's Darwin setpgid is decided on the
// global kernel's table (share op DSETPGID). A setpgid that changes a
// group needs a child of the caller's that is not a session leader, which
// a static page process cannot have (a RELEASE kernel refuses to spawn a
// static image), nor can EACCES for a child that has exec'd be had here:
// the share op's unit test covers both. The run is strict, so a report
// would stop it.
import { System } from '../../runtime/src/index.js';
import { MemoryFilesystem } from '../../runtime/src/fs.js';

export const meta = { hosts: ['browser'], arches: ['a64'], images: ['darwin-static'], timeout: 300 };

const PIDFILE = '/var/tmp/xpgid.pid';

export default async function (t) {
  const { eq, timeout } = t;
  const image = await (await fetch(t.work('darwin-static.json'))).json();
  const boot = Object.fromEntries(image.boot.map((f) => [f, new URL(t.work(`darwin-static/boot/${f}`))]));
  const sys = new System({ baseUrl: t.baseUrl, arch: 'aarch64', darwin: { boot, strict: true }, debug: t.debug() });
  const fs = new MemoryFilesystem(sys);
  fs.addFiles({ '/private/var/tmp/xproc': new URL(t.work('darwin-static/xproc')) }, { mode: 0o755 });
  await timeout(sys.boot(), 60000, 'boot');
  await fs.rm('/var/tmp');
  await fs.rm('/var');
  await fs.symlink('private/var', '/var');
  await fs.chmod('/private/var/tmp', 0o1777);
  const ctx = (r) => `stderr: ${r.stderr.slice(-2000)}\nconsole: ${sys.state.console.slice(-3000)}`;
  const leading = timeout(sys.run(['/private/var/tmp/xproc', 'lead', PIDFILE]), 60000, 'xproc lead');
  const asked = await timeout(sys.run(['/private/var/tmp/xproc', 'pgid', PIDFILE]), 60000, 'xproc pgid');
  const led = await leading;
  await t.saveFile('console.txt', sys.state.console);
  eq("the second finds the first's group in the system's table, and may not set it", asked.stdout, 'xproc pgid 1 3\n', ctx(asked));
  eq('and it ends', asked.code, 0, asked.signal ? `signal ${asked.signal}` : undefined);
  eq('the first, a session leader, may not change its group, and leads it', led.stdout, 'xproc led 1 1\n', ctx(led));
  eq('with status 0', led.code, 0, led.signal ? `signal ${led.signal}` : undefined);
  await sys.shutdown();
}
