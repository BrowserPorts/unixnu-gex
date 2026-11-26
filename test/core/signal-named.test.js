// sys.signal(name, sig): a signal to every running process of that name,
// which the page did not have to start (a page asks a daemon of one of its
// programs, such as Wine's wineserver, to save before it goes away). A shell
// that traps SIGUSR1 says so and goes on; a name nothing runs under signals
// none; a non-string name throws.
import { System } from '../../runtime/src/index.js';
import { MemoryFilesystem } from '../../runtime/src/fs.js';

export const meta = { hosts: ['browser'], images: ['busybox'], timeout: 300 };

export default async function (t) {
  const { eq, check, timeout, until, lines } = t;
  const sys = new System({ baseUrl: t.baseUrl, debug: t.debug() });
  new MemoryFilesystem(sys).addTar(t.work('bb.tar.zst'));
  eq('before boot, none', await sys.signal('sh', 'SIGUSR1'), 0);
  await timeout(sys.boot(), 60000, 'boot');
  const env = { PATH: '/bin:/usr/bin', HOME: '/root' };
  // Started by another shell, so the page holds no Process for it. Its loop
  // forks nothing once it is ready (a builtin read on a FIFO nobody writes, a
  // second at a time): busybox runs `sleep` as a fork of sh that never execs,
  // and a third process named sh while it sleeps made the count racy.
  const p = sys.spawn(['sh', '-c', `sh -c 'mkfifo /tmp/sn; exec 3<>/tmp/sn; trap "echo got usr1" USR1; echo ready; while :; do read -t 1 _ <&3; done' & wait`], { env });
  const said = lines(p);
  await until(() => said.includes('ready'), 'the trapping shell is up', 30000);
  // (both shells are named sh: the outer one, waiting, ends on it; the
  // inner one, an orphan then, still writes to the same pipe)
  const n = await sys.signal('sh', 'SIGUSR1');
  check('both shells signalled', n === 2, `signalled ${n}`);
  await until(() => said.includes('got usr1'), 'the trap ran', 20000);
  eq('a name nothing runs under signals none', await sys.signal('no-such-program', 'SIGUSR1'), 0);
  let threw = false;
  try { await sys.signal('', 'SIGUSR1'); } catch { threw = true; }
  check('an empty name throws', threw, 'no throw');
  p.kill('SIGKILL');
  await sys.shutdown();
}
