// System's `exec` event: each process's exec, its pid and the file it runs.
import { System } from '../../runtime/src/index.js';
import { MemoryFilesystem } from '../../runtime/src/fs.js';

export const meta = { hosts: ['browser'], images: ['busybox'], timeout: 120, single: 'the default build\'s events' };

export default async function (t) {
  const { eq, check, timeout } = t;
  const sys = new System({ baseUrl: t.baseUrl, debug: t.debug() });
  const fs = new MemoryFilesystem(sys);
  fs.addTar(t.work('bb.tar.zst'));
  const execs = [];
  sys.addEventListener('exec', (e) => execs.push({ pid: e.pid, path: e.path }));
  await timeout(sys.boot(), 60000, 'boot');
  const env = { PATH: '/bin:/usr/bin', HOME: '/root' };
  const p = sys.spawn(['/bin/sh', '-c', 'exec /bin/true'], { env });
  await timeout(p.exited, 60000, 'exit');
  const mine = execs.filter((x) => x.pid === p.pid).map((x) => x.path);
  check('a spawn and its exec are said, in order', mine.length >= 2 && mine[0] === '/bin/sh' && mine.at(-1) === '/bin/true', JSON.stringify(execs));
  const r = await timeout(sys.run(['sh', '-c', '/bin/echo hi'], { env }), 60000, 'run');
  eq('the run', r.stdout, 'hi\n');
  check('a child\'s exec has its own pid', execs.some((x) => x.path === '/bin/echo' && x.pid !== p.pid), JSON.stringify(execs.slice(-4)));
  await sys.shutdown();
}
