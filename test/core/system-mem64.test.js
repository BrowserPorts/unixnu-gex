// System({ mem64: true }): every program starts in a 64-bit memory, the
// first one included (page/mem64-pick's program says which it got; without
// the option it starts 32-bit, core/mem64).
import { System } from '../../runtime/src/index.js';
import { MemoryFilesystem } from '../../runtime/src/fs.js';

export const meta = { hosts: ['browser', 'node'], arches: ['x86'], images: ['busybox', 'mem64'], timeout: 120 };

export default async function (t) {
  const { eq, timeout } = t;
  const sys = new System({ baseUrl: t.baseUrl, debug: t.debug(), mem64: true });
  const fs = new MemoryFilesystem(sys);
  fs.addTar(t.work('bb.tar.zst'));
  fs.addFiles({ '/g/pick': new URL(t.work('mem64-pick.x86')) }, { mode: 0o755 });
  await timeout(sys.boot(), 60000, 'boot');
  const r = await timeout(sys.run(['/g/pick'], { env: { PATH: '/bin', HOME: '/' } }), 60000, 'mem64-pick');
  eq('the first program in a 64-bit memory', r.stdout.split('\n')[0], 'parent: 64', r.stdout + r.stderr.slice(-2000));
  await sys.shutdown();
}
