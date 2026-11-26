// A thread given a pointer into memory another thread has just mapped, which
// grew the process's memory, uses it at once (the busybox image's
// rt-stalebound, a wasm32 program; test/native/stale-bound runs the same
// source translated). Its Worker's engine had not yet taken the memory's new
// length and trapped out of bounds: FL Studio's FastMM on arm64, and this
// program on x86-64 on the first round or two. Five runs of 30 rounds; any
// failure is a failure.
import { System } from '../../runtime/src/index.js';
import { MemoryFilesystem } from '../../runtime/src/fs.js';

export const meta = { hosts: ['browser', 'node'], images: ['busybox'], timeout: 600 };

export default async function (t) {
  const { eq, timeout } = t;
  const sys = new System({ baseUrl: t.baseUrl, debug: t.debug() });
  const fs = new MemoryFilesystem(sys);
  fs.addTar(t.work('bb.tar.zst'));
  await timeout(sys.boot(), 60000, 'boot');
  const env = { PATH: '/bin:/usr/bin', HOME: '/root' };
  for (let i = 1; i <= 5; i++) {
    // spinning with a call: see native/stale-bound
    const r = await timeout(sys.run(['rt-stalebound', '30', 'yield'], { env }), 120000, `run ${i}`);
    eq(`run ${i}`, `${r.code} ${r.stdout.trim()}`, '0 stale-bound ok 30', r.stderr.trim().split('\n').slice(-4).join(' / '));
  }
}
