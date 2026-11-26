// dlopen in a static program (fixtures/probe/rt-dlstatic.c): a program with
// its libc inside it loads a side module (rt-side.c) whose imports, libc's
// among them, are the program's exports, from a lazy file, fetched as
// dlopen reads it, found by its bare name beside the program (a static
// program's run path is its own directory); calls into it from two threads, each calling back into
// the program's libc; its constructor, its data and a second dlopen.
import { System } from '../../runtime/src/index.js';
import { MemoryFilesystem } from '../../runtime/src/fs.js';
import { bytesOf } from '../../runtime/src/internal.js';

export const meta = { hosts: ['browser', 'node'], images: ['busybox'], timeout: 180 };

export default async function (t) {
  const { say, check, eq, timeout } = t;
  const side = await bytesOf(t.work('rt-side.so'));
  const sys = new System({ baseUrl: t.baseUrl, debug: t.debug() });
  const fs = new MemoryFilesystem(sys);
  fs.addTar(t.work('bb.tar.zst'), { lazy: [['/bin/rt-side.so', side.length, t.work('rt-side.so')]] });
  await timeout(sys.boot(), 60000, 'boot');
  const t0 = performance.now();
  let out = '';
  const run = sys.run(['/bin/rt-dlstatic', 'rt-side.so'], { env: ['PATH=/bin:/usr/bin', 'HOME=/root'], cwd: '/' })
    .then((r) => { out = r.stdout + r.stderr; return { status: r.code }; });
  const r = await timeout(run, 120000, 'the end').catch((e) => { throw new Error(`${e.message}: ${out.slice(-600)}`); });
  await sys.shutdown();
  const lines = out.replace(/\r/g, '');
  say(lines.split('\n').map((l) => `  | ${l}`).join('\n'));
  say(`the program ran in ${(performance.now() - t0).toFixed(0)} ms`);
  const ms = lines.match(/^dlopen ([0-9.]+) ms$/m);
  if (ms) say(`dlopen of a ${side.length}-byte side module, its fetch and compile: ${ms[1]} ms`);
  eq('the program\'s status', r.status, 0);
  check('dlopen in a static program', !!ms, lines.slice(0, 300));
  check('the side module called back into the program\'s fprintf', /^side: hello$/m.test(lines));
  check('every check passed', /^ok$/m.test(lines) && !/^FAIL/m.test(lines), lines.slice(0, 600));
}
