// fixtures/probe/rt-stalebound.c on the page's shim: a thread uses a pointer
// into memory another thread has just mapped, which grew the process's
// memory, before its Worker's engine took the memory's new length. The
// program translated (block tier and function JIT) and as a wasm32 program
// (gexcc's, where there is one), each with the engine's guard regions and
// with explicit bounds checks (--wasm-enforce-bounds-checks), as an arm64
// browser may check: five runs of 30 rounds each, any failure a failure.
// The wasm32 runs spin with a call (sched_yield): a wasm32 loop with no call
// has no point where gex can give it the length, and relies on the engine's
// interrupt within the grower's bounded wait (lib.rs `grow_settle`), which a
// loaded machine does not always give.
// test/core/stale-bound runs the wasm32 one through the runtime API on both
// hosts.
import { existsSync } from 'node:fs';
import { native, tail } from '../lib/native.mjs';
import { gexcc } from '../lib/gexcc.mjs';

export const meta = { hosts: ['node'], arches: ['x86', 'a64'], timeout: 1800 };

export default async function (t) {
  const n = native(t);
  const seed = n.seed();
  const d = n.dir('stale-bound');
  const src = n.src('../probe/rt-stalebound.c');
  const prog = `${d}/sb`;
  await n.cc(['-O2', '-static', '-pthread', '-o', prog, src]);
  const progs = [['translated, block tier', prog, {}], ['translated, function JIT', prog, { GEX_FJIT: '1' }]];
  const cc = process.env.GEXCC || null;
  if (cc && existsSync(cc)) {
    const c = gexcc(t);
    const wasm = `${d}/sb.wasm32`;
    const b = await c.run([cc, '-O2', '-pthread', '-o', wasm, src]);
    t.check('gexcc builds it', b.code === 0, b.out);
    if (b.code === 0) progs.push(['wasm32', wasm, {}, ['yield']]);
  } else t.say('wasm32: no GEXCC');
  for (const [bounds, node] of [['guard regions', []], ['explicit bounds checks', ['--wasm-enforce-bounds-checks']]]) {
    for (const [what, exe, env, more = []] of progs) {
      for (let i = 1; i <= 5; i++) {
        const p = await n.g.run(seed, exe, ['30', ...more], { files: { '/t/sb': exe }, argv0: '/t/sb', node, timeout: 120000, env: { GEX_SHARED: '1', ...env } });
        t.eq(`${what}, ${bounds}, run ${i}`, p.guest, 'stale-bound ok 30', tail(p.stderr));
      }
    }
  }
  n.clean();
}
