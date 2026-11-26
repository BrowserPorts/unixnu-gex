// The function JIT's hot tier (fjit.rs, `?fjit=hot`): tier-1 runs a program
// first, the safepoint's samples find its loops hot, and the JIT translates
// the functions around them (an ELF object's `.eh_frame` bounds them), on a
// helper Worker of the process (`hot`) or on the thread that sampled them
// (`hotsync`); the next round calls the JIT functions.
// fixtures/programs/fjit-hot.c's rounds must print what they print on tier-1
// alone, and the JIT must have taken hot roots: the helper's, translated and
// compiled there and published, under `hot`.
import { guest, tail } from '../lib/guest.mjs';

export const meta = { hosts: ['node'], arches: ['x86'], timeout: 900 };

export default async function (t) {
  const g = guest(t);
  const seed = g.pub('seed.x86.shared.wasm');
  g.pub('gex_browser.x86.shared.wasm');
  const prog = g.cc('fjit-hot.c', { imageBase: false });
  const run = (env) => g.run(seed, prog, [], { files: { '/g/hot': prog }, argv0: '/g/hot', env: { GEX_SHARED: '1', ...env }, timeout: 300000 });
  const rounds = (r) => r.stdout.split('\n').filter((l) => l.startsWith('round ')).join('\n');
  const base = await run({});
  t.check('tier-1 runs every round', rounds(base).split('\n').length === 8, tail(base.stderr, 6));
  for (const mode of ['hot', 'hotsync']) {
    const r = await run({ GEX_FJIT: mode, GEX_LOG: 'fjit' });
    t.check(`${mode}: every round as on tier-1`, rounds(r) === rounds(base), `${rounds(r) || 'no rounds'}; ${tail(r.stderr, 6)}`);
    t.check(`${mode}: the JIT took hot roots`, /\] fjit: .*hot roots [1-9]/.test(r.stderr), tail(r.stderr, 6));
    if (mode === 'hot') {
      t.check('hot: its helper translated and published them', /helper up/.test(r.stderr) && /translated in [0-9.]+ ms, compiled in [0-9.]+ ms, published/.test(r.stderr), tail(r.stderr, 8));
    }
  }
}
