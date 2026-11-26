// The runtime dispatch slot space is given out in ranges, each held by the
// live processes that may reach it; once none does, the range is kept (its
// code cached for the next run) until the space is half spent, and then
// taken back, oldest first, and given out again. A run of many short
// programs, each translating its own code, in a space a debug switch makes
// small (GEX_DEBUG_SLOT_SPACE): forty children would need far more than the
// whole space, so without the taking back the run says the space is spent.
// It must say instead that ranges were taken back, and every child must run.
import { readFileSync } from 'node:fs';
import { guest, tail } from '../lib/guest.mjs';

export const meta = { hosts: ['node'], arches: ['x86'], timeout: 600 };

// Room for about fifty refills of 8,192 slots.
const ROOM = 400000;
const N = 40;

export default async function (t) {
  const g = guest(t);
  const seed = g.pub('seed.x86.shared.wasm');
  g.pub('gex_browser.x86.shared.wasm');
  const prog = g.cc({ name: 'slotloop', code: readFileSync(new URL('../fixtures/programs/slotloop.c', import.meta.url), 'utf8') }, { opt: '-O1' });
  const files = { '/g/slotloop': prog };
  for (let i = 0; i < N; i++) files[`/g/c${i}`] = prog;
  const r = await g.run(seed, prog, [N], {
    files, argv0: '/g/slotloop', timeout: 540000,
    flags: ['--env', `GEX_DEBUG_SLOT_SPACE=${process.env.SR_ROOM ?? ROOM}`],
    env: { GEX_SHARED: '1' },
  });
  const said = r.stderr.split('\n').filter((l) => /dispatch slots: \d+ ranges of ended programs taken back/.test(l));
  t.check(`all ${N} children ran`, r.stdout.includes(`slotloop: ${N} of ${N} children ran`) && r.code === 0, `exit ${r.code}: ${tail(r.stdout + r.stderr, 6)}`);
  t.check('ranges of ended programs were taken back', said.length > 0, tail(r.stderr, 6));
  t.check('the space was never spent', !/dispatch slot space is spent/.test(r.stderr), said.at(-1) ?? tail(r.stderr, 4));
}
