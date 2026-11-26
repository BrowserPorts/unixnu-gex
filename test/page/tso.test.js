// Message passing between two guest threads, with plain x86 `mov`s, keeps
// x86 order in the TSO flavour (GEX_TSO=1, the page's `?tso=1`). Thread A
// writes data[i] then flag[i]; thread B reads flag[i] then data[i]. x86 never
// lets B see the flag without the data. Translated to plain wasm accesses,
// V8 may reorder them (rarely on an x86 host, freely on arm64); in the TSO
// flavour they are atomic and must not. The plain run's count is said for
// information (nonzero on an arm64 host is expected). GEX_TSO=2, the debug
// flavour, the same, and a misaligned 8-byte word written and read whole.
// The tear switch (GEX_TEAR, the page's `?tear=`): 1 counts the plain
// misaligned 8-byte accesses and says where the first are; 2 also splits
// each into 4-byte halves, so an x86 host tears the word as arm64 may.
import { guest } from '../lib/guest.mjs';

export const meta = { hosts: ['node'], arches: ['x86'], timeout: 1260 };

const ROUNDS = 300;

export default async function (t) {
  const g = guest(t);
  g.pub('gex_browser{infix}.shared.wasm');
  g.pub('gex_kernel{infix}.wasm');
  const prog = g.cc('tso-mp.c');
  const seed = g.seed();
  let last = '';
  const mp = async (tso, more = [], env = {}) => {
    const r = await g.run(seed, prog, [ROUNDS, ...more], { env: { GEX_SHARED: '1', GEX_TSO: tso, ...env }, timeout: 600000 });
    last = r.stderr;
    return r.guest.split('\n').find((l) => l.startsWith('mp ')) ?? 'mp ? (the run failed)';
  };
  t.say(`plain: ${await mp('0')}`);
  const got = await mp('1');
  t.check(`tso: ${got} reordered`, /^mp 0 of /.test(got) && !/ of 0$/.test(got), / of 0$/.test(got) ? 'the reader never saw a flag' : '');
  // tso=2 (the debug flavour): the same, and a misaligned word never torn
  const got2 = await mp('2');
  t.check(`tso=2: ${got2} reordered`, /^mp 0 of /.test(got2) && !/ of 0$/.test(got2));
  t.say(`plain, misaligned: ${await mp('0', ['tear'])} torn`);
  const tear2 = await mp('2', ['tear']);
  t.check(`tso=2, misaligned: ${tear2} torn`, /^mp 0 of /.test(tear2) && !/ of 0$/.test(tear2));
  // the tear switch: counted, the first few said; then split, and torn
  const counted = await mp('0', ['tear'], { GEX_TEAR: '1' });
  const n = /tear=1: (\d+) plain misaligned 8-byte loads, (\d+) stores/.exec(last);
  t.check(`tear=1: the misaligned loads and stores counted (${n ? `${n[1]} loads, ${n[2]} stores` : 'no count'}; ${counted})`,
    n && Number(n[1]) >= ROUNDS * 4096 * 4 && Number(n[2]) >= ROUNDS * 4096 * 4, last.split('\n').slice(-4).join(' / '));
  t.check('tear=1: the first said, with its address', /tear: a plain misaligned 8-byte (load|store) at 0x[0-9a-f]*4 /.test(last));
  const split = await mp('0', ['tear'], { GEX_TEAR: '2' });
  t.check(`tear=2: ${split} torn`, /^mp [1-9]\d* of /.test(split), last.split('\n').slice(-4).join(' / '));
}
