// A 64-bit program that asks for more address space than any memory gex
// has (a no-address 16 GiB reservation, a wasm sandbox's) is told no and
// goes on, and whoever runs it is told why while it runs: on the page, the
// System's notice ("needs more than 16 GiB of address space"), once,
// though it asks twice. The memory64 twin's page leg (in a lowered memory
// the reservation is gex's outgrow case instead, wow64/outgrow).
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { wow64 } from '../lib/winerun.mjs';

export const meta = { hosts: ['node'], arches: ['x86'], timeout: 900 };

export default async function (t) {
  const w = wow64(t);
  const exe = await w.mingw('big16', { x64: true });
  if (!existsSync(join(process.env.GEX_TEST_WOW64_DIST, 'lib/wine/x86_64-unix/wine.m64'))) t.skip('the WoW64 install has no memory64 twin (WINE64_TWIN=1)');
  // 600 s: its first start compiles its modules
  const p = await w.page(['/t/big16.exe'], { files: { '/t/big16.exe': exe }, name: 'page-m64', timeout: 600000, wineEnv: { GEX_MEM64: '1' } });
  const said = p.out.split('\n').filter((l) => /^\[gex\] pid \d+( \(.*\))?: needs more than 16 GiB of address space \(a reservation of 16 GiB did not fit\)$/.test(l.trim()));
  t.check('page mem64: refused, it goes on', /^big16 refused\r?$/m.test(p.out) && /^big16 done\r?$/m.test(p.out), w.detail(p));
  t.check('page mem64: the notice says why, once', said.length === 1, `${said.length} notices; ${w.detail(p)}`);
  w.clean();
}
