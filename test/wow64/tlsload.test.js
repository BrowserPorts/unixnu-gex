// wow64/tlsload's program (fixtures/wow64/tlsload.c, tlsdll.c): static TLS
// of a DLL loaded after threads exist is each thread's own, early threads,
// late ones, threadpool callbacks and a CreateRemoteThread alike; and every
// thread's id, TEB ClientId and gs:[0x30] agree. Natively, on the page and
// on the page with wine.m64.
import { join } from 'node:path';
import { wow64, FIXTURES } from '../lib/winerun.mjs';

export const meta = { hosts: ['node'], arches: ['x86'], timeout: 1200 };

export default async function (t) {
  const w = wow64(t);
  const exe = await w.mingw('tlsload', { x64: true });
  const dll = await w.mingw('tlsdll', { x64: true, flags: ['-shared'], out: 'tlsdll.dll', src: join(FIXTURES, 'tlsdll.c') });
  const pf = { '/t/tlsload.exe': exe, '/t/tlsdll.dll': dll };
  for (const [leg, go] of [
    ['native', () => w.native(['C:\\tlsload.exe'], { files: { 'tlsload.exe': exe, 'tlsdll.dll': dll }, name: 'native' })],
    ['page', () => w.page(['/t/tlsload.exe'], { files: pf, name: 'page' })],
    ['page-m64', () => w.page(['/t/tlsload.exe'], { files: pf, mem64: true, rel: 'lib/wine/x86_64-unix/wine.m64', name: 'page-m64' })],
  ]) {
    const r = await go();
    t.say(`${leg}:\n${r.out.split('\n').filter((l) => l.startsWith('tlsload')).join('\n')}`);
    t.check(`${leg}: every thread its own TLS and identity`, /^tlsload 18 ran 0 bad$/m.test(r.out), w.detail(r));
  }
  w.clean();
}
