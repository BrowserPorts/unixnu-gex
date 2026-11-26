// What a conservative collector's root scan finds on Windows (Boehm GC's,
// which takes a DLL's data only when VirtualQuery says it is committed
// MEM_IMAGE and PAGE_READWRITE): a program's and a loaded DLL's data and
// bss shown as written pages, VirtualProtect's old protection agreeing, a
// copy-on-write view of a plain file still PAGE_WRITECOPY, and each
// thread's TEB stack bounds around its stack. i386 and x64, natively and
// on the page.
import { wow64 } from '../lib/winerun.mjs';

export const meta = { hosts: ['node'], arches: ['x86'], timeout: 900 };

export default async function (t) {
  const w = wow64(t);
  for (const x64 of [false, true]) {
    const arch = x64 ? 'x64' : 'i386';
    const exe = await w.mingw('gcroots', { x64, out: `${arch}/gcroots.exe` });
    const dll = await w.mingw('gcdll', { x64, flags: ['-shared'], out: `${arch}/gcdll.dll` });
    for (const [leg, go] of [
      ['native', () => w.native(['C:\\gcroots.exe'], { files: { 'gcroots.exe': exe, 'gcdll.dll': dll }, name: `native-${arch}` })],
      ['page', () => w.page(['/t/gcroots.exe'], { files: { '/t/gcroots.exe': exe, '/t/gcdll.dll': dll }, name: `page-${arch}` })],
    ]) {
      const r = await go();
      const lines = r.out.split('\n').filter((l) => l.startsWith('gcroots'));
      t.check(`${leg} ${arch}: every root is where the collector looks`, r.code === 0 && /^gcroots 0 bad$/m.test(r.out) && !lines.some((l) => l.endsWith('BAD')),
        `exit ${r.code} / ${lines.filter((l) => l.endsWith('BAD') || /bad$/.test(l)).join(' / ') || r.out.trim().split('\n').slice(-3).join(' / ')}`);
    }
  }
}
