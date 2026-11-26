// A data export of a DLL of Wine's core PE module reaches the module's data
// when the prefix pins that DLL low (dll-bases, the band from 0x11000000):
// gdi32's pfnRealizePalette, which user32 and programs set, through the
// address GetProcAddress gives (gdidata.c). In a 64-bit memory, where the
// export table's 32-bit RVA reaches only the 4 GiB above the image, and in a
// 32-bit one; gex says nothing of an RVA out of reach.
import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { wow64 } from '../lib/winerun.mjs';

export const meta = { hosts: ['node'], arches: ['x86'], timeout: 900 };

export default async function (t) {
  const w = wow64(t);
  const exe = await w.mingw('gdidata', { x64: true, flags: ['-Wall'], libs: ['-lgdi32'] });
  const pin = (p) => writeFileSync(join(p, 'dll-bases'), '11bc0000 /wine32/lib/wine/x86_64-windows/gdi32.dll\n');
  // The memory64 leg needs the install's memory64 twin (WINE64_TWIN=1),
  // which a plain WoW64 install has not: said, and the wasm32 leg alone.
  const twin = existsSync(join(process.env.GEX_TEST_WOW64_DIST, 'lib/wine/x86_64-unix/wine.m64'));
  if (!twin) t.say('memory64: skipped, the WoW64 install has no memory64 twin (WINE64_TWIN=1)');
  for (const mem64 of twin ? [true, false] : [false]) {
    const leg = mem64 ? 'memory64' : 'wasm32';
    const r = await w.page(['Z:\\t\\gdidata.exe'], {
      files: { '/t/gdidata.exe': exe }, cwd: '/t', name: `gdidata-${leg}`, setup: pin,
      ...(mem64 && { mem64: true, rel: 'lib/wine/x86_64-unix/wine.m64' }),
    });
    for (const l of r.out.split('\n').filter((l) => /^gdidata /.test(l))) t.say(`${leg}: ${l}`);
    t.check(`${leg}: the hook set through the export ran`, /^gdidata ok/m.test(r.out), w.detail(r));
    t.check(`${leg}: no data export said out of reach`, !/out of its 32-bit RVA's reach/.test(r.out), r.out.split('\n').filter((l) => /RVA's reach/.test(l)).slice(0, 3).join(' / '));
  }
  w.clean();
}
