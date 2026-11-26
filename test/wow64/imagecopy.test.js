// A Wine process's memory holds no copy of Wine's loader's own wasm module
// (fixtures/wow64/imagecopy.c). The module rides in the loader's image
// (toolchain/gexcc/wasm-elf.py), but nothing in the guest reads it there:
// the image is placed around it, its ELF headers kept (dl_iterate_phdr), and
// the host reads the module from the file. Placed, it was 8 MiB of every Wine
// process's memory; the shim's copy of it, made to publish it, another 8.
// Natively, and on the page for a process Wine starts (an exec); the page's
// exit line says how much of the process's memory holds anything: 40-41 MiB
// for a bare process before (19 MiB of it wasm modules' bytes: the loader's
// twice, Wine's PE module's once), 21-24 MiB after.
import { wow64, graphics } from '../lib/winerun.mjs';

export const meta = { hosts: ['node'], arches: ['x86'], timeout: 900 };

const said = (r, re) => Number(re.exec(r.out)?.[1] ?? NaN);

export default async function (t) {
  const w = wow64(t);
  const exe = await w.mingw('imagecopy', { x64: true });
  const leg = (name, r) => {
    t.check(`${name}: the loader's ELF headers are placed`, said(r, /^imagecopy headers (\d)/m) === 1, w.detail(r));
    t.check(`${name}: its wasm module is not`, said(r, /^imagecopy module copies (\d+)/m) === 0, w.detail(r));
    t.say(`  ${name}: ${/^imagecopy VmRSS:\s*(.*)$/m.exec(r.out)?.[1] ?? '?'}`);
  };
  leg('native', await w.native(['C:\\imagecopy.exe'], { files: { 'imagecopy.exe': exe }, name: 'native', timeout: 300000 }));
  const p = await w.page(['/t/imagecopy.exe', 'child'], { files: { '/t/imagecopy.exe': exe }, userReg: graphics('null'), env: { GEX_DEBUG_EXIT: '1' }, timeout: 300000 });
  leg('page, a process Wine starts', p);
  // The child's exit line (run-node): what of its memory holds anything.
  const res = said(p, /\[gex\] process \d+ exited 0, memory \d+ MiB, resident (\d+) MiB.*imagecopy\.exe/);
  t.say(`  page child resident: ${res} MiB`);
  t.check(`page: the child's memory holding anything is under 32 MiB (${res})`, res < 32, w.detail(p));
  w.clean();
}
