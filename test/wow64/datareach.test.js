// A native module's data exports bind in a 32-bit memory wherever its data
// is (a 32-bit RVA wraps to any address there): DLLs whose exports include
// data (msftedit's and riched20's IIDs, oleacc's) load on the page in an
// i386 process, their data is read, and gex says nothing of an RVA out of
// reach (only a 64-bit memory has that limit).
import { wow64 } from '../lib/winerun.mjs';

export const meta = { hosts: ['node'], arches: ['x86'], timeout: 900 };

export default async function (t) {
  const w = wow64(t);
  const exe = await w.mingw('datareach', {});
  const r = await w.page(['/t/datareach.exe'], { files: { '/t/datareach.exe': exe }, name: 'page' });
  const lines = r.out.replace(/\r/g, '').split('\n').filter((l) => l.startsWith('datareach ')).join('\n');
  t.eq('page i386: each DLL\'s data exports read', lines, 'datareach msftedit.dll ok\ndatareach riched20.dll ok\ndatareach oleacc.dll ok\ndatareach done', w.detail(r));
  t.check('page i386: no data export said out of reach', !/out of its 32-bit RVA's reach/.test(r.out), w.detail(r));
  w.clean();
}
