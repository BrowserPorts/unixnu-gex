// CopyFileW of a 64 MiB file (fixtures/wow64/cowcopy.c): each file keeps its
// own bytes through a write to either and the source's deletion, natively on
// the host's disk (C:), natively in gex's kernel file system (Z:\dev\shm)
// and on the page. In the kernel's file system the copy shares the source's
// bytes until written: Wine's CopyFile asks for
// FSCTL_DUPLICATE_EXTENTS_TO_FILE, which ntdll makes a copy_file_range, and
// Shmem grows by under 1 MiB, not 64. (The page's kernel shares a
// copy_file_range alike: native/clone-copy's page leg. This harness's page
// shows its programs no Shmem for the prefix, so its leg checks the bytes.)
// An installer's package copied to C:\windows\Installer used to hold its
// bytes twice.
import { wow64, graphics } from '../lib/winerun.mjs';

export const meta = { hosts: ['node'], arches: ['x86'], timeout: 1200 };

export default async function (t) {
  const w = wow64(t);
  const exe = await w.mingw('cowcopy', { x64: true, flags: ['-municode'] });
  const own = (leg, r) => t.check(`${leg}: each file keeps its own bytes`, /^cowcopy ok\r?$/m.test(r.out), w.detail(r));
  own('native, the host\'s disk', await w.native(['C:\\cowcopy.exe'], { files: { 'cowcopy.exe': exe }, name: 'native-disk', timeout: 300000 }));
  const shm = await w.native(['C:\\cowcopy.exe', 'Z:\\dev\\shm\\cowcopy'], { files: { 'cowcopy.exe': exe }, name: 'native-shm', timeout: 300000 });
  own('native, the kernel\'s file system', shm);
  const held = Number(/^cowcopy source held (-?\d+) KiB/m.exec(shm.out)?.[1]);
  t.check(`native: the source is in the kernel's file system (${held} KiB)`, held >= 64 * 1024, w.detail(shm));
  const added = Number(/^cowcopy shmem added (-?\d+) KiB/m.exec(shm.out)?.[1]);
  t.check(`native: the copy shares the source's bytes (Shmem +${added} KiB, under 1024)`, added >= 0 && added < 1024, w.detail(shm));
  own('page', await w.page(['/t/cowcopy.exe'], { files: { '/t/cowcopy.exe': exe }, userReg: graphics('null'), timeout: 300000 }));
  w.clean();
}
