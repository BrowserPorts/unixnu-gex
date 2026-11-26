// CopyFileW of a 64 MiB file (fixtures/wow64/cowcopy.c) in a prefix whose
// root is an OPFSFilesystem: Wine's CopyFile asks for
// FSCTL_DUPLICATE_EXTENTS_TO_FILE, a copy_file_range, which the store's
// blocks share until written (core/fs-store-share is the same without
// Wine). Each file keeps its own bytes through a write to either and the
// source's deletion; the written copy, synced, reads back whole after a
// reload.
import { OPFSFilesystem } from '../../runtime/src/fs.js';
import { bootWine, WINE } from '../lib/wine.mjs';

export const meta = { hosts: ['browser'], arches: ['x86'], images: ['wine64', 'win-progs'], timeout: 1800 };

const MB = 1 << 20;
const LEN = 64 * MB;

/** fixtures/wow64/cowcopy.c's b.bin: its pattern, "copy!" at 70000. */
function copy() {
  const b = new Uint8Array(LEN);
  for (let i = 0; i < LEN; i++) b[i] = (i * 7 + (i >>> 16)) & 255;
  b.set(new TextEncoder().encode('copy!'), 70000);
  return b;
}

function same(a, b) {
  if (a.length !== b.length) return `${a.length} bytes, not ${b.length}`;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return `byte ${i} is ${a[i]}, not ${b[i]}`;
  return '';
}

export default async function (t) {
  const STORE = `gex-test-cowcopy-${t.arch}`;
  if (t.phase === 1) await OPFSFilesystem.erase(STORE);
  let fs;
  const w = await bootWine(t, { wow64: true, filesystem: (sys) => (fs = new OPFSFilesystem(sys, { name: STORE, cache: 64 })) });
  if (t.phase === 1) {
    await w.put('cowcopy.exe');
    const server = await w.startServer();
    const before = await fs.size();
    const r = await t.timeout(w.sys.run([WINE, 'C:\\cowcopy.exe', 'C:\\cowcopy', 'keep'], { env: w.env, cwd: '/pfx/drive_c' }), 600000, 'cowcopy');
    const out = r.stdout.replace(/\r/g, '');
    t.check('each file keeps its own bytes', /^cowcopy ok$/m.test(out), `code ${r.code} stdout ${JSON.stringify(out.slice(-400))} stderr ${JSON.stringify(r.stderr.slice(-600))}`);
    server.kill();
    await w.sys.sync();
    await w.sys.shutdown();
    // The source and a shared copy: one 64 MiB of blocks (the store grows
    // 64 MiB ahead); unshared, 128.
    const after = await fs.size();
    t.check(`the copy shares the source's blocks (the store ${(before / MB).toFixed(0)} MiB before, ${(after / MB).toFixed(0)} MiB after)`, after - before < 128 * MB, `${before} ${after}`);
    return t.reload();
  }
  const why = same(await fs.readFile('/pfx/drive_c/cowcopy/b.bin'), copy());
  t.check('after a reload the written copy reads back', !why, why);
  let gone = false;
  try { await fs.stat('/pfx/drive_c/cowcopy/a.bin'); } catch { gone = true; }
  t.check('and its deleted source is gone', gone);
  await w.sys.shutdown();
  await fs.erase();
}
