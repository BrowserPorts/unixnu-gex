// The translated architecture read from the tree when the page names none:
// a tree of wasm32 programs only (busybox: a 32-bit ELF, i386 by its header)
// says nothing, and boot fails naming the `arch` option, never guessing one;
// the same tree with a Windows program (a 32-bit Wine tree's, i386 PE) boots
// on x86's kernel.
import { System } from '../../runtime/src/index.js';
import { MemoryFilesystem } from '../../runtime/src/fs.js';

export const meta = { hosts: ['browser'], images: ['busybox'], timeout: 120 };

/** The headers of an i386 Windows program, as far as the runtime reads one. */
function pe386() {
  const b = new Uint8Array(0x200);
  b[0] = 0x4d; b[1] = 0x5a; // MZ
  b[0x3c] = 0x80; // the PE header's offset
  b.set([0x50, 0x45, 0, 0, 0x4c, 0x01], 0x80); // PE\0\0, IMAGE_FILE_MACHINE_I386
  return b;
}

export default async function (t) {
  const { check, eq, timeout } = t;
  const { arch, ...debug } = t.debug();
  const sys = new System({ baseUrl: t.baseUrl, debug });
  const fs = new MemoryFilesystem(sys);
  fs.addTar(t.work('bb.tar.zst'));
  if (t.phase === 1) {
    const e = await timeout(sys.boot().then(() => null, (err) => err), 60000, 'boot');
    check('a wasm32-only tree, no arch: boot fails', !!e, e ? '' : `booted on ${sys.describe().arch}`);
    check('... naming the arch option', /arch/.test(e?.message ?? ''), e?.message ?? '');
    return t.reload();
  }
  fs.addFiles({ '/root/app.exe': pe386() });
  await timeout(sys.boot(), 60000, 'boot');
  eq('with an i386 Windows program: x86', sys.describe().arch, 'x86');
  const r = await timeout(sys.run(['sh', '-c', 'echo up'], { env: { PATH: '/bin' } }), 30000, 'sh');
  eq('and its wasm32 programs run', r.stdout.trim(), 'up');
}
