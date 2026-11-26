// @gexemu/runtime/drop's HostDrop: files dropped on the page copied into the
// guest (here an array of Files, as a FileList would be), with no window
// under the point; their modes; `fallback` taking them when no window does;
// the argument checks.
import { System } from '../../runtime/src/index.js';
import { MemoryFilesystem } from '../../runtime/src/fs.js';
import { HostDrop } from '../../runtime/src/drop.js';

export const meta = { hosts: ['browser'], images: ['busybox'], timeout: 120, single: 'the drop Worker needs the shared kernel' };

export default async function (t) {
  const { eq, check, timeout } = t;
  const sys = new System({ baseUrl: t.baseUrl, debug: t.debug() });
  const fs = new MemoryFilesystem(sys);
  fs.addTar(t.work('bb.tar.zst'));
  const drop = new HostDrop(sys);
  const early = await drop.drop([new File(['x'], 'x.txt')]).then(() => '', (e) => e.message);
  check('before boot: refused', /not running/.test(early), early);
  await timeout(sys.boot(), 60000, 'boot');
  const env = { PATH: '/bin:/usr/bin', HOME: '/root' };
  const sh = (cmd) => timeout(sys.run(['sh', '-c', cmd], { env }), 60000, cmd);

  const big = new Uint8Array(3 << 20).map((_, i) => i & 0xff);
  const elf = new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 1, 1, 1, 0]);
  let progress = 0;
  const r = await timeout(drop.drop([new File(['hello\n'], 'a b.txt'), new File([big], 'big.bin'), new File([elf], 'prog')], { onProgress: () => { progress++; } }), 60000, 'the drop');
  check('copied into a new /tmp/drops/N', /^\/tmp\/drops\/\d+$/.test(r.path), r.path);
  eq('its files', r.files, 3);
  eq('its bytes', r.bytes, 6 + big.length + elf.length);
  eq('no window under no point', [r.window, r.accepted], [null, false]);
  eq('where they are', r.paths, [`${r.path}/a b.txt`, `${r.path}/big.bin`, `${r.path}/prog`]);
  check('progress was said', progress > 0, String(progress));
  eq('a file\'s text', (await sh(`cat "${r.path}/a b.txt"`)).stdout, 'hello\n');
  const got = await fs.readFile(`${r.path}/big.bin`);
  check('a big file\'s bytes', got.length === big.length && got.every((v, i) => v === big[i]));
  eq('modes: a file 0644, a program 0755', [(await fs.stat(`${r.path}/a b.txt`)).mode & 0o777, (await fs.stat(`${r.path}/prog`)).mode & 0o777], [0o644, 0o755]);

  const f = await timeout(drop.drop([new File(['one\n'], 'note.txt')], { x: 5, y: 5, fallback: '/root/Desktop' }), 60000, 'with a fallback');
  eq('no window took it: moved to the fallback', f.paths, ['/root/Desktop/note.txt']);
  eq('it is there', (await sh('cat /root/Desktop/note.txt')).stdout, 'one\n');
  const again = await timeout(drop.drop([new File(['two\n'], 'note.txt')], { fallback: '/root/Desktop' }), 60000, 'the same name');
  eq('a name taken there is numbered', again.paths, ['/root/Desktop/note (2).txt']);

  const bad = await drop.drop([new File(['x'], 'x')], { dir: 'relative' }).then(() => '', (e) => e.message);
  check('a relative dir is refused', /absolute guest path/.test(bad), bad);
  const none = await drop.drop('text').then(() => '', (e) => e.message);
  check('what is not a drop is refused', /DataTransfer/.test(none), none);
  eq('no window at a point with no windows', await drop.windowAt(1, 1), null);
  await sys.shutdown();
}
