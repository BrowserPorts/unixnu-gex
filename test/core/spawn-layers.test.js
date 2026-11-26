// A program on a terminal over the layers a page lays (fs.js): the bundle as a
// tar (its hard links, modes and extended attributes), a tar of the caller's
// over it (a file over the bundle's, a file time, an empty directory, symbolic
// links, a directory link), and a lazy file; the program, by a directory
// link's name, a child of the kernel's pid 1; keys typed into it; its exit
// status; and its last output before the system stops.
import { System } from '../../runtime/src/index.js';
import { MemoryFilesystem } from '../../runtime/src/fs.js';
import { tarOf } from '../lib/tar.mjs';

export const meta = { hosts: ['browser', 'node'], images: ['busybox'], timeout: 180 };

export default async function (t) {
  const { say, check, eq, until, timeout } = t;
  const sys = new System({ baseUrl: t.baseUrl, debug: t.debug() });
  const fs = new MemoryFilesystem(sys);
  fs.addTar(t.work('bb.tar.zst'));
  fs.addTar(tarOf([
    { path: '/etc/hello', data: 'hello\n', mtime: 1000000000 },
    { path: '/empty', dir: true },
    { path: '/etc/link', link: '/etc/hello' },
    { path: '/lbin', link: 'bin' },
  ]), { lazy: [['/lazy.bin', 3 << 20, t.work('lazy-program.bin')]] });

  let out = '';
  const script = [
    'rt-probe tty',
    'echo "ppid $PPID"; cat /proc/1/comm',
    'ls -i /bin/sh /bin/ls | sort -k2 | awk \'{print $1}\' | uniq | wc -l | sed "s/^/inodes /"',
    'ls -l /bin/rt-probe | cut -c1-10 | sed "s/^/mode /"',
    'rt-probe xattr /etc/xattr user.rt',
    'date -r /etc/hello +%s | sed "s/^/mtime /"',
    'cat /etc/hello',
    'wc -c < /lazy.bin | sed "s/^/lazy /"',
    'readlink /etc/link',
    'readlink /lbin | sed "s/^/lbin /"',
    'read x; echo "got $x"',
    'echo last line; exit 7',
  ].join('\n');
  const t0 = performance.now();
  await timeout(sys.boot(), 60000, 'boot');
  // The program by a directory link's name (/bin/bash, /bin -> usr/bin).
  const p = sys.spawn(['/lbin/sh', '-c', script], { pty: { cols: 80, rows: 24 }, env: ['PATH=/bin:/usr/bin', 'HOME=/root'], cwd: '/' });
  const dec = new TextDecoder();
  p.pty.addEventListener('data', (e) => { out += typeof e.data === 'string' ? e.data : dec.decode(e.data, { stream: true }); });
  const run = p.exited.then(async ({ code }) => {
    await sys.shutdown();
    return { status: code };
  });
  run.catch((e) => { out += `\n[threw: ${e?.stack ?? e}]`; });
  await timeout(until(() => /\/dev\/pts\//.test(out), 'the terminal', 60000), 70000, 'start')
    .catch((e) => { throw new Error(`${e.message}: ${out.slice(-600)}`); });
  say(`the program runs in ${(performance.now() - t0).toFixed(0)} ms`);
  p.pty.write('typed\r');
  const r = await timeout(run, 30000, 'the end');
  const lines = out.replace(/\r/g, '');
  say(lines.split('\n').map((l) => `  | ${l}`).join('\n'));
  eq('the program\'s status', r.status, 7);
  check('the program on a terminal', /^\/dev\/pts\/\d+$/m.test(lines), lines.slice(0, 200));
  // (The terminal echoes the typed keys wherever they fall.)
  check('a child of the kernel\'s pid 1', /^ppid 1$/m.test(lines) && /^init$/m.test(lines));
  check('hard links are one inode', /^inodes 1$/m.test(lines));
  check('a file\'s mode', /^mode -rwxr-xr-x$/m.test(lines));
  check('an extended attribute', /^kept$/m.test(lines));
  check('a file time', /^mtime 1000000000$/m.test(lines));
  check('a file of a later layer over the bundle\'s', /^hello$/m.test(lines));
  check('a lazy file', new RegExp(`^lazy ${3 << 20}$`, 'm').test(lines));
  check('a symbolic link', /^\/etc\/hello$/m.test(lines));
  check('the program by a directory link\'s name, the link kept', /^lbin bin$/m.test(lines));
  check('keys from the terminal', /^got typed$/m.test(lines));
  check('the last line before the system stops', /^last line$/m.test(lines));
  eq('the system stopped', sys.state.phase, 'stopped');
}
