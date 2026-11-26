// fs.usedFiles: the files whose bytes the programs read, in the order of
// their first reads (a stat alone is no read); hostTimeZone: the browser's
// zone as a program's environment.
import { System, hostTimeZone } from '../../runtime/src/index.js';
import { MemoryFilesystem } from '../../runtime/src/fs.js';

export const meta = { hosts: ['browser'], images: ['busybox'], timeout: 120, single: 'usedFiles needs the default build' };

export default async function (t) {
  const { eq, check, timeout } = t;
  const sys = new System({ baseUrl: t.baseUrl, debug: t.debug() });
  const fs = new MemoryFilesystem(sys);
  fs.addTar(t.work('bb.tar.zst'));
  fs.addFiles({ '/srv/one.txt': 'one\n', '/srv/two.txt': 'two\n', '/srv/seen.txt': 'only stat\n' });
  await timeout(sys.boot(), 60000, 'boot');
  const env = { PATH: '/bin:/usr/bin', HOME: '/root' };
  const sh = (cmd, e = env) => timeout(sys.run(['sh', '-c', cmd], { env: e }), 60000, cmd);
  eq('the reads ran', (await sh('cat /srv/two.txt /srv/one.txt; ls -l /srv/seen.txt > /dev/null')).stdout, 'two\none\n');
  const used = (await fs.usedFiles()).map((p) => `/${p.replace(/^\/+/, '')}`);
  const two = used.indexOf('/srv/two.txt'), one = used.indexOf('/srv/one.txt');
  check('both read files are used', two >= 0 && one >= 0, JSON.stringify(used.filter((p) => p.startsWith('/srv'))));
  check('in the order of their first reads', two < one, `${two} ${one}`);
  check('a file only stat\'d is not', !used.includes('/srv/seen.txt'));

  const tz = hostTimeZone();
  const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  check('the zone has rules', typeof tz.TZ === 'string' && tz.TZ.length > 0, JSON.stringify(tz));
  eq('and its name', tz.WINEGEX_TZNAME, zone);
  const off = -new Date().getTimezoneOffset();
  const want = `${off < 0 ? '-' : '+'}${String(Math.trunc(Math.abs(off) / 60)).padStart(2, '0')}${String(Math.abs(off) % 60).padStart(2, '0')}`;
  eq('a program\'s clock is in it', (await sh('date +%z', { ...env, ...tz })).stdout.trim(), want);
  await sys.shutdown();
}
