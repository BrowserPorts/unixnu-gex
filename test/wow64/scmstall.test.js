// A services.exe started on demand (a session booted without wineboot,
// WINEGEX_NO_WINEBOOT=1: the first OpenSCManager starts it) that never
// serves is ended when its 60 s are up, by the caller that started it,
// saying so: the next caller starts another rather than waiting on it
// again. Natively, with a services.exe that only sleeps
// (fixtures/wow64/scmstall.c built -DNEVER, put in system32 and loaded as
// native): both asks fail, each after its own start, and each start is
// ended.
import { copyFileSync } from 'node:fs';
import { join } from 'node:path';
import { wow64 } from '../lib/winerun.mjs';

export const meta = { hosts: ['node'], arches: ['x86'], timeout: 600 };

const ENDED = /services\.exe did not serve in 60 s: ended, the next caller starts it again/g;

export default async function (t) {
  const w = wow64(t);
  const never = await w.mingw('scmstall', { x64: true, flags: ['-DNEVER'], out: 'never/services.exe' });
  const exe = await w.mingw('scmstall', { x64: true, libs: ['-ladvapi32'] });
  const r = await w.native(['C:\\scmstall.exe'], {
    files: { 'scmstall.exe': exe }, name: 'native', timeout: 400000,
    setup: (p) => copyFileSync(never, join(p, 'drive_c/windows/system32/services.exe')),
    wineEnv: { WINEGEX_NO_WINEBOOT: '1', WINEDLLOVERRIDES: 'services.exe=n' },
  });
  const lines = r.out.replace(/\r/g, '').split('\n').filter((l) => l.startsWith('scmstall ')).join('\n');
  t.eq('both asks fail', lines, 'scmstall 1 failed 1722\nscmstall 2 failed 1722', w.detail(r));
  t.eq('each services.exe that never served is ended, saying so', (r.out.match(ENDED) ?? []).length, 2, w.detail(r));
  w.clean();
}
