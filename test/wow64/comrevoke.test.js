// A class object registered for other processes when no rpcss could be
// started (a session booted without wineboot, WINEGEX_NO_WINEBOOT=1, whose
// services.exe never serves) is revoked at once: the revoke is about what an
// rpcss holds, and starts none. Before, it waited on the service manager for
// another 60 s; explorer's exit sat in that wait (its class objects revoked at
// process detach) with its windows up and answering nothing.
import { copyFileSync } from 'node:fs';
import { join } from 'node:path';
import { wow64 } from '../lib/winerun.mjs';

export const meta = { hosts: ['node'], arches: ['x86'], timeout: 600 };

export default async function (t) {
  const w = wow64(t);
  const never = await w.mingw('scmstall', { x64: true, flags: ['-DNEVER'], out: 'never/services.exe' });
  const exe = await w.mingw('comrevoke', { x64: true, libs: ['-lole32', '-luuid'] });
  const r = await w.native(['C:\\comrevoke.exe'], {
    files: { 'comrevoke.exe': exe }, name: 'native', timeout: 400000,
    setup: (p) => copyFileSync(never, join(p, 'drive_c/windows/system32/services.exe')),
    wineEnv: { WINEGEX_NO_WINEBOOT: '1', WINEDLLOVERRIDES: 'services.exe=n' },
  });
  const out = r.out.replace(/\r/g, '');
  t.check('the register says S_OK', /^comrevoke register 00000000$/m.test(out), w.detail(r));
  const m = out.match(/^comrevoke revoke ([0-9a-f]{8}) (\d+)$/m);
  t.check('the revoke ends', !!m, w.detail(r));
  if (m) t.check(`the revoke starts no rpcss (${m[2]} ms)`, Number(m[2]) < 10000, w.detail(r));
  w.clean();
}
