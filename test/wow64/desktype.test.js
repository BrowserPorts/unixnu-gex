// Typing on Wine's desktop (explorer /desktop=shell) selects the icon whose
// title starts with what was typed, and Enter opens it, as on Windows
// (desktype.c): a click on the desktop where no icon is, then Z, T and Enter
// through SendInput, open the desktop's ztarget.exe. The click leaves nothing
// foreground (the desktop window never is), so explorer has to make the
// desktop's own hidden window foreground for the keys to reach it. Natively,
// under gexc's Wayland compositor; the program makes its desktop the input
// desktop first (SwitchDesktop), the only one injected input goes to.
import { copyFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { graphics, wow64 } from '../lib/winerun.mjs';

export const meta = { hosts: ['node'], arches: ['x86'], timeout: 900 };

export default async function (t) {
  const w = wow64(t);
  const exe = await w.mingw('desktype', { x64: true, flags: ['-Wall'] });
  const r = await w.native(['explorer', '/desktop=shell,1280x800', 'C:\\desktype.exe'], {
    files: { 'desktype.exe': exe }, userReg: graphics('wayland'), wayland: { size: '1280x800', out: 'null' },
    wineEnv: { USER: 'gex', HOME: '/tmp' }, name: 'desktype', timeout: 240000,
    setup: (p) => {
      // (the prefix is made without a display: the driver, as wineboot would install it)
      const drv = join(p, 'drive_c/windows/system32/winewayland.drv');
      if (!existsSync(drv)) copyFileSync(join(w.dist, 'lib/wine/x86_64-windows/winewayland.drv'), drv);
      const desk = join(p, 'drive_c/users/gex/Desktop');
      mkdirSync(desk, { recursive: true });
      copyFileSync(exe, join(desk, 'ztarget.exe'));
    },
  });
  // (what the program found, which it writes there: it has no console)
  const said = existsSync(join(r.pfx, 'drive_c/desktype.txt')) ? readFileSync(join(r.pfx, 'drive_c/desktype.txt'), 'utf8') : '';
  for (const l of said.split('\n').filter(Boolean)) t.say(l);
  t.check('typing ZT then Enter on the desktop opened ztarget.exe', /^desktype ok/m.test(said), said.trim() || w.detail(r, 4));
  w.clean();
}
