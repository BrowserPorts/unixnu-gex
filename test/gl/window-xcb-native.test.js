// gl/window-xcb natively: Xwayland as a client of gexc's compositor
// (--wayland), /probes/gles-window-xcb's source built with the host's cc
// against the guest GL and run under gexc --gl, with libxcb alone in the
// process. Its EGL display and window surface come through
// EGL_EXT_platform_xcb: the surface has the window's size, the config the
// screen's root visual, and frames draw without a GL error. The browser test
// (gl/window-xcb) also looks at the pixels; this one needs no GPU.
import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT, tail } from '../lib/native.mjs';
import { hostGl } from './hostgl.mjs';

export const meta = { hosts: ['node'], arches: ['x86'], timeout: 600 };
// Seconds Xwayland has to say its display, inside gexc's 480 s for the whole run.
const WAIT = 400;

export default async function (t) {
  const xwayland = '/usr/bin/Xwayland';
  if (!existsSync(xwayland)) return t.skip(`no ${xwayland}`);
  const h = await hostGl(t);
  const probe = join(h.dir, 'gles-window-xcb');
  await h.n.hostcc(['-O2', '-Wall', `-I${join(ROOT, 'third_party/opengl-registry/api')}`, '-o', probe,
    join(ROOT, 'guest/gl/probes/gles-window-xcb.c'), `-L${h.gl}`, '-l:libEGL.so.1', '-l:libGLESv2.so.2', '-ldl']);
  // Xwayland picks a free display and says which (-displayfd), so runs side
  // by side do not meet. Translated, it takes minutes to start on a busy
  // host: it gets most of the run's time to say its display.
  const script = join(h.dir, 'run.sh');
  writeFileSync(script, `d=${h.dir}
${xwayland} -noreset -displayfd 3 3>$d/display 2>$d/xwayland.log &
x=$!
t0=$(date +%s); while [ ! -s $d/display ] && [ $(($(date +%s) - t0)) -lt ${WAIT} ]; do sleep 0.5; done
[ -s $d/display ] || { echo "xwayland: no display in $(($(date +%s) - t0)) s"; kill $x; exit 0; }
DISPLAY=:$(cat $d/display) LD_LIBRARY_PATH=${h.gl} ${probe} 10 0
echo "exit $?"
kill $x
`);
  const r = await h.n.gexc(['run', '--wayland', join(h.dir, 'wl'), '--wayland-out', 'null', '--gl', '/bin/sh', script], { timeout: 480000 });
  const out = r.stdout.split('\n');
  const said = `exit ${r.code}: ${tail(r.stdout)} ${tail(r.stderr)}`;
  const nox = out.find((l) => l.startsWith('xwayland: no display'));
  t.check('Xwayland gave its display', !nox, nox?.replace('xwayland: no display', 'Xwayland gave no display'));
  t.eq('surface', out.find((l) => l.startsWith('surface')), 'surface 200x150 visual same', said);
  t.eq('frames', out.find((l) => l.startsWith('frames')), 'frames 10 gl error 0', said);
  t.eq('probe exit', out.find((l) => l.startsWith('exit')), 'exit 0', said);
  h.n.clean();
}
