// D3D presents paced in the compositor (page/src/d3d-pacing.js): a client's
// reply is held while it has as many frames presented and unshown as its swap
// interval, released when the page shows them or after the cap, and never
// held at interval 0. The interval comes from Mesa's environment
// (GEXGL_SWAP_INTERVAL in `?mesaenv=`).
import { D3dPacer, d3dSwapInterval } from '../../page/src/d3d-pacing.js';

export const meta = { hosts: ['node'], arches: ['a64'], timeout: 60 };

export default async function (t) {
  t.eq('no environment: interval 1', d3dSwapInterval(undefined), 1);
  t.eq('GEXGL_SWAP_INTERVAL=0', d3dSwapInterval('MESA_DEBUG=x,GEXGL_SWAP_INTERVAL=0'), 0);
  t.eq('GEXGL_SWAP_INTERVAL=1', d3dSwapInterval('GEXGL_SWAP_INTERVAL=1'), 1);
  t.eq('GEXGL_SWAP_INTERVAL=2: the default', d3dSwapInterval('GEXGL_SWAP_INTERVAL=2'), 1);

  // Two clients' unshown frames, and timers the test runs by hand.
  const unshown = new Map([[1, 0], [2, 0]]);
  const timers = new Set();
  const opts = {
    unshown: (c) => unshown.get(c) ?? 0,
    setTimer: (fn) => {
      const timer = { fn };
      timers.add(timer);
      return timer;
    },
    clearTimer: (timer) => timers.delete(timer),
  };
  const pacer = new D3dPacer({ interval: 1, ...opts });
  let released = 0;
  const hold = (client) => {
    const p = pacer.after(client);
    p?.then(() => released++);
    return p;
  };
  const settle = () => new Promise((r) => setTimeout(r, 0));

  unshown.set(1, 0);
  t.eq('nothing unshown: not held', hold(1), null);
  unshown.set(1, 1);
  t.check('one unshown at interval 1: held', hold(1) instanceof Promise);
  t.eq('held', pacer.held, 1);
  unshown.set(2, 0);
  t.eq('another client, nothing unshown: not held', hold(2), null);
  pacer.shown();
  await settle();
  t.eq('the page showed nothing of it: still held', [pacer.held, released], [1, 0]);
  unshown.set(1, 0);
  pacer.shown();
  await settle();
  t.eq('shown: released, its cap timer gone', [pacer.held, released, timers.size], [0, 1, 0]);

  unshown.set(1, 3);
  hold(1);
  t.eq('held again, one cap timer', [pacer.held, timers.size], [1, 1]);
  for (const timer of [...timers]) timer.fn();
  await settle();
  t.eq('a page that shows nothing: released at the cap', [pacer.held, released], [0, 2]);

  const off = new D3dPacer({ interval: 0, ...opts });
  unshown.set(1, 10);
  t.eq('interval 0: never held', off.after(1), null);
}
