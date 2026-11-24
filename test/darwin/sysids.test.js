// tests/darwin/src/sysids.c on the page, twice, half a second apart: each
// run is a process of its own, a Worker with a kernel instance of its own,
// whose system identifiers (its unique id and pidversion, its thread's
// unique id) and counter (mach_absolute_time) are the Darwin system's,
// which the page's global kernel holds for every process
// (gex_kernel::darwin::share), as one host process holds them for gexc's.
// So the second takes later identifiers than the first, and its counter
// runs from the same origin: at least the half second between them past
// the first's. Each run's output and status match gexc's.
import { System } from '../../page/runtime/src/index.js';
import { MemoryFilesystem } from '../../page/runtime/src/fs.js';

export const meta = { hosts: ['browser'], arches: ['a64'], images: ['darwin-static'], timeout: 300 };

/** mach_absolute_time's 24 MHz: half a second of it. */
const HALF_SECOND = 12_000_000n;

export default async function (t) {
  const { eq, timeout } = t;
  const image = await (await fetch(t.work('darwin-static.json'))).json();
  const native = image.native.sysids;
  eq("sysids: gexc's output", native.stdout, 'sysids ok\n');
  eq("sysids: gexc's status", native.status, 0);
  const boot = Object.fromEntries(image.boot.map((f) => [f, new URL(t.work(`darwin-static/boot/${f}`))]));
  const sys = new System({ baseUrl: t.baseUrl, arch: 'aarch64', darwin: { boot, strict: true }, debug: t.debug() });
  const fs = new MemoryFilesystem(sys);
  fs.addFiles({ '/var/tmp/sysids': new URL(t.work('darwin-static/sysids')) }, { mode: 0o755 });
  await timeout(sys.boot(), 60000, 'boot');
  const ids = [];
  for (let i = 0; i < 2; i++) {
    if (i) await new Promise((r) => setTimeout(r, 500));
    const r = await timeout(sys.run(['/var/tmp/sysids']), 60000, 'sysids');
    const ctx = `stderr: ${r.stderr.slice(-2000)}\nconsole: ${sys.state.console.slice(-2000)}`;
    eq(`sysids ${i + 1}: output, as gexc's`, r.stdout, native.stdout, ctx);
    eq(`sysids ${i + 1}: status, as gexc's`, r.code, native.status, r.signal ? `signal ${r.signal}` : undefined);
    const m = r.stderr.match(/^sysids uniqueid=(\d+) pidversion=(\d+) thread=(\d+) abs=(\d+)$/m);
    t.check(`sysids ${i + 1}: its identifiers`, m !== null, ctx);
    if (m) {
      ids.push(m.slice(1).map(BigInt));
      t.say(`sysids ${i + 1}: ${m[0]}`);
    }
  }
  if (ids.length === 2) {
    const [a, b] = ids;
    const both = `first ${a.join(' ')}, second ${b.join(' ')}`;
    t.check('the second process takes a later unique id', b[0] > a[0], both);
    t.check('and a later pidversion', b[1] > a[1], both);
    t.check('and its thread a later unique id', b[2] > a[2], both);
    t.check('and its counter runs from the system\'s origin', b[3] - a[3] >= HALF_SECOND, both);
  }
  await sys.shutdown();
}
