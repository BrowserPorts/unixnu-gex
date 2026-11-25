// A dynamic Darwin program in the page (tests/darwin/src/hello.c): dyld from
// the root, libSystem from the shared cache, the cache from the OS
// cryptex's graft on disk0's Preboot volume, as gexc runs it. The root is
// the `darwin-root` image's, laid as the page's filesystem (its /var, /tmp
// and /etc the Darwin root's links, not the page's own directories), disk0
// the image's, read by ranges; the program is in the root's /var/tmp with
// its owner recorded, as tests/darwin/run.sh places it. Its output and
// status must be gexc's (the `darwin-dyn` image, strict). The page's run is
// not strict: the page cannot say which pages of its memory a task has
// touched, so libmalloc's phys_footprint is reported as not done there
// (and a strict run stops at it); every such report is said. The time the run
// took (most of it mapping the cache and translating dyld's and the
// cache's code) is said, against gexc's.
import { System } from '../../page/runtime/src/index.js';
import { MemoryFilesystem } from '../../page/runtime/src/fs.js';
import { ROOT_OWNED, tarWithXattrs } from '../fixtures/xattr-tar.js';

/** What gexc says of its own standard streams, its host's (darwin/hoststd.rs):
 *  not the page's, whose streams are its pipes. */
const HOST_STREAMS = "[gex] Darwin: the host's standard streams stand in:";

export const meta = { hosts: ['browser'], arches: ['a64'], images: ['darwin-root', 'darwin-dyn'], timeout: 900 };

const PROG = '/var/tmp/gex-darwin-hello';

export default async function (t) {
  const { eq, timeout } = t;
  const image = await (await fetch(t.work('darwin-dyn.json'))).json();
  const native = image.native.hello;
  eq("gexc's run", [native.stdout, native.status], [`hello from ${PROG} with 2 arguments\n`, 0]);
  const boot = Object.fromEntries(image.boot.map((f) => [f, new URL(t.work(`darwin-dyn/boot/${f}`))]));
  const disk0 = { url: t.work('darwin-root/disk0'), missing: new URL(t.work('darwin-root/disk0.missing')) };
  // `log: 'debug'`: each process's numbers at its end (its translation's
  // time and its modules' compiles), on the browser's console.
  const sys = new System({ baseUrl: t.baseUrl, arch: 'aarch64', darwin: { boot, disk0, strict: false }, debug: t.debug({ log: 'debug' }) });
  const fs = new MemoryFilesystem(sys);
  fs.addTar(t.work('darwin-root/root.tar'), { lazy: t.work('darwin-root/root-lazy.json') });
  const body = new Uint8Array(await (await fetch(t.work('darwin-dyn/hello'))).arrayBuffer());
  fs.addTar(tarWithXattrs(`private${PROG}`, body, ROOT_OWNED));
  const b0 = performance.now();
  await timeout(sys.boot(), 240000, 'boot');
  t.say(`the system booted with the root in ${((performance.now() - b0) / 1000).toFixed(1)} s`);
  // The Darwin root's layout, as gexc's root has it.
  for (const [link, to] of [['/var', 'private/var'], ['/tmp', 'private/var/tmp'], ['/etc', 'private/etc']]) {
    eq(`${link} is the root's link`, await fs.readlink(link).catch((e) => `not a link (${e.code ?? e.message})`), to);
  }
  const r0 = performance.now();
  const r = await timeout(sys.run([PROG, 'a', 'b']), 800000, 'hello');
  const ms = performance.now() - r0;
  await t.saveFile('console.txt', sys.state.console);
  const ctx = `stderr: ${r.stderr.slice(-2000)}\nconsole: ${sys.state.console.slice(-4000)}`;
  eq("output, as gexc's", r.stdout, native.stdout, ctx);
  eq("status, as gexc's", r.code, native.status, r.signal ? `signal ${r.signal}` : ctx);
  t.say(`the run took ${(ms / 1000).toFixed(1)} s in the page, ${(native.ms / 1000).toFixed(1)} s under gexc`);
  // A second run in the same system: a process that joins the booted
  // system (its container, grafts and trust caches the system's), its code
  // translated again in a process of its own.
  const s0 = performance.now();
  const again = await timeout(sys.run([PROG, 'a', 'b']), 800000, 'hello again');
  t.say(`a second run took ${((performance.now() - s0) / 1000).toFixed(1)} s`);
  eq("a second run's output, as gexc's", again.stdout, native.stdout, `stderr: ${again.stderr.slice(-2000)}\nconsole: ${sys.state.console.slice(-3000)}`);
  eq("and its status", again.code, native.status);
  const said = sys.state.console.split('\n');
  for (const line of native.reports.filter((l) => !l.startsWith(HOST_STREAMS))) {
    const subject = line.slice(0, line.indexOf(':', line.indexOf(':') + 1) + 1);
    t.check(`the Darwin kernel's report on the console: ${subject}`, said.some((l) => l.startsWith(subject)), sys.state.console.slice(-2000));
  }
  for (const l of said.filter((l) => l.includes('Darwin: not implemented'))) t.say(`console: ${l.slice(0, 240)}`);
  await sys.shutdown();
}
