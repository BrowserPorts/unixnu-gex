// Dynamic Darwin processes in one page share the system's shared region
// (tests/darwin/src/dynspawn.c, the `darwin-dyn` image's): each process of
// the page maps the boot's region as its own copy, made of the same cache
// files at the slide the system drew once, so two processes find the cache
// at the same address, as two tasks of one system do; the second's copy is
// made from the first's, which the page keeps once. Then a posix_spawn's
// dynamic child (dynspawn with no argument): spawned in a group of its own,
// refused a setpgid after its exec (EACCES), waited for, its exit status
// gexc's, its cache its parent's. Its time among the reaped children's is
// not measurable in the page (a Worker has no per-thread clock), which
// getrusage reports and refuses (ENOSYS), so the page's run is not strict.
import { System } from '../../page/runtime/src/index.js';
import { MemoryFilesystem } from '../../page/runtime/src/fs.js';
import { ROOT_OWNED, tarWithXattrs } from '../fixtures/xattr-tar.js';

export const meta = { hosts: ['browser'], arches: ['a64'], images: ['darwin-root', 'darwin-dyn'], timeout: 900 };

const PROG = '/var/tmp/gex-darwin-dynspawn';

export default async function (t) {
  const { eq, timeout } = t;
  const image = await (await fetch(t.work('darwin-dyn.json'))).json();
  const boot = Object.fromEntries(image.boot.map((f) => [f, new URL(t.work(`darwin-dyn/boot/${f}`))]));
  const disk0 = { url: t.work('darwin-root/disk0'), missing: new URL(t.work('darwin-root/disk0.missing')) };
  const sys = new System({ baseUrl: t.baseUrl, arch: 'aarch64', darwin: { boot, disk0, strict: false }, debug: t.debug() });
  const fs = new MemoryFilesystem(sys);
  fs.addTar(t.work('darwin-root/root.tar'), { lazy: t.work('darwin-root/root-lazy.json') });
  const body = new Uint8Array(await (await fetch(t.work('darwin-dyn/dynspawn'))).arrayBuffer());
  fs.addTar(tarWithXattrs(`private${PROG}`, body, ROOT_OWNED));
  await timeout(sys.boot(), 240000, 'boot');
  const first = await timeout(sys.run([PROG, 'cache']), 800000, 'dynspawn cache');
  const ctx = (r) => `stderr: ${r.stderr.slice(-2000)}\nconsole: ${sys.state.console.slice(-3000)}`;
  t.check("the first process's cache", /^dynspawn cache [0-9a-f]+\n$/.test(first.stdout), ctx(first));
  const s0 = performance.now();
  const second = await timeout(sys.run([PROG, 'cache']), 800000, 'dynspawn cache again');
  t.say(`a second process started and ran in ${((performance.now() - s0) / 1000).toFixed(1)} s`);
  eq("a second process's cache, at the first's address", second.stdout, first.stdout, ctx(second));
  const native = image.native.dynspawn;
  eq("gexc's run", native.stdout, 'dynspawn spawn 0 pgid 1 setpgid 13 wait 1 exit 7\ndynspawn usage 1\ndynspawn ok\n');
  const p0 = performance.now();
  const spawned = await timeout(sys.run([PROG]), 800000, 'dynspawn');
  t.say(`the spawn, its child's start and run and its wait took ${((performance.now() - p0) / 1000).toFixed(1)} s`);
  await t.saveFile('console.txt', sys.state.console);
  const [line, usage] = spawned.stdout.split('\n');
  eq('the spawned child: its group, its setpgid, its wait and its status, as gexc\'s', line, native.stdout.split('\n')[0], ctx(spawned));
  eq('its usage, which the page cannot measure, refused (ENOSYS)', usage, 'dynspawn usage -78');
  t.check('and said', sys.state.console.includes("getrusage(RUSAGE_CHILDREN)'s times on a host without per-thread clocks"), sys.state.console.slice(-2000));
  for (const l of sys.state.console.split('\n').filter((l) => l.includes('Darwin: not implemented'))) t.say(`console: ${l.slice(0, 240)}`);
  await sys.shutdown();
}
