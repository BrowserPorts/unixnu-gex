// tests/darwin/src/cpuclk.c on the page: the calls that read a thread's
// processor time. gexc reads each host thread's clock; a Worker has none (its
// performance.now() is the wall clock's, which runs on while its thread is
// off a processor), so the page's Darwin kernel keeps no thread's time. Each
// call that would give one out fails instead, with the kernel's report on the
// system's console, where gexc's run of the same program succeeds at each.
// The reaped children's usage (getrusage RUSAGE_CHILDREN) is their times as
// each child's end gave them: with no child reaped it is all zero, known, and
// given. The run is not strict: a strict one stops at the first report.
import { System } from '../../page/runtime/src/index.js';
import { MemoryFilesystem } from '../../page/runtime/src/fs.js';

export const meta = { hosts: ['browser'], arches: ['a64'], images: ['darwin-static'], timeout: 300 };

const ENOSYS = 78;
const EINVAL = 22;
const KERN_NOT_SUPPORTED = 46;

/** Each call the page refuses, its error, and the report it makes. */
const REFUSED = [
  ['getrusage-self', ENOSYS, "getrusage's times on a host without per-thread clocks"],
  ['thread_selfusage', ENOSYS, 'thread_selfusage on a host without per-thread clocks'],
  ['setitimer-virtual', ENOSYS, 'a virtual timer on a host without per-thread clocks'],
  ['setitimer-prof', ENOSYS, 'a virtual timer on a host without per-thread clocks'],
  ['setrlimit-cpu', EINVAL, 'setrlimit(RLIMIT_CPU) on a host without per-thread clocks'],
  ['thread_info', KERN_NOT_SUPPORTED, "thread_info THREAD_BASIC_INFO's times on a host without per-thread clocks"],
];

export default async function (t) {
  const { eq, timeout } = t;
  const image = await (await fetch(t.work('darwin-static.json'))).json();
  const native = image.native.cpuclk;
  eq("cpuclk: gexc's output", native.stdout, 'cpuclk ok\n');
  eq("cpuclk: gexc's status", native.status, 0);
  // gexc's run reports what its boot answers with stand-ins, as every
  // program's does, and nothing of the threads' times.
  eq("cpuclk: gexc's reports of the threads' times", native.reports.filter((l) => l.includes('per-thread clocks')), []);
  const boot = Object.fromEntries(image.boot.map((f) => [f, new URL(t.work(`darwin-static/boot/${f}`))]));
  const sys = new System({ baseUrl: t.baseUrl, arch: 'aarch64', darwin: { boot, strict: false }, debug: t.debug() });
  const fs = new MemoryFilesystem(sys);
  fs.addFiles({ '/var/tmp/cpuclk': new URL(t.work('darwin-static/cpuclk')) }, { mode: 0o755 });
  await timeout(sys.boot(), 60000, 'boot');
  const r = await timeout(sys.run(['/var/tmp/cpuclk']), 120000, 'cpuclk');
  await t.saveFile('console.txt', sys.state.console);
  const ctx = `stderr: ${r.stderr.slice(-2000)}\nconsole: ${sys.state.console.slice(-4000)}`;
  eq('cpuclk: output', r.stdout, REFUSED.map(([call, err]) => `${call} ${err}\n`).join(''), ctx);
  eq('cpuclk: status', r.code, REFUSED.length, r.signal ? `signal ${r.signal}` : undefined);
  const said = sys.state.console.split('\n');
  for (const what of new Set(REFUSED.map(([, , what]) => what))) {
    t.check(`the Darwin kernel's report: ${what}`, said.some((l) => l.includes(`Darwin: not implemented: ${what}`)), sys.state.console.slice(-2000));
  }
  await sys.shutdown();
}
