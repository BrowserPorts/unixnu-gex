// A process that crashes in the runtime is reported (System's `crash`
// event) even when another process kills it at the same moment: rt-probe
// killrace's child crashes the kernel on purpose (prctl PR_GEX_DEBUG_TRAP,
// armed by `debugpanic=prctl`), and its other thread sends the process
// SIGKILL the moment the crash begins, so the kill ends the process in that
// thread's Worker while the crashed one's is still on its way to its end. Before, the kill's end claimed the process first and
// the crash was never said. Then rt-killwait: SIGKILL ends a process whose
// every thread is waiting.
import { System } from '../../runtime/src/index.js';
import { MemoryFilesystem } from '../../runtime/src/fs.js';

export const meta = { hosts: ['node', 'browser'], images: ['busybox'], timeout: 300 };

const ROUNDS = 8;

export default async function (t) {
  const { check, eq, timeout } = t;
  const sys = new System({ baseUrl: t.baseUrl, debug: { ...t.debug(), debugpanic: 'prctl' } });
  const fs = new MemoryFilesystem(sys);
  fs.addTar(t.work('bb.tar.zst'));
  const crashes = [];
  sys.addEventListener('crash', (e) => crashes.push({ pid: e.pid, name: e.name, reason: e.reason, code: e.code, signal: e.signal }));
  await timeout(sys.boot(), 60000, 'boot');
  const r = await sys.run(['rt-probe', 'killrace', String(ROUNDS)], { env: { PATH: '/bin:/usr/bin' } });
  eq('killrace: it ran to its end', r.code, 0);
  const rounds = r.stdout.split('\n').filter((l) => l.startsWith('round ')).map((l) => l.split(' ').map(Number));
  eq('killrace: every round', rounds.length, ROUNDS);
  for (let i = 0; i < 100 && crashes.length < rounds.length; i++) await new Promise((res) => setTimeout(res, 50));
  t.say(`rounds: ${JSON.stringify(rounds)} crashes: ${JSON.stringify(crashes)}`);
  for (const [, n, , pid, status] of rounds) {
    const c = crashes.find((x) => x.pid === pid);
    check(`round ${n}: pid ${pid} (status ${status}) is reported as a crash`, !!c, `crash reports: ${JSON.stringify(crashes)}`);
  }
  // A SIGKILL that was delivered ends the process, whatever its threads
  // wait on (a futex, a pipe, poll, a sleep): conhost survived one.
  const w = await sys.run(['rt-killwait', '4'], { env: { PATH: '/bin:/usr/bin' } });
  const kw = w.stdout.split('\n').filter((l) => l.startsWith('killwait '));
  eq('killwait: every round', kw.length, 4);
  for (const l of kw) {
    const [, n, how, ms] = l.split(' ').map(Number);
    check(`killwait ${n}: SIGKILL ends a process whose threads all wait`, how === 137, `ended ${how} after ${ms} ms (-1: still running at 10 s)`);
  }
  await sys.shutdown();
}
