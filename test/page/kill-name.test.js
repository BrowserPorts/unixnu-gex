// A process killed by another says the kill that reached it, not the last
// kill anyone sent: wineserver ending a program and then its conhost had
// the program's report name the conhost's kill ("from pid 3 to 70" in pid
// 69's). Two children, both left to die of SIGKILL from their parent, A
// first, B a moment after, then twenty SIGWINCHes the parent sends itself:
// each child's line must name its own kill.
import { guest } from '../lib/guest.mjs';

export const meta = { hosts: ['node'], arches: ['x86'], timeout: 300 };

const CODE = `#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>
int main(void) {
    int up[2];
    if (pipe(up)) return 2;
    pid_t k[2];
    for (int i = 0; i < 2; i++) {
        k[i] = fork();
        if (k[i] == 0) { (void)!write(up[1], "x", 1); for (;;) pause(); }
    }
    char c;
    for (int i = 0; i < 2; i++) (void)!read(up[0], &c, 1);
    usleep(100000);
    kill(k[0], SIGKILL);
    kill(k[1], SIGKILL);
    /* more kills after, to nobody that dies of them (SIGWINCH, ignored),
     * while A's Worker is still on its way to its end: anybody's last kill
     * is then never A's */
    signal(SIGWINCH, SIG_IGN);
    for (int i = 0; i < 20; i++) kill(getpid(), SIGWINCH);
    int st;
    waitpid(k[0], &st, 0);
    waitpid(k[1], &st, 0);
    printf("pids %d %d\\n", (int)k[0], (int)k[1]);
    return 0;
}
`;

export default async function (t) {
  const g = guest(t);
  g.pub('gex_browser{infix}.shared.wasm');
  g.pub('gex_kernel{infix}.wasm');
  const prog = g.cc({ name: 'kill-name', code: CODE });
  const seed = g.seed();
  const r = await g.run(seed, prog, [], { env: { GEX_SHARED: '1', GEX_LOG: 'debug' } });
  const m = r.stdout.match(/pids (\d+) (\d+)/);
  t.check('it ran', !!m, r.stdout + r.stderr.slice(-2000));
  if (!m) return;
  const [a, b] = [m[1], m[2]];
  const lines = (r.stdout + r.stderr).split('\n').filter((l) => /\[gex\] pid \d+ (ended|killed) by signal 9 \(signal #/.test(l));
  t.say(lines.join(' / '));
  for (const p of [a, b]) {
    const l = lines.find((x) => x.includes(`[gex] pid ${p} `));
    if (l) t.check(`pid ${p}: its own kill`, l.includes(` to ${p})`), l);
  }
  t.check('a line for either', lines.length > 0, 'no "ended by signal 9" line (GEX_LOG=debug)');
}
