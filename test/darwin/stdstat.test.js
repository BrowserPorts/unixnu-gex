// fstat64 of a Darwin program's standard streams in the page
// (tests/darwin/src/stdstat.c, static, strict): they are pipes the page's
// global kernel holds, so each is what XNU's `pipe_stat` gives a pipe: a
// FIFO (S_IFIFO | 0660) of the caller's ids, no links, its size what is
// buffered for reading and its block size the size of its buffer (the
// global kernel's pipe's, 64 KiB), the write ends their reader's. Bytes
// written to standard input show as its size, and as FIONREAD's count;
// proc_pidfdlist says each is a pipe. (gexc's standard streams
// are the host's, each shown as what it is: tests/darwin/run.sh's
// stdstat.)
import { System } from '../../page/runtime/src/index.js';
import { MemoryFilesystem } from '../../page/runtime/src/fs.js';

export const meta = { hosts: ['browser'], arches: ['a64'], images: ['darwin-static'], timeout: 300 };

export default async function (t) {
  const { eq, timeout } = t;
  const image = await (await fetch(t.work('darwin-static.json'))).json();
  const boot = Object.fromEntries(image.boot.map((f) => [f, new URL(t.work(`darwin-static/boot/${f}`))]));
  const sys = new System({ baseUrl: t.baseUrl, arch: 'aarch64', darwin: { boot, strict: true }, debug: t.debug() });
  const fs = new MemoryFilesystem(sys);
  fs.addFiles({ '/var/tmp/stdstat': new URL(t.work('darwin-static/stdstat')) }, { mode: 0o755 });
  await timeout(sys.boot(), 60000, 'boot');
  const pipe = (fd, size = 0) => `fd ${fd} mode 10660 nlink 0 uid 0 gid 0 size ${size} blksize 65536 flags 0\n`;
  const r = await timeout(sys.run(['/var/tmp/stdstat']), 60000, 'stdstat');
  const ctx = `stderr: ${r.stderr.slice(-1000)}\nconsole: ${sys.state.console.slice(-2000)}`;
  eq('each standard stream is a pipe of the caller\'s', r.stdout, pipe(0) + pipe(1) + pipe(2), ctx);
  eq('and it ends', r.code, 0, ctx);
  const w = await timeout(sys.run(['/var/tmp/stdstat', 'wait'], { input: 'abcdef' }), 60000, 'stdstat wait');
  eq("standard input's size is what is buffered", w.stdout, pipe(0, 6), `stderr: ${w.stderr.slice(-1000)}`);
  // Their kinds as proc_pidfdlist gives them (pipes), FIONREAD (this end's
  // buffered bytes; a write end has none), and a vnode's fcntl refused.
  const k = await timeout(sys.run(['/var/tmp/stdstat', 'kinds'], { input: 'abcdef' }), 60000, 'stdstat kinds');
  eq('each is a pipe to proc_pidfdlist and to FIONREAD', k.stdout, 'fd 0 type 6 nread 6 nocache 9\nfd 1 type 6 nread 0 nocache 9\n', `stderr: ${k.stderr.slice(-1000)}\nconsole: ${sys.state.console.slice(-2000)}`);
  // gexc's: its host's streams as the image's run gave them, Node's
  // socket pairs, each soo_stat's (S_IFSOCK).
  t.say(`gexc's: ${JSON.stringify(image.native.stdstat?.stdout)}`);
  eq("gexc's standard streams, Node's socket pairs, are sockets", image.native.stdstat?.stdout.split('\n').filter(Boolean).map((l) => / mode (\d+) /.exec(l)?.[1].slice(0, 3)), ['140', '140', '140']);
  await sys.shutdown();
}
