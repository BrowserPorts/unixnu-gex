// proc_pidfdinfo(PROC_PIDFDPIPEINFO) in the page (tests/darwin/src/pipeinfo.c,
// static, strict): a Darwin process's own pipes, as gexc gives them, and its
// standard streams, pipes the page's global kernel holds. Each is what XNU's
// fill_pipeinfo gives: a FIFO of the caller's, its size what the read side
// buffers and its block size MAX_PIPESIZE (the write end its peer's), its
// handle its peer's peer handle, and its status the end's pipe_state
// (PIPE_ASYNC, PIPE_WANTR and PIPE_WANTW as its readers and writers sleep,
// PIPE_WSELECT, PIPE_EOF). Standard input, written and closed by the page,
// is at its end with no peer; standard output has the page's reader for a
// peer, and the global kernel's pipe's 64 KiB buffer.
import { System } from '../../runtime/src/index.js';
import { MemoryFilesystem } from '../../runtime/src/fs.js';

export const meta = { hosts: ['browser'], arches: ['a64'], images: ['darwin-static'], timeout: 300 };

const WANT = `open r size 0 blocks 0 blksize 16384 status 0
open w size 0 blocks 0 blksize 16384 status 0
written r size 5 blocks 1 blksize 16384 status 0
written w size 5 blocks 1 blksize 16384 status 0
async r size 5 blocks 1 blksize 16384 status 4
async w size 5 blocks 1 blksize 16384 status 0
reader r size 0 blocks 0 blksize 16384 status 8
read r size 0 blocks 0 blksize 16384 status 0
writer r size 65536 blocks 1 blksize 65536 status 16
writer w size 65536 blocks 1 blksize 65536 status 0
drained r size 0 blocks 0 blksize 65536 status 0
closed r size 3 blocks 1 blksize 65536 status 128
select-w r size 0 blocks 0 blksize 16384 status 16384
select-w w size 0 blocks 0 blksize 16384 status 0
select-r w size 0 blocks 0 blksize 16384 status 16384
closed w size 0 blocks 0 blksize 16384 status 16512
pipeinfo ok
`;

export default async function (t) {
  const { eq, timeout } = t;
  const image = await (await fetch(t.work('darwin-static.json'))).json();
  const boot = Object.fromEntries(image.boot.map((f) => [f, new URL(t.work(`darwin-static/boot/${f}`))]));
  const sys = new System({ baseUrl: t.baseUrl, arch: 'aarch64', darwin: { boot, strict: true }, debug: t.debug() });
  const fs = new MemoryFilesystem(sys);
  fs.addFiles({ '/var/tmp/pipeinfo': new URL(t.work('darwin-static/pipeinfo')) }, { mode: 0o755 });
  await timeout(sys.boot(), 60000, 'boot');
  const native = image.native.pipeinfo;
  eq("gexc's run", [native.stdout, native.status], [WANT, 0]);
  const r = await timeout(sys.run(['/var/tmp/pipeinfo']), 120000, 'pipeinfo');
  const ctx = `stderr: ${r.stderr.slice(-1000)}\nconsole: ${sys.state.console.slice(-2000)}`;
  eq("its own pipes, as gexc's", r.stdout, native.stdout, ctx);
  eq('and it ends', r.code, 0, ctx);
  const s = await timeout(sys.run(['/var/tmp/pipeinfo', 'std'], { input: 'abcdef' }), 60000, 'pipeinfo std');
  eq('its standard input at its end, its standard output read by the page', s.stdout, 'fd 0 size 6 blksize 65536 status 128 handle set peer 0\nfd 1 size 0 blksize 65536 status 0 handle set peer set\n', `stderr: ${s.stderr.slice(-1000)}\nconsole: ${sys.state.console.slice(-2000)}`);
  eq('and it ends', s.code, 0);
  t.check("the handles' stand-in said", sys.state.console.includes('Darwin: stand-in: pipe_handle and pipe_peerhandle'), sys.state.console.slice(-2000));
  await sys.shutdown();
}
