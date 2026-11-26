// A whole-file copy_file_range in the kernel's file system shares the bytes
// until either file is written (fixtures/native/clone-copy/cc.c): 170 MiB
// copied adds under 1 MiB to what the file system holds (/proc/meminfo's
// Shmem), a write to either file, a truncation down and up, a rename and
// a delete of the source and a copy of the copy leave every other file as
// it was, and once all are gone their room is free. Natively and on the
// page's kernel. Every copy used to hold the source's bytes twice: an
// installer's package and its copy, 170 MiB more each.
import { native } from '../lib/native.mjs';

export const meta = { hosts: ['node'], arches: ['x86'], timeout: 600 };

export default async function (t) {
  const n = native(t);
  const d = n.dir('clone-copy');
  await n.cc(['-O1', '-static', '-o', `${d}/cc`, n.src('clone-copy/cc.c')]);
  const judge = (where, out) => {
    t.check(`${where}: ran to the end`, /^ok$/m.test(out), out.trim().split('\n').slice(-6).join(' / '));
    const added = Number(/^copy added (-?\d+) KiB/m.exec(out)?.[1]);
    t.check(`${where}: the copy added ${added} KiB (under 1024)`, added < 1024, out.trim());
    const wrote = Number(/^writes added (-?\d+) KiB/m.exec(out)?.[1]);
    t.check(`${where}: two small writes added ${wrote} KiB (under 1024)`, wrote < 1024, out.trim());
    const m = /^after both went: Shmem (\d+) KiB \(at the start (\d+)\)/m.exec(out);
    const left = m ? Number(m[1]) - Number(m[2]) : NaN;
    t.check(`${where}: ${left} KiB left once every file went (under 1024)`, left < 1024, out.trim());
    // the measure is the file system's: the source counted, 170 MiB
    const held = Number(/\(Shmem (\d+) ->/.exec(out)?.[1]) - Number(m?.[2]);
    t.check(`${where}: the source is counted (${held} KiB)`, held >= 170 * 1024, out.trim());
  };
  // in /dev/shm, the kernel's own file system on both (natively / and /tmp
  // are the host's)
  const r = await n.gexc(['run', `${d}/cc`, '/dev/shm'], { timeout: 240000 });
  judge('native', r.stdout + r.stderr);
  const p = await n.g.run(n.seed(), `${d}/cc`, ['/dev/shm'], { files: { '/g/cc': `${d}/cc` }, argv0: '/g/cc', env: { GEX_SHARED: '1' }, timeout: 240000 });
  judge('page', p.stdout + p.stderr);
  n.clean();
}
