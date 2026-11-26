// The early-init tests' body (test/core/early-init-*.test.js, one system
// each: a page runs one). A bundle laid while its program runs (fs.js
// `addTar(src, { early })`, kfs.js `#layEarly`): its index first, then the program starts with every file
// named and its bytes still coming. A file not yet laid is there to a lookup
// and `stat`, and a read of it waits for its bytes. When the bundle fails
// (a fetch error, a decode error, an archive that ends short), what never
// came is EIO to the program, never ENOENT; the system's phase is 'failed'
// with the error, and the program goes on.
import { System } from '../../runtime/src/index.js';
import { MemoryFilesystem } from '../../runtime/src/fs.js';
import { bytesOf } from '../../runtime/src/internal.js';
import { unzstd } from '../../runtime/src/host/zfetch.js';
import { tarOf } from './tar.mjs';

const enc = new TextEncoder();

/** The index's records (hosts/kernel `k_fs_seed`: 6 a directory, 5 a file
 *  still to come, 7 a hard link, 2 a symbolic link). */
function indexOf({ dirs, files, hard, links }) {
  const out = [];
  const u32 = (v) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, v, true); out.push(b); };
  const u64 = (v) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(v), true); out.push(b); };
  const text = (s) => { const b = enc.encode(s); u32(b.length); out.push(b); };
  for (const p of dirs) { out.push(Uint8Array.of(6)); u32(0o755); u64(0); text(p); }
  for (const [p, { size, mode }] of Object.entries(files)) { out.push(Uint8Array.of(5)); u32(mode); u64(size); u64(0); text(p); }
  for (const [p, target] of Object.entries(hard)) { out.push(Uint8Array.of(7)); text(target); text(p); }
  for (const [p, target] of Object.entries(links)) { out.push(Uint8Array.of(2)); text(target); text(p); }
  const b = new Uint8Array(out.reduce((n, x) => n + x.length, 0));
  let at = 0;
  for (const x of out) { b.set(x, at); at += x.length; }
  return b;
}

/** `how` the bundle fails: 'fetch', 'decode' or 'short'. */
export async function earlyInit(t, how) {
  const { say, check, eq, until, timeout } = t;
  const zbb = await bytesOf(t.work('bb.tar.zst'));
  // A decoder's own error: a frame cut and its bytes spoilt.
  const bad = zbb.slice(0, Math.min(zbb.length, 4096));
  bad.fill(0x5a, 64);
  const decodeError = await unzstd(bad).then(() => new Error('the spoilt frame decoded'), (e) => e);

  const late = enc.encode('late\n');

  {
    let out = '';
    // Busybox in a layer of its own; the early bundle /etc/early in its first
    // part, /etc/late in a part that never comes.
    const sys = new System({ baseUrl: t.baseUrl, debug: t.debug() });
    const fs = new MemoryFilesystem(sys);
    fs.addTar(zbb);
    const index = indexOf({ dirs: ['/etc'], files: { '/etc/early': { size: 6, mode: 0o644 }, '/etc/late': { size: late.length, mode: 0o644 } }, hard: {}, links: {} });
    const first = tarOf([{ path: '/.gex-index', data: index }, { path: '/etc/early', data: 'early\n' }]);
    let release;
    const gate = new Promise((r) => { release = r; });
    fs.addTar(new ReadableStream({
      async start(c) {
        // (without the archive's end)
        c.enqueue(first.slice(0, first.length - 1024));
        await gate;
        if (how === 'fetch') c.error(new TypeError('Failed to fetch'));
        else if (how === 'decode') c.error(decodeError);
        // 'short': the archive ends without /etc/late
        else c.close();
      },
    }), { early: true });
    const system = sys;
    const script = [
      'ls -ln /etc/late | sed "s/^/size /"',
      'ls /etc | grep -c "^late$" | sed "s/^/listed /"',
      'cat /etc/early',
      'echo waiting',
      'cat /etc/late; echo "cat $?"',
      'ls -ln /etc/late | sed "s/^/after /"',
      'cat /etc/late 2>&1 | grep -c "No such file" | sed "s/^/enoent /"',
      'read x; echo "got $x"',
      'exit 3',
    ].join('\n');
    const t0 = performance.now();
    await timeout(sys.boot(), 60000, `${how}: boot`);
    const p = sys.spawn(['/bin/sh', '-c', script], { pty: { cols: 80, rows: 24 }, env: ['PATH=/bin:/usr/bin', 'HOME=/root'], cwd: '/' });
    const dec = new TextDecoder();
    p.pty.addEventListener('data', (e) => { out += typeof e.data === 'string' ? e.data : dec.decode(e.data, { stream: true }); });
    const run = p.exited.then(({ code }) => ({ status: code }));
    run.catch((e) => { out += `\n[threw: ${e?.stack ?? e}]`; });
    await timeout(until(() => /^waiting$/m.test(out.replace(/\r/g, '')), 'the program', 60000), 70000, `${how}: start`)
      .catch((e) => { throw new Error(`${e.message}: ${out.slice(-600)} (phase ${system?.state.phase}: ${system?.state.error ?? ''} ${system?.state.console?.slice(-400) ?? ''})`); });
    say(`${how}: the program runs in ${(performance.now() - t0).toFixed(0)} ms, the bundle's last part not in`);
    // The cat of /etc/late waits for its bytes, until the bundle fails.
    await new Promise((r) => setTimeout(r, 500));
    check(`${how}: a read of a file still to come waits`, !/^cat \d+$/m.test(out.replace(/\r/g, '')), out.slice(-300));
    release();
    await timeout(until(() => /^enoent \d+$/m.test(out.replace(/\r/g, '')), 'the rest of the script', 30000), 40000, `${how}: the failure`)
      .catch((e) => { throw new Error(`${e.message}: ${out.slice(-600)}`); });
    eq(`${how}: the system's phase once the bundle failed`, system?.state.phase, 'failed');
    const err = system?.state.error ?? '';
    check(`${how}: the system's error says why`, how === 'fetch' ? /Failed to fetch/.test(err)
      : how === 'decode' ? err.includes(String(decodeError?.message ?? decodeError).slice(0, 40))
        : /ended with 1 of the files its index names missing/.test(err), err.slice(0, 300));
    p.pty.write('done\r');
    const r = await timeout(run, 30000, `${how}: the end`);
    const lines = out.replace(/\r/g, '');
    say(lines.split('\n').map((l) => `  | ${l}`).join('\n'));
    check(`${how}: a file still to come has its size`, /^size \S+\s+\d+\s+\d+\s+\d+\s+5\s/m.test(lines));
    check(`${how}: and is in its directory`, /^listed 1$/m.test(lines));
    check(`${how}: a file laid reads`, /^early$/m.test(lines));
    check(`${how}: a file that never came is EIO`, /I\/O error/.test(lines) && /^cat 1$/m.test(lines));
    check(`${how}: it is still there, its size kept`, /^after \S+\s+\d+\s+\d+\s+\d+\s+5\s/m.test(lines));
    check(`${how}: never ENOENT`, /^enoent 0$/m.test(lines));
    check(`${how}: the program goes on`, /^got done$/m.test(lines));
    eq(`${how}: the program's status`, r.status, 3);
    await sys.shutdown();
  }
}
