// addTar's `xattrs`: extended attributes a page sets on a layer's files (a
// Wine prefix's user.DOSATTRIB), on the tar's files, on its lazy files and
// on a layer laid after boot under `at`, beside the tar's own pax ones.
import { System } from '../../runtime/src/index.js';
import { MemoryFilesystem } from '../../runtime/src/fs.js';

export const meta = { hosts: ['browser', 'node'], images: ['busybox'], timeout: 120 };

export default async function (t) {
  const { eq, check, timeout } = t;
  const sys = new System({ baseUrl: t.baseUrl, debug: t.debug() });
  const fs = new MemoryFilesystem(sys);
  fs.addTar(t.work('bb.tar.zst'));
  const size = 3 << 20; // lazy.bin (images.mjs)
  fs.addTar(null, {
    lazy: { base: t.work('lazy.bin'), files: [['/opt/lazy.bin', size, 'lazy.bin', 1_700_000_000, 0o644]] },
    xattrs: {
      '/etc/xattr': { 'user.DOSATTRIB': '0x2' },
      '/opt/lazy.bin': { 'user.DOSATTRIB': '0x20', 'user.two': new Uint8Array([0x6f, 0x6b]) },
    },
  });
  await timeout(sys.boot(), 60000, 'boot');
  const env = { PATH: '/bin:/usr/bin', HOME: '/root' };
  const get = async (p, name) => {
    const r = await timeout(sys.run(['rt-probe', 'xattr', p, name], { env }), 60000, `xattr ${p}`);
    return (r.stdout + r.stderr).trim();
  };
  eq('on a tar\'s file', await get('/etc/xattr', 'user.DOSATTRIB'), '0x2');
  eq('the tar\'s own attribute is kept', await get('/etc/xattr', 'user.rt'), 'kept');
  eq('on a lazy file', await get('/opt/lazy.bin', 'user.DOSATTRIB'), '0x20');
  eq('a value as bytes', await get('/opt/lazy.bin', 'user.two'), 'ok');
  const sum = (await timeout(sys.run(['sh', '-c', 'wc -c < /opt/lazy.bin'], { env }), 60000, 'wc')).stdout.trim();
  eq('the lazy file still reads', sum, String(size));

  await fs.addTar(t.work('bb.tar.zst'), { at: '/opt/x', xattrs: { '/etc/xattr': { 'user.DOSATTRIB': '0x1' } } });
  eq('after boot, under `at`', await get('/opt/x/etc/xattr', 'user.DOSATTRIB'), '0x1');
  eq('the first layer\'s unchanged', await get('/etc/xattr', 'user.DOSATTRIB'), '0x2');

  let threw = null;
  try { await fs.addTar(null, { xattrs: { '/no/such/file': { 'user.x': '1' } } }); } catch (e) { threw = e; }
  check('a missing file is an error', threw?.code === 'ENOENT' || /ENOENT|no such/i.test(String(threw)), String(threw));
  await sys.shutdown();
}
