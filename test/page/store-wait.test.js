// OPFSFilesystem.busy(name), and a boot that waits for a store another page
// of the site has open (`wait`) instead of failing with EBUSY. The other page
// is a Worker holding the store's lock and handle, as a second tab's store
// Worker would. A page runs one system, so each phase is a load of its own:
//   1. busy: true while the other page holds the store; a wait whose signal
//      aborts rejects boot with the signal's reason;
//   2. a boot with `wait: true` goes on by itself once the other page closes;
//      busy is then false (this page's own system never makes it busy).
import { System } from '../../runtime/src/index.js';
import { OPFSFilesystem } from '../../runtime/src/fs.js';

export const meta = { hosts: ['browser'], images: ['busybox'], timeout: 180 };

async function otherPage(name) {
  const src = `onmessage = async ({ data: name }) => {
    navigator.locks.request('gex-fs-' + name, async () => {
      const root = await navigator.storage.getDirectory();
      const dir = await root.getDirectoryHandle('gex-fs-' + name, { create: true });
      await (await dir.getFileHandle('blocks', { create: true })).createSyncAccessHandle();
      postMessage('held');
      await new Promise(() => {});
    });
  };`;
  const w = new Worker(URL.createObjectURL(new Blob([src], { type: 'text/javascript' })));
  await new Promise((r) => { w.onmessage = r; w.postMessage(name); });
  return { close: () => w.terminate() };
}

export default async function (t) {
  const { check, eq, timeout } = t;
  const STORE = `gex-test-wait-${t.arch}`;
  const env = { PATH: '/bin:/usr/bin', HOME: '/root' };
  if (t.phase === 1) {
    await OPFSFilesystem.erase(STORE);
    eq('a store no page has open is not busy', await OPFSFilesystem.busy(STORE), false);
    await otherPage(STORE);
    eq('busy while another page has it open', await OPFSFilesystem.busy(STORE), true);
    const sys = new System({ baseUrl: t.baseUrl, debug: t.debug() });
    const stop = new AbortController();
    const fs = new OPFSFilesystem(sys, { name: STORE, wait: stop.signal });
    fs.addTar(t.work('bb.tar.zst'));
    let settled = false;
    const booting = sys.boot().then(() => null, (e) => e).finally(() => { settled = true; });
    await new Promise((r) => setTimeout(r, 3000));
    check('boot waits for the store', !settled, String(settled));
    stop.abort(new Error('the page gave up'));
    const e = await timeout(booting, 30000, 'boot after the abort');
    check('an abort ends the wait with its reason', /the page gave up/.test(String(e?.message ?? e)), String(e?.message ?? e));
    return t.reload();
  }
  const other = await otherPage(STORE);
  const sys = new System({ baseUrl: t.baseUrl, debug: t.debug() });
  const fs = new OPFSFilesystem(sys, { name: STORE, wait: true });
  fs.addTar(t.work('bb.tar.zst'));
  const booting = sys.boot();
  setTimeout(() => other.close(), 2000);
  await timeout(booting, 90000, 'boot once the other page closed');
  eq('it runs on the store', (await timeout(sys.run(['sh', '-c', 'echo kept > /root/f; cat /root/f'], { env }), 60000, 'run')).stdout, 'kept\n');
  eq('its own store is not busy to this page', await OPFSFilesystem.busy(STORE), false);
  await sys.shutdown();
  await OPFSFilesystem.erase(STORE).catch(() => {});
}
