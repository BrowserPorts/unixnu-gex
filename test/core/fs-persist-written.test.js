// An OPFSFilesystem's store keeps what the programs wrote and nothing else: not a file of the
// tar's that nobody touched, not a lazy file's bytes (a store that read every file under the root
// fetched a whole lazy split, and a 4 GiB memory trapped), and a file written on an earlier visit
// stays on later ones that did not write it again. Each phase is a load of its own:
//   1. a fresh store over the tar and a lazy file (3 MiB, never read); one small file written;
//      synced: nothing fetched the lazy file;
//   2. that file is there, the lazy file still reads as the server's; another file written,
//      synced, without the first written again;
//   3. both are there.
import { System } from '../../runtime/src/index.js';
import { OPFSFilesystem } from '../../runtime/src/fs.js';

export const meta = { hosts: ['browser'], images: ['busybox'], timeout: 300 };

const ENV = { PATH: '/bin:/usr/bin', HOME: '/root' };
const BIG = 3 << 20; // lazy-written-ARCH.bin (images.mjs)

/** How many times the page and its Workers asked the test server for the lazy file. */
const asked = async (name) => Number(await (await fetch(`/__t/asked?${name}`)).text());

export default async function (t) {
  const { eq, timeout } = t;
  // One store per arch: the two may run at once, in one origin.
  const STORE = `gex-test-persist-written-${t.arch}`;
  if (t.phase === 1) await OPFSFilesystem.erase(STORE);
  const sys = new System({ baseUrl: t.baseUrl, debug: t.debug() });
  const fs = new OPFSFilesystem(sys, { name: STORE, cache: 16 });
  fs.addTar(t.work('bb.tar.zst'));
  // Its own, for this arch: the requests for it are counted.
  const LAZY = `lazy-written-${t.arch}.bin`;
  fs.addTar(null, { lazy: { base: t.work(LAZY), files: [['/root/save/big.bin', BIG, LAZY, 1_700_000_000, 0o644]] } });
  await timeout(sys.boot(), 60000, 'boot');
  const sh = async (cmd) => {
    const r = await timeout(sys.run(['sh', '-c', cmd], { env: ENV }), 120000, cmd.slice(0, 40));
    return { code: r.code, out: (r.stdout + r.stderr).trim() };
  };

  if (t.phase === 1) {
    eq('the first visit writes a save', (await sh('echo one > /root/save/a.txt')).code, 0);
    await timeout(sys.sync(), 60000, 'sync');
    eq('the sync fetched none of the lazy file', await asked(LAZY), 0);
    return t.reload();
  }
  if (t.phase === 2) {
    eq('the save is there on the next visit', (await sh('cat /root/save/a.txt')).out, 'one');
    eq('the lazy file reads as the server\'s', (await sh('wc -c < /root/save/big.bin')).out, String(BIG));
    eq('a second save', (await sh('echo two > /root/save/b.txt')).code, 0);
    await timeout(sys.sync(), 60000, 'sync');
    return t.reload();
  }
  eq('a save not written again on the last visit is kept', (await sh('cat /root/save/a.txt /root/save/b.txt')).out, 'one\ntwo');
  await sys.shutdown();
  await OPFSFilesystem.erase(STORE).catch(() => {});
}
