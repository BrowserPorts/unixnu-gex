// The Darwin root and disk0 gexc runs a dynamic program on, as the page
// reads them without a copy (the `darwin-root` image): a range of the
// 64 GB disk0 image read alone from the work server (its GPT header, at
// its second 4 KiB block), and the root laid as the page's filesystem (a
// tar of directories and links, and a lazy list of its files): dyld and
// its neighbours are there, at their sizes. (A lazy file's bytes are read
// by a process's Worker, never the page's thread: a program reading them
// is the next slices'.)
import { System } from '../../runtime/src/index.js';
import { MemoryFilesystem } from '../../runtime/src/fs.js';

export const meta = { hosts: ['browser'], arches: ['a64'], images: ['darwin-root'], timeout: 300 };

export default async function (t) {
  const { eq, timeout } = t;
  const disk = await fetch(t.work('darwin-root/disk0'), { headers: { Range: 'bytes=4096-8191' } });
  const head = new Uint8Array(await disk.arrayBuffer());
  eq('a range of disk0 is read alone', [disk.status, head.length, disk.headers.get('content-range')], [206, 4096, 'bytes 4096-8191/64000000000']);
  eq("and it is the image's GPT header", new TextDecoder().decode(head.subarray(0, 8)), 'EFI PART');
  const whole = await fetch(t.work('darwin-root/root/usr/lib/dyld'));
  const dyld = new Uint8Array(await whole.arrayBuffer());
  const sys = new System({ baseUrl: t.baseUrl, arch: 'aarch64', debug: t.debug() });
  const fs = new MemoryFilesystem(sys);
  fs.addTar(t.work('darwin-root/root.tar'), { lazy: t.work('darwin-root/root-lazy.json') });
  await timeout(sys.boot(), 120000, 'boot');
  eq('the root has dyld', (await fs.stat('/usr/lib/dyld')).size, dyld.length);
  const lib = (await fs.readdir('/usr/lib')).map((e) => e.name);
  eq("and the root's /usr/lib", ['dyld', 'libobjc-trampolines.dylib', 'libz.1.2.12.dylib'].every((n) => lib.includes(n)), true);
  eq('a link of the root is a link', await fs.readlink('/usr/libexec/init_data_protection'), 'seputil');
  await sys.shutdown();
}
