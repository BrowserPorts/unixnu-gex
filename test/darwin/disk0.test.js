// The Darwin system's disk0 in the page (the `darwin-disk` image): the
// image gexc runs on, which the page's global kernel reads by ranges from
// the work server, the system's writes kept over it in the page. diskrw
// (tests/darwin/src/diskrw.c, static) reads it through disk0's character
// node: the GPT and its backup 64 GB in, and the container's superblock,
// which the boot's update of the container to read-write wrote (its
// NX_CLEANLY_UNMOUNTED cleared, which the image's has: the page reads the
// image's here from the image itself); its output and status must be
// gexc's. A second run in the same system reads the
// same disk the first one's boot wrote, the system's: its own boot does
// not mount the container again (the container's state in memory is the
// first process's), and says so.
import { System } from '../../page/runtime/src/index.js';
import { MemoryFilesystem } from '../../page/runtime/src/fs.js';

/** What gexc says of its own standard streams, its host's (darwin/hoststd.rs):
 *  not the page's, whose streams are its pipes. */
const HOST_STREAMS = "[gex] Darwin: the host's standard streams stand in:";

export const meta = { hosts: ['browser'], arches: ['a64'], images: ['darwin-disk'], timeout: 300 };

export default async function (t) {
  const { eq, timeout } = t;
  const image = await (await fetch(t.work('darwin-disk.json'))).json();
  const native = image.native;
  eq("gexc's run of diskrw", [native.stdout.split('\n').at(-2), native.status], ['diskrw ok', 0]);
  const boot = Object.fromEntries(image.boot.map((f) => [f, new URL(t.work(`darwin-disk/boot/${f}`))]));
  const disk0 = { url: t.work('darwin-disk/disk0'), missing: new URL(t.work('darwin-disk/disk0.missing')) };
  const sys = new System({ baseUrl: t.baseUrl, arch: 'aarch64', darwin: { boot, disk0 }, debug: t.debug() });
  const fs = new MemoryFilesystem(sys);
  fs.addFiles({ '/var/tmp/diskrw': new URL(t.work('darwin-disk/diskrw')) }, { mode: 0o755 });
  await timeout(sys.boot(), 60000, 'boot');
  const r = await timeout(sys.run(['/var/tmp/diskrw']), 150000, 'diskrw');
  await t.saveFile('console.txt', sys.state.console);
  eq('diskrw: output, as gexc\'s', r.stdout, native.stdout, `stderr: ${r.stderr.slice(-2000)}\nconsole: ${sys.state.console.slice(-4000)}`);
  eq('diskrw: status, as gexc\'s', r.code, native.status, r.signal ? `signal ${r.signal}` : undefined);
  // The superblock the program read is the system's write, not the
  // image's: the image's own says the container was cleanly unmounted.
  const sb = new Uint8Array(await (await fetch(t.work('darwin-disk/disk0'), { headers: { Range: `bytes=${6 * 4096}-${7 * 4096 - 1}` } })).arrayBuffer());
  const imageClean = (new DataView(sb.buffer).getBigUint64(0x4f0, true) & 2n) !== 0n;
  const read = /diskrw xid \d+ clean (\d)/.exec(r.stdout)?.[1];
  t.check(`the superblock read (clean ${read}) is the boot's write over the image's (clean ${imageClean ? 1 : 0})`, imageClean && read === '0');
  // What the Darwin kernel reported, as gexc's (by subject: up to its
  // second colon).
  const said = sys.state.console.split('\n');
  for (const line of native.reports.filter((l) => !l.startsWith(HOST_STREAMS))) {
    const subject = line.slice(0, line.indexOf(':', line.indexOf(':') + 1) + 1);
    t.check(`the Darwin kernel's report on the console: ${subject}`, said.some((l) => l.startsWith(subject)), sys.state.console.slice(-2000));
  }
  // A second process: the same disk, as the first one's boot left it.
  const again = await timeout(sys.run(['/var/tmp/diskrw']), 150000, 'diskrw again');
  eq('a second run reads the disk as the first left it', again.stdout, r.stdout, `stderr: ${again.stderr.slice(-2000)}`);
  t.check("and its boot's container mount is refused, said", sys.state.console.includes("the kernel's container in the disk0 image, which process "), sys.state.console.slice(-3000));
  for (const l of sys.state.console.split('\n').filter((l) => l.includes('Darwin: not implemented'))) t.say(`console: ${l.slice(0, 240)}`);
  await sys.shutdown();
}
