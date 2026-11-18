/**
 * Is a GL recording (`?glcapture=1`) handed over when the run ends, and not
 * only when it fills?
 *
 * The device posts the recording to /__gex_capture once (mesa-gl.js
 * `postCapture`): when the ceiling stops a batch, and when the last process it
 * recorded exits. `GlCapture` keeps which processes those are (`from`, `gone`):
 * a process that exits while another recorded one runs leaves the recording
 * open, one that recorded nothing changes nothing, and the last one's exit
 * closes it.
 *
 * Usage: node test/fixtures/page/gl-capture.mjs
 */
import { pathToFileURL as gexPathToFileURL } from 'node:url';
import { join as gexJoin } from 'node:path';
// gex: the checkout these fixtures are in, or GEX_ROOT.
const GEX_ROOT = process.env.GEX_ROOT || gexJoin(import.meta.dirname, '..', '..', '..');
const gexUrl = (p) => gexPathToFileURL(gexJoin(GEX_ROOT, p)).href;
const { GlCapture, captureIfRequested } = await import(gexUrl('page/src/gl-capture.js'));

let failed = 0;
const check = (what, cond, detail = '') => {
  console.log(`${cond ? 'ok' : 'FAIL'} ${what}${!cond && detail ? ` (${detail})` : ''}`);
  if (!cond) failed++;
};

const c = new GlCapture(13, 640, 480);
const batch = new Uint8Array(64).fill(7);
c.from(3); c.record(batch, 16);
c.from(5); c.record(batch, 16);
c.from(3); c.record(batch, 16);
check('three batches from two processes', c.batches === 3 && c.clients.size === 2, `${c.batches} ${c.clients.size}`);
check('a process that recorded nothing exits: the recording stays open', c.gone(9) === false);
check('one of two recorded processes exits: the recording stays open', c.gone(3) === false);
check('the same process again: nothing', c.gone(3) === false);
check('the last recorded process exits: the recording is whole', c.gone(5) === true);
check('and only once', c.gone(5) === false);
const bytes = c.toBytes();
check('the recording holds its three batches', bytes.length === c.bytes && c.bytes - c.parts[0].length === 3 * (8 + 64), `${bytes.length} bytes`);

// A process number is the guest's unsigned 32-bit one, however it arrives.
const d = new GlCapture(13, 1, 1);
d.from(-1);
check('a client number past 2^31 is one process', d.gone(0xffffffff) === true);

// ?glcapture= under Node: GEX_GLCAPTURE.
process.env.GEX_GLCAPTURE = '4096';
const e = captureIfRequested(13, 2, 2);
check('GEX_GLCAPTURE=N makes a capture of that ceiling', e instanceof GlCapture && e.maxBytes === 4096, String(e?.maxBytes));
check('a full capture refuses the batch', !e.record(new Uint8Array(8192), 0) && e.truncated);

if (failed) {
  console.error(`gl capture check FAILED: ${failed}`);
  process.exit(1);
}
